"""Authenticated dependency-free HTTP API for the control plane."""

from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import logging
import math
from threading import BoundedSemaphore, Condition
import time
from typing import Any, Callable
from urllib.parse import parse_qs, urlsplit
import uuid

from .config import Principal, Settings
from .metrics import Metrics
from .store import BudgetExceededError, ConflictError, NotFoundError


LOGGER = logging.getLogger("agent_tree_rl.api")


_MAX_JSON_DEPTH = 64
_MAX_JSON_VALUES = 10_000


_STATIC_ROUTES = frozenset(
    {
        "/healthz",
        "/readyz",
        "/metrics",
        "/v1/decisions/run",
        "/v1/evidence/run",
        "/v1/benchmarks/evaluate",
        "/v1/challengers/train",
        "/v1/audit",
    }
)
_OPERATIONAL_ROUTES = frozenset({"/healthz", "/readyz", "/metrics"})


def _query_integer(
    query: dict[str, list[str]],
    name: str,
    default: int,
    *,
    minimum: int,
    maximum: int,
) -> int:
    """Read one bounded base-10 ASCII integer from an HTTP query."""

    values = query.get(name)
    if values is None:
        return default
    if len(values) != 1:
        raise APIError(
            400,
            "invalid_query",
            "audit query fields may appear only once",
        )
    raw = values[0]
    if not raw or not raw.isascii() or not raw.isdigit():
        raise APIError(
            400,
            "invalid_query",
            f"audit query field {name!r} must contain ASCII digits",
        )
    try:
        value = int(raw, 10)
    except ValueError as error:
        raise APIError(
            400,
            "invalid_query",
            f"audit query field {name!r} is outside the supported range",
        ) from error
    if not minimum <= value <= maximum:
        raise APIError(
            400,
            "invalid_query",
            f"audit query field {name!r} must be between {minimum} and {maximum}",
        )
    return value


def _reject_json_constant(value: str) -> object:
    raise ValueError(f"non-finite JSON number: {value}")


def _parse_json_float(value: str) -> float:
    parsed = float(value)
    if not math.isfinite(parsed):
        raise ValueError("non-finite JSON number")
    return parsed


def _reject_duplicate_json_keys(
    pairs: list[tuple[str, Any]],
) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate JSON object key")
        value[key] = item
    return value


def _validate_json_limits(value: object) -> None:
    stack: list[tuple[object, int]] = [(value, 0)]
    value_count = 0
    while stack:
        current, enclosing_depth = stack.pop()
        value_count += 1
        if value_count > _MAX_JSON_VALUES:
            raise ValueError("JSON value limit exceeded")

        if isinstance(current, dict):
            children = current.values()
        elif isinstance(current, list):
            children = current
        else:
            continue
        depth = enclosing_depth + 1
        if depth > _MAX_JSON_DEPTH:
            raise ValueError("JSON nesting depth exceeded")
        stack.extend((item, depth) for item in children)


def _strict_json_loads(value: str) -> object:
    parsed = json.loads(
        value,
        object_pairs_hook=_reject_duplicate_json_keys,
        parse_constant=_reject_json_constant,
        parse_float=_parse_json_float,
    )
    _validate_json_limits(parsed)
    return parsed


def _match_route(path: str) -> tuple[str, dict[str, str]]:
    """Return a bounded route template and parameters for an exact API path."""

    if path in _STATIC_ROUTES:
        return path, {}
    segments = path.split("/")
    if len(segments) != 5 or segments[0] or not segments[3]:
        return "unmatched", {}
    if segments[1:3] == ["v1", "challengers"] and segments[4] == "promote":
        return "/v1/challengers/{challenger_id}/promote", {
            "challenger_id": segments[3]
        }
    if segments[1:3] == ["v1", "families"] and segments[4] == "rollback":
        return "/v1/families/{family}/rollback", {"family": segments[3]}
    if segments[1:3] == ["v1", "families"] and segments[4] == "champion":
        return "/v1/families/{family}/champion", {"family": segments[3]}
    return "unmatched", {}


class APIError(RuntimeError):
    def __init__(self, status: int, code: str, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message


class ProductionHTTPServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(
        self,
        address: tuple[str, int],
        handler: type[BaseHTTPRequestHandler],
        *,
        settings: Settings,
        control: object,
        metrics: Metrics,
    ) -> None:
        super().__init__(address, handler)
        self.settings = settings
        self.control = control
        self.metrics = metrics
        self._work_semaphore = BoundedSemaphore(settings.max_workers)
        self._operational_semaphore = BoundedSemaphore(
            settings.max_operational_workers
        )
        self._lifecycle = Condition()
        self._draining = False
        self._active_work_requests = 0

    @property
    def draining(self) -> bool:
        with self._lifecycle:
            return self._draining

    def begin_draining(self) -> bool:
        """Fail readiness and atomically stop admitting new work."""

        with self._lifecycle:
            changed = not self._draining
            if changed:
                begin_draining = getattr(self.control, "begin_draining", None)
                if callable(begin_draining):
                    begin_draining()
                self._draining = True
        return changed

    def admit_request(self, *, operational: bool) -> str | None:
        """Admit one bounded request or return its stable rejection code."""

        semaphore = (
            self._operational_semaphore if operational else self._work_semaphore
        )
        with self._lifecycle:
            if self._draining and not operational:
                return "draining"
        if not semaphore.acquire(blocking=False):
            return "operational_overloaded" if operational else "overloaded"
        with self._lifecycle:
            # Close the race between the first drain check and semaphore
            # acquisition. A request is either admitted before the drain gate
            # or rejected; it can never enter after draining starts.
            if self._draining and not operational:
                semaphore.release()
                return "draining"
            if not operational:
                self._active_work_requests += 1
        return None

    def release_admission(self, *, operational: bool) -> None:
        semaphore = (
            self._operational_semaphore if operational else self._work_semaphore
        )
        semaphore.release()
        if operational:
            return
        with self._lifecycle:
            self._active_work_requests -= 1
            if self._active_work_requests < 0:
                raise RuntimeError("HTTP active work request count underflow")
            if self._active_work_requests == 0:
                self._lifecycle.notify_all()

    def wait_for_drain(self, *, timeout: float) -> bool:
        if timeout < 0:
            raise ValueError("drain timeout must be nonnegative")
        with self._lifecycle:
            return self._lifecycle.wait_for(
                lambda: self._active_work_requests == 0,
                timeout=timeout,
            )


class RequestHandler(BaseHTTPRequestHandler):
    server: ProductionHTTPServer
    protocol_version = "HTTP/1.1"
    server_version = "AgentTreeRL/1"
    sys_version = ""

    def do_GET(self) -> None:  # noqa: N802
        self._dispatch("GET")

    def do_POST(self) -> None:  # noqa: N802
        self._dispatch("POST")

    def do_PUT(self) -> None:  # noqa: N802
        self._error(APIError(405, "method_not_allowed", "method not allowed"))

    def do_DELETE(self) -> None:  # noqa: N802
        self._error(APIError(405, "method_not_allowed", "method not allowed"))

    def log_message(self, format: str, *args: object) -> None:
        # Structured request logging happens once in _dispatch.
        return

    def _dispatch(self, method: str) -> None:
        started = time.monotonic()
        request_id = str(uuid.uuid4())
        status = 500
        route = "unmatched"
        route_parameters: dict[str, str] = {}
        principal: Principal | None = None
        admitted = False
        operational = False
        try:
            parsed = urlsplit(self.path)
            route, route_parameters = _match_route(parsed.path)
            operational = method == "GET" and route in _OPERATIONAL_ROUTES
            rejection = self.server.admit_request(operational=operational)
            if rejection is not None:
                status = 503
                message = (
                    "server is draining"
                    if rejection == "draining"
                    else "operational concurrency limit reached"
                    if rejection == "operational_overloaded"
                    else "worker concurrency limit reached"
                )
                self._error(APIError(503, rejection, message), request_id)
                return
            admitted = True
            if parsed.query and not (method == "GET" and route == "/v1/audit"):
                raise APIError(400, "invalid_query", "route accepts no query")
            if method == "GET" and route == "/healthz":
                status = self._json(200, self.server.control.health(), request_id)
                return
            if method == "GET" and route == "/readyz":
                payload = self.server.control.readiness()
                status = self._json(200 if payload.get("ready") else 503, payload, request_id)
                return
            if method == "GET" and route == "/metrics":
                status = self._text(200, self.server.metrics.render(), request_id)
                return

            principal = self._authenticate()
            if method == "POST":
                idempotency_key = self.headers.get("Idempotency-Key", "")
                if not 8 <= len(idempotency_key) <= 200:
                    raise APIError(
                        400,
                        "idempotency_required",
                        "Idempotency-Key must contain 8-200 characters",
                    )
                body = self._body()
                if route == "/v1/decisions/run":
                    self._require(principal, "agent")
                    payload = self.server.control.run_decision(
                        principal, body, idempotency_key=idempotency_key
                    )
                elif route == "/v1/evidence/run":
                    self._require(principal, "operator")
                    payload = self.server.control.run_evidence(
                        principal, body, idempotency_key=idempotency_key
                    )
                elif route == "/v1/benchmarks/evaluate":
                    self._require(principal, "promoter")
                    payload = self.server.control.evaluate_hidden_benchmark(
                        principal, body, idempotency_key=idempotency_key
                    )
                elif route == "/v1/challengers/train":
                    self._require(principal, "agent")
                    payload = self.server.control.train_challenger(
                        principal, body, idempotency_key=idempotency_key
                    )
                elif route == "/v1/challengers/{challenger_id}/promote":
                    self._require(principal, "promoter")
                    payload = self.server.control.promote(
                        principal,
                        route_parameters["challenger_id"],
                        body,
                        idempotency_key=idempotency_key,
                    )
                elif route == "/v1/families/{family}/rollback":
                    self._require(principal, "promoter")
                    payload = self.server.control.rollback(
                        principal,
                        route_parameters["family"],
                        body,
                        idempotency_key=idempotency_key,
                    )
                else:
                    raise APIError(404, "not_found", "route not found")
                status = self._json(200, payload, request_id)
                return

            if method == "GET" and route == "/v1/families/{family}/champion":
                self._require(principal, "operator", "promoter", "auditor")
                payload = self.server.control.get_champion(
                    principal, route_parameters["family"]
                )
                status = self._json(200, payload, request_id)
                return
            if method == "GET" and route == "/v1/audit":
                self._require(principal, "auditor", "operator")
                try:
                    query = parse_qs(
                        parsed.query,
                        keep_blank_values=True,
                        strict_parsing=True,
                        max_num_fields=4,
                    )
                except ValueError as error:
                    raise APIError(
                        400, "invalid_query", "invalid audit query"
                    ) from error
                unknown = sorted(set(query).difference({"after", "limit"}))
                if unknown:
                    raise APIError(
                        400,
                        "invalid_query",
                        "unknown audit query fields: " + ", ".join(unknown),
                    )
                after = _query_integer(
                    query,
                    "after",
                    0,
                    minimum=0,
                    maximum=(1 << 63) - 1,
                )
                limit = _query_integer(
                    query,
                    "limit",
                    100,
                    minimum=1,
                    maximum=500,
                )
                payload = self.server.control.audit(principal, after=after, limit=limit)
                status = self._json(200, payload, request_id)
                return
            raise APIError(404, "not_found", "route not found")
        except APIError as error:
            status = error.status
            self._error(error, request_id)
        except BudgetExceededError as error:
            status = 429
            self._error(APIError(429, "budget_exceeded", str(error)), request_id)
        except ConflictError as error:
            status = 409
            self._error(APIError(409, "conflict", str(error)), request_id)
        except NotFoundError as error:
            status = 404
            self._error(APIError(404, "not_found", str(error)), request_id)
        except (ValueError, KeyError, json.JSONDecodeError) as error:
            status = 400
            self._error(APIError(400, "invalid_request", str(error)), request_id)
        except Exception as error:
            status = 500
            # Keep unexpected exception details out of shared request logs. The
            # exception class plus correlation ID is enough to route an
            # operator to an access-controlled diagnostic surface.
            LOGGER.error(
                "request failed",
                extra={
                    "request_id": request_id,
                    "exception_type": type(error).__name__,
                },
            )
            self._error(APIError(500, "internal_error", "internal server error"), request_id)
        finally:
            if admitted:
                self.server.release_admission(operational=operational)
            self.server.metrics.increment(
                "http_requests_total",
                method=method,
                route=route,
                status=str(status),
            )
            LOGGER.info(
                "request",
                extra={
                    "request_id": request_id,
                    "method": method,
                    "route": route,
                    "status": status,
                    "authenticated": principal is not None,
                    "duration_ms": round((time.monotonic() - started) * 1000, 3),
                },
            )

    def _authenticate(self) -> Principal:
        settings = self.server.settings
        if not settings.require_auth:
            return Principal(
                "development",
                frozenset({"agent", "operator", "promoter", "auditor"}),
                "local-development",
            )
        header = self.headers.get("Authorization", "")
        if not header.startswith("Bearer "):
            raise APIError(401, "unauthorized", "bearer token required")
        principal = settings.authenticate(header[7:])
        if principal is None:
            raise APIError(401, "unauthorized", "invalid bearer token")
        return principal

    @staticmethod
    def _require(principal: Principal, *roles: str) -> None:
        if not principal.allows(*roles):
            raise APIError(403, "forbidden", "principal lacks required role")

    def _body(self) -> dict[str, Any]:
        raw_length = self.headers.get("Content-Length")
        if raw_length is None:
            raise APIError(411, "length_required", "Content-Length required")
        try:
            length = int(raw_length)
        except ValueError as error:
            raise APIError(400, "invalid_length", "invalid Content-Length") from error
        if not 0 <= length <= self.server.settings.max_request_bytes:
            raise APIError(413, "body_too_large", "request body exceeds limit")
        if self.headers.get_content_type() != "application/json":
            raise APIError(415, "unsupported_media_type", "application/json required")
        raw = self.rfile.read(length)
        try:
            value = _strict_json_loads(raw.decode("utf-8"))
        except (
            json.JSONDecodeError,
            UnicodeDecodeError,
            ValueError,
            TypeError,
            RecursionError,
        ):
            raise APIError(400, "invalid_json", "invalid JSON body") from None
        if not isinstance(value, dict):
            raise APIError(400, "invalid_body", "request JSON must be an object")
        return value

    def _json(self, status: int, payload: object, request_id: str) -> int:
        body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self._headers("application/json", len(body), request_id)
        self.end_headers()
        self.wfile.write(body)
        return status

    def _text(self, status: int, payload: str, request_id: str) -> int:
        body = payload.encode("utf-8")
        self.send_response(status)
        self._headers("text/plain; version=0.0.4", len(body), request_id)
        self.end_headers()
        self.wfile.write(body)
        return status

    def _error(self, error: APIError, request_id: str | None = None) -> None:
        identifier = request_id or str(uuid.uuid4())
        self._json(
            error.status,
            {"error": {"code": error.code, "message": error.message}, "request_id": identifier},
            identifier,
        )

    def _headers(self, content_type: str, length: int, request_id: str) -> None:
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(length))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Request-ID", request_id)
        self.send_header("Connection", "close")


def serve(
    settings: Settings,
    control: object,
    metrics: Metrics,
    *,
    ready_callback: Callable[[ProductionHTTPServer], None] | None = None,
    shutdown_timeout_seconds: float = 30,
    cancellation_timeout_seconds: float = 5,
) -> bool:
    server = ProductionHTTPServer(
        (settings.host, settings.port),
        RequestHandler,
        settings=settings,
        control=control,
        metrics=metrics,
    )
    if ready_callback:
        ready_callback(server)
    try:
        server.serve_forever(poll_interval=0.25)
    finally:
        server.begin_draining()
        graceful = server.wait_for_drain(timeout=shutdown_timeout_seconds)
        if not graceful:
            LOGGER.error(
                "HTTP drain deadline expired",
                extra={"shutdown_timeout_seconds": shutdown_timeout_seconds},
            )
            cancellation_deadline = time.monotonic() + cancellation_timeout_seconds
            cancel_active = getattr(control, "cancel_active_processes", None)
            if callable(cancel_active):
                report = cancel_active(
                    timeout_seconds=max(0.1, cancellation_timeout_seconds * 0.8)
                )
                LOGGER.warning(
                    "active subprocess cancellation completed",
                    extra={
                        "registered": report.registered,
                        "term_signalled": report.term_signalled,
                        "kill_signalled": report.kill_signalled,
                        "remaining": report.remaining,
                    },
                )
            remaining = max(0.0, cancellation_deadline - time.monotonic())
            drained_after_cancel = server.wait_for_drain(timeout=remaining)
            if not drained_after_cancel:
                LOGGER.error("HTTP work remained after forced cancellation")
        server.server_close()
    return graceful
