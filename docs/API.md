# HTTP API reference

The HTTP API is an alpha contract. All request and response bodies use JSON.
Production ingress must provide TLS, connection deadlines, header limits, body
limits, rate limits, and authenticated workload identity.

## Current product boundary

Decision and training routes operate only on the built-in synthetic
`flaky-android-ui-test` fixture and the `agent-decision-routing` policy family.
The API does not yet accept a user task, scenario manifest, or agent provider.

## Authentication and idempotency

Except for health, readiness, and metrics, send:

```text
Authorization: Bearer <role token>
```

Every `POST` also requires:

```text
Content-Type: application/json
Idempotency-Key: <8-200 characters>
```

Reuse a key only for an exact retry of the same tenant, operation, and body.
Changing the body under the same key returns a conflict.

Idempotency records are retained for 24 hours. Exact retry protection applies
only within that window; after expiry, the same key may execute and spend again.
Clients must retain the original response and reconcile ambiguous outcomes
before the window closes. Start a later logical operation with a fresh key.
Exception: startup recovery converts crash-interrupted `IN_PROGRESS` records to
durable, non-expiring `FAILED` tombstones with `retry_safe=false`; those keys
can never execute again because an external effect may be ambiguous.

## Roles

| Role | Allowed work |
|---|---|
| `agent` | Run a decision; train a challenger |
| `operator` | Run an allowlisted evidence command; read champion and audit |
| `promoter` | Evaluate, promote, roll back; read champion |
| `auditor` | Read champion and audit |

Bootstrap creates one distinct subject per role. Challenger producer and
promoter must remain different subjects when separation of duties is enabled.

## Operational routes

| Method and path | Authentication | Meaning |
|---|---|---|
| `GET /healthz` | None | Process is alive; does not prove dependencies |
| `GET /readyz` | None | Cheap storage probe plus evidence/benchmark configuration presence; does not execute workers |
| `GET /metrics` | None at app layer | Prometheus metrics; expose only on a monitoring network |

Operational routes use a small semaphore separate from normal work. Saturated
decision/tool capacity therefore cannot starve probes, while probe traffic is
still bounded. During SIGTERM drain, `/readyz` returns `503` with
`lifecycle=draining`; new work returns `503 draining`.

## Run a decision

`POST /v1/decisions/run` — `agent`

```json
{"simulations":64,"seed":7}
```

Optional `family` must equal `agent-decision-routing`. The response includes
`run_id`, `trajectory`, `feasible`, `abstained`, `reward`, model version, and an
authenticated experience receipt ID.

## Run evidence

`POST /v1/evidence/run` — `operator`

```json
{
  "command_id": "cmd0",
  "arguments": ["health"],
  "cwd": "/an/allowlisted/working/directory",
  "artifacts": []
}
```

`command_id` maps to a server-owned executable. The request cannot supply shell
text or an executable path. Arguments, output, duration, environment, working
directory, and artifacts are bounded by server policy.

## Train a challenger

`POST /v1/challengers/train` — `agent`

```json
{"episodes":12,"simulations":128}
```

The response contains `challenger_id`, the immutable `training_id` supplied as
the idempotency key, `model_version`, and the offline champion/challenger
promotion report. Identical deterministic training runs may produce the same
content-addressed challenger while retaining separate append-only provenance.

## Evaluate a policy artifact

`POST /v1/benchmarks/evaluate` — `promoter`

```json
{"challenger_id":"policy-<sha256>"}
```

The response contains a short-lived authenticated `receipt_id`, suite digest,
candidate fingerprint, pass/fail counts, and normalized score. Attempts are
durably limited per tenant, artifact, suite, and time window.

## Promote a challenger

`POST /v1/challengers/{challenger_id}/promote` — `promoter`

First promotion:

```json
{
  "reason": "reviewed local alpha gate",
  "hidden_benchmark_receipt_id": "<challenger receipt>"
}
```

When a champion exists, evaluate it on the same current suite and also supply:

```json
{"champion_hidden_benchmark_receipt_id":"<champion receipt>"}
```

Promotion requires current signed receipts, artifact binding, the absolute
threshold, no hidden regression, offline hard gates, separation of duties, and
an atomic champion compare-and-swap.

## Read and roll back the champion

- `GET /v1/families/agent-decision-routing/champion` — `operator`, `promoter`, or
  `auditor`.
- `POST /v1/families/agent-decision-routing/rollback` — `promoter`.

Rollback body:

```json
{"reason":"canary regression"}
```

Rollback creates another audited generation. It does not delete the rejected
artifact or reverse external side effects.

## Read audit events

`GET /v1/audit?after=0&limit=100` — `operator` or `auditor`.

Results are tenant-scoped. `limit` is bounded to 1–500.

## Errors

Errors use this shape and include an `X-Request-ID` response header:

```json
{
  "error": {"code":"invalid_request","message":"..."},
  "request_id": "..."
}
```

Common statuses are `400` invalid request, `401` unauthenticated, `403`
forbidden, `404` not found, `409` conflict/idempotency mismatch, `413` body too
large, `429` budget exhausted, and `503` overloaded or unready.
