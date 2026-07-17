"""Small dependency-free Prometheus metrics registry."""

from __future__ import annotations

from collections import defaultdict
import hashlib
from threading import Lock
import time


class Metrics:
    def __init__(self) -> None:
        self._lock = Lock()
        self._counters: dict[tuple[str, tuple[tuple[str, str], ...]], float] = defaultdict(float)
        self._started = time.monotonic()

    def increment(self, name: str, value: float = 1.0, **labels: str) -> None:
        if value < 0:
            raise ValueError("counter increments must be nonnegative")
        safe_labels = {
            str(key): (
                "tenant-"
                + hashlib.sha256(str(value).encode("utf-8")).hexdigest()[:12]
                if str(key) == "tenant"
                else str(value)
            )
            for key, value in labels.items()
        }
        key = (name, tuple(sorted(safe_labels.items())))
        with self._lock:
            self._counters[key] += value

    def render(self) -> str:
        lines = ["# TYPE agent_tree_rl_uptime_seconds gauge"]
        lines.append(f"agent_tree_rl_uptime_seconds {time.monotonic() - self._started:.3f}")
        with self._lock:
            items = sorted(self._counters.items())
        for (name, labels), value in items:
            metric = f"agent_tree_rl_{name}"
            rendered_labels = ""
            if labels:
                pairs = ",".join(
                    f'{key}="{_escape(label)}"' for key, label in labels
                )
                rendered_labels = "{" + pairs + "}"
            lines.append(f"{metric}{rendered_labels} {value:g}")
        return "\n".join(lines) + "\n"


def _escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace("\n", "\\n").replace('"', '\\"')
