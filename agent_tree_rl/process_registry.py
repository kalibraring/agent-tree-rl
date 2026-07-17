"""Exact, thread-safe ownership and cancellation of service subprocess groups."""

from __future__ import annotations

from dataclasses import dataclass
import os
import signal
import subprocess
from threading import RLock
import time
from typing import Any


class ProcessRegistryClosed(RuntimeError):
    """The service crossed its cancellation boundary and may not spawn work."""


@dataclass(frozen=True)
class CancellationReport:
    registered: int
    term_signalled: int
    kill_signalled: int
    remaining: int


@dataclass(frozen=True)
class _Entry:
    process: subprocess.Popen[bytes]
    process_group_id: int | None


class ActiveProcessRegistry:
    """Own isolated process groups from spawn through kill and reap.

    Spawn and cancellation are serialized, closing the race where shutdown
    snapshots active work while an admitted request is creating a child. The
    registry signals only process groups it created with ``start_new_session``;
    normal cleanup signals every member that remains in the owned process group
    before the leader is reaped, preventing PID/PGID reuse from redirecting a
    later cancellation signal. A deliberately daemonizing child can leave that
    group; production custom workers require cgroup/container job containment.
    """

    def __init__(self) -> None:
        self._lock = RLock()
        self._entries: dict[int, _Entry] = {}
        self._accepting = True

    def spawn(self, args: list[str], **kwargs: Any) -> subprocess.Popen[bytes]:
        with self._lock:
            if not self._accepting:
                raise ProcessRegistryClosed("subprocess registry is draining")
            isolated = os.name == "posix"
            if "start_new_session" in kwargs:
                raise ValueError("process registry owns start_new_session")
            process = subprocess.Popen(
                args,
                start_new_session=isolated,
                **kwargs,
            )
            entry = _Entry(
                process=process,
                process_group_id=process.pid if isolated else None,
            )
            # A Python signal handler can run re-entrantly while Popen waits for
            # exec. If cancellation closed the registry, kill this late child
            # before it can escape the ownership boundary.
            if not self._accepting:
                self._signal(entry, signal.SIGKILL)
                process.wait(timeout=2)
                raise ProcessRegistryClosed("subprocess registry is draining")
            self._entries[id(process)] = entry
            return process

    def kill_and_reap(
        self,
        process: subprocess.Popen[bytes],
        *,
        timeout_seconds: float = 2,
    ) -> int:
        """Kill one owned group, reap its leader, and release ownership."""

        with self._lock:
            entry = self._entries.get(id(process))
            if entry is None:
                # Service-wide cancellation may already have reaped it.
                return process.returncode if process.returncode is not None else -1
            self._signal(entry, signal.SIGKILL)
            returncode = process.wait(timeout=timeout_seconds)
            self._entries.pop(id(process), None)
            return int(returncode)

    def signal(self, process: subprocess.Popen[bytes], signum: int) -> None:
        """Signal one process group only while this registry still owns it."""

        with self._lock:
            entry = self._entries.get(id(process))
            if entry is not None:
                self._signal(entry, signum)

    def cancel_all(self, *, timeout_seconds: float) -> CancellationReport:
        """Close spawning, TERM then KILL every exactly owned process group."""

        if timeout_seconds <= 0:
            raise ValueError("cancellation timeout must be positive")
        with self._lock:
            self._accepting = False
            entries = list(self._entries.values())
            for entry in entries:
                self._signal(entry, signal.SIGTERM)

            # Do not poll/wait (and therefore reap) a group leader before the
            # final owned signal. Keeping the leader waitable prevents its
            # PID/PGID from being reused for an unrelated process group.
            term_window = min(2.0, timeout_seconds * 0.4)
            if entries:
                time.sleep(term_window)
            for entry in entries:
                self._signal(entry, signal.SIGKILL)

            final_deadline = time.monotonic() + max(0.0, timeout_seconds - term_window)
            remaining: list[_Entry] = []
            for entry in entries:
                wait = max(0.0, final_deadline - time.monotonic())
                try:
                    entry.process.wait(timeout=wait)
                    self._entries.pop(id(entry.process), None)
                except subprocess.TimeoutExpired:
                    remaining.append(entry)
            return CancellationReport(
                registered=len(entries),
                term_signalled=len(entries),
                kill_signalled=len(entries),
                remaining=len(remaining),
            )

    @staticmethod
    def _signal(entry: _Entry, signum: int) -> None:
        try:
            if entry.process_group_id is not None:
                os.killpg(entry.process_group_id, signum)
            elif signum == signal.SIGTERM:
                entry.process.terminate()
            else:
                entry.process.kill()
        except ProcessLookupError:
            pass
        except PermissionError:
            # Some POSIX kernels report EPERM for an exited session leader
            # that is still waitable. The unreaped Popen keeps its PID exact;
            # signal that owned leader as a bounded fallback.
            try:
                entry.process.send_signal(signum)
            except ProcessLookupError:
                pass

__all__ = [
    "ActiveProcessRegistry",
    "CancellationReport",
    "ProcessRegistryClosed",
]
