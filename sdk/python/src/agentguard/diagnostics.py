from __future__ import annotations

import threading
from typing import Any


class Diagnostics:
    """Thread-safe counters exposed without adding a diagnostics HTTP server."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._counters: dict[str, int] = {}
        self._last_error: str | None = None

    def increment(self, name: str, amount: int = 1) -> None:
        with self._lock:
            self._counters[name] = self._counters.get(name, 0) + amount

    def error(self, message: str) -> None:
        with self._lock:
            self._last_error = message
            self._counters["errors"] = self._counters.get("errors", 0) + 1

    def snapshot(self, spool_stats: dict[str, Any] | None = None) -> dict[str, Any]:
        with self._lock:
            result: dict[str, Any] = dict(self._counters)
            result["last_exporter_error"] = self._last_error
        result.update(spool_stats or {})
        return result

