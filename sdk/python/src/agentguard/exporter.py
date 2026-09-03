from __future__ import annotations

import logging
import queue
import threading
import time
from collections.abc import Callable
from typing import Any

import httpx

from .config import AgentGuardConfig
from .diagnostics import Diagnostics
from .redaction import redact
from .spool import EventSpool, SQLiteSpool

logger = logging.getLogger("agentguard.exporter")


class AuthFailure(RuntimeError):
    pass


class HttpBatchExporter:
    """Durable, bounded, background HTTP exporter with at-least-once delivery."""

    def __init__(self, config: AgentGuardConfig | None = None, *, send_batch: Callable[[list[dict[str, Any]]], Any] | None = None, spool: EventSpool | None = None):
        self.config = config or AgentGuardConfig.from_env()
        self.diagnostics_state = Diagnostics()
        self._send_batch_override = send_batch
        if spool is not None:
            self.spool = spool
        else:
            try:
                self.spool = SQLiteSpool(
                    self.config.spool_path if self.config.spool_enabled else ":memory:",
                    max_bytes=self.config.spool_max_bytes,
                    max_events=self.config.spool_max_events,
                    max_retries=self.config.max_retries,
                )
            except Exception as exc:
                # A corrupt/unwritable durable spool must not crash the monitored agent.
                self.diagnostics_state.error(redact(str(exc)))
                logger.error("AgentGuard durable spool unavailable; using in-memory fallback: %s", redact(str(exc)))
                self.spool = SQLiteSpool(":memory:", max_retries=self.config.max_retries)
        self._wake_queue: queue.Queue[object] = queue.Queue(maxsize=max(1, self.config.queue_size))
        self._stop = object()
        self._stop_event = threading.Event()
        self._auth_blocked_until = 0.0
        self._draining = threading.Event()
        self._draining.set()
        self._worker = threading.Thread(target=self._run, name="agentguard-exporter", daemon=True)
        self._worker.start()

    @property
    def dropped_events(self) -> int:
        return self.diagnostics_state.snapshot().get("dropped_events", 0)

    def submit(self, event: dict[str, Any]) -> bool:
        """Persist first; wakeup queue overflow never discards a persisted event."""
        if not self.config.spool_enabled and self._wake_queue.full():
            self.diagnostics_state.increment("dropped_events")
            logger.warning("AgentGuard in-memory exporter queue is full; dropped event")
            return False
        safe_event = redact(event, capture_content=self.config.capture_content)
        try:
            stored = self.spool.put(safe_event)
        except Exception as exc:
            self.diagnostics_state.error(redact(str(exc)))
            logger.warning("AgentGuard spool write failed; event was not persisted: %s", exc)
            return False
        if not stored:
            stats = self.spool.stats()
            self.diagnostics_state.increment("dropped_events")
            logger.warning("AgentGuard spool rejected event (pending=%d bytes=%d)", stats.pending, stats.bytes)
            return False
        self.diagnostics_state.increment("queued_events")
        try:
            self._wake_queue.put_nowait(object())
        except queue.Full:
            self.diagnostics_state.increment("coalesced_wakeups")
        return True

    def force_flush(self, timeout: float = 5.0) -> bool:
        """Wake the worker and wait for its current delivery attempt to finish."""
        wake_pending = getattr(self.spool, "wake_pending", None)
        if wake_pending:
            try:
                wake_pending()
            except Exception as exc:
                self.diagnostics_state.error(redact(str(exc)))
                logger.warning("AgentGuard could not wake pending spool rows: %s", redact(str(exc)))
        # A submit or timer may already have a worker task in flight. Adding a
        # second wake in that case can immediately retry the same failed batch
        # twice and make bounded shutdown race the HTTP timeout.
        wake = True
        if self._wake_queue.unfinished_tasks == 0 and self._draining.is_set():
            wake = self._wake()
        if not wake:
            return False
        deadline = time.monotonic() + timeout
        while (self._wake_queue.unfinished_tasks or not self._draining.is_set()) and time.monotonic() < deadline:
            time.sleep(0.01)
        return self._wake_queue.unfinished_tasks == 0 and self._draining.is_set()

    def shutdown(self, timeout: float | None = None) -> None:
        timeout = self.config.shutdown_timeout_seconds if timeout is None else timeout
        self.force_flush(timeout)
        self._stop_event.set()
        try:
            self._wake_queue.put_nowait(self._stop)
        except queue.Full:
            pass
        self._worker.join(timeout=max(0.0, timeout))
        if self._worker.is_alive():
            # Never close the SQLite connection underneath a still-running
            # worker. The daemon worker will finish its bounded HTTP attempt;
            # retained rows remain durable for the next exporter process.
            logger.warning("AgentGuard exporter worker did not stop before shutdown timeout; spool remains open")
            return
        self.spool.close()

    def diagnostics(self) -> dict[str, Any]:
        try:
            stats = self.spool.stats().as_dict()
        except Exception as exc:
            self.diagnostics_state.error(redact(str(exc)))
            stats = {}
        return self.diagnostics_state.snapshot(stats)

    def _wake(self) -> bool:
        try:
            self._wake_queue.put_nowait(object())
            return True
        except queue.Full:
            return False

    def _run(self) -> None:
        while True:
            try:
                signal = self._wake_queue.get(timeout=self.config.flush_interval_seconds)
            except queue.Empty:
                self._drain_due()
                if self._stop_event.is_set():
                    return
                continue
            try:
                if signal is not self._stop:
                    self._drain_due()
                else:
                    self._drain_due()
                    return
            finally:
                self._wake_queue.task_done()
            if self._stop_event.is_set():
                self._drain_due()
                return

    def _drain_due(self) -> None:
        self._draining.clear()
        try:
            self._drain_due_impl()
        finally:
            self._draining.set()

    def _drain_due_impl(self) -> None:
        if time.monotonic() < self._auth_blocked_until:
            return
        while True:
            try:
                batch = self.spool.get_batch(self.config.batch_size)
            except Exception as exc:
                self.diagnostics_state.error(redact(str(exc)))
                logger.warning("AgentGuard spool read failed: %s", exc)
                return
            if not batch:
                return
            event_ids = [event.event_id for event in batch]
            try:
                response = self._deliver([event.payload for event in batch])
                failed = self._failed_ids(response, event_ids)
                acknowledged = [event_id for event_id in event_ids if event_id not in failed]
                self.spool.acknowledge(acknowledged)
                if failed:
                    self.spool.retry(failed, "server rejected event")
                    self.diagnostics_state.increment("retry_count", len(failed))
                self.diagnostics_state.increment("delivered_events", len(acknowledged))
            except Exception as exc:  # fail-open: retain inflight rows for retry/recovery
                safe_error = redact(str(exc))
                try:
                    self.spool.retry(event_ids, safe_error)
                except Exception as spool_exc:
                    self.diagnostics_state.error(redact(str(spool_exc)))
                    logger.warning("AgentGuard could not record exporter failure: %s", redact(str(spool_exc)))
                self.diagnostics_state.increment("retry_count", len(event_ids))
                self.diagnostics_state.error(safe_error)
                if isinstance(exc, AuthFailure):
                    self._auth_blocked_until = time.monotonic() + max(0.0, self.config.auth_cooldown_seconds)
                    self.diagnostics_state.increment("auth_failures")
                    logger.warning("AgentGuard authentication rejected; delivery paused for %.1fs", self.config.auth_cooldown_seconds)
                logger.warning("AgentGuard export failed; events retained for retry: %s", safe_error)
                return

    def _deliver(self, batch: list[dict[str, Any]]) -> Any:
        if self._send_batch_override:
            return self._send_batch_override(batch)
        headers = {"Content-Type": "application/json"}
        if self.config.api_key:
            headers["Authorization"] = f"Bearer {self.config.api_key}"
        response = httpx.post(
            self.config.ingest_url,
            json={"schema_version": "0.1", "events": batch},
            headers=headers,
            timeout=5.0,
        )
        if response.status_code in {401, 403}:
            raise AuthFailure(f"HTTP {response.status_code} authentication/authorization failure")
        response.raise_for_status()
        return response.json()

    @staticmethod
    def _failed_ids(response: Any, event_ids: list[str]) -> set[str]:
        if not isinstance(response, dict):
            return set()
        failed = response.get("failed")
        if not isinstance(failed, list):
            return set()
        return {str(event_id) for event_id in failed if str(event_id) in event_ids}
