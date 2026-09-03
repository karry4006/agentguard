from __future__ import annotations

import json
import logging
import os
import secrets
import sqlite3
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from .base import SpoolEvent, SpoolStats
from .models import SPOOL_SCHEMA

logger = logging.getLogger("agentguard.spool")
_secure_random = secrets.SystemRandom()


def default_spool_path() -> Path:
    return Path.home() / ".agentguard" / "spool.sqlite3"


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat()


def _parse(value: str | None) -> datetime | None:
    return datetime.fromisoformat(value) if value else None


class SQLiteSpool:
    """Thread-safe SQLite WAL spool with crash recovery and bounded storage."""

    def __init__(self, path: str | Path | None = None, *, max_bytes: int = 50 * 1024 * 1024, max_events: int = 10000, max_retries: int = 3):
        self.path = Path(path) if path and str(path) != ":memory:" else Path(":memory:")
        self._sqlite_path = ":memory:" if str(self.path) == ":memory:" else str(self.path)
        self.max_bytes = max(0, max_bytes)
        self.max_events = max(0, max_events)
        self.max_retries = max(0, max_retries)
        self._lock = threading.RLock()
        if self._sqlite_path != ":memory:":
            self.path.parent.mkdir(parents=True, exist_ok=True)
            try:
                os.chmod(self.path.parent, 0o700)
            except OSError:
                logger.debug("AgentGuard could not harden spool directory permissions")
        self._connection = sqlite3.connect(self._sqlite_path, timeout=30, check_same_thread=False)
        self._connection.row_factory = sqlite3.Row
        with self._lock:
            self._connection.executescript(SPOOL_SCHEMA)
            self._connection.execute("PRAGMA journal_mode=WAL")
            self._connection.execute("PRAGMA synchronous=NORMAL")
            self._connection.execute("UPDATE spool_events SET status='pending', next_attempt_at=NULL WHERE status='inflight'")
            self._connection.commit()
            if self._sqlite_path != ":memory:":
                try:
                    os.chmod(self.path, 0o600)
                except OSError:
                    logger.debug("AgentGuard could not harden spool file permissions")

    def put(self, event: dict[str, Any]) -> bool:
        event_type = str(event.get("event_type") or "unknown")
        source_event_id = str(event.get("event_id") or "")
        if not source_event_id:
            return False
        # Start/end events share an upstream ID; include the type for a stable
        # spool key matching the server's idempotency semantics.
        event_id = f"{event_type}:{source_event_id}"
        payload = json.dumps(event, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
        payload_bytes = len(payload.encode("utf-8"))
        with self._lock:
            try:
                if self._connection.execute("SELECT 1 FROM spool_events WHERE event_id=?", (event_id,)).fetchone():
                    return False
                used_events, used_bytes = self._connection.execute("SELECT count(*), coalesce(sum(payload_bytes), 0) FROM spool_events").fetchone()
                if used_events >= self.max_events or used_bytes + payload_bytes > self.max_bytes:
                    self._increment_rejected()
                    return False
                self._connection.execute(
                    "INSERT INTO spool_events(event_id,event_type,payload,payload_bytes,created_at,status) VALUES(?,?,?,?,?, 'pending')",
                    (event_id, event_type, payload, payload_bytes, _iso(_now())),
                )
                self._connection.commit()
                return True
            except Exception:
                self._connection.rollback()
                raise

    def get_batch(self, limit: int) -> list[SpoolEvent]:
        if limit <= 0:
            return []
        now = _iso(_now())
        with self._lock:
            try:
                rows = self._connection.execute(
                    "SELECT * FROM spool_events WHERE status='pending' AND (next_attempt_at IS NULL OR next_attempt_at<=?) ORDER BY sequence LIMIT ?",
                    (now, limit),
                ).fetchall()
                if not rows:
                    return []
                attempt_at = _now()
                ids = [row["event_id"] for row in rows]
                self._connection.executemany(
                    "UPDATE spool_events SET status='inflight', attempt_count=attempt_count+1, last_attempt_at=?, next_attempt_at=NULL WHERE event_id=?",
                    [(_iso(attempt_at), event_id) for event_id in ids],
                )
                self._connection.commit()
                return [self._row_to_event(row, status="inflight", attempt_count=row["attempt_count"] + 1, last_attempt_at=attempt_at) for row in rows]
            except Exception:
                self._connection.rollback()
                raise

    def acknowledge(self, event_ids: list[str]) -> None:
        if not event_ids:
            return
        with self._lock:
            try:
                self._connection.executemany("DELETE FROM spool_events WHERE event_id=?", [(event_id,) for event_id in event_ids])
                self._connection.commit()
            except Exception:
                self._connection.rollback()
                raise

    def retry(self, event_ids: list[str], error: str) -> None:
        if not event_ids:
            return
        safe_error = str(error)[:2000]
        now = _now()
        with self._lock:
            try:
                for event_id in event_ids:
                    row = self._connection.execute("SELECT attempt_count FROM spool_events WHERE event_id=?", (event_id,)).fetchone()
                    if row is None:
                        continue
                    attempts = int(row["attempt_count"])
                    if attempts >= self.max_retries:
                        self._connection.execute(
                            "UPDATE spool_events SET status='dead_letter', last_error=?, next_attempt_at=NULL WHERE event_id=?",
                            (safe_error, event_id),
                        )
                        continue
                    base_delay = min(60.0, 0.5 * (2 ** max(0, attempts - 1)))
                    delay = base_delay + _secure_random.uniform(0.0, base_delay * 0.25)
                    self._connection.execute(
                        "UPDATE spool_events SET status='pending', next_attempt_at=?, last_error=? WHERE event_id=?",
                        (_iso(now + timedelta(seconds=delay)), safe_error, event_id),
                    )
                self._connection.commit()
            except Exception:
                self._connection.rollback()
                raise

    def wake_pending(self) -> None:
        """Make retryable rows immediately eligible for an explicit force_flush."""
        with self._lock:
            try:
                self._connection.execute("UPDATE spool_events SET next_attempt_at=NULL WHERE status='pending'")
                self._connection.commit()
            except Exception:
                self._connection.rollback()
                raise

    def stats(self) -> SpoolStats:
        with self._lock:
            rows = self._connection.execute("SELECT status, count(*) AS count, coalesce(sum(payload_bytes),0) AS bytes FROM spool_events GROUP BY status").fetchall()
            values = {row["status"]: (row["count"], row["bytes"]) for row in rows}
            rejected = self._connection.execute("SELECT value FROM spool_meta WHERE key='rejected_events'").fetchone()
            return SpoolStats(
                pending=values.get("pending", (0, 0))[0],
                inflight=values.get("inflight", (0, 0))[0],
                dead_letter=values.get("dead_letter", (0, 0))[0],
                bytes=sum(item[1] for item in values.values()),
                rejected_events=int(rejected["value"]) if rejected else 0,
            )

    def close(self) -> None:
        with self._lock:
            try:
                self._connection.commit()
                self._connection.close()
            except Exception as exc:
                logger.warning("AgentGuard spool close failed: %s", exc)

    def _increment_rejected(self) -> None:
        self._connection.execute(
            "INSERT INTO spool_meta(key,value) VALUES('rejected_events','1') ON CONFLICT(key) DO UPDATE SET value=cast(value as integer)+1"
        )
        self._connection.commit()

    @staticmethod
    def _row_to_event(row: sqlite3.Row, *, status: str | None = None, attempt_count: int | None = None, last_attempt_at: datetime | None = None) -> SpoolEvent:
        return SpoolEvent(
            sequence=row["sequence"], event_id=row["event_id"], event_type=row["event_type"],
            payload=json.loads(row["payload"]), created_at=_parse(row["created_at"]),
            attempt_count=attempt_count if attempt_count is not None else row["attempt_count"],
            next_attempt_at=_parse(row["next_attempt_at"]),
            last_attempt_at=last_attempt_at or _parse(row["last_attempt_at"]),
            last_error=row["last_error"], status=status or row["status"],
        )
