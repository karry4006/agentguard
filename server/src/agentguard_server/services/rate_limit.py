"""Database-backed fixed-window rate limiting.

The public HTTP paths use TenantRateLimiter.allow_shared; the small legacy
in-memory adapter remains only for callers of the old unit-test API.
It is never an authority for server requests.
"""

from __future__ import annotations

from collections import deque
from datetime import datetime, timedelta, timezone
import hashlib
import logging
import re
import threading
import time
import uuid

from sqlalchemy import case, delete, func, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.orm import Session

from agentguard_server.models import DistributedRateLimitBucket

logger = logging.getLogger("agentguard.coordination")
_SAFE_BUCKET = re.compile(r"^[a-z0-9][a-z0-9:._-]{0,63}$")


class RateLimitStorageError(RuntimeError):
    """The authoritative rate-limit store could not make a decision."""


def database_now(db: Session) -> datetime:
    value = db.scalar(select(func.current_timestamp()))
    if isinstance(value, datetime):
        current = value
    else:
        current = datetime.fromisoformat(str(value))
    return current.replace(tzinfo=timezone.utc) if current.tzinfo is None else current.astimezone(timezone.utc)


def _window_start(now: datetime, window_seconds: int) -> datetime:
    epoch = int(now.timestamp())
    return datetime.fromtimestamp(epoch - (epoch % window_seconds), tz=timezone.utc)


def _bucket_hash(tenant_id: uuid.UUID | None, operation: str, bucket_type: str,
                 subject: str | None = None) -> str:
    identity = subject or str(tenant_id or "global")
    material = f"agentguard-v14|{bucket_type}|{operation}|{identity}"
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


class TenantRateLimiter:
    """Shared PostgreSQL limiter with a compatibility-only local adapter."""

    def __init__(self) -> None:
        self._legacy_lock = threading.Lock()
        self._legacy_windows: dict[tuple[uuid.UUID, str], deque[float]] = {}

    def allow(self, tenant_id: uuid.UUID, operation: str, limit: int,
              window_seconds: float) -> tuple[bool, float]:
        """Compatibility adapter for the pre-V14 direct unit-test API.

        HTTP dependencies do not call this method because it has no database
        handle. New code must call allow_shared.
        """
        now = time.monotonic()
        cutoff = now - max(0.001, window_seconds)
        key = (tenant_id, operation)
        with self._legacy_lock:
            window = self._legacy_windows.setdefault(key, deque())
            while window and window[0] <= cutoff:
                window.popleft()
            if len(window) >= max(1, limit):
                return False, max(0.001, window[0] + window_seconds - now)
            window.append(now)
            return True, 0.0

    def allow_shared(self, db: Session, tenant_id: uuid.UUID | None, operation: str,
                     limit: int, window_seconds: float, *,
                     bucket_type: str | None = None,
                     subject: str | None = None,
                     fail_closed: bool = True) -> tuple[bool, float]:
        if not isinstance(operation, str) or not _SAFE_BUCKET.fullmatch(operation):
            raise ValueError("invalid rate-limit operation")
        if bucket_type is None:
            bucket_type = operation
        if not isinstance(bucket_type, str) or not _SAFE_BUCKET.fullmatch(bucket_type):
            raise ValueError("invalid rate-limit bucket type")
        if not 1 <= int(limit) <= 100000 or not 1 <= int(window_seconds) <= 86400:
            raise ValueError("invalid rate-limit bounds")

        try:
            now = database_now(db)
            seconds = int(window_seconds)
            start = _window_start(now, seconds)
            digest = _bucket_hash(tenant_id, operation, bucket_type, subject)
            table = DistributedRateLimitBucket.__table__
            values = {
                "bucket_key_hash": digest,
                "window_start": start,
                "bucket_type": bucket_type,
                "window_seconds": seconds,
                "count": 1,
                "updated_at": now,
            }
            dialect = db.get_bind().dialect.name
            insert = pg_insert if dialect == "postgresql" else sqlite_insert
            statement = insert(DistributedRateLimitBucket).values(**values)
            statement = statement.on_conflict_do_update(
                index_elements=["bucket_key_hash", "window_start"],
                set_={
                    "count": case(
                        (table.c.count >= int(limit), int(limit) + 1),
                        else_=table.c.count + 1,
                    ),
                    "updated_at": now,
                    "window_seconds": seconds,
                    "bucket_type": bucket_type,
                },
            ).returning(table.c.count)
            count = int(db.execute(statement).scalar_one())
            db.commit()
            if count > int(limit):
                return False, max(0.001, (start + timedelta(seconds=seconds) - now).total_seconds())
            return True, 0.0
        except Exception as exc:
            db.rollback()
            logger.error(
                "coordination_operation=rate_limit result=storage_error operation=%s",
                operation,
            )
            if fail_closed:
                raise RateLimitStorageError("rate-limit coordination unavailable") from exc
            return True, 0.0

    def reset(self) -> None:
        """Clear only the compatibility adapter; database state is authoritative."""
        with self._legacy_lock:
            self._legacy_windows.clear()


def prune_expired_buckets(db: Session, *, older_than_seconds: int = 7200,
                          batch_size: int = 1000, now: datetime | None = None) -> int:
    """Maintenance-role helper for bounded cleanup; never called by request paths."""
    if older_than_seconds < 1 or not 1 <= batch_size <= 10000:
        raise ValueError("invalid rate-limit cleanup bounds")
    current = now or database_now(db)
    cutoff = current - timedelta(seconds=older_than_seconds)
    rows = list(db.execute(
        select(DistributedRateLimitBucket.bucket_key_hash, DistributedRateLimitBucket.window_start)
        .where(DistributedRateLimitBucket.window_start < cutoff)
        .order_by(DistributedRateLimitBucket.window_start)
        .limit(batch_size)
    ))
    if not rows:
        return 0
    removed = db.execute(delete(DistributedRateLimitBucket).where(
        DistributedRateLimitBucket.bucket_key_hash.in_([item[0] for item in rows]),
        DistributedRateLimitBucket.window_start.in_([item[1] for item in rows]),
    )).rowcount or 0
    db.commit()
    return int(removed)


rate_limiter = TenantRateLimiter()