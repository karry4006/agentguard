from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Protocol


@dataclass(frozen=True)
class SpoolEvent:
    sequence: int
    event_id: str
    event_type: str
    payload: dict[str, Any]
    created_at: datetime
    attempt_count: int
    next_attempt_at: datetime | None
    last_attempt_at: datetime | None
    last_error: str | None
    status: str


@dataclass(frozen=True)
class SpoolStats:
    pending: int
    inflight: int
    dead_letter: int
    bytes: int
    rejected_events: int = 0

    def as_dict(self) -> dict[str, int]:
        return {
            "pending_events": self.pending,
            "inflight_events": self.inflight,
            "dead_letter_events": self.dead_letter,
            "spool_bytes": self.bytes,
            "rejected_events": self.rejected_events,
        }


class EventSpool(Protocol):
    def put(self, event: dict[str, Any]) -> bool: ...
    def get_batch(self, limit: int) -> list[SpoolEvent]: ...
    def acknowledge(self, event_ids: list[str]) -> None: ...
    def retry(self, event_ids: list[str], error: str) -> None: ...
    def stats(self) -> SpoolStats: ...
    def close(self) -> None: ...

