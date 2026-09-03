from __future__ import annotations

import os
import sys
import time
from statistics import median

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path[:0] = [ROOT, os.path.join(ROOT, "server", "src"), os.path.join(ROOT, "sdk", "python", "src")]
os.environ.setdefault("AGENTGUARD_DATABASE_URL", "sqlite://")
os.environ.setdefault("AGENTGUARD_KEY_PEPPER", "phase3-benchmark-key-pepper")
os.environ.setdefault("AGENTGUARD_INTEGRITY_KEY", "phase3-benchmark-integrity-key-32-bytes!!")
os.environ.setdefault("AGENTGUARD_AUTH_ENABLED", "false")

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from agentguard_server.db.base import Base
from agentguard_server.models import EventLog  # noqa: F401
from agentguard_server.services.auth import get_or_create_local_tenant

from examples.phase3_support import fixture_events


def percentile(values: list[float], fraction: float) -> float:
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, int(round((len(ordered) - 1) * fraction))))
    return ordered[index]


def disposable_db():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    return engine, factory


def timing(fn, repeats: int) -> list[float]:
    values = []
    for _ in range(repeats):
        started = time.perf_counter()
        fn()
        values.append((time.perf_counter() - started) * 1000)
    return values


def summary(values: list[float]) -> dict[str, float]:
    return {"median_ms": round(median(values), 4), "p95_ms": round(percentile(values, .95), 4),
            "min_ms": round(min(values), 4), "max_ms": round(max(values), 4)}
