from __future__ import annotations

import json
import time

from agentguard_server.services.ingestion import ingest_events
from support import disposable_db, summary
from examples.phase3_support import fixture_events


def main() -> None:
    engine, factory = disposable_db()
    with factory() as db:
        tenant = __import__("agentguard_server.services.auth", fromlist=["get_or_create_local_tenant"]).get_or_create_local_tenant(db)
        batches, traces = 10, 10
        samples = []
        accepted = 0
        for batch in range(batches):
            events = []
            for index in range(traces):
                events.extend(fixture_events(f"ingest-{batch}-{index}"))
            started = time.perf_counter(); result = ingest_events(db, events, tenant.id, capture_content=True)
            samples.append((time.perf_counter() - started) * 1000); accepted += result[0]
    engine.dispose()
    elapsed = sum(samples) / 1000
    print(json.dumps({"benchmark": "server_ingestion", "batches": batches, "traces": batches * traces,
                      "events": accepted, "latency": summary(samples), "events_per_second": round(accepted / elapsed, 2),
                      "notes": "SQLite StaticPool, real sanitize/canonicalize/integrity ingestion."}, sort_keys=True))


if __name__ == "__main__":
    main()
