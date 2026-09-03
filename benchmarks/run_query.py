from __future__ import annotations

import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import json

from agentguard_server.services.ingestion import ingest_events
from agentguard_server.services.query import get_trace, list_traces, make_span_tree
from examples.phase3_support import fixture_events
from support import disposable_db, summary, timing


def main() -> None:
    engine, factory = disposable_db()
    with factory() as db:
        tenant = __import__("agentguard_server.services.auth", fromlist=["get_or_create_local_tenant"]).get_or_create_local_tenant(db)
        for index in range(50):
            ingest_events(db, fixture_events(f"query-{index}"), tenant.id, capture_content=True)
        list_samples = timing(lambda: list_traces(db, tenant.id, limit=25), 50)
        detail_samples = timing(lambda: get_trace(db, "query-25", tenant.id), 50)
        trace, spans = get_trace(db, "query-25", tenant.id)
        tree_samples = timing(lambda: make_span_tree(spans), 50)
    engine.dispose()
    print(json.dumps({"benchmark": "server_query", "seeded_traces": 50,
                      "list_traces": summary(list_samples), "get_trace": summary(detail_samples),
                      "make_span_tree": summary(tree_samples),
                      "notes": "SQLite StaticPool, real query service and span-tree projection."}, sort_keys=True))


if __name__ == "__main__":
    main()
