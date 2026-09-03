from __future__ import annotations

import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from sqlalchemy import select

from examples.phase3_support import disposable_session, ingest_fixture
from agentguard_server.models import EventLog
from agentguard_server.services.integrity import verify_trace_integrity


def main() -> None:
    trace_id = "phase3-integrity-demo"
    with disposable_session() as (db, tenant):
        ingest_fixture(db, tenant.id, trace_id)
        before = verify_trace_integrity(db, tenant.id, trace_id)
        row = db.scalar(select(EventLog).where(EventLog.tenant_id == tenant.id, EventLog.trace_id == trace_id))
        payload = dict(row.payload_json)
        payload["data"] = dict(payload["data"])
        payload["data"]["demo_mutation"] = "disposable-only"
        row.payload_json = payload
        db.commit()
        after = verify_trace_integrity(db, tenant.id, trace_id)
        print(f"trace_id={trace_id}")
        print(f"before_mutation={before.status}")
        print(f"after_disposable_mutation={after.status}")
        print("v20_evidence_touched=0")
        print("cleanup=automatic_disposable_database")


if __name__ == "__main__":
    main()
