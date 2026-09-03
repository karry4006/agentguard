from __future__ import annotations

import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from examples.phase3_support import disposable_session, ingest_fixture
from agentguard_server.services.analysis import analyze_trace


def main() -> None:
    trace_id = "phase3-failure-demo"
    with disposable_session() as (db, tenant):
        ingest_fixture(db, tenant.id, trace_id, failed=True)
        report, _ = analyze_trace(db, tenant.id, trace_id)
        categories = sorted({finding.category.value for finding in report.findings})
        print(f"trace_id={trace_id}")
        print(f"analysis_status={report.deterministic_status}")
        print(f"failure_categories={','.join(categories)}")
        print(f"findings={len(report.findings)}")
        print("cleanup=automatic_disposable_database")


if __name__ == "__main__":
    main()
