from __future__ import annotations

import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from examples.phase3_support import disposable_session, ingest_fixture
from agentguard_server.services.replay import build_replay_plan


def main() -> None:
    trace_id = "phase3-replay-demo"
    with disposable_session() as (db, tenant):
        ingest_fixture(db, tenant.id, trace_id)
        plan = build_replay_plan(db, tenant.id, trace_id)
        step = plan.steps[0]
        print(f"trace_id={trace_id}")
        print("mode=dry_run")
        print(f"decision={step.decision.value}")
        print(f"tool={step.tool_name}")
        print(f"comparison={step.comparison_status.value}")
        print("external_side_effects=0")
        print("cleanup=automatic_disposable_database")


if __name__ == "__main__":
    main()
