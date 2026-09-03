from __future__ import annotations

import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from agentguard_server.services.evaluation import CaseMetrics, evaluate_population


def main() -> None:
    baseline = [CaseMetrics(f"case-{i}", f"baseline-{i}", "valid", True, tool_calls=1, span_count=2, duration_seconds=1.0) for i in range(3)]
    candidate = [CaseMetrics("case-0", "candidate-0", "valid", True, tool_calls=1, span_count=2, duration_seconds=1.1),
                 CaseMetrics("case-1", "candidate-1", "valid", False, ("TIMEOUT",), tool_calls=1, span_count=2, duration_seconds=3.0),
                 CaseMetrics("case-2", "candidate-2", "valid", True, tool_calls=2, span_count=3, duration_seconds=1.2)]
    result = evaluate_population(baseline, candidate, {"minimum_cases": 3, "rules": [
        {"metric": "candidate_success_rate", "operator": ">=", "baseline_metric": "baseline_success_rate", "offset": 0.0},
    ]})
    print("suite=phase3-regression-demo")
    print(f"decision={result.decision}")
    print(f"baseline_success_rate={result.metrics['baseline_success_rate']:.3f}")
    print(f"candidate_success_rate={result.metrics['candidate_success_rate']:.3f}")
    print(f"detected_diffs={len(result.case_diffs)}")
    print("cleanup=automatic_in_memory_inputs")


if __name__ == "__main__":
    main()
