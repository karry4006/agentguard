# Regression evaluation demo

Run `python examples/regression_demo/run.py`. It compares paired baseline and
candidate `CaseMetrics` through the real deterministic evaluation engine. The
candidate timeout lowers success rate, so the configured gate returns `FAIL`.
All inputs are in memory and contain no model calls.

