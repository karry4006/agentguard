# Failure analysis demo

Run `python examples/failure_demo/run.py`. It ingests a deterministic timeout
trace and runs the real deterministic-first analysis service. The expected
category is `TIMEOUT`; no model or paid API is used. The in-memory database is
discarded automatically when the process exits.

