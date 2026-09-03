# Safe replay demo

Run `python examples/replay_demo/run.py`. It builds a real V4 replay plan for
the allowlisted deterministic weather simulator. Replay defaults to
`dry_run`, reports `SIMULATE` and `MATCH`, and performs zero external side
effects. The disposable database is cleaned up automatically.

