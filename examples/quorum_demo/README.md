# Multi-witness quorum demo

Run `python examples/quorum_demo/run.py`. It exercises the real V20 local
quorum evaluator: witnesses A and B meet threshold while C is unavailable,
then a valid C `REMOTE_AHEAD` receipt causes destructive work to be blocked.
Receipts and keys exist only in memory.

