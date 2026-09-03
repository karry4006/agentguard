# Evidence integrity demo

Run `python examples/integrity_demo/run.py`. The real V20-compatible evidence
verification is first valid, then a disposable event payload is mutated and
verification becomes invalid. The mutation is limited to a temporary demo
database; sealed V20 evidence is never modified.

