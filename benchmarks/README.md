# Benchmarks

Run from the repository root:

```powershell
python benchmarks/run_sdk.py
python benchmarks/run_ingest.py
python benchmarks/run_query.py
python benchmarks/run_quorum.py
```

Each command executes the real local seam it names and emits one JSON record.
Results are machine-dependent; the committed result records include the exact
environment and commit. CI executes these commands as a smoke check only and
does not enforce performance thresholds.
