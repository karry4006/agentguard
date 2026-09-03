# Phase 3 benchmark environment

The committed benchmark record was produced on 2026-09-03 in the repository
working tree. The execution host reported Python 3.14.6. WMI access for exact
Windows OS, CPU, and RAM values was denied by the managed execution context;
those fields are therefore recorded as unavailable rather than inferred.

The service benchmarks use an in-memory SQLite `StaticPool`, and the SDK
benchmark uses the real SDK processor with a local exporter callback and
in-memory SQLite spool. No network, paid API, external witness, or Docker
database was used for these measurements.

For a release-grade rerun, record the output of:

```powershell
python --version
Get-CimInstance Win32_OperatingSystem | Select-Object Caption,Version,OSArchitecture
Get-CimInstance Win32_Processor | Select-Object -First 1 Name,NumberOfLogicalProcessors
Get-CimInstance Win32_ComputerSystem | Select-Object TotalPhysicalMemory
docker version
docker compose version
docker compose exec -T agentguard-postgres psql --version
git rev-parse HEAD
```
