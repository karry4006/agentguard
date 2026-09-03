# Operations

Health endpoints are intended for local and deployment probes:

    curl.exe http://127.0.0.1:8000/health
    curl.exe http://127.0.0.1:8000/health/live

Monitor ingest rejection rates, queue and spool pressure, database capacity,
integrity verification failures, archive lag, witness disagreement, key
rotation age, and replay quarantine. Back up PostgreSQL and encryption
material together under separate access controls, and rehearse restore and
verification.

Use docker compose stop for a safe local pause. Do not remove shared volumes
or run destructive cleanup commands as part of routine diagnosis. See the
existing incident, retention, disaster-recovery, and production-deployment
documents for detailed runbooks.
