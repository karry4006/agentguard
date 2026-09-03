from dataclasses import dataclass
import os
from urllib.parse import urlparse


def _bool(value: str | None, default: bool = False) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class AgentGuardConfig:
    ingest_url: str = "http://localhost:8000/v1/ingest"
    api_key: str | None = None
    capture_content: bool = False
    queue_size: int = 1000
    batch_size: int = 50
    flush_interval_seconds: float = 0.5
    max_retries: int = 3
    spool_enabled: bool = True
    spool_path: str | None = None
    spool_max_bytes: int = 50 * 1024 * 1024
    spool_max_events: int = 10000
    shutdown_timeout_seconds: float = 5.0
    auth_cooldown_seconds: float = 30.0
    allow_insecure_http: bool = False

    def __post_init__(self) -> None:
        parsed = urlparse(self.ingest_url)
        host = (parsed.hostname or "").lower()
        loopback = host in {"localhost", "127.0.0.1", "::1"}
        if parsed.scheme not in {"http", "https"}:
            raise ValueError("AGENTGUARD_INGEST_URL must use http or https")
        if parsed.scheme == "http" and not loopback and not self.allow_insecure_http:
            raise ValueError("HTTPS is required for non-loopback AgentGuard endpoints")

    @classmethod
    def from_env(cls) -> "AgentGuardConfig":
        return cls(
            ingest_url=os.getenv("AGENTGUARD_INGEST_URL", cls.ingest_url),
            api_key=os.getenv("AGENTGUARD_API_KEY"),
            capture_content=_bool(os.getenv("AGENTGUARD_CAPTURE_CONTENT")),
            queue_size=int(os.getenv("AGENTGUARD_QUEUE_SIZE", str(cls.queue_size))),
            batch_size=int(os.getenv("AGENTGUARD_BATCH_SIZE", str(cls.batch_size))),
            flush_interval_seconds=float(os.getenv("AGENTGUARD_FLUSH_INTERVAL_SECONDS", str(cls.flush_interval_seconds))),
            max_retries=int(os.getenv("AGENTGUARD_MAX_RETRIES", str(cls.max_retries))),
            spool_enabled=_bool(os.getenv("AGENTGUARD_SPOOL_ENABLED"), True),
            spool_path=os.getenv("AGENTGUARD_SPOOL_PATH") or None,
            spool_max_bytes=int(os.getenv("AGENTGUARD_SPOOL_MAX_BYTES", str(cls.spool_max_bytes))),
            spool_max_events=int(os.getenv("AGENTGUARD_SPOOL_MAX_EVENTS", str(cls.spool_max_events))),
            shutdown_timeout_seconds=float(os.getenv("AGENTGUARD_SHUTDOWN_TIMEOUT_SECONDS", str(cls.shutdown_timeout_seconds))),
            auth_cooldown_seconds=float(os.getenv("AGENTGUARD_AUTH_COOLDOWN_SECONDS", str(cls.auth_cooldown_seconds))),
            allow_insecure_http=_bool(os.getenv("AGENTGUARD_ALLOW_INSECURE_HTTP")),
        )
