from functools import lru_cache

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from agentguard_server.config import get_settings


@lru_cache
def get_engine():
    settings = get_settings()
    url = settings.database_url
    connect_args = {"check_same_thread": False} if url.startswith("sqlite") else {}
    if not url.startswith("sqlite"):
        connect_args = {
            "connect_timeout": int(settings.db_connect_timeout_seconds),
            "options": f"-c statement_timeout={settings.db_statement_timeout_ms}",
        }
        return create_engine(url, future=True, pool_pre_ping=True, pool_size=settings.db_pool_size,
                             max_overflow=settings.db_max_overflow, pool_timeout=settings.db_pool_timeout_seconds,
                             connect_args=connect_args)
    return create_engine(url, future=True, pool_pre_ping=True, connect_args=connect_args)


@lru_cache
def get_session_factory():
    return sessionmaker(bind=get_engine(), autoflush=False, expire_on_commit=False)


def dispose_engine() -> None:
    if get_engine.cache_info().currsize:
        get_engine().dispose()
