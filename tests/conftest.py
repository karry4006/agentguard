import os
import sys

ROOT = os.path.dirname(os.path.dirname(__file__))
sys.path.insert(0, os.path.join(ROOT, "sdk", "python", "src"))
sys.path.insert(0, os.path.join(ROOT, "server", "src"))

os.environ.setdefault("AGENTGUARD_DATABASE_URL", "sqlite:///./test-agentguard.db")
os.environ.setdefault("AGENTGUARD_KEY_PEPPER", "test-only-agentguard-pepper")
os.environ.setdefault("AGENTGUARD_INTEGRITY_KEY", "test-only-agentguard-integrity-key-32-bytes!!")

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from fastapi.testclient import TestClient

from agentguard_server.api.routes import db_session as api_db_session
from agentguard_server.db.base import Base
from agentguard_server.main import app
from agentguard_server.models import telemetry  # noqa: F401
from agentguard_server.services.auth import create_api_key, create_tenant
from agentguard_server.services.rate_limit import rate_limiter
from uuid import uuid4


@pytest.fixture(autouse=True)
def isolate_process_rate_limits():
    rate_limiter.reset()
    yield
    rate_limiter.reset()


@pytest.fixture()
def db_session(tmp_path, monkeypatch):
    engine = create_engine(f"sqlite:///{tmp_path / 'agentguard.db'}", connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine, expire_on_commit=False)()
    yield session
    session.close()
    engine.dispose()


@pytest.fixture()
def client(db_session):
    def override():
        yield db_session
    app.dependency_overrides[api_db_session] = override
    tenant = create_tenant(db_session, f"shared-{uuid4().hex[:12]}", "Shared test tenant")
    _, api_key = create_api_key(db_session, tenant, ["ingest:write", "traces:read"], "shared-test", os.environ["AGENTGUARD_KEY_PEPPER"])
    test_client = TestClient(app, raise_server_exceptions=False)
    test_client.headers.update({"Authorization": f"Bearer {api_key}"})
    yield test_client
    app.dependency_overrides.clear()
