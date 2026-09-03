"""V9 operational safety and release metadata regression tests."""

from pathlib import Path
import os

import pytest

from agentguard_server.cli import main as cli_main
from agentguard_server.config import Settings, get_settings, validate_configuration
from agentguard_server.provenance import build_metadata, migration_head


def _safe_settings(**overrides):
    values = {
        "database_url": "sqlite:///./v9-test.db",
        "key_pepper": "v9-test-pepper-only",
        "integrity_key": "v9-test-integrity-key-with-at-least-32-bytes",
        "environment": "test",
        "_env_file": None,
    }
    values.update(overrides)
    return Settings(**values)


def test_build_metadata_is_secret_free_and_reports_current_head():
    metadata = build_metadata()
    assert set(metadata) == {
        "agentguard_version", "git_commit", "build_timestamp", "migration_head", "python_version",
    }
    assert metadata["agentguard_version"] == "0.1.0-alpha.1"
    assert migration_head() == "0018_v20_archive_quorum_bindings"
    assert all("password" not in key.lower() and "secret" not in key.lower() for key in metadata)


def test_cli_version_does_not_open_database(capsys):
    assert cli_main(["version"]) == 0
    output = capsys.readouterr().out
    assert "agentguard_version=0.1.0-alpha.1" in output
    assert "migration_head=0018_v20_archive_quorum_bindings" in output
    assert "password" not in output.lower()


def test_secret_file_configuration_is_supported_and_trim_is_not_silent(tmp_path, monkeypatch):
    pepper_file = tmp_path / "pepper"
    integrity_file = tmp_path / "integrity"
    pepper_file.write_text("file-pepper", encoding="utf-8")
    integrity_file.write_text("file-integrity-key-with-at-least-32-bytes", encoding="utf-8")
    for name in ("AGENTGUARD_KEY_PEPPER", "AGENTGUARD_INTEGRITY_KEY", "AGENTGUARD_KEY_PEPPER_FILE", "AGENTGUARD_INTEGRITY_KEY_FILE"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("AGENTGUARD_KEY_PEPPER_FILE", str(pepper_file))
    monkeypatch.setenv("AGENTGUARD_INTEGRITY_KEY_FILE", str(integrity_file))
    settings = Settings(_env_file=None, database_url="sqlite:///./v9-test.db", environment="test")
    assert settings.key_pepper == "file-pepper"
    assert settings.integrity_key == "file-integrity-key-with-at-least-32-bytes"
    validate_configuration(settings)


def test_secret_file_rejects_missing_empty_multiline_and_conflict(tmp_path, monkeypatch):
    monkeypatch.delenv("AGENTGUARD_KEY_PEPPER", raising=False)
    missing = tmp_path / "missing"
    monkeypatch.setenv("AGENTGUARD_KEY_PEPPER_FILE", str(missing))
    with pytest.raises(ValueError, match="secret file is unavailable"):
        Settings(_env_file=None)

    empty = tmp_path / "empty"
    empty.write_text("", encoding="utf-8")
    monkeypatch.setenv("AGENTGUARD_KEY_PEPPER_FILE", str(empty))
    with pytest.raises(ValueError, match="secret file is empty"):
        Settings(_env_file=None)

    multiline = tmp_path / "multiline"
    multiline.write_text("one\ntwo", encoding="utf-8")
    monkeypatch.setenv("AGENTGUARD_KEY_PEPPER_FILE", str(multiline))
    with pytest.raises(ValueError, match="secret file is empty"):
        Settings(_env_file=None)

    monkeypatch.setenv("AGENTGUARD_KEY_PEPPER", "direct-value")
    with pytest.raises(ValueError, match="cannot both be set"):
        Settings(_env_file=None)


def test_database_url_file_and_production_validation(tmp_path, monkeypatch):
    url_file = tmp_path / "database-url"
    url_file.write_text("postgresql+psycopg://runtime@db.example/agentguard", encoding="utf-8")
    for name in ("DATABASE_URL", "AGENTGUARD_DATABASE_URL"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("DATABASE_URL_FILE", str(url_file))
    settings = _safe_settings(database_url=None)
    assert settings.database_url == "postgresql+psycopg://runtime@db.example/agentguard"
    validate_configuration(settings)
    monkeypatch.delenv("DATABASE_URL_FILE", raising=False)
    with pytest.raises(ValueError, match="production requires PostgreSQL"):
        validate_configuration(_safe_settings(environment="production"))
    with pytest.raises(ValueError, match="must use sqlite or PostgreSQL"):
        validate_configuration(_safe_settings(database_url="mysql://db/agentguard"))


def test_health_contract_keeps_legacy_health_and_adds_liveness(client):
    assert client.get("/health/live").status_code == 200
    assert client.get("/health/live").json() == {"status": "alive"}
    assert client.get("/health").json() == {"status": "healthy"}


def test_readiness_requires_migration_head(client, monkeypatch):
    monkeypatch.setenv("AGENTGUARD_ENVIRONMENT", "test")
    monkeypatch.setenv("AGENTGUARD_KEY_PEPPER", "v9-test-pepper-only")
    monkeypatch.setenv("AGENTGUARD_INTEGRITY_KEY", "v9-test-integrity-key-with-at-least-32-bytes")
    get_settings.cache_clear()
    try:
        response = client.get("/health/ready")
        assert response.status_code == 503
        assert response.json() == {"detail": "AgentGuard is not ready"}
    finally:
        get_settings.cache_clear()

