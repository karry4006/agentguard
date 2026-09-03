"""Provider-neutral cold archive object storage.

Only PUT/GET/HEAD are exposed.  There is intentionally no delete method:
AgentGuard V16 never deletes long-term archive objects.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import logging
from typing import Protocol
import json
import os
from urllib.parse import urlparse

from agentguard_server.config import Settings, get_settings

logger = logging.getLogger("agentguard.retention")


class ArchiveStoreError(RuntimeError):
    pass


class ArchiveObjectMissing(ArchiveStoreError):
    pass


class ArchiveObjectConflict(ArchiveStoreError):
    pass


class ArchiveStoreUnavailable(ArchiveStoreError):
    pass


class ArchiveStore(Protocol):
    def put(self, object_key: str, body: bytes) -> None: ...
    def head(self, object_key: str) -> dict[str, str] | None: ...
    def get(self, object_key: str) -> bytes: ...
    def exists(self, object_key: str) -> bool: ...


def validate_archive_object_key(object_key: str) -> str:
    """Accept only internal relative keys; callers never supply these keys."""
    if (not isinstance(object_key, str) or not object_key or len(object_key) > 512
            or object_key.startswith(("/", "\\")) or ".." in object_key
            or any(ord(ch) < 32 for ch in object_key)):
        raise ValueError("invalid archive object key")
    return object_key


@dataclass
class InMemoryArchiveStore:
    """Deterministic test store; it also models non-overwrite semantics."""

    objects: dict[str, bytes] | None = None

    def __post_init__(self) -> None:
        if self.objects is None:
            self.objects = {}

    def put(self, object_key: str, body: bytes) -> None:
        validate_archive_object_key(object_key)
        if self.objects is None:
            raise ArchiveStoreError("in-memory archive store is not initialized")
        current = self.objects.get(object_key)
        if current is not None and current != body:
            raise ArchiveObjectConflict("object key already contains different bytes")
        self.objects[object_key] = bytes(body)

    def head(self, object_key: str) -> dict[str, str] | None:
        validate_archive_object_key(object_key)
        if self.objects is None:
            raise ArchiveStoreError("in-memory archive store is not initialized")
        body = self.objects.get(object_key)
        if body is None:
            return None
        return {"content_length": str(len(body)), "sha256": hashlib.sha256(body).hexdigest()}

    def get(self, object_key: str) -> bytes:
        validate_archive_object_key(object_key)
        if self.objects is None:
            raise ArchiveStoreError("in-memory archive store is not initialized")
        try:
            return self.objects[object_key]
        except KeyError as exc:
            raise ArchiveObjectMissing("archive object is missing") from exc

    def exists(self, object_key: str) -> bool:
        return self.head(object_key) is not None


class S3ArchiveStore:
    """S3-compatible store using the maintained boto3 SigV4 implementation.

    boto3 is imported lazily so local unit tests can use the in-memory store
    without cloud dependencies.  Endpoint and credentials are trusted
    configuration, never request data.
    """

    def __init__(self, settings: Settings | None = None):
        settings = settings or get_settings()
        if not settings.archive_store_endpoint or not settings.archive_store_bucket:
            raise ValueError("archive object store endpoint and bucket are required")
        try:
            import boto3
            from botocore.config import Config
            from botocore.exceptions import ClientError, EndpointConnectionError, BotoCoreError
        except ImportError as exc:
            raise ArchiveStoreUnavailable("boto3 is required for S3 archive storage") from exc
        self._client_error = ClientError
        self._endpoint_errors = (EndpointConnectionError, BotoCoreError)
        self.bucket = settings.archive_store_bucket
        self.max_object_bytes = settings.archive_max_object_bytes
        self._client = boto3.client(
            "s3",
            endpoint_url=settings.archive_store_endpoint,
            region_name=settings.archive_store_region,
            aws_access_key_id=settings.archive_store_access_key,
            aws_secret_access_key=settings.archive_store_secret_key,
            aws_session_token=settings.archive_store_session_token,
            config=Config(
                signature_version="s3v4",
                connect_timeout=settings.archive_request_timeout_seconds,
                read_timeout=settings.archive_request_timeout_seconds,
                retries={"max_attempts": 3, "mode": "standard"},
            ),
        )

    def put(self, object_key: str, body: bytes) -> None:
        validate_archive_object_key(object_key)
        try:
            current = self.head(object_key)
            if current is not None:
                existing = self.get(object_key)
                if existing != body:
                    raise ArchiveObjectConflict("object key already contains different bytes")
                return
            self._client.put_object(Bucket=self.bucket, Key=object_key, Body=body, ContentType="application/octet-stream")
        except ArchiveObjectConflict:
            raise
        except self._endpoint_errors as exc:
            raise ArchiveStoreUnavailable("object store unavailable") from exc
        except self._client_error as exc:
            raise ArchiveStoreError("object store write failed") from exc

    def head(self, object_key: str) -> dict[str, str] | None:
        validate_archive_object_key(object_key)
        try:
            response = self._client.head_object(Bucket=self.bucket, Key=object_key)
            return {"content_length": str(response.get("ContentLength", "")), "etag": str(response.get("ETag", ""))}
        except self._client_error as exc:
            code = str(exc.response.get("Error", {}).get("Code", ""))
            if code in {"404", "NoSuchKey", "NotFound"}:
                return None
            raise ArchiveStoreError("object store head failed") from exc
        except self._endpoint_errors as exc:
            raise ArchiveStoreUnavailable("object store unavailable") from exc

    def get(self, object_key: str) -> bytes:
        validate_archive_object_key(object_key)
        try:
            response = self._client.get_object(Bucket=self.bucket, Key=object_key)
            body = response["Body"].read()
            if len(body) > self.max_object_bytes:
                raise ArchiveStoreError("archive object exceeds configured bound")
            return body
        except ArchiveStoreError:
            raise
        except self._client_error as exc:
            code = str(exc.response.get("Error", {}).get("Code", ""))
            if code in {"404", "NoSuchKey", "NotFound"}:
                raise ArchiveObjectMissing("archive object is missing") from exc
            raise ArchiveStoreError("object store read failed") from exc
        except self._endpoint_errors as exc:
            raise ArchiveStoreUnavailable("object store unavailable") from exc

    def exists(self, object_key: str) -> bool:
        return self.head(object_key) is not None


def archive_object_key(tenant_id: object, archive_id: object) -> str:
    """Generate a safe key from trusted UUID-like catalog identifiers only."""
    tenant_digest = hashlib.sha256(str(tenant_id).encode("ascii", "strict")).hexdigest()[:32]
    archive_text = str(archive_id)
    if len(archive_text) != 36 or any(ch not in "0123456789abcdef-" for ch in archive_text.lower()):
        raise ValueError("archive id must be a UUID")
    return f"trace-archive-v1/{tenant_digest}/{archive_text}.bin"


generate_archive_object_key = archive_object_key


@dataclass(frozen=True)
class ArchiveStoreBinding:
    """Trusted runtime binding; the database stores only ``store_id``."""

    store_id: str
    store: ArchiveStore
    priority: int = 100
    read_enabled: bool = True
    write_enabled: bool = True
    replication_enabled: bool = True
    scrub_enabled: bool = True


_test_store_registry: dict[str, ArchiveStoreBinding] = {}


def set_archive_store_registry_for_tests(bindings: dict[str, ArchiveStore | ArchiveStoreBinding]) -> None:
    global _test_store_registry
    _test_store_registry = {
        key: value if isinstance(value, ArchiveStoreBinding) else ArchiveStoreBinding(key, value)
        for key, value in bindings.items()
    }


def archive_store_registry(settings: Settings | None = None) -> dict[str, ArchiveStoreBinding]:
    """Build the trusted store map from process configuration.

    Additional store definitions contain only endpoint/bucket and names of
    environment variables holding credentials.  No request or archive data
    can add a store.
    """
    if _test_store_registry:
        return dict(_test_store_registry)
    settings = settings or get_settings()
    result: dict[str, ArchiveStoreBinding] = {}
    if settings.archive_store_endpoint and settings.archive_store_bucket:
        result[settings.archive_primary_store_id] = ArchiveStoreBinding(
            settings.archive_primary_store_id, S3ArchiveStore(settings), priority=0,
        )
    if settings.archive_store_registry:
        try:
            definitions = json.loads(settings.archive_store_registry)
        except json.JSONDecodeError as exc:
            raise ValueError("archive store registry is invalid") from exc
        if not isinstance(definitions, list):
            raise ValueError("archive store registry is invalid")
        for definition in definitions:
            if not isinstance(definition, dict):
                raise ValueError("archive store registry is invalid")
            store_id = definition.get("store_id")
            endpoint = definition.get("endpoint")
            bucket = definition.get("bucket")
            if (not isinstance(store_id, str) or not store_id or store_id in result
                    or not isinstance(endpoint, str) or not isinstance(bucket, str)):
                raise ValueError("archive store registry is invalid")
            parsed = urlparse(endpoint)
            private_ok = settings.environment == "test" and settings.allow_private_archive_tests and parsed.scheme == "http"
            if (parsed.scheme != "https" and not private_ok) or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
                raise ValueError("archive store registry endpoint is invalid")
            def env_value(field: str) -> str | None:
                name = definition.get(field)
                return os.getenv(name) if isinstance(name, str) and name else None
            local = settings.model_copy(update={
                "archive_store_endpoint": endpoint, "archive_store_bucket": bucket,
                "archive_store_region": str(definition.get("region", settings.archive_store_region)),
                "archive_store_access_key": env_value("access_key_env"),
                "archive_store_secret_key": env_value("secret_key_env"),
                "archive_store_session_token": env_value("session_token_env"),
            })
            result[store_id] = ArchiveStoreBinding(
                store_id, S3ArchiveStore(local), priority=int(definition.get("priority", 100)),
                read_enabled=bool(definition.get("read_enabled", True)),
                write_enabled=bool(definition.get("write_enabled", True)),
                replication_enabled=bool(definition.get("replication_enabled", True)),
                scrub_enabled=bool(definition.get("scrub_enabled", True)),
            )
    return result
