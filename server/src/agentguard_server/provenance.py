"""Safe, secret-free build and source provenance metadata."""

from __future__ import annotations

from datetime import datetime, timezone
import importlib.metadata
import os
from pathlib import Path
import re
import sys


_REVISION = re.compile(r"^(\d{4}_[A-Za-z0-9_]+)\.py$")


def _roots() -> tuple[Path, ...]:
    source_root = Path(__file__).resolve().parents[3]
    return (source_root, Path("/app"))


def read_version() -> str:
    for root in _roots():
        try:
            value = (root / "VERSION").read_text(encoding="utf-8").strip()
        except (OSError, UnicodeError):
            continue
        if re.fullmatch(r"\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?", value):
            return value
    try:
        return importlib.metadata.version("agentguard-server")
    except importlib.metadata.PackageNotFoundError:
        return "unknown"


def migration_head() -> str:
    candidates: list[tuple[int, str]] = []
    for root in _roots():
        for path in (root / "server" / "alembic" / "versions", root / "alembic" / "versions"):
            if not path.is_dir():
                continue
            for item in path.iterdir():
                match = _REVISION.match(item.name)
                if match:
                    candidates.append((int(match.group(1)[:4]), match.group(1)))
    return max(candidates, default=(0, "unknown"))[1]


def git_commit() -> str:
    for root in _roots():
        git_dir = root / ".git"
        try:
            head = (git_dir / "HEAD").read_text(encoding="ascii").strip()
            if head.startswith("ref: "):
                value = (git_dir / head[6:].strip()).read_text(encoding="ascii").strip()
            else:
                value = head
        except (OSError, UnicodeError):
            continue
        if re.fullmatch(r"[0-9a-f]{40}", value):
            return value
    return "unavailable"


def build_timestamp() -> str:
    configured = os.getenv("AGENTGUARD_BUILD_TIMESTAMP")
    if configured:
        return configured
    epoch = os.getenv("SOURCE_DATE_EPOCH")
    if epoch and epoch.isdigit():
        return datetime.fromtimestamp(int(epoch), tz=timezone.utc).isoformat()
    return "unknown"


def build_metadata() -> dict[str, str]:
    return {
        "agentguard_version": read_version(),
        "git_commit": git_commit(),
        "build_timestamp": build_timestamp(),
        "migration_head": migration_head(),
        "python_version": sys.version.split()[0],
    }
