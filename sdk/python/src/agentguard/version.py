from __future__ import annotations

import importlib.metadata
from pathlib import Path
import re


def _read_version() -> str:
    for root in (Path(__file__).resolve().parents[4], Path("/app")):
        try:
            value = (root / "VERSION").read_text(encoding="utf-8").strip()
        except (OSError, UnicodeError):
            continue
        if re.fullmatch(r"\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?", value):
            return value
    try:
        return importlib.metadata.version("agentguard")
    except importlib.metadata.PackageNotFoundError:
        return "unknown"


__version__ = _read_version()
