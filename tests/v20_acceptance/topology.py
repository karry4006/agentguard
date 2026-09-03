"""Optional lifecycle controls for the disposable V20 acceptance topology."""
from __future__ import annotations

from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[2]
COMPOSE_FILES = (ROOT / "compose.yaml", ROOT / "tests" / "compose.v20-live.yaml")


def load_env_file(path: Path) -> None:
    from .context import load_env_file as _load
    _load(path)


def _run(env_file: Path, *arguments: str) -> None:
    command = ["docker", "compose"]
    for compose_file in COMPOSE_FILES:
        command.extend(("-f", str(compose_file)))
    command.extend(("--env-file", str(env_file), *arguments))
    result = subprocess.run(command, cwd=ROOT, stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            text=True, timeout=180, check=False)
    if result.returncode:
        raise RuntimeError(f"disposable topology command failed: {arguments[0]}")


def start(env_file: Path, *, build: bool = False) -> None:
    arguments = ["up", "-d"]
    if build:
        arguments.insert(1, "--build")
    _run(env_file, *arguments)


def stop(env_file: Path) -> None:
    _run(env_file, "stop")
