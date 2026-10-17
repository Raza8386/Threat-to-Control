"""Configuration guards that keep known dependency advisories out of reach (see SECURITY.md)."""

from __future__ import annotations

import re
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[1]
SOURCE_FILES = [p for d in ("app", "ingest", "scripts", "evals") for p in (BACKEND / d).rglob("*.py")]


def _code() -> str:
    return "\n".join(p.read_text(encoding="utf-8") for p in SOURCE_FILES)


def test_chroma_is_embedded_only():
    """chromadb server-mode advisories (CVE-2026-45829/45830/45831/45833) need a running Chroma server."""
    code = _code()
    assert "PersistentClient" in code
    assert not re.search(r"HttpClient|AsyncHttpClient|chromadb\.server|chroma run|FastAPI\(.*chroma", code)


def test_chroma_telemetry_disabled():
    assert "anonymized_telemetry=False" in _code()


def test_remote_code_is_allowlisted():
    code = (BACKEND / "app" / "embeddings.py").read_text(encoding="utf-8")
    assert "trust_remote_code\": model in REMOTE_CODE_ALLOWLIST" in code
    assert "trust_remote_code=True" not in code


def test_no_secrets_committed():
    pattern = re.compile(r"sk-ant-[A-Za-z0-9_\-]{20,}|pa-[A-Za-z0-9_\-]{30,}")
    for p in BACKEND.parent.rglob("*"):
        if p.is_file() and ".git" not in p.parts and "data" not in p.parts and p.suffix in {".py", ".md", ".yaml", ".yml", ".json", ".txt", ".example", ".toml"}:
            assert not pattern.search(p.read_text(encoding="utf-8", errors="ignore")), f"possible API key in {p}"


def test_env_files_ignored():
    ignore = (BACKEND.parent / ".gitignore").read_text(encoding="utf-8")
    assert ".env" in ignore and "data/" in ignore
