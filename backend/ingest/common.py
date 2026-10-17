"""Shared helpers for the ingest scripts: downloads, chunk splitting, JSONL output."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Iterable

import requests

BACKEND_DIR = Path(__file__).resolve().parents[1]
DATA_DIR = BACKEND_DIR / "data"
RAW_DIR = DATA_DIR / "raw"
CHUNKS_DIR = DATA_DIR / "chunks"

MAX_TOKENS = 500
OVERLAP_TOKENS = 60

_WORD_RE = re.compile(r"\S+")


def download(urls: list[str], dest: Path, force: bool = False) -> Path:
    """Download the first URL that works into dest. Reuses an existing file unless force=True."""
    dest.parent.mkdir(parents=True, exist_ok=True)
    if dest.exists() and not force:
        return dest
    errors = []
    for url in urls:
        try:
            resp = requests.get(url, timeout=120)
            resp.raise_for_status()
            dest.write_bytes(resp.content)
            print(f"  downloaded {url} -> {dest.relative_to(BACKEND_DIR)}")
            return dest
        except requests.RequestException as exc:
            errors.append(f"{url}: {exc}")
    raise RuntimeError("All download URLs failed:\n" + "\n".join(errors))


def count_tokens(text: str) -> int:
    """Approximate token count (~1.3 tokens per whitespace word) without a tokenizer download."""
    return int(len(_WORD_RE.findall(text)) * 1.3) + 1


def split_text(title: str, body: str, max_tokens: int = MAX_TOKENS, overlap: int = OVERLAP_TOKENS) -> list[str]:
    """Return one piece if the unit fits; otherwise pack paragraphs into ~max_tokens pieces.

    Each piece repeats the title, and consecutive pieces overlap by ~`overlap` tokens so a
    sentence on a boundary is still retrievable from either side.
    """
    full = f"{title}\n\n{body}".strip()
    if count_tokens(full) <= max_tokens:
        return [full]

    budget = max_tokens - count_tokens(title) - 2
    words_per_piece = max(50, int(budget / 1.3))
    overlap_words = int(overlap / 1.3)

    # Pack whole paragraphs first; fall back to a word window for a paragraph that is too long.
    paragraphs = [p.strip() for p in re.split(r"\n\s*\n", body) if p.strip()]
    units: list[list[str]] = []
    for para in paragraphs:
        words = para.split()
        if len(words) <= words_per_piece:
            units.append(words)
        else:
            step = words_per_piece - overlap_words
            for i in range(0, len(words), step):
                units.append(words[i : i + words_per_piece])
                if i + words_per_piece >= len(words):
                    break

    pieces: list[list[str]] = []
    current: list[str] = []
    for unit in units:
        if current and len(current) + len(unit) > words_per_piece:
            pieces.append(current)
            current = current[-overlap_words:] if overlap_words else []
        current = current + [""] + unit if current else list(unit)
    if current:
        pieces.append(current)

    out = []
    for words in pieces:
        text = " ".join(w for w in words if w) if "" not in words else _join_paragraph_words(words)
        out.append(f"{title}\n\n{text}".strip())
    return out


def _join_paragraph_words(words: list[str]) -> str:
    # An empty-string marker separates paragraphs inside a packed piece.
    paras, cur = [], []
    for w in words:
        if w == "":
            if cur:
                paras.append(" ".join(cur))
            cur = []
        else:
            cur.append(w)
    if cur:
        paras.append(" ".join(cur))
    return "\n\n".join(paras)


def make_chunks(source: str, ref_id: str, title: str, url: str, body: str, extra: dict | None = None) -> list[dict]:
    """Build chunk records for one natural unit (technique, OWASP category, or CVE)."""
    pieces = split_text(title, body)
    chunks = []
    for i, text in enumerate(pieces, start=1):
        chunk_id = f"{source}:{ref_id}" + (f"#{i}" if len(pieces) > 1 else "")
        meta = {"source": source, "ref_id": ref_id, "title": title, "url": url, "part": i, "parts": len(pieces)}
        if extra:
            meta.update(extra)
        chunks.append({"id": chunk_id, "text": text, "metadata": meta})
    return chunks


def write_jsonl(records: Iterable[dict], dest: Path) -> int:
    dest.parent.mkdir(parents=True, exist_ok=True)
    n = 0
    with dest.open("w", encoding="utf-8") as fh:
        for rec in records:
            fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
            n += 1
    return n


def read_jsonl(path: Path) -> list[dict]:
    with path.open(encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]
