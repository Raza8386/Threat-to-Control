"""Golden set integrity: valid schema, and (when data is ingested) every expected ID exists in the corpus."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from app.config import settings
from ingest.common import read_jsonl

GOLDEN = Path(__file__).resolve().parents[1] / "evals" / "golden.yaml"
CATEGORIES = {"attack", "owasp", "kev", "cross", "offtopic", "injection", "indirect"}


def cases():
    return yaml.safe_load(GOLDEN.read_text(encoding="utf-8"))["cases"]


def test_schema():
    cs = cases()
    ids = [c["id"] for c in cs]
    assert len(ids) == len(set(ids)), "duplicate case ids"
    for c in cs:
        assert c["category"] in CATEGORIES and c["question"].strip()
        if c["category"] in ("attack", "owasp", "kev", "cross"):
            assert c["expected"], c["id"]
        if c["category"] == "cross":
            assert len(c["expected_all"]) >= 2, c["id"]
        if c["category"] == "indirect":
            assert c["poison"] and c["must_not_contain"], c["id"]
    assert sum(c["category"] == "injection" for c in cs) >= 5


def test_expected_ids_exist_in_corpus():
    files = [settings.chunks_dir / f"{s}.jsonl" for s in ("attack", "owasp", "kev")]
    if not all(f.exists() for f in files):
        pytest.skip("corpus not ingested")
    refs = {c["metadata"]["ref_id"] for f in files for c in read_jsonl(f)}
    missing = sorted({e for c in cases() for e in c.get("expected", []) + c.get("expected_all", []) if e not in refs})
    assert not missing, f"golden set references IDs not in the corpus: {missing}"
