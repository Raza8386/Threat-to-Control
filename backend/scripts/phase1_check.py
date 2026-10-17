"""Phase 1 gate: chunk counts match the sources, and exact-ID queries return the right chunk at rank 1.

Run from backend/:  python -m scripts.phase1_check [--mode hybrid|bm25|vector]
Exit code 0 = gate passed.
"""

from __future__ import annotations

import argparse
import json
import sys

from app.config import settings
from app.retrieve import Retriever
from ingest.common import RAW_DIR, read_jsonl

ID_QUERIES = [
    ("T1059.001", "attack", "T1059.001"),
    ("What is CVE-2015-5477 and what action does CISA require?", "kev", "CVE-2015-5477"),
    ("How do I prevent A03 injection?", "owasp", "A03:2021"),
    ("Explain T1053.005", "attack", "T1053.005"),
]

TOPIC_QUERIES = [
    ("How do attackers achieve persistence via scheduled tasks?", "T1053"),
    ("How do I prevent SQL injection according to OWASP?", "A03:2021"),
    ("How is PowerShell abused by adversaries, and how do I detect it?", "T1059.001"),
    ("What are the prevention steps for broken access control?", "A01:2021"),
]


def expected_counts() -> dict[str, int]:
    """Count natural units straight from the raw source files."""
    bundle = json.loads((RAW_DIR / "enterprise-attack.json").read_text(encoding="utf-8"))
    attack = sum(
        1
        for o in bundle["objects"]
        if o.get("type") == "attack-pattern"
        and not o.get("revoked")
        and not o.get("x_mitre_deprecated")
        and any(r.get("source_name") == "mitre-attack" for r in o.get("external_references", []))
    )
    kev = len(json.loads((RAW_DIR / "known_exploited_vulnerabilities.json").read_text(encoding="utf-8"))["vulnerabilities"])
    return {"attack": attack, "owasp": 10, "kev": kev}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", default=None, choices=["hybrid", "bm25", "vector"])
    args = ap.parse_args()

    ok = True
    print("1) Unit counts (unique ref_ids in chunks vs source files)")
    exp = expected_counts()
    for src, n_exp in exp.items():
        chunks = read_jsonl(settings.chunks_dir / f"{src}.jsonl")
        units = len({c["metadata"]["ref_id"] for c in chunks})
        flag = "PASS" if units == n_exp else "FAIL"
        ok &= units == n_exp
        print(f"   {flag} {src:7s} units={units:5d} expected={n_exp:5d} chunks={len(chunks)}")

    r = Retriever()
    mode = args.mode or ("hybrid" if r.has_vectors else "bm25")
    print(f"\n2) Exact-ID queries, mode={mode} (must be rank 1)")
    for q, src, ref in ID_QUERIES:
        hits = r.search(q, mode=mode, top_k=5)
        top = hits[0].metadata if hits else {}
        passed = top.get("source") == src and top.get("ref_id") == ref
        ok &= passed
        print(f"   {'PASS' if passed else 'FAIL'} {q!r} -> {top.get('ref_id')} ({top.get('source')})")

    print(f"\n3) Topic queries, mode={mode} (expected ref in top 5; informational)")
    for q, ref in TOPIC_QUERIES:
        hits = r.search(q, mode=mode, top_k=5)
        refs = [h.metadata["ref_id"] for h in hits]
        found = any(x == ref or x.startswith(ref + ".") for x in refs)
        print(f"   {'hit ' if found else 'miss'} {q!r}")
        for h in hits:
            print(f"        {h.metadata['ref_id']:16s} {h.metadata['title'][:70]}")

    print("\nPhase 1 gate:", "PASSED" if ok else "FAILED")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
