"""Phase 2 gate: 10 questions stream answers whose citations all resolve to the right source URLs.

Run from backend/:
    python -m scripts.phase2_check                 # real Claude (needs ANTHROPIC_API_KEY in .env)
    python -m scripts.phase2_check --check-links   # also fetch every cited URL (needs internet)
    LLM_BACKEND=fake python -m scripts.phase2_check  # offline dry run with the stand-in model
Exit code 0 = gate passed. Full answers are written to scripts/phase2_report.json.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

from app.config import settings
from app.llm import get_llm
from app.pipeline import answer_events
from app.retrieve import Retriever

QUESTIONS: list[tuple[str, str]] = [
    ("How do attackers achieve persistence via scheduled tasks?", "T1053"),
    ("What is CVE-2015-5477 and what action does CISA require?", "CVE-2015-5477"),
    ("How do I prevent SQL injection according to OWASP?", "A03:2021"),
    ("How is PowerShell abused by adversaries, and how do I detect it?", "T1059.001"),
    ("What are the prevention steps for broken access control?", "A01:2021"),
    ("How do adversaries dump credentials from LSASS memory?", "T1003.001"),
    ("What is server-side request forgery and how do I prevent it?", "A10:2021"),
    ("Is CVE-2021-44228 in the KEV catalog and what action is required?", "CVE-2021-44228"),
    ("What mitigations does ATT&CK list for spearphishing attachments?", "T1566.001"),
    ("How do attackers perform Kerberoasting?", "T1558.003"),
]

URL_RULES = {
    "attack": re.compile(r"^https://attack\.mitre\.org/techniques/T\d{4}(/\d{3})?/?$"),
    "owasp": re.compile(r"^https://owasp\.org/Top10/A\d{2}_2021-[^/]+/$"),
    "kev": re.compile(r"^https://nvd\.nist\.gov/vuln/detail/CVE-\d{4}-\d{4,7}$"),
}


def ref_matches(ref: str, expected: str) -> bool:
    return ref == expected or ref.startswith(expected + ".")


def url_matches(src: dict) -> bool:
    rule = URL_RULES.get(src["source"])
    if not rule or not rule.match(src["url"]):
        return False
    ref = src["ref_id"]
    if src["source"] == "attack":
        return src["url"].rstrip("/").endswith(ref.replace(".", "/"))
    if src["source"] == "kev":
        return src["url"].endswith(ref)
    return src["url"].startswith(f"https://owasp.org/Top10/{ref[:3]}_2021-")


def link_ok(url: str) -> bool:
    import requests

    try:
        r = requests.get(url, timeout=20, headers={"User-Agent": "threat-to-control-check"})
        return r.status_code < 400
    except requests.RequestException:
        return False


def run_one(question: str, retriever: Retriever, llm) -> dict:
    out = {"question": question, "answer": "", "sources": [], "done": {}, "error": None, "guardrail": None}
    for event, data in answer_events(question, retriever, llm):
        if event == "guardrail":
            out["guardrail"] = data
        elif event == "sources":
            out["sources"] = data
        elif event == "token":
            out["answer"] += data["text"]
        elif event == "done":
            out["done"] = data
        elif event == "error":
            out["error"] = data["message"]
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check-links", action="store_true", help="HTTP-fetch each cited URL")
    args = ap.parse_args()

    retriever = Retriever()
    llm = get_llm(settings.answer_model)
    print(f"Model: {llm.model} | vectors: {retriever.has_vectors}\n")

    report, passed, total_cost = [], 0, 0.0
    checked_links: dict[str, bool] = {}
    for i, (q, expected) in enumerate(QUESTIONS, start=1):
        r = run_one(q, retriever, llm)
        problems = []
        if r["error"]:
            problems.append(r["error"])
        if r["guardrail"] and r["guardrail"]["verdict"] != "allow":
            problems.append(f"blocked by guardrail: {r['guardrail']['reason']}")
        cited_nums = r["done"].get("cited", [])
        cited = [s for s in r["sources"] if s["n"] in cited_nums]
        if not cited_nums:
            problems.append("no citations")
        if r["done"].get("invalid_citations"):
            problems.append(f"citations with no source: {r['done']['invalid_citations']}")
        if cited and not any(ref_matches(s["ref_id"], expected) for s in cited):
            problems.append(f"expected {expected} not cited (cited {[s['ref_id'] for s in cited]})")
        bad_urls = [s["url"] for s in cited if not url_matches(s)]
        if bad_urls:
            problems.append(f"URL does not match its source: {bad_urls}")
        if args.check_links:
            for s in cited:
                if s["url"] not in checked_links:
                    checked_links[s["url"]] = link_ok(s["url"])
                if not checked_links[s["url"]]:
                    problems.append(f"dead link: {s['url']}")

        ok = not problems
        passed += ok
        total_cost += r["done"].get("cost_usd", 0.0)
        print(f"{'PASS' if ok else 'FAIL'} {i:2d}. {q}")
        print(f"        cited: {', '.join(s['ref_id'] for s in cited) or '-'} | {r['done'].get('latency_ms', 0)} ms | ${r['done'].get('cost_usd', 0):.5f}")
        for p in problems:
            print(f"        - {p}")
        report.append({**r, "expected": expected, "passed": ok, "problems": problems})

    out = Path(__file__).with_name("phase2_report.json")
    out.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"\n{passed}/{len(QUESTIONS)} passed | total cost ${total_cost:.4f} | answers -> {out.name}")
    print("Phase 2 gate:", "PASSED" if passed == len(QUESTIONS) else "FAILED")
    return 0 if passed == len(QUESTIONS) else 1


if __name__ == "__main__":
    sys.exit(main())
