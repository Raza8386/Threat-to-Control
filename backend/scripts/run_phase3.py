"""One command for the whole Phase 3 run: install, test, diagnose refusals, evaluate both models, export Excel.

Run from backend/ (after `git pull`):
    python -m scripts.run_phase3
Stops at the first failing step and says why.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[1]
MODELS = "claude-sonnet-5-5,claude-haiku-5-5"
PROBE = "How is PowerShell abused by adversaries, and how do I detect it?"


def step(title: str) -> None:
    print(f"\n{'=' * 70}\n{title}\n{'=' * 70}", flush=True)


def run(args: list[str], capture: bool = False) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, *args], cwd=BACKEND, text=True, capture_output=capture,
                          encoding="utf-8", errors="replace")


def stop(msg: str) -> None:
    print(f"\nSTOPPED: {msg}")
    sys.exit(1)


def main() -> None:
    os.chdir(BACKEND)

    step("1/5  Installing dependencies")
    r = run(["-m", "pip", "install", "-q", "--disable-pip-version-check", "-r", "requirements.txt"])
    if r.returncode:
        stop("pip install failed (see above).")
    print("ok")

    step("2/5  Unit and security tests")
    r = run(["-m", "pytest", "-q"], capture=True)
    summary = (r.stdout.strip().splitlines() or ["?"])[-1]
    print(summary)
    if r.returncode:
        print(r.stdout[-3000:])
        stop("tests failed.")
    if not (BACKEND / "tests" / "test_refusal.py").exists():
        stop("old code: tests/test_refusal.py is missing. Run `git pull` first.")

    step("3/5  Refusal diagnosis (one probe question on Haiku)")
    r = run(["-m", "scripts.debug_answer", PROBE, "--model", "claude-haiku-5-5", "--runs", "1"], capture=True)
    header = next((ln for ln in r.stdout.splitlines() if ln.startswith("===== run")), r.stderr.strip()[-300:])
    print(header)
    err = (r.stderr or "").lower()
    if r.returncode and ("credit balance" in err or "billing" in err):
        stop("Anthropic credit balance is too low. Add credit at console.anthropic.com > Billing, then re-run.")
    if r.returncode and ("authentication" in err or "401" in err or "api key" in err):
        stop("The Anthropic API key was rejected. Check ANTHROPIC_API_KEY in backend/.env.")
    if r.returncode:
        stop("the probe call to Claude failed; see the error above.")
    if "refusal" in header:
        print("-> the API's safety classifier stopped this answer; the pipeline now resets and retries on the other model.")
    elif "guard tripped: True" in header:
        print("-> the output guard tripped on a normal answer; see the matched phrase above.")
    else:
        print("-> no refusal on this probe (refusals can be intermittent); the eval below measures them across all cases.")

    step(f"4/5  Full evaluation: {MODELS} (about 4-8 minutes)")
    r = run(["-m", "evals.run_evals", "--models", MODELS])
    results_path = BACKEND / "evals" / "results.json"
    if not results_path.exists():
        stop("evaluation produced no results.json.")
    res = json.loads(results_path.read_text(encoding="utf-8"))

    step("5/5  Exporting spreadsheet")
    r = run(["-m", "evals.export_xlsx"], capture=True)
    print(r.stdout.strip() or r.stderr.strip()[-500:])

    step("SUMMARY")
    hybrid = next(x for x in res["retrieval"] if x["mode"] == "hybrid")
    g = res.get("guardrail") or {}
    print(f"Retrieval  hybrid hit@5 {hybrid['hit_at_5']:.0%}  MRR {hybrid['mrr']:.3f}")
    print(f"Guardrail  attacks blocked {g.get('attacks_blocked')}/{g.get('attacks_total')}  false positives {g.get('false_positives')}/{g.get('normal_total')}")
    for a in res.get("answers", []):
        print(f"{a['model']:18s} faithfulness {a['faithfulness']}  citations {a['citation_accuracy']}  "
              f"judged {a['judged_answers']} (failed {a.get('judge_failed')})  fallbacks {a.get('fallbacks')}  "
              f"refused-both {a.get('refused_both')}  errors {a.get('errors', 0)}  skipped {a.get('skipped', 0)}  "
              f"{a['avg_latency_ms']} ms  ${a['avg_cost_usd']}/answer")
    print(f"Failures: {len(res.get('failures', []))}  ->  see the 'Failures' tab")
    if res.get("stopped_reason"):
        print(f"\nRUN STOPPED EARLY: {res['stopped_reason']}")
    codes = {}
    for f in res.get("failures", []):
        m = re.match(r"\[(\w+)\]", f.get("detail", "")) if f["kind"] == "error" else None
        if m:
            codes[m.group(1)] = codes.get(m.group(1), 0) + 1
    if codes:
        print(f"Errors by cause: {codes}  (rate_limit/overloaded -> re-run with --workers 2; credits -> top up)")
    print(f"\nPHASE 3 GATE: {'PASSED' if res.get('gate_passed') else 'FAILED'}  {res.get('gate')}")
    xlsx = BACKEND / "evals" / "Threat-to-Control_Eval_Results.xlsx"
    if xlsx.exists() and sys.platform == "win32":
        os.startfile(xlsx)  # opens in Excel


if __name__ == "__main__":
    main()
