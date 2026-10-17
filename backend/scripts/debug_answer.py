"""Debug one question: print the raw, unguarded model output and whether the output guard would trip.

Local troubleshooting only (it prints the full model output, bypassing the guard). Run from backend/:
    python -m scripts.debug_answer "How do adversaries dump credentials from LSASS memory?" --model claude-sonnet-5-5 --runs 3
"""

from __future__ import annotations

import argparse

from app.config import settings
from app.llm import get_llm
from app.prompt import LEAK_PHRASES, OutputGuard, build_user_message, system_prompt
from app.retrieve import Retriever


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("question")
    ap.add_argument("--model", default=settings.answer_model)
    ap.add_argument("--runs", type=int, default=1)
    args = ap.parse_args()

    retriever = Retriever()
    hits = retriever.search(args.question)
    print("Sources:", ", ".join(h.metadata["ref_id"] for h in hits))
    user = build_user_message(args.question, hits)
    for run in range(1, args.runs + 1):
        llm = get_llm(args.model)
        raw = "".join(llm.stream(system_prompt(), user))
        guard = OutputGuard()
        guard.feed(raw)
        guard.flush()
        print(f"\n===== run {run} | {len(raw)} chars | stop_reason: {llm.stop_reason} {llm.stop_category or ''}"
              f" | guard tripped: {guard.tripped} {guard.reason} =====")
        if guard.reason.startswith("phrase:"):
            phrase = LEAK_PHRASES[int(guard.reason.split(":")[1])]
            i = raw.lower().find(phrase.lower())
            print(f"matched phrase {phrase!r} at char {i}: ...{raw[max(0, i - 80): i + len(phrase) + 40]}...")
        print(raw)


if __name__ == "__main__":
    main()
