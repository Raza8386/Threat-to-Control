"""One question -> a sequence of SSE events: guardrail, sources, token..., done (or error).

Kept separate from the web layer so the gate script, evals and tests run the exact same path.
Clients get generic error messages; details go to the server log only.
"""

from __future__ import annotations

import logging
import time
from typing import Iterator

from app import guardrail
from app.llm import LLM
from app.prompt import OutputGuard, build_user_message, extract_citations, system_prompt
from app.retrieve import Hit, Mode, Retriever

log = logging.getLogger("pipeline")
Event = tuple[str, dict | list]

MAX_ANSWER_TOKENS = 1024
GENERIC_LLM_ERROR = "The answer service is temporarily unavailable. Please try again shortly."
LEAK_MESSAGE = "The response was withheld by the output safety check."


def answer_events(
    question: str,
    retriever: Retriever,
    llm: LLM,
    mode: Mode = "hybrid",
    top_k: int | None = None,
    classifier_llm: LLM | None = None,
    extra_hits: list[Hit] | None = None,  # evals only: inject a poisoned source to test indirect injection
) -> Iterator[Event]:
    t0 = time.perf_counter()

    verdict = guardrail.check(question, classifier_llm)
    yield "guardrail", verdict.as_event()
    if verdict.verdict == "block":
        cost = classifier_llm.usage.cost_usd(classifier_llm.model) if (classifier_llm and verdict.layer == "classifier") else 0.0
        yield "done", {"latency_ms": _ms(t0), "tokens_in": 0, "tokens_out": 0, "cost_usd": cost, "blocked": True}
        return
    guard_cost = classifier_llm.usage.cost_usd(classifier_llm.model) if (classifier_llm and verdict.layer == "classifier") else 0.0

    try:
        hits = retriever.search(question.strip(), mode=mode, top_k=top_k)
    except RuntimeError as exc:  # e.g. vector mode requested but no vector index
        log.warning("retrieval failed: %s", exc)
        yield "error", {"message": "Search is unavailable in this mode right now."}
        return
    if extra_hits:
        hits = list(extra_hits) + hits[: max(0, len(hits) - len(extra_hits))]

    sources = [
        {
            "n": n,
            "ref_id": h.metadata["ref_id"],
            "title": h.metadata["title"],
            "url": h.metadata["url"],
            "source": h.metadata["source"],
            "ranks": h.ranks,
        }
        for n, h in enumerate(hits, start=1)
    ]
    yield "sources", sources

    out_guard = OutputGuard()
    try:
        for text in llm.stream(system_prompt(), build_user_message(question.strip(), hits), max_tokens=MAX_ANSWER_TOKENS):
            safe = out_guard.feed(text)
            if out_guard.tripped:
                break
            if safe:
                yield "token", {"text": safe}
        tail = out_guard.flush()
        if tail:
            yield "token", {"text": tail}
    except Exception as exc:  # network, auth, rate limit
        log.error("LLM call failed: %s: %s", type(exc).__name__, exc)
        yield "error", {"message": GENERIC_LLM_ERROR}
        return

    usage = llm.usage
    cost = round(usage.cost_usd(llm.model) + guard_cost, 6)
    if out_guard.tripped:
        log.warning("output guard tripped: possible system prompt leak (question len=%d)", len(question))
        yield "error", {"message": LEAK_MESSAGE}
        yield "done", {"latency_ms": _ms(t0), "tokens_in": usage.input_tokens, "tokens_out": usage.output_tokens,
                       "cost_usd": cost, "blocked": True, "withheld": True}
        return

    answer = out_guard.text
    cited = extract_citations(answer)
    valid = [n for n in cited if 1 <= n <= len(sources)]
    yield "done", {
        "latency_ms": _ms(t0),
        "tokens_in": usage.input_tokens,
        "tokens_out": usage.output_tokens,
        "cost_usd": cost,
        "model": llm.model,
        "mode": mode,
        "cited": valid,
        "invalid_citations": [n for n in cited if n not in valid],
        "blocked": False,
    }


def _ms(t0: float) -> int:
    return int((time.perf_counter() - t0) * 1000)
