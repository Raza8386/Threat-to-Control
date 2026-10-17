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
REFUSAL_MESSAGE = "This question couldn't be answered here. Try asking about detection or mitigation instead."


def answer_events(
    question: str,
    retriever: Retriever,
    llm: LLM,
    mode: Mode = "hybrid",
    top_k: int | None = None,
    classifier_llm: LLM | None = None,
    extra_hits: list[Hit] | None = None,  # evals only: inject a poisoned source to test indirect injection
    fallback_llm: LLM | None = None,  # retried once if `llm` ends with stop_reason "refusal"
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

    user_msg = build_user_message(question.strip(), hits)
    attempt = _Attempt()
    try:
        yield from _stream_attempt(llm, user_msg, attempt)
        refused_by = None
        if attempt.refused and fallback_llm is not None:
            # A safety classifier stopped the answer. The client must drop any partial text it has shown.
            refused_by = llm.model
            log.warning("refusal from %s (category=%s); retrying on %s", llm.model, attempt.category, fallback_llm.model)
            yield "reset", {"reason": "refusal"}
            first_cost = attempt.cost
            attempt = _Attempt(prior_cost=first_cost)
            llm = fallback_llm
            yield from _stream_attempt(llm, user_msg, attempt)
    except Exception as exc:  # network, auth, rate limit
        log.error("LLM call failed: %s: %s", type(exc).__name__, exc)
        yield "error", {"message": GENERIC_LLM_ERROR}
        return

    cost = round(attempt.cost + attempt.prior_cost + guard_cost, 6)
    usage = llm.usage
    base = {"latency_ms": _ms(t0), "tokens_in": usage.input_tokens, "tokens_out": usage.output_tokens, "cost_usd": cost, "model": llm.model}
    if attempt.guard.tripped:
        log.warning("output guard tripped (%s): possible system prompt leak (question len=%d)", attempt.guard.reason, len(question))
        yield "reset", {"reason": "withheld"}
        yield "error", {"message": LEAK_MESSAGE}
        yield "done", {**base, "blocked": True, "withheld": True}
        return
    if attempt.refused:
        log.warning("refusal from %s (category=%s); no answer returned", llm.model, attempt.category)
        yield "reset", {"reason": "refusal"}
        yield "error", {"message": REFUSAL_MESSAGE}
        yield "done", {**base, "blocked": True, "refused": True}
        return

    answer = attempt.guard.text
    cited = extract_citations(answer)
    valid = [n for n in cited if 1 <= n <= len(sources)]
    yield "done", {
        **base,
        "mode": mode,
        "cited": valid,
        "invalid_citations": [n for n in cited if n not in valid],
        "blocked": False,
        "fallback_from": refused_by,
        "truncated": llm.stop_reason == "max_tokens",
    }


class _Attempt:
    def __init__(self, prior_cost: float = 0.0):
        self.guard = OutputGuard()
        self.refused = False
        self.category: str | None = None
        self.cost = 0.0
        self.prior_cost = prior_cost


def _stream_attempt(llm: LLM, user_msg: str, attempt: _Attempt) -> Iterator[Event]:
    """Stream one model's answer through the output guard; record refusal and cost on `attempt`."""
    for text in llm.stream(system_prompt(), user_msg, max_tokens=MAX_ANSWER_TOKENS):
        safe = attempt.guard.feed(text)
        if attempt.guard.tripped:
            break
        if safe:
            yield "token", {"text": safe}
    attempt.refused = getattr(llm, "stop_reason", None) == "refusal"
    attempt.category = getattr(llm, "stop_category", None)
    attempt.cost = llm.usage.cost_usd(llm.model)
    if not attempt.refused and not attempt.guard.tripped:
        tail = attempt.guard.flush()
        if tail:
            yield "token", {"text": tail}


def _ms(t0: float) -> int:
    return int((time.perf_counter() - t0) * 1000)
