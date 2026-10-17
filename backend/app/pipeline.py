"""One question -> a sequence of SSE events: guardrail, sources, token..., done (or error).

Kept separate from the web layer so the gate script, evals and tests run the exact same path.
"""

from __future__ import annotations

import time
from typing import Iterator

from app import guardrail
from app.llm import LLM
from app.prompt import SYSTEM_PROMPT, build_user_message, extract_citations
from app.retrieve import Mode, Retriever

Event = tuple[str, dict | list]


def answer_events(question: str, retriever: Retriever, llm: LLM, mode: Mode = "hybrid", top_k: int | None = None) -> Iterator[Event]:
    t0 = time.perf_counter()

    verdict = guardrail.check(question)
    yield "guardrail", verdict.as_event()
    if verdict.verdict == "block":
        yield "done", {"latency_ms": _ms(t0), "tokens_in": 0, "tokens_out": 0, "cost_usd": 0.0, "blocked": True}
        return

    try:
        hits = retriever.search(question.strip(), mode=mode, top_k=top_k)
    except RuntimeError as exc:  # e.g. vector mode requested but no vector index
        yield "error", {"message": str(exc)}
        return

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

    answer_parts: list[str] = []
    try:
        for text in llm.stream(SYSTEM_PROMPT, build_user_message(question.strip(), hits)):
            answer_parts.append(text)
            yield "token", {"text": text}
    except Exception as exc:  # network, auth, rate limit
        yield "error", {"message": f"LLM call failed: {type(exc).__name__}: {exc}"}
        return

    answer = "".join(answer_parts)
    cited = extract_citations(answer)
    valid = [n for n in cited if 1 <= n <= len(sources)]
    usage = llm.usage
    yield "done", {
        "latency_ms": _ms(t0),
        "tokens_in": usage.input_tokens,
        "tokens_out": usage.output_tokens,
        "cost_usd": usage.cost_usd(llm.model),
        "model": llm.model,
        "mode": mode,
        "cited": valid,
        "invalid_citations": [n for n in cited if n not in valid],
        "blocked": False,
    }


def _ms(t0: float) -> int:
    return int((time.perf_counter() - t0) * 1000)
