"""Claude client: streams answer text and reports token usage and cost.

FakeLLM stands in for Claude in tests and offline runs (no API key needed).
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from typing import Iterator, Protocol

# USD per million tokens (input, output). Source: platform.claude.com/docs/en/about-claude/pricing, Oct 2026.
PRICES: dict[str, tuple[float, float]] = {
    "claude-sonnet-5-5": (2.00, 10.00),
    "claude-haiku-5-5": (0.10, 0.50),  # prompts <= 100K tokens
}


@dataclass
class Usage:
    input_tokens: int = 0
    output_tokens: int = 0

    def cost_usd(self, model: str) -> float:
        price_in, price_out = PRICES.get(model, (0.0, 0.0))
        return round((self.input_tokens * price_in + self.output_tokens * price_out) / 1_000_000, 6)


class LLM(Protocol):
    model: str

    def stream(self, system: str, user: str, max_tokens: int = 1024) -> Iterator[str]: ...
    def complete(self, system: str, user: str, max_tokens: int = 300) -> str: ...
    @property
    def usage(self) -> Usage: ...


class ClaudeLLM:
    def __init__(self, model: str):
        import anthropic

        if not os.getenv("ANTHROPIC_API_KEY"):
            raise RuntimeError("ANTHROPIC_API_KEY is not set. Add it to backend/.env")
        self.model = model
        # Bounded waits and retries: a hung upstream must not hold a request (or a worker) open.
        self._client = anthropic.Anthropic(timeout=float(os.getenv("LLM_TIMEOUT_S", "45")), max_retries=2)
        self._usage = Usage()

    def complete(self, system: str, user: str, max_tokens: int = 300) -> str:
        """Single non-streaming call (guardrail classifier, eval judge). Updates usage."""
        msg = self._client.messages.create(
            model=self.model,
            max_tokens=max_tokens,
            system=system,
            messages=[{"role": "user", "content": user}],
        )
        self._usage = Usage(msg.usage.input_tokens, msg.usage.output_tokens)
        return "".join(b.text for b in msg.content if getattr(b, "type", "") == "text")

    def stream(self, system: str, user: str, max_tokens: int = 1024) -> Iterator[str]:
        self._usage = Usage()
        with self._client.messages.stream(
            model=self.model,
            max_tokens=max_tokens,
            system=system,
            messages=[{"role": "user", "content": user}],
        ) as s:
            for text in s.text_stream:
                yield text
            final = s.get_final_message()
        self._usage = Usage(final.usage.input_tokens, final.usage.output_tokens)

    @property
    def usage(self) -> Usage:
        return self._usage


class FakeLLM:
    """Deterministic stand-in: cites the 3 sources whose text best overlaps the question (like a model choosing)."""

    def __init__(self, model: str = "fake"):
        self.model = model
        self._usage = Usage()

    def complete(self, system: str, user: str, max_tokens: int = 300) -> str:
        """Stand-in classifier/judge: flags obvious override wording, otherwise allows / supports."""
        self._usage = Usage(len(user) // 4, 20)
        if "classify" in system.lower():
            bad = re.search(r"system prompt|instructions|rules|override|debug mode|above this line", user, re.I)
            return '{"verdict": "%s", "reason": "stand-in"}' % ("block" if bad else "allow")
        return '{"claims": [{"supported": true, "citation_correct": true}]}'

    def stream(self, system: str, user: str, max_tokens: int = 1024) -> Iterator[str]:
        sources = re.findall(r'<source n="(\d+)" id="([^"]+)"[^>]*>\n(.*?)\n</source>', user, re.S)
        question = user.rsplit("Question:", 1)[-1].split("\n", 1)[0]
        q_terms = set(re.findall(r"[a-z0-9]{4,}", question.lower()))

        def overlap(item):
            title = item[2].split("\n", 1)[0].lower()
            return sum(t in title for t in q_terms) * 3 + sum(t in item[2].lower() for t in q_terms)

        ranked = sorted(sources, key=overlap, reverse=True)
        parts = []
        for n, ref, text in ranked[:3]:
            body = text.split("\n\n", 1)[-1].replace("\n", " ")
            first = re.split(r"(?<=[.!?])\s", body, maxsplit=1)[0]
            parts.append(f"{ref}: {first} [{n}]")
        answer = " ".join(parts) or "The indexed sources don't cover this."
        for i in range(0, len(answer), 24):
            yield answer[i : i + 24]
        self._usage = Usage(len(user) // 4, len(answer) // 4)

    @property
    def usage(self) -> Usage:
        return self._usage


def get_llm(model: str) -> LLM:
    if os.getenv("LLM_BACKEND", "claude") == "fake":
        return FakeLLM(model="fake")
    return ClaudeLLM(model)
