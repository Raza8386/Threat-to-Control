"""Input guardrail, layer 1: cheap regex heuristics.

Phase 3 adds layer 2: ambiguous scores go to a Claude Haiku classifier returning strict JSON.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

MAX_CHARS = 1000

# (pattern, weight). A score >= BLOCK is blocked outright; between REVIEW and BLOCK is "ambiguous".
_RULES: list[tuple[re.Pattern, float]] = [
    (re.compile(r"\b(ignore|disregard|forget|override)\b.{0,40}\b(previous|prior|above|earlier|all|your)\b.{0,30}\b(instructions?|rules?|prompts?|directions?)", re.I), 1.0),
    (re.compile(r"\b(reveal|show|print|repeat|output|leak|tell me)\b.{0,40}\b(system|hidden|initial|original)\s+(prompt|instructions?|message)", re.I), 1.0),
    (re.compile(r"\byou are now\b|\bact as\b.{0,30}\b(unrestricted|jailbroken|dan|developer mode)\b|\bdeveloper mode\b", re.I), 0.8),
    (re.compile(r"\b(pretend|roleplay|role-play)\b.{0,40}\b(no|without)\b.{0,20}\b(rules|restrictions|filters|limits)\b", re.I), 0.8),
    (re.compile(r"</?\s*(system|sources?|instructions?)\s*>", re.I), 0.6),
    (re.compile(r"\b(base64|rot13)\b.{0,30}\b(decode|execute|follow)\b", re.I), 0.5),
    (re.compile(r"[​-‏⁠﻿]"), 0.5),  # zero-width / invisible characters
]
BLOCK = 0.8
REVIEW = 0.4


@dataclass
class Verdict:
    verdict: str  # "allow" | "block"
    reason: str
    score: float = 0.0
    layer: str = "heuristic"

    def as_event(self) -> dict:
        return {"verdict": self.verdict, "reason": self.reason, "score": round(self.score, 2), "layer": self.layer}


def heuristic_score(text: str) -> float:
    return min(1.0, sum(w for pat, w in _RULES if pat.search(text)))


def check(question: str) -> Verdict:
    q = (question or "").strip()
    if not q:
        return Verdict("block", "Empty question.")
    if len(q) > MAX_CHARS:
        return Verdict("block", f"Question is longer than {MAX_CHARS} characters.")
    score = heuristic_score(q)
    if score >= BLOCK:
        return Verdict("block", "Looks like a prompt-injection attempt.", score)
    if score >= REVIEW:
        # Phase 3: send to the LLM classifier. Until then, allow; the grounded prompt still treats sources as data.
        return Verdict("allow", "Ambiguous; allowed pending classifier (Phase 3).", score)
    return Verdict("allow", "No injection patterns found.", score)
