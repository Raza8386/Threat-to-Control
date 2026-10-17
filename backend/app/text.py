"""Tokenizing and exact-ID detection shared by indexing and retrieval."""

from __future__ import annotations

import re

# Keeps IDs whole: "t1059.001", "cve-2015-5477", "a03" stay single tokens.
_TOKEN_RE = re.compile(r"[a-z0-9]+(?:[.\-][a-z0-9]+)*")

_STOPWORDS = frozenset(
    "a an and are as at be by can do does for from how i in is it its may of on or that the this to was what "
    "when where which who why will with".split()
)

_ID_PATTERNS = [
    re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE),        # ATT&CK technique / sub-technique
    re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE),          # CVE
    re.compile(r"\bA(?:0[1-9]|10)(?::2021)?\b", re.IGNORECASE),   # OWASP Top 10 2021 category
]


def tokenize(text: str) -> list[str]:
    tokens = _TOKEN_RE.findall(text.lower())
    out = []
    for t in tokens:
        if t in _STOPWORDS:
            continue
        out.append(t)
        # Also index the parts of dotted/hyphenated tokens, so "t1059.001" matches "t1059" and "cve-2015-5477" matches "5477".
        if "." in t or "-" in t:
            out.extend(p for p in re.split(r"[.\-]", t) if p and p not in _STOPWORDS)
    return out


def extract_ids(text: str) -> list[str]:
    """Return canonical IDs mentioned in a question, e.g. ['T1059.001', 'CVE-2015-5477', 'A03:2021']."""
    found: list[str] = []
    for pat in _ID_PATTERNS:
        for m in pat.findall(text):
            ident = m.upper()
            if re.fullmatch(r"A\d{2}", ident):
                ident += ":2021"
            if ident not in found:
                found.append(ident)
    return found
