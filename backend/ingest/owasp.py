"""OWASP Top 10 (2021) -> one chunk per category, split into ~500-token pieces when long.

Run from backend/:  python -m ingest.owasp [--force]
"""

from __future__ import annotations

import argparse
import re

from ingest.common import CHUNKS_DIR, RAW_DIR, download, make_chunks, write_jsonl

BASE = "https://raw.githubusercontent.com/OWASP/Top10/master/2021/docs/en/"
CATEGORIES = [
    ("A01", "A01_2021-Broken_Access_Control"),
    ("A02", "A02_2021-Cryptographic_Failures"),
    ("A03", "A03_2021-Injection"),
    ("A04", "A04_2021-Insecure_Design"),
    ("A05", "A05_2021-Security_Misconfiguration"),
    ("A06", "A06_2021-Vulnerable_and_Outdated_Components"),
    ("A07", "A07_2021-Identification_and_Authentication_Failures"),
    ("A08", "A08_2021-Software_and_Data_Integrity_Failures"),
    ("A09", "A09_2021-Security_Logging_and_Monitoring_Failures"),
    ("A10", "A10_2021-Server-Side_Request_Forgery_(SSRF)"),
]
OUT_PATH = CHUNKS_DIR / "owasp.jsonl"

# Sections that add noise rather than answers.
DROP_SECTIONS = {"references", "list of mapped cwes", "factors"}


def clean_markdown(md: str) -> tuple[str, str]:
    """Return (heading title, cleaned body) from an OWASP Top 10 page."""
    md = re.sub(r"<[^>]+>", "", md)                       # html tags / icons
    md = re.sub(r"!\[[^\]]*\]\([^)]*\)", "", md)            # images
    md = re.sub(r"\[([^\]]+)\]\([^)]*\)", r"\1", md)        # links -> text
    md = re.sub(r"\{[^}]*\}", "", md)                       # mkdocs attribute lists

    title = ""
    kept, skip = [], False
    for line in md.splitlines():
        h = re.match(r"^(#{1,3})\s+(.*)", line)
        if h:
            heading = h.group(2).strip()
            if h.group(1) == "#" and not title:
                title = heading
                continue
            skip = heading.lower() in DROP_SECTIONS
            if not skip:
                kept.append(f"\n{heading}\n")
            continue
        if skip or line.strip().startswith("|"):           # drop stat tables
            continue
        kept.append(line)
    body = re.sub(r"\n{3,}", "\n\n", "\n".join(kept)).strip()
    return title, body


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--force", action="store_true")
    args = ap.parse_args()
    chunks = []
    for code, slug in CATEGORIES:
        path = download([f"{BASE}{slug}.md"], RAW_DIR / "owasp" / f"{slug}.md", force=args.force)
        heading, body = clean_markdown(path.read_text(encoding="utf-8"))
        name = re.sub(r"^A\d{2}:2021\s*[–-]\s*", "", heading) or slug.split("-", 1)[1].replace("_", " ")
        ref_id = f"{code}:2021"
        title = f"{ref_id} {name} (OWASP Top 10)"
        url = f"https://owasp.org/Top10/{slug}/"
        chunks.extend(make_chunks("owasp", ref_id, title, url, body))
    n = write_jsonl(chunks, OUT_PATH)
    print(f"OWASP: {len(CATEGORIES)} categories -> {n} chunks -> {OUT_PATH.name}")


if __name__ == "__main__":
    main()
