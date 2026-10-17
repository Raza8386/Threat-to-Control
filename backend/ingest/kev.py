"""CISA Known Exploited Vulnerabilities -> one chunk per CVE.

Run from backend/:  python -m ingest.kev [--force]
"""

from __future__ import annotations

import argparse
import json

from ingest.common import CHUNKS_DIR, RAW_DIR, download, make_chunks, write_jsonl

URLS = [
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    "https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json",
]
RAW_PATH = RAW_DIR / "known_exploited_vulnerabilities.json"
OUT_PATH = CHUNKS_DIR / "kev.jsonl"


def build(feed: dict) -> list[dict]:
    chunks = []
    for v in feed["vulnerabilities"]:
        cve = v["cveID"]
        title = f"{cve} {v.get('vulnerabilityName', '').strip()} (CISA KEV)"
        lines = [
            f"Vendor: {v.get('vendorProject', '')}",
            f"Product: {v.get('product', '')}",
            f"Added to KEV: {v.get('dateAdded', '')}",
            f"Description: {v.get('shortDescription', '')}",
            f"Required action: {v.get('requiredAction', '')}",
            f"Due date for federal agencies: {v.get('dueDate', '')}",
            f"Known ransomware campaign use: {v.get('knownRansomwareCampaignUse', 'Unknown')}",
        ]
        if v.get("cwes"):
            lines.append("CWEs: " + ", ".join(v["cwes"]))
        url = f"https://nvd.nist.gov/vuln/detail/{cve}"
        extra = {"date_added": v.get("dateAdded", ""), "due_date": v.get("dueDate", "")}
        chunks.extend(make_chunks("kev", cve, title, url, "\n".join(lines), extra))
    return chunks


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--force", action="store_true")
    args = ap.parse_args()
    path = download(URLS, RAW_PATH, force=args.force)
    feed = json.loads(path.read_text(encoding="utf-8"))
    chunks = build(feed)
    n = write_jsonl(chunks, OUT_PATH)
    print(f"KEV: {feed.get('count', len(feed['vulnerabilities']))} CVEs (catalog {feed.get('catalogVersion')}) -> {n} chunks -> {OUT_PATH.name}")


if __name__ == "__main__":
    main()
