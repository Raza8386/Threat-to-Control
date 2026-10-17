"""MITRE ATT&CK Enterprise -> one chunk per technique / sub-technique.

Run from backend/:  python -m ingest.attack [--force]
"""

from __future__ import annotations

import argparse
import json
import re
from collections import defaultdict

from ingest.common import CHUNKS_DIR, RAW_DIR, download, make_chunks, write_jsonl

URLS = ["https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"]
RAW_PATH = RAW_DIR / "enterprise-attack.json"
OUT_PATH = CHUNKS_DIR / "attack.jsonl"

_CITATION = re.compile(r"\s*\(Citation:[^)]*\)")
_MD_LINK = re.compile(r"\[([^\]]+)\]\((?:https?://[^)]+)\)")
_TAGS = re.compile(r"</?code>")


def clean(text: str | None) -> str:
    if not text:
        return ""
    text = _CITATION.sub("", text)
    text = _MD_LINK.sub(r"\1", text)
    text = _TAGS.sub("", text)
    return text.strip()


def is_active(obj: dict) -> bool:
    return not obj.get("revoked") and not obj.get("x_mitre_deprecated")


def attack_ref(obj: dict) -> tuple[str, str] | None:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
            return ref["external_id"], ref.get("url", "")
    return None


def build(bundle: dict) -> tuple[list[dict], int]:
    objects = bundle["objects"]
    by_id = {o["id"]: o for o in objects}

    mitigations: dict[str, list[str]] = defaultdict(list)
    detections: dict[str, list[str]] = defaultdict(list)
    for rel in objects:
        if rel.get("type") != "relationship" or not is_active(rel):
            continue
        src = by_id.get(rel.get("source_ref", ""))
        if not src or not is_active(src):
            continue
        if rel.get("relationship_type") == "mitigates" and src.get("type") == "course-of-action":
            mitigations[rel["target_ref"]].append(src["name"])
        elif rel.get("relationship_type") == "detects":
            detections[rel["target_ref"]].append(src.get("name", ""))

    techniques = [o for o in objects if o.get("type") == "attack-pattern" and is_active(o)]
    chunks: list[dict] = []
    units = 0
    for tech in techniques:
        ref = attack_ref(tech)
        if not ref:
            continue
        tid, url = ref
        tactics = [p["phase_name"].replace("-", " ").title() for p in tech.get("kill_chain_phases", [])]
        platforms = tech.get("x_mitre_platforms", [])
        name = tech["name"]
        if tech.get("x_mitre_is_subtechnique") and "." in tid:
            parent = next((o for o in techniques if (attack_ref(o) or ("",))[0] == tid.split(".")[0]), None)
            if parent:
                name = f"{parent['name']}: {name}"
        title = f"{tid} {name} (MITRE ATT&CK)"

        parts = [
            f"Tactics: {', '.join(tactics)}" if tactics else "",
            f"Platforms: {', '.join(platforms)}" if platforms else "",
            clean(tech.get("description")),
        ]
        if tech.get("x_mitre_detection"):
            parts.append("Detection: " + clean(tech["x_mitre_detection"]))
        if detections.get(tech["id"]):
            parts.append("Detected by: " + ", ".join(sorted(set(filter(None, detections[tech["id"]])))))
        if mitigations.get(tech["id"]):
            parts.append("Mitigations: " + ", ".join(sorted(set(mitigations[tech["id"]]))))
        body = "\n\n".join(p for p in parts if p)

        chunks.extend(make_chunks("attack", tid, title, url, body, {"tactics": ", ".join(tactics)}))
        units += 1
    return chunks, units


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--force", action="store_true", help="re-download the source")
    args = ap.parse_args()
    path = download(URLS, RAW_PATH, force=args.force)
    bundle = json.loads(path.read_text(encoding="utf-8"))
    chunks, units = build(bundle)
    n = write_jsonl(chunks, OUT_PATH)
    print(f"ATT&CK: {units} techniques -> {n} chunks -> {OUT_PATH.name}")


if __name__ == "__main__":
    main()
