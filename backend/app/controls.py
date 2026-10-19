"""Threat -> NCA ECC-2:2024 control mapping.

Deterministic and auditable: no model is involved. For each retrieved source,
  ATT&CK technique -> its MITRE mitigations (official "mitigates" relationships, from the ingested chunks)
                   -> ECC controls (curated crosswalk, app/ecc/crosswalk.yaml)
  OWASP category   -> ECC controls (crosswalk)
  KEV CVE          -> ECC controls (crosswalk)
Every mapped control carries the trail ("basis") that produced it, so a reviewer can check each link.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

import yaml

from app.config import settings
from app.retrieve import Hit

log = logging.getLogger("controls")

ECC_DIR = Path(__file__).resolve().parent / "ecc"
MAX_CONTROLS = 10
_MITIGATIONS_LINE = re.compile(r"^Mitigations: (.+)$", re.MULTILINE)
_OWASP_ID = re.compile(r"^(A(?:0[1-9]|10))")


@dataclass
class Basis:
    n: int  # source number shown in the evidence rail
    ref_id: str  # T1566.001, A03, CVE-...
    via: str  # "M1032 Multi-factor Authentication", "OWASP A03 crosswalk", "KEV crosswalk"
    rationale: str


@dataclass
class MappedControl:
    ecc_id: str
    title: str
    subdomain_id: str
    subdomain: str
    domain: str
    primary: bool = False  # first-listed target for at least one basis
    basis: list[Basis] = field(default_factory=list)

    def as_event(self) -> dict:
        return {
            "ecc_id": self.ecc_id,
            "title": self.title,
            "subdomain_id": self.subdomain_id,
            "subdomain": self.subdomain,
            "domain": self.domain,
            "primary": self.primary,
            "basis": [b.__dict__ for b in self.basis],
        }


class EccCatalog:
    def __init__(self, path: Path = ECC_DIR / "ecc_2024.yaml"):
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        self.framework: dict = data["framework"]
        self.domains: dict[str, str] = {str(k): v for k, v in data["domains"].items()}
        self.subdomains: dict[str, str] = {str(k): v for k, v in data["subdomains"].items()}
        self.controls: dict[str, str] = {str(k): v for k, v in data["controls"].items()}

    def exists(self, ecc_id: str) -> bool:
        return ecc_id in self.controls or ecc_id in self.subdomains

    def describe(self, ecc_id: str) -> tuple[str, str, str, str]:
        """(title, subdomain_id, subdomain name, domain name) for a subcontrol or subdomain id."""
        parts = ecc_id.split("-")
        sub_id = "-".join(parts[:2])
        sub = self.subdomains[sub_id]
        title = self.controls.get(ecc_id, sub)
        return title, sub_id, sub, self.domains[parts[0]]


class Crosswalk:
    def __init__(self, path: Path = ECC_DIR / "crosswalk.yaml"):
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        self.techniques: dict[str, dict] = data.get("attack_techniques") or {}
        self.mitigations: dict[str, dict] = data["attack_mitigations"]
        self.mitigation_by_name = {v["name"].lower(): k for k, v in self.mitigations.items()}
        self.owasp: dict[str, dict] = data["owasp"]
        self.kev: dict = data["kev"]


def technique_mitigations(chunks_path: Path) -> dict[str, list[str]]:
    """ref_id -> mitigation names, read from the ingested ATT&CK chunks (the 'Mitigations:' line)."""
    out: dict[str, list[str]] = {}
    if not chunks_path.exists():
        log.warning("ATT&CK chunks not found at %s; technique mapping limited to retrieved text", chunks_path)
        return out
    with chunks_path.open(encoding="utf-8") as fh:
        for line in fh:
            chunk = json.loads(line)
            m = _MITIGATIONS_LINE.search(chunk["text"])
            if m:
                out[chunk["metadata"]["ref_id"]] = [s.strip() for s in m.group(1).split(", ") if s.strip()]
    return out


class ControlMapper:
    def __init__(self, catalog: EccCatalog, crosswalk: Crosswalk, tech_mitigations: dict[str, list[str]]):
        self.catalog = catalog
        self.crosswalk = crosswalk
        self.tech_mitigations = tech_mitigations

    def _targets(self, hit: Hit) -> list[tuple[str, str, list[str]]]:
        """[(via, rationale, ecc ids)] for one retrieved source."""
        meta = hit.metadata
        source, ref_id = meta.get("source"), str(meta.get("ref_id", ""))
        if source == "attack":
            out = []
            tech = self.crosswalk.techniques.get(ref_id) or self.crosswalk.techniques.get(ref_id.split(".")[0])
            if tech:
                out.append((f"{ref_id} technique crosswalk", tech["rationale"], tech["ecc"]))
            names = self.tech_mitigations.get(ref_id)
            if names is None:
                m = _MITIGATIONS_LINE.search(hit.text)
                names = [s.strip() for s in m.group(1).split(", ")] if m else []
            for name in names:
                mid = self.crosswalk.mitigation_by_name.get(name.lower())
                if mid:
                    entry = self.crosswalk.mitigations[mid]
                    out.append((f"{mid} {entry['name']}", entry["rationale"], entry["ecc"]))
            return out
        if source == "owasp":
            m = _OWASP_ID.match(ref_id)
            entry = self.crosswalk.owasp.get(m.group(1)) if m else None
            return [(f"OWASP {m.group(1)} crosswalk", entry["rationale"], entry["ecc"])] if entry else []
        if source == "kev":
            return [("KEV crosswalk", self.crosswalk.kev["rationale"], self.crosswalk.kev["ecc"])]
        return []

    def map(self, hits: list[Hit], limit: int = MAX_CONTROLS) -> list[MappedControl]:
        found: dict[str, MappedControl] = {}
        for n, hit in enumerate(hits, start=1):
            for via, rationale, ecc_ids in self._targets(hit):
                for i, ecc_id in enumerate(ecc_ids):
                    ecc_id = str(ecc_id)
                    if not self.catalog.exists(ecc_id):
                        log.warning("crosswalk target %s not in ECC catalogue; skipped", ecc_id)
                        continue
                    if ecc_id not in found:
                        title, sub_id, sub, dom = self.catalog.describe(ecc_id)
                        found[ecc_id] = MappedControl(ecc_id, title, sub_id, sub, dom)
                    mc = found[ecc_id]
                    mc.primary = mc.primary or i == 0
                    if not any(b.n == n and b.via == via for b in mc.basis):
                        mc.basis.append(Basis(n=n, ref_id=str(hit.metadata.get("ref_id", "")), via=via, rationale=rationale))
        ranked = sorted(found.values(), key=lambda c: (-_score(c), _id_key(c.ecc_id)))
        return ranked[:limit]


def _score(c: MappedControl) -> float:
    """Distinct reasons, weighted by the best rank each reason was reached from.

    Repetition does not inflate a control: six KEV hits all say "patch", so the KEV route counts once,
    at its best rank. A control reached for several different reasons, from top-ranked sources, wins.
    """
    best: dict[str, int] = {}
    for b in c.basis:
        key = "technique" if b.via.endswith("technique crosswalk") else b.via
        best[key] = min(best.get(key, b.n), b.n)
    # A technique-specific entry is more precise than a generic mitigation, so it weighs 1.5x.
    return sum((1.5 if k == "technique" else 1.0) / n for k, n in best.items()) + (0.5 if c.primary else 0.0)


def _id_key(ecc_id: str) -> tuple[int, ...]:
    return tuple(int(p) for p in ecc_id.split("-"))


@lru_cache(maxsize=1)
def default_mapper() -> ControlMapper:
    return ControlMapper(EccCatalog(), Crosswalk(), technique_mitigations(settings.chunks_dir / "attack.jsonl"))


def controls_event(hits: list[Hit]) -> dict:
    """Payload of the `controls` SSE event. Never raises: a mapping fault must not block the answer."""
    try:
        mapper = default_mapper()
        mapped = mapper.map(hits)
        return {
            "framework": mapper.catalog.framework["name"],
            "framework_url": mapper.catalog.framework["url"],
            "note": mapper.catalog.framework["disclaimer"],
            "controls": [c.as_event() for c in mapped],
        }
    except Exception as exc:  # noqa: BLE001
        log.error("control mapping failed: %s: %s", type(exc).__name__, exc)
        return {"framework": "NCA ECC-2:2024", "framework_url": "", "note": "", "controls": []}
