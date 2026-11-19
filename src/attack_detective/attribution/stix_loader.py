"""Load MITRE ATT&CK Enterprise techniques from the STIX JSON bundle."""
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import List


@dataclass
class AttackTechnique:
    technique_id: str          # e.g. "T1046" or "T1110.001"
    name: str
    description: str           # citations and markdown links removed
    tactics: List[str]
    is_subtechnique: bool


_CITATION = re.compile(r"\(Citation:[^)]*\)")
_MD_LINK = re.compile(r"\[([^\]]+)\]\([^)]+\)")
_HTML = re.compile(r"<[^>]+>")


def clean_text(s: str) -> str:
    s = _CITATION.sub("", s or "")
    s = _MD_LINK.sub(r"\1", s)
    s = _HTML.sub(" ", s)
    return re.sub(r"\s+", " ", s).strip()


def load_techniques(stix_path) -> List[AttackTechnique]:
    """Return active (not revoked, not deprecated) Enterprise techniques, sorted by ID."""
    with Path(stix_path).open(encoding="utf-8") as f:
        bundle = json.load(f)
    out = []
    for o in bundle["objects"]:
        if o.get("type") != "attack-pattern" or o.get("revoked") or o.get("x_mitre_deprecated"):
            continue
        ext = next((r for r in o.get("external_references", [])
                    if r.get("source_name") == "mitre-attack"), None)
        if not ext:
            continue
        out.append(AttackTechnique(
            technique_id=ext["external_id"], name=o["name"],
            description=clean_text(o.get("description", "")),
            tactics=[p["phase_name"] for p in o.get("kill_chain_phases", [])],
            is_subtechnique=bool(o.get("x_mitre_is_subtechnique", False))))
    return sorted(out, key=lambda t: t.technique_id)
