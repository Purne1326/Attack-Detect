"""Hand-made CICIDS2017 label -> acceptable ATT&CK technique IDs. EVALUATION ONLY.

This mapping is the team's own judgement (state that in the report). A prediction counts as
correct if its base ID (T1110.001 -> T1110) is in the accepted set.
Labels mapped to None are excluded from attribution accuracy (no clean ATT&CK match).
"""
from typing import Optional, Set

LABEL_TO_TECHNIQUES = {
    "PORTSCAN": {"T1046", "T1595"},
    "FTP-PATATOR": {"T1110"},
    "SSH-PATATOR": {"T1110"},
    "DDOS": {"T1498", "T1499"},
    "DOS HULK": {"T1499", "T1498"},
    "DOS GOLDENEYE": {"T1499", "T1498"},
    "DOS SLOWLORIS": {"T1499"},
    "DOS SLOWHTTPTEST": {"T1499"},
    "WEB ATTACK - BRUTE FORCE": {"T1110"},
    "WEB ATTACK - XSS": {"T1190", "T1189"},
    "WEB ATTACK - SQL INJECTION": {"T1190"},
    "BOT": {"T1071", "T1095", "T1105"},
    "HEARTBLEED": {"T1190"},        # exploit of a public-facing service (debatable; say so)
    "INFILTRATION": None,           # multi-stage; no single network-level technique
    "BENIGN": None,
}


def accepted(label: str) -> Optional[Set[str]]:
    return LABEL_TO_TECHNIQUES.get(str(label).strip().upper())


def base_id(technique_id: str) -> str:
    return technique_id.split(".")[0]


def is_correct(technique_id: str, label: str) -> bool:
    acc = accepted(label)
    return bool(acc) and base_id(technique_id) in acc
