"""Unit tests: ATT&CK attribution and policy.  Run:  pytest tests -q"""
import json
import sys
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from attack_detective.attribution.keywords import KEYWORDS
from attack_detective.attribution.label_map import LABEL_TO_TECHNIQUES, is_correct
from attack_detective.attribution.retrieve import Retriever
from attack_detective.attribution.stix_loader import AttackTechnique, clean_text, load_techniques
from attack_detective.contracts.schemas import Technique
from attack_detective.policy.rules import decide

TECHS = [
    AttackTechnique("T1046", "Network Service Discovery", "Adversaries may scan ports and services.",
                    ["discovery"], False),
    AttackTechnique("T1110", "Brute Force", "Adversaries may guess passwords with repeated logins.",
                    ["credential-access"], False),
    AttackTechnique("T1498", "Network Denial of Service", "Adversaries may flood the network with traffic.",
                    ["impact"], False),
]


def test_clean_text_removes_citations_and_links():
    s = "Scan ports.(Citation: X 2020) See [Nmap](https://nmap.org) <code>x</code>"
    assert clean_text(s) == "Scan ports. See Nmap x"


def test_stix_loader_filters_revoked_and_deprecated(tmp_path):
    def ap(tid, **kw):
        return {"type": "attack-pattern", "name": tid, "description": "d",
                "external_references": [{"source_name": "mitre-attack", "external_id": tid}], **kw}
    bundle = {"objects": [ap("T1"), ap("T2", revoked=True), ap("T3", x_mitre_deprecated=True),
                          {"type": "malware", "name": "m"}]}
    f = tmp_path / "b.json"
    f.write_text(json.dumps(bundle), encoding="utf-8")
    assert [t.technique_id for t in load_techniques(f)] == ["T1"]


def test_tfidf_retrieval_ranks_the_obvious_technique_first():
    r = Retriever(TECHS, "tfidf", enriched=False)
    assert r.attribute("repeated logins guessing passwords", k=3)[0].technique_id == "T1110"
    assert len(r.attribute("anything", k=2)) == 2


def test_minilm_path_with_fake_encoder():
    vocab = ["scan", "ports", "passwords", "logins", "flood", "traffic"]
    enc = lambda texts: np.array([[t.lower().count(w) for w in vocab] for t in texts], np.float32) + 1e-3
    r = Retriever(TECHS, "minilm", enriched=False, encoder=enc)
    assert r.attribute("flood traffic")[0].technique_id == "T1498"


def test_label_map_and_correctness():
    assert is_correct("T1110.001", "SSH-Patator") and not is_correct("T1046", "SSH-Patator")
    assert not is_correct("T1046", "BENIGN") and LABEL_TO_TECHNIQUES["INFILTRATION"] is None


def test_keywords_do_not_contain_cicids_label_names():
    banned = ["portscan", "patator", "hulk", "goldeneye", "slowloris", "slowhttptest", "heartbleed", "cicids"]
    text = " ".join(KEYWORDS.values()).lower()
    assert not [b for b in banned if b in text]


def test_policy_rules():
    techs = [Technique("T1046", "Network Service Discovery", 0.3)]
    cfg = {"high_multiplier": 3.0, "s_min": 0.2}
    e = {"flow_id": 1, "threshold": 1.0}
    assert decide({**e, "score": 0.5}, techs, cfg).action == "ALLOW"
    assert decide({**e, "score": 2.0}, techs, cfg).action == "MONITOR"
    assert decide({**e, "score": 5.0}, techs, cfg).action == "BLOCK"
    low = [Technique("T1046", "x", 0.1)]
    assert decide({**e, "score": 5.0}, low, cfg).action == "MONITOR"
