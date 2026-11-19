"""Shared helpers for every step script: project root, config, folders, JSON."""
import json
import os
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))           # lets the scripts import attack_detective

DEMO = os.environ.get("AD_DEMO") == "1"          # set by:  python run_all.py --demo


def load_cfg() -> dict:
    with open(ROOT / "config.yaml", encoding="utf-8") as f:
        cfg = yaml.safe_load(f)
    if DEMO:
        # Demo mode: synthetic data, separate folders, fast settings. Never mixes with real results.
        p = cfg["paths"]
        p["raw_dir"] = "data/raw_demo"
        p["processed_dir"] = "data/processed_demo"
        p["artifacts_dir"] = "artifacts_demo"
        p["results_dir"] = "results_demo"
        cfg["detection"]["seeds"] = [0, 1]
        cfg["detection"]["ae"]["epochs"] = 8
        cfg["pqc"]["bench_runs"] = 50
    return cfg


class Dirs:
    """All folders used by the steps (created on first use)."""

    def __init__(self, cfg: dict):
        p = cfg["paths"]
        self.raw = ROOT / p["raw_dir"]
        self.stix = ROOT / p["stix_path"]
        self.processed = ROOT / p["processed_dir"]
        art, res = ROOT / p["artifacts_dir"], ROOT / p["results_dir"]
        self.art_det, self.art_att, self.art_pqc = art / "detection", art / "attribution", art / "pqc"
        self.res_det, self.res_att, self.res_pqc = res / "detection", res / "attribution", res / "pqc"
        for d in (self.processed, self.art_det, self.art_att, self.art_pqc,
                  self.res_det, self.res_att, self.res_pqc):
            d.mkdir(parents=True, exist_ok=True)


def banner(title: str):
    tag = "   [DEMO MODE - synthetic data, not real results]" if DEMO else ""
    print(f"\n=== {title}{tag}")


def need(path: Path, made_by: str):
    """Stop with a clear message if an earlier step has not been run."""
    if not Path(path).exists():
        raise SystemExit(f"\nMissing {path}\n-> run {made_by} first.")


def save_json(obj, path):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2)


def load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


SAMPLE_DECISION = {"flow_id": 0, "score": 3.2, "action": "BLOCK", "reason": "sample",
                   "techniques": [{"technique_id": "T1046", "name": "Network Service Discovery", "similarity": 0.31},
                                  {"technique_id": "T1595", "name": "Active Scanning", "similarity": 0.22},
                                  {"technique_id": "T1110", "name": "Brute Force", "similarity": 0.12}]}


def sample_decisions(cfg) -> list:
    """Real decisions from step 08 if they exist, otherwise one realistic sample decision."""
    f = Dirs(cfg).art_att / "decisions.jsonl"
    if f.exists():
        with open(f, encoding="utf-8") as fh:
            return [json.loads(line) for line in fh if line.strip()]
    print("  (no decisions.jsonl yet - using a built-in sample decision)")
    return [SAMPLE_DECISION]
