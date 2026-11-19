"""Step 11: end-to-end - every decision is signed + encrypted, verified by the enforcer, then applied."""
import json

from common import Dirs, banner, load_cfg, need
from attack_detective.pipeline.run_pipeline import run


def main():
    banner("Step 11 - end-to-end secure delivery")
    full = load_cfg()
    cfg, d = full["pqc"], Dirs(full)
    need(d.art_att / "decisions.jsonl", "step 08 (08_decide_policy.py)")
    with open(d.art_att / "decisions.jsonl", encoding="utf-8") as f:
        decisions = [json.loads(line) for line in f if line.strip()]
    summary = run(decisions, cfg["mode"], cfg["backend"], cfg["allow_pure_python"], d.art_pqc / "enforcer_log.jsonl")
    print(json.dumps(summary, indent=2))
    (d.res_pqc / "pipeline_summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    if summary["accepted"] != summary["alerts"]:
        raise SystemExit("Some valid alerts were rejected - check artifacts/pqc/enforcer_log.jsonl")
    print("All alerts verified and applied. Next:  streamlit run dashboard\\app.py")


if __name__ == "__main__":
    main()
