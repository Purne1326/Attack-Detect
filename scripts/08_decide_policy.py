"""Step 08: tune Allow/Monitor/Block on one half, test on the other half, write decisions.jsonl."""
import numpy as np
import pandas as pd

from common import Dirs, banner, load_cfg, need, save_json
from attack_detective.contracts.io import read_jsonl, write_jsonl
from attack_detective.contracts.schemas import Technique
from attack_detective.policy.rules import decide


def rates(decisions, labels):
    acts = np.array([x.action for x in decisions])
    benign = np.char.upper(labels.astype(str)) == "BENIGN"
    out = {}
    for grp, m in (("benign", benign), ("attack", ~benign)):
        for act in ("ALLOW", "MONITOR", "BLOCK"):
            out[f"{grp}_{act.lower()}"] = float(np.mean(acts[m] == act)) if m.any() else float("nan")
    return out


def main():
    banner("Step 08 - Allow / Monitor / Block policy")
    cfg = load_cfg()
    pol, d = cfg["policy"], Dirs(cfg)
    need(d.art_att / "attributions.jsonl", "step 07 (07_evaluate_attribution.py)")
    expl = read_jsonl(d.art_det / "explanations.jsonl")
    attr = {x["flow_id"]: [Technique(**t) for t in x["techniques"]] for x in read_jsonl(d.art_att / "attributions.jsonl")}
    labels = np.array([e["true_label"] for e in expl])          # for measuring only
    perm = np.random.default_rng(0).permutation(len(expl))
    cut = int(pol["tune_fraction"] * len(expl))
    tune, test = perm[:cut], perm[cut:]

    def run(ids, params):
        ids = list(ids)
        return [decide(expl[i], attr[expl[i]["flow_id"]], params) for i in ids], labels[ids]

    grid = [{"high_multiplier": m, "s_min": s, **rates(*run(tune, {"high_multiplier": m, "s_min": s}))}
            for m in pol["grid_high_multiplier"] for s in pol["grid_s_min"]]
    g = pd.DataFrame(grid)
    g.round(4).to_csv(d.res_att / "policy_grid_tuning.csv", index=False)
    ok = g[g["benign_block"] <= pol["max_benign_block_rate"]]
    best = (ok if len(ok) else g).sort_values(["attack_block", "s_min"], ascending=[False, False]).iloc[0]
    chosen = {"high_multiplier": float(best["high_multiplier"]), "s_min": float(best["s_min"])}
    print("Chosen on the tuning half:", chosen)

    rows = [{"policy": name, "high_multiplier": p["high_multiplier"], "s_min": p["s_min"], **rates(*run(test, p))}
            for name, p in (("config.yaml values", pol), ("tuned", chosen))]
    t = pd.DataFrame(rows).round(4)
    t.to_csv(d.res_att / "policy_metrics_test_half.csv", index=False)
    print(t.T.to_string(header=False))
    save_json(chosen, d.res_att / "policy_chosen.json")

    decisions, _ = run(range(len(expl)), chosen)
    n = write_jsonl(decisions, d.art_att / "decisions.jsonl")
    counts = pd.Series([x.action for x in decisions]).value_counts().to_dict()
    print(f"Wrote {n:,} decisions {counts} -> {d.art_att / 'decisions.jsonl'}")
    print("Copy the chosen values into config.yaml (policy section) and state them in the report.")


if __name__ == "__main__":
    main()
