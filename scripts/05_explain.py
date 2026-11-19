"""Step 05: top-5 suspicious features + text explanation per flow -> explanations.jsonl."""
import numpy as np
import pandas as pd

from common import Dirs, banner, load_cfg, load_json, need
from attack_detective.contracts.io import write_jsonl
from attack_detective.detection.autoencoder import load_model
from attack_detective.explain.explain import explain_flows, fit_error_stats


def main():
    banner("Step 05 - explanations")
    cfg = load_cfg()
    c, d = cfg["detection"], Dirs(cfg)
    ec = c["explain"]
    seed = ec["model_seed"]
    need(d.art_det / "thresholds.json", "step 04 (04_evaluate_detection.py)")
    model = load_model(d.art_det / f"ae_seed{seed}.pt")
    names = load_json(d.processed / "feature_names.json")
    X_val, X_test = np.load(d.processed / "X_val.npy"), np.load(d.processed / "X_test.npy")
    labels = pd.read_csv(d.processed / "test_labels.csv")["Label"].to_numpy().astype(str)
    scores = np.load(d.art_det / f"test_scores_ae_seed{seed}.npy")
    t = load_json(d.art_det / "thresholds.json")[f"ae_seed{seed}"][str(c["main_percentile"])]

    # Evaluation subset: up to per_label_cap flows of every label (keeps files small)
    rng = np.random.default_rng(0)
    idx = np.sort(np.concatenate([rng.choice(np.flatnonzero(labels == lab),
                                             min(int((labels == lab).sum()), ec["per_label_cap"]),
                                             replace=False) for lab in np.unique(labels)]))
    expl = explain_flows(model, X_test[idx], idx, scores[idx], t, names,
                         fit_error_stats(model, X_val), labels[idx], ec["top_k"])
    n = write_jsonl(expl, d.art_det / "explanations.jsonl")
    print(f"Wrote {n:,} explanations ({sum(e.is_anomaly for e in expl):,} flagged) -> "
          f"{d.art_det / 'explanations.jsonl'}")
    shown = set()
    for e in expl:
        if e.is_anomaly and e.true_label not in shown:
            shown.add(e.true_label)
            print(f"  {e.true_label:<28} {e.text}")


if __name__ == "__main__":
    main()
