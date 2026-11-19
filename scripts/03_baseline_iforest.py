"""Step 03: Isolation Forest baseline (same benign training data, same seeds)."""
import numpy as np

from common import Dirs, banner, load_cfg, need
from attack_detective.detection.iforest import fit_iforest, iforest_scores


def main():
    banner("Step 03 - Isolation Forest baseline")
    cfg = load_cfg()
    c, d = cfg["detection"], Dirs(cfg)
    need(d.processed / "X_train.npy", "step 01 (01_prepare_data.py)")
    X_train = np.load(d.processed / "X_train.npy")
    X_val = np.load(d.processed / "X_val.npy")
    X_test = np.load(d.processed / "X_test.npy")
    f = c["iforest"]
    for seed in c["seeds"]:
        print(f"  Isolation Forest seed {seed} ...")
        m = fit_iforest(X_train, seed, f["n_estimators"], f["max_samples"], f["train_cap"])
        np.save(d.art_det / f"val_scores_if_seed{seed}.npy", iforest_scores(m, X_val))
        np.save(d.art_det / f"test_scores_if_seed{seed}.npy", iforest_scores(m, X_test))
    print("Saved Isolation Forest scores to", d.art_det)


if __name__ == "__main__":
    main()
