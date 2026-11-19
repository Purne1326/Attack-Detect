"""Step 02: train the autoencoder on benign flows for every seed; save models and scores."""
import os

import numpy as np
import pandas as pd
import torch

from common import Dirs, banner, load_cfg, need
from attack_detective.detection.autoencoder import save_model
from attack_detective.detection.score import anomaly_scores
from attack_detective.detection.train import train_autoencoder


def main():
    banner("Step 02 - train autoencoder")
    cfg = load_cfg()
    c, d = cfg["detection"], Dirs(cfg)
    need(d.processed / "X_train.npy", "step 01 (01_prepare_data.py)")
    torch.set_num_threads(os.cpu_count() or 4)
    X_train = np.load(d.processed / "X_train.npy")
    X_val = np.load(d.processed / "X_val.npy")
    X_test = np.load(d.processed / "X_test.npy")
    print(f"train {X_train.shape}  val {X_val.shape}  test {X_test.shape}  | CPU threads {torch.get_num_threads()}")
    for seed in c["seeds"]:
        print(f"-- seed {seed}")
        model, history = train_autoencoder(X_train, X_val, c["ae"], seed)
        save_model(model, d.art_det / f"ae_seed{seed}.pt")
        pd.DataFrame(history).to_csv(d.res_det / f"ae_loss_seed{seed}.csv", index=False)
        np.save(d.art_det / f"val_scores_ae_seed{seed}.npy", anomaly_scores(model, X_val))
        np.save(d.art_det / f"test_scores_ae_seed{seed}.npy", anomaly_scores(model, X_test))
    print("Saved models and scores to", d.art_det)


if __name__ == "__main__":
    main()
