"""Train the autoencoder on benign flows with early stopping on validation loss."""
import copy
import time

import numpy as np
import torch
import torch.nn.functional as F

from .autoencoder import AutoEncoder
from .score import anomaly_scores


def set_seed(seed: int):
    np.random.seed(seed)
    torch.manual_seed(seed)


def train_autoencoder(X_train: np.ndarray, X_val: np.ndarray, cfg: dict, seed: int):
    """Manual mini-batching (no DataLoader) - fast and safe on Windows."""
    set_seed(seed)
    Xtr = torch.from_numpy(X_train)
    model = AutoEncoder(X_train.shape[1], tuple(cfg["hidden"]))
    opt = torch.optim.Adam(model.parameters(), lr=cfg["lr"])
    gen = torch.Generator().manual_seed(seed)
    bs = cfg["batch_size"]
    best_val, best_state, bad, history = float("inf"), None, 0, []

    for epoch in range(1, cfg["epochs"] + 1):
        t0 = time.time()
        model.train()
        perm = torch.randperm(len(Xtr), generator=gen)
        total = 0.0
        for i in range(0, len(Xtr), bs):
            xb = Xtr[perm[i:i + bs]]
            loss = F.mse_loss(model(xb), xb)
            opt.zero_grad()
            loss.backward()
            opt.step()
            total += loss.item() * len(xb)
        train_loss = total / len(Xtr)
        val_loss = float(anomaly_scores(model, X_val).mean())
        history.append({"epoch": epoch, "train_loss": train_loss, "val_loss": val_loss,
                        "seconds": round(time.time() - t0, 1)})
        print(f"    seed {seed} epoch {epoch:2d}  train {train_loss:.5f}  val {val_loss:.5f}"
              f"  ({time.time() - t0:.1f}s)")
        if val_loss < best_val - 1e-6:
            best_val, best_state, bad = val_loss, copy.deepcopy(model.state_dict()), 0
        else:
            bad += 1
            if bad >= cfg["patience"]:
                print(f"    early stop at epoch {epoch}")
                break
    model.load_state_dict(best_state)
    model.eval()
    return model, history
