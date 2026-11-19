"""Benign-only train/val, mixed test. Attack labels are never used for training."""
import numpy as np
import pandas as pd


def is_benign(labels: pd.Series) -> np.ndarray:
    return labels.str.upper().eq("BENIGN").to_numpy()


def make_splits(labels: pd.Series, frac=(0.70, 0.15, 0.15), seed=42, benign_train_cap=None):
    """Return index arrays (train, val, test)."""
    rng = np.random.default_rng(seed)
    benign = is_benign(labels)
    b_idx = np.flatnonzero(benign)
    rng.shuffle(b_idx)
    n = len(b_idx)
    n_tr, n_va = int(frac[0] * n), int(frac[1] * n)
    train = b_idx[:n_tr]
    val = b_idx[n_tr:n_tr + n_va]
    test = np.concatenate([b_idx[n_tr + n_va:], np.flatnonzero(~benign)])
    if benign_train_cap:
        train = train[:benign_train_cap]
    return np.sort(train), np.sort(val), np.sort(test)
