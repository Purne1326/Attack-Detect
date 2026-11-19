"""Signed-log transform + standardisation, fitted on benign training data only."""
import pickle
from pathlib import Path

import numpy as np
import pandas as pd


def signed_log(a: np.ndarray) -> np.ndarray:
    # Network features are heavy-tailed (bytes/s up to 1e9); log compresses them.
    return np.sign(a) * np.log1p(np.abs(a))


class FeatureScaler:
    def __init__(self, clip: float = 10.0):
        self.clip = clip

    def fit(self, X: pd.DataFrame) -> "FeatureScaler":
        Z = signed_log(X.to_numpy(np.float32))
        mean = Z.mean(axis=0, dtype=np.float64)
        std = Z.std(axis=0, dtype=np.float64)
        keep = std > 1e-8                       # drop columns constant in benign training data
        self.columns = [c for c, k in zip(X.columns, keep) if k]
        self.dropped_constant = [c for c, k in zip(X.columns, keep) if not k]
        self.mean = mean[keep].astype(np.float32)
        self.std = std[keep].astype(np.float32)
        return self

    def transform(self, X: pd.DataFrame) -> np.ndarray:
        Z = signed_log(X[self.columns].to_numpy(np.float32))
        Z = (Z - self.mean) / self.std
        return np.clip(Z, -self.clip, self.clip).astype(np.float32)

    def save(self, path):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        with open(path, "wb") as f:
            pickle.dump(self, f)

    @staticmethod
    def load(path) -> "FeatureScaler":
        with open(path, "rb") as f:
            return pickle.load(f)
