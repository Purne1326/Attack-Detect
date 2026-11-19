"""Turn per-feature reconstruction errors into top-k features and a text explanation."""
from typing import List, Optional

import numpy as np

from attack_detective.contracts.schemas import Explanation
from attack_detective.detection.score import per_feature_errors, reconstruct
from .feature_dictionary import phrase


def fit_error_stats(model, X_val: np.ndarray):
    """Mean and SD of each feature's squared error on benign validation flows."""
    e = per_feature_errors(model, X_val)
    return e.mean(axis=0), e.std(axis=0) + 1e-8


def explain_flows(model, X: np.ndarray, flow_ids: np.ndarray, scores: np.ndarray,
                  threshold: float, feature_names: List[str], stats,
                  labels: Optional[np.ndarray] = None, top_k: int = 5) -> List[Explanation]:
    mu, sd = stats
    X_hat = reconstruct(model, X)
    z = ((X_hat - X) ** 2 - mu) / sd                   # how unusual each feature's error is
    top = np.argsort(-z, axis=1)[:, :top_k]
    out = []
    for r in range(len(X)):
        feats, phrases = [], []
        for j in top[r]:
            name = feature_names[j]
            feats.append((name, round(float(z[r, j]), 2)))
            phrases.append(phrase(name, higher=bool(X[r, j] > X_hat[r, j])))
        out.append(Explanation(
            flow_id=int(flow_ids[r]), score=float(scores[r]), threshold=float(threshold),
            is_anomaly=bool(scores[r] >= threshold), top_features=feats,
            text="; ".join(dict.fromkeys(phrases)),     # remove duplicate phrases, keep order
            true_label="" if labels is None else str(labels[r])))
    return out
