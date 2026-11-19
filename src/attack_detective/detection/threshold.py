"""Thresholds from benign validation scores, and detection metrics."""
import numpy as np
from sklearn.metrics import roc_auc_score


def thresholds_from_val(val_scores: np.ndarray, percentiles) -> dict:
    return {int(p): float(np.percentile(val_scores, p)) for p in percentiles}


def binary_metrics(scores: np.ndarray, y_attack: np.ndarray, t: float) -> dict:
    pred = scores >= t
    tp = int(np.sum(pred & y_attack)); fp = int(np.sum(pred & ~y_attack))
    fn = int(np.sum(~pred & y_attack)); tn = int(np.sum(~pred & ~y_attack))
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    fpr = fp / (fp + tn) if fp + tn else 0.0
    return {"precision": precision, "recall": recall, "f1": f1, "fpr": fpr,
            "tp": tp, "fp": fp, "fn": fn, "tn": tn}


def roc_auc(scores: np.ndarray, y_attack: np.ndarray) -> float:
    return float(roc_auc_score(y_attack.astype(int), scores))


def per_family_detection(scores: np.ndarray, labels: np.ndarray, t: float) -> dict:
    """Share of flows of each label flagged as anomalous (for BENIGN this is the FPR)."""
    out = {}
    for lab in np.unique(labels):
        m = labels == lab
        out[str(lab)] = {"n": int(m.sum()), "flagged_rate": float(np.mean(scores[m] >= t))}
    return out
