"""Isolation Forest baseline (fitted on benign training flows only)."""
import numpy as np
from sklearn.ensemble import IsolationForest


def fit_iforest(X_train: np.ndarray, seed: int, n_estimators=100, max_samples=256,
                train_cap=200000) -> IsolationForest:
    rng = np.random.default_rng(seed)
    if train_cap and len(X_train) > train_cap:
        X_train = X_train[rng.choice(len(X_train), train_cap, replace=False)]
    model = IsolationForest(n_estimators=n_estimators, max_samples=max_samples,
                            random_state=seed, n_jobs=-1)
    model.fit(X_train)
    return model


def iforest_scores(model: IsolationForest, X: np.ndarray) -> np.ndarray:
    # score_samples: higher = more normal, so negate (higher = more anomalous, like the AE)
    return (-model.score_samples(X)).astype(np.float32)
