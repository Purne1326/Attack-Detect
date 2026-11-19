"""Reconstruction errors, computed in batches to keep memory low."""
import numpy as np
import torch


@torch.no_grad()
def reconstruct(model, X: np.ndarray, batch: int = 65536) -> np.ndarray:
    model.eval()
    out = np.empty_like(X)
    for i in range(0, len(X), batch):
        xb = torch.from_numpy(X[i:i + batch])
        out[i:i + batch] = model(xb).detach().cpu().numpy()
    return out


@torch.no_grad()
def per_feature_errors(model, X: np.ndarray, batch: int = 65536) -> np.ndarray:
    """Squared error per flow and per feature, shape (n, d)."""
    model.eval()
    out = np.empty_like(X)
    for i in range(0, len(X), batch):
        xb = torch.from_numpy(X[i:i + batch])
        out[i:i + batch] = ((model(xb) - xb) ** 2).detach().cpu().numpy()
    return out


@torch.no_grad()
def anomaly_scores(model, X: np.ndarray, batch: int = 65536) -> np.ndarray:
    """Anomaly score = mean squared reconstruction error per flow, shape (n,)."""
    model.eval()
    out = np.empty(len(X), dtype=np.float32)
    for i in range(0, len(X), batch):
        xb = torch.from_numpy(X[i:i + batch])
        out[i:i + batch] = ((model(xb) - xb) ** 2).mean(dim=1).detach().cpu().numpy()
    return out
