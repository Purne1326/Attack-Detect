"""Unit tests: detection part.  Run all tests with:  pytest tests -q"""
import sys
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from attack_detective.data.clean import clean
from attack_detective.data.load import normalise_label
from attack_detective.data.scale import FeatureScaler
from attack_detective.data.split import make_splits
from attack_detective.detection.autoencoder import AutoEncoder
from attack_detective.detection.score import anomaly_scores, per_feature_errors
from attack_detective.detection.threshold import binary_metrics
from attack_detective.explain.explain import explain_flows, fit_error_stats


def _toy():
    df = pd.DataFrame({"A": [1, 2, np.inf, 4, 4, 6], "B": [1, 1, 1, 2, 2, 3],
                       "Flow ID": ["x"] * 6,
                       "Label": ["BENIGN", "BENIGN", "BENIGN", "PortScan", "PortScan", "BENIGN"]})
    return df


def test_label_fix():
    s = pd.Series([" Web Attack \x96 Brute Force ", "BENIGN"])
    assert normalise_label(s).tolist() == ["Web Attack - Brute Force", "BENIGN"]


def test_clean_removes_inf_duplicates_and_text_columns():
    X, labels, log = clean(_toy())
    assert log["after_inf_nan"] == 5 and log["after_duplicates"] == 4
    assert "Flow ID" not in X.columns and X.dtypes.eq(np.float32).all()


def test_splits_are_benign_only_and_disjoint():
    labels = pd.Series(["BENIGN"] * 100 + ["DDoS"] * 20)
    tr, va, te = make_splits(labels, seed=1)
    assert set(tr).isdisjoint(va) and set(tr).isdisjoint(te) and set(va).isdisjoint(te)
    assert labels.iloc[tr].eq("BENIGN").all() and labels.iloc[va].eq("BENIGN").all()
    assert labels.iloc[te].eq("DDoS").sum() == 20


def test_scaler_drops_constant_columns():
    X = pd.DataFrame({"a": np.arange(10, dtype=np.float32), "c": np.ones(10, np.float32)})
    sc = FeatureScaler().fit(X)
    assert sc.columns == ["a"] and abs(sc.transform(X).mean()) < 1e-5


def test_autoencoder_shapes_and_scores():
    X = np.random.default_rng(0).normal(size=(50, 8)).astype(np.float32)
    m = AutoEncoder(8)
    assert per_feature_errors(m, X).shape == (50, 8)
    s = anomaly_scores(m, X)
    assert s.shape == (50,) and np.allclose(s, per_feature_errors(m, X).mean(1), atol=1e-5)


def test_metrics():
    m = binary_metrics(np.array([0.1, 0.9, 0.8, 0.2]), np.array([False, True, False, False]), 0.5)
    assert m["tp"] == 1 and m["fp"] == 1 and abs(m["fpr"] - 1 / 3) < 1e-9


def test_explanations_follow_contract():
    X = np.random.default_rng(0).normal(size=(20, 4)).astype(np.float32)
    m = AutoEncoder(4, (3, 2))
    s = anomaly_scores(m, X)
    ex = explain_flows(m, X, np.arange(20), s, float(np.median(s)), ["Flow Duration", "SYN Flag Count",
                       "x", "y"], fit_error_stats(m, X), np.array(["BENIGN"] * 20), top_k=3)
    assert len(ex) == 20 and len(ex[0].top_features) == 3 and ex[0].text
    assert "DoS" not in ex[0].text
