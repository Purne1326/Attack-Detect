"""Step 04: detection metrics (mean +/- SD over seeds), per-attack-family table, ROC and loss plots."""
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.metrics import roc_curve

from common import Dirs, banner, load_cfg, need, save_json
from attack_detective.detection.threshold import (binary_metrics, per_family_detection,
                                                  roc_auc, thresholds_from_val)


def main():
    banner("Step 04 - evaluate detection")
    cfg = load_cfg()
    c, d = cfg["detection"], Dirs(cfg)
    need(d.art_det / f"test_scores_ae_seed{c['seeds'][0]}.npy", "step 02 (02_train_autoencoder.py)")
    labels = pd.read_csv(d.processed / "test_labels.csv")["Label"].to_numpy().astype(str)
    y = np.char.upper(labels) != "BENIGN"
    rows, fam_rows, thresholds = [], [], {}

    for model in ("ae", "if"):
        for seed in c["seeds"]:
            tf = d.art_det / f"test_scores_{model}_seed{seed}.npy"
            if not tf.exists():
                continue
            val, test = np.load(d.art_det / f"val_scores_{model}_seed{seed}.npy"), np.load(tf)
            ths = thresholds_from_val(val, c["percentiles"])
            thresholds[f"{model}_seed{seed}"] = ths
            auc = roc_auc(test, y)
            for pct, t in ths.items():
                rows.append({"model": model, "seed": seed, "percentile": pct, "threshold": t,
                             "roc_auc": auc, **binary_metrics(test, y, t)})
            for lab, v in per_family_detection(test, labels, ths[c["main_percentile"]]).items():
                fam_rows.append({"model": model, "seed": seed, "label": lab, **v})

    df = pd.DataFrame(rows)
    df.to_csv(d.res_det / "detection_metrics_all_seeds.csv", index=False)
    metrics = ["roc_auc", "precision", "recall", "f1", "fpr"]
    g = df.groupby(["model", "percentile"])[metrics]
    mean, sd = g.mean(), g.std().fillna(0.0)
    summary = pd.concat({"mean": mean, "sd": sd}, axis=1)
    summary.columns = [f"{m}_{stat}" for stat, m in summary.columns]
    summary = summary.round(4).reset_index()
    summary.to_csv(d.res_det / "detection_summary.csv", index=False)
    report = mean.round(4).astype(str) + " ± " + sd.round(4).astype(str)       # ready for the report
    report.reset_index().replace({"ae": "Autoencoder", "if": "Isolation Forest"}).to_csv(
        d.res_det / "detection_table_for_report.csv", index=False, encoding="utf-8-sig")
    print(report.to_string())

    fam = (pd.DataFrame(fam_rows).groupby(["model", "label"])
             .agg(n=("n", "first"), flagged_mean=("flagged_rate", "mean"),
                  flagged_sd=("flagged_rate", "std")).round(4).reset_index())
    fam.to_csv(d.res_det / "per_family_detection.csv", index=False)
    print("\nShare of each label flagged (BENIGN row = false positive rate):")
    print(fam.to_string(index=False))
    save_json(thresholds, d.art_det / "thresholds.json")

    plt.figure(figsize=(5, 4.5))
    for model, name in (("ae", "Autoencoder"), ("if", "Isolation Forest")):
        f = d.art_det / f"test_scores_{model}_seed{c['seeds'][0]}.npy"
        if f.exists():
            s = np.load(f)
            fpr, tpr, _ = roc_curve(y.astype(int), s)
            plt.plot(fpr, tpr, label=f"{name} (AUC {roc_auc(s, y):.3f})")
    plt.plot([0, 1], [0, 1], "k--", lw=0.8)
    plt.xlabel("False positive rate"); plt.ylabel("True positive rate")
    plt.title("ROC on CICIDS2017 test set"); plt.legend(); plt.tight_layout()
    plt.savefig(d.res_det / "roc.png", dpi=200); plt.close()

    loss = pd.read_csv(d.res_det / f"ae_loss_seed{c['seeds'][0]}.csv")
    plt.figure(figsize=(5, 3.5))
    plt.plot(loss["epoch"], loss["train_loss"], label="train"); plt.plot(loss["epoch"], loss["val_loss"], label="validation")
    plt.xlabel("epoch"); plt.ylabel("MSE"); plt.title("Autoencoder loss (seed 0)"); plt.legend(); plt.tight_layout()
    plt.savefig(d.res_det / "ae_loss.png", dpi=200); plt.close()
    print("\nTables and figures written to", d.res_det)


if __name__ == "__main__":
    main()
