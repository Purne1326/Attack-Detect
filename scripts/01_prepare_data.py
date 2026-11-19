"""Step 01: load the CICIDS2017 CSVs -> clean -> split -> scale -> save to data/processed/."""
import time

import numpy as np

from common import Dirs, banner, load_cfg, save_json
from attack_detective.data.clean import clean
from attack_detective.data.load import load_raw
from attack_detective.data.scale import FeatureScaler
from attack_detective.data.split import make_splits


def main():
    banner("Step 01 - prepare data")
    cfg = load_cfg()
    c, d = cfg["detection"], Dirs(cfg)
    t0 = time.time()
    print("1) Loading CSV files from", d.raw)
    df = load_raw(d.raw)

    print("2) Cleaning ...")
    X, labels, log = clean(df, c["drop_columns"])
    del df
    for k in ("raw_rows", "after_inf_nan", "after_duplicates", "n_features"):
        print(f"   {k:<18} {log[k]:>10,}")

    print("3) Splitting (benign-only train/val, mixed test) ...")
    tr, va, te = make_splits(labels, c["split"], c["split_seed"], c["benign_train_cap"])
    log.update(train_rows=len(tr), val_rows=len(va), test_rows=len(te))
    print(f"   train {len(tr):,}  val {len(va):,}  test {len(te):,}")

    print("4) Fitting the scaler on benign TRAIN only ...")
    scaler = FeatureScaler(c["scaler_clip"]).fit(X.iloc[tr])
    log["features_used"] = len(scaler.columns)
    log["dropped_constant_columns"] = scaler.dropped_constant
    print(f"   {len(scaler.columns)} features kept; constant and dropped: {scaler.dropped_constant}")

    print("5) Saving ...")
    np.save(d.processed / "X_train.npy", scaler.transform(X.iloc[tr]))
    np.save(d.processed / "X_val.npy", scaler.transform(X.iloc[va]))
    np.save(d.processed / "X_test.npy", scaler.transform(X.iloc[te]))
    labels.iloc[te].reset_index(drop=True).to_csv(d.processed / "test_labels.csv", index=False)
    scaler.save(d.processed / "scaler.pkl")
    save_json(scaler.columns, d.processed / "feature_names.json")
    save_json(log, d.processed / "clean_log.json")
    save_json(log, d.res_det / "dataset_summary.json")
    print(f"Done in {time.time() - t0:.0f}s -> {d.processed}")


if __name__ == "__main__":
    main()
