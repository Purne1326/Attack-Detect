"""Clean the raw flows: numeric features only, no inf/NaN, no duplicates, float32."""
import numpy as np
import pandas as pd


def clean(df: pd.DataFrame, drop_columns=()):
    """Return (X: float32 DataFrame, labels: Series, log: dict of row counts)."""
    log = {"raw_rows": int(len(df))}
    labels = df["Label"]
    X = df.drop(columns=["Label"])
    X = X.drop(columns=[c for c in drop_columns if c in X.columns])

    # Keep numeric columns; convert text columns that are really numbers; drop identifiers
    dropped_non_numeric = []
    for c in X.columns:
        if not pd.api.types.is_numeric_dtype(X[c]):     # works for pandas 2 and 3
            conv = pd.to_numeric(X[c], errors="coerce")
            if conv.notna().mean() > 0.99:
                X[c] = conv
            else:
                dropped_non_numeric.append(c)
    X = X.drop(columns=dropped_non_numeric)
    log["dropped_non_numeric_columns"] = dropped_non_numeric

    X = X.replace([np.inf, -np.inf], np.nan)
    bad = X.isna().any(axis=1).to_numpy()
    X, labels = X.loc[~bad], labels.loc[~bad]
    log["after_inf_nan"] = int(len(X))

    X = X.astype(np.float32)
    dup = pd.concat([X, labels], axis=1).duplicated().to_numpy()
    X, labels = X.loc[~dup].reset_index(drop=True), labels.loc[~dup].reset_index(drop=True)
    log["after_duplicates"] = int(len(X))
    log["n_features"] = int(X.shape[1])
    log["label_counts"] = {k: int(v) for k, v in labels.value_counts().items()}
    return X, labels, log
