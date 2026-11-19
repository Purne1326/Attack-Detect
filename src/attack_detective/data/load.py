"""Load the CICIDS2017 CSV files into one DataFrame."""
from pathlib import Path

import pandas as pd


def normalise_label(s: pd.Series) -> pd.Series:
    """Fix the broken dash in 'Web Attack \x96 Brute Force' and strip spaces."""
    s = s.astype(str).str.strip()
    return s.str.replace(r"\s*[^\x20-\x7E]+\s*", " - ", regex=True)


def find_label_column(df: pd.DataFrame) -> str:
    for c in df.columns:
        if c.strip().lower() == "label":
            return c
    raise KeyError("No 'Label' column found")


def load_raw(raw_dir) -> pd.DataFrame:
    files = sorted(Path(raw_dir).glob("*.csv"))
    if not files:
        raise FileNotFoundError(f"No CSV files in {raw_dir}")
    parts = []
    for f in files:
        # latin-1 avoids UnicodeDecodeError on the Web Attack labels
        df = pd.read_csv(f, encoding="latin-1", low_memory=False)
        df.columns = [c.strip() for c in df.columns]
        print(f"  {f.name:<70} {len(df):>10,} rows")
        parts.append(df)
    df = pd.concat(parts, ignore_index=True)
    label_col = find_label_column(df)
    df[label_col] = normalise_label(df[label_col])
    if label_col != "Label":
        df = df.rename(columns={label_col: "Label"})
    return df
