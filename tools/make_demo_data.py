"""SYNTHETIC demo data with CICIDS2017 column names - ONLY for testing the code (python run_all.py --demo).
Never report results from this data."""
import sys
from pathlib import Path
import numpy as np
import pandas as pd

COLS = ["Destination Port", "Flow Duration", "Total Fwd Packets", "Total Backward Packets",
"Total Length of Fwd Packets", "Total Length of Bwd Packets", "Fwd Packet Length Max",
"Fwd Packet Length Min", "Fwd Packet Length Mean", "Fwd Packet Length Std",
"Bwd Packet Length Max", "Bwd Packet Length Min", "Bwd Packet Length Mean",
"Bwd Packet Length Std", "Flow Bytes/s", "Flow Packets/s", "Flow IAT Mean", "Flow IAT Std",
"Flow IAT Max", "Flow IAT Min", "Fwd IAT Total", "Fwd IAT Mean", "Fwd IAT Std", "Fwd IAT Max",
"Fwd IAT Min", "Bwd IAT Total", "Bwd IAT Mean", "Bwd IAT Std", "Bwd IAT Max", "Bwd IAT Min",
"Fwd PSH Flags", "Bwd PSH Flags", "Fwd URG Flags", "Bwd URG Flags", "Fwd Header Length",
"Bwd Header Length", "Fwd Packets/s", "Bwd Packets/s", "Min Packet Length", "Max Packet Length",
"Packet Length Mean", "Packet Length Std", "Packet Length Variance", "FIN Flag Count",
"SYN Flag Count", "RST Flag Count", "PSH Flag Count", "ACK Flag Count", "URG Flag Count",
"CWE Flag Count", "ECE Flag Count", "Down/Up Ratio", "Average Packet Size",
"Avg Fwd Segment Size", "Avg Bwd Segment Size", "Fwd Header Length.1", "Fwd Avg Bytes/Bulk",
"Fwd Avg Packets/Bulk", "Fwd Avg Bulk Rate", "Bwd Avg Bytes/Bulk", "Bwd Avg Packets/Bulk",
"Bwd Avg Bulk Rate", "Subflow Fwd Packets", "Subflow Fwd Bytes", "Subflow Bwd Packets",
"Subflow Bwd Bytes", "Init_Win_bytes_forward", "Init_Win_bytes_backward", "act_data_pkt_fwd",
"min_seg_size_forward", "Active Mean", "Active Std", "Active Max", "Active Min", "Idle Mean",
"Idle Std", "Idle Max", "Idle Min"]
CONST = {"Bwd PSH Flags", "Fwd URG Flags", "Bwd URG Flags", "CWE Flag Count", "Fwd Avg Bytes/Bulk",
         "Fwd Avg Packets/Bulk", "Fwd Avg Bulk Rate", "Bwd Avg Bytes/Bulk", "Bwd Avg Packets/Bulk",
         "Bwd Avg Bulk Rate"}

rng = np.random.default_rng(0)
out = Path(sys.argv[1]); out.mkdir(parents=True, exist_ok=True)
d = len(COLS)
W = rng.normal(size=(6, d))            # benign lives on a low-dim manifold


def benign(n):
    z = rng.normal(size=(n, 6))
    return np.exp(np.clip(z @ W * 0.4 + 3, -5, 12)) * rng.uniform(0.9, 1.1, size=(n, d))


def attack(n, shift_cols, factor):
    a = benign(n)
    idx = [COLS.index(c) for c in shift_cols]
    a[:, idx] *= factor
    return a


files = {
 "Monday-WorkingHours.pcap_ISCX.csv": [("BENIGN", benign(15000))],
 "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv":
   [("BENIGN", benign(6000)), ("PortScan", attack(1500, ["SYN Flag Count", "Flow Duration", "Total Backward Packets"], 0.01))],
 "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv":
   [("BENIGN", benign(5000)), ("Web Attack \x96 Brute Force", attack(400, ["Total Length of Fwd Packets", "Fwd Packet Length Mean"], 30)),
    ("DDoS", attack(1500, ["Flow Packets/s", "Fwd Packets/s", "Flow Bytes/s"], 200))],
}
for name, parts in files.items():
    frames = []
    for lab, arr in parts:
        df = pd.DataFrame(arr.round(2), columns=COLS)
        for c in CONST:
            df[c] = 0
        df["Destination Port"] = rng.integers(1, 65535, len(df))
        df["Fwd Header Length.1"] = df["Fwd Header Length"]
        df["Label"] = lab
        frames.append(df)
    df = pd.concat(frames, ignore_index=True)
    df.loc[rng.choice(len(df), 20), "Flow Bytes/s"] = np.inf      # CICIDS quirk
    df.loc[rng.choice(len(df), 10), "Flow Packets/s"] = np.nan
    df = pd.concat([df, df.iloc[:200]])                              # duplicates
    df.columns = [" " + c if i else c for i, c in enumerate(df.columns)]  # leading spaces
    df.to_csv(out / name, index=False, encoding="latin-1")
    print(name, len(df))
