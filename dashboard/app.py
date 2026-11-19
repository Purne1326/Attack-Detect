"""Attack Detective dashboard.  Run:  streamlit run dashboard\\app.py
Reads saved files only (never retrains). Demo results:  $env:AD_DEMO=1; streamlit run dashboard\\app.py
"""
import json
import os
from pathlib import Path

import pandas as pd
import streamlit as st

ROOT = Path(__file__).resolve().parents[1]
DEMO = os.environ.get("AD_DEMO") == "1"          # PowerShell:  $env:AD_DEMO=1   (demo results)
ART = ROOT / ("artifacts_demo" if DEMO else "artifacts")
RES = ROOT / ("results_demo" if DEMO else "results")
F = {
    "expl": ART / "detection/explanations.jsonl",
    "dec": ART / "attribution/decisions.jsonl",
    "log": ART / "pqc/enforcer_log.jsonl",
    "det": RES / "detection/detection_summary.csv",
    "fam": RES / "detection/per_family_detection.csv",
    "att": RES / "attribution/attribution_topk.csv",
    "pol": RES / "attribution/policy_metrics_test_half.csv",
    "bench": RES / "pqc/pqc_benchmark.csv",
    "sec": RES / "pqc/security_tests.csv",
}


@st.cache_data
def jsonl(path: str) -> pd.DataFrame:
    with open(path, encoding="utf-8") as f:
        return pd.DataFrame([json.loads(line) for line in f if line.strip()])


def load(key):
    return jsonl(str(F[key])) if F[key].exists() else None


st.set_page_config(page_title="Attack Detective", layout="wide")
st.title("Attack Detective" + ("  (DEMO - synthetic data)" if DEMO else ""))
st.caption("Anomaly detection → explanation → MITRE ATT&CK → Allow/Monitor/Block → post-quantum signed alert")

expl, dec, log = load("expl"), load("dec"), load("log")
if expl is None or dec is None:
    st.error("No results yet. Run:  python run_all.py   (or  python run_all.py --demo  then set $env:AD_DEMO=1)")
    st.stop()

df = expl.merge(dec[["flow_id", "techniques", "action", "reason"]], on="flow_id", how="inner")
if log is not None and "flow_id" in log:
    alerts = log[log["event"] == "alert"].dropna(subset=["flow_id"])
    alerts = alerts.assign(flow_id=alerts["flow_id"].astype(int))
    df = df.merge(alerts[["flow_id", "accepted", "reason", "bytes", "counter"]]
                  .rename(columns={"reason": "verify_reason"}), on="flow_id", how="left")
else:
    df["accepted"], df["verify_reason"], df["bytes"] = None, "not sent yet", None

c1, c2, c3, c4, c5 = st.columns(5)
c1.metric("Flows", f"{len(df):,}")
c2.metric("Flagged anomalous", f"{int(df['is_anomaly'].sum()):,}")
c3.metric("BLOCK", f"{int((df['action'] == 'BLOCK').sum()):,}")
c4.metric("MONITOR", f"{int((df['action'] == 'MONITOR').sum()):,}")
verified = "-" if df["accepted"].isna().all() else f"{int(df['accepted'].fillna(False).sum()):,}"
c5.metric("Alerts verified", verified)

tab1, tab2, tab3 = st.tabs(["Alerts", "Flow detail", "Evaluation & PQC cost"])

with tab1:
    actions = st.multiselect("Action", ["BLOCK", "MONITOR", "ALLOW"], default=["BLOCK", "MONITOR"])
    view = df[df["action"].isin(actions)].copy()
    view["top_technique"] = view["techniques"].map(
        lambda t: f"{t[0]['technique_id']} {t[0]['name']}" if t else "")
    view["verified"] = view["accepted"].map({True: "signature OK", False: "REJECTED"}).fillna("–")
    st.dataframe(view[["flow_id", "score", "action", "top_technique", "verified", "true_label"]]
                 .sort_values("score", ascending=False), width="stretch", height=420)
    st.caption("true_label is shown for evaluation only; the pipeline never uses it.")

with tab2:
    fid = st.selectbox("Flow", df.sort_values("score", ascending=False)["flow_id"].head(500))
    r = df[df["flow_id"] == fid].iloc[0]
    a, b = st.columns(2)
    with a:
        st.subheader(f"Action: {r['action']}")
        st.write(f"**Anomaly score** {r['score']:.4f} (threshold {r['threshold']:.4f})")
        st.write(f"**Why:** {r['reason']}")
        st.write("**Explanation:**", r["text"])
        st.dataframe(pd.DataFrame(r["top_features"], columns=["feature", "z-score"]), hide_index=True)
    with b:
        st.subheader("Likely ATT&CK techniques")
        st.dataframe(pd.DataFrame(r["techniques"]), hide_index=True)
        st.subheader("Secure delivery")
        size = "-" if pd.isna(r["bytes"]) else f"{int(r['bytes']):,}"
        st.write(f"Verification: **{r['verify_reason']}**, message size {size} bytes")

with tab3:
    for key, title in (("det", "Detection: autoencoder vs Isolation Forest"),
                       ("fam", "Detection per attack family"),
                       ("att", "ATT&CK attribution accuracy"), ("pol", "Policy on the test half"),
                       ("bench", "Post-quantum cost per mode"), ("sec", "Security tests")):
        if F[key].exists():
            st.subheader(title)
            st.dataframe(pd.read_csv(F[key]), width="stretch")
    if F["bench"].exists():
        b = pd.read_csv(F["bench"]).set_index("mode")
        st.bar_chart(b[["added_latency_ms"]])
        st.bar_chart(b[["alert_bytes"]])
