# 🛡️ Attack Detective: Post-Quantum Secure Intrusion Detection

**Attack Detective** is an end-to-end autonomous cyber defense and secure alerting framework. It unifies unsupervised manifold anomaly detection, explainable MITRE ATT&CK attribution, tri-state policy decisions, and post-quantum cryptographic wire protection (NIST FIPS 203 ML-KEM & FIPS 204 ML-DSA) with automated netfilter firewall enforcement.

---

## 🌟 Key Features

1. **Unsupervised Anomaly Detection:**
   - 76-feature bottleneck Autoencoder trained strictly on benign baseline network traffic (zero-attack bias).
   - Dynamic thresholding ($\tau_{95} = 0.03443$) with an ROC-AUC of **0.9775 ± 0.0028** (benchmarked against Isolation Forest at 0.9085).

2. **Explainable Threat Attribution:**
   - Decomposes reconstruction errors into top feature residuals.
   - Dual-semantic retrieval (TF-IDF + dense MiniLM-L6-v2) maps suspicious behaviors to 706 Enterprise MITRE ATT&CK techniques (61.04% Top-3 accuracy).

3. **Tri-State Policy Engine:**
   - Dual-gating rules (`ALLOW`, `MONITOR`, `BLOCK`) guarantee **99.32% benign SLA continuity** while instantly isolating malicious flows.

4. **Post-Quantum Wiretap Immunity:**
   - Hybrid NIST FIPS 203 (ML-KEM-768) key exchange and FIPS 204 (ML-DSA-65) lattice digital signatures protect alerts sent to the firewall.
   - Tamper-proof, anti-replay validated with nanosecond timestamps and monotonic counters.

5. **Live Interactive SOC Dashboard:**
   - FastAPI + HTML5 glassmorphic dashboard featuring real-time telemetry, live packet journey animations, neural latent space projection, CSV file flow analysis, and an interactive MITM Quantum Wiretap simulation lab.

---

## 🚀 Quick Start

### 1. Prerequisites
- Python 3.10+ (recommended 3.11 or 3.12)
- Git

### 2. Installation
Clone the repository and set up a virtual environment:
```bash
git clone https://github.com/Purne1326/Attack-Detectv.git
cd Attack-Detectv

python -m venv .venv
# On Windows:
.\.venv\Scripts\activate
# On Linux/macOS:
source .venv/bin/activate

pip install -r requirements.txt
```

---

## 🖥️ Launching the Web Dashboard

To start the modern, interactive SOAR Web Dashboard:
```bash
python -m uvicorn web_dashboard.app:app --host 127.0.0.1 --port 8000
```
Open your browser and navigate to:
👉 **`http://127.0.0.1:8000`**

### Active Dashboard Capabilities:
- **Telemetry & Enforced Flows:** Real-time SOC event stream and firewall action monitor.
- **Flow File Analyzer:** Upload capture CSVs (or pick from sample captures in `demo_csv_samples/`) to parse anomalies and attribute MITRE tactics.
- **Neural Latent Space:** 2D/3D projection of benign manifolds and attack anomalies.
- **MITM Quantum Wiretap:** Simulate active wiretaps and tamper attacks to verify PQC cryptographic rejection.
- **🎬 Packet Journey:** Slow-motion pipeline visualization tracing packets from raw ingress to firewall drop.

---

## 🔬 Running the Pipeline & Benchmarks

To execute the entire end-to-end pipeline on synthetic or demonstration data:
```bash
python run_all.py --demo
```

To run individual steps:
```bash
# Step 00: Environment & PQC Backend Verification
python scripts/00_check_env.py

# Step 05: Benchmark Autoencoder vs Isolation Forest
python scripts/05_evaluate_detection.py

# Step 08: Test Post-Quantum Alert Wiretap Immunity
python scripts/08_evaluate_pqc.py
```

### Running Test Suite
Verify all modules and invariants:
```bash
pytest tests/ -v
```

---

## 📁 Repository Structure

```
├── artifacts/              # Pretrained model weights, thresholds, indices & decisions
├── demo_csv_samples/       # Pre-packaged network captures for dashboard testing
├── results/                # Evaluation benchmark tables and metrics
├── scripts/                # Modular pipeline execution scripts (00 to 10)
├── src/                    # Core framework modules
│   ├── attribution/        # Residual decomposition & STIX MITRE ATT&CK retrieval
│   ├── data/               # CIC-IDS2017 preprocessing & scaling
│   ├── detection/          # Autoencoder architecture & Isolation Forest baseline
│   ├── policy/             # Tri-state decision rules & gating
│   └── pqc/                # ML-KEM-768, ML-DSA-65 & authenticated channel
├── tests/                  # Unit and integration test suites
├── web_dashboard/          # FastAPI server and glassmorphic UI
├── config.yaml             # Hyperparameters & framework configuration
├── requirements.txt        # Python dependencies
└── run_all.py              # Unified pipeline runner
```

---

## 📜 Standards & References
- **NIST FIPS 203:** Module-Lattice-Based Key-Encapsulation Mechanism (ML-KEM / Kyber)
- **NIST FIPS 204:** Module-Lattice-Based Digital Signature Algorithm (ML-DSA / Dilithium)
- **MITRE ATT&CK:** Enterprise Matrix STIX 2.1 taxonomy
- **Dataset:** CIC-IDS2017 Intrusion Detection Evaluation Dataset
