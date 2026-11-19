import os
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as patches

WORKSPACE = r"c:\Users\Purnendu\Downloads\attack-detective"
OUTPUT_PNG = os.path.join(WORKSPACE, "Attack_Detective_Pipeline_Architecture.png")

def create_architecture_diagram():
    # 1. Canvas Setup (High resolution 300 DPI, 14.2 x 8.4 inches -> ~4260 x 2520 px)
    fig = plt.figure(figsize=(14.2, 8.4), dpi=300, facecolor="#ffffff")
    ax = fig.add_axes([0, 0, 1, 1])
    ax.set_xlim(0, 100)
    ax.set_ylim(0, 100)
    ax.axis("off")

    # Header section
    ax.text(
        50, 96.5,
        "Figure 1.2: Unified Architecture of Attack Detective with Post-Quantum Secure Alerts",
        fontsize=14.5,
        fontweight="bold",
        fontfamily="sans-serif",
        color="#0f172a",
        ha="center",
        va="center"
    )
    ax.text(
        50, 93.8,
        "End-to-End Pipeline: Unsupervised Manifold Detection → Residual Attribution → Tri-State Policy → Hybrid PQC Wiretap Immunity → Firewall Enforcement",
        fontsize=9.2,
        fontstyle="italic",
        fontfamily="sans-serif",
        color="#475569",
        ha="center",
        va="center"
    )

    # Helper function for drawing rounded card boxes
    def draw_card(x, y, w, h, bg_color, border_color, border_width=1.2, radius=1.2):
        rect = patches.FancyBboxPatch(
            (x, y), w, h,
            boxstyle=f"round,pad=0.2,rounding_size={radius}",
            linewidth=border_width,
            edgecolor=border_color,
            facecolor=bg_color,
            zorder=2
        )
        ax.add_patch(rect)
        return rect

    # Helper function for drawing pill badges
    def draw_badge(x, y, text, bg_color, text_color, fontsize=7.2):
        bbox_props = dict(boxstyle="round,pad=0.25", fc=bg_color, ec="none", alpha=0.95)
        ax.text(x, y, text, fontsize=fontsize, fontweight="bold", fontfamily="sans-serif",
                color=text_color, ha="center", va="center", bbox=bbox_props, zorder=4)

    # Helper function for drawing flow arrows
    def draw_arrow(x1, y1, x2, y2, label="", color="#64748b"):
        ax.annotate(
            "",
            xy=(x2, y2), xycoords="data",
            xytext=(x1, y1), textcoords="data",
            arrowprops=dict(
                arrowstyle="-|>",
                color=color,
                lw=1.8,
                mutation_scale=14
            ),
            zorder=3
        )
        if label:
            mid_x = (x1 + x2) / 2
            mid_y = ((y1 + y2) / 2) + 2.0
            ax.text(mid_x, mid_y, label, fontsize=7.0, fontfamily="monospace",
                    fontweight="bold", color="#1e293b", ha="center", va="center",
                    bbox=dict(boxstyle="round,pad=0.2", fc="#ffffff", ec="#cbd5e1", lw=0.6), zorder=5)

    # ==========================================
    # STAGE 1: INGESTION & UNSUPERVISED DETECTION
    # ==========================================
    draw_card(2.5, 30.5, 17.5, 59.5, "#f8fafc", "#cbd5e1")
    draw_card(3.5, 83.5, 15.5, 5.0, "#eff6ff", "#93c5fd")
    draw_badge(11.2, 86.0, "STAGE 1 • DETECTION", "#2563eb", "#ffffff", fontsize=7.5)
    
    ax.text(11.2, 79.5, "Unsupervised\nManifold Learning", fontsize=10.5, fontweight="bold",
            fontfamily="sans-serif", color="#0f172a", ha="center", va="center")
    
    # Box 1A: CICIDS2017 Telemetry
    draw_card(4.0, 64.0, 14.5, 11.5, "#ffffff", "#e2e8f0")
    ax.text(11.2, 72.2, "CIC-IDS2017 Traffic", fontsize=8.0, fontweight="bold", color="#1e3a8a", ha="center")
    ax.text(11.2, 67.5, "• 100% Benign Training [1]\n• 76 Continuous Features\n• Zero-Attack-Bias Baseline",
            fontsize=7.0, color="#475569", ha="center")

    # Box 1B: Bottleneck Autoencoder
    draw_card(4.0, 48.0, 14.5, 13.5, "#ffffff", "#93c5fd")
    ax.text(11.2, 58.2, "Bottleneck Autoencoder", fontsize=8.0, fontweight="bold", color="#2563eb", ha="center")
    ax.text(11.2, 53.5, "Architecture: 76→48→24→16\nBottleneck: d = 16 Latent Dims\nReconstruction: 16→24→48→76",
            fontsize=6.8, fontfamily="monospace", color="#334155", ha="center")
    ax.text(11.2, 49.5, "ROC-AUC: 0.9775 ± 0.0028 [2]", fontsize=7.2, fontweight="bold", color="#15803d", ha="center")

    # Box 1C: Anomaly Loss
    draw_card(4.0, 32.5, 14.5, 13.0, "#eff6ff", "#bfdbfe")
    ax.text(11.2, 42.5, "Anomaly Score Gating", fontsize=8.0, fontweight="bold", color="#1e40af", ha="center")
    ax.text(11.2, 38.0, r"$\mathcal{L}_{\mathrm{MSE}}(\mathbf{x}, \hat{\mathbf{x}}) = \frac{1}{D}\sum (x_j - \hat{x}_j)^2$",
            fontsize=7.5, color="#0f172a", ha="center")
    ax.text(11.2, 34.0, "Cutoff Threshold: τ₉₅ = 0.03443", fontsize=7.0, fontfamily="monospace", color="#64748b", ha="center")

    # Arrow 1 -> 2
    draw_arrow(20.5, 59.5, 22.8, 59.5, label="Residual r")

    # ==========================================
    # STAGE 2: ATTRIBUTION & STIX ATT&CK MAPPING
    # ==========================================
    draw_card(22.8, 30.5, 18.0, 59.5, "#fdf4ff", "#e879f9")
    draw_card(23.8, 83.5, 16.0, 5.0, "#fae8ff", "#f0abfc")
    draw_badge(31.8, 86.0, "STAGE 2 • ATTRIBUTION", "#9333ea", "#ffffff", fontsize=7.5)

    ax.text(31.8, 79.5, "Residual Explainability\n& STIX Retrieval", fontsize=10.5, fontweight="bold",
            fontfamily="sans-serif", color="#0f172a", ha="center", va="center")

    # Box 2A: Error Decomposition
    draw_card(24.3, 64.0, 15.0, 11.5, "#ffffff", "#f5d0fe")
    ax.text(31.8, 72.2, "Feature Decomposition", fontsize=8.0, fontweight="bold", color="#7e22ce", ha="center")
    ax.text(31.8, 67.5, "• Extract Top-5 Deviant z-Scores\n• Natural Language Narrative [3]\n• 'High SYN & Asymmetric IAT'",
            fontsize=7.0, color="#475569", ha="center")

    # Box 2B: NLP Dual Retrieval
    draw_card(24.3, 48.0, 15.0, 13.5, "#ffffff", "#d8b4fe")
    ax.text(31.8, 58.2, "Dual Semantic Vector Space", fontsize=8.0, fontweight="bold", color="#9333ea", ha="center")
    ax.text(31.8, 53.5, "1. Sparse: TF-IDF N-Gram Space\n2. Dense: all-MiniLM-L6-v2 [4]\nCosine Similarity Projection:",
            fontsize=6.8, color="#334155", ha="center")
    ax.text(31.8, 49.5, r"$\mathrm{Sim}(\mathbf{q}, \mathbf{d}_i) = \frac{\mathbf{q} \cdot \mathbf{d}_i}{\|\mathbf{q}\| \|\mathbf{d}_i\|}$",
            fontsize=7.5, color="#6b21a8", ha="center")

    # Box 2C: MITRE ATT&CK Matrix
    draw_card(24.3, 32.5, 15.0, 13.0, "#faf5ff", "#c084fc")
    ax.text(31.8, 42.5, "MITRE ATT&CK Mapping", fontsize=8.0, fontweight="bold", color="#581c87", ha="center")
    ax.text(31.8, 38.0, "• 706 Enterprise STIX Techniques\n• Top-1 Acc: 19.66%\n• Top-3 Acc: 61.04% (21.6× Base)",
            fontsize=7.0, color="#475569", ha="center")
    ax.text(31.8, 34.0, "Target ID: T1498 (Network DoS)", fontsize=6.8, fontfamily="monospace", color="#7e22ce", ha="center")

    # Arrow 2 -> 3
    draw_arrow(41.3, 59.5, 43.6, 59.5, label="Scores + Tactic")

    # ==========================================
    # STAGE 3: AUTONOMOUS POLICY ENGINE
    # ==========================================
    draw_card(43.6, 30.5, 17.0, 59.5, "#fffbeb", "#fcd34d")
    draw_card(44.6, 83.5, 15.0, 5.0, "#fef3c7", "#fde68a")
    draw_badge(52.1, 86.0, "STAGE 3 • POLICY", "#d97706", "#ffffff", fontsize=7.5)

    ax.text(52.1, 79.5, "Rule-Based\nDecision Engine", fontsize=10.5, fontweight="bold",
            fontfamily="sans-serif", color="#0f172a", ha="center", va="center")

    # Box 3A: Policy Logic
    draw_card(45.1, 64.0, 14.0, 11.5, "#ffffff", "#fde68a")
    ax.text(52.1, 72.2, "Dual Gating Rules", fontsize=8.0, fontweight="bold", color="#b45309", ha="center")
    ax.text(52.1, 67.5, "• Multiplier k = 1.5, s_min = 0.05\n• τ_block = μ_loss + 1.5·σ_loss\n• Zero Disruption Guarantee",
            fontsize=7.0, color="#475569", ha="center")

    # Box 3B: Tri-State Actions
    draw_card(45.1, 32.5, 14.0, 29.0, "#ffffff", "#cbd5e1")
    ax.text(52.1, 58.5, "Tri-State Firewall Actions", fontsize=8.0, fontweight="bold", color="#0f172a", ha="center")

    # ALLOW Action
    draw_card(46.0, 50.0, 12.2, 6.2, "#ecfdf5", "#a7f3d0", radius=0.6)
    draw_badge(49.0, 53.1, "ALLOW", "#059669", "#ffffff", fontsize=6.8)
    ax.text(54.2, 53.1, "99.32% Benign\nSLA Continuity", fontsize=6.5, color="#065f46")

    # MONITOR Action
    draw_card(46.0, 42.0, 12.2, 6.2, "#fffbeb", "#fde68a", radius=0.6)
    draw_badge(49.0, 45.1, "MONITOR", "#d97706", "#ffffff", fontsize=6.8)
    ax.text(54.2, 45.1, "Quarantine / Triage\nAnalyst Queue", fontsize=6.5, color="#92400e")

    # BLOCK Action
    draw_card(46.0, 34.0, 12.2, 6.2, "#fef2f2", "#fecaca", radius=0.6)
    draw_badge(49.0, 37.1, "BLOCK", "#dc2626", "#ffffff", fontsize=6.8)
    ax.text(54.2, 37.1, "18.56% Attacks\nImmediate Drop", fontsize=6.5, color="#991b1b")

    # Arrow 3 -> 4
    draw_arrow(61.1, 59.5, 63.4, 59.5, label="Action Decision")

    # ==========================================
    # STAGE 4: POST-QUANTUM CRYPTOGRAPHY (PQC)
    # ==========================================
    draw_card(63.4, 30.5, 17.5, 59.5, "#ecfeff", "#a5f3fc")
    draw_card(64.4, 83.5, 15.5, 5.0, "#cffafe", "#67e8f9")
    draw_badge(72.1, 86.0, "STAGE 4 • PQC WIRE", "#0891b2", "#ffffff", fontsize=7.5)

    ax.text(72.1, 79.5, "Hybrid Post-Quantum\nAlert Transport", fontsize=10.5, fontweight="bold",
            fontfamily="sans-serif", color="#0f172a", ha="center", va="center")

    # Box 4A: Hybrid Key Encapsulation (KEM)
    draw_card(64.9, 64.0, 14.5, 11.5, "#ffffff", "#bae6fd")
    ax.text(72.1, 72.2, "NIST FIPS 203 (ML-KEM)", fontsize=8.0, fontweight="bold", color="#0369a1", ha="center")
    ax.text(72.1, 67.5, "• ML-KEM-768 (Kyber Lattice) [5]\n• Classical: X25519 ECDH (32 B)\n• Dual HKDF Key Derivation",
            fontsize=7.0, color="#475569", ha="center")

    # Box 4B: Hybrid Signatures (DSA)
    draw_card(64.9, 48.0, 14.5, 13.5, "#ffffff", "#bae6fd")
    ax.text(72.1, 58.2, "NIST FIPS 204 (ML-DSA)", fontsize=8.0, fontweight="bold", color="#0891b2", ha="center")
    ax.text(72.1, 53.5, "• ML-DSA-65 (Dilithium Lattice) [6]\n• Classical: Ed25519 (64 B Sig)\n• 3,309 B Lattice Sig Seal",
            fontsize=6.8, color="#334155", ha="center")
    ax.text(72.1, 49.5, "Wire Overhead: +4.05 ms / alert", fontsize=7.0, fontfamily="monospace", color="#0f766e", ha="center")

    # Box 4C: Cryptographic Invariants
    draw_card(64.9, 32.5, 14.5, 13.0, "#cffafe", "#22d3ee")
    ax.text(72.1, 42.5, "Wiretap Invariants", fontsize=8.0, fontweight="bold", color="#155e75", ha="center")
    ax.text(72.1, 38.0, "• Anti-Replay: 64-bit Timestamp\n• Tamper-Proof: AES-256-GCM\n• Mode-Pinning Downgrade Shield",
            fontsize=7.0, color="#334155", ha="center")
    ax.text(72.1, 34.0, "35 / 35 Security Tests PASS", fontsize=7.2, fontweight="bold", color="#047857", ha="center")

    # Arrow 4 -> 5
    draw_arrow(81.4, 59.5, 83.7, 59.5, label="PQC Sealed Alert")

    # ==========================================
    # STAGE 5: FIREWALL ENFORCEMENT & MITIGATION
    # ==========================================
    draw_card(83.7, 30.5, 13.8, 59.5, "#ecfdf5", "#a7f3d0")
    draw_card(84.5, 83.5, 12.2, 5.0, "#d1fae5", "#6ee7b7")
    draw_badge(90.6, 86.0, "STAGE 5 • ENFORCE", "#059669", "#ffffff", fontsize=7.5)

    ax.text(90.6, 79.5, "Autonomous\nFirewall Enforcer", fontsize=10.5, fontweight="bold",
            fontfamily="sans-serif", color="#0f172a", ha="center", va="center")

    # Box 5A: Netfilter / iptables
    draw_card(84.7, 64.0, 11.8, 11.5, "#ffffff", "#6ee7b7")
    ax.text(90.6, 72.2, "Kernel Netfilter", fontsize=8.0, fontweight="bold", color="#065f46", ha="center")
    ax.text(90.6, 67.5, "• Dynamic iptables\n• eBPF / XDP Bypass\n• 0.00s Wire Latency",
            fontsize=7.0, color="#475569", ha="center")

    # Box 5B: Enforced Outcomes
    draw_card(84.7, 48.0, 11.8, 13.5, "#ffffff", "#a7f3d0")
    ax.text(90.6, 58.2, "Automated Action", fontsize=8.0, fontweight="bold", color="#059669", ha="center")
    ax.text(90.6, 53.0, "DROP: 192.168.10.142\nRate Limit SYN\nState: FAIL-CLOSED",
            fontsize=6.8, fontfamily="monospace", color="#1e293b", ha="center")
    ax.text(90.6, 49.5, "Throughput: 288.9/s", fontsize=7.0, fontfamily="monospace", color="#047857", ha="center")

    # Box 5C: Security Ops
    draw_card(84.7, 32.5, 11.8, 13.0, "#d1fae5", "#34d399")
    ax.text(90.6, 42.5, "SOC SIEM Feed", fontsize=8.0, fontweight="bold", color="#064e3b", ha="center")
    ax.text(90.6, 38.0, "• Verified Telemetry\n• Real-Time Topology\n• Live Threat Ticker",
            fontsize=7.0, color="#334155", ha="center")
    ax.text(90.6, 34.0, "Zero Human Delay", fontsize=7.2, fontweight="bold", color="#065f46", ha="center")

    # ==========================================
    # PUBLICATION CAPTION BOX AT BOTTOM
    # ==========================================
    draw_card(2.5, 3.5, 95.0, 23.5, "#f8fafc", "#cbd5e1", radius=1.0)
    
    caption_p1 = (
        r"$\bf{Figure\ 1.2:}$ The proposed Attack Detective with Post-Quantum Secure Alerts addresses these challenges "
        r"through a unified intrusion detection and secure communication pipeline. It uses an autoencoder trained "
        r"exclusively on benign CICIDS2017 network traffic to identify deviations from normal behaviour [1], [2]. "
        r"Feature-level reconstruction errors explain the detected anomalies, and TF-IDF and MiniLM-based retrieval "
        r"techniques link these explanations to relevant MITRE ATT&CK techniques [3], [4]."
    )
    caption_p2 = (
        r"From the anomaly scores and attribution results, a rule-based policy engine generates ALLOW, MONITOR, or BLOCK decisions. "
        r"These decisions are protected with hybrid post-quantum cryptography (NIST FIPS 203 ML-KEM-768 and NIST FIPS 204 ML-DSA-65 "
        r"paired with classical X25519 and Ed25519) before being sent across the wire to the autonomous firewall enforcer [5], [6]."
    )
    
    ax.text(
        4.5, 22.0,
        "Figure 1.2: End-to-End Autonomous Pipeline & Cryptographic Wire Transport Illustration",
        fontsize=9.8,
        fontweight="bold",
        fontfamily="sans-serif",
        color="#0f172a",
        va="top"
    )
    
    ax.text(
        4.5, 18.0,
        "The proposed Attack Detective with Post-Quantum Secure Alerts addresses these challenges through a unified intrusion detection\n"
        "and secure communication pipeline. It uses an autoencoder trained exclusively on benign CICIDS2017 network traffic to identify deviations\n"
        "from normal behaviour [1], [2]. Feature-level reconstruction errors explain the detected anomalies, and TF-IDF and MiniLM-based retrieval\n"
        "techniques link these explanations to relevant MITRE ATT&CK techniques [3], [4]. From the anomaly scores and attribution results,\n"
        "a rule-based policy engine generates ALLOW, MONITOR, or BLOCK decisions. These decisions are protected with hybrid post-quantum\n"
        "cryptography before being sent to the firewall enforcer [5], [6].",
        fontsize=8.2,
        fontfamily="sans-serif",
        color="#334155",
        linespacing=1.35,
        va="top"
    )

    # Inset Summary Pill Badges in caption box
    draw_badge(88.0, 19.5, "Zero Attack Bias [1]", "#eff6ff", "#1d4ed8", fontsize=7.2)
    draw_badge(88.0, 15.0, "STIX v2.1 (706 Techs) [3]", "#faf5ff", "#7e22ce", fontsize=7.2)
    draw_badge(88.0, 10.5, "99.32% Benign ALLOW", "#ecfdf5", "#047857", fontsize=7.2)
    draw_badge(88.0, 6.0, "NIST FIPS 203/204 [5],[6]", "#ecfeff", "#0e7490", fontsize=7.2)

    # Save PNG
    fig.savefig(OUTPUT_PNG, dpi=300, facecolor="#ffffff", edgecolor="none")
    plt.close(fig)
    print(f"Successfully generated pipeline architecture diagram: {OUTPUT_PNG}")

if __name__ == "__main__":
    create_architecture_diagram()
