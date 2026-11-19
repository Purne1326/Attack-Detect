import os
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as patches

WORKSPACE = r"c:\Users\Purnendu\Downloads\attack-detective"
OUTPUT_PNG = os.path.join(WORKSPACE, "Figure_3_4_Project_Organization_Flowchart.png")

def create_compact_flowchart():
    # 1. Canvas Setup - Compact & well-proportioned (8.6 x 8.6 inches, 300 DPI)
    fig = plt.figure(figsize=(8.6, 8.8), dpi=300, facecolor="#ffffff")
    ax = fig.add_axes([0, 0, 1, 1])
    ax.set_xlim(0, 100)
    ax.set_ylim(100, 0) # Invert Y so 0 is top, 100 is bottom (more natural coordinate system!)
    ax.axis("off")

    # Header Title Block
    ax.text(
        50, 4.5,
        "Figure 3.4: Organization of the Project",
        fontsize=14.5,
        fontweight="bold",
        fontfamily="sans-serif",
        color="#0f172a",
        ha="center",
        va="center"
    )
    ax.text(
        50, 7.8,
        "Modular Architecture of Intrusion Detection & Post-Quantum Secure Alerting",
        fontsize=9.0,
        fontfamily="sans-serif",
        color="#64748b",
        ha="center",
        va="center"
    )

    # Helper function for rounded cards
    def draw_rounded_rect(x, y, w, h, bg_color, border_color, border_width=1.4, radius=1.2):
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

    # Helper function for badges
    def draw_badge(x, y, text, bg_color, text_color, fontsize=7.5, pad=0.3):
        bbox_props = dict(boxstyle=f"round,pad={pad}", fc=bg_color, ec="none", alpha=0.95)
        ax.text(x, y, text, fontsize=fontsize, fontweight="bold", fontfamily="sans-serif",
                color=text_color, ha="center", va="center", bbox=bbox_props, zorder=4)

    # Helper function for downward flow arrows
    def draw_down_arrow(x, y1, y2, label=""):
        ax.annotate(
            "",
            xy=(x, y2), xycoords="data",
            xytext=(x, y1), textcoords="data",
            arrowprops=dict(
                arrowstyle="-|>",
                color="#64748b",
                lw=2.0,
                mutation_scale=15
            ),
            zorder=3
        )
        if label:
            mid_y = (y1 + y2) / 2
            ax.text(
                x, mid_y, label,
                fontsize=7.5,
                fontweight="bold",
                fontfamily="sans-serif",
                color="#334155",
                ha="center",
                va="center",
                bbox=dict(boxstyle="round,pad=0.2", fc="#ffffff", ec="#cbd5e1", lw=0.8),
                zorder=5
            )

    # Modules Data (Compact & Balanced 2-Column Inside Layout)
    modules = [
        {
            "tag": "MODULE 1",
            "title": "Data Preprocessing & Anomaly Detection",
            "bullets": [
                "Cleans & transforms CIC-IDS2017 traffic (76 features)",
                "Bottleneck Autoencoder trained on 100% benign flows",
                "Evaluates deviations against Isolation Forest baseline"
            ],
            "out_label": "MODULE OUTPUT",
            "out_val": "Reconstruction Loss S(x)\n& Threshold τ₉₅ Gating",
            "bg": "#f8fafc",
            "border": "#60a5fa",
            "tag_bg": "#2563eb",
            "tag_fg": "#ffffff",
            "out_bg": "#eff6ff",
            "out_border": "#bfdbfe",
            "out_color": "#1d4ed8",
            "arrow_label": "Flagged Deviations"
        },
        {
            "tag": "MODULE 2",
            "title": "Anomaly Explanation & Attack Attribution",
            "bullets": [
                "Decomposes reconstruction error into top-5 residuals",
                "Synthesizes explainable natural language descriptions",
                "TF-IDF & MiniLM retrieval maps to MITRE ATT&CK"
            ],
            "out_label": "MODULE OUTPUT",
            "out_val": "ATT&CK Technique Match\n(61.04% Top-3 Accuracy)",
            "bg": "#fdf4ff",
            "border": "#c084fc",
            "tag_bg": "#9333ea",
            "tag_fg": "#ffffff",
            "out_bg": "#faf5ff",
            "out_border": "#e9d5ff",
            "out_color": "#7e22ce",
            "arrow_label": "Attributed Threat"
        },
        {
            "tag": "MODULE 3",
            "title": "Security Policy Engine",
            "bullets": [
                "Evaluates anomaly score, threshold & tactic confidence",
                "Multi-condition rules prevent false positive disruptions",
                "Tri-state enforcement: ALLOW  |  MONITOR  |  BLOCK"
            ],
            "out_label": "MODULE OUTPUT",
            "out_val": "Action Policy Decision\n(99.32% Benign ALLOW)",
            "bg": "#fffbeb",
            "border": "#fbbf24",
            "tag_bg": "#d97706",
            "tag_fg": "#ffffff",
            "out_bg": "#fef3c7",
            "out_border": "#fde68a",
            "out_color": "#b45309",
            "arrow_label": "Policy Decision"
        },
        {
            "tag": "MODULE 4",
            "title": "Post-Quantum Cryptographic Protection",
            "bullets": [
                "NIST FIPS 203 ML-KEM-768 hybrid key encapsulation",
                "NIST FIPS 204 ML-DSA-65 lattice digital signatures",
                "Monotonic counter & timestamp anti-replay validation"
            ],
            "out_label": "MODULE OUTPUT",
            "out_val": "Quantum-Proof Sealed Alert\n(35/35 Security Tests PASS)",
            "bg": "#ecfeff",
            "border": "#22d3ee",
            "tag_bg": "#0891b2",
            "tag_fg": "#ffffff",
            "out_bg": "#cffafe",
            "out_border": "#a5f3fc",
            "out_color": "#0e7490",
            "arrow_label": "Encrypted & Signed Wire"
        }
    ]

    # Layout geometry (Compact, no dead space)
    box_w = 78.0
    box_h = 13.5
    start_y = 11.5
    spacing = 17.5
    center_x = 50.0
    left_x = center_x - (box_w / 2)

    for i, m in enumerate(modules):
        curr_y = start_y + (i * spacing)

        # 1. Outer Card
        draw_rounded_rect(left_x, curr_y, box_w, box_h, m["bg"], m["border"], radius=1.2)

        # 2. Left Accent Strip
        accent_strip = patches.FancyBboxPatch(
            (left_x, curr_y), 1.2, box_h,
            boxstyle="round,pad=0.1,rounding_size=0.6",
            linewidth=0,
            facecolor=m["tag_bg"],
            zorder=3
        )
        ax.add_patch(accent_strip)

        # 3. Module Header: Tag + Title
        draw_badge(left_x + 6.8, curr_y + 2.4, m["tag"], m["tag_bg"], m["tag_fg"], fontsize=7.2, pad=0.25)
        ax.text(
            left_x + 14.0, curr_y + 2.5,
            m["title"],
            fontsize=10.2,
            fontweight="bold",
            fontfamily="sans-serif",
            color="#0f172a",
            ha="left",
            va="center",
            zorder=4
        )

        # Header horizontal divider
        ax.plot(
            [left_x + 2.5, left_x + box_w - 2.5],
            [curr_y + 4.3, curr_y + 4.3],
            color=m["border"],
            linewidth=0.8,
            alpha=0.6,
            zorder=3
        )

        # 4. Left Column: Bullets (Compact, nicely aligned)
        bullet_start_y = curr_y + 6.4
        for b_idx, bullet in enumerate(m["bullets"]):
            by = bullet_start_y + (b_idx * 2.5)
            # Dot
            ax.plot(left_x + 4.0, by, marker="o", markersize=3.2, color=m["tag_bg"], zorder=4)
            # Text
            ax.text(
                left_x + 5.8, by,
                bullet,
                fontsize=7.8,
                fontfamily="sans-serif",
                color="#334155",
                ha="left",
                va="center",
                zorder=4
            )

        # 5. Right Column: Dedicated "Module Output" Card (Fills horizontal space cleanly!)
        out_w = 23.5
        out_h = 7.6
        out_x = left_x + box_w - out_w - 2.5
        out_y = curr_y + 4.9
        
        draw_rounded_rect(out_x, out_y, out_w, out_h, m["out_bg"], m["out_border"], border_width=1.0, radius=0.8)
        
        ax.text(
            out_x + (out_w / 2), out_y + 2.0,
            m["out_label"],
            fontsize=6.5,
            fontweight="bold",
            fontfamily="sans-serif",
            color="#64748b",
            ha="center",
            va="center",
            zorder=4
        )
        ax.text(
            out_x + (out_w / 2), out_y + 4.7,
            m["out_val"],
            fontsize=7.4,
            fontweight="bold",
            fontfamily="sans-serif",
            color=m["out_color"],
            ha="center",
            va="center",
            linespacing=1.2,
            zorder=4
        )

        # 6. Downward arrow to next box
        if i < len(modules) - 1:
            arrow_y1 = curr_y + box_h
            arrow_y2 = curr_y + spacing
            draw_down_arrow(center_x, arrow_y1, arrow_y2, label=m["arrow_label"])

    # 7. Final Enforcer Endpoint Box
    end_y = start_y + (3 * spacing) + box_h + 3.8
    draw_down_arrow(center_x, start_y + (3 * spacing) + box_h, end_y, label="Quantum-Proof Wire")

    end_w = 58.0
    end_h = 4.8
    end_x = center_x - (end_w / 2)
    draw_rounded_rect(end_x, end_y, end_w, end_h, "#ecfdf5", "#10b981", border_width=1.4, radius=1.0)
    
    # Left green dot
    ax.plot(end_x + 3.5, end_y + (end_h / 2), marker="s", markersize=5.0, color="#059669", zorder=4)
    ax.text(
        center_x + 1.0, end_y + (end_h / 2),
        "Autonomous Firewall Enforcer (iptables / eBPF) & SIEM Ingress",
        fontsize=8.8,
        fontweight="bold",
        fontfamily="sans-serif",
        color="#065f46",
        ha="center",
        va="center",
        zorder=4
    )

    # Save compact PNG
    fig.savefig(OUTPUT_PNG, dpi=300, facecolor="#ffffff", edgecolor="none")
    plt.close(fig)
    print(f"Successfully generated compact beautiful flowchart: {OUTPUT_PNG}")

if __name__ == "__main__":
    create_compact_flowchart()
