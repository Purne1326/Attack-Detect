import os
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as patches

WORKSPACE = r"c:\Users\Purnendu\Downloads\attack-detective"
OUTPUT_PNG = os.path.join(WORKSPACE, "Figure_3_4_Project_Organization_Flowchart.png")

def create_simple_flowchart():
    # 1. Canvas Setup (Clean vertical / balanced aspect ratio, 300 DPI)
    fig = plt.figure(figsize=(9.0, 10.5), dpi=300, facecolor="#ffffff")
    ax = fig.add_axes([0, 0, 1, 1])
    ax.set_xlim(0, 100)
    ax.set_ylim(0, 100)
    ax.axis("off")

    # Header Title (Minimal & Clean)
    ax.text(
        50, 96.0,
        "Figure 3.4: Organization of the Project",
        fontsize=15,
        fontweight="bold",
        fontfamily="sans-serif",
        color="#0f172a",
        ha="center",
        va="center"
    )
    ax.text(
        50, 93.0,
        "Modular Architecture of Intrusion Detection & Secure Communication",
        fontsize=9.5,
        fontfamily="sans-serif",
        color="#64748b",
        ha="center",
        va="center"
    )

    # Helper function for rounded module cards
    def draw_box(x, y, w, h, bg_color, border_color):
        rect = patches.FancyBboxPatch(
            (x, y), w, h,
            boxstyle="round,pad=0.2,rounding_size=1.8",
            linewidth=1.8,
            edgecolor=border_color,
            facecolor=bg_color,
            zorder=2
        )
        ax.add_patch(rect)

    # Helper function for pill badges
    def draw_badge(x, y, text, bg_color, text_color, fontsize=8.0):
        bbox_props = dict(boxstyle="round,pad=0.3", fc=bg_color, ec="none", alpha=0.95)
        ax.text(x, y, text, fontsize=fontsize, fontweight="bold", fontfamily="sans-serif",
                color=text_color, ha="center", va="center", bbox=bbox_props, zorder=4)

    # Helper function for connecting arrows
    def draw_arrow(x, y1, y2, label=""):
        ax.annotate(
            "",
            xy=(x, y2), xycoords="data",
            xytext=(x, y1), textcoords="data",
            arrowprops=dict(
                arrowstyle="-|>",
                color="#64748b",
                lw=2.4,
                mutation_scale=18
            ),
            zorder=3
        )
        if label:
            mid_y = (y1 + y2) / 2
            ax.text(
                x + 1.5, mid_y, label,
                fontsize=8.0,
                fontweight="bold",
                fontfamily="sans-serif",
                color="#475569",
                ha="left",
                va="center",
                bbox=dict(boxstyle="round,pad=0.25", fc="#f8fafc", ec="#cbd5e1", lw=0.8),
                zorder=5
            )

    # Module specifications (Minimal, simple terms, no clutter)
    modules = [
        {
            "tag": "MODULE 1",
            "title": "Data Preprocessing & Anomaly Detection",
            "items": [
                "• Clean & split CIC-IDS2017 traffic",
                "• Bottleneck Autoencoder (Benign-trained)",
                "• Isolation Forest baseline comparison"
            ],
            "badge": "Reconstruction Loss S(x)",
            "bg": "#f8fafc",
            "border": "#3b82f6",
            "tag_bg": "#2563eb",
            "tag_fg": "#ffffff",
            "arrow_label": "Flagged Deviations"
        },
        {
            "tag": "MODULE 2",
            "title": "Anomaly Explanation & Attack Attribution",
            "items": [
                "• Feature-level residual error analysis",
                "• TF-IDF & MiniLM retrieval models",
                "• Mapping to MITRE ATT&CK techniques"
            ],
            "badge": "Identified Threat Tactic",
            "bg": "#fdf4ff",
            "border": "#a855f7",
            "tag_bg": "#9333ea",
            "tag_fg": "#ffffff",
            "arrow_label": "Attributed Threat"
        },
        {
            "tag": "MODULE 3",
            "title": "Security Policy Engine",
            "items": [
                "• Anomaly score & similarity evaluation",
                "• Multi-condition decision rules",
                "• Tri-state action: ALLOW | MONITOR | BLOCK"
            ],
            "badge": "Automated Action Decision",
            "bg": "#fffbeb",
            "border": "#f59e0b",
            "tag_bg": "#d97706",
            "tag_fg": "#ffffff",
            "arrow_label": "Policy Decision"
        },
        {
            "tag": "MODULE 4",
            "title": "Post-Quantum Cryptographic Protection",
            "items": [
                "• Hybrid Key Encapsulation (ML-KEM-768)",
                "• Digital Signatures (ML-DSA-65)",
                "• Replay prevention (Timestamps & Counters)"
            ],
            "badge": "NIST FIPS 203 / 204 Secure Alert",
            "bg": "#ecfeff",
            "border": "#06b6d4",
            "tag_bg": "#0891b2",
            "tag_fg": "#ffffff",
            "arrow_label": ""
        }
    ]

    box_w = 76.0
    box_h = 14.5
    start_y = 75.0
    spacing = 19.5
    center_x = 50.0
    left_x = center_x - (box_w / 2)

    for i, m in enumerate(modules):
        curr_y = start_y - (i * spacing)
        
        # 1. Main Box
        draw_box(left_x, curr_y, box_w, box_h, m["bg"], m["border"])

        # 2. Module Header Tag (Top Left)
        draw_badge(left_x + 9.5, curr_y + box_h - 0.2, m["tag"], m["tag_bg"], m["tag_fg"], fontsize=8.0)

        # 3. Module Title (Bold)
        ax.text(
            left_x + 20.0, curr_y + box_h - 2.8,
            m["title"],
            fontsize=11.0,
            fontweight="bold",
            fontfamily="sans-serif",
            color="#0f172a",
            ha="left",
            va="center"
        )

        # 4. Minimal Bullet Points (Simple Terms)
        bullet_y = curr_y + box_h - 6.5
        for item in m["items"]:
            ax.text(
                left_x + 5.0, bullet_y,
                item,
                fontsize=8.5,
                fontfamily="sans-serif",
                color="#334155",
                ha="left",
                va="center"
            )
            bullet_y -= 3.0

        # 5. Right Output Pill
        draw_badge(left_x + box_w - 14.0, curr_y + 4.0, m["badge"], "#ffffff", m["tag_bg"], fontsize=7.8)

        # 6. Connecting Arrow to Next Module
        if i < len(modules) - 1:
            arrow_y1 = curr_y - 0.2
            arrow_y2 = curr_y - (spacing - box_h) + 0.2
            draw_arrow(center_x, arrow_y1, arrow_y2, label=m["arrow_label"])

    # Bottom Endpoint Box (Firewall & Alert Ingress)
    end_y = start_y - (3 * spacing) - 7.5
    draw_arrow(center_x, start_y - (3 * spacing) - 0.2, end_y + 3.8, label="Quantum-Proof Wire")
    
    draw_box(30.0, end_y, 40.0, 4.2, "#ecfdf5", "#10b981")
    ax.text(
        50.0, end_y + 2.1,
        "Autonomous Firewall Enforcer & SOC SIEM Feed",
        fontsize=9.0,
        fontweight="bold",
        fontfamily="sans-serif",
        color="#065f46",
        ha="center",
        va="center"
    )

    # Save high-res PNG
    fig.savefig(OUTPUT_PNG, dpi=300, facecolor="#ffffff", edgecolor="none")
    plt.close(fig)
    print(f"Successfully generated clean flowchart: {OUTPUT_PNG}")

if __name__ == "__main__":
    create_simple_flowchart()
