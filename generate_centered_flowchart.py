import os
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as patches

WORKSPACE = r"c:\Users\Purnendu\Downloads\attack-detective"
OUTPUT_PNG = os.path.join(WORKSPACE, "Figure_3_4_Project_Organization_Flowchart.png")

def create_centered_modern_flowchart():
    # Canvas Setup: 8.2 x 9.6 inches @ 300 DPI
    fig = plt.figure(figsize=(8.2, 9.6), dpi=300, facecolor="#ffffff")
    ax = fig.add_axes([0, 0, 1, 1])
    ax.set_xlim(0, 100)
    ax.set_ylim(100, 0)  # 0 top, 100 bottom
    ax.axis("off")

    # Header Title & Subtitle
    ax.text(
        50, 4.6,
        "Figure 3.4: Organization of the Project",
        fontsize=17,
        fontweight="bold",
        fontfamily="sans-serif",
        color="#0f172a",
        ha="center",
        va="center"
    )
    ax.text(
        50, 8.2,
        "Modular Architecture of Intrusion Detection & Post-Quantum Secure Alerting",
        fontsize=10.2,
        fontfamily="sans-serif",
        color="#64748b",
        ha="center",
        va="center"
    )

    # Helper function for drawing modern cards with soft drop-shadow
    def draw_card_with_shadow(x, y, w, h, bg_color, border_color):
        # 1. Soft ambient shadow
        shadow = patches.FancyBboxPatch(
            (x + 0.4, y + 0.5), w, h,
            boxstyle="round,pad=0.2,rounding_size=1.3",
            linewidth=0,
            facecolor="#94a3b8",
            alpha=0.18,
            zorder=1
        )
        ax.add_patch(shadow)

        # 2. Main card body
        card = patches.FancyBboxPatch(
            (x, y), w, h,
            boxstyle="round,pad=0.2,rounding_size=1.3",
            linewidth=2.0,
            edgecolor=border_color,
            facecolor=bg_color,
            zorder=2
        )
        ax.add_patch(card)
        return card

    # Helper function for downward flow arrows with transition badges
    def draw_flow_arrow(x, y1, y2, label=""):
        ax.annotate(
            "",
            xy=(x, y2), xycoords="data",
            xytext=(x, y1), textcoords="data",
            arrowprops=dict(
                arrowstyle="-|>",
                color="#64748b",
                lw=2.2,
                mutation_scale=16
            ),
            zorder=3
        )
        if label:
            mid_y = (y1 + y2) / 2
            ax.text(
                x, mid_y, label,
                fontsize=8.5,
                fontweight="bold",
                fontfamily="sans-serif",
                color="#334155",
                ha="center",
                va="center",
                bbox=dict(
                    boxstyle="round,pad=0.35,rounding_size=0.5",
                    fc="#ffffff",
                    ec="#cbd5e1",
                    lw=1.1
                ),
                zorder=5
            )

    # 5 Flowchart Stages
    modules = [
        {
            "tag": "MODULE 1",
            "name": "Data Preprocessing & Anomaly Detection",
            "bg": "#f8faff",
            "border": "#3b82f6",
            "pill_bg": "#2563eb",
            "pill_fg": "#ffffff",
            "text_color": "#1e3a8a",
            "arrow_label": "Flagged Deviations"
        },
        {
            "tag": "MODULE 2",
            "name": "Anomaly Explanation & Attack Attribution",
            "bg": "#faf5ff",
            "border": "#a855f7",
            "pill_bg": "#9333ea",
            "pill_fg": "#ffffff",
            "text_color": "#581c87",
            "arrow_label": "Attributed Threat"
        },
        {
            "tag": "MODULE 3",
            "name": "Security Policy Engine",
            "bg": "#fffdf5",
            "border": "#f59e0b",
            "pill_bg": "#d97706",
            "pill_fg": "#ffffff",
            "text_color": "#78350f",
            "arrow_label": "Policy Decision"
        },
        {
            "tag": "MODULE 4",
            "name": "Post-Quantum Cryptographic Protection",
            "bg": "#f0fdfa",
            "border": "#06b6d4",
            "pill_bg": "#0891b2",
            "pill_fg": "#ffffff",
            "text_color": "#164e63",
            "arrow_label": "Quantum-Proof Wire"
        },
        {
            "tag": "FINAL ENFORCEMENT",
            "name": "Autonomous Firewall Enforcer & SOC SIEM Feed",
            "bg": "#f0fdf4",
            "border": "#10b981",
            "pill_bg": "#059669",
            "pill_fg": "#ffffff",
            "text_color": "#064e3b",
            "arrow_label": ""
        }
    ]

    # Perfectly balanced geometry layout
    box_w = 72.0
    box_h = 9.4
    start_y = 12.8
    spacing = 16.6
    center_x = 50.0
    left_x = center_x - (box_w / 2)

    for i, m in enumerate(modules):
        curr_y = start_y + (i * spacing)

        # 1. Outer Card with Soft Drop-Shadow
        draw_card_with_shadow(left_x, curr_y, box_w, box_h, m["bg"], m["border"])

        # 2. Centered Pill / Module Tag (Line 1 - Center)
        pill_text = m["tag"]
        pill_w = max(14.0, len(pill_text) * 0.95 + 2.8)
        pill_h = 3.0
        pill_x = center_x - (pill_w / 2)
        pill_y = curr_y + 1.5

        pill = patches.FancyBboxPatch(
            (pill_x, pill_y), pill_w, pill_h,
            boxstyle="round,pad=0.12,rounding_size=0.6",
            linewidth=0,
            facecolor=m["pill_bg"],
            zorder=3
        )
        ax.add_patch(pill)

        ax.text(
            center_x, pill_y + (pill_h / 2),
            pill_text,
            fontsize=8.5,
            fontweight="bold",
            fontfamily="sans-serif",
            color=m["pill_fg"],
            ha="center",
            va="center",
            zorder=4
        )

        # 3. Centered Module Name (Line 2 - Directly below module tag)
        ax.text(
            center_x, curr_y + 6.3,
            m["name"],
            fontsize=12.5,
            fontweight="bold",
            fontfamily="sans-serif",
            color=m["text_color"],
            ha="center",
            va="center",
            zorder=4
        )

        # 4. Connecting Arrow with label badge
        if i < len(modules) - 1:
            arrow_y1 = curr_y + box_h
            arrow_y2 = curr_y + spacing
            draw_flow_arrow(center_x, arrow_y1, arrow_y2, label=m["arrow_label"])

    # Save 300 DPI high-resolution PNG
    fig.savefig(OUTPUT_PNG, dpi=300, facecolor="#ffffff", edgecolor="none")
    plt.close(fig)
    print(f"Successfully generated updated flowchart: {OUTPUT_PNG}")

if __name__ == "__main__":
    create_centered_modern_flowchart()
