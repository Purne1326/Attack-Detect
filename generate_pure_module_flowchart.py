import os
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as patches

WORKSPACE = r"c:\Users\Purnendu\Downloads\attack-detective"
OUTPUT_PNG = os.path.join(WORKSPACE, "Figure_3_4_Project_Organization_Flowchart.png")

def create_pure_module_flowchart():
    # 1. Canvas Setup (Clean, compact, publication-ready, 300 DPI)
    fig = plt.figure(figsize=(8.2, 7.6), dpi=300, facecolor="#ffffff")
    ax = fig.add_axes([0, 0, 1, 1])
    ax.set_xlim(0, 100)
    ax.set_ylim(100, 0) # 0 is top, 100 is bottom
    ax.axis("off")

    # Header Title
    ax.text(
        50, 6.0,
        "Figure 3.4: Organization of the Project",
        fontsize=15,
        fontweight="bold",
        fontfamily="sans-serif",
        color="#0f172a",
        ha="center",
        va="center"
    )
    ax.text(
        50, 9.8,
        "Modular Architecture of Intrusion Detection & Post-Quantum Secure Alerting",
        fontsize=9.2,
        fontfamily="sans-serif",
        color="#64748b",
        ha="center",
        va="center"
    )

    # Helper function for rounded module boxes
    def draw_module_box(x, y, w, h, bg_color, border_color, border_width=1.6, radius=1.2):
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

    # Helper function for downward arrows
    def draw_down_arrow(x, y1, y2, label=""):
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
                fontsize=7.8,
                fontweight="bold",
                fontfamily="sans-serif",
                color="#334155",
                ha="center",
                va="center",
                bbox=dict(boxstyle="round,pad=0.22", fc="#ffffff", ec="#cbd5e1", lw=0.8),
                zorder=5
            )

    # The 5 Modules - Pure titles only, zero inner clutter!
    modules = [
        {
            "tag": "MODULE 1",
            "name": "Data Preprocessing & Anomaly Detection",
            "bg": "#f0f7ff",
            "border": "#3b82f6",
            "tag_bg": "#2563eb",
            "tag_fg": "#ffffff",
            "text_color": "#1e3a8a",
            "arrow_label": "Flagged Deviations"
        },
        {
            "tag": "MODULE 2",
            "name": "Anomaly Explanation & Attack Attribution",
            "bg": "#faf5ff",
            "border": "#a855f7",
            "tag_bg": "#9333ea",
            "tag_fg": "#ffffff",
            "text_color": "#581c87",
            "arrow_label": "Attributed Threat"
        },
        {
            "tag": "MODULE 3",
            "name": "Security Policy Engine",
            "bg": "#fffbeb",
            "border": "#f59e0b",
            "tag_bg": "#d97706",
            "tag_fg": "#ffffff",
            "text_color": "#78350f",
            "arrow_label": "Policy Decision"
        },
        {
            "tag": "MODULE 4",
            "name": "Post-Quantum Cryptographic Protection",
            "bg": "#ecfeff",
            "border": "#06b6d4",
            "tag_bg": "#0891b2",
            "tag_fg": "#ffffff",
            "text_color": "#164e63",
            "arrow_label": "Quantum-Proof Wire"
        },
        {
            "tag": "ENFORCER",
            "name": "Autonomous Firewall Enforcer & SIEM Ingress",
            "bg": "#ecfdf5",
            "border": "#10b981",
            "tag_bg": "#059669",
            "tag_fg": "#ffffff",
            "text_color": "#064e3b",
            "arrow_label": ""
        }
    ]

    # Layout geometry
    box_w = 68.0
    box_h = 8.2
    start_y = 15.0
    spacing = 16.5
    center_x = 50.0
    left_x = center_x - (box_w / 2)

    for i, m in enumerate(modules):
        curr_y = start_y + (i * spacing)

        # Draw Clean Box
        draw_module_box(left_x, curr_y, box_w, box_h, m["bg"], m["border"], radius=1.0)

        # Left Pill Tag
        tag_w = 12.0
        tag_rect = patches.FancyBboxPatch(
            (left_x + 2.5, curr_y + 1.8), tag_w, 4.6,
            boxstyle="round,pad=0.1,rounding_size=0.6",
            linewidth=0,
            facecolor=m["tag_bg"],
            zorder=3
        )
        ax.add_patch(tag_rect)
        ax.text(
            left_x + 2.5 + (tag_w / 2), curr_y + 4.1,
            m["tag"],
            fontsize=7.8,
            fontweight="bold",
            fontfamily="sans-serif",
            color=m["tag_fg"],
            ha="center",
            va="center",
            zorder=4
        )

        # Module Name Text (Centered & Bold)
        ax.text(
            left_x + 18.0, curr_y + 4.1,
            m["name"],
            fontsize=10.5,
            fontweight="bold",
            fontfamily="sans-serif",
            color=m["text_color"],
            ha="left",
            va="center",
            zorder=4
        )

        # Draw connecting arrow to next box
        if i < len(modules) - 1:
            arrow_y1 = curr_y + box_h
            arrow_y2 = curr_y + spacing
            draw_down_arrow(center_x, arrow_y1, arrow_y2, label=m["arrow_label"])

    # Save PNG
    fig.savefig(OUTPUT_PNG, dpi=300, facecolor="#ffffff", edgecolor="none")
    plt.close(fig)
    print(f"Successfully generated pure modules flowchart: {OUTPUT_PNG}")

if __name__ == "__main__":
    create_pure_module_flowchart()
