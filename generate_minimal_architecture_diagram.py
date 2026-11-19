import os
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as patches

WORKSPACE = r"c:\Users\Purnendu\Downloads\attack-detective"
OUTPUT_PNG = os.path.join(WORKSPACE, "Attack_Detective_Pipeline_Architecture.png")

def create_minimal_diagram():
    # 1. Canvas Setup (Wide format, generous spacing, 300 DPI)
    fig = plt.figure(figsize=(14.0, 7.2), dpi=300, facecolor="#ffffff")
    ax = fig.add_axes([0, 0, 1, 1])
    ax.set_xlim(0, 100)
    ax.set_ylim(0, 100)
    ax.axis("off")

    # Header Title
    ax.text(
        50, 94.0,
        "Attack Detective: End-to-End Pipeline Architecture",
        fontsize=16,
        fontweight="bold",
        fontfamily="sans-serif",
        color="#0f172a",
        ha="center",
        va="center"
    )
    ax.text(
        50, 89.5,
        "A unified system for zero-day anomaly detection, MITRE ATT&CK attribution, and post-quantum secure defense",
        fontsize=10.5,
        fontfamily="sans-serif",
        color="#64748b",
        ha="center",
        va="center"
    )

    # Helper function for drawing elegant rounded cards
    def draw_card(x, y, w, h, bg_color, border_color, border_width=1.5, radius=2.0):
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

    # Helper function for pill badges
    def draw_badge(x, y, text, bg_color, text_color, fontsize=8.0, pad=0.35):
        bbox_props = dict(boxstyle=f"round,pad={pad}", fc=bg_color, ec="none", alpha=0.95)
        ax.text(x, y, text, fontsize=fontsize, fontweight="bold", fontfamily="sans-serif",
                color=text_color, ha="center", va="center", bbox=bbox_props, zorder=4)

    # Helper function for flow arrows
    def draw_arrow(x1, y1, x2, y2, label=""):
        ax.annotate(
            "",
            xy=(x2, y2), xycoords="data",
            xytext=(x1, y1), textcoords="data",
            arrowprops=dict(
                arrowstyle="-|>",
                color="#64748b",
                lw=2.2,
                mutation_scale=16
            ),
            zorder=3
        )
        if label:
            mid_x = (x1 + x2) / 2
            mid_y = y1 + 3.0
            ax.text(mid_x, mid_y, label, fontsize=7.8, fontfamily="sans-serif",
                    fontweight="bold", color="#475569", ha="center", va="center",
                    bbox=dict(boxstyle="round,pad=0.25", fc="#f8fafc", ec="#e2e8f0", lw=0.8), zorder=5)

    # Coordinates for the 5 Stage Cards
    card_w = 16.5
    card_h = 56.0
    card_y = 25.0
    spacing = 19.5
    start_x = 3.0

    stages = [
        {
            "num": "1",
            "tag": "DETECTION",
            "title": "Anomaly Detection",
            "subtitle": "Unsupervised Autoencoder",
            "desc": [
                "Trained exclusively on\nnormal network traffic",
                "Compresses flows to a\n16-D latent bottleneck",
                "Flags abnormal patterns\nvia reconstruction error"
            ],
            "badge": "Zero Attack Bias",
            "badge_bg": "#2563eb",
            "badge_fg": "#ffffff",
            "card_bg": "#f8fafc",
            "card_border": "#93c5fd",
            "accent": "#2563eb",
            "arrow_label": "Deviant Flow"
        },
        {
            "num": "2",
            "tag": "ATTRIBUTION",
            "title": "Threat Attribution",
            "subtitle": "STIX ATT&CK Mapping",
            "desc": [
                "Extracts top-5 anomalous\npacket features",
                "Matches patterns using\nTF-IDF & MiniLM retrieval",
                "Links unknown threats to\n706 MITRE techniques"
            ],
            "badge": "Explainable AI",
            "badge_bg": "#9333ea",
            "badge_fg": "#ffffff",
            "card_bg": "#fdf4ff",
            "card_border": "#f0abfc",
            "accent": "#9333ea",
            "arrow_label": "Technique ID"
        },
        {
            "num": "3",
            "tag": "POLICY",
            "title": "Decision Policy",
            "subtitle": "Rule-Based Gating",
            "desc": [
                "Combines anomaly loss\nand technique confidence",
                "Guarantees 99.32%\nnormal traffic continuity",
                "Automates triage without\nhuman delay"
            ],
            "badge": "Tri-State Safety",
            "badge_bg": "#d97706",
            "badge_fg": "#ffffff",
            "card_bg": "#fffbeb",
            "card_border": "#fde68a",
            "accent": "#d97706",
            "arrow_label": "Decision"
        },
        {
            "num": "4",
            "tag": "PQC WIRE",
            "title": "Post-Quantum Wire",
            "subtitle": "Quantum-Resistant Alerts",
            "desc": [
                "Protects alert channel\nagainst future CRQCs",
                "Hybrid lattice encryption\n(NIST ML-KEM & ML-DSA)",
                "Tamper-proof & immune\nto replay wiretaps"
            ],
            "badge": "NIST FIPS 203 / 204",
            "badge_bg": "#0891b2",
            "badge_fg": "#ffffff",
            "card_bg": "#ecfeff",
            "card_border": "#67e8f9",
            "accent": "#0891b2",
            "arrow_label": "Sealed Alert"
        },
        {
            "num": "5",
            "tag": "ENFORCE",
            "title": "Firewall Action",
            "subtitle": "Autonomous Netfilter",
            "desc": [
                "Applies real-time kernel\niptables drop rules",
                "Blocks attacking IP\nin zero seconds",
                "Updates SOC telemetry\nand threat feed"
            ],
            "badge": "Instant Mitigation",
            "badge_bg": "#059669",
            "badge_fg": "#ffffff",
            "card_bg": "#ecfdf5",
            "card_border": "#6ee7b7",
            "accent": "#059669",
            "arrow_label": ""
        }
    ]

    # Render each stage card
    for i, s in enumerate(stages):
        cx = start_x + (i * spacing)
        cy = card_y
        
        # Outer Card
        draw_card(cx, cy, card_w, card_h, s["card_bg"], s["card_border"])

        # Stage Header Pill
        header_y = cy + card_h - 4.5
        draw_badge(cx + (card_w / 2), header_y, f"STAGE {s['num']} • {s['tag']}", s["badge_bg"], s["badge_fg"], fontsize=8.0)

        # Stage Titles
        ax.text(
            cx + (card_w / 2), cy + card_h - 10.5,
            s["title"],
            fontsize=11.5,
            fontweight="bold",
            fontfamily="sans-serif",
            color="#0f172a",
            ha="center",
            va="center"
        )
        ax.text(
            cx + (card_w / 2), cy + card_h - 14.5,
            s["subtitle"],
            fontsize=8.5,
            fontweight="semibold",
            fontfamily="sans-serif",
            color=s["accent"],
            ha="center",
            va="center"
        )

        # Divider line
        ax.plot(
            [cx + 2.0, cx + card_w - 2.0],
            [cy + card_h - 18.0, cy + card_h - 18.0],
            color=s["card_border"],
            linewidth=1.2,
            zorder=3
        )

        # Stage 3 has interactive action badges
        if s["num"] == "3":
            # ALLOW / MONITOR / BLOCK visual pills
            ax.text(cx + (card_w / 2), cy + card_h - 22.5, "Action Outputs:", fontsize=8.5, fontweight="bold", color="#1e293b", ha="center")
            
            draw_badge(cx + (card_w / 2), cy + card_h - 28.0, "ALLOW  •  Normal Traffic", "#ecfdf5", "#047857", fontsize=8.0)
            draw_badge(cx + (card_w / 2), cy + card_h - 34.0, "MONITOR  •  Analyst Triage", "#fffbeb", "#b45309", fontsize=8.0)
            draw_badge(cx + (card_w / 2), cy + card_h - 40.0, "BLOCK  •  Immediate Drop", "#fef2f2", "#b91c1c", fontsize=8.0)
            
            ax.text(
                cx + (card_w / 2), cy + 8.5,
                "Multi-Condition Safety:\nOnly high-loss attacks blocked",
                fontsize=7.5,
                fontfamily="sans-serif",
                color="#475569",
                ha="center",
                va="center"
            )
        else:
            # Bullet point descriptions (Clean & Short)
            bullet_y = cy + card_h - 23.0
            for bullet in s["desc"]:
                # Bullet card
                draw_card(cx + 1.2, bullet_y - 6.0, card_w - 2.4, 6.8, "#ffffff", "#e2e8f0", border_width=0.8, radius=1.0)
                ax.text(
                    cx + (card_w / 2), bullet_y - 2.6,
                    bullet,
                    fontsize=7.8,
                    fontfamily="sans-serif",
                    color="#334155",
                    ha="center",
                    va="center"
                )
                bullet_y -= 8.5

        # Bottom Key Pill Badge
        draw_badge(cx + (card_w / 2), cy + 3.2, s["badge"], "#ffffff", s["accent"], fontsize=7.8, pad=0.25)

        # Draw Connecting Arrow to Next Stage
        if i < len(stages) - 1:
            arrow_x1 = cx + card_w + 0.4
            arrow_x2 = arrow_x1 + 2.2
            arrow_y = cy + (card_h / 2)
            draw_arrow(arrow_x1, arrow_y, arrow_x2, arrow_y, label=s["arrow_label"])

    # Bottom Simple Caption
    draw_card(3.0, 4.0, 94.0, 15.0, "#f8fafc", "#cbd5e1", radius=1.2)
    
    caption_title = "Figure 1.2: Simplified End-to-End Workflow"
    ax.text(5.5, 15.2, caption_title, fontsize=10.0, fontweight="bold", fontfamily="sans-serif", color="#0f172a", va="top")
    
    caption_body = (
        "1. Traffic is evaluated by an Autoencoder trained on normal traffic to detect zero-day deviations.\n"
        "2. Deviant features are translated into plain text and mapped to MITRE ATT&CK techniques via TF-IDF & MiniLM.\n"
        "3. A rule-based engine generates ALLOW, MONITOR, or BLOCK decisions without human delay.\n"
        "4. Alerts are sealed with hybrid post-quantum cryptography (ML-KEM-768 & ML-DSA-65) to protect against future quantum attacks.\n"
        "5. The firewall enforcer applies automated kernel rules to immediately neutralize attacks."
    )
    ax.text(5.5, 12.2, caption_body, fontsize=7.8, fontfamily="sans-serif", color="#334155", linespacing=1.35, va="top")

    # Right side badge
    draw_badge(88.0, 11.5, "100% Autonomous", "#eff6ff", "#1d4ed8", fontsize=8.2)
    draw_badge(88.0, 7.0, "Quantum-Proof Wire", "#ecfeff", "#0891b2", fontsize=8.2)

    # Save minimal PNG
    fig.savefig(OUTPUT_PNG, dpi=300, facecolor="#ffffff", edgecolor="none")
    plt.close(fig)
    print(f"Successfully generated clean minimal diagram: {OUTPUT_PNG}")

if __name__ == "__main__":
    create_minimal_diagram()
