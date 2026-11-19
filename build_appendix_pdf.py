import os
from PIL import Image as PILImage
import matplotlib.pyplot as plt
from reportlab.lib.pagesizes import A4
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image, PageBreak, KeepTogether, HRFlowable
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from reportlab.pdfgen import canvas

WORKSPACE = r"c:\Users\Purnendu\Downloads\attack-detective"
MATH_DIR = os.path.join(WORKSPACE, "math_img")
OUTPUT_PDF = os.path.join(WORKSPACE, "Attack_Detective_Report_Appendix.pdf")

os.makedirs(MATH_DIR, exist_ok=True)

# 1. Render Mathematical Formulas into crisp 300 DPI vector-sharp PNGs
def generate_formula_images():
    formulas = {
        'eq1_encoder': (r'$\mathbf{h}_1 = \mathrm{ReLU}(\mathbf{W}_1 \mathbf{x} + \mathbf{b}_1), \quad \mathbf{h}_2 = \mathrm{ReLU}(\mathbf{W}_2 \mathbf{h}_1 + \mathbf{b}_2), \quad \mathbf{z} = \mathrm{ReLU}(\mathbf{W}_3 \mathbf{h}_2 + \mathbf{b}_3)$', 11.5),
        'eq2_mse': (r'$\mathcal{L}_{\mathrm{MSE}}(\mathbf{x}, \hat{\mathbf{x}}) = \frac{1}{D} \sum_{j=1}^{D} (x_j - \hat{x}_j)^2$', 12.0),
        'eq3_decision': (r'$\mathrm{Decision}(\mathbf{x}) = \mathbf{ANOMALOUS} \;\; [\mathrm{if} \; S(\mathbf{x}) \geq \tau_\alpha], \quad \mathbf{BENIGN} \;\; [\mathrm{if} \; S(\mathbf{x}) < \tau_\alpha]$', 11.0),
        'eq4_residual': (r'$\mathcal{K} = \arg\max_{j \in \{1,\dots,76\}}^{(5)} \left( \frac{|x_j - \hat{x}_j|}{\sigma_j} \right)$', 12.0),
        'eq5_cosine': (r'$\mathrm{Sim}(\mathbf{q}, \mathbf{d}_i) = \frac{\mathbf{q} \cdot \mathbf{d}_i}{\|\mathbf{q}\|_2 \, \|\mathbf{d}_i\|_2}$', 12.0),
        'eq6_hkdf': (r'$K_{\mathrm{session}} = \mathrm{HKDF\text{-}Extract\text{-}Expand}(SS_{\mathrm{X25519}} \,\|\, SS_{\mathrm{ML\text{-}KEM\text{-}768}}, \; \mathrm{Context})$', 11.0),
        'eq7_policy': (r'$\mathrm{Action}(\mathbf{x}) = \mathbf{BLOCK} \; [S(\mathbf{x}) \geq \tau_{\mathrm{block}}], \;\; \mathbf{MONITOR} \; [\tau_\alpha \leq S(\mathbf{x}) < \tau_{\mathrm{block}}], \;\; \mathbf{ALLOW} \; [S(\mathbf{x}) < \tau_\alpha]$', 10.5)
    }

    image_meta = {}
    for name, (latex_str, fsize) in formulas.items():
        fig = plt.figure(figsize=(0.01, 0.01))
        fig.text(0, 0, latex_str, fontsize=fsize, color='#0f172a')
        out_path = os.path.join(MATH_DIR, f"{name}.png")
        fig.savefig(out_path, dpi=300, bbox_inches='tight', pad_inches=0.03, transparent=True)
        plt.close(fig)
        im = PILImage.open(out_path)
        image_meta[name] = (out_path, im.size[0], im.size[1])
    return image_meta

class NumberedCanvas(canvas.Canvas):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_decorations(num_pages)
            super().showPage()
        super().save()

    def draw_page_decorations(self, page_count):
        self.saveState()
        self.setFont("Helvetica", 7.5)
        self.setFillColor(colors.HexColor("#64748b"))
        
        # Header (pages after page 1)
        if self._pageNumber > 1:
            self.drawString(36, 810, "Attack Detective &bull; Comprehensive Technical Report Appendix")
            self.drawRightString(559, 810, "Mathematical Foundations &amp; System Specifications")
            self.setStrokeColor(colors.HexColor("#cbd5e1"))
            self.setLineWidth(0.5)
            self.line(36, 804, 559, 804)
            
        # Footer
        page_str = f"Page {self._pageNumber} of {page_count}"
        self.drawRightString(559, 24, page_str)
        self.drawString(36, 24, "Attack Detective: Autonomous Zero-Day Detection & PQC Wire Defense — Technical Appendix")
        self.setStrokeColor(colors.HexColor("#cbd5e1"))
        self.setLineWidth(0.5)
        self.line(36, 33, 559, 33)
        self.restoreState()

def create_eq_block(img_info, target_width, eq_number, num_style):
    img_path, w_px, h_px = img_info
    target_height = target_width * (h_px / w_px)
    img_elem = Image(img_path, width=target_width, height=target_height)
    
    # Table layout: [Spacer, Image (centered), Eq number (right-aligned)]
    t = Table(
        [[Paragraph("", num_style), img_elem, Paragraph(f"({eq_number})", num_style)]],
        colWidths=[30, 463, 30]
    )
    t.setStyle(TableStyle([
        ('ALIGN', (1, 0), (1, 0), 'CENTER'),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('ALIGN', (2, 0), (2, 0), 'RIGHT'),
        ('TOPPADDING', (0, 0), (-1, -1), 1),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 2),
    ]))
    return t

def build_pdf():
    img_meta = generate_formula_images()

    doc = SimpleDocTemplate(
        OUTPUT_PDF,
        pagesize=A4,
        leftMargin=36,
        rightMargin=36,
        topMargin=38,
        bottomMargin=38
    )

    styles = getSampleStyleSheet()

    sub_title = ParagraphStyle(
        'DocSubTitle',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=8.5,
        leading=11,
        textColor=colors.HexColor("#2563eb"),
        textTransform='uppercase',
        spaceAfter=2
    )

    title = ParagraphStyle(
        'DocTitle',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=15,
        leading=18,
        textColor=colors.HexColor("#0f172a"),
        spaceAfter=3
    )

    meta_bar = ParagraphStyle(
        'MetaBar',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=7.2,
        leading=9.5,
        textColor=colors.HexColor("#64748b"),
        spaceAfter=5
    )

    h2_style = ParagraphStyle(
        'H2Style',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=9.2,
        leading=11.5,
        textColor=colors.HexColor("#0f172a"),
        spaceBefore=5,
        spaceAfter=2,
        keepWithNext=True
    )

    p_style = ParagraphStyle(
        'BodyP',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=7.8,
        leading=10.2,
        textColor=colors.HexColor("#334155"),
        spaceAfter=3,
        alignment=4 # Justified
    )

    eq_num_style = ParagraphStyle(
        'EqNum',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=7.5,
        leading=9,
        textColor=colors.HexColor("#64748b")
    )

    callout_p = ParagraphStyle(
        'CalloutP',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=7.2,
        leading=9.2,
        textColor=colors.HexColor("#1e293b")
    )

    story = []

    # Title & Metadata Cover Header
    story.append(Paragraph("TECHNICAL SPECIFICATIONS &amp; METHODOLOGY REPORT", sub_title))
    story.append(Paragraph("APPENDIX: System Specifications, Mathematical Foundations, and Experimental Protocols", title))
    story.append(Paragraph("<b>System Architecture:</b> Unsupervised Bottleneck AE &bull; NLP Residual ATT&amp;CK Mapping &bull; NIST FIPS 203/204 Post-Quantum Wiretap Immunity &bull; <b>Dataset:</b> CIC-IDS2017 (2.83M Raw &rarr; 2.20M Cleaned Flows)", meta_bar))
    story.append(HRFlowable(width="100%", thickness=1.2, color=colors.HexColor("#0f172a"), spaceAfter=5))

    # P1: Overview
    story.append(Paragraph(
        "The Attack Detective framework is designed as a unified, defense-in-depth intrusion detection, attribution, and containment architecture. It integrates an unsupervised deep neural autoencoder for zero-day anomaly detection, a natural language processing (NLP) semantic attribution engine mapped against the MITRE ATT&amp;CK enterprise matrix, and a quantum-resistant cryptographic transport layer adhering to NIST FIPS post-quantum standards. This appendix provides the complete mathematical formulations, data preprocessing procedures, attribution mechanics, cryptographic protocols, policy gating formulas, and environmental specifications governing the system.",
        p_style
    ))

    # Section 1: Mathematical Formulation
    story.append(Paragraph("1. Mathematical Formulation and Reconstruction Manifold", h2_style))
    story.append(Paragraph(
        "The detection core operates on the mathematical premise that authorized, non-malicious enterprise network traffic occupies a low-dimensional manifold embedded within a high-dimensional feature space. Let <b>x</b> &isin; &real;<sup>D</sup> represent a continuous flow telemetry vector, where D = 76 corresponds to normalized bidirectional statistical attributes. The neural autoencoder comprises an encoding transformation f<sub>&theta;</sub>: &real;<sup>D</sup> &rarr; &real;<sup>d</sup> and a decoding transformation g<sub>&phi;</sub>: &real;<sup>d</sup> &rarr; &real;<sup>D</sup>, where d = 16 establishes a constrained latent bottleneck dimension (d &ll; D). The encoder compresses input telemetry through dense affine projections regulated by weight matrices <b>W</b> and bias vectors <b>b</b>:",
        p_style
    ))
    
    # Eq 1: Encoder
    story.append(create_eq_block(img_meta['eq1_encoder'], 360, 1, eq_num_style))
    
    story.append(Paragraph(
        "The decoder reconstructs the intermediate bottleneck representation <b>z</b> &isin; &real;<sup>16</sup> back into the original 76-dimensional space, yielding reconstructed vector <b>x&#770;</b> = g<sub>&phi;</sub>(<b>z</b>). During the training phase, the network optimizes parameter sets {&theta;, &phi;} exclusively on verified benign network interactions by minimizing the mean squared error (MSE) objective:",
        p_style
    ))
    
    # Eq 2: MSE Loss
    story.append(create_eq_block(img_meta['eq2_mse'], 140, 2, eq_num_style))
    
    story.append(Paragraph(
        "Because the narrow bottleneck restricts informational capacity, the autoencoder learns the generalized statistical regularities of benign flows (e.g., standard TCP handshakes, nominal byte asymmetries, predictable inter-arrival variances). When anomalous or adversarial traffic traverses the system, its structural patterns deviate from the learned benign subspace, producing sharp increases in reconstruction error. The scalar anomaly score S(<b>x</b>) = L<sub>MSE</sub>(<b>x</b>, <b>x&#770;</b>) is evaluated against an empirical cutoff threshold &tau;<sub>&alpha;</sub> established at the &alpha;-th percentile of the validation loss distribution:",
        p_style
    ))
    
    # Eq 3: Decision Rule
    story.append(create_eq_block(img_meta['eq3_decision'], 330, 3, eq_num_style))
    
    story.append(Paragraph(
        "Evaluating across &alpha; &isin; {95, 97, 99} demonstrated that &alpha; = 95 achieves an optimal balance between precision (0.9541 &plusmn; 0.0010) and recall (0.8797 &plusmn; 0.0163), yielding a peak F1-score of 0.9153 &plusmn; 0.0093 and an ROC-AUC of 0.9775 &plusmn; 0.0028.",
        p_style
    ))

    # Section 2: Dataset Preparation
    story.append(Paragraph("2. Dataset Preparation, Cleansing, and Feature Hygiene", h2_style))
    story.append(Paragraph(
        "The experimental evaluations utilized the Canadian Institute for Cybersecurity (CIC-IDS2017) benchmark dataset, capturing realistic background traffic interspersed with diverse attack behaviors across fifteen distinct traffic classes. The raw corpus of 2,830,743 records underwent a multi-stage data cleansing pipeline: (a) <i>Singularity Filtering:</i> Severe volumetric flooding attacks generated mathematical anomalies in downstream statistical divisions (flow byte rates and packets per second yielding divide-by-zero or infinite values). A total of 2,867 corrupted rows containing &plusmn;&infin; or NaN entries were excised, preserving 2,827,876 clean flow records. (b) <i>Cryptographic De-duplication:</i> Repetitive connection attempts, port scans, and multi-interface PCAP capture overlaps introduced substantial record duplication. A SHA-256 fingerprint was computed over each record's complete attribute tuple; 628,872 duplicate flows were removed, resulting in a finalized corpus of 2,199,004 unique flows (77.68% of raw volume). (c) <i>Statistical Normalization:</i> The remaining 76 continuous numerical features capture bidirectional traffic characteristics, including forward/backward inter-arrival times (IAT Mean, IAT Std, IAT Max), packet length distributions, subflow ratios, and TCP flag occurrences (FIN, SYN, RST, PSH, ACK, URG), scaled using robust median and IQR standard scaling. (d) <i>Partitioning:</i> Data was partitioned across a 5-fold stratified cross-validation split, isolating benign traffic (1,862,527 flows) exclusively for training the unsupervised model.",
        p_style
    ))

    # Section 3: Baseline Comparison
    story.append(Paragraph("3. Detection Benchmarking Against Isolation Forest Baseline", h2_style))
    story.append(Paragraph(
        "To establish comparative efficacy, the autoencoder was evaluated alongside an industry-standard Isolation Forest baseline configured with 100 isolation trees and contamination parameters tuned to corresponding percentile thresholds (95th, 97th, and 99th). While Isolation Forest achieved a respectable ROC-AUC of 0.9085 &plusmn; 0.0100, its operational performance degraded significantly under thresholded gating, registering a 95th-percentile recall of only 28.75% &plusmn; 17.98% and an F1-score of 0.4099 &plusmn; 0.2108. Granular per-family evaluations at the 99th percentile revealed severe structural limitations in Isolation Forest: it exhibited complete detection failure on distributed denial-of-service traffic (0.00% detection on DDoS, 0.12% on DoS Hulk). In contrast, the bottleneck autoencoder flagged 73.95% of DoS Hulk, 55.45% of DDoS, 61.34% of DoS Slowloris, and 75.00% of Infiltration attacks, while maintaining a false positive rate of only 1.02% on benign flows.",
        p_style
    ))

    # Clean Page Break to Page 2
    story.append(PageBreak())

    # Section 4: Feature Residual Synthesis
    story.append(Paragraph("4. Feature Residual Synthesis and MITRE ATT&amp;CK Attribution", h2_style))
    story.append(Paragraph(
        "Binary detection alone provides insufficient actionable context for Security Operations Center (SOC) personnel. Attack Detective bridges detection and operational intelligence through an automated <b>Residual Feature Synthesis Engine</b>. For any flagged anomalous flow <b>x</b>, an element-wise residual vector <b>r</b> = |<b>x</b> &minus; <b>x&#770;</b>| is computed across all 76 dimensions. The top-5 most deviant features are extracted based on their standardized z-score deviation:",
        p_style
    ))
    
    # Eq 4: Residual
    story.append(create_eq_block(img_meta['eq4_residual'], 135, 4, eq_num_style))
    
    story.append(Paragraph(
        "These deviant residuals are transformed into structured natural language behavioral summaries (e.g., <i>'Elevated SYN flag frequency with abnormal backward packet length variance and truncated inter-arrival timing'</i>). This synthesized behavioral text is mapped against a vector database indexing <b>706 enterprise techniques from the MITRE ATT&amp;CK framework</b> (parsed directly from official STIX v2.1 schemas). The query <b>q</b> and technique descriptions {<b>d</b><sub>i</sub>} are projected into an aligned semantic space using TF-IDF n-gram vectorization and dense transformer representations (<code>all-MiniLM-L6-v2</code>), ranking candidate tactics via cosine similarity:",
        p_style
    ))
    
    # Eq 5: Cosine Similarity
    story.append(create_eq_block(img_meta['eq5_cosine'], 115, 5, eq_num_style))
    
    story.append(Paragraph(
        "Benchmarking across 6,837 evaluated attack flows proved that enriching telemetry with residual feature synthesis increases Top-3 ATT&amp;CK attribution accuracy from <b>25.26% to 61.04%</b> (a 2.4&times; improvement and <b>21.6&times; above the uniform random guess baseline</b> of 2.82%).",
        p_style
    ))

    # Section 5: Post-Quantum Wiretap Immunity
    story.append(Paragraph("5. Post-Quantum Cryptographic Wiretap Immunity (NIST FIPS 203 / 204)", h2_style))
    story.append(Paragraph(
        "Telemetry alerts transmitted between distributed sensors and central SIEM/SOC platforms represent attractive targets for 'Harvest Now, Decrypt Later' (HNDL) quantum eavesdropping campaigns. Attack Detective eliminates quantum vulnerability by implementing a hybrid post-quantum transport layer conforming to <b>NIST FIPS 203 (ML-KEM)</b> and <b>NIST FIPS 204 (ML-DSA)</b> standards. The session handshake executes a dual-encapsulation protocol: classical elliptic-curve Diffie-Hellman (X25519, 32-byte public key) is combined with lattice-based Module Learning with Errors (ML-KEM-768 / Kyber, 1,184-byte public key). The resulting shared secrets are concatenated and derived through a SHA-3 HKDF key derivation function:",
        p_style
    ))
    
    # Eq 6: HKDF
    story.append(create_eq_block(img_meta['eq6_hkdf'], 360, 6, eq_num_style))
    
    story.append(Paragraph(
        "Alert payloads are encrypted using authenticated AES-256-GCM. Digital signatures and non-repudiation are enforced through a hybrid pairing of Ed25519 and ML-DSA-65 (Dilithium, 1,952-byte public key, 3,309-byte signature). A regression suite of 35 negative security test cases validated critical defense invariants: (1) <i>Anti-Replay Protection:</i> Monotonically incrementing 64-bit sequence counters tied to millisecond UNIX timestamps reject duplicated or delayed alerts (&Delta;t &gt; 300 s). (2) <i>Ciphertext Integrity:</i> Single-bit modifications to ciphertext or authenticated header bytes trigger immediate GCM authentication failures. (3) <i>Downgrade Immunity:</i> Strict mode pinning terminates handshakes if an active adversary attempts to strip post-quantum lattice extensions. Microbenchmarks demonstrate that hybrid post-quantum encapsulation incurs only <b>4.05 ms of added latency</b> and sustains <b>288.9 alerts/second</b>, ensuring high-throughput operational readiness.",
        p_style
    ))

    # Section 6: Autonomous Firewall Policy Calibration
    story.append(Paragraph("6. Autonomous Firewall Policy Calibration and Decision Logic", h2_style))
    story.append(Paragraph(
        "To minimize human operator fatigue, the system incorporates an autonomous tri-state firewall gating policy categorizing flows into ALLOW, MONITOR, and BLOCK actions based on reconstruction error S(<b>x</b>) and statistical bounds:",
        p_style
    ))
    
    # Eq 7: Policy
    story.append(create_eq_block(img_meta['eq7_policy'], 410, 7, eq_num_style))
    
    story.append(Paragraph(
        "Optimization sweeps across validation splits identified optimal hyperparameters at an enforcement multiplier k = 1.5 and minimum sensitivity floor s<sub>min</sub> = 0.05. When evaluated on the holdout test half, this policy achieved a <b>99.32% Benign ALLOW rate</b> (0.27% monitor, 0.41% false block), strictly preserving enterprise operational continuity and SLA requirements while isolating anomalous traffic.",
        p_style
    ))

    # Section 7: Hardware & Reproducibility
    story.append(Paragraph("7. Laboratory Hardware and Environmental Specifications", h2_style))
    story.append(Paragraph(
        "All training procedures, cross-validation folds, NLP attributions, and cryptographic wiretap benchmarks were conducted in an isolated laboratory environment under standardized hardware parameters: (a) <i>Processor:</i> 13th Gen Intel Core i7 (Intel64 Family 6 Model 186 Stepping 2, 16 physical cores, 24 execution threads @ 2.40 GHz &ndash; 5.00 GHz). (b) <i>Operating System:</i> Microsoft Windows 11 Enterprise (64-bit), Kernel Version 10.0.22631. (c) <i>Software Stack:</i> Python 3.12.3, PyTorch 2.15.0+cpu, Scikit-Learn 1.9.1, ReportLab 5.1.0, Cryptography 50.0.2. (d) <i>Reproducibility:</i> Seed controls (Seeds &isin; {0, 1, 2, 3, 4}) locked pseudorandom generators across NumPy, PyTorch CPU kernels, and Scikit-Learn splitters. Training converged uniformly within 20 epochs across all initialization seeds without numerical divergence.",
        p_style
    ))

    # Key Architectural Discovery Box
    callout_data = [[
        Paragraph(
            "<b>Key Architectural Discovery:</b> By decoupling unsupervised manifold learning (AE) from downstream semantic attribution (STIX ATT&amp;CK) and securing telemetry transport with NIST FIPS 203/204 hybrid lattice cryptography, Attack Detective achieves <b>0.9775 ROC-AUC</b>, elevates Top-3 attribution from <b>25.26% &rarr; 61.04%</b>, and guarantees <b>99.32% Benign ALLOW continuity</b> with absolute wiretap replay immunity.",
            callout_p
        )
    ]]
    callout_table = Table(callout_data, colWidths=[523])
    callout_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor("#f8fafc")),
        ('BOX', (0,0), (-1,-1), 1.0, colors.HexColor("#cbd5e1")),
        ('LEFTPADDING', (0,0), (-1,-1), 8),
        ('RIGHTPADDING', (0,0), (-1,-1), 8),
        ('TOPPADDING', (0,0), (-1,-1), 5),
        ('BOTTOMPADDING', (0,0), (-1,-1), 5),
    ]))
    story.append(Spacer(1, 4))
    story.append(callout_table)

    doc.build(story, canvasmaker=NumberedCanvas)
    print(f"Updated Appendix PDF successfully built: {OUTPUT_PDF}")

if __name__ == "__main__":
    build_pdf()
