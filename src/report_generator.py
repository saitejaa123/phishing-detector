"""
PDF Report Generator
Produces a professional security analysis report for a single URL scan.
Compatible with fpdf2 >= 2.7 (uses new-style cell API, ASCII-safe strings).
"""

import base64
import io
import os
import sys
from datetime import datetime
from pathlib import Path

from fpdf import FPDF, XPos, YPos

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(Path(__file__).parent))


# ── Colour palette ────────────────────────────────────────────────────────────
RED    = (220, 53,  69)
GREEN  = (40,  167, 69)
YELLOW = (255, 193,  7)
DARK   = (33,  37,  41)
LIGHT  = (248, 249, 250)
BLUE   = (0,   123, 255)
GRAY   = (108, 117, 125)


class PhishingReport(FPDF):
    """Custom FPDF subclass with branded header / footer."""

    def header(self):
        self.set_fill_color(*DARK)
        self.rect(0, 0, 210, 18, "F")
        self.set_font("Helvetica", "B", 13)
        self.set_text_color(255, 255, 255)
        # ASCII-only title (no em-dash or special chars)
        self.cell(
            0, 18,
            "  AI Phishing URL Detection - Security Report",
            border=0,
            new_x=XPos.LMARGIN, new_y=YPos.NEXT,
            align="L",
        )
        self.set_text_color(*DARK)

    def footer(self):
        self.set_y(-12)
        self.set_font("Helvetica", "I", 8)
        self.set_text_color(*GRAY)
        self.cell(
            0, 10,
            f"Page {self.page_no()} | Generated {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            align="C",
        )


def _verdict_color(label: int, prob: float):
    if label == 1:
        return RED
    if prob > 0.35:
        return YELLOW
    return GREEN


def _risk_label(label: int, prob: float) -> str:
    if label == 1:
        return "PHISHING"
    if prob > 0.35:
        return "SUSPICIOUS"
    return "LEGITIMATE"


def _cell(pdf, w, h, txt, border=0, align="L", fill=False,
          new_x=XPos.RIGHT, new_y=YPos.TOP):
    """Wrapper that uses fpdf2's new XPos/YPos API."""
    pdf.cell(w, h, txt, border=border, align=align, fill=fill,
             new_x=new_x, new_y=new_y)


def _cell_nl(pdf, w, h, txt, border=0, align="L", fill=False):
    """Cell that moves to next line (replaces ln=True)."""
    pdf.cell(w, h, txt, border=border, align=align, fill=fill,
             new_x=XPos.LMARGIN, new_y=YPos.NEXT)


def generate_pdf_report(
    url: str,
    label: int,
    prob: float,
    features: dict,
    shap_explanation: dict,
    chart_b64: str = None,
    output_dir: str = None,
) -> str:
    """
    Generate a PDF security report and return its absolute file path.
    """
    if output_dir is None:
        output_dir = str(ROOT / "reports")
    os.makedirs(output_dir, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename  = f"phishing_report_{timestamp}.pdf"
    filepath  = os.path.join(output_dir, filename)

    verdict = _risk_label(label, prob)
    v_color = _verdict_color(label, prob)

    pdf = PhishingReport(orientation="P", unit="mm", format="A4")
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()
    pdf.set_left_margin(15)
    pdf.set_right_margin(15)

    # ── Scan timestamp ────────────────────────────────────────────────────────
    pdf.set_font("Helvetica", "", 9)
    pdf.set_text_color(*GRAY)
    pdf.ln(2)
    _cell_nl(pdf, 0, 5,
             f"Scan Date: {datetime.now().strftime('%A, %B %d, %Y  %H:%M:%S')}")
    pdf.ln(3)

    # ── URL box ───────────────────────────────────────────────────────────────
    pdf.set_font("Helvetica", "B", 10)
    pdf.set_text_color(*DARK)
    _cell_nl(pdf, 0, 6, "Analysed URL")

    pdf.set_fill_color(*LIGHT)
    pdf.set_font("Courier", "", 9)
    pdf.set_text_color(*DARK)
    display_url = url if len(url) <= 90 else url[:87] + "..."
    # Replace any non-latin1 chars just in case
    display_url = display_url.encode("latin-1", errors="replace").decode("latin-1")
    pdf.multi_cell(0, 7, display_url, border=1, fill=True)
    pdf.ln(4)

    # ── Verdict banner ────────────────────────────────────────────────────────
    pdf.set_fill_color(*v_color)
    pdf.set_text_color(255, 255, 255)
    pdf.set_font("Helvetica", "B", 16)
    _cell_nl(pdf, 0, 14,
             f"  VERDICT: {verdict}   ({prob*100:.1f}% phishing probability)",
             border=0, align="L", fill=True)
    pdf.set_text_color(*DARK)
    pdf.ln(5)

    # ── Risk summary ──────────────────────────────────────────────────────────
    pdf.set_font("Helvetica", "B", 11)
    _cell_nl(pdf, 0, 7, "1. Risk Summary")
    pdf.set_font("Helvetica", "", 10)

    summary_lines = [
        ("Phishing Probability", f"{prob*100:.2f}%"),
        ("Classification",       verdict),
        ("Model Used",           "Ensemble (RF + XGBoost + LR)"),
        ("Features Extracted",   str(len(features))),
    ]
    for key, val in summary_lines:
        pdf.set_fill_color(*LIGHT)
        _cell(pdf, 70, 7, f"  {key}", border="B", fill=True)
        _cell_nl(pdf, 0, 7, f"  {val}", border="B")
    pdf.ln(5)

    # ── Top SHAP contributors ─────────────────────────────────────────────────
    pdf.set_font("Helvetica", "B", 11)
    _cell_nl(pdf, 0, 7, "2. Top Contributing Factors (SHAP)")

    pdf.set_font("Helvetica", "B", 9)
    pdf.set_fill_color(*DARK)
    pdf.set_text_color(255, 255, 255)
    _cell(pdf, 55, 7, "  Feature",   border=0, fill=True)
    _cell(pdf, 28, 7, "Value",       border=0, fill=True, align="C")
    _cell(pdf, 28, 7, "SHAP Impact", border=0, fill=True, align="C")
    _cell_nl(pdf, 0,  7, "Description", border=0, fill=True)
    pdf.set_text_color(*DARK)

    top_contribs = shap_explanation.get("top_contributors", [])[:10]
    for i, item in enumerate(top_contribs):
        sv = item["shap_value"]
        bg = LIGHT if i % 2 == 0 else (255, 255, 255)
        pdf.set_fill_color(*bg)
        pdf.set_font("Helvetica", "", 9)

        pdf.set_text_color(*(RED if sv > 0 else GREEN))
        _cell(pdf, 55, 6, f"  {item['feature']}",    border=0, fill=True)
        _cell(pdf, 28, 6, str(item["feature_value"]), border=0, fill=True, align="C")
        _cell(pdf, 28, 6, f"{sv:+.4f}",              border=0, fill=True, align="C")
        pdf.set_text_color(*DARK)
        desc = item.get("description", "")
        if len(desc) > 52:
            desc = desc[:49] + "..."
        _cell_nl(pdf, 0, 6, desc, border=0, fill=True)
    pdf.ln(5)

    # ── SHAP chart ────────────────────────────────────────────────────────────
    has_chart = False
    if chart_b64:
        try:
            pdf.set_font("Helvetica", "B", 11)
            pdf.set_text_color(*DARK)
            _cell_nl(pdf, 0, 7, "3. SHAP Feature Contribution Chart")
            img_data = base64.b64decode(chart_b64)
            tmp_path = os.path.join(output_dir, "_shap_tmp.png")
            with open(tmp_path, "wb") as f:
                f.write(img_data)
            pdf.image(tmp_path, x=15, w=180)
            os.remove(tmp_path)
            pdf.ln(5)
            has_chart = True
        except Exception as e:
            print(f"[!] Chart embed failed (skipping): {e}")

    # ── All features table ────────────────────────────────────────────────────
    section_num = 4 if has_chart else 3
    pdf.set_font("Helvetica", "B", 11)
    pdf.set_text_color(*DARK)
    _cell_nl(pdf, 0, 7, f"{section_num}. All Extracted Features")

    pdf.set_font("Helvetica", "B", 9)
    pdf.set_fill_color(*DARK)
    pdf.set_text_color(255, 255, 255)
    _cell(pdf, 90, 7, "  Feature Name", border=0, fill=True)
    _cell_nl(pdf, 0, 7, "Value",         border=0, fill=True)
    pdf.set_text_color(*DARK)

    for i, (key, val) in enumerate(features.items()):
        bg = LIGHT if i % 2 == 0 else (255, 255, 255)
        pdf.set_fill_color(*bg)
        pdf.set_font("Helvetica", "", 8)
        _cell(pdf, 90, 5, f"  {key}", border=0, fill=True)
        _cell_nl(pdf, 0, 5, str(val), border=0, fill=True)
    pdf.ln(5)

    # ── Recommendations ───────────────────────────────────────────────────────
    next_section = section_num + 1
    pdf.set_font("Helvetica", "B", 11)
    _cell_nl(pdf, 0, 7, f"{next_section}. Security Recommendations")
    pdf.set_font("Helvetica", "", 10)

    if label == 1:
        recommendations = [
            "DO NOT click this link or enter any credentials.",
            "Report the URL to your IT/security team immediately.",
            "If already visited, change related passwords at once.",
            "Enable multi-factor authentication (MFA) on all accounts.",
            "Block the domain in your firewall and DNS filter.",
        ]
    elif prob > 0.35:
        recommendations = [
            "Treat this URL with caution - it shows some suspicious traits.",
            "Verify the domain through official channels before proceeding.",
            "Check the SSL certificate and domain registration date.",
            "Avoid submitting sensitive information on this page.",
        ]
    else:
        recommendations = [
            "URL appears legitimate, but always stay vigilant online.",
            "Verify HTTPS and check for a valid SSL certificate.",
            "Keep your browser and OS up to date.",
            "Use a password manager to detect impersonation sites.",
        ]

    for rec in recommendations:
        _cell(pdf, 5, 6, "")
        _cell(pdf, 3, 6, "*")
        _cell_nl(pdf, 0, 6, f" {rec}")
    pdf.ln(3)

    # ── Disclaimer ────────────────────────────────────────────────────────────
    pdf.set_font("Helvetica", "I", 8)
    pdf.set_text_color(*GRAY)
    pdf.multi_cell(
        0, 5,
        "Disclaimer: This report is generated by an automated AI system for "
        "educational and informational purposes. It should not be the sole "
        "basis for security decisions. Always consult a qualified security "
        "professional for critical assessments.",
    )

    pdf.output(filepath)
    return filepath
