"""Session report export — JSON (native) and PDF."""

from __future__ import annotations

import time
from typing import Optional


def report_pdf_bytes(report: dict) -> bytes:
    """Generate a simple PDF incident/session report."""
    from fpdf import FPDF

    sess = report.get("session") or {}
    summary = report.get("summary") or {}
    company = report.get("company") or {}

    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.set_margins(15, 15, 15)
    pdf.add_page()
    w = pdf.w - pdf.l_margin - pdf.r_margin

    pdf.set_font("Helvetica", "B", 16)
    pdf.cell(w, 10, "Sentinel Memory - Session Report", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 10)
    ts = time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(summary.get("generated_at", time.time())))
    pdf.cell(w, 6, f"Generated: {ts}", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(4)

    pdf.set_font("Helvetica", "B", 12)
    pdf.cell(w, 8, "Company", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 10)
    pdf.multi_cell(w, 5, _ascii_safe(f"{company.get('name', 'N/A')} ({company.get('industry', '')})"))
    pdf.ln(2)

    pdf.set_font("Helvetica", "B", 12)
    pdf.cell(w, 8, "Session", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 10)
    pdf.multi_cell(w, 5, _ascii_safe(
        f"ID: {sess.get('id', '')}\n"
        f"Channel: {sess.get('channel', 'chat')}\n"
        f"Final trust: {summary.get('final_trust', sess.get('trust_score', 0))}\n"
        f"Turns: {summary.get('turns', 0)} | BLOCK: {summary.get('blocks', 0)} | ALLOW: {summary.get('allows', 0)}"
    ))
    pdf.ln(4)

    pdf.set_font("Helvetica", "B", 12)
    pdf.cell(w, 8, "Conversation transcript", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 9)
    for turn in sess.get("turns") or []:
        role = (turn.get("role") or "?").upper()
        verdict = turn.get("verdict") or ""
        vtag = f" [{verdict}]" if verdict else ""
        line = f"{role}{vtag}: {(turn.get('content') or '')[:480]}"
        pdf.multi_cell(w, 4, _ascii_safe(line))
        threat = (turn.get("analysis") or {}).get("threat_match")
        if threat:
            pdf.set_text_color(180, 40, 40)
            pdf.multi_cell(w, 4, _ascii_safe(f"  Threat: {str(threat)[:120]}"))
            pdf.set_text_color(0, 0, 0)
        pdf.ln(1)

    pdf.ln(4)
    pdf.set_font("Helvetica", "I", 8)
    pdf.multi_cell(w, 4, "Sentinel Memory - trust-aware retrieval firewall.")

    return bytes(pdf.output())


def _ascii_safe(text: str) -> str:
    if not text:
        return ""
    return text.encode("latin-1", errors="replace").decode("latin-1")
