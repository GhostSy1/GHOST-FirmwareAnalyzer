from __future__ import annotations

import json
from pathlib import Path
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors


def generate_executive_pdf(report_json_path: Path, output_pdf_path: Path) -> Path:
    data = json.loads(report_json_path.read_text(encoding="utf-8"))
    doc = SimpleDocTemplate(str(output_pdf_path), pagesize=letter, rightMargin=36, leftMargin=36, topMargin=36, bottomMargin=36)
    styles = getSampleStyleSheet()
    
    title_style = ParagraphStyle('DocTitle', parent=styles['Heading1'], fontSize=20, leading=24, textColor=colors.HexColor('#1a1a1a'), spaceAfter=6)
    sub_style = ParagraphStyle('DocSub', parent=styles['Normal'], fontSize=10, leading=14, textColor=colors.HexColor('#555555'), spaceAfter=14)
    h2_style = ParagraphStyle('Heading2Custom', parent=styles['Heading2'], fontSize=14, leading=18, textColor=colors.HexColor('#2c3e50'), spaceBefore=12, spaceAfter=6)
    body_style = ParagraphStyle('BodyCustom', parent=styles['Normal'], fontSize=9, leading=13, textColor=colors.HexColor('#222222'))
    
    story = []
    story.append(Paragraph("<b>GHOST SECURITY ASSESSMENT REPORT</b>", title_style))
    story.append(Paragraph(f"Tool: {data.get('tool')} | Version: {data.get('version')} | Profile: {data.get('profile')}", sub_style))
    story.append(Spacer(1, 8))
    
    summary_data = [
        ["Target Analyzed", str(data.get("target"))],
        ["Assessment Timestamp", str(data.get("analyzed_at"))],
        ["Total Artifacts Inspected", str(data.get("artifact_count"))],
        ["Total Findings Discovered", str(data.get("finding_count"))],
        ["Source-Bound Verified", str(data.get("metadata", {}).get("source_bound_verified", True))]
    ]
    t = Table(summary_data, colWidths=[160, 380])
    t.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (0,-1), colors.HexColor('#f0f3f4')),
        ('TEXTCOLOR', (0,0), (-1,-1), colors.HexColor('#222222')),
        ('FONTNAME', (0,0), (-1,-1), 'Helvetica-Bold'),
        ('FONTSIZE', (0,0), (-1,-1), 9),
        ('BOTTOMPADDING', (0,0), (-1,-1), 6),
        ('TOPPADDING', (0,0), (-1,-1), 6),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#dcdcdc'))
    ]))
    story.append(t)
    story.append(Spacer(1, 14))
    
    story.append(Paragraph("<b>Executive Findings Summary</b>", h2_style))
    findings = data.get("findings", [])
    if not findings:
        story.append(Paragraph("No security findings or risk indicators were identified in the inspected target.", body_style))
    else:
        table_rows = [["Rule ID", "Severity", "Location", "Evidence"]]
        for f in findings[:50]:
            table_rows.append([
                Paragraph(f.get("rule_id", ""), body_style),
                Paragraph(f.get("severity", "").upper(), body_style),
                Paragraph(f.get("location", ""), body_style),
                Paragraph(f.get("evidence", "")[:100], body_style)
            ])
        ft = Table(table_rows, colWidths=[90, 60, 140, 250])
        ft.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#2c3e50')),
            ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('FONTSIZE', (0,0), (-1,-1), 8),
            ('BOTTOMPADDING', (0,0), (-1,-1), 5),
            ('TOPPADDING', (0,0), (-1,-1), 5),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#dcdcdc'))
        ]))
        story.append(ft)
        
    doc.build(story)
    return output_pdf_path
