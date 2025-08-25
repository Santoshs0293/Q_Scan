from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
import json
import os
from datetime import datetime
from utils.helpers import setup_logger

class ReportGenerator:
    def __init__(self, output_dir):
        self.output_dir = output_dir
        self.logger = setup_logger()
        os.makedirs(output_dir, exist_ok=True)

    def generate_report(self, items, target, skipped_items=None):
        self.logger.info(f"Generating report for {target}")
        skipped_items = skipped_items or []
        
        # Sanitize target for filename
        safe_target = target.replace("https://", "").replace("http://", "").replace(":", "_").replace("/", "_")
        
        # JSON Report
        report_data = {
            "target": target,
            "scan_time": datetime.now().isoformat(),
            "items": items,
            "skipped_items": skipped_items
        }
        json_path = os.path.join(self.output_dir, f"{safe_target}_report.json")
        with open(json_path, "w") as f:
            json.dump(report_data, f, indent=4)
        
        # PDF Report
        pdf_path = os.path.join(self.output_dir, f"{safe_target}_report.pdf")
        doc = SimpleDocTemplate(pdf_path, pagesize=A4, leftMargin=36, rightMargin=36)
        styles = getSampleStyleSheet()
        
        # Define custom ParagraphStyle for table cells with wrapping
        cell_style = ParagraphStyle(
            name='CellStyle',
            parent=styles['Normal'],
            fontName='Helvetica',
            fontSize=8,
            leading=10,
            wordWrap='CJK',
            alignment=0,
            spaceAfter=4
        )
        
        def safe_str(value):
            return str(value) if value is not None else "None"
        
        story = []
        
        # Title
        story.append(Paragraph(f"Q-SecureScan Report for {target}", styles["Title"]))
        story.append(Paragraph(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles["Normal"]))
        story.append(Spacer(1, 12))
        
        # Scanned Items Table
        story.append(Paragraph("Scanned Items", styles["Heading2"]))
        table_data = [
            [
                Paragraph("Item ID", styles['Heading3']),
                Paragraph("Type", styles['Heading3']),
                Paragraph("Protocol/Service", styles['Heading3']),
                Paragraph("Heuristics", styles['Heading3']),
                Paragraph("Encryption Markers", styles['Heading3']),
                Paragraph("Algorithms", styles['Heading3']),
                Paragraph("PQC Recommendation", styles['Heading3'])
            ]
        ]
        
        for item in items:
            protocol_service = (
                item["analysis"].get("protocol", item["analysis"].get("service", "N/A"))
                if item["type"] in ["protocol", "port"]
                else item["analysis"].get("extension", "N/A")
            )
            
            algorithms = item.get("algorithms", [])
            algo_str = ", ".join(algorithms) if algorithms else "None"
            
            heuristics = safe_str(item["analysis"].get("heuristics", "N/A"))
            if item.get("is_anomaly"):
                heuristics += f"; Anomaly: {safe_str(item.get('anomaly_details'))}"
            
            table_data.append([
                Paragraph(safe_str(item["id"]), cell_style),
                Paragraph(safe_str(item["type"]), cell_style),
                Paragraph(safe_str(protocol_service), cell_style),
                Paragraph(safe_str(heuristics), cell_style),
                Paragraph(safe_str(item["analysis"].get("encryption_markers", "None")), cell_style),
                Paragraph(safe_str(algo_str), cell_style),
                Paragraph(safe_str(item["pqc_recommendation"]), cell_style)
            ])
        
        table = Table(table_data, colWidths=[75, 45, 75, 95, 75, 95, 108])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 8),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('LEFTPADDING', (0, 0), (-1, -1), 4),
            ('RIGHTPADDING', (0, 0), (-1, -1), 4),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ]))
        story.append(table)
        story.append(Spacer(1, 12))
        
        story.append(Paragraph("Skipped Items", styles["Heading2"]))
        if skipped_items:
            for item in skipped_items:
                story.append(Paragraph(f"Item: {safe_str(item)}", cell_style))
                story.append(Spacer(1, 6))
        else:
            story.append(Paragraph("None", cell_style))
            story.append(Spacer(1, 6))
        
        doc.build(story)
        self.logger.info(f"Reports saved: {json_path}, {pdf_path}")