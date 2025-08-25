from reportlab.lib.pagesizes import A3
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, KeepTogether
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
import json
import csv
import os
from datetime import datetime
from utils.helpers import setup_logger
from utils.crypto_db import is_quantum_vulnerable

class ReportGenerator:
    def __init__(self, output_dir):
        self.output_dir = output_dir
        self.logger = setup_logger("ReportGenerator")
        os.makedirs(output_dir, exist_ok=True)
        self.logger.info(f"Output directory set to {output_dir}")

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
        
        # SCAP-Compatible JSON Report
        scap_report = {
            "id": f"qsecurescan-{safe_target}-{datetime.now().strftime('%Y%m%d%H%M%S')}",
            "timestamp": datetime.now().isoformat(),
            "target": target,
            "vulnerabilities": []
        }
        for item in items:
            severity = item["pqc_recommendation"].split(";")[0].replace("Severity: ", "").strip() if "Severity" in item["pqc_recommendation"] else "Low"
            algorithms = ", ".join(a["full"] for a in item.get("algorithms", [])) or "None"
            for violation in item.get("policy_violations", []):
                scap_report["vulnerabilities"].append({
                    "id": f"QSEC-{item['id']}",
                    "description": violation.get("details", "Cryptographic vulnerability"),
                    "severity": violation.get("severity", severity),
                    "compliance": violation.get("compliance", ""),
                    "affected_item": item["id"],
                    "algorithms": algorithms,
                    "recommendation": item["pqc_recommendation"],
                    "remediation": item.get("remediation_guidance", "No remediation required")
                })
        scap_path = os.path.join(self.output_dir, f"{safe_target}_scap.json")
        with open(scap_path, "w") as f:
            json.dump(scap_report, f, indent=4)
        
        # CSV Report for Dashboard
        csv_path = os.path.join(self.output_dir, f"{safe_target}_dashboard.csv")
        dashboard = {
            "total_items": len(items),
            "severity_counts": {"High": 0, "Medium": 0, "Low": 0, "Unknown": 0},
            "compliance_issues": set(),
            "vulnerable_algorithms": set()
        }
        for item in items:
            severity = item["pqc_recommendation"].split(";")[0].replace("Severity: ", "").strip() if "Severity" in item["pqc_recommendation"] else "Low"
            if severity == "Unknown":
                self.logger.warning(f"Unknown severity for item {item['id']}: pqc_recommendation='{item['pqc_recommendation']}', algorithms={item.get('algorithms', [])}")
                severity = "Medium"
            dashboard["severity_counts"][severity] += 1
            for violation in item.get("policy_violations", []):
                dashboard["compliance_issues"].update(violation["compliance"].split(", "))
            for algo in item.get("algorithms", []):
                if is_quantum_vulnerable(algo["base"], algo["bits"]):
                    dashboard["vulnerable_algorithms"].add(algo["full"])
        
        with open(csv_path, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["Metric", "Value"])
            writer.writerow(["Total Items Scanned", dashboard["total_items"]])
            writer.writerow(["High Severity Issues", dashboard["severity_counts"]["High"]])
            writer.writerow(["Medium Severity Issues", dashboard["severity_counts"]["Medium"]])
            writer.writerow(["Low Severity Issues", dashboard["severity_counts"]["Low"]])
            writer.writerow(["Unknown Severity Issues", dashboard["severity_counts"]["Unknown"]])
            writer.writerow(["Compliance Issues", ", ".join(dashboard["compliance_issues"])])
            writer.writerow(["Vulnerable Algorithms", ", ".join(dashboard["vulnerable_algorithms"])])
        
        # Text-Based Dashboard
        print("\n=== Cryptographic Posture Dashboard ===")
        print(f"Target: {target}")
        print(f"Scan Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Total Items Scanned: {dashboard['total_items']}")
        print(f"Severity Distribution: High={dashboard['severity_counts']['High']}, Medium={dashboard['severity_counts']['Medium']}, Low={dashboard['severity_counts']['Low']}, Unknown={dashboard['severity_counts']['Unknown']}")
        print(f"Compliance Issues: {', '.join(dashboard['compliance_issues']) or 'None'}")
        print(f"Vulnerable Algorithms: {', '.join(dashboard['vulnerable_algorithms']) or 'None'}")
        print("======================================")
        
        # PDF Report
        pdf_path = os.path.join(self.output_dir, f"{safe_target}_report.pdf")
        doc = SimpleDocTemplate(pdf_path, pagesize=A3, leftMargin=36, rightMargin=36, topMargin=36, bottomMargin=36)
        self.logger.info(f"Creating PDF with page size A3 (842x1190 points)")
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
            spaceAfter=4,
            spaceBefore=4
        )
        
        def safe_str(value):
            return str(value) if value is not None else "None"
        
        story = []
        
        # Title
        story.append(Paragraph(f"Q-SecureScan Report for {target}", styles["Title"]))
        story.append(Paragraph(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles["Normal"]))
        story.append(Spacer(1, 12))
        
        # Summary
        story.append(Paragraph("Summary", styles["Heading2"]))
        story.append(Paragraph(f"Total Items Scanned: {dashboard['total_items']}", cell_style))
        story.append(Paragraph(f"High Severity: {dashboard['severity_counts']['High']}", cell_style))
        story.append(Paragraph(f"Medium Severity: {dashboard['severity_counts']['Medium']}", cell_style))
        story.append(Paragraph(f"Low Severity: {dashboard['severity_counts']['Low']}", cell_style))
        story.append(Paragraph(f"Unknown Severity: {dashboard['severity_counts']['Unknown']}", cell_style))
        story.append(Paragraph(f"Compliance Issues: {', '.join(dashboard['compliance_issues']) or 'None'}", cell_style))
        story.append(Spacer(1, 12))
        
        # Scanned Items Table with Dynamic Column Widths
        story.append(Paragraph("Scanned Items", styles["Heading2"]))
        table_data = [
            [
                Paragraph("Item ID", styles['Heading3']),
                Paragraph("Type", styles['Heading3']),
                Paragraph("Protocol/Service", styles['Heading3']),
                Paragraph("Heuristics", styles['Heading3']),
                Paragraph("Encryption Markers", styles['Heading3']),
                Paragraph("Algorithms", styles['Heading3']),
                Paragraph("Severity", styles['Heading3']),
                Paragraph("Policy Violations", styles['Heading3']),
                Paragraph("PQC Recommendation", styles['Heading3']),
                Paragraph("Remediation Guidance", styles['Heading3'])
            ]
        ]
        
        # Calculate dynamic column widths based on content
        col_widths = [80, 50, 80, 100, 80, 100, 60, 100, 100, 100]
        max_content_lengths = [0] * 10
        for item in items:
            protocol_service = (
                item["analysis"].get("protocol", item["analysis"].get("service", "N/A"))
                if item["type"] in ["protocol", "port"]
                else item["analysis"].get("extension", "N/A")
            )
            algorithms = item.get("algorithms", [])
            algo_str = ", ".join(a['full'] for a in algorithms) if algorithms else "None"
            heuristics = safe_str(item["analysis"].get("heuristics", "N/A"))
            if item.get("is_anomaly"):
                heuristics += f"; Anomaly: {safe_str(item.get('anomaly_details'))}"
            severity = item["pqc_recommendation"].split(";")[0].replace("Severity: ", "").strip() if "Severity" in item["pqc_recommendation"] else "Low"
            violations = "; ".join(v["details"] for v in item.get("policy_violations", [])) or "None"
            row = [
                safe_str(item["id"]),
                safe_str(item["type"]),
                safe_str(protocol_service),
                safe_str(heuristics),
                safe_str(item["analysis"].get("encryption_markers", "None")),
                safe_str(algo_str),
                safe_str(severity),
                safe_str(violations),
                safe_str(item["pqc_recommendation"]),
                safe_str(item.get("remediation_guidance", "None"))
            ]
            table_data.append([Paragraph(cell, cell_style) for cell in row])
            # Update max content lengths
            for i, cell in enumerate(row):
                max_content_lengths[i] = max(max_content_lengths[i], len(cell))
        
        # Adjust column widths proportionally to content length
        page_width = A3[0] - 72  # A3 width (842) minus margins (36 + 36)
        total_content_length = sum(max_content_lengths)
        if total_content_length > 0:
            col_widths = [max(50, (length / total_content_length) * page_width) for length in max_content_lengths]
            total_width = sum(col_widths)
            if total_width > page_width:
                scale = page_width / total_width
                col_widths = [w * scale for w in col_widths]
        
        # Split table if too many rows
        max_rows_per_page = 60  # Increased for A3 to accommodate more rows
        table_chunks = [table_data[i:i + max_rows_per_page] for i in range(0, len(table_data), max_rows_per_page)]
        for chunk in table_chunks:
            table = Table(chunk, colWidths=col_widths, repeatRows=1)
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
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.beige, colors.white]),
            ]))
            story.append(KeepTogether(table))
            story.append(Spacer(1, 12))
        
        # Skipped Items
        story.append(Paragraph("Skipped Items", styles["Heading2"]))
        if skipped_items:
            for item in skipped_items:
                story.append(Paragraph(f"Item: {safe_str(item)}", cell_style))
                story.append(Spacer(1, 6))
        else:
            story.append(Paragraph("None", cell_style))
            story.append(Spacer(1, 6))
        
        doc.build(story)
        self.logger.info(f"Reports saved: {json_path}, {scap_path}, {csv_path}, {pdf_path}")