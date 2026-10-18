"""
Report Generator Module
Generates PDF and HTML reports from scan results.
"""

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, A4
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from datetime import datetime
import json
import os
from typing import Dict, Any, List


class ReportGenerator:
    """Generate security scan reports in various formats."""
    
    @staticmethod
    def generate_report(scan_id: str, format_type: str = 'pdf') -> str:
        """
        Generate report for a scan.
        
        Args:
            scan_id: Scan identifier
            format_type: Report format (pdf, html, json)
            
        Returns:
            Path to generated report file
        """
        # Load scan results from history
        scan_data = ReportGenerator._load_scan_data(scan_id)
        
        if not scan_data:
            raise ValueError(f"Scan {scan_id} not found")
        
        if format_type == 'pdf':
            return ReportGenerator._generate_pdf(scan_data)
        elif format_type == 'html':
            return ReportGenerator._generate_html(scan_data)
        elif format_type == 'json':
            return ReportGenerator._generate_json(scan_data)
        else:
            raise ValueError(f"Unsupported format: {format_type}")
    
    @staticmethod
    def _load_scan_data(scan_id: str) -> Dict[str, Any]:
        """Load scan data from history file or active scans."""
        try:
            history_file = os.path.join('logs', 'scan_history.json')
            if os.path.exists(history_file):
                with open(history_file, 'r') as f:
                    history = json.load(f)
                    for scan in history:
                        if scan['scan_id'] == scan_id:
                            return scan
        except Exception:
            pass
            
        try:
            import app as app_mod
            if hasattr(app_mod, 'scanner'):
                status = app_mod.scanner.get_scan_status(scan_id)
                if status and status.get('scan_id') == scan_id and status.get('findings'):
                    return status
        except Exception:
            pass
        return None
    
    @staticmethod
    def _generate_pdf(scan_data: Dict[str, Any]) -> str:
        """Generate PDF report."""
        report_path = os.path.join('reports', f"scan_{scan_data['scan_id'][:8]}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf")
        os.makedirs('reports', exist_ok=True)
        
        doc = SimpleDocTemplate(report_path, pagesize=A4)
        elements = []
        styles = getSampleStyleSheet()
        
        # Custom styles
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=24,
            textColor=colors.HexColor('#1a237e'),
            spaceAfter=30,
            alignment=TA_CENTER
        )
        
        heading_style = ParagraphStyle(
            'CustomHeading',
            parent=styles['Heading2'],
            fontSize=16,
            textColor=colors.HexColor('#283593'),
            spaceAfter=12
        )
        
        # Title
        elements.append(Paragraph("Kavalu Labs Security Engine — Security Report", title_style))
        elements.append(Spacer(1, 0.2*inch))
        
        # Executive Summary
        elements.append(Paragraph("Executive Summary", heading_style))
        
        deployment = scan_data.get('deployment_info') or {}
        developer = scan_data.get('developer_info') or {}
        if not deployment or not developer:
            for f in scan_data.get('findings', []):
                if f.get('type') == 'deployment_infrastructure' and not deployment:
                    deployment = f.get('details', {})
                elif f.get('type') == 'developer_identity' and not developer:
                    developer = f.get('details', {})

        summary_data = [
            ['Target URL', scan_data.get('target_url', 'N/A')],
            ['Scan ID', scan_data['scan_id']],
            ['Assessment Engine', 'Kavalu Labs Security Engine'],
            ['Deployed Platform', str(deployment.get('platform', 'N/A'))],
            ['Server Location', str(deployment.get('location', deployment.get('server_location', 'N/A')))],
            ['Server IP', str(deployment.get('ip_address', deployment.get('server_ip', 'N/A')))],
            ['Target Developer', str(developer.get('developer_name', 'Not Disclosed'))],
            ['Target Organization', str(developer.get('organization', 'Not Disclosed'))],
            ['Start Time', scan_data.get('start_time', 'N/A')],
            ['Status', scan_data.get('status', 'N/A')],
        ]
        
        summary_table = Table(summary_data, colWidths=[2*inch, 4*inch])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#e8eaf6')),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('GRID', (0, 0), (-1, -1), 1, colors.grey),
            ('ROWBACKGROUNDS', (0, 0), (-1, -1), [colors.white, colors.HexColor('#f5f5f5')])
        ]))
        
        elements.append(summary_table)
        elements.append(Spacer(1, 0.2*inch))
        
        # Target Infrastructure & Developer Attribution Section
        elements.append(Paragraph("Target Infrastructure & Developer Attribution", heading_style))
        attr_table_data = [
            ['Deployed Platform', str(deployment.get('platform', 'Custom Web Server'))],
            ['Server Geolocation', str(deployment.get('location', deployment.get('server_location', 'Unknown')))],
            ['Server IP Address', str(deployment.get('ip_address', deployment.get('server_ip', 'Unknown')))],
            ['Reverse DNS / Host', str(deployment.get('reverse_dns', 'N/A'))],
            ['Web Server Header', str(deployment.get('server_header', 'N/A'))],
            ['Hosting Provider / ASN', f"{deployment.get('hosting_org', 'N/A')} ({deployment.get('asn', deployment.get('network_asn', 'N/A'))})"],
            ['Discovered Developer', str(developer.get('developer_name', 'Not Disclosed in Public Metadata'))],
            ['Attribution Confidence', f"{developer.get('confidence', 'N/A')} (Source: {developer.get('discovery_source', 'N/A')})"],
            ['Target Organization', str(developer.get('organization', 'N/A'))],
            ['Copyright Notice', str(developer.get('copyright', 'N/A'))],
        ]
        attr_table = Table(attr_table_data, colWidths=[2.2*inch, 3.8*inch])
        attr_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#ede7f6')),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#b39ddb')),
            ('ROWBACKGROUNDS', (0, 0), (-1, -1), [colors.white, colors.HexColor('#fafafa')])
        ]))
        elements.append(attr_table)
        elements.append(Spacer(1, 0.3*inch))
        
        # Risk Summary
        elements.append(Paragraph("Risk Summary", heading_style))
        
        stats = scan_data.get('stats', {})
        risk_data = [
            ['Critical', str(stats.get('critical', 0)), 'Immediate action required'],
            ['High', str(stats.get('high', 0)), 'Address as soon as possible'],
            ['Medium', str(stats.get('medium', 0)), 'Address in next release'],
            ['Low', str(stats.get('low', 0)), 'Address when convenient'],
            ['Info', str(stats.get('info', 0)), 'Informational findings'],
        ]
        
        risk_table = Table(risk_data, colWidths=[1.2*inch, 1*inch, 3.8*inch])
        risk_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.white),
            ('TEXTCOLOR', (0, 0), (0, 0), colors.HexColor('#d32f2f') if stats.get('critical', 0) > 0 else colors.black),
            ('TEXTCOLOR', (0, 1), (0, 1), colors.HexColor('#f57c00') if stats.get('high', 0) > 0 else colors.black),
            ('TEXTCOLOR', (0, 2), (0, 2), colors.HexColor('#fbc02d') if stats.get('medium', 0) > 0 else colors.black),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('GRID', (0, 0), (-1, -1), 1, colors.grey),
            ('ROWBACKGROUNDS', (0, 0), (-1, -1), [colors.white, colors.HexColor('#f5f5f5')]),
            ('BACKGROUND', (0, 0), (0, 0), colors.HexColor('#ffebee') if stats.get('critical', 0) > 0 else colors.white),
            ('BACKGROUND', (0, 1), (0, 1), colors.HexColor('#fff3e0') if stats.get('high', 0) > 0 else colors.white),
        ]))
        
        elements.append(risk_table)
        elements.append(Spacer(1, 0.3*inch))
        
        # Detailed Findings
        elements.append(PageBreak())
        elements.append(Paragraph("Detailed Findings", heading_style))
        elements.append(Spacer(1, 0.2*inch))
        
        findings = scan_data.get('findings', [])
        
        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
        sorted_findings = sorted(findings, key=lambda x: severity_order.get(x.get('severity', 'info'), 4))
        
        for i, finding in enumerate(sorted_findings[:50], 1):  # Limit to 50 findings
            severity = finding.get('severity', 'info')
            severity_colors = {
                'critical': colors.HexColor('#d32f2f'),
                'high': colors.HexColor('#f57c00'),
                'medium': colors.HexColor('#fbc02d'),
                'low': colors.HexColor('#689f38'),
                'info': colors.HexColor('#1976d2')
            }
            
            # Finding header
            finding_header = f"<b>{i}. [{severity.upper()}] {finding.get('title', 'Unknown')}</b>"
            elements.append(Paragraph(finding_header, styles['Heading3']))
            
            # Finding details
            finding_text = f"""
            <b>Type:</b> {finding.get('type', 'Unknown')}<br/>
            <b>Description:</b> {finding.get('description', 'No description')}<br/>
            """
            
            details = finding.get('details', {})
            if details:
                finding_text += "<b>Details:</b><br/>"
                for key, value in details.items():
                    if isinstance(value, (list, dict)):
                        value = json.dumps(value, indent=2)[:200]
                    finding_text += f"&nbsp;&nbsp;• {key}: {value}<br/>"
            
            if 'remediation' in finding:
                finding_text += f"<b>Remediation:</b> {finding['remediation']}<br/>"
            
            elements.append(Paragraph(finding_text, styles['Normal']))
            elements.append(Spacer(1, 0.2*inch))
        
        # Build PDF
        doc.build(elements)
        return report_path
    
    @staticmethod
    def _generate_html(scan_data: Dict[str, Any]) -> str:
        """Generate HTML report."""
        report_path = os.path.join('reports', f"scan_{scan_data['scan_id'][:8]}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html")
        os.makedirs('reports', exist_ok=True)
        
        stats = scan_data.get('stats', {})
        findings = scan_data.get('findings', [])
        
        deployment = scan_data.get('deployment_info') or {}
        developer = scan_data.get('developer_info') or {}
        if not deployment or not developer:
            for f in findings:
                if f.get('type') == 'deployment_infrastructure' and not deployment:
                    deployment = f.get('details', {})
                elif f.get('type') == 'developer_identity' and not developer:
                    developer = f.get('details', {})
        
        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
        sorted_findings = sorted(findings, key=lambda x: severity_order.get(x.get('severity', 'info'), 4))
        
        html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Scan Report - {scan_data.get('target_url', 'Unknown')}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
            line-height: 1.6; 
            color: #333;
            background: #f5f5f5;
        }}
        .container {{ max-width: 1200px; margin: 0 auto; padding: 20px; }}
        .header {{ 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
            color: white; 
            padding: 40px; 
            border-radius: 10px; 
            margin-bottom: 30px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }}
        .header h1 {{ font-size: 2.5em; margin-bottom: 10px; }}
        .summary-grid {{ 
            display: grid; 
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); 
            gap: 20px; 
            margin-bottom: 30px;
        }}
        .summary-card {{ 
            background: white; 
            padding: 25px; 
            border-radius: 10px; 
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            text-align: center;
        }}
        .summary-card.critical {{ border-top: 4px solid #d32f2f; }}
        .summary-card.high {{ border-top: 4px solid #f57c00; }}
        .summary-card.medium {{ border-top: 4px solid #fbc02d; }}
        .summary-card.low {{ border-top: 4px solid #689f38; }}
        .summary-card.info {{ border-top: 4px solid #1976d2; }}
        .count {{ font-size: 2.5em; font-weight: bold; margin: 10px 0; }}
        .critical .count {{ color: #d32f2f; }}
        .high .count {{ color: #f57c00; }}
        .medium .count {{ color: #fbc02d; }}
        .low .count {{ color: #689f38; }}
        .info .count {{ color: #1976d2; }}
        .findings-section {{ background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        .finding {{ 
            border-left: 4px solid #ddd; 
            padding: 20px; 
            margin-bottom: 20px; 
            background: #fafafa;
            border-radius: 0 5px 5px 0;
        }}
        .finding.critical {{ border-left-color: #d32f2f; background: #ffebee; }}
        .finding.high {{ border-left-color: #f57c00; background: #fff3e0; }}
        .finding.medium {{ border-left-color: #fbc02d; background: #fffde7; }}
        .finding.low {{ border-left-color: #689f38; background: #f1f8e9; }}
        .finding.info {{ border-left-color: #1976d2; background: #e3f2fd; }}
        .finding-header {{ 
            display: flex; 
            justify-content: space-between; 
            align-items: center; 
            margin-bottom: 10px;
        }}
        .finding-title {{ font-size: 1.2em; font-weight: bold; }}
        .severity-badge {{ 
            padding: 5px 15px; 
            border-radius: 20px; 
            color: white; 
            font-weight: bold;
            text-transform: uppercase;
            font-size: 0.8em;
        }}
        .severity-badge.critical {{ background: #d32f2f; }}
        .severity-badge.high {{ background: #f57c00; }}
        .severity-badge.medium {{ background: #fbc02d; color: #333; }}
        .severity-badge.low {{ background: #689f38; }}
        .severity-badge.info {{ background: #1976d2; }}
        .finding-description {{ margin: 10px 0; color: #555; }}
        .finding-details {{ 
            background: white; 
            padding: 15px; 
            border-radius: 5px; 
            margin-top: 10px;
            font-family: monospace;
            font-size: 0.9em;
        }}
        .remediation {{ 
            background: #e8f5e9; 
            padding: 15px; 
            border-radius: 5px; 
            margin-top: 10px;
            border-left: 3px solid #4caf50;
        }}
        .metadata {{ 
            display: grid; 
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); 
            gap: 15px; 
            margin-top: 30px;
            background: white;
            padding: 20px;
            border-radius: 10px;
        }}
        .metadata-item {{ display: flex; justify-content: space-between; }}
        .metadata-label {{ font-weight: bold; color: #666; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Kavalu Labs Security Engine — Security Report</h1>
            <p>Target: {scan_data.get('target_url', 'Unknown')}</p>
            <p>Assessment Engine: <strong>Kavalu Labs Security Engine</strong></p>
            <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </div>
        
        <div style="background: white; border: 1px solid #e0e0e0; border-left: 6px solid #283593; border-radius: 8px; padding: 20px; margin-bottom: 25px; box-shadow: 0 2px 4px rgba(0,0,0,0.06);">
            <h2 style="margin-top: 0; color: #283593; font-size: 18px; border-bottom: 1px solid #eee; padding-bottom: 8px; font-weight: 700;">Target Infrastructure & Developer Attribution</h2>
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 16px; margin-top: 14px;">
                <div>
                    <span style="font-size: 11px; text-transform: uppercase; color: #777; font-weight: bold; display: block;">DEPLOYED PLATFORM</span>
                    <strong style="color: #d32f2f; font-size: 16px;">{deployment.get('platform', 'Custom Web Server')}</strong>
                    <div style="font-size: 12px; color: #666; margin-top: 4px;">Server: {deployment.get('server_header', 'N/A')}</div>
                </div>
                <div>
                    <span style="font-size: 11px; text-transform: uppercase; color: #777; font-weight: bold; display: block;">HOSTING LOCATION & IP</span>
                    <strong style="color: #111; font-size: 15px;">{deployment.get('location', deployment.get('server_location', 'Unknown'))}</strong>
                    <div style="font-size: 12px; color: #666; margin-top: 4px;">IP: {deployment.get('ip_address', deployment.get('server_ip', 'Unknown'))}</div>
                </div>
                <div>
                    <span style="font-size: 11px; text-transform: uppercase; color: #777; font-weight: bold; display: block;">ATTRIBUTED DEVELOPER / AUTHOR</span>
                    <strong style="color: #2e7d32; font-size: 15px;">{developer.get('developer_name', 'Not Disclosed')}</strong>
                    <div style="font-size: 12px; color: #666; margin-top: 4px;">Source: {developer.get('discovery_source', 'Metadata')}</div>
                </div>
                <div>
                    <span style="font-size: 11px; text-transform: uppercase; color: #777; font-weight: bold; display: block;">ORGANIZATION & HOSTING</span>
                    <strong style="color: #111; font-size: 15px;">{developer.get('organization', 'Not Disclosed')}</strong>
                    <div style="font-size: 12px; color: #666; margin-top: 4px;">Provider: {deployment.get('hosting_org', 'N/A')}</div>
                </div>
            </div>
        </div>

        <div class="summary-grid">
            <div class="summary-card critical">
                <div class="label">Critical</div>
                <div class="count">{stats.get('critical', 0)}</div>
            </div>
            <div class="summary-card high">
                <div class="label">High</div>
                <div class="count">{stats.get('high', 0)}</div>
            </div>
            <div class="summary-card medium">
                <div class="label">Medium</div>
                <div class="count">{stats.get('medium', 0)}</div>
            </div>
            <div class="summary-card low">
                <div class="label">Low</div>
                <div class="count">{stats.get('low', 0)}</div>
            </div>
        </div>
        
        <div class="findings-section">
            <h2>Detailed Findings ({len(findings)} total)</h2>
"""
        
        for finding in sorted_findings:
            severity = finding.get('severity', 'info')
            html_content += f"""
            <div class="finding {severity}">
                <div class="finding-header">
                    <div class="finding-title">{finding.get('title', 'Unknown')}</div>
                    <span class="severity-badge {severity}">{severity.upper()}</span>
                </div>
                <div class="finding-description">{finding.get('description', 'No description')}</div>
                <div class="finding-details">
                    <strong>Type:</strong> {finding.get('type', 'Unknown')}<br>
"""
            
            details = finding.get('details', {})
            for key, value in details.items():
                if isinstance(value, (list, dict)):
                    value = json.dumps(value, indent=2)[:200]
                html_content += f"<strong>{key}:</strong> {value}<br>"
            
            html_content += "</div>"
            
            if 'remediation' in finding:
                html_content += f"""
                <div class="remediation">
                    <strong>Remediation:</strong> {finding['remediation']}
                </div>
"""
            
            html_content += "</div>"
        
        html_content += f"""
        </div>
        
        <div class="metadata">
            <div class="metadata-item">
                <span class="metadata-label">Assessment Engine:</span>
                <span>Kavalu Labs Security Engine</span>
            </div>
            <div class="metadata-item">
                <span class="metadata-label">Deployed Platform:</span>
                <span>{deployment.get('platform', 'Custom')}</span>
            </div>
            <div class="metadata-item">
                <span class="metadata-label">Server Location:</span>
                <span>{deployment.get('location', deployment.get('server_location', 'Unknown'))}</span>
            </div>
            <div class="metadata-item">
                <span class="metadata-label">Target Developer:</span>
                <span>{developer.get('developer_name', 'Not Disclosed')}</span>
            </div>
            <div class="metadata-item">
                <span class="metadata-label">Scan ID:</span>
                <span>{scan_data['scan_id']}</span>
            </div>
            <div class="metadata-item">
                <span class="metadata-label">Status:</span>
                <span>{scan_data.get('status', 'Unknown')}</span>
            </div>
            <div class="metadata-item">
                <span class="metadata-label">Start Time:</span>
                <span>{scan_data.get('start_time', 'N/A')}</span>
            </div>
            <div class="metadata-item">
                <span class="metadata-label">End Time:</span>
                <span>{scan_data.get('end_time', 'N/A')}</span>
            </div>
        </div>
    </div>
</body>
</html>
"""
        
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        return report_path
    
    @staticmethod
    def _generate_json(scan_data: Dict[str, Any]) -> str:
        """Generate JSON report."""
        report_path = os.path.join('reports', f"scan_{scan_data['scan_id'][:8]}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
        os.makedirs('reports', exist_ok=True)
        
        scan_data_copy = dict(scan_data)
        scan_data_copy['engine'] = 'Kavalu Labs Security Engine'
        scan_data_copy['deployment_info'] = scan_data.get('deployment_info') or {}
        scan_data_copy['developer_info'] = scan_data.get('developer_info') or {}
        with open(report_path, 'w') as f:
            json.dump(scan_data_copy, f, indent=2)
        
        return report_path
