from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image
from reportlab.graphics.shapes import Drawing
from reportlab.graphics.charts.piecharts import Pie
from reportlab.graphics.charts.barcharts import VerticalBarChart
from datetime import datetime, timedelta
from app import db
from app.models.alert import Alert
from app.models.log_entry import LogEntry
from app.config import Config
from sqlalchemy import func
import os

def generate_weekly_report():
    """Generate weekly PDF report"""
    # Date range
    end_date = datetime.utcnow()
    start_date = end_date - timedelta(days=7)
    
    # Report filename
    filename = f"wathiqnet_report_{start_date.strftime('%Y%m%d')}_{end_date.strftime('%Y%m%d')}.pdf"
    filepath = os.path.join(Config.REPORTS_FOLDER, filename)
    
    # Create PDF
    doc = SimpleDocTemplate(filepath, pagesize=A4)
    styles = getSampleStyleSheet()
    story = []
    
    # Title
    title_style = ParagraphStyle(
        'Title',
        parent=styles['Heading1'],
        fontSize=24,
        spaceAfter=30,
        alignment=1  # Center
    )
    
    story.append(Paragraph("Network Intrusion Detection System", title_style))
    story.append(Paragraph("Weekly Security Report", styles['Heading2']))
    story.append(Paragraph(f"Period: {start_date.strftime('%Y-%m-%d')} to {end_date.strftime('%Y-%m-%d')}", styles['Normal']))
    story.append(Spacer(1, 20))

  
    
    # Executive Summary
    story.append(Paragraph("Executive Summary", styles['Heading2']))
    
    # Get statistics
    total_alerts = Alert.query.filter(
        Alert.timestamp >= start_date,
        Alert.timestamp <= end_date
    ).count()
    
    critical_alerts = Alert.query.filter(
        Alert.timestamp >= start_date,
        Alert.timestamp <= end_date,
        Alert.severity == 'critical'
    ).count()
    
    resolved_alerts = Alert.query.filter(
        Alert.timestamp >= start_date,
        Alert.timestamp <= end_date,
        Alert.is_resolved == True
    ).count()
    
    total_logs = LogEntry.query.filter(
        LogEntry.timestamp >= start_date,
        LogEntry.timestamp <= end_date
    ).count()
    
    summary_text = f"""
    During this reporting period, the WathiqNet system analyzed {total_logs:,} network log entries 
    and generated {total_alerts} security alerts. {critical_alerts} alerts were classified as critical, 
    requiring immediate attention. {resolved_alerts} alerts have been resolved.
    """
    story.append(Paragraph(summary_text, styles['Normal']))
    story.append(Spacer(1, 20))
    
    # Severity Distribution
    story.append(Paragraph("Alert Severity Distribution", styles['Heading2']))
    
    severity_counts = db.session.query(
        Alert.severity, func.count(Alert.id)
    ).filter(
        Alert.timestamp >= start_date,
        Alert.timestamp <= end_date
    ).group_by(Alert.severity).all()
    
    severity_data = [['Severity', 'Count']]
    for severity, count in severity_counts:
        severity_data.append([severity.capitalize(), str(count)])
    
    if len(severity_data) > 1:
        severity_table = Table(severity_data, colWidths=[2*inch, 1*inch])
        severity_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        story.append(severity_table)
    story.append(Spacer(1, 20))
    
    # Alert Types
    story.append(Paragraph("Incidents by Type", styles['Heading2']))
    
    type_counts = db.session.query(
        Alert.alert_type, func.count(Alert.id)
    ).filter(
        Alert.timestamp >= start_date,
        Alert.timestamp <= end_date
    ).group_by(Alert.alert_type).all()
    
    type_data = [['Alert Type', 'Count']]
    for alert_type, count in type_counts:
        type_data.append([alert_type.replace('_', ' ').title(), str(count)])
    
    if len(type_data) > 1:
        type_table = Table(type_data, colWidths=[3*inch, 1*inch])
        type_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.darkblue),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.lightblue),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        story.append(type_table)
    story.append(Spacer(1, 20))
    
    # Top Suspicious Sources
    story.append(Paragraph("Top Sources of Suspicious Traffic", styles['Heading2']))
    
    top_sources = db.session.query(
        Alert.source_ip, func.count(Alert.id).label('count')
    ).filter(
        Alert.timestamp >= start_date,
        Alert.timestamp <= end_date,
        Alert.source_ip != None
    ).group_by(Alert.source_ip).order_by(func.count(Alert.id).desc()).limit(10).all()
    
    source_data = [['Source IP', 'Alert Count']]
    for ip, count in top_sources:
        source_data.append([ip or 'Unknown', str(count)])
    
    if len(source_data) > 1:
        source_table = Table(source_data, colWidths=[3*inch, 1.5*inch])
        source_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.darkred),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.mistyrose),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        story.append(source_table)
    story.append(Spacer(1, 20))
    
    # Recommendations
    story.append(Paragraph("Security Recommendations", styles['Heading2']))
    
    recommendations = []
    
    if critical_alerts > 0:
        recommendations.append(Paragraph(
            f"• <b>Critical:</b> {critical_alerts} critical alerts detected. Review and remediate immediately.",
            styles['Normal']
        ))
    
    brute_force_count = Alert.query.filter(
        Alert.timestamp >= start_date,
        Alert.alert_type == 'brute_force'
    ).count()
    if brute_force_count > 0:
        recommendations.append(Paragraph(
            f"• <b>Brute Force:</b> {brute_force_count} brute-force attempts detected. Consider implementing rate limiting and account lockout policies.",
            styles['Normal']
        ))
    
    port_scan_count = Alert.query.filter(
        Alert.timestamp >= start_date,
        Alert.alert_type == 'port_scan'
    ).count()
    if port_scan_count > 0:
        recommendations.append(Paragraph(
            f"• <b>Port Scanning:</b> {port_scan_count} port scan activities detected. Review firewall rules and consider blocking suspicious IPs.",
            styles['Normal']
        ))
    
    if not recommendations:
        recommendations.append(Paragraph("• No critical issues detected during this period. Continue monitoring.", styles['Normal']))
    
    for rec in recommendations:
        story.append(rec)
        story.append(Spacer(1, 5))
    
    # Footer
    story.append(Spacer(1, 40))
    story.append(Paragraph(
        f"Report generated on {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC",
        ParagraphStyle('Footer', parent=styles['Normal'], fontSize=8, textColor=colors.grey)
    ))
    
    # Build PDF
    doc.build(story)
    
    return filename
