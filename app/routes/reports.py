from flask import Blueprint, render_template, send_file, flash, redirect, url_for
from flask_login import login_required
from app import db
from app.models.alert import Alert
from app.models.log_entry import LogEntry
from datetime import datetime, timedelta
from sqlalchemy import func
import os
from app.config import Config

reports_bp = Blueprint('reports', __name__)

@reports_bp.route('/reports')
@login_required
def index():
    """List available reports"""
    # Get report files from reports folder
    reports_folder = Config.REPORTS_FOLDER
    reports = []
    
    if os.path.exists(reports_folder):
        for filename in os.listdir(reports_folder):
            if filename.endswith('.pdf'):
                filepath = os.path.join(reports_folder, filename)
                stat = os.stat(filepath)
                reports.append({
                    'filename': filename,
                    'created': datetime.fromtimestamp(stat.st_ctime),
                    'size': stat.st_size
                })
    
    reports.sort(key=lambda x: x['created'], reverse=True)
    
    # Get weekly statistics for preview
    week_ago = datetime.utcnow() - timedelta(days=7)
    
    weekly_alerts = Alert.query.filter(Alert.timestamp >= week_ago).count()
    weekly_logs = LogEntry.query.filter(LogEntry.timestamp >= week_ago).count()
    
    severity_counts = db.session.query(
        Alert.severity, func.count(Alert.id)
    ).filter(Alert.timestamp >= week_ago).group_by(Alert.severity).all()
    
    return render_template('reports.html',
                         reports=reports,
                         weekly_alerts=weekly_alerts,
                         weekly_logs=weekly_logs,
                         severity_counts=dict(severity_counts))

@reports_bp.route('/reports/generate', methods=['POST'])
@login_required
def generate():
    """Generate a new weekly report"""
    from app.utils.report_generator import generate_weekly_report
    
    try:
        filename = generate_weekly_report()
        flash(f'Report generated successfully: {filename}', 'success')
    except Exception as e:
        flash(f'Error generating report: {str(e)}', 'danger')
    
    return redirect(url_for('reports.index'))

@reports_bp.route('/reports/download/<filename>')
@login_required
def download(filename):
    """Download a report file"""
    filepath = os.path.join(Config.REPORTS_FOLDER, filename)
    
    if os.path.exists(filepath):
        return send_file(filepath, as_attachment=True)
    
    flash('Report not found.', 'danger')
    return redirect(url_for('reports.index'))
