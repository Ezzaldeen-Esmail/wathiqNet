from flask import Blueprint, render_template, jsonify
from flask_login import login_required, current_user
from app import db
from app.models.log_entry import LogEntry, Device
from app.models.alert import Alert
from datetime import datetime, timedelta
from sqlalchemy import func

dashboard_bp = Blueprint('dashboard', __name__)

@dashboard_bp.route('/')
@login_required
def index():
    # Get statistics
    today = datetime.utcnow().date()
    week_ago = datetime.utcnow() - timedelta(days=7)
    
    # Alert counts by severity
    severity_counts = db.session.query(
        Alert.severity, func.count(Alert.id)
    ).filter(Alert.is_resolved == False).group_by(Alert.severity).all()
    
    severity_stats = {
        'critical': 0, 'high': 0, 'medium': 0, 'low': 0
    }
    for severity, count in severity_counts:
        severity_stats[severity] = count
    
    # Active devices count
    active_devices = Device.query.filter_by(is_active=True).count()
    total_devices = Device.query.count()
    
    # Today's logs count
    today_start = datetime.combine(today, datetime.min.time())
    today_logs = LogEntry.query.filter(LogEntry.timestamp >= today_start).count()
    
    # Recent alerts
    recent_alerts = Alert.query.order_by(Alert.timestamp.desc()).limit(10).all()
    
    # Traffic data for chart (last 24 hours, hourly)
    traffic_data = []
    for i in range(24):
        hour_start = datetime.utcnow().replace(minute=0, second=0, microsecond=0) - timedelta(hours=23-i)
        hour_end = hour_start + timedelta(hours=1)
        count = LogEntry.query.filter(
            LogEntry.timestamp >= hour_start,
            LogEntry.timestamp < hour_end
        ).count()
        traffic_data.append({
            'hour': hour_start.strftime('%H:%M'),
            'count': count
        })
    
    # Protocol distribution
    protocol_stats_raw = db.session.query(
        LogEntry.protocol, func.count(LogEntry.id)
    ).group_by(LogEntry.protocol).all()
    
    # Convert to list of dicts for JSON serialization
    protocol_stats = [{'protocol': p[0] or 'Unknown', 'count': p[1]} for p in protocol_stats_raw]
    
    return render_template('dashboard.html',
                         severity_stats=severity_stats,
                         active_devices=active_devices,
                         total_devices=total_devices,
                         today_logs=today_logs,
                         recent_alerts=recent_alerts,
                         traffic_data=traffic_data,
                         protocol_stats=protocol_stats)

@dashboard_bp.route('/api/stats')
@login_required
def api_stats():
    """Real-time stats endpoint for dashboard updates"""
    today = datetime.utcnow().date()
    today_start = datetime.combine(today, datetime.min.time())
    
    # Alert counts
    severity_counts = db.session.query(
        Alert.severity, func.count(Alert.id)
    ).filter(Alert.is_resolved == False).group_by(Alert.severity).all()
    
    severity_stats = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
    for severity, count in severity_counts:
        severity_stats[severity] = count
    
    # Active devices
    active_devices = Device.query.filter_by(is_active=True).count()
    
    # Today's logs
    today_logs = LogEntry.query.filter(LogEntry.timestamp >= today_start).count()
    
    # Total unresolved alerts
    total_alerts = Alert.query.filter_by(is_resolved=False).count()
    
    return jsonify({
        'severity_stats': severity_stats,
        'active_devices': active_devices,
        'today_logs': today_logs,
        'total_alerts': total_alerts
    })
