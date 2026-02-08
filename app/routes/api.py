from flask import Blueprint, jsonify, request
from flask_login import login_required
from app import db, socketio
from app.models.log_entry import LogEntry, Device
from app.models.alert import Alert
from datetime import datetime

api_bp = Blueprint('api', __name__)

@api_bp.route('/health')
def health():
    """Health check endpoint"""
    return jsonify({'status': 'healthy', 'timestamp': datetime.utcnow().isoformat()})

@api_bp.route('/stats/realtime')
@login_required
def realtime_stats():
    """Real-time statistics for dashboard"""
    # Recent activity
    recent_logs = LogEntry.query.order_by(LogEntry.timestamp.desc()).limit(10).all()
    recent_alerts = Alert.query.filter_by(is_resolved=False).order_by(Alert.timestamp.desc()).limit(5).all()
    active_devices = Device.query.filter_by(is_active=True).count()
    
    return jsonify({
        'recent_logs': [log.to_dict() for log in recent_logs],
        'recent_alerts': [alert.to_dict() for alert in recent_alerts],
        'active_devices': active_devices,
        'timestamp': datetime.utcnow().isoformat()
    })

# WebSocket events
@socketio.on('connect')
def handle_connect():
    """Handle WebSocket connection"""
    pass

@socketio.on('disconnect')
def handle_disconnect():
    """Handle WebSocket disconnection"""
    pass

@socketio.on('request_update')
def handle_update_request():
    """Send current stats to client"""
    from sqlalchemy import func
    
    severity_counts = db.session.query(
        Alert.severity, func.count(Alert.id)
    ).filter(Alert.is_resolved == False).group_by(Alert.severity).all()
    
    active_devices = Device.query.filter_by(is_active=True).count()
    recent_logs = LogEntry.query.order_by(LogEntry.timestamp.desc()).limit(10).all()
    
    socketio.emit('stats_update', {
        'severity_counts': {s: c for s, c in severity_counts},
        'active_devices': active_devices,
        'recent_logs': [log.to_dict() for log in recent_logs]
    })

def emit_new_log(log_entry):
    """Emit new log entry to connected clients"""
    socketio.emit('new_log', log_entry.to_dict())

def emit_new_alert(alert):
    """Emit new alert to connected clients"""
    socketio.emit('new_alert', alert.to_dict())

def emit_device_update(device):
    """Emit device status update to clients"""
    socketio.emit('device_update', device.to_dict())
