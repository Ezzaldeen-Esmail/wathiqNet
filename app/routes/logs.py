from flask import Blueprint, render_template, request, jsonify, Response
from flask_login import login_required
from app import db
from app.models.log_entry import LogEntry
from datetime import datetime, timedelta
import csv
import io

logs_bp = Blueprint('logs', __name__)

@logs_bp.route('/logs')
@login_required
def index():
    """Daily logs page with filtering"""
    today = datetime.utcnow().date()
    return render_template('logs.html', today=today)

@logs_bp.route('/api/logs')
@login_required
def api_logs():
    """API endpoint for logs with filtering"""
    # Get filter parameters
    source_ip = request.args.get('source_ip', '')
    dest_ip = request.args.get('destination_ip', '')
    protocol = request.args.get('protocol', '')
    action = request.args.get('action', '')
    start_time = request.args.get('start_time', '')
    end_time = request.args.get('end_time', '')
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 50, type=int)
    
    # Default to today's logs
    today = datetime.utcnow().date()
    today_start = datetime.combine(today, datetime.min.time())
    today_end = datetime.combine(today, datetime.max.time())
    
    # Build query
    query = LogEntry.query.filter(
        LogEntry.timestamp >= today_start,
        LogEntry.timestamp <= today_end
    )
    
    if source_ip:
        query = query.filter(LogEntry.source_ip.ilike(f'%{source_ip}%'))
    if dest_ip:
        query = query.filter(LogEntry.destination_ip.ilike(f'%{dest_ip}%'))
    if protocol:
        query = query.filter(LogEntry.protocol == protocol)
    if action:
        query = query.filter(LogEntry.action == action)
    if start_time:
        try:
            start_dt = datetime.strptime(f"{today} {start_time}", '%Y-%m-%d %H:%M')
            query = query.filter(LogEntry.timestamp >= start_dt)
        except ValueError:
            pass
    if end_time:
        try:
            end_dt = datetime.strptime(f"{today} {end_time}", '%Y-%m-%d %H:%M')
            query = query.filter(LogEntry.timestamp <= end_dt)
        except ValueError:
            pass
    
    # Order and paginate
    query = query.order_by(LogEntry.timestamp.desc())
    total = query.count()
    logs = query.offset((page - 1) * per_page).limit(per_page).all()
    
    return jsonify({
        'logs': [log.to_dict() for log in logs],
        'total': total,
        'page': page,
        'per_page': per_page,
        'pages': (total + per_page - 1) // per_page
    })

@logs_bp.route('/api/logs/export')
@login_required
def export_logs():
    """Export logs to CSV"""
    # Get filter parameters (same as api_logs)
    source_ip = request.args.get('source_ip', '')
    dest_ip = request.args.get('destination_ip', '')
    protocol = request.args.get('protocol', '')
    action = request.args.get('action', '')
    start_time = request.args.get('start_time', '')
    end_time = request.args.get('end_time', '')
    
    today = datetime.utcnow().date()
    today_start = datetime.combine(today, datetime.min.time())
    today_end = datetime.combine(today, datetime.max.time())
    
    query = LogEntry.query.filter(
        LogEntry.timestamp >= today_start,
        LogEntry.timestamp <= today_end
    )
    
    if source_ip:
        query = query.filter(LogEntry.source_ip.ilike(f'%{source_ip}%'))
    if dest_ip:
        query = query.filter(LogEntry.destination_ip.ilike(f'%{dest_ip}%'))
    if protocol:
        query = query.filter(LogEntry.protocol == protocol)
    if action:
        query = query.filter(LogEntry.action == action)
    if start_time:
        try:
            start_dt = datetime.strptime(f"{today} {start_time}", '%Y-%m-%d %H:%M')
            query = query.filter(LogEntry.timestamp >= start_dt)
        except ValueError:
            pass
    if end_time:
        try:
            end_dt = datetime.strptime(f"{today} {end_time}", '%Y-%m-%d %H:%M')
            query = query.filter(LogEntry.timestamp <= end_dt)
        except ValueError:
            pass
    
    logs = query.order_by(LogEntry.timestamp.desc()).all()
    
    # Generate CSV
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['Timestamp', 'Source IP', 'Source Port', 'Destination IP', 
                    'Destination Port', 'Protocol', 'Packet Size', 'Flags', 'Action'])
    
    for log in logs:
        writer.writerow([
            log.timestamp.isoformat() if log.timestamp else '',
            log.source_ip,
            log.source_port,
            log.destination_ip,
            log.destination_port,
            log.protocol,
            log.packet_size,
            log.flags,
            log.action
        ])
    
    output.seek(0)
    
    return Response(
        output.getvalue(),
        mimetype='text/csv',
        headers={'Content-Disposition': f'attachment;filename=logs_{today}.csv'}
    )

@logs_bp.route('/api/logs/recent')
@login_required
def recent_logs():
    """Get most recent logs for real-time updates"""
    limit = request.args.get('limit', 20, type=int)
    logs = LogEntry.query.order_by(LogEntry.timestamp.desc()).limit(limit).all()
    return jsonify([log.to_dict() for log in logs])
