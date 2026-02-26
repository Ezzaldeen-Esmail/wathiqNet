from flask import Blueprint, render_template, request, jsonify, flash, redirect, url_for
from flask_login import login_required, current_user
from app import db
from app.models.alert import Alert
from datetime import datetime

alerts_bp = Blueprint('alerts', __name__)

@alerts_bp.route('/alerts')
@login_required
def index():
    # Get filter parameters
    severity = request.args.get('severity', '')
    alert_type = request.args.get('type', '')
    status = request.args.get('status', 'active')
    page = request.args.get('page', 1, type=int)
    
    # Build query
    query = Alert.query
    
    if severity:
        query = query.filter(Alert.severity == severity)
    if alert_type:
        query = query.filter(Alert.alert_type == alert_type)
    if status == 'active':
        query = query.filter(Alert.is_resolved == False)
    elif status == 'resolved':
        query = query.filter(Alert.is_resolved == True)
    
    # Order by timestamp descending
    query = query.order_by(Alert.timestamp.desc())
    
    # Paginate
    alerts = query.paginate(page=page, per_page=20, error_out=False)
    
    return render_template('alerts.html', 
                         alerts=alerts,
                         current_severity=severity,
                         current_type=alert_type,
                         current_status=status)

@alerts_bp.route('/alerts/<int:alert_id>')
@login_required
def detail(alert_id):
    alert = Alert.query.get_or_404(alert_id)
    return render_template('alert_detail.html', alert=alert)

@alerts_bp.route('/alerts/<int:alert_id>/resolve', methods=['POST'])
@login_required
def resolve(alert_id):
    alert = Alert.query.get_or_404(alert_id)
    alert.is_resolved = True
    alert.resolved_at = datetime.utcnow()
    alert.resolved_by = current_user.id
    db.session.commit()
    
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return jsonify({'success': True})
    
    flash('Alert marked as resolved.', 'success')
    return redirect(url_for('alerts.index'))

@alerts_bp.route('/alerts/<int:alert_id>/note', methods=['POST'])
@login_required
def add_note(alert_id):
    alert = Alert.query.get_or_404(alert_id)
    note = request.form.get('note', '')
    
    if alert.notes:
        alert.notes += f"\n\n[{datetime.utcnow().strftime('%Y-%m-%d %H:%M')}] {current_user.username}:\n{note}"
    else:
        alert.notes = f"[{datetime.utcnow().strftime('%Y-%m-%d %H:%M')}] {current_user.username}:\n{note}"
    
    db.session.commit()
    
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return jsonify({'success': True, 'notes': alert.notes})
    
    flash('Note added successfully.', 'success')
    return redirect(url_for('alerts.detail', alert_id=alert_id))

@alerts_bp.route('/api/alerts')
@login_required
def api_alerts():
    """API endpoint for real-time alert updates"""
    alerts = Alert.query.filter_by(is_resolved=False).order_by(Alert.timestamp.desc()).limit(50).all()
    return jsonify([alert.to_dict() for alert in alerts])
