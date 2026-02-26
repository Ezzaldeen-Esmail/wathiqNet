"""
Admin routes for network packet capture control
"""
from flask import Blueprint, render_template, request, jsonify, redirect, url_for, flash, current_app
from flask_login import login_required, current_user
from functools import wraps

capture_bp = Blueprint('capture', __name__, url_prefix='/admin/capture')

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'admin':
            flash('Admin access required', 'danger')
            return redirect(url_for('dashboard.index'))
        return f(*args, **kwargs)
    return decorated_function

@capture_bp.route('/')
@login_required
@admin_required
def index():
    """Packet capture control panel"""
    from app.utils.packet_capture import get_packet_capture
    
    capture = get_packet_capture()
    if capture:
        status = capture.get_status()
    else:
        status = {
            'running': False,
            'interface': None,
            'available': False,
            'interfaces': [],
            'stats': None
        }
    
    return render_template('admin/capture.html', status=status)

@capture_bp.route('/start', methods=['POST'])
@login_required
@admin_required
def start():
    """Start packet capture"""
    from app.utils.packet_capture import get_packet_capture
    
    interface = request.form.get('interface')
    filter_expr = request.form.get('filter') or None
    
    capture = get_packet_capture()
    if capture:
        success, message = capture.start(interface=interface, filter_expr=filter_expr)
        if success:
            flash(message, 'success')
        else:
            flash(message, 'danger')
    else:
        flash('Packet capture not initialized', 'danger')
    
    return redirect(url_for('capture.index'))

@capture_bp.route('/stop', methods=['POST'])
@login_required
@admin_required
def stop():
    """Stop packet capture"""
    from app.utils.packet_capture import get_packet_capture
    
    capture = get_packet_capture()
    if capture:
        success, message = capture.stop()
        if success:
            flash(message, 'warning')
        else:
            flash(message, 'danger')
    
    return redirect(url_for('capture.index'))

@capture_bp.route('/status')
@login_required
@admin_required
def status():
    """Get capture status as JSON"""
    from app.utils.packet_capture import get_packet_capture
    
    capture = get_packet_capture()
    if capture:
        return jsonify(capture.get_status())
    return jsonify({'running': False, 'available': False})

@capture_bp.route('/stats')
@login_required
@admin_required
def stats():
    """Get capture statistics as JSON"""
    from app.utils.packet_capture import get_packet_capture
    
    capture = get_packet_capture()
    if capture:
        return jsonify(capture.get_stats())
    return jsonify({'running': False, 'packet_count': 0})
