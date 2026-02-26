"""
Admin routes for log watcher control
"""
from flask import Blueprint, render_template, request, jsonify, redirect, url_for, flash, current_app
from flask_login import login_required, current_user
from functools import wraps

watcher_bp = Blueprint('watcher', __name__, url_prefix='/admin/watcher')

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'admin':
            flash('Admin access required', 'danger')
            return redirect(url_for('dashboard.index'))
        return f(*args, **kwargs)
    return decorated_function

@watcher_bp.route('/')
@login_required
@admin_required
def index():
    """Log watcher control panel"""
    from app.utils.log_watcher import get_log_watcher
    
    watcher = get_log_watcher()
    status = watcher.get_status() if watcher else {'running': False, 'watch_paths': []}
    
    watch_folder = current_app.config.get('WATCH_FOLDER', '')
    
    return render_template('admin/watcher.html', 
                          status=status,
                          watch_folder=watch_folder)

@watcher_bp.route('/start', methods=['POST'])
@login_required
@admin_required
def start():
    """Start the log watcher"""
    from app.utils.log_watcher import get_log_watcher
    
    watcher = get_log_watcher()
    if watcher:
        watch_folder = current_app.config.get('WATCH_FOLDER')
        watcher.start([watch_folder])
        flash('Log watcher started successfully', 'success')
    else:
        flash('Log watcher not initialized', 'danger')
    
    return redirect(url_for('watcher.index'))

@watcher_bp.route('/stop', methods=['POST'])
@login_required
@admin_required
def stop():
    """Stop the log watcher"""
    from app.utils.log_watcher import get_log_watcher
    
    watcher = get_log_watcher()
    if watcher:
        watcher.stop()
        flash('Log watcher stopped', 'warning')
    
    return redirect(url_for('watcher.index'))

@watcher_bp.route('/status')
@login_required
@admin_required
def status():
    """Get watcher status as JSON"""
    from app.utils.log_watcher import get_log_watcher
    
    watcher = get_log_watcher()
    if watcher:
        return jsonify(watcher.get_status())
    return jsonify({'running': False, 'watch_paths': []})
