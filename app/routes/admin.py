from flask import Blueprint, render_template, request, jsonify, flash, redirect, url_for
from flask_login import login_required, current_user
from functools import wraps
from app import db
from app.models.user import User
from app.models.alert import DetectionRule
from app.models.log_entry import LogEntry

admin_bp = Blueprint('admin', __name__, url_prefix='/admin')



def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin():
            flash('Admin access required.', 'danger')
            return redirect(url_for('dashboard.index'))
        return f(*args, **kwargs)
    return decorated_function



@admin_bp.route('/')
@login_required
@admin_required

def index():
    """Admin dashboard"""
    users = User.query.all()
    rules = DetectionRule.query.all()
    total_logs = LogEntry.query.count()
    
    return render_template('admin/index.html',
                         users=users,
                         rules=rules,
                         total_logs=total_logs)





# User Management
@admin_bp.route('/users')
@login_required
@admin_required
def users():
    users = User.query.all()
    return render_template('admin/users.html', users=users)





@admin_bp.route('/users/add', methods=['POST'])
@login_required
@admin_required
def add_user():
    username = request.form.get('username')
    email = request.form.get('email')
    password = request.form.get('password')
    role = request.form.get('role', 'viewer')
    
    if User.query.filter_by(username=username).first():
        flash('Username already exists.', 'danger')
        return redirect(url_for('admin.users'))
    
    user = User(username=username, email=email, role=role)
    user.set_password(password)
    db.session.add(user)
    db.session.commit()
    
    flash(f'User {username} created successfully.', 'success')
    return redirect(url_for('admin.users'))

@admin_bp.route('/users/<int:user_id>/toggle', methods=['POST'])
@login_required
@admin_required
def toggle_user(user_id):
    user = User.query.get_or_404(user_id)
    if user.id == current_user.id:
        flash('Cannot deactivate your own account.', 'danger')
    else:
        user.is_active = not user.is_active
        db.session.commit()
        status = 'activated' if user.is_active else 'deactivated'
        flash(f'User {user.username} {status}.', 'success')
    
    return redirect(url_for('admin.users'))

@admin_bp.route('/users/<int:user_id>/delete', methods=['POST'])
@login_required
@admin_required
def delete_user(user_id):
    user = User.query.get_or_404(user_id)
    if user.id == current_user.id:
        flash('Cannot delete your own account.', 'danger')
    else:
        db.session.delete(user)
        db.session.commit()
        flash(f'User {user.username} deleted.', 'success')
    
    return redirect(url_for('admin.users'))

# Detection Rules Management
@admin_bp.route('/rules')
@login_required
@admin_required
def rules():
    rules = DetectionRule.query.all()
    return render_template('admin/rules.html', rules=rules)

@admin_bp.route('/rules/add', methods=['POST'])
@login_required
@admin_required
def add_rule():
    rule = DetectionRule(
        name=request.form.get('name'),
        rule_type=request.form.get('rule_type'),
        description=request.form.get('description'),
        severity=request.form.get('severity', 'medium'),
        threshold=int(request.form.get('threshold', 10)),
        time_window=int(request.form.get('time_window', 60)),
        enabled=True
    )
    db.session.add(rule)
    db.session.commit()
    
    flash(f'Rule "{rule.name}" created successfully.', 'success')
    return redirect(url_for('admin.rules'))

@admin_bp.route('/rules/<int:rule_id>/toggle', methods=['POST'])
@login_required
@admin_required
def toggle_rule(rule_id):
    rule = DetectionRule.query.get_or_404(rule_id)
    rule.enabled = not rule.enabled
    db.session.commit()
    
    status = 'enabled' if rule.enabled else 'disabled'
    flash(f'Rule "{rule.name}" {status}.', 'success')
    return redirect(url_for('admin.rules'))

@admin_bp.route('/rules/<int:rule_id>/delete', methods=['POST'])
@login_required
@admin_required
def delete_rule(rule_id):
    rule = DetectionRule.query.get_or_404(rule_id)
    db.session.delete(rule)
    db.session.commit()
    
    flash(f'Rule deleted.', 'success')
    return redirect(url_for('admin.rules'))

# Data Management
@admin_bp.route('/data')
@login_required
@admin_required
def data():
    """Data management page"""
    from app.config import Config
    import os
    
    # Get folder sizes
    upload_size = sum(
        os.path.getsize(os.path.join(Config.UPLOAD_FOLDER, f)) 
        for f in os.listdir(Config.UPLOAD_FOLDER) if os.path.isfile(os.path.join(Config.UPLOAD_FOLDER, f))
    ) if os.path.exists(Config.UPLOAD_FOLDER) else 0
    
    backup_files = []
    if os.path.exists(Config.BACKUPS_FOLDER):
        for f in os.listdir(Config.BACKUPS_FOLDER):
            filepath = os.path.join(Config.BACKUPS_FOLDER, f)
            if os.path.isfile(filepath):
                backup_files.append({
                    'filename': f,
                    'size': os.path.getsize(filepath),
                    'created': datetime.fromtimestamp(os.path.getctime(filepath))
                })
    
    total_logs = LogEntry.query.count()
    
    return render_template('admin/data.html',
                         upload_size=upload_size,
                         backup_files=backup_files,
                         total_logs=total_logs)

from datetime import datetime

@admin_bp.route('/upload', methods=['POST'])
@login_required
@admin_required
def upload_logs():
    """Upload log files"""
    from app.utils.log_parser import parse_log_file
    
    if 'file' not in request.files:
        flash('No file provided.', 'danger')
        return redirect(url_for('admin.data'))
    
    file = request.files['file']
    if file.filename == '':
        flash('No file selected.', 'danger')
        return redirect(url_for('admin.data'))
    
    try:
        count = parse_log_file(file)
        flash(f'Successfully imported {count} log entries.', 'success')
    except Exception as e:
        flash(f'Error parsing file: {str(e)}', 'danger')
    
    return redirect(url_for('admin.data'))
