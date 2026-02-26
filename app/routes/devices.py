from flask import Blueprint, render_template, jsonify
from flask_login import login_required
from app import db
from app.models.log_entry import Device
from datetime import datetime, timedelta
from app.config import Config

devices_bp = Blueprint('devices', __name__)

@devices_bp.route('/devices')
@login_required
def index():
    # Update device status based on last_seen
    timeout = datetime.utcnow() - timedelta(seconds=Config.DEVICE_TIMEOUT)
    Device.query.filter(
        Device.last_seen < timeout,
        Device.is_active == True
    ).update({'is_active': False})
    db.session.commit()
    
    # Get all devices
    devices = Device.query.order_by(Device.is_active.desc(), Device.last_seen.desc()).all()
    
    active_count = Device.query.filter_by(is_active=True).count()
    inactive_count = Device.query.filter_by(is_active=False).count()
    
    return render_template('devices.html', 
                         devices=devices,
                         active_count=active_count,
                         inactive_count=inactive_count)

@devices_bp.route('/api/devices')
@login_required
def api_devices():
    """Real-time device status endpoint"""
    # Update device status
    timeout = datetime.utcnow() - timedelta(seconds=Config.DEVICE_TIMEOUT)
    Device.query.filter(
        Device.last_seen < timeout,
        Device.is_active == True
    ).update({'is_active': False})
    db.session.commit()
    
    devices = Device.query.order_by(Device.is_active.desc(), Device.last_seen.desc()).all()
    return jsonify([device.to_dict() for device in devices])

@devices_bp.route('/api/devices/stats')
@login_required
def api_device_stats():
    """Device statistics endpoint"""
    active = Device.query.filter_by(is_active=True).count()
    inactive = Device.query.filter_by(is_active=False).count()
    
    # Device types
    type_stats = db.session.query(
        Device.device_type, db.func.count(Device.id)
    ).group_by(Device.device_type).all()
    
    return jsonify({
        'active': active,
        'inactive': inactive,
        'total': active + inactive,
        'by_type': {t: c for t, c in type_stats}
    })
