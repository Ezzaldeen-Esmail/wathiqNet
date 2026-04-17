from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_socketio import SocketIO
from flask_wtf.csrf import CSRFProtect
from app.config import Config
import os

db = SQLAlchemy()
login_manager = LoginManager()
socketio = SocketIO()
csrf = CSRFProtect()

def create_app(config_class=Config):
    app = Flask(__name__, 
                template_folder='../templates',
                static_folder='../static')
    app.config.from_object(config_class)
    
    # Initialize extensions
    db.init_app(app)
    login_manager.init_app(app)
    socketio.init_app(app, cors_allowed_origins="*", async_mode='threading')
    csrf.init_app(app)
    
    # Login settings
    login_manager.login_view = 'auth.login'
    login_manager.login_message_category = 'warning'
    
    # Create upload folders
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    watch_folder = os.path.join(base_dir, 'data', 'watch')
    
    for folder in [app.config['UPLOAD_FOLDER'], 
                   app.config['REPORTS_FOLDER'],
                   app.config['BACKUPS_FOLDER'],
                   watch_folder]:
        os.makedirs(folder, exist_ok=True)
    
    # Store watch folder path in config
    app.config['WATCH_FOLDER'] = watch_folder
    
    # Register blueprints
    from app.routes.auth import auth_bp
    from app.routes.dashboard import dashboard_bp
    from app.routes.alerts import alerts_bp
    from app.routes.devices import devices_bp
    from app.routes.logs import logs_bp
    from app.routes.reports import reports_bp
    from app.routes.admin import admin_bp
    from app.routes.api import api_bp
    from app.routes.watcher import watcher_bp
    from app.routes.capture import capture_bp
    
    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(alerts_bp)
    app.register_blueprint(devices_bp)
    app.register_blueprint(logs_bp)
    app.register_blueprint(reports_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(api_bp, url_prefix='/api')
    app.register_blueprint(watcher_bp)
    app.register_blueprint(capture_bp)
    
    # Create database tables
    with app.app_context():
        db.create_all()
        # Create default admin user if not exists
        from app.models.user import User
        if not User.query.filter_by(username='admin').first():
            admin = User(
                username='admin',
                email='admin@wathiqnet.local',
                role='admin'
            )
            admin.set_password('admin123')
            db.session.add(admin)
            db.session.commit()
        
        # Create default detection rules if not exists
        from app.models.alert import DetectionRule
        if DetectionRule.query.count() == 0:
            default_rules = [
                DetectionRule(name='Brute Force Detection', rule_type='brute_force', 
                             description='Detect multiple failed login attempts', 
                             severity='high', threshold=10, time_window=60, enabled=True),
                DetectionRule(name='Port Scan Detection', rule_type='port_scan',
                             description='Detect port scanning activities',
                             severity='medium', threshold=20, time_window=60, enabled=True),
                DetectionRule(name='Traffic Spike Detection', rule_type='traffic_spike',
                             description='Detect unusual traffic volume',
                             severity='medium', threshold=100, time_window=60, enabled=True),
                DetectionRule(name='Suspicious IP Detection', rule_type='suspicious_ip',
                             description='Detect connections from known malicious IPs',
                             severity='critical', threshold=1, time_window=1, enabled=True),
            ]
            for rule in default_rules:
                db.session.add(rule)
            db.session.commit()
    
    return app

