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
    for folder in [app.config['UPLOAD_FOLDER'], 
                   app.config['REPORTS_FOLDER'],
                   app.config['BACKUPS_FOLDER']]:
        os.makedirs(folder, exist_ok=True)
    
    # Register blueprints
    from app.routes.auth import auth_bp
    from app.routes.dashboard import dashboard_bp
    from app.routes.alerts import alerts_bp
    from app.routes.devices import devices_bp
    from app.routes.logs import logs_bp
    from app.routes.reports import reports_bp
    from app.routes.admin import admin_bp
    from app.routes.api import api_bp
    
    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(alerts_bp)
    app.register_blueprint(devices_bp)
    app.register_blueprint(logs_bp)
    app.register_blueprint(reports_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(api_bp, url_prefix='/api')
    
    # Create database tables
    with app.app_context():
        db.create_all()
        # Create default admin user if not exists
        from app.models.user import User
        if not User.query.filter_by(username='admin').first():
            admin = User(
                username='admin',
                email='admin@nids.local',
                role='admin'
            )
            admin.set_password('admin123')
            db.session.add(admin)
            db.session.commit()
    
    return app
