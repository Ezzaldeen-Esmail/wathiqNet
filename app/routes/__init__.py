from app.routes.auth import auth_bp
from app.routes.dashboard import dashboard_bp
from app.routes.alerts import alerts_bp
from app.routes.devices import devices_bp
from app.routes.logs import logs_bp
from app.routes.reports import reports_bp
from app.routes.admin import admin_bp
from app.routes.api import api_bp

__all__ = [
    'auth_bp', 'dashboard_bp', 'alerts_bp', 'devices_bp',
    'logs_bp', 'reports_bp', 'admin_bp', 'api_bp'
]
