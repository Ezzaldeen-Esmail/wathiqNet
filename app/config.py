import os
from datetime import timedelta

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'wathiqnet-secret-key-change-in-production'
    # Use SQLite for development, set DATABASE_URL for PostgreSQL in production
    basedir = os.path.abspath(os.path.dirname(__file__))
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or f'sqlite:///{os.path.join(basedir, "..", "data", "wathiqnet.db")}'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Session config
    PERMANENT_SESSION_LIFETIME = timedelta(hours=24)
    
    # Upload config
    UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data', 'uploads')
    REPORTS_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data', 'reports')
    BACKUPS_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data', 'backups')
    MAX_CONTENT_LENGTH = 50 * 1024 * 1024  # 50MB max upload
    
    # Detection thresholds
    TRAFFIC_SPIKE_THRESHOLD = 100  # packets per second
    FAILED_CONNECTION_THRESHOLD = 10  # failed attempts
    PORT_SCAN_THRESHOLD = 20  # unique ports in short time
    
    # Suspicious IPs (example list)
    SUSPICIOUS_IPS = [
        '185.220.101.0/24',  # Known Tor exit nodes
        '45.33.32.156',  # Scanners
        '198.51.100.0/24',  # Test range
    ]
    
    # Device timeout (seconds)
    DEVICE_TIMEOUT = 300  # 5 minutes without activity = disconnected
