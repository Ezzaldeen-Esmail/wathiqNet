from app import db
from datetime import datetime

class Alert(db.Model):
    __tablename__ = 'alerts'
    
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, index=True)
    alert_type = db.Column(db.String(50), nullable=False)  # traffic_spike, brute_force, suspicious_ip, port_scan, protocol_anomaly
    severity = db.Column(db.String(20), nullable=False)  # low, medium, high, critical
    source_ip = db.Column(db.String(45))
    destination_ip = db.Column(db.String(45))
    description = db.Column(db.Text, nullable=False)
    recommendation = db.Column(db.Text)
    is_resolved = db.Column(db.Boolean, default=False)
    resolved_at = db.Column(db.DateTime)
    resolved_by = db.Column(db.Integer, db.ForeignKey('users.id'))
    notes = db.Column(db.Text)
    related_log_ids = db.Column(db.Text)  # Comma-separated log IDs
    
    def to_dict(self):
        return {
            'id': self.id,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            'alert_type': self.alert_type,
            'severity': self.severity,
            'source_ip': self.source_ip,
            'destination_ip': self.destination_ip,
            'description': self.description,
            'recommendation': self.recommendation,
            'is_resolved': self.is_resolved,
            'resolved_at': self.resolved_at.isoformat() if self.resolved_at else None,
            'notes': self.notes
        }
    
    @staticmethod
    def get_severity_color(severity):
        colors = {
            'low': 'success',
            'medium': 'warning',
            'high': 'orange',
            'critical': 'danger'
        }
        return colors.get(severity, 'secondary')
    
    def __repr__(self):
        return f'<Alert {self.id}: {self.alert_type} ({self.severity})>'


class DetectionRule(db.Model):
    __tablename__ = 'detection_rules'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    rule_type = db.Column(db.String(50), nullable=False)  # traffic_spike, brute_force, suspicious_ip, port_scan, protocol_anomaly
    description = db.Column(db.Text)
    enabled = db.Column(db.Boolean, default=True)
    severity = db.Column(db.String(20), default='medium')
    threshold = db.Column(db.Integer)  # Rule-specific threshold
    time_window = db.Column(db.Integer, default=60)  # Time window in seconds
    parameters = db.Column(db.Text)  # JSON string for additional parameters
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'rule_type': self.rule_type,
            'description': self.description,
            'enabled': self.enabled,
            'severity': self.severity,
            'threshold': self.threshold,
            'time_window': self.time_window,
            'parameters': self.parameters
        }
    
    def __repr__(self):
        return f'<DetectionRule {self.name}>'
