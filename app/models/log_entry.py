from app import db
from datetime import datetime

class LogEntry(db.Model):
    __tablename__ = 'log_entries'
    
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, index=True)
    source_ip = db.Column(db.String(45), nullable=False, index=True)
    destination_ip = db.Column(db.String(45), nullable=False, index=True)
    source_port = db.Column(db.Integer)
    destination_port = db.Column(db.Integer)
    protocol = db.Column(db.String(20), nullable=False)
    packet_size = db.Column(db.Integer, nullable=False)
    flags = db.Column(db.String(50))  # TCP flags like SYN, ACK, FIN
    action = db.Column(db.String(20), default='allow')  # allow, deny, drop
    device_id = db.Column(db.String(100))
    raw_data = db.Column(db.Text)  # Original log line
    processed = db.Column(db.Boolean, default=False)
    
    def to_dict(self):
        return {
            'id': self.id,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            'source_ip': self.source_ip,
            'destination_ip': self.destination_ip,
            'source_port': self.source_port,
            'destination_port': self.destination_port,
            'protocol': self.protocol,
            'packet_size': self.packet_size,
            'flags': self.flags,
            'action': self.action,
            'device_id': self.device_id
        }
    
    def __repr__(self):
        return f'<LogEntry {self.id}: {self.source_ip} -> {self.destination_ip}>'


class Device(db.Model):
    __tablename__ = 'devices'
    
    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(45), unique=True, nullable=False)
    mac_address = db.Column(db.String(17))
    hostname = db.Column(db.String(255))
    device_type = db.Column(db.String(50), default='unknown')  # router, firewall, workstation, server
    first_seen = db.Column(db.DateTime, default=datetime.utcnow)
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)
    total_packets = db.Column(db.Integer, default=0)
    total_bytes = db.Column(db.Integer, default=0)
    
    def to_dict(self):
        return {
            'id': self.id,
            'ip_address': self.ip_address,
            'mac_address': self.mac_address,
            'hostname': self.hostname,
            'device_type': self.device_type,
            'first_seen': self.first_seen.isoformat() if self.first_seen else None,
            'last_seen': self.last_seen.isoformat() if self.last_seen else None,
            'is_active': self.is_active,
            'total_packets': self.total_packets,
            'total_bytes': self.total_bytes
        }
    
    def __repr__(self):
        return f'<Device {self.ip_address}>'
