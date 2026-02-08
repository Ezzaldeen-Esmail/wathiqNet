import csv
import json
from datetime import datetime
from io import StringIO
from app import db
from app.models.log_entry import LogEntry, Device
from app.detection.engine import process_new_logs
from app.routes.api import emit_new_log, emit_device_update

def parse_log_file(file):
    """
    Parse uploaded log file (CSV or JSON) and store in database.
    Returns the number of entries processed.
    """
    filename = file.filename.lower()
    
    if filename.endswith('.csv'):
        return parse_csv(file)
    elif filename.endswith('.json'):
        return parse_json(file)
    else:
        raise ValueError("Unsupported file format. Use CSV or JSON.")

def parse_csv(file):
    """Parse CSV log file"""
    content = file.read().decode('utf-8')
    reader = csv.DictReader(StringIO(content))
    
    log_entries = []
    devices_updated = set()
    
    for row in reader:
        log_entry = create_log_entry(row)
        if log_entry:
            db.session.add(log_entry)
            log_entries.append(log_entry)
            
            # Update device tracking
            update_device(log_entry.source_ip, log_entry.packet_size)
            devices_updated.add(log_entry.source_ip)
    
    db.session.commit()
    
    # Process through detection engine
    if log_entries:
        process_new_logs(log_entries)
    
    return len(log_entries)

def parse_json(file):
    """Parse JSON log file"""
    content = file.read().decode('utf-8')
    data = json.loads(content)
    
    # Handle both array of logs and object with logs array
    if isinstance(data, dict) and 'logs' in data:
        logs = data['logs']
    elif isinstance(data, list):
        logs = data
    else:
        raise ValueError("Invalid JSON format. Expected array or object with 'logs' key.")
    
    log_entries = []
    
    for row in logs:
        log_entry = create_log_entry(row)
        if log_entry:
            db.session.add(log_entry)
            log_entries.append(log_entry)
            
            # Update device tracking
            update_device(log_entry.source_ip, log_entry.packet_size)
    
    db.session.commit()
    
    # Process through detection engine
    if log_entries:
        process_new_logs(log_entries)
    
    return len(log_entries)

def create_log_entry(row):
    """Create a LogEntry from a row of data"""
    try:
        # Parse timestamp
        timestamp_str = row.get('timestamp', row.get('time', ''))
        if timestamp_str:
            try:
                timestamp = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
            except:
                try:
                    timestamp = datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S')
                except:
                    timestamp = datetime.utcnow()
        else:
            timestamp = datetime.utcnow()
        
        # Required fields
        source_ip = row.get('source_ip', row.get('src_ip', row.get('src', '')))
        destination_ip = row.get('destination_ip', row.get('dst_ip', row.get('dst', '')))
        protocol = row.get('protocol', row.get('proto', 'TCP'))
        packet_size = int(row.get('packet_size', row.get('bytes', row.get('size', 0))))
        
        if not source_ip or not destination_ip:
            return None
        
        # Optional fields
        source_port = row.get('source_port', row.get('src_port'))
        destination_port = row.get('destination_port', row.get('dst_port'))
        flags = row.get('flags', row.get('tcp_flags', ''))
        action = row.get('action', 'allow')
        device_id = row.get('device_id', row.get('device', ''))
        
        log_entry = LogEntry(
            timestamp=timestamp,
            source_ip=source_ip,
            destination_ip=destination_ip,
            source_port=int(source_port) if source_port else None,
            destination_port=int(destination_port) if destination_port else None,
            protocol=protocol.upper(),
            packet_size=packet_size,
            flags=flags,
            action=action.lower() if action else 'allow',
            device_id=device_id,
            raw_data=json.dumps(row) if isinstance(row, dict) else str(row)
        )
        
        return log_entry
    
    except Exception as e:
        print(f"Error parsing log entry: {e}")
        return None

def update_device(ip_address, packet_size=0):
    """Update or create device record"""
    device = Device.query.filter_by(ip_address=ip_address).first()
    
    if device:
        device.last_seen = datetime.utcnow()
        device.is_active = True
        device.total_packets += 1
        device.total_bytes += packet_size
    else:
        device = Device(
            ip_address=ip_address,
            device_type='unknown',
            is_active=True,
            total_packets=1,
            total_bytes=packet_size
        )
        db.session.add(device)
    
    try:
        db.session.commit()
        emit_device_update(device)
    except:
        db.session.rollback()
    
    return device
