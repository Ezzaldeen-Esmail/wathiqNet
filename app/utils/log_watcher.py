"""
Real-time Log File Watcher
Monitors log files for new entries and processes them through the detection engine.
"""
import os
import time
import threading
import csv
import json
from datetime import datetime
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

class LogFileHandler(FileSystemEventHandler):
    """Handler for log file changes"""
    
    def __init__(self, app, socketio, detection_engine):
        self.app = app
        self.socketio = socketio
        self.detection_engine = detection_engine
        self.file_positions = {}  # Track read position for each file
        self.lock = threading.Lock()
    
    def on_modified(self, event):
        """Called when a file is modified"""
        if event.is_directory:
            return
        
        # Only process CSV and JSON files
        if not event.src_path.endswith(('.csv', '.json', '.log')):
            return
        
        self._process_new_lines(event.src_path)
    
    def on_created(self, event):
        """Called when a new file is created"""
        if event.is_directory:
            return
        
        if event.src_path.endswith(('.csv', '.json', '.log')):
            self.file_positions[event.src_path] = 0
            self._process_new_lines(event.src_path)
    
    def _process_new_lines(self, filepath):
        """Read and process new lines from a log file"""
        with self.lock:
            try:
                # Get current position or start from beginning
                current_pos = self.file_positions.get(filepath, 0)
                
                with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                    f.seek(current_pos)
                    new_lines = f.readlines()
                    self.file_positions[filepath] = f.tell()
                
                if not new_lines:
                    return
                
                # Process new lines
                if filepath.endswith('.csv'):
                    self._process_csv_lines(new_lines, filepath)
                elif filepath.endswith('.json'):
                    self._process_json_lines(new_lines)
                elif filepath.endswith('.log'):
                    self._process_log_lines(new_lines)
                    
            except Exception as e:
                print(f"Error processing {filepath}: {e}")
    
    def _process_csv_lines(self, lines, filepath):
        """Process CSV log lines"""
        from app.models.log_entry import LogEntry, Device
        from app import db
        
        with self.app.app_context():
            processed_logs = []
            for line in lines:
                line = line.strip()
                if not line or line.startswith('timestamp'):  # Skip header
                    continue
                
                try:
                    # Parse CSV line
                    parts = line.split(',')
                    if len(parts) < 7:
                        continue
                    
                    log_entry = LogEntry(
                        timestamp=datetime.strptime(parts[0], '%Y-%m-%d %H:%M:%S') if parts[0] else datetime.utcnow(),
                        source_ip=parts[1] if len(parts) > 1 else None,
                        destination_ip=parts[2] if len(parts) > 2 else None,
                        source_port=int(parts[3]) if len(parts) > 3 and parts[3].isdigit() else None,
                        destination_port=int(parts[4]) if len(parts) > 4 and parts[4].isdigit() else None,
                        protocol=parts[5] if len(parts) > 5 else None,
                        packet_size=int(parts[6]) if len(parts) > 6 and parts[6].isdigit() else 0,
                        flags=parts[7] if len(parts) > 7 else None,
                        action=parts[8] if len(parts) > 8 else None,
                        device_id=parts[9] if len(parts) > 9 else None
                    )
                    
                    db.session.add(log_entry)
                    db.session.commit()
                    
                    # Update device status
                    self._update_device(log_entry)
                    
                    # Add to batch
                    processed_logs.append(log_entry)
                    
                    # Emit real-time log update (optional, but good for UI)
                    self.socketio.emit('new_log', log_entry.to_dict())
                    
                except Exception as e:
                    print(f"Error parsing CSV line: {e}")
                    continue
            
            # Run batch detection
            if processed_logs:
                from app.detection.engine import process_new_logs
                process_new_logs(processed_logs)
    
    def _process_json_lines(self, lines):
        """Process JSON log lines (one JSON object per line)"""
        from app.models.log_entry import LogEntry
        from app import db
        
        with self.app.app_context():
            processed_logs = []
            for line in lines:
                line = line.strip()
                if not line:
                    continue
                
                try:
                    data = json.loads(line)
                    
                    log_entry = LogEntry(
                        timestamp=datetime.fromisoformat(data.get('timestamp', datetime.utcnow().isoformat())),
                        source_ip=data.get('source_ip') or data.get('src_ip'),
                        destination_ip=data.get('destination_ip') or data.get('dst_ip'),
                        source_port=data.get('source_port') or data.get('src_port'),
                        destination_port=data.get('destination_port') or data.get('dst_port'),
                        protocol=data.get('protocol'),
                        packet_size=data.get('packet_size') or data.get('bytes') or 0,
                        flags=data.get('flags'),
                        action=data.get('action'),
                        device_id=data.get('device_id')
                    )
                    
                    db.session.add(log_entry)
                    db.session.commit()
                    
                    # Update device
                    self._update_device(log_entry)
                    
                    # Add to batch
                    processed_logs.append(log_entry)
                    
                    # Emit updates
                    self.socketio.emit('new_log', log_entry.to_dict())
                    
                except json.JSONDecodeError:
                    continue
                except Exception as e:
                    print(f"Error parsing JSON line: {e}")
                    continue
            
            # Run batch detection
            if processed_logs:
                from app.detection.engine import process_new_logs
                process_new_logs(processed_logs)
    
    def _process_log_lines(self, lines):
        """Process generic log lines (syslog format)"""
        from app.models.log_entry import LogEntry
        from app import db
        import re
        
        # Simple pattern for firewall/router logs
        ip_pattern = r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
        
        with self.app.app_context():
            processed_logs = []
            for line in lines:
                line = line.strip()
                if not line:
                    continue
                
                try:
                    # Extract IPs from log line
                    ips = re.findall(ip_pattern, line)
                    
                    log_entry = LogEntry(
                        timestamp=datetime.utcnow(),
                        source_ip=ips[0] if len(ips) > 0 else None,
                        destination_ip=ips[1] if len(ips) > 1 else None,
                        protocol='TCP' if 'TCP' in line.upper() else 'UDP' if 'UDP' in line.upper() else 'UNKNOWN',
                        action='deny' if any(x in line.lower() for x in ['deny', 'drop', 'block']) else 'allow',
                        raw_log=line[:500]  # Store raw log (truncated)
                    )
                    
                    db.session.add(log_entry)
                    db.session.commit()
                    
                    # Add to batch
                    processed_logs.append(log_entry)
                    
                    # Emit updates
                    self.socketio.emit('new_log', log_entry.to_dict())
                    
                except Exception as e:
                    print(f"Error parsing log line: {e}")
                    continue
            
            # Run batch detection
            if processed_logs:
                from app.detection.engine import process_new_logs
                process_new_logs(processed_logs)
    
    def _update_device(self, log_entry):
        """Update device status based on log entry"""
        from app.models.log_entry import Device
        from app import db
        
        if not log_entry.source_ip:
            return
        
        try:
            device = Device.query.filter_by(ip_address=log_entry.source_ip).first()
            
            if device:
                device.last_seen = datetime.utcnow()
                device.is_active = True
                device.total_packets = (device.total_packets or 0) + 1
                device.total_bytes = (device.total_bytes or 0) + (log_entry.packet_size or 0)
            else:
                device = Device(
                    ip_address=log_entry.source_ip,
                    device_type='unknown',
                    first_seen=datetime.utcnow(),
                    last_seen=datetime.utcnow(),
                    is_active=True,
                    total_packets=1,
                    total_bytes=log_entry.packet_size or 0
                )
                db.session.add(device)
            
            db.session.commit()
            
            # Emit device update
            self.socketio.emit('device_update', {
                'ip_address': device.ip_address,
                'is_active': device.is_active,
                'last_seen': device.last_seen.isoformat()
            })
            
        except Exception as e:
            print(f"Error updating device: {e}")


class LogWatcher:
    """Main log watcher class that monitors directories for log files"""
    
    def __init__(self, app, socketio, detection_engine):
        self.app = app
        self.socketio = socketio
        self.detection_engine = detection_engine
        self.observer = None
        self.watch_paths = []
        self.running = False
    
    def start(self, watch_paths=None):
        """Start watching log directories"""
        if self.running:
            return
        
        if watch_paths is None:
            # Default watch path
            watch_paths = [
                os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 'data', 'watch')
            ]
        
        self.watch_paths = watch_paths
        
        # Create watch directories if they don't exist
        for path in self.watch_paths:
            os.makedirs(path, exist_ok=True)
        
        # Create event handler
        handler = LogFileHandler(self.app, self.socketio, self.detection_engine)
        
        # Create and start observer
        self.observer = Observer()
        for path in self.watch_paths:
            self.observer.schedule(handler, path, recursive=False)
            print(f"[LogWatcher] Watching: {path}")
        
        self.observer.start()
        self.running = True
        print("[LogWatcher] Started monitoring for log files")
    
    def stop(self):
        """Stop watching"""
        if self.observer and self.running:
            self.observer.stop()
            self.observer.join()
            self.running = False
            print("[LogWatcher] Stopped")
    
    def get_status(self):
        """Get watcher status"""
        return {
            'running': self.running,
            'watch_paths': self.watch_paths
        }


# Global instance
log_watcher = None

def init_log_watcher(app, socketio, detection_engine):
    """Initialize the global log watcher"""
    global log_watcher
    log_watcher = LogWatcher(app, socketio, detection_engine)
    return log_watcher

def get_log_watcher():
    """Get the global log watcher instance"""
    return log_watcher
