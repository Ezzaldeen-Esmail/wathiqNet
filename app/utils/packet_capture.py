"""
Real-time Network Packet Capture using Scapy
Captures packets from network interfaces and processes them through the detection engine.
NOTE: Requires administrator/root privileges to capture packets.
"""
import threading
import time
from datetime import datetime
from collections import defaultdict

# Try to import scapy
try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, Ether, get_if_list, conf
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("[PacketCapture] Scapy not available. Install with: pip install scapy")


class PacketCapture:
    """Network packet capture and analysis using Scapy"""
    
    def __init__(self, app, socketio, detection_engine):
        self.app = app
        self.socketio = socketio
        self.detection_engine = detection_engine
        self.running = False
        self.capture_thread = None
        self.interface = None
        self.packet_count = 0
        self.bytes_captured = 0
        self.start_time = None
        
        # Rate limiting for WebSocket updates
        self.last_emit_time = 0
        self.emit_interval = 0.1  # Emit at most every 100ms
        self.pending_logs = []
        
        # Statistics
        self.stats = defaultdict(int)
        self.protocol_stats = defaultdict(int)
    
    def get_interfaces(self):
        """Get available network interfaces"""
        if not SCAPY_AVAILABLE:
            return []
        
        try:
            interfaces = get_if_list()
            # Filter out loopback and invalid interfaces on Windows
            valid_interfaces = []
            for iface in interfaces:
                if 'loopback' not in iface.lower() and iface:
                    valid_interfaces.append(iface)
            return valid_interfaces if valid_interfaces else interfaces
        except Exception as e:
            print(f"[PacketCapture] Error getting interfaces: {e}")
            return []
    
    def start(self, interface=None, filter_expr=None):
        """Start packet capture on the specified interface"""
        if not SCAPY_AVAILABLE:
            return False, "Scapy is not installed. Install with: pip install scapy"
        
        if self.running:
            return False, "Capture is already running"
        
        # Get default interface if not specified
        if interface is None:
            interfaces = self.get_interfaces()
            if interfaces:
                interface = interfaces[0]
            else:
                return False, "No network interfaces available"
        
        self.interface = interface
        self.running = True
        self.packet_count = 0
        self.bytes_captured = 0
        self.start_time = datetime.utcnow()
        self.stats = defaultdict(int)
        self.protocol_stats = defaultdict(int)
        
        # Start capture in background thread
        self.capture_thread = threading.Thread(
            target=self._capture_packets,
            args=(interface, filter_expr),
            daemon=True
        )
        self.capture_thread.start()
        
        print(f"[PacketCapture] Started on interface: {interface}")
        return True, f"Capture started on {interface}"
    
    def stop(self):
        """Stop packet capture"""
        if not self.running:
            return False, "Capture is not running"
        
        self.running = False
        
        # Wait for thread to finish
        if self.capture_thread and self.capture_thread.is_alive():
            self.capture_thread.join(timeout=2)
        
        print(f"[PacketCapture] Stopped. Captured {self.packet_count} packets")
        return True, f"Capture stopped. Total packets: {self.packet_count}"
    
    def _capture_packets(self, interface, filter_expr):
        """Internal method to capture packets"""
        try:
            # Suppress Scapy warnings
            conf.verb = 0
            
            sniff(
                iface=interface,
                prn=self._process_packet,
                filter=filter_expr,
                store=False,
                stop_filter=lambda x: not self.running
            )
        except PermissionError:
            print("[PacketCapture] Permission denied. Run with administrator privileges.")
            self.running = False
        except Exception as e:
            print(f"[PacketCapture] Error during capture: {e}")
            self.running = False
    
    def _process_packet(self, packet):
        """Process captured packet"""
        if not self.running:
            return
        
        try:
            self.packet_count += 1
            
            # Extract packet info
            log_data = self._extract_packet_info(packet)
            
            if log_data:
                self.bytes_captured += log_data.get('packet_size', 0)
                
                # Update protocol stats
                protocol = log_data.get('protocol', 'OTHER')
                self.protocol_stats[protocol] += 1
                
                # Save to database and run detection
                with self.app.app_context():
                    log_entry = self._save_log(log_data)
                    
                    if log_entry:
                        # Run detection engine
                        alerts = self.detection_engine.analyze_log(log_entry)
                        
                        # Rate-limited WebSocket emit
                        current_time = time.time()
                        if current_time - self.last_emit_time >= self.emit_interval:
                            self.socketio.emit('new_log', log_entry.to_dict())
                            self.last_emit_time = current_time
                            
                            # Emit stats update
                            self.socketio.emit('capture_stats', self.get_stats())
                        
                        # Emit alerts immediately
                        for alert in alerts:
                            self.socketio.emit('new_alert', {
                                'id': alert.id,
                                'alert_type': alert.alert_type,
                                'severity': alert.severity,
                                'description': alert.description,
                                'source_ip': alert.source_ip,
                                'timestamp': alert.timestamp.isoformat()
                            })
                            
        except Exception as e:
            print(f"[PacketCapture] Error processing packet: {e}")
    
    def _extract_packet_info(self, packet):
        """Extract information from packet"""
        try:
            log_data = {
                'timestamp': datetime.utcnow(),
                'packet_size': len(packet),
                'flags': None,
                'action': 'allow'  # Captured packets are allowed by default
            }
            
            # Check for IP layer
            if IP in packet:
                ip = packet[IP]
                log_data['source_ip'] = ip.src
                log_data['destination_ip'] = ip.dst
                log_data['protocol'] = ip.proto
                
                # TCP
                if TCP in packet:
                    tcp = packet[TCP]
                    log_data['source_port'] = tcp.sport
                    log_data['destination_port'] = tcp.dport
                    log_data['protocol'] = 'TCP'
                    log_data['flags'] = str(tcp.flags)
                    
                # UDP
                elif UDP in packet:
                    udp = packet[UDP]
                    log_data['source_port'] = udp.sport
                    log_data['destination_port'] = udp.dport
                    log_data['protocol'] = 'UDP'
                    
                # ICMP
                elif ICMP in packet:
                    log_data['protocol'] = 'ICMP'
                    log_data['source_port'] = 0
                    log_data['destination_port'] = 0
                
                else:
                    # Other IP protocol
                    log_data['protocol'] = f'IP-{ip.proto}'
                    log_data['source_port'] = 0
                    log_data['destination_port'] = 0
                
                return log_data
            
            # ARP or other non-IP
            elif Ether in packet:
                eth = packet[Ether]
                log_data['source_ip'] = eth.src
                log_data['destination_ip'] = eth.dst
                log_data['protocol'] = 'ARP' if packet.type == 0x0806 else 'ETH'
                log_data['source_port'] = 0
                log_data['destination_port'] = 0
                return log_data
            
            return None
            
        except Exception as e:
            print(f"[PacketCapture] Error extracting packet info: {e}")
            return None
    
    def _save_log(self, log_data):
        """Save log entry to database"""
        from app.models.log_entry import LogEntry, Device
        from app import db
        
        try:
            log_entry = LogEntry(
                timestamp=log_data.get('timestamp', datetime.utcnow()),
                source_ip=log_data.get('source_ip'),
                destination_ip=log_data.get('destination_ip'),
                source_port=log_data.get('source_port'),
                destination_port=log_data.get('destination_port'),
                protocol=log_data.get('protocol'),
                packet_size=log_data.get('packet_size', 0),
                flags=log_data.get('flags'),
                action=log_data.get('action', 'allow'),
                device_id='live-capture'
            )
            
            db.session.add(log_entry)
            
            # Update device tracking
            if log_data.get('source_ip'):
                device = Device.query.filter_by(ip_address=log_data['source_ip']).first()
                if device:
                    device.last_seen = datetime.utcnow()
                    device.is_active = True
                    device.total_packets = (device.total_packets or 0) + 1
                    device.total_bytes = (device.total_bytes or 0) + log_data.get('packet_size', 0)
                else:
                    device = Device(
                        ip_address=log_data['source_ip'],
                        device_type='unknown',
                        first_seen=datetime.utcnow(),
                        last_seen=datetime.utcnow(),
                        is_active=True,
                        total_packets=1,
                        total_bytes=log_data.get('packet_size', 0)
                    )
                    db.session.add(device)
            
            db.session.commit()
            return log_entry
            
        except Exception as e:
            db.session.rollback()
            print(f"[PacketCapture] Error saving log: {e}")
            return None
    
    def get_stats(self):
        """Get current capture statistics"""
        uptime = 0
        if self.start_time:
            uptime = (datetime.utcnow() - self.start_time).total_seconds()
        
        return {
            'running': self.running,
            'interface': self.interface,
            'packet_count': self.packet_count,
            'bytes_captured': self.bytes_captured,
            'uptime_seconds': uptime,
            'packets_per_second': self.packet_count / uptime if uptime > 0 else 0,
            'protocol_stats': dict(self.protocol_stats)
        }
    
    def get_status(self):
        """Get capture status"""
        return {
            'running': self.running,
            'interface': self.interface,
            'available': SCAPY_AVAILABLE,
            'interfaces': self.get_interfaces(),
            'stats': self.get_stats() if self.running else None
        }


# Global instance
packet_capture = None

def init_packet_capture(app, socketio, detection_engine):
    """Initialize the global packet capture instance"""
    global packet_capture
    packet_capture = PacketCapture(app, socketio, detection_engine)
    return packet_capture

def get_packet_capture():
    """Get the global packet capture instance"""
    return packet_capture
