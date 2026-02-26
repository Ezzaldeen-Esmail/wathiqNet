from app import db
from app.models.log_entry import LogEntry, Device
from app.models.alert import Alert, DetectionRule
from datetime import datetime, timedelta
from collections import defaultdict
from sqlalchemy import func
import json

class DetectionEngine:
    """Main detection engine that processes logs and generates alerts"""
    
    def __init__(self):
        self.rules = self._load_rules()
    
    def _load_rules(self):
        """Load active detection rules from database"""
        return DetectionRule.query.filter_by(enabled=True).all()
    
    def reload_rules(self):
        """Reload rules from database"""
        self.rules = self._load_rules()
    
    def analyze_log(self, log_entry):
        """Analyze a single log entry against all rules"""
        alerts = []
        
        for rule in self.rules:
            alert = self._apply_rule(rule, log_entry)
            if alert:
                alerts.append(alert)
        
        return alerts
    
    def analyze_batch(self, log_entries):
        """Analyze a batch of log entries for pattern-based detection"""
        alerts = []
        
        alerts.extend(self._detect_traffic_spike(log_entries))
        alerts.extend(self._detect_brute_force(log_entries))
        alerts.extend(self._detect_port_scan(log_entries))
        alerts.extend(self._detect_suspicious_ips(log_entries))
        alerts.extend(self._detect_protocol_anomaly(log_entries))
        
        return alerts
    
    def _apply_rule(self, rule, log_entry):
        """Apply a single rule to a log entry"""
        if rule.rule_type == 'suspicious_ip':
            return self._check_suspicious_ip_single(rule, log_entry)
        elif rule.rule_type == 'protocol_anomaly':
            return self._check_protocol_single(rule, log_entry)
        return None
    
    def _detect_traffic_spike(self, log_entries, window_seconds=60, threshold=100):
        """Detect unusual traffic volume spikes"""
        alerts = []
        
        # Group by source IP and time window
        ip_traffic = defaultdict(list)
        for log in log_entries:
            ip_traffic[log.source_ip].append(log)
        
        for ip, logs in ip_traffic.items():
            if len(logs) >= threshold:
                alert = Alert(
                    alert_type='traffic_spike',
                    severity='high',
                    source_ip=ip,
                    description=f"Unusual traffic spike detected from {ip}. {len(logs)} packets in short time window.",
                    recommendation="Investigate the source IP for possible DDoS or anomalous behavior. Consider rate limiting."
                )
                db.session.add(alert)
                alerts.append(alert)
        
        return alerts
    
    def _detect_brute_force(self, log_entries, threshold=10):
        """Detect repeated failed connection attempts (brute force patterns)"""
        alerts = []
        
        # Look for multiple failed connections to same destination
        failed_attempts = defaultdict(list)
        
        for log in log_entries:
            if log.action in ['deny', 'drop'] or log.flags and 'RST' in log.flags:
                key = (log.source_ip, log.destination_ip, log.destination_port)
                failed_attempts[key].append(log)
        
        for (src, dst, port), logs in failed_attempts.items():
            if len(logs) >= threshold:
                severity = 'critical' if len(logs) >= threshold * 2 else 'high'
                alert = Alert(
                    alert_type='brute_force',
                    severity=severity,
                    source_ip=src,
                    destination_ip=dst,
                    description=f"Potential brute-force attack detected. {len(logs)} failed connection attempts from {src} to {dst}:{port}.",
                    recommendation="Block the source IP temporarily. Review authentication logs for the target service."
                )
                db.session.add(alert)
                alerts.append(alert)
        
        return alerts
    
    def _detect_port_scan(self, log_entries, threshold=20, window_seconds=60):
        """Detect port scanning behavior"""
        alerts = []
        
        # Group by source IP and count unique destination ports
        ip_ports = defaultdict(set)
        ip_logs = defaultdict(list)
        
        for log in log_entries:
            if log.destination_port:
                ip_ports[log.source_ip].add(log.destination_port)
                ip_logs[log.source_ip].append(log)
        
        for ip, ports in ip_ports.items():
            if len(ports) >= threshold:
                severity = 'critical' if len(ports) >= threshold * 2 else 'high'
                alert = Alert(
                    alert_type='port_scan',
                    severity=severity,
                    source_ip=ip,
                    description=f"Port scanning activity detected from {ip}. Probed {len(ports)} unique ports.",
                    recommendation="Block the source IP. This is likely reconnaissance activity preceding an attack."
                )
                db.session.add(alert)
                alerts.append(alert)
        
        return alerts
    
    def _detect_suspicious_ips(self, log_entries):
        """Check logs against known suspicious IP addresses"""
        alerts = []
        
        # Known malicious IP ranges (simplified)
        suspicious_ranges = [
            '185.220.101.',  # Tor exit nodes
            '45.33.32.',     # Known scanners
            '198.51.100.',   # Test range
            '203.0.113.',    # Documentation range
        ]
        
        suspicious_found = set()
        
        for log in log_entries:
            for prefix in suspicious_ranges:
                if log.source_ip.startswith(prefix) or log.destination_ip.startswith(prefix):
                    key = (log.source_ip, log.destination_ip)
                    if key not in suspicious_found:
                        suspicious_found.add(key)
                        alert = Alert(
                            alert_type='suspicious_ip',
                            severity='medium',
                            source_ip=log.source_ip,
                            destination_ip=log.destination_ip,
                            description=f"Communication with suspicious IP detected. Source: {log.source_ip}, Destination: {log.destination_ip}",
                            recommendation="Review the traffic content and block if malicious. Consider updating firewall rules."
                        )
                        db.session.add(alert)
                        alerts.append(alert)
        
        return alerts
    
    def _detect_protocol_anomaly(self, log_entries):
        """Detect unexpected protocol usage"""
        alerts = []
        
        # Suspicious protocols on standard ports
        anomalies = {
            (80, 'UDP'): 'HTTP port with UDP instead of TCP',
            (443, 'UDP'): 'HTTPS port with UDP instead of TCP',
            (22, 'UDP'): 'SSH port with UDP instead of TCP',
            (53, 'TCP'): 'DNS using TCP (possible zone transfer)',
        }
        
        found_anomalies = set()
        
        for log in log_entries:
            key = (log.destination_port, log.protocol)
            if key in anomalies and key not in found_anomalies:
                found_anomalies.add(key)
                alert = Alert(
                    alert_type='protocol_anomaly',
                    severity='medium',
                    source_ip=log.source_ip,
                    destination_ip=log.destination_ip,
                    description=f"Protocol anomaly detected: {anomalies[key]}. {log.source_ip} → {log.destination_ip}:{log.destination_port} ({log.protocol})",
                    recommendation="Investigate the traffic. This could indicate tunneling or misconfiguration."
                )
                db.session.add(alert)
                alerts.append(alert)
        
        return alerts
    
    def _check_suspicious_ip_single(self, rule, log_entry):
        """Check single log entry for suspicious IP"""
        params = json.loads(rule.parameters) if rule.parameters else {}
        suspicious_ips = params.get('suspicious_ips', [])
        
        if log_entry.source_ip in suspicious_ips or log_entry.destination_ip in suspicious_ips:
            return Alert(
                alert_type='suspicious_ip',
                severity=rule.severity,
                source_ip=log_entry.source_ip,
                destination_ip=log_entry.destination_ip,
                description=f"Connection to/from blacklisted IP detected.",
                recommendation="Block this IP immediately."
            )
        return None
    
    def _check_protocol_single(self, rule, log_entry):
        """Check single log entry for protocol anomaly"""
        params = json.loads(rule.parameters) if rule.parameters else {}
        blocked_protocols = params.get('blocked_protocols', [])
        
        if log_entry.protocol in blocked_protocols:
            return Alert(
                alert_type='protocol_anomaly',
                severity=rule.severity,
                source_ip=log_entry.source_ip,
                destination_ip=log_entry.destination_ip,
                description=f"Blocked protocol {log_entry.protocol} detected.",
                recommendation="This protocol is not allowed on this network."
            )
        return None


# Global instance
detection_engine = DetectionEngine()


def process_new_logs(log_entries):
    """Process new log entries through detection engine"""
    from app.routes.api import emit_new_alert
    
    # Run batch analysis
    alerts = detection_engine.analyze_batch(log_entries)
    
    # Commit alerts
    db.session.commit()
    
    # Emit alerts via WebSocket
    for alert in alerts:
        emit_new_alert(alert)
    
    return alerts
