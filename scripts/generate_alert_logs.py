"""
Generate specific log patterns to trigger NIDS alerts
"""
import csv
import random
from datetime import datetime, timedelta
import os

def generate_alert_logs(filename='data/alert_test_logs.csv'):
    # Ensure directory exists
    os.makedirs(os.path.dirname(filename), exist_ok=True)
    
    # Base configuration
    base_time = datetime.utcnow()
    logs = []
    
    # helper to add log
    def add_log(timestamp, src_ip, dst_ip, src_port, dst_port, proto, action, flags=None):
        logs.append([
            timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            src_ip, dst_ip, src_port, dst_port, proto,
            random.randint(60, 1500), # size
            flags,
            action,
            'test-generator'
        ])

    print("Generating logs to trigger specific alerts...")

    # 1. Brute Force Attack
    # Rule: >10 failed attempts to same dst:port with action='deny'
    # Target: 192.168.1.50:22 (SSH)
    attacker_ip = "10.10.10.100"
    target_ip = "192.168.1.50"
    print(f"- Generating Brute Force attack from {attacker_ip}...")
    for i in range(25): # 25 > 10 threshold
        add_log(
            base_time + timedelta(seconds=i),
            attacker_ip, target_ip, 
            random.randint(10000, 60000), 22, 
            'TCP', 'deny', 'S'
        )

    # 2. Port Scan
    # Rule: >20 unique destination ports from same source
    # Target: 192.168.1.51
    attacker_ip = "10.10.10.101"
    target_ip = "192.168.1.51"
    print(f"- Generating Port Scan from {attacker_ip}...")
    for i in range(50): # 50 unique ports > 20 threshold
        add_log(
            base_time + timedelta(seconds=i),
            attacker_ip, target_ip,
            random.randint(10000, 60000), 1000 + i, # Unique dst ports
            'TCP', 'allow', 'S'
        )

    # 3. Traffic Spike / DDoS
    # Rule: >100 packets from same source
    # Target: 192.168.1.52
    attacker_ip = "10.10.10.102"
    target_ip = "192.168.1.52"
    print(f"- Generating Traffic Spike from {attacker_ip}...")
    for i in range(150): # 150 packets > 100 threshold
        add_log(
            base_time + timedelta(milliseconds=i*10), # Fast burst
            attacker_ip, target_ip,
            random.randint(10000, 60000), 80,
            'TCP', 'allow', 'A'
        )

    # 4. Suspicious IP
    # Rule: Source IP in suspicious list (e.g., 185.220.101.x)
    attacker_ip = "185.220.101.55" # Tor exit node prefix
    target_ip = "192.168.1.53"
    print(f"- Generating Suspicious IP traffic from {attacker_ip}...")
    for i in range(5):
        add_log(
            base_time + timedelta(seconds=i),
            attacker_ip, target_ip,
            random.randint(10000, 60000), 443,
            'TCP', 'allow', 'A'
        )

    # Write to CSV
    with open(filename, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['timestamp', 'source_ip', 'destination_ip', 'source_port', 
                        'destination_port', 'protocol', 'packet_size', 'flags', 'action', 'device_id'])
        writer.writerows(logs)

    print(f"Done! Generated {len(logs)} records in {filename}")

if __name__ == "__main__":
    generate_alert_logs()
