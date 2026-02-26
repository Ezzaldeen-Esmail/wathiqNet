"""
Generate 10,000 log records for NIDS testing
"""
import csv
import random
from datetime import datetime, timedelta
import os
import ipaddress

def generate_logs(filename='data/generated_logs_10k.csv', count=10000):
    # Ensure directory exists
    os.makedirs(os.path.dirname(filename), exist_ok=True)
    
    # Common protocols and ports
    protocols = {
        'TCP': [80, 443, 22, 21, 3306, 8080],
        'UDP': [53, 123, 161, 500, 514],
        'ICMP': [0]
    }
    
    # Simulation parameters
    start_time = datetime.utcnow() - timedelta(hours=24)
    time_increment = timedelta(seconds=8)  # Roughly 10k logs in 24h
    
    # Simulated networks
    internal_network = ipaddress.ip_network('192.168.1.0/24')
    external_networks = [
        ipaddress.ip_network('10.0.0.0/8'),
        ipaddress.ip_network('172.16.0.0/12'),
        ipaddress.ip_network('8.8.8.0/24'),  # Google DNS
        ipaddress.ip_network('1.1.1.0/24'),  # Cloudflare
        ipaddress.ip_network('203.0.113.0/24') # Test net
    ]
    
    # Threats to simulate
    threat_patterns = [
        ('brute_force', 0.05),  # 5% chance
        ('port_scan', 0.03),    # 3% chance
        ('normal', 0.92)        # 92% normal traffic
    ]
    
    print(f"Generating {count} logs to {filename}...")
    
    with open(filename, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['timestamp', 'source_ip', 'destination_ip', 'source_port', 
                        'destination_port', 'protocol', 'packet_size', 'flags', 'action', 'device_id'])
        
        current_time = start_time
        
        # Keep state for attacks
        attack_state = {
            'active': False,
            'type': None,
            'source_ip': None,
            'target_ip': None,
            'remaining_packets': 0
        }
        
        for i in range(count):
            # Advance time
            current_time += time_increment + timedelta(milliseconds=random.randint(-500, 500))
            
            # Determine traffic type
            if attack_state['active']:
                traffic_type = attack_state['type']
                attack_state['remaining_packets'] -= 1
                if attack_state['remaining_packets'] <= 0:
                    attack_state['active'] = False
            else:
                # Pick a new pattern
                rand = random.random()
                cumulative = 0
                traffic_type = 'normal'
                for pattern, prob in threat_patterns:
                    cumulative += prob
                    if rand < cumulative:
                        traffic_type = pattern
                        break
                
                # Start new attack sequence?
                if traffic_type != 'normal':
                    attack_state['active'] = True
                    attack_state['type'] = traffic_type
                    attack_state['source_ip'] = str(ipaddress.IPv4Address(random.randint(0, 2**32))) # Random external IP
                    attack_state['target_ip'] = str(internal_network[random.randint(1, 254)])
                    attack_state['remaining_packets'] = random.randint(10, 50)
            
            # Generate packet details based on type
            if traffic_type == 'brute_force':
                src_ip = attack_state['source_ip']
                dst_ip = attack_state['target_ip']
                proto = 'TCP'
                src_port = random.randint(1024, 65535)
                dst_port = 22  # SSH brute force
                packet_size = random.randint(60, 150)
                flags = 'PA' 
                action = 'deny' if random.random() > 0.1 else 'allow' # Mostly blocked eventually
                device_id = 'firewall-main'
                
            elif traffic_type == 'port_scan':
                src_ip = attack_state['source_ip']
                dst_ip = attack_state['target_ip']
                proto = 'TCP'
                src_port = random.randint(1024, 65535)
                dst_port = random.randint(1, 1000) # Scanning low ports
                packet_size = 60
                flags = 'S' # SYN scan
                action = 'deny'
                device_id = 'firewall-main'
                
            else: # Normal traffic
                direction = random.choice(['inbound', 'outbound', 'internal'])
                
                if direction == 'inbound':
                    src_ip = str(ipaddress.IPv4Address(random.randint(0, 2**32)))
                    dst_ip = str(internal_network[random.randint(1, 254)])
                elif direction == 'outbound':
                    src_ip = str(internal_network[random.randint(1, 254)])
                    dst_ip = str(ipaddress.IPv4Address(random.randint(0, 2**32)))
                else:
                    src_ip = str(internal_network[random.randint(1, 254)])
                    dst_ip = str(internal_network[random.randint(1, 254)])
                
                proto = random.choice(list(protocols.keys()))
                dst_port = random.choice(protocols[proto])
                src_port = random.randint(1024, 65535)
                packet_size = random.randint(60, 1500)
                flags = 'A' if proto == 'TCP' else None
                action = 'allow'
                device_id = f"switch-0{random.randint(1,3)}"
            
            writer.writerow([
                current_time.strftime('%Y-%m-%d %H:%M:%S'),
                src_ip,
                dst_ip,
                src_port,
                dst_port,
                proto,
                packet_size,
                flags,
                action,
                device_id
            ])
            
            if (i + 1) % 1000 == 0:
                print(f"Generated {i + 1} records...")

if __name__ == "__main__":
    generate_logs()
    print("Done!")
