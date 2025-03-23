import random
import datetime
import json
import ipaddress
import logging
from config import Config
from utils import generate_random_ip

logger = logging.getLogger(__name__)

def generate_suricata_log():
    """
    Generate a simulated Suricata log entry.
    
    Returns:
        dict: A dictionary containing a simulated Suricata log entry
    """
    # Define common attack patterns
    attack_types = [
        {"message": "ET SCAN Nmap Scripting Engine User-Agent Detected", "severity": 2, "type": "recon"},
        {"message": "ET EXPLOIT SMB Exploit Behavior", "severity": 5, "type": "exploit"},
        {"message": "MALWARE-CNC Trojan Backdoor Activity", "severity": 4, "type": "malware"},
        {"message": "ET WEB_SERVER SQL Injection Attempt", "severity": 3, "type": "web_attack"},
        {"message": "ET POLICY SSH Brute Force Attempt", "severity": 3, "type": "brute_force"},
        {"message": "ET DOS SYN Flood Inbound", "severity": 4, "type": "dos"},
        {"message": "ET TROJAN DATA Exfiltration", "severity": 5, "type": "data_theft"},
        {"message": "ET COMPROMISED Known Compromised Host", "severity": 4, "type": "compromised"},
        {"message": "ET WEB_CLIENT Suspicious PDF Download", "severity": 2, "type": "suspicious"},
        {"message": "ET POLICY Cleartext Password over HTTP", "severity": 3, "type": "credential_exposure"}
    ]
    
    # Select a random attack type
    attack = random.choice(attack_types)
    
    # Determine direction (inbound or outbound)
    is_inbound = random.choice([True, False])
    
    # Generate IPs based on direction
    if is_inbound:
        source_ip = generate_random_ip(is_internal=False)
        destination_ip = generate_random_ip(is_internal=True)
    else:
        source_ip = generate_random_ip(is_internal=True)
        destination_ip = generate_random_ip(is_internal=False)
    
    # Select protocol and port
    protocols = ["TCP", "UDP", "ICMP"]
    protocol = random.choice(protocols)
    
    if protocol == "ICMP":
        port = None
    else:
        # Either use a common port or a random high port
        if random.random() < 0.7:  # 70% chance of common port
            port = random.choice(list(Config.COMMON_PORTS.values()))
        else:
            port = random.randint(1024, 65535)
    
    # Generate timestamp (within the last 24 hours)
    hours_ago = random.randint(0, 24)
    minutes_ago = random.randint(0, 59)
    seconds_ago = random.randint(0, 59)
    timestamp = datetime.datetime.utcnow() - datetime.timedelta(
        hours=hours_ago,
        minutes=minutes_ago,
        seconds=seconds_ago
    )
    
    # Create the basic log structure
    log_entry = {
        "timestamp": timestamp,
        "log_type": "Suricata",
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "protocol": protocol,
        "port": port,
        "alert_severity": attack["severity"],
        "alert_message": attack["message"],
    }
    
    # Generate a more detailed raw log in Suricata JSON format
    raw_log = {
        "timestamp": timestamp.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
        "flow_id": random.randint(1000000000, 9999999999),
        "event_type": "alert",
        "src_ip": source_ip,
        "src_port": random.randint(1024, 65535) if protocol != "ICMP" else None,
        "dest_ip": destination_ip,
        "dest_port": port if protocol != "ICMP" else None,
        "proto": protocol,
        "alert": {
            "action": "allowed" if random.random() < 0.7 else "blocked",
            "gid": 1,
            "signature_id": random.randint(2000000, 2999999),
            "rev": random.randint(1, 10),
            "signature": attack["message"],
            "category": attack["type"],
            "severity": attack["severity"]
        },
        "http": {
            "hostname": "example.com",
            "url": "/login.php",
            "http_user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "http_method": "POST",
            "http_refer": "https://example.com/index.html",
            "status": 200,
            "length": random.randint(500, 5000)
        } if attack["type"] in ["web_attack", "credential_exposure"] else None,
        "app_proto": "http" if attack["type"] in ["web_attack", "credential_exposure"] else None,
        "flow": {
            "pkts_toserver": random.randint(1, 50),
            "pkts_toclient": random.randint(1, 100),
            "bytes_toserver": random.randint(100, 5000),
            "bytes_toclient": random.randint(100, 10000),
            "start": (timestamp - datetime.timedelta(seconds=random.randint(0, 300))).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
        }
    }
    
    # Add the raw log to the log entry
    log_entry["raw_log"] = json.dumps(raw_log)
    
    return log_entry

def generate_suricata_logs(count=10):
    """
    Generate multiple Suricata log entries.
    
    Args:
        count (int): Number of log entries to generate
        
    Returns:
        list: A list of dictionaries containing simulated Suricata log entries
    """
    try:
        logs = [generate_suricata_log() for _ in range(count)]
        logger.info(f"Generated {count} Suricata logs")
        return logs
    except Exception as e:
        logger.error(f"Error generating Suricata logs: {e}")
        raise

def generate_multi_stage_attack_logs(stages=3, logs_per_stage=5):
    """
    Generate logs that simulate a multi-stage attack.
    
    Args:
        stages (int): Number of attack stages
        logs_per_stage (int): Number of logs per stage
        
    Returns:
        list: A list of dictionaries containing simulated attack logs
    """
    try:
        all_logs = []
        
        # Define attack stages
        attack_stages = [
            # Stage 1: Reconnaissance
            {"message": "ET SCAN Nmap Scripting Engine User-Agent Detected", "severity": 2, "type": "recon"},
            # Stage 2: Initial Access
            {"message": "ET EXPLOIT SSH Brute Force Attempt", "severity": 3, "type": "brute_force"},
            # Stage 3: Exploitation
            {"message": "ET EXPLOIT SMB Exploit Behavior", "severity": 5, "type": "exploit"},
            # Stage 4: Command and Control
            {"message": "MALWARE-CNC Trojan Backdoor Activity", "severity": 4, "type": "malware"},
            # Stage 5: Data Exfiltration
            {"message": "ET TROJAN DATA Exfiltration", "severity": 5, "type": "data_theft"}
        ]
        
        # Generate attacker and victim IPs (consistent across stages)
        attacker_ip = generate_random_ip(is_internal=False)
        victim_ip = generate_random_ip(is_internal=True)
        
        # Generate timestamp base (attack starts in the past)
        base_timestamp = datetime.datetime.utcnow() - datetime.timedelta(hours=random.randint(1, 12))
        
        # Generate logs for each stage
        for stage in range(min(stages, len(attack_stages))):
            stage_attack = attack_stages[stage]
            
            # Time passes between stages
            base_timestamp += datetime.timedelta(minutes=random.randint(5, 30))
            
            for _ in range(logs_per_stage):
                # Small time increment within the stage
                timestamp = base_timestamp + datetime.timedelta(seconds=random.randint(0, 300))
                
                # Create log with consistent IPs
                protocol = random.choice(["TCP", "UDP"])
                port = list(Config.COMMON_PORTS.values())[stage] if stage < len(Config.COMMON_PORTS) else random.randint(1024, 65535)
                
                log_entry = {
                    "timestamp": timestamp,
                    "log_type": "Suricata",
                    "source_ip": attacker_ip,
                    "destination_ip": victim_ip,
                    "protocol": protocol,
                    "port": port,
                    "alert_severity": stage_attack["severity"],
                    "alert_message": stage_attack["message"],
                }
                
                # Generate raw log
                raw_log = {
                    "timestamp": timestamp.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
                    "flow_id": random.randint(1000000000, 9999999999),
                    "event_type": "alert",
                    "src_ip": attacker_ip,
                    "src_port": random.randint(1024, 65535),
                    "dest_ip": victim_ip,
                    "dest_port": port,
                    "proto": protocol,
                    "alert": {
                        "action": "allowed",
                        "gid": 1,
                        "signature_id": 2000000 + stage,
                        "rev": random.randint(1, 10),
                        "signature": stage_attack["message"],
                        "category": stage_attack["type"],
                        "severity": stage_attack["severity"]
                    },
                    "flow": {
                        "pkts_toserver": random.randint(1, 50),
                        "pkts_toclient": random.randint(1, 100),
                        "bytes_toserver": random.randint(100, 5000),
                        "bytes_toclient": random.randint(100, 10000),
                        "start": (timestamp - datetime.timedelta(seconds=random.randint(0, 300))).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
                    }
                }
                
                log_entry["raw_log"] = json.dumps(raw_log)
                all_logs.append(log_entry)
        
        logger.info(f"Generated {len(all_logs)} logs simulating a {stages}-stage attack")
        return all_logs
    except Exception as e:
        logger.error(f"Error generating multi-stage attack logs: {e}")
        raise

if __name__ == "__main__":
    # Test log generation
    logs = generate_suricata_logs(5)
    for log in logs:
        print(f"Log: {log['alert_message']} - Severity: {log['alert_severity']}")
    
    # Test multi-stage attack generation
    attack_logs = generate_multi_stage_attack_logs(stages=3, logs_per_stage=2)
    for log in attack_logs:
        print(f"Attack Stage Log: {log['alert_message']} - From: {log['source_ip']} to {log['destination_ip']}")
