"""
Threat Intelligence Module for Autonomous Threat Hunter AI.

This module provides threat intelligence capabilities to enhance the detection
and analysis of security threats.
"""
import os
import json
import logging
import datetime
from config import Config

# Initialize logging
logger = logging.getLogger(__name__)

# Internal cache for threat intelligence
THREAT_INTEL_CACHE = {
    "ip_reputation": {},
    "malware_hashes": set(),
    "known_techniques": {},
    "last_updated": None
}

def load_threat_intel():
    """
    Load threat intelligence data from sources.
    In a real environment, this would connect to threat intel APIs.
    For demonstration, we'll use simulated data.
    
    Returns:
        bool: True if successful
    """
    try:
        logger.info("Loading threat intelligence data")
        
        # In a real system, this would load from APIs or databases
        THREAT_INTEL_CACHE["ip_reputation"] = {
            # Simulated malicious IPs with reputation scores and categories
            "185.13.45.235": {"score": 95, "category": "C2", "first_seen": "2024-01-15", "source": "Internal"},
            "91.243.85.126": {"score": 91, "category": "Phishing", "first_seen": "2024-02-10", "source": "Internal"}, 
            "45.61.138.109": {"score": 89, "category": "Malware Distribution", "first_seen": "2024-01-25", "source": "Internal"},
            "103.152.116.43": {"score": 87, "category": "Botnet", "first_seen": "2024-03-01", "source": "Internal"},
            "193.36.85.164": {"score": 85, "category": "Scanning", "first_seen": "2024-02-18", "source": "Internal"},
        }
        
        THREAT_INTEL_CACHE["malware_hashes"] = {
            # Simulated malware file hashes
            "5f31d93d15b10d57c7cf9167fe2767ec5c8e0020", 
            "f5bc1aae5a8651ad09c1b39c4f885ec6e4a7e803",
            "7b52cb8e18e8417a59f363fdeeed3a6978b977da",
            "9f57698287284613242a2d99fc80787ef41d3b95",
            "a1d0c6e83f027327d8461063f4ac58a6", 
            "4a417fe4d412dc2a8aaa6326a650cd7a"
        }
        
        THREAT_INTEL_CACHE["known_techniques"] = {
            # Simulated MITRE ATT&CK techniques
            "T1046": {
                "name": "Network Service Scanning",
                "description": "Adversaries may scan victims for services to identify open ports for initial access or lateral movement.",
                "tactics": ["Reconnaissance"],
                "indicators": ["Multiple connection attempts to different ports", "SYN scans"]
            },
            "T1110": {
                "name": "Brute Force",
                "description": "Adversaries may use brute force techniques to gain access to accounts when passwords are unknown.",
                "tactics": ["Credential Access"],
                "indicators": ["Multiple failed authentication attempts", "Authentication attempts with common username/password combinations"]
            },
            "T1566": {
                "name": "Phishing",
                "description": "Adversaries may send phishing emails with malicious attachments or links.",
                "tactics": ["Initial Access"],
                "indicators": ["Suspicious email attachments", "Links to unknown domains", "Executable files disguised as documents"]
            },
            "T1059": {
                "name": "Command and Scripting Interpreter",
                "description": "Adversaries may abuse command and script interpreters to execute commands.",
                "tactics": ["Execution"],
                "indicators": ["Unusual scripts being executed", "PowerShell with encoded commands", "Command line with suspicious arguments"]
            },
            "T1041": {
                "name": "Exfiltration Over C2 Channel",
                "description": "Adversaries may steal data by exfiltrating it over an existing command and control channel.",
                "tactics": ["Exfiltration"],
                "indicators": ["Large data transfers to external IPs", "Unusual outbound connections", "Regular beaconing to external systems"]
            }
        }
        
        THREAT_INTEL_CACHE["last_updated"] = datetime.datetime.utcnow()
        
        logger.info("Threat intelligence data loaded successfully")
        return True
    
    except Exception as e:
        logger.error(f"Error loading threat intelligence: {e}")
        return False

def check_ip_reputation(ip_address):
    """
    Check the reputation of an IP address against threat intelligence.
    
    Args:
        ip_address (str): The IP address to check
        
    Returns:
        dict: Reputation information or None if not found
    """
    # Load threat intel if it hasn't been loaded or is older than 1 hour
    if (THREAT_INTEL_CACHE["last_updated"] is None or 
        (datetime.datetime.utcnow() - THREAT_INTEL_CACHE["last_updated"]).total_seconds() > 3600):
        load_threat_intel()
    
    return THREAT_INTEL_CACHE["ip_reputation"].get(ip_address)

def check_file_hash(file_hash):
    """
    Check if a file hash is known to be malicious.
    
    Args:
        file_hash (str): The file hash to check
        
    Returns:
        bool: True if the hash is known to be malicious
    """
    # Load threat intel if needed
    if (THREAT_INTEL_CACHE["last_updated"] is None or 
        (datetime.datetime.utcnow() - THREAT_INTEL_CACHE["last_updated"]).total_seconds() > 3600):
        load_threat_intel()
    
    return file_hash in THREAT_INTEL_CACHE["malware_hashes"]

def get_technique_info(technique_id):
    """
    Get information about a MITRE ATT&CK technique.
    
    Args:
        technique_id (str): The MITRE ATT&CK technique ID (e.g., "T1046")
        
    Returns:
        dict: Information about the technique or None if not found
    """
    # Load threat intel if needed
    if (THREAT_INTEL_CACHE["last_updated"] is None or 
        (datetime.datetime.utcnow() - THREAT_INTEL_CACHE["last_updated"]).total_seconds() > 3600):
        load_threat_intel()
    
    return THREAT_INTEL_CACHE["known_techniques"].get(technique_id)

def detect_threats_in_logs(logs):
    """
    Analyze logs for potential threats using threat intelligence.
    
    Args:
        logs (list): List of log dictionaries
        
    Returns:
        list: Detected threats with details
    """
    # Load threat intel if needed
    if (THREAT_INTEL_CACHE["last_updated"] is None or 
        (datetime.datetime.utcnow() - THREAT_INTEL_CACHE["last_updated"]).total_seconds() > 3600):
        load_threat_intel()
    
    detected_threats = []
    
    for log in logs:
        # Check source and destination IPs against threat intelligence
        if log.get('source_ip'):
            source_rep = check_ip_reputation(log['source_ip'])
            if source_rep:
                detected_threats.append({
                    "log_id": log.get('id'),
                    "timestamp": log.get('timestamp'),
                    "threat_type": "Malicious IP",
                    "indicator": log['source_ip'],
                    "details": source_rep,
                    "confidence": "High",
                    "action": "Block IP and investigate"
                })
        
        if log.get('destination_ip'):
            dest_rep = check_ip_reputation(log['destination_ip'])
            if dest_rep:
                detected_threats.append({
                    "log_id": log.get('id'),
                    "timestamp": log.get('timestamp'),
                    "threat_type": "Connection to Malicious IP",
                    "indicator": log['destination_ip'],
                    "details": dest_rep,
                    "confidence": "High",
                    "action": "Block IP and investigate affected host"
                })
        
        # Check for scanning activity
        if log.get('alert_message') and "scan" in log.get('alert_message', '').lower():
            detected_threats.append({
                "log_id": log.get('id'),
                "timestamp": log.get('timestamp'),
                "threat_type": "Network Scanning",
                "indicator": log.get('source_ip'),
                "details": get_technique_info("T1046"),
                "confidence": "Medium",
                "action": "Monitor and block if pattern continues"
            })
        
        # Check for brute force attempts
        if log.get('alert_message') and any(x in log.get('alert_message', '').lower() for x in ["brute force", "multiple auth failures", "authentication failure"]):
            detected_threats.append({
                "log_id": log.get('id'),
                "timestamp": log.get('timestamp'),
                "threat_type": "Brute Force Attempt",
                "indicator": log.get('source_ip'),
                "details": get_technique_info("T1110"),
                "confidence": "Medium",
                "action": "Temporarily block IP and review authentication logs"
            })
        
        # Check for potential data exfiltration
        if log.get('protocol') == 'TCP' and log.get('port') in [443, 80, 8080, 8443] and log.get('alert_severity', 0) >= 3:
            # This is a very simplified check - real detection would be more sophisticated
            if check_ip_reputation(log.get('destination_ip')):
                detected_threats.append({
                    "log_id": log.get('id'),
                    "timestamp": log.get('timestamp'),
                    "threat_type": "Potential Data Exfiltration",
                    "indicator": f"{log.get('source_ip')} -> {log.get('destination_ip')}",
                    "details": get_technique_info("T1041"),
                    "confidence": "Medium",
                    "action": "Block connection and investigate source host"
                })
    
    return detected_threats

def correlate_with_global_threats(analysis_result):
    """
    Correlate local analysis with global threat intelligence.
    
    Args:
        analysis_result (dict): The result of log analysis
        
    Returns:
        dict: Enhanced analysis with global threat context
    """
    # In a real system, this would connect to threat intel APIs
    # and correlate local findings with global trends
    
    # For demonstration, we'll add simulated global context
    enhanced_result = analysis_result.copy()
    
    if 'attack_patterns' in enhanced_result:
        for pattern in enhanced_result['attack_patterns']:
            if 'mitre_id' in pattern:
                technique_info = get_technique_info(pattern['mitre_id'])
                if technique_info:
                    pattern['global_context'] = {
                        "prevalence": "High",
                        "trending": True,
                        "associated_threat_actors": ["APT29", "Lazarus Group"],
                        "industry_targets": ["Finance", "Healthcare", "Government"]
                    }
    
    # Add global threat trends
    enhanced_result['global_context'] = {
        "current_campaigns": [
            {
                "name": "BlackCat Ransomware",
                "targets": "Critical infrastructure",
                "prevalence": "Increasing",
                "first_observed": "2023-11-10"
            },
            {
                "name": "BianLian Malware",
                "targets": "Healthcare sector",
                "prevalence": "High",
                "first_observed": "2024-01-15"
            }
        ],
        "trending_techniques": [
            "T1566", # Phishing
            "T1059", # Command and Scripting Interpreter
            "T1041"  # Exfiltration Over C2 Channel
        ]
    }
    
    return enhanced_result

def suggest_mitigations(threats):
    """
    Suggest mitigations based on detected threats.
    
    Args:
        threats (list): List of detected threats
        
    Returns:
        dict: Suggested mitigations by category
    """
    # Group threats by type
    threat_types = set(threat['threat_type'] for threat in threats)
    
    mitigations = {
        "network": [],
        "endpoint": [],
        "identity": [],
        "data": []
    }
    
    # Add mitigations based on threat types
    if "Malicious IP" in threat_types or "Connection to Malicious IP" in threat_types:
        mitigations["network"].extend([
            "Update firewall rules to block identified malicious IPs",
            "Implement network segmentation to limit lateral movement",
            "Deploy an intrusion prevention system (IPS) to block known bad traffic"
        ])
        mitigations["endpoint"].append("Scan affected systems for indicators of compromise")
    
    if "Network Scanning" in threat_types:
        mitigations["network"].extend([
            "Implement port knocking for sensitive services",
            "Use a honeypot to detect and track scanning activity",
            "Configure alerts for unusual port scan activity"
        ])
    
    if "Brute Force Attempt" in threat_types:
        mitigations["identity"].extend([
            "Implement account lockout policies",
            "Enable multi-factor authentication",
            "Use CAPTCHA for login attempts",
            "Implement IP-based rate limiting for authentication requests"
        ])
    
    if "Potential Data Exfiltration" in threat_types:
        mitigations["data"].extend([
            "Implement Data Loss Prevention (DLP) solutions",
            "Encrypt sensitive data at rest and in transit",
            "Monitor and alert on unusual data transfer patterns",
            "Segment networks containing sensitive data"
        ])
        mitigations["network"].append("Implement egress filtering")
    
    return mitigations

if __name__ == "__main__":
    # Test the module
    from log_generator import generate_suricata_logs
    
    # Load threat intelligence
    load_threat_intel()
    
    # Generate some test logs
    logs = generate_suricata_logs(10)
    
    # Add some known malicious IPs for testing
    logs[0]['source_ip'] = "185.13.45.235"  # Known malicious IP
    logs[1]['destination_ip'] = "91.243.85.126"  # Known malicious IP
    logs[2]['alert_message'] = "Multiple failed login attempts - possible brute force attack"
    
    # Detect threats
    threats = detect_threats_in_logs(logs)
    
    # Print results
    print("Detected Threats:")
    for threat in threats:
        print(f"- {threat['threat_type']}: {threat['indicator']} (Confidence: {threat['confidence']})")
        print(f"  Action: {threat['action']}")
        print()
    
    # Test mitigation suggestions
    mitigations = suggest_mitigations(threats)
    
    print("\nSuggested Mitigations:")
    for category, actions in mitigations.items():
        if actions:
            print(f"\n{category.upper()}:")
            for action in actions:
                print(f"- {action}")