import random
import ipaddress
import logging
import re
import json
from datetime import datetime, timedelta
from config import Config

# Configure logging
logger = logging.getLogger(__name__)

def generate_random_ip(is_internal=True):
    """
    Generate a random IP address.
    
    Args:
        is_internal (bool): Whether to generate an internal or external IP
        
    Returns:
        str: IP address
    """
    if is_internal:
        # Choose a random internal IP range
        ip_range = random.choice(Config.INTERNAL_IP_RANGES)
        network = ipaddress.IPv4Network(ip_range)
        # Generate a random IP within the network
        ip_int = random.randint(int(network.network_address), int(network.broadcast_address))
        return str(ipaddress.IPv4Address(ip_int))
    else:
        # Choose a random external IP range
        ip_range = random.choice(Config.EXTERNAL_IP_RANGES)
        network = ipaddress.IPv4Network(ip_range)
        # Generate a random IP within the network
        ip_int = random.randint(int(network.network_address), int(network.broadcast_address))
        return str(ipaddress.IPv4Address(ip_int))

def parse_suricata_log(log_text):
    """
    Parse a Suricata log entry from text format.
    
    Args:
        log_text (str): Raw Suricata log text
        
    Returns:
        dict: Parsed log entry
    """
    try:
        # Try to parse as JSON
        if log_text.strip().startswith('{'):
            log_data = json.loads(log_text)
            return format_suricata_json(log_data)
        
        # Try to parse as EVE format
        if 'SURICATA ' in log_text:
            return parse_suricata_eve(log_text)
        
        # Generic log parsing fallback
        log_entry = {
            'timestamp': datetime.now(),
            'log_type': 'Suricata',
            'raw_log': log_text
        }
        
        # Extract IPs
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        ips = re.findall(ip_pattern, log_text)
        if len(ips) >= 1:
            log_entry['source_ip'] = ips[0]
        if len(ips) >= 2:
            log_entry['destination_ip'] = ips[1]
        
        # Extract common protocols
        protocols = ['TCP', 'UDP', 'ICMP', 'HTTP', 'HTTPS', 'SSH', 'FTP', 'DNS']
        for protocol in protocols:
            if protocol in log_text:
                log_entry['protocol'] = protocol
                break
        
        # Extract port numbers
        port_pattern = r'port (\d+)'
        ports = re.findall(port_pattern, log_text)
        if ports:
            log_entry['port'] = int(ports[0])
        
        # Extract severity and alert
        if 'ALERT' in log_text:
            log_entry['alert_severity'] = 4
        elif 'WARNING' in log_text:
            log_entry['alert_severity'] = 3
        elif 'NOTICE' in log_text:
            log_entry['alert_severity'] = 2
        else:
            log_entry['alert_severity'] = 1
        
        # Extract alert message
        message_match = re.search(r'\[([^\]]+)\]', log_text)
        if message_match:
            log_entry['alert_message'] = message_match.group(1)
        
        return log_entry
        
    except Exception as e:
        logger.error(f"Error parsing Suricata log: {e}")
        return {
            'timestamp': datetime.now(),
            'log_type': 'Suricata',
            'alert_message': 'Error parsing log',
            'alert_severity': 1,
            'raw_log': log_text
        }

def format_suricata_json(log_data):
    """
    Format a Suricata JSON log entry into standardized format.
    
    Args:
        log_data (dict): Raw Suricata JSON log data
        
    Returns:
        dict: Formatted log entry
    """
    log_entry = {
        'log_type': 'Suricata',
        'raw_log': json.dumps(log_data)
    }
    
    # Extract timestamp
    if 'timestamp' in log_data:
        try:
            log_entry['timestamp'] = datetime.strptime(log_data['timestamp'], '%Y-%m-%dT%H:%M:%S.%f%z')
        except ValueError:
            try:
                log_entry['timestamp'] = datetime.strptime(log_data['timestamp'], '%Y-%m-%dT%H:%M:%S.%fZ')
            except ValueError:
                log_entry['timestamp'] = datetime.now()
    else:
        log_entry['timestamp'] = datetime.now()
    
    # Extract source and destination IPs
    if 'src_ip' in log_data:
        log_entry['source_ip'] = log_data['src_ip']
    if 'dest_ip' in log_data:
        log_entry['destination_ip'] = log_data['dest_ip']
    
    # Extract protocol
    if 'proto' in log_data:
        log_entry['protocol'] = log_data['proto']
    
    # Extract port
    if 'dest_port' in log_data:
        log_entry['port'] = log_data['dest_port']
    
    # Extract alert information
    if 'alert' in log_data:
        if 'signature' in log_data['alert']:
            log_entry['alert_message'] = log_data['alert']['signature']
        if 'severity' in log_data['alert']:
            log_entry['alert_severity'] = log_data['alert']['severity']
    
    return log_entry

def parse_suricata_eve(log_text):
    """
    Parse a Suricata EVE format log entry.
    
    Args:
        log_text (str): Raw Suricata EVE log text
        
    Returns:
        dict: Parsed log entry
    """
    log_entry = {
        'timestamp': datetime.now(),
        'log_type': 'Suricata',
        'raw_log': log_text
    }
    
    # Extract timestamp
    timestamp_match = re.search(r'\[(.*?)\]', log_text)
    if timestamp_match:
        try:
            timestamp_str = timestamp_match.group(1)
            log_entry['timestamp'] = datetime.strptime(timestamp_str, '%m/%d/%Y-%H:%M:%S')
        except ValueError:
            pass
    
    # Extract IP addresses
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    ips = re.findall(ip_pattern, log_text)
    if len(ips) >= 1:
        log_entry['source_ip'] = ips[0]
    if len(ips) >= 2:
        log_entry['destination_ip'] = ips[1]
    
    # Extract protocol
    protocols = ['TCP', 'UDP', 'ICMP', 'HTTP', 'HTTPS', 'SSH', 'FTP', 'DNS']
    for protocol in protocols:
        if protocol in log_text or protocol.lower() in log_text:
            log_entry['protocol'] = protocol
            break
    
    # Extract port
    port_pattern = r':(\d+)'
    port_matches = re.findall(port_pattern, log_text)
    if port_matches:
        try:
            log_entry['port'] = int(port_matches[-1])  # Using the last match as it's often the destination port
        except ValueError:
            pass
    
    # Extract alert and severity
    if 'Classification:' in log_text:
        classification_match = re.search(r'Classification: \[(.*?)\]', log_text)
        if classification_match:
            log_entry['alert_message'] = classification_match.group(1)
    
    if 'Priority:' in log_text:
        priority_match = re.search(r'Priority: (\d+)', log_text)
        if priority_match:
            try:
                priority = int(priority_match.group(1))
                log_entry['alert_severity'] = min(5, priority)  # Scale priority to max 5
            except ValueError:
                log_entry['alert_severity'] = 1
    else:
        log_entry['alert_severity'] = 1
    
    return log_entry

def format_timestamp(timestamp):
    """
    Format a timestamp for display.
    
    Args:
        timestamp: Timestamp to format
        
    Returns:
        str: Formatted timestamp
    """
    if isinstance(timestamp, str):
        try:
            timestamp = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
        except ValueError:
            try:
                timestamp = datetime.strptime(timestamp, '%Y-%m-%dT%H:%M:%S.%fZ')
            except ValueError:
                return timestamp
    
    if isinstance(timestamp, datetime):
        return timestamp.strftime('%Y-%m-%d %H:%M:%S')
    
    return str(timestamp)

def is_ip_in_network(ip, network):
    """
    Check if an IP is in a given network.
    
    Args:
        ip (str): IP address to check
        network (str): Network in CIDR notation
        
    Returns:
        bool: True if IP is in network
    """
    try:
        ip_addr = ipaddress.IPv4Address(ip)
        net = ipaddress.IPv4Network(network)
        return ip_addr in net
    except Exception:
        return False
