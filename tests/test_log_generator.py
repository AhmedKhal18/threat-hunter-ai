import unittest
import sys
import os
from datetime import datetime
import json

# Add project root to Python path to import modules
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from log_generator import (
    generate_suricata_log, 
    generate_suricata_logs, 
    generate_multi_stage_attack_logs
)

class TestLogGenerator(unittest.TestCase):
    """Test the log generation functionality."""
    
    def test_generate_single_log(self):
        """Test generation of a single Suricata log entry."""
        log = generate_suricata_log()
        
        # Check that the log has the expected fields
        self.assertIsInstance(log, dict)
        self.assertIn('timestamp', log)
        self.assertIn('log_type', log)
        self.assertIn('source_ip', log)
        self.assertIn('destination_ip', log)
        self.assertIn('protocol', log)
        self.assertIn('alert_severity', log)
        self.assertIn('alert_message', log)
        self.assertIn('raw_log', log)
        
        # Check log_type
        self.assertEqual(log['log_type'], 'Suricata')
        
        # Check timestamp is a datetime
        self.assertIsInstance(log['timestamp'], datetime)
        
        # Check IPs are valid
        self.assertRegex(log['source_ip'], r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
        self.assertRegex(log['destination_ip'], r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
        
        # Check protocol is valid
        self.assertIn(log['protocol'], ["TCP", "UDP", "ICMP"])
        
        # Check alert severity is in range
        self.assertGreaterEqual(log['alert_severity'], 1)
        self.assertLessEqual(log['alert_severity'], 5)
        
        # Check raw_log is a valid JSON string
        raw_log = json.loads(log['raw_log'])
        self.assertIsInstance(raw_log, dict)
        self.assertIn('timestamp', raw_log)
        self.assertIn('src_ip', raw_log)
        self.assertIn('dest_ip', raw_log)
        
    def test_generate_multiple_logs(self):
        """Test generation of multiple Suricata log entries."""
        count = 5
        logs = generate_suricata_logs(count)
        
        # Check we get the right number of logs
        self.assertEqual(len(logs), count)
        
        # Check that all logs are properly formed
        for log in logs:
            self.assertIsInstance(log, dict)
            self.assertIn('timestamp', log)
            self.assertIn('log_type', log)
            self.assertEqual(log['log_type'], 'Suricata')
            
    def test_generate_multi_stage_attack(self):
        """Test generation of a multi-stage attack log sequence."""
        stages = 3
        logs_per_stage = 2
        logs = generate_multi_stage_attack_logs(stages=stages, logs_per_stage=logs_per_stage)
        
        # Check we get the right number of logs
        self.assertEqual(len(logs), stages * logs_per_stage)
        
        # Check that all logs are properly formed
        for log in logs:
            self.assertIsInstance(log, dict)
            self.assertIn('timestamp', log)
            self.assertIn('log_type', log)
            self.assertEqual(log['log_type'], 'Suricata')
        
        # Check that source and destination IPs are consistent across stages
        # (attacker IP should be the same throughout the attack)
        attacker_ip = logs[0]['source_ip']
        victim_ip = logs[0]['destination_ip']
        
        for log in logs:
            # In the first stages, attacker is the source
            if log['alert_message'] in [
                "ET SCAN Nmap Scripting Engine User-Agent Detected", 
                "ET EXPLOIT SSH Brute Force Attempt",
                "ET EXPLOIT SMB Exploit Behavior"
            ]:
                self.assertEqual(log['source_ip'], attacker_ip)
                self.assertEqual(log['destination_ip'], victim_ip)
            
            # In data exfiltration stages, victim might be the source
            # but either source or destination should match our expected IPs
            else:
                self.assertTrue(
                    log['source_ip'] in [attacker_ip, victim_ip] or 
                    log['destination_ip'] in [attacker_ip, victim_ip]
                )
                
    def test_timestamp_ordering(self):
        """Test that multi-stage attack logs have correct timestamp ordering."""
        logs = generate_multi_stage_attack_logs(stages=3, logs_per_stage=2)
        
        # Extract timestamps and check they are in chronological order within each stage
        for stage in range(3):
            stage_logs = logs[stage*2:(stage+1)*2]
            self.assertLessEqual(stage_logs[0]['timestamp'], stage_logs[1]['timestamp'])
            
        # Check that stages are in chronological order
        for i in range(1, 3):
            self.assertLessEqual(logs[(i-1)*2 + 1]['timestamp'], logs[i*2]['timestamp'])

if __name__ == '__main__':
    unittest.main()
