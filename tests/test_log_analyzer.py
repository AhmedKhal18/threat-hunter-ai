import unittest
import sys
import os
import json
from unittest.mock import patch, MagicMock
from datetime import datetime

# Add project root to Python path to import modules
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from log_analyzer import (
    analyze_logs, 
    format_logs_for_analysis,
    identify_attack_patterns,
    correlate_events
)

class TestLogAnalyzer(unittest.TestCase):
    """Test the log analysis functionality."""
    
    def setUp(self):
        """Set up test fixtures."""
        # Create sample logs for testing
        self.sample_logs = [
            {
                'id': 1,
                'timestamp': datetime(2023, 1, 1, 10, 0, 0),
                'log_type': 'Suricata',
                'source_ip': '203.0.113.10',
                'destination_ip': '192.168.1.100',
                'protocol': 'TCP',
                'port': 22,
                'alert_severity': 2,
                'alert_message': 'ET SCAN Nmap Scripting Engine User-Agent Detected',
                'raw_log': json.dumps({
                    'timestamp': '2023-01-01T10:00:00.000Z',
                    'event_type': 'alert',
                    'src_ip': '203.0.113.10',
                    'dest_ip': '192.168.1.100',
                    'proto': 'TCP',
                    'alert': {
                        'signature': 'ET SCAN Nmap Scripting Engine User-Agent Detected',
                        'category': 'recon',
                        'severity': 2
                    }
                })
            },
            {
                'id': 2,
                'timestamp': datetime(2023, 1, 1, 10, 5, 0),
                'log_type': 'Suricata',
                'source_ip': '203.0.113.10',
                'destination_ip': '192.168.1.100',
                'protocol': 'TCP',
                'port': 22,
                'alert_severity': 3,
                'alert_message': 'ET POLICY SSH Brute Force Attempt',
                'raw_log': json.dumps({
                    'timestamp': '2023-01-01T10:05:00.000Z',
                    'event_type': 'alert',
                    'src_ip': '203.0.113.10',
                    'dest_ip': '192.168.1.100',
                    'proto': 'TCP',
                    'alert': {
                        'signature': 'ET POLICY SSH Brute Force Attempt',
                        'category': 'brute_force',
                        'severity': 3
                    }
                })
            },
            {
                'id': 3,
                'timestamp': datetime(2023, 1, 1, 10, 10, 0),
                'log_type': 'Suricata',
                'source_ip': '192.168.1.100',
                'destination_ip': '203.0.113.50',
                'protocol': 'TCP',
                'port': 443,
                'alert_severity': 5,
                'alert_message': 'ET TROJAN DATA Exfiltration',
                'raw_log': json.dumps({
                    'timestamp': '2023-01-01T10:10:00.000Z',
                    'event_type': 'alert',
                    'src_ip': '192.168.1.100',
                    'dest_ip': '203.0.113.50',
                    'proto': 'TCP',
                    'alert': {
                        'signature': 'ET TROJAN DATA Exfiltration',
                        'category': 'data_theft',
                        'severity': 5
                    }
                })
            }
        ]
        
    @patch('log_analyzer.ChatOpenAI')
    def test_analyze_logs(self, mock_chat_openai):
        """Test the analyze_logs function with mocked LangChain."""
        # Create a mock response for the LLM
        mock_message = MagicMock()
        mock_message.content = json.dumps({
            "summary": "The logs show a multi-stage attack pattern.",
            "threat_level": "High",
            "attack_patterns": ["Reconnaissance", "Brute Force", "Data Exfiltration"],
            "recommended_actions": "Block the attacker IP and investigate the compromised host.",
            "attack_paths": [
                {
                    "path": [
                        {"type": "recon", "source_ip": "203.0.113.10", "destination_ip": "192.168.1.100"},
                        {"type": "brute_force", "source_ip": "203.0.113.10", "destination_ip": "192.168.1.100"},
                        {"type": "data_theft", "source_ip": "192.168.1.100", "destination_ip": "203.0.113.50"}
                    ],
                    "severity": "High",
                    "description": "Classic attack pattern: scan, brute force, and data theft."
                }
            ]
        })
        
        # Configure the mock LLM
        mock_llm_instance = mock_chat_openai.return_value
        mock_llm_instance.return_value = mock_message
        
        # Call the function
        with patch('log_analyzer.OPENAI_API_KEY', 'test-key'):
            result = analyze_logs(self.sample_logs)
        
        # Check that the function called LangChain
        mock_chat_openai.assert_called_once()
        mock_llm_instance.assert_called_once()
        
        # Check the output
        self.assertEqual(result['summary'], "The logs show a multi-stage attack pattern.")
        self.assertEqual(result['threat_level'], "High")
        self.assertEqual(result['recommended_actions'], "Block the attacker IP and investigate the compromised host.")
        self.assertEqual(len(result['attack_paths']), 1)
        self.assertEqual(result['attack_paths'][0]['severity'], "High")
        
    def test_format_logs_for_analysis(self):
        """Test the log formatting function."""
        formatted_logs = format_logs_for_analysis(self.sample_logs)
        
        # Check that the formatting creates a string
        self.assertIsInstance(formatted_logs, str)
        
        # Check that key fields are included
        self.assertIn('ET SCAN Nmap Scripting Engine User-Agent Detected', formatted_logs)
        self.assertIn('ET POLICY SSH Brute Force Attempt', formatted_logs)
        self.assertIn('ET TROJAN DATA Exfiltration', formatted_logs)
        self.assertIn('203.0.113.10', formatted_logs)
        self.assertIn('192.168.1.100', formatted_logs)
    
    @patch('log_analyzer.LLMChain')
    def test_identify_attack_patterns(self, mock_llm_chain):
        """Test the attack pattern identification function."""
        # Configure the mock chain
        mock_chain = MagicMock()
        mock_llm_chain.return_value = mock_chain
        
        mock_chain.run.return_value = json.dumps([
            {
                "pattern": "Network Reconnaissance", 
                "technique": "T1046", 
                "confidence": "High", 
                "evidence": "Nmap scanning detected"
            },
            {
                "pattern": "Brute Force", 
                "technique": "T1110", 
                "confidence": "Medium", 
                "evidence": "SSH brute force attempts"
            }
        ])
        
        # Call the function
        with patch('log_analyzer.OPENAI_API_KEY', 'test-key'):
            result = identify_attack_patterns(self.sample_logs)
        
        # Check that the function called LangChain
        mock_llm_chain.assert_called_once()
        mock_chain.run.assert_called_once()
        
        # Check the output
        self.assertEqual(len(result), 2)
        self.assertEqual(result[0]['pattern'], "Network Reconnaissance")
        self.assertEqual(result[1]['pattern'], "Brute Force")
    
    @patch('log_analyzer.LLMChain')
    def test_correlate_events(self, mock_llm_chain):
        """Test the event correlation function."""
        # Configure the mock chain
        mock_chain = MagicMock()
        mock_llm_chain.return_value = mock_chain
        
        mock_chain.run.return_value = json.dumps([
            {
                "attack": "Recon to Data Theft", 
                "logs": "1,2,3", 
                "stages": ["Reconnaissance", "Initial Access", "Data Exfiltration"], 
                "severity": "High"
            }
        ])
        
        # Call the function
        with patch('log_analyzer.OPENAI_API_KEY', 'test-key'):
            result = correlate_events(self.sample_logs)
        
        # Check that the function called LangChain
        mock_llm_chain.assert_called_once()
        mock_chain.run.assert_called_once()
        
        # Check the output
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]['attack'], "Recon to Data Theft")
        self.assertEqual(result[0]['severity'], "High")
        
    def test_analyze_logs_error_handling(self):
        """Test that analyze_logs handles missing API key properly."""
        with patch('log_analyzer.OPENAI_API_KEY', None):
            result = analyze_logs(self.sample_logs)
            
        # Should return an error object
        self.assertIn('error', result)
        self.assertEqual(result['threat_level'], 'Unknown')
        
if __name__ == '__main__':
    unittest.main()
