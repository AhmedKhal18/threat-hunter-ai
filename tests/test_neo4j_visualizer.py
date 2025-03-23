import unittest
import sys
import os
import json
from unittest.mock import patch, MagicMock

# Add project root to Python path to import modules
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from neo4j_visualizer import (
    get_neo4j_connection,
    init_neo4j_schema,
    create_attack_path_graph,
    get_attack_paths,
    generate_attack_path_visualization_data,
    _is_internal_ip,
    _merge_node
)

class TestNeo4jVisualizer(unittest.TestCase):
    """Test the Neo4j visualization functionality."""
    
    def setUp(self):
        """Set up test fixtures."""
        # Sample attack path for testing
        self.sample_path = {
            "severity": "High",
            "description": "Test attack path",
            "path": [
                {
                    "type": "recon",
                    "source_ip": "203.0.113.10",
                    "destination_ip": "192.168.1.100",
                    "protocol": "TCP",
                    "port": 22,
                    "alert": "SSH Scan"
                },
                {
                    "type": "exploit",
                    "source_ip": "203.0.113.10",
                    "destination_ip": "192.168.1.100",
                    "protocol": "TCP",
                    "port": 22,
                    "alert": "SSH Brute Force"
                },
                {
                    "type": "malware",
                    "source_ip": "192.168.1.100",
                    "destination_ip": "203.0.113.50",
                    "protocol": "TCP",
                    "port": 443,
                    "alert": "Data Exfiltration"
                }
            ]
        }
        
    @patch('neo4j_visualizer.Graph')
    def test_neo4j_connection(self, mock_graph):
        """Test Neo4j connection function."""
        # Configure the mock
        mock_graph_instance = MagicMock()
        mock_graph.return_value = mock_graph_instance
        
        # Call the function
        with patch('neo4j_visualizer.NEO4J_URI', 'bolt://test:7687'):
            with patch('neo4j_visualizer.NEO4J_USER', 'neo4j'):
                with patch('neo4j_visualizer.NEO4J_PASSWORD', 'password'):
                    graph = get_neo4j_connection()
        
        # Check that Graph was created with the right parameters
        mock_graph.assert_called_once_with('bolt://test:7687', auth=('neo4j', 'password'))
        
        # Check that a graph object was returned
        self.assertEqual(graph, mock_graph_instance)
        
    @patch('neo4j_visualizer.get_neo4j_connection')
    def test_init_schema(self, mock_get_connection):
        """Test Neo4j schema initialization."""
        # Configure the mock
        mock_graph = MagicMock()
        mock_get_connection.return_value = mock_graph
        
        # Call the function
        result = init_neo4j_schema()
        
        # Check that the function called the DB
        self.assertEqual(mock_graph.run.call_count, 5)  # 2 constraints, 3 indexes
        
        # Check the result
        self.assertTrue(result)
        
    @patch('neo4j_visualizer.get_neo4j_connection')
    @patch('neo4j_visualizer.init_neo4j_schema')
    def test_create_attack_path_graph(self, mock_init_schema, mock_get_connection):
        """Test creating an attack path graph."""
        # Configure the mocks
        mock_graph = MagicMock()
        mock_get_connection.return_value = mock_graph
        mock_init_schema.return_value = True
        
        # Mock various Neo4j functions
        mock_node = MagicMock()
        mock_relationship = MagicMock()
        mock_graph.create.return_value = None
        
        # Call the function
        with patch('neo4j_visualizer.Node', return_value=mock_node):
            with patch('neo4j_visualizer.Relationship', return_value=mock_relationship):
                result = create_attack_path_graph(self.sample_path)
        
        # Check that the function called the DB
        mock_get_connection.assert_called_once()
        mock_init_schema.assert_called_once()
        
        # The function should create multiple nodes and relationships
        self.assertGreater(mock_graph.create.call_count, 0)
        
        # Check the result
        self.assertTrue(result)
        
    @patch('neo4j_visualizer.get_neo4j_connection')
    def test_get_attack_paths(self, mock_get_connection):
        """Test retrieving attack paths from Neo4j."""
        # Configure the mock
        mock_graph = MagicMock()
        mock_get_connection.return_value = mock_graph
        
        # Create a mock result for graph.run()
        mock_record = {
            'path_id': 'test_path_123',
            'severity': 'High',
            'description': 'Test path',
            'timestamp': '2023-01-01T12:00:00',
            'nodes': [
                {
                    'node': MagicMock(
                        labels=['IP'], 
                        items=[('address', '192.168.1.100'), ('is_internal', True)]
                    ),
                    'relationship': MagicMock(items=[('role', 'target')])
                }
            ],
            'links': [
                {
                    'source': '203.0.113.10',
                    'target': '192.168.1.100',
                    'properties': MagicMock(items=[('protocol', 'TCP'), ('port', 22)])
                }
            ]
        }
        mock_graph.run.return_value.data.return_value = [mock_record]
        
        # Call the function
        result = get_attack_paths()
        
        # Check that the function called the DB
        mock_get_connection.assert_called_once()
        mock_graph.run.assert_called_once()
        
        # Check the result
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]['id'], 'test_path_123')
        self.assertEqual(result[0]['severity'], 'High')
        self.assertEqual(len(result[0]['nodes']), 1)
        self.assertEqual(len(result[0]['links']), 1)
        
    def test_is_internal_ip(self):
        """Test the IP classification function."""
        # Test internal IPs
        self.assertTrue(_is_internal_ip('10.0.0.1'))
        self.assertTrue(_is_internal_ip('192.168.1.1'))
        self.assertTrue(_is_internal_ip('172.16.0.1'))
        
        # Test external IPs
        self.assertFalse(_is_internal_ip('8.8.8.8'))
        self.assertFalse(_is_internal_ip('203.0.113.1'))
        self.assertFalse(_is_internal_ip('198.51.100.1'))
        
    @patch('neo4j_visualizer.get_neo4j_connection')
    def test_generate_visualization_data(self, mock_get_connection):
        """Test generating visualization data."""
        # Configure the mock
        mock_graph = MagicMock()
        mock_get_connection.return_value = mock_graph
        
        # Mock get_attack_paths to return sample data
        with patch('neo4j_visualizer.get_attack_paths') as mock_get_paths:
            # Create sample path data
            sample_paths = [{
                "id": "test_path_123",
                "severity": "High",
                "description": "Test path",
                "timestamp": "2023-01-01T12:00:00",
                "nodes": [
                    {
                        "id": "192.168.1.100",
                        "type": "IP",
                        "properties": {"is_internal": True}
                    },
                    {
                        "id": "203.0.113.10",
                        "type": "IP",
                        "properties": {"is_internal": False}
                    }
                ],
                "links": [
                    {
                        "source": "203.0.113.10",
                        "target": "192.168.1.100",
                        "properties": {"protocol": "TCP", "port": 22}
                    }
                ]
            }]
            mock_get_paths.return_value = sample_paths
            
            # Call the function
            result = generate_attack_path_visualization_data()
        
        # Check the result
        self.assertIn('nodes', result)
        self.assertIn('links', result)
        self.assertEqual(len(result['nodes']), 2)
        self.assertEqual(len(result['links']), 1)
        self.assertEqual(result['nodes'][0]['id'], '192.168.1.100')
        self.assertEqual(result['links'][0]['source'], '203.0.113.10')
        
    @patch('neo4j_visualizer.get_neo4j_connection')
    def test_create_attack_path_error_handling(self, mock_get_connection):
        """Test error handling in create_attack_path_graph."""
        # Configure the mock to return None (connection failure)
        mock_get_connection.return_value = None
        
        # Call the function with an invalid path
        result = create_attack_path_graph({})
        
        # Check that it returns False on failure
        self.assertFalse(result)
        
        # Test with empty path
        mock_get_connection.return_value = MagicMock()  # Restore connection
        result = create_attack_path_graph({"path": []})
        
        # Should return False for empty path
        self.assertFalse(result)
        
if __name__ == '__main__':
    unittest.main()
