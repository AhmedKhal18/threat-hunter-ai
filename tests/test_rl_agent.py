import unittest
import sys
import os
import tempfile
import shutil
import numpy as np
from unittest.mock import patch, MagicMock

# Add project root to Python path to import modules
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from rl_agent import (
    ThreatHuntingEnv, 
    train_agent, 
    evaluate_agent
)

class TestRLAgent(unittest.TestCase):
    """Test the reinforcement learning agent functionality."""
    
    def setUp(self):
        """Set up test fixtures."""
        # Create a temporary directory for models
        self.test_model_dir = tempfile.mkdtemp()
        
        # Create sample logs for the environment
        self.sample_logs = [
            {
                'timestamp': '2023-01-01T10:00:00',
                'log_type': 'Suricata',
                'source_ip': '203.0.113.10',
                'destination_ip': '192.168.1.100',
                'protocol': 'TCP',
                'port': 22,
                'alert_severity': 2,
                'alert_message': 'ET SCAN Nmap Scripting Engine User-Agent Detected'
            },
            {
                'timestamp': '2023-01-01T10:05:00',
                'log_type': 'Suricata',
                'source_ip': '203.0.113.10',
                'destination_ip': '192.168.1.100',
                'protocol': 'TCP',
                'port': 22,
                'alert_severity': 3,
                'alert_message': 'ET POLICY SSH Brute Force Attempt'
            },
            {
                'timestamp': '2023-01-01T10:10:00',
                'log_type': 'Suricata',
                'source_ip': '192.168.1.100',
                'destination_ip': '203.0.113.50',
                'protocol': 'TCP',
                'port': 443,
                'alert_severity': 5,
                'alert_message': 'ET TROJAN DATA Exfiltration'
            }
        ]
        
    def tearDown(self):
        """Clean up after tests."""
        # Remove the temporary directory
        shutil.rmtree(self.test_model_dir)
        
    def test_environment_initialization(self):
        """Test that the RL environment initializes correctly."""
        env = ThreatHuntingEnv(logs=self.sample_logs)
        
        # Check observation space
        self.assertEqual(env.observation_space.shape, (5,))
        
        # Check action space
        self.assertEqual(env.action_space.n, 5)
        
        # Check initial state
        self.assertEqual(env.current_log_index, 0)
        self.assertEqual(len(env.blocked_ips), 0)
        self.assertEqual(len(env.flagged_logs), 0)
        
    def test_environment_reset(self):
        """Test the environment reset function."""
        env = ThreatHuntingEnv(logs=self.sample_logs)
        
        # Make some changes to the environment
        env.current_log_index = 2
        env.blocked_ips.add('192.168.1.1')
        env.flagged_logs.append(self.sample_logs[0])
        
        # Reset the environment
        obs = env.reset()
        
        # Check that the state was reset
        self.assertEqual(env.current_log_index, 0)
        self.assertEqual(len(env.blocked_ips), 0)
        self.assertEqual(len(env.flagged_logs), 0)
        
        # Check that observation is the right shape
        self.assertEqual(obs.shape, (5,))
        self.assertTrue(np.all(obs >= 0))
        
    def test_environment_step(self):
        """Test the environment step function."""
        env = ThreatHuntingEnv(logs=self.sample_logs)
        
        # Take a step with action 1 (flag for review)
        obs, reward, done, info = env.step(1)
        
        # Check that the state changed correctly
        self.assertEqual(env.current_log_index, 1)
        self.assertEqual(len(env.flagged_logs), 1)
        
        # Check that observation is valid
        self.assertEqual(obs.shape, (5,))
        
        # Check that info contains metrics
        self.assertIn('true_positives', info)
        self.assertIn('false_positives', info)
        self.assertIn('f1_score', info)
        
        # Take steps until done
        while not done:
            obs, reward, done, info = env.step(0)  # Action 0 = ignore
            
        # Should be done after processing all logs
        self.assertTrue(done)
        
    def test_metric_calculations(self):
        """Test the metric calculation methods in the environment."""
        env = ThreatHuntingEnv(logs=self.sample_logs)
        
        # Setup some metrics
        env.true_positives = 5
        env.false_positives = 2
        env.true_negatives = 10
        env.false_negatives = 1
        
        # Calculate metrics
        precision = env._calculate_precision()
        recall = env._calculate_recall()
        f1 = env._calculate_f1_score()
        
        # Check calculations
        self.assertAlmostEqual(precision, 5 / 7)
        self.assertAlmostEqual(recall, 5 / 6)
        self.assertAlmostEqual(f1, 2 * precision * recall / (precision + recall))
        
    @patch('rl_agent.PPO')
    @patch('rl_agent.DummyVecEnv')
    @patch('rl_agent.EvalCallback')
    @patch('rl_agent.CheckpointCallback')
    def test_train_agent(self, mock_checkpoint, mock_eval, mock_vec_env, mock_ppo):
        """Test the train_agent function with mocked dependencies."""
        # Configure the mocks
        mock_model = MagicMock()
        mock_ppo.return_value = mock_model
        
        mock_env = MagicMock()
        mock_vec_env.return_value = mock_env
        
        # Set up the model dir for testing
        with patch('rl_agent.Config.RL_MODEL_DIR', self.test_model_dir):
            # Call the function
            result = train_agent(iterations=100, session_id=999)
        
        # Check that the function called the expected components
        mock_ppo.assert_called_once()
        mock_model.learn.assert_called_once()
        mock_model.save.assert_called_once()
        
        # Check the result
        self.assertIn('session_id', result)
        self.assertIn('iterations', result)
        self.assertIn('model_path', result)
        
    @patch('rl_agent.PPO')
    def test_evaluate_agent(self, mock_ppo):
        """Test the evaluate_agent function with mocked dependencies."""
        # Create a dummy model file
        model_path = os.path.join(self.test_model_dir, "test_model.zip")
        with open(model_path, 'w') as f:
            f.write("dummy model")
            
        # Configure the mocks
        mock_model = MagicMock()
        mock_ppo.load.return_value = mock_model
        
        mock_model.predict.return_value = (0, None)  # Action 0, no state
        
        # Create a patch for the environment
        with patch('rl_agent.ThreatHuntingEnv') as mock_env_class:
            mock_env = MagicMock()
            mock_env_class.return_value = mock_env
            
            # Configure the environment mock
            mock_env.reset.return_value = np.zeros(5)
            mock_env.step.return_value = (np.zeros(5), 1.0, False, {})
            mock_env.step.side_effect = [
                (np.zeros(5), 1.0, False, {}),
                (np.zeros(5), 0.5, True, {
                    'true_positives': 3,
                    'false_positives': 1,
                    'true_negatives': 5,
                    'false_negatives': 2
                })
            ]
            
            # Call the function
            result = evaluate_agent(model_path=model_path)
        
        # Check that the function loaded the model
        mock_ppo.load.assert_called_once_with(model_path)
        
        # Check the result
        self.assertIn('episodes', result)
        self.assertIn('overall', result)
        self.assertIn('true_positives', result['overall'])
        
    def test_evaluate_agent_missing_model(self):
        """Test that evaluate_agent handles missing model files."""
        # Call with a non-existent model path
        result = evaluate_agent(model_path="non_existent_model.zip")
        
        # Should return an error
        self.assertIn('error', result)
        
if __name__ == '__main__':
    unittest.main()
