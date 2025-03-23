import os
import gym
import numpy as np
import logging
import json
import pickle
import time
import random
from datetime import datetime
from gym import spaces
from stable_baselines3 import PPO
from stable_baselines3.common.vec_env import DummyVecEnv
from stable_baselines3.common.evaluation import evaluate_policy
from stable_baselines3.common.callbacks import EvalCallback, CheckpointCallback
from config import Config

# Configure logging
logger = logging.getLogger(__name__)

class ThreatHuntingEnv(gym.Env):
    """
    Custom Environment for threat hunting using reinforcement learning.
    This environment simulates a network where the agent needs to identify and respond to threats.
    """
    metadata = {'render.modes': ['human']}
    
    def __init__(self, logs=None):
        super(ThreatHuntingEnv, self).__init__()
        
        # Load logs if provided, otherwise generate simulated logs
        self.logs = logs if logs is not None else []
        if not self.logs:
            try:
                from log_generator import generate_suricata_logs
                self.logs = generate_suricata_logs(100)
            except Exception as e:
                logger.error(f"Error generating logs for RL environment: {e}")
                # Create minimal dummy logs if generation fails
                self.logs = [
                    {
                        "timestamp": datetime.utcnow(),
                        "log_type": "Suricata",
                        "source_ip": "192.168.1.1",
                        "destination_ip": "8.8.8.8",
                        "protocol": "TCP",
                        "port": 80,
                        "alert_severity": 1,
                        "alert_message": "Test Alert"
                    }
                ]
        
        # Define the observation space
        # We'll use a combination of features extracted from logs
        # Features: alert_severity, is_internal_src, is_internal_dst, port_risk, protocol_risk
        self.observation_space = spaces.Box(
            low=np.array([0, 0, 0, 0, 0]), 
            high=np.array([5, 1, 1, 1, 1]),
            dtype=np.float32
        )
        
        # Define the action space
        # Actions: ignore, flag for review, block source, block destination, collect more data
        self.action_space = spaces.Discrete(5)
        
        # Environment state
        self.current_log_index = 0
        self.blocked_ips = set()
        self.flagged_logs = []
        self.data_collection_requests = []
        
        # Score tracking
        self.true_positives = 0
        self.false_positives = 0
        self.true_negatives = 0
        self.false_negatives = 0
        
        # Rewards
        self.rewards = {
            'true_positive': 10.0,  # Correctly identifying a threat
            'false_positive': -5.0,  # Incorrectly flagging a non-threat
            'true_negative': 1.0,   # Correctly ignoring a non-threat
            'false_negative': -10.0, # Missing a threat
            'block_malicious': 15.0, # Blocking a truly malicious IP
            'block_benign': -15.0,   # Blocking a benign IP
            'data_collection': 0.5,  # Reward for collecting more data (small positive)
            'step_penalty': -0.1     # Small penalty for each step to encourage efficiency
        }

    def reset(self):
        """
        Reset the environment to its initial state.
        
        Returns:
            numpy.ndarray: Initial observation
        """
        # Reset environment state
        self.current_log_index = 0
        self.blocked_ips = set()
        self.flagged_logs = []
        self.data_collection_requests = []
        
        # Reset score tracking
        self.true_positives = 0
        self.false_positives = 0
        self.true_negatives = 0
        self.false_negatives = 0
        
        # Shuffle logs for variety
        random.shuffle(self.logs)
        
        # Return initial observation
        return self._get_observation()

    def step(self, action):
        """
        Take a step in the environment by performing the selected action.
        
        Args:
            action (int): The action to take
            
        Returns:
            tuple: (observation, reward, done, info)
        """
        # Get current log and determine if it's actually a threat
        current_log = self.logs[self.current_log_index]
        is_threat = self._is_actual_threat(current_log)
        
        # Initialize reward
        reward = self.rewards['step_penalty']  # Small penalty for each step
        info = {}
        
        # Process action
        if action == 0:  # Ignore
            if is_threat:
                reward += self.rewards['false_negative']
                self.false_negatives += 1
            else:
                reward += self.rewards['true_negative']
                self.true_negatives += 1
                
        elif action == 1:  # Flag for review
            self.flagged_logs.append(current_log)
            if is_threat:
                reward += self.rewards['true_positive']
                self.true_positives += 1
            else:
                reward += self.rewards['false_positive']
                self.false_positives += 1
                
        elif action == 2:  # Block source IP
            self.blocked_ips.add(current_log['source_ip'])
            # Determine if this is a good block
            if is_threat and self._is_malicious_ip(current_log['source_ip']):
                reward += self.rewards['block_malicious']
            else:
                reward += self.rewards['block_benign']
                
        elif action == 3:  # Block destination IP
            self.blocked_ips.add(current_log['destination_ip'])
            # Determine if this is a good block
            if is_threat and self._is_malicious_ip(current_log['destination_ip']):
                reward += self.rewards['block_malicious']
            else:
                reward += self.rewards['block_benign']
                
        elif action == 4:  # Collect more data
            self.data_collection_requests.append(current_log)
            reward += self.rewards['data_collection']
        
        # Move to the next log
        self.current_log_index += 1
        done = self.current_log_index >= len(self.logs)
        
        # Get new observation
        obs = self._get_observation() if not done else np.zeros(self.observation_space.shape)
        
        # Add additional info for monitoring
        info = {
            'true_positives': self.true_positives,
            'false_positives': self.false_positives,
            'true_negatives': self.true_negatives,
            'false_negatives': self.false_negatives,
            'f1_score': self._calculate_f1_score(),
            'precision': self._calculate_precision(),
            'recall': self._calculate_recall()
        }
        
        return obs, reward, done, info

    def render(self, mode='human'):
        """
        Render the current state of the environment.
        
        Args:
            mode (str): Rendering mode
        """
        if self.current_log_index < len(self.logs):
            log = self.logs[self.current_log_index]
            print(f"Log {self.current_log_index+1}/{len(self.logs)}")
            print(f"Alert: {log.get('alert_message', 'No message')}")
            print(f"Severity: {log.get('alert_severity', 'Unknown')}")
            print(f"Source IP: {log.get('source_ip', 'Unknown')} -> Destination IP: {log.get('destination_ip', 'Unknown')}")
            print(f"Blocked IPs: {len(self.blocked_ips)}")
            print(f"Flagged Logs: {len(self.flagged_logs)}")
            print(f"TP: {self.true_positives}, FP: {self.false_positives}, TN: {self.true_negatives}, FN: {self.false_negatives}")
            print(f"F1 Score: {self._calculate_f1_score():.4f}")
            print("-----------------------------------")

    def _get_observation(self):
        """
        Extract features from the current log to create an observation.
        
        Returns:
            numpy.ndarray: Observation vector
        """
        if self.current_log_index >= len(self.logs):
            return np.zeros(self.observation_space.shape)
        
        log = self.logs[self.current_log_index]
        
        # Extract features
        alert_severity = log.get('alert_severity', 0) / 5.0  # Normalize to [0, 1]
        
        is_internal_src = 0.0
        if log.get('source_ip'):
            is_internal_src = 1.0 if self._is_internal_ip(log['source_ip']) else 0.0
            
        is_internal_dst = 0.0
        if log.get('destination_ip'):
            is_internal_dst = 1.0 if self._is_internal_ip(log['destination_ip']) else 0.0
        
        port_risk = 0.0
        if log.get('port'):
            # Higher risk for certain ports
            high_risk_ports = [22, 23, 3389, 445, 1433, 3306]
            medium_risk_ports = [21, 25, 110, 143, 5060]
            if log['port'] in high_risk_ports:
                port_risk = 1.0
            elif log['port'] in medium_risk_ports:
                port_risk = 0.5
            elif log['port'] < 1024:
                port_risk = 0.3
                
        protocol_risk = 0.0
        if log.get('protocol'):
            protocol_risk = 0.7 if log['protocol'] == 'TCP' else 0.3
        
        return np.array([
            alert_severity * 5,  # Rescale to [0, 5]
            is_internal_src,
            is_internal_dst,
            port_risk,
            protocol_risk
        ], dtype=np.float32)

    def _is_actual_threat(self, log):
        """
        Determine if a log represents an actual threat.
        In a real environment, this would be based on ground truth.
        Here we'll simulate it based on log characteristics.
        
        Args:
            log (dict): The log entry
            
        Returns:
            bool: True if the log represents an actual threat
        """
        # Simulate ground truth based on alert severity and other heuristics
        if log.get('alert_severity', 0) >= 4:
            return True
        
        if log.get('alert_severity', 0) == 3:
            # 50% chance for severity 3 alerts to be real threats
            return random.random() < 0.5
            
        if log.get('alert_message') and any(kw in log['alert_message'] for kw in ['EXPLOIT', 'MALWARE', 'TROJAN', 'DATA']):
            return random.random() < 0.8
            
        # Check for known malicious IPs (simulated)
        if (log.get('source_ip') and self._is_malicious_ip(log['source_ip'])) or \
           (log.get('destination_ip') and self._is_malicious_ip(log['destination_ip'])):
            return random.random() < 0.9
            
        # Lower severity events
        return random.random() < 0.1

    def _is_internal_ip(self, ip):
        """
        Check if an IP is from an internal network.
        
        Args:
            ip (str): IP address
            
        Returns:
            bool: True if internal IP
        """
        # Simple check for common private IP ranges
        return ip.startswith(('10.', '192.168.', '172.16.', '172.17.', '172.18.', 
                             '172.19.', '172.20.', '172.21.', '172.22.', '172.23.',
                             '172.24.', '172.25.', '172.26.', '172.27.', '172.28.',
                             '172.29.', '172.30.', '172.31.'))

    def _is_malicious_ip(self, ip):
        """
        Simulate a check against a threat intelligence database.
        
        Args:
            ip (str): IP address
            
        Returns:
            bool: True if IP is known malicious
        """
        # Simulate some IPs being known malicious
        # In a real system, this would check against threat intelligence
        ip_sum = sum(int(octet) for octet in ip.split('.'))
        return ip_sum % 7 == 0  # Simple heuristic for simulation

    def _calculate_precision(self):
        """Calculate precision metric."""
        if self.true_positives + self.false_positives == 0:
            return 0.0
        return self.true_positives / (self.true_positives + self.false_positives)

    def _calculate_recall(self):
        """Calculate recall metric."""
        if self.true_positives + self.false_negatives == 0:
            return 0.0
        return self.true_positives / (self.true_positives + self.false_negatives)

    def _calculate_f1_score(self):
        """Calculate F1 score."""
        precision = self._calculate_precision()
        recall = self._calculate_recall()
        if precision + recall == 0:
            return 0.0
        return 2 * precision * recall / (precision + recall)

def train_agent(iterations=10000, session_id=None):
    """
    Train the reinforcement learning agent.
    
    Args:
        iterations (int): Number of training iterations
        session_id (int): ID of the training session
        
    Returns:
        dict: Training results
    """
    try:
        logger.info(f"Starting RL agent training with {iterations} iterations")
        
        # Create the environment
        def make_env():
            from log_generator import generate_suricata_logs
            logs = generate_suricata_logs(200)
            return ThreatHuntingEnv(logs=logs)
        
        env = DummyVecEnv([make_env])
        
        # Create evaluation environment
        eval_env = DummyVecEnv([make_env])
        
        # Set up model directory
        model_dir = os.path.join(Config.RL_MODEL_DIR, f"model_{session_id}")
        os.makedirs(model_dir, exist_ok=True)
        
        # Callbacks
        eval_callback = EvalCallback(
            eval_env,
            best_model_save_path=model_dir,
            log_path=model_dir,
            eval_freq=max(iterations // 10, 1),
            deterministic=True,
            render=False
        )
        
        checkpoint_callback = CheckpointCallback(
            save_freq=max(iterations // 5, 1),
            save_path=model_dir,
            name_prefix=f"ppo_threat_hunter_{session_id}"
        )
        
        # Initialize the agent with PPO algorithm
        model = PPO(
            "MlpPolicy", 
            env, 
            verbose=1,
            tensorboard_log=model_dir,
            learning_rate=0.0003
        )
        
        # Train the agent
        start_time = time.time()
        model.learn(
            total_timesteps=iterations,
            callback=[eval_callback, checkpoint_callback]
        )
        training_time = time.time() - start_time
        
        # Save the final model
        final_model_path = os.path.join(model_dir, f"final_model.zip")
        model.save(final_model_path)
        
        # Evaluate the trained model
        mean_reward, std_reward = evaluate_policy(model, eval_env, n_eval_episodes=10)
        
        # Save training stats
        stats = {
            "session_id": session_id,
            "iterations": iterations,
            "mean_reward": float(mean_reward),
            "std_reward": float(std_reward),
            "training_time": training_time,
            "model_path": final_model_path
        }
        
        with open(os.path.join(model_dir, "training_stats.json"), "w") as f:
            json.dump(stats, f, indent=2)
            
        logger.info(f"Training completed. Mean reward: {mean_reward:.2f} ± {std_reward:.2f}")
        
        return stats
        
    except Exception as e:
        logger.error(f"Error training RL agent: {e}")
        return {
            "session_id": session_id,
            "error": str(e),
            "final_reward": 0.0,
            "model_path": None
        }

def evaluate_agent(model_path=None):
    """
    Evaluate the performance of a trained RL agent.
    
    Args:
        model_path (str): Path to the trained model
        
    Returns:
        dict: Evaluation results
    """
    try:
        logger.info(f"Evaluating RL agent model: {model_path}")
        
        if not model_path or not os.path.exists(model_path):
            logger.error(f"Model file not found: {model_path}")
            return {"error": "Model file not found"}
        
        # Create evaluation environment with different data
        from log_generator import generate_suricata_logs
        eval_logs = generate_suricata_logs(100)
        
        # Also add multi-stage attack logs for more realistic evaluation
        from log_generator import generate_multi_stage_attack_logs
        attack_logs = generate_multi_stage_attack_logs(stages=3, logs_per_stage=5)
        eval_logs.extend(attack_logs)
        
        env = ThreatHuntingEnv(logs=eval_logs)
        
        # Load the trained model
        model = PPO.load(model_path)
        
        # Run evaluation
        episodes = 5
        results = {
            "episodes": episodes,
            "episode_data": [],
            "overall": {
                "true_positives": 0,
                "false_positives": 0,
                "true_negatives": 0,
                "false_negatives": 0,
                "precision": 0.0,
                "recall": 0.0,
                "f1_score": 0.0,
                "blocked_ips": 0,
                "flagged_logs": 0
            }
        }
        
        for episode in range(episodes):
            obs = env.reset()
            done = False
            episode_reward = 0
            steps = 0
            
            while not done:
                action, _ = model.predict(obs, deterministic=True)
                obs, reward, done, info = env.step(action)
                episode_reward += reward
                steps += 1
            
            # Collect episode data
            episode_data = {
                "episode": episode + 1,
                "reward": float(episode_reward),
                "steps": steps,
                "true_positives": env.true_positives,
                "false_positives": env.false_positives,
                "true_negatives": env.true_negatives,
                "false_negatives": env.false_negatives,
                "precision": env._calculate_precision(),
                "recall": env._calculate_recall(),
                "f1_score": env._calculate_f1_score(),
                "blocked_ips": len(env.blocked_ips),
                "flagged_logs": len(env.flagged_logs)
            }
            results["episode_data"].append(episode_data)
            
            # Accumulate overall stats
            results["overall"]["true_positives"] += env.true_positives
            results["overall"]["false_positives"] += env.false_positives
            results["overall"]["true_negatives"] += env.true_negatives
            results["overall"]["false_negatives"] += env.false_negatives
            results["overall"]["blocked_ips"] += len(env.blocked_ips)
            results["overall"]["flagged_logs"] += len(env.flagged_logs)
        
        # Calculate overall metrics
        tp = results["overall"]["true_positives"]
        fp = results["overall"]["false_positives"]
        fn = results["overall"]["false_negatives"]
        
        # Prevent division by zero
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
        
        results["overall"]["precision"] = precision
        results["overall"]["recall"] = recall
        results["overall"]["f1_score"] = f1
        
        logger.info(f"Evaluation completed. F1 Score: {f1:.4f}")
        
        return results
        
    except Exception as e:
        logger.error(f"Error evaluating RL agent: {e}")
        return {"error": str(e)}

if __name__ == "__main__":
    # Test the environment
    env = ThreatHuntingEnv()
    obs = env.reset()
    print(f"Observation shape: {obs.shape}")
    
    # Test a random action
    action = env.action_space.sample()
    obs, reward, done, info = env.step(action)
    print(f"Action: {action}, Reward: {reward}")
    env.render()
    
    # Test training with a small number of iterations
    result = train_agent(iterations=100, session_id=9999)
    print(f"Training result: {result}")
