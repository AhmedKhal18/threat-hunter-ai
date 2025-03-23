import os

# Application configuration
class Config:
    # General Config
    DEBUG = True
    SECRET_KEY = os.environ.get('SESSION_SECRET', 'dev_secret_key')
    
    # Database
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL', 'sqlite:///autonomous_threat_hunter.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # OpenAI API
    OPENAI_API_KEY = os.environ.get('OPENAI_API_KEY')
    
    # Neo4j Configuration
    NEO4J_URI = os.environ.get('NEO4J_URI', 'bolt://localhost:7687')
    NEO4J_USER = os.environ.get('NEO4J_USER', 'neo4j')
    NEO4J_PASSWORD = os.environ.get('NEO4J_PASSWORD', 'password')
    
    # RL Agent Configuration
    RL_MODEL_DIR = os.environ.get('RL_MODEL_DIR', './rl_models')
    
    # Log Configuration
    LOG_TYPES = ['Suricata', 'Firewall', 'Windows', 'Linux', 'Web Server']
    LOG_SEVERITIES = [1, 2, 3, 4, 5]  # 1 is lowest, 5 is highest
    
    # Sample IP ranges for simulation
    INTERNAL_IP_RANGES = ['192.168.1.0/24', '10.0.0.0/16']
    EXTERNAL_IP_RANGES = ['203.0.113.0/24', '198.51.100.0/24']
    
    # Common ports for simulation
    COMMON_PORTS = {
        'HTTP': 80,
        'HTTPS': 443,
        'SSH': 22,
        'FTP': 21,
        'SMB': 445,
        'RDP': 3389,
        'DNS': 53,
        'SMTP': 25,
        'SQL': 1433
    }
