from datetime import datetime
from app import db

class Log(db.Model):
    """Model representing a security log entry."""
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    log_type = db.Column(db.String(50), nullable=False)
    source_ip = db.Column(db.String(50))
    destination_ip = db.Column(db.String(50))
    protocol = db.Column(db.String(10))
    port = db.Column(db.Integer)
    alert_severity = db.Column(db.Integer)
    alert_message = db.Column(db.String(255))
    raw_log = db.Column(db.Text)

    def __repr__(self):
        return f"<Log {self.id}: {self.alert_message}>"

class Analysis(db.Model):
    """Model representing GPT analysis of logs."""
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    summary = db.Column(db.Text)
    threat_level = db.Column(db.String(20))
    recommended_actions = db.Column(db.Text)
    log_ids = db.Column(db.Text)  # Comma-separated list of log IDs that were analyzed
    
    def __repr__(self):
        return f"<Analysis {self.id}: {self.threat_level}>"

class AttackPath(db.Model):
    """Model representing a discovered attack path."""
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    path_data = db.Column(db.Text)  # JSON representation of path
    severity = db.Column(db.String(20))
    description = db.Column(db.Text)
    analysis_id = db.Column(db.Integer, db.ForeignKey('analysis.id'))
    
    def __repr__(self):
        return f"<AttackPath {self.id}: {self.severity}>"

class RLAgentTraining(db.Model):
    """Model for tracking RL agent training sessions."""
    id = db.Column(db.Integer, primary_key=True)
    start_time = db.Column(db.DateTime, default=datetime.utcnow)
    end_time = db.Column(db.DateTime, nullable=True)
    iterations = db.Column(db.Integer, default=0)
    reward = db.Column(db.Float, default=0.0)
    model_path = db.Column(db.String(255), nullable=True)
    
    def __repr__(self):
        return f"<RLAgentTraining {self.id}: {self.iterations} iterations>"
