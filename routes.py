import json
from flask import render_template, request, jsonify, redirect, url_for
from app import app, db
from models import Log, Analysis, AttackPath, RLAgentTraining
from log_generator import generate_suricata_logs
from log_analyzer import analyze_logs
from rl_agent import train_agent, evaluate_agent
from neo4j_visualizer import create_attack_path_graph, get_attack_paths
import logging

# Configure logging
logger = logging.getLogger(__name__)

@app.route('/')
def index():
    """Home page with dashboard overview."""
    log_count = Log.query.count()
    analysis_count = Analysis.query.count()
    attack_path_count = AttackPath.query.count()
    
    # Get latest analysis for threat summary
    latest_analysis = Analysis.query.order_by(Analysis.timestamp.desc()).first()
    
    # Get count of logs by severity for chart
    severity_counts = db.session.query(
        Log.alert_severity, 
        db.func.count(Log.id)
    ).group_by(Log.alert_severity).all()
    
    severity_data = {
        'labels': [f"Severity {level}" for level, _ in severity_counts],
        'data': [count for _, count in severity_counts]
    }
    
    return render_template(
        'index.html', 
        log_count=log_count,
        analysis_count=analysis_count,
        attack_path_count=attack_path_count,
        latest_analysis=latest_analysis,
        severity_data=json.dumps(severity_data)
    )

@app.route('/logs')
def logs():
    """Page to display and generate logs."""
    page = request.args.get('page', 1, type=int)
    logs = Log.query.order_by(Log.timestamp.desc()).paginate(page=page, per_page=20)
    return render_template('logs.html', logs=logs)

@app.route('/logs/generate', methods=['POST'])
def generate_logs():
    """Generate sample logs for the system."""
    count = request.form.get('count', 50, type=int)
    try:
        new_logs = generate_suricata_logs(count)
        for log in new_logs:
            db.session.add(Log(**log))
        db.session.commit()
        return redirect(url_for('logs'))
    except Exception as e:
        logger.error(f"Error generating logs: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/analysis')
def analysis():
    """Page to view log analyses."""
    page = request.args.get('page', 1, type=int)
    analyses = Analysis.query.order_by(Analysis.timestamp.desc()).paginate(page=page, per_page=10)
    return render_template('analysis.html', analyses=analyses)

@app.route('/analysis/run', methods=['POST'])
def run_analysis():
    """Trigger log analysis using LangChain + GPT-4."""
    try:
        # Get logs for analysis (either all or filtered by time/severity)
        hours = request.form.get('hours', 24, type=int)
        min_severity = request.form.get('min_severity', 1, type=int)
        
        # Query logs based on filters
        from datetime import datetime, timedelta
        since = datetime.utcnow() - timedelta(hours=hours)
        
        logs = Log.query.filter(
            Log.timestamp >= since,
            Log.alert_severity >= min_severity
        ).all()
        
        if not logs:
            return jsonify({"error": "No logs found matching criteria"}), 404
        
        # Convert logs to the format expected by analyzer
        log_dicts = [
            {
                'id': log.id,
                'timestamp': log.timestamp.isoformat(),
                'log_type': log.log_type,
                'source_ip': log.source_ip,
                'destination_ip': log.destination_ip,
                'protocol': log.protocol,
                'port': log.port,
                'alert_severity': log.alert_severity,
                'alert_message': log.alert_message,
                'raw_log': log.raw_log
            }
            for log in logs
        ]
        
        # Run analysis
        analysis_result = analyze_logs(log_dicts)
        
        # Save analysis to database
        new_analysis = Analysis(
            summary=analysis_result['summary'],
            threat_level=analysis_result['threat_level'],
            recommended_actions=analysis_result['recommended_actions'],
            log_ids=','.join([str(log.id) for log in logs])
        )
        db.session.add(new_analysis)
        
        # Create attack paths if any were found
        if 'attack_paths' in analysis_result and analysis_result['attack_paths']:
            for path in analysis_result['attack_paths']:
                new_path = AttackPath(
                    path_data=json.dumps(path['path']),
                    severity=path['severity'],
                    description=path['description'],
                    analysis_id=new_analysis.id
                )
                db.session.add(new_path)
                
                # Create Neo4j visualization
                create_attack_path_graph(path)
        
        db.session.commit()
        return redirect(url_for('analysis'))
    
    except Exception as e:
        logger.error(f"Error running analysis: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/rl_agent')
def rl_agent_dashboard():
    """Page for RL agent training and evaluation."""
    # Get training sessions
    training_sessions = RLAgentTraining.query.order_by(RLAgentTraining.start_time.desc()).limit(5).all()
    
    # Get latest training metrics if available
    latest_session = RLAgentTraining.query.order_by(RLAgentTraining.start_time.desc()).first()
    
    return render_template(
        'rl_agent.html',
        training_sessions=training_sessions,
        latest_session=latest_session
    )

@app.route('/rl_agent/train', methods=['POST'])
def train_rl_agent():
    """Train the RL agent with specified parameters."""
    try:
        iterations = request.form.get('iterations', 100, type=int)
        
        # Create training session record
        training_session = RLAgentTraining(iterations=iterations)
        db.session.add(training_session)
        db.session.commit()
        
        # Train the agent
        training_result = train_agent(iterations=iterations, session_id=training_session.id)
        
        # Update training session with results
        training_session.end_time = datetime.utcnow()
        training_session.reward = training_result['final_reward']
        training_session.model_path = training_result['model_path']
        db.session.commit()
        
        return redirect(url_for('rl_agent_dashboard'))
    
    except Exception as e:
        logger.error(f"Error training RL agent: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/rl_agent/evaluate', methods=['POST'])
def evaluate_rl_agent():
    """Evaluate the RL agent on current data."""
    try:
        # Get session ID to use model from
        session_id = request.form.get('session_id', type=int)
        
        if not session_id:
            latest_session = RLAgentTraining.query.filter(RLAgentTraining.model_path.isnot(None)).order_by(RLAgentTraining.end_time.desc()).first()
            if not latest_session:
                return jsonify({"error": "No trained model available"}), 404
            session_id = latest_session.id
        
        # Get the training session
        training_session = RLAgentTraining.query.get(session_id)
        if not training_session or not training_session.model_path:
            return jsonify({"error": "Training session has no model"}), 404
        
        # Evaluate agent
        evaluation_result = evaluate_agent(model_path=training_session.model_path)
        
        return jsonify(evaluation_result)
    
    except Exception as e:
        logger.error(f"Error evaluating RL agent: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/visualization')
def visualization():
    """Page for attack path visualization."""
    # Get all attack paths
    attack_paths = AttackPath.query.order_by(AttackPath.timestamp.desc()).all()
    
    # Get Neo4j graph data
    neo4j_paths = get_attack_paths()
    
    return render_template(
        'visualization.html',
        attack_paths=attack_paths,
        neo4j_paths=json.dumps(neo4j_paths)
    )

@app.route('/visualization/<int:path_id>')
def view_path(path_id):
    """View a specific attack path."""
    attack_path = AttackPath.query.get_or_404(path_id)
    
    # Get Neo4j visualization data for this path
    path_data = json.loads(attack_path.path_data)
    neo4j_path = get_attack_paths(path_id=path_id)
    
    return render_template(
        'visualization.html',
        attack_path=attack_path,
        path_data=path_data,
        neo4j_path=json.dumps(neo4j_path)
    )
