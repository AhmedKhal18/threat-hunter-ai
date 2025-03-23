import os
import json
import logging
from config import Config

# Configure logging
logger = logging.getLogger(__name__)

# Initialize OpenAI API key
OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY", Config.OPENAI_API_KEY)

# Initialize OpenAI client
openai_client = None
if OPENAI_API_KEY:
    try:
        import openai
        openai_client = openai.OpenAI(api_key=OPENAI_API_KEY)
        logger.info("OpenAI client initialized successfully")
    except ImportError:
        logger.error("Failed to import openai package")
    except Exception as e:
        logger.error(f"Error initializing OpenAI client: {e}")
else:
    logger.warning("OpenAI API key not found")

def analyze_logs(logs, model_name="gpt-4o", use_threat_intel=True):
    """
    Analyze security logs using GPT-4 via the OpenAI API and threat intelligence.
    
    Args:
        logs (list): List of log dictionaries
        model_name (str): OpenAI model to use
        use_threat_intel (bool): Whether to enhance analysis with threat intelligence
        
    Returns:
        dict: Analysis results including summary, threat level, and recommendations
    """
    try:
        if not OPENAI_API_KEY or not openai_client:
            logger.error("OpenAI API key not found")
            return {
                "summary": "Error: OpenAI API key not configured",
                "threat_level": "Unknown",
                "recommended_actions": "Configure OpenAI API key to enable analysis",
                "error": "API key missing"
            }
        
        # Run threat intelligence analysis if enabled
        threat_intel_results = None
        if use_threat_intel:
            try:
                from threat_intelligence import detect_threats_in_logs, suggest_mitigations, correlate_with_global_threats
                threat_intel_results = detect_threats_in_logs(logs)
                logger.info(f"Threat intelligence detected {len(threat_intel_results)} potential threats")
            except ImportError:
                logger.warning("Threat intelligence module not available")
            except Exception as e:
                logger.error(f"Error in threat intelligence analysis: {e}")
                
        # Prepare logs for analysis
        log_text = format_logs_for_analysis(logs)
        
        # Add threat intel findings to the prompt if available
        threat_intel_text = ""
        if threat_intel_results:
            threat_intel_text = "Threat Intelligence Findings:\n\n"
            for i, threat in enumerate(threat_intel_results, 1):
                threat_intel_text += f"Threat #{i}:\n"
                threat_intel_text += f"  Type: {threat.get('threat_type', 'Unknown')}\n"
                threat_intel_text += f"  Indicator: {threat.get('indicator', 'Unknown')}\n"
                threat_intel_text += f"  Confidence: {threat.get('confidence', 'Unknown')}\n"
                threat_intel_text += f"  Suggested Action: {threat.get('action', 'Investigate')}\n"
                if 'details' in threat and isinstance(threat['details'], dict):
                    for k, v in threat['details'].items():
                        if k != 'indicators' and not isinstance(v, (dict, list)):
                            threat_intel_text += f"  {k}: {v}\n"
                threat_intel_text += "\n"
        
        # Create the system prompt for log analysis
        system_prompt = """You are an advanced cybersecurity threat analysis AI with expertise in MITRE ATT&CK framework, 
        malware analysis, and network security. You're tasked with analyzing security logs and threat intelligence to identify 
        potential threats, attack patterns, and security incidents. Provide a comprehensive analysis that includes:

        1. A summary of the key findings
        2. The overall threat level (Critical, High, Medium, Low, Informational)
        3. Specific attack patterns or techniques identified (with MITRE ATT&CK references including technique IDs)
        4. Recommended actions to respond to or mitigate the threats, prioritized by urgency
        5. Potential attack paths if multiple related events are detected, including likely entry points and targets
        6. Adversary tactics and techniques observed, mapped to the MITRE ATT&CK framework

        Focus on correlating events across logs to identify multi-stage attacks and provide context that would help security analysts prioritize their response.
        Consider threat intelligence findings when determining threat severity and recommendations.
        
        Format your response as a structured JSON object with the following keys: 
        summary, threat_level, attack_patterns, recommended_actions, attack_paths, and adversary_tactics.
        """
        
        # Create the human message with logs and threat intel
        human_prompt = f"""Analyze the following security logs and threat intelligence findings:

        === SECURITY LOGS ===
        {log_text}

        {threat_intel_text if threat_intel_text else ""}
        
        Provide your analysis in JSON format. Be specific in your recommendations and include MITRE ATT&CK technique IDs where relevant.
        """
        
        # the newest OpenAI model is "gpt-4o" which was released May 13, 2024.
        # do not change this unless explicitly requested by the user
        response = openai_client.chat.completions.create(
            model=model_name,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": human_prompt}
            ],
            temperature=0.3,
            response_format={"type": "json_object"}
        )
        
        # Parse the JSON response
        try:
            content = response.choices[0].message.content
            analysis_result = json.loads(content)
            logger.info("Successfully analyzed logs with GPT-4")
            
            # Enhance with global threat intelligence if available
            if use_threat_intel and 'correlate_with_global_threats' in globals():
                try:
                    enhanced_result = correlate_with_global_threats(analysis_result)
                    logger.info("Enhanced analysis with global threat intelligence")
                    analysis_result = enhanced_result
                except Exception as e:
                    logger.error(f"Error enhancing analysis with global threats: {e}")
            
            # Add threat intelligence findings to the result
            if threat_intel_results:
                analysis_result['threat_intel_findings'] = threat_intel_results
                
                # Add mitigation suggestions from threat intelligence
                try:
                    mitigations = suggest_mitigations(threat_intel_results)
                    if mitigations:
                        analysis_result['mitigation_suggestions'] = mitigations
                        logger.info("Added mitigation suggestions from threat intelligence")
                except Exception as e:
                    logger.error(f"Error generating mitigation suggestions: {e}")
            
            return analysis_result
            
        except json.JSONDecodeError:
            logger.error("Failed to parse GPT-4 response as JSON")
            # Try to extract a JSON object if it's embedded in other text
            text = content
            try:
                # Find JSON-like content between curly braces
                start_idx = text.find('{')
                end_idx = text.rfind('}') + 1
                if start_idx >= 0 and end_idx > start_idx:
                    json_str = text[start_idx:end_idx]
                    analysis_result = json.loads(json_str)
                    logger.info("Successfully extracted JSON from GPT-4 response")
                    return analysis_result
            except:
                pass
            
            # Return a fallback analysis
            return {
                "summary": text[:500] + "...",  # Truncate if too long
                "threat_level": "Unknown",
                "recommended_actions": "Error in AI response format. Please review the raw analysis.",
                "raw_analysis": text
            }
            
    except Exception as e:
        logger.error(f"Error analyzing logs: {e}")
        return {
            "summary": f"Error analyzing logs: {str(e)}",
            "threat_level": "Error",
            "recommended_actions": "Check the system logs for more information",
            "error": str(e)
        }

def format_logs_for_analysis(logs):
    """
    Format logs into a readable text format for analysis.
    
    Args:
        logs (list): List of log dictionaries
        
    Returns:
        str: Formatted log text
    """
    formatted_logs = []
    
    for i, log in enumerate(logs, 1):
        # Format timestamp if it's a datetime object
        timestamp = log['timestamp']
        if hasattr(timestamp, 'strftime'):
            timestamp = timestamp.strftime("%Y-%m-%d %H:%M:%S")
            
        log_str = f"Log #{i}:\n"
        log_str += f"  Timestamp: {timestamp}\n"
        log_str += f"  Type: {log['log_type']}\n"
        log_str += f"  Source IP: {log['source_ip']}\n"
        log_str += f"  Destination IP: {log['destination_ip']}\n"
        log_str += f"  Protocol: {log['protocol']}\n"
        
        if log.get('port'):
            log_str += f"  Port: {log['port']}\n"
            
        log_str += f"  Severity: {log['alert_severity']}\n"
        log_str += f"  Alert: {log['alert_message']}\n"
        
        # Add raw log details if needed
        if 'raw_log' in log and log['raw_log']:
            try:
                # Try to parse the raw log if it's a JSON string
                raw_data = json.loads(log['raw_log'])
                # Add select relevant fields from raw log
                if 'alert' in raw_data and 'category' in raw_data['alert']:
                    log_str += f"  Category: {raw_data['alert']['category']}\n"
                if 'http' in raw_data and raw_data['http']:
                    log_str += f"  HTTP: Method: {raw_data['http'].get('http_method')}, URL: {raw_data['http'].get('url')}\n"
                if 'flow' in raw_data:
                    log_str += f"  Flow: Packets: {raw_data['flow'].get('pkts_toserver')} to server, {raw_data['flow'].get('pkts_toclient')} to client\n"
            except (json.JSONDecodeError, TypeError):
                # If parsing fails, just note that raw log is available
                log_str += "  Raw log data available but not displayed\n"
        
        formatted_logs.append(log_str)
    
    return "\n".join(formatted_logs)

def identify_attack_patterns(logs):
    """
    Use OpenAI API to identify specific attack patterns in logs.
    
    Args:
        logs (list): List of log dictionaries
        
    Returns:
        list: Identified attack patterns
    """
    try:
        if not OPENAI_API_KEY or not openai_client:
            logger.error("OpenAI API key not found")
            return [{"pattern": "Error", "confidence": "Low", "evidence": "OpenAI API key not configured"}]
        
        # Format logs
        log_text = format_logs_for_analysis(logs)
        
        # Create the system prompt for pattern recognition
        system_prompt = """You are a cybersecurity pattern recognition expert. Review these security logs and identify specific attack patterns or techniques.
        For each pattern, provide:
        1. Pattern name and MITRE ATT&CK technique ID if applicable
        2. Confidence level (Low, Medium, High)
        3. Supporting evidence from the logs
        4. Potential false positive considerations
        
        Format your response as a JSON array of identified patterns.
        """
        
        # Create the human message with logs
        human_prompt = f"""Review these security logs and identify specific attack patterns:

        {log_text}
        
        Provide your analysis as a JSON array.
        """
        
        # the newest OpenAI model is "gpt-4o" which was released May 13, 2024.
        # do not change this unless explicitly requested by the user
        response = openai_client.chat.completions.create(
            model="gpt-4o",
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": human_prompt}
            ],
            temperature=0.2,
            response_format={"type": "json_object"}
        )
        
        # Parse the response
        try:
            content = response.choices[0].message.content
            patterns = json.loads(content)
            # If it's a nested JSON object with a patterns key, extract just the patterns
            if isinstance(patterns, dict) and "patterns" in patterns:
                patterns = patterns["patterns"]
            return patterns
        except json.JSONDecodeError:
            logger.error("Failed to parse pattern recognition response as JSON")
            return [{"pattern": "Error parsing response", "confidence": "Low", "evidence": content[:100] + "..."}]
        
    except Exception as e:
        logger.error(f"Error identifying attack patterns: {e}")
        return [{"pattern": "Error in pattern analysis", "error": str(e)}]

def correlate_events(logs):
    """
    Correlate related events to identify multi-stage attacks using OpenAI API.
    
    Args:
        logs (list): List of log dictionaries
        
    Returns:
        list: Correlated event chains
    """
    try:
        if not OPENAI_API_KEY or not openai_client:
            logger.error("OpenAI API key not found")
            return [{"attack": "Error", "logs": "unknown", "stages": ["unknown"], "severity": "unknown"}]
        
        # Sort logs by timestamp
        sorted_logs = sorted(logs, key=lambda x: x['timestamp'] if hasattr(x['timestamp'], 'strftime') else x['timestamp'])
        
        # Prepare logs for correlation analysis
        log_text = format_logs_for_analysis(sorted_logs)
        
        # Create the system prompt for correlation analysis
        system_prompt = """You are a cybersecurity correlation analyst. Review these chronologically ordered security logs and identify related events that might constitute multi-stage attacks.
        For each correlated chain, provide:
        1. A name or description of the potential attack
        2. The log IDs that are part of this chain
        3. The attack stages in order (e.g., reconnaissance -> exploitation -> lateral movement)
        4. Overall severity assessment
        
        Format your response as a JSON array of correlated chains.
        """
        
        # Create the human message with logs
        human_prompt = f"""Review these chronologically ordered security logs and identify related events:

        {log_text}
        
        Provide your analysis as a JSON array of attack chains.
        """
        
        # the newest OpenAI model is "gpt-4o" which was released May 13, 2024.
        # do not change this unless explicitly requested by the user
        response = openai_client.chat.completions.create(
            model="gpt-4o",
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": human_prompt}
            ],
            temperature=0.2,
            response_format={"type": "json_object"}
        )
        
        # Parse the response
        try:
            content = response.choices[0].message.content
            chains = json.loads(content)
            # If it's a nested JSON object with a chains/correlations key, extract just the chains
            if isinstance(chains, dict):
                if "chains" in chains:
                    chains = chains["chains"]
                elif "correlations" in chains:
                    chains = chains["correlations"]
                elif "attacks" in chains:
                    chains = chains["attacks"]
            return chains
        except json.JSONDecodeError:
            logger.error("Failed to parse event correlation response as JSON")
            # Return a fallback response
            return [{"attack": "Error parsing response", "logs": "unknown", "stages": ["unknown"], "severity": "unknown"}]
        
    except Exception as e:
        logger.error(f"Error correlating events: {e}")
        return [{"attack": "Error in correlation analysis", "error": str(e)}]

if __name__ == "__main__":
    # Test with some sample logs
    from log_generator import generate_suricata_logs
    sample_logs = generate_suricata_logs(5)
    analysis = analyze_logs(sample_logs)
    print(json.dumps(analysis, indent=2))
