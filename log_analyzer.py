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

def analyze_logs(logs, model_name="gpt-4o"):
    """
    Analyze security logs using GPT-4 via the OpenAI API.
    
    Args:
        logs (list): List of log dictionaries
        model_name (str): OpenAI model to use
        
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
        
        # Prepare logs for analysis
        log_text = format_logs_for_analysis(logs)
        
        # Create the system prompt for log analysis
        system_prompt = """You are an advanced cybersecurity threat analysis AI. You're tasked with analyzing security logs to identify potential threats, 
        attack patterns, and security incidents. Provide a concise analysis that includes:

        1. A summary of the key findings
        2. The overall threat level (Critical, High, Medium, Low, Informational)
        3. Specific attack patterns or techniques identified (with MITRE ATT&CK references if applicable)
        4. Recommended actions to respond to or mitigate the threats
        5. Potential attack paths if multiple related events are detected

        Focus on correlating events across logs to identify multi-stage attacks and provide context that would help security analysts prioritize their response.
        Format your response as a structured JSON object with the following keys: summary, threat_level, attack_patterns, recommended_actions, and attack_paths.
        """
        
        # Create the human message with logs
        human_prompt = f"""Analyze the following security logs and provide your assessment:

        {log_text}

        Provide your analysis in JSON format.
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
    Correlate related events to identify multi-stage attacks.
    
    Args:
        logs (list): List of log dictionaries
        
    Returns:
        list: Correlated event chains
    """
    try:
        # Sort logs by timestamp
        sorted_logs = sorted(logs, key=lambda x: x['timestamp'] if hasattr(x['timestamp'], 'strftime') else x['timestamp'])
        
        # Prepare logs for correlation analysis
        log_text = format_logs_for_analysis(sorted_logs)
        
        # Create the prompt for event correlation
        prompt = PromptTemplate(
            input_variables=["logs"],
            template="""
            You are a cybersecurity correlation analyst. Review these chronologically ordered security logs and identify related events that might constitute multi-stage attacks.
            For each correlated chain, provide:
            1. A name or description of the potential attack
            2. The log IDs that are part of this chain
            3. The attack stages in order (e.g., reconnaissance -> exploitation -> lateral movement)
            4. Overall severity assessment
            
            Logs:
            {logs}
            
            Format your response as a JSON array of correlated chains.
            """
        )
        
        # the newest OpenAI model is "gpt-4o" which was released May 13, 2024.
        # do not change this unless explicitly requested by the user
        chat_model = ChatOpenAI(
            model_name="gpt-4o",
            temperature=0.2,
            openai_api_key=OPENAI_API_KEY
        )
        
        # Create the chain
        chain = LLMChain(llm=chat_model, prompt=prompt)
        
        # Run the chain
        response = chain.run(logs=log_text)
        
        # Parse the response
        try:
            correlated_chains = json.loads(response)
            return correlated_chains
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
