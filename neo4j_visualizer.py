import os
import logging
import json
from datetime import datetime
from py2neo import Graph, Node, Relationship
from config import Config

# Configure logging
logger = logging.getLogger(__name__)

# Neo4j connection parameters from environment or config
NEO4J_URI = os.environ.get("NEO4J_URI", Config.NEO4J_URI)
NEO4J_USER = os.environ.get("NEO4J_USER", Config.NEO4J_USER)
NEO4J_PASSWORD = os.environ.get("NEO4J_PASSWORD", Config.NEO4J_PASSWORD)

def get_neo4j_connection():
    """
    Establish connection to Neo4j database.
    
    Returns:
        Graph: Neo4j graph connection or None if failed
    """
    try:
        graph = Graph(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))
        logger.info("Connected to Neo4j database")
        return graph
    except Exception as e:
        logger.error(f"Error connecting to Neo4j: {e}")
        return None

def init_neo4j_schema():
    """
    Initialize Neo4j with necessary constraints and indexes.
    
    Returns:
        bool: True if successful, False otherwise
    """
    try:
        graph = get_neo4j_connection()
        if not graph:
            return False
        
        # Create constraints
        graph.run("CREATE CONSTRAINT IF NOT EXISTS ON (i:IP) ASSERT i.address IS UNIQUE")
        graph.run("CREATE CONSTRAINT IF NOT EXISTS ON (h:Host) ASSERT h.name IS UNIQUE")
        graph.run("CREATE CONSTRAINT IF NOT EXISTS ON (p:Path) ASSERT p.id IS UNIQUE")
        
        # Create indexes
        graph.run("CREATE INDEX IF NOT EXISTS FOR (i:IP) ON (i.address)")
        graph.run("CREATE INDEX IF NOT EXISTS FOR (h:Host) ON (h.name)")
        graph.run("CREATE INDEX IF NOT EXISTS FOR (p:Path) ON (p.id)")
        
        logger.info("Neo4j schema initialized successfully")
        return True
    except Exception as e:
        logger.error(f"Error initializing Neo4j schema: {e}")
        return False

def create_attack_path_graph(path_data):
    """
    Create a Neo4j graph representation of an attack path.
    
    Args:
        path_data (dict): Attack path data
        
    Returns:
        bool: True if successful, False otherwise
    """
    try:
        graph = get_neo4j_connection()
        if not graph:
            return False
        
        # Ensure schema is initialized
        init_neo4j_schema()
        
        # Extract path information
        path = path_data.get("path", [])
        severity = path_data.get("severity", "Medium")
        description = path_data.get("description", "Unknown attack path")
        
        if not path:
            logger.warning("Empty attack path provided")
            return False
        
        # Create a unique path ID
        path_id = f"path_{datetime.now().strftime('%Y%m%d%H%M%S')}_{hash(str(path))}"
        
        # Create path node
        path_node = Node("Path", 
                         id=path_id,
                         severity=severity,
                         description=description,
                         timestamp=datetime.now().isoformat())
        graph.create(path_node)
        
        prev_node = None
        
        # Create nodes and relationships for each step in the path
        for i, step in enumerate(path):
            # Extract step information
            step_type = step.get("type", "unknown")
            source_ip = step.get("source_ip")
            destination_ip = step.get("destination_ip")
            protocol = step.get("protocol")
            port = step.get("port")
            alert = step.get("alert")
            timestamp = step.get("timestamp", datetime.now().isoformat())
            
            # Create or get source IP node
            if source_ip:
                source_node = Node("IP", 
                                  address=source_ip,
                                  is_internal=_is_internal_ip(source_ip),
                                  first_seen=timestamp)
                source_node = _merge_node(graph, source_node, "IP", "address")
                
                # Connect to path
                rel = Relationship(source_node, "PART_OF", path_node, step=i, role="source")
                graph.create(rel)
                
                # Connect to previous node if exists
                if prev_node and prev_node != source_node:
                    action_rel = Relationship(prev_node, "CONNECTS_TO", source_node, 
                                             protocol=protocol,
                                             port=port,
                                             timestamp=timestamp,
                                             alert=alert)
                    graph.create(action_rel)
                
                prev_node = source_node
            
            # Create or get destination IP node
            if destination_ip:
                dest_node = Node("IP", 
                                address=destination_ip,
                                is_internal=_is_internal_ip(destination_ip),
                                first_seen=timestamp)
                dest_node = _merge_node(graph, dest_node, "IP", "address")
                
                # Connect to path
                rel = Relationship(dest_node, "PART_OF", path_node, step=i, role="destination")
                graph.create(rel)
                
                # Connect source to destination
                if source_ip and prev_node:
                    action_rel = Relationship(prev_node, "CONNECTS_TO", dest_node, 
                                             protocol=protocol,
                                             port=port,
                                             timestamp=timestamp,
                                             alert=alert,
                                             step_type=step_type)
                    graph.create(action_rel)
                
                prev_node = dest_node
            
            # Create additional nodes based on step type
            if step_type == "exploit":
                exploit_node = Node("Exploit",
                                   name=alert,
                                   timestamp=timestamp)
                graph.create(exploit_node)
                
                # Connect exploit to target
                if destination_ip and prev_node:
                    exploit_rel = Relationship(exploit_node, "TARGETS", prev_node,
                                              timestamp=timestamp)
                    graph.create(exploit_rel)
            
            elif step_type == "malware":
                malware_node = Node("Malware",
                                   name=alert,
                                   timestamp=timestamp)
                graph.create(malware_node)
                
                # Connect malware to host
                if source_ip and dest_node:
                    malware_rel = Relationship(malware_node, "INFECTS", prev_node,
                                              timestamp=timestamp)
                    graph.create(malware_rel)
        
        logger.info(f"Successfully created attack path graph: {path_id}")
        return True
    
    except Exception as e:
        logger.error(f"Error creating attack path graph: {e}")
        return False

def _merge_node(graph, node, label, key):
    """
    Merge a node into the graph, creating it if it doesn't exist.
    
    Args:
        graph (Graph): Neo4j graph connection
        node (Node): Node to merge
        label (str): Node label
        key (str): Key property
        
    Returns:
        Node: The merged node
    """
    query = f"MERGE (n:{label} {{{key}: $key_value}}) "
    props = {k: v for k, v in dict(node).items() if k != key}
    if props:
        query += "ON CREATE SET " + ", ".join(f"n.{k} = ${k}" for k in props.keys())
        query += " ON MATCH SET " + ", ".join(f"n.{k} = CASE WHEN n.{k} IS NULL THEN ${k} ELSE n.{k} END" for k in props.keys())
    query += " RETURN n"
    
    params = {"key_value": node[key], **props}
    result = graph.run(query, **params).data()
    return result[0]["n"] if result else node

def _is_internal_ip(ip):
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

def get_attack_paths(path_id=None):
    """
    Retrieve attack paths from Neo4j.
    
    Args:
        path_id (str): ID of a specific path to retrieve, or None for all paths
        
    Returns:
        list: Attack paths with nodes and relationships
    """
    try:
        graph = get_neo4j_connection()
        if not graph:
            return []
        
        if path_id:
            # Query for a specific path
            query = """
            MATCH (p:Path {id: $path_id})
            OPTIONAL MATCH (n)-[r:PART_OF]->(p)
            WITH p, collect({node: n, relationship: r}) as nodes
            OPTIONAL MATCH (n1)-[r:CONNECTS_TO]->(n2)
            WHERE (n1)-[:PART_OF]->(p) AND (n2)-[:PART_OF]->(p)
            WITH p, nodes, collect({source: n1.address, target: n2.address, properties: r}) as links
            RETURN p.id as path_id, p.severity as severity, p.description as description, 
                  p.timestamp as timestamp, nodes, links
            """
            result = graph.run(query, path_id=path_id).data()
        else:
            # Query for all paths
            query = """
            MATCH (p:Path)
            OPTIONAL MATCH (n)-[r:PART_OF]->(p)
            WITH p, collect({node: n, relationship: r}) as nodes
            OPTIONAL MATCH (n1)-[r:CONNECTS_TO]->(n2)
            WHERE (n1)-[:PART_OF]->(p) AND (n2)-[:PART_OF]->(p)
            WITH p, nodes, collect({source: n1.address, target: n2.address, properties: r}) as links
            RETURN p.id as path_id, p.severity as severity, p.description as description, 
                  p.timestamp as timestamp, nodes, links
            """
            result = graph.run(query).data()
        
        # Format the result for visualization
        paths = []
        for record in result:
            path = {
                "id": record["path_id"],
                "severity": record["severity"],
                "description": record["description"],
                "timestamp": record["timestamp"],
                "nodes": [],
                "links": []
            }
            
            # Process nodes
            for node_data in record["nodes"]:
                node = dict(node_data["node"])
                rel = dict(node_data["relationship"])
                
                # Add node type from labels
                node_type = list(node_data["node"].labels)[0]
                node["type"] = node_type
                
                path["nodes"].append({
                    "id": node.get("address", node.get("id", f"unknown_{len(path['nodes'])}")),
                    "type": node_type,
                    "properties": node,
                    "relationship": rel
                })
            
            # Process links
            for link in record["links"]:
                path["links"].append({
                    "source": link["source"],
                    "target": link["target"],
                    "properties": dict(link["properties"])
                })
            
            paths.append(path)
        
        return paths
    
    except Exception as e:
        logger.error(f"Error retrieving attack paths: {e}")
        return []

def generate_attack_path_visualization_data(path_id=None):
    """
    Generate visualization data for D3.js or similar libraries.
    
    Args:
        path_id (str): ID of a specific path to visualize, or None for all paths
        
    Returns:
        dict: Visualization data with nodes and links
    """
    paths = get_attack_paths(path_id)
    
    if not paths:
        return {"nodes": [], "links": []}
    
    # For simplicity, we'll just use the first path if no specific one is requested
    path = paths[0] if path_id is None and paths else paths[0]
    
    # Format for D3.js visualization
    vis_data = {
        "nodes": [],
        "links": []
    }
    
    # Node types with colors
    node_colors = {
        "IP": "#1f77b4",  # blue
        "Host": "#2ca02c",  # green
        "Exploit": "#d62728",  # red
        "Malware": "#9467bd",  # purple
        "Path": "#ff7f0e"  # orange
    }
    
    # Process nodes
    node_ids = set()
    for node in path["nodes"]:
        # Skip duplicates
        if node["id"] in node_ids:
            continue
            
        node_ids.add(node["id"])
        
        vis_data["nodes"].append({
            "id": node["id"],
            "name": node["id"],
            "type": node["type"],
            "color": node_colors.get(node["type"], "#aaaaaa"),
            "internal": node["properties"].get("is_internal", False) if node["type"] == "IP" else None
        })
    
    # Process links
    for link in path["links"]:
        vis_data["links"].append({
            "source": link["source"],
            "target": link["target"],
            "protocol": link["properties"].get("protocol", ""),
            "port": link["properties"].get("port", ""),
            "alert": link["properties"].get("alert", ""),
            "step_type": link["properties"].get("step_type", "")
        })
    
    # Add metadata
    vis_data["metadata"] = {
        "path_id": path["id"],
        "description": path["description"],
        "severity": path["severity"],
        "timestamp": path["timestamp"]
    }
    
    return vis_data

if __name__ == "__main__":
    # Test Neo4j connection
    graph = get_neo4j_connection()
    if graph:
        print("Neo4j connection successful")
        
        # Test schema initialization
        if init_neo4j_schema():
            print("Schema initialized successfully")
            
        # Test creating a sample attack path
        sample_path = {
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
        
        if create_attack_path_graph(sample_path):
            print("Sample attack path created successfully")
            
            # Test retrieving attack paths
            paths = get_attack_paths()
            print(f"Retrieved {len(paths)} attack paths")
            
            # Test generating visualization data
            vis_data = generate_attack_path_visualization_data()
            print(f"Visualization data generated with {len(vis_data['nodes'])} nodes and {len(vis_data['links'])} links")
    else:
        print("Neo4j connection failed")
