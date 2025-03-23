// Attack Path Visualization using D3.js
let simulation;
let svg;
let width, height;
let nodes = [];
let links = [];
let tooltip;
let zoom;

// Initialize the graph visualization
function initGraph(graphData) {
    // Clear any existing SVG
    d3.select("#graph-container svg").remove();
    
    // Set up dimensions
    const container = document.getElementById('graph-container');
    width = container.clientWidth;
    height = container.clientHeight;
    
    // Process data
    if (!graphData || !graphData.nodes || !graphData.links) {
        console.error("Invalid graph data", graphData);
        return;
    }
    
    // Create nodes and links arrays
    nodes = graphData.nodes.map(node => ({
        id: node.id,
        type: node.type,
        properties: node.properties || {},
        internal: node.properties ? node.properties.is_internal : false
    }));
    
    links = graphData.links.map(link => ({
        source: link.source,
        target: link.target,
        properties: link.properties || {}
    }));
    
    // Create SVG container
    svg = d3.select("#graph-container").append("svg")
        .attr("width", width)
        .attr("height", height)
        .attr("viewBox", [0, 0, width, height]);
    
    // Add zoom behavior
    zoom = d3.zoom()
        .scaleExtent([0.1, 4])
        .on("zoom", (event) => {
            g.attr("transform", event.transform);
        });
    
    svg.call(zoom);
    
    // Create a group for all elements
    const g = svg.append("g");
    
    // Create tooltips
    tooltip = d3.select("body").append("div")
        .attr("class", "tooltip")
        .style("opacity", 0);
    
    // Create links
    const link = g.append("g")
        .attr("class", "links")
        .selectAll("line")
        .data(links)
        .enter().append("line")
        .attr("class", d => "link " + getLinkClass(d))
        .attr("stroke-width", d => getLinkWidth(d));
    
    // Create nodes
    const node = g.append("g")
        .attr("class", "nodes")
        .selectAll("circle")
        .data(nodes)
        .enter().append("circle")
        .attr("class", d => "node " + getNodeClass(d))
        .attr("r", d => getNodeRadius(d))
        .attr("fill", d => getNodeColor(d))
        .call(drag(simulation))
        .on("mouseover", showTooltip)
        .on("mouseout", hideTooltip)
        .on("click", highlightConnections);
    
    // Add node labels
    const label = g.append("g")
        .attr("class", "labels")
        .selectAll("text")
        .data(nodes)
        .enter().append("text")
        .attr("dx", 12)
        .attr("dy", ".35em")
        .text(d => getNodeLabel(d))
        .style("font-size", "10px")
        .style("fill", "#fff")
        .style("stroke", "#000")
        .style("stroke-width", "0.5px")
        .style("pointer-events", "none");
    
    // Set up force simulation
    simulation = d3.forceSimulation(nodes)
        .force("link", d3.forceLink(links).id(d => d.id).distance(100))
        .force("charge", d3.forceManyBody().strength(-300))
        .force("center", d3.forceCenter(width / 2, height / 2))
        .force("collide", d3.forceCollide().radius(30))
        .on("tick", () => {
            link
                .attr("x1", d => d.source.x)
                .attr("y1", d => d.source.y)
                .attr("x2", d => d.target.x)
                .attr("y2", d => d.target.y);
            
            node
                .attr("cx", d => d.x = Math.max(d.r, Math.min(width - d.r, d.x)))
                .attr("cy", d => d.y = Math.max(d.r, Math.min(height - d.r, d.y)));
            
            label
                .attr("x", d => d.x)
                .attr("y", d => d.y);
        });
    
    // Function to implement dragging
    function drag(simulation) {
        function dragstarted(event, d) {
            if (!event.active) simulation.alphaTarget(0.3).restart();
            d.fx = d.x;
            d.fy = d.y;
        }
        
        function dragged(event, d) {
            d.fx = event.x;
            d.fy = event.y;
        }
        
        function dragended(event, d) {
            if (!event.active) simulation.alphaTarget(0);
            d.fx = null;
            d.fy = null;
        }
        
        return d3.drag()
            .on("start", dragstarted)
            .on("drag", dragged)
            .on("end", dragended);
    }
    
    // Run the simulation
    simulation.nodes(nodes);
    simulation.force("link").links(links);
    simulation.alpha(1).restart();
}

// Helper functions for styling nodes and links
function getNodeClass(node) {
    if (node.type === 'IP') {
        return node.internal ? 'node-internal' : 'node-external';
    } else if (node.type === 'Malware') {
        return 'node-malware';
    } else if (node.type === 'Exploit') {
        return 'node-exploit';
    }
    return '';
}

function getNodeColor(node) {
    if (node.type === 'IP') {
        return node.internal ? '#007bff' : '#dc3545';
    } else if (node.type === 'Malware') {
        return '#9c27b0';
    } else if (node.type === 'Exploit') {
        return '#ff9800';
    }
    return '#6c757d';
}

function getNodeRadius(node) {
    if (node.type === 'IP') {
        return 12;
    } else if (node.type === 'Malware' || node.type === 'Exploit') {
        return 10;
    }
    return 8;
}

function getNodeLabel(node) {
    // Return a short label for the node
    if (node.type === 'IP') {
        const parts = node.id.split('.');
        return parts.length >= 4 ? `${parts[2]}.${parts[3]}` : node.id;
    }
    
    // For other node types, truncate if too long
    if (node.id && node.id.length > 10) {
        return node.id.substring(0, 10) + '...';
    }
    
    return node.id;
}

function getLinkClass(link) {
    if (link.properties && link.properties.step_type) {
        if (link.properties.step_type === 'exploit') {
            return 'link-attack';
        } else if (link.properties.step_type === 'data_theft') {
            return 'link-data';
        }
    }
    return 'link-connection';
}

function getLinkWidth(link) {
    if (link.properties && link.properties.alert_severity) {
        return 1 + link.properties.alert_severity * 0.5;
    }
    return 1.5;
}

// Show tooltip with node details
function showTooltip(event, d) {
    if (!d3.select('#showTooltips').property('checked')) {
        return;
    }
    
    let content = `<strong>${d.id}</strong><br>`;
    content += `Type: ${d.type}<br>`;
    
    if (d.type === 'IP') {
        content += `Location: ${d.internal ? 'Internal' : 'External'}<br>`;
    }
    
    if (d.properties) {
        // Add relevant properties to tooltip
        if (d.properties.first_seen) {
            content += `First seen: ${d.properties.first_seen}<br>`;
        }
        
        if (d.type === 'Exploit' || d.type === 'Malware') {
            content += `Alert: ${d.properties.name || 'Unknown'}<br>`;
        }
    }
    
    tooltip.transition()
        .duration(200)
        .style("opacity", .9);
    tooltip.html(content)
        .style("left", (event.pageX + 10) + "px")
        .style("top", (event.pageY - 28) + "px");
}

// Hide tooltip
function hideTooltip() {
    tooltip.transition()
        .duration(500)
        .style("opacity", 0);
}

// Highlight node connections
function highlightConnections(event, d) {
    // Reset all nodes and links
    d3.selectAll(".node").attr("opacity", 0.3);
    d3.selectAll(".link").attr("opacity", 0.1);
    
    // Highlight the selected node
    d3.select(this).attr("opacity", 1);
    
    // Find connected nodes and links
    const connectedNodeIds = new Set();
    connectedNodeIds.add(d.id);
    
    // Find links connected to this node
    d3.selectAll(".link").each(function(link) {
        if (link.source.id === d.id || link.target.id === d.id) {
            d3.select(this).attr("opacity", 1).attr("stroke-width", getLinkWidth(link) * 1.5);
            connectedNodeIds.add(link.source.id);
            connectedNodeIds.add(link.target.id);
        }
    });
    
    // Highlight connected nodes
    d3.selectAll(".node").each(function(node) {
        if (connectedNodeIds.has(node.id)) {
            d3.select(this).attr("opacity", 1);
        }
    });
    
    // Allow clicking on background to reset
    svg.on("click", resetHighlighting);
}

// Reset node highlighting
function resetHighlighting() {
    if (event.target.tagName === 'svg' || event.target.tagName === 'g') {
        d3.selectAll(".node").attr("opacity", 1);
        d3.selectAll(".link").attr("opacity", 1).attr("stroke-width", d => getLinkWidth(d));
        svg.on("click", null);
    }
}

// Zoom controls
function zoomIn() {
    svg.transition().call(zoom.scaleBy, 1.3);
}

function zoomOut() {
    svg.transition().call(zoom.scaleBy, 0.7);
}

function resetView() {
    svg.transition().call(zoom.transform, d3.zoomIdentity);
}

// Toggle node visibility by type
function toggleNodeType(type, subType, visible) {
    const opacity = visible ? 1 : 0.1;
    
    d3.selectAll(".node").filter(function(d) {
        if (d.type === type) {
            if (subType === 'internal') {
                return d.internal === true;
            } else if (subType === 'external') {
                return d.internal === false;
            }
            return true;
        }
        return false;
    }).attr("opacity", opacity);
    
    // Also adjust related links
    d3.selectAll(".link").filter(function(d) {
        const sourceMatches = d.source.type === type && 
            (subType ? (subType === 'internal' ? d.source.internal : !d.source.internal) : true);
        const targetMatches = d.target.type === type && 
            (subType ? (subType === 'internal' ? d.target.internal : !d.target.internal) : true);
        
        return sourceMatches || targetMatches;
    }).attr("opacity", opacity);
}

// Toggle node labels
function toggleLabels(visible) {
    d3.selectAll(".labels text").style("visibility", visible ? "visible" : "hidden");
}

// Toggle tooltips
function toggleTooltips(visible) {
    // This function just sets a flag for the showTooltip function
    // No need to manipulate DOM here
}
