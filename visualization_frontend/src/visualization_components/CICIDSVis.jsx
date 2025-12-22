import { useState, useEffect, useRef } from 'react';
import * as d3 from 'd3';

// Color schemes based on features
// Attack types
const attackColors = {
  'benign': [52, 211, 153],
  'attack': [248, 113, 113],
  'DoS': [239, 68, 68],
  'DDoS': [220, 38, 38],
  'PortScan': [251, 146, 60],
  'BruteForce': [168, 85, 247],
  'Web': [236, 72, 153]
};

// Service types
const serviceColors = {
  'http': [59, 130, 246],
  'https': [37, 99, 235],
  'ssh': [234, 179, 8],
  'dns': [16, 185, 129],
  'ftp': [249, 115, 22],
  'other': [148, 163, 184]
};

const CICIDSVisualization = () => {
  const canvasRef = useRef(null);
  const [graphData, setGraphData] = useState({ nodes: [], edges: [] }); // we use a nodes/edges format in usestate given d3 (and other vis libraries) need it
  const [loading, setLoading] = useState(true);
  const [loadingProgress, setLoadingProgress] = useState(0);
  const [loadingStage, setLoadingStage] = useState('');
  const [selectedNode, setSelectedNode] = useState(null);
  const [colorMode, setColorMode] = useState('attack');
  const [error, setError] = useState(null);
  
  // State for pan + zoom
  const [transform, setTransform] = useState({ x: 0, y: 0, scale: 1 });
  const [isDragging, setIsDragging] = useState(false);
  const [dragStart, setDragStart] = useState({ x: 0, y: 0 });

  useEffect(() => {loadAndProcessData()}, []);

  useEffect(() => {
    if (!loading && graphData.nodes.length > 0) {
      drawVisualization();
    }
  }, [graphData, colorMode, loading, transform]);

  const loadAndProcessData = async () => {
    try {
      setLoadingStage('Fetching CSV...');
      setLoadingProgress(10);
      
      // Load csv data w/ timeout
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 30000); // 30 second timeout
      const response = await fetch('/cicids2017_balanced.csv', {signal: controller.signal});
      clearTimeout(timeoutId);
      if(!response.ok) {throw new Error(`HTTP error! status: ${response.status}`);}
      setLoadingProgress(20);
      const csvText = await response.text();
      
      setLoadingStage('Parsing CSV data...');
      setLoadingProgress(30);
      
      // Actually parse the csv
      // Currently pretty primitive, might upgrade to user deckgl's csv parser or papaparse
      const lines = csvText.split('\n');
      const headers = lines[0].split(',');
      const nodeMap = new Map();
      const edgesList = [];
      // Process first 4000 rows to avoid performance issues (loading everything would fry my laptop)
      const rowsToProcess = Math.min(36000, lines.length - 1);
      
      setLoadingStage('Processing network flows...');
      for (let i = 1; i <= rowsToProcess; i++) {
        // Update progress every 100 rows
        if (i % 100 === 0) {
          const progress = 30 + (i / rowsToProcess) * 40;
          setLoadingProgress(Math.floor(progress));
        }
        const values = lines[i].split(',');
        if (values.length < headers.length) continue;
        const row = {};
        headers.forEach((header, idx) => {
          row[header.trim()] = values[idx];
        });
        
        const destPort = parseInt(row['Destination Port']) || 80;
        const sourceId = `src_${i % 50}`; // Group into ~50 sources
        const destId = `dest_${destPort}`;
        
        const isAttack = parseInt(row['is_attack']) === 1;
        const attackGroup = row['attack_group'] || 'benign';
        const service = row['service_grouped'] || 'other';
        const packets = parseInt(row['packets_total']) || 0;
        const bytes = parseInt(row['bytes_total']) || 0;
        
        // Create/update source node
        if(!nodeMap.has(sourceId)) {
          nodeMap.set(sourceId, {
            id: sourceId,
            type: 'source',
            packets: 0,
            bytes: 0,
            connections: 0,
            isAttack: false,
            attackGroup: 'benign',
            service: service
          })
        }
        
        const sourceNode = nodeMap.get(sourceId)
        sourceNode.packets += packets
        sourceNode.bytes += bytes
        sourceNode.connections += 1
        if(isAttack) {
          sourceNode.isAttack = true
          sourceNode.attackGroup = attackGroup
        }
        
        // Create/update destination node
        if (!nodeMap.has(destId)) {
          nodeMap.set(destId, {
            id: destId,
            type: 'destination',
            port: destPort,
            packets: 0,
            bytes: 0,
            connections: 0,
            service: service,
            isAttack: false,
            attackGroup: 'benign'
          });
        }
        
        const destNode = nodeMap.get(destId);
        destNode.packets += packets;
        destNode.bytes += bytes;
        destNode.connections += 1;
        
        // Create edge so the data is compatible w/ vis libraries
        edgesList.push({
          source: sourceId,
          target: destId,
          flowDuration: parseFloat(row['Flow Duration']) || 0,
          flowBytesPerSec: parseFloat(row['Flow Bytes/s']) || 0,
          totalPackets: packets,
          isAttack: isAttack,
          attackGroup: attackGroup,
          service: service
        });
      }
      
      setLoadingStage('Building graph layout...');
      setLoadingProgress(75);
      
      const nodes = Array.from(nodeMap.values());
      
      // Convert edges to reference actual node objects for d3
      const d3Edges = edgesList.map(edge => ({
        source: nodeMap.get(edge.source),
        target: nodeMap.get(edge.target),
        ...edge
      }));
      
      // Use force-directed layout for vis
      // I use force-directed here for two reasons:
      // 1. It is extremely common + visually appealing
      // 2. The actual layout of the graph doesn't require any additional features within the dataset, as positions are done via a calculation. 
      // This means that I do not need to create any more columns/augment any more data to make a viable graph
      const simulation = d3.forceSimulation(nodes)
        .force("link", d3.forceLink(d3Edges)
          .id(d => d.id)
          .distance(150)
          .strength(0.5))
        .force("charge", d3.forceManyBody()
          .strength(-300)
          .distanceMax(500))
        .force("center", d3.forceCenter(0, 0))
        .force("collision", d3.forceCollide()
          .radius(d => Math.sqrt(d.packets) * 0.1 + 20))
        .force("x", d3.forceX(d => d.type === 'source' ? -300 : 300)
          .strength(0.3))
        .force("y", d3.forceY(0).strength(0.1))
        .stop();
      
      // Run simulation manually for 300 iterations
      for (let i = 0; i < 300; i++) {
        simulation.tick();
        if (i % 30 === 0) {
          setLoadingProgress(75 + Math.floor((i / 300) * 15));
        }
      }
      setLoadingStage('Rendering visualization...');
      setLoadingProgress(90);
      
      // Map edges back to positions after D3 has updated node positions
      const edges = d3Edges.map(edge => ({
        sourcePos: [edge.source.x, edge.source.y],
        targetPos: [edge.target.x, edge.target.y],
        flowDuration: edge.flowDuration,
        flowBytesPerSec: edge.flowBytesPerSec,
        totalPackets: edge.totalPackets,
        isAttack: edge.isAttack,
        attackGroup: edge.attackGroup,
        service: edge.service
      }))
      
      setGraphData({ nodes, edges })
      setLoadingProgress(100)
      setLoadingStage('Complete!')
      
      setTimeout(() => {setLoading(false);}, 300)
    
    } catch (err) {
      console.error('Error loading data:', err)
      setError(err.message)
      setLoading(false)
    }
  };

  const getNodeColor = (node) => {
    if (colorMode === 'attack') {
      if (node.isAttack) {
        return attackColors[node.attackGroup] || attackColors['attack']
      }
      return attackColors['benign']
    } else {
      return serviceColors[node.service] || serviceColors['other']
    }
  };

  const drawVisualization = () => {
    const canvas = canvasRef.current
    if(!canvas) return
    const ctx = canvas.getContext('2d')
    const width = canvas.width
    const height = canvas.height
    // Clear canvas
    ctx.fillStyle = '#0f172a'
    ctx.fillRect(0, 0, width, height)
    // Apply transform (pan and zoom)
    ctx.save()
    ctx.translate(width / 2 + transform.x, height / 2 + transform.y)
    ctx.scale(transform.scale, transform.scale)
    
    // Draw edges
    graphData.edges.forEach(edge => {
      const color = edge.isAttack ? 
        attackColors[edge.attackGroup] || attackColors['attack'] : 
        attackColors['benign'];
      
      const opacity = Math.min(edge.flowDuration / 1000, 1) * 0.5 + 0.3;
      const width = Math.max(1, Math.log(edge.flowBytesPerSec + 1) * 0.3);
      
      ctx.beginPath();
      ctx.moveTo(edge.sourcePos[0], edge.sourcePos[1]);
      ctx.lineTo(edge.targetPos[0], edge.targetPos[1]);
      ctx.strokeStyle = `rgba(${color[0]}, ${color[1]}, ${color[2]}, ${opacity})`;
      ctx.lineWidth = width;
      ctx.stroke();
    });
    
    // Draw nodes
    graphData.nodes.forEach(node => {
      const color = getNodeColor(node);
      const radius = Math.sqrt(node.packets) * 0.05 + 5;
      
      ctx.beginPath();
      ctx.arc(node.x, node.y, radius, 0, Math.PI * 2);
      ctx.fillStyle = `rgb(${color[0]}, ${color[1]}, ${color[2]})`;
      ctx.fill();
      
      // Draw labels for destination nodes (only if zoomed in enough)
      if(node.type === 'destination' && transform.scale > 0.5){
        ctx.fillStyle = 'rgba(255, 255, 255, 0.8)';
        ctx.font = '11px sans-serif';
        ctx.textAlign = 'left';
        ctx.fillText(`${node.service}:${node.port}`, node.x + radius + 5, node.y + 4);
      }
    });
    
    ctx.restore();
  };

  const handleCanvasClick = (e) => {
    if (isDragging) return
    const canvas = canvasRef.current
    const rect = canvas.getBoundingClientRect()
    const mouseX = e.clientX - rect.left
    const mouseY = e.clientY - rect.top;
    
    // Transform mouse coordinates to the graph scpace
    const x = (mouseX - canvas.width / 2 - transform.x) / transform.scale
    const y = (mouseY - canvas.height / 2 - transform.y) / transform.scale;
    
    // Check if we clicked on a node or not
    const clickedNode = graphData.nodes.find(node => {
      const radius = Math.sqrt(node.packets) * 0.05 + 5;
      const dx = x - node.x;
      const dy = y - node.y;
      return Math.sqrt(dx * dx + dy * dy) < radius;
    })
    setSelectedNode(clickedNode || null);
  };

  const handleMouseDown = (e) => { // Self-explanatory
    setIsDragging(true);
    setDragStart({ x: e.clientX - transform.x, y: e.clientY - transform.y });
  };

  const handleMouseMove = (e) => { // Self-explanatory
    if (!isDragging) return;
    
    setTransform(prev => ({
      ...prev,
      x: e.clientX - dragStart.x,
      y: e.clientY - dragStart.y
    }));
  };

  const handleMouseUp = () => {
    setIsDragging(false);
  };

  const handleWheel = (e) => {
    e.preventDefault();
    
    const canvas = canvasRef.current
    const rect = canvas.getBoundingClientRect()
    const mouseX = e.clientX - rect.left
    const mouseY = e.clientY - rect.top
    const zoomFactor = e.deltaY > 0 ? 0.9 : 1.1
    const newScale = Math.max(0.1, Math.min(5, transform.scale * zoomFactor))
    const scaleChange = newScale / transform.scale
    const newX = mouseX - (mouseX - canvas.width / 2 - transform.x) * scaleChange - canvas.width / 2
    const newY = mouseY - (mouseY - canvas.height / 2 - transform.y) * scaleChange - canvas.height / 2
    
    setTransform({x: newX, y: newY,scale: newScale});
  };

  const handleReset = () => {
    setTransform({ x: 0, y: 0, scale: 1 })
  };
  // --------UI FOR THE GRAPH--------
  return (
    <div style={{ width: '100vw', height: '100vh', position: 'fixed', top: 0, left: 0, fontFamily: 'system-ui, sans-serif', background: '#0f172a' }}>
      {loading && (
        <div style={{ position: 'absolute', top: '50%', left: '50%', transform: 'translate(-50%, -50%)',color: 'white',zIndex: 10,textAlign: 'center',background: 'rgba(0, 0, 0, 0.8)',padding: '30px',borderRadius: '12px',minWidth: '300px'}}>
          <div style={{ fontSize: '20px', marginBottom: '20px' }}>Loading CICIDS network traffic...</div>
          {/* Progress bar */}
          <div style={{width: '100%',height: '8px',background: 'rgba(255, 255, 255, 0.1)',borderRadius: '4px',overflow: 'hidden',marginBottom: '15px'}}>
            <div style={{width: `${loadingProgress}%`,height: '100%',background: 'linear-gradient(90deg, #3b82f6, #06b6d4)',transition: 'width 0.3s ease',borderRadius: '4px'}}></div></div>
          {/* Progress text */}
          <div style={{fontSize: '14px', color: '#94a3b8'}}>{loadingStage} ({loadingProgress}%)</div>
        </div>
      )}
      
      {error && (
        <div style={{ position: 'absolute', top: '50%', left: '50%', transform: 'translate(-50%, -50%)',color: '#f87171',fontSize: '16px',zIndex: 10,textAlign: 'center'}}>Error: {error}</div>)}
      {/* Controls */}
      <div style={{position: 'absolute', top: 20, left: 20, background: 'rgba(0, 0, 0, 0.8)', padding: '15px', borderRadius: '8px', color: 'white', zIndex: 10, minWidth: '250px'}}>
        <h3 style={{ margin: '0 0 15px 0', fontSize: '16px' }}>CICIDS Network Visualization</h3>
        <div style={{ marginBottom: '15px' }}>
          <label style={{ display: 'block', marginBottom: '5px', fontSize: '14px' }}>Color Mode:</label>
          <select 
            value={colorMode} 
            onChange={(e) => setColorMode(e.target.value)}
            style={{width: '100%', padding: '5px', borderRadius: '4px', border: 'none', background: '#333', color: 'white'}}>
            <option value="attack">Attack Status</option>
            <option value="service">Service Type</option>
          </select>
        </div>

        <button onClick={handleReset} style={{width: '100%', padding: '8px', marginBottom: '15px', borderRadius: '4px', border: 'none', background: '#3b82f6', color: 'white', cursor: 'pointer',fontSize: '14px'}}>Reset View</button>
        <div style={{ fontSize: '12px', lineHeight: '1.6' }}>
          <div style={{ marginBottom: '8px', paddingBottom: '8px', borderBottom: '1px solid #444' }}>
            <strong>Controls:</strong>
            <div style={{ marginTop: '4px' }}>- Drag to pan</div>
            <div>- Scroll to zoom</div>
            <div>- Click nodes for details</div>
          </div>
          <div><strong>Legend:</strong></div>
          {colorMode === 'attack' ? (
            <>
              <div style={{ display: 'flex', alignItems: 'center', marginTop: '8px' }}><div style={{ width: '12px', height: '12px', background: 'rgb(52, 211, 153)', marginRight: '8px', borderRadius: '2px' }}></div>Benign Traffic</div>
              <div style={{ display: 'flex', alignItems: 'center', marginTop: '5px' }}><div style={{ width: '12px', height: '12px', background: 'rgb(248, 113, 113)', marginRight: '8px', borderRadius: '2px' }}></div>Attack Traffic</div>
              <div style={{ display: 'flex', alignItems: 'center', marginTop: '5px' }}><div style={{ width: '12px', height: '12px', background: 'rgb(251, 146, 60)', marginRight: '8px', borderRadius: '2px' }}></div>PortScan</div>
              <div style={{ display: 'flex', alignItems: 'center', marginTop: '5px' }}><div style={{ width: '12px', height: '12px', background: 'rgb(168, 85, 247)', marginRight: '8px', borderRadius: '2px' }}></div>BruteForce</div>
            </>
          ):(
            <>
              <div style={{ display: 'flex', alignItems: 'center', marginTop: '8px' }}>
                <div style={{ width: '12px', height: '12px', background: 'rgb(59, 130, 246)', marginRight: '8px', borderRadius: '2px' }}></div>
                HTTP/HTTPS
              </div>
              <div style={{ display: 'flex', alignItems: 'center', marginTop: '5px' }}>
                <div style={{ width: '12px', height: '12px', background: 'rgb(234, 179, 8)', marginRight: '8px', borderRadius: '2px' }}></div>
                SSH
              </div>
              <div style={{ display: 'flex', alignItems: 'center', marginTop: '5px' }}>
                <div style={{ width: '12px', height: '12px', background: 'rgb(16, 185, 129)', marginRight: '8px', borderRadius: '2px' }}></div>
                DNS
              </div>
            </>
          )}
          <div style={{ marginTop: '12px', paddingTop: '12px', borderTop: '1px solid #444' }}>
            <div><strong>Visual Key:</strong></div>
            <div style={{ marginTop: '5px' }}>- Node size = Packet count</div>
            <div>- Edge thickness = Flow bytes/sec</div>
            <div>- Edge opacity = Flow duration</div>
          </div>
        </div>
      </div>
      
      {/* Node details panel */}
      {selectedNode && (
        <div style={{position: 'absolute', top: 20, right: 20, background: 'rgba(0, 0, 0, 0.9)', padding: '15px', borderRadius: '8px',color: 'white', zIndex: 10, minWidth: '280px', maxWidth: '350px'}}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
            <h4 style={{ margin: 0, fontSize: '14px' }}>Node Details</h4>
            <button 
              onClick={() => setSelectedNode(null)}
              style={{background: 'transparent',border: 'none',color: 'white',cursor: 'pointer',fontSize: '18px'}}>x</button></div>
          <div style={{ fontSize: '12px', lineHeight: '1.8' }}>
            <div><strong>ID:</strong> {selectedNode.id}</div>
            <div><strong>Type:</strong> {selectedNode.type === 'source' ? 'Source IP' : 'Service/Port'}</div>
            {selectedNode.type === 'destination' && (
              <div><strong>Port:</strong> {selectedNode.port}</div>
            )}
            <div><strong>Service:</strong> {selectedNode.service}</div>
            <div><strong>Total Packets:</strong> {selectedNode.packets.toLocaleString()}</div>
            <div><strong>Total Bytes:</strong> {selectedNode.bytes.toLocaleString()}</div>
            <div><strong>Connections:</strong> {selectedNode.connections}</div>
            <div><strong>Attack Traffic:</strong> {selectedNode.isAttack ? 'Yes' : 'No'}</div>
            {selectedNode.isAttack && (
              <div><strong>Attack Type:</strong> {selectedNode.attackGroup}</div>
            )}
          </div>
        </div>)}
      
      <canvas
        ref={canvasRef}
        width={window.innerWidth}
        height={window.innerHeight}
        onClick={handleCanvasClick}
        onMouseDown={handleMouseDown}
        onMouseMove={handleMouseMove}
        onMouseUp={handleMouseUp}
        onMouseLeave={handleMouseUp}
        onWheel={handleWheel}
        style={{ cursor: isDragging ? 'grabbing' : 'grab' }}/></div>
      )}
export default CICIDSVisualization;