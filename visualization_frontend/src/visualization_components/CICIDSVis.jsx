import { useState, useEffect, useRef } from 'react';
import * as d3 from 'd3';

// Color schemes based on features
const attackColors = {
  'benign': [52, 211, 153],
  'attack': [248, 113, 113],
  'DoS': [239, 68, 68],
  'DDoS': [220, 38, 38],
  'PortScan': [251, 146, 60],
  'BruteForce': [168, 85, 247],
  'Web': [236, 72, 153],
  'Infiltration': [147, 51, 234],
  'Botnet': [244, 63, 94]
};

const serviceColors = {
  'http': [59, 130, 246],
  'https': [37, 99, 235],
  'ssh': [234, 179, 8],
  'dns': [16, 185, 129],
  'ftp': [249, 115, 22],
  'smtp': [139, 92, 246],
  'other': [148, 163, 184]
};

const CICIDSVisualization = () => {
  const canvasRef = useRef(null);
  const [graphData, setGraphData] = useState({ nodes: [], edges: [] });
  const [loading, setLoading] = useState(false);
  const [loadingProgress, setLoadingProgress] = useState(0);
  const [loadingStage, setLoadingStage] = useState('');
  const [selectedNode, setSelectedNode] = useState(null);
  const [colorMode, setColorMode] = useState('attack');
  const [error, setError] = useState(null);
  const [showConfig, setShowConfig] = useState(true);
  
  // Configuration state
  const [config, setConfig] = useState({
    maxRows: 30000,
    numSourceNodes: 50,
    numDestNodes: 500,
    groupingStrategy: 'modulo'
  });
  
  // State for pan + zoom
  const [transform, setTransform] = useState({ x: 0, y: 0, scale: 1 });
  const [isDragging, setIsDragging] = useState(false);
  const [dragStart, setDragStart] = useState({ x: 0, y: 0 });

  useEffect(() => {
    if (!loading && graphData.nodes.length > 0) {
      drawVisualization();
    }
  }, [graphData, colorMode, loading, transform]);

  const startVisualization = () => {
    setShowConfig(false);
    loadAndProcessData();
  };

  const loadAndProcessData = async () => {
    try {
      setLoading(true);
      setLoadingStage('Fetching CSV...');
      setLoadingProgress(10);
      
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 30000);
      const response = await fetch('/cicids2017_balanced.csv', {signal: controller.signal});
      clearTimeout(timeoutId);
      if(!response.ok) {throw new Error(`HTTP error! status: ${response.status}`);}
      setLoadingProgress(20);
      const csvText = await response.text();
      
      setLoadingStage('Parsing CSV data...');
      setLoadingProgress(30);
      
      const lines = csvText.split('\n');
      const headers = lines[0].split(',').map(h => h.trim());
      const nodeMap = new Map();
      const edgesList = [];
      
      const rowsToProcess = Math.min(config.maxRows, lines.length - 1);
      
      setLoadingStage('Processing network flows...');
      for (let i = 1; i <= rowsToProcess; i++) {
        if (i % 100 === 0) {
          const progress = 30 + (i / rowsToProcess) * 40;
          setLoadingProgress(Math.floor(progress));
        }
        
        const values = lines[i].split(',');
        if (values.length < headers.length) continue;
        
        const row = {};
        headers.forEach((header, idx) => {
          row[header] = values[idx];
        });
        
        const destPort = parseInt(row['Destination Port']) || 80;
        const service = row['service_grouped'] || 'other';
        
        // Generate node IDs based on grouping strategy
        let sourceId, destId;
        
        if (config.groupingStrategy === 'modulo') {
          sourceId = `src_${i % config.numSourceNodes}`;
          destId = `dest_${destPort % config.numDestNodes}`;
        } else if (config.groupingStrategy === 'sequential') {
          sourceId = `src_${Math.floor(i / (rowsToProcess / config.numSourceNodes))}`;
          destId = `dest_${destPort % config.numDestNodes}`;
        } else if (config.groupingStrategy === 'port') {
          sourceId = `src_${i % config.numSourceNodes}`;
          destId = `dest_${destPort}`;
        }
        
        const isAttack = parseInt(row['is_attack']) === 1;
        const attackGroup = row['attack_group'] || 'benign';
        const packets = parseInt(row['packets_total']) || 0;
        const bytes = parseInt(row['bytes_total']) || 0;
        const flowDuration = parseFloat(row['Flow Duration']) || 0;
        const flowBytesPerSec = parseFloat(row['Flow Bytes/s']) || 0;
        
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
            service: service,
            attackCount: 0
          });
        }
        
        const sourceNode = nodeMap.get(sourceId);
        sourceNode.packets += packets;
        sourceNode.bytes += bytes;
        sourceNode.connections += 1;
        if(isAttack) {
          sourceNode.isAttack = true;
          sourceNode.attackGroup = attackGroup;
          sourceNode.attackCount += 1;
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
            attackGroup: 'benign',
            attacksReceived: 0
          });
        }
        
        const destNode = nodeMap.get(destId);
        destNode.packets += packets;
        destNode.bytes += bytes;
        destNode.connections += 1;
        if(isAttack) {
          destNode.attacksReceived += 1;
        }
        
        // Create edge
        edgesList.push({
          source: sourceId,
          target: destId,
          flowDuration: flowDuration,
          flowBytesPerSec: flowBytesPerSec,
          totalPackets: packets,
          totalBytes: bytes,
          isAttack: isAttack,
          attackGroup: attackGroup,
          service: service
        });
      }
      
      setLoadingStage('Building graph layout...');
      setLoadingProgress(75);
      
      const nodes = Array.from(nodeMap.values());
      
      const d3Edges = edgesList.map(edge => ({
        source: nodeMap.get(edge.source),
        target: nodeMap.get(edge.target),
        ...edge
      }));
      
      // Force-directed layout
      const simulation = d3.forceSimulation(nodes)
        .force("link", d3.forceLink(d3Edges)
          .id(d => d.id)
          .distance(120)
          .strength(0.5))
        .force("charge", d3.forceManyBody()
          .strength(-250)
          .distanceMax(450))
        .force("center", d3.forceCenter(0, 0))
        .force("collision", d3.forceCollide()
          .radius(d => Math.sqrt(d.packets) * 0.08 + 15))
        .force("x", d3.forceX(d => d.type === 'source' ? -350 : 350)
          .strength(0.3))
        .force("y", d3.forceY(0).strength(0.1))
        .stop();
      
      for (let i = 0; i < 300; i++) {
        simulation.tick();
        if (i % 30 === 0) {
          setLoadingProgress(75 + Math.floor((i / 300) * 15));
        }
      }
      
      setLoadingStage('Rendering visualization...');
      setLoadingProgress(90);
      
      const edges = d3Edges.map(edge => ({
        sourcePos: [edge.source.x, edge.source.y],
        targetPos: [edge.target.x, edge.target.y],
        flowDuration: edge.flowDuration,
        flowBytesPerSec: edge.flowBytesPerSec,
        totalPackets: edge.totalPackets,
        totalBytes: edge.totalBytes,
        isAttack: edge.isAttack,
        attackGroup: edge.attackGroup,
        service: edge.service
      }));
      
      setGraphData({ nodes, edges });
      setLoadingProgress(100);
      setLoadingStage('Complete!');
      
      setTimeout(() => {setLoading(false);}, 300);
    
    } catch (err) {
      console.error('Error loading data:', err);
      setError(err.message);
      setLoading(false);
    }
  };

  const getNodeColor = (node) => {
    if (colorMode === 'attack') {
      if (node.isAttack) {
        return attackColors[node.attackGroup] || attackColors['attack'];
      }
      return attackColors['benign'];
    } else {
      return serviceColors[node.service] || serviceColors['other'];
    }
  };

  const drawVisualization = () => {
    const canvas = canvasRef.current;
    if(!canvas) return;
    const ctx = canvas.getContext('2d');
    const width = canvas.width;
    const height = canvas.height;
    
    ctx.fillStyle = '#0f172a';
    ctx.fillRect(0, 0, width, height);
    
    ctx.save();
    ctx.translate(width / 2 + transform.x, height / 2 + transform.y);
    ctx.scale(transform.scale, transform.scale);
    
    // Draw edges
    graphData.edges.forEach(edge => {
      const color = edge.isAttack ? 
        attackColors[edge.attackGroup] || attackColors['attack'] : 
        attackColors['benign'];
      
      const opacity = Math.min(edge.flowDuration / 1000, 1) * 0.4 + 0.2;
      const width = Math.max(0.5, Math.log(edge.flowBytesPerSec + 1) * 0.3);
      
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
      const radius = Math.sqrt(node.packets) * 0.04 + 5;
      
      ctx.beginPath();
      ctx.arc(node.x, node.y, radius, 0, Math.PI * 2);
      ctx.fillStyle = `rgb(${color[0]}, ${color[1]}, ${color[2]})`;
      ctx.fill();
      
      if(node.attackCount > 5 && transform.scale > 0.4) {
        ctx.beginPath();
        ctx.arc(node.x, node.y, radius + 3, 0, Math.PI * 2);
        ctx.strokeStyle = 'rgba(239, 68, 68, 0.6)';
        ctx.lineWidth = 2;
        ctx.stroke();
      }
      
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
    if (isDragging) return;
    const canvas = canvasRef.current;
    const rect = canvas.getBoundingClientRect();
    const mouseX = e.clientX - rect.left;
    const mouseY = e.clientY - rect.top;
    
    const x = (mouseX - canvas.width / 2 - transform.x) / transform.scale;
    const y = (mouseY - canvas.height / 2 - transform.y) / transform.scale;
    
    const clickedNode = graphData.nodes.find(node => {
      const radius = Math.sqrt(node.packets) * 0.04 + 5;
      const dx = x - node.x;
      const dy = y - node.y;
      return Math.sqrt(dx * dx + dy * dy) < radius;
    });
    
    setSelectedNode(clickedNode || null);
  };

  const handleMouseDown = (e) => {
    setIsDragging(true);
    setDragStart({ x: e.clientX - transform.x, y: e.clientY - transform.y });
  };

  const handleMouseMove = (e) => {
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
    const canvas = canvasRef.current;
    const rect = canvas.getBoundingClientRect();
    const mouseX = e.clientX - rect.left;
    const mouseY = e.clientY - rect.top;
    const zoomFactor = e.deltaY > 0 ? 0.9 : 1.1;
    const newScale = Math.max(0.1, Math.min(5, transform.scale * zoomFactor));
    const scaleChange = newScale / transform.scale;
    const newX = mouseX - (mouseX - canvas.width / 2 - transform.x) * scaleChange - canvas.width / 2;
    const newY = mouseY - (mouseY - canvas.height / 2 - transform.y) * scaleChange - canvas.height / 2;
    
    setTransform({x: newX, y: newY, scale: newScale});
  };

  const handleReset = () => {
    setTransform({ x: 0, y: 0, scale: 1 });
  };

  const handleReconfigure = () => {
    setShowConfig(true);
    setGraphData({ nodes: [], edges: [] });
    setSelectedNode(null);
    setTransform({ x: 0, y: 0, scale: 1 });
  };

  return (
    <div style={{ width: '100vw', height: '100vh', position: 'fixed', top: 0, left: 0, fontFamily: 'system-ui, sans-serif', background: '#0f172a' }}>
      
      {/* Configuration Panel */}
      {showConfig && !loading && (
        <div style={{ position: 'absolute', top: '50%', left: '50%', transform: 'translate(-50%, -50%)', background: 'rgba(15, 23, 42, 0.95)', padding: '40px', borderRadius: '16px', color: 'white', zIndex: 20, minWidth: '500px', border: '1px solid rgba(59, 130, 246, 0.3)' }}>
          <h2 style={{ margin: '0 0 25px 0', fontSize: '24px', textAlign: 'center' }}>CICIDS-2017 Network Visualization</h2>
          
          <div style={{ marginBottom: '20px' }}>
            <label style={{ display: 'block', marginBottom: '8px', fontSize: '14px', fontWeight: '500' }}>Maximum Rows to Process:</label>
            <input 
              type="number" 
              value={config.maxRows}
              onChange={(e) => setConfig({...config, maxRows: parseInt(e.target.value) || 1000})}
              min="1000"
              max="100000"
              step="1000"
              style={{ width: '100%', padding: '10px', borderRadius: '6px', border: '1px solid #475569', background: '#1e293b', color: 'white', fontSize: '14px' }}
            />
            <div style={{ fontSize: '12px', color: '#94a3b8', marginTop: '5px' }}>Recommended: 10,000 - 50,000</div>
          </div>

          <div style={{ marginBottom: '20px' }}>
            <label style={{ display: 'block', marginBottom: '8px', fontSize: '14px', fontWeight: '500' }}>Number of Source Nodes:</label>
            <input 
              type="number" 
              value={config.numSourceNodes}
              onChange={(e) => setConfig({...config, numSourceNodes: parseInt(e.target.value) || 50})}
              min="10"
              max="1000"
              step="10"
              style={{ width: '100%', padding: '10px', borderRadius: '6px', border: '1px solid #475569', background: '#1e293b', color: 'white', fontSize: '14px' }}
            />
          </div>

          <div style={{ marginBottom: '20px' }}>
            <label style={{ display: 'block', marginBottom: '8px', fontSize: '14px', fontWeight: '500' }}>Number of Destination Nodes:</label>
            <input 
              type="number" 
              value={config.numDestNodes}
              onChange={(e) => setConfig({...config, numDestNodes: parseInt(e.target.value) || 500})}
              min="10"
              max="5000"
              step="50"
              style={{ width: '100%', padding: '10px', borderRadius: '6px', border: '1px solid #475569', background: '#1e293b', color: 'white', fontSize: '14px' }}
            />
          </div>

          <div style={{ marginBottom: '30px' }}>
            <label style={{ display: 'block', marginBottom: '8px', fontSize: '14px', fontWeight: '500' }}>Grouping Strategy:</label>
            <select 
              value={config.groupingStrategy}
              onChange={(e) => setConfig({...config, groupingStrategy: e.target.value})}
              style={{ width: '100%', padding: '10px', borderRadius: '6px', border: '1px solid #475569', background: '#1e293b', color: 'white', fontSize: '14px' }}
            >
              <option value="modulo">Modulo (Even distribution)</option>
              <option value="sequential">Sequential (Time-based grouping)</option>
              <option value="port">Port-based (Unique ports as destinations)</option>
            </select>
            <div style={{ fontSize: '12px', color: '#94a3b8', marginTop: '5px' }}>
              {config.groupingStrategy === 'modulo' && 'Distributes flows evenly across nodes'}
              {config.groupingStrategy === 'sequential' && 'Groups consecutive flows together (temporal patterns)'}
              {config.groupingStrategy === 'port' && 'Each unique port becomes a destination node'}
            </div>
          </div>

          <div style={{ background: 'rgba(59, 130, 246, 0.1)', padding: '15px', borderRadius: '8px', marginBottom: '25px', fontSize: '13px', lineHeight: '1.6' }}>
            <div style={{ fontWeight: '500', marginBottom: '8px' }}>Configuration Summary:</div>
            <div>• Processing <strong>{config.maxRows.toLocaleString()}</strong> network flows</div>
            <div>• Creating <strong>{(config.numSourceNodes + config.numDestNodes).toLocaleString()}</strong> total nodes</div>
            <div>• Using <strong>{config.groupingStrategy}</strong> grouping strategy</div>
            <div style={{ marginTop: '8px', color: '#94a3b8' }}>
              Note: More nodes = more detail but slower performance
            </div>
          </div>

          <button 
            onClick={startVisualization}
            style={{ width: '100%', padding: '14px', borderRadius: '8px', border: 'none', background: 'linear-gradient(135deg, #3b82f6, #06b6d4)', color: 'white', cursor: 'pointer', fontSize: '16px', fontWeight: '500', transition: 'transform 0.2s' }}
            onMouseEnter={(e) => e.target.style.transform = 'translateY(-2px)'}
            onMouseLeave={(e) => e.target.style.transform = 'translateY(0)'}
          >
            Load Visualization
          </button>
        </div>
      )}

      {/* Loading Screen */}
      {loading && (
        <div style={{ position: 'absolute', top: '50%', left: '50%', transform: 'translate(-50%, -50%)', color: 'white', zIndex: 10, textAlign: 'center', background: 'rgba(0, 0, 0, 0.8)', padding: '30px', borderRadius: '12px', minWidth: '300px'}}>
          <div style={{ fontSize: '20px', marginBottom: '20px' }}>Loading CICIDS-2017 network traffic...</div>
          <div style={{width: '100%', height: '8px', background: 'rgba(255, 255, 255, 0.1)', borderRadius: '4px', overflow: 'hidden', marginBottom: '15px'}}>
            <div style={{width: `${loadingProgress}%`, height: '100%', background: 'linear-gradient(90deg, #3b82f6, #06b6d4)', transition: 'width 0.3s ease', borderRadius: '4px'}}></div>
          </div>
          <div style={{fontSize: '14px', color: '#94a3b8'}}>{loadingStage} ({loadingProgress}%)</div>
        </div>
      )}
      
      {error && (
        <div style={{ position: 'absolute', top: '50%', left: '50%', transform: 'translate(-50%, -50%)', color: '#f87171', fontSize: '16px', zIndex: 10, textAlign: 'center'}}>Error: {error}</div>
      )}
      
      {/* Controls */}
      {!showConfig && (
        <div style={{position: 'absolute', top: 20, left: 20, background: 'rgba(0, 0, 0, 0.8)', padding: '15px', borderRadius: '8px', color: 'white', zIndex: 10, minWidth: '250px'}}>
          <h3 style={{ margin: '0 0 15px 0', fontSize: '16px' }}>CICIDS-2017 Network Visualization</h3>
          
          <div style={{ background: 'rgba(59, 130, 246, 0.1)', padding: '10px', borderRadius: '6px', marginBottom: '15px', fontSize: '12px' }}>
            <div><strong>Nodes:</strong> {graphData.nodes.length.toLocaleString()}</div>
            <div><strong>Edges:</strong> {graphData.edges.length.toLocaleString()}</div>
            <div><strong>Strategy:</strong> {config.groupingStrategy}</div>
          </div>
          
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

          <button onClick={handleReset} style={{width: '100%', padding: '8px', marginBottom: '10px', borderRadius: '4px', border: 'none', background: '#3b82f6', color: 'white', cursor: 'pointer', fontSize: '14px'}}>Reset View</button>
          <button onClick={handleReconfigure} style={{width: '100%', padding: '8px', marginBottom: '15px', borderRadius: '4px', border: 'none', background: '#8b5cf6', color: 'white', cursor: 'pointer', fontSize: '14px'}}>Reconfigure</button>
          
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
                <div style={{ display: 'flex', alignItems: 'center', marginTop: '8px' }}>
                  <div style={{ width: '12px', height: '12px', background: 'rgb(52, 211, 153)', marginRight: '8px', borderRadius: '2px' }}></div>
                  Benign Traffic
                </div>
                <div style={{ display: 'flex', alignItems: 'center', marginTop: '5px' }}>
                  <div style={{ width: '12px', height: '12px', background: 'rgb(248, 113, 113)', marginRight: '8px', borderRadius: '2px' }}></div>
                  Attack Traffic
                </div>
              </>
            ) : (
              <>
                <div style={{ display: 'flex', alignItems: 'center', marginTop: '8px' }}>
                  <div style={{ width: '12px', height: '12px', background: 'rgb(59, 130, 246)', marginRight: '8px', borderRadius: '2px' }}></div>
                  HTTP/HTTPS
                </div>
                <div style={{ display: 'flex', alignItems: 'center', marginTop: '5px' }}>
                  <div style={{ width: '12px', height: '12px', background: 'rgb(234, 179, 8)', marginRight: '8px', borderRadius: '2px' }}></div>
                  SSH
                </div>
              </>
            )}
            
            <div style={{ marginTop: '12px', paddingTop: '12px', borderTop: '1px solid #444' }}>
              <div><strong>Visual Key:</strong></div>
              <div style={{ marginTop: '5px' }}>- Node size = Packet count</div>
              <div>- Edge thickness = Flow bytes/sec</div>
              <div>- Edge opacity = Flow duration</div>
              <div>- Red ring = High attack count</div>
            </div>
          </div>
        </div>
      )}
      
      {/* Node details panel */}
      {selectedNode && !showConfig && (
        <div style={{position: 'absolute', top: 20, right: 20, background: 'rgba(0, 0, 0, 0.9)', padding: '15px', borderRadius: '8px', color: 'white', zIndex: 10, minWidth: '280px', maxWidth: '350px'}}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
            <h4 style={{ margin: 0, fontSize: '14px' }}>Node Details</h4>
            <button 
              onClick={() => setSelectedNode(null)}
              style={{background: 'transparent', border: 'none', color: 'white', cursor: 'pointer', fontSize: '18px'}}>
              ×
            </button>
          </div>
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
            {selectedNode.type === 'source' && (
              <>
                <div><strong>Attack Count:</strong> {selectedNode.attackCount}</div>
                <div><strong>Attack Traffic:</strong> {selectedNode.isAttack ? 'Yes' : 'No'}</div>
                {selectedNode.isAttack && (
                  <div><strong>Attack Type:</strong> {selectedNode.attackGroup}</div>
                )}
              </>
            )}
            {selectedNode.type === 'destination' && (
              <div><strong>Attacks Received:</strong> {selectedNode.attacksReceived}</div>
            )}
          </div>
        </div>
      )}
      
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
      style={{ cursor: isDragging ? 'grabbing' : 'grab', display: showConfig ? 'none' : 'block' }}
    />
  </div>
)};
export default CICIDSVisualization