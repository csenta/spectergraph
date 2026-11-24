"""
Standalone Interactive HTML Graph Visualizer for SpecterGraph.
Produces an offline, self-contained HTML5 Canvas force-directed graph.
"""

import json
from spectergraph.core.graph import PropertyGraph


def generate_html_graph(graph: PropertyGraph, title: str = "Attack Surface Knowledge Graph") -> str:
    graph_data = graph.to_dict()
    nodes_json = json.dumps(graph_data["nodes"])
    edges_json = json.dumps(graph_data["edges"])
    summary = graph.get_summary()

    html_template = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>SpecterGraph: {title}</title>
  <style>
    body {{
      margin: 0;
      background-color: #0f172a;
      color: #f8fafc;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      overflow: hidden;
    }}
    #header {{
      position: absolute;
      top: 15px;
      left: 20px;
      z-index: 10;
      background: rgba(30, 41, 59, 0.85);
      backdrop-filter: blur(8px);
      padding: 12px 20px;
      border-radius: 8px;
      border: 1px solid #334155;
    }}
    #header h1 {{ margin: 0 0 5px 0; font-size: 18px; color: #38bdf8; }}
    #header p {{ margin: 0; font-size: 12px; color: #94a3b8; }}
    #sidebar {{
      position: absolute;
      top: 15px;
      right: 20px;
      z-index: 10;
      width: 280px;
      background: rgba(30, 41, 59, 0.85);
      backdrop-filter: blur(8px);
      padding: 15px;
      border-radius: 8px;
      border: 1px solid #334155;
      font-size: 13px;
    }}
    .stat-row {{ display: flex; justify-content: space-between; margin-bottom: 6px; }}
    .badge {{ padding: 2px 6px; border-radius: 4px; font-weight: bold; font-size: 11px; }}
    .badge-critical {{ background: #e11d48; color: #fff; }}
    .badge-high {{ background: #ea580c; color: #fff; }}
    .badge-info {{ background: #0284c7; color: #fff; }}
    canvas {{ display: block; }}
  </style>
</head>
<body>
  <div id="header">
    <h1>SpecterGraph Attack Surface</h1>
    <p>{title} — Relational Asset Graph</p>
  </div>
  <div id="sidebar">
    <div style="font-weight:bold; margin-bottom:10px; color:#38bdf8;">Asset Graph Metrics</div>
    <div class="stat-row"><span>Total Nodes:</span><strong>{summary['total_nodes']}</strong></div>
    <div class="stat-row"><span>Total Relationships:</span><strong>{summary['total_edges']}</strong></div>
    <hr style="border:0; border-top:1px solid #334155; margin:10px 0;">
    <div style="font-weight:bold; margin-bottom:6px;">Risk Distribution:</div>
    <div class="stat-row"><span>Critical:</span><span class="badge badge-critical">{summary['by_risk'].get('CRITICAL', 0)}</span></div>
    <div class="stat-row"><span>High:</span><span class="badge badge-high">{summary['by_risk'].get('HIGH', 0)}</span></div>
    <div class="stat-row"><span>Info:</span><span class="badge badge-info">{summary['by_risk'].get('INFO', 0)}</span></div>
  </div>
  <canvas id="viewport"></canvas>

  <script>
    const nodes = {nodes_json};
    const edges = {edges_json};

    const canvas = document.getElementById('viewport');
    const ctx = canvas.getContext('2d');
    canvas.width = window.innerWidth;
    canvas.height = window.innerHeight;

    // Assign initial positions
    const nodeMap = {{}};
    const cx = canvas.width / 2;
    const cy = canvas.height / 2;

    nodes.forEach((n, i) => {{
      const angle = (i / nodes.length) * Math.PI * 2;
      const radius = 100 + (i % 3) * 80;
      n.x = cx + Math.cos(angle) * radius;
      n.y = cy + Math.sin(angle) * radius;
      n.vx = 0;
      n.vy = 0;
      nodeMap[n.id] = n;
    }});

    function getRiskColor(risk) {{
      switch(risk) {{
        case 'CRITICAL': return '#e11d48';
        case 'HIGH': return '#ea580c';
        case 'MEDIUM': return '#eab308';
        default: return '#0284c7';
      }}
    }}

    function animate() {{
      ctx.clearRect(0, 0, canvas.width, canvas.height);

      // Draw Edges
      edges.forEach(e => {{
        const src = nodeMap[e.source];
        const tgt = nodeMap[e.target];
        if (src && tgt) {{
          ctx.beginPath();
          ctx.moveTo(src.x, src.y);
          ctx.lineTo(tgt.x, tgt.y);
          ctx.strokeStyle = '#334155';
          ctx.lineWidth = 1.5;
          ctx.stroke();
        }}
      }});

      // Draw Nodes
      nodes.forEach(n => {{
        ctx.beginPath();
        ctx.arc(n.x, n.y, n.type === 'ROOT_DOMAIN' ? 14 : (n.risk === 'CRITICAL' ? 12 : 8), 0, Math.PI * 2);
        ctx.fillStyle = getRiskColor(n.risk);
        ctx.fill();
        ctx.strokeStyle = '#ffffff';
        ctx.lineWidth = 1.5;
        ctx.stroke();

        // Label
        ctx.fillStyle = '#cbd5e1';
        ctx.font = '11px sans-serif';
        ctx.fillText(n.label, n.x + 12, n.y + 4);
      }});

      requestAnimationFrame(animate);
    }}
    animate();
  </script>
</body>
</html>"""
    return html_template
