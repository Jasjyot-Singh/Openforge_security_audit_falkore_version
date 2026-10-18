"""
Graph Visualizer for FalkorDB Exploit Knowledge Graphs.
Provides Rich ASCII terminal graph rendering with markup escaping,
and standalone interactive Cytoscape.js HTML exports with locally bundled assets and XSS protection.
"""

import os
import json
import html
from pathlib import Path
from typing import Dict, Any, List, Optional
from rich.console import Console
from rich.panel import Panel
from rich.tree import Tree
from rich.markup import escape as rich_escape

from shadowprint.graph.client import FalkorDBClient
from shadowprint.graph.schema import NodeLabel

console = Console(legacy_windows=False)
ASSETS_DIR = Path(__file__).resolve().parent / "assets"
CYTOSCAPE_JS_PATH = ASSETS_DIR / "cytoscape.min.js"


class GraphVisualizer:
    """
    Renders Exploit Knowledge Graphs to terminal and interactive HTML with strict injection safety.
    """
    def __init__(self, client: Optional[FalkorDBClient] = None):
        self.client = client or FalkorDBClient.get_instance()

    def render_ascii_graph(self, chains: List[Dict[str, Any]], server_name: str):
        """Renders an intuitive ASCII attack tree in the terminal using Rich with escaped markup."""
        safe_server = rich_escape(server_name)
        if not chains:
            console.print(f"[dim]No compound exploit chains to visualize for '{safe_server}'.[/dim]")
            return

        tree = Tree(
            f"[bold red]CRITICAL: Multi-Hop Exploit Graph for '{safe_server}'[/bold red]",
            guide_style="bold red",
        )

        for i, ch in enumerate(chains, 1):
            ch_title = rich_escape(str(ch.get("title", "")))
            ch_inj = rich_escape(str(ch.get("injection_finding", "")))
            ch_tool = rich_escape(str(ch.get("tool", "")))
            ch_param = rich_escape(str(ch.get("parameter", "")))
            ch_sink = rich_escape(str(ch.get("ast_sink", "")))
            ch_canary = rich_escape(str(ch.get("canary_read", "")))
            ch_exfil = rich_escape(str(ch.get("network_exfil", "")))

            chain_branch = tree.add(
                f"[bold yellow]Exploit Chain #{i}: {ch_title}[/bold yellow] ([red]{ch.get('hop_count', 4)} Hops[/red])"
            )
            
            s1_node = chain_branch.add(f"[bold cyan]Hop 1 (Ingress):[/bold cyan] S1 Prompt Injection [{ch_inj}]")
            tool_node = s1_node.add(f"[bold magenta]Hop 2 (Control Hijack):[/bold magenta] Tool '{ch_tool}' (Param: '{ch_param}')")
            sink_node = tool_node.add(f"[bold red]Hop 3 (AST Execution Sink):[/bold red] {ch_sink}")
            
            if ch.get("canary_read"):
                sink_node.add(f"[bold yellow]Hop 4 (Privilege Escalation):[/bold yellow] Honeypot Read &rarr; '{ch_canary}'")
            
            if ch.get("network_exfil"):
                sink_node.add(f"[bold red]Hop 5 (Egress Exfiltration):[/bold red] Outbound Socket &rarr; '{ch_exfil}'")

        console.print(Panel(tree, title="[bold red]FalkorDB Exploit Knowledge Graph (EKG)[/bold red]", border_style="red"))

    def generate_cytoscape_html(self, server_name: str, output_path: str) -> str:
        """
        Generates a standalone, beautiful Cytoscape.js interactive HTML attack graph.
        Uses locally bundled cytoscape.min.js and safe JSON element embedding (XSS-safe).
        """
        g = self.client.in_memory_graph
        elements = []

        style_map = {
            NodeLabel.MCP_SERVER.value: {"color": "#38bdf8", "shape": "round-rectangle", "size": 65},
            NodeLabel.TOOL.value: {"color": "#facc15", "shape": "ellipse", "size": 55},
            NodeLabel.PARAMETER.value: {"color": "#94a3b8", "shape": "triangle", "size": 40},
            NodeLabel.FINDING.value: {"color": "#f87171", "shape": "diamond", "size": 45},
            NodeLabel.CODE_AST_SINK.value: {"color": "#ef4444", "shape": "octagon", "size": 55},
            NodeLabel.CANARY_TARGET.value: {"color": "#c084fc", "shape": "hexagon", "size": 50},
            NodeLabel.NETWORK_SINK.value: {"color": "#fb7185", "shape": "star", "size": 60},
            NodeLabel.AUDIT_SESSION.value: {"color": "#4ade80", "shape": "round-rectangle", "size": 50},
        }

        # Add Nodes
        for n_id, n_data in g.nodes.items():
            primary_label = n_data["labels"][0] if n_data["labels"] else "Node"
            styling = style_map.get(primary_label, {"color": "#64748b", "shape": "ellipse", "size": 45})
            raw_text = (
                n_data["properties"].get("name")
                or n_data["properties"].get("finding_id")
                or n_data["properties"].get("sink_type")
                or n_id.split(":")[-1]
            )

            elements.append({
                "data": {
                    "id": n_id,
                    "label": f"{primary_label}\n{raw_text}",
                    "node_type": primary_label,
                    "details": json.dumps(n_data["properties"], indent=2),
                    "color": styling["color"],
                    "shape": styling["shape"],
                    "size": styling["size"],
                }
            })

        # Add Edges
        for i, edge in enumerate(g.edges):
            elements.append({
                "data": {
                    "id": f"edge_{i}",
                    "source": edge["source"],
                    "target": edge["target"],
                    "label": edge["relation"],
                }
            })

        # Local script bundling or fallback
        js_inclusion = ""
        if CYTOSCAPE_JS_PATH.is_file():
            js_code = CYTOSCAPE_JS_PATH.read_text(encoding="utf-8")
            js_inclusion = f"<script>{js_code}</script>"
        else:
            js_inclusion = '<script src="https://cdnjs.cloudflare.com/ajax/libs/cytoscape/3.28.1/cytoscape.min.js"></script>'

        safe_server_name = html.escape(server_name)
        json_elements_str = json.dumps(elements, indent=2)

        html_template = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Shadowprint Exploit Knowledge Graph — {safe_server_name}</title>
    {js_inclusion}
    <style>
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background-color: #0b0f19;
            color: #f1f5f9;
            overflow: hidden;
            display: flex;
            height: 100vh;
        }}
        #sidebar {{
            width: 380px;
            background: #111827;
            border-right: 1px solid #1f2937;
            padding: 24px;
            display: flex;
            flex-direction: column;
            overflow-y: auto;
            z-index: 10;
        }}
        #cy {{
            flex: 1;
            height: 100vh;
            background: radial-gradient(circle at center, #111827 0%, #0b0f19 100%);
        }}
        h1 {{ font-size: 1.25rem; font-weight: 700; color: #f8fafc; margin-bottom: 8px; }}
        .badge {{
            display: inline-block;
            padding: 4px 10px;
            background: #ef444420;
            color: #ef4444;
            border: 1px solid #ef444450;
            border-radius: 9999px;
            font-size: 0.75rem;
            font-weight: 600;
            margin-bottom: 20px;
        }}
        .legend {{ margin-top: auto; padding-top: 20px; border-top: 1px solid #1f2937; }}
        .legend-item {{ display: flex; align-items: center; margin-bottom: 8px; font-size: 0.825rem; color: #94a3b8; }}
        .legend-dot {{ width: 12px; height: 12px; border-radius: 50%; margin-right: 10px; }}
        #details-panel {{
            background: #1e293b;
            padding: 16px;
            border-radius: 8px;
            border: 1px solid #334155;
            margin-top: 16px;
            font-size: 0.85rem;
            white-space: pre-wrap;
            word-break: break-all;
            max-height: 300px;
            overflow-y: auto;
            font-family: monospace;
            display: none;
        }}
    </style>
</head>
<body>
    <div id="sidebar">
        <h1>🕸️ Exploit Knowledge Graph</h1>
        <div class="badge">Target: {safe_server_name}</div>
        <p style="font-size: 0.875rem; color: #94a3b8; line-height: 1.5;">
            FalkorDB GraphBLAS multi-hop topology. Click any node to inspect detailed taint properties, AST locations, and vulnerability evidence.
        </p>

        <div id="details-header" style="margin-top: 24px; font-weight: 600; font-size: 0.9rem; color: #38bdf8; display: none;">Selected Node:</div>
        <div id="details-panel"></div>

        <div class="legend">
            <div style="font-weight: 600; font-size: 0.85rem; margin-bottom: 12px; color: #e2e8f0;">Graph Ontology Legend</div>
            <div class="legend-item"><div class="legend-dot" style="background: #38bdf8;"></div>MCPServer</div>
            <div class="legend-item"><div class="legend-dot" style="background: #facc15;"></div>MCP Tool</div>
            <div class="legend-item"><div class="legend-dot" style="background: #94a3b8;"></div>Parameter (Taint Source)</div>
            <div class="legend-item"><div class="legend-dot" style="background: #ef4444;"></div>Code AST Sink (eval / shell)</div>
            <div class="legend-item"><div class="legend-dot" style="background: #c084fc;"></div>Canary Target (Honeypot)</div>
            <div class="legend-item"><div class="legend-dot" style="background: #fb7185;"></div>Network Sink (Exfiltration)</div>
            <div class="legend-item"><div class="legend-dot" style="background: #f87171;"></div>Vulnerability Finding</div>
        </div>
    </div>
    <div id="cy"></div>

    <script type="application/json" id="cy-data">
{json_elements_str}
    </script>

    <script>
        const elementsData = JSON.parse(document.getElementById('cy-data').textContent);
        const cy = cytoscape({{
            container: document.getElementById('cy'),
            elements: elementsData,
            style: [
                {{
                    selector: 'node',
                    style: {{
                        'background-color': 'data(color)',
                        'shape': 'data(shape)',
                        'width': 'data(size)',
                        'height': 'data(size)',
                        'label': 'data(label)',
                        'color': '#f8fafc',
                        'font-size': '10px',
                        'text-valign': 'center',
                        'text-halign': 'center',
                        'text-wrap': 'wrap',
                        'text-max-width': '70px',
                        'border-width': 2,
                        'border-color': '#ffffff20'
                    }}
                }},
                {{
                    selector: 'edge',
                    style: {{
                        'width': 2,
                        'line-color': '#475569',
                        'target-arrow-color': '#94a3b8',
                        'target-arrow-shape': 'triangle',
                        'curve-style': 'bezier',
                        'label': 'data(label)',
                        'color': '#94a3b8',
                        'font-size': '8px',
                        'text-rotation': 'autorotate',
                        'text-background-color': '#0b0f19',
                        'text-background-opacity': 0.8,
                        'text-background-padding': '2px'
                    }}
                }},
                {{
                    selector: ':selected',
                    style: {{
                        'border-color': '#38bdf8',
                        'border-width': 4,
                        'line-color': '#38bdf8',
                        'target-arrow-color': '#38bdf8'
                    }}
                }}
            ],
            layout: {{
                name: 'breadthfirst',
                directed: true,
                padding: 40,
                spacingFactor: 1.4
            }}
        }});

        cy.on('tap', 'node', function(evt) {{
            const node = evt.target;
            const details = node.data('details');
            document.getElementById('details-header').style.display = 'block';
            document.getElementById('details-header').innerText = node.data('node_type') + ': ' + node.id();
            const panel = document.getElementById('details-panel');
            panel.style.display = 'block';
            panel.innerText = details;
        }});
    </script>
</body>
</html>
"""
        out_file = Path(output_path)
        out_file.parent.mkdir(parents=True, exist_ok=True)
        out_file.write_text(html_template, encoding="utf-8")
        return str(out_file)
