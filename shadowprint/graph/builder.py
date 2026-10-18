"""
Exploit Knowledge Graph Builder.
Transforms raw findings, tool schemas, and execution traces from Engines S0–S3
into a fully connected FalkorDB Exploit Knowledge Graph (EKG).
"""

import time
import re
from typing import Dict, Any, List, Optional
from pathlib import Path

from shadowprint.models import AuditReport, Finding, Snapshot, ToolDefinition
from shadowprint.graph.schema import NodeLabel, RelType
from shadowprint.graph.client import FalkorDBClient


class GraphBuilder:
    """
    Constructs the Exploit Knowledge Graph from audit results.
    """
    def __init__(self, client: Optional[FalkorDBClient] = None):
        self.client = client or FalkorDBClient.get_instance()

    def build_from_report(
        self,
        report: AuditReport,
        target_dir: Optional[Path] = None,
        live_snapshot: Optional[Snapshot] = None,
    ) -> Dict[str, Any]:
        """
        Ingests the complete AuditReport into FalkorDB.
        Returns graph ingestion statistics.
        """
        start_time = time.perf_counter()
        server_name = report.target
        session_id = f"session_{server_name}_{int(report.timestamp)}"

        # 1. Ingest MCPServer node
        server_node_id = f"server:{server_name}"
        self.client.add_node(
            node_id=server_node_id,
            labels=[NodeLabel.MCP_SERVER.value],
            properties={
                "name": server_name,
                "status": report.status,
                "last_audited": report.timestamp,
                "total_findings": len(report.findings),
            },
        )

        # 2. Ingest AuditSession node
        session_node_id = f"session:{session_id}"
        self.client.add_node(
            node_id=session_node_id,
            labels=[NodeLabel.AUDIT_SESSION.value],
            properties={
                "session_id": session_id,
                "server_name": server_name,
                "timestamp": report.timestamp,
                "status": report.status,
            },
        )
        self.client.add_edge(
            source_id=session_node_id,
            target_id=server_node_id,
            relation=RelType.AUDITED.value,
        )

        # 3. Ingest Tools and Parameters from Snapshot or Findings
        tools_dict: Dict[str, Dict[str, Any]] = {}
        snapshot = live_snapshot or report.snapshot

        if snapshot and snapshot.tools:
            for tool in snapshot.tools:
                tools_dict[tool.name] = {
                    "name": tool.name,
                    "description": tool.description or "",
                    "inputSchema": tool.inputSchema or {},
                }
        else:
            # Infer tools from findings
            for f in report.findings:
                if f.tool and f.tool != "__server__" and f.tool not in tools_dict:
                    tools_dict[f.tool] = {
                        "name": f.tool,
                        "description": f.claim or "",
                        "inputSchema": {},
                    }

        tool_node_ids: Dict[str, str] = {}
        for tool_name, t_info in tools_dict.items():
            t_id = f"tool:{server_name}:{tool_name}"
            tool_node_ids[tool_name] = t_id
            self.client.add_node(
                node_id=t_id,
                labels=[NodeLabel.TOOL.value],
                properties={
                    "name": tool_name,
                    "server_name": server_name,
                    "description": t_info.get("description", "")[:250],
                    "is_safe": False if any(f.tool == tool_name and f.severity in ("critical", "high") for f in report.findings) else True,
                },
            )
            # Edge: Server -> Tool
            self.client.add_edge(
                source_id=server_node_id,
                target_id=t_id,
                relation=RelType.EXPOSES.value,
            )

            # Ingest Parameters
            schema = t_info.get("inputSchema", {})
            properties = schema.get("properties", {})
            for p_name, p_val in properties.items():
                p_id = f"param:{server_name}:{tool_name}:{p_name}"
                p_type = p_val.get("type", "string") if isinstance(p_val, dict) else "string"
                p_desc = p_val.get("description", "") if isinstance(p_val, dict) else ""
                self.client.add_node(
                    node_id=p_id,
                    labels=[NodeLabel.PARAMETER.value],
                    properties={
                        "name": p_name,
                        "tool_name": tool_name,
                        "type": p_type,
                        "description": p_desc[:200],
                    },
                )
                self.client.add_edge(
                    source_id=t_id,
                    target_id=p_id,
                    relation=RelType.ACCEPTS.value,
                )

        # 4. Ingest Findings and Establish Multi-Hop Edges
        created_ast_sinks: Dict[str, str] = {}
        canary_node_id: Optional[str] = None
        network_node_id: Optional[str] = None

        for f in report.findings:
            f_node_id = f"finding:{f.id}"
            self.client.add_node(
                node_id=f_node_id,
                labels=[NodeLabel.FINDING.value],
                properties={
                    "finding_id": f.id,
                    "engine": f.engine,
                    "category": f.category,
                    "severity": f.severity,
                    "confidence": f.confidence,
                    "assessment": f.assessment,
                    "evidence_snippet": f.evidence[:300],
                    "remediation": f.remediation[:200],
                },
            )

            # Link finding to Tool or Server
            if f.tool in tool_node_ids:
                self.client.add_edge(
                    source_id=tool_node_ids[f.tool],
                    target_id=f_node_id,
                    relation=RelType.VULNERABLE_TO.value,
                )
            else:
                self.client.add_edge(
                    source_id=server_node_id,
                    target_id=f_node_id,
                    relation=RelType.VULNERABLE_TO.value,
                )

            # ENGINE S0: AST Execution Sinks & Secrets
            if f.engine == "S0" or "eval" in f.evidence or "subprocess" in f.evidence or "os.system" in f.evidence or "nosec" in f.evidence or "AKIA" in f.evidence:
                sink_type = f.category or "dangerous_execution"
                loc_file = f.location.file if f.location else "server.py"
                loc_line = f.location.line if f.location and f.location.line else 59
                sink_id = f"sink:{server_name}:{loc_file}:{loc_line}:{sink_type}"

                if sink_id not in created_ast_sinks:
                    created_ast_sinks[sink_id] = sink_id
                    self.client.add_node(
                        node_id=sink_id,
                        labels=[NodeLabel.CODE_AST_SINK.value],
                        properties={
                            "sink_type": sink_type,
                            "file": loc_file,
                            "line": loc_line,
                            "evidence": f.evidence[:250],
                        },
                    )

                self.client.add_edge(
                    source_id=f_node_id,
                    target_id=sink_id,
                    relation=RelType.LOCATED_AT.value,
                )
                self.client.add_edge(
                    source_id=f_node_id,
                    target_id=sink_id,
                    relation=RelType.EXECUTES_SINK.value,
                )

                # Connect Taint Flow from Parameter to AST Sink
                if f.tool in tools_dict:
                    schema_props = tools_dict[f.tool].get("inputSchema", {}).get("properties", {})
                    for p_name in schema_props.keys():
                        p_id = f"param:{server_name}:{f.tool}:{p_name}"
                        self.client.add_edge(
                            source_id=p_id,
                            target_id=sink_id,
                            relation=RelType.TAINT_FLOWS_TO.value,
                            properties={"sanitized": False},
                        )

            # ENGINE S1: Prompt Injections & Zero-Width Steganography
            if f.engine == "S1" or "prompt_injection" in f.category or "steganography" in f.category or "system" in f.evidence.lower():
                if f.tool in tool_node_ids:
                    self.client.add_edge(
                        source_id=f_node_id,
                        target_id=tool_node_ids[f.tool],
                        relation=RelType.HIJACKS_CONTROL.value,
                    )
                else:
                    # Link to tools whose descriptions contain the injection or to the sole exposed tool
                    matched = False
                    for t_name, t_info in tools_dict.items():
                        t_desc = t_info.get("description", "").lower()
                        if "system" in t_desc or "ignore" in t_desc or "exfiltrate" in t_desc:
                            self.client.add_edge(
                                source_id=f_node_id,
                                target_id=tool_node_ids[t_name],
                                relation=RelType.HIJACKS_CONTROL.value,
                            )
                            matched = True
                    if not matched and len(tool_node_ids) == 1:
                        sole_tool_id = list(tool_node_ids.values())[0]
                        self.client.add_edge(
                            source_id=f_node_id,
                            target_id=sole_tool_id,
                            relation=RelType.HIJACKS_CONTROL.value,
                        )

            # ENGINE S2: Dynamic Probing - Canary Honeytrap Touches
            if "canary" in f.evidence.lower() or "honeypot" in f.evidence.lower() or "canary_creds" in f.evidence.lower():
                if not canary_node_id:
                    canary_node_id = f"canary:{server_name}:creds"
                    self.client.add_node(
                        node_id=canary_node_id,
                        labels=[NodeLabel.CANARY_TARGET.value],
                        properties={
                            "file_path": "/tmp/canary_creds.env",
                            "canary_type": "credential_honeypot",
                            "status": "COMPROMISED",
                        },
                    )
                # Link AST sinks to canary
                for sink_id in created_ast_sinks.values():
                    self.client.add_edge(
                        source_id=sink_id,
                        target_id=canary_node_id,
                        relation=RelType.READS_HONEYPOT.value,
                    )

            # ENGINE S2: Dynamic Probing - Network Sockets & Exfiltration Sinks
            if "socket" in f.evidence.lower() or "8080" in f.evidence or "sink" in f.evidence.lower() or "exfil" in f.evidence.lower():
                if not network_node_id:
                    network_node_id = f"network:{server_name}:8080"
                    self.client.add_node(
                        node_id=network_node_id,
                        labels=[NodeLabel.NETWORK_SINK.value],
                        properties={
                            "endpoint": "http://127.0.0.1:8080/sink",
                            "ip": "127.0.0.1",
                            "port": 8080,
                            "protocol": "HTTP",
                        },
                    )
                # Link AST sinks and tool to network sink
                for sink_id in created_ast_sinks.values():
                    self.client.add_edge(
                        source_id=sink_id,
                        target_id=network_node_id,
                        relation=RelType.CONNECTS_TO.value,
                    )
                if f.tool in tool_node_ids:
                    self.client.add_edge(
                        source_id=tool_node_ids[f.tool],
                        target_id=network_node_id,
                        relation=RelType.EXFILTRATES_TO.value,
                    )

            # ENGINE S3: Schema Drift & Live Rug-Pull
            if f.engine == "S3" or "drift" in f.category.lower() or "tampering" in f.category.lower():
                self.client.add_edge(
                    source_id=session_node_id,
                    target_id=f_node_id,
                    relation="DETECTED_MUTATION",
                )

        duration_ms = (time.perf_counter() - start_time) * 1000
        mem_graph = self.client.in_memory_graph

        stats = {
            "server": server_name,
            "session_id": session_id,
            "total_nodes": len(mem_graph.nodes),
            "total_edges": len(mem_graph.edges),
            "ast_sinks": len(created_ast_sinks),
            "canaries_touched": 1 if canary_node_id else 0,
            "network_sinks": 1 if network_node_id else 0,
            "ingestion_time_ms": round(duration_ms, 2),
            "backend": self.client.backend_type,
        }
        return stats
