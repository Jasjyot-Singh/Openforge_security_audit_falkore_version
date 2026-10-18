"""
FalkorDB Exploit Knowledge Graph (EKG) Schema and Ontology.
Defines node labels, relationship types, properties, and GraphBLAS index definitions
for representing MCP servers, tools, code sinks, canaries, and multi-hop attack chains.
"""

from typing import Dict, Any, List
from enum import Enum


class NodeLabel(str, Enum):
    """Primary node labels in the Exploit Knowledge Graph."""
    MCP_SERVER = "MCPServer"
    TOOL = "Tool"
    PARAMETER = "Parameter"
    FINDING = "Finding"
    CODE_AST_SINK = "CodeASTSink"
    CANARY_TARGET = "CanaryTarget"
    NETWORK_SINK = "NetworkSink"
    AUDIT_SESSION = "AuditSession"
    AGENT_ORCHESTRATOR = "AgentOrchestrator"


class RelType(str, Enum):
    """Relationship (Edge) types connecting nodes in the EKG."""
    EXPOSES = "EXPOSES"                        # (MCPServer)-[:EXPOSES]->(Tool)
    ACCEPTS = "ACCEPTS"                        # (Tool)-[:ACCEPTS]->(Parameter)
    VULNERABLE_TO = "VULNERABLE_TO"            # (Tool)-[:VULNERABLE_TO]->(Finding)
    TAINT_FLOWS_TO = "TAINT_FLOWS_TO"          # (Parameter)-[:TAINT_FLOWS_TO]->(CodeASTSink)
    LOCATED_AT = "LOCATED_AT"                  # (Finding)-[:LOCATED_AT]->(CodeASTSink)
    HIJACKS_CONTROL = "HIJACKS_CONTROL"        # (Finding)-[:HIJACKS_CONTROL]->(Tool)
    EXECUTES_SINK = "EXECUTES_SINK"            # (Finding)-[:EXECUTES_SINK]->(CodeASTSink)
    READS_HONEYPOT = "READS_HONEYPOT"          # (CodeASTSink)-[:READS_HONEYPOT]->(CanaryTarget)
    CONNECTS_TO = "CONNECTS_TO"                # (CodeASTSink)-[:CONNECTS_TO]->(NetworkSink)
    EXFILTRATES_TO = "EXFILTRATES_TO"          # (Tool)-[:EXFILTRATES_TO]->(NetworkSink)
    AUDITED = "AUDITED"                        # (AuditSession)-[:AUDITED]->(MCPServer)
    MUTATED_FROM = "MUTATED_FROM"              # (AuditSession)-[:MUTATED_FROM]->(AuditSession)
    DETECTED_MUTATION = "DETECTED_MUTATION"    # (AuditSession)-[:DETECTED_MUTATION]->(Finding)


# Pre-defined GraphBLAS index creation statements for ultra-fast Cypher lookups
GRAPHBLAS_INDEX_STATEMENTS = [
    "CREATE INDEX FOR (s:MCPServer) ON (s.name)",
    "CREATE INDEX FOR (t:Tool) ON (t.server, t.name)",
    "CREATE INDEX FOR (f:Finding) ON (f.severity)",
    "CREATE INDEX FOR (f:Finding) ON (f.engine)",
    "CREATE INDEX FOR (a:AuditSession) ON (a.session_id)",
    "CREATE INDEX FOR (sink:CodeASTSink) ON (sink.sink_type)",
]
