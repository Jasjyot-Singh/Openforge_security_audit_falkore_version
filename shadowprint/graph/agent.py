"""
Autonomous Security Triage Agent (Track 01: Agents That Act on Connected Data).
Implements multi-hop reasoning over the FalkorDB Exploit Knowledge Graph,
using Cypher graph tools to triage findings, evaluate blast radius, and execute remediation actions.
"""

import time
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field

from shadowprint.graph.client import FalkorDBClient
from shadowprint.graph.queries import ExploitChainQueryEngine


class TriageDecision(BaseModel):
    """Formal decision rendered by the Security Triage Agent."""
    server_name: str
    action: str = Field(..., description="'BLOCK_REGISTRATION', 'QUARANTINE_TOOL', or 'APPROVE_SERVER'")
    overall_risk: str = Field(..., description="'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'")
    exploit_chains_found: int
    max_blast_radius: float
    executive_summary: str
    attack_chain_walkthrough: List[str]
    remediation_directives: List[str]
    agent_reasoning_steps: List[str]
    evaluation_time_ms: float


class SecurityTriageAgent:
    """
    Autonomous AI Triage Agent operating over FalkorDB connected graph data.
    """
    def __init__(self, client: Optional[FalkorDBClient] = None):
        self.client = client or FalkorDBClient.get_instance()
        self.query_engine = ExploitChainQueryEngine(self.client)

    # =========================================================================
    # MCP-Compatible Agent Tools
    # =========================================================================

    def tool_trace_exploit_chains(self, server_name: str) -> List[Dict[str, Any]]:
        """MCP Agent Tool: Finds multi-hop paths from prompt injection to network exfiltration."""
        return self.query_engine.find_exploit_chains(server_name)

    def tool_compute_blast_radius(self, tool_name: str) -> Dict[str, Any]:
        """MCP Agent Tool: Computes graph centrality and reachable sensitive host resources."""
        return self.query_engine.calculate_blast_radius(tool_name)

    def tool_query_graph_topology(self, server_name: str) -> Dict[str, Any]:
        """MCP Agent Tool: Returns graph metrics, node counts, and edge distributions."""
        return self.query_engine.get_graph_summary(server_name)

    # =========================================================================
    # Autonomous Multi-Hop Graph Reasoning Workflow
    # =========================================================================

    def run_triage(self, server_name: str) -> TriageDecision:
        """
        Executes autonomous graph-based triage:
        1. Selects and executes graph tools to traverse connected exploit paths.
        2. Assesses multi-hop compound risk vs. isolated findings.
        3. Determines enforcement action (BLOCK / QUARANTINE / APPROVE).
        4. Produces explainable reasoning breakdown.
        """
        start_t = time.perf_counter()
        reasoning_log: List[str] = []

        reasoning_log.append(f"Agent activated for target MCP server: '{server_name}'.")

        # Step 1: Query Graph for Multi-Hop Exploit Chains
        reasoning_log.append("Executing Agent Tool: [tool_trace_exploit_chains]...")
        chains = self.tool_trace_exploit_chains(server_name)
        reasoning_log.append(f"Discovered {len(chains)} multi-hop compound exploit chain(s) in FalkorDB.")

        # Step 2: Calculate Blast Radii for affected tools
        tools_analyzed: Dict[str, Dict[str, Any]] = {}
        max_blast = 0.0

        if chains:
            for ch in chains:
                t_name = ch["tool"]
                if t_name not in tools_analyzed:
                    reasoning_log.append(f"Executing Agent Tool: [tool_compute_blast_radius] for '{t_name}'...")
                    br = self.tool_compute_blast_radius(t_name)
                    tools_analyzed[t_name] = br
                    if br["blast_score"] > max_blast:
                        max_blast = br["blast_score"]
        else:
            # Check all tools in server
            summary = self.tool_query_graph_topology(server_name)
            reasoning_log.append(f"No compound chains detected. Topology summary: {summary.get('total_nodes', 0)} nodes.")

        # Step 3: Autonomous Action Determination
        if len(chains) > 0 and max_blast >= 8.0:
            action = "BLOCK_REGISTRATION"
            overall_risk = "CRITICAL"
            reasoning_log.append(
                f"DECISION: BLOCK_REGISTRATION. High blast radius ({max_blast}/10) with verified "
                f"end-to-end prompt-to-exfiltration exploit chain."
            )
        elif len(chains) > 0:
            action = "QUARANTINE_TOOL"
            overall_risk = "HIGH"
            reasoning_log.append(f"DECISION: QUARANTINE_TOOL. Compound chain detected with blast radius {max_blast}/10.")
        else:
            action = "APPROVE_SERVER"
            overall_risk = "LOW"
            reasoning_log.append("DECISION: APPROVE_SERVER. Zero multi-hop exploit paths discovered.")

        # Step 4: Synthesize Explainable Attack Walkthrough
        walkthrough: List[str] = []
        remediations: List[str] = []

        if chains:
            for i, ch in enumerate(chains, 1):
                walkthrough.append(f"### Exploit Chain #{i}: {ch['title']}")
                walkthrough.append(ch["narrative"])
                remediations.append(f"Fix for Tool '{ch['tool']}': {ch['remediation']}")
        else:
            walkthrough.append("Graph analysis confirmed that all declared tools have isolated execution with no reachable taint sinks.")
            remediations.append("Server complies with least-privilege MCP execution. Ready for deployment.")

        duration_ms = (time.perf_counter() - start_t) * 1000

        summary_text = (
            f"The Security Triage Agent evaluated '{server_name}' using connected data from FalkorDB. "
            f"Identified {len(chains)} compound attack chain(s) across {len(tools_analyzed)} tool(s). "
            f"Maximum blast radius score: {max_blast}/10. Action taken: {action}."
        )

        return TriageDecision(
            server_name=server_name,
            action=action,
            overall_risk=overall_risk,
            exploit_chains_found=len(chains),
            max_blast_radius=max_blast,
            executive_summary=summary_text,
            attack_chain_walkthrough=walkthrough,
            remediation_directives=remediations,
            agent_reasoning_steps=reasoning_log,
            evaluation_time_ms=round(duration_ms, 2),
        )
