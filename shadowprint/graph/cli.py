"""
FalkorDB Graph CLI Commands (Track 01: Agents That Act on Connected Data).
Exposes Exploit Knowledge Graph synchronization, multi-hop exploit chain queries,
blast radius calculations, and autonomous triage agent decision commands.
Requires a live FalkorDB instance on localhost:6379 (or explicit --use-test-double).
"""

import os
import sys
import asyncio
import time
from pathlib import Path
from typing import Optional, List, Dict, Any, Tuple

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from shadowprint.models import AuditReport, Finding, Snapshot
from shadowprint.normalizer import normalize_findings
from shadowprint.s0_static.scanner import scan_static
from shadowprint.s1_metadata.analyzer import analyze_metadata
from shadowprint.client.mcp_client import GuardedMCPClient
from shadowprint.s2_prober.output_scanner import OutputScanner

from shadowprint.graph.client import FalkorDBClient
from shadowprint.graph.builder import GraphBuilder
from shadowprint.graph.queries import ExploitChainQueryEngine
from shadowprint.graph.agent import SecurityTriageAgent
from shadowprint.graph.visualizer import GraphVisualizer

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent

console = Console(legacy_windows=False)
graph_app = typer.Typer(
    name="graph",
    help="FalkorDB Exploit Knowledge Graph (EKG) & AI Triage Agent",
    add_completion=False,
)


def _resolve_target(target: str) -> Tuple[Path, str, Path]:
    target_path = Path(target)
    if not target_path.exists():
        candidate = PROJECT_ROOT / target
        if candidate.exists():
            target_path = candidate
        else:
            console.print(f"[bold red]Error:[/bold red] Target path '{target}' does not exist.")
            raise typer.Exit(code=1)
    target_path = target_path.resolve()
    server_name = target_path.name if target_path.is_dir() else target_path.parent.name
    target_dir = target_path if target_path.is_dir() else target_path.parent
    return target_path, server_name, target_dir


def _get_graph_client(use_test_double: bool) -> FalkorDBClient:
    """
    Retrieves the FalkorDB client. Enforces connection to live FalkorDB daemon
    unless --use-test-double is explicitly specified (satisfying Block 1.1).
    """
    FalkorDBClient.reset_instance()
    if use_test_double:
        return FalkorDBClient.get_instance(use_test_double=True)

    client = FalkorDBClient.get_instance(use_test_double=False)
    if not client.is_connected:
        console.print(
            Panel(
                "[bold red]Error: FalkorDB daemon is not reachable on localhost:6379.[/bold red]\n\n"
                "Engine S5 requires an active FalkorDB instance for graph intelligence operations.\n\n"
                "[bold white]To start FalkorDB with Docker:[/bold white]\n"
                "  [cyan]docker run -p 6379:6379 -it --rm falkordb/falkordb:latest[/cyan]\n\n"
                "[dim](Note: For headless offline unit tests, re-run with [bold]--use-test-double[/bold])[/dim]",
                title="[bold red]FalkorDB Connection Required[/bold red]",
                border_style="red",
            )
        )
        raise typer.Exit(code=1)
    return client


def _run_quick_audit(target_path: Path, server_name: str, target_dir: Path) -> Tuple[AuditReport, Optional[Snapshot]]:
    """Runs an internal audit sweep to populate findings for graph ingestion."""
    all_findings: List[Finding] = []
    live_snapshot: Optional[Snapshot] = None

    # S2 Dynamic Entrypoint & Snapshot Fetch
    entrypoint = target_path if target_path.is_file() and target_path.suffix == ".py" else (target_dir / "server.py" if (target_dir / "server.py").is_file() else None)
    if entrypoint:
        async def _probe():
            client = GuardedMCPClient(command=sys.executable, args=[str(entrypoint)], timeout=3.0)
            snap = await client.fetch_snapshot(server_name)
            await client.start()
            dyn_findings = []
            try:
                await client.initialize()
                output_scanner = OutputScanner(server_name)
                for tool in snap.tools:
                    res = await client.call_tool(tool.name, {"expression": "10+20"})
                    if "content" in res:
                        for item in res["content"]:
                            dyn_findings.extend(output_scanner.scan_output(tool.name, item.get("text", "")))
            finally:
                await client.close()
            return dyn_findings, snap

        try:
            dyn_findings, live_snapshot = asyncio.run(_probe())
            all_findings.extend(dyn_findings)
        except Exception:
            pass

    # S0 Static
    s0_findings = scan_static(str(target_dir), server_name)
    all_findings.extend(s0_findings)

    # S1 Metadata (Passing live tools if available)
    s1_findings = analyze_metadata(
        target_path=str(target_dir),
        tools=live_snapshot.tools if live_snapshot else None,
        server_name=server_name,
    )
    all_findings.extend(s1_findings)

    merged = normalize_findings(all_findings)
    status = "FAILED" if any(f.severity in ("critical", "high") for f in merged) else "PASSED"

    report = AuditReport(
        target=server_name,
        timestamp=time.time(),
        status=status,
        findings=merged,
        snapshot=live_snapshot,
    )
    return report, live_snapshot


@graph_app.command(name="sync")
def sync_graph(
    target: str = typer.Argument(..., help="Path to MCP server directory or script to ingest into graph"),
    use_test_double: bool = typer.Option(False, "--use-test-double", help="Run with headless test double instead of live FalkorDB daemon"),
):
    """
    Audit an MCP server and construct its Exploit Knowledge Graph (EKG) in FalkorDB.
    """
    target_path, server_name, target_dir = _resolve_target(target)
    client = _get_graph_client(use_test_double)

    with console.status(f"[bold cyan]Auditing '{server_name}' and constructing FalkorDB EKG...[/bold cyan]"):
        report, live_snapshot = _run_quick_audit(target_path, server_name, target_dir)
        builder = GraphBuilder(client)
        stats = builder.build_from_report(report, target_dir=target_dir, live_snapshot=live_snapshot)

    console.print(
        Panel(
            f"[bold green]Exploit Knowledge Graph Ingested Successfully![/bold green]\n\n"
            f"[bold white]Target Server:[/bold white]     {stats['server']}\n"
            f"[bold white]Graph Backend:[/bold white]     [cyan]{stats['backend']}[/cyan]\n"
            f"[bold white]Total Graph Nodes:[/bold white] {stats['total_nodes']}\n"
            f"[bold white]Total Graph Edges:[/bold white] {stats['total_edges']}\n"
            f"[bold white]AST Code Sinks:[/bold white]    {stats['ast_sinks']}\n"
            f"[bold white]Honeypot Canaries:[/bold white] {stats['canaries_touched']}\n"
            f"[bold white]Network Sinks:[/bold white]     {stats['network_sinks']}\n"
            f"[bold white]Ingestion Latency:[/bold white] [yellow]{stats['ingestion_time_ms']} ms[/yellow]",
            title="[bold green]FalkorDB EKG Ingestion Complete[/bold green]",
            border_style="green",
        )
    )


@graph_app.command(name="triage")
def triage_server(
    target: str = typer.Argument(..., help="Path to MCP server directory or script to triage"),
    use_test_double: bool = typer.Option(False, "--use-test-double", help="Run with headless test double instead of live FalkorDB daemon"),
):
    """
    Launch the autonomous AI Triage Agent to reason over FalkorDB connected exploit data.
    """
    target_path, server_name, target_dir = _resolve_target(target)
    client = _get_graph_client(use_test_double)

    # Ingest graph first
    report, live_snapshot = _run_quick_audit(target_path, server_name, target_dir)
    builder = GraphBuilder(client)
    builder.build_from_report(report, target_dir=target_dir, live_snapshot=live_snapshot)

    agent = SecurityTriageAgent(client)
    with console.status(f"[bold magenta]Autonomous Security Triage Agent reasoning across graph...[/bold magenta]"):
        decision = agent.run_triage(server_name)

    color = "red" if decision.overall_risk == "CRITICAL" else ("yellow" if decision.overall_risk == "HIGH" else "green")
    steps_text = "\n".join(f"  [dim]•[/dim] {step}" for step in decision.agent_reasoning_steps)

    console.print(
        Panel(
            f"[bold {color}]DECISION: {decision.action}[/bold {color}]  ([bold]{decision.overall_risk} Risk[/bold])\n\n"
            f"[bold white]Backend:[/bold white]                 [cyan]{client.backend_type}[/cyan]\n"
            f"[bold white]Agent Executive Summary:[/bold white]\n{decision.executive_summary}\n\n"
            f"[bold white]Exploit Chains Discovered:[/bold white] [red]{decision.exploit_chains_found}[/red]\n"
            f"[bold white]Maximum Blast Radius:[/bold white]      [yellow]{decision.max_blast_radius} / 10.0[/yellow]\n"
            f"[bold white]Graph Reasoning Latency:[/bold white]   [dim]{decision.evaluation_time_ms} ms[/dim]\n\n"
            f"[bold white]Autonomous Reasoning Steps:[/bold white]\n{steps_text}",
            title=f"[bold {color}]🤖 Autonomous Security Triage Agent Decision[/bold {color}]",
            border_style=color,
        )
    )

    if decision.patch_file:
        console.print(f"[bold red]⛔ ENFORCEMENT:[/bold red] Server added to [bold]shadowprint_denylist.json[/bold]. Approval locked.")
        console.print(f"[bold green]✔ Patch emitted:[/bold green] [cyan]{decision.patch_file}[/cyan]\n")

    if decision.attack_chain_walkthrough:
        console.print("[bold red]── Multi-Hop Attack Lineage ─────────────────────────────────────[/bold red]")
        for entry in decision.attack_chain_walkthrough:
            console.print(entry)

    if decision.remediation_directives:
        console.print("\n[bold green]── Prescriptive Remediation Directives ──────────────────────────[/bold green]")
        for rem in decision.remediation_directives:
            console.print(f"[green]✔[/green] {rem}")
    console.print()


@graph_app.command(name="chains")
def find_chains(
    target: str = typer.Argument(..., help="Path to MCP server directory or script"),
    use_test_double: bool = typer.Option(False, "--use-test-double", help="Run with headless test double instead of live FalkorDB daemon"),
):
    """
    Search FalkorDB for multi-hop compound exploit chains and display the ASCII attack tree.
    """
    target_path, server_name, target_dir = _resolve_target(target)
    client = _get_graph_client(use_test_double)

    report, live_snapshot = _run_quick_audit(target_path, server_name, target_dir)
    GraphBuilder(client).build_from_report(report, target_dir=target_dir, live_snapshot=live_snapshot)

    engine = ExploitChainQueryEngine(client)
    chains = engine.find_exploit_chains(server_name)

    visualizer = GraphVisualizer(client)
    visualizer.render_ascii_graph(chains, server_name)


@graph_app.command(name="blast-radius")
def blast_radius(
    target: str = typer.Argument(..., help="Path to MCP server directory or script"),
    tool: Optional[str] = typer.Option(None, "--tool", "-t", help="Specific tool name to inspect"),
    use_test_double: bool = typer.Option(False, "--use-test-double", help="Run with headless test double instead of live FalkorDB daemon"),
):
    """
    Calculate the Graph Centrality Blast Radius score for tools in an MCP server.
    """
    target_path, server_name, target_dir = _resolve_target(target)
    client = _get_graph_client(use_test_double)

    report, live_snapshot = _run_quick_audit(target_path, server_name, target_dir)
    GraphBuilder(client).build_from_report(report, target_dir=target_dir, live_snapshot=live_snapshot)

    engine = ExploitChainQueryEngine(client)

    tools_to_check = [tool] if tool else [t.name for t in (live_snapshot.tools if live_snapshot else [])]
    if not tools_to_check:
        tools_to_check = [f.tool for f in report.findings if f.tool != "__server__"]

    tools_to_check = list(set(tools_to_check)) or ["omni_evaluator"]

    table = Table(
        title=f"Graph Blast Radius Reachability ({server_name}) — {client.backend_type}",
        header_style="bold cyan",
    )
    table.add_column("Tool Name", style="bold white", width=20)
    table.add_column("Blast Radius Score", justify="center", width=20)
    table.add_column("Risk Level", justify="center", width=14)
    table.add_column("Reachable Sensitive Sinks", width=36)

    for t_name in tools_to_check:
        res = engine.calculate_blast_radius(t_name, server_name=server_name)
        color = "red" if res["blast_score"] >= 8.0 else ("yellow" if res["blast_score"] >= 5.0 else "green")
        targets_str = ", ".join(r["target"] for r in res.get("reachable_resources", [])) or "None (Isolated)"
        table.add_row(
            t_name,
            f"[{color}]{res['blast_score']} / 10.0[/{color}]",
            f"[{color}]{res['risk_level']}[/{color}]",
            f"[dim]{targets_str}[/dim]",
        )

    console.print(table)


@graph_app.command(name="export-html")
def export_html(
    target: str = typer.Argument(..., help="Path to MCP server directory or script"),
    output: str = typer.Option("output/graph.html", "--output", "-o", help="Path for HTML visualization export"),
    use_test_double: bool = typer.Option(False, "--use-test-double", help="Run with headless test double instead of live FalkorDB daemon"),
):
    """
    Export the FalkorDB Exploit Knowledge Graph as an interactive Cytoscape.js HTML file.
    """
    target_path, server_name, target_dir = _resolve_target(target)
    client = _get_graph_client(use_test_double)

    report, live_snapshot = _run_quick_audit(target_path, server_name, target_dir)
    GraphBuilder(client).build_from_report(report, target_dir=target_dir, live_snapshot=live_snapshot)

    visualizer = GraphVisualizer(client)
    out_file = visualizer.generate_cytoscape_html(server_name, output)

    console.print(f"[bold green]✔ Interactive Exploit Knowledge Graph exported to:[/bold green] [cyan]{out_file}[/cyan]")
    console.print(f"[dim]Backend used: {client.backend_type}[/dim]")
