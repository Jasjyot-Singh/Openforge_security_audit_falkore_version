"""
Shadowprint CLI Orchestrator.
Command-line interface for auditing MCP servers, inspecting metadata,
dynamic probing, cryptographic baseline pinning, and live drift monitoring.
"""

import os
import sys
import time
import asyncio
import logging
from pathlib import Path
from typing import Optional, List, Dict, Any, Tuple
import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

if sys.platform == "win32":
    try:
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        if hasattr(sys.stderr, "reconfigure"):
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

from shadowprint.models import AuditReport, Finding, Snapshot, Pin, ToolDefinition
from shadowprint.normalizer import normalize_findings
from shadowprint.s0_static.scanner import scan_static
from shadowprint.s1_metadata.analyzer import analyze_metadata
from shadowprint.s1_metadata.prompt_guard import PromptGuard
from shadowprint.s2_prober.output_scanner import OutputScanner
from shadowprint.s2_prober.canary_tripwire import CanaryTripwire
from shadowprint.s3_integrity.db import PinDatabase
from shadowprint.s3_integrity.hasher import ThreeLayerHasher
from shadowprint.s3_integrity.differ import IntegrityDiffer
from shadowprint.s3_integrity.watcher import LiveWatcher
from shadowprint.client.mcp_client import GuardedMCPClient
from shadowprint.s4_reporting.terminal_ui import render_audit_report, render_banner
from shadowprint.s4_reporting.markdown_reporter import generate_markdown_report
from shadowprint.s4_reporting.sarif_exporter import export_to_sarif
from shadowprint.graph.cli import graph_app
from shadowprint.graph.client import FalkorDBClient
from shadowprint.graph.builder import GraphBuilder
from shadowprint.graph.queries import ExploitChainQueryEngine

logger = logging.getLogger("shadowprint.cli")

app = typer.Typer(
    name="shadowprint",
    help="Shadowprint — Model Context Protocol Security Auditor & Graph Intelligence",
    add_completion=False,
)
app.add_typer(graph_app, name="graph")
console = Console(legacy_windows=False)


def find_entrypoint(target_path: Path) -> Optional[Path]:
    """Resolves the executable Python script for an MCP server."""
    if target_path.is_file() and target_path.suffix == ".py":
        return target_path
    if target_path.is_dir():
        server_py = target_path / "server.py"
        if server_py.is_file():
            return server_py
        for candidate in target_path.glob("*.py"):
            return candidate
    return None


def resolve_target_path(target: str) -> Path:
    """Resolves target path against current working directory or PROJECT_ROOT."""
    p = Path(target)
    if p.exists():
        return p.resolve()
    candidate = PROJECT_ROOT / target
    if candidate.exists():
        return candidate.resolve()
    return p.resolve()



async def run_dynamic_checks(
    entrypoint: Path, server_name: str, target_dir: Path
) -> Tuple[List[Finding], Optional[Snapshot]]:
    """
    Executes Engine S2 Dynamic Probing and fetches a live snapshot.
    """
    findings: List[Finding] = []
    live_snapshot: Optional[Snapshot] = None

    client = GuardedMCPClient(command=sys.executable, args=[str(entrypoint)], timeout=8.0)
    try:
        live_snapshot = await client.fetch_snapshot(server_name)
    except Exception as e:
        logger.debug(f"Could not fetch snapshot dynamically: {e}")
        return findings, None

    # Probe tools over stdio & scan outputs for exfiltration
    await client.start()
    try:
        await client.initialize()
        output_scanner = OutputScanner(server_name)
        for tool in live_snapshot.tools:
            sample_args: Dict[str, Any] = {}
            if tool.inputSchema and "properties" in tool.inputSchema:
                for k, v in tool.inputSchema["properties"].items():
                    prop_type = v.get("type", "string")
                    if prop_type in ("number", "integer"):
                        sample_args[k] = 10
                    elif prop_type == "string":
                        sample_args[k] = "test"
            try:
                res = await client.call_tool(tool.name, sample_args)
                if "content" in res:
                    for item in res["content"]:
                        text = item.get("text", "")
                        out_findings = output_scanner.scan_output(tool.name, text)
                        findings.extend(out_findings)
            except Exception:
                pass
    except Exception as e:
        logger.debug(f"Dynamic probing failed: {e}")
    finally:
        await client.close()

    return findings, live_snapshot


@app.command(name="audit")
def audit(
    target: str = typer.Argument(..., help="Path to MCP server directory or script"),
    output_dir: str = typer.Option("output", "--output-dir", "-o", help="Directory for exported reports"),
    skip_static: bool = typer.Option(False, "--skip-static", help="Skip Engine S0 static analysis"),
    skip_metadata: bool = typer.Option(False, "--skip-metadata", help="Skip Engine S1 metadata inspection"),
    skip_dynamic: bool = typer.Option(False, "--skip-dynamic", help="Skip Engine S2 dynamic probing sweep"),
    skip_integrity: bool = typer.Option(False, "--skip-integrity", help="Skip Engine S3 integrity drift check"),
):
    """
    Run an end-to-end security audit against a target MCP server across Engines S0–S3.
    """
    target_path = resolve_target_path(target)
    if not target_path.exists():
        console.print(f"[bold red]Error:[/bold red] Target path '{target}' does not exist.")
        raise typer.Exit(code=1)

    server_name = target_path.name if target_path.is_dir() else target_path.parent.name
    target_dir = target_path if target_path.is_dir() else target_path.parent
    start_time = time.time()
    all_findings: List[Finding] = []
    live_snapshot: Optional[Snapshot] = None

    # 1. Engine S0: Static Code & Config Analysis
    if not skip_static:
        with console.status(f"[bold cyan]Running Engine S0 (Static Code Inspection)...[/bold cyan]"):
            s0_findings = scan_static(str(target_dir), server_name)
            all_findings.extend(s0_findings)

    # 2. Engine S1: Metadata & Prompt Injection Analysis
    if not skip_metadata:
        with console.status(f"[bold cyan]Running Engine S1 (Sandboxed Metadata Inspection)...[/bold cyan]"):
            s1_findings = analyze_metadata(target_path=str(target_dir), server_name=server_name)
            all_findings.extend(s1_findings)

    # 3. Engine S2: Dynamic Prober & Protocol Verification
    entrypoint = find_entrypoint(target_path)
    if entrypoint and not skip_dynamic:
        with console.status(f"[bold cyan]Running Engine S2 (Dynamic Least-Capability Prober)...[/bold cyan]"):
            s2_findings, live_snapshot = asyncio.run(run_dynamic_checks(entrypoint, server_name, target_dir))
            all_findings.extend(s2_findings)

    # 4. Engine S3: Integrity & Drift Check against Pinned Baseline
    if not skip_integrity and live_snapshot:
        with console.status(f"[bold cyan]Running Engine S3 (Cryptographic Baseline Pin & Diff)...[/bold cyan]"):
            db = PinDatabase()
            pinned_snapshot = db.get_pin_snapshot(server_name)
            if pinned_snapshot:
                differ = IntegrityDiffer(server_name)
                s3_findings = differ.compare_snapshots(pinned_snapshot, live_snapshot)
                all_findings.extend(s3_findings)

    # 5. Deduplicate and normalize
    merged_findings = normalize_findings(all_findings)

    # 6. Compute overall status
    if any(f.assessment == "FAIL" or f.severity in ("critical", "high") for f in merged_findings):
        status = "FAILED"
    elif any(f.assessment == "FLAGGED" or f.severity == "medium" for f in merged_findings):
        status = "FLAGGED"
    else:
        status = "PASSED"

    # Build AuditReport
    report = AuditReport(
        target=server_name,
        timestamp=start_time,
        status=status,
        findings=merged_findings,
        summary={
            "total": len(merged_findings),
            "critical": sum(1 for f in merged_findings if f.severity == "critical"),
            "high": sum(1 for f in merged_findings if f.severity == "high"),
            "medium": sum(1 for f in merged_findings if f.severity == "medium"),
            "low": sum(1 for f in merged_findings if f.severity == "low"),
        },
    )

    # Render Terminal UI
    render_audit_report(report)

    # 7. Sync with FalkorDB Exploit Knowledge Graph (EKG)
    try:
        g_client = FalkorDBClient.get_instance()
        g_builder = GraphBuilder(g_client)
        g_stats = g_builder.build_from_report(report, target_dir=target_dir, live_snapshot=live_snapshot)
        g_engine = ExploitChainQueryEngine(g_client)
        chains = g_engine.find_exploit_chains(server_name)
        if chains:
            console.print(
                Panel(
                    f"[bold red]CRITICAL: {len(chains)} Compound Exploit Chain(s) Discovered in FalkorDB EKG![/bold red]\n\n"
                    f"[bold white]Top Vector:[/bold white]     [yellow]{chains[0]['title']}[/yellow] ([red]{chains[0]['hop_count']} Hops[/red])\n"
                    f"[bold white]Entry Ingress:[/bold white]  S1 Prompt Injection ([cyan]{chains[0]['injection_finding']}[/cyan])\n"
                    f"[bold white]Pivot Tool:[/bold white]     [magenta]{chains[0]['tool']}[/magenta] (Param: '{chains[0]['parameter']}')\n"
                    f"[bold white]Execution Sink:[/bold white] [red]{chains[0]['ast_sink']}[/red]\n"
                    f"[bold white]Graph Action:[/bold white]   Run [bold cyan]shadowprint graph triage {server_name}[/bold cyan] for autonomous AI triage decision.",
                    title="[bold red]🕸️ FalkorDB Connected Exploit Alert (Track 01)[/bold red]",
                    border_style="red",
                )
            )
    except Exception as e:
        logger.debug(f"FalkorDB graph sync skipped: {e}")

    # Export Reports
    os.makedirs(output_dir, exist_ok=True)
    md_path = os.path.join(output_dir, f"shadowprint_report_{server_name}.md")
    sarif_path = os.path.join(output_dir, f"shadowprint_report_{server_name}.sarif")

    generate_markdown_report(report, output_file=md_path)
    export_to_sarif(report, output_file=sarif_path)

    console.print(f"[dim]Audit reports exported:[/dim]")
    console.print(f"  * Markdown: [cyan]{md_path}[/cyan]")
    console.print(f"  * SARIF:    [cyan]{sarif_path}[/cyan]\n")

    if status == "FAILED":
        raise typer.Exit(code=2)
    elif status == "FLAGGED":
        raise typer.Exit(code=1)
    else:
        raise typer.Exit(code=0)


@app.command(name="approve")
def approve(
    target: str = typer.Argument(..., help="Path to MCP server directory or script to approve"),
    approver: str = typer.Option("security_lead", "--approver", "-a", help="Approver identity or username"),
):
    """
    Approve an audited MCP server and save its cryptographic baseline SHA-256 pin to SQLite.
    """
    render_banner()
    target_path = resolve_target_path(target)
    if not target_path.exists():
        console.print(f"[bold red]Error:[/bold red] Target path '{target}' does not exist.")
        raise typer.Exit(code=1)

    server_name = target_path.name if target_path.is_dir() else target_path.parent.name
    target_dir = target_path if target_path.is_dir() else target_path.parent
    entrypoint = find_entrypoint(target_path)

    # Enforcement check: Verify server is not blocked by Security Triage Agent
    from shadowprint.graph.agent import is_server_blocked
    block_info = is_server_blocked(server_name)
    if block_info:
        console.print(
            Panel(
                f"[bold red]Approval Denied: Server '{server_name}' is currently BLOCKED by Security Triage Agent![/bold red]\n\n"
                f"[bold white]Reason:[/bold white]           {block_info.get('reason')}\n"
                f"[bold white]Blast Radius:[/bold white]     {block_info.get('blast_radius')} / 10.0\n"
                f"[bold white]Remediation Patch:[/bold white] [cyan]{block_info.get('patch_file')}[/cyan]\n\n"
                "[yellow]Action Required:[/yellow] Resolve findings and re-triage to unblock before creating baseline approval.",
                title="[bold red]Enforcement Policy Blocked Approval[/bold red]",
                border_style="red",
            )
        )
        raise typer.Exit(code=1)

    if not entrypoint:
        console.print(f"[bold red]Error:[/bold red] No valid Python entrypoint found in '{target}'.")
        raise typer.Exit(code=1)

    async def _do_approve():
        client = GuardedMCPClient(command=sys.executable, args=[str(entrypoint)], timeout=8.0)
        snapshot = await client.fetch_snapshot(server_name)
        def_hash = ThreeLayerHasher.compute_definition_hash(snapshot.tools)
        art_hash = ThreeLayerHasher.compute_artifact_hash(target_dir)

        pin = Pin(
            server_name=server_name,
            pinned_at=time.time(),
            definition_hash=def_hash,
            artifact_hash=art_hash,
            approved_by=approver,
            tools_count=len(snapshot.tools),
        )

        db = PinDatabase()
        db.save_pin(pin, snapshot)
        return pin

    with console.status(f"[bold cyan]Connecting to '{server_name}' and computing cryptographic pin...[/bold cyan]"):
        try:
            pin = asyncio.run(_do_approve())
        except Exception as e:
            console.print(f"[bold red]Failed to pin server:[/bold red] {e}")
            raise typer.Exit(code=1)

    console.print(
        Panel(
            f"[bold green][PASS] Server '{server_name}' Approved & Baseline Pinned![/bold green]\n\n"
            f"[bold white]Approver:[/bold white]               {pin.approved_by}\n"
            f"[bold white]Layer 1 Definition SHA-256:[/bold white] [yellow]{pin.definition_hash}[/yellow]\n"
            f"[bold white]Layer 2 Artifact SHA-256:[/bold white]   [yellow]{pin.artifact_hash}[/yellow]\n"
            f"[bold white]Tools Registered:[/bold white]          [cyan]{pin.tools_count}[/cyan]\n"
            f"[bold white]Database:[/bold white]                  shadowprint.db (SQLite)",
            title="[bold green]Baseline Approval Created[/bold green]",
            border_style="green",
        )
    )


@app.command(name="pins")
def list_pins():
    """List all approved and cryptographically pinned MCP servers in SQLite."""
    render_banner()
    db = PinDatabase()
    pins = db.list_pins()

    if not pins:
        console.print("[dim]No pinned servers found in shadowprint.db. Run 'shadowprint approve <target>' to pin a server.[/dim]\n")
        return

    table = Table(title="Approved Baseline Pins (shadowprint.db)", header_style="bold magenta")
    table.add_column("Server Name", style="bold white", width=22)
    table.add_column("Tools", justify="center", width=8)
    table.add_column("Approved By", width=16)
    table.add_column("Definition SHA-256 (Layer 1)", style="yellow", width=24)
    table.add_column("Artifact SHA-256 (Layer 2)", style="dim yellow", width=24)

    for p in pins:
        table.add_row(
            p.server_name,
            str(p.tools_count),
            p.approved_by,
            f"{p.definition_hash[:20]}...",
            f"{p.artifact_hash[:20]}...",
        )

    console.print(table)
    console.print(f"\n[bold green]Total Approved Servers:[/bold green] {len(pins)}\n")


@app.command(name="watch")
def watch(
    target: str = typer.Argument(..., help="Path to MCP server directory or script to monitor"),
    interval: float = typer.Option(0.5, "--interval", "-i", help="Sub-second polling interval in seconds (default: 0.5s)"),
    max_cycles: Optional[int] = typer.Option(None, "--max-cycles", "-n", help="Max check cycles (default: continuous)"),
):
    """
    Monitor an approved MCP server in real-time for live schema mutations and rug-pulls.
    """
    render_banner()
    target_path = resolve_target_path(target)
    if not target_path.exists():
        console.print(f"[bold red]Error:[/bold red] Target path '{target}' does not exist.")
        raise typer.Exit(code=1)
    server_name = target_path.name if target_path.is_dir() else target_path.parent.name
    target_dir = target_path if target_path.is_dir() else target_path.parent
    entrypoint = find_entrypoint(target_path)

    if not entrypoint:
        console.print(f"[bold red]Error:[/bold red] No valid Python entrypoint found in '{target}'.")
        raise typer.Exit(code=1)

    db = PinDatabase()
    pin = db.get_pin(server_name)
    if not pin:
        console.print(
            f"[bold yellow]Warning:[/bold yellow] Server '{server_name}' is not yet pinned in shadowprint.db.\n"
            f"Run [bold cyan]shadowprint approve {target}[/bold cyan] first to set the approved baseline."
        )
        raise typer.Exit(code=1)

    console.print(
        f"[dim]Starting real-time live watcher for [bold]{server_name}[/bold] (interval={interval}s)...[/dim]\n"
        f"[dim]Press Ctrl+C to stop.[/dim]\n"
    )

    client = GuardedMCPClient(command=sys.executable, args=[str(entrypoint)], timeout=8.0)

    def on_drift_detected(findings: List[Finding]):
        for f in findings:
            console.print(
                Panel(
                    f"[bold red]CRITICAL: Schema Mutation Detected on '{f.target}'![/bold red]\n"
                    f"[bold white]Category:[/bold white] {f.category}\n"
                    f"[bold white]Evidence:[/bold white]\n{f.evidence}",
                    title="[bold red]LIVE RUG-PULL ALARM[/bold red]",
                    border_style="red",
                )
            )

    watcher = LiveWatcher(
        server_name=server_name,
        client=client,
        db=db,
        target_dir=target_dir,
        poll_interval=interval,
        on_drift=on_drift_detected,
    )

    try:
        drift_findings = asyncio.run(watcher.watch_loop(max_iterations=max_cycles))
        if not drift_findings:
            console.print(f"[bold green][PASS] Server remained 100% compliant during monitoring session.[/bold green]")
    except KeyboardInterrupt:
        console.print("\n[dim]Watcher stopped by user.[/dim]")


@app.command(name="scorecard")
def scorecard():
    """
    Execute the automated 7-fixture benchmark recall scorecard.
    """
    from scripts.test_manifest import main_async
    exit_code = asyncio.run(main_async())
    if exit_code != 0:
        raise typer.Exit(code=exit_code)


@app.command(name="info")
def info():
    """Display system details, team attribution, and architectural guarantees."""
    render_banner()
    console.print(
        Panel(
            "[bold white]Problem Statement:[/bold white] PS02 — Model Context Protocol Security Auditor\n"
            "[bold white]Target Track:[/bold white]      Track 01: Agents That Act on Connected Data (FalkorDB)\n"
            "[bold white]Secondary Track:[/bold white]   Track 02: Agent Memory & Coordination (Drift Lineage)\n"
            "[bold white]Co-Builders (50/50):[/bold white] Jasjyot Singh & Gaurang Udgirkar\n"
            "[bold white]Architecture:[/bold white]       Engines S0–S4: 100% Offline & Standalone\n"
            "                   Engine S5: FalkorDB GraphBLAS Connected Intelligence Engine\n"
            "                   Autonomous AI Triage Agent with Multi-Hop Cypher Reasoning",
            title="[bold]Project Information[/bold]",
            border_style="cyan",
        )
    )


def main():
    app()


if __name__ == "__main__":
    main()
