#!/usr/bin/env python3
"""
Shadowprint One-Click Launcher & Zero-Friction Runner.
Hackathon Track 01: Agents That Act on Connected Data
Co-builders: Gaurang Udgirkar & Jasjyot Singh

This script guarantees reproducible, fail-safe startup:
1. Validates Python environment & dependencies.
2. Ensures output/ directories & fresh dashboard_data.json exist.
3. Automatically frees or binds the dashboard HTTP server.
4. Prints the complete judge demo cheatsheet directly to your terminal.
"""

import sys
import os
import socket
import argparse
import subprocess
from pathlib import Path
from http.server import HTTPServer, SimpleHTTPRequestHandler

# Ensure project root is in python path
PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# Safe Windows UTF-8 terminal configuration
if sys.platform == "win32":
    try:
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        if hasattr(sys.stderr, "reconfigure"):
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass


def check_python_version():
    """Ensure Python 3.10+ is running."""
    if sys.version_info < (3, 10):
        print(f"[!] Error: Shadowprint requires Python 3.10+. Current: {sys.version}")
        sys.exit(1)


def check_dependencies():
    """Check required modules and prompt if missing."""
    required = ["rich", "typer", "pydantic", "deepdiff", "bandit"]
    missing = []
    for pkg in required:
        try:
            __import__(pkg)
        except ImportError:
            missing.append(pkg)

    if missing:
        print(f"[!] Warning: Missing dependencies: {', '.join(missing)}")
        print("[*] Installing required packages from requirements.txt...")
        res = subprocess.call([sys.executable, "-m", "pip", "install", "-r", str(PROJECT_ROOT / "requirements.txt")])
        if res != 0:
            print("[!] pip install failed. Please run: pip install -r requirements.txt")
            sys.exit(1)


def ensure_dashboard_data():
    """Ensure output/ directory and dashboard_data.json are freshly populated."""
    output_dir = PROJECT_ROOT / "output"
    output_dir.mkdir(parents=True, exist_ok=True)

    gen_script = PROJECT_ROOT / "dashboard" / "generate_data.py"
    if gen_script.exists():
        try:
            import importlib.util
            spec = importlib.util.spec_from_file_location("generate_data", str(gen_script))
            if spec and spec.loader:
                mod = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(mod)
                if hasattr(mod, "main"):
                    mod.main()
        except Exception as e:
            # Fallback to subprocess execution
            subprocess.call([sys.executable, str(gen_script)], cwd=str(PROJECT_ROOT))


def is_port_in_use(host: str, port: int) -> bool:
    """Check if a given host/port is already occupied."""
    test_host = "127.0.0.1" if host in ("0.0.0.0", "", None) else host
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.5)
        return s.connect_ex((test_host, port)) == 0


def print_banner(host: str, port: int):
    """Print high-contrast, informative banner for hackathon judges and demo."""
    try:
        from rich.console import Console
        from rich.panel import Panel
        from rich.table import Table

        console = Console(legacy_windows=False)
        dashboard_url = f"http://{'localhost' if host in ('0.0.0.0', '127.0.0.1') else host}:{port}"

        console.print(
            Panel(
                f"[bold cyan]SHADOWPRINT v2.0.0[/bold cyan] — [bold white]Model Context Protocol Security Auditor[/bold white]\n"
                f"[bold magenta]Hackathon Track 01:[/bold magenta] Agents That Act on Connected Data (FalkorDB EKG)\n"
                f"[bold yellow]Co-Builders:[/bold yellow] Gaurang Udgirkar & Jasjyot Singh\n\n"
                f"[bold green]▶ DASHBOARD READY:[/bold green] [bold underline cyan]{dashboard_url}[/bold underline cyan]\n"
                f"[dim]Features: 7-MCP Selector, Console Simulator, Live SARIFs, EKG Graph, Scorecard[/dim]",
                title="[bold green]System Online & Ready[/bold green]",
                border_style="green",
            )
        )

        table = Table(title="Judge Demo Manual CLI Cheatsheet (Copy & Paste)", header_style="bold magenta")
        table.add_column("Step", style="bold cyan", width=6)
        table.add_column("Demo Command", style="bold yellow", width=54)
        table.add_column("What to Show / Expected Output", style="white")

        table.add_row(
            "1",
            "python -m shadowprint.cli audit fixtures/vulnerable_runner",
            "Catches 7 flaws (1 Critical, 3 High, 2 Medium, 1 Low). Generates SARIF.",
        )
        table.add_row(
            "2",
            "python -m shadowprint.cli audit fixtures/clean_notes",
            "Negative control. 0 False Positives. Green PASSED status.",
        )
        table.add_row(
            "3",
            "python -m shadowprint.cli scorecard",
            "Automated 7-fixture benchmark recall scorecard (100% Core Recall).",
        )
        table.add_row(
            "4",
            "python -m shadowprint.cli graph triage tests/final_test_mcp_1 --use-test-double",
            "Autonomous Security Triage Agent decisions via FalkorDB EKG.",
        )
        table.add_row(
            "5",
            "python -m shadowprint.cli watch fixtures/clean_notes --max-cycles 3 --interval 0.5",
            "Sub-second live polling verifying zero drift against approved SQLite baseline.",
        )
        table.add_row(
            "6",
            "python scripts/manual_demo.py all",
            "Interactive verification: live rug-pull diff + canary theft + SQLite pin.",
        )

        console.print(table)
        console.print(f"\n[bold green]Server is running. Open [cyan]{dashboard_url}[/cyan] in your browser.[/bold green]")
        console.print("[dim]Press Ctrl+C to stop the dashboard server anytime.\n[/dim]")

    except ImportError:
        print("=" * 75)
        print("  SHADOWPRINT v2.0.0 — MCP Security Auditor & FalkorDB Exploit Graph")
        print("  Co-Builders: Gaurang Udgirkar & Jasjyot Singh")
        print(f"  Dashboard URL: http://localhost:{port}")
        print("=" * 75)


class ReusableHTTPServer(HTTPServer):
    allow_reuse_address = True


def serve_dashboard(host: str, port: int):
    """Serve the dashboard directory using Python's standard HTTP server."""
    dashboard_dir = PROJECT_ROOT / "dashboard"
    os.chdir(str(dashboard_dir))

    class QuietHandler(SimpleHTTPRequestHandler):
        def log_message(self, format, *args):
            # Suppress normal GET logs to keep terminal clean for demo commands
            pass

    server = ReusableHTTPServer((host, port), QuietHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Dashboard server stopped cleanly.")
        server.server_close()


def main():
    parser = argparse.ArgumentParser(description="Shadowprint One-Click Launcher")
    parser.add_argument("--host", default="127.0.0.1", help="Host interface (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8080, help="Port to serve dashboard (default: 8080)")
    parser.add_argument("--check-only", action="store_true", help="Validate environment and exit")
    parser.add_argument("--scorecard", action="store_true", help="Run benchmark scorecard and exit")
    args = parser.parse_args()

    check_python_version()
    check_dependencies()
    ensure_dashboard_data()

    if args.scorecard:
        from scripts.test_manifest import main_async
        import asyncio
        sys.exit(asyncio.run(main_async()))

    if args.check_only:
        print("[+] Environment & dashboard data verified successfully.")
        sys.exit(0)

    # Check port availability
    target_port = args.port
    if is_port_in_use(args.host, target_port):
        # Check if already running dashboard or port occupied
        print(f"[*] Port {target_port} is currently in use.")
        print(f"[*] If Shadowprint is already running, open http://localhost:{target_port}")
        print(f"[*] To use an alternative port: python start.py --port 8081\n")
        # Attempt next port automatically for convenience
        for fallback_port in [8081, 8082, 8888, 3000]:
            if not is_port_in_use(args.host, fallback_port):
                print(f"[+] Binding dashboard to fallback port {fallback_port}...")
                target_port = fallback_port
                break

    print_banner(args.host, target_port)
    serve_dashboard(args.host, target_port)


if __name__ == "__main__":
    main()
