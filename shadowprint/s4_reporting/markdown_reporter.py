"""
Engine S4: Markdown Audit Report Generator.
Exports comprehensive, human-readable audit reports to Markdown.
Conforms to project structure requirements for CI/CD and offline archival.
"""

import datetime
import os
from typing import Optional
from shadowprint.models import AuditReport, Finding


def generate_markdown_report(report: AuditReport, output_file: Optional[str] = None) -> str:
    """
    Renders an AuditReport object into a structured Markdown document.
    Optionally saves the report to output_file.
    """
    date_str = datetime.datetime.fromtimestamp(report.timestamp).strftime("%Y-%m-%d %H:%M:%S UTC")

    crit_count = sum(1 for f in report.findings if f.severity == "critical")
    high_count = sum(1 for f in report.findings if f.severity == "high")
    med_count = sum(1 for f in report.findings if f.severity == "medium")
    low_count = sum(1 for f in report.findings if f.severity == "low")

    status_icon = "🔴 FAILED" if report.status == "FAILED" else ("🟡 FLAGGED" if report.status == "FLAGGED" else "🟢 PASSED")

    lines = [
        f"# Shadowprint Security Audit Report — `{report.target}`",
        "",
        "> **Notice:** This audit was performed 100% offline and airgapped by Shadowprint MCP Security Auditor.",
        "",
        "## 1. Executive Summary",
        "",
        f"- **Target Server:** `{report.target}`",
        f"- **Audit Timestamp:** `{date_str}`",
        f"- **Final Verdict:** **{status_icon}**",
        f"- **Total Findings:** **{len(report.findings)}**",
        "",
        "### Findings Severity Breakdown",
        "",
        "| Severity | Count | Assessment |",
        "|---|---|---|",
        f"| **CRITICAL** | `{crit_count}` | Immediate Safety Gate Block |",
        f"| **HIGH** | `{high_count}` | High Risk Vulnerability / Flaw |",
        f"| **MEDIUM** | `{med_count}` | Security Violation / Anomaly |",
        f"| **LOW / INFO** | `{low_count}` | Informational / Best Practice |",
        "",
        "---",
        "",
        "## 2. Detailed Findings Evidence Log",
        ""
    ]

    if not report.findings:
        lines.extend([
            "### ✅ Zero Findings Detected",
            "",
            "The target MCP server completed all static AST, configuration, and metadata security checks with **0 findings** (100% clean PASS).",
            ""
        ])
    else:
        for idx, f in enumerate(report.findings, start=1):
            loc_str = "Global Server Scope"
            if f.location:
                fname = f.location.file.replace("\\", "/")
                line_part = f" (Line {f.location.line})" if f.location.line else ""
                loc_str = f"`{fname}`{line_part}"

            rules_str = ", ".join(f.supporting_rules) if f.supporting_rules else "N/A"

            lines.extend([
                f"### {idx}. [{f.severity.upper()}] {f.category} (`{f.id}`)",
                "",
                f"- **Engine:** `{f.engine}` ({f.evidence_basis})",
                f"- **Tool Under Audit:** `{f.tool}`",
                f"- **Confidence:** `{f.confidence}`",
                f"- **Location:** {loc_str}",
                f"- **Associated Rules:** `{rules_str}`",
                ""
            ])

            if f.claim:
                lines.extend([
                    f"> **Tool Claim:** *\"{f.claim}\"*",
                    ""
                ])

            lines.extend([
                "#### Observed Evidence:",
                "```text",
                f.evidence.strip(),
                "```",
                "",
                f"**Remediation Guidance:** {f.remediation}",
                "",
                "---",
                ""
            ])

    lines.extend([
        "## 3. 🕸️ FalkorDB Exploit Knowledge Graph (EKG) Analysis",
        "",
        "> **Track 01 Multi-Hop Reasoning:** FalkorDB connects isolated scanner findings into multi-hop attack chains to reveal compound threats.",
        "",
    ])

    try:
        from shadowprint.graph.client import FalkorDBClient
        from shadowprint.graph.queries import ExploitChainQueryEngine

        g_client = FalkorDBClient.get_instance()
        engine = ExploitChainQueryEngine(g_client)
        chains = engine.find_exploit_chains(report.target)

        if chains:
            lines.extend([
                f"### 🚨 Discovered Multi-Hop Exploit Chains ({len(chains)} Found)",
                "",
                "| Chain ID | Vector Title | Hop Count | Pivot Tool | Execution Sink | Network Egress |",
                "|---|---|---|---|---|---|",
            ])
            for ch in chains:
                net_str = f"`{ch.get('network_exfil')}`" if ch.get("network_exfil") else "N/A"
                lines.append(
                    f"| `{ch['chain_id']}` | **{ch['title']}** | `{ch['hop_count']} Hops` | `{ch['tool']}` | `{ch['ast_sink']}` | {net_str} |"
                )
            lines.extend(["", "#### Detailed Attack Walkthroughs:", ""])
            for ch in chains:
                lines.extend([
                    f"##### {ch['chain_id']}: {ch['title']}",
                    "```text",
                    ch["narrative"].strip(),
                    "```",
                    f"**Prescribed Remediation:** {ch['remediation']}",
                    "",
                ])
        else:
            lines.extend([
                "### ✅ Zero Multi-Hop Exploit Paths",
                "",
                "Graph traversal over FalkorDB confirmed that declared tools and parameters do not connect to unauthorized AST sinks or exfiltration endpoints.",
                "",
            ])
    except Exception:
        lines.extend([
            "_FalkorDB EKG multi-hop analysis offline during this run._",
            "",
        ])

    lines.extend([
        "---",
        "",
        "## 4. Five-Dimension Evidence Chain Methodology",
        "",
        "Shadowprint verifies target servers across five independent evidence planes:",
        "1. **Claim (Metadata):** Evaluates declarations, tool descriptions, and parameters against Unicode TAG steganography and prompt injection.",
        "2. **Code (Static AST):** Pre-execution AST security checks (Bandit, Semgrep taint, Gitleaks secrets, AST claim mismatch).",
        "3. **Runtime (Kernel Syscalls):** Containerized execution capturing `openat`, `connect`, and `execve` kernel events.",
        "4. **Drift (Integrity Diff):** Cryptographic 3-layer SHA-256 fingerprinting and live mutation monitoring.",
        "5. **Graph Intelligence (FalkorDB EKG):** Multi-hop exploit chain analysis and autonomous triage reasoning.",
        "",
        "_Report auto-generated by Shadowprint v2.0.0 (FalkorDB Edition)._"
    ])

    content = "\n".join(lines)

    if output_file:
        os.makedirs(os.path.dirname(os.path.abspath(output_file)), exist_ok=True)
        with open(output_file, "w", encoding="utf-8") as out:
            out.write(content)

    return content
