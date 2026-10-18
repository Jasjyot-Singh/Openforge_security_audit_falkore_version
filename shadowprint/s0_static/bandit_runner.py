"""
Engine S0: Bandit AST Security Linter Runner.
Wraps Bandit to detect Python AST security flaws (CWE-78, CWE-502, CWE-798, CWE-918).
Runs with --ignore-nosec to prevent hostile suppression bypasses.
"""

import json
import os
import subprocess
import sys
from typing import List, Optional
from shadowprint.models import Finding, Location

CWE_CATEGORY_MAP = {
    78: "COMMAND_INJECTION",
    502: "INSECURE_DESERIALIZATION",
    798: "HARDCODED_SECRET",
    259: "HARDCODED_SECRET",
    918: "SSRF_UNSAFE_FETCH",
    22: "PATH_TRAVERSAL",
    377: "INSECURE_TEMP_USAGE",
}

TEST_ID_CATEGORY_MAP = {
    "B602": "COMMAND_INJECTION",
    "B603": "COMMAND_INJECTION",
    "B604": "COMMAND_INJECTION",
    "B605": "COMMAND_INJECTION",
    "B607": "COMMAND_INJECTION",
    "B301": "INSECURE_DESERIALIZATION",
    "B302": "INSECURE_DESERIALIZATION",
    "B403": "INSECURE_DESERIALIZATION",
    "B105": "HARDCODED_SECRET",
    "B106": "HARDCODED_SECRET",
    "B107": "HARDCODED_SECRET",
    "B310": "SSRF_UNSAFE_FETCH",
    "B108": "INSECURE_TEMP_USAGE",
}


def run_bandit(target_path: str, server_name: str = "target_server") -> List[Finding]:
    """
    Executes Bandit against target_path and transforms raw findings into
    standardized Finding instances.
    """
    if not os.path.isabs(target_path):
        project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
        candidate = os.path.join(project_root, target_path)
        target = os.path.abspath(candidate if os.path.exists(candidate) else target_path)
    else:
        target = os.path.abspath(target_path)

    if not os.path.exists(target):
        return []

    cmd = [
        sys.executable,
        "-m",
        "bandit",
        "-f",
        "json",
        "--ignore-nosec",
    ]
    if os.path.isdir(target):
        cmd.extend(["-r", target])
    else:
        cmd.append(target)

    findings: List[Finding] = []
    raw_output = ""

    try:
        proc = subprocess.run(
            cmd,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=60
        )
        raw_output = proc.stdout
    except Exception as e:
        return []

    # Bandit output might contain log lines before JSON output
    json_start = raw_output.find("{")
    if json_start == -1:
        return []

    try:
        report = json.loads(raw_output[json_start:])
    except json.JSONDecodeError:
        return []

    results = report.get("results", [])
    finding_idx = 1

    for res in results:
        test_id = res.get("test_id", "")
        # Filter out informational import warnings if not critical
        if test_id in ("B404",):  # Just importing subprocess isn't a vulnerability by itself
            continue

        cwe_info = res.get("issue_cwe", {})
        cwe_id = cwe_info.get("id") if isinstance(cwe_info, dict) else None

        category = TEST_ID_CATEGORY_MAP.get(test_id)
        if not category and cwe_id:
            category = CWE_CATEGORY_MAP.get(cwe_id, f"CWE_{cwe_id}")
        if not category:
            category = res.get("test_name", "STATIC_CODE_FLAW").upper()

        sev_raw = res.get("issue_severity", "MEDIUM").lower()
        if sev_raw not in ("critical", "high", "medium", "low", "info"):
            sev_raw = "medium"

        # Escalate high confidence shell=True or pickle to critical/high
        if test_id in ("B602", "B301") and sev_raw != "low":
            sev_raw = "high"

        filename = res.get("filename", target)
        line_num = res.get("line_number")
        col_num = res.get("col_offset")

        code_snippet = res.get("code", "").strip()
        issue_text = res.get("issue_text", "Security violation detected by Bandit AST analysis.")
        more_info = res.get("more_info", "")

        finding = Finding(
            id=f"SP-S0-BND-{finding_idx:03d}",
            engine="S0",
            target=server_name,
            tool="__server__",
            category=category,
            severity=sev_raw,
            assessment="FAIL" if sev_raw in ("critical", "high") else "FLAGGED",
            confidence="confirmed",
            evidence_basis="static",
            location=Location(
                file=os.path.normpath(filename).replace("\\", "/"),
                line=line_num,
                column=col_num
            ),
            evidence=f"[{test_id}] {issue_text}\nCode:\n{code_snippet}",
            remediation=f"Remediate {category} ({test_id}). Refer to: {more_info}",
            supporting_rules=[test_id] + ([f"CWE-{cwe_id}"] if cwe_id else [])
        )
        findings.append(finding)
        finding_idx += 1

    return findings
