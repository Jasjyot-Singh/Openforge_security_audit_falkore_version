"""
Engine S4: OASIS SARIF 2.1.0 Standard Exporter.
Serializes Shadowprint audit findings into the official OASIS SARIF 2.1.0 JSON format,
enabling integration with GitHub Advanced Security and enterprise CI/CD pipelines.
"""

import json
import os
from typing import Dict, Any, List, Optional
from shadowprint.models import AuditReport, Finding

SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
TOOL_NAME = "Shadowprint"
TOOL_VERSION = "1.0.0"

SEVERITY_LEVEL_MAP = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "none"
}


def export_to_sarif(report: AuditReport, output_file: Optional[str] = None) -> Dict[str, Any]:
    """
    Converts an AuditReport into standard SARIF 2.1.0 JSON object.
    Optionally persists the SARIF file to disk.
    """
    rules_dict: Dict[str, Dict[str, Any]] = {}
    sarif_results: List[Dict[str, Any]] = []

    for f in report.findings:
        rule_id = f.supporting_rules[0] if f.supporting_rules else f.category
        if rule_id not in rules_dict:
            rules_dict[rule_id] = {
                "id": rule_id,
                "name": f.category,
                "shortDescription": {"text": f"Rule {rule_id}: {f.category}"},
                "fullDescription": {"text": f.remediation},
                "defaultConfiguration": {
                    "level": SEVERITY_LEVEL_MAP.get(f.severity, "warning")
                },
                "properties": {
                    "precision": "high" if f.confidence == "confirmed" else "medium",
                    "security-severity": "9.5" if f.severity == "critical" else ("8.0" if f.severity == "high" else ("5.0" if f.severity == "medium" else "2.0"))
                }
            }

        # Build physical location if available
        locations: List[Dict[str, Any]] = []
        if f.location and f.location.file:
            uri = f.location.file.replace("\\", "/")
            if not uri.startswith("file://") and not uri.startswith("/"):
                uri = f"file:///{uri}"

            region: Dict[str, Any] = {}
            if f.location.line:
                region["startLine"] = f.location.line
            if f.location.column:
                region["startColumn"] = f.location.column

            locations.append({
                "physicalLocation": {
                    "artifactLocation": {"uri": uri},
                    "region": region
                }
            })

        sarif_results.append({
            "ruleId": rule_id,
            "level": SEVERITY_LEVEL_MAP.get(f.severity, "warning"),
            "message": {"text": f"[{f.engine}] {f.evidence}"},
            "locations": locations,
            "properties": {
                "severity": f.severity,
                "engine": f.engine,
                "assessment": f.assessment,
                "confidence": f.confidence,
                "evidence_basis": f.evidence_basis,
                "tool": f.tool
            }
        })

    sarif_log = {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": TOOL_NAME,
                        "semanticVersion": TOOL_VERSION,
                        "informationUri": "https://github.com/shadowprint/shadowprint",
                        "rules": list(rules_dict.values())
                    }
                },
                "results": sarif_results
            }
        ]
    }

    if output_file:
        os.makedirs(os.path.dirname(os.path.abspath(output_file)), exist_ok=True)
        with open(output_file, "w", encoding="utf-8") as sf:
            json.dump(sarif_log, sf, indent=2)

    return sarif_log
