#!/usr/bin/env bash
# Shadowprint One-Click Launcher for macOS / Linux
# Hackathon Track 01: Agents That Act on Connected Data
# Co-builders: Gaurang Udgirkar & Jasjyot Singh

set -e

echo "==============================================================================="
echo "  SHADOWPRINT v2.0.0 -- Model Context Protocol Security Auditor"
echo "  Hackathon Track 01: Agents That Act on Connected Data"
echo "  Co-Builders: Gaurang Udgirkar & Jasjyot Singh"
echo "==============================================================================="
echo ""

if command -v python3 >/dev/null 2>&1; then
    PYTHON_CMD="python3"
elif command -v python >/dev/null 2>&1; then
    PYTHON_CMD="python"
else
    echo "[ERROR] Python is not installed or not in PATH!"
    exit 1
fi

$PYTHON_CMD start.py "$@"
