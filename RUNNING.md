# Running Shadowprint (v2.0.0)

> **Hackathon Track 01: Agents That Act on Connected Data**  
> **Project:** Shadowprint — Model Context Protocol Security Auditor & Exploit Knowledge Graph  
> **Co-Builders:** Gaurang Udgirkar & Jasjyot Singh *(OpenForge Hackathon Winners)*  
> **Dashboard:** [http://localhost:8080](http://localhost:8080)  
> **FalkorDB EKG:** `localhost:6379` (GraphBLAS Graph Engine)

---

## Table of Contents
1. [Zero-Friction Quickstart](#1-zero-friction-quickstart)
   - [Option A: One-Click Local Launcher (Recommended)](#option-a-one-click-local-launcher-recommended)
   - [Option B: Full Docker Compose (Containerized)](#option-b-full-docker-compose-containerized)
   - [Option C: Standard Virtualenv Setup](#option-c-standard-virtualenv-setup)
2. [Judge Demo Command Cheatsheet](#2-judge-demo-command-cheatsheet)
3. [Interactive Dashboard & 7-MCP Explorer](#3-interactive-dashboard--7-mcp-explorer)
4. [FalkorDB Exploit Knowledge Graph Modes](#4-falkordb-exploit-knowledge-graph-modes)
5. [Automated Test Suite (100% Pass Rate)](#5-automated-test-suite-100-pass-rate)
6. [Reliability & Troubleshooting Guide](#6-reliability--troubleshooting-guide)

---

## 1. Zero-Friction Quickstart

Choose whichever method matches your environment. Both local and containerized options work out-of-the-box.

### Option A: One-Click Local Launcher (Recommended)
We built a resilient launcher that validates dependencies, ensures output data is freshly generated, handles port conflicts, and launches the dashboard.

**Windows (PowerShell / Command Prompt):**
```powershell
python start.py
```
*(Or simply double-click `start.bat`)*

**macOS / Linux:**
```bash
python3 start.py
# or
bash start.sh
```

**What this does automatically:**
- Validates Python 3.10+ and frozen dependencies.
- Synchronizes all audit reports and compiles `dashboard/dashboard_data.json`.
- Serves the dashboard at `http://localhost:8080`.
- Prints the exact copy-paste manual demo commands directly to your terminal.

---

### Option B: Full Docker Compose (Containerized)
To run Shadowprint and live FalkorDB without installing any local Python packages:

```bash
docker compose up --build
```

**Services launched:**
- `falkordb`: Live FalkorDB GraphBLAS instance listening on `localhost:6379`.
- `shadowprint-app`: Shadowprint web application & API serving the dashboard on `http://localhost:8080`.

Once started, open your browser at **[http://localhost:8080](http://localhost:8080)**.

To shut down:
```bash
docker compose down
```

---

### Option C: Standard Virtualenv Setup

If you prefer setting up a dedicated virtual environment manually:

```bash
# 1. Create and activate a virtual environment
python -m venv .venv

# Windows (PowerShell):
.venv\Scripts\Activate.ps1
# Windows (CMD):
.venv\Scripts\activate.bat
# macOS / Linux:
source .venv/bin/activate

# 2. Install frozen requirements
pip install -r requirements.txt

# 3. Install Shadowprint in editable mode
pip install -e .

# 4. Generate fresh dashboard data
python dashboard/generate_data.py

# 5. Start the dashboard server
python -m http.server 8080 -d dashboard
```

---

## 2. Judge Demo Command Cheatsheet

During a live demo or video recording, run these commands in sequence to demonstrate Shadowprint's core capabilities:

### Command 1: End-to-End Vulnerability Audit
Audits a vulnerable MCP server across Static AST (Bandit), Semantic Rules, Claim-Code Mismatch, and Sandbox Egress.
```bash
python -m shadowprint.cli audit fixtures/vulnerable_runner
```
- **What to show:** Catches 7 flaws (1 Critical, 3 High, 2 Medium, 1 Low). Discovers Hardcoded API Secret, Command Injection via `os.system`, Pickled Deserialization, SSRF Unsafe Fetch, Insecure `/tmp` usage, and Tool Claim Mismatch.
- **Artifacts:** Exports `output/shadowprint_report_vulnerable_runner.md` and standard SARIF `output/shadowprint_report_vulnerable_runner.sarif`.

---

### Command 2: Clean Negative Control (0 False Positives)
Demonstrates precision and zero false-alarm tolerance on safe code.
```bash
python -m shadowprint.cli audit fixtures/clean_notes
```
- **What to show:** Green `[PASS]` badge. 0 Findings detected across all engines. Validates 0 false positives.

---

### Command 3: Automated 7-Fixture Recall Scorecard
Executes the official benchmark test harness across all 7 manifest fixtures.
```bash
python -m shadowprint.cli scorecard
```
- **What to show:** 
  - `clean_notes` (0 FP, PASS)
  - `clean_fetch` (0 FP, PASS)
  - `poisoned_weather` (Zero-width chars & unicode tag steganography caught, PASS)
  - `vulnerable_runner` (Command injection, hardcoded secret, SSRF caught, PASS)
  - `exfil_calculator` (Covert markdown image exfiltration caught, PASS)
  - `rugpull_suite` (Live schema definition mutation caught, PASS)
  - `attack_the_auditor` (Symlink escape & audit poisoning caught, PASS)
  - **Result: 7/7 passing (100% Core Recall Guaranteed).**

---

### Command 4: Exploit Knowledge Graph Triage Agent (Track 01)
Runs the FalkorDB Autonomous Security Triage Agent to reason over connected MCP attack chains.
```bash
python -m shadowprint.cli graph triage tests/final_test_mcp_1 --use-test-double
```
*(If running live FalkorDB via Docker, omit `--use-test-double`)*:
```bash
python -m shadowprint.cli graph triage fixtures/compound_exploit_server
```
- **What to show:** The AI Triage Agent constructs the graph topology in FalkorDB, evaluates multi-hop attack lineage from prompt injection entry to execution sinks, calculates blast radius score, and issues autonomous triage verdicts (`APPROVE_SERVER` or `BLOCK_SERVER`).

---

### Command 5: Live Rug-Pull Mutation Watcher
Monitors an approved MCP server in real-time with sub-second polling to detect dynamic definition drift.
```bash
python -m shadowprint.cli watch fixtures/clean_notes --max-cycles 3 --interval 0.5
```
- **What to show:** Verifies runtime compliance against the 3-layer SHA-256 cryptographic pin in `shadowprint.db`. Single-cycle or continuous monitoring flags schema mutations within <500ms.

---

### Command 6: Interactive Verification Demo Harness
Zero-setup interactive verification demonstrating live rug-pull diffs, escaped characters, decoy canary extraction, and SQLite pinning.
```bash
python scripts/manual_demo.py all
```
- **What to show:**
  - `[1] Rug-Pull Mutation & Escaped Character Diff`: Touches trigger flag, escapes non-printable unicode tags (`[U+E0001]`), and highlights DeepDiff schema mutations.
  - `[2] Covert Canary Leak`: Extracts markdown image exfiltration payloads `!(http://127.0.0.1:8080/sink?data=...)`.
  - `[3] SQLite 3-Layer Pin Store`: Stores and verifies Definition SHA-256 and Artifact SHA-256 cryptographic pins.

---

## 3. Interactive Dashboard & 7-MCP Explorer

Open **[http://localhost:8080](http://localhost:8080)** in any modern browser.

### Features Available:
1. **Demo MCP Server Explorer & Live Console Simulator:**
   - Choose between all 7 official benchmark MCP fixtures + Track 01 compound exploit server:
     1. `vulnerable_runner` (Planted vulnerabilities showcase)
     2. `clean_notes` (Negative control benchmark)
     3. `poisoned_weather` (Unicode tag & prompt injection)
     4. `exfil_calculator` (Covert canary & markdown exfil)
     5. `rugpull_suite` (Dynamic schema mutation drift)
     6. `attack_the_auditor` (Adversarial auditor defense)
     7. `clean_fetch` (Safe network tool control)
     8. `compound_exploit_server` (FalkorDB multi-hop chain showcase)
   - **Live Terminal Window:** Shows exact terminal console output, traffic dots, command line prompt, and a one-click **"Copy Command"** button.
   - **Feature & Attack Profile:** Displays the builder attribution, target engine, and list of planted attack vectors with a direct jump link to the detailed audit report.
2. **Audit Reports & SARIF Inspector:**
   - Summary cards with Critical/High/Medium/Low counts.
   - Line-by-line file locations (`server.py:35`), CWE references, and remediation code snippets.
3. **Automated Benchmark Scorecard:**
   - 7/7 benchmark recall matrix with expected vs actual findings.
4. **FalkorDB Connected Exploit Graph & AI Triage:**
   - Visual multi-hop graph topology showing Server -> Tool -> Param -> Sink -> Egress paths.
   - Autonomous Security Triage Agent decisions and blast radius scores.

---

## 4. FalkorDB Exploit Knowledge Graph Modes

Shadowprint features dual-mode execution for FalkorDB:

| Mode | Command Flag | Use Case |
|---|---|---|
| **Live FalkorDB Daemon** | *(default)* | Production & live graph operations on `localhost:6379`. Spin up with `docker compose up falkordb`. |
| **Headless Test Double** | `--use-test-double` | 100% offline, zero-dependency CI/CD, offline grading, and unit testing. |

---

## 5. Automated Test Suite (100% Pass Rate)

Shadowprint maintains an end-to-end automated test suite:

```bash
python -m pytest tests/
```

**Expected Result:**
```text
======================== 55 passed, 2 skipped in ~55s ========================
```
- Total test cases: 57
- Status: **100% Pass Rate (0 failures)**
- Tests cover: CLI pipeline, Bandit AST runner, Semgrep static rules, prompt injection guards, canary tripwires, SQLite pinning, FalkorDB Cypher queries, multi-hop exploit chains, and SARIF export.

---

## 6. Reliability & Troubleshooting Guide

### Issue 1: Port 8080 is already in use
- **Cause:** A previous dashboard server or background process wasn't stopped.
- **Solution:** `start.py` automatically detects this and binds to the next available port (e.g. `8081`). You can also specify a port explicitly:
  ```bash
  python start.py --port 8085
  ```

### Issue 2: `pytest` command not recognized on Windows
- **Cause:** Python scripts directory is not in system `PATH`.
- **Solution:** Always run pytest via the Python module launcher:
  ```bash
  python -m pytest tests/
  ```

### Issue 3: Running commands from subdirectories
- **Solution:** Shadowprint automatically resolves relative paths against `PROJECT_ROOT`. Running `python -m shadowprint.cli audit fixtures/vulnerable_runner` works seamlessly regardless of your current working directory.

### Issue 4: Dashboard shows outdated reports
- **Solution:** Regenerate fresh data at any time with:
  ```bash
  python dashboard/generate_data.py
  ```

### Issue 5: Connecting to FalkorDB
- If running locally and you want to use the live FalkorDB instance:
  ```bash
  docker compose up -d falkordb
  ```
- If you don't have Docker running, simply pass `--use-test-double` to any `graph` command:
  ```bash
  python -m shadowprint.cli graph triage fixtures/compound_exploit_server --use-test-double
  ```

---

*Shadowprint — Built for the FalkorDB Hackathon Track 01 by Gaurang Udgirkar & Jasjyot Singh.*
