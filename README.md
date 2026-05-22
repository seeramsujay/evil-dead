# Project Aegis: Autonomous DFIR Threat Hunting Engine
**Version 1.0.0** · SANS Find Evil! Hackathon · 2026

Project Aegis is a state-of-the-art, autonomous Digital Forensics and Incident Response (DFIR) agent built for the SANS SIFT Workstation. It bridges the speed gap between offensive AI and human incident responders by automating triage, mapping lateral movement propagation, and detecting memory process anomalies—all while securing evidence integrity and avoiding LLM context collapse.

---

## 🚀 30-Second Quick Start

Get the entire threat hunting simulation and local environment running in 30 seconds:

```bash
# 1. Clone & Install Dependencies
git clone https://github.com/suzaykid/evil-dead.git
cd evil-dead
pip install -r requirements.txt

# 2. Start the Forensic Dashboard & Console
python3 -m http.server -d dashboard/ 8000
# ➜ Open http://localhost:8000 in your browser and click "Deploy Agent"!

# 3. (Optional) Run the FastMCP Server Membrane
mcp run aegis/mcp_server.py
```

---

## AI READING INSTRUCTION

Read `[SPEC]` and `[BUG]` blocks for authoritative facts and system commands.
Read `[NOTE]` only if additional context or design history is needed.
`[?]` blocks are unverified claims.

---

## 1. Core Architectural Concepts

**[SPEC]**
- **Evidence Integrity**: SIFT command-line tools (`volatility`, `log2timeline`) are executed strictly via `subprocess.run(shell=False)` with argument arrays to prevent shell escaping or command injections.
- **Context Protection**: Huge raw log text walls are piped through Python's `jc` (JSON Convert) library to convert CLI stdout into structured JSON, which is then cached locally. Only paths and condensed metadata enter the LLM context.
- **State safety**: LangGraph-controlled execution enforces an immutable step counter. If execution cycles hit `MAX_STEPS` (5), a **TTL Circuit Breaker** triggers, halting analysis to prevent loops and outputting a compiled markdown report.

**[NOTE]**
During incidents, responders are overwhelmed by data volume, and LLMs hallucinate when interpreting raw text logs. Aegis delegates the heavy parsing and anomaly search to deterministic Python logic, freeing the LLM to write high-level executive reports based on clean, structured findings.

---

## 2. Key Forensic Engines

**[SPEC]**
- **Deterministic Discrepancy Diffing (`aegis/diffing.py`)**:
  - Compares volatile memory processes (`windows.pslist`) with filesystem Master File Table (`MFT`) disk timestamps.
  - Flags processes running in memory that lack disk MFT creation records or have start times predating disk creation (revealing process hollowing, reflective loading, or memory-only payloads).
- **Forensic Flood-Fill BFS (`aegis/traversal.py`)**:
  - Performs a Breadth-First Search (BFS) over system authentication and network log files starting at "Patient Zero".
  - Automatically maps the lateral movement blast radius, validating chronological propagation paths (e.g. host A compromise must happen before host B).
- **LangGraph Stateful Orchestrator (`aegis/orchestrator.py`)**:
  - Models the triage, collection, analysis, and routing phases of DFIR as a state graph.
  - Implements the conditional circuit-breaker logic based on step count.

---

## 3. Interactive Web Dashboard

**[SPEC]**
Located in the `dashboard/` directory. Zero frameworks or complex bundlers required—built entirely on HTML5, CSS3, and Vanilla JS.
- **Live Agent Simulation**: Watch the LangGraph state machine trace compromised hosts, query targets, and execute secure SIFT commands.
- **BFS Lateral Movement Map**: SVG-rendered network tree highlighting compromise nodes, clean analyzed endpoints, and active traversal paths.
- **Process Discrepancies Panel**: Tabulates memory-vs-disk MFT discrepancies.
- **Circuit Breaker HUD**: Displays step counter meter. Flashes red and alerts the responder with an Executive Markdown report modal when the execution limit is hit.

---

## 4. Verification & Testing

**[SPEC]**
Verify the integrity of all codebases, safety membranes, and deterministic diffing models via the pre-built `pytest` suite:

```bash
# Set mock environment for non-SIFT environments
export AEGIS_MOCK=1

# Execute all tests
PYTHONPATH=. pytest -v tests/test_aegis.py
```

### Test Coverage Results:
- `test_safe_execute_command_mock`: Validates secure execution fallback logic when SIFT tools are missing.
- `test_safe_execute_command_shell_safety`: Ensures command injection inputs do not expand.
- `test_discrepancy_diffing`: Validates memory-only payload alerts.
- `test_lateral_traversal`: Asserts BFS lateral movement graphs correctly identify propagation paths.
- `test_langgraph_ttl_circuit_breaker`: Verifies the LangGraph orchestrator terminates and reports on TTL circuit break events.

---

## 5. Resolved Bugs & Troubleshooting

**[BUG] Missing typing import in diffing**
- **Symptom**: pytest fails during test collection with `NameError: name 'Optional' is not defined`.
- **Cause**: Misplaced `from typing import Optional` declaration at the very bottom of `aegis/diffing.py`.
- **Fix**: Moved import statement to the top of `aegis/diffing.py` and removed the stray block from the bottom.

**[BUG] Shell safety test mocked assertion**
- **Symptom**: `test_safe_execute_command_shell_safety` fails with KeyError when mocking is enabled.
- **Cause**: The test expected a mocked response for standard commands like `echo` when `AEGIS_MOCK=1` was active.
- **Fix**: Updated mocking checks to only mock forensic commands (`volatility`, `log2timeline`), allowing standard utilities to execute and verify that shell expansion did not occur.

**[BUG] LangGraph TTL step counter string match**
- **Symptom**: `test_langgraph_ttl_circuit_breaker` fails to find "TTL Circuit Breaker" in final report.
- **Cause**: The compiler generated the text "Time-To-Live (TTL) Circuit Breaker", but the assertion was checking for exact string "TTL Circuit Breaker" without parenthesis.
- **Fix**: Split assertion into separate tests for "TTL" and "Circuit Breaker" keywords in the report.

---

## Changelog
- **v1.0.0** (2026-05-22): Initial release of Project Aegis Core & Visual Incident Console. All tests PASSED.
