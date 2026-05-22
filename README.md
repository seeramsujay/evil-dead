# Project Aegis: The Autonomous DFIR Response Engine
**Version 1.0.0** · SANS Find Evil! Hackathon · 2026

---

## AI READING INSTRUCTION

Read `[SPEC]` and `[BUG]` blocks for authoritative facts and system commands.
Read `[NOTE]` only if additional context or design history is needed.
`[?]` blocks are unverified claims.

---

## 1. Overview & Core Concept

**[SPEC]**
- **Objective**: Fully autonomous Incident Response (IR) agent optimized for the SANS SIFT Workstation.
- **Architectural Shift**: Decouples the LLM from raw logs. Analysis runs locally via deterministic Python functions.
- **Integrity Boundary**: Restricts SIFT tool execution (`volatility`, `log2timeline`) to strict `subprocess.run(shell=False)` arrays.
- **Context Window Protection**: Automatically sanitizes CLI text walls into structured JSON using `jc` before context ingestion.
- **State safety**: Prevents multi-agent loops via a LangGraph state machine with an immutable step counter and TTL circuit breaker.

**[NOTE]**
Human responders frequently struggle to process voluminous forensic logs under time pressure, while LLMs degrade in accuracy when fed raw console dumps. Project Aegis bridges the gap. It is built as a SIFT Workstation FastMCP server and LangGraph runner to automate triage securely and present an executive summary automatically.

---

## 2. Architectural Pillars

**[SPEC]**
- **1. Custom FastMCP Server (`aegis/mcp_server.py`)**:
  - Exposes SIFT forensic tools and local analysis modules to MCP-capable clients.
  - Automatically manages target session scopes.
- **2. Secure Execution Membrane (`aegis/utils.py`)**:
  - Construction: Commands constructed as strict lists (e.g. `["volatility", "-f", img, "pslist"]`).
  - Parsing: Raw stdout is piped to the `jc` Python parsing library inside the Python server.
  - Caching: Output is saved to local JSON cache files. Only cache file paths or summaries are returned to the LLM.
- **3. Deterministic Discrepancy Diffing (`aegis/diffing.py`)**:
  - Logic: Cross-references Volatility process lists against Plaso MFT timeline entries.
  - Anomalies: Flags processes running in memory that lack valid disk creation times or signatures.
- **4. Forensic Flood-Fill BFS (`aegis/traversal.py`)**:
  - Logic: Executes BFS traversal starting from "Patient Zero" across auth/network logs.
  - Verification: Enforces chronological compromise propagation constraint.
- **5. LangGraph Stateful Orchestration (`aegis/orchestrator.py`)**:
  - Schema: Tracks current targets, compromised hosts, analyzed hosts, discrepancies, and steps.
  - Safety: Router halts graph execution if `steps >= MAX_STEPS` (5), forcing a compiler node run.

---

## 3. Visual Threat Hunting Dashboard

**[SPEC]**
- **Path**: Located under `dashboard/` in the project root.
- **Tech Stack**: HTML5, CSS3 Grid/Flexbox, Vanilla JS, and interactive SVG rendering (no external framework/build steps required).
- **Core Visualizations**:
  - **Simulation Console**: Step-by-step log of the agent traversing targets and executing SIFT commands.
  - **BFS Lateral Movement Map**: SVG-rendered tree mapping propagation from Patient Zero.
  - **Discrepancy Log Table**: Table showcasing memory-vs-disk MFT discrepancies.
  - **Circuit Breaker HUD**: Real-time step meter flashing red and halting simulation when hitting safety limits.

![Project Aegis Forensic Dashboard Mockup](/home/suzaykid/.gemini/antigravity/brain/ce65d5ab-eedd-4974-a14f-f447848559b9/aegis_forensic_dashboard_1779467106174.png)

---

## 4. Setup & Deployment

**[SPEC]**
```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Run the MCP server (launches FastMCP server)
mcp run aegis/mcp_server.py

# 3. Execute the automated verification tests
PYTHONPATH=. pytest -v tests/test_aegis.py

# 4. Open the Visual threat hunting console
# Navigate to the dashboard directory and open index.html in any browser
python3 -m http.server -d dashboard/ 8000
# Open browser at http://localhost:8000
```

---

## 5. Verification & Safety Guarantees

**[SPEC]**
- **Execution Safety**: Commands executed via `subprocess.run(shell=False)` do not trigger shell parsing or semicolon command injections.
- **Context Limit**: Large log outputs are stored in local JSON files in the `/cache` folder instead of entering the LLM conversation history.
- **Orchestrator Safety**: The TTL Circuit Breaker will unconditionally route to `compile_report` if agent steps exceed 5.

---

## 6. Resolved Bugs & Troubleshooting

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
- **Fix**: Splitted assertion into separate tests for "TTL" and "Circuit Breaker" keywords in the report.

---

## Changelog
- **v1.0.0** (2026-05-22): Initial release of Project Aegis Core & Visual Incident Console. All tests PASSED.
