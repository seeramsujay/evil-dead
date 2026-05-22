# Project Aegis: The Deterministic Discrepancy & Traversal Engine

## The Core Concept
Project Aegis is a fully autonomous incident response agent built on the SANS SIFT Workstation. It bridges the speed gap between offensive AI and human responders without falling victim to LLM hallucinations or context bloat. 

It achieves this by removing the LLM from the raw data analysis phase. Aegis uses a Custom Model Context Protocol (MCP) server to execute forensic tools, normalizes the outputs locally, and uses deterministic Python logic to identify anomalies *before* handing the curated findings to the LLM for contextual reporting.

## Architectural Pillars

### 1. The Custom MCP Membrane
- **Function:** Wraps SIFT CLI tools (`volatility`, `log2timeline`) into strict, type-safe Python functions using FastMCP.
- **Security:** Executes all forensic binaries using `subprocess.run(shell=False)` to prevent prompt-injection command execution and ensure absolute evidence integrity.
- **Normalization:** Pipes all massive terminal outputs through `jc` (JSON Convert) to transform unreadable text walls into structured, compressible JSON objects.

### 2. Deterministic Discrepancy Diffing
- **Function:** Cross-references active volatile memory (`pslist`) against the Master File Table (MFT) disk artifacts.
- **Target:** Automatically identifies process hollowing and rootkits by mathematically flagging processes running in memory that lack valid disk creation timestamps or signatures.

### 3. Forensic Flood-Fill (Lateral Traversal)
- **Function:** Applies a Breadth-First Search (BFS) algorithm to network and authentication logs.
- **Target:** Starts at "Patient Zero" (initial exploit indicator) and automatically maps the entire blast radius of the adversary's lateral movement, archiving the state of all contaminated endpoints into a single JSON manifest.

### 4. Stateful Orchestration (The Circuit Breaker)
- **Function:** Uses LangGraph to manage the agent's workflow.
- **Safety Valve:** Implements a hard-coded Time-To-Live (TTL) step counter embedded in the immutable `AgentState`. This unconditionally prevents "Multi-Agent Death Spirals" by forcing the agent into a graceful reporting node if it exceeds the maximum allowed execution cycles.