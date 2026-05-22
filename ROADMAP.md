# Project Aegis: 3-Week Execution Roadmap
**Target Deadline:** June 15, 2026

## Week 1: The Secure Membrane (May 23 - May 29)
**Objective:** Establish the FastMCP server, tool wrappers, and JSON normalization pipeline on the SIFT Workstation.

- [ ] Install SIFT Workstation OVA and Protocol SIFT dependencies.
- [ ] Initialize Python environment and install `mcp`, `pydantic`, `langgraph`, and `jc`.
- [ ] Write the `subprocess` wrapper for `volatility` (Memory Analysis).
- [ ] Write the `subprocess` wrapper for `log2timeline` / `psort` (Disk Analysis).
- [ ] Implement the `jc` pipe logic to ensure all tool standard outputs are perfectly formatted JSON.
- [ ] Run isolated local tests verifying the LLM can call the MCP server and receive JSON without context window collapse.

## Week 2: Deterministic Logic & Graph Orchestration (May 30 - June 5)
**Objective:** Build the local diffing algorithms and the LangGraph state machine.

- [ ] Develop the Discrepancy Diffing Python function (Memory vs. Disk comparison).
- [ ] Develop the Forensic Flood-Fill BFS algorithm to trace lateral movement through auth logs.
- [ ] Expose these two Python functions as `@mcp.tool()` endpoints.
- [ ] Construct the LangGraph `AgentState` schema (must include the `steps` integer).
- [ ] Build the conditional router to act as the TTL Circuit Breaker.
- [ ] Integrate the chosen LLM (e.g., Claude 3.5 Sonnet) into the LangGraph nodes.

## Week 3: Ground Truth Testing & Submission Prep (June 6 - June 14)
**Objective:** Validate accuracy against deterministic data and produce hackathon deliverables.

- [ ] Download NIST CFReDS sample memory images and PCAP files.
- [ ] Build the Pytest harness to evaluate Aegis against synthetic injected anomalies (bypassing model data contamination).
- [ ] Refine system prompts based on evaluation failure modes.
- [ ] **Deliverable 1:** Record the 5-minute screencast demonstrating the agent finding an anomaly and the TTL circuit breaker executing successfully.
- [ ] **Deliverable 2:** Draft the Architecture Diagram clearly defining the MCP trust boundaries.
- [ ] **Deliverable 3:** Complete the Devpost write-up (Accuracy Report, Try-It-Out instructions).
- [ ] Submit repository and assets before June 15.