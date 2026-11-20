# Project Aegis (Evil-Dead): Architectural Review & DFIR Roadmap (future.md)

---

## 1. Architectural Code Review & Threat Landscape Analysis

Project Aegis (`evil-dead`) is an autonomous Digital Forensics & Incident Response (DFIR) Copilot engineered for enterprise incident responders and SOC teams operating SIFT forensic workstations. It marries deterministic Python forensic discrepancy diffing with **LangGraph** multi-agent orchestration, isolating LLM hallucinations and constraining AI execution to verifiable timeline evidence.

### Architectural Strengths
- **Deterministic Discrepancy Diffing:** Compares volatile in-memory processes (`windows.pslist`) with non-volatile Master File Table (MFT) disk metadata, uncovering memory-only injections and process hollowing.
- **BFS Lateral Movement Engine:** Traverses system event logs (Windows Event ID 4624/4625, Kerberos ticket requests) using Breadth-First Search from Patient Zero, pruning false positives through strict chronological timestamps.
- **Shell-Injection Defense Membrane:** Forensic tooling (`volatility`, `log2timeline`) is invoked strictly through non-shell argument arrays (`shell=False`), preventing malicious filenames from executing command injections.
- **TTL Circuit Breaker:** Implements a hard step ceiling in LangGraph, preventing runaway LLM loops during sprawling incident graphs.

### Identified Bottlenecks & Modernization Needs
1. **Volatility 2 vs Volatility 3 Architecture:** Legacy Volatility 2 dependencies require manual OS profile guessing; upgrading to Volatility 3's modern symbol table architecture eliminates profile errors.
2. **Timeline Memory Scaling:** Parsing gigabyte-scale Plaso super-timelines (`.plaso` / `log2timeline`) directly in Python memory risks OOM on standard analyst machines.
3. **Graph Traversal Complexity:** In high-volume Active Directory domains with millions of authentication events, pure Python BFS traversal incurs high latency ($>30\text{s}$).

---

## 2. Strategic Engineering Roadmap

```mermaid
flowchart TD
    subgraph Phase 1: High-Performance Forensic Timeline Engine
        P1A[Volatility 3 Symbol Engine Ingestion] --> P1B[DuckDB / Polars Super-Timeline Ingestion]
        P1B --> P1C[Sub-Second SQL Event Aggregator]
    end

    subgraph Phase 2: Graph Neural Networks & Threat Hunting
        P2A[Graph Neural Network for Lateral Paths] --> P2B[Automated MITRE ATT&CK Matrix Mapping]
        P2B --> P2C[Context-Aware Sigma & YARA Rule Generator]
    end

    subgraph Phase 3: Live Incident Response Orchestration
        P3A[Velociraptor / osquery Live Endpoint Agent] --> P3B[Automated Memory Dump Trigger]
        P3B --> P3C[Automated Host Quarantine & Token Revocation]
    end

    subgraph Phase 4: Airgapped Sovereign DFIR Enclave
        P4A[Local Quantized Cyber LLM: Qwen / Llama 3] --> P4B[Zero-Telemetry SIFT Docker Enclave]
        P4B --> P4C[Cryptographically Signed Chain of Custody Report]
    end

    Phase 1 --> Phase 2
    Phase 2 --> Phase 3
    Phase 3 --> Phase 4
```

---

## 3. Detailed Milestone Execution Plan

### Milestone 1: Modern Volatility 3 Core & High-Speed DuckDB Timelines
- [ ] **Volatility 3 Migration:** Port `aegis/diffing.py` to use Volatility 3's unified ISF (Intermediate Symbol Format) for automated kernel symbol resolution across Windows 10/11 and Linux kernels.
- [ ] **DuckDB Timeline Storage:** Ingest Plaso timeline CSVs/JSONs directly into an in-process DuckDB analytical store, querying $>10^7$ events in milliseconds without RAM exhaustion.
- [ ] **Process Parent-Child Ancestry Verification:** Automatically detect orphan processes by validating PPID parentage against kernel PID recycling rules.

### Milestone 2: Automated Sigma Rule Synthesis & GNN Threat Hunting
- [ ] **Automated Rule Extraction:** Convert identified memory discrepancies and suspicious command lines into standard Sigma detection rules and YARA signatures.
- [ ] **MITRE ATT&CK Alignment:** Map identified execution artifacts to specific ATT&CK techniques (T1055: Process Injection, T1078: Valid Accounts, T1021: Remote Services).

### Milestone 3: Live Endpoint Triaging via Velociraptor
- [ ] **Velociraptor API Bridge:** Query live endpoints on-demand to pull volatile memory artifacts and MFT chunks without physical disk acquisition delays.
- [ ] **Automated Blast-Radius Containment:** Provide authorized responders with one-click isolation scripts to terminate compromised user sessions and revoke Kerberos TGT tickets.

### Milestone 4: Airgapped Chain of Custody Compliance
- [ ] **Offline Sovereign Inference:** Deploy local Ollama / vLLM instances for classified or sensitive DFIR investigations requiring strict zero-telemetry boundaries.
- [ ] **Cryptographic Hash Verification:** Automatically compute SHA-256 and Blake3 hashes of all ingested disk dumps, memory dumps, and generated Markdown reports for court-admissible chain of custody logs.
