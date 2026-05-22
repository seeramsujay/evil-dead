# Required Technical Stack & Proficiencies

## Core Development
- **Python 3.10+:** Advanced knowledge of `subprocess` management, error handling, and strict typing.
- **Pydantic:** Defining rigid data schemas for input validation to prevent model hallucinations from crashing tools.
- **Graph Algorithms:** Breadth-First Search (BFS) for the lateral movement flood-fill implementation.

## Agent Orchestration & Middleware
- **FastMCP (Model Context Protocol SDK):** Understanding how to expose Python functions as standardized JSON-RPC endpoints to an LLM.
- **LangGraph:** Managing stateful, cyclical agent workflows using `StateGraph`, `TypedDict`, and writing deterministic conditional edges (routing functions).

## Digital Forensics (Domain Knowledge)
- **Volatility 3:** Understanding how to extract process lists (`pslist`), network connections (`netstat`), and memory maps from raw memory dumps.
- **Plaso / log2timeline:** Understanding super-timeline creation and how to filter CSV outputs using `psort`.
- **jc (JSON Convert):** Familiarity with parsing legacy CLI outputs into JSON structures.