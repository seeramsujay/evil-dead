import logging
from typing import TypedDict, List, Dict, Any, Literal
from langgraph.graph import StateGraph, START, END

# Import our deterministic tools and logic
from aegis.mcp_server import run_volatility, run_plaso, analyze_discrepancies, trace_lateral_movement

logger = logging.getLogger("aegis.orchestrator")

# Maximum execution steps (TTL limit)
MAX_STEPS = 5

class AgentState(TypedDict):
    session_id: str
    memory_dump: str
    disk_image: str
    log_file_path: str
    patient_zero: str
    initial_compromise_time: str
    current_target: str
    analyzed_targets: List[str]
    discrepancies: List[Dict[str, Any]]
    lateral_movement: Dict[str, Any]
    report: str
    steps: int  # PRIME DIRECTIVE: MUST include steps in State

def node_run_tools(state: AgentState) -> Dict[str, Any]:
    """
    Executes forensic collection tools (Volatility and Plaso) for the current target.
    Updates the list of analyzed targets.
    """
    session_id = state["session_id"]
    current_target = state["current_target"]
    steps = state["steps"] + 1
    
    logger.info(f"[Step {steps}] Running forensic tools on target: {current_target}")
    
    # Run Volatility
    vol_res = run_volatility(
        memory_dump=state["memory_dump"],
        plugin="windows.pslist",
        session_id=session_id
    )
    
    # Run Plaso
    plaso_res = run_plaso(
        disk_image=state["disk_image"],
        session_id=session_id
    )
    
    analyzed = list(state.get("analyzed_targets", []))
    if current_target not in analyzed:
        analyzed.append(current_target)
        
    return {
        "steps": steps,
        "analyzed_targets": analyzed
    }

def node_analyze(state: AgentState) -> Dict[str, Any]:
    """
    Performs deterministic discrepancy diffing and lateral movement BFS traversal.
    """
    session_id = state["session_id"]
    steps = state["steps"] + 1
    
    logger.info(f"[Step {steps}] Running deterministic anomaly analysis & BFS lateral movement tracing.")
    
    # Run local discrepancy diffing
    diff_res = analyze_discrepancies(session_id=session_id)
    discrepancies = diff_res.get("discrepancies", [])
    
    # Run lateral movement BFS traversal from logs
    lat_res = trace_lateral_movement(
        log_file_path=state["log_file_path"],
        patient_zero=state["patient_zero"],
        initial_compromise_time=state["initial_compromise_time"]
    )
    
    return {
        "steps": steps,
        "discrepancies": discrepancies,
        "lateral_movement": lat_res
    }

def node_compile_report(state: AgentState) -> Dict[str, Any]:
    """
    Terminal node compiling the final findings.
    """
    steps = state["steps"] + 1
    logger.info(f"[Step {steps}] Entering terminal summary node. Compiling executive incident report.")
    
    discrepancies = state.get("discrepancies", [])
    lateral_movement = state.get("lateral_movement", {})
    
    compromised_hosts = list(lateral_movement.get("compromised_hosts", {}).keys())
    traversal_path = lateral_movement.get("traversal_path", [])
    
    report_lines = [
        "# PROJECT AEGIS EXECUTIVE DFIR REPORT",
        f"Session ID: {state['session_id']}",
        f"Total Steps Taken: {steps}",
        "",
        "## 1. DETERMINISTIC DISCREPANCY ANALYSIS",
        f"Scanned {state['current_target']}: Identified {len(discrepancies)} process/disk discrepancies."
    ]
    
    for idx, d in enumerate(discrepancies, 1):
        report_lines.append(f"  {idx}. [{d['severity']}] PID {d['pid']} ({d['process_name']}): {d['finding']}")
        
    report_lines.extend([
        "",
        "## 2. LATERAL MOVEMENT BLAST RADIUS MAP (BFS FLOOD-FILL)",
        f"Patient Zero: {state['patient_zero']}",
        f"Total Compromised Endpoints: {len(compromised_hosts)}",
        f"Compromised Host List: {', '.join(compromised_hosts)}",
        "",
        "### Traversal Propagation Hops:"
    ])
    
    for hop in traversal_path:
        report_lines.append(f"  - {hop}")
        
    if steps >= MAX_STEPS:
        report_lines.extend([
            "",
            "> [!WARNING]",
            f"> Aegis execution was stopped by the Time-To-Live (TTL) Circuit Breaker to prevent an infinite analysis loop. "
            f"There were still unanalyzed compromised hosts in the queue."
        ])
        
    report_body = "\n".join(report_lines)
    
    return {
        "steps": steps,
        "report": report_body
    }

# --- Routing Logic & TTL Circuit Breaker ---

def router_after_analysis(state: AgentState) -> Literal["run_tools", "compile_report"]:
    """
    Conditional routing edge acting as a TTL Circuit Breaker and IR work loop router.
    """
    steps = state["steps"]
    
    # 1. TTL Circuit Breaker check
    if steps >= MAX_STEPS:
        logger.warning(
            f"TTL Circuit Breaker Triggered (steps={steps} >= max_steps={MAX_STEPS}). "
            "Forcing routing to compile_report node to prevent infinite loop."
        )
        return "compile_report"
        
    # 2. Work Loop: Check if there are other compromised hosts we haven't analyzed yet
    lateral_movement = state.get("lateral_movement", {})
    compromised_hosts = list(lateral_movement.get("compromised_hosts", {}).keys())
    analyzed_targets = state.get("analyzed_targets", [])
    
    for host in compromised_hosts:
        if host not in analyzed_targets:
            # Set the next host to analyze dynamically (mock simulation)
            logger.info(f"Work loop: Found unanalyzed compromised host '{host}'. Looping back to run tools.")
            state["current_target"] = host
            return "run_tools"
            
    # No more targets to analyze, proceed to report
    logger.info("Work loop complete. All compromised hosts analyzed. Proceeding to compile report.")
    return "compile_report"

# --- Graph Assembly ---

def create_aegis_graph() -> StateGraph:
    """
    Assembles and compiles the LangGraph StateGraph.
    """
    builder = StateGraph(AgentState)
    
    # Add nodes
    builder.add_node("run_tools", node_run_tools)
    builder.add_node("analyze", node_analyze)
    builder.add_node("compile_report", node_compile_report)
    
    # Add transitions
    builder.add_edge(START, "run_tools")
    builder.add_edge("run_tools", "analyze")
    
    # Conditional edge from analysis node using router (TTL + Loop)
    builder.add_conditional_edges(
        "analyze",
        router_after_analysis,
        {
            "run_tools": "run_tools",
            "compile_report": "compile_report"
        }
    )
    
    builder.add_edge("compile_report", END)
    
    return builder.compile()
