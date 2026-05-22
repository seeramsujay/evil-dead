import logging
from typing import List, Dict, Any, Optional
from mcp.server.fastmcp import FastMCP
from aegis.utils import safe_execute_command, save_to_cache, load_from_cache
from aegis.diffing import run_discrepancy_diff
from aegis.traversal import run_lateral_traversal

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("aegis.mcp_server")

# Initialize FastMCP server
mcp = FastMCP("aegis")

@mcp.tool()
def run_volatility(
    memory_dump: str, 
    plugin: str = "windows.pslist", 
    session_id: str = "default"
) -> Dict[str, Any]:
    """
    Executes Volatility 3 on a memory dump securely using shell=False.
    Parses output and saves results in the local cache to protect the LLM's context window.
    
    Args:
        memory_dump: Absolute path to the raw memory dump.
        plugin: Volatility 3 plugin to run (e.g. windows.pslist, windows.netscan).
        session_id: Unique identifier for the analysis session.
    """
    logger.info(f"Running Volatility {plugin} on {memory_dump} for session {session_id}")
    
    # Construct strict command array to prevent command injection (Evidence Integrity Directive)
    command = ["volatility", "-f", memory_dump, plugin]
    
    # Run the command and get normalized JSON list (parsed with jc or natively)
    try:
        # Note: Volatility 3 outputs are processed via safe runner
        results = safe_execute_command(command)
        
        # Save to local session cache file instead of sending raw data to LLM (Context Window Protection)
        cache_path = save_to_cache(session_id, plugin, results)
        
        return {
            "status": "success",
            "session_id": session_id,
            "plugin": plugin,
            "record_count": len(results),
            "cache_path": cache_path,
            "message": "Forensic data parsed and cached locally. Raw logs withheld from LLM context."
        }
    except Exception as e:
        logger.error(f"Volatility tool execution error: {e}")
        return {
            "status": "error",
            "error_type": type(e).__name__,
            "message": str(e)
        }

@mcp.tool()
def run_plaso(
    disk_image: str, 
    session_id: str = "default"
) -> Dict[str, Any]:
    """
    Executes Plaso log2timeline on a disk image securely using shell=False.
    Parses resulting timelines and caches MFT records.
    
    Args:
        disk_image: Absolute path to the disk image.
        session_id: Unique identifier for the analysis session.
    """
    logger.info(f"Running Plaso on {disk_image} for session {session_id}")
    
    # Plaso commands constructed as a strict array
    output_plaso = f"/home/suzaykid/Projects/evil-dead/cache/{session_id}_timeline.plaso"
    command = ["log2timeline.py", "--status_view", "none", output_plaso, disk_image]
    
    try:
        # Normalizes output via jc 'csv' parser
        results = safe_execute_command(command, parser_name="csv")
        
        # Cache MFT records locally
        cache_path = save_to_cache(session_id, "mft", results)
        
        return {
            "status": "success",
            "session_id": session_id,
            "record_count": len(results),
            "cache_path": cache_path,
            "message": "Disk MFT timeline parsed and cached locally. Raw logs withheld from LLM context."
        }
    except Exception as e:
        logger.error(f"Plaso tool execution error: {e}")
        return {
            "status": "error",
            "error_type": type(e).__name__,
            "message": str(e)
        }

@mcp.tool()
def analyze_discrepancies(session_id: str = "default") -> Dict[str, Any]:
    """
    Calculates differences between volatile memory (pslist) and MFT records deterministically.
    Sends only the list of discrepancy reports back to the LLM (Context Protection & Anomaly Detection Directives).
    
    Args:
        session_id: Unique identifier for the analysis session.
    """
    logger.info(f"Calculating discrepancies for session {session_id}")
    
    processes = load_from_cache(session_id, "windows.pslist")
    mft_records = load_from_cache(session_id, "mft")
    
    if processes is None:
        return {
            "status": "error",
            "message": f"Volatility process list ('windows.pslist') not found in cache for session {session_id}. Please run Volatility tool first."
        }
        
    if mft_records is None:
        return {
            "status": "error",
            "message": f"MFT disk timeline ('mft') not found in cache for session {session_id}. Please run Plaso tool first."
        }
        
    try:
        # Calculate discrepancies locally (Deterministic Anomaly Detection)
        diff_result = run_discrepancy_diff(processes, mft_records)
        return diff_result.model_dump()
    except Exception as e:
        logger.error(f"Error during discrepancy diff: {e}")
        return {
            "status": "error",
            "error_type": type(e).__name__,
            "message": str(e)
        }

@mcp.tool()
def trace_lateral_movement(
    log_file_path: str, 
    patient_zero: str, 
    initial_compromise_time: str
) -> Dict[str, Any]:
    """
    Traces adversary lateral movement from network/authentication logs using BFS flood-fill.
    Enforces temporal analysis constraints (compromise propagation order) and returns a structural manifest.
    
    Args:
        log_file_path: Path to the log file (CSV containing authentication/connection logs).
        patient_zero: Hostname or IP of the initial compromise point.
        initial_compromise_time: Earliest timestamp of patient zero compromise (YYYY-MM-DD HH:MM:SS).
    """
    logger.info(f"Tracing lateral movement from {log_file_path} starting at {patient_zero}")
    
    # Construct command to cat the log file and parse as CSV using jc (Evidence Integrity & Normalization)
    command = ["cat", log_file_path]
    
    try:
        # Use safe runner and parse CSV using jc
        parsed_logs = safe_execute_command(command, parser_name="csv")
        
        # Calculate BFS traversal locally (Deterministic Anomaly Detection)
        manifest = run_lateral_traversal(parsed_logs, patient_zero, initial_compromise_time)
        return manifest.model_dump()
    except Exception as e:
        logger.error(f"Error tracing lateral movement: {e}")
        return {
            "status": "error",
            "error_type": type(e).__name__,
            "message": str(e)
        }

if __name__ == "__main__":
    # Start the FastMCP server when executed directly
    mcp.run()
