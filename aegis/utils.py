import subprocess
import shutil
import os
import json
import logging
import jc
from typing import List, Dict, Any, Optional

logger = logging.getLogger("aegis.utils")

# Set up environment-based mocking. If AEGIS_MOCK=1 or SIFT binaries are missing, use mock fallback.
AEGIS_MOCK = os.environ.get("AEGIS_MOCK", "1") == "1"

# In-memory mock database of forensic artifacts to simulate SIFT binaries if not present.
MOCK_DATA = {
    "volatility": {
        "windows.pslist": [
            {"PID": 4, "PPID": 0, "ImageFileName": "System", "CreateTime": "2026-05-22 10:00:00.000000"},
            {"PID": 120, "PPID": 4, "ImageFileName": "smss.exe", "CreateTime": "2026-05-22 10:00:05.000000"},
            {"PID": 524, "PPID": 120, "ImageFileName": "wininit.exe", "CreateTime": "2026-05-22 10:00:10.000000"},
            {"PID": 600, "PPID": 524, "ImageFileName": "services.exe", "CreateTime": "2026-05-22 10:00:11.000000"},
            {"PID": 612, "PPID": 524, "ImageFileName": "lsass.exe", "CreateTime": "2026-05-22 10:00:12.000000"},
            {"PID": 1024, "PPID": 600, "ImageFileName": "svchost.exe", "CreateTime": "2026-05-22 10:00:15.000000"},
            {"PID": 2048, "PPID": 600, "ImageFileName": "svchost.exe", "CreateTime": "2026-05-22 12:15:30.000000"}, # Normal svchost
            {"PID": 4321, "PPID": 600, "ImageFileName": "svchost.exe", "CreateTime": "2026-05-22 14:32:00.000000"}, # Suspicious (hollowed, spawned late)
            {"PID": 9999, "PPID": 1024, "ImageFileName": "backdoor.exe", "CreateTime": "2026-05-22 14:35:00.000000"}, # Suspicious (no file on disk)
        ],
        "windows.netscan": [
            {"PID": 4321, "LocalAddr": "192.168.1.50", "LocalPort": 49152, "ForeignAddr": "10.0.0.99", "ForeignPort": 4444, "State": "ESTABLISHED"},
            {"PID": 9999, "LocalAddr": "192.168.1.50", "LocalPort": 50000, "ForeignAddr": "10.0.0.99", "ForeignPort": 4445, "State": "ESTABLISHED"}
        ]
    },
    "log2timeline": [
        "datetime,source,source_long,message\n"
        "2026-05-22 10:00:11,MFT,MFT Record,File: C:\\Windows\\System32\\services.exe was created\n"
        "2026-05-22 10:00:12,MFT,MFT Record,File: C:\\Windows\\System32\\lsass.exe was created\n"
        "2026-05-22 10:00:15,MFT,MFT Record,File: C:\\Windows\\System32\\svchost.exe was created\n"
        "2026-05-22 12:15:30,MFT,MFT Record,File: C:\\Windows\\System32\\svchost.exe was modified\n"
        # Notice there is no MFT record for C:\Windows\System32\svchost.exe around 14:32:00, or it's missing entirely!
        # And C:\Windows\System32\backdoor.exe is missing from MFT records entirely!
    ]
}

def safe_execute_command(command: List[str], parser_name: Optional[str] = None) -> List[Dict[str, Any]]:
    """
    Executes a forensic CLI tool with absolute evidence integrity:
    1. Enforces shell=False.
    2. Inputs command as a strict list of arguments.
    3. Normalizes stdout using the `jc` library inside the Python middleware.
    4. Supports mock fallback if binary is not present in PATH.
    """
    if not command:
        raise ValueError("Command list cannot be empty.")

    binary_name = command[0]
    binary_path = shutil.which(binary_name)

    # Mock only if binary is missing OR (AEGIS_MOCK is enabled AND it's a forensic binary)
    is_forensic_tool = any(tool in binary_name for tool in ["volatility", "vol", "log2timeline", "psort"])
    if not binary_path or (AEGIS_MOCK and is_forensic_tool):
        logger.warning(f"Using mock fallback for command '{binary_name}' (missing binary or mock mode enabled).")
        return _get_mock_output(command, parser_name)

    # Execute the command securely (shell=False)
    try:
        result = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            shell=False,
            check=True
        )
    except subprocess.CalledProcessError as e:
        logger.error(f"Command execution failed: {e.stderr}")
        raise RuntimeError(f"Forensic tool execution failed: {e.stderr}") from e
    except FileNotFoundError as e:
        logger.error(f"Executable '{binary_name}' not found: {e}")
        # In case PATH resolution failed during runtime, fallback to mock
        return _get_mock_output(command, parser_name)

    # Normalize output through jc if a parser is specified
    stdout_data = result.stdout
    if parser_name:
        try:
            parsed_data = jc.parse(parser_name, stdout_data)
            # If jc returns a list of dicts, return it; if dict, wrap in a list
            if isinstance(parsed_data, list):
                return parsed_data
            elif isinstance(parsed_data, dict):
                return [parsed_data]
            else:
                return [{"raw_parsed": parsed_data}]
        except Exception as e:
            logger.error(f"Failed to parse stdout using jc parser '{parser_name}': {e}")
            raise RuntimeError(f"JSON normalization error: {e}") from e
    
    # Try parsing as native JSON first if no parser is specified
    try:
        parsed_json = json.loads(stdout_data)
        if isinstance(parsed_json, list):
            return parsed_json
        return [parsed_json]
    except json.JSONDecodeError:
        # If not JSON and no parser, return raw lines in a structured format
        return [{"line": line.strip()} for line in stdout_data.splitlines() if line.strip()]

def _get_mock_output(command: List[str], parser_name: Optional[str] = None) -> List[Dict[str, Any]]:
    """
    Returns mock forensic data based on the command.
    """
    binary_name = command[0]

    if "volatility" in binary_name or "vol" in binary_name:
        # Check plugin
        plugin = "windows.pslist"
        for arg in command:
            if "windows." in arg:
                plugin = arg
                break
        
        mock_list = MOCK_DATA["volatility"].get(plugin, MOCK_DATA["volatility"]["windows.pslist"])
        return mock_list

    elif "log2timeline" in binary_name:
        # Return mock plist/csv data
        csv_data = "".join(MOCK_DATA["log2timeline"])
        if parser_name == "csv":
            return jc.parse("csv", csv_data)
        return [{"raw": line} for line in csv_data.splitlines()]

    elif "psort" in binary_name:
        csv_data = "".join(MOCK_DATA["log2timeline"])
        if parser_name == "csv":
            return jc.parse("csv", csv_data)
        return [{"raw": line} for line in csv_data.splitlines()]

    # General fallback
    return [{"status": "mocked", "command": command}]

# --- Session Caching for Context Window Protection ---

CACHE_DIR = "/home/suzaykid/Projects/evil-dead/cache"

def save_to_cache(session_id: str, key: str, data: Any) -> str:
    """
    Saves forensic data to a local JSON cache file to protect the LLM's context window.
    """
    os.makedirs(CACHE_DIR, exist_ok=True)
    file_path = os.path.join(CACHE_DIR, f"{session_id}_{key}.json")
    with open(file_path, "w") as f:
        json.dump(data, f, indent=2)
    return file_path

def load_from_cache(session_id: str, key: str) -> Any:
    """
    Loads forensic data from the local JSON cache file.
    """
    file_path = os.path.join(CACHE_DIR, f"{session_id}_{key}.json")
    if not os.path.exists(file_path):
        logger.warning(f"Cache file {file_path} does not exist.")
        return None
    with open(file_path, "r") as f:
        return json.load(f)

