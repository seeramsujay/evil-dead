import pytest
import os
from aegis.utils import safe_execute_command, save_to_cache, load_from_cache, CACHE_DIR
from aegis.diffing import run_discrepancy_diff
from aegis.traversal import run_lateral_traversal
from aegis.orchestrator import create_aegis_graph, MAX_STEPS

# Ensure mock mode is enabled for test environment
os.environ["AEGIS_MOCK"] = "1"

# --- 1. Test Secure Command Execution Membrane ---

def test_safe_execute_command_mock():
    # Test volatility pslist mock execution
    command = ["volatility", "-f", "mock_mem.raw", "windows.pslist"]
    results = safe_execute_command(command)
    assert isinstance(results, list)
    assert len(results) > 0
    assert "PID" in results[0] or "pid" in results[0]

def test_safe_execute_command_shell_safety():
    # If shell=False is violated, executing arrays with shell metacharacters fails or acts literally.
    # We verify command is passed as array and does not trigger shell expansion.
    # E.g. cat with an argument containing spaces or characters.
    command = ["echo", "hello; echo world"]
    results = safe_execute_command(command)
    # Verify that the command executed securely and returned the output as a single string,
    # proving no shell parsing or split execution occurred.
    assert len(results) == 1
    assert results[0]["line"] == "hello; echo world"

# --- 2. Test Local Discrepancy Diffing ---

def test_discrepancy_diffing():
    # Define normal and anomalous processes
    processes = [
        {"PID": 100, "PPID": 4, "ImageFileName": "explorer.exe", "CreateTime": "2026-05-22 10:00:00"},
        {"PID": 200, "PPID": 100, "ImageFileName": "svchost.exe", "CreateTime": "2026-05-22 10:05:00"}, # Normal
        {"PID": 300, "PPID": 100, "ImageFileName": "hollowed.exe", "CreateTime": "2026-05-22 10:10:00"}, # Start time BEFORE disk create
        {"PID": 400, "PPID": 100, "ImageFileName": "memory_only.exe", "CreateTime": "2026-05-22 10:15:00"}, # Missing MFT disk file
    ]
    
    mft_records = [
        {"filepath": "C:\\Windows\\explorer.exe", "datetime": "2026-05-22 09:00:00"},
        {"filepath": "C:\\Windows\\System32\\svchost.exe", "datetime": "2026-05-22 09:00:00"},
        {"filepath": "C:\\Windows\\System32\\hollowed.exe", "datetime": "2026-05-22 10:30:00"}, # Created AFTER it started running (Anomalous!)
        # memory_only.exe is not in MFT records
    ]
    
    diff_result = run_discrepancy_diff(processes, mft_records)
    
    assert diff_result.scanned_processes == 4
    assert len(diff_result.discrepancies) == 2
    
    findings = {d.process_name: d for d in diff_result.discrepancies}
    
    # Check memory-only file discrepancy
    assert "memory_only.exe" in findings
    assert findings["memory_only.exe"].severity == "CRITICAL"
    assert "no corresponding MFT record" in findings["memory_only.exe"].finding
    
    # Check process hollowing time discrepancy
    assert "hollowed.exe" in findings
    assert findings["hollowed.exe"].severity == "HIGH"
    assert "earlier than its disk file creation time" in findings["hollowed.exe"].finding

# --- 3. Test Forensic Flood-Fill BFS Traversal ---

def test_lateral_traversal():
    # Temporal constraints test:
    # compromise chain: hostA -> hostB -> hostC
    logs = [
        # Connection A -> B (SUCCESS, after A compromise)
        {"timestamp": "2026-05-22 12:00:00", "source": "hostA", "destination": "hostB", "username": "admin", "event_type": "RDP", "status": "SUCCESS"},
        # Connection B -> C (SUCCESS, after B compromise)
        {"timestamp": "2026-05-22 12:30:00", "source": "hostB", "destination": "hostC", "username": "admin", "event_type": "SMB", "status": "SUCCESS"},
        # Connection C -> hostD (FAILED)
        {"timestamp": "2026-05-22 13:00:00", "source": "hostC", "destination": "hostD", "username": "admin", "event_type": "RDP", "status": "FAILED"},
        # Connection A -> hostE (SUCCESS, but BEFORE A compromise)
        {"timestamp": "2026-05-22 08:00:00", "source": "hostA", "destination": "hostE", "username": "admin", "event_type": "RDP", "status": "SUCCESS"},
    ]
    
    # Patient zero compromised at 2026-05-22 10:00:00
    manifest = run_lateral_traversal(logs, patient_zero="hostA", initial_compromise_time="2026-05-22 10:00:00")
    
    # Should find hostA, hostB, hostC compromised.
    # hostD should not be compromised (failed status).
    # hostE should not be compromised (before compromise time 10:00:00).
    compromised = manifest.compromised_hosts
    
    assert "hosta" in compromised
    assert "hostb" in compromised
    assert "hostc" in compromised
    assert "hostd" not in compromised
    assert "hoste" not in compromised
    
    assert manifest.total_compromised == 3
    assert len(manifest.traversal_path) == 2
    assert "hosta -> hostb" in manifest.traversal_path[0]
    assert "hostb -> hostc" in manifest.traversal_path[1]

# --- 4. Test LangGraph & TTL Circuit Breaker ---

def test_langgraph_ttl_circuit_breaker():
    graph = create_aegis_graph()
    
    # We will simulate a network log that causes a large loop.
    # Creating a temporary auth log file with multiple hops to trigger dynamic work loops.
    os.makedirs(CACHE_DIR, exist_ok=True)
    temp_log_path = os.path.join(CACHE_DIR, "test_auth.csv")
    
    # Compromise path: host0 (patient zero) -> host1 -> host2 -> host3 -> host4 -> host5 ...
    log_lines = [
        "timestamp,source,destination,username,event_type,status"
    ]
    for i in range(10):
        log_lines.append(f"2026-05-22 12:{i:02d}:00,host{i},host{i+1},admin,RDP,SUCCESS")
        
    with open(temp_log_path, "w") as f:
        f.write("\n".join(log_lines))
        
    initial_state = {
        "session_id": "test_session_ttl",
        "memory_dump": "mock_mem.raw",
        "disk_image": "mock_disk.img",
        "log_file_path": temp_log_path,
        "patient_zero": "host0",
        "initial_compromise_time": "2026-05-22 12:00:00",
        "current_target": "host0",
        "analyzed_targets": [],
        "discrepancies": [],
        "lateral_movement": {},
        "report": "",
        "steps": 0
    }
    
    # Execute the graph
    final_state = graph.invoke(initial_state)
    
    # Cleanup temp log file
    if os.path.exists(temp_log_path):
        os.remove(temp_log_path)
        
    # Verify the step counter is incremented and circuit breaker triggered.
    assert final_state["steps"] >= MAX_STEPS
    assert "TTL" in final_state["report"]
    assert "Circuit Breaker" in final_state["report"]
    assert "executive" in final_state["report"].lower()
    assert "dfir" in final_state["report"].lower()
