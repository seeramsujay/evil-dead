import logging
from collections import deque
from datetime import datetime
from typing import List, Dict, Any, Set, Tuple
from aegis.schemas import NetworkLogEvent, TraversalNode, LateralTraversalManifest
from aegis.diffing import parse_forensic_datetime

logger = logging.getLogger("aegis.traversal")

def run_lateral_traversal(
    logs: List[Dict[str, Any]], 
    patient_zero: str, 
    initial_compromise_time: str
) -> LateralTraversalManifest:
    """
    Applies BFS flood-fill algorithm to trace adversary lateral movement starting from patient_zero.
    
    Temporal Constraint:
    Lateral movement connection from Host A to Host B can only occur *after* Host A was compromised.
    
    Returns a LateralTraversalManifest mapping the compromised graph.
    """
    # 1. Parse and validate logs
    parsed_events: List[NetworkLogEvent] = []
    for l in logs:
        try:
            timestamp = l.get("timestamp") or l.get("Timestamp") or l.get("datetime")
            source = l.get("source") or l.get("Source") or l.get("src") or l.get("source_ip")
            destination = l.get("destination") or l.get("Destination") or l.get("dst") or l.get("destination_ip")
            username = l.get("username") or l.get("Username") or l.get("user")
            event_type = l.get("event_type") or l.get("Event") or l.get("type") or l.get("protocol") or "Network Connection"
            status = l.get("status") or l.get("Status") or "SUCCESS"
            
            if not timestamp or not source or not destination:
                continue
                
            parsed_events.append(NetworkLogEvent(
                timestamp=str(timestamp),
                source=str(source).strip().lower(),
                destination=str(destination).strip().lower(),
                username=str(username) if username else "unknown",
                event_type=str(event_type),
                status=str(status).upper()
            ))
        except Exception as e:
            logger.warning(f"Failed to parse log event {l}: {e}")

    # 2. Setup BFS structures
    # compromised_hosts: host -> TraversalNode
    patient_zero_norm = patient_zero.strip().lower()
    compromised_hosts: Dict[str, TraversalNode] = {
        patient_zero_norm: TraversalNode(
            host=patient_zero,
            compromise_time=initial_compromise_time,
            vector="Initial Compromise (Patient Zero)",
            username="SYSTEM/Exploit"
        )
    }

    # Queue contains tuples of (host_norm, compromise_time_str)
    queue: deque[Tuple[str, str]] = deque([(patient_zero_norm, initial_compromise_time)])
    
    # Store traversal path as sequence of edges/hops for reporting e.g. "patient_zero -> hostB (via RDP)"
    traversal_path: List[str] = []
    
    # Keep track of hops to avoid cyclical loops
    visited_hosts: Set[str] = {patient_zero_norm}

    # 3. BFS Loop
    while queue:
        curr_host, curr_compromise_str = queue.popleft()
        curr_comp_time = parse_forensic_datetime(curr_compromise_str)
        
        if not curr_comp_time:
            logger.error(f"Invalid compromise time format for host '{curr_host}': {curr_compromise_str}")
            continue

        # Find all successful lateral connections from this host
        for event in parsed_events:
            if event.source == curr_host and event.status == "SUCCESS":
                dest_host = event.destination
                
                # Check temporal ordering: connection must happen AFTER source compromise
                conn_time = parse_forensic_datetime(event.timestamp)
                if not conn_time:
                    continue
                    
                if conn_time >= curr_comp_time:
                    # If destination host is not yet compromised
                    if dest_host not in visited_hosts:
                        visited_hosts.add(dest_host)
                        
                        # Mark destination as compromised
                        compromised_hosts[dest_host] = TraversalNode(
                            host=dest_host,
                            compromise_time=event.timestamp,
                            vector=f"{event.event_type} from {curr_host}",
                            username=event.username
                        )
                        
                        # Add hop to path
                        traversal_path.append(f"{curr_host} -> {dest_host} ({event.event_type} as {event.username} at {event.timestamp})")
                        
                        # Enqueue for further traversal
                        queue.append((dest_host, event.timestamp))

    return LateralTraversalManifest(
        patient_zero=patient_zero,
        compromised_hosts=compromised_hosts,
        traversal_path=traversal_path,
        total_compromised=len(compromised_hosts)
    )
