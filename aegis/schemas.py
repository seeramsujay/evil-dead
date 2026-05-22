from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional

# --- Volatility & Plaso Schema Models ---

class ProcessInfo(BaseModel):
    pid: int = Field(..., description="Process Identifier")
    ppid: int = Field(..., description="Parent Process Identifier")
    name: str = Field(..., description="Name of the process executable")
    path: Optional[str] = Field(None, description="Executable path if available in memory")
    create_time: Optional[str] = Field(None, description="Process creation timestamp (ISO or Volatility format)")
    exit_time: Optional[str] = Field(None, description="Process exit timestamp (if terminated)")

class MftRecord(BaseModel):
    filepath: str = Field(..., description="Full file path on the disk filesystem")
    creation_time: str = Field(..., description="File creation timestamp from standard information / MFT record")
    modification_time: Optional[str] = Field(None, description="File modification timestamp")
    is_deleted: bool = Field(False, description="Flag indicating if the MFT record is marked as deleted")
    md5_hash: Optional[str] = Field(None, description="MD5 hash of the file if calculated")

# --- Anomaly Detection Schemas ---

class DiscrepancyReport(BaseModel):
    pid: int
    process_name: str
    mft_path: Optional[str]
    finding: str = Field(..., description="Explanation of the discrepancy (e.g. Memory process running with no corresponding disk file, or mismatching timestamps)")
    severity: str = Field("HIGH", description="Severity level: LOW, MEDIUM, HIGH, CRITICAL")

class DiffingResult(BaseModel):
    scanned_processes: int
    scanned_mft_records: int
    discrepancies: List[DiscrepancyReport] = Field(default_factory=list)

# --- Lateral Traversal Schemas ---

class NetworkLogEvent(BaseModel):
    timestamp: str = Field(..., description="Timestamp of the connection or authentication event")
    source: str = Field(..., description="Source hostname or IP address")
    destination: str = Field(..., description="Destination hostname or IP address")
    username: Optional[str] = Field(None, description="Username associated with the session")
    event_type: str = Field(..., description="Type of event, e.g. 'RDP', 'SMB', 'Logon', 'WinRM'")
    status: str = Field("SUCCESS", description="Outcome of the event: SUCCESS or FAILED")

class TraversalNode(BaseModel):
    host: str
    compromise_time: str
    vector: str = Field(..., description="Log event/action that resulted in compromise")
    username: str

class LateralTraversalManifest(BaseModel):
    patient_zero: str
    compromised_hosts: Dict[str, TraversalNode] = Field(default_factory=dict)
    traversal_path: List[str] = Field(default_factory=list)  # Sequence of hops
    total_compromised: int

# --- FastMCP Tool Argument Schemas ---

class VolatilityArgs(BaseModel):
    memory_dump: str = Field(..., description="Absolute path to the raw memory dump file")
    plugin: str = Field("windows.pslist", description="Volatility 3 plugin to run (e.g., windows.pslist, windows.netscan)")
    additional_args: List[str] = Field(default_factory=list, description="Additional plugin-specific arguments")

class PlasoArgs(BaseModel):
    disk_image: str = Field(..., description="Absolute path to the disk image to run log2timeline on")
    output_file: str = Field(..., description="Path where the plaso dump/CSV should be generated")
    filter_expression: Optional[str] = Field(None, description="Optional filter expression for psort")
