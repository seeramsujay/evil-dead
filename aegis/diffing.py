import logging
from datetime import datetime
from typing import List, Dict, Any, Optional
from aegis.schemas import ProcessInfo, MftRecord, DiscrepancyReport, DiffingResult

logger = logging.getLogger("aegis.diffing")

def parse_forensic_datetime(dt_str: str) -> Optional[datetime]:
    """
    Parses common forensic datetime string formats (from Volatility, Plaso, or standard ISO).
    """
    if not dt_str:
        return None
    # Strip any brackets or trailing zones for simplification
    dt_clean = dt_str.strip().split(".")[0] # remove microsecond precision for easier parsing
    formats = [
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S UTC",
        "%Y-%m-%d %H:%M:%S+00:00",
    ]
    for fmt in formats:
        try:
            return datetime.strptime(dt_clean, fmt)
        except ValueError:
            continue
    try:
        # Try isoformat directly
        return datetime.fromisoformat(dt_clean)
    except ValueError:
        return None

def run_discrepancy_diff(processes: List[Dict[str, Any]], mft_records: List[Dict[str, Any]]) -> DiffingResult:
    """
    Cross-references active volatile memory processes against MFT records.
    Identifies process hollowing and rootkits by identifying:
    1. Memory processes running without a corresponding disk file (e.g., deleted or run-only-in-memory).
    2. Processes running whose memory start time is EARLIER than the disk file creation time (Process Hollowing / Time-stomping indicator).
    """
    discrepancies = []
    
    # 1. Parse inputs into typed schemas
    parsed_procs: List[ProcessInfo] = []
    for p in processes:
        try:
            # Handle key mappings since Volatility and jc may output different field casings
            pid = p.get("PID") or p.get("pid")
            ppid = p.get("PPID") or p.get("ppid") or 0
            name = p.get("ImageFileName") or p.get("name") or p.get("Image")
            path = p.get("path") or p.get("Path") or p.get("CmdLine") or p.get("cmdline")
            create_time = p.get("CreateTime") or p.get("create_time") or p.get("Created")
            exit_time = p.get("ExitTime") or p.get("exit_time")
            
            if pid is None or name is None:
                continue
                
            parsed_procs.append(ProcessInfo(
                pid=int(pid),
                ppid=int(ppid),
                name=str(name),
                path=str(path) if path else None,
                create_time=str(create_time) if create_time else None,
                exit_time=str(exit_time) if exit_time else None
            ))
        except Exception as e:
            logger.warning(f"Failed to parse process entry {p}: {e}")

    parsed_mft: List[MftRecord] = []
    for m in mft_records:
        try:
            # Plaso/log2timeline MFT records parsing
            filepath = m.get("filepath") or m.get("Filepath") or m.get("Path")
            # If the log2timeline CSV format is parsed, MFT message contains file name
            message = m.get("message") or ""
            if not filepath and "File:" in message:
                # Extract file path from Plaso message e.g. "File: C:\\Windows\\System32\\services.exe was created"
                parts = message.split("File:")
                if len(parts) > 1:
                    filepath = parts[1].split("was")[0].strip()
            
            datetime_str = m.get("datetime") or m.get("timestamp") or m.get("creation_time") or m.get("datetime")
            
            if not filepath or not datetime_str:
                continue
                
            parsed_mft.append(MftRecord(
                filepath=str(filepath),
                creation_time=str(datetime_str),
                is_deleted=bool(m.get("is_deleted", False))
            ))
        except Exception as e:
            logger.warning(f"Failed to parse MFT entry {m}: {e}")

    # Index MFT records by file name (lowercase) and path (lowercase) for fast lookup
    mft_by_name: Dict[str, List[MftRecord]] = {}
    mft_by_path: Dict[str, MftRecord] = {}
    
    for record in parsed_mft:
        norm_path = record.filepath.lower().replace("\\\\", "\\")
        mft_by_path[norm_path] = record
        
        basename = norm_path.split("\\")[-1].split("/")[-1]
        mft_by_name.setdefault(basename, []).append(record)

    # Exclusions for processes that are natively memory-only or system internal
    exempt_processes = {"system", "idle", "registry", "interrupts"}

    # 2. Diff processes against MFT records
    for proc in parsed_procs:
        proc_name_lower = proc.name.lower()
        if proc_name_lower in exempt_processes:
            continue
            
        # Match process to MFT records
        matching_records = mft_by_name.get(proc_name_lower, [])
        
        # If process path is specified, try exact path matching
        record_to_compare = None
        if proc.path:
            norm_proc_path = proc.path.lower().replace("\\\\", "\\")
            record_to_compare = mft_by_path.get(norm_proc_path)
            
        if not record_to_compare and matching_records:
            # Fall back to using the newest record or any matching record by name
            record_to_compare = matching_records[0]

        # Case 1: No MFT record found for this executable
        if not record_to_compare:
            discrepancies.append(DiscrepancyReport(
                pid=proc.pid,
                process_name=proc.name,
                mft_path=proc.path,
                finding=f"Process '{proc.name}' (PID {proc.pid}) is running in memory but has no corresponding MFT record on disk. Potential memory-only payload or rootkit.",
                severity="CRITICAL"
            ))
            continue

        # Case 2: MFT record exists, check start time vs creation time
        proc_time = parse_forensic_datetime(proc.create_time)
        mft_time = parse_forensic_datetime(record_to_compare.creation_time)
        
        if proc_time and mft_time:
            # Discrepancy: Process start time is EARLIER than disk creation time
            if proc_time < mft_time:
                # Calculate time difference
                diff_sec = (mft_time - proc_time).total_seconds()
                # Flag if difference is substantial (e.g. > 2 seconds to avoid slight clock skew/rounding issues)
                if diff_sec > 5:
                    discrepancies.append(DiscrepancyReport(
                        pid=proc.pid,
                        process_name=proc.name,
                        mft_path=record_to_compare.filepath,
                        finding=(
                            f"Process start time ({proc.create_time}) is earlier than its disk file creation time "
                            f"({record_to_compare.creation_time}) by {diff_sec} seconds. Potential Process Hollowing "
                            f"or binary replacement."
                        ),
                        severity="HIGH"
                    ))

    return DiffingResult(
        scanned_processes=len(parsed_procs),
        scanned_mft_records=len(parsed_mft),
        discrepancies=discrepancies
    )
