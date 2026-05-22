// Simulation State Database
const MOCK_STEPS_DATA = [
    {
        // Step 1: Collection on host0
        title: "Forensic Collection: host0",
        logs: [
            { type: "prompt", text: "aegis::agent# python3 -c \"from aegis.mcp_server import run_volatility\"" },
            { type: "cmd", text: "volatility -f nist_mem_compromise.raw windows.pslist" },
            { type: "warn", text: "[INTEGRITY] Executing SIFT binary via subprocess.run(shell=False) with strict array parameters." },
            { type: "info", text: "[JC NORMALIZATION] Normalizing volatility raw text output through Python jc 'table' parsing..." },
            { type: "success", text: "[CACHE] Processed 254 active memory processes. Cached to /cache/default_windows.pslist.json" },
            { type: "cmd", text: "log2timeline.py --status_view none /cache/default_timeline.plaso win10_c_drive.img" },
            { type: "warn", text: "[INTEGRITY] Executing Plaso/log2timeline via subprocess.run(shell=False)." },
            { type: "info", text: "[JC NORMALIZATION] Normalizing Plaso CSV outputs through jc 'csv' parser." },
            { type: "success", text: "[CACHE] Processed 425,122 MFT timeline events. Cached to /cache/default_mft.json" }
        ],
        anomalies: [],
        nodes: [
            { id: "host0", label: "host0 (P0)", x: 200, y: 150, status: "patient-zero" }
        ],
        edges: []
    },
    {
        // Step 2: Anomaly analysis on host0
        title: "Anomaly Analysis: host0",
        logs: [
            { type: "prompt", text: "aegis::agent# python3 -c \"from aegis.diffing import run_discrepancy_diff\"" },
            { type: "cmd", text: "analyze_discrepancies --session=default" },
            { type: "info", text: "[DETERMINISTIC DIFF] Cross-referencing Volatility memory processes against Plaso MFT records." },
            { type: "danger", text: "[ANOMALY] PID 120 (smss.exe): Running process lacks disk MFT record! (Memory-only rootkit payload)" },
            { type: "danger", text: "[ANOMALY] PID 524 (wininit.exe): Running process lacks disk MFT record! (Memory-only execution)" },
            { type: "danger", text: "[ANOMALY] PID 9999 (backdoor.exe): Running process lacks disk MFT record! (Deleted binary/Reflective load)" },
            { type: "prompt", text: "aegis::agent# cat /var/log/auth.csv" },
            { type: "info", text: "[BFS TRAVERSAL] Tracing successful lateral credentials logins from host0..." },
            { type: "success", text: "[LATERAL] Found RDP connection: host0 -> host1 (as admin)" },
            { type: "success", text: "[LATERAL] Found SMB connection: host0 -> host2 (as admin)" }
        ],
        anomalies: [
            { pid: 120, name: "smss.exe", severity: "CRITICAL", finding: "Process running in memory but has no corresponding MFT record on disk. Potential memory-only rootkit payload." },
            { pid: 524, name: "wininit.exe", severity: "CRITICAL", finding: "Process running in memory but has no corresponding MFT record on disk. Potential memory-only injection." },
            { pid: 9999, name: "backdoor.exe", severity: "CRITICAL", finding: "Process running in memory but has no corresponding MFT record on disk. Deleted executable run from reflective memory space." }
        ],
        nodes: [
            { id: "host0", label: "host0 (P0)", x: 200, y: 150, status: "patient-zero" },
            { id: "host1", label: "host1", x: 120, y: 260, status: "compromised" },
            { id: "host2", label: "host2", x: 280, y: 260, status: "compromised" }
        ],
        edges: [
            { from: "host0", to: "host1", status: "compromised-edge" },
            { from: "host0", to: "host2", status: "compromised-edge" }
        ]
    },
    {
        // Step 3: Collection on host1
        title: "Forensic Collection: host1",
        logs: [
            { type: "prompt", text: "aegis::agent# deploying remote forensic collector to host1..." },
            { type: "cmd", text: "volatility -f host1_mem.raw windows.pslist" },
            { type: "warn", text: "[INTEGRITY] Executing SIFT binary securely." },
            { type: "success", text: "[CACHE] Processed 189 active processes on host1. Cached locally." },
            { type: "cmd", text: "log2timeline.py --status_view none /cache/host1_mft.plaso host1_disk.img" },
            { type: "success", text: "[CACHE] Processed 312,987 MFT events on host1." }
        ],
        anomalies: [
            { pid: 120, name: "smss.exe", severity: "CRITICAL", finding: "Process running in memory but has no corresponding MFT record on disk. Potential memory-only rootkit payload." },
            { pid: 524, name: "wininit.exe", severity: "CRITICAL", finding: "Process running in memory but has no corresponding MFT record on disk. Potential memory-only injection." },
            { pid: 9999, name: "backdoor.exe", severity: "CRITICAL", finding: "Process running in memory but has no corresponding MFT record on disk. Deleted executable run from reflective memory space." }
        ],
        nodes: [
            { id: "host0", label: "host0 (P0)", x: 200, y: 150, status: "patient-zero" },
            { id: "host1", label: "host1", x: 120, y: 260, status: "analyzed" },
            { id: "host2", label: "host2", x: 280, y: 260, status: "compromised" }
        ],
        edges: [
            { from: "host0", to: "host1", status: "compromised-edge" },
            { from: "host0", to: "host2", status: "compromised-edge" }
        ]
    },
    {
        // Step 4: Anomaly analysis on host1
        title: "Anomaly Analysis: host1",
        logs: [
            { type: "cmd", text: "analyze_discrepancies --session=host1" },
            { type: "info", text: "[DETERMINISTIC DIFF] Cross-referencing Volatility memory processes on host1. All processes valid on disk." },
            { type: "info", text: "[BFS TRAVERSAL] Tracing logins from host1..." },
            { type: "success", text: "[LATERAL] Found SMB connection: host1 -> host3 (via credentials reuse)" },
            { type: "success", text: "[LATERAL] Found RDP connection: host1 -> host4 (via credentials reuse)" },
            { type: "success", text: "[LATERAL] Found WinRM connection: host1 -> host5 (via credentials reuse)" }
        ],
        anomalies: [
            { pid: 120, name: "smss.exe", severity: "CRITICAL", finding: "Process running in memory but has no corresponding MFT record on disk. Potential memory-only rootkit payload." },
            { pid: 524, name: "wininit.exe", severity: "CRITICAL", finding: "Process running in memory but has no corresponding MFT record on disk. Potential memory-only injection." },
            { pid: 9999, name: "backdoor.exe", severity: "CRITICAL", finding: "Process running in memory but has no corresponding MFT record on disk. Deleted executable run from reflective memory space." }
        ],
        nodes: [
            { id: "host0", label: "host0 (P0)", x: 200, y: 150, status: "patient-zero" },
            { id: "host1", label: "host1", x: 120, y: 260, status: "analyzed" },
            { id: "host2", label: "host2", x: 280, y: 260, status: "compromised" },
            { id: "host3", label: "host3", x: 50, y: 350, status: "compromised" },
            { id: "host4", label: "host4", x: 120, y: 370, status: "compromised" },
            { id: "host5", label: "host5", x: 190, y: 350, status: "compromised" }
        ],
        edges: [
            { from: "host0", to: "host1", status: "compromised-edge" },
            { from: "host0", to: "host2", status: "compromised-edge" },
            { from: "host1", to: "host3", status: "compromised-edge" },
            { from: "host1", to: "host4", status: "compromised-edge" },
            { from: "host1", to: "host5", status: "compromised-edge" }
        ]
    },
    {
        // Step 5: Collection on host2
        title: "Forensic Collection: host2",
        logs: [
            { type: "prompt", text: "aegis::agent# deploying remote forensic collector to host2..." },
            { type: "cmd", text: "volatility -f host2_mem.raw windows.pslist" },
            { type: "success", text: "[CACHE] Processed 195 active processes on host2. Cached locally." },
            { type: "cmd", text: "log2timeline.py --status_view none /cache/host2_mft.plaso host2_disk.img" },
            { type: "success", text: "[CACHE] Processed 294,845 MFT events on host2." }
        ],
        anomalies: [
            { pid: 120, name: "smss.exe", severity: "CRITICAL", finding: "Process running in memory but has no corresponding MFT record on disk. Potential memory-only rootkit payload." },
            { pid: 524, name: "wininit.exe", severity: "CRITICAL", finding: "Process running in memory but has no corresponding MFT record on disk. Potential memory-only injection." },
            { pid: 9999, name: "backdoor.exe", severity: "CRITICAL", finding: "Process running in memory but has no corresponding MFT record on disk. Deleted executable run from reflective memory space." }
        ],
        nodes: [
            { id: "host0", label: "host0 (P0)", x: 200, y: 150, status: "patient-zero" },
            { id: "host1", label: "host1", x: 120, y: 260, status: "analyzed" },
            { id: "host2", label: "host2", x: 280, y: 260, status: "analyzed" },
            { id: "host3", label: "host3", x: 50, y: 350, status: "compromised" },
            { id: "host4", label: "host4", x: 120, y: 370, status: "compromised" },
            { id: "host5", label: "host5", x: 190, y: 350, status: "compromised" }
        ],
        edges: [
            { from: "host0", to: "host1", status: "compromised-edge" },
            { from: "host0", to: "host2", status: "compromised-edge" },
            { from: "host1", to: "host3", status: "compromised-edge" },
            { from: "host1", to: "host4", status: "compromised-edge" },
            { from: "host1", to: "host5", status: "compromised-edge" }
        ]
    },
    {
        // Step 6: Anomaly analysis on host2 -> Hits Circuit Breaker!
        title: "TTL Circuit Breaker Triggered",
        logs: [
            { type: "cmd", text: "analyze_discrepancies --session=host2" },
            { type: "info", text: "[BFS TRAVERSAL] Tracing logins from host2..." },
            { type: "success", text: "[LATERAL] Found WinRM connection: host2 -> host6" },
            { type: "success", text: "[LATERAL] Found RDP connection: host2 -> host7" },
            { type: "danger", text: "[CIRCUIT BREAKER] steps count = 6, exceeding maximum loop limit MAX_STEPS = 5!" },
            { type: "danger", text: "[CIRCUIT BREAKER] WARNING: Multi-agent infinite analysis loop detected (unscanned targets: host3, host4, host5, host6, host7)." },
            { type: "danger", text: "[CIRCUIT BREAKER] Halting execution immediately. Routing state flow to compile_report terminal node." }
        ],
        anomalies: [
            { pid: 120, name: "smss.exe", severity: "CRITICAL", finding: "Process running in memory but has no corresponding MFT record on disk. Potential memory-only rootkit payload." },
            { pid: 524, name: "wininit.exe", severity: "CRITICAL", finding: "Process running in memory but has no corresponding MFT record on disk. Potential memory-only injection." },
            { pid: 9999, name: "backdoor.exe", severity: "CRITICAL", finding: "Process running in memory but has no corresponding MFT record on disk. Deleted executable run from reflective memory space." }
        ],
        nodes: [
            { id: "host0", label: "host0 (P0)", x: 200, y: 150, status: "patient-zero" },
            { id: "host1", label: "host1", x: 120, y: 260, status: "analyzed" },
            { id: "host2", label: "host2", x: 280, y: 260, status: "analyzed" },
            { id: "host3", label: "host3", x: 50, y: 350, status: "compromised" },
            { id: "host4", label: "host4", x: 120, y: 370, status: "compromised" },
            { id: "host5", label: "host5", x: 190, y: 350, status: "compromised" },
            { id: "host6", label: "host6", x: 250, y: 350, status: "compromised" },
            { id: "host7", label: "host7", x: 330, y: 350, status: "compromised" }
        ],
        edges: [
            { from: "host0", to: "host1", status: "compromised-edge" },
            { from: "host0", to: "host2", status: "compromised-edge" },
            { from: "host1", to: "host3", status: "compromised-edge" },
            { from: "host1", to: "host4", status: "compromised-edge" },
            { from: "host1", to: "host5", status: "compromised-edge" },
            { from: "host2", to: "host6", status: "compromised-edge" },
            { from: "host2", to: "host7", status: "compromised-edge" }
        ]
    }
];

const EXECUTIVE_REPORT_MD = `
# PROJECT AEGIS EXECUTIVE DFIR REPORT
=====================================
Session ID: aegis_session_sans_2026
Total Steps Taken: 6
Orchestrator Mode: LANGGRAPH STATE MACHINE

## 1. DETERMINISTIC DISCREPANCY ANALYSIS
----------------------------------------
Target host0: Scanned and compared active memory processes (254) against MFT disk timeline entries (425,122).
Identified 3 CRITICAL process discrepancies:

  1. [CRITICAL] PID 120 (smss.exe):
     Finding: Process running in memory but has no corresponding MFT record on disk. Potential memory-only rootkit payload.
  
  2. [CRITICAL] PID 524 (wininit.exe):
     Finding: Process running in memory but has no corresponding MFT record on disk. Potential memory-only payload injection.
  
  3. [CRITICAL] PID 9999 (backdoor.exe):
     Finding: Process running in memory but has no corresponding MFT record on disk. Deleted executable run from reflective memory space.

## 2. LATERAL MOVEMENT BLAST RADIUS MAP (BFS FLOOD-FILL)
--------------------------------------------------------
Patient Zero: host0 (192.168.1.50)
Total Compromised Endpoints: 8
Compromised Host List: host0, host1, host2, host3, host4, host5, host6, host7

### Traversal Propagation Hops:
  - host0 -> host1 (RDP as admin at 2026-05-22 12:00:00)
  - host0 -> host2 (SMB as admin at 2026-05-22 12:05:00)
  - host1 -> host3 (SMB as admin at 2026-05-22 12:20:00)
  - host1 -> host4 (RDP as admin at 2026-05-22 12:25:00)
  - host1 -> host5 (WinRM as admin at 2026-05-22 12:30:00)
  - host2 -> host6 (WinRM as admin at 2026-05-22 12:45:00)
  - host2 -> host7 (RDP as admin at 2026-05-22 12:50:00)

> [!WARNING]
> Aegis execution was stopped by the Time-To-Live (TTL) Circuit Breaker to prevent an infinite analysis loop. 
> There were still 5 unanalyzed compromised hosts (host3, host4, host5, host6, host7) in the queue. 
> Final report compilation forced.
`;

// DOM Elements
const runBtn = document.getElementById("run-btn");
const stepBtn = document.getElementById("step-btn");
const resetBtn = document.getElementById("reset-btn");
const stepCounter = document.getElementById("step-counter");
const cbMeter = document.getElementById("cb-meter");
const cbStatus = document.getElementById("cb-status");
const compCount = document.getElementById("comp-count");
const anomalyRows = document.getElementById("anomaly-rows");
const terminalLog = document.getElementById("terminal-log");
const svgCanvas = document.getElementById("graph-svg");
const reportModal = document.getElementById("report-modal");
const modalReportText = document.getElementById("modal-report-text");
const closeModal = document.getElementById("close-modal");

// State variables
let currentStep = -1;
let autoSimulationInterval = null;

// Initialize SVG Graph dimensions
function getCanvasSize() {
    return {
        width: svgCanvas.clientWidth || 400,
        height: svgCanvas.clientHeight || 300
    };
}

// Render Graph using SVG
function renderGraph(nodes, edges) {
    // Clear canvas
    svgCanvas.innerHTML = "";
    
    // Create markers for arrows
    const defs = document.createElementNS("http://www.w3.org/2000/svg", "defs");
    const marker = document.createElementNS("http://www.w3.org/2000/svg", "marker");
    marker.setAttribute("id", "arrow");
    marker.setAttribute("viewBox", "0 0 10 10");
    marker.setAttribute("refX", "22");
    marker.setAttribute("refY", "5");
    marker.setAttribute("markerWidth", "6");
    marker.setAttribute("markerHeight", "6");
    marker.setAttribute("orient", "auto-start-reverse");
    
    const path = document.createElementNS("http://www.w3.org/2000/svg", "path");
    path.setAttribute("d", "M 0 0 L 10 5 L 0 10 z");
    path.setAttribute("fill", "rgba(0, 240, 255, 0.4)");
    marker.appendChild(path);
    defs.appendChild(marker);
    svgCanvas.appendChild(defs);

    // Render edges
    edges.forEach(edge => {
        const fromNode = nodes.find(n => n.id === edge.from);
        const toNode = nodes.find(n => n.id === edge.to);
        if (fromNode && toNode) {
            const line = document.createElementNS("http://www.w3.org/2000/svg", "line");
            line.setAttribute("x1", fromNode.x);
            line.setAttribute("y1", fromNode.y);
            line.setAttribute("x2", toNode.x);
            line.setAttribute("y2", toNode.y);
            line.setAttribute("class", `link ${edge.status}`);
            line.setAttribute("marker-end", "url(#arrow)");
            svgCanvas.appendChild(line);
        }
    });

    // Render nodes
    nodes.forEach(node => {
        const group = document.createElementNS("http://www.w3.org/2000/svg", "g");
        group.setAttribute("class", `node ${node.status}`);
        
        const circle = document.createElementNS("http://www.w3.org/2000/svg", "circle");
        circle.setAttribute("cx", node.x);
        circle.setAttribute("cy", node.y);
        circle.setAttribute("r", "16");
        
        // Dynamic node glowing colors
        if (node.status === "patient-zero") {
            circle.setAttribute("filter", "drop-shadow(0 0 6px var(--danger))");
        } else if (node.status === "compromised") {
            circle.setAttribute("filter", "drop-shadow(0 0 5px var(--warning))");
        } else if (node.status === "analyzed") {
            circle.setAttribute("filter", "drop-shadow(0 0 5px var(--success))");
        }

        const text = document.createElementNS("http://www.w3.org/2000/svg", "text");
        text.setAttribute("x", node.x);
        text.setAttribute("y", node.y + 4);
        text.textContent = node.id;
        
        group.appendChild(circle);
        group.appendChild(text);
        
        // Node hover metadata tooltip (simulated)
        group.addEventListener("click", () => {
            appendTerminalLine("info", `Click on node: Querying forensic state for ${node.id}`);
            if (node.status === "analyzed") {
                appendTerminalLine("success", `State: Collected & Duffed. Memory-MFT discrepancy checks clean.`);
            } else if (node.status === "compromised") {
                appendTerminalLine("warning", `State: Compromised via credentials. Memory dump analysis queued.`);
            } else if (node.status === "patient-zero") {
                appendTerminalLine("danger", `State: Primary exploit endpoint (Patient Zero). 3 critical anomalies detected.`);
            }
        });

        svgCanvas.appendChild(group);
    });
}

// Append line to terminal
function appendTerminalLine(type, text) {
    const line = document.createElement("div");
    line.className = "term-line";
    
    if (type === "prompt") {
        line.innerHTML = `<span class="term-prompt">aegis::agent#</span><span class="term-cmd">${text}</span>`;
    } else {
        let colorClass = "term-out";
        if (type === "warn") colorClass = "term-warning";
        if (type === "danger") colorClass = "term-danger";
        if (type === "success") colorClass = "term-success";
        
        line.innerHTML = `<span class="${colorClass}">${text}</span>`;
    }
    
    terminalLog.appendChild(line);
    terminalLog.scrollTop = terminalLog.scrollHeight;
}

// Update Anomaly Table
function updateAnomalyTable(anomalies) {
    if (anomalies.length === 0) {
        anomalyRows.innerHTML = `
            <tr>
                <td colspan="4" style="text-align: center; color: var(--text-muted); padding: 2rem;">No process discrepancies detected on current targets.</td>
            </tr>
        `;
        return;
    }
    
    anomalyRows.innerHTML = anomalies.map(a => `
        <tr>
            <td style="font-family: 'JetBrains Mono', monospace; color: var(--primary);">${a.pid}</td>
            <td style="font-weight: 600; color: var(--text-highlight);">${a.name}</td>
            <td><span class="badge badge-critical">${a.severity}</span></td>
            <td style="font-size: 0.8rem; color: var(--text-main);">${a.finding}</td>
        </tr>
    `).join("");
}

// Perform a single step of the simulation
function executeSimulationStep() {
    if (currentStep >= MOCK_STEPS_DATA.length - 1) {
        // Simulation finished, circuit breaker triggered
        showExecutiveReport();
        clearInterval(autoSimulationInterval);
        return;
    }

    currentStep++;
    const stepData = MOCK_STEPS_DATA[currentStep];

    // 1. Write terminal outputs
    stepData.logs.forEach(log => {
        appendTerminalLine(log.type, log.text);
    });

    // 2. Update Discrepancy Table
    updateAnomalyTable(stepData.anomalies);

    // 3. Render BFS SVG Graph
    renderGraph(stepData.nodes, stepData.edges);

    // 4. Update HUD counters
    const stepVal = currentStep + 1;
    stepCounter.textContent = `${stepVal} / 5`;
    compCount.textContent = stepData.nodes.filter(n => n.status !== "analyzed").length + stepData.nodes.filter(n => n.status === "analyzed").length;
    
    // Update meter bar percentage
    const percent = Math.min((stepVal / 5) * 100, 100);
    cbMeter.style.width = `${percent}%`;

    // Visual changes if hitting the limit
    if (stepVal >= 5) {
        cbMeter.className = "hud-meter-bar danger";
        cbStatus.textContent = "HALTED";
        cbStatus.style.color = "var(--danger)";
        cbStatus.style.background = "var(--danger-glow)";
        document.getElementById("system-status").className = "status-badge";
        document.getElementById("system-status").style.borderColor = "var(--danger)";
        document.getElementById("system-status").style.color = "var(--danger)";
        document.getElementById("system-status").style.boxShadow = "0 0 10px var(--danger-glow)";
        document.getElementById("status-text").textContent = "SIFT Workstation: Circuit Broken";
    } else {
        cbMeter.className = "hud-meter-bar";
        cbStatus.textContent = "ACTIVE";
        cbStatus.style.color = "var(--success)";
        cbStatus.style.background = "var(--success-glow)";
        document.getElementById("system-status").className = "status-badge";
        document.getElementById("system-status").style.borderColor = "var(--success)";
        document.getElementById("system-status").style.color = "var(--success)";
        document.getElementById("system-status").style.boxShadow = "0 0 10px var(--success-glow)";
        document.getElementById("status-text").textContent = "SIFT Workstation: Connected";
    }
}

// Show final MD report in Modal
function showExecutiveReport() {
    modalReportText.textContent = EXECUTIVE_REPORT_MD;
    reportModal.classList.add("active");
}

// Reset Simulation
function resetSimulation() {
    currentStep = -1;
    clearInterval(autoSimulationInterval);
    terminalLog.innerHTML = `
        <div class="term-line">
            <span class="term-prompt">aegis::root#</span>
            <span class="term-cmd">systemctl status aegis-mcp-server</span>
        </div>
        <div class="term-line">
            <span class="term-out term-success">Aegis Model Context Protocol Server active and listening on port 8000.</span>
        </div>
        <div class="term-line">
            <span class="term-prompt">aegis::root#</span>
            <span class="term-cmd">_</span>
        </div>
    `;
    updateAnomalyTable([]);
    renderGraph([], []);
    stepCounter.textContent = "0 / 5";
    compCount.textContent = "1";
    cbMeter.style.width = "0%";
    cbMeter.className = "hud-meter-bar";
    cbStatus.textContent = "ACTIVE";
    cbStatus.style.color = "var(--success)";
    cbStatus.style.background = "var(--success-glow)";
    
    document.getElementById("system-status").className = "status-badge";
    document.getElementById("system-status").removeAttribute("style");
    document.getElementById("status-text").textContent = "SIFT Workstation: Connected";
}

// Event Listeners
runBtn.addEventListener("click", () => {
    resetSimulation();
    appendTerminalLine("prompt", "deploy_aegis_agent --patient-zero=host0 --ttl=5");
    appendTerminalLine("info", "Starting autonomous incident response graph workflow...");
    
    // Run step-by-step automatically every 2.5s
    executeSimulationStep();
    autoSimulationInterval = setInterval(executeSimulationStep, 2500);
});

stepBtn.addEventListener("click", () => {
    clearInterval(autoSimulationInterval);
    if (currentStep === -1) {
        appendTerminalLine("prompt", "deploy_aegis_agent --step-by-step");
    }
    executeSimulationStep();
});

resetBtn.addEventListener("click", resetSimulation);

closeModal.addEventListener("click", () => {
    reportModal.classList.remove("active");
});

window.addEventListener("click", (e) => {
    if (e.target === reportModal) {
        reportModal.classList.remove("active");
    }
});

// Initial layout rendering (blank graph)
window.addEventListener("resize", () => {
    if (currentStep >= 0) {
        const stepData = MOCK_STEPS_DATA[currentStep];
        renderGraph(stepData.nodes, stepData.edges);
    }
});
