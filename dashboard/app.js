// Project Aegis Dashboard Core Simulation Engine
const MAX_STEPS = 5;

// Compact Simulation Database
const MOCK_STEPS_DATA = [
    {
        title: "Forensic Collection: host0",
        logs: [
            { type: "prompt", text: "deploy_aegis_agent --patient-zero=host0 --ttl=5" },
            { type: "warn", text: "[INTEGRITY] Executing SIFT volatility binary via subprocess.run(shell=False) with strict array parameters." },
            { type: "info", text: "[JC NORMALIZATION] Normalizing raw text output through Python jc table parser..." },
            { type: "success", text: "[CACHE] Processed 254 active memory processes. Cached to /cache/default_windows.pslist.json" },
            { type: "warn", text: "[INTEGRITY] Executing SIFT log2timeline binary via subprocess.run(shell=False)." },
            { type: "info", text: "[JC NORMALIZATION] Normalizing Plaso CSV timeline outputs..." },
            { type: "success", text: "[CACHE] Processed 425,122 MFT timeline events. Cached to /cache/default_mft.json" }
        ],
        anomalies: [],
        nodes: [{ id: "host0", label: "host0 (P0)", x: 200, y: 110, status: "patient-zero" }],
        edges: []
    },
    {
        title: "Anomaly Analysis: host0",
        logs: [
            { type: "prompt", text: "analyze_discrepancies --session=default" },
            { type: "info", text: "[DETERMINISTIC DIFF] Cross-referencing memory processes against disk MFT records..." },
            { type: "danger", text: "[ANOMALY] PID 120 (smss.exe): Running process lacks disk MFT record! (Potential memory-only rootkit)" },
            { type: "danger", text: "[ANOMALY] PID 524 (wininit.exe): Running process lacks disk MFT record!" },
            { type: "danger", text: "[ANOMALY] PID 9999 (backdoor.exe): Running process lacks disk MFT record!" },
            { type: "info", text: "[BFS TRAVERSAL] Tracing successful lateral credentials logins from host0..." },
            { type: "success", text: "[LATERAL] Found RDP connection: host0 -> host1 (as admin)" },
            { type: "success", text: "[LATERAL] Found SMB connection: host0 -> host2 (as admin)" }
        ],
        anomalies: [
            { pid: 120, name: "smss.exe", severity: "CRITICAL", finding: "Process running in memory but has no corresponding MFT record on disk. Potential memory-only rootkit payload." },
            { pid: 524, name: "wininit.exe", severity: "CRITICAL", finding: "Process running in memory but has no corresponding MFT record on disk. Potential memory-only injection." },
            { pid: 9999, name: "backdoor.exe", severity: "CRITICAL", finding: "Process running in memory but has no corresponding MFT record on disk. Reflective DLL injection." }
        ],
        nodes: [
            { id: "host0", label: "host0 (P0)", x: 200, y: 110, status: "patient-zero" },
            { id: "host1", label: "host1", x: 100, y: 180, status: "compromised" },
            { id: "host2", label: "host2", x: 300, y: 180, status: "compromised" }
        ],
        edges: [
            { from: "host0", to: "host1", status: "compromised-edge" },
            { from: "host0", to: "host2", status: "compromised-edge" }
        ]
    },
    {
        title: "Forensic Collection: host1",
        logs: [
            { type: "prompt", text: "deploy_collector --target=host1" },
            { type: "info", text: "Deploying remote forensic collector to host1..." },
            { type: "success", text: "[CACHE] Processed 189 active processes on host1." },
            { type: "success", text: "[CACHE] Processed 312,987 MFT events on host1." }
        ],
        anomalies: [
            { pid: 120, name: "smss.exe", severity: "CRITICAL", finding: "Process running in memory but has no corresponding MFT record on disk. Potential memory-only rootkit payload." },
            { pid: 524, name: "wininit.exe", severity: "CRITICAL", finding: "Process running in memory but has no corresponding MFT record on disk. Potential memory-only injection." },
            { pid: 9999, name: "backdoor.exe", severity: "CRITICAL", finding: "Process running in memory but has no corresponding MFT record on disk. Reflective DLL injection." }
        ],
        nodes: [
            { id: "host0", label: "host0 (P0)", x: 200, y: 110, status: "patient-zero" },
            { id: "host1", label: "host1", x: 100, y: 180, status: "analyzed" },
            { id: "host2", label: "host2", x: 300, y: 180, status: "compromised" }
        ],
        edges: [
            { from: "host0", to: "host1", status: "compromised-edge" },
            { from: "host0", to: "host2", status: "compromised-edge" }
        ]
    },
    {
        title: "Anomaly Analysis: host1",
        logs: [
            { type: "prompt", text: "analyze_discrepancies --session=host1" },
            { type: "info", text: "[DETERMINISTIC DIFF] Cross-referencing Volatility memory processes on host1. All processes valid on disk." },
            { type: "info", text: "[BFS TRAVERSAL] Tracing logins from host1..." },
            { type: "success", text: "[LATERAL] Found SMB connection: host1 -> host3" },
            { type: "success", text: "[LATERAL] Found RDP connection: host1 -> host4" },
            { type: "success", text: "[LATERAL] Found WinRM connection: host1 -> host5" }
        ],
        anomalies: [
            { pid: 120, name: "smss.exe", severity: "CRITICAL", finding: "Process running in memory but has no corresponding MFT record on disk. Potential memory-only rootkit payload." },
            { pid: 524, name: "wininit.exe", severity: "CRITICAL", finding: "Process running in memory but has no corresponding MFT record on disk. Potential memory-only injection." },
            { pid: 9999, name: "backdoor.exe", severity: "CRITICAL", finding: "Process running in memory but has no corresponding MFT record on disk. Reflective DLL injection." }
        ],
        nodes: [
            { id: "host0", label: "host0 (P0)", x: 200, y: 110, status: "patient-zero" },
            { id: "host1", label: "host1", x: 100, y: 180, status: "analyzed" },
            { id: "host2", label: "host2", x: 300, y: 180, status: "compromised" },
            { id: "host3", label: "host3", x: 40, y: 250, status: "compromised" },
            { id: "host4", label: "host4", x: 100, y: 260, status: "compromised" },
            { id: "host5", label: "host5", x: 160, y: 250, status: "compromised" }
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
        title: "Forensic Collection: host2",
        logs: [
            { type: "prompt", text: "deploy_collector --target=host2" },
            { type: "success", text: "[CACHE] Processed 195 active processes on host2." },
            { type: "success", text: "[CACHE] Processed 294,845 MFT events on host2." }
        ],
        anomalies: [
            { pid: 120, name: "smss.exe", severity: "CRITICAL", finding: "Process running in memory but has no corresponding MFT record on disk. Potential memory-only rootkit payload." },
            { pid: 524, name: "wininit.exe", severity: "CRITICAL", finding: "Process running in memory but has no corresponding MFT record on disk. Potential memory-only injection." },
            { pid: 9999, name: "backdoor.exe", severity: "CRITICAL", finding: "Process running in memory but has no corresponding MFT record on disk. Reflective DLL injection." }
        ],
        nodes: [
            { id: "host0", label: "host0 (P0)", x: 200, y: 110, status: "patient-zero" },
            { id: "host1", label: "host1", x: 100, y: 180, status: "analyzed" },
            { id: "host2", label: "host2", x: 300, y: 180, status: "analyzed" },
            { id: "host3", label: "host3", x: 40, y: 250, status: "compromised" },
            { id: "host4", label: "host4", x: 100, y: 260, status: "compromised" },
            { id: "host5", label: "host5", x: 160, y: 250, status: "compromised" }
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
        title: "TTL Circuit Breaker Triggered",
        logs: [
            { type: "prompt", text: "analyze_discrepancies --session=host2" },
            { type: "info", text: "[BFS TRAVERSAL] Tracing logins from host2..." },
            { type: "success", text: "[LATERAL] Found WinRM connection: host2 -> host6" },
            { type: "success", text: "[LATERAL] Found RDP connection: host2 -> host7" },
            { type: "danger", text: "[CIRCUIT BREAKER] Step count = 6, exceeding maximum loop limit MAX_STEPS = 5!" },
            { type: "danger", text: "[CIRCUIT BREAKER] WARNING: Multi-agent loop detected. Unscanned targets remaining." },
            { type: "danger", text: "[CIRCUIT BREAKER] Halting execution immediately. Generating final report." }
        ],
        anomalies: [
            { pid: 120, name: "smss.exe", severity: "CRITICAL", finding: "Process running in memory but has no corresponding MFT record on disk. Potential memory-only rootkit payload." },
            { pid: 524, name: "wininit.exe", severity: "CRITICAL", finding: "Process running in memory but has no corresponding MFT record on disk. Potential memory-only injection." },
            { pid: 9999, name: "backdoor.exe", severity: "CRITICAL", finding: "Process running in memory but has no corresponding MFT record on disk. Reflective DLL injection." }
        ],
        nodes: [
            { id: "host0", label: "host0 (P0)", x: 200, y: 110, status: "patient-zero" },
            { id: "host1", label: "host1", x: 100, y: 180, status: "analyzed" },
            { id: "host2", label: "host2", x: 300, y: 180, status: "analyzed" },
            { id: "host3", label: "host3", x: 40, y: 250, status: "compromised" },
            { id: "host4", label: "host4", x: 100, y: 260, status: "compromised" },
            { id: "host5", label: "host5", x: 160, y: 250, status: "compromised" },
            { id: "host6", label: "host6", x: 240, y: 250, status: "compromised" },
            { id: "host7", label: "host7", x: 300, y: 260, status: "compromised" }
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

const EXECUTIVE_REPORT_MD = `# PROJECT AEGIS EXECUTIVE DFIR REPORT
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
     Finding: Process running in memory but has no corresponding MFT record on disk. Reflective DLL injection.

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
> Final report compilation forced.`;

// DOM Selectors
const runBtn = document.getElementById("run-btn");
const stepBtn = document.getElementById("step-btn");
const resetBtn = document.getElementById("reset-btn");
const stepCounter = document.getElementById("step-counter");
const cbMeter = document.getElementById("cb-meter");
const cbStatus = document.getElementById("cb-status");
const compCount = document.getElementById("comp-count");
const analyzedCount = document.getElementById("analyzed-count");
const anomalyCount = document.getElementById("anomaly-count");
const anomalyRows = document.getElementById("anomaly-rows");
const terminalLog = document.getElementById("terminal-log");
const cursorSpan = document.getElementById("cursor-span");
const terminalCursorLine = document.getElementById("terminal-cursor-line");
const svgCanvas = document.getElementById("graph-svg");
const reportModal = document.getElementById("report-modal");
const modalReportText = document.getElementById("modal-report-text");
const closeModal = document.getElementById("close-modal");
const tooltip = document.getElementById("node-tooltip");
const ttHost = document.getElementById("tt-host");
const ttState = document.getElementById("tt-state");

let currentStep = -1;
let autoSimulationInterval = null;

// Dynamic SVG scaling helper
function getScaledCoords(x, y) {
    const w = svgCanvas.clientWidth || 400;
    const h = svgCanvas.clientHeight || 300;
    // Base design coords: w=400, h=300
    return {
        x: (x / 400) * w,
        y: (y / 300) * h
    };
}

function renderGraph(nodes, edges) {
    svgCanvas.innerHTML = "";
    if (nodes.length === 0) {
        const text = document.createElementNS("http://www.w3.org/2000/svg", "text");
        text.setAttribute("x", "50%");
        text.setAttribute("y", "50%");
        text.setAttribute("class", "svg-empty-text");
        text.textContent = "Deploy Aegis agent to map lateral propagation.";
        svgCanvas.appendChild(text);
        return;
    }

    const defs = document.createElementNS("http://www.w3.org/2000/svg", "defs");
    const marker = document.createElementNS("http://www.w3.org/2000/svg", "marker");
    marker.setAttribute("id", "arrow");
    marker.setAttribute("viewBox", "0 0 10 10");
    marker.setAttribute("refX", "22");
    marker.setAttribute("refY", "5");
    marker.setAttribute("markerWidth", "5");
    marker.setAttribute("markerHeight", "5");
    marker.setAttribute("orient", "auto-start-reverse");
    
    const markerPath = document.createElementNS("http://www.w3.org/2000/svg", "path");
    markerPath.setAttribute("d", "M 0 0 L 10 5 L 0 10 z");
    markerPath.setAttribute("fill", "rgba(0, 240, 255, 0.4)");
    marker.appendChild(markerPath);
    defs.appendChild(marker);
    svgCanvas.appendChild(defs);

    // Scaled coords map
    const coords = {};
    nodes.forEach(n => {
        coords[n.id] = getScaledCoords(n.x, n.y);
    });

    edges.forEach(edge => {
        const from = coords[edge.from];
        const to = coords[edge.to];
        if (from && to) {
            const line = document.createElementNS("http://www.w3.org/2000/svg", "line");
            line.setAttribute("x1", from.x);
            line.setAttribute("y1", from.y);
            line.setAttribute("x2", to.x);
            line.setAttribute("y2", to.y);
            line.setAttribute("class", `link ${edge.status}`);
            line.setAttribute("marker-end", "url(#arrow)");
            svgCanvas.appendChild(line);
        }
    });

    nodes.forEach(node => {
        const c = coords[node.id];
        const group = document.createElementNS("http://www.w3.org/2000/svg", "g");
        group.setAttribute("class", `node ${node.status}`);

        const circle = document.createElementNS("http://www.w3.org/2000/svg", "circle");
        circle.setAttribute("cx", c.x);
        circle.setAttribute("cy", c.y);
        circle.setAttribute("r", "15");

        const text = document.createElementNS("http://www.w3.org/2000/svg", "text");
        text.setAttribute("x", c.x);
        text.setAttribute("y", c.y + 4);
        text.textContent = node.id;

        group.appendChild(circle);
        group.appendChild(text);

        // Tooltip hover handlers
        group.addEventListener("mousemove", (e) => {
            tooltip.style.left = `${e.clientX + 15}px`;
            tooltip.style.top = `${e.clientY + 15}px`;
        });

        group.addEventListener("mouseenter", () => {
            ttHost.textContent = `Host: ${node.id}`;
            let statusText = "COMPROMISED";
            let statusClass = "warn";
            if (node.status === "patient-zero") {
                statusText = "PATIENT ZERO (BREACHED)";
                statusClass = "crit";
            } else if (node.status === "analyzed") {
                statusText = "COLLECTED & CLEAN";
                statusClass = "ok";
            }
            ttState.innerHTML = `Status: <span class="${statusClass}">${statusText}</span>`;
            tooltip.classList.add("visible");
        });

        group.addEventListener("mouseleave", () => {
            tooltip.classList.remove("visible");
        });

        group.addEventListener("click", () => {
            appendTerminalLine("prompt", `query_host_state --host=${node.id}`);
            if (node.status === "analyzed") {
                appendTerminalLine("success", `[STATE] ${node.id} analyzed successfully. Diffing checks verified.`);
            } else if (node.status === "patient-zero") {
                appendTerminalLine("danger", `[STATE] ${node.id} is Patient Zero. Exploited starting 2026-05-22 12:00:00.`);
            } else {
                appendTerminalLine("warning", `[STATE] ${node.id} compromised laterally. Forensic collection pending.`);
            }
        });

        svgCanvas.appendChild(group);
    });
}

function appendTerminalLine(type, text) {
    const line = document.createElement("div");
    line.className = "term-line";

    const secureText = document.createTextNode(text);
    
    if (type === "prompt") {
        const promptSpan = document.createElement("span");
        promptSpan.className = "term-prompt";
        promptSpan.textContent = "aegis::agent# ";
        const cmdSpan = document.createElement("span");
        cmdSpan.className = "term-cmd";
        cmdSpan.appendChild(secureText);
        line.appendChild(promptSpan);
        line.appendChild(cmdSpan);
    } else {
        const span = document.createElement("span");
        let cls = "term-out";
        if (type === "warn") cls = "term-warning";
        if (type === "danger") cls = "term-danger";
        if (type === "success") cls = "term-success";
        if (type === "info") cls = "term-info";
        span.className = cls;
        span.appendChild(secureText);
        line.appendChild(span);
    }

    terminalLog.insertBefore(line, terminalCursorLine);
    terminalLog.scrollTop = terminalLog.scrollHeight;
}

function updateAnomalyTable(anomalies) {
    const emptyRow = document.getElementById("anomaly-empty-row");
    if (anomalies.length === 0) {
        if (emptyRow) emptyRow.style.display = "table-row";
        anomalyRows.querySelectorAll("tr:not(#anomaly-empty-row)").forEach(tr => tr.remove());
        anomalyCount.textContent = "0 findings";
        return;
    }

    if (emptyRow) emptyRow.style.display = "none";
    
    // Clear old rows
    anomalyRows.querySelectorAll("tr:not(#anomaly-empty-row)").forEach(tr => tr.remove());

    anomalies.forEach(a => {
        const tr = document.createElement("tr");
        
        const tdPid = document.createElement("td");
        tdPid.style.fontFamily = "'JetBrains Mono', monospace";
        tdPid.style.color = "var(--primary)";
        tdPid.textContent = a.pid;
        
        const tdName = document.createElement("td");
        tdName.style.fontWeight = "600";
        tdName.style.color = "var(--text-highlight)";
        tdName.textContent = a.name;

        const tdSev = document.createElement("td");
        const badge = document.createElement("span");
        badge.className = "badge badge-critical";
        badge.textContent = a.severity;
        tdSev.appendChild(badge);

        const tdFind = document.createElement("td");
        tdFind.style.fontSize = "0.78rem";
        tdFind.textContent = a.finding;

        tr.appendChild(tdPid);
        tr.appendChild(tdName);
        tr.appendChild(tdSev);
        tr.appendChild(tdFind);
        
        anomalyRows.appendChild(tr);
    });

    anomalyCount.textContent = `${anomalies.length} findings`;
}

function updateProgressPips(stepVal) {
    document.querySelectorAll(".step-pip").forEach((pip, idx) => {
        pip.className = "step-pip";
        if (idx < stepVal) {
            pip.classList.add("done");
        }
        if (idx === stepVal) {
            pip.classList.add("active");
            if (stepVal >= 5) {
                pip.className = "step-pip breached";
            }
        }
    });
}

function executeSimulationStep() {
    if (currentStep >= MOCK_STEPS_DATA.length - 1) {
        showExecutiveReport();
        stopSimulation();
        return;
    }

    currentStep++;
    const stepData = MOCK_STEPS_DATA[currentStep];

    stepData.logs.forEach(log => {
        appendTerminalLine(log.type, log.text);
    });

    updateAnomalyTable(stepData.anomalies);
    renderGraph(stepData.nodes, stepData.edges);

    const stepVal = currentStep + 1;
    stepCounter.textContent = `${stepVal} / 5`;
    
    // Update headers and pips
    const totalComp = stepData.nodes.filter(n => n.status === "compromised" || n.status === "patient-zero").length;
    const totalAnal = stepData.nodes.filter(n => n.status === "analyzed").length;
    compCount.textContent = totalComp;
    analyzedCount.textContent = totalAnal;

    updateProgressPips(currentStep);

    const percent = Math.min((stepVal / 5) * 100, 100);
    cbMeter.style.width = `${percent}%`;

    if (stepVal >= 5) {
        cbMeter.className = "hud-meter-bar danger";
        cbStatus.textContent = "HALTED";
        cbStatus.style.color = "var(--danger)";
        cbStatus.style.background = "var(--danger-glow)";
        const badge = document.getElementById("system-status");
        badge.style.borderColor = "var(--danger)";
        badge.style.color = "var(--danger)";
        badge.style.boxShadow = "0 0 10px var(--danger-glow)";
        document.getElementById("status-text").textContent = "SIFT Workstation: Circuit Broken";
    }
}

function showExecutiveReport() {
    modalReportText.textContent = EXECUTIVE_REPORT_MD;
    reportModal.classList.add("active");
}

function stopSimulation() {
    clearInterval(autoSimulationInterval);
    autoSimulationInterval = null;
    runBtn.disabled = false;
    runBtn.classList.remove("running");
    stepBtn.disabled = false;
}

function resetSimulation() {
    stopSimulation();
    currentStep = -1;
    
    // Clear terminal log except first 3 lines
    const lines = terminalLog.querySelectorAll(".term-line");
    lines.forEach((l, idx) => {
        if (idx >= 3 && l.id !== "terminal-cursor-line") l.remove();
    });

    updateAnomalyTable([]);
    renderGraph([], []);
    updateProgressPips(-1);
    
    stepCounter.textContent = "0 / 5";
    compCount.textContent = "—";
    analyzedCount.textContent = "—";
    cbMeter.style.width = "0%";
    cbMeter.className = "hud-meter-bar";
    cbStatus.textContent = "ARMED";
    cbStatus.style.color = "var(--success)";
    cbStatus.style.background = "var(--success-glow)";

    const badge = document.getElementById("system-status");
    badge.removeAttribute("style");
    document.getElementById("status-text").textContent = "SIFT Workstation: Connected";
}

runBtn.addEventListener("click", () => {
    resetSimulation();
    runBtn.disabled = true;
    runBtn.classList.add("running");
    stepBtn.disabled = true;
    
    executeSimulationStep();
    autoSimulationInterval = setInterval(executeSimulationStep, 2000);
});

stepBtn.addEventListener("click", () => {
    stopSimulation();
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

// Window resize rendering
window.addEventListener("resize", () => {
    if (currentStep >= 0) {
        const stepData = MOCK_STEPS_DATA[currentStep];
        renderGraph(stepData.nodes, stepData.edges);
    } else {
        renderGraph([], []);
    }
});

// Load empty graph on startup
renderGraph([], []);
