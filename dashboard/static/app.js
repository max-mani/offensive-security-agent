const API = "";

let pollInterval = null;
let currentReport = null;

const els = {
  emptyState: document.getElementById("emptyState"),
  dashboardContent: document.getElementById("dashboardContent"),
  runScanBtn: document.getElementById("runScanBtn"),
  refreshBtn: document.getElementById("refreshBtn"),
  scanStatusBadge: document.getElementById("scanStatusBadge"),
  historySelect: document.getElementById("historySelect"),
  findingsBody: document.getElementById("findingsBody"),
  logPanel: document.getElementById("logPanel"),
  logOutput: document.getElementById("logOutput"),
  scanErrorsPanel: document.getElementById("scanErrorsPanel"),
  scanErrorsList: document.getElementById("scanErrorsList"),
  toast: document.getElementById("toast"),
  kpiCritical: document.getElementById("kpiCritical"),
  kpiHigh: document.getElementById("kpiHigh"),
  kpiMedium: document.getElementById("kpiMedium"),
  kpiTotal: document.getElementById("kpiTotal"),
  metaHealth: document.getElementById("metaHealth"),
  metaAccount: document.getElementById("metaAccount"),
  metaRegion: document.getElementById("metaRegion"),
  metaDuration: document.getElementById("metaDuration"),
  metaChecks: document.getElementById("metaChecks"),
  metaTime: document.getElementById("metaTime"),
};

async function fetchJSON(url, options = {}) {
  const res = await fetch(API + url, options);
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(err.detail || res.statusText);
  }
  return res.json();
}

function showToast(msg) {
  els.toast.textContent = msg;
  els.toast.classList.remove("hidden");
  setTimeout(() => els.toast.classList.add("hidden"), 2500);
}

function formatTime(iso) {
  if (!iso) return "-";
  try {
    return new Date(iso).toLocaleString();
  } catch {
    return iso;
  }
}

function setScanBadge(state) {
  els.scanStatusBadge.textContent = state;
  els.scanStatusBadge.className = `badge badge-${state}`;
}

function renderReport(report) {
  currentReport = report;
  els.emptyState.classList.add("hidden");
  els.dashboardContent.classList.remove("hidden");

  const sev = report.findings_by_severity || {};
  els.kpiCritical.textContent = sev.critical || 0;
  els.kpiHigh.textContent = sev.high || 0;
  els.kpiMedium.textContent = sev.medium || 0;
  els.kpiTotal.textContent = report.total_findings || 0;

  const health = report.scan_health || "unknown";
  els.metaHealth.innerHTML = `<span class="health-${health}">${health.charAt(0).toUpperCase() + health.slice(1)}</span>`;
  els.metaAccount.textContent = report.aws_account_id || "-";
  els.metaRegion.textContent = report.aws_region || "-";
  els.metaDuration.textContent = `${(report.duration_seconds || 0).toFixed(1)}s`;
  els.metaChecks.textContent = `${report.total_checks_succeeded || 0}/${report.total_checks_attempted || 0} succeeded`;
  els.metaTime.textContent = formatTime(report.end_time || report.start_time);

  renderFindings(report.findings || []);
  renderErrors(report.scan_errors || []);
}

function renderFindings(findings) {
  els.findingsBody.innerHTML = "";
  if (!findings.length) {
    els.findingsBody.innerHTML = `<tr><td colspan="7" style="text-align:center;color:var(--muted);padding:2rem">No findings - environment looks clean for enabled checks.</td></tr>`;
    return;
  }

  findings.forEach((f, idx) => {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td><button class="expand-btn" data-idx="${idx}" aria-label="Expand">+</button></td>
      <td><span class="sev sev-${f.severity}">${f.severity}</span></td>
      <td>${escapeHtml(f.title)}</td>
      <td><span class="resource-mono">${escapeHtml(f.resource_id)}</span></td>
      <td><span class="resource-mono">${escapeHtml(f.check_id)}</span></td>
      <td>${f.confidence_score}%</td>
      <td><button class="btn btn-copy" data-copy="${idx}">Copy CLI</button></td>
    `;
    els.findingsBody.appendChild(tr);

    const detailTr = document.createElement("tr");
    detailTr.className = "detail-row hidden";
    detailTr.dataset.detail = idx;
    detailTr.innerHTML = `<td colspan="7"><div class="detail-panel">
      <h4>Business Impact</h4>
      <p>${escapeHtml(f.business_impact)}</p>
      <h4>Severity Reasoning</h4>
      <p>${escapeHtml(f.severity_reasoning)}</p>
      <h4>Remediation Steps</h4>
      <ol>${(f.remediation_steps || []).map(s => `<li>${escapeHtml(s)}</li>`).join("")}</ol>
      <h4>Remediation Command</h4>
      <div class="cmd-block">
        <pre>${escapeHtml(f.remediation_command || "N/A")}</pre>
        <button class="btn btn-copy" data-copy="${idx}">Copy</button>
      </div>
      <h4>Raw Evidence</h4>
      <pre class="evidence-pre">${escapeHtml(JSON.stringify(f.raw_evidence, null, 2))}</pre>
      <p style="margin-top:0.75rem;font-size:0.8rem;color:var(--muted)">ARN: ${escapeHtml(f.resource_arn)}</p>
    </div></td>`;
    els.findingsBody.appendChild(detailTr);
  });

  els.findingsBody.querySelectorAll(".expand-btn").forEach(btn => {
    btn.addEventListener("click", () => {
      const idx = btn.dataset.idx;
      const row = els.findingsBody.querySelector(`tr[data-detail="${idx}"]`);
      const open = row.classList.toggle("hidden");
      btn.textContent = open ? "+" : "-";
    });
  });

  els.findingsBody.querySelectorAll("[data-copy]").forEach(btn => {
    btn.addEventListener("click", () => {
      const f = findings[parseInt(btn.dataset.copy, 10)];
      copyText(f.remediation_command || "");
    });
  });
}

function renderErrors(errors) {
  if (!errors.length) {
    els.scanErrorsPanel.classList.add("hidden");
    return;
  }
  els.scanErrorsPanel.classList.remove("hidden");
  els.scanErrorsList.innerHTML = errors.map(e =>
    `<li><strong>${escapeHtml(e.check_id)}</strong> (${escapeHtml(e.error_type)}): ${escapeHtml(e.error_message)}</li>`
  ).join("");
}

function escapeHtml(str) {
  if (!str) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text);
    showToast("Copied to clipboard");
  } catch {
    showToast("Copy failed");
  }
}

async function loadHistory() {
  try {
    const reports = await fetchJSON("/api/reports");
    els.historySelect.innerHTML = reports.map(r =>
      `<option value="${r.filename}">${formatTime(r.end_time)} - ${r.total_findings} findings (${r.scan_health})</option>`
    ).join("");
    if (currentReport && reports.length) {
      const match = reports.find(r => r.scan_id === currentReport.scan_id);
      if (match) els.historySelect.value = match.filename;
    }
  } catch {
    els.historySelect.innerHTML = "<option>No reports</option>";
  }
}

async function loadLatestReport() {
  try {
    const report = await fetchJSON("/api/reports/latest");
    renderReport(report);
    await loadHistory();
  } catch {
    els.emptyState.classList.remove("hidden");
    els.dashboardContent.classList.add("hidden");
    await loadHistory();
  }
}

async function loadReportByFilename(filename) {
  const report = await fetchJSON(`/api/reports/${encodeURIComponent(filename)}`);
  renderReport(report);
}

async function pollScanStatus() {
  try {
    const status = await fetchJSON("/api/scans/status");
    setScanBadge(status.state);

    if (status.state === "running") {
      els.runScanBtn.disabled = true;
      els.logPanel.classList.remove("hidden");
      els.logOutput.textContent = (status.log_tail || []).join("\n");
    } else {
      els.runScanBtn.disabled = false;
      if (status.state === "completed") {
        stopPolling();
        if (status.report_file) {
          await loadReportByFilename(status.report_file);
        } else {
          await loadLatestReport();
        }
        await loadHistory();
        showToast("Scan completed");
      } else if (status.state === "failed") {
        stopPolling();
        els.logPanel.classList.remove("hidden");
        els.logOutput.textContent = (status.log_tail || []).join("\n") + "\n\nERROR: " + (status.error || "Unknown");
        showToast("Scan failed: " + (status.error || "Unknown"));
      }
    }
  } catch (e) {
    console.error("Poll error", e);
  }
}

function startPolling() {
  stopPolling();
  pollInterval = setInterval(pollScanStatus, 2000);
  pollScanStatus();
}

function stopPolling() {
  if (pollInterval) {
    clearInterval(pollInterval);
    pollInterval = null;
  }
}

els.runScanBtn.addEventListener("click", async () => {
  try {
    await fetchJSON("/api/scans/run", { method: "POST" });
    setScanBadge("running");
    els.runScanBtn.disabled = true;
    els.logPanel.classList.remove("hidden");
    els.logOutput.textContent = "Starting scan...\n";
    showToast("Scan started");
    startPolling();
  } catch (e) {
    showToast(e.message || "Failed to start scan");
  }
});

els.refreshBtn.addEventListener("click", () => loadLatestReport());

els.historySelect.addEventListener("change", () => {
  const filename = els.historySelect.value;
  if (filename && filename !== "No reports") {
    loadReportByFilename(filename).catch(e => showToast(e.message));
  }
});

async function init() {
  try {
    const health = await fetchJSON("/api/health");
    if (health.scan_state === "running") {
      startPolling();
    } else {
      setScanBadge(health.scan_state || "idle");
    }
  } catch {
    setScanBadge("idle");
  }
  await loadLatestReport();
}

init();
