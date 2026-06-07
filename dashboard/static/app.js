const API = "";

let pollInterval = null;
let currentReport = null;
let activeMode = null; // "scan" | "job"

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
  fullDemoBtn: document.getElementById("fullDemoBtn"),
  setupBtn: document.getElementById("setupBtn"),
  verifyBtn: document.getElementById("verifyBtn"),
  cleanupBtn: document.getElementById("cleanupBtn"),
  scannerBadge: document.getElementById("scannerBadge"),
  adminBadge: document.getElementById("adminBadge"),
  pipelinePanel: document.getElementById("pipelinePanel"),
  pipelineTitle: document.getElementById("pipelineTitle"),
  pipelineSteps: document.getElementById("pipelineSteps"),
};

const demoBtns = [els.fullDemoBtn, els.setupBtn, els.verifyBtn, els.cleanupBtn, els.runScanBtn];

async function fetchJSON(url, options = {}) {
  const res = await fetch(API + url, options);
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(err.detail || res.statusText);
  }
  return res.json();
}

function showToast(msg, isError = false) {
  els.toast.textContent = msg;
  els.toast.classList.toggle("toast-error", isError);
  els.toast.classList.remove("hidden");
  setTimeout(() => els.toast.classList.add("hidden"), 3500);
}

function formatTime(iso) {
  if (!iso) return "-";
  try {
    return new Date(iso).toLocaleString();
  } catch {
    return iso;
  }
}

function setScanBadge(state, label) {
  els.scanStatusBadge.textContent = label || state;
  els.scanStatusBadge.className = `badge badge-${state}`;
}

function setButtonsDisabled(disabled) {
  demoBtns.forEach(b => { b.disabled = disabled; });
}

function escapeHtml(str) {
  if (!str) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function renderPipeline(title, steps) {
  if (!steps || !steps.length) {
    els.pipelinePanel.classList.add("hidden");
    return;
  }
  els.pipelinePanel.classList.remove("hidden");
  els.pipelineTitle.textContent = title;
  els.pipelineSteps.innerHTML = steps.map((s, i) => {
    const icon = s.status === "completed" ? "✓" : s.status === "running" ? "●" : s.status === "failed" ? "✗" : "○";
    const detail = s.detail ? `<span class="step-detail">${escapeHtml(s.detail)}</span>` : "";
    return `<li class="step step-${s.status}" data-idx="${i}">
      <span class="step-icon">${icon}</span>
      <span class="step-label">${escapeHtml(s.label)}</span>
      ${detail}
    </li>`;
  }).join("");
}

const JOB_TITLES = {
  setup: "Creating test misconfigurations…",
  cleanup: "Deleting test resources…",
  verify: "Verifying scanner can see resources…",
  full_demo: "Running full demo pipeline…",
  scan: "Running security scan…",
};

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
    els.findingsBody.innerHTML = `<tr><td colspan="7" style="text-align:center;color:var(--muted);padding:2rem">No findings — environment looks clean for enabled checks.</td></tr>`;
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
      btn.textContent = open ? "+" : "−";
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

async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text);
    showToast("Copied to clipboard");
  } catch {
    showToast("Copy failed", true);
  }
}

async function loadHistory() {
  try {
    const reports = await fetchJSON("/api/reports");
    els.historySelect.innerHTML = reports.map(r =>
      `<option value="${r.filename}">${formatTime(r.end_time)} — ${r.total_findings} findings (${r.scan_health})</option>`
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

async function updateCredentials() {
  try {
    const h = await fetchJSON("/api/health");
    els.scannerBadge.textContent = h.aws_configured ? "Scanner: ready" : "Scanner: missing .env";
    els.scannerBadge.className = `cred-badge ${h.aws_configured ? "cred-ok" : "cred-bad"}`;
    els.adminBadge.textContent = h.admin_configured ? "Admin: ready" : "Admin: missing .env.admin";
    els.adminBadge.className = `cred-badge ${h.admin_configured ? "cred-ok" : "cred-bad"}`;
  } catch {
    els.scannerBadge.textContent = "Scanner: unknown";
    els.adminBadge.textContent = "Admin: unknown";
  }
}

async function pollStatus() {
  try {
    const [scanSt, jobSt] = await Promise.all([
      fetchJSON("/api/scans/status"),
      fetchJSON("/api/jobs/status"),
    ]);

    const scanRunning = scanSt.state === "running";
    const jobRunning = jobSt.state === "running";

    if (scanRunning) {
      activeMode = "scan";
      setScanBadge("running", "Scanning");
      setButtonsDisabled(true);
      els.logPanel.classList.remove("hidden");
      els.logOutput.textContent = (scanSt.log_tail || []).join("\n");
      renderPipeline(JOB_TITLES.scan, scanSt.steps);
      const done = scanSt.steps_completed || 0;
      const total = scanSt.steps_total || 0;
      els.pipelineTitle.textContent = `${JOB_TITLES.scan} (${done}/${total})`;
    } else if (jobRunning) {
      activeMode = "job";
      const jt = jobSt.job_type || "job";
      setScanBadge("running", jt.replace("_", " "));
      setButtonsDisabled(true);
      els.logPanel.classList.remove("hidden");
      els.logOutput.textContent = (jobSt.log_tail || []).join("\n");
      renderPipeline(JOB_TITLES[jt] || "Working…", jobSt.steps);
      const done = jobSt.steps_completed || 0;
      const total = jobSt.steps_total || 0;
      els.pipelineTitle.textContent = `${JOB_TITLES[jt] || "Progress"} (${done}/${total})`;
    } else {
      setButtonsDisabled(false);

      if (activeMode === "scan" && scanSt.state === "completed") {
        stopPolling();
        setScanBadge("completed", "Done");
        if (scanSt.report_file) {
          await loadReportByFilename(scanSt.report_file);
        } else {
          await loadLatestReport();
        }
        await loadHistory();
        showToast(`Scan complete — ${scanSt.steps_total || 0} checks finished`);
        els.pipelinePanel.classList.add("hidden");
      } else if (activeMode === "job" && jobSt.state === "completed") {
        stopPolling();
        setScanBadge("completed", "Done");
        showToast(jobSt.result?.message || "Operation completed");
        if (jobSt.job_type === "full_demo" && jobSt.result?.report_file) {
          await loadReportByFilename(jobSt.result.report_file);
          await loadHistory();
        }
        if (jobSt.job_type === "verify" && jobSt.result) {
          showToast(`Verify: ${jobSt.result.passed}/${jobSt.result.total} PASS`);
        }
        setTimeout(() => els.pipelinePanel.classList.add("hidden"), 3000);
      } else if (scanSt.state === "failed") {
        stopPolling();
        setScanBadge("failed", "Failed");
        els.logOutput.textContent = (scanSt.log_tail || []).join("\n") + "\n\nERROR: " + (scanSt.error || "");
        showToast("Scan failed: " + (scanSt.error || ""), true);
      } else if (jobSt.state === "failed") {
        stopPolling();
        setScanBadge("failed", "Failed");
        els.logOutput.textContent = (jobSt.log_tail || []).join("\n") + "\n\nERROR: " + (jobSt.error || "");
        showToast(jobSt.error || "Operation failed", true);
      } else {
        setScanBadge("idle", "Idle");
      }
      activeMode = null;
    }
  } catch (e) {
    console.error("Poll error", e);
  }
}

function startPolling() {
  stopPolling();
  pollInterval = setInterval(pollStatus, 1200);
  pollStatus();
}

function stopPolling() {
  if (pollInterval) {
    clearInterval(pollInterval);
    pollInterval = null;
  }
}

async function postDemo(path, label) {
  try {
    setButtonsDisabled(true);
    els.logPanel.classList.remove("hidden");
    els.logOutput.textContent = `Starting ${label}…\n`;
    activeMode = "job";
    await fetchJSON(path, { method: "POST" });
    showToast(`${label} started`);
    startPolling();
  } catch (e) {
    setButtonsDisabled(false);
    showToast(e.message || `Failed: ${label}`, true);
  }
}

els.fullDemoBtn.addEventListener("click", () => postDemo("/api/demo/full", "Full demo"));
els.setupBtn.addEventListener("click", () => postDemo("/api/demo/setup", "Create misconfigs"));
els.verifyBtn.addEventListener("click", () => postDemo("/api/demo/verify-run", "Verify resources"));
els.cleanupBtn.addEventListener("click", () => {
  if (!confirm("Delete all test S3 buckets, security groups, and IAM user?")) return;
  postDemo("/api/demo/cleanup", "Cleanup");
});

els.runScanBtn.addEventListener("click", async () => {
  try {
    activeMode = "scan";
    await fetchJSON("/api/scans/run", { method: "POST" });
    setScanBadge("running", "Scanning");
    setButtonsDisabled(true);
    els.logPanel.classList.remove("hidden");
    els.logOutput.textContent = "Starting scan…\n";
    showToast("Scan started");
    startPolling();
  } catch (e) {
    showToast(e.message || "Failed to start scan", true);
  }
});

els.refreshBtn.addEventListener("click", async () => {
  await updateCredentials();
  await loadLatestReport();
});

els.historySelect.addEventListener("change", () => {
  const filename = els.historySelect.value;
  if (filename && filename !== "No reports") {
    loadReportByFilename(filename).catch(e => showToast(e.message, true));
  }
});

async function init() {
  await updateCredentials();
  try {
    const health = await fetchJSON("/api/health");
    if (health.scan_state === "running" || health.job_state === "running") {
      activeMode = health.scan_state === "running" ? "scan" : "job";
      startPolling();
    } else {
      setScanBadge("idle", "Idle");
    }
  } catch {
    setScanBadge("idle", "Idle");
  }
  await loadLatestReport();
}

init();
