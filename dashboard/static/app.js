const API = "";

let pollInterval = null;
let currentReport = null;
let activeMode = null;
let currentLevel = 1;
let activeScanLevel = 1;

const LEVEL_SUBTITLES = {
  1: "Level 1 - AWS Infrastructure Scanner",
  2: "Level 2 - Multi-Domain Scanner (AWS + API + CVE + Secrets)",
  3: "Level 3 - Autonomous Continuous Scanning",
};

const EMPTY_STATE = {
  1: {
    title: "No Level 1 reports yet",
    desc: 'Click <strong>Run Full Level 1 Scan</strong> or <strong>Run No Configuration Level 1 Scan</strong> to start.',
  },
  2: {
    title: "No Level 2 reports yet",
    desc: 'Click <strong>Run Level 2 Scan</strong> to run the multi-domain audit.',
  },
  3: {
    title: "No Level 3 data yet",
    desc: 'Click <strong>Run L3 Once</strong> or <strong>Start Daemon</strong> to begin autonomous scanning.',
  },
};

const els = {
  pageSubtitle: document.getElementById("pageSubtitle"),
  level1View: document.getElementById("level1View"),
  level2View: document.getElementById("level2View"),
  level3View: document.getElementById("level3View"),
  levelTabs: document.querySelectorAll(".level-tab"),
  emptyState: document.getElementById("emptyState"),
  emptyStateTitle: document.getElementById("emptyStateTitle"),
  emptyStateDesc: document.getElementById("emptyStateDesc"),
  dashboardContent: document.getElementById("dashboardContent"),
  runScanL1Btn: document.getElementById("runScanL1Btn"),
  runScanL2Btn: document.getElementById("runScanL2Btn"),
  refreshBtn: document.getElementById("refreshBtn"),
  scanStatusBadge: document.getElementById("scanStatusBadge"),
  historySelect: document.getElementById("historySelect"),
  findingsBody: document.getElementById("findingsBody"),
  findingsTableHead: document.getElementById("findingsTableHead"),
  findingsSectionTitle: document.getElementById("findingsSectionTitle"),
  logPanel: document.getElementById("logPanel"),
  logOutput: document.getElementById("logOutput"),
  scanErrorsPanel: document.getElementById("scanErrorsPanel"),
  scanErrorsList: document.getElementById("scanErrorsList"),
  toast: document.getElementById("toast"),
  kpiCritical: document.getElementById("kpiCritical"),
  kpiHigh: document.getElementById("kpiHigh"),
  kpiMedium: document.getElementById("kpiMedium"),
  kpiTotal: document.getElementById("kpiTotal"),
  metaLevel: document.getElementById("metaLevel"),
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
  kpiDomainsCard: document.getElementById("kpiDomainsCard"),
  kpiDedupCard: document.getElementById("kpiDedupCard"),
  kpiDomains: document.getElementById("kpiDomains"),
  kpiDedup: document.getElementById("kpiDedup"),
  runL3OnceBtn: document.getElementById("runL3OnceBtn"),
  startDaemonBtn: document.getElementById("startDaemonBtn"),
  stopDaemonBtn: document.getElementById("stopDaemonBtn"),
  refreshL3Btn: document.getElementById("refreshL3Btn"),
  l3PostureScore: document.getElementById("l3PostureScore"),
  l3TrendDirection: document.getElementById("l3TrendDirection"),
  l3OpenCritical: document.getElementById("l3OpenCritical"),
  l3SlaBreaches: document.getElementById("l3SlaBreaches"),
  l3DaemonStatus: document.getElementById("l3DaemonStatus"),
  l3MetaHealth: document.getElementById("l3MetaHealth"),
  l3MetaPosture: document.getElementById("l3MetaPosture"),
  l3MetaLifecycle: document.getElementById("l3MetaLifecycle"),
  l3MetaStarted: document.getElementById("l3MetaStarted"),
  l3MetaNextRun: document.getElementById("l3MetaNextRun"),
  l3MetaSlack: document.getElementById("l3MetaSlack"),
  l3TrendHistory: document.getElementById("l3TrendHistory"),
  l3FindingsBody: document.getElementById("l3FindingsBody"),
  l3HealthBody: document.getElementById("l3HealthBody"),
  l3AuditBody: document.getElementById("l3AuditBody"),
  l3LogPanel: document.getElementById("l3LogPanel"),
  l3LogOutput: document.getElementById("l3LogOutput"),
};

const DOMAIN_LABELS = {
  aws_infrastructure: "AWS",
  api_endpoints: "API",
  dependencies: "Deps",
  secrets: "Secrets",
};

const demoBtns = [
  els.fullDemoBtn,
  els.setupBtn,
  els.verifyBtn,
  els.cleanupBtn,
  els.runScanL1Btn,
  els.runScanL2Btn,
  els.runL3OnceBtn,
  els.startDaemonBtn,
  els.stopDaemonBtn,
  els.refreshL3Btn,
];

let l3PollInterval = null;

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
  demoBtns.forEach((b) => {
    if (b) b.disabled = disabled;
  });
}

function escapeHtml(str) {
  if (!str) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function reportLevel(report) {
  return report?.scan_level || (report?.filename?.includes("_l2") ? 2 : 1);
}

function switchLevel(level) {
  currentLevel = level;
  els.pageSubtitle.textContent = LEVEL_SUBTITLES[level] || LEVEL_SUBTITLES[1];

  els.levelTabs.forEach((tab) => {
    const tabLevel = parseInt(tab.dataset.level, 10);
    tab.classList.toggle("level-tab-active", tabLevel === level);
  });

  els.level1View.classList.toggle("hidden", level !== 1);
  els.level2View.classList.toggle("hidden", level !== 2);
  els.level3View.classList.toggle("hidden", level !== 3);

  if (level === 3) {
    els.dashboardContent.classList.add("hidden");
    els.emptyState.classList.add("hidden");
    els.pipelinePanel.classList.add("hidden");
    loadL3Dashboard();
    return;
  }

  loadLatestReportForLevel(level);
}

function renderFindingsTableHead(isL2) {
  if (isL2) {
    els.findingsTableHead.innerHTML = `
      <tr>
        <th></th>
        <th>Severity</th>
        <th>Impact</th>
        <th>Domain</th>
        <th>Title</th>
        <th>Resource</th>
        <th>Check</th>
        <th>Confidence</th>
        <th>Actions</th>
      </tr>`;
    els.findingsSectionTitle.textContent = "Findings (Ranked by Business Impact)";
  } else {
    els.findingsTableHead.innerHTML = `
      <tr>
        <th></th>
        <th>Severity</th>
        <th>Title</th>
        <th>Resource</th>
        <th>Check</th>
        <th>Confidence</th>
        <th>Actions</th>
      </tr>`;
    els.findingsSectionTitle.textContent = "Findings (By Severity)";
  }
}

function renderPipeline(title, steps) {
  if (!steps || !steps.length) {
    els.pipelinePanel.classList.add("hidden");
    return;
  }
  els.pipelinePanel.classList.remove("hidden");
  els.pipelineTitle.textContent = title;
  els.pipelineSteps.innerHTML = steps
    .map((s, i) => {
      const icon =
        s.status === "completed" ? "[OK]" : s.status === "running" ? "[..]" : s.status === "failed" ? "[X]" : "[ ]";
      const detail = s.detail ? `<span class="step-detail">${escapeHtml(s.detail)}</span>` : "";
      return `<li class="step step-${s.status}" data-idx="${i}">
      <span class="step-icon">${icon}</span>
      <span class="step-label">${escapeHtml(s.label)}</span>
      ${detail}
    </li>`;
    })
    .join("");
}

const JOB_TITLES = {
  setup: "Creating test misconfigurations...",
  cleanup: "Deleting test resources...",
  verify: "Verifying scanner can see resources...",
  full_demo: "Running full demo pipeline...",
  scan: "Running security scan...",
};

function renderReport(report) {
  currentReport = report;
  const level = reportLevel(report);
  const isL2 = level >= 2;

  els.emptyState.classList.add("hidden");
  els.dashboardContent.classList.remove("hidden");

  renderFindingsTableHead(isL2);
  els.kpiDomainsCard.classList.toggle("hidden", !isL2);
  els.kpiDedupCard.classList.toggle("hidden", !isL2);

  const sev = report.findings_by_severity || {};
  els.kpiCritical.textContent = sev.critical || 0;
  els.kpiHigh.textContent = sev.high || 0;
  els.kpiMedium.textContent = sev.medium || 0;
  els.kpiTotal.textContent = report.total_findings || 0;

  if (isL2) {
    els.kpiDomains.textContent = (report.domains_scanned || []).length;
    els.kpiDedup.textContent = report.deduplication_removed || 0;
  }

  els.metaLevel.textContent = `Level ${level}`;
  const health = report.scan_health || "unknown";
  els.metaHealth.innerHTML = `<span class="health-${health}">${health.charAt(0).toUpperCase() + health.slice(1)}</span>`;
  els.metaAccount.textContent = report.aws_account_id || "-";
  els.metaRegion.textContent = report.aws_region || "-";
  els.metaDuration.textContent = `${(report.duration_seconds || 0).toFixed(1)}s`;
  els.metaChecks.textContent = isL2
    ? `${(report.domains_scanned || []).join(", ") || "-"}`
    : `${report.total_checks_succeeded || 0}/${report.total_checks_attempted || 0} succeeded`;
  els.metaTime.textContent = formatTime(report.end_time || report.start_time);

  let findings = report.findings || [];
  if (isL2) {
    findings = [...findings].sort((a, b) => (b.impact_score || 0) - (a.impact_score || 0));
  }
  renderFindings(findings, isL2);
  renderErrors(report.scan_errors || []);
}

function renderFindings(findings, isL2 = false) {
  const colSpan = isL2 ? 9 : 7;
  els.findingsBody.innerHTML = "";
  if (!findings.length) {
    els.findingsBody.innerHTML = `<tr><td colspan="${colSpan}" style="text-align:center;color:var(--muted);padding:2rem">No findings - environment looks clean for enabled checks.</td></tr>`;
    return;
  }

  findings.forEach((f, idx) => {
    const tr = document.createElement("tr");
    const domainCell = isL2
      ? `<td><span class="domain-tag domain-${f.domain || "unknown"}">${escapeHtml(DOMAIN_LABELS[f.domain] || f.domain || "-")}</span></td>`
      : "";
    const impactCell = isL2
      ? `<td><span class="impact-score">${(f.impact_score || 0).toFixed(1)}</span></td>`
      : "";
    tr.innerHTML = `
      <td><button class="expand-btn" data-idx="${idx}" aria-label="Expand">+</button></td>
      <td><span class="sev sev-${f.severity}">${f.severity}</span></td>
      ${impactCell}
      ${domainCell}
      <td>${escapeHtml(f.title)}</td>
      <td><span class="resource-mono">${escapeHtml(f.resource_id)}</span></td>
      <td><span class="resource-mono">${escapeHtml(f.check_id)}</span></td>
      <td>${f.confidence_score}%</td>
      <td><button class="btn btn-copy" data-copy="${idx}">Copy CLI</button></td>
    `;
    els.findingsBody.appendChild(tr);

    const evidence = f.raw_evidence || {};
    let extraDetail = "";
    if (f.check_id === "dependency_cve") {
      extraDetail = `
        <h4>CVE Details</h4>
        <p>Package: ${escapeHtml(evidence.package_name || "-")}@${escapeHtml(evidence.installed_version || "-")}</p>
        <p>CVE IDs: ${escapeHtml((evidence.cve_ids || []).join(", ") || "-")}</p>
        <p>CVSS: ${escapeHtml(String(evidence.cvss_score ?? "-"))}</p>
        <p>Fix: ${escapeHtml((evidence.fix_versions || []).join(", ") || "-")}</p>`;
    }
    if (f.check_id === "secrets_scan") {
      extraDetail = `
        <h4>Secret Details</h4>
        <p>Type: ${escapeHtml(evidence.secret_type || "-")}</p>
        <p>Redacted: <code>${escapeHtml(evidence.value_redacted || "-")}</code></p>
        <p>File: ${escapeHtml(evidence.file_path || "-")} line ${escapeHtml(String(evidence.line_number || "-"))}</p>`;
    }

    const detailTr = document.createElement("tr");
    detailTr.className = "detail-row hidden";
    detailTr.dataset.detail = idx;
    detailTr.innerHTML = `<td colspan="${colSpan}"><div class="detail-panel">
      <h4>Business Impact</h4>
      <p>${escapeHtml(f.business_impact)}</p>
      ${extraDetail}
      <h4>Severity Reasoning</h4>
      <p>${escapeHtml(f.severity_reasoning)}</p>
      <h4>Remediation Steps</h4>
      <ol>${(f.remediation_steps || []).map((s) => `<li>${escapeHtml(s)}</li>`).join("")}</ol>
      <h4>Remediation Command</h4>
      <div class="cmd-block">
        <pre>${escapeHtml(f.remediation_command || "N/A")}</pre>
        <button class="btn btn-copy" data-copy="${idx}">Copy</button>
      </div>
      <h4>Raw Evidence</h4>
      <pre class="evidence-pre">${escapeHtml(JSON.stringify(f.raw_evidence, null, 2))}</pre>
      <p style="margin-top:0.75rem;font-size:0.8rem;color:var(--muted)">ARN: ${escapeHtml(f.resource_arn)}${isL2 ? ` | Domain: ${escapeHtml(f.domain || "-")} | Impact: ${f.impact_score || 0}` : ""}</p>
    </div></td>`;
    els.findingsBody.appendChild(detailTr);
  });

  els.findingsBody.querySelectorAll(".expand-btn").forEach((btn) => {
    btn.addEventListener("click", () => {
      const idx = btn.dataset.idx;
      const row = els.findingsBody.querySelector(`tr[data-detail="${idx}"]`);
      const open = row.classList.toggle("hidden");
      btn.textContent = open ? "+" : "-";
    });
  });

  els.findingsBody.querySelectorAll("[data-copy]").forEach((btn) => {
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
  els.scanErrorsList.innerHTML = errors
    .map(
      (e) =>
        `<li><strong>${escapeHtml(e.check_id)}</strong> (${escapeHtml(e.error_type)}): ${escapeHtml(e.error_message)}</li>`
    )
    .join("");
}

async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text);
    showToast("Copied to clipboard");
  } catch {
    showToast("Copy failed", true);
  }
}

async function loadHistory(level = currentLevel) {
  try {
    const reports = await fetchJSON("/api/reports");
    const filtered = reports.filter((r) => (r.scan_level || 1) === level);
    const list = filtered.length ? filtered : reports;

    els.historySelect.innerHTML = list
      .map((r) => {
        const lvl = r.scan_level || 1;
        return `<option value="${r.filename}">L${lvl} | ${formatTime(r.end_time)} - ${r.total_findings} findings (${r.scan_health})</option>`;
      })
      .join("");

    if (currentReport && list.length) {
      const match = list.find((r) => r.scan_id === currentReport.scan_id);
      if (match) els.historySelect.value = match.filename;
    }
  } catch {
    els.historySelect.innerHTML = "<option>No reports</option>";
  }
}

async function loadL3Dashboard() {
  try {
    const [trend, findings, health, audit, daemonSt] = await Promise.all([
      fetchJSON("/api/l3/trend"),
      fetchJSON("/api/l3/findings"),
      fetchJSON("/api/l3/scan-health"),
      fetchJSON("/api/l3/audit?limit=50"),
      fetchJSON("/api/l3/daemon/status"),
    ]);

    els.l3PostureScore.textContent = trend.posture_score != null ? `${trend.posture_score}/100` : "—";
    els.l3TrendDirection.textContent = (trend.trend_direction || "—").toUpperCase();
    els.l3OpenCritical.textContent = trend.open_findings_by_severity?.critical ?? 0;
    els.l3SlaBreaches.textContent = trend.sla_breached_count ?? 0;

    const daemonRunning = daemonSt.daemon_state === "running";
    els.l3DaemonStatus.textContent = daemonRunning ? "Running" : "Stopped";
    if (els.stopDaemonBtn) els.stopDaemonBtn.disabled = !daemonRunning;
    if (els.startDaemonBtn) els.startDaemonBtn.disabled = daemonRunning;

    const latest = trend.latest_scan_run;
    if (latest) {
      els.l3MetaHealth.textContent = latest.health || "—";
      els.l3MetaPosture.textContent = latest.posture_score != null ? `${latest.posture_score}/100` : "—";
      els.l3MetaLifecycle.textContent = `${latest.new_findings} new / ${latest.updated_findings} updated`;
      els.l3MetaStarted.textContent = formatTime(latest.started_at);
    } else {
      els.l3MetaHealth.textContent = "—";
      els.l3MetaPosture.textContent = "—";
      els.l3MetaLifecycle.textContent = "—";
      els.l3MetaStarted.textContent = "—";
    }

    els.l3MetaNextRun.textContent = daemonSt.next_run_time
      ? formatTime(daemonSt.next_run_time)
      : "—";
    els.l3MetaSlack.textContent = trend.slack_configured ? "Configured" : "Not configured";

    if (trend.scan_history?.length) {
      els.l3TrendHistory.innerHTML = trend.scan_history
        .slice(-10)
        .map(
          (r) =>
            `<div class="trend-history-row"><span>${formatTime(r.timestamp)}</span>` +
            `<span>${r.posture_score ?? "N/A"}/100 · ${r.health || "?"} · +${r.findings?.new ?? 0} new</span></div>`
        )
        .join("");
    } else {
      els.l3TrendHistory.textContent = "No scan history yet.";
    }

    renderL3Findings(findings);
    renderL3Health(health);
    renderL3Audit(audit);

    if (daemonSt.log_tail?.length) {
      els.l3LogPanel.classList.remove("hidden");
      els.l3LogOutput.textContent = daemonSt.log_tail.join("\n");
    }
  } catch (e) {
    console.error("L3 load error", e);
  }
}

function statusBadgeClass(status) {
  const s = (status || "").replace("-", "");
  return `status-badge status-${status || "opened"}`;
}

function renderL3Findings(findings) {
  if (!els.l3FindingsBody) return;
  if (!findings?.length) {
    els.l3FindingsBody.innerHTML =
      `<tr><td colspan="7" style="text-align:center;color:var(--muted)">No findings in database yet.</td></tr>`;
    return;
  }
  els.l3FindingsBody.innerHTML = findings
    .map(
      (f) => `<tr>
        <td><span class="${statusBadgeClass(f.status)}">${escapeHtml(f.status)}</span></td>
        <td><span class="sev-${f.severity}">${escapeHtml(f.severity)}</span></td>
        <td><code>${escapeHtml(f.check_id)}</code></td>
        <td>${escapeHtml(f.resource_id)}</td>
        <td>${formatTime(f.first_seen)}</td>
        <td>${formatTime(f.last_seen)}</td>
        <td>${f.sla_breached ? "BREACHED" : formatTime(f.sla_deadline)}</td>
      </tr>`
    )
    .join("");
}

function renderL3Health(health) {
  if (!els.l3HealthBody) return;
  if (!health?.length) {
    els.l3HealthBody.innerHTML =
      `<tr><td colspan="4" style="text-align:center;color:var(--muted)">No scan health data yet.</td></tr>`;
    return;
  }
  els.l3HealthBody.innerHTML = health
    .map(
      (h) => `<tr>
        <td class="${h.status === "success" ? "health-success" : "health-error"}">${escapeHtml(h.status)}</td>
        <td><code>${escapeHtml(h.check_id)}</code></td>
        <td>${escapeHtml(h.domain)}</td>
        <td>${escapeHtml(h.error_message || "—")}</td>
      </tr>`
    )
    .join("");
}

function renderL3Audit(audit) {
  if (!els.l3AuditBody) return;
  if (!audit?.length) {
    els.l3AuditBody.innerHTML =
      `<tr><td colspan="4" style="text-align:center;color:var(--muted)">No audit entries yet.</td></tr>`;
    return;
  }
  els.l3AuditBody.innerHTML = audit
    .map(
      (a) => `<tr>
        <td>${formatTime(a.timestamp)}</td>
        <td>${escapeHtml(a.actor)}</td>
        <td><code>${escapeHtml(a.action)}</code></td>
        <td>${escapeHtml(a.entity_type || "")}:${escapeHtml(a.entity_id || "")}</td>
      </tr>`
    )
    .join("");
}

function startL3Polling() {
  stopL3Polling();
  l3PollInterval = setInterval(async () => {
    if (currentLevel !== 3) return;
    await loadL3Dashboard();
    const st = await fetchJSON("/api/l3/daemon/status");
    if (st.l3_scan_state === "running") {
      setScanBadge("running", "L3 Scanning");
    } else if (st.daemon_state === "running") {
      setScanBadge("running", "Daemon Active");
    }
  }, 3000);
}

function stopL3Polling() {
  if (l3PollInterval) {
    clearInterval(l3PollInterval);
    l3PollInterval = null;
  }
}

async function runL3Once() {
  try {
    activeMode = "l3";
    switchLevel(3);
    await fetchJSON("/api/l3/run", { method: "POST" });
    setScanBadge("running", "L3 Scanning");
    setButtonsDisabled(true);
    els.l3LogPanel.classList.remove("hidden");
    els.l3LogOutput.textContent = "Starting Level 3 scan...\n";
    showToast("Level 3 scan started");
    startL3Polling();
    pollL3Status();
  } catch (e) {
    showToast(e.message || "Failed to start L3 scan", true);
  }
}

async function startDaemon() {
  try {
    await fetchJSON("/api/l3/daemon/start", { method: "POST" });
    showToast("Daemon started");
    setScanBadge("running", "Daemon Active");
    startL3Polling();
    await loadL3Dashboard();
  } catch (e) {
    showToast(e.message || "Failed to start daemon", true);
  }
}

async function stopDaemon() {
  try {
    await fetchJSON("/api/l3/daemon/stop", { method: "POST" });
    showToast("Daemon stopped");
    setScanBadge("idle", "Idle");
    stopL3Polling();
    await loadL3Dashboard();
  } catch (e) {
    showToast(e.message || "Failed to stop daemon", true);
  }
}

async function pollL3Status() {
  const interval = setInterval(async () => {
    try {
      const st = await fetchJSON("/api/l3/daemon/status");
      if (st.log_tail?.length) {
        els.l3LogOutput.textContent = st.log_tail.join("\n");
      }
      if (st.l3_scan_state === "running") return;

      clearInterval(interval);
      setButtonsDisabled(false);
      if (st.l3_scan_state === "completed") {
        setScanBadge("completed", "Done");
        showToast("Level 3 scan complete");
      } else if (st.l3_scan_state === "failed") {
        setScanBadge("failed", "Failed");
        showToast(st.error || "L3 scan failed", true);
      }
      await loadL3Dashboard();
      activeMode = null;
    } catch (e) {
      console.error("L3 poll error", e);
    }
  }, 1500);
}

async function loadLatestReportForLevel(level) {
  if (level === 3) {
    await loadL3Dashboard();
    return;
  }

  try {
    const report = await fetchJSON(`/api/reports/latest?level=${level}`);
    renderReport(report);
    await loadHistory(level);
  } catch {
    els.dashboardContent.classList.add("hidden");
    els.emptyState.classList.remove("hidden");
    const state = EMPTY_STATE[level] || EMPTY_STATE[1];
    els.emptyStateTitle.textContent = state.title;
    els.emptyStateDesc.innerHTML = state.desc;
    await loadHistory(level);
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
      const lvl = scanSt.scan_level || activeScanLevel;
      setScanBadge("running", lvl >= 2 ? "L2 Scanning" : "L1 Scanning");
      setButtonsDisabled(true);
      els.logPanel.classList.remove("hidden");
      els.logOutput.textContent = (scanSt.log_tail || []).join("\n");
      renderPipeline(`Level ${lvl} scan in progress...`, scanSt.steps);
      const done = scanSt.steps_completed || 0;
      const total = scanSt.steps_total || 0;
      els.pipelineTitle.textContent = `Level ${lvl} scan (${done}/${total})`;
    } else if (jobRunning) {
      activeMode = "job";
      const jt = jobSt.job_type || "job";
      setScanBadge("running", jt.replace("_", " "));
      setButtonsDisabled(true);
      els.logPanel.classList.remove("hidden");
      els.logOutput.textContent = (jobSt.log_tail || []).join("\n");
      renderPipeline(JOB_TITLES[jt] || "Working...", jobSt.steps);
      const done = jobSt.steps_completed || 0;
      const total = jobSt.steps_total || 0;
      els.pipelineTitle.textContent = `${JOB_TITLES[jt] || "Progress"} (${done}/${total})`;
    } else {
      setButtonsDisabled(false);

      if (activeMode === "scan" && scanSt.state === "completed") {
        stopPolling();
        setScanBadge("completed", "Done");
        const completedLevel = scanSt.scan_level || activeScanLevel;
        switchLevel(completedLevel);
        if (scanSt.report_file) {
          await loadReportByFilename(scanSt.report_file);
        } else {
          await loadLatestReportForLevel(completedLevel);
        }
        await loadHistory(completedLevel);
        showToast(`Level ${completedLevel} scan complete`);
        els.pipelinePanel.classList.add("hidden");
      } else if (activeMode === "job" && jobSt.state === "completed") {
        stopPolling();
        setScanBadge("completed", "Done");
        showToast(jobSt.result?.message || "Operation completed");
        if (jobSt.job_type === "full_demo" && jobSt.result?.report_file) {
          switchLevel(1);
          await loadReportByFilename(jobSt.result.report_file);
          await loadHistory(1);
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
    els.logOutput.textContent = `Starting ${label}...\n`;
    activeMode = "job";
    await fetchJSON(path, { method: "POST" });
    showToast(`${label} started`);
    startPolling();
  } catch (e) {
    setButtonsDisabled(false);
    showToast(e.message || `Failed: ${label}`, true);
  }
}

async function startScan(level) {
  try {
    activeScanLevel = level;
    activeMode = "scan";
    switchLevel(level);
    await fetchJSON(`/api/scans/run?level=${level}`, { method: "POST" });
    setScanBadge("running", level >= 2 ? "L2 Scanning" : "L1 Scanning");
    setButtonsDisabled(true);
    els.logPanel.classList.remove("hidden");
    els.logOutput.textContent = `Starting Level ${level} scan...\n`;
    showToast(`Level ${level} scan started`);
    startPolling();
  } catch (e) {
    showToast(e.message || "Failed to start scan", true);
  }
}

els.levelTabs.forEach((tab) => {
  tab.addEventListener("click", () => {
    const level = parseInt(tab.dataset.level, 10);
    switchLevel(level);
    if (level === 3) {
      const st = fetchJSON("/api/l3/daemon/status").then((s) => {
        if (s.daemon_state === "running") startL3Polling();
      });
    } else {
      stopL3Polling();
    }
  });
});

els.fullDemoBtn.addEventListener("click", () => postDemo("/api/demo/full", "Run Full Level 1 Scan"));
els.setupBtn.addEventListener("click", () => postDemo("/api/demo/setup", "Create misconfigs"));
els.verifyBtn.addEventListener("click", () => postDemo("/api/demo/verify-run", "Verify resources"));
els.cleanupBtn.addEventListener("click", () => {
  if (!confirm("Delete all test S3 buckets, security groups, and IAM user?")) return;
  postDemo("/api/demo/cleanup", "Cleanup");
});

els.runScanL1Btn.addEventListener("click", () => startScan(1));
els.runScanL2Btn.addEventListener("click", () => startScan(2));
if (els.runL3OnceBtn) els.runL3OnceBtn.addEventListener("click", () => runL3Once());
if (els.startDaemonBtn) els.startDaemonBtn.addEventListener("click", () => startDaemon());
if (els.stopDaemonBtn) els.stopDaemonBtn.addEventListener("click", () => stopDaemon());
if (els.refreshL3Btn) els.refreshL3Btn.addEventListener("click", () => loadL3Dashboard());

els.refreshBtn.addEventListener("click", async () => {
  await updateCredentials();
  if (currentLevel === 3) {
    await loadL3Dashboard();
  } else {
    await loadLatestReportForLevel(currentLevel);
  }
});

els.historySelect.addEventListener("change", () => {
  const filename = els.historySelect.value;
  if (filename && filename !== "No reports") {
    loadReportByFilename(filename).catch((e) => showToast(e.message, true));
  }
});

async function init() {
  await updateCredentials();
  try {
    const health = await fetchJSON("/api/health");
    if (health.scan_state === "running" || health.job_state === "running") {
      activeMode = health.scan_state === "running" ? "scan" : "job";
      startPolling();
    } else if (health.daemon_state === "running") {
      startL3Polling();
      setScanBadge("running", "Daemon Active");
    } else if (health.l3_scan_state === "running") {
      activeMode = "l3";
      startL3Polling();
      pollL3Status();
    } else {
      setScanBadge("idle", "Idle");
    }
  } catch {
    setScanBadge("idle", "Idle");
  }
  switchLevel(1);
}

init();
