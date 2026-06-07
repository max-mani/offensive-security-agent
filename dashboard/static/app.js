const API = "";

let pollInterval = null;
let currentReport = null;
let activeMode = null;
let currentLevel = 1;
let activeScanLevel = 1;
let currentL3Filter = "all";
let toastTimer = null;

const LEVEL_SUBTITLES = {
  1: "Level 1 — AWS Infrastructure Scanner",
  2: "Level 2 — Multi-Domain Scanner (AWS + API + CVE + Secrets)",
  3: "Level 3 — Autonomous Continuous Scanning",
};

const EMPTY_STATE = {
  1: {
    title: "No Level 1 reports yet",
    desc: 'Click <strong>Run Full Level 1 Demo</strong> or <strong>Run Scan Only</strong> to start.',
  },
  2: {
    title: "No Level 2 reports yet",
    desc: 'Click <strong>Run Level 2 Scan</strong> to run the multi-domain audit.',
  },
};

const DOMAIN_LABELS = {
  aws_infrastructure: "AWS",
  api_endpoints: "API",
  dependencies: "Deps",
  secrets: "Secrets",
};

const JOB_TITLES = {
  setup: "Creating test misconfigurations...",
  cleanup: "Deleting test resources...",
  verify: "Verifying scanner can see resources...",
  full_demo: "Running full demo pipeline...",
  scan: "Running security scan...",
};

// ─── Element references ────────────────────────────────────────────────────

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
  reportList: document.getElementById("reportList"),
  reportHistoryPanel: document.getElementById("reportHistoryPanel"),
  reportHistoryTitle: document.getElementById("reportHistoryTitle"),
  reportHistoryDesc: document.getElementById("reportHistoryDesc"),
  clearReportsBtn: document.getElementById("clearReportsBtn"),
  findingsBody: document.getElementById("findingsBody"),
  findingsTableHead: document.getElementById("findingsTableHead"),
  findingsSectionTitle: document.getElementById("findingsSectionTitle"),
  logPanel: document.getElementById("logPanel"),
  logOutputReport: document.getElementById("logOutputReport") || document.createElement("pre"),
  scanErrorsPanel: document.getElementById("scanErrorsPanel"),
  scanErrorsList: document.getElementById("scanErrorsList"),
  scanErrorsEmpty: document.getElementById("scanErrorsEmpty"),
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
  activeTaskPanel: document.getElementById("activeTaskPanel"),
  activeTaskTitle: document.getElementById("activeTaskTitle"),
  pipelineSteps: document.getElementById("pipelineSteps"),
  logOutput: document.getElementById("logOutput"),
  l1DemoPipelinePanel: document.getElementById("l1DemoPipelinePanel"),
  l1DemoPipelineStatus: document.getElementById("l1DemoPipelineStatus"),
  l1ScanPipelinePanel: document.getElementById("l1ScanPipelinePanel"),
  l1ScanPipelineStatus: document.getElementById("l1ScanPipelineStatus"),
  l1ScanLog: document.getElementById("l1ScanLog"),
  l2ScanPipelineStatus: document.getElementById("l2ScanPipelineStatus"),
  l2ScanLog: document.getElementById("l2ScanLog"),
  kpiDomainsCard: document.getElementById("kpiDomainsCard"),
  kpiDedupCard: document.getElementById("kpiDedupCard"),
  kpiDomains: document.getElementById("kpiDomains"),
  kpiDedup: document.getElementById("kpiDedup"),
  agentMetricsPanel: document.getElementById("agentMetricsPanel"),
  metricsHeadline: document.getElementById("metricsHeadline"),
  metricsEmpty: document.getElementById("metricsEmpty"),
  metricsContent: document.getElementById("metricsContent"),
  metricPrecision: document.getElementById("metricPrecision"),
  metricPrecisionBadge: document.getElementById("metricPrecisionBadge"),
  metricRecall: document.getElementById("metricRecall"),
  metricRecallBadge: document.getElementById("metricRecallBadge"),
  metricF1: document.getElementById("metricF1"),
  metricF1Badge: document.getElementById("metricF1Badge"),
  metricConfidence: document.getElementById("metricConfidence"),
  metricConfidenceBadge: document.getElementById("metricConfidenceBadge"),
  metricsDetectionDetail: document.getElementById("metricsDetectionDetail"),
  metricsSpeedDetail: document.getElementById("metricsSpeedDetail"),
  metricsCoverageDetail: document.getElementById("metricsCoverageDetail"),
  metricsL2Section: document.getElementById("metricsL2Section"),
  metricsL2Detail: document.getElementById("metricsL2Detail"),
  // L3
  runL3OnceBtn: document.getElementById("runL3OnceBtn"),
  startDaemonBtn: document.getElementById("startDaemonBtn"),
  stopDaemonBtn: document.getElementById("stopDaemonBtn"),
  refreshL3Btn: document.getElementById("refreshL3Btn"),
  l3PostureScore: document.getElementById("l3PostureScore"),
  l3TrendDirection: document.getElementById("l3TrendDirection"),
  l3TrendHint: document.getElementById("l3TrendHint"),
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
  l3MetricScans: document.getElementById("l3MetricScans"),
  l3MetricDb: document.getElementById("l3MetricDb"),
  l3MetricDedup: document.getElementById("l3MetricDedup"),
  l3MetricLifecycle: document.getElementById("l3MetricLifecycle"),
  l3MetricSla: document.getElementById("l3MetricSla"),
  l3MetricSlack: document.getElementById("l3MetricSlack"),
  l3MetricTrend: document.getElementById("l3MetricTrend"),
  l3MetricF1: document.getElementById("l3MetricF1"),
  l3MetricSlaCompliance: document.getElementById("l3MetricSlaCompliance"),
  l3MetricReliability: document.getElementById("l3MetricReliability"),
  l3MetricResolution: document.getElementById("l3MetricResolution"),
  l3PipelineStatus: document.getElementById("l3PipelineStatus"),
  resetL3Btn: document.getElementById("resetL3Btn"),
};

const L3_PIPELINE_ORDER = [
  { id: "l3StepScans", num: 1, name: "Continuous Scans" },
  { id: "l3StepDb", num: 2, name: "Persistent Findings DB" },
  { id: "l3StepDedup", num: 3, name: "Deduplication Engine" },
  { id: "l3StepLifecycle", num: 4, name: "Lifecycle Tracking" },
  { id: "l3StepSla", num: 5, name: "SLA Engine" },
  { id: "l3StepSlack", num: 6, name: "Slack Escalation" },
  { id: "l3StepTrend", num: 7, name: "Trend Analytics" },
];

const L3_PHASE_TO_STEP = {
  scans: "l3StepScans",
  db: "l3StepDb",
  dedup: "l3StepDedup",
  lifecycle: "l3StepLifecycle",
  sla: "l3StepSla",
  escalation: "l3StepSlack",
  trend: "l3StepTrend",
};

let l3PipelineStepIndex = 0;
let scanPipelineStepIndex = { l1: 0, l2: 0 };
let fullDemoPipelineStepIndex = 0;

const FULL_DEMO_PIPELINE_ORDER = [
  { id: "demoStepSetup", stepId: "demo_setup", num: 1, name: "Create Misconfigs", metricId: "demoMetricSetup" },
  { id: "demoStepVerify", stepId: "demo_verify", num: 2, name: "Verify Resources", metricId: "demoMetricVerify" },
  { id: "demoStepScan", stepId: "demo_scan", num: 3, name: "Run Security Scan", metricId: "demoMetricScan" },
  { id: "demoStepDone", stepId: "demo_done", num: 4, name: "Load Findings", metricId: "demoMetricDone" },
];

const L1_PHASE_STEP_IDS = new Set(["init", "llm_enrichment", "reports"]);

const L1_PIPELINE_ORDER = [
  { id: "l1StepConfig", stepIds: ["init"], num: 1, name: "Load Configuration", metricId: "l1MetricConfig" },
  { id: "l1StepAws", stepIds: "aws", num: 2, name: "AWS Infrastructure", metricId: "l1MetricAws" },
  { id: "l1StepLlm", stepIds: ["llm_enrichment"], num: 3, name: "LLM Enrichment", metricId: "l1MetricLlm" },
  { id: "l1StepReports", stepIds: ["reports"], num: 4, name: "Generate Reports", metricId: "l1MetricReports" },
];

const L2_PIPELINE_ORDER = [
  { id: "l2StepConfig", stepIds: ["init"], num: 1, name: "Load Configuration", metricId: "l2MetricConfig" },
  { id: "l2StepAws", stepIds: ["domain_aws"], num: 2, name: "AWS Infrastructure", metricId: "l2MetricAws" },
  { id: "l2StepApi", stepIds: ["domain_api"], num: 3, name: "API Endpoint Scanner", metricId: "l2MetricApi" },
  { id: "l2StepDeps", stepIds: ["domain_deps"], num: 4, name: "Dependency CVE Scanner", metricId: "l2MetricDeps" },
  { id: "l2StepSecrets", stepIds: ["domain_secrets"], num: 5, name: "Secrets Scanner", metricId: "l2MetricSecrets" },
  { id: "l2StepLlm", stepIds: ["llm_enrichment"], num: 6, name: "LLM Enrichment", metricId: "l2MetricLlm" },
  { id: "l2StepDedup", stepIds: ["dedup"], num: 7, name: "Cross-Domain Deduplication", metricId: "l2MetricDedup" },
  { id: "l2StepRanking", stepIds: ["ranking"], num: 8, name: "Business Impact Ranking", metricId: "l2MetricRanking" },
  { id: "l2StepReports", stepIds: ["reports"], num: 9, name: "Generate Reports", metricId: "l2MetricReports" },
];

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
  els.resetL3Btn,
];

let l3PollInterval = null;
let prevL3ScanState = "idle";

// ─── Utilities ─────────────────────────────────────────────────────────────

async function fetchJSON(url, options = {}) {
  const res = await fetch(API + url, options);
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }));
    let detail = err.detail || res.statusText;
    if (Array.isArray(detail)) {
      detail = detail.map((d) => d.msg || JSON.stringify(d)).join(", ");
    }
    throw new Error(detail);
  }
  return res.json();
}

function showToast(msg, isError = false, duration = 3500) {
  if (toastTimer) clearTimeout(toastTimer);
  els.toast.textContent = msg;
  els.toast.classList.toggle("toast-error", isError);
  els.toast.classList.remove("hidden");
  toastTimer = setTimeout(() => els.toast.classList.add("hidden"), duration);
}

function formatTime(iso) {
  if (!iso) return "—";
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
  demoBtns.forEach((b) => { if (b) b.disabled = disabled; });
}

function escapeHtml(str) {
  if (!str) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function attrEscape(str) {
  return String(str || "")
    .replace(/&/g, "&amp;")
    .replace(/"/g, "&quot;");
}

function resetL3PipelineProgress() {
  l3PipelineStepIndex = 0;
}

function extractCurrentScanLog(logTail) {
  const lines = logTail || [];
  let startIdx = 0;
  for (let i = lines.length - 1; i >= 0; i--) {
    if (/=== L3 Scan .+ started ===|Starting Level 3|\[l3-phase\] scans/i.test(lines[i])) {
      startIdx = i;
      break;
    }
  }
  return lines.slice(startIdx).join("\n");
}

function reportLevel(report) {
  return report?.scan_level || (report?.filename?.includes("_l2") ? 2 : 1);
}

// ─── Level switching ────────────────────────────────────────────────────────

function switchLevel(level) {
  currentLevel = level;
  els.pageSubtitle.textContent = LEVEL_SUBTITLES[level] || LEVEL_SUBTITLES[1];

  els.levelTabs.forEach((tab) => {
    const tabLevel = parseInt(tab.dataset.level, 10);
    tab.classList.toggle("level-tab-active", tabLevel === level);
  });

  const isL3 = level === 3;

  // Show the correct level-specific panel
  els.level1View.classList.toggle("hidden", level !== 1);
  els.level2View.classList.toggle("hidden", level !== 2);
  els.level3View.classList.toggle("hidden", !isL3);

  // Report history is always visible; L3 uses SQLite + optional JSON reports
  els.reportHistoryPanel?.classList.remove("hidden");
  updateReportHistoryHeading(level);

  if (!isL3 && activeMode !== "scan") {
    resetLevelScanPipelineIdle(level);
  }

  if (isL3) {
    els.dashboardContent.classList.add("hidden");
    els.emptyState.classList.add("hidden");
    hideActiveTaskPanel();
    loadHistory(null);
    loadL3Dashboard();
    return;
  }

  loadHistory(level);
  loadLatestReportForLevel(level);
}

function updateReportHistoryHeading(level) {
  if (!els.reportHistoryTitle) return;
  if (level === 3) {
    els.reportHistoryTitle.textContent = "Report History (All Levels)";
    if (els.reportHistoryDesc) {
      els.reportHistoryDesc.textContent =
        "L3 scan runs (SQLite) and L1/L2 JSON reports. Delete individual entries or clear all. Full SQLite reset: Reset L3 Data.";
    }
    if (els.clearReportsBtn) els.clearReportsBtn.textContent = "Clear All Reports";
  } else {
    els.reportHistoryTitle.textContent = `Report History (Level ${level})`;
    if (els.reportHistoryDesc) {
      els.reportHistoryDesc.textContent =
        `Level ${level} scan reports from reports/. Delete one or clear all for this level.`;
    }
    if (els.clearReportsBtn) els.clearReportsBtn.textContent = `Clear Level ${level} Reports`;
  }
}

// ─── Active Task Panel (replaces old #pipelinePanel) ───────────────────────

function showActiveTaskPanel(title) {
  els.activeTaskPanel.classList.remove("hidden");
  els.activeTaskTitle.textContent = title;
}

function hideActiveTaskPanel() {
  els.activeTaskPanel.classList.add("hidden");
  els.pipelineSteps.innerHTML = "";
  els.logOutput.textContent = "";
}

function getScanPipelineOrder(level) {
  return level >= 2 ? L2_PIPELINE_ORDER : L1_PIPELINE_ORDER;
}

function getLevelScanUi(level) {
  if (level >= 2) {
    return { status: els.l2ScanPipelineStatus, log: els.l2ScanLog, key: "l2" };
  }
  return { status: els.l1ScanPipelineStatus, log: els.l1ScanLog, key: "l1" };
}

function stepsForScanPhase(phase, steps, level) {
  if (phase.stepIds === "aws") {
    return steps.filter((s) => !L1_PHASE_STEP_IDS.has(s.id));
  }
  return steps.filter((s) => phase.stepIds.includes(s.id));
}

function scanPhaseStatus(phase, steps, level) {
  const phaseSteps = stepsForScanPhase(phase, steps, level);
  if (!phaseSteps.length) return "pending";
  if (phaseSteps.some((s) => s.status === "failed")) return "failed";
  if (phaseSteps.some((s) => s.status === "running")) return "running";
  if (phaseSteps.every((s) => s.status === "completed")) return "completed";
  if (phaseSteps.some((s) => s.status === "completed")) return "running";
  return "pending";
}

function resetScanPipelineProgress(level) {
  scanPipelineStepIndex[level >= 2 ? "l2" : "l1"] = 0;
}

function inferScanPipelinePhase(level, steps, scanRunning) {
  const order = getScanPipelineOrder(level);
  const key = level >= 2 ? "l2" : "l1";
  let idx = 0;

  if (scanRunning) {
    // Sequential display: find the FIRST running/failed step.
    // Parallel completions ahead of it are hidden until this step finishes.
    let found = false;
    for (let i = 0; i < order.length; i++) {
      const status = scanPhaseStatus(order[i], steps, level);
      if (status === "running" || status === "failed") {
        idx = i;
        found = true;
        break;
      }
      if (status === "completed") {
        idx = i; // track furthest completed in case nothing is running yet
      }
    }
    scanPipelineStepIndex[key] = Math.max(scanPipelineStepIndex[key] || 0, idx);
    return order[scanPipelineStepIndex[key]].id;
  }

  // Scan finished: find the furthest non-pending step
  for (let i = 0; i < order.length; i++) {
    const status = scanPhaseStatus(order[i], steps, level);
    if (status !== "pending") idx = i;
  }
  scanPipelineStepIndex[key] = idx;
  return order[idx].id;
}

function getScanStepMeta(level, stepId) {
  const order = getScanPipelineOrder(level);
  return order.find((s) => s.id === stepId) || order[0];
}

function highlightScanPipelineSteps(level, activeStepId, scanRunning, steps = null) {
  const order = getScanPipelineOrder(level);
  const activeIdx = order.findIndex((s) => s.id === activeStepId);
  const ui = getLevelScanUi(level);

  // Sequential display: while scanning, only reveal progress up to the first
  // running/failed step. Parallel completions ahead of it stay "pending" until
  // the blocking step finishes — so the UI always moves one step at a time.
  order.forEach((step, i) => {
    const el = document.getElementById(step.id);
    if (!el) return;
    el.classList.remove("l3-step-active", "l3-step-done", "l3-step-pending", "l3-step-failed");

    if (scanRunning && steps?.length) {
      if (i < activeIdx) {
        el.classList.add("l3-step-done");
      } else if (i === activeIdx) {
        const st = scanPhaseStatus(step, steps, level);
        el.classList.add(st === "failed" ? "l3-step-failed" : "l3-step-active");
      } else {
        el.classList.add("l3-step-pending");
      }
    } else {
      // Scan finished (or no step data): show actual final state
      if (steps?.length) {
        const st = scanPhaseStatus(step, steps, level);
        if (st === "failed") el.classList.add("l3-step-failed");
        else if (st === "completed" || st === "running") el.classList.add("l3-step-done");
        else if (i <= activeIdx) el.classList.add("l3-step-done");
        else el.classList.add("l3-step-pending");
      } else {
        if (i <= activeIdx) el.classList.add("l3-step-done");
        else el.classList.add("l3-step-pending");
      }
    }
  });

  if (ui.status) {
    if (scanRunning) {
      const meta = getScanStepMeta(level, activeStepId);
      ui.status.textContent = `Running — Step ${meta.num}: ${meta.name}`;
      ui.status.classList.remove("hidden");
    } else {
      ui.status.classList.add("hidden");
      ui.status.textContent = "";
    }
  }
}

function metricTextForPhase(phase, steps, level, scanRunning) {
  const phaseSteps = stepsForScanPhase(phase, steps, level);
  const status = scanPhaseStatus(phase, steps, level);

  // While scanning: suppress completion details for steps that come AFTER the
  // current active step — keep them showing "Waiting for scan" so the user
  // sees a clean 1-by-1 sequential progression in the metric labels.
  if (scanRunning && steps?.length) {
    const order = getScanPipelineOrder(level);
    const activeStepIdx = order.findIndex((p) => {
      const st = scanPhaseStatus(p, steps, level);
      return st === "running" || st === "failed";
    });
    const thisIdx = order.findIndex((p) => p.id === phase.id);
    if (activeStepIdx >= 0 && thisIdx > activeStepIdx) {
      return "Waiting for scan";
    }
  }

  if (status === "running") {
    const running = phaseSteps.find((s) => s.status === "running");
    return running?.detail ? `⟳ ${running.detail}` : "⟳ In progress…";
  }
  if (status === "failed") {
    const failed = phaseSteps.find((s) => s.status === "failed");
    return failed?.detail ? `✗ ${failed.detail}` : "✗ Failed";
  }
  if (status === "completed") {
    const done = phaseSteps.filter((s) => s.status === "completed");
    if (phase.stepIds === "aws") {
      return `✓ ${done.length} check(s) completed`;
    }
    const last = done[done.length - 1];
    return last?.detail ? `✓ ${last.detail}` : "✓ Complete";
  }
  if (!scanRunning && phase.num === 1) {
    return level >= 2 ? "Ready — click Run Level 2 Scan" : "Ready — click Run Scan";
  }
  return "Waiting for scan";
}

function updateScanPipelineMetrics(level, steps, scanRunning) {
  const order = getScanPipelineOrder(level);
  order.forEach((phase) => {
    const metricEl = document.getElementById(phase.metricId);
    if (metricEl) {
      metricEl.textContent = metricTextForPhase(phase, steps, level, scanRunning);
    }
  });
}

function renderLevelScanPipeline(level, steps, logText = "", scanRunning = true) {
  if (!steps?.length) return;

  const ui = getLevelScanUi(level);
  const activeStepId = inferScanPipelinePhase(level, steps, scanRunning);

  highlightScanPipelineSteps(level, activeStepId, scanRunning, steps);
  updateScanPipelineMetrics(level, steps, scanRunning);

  if (ui.log) {
    if (logText && scanRunning) {
      ui.log.textContent = logText;
      ui.log.classList.remove("hidden");
    } else if (!scanRunning) {
      ui.log.classList.add("hidden");
    }
  }
}

function finishLevelScanPipeline(level, steps) {
  renderLevelScanPipeline(level, steps, "", false);
  const order = getScanPipelineOrder(level);
  highlightScanPipelineSteps(level, order[order.length - 1].id, false, steps);
  order.forEach((step) => {
    const el = document.getElementById(step.id);
    if (el) {
      el.classList.remove("l3-step-active", "l3-step-pending");
      el.classList.add("l3-step-done");
    }
  });
  const ui = getLevelScanUi(level);
  if (ui.status) {
    ui.status.classList.add("hidden");
    ui.status.textContent = "";
  }
  if (ui.log) ui.log.classList.add("hidden");
}

function showFullDemoPipeline() {
  els.l1DemoPipelinePanel?.classList.remove("hidden");
  els.l1ScanPipelinePanel?.classList.add("hidden");
}

function hideFullDemoPipeline() {
  els.l1DemoPipelinePanel?.classList.add("hidden");
  els.l1ScanPipelinePanel?.classList.remove("hidden");
  if (els.l1DemoPipelineStatus) {
    els.l1DemoPipelineStatus.classList.add("hidden");
    els.l1DemoPipelineStatus.textContent = "";
  }
}

function resetFullDemoPipeline() {
  fullDemoPipelineStepIndex = 0;
  FULL_DEMO_PIPELINE_ORDER.forEach((phase, i) => {
    const el = document.getElementById(phase.id);
    if (el) {
      el.classList.remove("l3-step-active", "l3-step-done", "l3-step-failed");
      el.classList.add("l3-step-pending");
    }
    const metricEl = document.getElementById(phase.metricId);
    if (metricEl) metricEl.textContent = i === 0 ? "⟳ Starting…" : "Waiting…";
  });
}

function inferFullDemoPhase(jobSteps, running) {
  const stepMap = Object.fromEntries((jobSteps || []).map((s) => [s.id, s]));
  let idx = 0;
  FULL_DEMO_PIPELINE_ORDER.forEach((phase, i) => {
    const st = stepMap[phase.stepId];
    if (st && (st.status === "running" || st.status === "completed" || st.status === "failed")) {
      idx = i;
    }
  });
  if (running) {
    fullDemoPipelineStepIndex = Math.max(fullDemoPipelineStepIndex, idx);
    return FULL_DEMO_PIPELINE_ORDER[fullDemoPipelineStepIndex].id;
  }
  fullDemoPipelineStepIndex = idx;
  return FULL_DEMO_PIPELINE_ORDER[idx].id;
}

function renderFullDemoPipeline(jobSteps, logText = "", running = true) {
  if (!jobSteps?.length) return;

  const stepMap = Object.fromEntries(jobSteps.map((s) => [s.id, s]));
  const activeId = inferFullDemoPhase(jobSteps, running);
  const activeIdx = FULL_DEMO_PIPELINE_ORDER.findIndex((p) => p.id === activeId);

  FULL_DEMO_PIPELINE_ORDER.forEach((phase, i) => {
    const el = document.getElementById(phase.id);
    const st = stepMap[phase.stepId];
    if (el) {
      el.classList.remove("l3-step-active", "l3-step-done", "l3-step-pending", "l3-step-failed");
      if (running) {
        if (i < activeIdx) el.classList.add("l3-step-done");
        else if (i === activeIdx) el.classList.add(st?.status === "failed" ? "l3-step-failed" : "l3-step-active");
        else el.classList.add("l3-step-pending");
      } else if (st?.status === "completed") {
        el.classList.add("l3-step-done");
      } else if (st?.status === "failed") {
        el.classList.add("l3-step-failed");
      } else {
        el.classList.add("l3-step-pending");
      }
    }
    const metricEl = document.getElementById(phase.metricId);
    if (metricEl && st) {
      if (st.status === "running") metricEl.textContent = st.detail ? `⟳ ${st.detail}` : "⟳ In progress…";
      else if (st.status === "completed") metricEl.textContent = st.detail ? `✓ ${st.detail}` : "✓ Complete";
      else if (st.status === "failed") metricEl.textContent = st.detail ? `✗ ${st.detail}` : "✗ Failed";
      else metricEl.textContent = "Waiting…";
    }
  });

  if (els.l1DemoPipelineStatus) {
    if (running && activeIdx >= 0) {
      const meta = FULL_DEMO_PIPELINE_ORDER[activeIdx];
      els.l1DemoPipelineStatus.textContent = `Running — Step ${meta.num}: ${meta.name}`;
      els.l1DemoPipelineStatus.classList.remove("hidden");
    } else {
      els.l1DemoPipelineStatus.classList.add("hidden");
    }
  }

  if (els.l1ScanLog && logText) {
    els.l1ScanLog.textContent = logText;
    els.l1ScanLog.classList.remove("hidden");
  }
}

function resetLevelScanPipelineIdle(level) {
  resetScanPipelineProgress(level);
  const order = getScanPipelineOrder(level);
  order.forEach((phase, i) => {
    const el = document.getElementById(phase.id);
    if (el) {
      el.classList.remove("l3-step-active", "l3-step-done", "l3-step-failed");
      el.classList.add("l3-step-pending");
    }
    const metricEl = document.getElementById(phase.metricId);
    if (metricEl) {
      metricEl.textContent = i === 0
        ? (level >= 2 ? "Ready — click Run Level 2 Scan" : "Ready — click Run Scan")
        : "Waiting for scan";
    }
  });
  const ui = getLevelScanUi(level);
  if (ui.status) {
    ui.status.classList.add("hidden");
    ui.status.textContent = "";
  }
  if (ui.log) {
    ui.log.classList.add("hidden");
    ui.log.textContent = "";
  }
}

function renderJobPipeline(title, steps) {
  if (!steps || !steps.length) {
    hideActiveTaskPanel();
    return;
  }
  showActiveTaskPanel(title);
  els.pipelineSteps.innerHTML = steps
    .map((s, i) => {
      let icon;
      if (s.status === "completed") icon = '<span class="step-icon-ok">✓</span>';
      else if (s.status === "running") icon = '<span class="step-icon-run">⟳</span>';
      else if (s.status === "failed") icon = '<span class="step-icon-fail">✗</span>';
      else icon = '<span class="step-icon-pend">○</span>';

      const detail = s.detail ? `<span class="step-detail">${escapeHtml(s.detail)}</span>` : "";
      return `<li class="step step-${s.status}" data-idx="${i}">
        ${icon}
        <span class="step-label">${escapeHtml(s.label)}</span>
        ${detail}
      </li>`;
    })
    .join("");
}

// ─── Findings rendering ─────────────────────────────────────────────────────

function renderFindingsTableHead(isL2) {
  if (isL2) {
    els.findingsTableHead.innerHTML = `
      <tr>
        <th></th><th>Severity</th><th>Impact</th><th>Domain</th>
        <th>Title</th><th>Resource</th><th>Check</th><th>Confidence</th><th>Actions</th>
      </tr>`;
    els.findingsSectionTitle.textContent = "Findings — Ranked by Business Impact";
  } else {
    els.findingsTableHead.innerHTML = `
      <tr>
        <th></th><th>Severity</th><th>Title</th><th>Resource</th>
        <th>Check</th><th>Confidence</th><th>Actions</th>
      </tr>`;
    els.findingsSectionTitle.textContent = "Findings — By Severity";
  }
}

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

  renderAgentMetrics(report);

  els.metaLevel.textContent = `Level ${level}`;
  const health = report.scan_health || "unknown";
  els.metaHealth.innerHTML = `<span class="health-${health}">${health.charAt(0).toUpperCase() + health.slice(1)}</span>`;
  els.metaAccount.textContent = report.aws_account_id || "—";
  els.metaRegion.textContent = report.aws_region || "—";
  els.metaDuration.textContent = `${(report.duration_seconds || 0).toFixed(1)}s`;
  els.metaChecks.textContent = isL2
    ? (report.domains_scanned || []).join(", ") || "—"
    : `${report.total_checks_succeeded || 0}/${report.total_checks_attempted || 0} succeeded`;
  els.metaTime.textContent = formatTime(report.end_time || report.start_time);

  let findings = report.findings || [];
  if (isL2) {
    findings = [...findings].sort((a, b) => (b.impact_score || 0) - (a.impact_score || 0));
  }
  renderFindings(findings, isL2);
  renderErrors(report.scan_errors || []);
}

function metricBadgeClass(ok, warn = false) {
  if (ok) return "metric-pass";
  return warn ? "metric-warn" : "metric-fail";
}

function setMetricBadge(el, ok, warn = false, label = "") {
  if (!el) return;
  el.className = `metric-badge ${metricBadgeClass(ok, warn)}`;
  el.textContent = label || (ok ? "PASS" : warn ? "WARN" : "FAIL");
}

function formatMetricPct(value) {
  if (value == null) return "N/A";
  return `${Math.round(value * 100)}%`;
}

function renderMetricsDetailTable(container, rows) {
  if (!container) return;
  if (!rows.length) {
    container.innerHTML = "";
    return;
  }
  container.innerHTML = `<table><tbody>${rows
    .map(([label, value]) => `<tr><td>${escapeHtml(label)}</td><td>${escapeHtml(String(value))}</td></tr>`)
    .join("")}</tbody></table>`;
}

function renderAgentMetrics(report) {
  const metrics = report?.metrics;
  if (!metrics) {
    if (els.metricsEmpty) els.metricsEmpty.classList.remove("hidden");
    if (els.metricsContent) els.metricsContent.classList.add("hidden");
    if (els.metricsHeadline) els.metricsHeadline.classList.add("hidden");
    return;
  }

  if (els.metricsEmpty) els.metricsEmpty.classList.add("hidden");
  if (els.metricsContent) els.metricsContent.classList.remove("hidden");
  if (els.metricsHeadline) {
    els.metricsHeadline.textContent = metrics.headline || "";
    els.metricsHeadline.classList.toggle("hidden", !metrics.headline);
  }

  const d = metrics.detection || {};
  const s = metrics.speed || {};
  const c = metrics.coverage || {};
  const l2 = metrics.level2;

  if (els.metricPrecision) {
    els.metricPrecision.textContent = formatMetricPct(d.verified_precision_critical);
  }
  setMetricBadge(
    els.metricPrecisionBadge,
    d.verified_precision_critical != null && d.verified_precision_critical >= 0.95
  );

  if (els.metricRecall) {
    const recallText =
      d.verified_recall != null
        ? formatMetricPct(d.verified_recall)
        : d.known_misconfigs_found != null
          ? `${d.known_misconfigs_found}/${d.known_misconfigs_total || 0}`
          : "N/A";
    els.metricRecall.textContent = recallText;
  }
  setMetricBadge(
    els.metricRecallBadge,
    d.verified_recall != null && d.verified_recall >= 0.8
  );

  if (els.metricF1) {
    els.metricF1.textContent = d.f1_score != null ? d.f1_score.toFixed(2) : "N/A";
  }
  setMetricBadge(els.metricF1Badge, d.f1_score != null && d.f1_score >= 0.85);

  if (els.metricConfidence) {
    els.metricConfidence.textContent =
      d.avg_confidence_score != null ? `${d.avg_confidence_score}%` : "N/A";
  }
  setMetricBadge(els.metricConfidenceBadge, (d.avg_confidence_score || 0) >= 75);

  const sevRows = Object.entries(d.findings_by_severity || {}).map(
    ([sev, count]) => [`${sev} findings`, count]
  );
  renderMetricsDetailTable(els.metricsDetectionDetail, [
    ["Known misconfigs found", `${d.known_misconfigs_found ?? 0}/${d.known_misconfigs_total ?? 0}`],
    ["False positives (Critical)", d.false_positives_critical ?? 0],
    ["High confidence (≥80%)", `${d.high_confidence_pct ?? 0}%`],
    ["Est. precision (confidence proxy)", formatMetricPct(d.estimated_precision)],
    ...sevRows,
  ]);

  renderMetricsDetailTable(els.metricsSpeedDetail, [
    ["Scan duration", `${s.scan_duration_seconds ?? 0}s`],
    ["Avg check duration", `${s.avg_check_duration_ms ?? 0}ms`],
    ["Findings per second", s.findings_per_second ?? 0],
    ["Resources scanned", s.resources_scanned ?? 0],
  ]);

  renderMetricsDetailTable(els.metricsCoverageDetail, [
    [
      "Checks succeeded",
      `${c.checks_succeeded ?? 0}/${c.total_checks_attempted ?? 0}`,
    ],
    ["Check success rate", `${((c.check_success_rate ?? 0) * 100).toFixed(1)}%`],
    ["Infrastructure coverage", `${c.infrastructure_coverage_pct ?? 0}%`],
    ["Checks errored", c.checks_errored ?? 0],
  ]);

  if (els.metricsL2Section) {
    const showL2 = Boolean(l2) && reportLevel(report) >= 2;
    els.metricsL2Section.classList.toggle("hidden", !showL2);
    if (showL2 && l2) {
      const domainRows = Object.entries(l2.findings_per_domain || {}).map(([domain, count]) => [
        DOMAIN_LABELS[domain] || domain,
        count,
      ]);
      renderMetricsDetailTable(els.metricsL2Detail, [
        ["Domains succeeded", `${l2.domains_succeeded}/${l2.domains_attempted}`],
        ["Domain success rate", formatMetricPct(l2.domain_success_rate)],
        ["Duplicates removed", `${l2.duplicates_removed} of ${l2.total_before_dedup}`],
        ["Deduplication rate", `${((l2.deduplication_rate ?? 0) * 100).toFixed(1)}%`],
        ...domainRows,
      ]);
    }
  }
}

function renderFindings(findings, isL2 = false) {
  const colSpan = isL2 ? 9 : 7;
  els.findingsBody.innerHTML = "";
  if (!findings.length) {
    els.findingsBody.innerHTML = `<tr><td colspan="${colSpan}" class="table-empty">No findings — environment looks clean for enabled checks.</td></tr>`;
    return;
  }

  findings.forEach((f, idx) => {
    const tr = document.createElement("tr");
    const domainCell = isL2
      ? `<td><span class="domain-tag domain-${f.domain || "unknown"}">${escapeHtml(DOMAIN_LABELS[f.domain] || f.domain || "—")}</span></td>`
      : "";
    const impactCell = isL2
      ? `<td><span class="impact-score">${(f.impact_score || 0).toFixed(1)}</span></td>`
      : "";
    tr.innerHTML = `
      <td><button class="expand-btn" data-idx="${idx}" aria-label="Expand">+</button></td>
      <td><span class="sev sev-${f.severity}">${escapeHtml(f.severity)}</span></td>
      ${impactCell}${domainCell}
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
        <p>Package: ${escapeHtml(evidence.package_name || "—")}@${escapeHtml(evidence.installed_version || "—")}</p>
        <p>CVE IDs: ${escapeHtml((evidence.cve_ids || []).join(", ") || "—")}</p>
        <p>CVSS: ${escapeHtml(String(evidence.cvss_score ?? "—"))}</p>
        <p>Fix: ${escapeHtml((evidence.fix_versions || []).join(", ") || "—")}</p>`;
    }
    if (f.check_id === "secrets_scan") {
      extraDetail = `
        <h4>Secret Details</h4>
        <p>Type: ${escapeHtml(evidence.secret_type || "—")}</p>
        <p>Redacted: <code>${escapeHtml(evidence.value_redacted || "—")}</code></p>
        <p>File: ${escapeHtml(evidence.file_path || "—")} line ${escapeHtml(String(evidence.line_number || "—"))}</p>`;
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
      <p class="finding-meta">ARN: ${escapeHtml(f.resource_arn)}${isL2 ? ` | Domain: ${escapeHtml(f.domain || "—")} | Impact: ${f.impact_score || 0}` : ""}</p>
    </div></td>`;
    els.findingsBody.appendChild(detailTr);
  });

  els.findingsBody.querySelectorAll(".expand-btn").forEach((btn) => {
    btn.addEventListener("click", () => {
      const idx = btn.dataset.idx;
      const row = els.findingsBody.querySelector(`tr[data-detail="${idx}"]`);
      const isHidden = row.classList.toggle("hidden");
      btn.textContent = isHidden ? "+" : "−";
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
    els.scanErrorsList?.classList.add("hidden");
    els.scanErrorsEmpty?.classList.remove("hidden");
    return;
  }
  els.scanErrorsEmpty?.classList.add("hidden");
  els.scanErrorsList?.classList.remove("hidden");
  els.scanErrorsList.innerHTML = errors
    .map((e) => `<li><strong>${escapeHtml(e.check_id)}</strong> (${escapeHtml(e.error_type)}): ${escapeHtml(e.error_message)}</li>`)
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

// ─── Report history list with delete ───────────────────────────────────────

function historyLevelFilter(level) {
  return level == null ? null : level;
}

function sortHistoryItems(items) {
  return items.sort((a, b) => {
    const ta = new Date(a.end_time || a.completed_at || a.started_at || 0).getTime();
    const tb = new Date(b.end_time || b.completed_at || b.started_at || 0).getTime();
    return tb - ta;
  });
}

function bindReportListActions() {
  if (!els.reportList) return;

  els.reportList.querySelectorAll(".report-delete-btn").forEach((btn) => {
    btn.addEventListener("click", (e) => {
      e.preventDefault();
      e.stopPropagation();
      const l3RunId = btn.getAttribute("data-l3-run-id");
      const filename = btn.getAttribute("data-filename");
      if (l3RunId) {
        deleteL3ScanRun(l3RunId);
      } else if (filename) {
        deleteReport(filename);
      }
    });
  });

  els.reportList.querySelectorAll(".report-load-btn").forEach((btn) => {
    btn.addEventListener("click", (e) => {
      e.preventDefault();
      e.stopPropagation();
      const l3RunId = btn.getAttribute("data-l3-run-id");
      if (l3RunId) {
        if (currentLevel !== 3) switchLevel(3);
        showToast("L3 scan run loaded — see Posture & Lifecycle tabs");
        return;
      }
      const filename = btn.getAttribute("data-filename");
      if (!filename) return;
      fetchJSON("/api/reports")
        .then((reports) => {
          const match = reports.find((r) => r.filename === filename);
          const level = match?.scan_level || 1;
          if (currentLevel !== level) switchLevel(level);
          return loadReportByFilename(filename);
        })
        .catch((err) => showToast(err.message, true));
    });
  });
}

async function loadHistory(level = currentLevel) {
  if (!els.reportList) return;
  const filterLevel = historyLevelFilter(level);
  try {
    const includeL3Runs = filterLevel == null || filterLevel === 3;
    const [reports, l3Runs] = await Promise.all([
      fetchJSON("/api/reports"),
      includeL3Runs
        ? fetchJSON("/api/l3/scan-runs").catch(() => [])
        : Promise.resolve([]),
    ]);

    let list = filterLevel == null
      ? reports
      : reports.filter((r) => (r.scan_level || 1) === filterLevel);

    if (includeL3Runs && l3Runs.length) {
      const l3Items = l3Runs.map((run) => ({
        is_l3_run: true,
        scan_run_id: run.id,
        scan_level: 3,
        end_time: run.completed_at || run.started_at,
        total_findings: run.total_findings ?? 0,
        scan_health: run.health || "unknown",
        findings_by_severity: {
          critical: run.critical_count || 0,
          high: run.high_count || 0,
        },
        posture_score: run.posture_score,
      }));
      list = sortHistoryItems([...l3Items, ...list]);
    } else {
      list = sortHistoryItems([...list]);
    }

    if (!list.length) {
      const label = filterLevel == null ? "" : `Level ${filterLevel} `;
      els.reportList.innerHTML = `<div class="report-list-empty">No ${label}reports saved yet.</div>`;
      return;
    }

    els.reportList.innerHTML = list
      .map((r) => {
        const lvl = r.scan_level || 1;
        const sev = r.findings_by_severity || {};
        const critCount = sev.critical || 0;
        const highCount = sev.high || 0;
        const isL3Run = Boolean(r.is_l3_run);
        const fname = r.filename || "";
        const runId = r.scan_run_id || "";
        const timeLabel = isL3Run
          ? formatTime(r.end_time)
          : formatTime(r.end_time);
        const countsLabel = isL3Run
          ? `${r.total_findings} findings · posture ${r.posture_score ?? "—"}/100`
          : `${r.total_findings} findings`;
        const loadBtn = isL3Run
          ? `<button type="button" class="btn btn-copy report-load-btn" data-l3-run-id="${attrEscape(runId)}">View L3</button>`
          : `<button type="button" class="btn btn-copy report-load-btn" data-filename="${attrEscape(fname)}">Load</button>`;
        const deleteAttrs = isL3Run
          ? `data-l3-run-id="${attrEscape(runId)}"`
          : `data-filename="${attrEscape(fname)}"`;

        return `
          <div class="report-item" ${isL3Run ? `data-l3-run-id="${attrEscape(runId)}"` : `data-filename="${attrEscape(fname)}"`}>
            <span class="report-level-badge lvl-${lvl}">L${lvl}</span>
            <span class="report-time">${timeLabel}</span>
            <span class="report-counts">
              ${countsLabel}
              ${critCount > 0 ? `<span class="sev-dot sev-critical">${critCount}C</span>` : ""}
              ${highCount > 0 ? `<span class="sev-dot sev-high">${highCount}H</span>` : ""}
            </span>
            <span class="report-health health-${r.scan_health}">${r.scan_health}</span>
            <div class="report-actions">
              ${loadBtn}
              <button type="button" class="btn btn-danger report-delete-btn" ${deleteAttrs} title="Delete report">Delete</button>
            </div>
          </div>`;
      })
      .join("");

    bindReportListActions();

    if (currentReport?.filename) {
      els.reportList
        .querySelector(`[data-filename="${CSS.escape(currentReport.filename)}"]`)
        ?.classList.add("report-item-active");
    } else if (currentReport?.scan_id) {
      const match = list.find((r) => r.scan_id === currentReport.scan_id);
      if (match?.filename) {
        els.reportList
          .querySelector(`[data-filename="${CSS.escape(match.filename)}"]`)
          ?.classList.add("report-item-active");
      }
    }
  } catch {
    els.reportList.innerHTML = `<div class="report-list-empty">Could not load reports.</div>`;
  }
}

async function deleteReport(filename) {
  if (!filename) return;
  if (!confirm(`Delete "${filename}"?\nThis cannot be undone.`)) return;
  try {
    await fetchJSON(`/api/reports/${encodeURIComponent(filename)}`, { method: "DELETE" });
    showToast("Report deleted");
    if (currentReport?.filename === filename) {
      currentReport = null;
    }
    const histLevel = currentLevel === 3 ? null : currentLevel;
    await loadHistory(histLevel);
    if (currentLevel !== 3) {
      await loadLatestReportForLevel(currentLevel);
    }
  } catch (e) {
    showToast(e.message || "Failed to delete report", true, 6000);
  }
}

async function deleteL3ScanRun(runId) {
  if (!runId) return;
  if (!confirm(`Delete L3 scan run ${runId.slice(0, 8)}…?\nIf this is the last run, all L3 findings are cleared too.`)) return;
  try {
    await fetchJSON(`/api/l3/scan-runs/${encodeURIComponent(runId)}`, { method: "DELETE" });
    showToast("L3 scan run deleted");
    await loadHistory(currentLevel === 3 ? null : currentLevel);
    if (currentLevel === 3) {
      await loadL3Dashboard();
    }
  } catch (e) {
    showToast(e.message || "Failed to delete L3 scan run", true, 6000);
  }
}

async function clearAllReports() {
  const isL3 = currentLevel === 3;
  const label = isL3
    ? "all L3 data (SQLite findings, scan history, and JSON reports)"
    : `all Level ${currentLevel} reports`;
  if (!confirm(`Delete ${label}?\nThis cannot be undone.`)) return;
  try {
    if (isL3) {
      const result = await fetchJSON("/api/l3/reset", { method: "DELETE" });
      showToast(result.message || "Level 3 data reset");
      currentReport = null;
      await loadHistory(null);
      await loadL3Dashboard();
      return;
    }
    const url = `/api/reports?level=${currentLevel}`;
    let clearMsg = "Reports cleared";
    try {
      const result = await fetchJSON(url, { method: "DELETE" });
      clearMsg = result.message || clearMsg;
    } catch (e) {
      throw e;
    }
    showToast(clearMsg);
    currentReport = null;
    await loadHistory(currentLevel);
    await loadLatestReportForLevel(currentLevel);
  } catch (e) {
    showToast(e.message || "Failed to clear reports", true, 6000);
  }
}

// ─── Report loading ─────────────────────────────────────────────────────────

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
  report.filename = filename;
  renderReport(report);
}

// ─── Credentials check ──────────────────────────────────────────────────────

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

// ─── L1/L2 scan polling ─────────────────────────────────────────────────────

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
      const lvl = scanSt.scan_level || activeScanLevel || 1;
      setScanBadge("running", lvl >= 2 ? "L2 Scanning" : "L1 Scanning");
      setButtonsDisabled(true);
      hideActiveTaskPanel();
      const jobLog = jobSt.state === "running" ? (jobSt.log_tail || []).join("\n") : "";
      const scanLog = (scanSt.log_tail || []).join("\n");
      const logText = [jobLog, scanLog].filter(Boolean).join("\n");
      if (jobSt.job_type === "full_demo") {
        hideFullDemoPipeline();
      }
      renderLevelScanPipeline(lvl, scanSt.steps, logText, true);
    } else if (jobRunning) {
      activeMode = "job";
      const jt = jobSt.job_type || "job";
      setScanBadge("running", jt.replace("_", " "));
      setButtonsDisabled(true);
      if (jt === "full_demo") {
        hideActiveTaskPanel();
        switchLevel(1);
        showFullDemoPipeline();
        const logText = (jobSt.log_tail || []).join("\n");
        renderFullDemoPipeline(jobSt.steps, logText, true);
      } else {
        resetLevelScanPipelineIdle(1);
        resetLevelScanPipelineIdle(2);
        els.logOutput.textContent = (jobSt.log_tail || []).join("\n");
        renderJobPipeline(`${JOB_TITLES[jt] || "Working…"} (${jobSt.steps_completed || 0}/${jobSt.steps_total || 0})`, jobSt.steps);
      }
    } else {
      setButtonsDisabled(false);

      if (activeMode === "scan" && scanSt.state === "completed") {
        const completedLevel = scanSt.scan_level || activeScanLevel || 1;
        if (jobSt.state === "running" && jobSt.job_type === "full_demo") {
          finishLevelScanPipeline(completedLevel, scanSt.steps);
          return;
        }
        stopPolling();
        setScanBadge("completed", "Done");
        // Activate the correct tab without triggering an extra report load
        currentLevel = completedLevel;
        els.pageSubtitle.textContent = LEVEL_SUBTITLES[completedLevel] || LEVEL_SUBTITLES[1];
        els.levelTabs.forEach((tab) => {
          tab.classList.toggle("level-tab-active", parseInt(tab.dataset.level, 10) === completedLevel);
        });
        els.level1View.classList.toggle("hidden", completedLevel !== 1);
        els.level2View.classList.toggle("hidden", completedLevel !== 2);
        els.level3View.classList.add("hidden");
        // Load the report
        if (scanSt.report_file) {
          await loadReportByFilename(scanSt.report_file);
        } else {
          await loadLatestReportForLevel(completedLevel);
        }
        await loadHistory(completedLevel);
        const count = currentReport?.total_findings ?? "?";
        showToast(`Level ${completedLevel} scan complete — ${count} finding(s)`);
        finishLevelScanPipeline(completedLevel, scanSt.steps);
      } else if (activeMode === "job" && jobSt.state === "completed") {
        stopPolling();
        setScanBadge("completed", "Done");
        if (jobSt.job_type === "full_demo" && jobSt.result?.report_file) {
          hideActiveTaskPanel();
          renderFullDemoPipeline(jobSt.steps, (jobSt.log_tail || []).join("\n"), false);
          hideFullDemoPipeline();
          if (scanSt.steps?.length) {
            finishLevelScanPipeline(1, scanSt.steps);
          }
          currentLevel = 1;
          els.pageSubtitle.textContent = LEVEL_SUBTITLES[1];
          els.levelTabs.forEach((tab) => tab.classList.toggle("level-tab-active", tab.dataset.level === "1"));
          els.level1View.classList.remove("hidden");
          els.level2View.classList.add("hidden");
          els.level3View.classList.add("hidden");
          await loadReportByFilename(jobSt.result.report_file);
          await loadHistory(1);
          const count = currentReport?.total_findings ?? "?";
          showToast(`Full demo complete — ${count} finding(s) found`);
          if (els.l1ScanLog) els.l1ScanLog.classList.add("hidden");
        } else if (jobSt.job_type === "full_demo") {
          hideFullDemoPipeline();
          renderFullDemoPipeline(jobSt.steps, (jobSt.log_tail || []).join("\n"), false);
          showToast(jobSt.result?.message || "Full demo complete");
        } else if (jobSt.job_type === "verify" && jobSt.result) {
          showToast(`Verify: ${jobSt.result.passed}/${jobSt.result.total} PASS`);
        } else if (jobSt.job_type === "setup") {
          showToast("Misconfigs created successfully");
        } else if (jobSt.job_type === "cleanup") {
          showToast("Test resources deleted");
        } else {
          showToast(jobSt.result?.message || "Operation completed");
        }
        if (jobSt.job_type !== "full_demo") {
          setTimeout(() => hideActiveTaskPanel(), 2000);
        }
      } else if (scanSt.state === "failed") {
        stopPolling();
        setScanBadge("failed", "Failed");
        const failedLevel = scanSt.scan_level || activeScanLevel;
        const ui = getLevelScanEls(failedLevel);
        const errLog = `${(scanSt.log_tail || []).join("\n")}\n\nERROR: ${scanSt.error || "Unknown error"}`;
        if (ui.log) {
          ui.log.textContent = errLog;
          ui.log.classList.remove("hidden");
        }
        renderLevelScanPipeline(failedLevel, scanSt.steps, errLog, false);
        showToast("Scan failed: " + (scanSt.error || "Unknown error"), true, 6000);
      } else if (jobSt.state === "failed") {
        stopPolling();
        setScanBadge("failed", "Failed");
        const errLog = `${(jobSt.log_tail || []).join("\n")}\n\nERROR: ${jobSt.error || ""}`;
        if (jobSt.job_type === "full_demo") {
          hideActiveTaskPanel();
          showFullDemoPipeline();
          renderFullDemoPipeline(jobSt.steps, errLog, false);
          if (els.l1ScanLog) {
            els.l1ScanLog.textContent = errLog;
            els.l1ScanLog.classList.remove("hidden");
          }
        } else {
          els.logOutput.textContent = errLog;
        }
        showToast(jobSt.error || "Operation failed", true, 6000);
      } else {
        setScanBadge("idle", "Idle");
        hideActiveTaskPanel();
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

// ─── Demo / scan actions ─────────────────────────────────────────────────────

async function postDemo(path, label) {
  const isFullDemo = path.includes("/api/demo/full");
  try {
    setButtonsDisabled(true);
    activeMode = "job";
    if (isFullDemo) {
      switchLevel(1);
      hideActiveTaskPanel();
      resetFullDemoPipeline();
      showFullDemoPipeline();
      if (els.l1ScanLog) {
        els.l1ScanLog.textContent = `Starting ${label}...\n`;
        els.l1ScanLog.classList.remove("hidden");
      }
    } else {
      showActiveTaskPanel(`${label}…`);
      els.logOutput.textContent = `Starting ${label}...\n`;
    }
    await fetchJSON(path, { method: "POST" });
    showToast(`${label} started`);
    startPolling();
  } catch (e) {
    setButtonsDisabled(false);
    hideActiveTaskPanel();
    if (isFullDemo) hideFullDemoPipeline();
    showToast(e.message || `Failed: ${label}`, true, 6000);
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
    hideActiveTaskPanel();
    resetScanPipelineProgress(level);
    renderLevelScanPipeline(
      level,
      [{ id: "init", label: "Load configuration", status: "running", detail: "Starting…" }],
      `Starting Level ${level} scan...\n`,
      true
    );
    showToast(`Level ${level} scan started`);
    startPolling();
  } catch (e) {
    showToast(e.message || "Failed to start scan", true, 6000);
  }
}

// ─── L3 Dashboard ──────────────────────────────────────────────────────────

let l3LatestScanRunId = null;

function formatL3TrendLabel(direction, postureScore) {
  const labels = {
    no_data: "Run first scan",
    first_scan:
      postureScore != null
        ? `Baseline · ${Math.round(postureScore)}/100`
        : "Baseline set",
    insufficient_data: "Need 2+ scans",
    improving: "Improving",
    degrading: "Degrading",
    stable: "Stable",
  };
  return labels[direction] || String(direction).replace(/_/g, " ");
}

function l3TrendHintText(trend) {
  if (trend.data_inconsistent) {
    return "Scan history was cleared — reset L3 data or run a new scan";
  }
  if (trend.trend_direction === "first_scan") {
    return "Run again to compare trend direction";
  }
  if (trend.trend_direction === "no_data") {
    return null;
  }
  if (trend.trend_direction === "insufficient_data" && (trend.pipeline?.scan_run_count ?? 0) >= 2) {
    return "Comparing posture across scan history";
  }
  return null;
}

function formatL3PipelineTrend(trend, det) {
  const score = trend.posture_score;
  const dir = trend.trend_direction;
  const scanRuns = trend.pipeline?.scan_run_count ?? 0;
  const delta = trend.score_delta ?? 0;
  const deltaStr = `${delta >= 0 ? "+" : ""}${delta}`;

  if (dir === "first_scan" && score != null) {
    let text = `${Math.round(score)}/100 baseline · run again for direction`;
    if (det.f1_score != null) text += ` · F1 ${det.f1_score.toFixed(2)}`;
    return text;
  }
  if (scanRuns >= 2 && score != null) {
    const dirLabel = formatL3TrendLabel(dir, score);
    let text = `Posture ${Math.round(score)}/100 · ${dirLabel} (${deltaStr})`;
    if (det.f1_score != null) text += ` · F1 ${det.f1_score.toFixed(2)}`;
    return text;
  }
  if (score != null) {
    return `Posture ${Math.round(score)}/100 · ${formatL3TrendLabel(dir, score)}`;
  }
  return "Run 2+ scans to see trend direction";
}

async function loadL3Dashboard() {
  try {
    const [trend, daemonSt] = await Promise.all([
      fetchJSON("/api/l3/trend"),
      fetchJSON("/api/l3/daemon/status"),
    ]);

    // Determine the latest scan run id for health filtering
    l3LatestScanRunId = trend.latest_scan_run?.id || null;

    const [findings, health, audit] = await Promise.all([
      fetchJSON(`/api/l3/findings${buildL3FindingsQuery()}`),
      fetchJSON(`/api/l3/scan-health${l3LatestScanRunId ? `?scan_run_id=${l3LatestScanRunId}` : ""}`),
      fetchJSON("/api/l3/audit?limit=50"),
    ]);

    renderL3Pipeline(trend, daemonSt, health);
    renderL3AgentMetrics(trend.agent_metrics);

    // KPIs
    const hasData = trend.has_scan_data || (trend.pipeline?.total_findings ?? 0) > 0;
    const openCritical = trend.open_critical_count ?? trend.open_findings_by_severity?.critical ?? 0;
    const slaBreaches = trend.sla_breached_count ?? 0;

    if (!hasData) {
      els.l3PostureScore.textContent = "—";
      els.l3TrendDirection.textContent = "Run first scan";
      els.l3TrendDirection.className = "kpi-value trend-no_data";
      if (els.l3TrendHint) {
        els.l3TrendHint.textContent = "";
        els.l3TrendHint.classList.add("hidden");
      }
      els.l3OpenCritical.textContent = "—";
      els.l3SlaBreaches.textContent = "—";
    } else {
      els.l3PostureScore.textContent =
        trend.posture_score != null ? `${Math.round(trend.posture_score)}/100` : "—";
      const dir = trend.trend_direction || "—";
      els.l3TrendDirection.textContent = formatL3TrendLabel(dir, trend.posture_score);
      els.l3TrendDirection.className = `kpi-value trend-${dir}`;
      const hint = l3TrendHintText(trend);
      if (els.l3TrendHint) {
        els.l3TrendHint.textContent = hint || "";
        els.l3TrendHint.classList.toggle("hidden", !hint);
        els.l3TrendHint.classList.toggle("kpi-hint-warn", Boolean(trend.data_inconsistent));
      }
      els.l3OpenCritical.textContent = openCritical;
      els.l3SlaBreaches.textContent = slaBreaches;
    }

    const daemonRunning = daemonSt.daemon_state === "running";
    const l3ScanRunning = daemonSt.l3_scan_state === "running";
    els.l3DaemonStatus.textContent = daemonRunning ? "Running" : "Stopped";
    if (els.stopDaemonBtn) els.stopDaemonBtn.disabled = !daemonRunning;
    if (els.startDaemonBtn) els.startDaemonBtn.disabled = daemonRunning || l3ScanRunning;
    if (els.runL3OnceBtn) els.runL3OnceBtn.disabled = daemonRunning || l3ScanRunning;
    if (els.resetL3Btn) els.resetL3Btn.disabled = l3ScanRunning;

    // Latest run meta
    const latest = trend.latest_scan_run;
    if (latest) {
      els.l3MetaHealth.innerHTML = `<span class="health-${latest.health}">${latest.health || "—"}</span>`;
      els.l3MetaPosture.textContent = latest.posture_score != null ? `${latest.posture_score}/100` : "—";
      els.l3MetaLifecycle.textContent = `${latest.new_findings ?? 0} new / ${latest.updated_findings ?? 0} updated`;
      els.l3MetaStarted.textContent = formatTime(latest.started_at);
    } else {
      els.l3MetaHealth.textContent = "—";
      els.l3MetaPosture.textContent = "—";
      els.l3MetaLifecycle.textContent = "—";
      els.l3MetaStarted.textContent = "—";
    }

    els.l3MetaNextRun.textContent = daemonSt.next_run_time ? formatTime(daemonSt.next_run_time) : "—";
    els.l3MetaSlack.textContent = trend.slack_configured ? "Configured" : "Not configured";

    // Posture history
    if (trend.scan_history?.length) {
      els.l3TrendHistory.innerHTML = trend.scan_history
        .slice(-10)
        .map((r) =>
          `<div class="trend-history-row">
            <span>${formatTime(r.timestamp)}</span>
            <span>${r.posture_score ?? "N/A"}/100 · ${r.health || "?"} · +${r.findings?.new ?? 0} new</span>
          </div>`
        )
        .join("");
    } else {
      els.l3TrendHistory.textContent = "No scan history yet.";
    }

    // Activity log
    if (daemonSt.log_tail?.length) {
      els.l3LogOutput.textContent = daemonSt.log_tail.join("\n");
    }

    renderL3Findings(findings);
    renderL3Health(health);
    renderL3Audit(audit);
  } catch (e) {
    console.error("L3 load error", e);
  }
}

function buildL3FindingsQuery() {
  const MAP = {
    open: "?status=open",
    reopened: "?status=re-opened",
    resolved: "?status=resolved",
  };
  return MAP[currentL3Filter] || "";
}

function inferL3PipelineStep(logTail, scanRunning = false) {
  const log = extractCurrentScanLog(logTail);
  let idx = 0;

  for (const [phase, stepId] of Object.entries(L3_PHASE_TO_STEP)) {
    if (log.includes(`[l3-phase] ${phase}`)) {
      const stepIdx = L3_PIPELINE_ORDER.findIndex((s) => s.id === stepId);
      if (stepIdx >= 0) idx = Math.max(idx, stepIdx);
    }
  }

  if (idx === 0 && /=== L3 Scan .+ started ===|Starting Level 3/i.test(log)) {
    idx = 0;
  }

  if (scanRunning) {
    l3PipelineStepIndex = Math.max(l3PipelineStepIndex, idx);
    return L3_PIPELINE_ORDER[l3PipelineStepIndex].id;
  }

  l3PipelineStepIndex = idx;
  return L3_PIPELINE_ORDER[idx].id;
}

function getL3StepMeta(stepId) {
  return L3_PIPELINE_ORDER.find((s) => s.id === stepId) || L3_PIPELINE_ORDER[0];
}

function highlightL3PipelineSteps(activeStepId, scanRunning) {
  const activeIdx = L3_PIPELINE_ORDER.findIndex((s) => s.id === activeStepId);
  L3_PIPELINE_ORDER.forEach((step, i) => {
    const el = document.getElementById(step.id);
    if (!el) return;
    el.classList.remove("l3-step-active", "l3-step-done", "l3-step-pending");
    if (scanRunning) {
      if (i < activeIdx) el.classList.add("l3-step-done");
      else if (i === activeIdx) el.classList.add("l3-step-active");
      else el.classList.add("l3-step-pending");
    } else if (i === activeIdx) {
      el.classList.add("l3-step-active");
    }
  });

  if (els.l3PipelineStatus) {
    if (scanRunning) {
      const meta = getL3StepMeta(activeStepId);
      els.l3PipelineStatus.textContent = `Running — Step ${meta.num}: ${meta.name}`;
      els.l3PipelineStatus.classList.remove("hidden");
    } else {
      els.l3PipelineStatus.classList.add("hidden");
      els.l3PipelineStatus.textContent = "";
    }
  }
}

function renderL3AgentMetrics(agentMetrics) {
  const d = agentMetrics?.detection || {};
  const l3 = agentMetrics?.level3 || {};

  if (els.l3MetricF1) {
    els.l3MetricF1.textContent = d.f1_score != null ? d.f1_score.toFixed(2) : "—";
  }
  if (els.l3MetricSlaCompliance) {
    els.l3MetricSlaCompliance.textContent =
      l3.sla_compliance_rate != null
        ? `${Math.round(l3.sla_compliance_rate * 100)}%`
        : "—";
  }
  if (els.l3MetricReliability) {
    els.l3MetricReliability.textContent =
      l3.scan_reliability_rate != null
        ? `${Math.round(l3.scan_reliability_rate * 100)}%`
        : "—";
  }
  if (els.l3MetricResolution) {
    els.l3MetricResolution.textContent =
      l3.resolution_rate != null ? `${Math.round(l3.resolution_rate * 100)}%` : "—";
  }
}

function renderL3Pipeline(trend, daemonSt, health) {
  const pipe = trend.pipeline || {};
  const latest = trend.latest_scan_run;
  const agentMetrics = trend.agent_metrics;
  const daemonRunning = daemonSt.daemon_state === "running";
  const scanRunning = daemonSt.l3_scan_state === "running";
  const scanRuns = pipe.scan_run_count ?? 0;
  const l3m = agentMetrics?.level3 || {};
  const det = agentMetrics?.detection || {};

  let scanMetric = "No scans yet — click Run L3 Once";
  if (scanRunning) {
    scanMetric = "⟳ Scan in progress…";
  } else if (scanRuns > 0) {
    const next = daemonSt.next_run_time ? formatTime(daemonSt.next_run_time) : "manual";
    scanMetric = `${scanRuns} scan run(s)`;
    if (l3m.total_scan_runs) {
      scanMetric += ` · reliability ${Math.round((l3m.scan_reliability_rate || 0) * 100)}% (${l3m.successful_scan_runs}/${l3m.total_scan_runs})`;
    }
    if (daemonRunning) scanMetric += ` · Daemon ON · next: ${next}`;
    else scanMetric += " · Daemon OFF";
  }
  if (els.l3MetricScans) els.l3MetricScans.textContent = scanMetric;

  const totalFindings = pipe.total_findings ?? 0;
  if (els.l3MetricDb) {
    els.l3MetricDb.textContent = totalFindings > 0
      ? `${totalFindings} finding(s) in ${pipe.db_path || "storage/findings.db"}`
      : "Empty — run first scan to populate";
  }

  const newCount = latest?.new_findings ?? 0;
  const updatedCount = latest?.updated_findings ?? 0;
  if (els.l3MetricDedup) {
    if (scanRuns === 0) {
      els.l3MetricDedup.textContent = "Waiting for first scan";
    } else if (scanRuns === 1) {
      els.l3MetricDedup.textContent = `First run: ${newCount} new record(s) created`;
    } else {
      els.l3MetricDedup.textContent = `Last run: ${newCount} new, ${updatedCount} updated (duplicates merged)`;
    }
  }

  const lc = pipe.lifecycle_by_status || {};
  if (els.l3MetricLifecycle) {
    els.l3MetricLifecycle.textContent = totalFindings > 0
      ? `opened ${lc.opened ?? 0} · updated ${lc.updated ?? 0} · resolved ${lc.resolved ?? 0} · re-opened ${lc["re-opened"] ?? 0}`
      : "No lifecycle data yet";
  }

  const slaBreaches = trend.sla_breached_count ?? 0;
  if (els.l3MetricSla) {
    let slaText =
      slaBreaches > 0
        ? `${slaBreaches} SLA breach(es) · Critical deadline 24h`
        : "No breaches · Critical SLA 24h active";
    if (l3m.sla_compliance_rate != null) {
      slaText += ` · compliance ${Math.round(l3m.sla_compliance_rate * 100)}%`;
    }
    els.l3MetricSla.textContent = slaText;
  }

  const escalated = pipe.escalated_count ?? 0;
  const slackOk = trend.slack_configured;
  if (els.l3MetricSlack) {
    if (!slackOk) {
      els.l3MetricSlack.textContent = "Set SLACK_WEBHOOK_URL in .env";
    } else if (escalated > 0) {
      els.l3MetricSlack.textContent = `${escalated} Critical alert(s) sent · webhook configured`;
    } else {
      els.l3MetricSlack.textContent = "Webhook ready · no Criticals escalated yet";
    }
  }

  if (els.l3MetricTrend) {
    els.l3MetricTrend.textContent = formatL3PipelineTrend(trend, det);
  }

  // Highlight active pipeline step
  let activeStepId = "l3StepScans";
  if (scanRunning) {
    activeStepId = inferL3PipelineStep(daemonSt.log_tail, true);
  } else if (totalFindings > 0) {
    activeStepId = "l3StepTrend";
    resetL3PipelineProgress();
  }
  highlightL3PipelineSteps(activeStepId, scanRunning);
}

function statusBadgeClass(status) {
  const cleaned = (status || "opened").replace("-", "");
  return `status-badge status-${status || "opened"}`;
}

function renderL3Findings(findings) {
  if (!els.l3FindingsBody) return;
  if (!findings?.length) {
    const msg = currentL3Filter === "all" ? "No findings in database yet." : `No ${currentL3Filter} findings.`;
    els.l3FindingsBody.innerHTML = `<tr><td colspan="7" class="table-empty">${msg}</td></tr>`;
    return;
  }
  els.l3FindingsBody.innerHTML = findings
    .map((f) => {
      const slaCell = f.sla_breached
        ? `<span class="sla-breached">BREACHED</span>`
        : formatTime(f.sla_deadline);
      return `<tr>
        <td><span class="${statusBadgeClass(f.status)}">${escapeHtml(f.status)}</span></td>
        <td><span class="sev sev-${f.severity}">${escapeHtml(f.severity)}</span></td>
        <td><code>${escapeHtml(f.check_id)}</code></td>
        <td class="resource-mono">${escapeHtml(f.resource_id)}</td>
        <td>${formatTime(f.first_seen)}</td>
        <td>${formatTime(f.last_seen)}</td>
        <td>${slaCell}</td>
      </tr>`;
    })
    .join("");
}

function renderL3Health(health) {
  if (!els.l3HealthBody) return;
  if (!health?.length) {
    els.l3HealthBody.innerHTML = `<tr><td colspan="4" class="table-empty">No scan health data yet.</td></tr>`;
    return;
  }
  els.l3HealthBody.innerHTML = health
    .map((h) => `<tr>
      <td class="${h.status === "success" ? "health-success" : "health-error"}">${escapeHtml(h.status)}</td>
      <td><code>${escapeHtml(h.check_id)}</code></td>
      <td>${escapeHtml(h.domain)}</td>
      <td class="error-text">${escapeHtml(h.error_message || "—")}</td>
    </tr>`)
    .join("");
}

function renderL3Audit(audit) {
  if (!els.l3AuditBody) return;
  if (!audit?.length) {
    els.l3AuditBody.innerHTML = `<tr><td colspan="4" class="table-empty">No audit entries yet.</td></tr>`;
    return;
  }
  els.l3AuditBody.innerHTML = audit
    .map((a) => `<tr>
      <td>${formatTime(a.timestamp)}</td>
      <td>${escapeHtml(a.actor)}</td>
      <td><code>${escapeHtml(a.action)}</code></td>
      <td>${escapeHtml(a.entity_type || "")}:${escapeHtml(a.entity_id || "")}</td>
    </tr>`)
    .join("");
}

// ─── L3 polling ──────────────────────────────────────────────────────────────

function startL3Polling() {
  stopL3Polling();
  l3PollInterval = setInterval(async () => {
    if (currentLevel !== 3) return;
    try {
      const st = await fetchJSON("/api/l3/daemon/status");
      if (st.l3_scan_state === "running" && prevL3ScanState !== "running") {
        resetL3PipelineProgress();
      }
      prevL3ScanState = st.l3_scan_state;
      if (st.l3_scan_state === "running") {
        setScanBadge("running", "L3 Scanning");
        highlightL3PipelineSteps(inferL3PipelineStep(st.log_tail, true), true);
      } else if (st.daemon_state === "running") {
        setScanBadge("running", "Daemon Active");
      }
      await loadL3Dashboard();
    } catch (e) {
      console.error("L3 poll error", e);
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
    resetL3PipelineProgress();
    await fetchJSON("/api/l3/run", { method: "POST" });
    setScanBadge("running", "L3 Scanning");
    setButtonsDisabled(true);
    highlightL3PipelineSteps("l3StepScans", true);
    showToast("Level 3 scan started");
    startL3Polling();
    pollL3Status();
  } catch (e) {
    showToast(e.message || "Failed to start L3 scan", true, 6000);
  }
}

async function startDaemon() {
  try {
    await fetchJSON("/api/l3/daemon/start", { method: "POST" });
    showToast("Daemon started — scans will run automatically");
    setScanBadge("running", "Daemon Active");
    startL3Polling();
    await loadL3Dashboard();
  } catch (e) {
    showToast(e.message || "Failed to start daemon", true, 6000);
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
    showToast(e.message || "Failed to stop daemon", true, 6000);
  }
}

async function pollL3Status() {
  const interval = setInterval(async () => {
    try {
      const st = await fetchJSON("/api/l3/daemon/status");
      if (st.log_tail?.length) {
        els.l3LogOutput.textContent = st.log_tail.join("\n");
      }
      if (st.l3_scan_state === "running") {
        highlightL3PipelineSteps(inferL3PipelineStep(st.log_tail, true), true);
        return;
      }

      clearInterval(interval);
      setButtonsDisabled(false);
      if (st.l3_scan_state === "completed") {
        setScanBadge("completed", "Done");
        const res = st.last_result || {};
        const count = res.lifecycle
          ? `${res.lifecycle.new} new, ${res.lifecycle.updated} updated`
          : "complete";
        showToast(`Level 3 scan complete — ${count}`);
      } else if (st.l3_scan_state === "failed") {
        setScanBadge("failed", "Failed");
        showToast(st.error || "L3 scan failed", true, 6000);
      }
      await loadL3Dashboard();
      if (currentLevel === 3) {
        await loadHistory(null);
      }
      activeMode = null;
    } catch (e) {
      console.error("L3 poll error", e);
    }
  }, 1500);
}

// ─── L3 data tabs (Findings / Health / Audit) ───────────────────────────────

const L3_DATA_PANES = {
  findings: "l3TabFindings",
  health: "l3TabHealth",
  audit: "l3TabAudit",
};

function switchL3DataTab(tabId) {
  document.querySelectorAll(".l3-data-tab").forEach((tab) => {
    const active = tab.dataset.l3Tab === tabId;
    tab.classList.toggle("l3-data-tab-active", active);
    tab.setAttribute("aria-selected", active ? "true" : "false");
  });
  Object.entries(L3_DATA_PANES).forEach(([id, paneId]) => {
    const pane = document.getElementById(paneId);
    if (!pane) return;
    const active = id === tabId;
    pane.classList.toggle("hidden", !active);
    pane.classList.toggle("l3-data-pane-active", active);
  });
}

document.querySelectorAll(".l3-data-tab").forEach((tab) => {
  tab.addEventListener("click", () => switchL3DataTab(tab.dataset.l3Tab));
});

// Findings status sub-filters (scoped to findings pane only)
document.querySelectorAll("#l3TabFindings .filter-tab").forEach((tab) => {
  tab.addEventListener("click", async () => {
    document.querySelectorAll("#l3TabFindings .filter-tab").forEach((t) => t.classList.remove("filter-tab-active"));
    tab.classList.add("filter-tab-active");
    currentL3Filter = tab.dataset.filter;
    try {
      const findings = await fetchJSON(`/api/l3/findings${buildL3FindingsQuery()}`);
      renderL3Findings(findings);
    } catch (e) {
      console.error("L3 filter error", e);
    }
  });
});

// ─── Event listeners ────────────────────────────────────────────────────────

els.levelTabs.forEach((tab) => {
  tab.addEventListener("click", () => {
    const level = parseInt(tab.dataset.level, 10);
    switchLevel(level);
    if (level === 3) {
      fetchJSON("/api/l3/daemon/status").then((s) => {
        if (s.daemon_state === "running") startL3Polling();
      }).catch(() => {});
    } else {
      stopL3Polling();
    }
  });
});

function bindClick(el, handler) {
  if (el) el.addEventListener("click", handler);
}

bindClick(els.fullDemoBtn, () => postDemo("/api/demo/full", "Full Level 1 Demo"));
bindClick(els.setupBtn, () => postDemo("/api/demo/setup", "Create Misconfigs"));
bindClick(els.verifyBtn, () => postDemo("/api/demo/verify-run", "Verify Resources"));
bindClick(els.cleanupBtn, () => {
  if (!confirm("Delete all test S3 buckets, security groups, and IAM user?")) return;
  postDemo("/api/demo/cleanup", "Cleanup");
});

bindClick(els.runScanL1Btn, () => startScan(1));
bindClick(els.runScanL2Btn, () => startScan(2));
if (els.runL3OnceBtn) els.runL3OnceBtn.addEventListener("click", () => runL3Once());
if (els.startDaemonBtn) els.startDaemonBtn.addEventListener("click", () => startDaemon());
if (els.stopDaemonBtn) els.stopDaemonBtn.addEventListener("click", () => stopDaemon());
async function refreshCurrentView() {
  try {
    await updateCredentials();
    const [health, scanSt, jobSt, daemonSt] = await Promise.all([
      fetchJSON("/api/health"),
      fetchJSON("/api/scans/status"),
      fetchJSON("/api/jobs/status"),
      fetchJSON("/api/l3/daemon/status"),
    ]);

    if (scanSt.state === "running") {
      const lvl = scanSt.scan_level || activeScanLevel;
      setScanBadge("running", lvl >= 2 ? "L2 Scanning" : "L1 Scanning");
    } else if (jobSt.state === "running") {
      const jt = jobSt.job_type || "job";
      setScanBadge("running", jt.replace("_", " "));
    } else if (daemonSt.l3_scan_state === "running") {
      setScanBadge("running", "L3 Scanning");
    } else if (daemonSt.daemon_state === "running") {
      setScanBadge("running", "Daemon Active");
    } else {
      setScanBadge("idle", "Idle");
    }

    if (currentLevel === 3) {
      await Promise.all([loadHistory(null), loadL3Dashboard()]);
    } else {
      await loadHistory(currentLevel);
      await loadLatestReportForLevel(currentLevel);
    }
    showToast("Dashboard refreshed");
  } catch (e) {
    showToast(e.message || "Refresh failed", true, 6000);
  }
}

bindClick(els.refreshL3Btn, () => refreshCurrentView());

async function resetL3Data() {
  const msg =
    "Reset all Level 3 data?\n\n" +
    "This clears posture history, findings, audit trail, and scan health from SQLite. " +
    "Trend report files are also deleted. The next L3 scan will run as if it's the first time.";
  if (!confirm(msg)) return;
  try {
    const result = await fetchJSON("/api/l3/reset", { method: "DELETE" });
    showToast(result.message || "Level 3 data reset");
    currentL3Filter = "all";
    document.querySelectorAll("#l3TabFindings .filter-tab").forEach((t) => {
      t.classList.toggle("filter-tab-active", t.dataset.filter === "all");
    });
    await loadL3Dashboard();
  } catch (e) {
    showToast(e.message || "Failed to reset L3 data", true, 6000);
  }
}

if (els.resetL3Btn) els.resetL3Btn.addEventListener("click", () => resetL3Data());
bindClick(els.clearReportsBtn, () => clearAllReports());

bindClick(els.refreshBtn, () => refreshCurrentView());

// ─── Init ────────────────────────────────────────────────────────────────────

async function init() {
  await updateCredentials();
  try {
    const health = await fetchJSON("/api/health");
    if (health.scan_state === "running" || health.job_state === "running") {
      activeMode = health.scan_state === "running" ? "scan" : "job";
      if (health.job_state === "running" && health.active_job !== "full_demo") {
        showActiveTaskPanel("Task in progress…");
      }
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
