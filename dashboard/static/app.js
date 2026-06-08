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
  kpiGridRow: document.getElementById("kpiGridRow"),
  themeToggle: document.getElementById("themeToggle"),
  runScanL1BtnSecondary: document.getElementById("runScanL1BtnSecondary"),
  l1CheckBreakdown: document.getElementById("l1CheckBreakdown"),
  l1AssetTotal: document.getElementById("l1AssetTotal"),
  l1AssetCritical: document.getElementById("l1AssetCritical"),
  l1AssetResources: document.getElementById("l1AssetResources"),
  l1AssetHealth: document.getElementById("l1AssetHealth"),
  l1AssetChecksSub: document.getElementById("l1AssetChecksSub"),
  l1AssetHighSub: document.getElementById("l1AssetHighSub"),
  l1AssetRegionSub: document.getElementById("l1AssetRegionSub"),
  l1AssetDurationSub: document.getElementById("l1AssetDurationSub"),
  l1ReportsGenerated: document.getElementById("l1ReportsGenerated"),
  l1ReportsProcessed: document.getElementById("l1ReportsProcessed"),
  l1ReportsEnriched: document.getElementById("l1ReportsEnriched"),
  l1ReportsPending: document.getElementById("l1ReportsPending"),
  l1IssuesTotalCount: document.getElementById("l1IssuesTotalCount"),
  l1PctLow: document.getElementById("l1PctLow"),
  l1PctMedium: document.getElementById("l1PctMedium"),
  l1PctCritical: document.getElementById("l1PctCritical"),
  l1BarLow: document.getElementById("l1BarLow"),
  l1BarMedium: document.getElementById("l1BarMedium"),
  l1BarCritical: document.getElementById("l1BarCritical"),
  dashboardContent: document.getElementById("dashboardContent"),
  runScanL1Btn: document.getElementById("runScanL1Btn"),
  runScanL2Btn: document.getElementById("runScanL2Btn"),
  refreshBtn: document.getElementById("refreshBtn"),
  scanStatusBadge: document.getElementById("scanStatusBadge"),
  reportList: document.getElementById("reportList"),
  reportHistoryPanel: document.getElementById("reportHistoryPanel"),
  reportHistoryToggle: document.getElementById("reportHistoryToggle"),
  reportHistoryBody: document.getElementById("reportHistoryBody"),
  reportHistoryChevron: document.getElementById("reportHistoryChevron"),
  reportHistoryTitle: document.getElementById("reportHistoryTitle"),
  reportHistoryDesc: document.getElementById("reportHistoryDesc"),
  exportReportPdfBtn: document.getElementById("exportReportPdfBtn"),
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
  demoPipelineChecklist: document.getElementById("demoPipelineChecklist"),
  l1DemoPipelineLog: document.getElementById("l1DemoPipelineLog"),
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
  metricsChartHost: document.getElementById("metricsChartHost"),
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
  l3PostureChartHost: document.getElementById("l3PostureChartHost"),
  l3ActivityFeed: document.getElementById("l3ActivityFeed"),
  l3PostureCenterGrid: document.getElementById("l3PostureCenterGrid"),
  l3CriticalFindingsList: document.getElementById("l3CriticalFindingsList"),
  l3ScanPipelineHero: document.getElementById("l3ScanPipelineHero"),
  l3ScanPipelineBadge: document.getElementById("l3ScanPipelineBadge"),
  l3ScanStatusBadge: document.getElementById("l3ScanStatusBadge"),
  l3AgentHealthDot: document.getElementById("l3AgentHealthDot"),
  l3AgentHealthLabel: document.getElementById("l3AgentHealthLabel"),
  l3MetaDuration: document.getElementById("l3MetaDuration"),
  l3MetaSuccessRate: document.getElementById("l3MetaSuccessRate"),
  l3PostureProgress: document.getElementById("l3PostureProgress"),
  l3F1Progress: document.getElementById("l3F1Progress"),
  l3SlaComplianceProgress: document.getElementById("l3SlaComplianceProgress"),
  l3ReliabilityProgress: document.getElementById("l3ReliabilityProgress"),
  l3ResolutionProgress: document.getElementById("l3ResolutionProgress"),
  l3LiveBadge: document.getElementById("l3LiveBadge"),
  l3SchedulePanel: document.getElementById("l3SchedulePanel"),
  l3ScheduleCustomFields: document.getElementById("l3ScheduleCustomFields"),
  l3CustomIntervalHours: document.getElementById("l3CustomIntervalHours"),
  l3CustomIntervalMinutes: document.getElementById("l3CustomIntervalMinutes"),
  l3ScheduleActiveLabel: document.getElementById("l3ScheduleActiveLabel"),
  l3ScheduleActiveBadge: document.getElementById("l3ScheduleActiveBadge"),
  l3MetaSchedule: document.getElementById("l3MetaSchedule"),
};

const L3_SCHEDULE_STORAGE_KEY = "l3SchedulePrefs";
const L3_DEFAULT_INTERVAL_HOURS = 6;

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

const L3_SCAN_FLOW_STAGES = [
  { id: "infra", short: "1", label: "Infrastructure Scan", log: "domain_aws" },
  { id: "iam", short: "2", label: "IAM Audit", log: "iam_" },
  { id: "s3", short: "3", label: "S3 Audit", log: "s3_" },
  { id: "api", short: "4", label: "API Security", log: "domain_api" },
  { id: "deps", short: "5", label: "Dependency CVEs", log: "domain_deps" },
  { id: "secrets", short: "6", label: "Secret Detection", log: "domain_secrets" },
  { id: "risk", short: "7", label: "Risk Correlation", log: "dedup" },
  { id: "remediation", short: "8", label: "Remediation Engine", log: "reports" },
];

const L3_POSTURE_WIDGETS = [
  { id: "s3", title: "Public S3 Buckets", match: (f) => /^s3_public/.test(f.check_id || "") },
  { id: "sg", title: "Exposed Security Groups", match: (f) => /^sg_open/.test(f.check_id || "") },
  { id: "mfa", title: "MFA Disabled Users", match: (f) => /mfa/.test(f.check_id || "") && f.severity !== "info" },
  { id: "encrypt", title: "Unencrypted Resources", match: (f) => /unencrypted|encryption_disabled/.test(f.check_id || "") },
  { id: "cve", title: "High CVSS Vulnerabilities", match: (f) => f.check_id === "dependency_cve" },
  { id: "secrets", title: "Secrets Detected", match: (f) => f.check_id === "secrets_scan" },
];

let l3PipelineStepIndex = 0;
let scanPipelineStepIndex = { l1: 0, l2: 0 };

const L2_STEP_MIN_MS = 2000;
const L2_STEP_MAX_MS = 5000;

let l2DisplayTimeline = {
  displayIdx: 0,
  backendIdx: 0,
  stageStartedAt: 0,
  stageDuration: 3000,
};

let l2PipelineViz = null;
let l2TimelineTimer = null;
let l2Flushing = false;
let lastL2ScanSteps = null;
let prevL2DisplayIdx = -1;

function randomL2StageDuration() {
  return L2_STEP_MIN_MS + Math.random() * (L2_STEP_MAX_MS - L2_STEP_MIN_MS);
}

function resetL2DisplayTimeline() {
  l2DisplayTimeline = {
    displayIdx: 0,
    backendIdx: 0,
    stageStartedAt: Date.now(),
    stageDuration: randomL2StageDuration(),
  };
  l2Flushing = false;
  prevL2DisplayIdx = -1;
}

function inferScanPipelineBackendIndex(level, steps, scanRunning) {
  const order = getScanPipelineOrder(level);
  let idx = 0;
  if (!steps?.length) return 0;
  if (scanRunning) {
    for (let i = 0; i < order.length; i++) {
      const status = scanPhaseStatus(order[i], steps, level);
      if (status === "running" || status === "failed") return i;
      if (status === "completed") idx = i;
    }
    return idx;
  }
  for (let i = 0; i < order.length; i++) {
    if (scanPhaseStatus(order[i], steps, level) !== "pending") idx = i;
  }
  return idx;
}

function tickL2DisplayTimeline(backendIdx, scanRunning) {
  const t = l2DisplayTimeline;
  t.backendIdx = backendIdx;
  const now = Date.now();
  const elapsed = now - t.stageStartedAt;
  if (elapsed < t.stageDuration) return t.displayIdx;

  if (l2Flushing && t.displayIdx < L2_PIPELINE_ORDER.length - 1) {
    t.displayIdx += 1;
    t.stageStartedAt = now;
    t.stageDuration = randomL2StageDuration();
  } else if (scanRunning && t.displayIdx < backendIdx) {
    t.displayIdx += 1;
    t.stageStartedAt = now;
    t.stageDuration = randomL2StageDuration();
  }
  return t.displayIdx;
}

function getL2StepStatuses(steps, displayIdx, scanRunning) {
  return L2_PIPELINE_ORDER.map((phase, i) => {
    const st = steps?.length ? scanPhaseStatus(phase, steps, 2) : "pending";
    if (i < displayIdx) return st === "failed" ? "failed" : "completed";
    if (i === displayIdx) {
      if (scanRunning || l2Flushing) return st === "failed" ? "failed" : "running";
      return st === "failed" ? "failed" : st === "completed" ? "completed" : "pending";
    }
    return "pending";
  });
}

function ensureL2PipelineViz() {
  if (l2PipelineViz) return l2PipelineViz;
  const host = document.getElementById("l2PipelineVizHost");
  if (!host || !window.L2PipelineViz) return null;
  l2PipelineViz = new window.L2PipelineViz(host);
  document.getElementById("l2VizZoomIn")?.addEventListener("click", () => l2PipelineViz.zoomIn());
  document.getElementById("l2VizZoomOut")?.addEventListener("click", () => l2PipelineViz.zoomOut());
  document.getElementById("l2VizReset")?.addEventListener("click", () => l2PipelineViz.resetView());
  return l2PipelineViz;
}

function stopL2TimelineTimer() {
  if (l2TimelineTimer) {
    clearInterval(l2TimelineTimer);
    l2TimelineTimer = null;
  }
}

function startL2TimelineTimer() {
  if (l2TimelineTimer) return;
  l2TimelineTimer = setInterval(() => {
    if (!lastL2ScanSteps?.length) return;
    const scanRunning = !l2Flushing && activeMode === "scan" && activeScanLevel >= 2;
    const backendIdx = inferScanPipelineBackendIndex(2, lastL2ScanSteps, scanRunning || l2Flushing);
    const prev = l2DisplayTimeline.displayIdx;
    tickL2DisplayTimeline(backendIdx, scanRunning);
    if (l2DisplayTimeline.displayIdx !== prev || l2Flushing) {
      renderLevelScanPipeline(2, lastL2ScanSteps, "", scanRunning || l2Flushing);
    }
    if (l2Flushing && l2DisplayTimeline.displayIdx >= L2_PIPELINE_ORDER.length - 1) {
      l2Flushing = false;
      stopL2TimelineTimer();
      finalizeL2PipelineUI(lastL2ScanSteps);
    }
  }, 180);
}

function finalizeL2PipelineUI(steps) {
  const order = L2_PIPELINE_ORDER;
  order.forEach((step) => {
    const el = document.getElementById(step.id);
    if (el) {
      el.classList.remove("l3-step-active", "l3-step-pending", "l3-step-failed");
      el.classList.add("l3-step-done");
    }
  });
  ensureL2PipelineViz()?.update(8, getL2StepStatuses(steps, 8, false), false);
  const ui = getLevelScanUi(2);
  if (ui.status) {
    ui.status.classList.add("hidden");
    ui.status.textContent = "";
  }
  if (ui.log) ui.log.classList.add("hidden");
}

function resetL2PipelineFlowViz() {
  resetL2DisplayTimeline();
  lastL2ScanSteps = null;
  stopL2TimelineTimer();
  const panel = document.getElementById("l2ScanPipelinePanel");
  if (panel) {
    panel.dataset.l2Stage = "0";
    panel.dataset.l2Scanning = "false";
  }
  ensureL2PipelineViz()?.reset();
}

function updateL2PipelineFlowViz(displayIdx, steps, scanRunning) {
  const panel = document.getElementById("l2ScanPipelinePanel");
  if (panel) {
    panel.dataset.l2Stage = String(displayIdx);
    panel.dataset.l2Scanning = (scanRunning || l2Flushing) ? "true" : "false";
    panel.style.setProperty("--l2-progress", String(displayIdx / (L2_PIPELINE_ORDER.length - 1)));
  }
  ensureL2PipelineViz()?.update(
    displayIdx,
    getL2StepStatuses(steps, displayIdx, scanRunning || l2Flushing),
    scanRunning || l2Flushing
  );

  if (displayIdx !== prevL2DisplayIdx) {
    const stepEl = document.getElementById(L2_PIPELINE_ORDER[displayIdx]?.id);
    if (stepEl) {
      stepEl.classList.remove("l2-step-enter");
      void stepEl.offsetWidth;
      stepEl.classList.add("l2-step-enter");
    }
    prevL2DisplayIdx = displayIdx;
  }
}
let fullDemoPipelineStepIndex = 0;

const FULL_DEMO_PIPELINE_ORDER = [
  { id: "demoStepSetup", stepId: "demo_setup", num: 1, name: "Create Misconfigs", metricId: "demoMetricSetup" },
  { id: "demoStepVerify", stepId: "demo_verify", num: 2, name: "Verify Resources", metricId: "demoMetricVerify" },
  { id: "demoStepScan", stepId: "demo_scan", num: 3, name: "Run Security Scan", metricId: "demoMetricScan" },
  { id: "demoStepDone", stepId: "demo_done", num: 4, name: "Load Findings", metricId: "demoMetricDone" },
];

const L1_TRIAL_CONTAINERS = {
  config: "l1TrialConfig",
  aws: "l1TrialAws",
  llm: "l1TrialLlm",
  reports: "l1TrialReports",
};

const L1_CHECK_CATEGORIES = ["IAM", "S3", "EC2", "CloudTrail"];

const L1_PIE_COLORS = {
  IAM: "#8957e5",
  S3: "#2dd4bf",
  EC2: "#f59e0b",
  CloudTrail: "#58a6ff",
  Other: "#71717a",
};

// ─── Theme ───────────────────────────────────────────────────────────────────

function initTheme() {
  const saved = localStorage.getItem("theme");
  const isDark = saved !== "light";
  document.documentElement.classList.toggle("dark", isDark);
}

function toggleTheme() {
  const isDark = document.documentElement.classList.toggle("dark");
  localStorage.setItem("theme", isDark ? "dark" : "light");
}

// ─── L1 empty state ──────────────────────────────────────────────────────────

function showEmptyStateForLevel(level) {
  els.dashboardContent.classList.add("hidden");
  if (level === 1) {
    els.emptyState?.classList.add("hidden");
    resetL1Overview();
  } else {
    els.emptyState?.classList.remove("hidden");
    const state = EMPTY_STATE[level] || EMPTY_STATE[2];
    els.emptyStateTitle.textContent = state.title;
    els.emptyStateDesc.innerHTML = state.desc;
  }
}

function hideEmptyStateForLevel(level) {
  if (level !== 1) els.emptyState?.classList.add("hidden");
}

function categoryForCheck(checkId) {
  const id = (checkId || "").toLowerCase();
  if (id.includes("cloudtrail")) return "CloudTrail";
  if (id.includes("s3")) return "S3";
  if (id.includes("ec2") || id.includes("security_group") || id.includes("ssh") || id.includes("rdp")) {
    return "EC2";
  }
  if (id.includes("iam") || id.includes("mfa") || id.includes("password") || id.includes("root")) {
    return "IAM";
  }
  return "Other";
}

function renderSegmentedBar(containerId, progress) {
  const el = document.getElementById(containerId);
  if (!el) return;
  const segments = 24;
  const colors = ["bg-violet-500", "bg-teal-400", "bg-orange-400"];
  const empty = "bg-zinc-300 dark:bg-zinc-700";
  const clamped = Math.max(0, Math.min(1, progress));
  el.innerHTML = Array.from({ length: segments }, (_, i) => {
    const filled = (i + 1) / segments <= clamped;
    const color = filled ? colors[i % colors.length] : empty;
    return `<span class="l1-seg-bar ${color}"></span>`;
  }).join("");
}

function resetL1PipelineTrials() {
  Object.values(L1_TRIAL_CONTAINERS).forEach((id) => renderSegmentedBar(id, 0));
}

function updateL1PipelineTrials(level, steps, scanRunning) {
  if (level !== 1) return;
  const order = getScanPipelineOrder(1);
  order.forEach((phase) => {
    const key = phase.id.replace("l1Step", "").toLowerCase();
    const containerKey =
      key === "config" ? "config" : key === "aws" ? "aws" : key === "llm" ? "llm" : "reports";
    const status = scanPhaseStatus(phase, steps, 1);
    let progress = 0;
    if (status === "completed") progress = 1;
    else if (status === "running") progress = 0.55;
    else if (status === "failed") progress = 0.35;
    renderSegmentedBar(L1_TRIAL_CONTAINERS[containerKey], progress);
  });
  if (!scanRunning && steps?.length) {
    const allDone = order.every((p) => scanPhaseStatus(p, steps, 1) === "completed");
    if (allDone) {
      Object.values(L1_TRIAL_CONTAINERS).forEach((id) => renderSegmentedBar(id, 1));
    }
  }
}

function polarToCartesian(cx, cy, r, angleDeg) {
  const rad = ((angleDeg - 90) * Math.PI) / 180;
  return { x: cx + r * Math.cos(rad), y: cy + r * Math.sin(rad) };
}

function describeDonutSegment(cx, cy, outerR, innerR, startAngle, endAngle) {
  if (endAngle - startAngle >= 359.99) {
    endAngle = startAngle + 359.99;
  }
  const outerStart = polarToCartesian(cx, cy, outerR, endAngle);
  const outerEnd = polarToCartesian(cx, cy, outerR, startAngle);
  const innerStart = polarToCartesian(cx, cy, innerR, startAngle);
  const innerEnd = polarToCartesian(cx, cy, innerR, endAngle);
  const largeArc = endAngle - startAngle > 180 ? 1 : 0;
  return [
    "M", outerStart.x, outerStart.y,
    "A", outerR, outerR, 0, largeArc, 0, outerEnd.x, outerEnd.y,
    "L", innerStart.x, innerStart.y,
    "A", innerR, innerR, 0, largeArc, 1, innerEnd.x, innerEnd.y,
    "Z",
  ].join(" ");
}

function buildL1PieSegments(counts, categories) {
  const total = categories.reduce((sum, cat) => sum + (counts[cat] || 0), 0);
  if (!total) return { total: 0, segments: [] };

  let cursor = 0;
  const segments = [];
  categories.forEach((cat) => {
    const value = counts[cat] || 0;
    if (!value) return;
    const sweep = (value / total) * 360;
    const start = cursor;
    const end = cursor + sweep;
    cursor = end;
    segments.push({
      cat,
      value,
      pct: Math.round((value / total) * 100),
      start,
      end,
      color: L1_PIE_COLORS[cat] || L1_PIE_COLORS.Other,
    });
  });
  return { total, segments };
}

function renderL1PieChart(counts, categories) {
  const { total, segments } = buildL1PieSegments(counts, categories);
  const cx = 100;
  const cy = 100;
  const outerR = 88;
  const innerR = 54;

  const paths = segments
    .map((seg, i) => {
      const d = describeDonutSegment(cx, cy, outerR, innerR, seg.start, seg.end);
      return `<path class="l1-pie-segment"
        data-cat="${escapeHtml(seg.cat)}"
        d="${d}"
        fill="${seg.color}"
        style="--pie-i:${i}"
        tabindex="0"
        role="img"
        aria-label="${escapeHtml(seg.cat)}: ${seg.value} findings (${seg.pct}%)">
        <title>${escapeHtml(seg.cat)}: ${seg.value} (${seg.pct}%)</title>
      </path>`;
    })
    .join("");

  const legend = categories
    .map((cat) => {
      const value = counts[cat] || 0;
      const pct = total ? Math.round((value / total) * 100) : 0;
      const color = L1_PIE_COLORS[cat] || L1_PIE_COLORS.Other;
      return `<li class="l1-pie-legend-item"
        data-cat="${escapeHtml(cat)}">
        <span class="l1-pie-legend-swatch" style="background:${color}"></span>
        <span class="l1-pie-legend-label">${cat.toLowerCase()}</span>
        <span class="l1-pie-legend-meta">${value} · ${pct}%</span>
      </li>`;
    })
    .join("");

  return `
    <div class="l1-pie-chart l1-pie-chart-animate">
      <div class="l1-pie-visual">
        <svg class="l1-pie-svg" viewBox="0 0 200 200" aria-hidden="true">
          <circle class="l1-pie-track" cx="${cx}" cy="${cy}" r="${(outerR + innerR) / 2}" fill="none"
            stroke-width="${outerR - innerR}" stroke="#27272a"/>
          ${paths}
        </svg>
        <div class="l1-pie-center" aria-hidden="true">
          <span class="l1-pie-total">${total}</span>
          <span class="l1-pie-total-sub">findings</span>
        </div>
      </div>
      <ul class="l1-pie-legend">${legend}</ul>
    </div>`;
}

function bindL1PieInteractions() {
  if (!els.l1CheckBreakdown) return;

  const setHover = (cat) => {
    els.l1CheckBreakdown.querySelectorAll(".l1-pie-segment").forEach((el) => {
      el.classList.toggle("l1-pie-segment-dim", Boolean(cat && el.dataset.cat !== cat));
    });
    els.l1CheckBreakdown.querySelectorAll(".l1-pie-legend-item").forEach((el) => {
      el.classList.toggle("l1-pie-legend-active", Boolean(cat && el.dataset.cat === cat));
    });
  };

  els.l1CheckBreakdown.querySelectorAll(".l1-pie-segment, .l1-pie-legend-item").forEach((el) => {
    const cat = el.dataset.cat;
    el.addEventListener("mouseenter", () => setHover(cat));
    el.addEventListener("mouseleave", () => setHover(null));
    el.addEventListener("focus", () => setHover(cat));
    el.addEventListener("blur", () => setHover(null));
  });
}

function renderL1CheckBreakdown(findings) {
  if (!els.l1CheckBreakdown) return;
  const counts = { IAM: 0, S3: 0, EC2: 0, CloudTrail: 0, Other: 0 };
  (findings || []).forEach((f) => {
    const cat = categoryForCheck(f.check_id);
    counts[cat] = (counts[cat] || 0) + 1;
  });
  const categories = (findings || []).length ? L1_CHECK_CATEGORIES : [];
  if (!categories.length) {
    delete els.l1CheckBreakdown.dataset.counts;
    delete els.l1CheckBreakdown.dataset.categories;
    els.l1CheckBreakdown.innerHTML =
      '<p class="text-sm text-zinc-500">Run a scan to see findings by AWS service.</p>';
    return;
  }
  els.l1CheckBreakdown.dataset.counts = JSON.stringify(counts);
  els.l1CheckBreakdown.dataset.categories = JSON.stringify(categories);
  els.l1CheckBreakdown.innerHTML = renderL1PieChart(counts, categories);
  bindL1PieInteractions();
}

function renderL1ReportingStats(reports, report) {
  const l1 = (reports || []).filter((r) => (r.scan_level || 1) === 1);
  const generated = l1.length;
  const processed = report ? 1 : 0;
  const enriched = report?.findings?.length ? report.findings.length : 0;
  const pending = Math.max(0, generated - processed);
  if (els.l1ReportsGenerated) els.l1ReportsGenerated.textContent = generated;
  if (els.l1ReportsProcessed) els.l1ReportsProcessed.textContent = processed;
  if (els.l1ReportsEnriched) els.l1ReportsEnriched.textContent = enriched;
  if (els.l1ReportsPending) els.l1ReportsPending.textContent = pending;
}

function renderL1SeverityBars(sev, total) {
  const t = total || 0;
  const low = sev.low || 0;
  const medium = sev.medium || 0;
  const critical = sev.critical || 0;
  const high = sev.high || 0;
  const pct = (n) => (t ? Math.round((n / t) * 100) : 0);
  if (els.l1IssuesTotalCount) els.l1IssuesTotalCount.textContent = t;
  if (els.l1PctLow) els.l1PctLow.textContent = `${pct(low)}%`;
  if (els.l1PctMedium) els.l1PctMedium.textContent = `${pct(medium)}%`;
  if (els.l1PctCritical) els.l1PctCritical.textContent = `${pct(critical + high)}%`;
  if (els.l1BarLow) els.l1BarLow.style.width = `${pct(low)}%`;
  if (els.l1BarMedium) els.l1BarMedium.style.width = `${pct(medium)}%`;
  if (els.l1BarCritical) els.l1BarCritical.style.width = `${pct(critical + high)}%`;
}

function resetL1Overview() {
  ["l1AssetTotal", "l1AssetCritical", "l1AssetResources", "l1AssetHealth"].forEach((key) => {
    if (els[key]) els[key].textContent = "—";
  });
  ["l1AssetChecksSub", "l1AssetHighSub", "l1AssetRegionSub", "l1AssetDurationSub"].forEach((key) => {
    if (els[key]) els[key].textContent = "—";
  });
  renderL1CheckBreakdown([]);
  renderL1ReportingStats([], null);
  renderL1SeverityBars({}, 0);
  resetL1PipelineTrials();
}

function renderL1Overview(report, reports = []) {
  if (!report) {
    resetL1Overview();
    renderL1ReportingStats(reports, null);
    return;
  }
  const sev = report.findings_by_severity || {};
  const total = report.total_findings || 0;
  if (els.l1AssetTotal) els.l1AssetTotal.textContent = total;
  if (els.l1AssetCritical) els.l1AssetCritical.textContent = sev.critical || 0;
  if (els.l1AssetResources) {
    els.l1AssetResources.textContent = report.metrics?.speed?.resources_scanned ?? total;
  }
  if (els.l1AssetHealth) {
    els.l1AssetHealth.textContent = (report.scan_health || "unknown").replace(/^\w/, (c) => c.toUpperCase());
  }
  if (els.l1AssetChecksSub) {
    els.l1AssetChecksSub.textContent = `${report.total_checks_succeeded || 0}/${report.total_checks_attempted || 13} passed`;
  }
  if (els.l1AssetHighSub) els.l1AssetHighSub.textContent = String(sev.high || 0);
  if (els.l1AssetRegionSub) els.l1AssetRegionSub.textContent = report.aws_region || "—";
  if (els.l1AssetDurationSub) {
    els.l1AssetDurationSub.textContent = `${(report.duration_seconds || 0).toFixed(1)}s`;
  }
  renderL1CheckBreakdown(report.findings || []);
  renderL1ReportingStats(reports, report);
  renderL1SeverityBars(sev, total);
}


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

function setReportHistoryExpanded(expanded) {
  const isOpen = Boolean(expanded);
  els.reportHistoryBody?.classList.toggle("report-history-body-collapsed", !isOpen);
  els.reportHistoryPanel?.classList.toggle("report-history-collapsed", !isOpen);
  if (els.reportHistoryToggle) {
    els.reportHistoryToggle.setAttribute("aria-expanded", isOpen ? "true" : "false");
  }
  if (els.reportHistoryChevron) {
    els.reportHistoryChevron.textContent = isOpen ? "▼" : "▶";
  }
  localStorage.setItem("reportHistoryExpanded", isOpen ? "true" : "false");
}

function initReportHistoryCollapse() {
  const saved = localStorage.getItem("reportHistoryExpanded");
  const expanded = saved !== "false";
  setReportHistoryExpanded(expanded);
  els.reportHistoryToggle?.addEventListener("click", () => {
    const open = els.reportHistoryToggle?.getAttribute("aria-expanded") !== "true";
    setReportHistoryExpanded(open);
  });
}

async function initTerminalClientInfo() {
  const nodes = document.querySelectorAll(".terminal-client-info");
  const setAll = (text, title = "") => {
    nodes.forEach((el) => {
      el.textContent = text;
      if (title) el.title = title;
    });
  };
  setAll("Detecting IP…", "Resolving your IP and internet provider");
  try {
    const data = await fetchJSON("/api/client-session");
    const label = data.label || `${data.ip || "?"} · ${data.isp || "Unknown provider"}`;
    setAll(label, `IP: ${data.ip} — Provider: ${data.isp}`);
  } catch {
    setAll("Client IP unavailable", "Could not resolve session IP");
  }
}

// ─── Active Task Panel (replaces old #pipelinePanel) ───────────────────────

function showActiveTaskPanel(title) {
  if (currentLevel !== 1) return;
  els.activeTaskPanel.classList.remove("hidden");
  els.activeTaskTitle.textContent = title;
  els.activeTaskPanel.scrollIntoView({ behavior: "smooth", block: "nearest" });
}

function hideActiveTaskPanel() {
  els.activeTaskPanel.classList.add("hidden");
  els.pipelineSteps.innerHTML = "";
  setJobLog("");
}

function setJobLog(text) {
  if (!els.logOutput) return;
  els.logOutput.textContent = text || "";
  els.logOutput.scrollTop = els.logOutput.scrollHeight;
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
  if (level >= 2) resetL2PipelineFlowViz();
}

function inferScanPipelinePhase(level, steps, scanRunning) {
  if (level >= 2) {
    const backendIdx = inferScanPipelineBackendIndex(level, steps, scanRunning);
    tickL2DisplayTimeline(backendIdx, scanRunning);
    scanPipelineStepIndex.l2 = l2DisplayTimeline.displayIdx;
    return L2_PIPELINE_ORDER[l2DisplayTimeline.displayIdx].id;
  }

  const order = getScanPipelineOrder(level);
  let idx = 0;

  if (scanRunning) {
    for (let i = 0; i < order.length; i++) {
      const status = scanPhaseStatus(order[i], steps, level);
      if (status === "running" || status === "failed") {
        idx = i;
        break;
      }
      if (status === "completed") idx = i;
    }
    scanPipelineStepIndex.l1 = Math.max(scanPipelineStepIndex.l1 || 0, idx);
    return order[scanPipelineStepIndex.l1].id;
  }

  for (let i = 0; i < order.length; i++) {
    if (scanPhaseStatus(order[i], steps, level) !== "pending") idx = i;
  }
  scanPipelineStepIndex.l1 = idx;
  return order[idx].id;
}

function getScanStepMeta(level, stepId) {
  const order = getScanPipelineOrder(level);
  return order.find((s) => s.id === stepId) || order[0];
}

function highlightScanPipelineSteps(level, activeStepId, scanRunning, steps = null, displayIdxOverride = null) {
  const order = getScanPipelineOrder(level);
  const activeIdx = displayIdxOverride ?? order.findIndex((s) => s.id === activeStepId);
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

  if (level >= 2) {
    updateL2PipelineFlowViz(activeIdx, steps, scanRunning);
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
    let activeStepIdx = order.findIndex((p) => {
      const st = scanPhaseStatus(p, steps, level);
      return st === "running" || st === "failed";
    });
    if (level >= 2) activeStepIdx = l2DisplayTimeline.displayIdx;
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

  if (level >= 2) {
    lastL2ScanSteps = steps;
    if (scanRunning) startL2TimelineTimer();
  }

  const ui = getLevelScanUi(level);
  let displayIdx = null;
  if (level >= 2) {
    const backendIdx = inferScanPipelineBackendIndex(level, steps, scanRunning);
    tickL2DisplayTimeline(backendIdx, scanRunning);
    displayIdx = l2DisplayTimeline.displayIdx;
  }
  const activeStepId = level >= 2
    ? L2_PIPELINE_ORDER[displayIdx].id
    : inferScanPipelinePhase(level, steps, scanRunning);

  highlightScanPipelineSteps(level, activeStepId, scanRunning, steps, displayIdx);
  updateScanPipelineMetrics(level, steps, scanRunning);
  updateL1PipelineTrials(level, steps, scanRunning);

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
  if (level >= 2) {
    lastL2ScanSteps = steps;
    l2Flushing = true;
    l2DisplayTimeline.backendIdx = L2_PIPELINE_ORDER.length - 1;
    renderLevelScanPipeline(level, steps, "", false);
    startL2TimelineTimer();
    return;
  }

  renderLevelScanPipeline(level, steps, "", false);
  updateL1PipelineTrials(level, steps, false);
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

function setDemoPipelineLog(text) {
  if (!els.l1DemoPipelineLog) return;
  els.l1DemoPipelineLog.textContent = text || "";
  els.l1DemoPipelineLog.scrollTop = els.l1DemoPipelineLog.scrollHeight;
}

function demoChecklistStatus(phaseIndex, activeIdx, st, running) {
  if (!running) {
    if (st?.status === "completed") return "completed";
    if (st?.status === "failed") return "failed";
    if (st?.status === "running") return "running";
    return "pending";
  }
  if (phaseIndex < activeIdx) return "completed";
  if (phaseIndex === activeIdx) {
    if (st?.status === "failed") return "failed";
    return "running";
  }
  return "pending";
}

function fullDemoScanDetail(scanSteps, scanRunning) {
  if (!scanSteps?.length) return null;
  const activeStepId = inferScanPipelinePhase(1, scanSteps, scanRunning);
  const meta = getScanStepMeta(1, activeStepId);
  const order = getScanPipelineOrder(1);
  const phase = order.find((p) => p.id === activeStepId);
  if (!phase) return null;
  const status = scanPhaseStatus(phase, scanSteps, 1);
  if (status === "running") {
    const running = stepsForScanPhase(phase, scanSteps, 1).find((s) => s.status === "running");
    return running?.detail ? `⟳ ${running.detail}` : `⟳ ${meta.name}…`;
  }
  if (status === "failed") return `✗ ${meta.name} failed`;
  if (!scanRunning && status === "completed") return "✓ Scan complete";
  return `⟳ ${meta.name}…`;
}

function renderFullDemoChecklist(jobSteps, running, scanSteps = null, scanRunning = false) {
  if (!els.demoPipelineChecklist) return;
  const stepMap = Object.fromEntries((jobSteps || []).map((s) => [s.id, s]));
  const activeId = inferFullDemoPhase(jobSteps, running);
  const activeIdx = FULL_DEMO_PIPELINE_ORDER.findIndex((p) => p.id === activeId);

  els.demoPipelineChecklist.innerHTML = FULL_DEMO_PIPELINE_ORDER.map((phase, i) => {
    const st = stepMap[phase.stepId];
    const status = demoChecklistStatus(i, activeIdx, st, running);
    let icon;
    if (status === "completed") icon = '<span class="step-icon-ok">✓</span>';
    else if (status === "running") icon = '<span class="step-icon-run">⟳</span>';
    else if (status === "failed") icon = '<span class="step-icon-fail">✗</span>';
    else icon = '<span class="step-icon-pend">○</span>';

    const detail = (phase.stepId === "demo_scan" && (status === "running" || scanRunning) && scanSteps?.length)
      ? `<span class="step-detail">${escapeHtml(fullDemoScanDetail(scanSteps, scanRunning) || "⟳ In progress…")}</span>`
      : st?.detail
        ? `<span class="step-detail">${escapeHtml(st.detail)}</span>`
        : status === "pending"
          ? `<span class="step-detail">Waiting…</span>`
          : status === "running"
            ? `<span class="step-detail">⟳ In progress…</span>`
            : "";
    return `<li class="step step-${status}">
      ${icon}
      <span class="step-label">${phase.num}. ${escapeHtml(phase.name)}</span>
      ${detail}
    </li>`;
  }).join("");
}

function hideFullDemoPipeline() {
  els.l1DemoPipelinePanel?.classList.add("hidden");
  els.l1ScanPipelinePanel?.classList.remove("hidden");
  if (els.l1DemoPipelineStatus) {
    els.l1DemoPipelineStatus.classList.add("hidden");
    els.l1DemoPipelineStatus.textContent = "";
  }
  setDemoPipelineLog("");
  if (els.demoPipelineChecklist) els.demoPipelineChecklist.innerHTML = "";
}

function resetFullDemoPipeline() {
  fullDemoPipelineStepIndex = 0;
  renderFullDemoChecklist([], false);
  setDemoPipelineLog("");
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

function renderFullDemoPipeline(jobSteps, logText = "", running = true, scanSteps = null, scanRunning = false) {
  if (!jobSteps?.length && !running) return;

  const activeId = inferFullDemoPhase(jobSteps || [], running);
  const activeIdx = FULL_DEMO_PIPELINE_ORDER.findIndex((p) => p.id === activeId);

  renderFullDemoChecklist(jobSteps || [], running, scanSteps, scanRunning);

  if (els.l1DemoPipelineStatus) {
    if (running && activeIdx >= 0) {
      const meta = FULL_DEMO_PIPELINE_ORDER[activeIdx];
      els.l1DemoPipelineStatus.textContent = `Running — Step ${meta.num}: ${meta.name}`;
      els.l1DemoPipelineStatus.classList.remove("hidden");
    } else {
      els.l1DemoPipelineStatus.classList.add("hidden");
    }
  }

  if (logText) {
    setDemoPipelineLog(logText);
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
  if (level >= 2) resetL2PipelineFlowViz();
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

  hideEmptyStateForLevel(level);
  els.dashboardContent.classList.remove("hidden");
  els.kpiGridRow?.classList.toggle("hidden", level === 1);

  renderFindingsTableHead(isL2);
  els.kpiDomainsCard.classList.toggle("hidden", !isL2);
  els.kpiDedupCard.classList.toggle("hidden", !isL2);

  const sev = report.findings_by_severity || {};
  els.kpiCritical.textContent = sev.critical || 0;
  els.kpiHigh.textContent = sev.high || 0;
  els.kpiMedium.textContent = sev.medium || 0;
  els.kpiTotal.textContent = report.total_findings || 0;

  if (level === 1) {
    fetchJSON("/api/reports")
      .then((reports) => renderL1Overview(report, reports))
      .catch(() => renderL1Overview(report, []));
  }

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

const METRICS_CHART_SERIES = [
  {
    id: "precision",
    label: "Precision",
    short: "P",
    target: 95,
    pass: (v) => v != null && v >= 95,
    extract: (d) =>
      d.verified_precision_critical != null ? d.verified_precision_critical * 100 : null,
    format: (v) => `${v.toFixed(1)}%`,
  },
  {
    id: "recall",
    label: "Recall",
    short: "R",
    target: 80,
    pass: (v) => v != null && v >= 80,
    extract: (d) => {
      if (d.verified_recall != null) return d.verified_recall * 100;
      if (d.known_misconfigs_total > 0 && d.known_misconfigs_found != null) {
        return (d.known_misconfigs_found / d.known_misconfigs_total) * 100;
      }
      return null;
    },
    format: (v) => `${v.toFixed(1)}%`,
  },
  {
    id: "confidence",
    label: "Confidence",
    short: "C",
    target: 75,
    pass: (v) => v != null && v >= 75,
    extract: (d) => (d.avg_confidence_score != null ? d.avg_confidence_score : null),
    format: (v) => `${v.toFixed(1)}%`,
  },
  {
    id: "f1",
    label: "F1",
    short: "F1",
    target: 85,
    pass: (v) => v != null && v >= 85,
    extract: (d) => (d.f1_score != null ? d.f1_score * 100 : null),
    format: (v) => `${v.toFixed(1)}%`,
  },
];

function metricsChartYScale(values) {
  const nums = values.filter((v) => v != null);
  if (!nums.length) return { min: 0, max: 100, ticks: [0, 25, 50, 75, 100] };
  const lo = Math.min(...nums);
  const hi = Math.max(...nums);
  const min = Math.max(0, Math.floor((lo - 8) / 10) * 10);
  const max = Math.min(100, Math.ceil((hi + 8) / 10) * 10);
  const span = Math.max(max - min, 20);
  const step = span <= 30 ? 5 : span <= 50 ? 10 : 20;
  const ticks = [];
  for (let t = min; t <= max; t += step) ticks.push(t);
  if (ticks[ticks.length - 1] !== max) ticks.push(max);
  return { min, max, ticks };
}

function buildMetricsStepGeometry(points, width, height, pad, yMin, yMax) {
  const chartW = width - pad.left - pad.right;
  const chartH = height - pad.top - pad.bottom;
  const baseY = pad.top + chartH;
  const toX = (i) => pad.left + (i / Math.max(points.length - 1, 1)) * chartW;
  const toY = (v) => pad.top + chartH - ((v - yMin) / Math.max(yMax - yMin, 1)) * chartH;

  let line = "";
  let area = `M ${toX(0)} ${baseY}`;

  points.forEach((pt, i) => {
    const x = toX(i);
    const y = toY(pt.value);
    if (i === 0) {
      line = `M ${x} ${y}`;
      area += ` L ${x} ${y}`;
    } else {
      line += ` H ${x} V ${y}`;
      area += ` H ${x} V ${y}`;
    }
  });

  area += ` L ${toX(points.length - 1)} ${baseY} Z`;
  return { line, area, toX, toY, baseY, chartW, chartH };
}

function renderMetricsStepChart(detection) {
  if (!els.metricsChartHost) return;

  const points = METRICS_CHART_SERIES.map((s) => ({
    ...s,
    value: s.extract(detection),
  })).filter((p) => p.value != null);

  if (!points.length) {
    els.metricsChartHost.innerHTML =
      '<p class="text-sm text-muted">Metrics unavailable for this report.</p>';
    return;
  }

  const values = points.map((p) => p.value);
  const { min: yMin, max: yMax, ticks } = metricsChartYScale(values);
  const width = 560;
  const height = 200;
  const pad = { top: 16, right: 20, bottom: 28, left: 36 };
  const { line, area, toX, toY } = buildMetricsStepGeometry(points, width, height, pad, yMin, yMax);

  const gridLines = ticks
    .map((tick) => {
      const y = toY(tick);
      return `<line class="metrics-chart-grid" x1="${pad.left}" y1="${y}" x2="${width - pad.right}" y2="${y}" stroke-dasharray="4 6"/>`;
    })
    .join("");

  const yLabels = ticks
    .map((tick) => {
      const y = toY(tick);
      return `<text class="metrics-chart-y-label" x="${pad.left - 8}" y="${y + 4}" text-anchor="end">${tick}</text>`;
    })
    .join("");

  const dots = points
    .map((pt, i) => {
      const x = toX(i);
      const y = toY(pt.value);
      return `<circle class="metrics-chart-dot" data-metric-idx="${i}" cx="${x}" cy="${y}" r="5"
        tabindex="0" role="button" aria-label="${escapeHtml(pt.label)}: ${pt.format(pt.value)}"/>`;
    })
    .join("");

  const xLabels = points
    .map((pt, i) => {
      const x = toX(i);
      return `<text class="metrics-chart-x-label" x="${x}" y="${height - 8}" text-anchor="middle">${escapeHtml(pt.label)}</text>`;
    })
    .join("");

  const passCount = points.filter((p) => p.pass(p.value)).length;
  const lo = Math.min(...values);
  const hi = Math.max(...values);
  const allPass = passCount === points.length;
  const somePass = passCount > 0;
  const statusClass = allPass ? "metrics-status-ok" : somePass ? "metrics-status-warn" : "metrics-status-fail";
  const statusText = allPass ? "✓ On Target" : somePass ? "⚠ Needs Attention" : "✗ Below Target";

  els.metricsChartHost.innerHTML = `
    <div class="metrics-chart-panel">
      <div class="metrics-chart-wrap">
        <svg class="metrics-chart-svg" viewBox="0 0 ${width} ${height}" preserveAspectRatio="xMidYMid meet" aria-label="Agent performance step chart">
          <defs>
            <linearGradient id="metricsAreaGrad" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stop-color="#8957e5" stop-opacity="0.38"/>
              <stop offset="100%" stop-color="#8957e5" stop-opacity="0.02"/>
            </linearGradient>
          </defs>
          ${gridLines}
          ${yLabels}
          <path class="metrics-chart-area" d="${area}" fill="url(#metricsAreaGrad)"/>
          <path class="metrics-chart-line" d="${line}" fill="none"/>
          ${dots}
          ${xLabels}
        </svg>
        <div id="metricsChartTooltip" class="metrics-chart-tooltip hidden" role="tooltip"></div>
      </div>
      <div class="metrics-chart-footer">
        <div class="metrics-chart-range">
          <span class="metrics-chart-range-value">${lo.toFixed(1)} – ${hi.toFixed(1)}</span>
          <span class="metrics-chart-range-unit">composite %</span>
        </div>
        <span class="metrics-status-badge ${statusClass}">${statusText}</span>
      </div>
      <ul class="metrics-chart-legend">
        ${points
          .map(
            (p) => `<li class="metrics-chart-legend-item${p.pass(p.value) ? "" : " metrics-chart-legend-fail"}">
              <span class="metrics-chart-legend-dot"></span>
              <span>${escapeHtml(p.label)}</span>
              <span class="metrics-chart-legend-val">${escapeHtml(p.format(p.value))}</span>
              <span class="metrics-chart-legend-target">≥ ${p.target}%</span>
            </li>`
          )
          .join("")}
      </ul>
    </div>`;

  bindMetricsChartInteractions(points);
}

function bindMetricsChartInteractions(points) {
  const tooltip = document.getElementById("metricsChartTooltip");
  const wrap = els.metricsChartHost?.querySelector(".metrics-chart-wrap");
  if (!tooltip || !wrap) return;

  let pinnedIdx = null;

  const positionTip = (dotEl) => {
    const wrapRect = wrap.getBoundingClientRect();
    const dotRect = dotEl.getBoundingClientRect();
    const cx = dotRect.left + dotRect.width / 2 - wrapRect.left;
    const cy = dotRect.top - wrapRect.top;
    tooltip.style.left = `${cx}px`;
    tooltip.style.top = `${cy}px`;
  };

  const showTip = (idx, dotEl, pin = false) => {
    const pt = points[idx];
    if (!pt || !dotEl) return;
    if (pin) pinnedIdx = idx;
    tooltip.textContent = `${pt.label} · ${pt.format(pt.value)}`;
    tooltip.classList.remove("hidden");
    wrap.querySelectorAll(".metrics-chart-dot").forEach((d, i) => {
      d.classList.toggle("metrics-chart-dot-active", i === idx);
    });
    positionTip(dotEl);
  };

  const hideTip = (force = false) => {
    if (!force && pinnedIdx !== null) return;
    pinnedIdx = null;
    tooltip.classList.add("hidden");
    wrap.querySelectorAll(".metrics-chart-dot").forEach((d) => d.classList.remove("metrics-chart-dot-active"));
  };

  wrap.querySelectorAll(".metrics-chart-dot").forEach((dot) => {
    const idx = parseInt(dot.dataset.metricIdx, 10);
    dot.addEventListener("mouseenter", () => showTip(idx, dot));
    dot.addEventListener("focus", () => showTip(idx, dot));
    dot.addEventListener("mouseleave", () => hideTip());
    dot.addEventListener("blur", () => hideTip(true));
    dot.addEventListener("click", (ev) => {
      ev.preventDefault();
      ev.stopPropagation();
      if (pinnedIdx === idx) {
        hideTip(true);
      } else {
        showTip(idx, dot, true);
      }
    });
  });

  wrap.addEventListener("click", (ev) => {
    if (!ev.target.closest(".metrics-chart-dot")) hideTip(true);
  });
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
    setMetricsHeadline("");
    if (els.metricsChartHost) els.metricsChartHost.innerHTML = "";
    return;
  }

  if (els.metricsEmpty) els.metricsEmpty.classList.add("hidden");
  if (els.metricsContent) els.metricsContent.classList.remove("hidden");
  if (els.metricsHeadline) {
    setMetricsHeadline(metrics.headline || "");
  }

  const d = metrics.detection || {};
  const s = metrics.speed || {};
  const c = metrics.coverage || {};
  const l2 = metrics.level2;

  renderMetricsStepChart(d);

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

function parseMetricsHeadlineParts(headline) {
  if (!headline) return [];
  return headline.split(" | ").map((part) => {
    const colon = part.indexOf(":");
    if (colon === -1) return { label: part.trim(), value: "" };
    return {
      label: part.slice(0, colon).trim(),
      value: part.slice(colon + 1).trim(),
    };
  });
}

function metricsHeadlineChipClass(label) {
  const key = label.toLowerCase();
  if (key.includes("precision")) return "metrics-chip-precision";
  if (key.includes("recall")) return "metrics-chip-recall";
  if (key.includes("f1")) return "metrics-chip-f1";
  if (key.includes("scan")) return "metrics-chip-scan";
  if (key.includes("coverage")) return "metrics-chip-coverage";
  if (key.includes("domain")) return "metrics-chip-domain";
  if (key.includes("dedup")) return "metrics-chip-dedup";
  if (key.includes("posture")) return "metrics-chip-posture";
  return "metrics-chip-default";
}

function parseMetricForProgress(label, valueStr) {
  const key = label.toLowerCase();
  if (key.includes("f1")) {
    const n = parseFloat(valueStr);
    const pct = Number.isNaN(n) ? 0 : Math.min(100, n * 100);
    return { pct, target: 85, display: valueStr, showBar: true, pass: pct >= 85 };
  }
  if (key.includes("scan")) {
    const sec = parseFloat(String(valueStr).replace(/s$/i, ""));
    const pct = Number.isNaN(sec) ? 0 : Math.min(100, Math.max(8, 100 - sec * 1.5));
    return { pct, target: null, display: valueStr, showBar: true, pass: true, info: true };
  }
  const pctMatch = String(valueStr).match(/^([\d.]+)\s*%/);
  if (pctMatch) {
    const pct = parseFloat(pctMatch[1]);
    let target = 80;
    if (key.includes("precision")) target = 95;
    else if (key.includes("recall")) target = 80;
    else if (key.includes("coverage")) target = 100;
    return {
      pct: Number.isNaN(pct) ? 0 : Math.min(100, pct),
      target,
      display: valueStr,
      showBar: true,
      pass: !Number.isNaN(pct) && pct >= target,
    };
  }
  return { pct: 0, target: null, display: valueStr, showBar: false, pass: true };
}

function renderFindingsProgressBar(sev, total) {
  const t = total || 0;
  if (!t) {
    return `<div class="report-findings-progress">
      <div class="report-findings-progress-head"><span class="report-findings-progress-label">Findings</span><span class="report-findings-progress-value">0</span></div>
      <div class="report-findings-track"><div class="report-findings-fill report-findings-fill-empty" style="width:0%"></div></div>
    </div>`;
  }
  const critical = sev.critical || 0;
  const high = sev.high || 0;
  const medium = sev.medium || 0;
  const low = sev.low || 0;
  const other = Math.max(0, t - critical - high - medium - low);
  const segs = [
    { cls: "report-findings-seg-critical", n: critical },
    { cls: "report-findings-seg-high", n: high },
    { cls: "report-findings-seg-medium", n: medium },
    { cls: "report-findings-seg-low", n: low },
    { cls: "report-findings-seg-other", n: other },
  ].filter((s) => s.n > 0);
  const segHtml = segs
    .map((s) => `<span class="report-findings-seg ${s.cls}" style="width:${((s.n / t) * 100).toFixed(1)}%" title="${s.n}"></span>`)
    .join("");
  return `<div class="report-findings-progress">
    <div class="report-findings-progress-head">
      <span class="report-findings-progress-label">Findings distribution</span>
      <span class="report-findings-progress-value">${t} total</span>
    </div>
    <div class="report-findings-track" role="img" aria-label="${t} findings">${segHtml}</div>
  </div>`;
}

function renderMetricsProgressHtml(headline, compact = false) {
  const parts = parseMetricsHeadlineParts(headline);
  if (!parts.length) return "";
  const cards = parts
    .map((p) => {
      const chip = metricsHeadlineChipClass(p.label);
      const meta = parseMetricForProgress(p.label, p.value);
      const fillClass = meta.pass ? "metric-progress-fill-ok" : "metric-progress-fill-warn";
      const barWidth = meta.showBar ? `${Math.max(meta.pct, meta.info ? 8 : 4)}%` : "0%";
      const targetHint =
        meta.target != null && meta.showBar && !meta.info
          ? `<span class="metric-progress-target">target ≥ ${meta.target}%</span>`
          : "";
      const barHtml = meta.showBar
        ? `<div class="metric-progress-track"><div class="metric-progress-fill ${fillClass}" style="width:${barWidth}"></div></div>`
        : "";
      return `<div class="metric-progress-card ${chip}${compact ? " metric-progress-card-compact" : ""}">
        <div class="metric-progress-card-head">
          <span class="metric-progress-label">${escapeHtml(p.label)}</span>
          <span class="metric-progress-value">${escapeHtml(meta.display)}</span>
        </div>
        ${barHtml}
        ${targetHint}
      </div>`;
    })
    .join("");
  return `<div class="metrics-progress-grid${compact ? " metrics-progress-grid-compact" : ""}">${cards}</div>`;
}

function renderMetricsHeadlineHtml(headline) {
  return renderMetricsProgressHtml(headline, false);
}

function setMetricsHeadline(headline) {
  if (!els.metricsHeadline) return;
  if (!headline) {
    els.metricsHeadline.classList.add("hidden");
    els.metricsHeadline.innerHTML = "";
    return;
  }
  els.metricsHeadline.innerHTML = renderMetricsProgressHtml(headline, false);
  els.metricsHeadline.classList.remove("hidden");
}

function reportItemDate(r) {
  return r.end_time || r.completed_at || r.started_at || "";
}

function exportReportPdfJs(report, pdfName) {
  if (!window.jspdf?.jsPDF) {
    throw new Error("PDF library not loaded");
  }
  const { jsPDF } = window.jspdf;
  const doc = new jsPDF({ orientation: "portrait", unit: "mm", format: "a4" });
  const sev = report.findings_by_severity || {};
  const metrics = report.metrics?.headline || "";
  const margin = 14;
  let y = 16;

  doc.setFont("helvetica", "bold");
  doc.setFontSize(16);
  doc.setTextColor(24, 24, 27);
  doc.text("Aivar Security Scan Report", margin, y);

  y += 8;
  doc.setFont("helvetica", "normal");
  doc.setFontSize(10);
  doc.setTextColor(113, 113, 122);
  doc.text(
    `${formatTime(report.end_time || report.start_time)} · Level ${report.scan_level || 1} · ${report.scan_health || ""}`,
    margin,
    y
  );

  if (metrics) {
    y += 7;
    doc.setFontSize(9);
    doc.setTextColor(63, 63, 70);
    const lines = doc.splitTextToSize(metrics, 180);
    doc.text(lines, margin, y);
    y += lines.length * 4.5 + 2;
  }

  y += 4;
  doc.autoTable({
    startY: y,
    head: [["Metric", "Value"]],
    body: [
      ["Total findings", String(report.total_findings ?? 0)],
      ["Critical", String(sev.critical ?? 0)],
      ["High", String(sev.high ?? 0)],
      ["Medium", String(sev.medium ?? 0)],
      ["Low", String(sev.low ?? 0)],
      ["Region", report.aws_region || "—"],
      ["Account", report.aws_account_id || "—"],
      ["Duration", `${(report.duration_seconds || 0).toFixed(1)}s`],
    ],
    theme: "grid",
    styles: { fontSize: 9, cellPadding: 2, textColor: [24, 24, 27] },
    headStyles: { fillColor: [244, 244, 245], textColor: [24, 24, 27], fontStyle: "bold" },
    margin: { left: margin, right: margin },
  });

  y = doc.lastAutoTable.finalY + 8;
  const findings = (report.findings || []).slice(0, 250);
  doc.setFont("helvetica", "bold");
  doc.setFontSize(12);
  doc.setTextColor(24, 24, 27);
  doc.text("Findings", margin, y);

  doc.autoTable({
    startY: y + 4,
    head: [["Severity", "Check", "Title", "Conf."]],
    body: findings.length
      ? findings.map((f) => [
          f.severity || "",
          f.check_id || "",
          (f.title || f.resource_id || "").slice(0, 80),
          String(f.confidence_score ?? ""),
        ])
      : [["—", "—", "No findings", "—"]],
    theme: "grid",
    styles: { fontSize: 8, cellPadding: 2, overflow: "linebreak", textColor: [24, 24, 27] },
    headStyles: { fillColor: [244, 244, 245], textColor: [24, 24, 27], fontStyle: "bold" },
    columnStyles: { 2: { cellWidth: 80 } },
    margin: { left: margin, right: margin },
  });

  doc.save(pdfName);
}

async function exportReportAsPdf(filename = null) {
  try {
    let report = currentReport;
    if (filename) {
      report = await fetchJSON(`/api/reports/${encodeURIComponent(filename)}`);
    }
    if (!report) {
      showToast("Load a report first, or use PDF on a history row", true);
      return;
    }

    const pdfName = `scan-report-${(report.scan_id || report.filename || "export").slice(0, 12)}.pdf`;
    exportReportPdfJs(report, pdfName);
    showToast("PDF exported");
  } catch (e) {
    showToast(e.message || "PDF export failed", true, 6000);
  }
}

function renderReportHistoryList(list, filterLevel) {
  if (!els.reportList) return;

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
      const timeLabel = formatTime(reportItemDate(r));
      const countsLabel = isL3Run
        ? `${r.total_findings} findings · posture ${r.posture_score ?? "—"}/100`
        : `${r.total_findings} findings`;
      const findingsBar = renderFindingsProgressBar(sev, r.total_findings || 0);
      const metricsHtml = r.metrics_headline
        ? `<div class="report-item-metrics">${renderMetricsProgressHtml(r.metrics_headline, true)}</div>`
        : "";
      const loadBtn = isL3Run
        ? `<button type="button" class="btn btn-copy report-load-btn" data-l3-run-id="${attrEscape(runId)}">Load</button>`
        : `<button type="button" class="btn btn-copy report-load-btn" data-filename="${attrEscape(fname)}">Load</button>`;
      const pdfBtn = isL3Run
        ? ""
        : `<button type="button" class="btn btn-secondary report-pdf-btn" data-filename="${attrEscape(fname)}" title="Export PDF">PDF</button>`;
      const deleteAttrs = isL3Run
        ? `data-l3-run-id="${attrEscape(runId)}"`
        : `data-filename="${attrEscape(fname)}"`;

      return `
        <div class="report-item" ${isL3Run ? `data-l3-run-id="${attrEscape(runId)}"` : `data-filename="${attrEscape(fname)}"`} data-report-date="${escapeHtml(reportItemDate(r).slice(0, 10))}">
          <div class="report-item-main">
            <div class="report-item-top">
              <span class="report-level-badge lvl-${lvl}">L${lvl}</span>
              <span class="report-time">${timeLabel}</span>
              <span class="report-counts">
                ${countsLabel}
                ${critCount > 0 ? `<span class="sev-dot sev-critical">${critCount}C</span>` : ""}
                ${highCount > 0 ? `<span class="sev-dot sev-high">${highCount}H</span>` : ""}
              </span>
              <span class="report-health health-${r.scan_health}">${r.scan_health}</span>
            </div>
            ${findingsBar}
            ${metricsHtml}
          </div>
          <div class="report-actions">
            ${loadBtn}
            ${pdfBtn}
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

  els.reportList.querySelectorAll(".report-pdf-btn").forEach((btn) => {
    btn.addEventListener("click", (e) => {
      e.preventDefault();
      e.stopPropagation();
      const filename = btn.getAttribute("data-filename");
      if (filename) exportReportAsPdf(filename);
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

    renderReportHistoryList(list, filterLevel);

    if (filterLevel === 1) {
      const l1Reports = reports.filter((r) => (r.scan_level || 1) === 1);
      if (currentReport && reportLevel(currentReport) === 1) {
        renderL1Overview(currentReport, l1Reports);
      } else {
        renderL1ReportingStats(l1Reports, null);
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
    showEmptyStateForLevel(level);
    if (level === 1) {
      fetchJSON("/api/reports")
        .then((reports) => renderL1Overview(null, reports))
        .catch(() => resetL1Overview());
    }
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
        showFullDemoPipeline();
        renderFullDemoPipeline(jobSt.steps, logText, true, scanSt.steps, true);
        updateL1PipelineTrials(lvl, scanSt.steps, true);
      } else {
        els.l1ScanPipelinePanel?.classList.remove("hidden");
        renderLevelScanPipeline(lvl, scanSt.steps, logText, true);
      }
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
        setJobLog((jobSt.log_tail || []).join("\n"));
        renderJobPipeline(`${JOB_TITLES[jt] || "Working…"} (${jobSt.steps_completed || 0}/${jobSt.steps_total || 0})`, jobSt.steps);
      }
    } else {
      setButtonsDisabled(false);

      if (activeMode === "scan" && scanSt.state === "completed") {
        const completedLevel = scanSt.scan_level || activeScanLevel || 1;
        if (jobSt.state === "running" && jobSt.job_type === "full_demo") {
          finishLevelScanPipeline(completedLevel, scanSt.steps);
          const jobLog = (jobSt.log_tail || []).join("\n");
          const scanLog = (scanSt.log_tail || []).join("\n");
          const logText = [jobLog, scanLog].filter(Boolean).join("\n");
          showFullDemoPipeline();
          renderFullDemoPipeline(jobSt.steps, logText, true, scanSt.steps, false);
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
          const logText = (jobSt.log_tail || []).join("\n");
          showFullDemoPipeline();
          renderFullDemoPipeline(jobSt.steps, logText, false, scanSt.steps, false);
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
        } else if (jobSt.job_type === "full_demo") {
          showFullDemoPipeline();
          renderFullDemoPipeline(jobSt.steps, (jobSt.log_tail || []).join("\n"), false, scanSt.steps, false);
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
          setDemoPipelineLog(errLog);
        } else {
          setJobLog(errLog);
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
      setDemoPipelineLog(`Starting ${label}...\n`);
      if (els.l1DemoPipelineStatus) {
        els.l1DemoPipelineStatus.textContent = "Running — Step 1: Create Misconfigs";
        els.l1DemoPipelineStatus.classList.remove("hidden");
      }
      renderFullDemoChecklist(
        [{ id: "demo_setup", label: "Create Misconfigs", status: "running", detail: "Starting…" }],
        true
      );
    } else {
      showActiveTaskPanel(`${label}…`);
      setJobLog(`Starting ${label}...\n`);
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
    resetLevelScanPipelineIdle(level);
    els.l1ScanPipelinePanel?.classList.remove("hidden");
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

function setSocProgress(el, pct) {
  if (!el) return;
  el.style.width = `${Math.min(100, Math.max(0, pct))}%`;
}

function animateSocCounter(el, targetText) {
  if (!el || !el.dataset.animate) {
    if (el) el.textContent = targetText;
    return;
  }
  const numMatch = String(targetText).match(/([\d.]+)/);
  if (!numMatch || targetText === "—") {
    el.textContent = targetText;
    return;
  }
  const target = parseFloat(numMatch[1]);
  const suffix = targetText.replace(numMatch[0], "");
  const start = parseFloat(el.dataset.lastVal || "0") || 0;
  const duration = 600;
  const t0 = performance.now();
  const tick = (now) => {
    const p = Math.min(1, (now - t0) / duration);
    const eased = 1 - (1 - p) ** 3;
    const val = start + (target - start) * eased;
    el.textContent = `${Number.isInteger(target) ? Math.round(val) : val.toFixed(2)}${suffix}`;
    if (p < 1) requestAnimationFrame(tick);
    else el.dataset.lastVal = String(target);
  };
  requestAnimationFrame(tick);
}

function renderSocSparkline(svgEl, points, color = "#58a6ff") {
  if (!svgEl) return;
  const w = 64;
  const h = 24;
  const pad = 2;
  const nums = points.filter((n) => n != null && !Number.isNaN(n));
  if (nums.length < 2) {
    const flat = nums[0] ?? 50;
    nums.push(flat, flat);
  }
  const min = Math.min(...nums);
  const max = Math.max(...nums);
  const span = max - min || 1;
  const coords = nums.map((v, i) => {
    const x = pad + (i / (nums.length - 1)) * (w - pad * 2);
    const y = h - pad - ((v - min) / span) * (h - pad * 2);
    return `${x},${y}`;
  });
  svgEl.innerHTML = `<polyline points="${coords.join(" ")}" style="stroke:${color}"/>`;
}

function renderL3SocSparklines(trend, agentMetrics) {
  const history = (trend.scan_history || []).map((r) => r.posture_score).filter((v) => v != null);
  const l3 = agentMetrics?.level3 || {};
  const det = agentMetrics?.detection || {};
  document.querySelectorAll(".soc-kpi-spark").forEach((svg) => {
    const key = svg.dataset.spark;
    let pts = history.length ? history : [50, 52, 48, 55, 53];
    let color = "#58a6ff";
    if (key === "posture") pts = history.length ? history : [0, 0];
    else if (key === "critical") pts = [trend.open_critical_count ?? 0];
    else if (key === "f1") {
      pts = det.f1_score != null ? [det.f1_score * 80, det.f1_score * 100] : [0, 0];
      color = "#8957e5";
    } else if (key === "compliance") {
      pts = l3.sla_compliance_rate != null ? [l3.sla_compliance_rate * 100] : [0];
      color = "#f85149";
    } else if (key === "reliability") {
      pts = l3.scan_reliability_rate != null ? [l3.scan_reliability_rate * 100] : [0];
      color = "#3fb950";
    } else if (key === "resolution") {
      pts = l3.resolution_rate != null ? [l3.resolution_rate * 100] : [0];
    }
    renderSocSparkline(svg, pts.length > 1 ? pts : [...pts, ...pts], color);
  });
}

function inferL3ScanFlowIndex(logTail, scanRunning) {
  const log = extractCurrentScanLog(logTail || []).toLowerCase();
  if (!scanRunning) return L3_SCAN_FLOW_STAGES.length;
  let idx = 0;
  L3_SCAN_FLOW_STAGES.forEach((stage, i) => {
    if (log.includes(stage.log) || log.includes(`[l3-phase] ${stage.log}`)) idx = i + 1;
  });
  if (/l3 scan .+ started|starting level 3/i.test(log)) idx = Math.max(idx, 1);
  return Math.min(idx, L3_SCAN_FLOW_STAGES.length - 1);
}

function renderL3ScanPipelineHero(scanRunning, logTail) {
  const host = els.l3ScanPipelineHero;
  if (!host) return;
  const activeIdx = scanRunning ? inferL3ScanFlowIndex(logTail, true) : L3_SCAN_FLOW_STAGES.length;

  const nodes = L3_SCAN_FLOW_STAGES.map((stage, i) => {
    let cls = "soc-flow-node";
    if (scanRunning && i === activeIdx) cls += " soc-flow-running";
    else if (!scanRunning && i < L3_SCAN_FLOW_STAGES.length) cls += " soc-flow-done";
    else if (scanRunning && i < activeIdx) cls += " soc-flow-done";
    const conn =
      i < L3_SCAN_FLOW_STAGES.length - 1
        ? `<div class="soc-flow-connector${scanRunning && i < activeIdx ? " soc-flow-active" : ""}"></div>`
        : "";
    return `${i > 0 ? "" : ""}<div class="${cls}"><div class="soc-flow-ring">${stage.short}</div><span class="soc-flow-label">${escapeHtml(stage.label)}</span></div>${conn}`;
  }).join("");

  host.innerHTML = `<div class="soc-scan-flow-inner">${nodes}</div>`;

  if (els.l3ScanPipelineBadge) {
    els.l3ScanPipelineBadge.textContent = scanRunning ? "Running" : "Idle";
    els.l3ScanPipelineBadge.className = `soc-status-badge ${scanRunning ? "soc-status-running" : "soc-status-idle"}`;
  }
}

function renderL3PostureChart(history) {
  const host = els.l3PostureChartHost;
  if (!host) return;

  const scores = (history || []).map((r) => r.posture_score).filter((v) => v != null);
  const w = 360;
  const h = 140;
  const pad = { t: 12, r: 12, b: 24, l: 36 };

  if (!scores.length) {
    host.innerHTML = `<div class="soc-chart-empty">
      <svg width="120" height="40" viewBox="0 0 120 40"><path d="M0 30 L30 25 L60 28 L90 15 L120 20" fill="none" stroke="#58a6ff" stroke-width="1.5" opacity="0.35" stroke-dasharray="4 4"/></svg>
      <span>No scan history yet — run your first L3 scan to populate posture trend</span>
    </div>`;
    return;
  }

  const min = Math.max(0, Math.min(...scores) - 5);
  const max = Math.min(100, Math.max(...scores) + 5);
  const span = max - min || 1;
  const chartW = w - pad.l - pad.r;
  const chartH = h - pad.t - pad.b;

  const pts = scores.map((v, i) => {
    const x = pad.l + (i / Math.max(scores.length - 1, 1)) * chartW;
    const y = pad.t + chartH - ((v - min) / span) * chartH;
    return { x, y, v };
  });

  const line = pts.map((p, i) => `${i === 0 ? "M" : "L"} ${p.x} ${p.y}`).join(" ");
  const area = `${line} L ${pts[pts.length - 1].x} ${pad.t + chartH} L ${pts[0].x} ${pad.t + chartH} Z`;
  const dots = pts.map((p) => `<circle cx="${p.x}" cy="${p.y}" r="3" fill="#2dd4bf"/>`).join("");
  const grid = [0, 0.5, 1]
    .map((t) => {
      const y = pad.t + chartH * (1 - t);
      const val = Math.round(min + span * t);
      return `<line x1="${pad.l}" y1="${y}" x2="${w - pad.r}" y2="${y}" stroke="rgba(255,255,255,0.06)" stroke-dasharray="4 6"/><text x="${pad.l - 6}" y="${y + 4}" text-anchor="end" fill="#8b949e" font-size="9">${val}</text>`;
    })
    .join("");

  host.innerHTML = `<svg viewBox="0 0 ${w} ${h}" preserveAspectRatio="xMidYMid meet" aria-label="Posture score history">
    <defs><linearGradient id="socPostureGrad" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stop-color="#8957e5" stop-opacity="0.35"/><stop offset="100%" stop-color="#8957e5" stop-opacity="0"/></linearGradient></defs>
    ${grid}
    <path d="${area}" fill="url(#socPostureGrad)"/>
    <path d="${line}" fill="none" stroke="#58a6ff" stroke-width="2.5" stroke-linecap="round"/>
    ${dots}
  </svg>`;
}

function renderL3ActivityFeed(audit, logTail) {
  const host = els.l3ActivityFeed;
  if (!host) return;
  const events = [];

  (audit || []).slice(0, 12).forEach((a) => {
    const action = (a.action || "").toLowerCase();
    let iconCls = "soc-activity-icon-audit";
    if (/escalat|sla|breach|critical/.test(action)) iconCls = "soc-activity-icon-alert";
    events.push({
      time: a.timestamp,
      iconCls,
      icon: "◆",
      text: `${a.action} · ${a.entity_type || "system"}${a.entity_id ? ` (${a.entity_id.slice(0, 8)}…)` : ""}`,
    });
  });

  (logTail || [])
    .slice(-8)
    .reverse()
    .forEach((line) => {
      if (!line.trim()) return;
      events.push({ time: null, iconCls: "soc-activity-icon-log", icon: "›", text: line.trim().slice(0, 120) });
    });

  if (!events.length) {
    host.innerHTML = `<div class="soc-empty-state">No activity yet — start a scan or daemon to see live security events</div>`;
    return;
  }

  host.innerHTML = events
    .slice(0, 16)
    .map(
      (ev) => `<div class="soc-activity-item">
        <div class="soc-activity-icon ${ev.iconCls}">${ev.icon}</div>
        <div class="soc-activity-body">
          ${ev.time ? `<div class="soc-activity-time">${escapeHtml(formatTime(ev.time))}</div>` : ""}
          <div class="soc-activity-text">${escapeHtml(ev.text)}</div>
        </div>
      </div>`
    )
    .join("");
}

function renderL3PostureCenter(findings) {
  const host = els.l3PostureCenterGrid;
  if (!host) return;
  const open = (findings || []).filter((f) => ["opened", "updated", "re-opened"].includes(f.status));

  host.innerHTML = L3_POSTURE_WIDGETS.map((w) => {
    const matched = open.filter(w.match);
    const count = matched.length;
    const pct = Math.min(100, count * 18);
    return `<div class="soc-widget">
      <div class="soc-widget-head"><span class="soc-widget-title">${escapeHtml(w.title)}</span></div>
      <div class="soc-widget-count">${count}</div>
      <div class="soc-widget-bar"><div class="soc-widget-bar-fill" style="width:${pct}%"></div></div>
    </div>`;
  }).join("");
}

function renderL3CriticalFindings(findings) {
  const host = els.l3CriticalFindingsList;
  if (!host) return;
  const critical = (findings || []).filter(
    (f) =>
      (f.severity === "critical" || f.severity === "high") &&
      ["opened", "updated", "re-opened"].includes(f.status)
  );

  if (!critical.length) {
    host.innerHTML = `<div class="soc-empty-state">No open critical or high findings — posture looks healthy</div>`;
    return;
  }

  host.innerHTML = critical
    .slice(0, 8)
    .map((f, i) => {
      const cve =
        f.check_id === "dependency_cve"
          ? escapeHtml(f.title || "CVE detected")
          : "—";
      return `<article class="soc-finding-card" data-finding-idx="${i}">
        <div class="soc-finding-summary" role="button" tabindex="0" aria-expanded="false">
          <div>
            <h4>${escapeHtml(f.title || f.check_id)}</h4>
            <p class="soc-finding-meta"><span class="sev sev-${f.severity}">${escapeHtml(f.severity)}</span> · ${escapeHtml(f.check_id)}</p>
          </div>
          <span class="soc-pill soc-pill-critical">${escapeHtml(f.status)}</span>
        </div>
        <dl class="soc-finding-details">
          <dt>Resource ARN</dt><dd>${escapeHtml(f.resource_arn || f.resource_id || "—")}</dd>
          <dt>Severity</dt><dd>${escapeHtml(f.severity)}</dd>
          <dt>CVE / Check</dt><dd>${cve}</dd>
          <dt>Business Impact</dt><dd>${escapeHtml(f.business_impact || "—")}</dd>
          <dt>Remediation Command</dt><dd>${escapeHtml(f.remediation_command || "—")}</dd>
        </dl>
      </article>`;
    })
    .join("");

  host.querySelectorAll(".soc-finding-summary").forEach((btn) => {
    btn.addEventListener("click", () => {
      const card = btn.closest(".soc-finding-card");
      const open = card.classList.toggle("soc-finding-open");
      btn.setAttribute("aria-expanded", open ? "true" : "false");
    });
  });
}

function loadL3SchedulePrefs() {
  try {
    const raw = localStorage.getItem(L3_SCHEDULE_STORAGE_KEY);
    if (!raw) return { mode: "default", intervalHours: 12, intervalMinutes: "" };
    return JSON.parse(raw);
  } catch {
    return { mode: "default", intervalHours: 12, intervalMinutes: "" };
  }
}

function saveL3SchedulePrefs(prefs) {
  try {
    localStorage.setItem(L3_SCHEDULE_STORAGE_KEY, JSON.stringify(prefs));
  } catch {
    /* ignore */
  }
}

function getL3ScheduleModeInput() {
  return document.querySelector('input[name="l3ScheduleMode"]:checked');
}

function syncL3ScheduleCustomVisibility() {
  const mode = getL3ScheduleModeInput()?.value || "default";
  if (els.l3ScheduleCustomFields) {
    els.l3ScheduleCustomFields.classList.toggle("hidden", mode !== "custom");
  }
}

function readL3ScheduleForm() {
  const mode = getL3ScheduleModeInput()?.value || "default";
  const hoursRaw = els.l3CustomIntervalHours?.value?.trim();
  const minsRaw = els.l3CustomIntervalMinutes?.value?.trim();
  const intervalHours = hoursRaw ? parseFloat(hoursRaw) : null;
  const intervalMinutes = minsRaw ? parseFloat(minsRaw) : null;
  saveL3SchedulePrefs({
    mode,
    intervalHours: intervalHours || 12,
    intervalMinutes: minsRaw || "",
  });
  return { mode, intervalHours, intervalMinutes };
}

function buildL3DaemonStartBody() {
  const { mode, intervalHours, intervalMinutes } = readL3ScheduleForm();
  const body = { schedule_mode: mode };
  if (mode === "custom") {
    if (intervalMinutes && intervalMinutes > 0) {
      body.interval_minutes = intervalMinutes;
    } else if (intervalHours && intervalHours > 0) {
      body.interval_hours = intervalHours;
    } else {
      body.interval_hours = 12;
    }
  }
  return body;
}

function applyL3SchedulePrefsToForm(prefs) {
  const mode = prefs?.mode === "custom" ? "custom" : "default";
  document.querySelectorAll('input[name="l3ScheduleMode"]').forEach((input) => {
    input.checked = input.value === mode;
  });
  if (els.l3CustomIntervalHours && prefs?.intervalHours != null) {
    els.l3CustomIntervalHours.value = String(prefs.intervalHours);
  }
  if (els.l3CustomIntervalMinutes) {
    els.l3CustomIntervalMinutes.value = prefs?.intervalMinutes ?? "";
  }
  syncL3ScheduleCustomVisibility();
}

function renderL3ScheduleUI(daemonSt) {
  const daemonRunning = daemonSt?.daemon_state === "running";
  const schedule = daemonSt?.schedule;
  const label =
    schedule?.label ||
    (daemonRunning ? "Every 6 hours (default)" : `Every ${L3_DEFAULT_INTERVAL_HOURS} hours (default)`);

  if (els.l3MetaSchedule) {
    els.l3MetaSchedule.textContent = daemonRunning ? label : `Not running · selected: ${label}`;
  }

  if (els.l3SchedulePanel) {
    els.l3SchedulePanel.classList.toggle("l3-schedule-locked", daemonRunning);
  }

  if (els.l3ScheduleActiveBadge) {
    els.l3ScheduleActiveBadge.classList.toggle("hidden", !daemonRunning);
  }

  if (els.l3ScheduleActiveLabel) {
    if (daemonRunning) {
      const next = daemonSt.next_run_time ? formatTime(daemonSt.next_run_time) : "—";
      els.l3ScheduleActiveLabel.textContent = `Active schedule: ${label} · Next run: ${next}`;
      els.l3ScheduleActiveLabel.classList.remove("hidden");
    } else {
      els.l3ScheduleActiveLabel.classList.add("hidden");
      els.l3ScheduleActiveLabel.textContent = "";
    }
  }

  if (daemonRunning && schedule) {
    applyL3SchedulePrefsToForm({
      mode: schedule.mode || "default",
      intervalHours: schedule.interval_hours ?? L3_DEFAULT_INTERVAL_HOURS,
      intervalMinutes: schedule.interval_minutes ?? "",
    });
  } else if (!daemonRunning) {
    applyL3SchedulePrefsToForm(loadL3SchedulePrefs());
  }
}

function initL3ScheduleControls() {
  applyL3SchedulePrefsToForm(loadL3SchedulePrefs());
  document.querySelectorAll('input[name="l3ScheduleMode"]').forEach((input) => {
    input.addEventListener("change", () => {
      syncL3ScheduleCustomVisibility();
      saveL3SchedulePrefs({
        mode: input.value,
        intervalHours: parseFloat(els.l3CustomIntervalHours?.value) || 12,
        intervalMinutes: els.l3CustomIntervalMinutes?.value || "",
      });
    });
  });
  els.l3CustomIntervalHours?.addEventListener("change", () => {
    if (els.l3CustomIntervalMinutes) els.l3CustomIntervalMinutes.value = "";
    readL3ScheduleForm();
  });
  els.l3CustomIntervalMinutes?.addEventListener("change", () => {
    if (els.l3CustomIntervalMinutes?.value) {
      if (els.l3CustomIntervalHours) els.l3CustomIntervalHours.value = "";
    }
    readL3ScheduleForm();
  });
}

function updateL3OpsStatus(daemonSt, trend, latest) {
  const scanRunning = daemonSt.l3_scan_state === "running";
  const daemonRunning = daemonSt.daemon_state === "running";
  const health = latest?.health || "unknown";

  if (els.l3ScanStatusBadge) {
    els.l3ScanStatusBadge.textContent = scanRunning ? "Scanning" : daemonRunning ? "Scheduled" : "Idle";
    els.l3ScanStatusBadge.className = `soc-status-badge ${
      scanRunning ? "soc-status-running" : health === "healthy" ? "soc-status-healthy" : "soc-status-idle"
    }`;
  }

  if (els.l3AgentHealthDot && els.l3AgentHealthLabel) {
    els.l3AgentHealthDot.className = "soc-health-dot";
    if (scanRunning) {
      els.l3AgentHealthDot.classList.add("soc-health-run");
      els.l3AgentHealthLabel.textContent = "Agent executing scan pipeline";
    } else if (health === "healthy") {
      els.l3AgentHealthDot.classList.add("soc-health-ok");
      els.l3AgentHealthLabel.textContent = "Agent healthy · last scan passed";
    } else if (health === "degraded") {
      els.l3AgentHealthDot.classList.add("soc-health-warn");
      els.l3AgentHealthLabel.textContent = "Agent degraded · review scan health";
    } else {
      els.l3AgentHealthDot.classList.add("soc-health-unknown");
      els.l3AgentHealthLabel.textContent = daemonRunning ? "Daemon active · awaiting scan" : "Agent standby";
    }
  }

  if (els.l3LiveBadge) {
    els.l3LiveBadge.textContent = scanRunning ? "Live Scan" : daemonRunning ? "Monitoring" : "Live";
  }
}

async function loadL3Dashboard() {
  try {
    const [trend, daemonSt] = await Promise.all([
      fetchJSON("/api/l3/trend"),
      fetchJSON("/api/l3/daemon/status"),
    ]);

    // Determine the latest scan run id for health filtering
    l3LatestScanRunId = trend.latest_scan_run?.id || null;

    const [findings, health, audit, allFindings] = await Promise.all([
      fetchJSON(`/api/l3/findings${buildL3FindingsQuery()}`),
      fetchJSON(`/api/l3/scan-health${l3LatestScanRunId ? `?scan_run_id=${l3LatestScanRunId}` : ""}`),
      fetchJSON("/api/l3/audit?limit=50"),
      fetchJSON("/api/l3/findings"),
    ]);

    renderL3Pipeline(trend, daemonSt, health);
    renderL3AgentMetrics(trend.agent_metrics);
    renderL3SocSparklines(trend, trend.agent_metrics);
    renderL3ScanPipelineHero(daemonSt.l3_scan_state === "running", daemonSt.log_tail);
    renderL3PostureChart(trend.scan_history);
    renderL3ActivityFeed(audit, daemonSt.log_tail);
    renderL3PostureCenter(allFindings);
    renderL3CriticalFindings(allFindings);
    updateL3OpsStatus(daemonSt, trend, trend.latest_scan_run);
    renderL3ScheduleUI(daemonSt);

    // KPIs
    const hasData = trend.has_scan_data || (trend.pipeline?.total_findings ?? 0) > 0;
    const openCritical = trend.open_critical_count ?? trend.open_findings_by_severity?.critical ?? 0;
    const slaBreaches = trend.sla_breached_count ?? 0;
    const l3m = trend.agent_metrics?.level3 || {};

    if (!hasData) {
      animateSocCounter(els.l3PostureScore, "—");
      els.l3TrendDirection.textContent = "Run first scan";
      els.l3TrendDirection.className = "kpi-value soc-kpi-value trend-no_data";
      if (els.l3TrendHint) {
        els.l3TrendHint.textContent = "";
        els.l3TrendHint.classList.add("hidden");
      }
      animateSocCounter(els.l3OpenCritical, "—");
      animateSocCounter(els.l3SlaBreaches, "—");
      setSocProgress(els.l3PostureProgress, 0);
    } else {
      const postureText =
        trend.posture_score != null ? `${Math.round(trend.posture_score)}/100` : "—";
      animateSocCounter(els.l3PostureScore, postureText);
      setSocProgress(els.l3PostureProgress, trend.posture_score ?? 0);
      const dir = trend.trend_direction || "—";
      els.l3TrendDirection.textContent = formatL3TrendLabel(dir, trend.posture_score);
      els.l3TrendDirection.className = `kpi-value soc-kpi-value trend-${dir}`;
      const hint = l3TrendHintText(trend);
      if (els.l3TrendHint) {
        els.l3TrendHint.textContent = hint || "";
        els.l3TrendHint.classList.toggle("hidden", !hint);
        els.l3TrendHint.classList.toggle("kpi-hint-warn", Boolean(trend.data_inconsistent));
      }
      animateSocCounter(els.l3OpenCritical, String(openCritical));
      animateSocCounter(els.l3SlaBreaches, String(slaBreaches));
    }

    const daemonRunning = daemonSt.daemon_state === "running";
    const l3ScanRunning = daemonSt.l3_scan_state === "running";
    els.l3DaemonStatus.textContent = daemonRunning ? "Running" : "Stopped";
    els.l3DaemonStatus.className = `kpi-value soc-kpi-value ${daemonRunning ? "text-healthy" : ""}`;
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
      if (els.l3MetaDuration) {
        els.l3MetaDuration.textContent =
          latest.duration_seconds != null ? `${Math.round(latest.duration_seconds)}s` : "—";
      }
    } else {
      els.l3MetaHealth.textContent = "—";
      els.l3MetaPosture.textContent = "—";
      els.l3MetaLifecycle.textContent = "—";
      els.l3MetaStarted.textContent = "—";
      if (els.l3MetaDuration) els.l3MetaDuration.textContent = "—";
    }

    els.l3MetaNextRun.textContent = daemonSt.next_run_time ? formatTime(daemonSt.next_run_time) : "—";
    els.l3MetaSlack.textContent = trend.slack_configured ? "Configured" : "Not configured";
    if (els.l3MetaSuccessRate) {
      const rate = l3m.scan_reliability_rate;
      els.l3MetaSuccessRate.textContent =
        rate != null && l3m.total_scan_runs
          ? `${Math.round(rate * 100)}% (${l3m.successful_scan_runs}/${l3m.total_scan_runs})`
          : "—";
    }

    // Keep hidden legacy container in sync for any code that reads it
    if (els.l3TrendHistory && trend.scan_history?.length) {
      els.l3TrendHistory.innerHTML = trend.scan_history
        .slice(-10)
        .map(
          (r) =>
            `<div class="trend-history-row"><span>${formatTime(r.timestamp)}</span><span>${r.posture_score ?? "N/A"}/100</span></div>`
        )
        .join("");
    }

    // Activity log (hidden raw)
    if (daemonSt.log_tail?.length && els.l3LogOutput) {
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
    const f1Text = d.f1_score != null ? d.f1_score.toFixed(2) : "—";
    els.l3MetricF1.textContent = f1Text;
    setSocProgress(els.l3F1Progress, d.f1_score != null ? d.f1_score * 100 : 0);
  }
  if (els.l3MetricSlaCompliance) {
    const pct = l3.sla_compliance_rate != null ? `${Math.round(l3.sla_compliance_rate * 100)}%` : "—";
    els.l3MetricSlaCompliance.textContent = pct;
    setSocProgress(els.l3SlaComplianceProgress, l3.sla_compliance_rate != null ? l3.sla_compliance_rate * 100 : 0);
  }
  if (els.l3MetricReliability) {
    const pct = l3.scan_reliability_rate != null ? `${Math.round(l3.scan_reliability_rate * 100)}%` : "—";
    els.l3MetricReliability.textContent = pct;
    setSocProgress(els.l3ReliabilityProgress, l3.scan_reliability_rate != null ? l3.scan_reliability_rate * 100 : 0);
  }
  if (els.l3MetricResolution) {
    const pct = l3.resolution_rate != null ? `${Math.round(l3.resolution_rate * 100)}%` : "—";
    els.l3MetricResolution.textContent = pct;
    setSocProgress(els.l3ResolutionProgress, l3.resolution_rate != null ? l3.resolution_rate * 100 : 0);
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
  const schedule = daemonSt.schedule;

  let scanMetric = "No scans yet — click Run L3 Once";
  if (scanRunning) {
    scanMetric = "⟳ Scan in progress…";
  } else if (scanRuns > 0) {
    const next = daemonSt.next_run_time ? formatTime(daemonSt.next_run_time) : "manual";
    scanMetric = `${scanRuns} scan run(s)`;
    if (l3m.total_scan_runs) {
      scanMetric += ` · reliability ${Math.round((l3m.scan_reliability_rate || 0) * 100)}% (${l3m.successful_scan_runs}/${l3m.total_scan_runs})`;
    }
    if (daemonRunning) scanMetric += ` · Daemon ON · ${schedule?.label || "every 6h"} · next: ${next}`;
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
    const body = buildL3DaemonStartBody();
    await fetchJSON("/api/l3/daemon/start", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    const label =
      body.schedule_mode === "custom"
        ? body.interval_minutes
          ? `every ${body.interval_minutes} min`
          : `every ${body.interval_hours}h`
        : "every 6 hours (default)";
    showToast(`Daemon started — scans ${label}`);
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
if (els.runScanL1BtnSecondary) els.runScanL1BtnSecondary.addEventListener("click", () => startScan(1));
if (els.themeToggle) els.themeToggle.addEventListener("click", toggleTheme);

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
bindClick(els.exportReportPdfBtn, () => exportReportAsPdf());

bindClick(els.clearReportsBtn, () => clearAllReports());

bindClick(els.refreshBtn, () => refreshCurrentView());

// ─── Init ────────────────────────────────────────────────────────────────────

async function init() {
  initTheme();
  initReportHistoryCollapse();
  initTerminalClientInfo();
  initL3ScheduleControls();
  resetL1PipelineTrials();
  ensureL2PipelineViz();
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
