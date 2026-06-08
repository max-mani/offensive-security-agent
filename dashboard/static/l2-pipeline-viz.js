/**
 * Level 2 — Enterprise live pipeline visualization (SVG + particles + pan/zoom).
 */
(function () {
  const VIEW_W = 620;
  const VIEW_H = 680;

  const NODES = [
    { id: "config", idx: 0, label: "Load Config", short: "1", x: 310, y: 48, color: "#8b949e", branch: "main" },
    { id: "aws", idx: 1, label: "AWS Infrastructure", short: "2", x: 88, y: 168, color: "#f59e0b", branch: "domain" },
    { id: "api", idx: 2, label: "API Scanner", short: "3", x: 88, y: 248, color: "#58a6ff", branch: "domain" },
    { id: "deps", idx: 3, label: "CVE Scanner", short: "4", x: 88, y: 328, color: "#a78bfa", branch: "domain" },
    { id: "secrets", idx: 4, label: "Secrets Scanner", short: "5", x: 88, y: 408, color: "#f85149", branch: "domain" },
    { id: "hub", idx: 5, label: "LLM Enrichment", short: "6", x: 310, y: 420, color: "#8957e5", branch: "main" },
    { id: "dedup", idx: 6, label: "Dedup", short: "7", x: 532, y: 340, color: "#2dd4bf", branch: "main" },
    { id: "ranking", idx: 7, label: "Impact Rank", short: "8", x: 532, y: 420, color: "#2dd4bf", branch: "main" },
    { id: "reports", idx: 8, label: "Reports", short: "9", x: 532, y: 500, color: "#3fb950", branch: "main" },
  ];

  const EDGES = [
    { from: 0, to: 1, d: "M 310 78 C 310 110, 180 130, 88 148" },
    { from: 1, to: 2, d: "M 88 192 C 88 210, 88 222, 88 232" },
    { from: 2, to: 3, d: "M 88 272 C 88 290, 88 302, 88 312" },
    { from: 3, to: 4, d: "M 88 352 C 88 370, 88 382, 88 392" },
    { from: 4, to: 5, d: "M 88 432 C 160 450, 240 440, 310 448" },
    { from: 5, to: 6, d: "M 338 420 C 400 400, 470 370, 532 356" },
    { from: 6, to: 7, d: "M 532 364 C 532 382, 532 394, 532 404" },
    { from: 7, to: 8, d: "M 532 444 C 532 462, 532 474, 532 484" },
  ];

  function ns(tag) {
    return document.createElementNS("http://www.w3.org/2000/svg", tag);
  }

  class L2PipelineViz {
    constructor(hostEl) {
      this.host = hostEl;
      this.transform = { x: 0, y: 0, scale: 1 };
      this.particles = [];
      this.rafId = null;
      this.displayIdx = 0;
      this.scanRunning = false;
      this.branchExpanded = false;
      this._build();
      this._bindInteractions();
      this._loop();
    }

    _build() {
      this.host.innerHTML = "";
      this.host.classList.add("l2-live-canvas-host");

      this.svg = ns("svg");
      this.svg.setAttribute("class", "l2-live-svg");
      this.svg.setAttribute("viewBox", `0 0 ${VIEW_W} ${VIEW_H}`);
      this.svg.setAttribute("preserveAspectRatio", "xMidYMid meet");

      const defs = ns("defs");
      defs.innerHTML = `
        <filter id="l2Glow" x="-50%" y="-50%" width="200%" height="200%">
          <feGaussianBlur stdDeviation="3" result="blur"/>
          <feMerge><feMergeNode in="blur"/><feMergeNode in="SourceGraphic"/></feMerge>
        </filter>
        <pattern id="l2Grid" width="24" height="24" patternUnits="userSpaceOnUse">
          <path d="M 24 0 L 0 0 0 24" fill="none" stroke="rgba(255,255,255,0.04)" stroke-width="1"/>
        </pattern>
      `;
      this.svg.appendChild(defs);

      this.viewport = ns("g");
      this.viewport.setAttribute("class", "l2-live-viewport");

      const bg = ns("rect");
      bg.setAttribute("width", VIEW_W);
      bg.setAttribute("height", VIEW_H);
      bg.setAttribute("fill", "url(#l2Grid)");
      this.viewport.appendChild(bg);

      this.edgeLayer = ns("g");
      this.edgeLayer.setAttribute("class", "l2-live-edges");
      this.viewport.appendChild(this.edgeLayer);

      this.particleLayer = ns("g");
      this.particleLayer.setAttribute("class", "l2-live-particles");
      this.viewport.appendChild(this.particleLayer);

      this.nodeLayer = ns("g");
      this.nodeLayer.setAttribute("class", "l2-live-nodes");
      this.viewport.appendChild(this.nodeLayer);

      this.edgeEls = EDGES.map((e, i) => {
        const path = ns("path");
        path.setAttribute("d", e.d);
        path.setAttribute("class", "l2-live-edge");
        path.setAttribute("data-edge", String(i));
        path.setAttribute("fill", "none");
        path.setAttribute("stroke", NODES[e.from].color);
        path.setAttribute("pathLength", "1");
        this.edgeLayer.appendChild(path);
        return path;
      });

      this.nodeEls = NODES.map((n) => {
        const g = ns("g");
        g.setAttribute("class", "l2-live-node");
        g.setAttribute("data-idx", String(n.idx));
        g.setAttribute("data-branch", n.branch);
        g.setAttribute("transform", `translate(${n.x}, ${n.y})`);

        const glow = ns("circle");
        glow.setAttribute("r", "34");
        glow.setAttribute("class", "l2-live-node-glow");

        const ring = ns("circle");
        ring.setAttribute("r", "28");
        ring.setAttribute("class", "l2-live-node-ring");
        ring.setAttribute("stroke", n.color);

        const core = ns("circle");
        core.setAttribute("r", "22");
        core.setAttribute("class", "l2-live-node-core");

        const num = ns("text");
        num.setAttribute("class", "l2-live-node-num");
        num.setAttribute("y", "5");
        num.textContent = n.short;

        const label = ns("text");
        label.setAttribute("class", "l2-live-node-label");
        label.setAttribute("y", "48");
        label.textContent = n.label;

        const badge = ns("circle");
        badge.setAttribute("cx", "20");
        badge.setAttribute("cy", "-18");
        badge.setAttribute("r", "5");
        badge.setAttribute("class", "l2-live-node-badge hidden");

        g.appendChild(glow);
        g.appendChild(ring);
        g.appendChild(core);
        g.appendChild(num);
        g.appendChild(label);
        g.appendChild(badge);
        this.nodeLayer.appendChild(g);

        g.addEventListener("mouseenter", (ev) => this._showTooltip(n, ev));
        g.addEventListener("mousemove", (ev) => this._moveTooltip(ev));
        g.addEventListener("mouseleave", () => this._hideTooltip());

        return { g, glow, ring, core, badge, meta: n };
      });

      this.svg.appendChild(this.viewport);
      this.host.appendChild(this.svg);

      this.tooltip = document.createElement("div");
      this.tooltip.className = "l2-live-tooltip hidden";
      this.host.appendChild(this.tooltip);
    }

    _bindInteractions() {
      this.host.addEventListener("wheel", (ev) => {
        ev.preventDefault();
        const delta = ev.deltaY > 0 ? 0.92 : 1.08;
        this.transform.scale = Math.min(2.2, Math.max(0.55, this.transform.scale * delta));
        this._applyTransform();
      }, { passive: false });

    }

    _applyTransform() {
      const { x, y, scale } = this.transform;
      this.viewport.setAttribute("transform", `translate(${x}, ${y}) scale(${scale})`);
    }

    zoomIn() {
      this.transform.scale = Math.min(2.2, this.transform.scale * 1.15);
      this._applyTransform();
    }

    zoomOut() {
      this.transform.scale = Math.max(0.55, this.transform.scale * 0.87);
      this._applyTransform();
    }

    resetView() {
      this.transform = { x: 0, y: 0, scale: 1 };
      this._applyTransform();
    }

    _showTooltip(node, ev) {
      const st = this.nodeEls[node.idx]?.g?.dataset.status || "pending";
      this.tooltip.innerHTML = `<strong>${node.label}</strong><span class="l2-live-tooltip-status l2-status-${st}">${st}</span>`;
      this.tooltip.classList.remove("hidden");
      this._moveTooltip(ev);
    }

    _hideTooltip() {
      this.tooltip.classList.add("hidden");
    }

    _moveTooltip(ev) {
      const rect = this.host.getBoundingClientRect();
      this.tooltip.style.left = `${ev.clientX - rect.left + 12}px`;
      this.tooltip.style.top = `${ev.clientY - rect.top + 12}px`;
    }

    _spawnParticle(edgeIdx) {
      const path = this.edgeEls[edgeIdx];
      if (!path) return;
      const len = path.getTotalLength();
      const dot = ns("circle");
      dot.setAttribute("r", "3");
      dot.setAttribute("class", "l2-live-particle");
      const edge = EDGES[edgeIdx];
      const fromNode = NODES[edge.from];
      dot.setAttribute("fill", fromNode.color);
      this.particleLayer.appendChild(dot);
      this.particles.push({ el: dot, path, len, t: 0, speed: 0.004 + Math.random() * 0.003 });
    }

    _loop() {
      const tick = () => {
        if (this.scanRunning && this.displayIdx >= 0) {
          const edgeIdx = Math.min(this.displayIdx, EDGES.length - 1);
          if (Math.random() < 0.08) this._spawnParticle(edgeIdx);
        }

        this.particles = this.particles.filter((p) => {
          p.t += p.speed;
          if (p.t >= 1) {
            p.el.remove();
            return false;
          }
          const pt = p.path.getPointAtLength(p.t * p.len);
          p.el.setAttribute("cx", pt.x);
          p.el.setAttribute("cy", pt.y);
          p.el.setAttribute("opacity", String(1 - p.t * 0.6));
          return true;
        });

        this.rafId = requestAnimationFrame(tick);
      };
      this.rafId = requestAnimationFrame(tick);
    }

    destroy() {
      if (this.rafId) cancelAnimationFrame(this.rafId);
      this.host.innerHTML = "";
    }

    reset() {
      this.displayIdx = 0;
      this.scanRunning = false;
      this.branchExpanded = false;
      this.particles.forEach((p) => p.el.remove());
      this.particles = [];
      this.update(0, [], false);
    }

    update(displayIdx, stepStatuses, scanRunning) {
      this.displayIdx = displayIdx;
      this.scanRunning = scanRunning;

      const expandDomain = scanRunning && displayIdx >= 1 && displayIdx <= 4;
      if (expandDomain !== this.branchExpanded) {
        this.branchExpanded = expandDomain;
        this.nodeLayer.classList.toggle("l2-branch-expanded", expandDomain);
        this.nodeLayer.classList.toggle("l2-branch-collapsed", !expandDomain && displayIdx > 4);
      }

      this.nodeEls.forEach((node, i) => {
        const st = stepStatuses[i] || "pending";
        const cssSt = st === "completed" ? "done" : st;
        node.g.dataset.status = st;
        node.g.classList.remove("l2-node-pending", "l2-node-running", "l2-node-done", "l2-node-failed", "l2-node-warning");
        node.g.classList.add(`l2-node-${cssSt}`);

        const show = node.meta.branch === "main" || expandDomain || (st !== "pending" && i <= displayIdx);
        node.g.style.opacity = show ? "1" : "0.15";
        node.g.style.pointerEvents = show ? "auto" : "none";

        node.badge.classList.toggle("hidden", st !== "running" && st !== "failed");
        node.badge.classList.toggle("l2-badge-running", st === "running");
        node.badge.classList.toggle("l2-badge-failed", st === "failed");
      });

      EDGES.forEach((e, i) => {
        const path = this.edgeEls[i];
        const fromSt = stepStatuses[e.from];
        const toIdx = e.to;
        let edgeSt = "idle";
        if (toIdx <= displayIdx && (stepStatuses[toIdx] === "completed" || stepStatuses[toIdx] === "running")) {
          edgeSt = toIdx === displayIdx && scanRunning ? "flowing" : "done";
        } else if (e.from <= displayIdx && toIdx === displayIdx + 1 && scanRunning) {
          edgeSt = "flowing";
        }
        if (fromSt === "failed" || stepStatuses[e.to] === "failed") edgeSt = "failed";

        path.classList.remove("l2-edge-idle", "l2-edge-flowing", "l2-edge-done", "l2-edge-failed");
        path.classList.add(`l2-edge-${edgeSt}`);
        if (edgeSt === "flowing") {
          path.setAttribute("stroke-dasharray", "0.06 0.04");
        } else {
          path.removeAttribute("stroke-dasharray");
          path.setAttribute("pathLength", "1");
        }

        const domainEdge = NODES[e.from].branch === "domain" || NODES[e.to].branch === "domain";
        path.style.opacity = !expandDomain && domainEdge && displayIdx < 1 ? "0.08" : "1";
      });
    }
  }

  window.L2PipelineViz = L2PipelineViz;
})();
