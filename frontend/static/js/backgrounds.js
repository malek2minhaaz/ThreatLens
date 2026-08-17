/* ============================================================
   ThreatLens — ambient background effects
   ------------------------------------------------------------
   Vanilla JS ports of two effects (this project has no
   React/Tailwind toolchain, so the React sources are ported
   irectly to DOM/canvas APIs):

   1. Prism Grid  (Originkit "prism-grid")
      A 3D-tiltable grid of boxes that lights each cell in a
      random color as the cursor moves across it, fading softly
      back out. Ported from the Originkit component (same grid
      math, inverse-perspective screen→plane projection and
      fade-out behavior).

   2. Neon Maze
      Full-screen canvas animation of an isometric neon maze
      (cube faces with cyan→magenta gradients, yellow strokes).
      Ported from the NeonMaze React component.

   3. Edge Scroll
      When the cursor is held near the top or bottom edge of the
      viewport, the page auto-scrolls in that direction; the speed
      ramps up the closer the cursor gets to the edge. Disable per
      page with data-edge-scroll="0" on the <html> element.

   Markup (all optional — only present layers are initialised):
     <div class="prism-grid" aria-hidden="true"
          data-rotate-x="10" data-rotate-y="-8"></div>
     <canvas class="neon-maze" aria-hidden="true"></canvas>

   Optional data attributes on .prism-grid:
     data-box-size    cell size in px (default 40)
     data-rotate-x    plane rotation around Y in deg (default 10)
     data-rotate-y    plane rotation around X in deg (default -8)
     data-colors      comma-separated palette for lit cells
     data-sway        sway amplitude in deg (default 4; 0 disables)
     data-sway-speed  seconds per full sway cycle (default 12)
   ============================================================ */
"use strict";

(function () {
  const PERSPECTIVE = 1000;
  const FADE_MS = 1000;

  const DEFAULT_COLORS = [
    "#22d3ee", // cyan
    "#34d399", // mint
    "#a3e635", // lime
    "#fbbf24", // amber
    "#e879f9", // magenta
    "#a78bfa", // violet
  ];

  /* Map a screen point (relative to the container centre) back onto
     the unrotated grid plane, given the plane's yaw/pitch rotation.
     Ported verbatim from the Originkit prism-grid component. */
  function screenToPlane(sx, sy, yawDeg, pitchDeg, p = PERSPECTIVE) {
    const a = (yawDeg * Math.PI) / 180;
    const b = (pitchDeg * Math.PI) / 180;
    const ca = Math.cos(a);
    const sa = Math.sin(a);
    const cb = Math.cos(b);
    const sb = Math.sin(b);

    const a11 = p * ca - sx * sa * cb;
    const a12 = sx * sb;
    const a21 = p * sa * sb - sy * sa * cb;
    const a22 = p * cb + sy * sb;

    const det = a11 * a22 - a12 * a21;
    if (!isFinite(det) || Math.abs(det) < 1e-6) return null;

    const b1 = sx * p;
    const b2 = sy * p;
    return {
      x: (b1 * a22 - a12 * b2) / det,
      y: (a11 * b2 - b1 * a21) / det,
    };
  }

  /* ---------------- Prism Grid ---------------- */

  class PrismGrid {
    constructor(el) {
      this.el = el;
      this.boxSize = parseInt(el.dataset.boxSize, 10) || 40;
      this.swingX = parseFloat(el.dataset.rotateX) || 0;
      this.swingY = parseFloat(el.dataset.rotateY) || 0;
      this.colors = el.dataset.colors
        ? el.dataset.colors
            .split(",")
            .map((c) => c.trim())
            .filter(Boolean)
        : DEFAULT_COLORS;

      this.cols = 0;
      this.rows = 0;
      this.lit = null; // current lit cell { row, col, el }

      // Slow idle sway: rotateY/rotateX oscillate around the base tilt.
      this.sway = parseFloat(el.dataset.sway);
      this.sway = Number.isFinite(this.sway) ? this.sway : 4;
      this.swaySpeed = parseFloat(el.dataset.swaySpeed) || 12;
      this.swayRaf = 0;
      this.t0 = performance.now();

      const scene = document.createElement("div");
      scene.className = "prism-grid__scene";

      const plane = document.createElement("div");
      plane.className = "prism-grid__plane";
      plane.style.backgroundSize = `${this.boxSize}px ${this.boxSize}px`;
      plane.style.transform = this.buildTransform(this.t0);

      scene.appendChild(plane);
      el.appendChild(scene);
      this.plane = plane;

      this.calculateGrid();
      this.startSway();
      window.addEventListener("resize", this.calculateGrid);
      window.addEventListener("pointermove", this.onMove, { passive: true });
      document.documentElement.addEventListener("mouseleave", this.leave);
      window.addEventListener("blur", this.leave);
    }

    calculateGrid = () => {
      const w = this.el.clientWidth || window.innerWidth;
      const h = this.el.clientHeight || window.innerHeight;
      this.cols = Math.max(1, Math.ceil(w / this.boxSize));
      this.rows = Math.max(1, Math.ceil(h / this.boxSize));
      this.plane.style.width = `${this.cols * this.boxSize}px`;
      this.plane.style.height = `${this.rows * this.boxSize}px`;
    };

    randomColor() {
      return this.colors[Math.floor(Math.random() * this.colors.length)] || DEFAULT_COLORS[0];
    }

    onMove = (e) => {
      const rect = this.el.getBoundingClientRect();
      const sx = e.clientX - rect.left - rect.width / 2;
      const sy = e.clientY - rect.top - rect.height / 2;

      // Use the live sway angles so the lit cell tracks the moving plane.
      const a = this.currentAngles(performance.now());
      const point = screenToPlane(sx, sy, a.x, a.y);
      if (!point) return this.leave();

      const gx = point.x + (this.cols * this.boxSize) / 2;
      const gy = point.y + (this.rows * this.boxSize) / 2;
      const col = Math.floor(gx / this.boxSize);
      const row = Math.floor(gy / this.boxSize);
      if (col < 0 || col >= this.cols || row < 0 || row >= this.rows) return this.leave();

      // Same cell — keep it lit, don't flicker.
      if (this.lit && this.lit.row === row && this.lit.col === col) return;

      this.leave();
      this.lit = { row, col, el: this.spawnCell(col, row) };
    };

    leave = () => {
      if (!this.lit) return;
      this.fadeOut(this.lit.el);
      this.lit = null;
    };

    /* Rotation angles at time `now` — base tilt plus a slow sway. */
    currentAngles(now) {
      if (!this.sway) return { x: this.swingX, y: this.swingY };
      const t = (((now - this.t0) / 1000) / this.swaySpeed) * Math.PI * 2;
      return {
        x: this.swingX + Math.sin(t) * this.sway,
        y: this.swingY + Math.cos(t) * this.sway,
      };
    }

    buildTransform(now) {
      const a = this.currentAngles(now);
      return `translate(-50%, -50%) rotateY(${a.x}deg) rotateX(${a.y}deg)`;
    }

    /* Animate the idle sway. Skipped for reduced-motion users. */
    startSway() {
      if (!this.sway) return;
      if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) return;
      const tick = (now) => {
        this.plane.style.transform = this.buildTransform(now);
        this.swayRaf = requestAnimationFrame(tick);
      };
      this.swayRaf = requestAnimationFrame(tick);
    }

    spawnCell(col, row) {
      const cell = document.createElement("div");
      cell.className = "prism-grid__cell";
      cell.style.left = `${col * this.boxSize}px`;
      cell.style.top = `${row * this.boxSize}px`;
      cell.style.width = `${this.boxSize}px`;
      cell.style.height = `${this.boxSize}px`;
      cell.style.backgroundColor = this.randomColor();
      this.plane.appendChild(cell);
      return cell;
    }

    fadeOut(el) {
      el.classList.add("is-fading");
      setTimeout(() => el.remove(), FADE_MS + 120);
    }
  }

  /* ---------------- Neon Maze ---------------- */

  class NeonMaze {
    constructor(canvas) {
      this.canvas = canvas;
      this.ctx = canvas.getContext("2d");
      this.t = 0;
      this.raf = 0;

      this.resize();
      window.addEventListener("resize", this.resize);
      this.drawFrame();

      if (!window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
        this.loop();
      }
    }

    resize = () => {
      this.canvas.width = window.innerWidth;
      this.canvas.height = window.innerHeight;
      this.drawFrame();
    };

    /* Colors adapt to the active theme (read fresh each frame so a
       mid-session theme toggle is picked up immediately). */
    palette() {
      const dark = document.documentElement.dataset.theme !== "light";
      return dark
        ? {
            fade: "rgba(7, 11, 20, 0.10)",
            c1: "rgba(34, 211, 238, 0.5)",
            c2: "rgba(232, 121, 249, 0.5)",
            stroke: "rgba(255, 255, 0, 0.3)",
            wire: "rgba(255, 255, 255, 0.18)",
          }
        : {
            fade: "rgba(255, 255, 255, 0.14)",
            c1: "rgba(34, 211, 238, 0.35)",
            c2: "rgba(232, 121, 249, 0.3)",
            stroke: "rgba(245, 158, 11, 0.3)",
            wire: "rgba(15, 23, 42, 0.15)",
          };
    }

    /* Draw one isometric maze frame (the `d()` from the original). */
    drawFrame = () => {
      const canvas = this.canvas;
      const x = this.ctx;
      if (!canvas || !x) return;

      const p = this.palette();
      const s = Math.min(canvas.width, canvas.height) / 15;
      const g = Math.ceil(canvas.width / s) * 2;
      const h = Math.ceil(canvas.height / (s * 0.5)) * 2;
      const w = canvas.width / 2;
      const v = canvas.height / 2;

      for (let y = -h; y < h; y++) {
        for (let i = -g; i < g; i++) {
          const px = w + ((i - y) * s) / 2;
          const q = v + ((i + y) * s) / 4;
          const m = Math.sqrt(i * i + y * y);
          const n = Math.sqrt(g * g + h * h);
          const e = 1 - m / n;
          const f = s * e * Math.abs(Math.sin(m * 0.5 + this.t));

          x.beginPath();
          x.moveTo(px, q - f);
          x.lineTo(px + s / 2, q - s / 2 - f);
          x.lineTo(px + s, q - f);
          x.lineTo(px + s, q);
          x.lineTo(px + s / 2, q + s / 2);
          x.lineTo(px, q);
          x.closePath();

          const l = x.createLinearGradient(px, q - f, px + s, q);
          l.addColorStop(0, p.c1);
          l.addColorStop(1, p.c2);
          x.fillStyle = l;
          x.fill();
          x.strokeStyle = p.stroke;
          x.stroke();

          x.beginPath();
          x.moveTo(px, q);
          x.lineTo(px, q - f);
          x.moveTo(px + s, q);
          x.lineTo(px + s, q - f);
          x.moveTo(px + s / 2, q + s / 2);
          x.lineTo(px + s / 2, q - s / 2 - f);
          x.strokeStyle = p.wire;
          x.stroke();
        }
      }
    };

    /* Animation loop: fade the previous frame, draw the next, advance t. */
    loop = () => {
      const x = this.ctx;
      const p = this.palette();
      x.fillStyle = p.fade;
      x.fillRect(0, 0, this.canvas.width, this.canvas.height);
      this.drawFrame();
      this.t += 0.05;
      this.raf = requestAnimationFrame(this.loop);
    };
  }

  /* ---------------- Edge scroll (cursor-driven page scroll) ---------------- */

  class EdgeScroll {
    constructor({ zoneRatio = 0.12, maxSpeed = 900 } = {}) {
      this.zoneRatio = zoneRatio;
      this.maxSpeed = maxSpeed; // px per second at the extreme edge
      this.velocity = 0; // px per second (negative = up)
      this.last = 0;
      this.raf = 0;

      window.addEventListener("pointermove", this.onMove, { passive: true });
      document.documentElement.addEventListener("mouseleave", this.onLeave);
      window.addEventListener("blur", this.onLeave);
      this.raf = requestAnimationFrame(this.loop);
    }

    scrollable() {
      return document.documentElement.scrollHeight > window.innerHeight + 4;
    }

    /* Never hijack the scroll while the pointer is over something the
       user is likely interacting with (forms, buttons, links). */
    onMove = (e) => {
      const t = e.target;
      if (t && typeof t.closest === "function" &&
          t.closest("textarea, input, select, button, a, [contenteditable='true']")) {
        this.velocity = 0;
        return;
      }
      if (!this.scrollable()) {
        this.velocity = 0;
        return;
      }
      const y = e.clientY;
      const h = window.innerHeight;
      const zone = h * this.zoneRatio;
      if (y < zone) {
        this.velocity = -this.maxSpeed * ((zone - y) / zone);
      } else if (y > h - zone) {
        this.velocity = this.maxSpeed * ((y - (h - zone)) / zone);
      } else {
        this.velocity = 0;
      }
    };

    onLeave = () => {
      this.velocity = 0;
    };

    loop = (now) => {
      if (this.last) {
        const dt = Math.min((now - this.last) / 1000, 0.05);
        if (this.velocity !== 0) {
          // "instant" overrides html { scroll-behavior: smooth } so each
          // frame moves exactly the intended distance.
          window.scrollBy({ top: this.velocity * dt, behavior: "instant" });
        }
      }
      this.last = now;
      this.raf = requestAnimationFrame(this.loop);
    };
  }

  /* ---------------- Boot ---------------- */

  function boot() {
    document.querySelectorAll(".prism-grid").forEach((el) => new PrismGrid(el));
    document.querySelectorAll("canvas.neon-maze").forEach((el) => new NeonMaze(el));

    // Edge scroll is on by default; set data-edge-scroll="0" on <html> to
    // disable it for a specific page. Skipped for reduced-motion users.
    if (
      document.documentElement.dataset.edgeScroll !== "0" &&
      !window.matchMedia("(prefers-reduced-motion: reduce)").matches
    ) {
      new EdgeScroll();
    }
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", boot);
  } else {
    boot();
  }
})();
