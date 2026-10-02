const CH = (() => {
  const CSS = (n, fb) => (getComputedStyle(document.documentElement).getPropertyValue(n) || fb).trim() || fb;

  function prep(cv) {
    const dpr = Math.min(2, window.devicePixelRatio || 1);
    const w = cv.clientWidth || cv.width;
    const h = cv.clientHeight || cv.height;
    if (cv.width !== Math.round(w * dpr) || cv.height !== Math.round(h * dpr)) {
      cv.width = Math.round(w * dpr);
      cv.height = Math.round(h * dpr);
    }
    const c = cv.getContext("2d");
    c.setTransform(dpr, 0, 0, dpr, 0, 0);
    c.clearRect(0, 0, w, h);
    return { c, w, h };
  }

  function grid(c, w, h, pad, rows = 4) {
    c.strokeStyle = "rgba(140,170,200,0.10)";
    c.lineWidth = 1;
    for (let i = 0; i <= rows; i++) {
      const y = pad.t + ((h - pad.t - pad.b) * i) / rows;
      c.beginPath();
      c.moveTo(pad.l, y);
      c.lineTo(w - pad.r, y);
      c.stroke();
    }
  }

  function fmtAxis(v, unit) {
    const a = Math.abs(v);
    let s;
    if (a >= 1e9) s = (v / 1e9).toFixed(1) + "G";
    else if (a >= 1e6) s = (v / 1e6).toFixed(1) + "M";
    else if (a >= 1e3) s = (v / 1e3).toFixed(1) + "k";
    else if (a >= 10) s = v.toFixed(0);
    else if (a >= 1) s = v.toFixed(1);
    else s = v.toFixed(2);
    return unit ? s + unit : s;
  }

  function lineChart(cv, series, opts = {}) {
    const { c, w, h } = prep(cv);
    const pad = opts.pad || { l: 46, r: 12, t: 10, b: 20 };
    const n = opts.n || 120;
    let max = opts.max;
    if (max === undefined) {
      max = 0;
      for (const s of series) for (let i = 0; i < s.data.length; i++) if (s.data[i] > max) max = s.data[i];
      max = max * 1.15 || 1;
    }
    grid(c, w, h, pad, opts.rows || 4);
    c.font = "10px ui-monospace, SFMono-Regular, Menlo, monospace";
    c.fillStyle = "rgba(160,185,210,0.55)";
    c.textAlign = "right";
    c.textBaseline = "middle";
    const steps = opts.rows || 4;
    for (let i = 0; i <= steps; i++) {
      const y = pad.t + ((h - pad.t - pad.b) * i) / steps;
      c.fillText(fmtAxis(max * (1 - i / steps), opts.unit), w - pad.r - 4, y);
    }
    const X = (i) => pad.l + ((w - pad.l - pad.r) * i) / Math.max(1, n - 1);
    const Y = (v) => pad.t + (h - pad.t - pad.b) * (1 - v / max);
    for (const s of series) {
      if (s.fill) {
        c.beginPath();
        c.moveTo(X(0), h - pad.b);
        const len = s.data.length;
        for (let i = 0; i < len; i++) c.lineTo(X(n - len + i), Y(s.data[i]));
        c.lineTo(X(n - 1), h - pad.b);
        c.closePath();
        const g = c.createLinearGradient(0, pad.t, 0, h - pad.b);
        g.addColorStop(0, s.fill);
        g.addColorStop(1, "rgba(0,0,0,0)");
        c.fillStyle = g;
        c.fill();
      }
      c.beginPath();
      const len = s.data.length;
      for (let i = 0; i < len; i++) {
        const x = X(n - len + i), y = Y(s.data[i]);
        if (i === 0) c.moveTo(x, y);
        else c.lineTo(x, y);
      }
      c.strokeStyle = s.color;
      c.lineWidth = s.width || 1.6;
      if (s.dash) c.setLineDash(s.dash);
      c.lineJoin = "round";
      c.stroke();
      c.setLineDash([]);
      if (s.dot && len) {
        c.fillStyle = s.color;
        c.beginPath();
        c.arc(X(n - 1), Y(s.data[len - 1]), 2.4, 0, Math.PI * 2);
        c.fill();
      }
    }
    c.strokeStyle = "rgba(140,170,200,0.18)";
    c.beginPath();
    c.moveTo(pad.l, h - pad.b);
    c.lineTo(w - pad.r, h - pad.b);
    c.stroke();
    return { X, Y, max };
  }

  function stackedArea(cv, series, opts = {}) {
    const { c, w, h } = prep(cv);
    const pad = opts.pad || { l: 46, r: 12, t: 10, b: 20 };
    const n = opts.n || 120;
    let max = 0;
    for (let i = 0; i < n; i++) {
      let s = 0;
      for (const k in series) if (series[k].data[i]) s += series[k].data[i];
      if (s > max) max = s;
    }
    max = max * 1.15 || 1;
    grid(c, w, h, pad, 4);
    c.font = "10px ui-monospace, SFMono-Regular, Menlo, monospace";
    c.fillStyle = "rgba(160,185,210,0.55)";
    c.textAlign = "right";
    c.textBaseline = "middle";
    for (let i = 0; i <= 4; i++) {
      const y = pad.t + ((h - pad.t - pad.b) * i) / 4;
      c.fillText(fmtAxis(max * (1 - i / 4)), w - pad.r - 4, y);
    }
    const X = (i) => pad.l + ((w - pad.l - pad.r) * i) / Math.max(1, n - 1);
    const base = new Float64Array(n);
    for (const k in series) {
      const s = series[k];
      c.beginPath();
      for (let i = 0; i < n; i++) {
        const y = pad.t + (h - pad.t - pad.b) * (1 - (base[i] + s.data[i]) / max);
        if (i === 0) c.moveTo(X(i), y);
        else c.lineTo(X(i), y);
      }
      for (let i = n - 1; i >= 0; i--) {
        const y = pad.t + (h - pad.t - pad.b) * (1 - base[i] / max);
        c.lineTo(X(i), y);
      }
      c.closePath();
      c.fillStyle = s.fill || s.color;
      c.globalAlpha = 0.72;
      c.fill();
      c.globalAlpha = 1;
      for (let i = 0; i < n; i++) base[i] += s.data[i];
    }
    c.strokeStyle = "rgba(140,170,200,0.18)";
    c.beginPath();
    c.moveTo(pad.l, h - pad.b);
    c.lineTo(w - pad.r, h - pad.b);
    c.stroke();
  }

  function bars(cv, items, opts = {}) {
    const { c, w, h } = prep(cv);
    const pad = opts.pad || { l: 40, r: 8, t: 8, b: 26 };
    let max = 0;
    for (const it of items) if (it.v > max) max = it.v;
    max = max || 1;
    grid(c, w, h, pad, 3);
    c.font = "10px ui-monospace, SFMono-Regular, Menlo, monospace";
    c.fillStyle = "rgba(160,185,210,0.55)";
    c.textAlign = "right";
    c.textBaseline = "middle";
    for (let i = 0; i <= 3; i++) {
      const y = pad.t + ((h - pad.t - pad.b) * i) / 3;
      c.fillText(fmtAxis(max * (1 - i / 3)), w - pad.r - 3, y);
    }
    const bw = (w - pad.l - pad.r) / Math.max(1, items.length);
    items.forEach((it, i) => {
      const x = pad.l + i * bw + bw * 0.22;
      const bwid = bw * 0.56;
      const y = pad.t + (h - pad.t - pad.b) * (1 - it.v / max);
      c.fillStyle = it.color || "#4dabf7";
      c.beginPath();
      const r = Math.min(3, bwid / 2);
      c.moveTo(x, h - pad.b);
      c.lineTo(x, y + r);
      c.quadraticCurveTo(x, y, x + r, y);
      c.lineTo(x + bwid - r, y);
      c.quadraticCurveTo(x + bwid, y, x + bwid, y + r);
      c.lineTo(x + bwid, h - pad.b);
      c.closePath();
      c.fill();
      if (opts.labels !== false) {
        c.fillStyle = "rgba(190,210,230,0.75)";
        c.textAlign = "center";
        c.textBaseline = "top";
        c.font = "9px ui-monospace, SFMono-Regular, Menlo, monospace";
        c.fillText(it.k, x + bwid / 2, h - pad.b + 5);
        if (it.top) {
          c.fillStyle = "rgba(230,240,250,0.95)";
          c.textBaseline = "bottom";
          c.font = "9px ui-monospace, SFMono-Regular, Menlo, monospace";
          c.fillText(it.top, x + bwid / 2, y - 2);
        }
      }
    });
  }

  function donut(cv, items, opts = {}) {
    const { c, w, h } = prep(cv);
    const cx = opts.cx || w / 2;
    const cy = opts.cy || h / 2;
    const R = Math.min(w, h) / 2 - (opts.pad || 6);
    const r0 = R * (opts.inner || 0.62);
    let tot = 0;
    for (const it of items) tot += it.v;
    if (tot <= 0) {
      c.beginPath();
      c.arc(cx, cy, (R + r0) / 2, 0, Math.PI * 2);
      c.strokeStyle = "rgba(120,150,180,0.2)";
      c.lineWidth = R - r0;
      c.stroke();
      c.fillStyle = "rgba(150,175,200,0.5)";
      c.font = "11px ui-monospace, monospace";
      c.textAlign = "center";
      c.textBaseline = "middle";
      c.fillText("no data", cx, cy);
      return;
    }
    let a0 = -Math.PI / 2;
    for (const it of items) {
      if (it.v <= 0) continue;
      const a1 = a0 + (it.v / tot) * Math.PI * 2;
      c.beginPath();
      c.arc(cx, cy, R, a0, a1);
      c.arc(cx, cy, r0, a1, a0, true);
      c.closePath();
      c.fillStyle = it.color;
      c.fill();
      a0 = a1;
    }
    if (opts.centerTop) {
      c.fillStyle = "rgba(235,245,255,0.95)";
      c.font = "600 20px ui-monospace, SFMono-Regular, Menlo, monospace";
      c.textAlign = "center";
      c.textBaseline = "alphabetic";
      c.fillText(opts.centerTop, cx, cy + 2);
    }
    if (opts.centerSub) {
      c.fillStyle = "rgba(160,185,210,0.7)";
      c.font = "9px ui-monospace, monospace";
      c.textAlign = "center";
      c.textBaseline = "top";
      c.fillText(opts.centerSub, cx, cy + 6);
    }
  }

  function legend(el, items, opts = {}) {
    el.innerHTML = items
      .map(
        (it) =>
          `<span class="lg"><i style="background:${it.color}"></i>${U.esc(it.k)}<b>${it.txt !== undefined ? it.txt : it.v}</b></span>`
      )
      .join("");
  }

  function heatmap(cv, m, rowLabels, colLabels, opts = {}) {
    const { c, w, h } = prep(cv);
    const rows = rowLabels.length, cols = colLabels.length;
    const pad = { l: opts.left || 96, r: 8, t: 18, b: 6 };
    const cw = (w - pad.l - pad.r) / cols;
    const chh = (h - pad.t - pad.b) / rows;
    let max = 0;
    for (let i = 0; i < rows; i++) for (let j = 0; j < cols; j++) if (m[i][j] > max) max = m[i][j];
    max = max || 1;
    c.font = "9px ui-monospace, monospace";
    for (let i = 0; i < rows; i++) {
      c.fillStyle = "rgba(190,210,230,0.8)";
      c.textAlign = "right";
      c.textBaseline = "middle";
      c.fillText(rowLabels[i], pad.l - 6, pad.t + chh * (i + 0.5));
      for (let j = 0; j < cols; j++) {
        const v = m[i][j] / max;
        const x = pad.l + cw * j, y = pad.t + chh * i;
        c.fillStyle = i === j ? `rgba(77,171,247,${0.15 + v * 0.8})` : `rgba(255,77,109,${0.06 + v * 0.85})`;
        c.fillRect(x + 1, y + 1, cw - 2, chh - 2);
        c.fillStyle = "rgba(10,16,24,0.9)";
        c.textAlign = "center";
        c.font = "9px ui-monospace, monospace";
        if (cw > 22) c.fillText(String(m[i][j]), x + cw / 2, y + chh / 2);
      }
    }
    c.fillStyle = "rgba(160,185,210,0.65)";
    c.textAlign = "center";
    c.textBaseline = "bottom";
    c.font = "9px ui-monospace, monospace";
    for (let j = 0; j < cols; j++) {
      c.save();
      c.translate(pad.l + cw * (j + 0.5), pad.t - 3);
      c.rotate(-0.32);
      c.fillText(colLabels[j], 0, 0);
      c.restore();
    }
  }

  function scatter(cv, pts, opts = {}) {
    const { c, w, h } = prep(cv);
    const pad = { l: 44, r: 12, t: 12, b: 26 };
    let mx = 0, my = 0;
    for (const p of pts) {
      if (p.x > mx) mx = p.x;
      if (p.y > my) my = p.y;
    }
    mx = mx * 1.1 || 1;
    my = my * 1.1 || 1;
    grid(c, w, h, pad, 4);
    c.font = "9px ui-monospace, monospace";
    c.fillStyle = "rgba(160,185,210,0.6)";
    c.textAlign = "right";
    c.textBaseline = "middle";
    for (let i = 0; i <= 4; i++) {
      const y = pad.t + ((h - pad.t - pad.b) * i) / 4;
      c.fillText(fmtAxis(my * (1 - i / 4)), w - pad.r - 3, y);
    }
    c.textAlign = "center";
    c.textBaseline = "top";
    for (let i = 0; i <= 4; i++) {
      const x = pad.l + ((w - pad.l - pad.r) * i) / 4;
      c.fillText(fmtAxis(mx * (i / 4)), x, h - pad.b + 4);
    }
    c.textAlign = "left";
    c.fillText(opts.xlabel || "", pad.l, h - 11);
    c.save();
    c.translate(11, h / 2);
    c.rotate(-Math.PI / 2);
    c.textAlign = "center";
    c.fillText(opts.ylabel || "", 0, 0);
    c.restore();
    for (const p of pts) {
      const x = pad.l + ((w - pad.l - pad.r) * p.x) / mx;
      const y = pad.t + (h - pad.t - pad.b) * (1 - p.y / my);
      c.beginPath();
      c.arc(x, y, opts.r || 2.4, 0, Math.PI * 2);
      c.fillStyle = p.color;
      c.globalAlpha = p.a === undefined ? 0.6 : p.a;
      c.fill();
      c.globalAlpha = 1;
    }
  }

  function gauge(cv, v, opts = {}) {
    const { c, w, h } = prep(cv);
    const cx = w / 2, cy = h * 0.78, R = Math.min(w / 2, h * 0.8) - 4;
    c.lineCap = "round";
    c.lineWidth = 9;
    c.strokeStyle = "rgba(120,150,180,0.16)";
    c.beginPath();
    c.arc(cx, cy, R, Math.PI, 0);
    c.stroke();
    const g = c.createLinearGradient(cx - R, 0, cx + R, 0);
    g.addColorStop(0, "#3ddc97");
    g.addColorStop(0.55, "#ffd43b");
    g.addColorStop(1, "#ff4d6d");
    c.strokeStyle = g;
    c.beginPath();
    c.arc(cx, cy, R, Math.PI, Math.PI + Math.PI * U.clamp(v, 0, 1));
    c.stroke();
    c.fillStyle = "rgba(235,245,255,0.96)";
    c.font = "600 17px ui-monospace, SFMono-Regular, Menlo, monospace";
    c.textAlign = "center";
    c.textBaseline = "alphabetic";
    c.fillText(opts.text || U.round(v * 100, 0) + "%", cx, cy - 4);
    c.fillStyle = "rgba(160,185,210,0.7)";
    c.font = "9px ui-monospace, monospace";
    c.fillText(opts.sub || "", cx, cy + 9);
  }

  function hbars(cv, items, opts = {}) {
    const { c, w, h } = prep(cv);
    const pad = { l: opts.left || 128, r: 52, t: 4, b: 4 };
    let max = 0;
    for (const it of items) max = Math.max(max, Math.abs(it.v));
    max = max || 1;
    const rh = (h - pad.t - pad.b) / Math.max(1, items.length);
    c.font = "9px ui-monospace, monospace";
    items.forEach((it, i) => {
      const y = pad.t + rh * i;
      c.fillStyle = "rgba(190,210,230,0.78)";
      c.textAlign = "right";
      c.textBaseline = "middle";
      c.fillText(it.k, pad.l - 6, y + rh / 2);
      const bw = ((w - pad.l - pad.r) * Math.abs(it.v)) / max;
      c.fillStyle = it.v >= 0 ? (it.color || "#4dabf7") : "#ff8fa3";
      c.fillRect(pad.l, y + rh * 0.22, Math.max(1, bw), rh * 0.56);
      c.fillStyle = "rgba(200,220,240,0.85)";
      c.textAlign = "left";
      c.fillText(it.txt !== undefined ? it.txt : U.round(it.v, 3), pad.l + bw + 5, y + rh / 2);
    });
  }

  return { lineChart, stackedArea, bars, donut, heatmap, scatter, gauge, hbars, legend, prep };
})();
