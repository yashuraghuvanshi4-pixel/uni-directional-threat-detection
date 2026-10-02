const U = (() => {
  function mulberry32(seed) {
    let a = seed >>> 0;
    return function () {
      a = (a + 0x6d2b79f5) | 0;
      let t = Math.imul(a ^ (a >>> 15), 1 | a);
      t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
      return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    };
  }

  class Rng {
    constructor(seed) {
      this.next = mulberry32(seed);
      this._g = null;
    }
    f() {
      return this.next();
    }
    int(n) {
      return Math.floor(this.next() * n);
    }
    range(a, b) {
      return a + this.next() * (b - a);
    }
    irange(a, b) {
      return a + Math.floor(this.next() * (b - a + 1));
    }
    pick(arr) {
      return arr[Math.floor(this.next() * arr.length)];
    }
    chance(p) {
      return this.next() < p;
    }
    gauss(mu = 0, sigma = 1) {
      if (this._g !== null) {
        const v = this._g;
        this._g = null;
        return mu + sigma * v;
      }
      let u = 0, v = 0, s = 0;
      do {
        u = this.next() * 2 - 1;
        v = this.next() * 2 - 1;
        s = u * u + v * v;
      } while (s >= 1 || s === 0);
      const f = Math.sqrt((-2 * Math.log(s)) / s);
      this._g = v * f;
      return mu + sigma * u * f;
    }
    poisson(lam) {
      if (lam <= 0) return 0;
      if (lam > 24) return Math.max(0, Math.round(this.gauss(lam, Math.sqrt(lam))));
      const L = Math.exp(-lam);
      let k = 0, p = 1;
      do {
        k++;
        p *= this.next();
      } while (p > L);
      return k - 1;
    }
    pareto(alpha, xm) {
      const u = this.next();
      return xm / Math.pow(1 - u, 1 / alpha);
    }
    shuffle(arr) {
      for (let i = arr.length - 1; i > 0; i--) {
        const j = Math.floor(this.next() * (i + 1));
        const t = arr[i];
        arr[i] = arr[j];
        arr[j] = t;
      }
      return arr;
    }
  }

  function shannonFromCounts(counts) {
    let total = 0;
    for (const k in counts) total += counts[k];
    if (total === 0) return 0;
    let h = 0;
    for (const k in counts) {
      const p = counts[k] / total;
      if (p > 0) h -= p * Math.log2(p);
    }
    return h;
  }

  function shannonFromCountsMap(map) {
    let total = 0;
    for (const v of map.values()) total += v;
    if (total === 0) return 0;
    let h = 0;
    for (const v of map.values()) {
      const p = v / total;
      if (p > 0) h -= p * Math.log2(p);
    }
    return h;
  }

  function shannonOf(arr) {
    const m = new Map();
    for (let i = 0; i < arr.length; i++) m.set(arr[i], (m.get(arr[i]) || 0) + 1);
    return shannonFromCountsMap(m);
  }

  function shannonOfBytes(u8) {
    const m = new Uint32Array(256);
    for (let i = 0; i < u8.length; i++) m[u8[i]]++;
    let total = 0;
    for (let i = 0; i < 256; i++) total += m[i];
    if (!total) return 0;
    let h = 0;
    for (let i = 0; i < 256; i++) {
      if (!m[i]) continue;
      const p = m[i] / total;
      h -= p * Math.log2(p);
    }
    return h;
  }

  function mean(a) {
    if (!a.length) return 0;
    let s = 0;
    for (let i = 0; i < a.length; i++) s += a[i];
    return s / a.length;
  }

  function std(a) {
    if (a.length < 2) return 0;
    const m = mean(a);
    let s = 0;
    for (let i = 0; i < a.length; i++) {
      const d = a[i] - m;
      s += d * d;
    }
    return Math.sqrt(s / (a.length - 1));
  }

  function median(a) {
    if (!a.length) return 0;
    const s = Array.from(a).sort((x, y) => x - y);
    const h = s.length >> 1;
    return s.length % 2 ? s[h] : (s[h - 1] + s[h]) / 2;
  }

  function quantile(a, q) {
    if (!a.length) return 0;
    const s = Array.from(a).sort((x, y) => x - y);
    const pos = (s.length - 1) * q;
    const lo = Math.floor(pos), hi = Math.ceil(pos);
    return lo === hi ? s[lo] : s[lo] + (s[hi] - s[lo]) * (pos - lo);
  }

  function normalizedGaps(sorted) {
    const g = [];
    for (let i = 1; i < sorted.length; i++) g.push(sorted[i] - sorted[i - 1]);
    return g;
  }

  function periodicity(sortedTs) {
    if (sortedTs.length < 6) return { r: 0, period: 0, cv: 1, ac: 0 };
    const t0 = sortedTs[0];
    const t = sortedTs.map((x) => x - t0);
    const gaps = normalizedGaps(t);
    const gm = mean(gaps);
    if (gm <= 0) return { r: 0, period: 0, cv: 1, ac: 0 };
    const p10 = quantile(gaps, 0.1);
    const cyc = gaps.filter((g) => g >= p10 * 3);
    const cycCV = cyc.length >= 3 ? U.cv(cyc) : 1;
    const ac = maxAutocorr(t, 0.15, 0.6, 6);
    const disp = Math.max(0, 1 - Math.min(1, cycCV));
    const r = Math.max(0, ac.r) * (0.28 + 0.72 * disp);
    return { r, period: ac.period, ac: ac.r, cv: cycCV, disp };
  }

  function maxAutocorr(t, minLag, maxLag, maxK) {
    if (t.length < 8) return { r: 0, period: 0 };
    const span = t[t.length - 1] - t[0];
    if (span <= 0) return { r: 0, period: 0 };
    const step = span / 220;
    const series = [];
    for (let x = 0; x <= span; x += step) series.push(0);
    for (let i = 0; i < t.length; i++) {
      const idx = Math.min(series.length - 1, Math.round((t[i] - t[0]) / step));
      series[idx]++;
    }
    let mu = 0;
    for (let i = 0; i < series.length; i++) mu += series[i];
    mu /= series.length;
    let denom = 0;
    for (let i = 0; i < series.length; i++) {
      const d = series[i] - mu;
      denom += d * d;
    }
    if (denom === 0) return { r: 0, period: 0 };
    const lagLo = Math.max(1, Math.floor((minLag / step)));
    const lagHi = Math.min(series.length - 2, Math.ceil(maxLag / step));
    let best = 0, bestLag = 0;
    for (let lag = lagLo; lag <= lagHi; lag++) {
      let num = 0;
      for (let i = 0; i + lag < series.length; i++) num += (series[i] - mu) * (series[i + lag] - mu);
      const r = num / denom;
      if (r > best) {
        best = r;
        bestLag = lag;
      }
    }
    return { r: best, period: bestLag * step };
  }

  function cv(a) {
    const m = mean(a);
    if (m <= 0) return 0;
    return std(a) / m;
  }

  class Ewma {
    constructor(alpha, init = null) {
      this.a = alpha;
      this.v = init;
    }
    push(x) {
      if (this.v === null) this.v = x;
      else this.v += this.a * (x - this.v);
      return this.v;
    }
    get value() {
      return this.v === null ? 0 : this.v;
    }
  }

  function clamp(x, lo, hi) {
    return x < lo ? lo : x > hi ? hi : x;
  }

  function sigmoid(x) {
    return x >= 0 ? 1 / (1 + Math.exp(-x)) : Math.exp(x) / (1 + Math.exp(x));
  }

  function softmax(arr) {
    let mx = -Infinity;
    for (let i = 0; i < arr.length; i++) if (arr[i] > mx) mx = arr[i];
    let s = 0;
    for (let i = 0; i < arr.length; i++) s += Math.exp(arr[i] - mx);
    const out = new Array(arr.length);
    for (let i = 0; i < arr.length; i++) out[i] = Math.exp(arr[i] - mx) / s;
    return out;
  }

  function logistic(agg, t) {
    let mx = -Infinity;
    for (let i = 0; i < agg.length; i++) if (agg[i] > mx) mx = agg[i];
    let s = 0;
    for (let i = 0; i < agg.length; i++) s += Math.exp(agg[i] - mx);
    return (Math.exp(agg[t] - mx)) / s;
  }

  function fmtBytes(n) {
    if (!n && n !== 0) return "-";
    const u = ["B", "KB", "MB", "GB", "TB"];
    let i = 0;
    let v = n;
    while (v >= 1024 && i < u.length - 1) {
      v /= 1024;
      i++;
    }
    return (i === 0 ? v.toFixed(0) : v.toFixed(v < 10 ? 2 : 1)) + " " + u[i];
  }

  function fmtNum(n) {
    if (n === null || n === undefined || Number.isNaN(n)) return "-";
    const a = Math.abs(n);
    if (a >= 1e9) return (n / 1e9).toFixed(2) + "B";
    if (a >= 1e6) return (n / 1e6).toFixed(2) + "M";
    if (a >= 1e3) return (n / 1e3).toFixed(2) + "k";
    if (a >= 1) return n.toFixed(2);
    return n.toFixed(3);
  }

  function fmtInt(n) {
    return Math.round(n).toLocaleString("en-US");
  }

  function fmtPct(x, d = 1) {
    return (x * 100).toFixed(d) + "%";
  }

  function fmtTime(ts) {
    const d = new Date(ts);
    const p = (v) => String(v).padStart(2, "0");
    return p(d.getUTCHours()) + ":" + p(d.getUTCMinutes()) + ":" + p(d.getUTCSeconds()) + "." + p(d.getUTCMilliseconds());
  }

  function fmtTimeShort(ts) {
    const d = new Date(ts);
    const p = (v) => String(v).padStart(2, "0");
    return p(d.getUTCHours()) + ":" + p(d.getUTCMinutes()) + ":" + p(d.getUTCSeconds());
  }

  function round(x, d = 4) {
    const m = Math.pow(10, d);
    return Math.round(x * m) / m;
  }

  function ring(arr, cap) {
    if (arr.length > cap) arr.splice(0, arr.length - cap);
    return arr;
  }

  function download(name, text, type) {
    const blob = new Blob([text], { type: type || "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = name;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 2000);
  }

  function downloadCanvas(name, canvas) {
    canvas.toBlob((b) => {
      const url = URL.createObjectURL(b);
      const a = document.createElement("a");
      a.href = url;
      a.download = name;
      document.body.appendChild(a);
      a.click();
      a.remove();
      setTimeout(() => URL.revokeObjectURL(url), 2000);
    });
  }

  function el(id) {
    return document.getElementById(id);
  }

  function esc(s) {
    return String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  }

  return {
    Rng, shannonFromCounts, shannonFromCountsMap, shannonOf, shannonOfBytes,
    mean, std, median, quantile, cv, maxAutocorr, periodicity, normalizedGaps,
    Ewma, clamp, sigmoid, softmax, logistic,
    fmtBytes, fmtNum, fmtInt, fmtPct, fmtTime, fmtTimeShort, round, ring,
    download, downloadCanvas, el, esc,
  };
})();
