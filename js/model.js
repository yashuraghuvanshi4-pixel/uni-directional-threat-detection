const MODEL = (() => {
  const K = CLASSES.length;

  class SoftmaxLR {
    constructor(d = FEAT.D, k = K) {
      this.d = d;
      this.k = k;
      this.W = new Float64Array(d * k);
      this.b = new Float64Array(k);
      this.mu = new Float64Array(d);
      this.sd = new Float64Array(d).fill(1);
      this.lr = 0.5;
      this.l2 = 2e-4;
      this.epochs = 0;
      this.meta = {};
    }

    fitStats(X, n) {
      for (let j = 0; j < this.d; j++) {
        let s = 0;
        for (let i = 0; i < n; i++) s += X[i * this.d + j];
        this.mu[j] = s / n;
      }
      for (let j = 0; j < this.d; j++) {
        let s = 0;
        const m = this.mu[j];
        for (let i = 0; i < n; i++) {
          const t = X[i * this.d + j] - m;
          s += t * t;
        }
        const v = Math.sqrt(s / Math.max(1, n - 1));
        this.sd[j] = v < 1e-6 ? 1 : v;
      }
    }
    prepare(X, y, n, opts = {}) {
      const epochs = opts.epochs || 60;
      this.lr = opts.lr || 0.6;
      this.l2 = opts.l2 === undefined ? 3e-4 : opts.l2;
      this.epochs = epochs;
      this.fitStats(X, n);
      const counts = new Float64Array(this.k);
      for (let i = 0; i < n; i++) counts[y[i]]++;
      this.sampleW = new Float64Array(n);
      for (let i = 0; i < n; i++) {
        const c = counts[y[i]] || 1;
        this.sampleW[i] = Math.min(9, Math.sqrt(n / (this.k * c)));
      }
      this.order = new Int32Array(n);
      for (let i = 0; i < n; i++) this.order[i] = i;
      this._seed = 12345;
      this.history = [];
      return this;
    }

    epochStep(X, y, n, e, batch) {
      const d = this.d, k = this.k;
      const W = this.W, b = this.b, mu = this.mu, sd = this.sd;
      const gW = this._gW || (this._gW = new Float64Array(d * k));
      const gb = this._gb || (this._gb = new Float64Array(k));
      const Z = this._Z || (this._Z = new Float64Array(256 * k));
      const ps = this._ps || (this._ps = new Float64Array(k));
      const l2 = this.l2;
      const order = this.order;
      const rnd = () => {
        this._seed = (this._seed * 1103515245 + 12345) & 0x7fffffff;
        return this._seed / 0x7fffffff;
      };
      for (let i = n - 1; i > 0; i--) {
        const j = (rnd() * (i + 1)) | 0;
        const t = order[i];
        order[i] = order[j];
        order[j] = t;
      }
      const lrT = this.lr * (0.5 * (1 + Math.cos((Math.PI * e) / this.epochs)) * 0.9 + 0.1);
      let loss = 0, wsum = 0;
      for (let bi = 0; bi < n; bi += batch) {
        const m = Math.min(batch, n - bi);
        gW.fill(0);
        gb.fill(0);
        loss = 0;
        wsum = 0;
        for (let r = 0; r < m; r++) {
          const i = order[bi + r];
          const off = i * d;
          for (let c = 0; c < k; c++) {
            let z = b[c];
            const wo = c * d;
            for (let j = 0; j < d; j++) z += W[wo + j] * ((X[off + j] - mu[j]) / sd[j]);
            Z[r * k + c] = z;
          }
          let mxs = -Infinity;
          for (let c = 0; c < k; c++) {
            const z = Z[r * k + c];
            ps[c] = z;
            if (z > mxs) mxs = z;
          }
          let zs = 0;
          for (let c = 0; c < k; c++) {
            ps[c] = Math.exp(ps[c] - mxs);
            zs += ps[c];
          }
          const t = y[i];
          const w = this.sampleW[i];
          loss -= w * Math.log(Math.max(1e-12, ps[t] / zs));
          wsum += w;
          for (let c = 0; c < k; c++) {
            const g = ps[c] / zs - (c === t ? 1 : 0);
            gb[c] += g * w;
            const wo = c * d;
            for (let j = 0; j < d; j++) gW[wo + j] += g * w * ((X[off + j] - mu[j]) / sd[j]);
          }
        }
        const inv = 1 / Math.max(1e-6, wsum);
        for (let c = 0; c < k; c++) {
          b[c] -= lrT * (gb[c] * inv + l2 * b[c]);
          const wo = c * d;
          for (let j = 0; j < d; j++) W[wo + j] -= lrT * (gW[wo + j] * inv + l2 * W[wo + j]);
        }
      }
      this.history.push({ epoch: e, loss: loss / Math.max(1e-6, wsum), lr: lrT });
    }

    fit(X, y, n, opts = {}) {
      this.prepare(X, y, n, opts);
      const batch = opts.batch || 64;
      for (let e = 0; e < this.epochs; e++) this.epochStep(X, y, n, e, batch);
      return this;
    }

    async fitAsync(X, y, n, opts = {}, onEpoch) {
      this.prepare(X, y, n, opts);
      const batch = opts.batch || 64;
      for (let e = 0; e < this.epochs; e++) {
        this.epochStep(X, y, n, e, batch);
        if (onEpoch) onEpoch(e + 1, this.epochs, this.history[this.history.length - 1].loss);
        await new Promise((r) => setTimeout(r, 0));
      }
      return this;
    }

    logits(x) {
      const d = this.d, W = this.W, b = this.b;
      const out = new Float64Array(this.k);
      for (let c = 0; c < this.k; c++) {
        let z = b[c];
        const wo = c * d;
        for (let j = 0; j < d; j++) z += W[wo + j] * ((x[j] - this.mu[j]) / this.sd[j]);
        out[c] = z;
      }
      return out;
    }

    predict(x) {
      const lg = this.logits(x);
      let mx = -Infinity;
      for (let i = 0; i < lg.length; i++) if (lg[i] > mx) mx = lg[i];
      let s = 0;
      for (let i = 0; i < lg.length; i++) s += Math.exp(lg[i] - mx);
      const p = new Float64Array(this.k);
      for (let i = 0; i < lg.length; i++) p[i] = Math.exp(lg[i] - mx) / s;
      return p;
    }

    topWeights(classId, limit = 12) {
      const d = this.d, W = this.W;
      const arr = [];
      for (let j = 0; j < d; j++) arr.push({ name: FEAT.NAMES[j], w: W[classId * d + j], std: W[classId * d + j] / this.sd[j] });
      arr.sort((a, b) => Math.abs(b.w) - Math.abs(a.w));
      return arr.slice(0, limit);
    }

    toJSON() {
      return {
        type: "softmax-multinomial-logistic-regression",
        features: FEAT.NAMES,
        classes: CLASSES.map((c) => c.id),
        mu: Array.from(this.mu),
        sd: Array.from(this.sd),
        W: Array.from(this.W),
        b: Array.from(this.b),
        meta: this.meta,
      };
    }
  }

  class PipelineTrainer {
    constructor() {
      this.sim = null;
      this.ex = null;
      this.samples = [];
      this.onProgress = null;
      this.history = [];
    }

    async run(cfg = {}) {
      const warmup = cfg.warmup || 420;
      const collect = cfg.collect || 300;
      const stepMs = 25;
      this.sim = new SIM.TrafficSim(cfg.seed || 424242);
      this.sim.schedule(1, { ddos: 1, benign: 1 });
      this.ex = new FEAT.Extractor();
      const X = [];
      const Y = [];
      const keys = {};
      for (const c of CLASSES) keys[c.id] = CLASSES.indexOf(c);
      let t = 0;
      const totalSteps = Math.ceil((warmup + collect) * 1000 / stepMs);
      let step = 0;
      let lastFlush = 0;
      while (t < warmup + collect) {
        const flows = this.sim.step(stepMs);
        for (let i = 0; i < flows.length; i++) this.ex.ingest(flows[i], t);
        t += stepMs;
        if (t - lastFlush >= 250) {
          lastFlush = t;
          const obs = this.ex.flush(t);
          if (t > warmup) this.collect(obs, X, Y, keys);
        }
        step++;
        if (step % 900 === 0) {
          if (this.onProgress) this.onProgress(t / (warmup + collect), X.length);
          await new Promise((r) => setTimeout(r, 0));
        }
      }
      const nRaw = Y.length;
      const maxPer = cfg.maxPer || 2000;
      const byClass = new Map();
      for (let c = 0; c < K; c++) byClass.set(c, []);
      for (let i = 0; i < nRaw; i++) byClass.get(Y[i]).push(i);
      const rnd = new U.Rng((cfg.seed || 1) ^ 0x5bf03635);
      const keep = [];
      const rawBalance = {};
      for (const [c, list] of byClass) {
        rawBalance[CLASSES[c].short] = list.length;
        rnd.shuffle(list);
        for (let i = 0; i < Math.min(maxPer, list.length); i++) keep.push(list[i]);
      }
      rnd.shuffle(keep);
      const n = keep.length;
      const Xf = new Float64Array(n * FEAT.D);
      const Yf = new Int32Array(n);
      for (let i = 0; i < n; i++) {
        const src = keep[i];
        Yf[i] = Y[src];
        for (let j = 0; j < FEAT.D; j++) Xf[i * FEAT.D + j] = X[src][j];
      }
      this.n = n;
      this.nRaw = nRaw;
      this.rawBalance = rawBalance;
      return { X: Xf, Y: Yf, n, rawBalance, nRaw, totalSteps };
    }

    collect(obs, X, Y, keys) {
      for (const o of obs) {
        const k = keys[o.truth];
        if (k === undefined) continue;
        X.push(o.x);
        Y.push(k);
      }
    }
  }

  function split(X, Y, n, frac, seed) {
    const rnd = new U.Rng(seed);
    const idx = [];
    for (let i = 0; i < n; i++) idx.push(i);
    rnd.shuffle(idx);
    const cut = Math.floor(n * frac);
    const tr = idx.slice(0, cut);
    const te = idx.slice(cut);
    return { tr, te };
  }

  function evaluate(model, X, Y, idx) {
    const conf = [];
    for (let c = 0; c < model.k; c++) conf.push(new Int32Array(model.k));
    const per = CLASSES.map(() => ({ tp: 0, fp: 0, fn: 0, n: 0 }));
    let correct = 0;
    const d = model.d;
    const x = new Float32Array(d);
    for (let q = 0; q < idx.length; q++) {
      const i = idx[q];
      for (let j = 0; j < d; j++) x[j] = X[i * d + j];
      const p = model.predict(x);
      let pred = 0;
      for (let c = 1; c < model.k; c++) if (p[c] > p[pred]) pred = c;
      const t = Y[i];
      conf[t][pred]++;
      per[t].n++;
      if (pred === t) { correct++; per[t].tp++; } else { per[t].fn++; per[pred].fp++; }
    }
    const rows = per.map((r, i) => {
      const prec = r.tp + r.fp ? r.tp / (r.tp + r.fp) : 0;
      const rec = r.tp + r.fn ? r.tp / (r.tp + r.fn) : 0;
      const f1 = prec + rec ? (2 * prec * rec) / (prec + rec) : 0;
      return { cls: CLASSES[i], support: r.n, precision: prec, recall: rec, f1 };
    });
    let macro = 0;
    for (const r of rows) macro += r.f1;
    return { accuracy: correct / idx.length, rows, conf, macroF1: macro / rows.length, n: idx.length };
  }

  return { SoftmaxLR, PipelineTrainer, evaluate, split, K };
})();
