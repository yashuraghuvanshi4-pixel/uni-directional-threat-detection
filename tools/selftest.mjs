import fs from "node:fs";
import vm from "node:vm";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const files = ["util.js", "lex.js", "traffic-sim.js", "features.js", "model.js", "detectors.js", "alerts.js"];

const ctx = vm.createContext({
  console,
  TextEncoder,
  TextDecoder,
  performance,
  setTimeout,
  clearTimeout,
  Promise,
  Date,
  Math,
  JSON,
  Float32Array,
  Float64Array,
  Int32Array,
  Uint32Array,
  Map,
  Set,
  Array,
  Number,
  String,
  Object,
  Error,
  Blob: class {},
  URL: { createObjectURL: () => "", revokeObjectURL: () => {} },
});

for (const f of files) {
  const src = fs.readFileSync(path.join(root, "js", f), "utf8");
  vm.runInContext(src, ctx, { filename: f });
}

const ns = vm.runInContext("({ U, LEX, SIM, FEAT, MODEL, DET, ALERTS, CLASSES })", ctx);
const { U, LEX, SIM, FEAT, MODEL, DET, ALERTS, CLASSES } = ns;

const args = process.argv.slice(2);
const opt = Object.fromEntries(args.map((a) => a.split("=").map((s) => s.replace(/^--/, ""))));

async function pipeline(warmupMs, collectMs, seed, model) {
  const sim = new SIM.TrafficSim(seed);
  sim.schedule(1, { ddos: +(opt.ddos || 1), benign: 1 });
  const ex = new FEAT.Extractor();
  const X = [];
  const Y = [];
  const keys = {};
  SIM.CLASSES.forEach((c, i) => (keys[c.id] = i));
  let t = 0, lastFlush = 0, bytes = 0, threatFlows = 0;
  const t0 = performance.now();
  while (t < warmupMs + collectMs) {
    const flows = sim.step(25);
    for (let i = 0; i < flows.length; i++) {
      ex.ingest(flows[i], t);
      bytes += flows[i].bytes;
      if (flows[i].truth !== "benign") threatFlows++;
    }
    t += 25;
    if (t - lastFlush >= 250) {
      lastFlush = t;
      const obs = ex.flush(t);
      if (t > warmupMs) {
        for (const o of obs) {
          X.push(o.x);
          Y.push(keys[o.truth]);
        }
      }
    }
  }
  const dur = (performance.now() - t0) / 1000;
  return { X, Y, n: Y.length, ex, sim, recs: ex.flowsIngested, bytes, threatFlows, dur, t };
}

function toMatrix(X) {
  const n = X.length, d = FEAT.D;
  const M = new Float64Array(n * d);
  for (let i = 0; i < n; i++) for (let j = 0; j < d; j++) M[i * d + j] = X[i][j];
  return M;
}

const warmup = +(opt.warmup || 420000);
const collect = +(opt.collect || 300000);

console.log("── SENTINEL pipeline self-test ──────────────────────────────");
console.log(`features: ${FEAT.D}   classes: ${SIM.CLASSES.length}   ngram model chars: ${LEX.CHARS.length}`);

const tA = performance.now();
const train = await pipeline(warmup, collect, +(opt.seed || 20260101), null);
console.log(`\ntrain corpus: ${train.n} window observations from ${train.recs.toLocaleString()} flow records (${(train.dur).toFixed(1)}s wall)`);
console.log(`  ${(train.recs / train.dur / 1000).toFixed(1)}k records/s ingest, ${(train.bytes / train.dur / 1e6).toFixed(1)} Mbps, ${train.ex.views.size} entities resident`);

const perClass = {};
for (const y of train.Y) perClass[y] = (perClass[y] || 0) + 1;
console.log("  label balance: " + SIM.CLASSES.map((c, i) => `${c.short}=${perClass[i] || 0}`).join("  "));

const M = toMatrix(train.X);
const maxPer = +(opt.maxper || 2000);
const byClass = new Map();
SIM.CLASSES.forEach((_, i) => byClass.set(i, []));
for (let i = 0; i < train.n; i++) byClass.get(train.Y[i]).push(i);
const brng = new U.Rng(99);
const keep = [];
for (const [, list] of byClass) {
  brng.shuffle(list);
  for (let i = 0; i < Math.min(maxPer, list.length); i++) keep.push(list[i]);
}
brng.shuffle(keep);
const Xb = new Float64Array(keep.length * FEAT.D);
const Yb = new Int32Array(keep.length);
keep.forEach((src, i) => {
  Yb[i] = train.Y[src];
  for (let j = 0; j < FEAT.D; j++) Xb[i * FEAT.D + j] = train.X[src][j];
});
const split = MODEL.split(Xb, Yb, keep.length, 0.75, 777);

const epochs = +(opt.epochs || 60);
const model = new MODEL.SoftmaxLR();
const fitT0 = performance.now();
model.fit(Xb, Yb, keep.length, { epochs, lr: 0.6, l2: 3e-4, batch: 64 });
const fitMs = performance.now() - fitT0;
const tr = MODEL.evaluate(model, Xb, Yb, split.tr);
const te = MODEL.evaluate(model, Xb, Yb, split.te);
console.log(`\nbalanced training set: ${keep.length} windows (cap ${maxPer}/class) of ${train.n.toLocaleString()} raw`);
console.log(`fit: ${epochs} epochs in ${fitMs.toFixed(0)} ms`);
console.log(`train accuracy ${(tr.accuracy * 100).toFixed(2)}%   val accuracy ${(te.accuracy * 100).toFixed(2)}%   val macro-F1 ${(te.macroF1 * 100).toFixed(2)}%`);
console.log("\nper-class (held-out):");
console.log("  class      support   prec    rec     f1");
for (const r of te.rows) {
  console.log(
    `  ${r.cls.label.padEnd(24)} ${String(r.support).padStart(6)}  ${(r.precision * 100).toFixed(1).padStart(5)}%  ${(r.recall * 100).toFixed(1).padStart(5)}%  ${(r.f1 * 100).toFixed(1).padStart(5)}%`
  );
}
console.log("\nconfusion (rows = truth, cols = predicted):");
console.log("           " + SIM.CLASSES.map((c) => c.short.padStart(6)).join(""));
for (let i = 0; i < te.conf.length; i++) {
  console.log("  " + SIM.CLASSES[i].short.padEnd(9) + te.conf[i].map((v) => String(v).padStart(6)).join(""));
}

const heldout = process.argv.includes("--holdout");
if (heldout) {
  console.log("\n── unseen-seed generalisation test ─────────────────────────");
  const fresh = await pipeline(120000, 180000, 987654321, model);
  const FM = toMatrix(fresh.X);
  const ev = MODEL.evaluate(model, FM, fresh.Y, fresh.Y.map((_, i) => i));
  console.log(`fresh stream (seed 987654321, 120s warm): ${fresh.n} observations, ${(fresh.recs / fresh.dur / 1000).toFixed(1)}k records/s`);
  console.log(`accuracy ${(ev.accuracy * 100).toFixed(2)}%   macro-F1 ${(ev.macroF1 * 100).toFixed(2)}%`);
  for (const r of ev.rows) {
    console.log(`  ${r.cls.label.padEnd(24)} n=${String(r.support).padStart(5)}  f1=${(r.f1 * 100).toFixed(1)}%`);
  }
}

console.log(`\ntotal ${((performance.now() - tA) / 1000).toFixed(1)}s`);
console.log("── end ──────────────────────────────────────────────────────");
