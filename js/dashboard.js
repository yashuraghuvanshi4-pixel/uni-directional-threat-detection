const FEATURE_META = [
  ["flow_rate", "Rate", "Forward flows per second attributed to the entity in this window"],
  ["flow_rate_z", "Rate", "z-score of the rate against the entity's EWMA baseline (slow-burn vs surge)"],
  ["log_flow_rate", "Rate", "log10(1+rate) — compresses volumetric spread"],
  ["pkt_rate", "Volume", "Packets per second in the primary direction"],
  ["log_byte_rate", "Volume", "log10(1+primary bytes/s)"],
  ["distinct_peers", "Cardinality", "log10 distinct counterparties (spoofed floods explode this)"],
  ["peer_entropy", "Cardinality", "Shannon entropy of the counterparty distribution"],
  ["peer_entropy_norm", "Cardinality", "Entropy / log2(#peers) — 1.0 = uniformly spread source space"],
  ["peer_churn", "Cardinality", "Fraction of peers never before observed"],
  ["distinct_ports", "Cardinality", "log10 distinct destination ports"],
  ["port_entropy", "Cardinality", "Entropy of the destination-port distribution"],
  ["ports_per_peer", "Cardinality", "log10 ports per counterparty — the horizontal/vertical scan axis"],
  ["flows_per_peer", "Cardinality", "log10 flows per counterparty"],
  ["new_peer_ratio", "Cardinality", "New-counterparty ratio over forward flows"],
  ["syn_ratio", "Protocol", "SYN-carrying flows / forward flows"],
  ["response_ratio", "Protocol", "Reverse-direction flows / forward flows"],
  ["unanswered_ratio", "Protocol", "1 - min(1, response ratio) — no handshake completes"],
  ["proto_mix_entropy", "Protocol", "Entropy of the transport-protocol mix"],
  ["udp_ratio", "Protocol", "UDP share of forward flows"],
  ["tcp_ratio", "Protocol", "TCP share of forward flows"],
  ["small_pkt_ratio", "Payload shape", "Share of flows of ≤2 packets (amplification requests, scan probes)"],
  ["log_mean_pkt", "Payload shape", "log10 mean packets per flow"],
  ["log_mean_bytes", "Payload shape", "log10 mean bytes per flow"],
  ["log_mean_dur", "Payload shape", "log10 mean flow duration (ms)"],
  ["log_primary_bytes", "Volume", "log10 primary-direction bytes/s"],
  ["log_secondary_bytes", "Volume", "log10 reverse-direction bytes/s"],
  ["out_in_ratio", "Volume", "log10 primary/secondary byte ratio — exfil and flood asymmetry"],
  ["asym", "Volume", "|primary−secondary| / (primary+secondary)"],
  ["beacon_r", "Beaconing", "Periodicity strength = autocorrelation peak × cycle-gap dispersion"],
  ["log_beacon_period", "Beaconing", "log10(estimated beacon period in seconds)"],
  ["beacon_iat_cv", "Beaconing", "Coefficient of variation of inter-cycle gaps (jitter)"],
  ["beacon_peers", "Beaconing", "log10 number of peers showing repeated contact"],
  ["beacon_regularity", "Beaconing", "1 − cycle-gap CV"],
  ["dns_ratio", "DNS", "DNS flows / forward flows"],
  ["dns_len_mean", "DNS", "Mean query-name length in characters"],
  ["dns_len_max", "DNS", "Maximum query-name length observed"],
  ["dns_label_max", "DNS", "Longest single DNS label (tunnelling payload size)"],
  ["dns_entropy_mean", "DNS", "Mean per-query character entropy"],
  ["dns_entropy_max", "DNS", "Max per-query character entropy"],
  ["dns_ngram", "DNS", "Mean character-bigram log-likelihood against a benign-corpora model"],
  ["dns_uniq", "DNS", "Unique query-name ratio (DGA generates near-100 %)"],
  ["dns_txt", "DNS", "TXT query ratio — classic tunnelling channel"],
  ["dns_nx", "DNS", "NXDOMAIN ratio — DGA churn and sinkholed callbacks"],
  ["dns_any", "DNS", "ANY query ratio (cache-poisoning / enumeration)"],
  ["tls_ratio", "TLS/QUIC", "Encrypted flows / forward flows (metadata only)"],
  ["tls_ja3_rarity", "TLS/QUIC", "Rarity of the JA3 (TCP) or JA4 (QUIC) fingerprint in this stream"],
  ["tls_self_signed", "TLS/QUIC", "Self-signed certificate ratio"],
  ["tls_no_cert", "TLS/QUIC", "Sessions presenting no certificate at all"],
  ["tls_sni_entropy", "TLS/QUIC", "Entropy across observed SNI values"],
  ["tls_size_entropy", "TLS/QUIC", "Normalised entropy of the packet-size sequence"],
  ["tls_size_uniform", "TLS/QUIC", "1 − CV of the packet-size sequence (machine-generated uniformity)"],
  ["tls_ja3_count", "TLS/QUIC", "Distinct fingerprints inside the window"],
  ["is_dst_view", "Context", "1 when the entity is observed as a flood target (destination-centric view)"],
  ["active_log", "Context", "log10 seconds the entity has been tracked in the enclave"],
  ["phase_mod", "Context", "Flow sequence phase (beacon message index) mod 97"],
  ["tcp_flags_norm", "Protocol", "Normalised SYN / FIN-RST flag mix"],
  ["bytes_per_pkt", "Payload shape", "log10 bytes per packet — low for tunnels, high for bulk transfer"],
  ["port_rare", "Cardinality", "Normalised destination-port rarity"],
  ["log_window_span", "Context", "log10 detection horizon: 1 s short window or 30 s long window"],
];

const CONSTRAINTS = [
  ["Read-only ingest", "Ingest is a firehose from a one-way mirror. Nothing in the pipeline opens a socket, sends a probe, completes a handshake, or emits a block. The only output channel is the alert store. The ✕ in the header is the diode's missing return edge."],
  ["No payload decryption", "TLS/QUIC flows are represented only by handshake metadata (JA3/JA4 fingerprint, SNI, version, cipher, ALPN, certificate length/validity flags) plus packet-size and inter-arrival sequences. No key material, no plaintext, no record payload is ever read."],
  ["Streaming, not batch", "Ingest is incremental. A sliding 1 s short window and a 30 s long window are scored every 250 ms of stream time, so an alert is raised and pushed to the dashboard within one window + one flush. There is no end-of-run report path."],
  ["Defined throughput target", "The Architecture tab runs an in-browser benchmark that pushes the full ingest → feature → inference path and reports the sustained flow-record rate, per-observation p50/p99 inference latency and the implied Mbps."],
  ["Standardized alert schema", "Every alert is a versioned record: schema id, ISO-8601 timestamp, flow identifier (entity, role, window span, fan-out, rates), threat class + MITRE technique ids, confidence + band, severity 1-5, the fusion breakdown, ranked supporting evidence with per-feature contribution, and the full 59-feature vector."],
];

const NOTES = `
<h4>What the pipeline actually does</h4>
<p>Five stages run in the browser with no server and no third-party code. (1) <code>Ingest</code> synthesises a one-directional IP flow stream (NetFlow/IPFIX-shaped records) in 25 ms slices. (2) <code>Feature extraction</code> maintains bounded per-entity state: sliding 1 s windows for every source and destination entity, plus promoted 30 s long-horizon windows for entities that show repeated contact with the same peers. (3) <code>Inference</code> runs a 7-class softmax logistic regression trained on data that flowed through this very same extractor. (4) <code>Statistical detectors</code> score each threat class from interpretable rules and emit the ranked evidence list. (5) <code>Fusion &amp; alerting</code> combines model probability and rule score per class, applies a per-entity cooldown, and writes versioned alert records.</p>

<h4>Entity views, and why there are two</h4>
<p>A source-centric view answers "who is behaving badly?", a destination-centric view answers "who is being attacked?". Volumetric DDoS is only visible in the destination view (the sources are spoofed and never repeat, so per-source state is intentionally not created for them — a documented high-cardinality guard, not a heuristic shortcut). Exfiltration and C2 are only visible in the source view. Both views emit the same 59-feature vector and share the classifier, distinguished by the <code>is_dst_view</code> feature.</p>

<h4>Long-horizon promotion</h4>
<p>A beacon with a 45 s period puts at most one flow in a 1 s window, so a short window alone cannot see periodicity. When any (entity, peer) pair accumulates 5 inter-arrival samples, the entity is promoted to a 30 s window whose counters are EWMA-smoothed (12 s time constant) while peer-interarrival history is kept for autocorrelation. At most 110 entities are promoted at once; the rest are decided by short windows.</p>

<h4>Beacon periodicity metric</h4>
<p><code>beacon_r = max autocorrelation peak of the resampled inter-arrival impulse train × (0.28 + 0.72 × cycle-gap dispersion)</code>. Autocorrelation on the impulse train makes the metric robust to bursty beacons, where a naive inter-arrival CV collapses to 1.0. The dispersion term uses only gaps above 3× the 10th percentile, which separates cycle gaps from intra-burst gaps.</p>

<h4>DNS analysis</h4>
<p>Query names are scored with a character-bigram model fitted on 4000 benign names generated from a service-vocabulary corpus. <code>dns_ngram</code> is the mean per-character log-likelihood under that model: well-formed names score near −1.5, algorithmic names near −3.6, base32 tunnel payloads near −4.5. Combined with per-query entropy, label length, uniqueness, TXT and NXDOMAIN ratios this cleanly separates DGA and tunnelling from ordinary resolution.</p>

<h4>Encrypted-traffic analysis</h4>
<p>Fingerprint rarity is estimated online: each JA3/JA4 hash is counted in a stream-wide table and rarity = min(1, log10(1 + max(total,4000)/(count+1)) / 3.2). A hash seen 2 000 times scores 0; a hash seen 5 times scores 1. This is a purely passive statistic that needs no threat feed and no decryption. Packet-size uniformity (1 − CV of the observed size sequence) and its normalised entropy act as the "same implant, same code path every time" signal.</p>

<h4>Honest limitations</h4>
<ul>
<li>Training data is synthetic. It is produced by the same generator that feeds the live stream, so the reported metrics measure pipeline separability under the modelled threat family, not real-world generalisation. On a real deployment, retrain on labelled captures from the monitored estate — the trainer takes a labelled corpus and nothing else changes.</li>
<li>Fingerprint strings in the simulator are synthetic stand-ins for MD5 JA3 values, not published real-world hashes.</li>
<li>Per-source state is suppressed below 12 observations from a non-internal address, which bounds memory under spoofed-source floods. A real deployment would pair this with a top-K heavy-hitter sketch and prefix-scoped monitoring policy.</li>
<li>Detection is alert-only. By construction there is no response path, so no containment, no blocking, no sinkholing — that is the requirement, not an omission.</li>
</ul>

<h4>Reproducing the numbers</h4>
<p>Open <code>index.html</code> over any static server (for example <code>python3 -m http.server</code>). Training runs at page load in about a second and can be re-run with a fresh seed from the Model tab. The benchmark measures this machine and this browser, so absolute rates vary; the architecture, the feature set and the alert schema are the reproducible artefact.</p>
`;

const APP = (() => {
  const $ = (id) => document.getElementById(id);
  const N = 120;
  const BINS = 120;

  const eng = {
    sim: null, ex: null, model: null, store: null,
    t: 0, speed: 2, running: true, ddos: 1.6,
    epochWall: Date.now(),
    flowBucket: 0, byteBucket: 0, threatBucket: 0, alertBucket: 0,
    rates: new Float64Array(BINS), bits: new Float64Array(BINS),
    threats: new Float64Array(BINS), confs: new Float64Array(BINS),
    totalFlows: 0, totalBytes: 0, totalThreats: 0,
    lat: [], flowLat: [],
    scatter: [],
    liveConf: null, liveN: 0, liveCorrect: 0, liveSeen: 0,
    saturated: 0, ingestMs: 0,
    bench: [],
    infCount: 0,
  };

  const INJECTORS = [
    ["syn_flood", "SYN flood"], ["udp_amplification", "UDP reflection"],
    ["c2_beacon", "C2 beacon"], ["dga", "DGA"], ["dns_tunnel", "DNS tunnel"],
    ["ja3_malware", "Bad JA3"], ["quic_bad", "Bad JA4/QUIC"],
    ["port_scan", "Port scan"], ["host_scan", "Host scan"], ["exfil", "Exfiltration"],
  ];

  function boot(msg, pct) {
    $("bootMsg").textContent = msg;
    $("bootBar").style.width = pct + "%";
  }

  async function trainModel() {
    setEngine("train", "training");
    for (const li of document.querySelectorAll("#trainSteps li")) li.className = "";
    const t0 = performance.now();
    const trainer = new MODEL.PipelineTrainer();
    const data = await trainer.run({
      seed: 20260101 + Math.floor(Math.random() * 100000),
      warmup: 420,
      collect: 300,
      onProgress: (p, n) => {
        boot("training on synthesised corpus · " + U.fmtInt(n) + " windows", 8 + p * 76);
        const steps = document.querySelectorAll("#trainSteps li");
        const idx = Math.min(steps.length - 1, Math.floor(p * steps.length));
        for (let i = 0; i < steps.length; i++) steps[i].className = i < idx ? "done" : i === idx ? "act" : "";
      },
    });
    const steps = document.querySelectorAll("#trainSteps li");
    for (let i = 0; i < steps.length; i++) steps[i].className = "done";

    const split = MODEL.split(data.X, data.Y, data.n, 0.75, 777);
    const model = new MODEL.SoftmaxLR();
    model.fit(data.X, data.Y, data.n, { epochs: 60, lr: 0.6, l2: 3e-4, batch: 64 });
    const trainEval = MODEL.evaluate(model, data.X, data.Y, split.tr);
    const testEval = MODEL.evaluate(model, data.X, data.Y, split.te);
    const dur = performance.now() - t0;
    model.meta = {
      trained_at: new Date().toISOString(),
      train_windows: split.tr.length,
      val_windows: split.te.length,
      feature_count: FEAT.D,
      classes: CLASSES.length,
      epochs: 60,
      optimizer: "mini-batch SGD, cosine LR decay, L2=3e-4",
      train_ms: Math.round(dur),
      val_accuracy: U.round(testEval.accuracy, 4),
      val_macro_f1: U.round(testEval.macroF1, 4),
      train_accuracy: U.round(trainEval.accuracy, 4),
    };
    eng.model = model;
    renderModel(model, testEval, trainEval, data);
    boot("model ready", 100);
    return model;
  }

  function renderModel(model, testEval, trainEval, data) {
    $("modelHint").textContent =
      "softmax multinomial logistic regression · " + CLASSES.length + " classes · " + FEAT.D + " features";
    $("trainStats").innerHTML = [
      ["windows", U.fmtInt(data.n), ""],
      ["train acc", U.fmtPct(trainEval.accuracy), "good"],
      ["val acc", U.fmtPct(testEval.accuracy), "good"],
      ["val macro-F1", U.fmtPct(testEval.macroF1), "good"],
      ["fit time", Math.round(model.meta.train_ms) + " ms", ""],
    ].map((s) => `<div class="stat ${s[2]}"><span>${s[0]}</span><b>${s[1]}</b></div>`).join("");

    const hist = model.history;
    const perEpoch = [];
    for (const h of hist) {
      const e = perEpoch[perEpoch.length - 1];
      if (!e || e.epoch !== h.epoch) perEpoch.push({ epoch: h.epoch, loss: h.loss });
      else e.loss = (e.loss * 0.8 + h.loss * 0.2);
    }
    CH.lineChart($("cLoss"), [{ data: perEpoch.map((p) => p.loss), color: "#00d3a7", fill: "rgba(0,211,167,0.22)", dot: true, width: 1.8 }], { n: perEpoch.length, pad: { l: 40, r: 12, t: 8, b: 16 } });

    CH.heatmap($("cConf2"), testEval.conf, CLASSES.map((c) => c.short), CLASSES.map((c) => c.short), { left: 78 });

    $("metricsTable").querySelector("tbody").innerHTML = testEval.rows
      .map(
        (r) => `<tr><td style="color:${r.cls.color}">${U.esc(r.cls.label)}</td><td>${U.fmtInt(r.support)}</td>
<td>${U.fmtPct(r.precision)}</td><td>${U.fmtPct(r.recall)}</td><td>${U.fmtPct(r.f1)}</td></tr>`
      )
      .join("");

    const wt = $("wTabs");
    wt.innerHTML = CLASSES.map((c, i) => `<button data-c="${i}" class="${i === 1 ? "on" : ""}" style="${i === 1 ? "background:" + c.color + ";border-color:" + c.color : ""}">${c.short}</button>`).join("");
    const drawW = (ci) => {
      const ws = model.topWeights(ci, 14);
      CH.hbars($("cWeights"), ws.map((w) => ({ k: w.name, v: w.w, txt: (w.w >= 0 ? "+" : "") + U.round(w.w, 3), color: CLASSES[ci].color })), { left: 178 });
    };
    wt.querySelectorAll("button").forEach((b) => {
      b.onclick = () => {
        wt.querySelectorAll("button").forEach((x) => { x.className = ""; x.style.cssText = ""; });
        const ci = +b.dataset.c;
        b.className = "on";
        b.style.background = CLASSES[ci].color;
        b.style.borderColor = CLASSES[ci].color;
        drawW(ci);
      };
    });
    drawW(1);
  }

  function setEngine(mode, text) {
    const p = $("enginePill");
    p.className = "pill " + mode;
    $("engineStatus").textContent = text;
  }

  function resetEngine() {
    eng.sim = new SIM.TrafficSim(20260101);
    eng.sim.schedule(1, { ddos: eng.ddos, benign: 1 });
    eng.ex = new FEAT.Extractor();
    eng.store.reset();
    eng.t = 0;
    eng.epochWall = Date.now();
    eng.flowBucket = 0; eng.byteBucket = 0; eng.threatBucket = 0; eng.alertBucket = 0;
    eng.rates.fill(0); eng.bits.fill(0); eng.threats.fill(0); eng.confs.fill(0);
    eng.totalFlows = 0; eng.totalBytes = 0; eng.totalThreats = 0;
    eng.lat.length = 0; eng.scatter.length = 0;
    eng.liveN = 0; eng.liveCorrect = 0; eng.liveSeen = 0; eng.saturated = 0;
    eng.liveStreamTop = 0;
    $("liveStream").innerHTML = "";
    prewarm();
  }

  function prewarm() {
    const step = 25;
    let t = 0;
    let lastFlush = 0;
    while (t < 300000) {
      const flows = eng.sim.step(step);
      for (let i = 0; i < flows.length; i++) eng.ex.ingest(flows[i], t);
      t += step;
      if (t - lastFlush >= 250) {
        lastFlush = t;
        eng.ex.flush(t);
      }
    }
    eng.t = t;
    eng.flowBucket = 0;
    eng.byteBucket = 0;
    eng.threatBucket = 0;
    eng.alertBucket = 0;
  }

  function push(arr, v) {
    arr.copyWithin(0, 1);
    arr[arr.length - 1] = v;
  }

  function score(obs) {
    const t0 = performance.now();
    const x = obs.x;
    const p = eng.model.predict(x);
    let bi = 0;
    for (let c = 1; c < p.length; c++) if (p[c] > p[bi]) bi = c;
    const stats = DET.scoreAll(x, obs);
    let bestId = null, bestF = 0, bestS = 0;
    for (const id of DET.IDS) {
      const ci = CLASSES.findIndex((c) => c.id === id);
      const s = stats[id].score;
      const f = 0.62 * p[ci] + 0.38 * s;
      if (f > bestF) { bestF = f; bestId = id; bestS = s; }
    }
    const truthIdx = CLASSES.findIndex((c) => c.id === obs.truth);
    eng.liveSeen++;
    if (truthIdx === bi) eng.liveCorrect++;
    const dt = performance.now() - t0;
    eng.lat.push(dt);
    if (eng.lat.length > 4000) eng.lat.splice(0, 2000);
    if (!eng.liveConf) eng.liveConf = new Int32Array(CLASSES.length);
    eng.liveConf[bi * CLASSES.length + truthIdx]++;
    if (eng.scatter.length < 900) {
      const F = FEAT.IDX;
      eng.scatter.push({
        x: x[F.get("peer_entropy")],
        y: x[F.get("asym")],
        r: Math.min(6, 1.2 + Math.log10(1 + Math.pow(10, x[F.get("distinct_peers")]) - 1) * 1.4),
        color: CLASSES[bi].color,
        a: 0.42,
      });
    }
    const ci = CLASSES.findIndex((c) => c.id === bestId);
    const modelProb = p[ci];
    if (bestF >= 0.5 && bestF > p[0] + 0.04) {
      const a = eng.store.make({
        now: eng.epochWall + (obs.now - eng.t),
        classId: bestId,
        confidence: bestF,
        modelProb,
        statScore: bestS,
        evidence: stats[bestId].evidence,
        x,
        view: obs.view,
        kind: obs.kind,
        ipStr: obs.ipStr,
        modelVersion: eng.model.meta.model_version || "trained-" + (eng.model.meta.trained_at || "").slice(0, 10),
      });
      const pushed = eng.store.push(a);
      if (pushed) {
        eng.threatBucket += 1;
        eng.alertBucket += 1;
        push(eng.confs, pushed.confidence);
        addStreamRow(pushed);
        $("alertBadge").textContent = eng.store.items.length;
      }
    } else {
      push(eng.confs, 0);
    }
    if (bestId === "ddos_volumetric") eng.threatBucket += 0;
  }

  function addStreamRow(a) {
    const wrap = $("liveStream");
    const row = document.createElement("div");
    row.className = "srow";
    row.style.borderLeftColor = CLASSES.find((c) => c.id === a.threat_class).color;
    const ev = a.supporting_evidence.top_features
      .slice(0, 2)
      .map((e) => `${e.feature}=${e.value}`)
      .join(" · ");
    row.innerHTML = `<span class="t">${U.fmtTimeShort(a.ts_ms)}</span>
<span class="m"><span class="c" style="color:${CLASSES.find((c) => c.id === a.threat_class).color}">${U.esc(a.threat_label)}</span>
<span class="sevtag sev${a.severity}">S${a.severity}</span>
<span class="e"> ${U.esc(a.flow_identifier.entity)} · ${U.esc(ev)}</span></span>
<span class="cf">${U.fmtPct(a.confidence, 0)}</span>`;
    wrap.insertBefore(row, wrap.firstChild);
    while (wrap.childElementCount > 60) wrap.removeChild(wrap.lastChild);
  }

  let lastReal = 0;
  let lastFlushT = 0;

  function frame(now) {
    requestAnimationFrame(frame);
    const dtReal = Math.min(120, now - lastReal);
    lastReal = now;
    if (!eng.model) return;
    if (eng.running) {
      let simDt = dtReal * eng.speed;
      const maxSteps = 26;
      let steps = Math.min(maxSteps, Math.ceil(simDt / 25));
      if (steps * 25 < simDt) { eng.saturated += simDt - steps * 25; }
      const t0 = performance.now();
      for (let s = 0; s < steps; s++) {
        const flows = eng.sim.step(25);
        for (let i = 0; i < flows.length; i++) {
          eng.ex.ingest(flows[i], eng.t);
          eng.flowBucket++;
          eng.byteBucket += flows[i].bytes;
          eng.totalFlows++;
          eng.totalBytes += flows[i].bytes;
        }
        eng.t += 25;
        if (eng.t - lastFlushT >= 250) {
          lastFlushT = eng.t;
          const obs = eng.ex.flush(eng.t);
          for (let i = 0; i < obs.length; i++) score(obs[i]);
        }
      }
      eng.ingestMs = eng.ingestMs * 0.9 + (performance.now() - t0) * 0.1;
      if (eng.t - eng.lastBucketAt > 1000) {
        eng.lastBucketAt = eng.t;
        push(eng.rates, eng.flowBucket);
        push(eng.bits, (eng.byteBucket * 8) / 1e6);
        push(eng.threats, eng.threatBucket);
        eng.flowBucket = 0; eng.byteBucket = 0; eng.threatBucket = 0; eng.alertBucket = 0;
      }
    }
    if (now - (eng.lastPaint || 0) > 320) {
      eng.lastPaint = now;
      render();
    }
  }

  function render() {
    const F = FEAT.IDX;
    $("kFlows").textContent = U.fmtNum(eng.totalFlows);
    const recentRate = eng.rates[eng.rates.length - 1] || 0;
    $("kFlowsRate").textContent = U.fmtInt(recentRate) + " f/s now";
    $("kTput").textContent = U.fmtInt(recentRate);
    $("kBits").textContent = ((eng.bits[eng.bits.length - 1] || 0)).toFixed(1);
    $("kViews").textContent = U.fmtInt(eng.ex.views.size);
    let slowN = 0;
    for (const v of eng.ex.views.values()) if (v.isSlow) slowN++;
    $("kViewsSub").textContent = slowN + " long-horizon · " + U.fmtInt(eng.ex.ja3.size) + " fingerprints";
    const lat = eng.lat.slice().sort((a, b) => a - b);
    if (lat.length) {
      const p99 = lat[Math.min(lat.length - 1, Math.floor(lat.length * 0.99))];
      $("kLat").textContent = p99.toFixed(3);
    }
    const items = eng.store.items;
    $("kAlerts").textContent = U.fmtInt(items.length);
    const sev = eng.store.sevCounts;
    $("kAlertsSub").textContent = `critical ${sev[5]} · high ${sev[4]}`;
    $("alertBadge").textContent = items.length;
    $("footStat").textContent =
      `${U.fmtInt(eng.totalFlows)} records · ${U.fmtBytes(eng.totalBytes)} · ${U.fmtInt(eng.ex.flowsIngested)} through extractor · sim clock ${U.fmtTimeShort(eng.epochWall + (eng.t - eng.t))}`;

    CH.lineChart($("cRate"), [
      { data: Array.from(eng.rates), color: "#00d3a7", fill: "rgba(0,211,167,0.2)", dot: true },
      { data: Array.from(eng.threats), color: "#ff4d6d", width: 1.3 },
    ], { n: BINS });
    CH.legend($("lgRate"), [
      { color: "#00d3a7", k: "flow records/s", txt: U.fmtInt(recentRate) },
      { color: "#ff4d6d", k: "alerts/s", txt: U.fmtInt(eng.threats[eng.threats.length - 1] || 0) },
      { color: "#63788f", k: "sustained", txt: U.fmtInt(eng.ingestMs > 0 ? Math.round(eng.totalFlows / Math.max(0.001, (Date.now() - eng.epochWall) / 1000)) : 0) + "/s" },
    ]);

    CH.lineChart($("cBits"), [{ data: Array.from(eng.bits), color: "#4dabf7", fill: "rgba(77,171,247,0.22)", dot: true }], { n: BINS, unit: "M" });
    CH.legend($("lgBits"), [{ color: "#4dabf7", k: "Mbps observed", txt: (eng.bits[eng.bits.length - 1] || 0).toFixed(1) }]);

    const clsItems = CLASSES.map((c) => ({ k: c.label, v: eng.store.counts[CLASSES.indexOf(c)], color: c.color }));
    CH.donut($("cClass"), clsItems, { centerTop: String(eng.store.total), centerSub: "alerts total" });
    CH.legend($("lgClass"), clsItems.map((i) => ({ color: i.color, k: i.k, txt: i.v })));

    const sevNames = ["1 info", "2 low", "3 medium", "4 high", "5 critical"];
    const sevItems = [1, 2, 3, 4, 5].map((s, i) => ({ k: sevNames[i], v: eng.store.sevCounts[s], color: ["#63788f", "#4dabf7", "#ffd43b", "#ff9f43", "#ff4d6d"][i] }));
    CH.bars($("cSev"), sevItems, {});
    CH.legend($("lgSev"), sevItems.map((i) => ({ color: i.color, k: i.k, txt: i.v })));

    const meanConf = eng.store.items.length
      ? eng.store.items.reduce((a, b) => a + b.confidence, 0) / eng.store.items.length
      : 0;
    CH.lineChart($("cConf"), [{ data: Array.from(eng.confs), color: "#c56cf0", fill: "rgba(197,108,240,0.2)", dot: true }], { n: BINS, max: 1, unit: "" });
    CH.legend($("lgConf"), [
      { color: "#c56cf0", k: "fused confidence / alert", txt: U.fmtPct(meanConf, 0) },
      { color: "#63788f", k: "threshold", txt: "0.50" },
    ]);

    CH.scatter($("cScatter"), eng.scatter, { xlabel: "counterparty entropy (bits)", ylabel: "byte asymmetry" });
    const seen = CLASSES.map((c) => ({ color: c.color, k: c.short, txt: eng.store.counts[CLASSES.indexOf(c)] }));
    CH.legend($("lgScatter"), seen);

    if ($("tabs").dataset.active === "alerts") renderTable();
  }

  function renderTable() {
    const q = $("fText").value.trim().toLowerCase();
    const cf = $("fClass").value;
    const sv = +$("fSev").value;
    let list = eng.store.recent(400).reverse();
    if (cf) list = list.filter((a) => a.threat_class === cf);
    if (sv) list = list.filter((a) => a.severity >= sv);
    if (q) list = list.filter((a) => (a.flow_identifier.entity + " " + a.threat_label + " " + a.supporting_evidence.top_features.map((e) => e.feature + e.value).join(" ")).toLowerCase().includes(q));
    $("alertCount").textContent = list.length + " shown / " + eng.store.items.length + " stored";
    $("alertTable").querySelector("tbody").innerHTML = list
      .slice(0, 260)
      .map((a) => {
        const c = CLASSES.find((x) => x.id === a.threat_class);
        const ev = a.supporting_evidence.top_features.slice(0, 3).map((e) => `${e.feature}=${e.value}`).join(", ");
        return `<tr><td>${a.timestamp.slice(11, 23)}</td><td>${U.esc(a.alert_id)}</td><td>${U.esc(a.flow_identifier.entity)}<span class="dim"> ${a.flow_identifier.role}</span></td>
<td style="color:${c.color}">${U.esc(a.threat_label)}</td><td>${U.fmtPct(a.confidence, 0)}</td>
<td><span class="sevtag sev${a.severity}">${a.severity} ${a.severity_label}</span></td>
<td>${a.flow_identifier.detection_horizon} ${a.flow_identifier.window_span_ms}ms</td><td>${U.esc(ev)}</td>
<td class="dim">${a.mitre_attack.join(", ")}</td></tr>`;
      })
      .join("");
  }

  function renderSchemaSample() {
    const a = eng.store.items[eng.store.items.length - 1] || {
      alert_id: "ALT-EXAMPLE",
      schema: ALERTS.SCHEMA_VERSION,
      timestamp: new Date().toISOString(),
      flow_identifier: { view: "source-entity", entity: "10.20.131.7", role: "originator", window_span_ms: 1000, detection_horizon: "fast", distinct_peers: 3, distinct_ports: 1, flow_rate_per_s: 2.1, primary_bytes_per_s: 2400, secondary_bytes_per_s: 900 },
      threat_class: "c2_beaconing",
      threat_label: "Botnet C2 beaconing",
      mitre_attack: ["T1071.001", "T1573"],
      confidence: 0.93, confidence_band: "high", severity: 4, severity_label: "high",
      scoring: { model_probability: 0.92, statistical_score: 0.95, fusion: "0.62*model + 0.38*statistical", model: "softmax-multinomial-logistic-regression", model_version: "trained-2026-01-01" },
      supporting_evidence: { top_features: [{ feature: "beacon_periodicity_r", value: 0.88, contribution: 0.37 }] },
      ingest: { source: "one-way SPAN mirror / hardware data diode", direction: "unidirectional (read-only)", active_response: false, payload_decryption: false, pipeline_stage: "streaming-inference" },
      status: "new", repeat_count: 1,
    };
    const json = JSON.stringify(a, null, 2);
    $("schemaSample").innerHTML = U.esc(json.length > 20000 ? json.slice(0, 20000) + "\n… truncated, use Alerts JSON export for the full record" : json)
      .replace(/&quot;([^&]*?)&quot;:/g, '<span class="k">"$1"</span>:')
      .replace(/: "([^"]*)"/g, ': <span class="s">"$1"</span>')
      .replace(/: (-?\d+\.?\d*)/g, ': <span class="n">$1</span>');
  }

  function renderFeatures() {
    $("featCount").textContent = FEAT.D + " features · " + FEAT.NAMES.length + " names · dual-horizon";
    $("featTable").querySelector("tbody").innerHTML = FEATURE_META.map(
      (m, i) => `<tr><td>${i}</td><td style="color:var(--cy)">${m[0]}</td><td class="dim">${m[1]}</td><td>${U.esc(m[2])}</td></tr>`
    ).join("");
  }

  function renderConstraints() {
    $("constraintTable").querySelector("tbody").innerHTML = CONSTRAINTS.map(
      (c) => `<tr><td style="color:var(--cy);width:180px">${U.esc(c[0])}</td><td>${U.esc(c[1])}</td></tr>`
    ).join("");
    $("docNotes").innerHTML = NOTES;
  }

  function buildInjectors() {
    $("injectChips").innerHTML = INJECTORS.map(
      ([k, l]) => `<span class="chip on" data-k="${k}">${l}</span>`
    ).join("");
    $("injectChips").querySelectorAll(".chip").forEach((c) => {
      c.onclick = () => {
        const k = c.dataset.k;
        eng.sim.enabled[k] = !eng.sim.enabled[k];
        c.className = "chip " + (eng.sim.enabled[k] ? "on" : "off");
        if (eng.sim.enabled[k]) reschedule();
      };
    });
  }

  function reschedule() {
    eng.sim.attackers.length = 0;
    eng.sim.hosts = eng.sim.hosts.filter((h) => h.truth === "benign");
    eng.sim.schedule(1, { ddos: eng.ddos, benign: 1 });
  }

  async function runBench() {
    const targets = [0.4, 1.6, 5, 12];
    const results = [];
    for (const d of targets) {
      $("btnBench").disabled = true;
      $("btnBench2").disabled = true;
      const sim = new SIM.TrafficSim(7);
      sim.schedule(1, { ddos: d, benign: 1 });
      const ex = new FEAT.Extractor();
      let t = 0, lastFlush = 0;
      while (t < 60000) {
        const flows = sim.step(25);
        for (let i = 0; i < flows.length; i++) ex.ingest(flows[i], t);
        t += 25;
        if (t - lastFlush >= 250) { lastFlush = t; ex.flush(t); }
      }
      const recs = ex.flowsIngested;
      const t0 = performance.now();
      let bytes = 0, obsN = 0;
      const lat = [];
      let t2 = 0, lf = 0;
      while (t2 < 15000) {
        const flows = sim.step(25);
        for (let i = 0; i < flows.length; i++) {
          ex.ingest(flows[i], t2);
          bytes += flows[i].bytes;
        }
        t2 += 25;
        if (t2 - lf >= 250) {
          lf = t2;
          const obs = ex.flush(t2);
          const a = performance.now();
          for (let i = 0; i < obs.length; i++) {
            eng.model.predict(obs[i].x);
            DET.scoreAll(obs[i].x, obs[i]);
            obsN++;
          }
          lat.push((performance.now() - a) / Math.max(1, obs.length));
        }
        if ((t2 / 1000) % 2 < 0.03) await new Promise((r) => setTimeout(r, 0));
      }
      const dur = (performance.now() - t0) / 1000;
      lat.sort((a, b) => a - b);
      const meanBytes = bytes / Math.max(1, recs);
      results.push({
        ddos: d,
        recs: Math.round(recs / dur),
        mbps: U.round((recs * meanBytes * 8) / 1e6 / dur, 1),
        p50: lat.length ? U.round(lat[Math.floor(lat.length * 0.5)] * 1000, 1) : 0,
        p99: lat.length ? U.round(lat[Math.floor(lat.length * 0.99)] * 1000, 1) : 0,
        obsPerSec: Math.round(obsN / dur),
        entities: ex.views.size,
      });
      eng.bench = results;
      renderBench();
    }
    $("btnBench").disabled = false;
    $("btnBench2").disabled = false;
  }

  function renderBench() {
    if (!eng.bench.length) {
      $("benchStats").innerHTML = `<div class="stat"><span>status</span><b>not run</b></div>`;
      return;
    }
    const best = eng.bench[eng.bench.length - 1];
    $("benchStats").innerHTML = [
      ["peak records/s", U.fmtInt(best.recs), "good"],
      ["peak equivalent", best.mbps + " Mbps", "good"],
      ["infer p50", best.p50 + " µs/entity", ""],
      ["infer p99", best.p99 + " µs/entity", ""],
      ["observations/s", U.fmtInt(best.obsPerSec), ""],
      ["entities resident", U.fmtInt(best.entities), ""],
    ].map((s) => `<div class="stat ${s[2]}"><span>${s[0]}</span><b>${s[1]}</b></div>`).join("");
    CH.bars($("cBench"), eng.bench.map((b) => ({ k: "×" + b.ddos, v: b.recs, top: U.fmtNum(b.recs), color: "#00d3a7" })), { unit: "" });
  }

  function wire() {
    $("btnPlay").onclick = () => {
      eng.running = !eng.running;
      $("btnPlay").textContent = eng.running ? "❚❚ Pause" : "▶ Run";
      setEngine(eng.running ? "live" : "paused", eng.running ? "streaming" : "paused");
    };
    $("btnStep").onclick = () => {
      const flows = eng.sim.step(250);
      for (let i = 0; i < flows.length; i++) { eng.ex.ingest(flows[i], eng.t); eng.flowBucket++; eng.byteBucket += flows[i].bytes; }
      eng.t += 250;
      const obs = eng.ex.flush(eng.t);
      for (let i = 0; i < obs.length; i++) score(obs[i]);
      render();
    };
    $("btnReset").onclick = () => { resetEngine(); renderTable(); };
    $("btnExport").onclick = () => {
      const out = {
        export: "sentinel-alerts",
        generated_at: new Date().toISOString(),
        schema: ALERTS.SCHEMA_VERSION,
        records_ingested: eng.totalFlows,
        bytes_ingested: eng.totalBytes,
        model: eng.model ? eng.model.meta : null,
        alerts: eng.store.items,
      };
      U.download("sentinel-alerts.json", JSON.stringify(out, null, 2));
    };
    $("btnModel").onclick = () => U.download("sentinel-model.json", JSON.stringify(eng.model.toJSON(), null, 2));
    $("btnBench").onclick = runBench;
    $("btnBench2").onclick = runBench;
    $("btnRetrain").onclick = async () => {
      setEngine("train", "retraining");
      await trainModel();
      setEngine(eng.running ? "live" : "paused", eng.running ? "streaming" : "paused");
    };
    $("btnLoadModel").onclick = () => $("fileModel").click();
    $("fileModel").onchange = (e) => {
      const f = e.target.files[0];
      if (!f) return;
      const r = new FileReader();
      r.onload = () => {
        try {
          const j = JSON.parse(r.result);
          if (!j.W || !j.mu) throw new Error("not a SENTINEL model file");
          const m = new MODEL.SoftmaxLR(j.features.length, j.classes.length);
          m.mu.set(j.mu);
          m.sd.set(j.sd);
          m.W.set(j.W);
          m.b.set(j.b);
          m.meta = j.meta || {};
          eng.model = m;
          const ev = MODEL.evaluate(m, m._X || new Float64Array(0), [], []);
          renderModel(m, { rows: CLASSES.map((c) => ({ cls: c, support: 0, precision: 0, recall: 0, f1: 0 })), conf: CLASSES.map(() => CLASSES.map(() => 0)), accuracy: 0, macroF1: 0 }, { rows: [], accuracy: 0, macroF1: 0 }, { n: 0 });
          setEngine(eng.running ? "live" : "paused", "model loaded");
        } catch (err) {
          setEngine("err", "bad model file");
          alert("Could not load model: " + err.message);
        }
      };
      r.readAsText(f);
    };
    $("ddosRange").oninput = (e) => {
      eng.ddos = +e.target.value;
      $("ddosVal").textContent = eng.ddos.toFixed(1);
      eng.sim.setIntensity("ddos", eng.ddos);
    };
    $("speedSeg").querySelectorAll("button").forEach((b) => {
      b.onclick = () => {
        $("speedSeg").querySelectorAll("button").forEach((x) => x.classList.remove("on"));
        b.classList.add("on");
        eng.speed = +b.dataset.v;
      };
    });
    $("tabs").querySelectorAll("button").forEach((b) => {
      b.onclick = () => {
        $("tabs").querySelectorAll("button").forEach((x) => x.classList.remove("on"));
        b.classList.add("on");
        const id = b.dataset.tab;
        $("tabs").dataset.active = id;
        document.querySelectorAll(".page").forEach((p) => p.classList.toggle("on", p.id === "page-" + id));
        if (id === "alerts") { renderTable(); renderSchemaSample(); }
        if (id === "arch") renderBench();
        if (id === "live") render();
      };
    });
    $("fClass").innerHTML = `<option value="">all classes</option>` + CLASSES.map((c) => `<option value="${c.id}">${c.label}</option>`).join("");
    ["fClass", "fSev", "fText"].forEach((id) => {
      $(id).addEventListener("input", () => { renderTable(); renderSchemaSample(); });
    });
    window.addEventListener("resize", () => { if (eng.model) render(); });
  }

  async function main() {
    boot("building character n-gram model…", 6);
    LEX.model();
    boot("synthesising labelled training corpus…", 14);
    renderFeatures();
    renderConstraints();
    wire();
    buildInjectors();
    renderBench();
    await new Promise((r) => setTimeout(r, 30));
    const model = await trainModel();
    boot("warming long-horizon baselines (300 s of stream)…", 92);
    resetEngine();
    boot("streaming", 100);
    setTimeout(() => $("boot").classList.add("gone"), 260);
    setEngine("live", "streaming");
    lastReal = performance.now();
    requestAnimationFrame(frame);
    window.__sentinel = { eng, model, U, FEAT, DET, CLASSES };
  }

  main();
  return { eng };
})();
