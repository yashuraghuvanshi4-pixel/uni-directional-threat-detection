const ALERTS = (() => {
  const SCHEMA_VERSION = "sentinel.alert/1.0.0";

  class AlertStore {
    constructor(cap = 4000) {
      this.cap = cap;
      this.items = [];
      this.counts = new Int32Array(CLASSES.length);
      this.sevCounts = new Int32Array(6);
      this.total = 0;
      this.byClass = new Map();
      this.lastByKey = new Map();
      this.cooldownMs = 9000;
      this.maxPerKey = 3;
      this.emis = 0;
    }

    reset() {
      this.items.length = 0;
      this.counts.fill(0);
      this.sevCounts.fill(0);
      this.total = 0;
      this.byClass.clear();
      this.lastByKey.clear();
      this.emis = 0;
    }

    make(o) {
      const spec = DET.SPECS[o.classId];
      const conf = o.confidence;
      const sev = DET.severity(o.classId, conf);
      const a = {
        schema: SCHEMA_VERSION,
        alert_id: "ALT-" + o.now.toString(36).toUpperCase() + "-" + (++this.emis).toString(36).toUpperCase().padStart(4, "0"),
        timestamp: new Date(o.now).toISOString(),
        ts_ms: o.now,
        flow_identifier: {
          view: o.kind === "slow" ? "source-entity" : o.view.isDst ? "destination-entity" : "source-entity",
          entity: o.ipStr,
          role: o.view.isDst ? "target" : "originator",
          window_span_ms: o.kind === "slow" ? FEAT.SLOW_MS : FEAT.WINDOW_MS,
          detection_horizon: o.kind,
          distinct_peers: Math.round(Math.pow(10, o.x[FEAT.IDX.get("distinct_peers")]) - 1),
          distinct_ports: Math.round(Math.pow(10, o.x[FEAT.IDX.get("distinct_ports")]) - 1),
          flow_rate_per_s: U.round(o.x[FEAT.IDX.get("flow_rate")], 2),
          primary_bytes_per_s: Math.round(Math.pow(10, o.x[FEAT.IDX.get("log_primary_bytes")]) - 1),
          secondary_bytes_per_s: Math.round(Math.pow(10, o.x[FEAT.IDX.get("log_secondary_bytes")]) - 1),
        },
        threat_class: o.classId,
        threat_label: spec.label,
        mitre_attack: spec.mitre,
        confidence: U.round(conf, 4),
        confidence_band: conf >= 0.9 ? "high" : conf >= 0.7 ? "medium" : "low",
        severity: sev,
        severity_label: DET.SEV_NAME[sev],
        scoring: {
          model_probability: U.round(o.modelProb, 4),
          statistical_score: U.round(o.statScore, 4),
          fusion: "0.62*model + 0.38*statistical",
          model: "softmax-multinomial-logistic-regression",
          model_version: o.modelVersion,
        },
        supporting_evidence: {
          top_features: o.evidence.map((e) => ({
            feature: e.name,
            value: e.value,
            contribution: e.weight,
          })),
          all_features: FEAT.NAMES.map((n, i) => ({ feature: n, value: U.round(o.x[i], 4) })),
        },
        ingest: {
          source: "one-way SPAN mirror / hardware data diode",
          direction: "unidirectional (read-only)",
          active_response: false,
          payload_decryption: false,
          pipeline_stage: "streaming-inference",
        },
        status: "new",
        labels: [o.kind === "slow" ? "long-horizon" : "short-horizon"],
      };
      return a;
    }

    push(alert) {
      const k = alert.flow_identifier.entity + "|" + alert.threat_class;
      const prev = this.lastByKey.get(k);
      if (prev && alert.ts_ms - prev.ts_ms < this.cooldownMs) {
        const c = prev.repeat_count + 1;
        prev.repeat_count = c;
        prev.confidence = Math.max(prev.confidence, alert.confidence);
        prev.ts_ms = alert.ts_ms;
        prev.timestamp = alert.timestamp;
        prev.last_seen = alert.timestamp;
        this.byClass.set(alert.threat_class, (this.byClass.get(alert.threat_class) || 0) + 1);
        this.sevCounts[prev.severity]++;
        return null;
      }
      alert.repeat_count = 1;
      alert.first_seen = alert.timestamp;
      alert.last_seen = alert.timestamp;
      this.items.push(alert);
      if (this.items.length > this.cap) this.items.shift();
      const ci = CLASSES.findIndex((c) => c.id === alert.threat_class);
      if (ci >= 0) this.counts[ci]++;
      this.sevCounts[alert.severity]++;
      this.byClass.set(alert.threat_class, (this.byClass.get(alert.threat_class) || 0) + 1);
      this.total++;
      this.lastByKey.set(k, alert);
      return alert;
    }

    recent(n) {
      const start = Math.max(0, this.items.length - n);
      return this.items.slice(start);
    }

    bySeverity(min) {
      return this.items.filter((a) => a.severity >= min);
    }
  }

  return { AlertStore, SCHEMA_VERSION };
})();
