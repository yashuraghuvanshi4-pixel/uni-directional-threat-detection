const DET = (() => {
  const IDX = FEAT.IDX;
  const f = (x, name) => x[IDX.get(name)];

  const SPECS = {
    ddos_volumetric: {
      label: "Volumetric / protocol DDoS",
      severityBase: 4,
      mitre: ["T1498.001", "T1498.002", "T1499"],
      score(x, o) {
        const parts = [];
        let s = 0;
        const rateTerm = U.clamp((f(x, "flow_rate_z") - 2.2) / 5, 0, 1) * 0.24;
        const peerTerm = U.clamp((f(x, "distinct_peers") - 2.1) / 1.6, 0, 1) * 0.22;
        const entTerm = U.clamp((f(x, "peer_entropy_norm") - 0.62) / 0.36, 0, 1) * 0.16;
        const synTerm = U.clamp((f(x, "syn_ratio") - 0.5) / 0.45, 0, 1) * 0.14;
        const unansTerm = f(x, "unanswered_ratio") * 0.12;
        const smallTerm = U.clamp((f(x, "small_pkt_ratio") - 0.4) / 0.5, 0, 1) * 0.12;
        s = rateTerm + peerTerm + entTerm + synTerm + unansTerm + smallTerm;
        parts.push({ name: "flow_rate_z", value: U.round(f(x, "flow_rate_z"), 2), weight: U.round(rateTerm, 3) });
        parts.push({ name: "distinct_peers_log10", value: U.round(f(x, "distinct_peers"), 2), weight: U.round(peerTerm, 3) });
        parts.push({ name: "src_peer_entropy_norm", value: U.round(f(x, "peer_entropy_norm"), 3), weight: U.round(entTerm, 3) });
        parts.push({ name: "syn_ratio", value: U.round(f(x, "syn_ratio"), 3), weight: U.round(synTerm, 3) });
        parts.push({ name: "unanswered_ratio", value: U.round(f(x, "unanswered_ratio"), 3), weight: U.round(unansTerm, 3) });
        parts.push({ name: "small_pkt_ratio", value: U.round(f(x, "small_pkt_ratio"), 3), weight: U.round(smallTerm, 3) });
        return { score: U.clamp(s, 0, 1), evidence: parts, extra: { view: o.kind } };
      },
    },
    c2_beaconing: {
      label: "Botnet C2 beaconing",
      severityBase: 4,
      mitre: ["T1071.001", "T1573"],
      score(x) {
        const parts = [];
        const rTerm = U.clamp((f(x, "beacon_r") - 0.22) / 0.42, 0, 1) * 0.42;
        const regTerm = U.clamp((f(x, "beacon_regularity") - 0.68) / 0.3, 0, 1) * 0.24;
        const cvTerm = U.clamp((1.35 - f(x, "beacon_iat_cv")) / 0.7, 0, 1) * 0.18;
        const periodOk = (() => {
          const p = Math.pow(10, f(x, "log_beacon_period")) - 1;
          return p >= 1.5 && p <= 900 ? 1 : 0.25;
        })();
        const perTerm = periodOk * 0.16;
        const s = rTerm + regTerm + cvTerm + perTerm;
        parts.push({ name: "beacon_periodicity_r", value: U.round(f(x, "beacon_r"), 3), weight: U.round(rTerm, 3) });
        parts.push({ name: "beacon_regularity", value: U.round(f(x, "beacon_regularity"), 3), weight: U.round(regTerm, 3) });
        parts.push({ name: "beacon_iat_cv", value: U.round(f(x, "beacon_iat_cv"), 3), weight: U.round(cvTerm, 3) });
        parts.push({ name: "estimated_period_s", value: U.round(Math.pow(10, f(x, "log_beacon_period")) - 1, 1), weight: U.round(perTerm, 3) });
        return { score: U.clamp(s, 0, 1), evidence: parts, extra: {} };
      },
    },
    dga_dns: {
      label: "DGA domain / DNS tunnelling",
      severityBase: 4,
      mitre: ["T1568.002", "T1071.004", "T1572"],
      score(x) {
        const parts = [];
        const ngTerm = U.clamp((-3.55 - f(x, "dns_ngram")) / 1.5, 0, 1) * 0.3;
        const entTerm = U.clamp((f(x, "dns_entropy_mean") - 3.5) / 1.1, 0, 1) * 0.2;
        const lenTerm = U.clamp((f(x, "dns_len_mean") - 22) / 60, 0, 1) * 0.16;
        const labTerm = U.clamp((f(x, "dns_label_max") - 16) / 30, 0, 1) * 0.12;
        const uniqTerm = U.clamp((f(x, "dns_uniq") - 0.75) / 0.24, 0, 1) * 0.12;
        const nxTerm = U.clamp(f(x, "dns_nx") * 1.4, 0, 1) * 0.05;
        const txtTerm = U.clamp(f(x, "dns_txt") * 1.6, 0, 1) * 0.05;
        const s = (ngTerm + entTerm + lenTerm + labTerm + uniqTerm + nxTerm + txtTerm) * U.clamp(f(x, "dns_ratio") * 12, 0.2, 1);
        parts.push({ name: "dns_bigram_llr", value: U.round(f(x, "dns_ngram"), 3), weight: U.round(ngTerm, 3) });
        parts.push({ name: "dns_qname_entropy", value: U.round(f(x, "dns_entropy_mean"), 3), weight: U.round(entTerm, 3) });
        parts.push({ name: "dns_qname_len_mean", value: U.round(f(x, "dns_len_mean"), 1), weight: U.round(lenTerm, 3) });
        parts.push({ name: "dns_max_label_len", value: U.round(f(x, "dns_label_max"), 1), weight: U.round(labTerm, 3) });
        parts.push({ name: "dns_unique_ratio", value: U.round(f(x, "dns_uniq"), 3), weight: U.round(uniqTerm, 3) });
        parts.push({ name: "dns_nxdomain_ratio", value: U.round(f(x, "dns_nx"), 3), weight: U.round(nxTerm, 3) });
        parts.push({ name: "dns_txt_ratio", value: U.round(f(x, "dns_txt"), 3), weight: U.round(txtTerm, 3) });
        return { score: U.clamp(s, 0, 1), evidence: parts, extra: {} };
      },
    },
    tls_malware: {
      label: "Malware in encrypted session",
      severityBase: 4,
      mitre: ["T1071.001", "T1573.001", "T1027"],
      score(x) {
        const parts = [];
        const rarTerm = U.clamp((f(x, "tls_ja3_rarity") - 0.42) / 0.45, 0, 1) * 0.4;
        const selfTerm = U.clamp(f(x, "tls_self_signed") * 1.5, 0, 1) * 0.14;
        const nocTerm = U.clamp(f(x, "tls_no_cert") * 1.4, 0, 1) * 0.1;
        const unifTerm = U.clamp((f(x, "tls_size_uniform") - 0.72) / 0.26, 0, 1) * 0.16;
        const sizeEntTerm = U.clamp((0.72 - f(x, "tls_size_entropy")) / 0.4, 0, 1) * 0.1;
        const bTerm = U.clamp((f(x, "beacon_r") - 0.3) / 0.4, 0, 1) * 0.1;
        const s = (rarTerm + selfTerm + nocTerm + unifTerm + sizeEntTerm + bTerm) * U.clamp(f(x, "tls_ratio") * 10, 0.25, 1);
        parts.push({ name: "ja3_ja4_rarity", value: U.round(f(x, "tls_ja3_rarity"), 3), weight: U.round(rarTerm, 3) });
        parts.push({ name: "tls_self_signed_ratio", value: U.round(f(x, "tls_self_signed"), 3), weight: U.round(selfTerm, 3) });
        parts.push({ name: "tls_cert_len_zero_ratio", value: U.round(f(x, "tls_no_cert"), 3), weight: U.round(nocTerm, 3) });
        parts.push({ name: "tls_packet_size_uniformity", value: U.round(f(x, "tls_size_uniform"), 3), weight: U.round(unifTerm, 3) });
        parts.push({ name: "tls_size_seq_entropy", value: U.round(f(x, "tls_size_entropy"), 3), weight: U.round(sizeEntTerm, 3) });
        parts.push({ name: "beacon_periodicity_r", value: U.round(f(x, "beacon_r"), 3), weight: U.round(bTerm, 3) });
        return { score: U.clamp(s, 0, 1), evidence: parts, extra: {} };
      },
    },
    recon_scan: {
      label: "Reconnaissance / port scanning",
      severityBase: 3,
      mitre: ["T1046", "T1595.001"],
      score(x) {
        const parts = [];
        const ppTerm = U.clamp((f(x, "ports_per_peer") - 1.15) / 1.4, 0, 1) * 0.28;
        const churnTerm = U.clamp((f(x, "peer_churn") - 0.2) / 0.6, 0, 1) * 0.22;
        const synTerm = U.clamp((f(x, "syn_ratio") - 0.45) / 0.45, 0, 1) * 0.2;
        const portEntTerm = U.clamp((f(x, "port_entropy") - 4.4) / 2.4, 0, 1) * 0.14;
        const unansTerm = U.clamp(f(x, "unanswered_ratio") - 0.4, 0, 1) * 0.1;
        const smallTerm = U.clamp(f(x, "small_pkt_ratio") - 0.4, 0, 1) * 0.06;
        const s = ppTerm + churnTerm + synTerm + portEntTerm + unansTerm + smallTerm;
        parts.push({ name: "ports_per_peer_log10", value: U.round(f(x, "ports_per_peer"), 3), weight: U.round(ppTerm, 3) });
        parts.push({ name: "peer_churn_ratio", value: U.round(f(x, "peer_churn"), 3), weight: U.round(churnTerm, 3) });
        parts.push({ name: "syn_ratio", value: U.round(f(x, "syn_ratio"), 3), weight: U.round(synTerm, 3) });
        parts.push({ name: "dst_port_entropy", value: U.round(f(x, "port_entropy"), 3), weight: U.round(portEntTerm, 3) });
        parts.push({ name: "unanswered_ratio", value: U.round(f(x, "unanswered_ratio"), 3), weight: U.round(unansTerm, 3) });
        return { score: U.clamp(s, 0, 1), evidence: parts, extra: {} };
      },
    },
    exfiltration: {
      label: "Data exfiltration",
      severityBase: 5,
      mitre: ["T1041", "T1567", "T1030"],
      score(x) {
        const parts = [];
        const ratioTerm = U.clamp((f(x, "out_in_ratio") - 0.75) / 2.2, 0, 1) * 0.3;
        const asymTerm = U.clamp((f(x, "asym") - 0.72) / 0.27, 0, 1) * 0.2;
        const brTerm = U.clamp((f(x, "log_primary_bytes") - 4.2) / 2.0, 0, 1) * 0.2;
        const durTerm = U.clamp((f(x, "log_mean_dur") - 2.4) / 1.6, 0, 1) * 0.1;
        const uniTerm = U.clamp((f(x, "tls_size_uniform") - 0.6) / 0.35, 0, 1) * 0.1;
        const churnTerm = U.clamp((f(x, "new_peer_ratio") - 0.3) / 0.6, 0, 1) * 0.1;
        const s = ratioTerm + asymTerm + brTerm + durTerm + uniTerm + churnTerm;
        parts.push({ name: "log10_out_in_byte_ratio", value: U.round(f(x, "out_in_ratio"), 3), weight: U.round(ratioTerm, 3) });
        parts.push({ name: "byte_asymmetry", value: U.round(f(x, "asym"), 3), weight: U.round(asymTerm, 3) });
        parts.push({ name: "log10_primary_bytes_per_s", value: U.round(f(x, "log_primary_bytes"), 3), weight: U.round(brTerm, 3) });
        parts.push({ name: "log10_mean_duration_ms", value: U.round(f(x, "log_mean_dur"), 3), weight: U.round(durTerm, 3) });
        parts.push({ name: "encrypted_size_uniformity", value: U.round(f(x, "tls_size_uniform"), 3), weight: U.round(uniTerm, 3) });
        return { score: U.clamp(s, 0, 1), evidence: parts, extra: {} };
      },
    },
  };

  const IDS = CLASSES.map((c) => c.id);

  function scoreAll(x, o) {
    const out = {};
    for (const id of IDS) {
      if (id === "benign") continue;
      out[id] = SPECS[id].score(x, o);
    }
    return out;
  }

  function severity(classId, conf) {
    const base = SPECS[classId].severityBase;
    const s = base - 1 + conf * 2;
    return U.clamp(Math.round(s), 1, 5);
  }

  const SEV_NAME = ["", "informational", "low", "medium", "high", "critical"];

  return { SPECS, IDS, scoreAll, severity, SEV_NAME };
})();
