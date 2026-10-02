const FEAT = (() => {
  const NAMES = [
    "flow_rate", "flow_rate_z", "log_flow_rate", "pkt_rate", "log_byte_rate",
    "distinct_peers", "peer_entropy", "peer_entropy_norm", "peer_churn",
    "distinct_ports", "port_entropy", "ports_per_peer", "flows_per_peer", "new_peer_ratio",
    "syn_ratio", "response_ratio", "unanswered_ratio", "proto_mix_entropy",
    "udp_ratio", "tcp_ratio", "small_pkt_ratio", "log_mean_pkt", "log_mean_bytes",
    "log_mean_dur", "log_primary_bytes", "log_secondary_bytes", "out_in_ratio", "asym",
    "beacon_r", "log_beacon_period", "beacon_iat_cv", "beacon_peers", "beacon_regularity",
    "dns_ratio", "dns_len_mean", "dns_len_max", "dns_label_max", "dns_entropy_mean",
    "dns_entropy_max", "dns_ngram", "dns_uniq", "dns_txt", "dns_nx", "dns_any",
    "tls_ratio", "tls_ja3_rarity", "tls_self_signed", "tls_no_cert", "tls_sni_entropy",
    "tls_size_entropy", "tls_size_uniform", "tls_ja3_count", "is_dst_view", "active_log",
    "phase_mod", "tcp_flags_norm", "bytes_per_pkt", "port_rare", "log_window_span",
  ];
  const IDX = new Map();
  NAMES.forEach((n, i) => (IDX.set(n, i)));
  const D = NAMES.length;

  const WINDOW_MS = 1000;
  const SLOW_MS = 30000;
  const SLOW_ALPHA = 1 - Math.exp(-(WINDOW_MS / 1000) / 12);
  const INTERNAL_BASE = 0x0a140000;
  const INTERNAL_MASK = 0xffff0000;
  const HEAVY_MIN_SRC = 12;
  const HEAVY_MIN_DST = 4;
  const MAX_VIEWS = 2600;
  const MAX_SLOW_VIEWS = 110;
  const MAX_FLOWS_KEPT = 1400;
  const MAX_SLOW_FLOWS = 3200;
  const MAX_QNAMES = 72;
  const MAX_TLS = 72;
  const MAX_SLOW_QNAMES = 260;
  const MAX_SLOW_TLS = 260;
  const MAX_IAT_PEERS = 12;
  const IAT_LEN = 34;
  const VIEW_IDLE_MS = 9000;
  const SLOW_TRIGGER = 5;

  const isInternal = (ip) => (ip & INTERNAL_MASK) === INTERNAL_BASE;
  const enc = new TextEncoder();

  const qCache = new Map();
  function qEntropy(q) {
    let e = qCache.get(q);
    if (e === undefined) {
      e = U.shannonOfBytes(enc.encode(q));
      if (qCache.size > 30000) qCache.clear();
      qCache.set(q, e);
    }
    return e;
  }

  const ngramCache = new Map();
  function qNgram(q) {
    let s = ngramCache.get(q);
    if (s === undefined) {
      s = LEX.score(q);
      if (ngramCache.size > 30000) ngramCache.clear();
      ngramCache.set(q, s);
    }
    return s;
  }

  const domTruth = (m) => {
    let best = "benign", bn = -1;
    for (const [k, v] of m) if (v > bn) { bn = v; best = k; }
    return best;
  };

  class View {
    constructor(key, ip, isDst) {
      this.key = key;
      this.ip = ip;
      this.isDst = isDst;
      this.flows = [];
      this.slowFlows = [];
      this.qnames = [];
      this.qset = new Set();
      this.tls = [];
      this.peers = new Map();
      this.ports = new Set();
      this.iat = new Map();
      this.protoC = { t6: 0, u17: 0, i1: 0, g47: 0, o: 0 };
      this.truthC = new Map();
      this.slowTruthC = new Map();
      this.lastSeen = 0;
      this.firstSeen = 0;
      this.primFlows = 0;
      this.revFlows = 0;
      this.pkts = 0;
      this.bytesPrimary = 0;
      this.bytesSecondary = 0;
      this.syn = 0;
      this.finrst = 0;
      this.small = 0;
      this.durSum = 0;
      this.fb = { pkts: 0, bytes: 0, dur: 0, n: 0 };
      this.dnsN = 0; this.dnsTxt = 0; this.dnsNx = 0; this.dnsAny = 0;
      this.tlsN = 0; this.tlsRare = 0; this.tlsSelf = 0; this.tlsNoCert = 0;
      this.newPeerN = 0;
      this.ewma = new U.Ewma(0.1);
      this.phase = 0;
      this.beaconSig = "";
      this.periodCache = new Map();
      this.isSlow = false;
      this.slowPromotedAt = 0;
      this.slowEvictAt = 0;
      this.e = {
        fr: 0, br: 0, pr: 0, syn: 0, dns: 0, tls: 0, rar: 0, self: 0, noc: 0,
        resp: 0, bp: 0, bs: 0, pk: 0, by: 0, du: 0, sm: 0, udp: 0, np: 0,
        txt: 0, nx: 0, any: 0, n: 0,
      };
      this.totalFlows = 0;
      this.totalFlowsEver = 0;
    }

    reset() {
      this.flows.length = 0;
      this.qnames.length = 0;
      this.qset.clear();
      this.tls.length = 0;
      this.primFlows = 0;
      this.revFlows = 0;
      this.pkts = 0;
      this.bytesPrimary = 0;
      this.bytesSecondary = 0;
      this.syn = 0;
      this.finrst = 0;
      this.small = 0;
      this.durSum = 0;
      this.fb.pkts = 0; this.fb.bytes = 0; this.fb.dur = 0; this.fb.n = 0;
      this.dnsN = 0; this.dnsTxt = 0; this.dnsNx = 0; this.dnsAny = 0;
      this.tlsN = 0; this.tlsRare = 0; this.tlsSelf = 0; this.tlsNoCert = 0;
      this.newPeerN = 0;
      this.truthC.clear();
      this.protoC.t6 = 0; this.protoC.u17 = 0; this.protoC.i1 = 0; this.protoC.g47 = 0; this.protoC.o = 0;
    }
  }

  class Extractor {
    constructor() {
      this.views = new Map();
      this.srcHeavy = new Map();
      this.dstHeavy = new Map();
      this.knownPeers = new Set();
      this.knownOrder = [];
      this.ja3 = new Map();
      this.ja3Total = 0;
      this.slowCount = 0;
      this.now = 0;
      this.flowsIngested = 0;
      this.lastEvict = 0;
    }

    getView(ip, isDst) {
      const key = ip * 2 + (isDst ? 1 : 0);
      let v = this.views.get(key);
      if (v) return v;
      v = new View(key, ip, isDst);
      this.views.set(key, v);
      return v;
    }

    known(ip) {
      if (this.knownPeers.has(ip)) return true;
      this.knownPeers.add(ip);
      this.knownOrder.push(ip);
      if (this.knownOrder.length > 150000) {
        const drop = this.knownOrder.splice(0, 50000);
        for (const d of drop) this.knownPeers.delete(d);
      }
      return false;
    }

    bump(map, ip) {
      const c = map.get(ip);
      if (c === undefined) map.set(ip, 1);
      else map.set(ip, c + 1);
    }

    rarity(hash) {
      let c = this.ja3.get(hash);
      if (c === undefined) { this.ja3.set(hash, 1); c = 1; } else { c++; this.ja3.set(hash, c); }
      this.ja3Total++;
      const total = Math.max(this.ja3Total, 4000);
      return Math.min(1, Math.log10(1 + total / (c + 1)) / 3.2);
    }

    ingest(flow, now) {
      this.now = now;
      this.flowsIngested++;
      const f = flow;
      const isSrcKnown = isInternal(f.sip);
      const isDstKnown = isInternal(f.dip);
      this.bump(this.srcHeavy, f.sip);
      this.bump(this.dstHeavy, f.dip);
      const sc = this.srcHeavy.get(f.sip);
      const dc = this.dstHeavy.get(f.dip);
      const wantSrc = isSrcKnown || sc >= HEAVY_MIN_SRC;
      const wantDst = isDstKnown || dc >= HEAVY_MIN_DST;

      if (f.dir === 0) {
        const isNew = !this.known(f.dip);
        if (wantSrc) this.pushFwd(this.getView(f.sip, false), f, f.dip, isNew, now, true);
        if (wantDst) this.pushFwd(this.getView(f.dip, true), f, f.sip, isNew, now, false);
      } else {
        if (wantSrc) {
          const v = this.views.get(f.sip * 2);
          if (v) this.pushRev(v, f, now, true);
        }
        if (wantDst) {
          const v = this.views.get(f.dip * 2 + 1);
          if (v) this.pushRev(v, f, now, false);
        }
      }
    }

    pushFwd(v, f, peer, isNew, now, isSrc) {
      v.lastSeen = now;
      if (!v.firstSeen) v.firstSeen = now;
      v.primFlows++;
      v.totalFlows++;
      v.phase++;
      v.pkts += f.pkts;
      v.bytesPrimary += f.bytes;
      v.durSum += f.dur;
      v.fb.pkts += f.pkts;
      v.fb.bytes += f.bytes;
      v.fb.dur += f.dur;
      v.fb.n++;
      if (f.pkts <= 2) v.small++;
      if (f.proto === 6) {
        v.protoC.t6++;
        if (f.flags & 0x02) v.syn++;
        if (f.flags & 0x14) v.finrst++;
      } else if (f.proto === 17) v.protoC.u17++;
      else if (f.proto === 1) v.protoC.i1++;
      else if (f.proto === 47) v.protoC.g47++;
      else v.protoC.o++;
      v.peers.set(peer, (v.peers.get(peer) || 0) + 1);
      if (v.ports.size < 3072) v.ports.add(f.dport);
      if (isNew) v.newPeerN++;
      if (v.flows.length < MAX_FLOWS_KEPT) v.flows.push(f);
      v.truthC.set(f.truth, (v.truthC.get(f.truth) || 0) + 1);

      if (isSrc) {
        this.trackIat(v, peer, f, now);
        if (v.isSlow) {
          if (v.slowFlows.length < MAX_SLOW_FLOWS) v.slowFlows.push(f);
          v.slowTruthC.set(f.truth, (v.slowTruthC.get(f.truth) || 0) + 1);
        } else if (this.maybePromote(v, now)) {
          v.slowFlows.push(f);
          v.slowTruthC.set(f.truth, 1);
        }
      }
      if (f.dns) this.trackDns(v, f);
      if (f.tls) this.trackTls(v, f);
    }

    pushRev(v, f, now, isSrc) {
      v.lastSeen = now;
      v.revFlows++;
      v.pkts += f.pkts;
      v.bytesSecondary += f.bytes;
      if (f.dns) this.trackDns(v, f);
      if (f.tls) this.trackTls(v, f);
    }

    maybePromote(v, now) {
      if (this.slowCount >= MAX_SLOW_VIEWS) return false;
      for (const [, arr] of v.iat) {
        if (arr.length >= SLOW_TRIGGER) {
          v.isSlow = true;
          v.slowPromotedAt = now;
          this.slowCount++;
          return true;
        }
      }
      return false;
    }

    demote(v) {
      if (!v.isSlow) return;
      v.isSlow = false;
      v.slowFlows.length = 0;
      v.slowTruthC.clear();
      v.e = { fr: 0, br: 0, pr: 0, syn: 0, dns: 0, tls: 0, rar: 0, self: 0, noc: 0, resp: 0, bp: 0, bs: 0, pk: 0, by: 0, du: 0, sm: 0, udp: 0, np: 0, txt: 0, nx: 0, any: 0, n: 0 };
      this.slowCount--;
    }

    bumpSlow(v, now) {
      return true;
    }

    trackIat(v, peer, f, now) {
      let arr = v.iat.get(peer);
      if (!arr) {
        if (v.iat.size >= MAX_IAT_PEERS) return;
        arr = [];
        v.iat.set(peer, arr);
      }
      const n = arr.length;
      if (n && now - arr[n - 1] < 12) return;
      arr.push(now);
      if (arr.length > IAT_LEN) arr.splice(0, arr.length - IAT_LEN);
    }

    trackDns(v, f) {
      const d = f.dns;
      v.dnsN++;
      if (d.qt === 16) v.dnsTxt++;
      if (d.qt === 255) v.dnsAny++;
      if (d.rc === 3) v.dnsNx++;
      const cap = v.isSlow ? MAX_SLOW_QNAMES : MAX_QNAMES;
      if (v.qnames.length < cap) {
        v.qnames.push(d.q);
        v.qset.add(d.q);
      }
    }

    trackTls(v, f) {
      const t = f.tls;
      v.tlsN++;
      v.tlsRare += this.rarity(t.quic ? t.ja4 : t.ja3);
      if (t.self) v.tlsSelf++;
      if (!t.cert) v.tlsNoCert++;
      const cap = v.isSlow ? MAX_SLOW_TLS : MAX_TLS;
      if (v.tls.length < cap) v.tls.push(f);
    }

    evict(now) {
      if (this.views.size <= MAX_VIEWS && now - this.lastEvict < 3000) return;
      this.lastEvict = now;
      const stale = now - VIEW_IDLE_MS;
      for (const [k, v] of this.views) {
        if (v.lastSeen < stale) {
          if (v.isSlow) { v.isSlow = false; this.slowCount--; }
          this.views.delete(k);
        }
      }
      if (this.views.size > MAX_VIEWS) {
        const arr = Array.from(this.views.values()).sort((a, b) => a.lastSeen - b.lastSeen);
        const cut = this.views.size - MAX_VIEWS;
        for (let i = 0; i < cut; i++) {
          if (arr[i].isSlow) { arr[i].isSlow = false; this.slowCount--; }
          this.views.delete(arr[i].key);
        }
      }
      if (this.srcHeavy.size > 260000) {
        const arr = Array.from(this.srcHeavy.keys());
        for (let i = 0; i < arr.length >> 1; i++) this.srcHeavy.delete(arr[i]);
      }
      if (this.dstHeavy.size > 260000) {
        const arr = Array.from(this.dstHeavy.keys());
        for (let i = 0; i < arr.length >> 1; i++) this.dstHeavy.delete(arr[i]);
      }
    }

    prune(arr, now, span) {
      const cut = now - span;
      let i = 0;
      while (i < arr.length && arr[i].ts < cut) i++;
      if (i > 0) arr.splice(0, i);
    }

    beaconOf(v) {
      const cands = [];
      for (const [, arr] of v.iat) if (arr.length >= 5) cands.push(arr);
      cands.sort((a, b) => b.length - a.length);
      if (!cands.length) return { r: 0, period: 0, cv: 1, peers: 0 };
      const sig = cands.map((c) => c.length).join(",");
      if (v.beaconSig !== sig) {
        v.beaconSig = sig;
        v.periodCache.clear();
        for (const arr of cands.slice(0, 3)) v.periodCache.set(arr, U.periodicity(arr));
      }
      let top = null;
      for (const arr of cands.slice(0, 3)) {
        const p = v.periodCache.get(arr);
        if (!top || p.r > top.r) top = p;
      }
      return { r: top.r, period: top.period, cv: top.cv, disp: top.disp, peers: Math.min(cands.length, 9) };
    }

    buildCommon(x, v, now, span, obs) {
      const n = Math.max(1, obs.n);
      const flowRate = obs.fr;
      const base = v.ewma.value;
      v.ewma.push(flowRate);
      const sd = Math.max(1.2, base * 0.5);
      x[IDX.get("flow_rate")] = flowRate;
      x[IDX.get("flow_rate_z")] = U.clamp((flowRate - base) / sd, -6, 14);
      x[IDX.get("log_flow_rate")] = Math.log10(1 + flowRate);
      x[IDX.get("pkt_rate")] = obs.pr;
      x[IDX.get("log_byte_rate")] = Math.log10(1 + obs.br);

      const dp = obs.peers;
      const pe = U.shannonFromCountsMap(obs.peerMap);
      x[IDX.get("distinct_peers")] = Math.log10(1 + dp);
      x[IDX.get("peer_entropy")] = pe;
      x[IDX.get("peer_entropy_norm")] = dp > 0 ? pe / Math.log2(dp) : 0;
      x[IDX.get("peer_churn")] = obs.newPeer / n;

      const dports = obs.ports;
      const dpn = dports.size;
      x[IDX.get("distinct_ports")] = Math.log10(1 + dpn);
      x[IDX.get("port_entropy")] = U.shannonOf(dports);
      x[IDX.get("ports_per_peer")] = Math.log10(1 + dpn / Math.max(1, dp));
      x[IDX.get("flows_per_peer")] = Math.log10(1 + obs.n / Math.max(1, dp));
      x[IDX.get("new_peer_ratio")] = obs.newPeer / n;

      x[IDX.get("syn_ratio")] = obs.syn;
      x[IDX.get("response_ratio")] = U.clamp(obs.resp, 0, 8);
      x[IDX.get("unanswered_ratio")] = U.clamp(1 - Math.min(1, obs.resp), 0, 1);
      x[IDX.get("proto_mix_entropy")] = U.shannonFromCounts(obs.protoMap);
      x[IDX.get("udp_ratio")] = obs.udp;
      x[IDX.get("tcp_ratio")] = obs.tcp;
      x[IDX.get("small_pkt_ratio")] = obs.sm;
      x[IDX.get("log_mean_pkt")] = Math.log10(1 + obs.pk / Math.max(1, obs.n));
      x[IDX.get("log_mean_bytes")] = Math.log10(1 + obs.by / Math.max(1, obs.n));
      x[IDX.get("log_mean_dur")] = Math.log10(1 + obs.du / Math.max(1, obs.n));

      x[IDX.get("log_primary_bytes")] = Math.log10(1 + obs.bp);
      x[IDX.get("log_secondary_bytes")] = Math.log10(1 + obs.bs);
      x[IDX.get("out_in_ratio")] = Math.log10((obs.bp + 512) / (obs.bs + 512));
      x[IDX.get("asym")] = Math.abs(obs.bp - obs.bs) / Math.max(1, obs.bp + obs.bs);

      const b = obs.beacon;
      x[IDX.get("beacon_r")] = b.r;
      x[IDX.get("log_beacon_period")] = Math.log10(1 + (b.period || 0) / 1000);
      x[IDX.get("beacon_iat_cv")] = U.clamp(b.cv === undefined ? 1 : b.cv, 0, 5);
      x[IDX.get("beacon_peers")] = Math.log10(1 + b.peers);
      x[IDX.get("beacon_regularity")] = U.clamp(1 - Math.min(1, b.disp === undefined ? 0 : b.disp), 0, 1);

      x[IDX.get("dns_ratio")] = obs.dns;
      if (obs.qnames.length) {
        let lsum = 0, lmax = 0, emax = 0, esum = 0, ngSum = 0, labMax = 0;
        for (const q of obs.qnames) {
          const L = q.length;
          lsum += L;
          if (L > lmax) lmax = L;
          const e = qEntropy(q);
          esum += e;
          if (e > emax) emax = e;
          ngSum += qNgram(q);
          let s = 0;
          for (let i = 0; i < L; i++) if (q.charCodeAt(i) === 46) { if (i - s > labMax) labMax = i - s; s = i + 1; }
          if (L - s > labMax) labMax = L - s;
        }
        const qn = obs.qnames.length;
        x[IDX.get("dns_len_mean")] = lsum / qn;
        x[IDX.get("dns_len_max")] = lmax;
        x[IDX.get("dns_label_max")] = labMax;
        x[IDX.get("dns_entropy_mean")] = esum / qn;
        x[IDX.get("dns_entropy_max")] = emax;
        x[IDX.get("dns_ngram")] = ngSum / qn;
        x[IDX.get("dns_uniq")] = obs.quniq;
        x[IDX.get("dns_txt")] = obs.txt;
        x[IDX.get("dns_nx")] = obs.nx;
        x[IDX.get("dns_any")] = obs.any;
      } else {
        x[IDX.get("dns_ngram")] = -2.1;
        x[IDX.get("dns_len_mean")] = 0;
        x[IDX.get("dns_ratio")] = obs.dns;
      }

      if (obs.tlsFlows.length) {
        const sniSet = new Set();
        const sizes = [];
        let self = 0, noc = 0;
        const ja3set = new Set();
        for (const f of obs.tlsFlows) {
          const t = f.tls;
          ja3set.add(t.quic ? t.ja4 : t.ja3);
          if (t.self) self++;
          if (!t.cert) noc++;
          if (t.sni) sniSet.add(t.sni);
          if (f.pk) for (const s of f.pk) sizes.push(s);
        }
        const k = Math.max(1, ja3set.size);
        x[IDX.get("tls_ratio")] = obs.tls;
        x[IDX.get("tls_ja3_rarity")] = obs.rar;
        x[IDX.get("tls_self_signed")] = self / k;
        x[IDX.get("tls_no_cert")] = noc / k;
        x[IDX.get("tls_sni_entropy")] = sniSet.size > 1 ? U.shannonOf(Array.from(sniSet)) : 0;
        x[IDX.get("tls_size_entropy")] = sizes.length > 3 ? U.shannonOf(sizes) / 6 : 0;
        x[IDX.get("tls_size_uniform")] = sizes.length > 3 ? U.clamp(1 - U.cv(sizes), 0, 1) : 0;
        x[IDX.get("tls_ja3_count")] = ja3set.size;
      } else {
        x[IDX.get("tls_ratio")] = obs.tls;
        x[IDX.get("tls_ja3_rarity")] = obs.rar;
      }

      x[IDX.get("is_dst_view")] = v.isDst ? 1 : 0;
      x[IDX.get("active_log")] = Math.log10(1 + (now - v.firstSeen) / 1000);
      x[IDX.get("phase_mod")] = v.phase % 97;
      x[IDX.get("tcp_flags_norm")] = obs.syn * 0.6 + Math.min(1, obs.fin) * 0.4;
      x[IDX.get("bytes_per_pkt")] = Math.log10(1 + obs.by / Math.max(1, obs.pk));
      x[IDX.get("port_rare")] = v.isDst ? U.clamp(dpn / Math.max(1, obs.n), 0, 1) : U.clamp(dpn / Math.max(1, dp), 0, 1);
      x[IDX.get("log_window_span")] = Math.log10(span / 1000);
      return x;
    }

    fastObs(v) {
      const ws = WINDOW_MS / 1000;
      const n = v.primFlows;
      const protoMap = { t6: v.protoC.t6, u17: v.protoC.u17, i1: v.protoC.i1, g47: v.protoC.g47, o: v.protoC.o };
      return {
        n, span: WINDOW_MS,
        fr: n / ws, pr: v.pkts / ws, br: v.bytesPrimary / ws,
        peers: v.peers.size, peerMap: v.peers, ports: v.ports,
        newPeer: v.newPeerN,
        syn: v.syn / Math.max(1, n),
        resp: v.revFlows / Math.max(1, n),
        protoMap, udp: v.protoC.u17 / Math.max(1, n), tcp: v.protoC.t6 / Math.max(1, n),
        sm: v.small / Math.max(1, n),
        pk: v.fb.pkts, by: v.fb.bytes, du: v.fb.dur,
        bp: v.bytesPrimary / ws, bs: v.bytesSecondary / ws,
        fin: v.finrst / Math.max(1, n),
        beacon: v.isDst ? { r: 0, period: 0, cv: 1, disp: 0, peers: 0 } : this.beaconOf(v),
        dns: v.dnsN / Math.max(1, n), qnames: v.qnames, quniq: v.qset.size / Math.max(1, v.dnsN),
        txt: v.dnsTxt / Math.max(1, v.dnsN), nx: v.dnsNx / Math.max(1, v.dnsN), any: v.dnsAny / Math.max(1, v.dnsN),
        tls: v.tlsN / Math.max(1, n), tlsFlows: v.tls,
        rar: v.tlsN > 0 ? (v.tlsRare / v.tlsN) * U.clamp(v.tlsN / 6, 0.3, 1) : 0,
      };
    }

    slowObs(v) {
      const a = SLOW_ALPHA;
      const e = v.e;
      const ws = 12;
      const flows = v.slowFlows;
      const peerMap = new Map();
      const ports = new Set();
      const protoMap = { t6: 0, u17: 0, i1: 0, g47: 0, o: 0 };
      const qnames = [];
      const qset = new Set();
      const tlsFlows = [];
      let newPeer = 0, n = 0, pk = 0, by = 0, du = 0;
      for (let i = 0; i < flows.length; i++) {
        const f = flows[i];
        n++;
        pk += f.pkts; by += f.bytes; du += f.dur;
        if (f.proto === 6) protoMap.t6++;
        else if (f.proto === 17) protoMap.u17++;
        else if (f.proto === 1) protoMap.i1++;
        else if (f.proto === 47) protoMap.g47++;
        else protoMap.o++;
        peerMap.set(f.dip, (peerMap.get(f.dip) || 0) + 1);
        if (ports.size < 3072) ports.add(f.dport);
        if (f.dns && qnames.length < 260) { qnames.push(f.dns.q); qset.add(f.dns.q); }
        if (f.tls && tlsFlows.length < 260) tlsFlows.push(f);
      }
      return {
        n: Math.max(1, n), span: SLOW_MS,
        fr: e.fr, pr: e.pr, br: e.br,
        peers: peerMap.size, peerMap, ports,
        newPeer: e.np,
        syn: e.syn, resp: e.resp, protoMap, udp: e.udp, tcp: 1 - e.udp,
        sm: e.sm,
        pk: e.pk, by: e.by, du: e.du,
        bp: e.bp, bs: e.bs,
        fin: 0,
        beacon: this.beaconOf(v),
        dns: e.dns, qnames, quniq: qset.size / Math.max(1, e.dns * ws),
        txt: e.txt, nx: e.nx, any: e.any,
        tls: e.tls, tlsFlows,
        rar: e.rar,
        _ws: ws,
      };
    }

    updateSlowEwma(v) {
      const a = SLOW_ALPHA;
      const ws = WINDOW_MS / 1000;
      const e = v.e;
      const n = Math.max(1, v.primFlows);
      const p = (k, val) => (e[k] = e[k] * (1 - a) + val * a);
      if (v.primFlows > 0 || v.revFlows > 0) {
        p("fr", v.primFlows / ws);
        p("pr", v.pkts / ws);
        p("br", v.bytesPrimary / ws);
        p("bp", v.bytesPrimary / ws);
        p("bs", v.bytesSecondary / ws);
        p("syn", v.syn / n);
        p("resp", Math.min(4, v.revFlows / n));
        p("udp", v.protoC.u17 / n);
        p("sm", v.small / n);
        p("np", v.newPeerN / n);
        p("pk", v.fb.pkts);
        p("by", v.fb.bytes);
        p("du", v.fb.dur);
        p("dns", v.dnsN / n);
        p("txt", v.dnsN ? v.dnsTxt / v.dnsN : 0);
        p("nx", v.dnsN ? v.dnsNx / v.dnsN : 0);
        p("any", v.dnsN ? v.dnsAny / v.dnsN : 0);
        p("tls", v.tlsN / n);
        p("rar", v.tlsN ? (v.tlsRare / v.tlsN) * U.clamp(v.tlsN / 6, 0.3, 1) : 0);
        e.n = 1;
      } else if (e.n === 0) {
        e.fr = 0; e.pr = 0; e.br = 0; e.bp = 0; e.bs = 0;
      }
      v.totalFlowsEver += v.primFlows;
    }

    flush(now) {
      const out = [];
      this.evict(now);
      for (const v of this.views.values()) {
        this.prune(v.flows, now, WINDOW_MS);
        const active = v.primFlows > 0 || v.revFlows > 0;
        if (v.isSlow) {
          this.prune(v.slowFlows, now, SLOW_MS);
          this.updateSlowEwma(v);
          if (v.slowFlows.length >= 4) {
            const x = this.buildCommon(new Float32Array(D), v, now, SLOW_MS, this.slowObs(v));
            out.push({
              view: v, x, now, ipStr: SIM.inet(v.ip), kind: "slow",
              truth: domTruth(v.slowTruthC.size ? v.slowTruthC : v.truthC),
            });
          }
        }
        if (active) {
          const x = this.buildCommon(new Float32Array(D), v, now, WINDOW_MS, this.fastObs(v));
          out.push({
            view: v, x, now, ipStr: SIM.inet(v.ip), kind: "fast",
            truth: domTruth(v.truthC),
          });
        }
        v.reset();
      }
      return out;
    }
  }

  return { Extractor, NAMES, IDX, D, WINDOW_MS, SLOW_MS, isInternal };
})();
