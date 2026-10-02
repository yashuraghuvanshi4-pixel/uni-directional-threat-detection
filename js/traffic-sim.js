const CLASSES = [
  { id: "benign", label: "Benign", color: "#3ddc97", short: "BEN" },
  { id: "ddos_volumetric", label: "DDoS / Volumetric", color: "#ff4d6d", short: "DDoS" },
  { id: "c2_beaconing", label: "C2 Beaconing", color: "#ff9f43", short: "C2" },
  { id: "dga_dns", label: "DGA / DNS Tunnel", color: "#c56cf0", short: "DGA" },
  { id: "tls_malware", label: "Encrypted Malware", color: "#4dabf7", short: "TLS" },
  { id: "recon_scan", label: "Recon / Port Scan", color: "#ffd43b", short: "SCAN" },
  { id: "exfiltration", label: "Data Exfiltration", color: "#20c997", short: "EXFIL" },
];

const SIM = (() => {
  const ipCache = new Map();
  const inet = (n) => {
    let s = ipCache.get(n);
    if (s === undefined) {
      s = (n >>> 24) + "." + ((n >>> 16) & 255) + "." + ((n >>> 8) & 255) + "." + (n & 255);
      ipCache.set(n, s);
    }
    return s;
  };

  const INT_A = 0x0a140000, INT_N = 4096;
  const EXT_POOL_N = 900;
  const SPOOF_RANGES = [0x2d000000, 0x67000000, 0xb9000000, 0x5c000000, 0xcb000000, 0x8e000000];

  class Flow {
    constructor() {
      this.ts = 0; this.id = 0; this.sip = 0; this.dip = 0; this.sport = 0; this.dport = 0;
      this.proto = 6; this.flags = 0x10; this.pkts = 1; this.bytes = 100; this.dur = 100;
      this.dir = 0; this.phase = 0; this.ifIn = 1; this.ifOut = 0;
      this.dns = null; this.tls = null; this.pk = null; this.truth = "benign";
    }
  }

  class TrafficSim {
    constructor(seed = 20260101) {
      this.rng = new U.Rng(seed);
      this.t = 0;
      this.seq = 0;
      this.pool = new U.Rng(seed ^ 0x9e3779b9);
      this.extHosts = Array.from({ length: EXT_POOL_N }, () => 0x40000000 + this.pool.int(0x20000000));
      this.intensity = { ddos: 1, benign: 1 };
      this.resolvers = [inet(0x0a140005), inet(0x0a140006)];
      this.resolverN = [INT_A + 5, INT_A + 6];
      this.victims = { web: INT_A + 40, dns: INT_A + 41, db: INT_A + 42, mail: INT_A + 43 };
      this.servers = { web: INT_A + 40, mail: INT_A + 43, db: INT_A + 42, files: INT_A + 44 };
      this.hosts = [];
      this.attackers = [];
      this.floodState = null;
      this.enabled = {
        syn_flood: true, udp_amplification: true, c2_beacon: true, dga: true,
        dns_tunnel: true, ja3_malware: true, quic_bad: true, port_scan: true,
        host_scan: true, exfil: true,
      };
      this.counts = {};
      this.populate();
    }

    poolInt() {
      return this.pool.int(INT_N);
    }

    populate() {
      const rng = this.rng;
      const kinds = [
        ["web", 26], ["dns", 10], ["video", 8], ["mail", 4], ["update", 4],
        ["ssh", 3], ["ntp", 3], ["iot", 5], ["vpn", 4], ["web", 8],
      ];
      for (const [kind, n] of kinds) {
        for (let i = 0; i < n; i++) {
          const ip = INT_A + 20 + this.hosts.length;
          const h = this.makeHost(ip, kind, "benign");
          h.phase = rng.f() * 1000;
          this.hosts.push(h);
        }
      }
    }

    makeHost(ip, kind, truth) {
      const rng = this.rng;
      return {
        ip, ipStr: inet(ip), kind, truth,
        next: rng.range(0, 2),
        phase: 0,
        dstSet: this.k8Set(rng, 2, 12),
        dst: 0,
        dport: 443,
        n: 0,
        bytesSent: 0,
        period: 0,
        jitter: 0,
        portsPtr: 1,
        scanTargets: [],
        scanHostPtr: 0,
        beaconT: rng.range(1, 40),
        dnsSeen: new Set(),
        rate: 1,
        ja3: LEX.JA3_BENIGN[rng.int(LEX.JA3_BENIGN.length)],
        quic: false,
        alive: true,
      };
    }

    k8Set(rng, a, b) {
      const s = new Set();
      const n = rng.irange(a, b);
      for (let i = 0; i < n; i++) s.add(this.extHosts[rng.int(this.extHosts.length)]);
      return s;
    }

    newFlow(truth) {
      const f = new Flow();
      f.ts = this.t;
      f.id = ++this.seq;
      f.truth = truth;
      return f;
    }

    benignQuery(rng) {
      const n = rng.irange(0, 2);
      let q = "";
      for (let i = 0; i < n; i++) q += rng.pick(LEX.WORDS) + rng.int(1000) + ".";
      q += rng.pick(LEX.WORDS) + "." + rng.pick(LEX.TLDS);
      return q;
    }

    sizes(rng, base, jitterPct, n) {
      const out = new Array(n);
      for (let i = 0; i < n; i++) out[i] = Math.max(40, Math.round(base * (1 + rng.gauss(0, jitterPct))));
      return out;
    }

    step(dtMs) {
      const out = [];
      const rng = this.rng;
      this.t += dtMs;
      const dt = dtMs / 1000;

      for (const h of this.hosts) {
        if (!h.alive) continue;
        const lam = this.hostLam(h);
        h.next -= dt;
        let guard = 0;
        while (h.next <= 0 && guard < 400) {
          guard++;
          h.next += this.hostGap(h, lam);
          const n = this.hostBurst(h, lam);
          for (let i = 0; i < n; i++) this.emitHostFlow(h, out, rng);
        }
      }

      this.stepFlood(out, rng, dt);
      this.stepAttackers(out, rng, dt);

      this.counts.flows = out.length;
      return out;
    }

    hostLam(h) {
      switch (h.kind) {
        case "web": return h.rate * (h.rate ? 1 : 1);
        case "dns": return 0.4;
        case "video": return 0.25;
        case "mail": return 0.12;
        case "update": return 0.08;
        case "ssh": return 0.05;
        case "ntp": return 1.0;
        case "iot": return 0.6;
        case "vpn": return 0.15;
        default: return 1;
      }
    }

    hostGap(h, lam) {
      const rng = this.rng;
      if (h.kind === "ntp") return rng.range(0.6, 1.6);
      if (h.kind === "update") return rng.range(6, 14);
      if (h.kind === "web") {
        if (rng.chance(0.72)) return -Math.log(1 - rng.f()) / (lam * 2.2);
        return rng.range(3, 22);
      }
      if (h.kind === "dns") return rng.range(1.2, 9);
      if (h.kind === "video") return rng.range(3.5, 6.5);
      if (h.kind === "mail") return rng.range(5, 30);
      if (h.kind === "ssh") return rng.range(20, 90);
      if (h.kind === "iot") return rng.range(0.7, 6);
      if (h.kind === "vpn") return rng.range(4, 12);
      return rng.range(1, 5);
    }

    hostBurst(h, lam) {
      const rng = this.rng;
      if (h.kind === "web" && rng.chance(0.5)) return rng.irange(2, 9);
      return 1;
    }

    pickDst(h, rng) {
      const arr = h.dstSet;
      return arr.length ? arr[rng.int(arr.length)] : this.extHosts[rng.int(this.extHosts.length)];
    }

    emitHostFlow(h, out, rng) {
      const f = this.newFlow("benign");
      f.sip = h.ip;
      f.dport = h.dport;
      f.dur = rng.irange(40, 2400);
      f.phase = h.phase;
      switch (h.kind) {
        case "web": {
          f.dip = this.pickDst(h, rng);
          f.sport = rng.irange(33000, 65000);
          f.dport = rng.chance(0.94) ? 443 : 80;
          f.proto = 6;
          f.flags = 0x1b;
          f.pkts = rng.irange(4, 26);
          f.bytes = rng.irange(320, 42000);
          const sni = rng.pick(LEX.SNI);
          f.tls = { ja3: h.ja3, ver: 771, cipher: 4865, alpn: "h2", sni, cert: rng.irange(1100, 1400), self: false, res: false, quic: false, ja4: LEX.JA4_BENIGN[rng.int(LEX.JA4_BENIGN.length)] };
          f.pk = this.sizes(rng, 1200, 0.55, 10);
          h.phase++;
          out.push(f);
          if (rng.chance(0.6)) {
            const r = this.newFlow("benign");
            r.sip = f.dip; r.dip = f.sip; r.sport = f.dport; r.dport = f.sport;
            r.proto = 6; r.flags = 0x1b; r.dir = 1; r.dur = f.dur;
            r.pkts = rng.irange(3, 30); r.bytes = rng.irange(500, 90000);
            r.pk = this.sizes(rng, 1400, 0.6, 10);
            r.phase = h.phase;
            out.push(r);
          }
          break;
        }
        case "dns": {
          f.dip = this.resolverN[rng.int(this.resolverN.length)];
          f.sport = rng.irange(30000, 60000);
          f.dport = 53; f.proto = 17; f.flags = 0;
          f.dur = rng.irange(2, 60);
          f.pkts = 2; f.bytes = rng.irange(70, 180);
          const q = this.benignQuery(rng);
          f.dns = { q, qt: rng.chance(0.55) ? 1 : 28, qr: 1, rc: 0, an: rng.irange(1, 6) };
          out.push(f);
          if (rng.chance(0.5)) {
            const r = this.newFlow("benign");
            r.sip = f.dip; r.dip = f.sip; r.sport = 53; r.dport = f.sport;
            r.proto = 17; r.dir = 1; r.dur = f.dur; r.pkts = 2; r.bytes = rng.irange(90, 700);
            r.dns = { q, qt: 1, qr: 0, rc: 0, an: rng.irange(1, 6) };
            out.push(r);
          }
          break;
        }
        case "video": {
          f.dip = h.dst;
          f.sport = rng.irange(40000, 60000);
          f.dport = 443; f.proto = 17; f.flags = 0;
          f.dur = rng.irange(1200, 4000);
          f.pkts = rng.irange(40, 260);
          f.bytes = rng.irange(90000, 1400000);
          f.tls = { ja3: h.ja3, ver: 772, cipher: 0, alpn: "h3", sni: rng.pick(LEX.SNI), cert: 0, self: false, res: true, quic: true, ja4: LEX.JA4_BENIGN[rng.int(LEX.JA4_BENIGN.length)] };
          f.pk = this.sizes(rng, 1250, 0.12, 12);
          out.push(f);
          const r = this.newFlow("benign");
          r.sip = f.dip; r.dip = f.sip; r.sport = 443; r.dport = f.sport;
          r.proto = 17; r.dir = 1; r.dur = f.dur;
          r.pkts = rng.irange(30, 220); r.bytes = rng.irange(30000, 600000);
          r.pk = this.sizes(rng, 1200, 0.2, 12);
          out.push(r);
          break;
        }
        case "mail": {
          f.dip = INT_A + 43;
          f.sport = rng.irange(30000, 60000); f.dport = 25; f.proto = 6; f.flags = 0x1b;
          f.dur = rng.irange(300, 4000);
          f.pkts = rng.irange(10, 90); f.bytes = rng.irange(1200, 260000);
          f.pk = this.sizes(rng, 900, 0.7, 10);
          out.push(f);
          const r = this.newFlow("benign");
          r.sip = f.dip; r.dip = f.sip; r.sport = 25; r.dport = f.sport;
          r.proto = 6; r.flags = 0x1b; r.dir = 1; r.dur = f.dur;
          r.pkts = rng.irange(8, 80); r.bytes = rng.irange(900, 180000);
          out.push(r);
          break;
        }
        case "update": {
          f.dip = h.dst;
          f.sport = rng.irange(30000, 60000); f.dport = 443; f.proto = 6; f.flags = 0x1b;
          f.dur = rng.irange(3000, 12000);
          f.pkts = rng.irange(300, 2400);
          f.bytes = rng.irange(400000, 6000000);
          f.tls = { ja3: h.ja3, ver: 771, cipher: 4865, alpn: "http/1.1", sni: rng.pick(["deb.debian.org", "archive.ubuntu.com", "dl.google.com", "update.googleapis.com"]), cert: 1200, self: false, res: false, quic: false, ja4: LEX.JA4_BENIGN[rng.int(LEX.JA4_BENIGN.length)] };
          f.pk = this.sizes(rng, 1400, 0.3, 12);
          out.push(f);
          const r = this.newFlow("benign");
          r.sip = f.dip; r.dip = f.sip; r.sport = 443; r.dport = f.sport;
          r.proto = 6; r.flags = 0x1b; r.dir = 1; r.dur = f.dur;
          r.pkts = rng.irange(200, 1600); r.bytes = rng.irange(200000, 3000000);
          out.push(r);
          break;
        }
        case "ssh": {
          f.dip = INT_A + 45;
          f.sport = rng.irange(30000, 60000); f.dport = 22; f.proto = 6; f.flags = 0x1b;
          f.dur = rng.irange(200, 30000);
          f.pkts = rng.irange(3, 200); f.bytes = rng.irange(200, 90000);
          f.pk = this.sizes(rng, 300, 0.8, 8);
          out.push(f);
          if (rng.chance(0.55)) {
            const r = this.newFlow("benign");
            r.sip = f.dip; r.dip = f.sip; r.sport = 22; r.dport = f.sport;
            r.proto = 6; r.flags = 0x1b; r.dir = 1; r.dur = f.dur;
            r.pkts = rng.irange(3, 200); r.bytes = rng.irange(150, 80000);
            out.push(r);
          }
          break;
        }
        case "ntp": {
          f.dip = 0xcb0071a0 + this.rng.int(64);
          f.sport = rng.irange(30000, 60000); f.dport = 123; f.proto = 17; f.flags = 0;
          f.dur = rng.irange(10, 300); f.pkts = 2; f.bytes = rng.irange(72, 152);
          out.push(f);
          if (rng.chance(0.6)) {
            const r = this.newFlow("benign");
            r.sip = f.dip; r.dip = f.sip; r.sport = 123; r.dport = f.sport;
            r.proto = 17; r.dir = 1; r.dur = f.dur; r.pkts = 2; r.bytes = rng.irange(72, 152);
            out.push(r);
          }
          break;
        }
        case "iot": {
          f.dip = this.extHosts[h.n % this.extHosts.length];
          f.sport = rng.irange(30000, 60000); f.dport = rng.chance(0.5) ? 5000 : 34567;
          f.proto = 17; f.flags = 0;
          f.dur = rng.irange(30, 400);
          f.pkts = rng.irange(2, 9); f.bytes = rng.irange(120, 1400);
          f.pk = this.sizes(rng, 260, 0.3, 6);
          out.push(f);
          if (rng.chance(0.35)) {
            const r = this.newFlow("benign");
            r.sip = f.dip; r.dip = f.sip; r.sport = f.dport; r.dport = f.sport;
            r.proto = 17; r.dir = 1; r.dur = f.dur;
            r.pkts = rng.irange(2, 9); r.bytes = rng.irange(120, 1400);
            out.push(r);
          }
          break;
        }
        case "vpn": {
          f.dip = h.dst;
          f.sport = rng.irange(30000, 60000); f.dport = 51820; f.proto = 17; f.flags = 0;
          f.dur = rng.irange(200, 2500);
          f.pkts = rng.irange(20, 160); f.bytes = rng.irange(4000, 260000);
          f.tls = { ja3: h.ja3, ver: 771, cipher: 4865, alpn: "h2", sni: "vpn.corp.example", cert: 1180, self: true, res: true, quic: false, ja4: LEX.JA4_BENIGN[rng.int(LEX.JA4_BENIGN.length)] };
          f.pk = this.sizes(rng, 1300, 0.25, 12);
          out.push(f);
          const r = this.newFlow("benign");
          r.sip = f.dip; r.dip = f.sip; r.sport = 51820; r.dport = f.sport;
          r.proto = 17; r.dir = 1; r.dur = f.dur;
          r.pkts = rng.irange(18, 150); r.bytes = rng.irange(3500, 220000);
          r.pk = this.sizes(rng, 1250, 0.3, 12);
          out.push(r);
          break;
        }
      }
    }

    stepFlood(out, rng, dt) {
      this.floodState = this.floodState || {
        synNext: 0, udpNext: 0, synRate: 0, udpRate: 0,
      };
      const F = this.floodState;
      const target = this.intensity.ddos;
      F.synRate = target * 900;
      F.udpRate = target * 420;
      if (this.enabled.syn_flood && F.synRate > 0) {
        F.synNext -= dt;
        while (F.synNext <= 0) {
          F.synNext += 0.05;
          const n = Math.max(1, Math.round(F.synRate * 0.05));
          for (let i = 0; i < n; i++) {
            const f = this.newFlow("ddos_volumetric");
            const rr = SPOOF_RANGES[rng.int(SPOOF_RANGES.length)];
            f.sip = rr + rng.int(0x00ffffff);
            f.dip = this.victims.web;
            f.sport = rng.irange(1024, 65000);
            f.dport = rng.chance(0.86) ? 443 : 80;
            f.proto = 6; f.flags = 0x02;
            f.pkts = 1; f.bytes = rng.irange(40, 62);
            f.dur = 0;
            f.phase = 0;
            out.push(f);
          }
        }
      }
      if (this.enabled.udp_amplification && F.udpRate > 0) {
        F.udpNext -= dt;
        while (F.udpNext <= 0) {
          F.udpNext += 0.05;
          const n = Math.max(1, Math.round(F.udpRate * 0.05));
          for (let i = 0; i < n; i++) {
            const f = this.newFlow("ddos_volumetric");
            const rr = SPOOF_RANGES[rng.int(SPOOF_RANGES.length)];
            f.sip = rr + rng.int(0x00ffffff);
            f.dip = this.extHosts[rng.int(400)] ;
            f.sport = rng.irange(1024, 65000);
            f.dport = rng.chance(0.7) ? 53 : rng.chance(0.5) ? 123 : 1900;
            f.proto = 17; f.flags = 0;
            f.pkts = 1; f.bytes = rng.irange(48, 92);
            f.dur = 0;
            out.push(f);
          }
        }
      }
    }

    stepAttackers(out, rng, dt) {
      for (const a of this.attackers) {
        if (this.t < a.start) continue;
        if (this.t > a.end) {
          if (a.host) a.host.alive = false;
          a.done = true;
          continue;
        }
        const ramp = Math.min(1, (this.t - a.start) / 6);
        this[a.gen](a, out, rng, dt, ramp);
      }
      this.attackers = this.attackers.filter((a) => !a.done);
    }

    spoofIp(rng) {
      const rr = SPOOF_RANGES[rng.int(SPOOF_RANGES.length)];
      return rr + rng.int(0x00ffffff);
    }

    genBeacon(a, out, rng, dt, ramp) {
      const h = a.host;
      h.beaconT -= dt;
      if (h.beaconT > 0) return;
      h.beaconT = h.period * (1 + rng.gauss(0, h.jitter));
      const n = 1;
      for (let i = 0; i < n; i++) {
        const f = this.newFlow("c2_beaconing");
        f.sip = h.ip;
        f.dip = h.dst;
        f.sport = rng.irange(40000, 60000);
        f.dport = 443; f.proto = 6; f.flags = 0x1b;
        f.dur = rng.irange(120, 400);
        f.pkts = rng.irange(4, 7);
        f.bytes = rng.irange(880, 1180);
        f.tls = { ja3: h.ja3, ver: 771, cipher: rng.pick([4865, 4866, 49199]), alpn: "http/1.1", sni: h.sni, cert: 0, self: true, res: false, quic: false, ja4: LEX.JA4_BENIGN[rng.int(LEX.JA4_BENIGN.length)] };
        f.pk = this.sizes(rng, 1100, 0.035, 8);
        f.phase = h.phase;
        out.push(f);
        h.phase++;
        if (rng.chance(0.55)) {
          const r = this.newFlow("c2_beaconing");
          r.sip = f.dip; r.dip = f.sip; r.sport = 443; r.dport = f.sport;
          r.proto = 6; r.flags = 0x1b; r.dir = 1; r.dur = f.dur;
          r.pkts = rng.irange(3, 6); r.bytes = rng.irange(420, 700);
          r.pk = this.sizes(rng, 480, 0.06, 8);
          out.push(r);
        }
      }
    }

    genDga(a, out, rng, dt, ramp) {
      const h = a.host;
      const lam = 3.4 * ramp;
      a.acc = (a.acc || 0) + lam * dt;
      const n = Math.floor(a.acc);
      a.acc -= n;
      for (let i = 0; i < n; i++) {
        const f = this.newFlow("dga_dns");
        f.sip = h.ip;
        f.dip = this.resolverN[rng.int(this.resolverN.length)];
        f.sport = rng.irange(30000, 60000);
        f.dport = 53; f.proto = 17; f.flags = 0;
        f.dur = rng.irange(5, 90);
        f.pkts = 2; f.bytes = rng.irange(60, 140);
        const q = LEX.dgaName(rng);
        const nx = rng.chance(0.7);
        f.dns = { q, qt: rng.chance(0.8) ? 1 : 28, qr: 1, rc: nx ? 3 : 0, an: nx ? 0 : 1 };
        out.push(f);
        if (rng.chance(0.6)) {
          const r = this.newFlow("dga_dns");
          r.sip = f.dip; r.dip = f.sip; r.sport = 53; r.dport = f.sport;
          r.proto = 17; r.dir = 1; r.dur = f.dur; r.pkts = 2; r.bytes = rng.irange(80, 320);
          r.dns = { q, qt: 1, qr: 0, rc: nx ? 3 : 0, an: nx ? 0 : 1 };
          out.push(r);
        }
      }
    }

    genTunnel(a, out, rng, dt, ramp) {
      const h = a.host;
      const lam = 2.2 * ramp;
      a.acc = (a.acc || 0) + lam * dt;
      const n = Math.floor(a.acc);
      a.acc -= n;
      for (let i = 0; i < n; i++) {
        const f = this.newFlow("dga_dns");
        f.sip = h.ip;
        f.dip = this.resolverN[0];
        f.sport = rng.irange(30000, 60000);
        f.dport = 53; f.proto = 17; f.flags = 0;
        f.dur = rng.irange(8, 70);
        f.pkts = 2; f.bytes = rng.irange(280, 420);
        const q = h.sub + "." + LEX.tunnelName(rng);
        f.dns = { q, qt: 16, qr: 1, rc: 0, an: 1 };
        out.push(f);
        if (rng.chance(0.5)) {
          const r = this.newFlow("dga_dns");
          r.sip = f.dip; r.dip = f.sip; r.sport = 53; r.dport = f.sport;
          r.proto = 17; r.dir = 1; r.dur = f.dur; r.pkts = 2; r.bytes = rng.irange(120, 260);
          r.dns = { q, qt: 16, qr: 0, rc: 0, an: 1 };
          out.push(r);
        }
      }
    }

    genJa3(a, out, rng, dt, ramp) {
      const h = a.host;
      const lam = 2.0 * ramp;
      a.acc = (a.acc || 0) + lam * dt;
      const n = Math.floor(a.acc);
      a.acc -= n;
      for (let i = 0; i < n; i++) {
        const f = this.newFlow("tls_malware");
        f.sip = h.ip;
        f.dip = h.dst;
        f.sport = rng.irange(40000, 60000);
        f.dport = 443; f.proto = 6; f.flags = 0x1b;
        f.dur = rng.irange(200, 1200);
        f.pkts = rng.irange(5, 14);
        f.bytes = rng.irange(900, 2600);
        f.tls = {
          ja3: h.quic ? LEX.JA3_BENIGN[h.n % LEX.JA3_BENIGN.length] : h.ja3,
          ja4: h.quic ? LEX.JA4_SUSPECT[h.n % LEX.JA4_SUSPECT.length] : LEX.JA4_BENIGN[h.n % LEX.JA4_BENIGN.length],
          ver: 771, cipher: rng.pick([47, 49195, 52392, 4865]), alpn: "http/1.1",
          sni: LEX.beaconSni(rng), cert: 0, self: true, res: false, quic: h.quic,
        };
        f.pk = this.sizes(rng, 1150, 0.04, 9);
        f.phase = h.phase;
        out.push(f);
        h.phase++;
        if (rng.chance(0.45)) {
          const r = this.newFlow("tls_malware");
          r.sip = f.dip; r.dip = f.sip; r.sport = 443; r.dport = f.sport;
          r.proto = 6; r.flags = 0x1b; r.dir = 1; r.dur = f.dur;
          r.pkts = rng.irange(4, 10); r.bytes = rng.irange(500, 1800);
          r.pk = this.sizes(rng, 700, 0.08, 9);
          out.push(r);
        }
      }
    }

    genPortScan(a, out, rng, dt, ramp) {
      const h = a.host;
      const lam = 340 * ramp;
      a.acc = (a.acc || 0) + lam * dt;
      const n = Math.floor(a.acc);
      a.acc -= n;
      for (let i = 0; i < n; i++) {
        const f = this.newFlow("recon_scan");
        f.sip = h.ip;
        f.dip = h.scanTargets[h.scanHostPtr % h.scanTargets.length];
        f.sport = rng.irange(40000, 65000);
        f.dport = h.portsPtr;
        h.portsPtr++;
        if (h.portsPtr > 1024) h.portsPtr = 1;
        f.proto = 6; f.flags = 0x02;
        f.pkts = 1; f.bytes = rng.irange(38, 58);
        f.dur = 0;
        out.push(f);
        if (h.scanHostPtr % 64 === 63) h.scanHostPtr++;
      }
    }

    genHostScan(a, out, rng, dt, ramp) {
      const h = a.host;
      const lam = 190 * ramp;
      a.acc = (a.acc || 0) + lam * dt;
      const n = Math.floor(a.acc);
      a.acc -= n;
      const pset = [22, 23, 80, 135, 139, 443, 445, 3306, 3389, 5432, 8080, 9200];
      for (let i = 0; i < n; i++) {
        const f = this.newFlow("recon_scan");
        f.sip = h.ip;
        f.dip = h.netBase + h.scanHostPtr;
        f.sport = rng.irange(40000, 65000);
        f.dport = pset[rng.int(pset.length)];
        f.proto = 6; f.flags = 0x02;
        f.pkts = 1; f.bytes = rng.irange(38, 58);
        f.dur = 0;
        out.push(f);
        h.scanHostPtr++;
        if (h.scanHostPtr > 254) h.scanHostPtr = 1;
      }
    }

    genExfil(a, out, rng, dt, ramp) {
      const h = a.host;
      const bps = 5.2e6 * ramp;
      a.acc = (a.acc || 0) + bps * dt;
      const chunk = 240000;
      const n = Math.floor(a.acc / chunk);
      a.acc -= n * chunk;
      for (let i = 0; i < n; i++) {
        const f = this.newFlow("exfiltration");
        f.sip = h.ip;
        f.dip = h.dst;
        f.sport = rng.irange(40000, 60000);
        f.dport = 443; f.proto = 6; f.flags = 0x1b;
        f.dur = rng.irange(4000, 18000);
        f.pkts = rng.irange(160, 300);
        f.bytes = chunk + rng.irange(-2000, 2000);
        f.tls = { ja3: h.ja3, ver: 771, cipher: 4865, alpn: "h2", sni: h.sni, cert: 1150, self: false, res: true, quic: false, ja4: LEX.JA4_BENIGN[rng.int(LEX.JA4_BENIGN.length)] };
        f.pk = this.sizes(rng, 1420, 0.02, 12);
        f.phase = h.phase;
        out.push(f);
        h.phase++;
        if (rng.chance(0.22)) {
          const r = this.newFlow("exfiltration");
          r.sip = f.dip; r.dip = f.sip; r.sport = 443; r.dport = f.sport;
          r.proto = 6; r.flags = 0x1b; r.dir = 1; r.dur = f.dur;
          r.pkts = rng.irange(3, 12); r.bytes = rng.irange(1200, 9000);
          out.push(r);
        }
      }
    }

    schedule(benignScale, intensity) {
      this.intensity = intensity;
      const rng = this.rng;
      for (const h of this.hosts) h.rate = 0.6 * benignScale;
      let ip = INT_A + 300;
      const mk = (kind, opts) => {
        const h = this.makeHost(ip++, kind, opts.truth);
        Object.assign(h, opts.h || {});
        if (opts.h && opts.h.sni === undefined) h.sni = LEX.beaconSni(rng);
        h.dst = opts.h && opts.h.dst !== undefined ? opts.h.dst : this.extHosts[rng.int(this.extHosts.length)];
        this.hosts.push(h);
        this.attackers.push({
          gen: opts.gen, host: h, start: this.t + (opts.delay || 0) * 1000,
          end: this.t + (opts.dur || 900) * 1000, done: false,
        });
        return h;
      };
      if (this.enabled.c2_beacon) {
        mk("beacon", { gen: "genBeacon", truth: "c2_beaconing", dur: 1500, h: { period: rng.irange(9, 55), jitter: 0.02, sni: rng.pick(LEX.SNI_BAD) } });
        mk("beacon", { gen: "genBeacon", truth: "c2_beaconing", dur: 1500, h: { period: rng.irange(14, 60), jitter: 0.035 } });
        mk("beacon", { gen: "genBeacon", truth: "c2_beaconing", dur: 1500, h: { period: rng.irange(8, 40), jitter: 0.012 } });
      }
      if (this.enabled.dga) {
        mk("dga", { gen: "genDga", truth: "dga_dns", dur: 1500 });
        mk("dga", { gen: "genDga", truth: "dga_dns", dur: 1500 });
      }
      if (this.enabled.dns_tunnel) {
        mk("tunnel", { gen: "genTunnel", truth: "dga_dns", dur: 1500, h: { sub: "s" + rng.irange(1000, 9999) } });
      }
      if (this.enabled.ja3_malware) {
        mk("ja3", { gen: "genJa3", truth: "tls_malware", dur: 1500, h: { ja3: LEX.JA3_SUSPECT[rng.int(LEX.JA3_SUSPECT.length)], period: rng.irange(45, 95) } });
        mk("ja3", { gen: "genJa3", truth: "tls_malware", dur: 1500, h: { ja3: LEX.JA3_SUSPECT[rng.int(LEX.JA3_SUSPECT.length)] } });
      }
      if (this.enabled.quic_bad) {
        mk("quic", { gen: "genJa3", truth: "tls_malware", dur: 1500, h: { quic: true } });
      }
      if (this.enabled.port_scan) {
        const base = this.extHosts[rng.int(300)];
        mk("scan", { gen: "genPortScan", truth: "recon_scan", dur: 1500, h: { scanTargets: [base], portsPtr: 1 } });
        mk("scan", { gen: "genPortScan", truth: "recon_scan", dur: 1500, h: { scanTargets: [this.extHosts[rng.int(300)], this.extHosts[rng.int(300)]], portsPtr: 21 } });
      }
      if (this.enabled.host_scan) {
        const nb = 0x0a1f0000 + rng.int(64) * 256;
        mk("hscan", { gen: "genHostScan", truth: "recon_scan", dur: 1500, h: { netBase: nb, scanHostPtr: 1 } });
        mk("hscan", { gen: "genHostScan", truth: "recon_scan", dur: 1500, h: { netBase: 0x0a1e0000 + rng.int(64) * 256, scanHostPtr: 8 } });
      }
      if (this.enabled.exfil) {
        mk("exfil", { gen: "genExfil", truth: "exfiltration", dur: 1500, h: { sni: rng.pick(["storage-eu1.vendor-cloud.net", "s3.ap-south-1.amazonaws.com", "dropboxusercontent.com"]) } });
        mk("exfil", { gen: "genExfil", truth: "exfiltration", dur: 1500, h: { sni: "sync-api7.icu" } });
      }
    }

    setIntensity(k, v) {
      this.intensity = this.intensity || {};
      this.intensity[k] = v;
    }
  }

  return { TrafficSim, inet, INT_A, CLASSES };
})();
