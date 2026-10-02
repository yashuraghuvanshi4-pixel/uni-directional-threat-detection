const LEX = (() => {
  const CHARS = "abcdefghijklmnopqrstuvwxyz0123456789.-_";
  const IDX = new Map();
  for (let i = 0; i < CHARS.length; i++) IDX.set(CHARS[i], i);
  const N = CHARS.length;
  const EOT = N;
  const T = N + 1;
  const B32 = "abcdefghijklmnopqrstuvwxyz234567";
  const B32I = new Map();
  for (let i = 0; i < B32.length; i++) B32I.set(B32[i], i);

  const WORDS = ("www mail api cdn static assets login account accounts portal gateway edge node svc services data files img images video stream media download updates update repo git registry registry1 registry0 store shop pay secure vpn auth sso id identity oauth accounts2 billing help support status health ns1 ns2 mx smtp imap pop pop3 ftp ssh gitlab jenkins ci build deploy monitor metrics logs log sys admin intranet intranet1 extranet partner cdn1 cdn2 video1 video2 live chat mail2 mail3 search discover explore news blog docs documentation wiki confluence jira redmine grafana kibana prometheus backup db db1 sql oracle postgres redis cache queue kafka rabbit worker cron batch api1 api2 api3 app web web1 web2 mobile ios android desktop client agent push notify alert alerts notify1 sms mail4 smtp2 relay mx2 cloud storage bucket s3 blob drive test staging dev qa uat prod internal dmz guest kiosk pos terminal printer camera nvr dvr iot sensor serial modbus scada plc hmi rtu iec61850 bacnet").split(" ");

  const TLDS = ["com", "net", "org", "io", "co", "in", "co.in", "com.br", "de", "fr", "jp", "uk", "au", "ca", "ru", "cn", "us", "info", "biz", "dev", "app", "cloud", "io"];
  const SNI = ["www.google.com", "www.youtube.com", "api.github.com", "github.com", "www.microsoft.com", "login.microsoftonline.com", "www.amazonaws.com", "s3.amazonaws.com", "cdn.jsdelivr.net", "www.cloudflare.com", "fonts.googleapis.com", "www.wikipedia.org", "mail.google.com", "drive.google.com", "www.linkedin.com", "zoom.us", "slack.com", "www.dropbox.com", "registry.npmjs.org", "pypi.org", "deb.debian.org", "archive.ubuntu.com", "security.apple.com", "update.googleapis.com", "www.nytimes.com", "accounts.google.com", "clientservices.googleapis.com", "graph.facebook.com", "ocsp.digicert.com", "www.android.com"];
  const SNI_BAD = ["d7fq2mz9k3.net", "a1b2c3d4e5f6.top", "cdn-update-check.pw", "0x9f8e7d6c5b.xyz", "telemetry-collect.click", "g1h2i3j4k5l6.ru", "sync-api7.icu", "windowsupdate2.xyz", "r1n2d0m3i4n5.io", "q7w9e1r2t3y4.cf"];

  const JA3_BENIGN = ["e7d705a3286e19ea42f587b344ee6865", "579ccef312d18482fc42e2b822ca2430", "b32309a26951912be7dba376398abc3b", "cd08e31494f9531f560d64c695473da9", "a0e9f5c2b8b0d0f1c2d3e4a5b6c7d8e", "5b3d1e0c9a8f7e6d5c4b3a2918273645", "1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d", "0f1e2d3c4b5a69788796a5b4c3d2e1f0", "6d0e0b1c9a8f7e6d5c4b3a2918273645", "f3e2d1c0b9a89786958473625140f3e", "2c1b0a9988776655443322110ffeedd", "99887766554433221100ffeeddccbbaa", "aabbccddeeff00112233445566778899", "1234567890abcdef1234567890abcdef", "fedcba0987654321fedcba0987654321", "0a1b2c3d4e5f60718293a4b5c6d7e8f9", "9988776655443322112233445566aabb", "1122334455667788990011223344ffee", "cafebabe1234567890abcdefabcdef", "0badc0de1234567890abcdefabcdef0", "feedfacecafebeef0123456789abcdef", "13579bdf02468ace0f1e2d3c4b5a6978"];
  const JA3_SUSPECT = ["4b1d4a0c9e8f7a6b5c4d3e2f1a0b9c8d", "e2f1a0b9c8d7e6f5a4b3c2d1e0f9a8b7c", "c0ffee112233445566778899aabbccdd", "badc0de112233445566778899aabbccdd", "deadbeef00112233445566778899aabb", "f00dfeed112233445566778899aabbcc", "0badf00d112233445566778899aabbcc", "malwareda1b2c3d4e5f60718293a4b5c6d", "c0deba5e112233445566778899aabbcc", "1337c0de112233445566778899aabbcc", "beefface112233445566778899aabbcc", "d15ea5e112233445566778899aabbcc"];
  const JA4_SUSPECT = ["t13d1516h2_8daaf6152771_b0da82dd1658", "t13d1516h2_8daaf6152771_4a3b2c1d0e9f", "q13d1516h2_8daaf6152771_9f8e7d6c5b4a"];
  const JA4_BENIGN = ["t13d1516h2_8daaf6152771_2b3c4d5e6f70", "t13d1516h2_8daaf6152771_8e9d0c1b2a39", "t13d1516h2_8daaf6152771_c1d2e3f40516", "q13d1516h2_8daaf6152771_112233445566"];

  const PORTS_WEB = [443, 443, 443, 443, 80, 8443, 8080];
  const EXTS = ["co.in", "com", "net", "org", "io", "in", "de", "com.br"];

  function buildBigramModel(samples) {
    const counts = new Float64Array(T * T);
    for (const s of samples) {
      const str = s.toLowerCase();
      let prev = -1;
      for (let i = 0; i < str.length; i++) {
        const c = IDX.get(str[i]);
        if (c === undefined) continue;
        if (prev >= 0) counts[prev * T + c]++;
        prev = c;
      }
      if (prev >= 0) counts[prev * T + EOT]++;
    }
    const total = counts.reduce((a, b) => a + b, 0);
    const logp = new Float64Array(T * T);
    for (let i = 0; i < counts.length; i++) {
      logp[i] = Math.log((counts[i] + 0.3) / (total + 0.3 * counts.length));
    }
    return { logp, unigram: null, total };
  }

  function benignCorpus() {
    const rng = new U.Rng(97531);
    const out = [];
    for (let i = 0; i < 4000; i++) {
      const n = rng.irange(1, 3);
      let q = "";
      for (let j = 0; j < n; j++) {
        if (rng.chance(0.55)) q += rng.pick(WORDS);
        else q += rng.int(10) + rng.int(10) + rng.int(10);
        q += ".";
      }
      q += rng.pick(TLDS);
      out.push(q);
    }
    return out;
  }

  let MODEL = null;
  function model() {
    if (!MODEL) MODEL = buildBigramModel(benignCorpus());
    return MODEL;
  }

  function score(qname) {
    const m = model();
    const str = String(qname).toLowerCase();
    let prev = -1, sum = 0, n = 0;
    for (let i = 0; i < str.length; i++) {
      const c = IDX.get(str[i]);
      if (c === undefined) continue;
      if (prev >= 0) {
        sum += m.logp[prev * N + c];
        n++;
      }
      prev = c;
    }
    return n ? sum / n : 0;
  }

  function dgaName(rng) {
    const labels = rng.irange(1, 3);
    let q = "";
    for (let i = 0; i < labels; i++) {
      const len = rng.irange(7, 15);
      let s = "";
      for (let j = 0; j < len; j++) s += CHARS[rng.int(CHARS.length)];
      q += s + ".";
    }
    return q + rng.pick(EXTS);
  }

  function tunnelName(rng) {
    const labels = rng.irange(3, 4);
    let q = "";
    for (let i = 0; i < labels; i++) {
      const len = rng.irange(48, 60);
      let s = "";
      for (let j = 0; j < len; j++) s += B32[rng.int(B32.length)];
      q += s + ".";
    }
    return q + "tun" + rng.int(1000) + "." + rng.pick(EXTS);
  }

  function beaconSni(rng) {
    return rng.chance(0.55) ? rng.pick(SNI_BAD) : rng.pick(SNI);
  }

  return {
    model, score, dgaName, tunnelName, beaconSni, WORDS, TLDS, SNI, SNI_BAD,
    JA3_BENIGN, JA3_SUSPECT, JA4_BENIGN, JA4_SUSPECT, PORTS_WEB, EXTS, B32, CHARS, IDX, N,
  };
})();
