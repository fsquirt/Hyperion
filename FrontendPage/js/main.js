// ════════════════════════════════════════════════════════════
// HYPERION — 站点主控
// 单流水线控制器 / 真实 SHA-256 PCR Extend / 代码行高亮联动
// ════════════════════════════════════════════════════════════
import { initNebula } from "./nebula.js";
import { PipelineScene } from "./demos.js";

/* ══════════ 纯 JS SHA-256（真实计算，页面内演示 PCR Extend 用） ══════════ */
const SHA256 = (() => {
  const K = new Uint32Array([
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
  ]);
  const rotr = (x, n) => (x >>> n) | (x << (32 - n));
  return function sha256(bytes) {
    const l = bytes.length;
    const bitLen = l * 8;
    const padded = new Uint8Array((((l + 8) >> 6) + 1) << 6);
    padded.set(bytes);
    padded[l] = 0x80;
    const dv = new DataView(padded.buffer);
    dv.setUint32(padded.length - 4, bitLen >>> 0);
    dv.setUint32(padded.length - 8, Math.floor(bitLen / 0x100000000));
    const H = new Uint32Array([
      0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
      0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    ]);
    const w = new Uint32Array(64);
    for (let off = 0; off < padded.length; off += 64) {
      for (let i = 0; i < 16; i++) w[i] = dv.getUint32(off + i * 4);
      for (let i = 16; i < 64; i++) {
        const s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >>> 3);
        const s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >>> 10);
        w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
      }
      let [a, b, c, d, e, f, g, h] = H;
      for (let i = 0; i < 64; i++) {
        const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
        const ch = (e & f) ^ (~e & g);
        const t1 = (h + S1 + ch + K[i] + w[i]) >>> 0;
        const S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
        const mj = (a & b) ^ (a & c) ^ (b & c);
        const t2 = (S0 + mj) >>> 0;
        h = g; g = f; f = e; e = (d + t1) >>> 0;
        d = c; c = b; b = a; a = (t1 + t2) >>> 0;
      }
      H[0] += a; H[1] += b; H[2] += c; H[3] += d;
      H[4] += e; H[5] += f; H[6] += g; H[7] += h;
    }
    const out = new Uint8Array(32);
    const odv = new DataView(out.buffer);
    for (let i = 0; i < 8; i++) odv.setUint32(i * 4, H[i]);
    return out;
  };
})();
const hex = (u8) => [...u8].map(b => b.toString(16).padStart(2, "0")).join("");
const strBytes = (s) => new TextEncoder().encode(s);

/* ══════════ PCR 状态机：新PCR = SHA256(旧PCR ‖ digest) ══════════ */
const pcrState = {};
const pcrEl = document.getElementById("hud-pcr");
function pcrInit(names) {
  pcrEl.innerHTML = "";
  for (const nm of names) {
    pcrState[nm] = new Uint8Array(32);
    const row = document.createElement("div");
    row.className = "pcr-row";
    row.dataset.pcr = nm;
    row.innerHTML = `<span class="pcr-name">${nm}</span><span class="pcr-val">${"0".repeat(64)}</span>`;
    pcrEl.appendChild(row);
  }
}
function pcrExtend(name, eventDesc) {
  const digest = SHA256(strBytes(eventDesc));               // 事件摘要
  const combined = new Uint8Array(64);
  combined.set(pcrState[name]);
  combined.set(digest, 32);
  pcrState[name] = SHA256(combined);                        // 真实 Extend
  const row = pcrEl.querySelector(`[data-pcr="${name}"]`);
  pcrEl.querySelectorAll(".pcr-row").forEach(r => r.classList.remove("hot"));
  if (row) {
    row.querySelector(".pcr-val").textContent = hex(pcrState[name]);
    row.classList.add("hot");
  }
  return { digest: hex(digest), value: hex(pcrState[name]) };
}
function pcrHotAll() {
  pcrEl.querySelectorAll(".pcr-row").forEach(r => r.classList.add("hot"));
}

/* ══════════ 语法高亮（C# / C 轻量分词） ══════════ */
const KEYWORDS = new Set(("public private static class struct void var new return if else foreach for while " +
  "using namespace bool byte uint ulong ushort int long string out ref in fixed unsafe switch case break " +
  "continue null true false async await Task readonly const enum interface override sealed try catch " +
  "finally throw is as get set default NULL sizeof").split(" "));
const esc = (s) => s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
function highlightLine(line) {
  const re = /(\/\/.*$)|("(?:[^"\\]|\\.)*")|(\$"(?:[^"\\]|\\.)*")|('(?:[^'\\]|\\.)*')|\b(0x[0-9A-Fa-f_]+|\d+)\b|\b([A-Za-z_][A-Za-z0-9_]*)\b/g;
  let out = "", last = 0, m;
  while ((m = re.exec(line)) !== null) {
    out += esc(line.slice(last, m.index));
    const tok = m[0];
    if (m[1]) out += `<span class="tok-c">${esc(tok)}</span>`;
    else if (m[2] || m[3] || m[4]) out += `<span class="tok-s">${esc(tok)}</span>`;
    else if (m[5]) out += `<span class="tok-n">${esc(tok)}</span>`;
    else if (m[6]) {
      if (KEYWORDS.has(tok)) out += `<span class="tok-k">${esc(tok)}</span>`;
      else if (/^_?[A-Z]/.test(tok) && tok.length > 1) out += `<span class="tok-t">${esc(tok)}</span>`;
      else out += esc(tok);
    }
    last = m.index + tok.length;
  }
  return out + esc(line.slice(last));
}

/* ══════════ 代码面板渲染 ══════════ */
function buildPane(sourceId) {
  const src = document.getElementById(sourceId);
  if (!src) return null;
  let text = src.textContent;
  text = text.replace(/^\n+/, "").replace(/\s+$/, "");
  const pane = document.createElement("div");
  pane.className = "code-pane";
  const lines = text.split("\n");
  const lineEls = lines.map((ln, i) => {
    const div = document.createElement("div");
    div.className = "code-line";
    div.innerHTML = `<span class="no">${i + 1}</span><span class="tx">${highlightLine(ln) || " "}</span>`;
    pane.appendChild(div);
    return { el: div, text: ln };
  });
  return { pane, lines: lineEls };
}

/* ══════════ 四个阶段（每阶段 6 步，共 24 步） ══════════ */
const PHASES = [
  { en: "MEASURED BOOT", tabStart: 0 },
  { en: "REMOTE ATTESTATION", tabStart: 2 },
  { en: "VBS · HVCI", tabStart: 3 },
  { en: "WHQL SIGNING GATE", tabStart: 4 },
];

/* ══════════ 24 步脚本（code 高亮锚点 = 真实源码子串） ══════════ */
const STEPS = [
  // ── 阶段 1 · 度量启动 ──
  {
    title: "初始化 PCR Banks（全零）",
    tab: 0, from: "var banks = new Dictionary", to: "banks[0x0004] = new Dictionary",
    log: ["info|[*] Replay: 初始化 SHA-256 bank · PCR0/4/7/12 = 00…00 (32 bytes)"],
    action: () => pcrInit(["PCR0", "PCR4", "PCR7", "PCR12"]),
  },
  {
    title: "SRTM 度量固件 → PCR0",
    tab: 0, from: "foreach (var evt in log.Events)", to: "if (evt.PcrIndex == 0xFFFFFFFF) continue;",
    action: () => {
      const r = pcrExtend("PCR0", "EV_S_CRTM_VERSION");
      return [`[EV] EV_S_CRTM_VERSION  digest=${r.digest.slice(0, 16)}…`,
              `ok|    PCR0 ← SHA256(PCR0 ‖ digest) = ${r.value.slice(0, 32)}…`];
    },
  },
  {
    title: "SecureBoot 变量 → PCR7",
    tab: 1, from: "var secureBootEvent = log.Events.FirstOrDefault", to: "bool enabled = varData?.VariableData?.Length",
    action: () => {
      const a = pcrExtend("PCR7", "EFI_VARIABLE_DRIVER_CONFIG: SecureBoot = 0x01");
      const b = pcrExtend("PCR7", "EFI_VARIABLE_DRIVER_CONFIG: dbx (forbidden db)");
      return [`[EV] SecureBoot=0x01  digest=${a.digest.slice(0, 16)}…`,
              `[EV] dbx measured     digest=${b.digest.slice(0, 16)}…`,
              `ok|    PCR7 = ${b.value.slice(0, 32)}…`];
    },
  },
  {
    title: "bootmgfw → winload → PCR4",
    tab: 0, from: "foreach (var digest in evt.Digests)", to: "bank[evt.PcrIndex] = Extend(digest.AlgorithmId",
    action: () => {
      const a = pcrExtend("PCR4", "EV_EFI_BOOT_SERVICES_APPLICATION: bootmgfw.efi");
      const b = pcrExtend("PCR4", "EV_EFI_BOOT_SERVICES_APPLICATION: winload.efi");
      return [`[EV] bootmgfw.efi  digest=${a.digest.slice(0, 16)}…`,
              `[EV] winload.efi   digest=${b.digest.slice(0, 16)}…`,
              `ok|    PCR4 = ${b.value.slice(0, 32)}…`];
    },
  },
  {
    title: "WBCL 内核度量 → PCR12",
    tab: 0, from: "private static byte[] Extend", to: "return hash.ComputeHash(combined);",
    action: () => {
      const r = pcrExtend("PCR12", "WBCL: ntoskrnl.exe + ELAM boot driver list");
      return [`[EV] WBCL kernel measurement  digest=${r.digest.slice(0, 16)}…`,
              `ok|    PCR12 = ${r.value.slice(0, 32)}…`];
    },
  },
  {
    title: "重放值 vs TPM 硬件值比对",
    tab: 0, from: "return banks;", to: "return banks;",
    log: ["ok|[✔] Replayed PCR bank == TPM PCR bank — 启动链完整",
          "ok|[✔] Measured Boot: TRUSTED"],
    action: () => { pcrHotAll(); },
  },

  // ── 阶段 2 · 远程证明 ──
  {
    title: "POST /request_nonce · 服务端下发 nonce",
    tab: 2, from: 'Console.WriteLine("[*] PCRVerify: POST /request_nonce...");', to: "byte[] nonce = Convert.FromBase64String",
    log: ["info|[*] PCRVerify: POST /request_nonce...",
          "    quote_sid : 8f21c7d3-a4…",
          "    nonce     : 7f3a61c2 9d04e8b1 … (32 bytes)"],
  },
  {
    title: "读取 WBCL 度量日志（TBS API）",
    tab: 2, from: "// ── Step 2", to: 'Console.WriteLine($"    WBCL: {wbcl.Length} bytes");',
    log: ["info|[*] PCRVerify: 读取 WBCL...",
          "    WBCL: 65 8321 bytes · SIPA events parsed"],
  },
  {
    title: "TPM2_Quote · 硬件 RSASSA-SHA256 签名",
    tab: 2, from: "Attest quoted = tpm.Quote(", to: "signature: out ISignatureUnion signature);",
    log: ["info|[*] PCRVerify: TPM2_Quote (TPM 硬件)...",
          "    pcrSelect : SHA256 bank, PCR 0-14",
          "    scheme    : RSASSA-SHA256 (AK 私钥签名)"],
  },
  {
    title: "上送 /verify_quote · attest + sig + wbcl",
    tab: 2, from: 'Console.WriteLine("[*] PCRVerify: POST /verify_quote...");', to: "wbcl = Convert.ToBase64String(wbcl),",
    log: ["info|[*] PCRVerify: POST /verify_quote...",
          "    attest : 145 bytes · sig : 256 bytes · wbcl : 65 KB"],
  },
  {
    title: "服务端四步裁决",
    tab: 2, from: "bool sigValid = qBody.TryGetProperty", to: "bool pcrMatch = qBody.TryGetProperty",
    log: ["ok|    ① AK 签名  : ✔ 有效",
          "ok|    ② TPM magic: ✔ 0xFF544347",
          "ok|    ③ nonce    : ✔ 一致",
          "ok|    ④ PCR重放  : ✔ 一致"],
  },
  {
    title: "会话通过 · 硬件级信任建立",
    tab: 2, from: '① AK 签名', to: "④ PCR重放",
    log: ["ok|[✔] Remote Attestation PASSED — 客户端进入受信池"],
  },

  // ── 阶段 3 · VBS / HVCI ──
  {
    title: "WbclParser.ParseAll · SIPA 事件",
    tab: 3, from: "var wbclEvents = WbclParser.ParseAll(log);", to: "bool hvciDetected = false;",
    log: ["info|[*] WbclParser: 1 042 SIPA events · PCR11-14"],
  },
  {
    title: "证据链 1 · HypervisorLaunchType",
    tab: 3, from: "// ── Evidence 1", to: "hvciDetected = true;",
    log: ["ok|Chain 1: HypervisorLaunchType=1 (Hyper-V launched, VT-x occupied) [0x00080001, PCR12]"],
  },
  {
    title: "证据链 2 · vbsFlags 位解析",
    tab: 3, from: "// ── Evidence 2", to: 'if (hvciEnabled) flagStrs.Add("HVCI=ON");',
    log: ["ok|Chain 2: VBS/HVCI flags=0x5 (VBS=ON, HVCI=ON) [0x000A0001, PCR12]"],
  },
  {
    title: "VTL1 裁决 · W^X 强制执行",
    tab: 3, from: "bool hvciEnabled = (vbsFlags & 0x04) != 0;", to: "bool hvciEnabled = (vbsFlags & 0x04) != 0;",
    log: ["err|[HVCI] unsigned page 0xFFFFA803`1C40000 → execute request",
          "err|[SLAT] EPT entry: RW- (NX) · execute DENIED"],
  },
  {
    title: "证据链 3 · PCR12 重放完整性",
    tab: 3, from: "// ── Evidence 3", to: 'evidences.Add("Chain 3: PCR12 events present',
    log: ["ok|Chain 3: PCR12 events present — replay match verified in PCR Banks"],
  },
  {
    title: "判定 · FeatureStatus.Enabled",
    tab: 3, from: "// ── Final verdict", to: 'feat.Evidence = "HVCI/VBS is active',
    log: ["ok|[✔] HVCI / VBS (Hypervisor Code Integrity): Enabled",
          "ok|    Hyper-V occupying VT-x, PCR12 integrity verified"],
  },

  // ── 阶段 4 · WHQL 门禁 ──
  {
    title: "双通道验证入口",
    tab: 4, from: "// 1. 先试 Authenticode", to: 'return (true, "目录签名有效 (Catalog Signed)");',
    log: ["info|[*] VerifyFileSignature: driver.sys"],
  },
  {
    title: "WinVerifyTrust · Authenticode",
    tab: 4, from: "Guid guidAction = new(", to: "return WinVerifyTrust(-1, &guidAction, &trustData);",
    log: ["info|[*] WinVerifyTrust(WTD_CHOICE_FILE, WTD_SAFER_FLAG)",
          "    hr = 0x00000000 (S_OK)"],
  },
  {
    title: "证书链上行至 Microsoft Root",
    tab: 4, from: "if (hr == 0)", to: 'return (true, "Authenticode 签名有效");',
    log: ["ok|    leaf   : Contoso Driver Co. (EV)",
          "ok|    issuer : MS Windows Hardware Compatibility Publisher",
          "ok|    root   : Microsoft Root Certificate Authority"],
  },
  {
    title: "Catalog · 计算文件哈希",
    tab: 4, from: "uint hashSize = 0;", to: "if (!CryptCATAdminCalcHashFromFileHandle(handle, ref hashSize, pHash, 0))",
    log: ["info|[*] CryptCATAdminCalcHashFromFileHandle",
          "    hash = 9E4B21A7 D3F0C8… (32 bytes)"],
  },
  {
    title: "在已注册目录中检索哈希",
    tab: 4, from: "IntPtr catInfo = CryptCATAdminEnumCatalogFromHash", to: "return true;",
    log: ["ok|    hit: Package_1234_for_KB5034... .cat",
          "ok|[✔] 目录签名有效 (Catalog Signed)"],
  },
  {
    title: "内核门禁 · 映像 SHA256 白名单",
    tab: 5, from: "status = ComputeFileSha256(fileHandle, actual);", to: "return STATUS_SUCCESS;",
    log: ["info|[KernelService] Verify: SHA256 OK for '\\Device\\HarddiskVolume3\\...\\UserService.exe' -> ALLOWED"],
  },
];

/* ══════════ 流水线控制器 ══════════ */
class PipelineController {
  constructor(section) {
    this.section = section;
    this.steps = STEPS;
    this.idx = -1;
    this.playing = false;
    this.timer = null;
    this.phase = -1;

    const canvas = document.getElementById("pipe-canvas");
    const labelWrap = document.getElementById("pipe-labels");
    this.scene = new PipelineScene(canvas, labelWrap);

    this.logEl = section.querySelector("[data-log]");
    this.titleEl = document.getElementById("hud-title");
    this.dotsEl = section.querySelector(".step-dots");
    this.playBtn = section.querySelector('[data-ctrl="play"]');
    this.phaseTabs = [...section.querySelectorAll(".phase-tab")];

    // 代码面板（6 个 tab，跨阶段复用；面板位于 demo-stage 之外）
    this.panes = [];
    const panesWrap = document.querySelector(".code-panes");
    this.tabs = [...document.querySelectorAll(".code-tab")];
    this.tabs.forEach((tab, ti) => {
      const built = buildPane(`code-${ti}`);
      if (!built) return;
      panesWrap.appendChild(built.pane);
      this.panes.push(built);
      tab.addEventListener("click", () => this.showTab(ti));
    });
    if (this.panes[0]) this.panes[0].pane.classList.add("active");

    // 步骤点（每阶段 6 个）
    this.dots = Array.from({ length: 6 }, (_, i) => {
      const d = document.createElement("span");
      d.className = "step-dot";
      d.addEventListener("click", () => this.go((this.phase * 6) + i, true));
      this.dotsEl.appendChild(d);
      return d;
    });

    section.querySelector('[data-ctrl="prev"]').addEventListener("click", () => this.go(this.idx - 1, true));
    section.querySelector('[data-ctrl="next"]').addEventListener("click", () => this.go(this.idx + 1, true));
    this.playBtn.addEventListener("click", () => this.playing ? this.stop() : this.play());
    this.phaseTabs.forEach((t, p) => t.addEventListener("click", () => this.phaseTo(p)));

    // 进入视口时自动开播（仅首次）
    let armed = true;
    new IntersectionObserver(([e]) => {
      if (e.isIntersecting && armed) { armed = false; this.go(0); this.play(); }
    }, { threshold: 0.35 }).observe(section.querySelector(".stage-frame"));
  }

  showTab(ti) {
    this.tabs.forEach((t, i) => t.classList.toggle("active", i === ti));
    this.panes.forEach((p, i) => p.pane.classList.toggle("active", i === ti));
  }

  phaseTo(p) {
    if (p < 0 || p >= 4) return;
    this.go(p * 6, true);
  }

  log(line) {
    const [cls, text] = line.includes("|") ? line.split(/\|(.+)/) : ["", line];
    const el = document.createElement("span");
    el.className = "ln " + cls;
    el.textContent = text ?? line;
    this.logEl.appendChild(el);
    this.logEl.scrollTop = this.logEl.scrollHeight;
  }

  highlight(step) {
    const ti = step.tab ?? 0;
    this.showTab(ti);
    const pane = this.panes[ti];
    if (!pane) return;
    this.panes.forEach(p => {
      p.pane.classList.remove("focusing");
      p.lines.forEach(l => l.el.classList.remove("hl"));
    });
    const fromIdx = pane.lines.findIndex(l => l.text.includes(step.from));
    if (fromIdx < 0) return;
    let toIdx = fromIdx;
    if (step.to) {
      for (let i = fromIdx; i < pane.lines.length; i++)
        if (pane.lines[i].text.includes(step.to)) { toIdx = i; break; }
    }
    pane.pane.classList.add("focusing");
    for (let i = fromIdx; i <= toIdx; i++) pane.lines[i].el.classList.add("hl");
    const target = pane.lines[Math.max(0, fromIdx - 3)].el;
    pane.pane.parentElement.scrollTo({ top: target.offsetTop - pane.pane.offsetTop, behavior: "smooth" });
  }

  go(i, manual = false) {
    if (i < 0 || i >= this.steps.length) { if (manual) return; this.stop(); return; }
    if (manual) this.stop();
    this.idx = i;
    const step = this.steps[i];
    const p = Math.floor(i / 6), li = i % 6;

    // 阶段切换：清日志、激活阶段 tab、切代码 tab
    if (p !== this.phase) {
      this.phase = p;
      this.phaseTabs.forEach((t, k) => t.classList.toggle("active", k === p));
      this.showTab(PHASES[p].tabStart);
      this.logEl.innerHTML = "";
    }

    this.dots.forEach((d, k) => {
      d.classList.toggle("active", k === li);
      d.classList.toggle("done", k < li);
    });

    this.titleEl.textContent =
      `// STEP ${String(i + 1).padStart(2, "0")}/24 · ${PHASES[p].en} — ${step.title}`;

    this.log(`// ${String(i + 1).padStart(2, "0")}/24 — ${step.title}`);
    (step.log || []).forEach(l => this.log(l));
    const extra = step.action ? step.action() : null;
    if (Array.isArray(extra)) extra.forEach(l => this.log(l));

    this.highlight(step);
    this.scene.step(i, manual);
  }

  play() {
    this.playing = true;
    this.playBtn.textContent = "■ 停止";
    this.playBtn.classList.add("playing");
    this.timer = setInterval(() => {
      if (this.idx + 1 >= this.steps.length) { this.stop(); return; }
      this.go(this.idx + 1);
    }, 1700);
  }

  stop() {
    this.playing = false;
    this.playBtn.textContent = "▶ 自动播放";
    this.playBtn.classList.remove("playing");
    if (this.timer) { clearInterval(this.timer); this.timer = null; }
  }
}

/* ══════════ 页面初始化 ══════════ */
initNebula(document.getElementById("nebula-canvas"));

const pipelineSection = document.querySelector(".demo-stage");
const controller = new PipelineController(pipelineSection);

// 导航哈希：#p1..#p4 → 跳转对应阶段
const goHash = () => {
  const m = location.hash.match(/^#p(\d)$/);
  if (!m) return;
  const p = +m[1] - 1;
  if (p >= 0 && p < 4) {
    controller.phaseTo(p);
    document.getElementById("pipeline").scrollIntoView({ behavior: "smooth" });
  }
};
addEventListener("hashchange", goHash);

// 滚动显现
const revealIO = new IntersectionObserver((entries) => {
  entries.forEach(e => { if (e.isIntersecting) { e.target.classList.add("on"); revealIO.unobserve(e.target); } });
}, { threshold: 0.12 });
document.querySelectorAll(".reveal").forEach(el => revealIO.observe(el));

// 登录按钮 → Server 控制台登录页
window.startLogin = () => {
  const btn = document.getElementById("btnLogin");
  const status = document.getElementById("loginStatus");
  btn.disabled = true;
  status.hidden = false;
  status.textContent = "正在跳转至 Server 控制台…";
  location.href = "https://hyperion.cloudyou.top/login";
};
