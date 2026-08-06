// ════════════════════════════════════════════════════════════
// HYPERION — 单一信任链流水线场景
// 四个防线阶段放进同一个 3D 世界，相机随阶段飞越四个区域：
//   ZONE A  MEASURED BOOT    度量启动（PCR Extend 链）
//   ZONE B  REMOTE ATTEST    远程证明（Verifyer ⇄ Server）
//   ZONE C  VBS · HVCI       Hypervisor 强制执行
//   ZONE D  WHQL GATE        驱动签名 + 内核 SHA256 门禁
// 直角几何 + 线框玻璃 + 拖影运动模糊
// ════════════════════════════════════════════════════════════
import * as THREE from "three";
import { CSS2DRenderer, CSS2DObject } from "three/addons/renderers/CSS2DRenderer.js";

const C = {
  violet: 0x3b82f6, magenta: 0xff2d78, cyan: 0x38e1ff,
  amber: 0xffb454, green: 0x3dffa0, dim: 0x48528f,
};

/* 四个区域的中心 X 坐标（几何布局）与相机实际中心（视觉内容中心） */
const ZONE = [-48, -16, 16, 48];
const CAM = [-55, -16, 16, 48];      // 区域 A 的引导链比 PCR 塔宽，相机中心取内容几何中心
const ZONE_DIST = [46, 38, 36, 36];   // 各区域相机距离

/* ──────────────────────────────────────────────
   基类：渲染循环 / 直角几何工具 / 拖影运动模糊
   ────────────────────────────────────────────── */
class BaseScene {
  constructor(canvas, labelWrap) {
    this.canvas = canvas;
    this.renderer = new THREE.WebGLRenderer({ canvas, antialias: true, alpha: true });
    this.renderer.setPixelRatio(Math.min(devicePixelRatio, 2));

    this.labelRenderer = new CSS2DRenderer({ element: labelWrap });
    labelWrap.style.position = "absolute";
    labelWrap.style.inset = "0";

    this.scene = new THREE.Scene();
    this.camera = new THREE.PerspectiveCamera(42, 1, 0.1, 500);
    this.clock = new THREE.Clock();
    this.movers = [];
    this.ghosts = [];
    this.pulses = [];
    this.beams = [];
    this.mouse = new THREE.Vector2();
    this.visible = false;

    // 深空尘埃背景
    const n = 260, p = new Float32Array(n * 3);
    for (let i = 0; i < n * 3; i++) p[i] = (Math.random() - 0.5) * 140;
    const dustGeo = new THREE.BufferGeometry();
    dustGeo.setAttribute("position", new THREE.BufferAttribute(p, 3));
    this.dust = new THREE.Points(dustGeo, new THREE.PointsMaterial({
      color: 0x7d93c9, size: 0.28, transparent: true, opacity: 0.55,
      blending: THREE.AdditiveBlending, depthWrite: false,
    }));
    this.scene.add(this.dust);

    canvas.parentElement.addEventListener("pointermove", (e) => {
      const r = canvas.getBoundingClientRect();
      this.mouse.set(((e.clientX - r.left) / r.width) * 2 - 1, -((e.clientY - r.top) / r.height) * 2 + 1);
    }, { passive: true });

    new IntersectionObserver(([e]) => { this.visible = e.isIntersecting; }, { threshold: 0.05 })
      .observe(canvas);

    this._loop = this._loop.bind(this);
    requestAnimationFrame(this._loop);
  }

  /* 直角平板/方块：半透明填充 + 发光描边 */
  slab(w, h, d, color, opacity = 0.1) {
    const g = new THREE.Group();
    const geo = new THREE.BoxGeometry(w, h, d);
    const fill = new THREE.Mesh(geo, new THREE.MeshBasicMaterial({
      color, transparent: true, opacity, depthWrite: false,
    }));
    const edge = new THREE.LineSegments(
      new THREE.EdgesGeometry(geo),
      new THREE.LineBasicMaterial({ color, transparent: true, opacity: 0.85 })
    );
    g.add(fill, edge);
    g.userData = { fill, edge, baseColor: color, baseOpacity: opacity };
    this.scene.add(g);
    return g;
  }

  /* 激活/熄灭一个 slab */
  lit(g, on, color) {
    const { fill, edge, baseColor, baseOpacity } = g.userData;
    const c = color !== undefined ? color : baseColor;
    fill.material.color.setHex(on ? c : baseColor);
    edge.material.color.setHex(on ? c : baseColor);
    fill.material.opacity = on ? 0.3 : baseOpacity;
    edge.material.opacity = on ? 1 : 0.4;
    if (on) this.pulse(g);
  }

  dim(g) {
    g.userData.fill.material.opacity = 0.05;
    g.userData.edge.material.opacity = 0.22;
  }

  /* CSS2D 标签 */
  lbl(text, cls, pos, parent) {
    const div = document.createElement("div");
    div.className = "lbl " + (cls || "");
    div.innerHTML = text;
    const o = new CSS2DObject(div);
    o.position.copy(pos);
    (parent || this.scene).add(o);
    return o;
  }

  /* 光束（两点连线，自动淡出可选） */
  beam(a, b, color, { persist = false, width = 1 } = {}) {
    const geo = new THREE.BufferGeometry().setFromPoints([a.clone(), b.clone()]);
    const mat = new THREE.LineBasicMaterial({
      color, transparent: true, opacity: 1, blending: THREE.AdditiveBlending, linewidth: width,
    });
    const line = new THREE.Line(geo, mat);
    line.userData.persist = persist;
    line.userData.life = 1;
    this.scene.add(line);
    this.beams.push(line);
    return line;
  }

  /* 飞行体：沿路径插值移动，逐帧留下渐隐残影 = 运动模糊 */
  fly(size, color, path, dur, onDone) {
    const geo = new THREE.BoxGeometry(size, size, size);
    const mesh = new THREE.Mesh(geo, new THREE.MeshBasicMaterial({
      color, transparent: true, opacity: 0.95, blending: THREE.AdditiveBlending, depthWrite: false,
    }));
    mesh.position.copy(path[0]);
    this.scene.add(mesh);
    this.movers.push({ mesh, path, t: 0, dur, onDone });
    return mesh;
  }

  pulse(obj) { this.pulses.push({ obj, t: 0 }); }

  clearFx() {
    for (const m of this.movers) this.scene.remove(m.mesh);
    this.movers.length = 0;
    for (let i = this.beams.length - 1; i >= 0; i--) {
      if (this.beams[i].userData.static) continue;   // 保留场景固定连线
      this.scene.remove(this.beams[i]);
      this.beams.splice(i, 1);
    }
  }

  _resize() {
    const w = this.canvas.clientWidth, h = this.canvas.clientHeight;
    if (w === 0 || h === 0) return;
    const pr = this.renderer.getPixelRatio();
    if (this.canvas.width !== Math.floor(w * pr) || this.canvas.height !== Math.floor(h * pr)) {
      this.renderer.setSize(w, h, false);
      this.labelRenderer.setSize(w, h);
      this.camera.aspect = w / h;
      this.camera.updateProjectionMatrix();
    }
  }

  _loop() {
    requestAnimationFrame(this._loop);
    if (!this.visible) return;
    this._resize();
    const dt = Math.min(this.clock.getDelta(), 0.05);
    const t = this.clock.elapsedTime;

    // 飞行体 + 残影拖尾
    for (let i = this.movers.length - 1; i >= 0; i--) {
      const m = this.movers[i];
      m.t += dt / m.dur;
      const k = Math.min(m.t, 1);
      const seg = k * (m.path.length - 1);
      const idx = Math.min(seg | 0, m.path.length - 2);
      m.mesh.position.lerpVectors(m.path[idx], m.path[idx + 1], seg - idx);
      m.mesh.rotation.x += dt * 3;
      m.mesh.rotation.y += dt * 4;

      const ghost = new THREE.Mesh(m.mesh.geometry, m.mesh.material.clone());
      ghost.position.copy(m.mesh.position);
      ghost.rotation.copy(m.mesh.rotation);
      ghost.material.opacity = 0.35;
      this.scene.add(ghost);
      this.ghosts.push(ghost);

      if (k >= 1) {
        this.scene.remove(m.mesh);
        this.movers.splice(i, 1);
        if (m.onDone) m.onDone();
      }
    }
    for (let i = this.ghosts.length - 1; i >= 0; i--) {
      const g = this.ghosts[i];
      g.material.opacity -= dt * 1.6;
      g.scale.multiplyScalar(1 - dt * 0.8);
      if (g.material.opacity <= 0) {
        this.scene.remove(g);
        g.material.dispose();
        this.ghosts.splice(i, 1);
      }
    }

    // 脉冲
    for (let i = this.pulses.length - 1; i >= 0; i--) {
      const p = this.pulses[i];
      p.t += dt * 2.2;
      const s = 1 + Math.sin(Math.min(p.t, 1) * Math.PI) * 0.08;
      p.obj.scale.setScalar(s);
      if (p.t >= 1) { p.obj.scale.setScalar(1); this.pulses.splice(i, 1); }
    }

    // 光束衰减
    for (let i = this.beams.length - 1; i >= 0; i--) {
      const b = this.beams[i];
      if (!b.userData.persist) {
        b.userData.life -= dt * 0.7;
        b.material.opacity = Math.max(0, b.userData.life);
        if (b.userData.life <= 0) { this.scene.remove(b); this.beams.splice(i, 1); }
      } else {
        b.material.opacity = 0.55 + Math.sin(t * 4) * 0.3;
      }
    }

    this.dust.rotation.y = t * 0.01;
    this.updateScene(dt, t);

    // 相机：飞向当前区域中心 + 漂移 + 鼠标视差
    const cam = this.camDrift(t);
    cam.x += this.mouse.x * 2.2;
    cam.y += this.mouse.y * 1.2;
    this.camera.position.lerp(cam, 0.055);
    this.camera.lookAt(this.lookAt || new THREE.Vector3(0, 0, 0));

    this.renderer.render(this.scene, this.camera);
    this.labelRenderer.render(this.scene, this.camera);
  }

  updateScene() {}
  camDrift(t) { return new THREE.Vector3(Math.sin(t * 0.1) * 3, 6, 34); }
  step() {}
}

/* ══════════════════════════════════════════════
   信任链流水线：四区域合体世界
   ══════════════════════════════════════════════ */
export class PipelineScene extends BaseScene {
  constructor(canvas, labelWrap) {
    super(canvas, labelWrap);
    this.zoneIdx = 0;
    this.lookAt = new THREE.Vector3(CAM[0], 1.5, 0);

    // 贯通全世界的网格地面
    const grid = new THREE.GridHelper(220, 54, 0x2e3f6e, 0x10142a);
    grid.position.y = -5.6;
    this.scene.add(grid);

    // 区域铭牌
    ["01 MEASURED BOOT", "02 REMOTE ATTESTATION", "03 VBS · HVCI", "04 WHQL SIGNING GATE"]
      .forEach((nm, i) => {
        const t = this.lbl(nm, "lbl-dim", new THREE.Vector3(CAM[i], 9.2, -4));
        t.element.style.fontSize = "12.5px";
        t.element.style.letterSpacing = "0.34em";
      });

    this.buildBoot();
    this.buildAttest();
    this.buildHvci();
    this.buildGate();
  }

  camDrift(t) {
    const cx = CAM[this.zoneIdx];
    return new THREE.Vector3(
      cx + Math.sin(t * 0.07) * (this.zoneIdx === 0 ? 5 : 3),
      5.2 + Math.sin(t * 0.11) * 0.9,
      ZONE_DIST[this.zoneIdx]
    );
  }

  step(i, reset = true) {
    const z = Math.floor(i / 6), k = i % 6;
    // 自动连续播放时保留上一步动画的飞行体/光束收尾；手动跳步或跨阶段时清场
    if (reset || z !== this.zoneIdx) this.clearFx();
    this.zoneIdx = z;
    this.lookAt.set(CAM[z], 1.5, 0);
    [this.stepBoot, this.stepAttest, this.stepHvci, this.stepGate][z].call(this, k);
  }

  /* ── ZONE A · 度量启动 ── */
  buildBoot() {
    const z = ZONE[0];
    const names = [
      ["UEFI 固件<br>SRTM", "lbl-violet"],
      ["SecureBoot 变量", "lbl-cyan"],
      ["bootmgfw.efi", ""],
      ["winload.efi", ""],
      ["ntoskrnl.exe<br>+ ELAM", "lbl-amber"],
    ];
    this.stages = names.map((nm, i) => {
      const s = this.slab(4.2, 5.4, 1.4, C.dim, 0.08);
      s.position.set(z - 26 + i * 6.2, -2.5, 0);
      this.lbl(nm[0], nm[1] + " lbl-dim", new THREE.Vector3(0, -4.2, 0), s);
      return s;
    });
    for (let i = 0; i < 4; i++) {
      const b = this.beam(
        new THREE.Vector3(z - 26 + i * 6.2 + 2.1, -2.5, 0),
        new THREE.Vector3(z - 26 + (i + 1) * 6.2 - 2.1, -2.5, 0),
        C.dim, { persist: true });
      b.material.blending = THREE.NormalBlending;
      b.userData.static = true;
    }
    this.pcrNames = ["PCR0", "PCR4", "PCR7", "PCR12"];
    this.pcrSlots = this.pcrNames.map((nm, i) => {
      const s = this.slab(5.6, 1.6, 3.2, C.violet, 0.08);
      s.position.set(z + 11, -3.9 + i * 2.1, 0);
      this.lbl(nm, "lbl-violet lbl-dim", new THREE.Vector3(-4.6, 0, 0), s);
      return s;
    });
    this.lbl("TPM 2.0", "lbl-violet", new THREE.Vector3(z + 11, 6.2, 0));
    this.slab(6.6, 9.6, 4.2, C.violet, 0.02).position.set(z + 11, 0.6, 0);
  }

  sendDigest(stageIdx, pcrIdx, color) {
    const from = this.stages[stageIdx].position.clone().add(new THREE.Vector3(0, 3.6, 0));
    const slot = this.pcrSlots[pcrIdx].position.clone();
    this.fly(0.9, color, [
      from,
      from.clone().add(new THREE.Vector3(3, 5, 2)),
      slot.clone().add(new THREE.Vector3(-4, 3, 1)),
      slot,
    ], 1.0, () => {
      this.lit(this.pcrSlots[pcrIdx], true, color);
      this.beam(slot.clone().add(new THREE.Vector3(-2.8, 0, 0)),
        slot.clone().add(new THREE.Vector3(2.8, 0, 0)), color);
    });
  }

  stepBoot(k) {
    const A = this;
    if (k === 0) {
      A.stages.forEach(s => A.lit(s, false));
      A.pcrSlots.forEach(s => { A.lit(s, false); A.dim(s); });
      A.pcrSlots.forEach(s => A.pulse(s));
    }
    if (k === 1) { A.lit(A.stages[0], true, C.violet); A.sendDigest(0, 0, C.violet); }
    if (k === 2) {
      A.lit(A.stages[1], true, C.cyan);
      A.sendDigest(1, 2, C.cyan);
      setTimeout(() => A.visible && A.sendDigest(1, 2, C.cyan), 450);
    }
    if (k === 3) {
      A.lit(A.stages[2], true, C.magenta);
      A.sendDigest(2, 1, C.magenta);
      setTimeout(() => {
        if (!A.visible) return;
        A.lit(A.stages[3], true, C.magenta);
        A.sendDigest(3, 1, C.magenta);
      }, 500);
    }
    if (k === 4) { A.lit(A.stages[4], true, C.amber); A.sendDigest(4, 3, C.amber); }
    if (k === 5) {
      A.stages.forEach(s => A.lit(s, true, C.green));
      A.pcrSlots.forEach((s, j) => setTimeout(() => {
        if (!A.visible) return;
        A.lit(s, true, C.green);
        A.beam(s.position.clone().add(new THREE.Vector3(-3, 0, 2)),
          s.position.clone().add(new THREE.Vector3(3, 0, 2)), C.green);
      }, j * 140));
    }
  }

  /* ── ZONE B · 远程证明 ── */
  buildAttest() {
    const z = ZONE[1];
    this.client = this.slab(7, 10, 5, C.cyan, 0.07);
    this.client.position.set(z - 6, 0, 0);
    this.lbl("VERIFYER · 客户端", "lbl-cyan", new THREE.Vector3(0, 6.4, 0), this.client);
    this.tpm = this.slab(2.6, 1.2, 2.6, C.violet, 0.16);
    this.tpm.position.set(z - 6, -3.2, 3.2);
    this.lbl("TPM 2.0", "lbl-violet lbl-dim", new THREE.Vector3(0, -1.6, 0), this.tpm);

    this.server = this.slab(7, 12, 5, C.magenta, 0.07);
    this.server.position.set(z + 6, 1, 0);
    this.lbl("SERVER · 验证后端", "lbl-magenta", new THREE.Vector3(0, 7.4, 0), this.server);

    // WBCL 日志片（隐藏，Step 升起）
    this.wbcl = [];
    for (let k = 0; k < 4; k++) {
      const p = this.slab(3.6, 0.5, 2.4, C.amber, 0.14);
      p.position.set(z - 6, -20, -2.6);
      this.wbcl.push(p);
    }

    // 服务端四步校验板
    this.checks = [];
    ["① AK 签名 RSASSA-SHA256", "② magic 0xFF544347", "③ nonce 一致（防重放）", "④ PCR 重放比对"]
      .forEach((nm, k) => {
        const p = this.slab(5.4, 1.5, 0.6, C.dim, 0.08);
        p.position.set(z + 6, 4.6 - k * 2.2, 2.9);
        const l = this.lbl(nm, "lbl-dim", new THREE.Vector3(-4.6, 0, 0), p);
        this.checks.push({ p, l });
      });
  }

  stepAttest(k) {
    const A = this, cPos = A.client.position, sPos = A.server.position;
    if (k === 0) {
      A.wbcl.forEach(p => p.position.y = -20);
      A.checks.forEach(c => { A.lit(c.p, false); c.l.element.className = "lbl lbl-dim"; });
      A.fly(0.8, C.cyan, [
        sPos.clone().add(new THREE.Vector3(-3.5, 2, 1)),
        new THREE.Vector3(ZONE[1], 6, 3),
        cPos.clone().add(new THREE.Vector3(3.5, 2, 1)),
      ], 1.1, () => A.lit(A.client, true, C.cyan));
    }
    if (k === 1) {
      A.wbcl.forEach((p, j) => {
        p.position.y = -20;
        const target = -1.8 + j * 0.8;
        const anim = () => {
          if (p.position.y < target) { p.position.y += 0.6; requestAnimationFrame(anim); }
          else A.lit(p, true, C.amber);
        };
        setTimeout(anim, j * 120);
      });
    }
    if (k === 2) {
      A.lit(A.tpm, true, C.violet);
      A.pulse(A.tpm);
      A.beam(A.tpm.position.clone(), cPos.clone().add(new THREE.Vector3(0, 2, 0)), C.violet);
      A.fly(0.7, C.violet, [
        A.tpm.position.clone(),
        A.tpm.position.clone().add(new THREE.Vector3(0, 4, 2)),
        cPos.clone().add(new THREE.Vector3(0, 3, 3)),
      ], 0.9);
    }
    if (k === 3) {
      [C.violet, C.magenta, C.amber].forEach((col, j) => {
        setTimeout(() => {
          if (!A.visible) return;
          A.fly(0.85, col, [
            cPos.clone().add(new THREE.Vector3(3.5, 1 + j, 1)),
            new THREE.Vector3(ZONE[1], 7 + j, 2),
            sPos.clone().add(new THREE.Vector3(-3.5, 2, 1)),
          ], 1.2, () => A.lit(A.server, true, C.magenta));
        }, j * 180);
      });
    }
    if (k === 4) {
      A.checks.forEach((c, j) => {
        setTimeout(() => {
          if (!A.visible) return;
          A.lit(c.p, true, C.green);
          c.l.element.className = "lbl lbl-green";
          A.beam(c.p.position.clone().add(new THREE.Vector3(-3, 0, 1)),
            c.p.position.clone().add(new THREE.Vector3(3, 0, 1)), C.green);
        }, j * 280);
      });
    }
    if (k === 5) {
      A.lit(A.client, true, C.green);
      A.lit(A.server, true, C.green);
      A.beam(cPos.clone().add(new THREE.Vector3(3.5, 0, 0)),
        sPos.clone().add(new THREE.Vector3(-3.5, 0, 0)), C.green, { persist: true });
    }
  }

  /* ── ZONE C · VBS / HVCI ── */
  buildHvci() {
    const z = ZONE[2];
    this.hv = this.slab(34, 1.4, 16, C.violet, 0.07);
    this.hv.position.set(z, -5, 0);
    this.lbl("HYPER-V · VT-x / EPT(SLAT)", "lbl-violet", new THREE.Vector3(0, -1.8, 0), this.hv);

    this.vtl0 = this.slab(13, 11, 9, C.cyan, 0.05);
    this.vtl0.position.set(z - 8, 1.6, 0);
    this.lbl("VTL0 · 普通世界<br>Windows 内核 / 进程", "lbl-cyan", new THREE.Vector3(0, 7, 0), this.vtl0);

    this.vtl1 = this.slab(9, 11, 9, C.magenta, 0.05);
    this.vtl1.position.set(z + 8, 1.6, 0);
    this.lbl("VTL1 · 安全世界<br>Secure Kernel / HVCI", "lbl-magenta", new THREE.Vector3(0, 7, 0), this.vtl1);

    this.hvci = this.slab(3.4, 3.4, 3.4, C.magenta, 0.14);
    this.hvci.position.set(z + 8, 1.6, 0);
    this.lbl("HVCI", "lbl-magenta lbl-dim", new THREE.Vector3(0, -2.6, 0), this.hvci);

    this.page = this.slab(2.2, 2.2, 2.2, C.amber, 0.16);
    this.page.position.set(z - 8, 3, 4.2);
    this.pageLbl = this.lbl("未签名页 · 申请 W+X", "lbl-amber lbl-dim", new THREE.Vector3(0, 2, 0), this.page);

    this.slat = this.slab(6.4, 0.9, 3, C.violet, 0.14);
    this.slat.position.set(z, -3.6, 5.4);
    this.slatLbl = this.lbl("SLAT 表项: —", "lbl-violet lbl-dim", new THREE.Vector3(0, -1.4, 0), this.slat);
  }

  stepHvci(k) {
    const A = this;
    if (k === 0) {
      [A.hv, A.vtl0, A.vtl1, A.hvci, A.page, A.slat].forEach(s => A.lit(s, false));
      A.slatLbl.element.innerHTML = "SLAT 表项: —";
      A.slatLbl.element.className = "lbl lbl-violet lbl-dim";
      A.pageLbl.element.className = "lbl lbl-amber lbl-dim";
      [A.hv, A.vtl0, A.vtl1].forEach(s => A.pulse(s));
    }
    if (k === 1) {
      A.lit(A.hv, true, C.violet);
      A.beam(new THREE.Vector3(ZONE[2] - 16, -5, 0), new THREE.Vector3(ZONE[2] + 16, -5, 0), C.violet);
    }
    if (k === 2) {
      A.lit(A.vtl1, true, C.magenta);
      A.lit(A.hvci, true, C.magenta);
    }
    if (k === 3) {
      A.lit(A.page, true, C.amber);
      A.pageLbl.element.className = "lbl lbl-amber";
      const p0 = A.page.position.clone();
      const hvP = new THREE.Vector3(ZONE[2], -4.4, 2);
      const hvciP = A.hvci.position.clone();
      A.fly(0.9, C.amber, [p0, p0.clone().add(new THREE.Vector3(2, -3, 1)), hvP], 0.85, () => {
        if (!A.visible) return;
        A.fly(0.9, C.amber, [hvP, new THREE.Vector3(ZONE[2] + 6, -1, 2), hvciP], 0.8, () => {
          A.lit(A.hvci, true, C.magenta);
          A.beam(hvciP, p0, C.magenta);
          A.beam(hvciP.clone().add(new THREE.Vector3(0, 1, 1)), p0.clone().add(new THREE.Vector3(0, 1, 1)), C.magenta);
          A.lit(A.slat, true, C.magenta);
          A.slatLbl.element.innerHTML = "SLAT 表项: RW- (NX) · execute DENIED";
          A.slatLbl.element.className = "lbl lbl-magenta";
        });
      });
    }
    if (k === 4) {
      A.lit(A.slat, true, C.violet);
      A.slatLbl.element.innerHTML = "PCR12 重放: ✔ 与 WBCL 一致";
      A.slatLbl.element.className = "lbl lbl-violet";
      A.beam(A.slat.position.clone(), new THREE.Vector3(ZONE[2], 8, 0), C.violet);
    }
    if (k === 5) {
      [A.hv, A.vtl1, A.hvci].forEach(s => A.lit(s, true, C.green));
      A.lit(A.vtl0, true, C.cyan);
      A.beam(new THREE.Vector3(ZONE[2] - 9, 8.5, 0), new THREE.Vector3(ZONE[2] + 11, 8.5, 0), C.green, { persist: true });
    }
  }

  /* ── ZONE D · WHQL 签名门禁 ── */
  buildGate() {
    const z = ZONE[3];
    this.driver = this.slab(3.6, 3.6, 3.6, C.amber, 0.14);
    this.driver.position.set(z - 8, -3, 2);
    this.lbl("driver.sys", "lbl-amber", new THREE.Vector3(0, -2.8, 0), this.driver);

    const chainNames = [
      ["叶证书 · 厂商 EV 证书", C.cyan],
      ["MS WHQL Publisher", C.violet],
      ["Microsoft Root CA 2010", C.magenta],
    ];
    this.chain = chainNames.map(([nm, col], k) => {
      const p = this.slab(7.2, 2, 0.7, col, 0.08);
      p.position.set(z - 18, -1 + k * 3.4, 0);
      this.lbl(nm, "lbl-dim", new THREE.Vector3(0, k === 2 ? 2 : -1.9, 0), p);
      return p;
    });
    this.lbl("AUTHENTICODE 链", "lbl-cyan lbl-dim", new THREE.Vector3(z - 18, 9.2, 0));

    this.cat = this.slab(6.6, 9, 2.4, C.violet, 0.06);
    this.cat.position.set(z + 8, 1.4, 0);
    this.lbl("Windows Catalog (.cat)", "lbl-violet lbl-dim", new THREE.Vector3(0, 6.2, 0), this.cat);

    this.hashCells = [];
    for (let r = 0; r < 4; r++) for (let c = 0; c < 3; c++) {
      const cell = this.slab(1.6, 1.4, 0.5, C.dim, 0.1);
      cell.position.set(z + 6.4 + c * 1.8, -1.4 + r * 1.9, 1.4);
      this.hashCells.push(cell);
    }

    this.gate = this.slab(9, 5, 1, C.green, 0.05);
    this.gate.position.set(z, 2.5, -7);
    this.gateLbl = this.lbl("KernelService · SHA256 门禁", "lbl-dim", new THREE.Vector3(0, 3.4, 0), this.gate);
  }

  stepGate(k) {
    const A = this, dPos = A.driver.position;
    if (k === 0) {
      A.chain.forEach(p => A.lit(p, false));
      A.hashCells.forEach(p => A.lit(p, false));
      [A.cat, A.gate].forEach(p => A.lit(p, false));
      A.lit(A.driver, true, C.amber);
      A.gateLbl.element.className = "lbl lbl-dim";
    }
    if (k === 1) {
      A.fly(0.8, C.cyan, [
        dPos.clone(),
        dPos.clone().add(new THREE.Vector3(-5, 2, 1)),
        A.chain[0].position.clone(),
      ], 0.9, () => A.lit(A.chain[0], true, C.cyan));
    }
    if (k === 2) {
      A.lit(A.chain[0], true, C.cyan);
      [1, 2].forEach(j => setTimeout(() => {
        if (!A.visible) return;
        A.lit(A.chain[j], true, j === 1 ? C.violet : C.magenta);
        A.beam(A.chain[j - 1].position.clone(), A.chain[j].position.clone(),
          j === 1 ? C.violet : C.magenta);
      }, j * 350));
    }
    if (k === 3) {
      A.lit(A.cat, true, C.violet);
      A.fly(0.8, C.violet, [
        dPos.clone(),
        dPos.clone().add(new THREE.Vector3(5, 3, 1)),
        A.cat.position.clone().add(new THREE.Vector3(-1, 0, 2)),
      ], 0.9);
    }
    if (k === 4) {
      A.hashCells.forEach((cell, j) => setTimeout(() => {
        if (!A.visible) return;
        if (j === 7) {
          A.lit(cell, true, C.green);
          A.beam(cell.position.clone(), dPos.clone(), C.green);
        } else {
          A.lit(cell, true, C.dim);
          setTimeout(() => A.dim(cell), 300);
        }
      }, j * 90));
    }
    if (k === 5) {
      A.lit(A.gate, true, C.green);
      A.gateLbl.element.className = "lbl lbl-green";
      A.fly(0.8, C.green, [
        dPos.clone(),
        dPos.clone().add(new THREE.Vector3(0, 4, -3)),
        A.gate.position.clone(),
      ], 1.0, () => {
        A.beam(A.gate.position.clone().add(new THREE.Vector3(-4.5, 0, 0.6)),
          A.gate.position.clone().add(new THREE.Vector3(4.5, 0, 0.6)), C.green, { persist: true });
      });
    }
  }
}
