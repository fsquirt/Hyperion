// ════════════════════════════════════════════════════════════
// HYPERION — 四个 3D 演示场景
// 度量启动 / TPM 远程证明 / VBS·HVCI / WHQL 签名链
// 直角几何 + 线框玻璃 + 拖影运动模糊
// ════════════════════════════════════════════════════════════
import * as THREE from "three";
import { CSS2DRenderer, CSS2DObject } from "three/addons/renderers/CSS2DRenderer.js";

const C = {
  violet: 0x8b5cf6, magenta: 0xff2d78, cyan: 0x38e1ff,
  amber: 0xffb454, green: 0x3dffa0, dim: 0x4a4870, ink: 0xc8c5de,
};

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
      color: 0x8d8ac0, size: 0.28, transparent: true, opacity: 0.55,
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

      // 残影
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

    // 相机漂移 + 鼠标视差
    const cam = this.camDrift(t);
    cam.x += this.mouse.x * 2.2;
    cam.y += this.mouse.y * 1.2;
    this.camera.position.lerp(cam, 0.04);
    this.camera.lookAt(this.lookAt || new THREE.Vector3(0, 0, 0));

    this.renderer.render(this.scene, this.camera);
    this.labelRenderer.render(this.scene, this.camera);
  }

  updateScene() {}
  camDrift(t) { return new THREE.Vector3(Math.sin(t * 0.1) * 3, 6, 34); }
  step() {}
}

/* ══════════════════════════════════════════════
   DEMO 1 · UEFI 安全启动 / PCR 度量重放
   ══════════════════════════════════════════════ */
export class SecureBootScene extends BaseScene {
  constructor(canvas, labelWrap) {
    super(canvas, labelWrap);
    this.lookAt = new THREE.Vector3(0, 2, 0);

    // 地面网格
    const grid = new THREE.GridHelper(70, 26, 0x3a3760, 0x1d1b36);
    grid.position.y = -4;
    this.scene.add(grid);

    // 启动链 5 个环节
    const names = [
      ["UEFI 固件<br>SRTM", "lbl-violet"],
      ["固件配置<br>SecureBoot 变量", "lbl-cyan"],
      ["bootmgfw.efi", ""],
      ["winload.efi", ""],
      ["ntoskrnl.exe<br>+ ELAM", "lbl-amber"],
    ];
    this.stages = names.map((nm, i) => {
      const s = this.slab(4.2, 5.4, 1.4, C.dim, 0.08);
      s.position.set(-16 + i * 6.2, -1, 0);
      this.lbl(nm[0], nm[1] + " lbl-dim", new THREE.Vector3(0, -4.2, 0), s);
      return s;
    });

    // 链路连线
    for (let i = 0; i < 4; i++) {
      const b = this.beam(
        new THREE.Vector3(-16 + i * 6.2 + 2.1, -1, 0),
        new THREE.Vector3(-16 + (i + 1) * 6.2 - 2.1, -1, 0),
        C.dim, { persist: true });
      b.material.blending = THREE.NormalBlending;
      b.userData.static = true;
    }

    // TPM PCR 塔
    this.pcrNames = ["PCR0", "PCR4", "PCR7", "PCR12"];
    this.pcrSlots = this.pcrNames.map((nm, i) => {
      const s = this.slab(5.6, 1.6, 3.2, C.violet, 0.08);
      s.position.set(17, -2.2 + i * 2.1, 0);
      this.lbl(nm, "lbl-violet lbl-dim", new THREE.Vector3(-4.6, 0, 0), s);
      return s;
    });
    const tpmLbl = this.lbl("TPM 2.0", "lbl-violet", new THREE.Vector3(17, 6.4, 0));
    this.slab(6.6, 9.6, 4.2, C.violet, 0.02).position.set(17, 0.9, 0);
  }

  camDrift(t) { return new THREE.Vector3(Math.sin(t * 0.08) * 4, 5, 33); }

  /* digest 飞入 PCR 槽 */
  sendDigest(stageIdx, pcrIdx, color) {
    const from = this.stages[stageIdx].position.clone().add(new THREE.Vector3(0, 3.6, 0));
    const slot = this.pcrSlots[pcrIdx].position.clone();
    this.fly(0.9, color, [
      from,
      from.clone().add(new THREE.Vector3(3, 5, 2)),
      slot.clone().add(new THREE.Vector3(-4, 3, 1)),
      slot,
    ], 1.4, () => {
      this.lit(this.pcrSlots[pcrIdx], true, color);
      this.beam(slot.clone().add(new THREE.Vector3(-2.8, 0, 0)),
        slot.clone().add(new THREE.Vector3(2.8, 0, 0)), color);
    });
  }

  step(i) {
    this.clearFx();
    if (i === 0) {
      this.stages.forEach(s => this.lit(s, false));
      this.pcrSlots.forEach(s => { this.lit(s, false); this.dim(s); });
      this.pcrSlots.forEach(s => this.pulse(s));
    }
    if (i === 1) { this.lit(this.stages[0], true, C.violet); this.sendDigest(0, 0, C.violet); }
    if (i === 2) {
      this.lit(this.stages[1], true, C.cyan);
      this.sendDigest(1, 2, C.cyan);
      setTimeout(() => this.visible && this.sendDigest(1, 2, C.cyan), 700);
    }
    if (i === 3) {
      this.lit(this.stages[2], true, C.magenta);
      this.sendDigest(2, 1, C.magenta);
      setTimeout(() => {
        if (!this.visible) return;
        this.lit(this.stages[3], true, C.magenta);
        this.sendDigest(3, 1, C.magenta);
      }, 800);
    }
    if (i === 4) { this.lit(this.stages[4], true, C.amber); this.sendDigest(4, 3, C.amber); }
    if (i === 5) {
      this.stages.forEach(s => this.lit(s, true, C.green));
      this.pcrSlots.forEach((s, k) => setTimeout(() => {
        if (!this.visible) return;
        this.lit(s, true, C.green);
        this.beam(s.position.clone().add(new THREE.Vector3(-3, 0, 2)),
          s.position.clone().add(new THREE.Vector3(3, 0, 2)), C.green);
      }, k * 220));
    }
  }
}

/* ══════════════════════════════════════════════
   DEMO 2 · TPM 远程证明
   ══════════════════════════════════════════════ */
export class AttestScene extends BaseScene {
  constructor(canvas, labelWrap) {
    super(canvas, labelWrap);
    this.lookAt = new THREE.Vector3(0, 1, 0);

    const grid = new THREE.GridHelper(80, 30, 0x3a3760, 0x1d1b36);
    grid.position.y = -5;
    this.scene.add(grid);

    // 客户端（Verifyer 主机 + TPM 芯片）
    this.client = this.slab(7, 10, 5, C.cyan, 0.07);
    this.client.position.set(-15, 0, 0);
    this.lbl("VERIFYER · 客户端", "lbl-cyan", new THREE.Vector3(0, 6.4, 0), this.client);
    this.tpm = this.slab(2.6, 1.2, 2.6, C.violet, 0.16);
    this.tpm.position.set(-15, -3.2, 3.2);
    this.lbl("TPM 2.0", "lbl-violet lbl-dim", new THREE.Vector3(0, -1.6, 0), this.tpm);

    // 服务端
    this.server = this.slab(7, 12, 5, C.magenta, 0.07);
    this.server.position.set(15, 1, 0);
    this.lbl("SERVER · 验证后端", "lbl-magenta", new THREE.Vector3(0, 7.4, 0), this.server);

    // WBCL 日志片（隐藏，Step2 升起）
    this.wbcl = [];
    for (let k = 0; k < 4; k++) {
      const p = this.slab(3.6, 0.5, 2.4, C.amber, 0.14);
      p.position.set(-15, -20, -2.6);
      this.wbcl.push(p);
    }

    // 服务端四步校验板
    this.checks = [];
    const checkNames = [
      "① AK 签名 RSASSA-SHA256", "② magic 0xFF544347",
      "③ nonce 一致（防重放）", "④ PCR 重放比对",
    ];
    checkNames.forEach((nm, k) => {
      const p = this.slab(5.4, 1.5, 0.6, C.dim, 0.08);
      p.position.set(15, 4.6 - k * 2.2, 2.9);
      const l = this.lbl(nm, "lbl-dim", new THREE.Vector3(-4.6, 0, 0), p);
      this.checks.push({ p, l });
    });
  }

  camDrift(t) { return new THREE.Vector3(Math.sin(t * 0.09) * 5, 4, 36); }

  step(i) {
    this.clearFx();
    const cPos = this.client.position, sPos = this.server.position;
    if (i === 0) {
      this.wbcl.forEach(p => p.position.y = -20);
      this.checks.forEach(c => { this.lit(c.p, false); c.l.element.className = "lbl lbl-dim"; });
      // nonce: server → client
      this.fly(0.8, C.cyan, [
        sPos.clone().add(new THREE.Vector3(-3.5, 2, 1)),
        new THREE.Vector3(0, 6, 3),
        cPos.clone().add(new THREE.Vector3(3.5, 2, 1)),
      ], 1.5, () => this.lit(this.client, true, C.cyan));
    }
    if (i === 1) {
      this.wbcl.forEach((p, k) => {
        p.position.set(-15, -20, -2.6);
        const target = -1.8 + k * 0.8;
        const anim = () => {
          if (p.position.y < target) { p.position.y += 0.6; requestAnimationFrame(anim); }
          else this.lit(p, true, C.amber);
        };
        setTimeout(anim, k * 180);
      });
    }
    if (i === 2) {
      this.lit(this.tpm, true, C.violet);
      this.pulse(this.tpm);
      this.beam(this.tpm.position.clone(), cPos.clone().add(new THREE.Vector3(0, 2, 0)), C.violet);
      this.fly(0.7, C.violet, [
        this.tpm.position.clone(),
        this.tpm.position.clone().add(new THREE.Vector3(0, 4, 2)),
        cPos.clone().add(new THREE.Vector3(0, 3, 3)),
      ], 1.2);
    }
    if (i === 3) {
      // attest + sig + wbcl 三件套飞向服务端
      [C.violet, C.magenta, C.amber].forEach((col, k) => {
        setTimeout(() => {
          if (!this.visible) return;
          this.fly(0.85, col, [
            cPos.clone().add(new THREE.Vector3(3.5, 1 + k, 1)),
            new THREE.Vector3(0, 7 + k, 2),
            sPos.clone().add(new THREE.Vector3(-3.5, 2, 1)),
          ], 1.6, () => this.lit(this.server, true, C.magenta));
        }, k * 260);
      });
    }
    if (i === 4) {
      this.checks.forEach((c, k) => {
        setTimeout(() => {
          if (!this.visible) return;
          this.lit(c.p, true, C.green);
          c.l.element.className = "lbl lbl-green";
          this.beam(c.p.position.clone().add(new THREE.Vector3(-3, 0, 1)),
            c.p.position.clone().add(new THREE.Vector3(3, 0, 1)), C.green);
        }, k * 420);
      });
    }
    if (i === 5) {
      this.lit(this.client, true, C.green);
      this.lit(this.server, true, C.green);
      this.beam(cPos.clone().add(new THREE.Vector3(3.5, 0, 0)),
        sPos.clone().add(new THREE.Vector3(-3.5, 0, 0)), C.green, { persist: true });
    }
  }
}

/* ══════════════════════════════════════════════
   DEMO 3 · Hypervisor / VBS / HVCI
   ══════════════════════════════════════════════ */
export class VbsScene extends BaseScene {
  constructor(canvas, labelWrap) {
    super(canvas, labelWrap);
    this.lookAt = new THREE.Vector3(0, 2, 0);

    // Hyper-V 底座
    this.hv = this.slab(34, 1.4, 16, C.violet, 0.07);
    this.hv.position.set(0, -5, 0);
    this.lbl("HYPER-V · VT-x / EPT(SLAT)", "lbl-violet", new THREE.Vector3(0, -1.8, 0), this.hv);

    const grid = new THREE.GridHelper(70, 26, 0x3a3760, 0x17152c);
    grid.position.y = -5.8;
    this.scene.add(grid);

    // VTL0 普通世界
    this.vtl0 = this.slab(13, 11, 9, C.cyan, 0.05);
    this.vtl0.position.set(-9, 1.6, 0);
    this.lbl("VTL0 · 普通世界<br>Windows 内核 / 进程", "lbl-cyan", new THREE.Vector3(0, 7, 0), this.vtl0);

    // VTL1 安全世界
    this.vtl1 = this.slab(9, 11, 9, C.magenta, 0.05);
    this.vtl1.position.set(11, 1.6, 0);
    this.lbl("VTL1 · 安全世界<br>Secure Kernel / HVCI", "lbl-magenta", new THREE.Vector3(0, 7, 0), this.vtl1);

    // HVCI 裁决核心
    this.hvci = this.slab(3.4, 3.4, 3.4, C.magenta, 0.14);
    this.hvci.position.set(11, 1.6, 0);
    this.lbl("HVCI", "lbl-magenta lbl-dim", new THREE.Vector3(0, -2.6, 0), this.hvci);

    // 未签名代码页
    this.page = this.slab(2.2, 2.2, 2.2, C.amber, 0.16);
    this.page.position.set(-9, 3, 4.2);
    this.pageLbl = this.lbl("未签名页 · 申请 W+X", "lbl-amber lbl-dim", new THREE.Vector3(0, 2, 0), this.page);

    // SLAT 表
    this.slat = this.slab(6.4, 0.9, 3, C.violet, 0.14);
    this.slat.position.set(0, -3.6, 5.4);
    this.slatLbl = this.lbl("SLAT 表项: —", "lbl-violet lbl-dim", new THREE.Vector3(0, -1.4, 0), this.slat);
  }

  camDrift(t) { return new THREE.Vector3(Math.sin(t * 0.07) * 6, 7, 34); }

  step(i) {
    this.clearFx();
    if (i === 0) {
      [this.hv, this.vtl0, this.vtl1, this.hvci, this.page, this.slat].forEach(s => this.lit(s, false));
      this.slatLbl.element.innerHTML = "SLAT 表项: —";
      this.slatLbl.element.className = "lbl lbl-violet lbl-dim";
      this.pageLbl.element.className = "lbl lbl-amber lbl-dim";
      [this.hv, this.vtl0, this.vtl1].forEach(s => this.pulse(s));
    }
    if (i === 1) {
      this.lit(this.hv, true, C.violet);
      this.beam(new THREE.Vector3(-16, -5, 0), new THREE.Vector3(16, -5, 0), C.violet);
    }
    if (i === 2) {
      this.lit(this.vtl1, true, C.magenta);
      this.lit(this.hvci, true, C.magenta);
    }
    if (i === 3) {
      // 未签名页申请可执行 → 下行到 Hyper-V → HVCI 裁决 → 拒绝
      this.lit(this.page, true, C.amber);
      this.pageLbl.element.className = "lbl lbl-amber";
      const p0 = this.page.position.clone();
      const hvP = new THREE.Vector3(0, -4.4, 2);
      const hvciP = this.hvci.position.clone();
      this.fly(0.9, C.amber, [p0, p0.clone().add(new THREE.Vector3(2, -3, 1)), hvP], 1.1, () => {
        if (!this.visible) return;
        this.fly(0.9, C.amber, [hvP, new THREE.Vector3(6, -1, 2), hvciP], 1.0, () => {
          // HVCI 拒绝：红色驳回光束
          this.lit(this.hvci, true, C.magenta);
          this.beam(hvciP, p0, C.magenta);
          this.beam(hvciP.clone().add(new THREE.Vector3(0, 1, 1)), p0.clone().add(new THREE.Vector3(0, 1, 1)), C.magenta);
          this.lit(this.slat, true, C.magenta);
          this.slatLbl.element.innerHTML = "SLAT 表项: RW- (NX) · execute DENIED";
          this.slatLbl.element.className = "lbl lbl-magenta";
        });
      });
    }
    if (i === 4) {
      this.lit(this.slat, true, C.violet);
      this.slatLbl.element.innerHTML = "PCR12 重放: ✔ 与 WBCL 一致";
      this.slatLbl.element.className = "lbl lbl-violet";
      this.beam(this.slat.position.clone(), new THREE.Vector3(0, 8, 0), C.violet);
    }
    if (i === 5) {
      [this.hv, this.vtl1, this.hvci].forEach(s => this.lit(s, true, C.green));
      this.lit(this.vtl0, true, C.cyan);
      this.beam(new THREE.Vector3(-9, 8.5, 0), new THREE.Vector3(11, 8.5, 0), C.green, { persist: true });
    }
  }
}

/* ══════════════════════════════════════════════
   DEMO 4 · WHQL 驱动签名体系
   ══════════════════════════════════════════════ */
export class WhqlScene extends BaseScene {
  constructor(canvas, labelWrap) {
    super(canvas, labelWrap);
    this.lookAt = new THREE.Vector3(0, 3, 0);

    const grid = new THREE.GridHelper(70, 26, 0x3a3760, 0x17152c);
    grid.position.y = -6;
    this.scene.add(grid);

    // 待验证驱动
    this.driver = this.slab(3.6, 3.6, 3.6, C.amber, 0.14);
    this.driver.position.set(0, -3, 2);
    this.lbl("driver.sys", "lbl-amber", new THREE.Vector3(0, -2.8, 0), this.driver);

    // Authenticode 证书链（左侧，向上）
    const chainNames = [
      ["叶证书 · 厂商 EV 证书", C.cyan],
      ["MS Windows Hardware<br>Compatibility Publisher", C.violet],
      ["Microsoft Root CA 2010", C.magenta],
    ];
    this.chain = chainNames.map(([nm, col], k) => {
      const p = this.slab(7.2, 2, 0.7, col, 0.08);
      p.position.set(-10, -1 + k * 3.4, 0);
      this.lbl(nm, "lbl-dim", new THREE.Vector3(0, k === 2 ? 2 : -1.9, 0), p);
      return p;
    });
    this.lbl("AUTHENTICODE 链", "lbl-cyan lbl-dim", new THREE.Vector3(-10, 9.4, 0));

    // Catalog 目录（右侧）
    this.cat = this.slab(6.6, 9, 2.4, C.violet, 0.06);
    this.cat.position.set(10, 1.4, 0);
    this.lbl("Windows Catalog (.cat)<br>已注册哈希库", "lbl-violet lbl-dim", new THREE.Vector3(0, 6.2, 0), this.cat);
    // 哈希格
    this.hashCells = [];
    for (let r = 0; r < 4; r++) for (let c = 0; c < 3; c++) {
      const cell = this.slab(1.6, 1.4, 0.5, C.dim, 0.1);
      cell.position.set(8.4 + c * 1.8, -1.4 + r * 1.9, 1.4);
      this.hashCells.push(cell);
    }

    // 内核门禁（后方）
    this.gate = this.slab(9, 5, 1, C.green, 0.05);
    this.gate.position.set(0, 2.5, -7);
    this.gateLbl = this.lbl("KernelService · SHA256 白名单门禁", "lbl-dim", new THREE.Vector3(0, 3.4, 0), this.gate);
  }

  camDrift(t) { return new THREE.Vector3(Math.sin(t * 0.08) * 5, 6, 33); }

  step(i) {
    this.clearFx();
    const dPos = this.driver.position;
    if (i === 0) {
      this.chain.forEach(p => this.lit(p, false));
      this.hashCells.forEach(p => this.lit(p, false));
      [this.cat, this.gate].forEach(p => this.lit(p, false));
      this.lit(this.driver, true, C.amber);
      this.gateLbl.element.className = "lbl lbl-dim";
    }
    if (i === 1) {
      // 哈希飞向叶证书
      this.fly(0.8, C.cyan, [
        dPos.clone(),
        dPos.clone().add(new THREE.Vector3(-5, 2, 1)),
        this.chain[0].position.clone(),
      ], 1.2, () => this.lit(this.chain[0], true, C.cyan));
    }
    if (i === 2) {
      // 链式上行
      this.lit(this.chain[0], true, C.cyan);
      [1, 2].forEach(k => setTimeout(() => {
        if (!this.visible) return;
        this.lit(this.chain[k], true, k === 1 ? C.violet : C.magenta);
        this.beam(this.chain[k - 1].position.clone(), this.chain[k].position.clone(),
          k === 1 ? C.violet : C.magenta);
      }, k * 500));
    }
    if (i === 3) {
      // CryptCATAdminCalcHashFromFileHandle：驱动哈希飞向目录
      this.lit(this.cat, true, C.violet);
      this.fly(0.8, C.violet, [
        dPos.clone(),
        dPos.clone().add(new THREE.Vector3(5, 3, 1)),
        this.cat.position.clone().add(new THREE.Vector3(-1, 0, 2)),
      ], 1.2);
    }
    if (i === 4) {
      // 目录扫描：依次点亮，命中第 8 格
      this.hashCells.forEach((cell, k) => setTimeout(() => {
        if (!this.visible) return;
        if (k === 7) {
          this.lit(cell, true, C.green);
          this.beam(cell.position.clone(), dPos.clone(), C.green);
        } else {
          this.lit(cell, true, C.dim);
          setTimeout(() => this.dim(cell), 300);
        }
      }, k * 130));
    }
    if (i === 5) {
      this.lit(this.gate, true, C.green);
      this.gateLbl.element.className = "lbl lbl-green";
      this.fly(0.8, C.green, [
        dPos.clone(),
        dPos.clone().add(new THREE.Vector3(0, 4, -3)),
        this.gate.position.clone(),
      ], 1.3, () => {
        this.beam(this.gate.position.clone().add(new THREE.Vector3(-4.5, 0, 0.6)),
          this.gate.position.clone().add(new THREE.Vector3(4.5, 0, 0.6)), C.green, { persist: true });
      });
    }
  }
}

export const SCENES = {
  secureboot: SecureBootScene,
  attest: AttestScene,
  vbs: VbsScene,
  whql: WhqlScene,
};
