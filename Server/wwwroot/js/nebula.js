// HYPERION — Hero 星云背景
// 全屏 FBM 星云着色器 + 速度拉伸星轨，即真实运动模糊 + 流星
import * as THREE from "https://cdn.jsdelivr.net/npm/three@0.160.0/build/three.module.js";

const NEBULA_FRAG = /* glsl */ `
  precision highp float;
  uniform vec2 uRes;
  uniform float uTime;
  uniform vec2 uMouse;

  float hash(vec2 p) {
    return fract(sin(dot(p, vec2(127.1, 311.7))) * 43758.5453123);
  }
  float noise(vec2 p) {
    vec2 i = floor(p), f = fract(p);
    vec2 u = f * f * (3.0 - 2.0 * f);
    return mix(mix(hash(i), hash(i + vec2(1.0, 0.0)), u.x),
               mix(hash(i + vec2(0.0, 1.0)), hash(i + vec2(1.0, 1.0)), u.x), u.y);
  }
  float fbm(vec2 p) {
    float v = 0.0, a = 0.5;
    mat2 rot = mat2(0.8, 0.6, -0.6, 0.8);
    for (int i = 0; i < 5; i++) {
      v += a * noise(p);
      p = rot * p * 2.03;
      a *= 0.52;
    }
    return v;
  }

  void main() {
    vec2 uv = (gl_FragCoord.xy - 0.5 * uRes) / uRes.y;
    vec2 m = uMouse * 0.06;
    float t = uTime * 0.022;

    // 域扭曲星云
    vec2 q = vec2(fbm(uv * 1.6 + t), fbm(uv * 1.6 - t * 0.7));
    vec2 r = vec2(fbm(uv * 2.1 + q * 1.4 + m), fbm(uv * 2.1 - q * 1.2 - m));
    float f = fbm(uv * 2.4 + r * 1.8);

    // 星云配色：深空紫 → 洋红 → 青
    vec3 deep    = vec3(0.016, 0.02, 0.05);
    vec3 violet  = vec3(0.16, 0.36, 0.93);
    vec3 magenta = vec3(0.72, 0.10, 0.38);
    vec3 cyan    = vec3(0.10, 0.55, 0.72);

    vec3 col = deep;
    col = mix(col, violet,  smoothstep(0.32, 0.86, f) * 0.85);
    col = mix(col, magenta, smoothstep(0.45, 0.95, q.y * f) * 0.55);
    col = mix(col, cyan,    smoothstep(0.55, 1.0, r.x * f) * 0.45);

    // 星云核心亮斑
    float core = smoothstep(0.68, 1.0, f);
    col += vec3(0.32, 0.52, 0.95) * core * core * 0.6;

    // 远景静态星，共两层并带闪烁
    for (int L = 0; L < 2; L++) {
      float scale = L == 0 ? 190.0 : 90.0;
      vec2 gp = uv * scale + float(L) * 37.7;
      vec2 cell = floor(gp);
      float star = hash(cell);
      if (star > 0.978) {
        vec2 pos = fract(gp) - 0.5;
        float d = length(pos - (vec2(hash(cell + 1.3), hash(cell + 2.7)) - 0.5) * 0.6);
        float tw = 0.6 + 0.4 * sin(uTime * (1.0 + star * 4.0) + star * 40.0);
        col += vec3(0.9, 0.92, 1.0) * smoothstep(0.11, 0.0, d) * tw * 0.85;
      }
    }

    // 暗角
    float vig = 1.0 - dot(uv, uv) * 0.55;
    col *= vig;

    gl_FragColor = vec4(col, 1.0);
  }
`;

export function initNebula(canvas) {
  const renderer = new THREE.WebGLRenderer({ canvas, antialias: true });
  renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));

  const scene = new THREE.Scene();
  const camera = new THREE.PerspectiveCamera(60, 1, 0.1, 400);
  camera.position.z = 60;

  //  星云背景全屏面片，使用独立正交场景 
  const bgScene = new THREE.Scene();
  const bgCam = new THREE.OrthographicCamera(-1, 1, 1, -1, 0, 1);
  const uniforms = {
    uRes: { value: new THREE.Vector2(1, 1) },
    uTime: { value: 0 },
    uMouse: { value: new THREE.Vector2(0, 0) },
  };
  bgScene.add(new THREE.Mesh(
    new THREE.PlaneGeometry(2, 2),
    new THREE.ShaderMaterial({
      fragmentShader: NEBULA_FRAG,
      uniforms,
      depthWrite: false,
    })
  ));

  //  前景星轨：LineSegments，长度 ∝ 速度 = 真实运动模糊 
  const STAR_COUNT = 900;
  const positions = new Float32Array(STAR_COUNT * 6);
  const colors = new Float32Array(STAR_COUNT * 6);
  const stars = [];
  const palette = [
    new THREE.Color(0x6aa5ff), new THREE.Color(0xffffff),
    new THREE.Color(0x38e1ff), new THREE.Color(0xff5c9d),
  ];
  for (let i = 0; i < STAR_COUNT; i++) {
    stars.push({
      pos: new THREE.Vector3(
        (Math.random() - 0.5) * 220,
        (Math.random() - 0.5) * 130,
        (Math.random() - 0.5) * 160
      ),
      vel: new THREE.Vector3(
        0.6 + Math.random() * 2.4,
        (Math.random() - 0.5) * 0.35,
        0
      ),
      col: palette[(Math.random() * palette.length) | 0],
      w: 0.35 + Math.random() * 0.65,
    });
  }
  const starGeo = new THREE.BufferGeometry();
  starGeo.setAttribute("position", new THREE.BufferAttribute(positions, 3));
  starGeo.setAttribute("color", new THREE.BufferAttribute(colors, 3));
  const starLines = new THREE.LineSegments(
    starGeo,
    new THREE.LineBasicMaterial({
      vertexColors: true,
      transparent: true,
      opacity: 0.8,
      blending: THREE.AdditiveBlending,
      depthWrite: false,
    })
  );
  scene.add(starLines);

  //  流星 
  const meteors = [];
  function spawnMeteor() {
    const geo = new THREE.BufferGeometry();
    geo.setAttribute("position", new THREE.BufferAttribute(new Float32Array(6), 3));
    const mat = new THREE.LineBasicMaterial({
      color: 0xbfe9ff,
      transparent: true,
      opacity: 1,
      blending: THREE.AdditiveBlending,
    });
    const line = new THREE.Line(geo, mat);
    scene.add(line);
    meteors.push({
      line,
      pos: new THREE.Vector3(-140 + Math.random() * 80, 40 + Math.random() * 40, -30),
      vel: new THREE.Vector3(2.6 + Math.random() * 1.6, -(1.0 + Math.random() * 0.9), 0),
      life: 1,
    });
  }
  let meteorTimer = 2;

  //  交互 
  const mouse = new THREE.Vector2();
  const mouseSmooth = new THREE.Vector2();
  window.addEventListener("pointermove", (e) => {
    mouse.set((e.clientX / innerWidth) * 2 - 1, -(e.clientY / innerHeight) * 2 + 1);
  }, { passive: true });

  function resize() {
    const w = canvas.clientWidth, h = canvas.clientHeight;
    if (canvas.width !== w * renderer.getPixelRatio() || canvas.height !== h * renderer.getPixelRatio()) {
      renderer.setSize(w, h, false);
      camera.aspect = w / h;
      camera.updateProjectionMatrix();
      uniforms.uRes.value.set(w * renderer.getPixelRatio(), h * renderer.getPixelRatio());
    }
  }

  const clock = new THREE.Clock();
  let visible = true;
  new IntersectionObserver(([e]) => { visible = e.isIntersecting; }, { threshold: 0 })
    .observe(canvas);

  // 滚动加速：滚得越快，星轨越长，动态模糊随速度增强
  let scrollBoost = 0, lastY = window.scrollY;
  window.addEventListener("scroll", () => {
    scrollBoost = Math.min(6, Math.abs(window.scrollY - lastY) * 0.06 + scrollBoost);
    lastY = window.scrollY;
  }, { passive: true });

  function frame() {
    requestAnimationFrame(frame);
    if (!visible) return;
    resize();

    const dt = Math.min(clock.getDelta(), 0.05);
    const t = clock.elapsedTime;
    uniforms.uTime.value = t;
    mouseSmooth.lerp(mouse, 0.04);
    uniforms.uMouse.value.copy(mouseSmooth);
    scrollBoost = Math.max(0, scrollBoost - dt * 4);

    const boost = 1 + scrollBoost;
    const pos = starGeo.attributes.position.array;
    const col = starGeo.attributes.color.array;
    for (let i = 0; i < STAR_COUNT; i++) {
      const s = stars[i];
      s.pos.x += s.vel.x * dt * 6 * boost;
      s.pos.y += s.vel.y * dt * 6;
      if (s.pos.x > 120) { s.pos.x = -120; s.pos.y = (Math.random() - 0.5) * 130; }

      // 尾迹长度 = 速度 × 模糊系数
      const trail = s.vel.x * (0.9 + scrollBoost * 1.4) * s.w;
      const o = i * 6;
      pos[o] = s.pos.x; pos[o + 1] = s.pos.y; pos[o + 2] = s.pos.z;
      pos[o + 3] = s.pos.x - trail; pos[o + 4] = s.pos.y - s.vel.y * trail * 0.4; pos[o + 5] = s.pos.z;

      const c = s.col, w = s.w;
      col[o] = c.r * w; col[o + 1] = c.g * w; col[o + 2] = c.b * w;
      col[o + 3] = 0; col[o + 4] = 0; col[o + 5] = 0; // 尾端透明 → 渐隐模糊
    }
    starGeo.attributes.position.needsUpdate = true;
    starGeo.attributes.color.needsUpdate = true;

    // 流星
    meteorTimer -= dt;
    if (meteorTimer <= 0) { spawnMeteor(); meteorTimer = 3 + Math.random() * 5; }
    for (let i = meteors.length - 1; i >= 0; i--) {
      const m = meteors[i];
      m.pos.addScaledVector(m.vel, dt * 40);
      m.life -= dt * 0.5;
      const p = m.line.geometry.attributes.position.array;
      const tail = 14 * m.life;
      p[0] = m.pos.x; p[1] = m.pos.y; p[2] = m.pos.z;
      p[3] = m.pos.x - m.vel.x * tail; p[4] = m.pos.y - m.vel.y * tail; p[5] = m.pos.z;
      m.line.geometry.attributes.position.needsUpdate = true;
      m.line.material.opacity = Math.max(0, m.life);
      if (m.life <= 0) {
        scene.remove(m.line);
        m.line.geometry.dispose();
        m.line.material.dispose();
        meteors.splice(i, 1);
      }
    }

    // 相机漂移
    camera.position.x = mouseSmooth.x * 6;
    camera.position.y = mouseSmooth.y * 3 + Math.sin(t * 0.13) * 1.5;
    camera.lookAt(0, 0, 0);

    renderer.autoClear = true;
    renderer.render(bgScene, bgCam);
    renderer.autoClear = false;
    renderer.render(scene, camera);
  }
  frame();
}
