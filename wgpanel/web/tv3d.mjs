// tv3d.mjs — صحنه‌ی سه‌بعدی «شبکه» برای نمای TV پنل (three.js)
// THREE از بیرون تزریق می‌شود تا نسخه/کش فقط دستِ پنل باشد.
export function start(opts){
  const THREE = opts.THREE;
  const holder = opts.holder;
  const reduced = !!opts.reduced;
  const onFail = opts.onFail || function(){};
  function deadHandle(){
    return {update: function(){}, pause: function(){},
            resume: function(){}, dispose: function(){}};
  }

  // رنگ کم‌روشنا (مثل پالت تم روشن) روی زمینه‌ی تیره دیده نمی‌شود؛ در صورت
  // نیاز به سمت روشن/اشباع می‌بریم — معنای رنگ (rx/tx/خطا) عوض نمی‌شود.
  function vivid(hex, minL){
    const c = new THREE.Color(hex || '#8899aa');
    const hsl = {h: 0, s: 0, l: 0}; c.getHSL(hsl);
    if(hsl.l < minL) c.setHSL(hsl.h, Math.max(hsl.s, .55), minL);
    return c;
  }
  const O = opts.colors || {};
  const COL = {
    rx: vivid(O.rx, .58), tx: vivid(O.tx, .52), gold: vivid(O.gold, .6),
    err: vivid(O.err, .55), off: new THREE.Color(O.off || '#55607a'),
    star: new THREE.Color('#aebdd6'), ring: new THREE.Color('#2c3a55')
  };

  let renderer;
  try{
    renderer = new THREE.WebGLRenderer({antialias: true, alpha: false});
  }catch(e){ onFail(e); return deadHandle(); }
  renderer.setClearColor(0x05070d, 1);
  const canvas = renderer.domElement;
  holder.insertBefore(canvas, holder.firstChild);   // اورلی‌های DOM رویش می‌مانند

  const scene = new THREE.Scene();
  scene.fog = new THREE.FogExp2(0x05070d, 0.010);
  const camera = new THREE.PerspectiveCamera(50, 1, 0.1, 600);

  // ---- بافت‌های نرم بدون فایل خارجی (گرادیان شعاعی روی canvas)
  function discTexture(sharp){
    const c = document.createElement('canvas'); c.width = c.height = 64;
    const x = c.getContext('2d');
    const g = x.createRadialGradient(32, 32, 0, 32, 32, 32);
    g.addColorStop(0, 'rgba(255,255,255,1)');
    g.addColorStop(sharp ? .35 : .12, sharp ? 'rgba(255,255,255,.9)'
                                            : 'rgba(255,255,255,.5)');
    g.addColorStop(1, 'rgba(255,255,255,0)');
    x.fillStyle = g; x.fillRect(0, 0, 64, 64);
    return new THREE.CanvasTexture(c);
  }
  const texDot = discTexture(true);
  const texGlow = discTexture(false);

  // ---- ستاره‌های پس‌زمینه (پوسته‌ی کروی دور؛ با مه محو می‌شوند)
  const starGeo = new THREE.BufferGeometry();
  {
    const n = 900, pos = new Float32Array(n * 3);
    for(let i = 0; i < n; i++){
      const r = 130 + Math.random() * 170;
      const th = Math.random() * Math.PI * 2, ph = Math.acos(2 * Math.random() - 1);
      pos[i*3] = r * Math.sin(ph) * Math.cos(th);
      pos[i*3+1] = r * Math.cos(ph);
      pos[i*3+2] = r * Math.sin(ph) * Math.sin(th);
    }
    starGeo.setAttribute('position', new THREE.BufferAttribute(pos, 3));
  }
  const stars = new THREE.Points(starGeo, new THREE.PointsMaterial({
    color: COL.star, size: 1.5, sizeAttenuation: false, map: texDot,
    transparent: true, opacity: .7, depthWrite: false}));
  scene.add(stars);

  // ---- سرور در مرکز: هسته‌ی سیمی چرخان + هاله‌ای که با نرخ کل می‌تپد
  const srvCore = new THREE.Mesh(
    new THREE.IcosahedronGeometry(2.1, 1),
    new THREE.MeshBasicMaterial({color: COL.gold, wireframe: true,
                                 transparent: true, opacity: .85}));
  const srvInner = new THREE.Mesh(
    new THREE.IcosahedronGeometry(1.25, 2),
    new THREE.MeshBasicMaterial({color: 0x0e1a30}));
  const srvGlow = new THREE.Sprite(new THREE.SpriteMaterial({
    map: texGlow, color: COL.gold, transparent: true, opacity: .45,
    blending: THREE.AdditiveBlending, depthWrite: false}));
  srvGlow.scale.set(9, 9, 1);
  scene.add(srvInner, srvCore, srvGlow);

  // ---- حلقه‌های مداری + گره‌ها
  const rings = new THREE.Group(); scene.add(rings);
  const nodesG = new THREE.Group(); scene.add(nodesG);
  const nodeGeo = new THREE.SphereGeometry(.55, 20, 14);
  const tunGeo = new THREE.OctahedronGeometry(.7, 0);
  const ringMat = new THREE.LineBasicMaterial({color: COL.ring,
                                               transparent: true, opacity: .55});
  const matCache = new Map();
  function matFor(col){
    const k = col.getHexString();
    if(!matCache.has(k))
      matCache.set(k, new THREE.MeshBasicMaterial({color: col.clone()}));
    return matCache.get(k);
  }
  function makeRing(radius){
    const seg = 128, pos = new Float32Array(seg * 3);
    for(let i = 0; i < seg; i++){
      const a = i / seg * Math.PI * 2;
      pos[i*3] = Math.cos(a) * radius; pos[i*3+1] = 0;
      pos[i*3+2] = Math.sin(a) * radius;
    }
    const g = new THREE.BufferGeometry();
    g.setAttribute('position', new THREE.BufferAttribute(pos, 3));
    return new THREE.LineLoop(g, ringMat);
  }

  // ---- استخر ذرات (آرایه‌های موازی فشرده؛ مرگ = جابه‌جایی با آخری)
  const PMAX = 3000;
  const pGeo = new THREE.BufferGeometry();
  const pPos = new Float32Array(PMAX * 3);
  const pCol = new Float32Array(PMAX * 3);
  const aPos = new THREE.BufferAttribute(pPos, 3);
  const aCol = new THREE.BufferAttribute(pCol, 3);
  aPos.setUsage(THREE.DynamicDrawUsage); aCol.setUsage(THREE.DynamicDrawUsage);
  pGeo.setAttribute('position', aPos);
  pGeo.setAttribute('color', aCol);
  const pMat = new THREE.PointsMaterial({size: .5, map: texDot,
    vertexColors: true, transparent: true, opacity: .9,
    blending: THREE.AdditiveBlending, depthWrite: false, sizeAttenuation: true});
  const points = new THREE.Points(pGeo, pMat);
  points.frustumCulled = false;
  scene.add(points);
  let alive = 0;
  const pT = new Float32Array(PMAX), pSp = new Float32Array(PMAX);
  const pNode = new Array(PMAX), pDir = new Uint8Array(PMAX);
  const pGen = new Float32Array(PMAX);
  const pJ = new Float32Array(PMAX * 3);   // خمیدگی تصادفی مسیر هر ذره

  function spawn(nd, dir){
    if(alive >= PMAX) return;
    const i = alive++;
    pT[i] = 0; pNode[i] = nd; pDir[i] = dir; pGen[i] = nd.gen;
    const rate = dir ? nd.want.txRate : nd.want.rxRate;
    pSp[i] = (0.35 + Math.min(1.1, Math.log10(1 + rate / 32768) * .5))
             * (0.85 + Math.random() * .3);
    pJ[i*3] = (Math.random() - .5) * 3.5;
    pJ[i*3+1] = 2.5 + Math.random() * 3.5;
    pJ[i*3+2] = (Math.random() - .5) * 3.5;
  }
  function kill(i){
    alive--;
    if(i !== alive){
      pT[i] = pT[alive]; pSp[i] = pSp[alive]; pNode[i] = pNode[alive];
      pDir[i] = pDir[alive]; pGen[i] = pGen[alive];
      pJ[i*3] = pJ[alive*3]; pJ[i*3+1] = pJ[alive*3+1]; pJ[i*3+2] = pJ[alive*3+2];
    }
    pNode[alive] = null;
  }
  function stepParticles(dt){
    nodes.forEach(function(nd){ nd.cnt[0] = 0; nd.cnt[1] = 0; });
    for(let i = 0; i < alive; ){
      const nd = pNode[i];
      pT[i] += pSp[i] * dt;
      if(!nd || nd.gen !== pGen[i] || pT[i] >= 1){ kill(i); continue; }
      nd.cnt[pDir[i]]++;
      i++;
    }
    // رمپ نرم: هر جهتِ هر گره حداکثر یک ذره‌ی تازه در هر فریم
    nodes.forEach(function(nd){
      if(nd.cnt[0] < nd.want[0]) spawn(nd, 0);
      if(nd.cnt[1] < nd.want[1]) spawn(nd, 1);
    });
    for(let i = 0; i < alive; i++){
      const nd = pNode[i], dir = pDir[i];
      const t = dir ? 1 - pT[i] : pT[i];   // TX معکوس: گره → سرور
      const mt = 1 - t;
      const cx = nd.pos.x * .5 + pJ[i*3], cy = nd.pos.y * .5 + pJ[i*3+1],
            cz = nd.pos.z * .5 + pJ[i*3+2];
      // بزیه‌ی درجه‌۲ از مرکز (سرور) تا گره با نقطه‌ی کنترل برآمده
      pPos[i*3] = 2*mt*t*cx + t*t*nd.pos.x;
      pPos[i*3+1] = 2*mt*t*cy + t*t*nd.pos.y;
      pPos[i*3+2] = 2*mt*t*cz + t*t*nd.pos.z;
      const env = Math.sin(Math.PI * pT[i]) * .95;   // ظهور/محو نرم (بلندینگ افزایشی)
      const c = dir ? COL.tx : COL.rx;
      pCol[i*3] = c.r * env; pCol[i*3+1] = c.g * env; pCol[i*3+2] = c.b * env;
    }
    aPos.needsUpdate = true; aCol.needsUpdate = true;
    pGeo.setDrawRange(0, alive);
  }
  // تراکم ذره از نرخ: 1KB/s→۲ ذره، 1MB/s→~۲۳؛ سقف برای خوانایی/کارایی
  function wantCount(rate){
    if(!rate || rate < 256) return 0;
    const n = Math.round(2 + 7 * Math.log10(rate / 1024));
    return Math.max(1, Math.min(reduced ? 6 : 22, n));
  }

  // ---- گره‌ها
  const nodes = new Map();   // id → وضعیت گره (مش، هاله، مقصد حرکت، نرخ‌ها)
  let gen = 0;               // نسل؛ ذرات گره‌ی حذف‌شده با این باطل می‌شوند
  function placeNode(n, r, ang){
    const tgt = new THREE.Vector3(Math.cos(ang) * r, 0, Math.sin(ang) * r);
    let nd = nodes.get(n.id);
    if(!nd){
      nd = {gen: ++gen, cnt: [0, 0], want: [0, 0], info: n,
            pos: tgt.clone(), tgt: tgt, lb: null,
            mesh: new THREE.Mesh(n.kind === 'tunnel' ? tunGeo : nodeGeo,
                                 matFor(COL.off)),
            glow: new THREE.Sprite(new THREE.SpriteMaterial({
              map: texGlow, transparent: true, opacity: 0,
              blending: THREE.AdditiveBlending, depthWrite: false}))};
      nd.mesh.position.copy(nd.pos); nd.glow.position.copy(nd.pos);
      nodesG.add(nd.mesh); nodesG.add(nd.glow);
      nodes.set(n.id, nd);
    }
    nd.tgt = tgt; nd.info = n;
    nd.want[0] = n.online ? wantCount(n.rx) : 0;
    nd.want[1] = n.online ? wantCount(n.tx) : 0;
    nd.want.rxRate = n.rx || 0; nd.want.txRate = n.tx || 0;
    let col;
    if(n.kind === 'tunnel') col = !n.ok ? COL.err : n.online ? COL.gold : COL.off;
    else col = !n.ok ? COL.err : n.online ? COL.rx : COL.off;
    nd.mesh.material = matFor(col);
    nd.glow.material.color.copy(col);
    const act = Math.min(1, ((n.rx || 0) + (n.tx || 0)) / 1048576);
    nd.glowT = n.online ? (.25 + .5 * act) : 0;
    nd.scaleT = (n.kind === 'other' ? 1.3 : 1) * (1 + .35 * act);
  }
  function removeNode(id){
    const nd = nodes.get(id); if(!nd) return;
    nodes.delete(id);
    nd.gen = -1;
    nodesG.remove(nd.mesh); nodesG.remove(nd.glow);
    nd.glow.material.dispose();
    if(nd.lb){ nd.lb.remove(); nd.lb = null; }
  }

  // ---- برچسب‌های DOM: فقط پرترافیک‌ترین‌ها؛ متن با textContent (بدون HTML)
  const LBN = 6;
  function syncLabels(){
    const arr = [];
    nodes.forEach(function(nd){ arr.push(nd); });
    arr.sort(function(a, b){
      return ((b.info.rx || 0) + (b.info.tx || 0)) -
             ((a.info.rx || 0) + (a.info.tx || 0)); });
    arr.forEach(function(nd, i){
      const on = i < LBN && ((nd.info.rx || 0) + (nd.info.tx || 0)) > 512;
      if(on && !nd.lb){
        const d = document.createElement('div');
        d.className = 'tv3d-lb';
        d.appendChild(document.createElement('b'));
        const s = document.createElement('span'); s.className = 's';
        d.appendChild(s);
        holder.appendChild(d);
        nd.lb = d;
      }
      if(!on && nd.lb){ nd.lb.remove(); nd.lb = null; }
      if(nd.lb){
        nd.lb.firstChild.textContent = nd.info.name || '';
        nd.lb.lastChild.textContent = nd.info.sub || '';
      }
    });
  }
  const _pv = new THREE.Vector3();
  function positionLabels(){
    const w = holder.clientWidth, h = holder.clientHeight;
    if(!w || !h) return;
    nodes.forEach(function(nd){
      if(!nd.lb) return;
      _pv.copy(nd.pos); _pv.y += 1.1; _pv.project(camera);
      const vis = _pv.z < 1 && _pv.x > -1.05 && _pv.x < 1.05 &&
                  _pv.y > -1.05 && _pv.y < 1.05;
      nd.lb.style.opacity = vis ? '1' : '0';
      if(vis){
        nd.lb.style.left = ((_pv.x + 1) / 2 * w) + 'px';
        nd.lb.style.top = ((1 - _pv.y) / 2 * h) + 'px';
      }
    });
  }

  // ---- به‌روزرسانی داده (هر ~۲ ثانیه از refresh پنل)
  let ringKey = '', srvRate = 0;
  function update(data){
    if(disposed) return;
    data = data || {};
    const groups = data.groups || [], list = data.nodes || [];
    const gi = new Map();
    groups.forEach(function(g, i){ gi.set(g, i); });
    const R0 = 10.5, DR = 4.2;
    const tunR = R0 + groups.length * DR;
    const otherR = tunR + DR * .75;
    const hasTun = list.some(function(n){ return n.kind === 'tunnel'; });
    const rk = groups.join('|') + (hasTun ? '#t' : '');
    if(rk !== ringKey){
      ringKey = rk;
      while(rings.children.length){
        const r = rings.children[rings.children.length - 1];
        rings.remove(r); r.geometry.dispose();
      }
      groups.forEach(function(_, i){ rings.add(makeRing(R0 + i * DR)); });
      if(hasTun) rings.add(makeRing(tunR));
    }
    // چیدمان زاویه‌ای پایدار: در هر حلقه به ترتیب id (نه نرخ) تا گره‌ها نپرند
    const byRing = new Map();
    list.forEach(function(n){
      const r = n.kind === 'tunnel' ? tunR : n.kind === 'other' ? otherR
              : R0 + (gi.has(n.group) ? gi.get(n.group) : 0) * DR;
      if(!byRing.has(r)) byRing.set(r, []);
      byRing.get(r).push(n);
    });
    const seen = new Set();
    byRing.forEach(function(lst, r){
      lst.sort(function(a, b){ return a.id < b.id ? -1 : 1; });
      lst.forEach(function(n, i){
        seen.add(n.id);
        placeNode(n, r, i / lst.length * Math.PI * 2 + r * .7);
      });
    });
    nodes.forEach(function(nd, id){ if(!seen.has(id)) removeNode(id); });
    srvRate = ((data.server && data.server.rx) || 0) +
              ((data.server && data.server.tx) || 0);
    syncLabels();
  }

  // ---- دوربین مداری سبک (درگ/چرخ/pinch؛ چرخش خودکار پس از سکون)
  const HOME = {r: 42, th: .8, ph: 1.04};
  const view = {r: HOME.r, th: HOME.th, ph: HOME.ph};
  const cur = {r: HOME.r, th: HOME.th, ph: HOME.ph};
  let velTh = 0, idleT = 0, dragging = false, px0 = 0, py0 = 0, pinch0 = 0;
  function clampView(){
    view.ph = Math.max(.35, Math.min(1.45, view.ph));
    view.r = Math.max(18, Math.min(95, view.r));
  }
  const ac = new AbortController();
  const sig = {signal: ac.signal};
  const ptrs = new Map();
  canvas.addEventListener('pointerdown', function(e){
    try{ canvas.setPointerCapture(e.pointerId); }catch(err){}
    ptrs.set(e.pointerId, [e.clientX, e.clientY]);
    if(ptrs.size === 1){ dragging = true; px0 = e.clientX; py0 = e.clientY; velTh = 0; }
    else if(ptrs.size === 2){
      dragging = false;
      const a = Array.from(ptrs.values());
      pinch0 = Math.hypot(a[0][0] - a[1][0], a[0][1] - a[1][1]);
    }
    idleT = 0;
  }, sig);
  canvas.addEventListener('pointermove', function(e){
    if(!ptrs.has(e.pointerId)) return;
    ptrs.set(e.pointerId, [e.clientX, e.clientY]);
    idleT = 0;
    if(ptrs.size === 2 && pinch0 > 0){
      const a = Array.from(ptrs.values());
      const d = Math.hypot(a[0][0] - a[1][0], a[0][1] - a[1][1]);
      if(d > 10){ view.r *= pinch0 / d; pinch0 = d; clampView(); }
      return;
    }
    if(!dragging) return;
    const dx = e.clientX - px0, dy = e.clientY - py0;
    px0 = e.clientX; py0 = e.clientY;
    view.th += dx * .005; velTh = dx * .002;
    view.ph -= dy * .004;
    clampView();
  }, sig);
  function ptrUp(e){
    ptrs.delete(e.pointerId);
    if(ptrs.size < 2) pinch0 = 0;
    if(!ptrs.size) dragging = false;
  }
  canvas.addEventListener('pointerup', ptrUp, sig);
  canvas.addEventListener('pointercancel', ptrUp, sig);
  canvas.addEventListener('wheel', function(e){
    e.preventDefault(); idleT = 0;
    view.r *= (e.deltaY > 0 ? 1.09 : .92); clampView();
  }, {signal: ac.signal, passive: false});
  canvas.addEventListener('dblclick', function(){
    view.r = HOME.r; view.th = HOME.th; view.ph = HOME.ph;
    velTh = 0; idleT = 0;
  }, sig);
  document.addEventListener('visibilitychange', function(){
    if(document.hidden) stopLoop(); else if(shouldRun) runLoop();
  }, sig);
  canvas.addEventListener('webglcontextlost', function(e){
    e.preventDefault();
    onFail(new Error('webgl context lost'));
  }, sig);

  // ---- اندازه (ResizeObserver؛ dpr سقف ۲ برای نمایشگرهای متراکم)
  function resize(){
    const w = holder.clientWidth, h = holder.clientHeight;
    if(!w || !h) return;
    renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 2));
    renderer.setSize(w, h, false);
    camera.aspect = w / h;
    camera.updateProjectionMatrix();
  }
  let ro = null;
  if(typeof ResizeObserver !== 'undefined'){
    ro = new ResizeObserver(resize); ro.observe(holder);
  } else {
    window.addEventListener('resize', resize, sig);
  }

  // ---- حلقه‌ی رندر (فقط وقتی اسلاید فعال و تب دیده می‌شود)
  let raf = 0, running = false, shouldRun = false, disposed = false, last = 0;
  function frame(now){
    if(!running){ raf = 0; return; }
    raf = requestAnimationFrame(frame);
    const dt = Math.min(.1, (now - last) / 1000 || .016);
    last = now;
    idleT += dt;
    if(!dragging){
      view.th += velTh; velTh *= .93;
      if(!reduced && idleT > 8) view.th += dt * .07;   // چرخش خودکار پس از سکون
    }
    clampView();
    const k = 1 - Math.exp(-dt * 7);   // نرم‌سازی مستقل از fps
    cur.th += (view.th - cur.th) * k;
    cur.ph += (view.ph - cur.ph) * k;
    cur.r += (view.r - cur.r) * k;
    camera.position.set(cur.r * Math.sin(cur.ph) * Math.cos(cur.th),
                        cur.r * Math.cos(cur.ph),
                        cur.r * Math.sin(cur.ph) * Math.sin(cur.th));
    camera.lookAt(0, .8, 0);
    srvCore.rotation.y += dt * .25; srvCore.rotation.x += dt * .09;
    const act = Math.min(1, srvRate / 2097152);
    const pul = 1 + .06 * Math.sin(now * .002) + .2 * act;
    srvGlow.scale.set(9 * pul, 9 * pul, 1);
    srvGlow.material.opacity = .3 + .4 * act;
    if(!reduced) stars.rotation.y += dt * .004;
    nodes.forEach(function(nd){
      nd.pos.lerp(nd.tgt, k);
      nd.mesh.position.copy(nd.pos);
      const sc = nd.scaleT || 1;
      nd.mesh.scale.set(sc, sc, sc);
      nd.glow.position.copy(nd.pos);
      nd.glow.material.opacity += ((nd.glowT || 0) - nd.glow.material.opacity) * k;
      const gs = 3.2 * sc;
      nd.glow.scale.set(gs, gs, 1);
    });
    stepParticles(reduced ? dt * .6 : dt);
    positionLabels();
    renderer.render(scene, camera);
  }
  function runLoop(){
    if(disposed || running) return;
    running = true; last = performance.now();
    resize();
    raf = requestAnimationFrame(frame);
  }
  function stopLoop(){
    running = false;
    if(raf){ cancelAnimationFrame(raf); raf = 0; }
  }

  function dispose(){
    if(disposed) return;
    disposed = true; shouldRun = false;
    stopLoop();
    ac.abort();
    if(ro) ro.disconnect();
    const ids = [];
    nodes.forEach(function(_, id){ ids.push(id); });
    ids.forEach(removeNode);
    scene.traverse(function(o){
      if(o.geometry) o.geometry.dispose();
      if(o.material) o.material.dispose();
    });
    matCache.forEach(function(m){ m.dispose(); });
    nodeGeo.dispose(); tunGeo.dispose(); pGeo.dispose();
    texDot.dispose(); texGlow.dispose();
    renderer.dispose();
    try{ renderer.forceContextLoss(); }catch(e){}
    canvas.remove();
  }

  return {
    update: update,
    pause: function(){ shouldRun = false; stopLoop(); },
    resume: function(){ shouldRun = true; if(!document.hidden) runLoop(); },
    dispose: dispose
  };
}
