
(() => {
    'use strict';

    const canvas = document.getElementById('bg-canvas');
    if (!canvas) return;
    const ctx = canvas.getContext('2d', { alpha: true });

    const reduce = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

    const CHASE = false;

    let W = 0, H = 0, DPR = 1;
    let nodes = [], packets = [], rings = [], ghosts = [];
    let hunter = null;
    let mouse = { x: 0, y: 0, set: false };
    let raf = null, running = true, t0 = 0;
    let phase = 'run', ftimer = 0;

    const GHOST = [
        '   XXXXX   ',
        '  XXXXXXX  ',
        ' XXXXXXXXX ',
        'XXXXXXXXXXX',
        'XXXXXXXXXXX',
        'XXXXXXXXXXX',
        'XXXXXXXXXXX',
        'XXXXXXXXXXX',
        'XXXXXXXXXXX',
        'XX XX XX XX',
    ];
    const GW = 11, GH = 10;
    const EYES = [[2, 3], [6, 3]];

    let COL = { amber: '255,176,0', mesh: '102,100,90', node: '156,154,140' };
    function readTheme() {
        const cs = getComputedStyle(document.documentElement);
        const hex = (v, f) => toRgb(cs.getPropertyValue(v).trim()) || f;
        COL.amber = hex('--amber', '255,176,0');
        COL.mesh  = hex('--text-3', '102,100,90');
        COL.node  = hex('--text-2', '156,154,140');
    }
    function toRgb(h) {
        if (!h) return null;
        h = h.replace('#', '');
        if (h.length === 3) h = h.split('').map(c => c + c).join('');
        if (h.length !== 6) return null;
        const n = parseInt(h, 16);
        return `${(n >> 16) & 255},${(n >> 8) & 255},${n & 255}`;
    }

    function resize() {
        DPR = Math.min(window.devicePixelRatio || 1, 2);
        W = window.innerWidth; H = window.innerHeight;
        canvas.width = W * DPR; canvas.height = H * DPR;
        canvas.style.width = W + 'px'; canvas.style.height = H + 'px';
        ctx.setTransform(DPR, 0, 0, DPR, 0, 0);

        const hdr = document.getElementById('app-header');
        GMT = hdr ? Math.round(hdr.getBoundingClientRect().bottom) + 28 : 74;
        build();
    }

    function build() {
        const density = (W * H) / 26000;
        const count = Math.max(26, Math.min(74, Math.round(density)));
        nodes = [];
        for (let i = 0; i < count; i++) {
            nodes.push({
                x: Math.random() * W,
                y: Math.random() * H,
                vx: (Math.random() - 0.5) * 0.16,
                vy: (Math.random() - 0.5) * 0.16,
                r: Math.random() * 1.4 + 0.8,
                ph: Math.random() * Math.PI * 2,
            });
        }
        packets = [];
        rings = [];
        if (CHASE) placeChase(); else { hunter = null; ghosts = []; }
        if (!mouse.set) { mouse.x = W / 2; mouse.y = H / 2; }
    }

    function placeChase() {
        const { P } = ghostRect();
        const gn = W < 720 ? 2 : 3;
        const base = Math.random() * P;
        phase = 'run'; ftimer = 0;

        hunter = {
            p: base, dir: Math.random() < 0.5 ? 1 : -1,
            x: 0, y: 0, mouth: 0, faceDir: 0, trail: [],
        };
        const hp = perimToXY(base);
        hunter.x = hp.x; hunter.y = hp.y;

        ghosts = [];
        for (let i = 0; i < gn; i++) {
            const p = base + P * (i + 0.12 + Math.random() * 0.76) / gn;
            ghosts.push({
                p, dir: 1,
                x: 0, y: 0,
                u: 3.0 + Math.random() * 1.3,
                alpha: 0.5 + Math.random() * 0.28,
                bob: Math.random() * Math.PI * 2,
                blink: 0, nextBlink: 80 + Math.random() * 280,
            });
            const pt = perimToXY(p);
            ghosts[i].x = pt.x; ghosts[i].y = pt.y;
        }
    }

    const LINK = 168;
    const GM = 30;
    let GMT = 64;

    function ghostRect() {
        const Wi = Math.max(40, W - 2 * GM);
        const Hi = Math.max(40, (H - GM) - GMT);
        return { Wi, Hi, P: 2 * (Wi + Hi) };
    }
    function perimToXY(p) {
        const { Wi, Hi, P } = ghostRect();
        p = ((p % P) + P) % P;
        if (p < Wi) return { x: GM + p, y: GMT };
        p -= Wi;
        if (p < Hi) return { x: GM + Wi, y: GMT + p };
        p -= Hi;
        if (p < Wi) return { x: GM + Wi - p, y: H - GM };
        p -= Wi;
        return { x: GM, y: (H - GM) - p };
    }

    function spawnPacket() {

        const i = (Math.random() * nodes.length) | 0;
        const a = nodes[i];
        const near = [];
        for (let j = 0; j < nodes.length; j++) {
            if (j === i) continue;
            const d = Math.hypot(nodes[j].x - a.x, nodes[j].y - a.y);
            if (d < LINK) near.push(j);
        }
        if (!near.length) return;
        const j = near[(Math.random() * near.length) | 0];
        packets.push({ from: i, to: j, t: 0, speed: 0.006 + Math.random() * 0.01 });
    }

    function step(dt, time) {

        for (const n of nodes) {
            n.x += n.vx * dt; n.y += n.vy * dt;
            if (n.x < -20) n.x = W + 20; else if (n.x > W + 20) n.x = -20;
            if (n.y < -20) n.y = H + 20; else if (n.y > H + 20) n.y = -20;
        }

        for (let k = packets.length - 1; k >= 0; k--) {
            packets[k].t += packets[k].speed * dt;
            if (packets[k].t >= 1) packets.splice(k, 1);
        }

        for (let k = rings.length - 1; k >= 0; k--) {
            rings[k].r += 0.9 * dt;
            rings[k].life -= 0.02 * dt;
            if (rings[k].life <= 0) rings.splice(k, 1);
        }

        if (!CHASE) return;
        const { P } = ghostRect();

        if (phase === 'caught') {

            ftimer -= dt;
            if (ftimer <= 0) placeChase();
            return;
        }

        let aheadGap = P;
        for (const g of ghosts) {
            const fwd = ((((g.p - hunter.p) * hunter.dir) % P) + P) % P;
            if (fwd < aheadGap) aheadGap = fwd;
        }
        if (aheadGap < 95) hunter.dir = -hunter.dir;
        const pspeed = 1.05 + Math.sin(time * 0.0016) * 0.3;
        const ppx = hunter.x, ppy = hunter.y;
        hunter.p += hunter.dir * pspeed * dt;
        const hpt = perimToXY(hunter.p);
        hunter.x = hpt.x; hunter.y = hpt.y;
        hunter.faceDir = Math.atan2(hunter.y - ppy, hunter.x - ppx) || hunter.faceDir;
        hunter.mouth = Math.abs(Math.sin(time * 0.012)) * 0.42;
        hunter.trail.push({ x: hunter.x, y: hunter.y, life: 1 });
        if (hunter.trail.length > 16) hunter.trail.shift();
        for (const tp of hunter.trail) tp.life -= 0.04 * dt;

        let caught = false;
        for (const g of ghosts) {
            let d = (((hunter.p - g.p) % P) + P) % P;
            if (d > P / 2) d -= P;
            const dir = Math.abs(d) < 0.5 ? g.dir : Math.sign(d);
            g.dir = dir;
            const gspeed = 0.78 + Math.min(Math.abs(d) / 500, 1) * 0.2;
            g.p += dir * gspeed * dt;
            const pt = perimToXY(g.p);
            g.x = pt.x; g.y = pt.y;
            g.bob += 0.03 * dt;
            if (g.blink > 0) { g.blink -= dt; }
            else { g.nextBlink -= dt; if (g.nextBlink <= 0) { g.blink = 7; g.nextBlink = 120 + Math.random() * 300; } }
            if (Math.abs(d) < 13) caught = true;
        }
        if (caught) {
            phase = 'caught';
            ftimer = 105;
            rings.push({ x: hunter.x, y: hunter.y, r: 3, life: 1 });
        }
    }

    function draw(time) {
        ctx.clearRect(0, 0, W, H);

        for (let i = 0; i < nodes.length; i++) {
            const a = nodes[i];
            for (let j = i + 1; j < nodes.length; j++) {
                const b = nodes[j];
                const dx = a.x - b.x, dy = a.y - b.y;
                const d = Math.hypot(dx, dy);
                if (d < LINK) {
                    const al = (1 - d / LINK) * 0.62;
                    ctx.strokeStyle = `rgba(${COL.mesh},${al.toFixed(3)})`;
                    ctx.lineWidth = 1;
                    ctx.beginPath();
                    ctx.moveTo(a.x, a.y); ctx.lineTo(b.x, b.y);
                    ctx.stroke();
                }
            }
        }

        for (const n of nodes) {
            ctx.fillStyle = `rgba(${COL.node},0.5)`;
            ctx.beginPath();
            ctx.arc(n.x, n.y, n.r, 0, Math.PI * 2);
            ctx.fill();
        }

        for (const p of packets) {
            const a = nodes[p.from], b = nodes[p.to];
            if (!a || !b) continue;
            const x = a.x + (b.x - a.x) * p.t;
            const y = a.y + (b.y - a.y) * p.t;
            const fade = Math.sin(p.t * Math.PI);
            ctx.fillStyle = `rgba(${COL.amber},${(0.6 * fade).toFixed(3)})`;
            ctx.shadowColor = `rgba(${COL.amber},0.4)`;
            ctx.shadowBlur = 3;
            ctx.beginPath();
            ctx.arc(x, y, 1.4, 0, Math.PI * 2);
            ctx.fill();
            ctx.shadowBlur = 0;
        }

        for (const r of rings) {
            ctx.strokeStyle = `rgba(${COL.amber},${(r.life * 0.5).toFixed(3)})`;
            ctx.lineWidth = 1;
            ctx.beginPath();
            ctx.arc(r.x, r.y, r.r, 0, Math.PI * 2);
            ctx.stroke();
        }

        if (!CHASE) return;

        const flashOn = phase !== 'caught' || (Math.floor(ftimer / 6) % 2 === 0);

        if (flashOn) for (const g of ghosts) drawGhost(g);

        for (const tp of hunter.trail) {
            if (tp.life <= 0) continue;
            ctx.fillStyle = `rgba(${COL.amber},${(tp.life * 0.18).toFixed(3)})`;
            ctx.beginPath();
            ctx.arc(tp.x, tp.y, 2.2 * tp.life, 0, Math.PI * 2);
            ctx.fill();
        }

        if (!flashOn) return;
        const R = 8.5;
        const m = hunter.mouth;
        ctx.save();
        ctx.translate(hunter.x, hunter.y);
        ctx.rotate(hunter.faceDir);
        ctx.fillStyle = `rgba(${COL.amber},0.85)`;
        ctx.shadowColor = `rgba(${COL.amber},0.5)`;
        ctx.shadowBlur = 7;
        ctx.beginPath();
        ctx.moveTo(0, 0);
        ctx.arc(0, 0, R, m, Math.PI * 2 - m);
        ctx.closePath();
        ctx.fill();
        ctx.shadowBlur = 0;
        ctx.restore();
    }

    function drawGhost(g) {
        const u = g.u;
        const ox = Math.round(g.x - (GW * u) / 2);
        const oy = Math.round(g.y - (GH * u) / 2 + Math.sin(g.bob) * 3);

        ctx.fillStyle = `rgba(${COL.amber},${g.alpha.toFixed(3)})`;
        for (let r = 0; r < GH; r++) {
            const row = GHOST[r];
            for (let c = 0; c < GW; c++) {
                if (row[c] !== ' ') ctx.fillRect(ox + c * u, oy + r * u, u, u);
            }
        }

        const blinking = g.blink > 0;
        for (const [ec, er] of EYES) {
            if (blinking) {
                ctx.fillStyle = 'rgba(238,238,238,0.95)';
                ctx.fillRect(ox + ec * u, oy + (er + 1) * u, 3 * u, u);
                continue;
            }

            ctx.fillStyle = 'rgba(238,238,238,0.95)';
            ctx.fillRect(ox + ec * u, oy + er * u, 3 * u, 3 * u);

            const cx = ox + (ec + 1.5) * u, cy = oy + (er + 1.5) * u;
            let dx = mouse.x - cx, dy = mouse.y - cy;
            const m = Math.hypot(dx, dy) || 1; dx /= m; dy /= m;
            const px = ec + 1 + Math.round(dx);
            const py = er + 1 + Math.round(dy);
            ctx.fillStyle = 'rgba(10,10,12,0.95)';
            ctx.fillRect(ox + px * u, oy + py * u, u, u);
        }
    }

    function loop(time) {
        if (!running) return;
        const dt = Math.min(2.4, (time - t0) / 16.67) || 1;
        t0 = time;
        step(dt * 0.55, time);
        draw(time);
        raf = requestAnimationFrame(loop);
    }

    function start() {
        running = true;
        t0 = performance.now();
        cancelAnimationFrame(raf);
        raf = requestAnimationFrame(loop);
    }
    function stop() { running = false; cancelAnimationFrame(raf); }

    function staticFrame() {
        draw(0);
    }

    readTheme();
    resize();

    if (reduce) {
        staticFrame();
    } else {
        start();
        document.addEventListener('visibilitychange', () => {
            if (document.hidden) stop(); else start();
        });
    }

    let mq = false;
    window.addEventListener('mousemove', (e) => {
        mouse.x = e.clientX; mouse.y = e.clientY; mouse.set = true;
        if (reduce && !mq) { mq = true; requestAnimationFrame(() => { staticFrame(); mq = false; }); }
    }, { passive: true });

    let rt;
    window.addEventListener('resize', () => {
        clearTimeout(rt);
        rt = setTimeout(() => { resize(); if (reduce) staticFrame(); }, 150);
    });

    new MutationObserver(() => { readTheme(); if (reduce) staticFrame(); })
        .observe(document.documentElement, { attributes: true, attributeFilter: ['data-theme'] });
})();
