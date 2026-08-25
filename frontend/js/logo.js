
(() => {
    'use strict';

    const stage = document.querySelector('.logo-anim');
    if (!stage) return;
    const letters = Array.from(stage.querySelectorAll('.ll'));
    const pac = stage.querySelector('.logo-pac');
    if (letters.length !== 7 || !pac) return;

    const reduce = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    const N = letters.length;

    let CELL = 14, LEAD = 20, HOP = 22;
    const wait  = (ms) => new Promise(r => setTimeout(r, ms));
    const pos   = (x, hop) => `translate(${x}px, calc(-50% - ${hop || 0}px))`;
    const ppos  = (x) => `translate(${x}px, -50%)`;
    const slotX = (s) => LEAD + s * CELL;

    let order = letters.slice();

    function measure() {
        const w = letters[0].getBoundingClientRect().width || 12;
        CELL = Math.round(w + 3);
        LEAD = Math.round(CELL * 1.45);
        HOP  = Math.round(CELL * 1.55);
        stage.style.width = (LEAD + N * CELL + 14) + 'px';
    }

    function layoutAll() {
        order.forEach((el, s) => { el.style.transform = pos(slotX(s)); });
    }
    function showAll() {
        letters.forEach(el => { el.style.opacity = '1'; });
    }
    const setPac = (x) => { pac.style.transform = ppos(x); };

    function flee(el, fromX, toX) {
        return new Promise(res => {
            const a = el.animate([
                { transform: pos(fromX, 0) },
                { transform: pos((fromX + toX) / 2, HOP), offset: 0.5 },
                { transform: pos(toX, 0) }
            ], { duration: 430, easing: 'cubic-bezier(.4,-0.25,.5,1.3)', fill: 'forwards' });
            a.onfinish = () => { el.style.transform = pos(toX, 0); a.cancel(); res(); };
            a.oncancel = () => res();
        });
    }

    async function escapeRound() {
        setPac(slotX(0) - CELL * 0.45);
        await wait(170);
        const front = order[0];
        const fromX = slotX(0), toX = slotX(N - 1);
        for (let i = 1; i < N; i++) order[i].style.transform = pos(slotX(i - 1));
        await flee(front, fromX, toX);
        order.push(order.shift());
        setPac(slotX(0) - CELL * 1.0);
        await wait(70);
    }

    async function eatRound() {
        await wait(320);
        for (let s = 0; s < N; s++) {
            const el = order[s];
            setPac(slotX(s) - CELL * 0.1);
            await wait(210);
            el.style.opacity = '0';
            el.style.transform = pos(slotX(s)) + ' scale(.25)';
        }
        setPac(slotX(N));
        await wait(450);
    }

    function snapReset() {
        letters.forEach(el => { el.style.transition = 'none'; });
        pac.style.transition = 'none';
        order = letters.slice();
        showAll();
        layoutAll();
        setPac(slotX(0) - CELL * 1.0);
        void stage.offsetWidth;
        letters.forEach(el => { el.style.transition = ''; });
        pac.style.transition = '';
    }

    async function loop() {
        while (true) {
            await wait(650);
            for (let k = 0; k < N; k++) await escapeRound();
            await eatRound();
            snapReset();
            await wait(450);
        }
    }

    let started = false;
    function start() {
        if (started) return;
        started = true;
        measure();
        order = letters.slice();
        showAll();
        layoutAll();
        if (reduce) { pac.style.display = 'none'; return; }
        setPac(slotX(0) - CELL * 1.0);
        loop();
    }

    if (document.fonts && document.fonts.ready) {
        document.fonts.ready.then(start);
        setTimeout(start, 1200);
    } else {
        start();
    }
})();
