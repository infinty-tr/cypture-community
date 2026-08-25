
const Term = (() => {
    'use strict';
    const dom = (id) => document.getElementById(id);
    const PHASES = ['RECON', 'ANALYSIS', 'TEST', 'DEEP', 'REPORT'];
    const MAX_LINES = 1200;

    let phaseIdx = -1;
    const experts = {};
    let live = false;

    const REDACT = [
        [/\bcypture(?:-mcp(?:-server)?)?\b/gi, 'request engine'],
        [/\bmcp\b/gi, ''],
        [/\bcypture-agent(?:-go)?\b/gi, 'engine'],
        [/\b(anthropic|claude|deepseek|openrouter|openai|gpt-?4[a-z0-9.\-]*|gemini|qwen|kimi|glm)\b/gi, 'engine'],
        [/\bsk-[A-Za-z0-9_\-]{6,}\b/g, '••••'],
        [/\b(sqlmap|nuclei|ffuf|gobuster|nmap|burp|metasploit|hydra|wpscan|nikto)\b/gi, 'scanner'],
        [/\b(curl|wget|bash|sh|python3?|\/bin\/[a-z]+)\b/gi, 'command'],
        [/\bcypture-orchestrator\b/gi, 'Cypture'],
    ];
    function redact(s) {
        if (s == null) return '';
        let out = String(s);
        for (const [re, to] of REDACT) out = out.replace(re, to);
        return out.replace(/\s{2,}/g, ' ').trim();
    }
    function esc(s) { const d = document.createElement('div'); d.textContent = s == null ? '' : String(s); return d.innerHTML; }
    function ts() {
        const d = new Date(); const p = (n) => String(n).padStart(2, '0');
        return p(d.getHours()) + ':' + p(d.getMinutes()) + ':' + p(d.getSeconds());
    }

    function reset() {
        phaseIdx = -1;
        for (const k in experts) delete experts[k];
        const t = dom('terminal'); if (t) t.innerHTML = '';
        renderPhasebar(); renderExperts();
        line('info', 'Cypture ready. Every step will stream here live once a scan starts.');
    }

    function setLive(on) {
        live = !!on;
        const ind = dom('live-ind'); if (ind) ind.classList.toggle('on', live);
    }

    function phaseFrom(text) {
        const w = (text || '').toLocaleUpperCase('tr');
        if (/(RAPOR|REPORT|TAMAMLAND|SONLAND|DUR)/.test(w)) return 4;
        if (/(DERİN|DERIN|DEEP|SÖMÜR|EXPLOIT)/.test(w)) return 3;
        if (/(TEST|DALGA|ZAFİYET|ZAFIYET|PROBE)/.test(w)) return 2;
        if (/(ANALİZ|ANALIZ|TRIAGE|DEĞERLEND)/.test(w)) return 1;
        if (/(KEŞİF|KESIF|RECON|ENVANTER|YÜZEY)/.test(w)) return 0;
        return -1;
    }
    function bumpPhase(text) {
        const p = phaseFrom(text);
        if (p > phaseIdx) { phaseIdx = p; renderPhasebar(); }
    }
    function renderPhasebar() {
        const bar = dom('term-phasebar'); if (!bar) return;
        bar.innerHTML = PHASES.map((name, i) => {
            let dotCls = 'ph-todo', dot = '○';
            if (phaseIdx >= 0 && i < phaseIdx) { dotCls = 'ph-done'; dot = '●'; }
            else if (i === phaseIdx) { dotCls = 'ph-now'; dot = '◉'; }
            const sep = i < PHASES.length - 1 ? '<span class="ph-sep">─</span>' : '';
            return `<span class="ph ${dotCls}"><span class="ph-dot">${dot}</span> ${esc(name)}</span>${sep}`;
        }).join('');
    }

    function touchExpert(moduleName, status) {
        const m = (moduleName || '').trim();
        if (!m || m === 'Çekirdek' || m === 'Metre' || m === 'Tarama Motoru' ||
            m === 'Kapsam Denetimi' || m === 'Operatör' || m === 'Operatör Sorusu' ||
            m === 'Bilgi Tabanı') return;
        if (!experts[m]) experts[m] = { status: 'running' };
        if (status === 'close') experts[m].status = 'done';
        else if (status === 'open') experts[m].status = 'running';
        renderExperts();
    }
    function renderExperts() {
        const wrap = dom('term-experts'); if (!wrap) return;
        const keys = Object.keys(experts);
        if (!keys.length) { wrap.innerHTML = '<span class="exp-empty">specialists will appear here once assigned…</span>'; return; }
        wrap.innerHTML = keys.map((k) => {
            const st = experts[k].status;
            const glyph = st === 'done' ? '✓' : '●';
            return `<span class="exp-chip ${st}"><span class="exp-g">${glyph}</span> ${esc(redact(k))}</span>`;
        }).join('');
    }

    function line(level, text, moduleName) {
        const t = dom('terminal'); if (!t) return;
        const cls = ({ info: 'info', success: 'success', warning: 'warning', error: 'error', thought: 'thought', action: 'action', finding: 'finding', system: 'info' })[level] || 'info';
        const tag = moduleName ? `<span class="feed-mod">${esc(redact(moduleName))}</span>` : '';
        const row = document.createElement('div');
        row.className = 'feed-line feed-item-' + cls;
        row.innerHTML = `<span class="feed-ts">${ts()}</span><div class="feed-body">${tag}<span class="feed-message">${esc(redact(text))}</span></div>`;
        const atBottom = (t.scrollTop + t.clientHeight) >= (t.scrollHeight - 40);
        t.appendChild(row);
        while (t.childElementCount > MAX_LINES) t.removeChild(t.firstChild);
        if (atBottom) t.scrollTop = t.scrollHeight;
    }

    function event(m) {
        if (!m) return;
        if (m.category === 'usage') return;
        const data = m.data || {};
        const mod = data.pane_module || m.module || '';
        if (data.pane_status) touchExpert(mod, data.pane_status);
        else if (mod) touchExpert(mod, '');
        bumpPhase((m.message || '') + ' ' + mod);
        if (m.message) line(m.level || 'info', m.message, mod);
    }

    function finding(d) {
        if (!d) return;
        const sev = (d.severity || 'info').toLocaleUpperCase('tr');
        const where = d.endpoint ? ' · ' + d.endpoint : '';
        line('finding', `🚩 ${sev} — ${d.title || 'finding'}${where}`, d.pane_module);
    }

    function lifecycle(status) {
        setLive(false);
        for (const k in experts) if (experts[k].status !== 'done') experts[k].status = 'done';
        renderExperts();
        if (status === 'completed') { phaseIdx = 4; renderPhasebar(); line('success', '✅ Scan completed.'); }
        else if (status === 'stopped') line('warning', '⏹ Scan stopped.');
        else if (status === 'failed') line('error', '❌ Scan ended with an error; you can try again.');
    }

    return { reset, setLive, event, finding, lifecycle, line };
})();
