
const Scanner = (() => {
    'use strict';

    function getTimestamp(at) {
        let d = at ? new Date(at) : new Date();
        if (isNaN(d.getTime())) d = new Date();
        return d.toLocaleTimeString('tr-TR', {
            hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false
        });
    }

    function escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text == null ? '' : String(text);
        return div.innerHTML;
    }

    function inlineMd(text) {
        let s = escapeHtml(text == null ? '' : String(text));
        s = s.replace(/\*\*([^*]+)\*\*/g, '<b>$1</b>');
        s = s.replace(/__([^_]+)__/g, '<b>$1</b>');
        s = s.replace(/`([^`]+)`/g, '<code class="feed-code">$1</code>');
        s = s.replace(/(^|[\s(>])\*([^*\s][^*]*)\*/g, '$1<i>$2</i>');
        return s;
    }

    // Render one line of agent output. Block-level markdown (#, lists, code
    // fences, tables, quotes) → full Md.render so `# Heading` becomes a real big
    // heading. Everything else → tight inline markdown so HTTP probes stay compact.
    // `m` flag → matches a block construct on ANY line, not just the first. The
    // brain's reasoning often starts with prose ("I've now analyzed…") and embeds a
    // table/code-fence LATER; without `m` that fell to inline rendering and showed raw
    // `|---|`. Md.render handles mixed prose+table+fence fine, so detect-anywhere is safe.
    const BLOCK_RE = /^\s*(#{1,6}\s|[-*+]\s|\d+[.)]\s|>\s?|\|.*\||```)/m;

    function renderBody(msg) {
        const s = String(msg == null ? '' : msg);

        const mt = s.match(/^(\s*(?:\[[^\]]+\]\s*)?(?:↳|»|~|·|•)?\s*)/);
        const prefix = mt ? mt[1] : '';
        const rest = s.slice(prefix.length);
        if (typeof Md !== 'undefined' && BLOCK_RE.test(rest)) {
            const pfx = prefix.trim() ? `<span class="feed-pfx">${escapeHtml(prefix.trim())}</span> ` : '';
            return `${pfx}<div class="md-body feed-md">${Md.render(rest)}</div>`;
        }
        return `<span class="feed-message">${inlineMd(s)}</span>`;
    }

    function nearBottom(el) {
        return el.scrollHeight - el.scrollTop - el.clientHeight < 40;
    }
    function stick(el, wasNear) {
        if (wasNear) el.scrollTop = el.scrollHeight;
    }

    function appendLine(container, type, msg, at) {
        if (!container) return;
        const wasNear = nearBottom(container);
        const last = container.lastElementChild;
        if (last && last.dataset && last.dataset.msg === msg) {
            const n = (parseInt(last.dataset.count || '1', 10) || 1) + 1;
            last.dataset.count = String(n);
            const body = last.querySelector('.feed-body');
            let badge = last.querySelector('.feed-rep');
            if (!badge && body) { badge = document.createElement('span'); badge.className = 'feed-rep'; body.appendChild(badge); }
            if (badge) badge.textContent = ' ×' + n;
            stick(container, wasNear);
            return;
        }
        const div = document.createElement('div');
        div.className = `feed-line feed-item-${type}`;
        div.dataset.msg = msg;
        div.innerHTML = `<span class="feed-ts">${getTimestamp(at)}</span><div class="feed-body">${renderBody(msg)}</div>`;
        container.appendChild(div);
        stick(container, wasNear);
    }

    const panes = new Map();
    let activePaneId = null;

    let bannerTimer = null;
    function showBanner(level, msg) {
        let host = document.getElementById('ck-banner');
        if (!host) {
            host = document.createElement('div');
            host.id = 'ck-banner';
            document.body.appendChild(host);
        }
        const err = level === 'error';
        host.className = 'ck-banner ' + (err ? 'ck-banner-error' : 'ck-banner-warn') + ' show';
        host.innerHTML =
            `<span class="ck-banner-ic">${err ? '⛔' : '⚠'}</span>` +
            `<span class="ck-banner-msg"></span>` +
            `<button class="ck-banner-x" aria-label="close">×</button>`;
        host.querySelector('.ck-banner-msg').textContent = String(msg || '').slice(0, 240);
        host.querySelector('.ck-banner-x').onclick = () => host.classList.remove('show');
        clearTimeout(bannerTimer);

        if (!err) bannerTimer = setTimeout(() => host.classList.remove('show'), 14000);
    }

    function grid() { return document.getElementById('agent-grid'); }
    function systemFeed() { return document.getElementById('terminal-feed'); }
    function treeHost() { return document.getElementById('agent-tree'); }
    function liveFindHost() { return document.getElementById('live-findings'); }
    function signalHost() { return document.getElementById('signal-stream'); }

    function waveOf(label) {
        const s = (label || '').toLocaleUpperCase('tr');
        if (/RAPOR|REPORT|SCRIBE/.test(s)) return 'WAVE 4 — Report';
        if (/ZİNCİR|ZINCIR|SÖMÜR|SOMUR|EXPLOIT|DOMINO|DOĞRULAMA|DOGRULAMA|VALID|ORACLE|OPERAT|REAPER|DERİN|DERIN/.test(s)) return 'WAVE 3 — Deep';
        if (/KEŞİF|KEŞIF|KESIF|RECON|GHOST|ENVANTER|YÜZEY/.test(s)) return 'WAVE 1 — Recon';
        if (/KOORDİN|KOORDIN|MAESTRO|BAĞLANTI|BAGLANTI|NEXUS|CONNECT/.test(s)) return 'WAVE 0 — Coordination';
        if (/WEB|VIPER|API|CIPHER|KİMLİK|KIMLIK|SPECTER|AUTH|İSTEMCİ|ISTEMCI|PHANTOM|CLIENT|BULUT|NIMBUS|CLOUD|FUZZ|SWARM|KAPI|WARDEN|TEST/.test(s)) return 'WAVE 2 — Test';
        return 'WAVE 2 — Test';
    }

    const treeWaves = new Map();
    const treeLeaves = new Map();

    function ensureTreeLeaf(paneId, label) {
        let leaf = treeLeaves.get(paneId);
        if (leaf) {
            const lbl = leaf.el.querySelector('.tree-label');
            if (lbl && label && lbl.textContent !== label) lbl.textContent = label;
            return leaf;
        }
        const host = treeHost();
        if (!host) return null;
        const empty = host.querySelector('.ck-empty');
        if (empty) empty.remove();
        const waveName = waveOf(label);
        let wave = treeWaves.get(waveName);
        if (!wave) {
            wave = document.createElement('div');
            wave.className = 'tree-wave';
            wave.innerHTML = `<div class="tree-wave-label">${escapeHtml(waveName)}</div>`;
            host.appendChild(wave);
            treeWaves.set(waveName, wave);
        }
        const el = document.createElement('div');
        el.className = 'tree-leaf'; el.dataset.pane = paneId;
        el.innerHTML = `<span class="tree-dot"></span><span class="tree-label">${escapeHtml(label || 'Module')}</span><span class="tree-badge" style="display:none">0</span>`;
        const badge = el.querySelector('.tree-badge');
        el.addEventListener('click', () => {
            setActive(paneId);
            const p = panes.get(paneId);
            if (p && p.tile) p.tile.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
        });
        wave.appendChild(el);
        leaf = { el, badge, count: 0 };
        treeLeaves.set(paneId, leaf);
        return leaf;
    }

    function ensurePane(id, label) {
        let p = panes.get(id);
        if (p) {
            if (label && p.label !== label) {
                p.label = label;
                const l = p.tile.querySelector('.agent-tile-label');
                if (l) l.textContent = label;
            }
            return p;
        }
        const g = grid();
        if (!g) return null;
        const tile = document.createElement('div');
        tile.className = 'agent-tile'; tile.dataset.pane = id;
        tile.innerHTML =
            `<div class="agent-tile-head"><span class="agent-tile-dot"></span>` +
            `<span class="agent-tile-label">${escapeHtml(label || 'Module')}</span></div>` +
            `<div class="agent-tile-body"></div>`;
        g.appendChild(tile);
        p = { tile, body: tile.querySelector('.agent-tile-body'), label: label || 'Module', last: Date.now() };
        panes.set(id, p);
        ensureTreeLeaf(id, label || 'Module');
        return p;
    }

    function setActive(id) {
        activePaneId = id;
        panes.forEach((pn, pid) => pn.tile.classList.toggle('active', pid === id));
        treeLeaves.forEach((lf, pid) => lf.el.classList.toggle('active', pid === id));
    }

    function closePane(id, ok) {
        const p = panes.get(id);
        if (p) p.tile.classList.add(ok ? 'done' : 'closed');
        const leaf = treeLeaves.get(id);
        if (leaf) leaf.el.classList.add(ok ? 'done' : 'closed');
    }

    function finishAllPanes() { panes.forEach((_, id) => closePane(id, true)); }

    function addEvent(type, ev) {
        const data = ev.data || {};
        const paneId = data.pane_id || 'system';
        const status = data.pane_status;
        const label = data.pane_module || ev.module || 'Module';
        const msg = ev.message || '';
        const at = ev.created_at;

        if (paneId === 'system') {
            addFeedItem(type, (ev.module ? `[${ev.module}] ` : '') + msg, at);
            return;
        }
        const p = ensurePane(paneId, label);
        if (!p) { addFeedItem(type, (ev.module ? `[${ev.module}] ` : '') + msg, at); return; }
        if (status === 'close') closePane(paneId, true);
        setActive(paneId);
        appendLine(p.body, type, msg, at);
        p.last = Date.now();
        p.tile.classList.remove('stalled');
        if (type === 'warning' || type === 'error') showBanner(type, (label ? `[${label}] ` : '') + msg);
        maybeSignal(msg, at);
        markActivity();
    }

    function addFeedItem(type, message, at) {
        const msg = String(message == null ? '' : message);
        appendLine(systemFeed(), type, msg, at);
        if (type === 'warning' || type === 'error') showBanner(type, msg);
        maybeSignal(msg, at);
        markActivity();
    }

    const SIGNAL_RE = /^\s*(?:💡|⚠️?|🔗|🚩|❗)|^\s*(?:S[İI]NYAL|D[İI]KKAT|Z[İI]NC[İI]R)\s*:/i;
    function signalClass(msg) {
        if (/^\s*(?:⚠️?|🚩|❗)|D[İI]KKAT\s*:/i.test(msg)) return 'warn';
        if (/^\s*🔗|Z[İI]NC[İI]R\s*:/i.test(msg)) return 'chain';
        return 'sig';
    }
    function maybeSignal(msg, at) {
        if (!msg || !SIGNAL_RE.test(msg)) return;
        const host = signalHost();
        if (!host) return;
        const empty = host.querySelector('.ck-empty');
        if (empty) empty.remove();
        const wasNear = nearBottom(host);
        const div = document.createElement('div');
        div.className = `signal-line ${signalClass(msg)}`;
        div.innerHTML = `<span class="sl-ts">${getTimestamp(at)}</span><div class="sl-body">${renderBody(msg)}</div>`;
        host.appendChild(div);
        stick(host, wasNear);
    }

    const liveFindRows = new Map();
    let liveFindCount = 0;
    function addLiveFinding(data) {
        if (!data) return;
        const title = String(data.title || '').trim();
        if (!title) return;

        const key = (typeof Findings !== 'undefined' && Findings.dedupKey) ? Findings.dedupKey(data) : title.toLowerCase();
        const existing = liveFindRows.get(key);
        if (existing) {

            if (data.verified) {
                const p = existing.querySelector('.lf-pending');
                if (p) p.outerHTML = '<span class="lf-ok" title="verified">✓</span>';
                const sv = String(data.severity || '').toLowerCase();
                if (sv) { existing.className = `lf-row sev-${sv}`; const se = existing.querySelector('.lf-sev'); if (se) se.textContent = sv; }
            }
            return;
        }

        const leaf = data.pane_id && treeLeaves.get(data.pane_id);
        if (leaf) { leaf.count++; if (leaf.badge) { leaf.badge.textContent = String(leaf.count); leaf.badge.style.display = ''; } }
        const host = liveFindHost();
        if (!host) return;
        const empty = host.querySelector('.ck-empty');
        if (empty) empty.remove();
        const sev = String(data.severity || 'info').toLowerCase();
        const method = String(data.method || '').toUpperCase();
        const ep = String(data.endpoint || '');
        const ok = data.verified ? '<span class="lf-ok" title="verified">✓</span>' : '<span class="lf-pending" title="awaiting verification">⏳</span>';

        const epText = (method + ' ' + ep).trim();
        const note = String(data.vuln_type || '').trim();
        const row = document.createElement('div');
        row.className = `lf-row sev-${sev}`;
        row.title = title;
        row.innerHTML =
            `<span class="lf-sev">${escapeHtml(sev)}</span>` +
            `<div class="lf-main"><div class="lf-title">${inlineMd(title)}</div>` +
            (epText ? `<div class="lf-ep">${inlineMd(epText)}</div>` : '') +
            (note ? `<div class="lf-note">${inlineMd(note)}</div>` : '') +
            `</div>${ok}`;
        row.addEventListener('click', () => {
            location.hash = 'findings';
            if (typeof Findings !== 'undefined' && Findings.focusByTitle) setTimeout(() => Findings.focusByTitle(title), 50);
        });
        host.appendChild(row);
        liveFindRows.set(key, row);
        host.scrollTop = host.scrollHeight;

    }

    let lastTs = 0, liveRunning = false, liveTimer = null;
    function markActivity() { lastTs = Date.now(); }

    function checkStalled() {
        const now = Date.now();
        panes.forEach((p) => {
            if (!p.tile || p.tile.classList.contains('done') || p.tile.classList.contains('closed')) return;
            p.tile.classList.toggle('stalled', now - (p.last || now) > 25000);
        });
    }
    function updateLive() {
        checkStalled();
        const el = document.getElementById('live-ind');
        if (!el) return;
        el.classList.toggle('alive', liveRunning && (Date.now() - lastTs < 15000));
    }
    function setLive(on) {
        liveRunning = !!on;
        if (on) { lastTs = Date.now(); if (!liveTimer) liveTimer = setInterval(updateLive, 1000); }
        updateLive();
    }

    function clearFeed() {
        const feed = systemFeed();
        if (feed) feed.innerHTML = '';
        const g = grid();
        if (g) g.innerHTML = '';
        panes.clear();
        activePaneId = null;

        treeWaves.clear(); treeLeaves.clear();
        const tree = treeHost(); if (tree) tree.innerHTML = '<div class="ck-empty">Modules will appear here as a tree once the scan starts.</div>';
        const lf = liveFindHost(); if (lf) lf.innerHTML = '<div class="ck-empty">Findings appear here in real time as they are discovered (verified ✓).</div>';
        const sg = signalHost(); if (sg) sg.innerHTML = '<div class="ck-empty">The engine comments here when it finds an interesting lead.</div>';
        liveFindRows.clear(); liveFindCount = 0;
        const c = document.getElementById('live-find-count'); if (c) c.textContent = '0';
        addFeedItem('info', 'Terminal cleared.');
    }

    return { addEvent, addFeedItem, addLiveFinding, clearFeed, finishAllPanes, setLive, getTimestamp, escapeHtml };
})();
