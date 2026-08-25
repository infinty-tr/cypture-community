
(() => {
    'use strict';
    const API = window.location.origin;
    const WS = `${location.protocol === 'https:' ? 'wss' : 'ws'}://${location.host}`;
    const $ = (id) => document.getElementById(id);

    const state = {
        view: 'overview',
        scanId: null,
        ws: null,
        durTimer: null, startTime: null,
        liveRunning: false,
        openQ: null,
        newMode: 'full',
        newModel: 'free',
        term: null, fit: null, ttyWs: null,
    };
    const RUNNING = ['starting', 'running', 'awaiting_input'];

    function getCookie(name) {
        return document.cookie.split('; ').reduce((acc, c) => {
            const [k, v] = c.split('='); return k === name ? decodeURIComponent(v) : acc;
        }, '');
    }
    async function api(path, method = 'GET', body) {
        const opts = { method, headers: {}, credentials: 'same-origin' };
        if (body !== undefined) { opts.headers['Content-Type'] = 'application/json'; opts.body = JSON.stringify(body); }
        if (method !== 'GET') opts.headers['X-CSRF-Token'] = getCookie('cyp_csrf');
        const res = await fetch(`${API}${path}`, opts);
        if (res.status === 401) { location.href = '/login'; throw new Error('unauthorized'); }
        const data = await res.json().catch(() => ({}));
        if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
        return data;
    }
    function esc(s) { const d = document.createElement('div'); d.textContent = s == null ? '' : String(s); return d.innerHTML; }
    function flash(el, text, isErr) { if (!el) return; el.textContent = text; el.className = 'admin-msg' + (isErr ? ' error' : ''); setTimeout(() => { if (el.textContent === text) el.textContent = ''; }, 6000); }
    function setCount(id, n) { const el = $(id); if (!el) return; el.textContent = String(n); el.classList.toggle('zero', !n); }

    const STATUS_TR = {
        starting: 'starting', running: 'running', awaiting_input: 'awaiting decision',
        completed: 'completed', stopped: 'stopped', failed: 'failed',
    };
    function fmtDate(s) { if (!s) return ''; try { return new Date(s).toLocaleString('en-GB', { day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit' }); } catch { return s; } }
    function label(st) { return ({ starting: 'Running', running: 'Running', awaiting_input: 'Awaiting decision', completed: 'Completed', stopped: 'Stopped', failed: 'Failed' })[st] || st; }

    function bindNav() {
        document.querySelectorAll('.nav-item').forEach((b) => b.addEventListener('click', (e) => {
            if (b.classList.contains('nav-group-btn')) { e.stopPropagation(); toggleSettingsMenu(); return; }
            if (!b.dataset.view) return;
            navTo(b.dataset.view);
            const sec = b.dataset.sec;
            if (sec) setTimeout(() => { const el = document.getElementById(sec); if (el) el.scrollIntoView({ behavior: 'smooth', block: 'start' }); }, 90);
            closeSettingsMenu();
        }));
        document.addEventListener('click', (e) => {
            const g = document.getElementById('nav-settings-group');
            if (g && !g.contains(e.target)) closeSettingsMenu();
        });
        window.addEventListener('hashchange', routeFromHash);
    }
    function toggleSettingsMenu() {
        const g = document.getElementById('nav-settings-group'); if (!g) return;
        const open = g.classList.toggle('open');
        const btn = g.querySelector('.nav-group-btn'); if (btn) btn.setAttribute('aria-expanded', open ? 'true' : 'false');
    }
    function closeSettingsMenu() {
        const g = document.getElementById('nav-settings-group'); if (!g) return;
        g.classList.remove('open');
        const btn = g.querySelector('.nav-group-btn'); if (btn) btn.setAttribute('aria-expanded', 'false');
    }
    function navTo(view) {
        if (view === 'live' && state.scanId) location.hash = `scan/${state.scanId}`;
        else location.hash = view;
    }
    function routeFromHash() {
        const h = (location.hash || '').replace(/^#/, '');
        if (h.startsWith('scan/')) { const id = h.slice(5); if (id && id !== state.scanId) { openScan(id); return; } showView('live'); return; }
        showView(['overview', 'new', 'queue', 'scans', 'findings', 'traffic', 'users', 'questions', 'audit'].includes(h) ? h : 'overview');
    }
    function showView(view) {
        state.view = view;
        document.querySelectorAll('.nav-item').forEach((b) => b.classList.toggle('active', b.dataset.view === view));
        document.querySelectorAll('.view').forEach((v) => v.classList.toggle('active', v.id === `view-${view}`));

        document.body.classList.toggle('cockpit', view === 'live');
        if (view !== 'live') closeTTY();
        if (view === 'overview') { loadStats(); loadRecent(); }
        if (view === 'queue') loadQueue();
        if (view === 'scans') loadScans();
        if (view === 'users') { loadSettings(); loadPool(); }
        if (view === 'questions') loadQuestions();
        if (view === 'audit') loadAudit();
    }

    async function loadStats() {
        try {
            const s = await api('/api/admin/stats');
            $('st-pending').textContent = s.pending; $('st-running').textContent = s.running;
            $('st-scans').textContent = s.scans; $('st-findings').textContent = s.findings;
            $('ov-sub').textContent = `${s.running} active · ${s.pending} pending`;
            setCount('nav-queue-count', s.pending);
        } catch {}
    }
    async function loadRecent() {
        try {
            const scans = ((await api('/api/scans')).scans || []).slice(0, 6);
            const wrap = $('ov-recent');
            if (!scans.length) { wrap.innerHTML = '<p class="prompt-note">No scans yet.</p>'; return; }
            wrap.innerHTML = scans.map(scanCard).join('');
            bindScanCards(wrap);
        } catch {}
    }

    function bindNewScan() {
        document.querySelectorAll('#ns-mode button').forEach((b) => b.addEventListener('click', () => {
            state.newMode = b.dataset.mode;
            document.querySelectorAll('#ns-mode button').forEach((x) => x.classList.toggle('active', x === b));
        }));
        document.querySelectorAll('#ns-model button').forEach((b) => b.addEventListener('click', () => {
            state.newModel = b.dataset.model;
            document.querySelectorAll('#ns-model button').forEach((x) => x.classList.toggle('active', x === b));
        }));
        $('ns-start')?.addEventListener('click', startNewScan);
    }
    function splitCsv(s) { return (s || '').split(',').map((x) => x.trim()).filter(Boolean); }
    async function startNewScan() {
        const inc = splitCsv($('ns-inc').value);
        if (!inc.length) { flash($('ns-msg'), 'Enter at least one include scope pattern.', true); return; }
        $('ns-start').disabled = true;
        try {
            const r = await api('/api/admin/scans', 'POST', {
                title: $('ns-title').value.trim(),
                scope_includes: inc,
                scope_excludes: splitCsv($('ns-exc').value),
                scope_text: $('ns-text').value.trim(),
                operator_prompt: ($('ns-prompt')?.value || '').trim(),
                test_credentials: ($('ns-creds')?.value || '').trim(),
                mode: state.newMode,
                model: state.newModel,
            });
            flash($('ns-msg'), '✅ Scan started.');
            $('ns-inc').value = ''; $('ns-exc').value = ''; $('ns-text').value = ''; $('ns-title').value = '';
            if ($('ns-prompt')) $('ns-prompt').value = '';
            if ($('ns-creds')) $('ns-creds').value = '';
            location.hash = `scan/${r.scan_id}`;
        } catch (e) { flash($('ns-msg'), e.message, true); }
        finally { $('ns-start').disabled = false; }
    }

    async function loadScans() {
        try {
            const scans = (await api('/api/scans')).scans || [];
            const wrap = $('scan-list');
            if (!scans.length) { wrap.innerHTML = '<div class="scan-empty"><div class="empty-icon">▱</div><p class="empty-text">No scans yet</p></div>'; return; }
            wrap.innerHTML = scans.map(scanCard).join('');
            bindScanCards(wrap);
            $('scans-sub').textContent = `${scans.length} scans`;
            setCount('nav-scans-count', scans.length);
        } catch (e) { $('scan-list').innerHTML = `<p class="prompt-note">Could not load list: ${esc(e.message)}</p>`; }
    }
    function scanCard(it) {
        const st = it.status || 'starting';
        return `<div class="scan-card" data-scan="${esc(it.scan_id)}">
            <div class="sc-main">
                <div class="sc-target">${esc(it.seed || it.title || 'Scan')}</div>
                <div class="sc-meta">${esc(fmtDate(it.created_at))} · ${esc(it.mode || 'full')}</div>
            </div>
            <div class="sc-side">
                <div class="sc-find"><b>${it.findings || 0}</b>findings</div>
                <span class="cyp-pill ${esc(st)}">${esc(STATUS_TR[st] || st)}</span>
                <button class="btn btn-ghost btn-sm sc-restart" data-restart="${esc(it.scan_id)}" title="Rescan the same target">Rescan</button>
                <button class="btn btn-ghost btn-sm sc-del" data-del="${esc(it.scan_id)}" title="Delete scan">Delete</button>
            </div>
        </div>`;
    }
    function bindScanCards(wrap) {
        wrap.querySelectorAll('.scan-card[data-scan]').forEach((c) => c.addEventListener('click', (e) => {
            if (e.target.closest('.sc-del') || e.target.closest('.sc-restart')) return;
            location.hash = `scan/${c.dataset.scan}`;
        }));
        wrap.querySelectorAll('.sc-restart').forEach((b) => b.addEventListener('click', async (e) => {
            e.stopPropagation();
            if (!confirm('Start a new scan for the same target?')) return;
            try {
                const r = await api(`/api/admin/scans/${b.dataset.restart}/restart`, 'POST', {});
                if (r.status === 'stopping') { alert(r.message || 'The running scan is stopping; try again once it finishes.'); loadScans(); return; }
                if (r.scan_id) location.hash = `scan/${r.scan_id}`;
            } catch (err) { alert('Could not start: ' + err.message); }
        }));
        wrap.querySelectorAll('.sc-del').forEach((b) => b.addEventListener('click', async (e) => {
            e.stopPropagation();
            if (!confirm('Delete this scan (and all of its events/findings)?')) return;
            try {
                const r = await api(`/api/admin/scans/${b.dataset.del}/delete`, 'POST', {});
                if (r.status === 'stopping') alert(r.message || 'The scan is stopping; delete again once it finishes.');
                loadScans();
            } catch (err) { alert('Could not delete: ' + err.message); }
        }));
    }

    async function openScan(scanId) {
        state.scanId = scanId;
        showView('live');
        showLivePanel('cockpit');
        Scanner.clearFeed(); Findings.clearFindings(); Traffic.clear();
        setStat('stat-vulns', '0'); setCount('nav-findings-count', 0); setCount('live-find-count', 0); setStat('stat-status', 'Loading'); setStat('stat-duration', '00:00');
        clearLiveQuestion();
        let st;
        try { st = await api(`/api/scans/${scanId}`); }
        catch (e) { Scanner.addFeedItem('error', `Could not load scan: ${e.message}`); return; }

        $('live-title').textContent = (st.engagement && st.engagement.seed) || 'Live Scan';
        $('live-sub').textContent = `mode: ${(st.engagement && st.engagement.mode) || 'full'}`;
        setStat('stat-status', label(st.status));

        try {
            const { findings } = await api(`/api/scans/${scanId}/findings`);
            (findings || []).forEach((f) => Findings.addFinding(mapFinding(f)));
            setStat('stat-vulns', Findings.count()); setCount('nav-findings-count', Findings.count()); setCount('live-find-count', Findings.count());
        } catch {}

        try {
            const { traffic } = await api(`/api/scans/${scanId}/traffic`);
            (traffic || []).forEach((t) => Traffic.add(t));
        } catch {}

        try {
            const { events } = await api(`/api/scans/${scanId}/events`);
            (events || []).forEach((e) => Scanner.addEvent(LEVEL_FEED[e.level] || 'info', e));
        } catch {}

        connectWS(scanId);
        state.liveRunning = RUNNING.includes(st.status);
        Scanner.setLive(state.liveRunning);
        $('live-stop').style.display = state.liveRunning ? 'inline-flex' : 'none';
        $('report-button').style.display = ['completed', 'stopped', 'failed'].includes(st.status) ? 'inline-flex' : 'none';
        if (st.open_question) renderLiveQuestion(scanId, st.open_question);
        if (state.liveRunning) startDurationFrom(st.started_at);
        else { stopDuration(); setDurationFrom(st.started_at, st.ended_at); }
    }

    function connectWS(scanId, isReconnect) {
        if (state.ws) try { state.ws.close(1000); } catch {}

        if (isReconnect) { Scanner.clearFeed(); Findings.clearFindings(); Traffic.clear(); }
        const ws = new WebSocket(`${WS}/ws/scan/${scanId}`);
        ws.onmessage = (ev) => { try { onWs(JSON.parse(ev.data)); } catch {} };
        ws.onclose = (e) => { if (e.code !== 1000 && state.scanId === scanId && state.liveRunning) setTimeout(() => { if (state.scanId === scanId) connectWS(scanId, true); }, 3000); };
        state.ws = ws;
    }
    const LEVEL_FEED = { info: 'info', success: 'success', warning: 'warning', error: 'error', thought: 'thought', action: 'action', finding: 'finding', system: 'info' };
    function onWs(m) {
        switch (m.type) {
            case 'event': {
                if (m.category === 'usage' && m.data) {

                    return;
                }
                if (m.category === 'finding' && m.data) {
                    Findings.addFinding(mapFinding(m.data));
                    Scanner.addLiveFinding(m.data);
                    setStat('stat-vulns', Findings.count()); setCount('nav-findings-count', Findings.count()); setCount('live-find-count', Findings.count());
                }
                Scanner.addEvent(LEVEL_FEED[m.level] || 'info', m);
                return;
            }
            case 'finding':
                if (m.data) { Findings.addFinding(mapFinding(m.data)); setStat('stat-vulns', Findings.count()); setCount('nav-findings-count', Findings.count()); setCount('live-find-count', Findings.count()); }
                return;
            case 'traffic':
                if (m.data) Traffic.add(m.data);
                return;
            case 'question': return renderLiveQuestion(state.scanId, m);
            case 'question_resolved': { clearLiveQuestion(); Scanner.addFeedItem('info', '⚙ Decision applied.'); return; }
            case 'lifecycle': {
                state.liveRunning = false; stopDuration();
                $('live-stop').style.display = 'none';
                setStat('stat-status', label(m.status));
                if (['completed', 'stopped', 'failed'].includes(m.status)) $('report-button').style.display = 'inline-flex';
                Scanner.finishAllPanes(); Scanner.setLive(false);
                Scanner.addFeedItem('info', m.status === 'completed' ? '✅ Process completed.' : (m.status === 'stopped' ? '⏹ Stopped.' : '❌ Error.'));
                return;
            }
        }
    }

    let lqTimer = null;
    function clearLiveQuestion() {
        if (lqTimer) { clearInterval(lqTimer); lqTimer = null; }
        const box = $('live-question'); if (box) box.style.display = 'none';
    }
    function renderLiveQuestion(scanId, q) {
        const box = $('live-question');
        box.style.display = 'block';
        box.className = 'live-question-card';
        box.innerHTML = `<div class="framed" style="padding:16px;margin-top:16px;border-color:var(--amber-line)">
            <div class="prompt-note">⚙ Depth decision — awaiting operator response <span id="lq-count" class="lq-count"></span></div>
            <p style="margin:8px 0 12px"><b>${esc(q.prompt)}</b></p>
            <div class="cyp-row-actions" id="lq-opts"></div></div>`;
        const opts = $('lq-opts');
        (q.options || []).forEach((o) => {
            const b = document.createElement('button');
            b.className = 'btn btn-sm ' + (o.id === q.default_id ? 'btn-primary' : 'btn-ghost');
            b.textContent = o.label + (o.id === q.default_id ? ' (default)' : '');
            b.addEventListener('click', async () => {
                try { await api(`/api/scans/${scanId}/answer`, 'POST', { question_id: q.question_id, option_id: o.id }); clearLiveQuestion(); }
                catch (e) { Scanner.addFeedItem('error', e.message); }
            });
            opts.appendChild(b);
        });

        if (lqTimer) clearInterval(lqTimer);
        const deadline = q.expires_at ? new Date(q.expires_at).getTime() : 0;
        const tick = () => {
            const c = $('lq-count'); if (!c) { clearInterval(lqTimer); return; }
            if (!deadline) { c.textContent = ''; return; }
            const left = Math.max(0, Math.round((deadline - Date.now()) / 1000));
            c.textContent = `(auto “${defLabel(q)}” in ${left}s)`;
            if (left <= 0) clearInterval(lqTimer);
        };
        tick();
        lqTimer = setInterval(tick, 1000);
    }
    function defLabel(q) {
        const d = (q.options || []).find((o) => o.id === q.default_id);
        return d ? d.label : 'continue';
    }

    async function openReport(scanId) {
        let md = '';
        try { const res = await fetch(`${API}/api/scans/${scanId}/report`, { credentials: 'same-origin' }); md = await res.text(); }
        catch { md = '# Could not load report'; }
        const back = document.createElement('div');
        back.className = 'cyp-modal-back';
        const body = (typeof Md !== 'undefined') ? Md.render(md) : `<pre>${md.replace(/</g, '&lt;')}</pre>`;
        back.innerHTML = `<div class="cyp-modal">
            <div class="cyp-modal-head"><h3>Scan Report</h3><span class="spacer"></span>
                <button class="btn btn-sm btn-ghost" id="rep-dl">↓ Download</button>
                <button class="btn btn-sm btn-ghost" id="rep-close">✕</button></div>
            <div class="cyp-modal-body"><div class="md-body">${body}</div></div></div>`;
        document.body.appendChild(back);
        const close = () => back.remove();
        back.addEventListener('click', (e) => { if (e.target === back) close(); });
        back.querySelector('#rep-close').addEventListener('click', close);
        back.querySelector('#rep-dl').addEventListener('click', () => {
            const blob = new Blob([md], { type: 'text/markdown' }); const a = document.createElement('a');
            a.href = URL.createObjectURL(blob); a.download = `cypture-report-${scanId.slice(0, 8)}.md`; a.click(); URL.revokeObjectURL(a.href);
        });
    }

    function mapFinding(f) {
        return {
            db_id: f.id,
            severity: f.severity, title: f.title, endpoint: f.endpoint, method: f.method,
            vuln_type: f.vuln_type, evidence: f.evidence, remediation: f.remediation,
            poc: f.poc, cvss: f.cvss, confidence: f.confidence,
            request: f.request, response: f.response,
            verified: f.verified, verify_note: f.verify_note,
        };
    }

    function setStat(id, v) { const el = $(id); if (el) el.textContent = v; }
    function startDurationFrom(startedAt) {
        state.startTime = startedAt ? new Date(startedAt).getTime() : Date.now(); stopDuration();
        state.durTimer = setInterval(() => { const s = Math.max(0, Math.floor((Date.now() - state.startTime) / 1000)); setStat('stat-duration', hhmm(s)); }, 1000);
    }
    function setDurationFrom(a, b) { if (!a) { setStat('stat-duration', '00:00'); return; } const x = new Date(a).getTime(), y = b ? new Date(b).getTime() : Date.now(); setStat('stat-duration', hhmm(Math.max(0, Math.floor((y - x) / 1000)))); }
    function hhmm(s) { const h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60), sec = s % 60; return (h > 0 ? h + ':' : '') + String(m).padStart(2, '0') + ':' + String(sec).padStart(2, '0'); }
    function stopDuration() { if (state.durTimer) { clearInterval(state.durTimer); state.durTimer = null; } }

    function bindLive() {
        $('live-back')?.addEventListener('click', () => { location.hash = 'scans'; });
        $('lt-cockpit')?.addEventListener('click', () => showLivePanel('cockpit'));
        $('lt-terminal')?.addEventListener('click', () => showLivePanel('terminal'));
        $('clear-feed-btn')?.addEventListener('click', () => Scanner.clearFeed());
        $('export-findings-btn')?.addEventListener('click', () => Findings.exportFindings());

        $('report-button')?.addEventListener('click', () => { if (state.scanId) window.open(`${API}/api/scans/${state.scanId}/report?format=html`, '_blank'); });
        $('live-stop')?.addEventListener('click', async () => {
            if (!state.scanId) return;
            try { await api(`/api/scans/${state.scanId}/stop`, 'POST', {}); Scanner.addFeedItem('warning', 'Durduruluyor…'); }
            catch (e) { Scanner.addFeedItem('error', e.message); }
        });
    }

    function showLivePanel(which) {
        const ck = $('live-cockpit'), tm = $('live-terminal');
        const bc = $('lt-cockpit'), bt = $('lt-terminal');
        if (which === 'terminal') {
            if (ck) ck.style.display = 'none';
            if (tm) tm.style.display = '';
            bc?.classList.remove('active'); bt?.classList.add('active');

            requestAnimationFrame(() => requestAnimationFrame(() => {
                if (state.scanId) connectTTY(state.scanId);
                fitTerm();
            }));
        } else {
            if (tm) tm.style.display = 'none';
            if (ck) ck.style.display = '';
            bt?.classList.remove('active'); bc?.classList.add('active');
            closeTTY();
        }
    }
    function ensureTerm() {
        if (state.term || typeof Terminal === 'undefined') return;
        state.term = new Terminal({
            cursorBlink: false, scrollback: 4000,
            fontFamily: "'JetBrains Mono', ui-monospace, monospace", fontSize: 13, lineHeight: 1.2,
            theme: { background: '#07090a', foreground: '#ece9df', cursor: '#ffb000', selectionBackground: 'rgba(255,176,0,.25)' },
        });
        if (typeof FitAddon === 'undefined' || !FitAddon.FitAddon) {
            console.error('[cypture] xterm FitAddon failed to load');
        } else {
            try { state.fit = new FitAddon.FitAddon(); state.term.loadAddon(state.fit); }
            catch (e) { console.error('[cypture] FitAddon init', e); }
        }
        state.term.open($('xterm'));
        state.term.onData((d) => { if (state.ttyWs && state.ttyWs.readyState === 1) { try { state.ttyWs.send(d); } catch {} } });
        try {
            const el = $('xterm');
            if (el && 'ResizeObserver' in window) { state.termRO = new ResizeObserver(() => fitTerm()); state.termRO.observe(el); }
        } catch {}
        window.addEventListener('resize', fitTerm);
    }
    function fitTerm() {
        if (!state.term) return;
        const el = $('xterm');
        if (!el || el.clientHeight < 8 || el.clientWidth < 8) return;
        try { if (state.fit && state.fit.fit) state.fit.fit(); } catch (e) { console.warn('[cypture] fit', e); }
        sendResize();
    }
    function sendResize() {
        if (state.ttyWs && state.ttyWs.readyState === 1 && state.term && state.term.rows > 0) {
            try { state.ttyWs.send(JSON.stringify({ cols: state.term.cols, rows: state.term.rows })); } catch {}
        }
    }
    function closeTTY() { if (state.ttyWs) { try { state.ttyWs.close(1000); } catch {} state.ttyWs = null; } }
    function connectTTY(scanId) {
        closeTTY();
        ensureTerm();
        if (state.term) state.term.reset();
        const ws = new WebSocket(`${WS}/ws/scan/${scanId}/tty`);
        ws.binaryType = 'arraybuffer';
        ws.onmessage = (ev) => {
            if (!state.term) return;
            if (typeof ev.data === 'string') state.term.write(ev.data);
            else state.term.write(new Uint8Array(ev.data));
        };
        ws.onopen = () => { fitTerm(); requestAnimationFrame(() => fitTerm()); setTimeout(fitTerm, 120); };
        ws.onclose = (e) => { if (e.code !== 1000 && state.scanId === scanId && state.liveRunning) setTimeout(() => { if (state.scanId === scanId) connectTTY(scanId); }, 3000); };
        state.ttyWs = ws;
    }

    function settingsBody() {
        const prov = state.setProvider || 'openrouter';
        const body = { runner_model: $('set-model').value.trim(), reasoning_model: ($('set-reasoning') ? $('set-reasoning').value.trim() : ''), llm_provider: prov };
        const k = $('set-key').value.trim();
        if (k) body.llm_api_key = k;
        return body;
    }
    async function loadSettings() {
        try {
            const s = await api('/api/admin/settings');
            $('set-model').value = s.runner_model || '';
            if ($('set-reasoning')) $('set-reasoning').value = s.reasoning_model || '';
            $('set-key-cur').textContent = s.llm_api_key_set ? `Current: ${s.llm_api_key_masked}` : 'No key set';
            state.setProvider = s.llm_provider || 'openrouter';
            document.querySelectorAll('#set-provider button').forEach((b) => b.classList.toggle('active', b.dataset.prov === state.setProvider));
        } catch {}
    }
    async function validateSettings() {
        $('set-validate').disabled = true;
        flash($('set-msg'), '⏳ Validating (provider test ~20s)…');
        try {
            const r = await api('/api/admin/settings/validate', 'POST', settingsBody());
            flash($('set-msg'), (r.valid ? '✅ ' : '❌ ') + r.message, !r.valid);
        } catch (e) { flash($('set-msg'), e.message, true); }
        finally { $('set-validate').disabled = false; }
    }
    async function saveSettings() {
        $('set-save').disabled = true;
        try {
            await api('/api/admin/settings', 'POST', settingsBody());
            $('set-key').value = '';
            flash($('set-msg'), '✅ Saved. New scans will use this provider/model.');
            loadSettings();
        } catch (e) { flash($('set-msg'), e.message, true); }
        finally { $('set-save').disabled = false; }
    }

    async function loadPool() {
        try {
            const { keys } = await api('/api/admin/api-keys');
            const tb = $('pool-tbody');
            if (!tb) return;
            tb.innerHTML = (keys || []).map((k) => {
                const st = k.disabled ? 'disabled' : (k.active ? 'active' : 'invited');
                const stTxt = k.disabled ? 'Exhausted/Invalid' : (k.active ? 'Active' : 'Off');
                return `<tr><td>${esc(k.provider)}</td><td><code>${esc(k.key_masked)}</code>${k.label ? ' · ' + esc(k.label) : ''}</td>
                    <td>${esc(k.model || '—')}</td><td>${k.users}</td><td>${k.usage_count}</td>
                    <td><span class="cyp-pill ${st}">${stTxt}</span>${k.last_error ? `<br><span class="prompt-note">${esc(k.last_error)}</span>` : ''}</td>
                    <td><div class="cyp-row-actions">
                        <button class="btn btn-ghost btn-sm" data-pool-act="toggle" data-id="${k.id}">${k.active && !k.disabled ? 'Disable' : 'Enable'}</button>
                        <button class="btn btn-ghost btn-sm" data-pool-act="delete" data-id="${k.id}">Delete</button>
                    </div></td></tr>`;
            }).join('') || '<tr><td colspan="7"><span class="prompt-note">Pool is empty — the single key above is used.</span></td></tr>';
            tb.querySelectorAll('button[data-pool-act]').forEach((b) => b.addEventListener('click', () => poolAction(b.dataset.poolAct, b.dataset.id)));
        } catch {}
    }
    function poolBody() {
        return { provider: state.poolProvider || 'openrouter', model: $('pool-model').value.trim(), key_value: $('pool-key').value.trim(), label: $('pool-label').value.trim() };
    }
    async function validatePoolKey() {
        const body = poolBody();
        if (!body.key_value) { flash($('pool-msg'), 'Key is required', true); return; }
        $('pool-validate').disabled = true;
        flash($('pool-msg'), '⏳ Validating (provider test ~20s)…');
        try {
            const r = await api('/api/admin/api-keys', 'POST', { ...body, validate: true });
            flash($('pool-msg'), (r.valid ? '✅ ' : '❌ ') + r.message, !r.valid);
        } catch (e) { flash($('pool-msg'), e.message, true); }
        finally { $('pool-validate').disabled = false; }
    }
    async function addPoolKey() {
        const body = poolBody();
        if (!body.key_value) { flash($('pool-msg'), 'Key is required', true); return; }
        $('pool-add').disabled = true;
        try {
            await api('/api/admin/api-keys', 'POST', body);
            $('pool-key').value = ''; $('pool-label').value = '';
            flash($('pool-msg'), '✅ Added to pool.');
            loadPool();
        } catch (e) { flash($('pool-msg'), e.message, true); }
        finally { $('pool-add').disabled = false; }
    }
    async function poolAction(act, id) {
        try {
            if (act === 'delete') {
                if (!confirm('Delete this key from the pool? Associated scans move to the next key.')) return;
                await api(`/api/admin/api-keys/${id}`, 'DELETE');
            } else {
                await api(`/api/admin/api-keys/${id}/toggle`, 'POST', {});
            }
            loadPool();
        } catch (e) { flash($('pool-msg'), e.message, true); }
    }

    async function loadAudit() {
        try {
            const { logs } = await api('/api/admin/audit?limit=200');
            const tb = $('audit-tbody');
            tb.innerHTML = (logs || []).map((l) => `<tr>
                <td>${esc(fmtDate(l.created_at))}</td><td>${esc(l.actor || '—')}</td>
                <td><b>${esc(l.action)}</b></td><td>${esc(l.target_type)}${l.target_id ? ' ' + esc(String(l.target_id).slice(0, 8)) : ''}</td>
                <td>${esc(l.detail || '')}</td><td>${esc(l.ip || '')}</td></tr>`).join('') || '<tr><td colspan="6"><span class="prompt-note">No records.</span></td></tr>';
        } catch (e) { $('audit-tbody').innerHTML = `<tr><td colspan="6"><span class="prompt-note">Could not load: ${esc(e.message)}</span></td></tr>`; }
    }

    function queueBusy() {
        const wrap = $('queue-wrap');
        if (!wrap) return false;
        if (wrap.contains(document.activeElement)) return true;
        return [...wrap.querySelectorAll('textarea, input[type="password"], input[id^="key-prov-"], input[id^="key-model-"]')]
            .some((el) => (el.value || '').trim() !== '');
    }
    async function loadQueue() {
        try {
            const sub = (await api('/api/admin/engagements?status=submitted')).engagements || [];
            const rev = (await api('/api/admin/engagements?status=under_review')).engagements || [];
            const items = [...sub, ...rev];
            setCount('nav-queue-count', items.length);
            const wrap = $('queue-wrap');
            if (!items.length) { wrap.innerHTML = '<p class="prompt-note">No pending scope requests.</p>'; return; }
            wrap.innerHTML = items.map(renderQueueItem).join('');
            items.forEach((e) => {
                $(`accept-${e.id}`)?.addEventListener('click', () => decide(e.id, 'accept'));
                $(`reject-${e.id}`)?.addEventListener('click', () => decide(e.id, 'reject'));
                $(`key-val-btn-${e.id}`)?.addEventListener('click', () => validateClientKey(e.id));
            });
        } catch (e) { $('queue-wrap').innerHTML = `<p class="prompt-note">Could not load queue: ${esc(e.message)}</p>`; }
    }
    function renderQueueItem(e) {
        const inc = (e.scope_includes || []).join(', ');
        const exc = (e.scope_excludes || []).join(', ');
        return `<div class="framed" style="padding:16px;margin-bottom:14px;position:relative">
          <div style="display:flex;justify-content:space-between;gap:10px;flex-wrap:wrap">
            <div><b>${esc(e.company_name || e.client_email || '—')}</b> <span class="prompt-note">(${esc(e.client_email || '')})</span></div>
            <span class="cyp-pill ${esc(e.status)}">${esc(e.status)}</span>
          </div>
          <table class="cyp-table" style="margin-top:10px">
            <tr><th>Title</th><td>${esc(e.title || '—')}</td></tr>
            <tr><th>Derived Target</th><td><b>${esc(e.seed || '—')}</b></td></tr>
            <tr><th>Mode</th><td>${esc(e.mode)}</td></tr>
            <tr><th>Include Scope</th><td><b>${esc(inc || '—')}</b></td></tr>
            <tr><th>Exclude Scope</th><td>${esc(exc || '—')}</td></tr>
            <tr><th>Scope Note</th><td>${esc(e.scope_text || '—')}</td></tr>
          </table>
          <div class="cyp-field" style="margin-top:12px"><label>Approved INCLUDE scope (comma-separated)</label><input class="cyp-input" id="inc-${e.id}" value="${esc(inc)}" placeholder="*.company.com"></div>
          <div class="cyp-field"><label>Approved EXCLUDE scope (comma-separated)</label><input class="cyp-input" id="exc-${e.id}" value="${esc(exc)}" placeholder="legacy.company.com"></div>
          <div class="cyp-field"><label>Admin Note</label><textarea class="cyp-textarea" id="notes-${e.id}" placeholder="Scope verified…"></textarea></div>
          <div class="cyp-field"><label>Extra directive for the agent (optional)</label><textarea class="cyp-textarea" id="op-${e.id}" placeholder="e.g. focus on /api/v2 · try JWT RS256, key confusion · skip noisy fuzzing · emphasize business-logic/response manipulation"></textarea></div>
          <details class="byok-card" style="margin-top:10px" ${e.client_has_key ? '' : 'open'}>
            <summary>Provide an API key for this scan <span class="byok-state">${e.client_has_key ? '✓ a dedicated key is set' : '— no key provided'}</span></summary>
            <div class="byok-body">
              <p class="prompt-note">If no key was provided, you can supply one here for this scan. The key is saved to the account; the scan runs with this key. Leave empty to use the current setting/.env.</p>
              <div class="cyp-field"><label>Provider (opt. — derived from the model prefix if empty)</label><input class="cyp-input" id="key-prov-${e.id}" placeholder="openrouter / openai / anthropic" autocomplete="off"></div>
              <div class="cyp-field"><label>API key</label><input class="cyp-input" id="key-val-${e.id}" type="password" placeholder="sk-or-... / sk-..." autocomplete="off"></div>
              <div class="cyp-field"><label>Model (opt.)</label><input class="cyp-input" id="key-model-${e.id}" placeholder="openai/gpt-4o · openrouter/anthropic/claude-3-5-sonnet" autocomplete="off"></div>
              <div class="cyp-row-actions"><button class="btn btn-ghost btn-sm" id="key-val-btn-${e.id}" type="button">🔍 Validate Key</button><span class="admin-msg" id="key-msg-${e.id}"></span></div>
            </div>
          </details>
          <div class="cyp-row-actions" style="margin-top:10px">
            <button class="btn btn-primary btn-sm" id="accept-${e.id}">Accept &amp; Start</button>
            <button class="btn btn-stop btn-sm" id="reject-${e.id}">Reject</button>
            <span class="admin-msg" id="qmsg-${e.id}"></span>
          </div></div>`;
    }
    async function decide(id, action) {
        const notes = $(`notes-${id}`)?.value || '';
        const msg = $(`qmsg-${id}`);

        const aBtn = $(`accept-${id}`), rBtn = $(`reject-${id}`);
        if (aBtn) aBtn.disabled = true;
        if (rBtn) rBtn.disabled = true;
        if (action === 'accept' && aBtn) aBtn.textContent = 'Validating…';
        try {
            if (action === 'accept') {
                const body = { admin_notes: notes, operator_prompt: ($(`op-${id}`)?.value || '').trim(), scope_includes: splitCsv($(`inc-${id}`)?.value), scope_excludes: splitCsv($(`exc-${id}`)?.value) };

                const kv = ($(`key-val-${id}`)?.value || '').trim();
                if (kv) {
                    body.llm_api_key = kv;
                    body.llm_provider = ($(`key-prov-${id}`)?.value || '').trim();
                    body.runner_model = ($(`key-model-${id}`)?.value || '').trim();
                }
                const r = await api(`/api/admin/engagements/${id}/accept`, 'POST', body);
                flash(msg, '✅ Accepted, the process has started.');
                if (r.scan_id) setTimeout(() => { location.hash = `scan/${r.scan_id}`; }, 600);
            } else { await api(`/api/admin/engagements/${id}/reject`, 'POST', { admin_notes: notes }); flash(msg, 'Rejected.'); }
            loadQueue(); loadStats();
        } catch (e) {
            flash(msg, e.message, true);

            if (aBtn) { aBtn.disabled = false; aBtn.textContent = 'Accept & Start'; }
            if (rBtn) rBtn.disabled = false;
        }
    }

    async function validateClientKey(id) {
        const msg = $(`key-msg-${id}`);
        const key = ($(`key-val-${id}`)?.value || '').trim();
        if (!key) { flash(msg, 'Enter a key first.', true); return; }
        flash(msg, 'Validating… (a few seconds)');
        try {
            const r = await api('/api/admin/settings/validate', 'POST', {
                llm_api_key: key,
                runner_model: ($(`key-model-${id}`)?.value || '').trim(),
                llm_provider: ($(`key-prov-${id}`)?.value || '').trim(),
            });
            flash(msg, (r.valid ? '✓ ' : '✗ ') + (r.message || ''), !r.valid);
        } catch (e) { flash(msg, e.message, true); }
    }

    async function loadQuestions() {
        try {
            const { questions } = await api('/api/admin/questions');
            setCount('nav-q-count', (questions || []).length);
            const wrap = $('questions-wrap');
            if (!questions || !questions.length) { wrap.innerHTML = '<p class="prompt-note">No pending decisions.</p>'; return; }
            wrap.innerHTML = questions.map((q) => `
                <div class="framed" style="padding:14px;margin-bottom:12px">
                  <div class="prompt-note">${esc(q.company_name || q.client_email || '')} · ${esc(q.seed || '')}</div>
                  <p style="margin:8px 0 10px"><b>${esc(q.prompt)}</b></p>
                  <div class="cyp-row-actions" id="qopts-${q.question_id}"></div>
                  <span class="admin-msg" id="qamsg-${q.question_id}"></span></div>`).join('');
            questions.forEach((q) => {
                const box = $(`qopts-${q.question_id}`);
                (q.options || []).forEach((o) => {
                    const b = document.createElement('button');
                    b.className = 'btn btn-ghost btn-sm';
                    b.textContent = o.label + (o.id === q.default_id ? ' (default)' : '');
                    b.addEventListener('click', () => answerQuestion(q.scan_id, q.question_id, o.id));
                    box.appendChild(b);
                });
            });
        } catch {}
    }
    async function answerQuestion(scanId, questionId, optionId) {
        try { await api(`/api/scans/${scanId}/answer`, 'POST', { question_id: questionId, option_id: optionId }); loadQuestions(); }
        catch (e) { flash($(`qamsg-${questionId}`), e.message, true); }
    }

    async function logout() { try { await api('/api/auth/logout', 'POST', {}); } catch {} location.href = '/login'; }

    async function init() {
        try { const me = await api('/api/auth/me'); if (me.user.role !== 'admin') { location.href = '/login'; return; } }
        catch { return; }
        bindNav(); bindNewScan(); bindLive();

        Findings.enableAdmin({
            onSeverity: async (fid, sev) => { try { await api(`/api/admin/findings/${fid}`, 'POST', { severity: sev }); } catch (e) { alert('Could not update: ' + e.message); } },
            onDelete: async (fid) => { if (!confirm('Delete this finding?')) return; try { await api(`/api/admin/findings/${fid}`, 'DELETE'); Findings.removeByDbId(fid); setStat('stat-vulns', Findings.count()); setCount('nav-findings-count', Findings.count()); setCount('live-find-count', Findings.count()); } catch (e) { alert('Could not delete: ' + e.message); } },
        });
        $('set-save')?.addEventListener('click', saveSettings);
        $('set-validate')?.addEventListener('click', validateSettings);
        $('pool-add')?.addEventListener('click', addPoolKey);
        $('pool-validate')?.addEventListener('click', validatePoolKey);
        document.querySelectorAll('#pool-provider button').forEach((b) => b.addEventListener('click', () => {
            state.poolProvider = b.dataset.prov;
            document.querySelectorAll('#pool-provider button').forEach((x) => x.classList.toggle('active', x === b));
            const m = $('pool-model');
            if (m && !m.value) {
                if (b.dataset.prov === 'openrouter') m.value = 'openrouter/openai/gpt-4o-mini';
                if (b.dataset.prov === 'openai') m.value = 'openai/gpt-4o-mini';
                if (b.dataset.prov === 'anthropic') m.value = 'anthropic/claude-3-5-sonnet';
                if (b.dataset.prov === 'deepseek') m.value = 'deepseek/deepseek-chat';
                if (b.dataset.prov === 'groq') m.value = 'groq/llama-3.1-70b';
            }
        }));
        document.querySelectorAll('#set-provider button').forEach((b) => b.addEventListener('click', () => {
            state.setProvider = b.dataset.prov;
            document.querySelectorAll('#set-provider button').forEach((x) => x.classList.toggle('active', x === b));

            const m = $('set-model');
            if (b.dataset.prov === 'openrouter' && !m.value.startsWith('openrouter/')) m.value = 'openrouter/openai/gpt-4o-mini';
            if (b.dataset.prov === 'openai' && !m.value.startsWith('openai/')) m.value = 'openai/gpt-4o-mini';
            if (b.dataset.prov === 'anthropic' && !m.value.startsWith('anthropic/')) m.value = 'anthropic/claude-3-5-sonnet';
            if (b.dataset.prov === 'deepseek' && !m.value.startsWith('deepseek/')) m.value = 'deepseek/deepseek-chat';
        }));
        $('logout-btn')?.addEventListener('click', logout);
        $('audit-refresh')?.addEventListener('click', loadAudit);
        routeFromHash();

        loadStats();
        setInterval(loadStats, 6000);
        setInterval(() => { if (state.view === 'queue' && !queueBusy()) loadQueue(); }, 6000);
        setInterval(() => { if (state.view === 'scans') loadScans(); }, 6000);
        setInterval(() => { if (state.view === 'questions') loadQuestions(); }, 3000);
        setInterval(() => { if (state.view === 'overview') loadRecent(); }, 8000);
    }

    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
    else init();
})();
