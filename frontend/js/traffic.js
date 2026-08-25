
const Traffic = (() => {
    let counter = 0;
    const seen = new Set();
    const byId = new Map();
    const esc = (s) => String(s == null ? '' : s).replace(/[&<>"']/g, (c) => (
        { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

    function statusClass(st) {
        st = +st || 0;
        if (st >= 500) return 'st-5';
        if (st >= 400) return 'st-4';
        if (st >= 300) return 'st-3';
        if (st >= 200) return 'st-2';
        return 'st-0';
    }
    function fmtBytes(n) {
        n = +n || 0;
        if (n < 1024) return n + ' B';
        if (n < 1048576) return (n / 1024).toFixed(1) + ' KB';
        return (n / 1048576).toFixed(1) + ' MB';
    }
    function fmtHeaders(h) {
        if (!h) return '';
        try {
            const o = JSON.parse(h);
            if (o && typeof o === 'object') return Object.entries(o).map(([k, v]) => `${k}: ${v}`).join('\n');
        } catch { /* plain text */ }
        return String(h);
    }

    // reqPath returns path+QUERY. t.path drops the query string — but that's exactly
    // where most web payloads live (?id=1' OR 1=1, ?item=../../etc/passwd), so showing
    // t.path alone made the displayed request not match what the agent actually sent.
    // t.url carries the full target (scheme://host:port/path?query); pull path+query from it.
    function reqPath(t) {
        if (t && t.url) {
            try { const u = new URL(t.url); return (u.pathname || '/') + (u.search || ''); } catch {}
            const m = String(t.url).match(/^[a-z][a-z0-9+.\-]*:\/\/[^/]+(\/[^\s]*)/i);
            if (m) return m[1];
        }
        return (t && t.path) || '/';
    }

    function rowHtml(t, n) {
        const st = +t.status || 0;
        const m = (t.method || 'GET').toUpperCase();
        const p = reqPath(t);
        return `<td class="tr-c-n">${n}</td>
            <td class="tr-c-m"><span class="tr-m ${m.toLowerCase()}">${esc(m)}</span></td>
            <td class="tr-c-s"><span class="tr-s ${statusClass(st)}">${st || '—'}</span></td>
            <td class="tr-c-h">${esc(t.host || '')}</td>
            <td class="tr-c-p" title="${esc(p)}">${esc(p)}</td>
            <td class="tr-c-l">${t.length != null ? fmtBytes(t.length) : ''}</td>
            <td class="tr-c-t">${(t.duration_ms != null && t.duration_ms !== '') ? t.duration_ms + ' ms' : ''}</td>`;
    }

    function add(t) {
        if (!t) return;
        if (t.seq != null) { if (seen.has(t.seq)) return; seen.add(t.seq); }
        const tb = document.getElementById('traffic-tbody');
        if (!tb) return;
        const empty = document.getElementById('traffic-empty');
        if (empty) empty.style.display = 'none';
        counter++;
        const id = `tr-${counter}`;
        byId.set(id, t);
        const tr = document.createElement('tr');
        tr.className = 'tr-tr';
        tr.id = id;
        tr.dataset.q = `${t.method || ''} ${t.host || ''} ${reqPath(t)} ${t.status || ''}`.toLowerCase();
        tr.innerHTML = rowHtml(t, counter);
        tr.addEventListener('click', () => select(id));
        const f = document.getElementById('traffic-filter');
        if (f && f.value.trim()) tr.style.display = tr.dataset.q.includes(f.value.toLowerCase().trim()) ? '' : 'none';
        tb.appendChild(tr);
        // Cap the DOM (so a long scan doesn't bloat it); drop the oldest.
        while (tb.children.length > 4000) {
            const first = tb.firstChild;
            if (first) { byId.delete(first.id); tb.removeChild(first); }
        }
        const badge = document.getElementById('nav-traffic-count');
        if (badge) { badge.textContent = String(counter); badge.classList.toggle('zero', counter === 0); }
    }

    function select(id) {
        const t = byId.get(id);
        if (!t) return;
        document.querySelectorAll('#traffic-tbody .tr-tr.sel').forEach((r) => r.classList.remove('sel'));
        const row = document.getElementById(id);
        if (row) row.classList.add('sel');
        const st = +t.status || 0;
        const reqRaw = `${(t.method || 'GET')} ${reqPath(t)}\n${fmtHeaders(t.req_headers)}\n\n${t.req_body || ''}`.trim();
        const respRaw = `HTTP ${st || '—'}\n${fmtHeaders(t.resp_headers)}\n\n${t.resp_body || ''}`.trim();
        const bodyLen = String(t.resp_body || '').length;
        const trunc = (t.true_len && t.true_len > bodyLen) ? ` <span class="tr-trunc">(body ${t.true_len}B — truncated)</span>` : '';
        const errLine = t.error ? `<div class="tr-dp-err">✗ ${esc(t.error)}</div>` : '';
        const dp = document.getElementById('traffic-detail');
        if (!dp) return;
        dp.innerHTML = `${errLine}<div class="tr-dp-cols">
            <div class="tr-dp-col"><div class="tr-dp-lbl">Request</div><pre class="tr-pre">${esc(reqRaw)}</pre></div>
            <div class="tr-dp-col"><div class="tr-dp-lbl">Response${trunc}</div><pre class="tr-pre">${esc(respRaw)}</pre></div>
        </div>`;
    }

    function applyFilter(q) {
        q = (q || '').toLowerCase().trim();
        document.querySelectorAll('#traffic-tbody .tr-tr').forEach((row) => {
            row.style.display = (!q || (row.dataset.q || '').includes(q)) ? '' : 'none';
        });
    }

    function clear() {
        counter = 0;
        seen.clear();
        byId.clear();
        const tb = document.getElementById('traffic-tbody');
        if (tb) tb.innerHTML = '';
        const dp = document.getElementById('traffic-detail');
        if (dp) dp.innerHTML = '<div class="tr-detail-empty">Select a request above to see its details.</div>';
        const empty = document.getElementById('traffic-empty');
        if (empty) empty.style.display = '';
        const badge = document.getElementById('nav-traffic-count');
        if (badge) { badge.textContent = '0'; badge.classList.add('zero'); }
        const f = document.getElementById('traffic-filter');
        if (f) f.value = '';
    }

    function count() { return counter; }

    return { add, select, applyFilter, clear, count };
})();
