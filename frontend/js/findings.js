
const Findings = (() => {
    'use strict';

    const SEVERITY_COLORS = {
        critical: { bg: 'rgba(239, 68, 68, 0.15)', text: '#ef4444', border: 'rgba(239, 68, 68, 0.25)' },
        high:     { bg: 'rgba(249, 115, 22, 0.15)', text: '#f97316', border: 'rgba(249, 115, 22, 0.25)' },
        medium:   { bg: 'rgba(245, 158, 11, 0.15)', text: '#f59e0b', border: 'rgba(245, 158, 11, 0.25)' },
        low:      { bg: 'rgba(59, 130, 246, 0.15)',  text: '#3b82f6', border: 'rgba(59, 130, 246, 0.25)' },
        info:     { bg: 'rgba(107, 114, 128, 0.15)', text: '#6b7280', border: 'rgba(107, 114, 128, 0.25)' }
    };

    const METHOD_CLASSES = {
        GET: 'method-get',
        POST: 'method-post',
        PUT: 'method-put',
        DELETE: 'method-delete',
        PATCH: 'method-post',
        OPTIONS: 'method-get',
        HEAD: 'method-get'
    };

    let findings = [];
    let findingCounter = 0;

    const byKey = new Map();

    function normKey(finding) {

        if (finding.db_id != null && finding.db_id !== '') return 'id:' + finding.db_id;
        const fam = findingFamilyJS(finding.title, finding.vuln_type || finding.vtype || finding.type);
        const path = findingPathJS(finding.endpoint);
        if (fam && path) return fam + '|' + path;
        return String(finding.title || '').trim().toLowerCase();
    }

    function findingFamilyJS(title, vulnType) {
        const s = String((title || '') + ' ' + (vulnType || '')).toLowerCase();
        const has = (...subs) => subs.some((x) => s.includes(x));
        if (has('sql injection', 'sqli', 'sql enjeksiyon')) return 'sqli';
        if (has('cross-site script', 'xss')) return 'xss';
        if (has('ssrf', 'server-side request')) return 'ssrf';
        if (has('idor', 'bola', 'broken object', 'yetkisiz nesne')) return 'idor';
        if (has('path traversal', 'lfi', 'local file', '/etc/passwd', 'dizin gezme')) return 'lfi';
        if (has('rce', 'remote code', 'command inj', 'komut enjeksiyon', 'deserial', 'ssti', 'template inj')) return 'rce';
        if (has('open redirect', 'açık yönlendirme')) return 'open-redirect';
        if (has('cors')) return 'cors';
        if (has('clickjack', 'x-frame', 'çerçeveleme')) return 'clickjacking';
        if (has('csrf', 'cross-site request forgery', 'sahte istek')) return 'csrf';
        if (has('debug')) return 'debug-disclosure';
        if (has('brute', 'rate limit', 'rate-limit', 'kaba kuvvet')) return 'rate-limit';
        if ((has('httponly', 'secure flag', 'samesite', 'cookie')) && has('flag', 'httponly', 'secure', 'samesite')) return 'cookie-flags';
        if (has('security header', 'güvenlik başlık', 'missing header', 'eksik başlık', 'hsts', 'content-security-policy', 'csp')) return 'headers';
        if (has('information disclosure', 'info disclosure', 'bilgi sızınt', 'bilgi sizint', 'teknoloji', 'technology', 'version', 'sürüm', 'leak', 'sızınt', 'sizint', 'fingerprint')) return 'info-disclosure';
        return '';
    }

    function findingPathJS(endpoint) {
        let e = String(endpoint || '').trim().toLowerCase();
        if (!e) return '';
        const s = e.indexOf('://');
        if (s >= 0) {
            e = e.slice(s + 3);
            const j = e.indexOf('/');
            e = j >= 0 ? e.slice(j) : '/';
        }
        e = e.split('?')[0].split('#')[0];
        if (e.length > 1 && e.endsWith('/')) e = e.slice(0, -1);
        return e;
    }

    function getTimestamp() {
        return new Date().toLocaleTimeString('tr-TR', {
            hour: '2-digit',
            minute: '2-digit',
            second: '2-digit',
            hour12: false
        });
    }

    function cardInner(finding, findingId) {
        const severity = (finding.severity || 'info').toLowerCase();
        const method = (finding.method || 'GET').toUpperCase();
        const methodClass = METHOD_CLASSES[method] || 'method-get';
        const timestamp = finding.timestamp || getTimestamp();
        const hasMd = (typeof Md !== 'undefined');

        const group = (label, content, kind) => {
            if (!content) return '';
            let body;
            if (kind === 'code') body = `<div class="finding-detail-content fd-code">${escapeHtml(content)}</div>`;
            else if (kind === 'md' && hasMd) body = `<div class="finding-detail-content md-body">${Md.render(content)}</div>`;
            else body = `<div class="finding-detail-content">${escapeHtml(content)}</div>`;
            return `<div class="finding-detail-group"><div class="finding-detail-label">${label}</div>${body}</div>`;
        };
        const cvss = finding.cvss ? `<span class="fd-chip cvss">CVSS ${escapeHtml(finding.cvss)}</span>` : '';
        const vtype = finding.vuln_type ? `<span class="fd-chip">${escapeHtml(finding.vuln_type)}</span>` : '';
        const verified = finding.verified
            ? `<span class="fd-chip verified">✓ verified</span>`
            : (finding.confidence ? `<span class="fd-chip">${escapeHtml(finding.confidence)}</span>` : '');
        return `
            <div class="finding-header" onclick="Findings.expandFinding('${findingId}')">
                <span class="severity-badge ${severity}">${severity.toUpperCase()}</span>
                <span class="finding-title">${escapeHtml(finding.title || 'Unknown Finding')}</span>
                <button class="finding-expand-btn" id="${findingId}-expand" aria-label="Show details">▼</button>
            </div>
            <div class="finding-meta">
                <span class="method-badge ${methodClass}">${method}</span>
                <span class="finding-endpoint">${escapeHtml(finding.endpoint || 'N/A')}</span>
                ${cvss}${vtype}${verified}
                <span class="finding-time">${timestamp}</span>
            </div>
            <div class="finding-details" id="${findingId}-details">
                ${group('Description', finding.description, 'md')}
                ${group('Impact', finding.impact, 'md')}
                ${group('Evidence', finding.evidence, 'md')}
                ${group('PoC (Proof of Concept)', finding.poc, 'md')}
                ${group('Reproduction Steps', finding.repro_steps, 'md')}
                ${group('Raw Request', finding.request, 'code')}
                ${group('Raw Response', finding.response, 'code')}
                ${group('Extracted Evidence', finding.extracted_evidence, 'code')}
                ${group('Remediation', finding.remediation, 'md')}
                ${finding.verify_note ? group('Verification Note', finding.verify_note, 'md') : ''}
            </div>
            ${adminBar(finding)}
        `;
    }

    let adminMod = null;
    let adminWired = false;
    function enableAdmin(handlers) { adminMod = handlers; }
    function adminBar(finding) {
        if (!adminMod || !finding.db_id) return '';
        const sev = (finding.severity || 'info').toLowerCase();
        const opt = (v, l) => `<option value="${v}"${v === sev ? ' selected' : ''}>${l}</option>`;
        return `<div class="fd-admin" data-fid="${escapeHtml(finding.db_id)}">
            <span class="fd-admin-lbl">Moderation:</span>
            <select class="fd-sev">${opt('critical', 'Critical')}${opt('high', 'High')}${opt('medium', 'Medium')}${opt('low', 'Low')}${opt('info', 'Info')}</select>
            <button type="button" class="btn btn-ghost btn-sm fd-del">Delete</button>
        </div>`;
    }
    function wireAdmin(container) {
        if (adminWired || !container) return;
        adminWired = true;
        container.addEventListener('change', (e) => {
            const sel = e.target.closest('.fd-sev'); if (!sel) return;
            const bar = sel.closest('.fd-admin'); if (!bar) return;
            if (adminMod && adminMod.onSeverity) adminMod.onSeverity(bar.dataset.fid, sel.value);
        });
        container.addEventListener('click', (e) => {
            const del = e.target.closest('.fd-del'); if (!del) return;
            const bar = del.closest('.fd-admin'); if (!bar) return;
            if (adminMod && adminMod.onDelete) adminMod.onDelete(bar.dataset.fid);
        });
    }

    function addFinding(finding) {

        if (!finding || !String(finding.title || '').trim()) return null;
        const container = document.getElementById('findings-container');
        if (!container) return null;
        wireAdmin(container);

        const severity = (finding.severity || 'info').toLowerCase();
        const method = (finding.method || 'GET').toUpperCase();
        const timestamp = finding.timestamp || getTimestamp();
        const key = normKey(finding);

        const existingId = key && byKey.get(key);
        if (existingId) {
            const card = document.getElementById(existingId);
            const idx = findings.findIndex((f) => f.id === existingId);
            const merged = { ...(idx >= 0 ? findings[idx] : {}), ...finding, id: existingId, severity, method, timestamp };
            if (idx >= 0) findings[idx] = merged;
            if (card) {
                card.className = `finding-card severity-${severity}`;
                card.innerHTML = cardInner(merged, existingId);
                card.style.display = cardVisible(severity) ? '' : 'none';
            }
            renderStats();
            return { id: existingId, isNew: false };
        }

        const emptyState = document.getElementById('findings-empty');
        if (emptyState) emptyState.style.display = 'none';

        findingCounter++;
        const findingId = `finding-${findingCounter}`;

        const findingData = { id: findingId, ...finding, severity, method, timestamp };
        findings.push(findingData);
        if (key) byKey.set(key, findingId);

        const card = document.createElement('div');
        card.className = `finding-card severity-${severity}`;
        card.id = findingId;
        card.innerHTML = cardInner(findingData, findingId);

        container.appendChild(card);
        card.style.display = cardVisible(severity) ? '' : 'none';

        container.scrollTop = container.scrollHeight;

        renderStats();
        return { id: findingId, isNew: true };
    }

    let activeFilter = '';

    let showLowInfo = false;
    const isLowInfo = (sev) => sev === 'low' || sev === 'info';

    const cardVisible = (sev) => activeFilter ? (activeFilter === sev) : (showLowInfo || !isLowInfo(sev));

    function renderStats() {
        const el = document.getElementById('findings-stats');
        if (!el) return;
        const stats = getStats();
        const order = ['critical', 'high', 'medium', 'low', 'info'];
        const labels = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', info: 'Info' };

        const mainOrder = ['critical', 'high', 'medium'];
        let html = mainOrder.map(s => {
            const n = stats[s] || 0;
            const dim = n === 0 ? ' zero' : '';
            const on = activeFilter === s ? ' active' : '';
            return `<button type="button" class="sev-chip ${s}${dim}${on}" data-sev="${s}">${labels[s]} <b>${n}</b></button>`;
        }).join('');
        const lowInfoN = (stats.low || 0) + (stats.info || 0);
        if (lowInfoN > 0) {
            const on = showLowInfo ? ' active' : '';
            html += `<button type="button" class="sev-chip lowinfo${on}" data-toggle="lowinfo" title="Low-severity / informational observations (not standalone findings)">${showLowInfo ? 'Hide Low/Info' : 'Show Low/Info'} <b>${lowInfoN}</b></button>`;
        }
        el.innerHTML = html;
        el.querySelectorAll('.sev-chip[data-sev]').forEach(b => b.addEventListener('click', () => {
            activeFilter = (activeFilter === b.dataset.sev) ? '' : b.dataset.sev;
            applyFilter();
            renderStats();
        }));
        const tgl = el.querySelector('.sev-chip[data-toggle="lowinfo"]');
        if (tgl) tgl.addEventListener('click', () => {
            showLowInfo = !showLowInfo;
            if (showLowInfo) activeFilter = '';
            applyFilter();
            renderStats();
        });
    }

    function applyFilter() {
        document.querySelectorAll('#findings-container .finding-card').forEach(card => {
            const sev = (card.className.match(/severity-(\w+)/) || [, ''])[1];
            card.style.display = cardVisible(sev) ? '' : 'none';
        });
    }

    function expandFinding(id) {
        const details = document.getElementById(`${id}-details`);
        const expandBtn = document.getElementById(`${id}-expand`);

        if (!details) return;

        const isExpanded = details.classList.contains('expanded');

        if (isExpanded) {
            details.classList.remove('expanded');
            if (expandBtn) expandBtn.classList.remove('expanded');
        } else {
            details.classList.add('expanded');
            if (expandBtn) expandBtn.classList.add('expanded');
        }
    }

    function focusByTitle(title) {
        const id = byKey.get(String(title || '').trim().toLowerCase());
        if (!id) return;
        const card = document.getElementById(id);
        if (!card) return;
        card.scrollIntoView({ behavior: 'smooth', block: 'center' });
        const details = document.getElementById(`${id}-details`);
        if (details && !details.classList.contains('expanded')) expandFinding(id);
    }

    function clearFindings() {
        const container = document.getElementById('findings-container');
        if (!container) return;

        container.innerHTML = `
            <div class="empty-state" id="findings-empty">
                <div class="empty-icon">⌖</div>
                <p class="empty-text">No findings yet</p>
                <p class="empty-subtext">Findings will appear here once the scan begins</p>
            </div>
        `;

        findings = [];
        findingCounter = 0;
        activeFilter = '';
        byKey.clear();
        renderStats();
    }

    function count() { return findings.length; }

    function removeByDbId(dbId) {
        const idx = findings.findIndex((f) => f.db_id === dbId);
        if (idx < 0) return;
        const f = findings[idx];
        document.getElementById(f.id)?.remove();
        const k = normKey(f);
        if (k && byKey.get(k) === f.id) byKey.delete(k);
        findings.splice(idx, 1);
        renderStats();
    }

    function exportFindings() {
        if (findings.length === 0) {
            Scanner.addFeedItem('warning', 'No findings available to export.');
            return;
        }

        const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
        let markdown = `# Cypture Scan Report\n`;
        markdown += `**Date:** ${new Date().toLocaleString('en-US')}\n`;
        markdown += `**Total Findings:** ${findings.length}\n\n`;
        markdown += `---\n\n`;

        const severityOrder = ['critical', 'high', 'medium', 'low', 'info'];
        const grouped = {};
        severityOrder.forEach(s => { grouped[s] = []; });

        findings.forEach(f => {
            const sev = f.severity || 'info';
            if (grouped[sev]) {
                grouped[sev].push(f);
            } else {
                grouped['info'].push(f);
            }
        });

        severityOrder.forEach(severity => {
            const items = grouped[severity];
            if (items.length === 0) return;

            markdown += `## ${severity.toUpperCase()} (${items.length})\n\n`;

            items.forEach((f, index) => {
                markdown += `### ${index + 1}. ${f.title || 'Unknown'}\n`;
                markdown += `- **Endpoint:** \`${f.endpoint || 'N/A'}\`\n`;
                markdown += `- **Method:** ${f.method || 'N/A'}\n`;
                if (f.vuln_type) markdown += `- **Type:** ${f.vuln_type}\n`;
                if (f.cvss) markdown += `- **CVSS:** ${f.cvss}\n`;
                if (f.confidence || f.verified) markdown += `- **Confidence:** ${f.verified ? 'verified' : f.confidence}\n`;
                if (f.description) markdown += `- **Description:** ${f.description}\n`;
                if (f.evidence) markdown += `- **Evidence:** ${f.evidence}\n`;
                if (f.remediation) markdown += `- **Remediation:** ${f.remediation}\n`;
                if (f.poc) markdown += `\n**PoC:**\n\`\`\`\n${f.poc}\n\`\`\`\n`;
                if (f.request) markdown += `\n**Raw Request:**\n\`\`\`http\n${f.request}\n\`\`\`\n`;
                if (f.response) markdown += `\n**Raw Response:**\n\`\`\`http\n${f.response}\n\`\`\`\n`;
                markdown += `\n`;
            });
        });

        const blob = new Blob([markdown], { type: 'text/markdown' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `cypture-report-${timestamp}.md`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);

        Scanner.addFeedItem('success', `Report exported successfully (${findings.length} findings).`);
    }

    function getStats() {
        const stats = { total: findings.length, critical: 0, high: 0, medium: 0, low: 0, info: 0 };
        findings.forEach(f => {
            if (stats.hasOwnProperty(f.severity)) {
                stats[f.severity]++;
            }
        });
        return stats;
    }

    function escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    return {
        addFinding,
        expandFinding,
        focusByTitle,
        clearFindings,
        exportFindings,
        getStats,
        count,
        enableAdmin,
        removeByDbId,

        dedupKey: normKey,
        SEVERITY_COLORS,
        METHOD_CLASSES
    };
})();
