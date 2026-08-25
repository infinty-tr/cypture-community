
const Md = (() => {
    'use strict';

    function esc(s) {
        return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
    }
    function inline(s) {
        return s
            .replace(/`([^`]+)`/g, '<code>$1</code>')
            .replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>')
            .replace(/(^|[^*])\*([^*\n]+)\*/g, '$1<em>$2</em>')
            .replace(/\[([^\]]+)\]\((https?:[^)\s]+)\)/g, '<a href="$2" target="_blank" rel="noopener">$1</a>');
    }

    function renderTable(lines) {
        // lines: header | sep | rows...
        const cells = (l) => l.replace(/^\||\|$/g, '').split('|').map((c) => c.trim());
        const head = cells(lines[0]);
        let html = '<table class="md-table"><thead><tr>' +
            head.map((h) => `<th>${inline(esc(h))}</th>`).join('') + '</tr></thead><tbody>';
        for (let i = 2; i < lines.length; i++) {
            const row = cells(lines[i]);
            html += '<tr>' + row.map((c) => `<td>${inline(esc(c))}</td>`).join('') + '</tr>';
        }
        return html + '</tbody></table>';
    }

    function render(src) {
        if (!src) return '';
        const lines = String(src).replace(/\r\n/g, '\n').split('\n');
        let out = [];
        let i = 0;
        let listType = null;

        const closeList = () => { if (listType) { out.push(`</${listType}>`); listType = null; } };

        while (i < lines.length) {
            let line = lines[i];

            // Code block (```)
            const fence = line.match(/^\s*```(\w*)\s*$/);
            if (fence) {
                closeList();
                const buf = [];
                i++;
                while (i < lines.length && !/^\s*```\s*$/.test(lines[i])) { buf.push(lines[i]); i++; }
                i++; // closing fence
                out.push(`<pre class="md-pre"><code>${esc(buf.join('\n'))}</code></pre>`);
                continue;
            }

            // Table (| ... | row + following separator row)
            if (/^\s*\|.*\|\s*$/.test(line) && i + 1 < lines.length && /^\s*\|?[\s:|-]+\|?\s*$/.test(lines[i + 1]) && lines[i + 1].includes('-')) {
                closeList();
                const tbl = [line, lines[i + 1]];
                i += 2;
                while (i < lines.length && /^\s*\|.*\|\s*$/.test(lines[i])) { tbl.push(lines[i]); i++; }
                out.push(renderTable(tbl));
                continue;
            }

            // Heading
            const h = line.match(/^(#{1,6})\s+(.*)$/);
            if (h) { closeList(); out.push(`<h${h[1].length} class="md-h">${inline(esc(h[2]))}</h${h[1].length}>`); i++; continue; }

            // Horizontal rule
            if (/^\s*([-*_])\1{2,}\s*$/.test(line)) { closeList(); out.push('<hr class="md-hr">'); i++; continue; }

            // Blockquote
            if (/^\s*>\s?/.test(line)) { closeList(); out.push(`<blockquote class="md-quote">${inline(esc(line.replace(/^\s*>\s?/, '')))}</blockquote>`); i++; continue; }

            // List (ordered / unordered)
            const ul = line.match(/^\s*[-*+]\s+(.*)$/);
            const ol = line.match(/^\s*\d+[.)]\s+(.*)$/);
            if (ul || ol) {
                const want = ul ? 'ul' : 'ol';
                if (listType !== want) { closeList(); out.push(`<${want} class="md-list">`); listType = want; }
                out.push(`<li>${inline(esc((ul || ol)[1]))}</li>`);
                i++; continue;
            }

            // Empty line
            if (/^\s*$/.test(line)) { closeList(); i++; continue; }

            // Paragraph
            closeList();
            out.push(`<p class="md-p">${inline(esc(line))}</p>`);
            i++;
        }
        closeList();
        return out.join('\n');
    }

    return { render, esc };
})();
