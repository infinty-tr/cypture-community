
(() => {
    'use strict';
    const KEY = 'cypture-theme';
    const root = document.documentElement;

    function current() {
        return root.getAttribute('data-theme') || 'dark';
    }
    function apply(theme) {
        root.setAttribute('data-theme', theme);
        try { localStorage.setItem(KEY, theme); } catch {}
        const btn = document.getElementById('theme-toggle');
        if (btn) {
            const dark = theme === 'dark';
            btn.textContent = dark ? 'LIGHT' : 'DARK';
            btn.setAttribute('aria-label', dark ? 'Switch to light theme' : 'Switch to dark theme');
        }
    }
    function toggle() { apply(current() === 'dark' ? 'light' : 'dark'); }

    function init() {
        apply(current());
        document.getElementById('theme-toggle')?.addEventListener('click', toggle);
    }
    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
    else init();
})();
