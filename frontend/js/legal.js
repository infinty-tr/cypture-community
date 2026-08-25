
(function () {
    'use strict';

    var COMPANY = 'Example Technology';
    var BRAND = 'Cypture';
    var CONTACT = 'contact@example.com';
    var UPDATED = 'July 2026';

    var AYDINLATMA =
        '<h3>Privacy Notice</h3>' +
        '<p class="lg-meta">Last updated: ' + UPDATED + ' · Data Controller: <b>' + COMPANY + '</b> (' + BRAND + ')</p>' +
        '<p>Under applicable data protection law, your personal data is processed by ' + COMPANY + ' as data controller in connection with your use of ' + BRAND + ', as described below.</p>' +
        '<h4>Personal Data Processed</h4>' +
        '<ul>' +
        '<li><b>Identity/Contact:</b> email address, company name.</li>' +
        '<li><b>Account security:</b> your password (stored only as an irreversible <i>hash</i> — never kept in plaintext), session and login records, IP address.</li>' +
        '<li><b>Service data:</b> target information for the security tests you start, findings, HTTP traffic and reports.</li>' +
        '</ul>' +
        '<h4>Purposes of Processing</h4>' +
        '<ul>' +
        '<li>Creating and managing your account, providing the service and running security tests,</li>' +
        '<li>Ensuring the security of Cypture and its users and preventing misuse,</li>' +
        '<li>Meeting legal obligations and responding to requests.</li>' +
        '</ul>' +
        '<h4>Legal Bases</h4>' +
        '<p>Your data is processed on the legal bases of the establishment/performance of a contract, legal obligation, legitimate interest, and, where required, your explicit consent.</p>' +
        '<h4>Transfers</h4>' +
        '<p>Your data may be shared with hosting and email service providers to the extent necessary for the service, and only with authorized public authorities where legally required.</p>' +
        '<h4>Retention Period</h4>' +
        '<p>Your personal data is retained for as long as the purpose of processing requires and for the periods prescribed by applicable law; at the end of these periods it is deleted, destroyed or anonymized.</p>' +
        '<h4>Your Rights</h4>' +
        '<p>You have the right to learn whether your personal data is being processed, to request information, to have it corrected, to request its deletion/destruction, to object to processing, and to seek redress for any damage. You can submit your requests to <b>' + CONTACT + '</b>.</p>';

    var KOSULLAR =
        '<h3>Terms of Use and Disclaimer</h3>' +
        '<p class="lg-meta">Last updated: ' + UPDATED + ' · ' + BRAND + ' is a brand of ' + COMPANY + '.</p>' +
        '<h4>1. Authorized Use (Mandatory)</h4>' +
        '<p>' + BRAND + ' is provided solely for <b>authorized security testing</b>. By using it, you represent and warrant that you <b>own the systems/domains you will test, or hold explicit written permission to test them</b>. Any scanning of or access to targets you are not authorized for is <b>prohibited and unlawful</b>.</p>' +
        '<h4>2. User Responsibility</h4>' +
        '<p>You are <b>solely responsible</b> for all activities you carry out through Cypture and for their legal consequences. You agree to comply with all applicable laws. Testing out-of-scope targets and misusing any information obtained is prohibited.</p>' +
        '<h4>3. Disclaimer</h4>' +
        '<p>' + BRAND + ' and ' + COMPANY + ' provide the service <b>"as is" and "as available"</b>, with no express or implied warranty of any kind. ' + COMPANY + ' <b>cannot be held liable</b> for any use or misuse of Cypture, for any interruption, data loss or damage that may occur to the systems tested, or for any indirect, direct, incidental or consequential damages. The accuracy, completeness or fitness for a particular purpose of the findings is not guaranteed.</p>' +
        '<h4>4. Indemnification</h4>' +
        '<p>You agree to <b>indemnify and hold ' + COMPANY + ' harmless</b> against any third-party claim, damage, penalty or cost arising from your use of Cypture in breach of these terms.</p>' +
        '<h4>5. Account and Access</h4>' +
        '<p>You are responsible for keeping your account credentials confidential. ' + COMPANY + ' reserves the right to suspend or close the account in the event of a breach of these terms.</p>' +
        '<p class="lg-note">By accepting this text you declare that you have read, understood and accepted the terms above.</p>';

    function ensureModal() {
        var m = document.getElementById('legal-modal');
        if (m) return m;
        m = document.createElement('div');
        m.id = 'legal-modal';
        m.setAttribute('role', 'dialog');
        m.setAttribute('aria-modal', 'true');
        m.style.cssText = 'position:fixed;inset:0;z-index:9999;display:none;align-items:center;justify-content:center;background:rgba(0,0,0,.72);backdrop-filter:blur(3px);padding:20px';
        m.innerHTML =
            '<div class="lg-box" style="max-width:680px;width:100%;max-height:82vh;overflow:auto;background:#111110;color:#e8e6df;border:1px solid #ffb00033;border-radius:14px;box-shadow:0 20px 60px rgba(0,0,0,.6);padding:26px 28px;font:400 14px/1.6 Inter,system-ui,sans-serif">' +
            '<button type="button" id="legal-close" aria-label="Close" style="position:sticky;top:0;float:right;background:transparent;border:0;color:#ffb000;font-size:26px;line-height:1;cursor:pointer">×</button>' +
            '<div id="legal-content"></div>' +
            '<div style="text-align:right;margin-top:18px"><button type="button" id="legal-ok" style="background:#ffb000;color:#0a0a09;border:0;border-radius:8px;padding:10px 22px;font-weight:700;cursor:pointer">Got it</button></div>' +
            '</div>';
        document.body.appendChild(m);
        var style = document.createElement('style');
        style.textContent =
            '#legal-modal h3{color:#ffb000;font-size:19px;margin:0 0 6px}' +
            '#legal-modal h4{color:#ffce5a;font-size:14px;margin:16px 0 4px}' +
            '#legal-modal .lg-meta{color:#9a968c;font-size:12px;margin:0 0 12px}' +
            '#legal-modal .lg-note{color:#cfc9bd;font-style:italic;margin-top:14px}' +
            '#legal-modal ul{margin:4px 0 4px 18px;padding:0}#legal-modal li{margin:3px 0}' +
            '#legal-modal p{margin:6px 0}' +
            ':root[data-theme="light"] #legal-modal .lg-box{background:#fbfaf7;color:#1a1917;border-color:#d8b45b}' +
            ':root[data-theme="light"] #legal-modal h3{color:#a9740b}:root[data-theme="light"] #legal-modal h4{color:#8a5e08}';
        document.head.appendChild(style);
        var close = function () { m.style.display = 'none'; };
        m.querySelector('#legal-close').addEventListener('click', close);
        m.querySelector('#legal-ok').addEventListener('click', close);
        m.addEventListener('click', function (e) { if (e.target === m) close(); });
        document.addEventListener('keydown', function (e) { if (e.key === 'Escape') close(); });
        return m;
    }

    function open(which) {
        var m = ensureModal();
        m.querySelector('#legal-content').innerHTML = (which === 'kosullar') ? KOSULLAR : AYDINLATMA;
        m.style.display = 'flex';
        m.scrollTop = 0;
        var box = m.querySelector('.lg-box'); if (box) box.scrollTop = 0;
    }

    function wireLinks() {
        document.querySelectorAll('[data-legal]').forEach(function (el) {
            el.addEventListener('click', function (e) { e.preventDefault(); open(el.getAttribute('data-legal')); });
        });
    }

    function requireConsent(formId, checkboxId, msgId) {
        var form = document.getElementById(formId);
        var box = document.getElementById(checkboxId);
        if (!form || !box) return;
        form.addEventListener('submit', function (e) {
            if (!box.checked) {
                e.preventDefault();
                e.stopImmediatePropagation();
                var msg = msgId && document.getElementById(msgId);
                if (msg) { msg.textContent = 'You must accept the privacy notice and terms of use to continue.'; msg.classList.add('error'); }
                var wrap = box.closest('.legal-consent'); if (wrap) { wrap.classList.add('shake'); setTimeout(function () { wrap.classList.remove('shake'); }, 450); }
            }
        }, true);
    }

    window.Legal = { open: open, requireConsent: requireConsent };
    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', wireLinks);
    else wireLinks();
})();
