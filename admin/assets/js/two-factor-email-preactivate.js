/*!
 * LoginArmor: pre-activation modal for Email two-factor auth.
 * Exposes window.LA.openEmailPreactivate(onConfirm) => Promise<void>.
 *
 * Forces a real wp_mail() round-trip BEFORE letting the user commit
 * to Email 2FA, and a safety-net checkbox confirming a backup admin
 * tab is open. Both gates must pass before the final button enables.
 *
 * Vanilla, zero dependency, native <dialog>. Reads strings from
 * window.la2faPreactivate (injected via wp_localize_script).
 */
(function () {
    'use strict';

    if (window.LA && window.LA.openEmailPreactivate) { return; }

    function getCfg() {
        return window.la2faPreactivate || {};
    }

    function t(key, fallback) {
        var i18n = (getCfg().i18n) || {};
        return i18n[key] || fallback;
    }

    var dlg = null;
    var lastTrigger = null;

    function ensureDialog() {
        if (dlg) { return dlg; }
        dlg = document.createElement('dialog');
        dlg.id = 'la-2fa-preactivate-dialog';
        dlg.className = 'la-2fa-preactivate';
        dlg.setAttribute('role', 'dialog');
        dlg.setAttribute('aria-modal', 'true');
        dlg.setAttribute('aria-labelledby', 'la-2fa-preactivate-title');

        dlg.innerHTML =
            '<div class="la-2fa-preactivate__inner">' +
                '<h2 class="la-2fa-preactivate__title" id="la-2fa-preactivate-title"></h2>' +
                '<p class="la-2fa-preactivate__warning" data-warning></p>' +

                '<div class="la-2fa-preactivate__step">' +
                    '<div class="la-2fa-preactivate__step-num">1</div>' +
                    '<div class="la-2fa-preactivate__step-body">' +
                        '<h3 class="la-2fa-preactivate__step-title" data-step1-title></h3>' +
                        '<p class="la-2fa-preactivate__step-desc">' +
                            '<span data-step1-desc></span> ' +
                            '<strong class="la-2fa-preactivate__email" data-email></strong>' +
                        '</p>' +
                        '<button type="button" class="la-2fa-preactivate__btn la-2fa-preactivate__btn--secondary" data-test-btn></button>' +
                        '<div class="la-2fa-preactivate__test-result" data-test-result hidden role="status" aria-live="polite"></div>' +
                    '</div>' +
                '</div>' +

                '<div class="la-2fa-preactivate__step">' +
                    '<div class="la-2fa-preactivate__step-num">2</div>' +
                    '<div class="la-2fa-preactivate__step-body">' +
                        '<h3 class="la-2fa-preactivate__step-title" data-step2-title></h3>' +
                        '<p class="la-2fa-preactivate__step-desc" data-step2-desc></p>' +
                        '<label class="la-2fa-preactivate__checkbox">' +
                            '<input type="checkbox" data-safety-check>' +
                            '<span data-safety-label></span>' +
                        '</label>' +
                    '</div>' +
                '</div>' +
            '</div>' +
            '<div class="la-2fa-preactivate__actions">' +
                '<button type="button" class="la-2fa-preactivate__btn" data-cancel></button>' +
                '<button type="button" class="la-2fa-preactivate__btn la-2fa-preactivate__btn--primary" data-confirm disabled></button>' +
            '</div>';

        document.body.appendChild(dlg);
        return dlg;
    }

    function setText(el, str) {
        el.textContent = (str == null) ? '' : String(str);
    }

    function open(onConfirm) {
        var cfg     = getCfg();
        var d       = ensureDialog();

        var titleEl     = d.querySelector('[id="la-2fa-preactivate-title"]');
        var warningEl   = d.querySelector('[data-warning]');
        var step1Title  = d.querySelector('[data-step1-title]');
        var step1Desc   = d.querySelector('[data-step1-desc]');
        var emailEl     = d.querySelector('[data-email]');
        var testBtn     = d.querySelector('[data-test-btn]');
        var testResult  = d.querySelector('[data-test-result]');
        var step2Title  = d.querySelector('[data-step2-title]');
        var step2Desc   = d.querySelector('[data-step2-desc]');
        var safetyCheck = d.querySelector('[data-safety-check]');
        var safetyLabel = d.querySelector('[data-safety-label]');
        var cancelBtn   = d.querySelector('[data-cancel]');
        var confirmBtn  = d.querySelector('[data-confirm]');

        setText(titleEl,     t('title',       'Before enabling Email two-factor authentication'));
        setText(warningEl,   t('warning',     'If your hosting does not deliver emails, you will be locked out of your site.'));
        setText(step1Title,  t('step1Title',  'Test email delivery'));
        setText(step1Desc,   t('step1Desc',   'A test message will be sent to:'));
        setText(emailEl,     cfg.email || '');
        setText(testBtn,     t('sendTest',    'Send test email'));
        setText(step2Title,  t('step2Title',  'Open a safety-net session in a different browser'));
        setText(step2Desc,   t('step2Desc',   'Open a DIFFERENT browser (for example Firefox if you are on Chrome) or a private/incognito window, and stay logged in as administrator there. Tabs of the same browser share cookies, so they are not a real safety net: if you log out to test 2FA, every tab disconnects at once. A different browser keeps a separate session you can use to disable 2FA if email delivery fails.'));
        setText(safetyLabel, t('safetyLabel', 'I have a different browser (or a private/incognito window) logged in as administrator.'));
        setText(cancelBtn,   t('cancel',      'Cancel'));
        setText(confirmBtn,  t('confirm',     'Enable Email 2FA'));

        var testPassed = false;
        safetyCheck.checked = false;
        confirmBtn.disabled = true;
        testBtn.disabled = false;
        testResult.hidden = true;
        testResult.className = 'la-2fa-preactivate__test-result';
        setText(testResult, '');

        function refreshConfirmState() {
            confirmBtn.disabled = !(testPassed && safetyCheck.checked);
        }

        function showTestSuccess(msg) {
            testPassed = true;
            testResult.hidden = false;
            testResult.className = 'la-2fa-preactivate__test-result la-2fa-preactivate__test-result--ok';
            setText(testResult, msg);
            refreshConfirmState();
        }

        function showTestError(msg) {
            testPassed = false;
            testResult.hidden = false;
            testResult.className = 'la-2fa-preactivate__test-result la-2fa-preactivate__test-result--err';
            setText(testResult, msg);
            refreshConfirmState();
        }

        function runTest() {
            if (!cfg.ajaxUrl || !cfg.nonce) {
                showTestError(t('configError', 'Missing AJAX configuration.'));
                return;
            }
            testBtn.disabled = true;
            setText(testBtn, t('sending', 'Sending...'));
            testResult.hidden = true;

            var body = new URLSearchParams();
            body.append('action', 'login_armor_2fa_email_test');
            body.append('nonce', cfg.nonce);

            fetch(cfg.ajaxUrl, {
                method: 'POST',
                credentials: 'same-origin',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: body.toString()
            })
                .then(function (r) { return r.json().catch(function () { return null; }); })
                .then(function (json) {
                    testBtn.disabled = false;
                    setText(testBtn, t('sendAgain', 'Send another test email'));
                    if (json && json.success) {
                        var okMsg = (json.data && json.data.message) || t('testOk', 'Test email sent. Check your inbox (and spam folder) before continuing.');
                        showTestSuccess(okMsg);
                    } else {
                        var errMsg = (json && json.data && json.data.message) || t('testFail', 'The test email could not be sent. Configure WP Mail SMTP (or contact your host) before enabling Email 2FA, otherwise you will be locked out.');
                        showTestError(errMsg);
                    }
                })
                .catch(function () {
                    testBtn.disabled = false;
                    setText(testBtn, t('sendTest', 'Send test email'));
                    showTestError(t('networkError', 'Network error. Please try again.'));
                });
        }

        lastTrigger = document.activeElement;

        return new Promise(function (resolve) {
            var settled = false;
            function done(confirmed) {
                if (settled) { return; }
                settled = true;
                cleanup();
                try { d.close(); } catch (e) { /* already closed */ }
                if (lastTrigger && typeof lastTrigger.focus === 'function') { lastTrigger.focus(); }
                if (confirmed && typeof onConfirm === 'function') { onConfirm(); }
                resolve(confirmed);
            }

            function onConfirmClick() { if (!confirmBtn.disabled) { done(true); } }
            function onCancelClick()  { done(false); }
            function onCheckChange()  { refreshConfirmState(); }
            function onTestClick()    { runTest(); }
            function onEsc(ev) {
                if (ev.key === 'Escape') { ev.preventDefault(); done(false); }
            }
            function onBackdrop(ev) {
                if (ev.target === d) { done(false); }
            }

            function cleanup() {
                confirmBtn.removeEventListener('click', onConfirmClick);
                cancelBtn.removeEventListener('click', onCancelClick);
                safetyCheck.removeEventListener('change', onCheckChange);
                testBtn.removeEventListener('click', onTestClick);
                d.removeEventListener('keydown', onEsc);
                d.removeEventListener('click', onBackdrop);
            }

            confirmBtn.addEventListener('click', onConfirmClick);
            cancelBtn.addEventListener('click', onCancelClick);
            safetyCheck.addEventListener('change', onCheckChange);
            testBtn.addEventListener('click', onTestClick);
            d.addEventListener('keydown', onEsc);
            d.addEventListener('click', onBackdrop);

            if (typeof d.showModal === 'function') {
                d.showModal();
            } else {
                // Fallback for very old browsers: proceed without modal.
                done(window.confirm(t('title', 'Before enabling Email two-factor authentication') + '\n\n' + t('warning', '')));
                return;
            }
            setTimeout(function () { testBtn.focus(); }, 0);
        });
    }

    window.LA = window.LA || {};
    window.LA.openEmailPreactivate = open;
}());
