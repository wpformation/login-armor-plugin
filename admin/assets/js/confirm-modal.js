/*!
 * LoginArmor: singleton confirmation modal.
 * Exposes window.LA.confirm({...}) => Promise<boolean>.
 * Vanilla, zero dependency, native <dialog>.
 *
 * 2.8.0: with `password: true` the dialog also asks for the account password
 * (for the changes that weaken an account), and the promise resolves to the
 * password typed, or to false when the dialog is dismissed.
 */
(function () {
    'use strict';

    if (window.LA && window.LA.confirm) { return; }

    // i18n strings are read lazily at modal open time (not at IIFE load)
    // because on admin pages this script is enqueued BEFORE admin.js'
    // wp_localize_script output, so window.loginArmor is still undefined
    // here. By the time the user clicks something, it IS defined. Only
    // the 2FA profile page enqueues a dedicated localize on the
    // confirm-modal handle; every other page relies on admin.js'
    // localize, which lands in the DOM later than this file.
    function getStrings() {
        var i18n = (window.loginArmor && window.loginArmor.confirmI18n) || {};
        return {
            cancel:  i18n.cancel  || 'Cancel',
            confirm: i18n.confirm || 'Confirm',
            ack:     i18n.ack     || 'I understand',
            password: i18n.password || 'Your password'
        };
    }

    var dlg = null;
    var lastTrigger = null;

    function ensureDialog() {
        if (dlg) { return dlg; }
        dlg = document.createElement('dialog');
        dlg.className = 'la-confirm';
        dlg.setAttribute('role', 'dialog');
        dlg.setAttribute('aria-modal', 'true');
        dlg.innerHTML =
            '<div class="la-confirm__inner">' +
                '<h2 class="la-confirm__title" id="la-confirm-title"></h2>' +
                '<div class="la-confirm__body" id="la-confirm-body"></div>' +
                '<label class="la-confirm__checkbox" hidden>' +
                    '<input type="checkbox">' +
                    '<span class="la-confirm__checkbox-label"></span>' +
                '</label>' +
                '<p class="la-confirm__password" hidden>' +
                    '<label for="la-confirm-password" class="la-confirm__password-label"></label>' +
                    '<input type="password" id="la-confirm-password" autocomplete="current-password" spellcheck="false">' +
                '</p>' +
            '</div>' +
            '<div class="la-confirm__actions">' +
                '<button type="button" class="la-confirm__btn" data-la-confirm-cancel></button>' +
                '<button type="button" class="la-confirm__btn la-confirm__btn--primary" data-la-confirm-ok></button>' +
            '</div>';
        dlg.setAttribute('aria-labelledby', 'la-confirm-title');
        dlg.setAttribute('aria-describedby', 'la-confirm-body');
        document.body.appendChild(dlg);
        return dlg;
    }

    function setText(el, str) {
        el.textContent = (str == null) ? '' : String(str);
    }

    function open(opts) {
        opts = opts || {};
        var t           = getStrings();
        var d           = ensureDialog();
        var titleEl     = d.querySelector('#la-confirm-title');
        var bodyEl      = d.querySelector('#la-confirm-body');
        var checkLabel  = d.querySelector('.la-confirm__checkbox');
        var checkInput  = checkLabel.querySelector('input');
        var checkSpan   = checkLabel.querySelector('.la-confirm__checkbox-label');
        var cancelBtn   = d.querySelector('[data-la-confirm-cancel]');
        var okBtn       = d.querySelector('[data-la-confirm-ok]');
        var passWrap    = d.querySelector('.la-confirm__password');
        var passLabel   = passWrap.querySelector('label');
        var passInput   = passWrap.querySelector('input');

        setText(titleEl, opts.title || '');
        setText(bodyEl, opts.body || '');
        setText(cancelBtn, opts.cancelLabel || t.cancel);
        setText(okBtn, opts.confirmLabel || t.confirm);

        d.classList.remove('la-confirm__variant--danger', 'la-confirm__variant--primary', 'la-confirm__variant--neutral');
        var variant = opts.variant || 'primary';
        d.classList.add('la-confirm__variant--' + variant);

        okBtn.classList.remove('la-confirm__btn--primary', 'la-confirm__btn--danger');
        if (variant === 'danger') {
            okBtn.classList.add('la-confirm__btn--danger');
        } else {
            okBtn.classList.add('la-confirm__btn--primary');
        }

        var requireCheckbox = !!opts.requireCheckbox;
        checkLabel.hidden = !requireCheckbox;
        checkInput.checked = false;
        setText(checkSpan, opts.checkboxLabel || t.ack);
        okBtn.disabled = requireCheckbox;

        var askPassword = !!opts.password;
        passWrap.hidden = !askPassword;
        passInput.value = '';
        setText(passLabel, opts.passwordLabel || t.password);
        if (askPassword) { okBtn.disabled = true; }

        lastTrigger = document.activeElement;

        return new Promise(function (resolve) {
            var settled = false;
            function done(val) {
                if (settled) { return; }
                settled = true;
                cleanup();
                try { d.close(); } catch (e) { /* already closed */ }
                if (lastTrigger && typeof lastTrigger.focus === 'function') { lastTrigger.focus(); }
                resolve(val);
            }

            function onOk()     { done(askPassword ? passInput.value : true); }
            function onCancel() { done(false); }
            function onEsc(ev) {
                if (ev.key === 'Escape' && !requireCheckbox) {
                    ev.preventDefault();
                    done(false);
                } else if (ev.key === 'Escape' && requireCheckbox) {
                    ev.preventDefault();
                }
            }
            function onCheck() { okBtn.disabled = !checkInput.checked; }
            function onPassInput() { okBtn.disabled = '' === passInput.value; }
            function onPassKey(ev) {
                if (ev.key === 'Enter' && '' !== passInput.value) {
                    ev.preventDefault();
                    onOk();
                }
            }
            function onBackdrop(ev) {
                if (ev.target === d && !requireCheckbox) { done(false); }
            }

            function cleanup() {
                okBtn.removeEventListener('click', onOk);
                cancelBtn.removeEventListener('click', onCancel);
                checkInput.removeEventListener('change', onCheck);
                passInput.removeEventListener('input', onPassInput);
                passInput.removeEventListener('keydown', onPassKey);
                passInput.value = '';
                d.removeEventListener('keydown', onEsc);
                d.removeEventListener('click', onBackdrop);
            }

            okBtn.addEventListener('click', onOk);
            cancelBtn.addEventListener('click', onCancel);
            checkInput.addEventListener('change', onCheck);
            passInput.addEventListener('input', onPassInput);
            passInput.addEventListener('keydown', onPassKey);
            d.addEventListener('keydown', onEsc);
            d.addEventListener('click', onBackdrop);

            if (typeof d.showModal === 'function') {
                d.showModal();
            } else if (askPassword) {
                done(window.prompt(opts.title + '\n\n' + opts.body) || false);
            } else {
                done(window.confirm(opts.title + '\n\n' + opts.body));
            }
            setTimeout(function () {
                if (askPassword) { passInput.focus(); } else if (requireCheckbox) { cancelBtn.focus(); } else { okBtn.focus(); }
            }, 0);
        });
    }

    window.LA = window.LA || {};
    window.LA.confirm = open;
}());
