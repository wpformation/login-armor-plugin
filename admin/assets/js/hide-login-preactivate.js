/*!
 * LoginArmor: Hide Login pre-activation modal.
 *
 * Exposes window.LA.hideLoginPreActivate() => Promise<{slug, send_email, url} | null>.
 * The caller opens it BEFORE activation so the user picks their own slug
 * and opts in (or not) to a recovery email: no more "imposed URL then
 * fix it" round-trip.
 *
 * Vanilla, zero dependency, native <dialog>, reads i18n strings lazily
 * at open time from window.loginArmor.hideLoginPreActivate (wp_localize).
 */
(function () {
    'use strict';

    if (window.LA && window.LA.hideLoginPreActivate) { return; }

    function getStrings() {
        var i18n = (window.loginArmor && window.loginArmor.hideLoginPreActivate) || {};
        return {
            title:            i18n.title            || 'Enable Hide Login',
            lede:             i18n.lede             || 'Pick the secret URL for your login page. Visitors will not be able to discover it.',
            slugLabel:        i18n.slugLabel        || 'Your login slug',
            slugHint:         i18n.slugHint         || 'Lowercase letters, digits, and hyphens. 3 to 64 characters.',
            regenerate:       i18n.regenerate       || 'Regenerate',
            emailLabel:       i18n.emailLabel       || 'Email me this URL (recommended, you will need it to log in).',
            cancel:           i18n.cancel           || 'Cancel',
            activate:         i18n.activate         || 'Activate Hide Login',
            invalidSlug:      i18n.invalidSlug      || 'This slug cannot be used. Try another or click Regenerate.',
            genericError:     i18n.genericError     || 'Something went wrong. Try again.'
        };
    }

    function randomSlug() {
        // Mirrors includes/class-hide-login.php::SLUG_ALPHABET + SLUG_LENGTH.
        // Client-side suggestion only; server will re-validate on activate.
        var alphabet = 'abcdefghjkmnpqrstuvwxyz23456789';
        var out = '';
        for (var i = 0; i < 8; i++) {
            out += alphabet.charAt(Math.floor(Math.random() * alphabet.length));
        }
        return out;
    }

    var dlg = null;
    var lastTrigger = null;

    function ensureDialog() {
        if (dlg) { return dlg; }
        dlg = document.createElement('dialog');
        dlg.className = 'la-hl-preactivate';
        dlg.setAttribute('role', 'dialog');
        dlg.setAttribute('aria-modal', 'true');
        dlg.innerHTML =
            '<div class="la-hl-preactivate__inner">' +
                '<h2 class="la-hl-preactivate__title"></h2>' +
                '<p class="la-hl-preactivate__lede"></p>' +
                '<label class="la-hl-preactivate__field">' +
                    '<span class="la-hl-preactivate__field-label"></span>' +
                    '<div class="la-hl-preactivate__input-row">' +
                        '<input type="text" class="la-hl-preactivate__input" autocomplete="off" spellcheck="false">' +
                        '<button type="button" class="la-hl-preactivate__regenerate"></button>' +
                    '</div>' +
                    '<span class="la-hl-preactivate__hint"></span>' +
                    '<span class="la-hl-preactivate__error" hidden></span>' +
                '</label>' +
                '<label class="la-hl-preactivate__checkbox">' +
                    '<input type="checkbox" class="la-hl-preactivate__email">' +
                    '<span class="la-hl-preactivate__email-label"></span>' +
                '</label>' +
            '</div>' +
            '<div class="la-hl-preactivate__actions">' +
                '<button type="button" class="la-hl-preactivate__btn la-hl-preactivate__btn--secondary" data-la-preact-cancel></button>' +
                '<button type="button" class="la-hl-preactivate__btn la-hl-preactivate__btn--primary" data-la-preact-activate></button>' +
            '</div>';
        document.body.appendChild(dlg);
        return dlg;
    }

    function open(opts) {
        opts = opts || {};
        var t         = getStrings();
        var d         = ensureDialog();
        var titleEl   = d.querySelector('.la-hl-preactivate__title');
        var ledeEl    = d.querySelector('.la-hl-preactivate__lede');
        var fieldLbl  = d.querySelector('.la-hl-preactivate__field-label');
        var input     = d.querySelector('.la-hl-preactivate__input');
        var regenBtn  = d.querySelector('.la-hl-preactivate__regenerate');
        var hintEl    = d.querySelector('.la-hl-preactivate__hint');
        var errorEl   = d.querySelector('.la-hl-preactivate__error');
        var emailCb   = d.querySelector('.la-hl-preactivate__email');
        var emailLbl  = d.querySelector('.la-hl-preactivate__email-label');
        var cancelBtn = d.querySelector('[data-la-preact-cancel]');
        var activateBtn = d.querySelector('[data-la-preact-activate]');

        titleEl.textContent = t.title;
        ledeEl.textContent = t.lede;
        fieldLbl.textContent = t.slugLabel;
        hintEl.textContent = t.slugHint;
        regenBtn.textContent = t.regenerate;
        emailLbl.textContent = t.emailLabel;
        cancelBtn.textContent = t.cancel;
        activateBtn.textContent = t.activate;

        input.value = (opts.initialSlug && typeof opts.initialSlug === 'string')
            ? opts.initialSlug
            : randomSlug();
        emailCb.checked = false;
        errorEl.hidden = true;
        errorEl.textContent = '';

        lastTrigger = document.activeElement;

        return new Promise(function (resolve) {
            var settled = false;

            function cleanup() {
                activateBtn.removeEventListener('click', onActivate);
                cancelBtn.removeEventListener('click', onCancel);
                regenBtn.removeEventListener('click', onRegen);
                d.removeEventListener('keydown', onEsc);
            }
            function done(val) {
                if (settled) { return; }
                settled = true;
                cleanup();
                try { d.close(); } catch (e) { /* already closed */ }
                if (lastTrigger && typeof lastTrigger.focus === 'function') {
                    lastTrigger.focus();
                }
                resolve(val);
            }
            function onActivate() {
                var slug = input.value.trim();
                // Light client-side check, server re-validates via HideLogin::validate_slug.
                if (!/^[a-z0-9][a-z0-9-]{2,63}$/.test(slug)) {
                    errorEl.textContent = t.invalidSlug;
                    errorEl.hidden = false;
                    input.focus();
                    input.select();
                    return;
                }
                done({ slug: slug, send_email: emailCb.checked });
            }
            function onCancel() { done(null); }
            function onRegen() {
                input.value = randomSlug();
                errorEl.hidden = true;
                input.focus();
                input.select();
            }
            function onEsc(ev) {
                if (ev.key === 'Escape') {
                    ev.preventDefault();
                    done(null);
                }
            }

            activateBtn.addEventListener('click', onActivate);
            cancelBtn.addEventListener('click', onCancel);
            regenBtn.addEventListener('click', onRegen);
            d.addEventListener('keydown', onEsc);

            if (typeof d.showModal === 'function') {
                d.showModal();
            } else {
                // Ultra-old browser fallback: prompt chain.
                var fallbackSlug = window.prompt(t.slugLabel, input.value);
                if (!fallbackSlug) { done(null); return; }
                var fallbackEmail = window.confirm(t.emailLabel);
                done({ slug: fallbackSlug.trim(), send_email: !!fallbackEmail });
                return;
            }
            setTimeout(function () { input.focus(); input.select(); }, 0);
        });
    }

    window.LA = window.LA || {};
    window.LA.hideLoginPreActivate = open;
}());
