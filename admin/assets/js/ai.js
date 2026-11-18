/*!
 * Login Armor: AI analysis panel (on-demand, WP7 native AI Client).
 * Vanilla, no dependency. Reuses window.LA.toast (admin.js) when present.
 */
(function () {
	'use strict';

	var root = document.getElementById('la-root');
	if (!root) { return; }

	var ajaxUrl = root.getAttribute('data-la-ajax') || '';
	var nonce   = root.getAttribute('data-la-admin-nonce') || '';
	var L       = window.loginArmorAI || {};

	function notify(msg, kind) {
		if (window.LA && typeof window.LA.toast === 'function') {
			window.LA.toast(msg, kind);
		}
	}

	function post(action, payload) {
		var body = new URLSearchParams();
		body.append('action', action);
		body.append('nonce', nonce);
		Object.keys(payload || {}).forEach(function (k) { body.append(k, payload[k]); });
		return fetch(ajaxUrl, {
			method: 'POST',
			credentials: 'same-origin',
			headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
			body: body.toString()
		}).then(function (r) { return r.json(); });
	}

	function runAnalysis(panel, btn, force) {
		var action   = btn.getAttribute('data-la-ai-action');
		var id       = btn.getAttribute('data-la-ai-id');
		var endpoints = {
			'explain-incident': 'login_armor_ai_explain_incident',
			'posture': 'login_armor_ai_posture'
		};
		var endpoint = endpoints[action] || 'login_armor_ai_posture';

		var stateEl  = panel.querySelector('[data-la-ai-state]');
		var resultEl = panel.querySelector('[data-la-ai-result]');
		var regenEl  = panel.querySelector('[data-la-ai-regen]');
		var hintEl   = panel.querySelector('[data-la-ai-regen-hint]');
		var stampEl  = panel.querySelector('[data-la-ai-stamp]');

		var payload = { force: force ? '1' : '0' };
		if (id) { payload.id = id; }

		btn.disabled = true;
		if (regenEl) { regenEl.disabled = true; }
		if (stateEl) {
			stateEl.hidden = false;
			stateEl.className = 'la-ai-panel__state is-loading';
			stateEl.textContent = L.analysing || 'Analysing…';
		}

		post(endpoint, payload).then(function (json) {
			if (json && json.success && json.data && json.data.html) {
				if (resultEl) {
					// Server output is already escaped by Client::format_markdown()
					// (every line esc_html'd before tags are injected).
					resultEl.innerHTML = json.data.html;
					resultEl.hidden = false;
				}
				// A reading the row would not take is about to vanish, and the
				// regenerate button would bill for the same text again. The
				// server says so; hiding the state line here would swallow it.
				var warning = (json.data.warning || '');
				if (stateEl) {
					stateEl.hidden = '' === warning;
					if ('' !== warning) {
						stateEl.className = 'la-ai-panel__state is-error';
						stateEl.textContent = warning;
					}
				}
				if ('' !== warning) { notify(warning, 'error'); }
				// One button at a time: once a result is shown, hide the primary
				// "Analyse" action and reveal "Regenerate" (+ its caching hint).
				if (regenEl) { regenEl.hidden = false; }
				if (hintEl)  { hintEl.hidden = false; }
				// The stamp on screen dates the analysis this one just replaced,
				// and may carry the "describes an earlier state" warning. Leaving
				// it there would caption fresh text with a stale disclaimer.
				if (stampEl) {
					stampEl.textContent = L.justNow || 'Analysis produced just now.';
				}
				btn.hidden = true;
			} else {
				var msg = (json && json.data && json.data.message) || L.failed || 'AI analysis failed.';
				if (stateEl) {
					stateEl.className = 'la-ai-panel__state is-error';
					stateEl.textContent = msg;
				}
				notify(msg, 'error');
			}
		}).catch(function () {
			if (stateEl) {
				stateEl.className = 'la-ai-panel__state is-error';
				stateEl.textContent = L.network || 'Network error.';
			}
			notify('Network error.', 'error');
		}).then(function () {
			btn.disabled = false;
			if (regenEl) { regenEl.disabled = false; }
		});
	}

	// Analysis + regenerate buttons, scoped per panel.
	Array.prototype.forEach.call(document.querySelectorAll('.la-ai-panel'), function (panel) {
		var actionBtn = panel.querySelector('[data-la-ai-action]');
		var regenBtn  = panel.querySelector('[data-la-ai-regen]');
		if (actionBtn) {
			actionBtn.addEventListener('click', function () { runAnalysis(panel, actionBtn, false); });
		}
		if (regenBtn) {
			regenBtn.addEventListener('click', function () { runAnalysis(panel, actionBtn, true); });
		}
	});

	// Connector-approval buttons (panel or settings).
	Array.prototype.forEach.call(document.querySelectorAll('[data-la-ai-approve]'), function (btn) {
		btn.addEventListener('click', function () {
			btn.disabled = true;
			post('login_armor_ai_approve', {}).then(function (json) {
				if (json && json.success) { window.location.reload(); }
				else { btn.disabled = false; notify('Action failed.', 'error'); }
			}).catch(function () { btn.disabled = false; notify('Network error.', 'error'); });
		});
	});

	// Deep-analysis cursor: reveal the privacy warning live the moment it is
	// ticked. The value itself is NOT saved on change: it is persisted through
	// the standard Settings "Save" bar (admin.js save-all), because deep mode
	// sends real IP addresses out and needs an explicit, confirmed save.
	Array.prototype.forEach.call(document.querySelectorAll('[data-la-ai-deep-toggle]'), function (cb) {
		var warn = document.querySelector('[data-la-ai-deep-warn]');
		cb.addEventListener('change', function () {
			if (warn) { warn.hidden = !cb.checked; }
		});
	});
})();
