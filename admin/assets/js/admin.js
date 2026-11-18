/*!
 * Login Armor v2.0.0 admin JS
 * Vanilla, no dependency.
 */
(function () {
	'use strict';

	const root = document.getElementById('la-root');
	if (!root) {
		return;
	}

	const ajaxUrl = root.getAttribute('data-la-ajax') || '';

	// ---------- Keep the worked-on settings section open across reloads ----------
	// Almost every admin action ends in window.location.reload(), which resets the
	// <details> accordions to their default (categories collapsed, modules closed).
	// That collapsed the section the user had just acted in: e.g. enabling the
	// firewall snapped its panel shut before they could pick a mode/rules. We
	// record the enclosing module id at action time; initScrollToSection() consumes
	// it on the next load to re-open that module AND its parent category and scroll
	// back to it. Centralized here so it covers every module, not just the firewall.
	function laRememberSection(el) {
		var w = (el && el.closest) ? el.closest('.la-setting-wrapper') : null;
		// 2.8.0: a module's Disable button follows its <details> instead of
		// sitting in its <summary>, so it is a sibling of the wrapper.
		if (!w && el && el.closest) {
			var item = el.closest('.la-setting-item');
			w = item ? item.querySelector(':scope > .la-setting-wrapper') : null;
		}
		if (w && w.id) {
			try { sessionStorage.setItem('la_reopen', w.id); } catch (e) {}
		}
	}
	root.addEventListener('click', function (e) {
		var trigger = e.target.closest('[data-la-action]');
		if (trigger) { laRememberSection(trigger); }
	}, true);
	root.addEventListener('submit', function (e) {
		laRememberSection(e.target);
	}, true);

	// All user-facing dialog strings are localized PHP-side via wp_localize_script
	// and exposed as window.loginArmor.strings. s(key) returns a {title, body, …}
	// bundle and fmt(tmpl, a, b, …) substitutes %s placeholders in order.
	const LS = (window.loginArmor && window.loginArmor.strings) || {};
	function s(key) { return LS[key] || {}; }
	// sprintf-lite: supports %s, %d, and positional %1$s / %2$s / %1$d.
	function fmt(tmpl, ...args) {
		var i = 0;
		return String(tmpl || '').replace(/%(?:(\d+)\$)?([sd])/g, function (_, pos) {
			var v = pos ? args[parseInt(pos, 10) - 1] : args[i++];
			return v !== undefined ? String(v) : '';
		});
	}

	/* ---------- Overview tab live refresh ---------- */
	const activeTab     = root.getAttribute('data-la-active-tab') || '';
	const overviewNonce = root.getAttribute('data-la-overview-nonce') || '';
	const POLL_INTERVAL = 10000;
	const MAX_FAILURES  = 3;

	if (activeTab === 'overview' && overviewNonce) {
		let paused       = false;
		let failureCount = 0;
		let timer        = null;

		const pauseBtn = document.querySelector('[data-la-live-pause]');
		const liveBox  = document.querySelector('[data-la-live-events]');
		// Lot 18: hero sub holds the "last checked" span; old topbar selector is dead.
		const lastMeta = document.querySelector('[data-la-last-check]');

		function escapeHtml(str) {
			return String(str)
				.replace(/&/g, '&amp;')
				.replace(/</g, '&lt;')
				.replace(/>/g, '&gt;')
				.replace(/"/g, '&quot;')
				.replace(/'/g, '&#039;');
		}

		var LIVE_L10N = (window.loginArmor && window.loginArmor.liveEvents) || {};

		function statusInfo(status) {
			if (status === 'success') { return { cls: 'ok',   txt: LIVE_L10N.statusOk   || 'OK'   }; }
			if (status === 'locked')  { return { cls: 'lock', txt: LIVE_L10N.statusLock || 'LOCK' }; }
			return { cls: 'fail', txt: LIVE_L10N.statusFail || 'FAIL' };
		}

		function actionLabel(status) {
			if (status === 'success') { return LIVE_L10N.actionSuccess || 'Successful sign-in'; }
			if (status === 'locked')  { return LIVE_L10N.actionLocked  || 'Locked out'; }
			return LIVE_L10N.actionDenied || 'Auth denied: wrong password';
		}

		function shortUa(ua) {
			if (!ua) { return ''; }
			var hasChrome  = /Chrome\/[\d.]+/.test(ua);
			var hasSafari  = /Safari\/[\d.]+/.test(ua);
			if (hasChrome && ua.indexOf('Mac OS') !== -1)  { return LIVE_L10N.uaChromeMac     || 'Chrome on macOS'; }
			if (hasChrome && ua.indexOf('Windows') !== -1) { return LIVE_L10N.uaChromeWindows || 'Chrome on Windows'; }
			if (hasChrome && ua.indexOf('Linux') !== -1)   { return LIVE_L10N.uaChromeLinux   || 'Chrome on Linux'; }
			if (hasSafari && ua.indexOf('iPhone') !== -1)  { return LIVE_L10N.uaSafariIOS     || 'Safari on iOS'; }
			if (hasSafari && ua.indexOf('iPad') !== -1)    { return LIVE_L10N.uaSafariIPadOS  || 'Safari on iPadOS'; }
			if (hasSafari && ua.indexOf('Mac OS') !== -1)  { return LIVE_L10N.uaSafariMac     || 'Safari on macOS'; }
			if (/Firefox\/[\d.]+/.test(ua))                 { return LIVE_L10N.uaFirefox       || 'Firefox'; }
			if (/Edg\/[\d.]+/.test(ua))                     { return LIVE_L10N.uaEdge          || 'Edge'; }
			if (/curl\/[\d.]+/.test(ua))                    { return LIVE_L10N.uaCurl          || 'curl'; }
			if (/wget\/[\d.]+/.test(ua))                    { return LIVE_L10N.uaWget          || 'wget'; }
			if (/python-requests\/[\d.]+/.test(ua))         { return LIVE_L10N.uaPython        || 'python-requests'; }
			if (/Go-http-client\/[\d.]+/.test(ua))          { return LIVE_L10N.uaGo            || 'Go http-client'; }
			if (/bot|spider|crawler/i.test(ua))             { return LIVE_L10N.uaBot           || 'Bot / crawler'; }
			if (/jetpack/i.test(ua))                        { return LIVE_L10N.uaJetpack       || 'Jetpack (WordPress.com)'; }
			if (/wordpress\.com/i.test(ua))                 { return LIVE_L10N.uaWpcom         || 'WordPress.com'; }
			if (/WordPress\/[\d.]+/.test(ua))               { return LIVE_L10N.uaWordpress     || 'WordPress'; }
			// Generic fallback: trim to a word boundary, drop a dangling "(" and
			// trailing punctuation, append an ellipsis: never a cut-off token.
			if (ua.length <= 30) { return ua; }
			var uaShort = ua.substring(0, 30);
			var uaSp = uaShort.lastIndexOf(' ');
			if (uaSp >= 12) { uaShort = uaShort.substring(0, uaSp); }
			return uaShort.replace(/[ \t(;,/-]+$/, '') + '…';
		}

		function renderEvents(events) {
			if (!liveBox) { return; }
			if (!events || events.length === 0) {
				liveBox.innerHTML = '<div class="la-live-events__empty">' + escapeHtml(LIVE_L10N.empty || 'No events recorded yet.') + '</div>';
				return;
			}
			var globeSvg = '<svg class="la-live-events__globe" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 014 10 15.3 15.3 0 01-4 10 15.3 15.3 0 01-4-10 15.3 15.3 0 014-10z"/></svg>';
			const parts = events.map(function (ev) {
				const info      = statusInfo(ev.status);
				const user      = (ev.username === '' || ev.username == null) ? '-' : ev.username;
				const letter    = (user === '-') ? '-' : user.charAt(0).toUpperCase();
				// V2.4.5: the server resolves the real failure reason (wrong
				// password, 2FA lockout, blocked cookies…). Fall back to the
				// generic status label for rows logged before the migration.
				const action    = (ev.reason_label && ev.status !== 'success' && ev.status !== 'locked')
					? ev.reason_label
					: actionLabel(ev.status);
				const uaShort   = shortUa(ev.user_agent || '');
				const isFail    = info.cls === 'fail';
				const smallCls  = isFail ? ' class="is-bad"' : '';
				const userCls   = 'la-live-events__user' + (isFail ? ' is-fail' : '');
				// 2.7.8: a space on each side of the dot, as the server renders
				// it. Without them "réussie·Chrome" was one word, and a narrow
				// cell broke it anywhere: "Ch" on one line, "rome" on the next.
				const uaBlock   = uaShort
					? ' <span class="la-live-events__sep">·</span> ' + escapeHtml(uaShort)
					: '';
				return '<div class="la-live-events__row" data-la-event-id="' + (parseInt(ev.id, 10) || 0) + '">' +
					'<span class="la-live-events__time">' + escapeHtml(ev.time_short) + '</span>' +
					'<span class="la-badge la-badge--' + info.cls + '">' + info.txt + '</span>' +
					'<span class="la-live-events__ip">' + globeSvg + escapeHtml(ev.ip) + '</span>' +
					'<span class="' + userCls + '">' +
						'<span class="la-live-events__avatar la-live-events__avatar--' + info.cls + '">' + escapeHtml(letter) + '</span>' +
						'<span class="la-live-events__detail">' +
							'<b>' + escapeHtml(user) + '</b>' +
							'<small' + smallCls + '>' + escapeHtml(action) + uaBlock + '</small>' +
						'</span>' +
					'</span>' +
					'<span class="la-live-events__ago">' + escapeHtml(ev.ago || '') + '</span>' +
				'</div>';
			});
			liveBox.innerHTML = parts.join('');
		}

		function updateLastEvent(text) {
			// Lot 18: hero sub has its own template ("System last checked X..."),
			// just swap the span's inner text.
			if (lastMeta) {
				lastMeta.textContent = text;
			}
		}

		function fetchOnce() {
			if (paused) { return; }
			const body = new URLSearchParams();
			body.append('action', 'login_armor_overview_data');
			body.append('nonce', overviewNonce);

			fetch(ajaxUrl, {
				method: 'POST',
				credentials: 'same-origin',
				headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
				body: body.toString()
			})
				.then(function (r) { return r.json(); })
				.then(function (json) {
					if (!json || !json.success || !json.data) {
						throw new Error('bad-payload');
					}
					failureCount = 0;
					renderEvents(json.data.recent_events);
					if (json.data.last_event_ago) {
						updateLastEvent(json.data.last_event_ago);
					}
					if (json.data.all_quiet !== undefined) {
						// Lot 18 redesign: the hero carries data-la-allquiet="1|0"
						// (the old .la-allquiet card was removed). Read the actual
						// rendered state from the attribute so we only reload when
						// the quiet state has really flipped.
						var heroEl       = document.querySelector('[data-la-allquiet]');
						var wantAllQuiet = !!json.data.all_quiet;
						var haveAllQuiet = heroEl ? heroEl.getAttribute('data-la-allquiet') === '1' : false;
						if (heroEl && wantAllQuiet !== haveAllQuiet) {
							window.location.reload();
						}
					}
				})
				.catch(function () {
					failureCount += 1;
					if (failureCount >= MAX_FAILURES) {
						if (timer) { clearInterval(timer); timer = null; }
					}
				});
		}

		if (pauseBtn) {
			// Lot 18: new markup is <svg>…</svg><span class="la-pause-label">Pause</span>.
			// Swap both the icon path and the label; dim the streaming pill.
			const pauseLabel = pauseBtn.querySelector('.la-pause-label');
			const pauseIcon  = pauseBtn.querySelector('svg');
			const streaming  = document.querySelector('.la-streaming');

			function updatePauseVisual() {
				if (pauseLabel) {
					pauseLabel.textContent = paused ? 'Resume' : 'Pause';
				}
				if (pauseIcon) {
					pauseIcon.innerHTML = paused
						? '<path d="M5 3l14 9-14 9V3z"/>'
						: '<rect x="6" y="4" width="4" height="16"/><rect x="14" y="4" width="4" height="16"/>';
				}
				pauseBtn.classList.toggle('is-active', paused);
				pauseBtn.setAttribute('aria-pressed', paused ? 'true' : 'false');
				if (streaming) { streaming.style.opacity = paused ? '0.4' : '1'; }
			}

			pauseBtn.addEventListener('click', function () {
				paused = !paused;
				updatePauseVisual();
			});
		}

		document.addEventListener('click', function (ev) {
			var btn = ev.target.closest('[data-la-advice-skip]');
			if (!btn) { return; }
			var wrap = btn.closest('[data-la-advice]');
			var key  = wrap && wrap.getAttribute('data-la-advice-key');
			if (!key) { return; }
			btn.disabled = true;
			postAction('login_armor_skip_advice', { key: key }).then(function (res) {
				if (res && res.success) {
					window.location.reload();
				} else {
					btn.disabled = false;
					if (window.LA && window.LA.toast) {
						window.LA.toast('Could not skip advice.', 'error');
					}
				}
			}).catch(function () {
				btn.disabled = false;
				if (window.LA && window.LA.toast) {
					window.LA.toast('Network error.', 'error');
				}
			});
		});

		// Kick off: first fetch immediately so the "last event" counter updates on load,
		// then schedule the polling loop.
		fetchOnce();
		timer = setInterval(fetchOnce, POLL_INTERVAL);
	}

	/* ---------- Admin actions (Incidents + Events) ---------- */
	const adminNonce = root.getAttribute('data-la-admin-nonce') || '';

	function ensureToastZone() {
		let zone = document.querySelector('.la-toast-zone');
		if (!zone) {
			zone = document.createElement('div');
			zone.className = 'la-toast-zone';
			document.body.appendChild(zone);
		}
		return zone;
	}

	// 2.8.0: the login URL may break after a slash, and nowhere else, as the
	// server renders it (sections/hide-login.php). textContent would drop the
	// <wbr> break points and the URL would spill out of its box on a phone.
	function laSetHideUrl(el, url) {
		el.textContent = '';
		String(url).replace(/\/(?!\/)/g, '/\u0000').split('\u0000').forEach(function (part, i, all) {
			el.appendChild(document.createTextNode(part));
			if (i < all.length - 1) { el.appendChild(document.createElement('wbr')); }
		});
	}

	function toast(message, kind) {
		// Translate known (English) toast messages via the PHP-localized map so
		// they honour the site locale. Unknown/dynamic messages pass through.
		if (window.loginArmor && window.loginArmor.toasts && window.loginArmor.toasts[message]) {
			message = window.loginArmor.toasts[message];
		}
		const zone = ensureToastZone();
		const el = document.createElement('div');
		el.className = 'la-toast la-toast--' + (kind || 'success');
		el.textContent = message;
		zone.appendChild(el);
		setTimeout(function () {
			el.style.transition = 'opacity 200ms';
			el.style.opacity = '0';
			setTimeout(function () { el.remove(); }, 220);
		}, 3000);
	}

	window.LA = window.LA || {};
	window.LA.toast = toast;

	function postAction(actionName, payload) {
		if (!adminNonce) {
			toast('Missing nonce, reload the page.', 'error');
			return Promise.reject(new Error('no-nonce'));
		}
		const body = new URLSearchParams();
		body.append('action', actionName);
		body.append('nonce', adminNonce);
		Object.keys(payload || {}).forEach(function (k) {
			body.append(k, payload[k]);
		});
		return fetch(ajaxUrl, {
			method: 'POST',
			credentials: 'same-origin',
			headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
			body: body.toString()
		}).then(function (r) { return r.json(); });
	}

	// 2.9.0: application-password monitoring, saved on change.
	document.addEventListener('change', function (ev) {
		var box = ev.target;
		if (!box || !box.matches || !box.matches('[data-la-app-watch]')) { return; }
		box.disabled = true;
		postAction('login_armor_set_app_password_watch', { enabled: box.checked ? '1' : '0' }).then(function (json) {
			box.disabled = false;
			box.focus();
			if (json && json.success) {
				toast(box.checked ? (s('headless').watchOn || 'Monitoring enabled.') : (s('headless').watchOff || 'Monitoring disabled.'), 'success');
			} else {
				box.checked = !box.checked;
				toast(s('headless').watchFailed || 'Save failed.', 'error');
			}
		}).catch(function () {
			box.disabled = false;
			box.focus();
			box.checked = !box.checked;
			toast('Network error.', 'error');
		});
	});

	// Same as postAction() but lets the browser set the multipart boundary,
	// for the settings-file upload.
	function postMultipart(actionName, formData) {
		if (!adminNonce) {
			toast('Missing nonce, reload the page.', 'error');
			return Promise.reject(new Error('no-nonce'));
		}
		formData.append('action', actionName);
		formData.append('nonce', adminNonce);
		return fetch(ajaxUrl, {
			method: 'POST',
			credentials: 'same-origin',
			body: formData
		}).then(function (r) { return r.json(); });
	}

	/* ---------- Cache-exclusion notice: remember the dismissal ---------- */
	// WordPress' own is-dismissible affordance only removes the notice from
	// the current DOM: nothing is stored, so the same warning is printed again
	// on the next page load. That is exactly the defect being fixed here, and
	// the server call below is the whole difference between a dismiss button
	// and a dismissal. The listener is on document because admin_notices
	// renders above #la-root, outside the page shell the other handlers watch.
	document.addEventListener('click', function (e) {
		if (!e.target.closest) { return; }
		var btn = e.target.closest('.notice[data-la-notice="cache-exclusion"] .notice-dismiss');
		if (!btn) { return; }
		postAction('login_armor_dismiss_cache_notice', {}).then(function (json) {
			// Say so when it did not stick. Staying silent would leave the
			// administrator believing the notice is answered until it returns
			// on the next page, which is the behaviour being fixed.
			if (!json || !json.success) {
				toast('Save failed.', 'error');
			}
		}).catch(function () {
			toast('Network error.', 'error');
		});
	});

	/* ---------- Settings transfer helpers (DOM APIs only) ---------- */
	var laTransferText = '';

	function laEl(tag, className, text) {
		var el = document.createElement(tag);
		if (className) { el.className = className; }
		if (text !== undefined && text !== null) { el.textContent = String(text); }
		return el;
	}

	function laTransferList(container, title, items, className) {
		if (!items || !items.length) { return; }
		container.appendChild(laEl('p', 'la-transfer__list-title ' + (className || ''), title));
		var ul = laEl('ul', 'la-transfer__list ' + (className || ''));
		items.forEach(function (item) {
			var text = (typeof item === 'string') ? item : ((item.path ? item.path + ': ' : '') + (item.message || ''));
			ul.appendChild(laEl('li', '', text));
		});
		container.appendChild(ul);
	}

	function laRenderTransferPlan(container, data, isError) {
		var st = s('settingsTransfer');
		while (container.firstChild) { container.removeChild(container.firstChild); }
		container.hidden = false;

		if (data.message) {
			container.appendChild(laEl('p', 'la-transfer__msg ' + (isError ? 'la-transfer__msg--error' : ''), data.message));
		}
		if (data.source && data.source.host) {
			container.appendChild(laEl('p', 'la-transfer__source', fmt(st.source || 'Exported from %1$s (Login Armor %2$s, %3$s)', data.source.host, data.source.version, data.source.exported_at)));
		}
		laTransferList(container, st.errorsTitle || 'Errors:', data.errors, 'la-transfer__list--error');

		var counts = data.counts || { change: 0, same: 0 };
		var rows = (data.rows || []).filter(function (r) { return r.status === 'change'; });
		if (!data.errors || !data.errors.length) {
			if (!rows.length) {
				container.appendChild(laEl('p', 'la-transfer__msg', st.noChanges || 'Nothing to apply.'));
			} else {
				container.appendChild(laEl('p', 'la-transfer__msg', fmt(st.summary || '%1$s setting(s) will change, %2$s already match.', counts.change, counts.same)));
				var table = laEl('table', 'la-transfer__diff');
				var thead = laEl('thead');
				var hr = laEl('tr');
				[st.colModule || 'Module', st.colSetting || 'Setting', st.colCurrent || 'On this site', st.colIncoming || 'In the file'].forEach(function (h) {
					hr.appendChild(laEl('th', '', h));
				});
				thead.appendChild(hr);
				table.appendChild(thead);
				var tbody = laEl('tbody');
				rows.forEach(function (r) {
					var tr = laEl('tr');
					tr.appendChild(laEl('td', 'la-transfer__module', r.module));
					tr.appendChild(laEl('td', 'la-transfer__setting', r.setting));
					tr.appendChild(laEl('td', 'la-transfer__current', r.current));
					tr.appendChild(laEl('td', 'la-transfer__incoming', r.incoming));
					tbody.appendChild(tr);
				});
				table.appendChild(tbody);
				var wrap = laEl('div', 'la-transfer__diff-wrap');
				wrap.appendChild(table);
				container.appendChild(wrap);
			}
		}
		if (data.login_url_after) {
			container.appendChild(laEl('p', 'la-transfer__url', fmt(st.loginUrlAfter || 'The login URL will become: %s', data.login_url_after)));
		}
		laTransferList(container, st.warningsTitle || 'Please read before applying:', data.warnings, 'la-transfer__list--warn');
		laTransferList(container, st.unknownTitle || 'Ignored:', data.unknown, 'la-transfer__list--muted');

		return !isError && rows.length > 0;
	}

	function laRenderTransferReport(container, data) {
		var st = s('settingsTransfer');
		while (container.firstChild) { container.removeChild(container.firstChild); }
		container.hidden = false;
		container.appendChild(laEl('p', 'la-transfer__msg la-transfer__msg--ok', fmt(st.applied || 'Settings imported: %1$s applied, %2$s unchanged.', (data.applied || []).length, (data.unchanged || []).length)));
		laTransferList(container, st.failedTitle || 'Could not apply:', data.errors, 'la-transfer__list--error');
		laTransferList(container, st.warningsTitle || 'Please read:', data.warnings, 'la-transfer__list--warn');
		if (data.login_url) {
			var p = laEl('p', 'la-transfer__url la-transfer__url--final');
			p.appendChild(laEl('span', '', (st.loginUrlNow || 'Your login URL is now:') + ' '));
			var a = laEl('a', '', data.login_url);
			a.href = data.login_url;
			p.appendChild(a);
			container.appendChild(p);
		}
		var reload = laEl('button', 'la-btn la-btn--secondary la-transfer__reload', st.reloadLabel || 'Reload the page');
		reload.type = 'button';
		reload.addEventListener('click', function () { window.location.assign(window.location.href); });
		container.appendChild(reload);
	}

	var updateHardeningScoreGlobal = null;

	function doSubnetOrUnblock(act, ip, btn) {
		btn.disabled = true;
		var endpoint;
		var successToast;
		if (act === 'subnet-block') {
			endpoint = 'login_armor_subnet_block';
			successToast = 'Subnet blocked.';
		} else if (act === 'subnet-unblock') {
			endpoint = 'login_armor_subnet_unblock';
			successToast = 'Subnet removed from blocklist.';
		} else {
			endpoint = 'login_armor_ip_unblock_v2';
			successToast = 'IP unblocked.';
		}
		postAction(endpoint, { ip: ip }).then(function (json) {
			if (json && json.success) {
				toast(successToast, 'success');
				setTimeout(function () { window.location.reload(); }, 600);
			} else {
				btn.disabled = false;
				// 2.8.0: the server explains a refusal it can name, such as
				// the administrator's own network, in a translated `notice`.
				toast((json && json.data && json.data.notice) || 'Action failed.', 'error');
			}
		}).catch(function () {
			btn.disabled = false;
			toast('Network error.', 'error');
		});
	}

	// --- Incident bulk selection + bulk resolve/ignore (2.1.17) ---
	//
	// Two scopes since 2.7.1. The header checkbox ticks the rows the page
	// rendered, which is 25 of them; with 235 matching the filter, clearing
	// the list meant repeating the whole operation ten times. So selecting the
	// page offers a second, explicit action for the whole filtered set, and
	// that one sends the FILTER to the server rather than 235 ids in a body.
	// laBulkFiltered is which of the two is armed right now, and every path
	// that changes the selection puts it back to false: an action must never
	// be wider than the sentence the administrator last read.
	var laBulkFiltered = false;

	function laBulkChecks() {
		return Array.prototype.slice.call(document.querySelectorAll('.la-incident-check'));
	}
	function laBulkSelectedIds() {
		return laBulkChecks()
			.filter(function (c) { return c.checked; })
			.map(function (c) { return parseInt(c.value, 10) || 0; })
			.filter(function (id) { return id > 0; });
	}
	function laBulkBar() {
		return document.querySelector('[data-la-bulk-bar]');
	}
	function laBulkFilterTotal() {
		var bar = laBulkBar();
		return bar ? (parseInt(bar.getAttribute('data-la-filter-total'), 10) || 0) : 0;
	}
	// The filter the list is showing, read back off the bar the server rendered.
	// Nothing is reconstructed from the URL: what the server put here is what
	// the server used to build the list.
	function laBulkFilterPayload() {
		var bar = laBulkBar();
		if (!bar) { return {}; }
		return {
			scope: 'filtered',
			status: bar.getAttribute('data-la-filter-status') || '',
			pattern: bar.getAttribute('data-la-filter-pattern') || '',
			severity: bar.getAttribute('data-la-filter-severity') || '0',
			min_severity: bar.getAttribute('data-la-filter-min-severity') || '0',
			period: bar.getAttribute('data-la-filter-period') || ''
		};
	}
	function laBulkSync() {
		var checks = laBulkChecks();
		var selected = checks.filter(function (c) { return c.checked; });
		var pageFull = checks.length > 0 && selected.length === checks.length;

		// Selecting the whole filter only survives while the whole page is
		// still ticked. Untick one row and the wider action is off, because
		// the bar no longer says what it would do.
		if (!pageFull) { laBulkFiltered = false; }

		var countEl = document.querySelector('[data-la-bulk-count]');
		if (countEl) {
			countEl.textContent = String(laBulkFiltered ? laBulkFilterTotal() : selected.length);
		}
		Array.prototype.forEach.call(document.querySelectorAll('[data-la-bulk-op]'), function (b) {
			b.disabled = selected.length === 0 && !laBulkFiltered;
		});
		var all = document.querySelector('[data-la-bulk-all]');
		if (all) {
			all.checked = pageFull;
			all.indeterminate = selected.length > 0 && !pageFull;
		}

		var scope = document.querySelector('[data-la-bulk-scope]');
		if (scope) {
			scope.hidden = !pageFull;
			var pageMsg = scope.querySelector('[data-la-bulk-scope-page]');
			var allMsg = scope.querySelector('[data-la-bulk-scope-filtered]');
			if (pageMsg) { pageMsg.hidden = laBulkFiltered; }
			if (allMsg) { allMsg.hidden = !laBulkFiltered; }
		}
	}
	document.addEventListener('change', function (e) {
		if (e.target.matches && e.target.matches('[data-la-bulk-all]')) {
			var on = e.target.checked;
			laBulkFiltered = false;
			laBulkChecks().forEach(function (c) { c.checked = on; });
			laBulkSync();
			return;
		}
		if (e.target.classList && e.target.classList.contains('la-incident-check')) {
			laBulkFiltered = false;
			laBulkSync();
		}
	});

	document.addEventListener('click', function (e) {
		// Widen the selection from this page to everything the filter matches.
		if (e.target.closest('[data-la-bulk-select-all-filtered]')) {
			laBulkFiltered = true;
			laBulkChecks().forEach(function (c) { c.checked = true; });
			laBulkSync();
			return;
		}
		if (e.target.closest('[data-la-bulk-clear-filtered]')) {
			laBulkFiltered = false;
			laBulkSync();
			return;
		}

		const bulkBtn = e.target.closest('[data-la-bulk-op]');
		if (bulkBtn) {
			const op = bulkBtn.getAttribute('data-la-bulk-op');
			const ids = laBulkSelectedIds();
			const filtered = laBulkFiltered;
			const count = filtered ? laBulkFilterTotal() : ids.length;
			if (!count) { return; }
			const bulkS = s('incidentBulk');
			LA.confirm({
				title: op === 'resolve' ? (bulkS.titleResolve || 'Resolve incidents') : (bulkS.titleIgnore || 'Ignore incidents'),
				// Two different sentences on purpose: "all 235 matching your
				// filter" is a materially different act from "these 25", and
				// the confirmation is the last place it can still be said.
				body: fmt(filtered ? (bulkS.bodyFiltered || 'Apply to ALL %s incidents matching the current filter?') : (bulkS.body || 'Apply to %s selected incident(s)?'), String(count)),
				variant: op === 'resolve' ? 'primary' : 'danger',
				confirmLabel: bulkS.confirmLabel || 'Confirm',
				cancelLabel: bulkS.cancelLabel || 'Cancel'
			}).then(function (ok) {
				if (!ok) { return; }
				Array.prototype.forEach.call(document.querySelectorAll('[data-la-bulk-op]'), function (b) { b.disabled = true; });
				const payload = filtered
					? Object.assign({ op: op }, laBulkFilterPayload())
					: { op: op, scope: 'page', ids: ids.join(',') };
				postAction('login_armor_incidents_bulk', payload).then(function (json) {
					if (json && json.success) {
						const data = json.data || {};
						// The server's count, never the one guessed here: a
						// filtered run stops at a per-request ceiling, and a
						// toast that reported the intention rather than the
						// result would hide the rows that are still there.
						const done = typeof data.updated === 'number' ? data.updated : ids.length;
						const left = typeof data.remaining === 'number' ? data.remaining : 0;
						let msg = fmt(op === 'resolve' ? (bulkS.doneResolved || '%s incident(s) resolved.') : (bulkS.doneIgnored || '%s incident(s) ignored.'), String(done));
						if (left > 0) { msg += ' ' + fmt(bulkS.remaining || '%s still match the filter: run it again to continue.', String(left)); }
						toast(msg, 'success');
						setTimeout(function () { window.location.reload(); }, 900);
					} else {
						toast('Action failed.', 'error');
						laBulkSync();
					}
				}).catch(function () {
					toast('Network error.', 'error');
					laBulkSync();
				});
			});
			return;
		}

		const btn = e.target.closest('[data-la-action]');
		if (!btn) { return; }
		const action = btn.getAttribute('data-la-action');

		if (action === 'resolve' || action === 'ignore') {
			const id = parseInt(btn.getAttribute('data-la-id'), 10) || 0;
			if (id <= 0) { return; }
			btn.disabled = true;
			const endpoint = action === 'resolve' ? 'login_armor_incident_resolve' : 'login_armor_incident_ignore';
			postAction(endpoint, { id: id }).then(function (json) {
				if (json && json.success) {
					toast('Incident ' + (action === 'resolve' ? 'resolved' : 'ignored') + '.', 'success');
					setTimeout(function () { window.location.reload(); }, 600);
				} else {
					btn.disabled = false;
					toast('Action failed.', 'error');
				}
			}).catch(function () {
				btn.disabled = false;
				toast('Network error.', 'error');
			});
			return;
		}

		if (action === 'subnet-block' || action === 'ip-unblock' || action === 'subnet-unblock') {
			const ip = btn.getAttribute('data-la-ip') || '';
			if (!ip) { return; }
			if (action === 'subnet-block') {
				var sb = s('subnetBlock');
				LA.confirm({
					title: sb.title,
					body: fmt(sb.body, ip),
					variant: 'danger',
					confirmLabel: sb.confirmLabel,
					cancelLabel: sb.cancelLabel
				}).then(function (ok) { if (ok) { doSubnetOrUnblock('subnet-block', ip, btn); } });
				return;
			}
			if (action === 'subnet-unblock') {
				var su = s('subnetUnblock');
				LA.confirm({
					title: su.title,
					body: fmt(su.body, ip),
					variant: 'danger',
					confirmLabel: su.confirmLabel,
					cancelLabel: su.cancelLabel
				}).then(function (ok) { if (ok) { doSubnetOrUnblock('subnet-unblock', ip, btn); } });
				return;
			}
			if (action === 'ip-unblock') {
				var iu = s('ipUnblock');
				LA.confirm({
					title: iu.title,
					body: fmt(iu.body, ip),
					variant: 'primary',
					confirmLabel: iu.confirmLabel,
					cancelLabel: iu.cancelLabel
				}).then(function (ok) { if (ok) { doSubnetOrUnblock('ip-unblock', ip, btn); } });
				return;
			}
			return;
		}

		if (action === 'events-export') {
			// CSV export uses a form POST so the browser handles the download prompt.
			const form = document.createElement('form');
			form.method = 'POST';
			form.action = ajaxUrl;
			form.style.display = 'none';
			function addField(name, value) {
				const i = document.createElement('input');
				i.type = 'hidden';
				i.name = name;
				i.value = value;
				form.appendChild(i);
			}
			addField('action', 'login_armor_events_export');
			addField('nonce', adminNonce);
			addField('status',   btn.getAttribute('data-la-status') || '');
			addField('ip',       btn.getAttribute('data-la-ip') || '');
			addField('username', btn.getAttribute('data-la-username') || '');
			addField('period',   btn.getAttribute('data-la-period') || '');
			addField('source',   btn.getAttribute('data-la-source') || '');
			document.body.appendChild(form);
			form.submit();
			document.body.removeChild(form);
			return;
		}

		if (action === 'activity-export') {
			// CSV export for the Activity Log tab: same form-POST pattern as events-export.
			const form = document.createElement('form');
			form.method = 'POST';
			form.action = ajaxUrl;
			form.style.display = 'none';
			function addActField(name, value) {
				const i = document.createElement('input');
				i.type = 'hidden';
				i.name = name;
				i.value = value;
				form.appendChild(i);
			}
			addActField('action', 'login_armor_activity_export');
			addActField('nonce', adminNonce);
			addActField('object_type', btn.getAttribute('data-la-object-type') || '');
			addActField('user_id',     btn.getAttribute('data-la-user-id') || '');
			addActField('period',      btn.getAttribute('data-la-period') || '');
			document.body.appendChild(form);
			form.submit();
			document.body.removeChild(form);
			return;
		}

		/* ---------- Lot 5: Hide Login actions ---------- */

		if (action === 'hide-copy') {
			const sel = btn.getAttribute('data-la-copy-target');
			const el  = sel ? document.querySelector(sel) : null;
			if (el && navigator.clipboard) {
				const val = (el.value !== undefined) ? el.value : el.textContent;
				navigator.clipboard.writeText(val).then(function () {
					btn.classList.add('la-lab__btn--copied');
					var origText = btn.textContent;
					btn.textContent = 'Copied!';
					setTimeout(function() {
						btn.classList.remove('la-lab__btn--copied');
						btn.textContent = origText;
					}, 1500);
					toast('Copied.', 'success');
				}).catch(function () {
					toast('Copy failed.', 'error');
				});
			}
			return;
		}

		if (action === 'hide-regenerate') {
			var hr = s('hideRegenerate');
			LA.confirm({
				title: hr.title,
				body: hr.body,
				variant: 'danger',
				confirmLabel: hr.confirmLabel,
				cancelLabel: hr.cancelLabel
			}).then(function (ok) {
				if (!ok) { return; }
				btn.disabled = true;
				postAction('login_armor_regenerate_slug', {}).then(function (json) {
					btn.disabled = false;
					if (json && json.success) {
						const slugInput = document.getElementById('la-hide-slug');
						if (slugInput) { slugInput.value = json.data.slug; }
						const urlEl = document.querySelector('[data-la-hide-url]');
						if (urlEl) { laSetHideUrl(urlEl, json.data.url); }
						toast('Regenerated. This new URL was not emailed: bookmark it now, or use “Email me this URL”.', 'success');
					} else {
						toast('Regenerate failed.', 'error');
					}
				}).catch(function () {
					btn.disabled = false;
					toast('Network error.', 'error');
				});
			});
			return;
		}

		if (action === 'hide-save') {
			const hideForm = btn.closest('form');
			if (!hideForm) { return; }
			const slugInput     = hideForm.querySelector('[name="slug"]');
			const typeInput     = hideForm.querySelector('[name="redirect_type"]:checked');
			const urlInput      = hideForm.querySelector('[name="redirect_url"]');
			const payload = {
				slug: slugInput ? slugInput.value : '',
				redirect_type: typeInput ? typeInput.value : 'notfound',
				redirect_url: urlInput ? urlInput.value : ''
			};
			btn.disabled = true;
			postAction('login_armor_save_hide_settings', payload).then(function (json) {
				btn.disabled = false;
				if (json && json.success) {
					const urlEl = document.querySelector('[data-la-hide-url]');
					if (urlEl) { laSetHideUrl(urlEl, json.data.url); }
					toast('Hide Login settings saved.', 'success');
					if (window._laStickyHide) { window._laStickyHide(); }
				} else {
					const msg = (json && json.data && json.data.message) ? json.data.message : 'Save failed.';
					toast(msg, 'error');
				}
			}).catch(function () {
				btn.disabled = false;
				toast('Network error.', 'error');
			});
			return;
		}

		if (action === 'hide-reset') {
			var hrs = s('hideReset');
			LA.confirm({
				title: hrs.title,
				body: hrs.body,
				variant: 'danger',
				confirmLabel: hrs.confirmLabel,
				cancelLabel: hrs.cancelLabel
			}).then(function (ok) {
				if (!ok) { return; }
				btn.disabled = true;
				postAction('login_armor_regenerate_slug', {}).then(function (regen) {
					if (!regen || !regen.success) {
						btn.disabled = false;
						toast('Reset failed.', 'error');
						return;
					}
					postAction('login_armor_save_hide_settings', {
						slug: regen.data.slug,
						redirect_type: 'notfound',
						redirect_url: ''
					}).then(function (save) {
						btn.disabled = false;
						if (save && save.success) {
							const slugInput = document.getElementById('la-hide-slug');
							if (slugInput) { slugInput.value = regen.data.slug; }
							const urlEl = document.querySelector('[data-la-hide-url]');
							if (urlEl) { laSetHideUrl(urlEl, regen.data.url); }
							const radio = document.querySelector('[name="redirect_type"][value="notfound"]');
							if (radio) { radio.checked = true; }
							const urlInput = document.querySelector('[name="redirect_url"]');
							if (urlInput) { urlInput.value = ''; }
							toast('Reset to defaults. New URL emailed to admin.', 'success');
						} else {
							toast('Reset failed.', 'error');
						}
					}).catch(function () {
						btn.disabled = false;
						toast('Network error.', 'error');
					});
				}).catch(function () {
					btn.disabled = false;
					toast('Network error.', 'error');
				});
			});
			return;
		}

		if (action === 'hide-enable') {
			var initialSlug = (window.loginArmor && window.loginArmor.hideLoginCurrentSlug) || '';
			window.LA.hideLoginPreActivate({ initialSlug: initialSlug }).then(function (choice) {
				if (!choice) { return; } // user cancelled
				btn.disabled = true;
				postAction('login_armor_enable_hide', {
					slug: choice.slug,
					send_email: choice.send_email ? '1' : '0'
				}).then(function (json) {
					if (json && json.success) {
						toast('Hide Login enabled.', 'success');
						setTimeout(function () { window.location.reload(); }, 600);
					} else {
						btn.disabled = false;
						var msg = (json && json.data && json.data.message)
							? json.data.message
							: 'Enable failed.';
						toast(msg, 'error');
					}
				}).catch(function () {
					btn.disabled = false;
					toast('Network error.', 'error');
				});
			});
			return;
		}

		if (action === 'hide-disable') {
			var hd = s('hideDisable');
			LA.confirm({
				title: hd.title,
				body: hd.body,
				variant: 'danger',
				confirmLabel: hd.confirmLabel,
				cancelLabel: hd.cancelLabel
			}).then(function (ok) {
				if (!ok) { return; }
				btn.disabled = true;
				postAction('login_armor_disable_hide', {}).then(function (json) {
					if (json && json.success) {
						toast('Hide Login disabled.', 'success');
						setTimeout(function () { window.location.reload(); }, 600);
					} else {
						btn.disabled = false;
						toast('Disable failed.', 'error');
					}
				}).catch(function () {
					btn.disabled = false;
					toast('Network error.', 'error');
				});
			});
			return;
		}

		if (action === 'hide-email') {
			const originalText = btn.textContent;
			btn.disabled = true;
			btn.textContent = 'Sending...';
			postAction('login_armor_email_slug', {}).then(function (json) {
				btn.disabled = false;
				btn.textContent = originalText;
				if (json && json.success) {
					toast('Email sent to ' + (json.data && json.data.to ? json.data.to : 'admin'), 'success');
				} else {
					toast('Email failed.', 'error');
				}
			}).catch(function () {
				btn.disabled = false;
				btn.textContent = originalText;
				toast('Network error.', 'error');
			});
			return;
		}

		/* ---------- Lot 5bis: Hardening actions ---------- */

		if (action === 'hardening-save') {
			var hardeningForm = document.querySelector('[data-la-hardening-form]');
			if (!hardeningForm) { return; }
			var checked = hardeningForm.querySelectorAll('input[type="checkbox"]:checked');
			var toggles = [];
			checked.forEach(function (cb) { toggles.push(cb.name); });
			btn.disabled = true;

			var body = new URLSearchParams();
			body.append('action', 'login_armor_save_hardening');
			body.append('nonce', adminNonce);
			toggles.forEach(function (t) { body.append('toggles[]', t); });

			fetch(ajaxUrl, {
				method: 'POST',
				credentials: 'same-origin',
				headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
				body: body.toString()
			}).then(function (r) { return r.json(); }).then(function (json) {
				btn.disabled = false;
				if (json && json.success) {
					toast('Hardening settings saved.', 'success');
					if (updateHardeningScoreGlobal) { updateHardeningScoreGlobal(); }
					if (window._laStickyHide) { window._laStickyHide(); }
				} else {
					// A refusal used to show a bare "Save failed." and leave the
					// checkbox ticked, so the screen disagreed with the database.
					// The server message is already localized; show it, and put
					// the toggle back where the database actually left it.
					var hardErr = (json && json.data) || {};
					toast(hardErr.message || 'Save failed.', 'error');
					if (hardErr.code === 'force_https_insecure') {
						var fhBox = hardeningForm.querySelector('input[name="force_https"]');
						if (fhBox) {
							fhBox.checked = false;
							fhBox.dispatchEvent(new Event('change', { bubbles: true }));
						}
					}
				}
			}).catch(function () {
				btn.disabled = false;
				toast('Network error.', 'error');
			});
			return;
		}

		/* ---------- Hardening: toggle card states + score ring ---------- */

		if (action === 'hardening-toggle') {
			// This is handled by the checkbox onchange, not the click listener
			return;
		}

		/* ---------- Lot 6: Limit Login actions ---------- */

		if (action === 'limit-enable') {
			var le = s('limitEnable');
			LA.confirm({
				title: le.title,
				body: le.body,
				variant: 'primary',
				confirmLabel: le.confirmLabel,
				cancelLabel: le.cancelLabel
			}).then(function (ok) {
				if (!ok) { return; }
				btn.disabled = true;
				postAction('login_armor_enable_limit', {}).then(function (json) {
					if (json && json.success) {
						toast('Brute force protection enabled.', 'success');
						setTimeout(function () { window.location.reload(); }, 600);
					} else {
						btn.disabled = false;
						toast('Enable failed.', 'error');
					}
				}).catch(function () {
					btn.disabled = false;
					toast('Network error.', 'error');
				});
			});
			return;
		}

		if (action === 'limit-disable') {
			var ld = s('limitDisable');
			LA.confirm({
				title: ld.title,
				body: ld.body,
				variant: 'danger',
				confirmLabel: ld.confirmLabel,
				cancelLabel: ld.cancelLabel
			}).then(function (ok) {
				if (!ok) { return; }
				btn.disabled = true;
				postAction('login_armor_disable_limit', {}).then(function (json) {
					if (json && json.success) {
						toast('Brute force protection disabled.', 'success');
						setTimeout(function () { window.location.reload(); }, 600);
					} else {
						btn.disabled = false;
						toast('Disable failed.', 'error');
					}
				}).catch(function () {
					btn.disabled = false;
					toast('Network error.', 'error');
				});
			});
			return;
		}

		if (action === 'limit-add-ip') {
			btn.disabled = true;
			postAction('login_armor_get_current_ip', {}).then(function (json) {
				btn.disabled = false;
				if (json && json.success && json.data && json.data.ip) {
					var textarea = document.querySelector('[data-la-limit-form] textarea[name="whitelist_ips"]');
					if (textarea) {
						var val = textarea.value.trim();
						if (val && val.indexOf(json.data.ip) === -1) {
							textarea.value = val + '\n' + json.data.ip;
						} else if (!val) {
							textarea.value = json.data.ip;
						}
						if (typeof window._laStickyShow === 'function') { window._laStickyShow(); }
						toast('IP ' + json.data.ip + ' added.', 'success');
					}
				} else {
					toast('Could not detect IP.', 'error');
				}
			}).catch(function () {
				btn.disabled = false;
				toast('Network error.', 'error');
			});
			return;
		}

		if (action === 'limit-recommend' || action === 'limit-reset') {
			var applyLimitDefaults = function () {
				var defaults = { allowed_retries: 4, lockout_duration: 20, max_lockouts: 4, long_duration: 24, valid_duration: 24 };
				var limitFormAction = document.querySelector('[data-la-limit-form]');
				if (limitFormAction) {
					Object.keys(defaults).forEach(function (key) {
						var input = limitFormAction.querySelector('[name="' + key + '"]');
						if (input) { input.value = defaults[key]; }
					});
					var thresholdInput = limitFormAction.querySelector('[name="notify_threshold"]');
					if (thresholdInput) { thresholdInput.value = 5; }
					if (typeof window._laUpdateLimitSummary === 'function') { window._laUpdateLimitSummary(); }
					if (typeof window._laStickyShow === 'function') { window._laStickyShow(); }
				}
				toast(action === 'limit-recommend' ? 'Recommended values applied.' : 'Defaults restored.', 'success');
			};
			if (action === 'limit-reset') {
				var lr = s('limitReset');
				LA.confirm({
					title: lr.title,
					body: lr.body,
					variant: 'danger',
					confirmLabel: lr.confirmLabel,
					cancelLabel: lr.cancelLabel
				}).then(function (ok) { if (ok) { applyLimitDefaults(); } });
			} else {
				applyLimitDefaults();
			}
			return;
		}

		/* ---------- Lot 6: Detection & Logs actions ---------- */

		if (action === 'detection-enable') {
			btn.disabled = true;
			postAction('login_armor_enable_detection', {}).then(function (json) {
				if (json && json.success) {
					toast('Detection & logs enabled.', 'success');
					setTimeout(function () { window.location.reload(); }, 600);
				} else {
					btn.disabled = false;
					toast('Enable failed.', 'error');
				}
			}).catch(function () {
				btn.disabled = false;
				toast('Network error.', 'error');
			});
			return;
		}

		if (action === 'detection-disable') {
			var dd = s('detectionDisable');
			LA.confirm({
				title: dd.title,
				body: dd.body,
				variant: 'danger',
				confirmLabel: dd.confirmLabel,
				cancelLabel: dd.cancelLabel
			}).then(function (ok) {
				if (!ok) { return; }
				btn.disabled = true;
				postAction('login_armor_disable_detection', {}).then(function (json) {
					if (json && json.success) {
						toast('Detection & logs disabled.', 'success');
						setTimeout(function () { window.location.reload(); }, 600);
					} else {
						btn.disabled = false;
						toast('Disable failed.', 'error');
					}
				}).catch(function () {
					btn.disabled = false;
					toast('Network error.', 'error');
				});
			});
			return;
		}

		if (action === 'detection-purge') {
			var retentionSelect = document.querySelector('[data-la-detection-form] select[name="retention_days"]');
			var days = retentionSelect ? retentionSelect.value : '90';
			var dp = s('detectionPurge');
			LA.confirm({
				title: dp.title,
				body: fmt(dp.body, days),
				variant: 'danger',
				confirmLabel: dp.confirmLabel,
				cancelLabel: dp.cancelLabel,
				requireCheckbox: true
			}).then(function (ok) {
				if (!ok) { return; }
				btn.disabled = true;
				postAction('login_armor_purge_logs_manual', {}).then(function (json) {
					btn.disabled = false;
					if (json && json.success) {
						toast('Purged ' + (json.data.deleted || 0) + ' old records.', 'success');
					} else {
						toast('Purge failed.', 'error');
					}
				}).catch(function () {
					btn.disabled = false;
					toast('Network error.', 'error');
				});
			});
			return;
		}

		// 2.0.1: full reset of detection data (events + counters + incidents).
		if (action === 'detection-reset') {
			var dr = s('detectionReset');
			LA.confirm({
				title: dr.title,
				body: dr.body,
				variant: 'danger',
				confirmLabel: dr.confirmLabel,
				cancelLabel: dr.cancelLabel,
				requireCheckbox: true
			}).then(function (ok) {
				if (!ok) { return; }
				btn.disabled = true;
				postAction('login_armor_reset_detection_data', {}).then(function (json) {
					btn.disabled = false;
					if (json && json.success && json.data && json.data.deleted) {
						toast('Reset OK: ' + json.data.deleted.total + ' rows removed.', 'success');
						setTimeout(function () { window.location.reload(); }, 800);
					} else {
						toast('Reset failed.', 'error');
					}
				}).catch(function () {
					btn.disabled = false;
					toast('Network error.', 'error');
				});
			});
			return;
		}

		/* ---------- Lot 9: Activity Log actions ---------- */

		if (action === 'activity-enable') {
			btn.disabled = true;
			postAction('login_armor_enable_activity', {}).then(function (json) {
				if (json && json.success) {
					toast('Activity logging enabled.', 'success');
					setTimeout(function () { window.location.reload(); }, 600);
				} else {
					btn.disabled = false;
					toast('Enable failed.', 'error');
				}
			}).catch(function () {
				btn.disabled = false;
				toast('Network error.', 'error');
			});
			return;
		}

		if (action === 'activity-disable') {
			var ad = s('activityDisable');
			LA.confirm({
				title: ad.title,
				body: ad.body,
				variant: 'danger',
				confirmLabel: ad.confirmLabel,
				cancelLabel: ad.cancelLabel
			}).then(function (ok) {
				if (!ok) { return; }
				btn.disabled = true;
				postAction('login_armor_disable_activity', {}).then(function (json) {
					if (json && json.success) {
						toast('Activity logging disabled.', 'success');
						setTimeout(function () { window.location.reload(); }, 600);
					} else {
						btn.disabled = false;
						toast('Disable failed.', 'error');
					}
				}).catch(function () {
					btn.disabled = false;
					toast('Network error.', 'error');
				});
			});
			return;
		}

		if (action === 'activity-purge') {
			// V10.18: accept either <input> or <select> for retention and
			// fall back to the stored option value rather than hardcoding 90.
			var actRetEl = document.querySelector('[data-la-activity-form] [name="activity_retention"]');
			var actDays = actRetEl ? (actRetEl.value || '90') : '90';
			var ap = s('activityPurge');
			LA.confirm({
				title: ap.title,
				body: fmt(ap.body, actDays),
				variant: 'danger',
				confirmLabel: ap.confirmLabel,
				cancelLabel: ap.cancelLabel,
				requireCheckbox: true
			}).then(function (ok) {
				if (!ok) { return; }
				btn.disabled = true;
				postAction('login_armor_purge_activity', {}).then(function (json) {
					btn.disabled = false;
					if (json && json.success) {
						toast('Purged ' + (json.data.deleted || 0) + ' old activity records.', 'success');
					} else {
						toast('Purge failed.', 'error');
					}
				}).catch(function () {
					btn.disabled = false;
					toast('Network error.', 'error');
				});
			});
			return;
		}

		// 2.0.1: full reset of admin activity log.
		if (action === 'activity-reset') {
			var ar = s('activityReset');
			LA.confirm({
				title: ar.title,
				body: ar.body,
				variant: 'danger',
				confirmLabel: ar.confirmLabel,
				cancelLabel: ar.cancelLabel,
				requireCheckbox: true
			}).then(function (ok) {
				if (!ok) { return; }
				btn.disabled = true;
				postAction('login_armor_reset_activity_data', {}).then(function (json) {
					btn.disabled = false;
					if (json && json.success) {
						toast('Reset OK: ' + (json.data.deleted || 0) + ' activity rows removed.', 'success');
						setTimeout(function () { window.location.reload(); }, 800);
					} else {
						toast('Reset failed.', 'error');
					}
				}).catch(function () {
					btn.disabled = false;
					toast('Network error.', 'error');
				});
			});
			return;
		}

		/* ---------- Lot 10: Two-Factor Authentication actions ---------- */

		if (action === '2fa-enable') {
			btn.disabled = true;
			postAction('login_armor_enable_2fa', {}).then(function (json) {
				if (json && json.success) {
					toast('Two-factor authentication enabled.', 'success');
					setTimeout(function () { window.location.reload(); }, 600);
				} else {
					btn.disabled = false;
					toast('Enable failed.', 'error');
				}
			}).catch(function () {
				btn.disabled = false;
				toast('Network error.', 'error');
			});
			return;
		}

		if (action === '2fa-disable') {
			var tfd = s('twofaOff');
			LA.confirm({
				title: tfd.title,
				body: tfd.body,
				variant: 'danger',
				confirmLabel: tfd.confirmLabel,
				cancelLabel: tfd.cancelLabel
			}).then(function (ok) {
				if (!ok) { return; }
				btn.disabled = true;
				postAction('login_armor_disable_2fa', {}).then(function (json) {
					if (json && json.success) {
						toast('Two-factor authentication disabled.', 'success');
						setTimeout(function () { window.location.reload(); }, 600);
					} else {
						btn.disabled = false;
						toast('Disable failed.', 'error');
					}
				}).catch(function () {
					btn.disabled = false;
					toast('Network error.', 'error');
				});
			});
			return;
		}

		if (action === 'notif-test') {
			btn.disabled = true;
			var resultEl = document.querySelector('[data-la-notif-test-result]');
			if (resultEl) { resultEl.textContent = ''; resultEl.className = 'la-notif-test-result'; }
			postAction('login_armor_test_notification', {}).then(function (json) {
				btn.disabled = false;
				if (json && json.success) {
					if (resultEl) { resultEl.textContent = json.data.message; resultEl.className = 'la-notif-test-result la-notif-test-result--ok'; }
					toast('Test notification sent.', 'success');
				} else {
					var msg = (json && json.data && json.data.message) ? json.data.message : 'Test failed.';
					if (resultEl) { resultEl.textContent = msg; resultEl.className = 'la-notif-test-result la-notif-test-result--err'; }
					toast(msg, 'error');
				}
			}).catch(function () {
				btn.disabled = false;
				toast('Network error.', 'error');
			});
			return;
		}

		if (action === 'notifications-enable') {
			btn.disabled = true;
			postAction('login_armor_enable_notifications', {}).then(function (json) {
				if (json && json.success) {
					toast('Notifications enabled: defaulting to Email. Configure channel below.', 'success');
					setTimeout(function () { window.location.reload(); }, 600);
				} else {
					btn.disabled = false;
					toast('Enable failed.', 'error');
				}
			}).catch(function () {
				btn.disabled = false;
				toast('Network error.', 'error');
			});
			return;
		}

		if (action === 'notifications-disable') {
			var no = s('notificationsOff');
			LA.confirm({
				title: no.title,
				body: no.body,
				variant: 'danger',
				confirmLabel: no.confirmLabel,
				cancelLabel: no.cancelLabel
			}).then(function (ok) {
				if (!ok) { return; }
				btn.disabled = true;
				postAction('login_armor_disable_notifications', {}).then(function (json) {
					if (json && json.success) {
						toast('Notifications disabled.', 'success');
						setTimeout(function () { window.location.reload(); }, 600);
					} else {
						btn.disabled = false;
						toast('Disable failed.', 'error');
					}
				}).catch(function () {
					btn.disabled = false;
					toast('Network error.', 'error');
				});
			});
			return;
		}

		/* ---------- Lot 13: Login Page Security Headers actions ---------- */

		if (action === 'login-headers-enable') {
			btn.disabled = true;
			postAction('login_armor_enable_login_headers', {}).then(function (json) {
				if (json && json.success) {
					toast('Login headers enabled.', 'success');
					setTimeout(function () { window.location.reload(); }, 600);
				} else {
					btn.disabled = false;
					toast('Enable failed.', 'error');
				}
			}).catch(function () {
				btn.disabled = false;
				toast('Network error.', 'error');
			});
			return;
		}

		if (action === 'login-headers-disable') {
			var lh = s('loginHeadersOff');
			LA.confirm({
				title: lh.title,
				body: lh.body,
				variant: 'danger',
				confirmLabel: lh.confirmLabel,
				cancelLabel: lh.cancelLabel
			}).then(function (ok) {
				if (!ok) { return; }
				btn.disabled = true;
				postAction('login_armor_disable_login_headers', {}).then(function (json) {
					if (json && json.success) {
						toast('Login headers disabled.', 'success');
						setTimeout(function () { window.location.reload(); }, 600);
					} else {
						btn.disabled = false;
						toast('Disable failed.', 'error');
					}
				}).catch(function () {
					btn.disabled = false;
					toast('Network error.', 'error');
				});
			});
			return;
		}

		if (action === 'login-headers-save') {
			var lhForm = document.querySelector('[data-la-login-headers-form]');
			if (!lhForm) { return; }
			var modeEl = lhForm.querySelector('[name="login_headers_mode"]:checked');
			var reportEl = lhForm.querySelector('[name="login_headers_report_uri"]');
			var hstsEl = lhForm.querySelector('[name="login_headers_hsts"]:checked');
			btn.disabled = true;
			var hint = lhForm.querySelector('[data-la-save-hint]');
			if (hint) { hint.textContent = ''; }
			var sitewideEl = lhForm.querySelector('[name="login_headers_sitewide"]');
			postAction('login_armor_save_login_headers', {
				login_headers_mode: modeEl ? modeEl.value : 'standard',
				login_headers_report_uri: reportEl ? reportEl.value : '',
				login_headers_hsts: hstsEl ? hstsEl.value : 'off',
				login_headers_sitewide: (sitewideEl && sitewideEl.checked) ? '1' : ''
			}).then(function (json) {
				btn.disabled = false;
				if (json && json.success) {
					toast('Login headers saved.', 'success');
					if (hint) { hint.textContent = 'Saved.'; hint.className = 'la-save-hint la-save-hint--ok'; }
					// Refresh the preview block with the new computed headers.
					var previewEl = document.querySelector('[data-la-headers-preview]');
					if (previewEl && json.data && json.data.preview) {
						var html = '';
						Object.keys(json.data.preview).forEach(function (name) {
							// Escape BOTH key and value before innerHTML. Header names are
							// server-built today, but escaping symmetrically prevents a
							// regression if that data shape ever widens (audit 2.4.0).
							var safeName = String(name)
							          .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
							html += '<span class="la-code-preview__header">' + safeName + ':</span> ' +
							        '<span class="la-code-preview__value">' + String(json.data.preview[name])
							          .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;') +
							        '</span>\n';
						});
						previewEl.innerHTML = html;
					}
				} else {
					var msg = (json && json.data && json.data.message) ? json.data.message : 'Save failed.';
					if (hint) { hint.textContent = msg; hint.className = 'la-save-hint la-save-hint--err'; }
					toast(msg, 'error');
				}
			}).catch(function () {
				btn.disabled = false;
				toast('Network error.', 'error');
			});
			return;
		}

		/* ---------- Lot 21: Breach Check actions ---------- */

		if (action === 'breach-check-enable') {
			btn.disabled = true;
			postAction('login_armor_enable_breach_check', {}).then(function (json) {
				if (json && json.success) {
					var msg = s('breachCheck').enabled || 'Breach Check enabled.';
					var scan = json.data && json.data.scan;
					if (scan && scan.scanned > 0) {
						msg = (s('breachCheck').scanDone || 'Breach Check enabled. Scanned %1$d admin emails, %2$d flagged.')
							.replace('%1$d', scan.scanned).replace('%2$d', scan.flagged);
					}
					toast(msg, scan && scan.flagged > 0 ? 'warning' : 'success');
					setTimeout(function () { window.location.reload(); }, 900);
				} else {
					btn.disabled = false;
					toast(s('breachCheck').enableFailed || 'Enable failed.', 'error');
				}
			}).catch(function () {
				btn.disabled = false;
				toast('Network error.', 'error');
			});
			return;
		}

		if (action === 'breach-check-disable') {
			var bcOff = s('breachCheckOff');
			LA.confirm({
				title: bcOff.title,
				body: bcOff.body,
				variant: 'danger',
				confirmLabel: bcOff.confirmLabel,
				cancelLabel: bcOff.cancelLabel
			}).then(function (ok) {
				if (!ok) { return; }
				btn.disabled = true;
				postAction('login_armor_disable_breach_check', {}).then(function (json) {
					if (json && json.success) {
						toast(s('breachCheck').disabled || 'Breach Check disabled.', 'success');
						setTimeout(function () { window.location.reload(); }, 600);
					} else {
						btn.disabled = false;
						toast(s('breachCheck').disableFailed || 'Disable failed.', 'error');
					}
				}).catch(function () {
					btn.disabled = false;
					toast('Network error.', 'error');
				});
			});
			return;
		}

		/* ---------- Password Policy actions ---------- */

		if (action === 'password-policy-enable') {
			btn.disabled = true;
			postAction('login_armor_enable_password_policy', {}).then(function (json) {
				if (json && json.success) {
					toast(s('passwordPolicy').enabled || 'Password policy enabled.', 'success');
					setTimeout(function () { window.location.reload(); }, 700);
				} else {
					btn.disabled = false;
					toast(s('passwordPolicy').enableFailed || 'Enable failed.', 'error');
				}
			}).catch(function () {
				btn.disabled = false;
				toast('Network error.', 'error');
			});
			return;
		}

		if (action === 'password-policy-disable') {
			var ppOff = s('passwordPolicyOff');
			LA.confirm({
				title: ppOff.title,
				body: ppOff.body,
				variant: 'danger',
				confirmLabel: ppOff.confirmLabel,
				cancelLabel: ppOff.cancelLabel
			}).then(function (ok) {
				if (!ok) { return; }
				btn.disabled = true;
				postAction('login_armor_disable_password_policy', {}).then(function (json) {
					if (json && json.success) {
						toast(s('passwordPolicy').disabled || 'Password policy disabled.', 'success');
						setTimeout(function () { window.location.reload(); }, 600);
					} else {
						btn.disabled = false;
						toast(s('passwordPolicy').disableFailed || 'Disable failed.', 'error');
					}
				}).catch(function () {
					btn.disabled = false;
					toast('Network error.', 'error');
				});
			});
			return;
		}

		/* ---------- Session Manager actions ---------- */

		if (action === 'session-enable') {
			btn.disabled = true;
			postAction('login_armor_enable_session', {}).then(function (json) {
				if (json && json.success) {
					toast(s('session').enabled || 'Session management enabled.', 'success');
					setTimeout(function () { window.location.reload(); }, 700);
				} else {
					btn.disabled = false;
					toast(s('session').enableFailed || 'Enable failed.', 'error');
				}
			}).catch(function () {
				btn.disabled = false;
				toast('Network error.', 'error');
			});
			return;
		}

		if (action === 'session-disable') {
			var seOff = s('sessionOff');
			LA.confirm({
				title: seOff.title,
				body: seOff.body,
				variant: 'danger',
				confirmLabel: seOff.confirmLabel,
				cancelLabel: seOff.cancelLabel
			}).then(function (ok) {
				if (!ok) { return; }
				btn.disabled = true;
				postAction('login_armor_disable_session', {}).then(function (json) {
					if (json && json.success) {
						toast(s('session').disabled || 'Session management disabled.', 'success');
						setTimeout(function () { window.location.reload(); }, 600);
					} else {
						btn.disabled = false;
						toast(s('session').disableFailed || 'Disable failed.', 'error');
					}
				}).catch(function () {
					btn.disabled = false;
					toast('Network error.', 'error');
				});
			});
			return;
		}

		if (action === 'session-logout-others') {
			btn.disabled = true;
			postAction('login_armor_session_logout_others', {}).then(function (json) {
				btn.disabled = false;
				if (json && json.success) {
					toast(s('session').loggedOut || 'Other devices have been signed out.', 'success');
					setTimeout(function () { window.location.reload(); }, 800);
				} else {
					toast(s('session').logoutFailed || 'Could not sign out other devices.', 'error');
				}
			}).catch(function () {
				btn.disabled = false;
				toast('Network error.', 'error');
			});
			return;
		}

		/* ---------- GeoIP actions ---------- */

		if (action === 'geoip-enable') {
			btn.disabled = true;
			postAction('login_armor_enable_geoip', {}).then(function (json) {
				if (json && json.success) {
					toast(s('geoip').enabled || 'IP geolocation enabled.', 'success');
					setTimeout(function () { window.location.reload(); }, 700);
				} else {
					btn.disabled = false;
					toast(s('geoip').enableFailed || 'Enable failed.', 'error');
				}
			}).catch(function () {
				btn.disabled = false;
				toast('Network error.', 'error');
			});
			return;
		}

		if (action === 'geoip-disable') {
			var giOff = s('geoipOff');
			LA.confirm({
				title: giOff.title,
				body: giOff.body,
				variant: 'danger',
				confirmLabel: giOff.confirmLabel,
				cancelLabel: giOff.cancelLabel
			}).then(function (ok) {
				if (!ok) { return; }
				btn.disabled = true;
				postAction('login_armor_disable_geoip', {}).then(function (json) {
					if (json && json.success) {
						toast(s('geoip').disabled || 'IP geolocation disabled.', 'success');
						setTimeout(function () { window.location.reload(); }, 600);
					} else {
						btn.disabled = false;
						toast(s('geoip').disableFailed || 'Disable failed.', 'error');
					}
				}).catch(function () {
					btn.disabled = false;
					toast('Network error.', 'error');
				});
			});
			return;
		}

		/* ---------- Headless mode (2.9.0) ---------- */

		if (action === 'headless-enable') {
			btn.disabled = true;
			postAction('login_armor_enable_headless', {}).then(function (json) {
				if (json && json.success) {
					var off = (json.data && json.data.labels) || [];
					var msg = off.length
						? (s('headless').turnedOff || 'Headless mode enabled. Turned off: %s.').replace('%s', off.join(', '))
						: (s('headless').enabled || 'Headless mode enabled.');
					toast(msg, 'success');
					setTimeout(function () { window.location.reload(); }, 1600);
				} else {
					btn.disabled = false;
					toast(s('headless').enableFailed || 'Enable failed.', 'error');
				}
			}).catch(function () {
				btn.disabled = false;
				toast('Network error.', 'error');
			});
			return;
		}

		if (action === 'headless-disable') {
			var hlOff = s('headlessOff');
			LA.confirm({
				title: hlOff.title,
				body: hlOff.body,
				variant: 'danger',
				confirmLabel: hlOff.confirmLabel,
				cancelLabel: hlOff.cancelLabel
			}).then(function (ok) {
				if (!ok) { return; }
				btn.disabled = true;
				postAction('login_armor_disable_headless', {}).then(function (json) {
					if (json && json.success) {
						toast(s('headless').disabled || 'Headless mode disabled.', 'success');
						setTimeout(function () { window.location.reload(); }, 900);
					} else {
						btn.disabled = false;
						toast(s('headless').disableFailed || 'Disable failed.', 'error');
					}
				}).catch(function () {
					btn.disabled = false;
					toast('Network error.', 'error');
				});
			});
			return;
		}

		/* ---------- Request Firewall actions ---------- */

		if (action === 'firewall-enable') {
			btn.disabled = true;
			postAction('login_armor_enable_firewall', {}).then(function (json) {
				if (json && json.success) {
					toast(s('firewall').enabled || 'Request firewall enabled in monitor mode.', 'success');
					setTimeout(function () { window.location.reload(); }, 700);
				} else {
					btn.disabled = false;
					toast(s('firewall').enableFailed || 'Enable failed.', 'error');
				}
			}).catch(function () {
				btn.disabled = false;
				toast('Network error.', 'error');
			});
			return;
		}

		if (action === 'firewall-disable') {
			var fwOff = s('firewallOff');
			LA.confirm({
				title: fwOff.title,
				body: fwOff.body,
				variant: 'danger',
				confirmLabel: fwOff.confirmLabel,
				cancelLabel: fwOff.cancelLabel
			}).then(function (ok) {
				if (!ok) { return; }
				btn.disabled = true;
				postAction('login_armor_disable_firewall', {}).then(function (json) {
					if (json && json.success) {
						toast(s('firewall').disabled || 'Request firewall disabled.', 'success');
						setTimeout(function () { window.location.reload(); }, 600);
					} else {
						btn.disabled = false;
						toast(s('firewall').disableFailed || 'Disable failed.', 'error');
					}
				}).catch(function () {
					btn.disabled = false;
					toast('Network error.', 'error');
				});
			});
			return;
		}

		/* ---------- Bot Challenge (Proof-of-Work) actions ---------- */

		if (action === 'pow-enable') {
			btn.disabled = true;
			postAction('login_armor_enable_pow', {}).then(function (json) {
				if (json && json.success) {
					toast(s('pow').enabled || 'Bot challenge enabled in monitor mode.', 'success');
					setTimeout(function () { window.location.reload(); }, 700);
				} else {
					btn.disabled = false;
					toast(s('pow').enableFailed || 'Enable failed.', 'error');
				}
			}).catch(function () {
				btn.disabled = false;
				toast('Network error.', 'error');
			});
			return;
		}

		if (action === 'pow-disable') {
			var powOff = s('powOff');
			LA.confirm({
				title: powOff.title,
				body: powOff.body,
				variant: 'danger',
				confirmLabel: powOff.confirmLabel,
				cancelLabel: powOff.cancelLabel
			}).then(function (ok) {
				if (!ok) { return; }
				btn.disabled = true;
				postAction('login_armor_disable_pow', {}).then(function (json) {
					if (json && json.success) {
						toast(s('pow').disabled || 'Bot challenge disabled.', 'success');
						setTimeout(function () { window.location.reload(); }, 600);
					} else {
						btn.disabled = false;
						toast(s('pow').disableFailed || 'Disable failed.', 'error');
					}
				}).catch(function () {
					btn.disabled = false;
					toast('Network error.', 'error');
				});
			});
			return;
		}

		if (action === 'firewall-add-ip') {
			btn.disabled = true;
			postAction('login_armor_get_current_ip', {}).then(function (json) {
				btn.disabled = false;
				if (json && json.success && json.data && json.data.ip) {
					var fwTa = document.querySelector('[data-la-firewall-form] textarea[name="firewall_allow_ips"]');
					if (fwTa) {
						var fwVal = fwTa.value.trim();
						if (fwVal && fwVal.indexOf(json.data.ip) === -1) {
							fwTa.value = fwVal + '\n' + json.data.ip;
						} else if (!fwVal) {
							fwTa.value = json.data.ip;
						}
						if (typeof window._laStickyShow === 'function') { window._laStickyShow(); }
						toast(s('firewall').ipAdded || ('IP ' + json.data.ip + ' added.'), 'success');
					}
				} else {
					toast(s('firewall').ipDetectFailed || 'Could not detect IP.', 'error');
				}
			}).catch(function () {
				btn.disabled = false;
				toast('Network error.', 'error');
			});
			return;
		}

		/* ---------- Safe baseline ---------- */

		if (action === 'apply-safe-baseline') {
			var sb = s('safeBaseline');
			LA.confirm({
				title: sb.title || 'Apply the safe baseline?',
				body: sb.body || '',
				variant: 'primary',
				confirmLabel: sb.confirmLabel || 'Apply',
				cancelLabel: sb.cancelLabel || 'Cancel'
			}).then(function (ok) {
				if (!ok) { return; }
				btn.disabled = true;
				postAction('login_armor_apply_safe_baseline', {}).then(function (json) {
					if (json && json.success) {
						toast(sb.applied || 'Safe baseline applied.', 'success');
						setTimeout(function () { window.location.reload(); }, 700);
					} else {
						btn.disabled = false;
						toast(sb.failed || 'Could not apply the safe baseline.', 'error');
					}
				}).catch(function () {
					btn.disabled = false;
					toast('Network error.', 'error');
				});
			});
			return;
		}

		/* ---------- Settings transfer (export / import) ---------- */

		if (action === 'settings-export') {
			var exportOptin = document.querySelector('#la-settings-transfer input[name="include_webhooks"]');
			var exportUrl = ajaxUrl + '?action=login_armor_settings_export&nonce=' + encodeURIComponent(adminNonce)
				+ (exportOptin && exportOptin.checked ? '&include_webhooks=1' : '');
			window.location.assign(exportUrl);
			return;
		}

		if (action === 'settings-preview') {
			var stp = s('settingsTransfer');
			var fileInput = document.getElementById('la-transfer-file');
			var resultBox = document.querySelector('[data-la-transfer-result]');
			var applyBtn = document.querySelector('[data-la-action="settings-apply"]');
			if (!fileInput || !fileInput.files || !fileInput.files.length) {
				toast(stp.noFile || 'Choose a settings file first.', 'error');
				return;
			}
			var file = fileInput.files[0];
			if (file.size > 262144) {
				toast(stp.fileTooLarge || 'This file is too large.', 'error');
				return;
			}
			btn.disabled = true;
			if (applyBtn) { applyBtn.hidden = true; }
			var reader = new FileReader();
			reader.onerror = function () {
				btn.disabled = false;
				toast(stp.readFailed || 'Could not read the file.', 'error');
			};
			reader.onload = function () {
				laTransferText = String(reader.result || '');
				var fd = new FormData();
				fd.append('mode', 'preview');
				fd.append('file', file, file.name);
				postMultipart('login_armor_settings_import', fd).then(function (json) {
					btn.disabled = false;
					var data = (json && json.data) || {};
					var canApply = laRenderTransferPlan(resultBox, data, !(json && json.success));
					if (applyBtn) { applyBtn.hidden = !canApply; applyBtn.disabled = false; }
					if (!json || (!json.success && !data.errors)) {
						toast((data && data.message) || stp.previewFailed || 'Could not preview this file.', 'error');
					}
				}).catch(function () {
					btn.disabled = false;
					toast('Network error.', 'error');
				});
			};
			reader.readAsText(file);
			return;
		}

		if (action === 'settings-apply') {
			var sta = s('settingsTransfer');
			var resultBoxA = document.querySelector('[data-la-transfer-result]');
			var urlAfterEl = resultBoxA ? resultBoxA.querySelector('.la-transfer__url') : null;
			var changeCount = resultBoxA ? resultBoxA.querySelectorAll('.la-transfer__diff tbody tr').length : 0;
			if (!laTransferText) {
				toast(sta.noFile || 'Choose a settings file first.', 'error');
				return;
			}
			LA.confirm({
				title: sta.confirmTitle || 'Apply the imported settings?',
				body: fmt(sta.confirmBody || '%1$s setting(s) will change. The login URL will be %2$s.', changeCount, urlAfterEl ? urlAfterEl.textContent.replace(/^.*?:\s*/, '') : window.location.origin),
				variant: 'primary',
				confirmLabel: sta.confirmLabel || 'Apply',
				cancelLabel: sta.cancelLabel || 'Cancel'
			}).then(function (ok) {
				if (!ok) { return; }
				btn.disabled = true;
				postAction('login_armor_settings_import', { mode: 'apply', payload: laTransferText }).then(function (json) {
					var data = (json && json.data) || {};
					if (json && json.success) {
						laTransferText = '';
						btn.hidden = true;
						laRenderTransferReport(resultBoxA, data);
					} else {
						btn.disabled = false;
						if (data.rows || data.errors) { laRenderTransferPlan(resultBoxA, data, true); }
						toast(data.message || sta.applyFailed || 'Import failed.', 'error');
					}
				}).catch(function () {
					btn.disabled = false;
					toast('Network error.', 'error');
				});
			});
			return;
		}

		/* ---------- Sticky bar actions ---------- */

		if (action === 'discard') {
			window.location.reload();
			return;
		}

		if (action === 'save-all') {
			btn.disabled = true;
			var promises = [];

			// Save Hide Login settings if the form exists
			var hideForm = document.querySelector('[data-la-hide-form]');
			if (hideForm) {
				var slugInput     = hideForm.querySelector('[name="slug"]');
				var typeInput     = hideForm.querySelector('[name="redirect_type"]:checked');
				var urlInput      = hideForm.querySelector('[name="redirect_url"]');
				promises.push(postAction('login_armor_save_hide_settings', {
					slug: slugInput ? slugInput.value : '',
					redirect_type: typeInput ? typeInput.value : 'notfound',
					redirect_url: urlInput ? urlInput.value : ''
				}));
			}

			// Save Hardening toggles
			var hardeningForm = document.querySelector('[data-la-hardening-form]');
			if (hardeningForm) {
				var checked = hardeningForm.querySelectorAll('input[type="checkbox"]:checked');
				var toggles = [];
				checked.forEach(function (cb) { toggles.push(cb.name); });
				var hBody = new URLSearchParams();
				hBody.append('action', 'login_armor_save_hardening');
				hBody.append('nonce', adminNonce);
				toggles.forEach(function (t) { hBody.append('toggles[]', t); });
				promises.push(
					fetch(ajaxUrl, {
						method: 'POST',
						credentials: 'same-origin',
						headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
						body: hBody.toString()
					}).then(function (r) { return r.json(); })
				);
			}

			// Save Limit Login settings if the form exists
			var limitForm = document.querySelector('[data-la-limit-form]');
			if (limitForm) {
				var limitPayload = {};
				['allowed_retries', 'lockout_duration', 'max_lockouts', 'long_duration', 'valid_duration', 'notify_threshold'].forEach(function (name) {
					var el = limitForm.querySelector('[name="' + name + '"]');
					if (el) { limitPayload[name] = el.value; }
				});
				var emailEl = limitForm.querySelector('[name="notify_email"]');
				if (emailEl) { limitPayload.notify_email = emailEl.value; }
				var syslogEl = limitForm.querySelector('[name="syslog"]');
				if (syslogEl) { limitPayload.syslog = syslogEl.checked ? '1' : '0'; }
				var whitelistEl = limitForm.querySelector('[name="whitelist_ips"]');
				if (whitelistEl) { limitPayload.whitelist_ips = whitelistEl.value; }
				var ipMethodEl = limitForm.querySelector('[name="ip_method"]');
				if (ipMethodEl) { limitPayload.ip_method = ipMethodEl.value; }
				var trustedProxiesEl = limitForm.querySelector('[name="trusted_proxies"]');
				if (trustedProxiesEl) { limitPayload.trusted_proxies = trustedProxiesEl.value; }
				promises.push(postAction('login_armor_save_limit_settings', limitPayload));
			}

			// Save Detection & Logs settings if the form exists
			var detectionForm = document.querySelector('[data-la-detection-form]');
			if (detectionForm) {
				var retSelect = detectionForm.querySelector('[name="retention_days"]');
				var autoPurge = detectionForm.querySelector('[name="auto_purge"]');
				promises.push(postAction('login_armor_save_detection_settings', {
					retention_days: retSelect ? retSelect.value : '90',
					auto_purge: autoPurge && autoPurge.checked ? '1' : '0'
				}));
			}

			// Save Activity Log settings if the form exists
			var activityForm = document.querySelector('[data-la-activity-form]');
			if (activityForm) {
				var actRetention = activityForm.querySelector('[name="activity_retention"]');
				promises.push(postAction('login_armor_save_activity_settings', {
					activity_retention: actRetention ? actRetention.value : '90'
				}));
			}

			// Save AI Assistant settings if the form exists. Both toggles ride the
			// sticky Save bar; deep mode (real IPs out) needs an explicit save.
			var aiForm = document.querySelector('[data-la-ai-settings-form]');
			if (aiForm) {
				var aiEnabled = aiForm.querySelector('[name="ai_enabled"]');
				var aiDeep    = aiForm.querySelector('[name="ai_deep"]');
				promises.push(postAction('login_armor_ai_save_settings', {
					ai_enabled: aiEnabled && aiEnabled.checked ? '1' : '0',
					ai_deep:    aiDeep && aiDeep.checked ? '1' : '0'
				}));
			}

			// Save Two-Factor Authentication settings if the form exists.
			// The PHP handler treats unsent checkboxes as unchecked, so every
			// checkbox in this form must be forwarded as "1" or "0" explicitly,
			// otherwise ticking "Allow trusted devices" or "Allow recovery" and
			// saving silently resets them to false.
			var twoFactorForm = document.querySelector('[data-la-2fa-settings-form]');
			if (twoFactorForm) {
				var tfBody = new URLSearchParams();
				tfBody.append('action', 'login_armor_save_2fa_settings');
				tfBody.append('nonce', adminNonce);
				twoFactorForm.querySelectorAll('input[type="checkbox"]').forEach(function (cb) {
					if (cb.name.startsWith('method_') && cb.checked) {
						tfBody.append(cb.name, cb.value);
					}
					if (cb.name === 'enforce_roles[]' && cb.checked) {
						tfBody.append('enforce_roles[]', cb.value);
					}
				});
				var graceSelect = twoFactorForm.querySelector('[name="grace_days"]');
				if (graceSelect) { tfBody.append('grace_days', graceSelect.value); }

				var tdToggle   = twoFactorForm.querySelector('[name="allow_trusted_devices"]');
				var tdDuration = twoFactorForm.querySelector('[name="trusted_devices_duration_days"]');
				var recovToggle = twoFactorForm.querySelector('[name="allow_2fa_recovery"]');
				tfBody.append('allow_trusted_devices', tdToggle && tdToggle.checked ? '1' : '0');
				if (tdDuration) { tfBody.append('trusted_devices_duration_days', tdDuration.value); }
				tfBody.append('allow_2fa_recovery', recovToggle && recovToggle.checked ? '1' : '0');

				promises.push(
					fetch(ajaxUrl, {
						method: 'POST',
						credentials: 'same-origin',
						headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
						body: tfBody.toString()
					}).then(function (r) { return r.json(); })
				);
			}

			// Save Login Headers settings if the form exists.
			var lhFormSaveAll = document.querySelector('[data-la-login-headers-form]');
			if (lhFormSaveAll) {
				var lhModeEl   = lhFormSaveAll.querySelector('[name="login_headers_mode"]:checked');
				var lhReportEl = lhFormSaveAll.querySelector('[name="login_headers_report_uri"]');
				var lhHstsEl   = lhFormSaveAll.querySelector('[name="login_headers_hsts"]:checked');
				var lhSitewideEl = lhFormSaveAll.querySelector('[name="login_headers_sitewide"]');
				promises.push(postAction('login_armor_save_login_headers', {
					login_headers_mode: lhModeEl ? lhModeEl.value : 'standard',
					login_headers_report_uri: lhReportEl ? lhReportEl.value : '',
					login_headers_hsts: lhHstsEl ? lhHstsEl.value : 'off',
					login_headers_sitewide: (lhSitewideEl && lhSitewideEl.checked) ? '1' : ''
				}));
			}

			// Save Request Firewall settings if the form exists.
			var fwFormSaveAll = document.querySelector('[data-la-firewall-form]');
			if (fwFormSaveAll) {
				var fwModeEl = fwFormSaveAll.querySelector('[name="firewall_mode"]:checked');
				var fwChk = function (name) {
					var el = fwFormSaveAll.querySelector('[name="firewall_' + name + '"]');
					return (el && el.checked) ? '1' : '';
				};
				var fwIpsEl   = fwFormSaveAll.querySelector('[name="firewall_allow_ips"]');
				var fwPathsEl = fwFormSaveAll.querySelector('[name="firewall_allow_paths"]');
				promises.push(postAction('login_armor_save_firewall', {
					firewall_mode:                   fwModeEl ? fwModeEl.value : 'log_only',
					firewall_query_string:           fwChk('query_string'),
					firewall_request_uri:            fwChk('request_uri'),
					firewall_request_method:         fwChk('request_method'),
					firewall_user_agent:             fwChk('user_agent'),
					firewall_referer:                fwChk('referer'),
					firewall_request_uri_aggressive: fwChk('request_uri_aggressive'),
					firewall_allow_ips:              fwIpsEl ? fwIpsEl.value : '',
					firewall_allow_paths:            fwPathsEl ? fwPathsEl.value : ''
				}));
			}

			// Save Bot Challenge (Proof-of-Work) settings if the form exists.
			var powFormSaveAll = document.querySelector('[data-la-pow-form]');
			if (powFormSaveAll) {
				var powModeEl = powFormSaveAll.querySelector('[name="pow_mode"]:checked');
				var powDiffEl = powFormSaveAll.querySelector('[name="pow_difficulty"]:checked');
				promises.push(postAction('login_armor_save_pow', {
					pow_mode:       powModeEl ? powModeEl.value : 'log_only',
					pow_difficulty: powDiffEl ? powDiffEl.value : 'standard'
				}));
			}

			// Save Breach Check sub-toggles if the form exists (v2.0.5)
			var breachForm = document.querySelector('[data-la-breach-check-form]');
			if (breachForm) {
				var bcPwd   = breachForm.querySelector('[name="breach_check_passwords"]');
				var bcEmail = breachForm.querySelector('[name="breach_check_emails"]');
				var bcForce = breachForm.querySelector('[name="breach_check_force_reset"]');
				promises.push(postAction('login_armor_save_breach_check', {
					breach_check_passwords:   (bcPwd   && bcPwd.checked)   ? '1' : '',
					breach_check_emails:      (bcEmail && bcEmail.checked) ? '1' : '',
					breach_check_force_reset: (bcForce && bcForce.checked) ? '1' : ''
				}));
			}

			// Save Password Policy rules if the form exists
			var ppForm = document.querySelector('[data-la-password-policy-form]');
			if (ppForm) {
				var ppGet = function (name) { return ppForm.querySelector('[name="' + name + '"]'); };
				var ppChecked = function (name) { var el = ppGet(name); return (el && el.checked) ? '1' : ''; };
				var ppMinEl = ppGet('min_length');
				var ppExpEl = ppGet('expiration_days');
				promises.push(postAction('login_armor_save_password_policy', {
					enabled:           '1',
					min_length:        ppMinEl ? ppMinEl.value : '12',
					require_lower:     ppChecked('require_lower'),
					require_upper:     ppChecked('require_upper'),
					require_number:    ppChecked('require_number'),
					require_symbol:    ppChecked('require_symbol'),
					forbid_username:   ppChecked('forbid_username'),
					block_compromised: ppChecked('block_compromised'),
					expiration_days:   ppExpEl ? ppExpEl.value : '0'
				}));
			}

			// Save Session Manager settings if the form exists
			var seForm = document.querySelector('[data-la-session-form]');
			if (seForm) {
				var seIdleEl = seForm.querySelector('[name="idle_timeout_min"]');
				var seLifeEl = seForm.querySelector('[name="max_lifetime_hours"]');
				var seSingleEl = seForm.querySelector('[name="single_session"]');
				promises.push(postAction('login_armor_save_session', {
					enabled:            '1',
					idle_timeout_min:   seIdleEl ? seIdleEl.value : '0',
					max_lifetime_hours: seLifeEl ? seLifeEl.value : '0',
					single_session:     (seSingleEl && seSingleEl.checked) ? '1' : ''
				}));
			}

			// V2.1.1 B12: Webhook form save
			var webhookForm = document.querySelector('[data-la-webhook-form]');
			if (webhookForm) {
				var whEnabledEl = webhookForm.querySelector('input[name="webhook_enabled"]');
				var whUrlEl     = webhookForm.querySelector('input[name="webhook_url"]');
				promises.push(postAction('login_armor_webhook_save', {
					webhook_enabled: (whEnabledEl && whEnabledEl.checked) ? '1' : '0',
					webhook_url:     whUrlEl ? whUrlEl.value : ''
				}));
			}

			// Save Notifications settings if the form exists
			var notifForm = document.querySelector('[data-la-notifications-form]');
			if (notifForm) {
				var notifPayload = {};
				var channelEl = notifForm.querySelector('[name="notif_channel"]');
				var urlEl = notifForm.querySelector('[name="notif_webhook_url"]');
				var emailEl = notifForm.querySelector('[name="notif_email_to"]');
				var sevEl = notifForm.querySelector('[name="notif_min_severity"]');
				var rateEl = notifForm.querySelector('[name="notif_rate_limit"]');
				var digestEl = notifForm.querySelector('[name="notif_digest"]');
				var digestToEl = notifForm.querySelector('[name="notif_digest_to"]');
				if (channelEl) { notifPayload.notif_channel = channelEl.value; }
				// Send email address OR webhook URL in the same backend field.
				if (channelEl && channelEl.value === 'email') {
					notifPayload.notif_webhook_url = emailEl ? emailEl.value : '';
				} else if (urlEl) {
					notifPayload.notif_webhook_url = urlEl.value;
				}
				if (sevEl) { notifPayload.notif_min_severity = sevEl.value; }
				if (rateEl) { notifPayload.notif_rate_limit = rateEl.value; }
				// 2.7.0: the scheduled digest. Sent only when the select is on
				// the page, so an older cached view cannot post an empty value
				// and silently switch the digest off.
				if (digestEl) { notifPayload.notif_digest = digestEl.value; }
				if (digestToEl) { notifPayload.notif_digest_to = digestToEl.value.trim(); }
				promises.push(postAction('login_armor_save_notifications', notifPayload));
			}

			Promise.all(promises).then(function (results) {
				btn.disabled = false;
				var allOk = results.every(function (r) { return r && r.success; });
				if (allOk) {
					// If the save-all response includes a freshly-performed
					// admin-email scan (email check sub-toggle was just flipped
					// on), surface the result as a toast so the admin knows it
					// ran and what it found.
					for (var si = 0; si < results.length; si++) {
						var bcScan = results[si] && results[si].data && results[si].data.scan;
						if (bcScan && bcScan.scanned > 0) {
							var bcMsg = (s('breachCheck').scanDone || 'Scanned %1$d admin emails, %2$d flagged.')
								.replace('%1$d', bcScan.scanned).replace('%2$d', bcScan.flagged);
							toast(bcMsg, bcScan.flagged > 0 ? 'warning' : 'success');
							break;
						}
					}
					toast('All changes saved.', 'success');
					if (updateHardeningScoreGlobal) { updateHardeningScoreGlobal(); }
					if (window._laStickyHide) { window._laStickyHide(); }
					// Update the URL preview after saving hide settings
					for (var i = 0; i < results.length; i++) {
						if (results[i] && results[i].data && results[i].data.url) {
							var urlEl = document.querySelector('[data-la-hide-url]');
							if (urlEl) {
								laSetHideUrl(urlEl, results[i].data.url);
								urlEl.href = results[i].data.url;
							}
							break;
						}
					}
				} else {
					// Extract error message from first failed result
					var errMsg = 'Some settings failed to save.';
					for (var i = 0; i < results.length; i++) {
						if (results[i] && !results[i].success && results[i].data && results[i].data.message) {
							errMsg = results[i].data.message;
							// 2.9.0: headless mode refused a save that switched a guarded
							// toggle on. Nothing was saved: put the boxes back.
							if ('headless_conflict' === results[i].data.code && Array.isArray(results[i].data.keys)) {
								var hlForm = document.querySelector('[data-la-hardening-form]');
								results[i].data.keys.forEach(function (key) {
									var hlBox = hlForm ? hlForm.querySelector('input[name="' + key + '"]') : null;
									if (hlBox) {
										hlBox.checked = false;
										hlBox.dispatchEvent(new Event('change', { bubbles: true }));
									}
								});
							}
							break;
						}
					}
					toast(errMsg, 'error');
				}
			}).catch(function () {
				btn.disabled = false;
				toast('Network error.', 'error');
			});
			return;
		}
	});
	/* ---------- Hardening per-group counters + toggle state (Lot 18 V10.2) ---------- */
	(function initHardeningGroups() {
		var form = document.querySelector('[data-la-hardening-form]');
		if (!form) { return; }

		function updateHardeningScore() {
			// Per-group "N / M" pills (sub-sections inside the Hardening form).
			document.querySelectorAll('[data-la-harden-group]').forEach(function (grp) {
				var rows = grp.querySelectorAll('[data-la-toggle]:not([data-la-headless-locked])');
				var rowsOn = grp.querySelectorAll('[data-la-toggle]:not([data-la-headless-locked]) input[type="checkbox"]:checked');
				var countEl = grp.querySelector('[data-la-harden-group-count]');
				if (countEl) { countEl.textContent = rowsOn.length + ' / ' + rows.length; }
			});

			// Outer "X of Y" pill on the <details id="hardening"> summary.
			// Server-rendered once via PHP; needs live refresh so the user sees
			// the new count without a full page reload after toggling / saving.
			var wrapper = document.getElementById('hardening');
			if (!wrapper) { return; }
			// 2.9.0: boxes headless mode keeps off are disabled, and the server
			// leaves them out of its own count.
			var allBoxes    = form.querySelectorAll('input[type="checkbox"]:not(:disabled)');
			var activeBoxes = form.querySelectorAll('input[type="checkbox"]:not(:disabled):checked');
			var total       = allBoxes.length;
			var active      = activeBoxes.length;

			var pill = wrapper.querySelector('summary .la-pill');
			if (pill) {
				// Replace the first digit run so the localized separator
				// (" of " / " SUR " / …) stays intact.
				pill.textContent = pill.textContent.replace(/^\s*\d+/, String(active));
			}

			var newState = (active === total) ? 'on' : (active > 0 ? 'warn' : 'off');
			wrapper.classList.remove('la-setting-wrapper--on', 'la-setting-wrapper--warn', 'la-setting-wrapper--off');
			wrapper.classList.add('la-setting-wrapper--' + newState);

			var iconEl = wrapper.querySelector('summary .la-setting-row__icon');
			if (iconEl) {
				iconEl.classList.remove('la-setting-row__icon--on', 'la-setting-row__icon--warn', 'la-setting-row__icon--off');
				iconEl.classList.add('la-setting-row__icon--' + newState);
			}

			if (pill) {
				var pillVariant = (newState === 'on') ? 'ok' : ((newState === 'warn') ? 'warn' : 'neutral');
				pill.classList.remove('la-pill--ok', 'la-pill--warn', 'la-pill--neutral');
				pill.classList.add('la-pill--' + pillVariant);
			}
		}

		// Expose for the hardening-save handler (save-all / apply-recommended).
		updateHardeningScoreGlobal = updateHardeningScore;

		// React to every toggle change: flip row state classes + refresh counts.
		document.querySelectorAll('[data-la-toggle] input[type="checkbox"]').forEach(function(cb) {
			cb.addEventListener('change', function() {
				var row = this.closest('[data-la-toggle]');
				if (row) {
					row.classList.toggle('la-harden-row--on', this.checked);
					row.classList.toggle('la-harden-row--off', !this.checked);
				}
				updateHardeningScore();
			});
		});

		// Initial render.
		updateHardeningScore();

		// "Apply recommended defaults" button: sets EXACTLY the 7 recommended toggles.
		var defaultsBtn = document.querySelector('[data-la-hardening-defaults]');
		var defaultsHint = document.querySelector('.la-hardening-defaults__hint');
		if (defaultsBtn) {
			var recommendedKeys = [
				'disable_xmlrpc', 'disable_file_editor', 'hide_wp_version',
				'mask_login_errors', 'block_php_uploads', 'prevent_author_enum',
				'disable_directory_listing'
			];

			function isRecommendedState() {
				var allBoxes = document.querySelectorAll('[data-la-hardening-form] input[type="checkbox"]');
				var ok = true;
				allBoxes.forEach(function (cb) {
					var isRec = recommendedKeys.indexOf(cb.name) !== -1;
					if (isRec && !cb.checked) { ok = false; }
					if (!isRec && cb.checked) { ok = false; }
				});
				return ok;
			}

			function updateDefaultsHint() {
				if (!defaultsHint) { return; }
				var l10n = (window.loginArmor && window.loginArmor.hardeningDefaults) || {};
				if (isRecommendedState()) {
					defaultsHint.textContent = l10n.active || '7 recommended defaults active.';
				} else {
					defaultsHint.textContent = l10n.hint || 'Enables the 7 most common security toggles at once.';
				}
			}

			// Update hint on page load and on any toggle change
			updateDefaultsHint();
			document.querySelectorAll('[data-la-hardening-form] input[type="checkbox"]').forEach(function (cb) {
				cb.addEventListener('change', updateDefaultsHint);
			});

			defaultsBtn.addEventListener('click', function() {
				if (isRecommendedState()) {
					var l10nAll = (window.loginArmor && window.loginArmor.hardeningDefaults) || {};
					toast(l10nAll.allOn || 'All 7 recommended defaults are already active.', 'success');
					return;
				}

				// Enable recommended, disable non-recommended
				var allBoxes = document.querySelectorAll('[data-la-hardening-form] input[type="checkbox"]');
				allBoxes.forEach(function (cb) {
					var isRec = recommendedKeys.indexOf(cb.name) !== -1;
					var shouldBeOn = isRec;
					if (cb.checked !== shouldBeOn) {
						cb.checked = shouldBeOn;
						var card = cb.closest('[data-la-toggle]');
						if (card) {
							if (shouldBeOn) {
								card.classList.add('la-harden-card--on');
								card.classList.remove('la-harden-card--off');
							} else {
								card.classList.add('la-harden-card--off');
								card.classList.remove('la-harden-card--on');
							}
						}
						cb.dispatchEvent(new Event('change', { bubbles: true }));
					}
				});
				updateHardeningScore();
				updateDefaultsHint();
			});
		}
	})();

	/* ---------- Lot 14: Username blacklist inline save + reveal ---------- */
	(function initUsernameBlacklist() {
		var panel = document.querySelector('[data-la-blacklist-panel]');
		if (!panel) { return; }

		var toggle  = document.querySelector('[data-la-hardening-form] input[name="block_reserved_usernames"]');
		var input   = panel.querySelector('[data-la-blacklist-input]');
		var count   = panel.querySelector('[data-la-blacklist-count]');
		var warn    = panel.querySelector('[data-la-blacklist-warning]');
		var warnCnt = panel.querySelector('[data-la-blacklist-warning-count]');
		var warnLst = panel.querySelector('[data-la-blacklist-warning-list]');

		function reveal(on) {
			if (on) {
				panel.removeAttribute('hidden');
			} else {
				panel.setAttribute('hidden', '');
			}
		}

		if (toggle) {
			reveal(toggle.checked);
			toggle.addEventListener('change', function () { reveal(toggle.checked); });
		}

		if (!input) { return; }

		var timer = null;
		input.addEventListener('input', function () {
			if (timer) { clearTimeout(timer); }
			timer = setTimeout(function () {
				if (!adminNonce) { return; }
				var body = new URLSearchParams();
				body.append('action', 'login_armor_save_username_blacklist');
				body.append('nonce', adminNonce);
				body.append('blacklist', input.value);
				fetch(ajaxUrl, {
					method: 'POST',
					credentials: 'same-origin',
					headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
					body: body.toString()
				}).then(function (r) { return r.json(); }).then(function (json) {
					if (!json || !json.success || !json.data) { return; }
					if (count) { count.textContent = String(json.data.count || 0); }
					var matches = Array.isArray(json.data.existing_matches) ? json.data.existing_matches : [];
					if (warn) {
						if (matches.length === 0) {
							warn.setAttribute('hidden', '');
						} else {
							warn.removeAttribute('hidden');
						}
					}
					if (warnCnt) { warnCnt.textContent = String(matches.length); }
					if (warnLst) { warnLst.textContent = matches.join(', '); }
					if (window.LA && window.LA.toast) {
						window.LA.toast('Saved', 'success');
					}
				}).catch(function () {
					if (window.LA && window.LA.toast) {
						window.LA.toast('Network error.', 'error');
					}
				});
			}, 500);
		});
	})();

	/* ---------- 2.5.1 - Public REST namespaces inline save + reveal ---------- */
	(function initRestNamespaces() {
		var panel = document.querySelector('[data-la-restns-panel]');
		if (!panel) { return; }

		var toggle = document.querySelector('[data-la-hardening-form] input[name="restrict_rest_api"]');
		var input  = panel.querySelector('[data-la-restns-input]');
		var count  = panel.querySelector('[data-la-restns-count]');
		var warn   = panel.querySelector('[data-la-restns-warning]');

		function reveal(on) {
			if (on) {
				panel.removeAttribute('hidden');
			} else {
				panel.setAttribute('hidden', '');
			}
		}

		// The server decides what counts as risky and returns the offending
		// entries: duplicating that rule here would let the two drift apart.
		var warnList = panel.querySelector('[data-la-restns-warning-list]');

		function showWarning(risky) {
			if (!warn) { return; }
			if (Array.isArray(risky) && risky.length) {
				if (warnList) { warnList.textContent = risky.join(', '); }
				warn.removeAttribute('hidden');
			} else {
				warn.setAttribute('hidden', '');
			}
		}

		if (toggle) {
			reveal(toggle.checked);
			toggle.addEventListener('change', function () { reveal(toggle.checked); });
		}

		if (!input) { return; }

		var timer = null;
		input.addEventListener('input', function () {
			if (timer) { clearTimeout(timer); }
			timer = setTimeout(function () {
				if (!adminNonce) { return; }
				var body = new URLSearchParams();
				body.append('action', 'login_armor_save_rest_namespaces');
				body.append('nonce', adminNonce);
				body.append('namespaces', input.value);
				fetch(ajaxUrl, {
					method: 'POST',
					credentials: 'same-origin',
					headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
					body: body.toString()
				}).then(function (r) { return r.json(); }).then(function (json) {
					if (!json || !json.success || !json.data) { return; }
					if (count) { count.textContent = String(json.data.count || 0); }
					showWarning(json.data.risky);
					// Echo back exactly what was stored, so the admin never reads a
					// value the gate does not use. Skip while the field has focus,
					// to avoid rewriting text under the cursor mid-typing.
					if (typeof json.data.normalized === 'string'
						&& document.activeElement !== input
						&& input.value !== json.data.normalized) {
						input.value = json.data.normalized;
					}
					if (window.LA && window.LA.toast) {
						window.LA.toast('Saved', 'success');
					}
				}).catch(function () {
					if (window.LA && window.LA.toast) {
						window.LA.toast('Network error.', 'error');
					}
				});
			}, 500);
		});
	})();

	/* ---------- Slug input: real-time normalization ---------- */
	(function initSlugNormalize() {
		var slugInput = document.getElementById('la-hide-slug');
		if (!slugInput) { return; }

		function normalizeSlug(value, trim) {
			var out = value
				.normalize('NFD').replace(/[\u0300-\u036f]/g, '')  // strip accents
				.toLowerCase()
				.replace(/\s+/g, '-')              // spaces → hyphens
				.replace(/[^a-z0-9\-]/g, '')       // keep only a-z, 0-9, hyphens
				.replace(/-{2,}/g, '-');            // collapse multiple hyphens
			if (trim) {
				out = out.replace(/^-|-$/g, '');    // trim leading/trailing hyphens
			}
			return out;
		}

		// While typing: normalize but keep trailing hyphen so user can type "my-slug"
		slugInput.addEventListener('input', function () {
			var raw = this.value;
			var normalized = normalizeSlug(raw, false);
			if (normalized !== raw) {
				var pos = this.selectionStart;
				var diff = raw.length - normalized.length;
				this.value = normalized;
				this.setSelectionRange(Math.max(0, pos - diff), Math.max(0, pos - diff));
			}
		});

		// On blur: trim leading/trailing hyphens
		slugInput.addEventListener('blur', function () {
			this.value = normalizeSlug(this.value, true);
		});
	})();

	/* ---------- Radio card selection (Hide Login redirect type, firewall
	   and bot-challenge modes). Active state is cleared per radio GROUP so
	   two groups in the same section never fight each other's highlight. */
	document.querySelectorAll('.la-radio-opt').forEach(function(card) {
		card.addEventListener('click', function() {
			var radio = this.querySelector('input[type="radio"]');
			var groupName = radio ? radio.name : '';
			document.querySelectorAll('.la-radio-opt').forEach(function(c) {
				var r = c.querySelector('input[type="radio"]');
				if (!groupName || (r && r.name === groupName)) {
					c.classList.remove('la-radio-opt--active');
				}
			});
			this.classList.add('la-radio-opt--active');
			// Sync the hidden radio input
			if (radio) {
				radio.checked = true;
				// Update the redirect note text
				var noteEl = document.querySelector('[data-la-redirect-note]');
				if (noteEl) {
					noteEl.textContent = radio.value === 'url'
						? noteEl.getAttribute('data-note-url')
						: noteEl.getAttribute('data-note-404');
				}
			}
		});
	});

	/* ---------- Sticky bar dirty state tracking ---------- */
	(function initStickyBar() {
		var stickyBar = document.querySelector('[data-la-sticky-bar]');
		if (!stickyBar) { return; }

		function showBar() {
			stickyBar.classList.add('la-sticky-bar--visible');
		}

		function hideBar() {
			stickyBar.classList.remove('la-sticky-bar--visible');
		}

		// Track changes on all Settings tab inputs. Every form must list BOTH
		// `input` and `select` (plus `textarea` where used), V10.18 bug: the
		// activity-retention field is an <input type="number"> and was
		// missed when the tracker only covered <select>, so edits never
		// triggered the sticky bar and were never saved.
		var settingsInputs = document.querySelectorAll(
			'[data-la-hide-form] input, [data-la-hide-form] select, ' +
			'[data-la-hardening-form] input, ' +
			'[data-la-limit-form] input, [data-la-limit-form] select, [data-la-limit-form] textarea, ' +
			'[data-la-detection-form] input, [data-la-detection-form] select, ' +
			'[data-la-activity-form] input, [data-la-activity-form] select, ' +
			'[data-la-webhook-form] input, ' +
			'[data-la-2fa-settings-form] input, [data-la-2fa-settings-form] select, ' +
			'[data-la-login-headers-form] input, ' +
			'[data-la-firewall-form] input, [data-la-firewall-form] textarea, ' +
			'[data-la-pow-form] input, ' +
			'[data-la-breach-check-form] input, ' +
			'[data-la-password-policy-form] input, ' +
			'[data-la-session-form] input, ' +
			'[data-la-notifications-form] input, [data-la-notifications-form] select, ' +
			'[data-la-ai-settings-form] input'
		);
		settingsInputs.forEach(function(input) {
			input.addEventListener('change', showBar);
			input.addEventListener('input', showBar);
		});

		// Radio cards also trigger dirty state
		document.querySelectorAll('.la-radio-opt').forEach(function(card) {
			card.addEventListener('click', showBar);
		});

		// Expose showBar and hideBar so actions can call them
		window._laStickyShow = showBar;
		window._laStickyHide = hideBar;
	})();

	/* ---------- Limit Login summary (Lot 6) ---------- */
	(function initLimitSummary() {
		var summaryEl = document.querySelector('[data-la-limit-summary]');
		if (!summaryEl) { return; }
		var form = document.querySelector('[data-la-limit-form]');
		if (!form) { return; }

		function updateLimitSummary() {
			var retries  = form.querySelector('[name="allowed_retries"]');
			var lockout  = form.querySelector('[name="lockout_duration"]');
			var maxLock  = form.querySelector('[name="max_lockouts"]');
			var longDur  = form.querySelector('[name="long_duration"]');
			var validDur = form.querySelector('[name="valid_duration"]');
			if (!retries || !lockout || !maxLock || !longDur || !validDur) { return; }

			var retriesN  = parseInt(retries.value, 10)  || 4;
			var lockoutN  = parseInt(lockout.value, 10)  || 20;
			var maxLockN  = parseInt(maxLock.value, 10)  || 4;
			var validDurN = parseInt(validDur.value, 10) || 24;
			var longDurN  = parseInt(longDur.value, 10)  || 24;

			// Grab the localized template (with <strong>%Nd</strong> placeholders).
			var tpl = (window.loginArmor && window.loginArmor.limitSummary && window.loginArmor.limitSummary.template)
				|| 'After <strong>%1$d</strong> failed attempts, the IP is locked for <strong>%2$d minutes</strong>. After <strong>%3$d</strong> lockouts within <strong>%4$d hours</strong>, the ban extends to <strong>%5$d hours</strong>. Failed attempts reset after <strong>%6$d hours</strong> of inactivity.';

			// Resolve %1$d … %6$d with the current numeric values.
			var args = [retriesN, lockoutN, maxLockN, validDurN, longDurN, validDurN];
			summaryEl.innerHTML = tpl.replace(/%(\d+)\$d/g, function (_, n) {
				return String(args[parseInt(n, 10) - 1]);
			});
		}

		// Expose globally for the recommend/reset handlers
		window._laUpdateLimitSummary = updateLimitSummary;

		// Listen for input changes
		form.querySelectorAll('input[type="number"]').forEach(function (input) {
			input.addEventListener('input', updateLimitSummary);
		});

		// Initial render
		updateLimitSummary();
	})();

	/* ---------- Scroll to section from URL hash or ?section= param ---------- */
	(function initScrollToSection() {
		var hash = window.location.hash.replace('#', '');
		if (!hash) {
			var params = new URLSearchParams(window.location.search);
			hash = params.get('section') || '';
		}
		// Section remembered just before an action's reload (see laRememberSection).
		// An explicit hash / ?section= wins; otherwise re-open what we were working in.
		try {
			var stored = sessionStorage.getItem('la_reopen');
			if (stored) {
				sessionStorage.removeItem('la_reopen');
				if (!hash) { hash = stored; }
			}
		} catch (e) {}
		if (!hash) { return; }
		// hash may come from location.hash / ?section= (attacker-influenceable).
		// Server-rendered ids are slugs only, so reject anything else BEFORE it
		// reaches querySelector: a malformed value would throw a SyntaxError that
		// aborts the rest of this script's initialization.
		if (!/^[A-Za-z0-9_-]+$/.test(hash)) { return; }
		var wrapper = document.querySelector('.la-setting-wrapper#' + hash);
		if (wrapper) {
			var cat = wrapper.closest('.la-cat');
				if (cat) { cat.open = true; }
				wrapper.open = true;
			setTimeout(function () {
				wrapper.scrollIntoView({ behavior: 'smooth', block: 'start' });
				wrapper.classList.add('la-highlight');
			}, 100);
		}
	})();

	/* ---------- Settings tab: search across the collapsed modules ---------- */
	// The Settings tab holds about 88 controls behind three nesting levels of
	// <details> (a category, a module, and Hide Login's recovery panel inside
	// one of them), every one of them closed on load. The browser's own find bar
	// cannot look inside a closed <details>, so Ctrl+F found almost nothing.
	// This box indexes the text of every module once, then hides the modules
	// that do not match and opens the ones that do. Nothing is persisted: a
	// reload gives the untouched list back.
	(function initSettingsSearch() {
		var input = document.querySelector('[data-la-settings-search]');
		if (!input) { return; }
		var col = input.closest('.la-settings-col');
		if (!col) { return; }

		var counter = col.querySelector('[data-la-settings-search-count]');
		var I18N    = (window.loginArmor && window.loginArmor.settingsSearch) || {};

		// Every place a module's own wording ends up in the body. Kept as one
		// list so a new section template only has to reuse an existing class.
		// The last line is the generic sweep: prose, list items, code samples
		// and the summary of a nested <details>. Hide Login's recovery panel
		// ("Forgot your login URL?") is written entirely in those tags, and
		// without them its three methods were unfindable.
		var TEXT_SELECTOR = [
			'label',
			'.la-field__label', '.la-field__desc',
			'.la-harden-row__text', '.la-harden-group__label', '.la-harden-group__hint',
			'.la-sub-panel__title', '.la-sub-panel__desc',
			'.la-card-title', '.la-card-subtitle',
			'.la-radio-opt__title', '.la-radio-opt__desc',
			'h3', 'h4', 'option',
			'summary', 'p', 'li', 'code'
		].join(', ');

		// Accent-insensitive on both sides: "securite" must find "sécurité" and
		// "sécurité" must find a label written without its accents.
		function normalize(str) {
			return String(str || '')
				.toLowerCase()
				.normalize('NFD')
				.replace(/\p{M}/gu, '')
				.replace(/\s+/g, ' ')
				.trim();
		}

		// Every lookup here is scoped to .la-settings-col. Until 2.8.2 the
		// <section> inside each module carried the module's own id; it is now
		// la-section-<id>, and the scope stays as the cheaper search anyway.
		var modules = [];
		Array.prototype.forEach.call(col.querySelectorAll('.la-setting-wrapper'), function (el) {
			var summary = el.querySelector('summary');
			var body    = el.querySelector('.la-setting-wrapper__body');
			var cat     = el.closest('.la-cat');
			var catHead = cat ? cat.querySelector('.la-cat__summary') : null;
			// The category heading is part of how a module is named on screen:
			// "Accounts & passwords" has to find the modules filed under it.
			var parts   = [ summary ? summary.textContent : '', catHead ? catHead.textContent : '' ];
			// 2.7.1: two sources that are indexed and never shown. The index
			// above is built from rendered text only, and the match below is a
			// plain substring test, so a translated label takes its own
			// abbreviation out of reach: the French label reads "A2F", "2fa" is
			// not a substring of "a2f", and the box answered "No matching
			// module" for the very term its placeholder offers. The alias list
			// declared next to each module closes that, and the wrapper id adds
			// the English slug ("two-factor", "breach check") for free in every
			// language, with its separators opened out so both spellings hit.
			parts.push(el.getAttribute('data-la-search-alias') || '');
			var slug = String(el.id || '');
			parts.push(slug + ' ' + slug.replace(/[-_]/g, ' '));
			if (body) {
				Array.prototype.forEach.call(body.querySelectorAll(TEXT_SELECTOR), function (node) {
					parts.push(node.textContent);
				});
			}
			var rows = [];
			Array.prototype.forEach.call(el.querySelectorAll('[data-la-harden-key]'), function (row) {
				// The option key is indexed next to the wording: the label reads
				// "XML-RPC" while an administrator types "xmlrpc", and only
				// disable_xmlrpc carries that spelling.
				rows.push({
					el: row,
					text: normalize(row.textContent + ' ' + (row.getAttribute('data-la-harden-key') || '').replace(/_/g, ' '))
				});
			});
			// A module must be findable by anything its own rows are findable
			// by, otherwise it would be hidden before the row filter ever runs.
			rows.forEach(function (r) { parts.push(r.text); });
			modules.push({
				el: el,
				cat: cat,
				text: normalize(parts.join(' ')),
				rows: rows,
				// Hardening rows are grouped under their own heading and count.
				// A group left on screen with none of its rows would read as an
				// empty section, so it follows its rows.
				groups: Array.prototype.slice.call(el.querySelectorAll('.la-harden-group'))
			});
		});
		if (!modules.length) { return; }

		var cats = Array.prototype.slice.call(col.querySelectorAll('.la-cat'));

		// Open/closed state of the column, captured just before a filter opens
		// anything, so that clearing the box restores exactly what was on
		// screen. Released on every clear: between two searches the
		// administrator may have opened or closed a panel by hand, and
		// replaying a stale snapshot would silently undo that.
		var snapshot = null;
		function takeSnapshot() {
			if (snapshot) { return; }
			snapshot = [];
			Array.prototype.forEach.call(col.querySelectorAll('details'), function (d) {
				snapshot.push([ d, d.open ]);
			});
		}

		function showEverything() {
			modules.forEach(function (m) {
				m.el.hidden = false;
				m.rows.forEach(function (r) { r.el.hidden = false; });
				m.groups.forEach(function (g) { g.hidden = false; });
			});
			cats.forEach(function (cat) { cat.hidden = false; });
		}

		function setCount(text) {
			if (counter) { counter.textContent = text; }
		}

		function clearFilter() {
			showEverything();
			if (snapshot) {
				snapshot.forEach(function (pair) { pair[0].open = pair[1]; });
			}
			snapshot = null;
			setCount('');
		}

		function applyFilter(query) {
			var normalized = normalize(query);
			var tokens     = normalized ? normalized.split(' ') : [];
			// One character matches nearly everything and would just flash the
			// whole page open on the way to a real query.
			if (normalized.length < 2 || !tokens.length) {
				clearFilter();
				return;
			}
			takeSnapshot();

			var matched = 0;
			modules.forEach(function (m) {
				var hit = tokens.every(function (t) { return m.text.indexOf(t) !== -1; });
				m.el.hidden = !hit;
				if (!hit) {
					m.rows.forEach(function (r) { r.el.hidden = false; });
					m.groups.forEach(function (g) { g.hidden = false; });
					return;
				}
				matched++;
				m.el.open = true;
				if (m.cat) { m.cat.open = true; }
				// Narrow the hardening list to the rows that match, but only when
				// at least one of them does: a hit on the module title alone has
				// to leave the whole module readable.
				var rowHits = m.rows.filter(function (r) {
					return tokens.every(function (t) { return r.text.indexOf(t) !== -1; });
				});
				m.rows.forEach(function (r) {
					r.el.hidden = rowHits.length > 0 && rowHits.indexOf(r) === -1;
				});
				// A group heading with no row left under it reads as an empty
				// section, so it goes with its rows.
				m.groups.forEach(function (g) {
					g.hidden = !m.rows.some(function (r) { return !r.el.hidden && g.contains(r.el); });
				});
			});

			cats.forEach(function (cat) {
				var visible = modules.some(function (m) { return m.cat === cat && !m.el.hidden; });
				cat.hidden = !visible;
			});

			// English literal fallbacks, as everywhere else in this file: a
			// missing dictionary must still say something.
			if (0 === matched) {
				setCount(I18N.resultsNone || 'No matching module');
			} else if (1 === matched) {
				setCount(I18N.resultsOne || '1 matching module');
			} else {
				setCount(fmt(I18N.results || '%d matching modules', matched));
			}
		}

		var debounce = null;
		function schedule() {
			if (debounce) { clearTimeout(debounce); }
			debounce = setTimeout(function () { applyFilter(input.value); }, 120);
		}
		input.addEventListener('input', schedule);
		// The little clear cross of type="search" fires `search`, not `input`,
		// in Safari.
		input.addEventListener('search', schedule);
		input.addEventListener('keydown', function (e) {
			if ('Escape' !== e.key) { return; }
			e.preventDefault();
			input.value = '';
			if (debounce) { clearTimeout(debounce); }
			clearFilter();
			input.focus();
		});

		// Ctrl+F / Cmd+F. The until-found value of the hidden attribute does not
		// apply to the content of a <details>, and no event announcing that a
		// native find has started is available across browsers. So the only
		// reliable answer is to open every panel the moment the shortcut is
		// pressed and let the browser's own find bar work on a fully expanded
		// page. preventDefault() is deliberately NOT called: the native bar
		// must still open.
		document.addEventListener('keydown', function (e) {
			// e.code, not e.key: the physical key is what the browser binds the
			// find bar to, and e.key reads "F" under CapsLock and something
			// else entirely on a non-Latin layout. Ctrl+Shift+F stays out, as
			// before.
			if (!(e.ctrlKey || e.metaKey) || e.altKey || e.shiftKey || 'KeyF' !== e.code) { return; }
			if ('settings' !== activeTab) { return; }
			takeSnapshot();
			input.value = '';
			if (debounce) { clearTimeout(debounce); }
			showEverything();
			// Every <details> of the column, not just the categories and the
			// modules: Hide Login's recovery panel is a third level, and the
			// find bar cannot look inside it either.
			Array.prototype.forEach.call(col.querySelectorAll('details'), function (d) { d.open = true; });
			setCount('');
		});

		// A browser can restore the box's value across a reload or a back and
		// forward navigation without firing `input`, which would leave a filled
		// box sitting over a completely unfiltered list.
		if (input.value) { applyFilter(input.value); }
	})();

	/* ---------- Notifications: channel enable/disable toggle ---------- */
	(function initNotifToggle() {
		var channelSelect = document.querySelector('[data-la-notif-channel-select]');
		if (!channelSelect) { return; }

		var emailField   = document.querySelector('[data-la-notif-email-field]');
		var webhookField = document.querySelector('[data-la-notif-webhook-field]');

		function toggleNotifFields() {
			var value      = channelSelect.value;
			var isDisabled = value === 'disabled';
			var isEmail    = value === 'email';

			// Disable all fields when disabled.
			var fields = document.querySelectorAll('[data-la-notif-field] input, [data-la-notif-field] select, [data-la-notif-field] button');
			fields.forEach(function (el) {
				el.disabled = isDisabled;
			});

			// Show/hide email vs webhook field.
			if (emailField)   { emailField.style.display   = isEmail && !isDisabled ? '' : 'none'; }
			if (webhookField) { webhookField.style.display  = !isEmail && !isDisabled ? '' : 'none'; }
		}

		channelSelect.addEventListener('change', toggleNotifFields);
		toggleNotifFields(); // Initial state.
	})();

	/* ---------- Lot 18 hero count-up ---------- */
	(function () {
		const numEl = document.querySelector('.la-hero__num');
		if (!numEl) { return; }
		const valEl = numEl.querySelector('.la-hero__num-value');
		const target = parseInt(numEl.getAttribute('data-la-target') || '0', 10);
		if (!valEl || target <= 0) { return; }
		const dur = 900;
		const start = performance.now();
		function step(t) {
			const k = Math.min(1, (t - start) / dur);
			const ease = 1 - Math.pow(1 - k, 3);
			valEl.textContent = String(Math.round(target * ease));
			if (k < 1) { requestAnimationFrame(step); }
		}
		requestAnimationFrame(step);
	})();

	/* ---------- Lot 18 chart draw ----------
	 * 2.7.8: in the stylesheet now, next to .la-chart__line in admin.css. This
	 * block walked a dash along the line, and a dash is laid out on the screen
	 * once the stroke width is taken out of the viewBox transform: on a chart
	 * drawn larger than 300 x 200 pixels the line stopped short. The order it
	 * kept is kept there: the area lands with the line, never before it, and
	 * nothing is hidden once the animations have run. */

	/* ---------- V2.1.1: Integrity panel actions (Activity tab) ---------- */
	var INTEGRITY_L10N = (window.loginArmor && window.loginArmor.integrity) || {};

	function integrityFmtNumber(n) {
		try { return Number(n).toLocaleString(); } catch (e) { return String(n); }
	}

	function integrityPatchPanel(panel, data) {
		if (!panel || !data) { return; }
		var metaLine = panel.querySelector('[data-la-integrity-meta]');
		// Pill lives directly inside the integrity bar (.la-integrity-bar), not
		// under a .la-card-title wrapper (legacy selector left the pill stuck on
		// "UNVERIFIED" even after a successful verify).
		var pill     = panel.querySelector('.la-status-pill');

		var rows = integrityFmtNumber(data.total || 0);
		var when = INTEGRITY_L10N.justNow || 'just now';
		var verifiedAt = data.verified_at || '';

		if (data.status === 'intact') {
			panel.classList.remove('la-integrity--broken', 'la-integrity--never');
			panel.classList.add('la-integrity--intact');
			if (metaLine) {
				// Escape verifiedAt for the attribute context (quotes included): it is
				// a server datetime today, escaped defensively (audit 2.4.0).
				var safeVerifiedAt = String(verifiedAt)
					.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
				metaLine.innerHTML =
					(INTEGRITY_L10N.metaRows || '%s rows signed').replace('%s', rows) +
					' <span class="la-integrity-bar__sep" aria-hidden="true">·</span> ' +
					'<span title="' + safeVerifiedAt + '">' +
						(INTEGRITY_L10N.metaWhen || 'verified %s').replace('%s', when) +
					'</span>';
			}
			if (pill) {
				pill.className = 'la-status-pill la-status-pill--on';
				pill.textContent = INTEGRITY_L10N.pillIntact || 'INTACT';
			}
		} else if (data.status === 'broken' && data.salt_changed) {
			// V2.1.20: benign security-key rotation, not tampering. Amber state.
			panel.classList.remove('la-integrity--intact', 'la-integrity--never', 'la-integrity--broken');
			panel.classList.add('la-integrity--keys');
			if (pill) {
				pill.className = 'la-status-pill la-status-pill--warn';
				pill.textContent = INTEGRITY_L10N.pillKeysChanged || 'KEYS CHANGED';
			}
		} else if (data.status === 'broken') {
			panel.classList.remove('la-integrity--intact', 'la-integrity--never', 'la-integrity--keys');
			panel.classList.add('la-integrity--broken');
			if (pill) {
				pill.className = 'la-status-pill la-status-pill--danger';
				pill.textContent = INTEGRITY_L10N.pillBroken || 'BROKEN';
			}
		}
	}

	document.addEventListener('click', function (e) {
		var verify = e.target.closest('[data-la-action="activity-verify-chain"]');
		if (verify) {
			e.preventDefault();
			verify.disabled = true;
			verify.classList.add('is-loading');
			var origLabel = verify.textContent;
			verify.textContent = INTEGRITY_L10N.verifying || 'Verifying…';
			postAction('login_armor_activity_verify_chain', {})
				.then(function (resp) {
					if (!resp || !resp.success || !resp.data) {
						toast((resp && resp.data && resp.data.message) || INTEGRITY_L10N.verifyFail || 'Verify failed.', 'error');
						return;
					}
					var data  = resp.data;
					var panel = document.querySelector('[data-la-integrity-panel]');
					integrityPatchPanel(panel, data);
					if (data.status === 'intact') {
						var msg = (INTEGRITY_L10N.intactToast || 'Chain intact: %s rows signed.').replace('%s', integrityFmtNumber(data.total || 0));
						toast(msg, 'success');
					} else if (data.status === 'broken' && data.salt_changed) {
						// Benign key rotation (migration / restored backup). Amber, not red.
						toast(INTEGRITY_L10N.keysChangedToast || 'Security keys changed (migration?). Re-baseline the chain to restore integrity.', 'info');
						// Reload to expose the Re-baseline button (PHP-rendered).
						setTimeout(function () { window.location.reload(); }, 1500);
					} else if (data.status === 'broken') {
						var firstBreak = (data.broken && data.broken[0] && data.broken[0].id) ? data.broken[0].id : 0;
						var bmsg = (INTEGRITY_L10N.brokenToast || 'Chain BROKEN at row %d.').replace('%d', String(firstBreak));
						toast(bmsg, 'error');
						// Reload to expose the Repair button (PHP-rendered when orphans > 0).
						setTimeout(function () { window.location.reload(); }, 1500);
					}
				})
				.catch(function (err) {
					toast(String(err && err.message ? err.message : err), 'error');
				})
				.then(function () {
					verify.disabled = false;
					verify.classList.remove('is-loading');
					verify.textContent = origLabel;
				});
			return;
		}

		var repair = e.target.closest('[data-la-action="activity-repair-chain"]');
		if (repair) {
			e.preventDefault();
			repair.disabled = true;
			repair.classList.add('is-loading');
			var origRepair = repair.textContent;
			repair.textContent = INTEGRITY_L10N.repairing || 'Repairing…';
			postAction('login_armor_activity_repair_chain', {})
				.then(function (resp) {
					if (resp && resp.success) {
						var n = (resp.data && resp.data.repaired) ? resp.data.repaired : 0;
						var msg = (INTEGRITY_L10N.repairedToast || 'Repaired %d orphan(s).').replace('%d', String(n));
						toast(msg, 'success');
						setTimeout(function () { window.location.reload(); }, 800);
					} else {
						toast((resp && resp.data && resp.data.message) || INTEGRITY_L10N.repairFail || 'Repair failed.', 'error');
						repair.disabled = false;
						repair.classList.remove('is-loading');
						repair.textContent = origRepair;
					}
				})
				.catch(function (err) {
					toast(String(err && err.message ? err.message : err), 'error');
					repair.disabled = false;
					repair.classList.remove('is-loading');
					repair.textContent = origRepair;
				});
		}

		// V2.1.20: Re-baseline the chain after a benign security-key rotation.
		var reset = e.target.closest('[data-la-action="activity-reset-chain"]');
		if (reset) {
			e.preventDefault();
			var doReset = function () {
				reset.disabled = true;
				reset.classList.add('is-loading');
				var origReset = reset.textContent;
				reset.textContent = INTEGRITY_L10N.resetting || 'Re-basing…';
				postAction('login_armor_activity_reset_chain', {})
					.then(function (resp) {
						if (resp && resp.success && resp.data) {
							var n = (typeof resp.data.rows_resigned !== 'undefined') ? resp.data.rows_resigned : (resp.data.total || 0);
							var msg = (INTEGRITY_L10N.resetToast || 'Chain re-based: %s rows re-signed under the current key.').replace('%s', integrityFmtNumber(n));
							toast(msg, 'success');
							setTimeout(function () { window.location.reload(); }, 900);
						} else {
							toast((resp && resp.data && resp.data.message) || INTEGRITY_L10N.resetFail || 'Re-baseline failed.', 'error');
							reset.disabled = false;
							reset.classList.remove('is-loading');
							reset.textContent = origReset;
						}
					})
					.catch(function (err) {
						toast(String(err && err.message ? err.message : err), 'error');
						reset.disabled = false;
						reset.classList.remove('is-loading');
						reset.textContent = origReset;
					});
			};
			var confirmBody = reset.getAttribute('data-la-confirm') || '';
			if (window.LA && typeof window.LA.confirm === 'function') {
				window.LA.confirm({
					title: INTEGRITY_L10N.pillKeysChanged || 'Re-baseline chain',
					body: confirmBody,
					variant: 'primary',
					confirmLabel: (window.loginArmor && window.loginArmor.confirmI18n && window.loginArmor.confirmI18n.confirm) || 'Confirm',
					cancelLabel: (window.loginArmor && window.loginArmor.confirmI18n && window.loginArmor.confirmI18n.cancel) || 'Cancel'
				}).then(function (ok) { if (ok) { doReset(); } });
			} else if (!confirmBody || window.confirm(confirmBody)) {
				doReset();
			}
		}
	});

	// V2.1.1 B12: Webhook UI helpers (Copy / Regenerate / Test)
	// Strings localized via wp_localize_script under window.loginArmor.webhook.
	var WEBHOOK_L10N = (window.loginArmor && window.loginArmor.webhook) || {};
	document.addEventListener('click', function (e) {
		var copyBtn = e.target.closest('[data-la-action="webhook-copy-secret"]');
		if (copyBtn) {
			e.preventDefault();
			var input = document.querySelector('[data-la-webhook-secret-display]');
			if (input && navigator.clipboard) {
				navigator.clipboard.writeText(input.value).then(function () {
					toast(WEBHOOK_L10N.secret_copied || 'Secret copied to clipboard.', 'success');
				}).catch(function () {
					toast(WEBHOOK_L10N.copy_failed || 'Copy failed; select and copy manually.', 'error');
				});
			} else if (input) {
				input.select();
				try {
					document.execCommand('copy');
					toast(WEBHOOK_L10N.secret_copied || 'Secret copied to clipboard.', 'success');
				} catch (err) {
					toast(WEBHOOK_L10N.copy_failed || 'Copy failed; select and copy manually.', 'error');
				}
			}
		}

		var regen = e.target.closest('[data-la-action="webhook-regenerate-secret"]');
		if (regen) {
			e.preventDefault();
			var regenBody = WEBHOOK_L10N.regenerate_confirm || 'Regenerate the webhook secret? Your receiver will need to be reconfigured with the new value.';
			var doRegen = function () {
				regen.disabled = true;
				postAction('login_armor_webhook_regenerate_secret', {})
					.then(function (data) {
						if (data && data.success && data.data && data.data.secret) {
							var input = document.querySelector('[data-la-webhook-secret-display]');
							if (input) { input.value = data.data.secret; }
							toast(WEBHOOK_L10N.secret_regenerated || 'Secret regenerated. Update your receiver.', 'success');
						} else {
							toast((data && data.data && data.data.message) || WEBHOOK_L10N.regenerate_failed || 'Regenerate failed.', 'error');
						}
					})
					.catch(function (err) { toast(String(err && err.message ? err.message : err), 'error'); })
					.then(function () { regen.disabled = false; });
			};
			if (window.LA && typeof window.LA.confirm === 'function') {
				window.LA.confirm({
					title: WEBHOOK_L10N.regenerate_title || 'Regenerate webhook secret?',
					body: regenBody,
					variant: 'danger',
					confirmLabel: (window.loginArmor && window.loginArmor.confirmI18n && window.loginArmor.confirmI18n.confirm) || 'Confirm',
					cancelLabel: (window.loginArmor && window.loginArmor.confirmI18n && window.loginArmor.confirmI18n.cancel) || 'Cancel'
				}).then(function (ok) { if (ok) { doRegen(); } });
			} else if (window.confirm(regenBody)) {
				doRegen();
			}
		}

		var test = e.target.closest('[data-la-action="webhook-test"]');
		if (test) {
			e.preventDefault();
			var resultEl = document.querySelector('[data-la-webhook-test-result]');
			test.disabled = true;
			if (resultEl) { resultEl.textContent = '…'; }
			postAction('login_armor_webhook_test', {})
				.then(function (data) {
					if (data && data.success && data.data) {
						// Result span shows the raw status only; toast uses the localized template.
						var statusStr = 'HTTP ' + data.data.http_status;
						var msg = statusStr + ' OK';
						if (resultEl) { resultEl.textContent = msg; }
						var template = WEBHOOK_L10N.test_delivered || 'Test event delivered: %s';
						toast(fmt(template, statusStr), 'success');
					} else {
						var err = (data && data.data && data.data.message) || WEBHOOK_L10N.test_failed || 'Test failed.';
						if (resultEl) { resultEl.textContent = err; }
						toast(err, 'error');
					}
				})
				.catch(function (err) {
					var msg = String(err && err.message ? err.message : err);
					toast(msg, 'error');
					if (resultEl) { resultEl.textContent = msg; }
				})
				.then(function () { test.disabled = false; });
		}
	});

})();
