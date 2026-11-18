/**
 * Login Armor: Two-Factor Authentication JS.
 *
 * Handles:
 * - Verification screen: method toggle, resend cooldown
 * - Profile page: setup wizard, AJAX interactions
 *
 * @package LoginArmor
 * @since   2.2.0
 */

(function () {
	'use strict';

	/* ── Verification Screen ─────────────────────────────────── */

	var toggleBtn = document.getElementById('la-2fa-toggle-methods');
	var methodsEl = document.getElementById('la-2fa-methods');

	if (toggleBtn && methodsEl) {
		toggleBtn.addEventListener('click', function () {
			var hidden = methodsEl.hidden;
			methodsEl.hidden = !hidden;
			toggleBtn.textContent = hidden ? la2faStrings.hideOther : la2faStrings.useOther;
		});
	}

	// Resend cooldown timer.
	var resendBtn = document.getElementById('la-2fa-resend');
	if (resendBtn) {
		var cooldown = 60;
		var timer = null;

		function startCooldown() {
			var remaining = cooldown;
			resendBtn.disabled = true;
			timer = setInterval(function () {
				remaining--;
				if (remaining <= 0) {
					clearInterval(timer);
					resendBtn.disabled = false;
					resendBtn.textContent = la2faStrings.resend;
				} else {
					resendBtn.textContent = la2faStrings.resendIn.replace('%d', remaining);
				}
			}, 1000);
		}

		// Start cooldown on page load if resent flag is present.
		if (window.location.search.indexOf('resent=1') !== -1) {
			startCooldown();
		}

		resendBtn.addEventListener('click', function (e) {
			if (resendBtn.disabled) {
				e.preventDefault();
				return;
			}
			startCooldown();
		});
	}

	/*
	 * Auto-submit when 6 digits are entered, but ONLY when the "trust this
	 * device" checkbox is absent from the form. That checkbox sits after the
	 * code field, so submitting on the 6th keystroke left no window at all to
	 * tick it (reported by a user: "pas le temps de cocher la case"). The
	 * listener is on `input`, so paste and one-time-code autofill fired it too.
	 * Losing a reachable feature costs more than the saved click; when the box
	 * is on screen the visitor uses the Verify button.
	 */
	var codeInput = document.querySelector('.la-2fa-input:not(.la-2fa-input--backup)');
	var form = document.getElementById('la-2fa-form');
	if (codeInput && form) {
		var trustBox = form.querySelector('input[name="la_trust_device"]');
		codeInput.addEventListener('input', function () {
			// Strip non-digits.
			this.value = this.value.replace(/\D/g, '');
			if (this.value.length === 6 && !trustBox) {
				// requestSubmit() keeps HTML5 validation and submit listeners
				// alive, unlike submit(); fall back for older browsers.
				if (typeof form.requestSubmit === 'function') {
					form.requestSubmit();
				} else {
					form.submit();
				}
			}
		});
	}

	/* ── Profile Page Setup Wizard ───────────────────────────── */

	var wizardEl = document.getElementById('la-2fa-wizard');
	if (!wizardEl) { return; }

	var currentStep = 0;
	var steps = wizardEl.querySelectorAll('.la-2fa-wizard__step');

	function showStep(index) {
		steps.forEach(function (s, i) {
			s.classList.toggle('la-2fa-wizard__step--active', i === index);
		});
		currentStep = index;
	}

	// Copy secret to clipboard.
	var copyBtn = wizardEl.querySelector('.la-2fa-wizard__copy');
	if (copyBtn) {
		copyBtn.addEventListener('click', function () {
			var secretEl = wizardEl.querySelector('.la-2fa-wizard__secret-text');
			if (secretEl && navigator.clipboard) {
				navigator.clipboard.writeText(secretEl.textContent.trim());
				copyBtn.textContent = la2faStrings.copied;
				setTimeout(function () { copyBtn.textContent = la2faStrings.copy; }, 2000);
			}
		});
	}

	// Verify code step: bind ALL verify buttons (one per wizard step).
	wizardEl.querySelectorAll('[data-la-2fa-action="verify-setup"]').forEach(function (verifyBtn) {
		verifyBtn.addEventListener('click', function () {
			// Find the input and error element in the ACTIVE step.
			var activeStep = wizardEl.querySelector('.la-2fa-wizard__step--active');
			var input = activeStep ? activeStep.querySelector('.la-2fa-wizard__verify-input') : null;
			var errorEl = activeStep ? activeStep.querySelector('.la-2fa-wizard__error') : null;
			var code = input ? input.value.replace(/\D/g, '') : '';

			if (code.length !== 6) {
				if (errorEl) { errorEl.textContent = la2faStrings.codeRequired; }
				return;
			}

			verifyBtn.disabled = true;
			if (errorEl) { errorEl.textContent = ''; }

			var body = new URLSearchParams();
			body.append('action', 'login_armor_verify_2fa_setup');
			body.append('nonce', la2faData.nonce);
			body.append('code', code);
			body.append('method', la2faData.method);
			body.append('setup_token', la2faData.setupToken || '');

			fetch(la2faData.ajaxUrl, { method: 'POST', body: body, credentials: 'same-origin' })
				.then(function (r) { return r.json(); })
				.then(function (json) {
					verifyBtn.disabled = false;
					if (json && json.success) {
						// Show backup codes step.
						if (json.data && json.data.backup_codes) {
							var codesContainer = wizardEl.querySelector('.la-2fa-wizard__codes');
							if (codesContainer) {
								codesContainer.innerHTML = '';
								json.data.backup_codes.forEach(function (c) {
									var div = document.createElement('div');
									div.className = 'la-2fa-wizard__code';
									div.textContent = c;
									codesContainer.appendChild(div);
								});
							}
						}
						showStep(steps.length - 1); // Always go to backup codes (last step).
					} else {
						if (errorEl) { errorEl.textContent = (json && json.data && json.data.message) || la2faStrings.verifyFailed; }
					}
				})
				.catch(function () {
					verifyBtn.disabled = false;
					if (errorEl) { errorEl.textContent = la2faStrings.networkError; }
				});
		});
	});

	// Download backup codes.
	var downloadBtn = wizardEl.querySelector('[data-la-2fa-action="download-codes"]');
	if (downloadBtn) {
		downloadBtn.addEventListener('click', function () {
			var codes = [];
			wizardEl.querySelectorAll('.la-2fa-wizard__code').forEach(function (el) {
				codes.push(el.textContent);
			});
			var text = 'Login Armor Backup Codes\n' +
				'========================\n\n' +
				codes.map(function (c, i) { return (i + 1) + '. ' + c; }).join('\n') +
				'\n\nEach code can only be used once.\nKeep these codes in a safe place.';

			var blob = new Blob([text], { type: 'text/plain' });
			var url = URL.createObjectURL(blob);
			var a = document.createElement('a');
			a.href = url;
			a.download = 'login-armor-backup-codes.txt';
			a.click();
			URL.revokeObjectURL(url);
		});
	}

	// Complete setup.
	var completeBtn = wizardEl.querySelector('[data-la-2fa-action="complete-setup"]');
	if (completeBtn) {
		var confirmCheck = wizardEl.querySelector('.la-2fa-wizard__confirm input');
		if (confirmCheck) {
			completeBtn.disabled = true;
			confirmCheck.addEventListener('change', function () {
				completeBtn.disabled = !this.checked;
			});
		}

		completeBtn.addEventListener('click', function () {
			var activeStep = wizardEl.querySelector('.la-2fa-wizard__step--active');
			var errorEl = activeStep ? activeStep.querySelector('.la-2fa-wizard__error') : null;
			if (errorEl) { errorEl.textContent = ''; }
			completeBtn.disabled = true;

			var body = new URLSearchParams();
			body.append('action', 'login_armor_complete_2fa_setup');
			body.append('nonce', la2faData.nonce);
			body.append('setup_token', la2faData.setupToken || '');

			fetch(la2faData.ajaxUrl, { method: 'POST', body: body, credentials: 'same-origin' })
				.then(function (r) { return r.json(); })
				.then(function (json) {
					if (json && json.success) {
						window.location.reload();
						return;
					}
					completeBtn.disabled = false;
					if (errorEl) {
						errorEl.textContent = (json && json.data && json.data.message) || la2faStrings.completeFailed;
					}
				})
				.catch(function () {
					completeBtn.disabled = false;
					if (errorEl) { errorEl.textContent = la2faStrings.networkError; }
				});
		});
	}

	// Start setup buttons.
	document.querySelectorAll('[data-la-2fa-action="start-totp"]').forEach(function (btn) {
		btn.addEventListener('click', function () {
			btn.disabled = true;
			var body = new URLSearchParams();
			body.append('action', 'login_armor_start_2fa_setup');
			body.append('nonce', la2faData.nonce);
			body.append('method', 'totp');

			fetch(la2faData.ajaxUrl, { method: 'POST', body: body, credentials: 'same-origin' })
				.then(function (r) { return r.json(); })
				.then(function (json) {
					btn.disabled = false;
					if (json && json.success) {
						// Generate QR code client-side.
						var qrEl = wizardEl.querySelector('.la-2fa-wizard__qr');
						if (qrEl && json.data.otpauth_uri && typeof LoginArmorQR !== 'undefined') {
							qrEl.innerHTML = LoginArmorQR.toSVG(json.data.otpauth_uri);
						}
						// Inject secret.
						var secretEl = wizardEl.querySelector('.la-2fa-wizard__secret-text');
						if (secretEl && json.data.secret) {
							secretEl.textContent = json.data.secret;
						}
						la2faData.method = 'totp';
						la2faData.setupToken = json.data.setup_token || '';
						showStep(0);
						wizardEl.hidden = false;
					} else {
						// Surface the server error (e.g. the TOTP secret could not
						// be encrypted, an expired nonce, or a security plugin
						// blocking admin-ajax) instead of leaving the button dead
						// and the user staring at a wizard that never opens.
						var msg = (json && json.data && json.data.message) || la2faStrings.networkError;
						if (window.LA && window.LA.toast) {
							window.LA.toast(msg, 'error');
						} else {
							window.alert(msg);
						}
					}
				})
				.catch(function () {
					btn.disabled = false;
					if (window.LA && window.LA.toast) {
						window.LA.toast(la2faStrings.networkError, 'error');
					} else {
						window.alert(la2faStrings.networkError);
					}
				});
		});
	});

	function startEmailSetup(btn) {
		btn.disabled = true;
		var body = new URLSearchParams();
		body.append('action', 'login_armor_start_2fa_setup');
		body.append('nonce', la2faData.nonce);
		body.append('method', 'email');

		fetch(la2faData.ajaxUrl, { method: 'POST', body: body, credentials: 'same-origin' })
			.then(function (r) { return r.json(); })
			.then(function (json) {
				btn.disabled = false;
				if (json && json.success) {
					la2faData.method = 'email';
					la2faData.setupToken = (json.data && json.data.setup_token) || '';
					showStep(1); // Skip QR step, go to verify.
					wizardEl.hidden = false;
				} else {
					// Surface a delivery failure (e.g. wp_mail returned false
					// between the test and the real send) instead of failing
					// silently: the user must know why nothing happened.
					var msg = (json && json.data && json.data.message) || la2faStrings.networkError;
					if (window.LA && window.LA.toast) {
						window.LA.toast(msg, 'error');
					} else {
						window.alert(msg);
					}
				}
			})
			.catch(function () {
				btn.disabled = false;
				if (window.LA && window.LA.toast) {
					window.LA.toast(la2faStrings.networkError, 'error');
				}
			});
	}

	document.querySelectorAll('[data-la-2fa-action="start-email"]').forEach(function (btn) {
		btn.addEventListener('click', function () {
			// Pre-activation gate: force a real wp_mail() round-trip and a
			// safety-net acknowledgement before committing. Falls through to
			// the legacy direct-start if the modal helper is unavailable.
			if (window.LA && typeof window.LA.openEmailPreactivate === 'function') {
				window.LA.openEmailPreactivate(function () {
					startEmailSetup(btn);
				});
				return;
			}
			startEmailSetup(btn);
		});
	});

	// 2.8.0: a refusal says why (wrong password, too many attempts), where it
	// used to re-enable the button without a word.
	function la2faFail(json) {
		var msg = (json && json.data && json.data.message) || la2faStrings.actionFailed;
		if (window.LA && window.LA.toast) { window.LA.toast(msg, 'error'); } else { window.alert(msg); }
	}

	// Disable 2FA. 2.8.0: confirmed with the account password, which a stolen
	// session cookie does not carry.
	document.querySelectorAll('[data-la-2fa-action="disable"]').forEach(function (btn) {
		btn.addEventListener('click', function () {
			LA.confirm({
				title: la2faStrings.disableTitle,
				body: la2faStrings.disableBody,
				variant: 'danger',
				confirmLabel: la2faStrings.disableConfirm,
				cancelLabel: la2faStrings.cancel,
				password: true,
				passwordLabel: la2faStrings.passwordLabel
			}).then(function (password) {
				if (!password) { return; }
				btn.disabled = true;
				var body = new URLSearchParams();
				body.append('action', 'login_armor_disable_user_2fa');
				body.append('nonce', la2faData.nonce);
				body.append('current_password', password);

				fetch(la2faData.ajaxUrl, { method: 'POST', body: body, credentials: 'same-origin' })
					.then(function (r) { return r.json(); })
					.then(function (json) {
						if (json && json.success) {
							window.location.reload();
						} else {
							btn.disabled = false;
							la2faFail(json);
						}
					})
					.catch(function () {
						btn.disabled = false;
						la2faFail(null);
					});
			});
		});
	});

	// Administrator reset for another user's profile.
	document.querySelectorAll('[data-la-2fa-action="admin-reset"]').forEach(function (btn) {
		btn.addEventListener('click', function () {
			var userId = btn.getAttribute('data-user-id') || '';
			if (!userId) { return; }
			LA.confirm({
				title: 'Reset 2FA for this user?',
				body: 'The user will lose every active 2FA method, backup code and trusted device. Their active sessions will be closed.',
				variant: 'danger',
				confirmLabel: 'Reset 2FA',
				cancelLabel: 'Cancel'
			}).then(function (ok) {
				if (!ok) { return; }
				btn.disabled = true;
				var body = new URLSearchParams();
				body.append('action', 'login_armor_admin_reset_user_2fa');
				body.append('nonce', la2faData.nonce);
				body.append('user_id', userId);
				fetch(la2faData.ajaxUrl, { method: 'POST', body: body, credentials: 'same-origin' })
					.then(function (r) { return r.json(); })
					.then(function (json) {
						if (json && json.success) {
							window.location.reload();
							return;
						}
						btn.disabled = false;
						if (window.LA && window.LA.toast) {
							window.LA.toast((json && json.data && json.data.message) || 'Reset failed.', 'error');
						}
					})
					.catch(function () {
						btn.disabled = false;
						if (window.LA && window.LA.toast) { window.LA.toast(la2faStrings.networkError, 'error'); }
					});
			});
		});
	});

	// Regenerate backup codes.
	document.querySelectorAll('[data-la-2fa-action="regenerate-codes"]').forEach(function (btn) {
		btn.addEventListener('click', function () {
			LA.confirm({
				title: la2faStrings.regenTitle,
				body: la2faStrings.regenBody,
				variant: 'danger',
				confirmLabel: la2faStrings.regenConfirm,
				cancelLabel: la2faStrings.cancel,
				password: true,
				passwordLabel: la2faStrings.passwordLabel
			}).then(function (password) {
				if (!password) { return; }
				btn.disabled = true;
				var body = new URLSearchParams();
				body.append('action', 'login_armor_regenerate_backup_codes');
				body.append('nonce', la2faData.nonce);
				body.append('current_password', password);

				fetch(la2faData.ajaxUrl, { method: 'POST', body: body, credentials: 'same-origin' })
					.then(function (r) { return r.json(); })
					.then(function (json) {
						btn.disabled = false;
						if (!json || !json.success) {
							la2faFail(json);
							return;
						}
						if (json && json.success && json.data.backup_codes) {
							var codesContainer = wizardEl.querySelector('.la-2fa-wizard__codes');
							if (codesContainer) {
								codesContainer.innerHTML = '';
								json.data.backup_codes.forEach(function (c) {
									var div = document.createElement('div');
									div.className = 'la-2fa-wizard__code';
									div.textContent = c;
									codesContainer.appendChild(div);
								});
							}
							showStep(steps.length - 1);
							wizardEl.hidden = false;
						}
					});
			});
		});
	});

	/* ── Trusted Devices: revoke single / revoke all ─────────── */

	// Revoke a single trusted device row.
	document.addEventListener('click', function (ev) {
		var btn = ev.target.closest('[data-la-2fa-action="revoke-device"]');
		if (!btn) { return; }
		var deviceId = btn.getAttribute('data-device-id') || '';
		if (!deviceId) { return; }

		window.LA.confirm({
			title: 'Revoke this device?',
			body: 'The browser you revoke will be asked for 2FA again on its next login.',
			variant: 'danger',
			confirmLabel: 'Revoke',
			cancelLabel: 'Cancel'
		}).then(function (ok) {
			if (!ok) { return; }
			var body = new URLSearchParams();
			body.append('action', 'login_armor_2fa_revoke_trusted_device');
			body.append('nonce', la2faData.nonce);
			body.append('device_id', deviceId);
			fetch(la2faData.ajaxUrl, {
				method: 'POST',
				credentials: 'same-origin',
				headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
				body: body.toString()
			}).then(function (r) { return r.json(); }).then(function (res) {
				if (res && res.success) {
					var row = btn.closest('.la-2fa-device');
					if (row) { row.remove(); }
					if (window.LA && window.LA.toast) { window.LA.toast('Device revoked.', 'success'); }
				} else if (window.LA && window.LA.toast) {
					window.LA.toast('Revoke failed.', 'error');
				}
			});
		});
	});

	// Revoke every trusted device for the current user.
	document.addEventListener('click', function (ev) {
		var btn = ev.target.closest('[data-la-2fa-action="revoke-all-devices"]');
		if (!btn) { return; }

		window.LA.confirm({
			title: 'Revoke every trusted device?',
			body: 'Every browser currently trusted for your account will be asked for 2FA on its next login.',
			variant: 'danger',
			confirmLabel: 'Revoke all',
			cancelLabel: 'Cancel',
			requireCheckbox: true,
			checkboxLabel: 'I want to revoke all trusted devices for my account'
		}).then(function (ok) {
			if (!ok) { return; }
			var body = new URLSearchParams();
			body.append('action', 'login_armor_2fa_revoke_all_trusted_devices');
			body.append('nonce', la2faData.nonce);
			fetch(la2faData.ajaxUrl, {
				method: 'POST',
				credentials: 'same-origin',
				headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
				body: body.toString()
			}).then(function (r) { return r.json(); }).then(function (res) {
				if (res && res.success) {
					var wrap = document.querySelector('[data-la-2fa-devices]');
					if (wrap) { wrap.remove(); }
					if (window.LA && window.LA.toast) { window.LA.toast('All devices revoked.', 'success'); }
				} else if (window.LA && window.LA.toast) {
					window.LA.toast('Revoke all failed.', 'error');
				}
			});
		});
	});
})();

/**
 * Localization strings: injected via wp_localize_script() from PHP.
 * Defaults for standalone verification screen (no WP enqueue).
 */
if (typeof la2faStrings === 'undefined') {
	var la2faStrings = {
		useOther: 'Use a different method',
		hideOther: 'Hide other methods',
		resend: 'Resend code',
		resendIn: 'Resend in %ds',
		copied: 'Copied!',
		copy: 'Copy',
		codeRequired: 'Please enter a 6-digit code.',
		verifyFailed: 'Invalid code. Please try again.',
		networkError: 'Network error. Please try again.',
		confirmDisable: 'Are you sure you want to disable two-factor authentication?',
		confirmRegenerate: 'This will invalidate your current backup codes. Continue?'
	};
}

if (typeof la2faData === 'undefined') {
	var la2faData = { nonce: '', ajaxUrl: '', method: '' };
}
