<?php
/**
 * Brute Force Protection section: Settings tab.
 *
 * When disabled, shows a CTA to enable brute force protection.
 * When enabled, shows lockout rules, IP safelist, and notification settings.
 *
 * @package LoginArmor
 *
 * @var bool   $la_limit_enabled    Whether brute force protection is on.
 * @var int    $la_allowed_retries  Failed attempts before lockout.
 * @var int    $la_lockout_duration Lockout duration in minutes.
 * @var int    $la_max_lockouts     Lockouts before long ban.
 * @var int    $la_long_duration    Long ban duration in hours.
 * @var int    $la_valid_duration   Reset period in hours.
 * @var string $la_whitelist_ips    Newline-separated safelist IPs.
 * @var int    $la_notify_threshold Lockouts before email notification (0 = disabled).
 * @var string $la_notify_email     Notification email (empty = admin email).
 * @var bool   $la_syslog           Syslog lines for fail2ban (2.10.0).
 * @var bool   $la_syslog_available Whether this PHP can write to the system log.
 * @var string $la_ip_method        IP detection method (REMOTE_ADDR, HTTP_CF_CONNECTING_IP, etc.).
 * @var string $la_trusted_proxies  Newline-separated exact proxy IPs/CIDRs.
 */

// phpcs:disable WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}
?>
<section class="la-card la-card--section" id="la-section-limit-login" data-la-section="limit-login">
	<header class="la-card-header">
		<div class="la-card-header__left">
			<div class="la-card-icon">
				<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
					<circle cx="12" cy="12" r="10"/>
					<line x1="4.93" y1="4.93" x2="19.07" y2="19.07"/>
				</svg>
			</div>
			<div>
				<h2 class="la-card-title">
					<?php esc_html_e( 'Brute Force Protection', 'login-armor' ); ?>
					<?php if ( $la_limit_enabled ) : ?>
						<span class="la-status-pill la-status-pill--on"><?php esc_html_e( 'ACTIVE', 'login-armor' ); ?></span>
					<?php else : ?>
						<span class="la-status-pill la-status-pill--off"><?php esc_html_e( 'DISABLED', 'login-armor' ); ?></span>
					<?php endif; ?>
				</h2>
				<p class="la-card-subtitle">
					<?php if ( $la_limit_enabled ) : ?>
						<?php esc_html_e( 'Rate-limit failed login attempts and lock out attacking IPs.', 'login-armor' ); ?>
					<?php else : ?>
						<?php esc_html_e( 'Brute force protection is currently disabled. Enable it to rate-limit login attempts.', 'login-armor' ); ?>
					<?php endif; ?>
				</p>
			</div>
		</div>
		<?php if ( $la_limit_enabled ) : ?>
			<button type="button" class="la-btn la-btn--danger la-btn--small" data-la-action="limit-disable">
				<?php esc_html_e( 'Disable', 'login-armor' ); ?>
			</button>
		<?php endif; ?>
	</header>

	<div class="la-card-sep"></div>

	<?php if ( ! $la_limit_enabled ) : ?>

		<div class="la-card-body">
			<div class="la-hide-disabled">
				<div class="la-hide-disabled__warning">
					<div class="la-hide-disabled__warning-icon">
						<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
							<path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/>
							<line x1="12" y1="9" x2="12" y2="13"/>
							<line x1="12" y1="17" x2="12.01" y2="17"/>
						</svg>
					</div>
					<div class="la-hide-disabled__warning-text">
						<strong><?php esc_html_e( 'Brute force protection is disabled', 'login-armor' ); ?></strong>
						<span><?php esc_html_e( 'Attackers can try unlimited passwords without being locked out.', 'login-armor' ); ?></span>
					</div>
				</div>
				<div class="la-hide-disabled__body">
					<p class="la-hide-disabled__desc">
						<?php esc_html_e( 'When enabled, IPs that fail to log in too many times are temporarily locked out. This is your primary defense against password guessing attacks.', 'login-armor' ); ?>
					</p>
				</div>
				<div class="la-hide-disabled__actions">
					<button type="button" class="la-btn la-btn--primary la-btn--amber" data-la-action="limit-enable">
						<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="width:16px;height:16px;margin-right:6px;">
							<circle cx="12" cy="12" r="10"/>
							<line x1="4.93" y1="4.93" x2="19.07" y2="19.07"/>
						</svg>
						<?php esc_html_e( 'Enable Brute Force Protection', 'login-armor' ); ?>
					</button>
				</div>
			</div>
		</div>

	<?php else : ?>

		<div class="la-card-body">
			<div data-la-limit-form>

				<!-- Field: IP Detection Method -->
				<div class="la-field">
					<?php // 2.8.0: every control below is named by the text shown with it (aria-labelledby): none had an accessible name. ?>
					<h4 class="la-field__label" id="la-lbl-ip-method"><?php esc_html_e( 'IP Detection Method', 'login-armor' ); ?></h4>
					<p class="la-field__desc"><?php esc_html_e( 'How to detect the visitor IP address. Choose based on your server setup.', 'login-armor' ); ?></p>

					<div class="la-inline-fields">
						<div class="la-inline-field">
							<select class="la-select" name="ip_method" aria-labelledby="la-lbl-ip-method">
								<option value="REMOTE_ADDR" <?php selected( $la_ip_method, 'REMOTE_ADDR' ); ?>><?php esc_html_e( 'Direct connection (default)', 'login-armor' ); ?></option>
								<option value="HTTP_CF_CONNECTING_IP" <?php selected( $la_ip_method, 'HTTP_CF_CONNECTING_IP' ); ?>><?php esc_html_e( 'Behind Cloudflare', 'login-armor' ); ?></option>
								<option value="HTTP_X_FORWARDED_FOR" <?php selected( $la_ip_method, 'HTTP_X_FORWARDED_FOR' ); ?>><?php esc_html_e( 'Behind a reverse proxy', 'login-armor' ); ?></option>
								<option value="HTTP_X_REAL_IP" <?php selected( $la_ip_method, 'HTTP_X_REAL_IP' ); ?>><?php esc_html_e( 'Behind Nginx proxy', 'login-armor' ); ?></option>
							</select>
						</div>
					</div>
					<p class="la-field__help"><?php esc_html_e( 'Forwarding headers are ignored unless the immediate network peer is listed below. If unsure, keep "Direct connection".', 'login-armor' ); ?></p>
				</div>

				<div class="la-inner-sep"></div>

				<!-- Field: Trusted Proxies -->
				<div class="la-field">
					<h4 class="la-field__label" id="la-lbl-trusted-proxies"><?php esc_html_e( 'Trusted Proxy IPs', 'login-armor' ); ?></h4>
					<p class="la-field__desc"><?php esc_html_e( 'Required when a proxy header is selected. Enter the immediate proxy IPs or CIDR ranges, one per line. Never enter 0.0.0.0/0 or ::/0.', 'login-armor' ); ?></p>
					<textarea class="la-textarea" name="trusted_proxies" aria-labelledby="la-lbl-trusted-proxies" placeholder="127.0.0.1&#10;10.0.0.0/24&#10;2001:db8::/48"><?php echo esc_textarea( $la_trusted_proxies ); ?></textarea>
				</div>

				<div class="la-inner-sep"></div>

				<!-- Group 1: Lockout Rules -->
				<div class="la-field">
					<h4 class="la-field__label"><?php esc_html_e( 'Lockout Rules', 'login-armor' ); ?></h4>
					<p class="la-field__desc"><?php esc_html_e( 'How failed login attempts trigger temporary IP bans.', 'login-armor' ); ?></p>

					<div class="la-numbers-grid">
						<div class="la-number-field">
							<input type="number" class="la-number-field__input" name="allowed_retries" value="<?php echo esc_attr( $la_allowed_retries ); ?>" min="1" max="20" aria-labelledby="la-lbl-allowed-retries" aria-describedby="la-hint-allowed-retries">
							<div class="la-number-field__meta">
								<span class="la-number-field__unit" id="la-lbl-allowed-retries"><?php esc_html_e( 'Allowed retries', 'login-armor' ); ?></span>
								<span class="la-number-field__hint" id="la-hint-allowed-retries"><?php esc_html_e( 'before lockout', 'login-armor' ); ?></span>
							</div>
						</div>

						<div class="la-number-field">
							<input type="number" class="la-number-field__input" name="lockout_duration" value="<?php echo esc_attr( $la_lockout_duration ); ?>" min="1" max="1440" aria-labelledby="la-lbl-lockout-duration" aria-describedby="la-hint-lockout-duration">
							<div class="la-number-field__meta">
								<span class="la-number-field__unit" id="la-lbl-lockout-duration"><?php esc_html_e( 'Minutes lockout', 'login-armor' ); ?></span>
								<span class="la-number-field__hint" id="la-hint-lockout-duration"><?php esc_html_e( 'first lockout duration', 'login-armor' ); ?></span>
							</div>
						</div>

						<div class="la-number-field">
							<input type="number" class="la-number-field__input" name="max_lockouts" value="<?php echo esc_attr( $la_max_lockouts ); ?>" min="1" max="20" aria-labelledby="la-lbl-max-lockouts" aria-describedby="la-hint-max-lockouts">
							<div class="la-number-field__meta">
								<span class="la-number-field__unit" id="la-lbl-max-lockouts"><?php esc_html_e( 'Max lockouts', 'login-armor' ); ?></span>
								<span class="la-number-field__hint" id="la-hint-max-lockouts"><?php esc_html_e( 'before long ban', 'login-armor' ); ?></span>
							</div>
						</div>

						<div class="la-number-field">
							<input type="number" class="la-number-field__input" name="long_duration" value="<?php echo esc_attr( $la_long_duration ); ?>" min="1" max="168" aria-labelledby="la-lbl-long-duration" aria-describedby="la-hint-long-duration">
							<div class="la-number-field__meta">
								<span class="la-number-field__unit" id="la-lbl-long-duration"><?php esc_html_e( 'Hours long ban', 'login-armor' ); ?></span>
								<span class="la-number-field__hint" id="la-hint-long-duration"><?php esc_html_e( 'extended lockout', 'login-armor' ); ?></span>
							</div>
						</div>

						<div class="la-number-field la-number-field--full">
							<input type="number" class="la-number-field__input" name="valid_duration" value="<?php echo esc_attr( $la_valid_duration ); ?>" min="1" max="168" aria-labelledby="la-lbl-valid-duration" aria-describedby="la-hint-valid-duration">
							<div class="la-number-field__meta">
								<span class="la-number-field__unit" id="la-lbl-valid-duration"><?php esc_html_e( 'Hours reset period', 'login-armor' ); ?></span>
								<span class="la-number-field__hint" id="la-hint-valid-duration"><?php esc_html_e( 'failed attempts cleared after this inactivity window', 'login-armor' ); ?></span>
							</div>
						</div>
					</div>

					<div class="la-summary-box" data-la-limit-summary></div>
				</div>

				<div class="la-inner-sep"></div>

				<!-- Group 2: IP Safelist -->
				<div class="la-field">
					<h4 class="la-field__label" id="la-lbl-whitelist-ips"><?php esc_html_e( 'IP Safelist', 'login-armor' ); ?></h4>
					<p class="la-field__desc"><?php esc_html_e( 'These client IPs will never be locked out. One per line. Localhost is automatically safe only in direct-connection mode.', 'login-armor' ); ?></p>

					<textarea class="la-textarea" name="whitelist_ips" aria-labelledby="la-lbl-whitelist-ips" placeholder="192.168.1.100&#10;203.0.113.50"><?php echo esc_textarea( $la_whitelist_ips ); ?></textarea>

					<button type="button" class="la-btn--small-action" data-la-action="limit-add-ip">
						<svg viewBox="0 0 24 24" stroke-linecap="round" stroke-linejoin="round"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>
						<?php esc_html_e( 'Add my current IP', 'login-armor' ); ?>
					</button>
				</div>

				<div class="la-inner-sep"></div>

				<!-- Group 3: Email Notifications -->
				<div class="la-field">
					<h4 class="la-field__label"><?php esc_html_e( 'Email Notifications', 'login-armor' ); ?></h4>
					<p class="la-field__desc"><?php esc_html_e( 'Get notified when an IP triggers repeated lockouts. Set to 0 to disable.', 'login-armor' ); ?></p>

					<div class="la-inline-fields">
						<div class="la-bf-field">
							<span class="la-bf-field__label" id="la-lbl-notify-after"><?php esc_html_e( 'After', 'login-armor' ); ?></span>
							<input type="number" class="la-bf-field__input" name="notify_threshold" value="<?php echo esc_attr( $la_notify_threshold ); ?>" min="0" max="100" aria-labelledby="la-lbl-notify-after la-lbl-notify-lockouts">
							<span class="la-bf-field__suffix" id="la-lbl-notify-lockouts"><?php esc_html_e( 'lockouts', 'login-armor' ); ?></span>
						</div>
						<div class="la-inline-field la-inline-field--grow">
							<span class="la-inline-field__label" id="la-lbl-notify-email"><?php esc_html_e( 'Send to', 'login-armor' ); ?></span>
							<input type="email" class="la-inline-field__input la-inline-field__input--wide" name="notify_email" aria-labelledby="la-lbl-notify-email" value="<?php echo esc_attr( $la_notify_email ); ?>" placeholder="<?php echo esc_attr( get_option( 'admin_email' ) ); ?> (<?php esc_attr_e( 'default', 'login-armor' ); ?>)">
						</div>
					</div>
				</div>

				<!-- Group 4: syslog lines for fail2ban (2.10.0) -->
				<div class="la-field">
					<h4 class="la-field__label"><?php esc_html_e( 'System log (fail2ban)', 'login-armor' ); ?></h4>
					<p class="la-field__desc"><?php esc_html_e( 'Writes one line to the server\'s system log for each failed login that counts toward the lockout, and one per lockout, so fail2ban can ban the address at the network level. Never the login typed. Configuring fail2ban is done on the server: see the FAQ.', 'login-armor' ); ?></p>
					<div class="la-toggle-row">
						<label class="la-toggle">
							<input type="checkbox" name="syslog" value="1" <?php checked( $la_syslog ); ?> aria-labelledby="la-lbl-syslog" />
							<span class="la-toggle__track"></span>
						</label>
						<span class="la-toggle-row__label" id="la-lbl-syslog"><?php esc_html_e( 'Write failures and lockouts to the system log', 'login-armor' ); ?></span>
					</div>
					<?php if ( ! $la_syslog_available ) : ?>
						<p class="la-field__desc"><?php esc_html_e( 'This server\'s PHP cannot write to the system log (the syslog functions are disabled): nothing will be written.', 'login-armor' ); ?></p>
					<?php endif; ?>
				</div>

				<!-- Actions row -->
				<div class="la-actions-row">
					<button type="button" class="la-btn la-btn--recommend" data-la-action="limit-recommend">
						<?php esc_html_e( 'Apply recommended defaults', 'login-armor' ); ?>
					</button>
					<button type="button" class="la-btn la-btn--reset-defaults" data-la-action="limit-reset">
						<?php esc_html_e( 'Reset defaults', 'login-armor' ); ?>
					</button>
				</div>

			</div>
		</div>

	<?php endif; ?>
</section>
