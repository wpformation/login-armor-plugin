<?php
/**
 * Login Page Security Headers section: Settings tab.
 *
 * Renders the enable/disable toggle, the mode preset selector, the optional
 * CSP report URI, and a live preview of the headers that will be emitted.
 *
 * @package LoginArmor
 *
 * @var bool   $la_login_headers_enabled    Whether the module is on.
 * @var string $la_login_headers_mode       One of 'standard' | 'strict'.
 * @var string $la_login_headers_report_uri Reporting endpoint (https://...).
 * @var string $la_login_headers_hsts       One of 'off' | 'enabled' | 'enabled_subdomains'.
 */

// phpcs:disable WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

// Compute the header preview from the current settings so admins see exactly
// what will hit the wire. Calls the module statically to stay DRY.
$la_headers_preview = \LoginArmor\LoginHeaders::build_headers();
?>
<section class="la-card la-card--section" id="la-section-login-headers" data-la-section="login-headers">
	<header class="la-card-header">
		<div class="la-card-header__left">
			<div class="la-card-icon">
				<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
					<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
					<path d="M9 12l2 2 4-4"/>
				</svg>
			</div>
			<div>
				<h2 class="la-card-title">
					<?php esc_html_e( 'Login Page Protection Headers', 'login-armor' ); ?>
					<?php if ( $la_login_headers_enabled ) : ?>
						<span class="la-status-pill la-status-pill--on"><?php esc_html_e( 'ACTIVE', 'login-armor' ); ?></span>
					<?php else : ?>
						<span class="la-status-pill la-status-pill--off"><?php esc_html_e( 'DISABLED', 'login-armor' ); ?></span>
					<?php endif; ?>
				</h2>
				<p class="la-card-subtitle">
					<?php if ( $la_login_headers_enabled ) : ?>
						<?php esc_html_e( 'Security headers scoped to the login request: nothing else on the site is affected.', 'login-armor' ); ?>
					<?php else : ?>
						<?php esc_html_e( 'Send HTTP headers that block clickjacking, MIME sniffing, and credential exfiltration on the login page.', 'login-armor' ); ?>
					<?php endif; ?>
				</p>
			</div>
		</div>
		<?php if ( $la_login_headers_enabled ) : ?>
			<button type="button" class="la-btn la-btn--danger la-btn--small" data-la-action="login-headers-disable">
				<?php esc_html_e( 'Disable', 'login-armor' ); ?>
			</button>
		<?php endif; ?>
	</header>

	<div class="la-card-sep"></div>

	<?php if ( ! $la_login_headers_enabled ) : ?>

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
						<strong><?php esc_html_e( 'Login headers are disabled', 'login-armor' ); ?></strong>
						<span><?php esc_html_e( 'Your login page can be framed, its referrer leaks, and MIME sniffing is permitted. Enable for a single-click hardening of the most targeted page.', 'login-armor' ); ?></span>
					</div>
				</div>
				<div class="la-hide-disabled__body">
					<p class="la-hide-disabled__desc">
						<?php esc_html_e( 'When enabled, LoginArmor adds a curated set of security headers only on wp-login.php and your Hide Login slug. Nothing is applied to front-end pages or the WP admin, so the risk of breaking your theme or admin scripts is zero.', 'login-armor' ); ?>
					</p>
				</div>
				<div class="la-hide-disabled__actions">
					<button type="button" class="la-btn la-btn--primary la-btn--amber" data-la-action="login-headers-enable">
						<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="width:16px;height:16px;margin-right:6px;">
							<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
						</svg>
						<?php esc_html_e( 'Enable Login Page Protection Headers', 'login-armor' ); ?>
					</button>
				</div>
			</div>
		</div>

	<?php else : ?>

		<div class="la-card-body">
			<div data-la-login-headers-form>

				<!-- Field 1: Profile -->
				<div class="la-field">
					<h4 class="la-field__label"><?php esc_html_e( 'Profile', 'login-armor' ); ?></h4>
					<p class="la-field__desc">
						<?php esc_html_e( 'Standard keeps WordPress core login scripts working. Strict tightens the CSP for hardened deployments: may break login themes that inject third-party assets.', 'login-armor' ); ?>
					</p>

					<div class="la-radio-grid">
						<label class="la-radio-opt <?php echo 'standard' === $la_login_headers_mode ? 'la-radio-opt--active' : ''; ?>">
							<div class="la-radio-opt__top">
								<input type="radio" name="login_headers_mode" value="standard" <?php checked( $la_login_headers_mode, 'standard' ); ?> />
								<span class="la-radio-opt__title"><?php esc_html_e( 'Standard', 'login-armor' ); ?></span>
								<span class="la-radio-opt__tag"><?php esc_html_e( 'Recommended', 'login-armor' ); ?></span>
							</div>
							<p class="la-radio-opt__desc">
								<?php esc_html_e( 'frame-ancestors none + form-action self + MIME + Referrer + Permissions-Policy. Safe for 99% of sites.', 'login-armor' ); ?>
							</p>
						</label>
						<label class="la-radio-opt <?php echo 'strict' === $la_login_headers_mode ? 'la-radio-opt--active' : ''; ?>">
							<div class="la-radio-opt__top">
								<input type="radio" name="login_headers_mode" value="strict" <?php checked( $la_login_headers_mode, 'strict' ); ?> />
								<span class="la-radio-opt__title"><?php esc_html_e( 'Strict', 'login-armor' ); ?></span>
							</div>
							<p class="la-radio-opt__desc">
								<?php esc_html_e( 'Standard + default-src self, full CSP lockdown. Test before enabling on sites with custom login themes.', 'login-armor' ); ?>
							</p>
						</label>
					</div>
				</div>

				<div class="la-inner-sep"></div>

				<!-- Field 2 bis: HSTS -->
				<div class="la-field">
					<h4 class="la-field__label"><?php esc_html_e( 'HTTP Strict Transport Security (HSTS)', 'login-armor' ); ?></h4>
					<p class="la-field__desc">
						<?php esc_html_e( 'Pin TLS for the login surface. The browser will refuse to connect over plain HTTP for the configured duration. Only emitted on HTTPS requests.', 'login-armor' ); ?>
					</p>

					<div class="la-radio-grid">
						<label class="la-radio-opt <?php echo 'off' === $la_login_headers_hsts ? 'la-radio-opt--active' : ''; ?>">
							<div class="la-radio-opt__top">
								<input type="radio" name="login_headers_hsts" value="off" <?php checked( $la_login_headers_hsts, 'off' ); ?> />
								<span class="la-radio-opt__title"><?php esc_html_e( 'Off', 'login-armor' ); ?></span>
							</div>
							<p class="la-radio-opt__desc">
								<?php esc_html_e( 'Do not emit HSTS. Pick this if the site is still being migrated to HTTPS.', 'login-armor' ); ?>
							</p>
						</label>
						<label class="la-radio-opt <?php echo 'enabled' === $la_login_headers_hsts ? 'la-radio-opt--active' : ''; ?>">
							<div class="la-radio-opt__top">
								<input type="radio" name="login_headers_hsts" value="enabled" <?php checked( $la_login_headers_hsts, 'enabled' ); ?> />
								<span class="la-radio-opt__title"><?php esc_html_e( '180 days', 'login-armor' ); ?></span>
								<span class="la-radio-opt__tag"><?php esc_html_e( 'Recommended', 'login-armor' ); ?></span>
							</div>
							<p class="la-radio-opt__desc">
								<?php esc_html_e( 'max-age=15552000. Safe default: six-month TLS commitment, no subdomain impact.', 'login-armor' ); ?>
							</p>
						</label>
						<label class="la-radio-opt <?php echo 'enabled_subdomains' === $la_login_headers_hsts ? 'la-radio-opt--active' : ''; ?>">
							<div class="la-radio-opt__top">
								<input type="radio" name="login_headers_hsts" value="enabled_subdomains" <?php checked( $la_login_headers_hsts, 'enabled_subdomains' ); ?> />
								<span class="la-radio-opt__title"><?php esc_html_e( '1 year + subdomains', 'login-armor' ); ?></span>
							</div>
							<p class="la-radio-opt__desc">
								<?php esc_html_e( 'max-age=31536000; includeSubDomains. Verify every subdomain serves valid HTTPS first: recovery is hard.', 'login-armor' ); ?>
							</p>
						</label>
					</div>
				</div>

				<div class="la-inner-sep"></div>

				<!-- Field 2: Report URI -->
				<div class="la-field">
					<?php // 2.8.0: named by its heading (aria-labelledby): it had no accessible name. ?>
					<h4 class="la-field__label" id="la-lbl-report-uri"><?php esc_html_e( 'CSP Report Endpoint (optional)', 'login-armor' ); ?></h4>
					<p class="la-field__desc">
						<?php esc_html_e( 'HTTPS endpoint to receive CSP violation reports. Useful for monitoring attempted injections. Leave blank to skip.', 'login-armor' ); ?>
					</p>
					<input
						type="url"
						class="la-input"
						name="login_headers_report_uri"
						aria-labelledby="la-lbl-report-uri"
						value="<?php echo esc_attr( $la_login_headers_report_uri ); ?>"
						placeholder="https://your-report-collector.example/csp"
						pattern="https://.+"
					/>
				</div>

				<div class="la-inner-sep"></div>

				<!-- Field 2b: Site-wide non-CSP headers -->
				<div class="la-field">
					<h4 class="la-field__label"><?php esc_html_e( 'Apply baseline headers site-wide', 'login-armor' ); ?></h4>
					<p class="la-field__desc">
						<?php esc_html_e( 'Also emit the non-CSP security headers (X-Content-Type-Options, Referrer-Policy, Permissions-Policy, X-Frame-Options: SAMEORIGIN, and HSTS if configured) on every front-end page, not just the login. The Content-Security-Policy is intentionally NOT applied site-wide, because a strict CSP commonly breaks themes and page builders.', 'login-armor' ); ?>
					</p>
					<div class="la-toggle-row">
						<label class="la-toggle">
							<input type="checkbox" name="login_headers_sitewide" value="1" <?php checked( ! empty( $la_login_headers_sitewide ) ); ?> aria-labelledby="la-lbl-headers-sitewide" />
							<span class="la-toggle__track"></span>
						</label>
						<?php // 2.8.0: the switch is named by the sentence beside it: its <label> holds no text. ?>
						<span class="la-toggle-row__label" id="la-lbl-headers-sitewide"><?php esc_html_e( 'Send baseline security headers on the whole front-end', 'login-armor' ); ?></span>
					</div>
				</div>

				<div class="la-inner-sep"></div>

				<!-- Field 3: Preview -->
				<div class="la-field">
					<h4 class="la-field__label" id="la-lbl-headers-preview"><?php esc_html_e( 'Headers Sent on Login', 'login-armor' ); ?></h4>
					<p class="la-field__desc">
						<?php esc_html_e( 'Live preview of what LoginArmor will emit. Update settings to see the output change.', 'login-armor' ); ?>
					</p>
					<?php // 2.8.0: the box scrolls (max-height 320px), so it takes the focus to be scrolled from the keyboard (axe: scrollable-region-focusable). ?>
					<div class="la-code-preview" data-la-headers-preview tabindex="0" role="region" aria-labelledby="la-lbl-headers-preview">
<?php foreach ( $la_headers_preview as $la_name => $la_value ) : ?>
<span class="la-code-preview__header"><?php echo esc_html( $la_name ); ?>:</span> <span class="la-code-preview__value"><?php echo esc_html( $la_value ); ?></span>
<?php endforeach; ?>
					</div>
				</div>

			</div>
		</div>

	<?php endif; ?>
</section>
