<?php
/**
 * Request Firewall section: Settings tab.
 *
 * Renders the enable/disable control, the Monitor/Enforce mode selector, the
 * conservative + aggressive rule-family toggles, the IP/path allowlists, and a
 * recent-blocks panel. The PHP filter is portable (works on Apache, Nginx,
 * LiteSpeed, IIS), so the server note is purely informational.
 *
 * @package LoginArmor
 *
 * @var array  $la_fw          Resolved firewall settings.
 * @var bool   $la_fw_enabled  Whether the module is on.
 * @var string $la_fw_mode      'log_only' | 'enforce', as stored.
 * @var string $la_fw_effective 'log_only' | 'enforce', as actually applied right now.
 * @var string $la_fw_server   apache|nginx|litespeed|iis|unknown.
 * @var bool   $la_fw_class    Whether the Firewall class is loaded.
 * @var int    $la_fw_blocks30 Block count over the last 30 days.
 * @var \LoginArmor\Detection\Incident[] $la_fw_recent Recent firewall-block incidents.
 */

// phpcs:disable WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

// Human labels for the rule families, reused by the toggles and the recent
// blocks panel.
$la_fw_labels = array(
	'request_method'         => __( 'Bad request methods', 'login-armor' ),
	'query_string'           => __( 'Bad query strings', 'login-armor' ),
	'request_uri'            => __( 'Bad request paths', 'login-armor' ),
	'request_uri_aggressive' => __( 'Aggressive path rules', 'login-armor' ),
	'user_agent'             => __( 'Bad user agents', 'login-armor' ),
	'referer'                => __( 'Spam referrers', 'login-armor' ),
);

$la_fw_server_note = array(
	'apache'    => __( 'Your server supports .htaccess too, but this PHP filter is portable and every block is logged here.', 'login-armor' ),
	'litespeed' => __( 'Your server supports .htaccess too, but this PHP filter is portable and every block is logged here.', 'login-armor' ),
	'nginx'     => __( 'Nginx ignores .htaccess: this PHP-level firewall is the right tool for your stack.', 'login-armor' ),
	'iis'       => __( 'On IIS this PHP-level firewall works without any web-server configuration.', 'login-armor' ),
	'unknown'   => __( 'This firewall runs in PHP, so it works regardless of your web server.', 'login-armor' ),
);
?>
<section class="la-card la-card--section" id="la-section-firewall" data-la-section="firewall">
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
					<?php esc_html_e( 'Request Firewall', 'login-armor' ); ?>
					<?php if ( $la_fw_enabled && 'enforce' === $la_fw_effective ) : ?>
						<span class="la-status-pill la-status-pill--on"><?php esc_html_e( 'ENFORCING', 'login-armor' ); ?></span>
					<?php elseif ( $la_fw_enabled ) : ?>
						<span class="la-status-pill la-status-pill--warn"><?php esc_html_e( 'MONITORING', 'login-armor' ); ?></span>
					<?php else : ?>
						<span class="la-status-pill la-status-pill--off"><?php esc_html_e( 'DISABLED', 'login-armor' ); ?></span>
					<?php endif; ?>
				</h2>
				<p class="la-card-subtitle">
					<?php esc_html_e( 'Blocks malicious requests in PHP before WordPress processes them: bad query strings, traversal, SQLi/XSS probes, disallowed HTTP methods. Inspired by the 8G firewall.', 'login-armor' ); ?>
				</p>
			</div>
		</div>
		<?php if ( $la_fw_enabled ) : ?>
			<button type="button" class="la-btn la-btn--danger la-btn--small" data-la-action="firewall-disable">
				<?php esc_html_e( 'Disable', 'login-armor' ); ?>
			</button>
		<?php endif; ?>
	</header>

	<div class="la-card-sep"></div>

	<?php if ( ! $la_fw_enabled ) : ?>

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
						<strong><?php esc_html_e( 'The request firewall is off', 'login-armor' ); ?></strong>
						<span><?php esc_html_e( 'Common automated probes (SQL injection, traversal, scanner tools) reach WordPress unfiltered. Enabling starts in monitor mode: it logs would-be blocks without blocking anything, so you can review before enforcing.', 'login-armor' ); ?></span>
					</div>
				</div>
				<div class="la-hide-disabled__actions">
					<button type="button" class="la-btn la-btn--primary la-btn--amber" data-la-action="firewall-enable">
						<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="width:16px;height:16px;margin-right:6px;">
							<circle cx="12" cy="12" r="10"/>
							<line x1="4.93" y1="4.93" x2="19.07" y2="19.07"/>
						</svg>
						<?php esc_html_e( 'Enable Request Firewall (monitor mode)', 'login-armor' ); ?>
					</button>
				</div>
			</div>
		</div>

	<?php else : ?>

		<div class="la-card-body">
			<div data-la-firewall-form>

				<?php if ( $la_fw_enabled && $la_fw_mode !== $la_fw_effective ) : ?>
					<div class="la-danger-note" data-la-fw-safe-mode>
						<?php \LoginArmor\Icons::render( 'alert-triangle', '', 14 ); ?>
						<span>
							<strong><?php esc_html_e( 'Safe mode is active.', 'login-armor' ); ?></strong>
							<?php esc_html_e( 'This module is only logging right now, whatever the mode selected below. Your setting is untouched and comes back the moment you remove LOGIN_ARMOR_SAFE_MODE from wp-config.php.', 'login-armor' ); ?>
						</span>
					</div>
				<?php endif; ?>

				<?php if ( $la_fw_blocks30 > 0 ) : ?>
					<p class="la-field__desc" style="margin-top:0;">
						<strong><?php echo esc_html( (string) $la_fw_blocks30 ); ?></strong>
						<?php esc_html_e( 'firewall matches in the last 30 days.', 'login-armor' ); ?>
						<?php if ( 'log_only' === $la_fw_mode ) : ?>
							<?php esc_html_e( '(Monitor mode: these were logged, not blocked.)', 'login-armor' ); ?>
						<?php endif; ?>
					</p>
				<?php endif; ?>

				<?php
				/*
				 * 2.7.0: the deterministic half of the "switch to Enforce"
				 * nudge. The Overview advice only renders in the all-quiet
				 * state, and a monitor-mode match opens an ACTIVE incident,
				 * so the very sites with something to report are the ones
				 * that never see it there. This banner has no such condition:
				 * it appears on the module's own screen, right above the mode
				 * selector it is talking about.
				 */
				$la_fw_monitor_days = $la_fw_class ? \LoginArmor\Firewall\Firewall::monitoring_days() : 0;
				if ( $la_fw_monitor_days >= \LoginArmor\Overview::ENFORCE_ADVICE_MIN_DAYS ) :
					$la_fw_monitor_matches = \LoginArmor\Firewall\Firewall::count_blocks( '7d' );
					?>
					<div class="la-enforce-hint">
						<?php
						/*
						 * Two sentences, two plurals. A single sentence
						 * carrying both counts has to pick ONE of them for
						 * _n(), and the agreement of the other then follows
						 * the wrong number in every language with more than
						 * two plural forms.
						 */
						printf(
							esc_html(
								/* translators: %d: number of days in monitor mode. */
								_n( 'Monitoring for %d day.', 'Monitoring for %d days.', (int) $la_fw_monitor_days, 'login-armor' )
							),
							(int) $la_fw_monitor_days
						);
						echo ' ';
						printf(
							esc_html(
								/* translators: %d: number of matches over the last 7 days. */
								_n(
									'%d match over the last week: switch to Enforce below to start blocking instead of only logging.',
									'%d matches over the last week: switch to Enforce below to start blocking instead of only logging.',
									(int) $la_fw_monitor_matches,
									'login-armor'
								)
							),
							(int) $la_fw_monitor_matches
						);
						?>
					</div>
				<?php endif; ?>

				<!-- Mode -->
				<div class="la-field">
					<h4 class="la-field__label"><?php esc_html_e( 'Mode', 'login-armor' ); ?></h4>
					<p class="la-field__desc">
						<?php esc_html_e( 'Start in Monitor to validate against real traffic. Switch to Enforce only once the monitor log looks clean.', 'login-armor' ); ?>
					</p>
					<div class="la-radio-grid">
						<label class="la-radio-opt <?php echo 'log_only' === $la_fw_mode ? 'la-radio-opt--active' : ''; ?>">
							<div class="la-radio-opt__top">
								<input type="radio" name="firewall_mode" value="log_only" <?php checked( $la_fw_mode, 'log_only' ); ?> />
								<span class="la-radio-opt__title"><?php esc_html_e( 'Monitor', 'login-armor' ); ?></span>
								<span class="la-radio-opt__tag"><?php esc_html_e( 'Recommended', 'login-armor' ); ?></span>
							</div>
							<p class="la-radio-opt__desc">
								<?php esc_html_e( 'Logs would-be blocks as incidents without blocking. Zero risk of breaking the site.', 'login-armor' ); ?>
							</p>
						</label>
						<label class="la-radio-opt <?php echo 'enforce' === $la_fw_mode ? 'la-radio-opt--active' : ''; ?>">
							<div class="la-radio-opt__top">
								<input type="radio" name="firewall_mode" value="enforce" <?php checked( $la_fw_mode, 'enforce' ); ?> />
								<span class="la-radio-opt__title"><?php esc_html_e( 'Enforce', 'login-armor' ); ?></span>
							</div>
							<p class="la-radio-opt__desc">
								<?php esc_html_e( 'Actually blocks matching requests with a 403. Logged-in admins are never filtered.', 'login-armor' ); ?>
							</p>
						</label>
					</div>
				</div>

				<div class="la-inner-sep"></div>

				<!-- Conservative families -->
				<div class="la-field">
					<h4 class="la-field__label"><?php esc_html_e( 'Conservative rules', 'login-armor' ); ?></h4>
					<p class="la-field__desc">
						<?php esc_html_e( 'Very low false-positive risk. Recommended on for everyone.', 'login-armor' ); ?>
					</p>
					<?php
					$la_fw_conservative = array(
						'query_string'   => __( 'Block SQL injection, code-exec, traversal and XSS markers in the query string.', 'login-armor' ),
						'request_uri'    => __( 'Block traversal, sensitive system files, backups and known web-shell paths.', 'login-armor' ),
						'request_method' => __( 'Allow only standard HTTP methods; block CONNECT, TRACE, TRACK, DEBUG and malformed ones.', 'login-armor' ),
					);
					foreach ( $la_fw_conservative as $la_k => $la_desc ) :
						?>
						<div class="la-toggle-row">
							<label class="la-toggle">
								<input type="checkbox" name="firewall_<?php echo esc_attr( $la_k ); ?>" value="1" <?php checked( ! empty( $la_fw[ $la_k ] ) ); ?> aria-labelledby="la-lbl-firewall-<?php echo esc_attr( $la_k ); ?>" />
								<span class="la-toggle__track"></span>
							</label>
							<?php // 2.8.0: the switch is named by the sentence beside it: its <label> holds no text. ?>
							<span class="la-toggle-row__label" id="la-lbl-firewall-<?php echo esc_attr( $la_k ); ?>">
								<strong><?php echo esc_html( $la_fw_labels[ $la_k ] ); ?></strong>: <?php echo esc_html( $la_desc ); ?>
							</span>
						</div>
					<?php endforeach; ?>
				</div>

				<div class="la-inner-sep"></div>

				<!-- Aggressive families -->
				<div class="la-field">
					<h4 class="la-field__label"><?php esc_html_e( 'Aggressive rules', 'login-armor' ); ?></h4>
					<p class="la-field__desc">
						<?php esc_html_e( 'Higher false-positive risk: these can hit legitimate clients (uptime monitors, Jetpack/XML-RPC, author pages). Enable only if you understand the trade-off, and test in Monitor first.', 'login-armor' ); ?>
					</p>
					<?php
					$la_fw_aggressive = array(
						'user_agent'             => __( 'Block scanner and generic HTTP-library user agents (curl, wget, python, sqlmap, nikto…).', 'login-armor' ),
						'referer'                => __( 'Block requests from known spam referrer domains (best-effort, list ages quickly).', 'login-armor' ),
						'request_uri_aggressive' => __( 'Block XML-RPC, author enumeration and exposed dev/source files.', 'login-armor' ),
					);
					foreach ( $la_fw_aggressive as $la_k => $la_desc ) :
						?>
						<div class="la-toggle-row">
							<label class="la-toggle">
								<input type="checkbox" name="firewall_<?php echo esc_attr( $la_k ); ?>" value="1" <?php checked( ! empty( $la_fw[ $la_k ] ) ); ?> aria-labelledby="la-lbl-firewall-<?php echo esc_attr( $la_k ); ?>" />
								<span class="la-toggle__track"></span>
							</label>
							<?php // 2.8.0: the switch is named by the sentence beside it: its <label> holds no text. ?>
							<span class="la-toggle-row__label" id="la-lbl-firewall-<?php echo esc_attr( $la_k ); ?>">
								<strong><?php echo esc_html( $la_fw_labels[ $la_k ] ); ?></strong>: <?php echo esc_html( $la_desc ); ?>
							</span>
						</div>
					<?php endforeach; ?>
				</div>

				<div class="la-inner-sep"></div>

				<!-- Allowlists -->
				<div class="la-field">
					<h4 class="la-field__label"><?php esc_html_e( 'Allowlist', 'login-armor' ); ?></h4>
					<p class="la-field__desc">
						<?php esc_html_e( 'Requests from these IPs, or to these paths, are never inspected. One entry per line. IPs accept CIDR ranges (e.g. 203.0.113.0/24). Logged-in administrators are always exempt.', 'login-armor' ); ?>
					</p>
					<div class="la-fw-allow-grid">
						<div class="la-fw-allow-col">
							<label class="la-fw-allow-col__label">
								<span><?php esc_html_e( 'Allowed IPs', 'login-armor' ); ?></span>
								<textarea
									rows="5"
									class="la-input la-input--mono"
									name="firewall_allow_ips"
									placeholder="203.0.113.10&#10;198.51.100.0/24"
								><?php echo esc_textarea( (string) ( $la_fw['allow_ips'] ?? '' ) ); ?></textarea>
							</label>
							<button type="button" class="la-btn la-btn--secondary la-btn--small la-fw-allow-col__btn" data-la-action="firewall-add-ip">
								<?php esc_html_e( 'Use my current IP', 'login-armor' ); ?>
							</button>
						</div>
						<div class="la-fw-allow-col">
							<label class="la-fw-allow-col__label">
								<span><?php esc_html_e( 'Allowed paths', 'login-armor' ); ?></span>
								<textarea
									rows="5"
									class="la-input la-input--mono"
									name="firewall_allow_paths"
									placeholder="/wp-json/my-plugin/&#10;/my-export.csv"
								><?php echo esc_textarea( (string) ( $la_fw['allow_paths'] ?? '' ) ); ?></textarea>
							</label>
						</div>
					</div>
				</div>

				<div class="la-inner-sep"></div>

				<!-- Server note -->
				<p class="la-muted">
					<?php
					$la_srv_key = isset( $la_fw_server_note[ $la_fw_server ] ) ? $la_fw_server : 'unknown';
					echo esc_html( $la_fw_server_note[ $la_srv_key ] );
					?>
				</p>

				<?php if ( ! empty( $la_fw_recent ) ) : ?>
					<div class="la-inner-sep"></div>
					<div class="la-field">
						<h4 class="la-field__label"><?php esc_html_e( 'Recent blocks', 'login-armor' ); ?></h4>
						<div class="la-code-preview">
							<?php
							foreach ( $la_fw_recent as $la_inc ) :
								$la_marker = (string) $la_inc->target_username;
								$la_dry    = ( 0 === strpos( $la_marker, 'fw-dry:' ) );
								$la_famkey = preg_replace( '/^fw(-dry)?:/', '', $la_marker );
								$la_famlbl = isset( $la_fw_labels[ $la_famkey ] ) ? $la_fw_labels[ $la_famkey ] : $la_famkey;
								?>
								<div>
									<span class="la-code-preview__header"><?php echo esc_html( (string) $la_inc->ip ); ?></span>
									<span class="la-code-preview__value">
										<?php echo esc_html( $la_famlbl ); ?>
										&middot; <?php echo esc_html( sprintf( /* translators: %d: number of matched requests */ _n( '%d hit', '%d hits', (int) $la_inc->events_count, 'login-armor' ), (int) $la_inc->events_count ) ); ?>
										<?php if ( $la_dry ) : ?>
											&middot; <?php esc_html_e( 'monitor', 'login-armor' ); ?>
										<?php endif; ?>
									</span>
								</div>
							<?php endforeach; ?>
						</div>
					</div>
				<?php endif; ?>

			</div>
		</div>

	<?php endif; ?>
</section>
