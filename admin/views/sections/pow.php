<?php
/**
 * Bot Challenge (Proof-of-Work) section (Settings tab).
 *
 * Invisible computational challenge on the login form. Two modes: monitor
 * (count submissions without a valid proof) and enforce (reject them).
 *
 * @package LoginArmor
 *
 * @var bool   $la_pow_enabled    Whether the module is on.
 * @var string $la_pow_mode       'log_only' | 'enforce', as stored.
 * @var string $la_pow_effective  'log_only' | 'enforce', as actually applied right now.
 * @var string $la_pow_difficulty 'low' | 'standard' | 'high'.
 * @var bool   $la_pow_class      Whether the PowChallenge class is loaded.
 * @var int    $la_pow_softfails  Submissions without a valid proof (7-day window).
 */

// phpcs:disable WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}
?>
<section class="la-card la-card--section" id="la-section-pow" data-la-section="pow">
	<header class="la-card-header">
		<div class="la-card-header__left">
			<div class="la-card-icon">
				<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
					<rect x="4" y="4" width="16" height="16" rx="2"/>
					<rect x="9" y="9" width="6" height="6"/>
					<path d="M9 1v3M15 1v3M9 20v3M15 20v3M1 9h3M1 15h3M20 9h3M20 15h3"/>
				</svg>
			</div>
			<div>
				<h2 class="la-card-title">
					<?php esc_html_e( 'Bot Challenge', 'login-armor' ); ?>
					<?php if ( $la_pow_enabled && 'enforce' === $la_pow_effective ) : ?>
						<span class="la-status-pill la-status-pill--on"><?php esc_html_e( 'ENFORCING', 'login-armor' ); ?></span>
					<?php elseif ( $la_pow_enabled ) : ?>
						<span class="la-status-pill la-status-pill--on"><?php esc_html_e( 'MONITORING', 'login-armor' ); ?></span>
					<?php else : ?>
						<span class="la-status-pill la-status-pill--off"><?php esc_html_e( 'DISABLED', 'login-armor' ); ?></span>
					<?php endif; ?>
				</h2>
				<p class="la-card-subtitle">
					<?php if ( $la_pow_enabled ) : ?>
						<?php esc_html_e( 'Every login submission must carry an invisible proof-of-work solved by the browser.', 'login-armor' ); ?>
					<?php else : ?>
						<?php esc_html_e( 'Make every login attempt cost the sender CPU time: invisible to humans, expensive for botnets.', 'login-armor' ); ?>
					<?php endif; ?>
				</p>
			</div>
		</div>
		<?php if ( $la_pow_enabled ) : ?>
			<button type="button" class="la-btn la-btn--danger la-btn--small" data-la-action="pow-disable">
				<?php esc_html_e( 'Disable', 'login-armor' ); ?>
			</button>
		<?php endif; ?>
	</header>

	<div class="la-card-sep"></div>

	<?php if ( ! $la_pow_enabled ) : ?>

		<div class="la-card-body">
			<div class="la-hide-disabled">
				<div class="la-hide-disabled__body">
					<p class="la-hide-disabled__desc">
						<?php esc_html_e( 'A proof-of-work is an invisible alternative to a CAPTCHA: instead of asking humans to click on bicycles, the browser silently solves a small cryptographic puzzle before the login form is accepted. A real visitor never notices: it takes a fraction of a second. A botnet hammering thousands of passwords has to pay that computation on every single attempt, which makes the attack slow and expensive.', 'login-armor' ); ?>
					</p>
					<p class="la-hide-disabled__desc">
						<?php esc_html_e( 'Everything runs on your own site: no external service, no account, no data sent anywhere. Enabling starts in monitor mode: submissions without a valid proof are counted but never blocked, so you can verify real users are unaffected before enforcing. Note: login flows without JavaScript (or custom login plugins) cannot solve the challenge; monitor mode will reveal them.', 'login-armor' ); ?>
					</p>
				</div>
				<div class="la-hide-disabled__actions">
					<button type="button" class="la-btn la-btn--primary la-btn--amber" data-la-action="pow-enable">
						<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="width:16px;height:16px;margin-right:6px;">
							<rect x="4" y="4" width="16" height="16" rx="2"/>
							<rect x="9" y="9" width="6" height="6"/>
						</svg>
						<?php esc_html_e( 'Enable Bot Challenge (monitor mode)', 'login-armor' ); ?>
					</button>
				</div>
			</div>
		</div>

	<?php else : ?>

		<div class="la-card-body">
			<div data-la-pow-form>

				<?php if ( $la_pow_enabled && $la_pow_mode !== $la_pow_effective ) : ?>
					<div class="la-danger-note" data-la-pow-safe-mode>
						<?php \LoginArmor\Icons::render( 'alert-triangle', '', 14 ); ?>
						<span>
							<strong><?php esc_html_e( 'Safe mode is active.', 'login-armor' ); ?></strong>
							<?php esc_html_e( 'This module is only logging right now, whatever the mode selected below. Your setting is untouched and comes back the moment you remove LOGIN_ARMOR_SAFE_MODE from wp-config.php.', 'login-armor' ); ?>
						</span>
					</div>
				<?php endif; ?>

				<?php if ( $la_pow_softfails > 0 ) : ?>
					<p class="la-field__desc" style="margin-top:0;">
						<strong><?php echo esc_html( (string) $la_pow_softfails ); ?></strong>
						<?php esc_html_e( 'login submissions without a valid proof in the current 7-day window.', 'login-armor' ); ?>
						<?php if ( 'log_only' === $la_pow_mode ) : ?>
							<?php esc_html_e( '(Monitor mode: these were counted, not blocked.)', 'login-armor' ); ?>
						<?php endif; ?>
					</p>
				<?php else : ?>
					<p class="la-field__desc" style="margin-top:0;">
						<?php esc_html_e( 'No login submission without a valid proof in the current 7-day window.', 'login-armor' ); ?>
					</p>
				<?php endif; ?>

				<?php
				/*
				 * 2.7.0: the deterministic half of the "switch to Enforce"
				 * nudge. The Overview advice only renders in the all-quiet
				 * state, and a monitor-mode soft failure opens an ACTIVE
				 * incident, so the very sites with something to report are the
				 * ones that never see it there. This banner has no such
				 * condition: it appears on the module's own screen, right
				 * above the mode selector it is talking about.
				 */
				$la_pow_monitor_days = $la_pow_class ? \LoginArmor\PowChallenge::monitoring_days() : 0;
				if ( $la_pow_monitor_days >= \LoginArmor\Overview::ENFORCE_ADVICE_MIN_DAYS ) :
					?>
					<div class="la-enforce-hint">
						<?php
						/*
						 * Two sentences, two plurals: see the same block in
						 * sections/firewall.php.
						 */
						printf(
							esc_html(
								/* translators: %d: number of days in monitor mode. */
								_n( 'Monitoring for %d day.', 'Monitoring for %d days.', (int) $la_pow_monitor_days, 'login-armor' )
							),
							(int) $la_pow_monitor_days
						);
						echo ' ';
						printf(
							esc_html(
								/* translators: %d: number of submissions without a valid proof over the last 7 days. */
								_n(
									'%d match over the last week: switch to Enforce below to start rejecting instead of only counting.',
									'%d matches over the last week: switch to Enforce below to start rejecting instead of only counting.',
									(int) $la_pow_softfails,
									'login-armor'
								)
							),
							(int) $la_pow_softfails
						);
						?>
					</div>
				<?php endif; ?>

				<!-- Mode -->
				<div class="la-field">
					<h4 class="la-field__label"><?php esc_html_e( 'Mode', 'login-armor' ); ?></h4>
					<p class="la-field__desc">
						<?php esc_html_e( 'Start in Monitor to confirm your real users pass the challenge. Switch to Enforce once the counter above stays at bot-only levels.', 'login-armor' ); ?>
					</p>
					<div class="la-radio-grid">
						<label class="la-radio-opt <?php echo 'log_only' === $la_pow_mode ? 'la-radio-opt--active' : ''; ?>">
							<div class="la-radio-opt__top">
								<input type="radio" name="pow_mode" value="log_only" <?php checked( $la_pow_mode, 'log_only' ); ?> />
								<span class="la-radio-opt__title"><?php esc_html_e( 'Monitor', 'login-armor' ); ?></span>
								<span class="la-radio-opt__tag"><?php esc_html_e( 'Recommended', 'login-armor' ); ?></span>
							</div>
							<p class="la-radio-opt__desc">
								<?php esc_html_e( 'Counts submissions without a valid proof without blocking anything. Zero risk of locking out a real user.', 'login-armor' ); ?>
							</p>
						</label>
						<label class="la-radio-opt <?php echo 'enforce' === $la_pow_mode ? 'la-radio-opt--active' : ''; ?>">
							<div class="la-radio-opt__top">
								<input type="radio" name="pow_mode" value="enforce" <?php checked( $la_pow_mode, 'enforce' ); ?> />
								<span class="la-radio-opt__title"><?php esc_html_e( 'Enforce', 'login-armor' ); ?></span>
							</div>
							<p class="la-radio-opt__desc">
								<?php esc_html_e( 'Rejects logins without a valid proof, even with correct credentials. Requires JavaScript on the login page.', 'login-armor' ); ?>
							</p>
						</label>
					</div>
				</div>

				<div class="la-inner-sep"></div>

				<!-- Difficulty -->
				<div class="la-field">
					<h4 class="la-field__label"><?php esc_html_e( 'Difficulty', 'login-armor' ); ?></h4>
					<p class="la-field__desc">
						<?php esc_html_e( 'How much computation each login costs the sender. Higher hurts botnets more but takes slightly longer on very old devices. Standard suits almost every site.', 'login-armor' ); ?>
					</p>
					<div class="la-radio-grid">
						<label class="la-radio-opt <?php echo 'low' === $la_pow_difficulty ? 'la-radio-opt--active' : ''; ?>">
							<div class="la-radio-opt__top">
								<input type="radio" name="pow_difficulty" value="low" <?php checked( $la_pow_difficulty, 'low' ); ?> />
								<span class="la-radio-opt__title"><?php esc_html_e( 'Low', 'login-armor' ); ?></span>
							</div>
							<p class="la-radio-opt__desc">
								<?php esc_html_e( 'Lightest cost. For sites with visitors on very old phones or computers.', 'login-armor' ); ?>
							</p>
						</label>
						<label class="la-radio-opt <?php echo 'standard' === $la_pow_difficulty ? 'la-radio-opt--active' : ''; ?>">
							<div class="la-radio-opt__top">
								<input type="radio" name="pow_difficulty" value="standard" <?php checked( $la_pow_difficulty, 'standard' ); ?> />
								<span class="la-radio-opt__title"><?php esc_html_e( 'Standard', 'login-armor' ); ?></span>
								<span class="la-radio-opt__tag"><?php esc_html_e( 'Recommended', 'login-armor' ); ?></span>
							</div>
							<p class="la-radio-opt__desc">
								<?php esc_html_e( 'A fraction of a second in any modern browser. The right balance for almost every site.', 'login-armor' ); ?>
							</p>
						</label>
						<label class="la-radio-opt <?php echo 'high' === $la_pow_difficulty ? 'la-radio-opt--active' : ''; ?>">
							<div class="la-radio-opt__top">
								<input type="radio" name="pow_difficulty" value="high" <?php checked( $la_pow_difficulty, 'high' ); ?> />
								<span class="la-radio-opt__title"><?php esc_html_e( 'High', 'login-armor' ); ?></span>
							</div>
							<p class="la-radio-opt__desc">
								<?php esc_html_e( 'Maximum cost for attackers. May take a second or two on older devices.', 'login-armor' ); ?>
							</p>
						</label>
					</div>
				</div>

			</div>
		</div>

	<?php endif; ?>
</section>
