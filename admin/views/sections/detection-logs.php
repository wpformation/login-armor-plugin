<?php
/**
 * Detection & Logs section: Settings tab.
 *
 * When disabled, shows a CTA to enable detection & logging.
 * When enabled, shows log retention, auto-purge toggle, and manual purge.
 *
 * @package LoginArmor
 *
 * @var bool $la_detection_enabled Whether detection & logging is on.
 * @var int  $la_retention_days    Log retention period in days.
 * @var bool $la_auto_purge        Whether auto-purge cron is enabled.
 */

// phpcs:disable WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}
?>
<section class="la-card la-card--section" id="la-section-detection-logs" data-la-section="detection-logs">
	<header class="la-card-header">
		<div class="la-card-header__left">
			<div class="la-card-icon">
				<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
					<path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/>
					<path d="M14 2v6h6"/>
					<line x1="16" y1="13" x2="8" y2="13"/>
					<line x1="16" y1="17" x2="8" y2="17"/>
				</svg>
			</div>
			<div>
				<h2 class="la-card-title">
					<?php esc_html_e( 'Detection & Logs', 'login-armor' ); ?>
					<?php if ( $la_detection_enabled ) : ?>
						<span class="la-status-pill la-status-pill--on"><?php esc_html_e( 'ACTIVE', 'login-armor' ); ?></span>
					<?php else : ?>
						<span class="la-status-pill la-status-pill--off"><?php esc_html_e( 'DISABLED', 'login-armor' ); ?></span>
					<?php endif; ?>
				</h2>
				<p class="la-card-subtitle">
					<?php if ( $la_detection_enabled ) : ?>
						<?php esc_html_e( 'Log retention and automatic cleanup.', 'login-armor' ); ?>
					<?php else : ?>
						<?php esc_html_e( 'Login attempt logging is currently disabled.', 'login-armor' ); ?>
					<?php endif; ?>
				</p>
			</div>
		</div>
		<?php if ( $la_detection_enabled ) : ?>
			<button type="button" class="la-btn la-btn--danger la-btn--small" data-la-action="detection-disable">
				<?php esc_html_e( 'Disable', 'login-armor' ); ?>
			</button>
		<?php endif; ?>
	</header>

	<div class="la-card-sep"></div>

	<?php if ( ! $la_detection_enabled ) : ?>

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
						<strong><?php esc_html_e( 'Detection & logging is disabled', 'login-armor' ); ?></strong>
						<span><?php esc_html_e( 'Login attempts are not being recorded. You will have no audit trail.', 'login-armor' ); ?></span>
					</div>
				</div>
				<div class="la-hide-disabled__body">
					<p class="la-hide-disabled__desc">
						<?php esc_html_e( 'When enabled, all login attempts are recorded and analyzed by the incident detection engine. This powers the Overview dashboard, Events tab, and Incidents tab.', 'login-armor' ); ?>
					</p>
				</div>
				<div class="la-hide-disabled__actions">
					<button type="button" class="la-btn la-btn--primary la-btn--amber" data-la-action="detection-enable">
						<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="width:16px;height:16px;margin-right:6px;">
							<path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/>
							<path d="M14 2v6h6"/>
						</svg>
						<?php esc_html_e( 'Enable Detection & Logs', 'login-armor' ); ?>
					</button>
				</div>
			</div>
		</div>

	<?php else : ?>

		<div class="la-card-body">
			<div data-la-detection-form>

				<!-- Field 1: Log Retention -->
				<div class="la-field">
					<h4 class="la-field__label"><?php esc_html_e( 'Log Retention', 'login-armor' ); ?></h4>
					<p class="la-field__desc"><?php esc_html_e( 'How long to keep login attempt logs and incident records.', 'login-armor' ); ?></p>

					<div class="la-bf-field">
						<?php // 2.8.0: named by the words on both sides of the number, as read on screen. ?>
						<span class="la-bf-field__label" id="la-lbl-retention-days"><?php esc_html_e( 'Keep logs for', 'login-armor' ); ?></span>
						<input
							type="number"
							class="la-bf-field__input"
							name="retention_days"
							aria-labelledby="la-lbl-retention-days la-lbl-retention-days-unit"
							value="<?php echo esc_attr( (string) $la_retention_days ); ?>"
							min="1"
							max="3650"
						/>
						<span class="la-bf-field__suffix" id="la-lbl-retention-days-unit"><?php esc_html_e( 'days', 'login-armor' ); ?></span>
					</div>
				</div>

				<div class="la-inner-sep"></div>

				<!-- Field 2: Auto-Purge -->
				<div class="la-field">
					<?php // 2.8.0: the switch is named by this heading: its <label> holds no text. ?>
					<h4 class="la-field__label" id="la-lbl-auto-purge"><?php esc_html_e( 'Auto-Purge', 'login-armor' ); ?></h4>
					<p class="la-field__desc"><?php esc_html_e( 'Automatically delete old logs via WP-Cron. Runs daily.', 'login-armor' ); ?></p>

					<label class="la-toggle">
						<input type="checkbox" name="auto_purge" value="1" <?php checked( $la_auto_purge ); ?> aria-labelledby="la-lbl-auto-purge">
						<span class="la-toggle__track"></span>
					</label>

					<p class="la-field__help"><?php esc_html_e( 'Logs older than the retention period will be automatically deleted every night at 3:00 AM (server time).', 'login-armor' ); ?></p>
				</div>

				<div class="la-inner-sep"></div>

				<!-- Field 3: Manual Purge -->
				<div class="la-field">
					<h4 class="la-field__label"><?php esc_html_e( 'Manual Purge', 'login-armor' ); ?></h4>
					<p class="la-field__desc"><?php esc_html_e( 'Immediately delete all logs older than the retention period.', 'login-armor' ); ?></p>

					<button type="button" class="la-btn la-btn--danger" data-la-action="detection-purge">
						<?php esc_html_e( 'Purge old logs now', 'login-armor' ); ?>
					</button>
				</div>

				<div class="la-inner-sep"></div>

				<!-- Field 4: Reset everything (2.0.1) -->
				<div class="la-field">
					<h4 class="la-field__label"><?php esc_html_e( 'Reset all statistics', 'login-armor' ); ?></h4>
					<p class="la-field__desc"><?php esc_html_e( 'Delete every event, brute-force counter, and incident regardless of age. All currently locked-out IPs are released. Use this for a fresh start, e.g. after a large attack wave or before a client demo.', 'login-armor' ); ?></p>

					<button type="button" class="la-btn la-btn--danger" data-la-action="detection-reset">
						<?php esc_html_e( 'Reset all events & incidents', 'login-armor' ); ?>
					</button>
				</div>

			</div>
		</div>

	<?php endif; ?>
</section>
