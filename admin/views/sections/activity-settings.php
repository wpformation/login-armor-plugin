<?php
/**
 * Activity Log section: Settings tab.
 *
 * When disabled, shows a CTA to enable activity logging.
 * When enabled, shows log retention and manual purge.
 *
 * @package LoginArmor
 *
 * @var bool $la_activity_enabled   Whether the Activity Log module is on.
 * @var int  $la_activity_retention Log retention period in days.
 */

// phpcs:disable WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}
?>
<section class="la-card la-card--section" id="la-section-activity-log" data-la-section="activity-log">
	<header class="la-card-header">
		<div class="la-card-header__left">
			<div class="la-card-icon">
				<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
					<polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/>
				</svg>
			</div>
			<div>
				<h2 class="la-card-title">
					<?php esc_html_e( 'Activity Log', 'login-armor' ); ?>
					<?php if ( $la_activity_enabled ) : ?>
						<span class="la-status-pill la-status-pill--on"><?php esc_html_e( 'ACTIVE', 'login-armor' ); ?></span>
					<?php else : ?>
						<span class="la-status-pill la-status-pill--off"><?php esc_html_e( 'DISABLED', 'login-armor' ); ?></span>
					<?php endif; ?>
				</h2>
				<p class="la-card-subtitle">
					<?php if ( $la_activity_enabled ) : ?>
						<?php esc_html_e( 'Tracking admin actions across your site.', 'login-armor' ); ?>
					<?php else : ?>
						<?php esc_html_e( 'Admin action logging is currently disabled.', 'login-armor' ); ?>
					<?php endif; ?>
				</p>
			</div>
		</div>
		<?php if ( $la_activity_enabled ) : ?>
			<button type="button" class="la-btn la-btn--danger la-btn--small" data-la-action="activity-disable">
				<?php esc_html_e( 'Disable', 'login-armor' ); ?>
			</button>
		<?php endif; ?>
	</header>

	<div class="la-card-sep"></div>

	<?php if ( ! $la_activity_enabled ) : ?>

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
						<strong><?php esc_html_e( 'Activity logging is disabled', 'login-armor' ); ?></strong>
						<span><?php esc_html_e( 'Admin actions are not being recorded. You will have no audit trail of site changes.', 'login-armor' ); ?></span>
					</div>
				</div>
				<div class="la-hide-disabled__body">
					<p class="la-hide-disabled__desc">
						<?php esc_html_e( 'When enabled, key admin actions (user creation, plugin activation, settings changes, etc.) are recorded with the author, timestamp, and context.', 'login-armor' ); ?>
					</p>
				</div>
				<div class="la-hide-disabled__actions">
					<button type="button" class="la-btn la-btn--primary la-btn--amber" data-la-action="activity-enable">
						<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="width:16px;height:16px;margin-right:6px;">
							<polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/>
						</svg>
						<?php esc_html_e( 'Enable Activity Log', 'login-armor' ); ?>
					</button>
				</div>
			</div>
		</div>

	<?php else : ?>

		<div class="la-card-body">
			<div data-la-activity-form>

				<!-- Field 1: Log Retention -->
				<div class="la-field">
					<h4 class="la-field__label"><?php esc_html_e( 'Log Retention', 'login-armor' ); ?></h4>
					<p class="la-field__desc"><?php esc_html_e( 'How long to keep activity log records before automatic cleanup.', 'login-armor' ); ?></p>

					<div class="la-bf-field">
						<?php // 2.8.0: named by the words on both sides of the number, as read on screen. ?>
						<span class="la-bf-field__label" id="la-lbl-activity-retention"><?php esc_html_e( 'Keep logs for', 'login-armor' ); ?></span>
						<input
							type="number"
							class="la-bf-field__input"
							name="activity_retention"
							aria-labelledby="la-lbl-activity-retention la-lbl-activity-retention-unit"
							value="<?php echo esc_attr( (string) $la_activity_retention ); ?>"
							min="1"
							max="3650"
						/>
						<span class="la-bf-field__suffix" id="la-lbl-activity-retention-unit"><?php esc_html_e( 'days', 'login-armor' ); ?></span>
					</div>
				</div>

				<div class="la-inner-sep"></div>

				<!-- Field 2: Manual Purge -->
				<div class="la-field">
					<h4 class="la-field__label"><?php esc_html_e( 'Manual Purge', 'login-armor' ); ?></h4>
					<p class="la-field__desc"><?php esc_html_e( 'Immediately delete all activity logs older than the retention period.', 'login-armor' ); ?></p>

					<button type="button" class="la-btn la-btn--danger" data-la-action="activity-purge">
						<?php esc_html_e( 'Purge old activity logs now', 'login-armor' ); ?>
					</button>
				</div>

				<div class="la-inner-sep"></div>

				<!-- Field 3: Reset everything (2.0.1) -->
				<div class="la-field">
					<h4 class="la-field__label"><?php esc_html_e( 'Reset activity log', 'login-armor' ); ?></h4>
					<p class="la-field__desc"><?php esc_html_e( 'Delete every admin-action row regardless of age. Login events and incidents are not affected: they have their own reset in Detection & Logs.', 'login-armor' ); ?></p>

					<button type="button" class="la-btn la-btn--danger" data-la-action="activity-reset">
						<?php esc_html_e( 'Reset all activity entries', 'login-armor' ); ?>
					</button>
				</div>

			</div>
		</div>

	<?php endif; ?>
</section>
