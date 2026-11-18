<?php
/**
 * Notifications section: Settings tab.
 *
 * When the channel is 'disabled', shows an amber warning + gold CTA to
 * enable. When a real channel is configured, shows the full form plus
 * a Disable button in the header. This mirrors the active/disabled
 * pattern used by every other module on the Settings screen.
 *
 * @package LoginArmor
 *
 * @var string $la_notif_channel      Active channel key (disabled, email, slack, discord, generic).
 * @var string $la_notif_webhook_url  Webhook URL or email address.
 * @var int    $la_notif_min_severity Minimum severity (1-4).
 * @var int    $la_notif_rate_limit   Max notifications per hour.
 * @var string $la_notif_digest       Scheduled digest period (off, weekly, monthly).
 * @var int    $la_notif_digest_last  Unix time of the last digest sent, 0 when none.
 * @var string $la_notif_digest_to    The digest's own recipient, '' when none (2.10.0).
 */

// phpcs:disable WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

$la_notif_disabled = ( 'disabled' === $la_notif_channel );

$la_notif_suppressed = class_exists( '\\LoginArmor\\Notifications\\Dispatcher' )
	? \LoginArmor\Notifications\Dispatcher::get_suppressed()
	: array( 'hour' => gmdate( 'YmdH' ), 'count' => 0, 'max_severity' => 0, 'last_pattern' => '', 'raw' => '' );

$la_last_error = get_option( 'login_armor_last_notif_error', [] );
$la_has_error  = is_array( $la_last_error )
	&& isset( $la_last_error['timestamp'] )
	&& ( time() - (int) $la_last_error['timestamp'] ) < DAY_IN_SECONDS;
?>
<section class="la-card la-card--section" id="la-section-notifications" data-la-section="notifications">
	<header class="la-card-header">
		<div class="la-card-header__left">
			<div class="la-card-icon">
				<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
					<path d="M18 8A6 6 0 006 8c0 7-3 9-3 9h18s-3-2-3-9"/>
					<path d="M13.73 21a2 2 0 01-3.46 0"/>
				</svg>
			</div>
			<div>
				<h2 class="la-card-title">
					<?php esc_html_e( 'Notifications', 'login-armor' ); ?>
					<?php if ( ! $la_notif_disabled ) : ?>
						<span class="la-status-pill la-status-pill--on"><?php echo esc_html( strtoupper( $la_notif_channel ) ); ?></span>
					<?php else : ?>
						<span class="la-status-pill la-status-pill--off"><?php esc_html_e( 'DISABLED', 'login-armor' ); ?></span>
					<?php endif; ?>
				</h2>
				<p class="la-card-subtitle">
					<?php if ( ! $la_notif_disabled ) : ?>
						<?php esc_html_e( 'Receive alerts when security incidents are detected.', 'login-armor' ); ?>
					<?php else : ?>
						<?php esc_html_e( 'Security alerts are silent. Critical incidents will not reach you.', 'login-armor' ); ?>
					<?php endif; ?>
				</p>
			</div>
		</div>
		<?php if ( ! $la_notif_disabled ) : ?>
			<button type="button" class="la-btn la-btn--danger la-btn--small" data-la-action="notifications-disable">
				<?php esc_html_e( 'Disable', 'login-armor' ); ?>
			</button>
		<?php endif; ?>
	</header>

	<div class="la-card-sep"></div>

	<?php if ( $la_notif_disabled ) : ?>

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
						<strong><?php esc_html_e( 'Notifications are disabled', 'login-armor' ); ?></strong>
						<span><?php esc_html_e( 'Brute force attacks, lockouts, and detected incidents trigger no alert. You only find out when you open the dashboard.', 'login-armor' ); ?></span>
					</div>
				</div>
				<div class="la-hide-disabled__body">
					<p class="la-hide-disabled__desc">
						<?php esc_html_e( 'When enabled, LoginArmor sends an alert to the channel of your choice (email, Slack, Discord, or a generic JSON webhook) as soon as an incident crosses your severity threshold.', 'login-armor' ); ?>
					</p>
				</div>
				<div class="la-hide-disabled__actions">
					<button type="button" class="la-btn la-btn--primary la-btn--amber" data-la-action="notifications-enable">
						<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="width:16px;height:16px;margin-right:6px;">
							<path d="M18 8A6 6 0 006 8c0 7-3 9-3 9h18s-3-2-3-9"/>
							<path d="M13.73 21a2 2 0 01-3.46 0"/>
						</svg>
						<?php esc_html_e( 'Enable Notifications', 'login-armor' ); ?>
					</button>
				</div>
			</div>
		</div>

	<?php else : ?>

		<div class="la-card-body">
			<div data-la-notifications-form>

				<!-- Field 1: Notification Channel -->
				<div class="la-field">
					<?php // 2.8.0: the controls below are named by their heading (aria-labelledby): none had an accessible name. ?>
					<h4 class="la-field__label" id="la-lbl-notif-channel"><?php esc_html_e( 'Notification Channel', 'login-armor' ); ?></h4>
					<p class="la-field__desc"><?php esc_html_e( 'Where incident alerts should be delivered.', 'login-armor' ); ?></p>
					<select class="la-select" name="notif_channel" data-la-notif-channel-select aria-labelledby="la-lbl-notif-channel">
						<option value="email" <?php selected( $la_notif_channel, 'email' ); ?>><?php esc_html_e( 'Email', 'login-armor' ); ?></option>
						<option value="slack" <?php selected( $la_notif_channel, 'slack' ); ?>>Slack</option>
						<option value="discord" <?php selected( $la_notif_channel, 'discord' ); ?>>Discord</option>
						<option value="generic" <?php selected( $la_notif_channel, 'generic' ); ?>><?php esc_html_e( 'Generic JSON', 'login-armor' ); ?></option>
					</select>
				</div>

				<div class="la-inner-sep"></div>

				<!-- Field 2a: Email address (visible when channel = email) -->
				<div class="la-field" data-la-notif-field data-la-notif-email-field>
					<h4 class="la-field__label" id="la-lbl-notif-email-to"><?php esc_html_e( 'Recipient Email', 'login-armor' ); ?></h4>
					<p class="la-field__desc">
						<?php
						printf(
							/* translators: %s: admin email address */
							esc_html__( 'Leave empty to use the site admin email (%s).', 'login-armor' ),
							esc_html( get_option( 'admin_email', '' ) )
						);
						?>
					</p>
					<input type="email" class="la-input la-input--wide" name="notif_email_to" aria-labelledby="la-lbl-notif-email-to"
						value="<?php echo esc_attr( 'email' === $la_notif_channel ? $la_notif_webhook_url : '' ); ?>"
						placeholder="<?php echo esc_attr( get_option( 'admin_email', '' ) ); ?>">
				</div>

				<!-- Field 2b: Webhook URL (visible when channel = slack/discord/generic) -->
				<div class="la-field" data-la-notif-field data-la-notif-webhook-field>
					<h4 class="la-field__label" id="la-lbl-notif-webhook-url"><?php esc_html_e( 'Webhook URL', 'login-armor' ); ?></h4>
					<p class="la-field__desc"><?php esc_html_e( 'Paste your Slack, Discord, or custom webhook URL.', 'login-armor' ); ?></p>
					<input type="url" class="la-input la-input--wide" name="notif_webhook_url" aria-labelledby="la-lbl-notif-webhook-url"
						value="<?php echo esc_attr( 'email' !== $la_notif_channel ? $la_notif_webhook_url : '' ); ?>"
						placeholder="https://">
				</div>

				<div class="la-inner-sep"></div>

				<!-- Field 3: Minimum Severity -->
				<div class="la-field" data-la-notif-field>
					<h4 class="la-field__label" id="la-lbl-notif-min-severity"><?php esc_html_e( 'Minimum Severity', 'login-armor' ); ?></h4>
					<p class="la-field__desc"><?php esc_html_e( 'Only incidents at this severity or higher will trigger a notification.', 'login-armor' ); ?></p>
					<select class="la-select" name="notif_min_severity" aria-labelledby="la-lbl-notif-min-severity">
						<option value="1" <?php selected( $la_notif_min_severity, 1 ); ?>><?php esc_html_e( 'Low', 'login-armor' ); ?></option>
						<option value="2" <?php selected( $la_notif_min_severity, 2 ); ?>><?php esc_html_e( 'Medium', 'login-armor' ); ?></option>
						<option value="3" <?php selected( $la_notif_min_severity, 3 ); ?>><?php esc_html_e( 'High', 'login-armor' ); ?></option>
						<option value="4" <?php selected( $la_notif_min_severity, 4 ); ?>><?php esc_html_e( 'Critical', 'login-armor' ); ?></option>
					</select>
				</div>

				<div class="la-inner-sep"></div>

				<!-- Field 4: Rate Limit -->
				<div class="la-field" data-la-notif-field>
					<h4 class="la-field__label" id="la-lbl-notif-rate-limit"><?php esc_html_e( 'Rate Limit', 'login-armor' ); ?></h4>
					<p class="la-field__desc"><?php esc_html_e( 'Maximum notifications per hour. Set to 0 for unlimited.', 'login-armor' ); ?></p>
					<div class="la-bf-field">
						<input type="number" class="la-bf-field__input" name="notif_rate_limit" aria-labelledby="la-lbl-notif-rate-limit la-lbl-notif-rate-limit-unit"
							value="<?php echo esc_attr( $la_notif_rate_limit ); ?>"
							min="0" max="100">
						<span class="la-bf-field__suffix" id="la-lbl-notif-rate-limit-unit"><?php esc_html_e( 'per hour', 'login-armor' ); ?></span>
					</div>
				</div>

				<div class="la-inner-sep"></div>

				<!-- Field 5: Scheduled digest (2.7.0) -->
				<div class="la-field" data-la-notif-field>
					<h4 class="la-field__label" id="la-lbl-notif-digest"><?php esc_html_e( 'Scheduled digest', 'login-armor' ); ?></h4>
					<p class="la-field__desc">
						<?php esc_html_e( 'A summary of the period through the channel above, whether or not anything happened. Alerts are silent on a quiet site, which is exactly the site nobody checks. It carries no IP address.', 'login-armor' ); ?>
					</p>
					<select class="la-select" name="notif_digest" aria-labelledby="la-lbl-notif-digest">
						<option value="off" <?php selected( $la_notif_digest, 'off' ); ?>><?php esc_html_e( 'Off', 'login-armor' ); ?></option>
						<option value="weekly" <?php selected( $la_notif_digest, 'weekly' ); ?>><?php esc_html_e( 'Weekly', 'login-armor' ); ?></option>
						<option value="monthly" <?php selected( $la_notif_digest, 'monthly' ); ?>><?php esc_html_e( 'Monthly', 'login-armor' ); ?></option>
					</select>
					<?php if ( $la_notif_digest_last > 0 ) : ?>
						<p class="la-field__desc">
							<?php
							printf(
								/* translators: %s: human-readable elapsed time, e.g. "6 days". */
								esc_html__( 'Last sent: %s ago.', 'login-armor' ),
								esc_html( human_time_diff( $la_notif_digest_last ) )
							);
							?>
						</p>
					<?php endif; ?>
				</div>

				<!-- Field 6: Digest recipient (2.10.0) -->
				<div class="la-field" data-la-notif-field>
					<h4 class="la-field__label"><label for="la-notif-digest-to"><?php esc_html_e( 'Send the digest to', 'login-armor' ); ?></label></h4>
					<p class="la-field__desc">
						<?php esc_html_e( 'Optional. An e-mail address that receives the digest whatever the alert channel above, even when alerts are off: the digest alone, no incident mail. Empty, the digest goes through the alert channel.', 'login-armor' ); ?>
					</p>
					<input type="email" class="la-input" id="la-notif-digest-to" name="notif_digest_to" value="<?php echo esc_attr( $la_notif_digest_to ); ?>" placeholder="security@example.com" autocomplete="off" />
				</div>

				<div class="la-inner-sep"></div>

				<!-- Test Button -->
				<div class="la-field" data-la-notif-field>
					<button type="button" class="la-btn la-btn--ghost" data-la-action="notif-test">
						<?php esc_html_e( 'Send test notification', 'login-armor' ); ?>
					</button>
					<span class="la-notif-test-result" data-la-notif-test-result></span>
				</div>

				<?php if ( $la_notif_suppressed['count'] > 0 ) : ?>
					<div class="la-inner-sep"></div>
					<div class="la-field">
						<p class="la-field__desc">
							<?php
							printf(
								/* translators: 1: number of alerts not sent, 2: start of the hour in UTC, e.g. 13:00 UTC. */
								esc_html__( 'Hourly cap: %1$d alerts were not sent since %2$s. The next alert that goes out will say so, and clear this counter.', 'login-armor' ),
								(int) $la_notif_suppressed['count'],
								esc_html( \LoginArmor\Notifications\Dispatcher::suppressed_since_label( (string) $la_notif_suppressed['hour'] ) . ' UTC' )
							);
							?>
						</p>
					</div>
				<?php endif; ?>

				<?php if ( $la_has_error ) : ?>
					<div class="la-inner-sep"></div>
					<div class="la-field">
						<div class="la-notif-error">
							<span class="la-notif-error__icon">&#9888;</span>
							<span class="la-notif-error__text">
								<?php
								printf(
									/* translators: 1: Error message, 2: Human-readable time diff. */
									esc_html__( 'Last error: %1$s (%2$s ago)', 'login-armor' ),
									esc_html( $la_last_error['message'] ?? '' ),
									esc_html( human_time_diff( (int) $la_last_error['timestamp'] ) )
								);
								?>
							</span>
						</div>
					</div>
				<?php endif; ?>

			</div>
		</div>

	<?php endif; ?>
</section>
