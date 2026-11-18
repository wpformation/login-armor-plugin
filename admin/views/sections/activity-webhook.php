<?php
/**
 * Activity Webhook Forwarding section: Settings tab.
 *
 * @package LoginArmor
 *
 * @var bool   $la_webhook_enabled  Whether webhook forwarding is on.
 * @var string $la_webhook_url      Configured HTTPS endpoint.
 * @var string $la_webhook_secret   64-hex shared secret.
 * @var array  $la_webhook_stats    Keys: queued, sent, dead.
 */

// phpcs:disable WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}
?>
<section class="la-card la-card--section" id="la-section-activity-webhook" data-la-section="activity-webhook">
	<header class="la-card-header">
		<div class="la-card-header__left">
			<div class="la-card-icon">
				<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
					<polyline points="16 12 22 6 22 18 16 12"/>
					<rect x="2" y="3" width="14" height="18" rx="2"/>
				</svg>
			</div>
			<div>
				<h2 class="la-card-title">
					<?php esc_html_e( 'Activity Webhook Forwarding', 'login-armor' ); ?>
					<?php if ( $la_webhook_enabled ) : ?>
						<span class="la-status-pill la-status-pill--on"><?php esc_html_e( 'ACTIVE', 'login-armor' ); ?></span>
					<?php else : ?>
						<span class="la-status-pill la-status-pill--off"><?php esc_html_e( 'DISABLED', 'login-armor' ); ?></span>
					<?php endif; ?>
				</h2>
				<p class="la-card-subtitle">
					<?php esc_html_e( 'Push every admin action (user creation, plugin install, config change, login, etc.) to an external service in real time. Useful for off-site backup of the audit log (so an attacker who tampers with the database cannot also erase their tracks), instant alerts on sensitive events, or centralizing logs from multiple sites. Compatible with Slack, Discord, Datadog, Splunk, any SIEM, or any custom HTTPS receiver.', 'login-armor' ); ?>
				</p>
			</div>
		</div>
	</header>

	<div class="la-card-sep"></div>

	<div class="la-card-body">
		<div data-la-webhook-form>

			<div class="la-webhook-toprow">
				<div class="la-toggle-row">
					<?php // 2.8.0: the switch is named by the sentence beside it: its <label> holds no text. ?>
					<label class="la-toggle">
						<input type="checkbox" name="webhook_enabled" value="1" <?php checked( $la_webhook_enabled ); ?> aria-labelledby="la-lbl-webhook-enabled" />
						<span class="la-toggle__track"></span>
					</label>
					<span class="la-toggle-row__label" id="la-lbl-webhook-enabled"><?php esc_html_e( 'Enable webhook forwarding', 'login-armor' ); ?></span>
				</div>
				<ul class="la-webhook-stats" title="<?php esc_attr_e( 'Queue stats over the last 7 days.', 'login-armor' ); ?>">
					<li><strong><?php echo (int) ( $la_webhook_stats['queued'] ?? 0 ); ?></strong> <?php esc_html_e( 'queued', 'login-armor' ); ?></li>
					<li><strong><?php echo (int) ( $la_webhook_stats['sent'] ?? 0 ); ?></strong> <?php esc_html_e( 'sent', 'login-armor' ); ?></li>
					<li><strong><?php echo (int) ( $la_webhook_stats['dead'] ?? 0 ); ?></strong> <?php esc_html_e( 'dead', 'login-armor' ); ?></li>
				</ul>
			</div>

			<div class="la-inner-sep"></div>

			<div class="la-field la-field--bounded">
				<?php // 2.8.0: the two fields below are named by their heading (aria-labelledby). ?>
				<h4 class="la-field__label" id="la-lbl-webhook-url"><?php esc_html_e( 'Webhook URL', 'login-armor' ); ?></h4>
				<p class="la-field__desc"><?php esc_html_e( 'Must be HTTPS. The receiver verifies signatures via the secret below.', 'login-armor' ); ?></p>
				<input
					type="url"
					class="la-input la-input--mono la-input--bounded"
					name="webhook_url"
					aria-labelledby="la-lbl-webhook-url"
					value="<?php echo esc_attr( $la_webhook_url ); ?>"
					placeholder="https://siem.example.com/loginarmor"
					pattern="https://.*"
				/>
			</div>

			<div class="la-inner-sep"></div>

			<div class="la-field la-field--bounded">
				<h4 class="la-field__label" id="la-lbl-webhook-secret"><?php esc_html_e( 'Shared Secret', 'login-armor' ); ?></h4>
				<p class="la-field__desc"><?php esc_html_e( 'Configure this secret on your receiver to verify HMAC-SHA256 signatures via the X-LoginArmor-Signature header.', 'login-armor' ); ?></p>
				<div class="la-secret-row">
					<input
						type="text"
						class="la-input la-input--mono la-input--bounded"
						readonly
						data-la-webhook-secret-display
						aria-labelledby="la-lbl-webhook-secret"
						value="<?php echo esc_attr( $la_webhook_secret ); ?>"
					/>
					<button type="button" class="la-btn la-btn--small" data-la-action="webhook-copy-secret"><?php esc_html_e( 'Copy', 'login-armor' ); ?></button>
					<button type="button" class="la-btn la-btn--small la-btn--danger" data-la-action="webhook-regenerate-secret"><?php esc_html_e( 'Regenerate', 'login-armor' ); ?></button>
				</div>
			</div>

			<div class="la-inner-sep"></div>

			<div class="la-field">
				<button type="button" class="la-btn la-btn--secondary" data-la-action="webhook-test">
					<?php esc_html_e( 'Send test event', 'login-armor' ); ?>
				</button>
				<span class="la-webhook-test-result" data-la-webhook-test-result style="margin-left:12px;color:#50575e;"></span>
			</div>

		</div>
	</div>
</section>
