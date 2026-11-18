<?php
/**
 * GeoIP section, Settings tab.
 *
 * Single opt-in toggle. When on, the IPs Login Armor already displays
 * (incidents, login events) are resolved to a country by a background task
 * and cached for 30 days. Nothing is looked up while a page is rendered.
 * Discloses the external service inline.
 *
 * @package LoginArmor
 *
 * @var bool $la_geoip_enabled Whether the module is on.
 */

// phpcs:disable WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}
?>
<section class="la-card la-card--section" id="la-section-geoip" data-la-section="geoip">
	<header class="la-card-header">
		<div class="la-card-header__left">
			<div class="la-card-icon">
				<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
					<circle cx="12" cy="12" r="10"/>
					<path d="M2 12h20"/>
					<path d="M12 2a15 15 0 0 1 0 20a15 15 0 0 1 0-20"/>
				</svg>
			</div>
			<div>
				<h2 class="la-card-title">
					<?php esc_html_e( 'IP Geolocation', 'login-armor' ); ?>
					<?php if ( $la_geoip_enabled ) : ?>
						<span class="la-status-pill la-status-pill--on"><?php esc_html_e( 'ACTIVE', 'login-armor' ); ?></span>
					<?php else : ?>
						<span class="la-status-pill la-status-pill--off"><?php esc_html_e( 'DISABLED', 'login-armor' ); ?></span>
					<?php endif; ?>
				</h2>
				<p class="la-card-subtitle">
					<?php if ( $la_geoip_enabled ) : ?>
						<?php esc_html_e( 'Attacking and login IPs are shown with their country of origin.', 'login-armor' ); ?>
					<?php else : ?>
						<?php esc_html_e( 'Show the country of origin next to the IP addresses in your incidents and events.', 'login-armor' ); ?>
					<?php endif; ?>
				</p>
			</div>
		</div>
		<?php if ( $la_geoip_enabled ) : ?>
			<button type="button" class="la-btn la-btn--danger la-btn--small" data-la-action="geoip-disable">
				<?php esc_html_e( 'Disable', 'login-armor' ); ?>
			</button>
		<?php endif; ?>
	</header>

	<div class="la-card-sep"></div>

	<?php if ( ! $la_geoip_enabled ) : ?>

		<div class="la-card-body">
			<div class="la-hide-disabled">
				<div class="la-hide-disabled__body">
					<p class="la-hide-disabled__desc">
						<?php esc_html_e( 'When enabled, the IP addresses Login Armor already shows you (failed logins, lockouts, incidents) are resolved to a country, so you can tell at a glance where attacks come from. The work happens in a background task, never while you are waiting for a page: an address gets its country within a few minutes of appearing, and each result is cached for 30 days. There is no impact on your visitors or on the login page.', 'login-armor' ); ?>
					</p>
					<p class="la-hide-disabled__desc">
						<strong><?php esc_html_e( 'External service:', 'login-armor' ); ?></strong>
						<?php esc_html_e( 'this feature sends public IP addresses recorded in the login log or in an incident to the keyless public geolocation API ipwho.is, which returns the country. No API key or account is required. Addresses are sent in a background task: at most 20 addresses every five minutes, no request is made while an admin page is being rendered, and there is no request at all for five minutes after an API failure. Private and reserved IP ranges are never sent. Developers can replace the source with an offline database via the login_armor_geoip_lookup filter to make zero external calls. See the External Services section of the plugin readme.', 'login-armor' ); ?>
					</p>
					<p class="la-hide-disabled__desc">
						<?php esc_html_e( 'The compromise: the background task is a WordPress scheduled event. On a site where WP-Cron is disabled and no system cron calls wp-cron.php, nothing resolves and the country badges stay empty.', 'login-armor' ); ?>
					</p>
				</div>
				<div class="la-hide-disabled__actions">
					<button type="button" class="la-btn la-btn--primary la-btn--amber" data-la-action="geoip-enable">
						<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="width:16px;height:16px;margin-right:6px;">
							<circle cx="12" cy="12" r="10"/>
							<path d="M2 12h20"/>
						</svg>
						<?php esc_html_e( 'Enable IP Geolocation', 'login-armor' ); ?>
					</button>
				</div>
			</div>
		</div>

	<?php else : ?>

		<div class="la-card-body">
			<div class="la-field">
				<p class="la-field__desc">
					<?php esc_html_e( 'Geolocation is active. Country codes appear next to IP addresses on the Incidents and Events tabs, filled in by a background task within a few minutes of an address appearing. Results are cached for 30 days.', 'login-armor' ); ?>
				</p>
				<p class="la-field__desc">
					<strong><?php esc_html_e( 'External service:', 'login-armor' ); ?></strong>
					<?php esc_html_e( 'public IP addresses recorded in the login log or in an incident are sent to the keyless public API ipwho.is to obtain a country, in a background task: at most 20 addresses every five minutes, no request is made while an admin page is being rendered, and there is no request at all for five minutes after an API failure. Private and reserved ranges are never sent. The compromise: the background task is a WordPress scheduled event, so on a site where WP-Cron is disabled and no system cron calls wp-cron.php, the badges stay empty. Disclosed in the plugin readme under External Services.', 'login-armor' ); ?>
				</p>
			</div>
		</div>

	<?php endif; ?>
</section>
