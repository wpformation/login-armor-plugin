<?php
/**
 * Headless back end section, Settings tab (2.9.0).
 *
 * The mode keeps "Restrict REST API" and "Disable application passwords" off;
 * the lines under it say what Login Armor does and does not cover on a
 * headless back end. Application-password monitoring lives here too: it is
 * useful with or without the mode.
 *
 * @package LoginArmor
 *
 * @var bool $la_headless_on    Whether headless mode is on.
 * @var bool $la_app_watch_on   Whether application-password monitoring is on.
 * @var bool $la_fw_ua_on       Whether the firewall user-agent family is on.
 * @var bool $la_author_enum_on Whether "Prevent author enumeration" is on.
 */

// phpcs:disable WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}
?>
<section class="la-card la-card--section" id="la-section-headless" data-la-section="headless">
	<header class="la-card-header">
		<div class="la-card-header__left">
			<div class="la-card-icon">
				<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
					<rect x="3" y="4" width="18" height="12" rx="2"/>
					<path d="M8 20h8"/>
					<path d="M12 16v4"/>
				</svg>
			</div>
			<div>
				<h2 class="la-card-title">
					<?php esc_html_e( 'Headless back end', 'login-armor' ); ?>
					<?php if ( $la_headless_on ) : ?>
						<span class="la-status-pill la-status-pill--on"><?php esc_html_e( 'ACTIVE', 'login-armor' ); ?></span>
					<?php else : ?>
						<span class="la-status-pill la-status-pill--off"><?php esc_html_e( 'DISABLED', 'login-armor' ); ?></span>
					<?php endif; ?>
				</h2>
				<p class="la-card-subtitle">
					<?php esc_html_e( 'For a WordPress that serves its REST API to a separate front end (Next.js, Nuxt, Astro).', 'login-armor' ); ?>
				</p>
			</div>
		</div>
		<?php if ( $la_headless_on ) : ?>
			<button type="button" class="la-btn la-btn--danger la-btn--small" data-la-action="headless-disable">
				<?php esc_html_e( 'Disable', 'login-armor' ); ?>
			</button>
		<?php endif; ?>
	</header>

	<div class="la-card-sep"></div>

	<div class="la-card-body">
		<?php if ( ! $la_headless_on ) : ?>
			<div class="la-hide-disabled">
				<div class="la-hide-disabled__body">
					<p class="la-hide-disabled__desc">
						<?php esc_html_e( 'Headless mode keeps "Restrict REST API" and "Disable application passwords" off, from this screen, an import or WP-CLI: on a headless back end, the first closes the API your front end reads and the second refuses the passwords your scripts write with. Enabling it turns them off if they are on, and tells you so.', 'login-armor' ); ?>
					</p>
				</div>
				<div class="la-hide-disabled__actions">
					<button type="button" class="la-btn la-btn--primary la-btn--amber" data-la-action="headless-enable">
						<?php esc_html_e( 'Enable headless mode', 'login-armor' ); ?>
					</button>
				</div>
			</div>
		<?php else : ?>
			<p class="la-hide-disabled__desc">
				<?php esc_html_e( 'Restrict REST API and Disable application passwords are kept off.', 'login-armor' ); ?>
			</p>
		<?php endif; ?>

		<div class="la-hide-disabled__desc">
			<p>
				<strong><?php esc_html_e( 'The request firewall does not inspect the REST API.', 'login-armor' ); ?></strong>
				<?php esc_html_e( 'On a headless back end the API is protected by brute-force protection, two-factor authentication of the accounts, and the monitoring of application passwords below.', 'login-armor' ); ?>
			</p>
			<?php if ( $la_fw_ua_on ) : ?>
				<p>
					<?php esc_html_e( 'The firewall "Bad user agents" family is on: it blocks pages outside the REST API (feed, sitemap) requested by tools such as curl or python, uptime probes included.', 'login-armor' ); ?>
				</p>
			<?php endif; ?>
			<?php if ( $la_author_enum_on ) : ?>
				<p>
					<?php esc_html_e( '"Prevent author enumeration" is on: an anonymous front end no longer receives author names through _embed, because /wp/v2/users is closed to it.', 'login-armor' ); ?>
				</p>
			<?php endif; ?>
		</div>

		<div class="la-harden-row <?php echo $la_app_watch_on ? 'la-harden-row--on' : 'la-harden-row--off'; ?>">
			<div class="la-harden-row__text">
				<b id="la-lbl-app-watch"><?php esc_html_e( 'Monitor application passwords', 'login-armor' ); ?></b>
				<small id="la-desc-app-watch"><?php esc_html_e( 'Records which networks each application password is used from, and alerts you the first time one is used from a hosting provider it has never been used from. Works with or without headless mode.', 'login-armor' ); ?></small>
			</div>
			<label class="la-toggle">
				<input type="checkbox" value="1" data-la-app-watch <?php checked( $la_app_watch_on ); ?> aria-labelledby="la-lbl-app-watch" aria-describedby="la-desc-app-watch" />
				<span class="la-toggle__track"></span>
			</label>
		</div>
	</div>
</section>
