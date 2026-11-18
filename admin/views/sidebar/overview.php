<?php
/**
 * Sidebar content for the Overview tab.
 *
 * Native <details>/<summary> accordion: see `settings.php` for the rationale.
 *
 * @package LoginArmor
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}
?>
<h3 class="la-sidebar__title"><?php esc_html_e( 'About this view', 'login-armor' ); ?></h3>

<details class="la-sidebar__section">
	<summary class="la-sidebar__section-title"><?php esc_html_e( 'Attacks Neutralized', 'login-armor' ); ?></summary>
	<p class="la-sidebar__text"><?php esc_html_e( 'Total number of login attempts blocked by brute force protection or IP lockouts.', 'login-armor' ); ?></p>
</details>

<details class="la-sidebar__section">
	<summary class="la-sidebar__section-title"><?php esc_html_e( 'Health Cards', 'login-armor' ); ?></summary>
	<p class="la-sidebar__text"><?php esc_html_e( 'Each card represents a security module. Click any card to jump to its settings.', 'login-armor' ); ?></p>
	<ul class="la-sidebar__list">
		<li><strong><?php esc_html_e( 'Hide Login', 'login-armor' ); ?></strong>: <?php esc_html_e( 'conceals wp-login.php behind a secret URL.', 'login-armor' ); ?></li>
		<li><strong><?php esc_html_e( 'Brute Force', 'login-armor' ); ?></strong>: <?php esc_html_e( 'locks out IPs after repeated failures.', 'login-armor' ); ?></li>
		<li><strong><?php esc_html_e( 'Hardening', 'login-armor' ); ?></strong>: <?php esc_html_e( 'one-click security toggles.', 'login-armor' ); ?></li>
		<li><strong><?php esc_html_e( 'Detection', 'login-armor' ); ?></strong>: <?php esc_html_e( 'identifies attack patterns automatically.', 'login-armor' ); ?></li>
		<li><strong><?php esc_html_e( 'Activity', 'login-armor' ); ?></strong>: <?php esc_html_e( 'tracks admin actions across users, posts, plugins, and options.', 'login-armor' ); ?></li>
		<li><strong><?php esc_html_e( '2FA', 'login-armor' ); ?></strong>: <?php esc_html_e( 'adds a second factor (TOTP, email, backup codes) to the login flow.', 'login-armor' ); ?></li>
		<li><strong><?php esc_html_e( 'Login Headers', 'login-armor' ); ?></strong>: <?php esc_html_e( 'HTTP security headers scoped to the login page (CSP, X-Frame-Options).', 'login-armor' ); ?></li>
		<li><strong><?php esc_html_e( 'Breach Check', 'login-armor' ); ?></strong>: <?php esc_html_e( 'detects user passwords and emails that appear in public data leaks, using privacy-preserving lookups (k-anonymity).', 'login-armor' ); ?></li>
			<li><strong><?php esc_html_e( 'Password Policy', 'login-armor' ); ?></strong> &mdash; <?php esc_html_e( 'enforces strong, unique passwords and blocks breached ones.', 'login-armor' ); ?></li>
			<li><strong><?php esc_html_e( 'Session Management', 'login-armor' ); ?></strong> &mdash; <?php esc_html_e( 'idle timeout, maximum session lifetime, single-device login.', 'login-armor' ); ?></li>
	</ul>
</details>

<details class="la-sidebar__section">
	<summary class="la-sidebar__section-title"><?php esc_html_e( 'Activity Chart', 'login-armor' ); ?></summary>
	<p class="la-sidebar__text"><?php esc_html_e( 'Login activity over the past 7 days. Spikes may indicate ongoing attacks.', 'login-armor' ); ?></p>
</details>

<details class="la-sidebar__section">
	<summary class="la-sidebar__section-title"><?php esc_html_e( 'Live Events', 'login-armor' ); ?></summary>
	<p class="la-sidebar__text"><?php esc_html_e( 'Most recent login attempts in real time. Red entries are failed or locked-out attempts.', 'login-armor' ); ?></p>
</details>
