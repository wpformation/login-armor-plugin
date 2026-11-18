<?php
/**
 * Sidebar content for the Events tab.
 *
 * Native <details>/<summary> accordion: see `settings.php` for the rationale.
 *
 * @package LoginArmor
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}
?>
<h3 class="la-sidebar__title"><?php esc_html_e( 'Event Log Guide', 'login-armor' ); ?></h3>

<details class="la-sidebar__section">
	<summary class="la-sidebar__section-title"><?php esc_html_e( 'What gets logged', 'login-armor' ); ?></summary>
	<p class="la-sidebar__text"><?php esc_html_e( 'Every login attempt is recorded with its outcome, IP address, and timestamp.', 'login-armor' ); ?></p>
</details>

<details class="la-sidebar__section">
	<summary class="la-sidebar__section-title"><?php esc_html_e( 'Status Codes', 'login-armor' ); ?></summary>
	<ul class="la-sidebar__list">
		<li><strong><?php esc_html_e( 'OK', 'login-armor' ); ?></strong>: <?php esc_html_e( 'successful login.', 'login-armor' ); ?></li>
		<li><strong><?php esc_html_e( 'FAIL', 'login-armor' ); ?></strong>: <?php esc_html_e( 'wrong username or password.', 'login-armor' ); ?></li>
		<li><strong><?php esc_html_e( 'BLOCKED', 'login-armor' ); ?></strong>: <?php esc_html_e( 'Auth blocked after too many failures.', 'login-armor' ); ?></li>
	</ul>
</details>

<details class="la-sidebar__section">
	<summary class="la-sidebar__section-title"><?php esc_html_e( 'Filtering & Export', 'login-armor' ); ?></summary>
	<p class="la-sidebar__text"><?php esc_html_e( 'Use the filters to narrow results by status, IP, or username. The export button downloads matching events as CSV.', 'login-armor' ); ?></p>
</details>

<details class="la-sidebar__section">
	<summary class="la-sidebar__section-title"><?php esc_html_e( 'Retention', 'login-armor' ); ?></summary>
	<p class="la-sidebar__text"><?php esc_html_e( 'Log retention and auto-purge settings can be configured in Settings > Detection & Logs.', 'login-armor' ); ?></p>
</details>
