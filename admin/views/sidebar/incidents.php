<?php
/**
 * Sidebar content for the Incidents tab.
 *
 * Native <details>/<summary> accordion: see `settings.php` for the rationale.
 *
 * @package LoginArmor
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}
?>
<h3 class="la-sidebar__title"><?php esc_html_e( 'Understanding Incidents', 'login-armor' ); ?></h3>

<details class="la-sidebar__section">
	<summary class="la-sidebar__section-title"><?php esc_html_e( 'How it works', 'login-armor' ); ?></summary>
	<p class="la-sidebar__text"><?php esc_html_e( 'Login Armor automatically groups suspicious login attempts into incidents using pattern detection.', 'login-armor' ); ?></p>
</details>

<details class="la-sidebar__section">
	<summary class="la-sidebar__section-title"><?php esc_html_e( 'Severity Levels', 'login-armor' ); ?></summary>
	<ul class="la-sidebar__list">
		<li><strong><?php esc_html_e( 'Critical', 'login-armor' ); ?></strong>: <?php esc_html_e( 'active attack, immediate attention.', 'login-armor' ); ?></li>
		<li><strong><?php esc_html_e( 'High', 'login-armor' ); ?></strong>: <?php esc_html_e( 'significant threat, review recommended.', 'login-armor' ); ?></li>
		<li><strong><?php esc_html_e( 'Medium', 'login-armor' ); ?></strong>: <?php esc_html_e( 'moderate activity worth monitoring.', 'login-armor' ); ?></li>
		<li><strong><?php esc_html_e( 'Low', 'login-armor' ); ?></strong>: <?php esc_html_e( 'minor or isolated event.', 'login-armor' ); ?></li>
	</ul>
</details>

<details class="la-sidebar__section">
	<summary class="la-sidebar__section-title"><?php esc_html_e( 'Actions', 'login-armor' ); ?></summary>
	<ul class="la-sidebar__list">
		<li><strong><?php esc_html_e( 'Resolve', 'login-armor' ); ?></strong>: <?php esc_html_e( 'mark as handled.', 'login-armor' ); ?></li>
		<li><strong><?php esc_html_e( 'Ignore', 'login-armor' ); ?></strong>: <?php esc_html_e( 'dismiss as false positive.', 'login-armor' ); ?></li>
		<li><strong><?php esc_html_e( 'Block Subnet', 'login-armor' ); ?></strong>: <?php esc_html_e( 'block the entire /24 subnet.', 'login-armor' ); ?></li>
	</ul>
</details>

<details class="la-sidebar__section">
	<summary class="la-sidebar__section-title"><?php esc_html_e( 'Tip', 'login-armor' ); ?></summary>
	<p class="la-sidebar__text"><?php esc_html_e( 'Click any incident row to see the full timeline, correlated events, and user agents involved.', 'login-armor' ); ?></p>
</details>
