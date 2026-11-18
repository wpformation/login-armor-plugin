<?php
/**
 * Sidebar content for the Activity tab.
 *
 * Native <details>/<summary> accordion: see `settings.php` for the rationale.
 *
 * @package LoginArmor
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}
?>
<h3 class="la-sidebar__title"><?php esc_html_e( 'Activity Log Guide', 'login-armor' ); ?></h3>

<details class="la-sidebar__section">
	<summary class="la-sidebar__section-title"><?php esc_html_e( 'What gets logged', 'login-armor' ); ?></summary>
	<ul class="la-sidebar__list">
		<li><strong><?php esc_html_e( 'Users', 'login-armor' ); ?></strong>: <?php esc_html_e( 'creation, deletion, role and email changes, password resets.', 'login-armor' ); ?></li>
		<li><strong><?php esc_html_e( 'Posts & Pages', 'login-armor' ); ?></strong>: <?php esc_html_e( 'created, edited, trashed, restored, permanently deleted.', 'login-armor' ); ?></li>
		<li><strong><?php esc_html_e( 'Media', 'login-armor' ); ?></strong>: <?php esc_html_e( 'uploads, edits, deletions.', 'login-armor' ); ?></li>
		<li><strong><?php esc_html_e( 'Plugins & Themes', 'login-armor' ); ?></strong>: <?php esc_html_e( 'installed, activated, deactivated, updated, deleted.', 'login-armor' ); ?></li>
		<li><strong><?php esc_html_e( 'Critical Options', 'login-armor' ); ?></strong>: <?php esc_html_e( 'site URL, admin email, registration, roles, permalink changes.', 'login-armor' ); ?></li>
	</ul>
</details>

<details class="la-sidebar__section">
	<summary class="la-sidebar__section-title"><?php esc_html_e( 'Reading the log', 'login-armor' ); ?></summary>
	<ul class="la-sidebar__list">
		<li><span class="la-badge la-badge--ok" style="font-size:11px">Created</span>: <?php esc_html_e( 'new content or resource.', 'login-armor' ); ?></li>
		<li><span class="la-badge la-badge--info" style="font-size:11px">Updated</span>: <?php esc_html_e( 'content or settings modified.', 'login-armor' ); ?></li>
		<li><span class="la-badge la-badge--warn" style="font-size:11px">Activated</span>: <?php esc_html_e( 'plugin/theme activated or restored.', 'login-armor' ); ?></li>
		<li><span class="la-badge la-badge--fail" style="font-size:11px">Deleted</span>: <?php esc_html_e( 'permanently removed.', 'login-armor' ); ?></li>
	</ul>
</details>

<details class="la-sidebar__section">
	<summary class="la-sidebar__section-title"><?php esc_html_e( 'When to worry', 'login-armor' ); ?></summary>
	<ul class="la-sidebar__list">
		<li><?php esc_html_e( 'Mass deletions in a short timeframe.', 'login-armor' ); ?></li>
		<li><?php esc_html_e( 'Role escalations (subscriber to admin).', 'login-armor' ); ?></li>
		<li><?php esc_html_e( 'Plugin installs or theme changes at unusual hours.', 'login-armor' ); ?></li>
		<li><?php esc_html_e( 'Changes to site URL, admin email, or registration settings.', 'login-armor' ); ?></li>
	</ul>
</details>
