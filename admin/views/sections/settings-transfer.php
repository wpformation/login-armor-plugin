<?php
/**
 * Settings transfer: export this site's settings as JSON, import a file
 * exported elsewhere with a preview-then-confirm flow.
 *
 * Rendered on the Settings tab right after the safe baseline strip.
 * Handlers: Admin::ajax_settings_export() / ajax_settings_import();
 * behaviour: admin.js "Settings transfer" block.
 *
 * @package LoginArmor
 * @since   2.6.0
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}
?>
<div class="la-transfer" id="la-settings-transfer">
	<div class="la-transfer__card">
		<div class="la-transfer__head">
			<?php \LoginArmor\Icons::render( 'download', '', 18 ); ?>
			<span><?php esc_html_e( 'Export settings', 'login-armor' ); ?></span>
		</div>
		<p class="la-transfer__desc"><?php esc_html_e( 'Download every setting as a JSON file and replay it on your other sites. The file contains your login slug and your allowlisted IPs: keep it private. Webhook signing secrets and users’ two-factor enrolments never leave this site.', 'login-armor' ); ?></p>
		<label class="la-transfer__optin">
			<input type="checkbox" name="include_webhooks" value="1">
			<span><?php esc_html_e( 'Include webhook URLs (Slack, Discord, SIEM). They carry an access token: only tick this for a file you will store safely.', 'login-armor' ); ?></span>
		</label>
		<div class="la-transfer__actions">
			<button type="button" class="la-btn la-btn--secondary" data-la-action="settings-export">
				<?php esc_html_e( 'Download settings (JSON)', 'login-armor' ); ?>
			</button>
		</div>
	</div>
	<div class="la-transfer__card">
		<div class="la-transfer__head">
			<?php \LoginArmor\Icons::render( 'file', '', 18 ); ?>
			<span id="la-lbl-transfer-file"><?php esc_html_e( 'Import settings', 'login-armor' ); ?></span>
		</div>
		<p class="la-transfer__desc"><?php esc_html_e( 'Upload a file exported from another site. You see every change first; nothing is written until you confirm. One invalid value refuses the whole file, so a site is never half-configured.', 'login-armor' ); ?></p>
		<?php // 2.8.0: named by the heading of its card: it had no accessible name. ?>
		<input type="file" id="la-transfer-file" class="la-transfer__file" accept=".json,application/json" aria-labelledby="la-lbl-transfer-file">
		<div class="la-transfer__result" data-la-transfer-result hidden></div>
		<div class="la-transfer__actions">
			<button type="button" class="la-btn la-btn--secondary" data-la-action="settings-preview">
				<?php esc_html_e( 'Preview changes', 'login-armor' ); ?>
			</button>
			<button type="button" class="la-btn la-btn--primary" data-la-action="settings-apply" hidden>
				<?php esc_html_e( 'Apply these changes', 'login-armor' ); ?>
			</button>
		</div>
	</div>
</div>
