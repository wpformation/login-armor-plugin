<?php
/**
 * Admin class.
 *
 * Handles the plugin settings page, menu registration, asset enqueuing,
 * form submissions, and AJAX endpoints.
 *
 * @package LoginArmor
 * @since   1.0.0
 */

namespace LoginArmor;

// Exit if accessed directly.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Plugin admin interface.
 */
class Admin {

	/**
	 * Cache-exclusion notice: the set of caches whose exclusion was confirmed.
	 *
	 * Holds PluginDetection::cache_set_key() as it stood when an administrator
	 * dismissed the notice, never a boolean. Non-autoloaded: it is read on the
	 * plugin's own admin screen and nowhere else, so it has no business being
	 * in the alloptions blob of every front-end request.
	 *
	 * @since 2.7.1
	 * @var string
	 */
	public const OPTION_CACHE_NOTICE_DISMISSED = 'login_armor_cache_notice_dismissed';

	/** @var string Current admin page hook suffix. */
	private string $hook_suffix = '';

	/**
	 * Constructor. Registers admin hooks.
	 */
	public function __construct() {
		add_action( 'admin_menu', [ $this, 'add_menu_page' ] );
		add_action( 'admin_enqueue_scripts', [ $this, 'enqueue_assets' ] );
		add_action( 'admin_init', [ $this, 'handle_form_submission' ] );
		add_action( 'admin_init', [ $this, 'maybe_onboarding_redirect' ] );
		add_action( 'admin_notices', [ $this, 'maybe_render_conflict_notice' ] );

		// AJAX endpoints.
		add_action( 'wp_ajax_login_armor_unblock_ip', [ $this, 'ajax_unblock_ip' ] );
		add_action( 'wp_ajax_login_armor_purge_logs', [ $this, 'ajax_purge_logs' ] );
		add_action( 'wp_ajax_login_armor_overview_data', [ $this, 'ajax_overview_data' ] );
		add_action( 'wp_ajax_login_armor_skip_advice', [ $this, 'ajax_skip_advice' ] );
		add_action( 'wp_ajax_login_armor_dismiss_cache_notice', [ $this, 'ajax_dismiss_cache_notice' ] );
		add_action( 'wp_ajax_login_armor_incident_resolve', [ $this, 'ajax_incident_resolve' ] );
		add_action( 'wp_ajax_login_armor_incident_ignore', [ $this, 'ajax_incident_ignore' ] );
		add_action( 'wp_ajax_login_armor_incidents_bulk', [ $this, 'ajax_incidents_bulk' ] );
		add_action( 'wp_ajax_login_armor_subnet_block', [ $this, 'ajax_subnet_block' ] );
		add_action( 'wp_ajax_login_armor_subnet_unblock', [ $this, 'ajax_subnet_unblock' ] );
		add_action( 'wp_ajax_login_armor_ip_unblock_v2', [ $this, 'ajax_ip_unblock_v2' ] );
		add_action( 'wp_ajax_login_armor_events_export', [ $this, 'ajax_events_export' ] );
		add_action( 'wp_ajax_login_armor_activity_export', [ $this, 'ajax_activity_export' ] );

		// Lot 5: Hide Login AJAX endpoints.
		add_action( 'wp_ajax_login_armor_regenerate_slug', [ $this, 'ajax_regenerate_slug' ] );
		add_action( 'wp_ajax_login_armor_save_hide_settings', [ $this, 'ajax_save_hide_settings' ] );
		add_action( 'wp_ajax_login_armor_email_slug', [ $this, 'ajax_email_slug' ] );
		add_action( 'wp_ajax_login_armor_enable_hide', [ $this, 'ajax_enable_hide' ] );
		add_action( 'wp_ajax_login_armor_disable_hide', [ $this, 'ajax_disable_hide' ] );

		// Lot 5bis: Hardening AJAX endpoint.
		add_action( 'wp_ajax_login_armor_save_hardening', [ $this, 'ajax_save_hardening' ] );

		// Lot 14: Username blacklist inline save.
		add_action( 'wp_ajax_login_armor_save_username_blacklist', [ $this, 'ajax_save_username_blacklist' ] );

		// 2.5.1 - Public REST namespaces inline save.
		add_action( 'wp_ajax_login_armor_save_rest_namespaces', [ $this, 'ajax_save_rest_namespaces' ] );

		// Lot 6: Limit Login AJAX endpoints.
		add_action( 'wp_ajax_login_armor_save_limit_settings', [ $this, 'ajax_save_limit_settings' ] );
		add_action( 'wp_ajax_login_armor_enable_limit', [ $this, 'ajax_enable_limit' ] );
		add_action( 'wp_ajax_login_armor_disable_limit', [ $this, 'ajax_disable_limit' ] );
		add_action( 'wp_ajax_login_armor_get_current_ip', [ $this, 'ajax_get_current_ip' ] );

		// Lot 6: Detection & Logs AJAX endpoints.
		add_action( 'wp_ajax_login_armor_save_detection_settings', [ $this, 'ajax_save_detection_settings' ] );
		add_action( 'wp_ajax_login_armor_enable_detection', [ $this, 'ajax_enable_detection' ] );
		add_action( 'wp_ajax_login_armor_disable_detection', [ $this, 'ajax_disable_detection' ] );
		add_action( 'wp_ajax_login_armor_purge_logs_manual', [ $this, 'ajax_purge_logs_manual' ] );
		// 2.0.1: full wipe (destructive, distinct from retention-based purge above).
		add_action( 'wp_ajax_login_armor_reset_detection_data', [ $this, 'ajax_reset_detection_data' ] );

		// Lot 9: Activity Log AJAX endpoints.
		add_action( 'wp_ajax_login_armor_enable_activity', [ $this, 'ajax_enable_activity' ] );
		add_action( 'wp_ajax_login_armor_disable_activity', [ $this, 'ajax_disable_activity' ] );
		add_action( 'wp_ajax_login_armor_save_activity_settings', [ $this, 'ajax_save_activity_settings' ] );
		add_action( 'wp_ajax_login_armor_purge_activity', [ $this, 'ajax_purge_activity' ] );
		// 2.0.1: full wipe of admin activity log.
		add_action( 'wp_ajax_login_armor_reset_activity_data', [ $this, 'ajax_reset_activity_data' ] );

		// Lot 10: Two-Factor Authentication AJAX endpoints.
		add_action( 'wp_ajax_login_armor_enable_2fa', [ $this, 'ajax_enable_2fa' ] );
		add_action( 'wp_ajax_login_armor_disable_2fa', [ $this, 'ajax_disable_2fa' ] );
		add_action( 'wp_ajax_login_armor_save_2fa_settings', [ $this, 'ajax_save_2fa_settings' ] );
		add_action( 'wp_ajax_login_armor_start_2fa_setup', [ $this, 'ajax_start_2fa_setup' ] );
		add_action( 'wp_ajax_login_armor_verify_2fa_setup', [ $this, 'ajax_verify_2fa_setup' ] );
		add_action( 'wp_ajax_login_armor_complete_2fa_setup', [ $this, 'ajax_complete_2fa_setup' ] );
		add_action( 'wp_ajax_login_armor_2fa_email_test', [ $this, 'ajax_2fa_email_test' ] );
		add_action( 'wp_ajax_login_armor_disable_user_2fa', [ $this, 'ajax_disable_user_2fa' ] );
		add_action( 'wp_ajax_login_armor_admin_reset_user_2fa', [ $this, 'ajax_admin_reset_user_2fa' ] );
		add_action( 'wp_ajax_login_armor_regenerate_backup_codes', [ $this, 'ajax_regenerate_backup_codes' ] );
		add_action( 'wp_ajax_login_armor_2fa_revoke_trusted_device', [ $this, 'ajax_2fa_revoke_trusted_device' ] );
		add_action( 'wp_ajax_login_armor_2fa_revoke_all_trusted_devices', [ $this, 'ajax_2fa_revoke_all_trusted_devices' ] );

		// Lot 10: Profile page hooks.
		add_action( 'show_user_profile', [ $this, 'render_2fa_profile_section' ] );
		add_action( 'edit_user_profile', [ $this, 'render_2fa_profile_section' ] );

		// 2.9.0: networks seen per application password, after the 2FA section.
		add_action( 'show_user_profile', [ $this, 'render_app_password_networks' ], 20 );
		add_action( 'edit_user_profile', [ $this, 'render_app_password_networks' ], 20 );
		add_action( 'admin_post_login_armor_approve_network', [ $this, 'handle_approve_network' ] );
		add_action( 'admin_notices', [ $this, 'maybe_network_approved_notice' ] );
		add_filter( 'removable_query_args', [ $this, 'removable_query_args' ] );

		// 2.4.3, Admin recovery for users hard-blocked by mandatory 2FA:
		// a "restart 2FA grace" row action on the Users list + its handler, so an
		// admin can re-open the setup window without needing WP-CLI.
		add_filter( 'user_row_actions', [ $this, 'add_2fa_grace_row_action' ], 10, 2 );
		add_action( 'admin_post_login_armor_restart_2fa_grace', [ $this, 'handle_restart_2fa_grace' ] );
		add_action( 'admin_notices', [ $this, 'maybe_grace_reset_notice' ] );

		// Lot 7: Notifications AJAX endpoints.
		add_action( 'wp_ajax_login_armor_save_notifications', [ $this, 'ajax_save_notifications' ] );
		add_action( 'wp_ajax_login_armor_test_notification', [ $this, 'ajax_test_notification' ] );
		add_action( 'wp_ajax_login_armor_enable_notifications', [ $this, 'ajax_enable_notifications' ] );
		add_action( 'wp_ajax_login_armor_disable_notifications', [ $this, 'ajax_disable_notifications' ] );

		// Lot 13: Login Page Security Headers AJAX endpoints.
		add_action( 'wp_ajax_login_armor_enable_login_headers', [ $this, 'ajax_enable_login_headers' ] );
		add_action( 'wp_ajax_login_armor_disable_login_headers', [ $this, 'ajax_disable_login_headers' ] );
		add_action( 'wp_ajax_login_armor_save_login_headers', [ $this, 'ajax_save_login_headers' ] );

		// Lot 21: Breach Check AJAX endpoints.
		add_action( 'wp_ajax_login_armor_enable_breach_check', [ $this, 'ajax_enable_breach_check' ] );
		add_action( 'wp_ajax_login_armor_disable_breach_check', [ $this, 'ajax_disable_breach_check' ] );
		add_action( 'wp_ajax_login_armor_save_breach_check', [ $this, 'ajax_save_breach_check' ] );

		// Password Policy AJAX endpoints.
		add_action( 'wp_ajax_login_armor_enable_password_policy', [ $this, 'ajax_enable_password_policy' ] );
		add_action( 'wp_ajax_login_armor_disable_password_policy', [ $this, 'ajax_disable_password_policy' ] );
		add_action( 'wp_ajax_login_armor_save_password_policy', [ $this, 'ajax_save_password_policy' ] );

		// Session Manager AJAX endpoints.
		add_action( 'wp_ajax_login_armor_enable_session', [ $this, 'ajax_enable_session' ] );
		add_action( 'wp_ajax_login_armor_disable_session', [ $this, 'ajax_disable_session' ] );
		add_action( 'wp_ajax_login_armor_save_session', [ $this, 'ajax_save_session' ] );
		add_action( 'wp_ajax_login_armor_session_logout_others', [ $this, 'ajax_session_logout_others' ] );

		// GeoIP AJAX endpoints.
		add_action( 'wp_ajax_login_armor_enable_geoip', [ $this, 'ajax_enable_geoip' ] );
		add_action( 'wp_ajax_login_armor_disable_geoip', [ $this, 'ajax_disable_geoip' ] );
		// 2.9.0: headless mode and application-password monitoring.
		add_action( 'wp_ajax_login_armor_enable_headless', [ $this, 'ajax_enable_headless' ] );
		add_action( 'wp_ajax_login_armor_disable_headless', [ $this, 'ajax_disable_headless' ] );
		add_action( 'wp_ajax_login_armor_set_app_password_watch', [ $this, 'ajax_set_app_password_watch' ] );

		// Request Firewall (8G-inspired PHP filter).
		add_action( 'wp_ajax_login_armor_enable_firewall', [ $this, 'ajax_enable_firewall' ] );
		add_action( 'wp_ajax_login_armor_disable_firewall', [ $this, 'ajax_disable_firewall' ] );
		add_action( 'wp_ajax_login_armor_save_firewall', [ $this, 'ajax_save_firewall' ] );

		// Bot Challenge (Proof-of-Work).
		add_action( 'wp_ajax_login_armor_enable_pow', [ $this, 'ajax_enable_pow' ] );
		add_action( 'wp_ajax_login_armor_disable_pow', [ $this, 'ajax_disable_pow' ] );
		add_action( 'wp_ajax_login_armor_save_pow', [ $this, 'ajax_save_pow' ] );

		// Onboarding wizard + safe baseline.
		add_action( 'wp_ajax_login_armor_onboard', [ $this, 'ajax_onboard' ] );
		add_action( 'wp_ajax_login_armor_apply_safe_baseline', [ $this, 'ajax_apply_safe_baseline' ] );

		// 2.6.0: settings transfer (export / import).
		add_action( 'wp_ajax_login_armor_settings_export', [ $this, 'ajax_settings_export' ] );
		add_action( 'wp_ajax_login_armor_settings_import', [ $this, 'ajax_settings_import' ] );

		// V2.1.1 B10: Activity Log integrity + Webhook AJAX endpoints.
		add_action( 'wp_ajax_login_armor_activity_verify_chain', [ $this, 'ajax_activity_verify_chain' ] );
		add_action( 'wp_ajax_login_armor_activity_repair_chain', [ $this, 'ajax_activity_repair_chain' ] );
		add_action( 'wp_ajax_login_armor_activity_reset_chain', [ $this, 'ajax_activity_reset_chain' ] );
		add_action( 'wp_ajax_login_armor_webhook_test', [ $this, 'ajax_webhook_test' ] );
		add_action( 'wp_ajax_login_armor_webhook_regenerate_secret', [ $this, 'ajax_webhook_regenerate_secret' ] );
		add_action( 'wp_ajax_login_armor_webhook_save', [ $this, 'ajax_webhook_save' ] );

		// AI layer: WP7 native AI Client analysis (on-demand, read-only).
		add_action( 'wp_ajax_login_armor_ai_explain_incident', [ $this, 'ajax_ai_explain_incident' ] );
		add_action( 'wp_ajax_login_armor_ai_posture', [ $this, 'ajax_ai_posture' ] );
		add_action( 'wp_ajax_login_armor_ai_approve', [ $this, 'ajax_ai_approve' ] );
		add_action( 'wp_ajax_login_armor_ai_revoke', [ $this, 'ajax_ai_revoke' ] );
		add_action( 'wp_ajax_login_armor_ai_save_settings', [ $this, 'ajax_ai_save_settings' ] );

		// Lot 8d: WP Dashboard widget.
		add_action( 'wp_dashboard_setup', [ $this, 'register_dashboard_widget' ] );
		add_action( 'admin_enqueue_scripts', [ $this, 'maybe_enqueue_widget_css' ] );

		add_action( 'admin_notices', [ $this, 'safe_mode_notice' ] );
		add_action( 'admin_notices', [ $this, 'safe_mode_unblocked_notice' ] );
		add_action( 'admin_post_login_armor_safe_mode_unblock', [ $this, 'handle_safe_mode_unblock' ] );
		add_action( 'admin_notices', [ $this, 'conflict_notice' ] );
		add_action( 'admin_notices', [ $this, 'htaccess_write_failed_notice' ] );
		add_action( 'admin_notices', [ $this, 'htaccess_ambiguous_notice' ] );
		add_action( 'admin_notices', [ $this, 'ip_identity_notice' ] );
		add_action( 'admin_notices', [ $this, 'https_terminator_notice' ] );
		add_action( 'admin_notices', [ $this, 'notif_suppressed_notice' ] );

		// LoginArmor admin page isolation.
		add_action( 'in_admin_header', [ $this, 'maybe_suppress_admin_notices' ] );
		add_action( 'admin_head', [ $this, 'force_light_mode' ] );
		add_filter( 'admin_body_class', [ $this, 'maybe_add_body_class' ] );
	}

	/**
	 * Register LoginArmor as a top-level admin menu entry.
	 *
	 * LoginArmor is a monitoring tool (detection dashboard, incidents, events),
	 * consulted multiple times a day: it belongs at the top level, not buried
	 * under Settings. The menu icon reuses the brand shield SVG (polygon); WP
	 * recolors it automatically to match the admin color scheme.
	 */
	public function add_menu_page(): void {
		$svg = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><path d="M0 0 L24 0 L24 15 L12 24 L0 15 Z" fill="black"/><rect x="7.2" y="8.4" width="9.6" height="1.92" fill="transparent"/></svg>';
		$icon_url = 'data:image/svg+xml;base64,' . base64_encode( $svg ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode -- Required for WP menu icon data URI.

		$this->hook_suffix = \add_menu_page(
			__( 'Login Armor', 'login-armor' ),
			__( 'Login Armor', 'login-armor' ),
			'manage_options',
			'login-armor',
			[ $this, 'render_page' ],
			$icon_url,
			80
		);
	}

	/**
	 * Enqueue CSS and JS assets on the plugin settings page only.
	 *
	 * Parameter untyped with a default: `admin_enqueue_scripts` can be
	 * re-fired by admin-page plugins without arguments.
	 *
	 * @param mixed $hook_suffix The current admin page hook suffix (expected string).
	 */
	public function enqueue_assets( $hook_suffix = '' ): void {
		if ( $hook_suffix !== $this->hook_suffix ) {
			return;
		}

		$css_path = LOGIN_ARMOR_DIR . 'admin/assets/css/admin.css';
		$js_path  = LOGIN_ARMOR_DIR . 'admin/assets/js/admin.js';

		// Use file content hash as version: filemtime() is unreliable through Windows symlinks.
		$css_version = file_exists( $css_path ) ? substr( md5_file( $css_path ), 0, 8 ) : LOGIN_ARMOR_VERSION;
		$js_version  = file_exists( $js_path ) ? substr( md5_file( $js_path ), 0, 8 ) : LOGIN_ARMOR_VERSION;

		$confirm_css_path = LOGIN_ARMOR_DIR . 'admin/assets/css/confirm-modal.css';
		$confirm_js_path  = LOGIN_ARMOR_DIR . 'admin/assets/js/confirm-modal.js';
		$confirm_css_ver  = file_exists( $confirm_css_path ) ? substr( md5_file( $confirm_css_path ), 0, 8 ) : LOGIN_ARMOR_VERSION;
		$confirm_js_ver   = file_exists( $confirm_js_path ) ? substr( md5_file( $confirm_js_path ), 0, 8 ) : LOGIN_ARMOR_VERSION;

		wp_enqueue_style(
			'login-armor-confirm-modal',
			LOGIN_ARMOR_URL . 'admin/assets/css/confirm-modal.css',
			[],
			$confirm_css_ver
		);
		wp_enqueue_script(
			'login-armor-confirm-modal',
			LOGIN_ARMOR_URL . 'admin/assets/js/confirm-modal.js',
			[],
			$confirm_js_ver,
			true
		);

		$preact_css_path = LOGIN_ARMOR_DIR . 'admin/assets/css/hide-login-preactivate.css';
		$preact_js_path  = LOGIN_ARMOR_DIR . 'admin/assets/js/hide-login-preactivate.js';
		$preact_css_ver  = file_exists( $preact_css_path ) ? substr( md5_file( $preact_css_path ), 0, 8 ) : LOGIN_ARMOR_VERSION;
		$preact_js_ver   = file_exists( $preact_js_path ) ? substr( md5_file( $preact_js_path ), 0, 8 ) : LOGIN_ARMOR_VERSION;

		wp_enqueue_style(
			'login-armor-hl-preactivate',
			LOGIN_ARMOR_URL . 'admin/assets/css/hide-login-preactivate.css',
			[ 'login-armor-tokens' ],
			$preact_css_ver
		);
		wp_enqueue_script(
			'login-armor-hl-preactivate',
			LOGIN_ARMOR_URL . 'admin/assets/js/hide-login-preactivate.js',
			[],
			$preact_js_ver,
			true
		);

		wp_enqueue_style(
			'login-armor-fonts',
			LOGIN_ARMOR_URL . 'admin/assets/fonts/fonts.css',
			[],
			LOGIN_ARMOR_VERSION
		);

		$tokens_path    = LOGIN_ARMOR_DIR . 'admin/assets/css/tokens.css';
		$tokens_version = file_exists( $tokens_path ) ? substr( md5_file( $tokens_path ), 0, 8 ) : LOGIN_ARMOR_VERSION;

		wp_enqueue_style(
			'login-armor-tokens',
			LOGIN_ARMOR_URL . 'admin/assets/css/tokens.css',
			[ 'login-armor-fonts' ],
			$tokens_version
		);

		wp_enqueue_style(
			'login-armor-admin',
			LOGIN_ARMOR_URL . 'admin/assets/css/admin.css',
			[ 'login-armor-fonts', 'login-armor-tokens' ],
			$css_version
		);

		wp_enqueue_script(
			'login-armor-admin',
			LOGIN_ARMOR_URL . 'admin/assets/js/admin.js',
			[ 'login-armor-confirm-modal', 'login-armor-hl-preactivate' ],
			$js_version,
			true
		);

		// AI panel STYLES are always loaded: the security briefing on the
		// Overview always renders a deterministic facts snapshot (with or without
		// an AI connector), and that snapshot uses ai.css. Without it the facts
		// panel renders unstyled (labels glued to values).
		$ai_css_path = LOGIN_ARMOR_DIR . 'admin/assets/css/ai.css';
		$ai_css_ver  = file_exists( $ai_css_path ) ? substr( md5_file( $ai_css_path ), 0, 8 ) : LOGIN_ARMOR_VERSION;
		wp_enqueue_style(
			'login-armor-ai',
			LOGIN_ARMOR_URL . 'admin/assets/css/ai.css',
			[ 'login-armor-admin' ],
			$ai_css_ver
		);

		// AI SCRIPT + localization are loaded only when an interactive AI panel
		// can actually appear (native connector usable or pending approval).
		// Zero JS on sites without a WordPress 7 AI connector.
		if ( \LoginArmor\AI\Client::is_available() || \LoginArmor\AI\Client::needs_approval() ) {
			$ai_js_path  = LOGIN_ARMOR_DIR . 'admin/assets/js/ai.js';
			$ai_js_ver   = file_exists( $ai_js_path ) ? substr( md5_file( $ai_js_path ), 0, 8 ) : LOGIN_ARMOR_VERSION;
			wp_enqueue_script(
				'login-armor-ai',
				LOGIN_ARMOR_URL . 'admin/assets/js/ai.js',
				[ 'login-armor-admin' ],
				$ai_js_ver,
				true
			);
			wp_localize_script(
				'login-armor-ai',
				'loginArmorAI',
				[
					'analysing' => __( 'Analysing…', 'login-armor' ),
					'failed'    => __( 'AI analysis failed.', 'login-armor' ),
					'network'   => __( 'Network error.', 'login-armor' ),
					'saved'     => __( 'Saved.', 'login-armor' ),
					// Replaces the stored analysis stamp after a regeneration: the
					// date and the "earlier state" warning on screen describe the
					// text that was just replaced, and must not outlive it.
					'justNow'   => __( 'Analysis produced just now.', 'login-armor' ),
				]
			);
		}

		wp_localize_script(
			'login-armor-admin',
			'loginArmor',
			[
				'ajaxUrl'        => admin_url( 'admin-ajax.php' ),
				'nonce'          => wp_create_nonce( 'login_armor_ajax' ),
				'confirmUnblock' => __( 'Unblock this IP address?', 'login-armor' ),
				'confirmPurge'   => __( 'Delete all logs older than the selected period? This cannot be undone.', 'login-armor' ),
				'success'        => __( 'Done.', 'login-armor' ),
				'error'          => __( 'An error occurred. Please try again.', 'login-armor' ),
				// English → localized map for the toast() helper (admin.js). Keys
				// are the literal English messages emitted at the call sites; the
				// JS looks the message up here so toasts honour the site locale.
				'toasts'         => [
					'Action failed.'                          => __( 'Action failed.', 'login-armor' ),
					'Network error.'                          => __( 'Network error.', 'login-armor' ),
					'Missing nonce, reload the page.'         => __( 'Missing nonce, reload the page.', 'login-armor' ),
					'All changes saved.'                      => __( 'All changes saved.', 'login-armor' ),
					'Saved'                                   => __( 'Saved', 'login-armor' ),
					'Save failed.'                            => __( 'Save failed.', 'login-armor' ),
					'Copied.'                                 => __( 'Copied.', 'login-armor' ),
					'Copy failed.'                            => __( 'Copy failed.', 'login-armor' ),
					'Could not detect IP.'                    => __( 'Could not detect IP.', 'login-armor' ),
					'Could not skip advice.'                  => __( 'Could not skip advice.', 'login-armor' ),
					'Activity logging enabled.'               => __( 'Activity logging enabled.', 'login-armor' ),
					'Activity logging disabled.'              => __( 'Activity logging disabled.', 'login-armor' ),
					'Brute force protection enabled.'         => __( 'Brute force protection enabled.', 'login-armor' ),
					'Brute force protection disabled.'        => __( 'Brute force protection disabled.', 'login-armor' ),
					'Detection & logs enabled.'               => __( 'Detection & logs enabled.', 'login-armor' ),
					'Detection & logs disabled.'              => __( 'Detection & logs disabled.', 'login-armor' ),
					'Hardening settings saved.'               => __( 'Hardening settings saved.', 'login-armor' ),
					'Hide Login enabled.'                     => __( 'Hide Login enabled.', 'login-armor' ),
					'Hide Login disabled.'                    => __( 'Hide Login disabled.', 'login-armor' ),
					'Hide Login settings saved.'              => __( 'Hide Login settings saved.', 'login-armor' ),
					'Login headers enabled.'                  => __( 'Login headers enabled.', 'login-armor' ),
					'Login headers disabled.'                 => __( 'Login headers disabled.', 'login-armor' ),
					'Login headers saved.'                    => __( 'Login headers saved.', 'login-armor' ),
					'Notifications enabled: defaulting to Email. Configure channel below.' => __( 'Notifications enabled: defaulting to Email. Configure channel below.', 'login-armor' ),
					'Notifications disabled.'                 => __( 'Notifications disabled.', 'login-armor' ),
					'Test notification sent.'                 => __( 'Test notification sent.', 'login-armor' ),
					'Two-factor authentication enabled.'      => __( 'Two-factor authentication enabled.', 'login-armor' ),
					'Two-factor authentication disabled.'     => __( 'Two-factor authentication disabled.', 'login-armor' ),
					// Trusted-device panel of the 2FA profile screen (two-factor.js).
					'Device revoked.'                         => __( 'Device revoked.', 'login-armor' ),
					'Revoke failed.'                          => __( 'Revoke failed.', 'login-armor' ),
					'All devices revoked.'                    => __( 'All devices revoked.', 'login-armor' ),
					'Revoke all failed.'                      => __( 'Revoke all failed.', 'login-armor' ),
					'Enable failed.'                          => __( 'Enable failed.', 'login-armor' ),
					'Disable failed.'                         => __( 'Disable failed.', 'login-armor' ),
					'Email failed.'                           => __( 'Email failed.', 'login-armor' ),
					'Purge failed.'                           => __( 'Purge failed.', 'login-armor' ),
					'Regenerate failed.'                      => __( 'Regenerate failed.', 'login-armor' ),
					// 2.8.0: the old message said the new URL had been emailed;
					// ajax_regenerate_slug() deliberately sends nothing.
					'Regenerated. This new URL was not emailed: bookmark it now, or use “Email me this URL”.' => __( 'Regenerated. This new URL was not emailed: bookmark it now, or use “Email me this URL”.', 'login-armor' ),
					'Reset failed.'                           => __( 'Reset failed.', 'login-armor' ),
					'Reset to defaults. New URL emailed to admin.' => __( 'Reset to defaults. New URL emailed to admin.', 'login-armor' ),
					'Recommended values applied.'             => __( 'Recommended values applied.', 'login-armor' ),
					'Defaults restored.'                      => __( 'Defaults restored.', 'login-armor' ),
					'Incident resolved.'                      => __( 'Incident resolved.', 'login-armor' ),
					'Incident ignored.'                       => __( 'Incident ignored.', 'login-armor' ),
				],
				'confirmI18n'    => [
					'cancel'  => __( 'Cancel', 'login-armor' ),
					'confirm' => __( 'Confirm', 'login-armor' ),
					'ack'     => __( 'I understand', 'login-armor' ),
				],
				'hardeningDefaults' => [
					'active' => __( '7 recommended defaults active.', 'login-armor' ),
					'hint'   => __( 'Enables the 7 most common security toggles at once.', 'login-armor' ),
					'allOn'  => __( 'All 7 recommended defaults are already active.', 'login-armor' ),
				],
				'settingsSearch' => [
					/* translators: %d: number of settings modules matching what was typed in the Settings search box. */
					'results'     => __( '%d matching modules', 'login-armor' ),
					'resultsOne'  => __( '1 matching module', 'login-armor' ),
					'resultsNone' => __( 'No matching module', 'login-armor' ),
				],
				'liveEvents'     => [
					'statusOk'        => __( 'OK', 'login-armor' ),
					'statusFail'      => __( 'FAIL', 'login-armor' ),
					'statusLock'      => __( 'BLOCKED', 'login-armor' ),
					'actionSuccess'   => __( 'Successful sign-in', 'login-armor' ),
					'actionLocked'    => __( 'Locked out', 'login-armor' ),
					'actionDenied'    => __( 'Auth denied: wrong password', 'login-armor' ),
					'empty'           => __( 'No events recorded yet.', 'login-armor' ),
					'uaChromeMac'     => __( 'Chrome on macOS', 'login-armor' ),
					'uaChromeWindows' => __( 'Chrome on Windows', 'login-armor' ),
					'uaChromeLinux'   => __( 'Chrome on Linux', 'login-armor' ),
					'uaSafariIOS'     => __( 'Safari on iOS', 'login-armor' ),
					'uaSafariIPadOS'  => __( 'Safari on iPadOS', 'login-armor' ),
					'uaSafariMac'     => __( 'Safari on macOS', 'login-armor' ),
					'uaFirefox'       => __( 'Firefox', 'login-armor' ),
					'uaEdge'          => __( 'Edge', 'login-armor' ),
					'uaCurl'          => __( 'curl', 'login-armor' ),
					'uaWget'          => __( 'wget', 'login-armor' ),
					'uaPython'        => __( 'python-requests', 'login-armor' ),
					'uaGo'            => __( 'Go http-client', 'login-armor' ),
					'uaBot'           => __( 'Bot / crawler', 'login-armor' ),
					'uaJetpack'       => __( 'Jetpack (WordPress.com)', 'login-armor' ),
					'uaWpcom'         => __( 'WordPress.com', 'login-armor' ),
					'uaWordpress'     => __( 'WordPress', 'login-armor' ),
				],
				'limitSummary'   => [
					/* translators: 1: retries allowed, 2: lockout minutes, 3: max lockouts in window, 4: window hours, 5: extended ban hours, 6: reset window hours. <strong> tags must be preserved around numbers. */
					'template' => __( 'After <strong>%1$d</strong> failed attempts, the IP is locked for <strong>%2$d minutes</strong>. After <strong>%3$d</strong> lockouts within <strong>%4$d hours</strong>, the ban extends to <strong>%5$d hours</strong>. Failed attempts reset after <strong>%6$d hours</strong> of inactivity.', 'login-armor' ),
				],
				'hideLoginCurrentSlug' => (string) get_option( \LoginArmor\HideLogin::OPTION_SLUG, '' ),
				'hideLoginPreActivate' => [
					'title'            => __( 'Enable Hide Login', 'login-armor' ),
					'lede'             => __( 'Pick the secret URL for your login page. Visitors will not be able to discover it.', 'login-armor' ),
					'slugLabel'        => __( 'Your login slug', 'login-armor' ),
					'slugHint'         => __( 'Lowercase letters, digits, and hyphens. 3 to 64 characters.', 'login-armor' ),
					'regenerate'       => __( 'Regenerate', 'login-armor' ),
					'emailLabel'       => __( 'Email me this URL (recommended, you will need it to log in).', 'login-armor' ),
					'cancel'           => __( 'Cancel', 'login-armor' ),
					'activate'         => __( 'Activate Hide Login', 'login-armor' ),
					'invalidSlug'      => __( 'This slug cannot be used. Try another or click Regenerate.', 'login-armor' ),
					'genericError'     => __( 'Something went wrong. Try again.', 'login-armor' ),
				],
				// V2.1.1 B12: Activity Webhook UI strings (admin.js Copy / Regenerate / Test handlers).
				'webhook'        => [
					'secret_copied'        => __( 'Secret copied to clipboard.', 'login-armor' ),
					'copy_failed'          => __( 'Copy failed; select and copy manually.', 'login-armor' ),
					'regenerate_title'     => __( 'Regenerate webhook secret?', 'login-armor' ),
					'regenerate_confirm'   => __( 'Regenerate the webhook secret? Your receiver will need to be reconfigured with the new value.', 'login-armor' ),
					'secret_regenerated'   => __( 'Secret regenerated. Update your receiver.', 'login-armor' ),
					'regenerate_failed'    => __( 'Regenerate failed.', 'login-armor' ),
					/* translators: %s: HTTP status code returned by the test webhook delivery (e.g. "HTTP 200"). */
					'test_delivered'       => __( 'Test event delivered: %s', 'login-armor' ),
					'test_failed'          => __( 'Test failed.', 'login-armor' ),
				],
				// V2.1.1: Integrity panel UI strings (admin.js verify/repair handlers + in-place DOM patch).
				'integrity'      => [
					'verifying'   => __( 'Verifying…', 'login-armor' ),
					'repairing'   => __( 'Repairing…', 'login-armor' ),
					'verifyFail'  => __( 'Verify failed.', 'login-armor' ),
					'repairFail'  => __( 'Repair failed.', 'login-armor' ),
					/* translators: %s: row count formatted (e.g. "1 234"). */
					'intactToast' => __( 'Chain intact: %s rows signed.', 'login-armor' ),
					/* translators: %d: row id where chain integrity is broken. */
					'brokenToast' => __( 'Chain BROKEN at row %d. See panel for details.', 'login-armor' ),
					/* translators: %d: number of orphan rows repaired. */
					'repairedToast' => __( 'Repaired %d orphan(s).', 'login-armor' ),
					'labelIntact' => __( 'Chain intact', 'login-armor' ),
					'labelBroken' => __( 'Chain BROKEN', 'login-armor' ),
					/* translators: %s: row count formatted. */
					'metaRows'    => __( '%s rows signed', 'login-armor' ),
					/* translators: %s: relative time (e.g. "5m ago"). */
					'metaWhen'    => __( 'verified %s', 'login-armor' ),
					'pillIntact'  => __( 'INTACT', 'login-armor' ),
					'pillBroken'  => __( 'BROKEN', 'login-armor' ),
					'pillKeysChanged' => __( 'KEYS CHANGED', 'login-armor' ),
					'resetting'   => __( 'Re-basing…', 'login-armor' ),
					'resetFail'   => __( 'Re-baseline failed.', 'login-armor' ),
					/* translators: %s: number of rows re-signed. */
					'resetToast'  => __( 'Chain re-based: %s rows re-signed under the current key.', 'login-armor' ),
					'keysChangedToast' => __( 'Security keys changed (migration?). Re-baseline the chain to restore integrity.', 'login-armor' ),
					'justNow'     => __( 'just now', 'login-armor' ),
				],
				'strings'        => self::get_admin_js_strings(),
			]
		);
	}

	/**
	 * Translatable strings surfaced by admin.js confirmation dialogs and
	 * inline feedback. Kept in PHP so that WP's POT tooling picks them up
	 * without scanning JS sources.
	 *
	 * @return array<string, array<string, string>>
	 */
	private static function get_admin_js_strings(): array {
		return [
			// Incident bulk actions (2.7.1). Two confirmation sentences, not
			// one: applying an operation to the 25 rows on screen and applying
			// it to all 235 the filter matches are materially different acts,
			// and the dialog is the last place the difference can be stated.
			// The result sentence carries the server's own count, and says so
			// when rows are left, because a filtered run stops at a ceiling.
			'incidentBulk'      => [
				'titleResolve' => __( 'Resolve incidents', 'login-armor' ),
				'titleIgnore'  => __( 'Ignore incidents', 'login-armor' ),
				/* translators: %s: number of incidents ticked on the current page. */
				'body'         => __( 'Apply to the %s selected incident(s)?', 'login-armor' ),
				/* translators: %s: total number of incidents matching the current filter. */
				'bodyFiltered' => __( 'Apply to ALL %s incidents matching the current filter, including those on the other pages?', 'login-armor' ),
				'confirmLabel' => __( 'Confirm', 'login-armor' ),
				'cancelLabel'  => __( 'Cancel', 'login-armor' ),
				/* translators: %s: number of incidents actually marked resolved. */
				'doneResolved' => __( '%s incident(s) marked resolved.', 'login-armor' ),
				/* translators: %s: number of incidents actually ignored. */
				'doneIgnored'  => __( '%s incident(s) ignored.', 'login-armor' ),
				/* translators: %s: number of incidents still matching the filter after the operation. */
				'remaining'    => __( '%s still match the filter: run it again to continue.', 'login-armor' ),
			],
			'subnetBlock'       => [
				'title'        => __( 'Block subnet?', 'login-armor' ),
				/* translators: %s: IP address contained in the /24 subnet. */
				'body'         => __( 'Block the /24 subnet containing %s. All IPs in that range will be denied immediately.', 'login-armor' ),
				'confirmLabel' => __( 'Block subnet', 'login-armor' ),
				'cancelLabel'  => __( 'Cancel', 'login-armor' ),
			],
			'subnetUnblock'     => [
				'title'        => __( 'Remove from blocklist?', 'login-armor' ),
				/* translators: %s: IP address used to identify the /24 subnet being removed from the blocklist. */
				'body'         => __( 'The /24 subnet containing %s will be removed from the manual blocklist. Previously blocked IPs in that range can attempt logins again.', 'login-armor' ),
				'confirmLabel' => __( 'Remove from blocklist', 'login-armor' ),
				'cancelLabel'  => __( 'Cancel', 'login-armor' ),
			],
			'ipUnblock'         => [
				'title'        => __( 'Unblock IP?', 'login-armor' ),
				/* translators: %s: IP address being removed from the blocklist. */
				'body'         => __( 'IP %s will be removed from the blocklist and can attempt logins again immediately.', 'login-armor' ),
				'confirmLabel' => __( 'Unblock', 'login-armor' ),
				'cancelLabel'  => __( 'Cancel', 'login-armor' ),
			],
			'hideRegenerate'    => [
				'title'        => __( 'Generate a new Hide Login URL?', 'login-armor' ),
				'body'         => __( 'Your current URL will stop working immediately. Bookmark the new one before closing this tab.', 'login-armor' ),
				'confirmLabel' => __( 'Generate new URL', 'login-armor' ),
				'cancelLabel'  => __( 'Cancel', 'login-armor' ),
			],
			'hideReset'         => [
				'title'        => __( 'Reset Hide Login to defaults?', 'login-armor' ),
				'body'         => __( 'This generates a new random URL and switches the redirect to 404.', 'login-armor' ),
				'confirmLabel' => __( 'Reset', 'login-armor' ),
				'cancelLabel'  => __( 'Cancel', 'login-armor' ),
			],
			// Note: v2.0.4 replaced the LA.confirm-based hide-enable flow with
			// LA.hideLoginPreActivate (new modal with slug input + email opt-in);
			// the hideEnable strings were removed here because nothing reads
			// them any more. Their translations would otherwise be dead weight
			// in the fr_FR.po file. See admin.js hide-enable branch.
			'hideDisable'       => [
				'title'        => __( 'Disable Hide Login?', 'login-armor' ),
				'body'         => __( '/wp-login.php will become reachable again at its default location. Your slug is kept so you can re-enable later with one click.', 'login-armor' ),
				'confirmLabel' => __( 'Disable', 'login-armor' ),
				'cancelLabel'  => __( 'Keep enabled', 'login-armor' ),
			],
			'limitEnable'       => [
				'title'        => __( 'Enable brute force protection?', 'login-armor' ),
				'body'         => __( 'IPs with too many failed logins will be temporarily locked out.', 'login-armor' ),
				'confirmLabel' => __( 'Enable', 'login-armor' ),
				'cancelLabel'  => __( 'Cancel', 'login-armor' ),
			],
			'limitDisable'      => [
				'title'        => __( 'Disable brute force protection?', 'login-armor' ),
				'body'         => __( 'Your site will no longer rate-limit login attempts.', 'login-armor' ),
				'confirmLabel' => __( 'Disable', 'login-armor' ),
				'cancelLabel'  => __( 'Cancel', 'login-armor' ),
			],
			'limitReset'        => [
				'title'        => __( 'Reset brute force settings?', 'login-armor' ),
				'body'         => __( 'All brute force thresholds will return to their default values.', 'login-armor' ),
				'confirmLabel' => __( 'Reset', 'login-armor' ),
				'cancelLabel'  => __( 'Cancel', 'login-armor' ),
			],
			'detectionDisable'  => [
				'title'        => __( 'Disable detection & logging?', 'login-armor' ),
				'body'         => __( 'Login attempts will no longer be recorded.', 'login-armor' ),
				'confirmLabel' => __( 'Disable', 'login-armor' ),
				'cancelLabel'  => __( 'Cancel', 'login-armor' ),
			],
			'detectionPurge'    => [
				'title'        => __( 'Delete old logs?', 'login-armor' ),
				/* translators: %s: retention threshold in days. */
				'body'         => __( 'Delete all logs and incidents older than %s days? This cannot be undone.', 'login-armor' ),
				'confirmLabel' => __( 'Delete', 'login-armor' ),
				'cancelLabel'  => __( 'Cancel', 'login-armor' ),
			],
			'detectionReset'    => [
				'title'        => __( 'Reset all detection statistics?', 'login-armor' ),
				'body'         => __( 'This deletes every login event, every brute-force counter, every active and resolved incident. All currently locked-out IPs are immediately released. This cannot be undone.', 'login-armor' ),
				'confirmLabel' => __( 'Reset everything', 'login-armor' ),
				'cancelLabel'  => __( 'Cancel', 'login-armor' ),
			],
			'activityDisable'   => [
				'title'        => __( 'Disable activity logging?', 'login-armor' ),
				'body'         => __( 'Existing logs will be preserved.', 'login-armor' ),
				'confirmLabel' => __( 'Disable', 'login-armor' ),
				'cancelLabel'  => __( 'Cancel', 'login-armor' ),
			],
			'activityPurge'     => [
				'title'        => __( 'Delete old admin activity logs?', 'login-armor' ),
				/* translators: %s: retention threshold in days. */
				'body'         => __( 'Delete every admin-action log (user edits, plugin changes, settings updates, etc.) older than %s days. Login events and incidents are not affected: they have their own retention in Detection & Logs. This cannot be undone.', 'login-armor' ),
				'confirmLabel' => __( 'Delete', 'login-armor' ),
				'cancelLabel'  => __( 'Cancel', 'login-armor' ),
			],
			'activityReset'     => [
				'title'        => __( 'Reset the entire admin activity log?', 'login-armor' ),
				'body'         => __( 'This deletes every admin-action row, regardless of age. Login events and incidents are not affected: they have their own reset in Detection & Logs. This cannot be undone.', 'login-armor' ),
				'confirmLabel' => __( 'Reset everything', 'login-armor' ),
				'cancelLabel'  => __( 'Cancel', 'login-armor' ),
			],
			'twofaOff'          => [
				'title'        => __( 'Disable two-factor authentication?', 'login-armor' ),
				'body'         => __( 'All users will sign in with their password alone. Per-user secrets, backup codes and trusted devices are preserved and restored when you re-enable.', 'login-armor' ),
				'confirmLabel' => __( 'Disable', 'login-armor' ),
				'cancelLabel'  => __( 'Keep enabled', 'login-armor' ),
			],
			'notificationsOff'  => [
				'title'        => __( 'Disable notifications?', 'login-armor' ),
				'body'         => __( 'Incidents will no longer trigger alerts. Your channel settings (webhook URL, severity, rate limit) are preserved and restored when you re-enable.', 'login-armor' ),
				'confirmLabel' => __( 'Disable', 'login-armor' ),
				'cancelLabel'  => __( 'Keep enabled', 'login-armor' ),
			],
			'loginHeadersOff'   => [
				'title'        => __( 'Disable login page security headers?', 'login-armor' ),
				'body'         => __( 'The login form will no longer be protected against clickjacking and credential theft via injected scripts.', 'login-armor' ),
				'confirmLabel' => __( 'Disable', 'login-armor' ),
				'cancelLabel'  => __( 'Cancel', 'login-armor' ),
			],
			'breachCheckOff'    => [
				'title'        => __( 'Disable Breach Check?', 'login-armor' ),
				'body'         => __( 'New logins and profile updates will no longer be checked against public breach corpora. Existing flags on user accounts are kept: they clear automatically when the user changes their password.', 'login-armor' ),
				'confirmLabel' => __( 'Disable', 'login-armor' ),
				'cancelLabel'  => __( 'Keep enabled', 'login-armor' ),
			],
			'breachCheck'       => [
				'enabled'       => __( 'Breach Check enabled.', 'login-armor' ),
				'disabled'      => __( 'Breach Check disabled.', 'login-armor' ),
				'saved'         => __( 'Settings saved.', 'login-armor' ),
				'enableFailed'  => __( 'Could not enable Breach Check.', 'login-armor' ),
				'disableFailed' => __( 'Could not disable Breach Check.', 'login-armor' ),
				'saveFailed'    => __( 'Save failed.', 'login-armor' ),
				/* translators: 1: number of admin accounts scanned, 2: number of them flagged. */
				'scanDone'      => __( 'Scanned %1$d administrator emails, %2$d flagged.', 'login-armor' ),
			],
			'passwordPolicyOff' => [
				'title'        => __( 'Disable password policy?', 'login-armor' ),
				'body'         => __( 'New and changed passwords will no longer be checked against your rules. Your configured rules are preserved and restored when you re-enable.', 'login-armor' ),
				'confirmLabel' => __( 'Disable', 'login-armor' ),
				'cancelLabel'  => __( 'Keep enabled', 'login-armor' ),
			],
			'passwordPolicy'    => [
				'enabled'       => __( 'Password policy enabled.', 'login-armor' ),
				'disabled'      => __( 'Password policy disabled.', 'login-armor' ),
				'saved'         => __( 'Settings saved.', 'login-armor' ),
				'enableFailed'  => __( 'Could not enable the password policy.', 'login-armor' ),
				'disableFailed' => __( 'Could not disable the password policy.', 'login-armor' ),
			],
			'sessionOff'        => [
				'title'        => __( 'Disable session management?', 'login-armor' ),
				'body'         => __( 'Idle timeout, maximum session lifetime, and single-session enforcement will stop applying. Your settings are preserved and restored when you re-enable.', 'login-armor' ),
				'confirmLabel' => __( 'Disable', 'login-armor' ),
				'cancelLabel'  => __( 'Keep enabled', 'login-armor' ),
			],
			'session'           => [
				'enabled'       => __( 'Session management enabled.', 'login-armor' ),
				'disabled'      => __( 'Session management disabled.', 'login-armor' ),
				'saved'         => __( 'Settings saved.', 'login-armor' ),
				'enableFailed'  => __( 'Could not enable session management.', 'login-armor' ),
				'disableFailed' => __( 'Could not disable session management.', 'login-armor' ),
				'loggedOut'     => __( 'Other devices have been signed out.', 'login-armor' ),
				'logoutFailed'  => __( 'Could not sign out other devices.', 'login-armor' ),
			],
			'geoipOff'          => [
				'title'        => __( 'Disable IP geolocation?', 'login-armor' ),
				'body'         => __( 'Attacking IPs will no longer show a country. No further lookups will be sent to the geolocation service.', 'login-armor' ),
				'confirmLabel' => __( 'Disable', 'login-armor' ),
				'cancelLabel'  => __( 'Keep enabled', 'login-armor' ),
			],
			'geoip'             => [
				'enabled'       => __( 'IP geolocation enabled.', 'login-armor' ),
				'disabled'      => __( 'IP geolocation disabled.', 'login-armor' ),
				'enableFailed'  => __( 'Could not enable IP geolocation.', 'login-armor' ),
				'disableFailed' => __( 'Could not disable IP geolocation.', 'login-armor' ),
			],
			'headless'          => [
				'enabled'       => __( 'Headless mode enabled.', 'login-armor' ),
				/* translators: %s: comma-separated list of hardening toggle names. */
				'turnedOff'     => __( 'Headless mode enabled. Turned off: %s.', 'login-armor' ),
				'disabled'      => __( 'Headless mode disabled. Nothing was turned back on.', 'login-armor' ),
				'enableFailed'  => __( 'Could not enable headless mode.', 'login-armor' ),
				'disableFailed' => __( 'Could not disable headless mode.', 'login-armor' ),
				'watchOn'       => __( 'Application-password monitoring enabled.', 'login-armor' ),
				'watchOff'      => __( 'Application-password monitoring disabled.', 'login-armor' ),
				'watchFailed'   => __( 'Could not change application-password monitoring.', 'login-armor' ),
			],
			'headlessOff'       => [
				'title'        => __( 'Disable headless mode?', 'login-armor' ),
				'body'         => __( 'Restrict REST API and Disable application passwords can be switched on again. On a headless back end, either one breaks the front end.', 'login-armor' ),
				'confirmLabel' => __( 'Disable', 'login-armor' ),
				'cancelLabel'  => __( 'Keep enabled', 'login-armor' ),
			],
			'firewallOff'       => [
				'title'        => __( 'Disable the request firewall?', 'login-armor' ),
				'body'         => __( 'Malicious requests will no longer be inspected or blocked. Your rule selection and allowlists are preserved and restored when you re-enable.', 'login-armor' ),
				'confirmLabel' => __( 'Disable', 'login-armor' ),
				'cancelLabel'  => __( 'Keep enabled', 'login-armor' ),
			],
			'firewall'          => [
				'enabled'        => __( 'Request firewall enabled in monitor mode.', 'login-armor' ),
				'disabled'       => __( 'Request firewall disabled.', 'login-armor' ),
				'saved'          => __( 'Firewall settings saved.', 'login-armor' ),
				'enableFailed'   => __( 'Could not enable the request firewall.', 'login-armor' ),
				'disableFailed'  => __( 'Could not disable the request firewall.', 'login-armor' ),
				'ipAdded'        => __( 'Added your current IP to the allowlist.', 'login-armor' ),
				'ipDetectFailed' => __( 'Could not detect your IP.', 'login-armor' ),
			],
			'powOff'            => [
				'title'        => __( 'Disable the bot challenge?', 'login-armor' ),
				'body'         => __( 'Login submissions will no longer have to solve the invisible proof-of-work. Your mode and difficulty are preserved and restored when you re-enable.', 'login-armor' ),
				'confirmLabel' => __( 'Disable', 'login-armor' ),
				'cancelLabel'  => __( 'Keep enabled', 'login-armor' ),
			],
			'pow'               => [
				'enabled'       => __( 'Bot challenge enabled in monitor mode.', 'login-armor' ),
				'disabled'      => __( 'Bot challenge disabled.', 'login-armor' ),
				'saved'         => __( 'Bot challenge settings saved.', 'login-armor' ),
				'enableFailed'  => __( 'Could not enable the bot challenge.', 'login-armor' ),
				'disableFailed' => __( 'Could not disable the bot challenge.', 'login-armor' ),
			],
			'safeBaseline'      => [
				'title'        => __( 'Apply the safe baseline?', 'login-armor' ),
				// 2.7.1: this text still described the 2.6.x baseline. Since
				// 2.7.0 the baseline also enables the request firewall and the
				// bot challenge, in monitor mode, so the dialog was promising
				// the opposite of what the button was about to do.
				'body'         => __( 'This turns on brute-force protection, attack detection, login-page headers, the activity log, the 7 safest hardening toggles, and the request firewall and bot challenge in monitor mode, where they record without blocking. It never changes Hide Login or Two-Factor, and never disables anything.', 'login-armor' ),
				'confirmLabel' => __( 'Apply', 'login-armor' ),
				'cancelLabel'  => __( 'Cancel', 'login-armor' ),
				'applied'      => __( 'Safe baseline applied.', 'login-armor' ),
				'failed'       => __( 'Could not apply the safe baseline.', 'login-armor' ),
			],
			'settingsTransfer'  => [
				'noFile'        => __( 'Choose a settings file first.', 'login-armor' ),
				'fileTooLarge'  => __( 'This file is too large to be a Login Armor settings export.', 'login-armor' ),
				'readFailed'    => __( 'Could not read the file.', 'login-armor' ),
				'previewFailed' => __( 'Could not preview this file.', 'login-armor' ),
				'applyFailed'   => __( 'Import failed. Nothing was changed.', 'login-armor' ),
				/* translators: 1: source host, 2: plugin version, 3: export date. */
				'source'        => __( 'Exported from %1$s (Login Armor %2$s, %3$s)', 'login-armor' ),
				'noChanges'     => __( 'This site already matches the file: nothing to apply.', 'login-armor' ),
				/* translators: 1: number of changes, 2: number of unchanged settings. */
				'summary'       => __( '%1$s setting(s) will change, %2$s already match.', 'login-armor' ),
				'colModule'     => __( 'Module', 'login-armor' ),
				'colSetting'    => __( 'Setting', 'login-armor' ),
				'colCurrent'    => __( 'On this site', 'login-armor' ),
				'colIncoming'   => __( 'In the file', 'login-armor' ),
				'errorsTitle'   => __( 'Errors (the file is refused as a whole):', 'login-armor' ),
				'warningsTitle' => __( 'Please read before applying:', 'login-armor' ),
				'unknownTitle'  => __( 'Ignored (unknown to this version):', 'login-armor' ),
				/* translators: %s: login URL. */
				'loginUrlAfter' => __( 'The login URL will become: %s', 'login-armor' ),
				'confirmTitle'  => __( 'Apply the imported settings?', 'login-armor' ),
				/* translators: 1: number of changes, 2: login URL after import. */
				'confirmBody'   => __( '%1$s setting(s) will change on this site. After the import the login URL will be %2$s. Write it down before confirming.', 'login-armor' ),
				'confirmLabel'  => __( 'Apply', 'login-armor' ),
				'cancelLabel'   => __( 'Cancel', 'login-armor' ),
				/* translators: 1: applied count, 2: unchanged count. */
				'applied'       => __( 'Settings imported: %1$s applied, %2$s unchanged.', 'login-armor' ),
				'failedTitle'   => __( 'Could not apply:', 'login-armor' ),
				'loginUrlNow'   => __( 'Your login URL is now:', 'login-armor' ),
				'reloadLabel'   => __( 'Reload the page', 'login-armor' ),
			],
			'toasts'            => [
				'saveFailed'     => __( 'Save failed.', 'login-armor' ),
				'networkError'   => __( 'Network error.', 'login-armor' ),
			],
		];
	}

	/**
	 * Render the main settings page (v2 shell: top bar + tabs + active tab view).
	 */
	public function render_page(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You do not have permission to access this page.', 'login-armor' ) );
		}

		// Onboarding wizard (shown only when explicitly requested, e.g. by the
		// post-activation redirect). Self-contained view; returns early.
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Read-only routing flag.
		if ( isset( $_GET['la-onboarding'] ) ) {
			// Read BEFORE the write below, which is the only thing that can
			// still tell a first activation from the Settings-tab link back to
			// this screen. The wizard greets the first and reports to the
			// second: "Welcome to Login Armor" on a site that has been running
			// for a year reads as a screen that knows nothing about it.
			$first_run = ! get_option( 'login_armor_onboarded', false );
			// Mark the wizard as seen so it never auto-appears again, even if the
			// admin navigates away without picking a choice.
			update_option( 'login_armor_onboarded', true );
			$admin_nonce = wp_create_nonce( 'login_armor_admin_action' );
			$ajax_url    = admin_url( 'admin-ajax.php' );
			include LOGIN_ARMOR_DIR . 'admin/views/onboarding.php';
			return;
		}

		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Read-only tab routing.
		$active_tab = isset( $_GET['tab'] ) ? sanitize_key( wp_unslash( $_GET['tab'] ) ) : 'overview';

		$allowed_tabs = array( 'overview', 'incidents', 'events', 'activity', 'settings' );
		if ( ! in_array( $active_tab, $allowed_tabs, true ) ) {
			$active_tab = 'overview';
		}

		$overview_nonce = wp_create_nonce( 'login_armor_overview' );
		$admin_nonce    = wp_create_nonce( 'login_armor_admin_action' );
		$ajax_url       = admin_url( 'admin-ajax.php' );

		include LOGIN_ARMOR_DIR . 'admin/views/page.php';
	}

	/**
	 * Force light color scheme on LoginArmor pages to prevent browser dark mode.
	 */
	public function force_light_mode(): void {
		$screen = function_exists( 'get_current_screen' ) ? get_current_screen() : null;
		if ( $screen && $screen->id === $this->hook_suffix ) {
			echo '<meta name="color-scheme" content="light only">' . "\n";
			echo '<meta name="supported-color-schemes" content="light only">' . "\n";
		}
	}

	/**
	 * Remove admin notices on LoginArmor pages only to keep the UI clean.
	 */
	public function maybe_suppress_admin_notices(): void {
		$screen = function_exists( 'get_current_screen' ) ? get_current_screen() : null;
		if ( $screen && $screen->id === $this->hook_suffix ) {
			remove_all_actions( 'admin_notices' );
			remove_all_actions( 'all_admin_notices' );
			// Keep Login Armor's own warnings alive: the blanket suppression
			// above is meant to hide *other* plugins' noise, but until 2.4.2 it
			// also silently removed the plugin's own conflict / incompatibility
			// / htaccess-write notices, i.e. the ones that specifically belong
			// on this page. Re-register them after the purge.
			add_action( 'admin_notices', [ $this, 'safe_mode_notice' ] );
			add_action( 'admin_notices', [ $this, 'safe_mode_unblocked_notice' ] );
			add_action( 'admin_notices', [ $this, 'maybe_render_conflict_notice' ] );
			add_action( 'admin_notices', [ $this, 'htaccess_write_failed_notice' ] );
			add_action( 'admin_notices', [ $this, 'htaccess_ambiguous_notice' ] );
			add_action( 'admin_notices', [ $this, 'ip_identity_notice' ] );
			add_action( 'admin_notices', [ $this, 'https_terminator_notice' ] );
			add_action( 'admin_notices', [ $this, 'notif_suppressed_notice' ] );
		}
	}

	/**
	 * Add a body class on the LoginArmor admin page so CSS can go full-bleed.
	 *
	 * Parameter untyped with a default; non-strings are normalized because
	 * the return value is always rebuilt as a string here.
	 *
	 * @param mixed $classes Existing body classes (expected string).
	 * @return string
	 */
	public function maybe_add_body_class( $classes = '' ): string {
		if ( ! is_string( $classes ) ) {
			$classes = '';
		}
		$screen = function_exists( 'get_current_screen' ) ? get_current_screen() : null;
		if ( $screen && $screen->id === $this->hook_suffix ) {
			$classes .= ' login-armor-page';
		}
		return $classes;
	}

	/**
	 * Register the LoginArmor dashboard widget.
	 */
	public function register_dashboard_widget(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}

		wp_add_dashboard_widget(
			'login_armor_dashboard',
			'Login Armor',
			[ $this, 'render_dashboard_widget' ]
		);
	}

	/**
	 * Render the dashboard widget content.
	 */
	public function render_dashboard_widget(): void {
		include LOGIN_ARMOR_DIR . 'admin/views/widget-dashboard.php';
	}

	/**
	 * Enqueue admin CSS on the WP Dashboard screen for the widget.
	 *
	 * Parameter untyped with a default: `admin_enqueue_scripts` can be
	 * re-fired by admin-page plugins without arguments.
	 *
	 * @param mixed $hook_suffix The current admin page hook suffix (expected string).
	 */
	public function maybe_enqueue_widget_css( $hook_suffix = '' ): void {
		if ( 'index.php' !== $hook_suffix || ! current_user_can( 'manage_options' ) ) {
			return;
		}

		$css_path = LOGIN_ARMOR_DIR . 'admin/assets/css/admin.css';
		$css_version = file_exists( $css_path ) ? substr( md5_file( $css_path ), 0, 8 ) : LOGIN_ARMOR_VERSION;

		wp_enqueue_style(
			'login-armor-widget',
			LOGIN_ARMOR_URL . 'admin/assets/css/admin.css',
			[],
			$css_version
		);
	}

	/**
	 * Show a warning if a conflicting login plugin is detected.
	 */
	public function conflict_notice(): void {
		$conflict = HideLogin::get_conflicting_plugin();
		if ( false === $conflict || ! HideLogin::is_enabled() ) {
			return;
		}
		printf(
			'<div class="notice la-notice notice-warning is-dismissible"><p>%s</p></div>',
			sprintf(
				/* translators: %s: conflicting plugin name */
				esc_html__( 'Login Armor Hide Login may conflict with %s. Please deactivate one of them to avoid unexpected behavior.', 'login-armor' ),
				'<strong>' . esc_html( $conflict ) . '</strong>'
			)
		);
	}

	/**
	 * Show a notice when a recent .htaccess write failed.
	 *
	 * Failed writes are recorded in a 5-minute transient by the hardening
	 * module (Block PHP in uploads / Disable directory listing toggles).
	 * Without this notice the toggle would appear saved while the on-disk
	 * rule was actually never written.
	 */
	public function htaccess_write_failed_notice(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}
		$path = get_transient( 'login_armor_htaccess_write_failed' );
		if ( false === $path || '' === $path ) {
			return;
		}
		delete_transient( 'login_armor_htaccess_write_failed' );

		// 2.7.1: the reason comes from the durable record, which the same
		// writer stamped at the same instant. The transient only says "recent
		// enough to still be worth mentioning"; it never carried the reason,
		// which is why this notice sent everybody to look at permissions,
		// including the people whose permissions were correct and whose only
		// problem was a concurrent save.
		$failure = get_option( Hardening::OPTION_HTACCESS_LAST_FAILURE, array() );
		$reason  = is_array( $failure ) ? (string) ( $failure['kind'] ?? 'write' ) : 'write';

		// A cause that repairs itself is stated calmly and is not an error:
		// nothing is broken, and the next save applies the rule. Dressing that
		// up in red teaches administrators to ignore the red ones that matter.
		$transient = Hardening::htaccess_failure_is_transient( $reason );

		printf(
			'<div class="notice la-notice %s is-dismissible"><p>%s</p></div>',
			$transient ? 'notice-info' : 'notice-error',
			esc_html( Hardening::htaccess_failure_message( $reason, (string) $path ) )
		);
	}

	/**
	 * Show a notice when an .htaccess block could not be delimited.
	 *
	 * The hardening module refuses to touch a file whose LoginArmor block
	 * carries a BEGIN without its END, an END without its BEGIN, or two
	 * BEGINs: nothing in such a file says where the administrator's own
	 * rules resume, and guessing is how the rules got lost in the first
	 * place. Until a human repairs the markers, the toggle and the file
	 * legitimately disagree, and only this notice says so.
	 *
	 * @since 2.6.1
	 */
	public function htaccess_ambiguous_notice(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}
		$path = get_transient( 'login_armor_htaccess_ambiguous' );
		if ( false === $path || '' === $path ) {
			return;
		}
		delete_transient( 'login_armor_htaccess_ambiguous' );
		printf(
			'<div class="notice la-notice notice-warning is-dismissible"><p>%s</p></div>',
			sprintf(
				/* translators: %s: full path of the .htaccess file that was left untouched. */
				esc_html__( 'Login Armor left %s untouched: it contains Login Armor markers that do not form exactly one complete block. Nothing says where your own rules resume, so the file was not rewritten. Repair the markers by hand, then re-toggle the affected hardening rule. Until then the toggle and the file may disagree.', 'login-armor' ),
				'<code>' . esc_html( (string) $path ) . '</code>'
			)
		);
	}

	/**
	 * Say, on every admin page, that the site is running with its guard down.
	 *
	 * Not dismissible on purpose. Safe mode is meant to last minutes, the time
	 * to get back in; the failure mode is a constant added during an incident
	 * and never removed, and a notice that can be clicked away is exactly how
	 * that happens. It disappears when the wp-config.php line does.
	 *
	 * Brute-force lockouts deliberately stay active in safe mode, so the notice
	 * carries the one action an administrator locked out on their own address
	 * still needs: clearing that address.
	 *
	 * @since 2.7.0
	 */
	public function safe_mode_notice(): void {
		if ( ! current_user_can( 'manage_options' ) || ! LoginArmor::is_safe_mode() ) {
			return;
		}

		$ip        = LoginArmor::get_client_ip();
		$unblock   = wp_nonce_url(
			admin_url( 'admin-post.php?action=login_armor_safe_mode_unblock' ),
			'login_armor_safe_mode_unblock'
		);
		$locked    = LimitLogin::is_ip_locked( $ip );
		$body      = self::safe_mode_body( ! empty( Hardening::get_settings()['force_https'] ) );
		$next_step = __( 'Remove that line from wp-config.php as soon as you are back in, to restore protection.', 'login-armor' );
		$lockouts  = __( 'Brute-force lockouts are still active: safe mode never lifts one by itself.', 'login-armor' );

		printf(
			'<div class="notice la-notice notice-error"><p><strong>%s</strong></p><p>%s</p><p>%s %s</p><p><a class="button" href="%s">%s</a></p></div>',
			esc_html__( 'Login Armor: safe mode is active.', 'login-armor' ),
			esc_html( $body ),
			esc_html( $lockouts ),
			esc_html( $next_step ),
			esc_url( $unblock ),
			$locked
				/* translators: %s: the administrator's own IP address. */
				? esc_html( sprintf( __( 'Unblock my IP (%s), currently locked', 'login-armor' ), $ip ) )
				/* translators: %s: the administrator's own IP address. */
				: esc_html( sprintf( __( 'Unblock my IP (%s)', 'login-armor' ), $ip ) )
		);
	}

	/**
	 * What safe mode has stood down, in one sentence.
	 *
	 * Two complete alternatives rather than a clause glued on: a translator
	 * needs the whole enumeration to get the agreement and the ordering right
	 * in their language, and the one the site actually reads has to be a
	 * sentence, not a list that grows a line every release.
	 *
	 * Keyed on the STORED toggle, and only on it. A site that never switched
	 * Force HTTPS on must not be told about a protection it does not use, and
	 * Hardening::force_https_effective() is false for EVERY site in safe mode,
	 * so it could never tell the two apart.
	 *
	 * Pure and static, which is what lets the offline suite drive both
	 * branches without a WordPress admin screen.
	 *
	 * @since 2.7.0
	 *
	 * @param bool $force_https_on Whether the Force HTTPS toggle is stored on.
	 */
	public static function safe_mode_body( bool $force_https_on ): string {
		if ( $force_https_on ) {
			return __( 'Login Armor is running in safe mode because LOGIN_ARMOR_SAFE_MODE is defined in wp-config.php. wp-login.php is served, two-factor authentication is not required, the request firewall and the bot challenge only log, single-session enforcement is paused, and the Force HTTPS hardening toggle enforces nothing. Your settings are untouched.', 'login-armor' );
		}

		return __( 'Login Armor is running in safe mode because LOGIN_ARMOR_SAFE_MODE is defined in wp-config.php. wp-login.php is served, two-factor authentication is not required, the request firewall and the bot challenge only log, and single-session enforcement is paused. Your settings are untouched.', 'login-armor' );
	}

	/**
	 * Clear the brute-force lockout on the address the administrator is using.
	 *
	 * The deliberate counterpart of safe mode leaving lockouts alone: the
	 * constant does not lift them, this button does, for one address, on an
	 * explicit click, behind a nonce and a capability.
	 *
	 * @since 2.7.0
	 */
	public function handle_safe_mode_unblock(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You are not allowed to do this.', 'login-armor' ), 403 );
		}

		check_admin_referer( 'login_armor_safe_mode_unblock' );

		$ip       = LoginArmor::get_client_ip();
		$released = LimitLogin::release_ip( $ip );

		// 2.8.0: a removed network block counts as something cleared, so the
		// notice says "unblocked" rather than "was not blocked".
		$redirect = add_query_arg(
			[
				'login_armor_unblocked' => (int) $released['rows'],
				'login_armor_subnet'    => '' !== $released['subnet'] ? 1 : 0,
			],
			wp_get_referer() ? wp_get_referer() : admin_url()
		);
		wp_safe_redirect( $redirect );
		exit;
	}

	/**
	 * Say whether the unblock button actually cleared anything.
	 *
	 * The handler already redirects with the row count; without this it went
	 * nowhere, so the administrator clicked a button and the page came back
	 * looking identical whether their address had been banned or not. Both
	 * answers are useful: "nothing to clear" means the lockout is not what is
	 * keeping them out, and sends them to the next item of `wp login-armor
	 * rescue` instead of clicking again.
	 *
	 * @since 2.7.0
	 */
	public function safe_mode_unblocked_notice(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Read-only flag; the state change already happened behind a nonce in handle_safe_mode_unblock().
		if ( ! isset( $_GET['login_armor_unblocked'] ) ) {
			return;
		}
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Read-only flag, see above.
		$removed = absint( wp_unslash( $_GET['login_armor_unblocked'] ) );
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Read-only flag, see above.
		$subnet = ! empty( $_GET['login_armor_subnet'] );

		if ( $subnet ) {
			printf(
				'<div class="notice la-notice notice-success is-dismissible"><p>%s</p></div>',
				esc_html__( 'Login Armor: your IP address has been unblocked. The blocked network that contained it was removed from the blocklist.', 'login-armor' )
			);
			return;
		}

		if ( $removed < 1 ) {
			printf(
				'<div class="notice la-notice notice-info is-dismissible"><p>%s</p></div>',
				esc_html__( 'Login Armor: your IP address was not blocked, so there was nothing to clear. If you still cannot get in, the lockout is not the cause.', 'login-armor' )
			);
			return;
		}

		printf(
			'<div class="notice la-notice notice-success is-dismissible"><p>%s</p></div>',
			esc_html(
				sprintf(
					/* translators: %d: number of database records removed. */
					_n(
						'Login Armor: your IP address has been unblocked (%d record removed).',
						'Login Armor: your IP address has been unblocked (%d records removed).',
						$removed,
						'login-armor'
					),
					$removed
				)
			)
		);
	}

	/**
	 * Show while Force HTTPS is on but has switched itself off (2.7.0).
	 *
	 * Something upstream reports that visitors arrive over HTTPS, from an
	 * address this site does not declare as a proxy. In that state none of
	 * the option's effects can be applied without locking the administrator
	 * out, so the module registers nothing and leaves this marker instead.
	 *
	 * THE ADDRESSES ARE AN OBSERVATION, NOT AN INSTRUCTION. Anyone on the
	 * internet can cause this notice by sending a forwarded-protocol header,
	 * and an address on the trusted-proxy list is believed when it declares
	 * a visitor's IP, which is the identity every lockout and quota in this
	 * plugin rests on. A notice that said "add this address" would therefore
	 * be a way for an attacker to have the plugin ask its own administrator
	 * to trust the attacker. So it reports what was seen, says who can cause
	 * it, and names the only safe next step: ask the host or the CDN what
	 * their terminator actually is. When more than one address has been
	 * seen, it says that too, because that shape is not a terminator.
	 *
	 * NOT dismissible, and the marker is NOT cleared here: the situation
	 * lasts until the proxy is declared, and the module removes the marker
	 * itself on the first request after that. A notice that could be
	 * dismissed would hide a site that believes it enforces HTTPS and does
	 * not.
	 *
	 * @since 2.7.0
	 */
	public function https_terminator_notice(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}
		$state = \LoginArmor\Hardening::undeclared_terminator();
		if ( null === $state ) {
			return;
		}

		$addresses = array();
		foreach ( $state['peers'] as $peer ) {
			$addresses[] = '<code>' . esc_html( (string) $peer ) . '</code>';
		}
		$several = $state['distinct'] > 1 || $state['more'];

		$lines = array(
			esc_html__( 'Force HTTPS is switched on but is enforcing nothing at the moment. Something in front of this site reports that your visitors arrive over HTTPS, from an address that is not listed in Trusted proxy IPs. Login Armor has no way to verify that claim, and applying the option on an unverified claim would send visitors into a redirect loop and stop anyone signing in, so the whole option stands down until the proxy is declared.', 'login-armor' ),
			sprintf(
				/* translators: %s: one or more IP addresses, already wrapped in <code> tags. */
				esc_html__( 'Observed so far: %s.', 'login-armor' ),
				implode( ', ', $addresses )
			),
		);

		if ( $several ) {
			$lines[] = esc_html__( 'Several different addresses have sent that header. A real terminator is one address, or a small stable set, so this pattern is what forgery looks like rather than a proxy you forgot to declare. Treat it as forgery unless your host tells you otherwise.', 'login-armor' );
		}

		$lines[] = esc_html__( 'Do not add an address to Trusted proxy IPs because it appears here. Any visitor can make this notice appear by sending one request, and an address on that list is believed when it tells Login Armor who your visitors are, which is what every lockout and ban depends on. Ask your host or your CDN which address their terminator uses, and add only that one.', 'login-armor' );

		printf(
			'<div class="notice la-notice notice-warning"><p>%s</p></div>',
			wp_kses( implode( ' ', $lines ), array( 'code' => array() ) )
		);
	}

	/** Show when proxy settings prevent a safe per-client identity. */
	public function ip_identity_notice(): void {
		if ( ! current_user_can( 'manage_options' ) || false === get_transient( 'login_armor_ip_method_misconfigured' ) ) {
			return;
		}
		delete_transient( 'login_armor_ip_method_misconfigured' );
		printf(
			'<div class="notice la-notice notice-warning is-dismissible"><p>%s</p></div>',
			esc_html__( 'Login Armor could not determine a reliable visitor IP. Per-client lockouts and security quotas are paused to avoid blocking every visitor. Verify the IP detection method and trusted proxy list in Login Armor settings.', 'login-armor' )
		);
	}

	/**
	 * Show a notice while the hourly notification cap is swallowing alerts.
	 *
	 * The cap exists so a flood cannot turn the site into a mail or webhook
	 * relay, but a cap that drops alerts without saying so is indistinguishable
	 * from a quiet hour. This notice, the counter in the Notifications section
	 * and the line appended to the next successful alert are the three places
	 * that say it out loud.
	 *
	 * Shown until the backlog is announced: it is cleared by a successful
	 * send carrying the count, not by the turn of the hour, so an operator
	 * who opens the admin at 14:05 still learns about a 13:20 flood.
	 *
	 * @since 2.6.1
	 */
	public function notif_suppressed_notice(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}
		if ( ! class_exists( '\\LoginArmor\\Notifications\\Dispatcher' ) ) {
			return;
		}
		// Cheap autoloaded gate first: the counter lives in a row that has to
		// be read uncached, and there is nothing to read when the module is off.
		if ( 'disabled' === (string) get_option( 'login_armor_notif_channel', 'disabled' ) ) {
			return;
		}

		$suppressed = \LoginArmor\Notifications\Dispatcher::get_suppressed();
		if ( $suppressed['count'] < 1 ) {
			return;
		}

		$since = \LoginArmor\Notifications\Dispatcher::suppressed_since_label( $suppressed['hour'] ) . ' UTC';

		// Which cap refused decides what to advise. A critical alert draws on
		// its reserve first and only falls back to the ordinary bucket, so a
		// refused critical means both were full, and saying so is the
		// difference between an actionable notice and a puzzling one.
		//
		// The two branches are assembled with plain __() and escaped once, at
		// the point of output. Escaping inside the branches and printing the
		// variable is what a static analyser cannot follow, and it would also
		// double-escape: a French translation carrying an apostrophe would
		// reach the screen as &amp;#039;.
		$message = \LoginArmor\Notifications\Dispatcher::CRITICAL_SEVERITY <= (int) $suppressed['max_severity']
			? sprintf(
				/* translators: 1: number of alerts not sent, 2: start of the hour in UTC, e.g. 13:00 UTC. */
				__( 'Login Armor did not send %1$d alerts since %2$s, critical ones included: the hourly notification cap was reached, and so were the slots held in reserve for critical alerts. Raise the limit in the Notifications settings if you need every alert.', 'login-armor' ),
				(int) $suppressed['count'],
				$since
			)
			: sprintf(
				/* translators: 1: number of alerts not sent, 2: start of the hour in UTC, e.g. 13:00 UTC. */
				__( 'Login Armor did not send %1$d alerts since %2$s: the hourly notification cap was reached. Critical alerts keep a reserve of their own and were not affected. Raise the limit in the Notifications settings if you need every alert.', 'login-armor' ),
				(int) $suppressed['count'],
				$since
			);

		printf( '<div class="notice la-notice notice-warning is-dismissible"><p>%s</p></div>', esc_html( $message ) );
	}

	/**
	 * AJAX: return the Overview dashboard payload as JSON.
	 *
	 * Polled every 10 seconds by the Overview tab JS module to refresh
	 * the live events tail, threat bar, stats and sparkline without a full
	 * page reload. Nonce-protected with a dedicated action to isolate the
	 * attack surface from other endpoints.
	 */
	public function ajax_overview_data(): void {
		check_ajax_referer( 'login_armor_overview', 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => 'forbidden' ), 403 );
		}
		wp_send_json_success( \LoginArmor\Overview::get_dashboard_data() );
	}

	/**
	 * AJAX: persist a skipped advice key in user meta.
	 *
	 * Used by the Overview « all-quiet » CTA so that dismissed proactive
	 * suggestions don't surface again for the same user.
	 */
	public function ajax_skip_advice(): void {
		$this->guard_admin_action();

		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Verified in guard_admin_action().
		$key     = isset( $_POST['key'] ) ? sanitize_key( wp_unslash( $_POST['key'] ) ) : '';
		// Keep in sync with the candidate keys of Overview::get_next_advice():
		// an advice whose key is missing here cannot be dismissed and comes
		// back on every single page load.
		$allowed = array( '2fa', 'hide-login', 'breach-check', 'notifications', 'firewall-enforce', 'pow-enforce' );
		if ( ! in_array( $key, $allowed, true ) ) {
			wp_send_json_error( array( 'message' => 'invalid key' ), 400 );
		}

		$user_id = get_current_user_id();
		$skipped = (array) get_user_meta( $user_id, 'login_armor_skipped_advice', true );
		if ( ! in_array( $key, $skipped, true ) ) {
			$skipped[] = $key;
			update_user_meta( $user_id, 'login_armor_skipped_advice', $skipped );
		}

		wp_send_json_success( array( 'skipped' => $skipped ) );
	}

	/**
	 * Shared guard for all admin-action AJAX endpoints.
	 * Dies via `wp_send_json_error` on failure.
	 */
	private function guard_admin_action(): void {
		check_ajax_referer( 'login_armor_admin_action', 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => 'forbidden' ), 403 );
		}
	}

	/**
	 * AJAX: generate a plain-language AI explanation for one incident.
	 *
	 * On-demand only (the admin clicked "Explain with AI"); strictly minimised
	 * data leaves the site (see IncidentExplainer). The returned HTML is already
	 * escaped by Client::format_markdown().
	 */
	public function ajax_ai_explain_incident(): void {
		$this->guard_admin_action();

		if ( ! \LoginArmor\AI\Client::is_available() ) {
			wp_send_json_error( array( 'message' => __( 'The AI layer is not available.', 'login-armor' ) ), 400 );
		}

		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Verified in guard_admin_action().
		$id = isset( $_POST['id'] ) ? (int) $_POST['id'] : 0;
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Verified in guard_admin_action().
		$force = ! empty( $_POST['force'] );
		if ( $id <= 0 ) {
			wp_send_json_error( array( 'message' => __( 'Invalid incident ID.', 'login-armor' ) ), 400 );
		}

		require_once LOGIN_ARMOR_DIR . 'includes/AI/IncidentExplainer.php';
		$incident = \LoginArmor\Detection\Incident::find_by_id( $id );
		if ( null === $incident ) {
			wp_send_json_error( array( 'message' => __( 'Incident not found.', 'login-armor' ) ), 404 );
		}

		// `$persisted` false means the reading exists but the row would not
		// take it, so it is gone on the next page load. Saying so is the whole
		// point: silence here is what makes an administrator generate, and pay
		// for, the same analysis over and over (2.7.2).
		$persisted = null;
		$result    = \LoginArmor\AI\IncidentExplainer::explain( $incident, $force, $persisted );
		if ( is_wp_error( $result ) ) {
			wp_send_json_error( array( 'message' => $result->get_error_message() ) );
		}
		wp_send_json_success(
			array(
				'html'    => $result,
				'warning' => false === $persisted
					? __( 'This analysis could not be saved, so it will be gone when you leave this page. Tools > Site Health says why.', 'login-armor' )
					: '',
			)
		);
	}

	/**
	 * AJAX: generate a prioritised AI hardening plan (config × 30-day threat).
	 *
	 * PII-free by construction (see PostureAdvisor). Returned HTML is escaped.
	 */
	public function ajax_ai_posture(): void {
		$this->guard_admin_action();

		if ( ! \LoginArmor\AI\Client::is_available() ) {
			wp_send_json_error( array( 'message' => __( 'The AI layer is not available.', 'login-armor' ) ), 400 );
		}

		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Verified in guard_admin_action().
		$force = ! empty( $_POST['force'] );

		require_once LOGIN_ARMOR_DIR . 'includes/AI/PostureAdvisor.php';
		$result = \LoginArmor\AI\PostureAdvisor::analyze( $force );
		if ( is_wp_error( $result ) ) {
			wp_send_json_error( array( 'message' => $result->get_error_message() ) );
		}
		wp_send_json_success( array( 'html' => $result ) );
	}

	/**
	 * AJAX: grant the WordPress 7 connector approval so LoginArmor may use the
	 * site's configured AI connector.
	 */
	public function ajax_ai_approve(): void {
		$this->guard_admin_action();
		\LoginArmor\AI\Client::grant_approval();
		wp_send_json_success( array( 'approved' => true ) );
	}

	/**
	 * AJAX: revoke the WordPress 7 connector approval.
	 */
	public function ajax_ai_revoke(): void {
		$this->guard_admin_action();
		\LoginArmor\AI\Client::revoke_approval();
		wp_send_json_success( array( 'approved' => false ) );
	}

	/**
	 * AJAX: save the AI Assistant settings (enable + deep-analysis cursor) in one
	 * round-trip, through the standard Settings "Save" bar. Deep mode sends real
	 * IPs to the site's own connector, so it must be an explicit, confirmed save
	 * rather than an instant on-change toggle.
	 */
	public function ajax_ai_save_settings(): void {
		$this->guard_admin_action();
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Verified in guard_admin_action().
		$enabled = isset( $_POST['ai_enabled'] ) && '1' === $_POST['ai_enabled'];
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Verified in guard_admin_action().
		$deep = isset( $_POST['ai_deep'] ) && '1' === $_POST['ai_deep'];
		update_option( \LoginArmor\AI\Client::OPTION_ENABLED, $enabled, false );
		update_option( \LoginArmor\AI\Client::OPTION_DEEP, $deep, false );
		wp_send_json_success( array( 'enabled' => $enabled, 'deep' => $deep ) );
	}

	/**
	 * AJAX: resolve an incident.
	 */
	public function ajax_incident_resolve(): void {
		$this->guard_admin_action();
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Verified in guard_admin_action().
		$id = isset( $_POST['id'] ) ? (int) $_POST['id'] : 0;
		if ( $id <= 0 ) {
			wp_send_json_error( array( 'message' => 'invalid_id' ), 400 );
		}
		$ok = \LoginArmor\Detection\Incident::resolve( $id );
		if ( ! $ok ) {
			wp_send_json_error( array( 'message' => 'db_error' ), 500 );
		}
		wp_send_json_success( array( 'id' => $id, 'status' => 'resolved' ) );
	}

	/**
	 * AJAX: mark an incident as ignored.
	 */
	public function ajax_incident_ignore(): void {
		$this->guard_admin_action();
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Verified in guard_admin_action().
		$id = isset( $_POST['id'] ) ? (int) $_POST['id'] : 0;
		if ( $id <= 0 ) {
			wp_send_json_error( array( 'message' => 'invalid_id' ), 400 );
		}
		$ok = \LoginArmor\Detection\Incident::ignore( $id );
		if ( ! $ok ) {
			wp_send_json_error( array( 'message' => 'db_error' ), 500 );
		}
		wp_send_json_success( array( 'id' => $id, 'status' => 'ignored' ) );
	}

	/**
	 * AJAX: bulk-resolve or bulk-ignore incidents in one round-trip.
	 *
	 * Two scopes. `page` is the historical one: POST `ids`, a comma-separated
	 * list of exactly what the administrator ticked. `filtered` (2.7.1) applies
	 * the operation to EVERY incident matching the filters the list is showing,
	 * which is what the header checkbox could never do: it ticks the 25 rows
	 * the page rendered, so clearing 235 open incidents meant repeating the
	 * whole operation ten times.
	 *
	 * The filtered scope sends filters, never 235 ids in a POST body: the
	 * filter is what the screen promised, so the filter is what the UPDATE
	 * uses, through the same Incident::sanitize_filters() the list itself goes
	 * through. The response carries what actually changed and what is left, so
	 * a run that hits the per-request ceiling says so instead of looking done.
	 */
	public function ajax_incidents_bulk(): void {
		$this->guard_admin_action();

		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Verified in guard_admin_action().
		$op = isset( $_POST['op'] ) ? sanitize_key( wp_unslash( $_POST['op'] ) ) : '';
		if ( ! in_array( $op, array( 'resolve', 'ignore' ), true ) ) {
			wp_send_json_error( array( 'message' => 'invalid_op' ), 400 );
		}
		$status = 'resolve' === $op
			? \LoginArmor\Detection\Incident::STATUS_RESOLVED
			: \LoginArmor\Detection\Incident::STATUS_IGNORED;

		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Verified in guard_admin_action().
		$scope = isset( $_POST['scope'] ) ? sanitize_key( wp_unslash( $_POST['scope'] ) ) : 'page';

		if ( 'filtered' === $scope ) {
			// phpcs:disable WordPress.Security.NonceVerification.Missing -- Verified in guard_admin_action().
			$raw = array(
				'status'       => isset( $_POST['status'] ) ? sanitize_key( wp_unslash( $_POST['status'] ) ) : '',
				'pattern'      => isset( $_POST['pattern'] ) ? sanitize_key( wp_unslash( $_POST['pattern'] ) ) : '',
				'severity'     => isset( $_POST['severity'] ) ? (int) $_POST['severity'] : 0,
				'min_severity' => isset( $_POST['min_severity'] ) ? (int) $_POST['min_severity'] : 0,
				'period'       => isset( $_POST['period'] ) ? sanitize_key( wp_unslash( $_POST['period'] ) ) : '',
			);
			// phpcs:enable WordPress.Security.NonceVerification.Missing

			// Which filters the caller actually sent. The bar posts all five
			// keys and leaves the unused ones neutral, so a neutral value is
			// not a filter; anything else is, and a value that does not
			// survive sanitize_filters() is one this endpoint cannot honour.
			//
			// Dropping it and carrying on is the dangerous reading, because
			// the filter that disappears is the one that was NARROWING the
			// operation: `pattern=firewal_block` misspelt by one letter turns
			// "resolve the firewall observations" into "resolve everything".
			// The command line has refused this since 2.7.1; a POST body is no
			// more trustworthy than a typed argument, and this is the only
			// operation in the plugin that writes rows the caller never named.
			//
			// No filter at all stays legal, unlike on the command line: here
			// the screen has already shown the set and named its size in the
			// confirmation, which is the check `--all` has to ask for in words.
			$given = 0;
			foreach ( $raw as $value ) {
				if ( '' !== (string) $value && '0' !== (string) $value ) {
					++$given;
				}
			}

			$filters = \LoginArmor\Detection\Incident::sanitize_filters( $raw );
			if ( count( $filters ) !== $given ) {
				wp_send_json_error( array( 'message' => 'invalid_filter' ), 400 );
			}

			$pending = \LoginArmor\Detection\Incident::pending( $filters, $status );
			$matched = \LoginArmor\Detection\Incident::count_filtered( $pending );
			$updated = \LoginArmor\Detection\Incident::bulk_set_status_filtered( $filters, $status );

			wp_send_json_success(
				array(
					'op'        => $op,
					'scope'     => 'filtered',
					'updated'   => $updated,
					'matched'   => $matched,
					// Rows the operation would still change, counted with the
					// predicate it actually used. Non-zero means the ceiling
					// was reached and another click is due; counting the plain
					// filter here would report the rows just resolved as work
					// remaining, on a run that finished.
					'remaining' => \LoginArmor\Detection\Incident::count_filtered( $pending ),
					'status'    => $status,
				)
			);
		}

		// IDs arrive as a comma-separated string (the admin JS sends ids.join(',')).
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Verified in guard_admin_action().
		$raw = isset( $_POST['ids'] ) ? sanitize_text_field( wp_unslash( (string) $_POST['ids'] ) ) : '';
		$ids = array_values( array_filter( array_map( 'intval', explode( ',', $raw ) ), static fn( $id ) => $id > 0 ) );

		if ( empty( $ids ) ) {
			wp_send_json_error( array( 'message' => 'no_ids' ), 400 );
		}

		$updated = 'resolve' === $op
			? \LoginArmor\Detection\Incident::bulk_resolve( $ids )
			: \LoginArmor\Detection\Incident::bulk_ignore( $ids );

		wp_send_json_success(
			array(
				'op'      => $op,
				'scope'   => 'page',
				'updated' => $updated,
				'status'  => $status,
			)
		);
	}

	/**
	 * AJAX: block the /24 (IPv4) or /64 (IPv6) subnet containing the given IP.
	 */
	public function ajax_subnet_block(): void {
		$this->guard_admin_action();
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Verified in guard_admin_action().
		$ip = isset( $_POST['ip'] ) ? sanitize_text_field( wp_unslash( $_POST['ip'] ) ) : '';
		if ( ! filter_var( $ip, FILTER_VALIDATE_IP ) ) {
			wp_send_json_error( array( 'message' => 'invalid_ip' ), 400 );
		}
		$subnet = LimitLogin::subnet_of( $ip );
		if ( '' === $subnet ) {
			wp_send_json_error( array( 'message' => 'invalid_ip' ), 400 );
		}
		// 2.8.0: never the administrator's own network. Same rule as the
		// settings import, which has refused this since 2.6.0.
		if ( LimitLogin::would_lock_out_current_user( $ip ) ) {
			wp_send_json_error(
				array(
					'message' => 'own_subnet',
					'notice'  => __( 'This network contains your own address: blocking it would lock you out. Add your address to the IP safelist first if you really want to block it.', 'login-armor' ),
				),
				409
			);
		}
		LimitLogin::add_blocked_subnet( $subnet );
		wp_send_json_success( array( 'subnet' => $subnet ) );
	}

	/**
	 * AJAX: remove a manually-blocked /24 subnet derived from an IP.
	 *
	 * The UI passes the IP; the server resolves it to the /24 subnet the
	 * IP belongs to, then calls LimitLogin::remove_blocked_subnet. This
	 * mirrors the convention of ajax_subnet_block (which also takes an
	 * IP and derives the /24 server-side).
	 */
	public function ajax_subnet_unblock(): void {
		$this->guard_admin_action();

		// phpcs:disable WordPress.Security.NonceVerification.Missing -- Verified in guard_admin_action().
		$ip = isset( $_POST['ip'] )
			? sanitize_text_field( wp_unslash( (string) $_POST['ip'] ) )
			: '';
		// phpcs:enable

		if ( '' === $ip || false === filter_var( $ip, FILTER_VALIDATE_IP ) ) {
			wp_send_json_error( array( 'message' => __( 'Invalid IP.', 'login-armor' ) ), 400 );
		}

		$subnet  = LimitLogin::subnet_of( $ip );
		$removed = LimitLogin::remove_blocked_subnet( $subnet );

		wp_send_json_success(
			array(
				'ip'      => $ip,
				'subnet'  => $subnet,
				'removed' => (bool) $removed,
			)
		);
	}

	/**
	 * AJAX: unblock an IP (remove lockout rows and any subnet containing it).
	 * v2 version: kept separate from the v1 `ajax_unblock_ip` to avoid mixing
	 * nonce schemes during the v1→v2 migration.
	 */
	public function ajax_ip_unblock_v2(): void {
		$this->guard_admin_action();
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Verified in guard_admin_action().
		$ip = isset( $_POST['ip'] ) ? sanitize_text_field( wp_unslash( $_POST['ip'] ) ) : '';
		if ( ! filter_var( $ip, FILTER_VALIDATE_IP ) ) {
			wp_send_json_error( array( 'message' => 'invalid_ip' ), 400 );
		}
		$released = LimitLogin::release_ip( $ip );
		wp_send_json_success(
			array(
				'ip'      => $ip,
				'deleted' => $released['rows'],
				'subnet'  => LimitLogin::subnet_of( $ip ),
			)
		);
	}

	/**
	 * AJAX: stream the filtered events log as a CSV download.
	 */
	public function ajax_events_export(): void {
		$this->guard_admin_action();

		// phpcs:disable WordPress.Security.NonceVerification.Missing -- Verified in guard_admin_action().
		$filters = array(
			'status'   => isset( $_POST['status'] ) ? sanitize_key( wp_unslash( $_POST['status'] ) ) : '',
			'ip'       => isset( $_POST['ip'] ) ? sanitize_text_field( wp_unslash( $_POST['ip'] ) ) : '',
			'username' => isset( $_POST['username'] ) ? sanitize_text_field( wp_unslash( $_POST['username'] ) ) : '',
			'period'   => isset( $_POST['period'] ) ? sanitize_key( wp_unslash( $_POST['period'] ) ) : '',
			'source'   => isset( $_POST['source'] ) ? sanitize_key( wp_unslash( $_POST['source'] ) ) : '',
		);
		// phpcs:enable WordPress.Security.NonceVerification.Missing

		nocache_headers();
		header( 'Content-Type: text/csv; charset=utf-8' );
		header( 'Content-Disposition: attachment; filename="login-armor-events-' . gmdate( 'Ymd-His' ) . '.csv"' );

		while ( ob_get_level() > 0 ) {
			ob_end_clean();
		}

		LoginLogs::export_csv_stream( $filters );
		exit;
	}

	/**
	 * AJAX: stream the filtered activity log as a CSV download.
	 *
	 * Mirrors ajax_events_export() but for the Activity Log table. Filters
	 * are read from POST: object_type, user_id, period.
	 */
	public function ajax_activity_export(): void {
		$this->guard_admin_action();

		// phpcs:disable WordPress.Security.NonceVerification.Missing -- Verified in guard_admin_action().
		$filters = [
			'object_type' => isset( $_POST['object_type'] ) ? sanitize_key( wp_unslash( $_POST['object_type'] ) ) : '',
			'user_id'     => isset( $_POST['user_id'] ) ? (int) $_POST['user_id'] : 0,
			'period'      => isset( $_POST['period'] ) ? sanitize_key( wp_unslash( $_POST['period'] ) ) : '',
		];
		// phpcs:enable WordPress.Security.NonceVerification.Missing

		nocache_headers();
		header( 'Content-Type: text/csv; charset=utf-8' );
		header( 'Content-Disposition: attachment; filename="login-armor-activity-' . gmdate( 'Ymd-His' ) . '.csv"' );

		while ( ob_get_level() > 0 ) {
			ob_end_clean();
		}

		\LoginArmor\ActivityLog\ActivityLog::export_csv_stream( $filters );
		exit;
	}

	/**
	 * AJAX: regenerate the Hide Login slug.
	 *
	 * Nonce and capability are verified by guard_admin_action(). The new slug
	 * goes through validate_slug(): on the extremely unlikely case of a
	 * collision (random 8-char slug matching an existing page), we retry up
	 * to 5 times before surrendering with a 500.
	 */
	public function ajax_regenerate_slug(): void {
		$this->guard_admin_action();

		$new_slug = '';
		for ( $i = 0; $i < 5; $i++ ) {
			$candidate = HideLogin::generate_slug();
			$result    = HideLogin::validate_slug( $candidate );
			if ( true === $result ) {
				$new_slug = $candidate;
				break;
			}
		}

		if ( '' === $new_slug ) {
			wp_send_json_error( array( 'message' => 'generation_failed' ), 500 );
		}

		update_option( HideLogin::OPTION_SLUG, $new_slug );
		// NOTE: Email delivery is intentionally NOT triggered here. Users
		// may regenerate the slug several times (e.g. in the pre-activation
		// modal) before settling on one: auto-emailing every attempt would
		// spam the admin inbox. Email is now sent only when the user
		// explicitly opts in via the Settings page "Email me this URL"
		// button or via the pre-activation modal's opt-in checkbox.

		wp_send_json_success(
			array(
				'slug' => $new_slug,
				'url'  => HideLogin::build_login_url( '/' . $new_slug ),
			)
		);
	}

	/**
	 * AJAX: save the Hide Login section (slug + redirect type + custom URL).
	 *
	 * The slug must pass validate_slug(). The redirect type is one of
	 * 'notfound' or 'url'. The custom URL is only persisted when the type
	 * is 'url'; otherwise it is cleared.
	 */
	public function ajax_save_hide_settings(): void {
		$this->guard_admin_action();

		// phpcs:disable WordPress.Security.NonceVerification.Missing -- Verified in guard_admin_action().
		$slug          = isset( $_POST['slug'] ) ? sanitize_title( wp_unslash( $_POST['slug'] ) ) : '';
		$redirect_type = isset( $_POST['redirect_type'] ) ? sanitize_key( wp_unslash( $_POST['redirect_type'] ) ) : HideLogin::REDIRECT_NOT_FOUND;
		$redirect_url  = isset( $_POST['redirect_url'] ) ? esc_url_raw( wp_unslash( $_POST['redirect_url'] ) ) : '';
		// phpcs:enable WordPress.Security.NonceVerification.Missing

		$validation = HideLogin::validate_slug( $slug );
		if ( is_wp_error( $validation ) ) {
			wp_send_json_error(
				array(
					'message' => $validation->get_error_message(),
					'code'    => $validation->get_error_code(),
				),
				400
			);
		}

		if ( ! in_array( $redirect_type, array( HideLogin::REDIRECT_NOT_FOUND, HideLogin::REDIRECT_URL ), true ) ) {
			$redirect_type = HideLogin::REDIRECT_NOT_FOUND;
		}

		update_option( HideLogin::OPTION_SLUG, $slug );
		update_option( HideLogin::OPTION_REDIRECT_TYPE, $redirect_type );
		update_option( HideLogin::OPTION_REDIRECT_URL, HideLogin::REDIRECT_URL === $redirect_type ? $redirect_url : '' );

		wp_send_json_success(
			array(
				'slug'          => $slug,
				'url'           => HideLogin::build_login_url( '/' . $slug ),
				'redirect_type' => $redirect_type,
				'redirect_url'  => HideLogin::REDIRECT_URL === $redirect_type ? $redirect_url : '',
			)
		);
	}

	/**
	 * AJAX: email the current Hide Login URL and recovery instructions
	 * to the site's admin email address.
	 */
	public function ajax_email_slug(): void {
		$this->guard_admin_action();

		$sent = HideLogin::send_recovery_email( 'reminder' );
		if ( ! $sent ) {
			wp_send_json_error( array( 'message' => 'mail_failed' ), 500 );
		}

		wp_send_json_success(
			array(
				'to' => (string) get_option( 'admin_email', '' ),
			)
		);
	}

	/**
	 * AJAX: turn Hide Login on.
	 *
	 * Accepts optional POST params `slug` (user-chosen login slug, validated
	 * via HideLogin::validate_slug) and `send_email` (truthy → fire the
	 * recovery email with the final slug). When `slug` is omitted, falls
	 * back to the stored option or a fresh generate_slug() call. The caller
	 * is expected to reload the page so the HideLogin hooks get wired by
	 * the next request.
	 *
	 * Called by admin.js → LA.hideLoginPreActivate flow.
	 */
	public function ajax_enable_hide(): void {
		$this->guard_admin_action();

		// 2.10.0: never two hidden login addresses. A plugin whose only job is
		// hiding the login page owns wp-login.php while it is active.
		$exclusive = HideLogin::get_exclusive_conflict();
		if ( false !== $exclusive ) {
			wp_send_json_error(
				array(
					'code'    => 'hide_login_exclusive_conflict',
					'message' => sprintf(
						/* translators: %s: plugin name, e.g. WPS Hide Login. */
						__( '%s already hides the login page. Deactivate it first, then switch on Login Armor\'s hidden login address. Nothing was saved.', 'login-armor' ),
						$exclusive
					),
				),
				409
			);
		}

		// phpcs:disable WordPress.Security.NonceVerification.Missing -- Verified in guard_admin_action().
		$requested_slug = isset( $_POST['slug'] )
			? sanitize_text_field( wp_unslash( (string) $_POST['slug'] ) )
			: '';
		$send_email     = ! empty( $_POST['send_email'] );
		// phpcs:enable

		if ( '' !== $requested_slug ) {
			$validation = HideLogin::validate_slug( $requested_slug );
			if ( true !== $validation ) {
				wp_send_json_error(
					array(
						'code'    => 'invalid_slug',
						'message' => is_wp_error( $validation )
							? $validation->get_error_message()
							: __( 'This slug cannot be used.', 'login-armor' ),
					),
					400
				);
			}
			$slug = $requested_slug;
		} else {
			// No slug posted: fall back to the stored one, or generate a
			// fresh random one on very first activation (legacy callers).
			$slug = trim( (string) get_option( HideLogin::OPTION_SLUG, '' ) );
			if ( '' === $slug ) {
				$slug = HideLogin::generate_slug();
			}
		}

		update_option( HideLogin::OPTION_SLUG, $slug );
		update_option( HideLogin::OPTION_ENABLED, 1 );

		if ( $send_email ) {
			HideLogin::send_recovery_email( 'activation' );
		}

		wp_send_json_success(
			array(
				'enabled'     => 1,
				'slug'        => $slug,
				'url'         => HideLogin::build_login_url( '/' . $slug ),
				'email_sent'  => $send_email,
			)
		);
	}

	/**
	 * AJAX: turn Hide Login off.
	 *
	 * The slug is preserved in options so re-enabling is instant and does
	 * not invalidate previously bookmarked URLs. Only the enabled flag is
	 * flipped.
	 */
	public function ajax_disable_hide(): void {
		$this->guard_admin_action();
		update_option( HideLogin::OPTION_ENABLED, 0 );
		wp_send_json_success( array( 'enabled' => 0 ) );
	}

	/**
	 * AJAX: save hardening toggle settings.
	 *
	 * Receives the 5 boolean flags from the hardening section form,
	 * sanitizes them and persists to a single option array.
	 */
	public function ajax_save_hardening(): void {
		$this->guard_admin_action();

		// phpcs:disable WordPress.Security.NonceVerification.Missing -- Verified in guard_admin_action().
		$input = isset( $_POST['toggles'] ) && is_array( $_POST['toggles'] )
			? array_map( 'sanitize_key', wp_unslash( $_POST['toggles'] ) )
			: array();
		// phpcs:enable WordPress.Security.NonceVerification.Missing

		// Convert the list of enabled keys into the associative array expected by save_settings.
		$settings = array();
		foreach ( $input as $key ) {
			$settings[ $key ] = true;
		}

		// 2.9.0: headless mode keeps two toggles off. A save that switches one
		// on is refused WHOLE, like Force HTTPS below: the screen greys them
		// out, so this is a stale page or a crafted request.
		$headless_conflicts = Headless::is_enabled() ? Headless::conflicts( $settings ) : array();
		if ( array() !== $headless_conflicts ) {
			wp_send_json_error(
				array(
					'code'    => 'headless_conflict',
					'keys'    => $headless_conflicts,
					'message' => sprintf(
						/* translators: %s: comma-separated list of hardening toggle names. */
						__( 'Headless mode keeps these settings off: %s. Turn headless mode off first. Nothing was saved.', 'login-armor' ),
						implode( ', ', Headless::labels( $headless_conflicts ) )
					),
				),
				409
			);
		}

		// 2.7.0: Force HTTPS is the one toggle that can make this very admin
		// unreachable. Switching it on from a request that is not demonstrably
		// HTTPS is refused, and the WHOLE save is refused with it: a partial
		// save would leave the screen disagreeing with the database.
		if (
			! empty( $settings['force_https'] )
			&& ! Hardening::can_enable_force_https(
				! empty( Hardening::get_settings()['force_https'] ),
				\LoginArmor\LoginArmor::request_is_https()
			)
		) {
			wp_send_json_error(
				array(
					'code'    => 'force_https_insecure',
					'message' => __( 'Force HTTPS can only be enabled from an HTTPS connection (or behind a proxy listed in Trusted proxies that sends X-Forwarded-Proto). Nothing was saved.', 'login-armor' ),
				),
				409
			);
		}

		Hardening::save_settings( $settings );

		// 2.7.1: the answer tells the truth about the FILE, not just about the
		// option. The settings row is written either way, so a refused
		// .htaccess write used to leave the screen showing a rule as ON while
		// the file did not carry it. The toast now says the rule is saved but
		// not applied, and the notice that follows says why.
		if ( ! Hardening::sync_htaccess() ) {
			$failure = get_option( Hardening::OPTION_HTACCESS_LAST_FAILURE, array() );
			$reason  = is_array( $failure ) ? (string) ( $failure['kind'] ?? 'write' ) : 'write';

			wp_send_json_success(
				array(
					'saved'      => true,
					'applied'    => false,
					'reason'     => $reason,
					'transient'  => Hardening::htaccess_failure_is_transient( $reason ),
					'message'    => Hardening::htaccess_failure_message(
						$reason,
						is_array( $failure ) ? (string) ( $failure['path'] ?? '' ) : ''
					),
				)
			);
		}

		wp_send_json_success( array( 'saved' => true, 'applied' => true ) );
	}

	/**
	 * AJAX: persist the public REST namespaces allowlist (2.5.1).
	 *
	 * Normalizes the textarea content, stores the resulting array, and returns
	 * the new count plus the normalized text so the field can echo back what
	 * was actually saved.
	 */
	public function ajax_save_rest_namespaces(): void {
		$this->guard_admin_action();

		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Verified in guard_admin_action().
		$raw = isset( $_POST['namespaces'] ) ? sanitize_textarea_field( wp_unslash( $_POST['namespaces'] ) ) : '';

		$list = Hardening::normalize_rest_namespaces( $raw );
		update_option( Hardening::OPTION_REST_NAMESPACES, $list, false );

		wp_send_json_success(
			array(
				'count'      => count( $list ),
				'normalized' => Hardening::get_rest_namespaces_textarea(),
				'risky'      => Hardening::risky_rest_namespaces( $list ),
			)
		);
	}

	/**
	 * AJAX: persist the reserved-usernames blacklist (Lot 14).
	 *
	 * Normalizes the textarea content, stores the resulting array, and
	 * returns the new count + any existing user_logins that match the list.
	 */
	public function ajax_save_username_blacklist(): void {
		$this->guard_admin_action();

		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Verified in guard_admin_action().
		$raw = isset( $_POST['blacklist'] ) ? sanitize_textarea_field( wp_unslash( $_POST['blacklist'] ) ) : '';

		$list = \LoginArmor\Hardening\UsernameBlacklist::normalize( $raw );
		update_option( \LoginArmor\Hardening\UsernameBlacklist::OPTION_KEY, $list, false );

		wp_send_json_success(
			array(
				'count'            => count( $list ),
				'existing_matches' => \LoginArmor\Hardening\UsernameBlacklist::existing_matching_users(),
			)
		);
	}

	/**
	 * AJAX: save Limit Login settings.
	 */
	public function ajax_save_limit_settings(): void {
		$this->guard_admin_action();

		// phpcs:disable WordPress.Security.NonceVerification.Missing -- Verified in guard_admin_action().
		$allowed_retries  = isset( $_POST['allowed_retries'] ) ? absint( wp_unslash( $_POST['allowed_retries'] ) ) : 4;
		$lockout_duration = isset( $_POST['lockout_duration'] ) ? absint( wp_unslash( $_POST['lockout_duration'] ) ) : 20;
		$max_lockouts     = isset( $_POST['max_lockouts'] ) ? absint( wp_unslash( $_POST['max_lockouts'] ) ) : 4;
		$long_duration    = isset( $_POST['long_duration'] ) ? absint( wp_unslash( $_POST['long_duration'] ) ) : 24;
		$valid_duration   = isset( $_POST['valid_duration'] ) ? absint( wp_unslash( $_POST['valid_duration'] ) ) : 24;
		$notify_threshold = isset( $_POST['notify_threshold'] ) ? absint( wp_unslash( $_POST['notify_threshold'] ) ) : 5;
		$notify_email     = isset( $_POST['notify_email'] ) ? sanitize_email( wp_unslash( $_POST['notify_email'] ) ) : '';
		// 2.10.0: syslog lines for fail2ban. Absent (an older view) is silence.
		$syslog           = isset( $_POST['syslog'] ) ? ( '1' === sanitize_key( wp_unslash( $_POST['syslog'] ) ) ? 1 : 0 ) : null;
		$whitelist_ips    = isset( $_POST['whitelist_ips'] ) ? sanitize_textarea_field( wp_unslash( $_POST['whitelist_ips'] ) ) : '';
		$trusted_proxies  = isset( $_POST['trusted_proxies'] ) ? sanitize_textarea_field( wp_unslash( $_POST['trusted_proxies'] ) ) : '';
		// sanitize_key() would lowercase the value and break the allowlist match below: compare uppercased raw input against the allowlist instead.
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Verified in guard_admin_action().
		$ip_method        = isset( $_POST['ip_method'] ) ? strtoupper( sanitize_text_field( wp_unslash( $_POST['ip_method'] ) ) ) : 'REMOTE_ADDR';
		// phpcs:enable WordPress.Security.NonceVerification.Missing

		$allowed_methods = [ 'REMOTE_ADDR', 'HTTP_CF_CONNECTING_IP', 'HTTP_X_FORWARDED_FOR', 'HTTP_X_REAL_IP' ];
		if ( ! in_array( $ip_method, $allowed_methods, true ) ) {
			$ip_method = 'REMOTE_ADDR';
		}
		$trusted_proxies = LoginArmor::normalize_trusted_proxies( $trusted_proxies );

		// Clamp values.
		$allowed_retries  = max( 1, min( 20, $allowed_retries ) );
		$lockout_duration = max( 1, min( 1440, $lockout_duration ) );
		$max_lockouts     = max( 1, min( 20, $max_lockouts ) );
		$long_duration    = max( 1, min( 168, $long_duration ) );
		$valid_duration   = max( 1, min( 168, $valid_duration ) );

		update_option( 'login_armor_allowed_retries', $allowed_retries );
		update_option( 'login_armor_lockout_duration', $lockout_duration );
		update_option( 'login_armor_max_lockouts', $max_lockouts );
		update_option( 'login_armor_long_duration', $long_duration );
		update_option( 'login_armor_valid_duration', $valid_duration );
		update_option( 'login_armor_notify_threshold', $notify_threshold );
		update_option( 'login_armor_notify_email', $notify_email );
		if ( null !== $syslog ) {
			update_option( 'login_armor_syslog', $syslog );
		}
		update_option( 'login_armor_whitelist_ips', $whitelist_ips );
		update_option( 'login_armor_ip_method', $ip_method );
		update_option( 'login_armor_trusted_proxies', $trusted_proxies, false );
		LoginArmor::reset_client_ip_cache();

		wp_send_json_success( array( 'saved' => true ) );
	}

	/**
	 * AJAX: enable brute force protection.
	 */
	public function ajax_enable_limit(): void {
		$this->guard_admin_action();
		update_option( 'login_armor_limit_enabled', true );
		wp_send_json_success( array( 'enabled' => true ) );
	}

	/**
	 * AJAX: disable brute force protection.
	 */
	public function ajax_disable_limit(): void {
		$this->guard_admin_action();
		update_option( 'login_armor_limit_enabled', false );
		wp_send_json_success( array( 'enabled' => false ) );
	}

	/**
	 * AJAX: return the current user's IP address.
	 */
	public function ajax_get_current_ip(): void {
		$this->guard_admin_action();
		wp_send_json_success( array( 'ip' => LoginArmor::get_client_ip() ) );
	}

	/**
	 * AJAX: save Detection & Logs settings.
	 */
	public function ajax_save_detection_settings(): void {
		$this->guard_admin_action();

		// phpcs:disable WordPress.Security.NonceVerification.Missing -- Verified in guard_admin_action().
		$retention_days = isset( $_POST['retention_days'] ) ? absint( wp_unslash( $_POST['retention_days'] ) ) : 90;
		$auto_purge     = isset( $_POST['auto_purge'] ) && sanitize_text_field( wp_unslash( $_POST['auto_purge'] ) ) === '1';
		// phpcs:enable WordPress.Security.NonceVerification.Missing

		$retention_days = max( 1, min( 3650, $retention_days ) );

		update_option( 'login_armor_log_retention_days', $retention_days );
		update_option( 'login_armor_auto_purge', $auto_purge );

		// Schedule or unschedule cron.
		if ( $auto_purge ) {
			if ( ! wp_next_scheduled( 'login_armor_purge_logs' ) ) {
				wp_schedule_event( time(), 'daily', 'login_armor_purge_logs' );
			}
		} else {
			wp_clear_scheduled_hook( 'login_armor_purge_logs' );
		}

		wp_send_json_success( array( 'saved' => true ) );
	}

	/**
	 * AJAX: enable detection & logs.
	 */
	public function ajax_enable_detection(): void {
		$this->guard_admin_action();
		update_option( 'login_armor_detection_enabled', true );
		wp_send_json_success( array( 'enabled' => true ) );
	}

	/**
	 * AJAX: disable detection & logs.
	 */
	public function ajax_disable_detection(): void {
		$this->guard_admin_action();
		update_option( 'login_armor_detection_enabled', false );
		wp_send_json_success( array( 'enabled' => false ) );
	}

	/**
	 * AJAX: manually purge old logs.
	 */
	public function ajax_purge_logs_manual(): void {
		$this->guard_admin_action();
		$deleted = LoginArmor::do_purge();
		wp_send_json_success( array( 'deleted' => $deleted ) );
	}

	/**
	 * AJAX: total wipe of detection-related data (events feed + brute-force
	 * counter + grouped incidents). Distinct from `ajax_purge_logs_manual`,
	 * which only deletes rows older than the retention threshold.
	 *
	 * Side effects:
	 * - All current lockouts are released. Any IP that was banned for 20 min
	 *   can immediately retry. This is intentional and matches the user's
	 *   mental model of "start from zero".
	 * - Per-pattern incident counters reset. A subsequent attack from the
	 *   same IP will create a fresh incident, not append to the wiped one.
	 * - The destructive action is itself logged to the Activity Log when
	 *   that module is enabled, so the wipe is auditable.
	 *
	 * @since 2.0.1
	 */
	public function ajax_reset_detection_data(): void {
		$this->guard_admin_action();

		global $wpdb;

		$logs = (int) $wpdb->query( "DELETE FROM {$wpdb->prefix}login_armor_logs" ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.NotPrepared -- Custom plugin table, full-table wipe explicitly authorised by admin via guarded AJAX action.
		$attempts = (int) $wpdb->query( "DELETE FROM {$wpdb->prefix}login_armor_attempts" ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.NotPrepared -- Same.

		$incidents = 0;
		$incidents_table = $wpdb->prefix . 'login_armor_incidents';
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
		if ( $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $incidents_table ) ) === $incidents_table ) {
			$incidents = (int) $wpdb->query( "DELETE FROM {$wpdb->prefix}login_armor_incidents" ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.NotPrepared -- Same.
		}

		$total = $logs + $attempts + $incidents;

		/**
		 * Fires after a manual reset of detection data.
		 *
		 * Subscribers (Activity Log, SIEM forwarders, audit) can record the
		 * destructive action and surface it to the admin view.
		 *
		 * Since 2.7.9 the Activity Log records it (SettingsLogger), which this
		 * docblock had promised since 2.0.1 with nothing subscribed.
		 *
		 * @param string            $scope     Which dataset was reset (here: 'detection').
		 * @param int               $row_count Total number of rows deleted across tables.
		 * @param int               $user_id   ID of the admin who triggered the reset.
		 * @param array<string,int> $deleted   Rows per table: events, attempts, incidents (2.7.9).
		 */
		do_action(
			'login_armor_data_reset',
			'detection',
			$total,
			get_current_user_id(),
			array(
				'events'    => $logs,
				'attempts'  => $attempts,
				'incidents' => $incidents,
			)
		);

		wp_send_json_success( [
			'deleted' => [
				'events'    => $logs,
				'attempts'  => $attempts,
				'incidents' => $incidents,
				'total'     => $total,
			],
		] );
	}

	/**
	 * AJAX: enable the Activity Log module.
	 */
	public function ajax_enable_activity(): void {
		$this->guard_admin_action();

		require_once LOGIN_ARMOR_DIR . 'includes/ActivityLog/ActivityLog.php';
		\LoginArmor\ActivityLog\ActivityLog::create_table();

		update_option( 'login_armor_activity_enabled', true );

		if ( ! wp_next_scheduled( \LoginArmor\ActivityLog\ActivityLog::CRON_HOOK ) ) {
			wp_schedule_event( time(), 'daily', \LoginArmor\ActivityLog\ActivityLog::CRON_HOOK );
		}

		wp_send_json_success( [ 'enabled' => true ] );
	}

	/**
	 * AJAX: disable the Activity Log module. Data is preserved.
	 */
	public function ajax_disable_activity(): void {
		$this->guard_admin_action();
		update_option( 'login_armor_activity_enabled', false );
		wp_clear_scheduled_hook( 'login_armor_activity_purge' );
		wp_send_json_success( [ 'enabled' => false ] );
	}

	/**
	 * AJAX: save Activity Log settings (retention period).
	 */
	public function ajax_save_activity_settings(): void {
		$this->guard_admin_action();

		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Verified in guard_admin_action().
		$retention = isset( $_POST['activity_retention'] ) ? absint( wp_unslash( $_POST['activity_retention'] ) ) : 90;

		$retention = max( 1, min( 3650, $retention ) );

		update_option( 'login_armor_activity_retention', $retention );

		wp_send_json_success( [ 'saved' => true ] );
	}

	/**
	 * AJAX: manually purge old activity logs.
	 */
	public function ajax_purge_activity(): void {
		$this->guard_admin_action();

		require_once LOGIN_ARMOR_DIR . 'includes/ActivityLog/ActivityLog.php';
		$deleted = \LoginArmor\ActivityLog\ActivityLog::purge();

		wp_send_json_success( [ 'deleted' => $deleted ] );
	}

	/**
	 * AJAX: total wipe of the admin activity log table. Distinct from
	 * `ajax_purge_activity`, which only deletes rows older than retention.
	 *
	 * Cannot be self-audited: emitting `login_armor_data_reset` after the
	 * delete still records the action via the Activity Log subscriber, but
	 * we explicitly suppress that recording when scope='activity' so the
	 * brand-new empty table doesn't immediately get a row back.
	 *
	 * @since 2.0.1
	 */
	public function ajax_reset_activity_data(): void {
		$this->guard_admin_action();

		global $wpdb;

		$activity_table = $wpdb->prefix . 'login_armor_activity';
		$deleted = 0;
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
		if ( $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $activity_table ) ) === $activity_table ) {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.NotPrepared -- Custom plugin table, explicit admin wipe via guarded AJAX action.
			$deleted = (int) $wpdb->query( "DELETE FROM {$wpdb->prefix}login_armor_activity" );
		}

		// Note: do NOT fire `login_armor_data_reset` here, the Activity Log
		// is the audit channel itself, and the row written by the subscriber
		// would just re-populate the table we just emptied. The destructive
		// action remains visible: it is the admin's last login that no longer
		// has a corresponding "user logged in" row.

		// The Integrity panel shows the last verification, kept seven days:
		// left alone it went on reading "INTACT, 143 rows signed" over the
		// table just emptied (2.7.9).
		require_once LOGIN_ARMOR_DIR . 'includes/ActivityLog/ActivityLog.php';
		\LoginArmor\ActivityLog\ActivityLog::refresh_verification();

		wp_send_json_success( [ 'deleted' => $deleted ] );
	}

	// ── Lot 10: Two-Factor Authentication AJAX handlers ────────

	/**
	 * AJAX: Enable 2FA module globally.
	 */
	public function ajax_enable_2fa(): void {
		$this->guard_admin_action();
		update_option( 'login_armor_2fa_enabled', true );
		wp_send_json_success();
	}

	/**
	 * AJAX: Disable 2FA module globally (preserves user data).
	 */
	public function ajax_disable_2fa(): void {
		$this->guard_admin_action();
		update_option( 'login_armor_2fa_enabled', false );
		wp_send_json_success();
	}

	/**
	 * AJAX: Save 2FA settings (methods, enforcement, grace period).
	 */
	public function ajax_save_2fa_settings(): void {
		$this->guard_admin_action();

		// phpcs:disable WordPress.Security.NonceVerification.Missing -- Nonce verified in guard_admin_action() above.
		$methods = [];
		if ( ! empty( $_POST['method_totp'] ) ) {
			$methods[] = 'totp';
		}
		if ( ! empty( $_POST['method_email'] ) ) {
			$methods[] = 'email';
		}
		if ( ! empty( $_POST['method_backup'] ) ) {
			$methods[] = 'backup';
		}
		if ( empty( $methods ) ) {
			// V2.4.2: explicit rejection instead of the previous silent
			// all-three fallback: unchecking every method looked accepted in
			// the UI while the server re-enabled everything, and with roles
			// enforced a truly empty selection would leave those users unable
			// to enrol. Rejecting keeps the last valid selection untouched.
			wp_send_json_error(
				[ 'message' => __( 'Select at least one two-factor method: users cannot verify their sign-in without one.', 'login-armor' ) ]
			);
		}

		$enforce_roles = [];
		if ( isset( $_POST['enforce_roles'] ) && is_array( $_POST['enforce_roles'] ) ) {
			$enforce_roles = array_map( 'sanitize_text_field', wp_unslash( $_POST['enforce_roles'] ) );
			// Validate against existing roles.
			$valid_roles   = array_keys( wp_roles()->role_names );
			$enforce_roles = array_intersect( $enforce_roles, $valid_roles );
		}

		$grace_days = isset( $_POST['grace_days'] ) ? absint( $_POST['grace_days'] ) : 3;
		if ( ! in_array( $grace_days, [ 1, 3, 7, 14 ], true ) ) {
			$grace_days = 3;
		}
		// phpcs:enable WordPress.Security.NonceVerification.Missing

		update_option( 'login_armor_2fa_methods', $methods );
		update_option( 'login_armor_2fa_enforce_roles', $enforce_roles );
		update_option( 'login_armor_2fa_grace_days', $grace_days );

		// phpcs:disable WordPress.Security.NonceVerification.Missing -- Nonce verified in guard_admin_action() above.
		require_once LOGIN_ARMOR_DIR . 'includes/TwoFactor/TrustedDevices.php';
		$td_enabled = ! empty( $_POST['allow_trusted_devices'] );
		update_option( \LoginArmor\TwoFactor\TrustedDevices::OPTION_ENABLED, $td_enabled, false );

		$td_duration_raw = isset( $_POST['trusted_devices_duration_days'] ) ? (int) $_POST['trusted_devices_duration_days'] : \LoginArmor\TwoFactor\TrustedDevices::DEFAULT_DURATION_DAYS;
		if ( in_array( $td_duration_raw, \LoginArmor\TwoFactor\TrustedDevices::ALLOWED_DURATIONS, true ) ) {
			update_option( \LoginArmor\TwoFactor\TrustedDevices::OPTION_DURATION_DAYS, $td_duration_raw, false );
		}

		require_once LOGIN_ARMOR_DIR . 'includes/TwoFactor/Recovery.php';
		$recov_enabled = ! empty( $_POST['allow_2fa_recovery'] );
		update_option( \LoginArmor\TwoFactor\Recovery::OPTION_ENABLED, $recov_enabled, false );
		// phpcs:enable WordPress.Security.NonceVerification.Missing

		wp_send_json_success();
	}

	/**
	 * AJAX: Start 2FA setup for the current user.
	 */
	public function ajax_start_2fa_setup(): void {
		check_ajax_referer( 'login_armor_2fa_profile', 'nonce' );

		$user_id = get_current_user_id();
		if ( $user_id <= 0 || ! TwoFactor\TwoFactor::is_enabled() ) {
			wp_send_json_error( [ 'message' => __( 'Two-factor authentication is not available.', 'login-armor' ) ], 403 );
		}
		if ( TwoFactor\TwoFactor::is_user_enabled( $user_id ) ) {
			wp_send_json_error( [ 'message' => __( 'Two-factor authentication is already configured for this account.', 'login-armor' ) ], 409 );
		}
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Verified above.
		$method  = isset( $_POST['method'] ) ? sanitize_text_field( wp_unslash( $_POST['method'] ) ) : 'totp';
		if ( ! in_array( $method, array( 'totp', 'email' ), true ) || ! TwoFactor\TwoFactor::is_method_enabled( $method ) ) {
			wp_send_json_error( [ 'message' => __( 'This two-factor method is not enabled by the site administrator.', 'login-armor' ) ], 400 );
		}

		if ( 'totp' === $method ) {
			require_once LOGIN_ARMOR_DIR . 'includes/TwoFactor/TOTP.php';

			$secret    = TwoFactor\TOTP::generate_secret();
			$encrypted = TwoFactor\TOTP::encrypt_secret( $secret );

			if ( '' === $encrypted ) {
				wp_send_json_error( [ 'message' => __( 'Unable to encrypt the TOTP secret. Contact the site administrator.', 'login-armor' ) ], 500 );
			}

			$setup_token = TwoFactor\TwoFactor::begin_setup( $user_id, 'totp', $encrypted );
			if ( '' === $setup_token ) {
				wp_send_json_error( [ 'message' => __( 'Unable to start the two-factor setup. Please try again.', 'login-armor' ) ], 500 );
			}

			$uri = TwoFactor\TOTP::build_uri( $secret, wp_get_current_user()->user_login, '', $user_id );

			wp_send_json_success( [
				'secret'       => $secret,
				'otpauth_uri'  => $uri,
				'setup_token'  => $setup_token,
			] );
		} elseif ( 'email' === $method ) {
			require_once LOGIN_ARMOR_DIR . 'includes/TwoFactor/EmailOTP.php';
			$setup_token = TwoFactor\TwoFactor::begin_setup( $user_id, 'email' );
			if ( '' === $setup_token ) {
				wp_send_json_error( [ 'message' => __( 'Unable to start the two-factor setup. Please try again.', 'login-armor' ) ], 500 );
			}

			// Send the verification code first. Only persist the method
			// choice if delivery succeeds: a failed wp_mail() must not
			// leave a half-configured 2FA state behind. The user is not
			// committed until the code reaches them.
			$sent = TwoFactor\EmailOTP::send_code( $user_id );
			if ( ! $sent ) {
				TwoFactor\TwoFactor::cancel_setup( $user_id );
				wp_send_json_error(
					[ 'message' => __( 'Unable to send the verification code email. Check your site email configuration, then try again.', 'login-armor' ) ],
					500
				);
			}

			wp_send_json_success( [ 'setup_token' => $setup_token ] );
		} else {
			wp_send_json_error( [ 'message' => 'invalid_method' ], 400 );
		}
	}

	/**
	 * AJAX: Send a one-shot test email to confirm wp_mail() reaches
	 * the user before they commit to Email-based 2FA.
	 *
	 * No transient, no OTP code, no user_meta write: pure delivery
	 * probe. Used by the pre-activation modal on the profile page to
	 * gate the "Set up Email" button until a real email succeeds.
	 */
	public function ajax_2fa_email_test(): void {
		check_ajax_referer( 'login_armor_2fa_profile', 'nonce' );

		$user = wp_get_current_user();
		if ( ! $user || 0 === $user->ID || empty( $user->user_email ) ) {
			wp_send_json_error(
				[ 'message' => __( 'No email address found on your account.', 'login-armor' ) ],
				400
			);
		}

		$site_name = wp_specialchars_decode( (string) get_bloginfo( 'name' ), ENT_QUOTES );
		$subject   = sprintf(
			/* translators: %s: site name */
			__( '[%s] Login Armor: Email delivery test', 'login-armor' ),
			$site_name
		);
		$message = sprintf(
			/* translators: 1: display name, 2: site name */
			__( "Hello %1\$s,\n\nThis is a test message from Login Armor on %2\$s.\n\nIf you can read this, your hosting delivers emails correctly. You can safely enable Email two-factor authentication.\n\nIf you did not request this test, you can ignore this message.", 'login-armor' ),
			$user->display_name,
			$site_name
		);

		$sent = wp_mail( $user->user_email, $subject, $message );

		if ( ! $sent ) {
			wp_send_json_error(
				[
					'message' => __( 'The test email could not be sent. Configure WP Mail SMTP (or contact your host) before enabling Email 2FA, otherwise you will be locked out.', 'login-armor' ),
				],
				500
			);
		}

		wp_send_json_success(
			[
				'message' => __( 'Test email sent. Check your inbox (and spam folder) before continuing.', 'login-armor' ),
				'email'   => $user->user_email,
			]
		);
	}

	/**
	 * AJAX: Verify the setup code and generate backup codes.
	 */
	public function ajax_verify_2fa_setup(): void {
		check_ajax_referer( 'login_armor_2fa_profile', 'nonce' );

		$user_id = get_current_user_id();
		if ( $user_id <= 0 || TwoFactor\TwoFactor::is_user_enabled( $user_id ) ) {
			wp_send_json_error( [ 'message' => __( 'This setup session is not available.', 'login-armor' ) ], 409 );
		}
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Verified above.
		$code   = isset( $_POST['code'] ) ? sanitize_text_field( wp_unslash( $_POST['code'] ) ) : '';
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Verified above.
		$setup_token = isset( $_POST['setup_token'] ) ? sanitize_text_field( wp_unslash( $_POST['setup_token'] ) ) : '';
		$state       = TwoFactor\TwoFactor::get_setup( $user_id, $setup_token );
		if ( false === $state ) {
			wp_send_json_error( [ 'message' => __( 'This setup session has expired. Please start again.', 'login-armor' ) ], 403 );
		}
		$method = (string) ( $state['method'] ?? '' );
		if ( ! TwoFactor\TwoFactor::is_method_enabled( $method ) ) {
			TwoFactor\TwoFactor::cancel_setup( $user_id );
			wp_send_json_error( [ 'message' => __( 'This two-factor method is no longer enabled.', 'login-armor' ) ], 403 );
		}

		$valid        = false;
		$matched_step = 0;

		if ( 'totp' === $method ) {
			require_once LOGIN_ARMOR_DIR . 'includes/TwoFactor/TOTP.php';
			$encrypted_secret = (string) ( $state['encrypted_secret'] ?? '' );
			$secret           = TwoFactor\TOTP::decrypt_secret( $encrypted_secret );
			if ( false !== $secret ) {
				$step  = null;
				$valid = TwoFactor\TOTP::validate( $code, $secret, $step );
				$matched_step = null === $step ? 0 : (int) $step;
			}
		} elseif ( 'email' === $method ) {
			require_once LOGIN_ARMOR_DIR . 'includes/TwoFactor/EmailOTP.php';
			$valid = TwoFactor\EmailOTP::validate( $user_id, $code );
		}

		if ( ! $valid ) {
			wp_send_json_error( [ 'message' => __( 'Invalid code. Please try again.', 'login-armor' ) ] );
		}

		// Prepare backup codes without replacing the active recovery data. The
		// hashes are committed only by the verified completion transaction.
		require_once LOGIN_ARMOR_DIR . 'includes/TwoFactor/BackupCodes.php';
		$prepared = TwoFactor\BackupCodes::prepare();
		if ( ! TwoFactor\TwoFactor::mark_setup_verified( $user_id, $setup_token, $prepared['hashes'], $matched_step ) ) {
			wp_send_json_error( [ 'message' => __( 'Unable to save the verified setup state. Please start again.', 'login-armor' ) ], 500 );
		}

		wp_send_json_success( [ 'backup_codes' => $prepared['codes'] ] );
	}

	/**
	 * AJAX: Complete the 2FA setup (after user confirms saving backup codes).
	 */
	public function ajax_complete_2fa_setup(): void {
		check_ajax_referer( 'login_armor_2fa_profile', 'nonce' );

		$user_id = get_current_user_id();
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Verified above.
		$setup_token = isset( $_POST['setup_token'] ) ? sanitize_text_field( wp_unslash( $_POST['setup_token'] ) ) : '';
		$state = TwoFactor\TwoFactor::activate_verified_setup( $user_id, $setup_token );
		if ( false === $state ) {
			wp_send_json_error( [ 'message' => __( 'This verified setup session is invalid, expired, or already completed.', 'login-armor' ) ], 409 );
		}
		$method = (string) $state['method'];

		/**
		 * Fires when a user enables 2FA.
		 *
		 * @param int    $user_id WordPress user ID.
		 * @param string $method  The configured method.
		 */
		do_action( 'login_armor_2fa_user_enabled', $user_id, $method );

		wp_send_json_success();
	}

	/** @var int Wrong passwords accepted per account before re-authentication pauses (2.8.0). */
	private const REAUTH_MAX_FAILURES = 5;

	/** @var int How long re-authentication pauses after too many wrong passwords (2.8.0). */
	private const REAUTH_WINDOW = 15 * MINUTE_IN_SECONDS;

	/**
	 * Ask for the account password before a change that weakens the account (2.8.0).
	 *
	 * Disabling two-factor and regenerating the backup codes used to need the
	 * session alone: a stolen session cookie was enough to switch the second
	 * factor off, or to mint eight fresh codes that outlive the session. The
	 * password is what a stolen cookie does not carry. Wrong passwords are
	 * counted per account, so the check cannot be used to guess it.
	 *
	 * Ends the request with an error when the password is missing or wrong.
	 */
	private function require_current_password(): void {
		$user = wp_get_current_user();

		// Every attempt is counted before the password is compared, in one
		// atomic step: parallel requests cannot all read the same count.
		require_once LOGIN_ARMOR_DIR . 'includes/TwoFactor/TwoFactor.php';
		$attempts = TwoFactor\TwoFactor::count_reauth_attempt( (int) $user->ID, self::REAUTH_MAX_FAILURES, self::REAUTH_WINDOW );
		if ( $attempts > self::REAUTH_MAX_FAILURES ) {
			wp_send_json_error( [ 'code' => 'reauth_locked', 'message' => __( 'Too many incorrect passwords. Try again in 15 minutes.', 'login-armor' ) ], 429 );
		}

		// phpcs:ignore WordPress.Security.NonceVerification.Missing,WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Nonce checked by the caller; a password is compared, never stored or printed, and sanitizing would change it.
		$password = isset( $_POST['current_password'] ) && is_string( $_POST['current_password'] ) ? (string) wp_unslash( $_POST['current_password'] ) : '';
		if ( '' === $password || ! wp_check_password( $password, (string) $user->user_pass, (int) $user->ID ) ) {
			wp_send_json_error( [ 'code' => 'reauth', 'message' => __( 'The password is not correct.', 'login-armor' ) ], 403 );
		}

		TwoFactor\TwoFactor::clear_reauth_attempts( (int) $user->ID );
	}

	/**
	 * AJAX: Disable 2FA for the current user.
	 */
	public function ajax_disable_user_2fa(): void {
		check_ajax_referer( 'login_armor_2fa_profile', 'nonce' );

		$user_id = get_current_user_id();

		require_once LOGIN_ARMOR_DIR . 'includes/TwoFactor/TwoFactor.php';
		// 2.8.0: nothing to disable on an account that never enrolled. Until
		// then this still ran the reset, closed the other sessions and logged
		// "2FA disabled" for a subscriber who had never switched it on: a
		// journal entry describing an event that did not happen.
		if ( ! TwoFactor\TwoFactor::is_user_enabled( $user_id ) ) {
			wp_send_json_success( [ 'unchanged' => true ] );
		}
		if ( TwoFactor\TwoFactor::is_required_for_user( $user_id ) ) {
			wp_send_json_error( [ 'message' => __( 'Two-factor authentication is required for your role and can only be reset by an administrator.', 'login-armor' ) ], 403 );
		}
		$this->require_current_password();
		// Keep the current session alive (user is mid-action), but invalidate every other session.
		TwoFactor\TwoFactor::reset_user( $user_id, false, 'user' );
		wp_destroy_other_sessions();

		/**
		 * Fires when a user disables 2FA.
		 *
		 * @param int $user_id WordPress user ID.
		 */
		do_action( 'login_armor_2fa_user_disabled', $user_id );

		wp_send_json_success();
	}

	/** AJAX: Reset another user's 2FA as an administrator. */
	public function ajax_admin_reset_user_2fa(): void {
		check_ajax_referer( 'login_armor_2fa_profile', 'nonce' );
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Verified above.
		$user_id = isset( $_POST['user_id'] ) ? absint( wp_unslash( $_POST['user_id'] ) ) : 0;
		if ( $user_id <= 0 || $user_id === get_current_user_id() || ! current_user_can( 'edit_user', $user_id ) || ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( [ 'message' => __( 'You are not allowed to reset two-factor authentication for this user.', 'login-armor' ) ], 403 );
		}
		require_once LOGIN_ARMOR_DIR . 'includes/TwoFactor/TwoFactor.php';
		TwoFactor\TwoFactor::reset_user( $user_id, true, 'admin' );
		if ( TwoFactor\TwoFactor::is_required_for_user( $user_id ) ) {
			TwoFactor\TwoFactor::set_grace_period( $user_id );
		}
		do_action( 'login_armor_2fa_user_reset_by_admin', $user_id, get_current_user_id() );
		wp_send_json_success();
	}

	/**
	 * Add a "Restart 2FA grace" row action on the Users list.
	 *
	 * Only shown for users whose role mandates 2FA but who have not enrolled:
	 * i.e. those at risk of (or already) being hard-blocked at login once their
	 * grace window expires. Clicking it re-opens a fresh grace window so the user
	 * can sign in again and complete setup. Requires `edit_users`.
	 *
	 * Untyped params with defaults: `user_row_actions` is re-fired by user-table
	 * plugins and its signature has historically varied.
	 *
	 * @param mixed $actions Existing row actions (expected array).
	 * @param mixed $user    The user row object (expected WP_User).
	 * @return array Filtered row actions.
	 */
	public function add_2fa_grace_row_action( $actions = [], $user = null ): array {
		$actions = (array) $actions;

		if ( ! $user instanceof \WP_User || ! current_user_can( 'edit_users', $user->ID ) ) {
			return $actions;
		}

		// Only relevant when the 2FA module is active.
		if ( ! get_option( 'login_armor_2fa_enabled', false ) ) {
			return $actions;
		}

		require_once LOGIN_ARMOR_DIR . 'includes/TwoFactor/TwoFactor.php';
		// Enrolled users, or users whose role does not mandate 2FA, need nothing.
		if ( TwoFactor\TwoFactor::is_user_enabled( $user->ID ) || ! TwoFactor\TwoFactor::is_required_for_user( $user->ID ) ) {
			return $actions;
		}

		$url = wp_nonce_url(
			add_query_arg(
				[
					'action' => 'login_armor_restart_2fa_grace',
					'user'   => $user->ID,
				],
				admin_url( 'admin-post.php' )
			),
			'login_armor_restart_2fa_grace_' . $user->ID
		);

		$actions['login_armor_restart_2fa_grace'] = sprintf(
			'<a href="%s">%s</a>',
			esc_url( $url ),
			esc_html__( 'Restart 2FA grace', 'login-armor' )
		);

		return $actions;
	}

	/**
	 * Handle the "Restart 2FA grace" row action.
	 *
	 * Re-opens the 2FA setup window for a target user so an admin can un-block
	 * someone locked out by mandatory-2FA enforcement, without WP-CLI. This does
	 * NOT enrol or disable 2FA for the user: it only resets the deadline clock.
	 */
	public function handle_restart_2fa_grace(): void {
		$user_id = isset( $_GET['user'] ) ? absint( $_GET['user'] ) : 0;

		if ( ! current_user_can( 'edit_users', $user_id ) ) {
			wp_die( esc_html__( 'You are not allowed to do this.', 'login-armor' ), 403 );
		}

		check_admin_referer( 'login_armor_restart_2fa_grace_' . $user_id );

		$target = $user_id > 0 ? get_userdata( $user_id ) : false;
		if ( ! $target ) {
			wp_die( esc_html__( 'Unknown user.', 'login-armor' ), 400 );
		}

		require_once LOGIN_ARMOR_DIR . 'includes/TwoFactor/TwoFactor.php';
		TwoFactor\TwoFactor::set_grace_period( $user_id );

		$redirect = add_query_arg(
			[ 'login_armor_grace_reset' => 1 ],
			wp_get_referer() ? wp_get_referer() : admin_url( 'users.php' )
		);
		wp_safe_redirect( $redirect );
		exit;
	}

	/**
	 * Success notice after an admin restarts a user's 2FA grace window.
	 */
	public function maybe_grace_reset_notice(): void {
		if ( ! current_user_can( 'edit_users' ) ) {
			return;
		}
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Read-only flag, no state change; the state change already happened behind a nonce in handle_restart_2fa_grace().
		if ( empty( $_GET['login_armor_grace_reset'] ) ) {
			return;
		}
		printf(
			'<div class="notice la-notice notice-success is-dismissible"><p>%s</p></div>',
			esc_html__( 'Login Armor: the two-factor setup window has been reopened for this user.', 'login-armor' )
		);
	}

	/**
	 * AJAX: revoke a single trusted device for the current user.
	 */
	public function ajax_2fa_revoke_trusted_device(): void {
		check_ajax_referer( 'login_armor_2fa_profile', 'nonce' );

		$user_id = get_current_user_id();
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Verified above.
		$device_id = isset( $_POST['device_id'] ) ? (string) sanitize_text_field( wp_unslash( $_POST['device_id'] ) ) : '';
		if ( ! preg_match( '/^[a-f0-9]{32}$/', $device_id ) ) {
			wp_send_json_error( [ 'message' => 'invalid device id' ], 400 );
		}

		require_once LOGIN_ARMOR_DIR . 'includes/TwoFactor/TrustedDevices.php';
		$ok = \LoginArmor\TwoFactor\TrustedDevices::revoke_device( $user_id, $device_id );

		if ( ! $ok ) {
			wp_send_json_error( [ 'message' => 'not found' ], 404 );
		}
		wp_send_json_success();
	}

	/**
	 * AJAX: revoke every trusted device for the current user.
	 */
	public function ajax_2fa_revoke_all_trusted_devices(): void {
		check_ajax_referer( 'login_armor_2fa_profile', 'nonce' );

		$user_id = get_current_user_id();
		require_once LOGIN_ARMOR_DIR . 'includes/TwoFactor/TrustedDevices.php';
		$count = \LoginArmor\TwoFactor\TrustedDevices::revoke_all( $user_id, 'user' );

		wp_send_json_success( [ 'revoked' => $count ] );
	}

	/**
	 * AJAX: Regenerate backup codes for the current user.
	 */
	public function ajax_regenerate_backup_codes(): void {
		check_ajax_referer( 'login_armor_2fa_profile', 'nonce' );

		$user_id = get_current_user_id();

		// 2.8.0: backup codes only exist for an enrolled account. Generating
		// them for one without two-factor stored codes that no screen shows
		// and no login ever asks for.
		require_once LOGIN_ARMOR_DIR . 'includes/TwoFactor/TwoFactor.php';
		if ( ! TwoFactor\TwoFactor::is_user_enabled( $user_id ) ) {
			wp_send_json_error( [ 'message' => __( 'Two-factor authentication is not enabled on your account, so it has no backup codes.', 'login-armor' ) ], 409 );
		}
		$this->require_current_password();

		require_once LOGIN_ARMOR_DIR . 'includes/TwoFactor/BackupCodes.php';
		$codes = TwoFactor\BackupCodes::generate( $user_id );

		wp_send_json_success( [ 'backup_codes' => $codes ] );
	}

	/**
	 * Render the 2FA section on the user Profile page.
	 *
	 * Parameter untyped with a guard: `show_user_profile`/`edit_user_profile`
	 * may be re-fired by profile plugins with a user ID or nothing.
	 *
	 * @param mixed $user The user being viewed/edited (expected WP_User).
	 */
	public function render_2fa_profile_section( $user = null ): void {
		if ( ! $user instanceof \WP_User ) {
			return;
		}
		// TwoFactor class is only loaded when the module is enabled (see
		// class-login-armor.php::load_modules). Guard both the class
		// existence AND the enabled flag so viewing /wp-admin/profile.php
		// with 2FA off doesn't throw a fatal.
		if ( ! class_exists( '\\LoginArmor\\TwoFactor\\TwoFactor' ) ) {
			return;
		}
		if ( ! \LoginArmor\TwoFactor\TwoFactor::is_enabled() ) {
			return;
		}

		// Enqueue 2FA assets for profile page.
		wp_enqueue_style(
			'login-armor-2fa',
			plugins_url( 'admin/assets/css/two-factor.css', LOGIN_ARMOR_FILE ),
			[],
			LOGIN_ARMOR_VERSION
		);
		wp_enqueue_style(
			'login-armor-confirm-modal',
			plugins_url( 'admin/assets/css/confirm-modal.css', LOGIN_ARMOR_FILE ),
			[],
			LOGIN_ARMOR_VERSION
		);
		wp_enqueue_script(
			'login-armor-confirm-modal',
			plugins_url( 'admin/assets/js/confirm-modal.js', LOGIN_ARMOR_FILE ),
			[],
			LOGIN_ARMOR_VERSION,
			true
		);
		wp_enqueue_script(
			'login-armor-qr',
			plugins_url( 'admin/assets/js/qr.js', LOGIN_ARMOR_FILE ),
			[],
			LOGIN_ARMOR_VERSION,
			true
		);
		wp_enqueue_style(
			'login-armor-2fa-email-preactivate',
			plugins_url( 'admin/assets/css/two-factor-email-preactivate.css', LOGIN_ARMOR_FILE ),
			[],
			LOGIN_ARMOR_VERSION
		);
		wp_enqueue_script(
			'login-armor-2fa-email-preactivate',
			plugins_url( 'admin/assets/js/two-factor-email-preactivate.js', LOGIN_ARMOR_FILE ),
			[],
			LOGIN_ARMOR_VERSION,
			true
		);
		wp_enqueue_script(
			'login-armor-2fa',
			plugins_url( 'admin/assets/js/two-factor.js', LOGIN_ARMOR_FILE ),
			[ 'login-armor-qr', 'login-armor-confirm-modal', 'login-armor-2fa-email-preactivate' ],
			LOGIN_ARMOR_VERSION,
			true
		);
		// Display the CURRENT user's email (not the edited profile's),
		// because ajax_2fa_email_test() always sends to wp_get_current_user().
		$la_current_user = wp_get_current_user();
		wp_localize_script( 'login-armor-2fa-email-preactivate', 'la2faPreactivate', [
			'ajaxUrl' => admin_url( 'admin-ajax.php' ),
			'nonce'   => wp_create_nonce( 'login_armor_2fa_profile' ),
			'email'   => $la_current_user ? (string) $la_current_user->user_email : '',
			'i18n'    => [
				'title'        => __( 'Before enabling Email two-factor authentication', 'login-armor' ),
				'warning'      => __( 'If your hosting does not deliver emails, you will be locked out of your site.', 'login-armor' ),
				'step1Title'   => __( 'Test email delivery', 'login-armor' ),
				'step1Desc'    => __( 'A test message will be sent to:', 'login-armor' ),
				'sendTest'     => __( 'Send test email', 'login-armor' ),
				'sendAgain'    => __( 'Send another test email', 'login-armor' ),
				'sending'      => __( 'Sending…', 'login-armor' ),
				'testOk'       => __( 'Test email sent. Check your inbox (and spam folder) before continuing.', 'login-armor' ),
				'testFail'     => __( 'The test email could not be sent. Configure WP Mail SMTP (or contact your host) before enabling Email 2FA, otherwise you will be locked out.', 'login-armor' ),
				'step2Title'   => __( 'Open a safety-net session in a different browser', 'login-armor' ),
				'step2Desc'    => __( 'Open a DIFFERENT browser (for example Firefox if you are on Chrome) or a private/incognito window, and stay logged in as administrator there. Tabs of the same browser share cookies, so they are not a real safety net: if you log out to test 2FA, every tab disconnects at once. A different browser keeps a separate session you can use to disable 2FA if email delivery fails.', 'login-armor' ),
				'safetyLabel'  => __( 'I have a different browser (or a private/incognito window) logged in as administrator.', 'login-armor' ),
				'cancel'       => __( 'Cancel', 'login-armor' ),
				'confirm'      => __( 'Enable Email 2FA', 'login-armor' ),
				'networkError' => __( 'Network error. Please try again.', 'login-armor' ),
				'configError'  => __( 'Missing AJAX configuration.', 'login-armor' ),
			],
		] );
		wp_localize_script( 'login-armor-confirm-modal', 'loginArmor', [
			'confirmI18n' => [
				'cancel'   => __( 'Cancel', 'login-armor' ),
				'confirm'  => __( 'Confirm', 'login-armor' ),
				'ack'      => __( 'I understand', 'login-armor' ),
				'password' => __( 'Your password', 'login-armor' ),
			],
		] );
		wp_localize_script( 'login-armor-2fa', 'la2faData', [
			'ajaxUrl'    => admin_url( 'admin-ajax.php' ),
			'nonce'      => wp_create_nonce( 'login_armor_2fa_profile' ),
			'method'     => '',
			'setupToken' => '',
		] );
		wp_localize_script( 'login-armor-2fa', 'la2faStrings', [
			'useOther'          => __( 'Use a different method', 'login-armor' ),
			'hideOther'         => __( 'Hide other methods', 'login-armor' ),
			'resend'            => __( 'Resend code', 'login-armor' ),
			/* translators: %d: number of seconds remaining before the resend button unlocks */
			'resendIn'          => __( 'Resend in %ds', 'login-armor' ),
			'copied'            => __( 'Copied!', 'login-armor' ),
			'copy'              => __( 'Copy', 'login-armor' ),
			'codeRequired'      => __( 'Please enter a 6-digit code.', 'login-armor' ),
			'verifyFailed'      => __( 'Invalid code. Please try again.', 'login-armor' ),
			'networkError'      => __( 'Network error. Please try again.', 'login-armor' ),
			'completeFailed'    => __( 'Setup completion failed. Please reload the page and try again.', 'login-armor' ),
			'confirmDisable'    => __( 'Are you sure you want to disable two-factor authentication?', 'login-armor' ),
			'confirmRegenerate' => __( 'This will invalidate your current backup codes. Continue?', 'login-armor' ),
			// 2.8.0: the two confirmations that ask for the password, and the
			// titles and buttons that were written in English in two-factor.js.
			'disableTitle'      => __( 'Disable 2FA for your account?', 'login-armor' ),
			'disableBody'       => __( 'Enter your password to confirm. Two-factor authentication will be removed from your account and your other sessions will be closed.', 'login-armor' ),
			'disableConfirm'    => __( 'Disable 2FA', 'login-armor' ),
			'regenTitle'        => __( 'Generate new backup codes?', 'login-armor' ),
			'regenBody'         => __( 'Enter your password to confirm. Your previous 8 backup codes will be invalidated immediately. Only the new ones will work.', 'login-armor' ),
			'regenConfirm'      => __( 'Regenerate', 'login-armor' ),
			'cancel'            => __( 'Cancel', 'login-armor' ),
			'passwordLabel'     => __( 'Your password', 'login-armor' ),
			'actionFailed'      => __( 'The change could not be made.', 'login-armor' ),
		] );

		require_once LOGIN_ARMOR_DIR . 'includes/TwoFactor/TwoFactor.php';
		require_once LOGIN_ARMOR_DIR . 'includes/TwoFactor/BackupCodes.php';

		$la_2fa_profile_user = $user;
		include LOGIN_ARMOR_DIR . 'admin/views/profile/two-factor.php';
	}

	/**
	 * Profile section: networks seen per application password (2.9.0).
	 *
	 * Untyped with a guard, like the 2FA section: profile plugins re-fire
	 * these hooks with a user ID or nothing.
	 *
	 * @param mixed $user The user being viewed/edited (expected WP_User).
	 */
	public function render_app_password_networks( $user = null ): void {
		if ( ! $user instanceof \WP_User ) {
			return;
		}
		$la_watching = AppPasswords\Usage::is_watching();
		$rows        = AppPasswords\Usage::rows_for_user( (int) $user->ID );
		if ( array() === $rows && ! $la_watching ) {
			return;
		}
		$la_user        = $user;
		$la_networks    = AppPasswords\Usage::group_by_password( $rows );
		$la_can_approve = current_user_can( 'manage_options' );
		include LOGIN_ARMOR_DIR . 'admin/views/profile/app-password-networks.php';
	}

	/**
	 * admin-post: approve a flagged network of an application password (2.9.0).
	 */
	public function handle_approve_network(): void {
		// phpcs:disable WordPress.Security.NonceVerification.Recommended -- check_admin_referer() below, after the arguments it binds are read.
		$user_id = isset( $_GET['user'] ) ? absint( $_GET['user'] ) : 0;
		$uuid    = isset( $_GET['uuid'] ) ? AppPasswords\Usage::clean_uuid( sanitize_key( wp_unslash( $_GET['uuid'] ) ) ) : '';
		// Not sanitize_text_field(): only the characters of dns:, as: and net:
		// identities are kept, IPv6 ranges included.
		$network = isset( $_GET['network'] ) ? substr( (string) preg_replace( '#[^a-z0-9:./\-]#i', '', (string) wp_unslash( $_GET['network'] ) ), 0, 80 ) : ''; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Filtered by the character whitelist (not sanitize_text_field(), which would delete percent sequences).
		// phpcs:enable WordPress.Security.NonceVerification.Recommended

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You are not allowed to do this.', 'login-armor' ), 403 );
		}
		check_admin_referer( 'login_armor_approve_network_' . $user_id . '_' . $uuid );

		$changed = ( $user_id > 0 && '' !== $uuid && '' !== $network ) ? AppPasswords\Usage::approve( $user_id, $uuid, $network ) : 0;
		if ( $changed > 0 ) {
			/**
			 * Fires after an administrator approved a flagged network.
			 *
			 * @since 2.9.0
			 *
			 * @param int    $user_id  Owner of the password.
			 * @param string $uuid     Password identifier.
			 * @param string $network  Network approved.
			 * @param int    $approver Administrator who approved it.
			 */
			do_action( 'login_armor_app_password_network_approved', $user_id, $uuid, $network, get_current_user_id() );
		}

		$back = wp_get_referer() ? wp_get_referer() : add_query_arg( 'user_id', $user_id, admin_url( 'user-edit.php' ) );
		wp_safe_redirect( add_query_arg( 'login_armor_network_approved', $changed > 0 ? 1 : 0, $back ) . '#login-armor-app-password-networks' );
		exit;
	}

	/**
	 * Let WordPress drop the approval flag from the address once the notice is
	 * shown, so that a reload does not show it again (2.9.0).
	 *
	 * @param mixed $args Query arguments core removes (expected array).
	 * @return mixed
	 */
	public function removable_query_args( $args = array() ) {
		if ( ! is_array( $args ) ) {
			return $args;
		}
		$args[] = 'login_armor_network_approved';
		return $args;
	}

	/**
	 * Notice after an approval (2.9.0).
	 */
	public function maybe_network_approved_notice(): void {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Read-only flag; the change happened behind a nonce.
		if ( ! isset( $_GET['login_armor_network_approved'] ) || ! current_user_can( 'manage_options' ) ) {
			return;
		}
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Read-only flag.
		$ok = '1' === sanitize_key( wp_unslash( $_GET['login_armor_network_approved'] ) );
		printf(
			'<div class="notice la-notice %1$s is-dismissible"><p>%2$s</p></div>',
			esc_attr( $ok ? 'notice-success' : 'notice-warning' ),
			esc_html( $ok ? __( 'Login Armor: the network is approved for this application password.', 'login-armor' ) : __( 'Login Armor: nothing to approve, the network was already approved or is no longer reported.', 'login-armor' ) )
		);
	}

	/**
	 * AJAX: save notification settings.
	 */
	public function ajax_save_notifications(): void {
		$this->guard_admin_action();

		// phpcs:disable WordPress.Security.NonceVerification.Missing -- Verified in guard_admin_action().
		$channel      = isset( $_POST['notif_channel'] ) ? sanitize_key( wp_unslash( $_POST['notif_channel'] ) ) : 'disabled';
		$webhook_url  = isset( $_POST['notif_webhook_url'] ) ? esc_url_raw( wp_unslash( $_POST['notif_webhook_url'] ) ) : '';
		$min_severity = isset( $_POST['notif_min_severity'] ) ? absint( wp_unslash( $_POST['notif_min_severity'] ) ) : 2;
		$rate_limit   = isset( $_POST['notif_rate_limit'] ) ? absint( wp_unslash( $_POST['notif_rate_limit'] ) ) : 10;
		$digest       = isset( $_POST['notif_digest'] ) ? sanitize_key( wp_unslash( $_POST['notif_digest'] ) ) : '';
		// 2.10.0: the digest's own recipient. Absent is silence (an older view).
		$digest_to_raw = isset( $_POST['notif_digest_to'] ) ? trim( sanitize_text_field( wp_unslash( $_POST['notif_digest_to'] ) ) ) : null;
		// phpcs:enable WordPress.Security.NonceVerification.Missing
		$digest_to = null === $digest_to_raw ? null : sanitize_email( $digest_to_raw );
		if ( null !== $digest_to && '' !== $digest_to_raw && ( '' === $digest_to || ! is_email( $digest_to ) ) ) {
			wp_send_json_error( array( 'message' => __( 'The digest recipient is not a valid e-mail address. Nothing was saved.', 'login-armor' ) ), 400 );
		}

		// Validate channel.
		$allowed_channels = [ 'disabled', 'email', 'slack', 'discord', 'generic' ];
		if ( ! in_array( $channel, $allowed_channels, true ) ) {
			$channel = 'disabled';
		}

		// For email: sanitize as email (esc_url_raw may have mangled it).
		if ( 'email' === $channel ) {
			$raw_email  = isset( $_POST['notif_webhook_url'] ) ? sanitize_email( wp_unslash( $_POST['notif_webhook_url'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Missing
			$webhook_url = $raw_email; // Empty = admin_email fallback.
		}

		// Validate URL (must be https, must not resolve to a private/internal IP: SSRF prevention).
		if ( ! in_array( $channel, [ 'disabled', 'email' ], true ) ) {
			if ( '' === $webhook_url || ! str_starts_with( $webhook_url, 'https://' ) ) {
				wp_send_json_error( [ 'message' => __( 'Webhook URL must start with https://.', 'login-armor' ) ] );
			}

			// Full SSRF policy (HTTPS + every A/AAAA record vetted, fail-closed).
			// The same check runs again at each send, but rejecting here gives the
			// admin immediate feedback instead of a silently-dropped notification.
			if ( ! \LoginArmor\Support\SafeUrl::is_safe( $webhook_url ) ) {
				wp_send_json_error( [ 'message' => __( 'Webhook URL must not point to a private, reserved or unresolvable address.', 'login-armor' ) ] );
			}
		}

		// 2.7.0, the scheduled digest. An ABSENT field is silence: an older
		// cached view posts nothing, and must not be read as "switch the
		// digest off". A field that is present but carries a value outside the
		// list is a client defect, and answering "saved" to it would hide the
		// defect behind a green toast. Checked before anything is written, so
		// a refusal leaves the whole form untouched.
		require_once LOGIN_ARMOR_DIR . 'includes/Notifications/Digest.php';
		$digest_class = '\\LoginArmor\\Notifications\\Digest';
		if ( '' !== $digest && ! in_array( $digest, $digest_class::MODES, true ) ) {
			wp_send_json_error( array( 'message' => __( 'Unknown digest period.', 'login-armor' ) ), 400 );
		}

		// Validate severity (1-4).
		$min_severity = max( 1, min( 4, $min_severity ) );

		// Validate rate limit (0-100).
		$rate_limit = max( 0, min( 100, $rate_limit ) );

		// 2.7.0: a successful test proves the destination it was sent to, and
		// nothing else. Called BEFORE the writes below, because it compares
		// what is stored with what is about to be. Re-saving the same
		// destination, which is what happens when only the severity or the
		// cap changes, keeps the proof: nothing has moved.
		\LoginArmor\LoginArmor::forget_notification_test_if_moved( $channel, $webhook_url );

		update_option( 'login_armor_notif_channel', $channel );
		update_option( 'login_armor_notif_webhook_url', $webhook_url );
		update_option( 'login_armor_notif_min_severity', $min_severity );
		update_option( 'login_armor_notif_rate_limit', $rate_limit );
		if ( null !== $digest_to ) {
			update_option( 'login_armor_notif_digest_to', $digest_to, false );
		}

		// The value was validated above, so reaching here with a non-empty
		// $digest means it is one of Digest::MODES.
		if ( '' !== $digest ) {
			$previous_mode = $digest_class::get_mode();
			update_option( $digest_class::OPTION_MODE, $digest );

			// Switching the digest on starts its clock NOW. Without this, a
			// site whose option row still carried a stamp from a previous
			// subscription would send a digest on the very next daily tick,
			// covering a period nobody asked about; and a site that never had
			// one would wait for the first tick to notice. Either way the
			// first digest must cover a full period of real data.
			if ( 'off' === $previous_mode && 'off' !== $digest ) {
				update_option( $digest_class::OPTION_LAST, time(), false );
			}
		}

		wp_send_json_success( array( 'saved' => true ) );
	}

	/**
	 * AJAX: enable notifications by flipping the channel to 'email'.
	 *
	 * Preserves existing webhook_url / severity / rate_limit so admins can
	 * re-enable and fine-tune without losing their previous configuration.
	 */
	public function ajax_enable_notifications(): void {
		$this->guard_admin_action();
		// 2.7.0: this button repoints the alerts just as surely as the form
		// does. The webhook field is preserved, so it is passed unchanged and
		// only the channel can have moved.
		\LoginArmor\LoginArmor::forget_notification_test_if_moved( 'email', (string) get_option( 'login_armor_notif_webhook_url', '' ) );
		update_option( 'login_armor_notif_channel', 'email' );
		wp_send_json_success( [ 'channel' => 'email' ] );
	}

	/**
	 * AJAX: disable notifications by flipping the channel to 'disabled'.
	 *
	 * Preserves webhook_url / severity / rate_limit so re-enabling later
	 * restores the previous configuration exactly.
	 */
	public function ajax_disable_notifications(): void {
		$this->guard_admin_action();
		// 2.7.0: switching the alerts off and back on later is a round trip
		// through two channels. The proof must not survive it, or a site that
		// was disabled for a month would claim its alerts are known to work.
		\LoginArmor\LoginArmor::forget_notification_test_if_moved( 'disabled', (string) get_option( 'login_armor_notif_webhook_url', '' ) );
		update_option( 'login_armor_notif_channel', 'disabled' );
		wp_send_json_success( [ 'channel' => 'disabled' ] );
	}

	/**
	 * AJAX: send a test notification.
	 */
	public function ajax_test_notification(): void {
		$this->guard_admin_action();

		require_once LOGIN_ARMOR_DIR . 'includes/Notifications/ChannelInterface.php';
		require_once LOGIN_ARMOR_DIR . 'includes/Notifications/Dispatcher.php';

		$result = \LoginArmor\Notifications\Dispatcher::send_test();

		if ( $result['success'] ) {
			// 2.7.0: a test that worked is the only proof this site has that
			// its alerts actually arrive, and the button that produced it
			// leaves nothing behind. An unreachable webhook is otherwise
			// indistinguishable from a quiet week. Read by the Site Health
			// test, and forgotten as soon as the channel changes.
			update_option( 'login_armor_notif_last_test_ok', time(), false );
			wp_send_json_success( [ 'message' => $result['message'] ] );
		} else {
			wp_send_json_error( [ 'message' => $result['message'] ] );
		}
	}

	// ── Lot 13: Login Page Security Headers AJAX handlers ────────

	/**
	 * AJAX: enable the login-page security headers module.
	 */
	public function ajax_enable_login_headers(): void {
		$this->guard_admin_action();
		update_option( LoginHeaders::OPTION_ENABLED, true );
		wp_send_json_success( [ 'enabled' => true ] );
	}

	/**
	 * AJAX: disable the login-page security headers module.
	 */
	public function ajax_disable_login_headers(): void {
		$this->guard_admin_action();
		update_option( LoginHeaders::OPTION_ENABLED, false );
		wp_send_json_success( [ 'enabled' => false ] );
	}

	/**
	 * AJAX: save the login-headers profile and optional report URI.
	 *
	 * The report URI is rejected unless it starts with https://, a plain
	 * http:// endpoint would leak its contents over the wire, defeating the
	 * purpose of CSP reporting.
	 */
	public function ajax_save_login_headers(): void {
		$this->guard_admin_action();

		// phpcs:disable WordPress.Security.NonceVerification.Missing -- Verified in guard_admin_action().
		$mode       = isset( $_POST['login_headers_mode'] ) ? sanitize_key( wp_unslash( $_POST['login_headers_mode'] ) ) : 'standard';
		$report_uri = isset( $_POST['login_headers_report_uri'] ) ? esc_url_raw( wp_unslash( $_POST['login_headers_report_uri'] ) ) : '';
		$hsts_mode  = isset( $_POST['login_headers_hsts'] ) ? sanitize_key( wp_unslash( $_POST['login_headers_hsts'] ) ) : 'off';
		// phpcs:enable WordPress.Security.NonceVerification.Missing

		if ( ! in_array( $mode, LoginHeaders::ALLOWED_MODES, true ) ) {
			$mode = 'standard';
		}

		if ( ! in_array( $hsts_mode, LoginHeaders::ALLOWED_HSTS_MODES, true ) ) {
			$hsts_mode = 'off';
		}

		if ( '' !== $report_uri && ! str_starts_with( $report_uri, 'https://' ) ) {
			wp_send_json_error( [ 'message' => __( 'Report URI must start with https://.', 'login-armor' ) ], 400 );
		}

		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Verified in guard_admin_action().
		$sitewide = ! empty( $_POST['login_headers_sitewide'] );

		update_option( LoginHeaders::OPTION_MODE, $mode );
		update_option( LoginHeaders::OPTION_REPORT_URI, $report_uri );
		update_option( LoginHeaders::OPTION_HSTS, $hsts_mode );
		update_option( LoginHeaders::OPTION_SITEWIDE, $sitewide );

		// Recompute the preview so the UI can update without a reload.
		$preview = LoginHeaders::build_headers();

		wp_send_json_success(
			[
				'saved'   => true,
				'mode'    => $mode,
				'hsts'    => $hsts_mode,
				'preview' => $preview,
			]
		);
	}

	// ── Lot 21: Breach Check AJAX handlers ────────

	/**
	 * AJAX: enable the Breach Check module.
	 *
	 * If the email sub-toggle was already on (admin is re-enabling the
	 * module after a previous disable), immediately scan administrator
	 * email addresses so the flagged count reflects reality without
	 * waiting for a full cycle of user logins. Password scan is
	 * technically impossible (WP stores bcrypt/phpass hashes, not
	 * plaintext) so we defer those to each user's next login: the
	 * admin-side copy makes that clear.
	 */
	public function ajax_enable_breach_check(): void {
		$this->guard_admin_action();
		update_option( BreachCheck::OPTION_ENABLED, true );
		// Password check (k-anonymity, no PII transmitted) is enabled by
		// default. Email check sends real email addresses to XposedOrNot
		// and must be explicitly opted-in by the admin via the settings
		// form, per the readme.txt External Services section. Force reset
		// also stays off because it nags real users.
		update_option( BreachCheck::OPTION_CHECK_PASSWORDS, true );
		update_option( BreachCheck::OPTION_CHECK_EMAILS, false );

		wp_send_json_success(
			array(
				'enabled' => true,
				'scan'    => array( 'scanned' => 0, 'flagged' => 0 ),
			)
		);
	}

	/**
	 * AJAX: disable the Breach Check module.
	 */
	public function ajax_disable_breach_check(): void {
		$this->guard_admin_action();
		update_option( BreachCheck::OPTION_ENABLED, false );
		wp_send_json_success( [ 'enabled' => false ] );
	}

	/**
	 * AJAX: save the three Breach Check sub-options (password check,
	 * email check, force reset).
	 */
	public function ajax_save_breach_check(): void {
		$this->guard_admin_action();

		// phpcs:disable WordPress.Security.NonceVerification.Missing -- Verified in guard_admin_action().
		$check_passwords = ! empty( $_POST['breach_check_passwords'] );
		$check_emails    = ! empty( $_POST['breach_check_emails'] );
		$force_reset     = ! empty( $_POST['breach_check_force_reset'] );
		// phpcs:enable WordPress.Security.NonceVerification.Missing

		// Detect the off→on transition on email check so we can trigger
		// an initial admin-email scan. We don't run it on every save:
		// that would hammer the API. Only on the transition.
		$was_checking_emails = (bool) get_option( BreachCheck::OPTION_CHECK_EMAILS, false );

		update_option( BreachCheck::OPTION_CHECK_PASSWORDS, $check_passwords );
		update_option( BreachCheck::OPTION_CHECK_EMAILS, $check_emails );
		update_option( BreachCheck::OPTION_FORCE_RESET, $force_reset );

		$scan = array( 'scanned' => 0, 'flagged' => 0 );
		if ( $check_emails && ! $was_checking_emails && BreachCheck::is_enabled() ) {
			$scan = BreachCheck::scan_admin_emails();
		}

		wp_send_json_success(
			array(
				'saved'           => true,
				'check_passwords' => $check_passwords,
				'check_emails'    => $check_emails,
				'force_reset'     => $force_reset,
				'scan'            => $scan,
			)
		);
	}

	/**
	 * AJAX: enable the Password Policy module with sane defaults.
	 */
	public function ajax_enable_password_policy(): void {
		$this->guard_admin_action();
		$settings            = \LoginArmor\PasswordPolicy::get_settings();
		$settings['enabled'] = true;
		\LoginArmor\PasswordPolicy::save_settings( $settings );
		wp_send_json_success( [ 'enabled' => true ] );
	}

	/**
	 * AJAX: disable the Password Policy module (settings preserved).
	 */
	public function ajax_disable_password_policy(): void {
		$this->guard_admin_action();
		$settings            = \LoginArmor\PasswordPolicy::get_settings();
		$settings['enabled'] = false;
		\LoginArmor\PasswordPolicy::save_settings( $settings );
		wp_send_json_success( [ 'enabled' => false ] );
	}

	/**
	 * AJAX: persist the Password Policy rules.
	 */
	public function ajax_save_password_policy(): void {
		$this->guard_admin_action();

		// phpcs:disable WordPress.Security.NonceVerification.Missing -- Verified in guard_admin_action().
		$input = [
			'enabled'           => ! empty( $_POST['enabled'] ),
			'min_length'        => isset( $_POST['min_length'] ) ? (int) $_POST['min_length'] : 12,
			'require_lower'     => ! empty( $_POST['require_lower'] ),
			'require_upper'     => ! empty( $_POST['require_upper'] ),
			'require_number'    => ! empty( $_POST['require_number'] ),
			'require_symbol'    => ! empty( $_POST['require_symbol'] ),
			'forbid_username'   => ! empty( $_POST['forbid_username'] ),
			'block_compromised' => ! empty( $_POST['block_compromised'] ),
			'expiration_days'   => isset( $_POST['expiration_days'] ) ? (int) $_POST['expiration_days'] : 0,
		];
		// phpcs:enable WordPress.Security.NonceVerification.Missing

		\LoginArmor\PasswordPolicy::save_settings( $input );

		wp_send_json_success( [ 'saved' => true ] );
	}

	/**
	 * AJAX: enable the Session Manager module.
	 */
	public function ajax_enable_session(): void {
		$this->guard_admin_action();
		$settings            = \LoginArmor\SessionManager::get_settings();
		$settings['enabled'] = true;
		\LoginArmor\SessionManager::save_settings( $settings );
		wp_send_json_success( [ 'enabled' => true ] );
	}

	/**
	 * AJAX: disable the Session Manager module (settings preserved).
	 */
	public function ajax_disable_session(): void {
		$this->guard_admin_action();
		$settings            = \LoginArmor\SessionManager::get_settings();
		$settings['enabled'] = false;
		\LoginArmor\SessionManager::save_settings( $settings );
		wp_send_json_success( [ 'enabled' => false ] );
	}

	/**
	 * AJAX: persist the Session Manager settings.
	 */
	public function ajax_save_session(): void {
		$this->guard_admin_action();

		// phpcs:disable WordPress.Security.NonceVerification.Missing -- Verified in guard_admin_action().
		$input = [
			'enabled'            => ! empty( $_POST['enabled'] ),
			'idle_timeout_min'   => isset( $_POST['idle_timeout_min'] ) ? (int) $_POST['idle_timeout_min'] : 0,
			'max_lifetime_hours' => isset( $_POST['max_lifetime_hours'] ) ? (int) $_POST['max_lifetime_hours'] : 0,
			'single_session'     => ! empty( $_POST['single_session'] ),
		];
		// phpcs:enable WordPress.Security.NonceVerification.Missing

		\LoginArmor\SessionManager::save_settings( $input );

		wp_send_json_success( [ 'saved' => true ] );
	}

	/**
	 * AJAX: destroy every session for the current admin except this one.
	 */
	public function ajax_session_logout_others(): void {
		$this->guard_admin_action();
		$done = \LoginArmor\SessionManager::logout_other_devices( get_current_user_id() );
		wp_send_json_success( [ 'done' => $done ] );
	}

	/**
	 * AJAX: enable the GeoIP module.
	 *
	 * Geolocation resolves in the background from 2.6.1 on, so switching it on
	 * has to schedule the prefetch event: without it the module is enabled and
	 * nothing ever fills a badge.
	 */
	public function ajax_enable_geoip(): void {
		$this->guard_admin_action();
		update_option( \LoginArmor\GeoIP::OPTION_ENABLED, true );
		\LoginArmor\GeoIP::sync_prefetch_schedule();
		wp_send_json_success( [ 'enabled' => true ] );
	}

	/**
	 * AJAX: disable the GeoIP module.
	 */
	public function ajax_disable_geoip(): void {
		$this->guard_admin_action();
		update_option( \LoginArmor\GeoIP::OPTION_ENABLED, false );
		\LoginArmor\GeoIP::sync_prefetch_schedule();
		wp_send_json_success( [ 'enabled' => false ] );
	}

	/**
	 * AJAX: switch headless mode on (2.9.0).
	 *
	 * Answers with the toggles it turned off, by key and by label, so the
	 * screen can say exactly what changed. Empty when nothing changed.
	 */
	public function ajax_enable_headless(): void {
		$this->guard_admin_action();
		$turned_off = Headless::enable( get_current_user_id() );
		wp_send_json_success(
			[
				'enabled'    => true,
				'turned_off' => $turned_off,
				'labels'     => Headless::labels( $turned_off ),
			]
		);
	}

	/**
	 * AJAX: switch headless mode off (2.9.0). Nothing is turned back on.
	 */
	public function ajax_disable_headless(): void {
		$this->guard_admin_action();
		Headless::disable( get_current_user_id() );
		wp_send_json_success( [ 'enabled' => false ] );
	}

	/**
	 * AJAX: switch application-password monitoring on or off (2.9.0).
	 */
	public function ajax_set_app_password_watch(): void {
		$this->guard_admin_action();
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Verified in guard_admin_action().
		$enabled = isset( $_POST['enabled'] ) && LoginArmor::to_bool( sanitize_key( wp_unslash( $_POST['enabled'] ) ) );
		\LoginArmor\AppPasswords\Usage::set_watching( $enabled );
		wp_send_json_success( [ 'enabled' => $enabled ] );
	}

	// ── Request Firewall AJAX handlers ────────

	/**
	 * AJAX: enable the Request Firewall. Always starts in monitor (log-only)
	 * mode: the firewall never begins blocking traffic the instant it is
	 * switched on; the admin must consciously flip it to enforce.
	 */
	public function ajax_enable_firewall(): void {
		$this->guard_admin_action();
		// set_enabled( true ) always resets the mode to log_only, so calling
		// it on a module that is already on demotes an enforcing firewall to
		// monitoring. Enabling something already enabled is a no-op by
		// definition; make it one. Since 2.7.0 the cost of not doing it is
		// worse than a silent demotion: the monitoring stamp survives the
		// save, so the banner would immediately offer a monitoring period
		// that was really spent enforcing.
		if ( ! \LoginArmor\Firewall\Firewall::is_enabled() ) {
			\LoginArmor\Firewall\Firewall::set_enabled( true );
		}
		wp_send_json_success(
			[
				'enabled' => true,
				'mode'    => \LoginArmor\Firewall\Firewall::get_mode(),
			]
		);
	}

	/**
	 * AJAX: disable the Request Firewall.
	 */
	public function ajax_disable_firewall(): void {
		$this->guard_admin_action();
		\LoginArmor\Firewall\Firewall::set_enabled( false );
		wp_send_json_success( [ 'enabled' => false ] );
	}

	/**
	 * AJAX: save the firewall mode, family toggles and allowlists. Does not
	 * touch the master enabled flag (that is enable/disable only).
	 */
	public function ajax_save_firewall(): void {
		$this->guard_admin_action();

		// phpcs:disable WordPress.Security.NonceVerification.Missing -- Verified in guard_admin_action().
		$input = [
			'mode'                   => isset( $_POST['firewall_mode'] ) ? sanitize_key( wp_unslash( $_POST['firewall_mode'] ) ) : 'log_only',
			'query_string'           => ! empty( $_POST['firewall_query_string'] ),
			'request_uri'            => ! empty( $_POST['firewall_request_uri'] ),
			'request_method'         => ! empty( $_POST['firewall_request_method'] ),
			'user_agent'             => ! empty( $_POST['firewall_user_agent'] ),
			'referer'                => ! empty( $_POST['firewall_referer'] ),
			'request_uri_aggressive' => ! empty( $_POST['firewall_request_uri_aggressive'] ),
			'allow_ips'              => isset( $_POST['firewall_allow_ips'] ) ? sanitize_textarea_field( wp_unslash( $_POST['firewall_allow_ips'] ) ) : '',
			'allow_paths'            => isset( $_POST['firewall_allow_paths'] ) ? sanitize_textarea_field( wp_unslash( $_POST['firewall_allow_paths'] ) ) : '',
		];
		// phpcs:enable WordPress.Security.NonceVerification.Missing

		\LoginArmor\Firewall\Firewall::save_settings( $input );

		$settings = \LoginArmor\Firewall\Firewall::get_settings();
		wp_send_json_success(
			[
				'saved' => true,
				'mode'  => $settings['mode'],
			]
		);
	}

	// ── Bot Challenge (Proof-of-Work) AJAX handlers ────────

	/**
	 * AJAX: enable the Bot Challenge. Always starts in monitor (log-only)
	 * mode: the challenge never begins rejecting logins the instant it is
	 * switched on; the admin must consciously flip it to enforce.
	 */
	public function ajax_enable_pow(): void {
		$this->guard_admin_action();
		// Same invariant as ajax_enable_firewall(): set_enabled( true ) resets
		// the mode, so it must never run against a module that is already on.
		if ( ! \LoginArmor\PowChallenge::is_enabled() ) {
			\LoginArmor\PowChallenge::set_enabled( true );
		}
		wp_send_json_success(
			[
				'enabled' => true,
				'mode'    => \LoginArmor\PowChallenge::get_mode(),
			]
		);
	}

	/**
	 * AJAX: disable the Bot Challenge.
	 */
	public function ajax_disable_pow(): void {
		$this->guard_admin_action();
		\LoginArmor\PowChallenge::set_enabled( false );
		wp_send_json_success( [ 'enabled' => false ] );
	}

	/**
	 * AJAX: save the Bot Challenge mode and difficulty. Does not touch the
	 * master enabled flag (that is enable/disable only).
	 */
	public function ajax_save_pow(): void {
		$this->guard_admin_action();

		// phpcs:disable WordPress.Security.NonceVerification.Missing -- Verified in guard_admin_action().
		$input = [
			'mode'       => isset( $_POST['pow_mode'] ) ? sanitize_key( wp_unslash( $_POST['pow_mode'] ) ) : 'log_only',
			'difficulty' => isset( $_POST['pow_difficulty'] ) ? sanitize_key( wp_unslash( $_POST['pow_difficulty'] ) ) : 'standard',
		];
		// phpcs:enable WordPress.Security.NonceVerification.Missing

		\LoginArmor\PowChallenge::save_settings( $input );

		$settings = \LoginArmor\PowChallenge::get_settings();
		wp_send_json_success(
			[
				'saved' => true,
				'mode'  => $settings['mode'],
			]
		);
	}

	// ── Onboarding wizard + Safe Baseline ────────

	/**
	 * One-shot redirect to the onboarding wizard right after a fresh, single-
	 * site, interactive activation. Guards against bulk activation, the network
	 * admin, and AJAX so it never hijacks anything else.
	 */
	public function maybe_onboarding_redirect(): void {
		if ( ! get_transient( 'login_armor_activation_redirect' ) ) {
			return;
		}
		delete_transient( 'login_armor_activation_redirect' );

		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- read-only activation routing check.
		if ( isset( $_GET['activate-multi'] ) || is_network_admin() || wp_doing_ajax() ) {
			return;
		}
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}

		wp_safe_redirect( admin_url( 'admin.php?page=login-armor&la-onboarding=1' ) );
		exit;
	}

	/**
	 * AJAX: record the onboarding choice. In "simple" mode the safe baseline is
	 * applied; in "advanced" mode nothing is changed. Either way the install is
	 * marked onboarded so the wizard never auto-appears again.
	 *
	 * The answer carries SafeBaseline::apply()'s report, whose `items` say, for
	 * each protection, what it was before and what it is now. Since 2.7.1 the
	 * wizard renders that list instead of redirecting on trust, and treats an
	 * answer without it as a failure: the whole point is that nothing is
	 * claimed that cannot be checked on the screen that claims it.
	 *
	 * The "advanced" branch is kept although the wizard no longer posts it. It
	 * was always a no-op (render_page() marks the install onboarded as soon as
	 * the wizard is displayed), and dropping it would make an "advanced" POST
	 * from a page left open in another tab fall through to the baseline.
	 */
	public function ajax_onboard(): void {
		$this->guard_admin_action();

		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Verified in guard_admin_action().
		$mode    = isset( $_POST['mode'] ) ? sanitize_key( wp_unslash( $_POST['mode'] ) ) : 'advanced';
		$summary = array();

		if ( 'simple' === $mode && class_exists( '\LoginArmor\Setup\SafeBaseline' ) ) {
			$summary = \LoginArmor\Setup\SafeBaseline::apply();
		}

		update_option( 'login_armor_onboarded', true );

		wp_send_json_success(
			[
				'mode'     => 'simple' === $mode ? 'simple' : 'advanced',
				'summary'  => $summary,
				'redirect' => admin_url( 'admin.php?page=login-armor&tab=settings' ),
			]
		);
	}

	/**
	 * AJAX: apply the safe baseline from the permanent Settings-tab button.
	 */
	public function ajax_apply_safe_baseline(): void {
		$this->guard_admin_action();

		if ( ! class_exists( '\LoginArmor\Setup\SafeBaseline' ) ) {
			wp_send_json_error( [ 'message' => __( 'Could not load the safe baseline.', 'login-armor' ) ], 500 );
		}

		$summary = \LoginArmor\Setup\SafeBaseline::apply();
		update_option( 'login_armor_onboarded', true );

		wp_send_json_success( [ 'summary' => $summary ] );
	}

	/**
	 * Show an informational notice on Login Armor screens when another
	 * security plugin that overlaps the login/hardening surface is active,
	 * so admins know to avoid double-configuring the same protections
	 * (a frequent cause of lockouts and support tickets). Read-only: we
	 * never deactivate anything.
	 */
	public function maybe_render_conflict_notice(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Read-only page routing check.
		$page = isset( $_GET['page'] ) ? sanitize_key( wp_unslash( $_GET['page'] ) ) : '';
		if ( 'login-armor' !== $page ) {
			return;
		}

		// The two shared maps below load this themselves; the front-end login
		// loop at the end of this method calls is_plugin_active() directly
		// and still needs it, because admin_notices fires on screens where
		// wp-admin/includes/plugin.php has not been pulled in.
		if ( ! function_exists( 'is_plugin_active' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}

		// Translatable, reusable labels for the overlapping protection surfaces.
		$la_ov = [
			'brute'     => __( 'brute-force protection', 'login-armor' ),
			'firewall'  => __( 'firewall', 'login-armor' ),
			'2fa'       => __( 'two-factor authentication', 'login-armor' ),
			'hide'      => __( 'login URL hiding', 'login-armor' ),
			'headers'   => __( 'security headers', 'login-armor' ),
			'hardening' => __( 'hardening', 'login-armor' ),
			'limit'     => __( 'login rate-limiting', 'login-armor' ),
		];

		// Which competitor is running, and what it duplicates, are two
		// different questions. Since 2.7.0 the first one is answered by
		// \LoginArmor\Support\PluginDetection, which the Site Health test
		// asks as well: two copies of a plugin list drift the first time a
		// competitor renames its main file. The wording below stays here,
		// because it belongs to this notice and to nothing else.
		$known = \LoginArmor\Support\PluginDetection::security_plugin_map();

		$lines = [];
		foreach ( \LoginArmor\Support\PluginDetection::active_security_plugins() as $file => $name ) {
			$labels = [];
			foreach ( $known[ $file ]['overlaps'] as $key ) {
				if ( isset( $la_ov[ $key ] ) ) {
					$labels[] = $la_ov[ $key ];
				}
			}
			$lines[] = '<strong>' . esc_html( $name ) . '</strong> &mdash; ' . esc_html( implode( ', ', $labels ) );
		}

		if ( ! empty( $lines ) ) {
			printf(
				'<div class="notice la-notice notice-warning"><p><strong>%s</strong></p><p>%s</p><p>%s</p></div>',
				esc_html__( 'Login Armor: another security plugin overlaps with this one', 'login-armor' ),
				wp_kses( implode( '<br>', $lines ), [ 'strong' => [], 'br' => [] ] ),
				esc_html__( 'Running two plugins for the same protection causes double lockouts, hidden-login clashes and duplicated headers. Enable each protection in only one plugin to avoid locking yourself out.', 'login-armor' )
			);
		}

		// Cache plugins are only a problem when Hide Login is active. Three
		// URLs are at stake, not one: the secret slug can be served from the
		// page cache as a stale 404, and `/wp-login.php` and `/wp-admin/` are
		// decoys whose answer is a setting the administrator can change, which
		// a stored copy freezes (see HideLogin::refuse_page_cache()).
		//
		// This notice asks for work that happens in ANOTHER plugin's settings,
		// so it needs a way to be answered. Until 2.7.1 it had none: it carried
		// no dismiss control and stored no state, so an administrator who had
		// configured the exclusion exactly as asked was shown the same warning
		// on every page load, for ever, with nothing to click.
		//
		// Deliberately NOT implemented: reading the cache plugin's own
		// exclusion list. Five products, five private formats that each change
		// between their own releases, and a wrong "all good" is far worse than
		// a nag: it tells an administrator the login page is safe from the
		// cache when it is not. The dismissal is therefore a statement by the
		// administrator, and the notice says so in those words.
		$la_hide_on = class_exists( '\LoginArmor\HideLogin' ) && \LoginArmor\HideLogin::is_enabled();
		if ( $la_hide_on ) {
			$cache_found = array_values( \LoginArmor\Support\PluginDetection::active_cache_plugins() );
			$cache_key   = \LoginArmor\Support\PluginDetection::cache_set_key();
			if ( ! empty( $cache_found ) && ! self::cache_notice_dismissed( $cache_key ) ) {
				// The two decoy endpoints, printed so they can be copied
				// rather than guessed. Until 2.7.1 this notice named only the
				// hidden URL, and an administrator who excluded exactly that
				// still had a broken site: the decoys are what was cached.
				//
				// The hidden URL is NOT printed here, on purpose, and a test
				// holds that line. An admin notice is the thing people
				// screenshot into a support thread (a 2.5.3 defect was found
				// in one), so this notice describes the hidden URL and lets
				// the Hide Login section below be the one place that shows it.
				//
				// `wp-login.php` is NOT built with site_url( 'wp-login.php' ):
				// HideLogin filters `site_url` and would hand back the secret
				// slug, so the notice would print the hidden URL after all and
				// never name the endpoint that is actually cached. admin_url()
				// goes through the same filter but carries no wp-login.php, so
				// it comes back untouched.
				$cache_root = trailingslashit( site_url( '/' ) );
				$cache_list = '';
				foreach ( [ $cache_root . 'wp-login.php', admin_url() ] as $cache_url ) {
					$cache_list .= '<li><code>' . esc_html( (string) $cache_url ) . '</code></li>';
				}

				printf(
					'<div class="notice la-notice notice-warning is-dismissible" data-la-notice="cache-exclusion"><p><strong>%1$s</strong><br>%2$s</p><ul>%3$s</ul><p>%4$s</p><p>%5$s</p></div>',
					esc_html__( 'Login Armor: caching plugin detected with Hide Login active', 'login-armor' ),
					esc_html(
						sprintf(
							/* translators: %s: comma-separated list of cache plugin names. */
							__( 'We detected: %s. Exclude your hidden login URL, shown in the Hide Login section further down this page, from the page cache. Exclude these two decoy endpoints as well:', 'login-armor' ),
							implode( ', ', $cache_found )
						)
					),
					wp_kses( $cache_list, [ 'li' => [], 'code' => [] ] ),
					esc_html__( 'Those two are decoys, and their answer is recomputed on every request: a stored copy freezes it. This is not hypothetical. On a live site with /wp-login.php cached, changing Blocked Access Redirect from the 404 page to a custom URL had no visible effect at all, while /wp-admin/ obeyed the new setting straight away. Login Armor now asks every caching plugin to skip these responses, but a server-level or CDN cache configured outside WordPress never sees that, and a copy stored before this version stays until it is purged.', 'login-armor' ),
					esc_html__( 'Dismiss this notice once the exclusion is in place: it records that you have configured it. Login Armor cannot read your caching plugin\'s exclusion list, so this is your confirmation and not a verified result. The notice returns if a different caching plugin is detected later.', 'login-armor' )
				);
			}
		}

		// Front-end login / membership plugins replace the WordPress login form
		// with their own on public pages. Login Armor's login-flow modules key
		// off wp-login.php and the core auth redirect, so Two-Factor enforcement
		// and Hide Login are structurally incompatible with them: a member with
		// 2FA is redirected to the wp-login.php verify screen mid-submit, which
		// breaks the plugin's (often AJAX) front-end login. Reproduced with
		// Ultimate Member (a 2FA-enrolled subscriber can no longer sign in).
		// This is a documented incompatibility, not something Login Armor adapts
		// to; the notice only tells the admin which modules to leave off.
		$la_frontend_login = apply_filters(
			'login_armor_frontend_login_plugins',
			[
				'ultimate-member/ultimate-member.php' => 'Ultimate Member',
			]
		);
		$la_fl_found = [];
		foreach ( $la_frontend_login as $la_fl_file => $la_fl_name ) {
			if ( is_plugin_active( $la_fl_file ) ) {
				$la_fl_found[] = $la_fl_name;
			}
		}
		$la_2fa_on = (bool) get_option( 'login_armor_2fa_enabled', false );
		if ( ! empty( $la_fl_found ) && ( $la_2fa_on || $la_hide_on ) ) {
			printf(
				'<div class="notice la-notice notice-warning"><p><strong>%s</strong><br>%s</p></div>',
				esc_html(
					sprintf(
						/* translators: %s: comma-separated list of front-end login plugin names. */
						__( 'Login Armor: front-end login plugin detected: %s', 'login-armor' ),
						implode( ', ', $la_fl_found )
					)
				),
				esc_html__( "This plugin handles sign-in on your own pages, not wp-login.php. Login Armor's Two-Factor and Hide Login work on the WordPress login flow and are not compatible with it: a member could be locked out of the front-end login. Keep Two-Factor and Hide Login turned off while this plugin manages your logins. Brute-force protection, hardening, detection and the firewall are unaffected.", 'login-armor' )
			);
		}
	}

	/**
	 * Has this exact set of caches already been confirmed as excluded?
	 *
	 * Compared WHOLE, against the stored set. A dismissal recorded for WP
	 * Rocket alone must not silence the warning on a site that has since added
	 * LiteSpeed Cache, whose exclusion nobody has written yet, and a
	 * two-cache confirmation must not answer for one of the two on its own.
	 * A substring or count comparison would pass one of those cases and fail
	 * the other; both are covered by tests/cache-notice.php.
	 *
	 * A plain strict comparison, deliberately, and not hash_equals(): neither
	 * side is a secret and nothing here is timing-sensitive, so the plugin's
	 * hash_equals() rule (which is about secrets) does not apply, and reaching
	 * for it anyway would suggest a threat that is not there.
	 *
	 * @since 2.7.1
	 *
	 * @param string $key Current set, from PluginDetection::cache_set_key().
	 * @return bool
	 */
	private static function cache_notice_dismissed( string $key ): bool {
		if ( '' === $key ) {
			return false;
		}

		$stored = (string) get_option( self::OPTION_CACHE_NOTICE_DISMISSED, '' );

		return '' !== $stored && $stored === $key;
	}

	/**
	 * AJAX: record that the cache-exclusion notice has been answered.
	 *
	 * The set is recomputed here rather than taken from the request. What the
	 * browser last rendered is not evidence of what is active now, and a key
	 * posted by the client would let one request silence a cache plugin that
	 * was never detected.
	 *
	 * @since 2.7.1
	 */
	public function ajax_dismiss_cache_notice(): void {
		$this->guard_admin_action();

		$key = \LoginArmor\Support\PluginDetection::cache_set_key();
		if ( '' === $key ) {
			// Nothing is running, so there is nothing to confirm. Writing an
			// empty value here would store a row that can never match a real
			// set, and would read as "dismissed" to anyone inspecting it.
			wp_send_json_error( [ 'message' => __( 'No caching plugin is active.', 'login-armor' ) ], 400 );
		}

		update_option( self::OPTION_CACHE_NOTICE_DISMISSED, $key, false );

		wp_send_json_success( [ 'dismissed' => $key ] );
	}

	/**
	 * Handle settings form submissions.
	 */
	public function handle_form_submission(): void {
		if ( ! isset( $_POST['login_armor_nonce'] ) ) {
			return;
		}

		if ( ! wp_verify_nonce( sanitize_text_field( wp_unslash( $_POST['login_armor_nonce'] ) ), 'login_armor_settings' ) ) {
			wp_die( esc_html__( 'Security check failed.', 'login-armor' ) );
		}

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Unauthorized access.', 'login-armor' ) );
		}

		$tab = isset( $_POST['login_armor_tab'] )
			? sanitize_key( $_POST['login_armor_tab'] )
			: 'hide';

		switch ( $tab ) {
			case 'limit':
				$this->save_limit_settings();
				break;

			case 'logs':
				$this->save_logs_settings();
				break;
		}

		wp_safe_redirect(
			add_query_arg(
				[
					'page'             => 'login-armor',
					'tab'              => $tab,
					'settings-updated' => 'true',
				],
				admin_url( 'admin.php' )
			)
		);
		exit;
	}

	/**
	 * Save Limit Login settings.
	 *
	 * Nonce and capability have already been verified in handle_form_submission().
	 */
	private function save_limit_settings(): void {
		// phpcs:disable WordPress.Security.NonceVerification.Missing -- Nonce verified upstream in handle_form_submission().
		$fields = [
			'login_armor_allowed_retries'  => [ 'min' => 1, 'max' => 100 ],
			'login_armor_lockout_duration' => [ 'min' => 1, 'max' => 1440 ],
			'login_armor_max_lockouts'     => [ 'min' => 1, 'max' => 100 ],
			'login_armor_long_duration'    => [ 'min' => 1, 'max' => 720 ],
			'login_armor_notify_threshold' => [ 'min' => 0, 'max' => 100 ],
		];

		foreach ( $fields as $key => $rules ) {
			if ( isset( $_POST[ $key ] ) ) {
				$value = absint( wp_unslash( $_POST[ $key ] ) );
				$value = max( $rules['min'], min( $rules['max'], $value ) );
				update_option( $key, $value );
			}
		}

		// Whitelist IPs: one per line, validate each.
		$whitelist_raw = isset( $_POST['login_armor_whitelist_ips'] )
			? sanitize_textarea_field( wp_unslash( $_POST['login_armor_whitelist_ips'] ) )
			: '';

		$lines     = array_filter( array_map( 'trim', explode( "\n", $whitelist_raw ) ) );
		$valid_ips = [];
		foreach ( $lines as $line ) {
			if ( filter_var( $line, FILTER_VALIDATE_IP ) ) {
				$valid_ips[] = $line;
			}
		}
		update_option( 'login_armor_whitelist_ips', implode( "\n", $valid_ips ) );

		// Notification email.
		$notify_email = isset( $_POST['login_armor_notify_email'] )
			? sanitize_email( wp_unslash( $_POST['login_armor_notify_email'] ) )
			: '';
		update_option( 'login_armor_notify_email', $notify_email );
		// phpcs:enable WordPress.Security.NonceVerification.Missing
	}

	/**
	 * Save Logs settings (auto-purge configuration).
	 *
	 * Nonce and capability have already been verified in handle_form_submission().
	 */
	private function save_logs_settings(): void {
		// phpcs:disable WordPress.Security.NonceVerification.Missing -- Nonce verified upstream in handle_form_submission().
		if ( isset( $_POST['login_armor_logs_auto_purge'] ) ) {
			$days = absint( wp_unslash( $_POST['login_armor_logs_auto_purge'] ) );
			update_option( 'login_armor_logs_auto_purge', $days );
		}
		// phpcs:enable WordPress.Security.NonceVerification.Missing
	}

	/**
	 * AJAX handler: unblock an IP address.
	 */
	public function ajax_unblock_ip(): void {
		check_ajax_referer( 'login_armor_ajax', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( [ 'message' => __( 'Unauthorized.', 'login-armor' ) ] );
		}

		$ip = isset( $_POST['ip'] )
			? sanitize_text_field( wp_unslash( $_POST['ip'] ) )
			: '';

		if ( ! filter_var( $ip, FILTER_VALIDATE_IP ) ) {
			wp_send_json_error( [ 'message' => __( 'Invalid IP address.', 'login-armor' ) ] );
		}

		$deleted = LimitLogin::unblock_ip( $ip );

		wp_send_json_success( [
			'message' => sprintf(
				/* translators: %s: IP address that was unblocked. */
				__( 'IP %s has been unblocked.', 'login-armor' ),
				$ip
			),
			'deleted' => $deleted,
		] );
	}

	/**
	 * AJAX handler: purge old logs.
	 */
	public function ajax_purge_logs(): void {
		check_ajax_referer( 'login_armor_ajax', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( [ 'message' => __( 'Unauthorized.', 'login-armor' ) ] );
		}

		$days = isset( $_POST['days'] ) ? absint( $_POST['days'] ) : 0;

		if ( $days > 0 ) {
			$deleted = LoginLogs::purge_logs( $days );
		} else {
			$deleted = LoginLogs::purge_all_logs();
		}

		wp_send_json_success( [
			'message' => sprintf(
				/* translators: %d: Number of log entries deleted. */
				__( '%d log entries deleted.', 'login-armor' ),
				$deleted
			),
			'deleted' => $deleted,
		] );
	}

	/**
	 * Get the currently active tab.
	 */
	public static function get_current_tab(): string {
		$tab = isset( $_GET['tab'] ) ? sanitize_key( $_GET['tab'] ) : 'hide'; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( ! in_array( $tab, [ 'hide', 'limit', 'logs' ], true ) ) {
			$tab = 'hide';
		}
		return $tab;
	}

	/**
	 * V2.1.1 B10, AJAX: verify the activity-log hash chain.
	 *
	 * Runs ActivityLog::verify_chain() and caches the result in a transient
	 * (login_armor_chain_verify_last, 7 day TTL) so the Integrity panel can
	 * surface the last-known status without re-walking the table.
	 */
	public function ajax_activity_verify_chain(): void {
		$this->guard_admin_action();

		$result = \LoginArmor\ActivityLog\ActivityLog::verify_chain();
		set_transient( 'login_armor_chain_verify_last', $result, 7 * DAY_IN_SECONDS );
		wp_send_json_success( $result );
	}

	/**
	 * V2.1.1 B10, AJAX: repair the activity-log hash chain.
	 *
	 * Re-walks rows missing prev_hash/row_hash and links them to the latest
	 * sealed row. Returns the number of repaired rows.
	 */
	public function ajax_activity_repair_chain(): void {
		$this->guard_admin_action();

		$repaired = \LoginArmor\ActivityLog\ActivityLog::repair_chain();
		wp_send_json_success( [ 'repaired' => $repaired ] );
	}

	/**
	 * V2.1.20, AJAX: re-baseline the activity-log hash chain.
	 *
	 * Remedy offered when verify reports `salt_changed` (a benign security-key
	 * rotation from a migration / restored backup left pre-change rows
	 * unverifiable). Re-signs every row under the current key, records the new
	 * baseline, re-verifies, and caches the fresh panel state. Returns the new
	 * verify result so the Integrity panel flips to INTACT without a reload.
	 */
	public function ajax_activity_reset_chain(): void {
		$this->guard_admin_action();

		$reset  = \LoginArmor\ActivityLog\ActivityLog::reset_chain();
		$result = \LoginArmor\ActivityLog\ActivityLog::verify_chain();
		set_transient( 'login_armor_chain_verify_last', $result, 7 * DAY_IN_SECONDS );

		wp_send_json_success( array_merge( $result, [ 'rows_resigned' => (int) $reset['rows'] ] ) );
	}

	/**
	 * V2.1.1 B10, AJAX: send a synthetic test event to the configured webhook.
	 *
	 * Builds a fake row (genesis hashes, action=webhook_test, no DB write),
	 * signs it via WebhookDispatcher::sign(), and POSTs the payload to the
	 * configured OPTION_URL. Returns http_status + truncated response_body
	 * so the admin UI can display the receiver's reaction.
	 */
	public function ajax_webhook_test(): void {
		$this->guard_admin_action();

		$url = (string) get_option( \LoginArmor\ActivityLog\WebhookDispatcher::OPTION_URL, '' );
		if ( ! \LoginArmor\ActivityLog\WebhookDispatcher::is_safe_url( $url ) ) {
			wp_send_json_error( [ 'message' => __( 'Webhook URL is not configured, invalid, or points to a private or reserved address.', 'login-armor' ) ] );
		}

		$current       = wp_get_current_user();
		$synthetic_row = [
			'id'          => 0,
			'user_id'     => (int) $current->ID,
			'user_login'  => (string) $current->user_login,
			'user_role'   => 'administrator',
			'action'      => 'webhook_test',
			'object_type' => 'system',
			'object_id'   => 0,
			'object_name' => 'webhook-test',
			'description' => 'LoginArmor webhook test event from admin UI',
			'ip'          => \LoginArmor\LoginArmor::get_client_ip(),
			'log_time'    => gmdate( 'Y-m-d H:i:s' ),
			'prev_hash'   => str_repeat( '0', 64 ),
			'row_hash'    => str_repeat( '0', 64 ),
		];

		$payload = \LoginArmor\ActivityLog\WebhookDispatcher::build_payload( $synthetic_row );
		if ( '' === $payload ) {
			wp_send_json_error( [ 'message' => __( 'Failed to build test payload.', 'login-armor' ) ] );
		}
		$signature = \LoginArmor\ActivityLog\WebhookDispatcher::sign( $payload );

		$response = wp_safe_remote_post(
			$url,
			[
				'timeout'     => 10,
				'redirection' => 0,
				'blocking'    => true,
				'headers'     => [
					'Content-Type' => 'application/json',
					'User-Agent'   => 'LoginArmor-Webhook/' . ( defined( 'LOGIN_ARMOR_VERSION' ) ? LOGIN_ARMOR_VERSION : '2.1.1' ) . ' (test)',
					\LoginArmor\ActivityLog\WebhookDispatcher::SIGNATURE_HEADER => $signature,
					\LoginArmor\ActivityLog\WebhookDispatcher::TIMESTAMP_HEADER => (string) time(),
					\LoginArmor\ActivityLog\WebhookDispatcher::EVENT_ID_HEADER  => '0',
				],
				'body'        => $payload,
			]
		);

		if ( is_wp_error( $response ) ) {
			wp_send_json_error( [ 'message' => $response->get_error_message() ] );
		}

		$code = (int) wp_remote_retrieve_response_code( $response );
		$body = (string) wp_remote_retrieve_body( $response );
		wp_send_json_success(
			[
				'http_status'   => $code,
				'response_body' => mb_substr( $body, 0, 1000 ),
			]
		);
	}

	/**
	 * V2.1.1 B10, AJAX: rotate the webhook signing secret.
	 *
	 * Returns the freshly minted secret so the admin UI can show it once
	 * (the same value is also persisted in OPTION_SECRET).
	 */
	public function ajax_webhook_regenerate_secret(): void {
		$this->guard_admin_action();
		$new_secret = \LoginArmor\ActivityLog\WebhookDispatcher::regenerate_secret();
		wp_send_json_success( [ 'secret' => $new_secret ] );
	}

	/**
	 * V2.1.1 B10, AJAX: persist webhook URL + enabled toggle.
	 *
	 * Validates HTTPS scheme strictly (`stripos === 0`) so http:// (even with
	 * mixed-case shenanigans) is rejected when the webhook is enabled. Empty
	 * URL is allowed when disabling, so admins can clear the field.
	 */
	public function ajax_webhook_save(): void {
		$this->guard_admin_action();

		// phpcs:disable WordPress.Security.NonceVerification.Missing -- Verified in guard_admin_action().
		$enabled = ! empty( $_POST['webhook_enabled'] ) ? 1 : 0;
		$url     = isset( $_POST['webhook_url'] ) ? esc_url_raw( wp_unslash( (string) $_POST['webhook_url'] ) ) : '';
		// phpcs:enable WordPress.Security.NonceVerification.Missing

		if ( $enabled && ! \LoginArmor\ActivityLog\WebhookDispatcher::is_safe_url( $url ) ) {
			wp_send_json_error( [ 'message' => __( 'Webhook URL must be a valid HTTPS URL that does not point to a private or reserved address.', 'login-armor' ) ] );
		}

		update_option( \LoginArmor\ActivityLog\WebhookDispatcher::OPTION_ENABLED, $enabled );
		update_option( \LoginArmor\ActivityLog\WebhookDispatcher::OPTION_URL, $url );
		wp_send_json_success();
	}

	// ── Settings transfer (export / import), 2.6.0 ────────

	/**
	 * AJAX (GET): download every setting as a JSON attachment.
	 *
	 * Webhook URLs are included only when the admin ticked the opt-in box;
	 * the SIEM signing secret and per-user 2FA enrolments never leave.
	 */
	public function ajax_settings_export(): void {
		$this->guard_admin_action();

		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Verified in guard_admin_action().
		$include_webhooks = ! empty( $_GET['include_webhooks'] );

		$json = \LoginArmor\Settings\Exporter::to_json( \LoginArmor\Settings\Exporter::build( $include_webhooks ) );

		nocache_headers();
		header( 'Content-Type: application/json; charset=utf-8' );
		header( 'Content-Disposition: attachment; filename="' . \LoginArmor\Settings\Exporter::filename() . '"' );
		header( 'Content-Length: ' . strlen( $json ) );

		while ( ob_get_level() > 0 ) {
			ob_end_clean();
		}

		echo $json; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- JSON attachment produced by wp_json_encode(), not HTML.
		exit;
	}

	/**
	 * AJAX: preview (mode=preview, the default) or apply (mode=apply) a
	 * settings file. Stateless on purpose: both modes re-run parse + plan on
	 * the text the browser sends, so nothing "pre-validated" is trusted and
	 * no transient bridges the two clicks.
	 */
	public function ajax_settings_import(): void {
		$this->guard_admin_action();

		// phpcs:disable WordPress.Security.NonceVerification.Missing -- Verified in guard_admin_action().
		$mode     = isset( $_POST['mode'] ) && 'apply' === $_POST['mode'] ? 'apply' : 'preview';
		$json     = '';
		// tmp_name is a server-generated path, only ever handed to is_uploaded_file():
		// unslashing would corrupt Windows paths and sanitizing a path is meaningless.
		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized, WordPress.Security.ValidatedSanitizedInput.MissingUnslash
		$tmp_name = isset( $_FILES['file']['tmp_name'] ) && is_string( $_FILES['file']['tmp_name'] ) ? $_FILES['file']['tmp_name'] : '';
		$tmp_size = isset( $_FILES['file']['size'] ) ? absint( wp_unslash( $_FILES['file']['size'] ) ) : 0;
		if ( '' !== $tmp_name && is_uploaded_file( $tmp_name ) ) {
			if ( $tmp_size > \LoginArmor\Settings\Importer::MAX_BYTES ) {
				wp_send_json_error( array( 'message' => __( 'This file is too large to be a Login Armor settings export.', 'login-armor' ) ), 413 );
			}
			$json = (string) file_get_contents( $tmp_name ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Size-capped PHP upload verified by is_uploaded_file(); WP_Filesystem does not cover tmp uploads.
		} elseif ( isset( $_POST['payload'] ) && is_string( $_POST['payload'] ) ) {
			// Raw JSON document: sanitize_text_field() would corrupt it. It is
			// vetted structurally by Importer::parse() and value by value by
			// Importer::plan(); nothing from it is echoed unescaped.
			$json = wp_unslash( $_POST['payload'] ); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
		}
		// phpcs:enable WordPress.Security.NonceVerification.Missing

		if ( strlen( $json ) > \LoginArmor\Settings\Importer::MAX_BYTES ) {
			wp_send_json_error( array( 'message' => __( 'This file is too large to be a Login Armor settings export.', 'login-armor' ) ), 413 );
		}

		$parsed = \LoginArmor\Settings\Importer::parse( $json );
		if ( is_wp_error( $parsed ) ) {
			wp_send_json_error( array( 'message' => $parsed->get_error_message(), 'errors' => array() ), 400 );
		}

		$context = array(
			'source'    => 'admin',
			'user_id'   => get_current_user_id(),
			'client_ip' => LoginArmor::get_client_ip(),
		);
		$plan    = \LoginArmor\Settings\Importer::plan( $parsed, $context );
		$payload = self::settings_plan_payload( $plan );

		if ( 'preview' === $mode ) {
			if ( ! empty( $plan['errors'] ) ) {
				$payload['message'] = __( 'This file cannot be imported. Fix the errors below and try again; nothing was changed.', 'login-armor' );
				wp_send_json_error( $payload, 400 );
			}
			wp_send_json_success( $payload );
		}

		if ( ! empty( $plan['errors'] ) ) {
			$payload['message'] = __( 'This file cannot be imported. Nothing was changed.', 'login-armor' );
			wp_send_json_error( $payload, 400 );
		}

		$report = \LoginArmor\Settings\Importer::apply( $plan, $context );
		if ( is_wp_error( $report ) ) {
			wp_send_json_error( array( 'message' => $report->get_error_message(), 'errors' => array() ), 400 );
		}

		wp_send_json_success(
			array(
				'applied'   => $report['applied'],
				'unchanged' => $report['unchanged'],
				'warnings'  => $report['warnings'],
				'errors'    => $report['errors'],
				'login_url' => $report['login_url'],
			)
		);
	}

	/**
	 * Plan -> JSON-friendly rows for the preview table.
	 *
	 * @param array<string,mixed> $plan
	 * @return array<string,mixed>
	 */
	private static function settings_plan_payload( array $plan ): array {
		$rows = array();
		foreach ( $plan['entries'] as $row ) {
			$rows[] = array(
				'module'   => (string) $row['group'],
				'setting'  => (string) $row['path'],
				'current'  => self::settings_value_label( $row['current'] ),
				'incoming' => self::settings_value_label( $row['incoming'] ),
				'status'   => (string) $row['status'],
			);
		}
		usort( $rows, static fn( array $a, array $b ): int => strcmp( $a['status'], $b['status'] ) ?: strcmp( $a['setting'], $b['setting'] ) );

		return array(
			'source'           => array(
				'host'        => (string) ( $plan['envelope']['source']['host'] ?? '' ),
				'version'     => (string) ( $plan['envelope']['plugin_version'] ?? '' ),
				'exported_at' => (string) ( $plan['envelope']['exported_at'] ?? '' ),
			),
			'rows'             => $rows,
			'counts'           => $plan['counts'],
			'warnings'         => $plan['warnings'],
			'errors'           => $plan['errors'],
			'unknown'          => $plan['unknown'],
			'login_url_before' => $plan['login_url_before'],
			'login_url_after'  => $plan['login_url_after'],
		);
	}

	/**
	 * One-line, human-readable rendering of a setting value for the diff.
	 */
	private static function settings_value_label( mixed $value ): string {
		if ( is_bool( $value ) ) {
			return $value ? __( 'on', 'login-armor' ) : __( 'off', 'login-armor' );
		}
		if ( is_array( $value ) ) {
			if ( array_is_list( $value ) ) {
				return empty( $value ) ? __( '(empty)', 'login-armor' ) : implode( ', ', array_map( 'strval', $value ) );
			}
			$parts = array();
			foreach ( $value as $k => $v ) {
				$parts[] = $k . '=' . self::settings_value_label( $v );
			}
			return implode( ' ', $parts );
		}
		if ( '' === $value || null === $value ) {
			return __( '(empty)', 'login-armor' );
		}
		return (string) $value;
	}
}
