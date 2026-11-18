<?php
/**
 * LoginArmor Settings tab (Lot 18 redesign).
 *
 * Score card + settings list wrapper. Individual settings forms come from
 * admin/views/sections/*.php: those files are NOT touched in Lot 18 and
 * continue to consume the $la_* locals declared below.
 *
 * @package LoginArmor
 */

// phpcs:disable WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/*
 * -----------------------------------------------------------------
 * Locals consumed by admin/views/sections/*.php (kept from Lot 5-13).
 * -----------------------------------------------------------------
 */

$la_enabled = \LoginArmor\HideLogin::is_enabled();
$la_slug    = (string) get_option( \LoginArmor\HideLogin::OPTION_SLUG, '' );

// Display-only placeholder for the URL preview when Hide Login has never
// been enabled. Do NOT persist it: otherwise simply opening the Settings
// page would write "loginarmor" (a plugin-signature slug trivially guessed
// by scanners) to the DB before the user has chosen anything. The real
// slug is generated on activation by HideLogin::__construct or the
// ajax_enable_hide handler, both of which call generate_slug().
if ( '' === $la_slug ) {
	$la_slug = 'loginarmor';
}

$la_login_url     = \LoginArmor\HideLogin::build_login_url( '/' . $la_slug );
$la_redirect_type = \LoginArmor\HideLogin::normalize_redirect_type(
	(string) get_option( \LoginArmor\HideLogin::OPTION_REDIRECT_TYPE, \LoginArmor\HideLogin::REDIRECT_NOT_FOUND )
);
$la_redirect_url  = (string) get_option( \LoginArmor\HideLogin::OPTION_REDIRECT_URL, '' );

$la_hardening = \LoginArmor\Hardening::get_settings();
$la_toggles   = \LoginArmor\Hardening::get_toggles();

// 2.7.0 - what Force HTTPS is ACTUALLY doing right now. Safe mode brings it
// down to nothing without touching the option, so the switch in the card keeps
// showing what is STORED (saving that form must never switch off a toggle the
// administrator armed) while the card says out loud that nothing is enforced.
// Same shape as $la_fw_effective and $la_pow_effective below.
$la_hard_https_on        = ! empty( $la_hardening['force_https'] );
$la_hard_https_effective = \LoginArmor\Hardening::force_https_effective();

// Lot 6: Brute Force Protection section.
$la_limit_enabled    = (bool) get_option( 'login_armor_limit_enabled', true );
$la_allowed_retries  = (int) get_option( 'login_armor_allowed_retries', 4 );
$la_lockout_duration = (int) get_option( 'login_armor_lockout_duration', 20 );
$la_max_lockouts     = (int) get_option( 'login_armor_max_lockouts', 4 );
$la_long_duration    = (int) get_option( 'login_armor_long_duration', 24 );
$la_valid_duration   = (int) get_option( 'login_armor_valid_duration', 24 );
$la_whitelist_ips    = (string) get_option( 'login_armor_whitelist_ips', '' );
$la_notify_threshold = (int) get_option( 'login_armor_notify_threshold', 5 );
$la_notify_email     = (string) get_option( 'login_armor_notify_email', '' );
// 2.10.0: syslog lines for fail2ban, and whether this PHP can write them.
$la_syslog           = \LoginArmor\LoginArmor::to_bool( get_option( 'login_armor_syslog', 0 ) );
$la_syslog_available = function_exists( 'openlog' ) && function_exists( 'syslog' );
$la_ip_method        = (string) get_option( 'login_armor_ip_method', 'REMOTE_ADDR' );
$la_trusted_proxies  = (string) get_option( 'login_armor_trusted_proxies', '' );

// Lot 6: Detection & Logs section.
$la_detection_enabled = (bool) get_option( 'login_armor_detection_enabled', true );
$la_retention_days    = (int) get_option(
	'login_armor_log_retention_days',
	(int) get_option( 'login_armor_logs_auto_purge', 90 )
);
$la_auto_purge        = (bool) get_option( 'login_armor_auto_purge', true );

// Lot 13: Login Page Security Headers section.
$la_login_headers_enabled    = \LoginArmor\LoginHeaders::is_enabled();
$la_login_headers_mode       = \LoginArmor\LoginHeaders::get_mode();
$la_login_headers_report_uri = (string) get_option( \LoginArmor\LoginHeaders::OPTION_REPORT_URI, '' );
$la_login_headers_hsts       = \LoginArmor\LoginHeaders::get_hsts_mode();
$la_login_headers_sitewide   = \LoginArmor\LoginHeaders::is_sitewide_enabled();

// Lot 9: Activity Log section.
$la_activity_enabled   = (bool) get_option( 'login_armor_activity_enabled', false );
$la_activity_retention = (int) get_option( 'login_armor_activity_retention', 90 );

// V2.1.1 B12: Activity Webhook Forwarding section.
// V2.1.2 hotfix: WebhookDispatcher lives under ActivityLog/ which is loaded
// conditionally (Activity Log module disabled by default on fresh installs).
// The Settings tab MUST require_once the file explicitly, otherwise this whole
// tab fatal-errors with "Class WebhookDispatcher not found" on every fresh
// install where the user hasn't yet enabled Activity Log.
require_once LOGIN_ARMOR_DIR . 'includes/ActivityLog/WebhookDispatcher.php';
$la_webhook_enabled = (bool) get_option( \LoginArmor\ActivityLog\WebhookDispatcher::OPTION_ENABLED, false );
$la_webhook_url     = (string) get_option( \LoginArmor\ActivityLog\WebhookDispatcher::OPTION_URL, '' );
$la_webhook_secret  = \LoginArmor\ActivityLog\WebhookDispatcher::get_secret();

// V2.1.1 B12-fixup: Activity Webhook stats (cached 5 min, admin tab read on every page load).
// V2.1.8 LA-217-AUDIT-01: guard the SELECT against table-missing (Activity Log never
// enabled OR `wp plugin install --force` reactivation that doesn't re-fire activate hook).
// Without this guard, every Settings tab load on a fresh install emits 3 DB warnings:
// `Table '<prefix>login_armor_webhook_queue' doesn't exist`. Non-fatal, but pollutes log.
$la_webhook_stats = wp_cache_get( 'login_armor_webhook_stats_7d', 'login-armor' );
if ( false === $la_webhook_stats ) {
	global $wpdb;
	$la_queue_table = $wpdb->prefix . 'login_armor_webhook_queue';
	// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- One cached schema guard for the plugin-owned queue table.
	$la_table_exists = (string) $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $wpdb->esc_like( $la_queue_table ) ) ) === $la_queue_table;
	if ( $la_table_exists ) {
		$la_cutoff = gmdate( 'Y-m-d H:i:s', time() - 7 * DAY_IN_SECONDS );
		// Cached for five minutes below; direct reads target only the plugin-owned queue table.
		// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
		$la_webhook_stats = array(
			'queued' => (int) $wpdb->get_var( $wpdb->prepare( 'SELECT COUNT(*) FROM %i WHERE state IN (\'new\',\'sending\') AND created_at >= %s', $la_queue_table, $la_cutoff ) ),
			'sent'   => (int) $wpdb->get_var( $wpdb->prepare( 'SELECT COUNT(*) FROM %i WHERE state=\'sent\' AND created_at >= %s', $la_queue_table, $la_cutoff ) ),
			'dead'   => (int) $wpdb->get_var( $wpdb->prepare( 'SELECT COUNT(*) FROM %i WHERE state=\'dead\' AND created_at >= %s', $la_queue_table, $la_cutoff ) ),
		);
		// phpcs:enable WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
	} else {
		// Fresh install without Activity Log → return zero counts.
		$la_webhook_stats = array( 'queued' => 0, 'sent' => 0, 'dead' => 0 );
	}
	wp_cache_set( 'login_armor_webhook_stats_7d', $la_webhook_stats, 'login-armor', 5 * MINUTE_IN_SECONDS );
}

// Lot 10: Two-Factor Authentication section.
$la_2fa_enabled = (bool) get_option( 'login_armor_2fa_enabled', false );
$la_2fa_methods = (array) get_option( 'login_armor_2fa_methods', array( 'totp', 'email', 'backup' ) );
$la_2fa_enforce = (array) get_option( 'login_armor_2fa_enforce_roles', array() );
$la_2fa_grace   = (int) get_option( 'login_armor_2fa_grace_days', 3 );

// Lot 7: Notifications section.
$la_notif_channel      = (string) get_option( 'login_armor_notif_channel', 'disabled' );
$la_notif_webhook_url  = (string) get_option( 'login_armor_notif_webhook_url', '' );
$la_notif_min_severity = (int) get_option( 'login_armor_notif_min_severity', 2 );
$la_notif_rate_limit   = (int) get_option( 'login_armor_notif_rate_limit', 10 );
// 2.7.0: the scheduled digest. Read through the class so an unknown stored
// value falls back to 'off' here exactly as it does on the cron tick.
require_once LOGIN_ARMOR_DIR . 'includes/Notifications/Digest.php';
$la_notif_digest      = \LoginArmor\Notifications\Digest::get_mode();
$la_notif_digest_last = (int) get_option( \LoginArmor\Notifications\Digest::OPTION_LAST, 0 );
// 2.10.0: the digest's own recipient.
$la_notif_digest_to   = (string) get_option( \LoginArmor\Notifications\Digest::OPTION_TO, '' );

/*
 * -----------------------------------------------------------------
 * Score card computation (Lot 18).
 * -----------------------------------------------------------------
 */

$la_score = \LoginArmor\SecurityScore::compute();
$la_next  = \LoginArmor\SecurityScore::next_action();
// r=44, circumference = 2πr ≈ 276.46. Keep float precision so the arc
// covers exactly score% of the circle (score=50 → dashoffset=138.23).
$la_ring_circumference = 2 * M_PI * 44; // 276.4601…
$la_ring_off           = number_format( $la_ring_circumference * ( 1 - ( (int) $la_score / 100 ) ), 2, '.', '' );
$la_ring_dasharray     = number_format( $la_ring_circumference, 2, '.', '' );
?>

<header class="la-page-header">
	<div>
		<span class="la-kicker"><?php esc_html_e( 'SETTINGS', 'login-armor' ); ?></span>
		<h2><?php esc_html_e( 'Protection modules', 'login-armor' ); ?></h2>
		<p class="la-lead"><?php esc_html_e( "Each module is one click. Enable what applies, skip what doesn't.", 'login-armor' ); ?></p>
	</div>
</header>

<section class="la-score-card">
	<div class="la-score-ring" data-la-score="<?php echo esc_attr( (string) $la_score ); ?>">
		<svg viewBox="0 0 100 100" width="88" height="88" aria-hidden="true" style="transform: rotate(-90deg);">
			<circle class="la-score-ring__bg" cx="50" cy="50" r="44" fill="none" stroke="rgba(255,255,255,0.08)" stroke-width="8"/>
			<circle class="la-score-ring__fg" cx="50" cy="50" r="44" fill="none" stroke="#10b981" stroke-width="8" stroke-linecap="round"
				stroke-dasharray="<?php echo esc_attr( $la_ring_dasharray ); ?>" stroke-dashoffset="<?php echo esc_attr( $la_ring_off ); ?>"/>
		</svg>
		<span class="la-score-ring__num"><?php echo esc_html( (string) $la_score ); ?></span>
	</div>
	<div class="la-score-copy">
		<span class="la-score-kicker"><?php esc_html_e( 'SECURITY SCORE', 'login-armor' ); ?></span>
		<h3><?php echo esc_html( (string) $la_next['title'] ); ?></h3>
		<p><?php echo esc_html( (string) $la_next['body'] ); ?></p>
	</div>
	<a class="la-score-cta" href="<?php echo esc_url( (string) $la_next['cta_url'] ); ?>">
		<?php echo esc_html( (string) $la_next['cta_label'] ); ?>
	</a>
</section>

<div class="la-baseline">
	<div class="la-baseline__icon" aria-hidden="true">
		<?php \LoginArmor\Icons::render( 'shield', '', 18 ); ?>
	</div>
	<div class="la-baseline__text">
		<strong class="la-baseline__title"><?php esc_html_e( 'New here? Start with the safe essentials', 'login-armor' ); ?></strong>
		<span class="la-baseline__desc"><?php esc_html_e( 'One click turns on the protections that can’t lock you out or break your theme, including the request firewall and the bot challenge in monitor mode, where they record without blocking. Hide Login and Two-Factor stay untouched.', 'login-armor' ); ?></span>
	</div>
	<div class="la-baseline__actions">
		<button type="button" class="la-btn la-btn--primary la-baseline__btn" data-la-action="apply-safe-baseline">
			<?php esc_html_e( 'Enable recommended protections', 'login-armor' ); ?>
		</button>
		<a class="la-baseline__link" href="<?php echo esc_url( add_query_arg( array( 'page' => 'login-armor', 'la-onboarding' => '1' ), admin_url( 'admin.php' ) ) ); ?>">
			<?php esc_html_e( 'Review the setup assistant', 'login-armor' ); ?>
		</a>
	</div>
</div>

<?php require LOGIN_ARMOR_DIR . 'admin/views/sections/settings-transfer.php'; ?>

<?php
/*
 * Each module is wrapped in a <details>/<summary> "setting row" so the
 * Settings screen reads as a collapsed list: icon + label + state pill
 * + chevron on the summary; the section's full form in the body. This
 * matches the Claude.ai handoff pattern (collapsed row + inline
 * expansion). Hardening and any module in a non-nominal "warn" state
 * (e.g. partial hardening) defaults to open so the issue is visible.
 */
$la_hard_settings = class_exists( '\LoginArmor\Hardening' ) ? \LoginArmor\Hardening::get_settings() : array();
$la_hard_toggles  = class_exists( '\LoginArmor\Hardening' ) ? \LoginArmor\Hardening::get_toggles() : array();
$la_hard_active   = 0;
$la_hard_counted  = 0;
// 2.9.0: in headless mode the two guarded toggles are not choices the
// administrator can make, so they leave the count, as they leave the score.
$la_hard_excluded = ( class_exists( '\LoginArmor\Headless' ) && \LoginArmor\Headless::is_enabled() ) ? \LoginArmor\Headless::GUARDED_TOGGLES : array();
foreach ( $la_hard_toggles as $la_t ) {
	if ( in_array( $la_t['key'], $la_hard_excluded, true ) ) {
		continue;
	}
	++$la_hard_counted;
	if ( ! empty( $la_hard_settings[ $la_t['key'] ] ) ) {
		++$la_hard_active;
	}
}
$la_hard_total = max( 1, $la_hard_counted );

$la_2fa_on       = (bool) get_option( 'login_armor_2fa_enabled', false );
$la_hide_on      = class_exists( '\LoginArmor\HideLogin' ) && \LoginArmor\HideLogin::is_enabled();
$la_limit_on     = (bool) get_option( 'login_armor_limit_enabled', true );
$la_detection_on = (bool) get_option( 'login_armor_detection_enabled', true );
$la_activity_on  = (bool) get_option( 'login_armor_activity_enabled', false );
$la_headers_on   = class_exists( '\LoginArmor\LoginHeaders' ) && \LoginArmor\LoginHeaders::is_enabled();
$la_breach_enabled         = class_exists( '\LoginArmor\BreachCheck' ) && \LoginArmor\BreachCheck::is_enabled();
$la_breach_check_passwords = (bool) get_option( 'login_armor_breach_check_passwords', true );
$la_breach_check_emails    = (bool) get_option( 'login_armor_breach_check_emails', false );
$la_breach_force_reset     = (bool) get_option( 'login_armor_breach_check_force_reset', false );
$la_breach_flagged_counts  = class_exists( '\LoginArmor\BreachCheck' ) ? \LoginArmor\BreachCheck::get_flagged_counts() : array( 'password' => 0, 'email' => 0 );
$la_breach_flagged_users   = class_exists( '\LoginArmor\BreachCheck' ) ? \LoginArmor\BreachCheck::get_flagged_users( 20 ) : array( 'password' => array(), 'email' => array() );
$la_notif_on     = 'disabled' !== (string) get_option( 'login_armor_notif_channel', 'disabled' );

// Password Policy section state.
$la_pwpolicy         = class_exists( '\LoginArmor\PasswordPolicy' ) ? \LoginArmor\PasswordPolicy::get_settings() : array();
$la_pwpolicy_enabled = class_exists( '\LoginArmor\PasswordPolicy' ) && \LoginArmor\PasswordPolicy::is_enabled();

// Session Manager section state.
$la_session         = class_exists( '\LoginArmor\SessionManager' ) ? \LoginArmor\SessionManager::get_settings() : array();
$la_session_enabled = class_exists( '\LoginArmor\SessionManager' ) && \LoginArmor\SessionManager::is_enabled();
$la_session_count   = ( $la_session_enabled && is_user_logged_in() ) ? \LoginArmor\SessionManager::active_session_count( get_current_user_id() ) : 0;

// GeoIP section state.
$la_geoip_enabled = class_exists( '\LoginArmor\GeoIP' ) && \LoginArmor\GeoIP::is_enabled();

// Headless section state (2.9.0).
$la_headless_on    = class_exists( '\LoginArmor\Headless' ) && \LoginArmor\Headless::is_enabled();
$la_app_watch_on   = class_exists( '\LoginArmor\AppPasswords\Usage', false ) && \LoginArmor\AppPasswords\Usage::is_watching();
// The note says the family blocks, so it only shows when the firewall really blocks (effective mode, safe mode included).
$la_fw_ua_on       = class_exists( '\LoginArmor\Firewall\Firewall' ) && \LoginArmor\Firewall\Firewall::is_enabled() && 'enforce' === \LoginArmor\Firewall\Firewall::effective_mode() && ! empty( \LoginArmor\Firewall\Firewall::get_settings()['user_agent'] );
$la_author_enum_on = ! empty( $la_hard_settings['prevent_author_enum'] );

// Request Firewall section state.
$la_fw_class    = class_exists( '\LoginArmor\Firewall\Firewall' );
$la_fw          = $la_fw_class ? \LoginArmor\Firewall\Firewall::get_settings() : array();
$la_fw_enabled  = $la_fw_class && \LoginArmor\Firewall\Firewall::is_enabled();
$la_fw_mode     = $la_fw_class ? \LoginArmor\Firewall\Firewall::get_mode() : 'log_only';
// 2.7.0 - what this module is ACTUALLY doing right now. Safe mode brings it
// down to observation without touching the stored mode, so the radios below
// keep showing what is stored (saving the form must never silently downgrade
// a firewall the administrator set to enforce) while every status read-out
// shows the truth.
$la_fw_effective = $la_fw_class ? \LoginArmor\Firewall\Firewall::effective_mode() : 'log_only';
$la_fw_server   = $la_fw_class ? \LoginArmor\Firewall\Firewall::detect_server() : 'unknown';
$la_fw_blocks30 = ( $la_fw_enabled && $la_fw_class ) ? \LoginArmor\Firewall\Firewall::count_blocks( '30d' ) : 0;
$la_fw_recent   = ( $la_fw_enabled && $la_fw_class ) ? \LoginArmor\Firewall\Firewall::recent_blocks( 5 ) : array();

// Bot Challenge (Proof-of-Work) section state.
$la_pow_class      = class_exists( '\LoginArmor\PowChallenge' );
$la_pow_enabled    = $la_pow_class && \LoginArmor\PowChallenge::is_enabled();
$la_pow_mode       = $la_pow_class ? \LoginArmor\PowChallenge::get_mode() : 'log_only';
$la_pow_effective  = $la_pow_class ? \LoginArmor\PowChallenge::effective_mode() : 'log_only';
$la_pow_settings   = $la_pow_class ? \LoginArmor\PowChallenge::get_settings() : array();
$la_pow_difficulty = isset( $la_pow_settings['difficulty'] ) ? (string) $la_pow_settings['difficulty'] : 'standard';
$la_pow_softfails  = ( $la_pow_enabled && $la_pow_class ) ? \LoginArmor\PowChallenge::get_softfail_count() : 0;

// AI Assistant section state (WP7 native AI Client).
$la_ai_native_ok = \LoginArmor\AI\Client::is_available();
$la_ai_state     = $la_ai_native_ok ? 'on' : 'off';
$la_ai_pill      = $la_ai_native_ok ? __( 'Available', 'login-armor' ) : __( 'Needs WP 7', 'login-armor' );

/*
 * 2.7.1 - 'aliases': search keywords indexed by the Settings search box and
 * never rendered. The index is built from what the page shows, and the box
 * matches on plain substrings, so a translated label silently takes its own
 * abbreviation out of reach: on a French site the two-factor module reads
 * "A2F", and "2fa" is not a substring of "a2f". The box then answered "No
 * matching module" for the exact term its own placeholder offers. Each list
 * carries the English technical name, the usual abbreviations and the other
 * language's word, and nothing the label already spells out. The wrapper id is
 * indexed too (see initSettingsSearch), so the slug of every module is free.
 */
$la_sections = array(
	array(
		'id'      => 'hide-login',
		'file'    => 'hide-login.php',
		'icon'    => 'shield',
		'label'   => __( 'Hide Login', 'login-armor' ),
		'aliases' =>
			/* translators: search keywords for the Settings search box, never displayed. Space-separated. Keep the English terms and add the ones an administrator types in your language. */
			__( 'rename custom secret slug masquer cacher connexion', 'login-armor' ),
		'desc'    => $la_hide_on
			? __( 'Your login URL is hidden. Direct access attempts return a 404.', 'login-armor' )
			: __( 'Move your login page to a secret URL. Your /wp-login.php is currently reachable.', 'login-armor' ),
		'state'   => $la_hide_on ? 'on' : 'off',
		'pill'    => $la_hide_on ? __( 'Protected', 'login-armor' ) : __( 'Disabled', 'login-armor' ),
		'disable_action' => 'hide-disable',
	),
	array(
		'id'      => 'hardening',
		'file'    => 'hardening.php',
		'icon'    => 'lock',
		'label'   => __( 'Hardening', 'login-armor' ),
		'aliases' =>
			/* translators: search keywords for the Settings search box, never displayed. Space-separated. Keep the English terms and add the ones an administrator types in your language. */
			__( 'harden lockdown durcissement durcir renforcer securisation', 'login-armor' ),
		'desc'    => __( 'Quick security wins. Each toggle hardens one attack surface.', 'login-armor' ),
		'state'   => ( $la_hard_active === $la_hard_total ) ? 'on' : ( $la_hard_active > 0 ? 'warn' : 'off' ),
		/* translators: 1: active count, 2: total count */
		'pill'    => sprintf( __( '%1$d of %2$d', 'login-armor' ), $la_hard_active, $la_hard_total ),
		'disable_action' => '', // per-toggle; no master disable.
	),
	array(
		'id'      => 'headless',
		'file'    => 'headless.php',
		'icon'    => 'shield',
		'label'   => __( 'Headless back end', 'login-armor' ),
		'aliases' =>
			/* translators: search keywords for the Settings search box, never displayed. Space-separated. Keep the English terms and add the ones an administrator types in your language. */
			__( 'headless decoupled rest api application passwords nextjs nuxt astro decouple mot de passe application', 'login-armor' ),
		'desc'    => $la_headless_on
			? __( 'Restrict REST API and Disable application passwords are kept off.', 'login-armor' )
			: __( 'For a WordPress that serves its REST API to a separate front end.', 'login-armor' ),
		'state'   => $la_headless_on ? 'on' : 'off',
		'pill'    => $la_headless_on ? __( 'Active', 'login-armor' ) : __( 'Disabled', 'login-armor' ),
		'disable_action' => 'headless-disable',
	),
	array(
		'id'      => 'limit-login',
		'file'    => 'limit-login.php',
		'icon'    => 'circle-slash',
		'label'   => __( 'Brute Force Protection', 'login-armor' ),
		'aliases' =>
			/* translators: search keywords for the Settings search box, never displayed. Space-separated. Keep the English terms and add the ones an administrator types in your language. */
			__( 'bruteforce lockout rate limiting ban dictionnaire', 'login-armor' ),
		'desc'    => __( 'Rate-limit failed login attempts and lock out attacking IPs.', 'login-armor' ),
		'state'   => $la_limit_on ? 'on' : 'off',
		'pill'    => $la_limit_on ? __( 'Active', 'login-armor' ) : __( 'Disabled', 'login-armor' ),
		'disable_action' => 'limit-disable',
	),
	array(
		'id'      => 'detection-logs',
		'file'    => 'detection-logs.php',
		'icon'    => 'file',
		'label'   => __( 'Detection & Logs', 'login-armor' ),
		'aliases' =>
			/* translators: search keywords for the Settings search box, never displayed. Space-separated. Keep the English terms and add the ones an administrator types in your language. */
			__( 'cleanup housekeeping historique conservation evenements', 'login-armor' ),
		'desc'    => __( 'Log retention and automatic cleanup.', 'login-armor' ),
		'state'   => $la_detection_on ? 'on' : 'off',
		'pill'    => $la_detection_on ? __( 'Active', 'login-armor' ) : __( 'Disabled', 'login-armor' ),
		'disable_action' => 'detection-disable',
	),
	array(
		'id'      => 'login-headers',
		'file'    => 'login-headers.php',
		'icon'    => 'shield',
		'label'   => __( 'Login Page Protection Headers', 'login-armor' ),
		'aliases' =>
			/* translators: search keywords for the Settings search box, never displayed. Space-separated. Keep the English terms and add the ones an administrator types in your language. */
			__( 'entetes clickjacking csp hsts referrer securite', 'login-armor' ),
		'desc'    => __( 'Block clickjacking, MIME sniffing, and credential exfiltration on the login page.', 'login-armor' ),
		'state'   => $la_headers_on ? 'on' : 'off',
		'pill'    => $la_headers_on ? __( 'Active', 'login-armor' ) : __( 'Disabled', 'login-armor' ),
		'disable_action' => 'login-headers-disable',
	),
	array(
		'id'      => 'breach-check',
		'file'    => 'breach-check.php',
		'icon'    => 'search',
		'label'   => __( 'Breach Check', 'login-armor' ),
		'aliases' =>
			/* translators: search keywords for the Settings search box, never displayed. Space-separated. Keep the English terms and add the ones an administrator types in your language. */
			__( 'pwned haveibeenpwned hibp leak compromis fuite', 'login-armor' ),
		'desc'    => __( 'Detect passwords and emails that appear in public data breach corpora.', 'login-armor' ),
		'state'   => $la_breach_enabled ? 'on' : 'off',
		'pill'    => $la_breach_enabled ? __( 'Active', 'login-armor' ) : __( 'Disabled', 'login-armor' ),
		'disable_action' => 'breach-check-disable',
		// Count pill rendered next to the "Active" pill when there are
		// flagged accounts, so the Settings tab surfaces the signal
		// even when the breach-check section is collapsed.
		'count'   => $la_breach_enabled
			? (int) ( ( $la_breach_flagged_counts['password'] ?? 0 ) + ( $la_breach_flagged_counts['email'] ?? 0 ) )
			: 0,
	),
	array(
		'id'      => 'password-policy',
		'file'    => 'password-policy.php',
		'icon'    => 'lock',
		'label'   => __( 'Password Policy', 'login-armor' ),
		'aliases' =>
			/* translators: search keywords for the Settings search box, never displayed. Space-separated. Keep the English terms and add the ones an administrator types in your language. */
			__( 'complexity strength complexite robustesse solidite', 'login-armor' ),
		'desc'    => __( 'Enforce strong, unique passwords and block ones found in public breaches.', 'login-armor' ),
		'state'   => $la_pwpolicy_enabled ? 'on' : 'off',
		'pill'    => $la_pwpolicy_enabled ? __( 'Active', 'login-armor' ) : __( 'Disabled', 'login-armor' ),
		'disable_action' => 'password-policy-disable',
	),
	array(
		'id'      => 'session',
		'file'    => 'session.php',
		'icon'    => 'unlock',
		'label'   => __( 'Session Management', 'login-armor' ),
		'aliases' =>
			/* translators: search keywords for the Settings search box, never displayed. Space-separated. Keep the English terms and add the ones an administrator types in your language. */
			__( 'timeout logout idle expiration inactivite deconnexion', 'login-armor' ),
		'desc'    => __( 'Log out idle accounts, cap session lifetime, and limit logins to one device.', 'login-armor' ),
		'state'   => $la_session_enabled ? 'on' : 'off',
		'pill'    => $la_session_enabled ? __( 'Active', 'login-armor' ) : __( 'Disabled', 'login-armor' ),
		'disable_action' => 'session-disable',
	),
	array(
		'id'      => 'geoip',
		'file'    => 'geoip.php',
		'icon'    => 'search',
		'label'   => __( 'IP Geolocation', 'login-armor' ),
		'aliases' =>
			/* translators: search keywords for the Settings search box, never displayed. Space-separated. Keep the English terms and add the ones an administrator types in your language. */
			__( 'country geolocation localisation drapeau pays', 'login-armor' ),
		'desc'    => __( 'Show the country of origin next to IP addresses in incidents and events.', 'login-armor' ),
		'state'   => $la_geoip_enabled ? 'on' : 'off',
		'pill'    => $la_geoip_enabled ? __( 'Active', 'login-armor' ) : __( 'Disabled', 'login-armor' ),
		'disable_action' => 'geoip-disable',
	),
	array(
		'id'      => 'firewall',
		'file'    => 'firewall.php',
		'icon'    => 'circle-slash',
		'label'   => __( 'Request Firewall', 'login-armor' ),
		'aliases' =>
			/* translators: search keywords for the Settings search box, never displayed. Space-separated. Keep the English terms and add the ones an administrator types in your language. */
			__( 'waf parefeu pare-feu 8g requetes', 'login-armor' ),
		'desc'    => $la_fw_enabled
			? ( 'enforce' === $la_fw_effective
				? __( 'Blocking malicious requests before WordPress processes them.', 'login-armor' )
				: __( 'Monitoring malicious requests, not blocking yet. Review, then enforce.', 'login-armor' ) )
			: __( 'Block malicious requests (bad query strings, paths, methods) before WordPress runs.', 'login-armor' ),
		'state'   => $la_fw_enabled ? ( 'enforce' === $la_fw_effective ? 'on' : 'warn' ) : 'off',
		'pill'    => $la_fw_enabled
			? ( 'enforce' === $la_fw_effective ? __( 'Enforcing', 'login-armor' ) : __( 'Monitoring', 'login-armor' ) )
			: __( 'Disabled', 'login-armor' ),
		'disable_action' => 'firewall-disable',
	),
	array(
		'id'      => 'pow',
		'file'    => 'pow.php',
		'icon'    => 'circle-slash',
		'label'   => __( 'Bot Challenge', 'login-armor' ),
		'aliases' =>
			/* translators: search keywords for the Settings search box, never displayed. Space-separated. Keep the English terms and add the ones an administrator types in your language. */
			__( 'proof of work captcha challenge preuve de travail anti-bot', 'login-armor' ),
		'desc'    => $la_pow_enabled
			? ( 'enforce' === $la_pow_effective
				? __( 'Every login must carry an invisible proof-of-work solved by the browser.', 'login-armor' )
				: __( 'Monitoring submissions without a valid proof, not blocking yet. Review, then enforce.', 'login-armor' ) )
			: __( 'Make every login attempt cost CPU time: invisible to humans, expensive for botnets.', 'login-armor' ),
		'state'   => $la_pow_enabled ? ( 'enforce' === $la_pow_effective ? 'on' : 'warn' ) : 'off',
		'pill'    => $la_pow_enabled
			? ( 'enforce' === $la_pow_effective ? __( 'Enforcing', 'login-armor' ) : __( 'Monitoring', 'login-armor' ) )
			: __( 'Disabled', 'login-armor' ),
		'disable_action' => 'pow-disable',
	),
	array(
		'id'      => 'activity-log',
		'file'    => 'activity-settings.php',
		'icon'    => 'pulse',
		'label'   => __( 'Activity Log', 'login-armor' ),
		'aliases' =>
			/* translators: search keywords for the Settings search box, never displayed. Space-separated. Keep the English terms and add the ones an administrator types in your language. */
			__( 'audit trail tracabilite historique', 'login-armor' ),
		'desc'    => __( 'Tracking admin actions across your site.', 'login-armor' ),
		'state'   => $la_activity_on ? 'on' : 'off',
		'pill'    => $la_activity_on ? __( 'Active', 'login-armor' ) : __( 'Disabled', 'login-armor' ),
		'disable_action' => 'activity-disable',
	),
	array(
		'id'      => 'activity-webhook',
		'file'    => 'activity-webhook.php',
		'icon'    => 'pulse',
		'label'   => __( 'Activity Webhook Forwarding', 'login-armor' ),
		'aliases' =>
			/* translators: search keywords for the Settings search box, never displayed. Space-separated. Keep the English terms and add the ones an administrator types in your language. */
			__( 'forward syslog export externe relais siem', 'login-armor' ),
		'desc'    => __( 'Forward each activity event as a signed POST to a SIEM, Slack, or any HTTPS endpoint.', 'login-armor' ),
		'state'   => $la_webhook_enabled ? 'on' : 'off',
		'pill'    => $la_webhook_enabled ? __( 'Active', 'login-armor' ) : __( 'Disabled', 'login-armor' ),
		'disable_action' => '', // Disable handled by toggle inside the section + sticky bar save.
	),
	array(
		'id'      => 'two-factor',
		'file'    => 'two-factor-settings.php',
		'icon'    => 'unlock',
		'label'   => __( 'Two-Factor Authentication', 'login-armor' ),
		// "f2a" is in the list on purpose: it is the transposition the author
		// typed himself, sitting between the English "2FA" and the French "A2F".
		// A box that holds the answer and refuses the near miss is worse than none.
		'aliases' =>
			/* translators: search keywords for the Settings search box, never displayed. Space-separated. Keep the English terms and add the ones an administrator types in your language. */
			__( '2fa a2f f2a mfa otp totp authenticator two-factor two factor double authentification deux facteurs', 'login-armor' ),
		'desc'    => __( 'Require a second code after password. Biggest single lift to your score.', 'login-armor' ),
		'state'   => $la_2fa_on ? 'on' : 'off',
		'pill'    => $la_2fa_on ? __( 'Active', 'login-armor' ) : __( 'Disabled', 'login-armor' ),
		'disable_action' => '2fa-disable',
	),
	array(
		'id'      => 'notifications',
		'file'    => 'notifications.php',
		'icon'    => 'bell',
		'label'   => __( 'Notifications', 'login-armor' ),
		'aliases' =>
			/* translators: search keywords for the Settings search box, never displayed. Space-separated. Keep the English terms and add the ones an administrator types in your language. */
			__( 'email alerte avertissement notifier prevenir', 'login-armor' ),
		'desc'    => __( 'Alerts on incidents, repeated lockouts, new administrators and settings imports.', 'login-armor' ),
		'state'   => $la_notif_on ? 'on' : 'off',
		'pill'    => $la_notif_on ? __( 'Active', 'login-armor' ) : __( 'Disabled', 'login-armor' ),
		'disable_action' => 'notifications-disable',
	),
	array(
		'id'      => 'ai-assistant',
		'file'    => 'ai.php',
		'icon'    => 'shield',
		'label'   => __( 'AI Assistant', 'login-armor' ),
		'aliases' =>
			/* translators: search keywords for the Settings search box, never displayed. Space-separated. Keep the English terms and add the ones an administrator types in your language. */
			__( 'intelligence artificielle llm abilities modele', 'login-armor' ),
		'desc'    => __( 'Optional AI analysis via your WordPress 7 connector: explains incidents and advises on hardening.', 'login-armor' ),
		'state'   => $la_ai_state,
		'pill'    => $la_ai_pill,
		'disable_action' => '',
	),
);

// Group the modules into labelled categories so the long list scans easily.
$la_cat_of = array(
	'hide-login'      => 'access',
	'limit-login'     => 'access',
	'pow'             => 'access',
	'two-factor'      => 'access',
	'detection-logs'  => 'detection',
	'activity-log'    => 'detection',
	'activity-webhook' => 'detection',
	'password-policy' => 'accounts',
	'session'         => 'accounts',
	'breach-check'    => 'accounts',
	'firewall'        => 'perimeter',
	'login-headers'   => 'perimeter',
	'hardening'       => 'perimeter',
	'headless'        => 'perimeter',
	'geoip'           => 'alerts',
	'notifications'   => 'alerts',
	'ai-assistant'    => 'alerts',
);
$la_categories = array(
	'access'    => __( 'Access & login', 'login-armor' ),
	'detection' => __( 'Detection & logs', 'login-armor' ),
	'accounts'  => __( 'Accounts & passwords', 'login-armor' ),
	'perimeter' => __( 'Firewall & hardening', 'login-armor' ),
	'alerts'    => __( 'Alerts & AI', 'login-armor' ),
);
?>

<div class="la-page-grid">
	<div class="la-settings-col">
		<?php
		// About 88 controls live behind three nesting levels of <details> (a
		// category, a module, and Hide Login's recovery panel inside one of
		// them), all closed on load, so the browser's own find bar sees almost
		// nothing. This
		// box filters the module list client-side and opens what it matches.
		// Nothing is stored: a reload gives the untouched list back.
		?>
		<div class="la-settings-search" role="search">
			<label class="screen-reader-text" for="la-settings-search"><?php esc_html_e( 'Search the settings', 'login-armor' ); ?></label>
			<input
				type="search"
				id="la-settings-search"
				class="la-input la-settings-search__input"
				data-la-settings-search
				autocomplete="off"
				spellcheck="false"
				placeholder="<?php esc_attr_e( 'Search a setting: XML-RPC, 2FA, firewall…', 'login-armor' ); ?>"
			/>
			<output class="la-settings-search__count" data-la-settings-search-count aria-live="polite"></output>
		</div>
		<?php
		foreach ( $la_categories as $la_cat_key => $la_cat_label ) :
				$la_cat_items = array_filter(
					$la_sections,
					static function ( $s ) use ( $la_cat_of, $la_cat_key ) {
						return ( $la_cat_of[ $s['id'] ] ?? '' ) === $la_cat_key
							&& file_exists( LOGIN_ARMOR_DIR . 'admin/views/sections/' . $s['file'] );
					}
				);
				if ( empty( $la_cat_items ) ) {
					continue;
				}
				?>
				<?php
					$la_cat_total  = count( $la_cat_items );
					$la_cat_active = count( array_filter( $la_cat_items, static function ( $s ) { return in_array( $s['state'], array( 'on', 'warn' ), true ); } ) );
					?>
					<details class="la-cat">
						<summary class="la-cat__summary">
							<span class="la-cat__title"><?php echo esc_html( $la_cat_label ); ?></span>
							<span class="la-cat__count<?php echo $la_cat_active > 0 ? ' is-active' : ''; ?>"><?php echo esc_html( sprintf( /* translators: 1: active modules in this category, 2: total modules in this category. */ __( '%1$d/%2$d on', 'login-armor' ), (int) $la_cat_active, (int) $la_cat_total ) ); ?></span>
							<span class="la-cat__chevron" aria-hidden="true"></span>
						</summary>
						<div class="la-cat__body">
				<?php
				foreach ( $la_cat_items as $la_s ) :
			$la_path = LOGIN_ARMOR_DIR . 'admin/views/sections/' . $la_s['file'];
			if ( ! file_exists( $la_path ) ) {
				continue;
			}
			$la_open_default = false;
			$la_pill_variant = ( 'on' === $la_s['state'] ) ? 'ok' : ( ( 'warn' === $la_s['state'] ) ? 'warn' : 'neutral' );
			$la_has_disable  = ( 'on' === $la_s['state'] || 'warn' === $la_s['state'] ) && ! empty( $la_s['disable_action'] );
			// 2.8.0: the Disable button used to sit inside the <summary>. A
			// summary is itself the control that opens the module, and a button
			// inside it is not reachable as a control of its own by assistive
			// technology (axe: nested-interactive). The button now follows the
			// <details>, inside .la-setting-item, and the stylesheet draws it
			// over a hidden copy of itself left in the row, so the row keeps the
			// width and the line the button takes in every language.
			?>
			<div class="la-setting-item">
			<details class="la-setting-wrapper la-setting-wrapper--<?php echo esc_attr( $la_s['state'] ); ?>" id="<?php echo esc_attr( $la_s['id'] ); ?>" data-la-search-alias="<?php echo esc_attr( isset( $la_s['aliases'] ) ? $la_s['aliases'] : '' ); ?>"<?php echo $la_open_default ? ' open' : ''; ?>>
				<summary class="la-setting-row">
					<span class="la-setting-row__icon la-setting-row__icon--<?php echo esc_attr( $la_s['state'] ); ?>">
						<?php \LoginArmor\Icons::render( $la_s['icon'], '', 18 ); ?>
					</span>
					<span class="la-setting-row__text">
						<b>
							<?php echo esc_html( $la_s['label'] ); ?>
							<span class="la-pill la-pill--<?php echo esc_attr( $la_pill_variant ); ?>">
								<?php echo esc_html( $la_s['pill'] ); ?>
							</span>
							<?php if ( ! empty( $la_s['count'] ) && (int) $la_s['count'] > 0 ) : ?>
								<span class="la-setting-wrapper__count">
									<?php
									echo esc_html(
										sprintf(
											/* translators: %d: number of flagged accounts from Breach Check, shown as a pill next to the section title. */
											_n( '%d flagged', '%d flagged', (int) $la_s['count'], 'login-armor' ),
											(int) $la_s['count']
										)
									);
									?>
								</span>
							<?php endif; ?>
						</b>
						<small><?php echo esc_html( $la_s['desc'] ); ?></small>
					</span>
					<?php if ( $la_has_disable ) : ?>
						<span class="la-setting-row__disable la-setting-row__disable--slot" aria-hidden="true"><?php esc_html_e( 'Disable', 'login-armor' ); ?></span>
					<?php endif; ?>
					<span class="la-setting-row__chevron" aria-hidden="true"></span>
				</summary>
				<div class="la-setting-wrapper__body">
					<?php include $la_path; ?>
				</div>
			</details>
			<?php if ( $la_has_disable ) : ?>
				<button
					type="button"
					class="la-setting-row__disable"
					data-la-action="<?php echo esc_attr( $la_s['disable_action'] ); ?>"
				><?php esc_html_e( 'Disable', 'login-armor' ); ?></button>
			<?php endif; ?>
			</div>
			<?php
			endforeach;
				?>
						</div>
					</details>
					<?php
				endforeach;
		?>
	</div>

	<aside>
		<?php
		$la_guide_file = LOGIN_ARMOR_DIR . 'admin/views/sidebar/settings.php';
		if ( file_exists( $la_guide_file ) ) {
			echo '<div class="la-guide">';
			include $la_guide_file;
			echo '</div>';
		}
		// Sponsored cards (OGEEAT / Crash-Test) are intentionally NOT shown on the
		// Settings tab: its sidebar already carries the per-module help guides, and
		// the extra promo cards made it too crowded. They still appear on the
		// Incidents, Events and Activity tabs.
		?>
	</aside>
</div>

<div class="la-sticky-bar" data-la-sticky-bar>
	<span class="la-sticky-bar__hint">
		<span class="la-sticky-bar__dot"></span>
		<?php esc_html_e( 'Unsaved changes', 'login-armor' ); ?>
	</span>
	<button type="button" class="la-btn la-btn--ghost" data-la-action="discard"><?php esc_html_e( 'Discard', 'login-armor' ); ?></button>
	<button type="button" class="la-btn la-btn--primary" data-la-action="save-all"><?php esc_html_e( 'Save all changes', 'login-armor' ); ?></button>
</div>
