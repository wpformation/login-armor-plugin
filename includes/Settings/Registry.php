<?php
/**
 * Declarative registry of every exportable Login Armor setting.
 *
 * One entry per WordPress option. Each entry says where the value lives in
 * the JSON file (group + key), how it is stored (scalar, newline-joined
 * string, list, object), how to validate an imported value, how to write it
 * back (raw option or through the owning module), and how sensitive it is.
 *
 * The bounds and allowlists below deliberately mirror the inline validation
 * of the AJAX handlers in admin/class-admin.php; the offline harness asserts
 * the two never drift apart. Runtime state (counters, secrets, chain
 * fingerprints, per-IP claims) is not here on purpose: see NEVER.
 *
 * @package LoginArmor\Settings
 * @since   2.6.0
 */

namespace LoginArmor\Settings;

use LoginArmor\Firewall\Firewall;
use LoginArmor\Hardening;
use LoginArmor\HideLogin;
use LoginArmor\LoginArmor;
use LoginArmor\LoginHeaders;
use LoginArmor\PasswordPolicy;
use LoginArmor\PowChallenge;
use LoginArmor\SessionManager;
use LoginArmor\TwoFactor\Recovery;
use LoginArmor\TwoFactor\TrustedDevices;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Registry {

	/**
	 * Options that must never appear in an export, whatever the flags:
	 * secrets, bookkeeping, integrity fingerprints and dead option names.
	 *
	 * @var string[]
	 */
	public const NEVER = array(
		'login_armor_webhook_secret',
		// 2.7.0: a fact about THIS site's network path, meaningless elsewhere.
		'login_armor_https_terminator_undeclared',
		'login_armor_db_version',
		'login_armor_onboarded',
		'login_armor_activation_acknowledged',
		'login_armor_ai_usage',
		'login_armor_pow_softfails',
		'login_armor_v211_chain_initialized',
		'login_armor_v211_show_chain_init_notice',
		'login_armor_activity_chain_start_id',
		'login_armor_activity_chain_salt_fp',
		'login_armor_webhook_consecutive_failures',
		'login_armor_webhook_last_dead_notice',
		'login_armor_last_notif_error',
		'login_armor_notif_suppressed',
		// 2.7.0 : when THIS site last sent a digest, how many sends in a row
		// have failed, and the send lock. Per-site bookkeeping: exporting the
		// clock would make every site of a fleet believe it had already
		// reported and skip a whole period.
		'login_armor_notif_digest_last',
		'login_armor_notif_digest_failures',
		'login_armor_notif_digest_lock',
		'login_armor_login_headers_preset',
		'login_armor_hardening_options',
		// 2.6.1 : per-site bookkeeping, meaningless on another site.
		'login_armor_provision_lock',
		'login_armor_geoip_prefetch_lock',
		'login_armor_geoip_watermark',
		// 2.7.0 : what went wrong on THIS server, and what was proven to
		// work from it. An .htaccess this site could not write is a fact
		// about its filesystem, and a test alert that arrived is a fact
		// about its outbound network. Neither travels.
		'login_armor_htaccess_last_failure',
		'login_armor_notif_last_test_ok',
		// 2.9.0: when monitoring started on THIS site and how many days each
		// password was used here. Replayed elsewhere, they would end the
		// learning period of passwords that site has never seen.
		'login_armor_app_password_watch_since',
		'login_armor_app_password_days',
	);

	/** JSON groups, in file order. */
	public const GROUPS = array(
		'hide_login',
		'brute_force',
		'detection',
		'notifications',
		'activity_log',
		'activity_webhook',
		'two_factor',
		'login_headers',
		'breach_check',
		'headless',
		'hardening',
		'password_policy',
		'session',
		'firewall',
		'bot_challenge',
		'geoip',
		'ai',
	);

	/** @var array<string,array<string,mixed>>|null */
	private static ?array $entries = null;

	/**
	 * The registry, keyed by option name.
	 *
	 * Entry shape:
	 *  - group       JSON section.
	 *  - key         JSON key inside the section; null = the entry's fields ARE the section.
	 *  - type        Sanitizer: bool|int|enum|enum_int|email|https_url|webhook|text|slug|redirect_type|
	 *                ip_list|cidr_list|string_list|subset|roles|object.
	 *  - args        Sanitizer arguments (bounds or allowlist).
	 *  - store       How the value sits in wp_options: scalar|lines|list|object. `lines` is a
	 *                newline-joined string exported as a JSON list.
	 *  - fields      For type=object: nested field specs (type/args/store).
	 *  - default     Value when the option is unset (Exporter merges defaults).
	 *  - apply       option (raw update_option) or group (through the owning module).
	 *  - autoload    update_option() autoload flag, as the admin handlers set it.
	 *  - sensitivity normal|optin|sensitive.
	 *
	 * @return array<string,array<string,mixed>>
	 */
	public static function entries(): array {
		if ( null !== self::$entries ) {
			return self::$entries;
		}

		$e = array();

		// Hide Login. Applied last, through the group applier.
		$e[ HideLogin::OPTION_ENABLED ]       = self::def( 'hide_login', 'enabled', 'bool', array(), false, 'group' );
		$e[ HideLogin::OPTION_SLUG ]          = self::def( 'hide_login', 'slug', 'slug', array(), '', 'group', true, 'sensitive' );
		$e[ HideLogin::OPTION_REDIRECT_TYPE ] = self::def( 'hide_login', 'redirect_type', 'redirect_type', array(), HideLogin::REDIRECT_NOT_FOUND, 'group' );
		$e[ HideLogin::OPTION_REDIRECT_URL ]  = self::def( 'hide_login', 'redirect_url', 'https_url', array(), '', 'group' );

		// Brute force. Bounds: admin/class-admin.php ajax_save_limit_settings().
		$e['login_armor_limit_enabled']    = self::def( 'brute_force', 'enabled', 'bool', array(), true );
		$e['login_armor_allowed_retries']  = self::def( 'brute_force', 'allowed_retries', 'int', array( 1, 20 ), 4 );
		$e['login_armor_lockout_duration'] = self::def( 'brute_force', 'lockout_duration', 'int', array( 1, 1440 ), 20 );
		$e['login_armor_max_lockouts']     = self::def( 'brute_force', 'max_lockouts', 'int', array( 1, 20 ), 4 );
		$e['login_armor_long_duration']    = self::def( 'brute_force', 'long_duration', 'int', array( 1, 168 ), 24 );
		$e['login_armor_valid_duration']   = self::def( 'brute_force', 'valid_duration', 'int', array( 1, 168 ), 24 );
		$e['login_armor_lockout_window']   = self::def( 'brute_force', 'lockout_window', 'int', array( 1, 168 ), 24 );
		$e['login_armor_whitelist_ips']    = self::def( 'brute_force', 'whitelist_ips', 'ip_list', array(), '', 'option', true, 'sensitive', 'lines' );
		$e['login_armor_blocked_subnets']  = self::def( 'brute_force', 'blocked_subnets', 'cidr_list', array(), array(), 'option', false, 'normal', 'list' );
		$e['login_armor_notify_email']     = self::def( 'brute_force', 'notify_email', 'email', array(), '' );
		// 2.10.0: opt-in syslog lines for fail2ban.
		$e['login_armor_syslog']           = self::def( 'brute_force', 'syslog', 'bool', array(), false );
		$e['login_armor_notify_threshold'] = self::def( 'brute_force', 'notify_threshold', 'int', array( 0, 1000 ), 5 );
		$e['login_armor_ip_method']        = self::def( 'brute_force', 'ip_method', 'enum', array( 'REMOTE_ADDR', 'HTTP_CF_CONNECTING_IP', 'HTTP_X_FORWARDED_FOR', 'HTTP_X_REAL_IP' ), 'REMOTE_ADDR' );
		$e['login_armor_trusted_proxies']  = self::def( 'brute_force', 'trusted_proxies', 'cidr_list', array(), '', 'option', false, 'normal', 'lines' );

		// Detection & logs. Bounds: ajax_save_detection_settings().
		$e['login_armor_detection_enabled']  = self::def( 'detection', 'enabled', 'bool', array(), true );
		$e['login_armor_log_retention_days'] = self::def( 'detection', 'log_retention_days', 'int', array( 1, 3650 ), 90 );
		$e['login_armor_auto_purge']         = self::def( 'detection', 'auto_purge', 'bool', array(), true );
		$e['login_armor_logs_auto_purge']    = self::def( 'detection', 'logs_auto_purge', 'int', array( 1, 3650 ), 90 );

		// Notifications. Bounds: ajax_save_notifications().
		$e['login_armor_notif_channel']      = self::def( 'notifications', 'channel', 'enum', array( 'disabled', 'email', 'slack', 'discord', 'generic' ), 'disabled' );
		$e['login_armor_notif_webhook_url']  = self::def( 'notifications', 'webhook_url', 'text', array( 2048 ), '', 'option', true, 'optin' );
		$e['login_armor_notif_min_severity'] = self::def( 'notifications', 'min_severity', 'int', array( 1, 4 ), 2 );
		$e['login_armor_notif_rate_limit']   = self::def( 'notifications', 'rate_limit', 'int', array( 0, 100 ), 10 );
		// 2.7.0 : scheduled digest. The allowlist repeats
		// \LoginArmor\Notifications\Digest::MODES rather than referencing it:
		// the Digest class is only loaded on the cron tick and by WP-CLI, and
		// naming it here would make the registry depend on a file no
		// autoloader will fetch. tests/notif-digest.php asserts the two lists
		// are identical, so the repetition cannot drift.
		$e['login_armor_notif_digest']       = self::def( 'notifications', 'digest', 'enum', array( 'off', 'weekly', 'monthly' ), 'off' );
		// 2.10.0: the digest's own recipient, whatever the alert channel.
		$e['login_armor_notif_digest_to']    = self::def( 'notifications', 'digest_to', 'email', array(), '' );

		// Activity log. Bounds: ajax_save_activity_settings().
		$e['login_armor_activity_enabled']           = self::def( 'activity_log', 'enabled', 'bool', array(), false, 'group' );
		$e['login_armor_activity_retention']         = self::def( 'activity_log', 'retention', 'int', array( 1, 3650 ), 90 );
		$e['login_armor_activity_auto_verify_daily'] = self::def( 'activity_log', 'auto_verify_daily', 'bool', array(), true );

		// Activity webhook (SIEM). The HMAC secret never travels.
		$e['login_armor_webhook_enabled'] = self::def( 'activity_webhook', 'enabled', 'bool', array(), false );
		$e['login_armor_webhook_url']     = self::def( 'activity_webhook', 'url', 'text', array( 2048 ), '', 'option', true, 'optin' ); // https + SSRF policy enforced by the Importer group check.

		// Two-factor. Bounds: ajax_save_2fa_settings().
		$e['login_armor_2fa_enabled']       = self::def( 'two_factor', 'enabled', 'bool', array(), false );
		$e['login_armor_2fa_methods']       = self::def( 'two_factor', 'methods', 'subset', array( 'totp', 'email', 'backup' ), array( 'totp', 'email', 'backup' ), 'option', true, 'normal', 'list' );
		$e['login_armor_2fa_enforce_roles'] = self::def( 'two_factor', 'enforce_roles', 'roles', array(), array(), 'option', true, 'normal', 'list' );
		$e['login_armor_2fa_grace_days']    = self::def( 'two_factor', 'grace_days', 'enum_int', array( 1, 3, 7, 14 ), 3 );
		$e[ TrustedDevices::OPTION_ENABLED ]       = self::def( 'two_factor', 'trusted_devices_enabled', 'bool', array(), true, 'option', false );
		$e[ TrustedDevices::OPTION_DURATION_DAYS ] = self::def( 'two_factor', 'trusted_devices_duration_days', 'enum_int', TrustedDevices::ALLOWED_DURATIONS, TrustedDevices::DEFAULT_DURATION_DAYS, 'option', false );
		// Default true, like the runtime (Recovery::is_feature_enabled()) and the
		// settings screen. It read false until 2.6.1, so an export taken from an
		// untouched site described an active feature as off, and importing that
		// file elsewhere turned account recovery off without saying so.
		$e[ Recovery::OPTION_ENABLED ]             = self::def( 'two_factor', 'recovery_enabled', 'bool', array(), true, 'option', false );

		// Login page security headers. Bounds: ajax_save_login_headers().
		$e[ LoginHeaders::OPTION_ENABLED ]    = self::def( 'login_headers', 'enabled', 'bool', array(), true );
		$e[ LoginHeaders::OPTION_MODE ]       = self::def( 'login_headers', 'mode', 'enum', LoginHeaders::ALLOWED_MODES, 'standard' );
		$e[ LoginHeaders::OPTION_REPORT_URI ] = self::def( 'login_headers', 'report_uri', 'https_url', array(), '' );
		$e[ LoginHeaders::OPTION_HSTS ]       = self::def( 'login_headers', 'hsts', 'enum', LoginHeaders::ALLOWED_HSTS_MODES, 'off' );
		$e[ LoginHeaders::OPTION_SITEWIDE ]   = self::def( 'login_headers', 'sitewide', 'bool', array(), false );

		// Breach check.
		$e['login_armor_breach_check_enabled']     = self::def( 'breach_check', 'enabled', 'bool', array(), false );
		$e['login_armor_breach_check_passwords']   = self::def( 'breach_check', 'passwords', 'bool', array(), true );
		$e['login_armor_breach_check_emails']      = self::def( 'breach_check', 'emails', 'bool', array(), false );
		$e['login_armor_breach_check_force_reset'] = self::def( 'breach_check', 'force_reset', 'bool', array(), false );

		// Hardening: the toggles object plus its two lists.
		$toggle_fields = array();
		foreach ( Hardening::get_toggles() as $toggle ) {
			$toggle_fields[ (string) $toggle['key'] ] = array( 'type' => 'bool', 'default' => false );
		}
		$e[ Hardening::OPTION_KEY ] = self::def( 'hardening', 'toggles', 'object', array(), array(), 'group', false, 'normal', 'object', $toggle_fields );
		$e[ \LoginArmor\Hardening\UsernameBlacklist::OPTION_KEY ] = self::def( 'hardening', 'username_blacklist', 'string_list', array(), \LoginArmor\Hardening\UsernameBlacklist::DEFAULTS, 'group', false, 'normal', 'list' );
		$e[ Hardening::OPTION_REST_NAMESPACES ] = self::def( 'hardening', 'rest_namespaces', 'string_list', array(), array(), 'group', false, 'normal', 'list' );

		// Password policy. Bounds: PasswordPolicy::save_settings().
		$e[ PasswordPolicy::OPTION_KEY ] = self::def(
			'password_policy',
			null,
			'object',
			array(),
			array(),
			'group',
			false,
			'normal',
			'object',
			array(
				'enabled'           => array( 'type' => 'bool', 'default' => false ),
				'min_length'        => array( 'type' => 'int', 'args' => array( 6, 64 ), 'default' => 12 ),
				'require_lower'     => array( 'type' => 'bool', 'default' => true ),
				'require_upper'     => array( 'type' => 'bool', 'default' => true ),
				'require_number'    => array( 'type' => 'bool', 'default' => true ),
				'require_symbol'    => array( 'type' => 'bool', 'default' => false ),
				'forbid_username'   => array( 'type' => 'bool', 'default' => true ),
				'block_compromised' => array( 'type' => 'bool', 'default' => true ),
				'expiration_days'   => array( 'type' => 'int', 'args' => array( 0, 3650 ), 'default' => 0 ),
			)
		);

		// Session management. Bounds: SessionManager::save_settings().
		$e[ SessionManager::OPTION_KEY ] = self::def(
			'session',
			null,
			'object',
			array(),
			array(),
			'group',
			false,
			'normal',
			'object',
			array(
				'enabled'            => array( 'type' => 'bool', 'default' => false ),
				'idle_timeout_min'   => array( 'type' => 'int', 'args' => array( 0, 1440 ), 'default' => 0 ),
				'max_lifetime_hours' => array( 'type' => 'int', 'args' => array( 0, 8760 ), 'default' => 0 ),
				'single_session'     => array( 'type' => 'bool', 'default' => false ),
			)
		);

		// Request firewall. Allowlists are newline-joined strings in the option.
		//
		// `enabled_at` (2.7.0) is deliberately absent from the field list
		// below, and that absence is the whole mechanism: to_json_value()
		// walks `fields`, so a key that is not declared here is never
		// exported, and sanitize() drops it on import. The stamp dates the
		// monitoring period of ONE site; replayed on sixty others it would
		// claim a week of evidence none of them has, and the "switch to
		// Enforce" advice would fire on day one everywhere.
		$e[ Firewall::OPTION_KEY ] = self::def(
			'firewall',
			null,
			'object',
			array(),
			array(),
			'group',
			false,
			'normal',
			'object',
			array(
				'enabled'                => array( 'type' => 'bool', 'default' => false ),
				'mode'                   => array( 'type' => 'enum', 'args' => array( 'log_only', 'enforce' ), 'default' => 'log_only' ),
				'query_string'           => array( 'type' => 'bool', 'default' => true ),
				'request_uri'            => array( 'type' => 'bool', 'default' => true ),
				'request_method'         => array( 'type' => 'bool', 'default' => true ),
				'user_agent'             => array( 'type' => 'bool', 'default' => false ),
				'referer'                => array( 'type' => 'bool', 'default' => false ),
				'request_uri_aggressive' => array( 'type' => 'bool', 'default' => false ),
				'allow_ips'              => array( 'type' => 'string_list', 'default' => '', 'store' => 'lines' ),
				'allow_paths'            => array( 'type' => 'string_list', 'default' => '', 'store' => 'lines' ),
			)
		);

		// Bot challenge (proof-of-work). Same rule as the firewall above:
		// `enabled_at` (2.7.0) is not declared, therefore never exported and
		// never importable.
		$e[ PowChallenge::OPTION_KEY ] = self::def(
			'bot_challenge',
			null,
			'object',
			array(),
			array(),
			'group',
			false,
			'normal',
			'object',
			array(
				'enabled'    => array( 'type' => 'bool', 'default' => false ),
				'mode'       => array( 'type' => 'enum', 'args' => array( 'log_only', 'enforce' ), 'default' => 'log_only' ),
				'difficulty' => array( 'type' => 'enum', 'args' => array( 'low', 'standard', 'high' ), 'default' => 'standard' ),
			)
		);

		// GeoIP and AI.
		$e['login_armor_geoip_enabled'] = self::def( 'geoip', 'enabled', 'bool', array(), false );
		$e['login_armor_ai_enabled']    = self::def( 'ai', 'enabled', 'bool', array(), false, 'option', false );
		$e['login_armor_ai_deep']       = self::def( 'ai', 'deep', 'bool', array(), false, 'option', false );

		// 2.9.0: headless mode and application-password monitoring. Applied
		// through the group applier, before the hardening group, so that the
		// mode is on before any guarded toggle of the same file is written.
		$e['login_armor_headless']           = self::def( 'headless', 'enabled', 'bool', array(), false, 'group' );
		$e['login_armor_app_password_watch'] = self::def( 'headless', 'watch_app_passwords', 'bool', array(), true, 'group' );

		self::$entries = $e;
		return $e;
	}

	/**
	 * Current value of one option, in its JSON representation (defaults
	 * merged, lists exploded, objects normalized field by field).
	 */
	public static function read( string $option ): mixed {
		$entry = self::entries()[ $option ];

		// An export has exactly one job: to say what this site DOES. So every
		// value is read the way the running plugin reads it, and never raw.
		//
		// The hardening toggles go through their accessor because that is where
		// the string "false" that WP-CLI leaves behind becomes a real boolean.
		// Reading raw here while Hardening::get_settings() normalises would
		// make the export disagree with the site about Force HTTPS, and an
		// import of that file would arm a toggle the administrator had
		// switched off.
		$stored = Hardening::OPTION_KEY === $option
			? Hardening::get_settings()
			: get_option( $option, $entry['default'] );

		// Same rule, one level down: a standalone boolean whose module owns an
		// accessor is read THROUGH it. The accessor is the run-time truth, and
		// it carries both halves that a raw read gets wrong: the rule (Hide
		// Login compares to the integer 1, so the string "false" reads as OFF
		// while PHP truthiness reads it as ON) and the default (the AI client
		// defaults to true where this registry declares false, so an untouched
		// site runs it while a raw read would export it as off).
		//
		// Curated deliberately, one line at a time, and NOT applied to every
		// is_enabled() in the plugin: WebhookDispatcher::is_enabled() also
		// requires a non-empty URL, so routing through it would export the
		// toggle as off on a site that has it on and simply has not filled the
		// URL in yet. That is the same class of lie, pointed the other way.
		if ( 'bool' === ( $entry['type'] ?? '' ) ) {
			$reader = self::bool_readers()[ $option ] ?? null;
			if ( null !== $reader && is_callable( $reader ) ) {
				return (bool) call_user_func( $reader );
			}
		}

		return self::to_json_value( $entry, $stored );
	}

	/**
	 * Standalone boolean options that must be read through their module.
	 *
	 * Every entry here is a PURE reader of the one option it is mapped to: it
	 * answers "is this setting on", and nothing else. An accessor that folds in
	 * a second condition does not belong here, whatever its name suggests.
	 *
	 * tests/force-https.php holds the guard that keeps this list honest: it
	 * walks every boolean entry of the registry and fails when the exported
	 * value and the run-time value disagree, so a module that grows an accessor
	 * without being added here is caught rather than discovered in the field.
	 *
	 * Public so the guard can walk it instead of keeping a second copy that
	 * would drift away from this one.
	 *
	 * @return array<string,callable-string|array{0:string,1:string}>
	 */
	public static function bool_readers(): array {
		return array(
			HideLogin::OPTION_ENABLED          => array( HideLogin::class, 'is_enabled' ),
			LoginHeaders::OPTION_ENABLED       => array( LoginHeaders::class, 'is_enabled' ),
			'login_armor_activity_enabled'     => array( '\LoginArmor\ActivityLog\ActivityLog', 'is_enabled' ),
			'login_armor_2fa_enabled'          => array( '\LoginArmor\TwoFactor\TwoFactor', 'is_enabled' ),
			'login_armor_breach_check_enabled' => array( '\LoginArmor\BreachCheck', 'is_enabled' ),
			'login_armor_geoip_enabled'        => array( '\LoginArmor\GeoIP', 'is_enabled' ),
			'login_armor_ai_enabled'           => array( '\LoginArmor\AI\Client', 'is_enabled' ),
			'login_armor_headless'             => array( '\LoginArmor\Headless', 'is_enabled' ),
			'login_armor_app_password_watch'   => array( '\LoginArmor\AppPasswords\Usage', 'is_watching' ),
		);
	}

	/**
	 * Convert a stored value to its JSON form.
	 *
	 * @param array<string,mixed> $entry Registry entry (or nested field spec with type/store).
	 */
	public static function to_json_value( array $entry, mixed $stored ): mixed {
		$store = $entry['store'] ?? 'scalar';
		$type  = $entry['type'] ?? 'text';

		if ( 'object' === $type ) {
			$stored = is_array( $stored ) ? $stored : array();
			$out    = array();
			foreach ( $entry['fields'] as $field => $spec ) {
				$out[ $field ] = self::to_json_value( $spec, array_key_exists( $field, $stored ) ? $stored[ $field ] : ( $spec['default'] ?? null ) );
			}
			return $out;
		}
		if ( 'lines' === $store ) {
			$lines = preg_split( '/\r\n|\r|\n/', (string) $stored );
			$out   = array();
			foreach ( is_array( $lines ) ? $lines : array() as $line ) {
				$line = trim( $line );
				if ( '' !== $line ) {
					$out[] = $line;
				}
			}
			return $out;
		}
		if ( 'list' === $store ) {
			return is_array( $stored ) ? array_values( array_map( 'strval', $stored ) ) : array();
		}
		return match ( $type ) {
			// PHP truthiness, deliberately, and NOT LoginArmor::to_bool().
			//
			// The two rules disagree on exactly one stored value, the string
			// "false", which is what `wp option update <opt> false` leaves
			// behind. Normalising it belongs to whoever READS the setting at
			// run time, and one accessor does it: Hardening::get_settings(),
			// which is why read() routes the toggles through it.
			//
			// The nineteen standalone booleans have no such accessor. Their
			// run-time readers are plain get_option() calls, so on a site
			// holding "false" the module is RUNNING. Applying to_bool() here
			// made the export say `false` about a module that was up, and
			// importing that file on the next site switched Hide Login, brute
			// force or two-factor off without anyone asking. An export that
			// contradicts the site is worse than one that repeats a stored
			// value nobody normalised: the first silently disarms a fleet,
			// the second is merely faithful. Honouring `false` for those
			// options is a separate change, and it belongs with a migration
			// and a line in the changelog, not inside the exporter.
			//
			// 2.10.0: that change is made. Support\Booleans normalises these
			// options on write and on read, and the upgrade rewrote every
			// stored string as what the site was doing. get_option() hands this
			// method a value that is already 1 or 0, so (bool) is exact.
			'bool'             => (bool) $stored,
			'int', 'enum_int'  => (int) $stored,
			default            => (string) $stored,
		};
	}

	/**
	 * Convert a sanitized JSON value back to the stored form.
	 *
	 * @param array<string,mixed> $entry Registry entry or nested field spec.
	 */
	public static function to_stored_value( array $entry, mixed $value ): mixed {
		$store = $entry['store'] ?? 'scalar';
		if ( 'lines' === $store ) {
			return implode( "\n", is_array( $value ) ? $value : array() );
		}
		if ( 'object' === $store && is_array( $value ) ) {
			$out = array();
			foreach ( $value as $field => $field_value ) {
				$spec          = $entry['fields'][ $field ] ?? array();
				$out[ $field ] = self::to_stored_value( $spec, $field_value );
			}
			return $out;
		}
		return $value;
	}

	/**
	 * Validate one imported JSON value against its entry. Objects are
	 * validated field by field; only the fields present are returned, so an
	 * absent field means "leave untouched".
	 *
	 * @param array<string,mixed> $entry Registry entry or nested field spec.
	 * @return mixed|\WP_Error Normalized value.
	 */
	public static function sanitize( array $entry, mixed $value ): mixed {
		$type = $entry['type'] ?? 'text';
		$args = $entry['args'] ?? array();

		switch ( $type ) {
			case 'bool':
				return Sanitizers::bool( $value );
			case 'int':
				return Sanitizers::int_range( $value, (int) $args[0], (int) $args[1] );
			case 'enum':
				return Sanitizers::enum( $value, $args );
			case 'enum_int':
				return Sanitizers::enum_int( $value, $args );
			case 'email':
				return Sanitizers::email( $value );
			case 'https_url':
				return Sanitizers::https_url( $value, true );
			case 'webhook':
				return Sanitizers::webhook_url( $value );
			case 'text':
				return Sanitizers::text( $value, isset( $args[0] ) ? (int) $args[0] : 255 );
			case 'ip_list':
				return Sanitizers::ip_list( $value );
			case 'cidr_list':
				return Sanitizers::cidr_list( $value );
			case 'string_list':
				return Sanitizers::string_list( $value );
			case 'subset':
				return Sanitizers::subset( $value, $args );
			case 'roles':
				return Sanitizers::subset( $value, array_keys( (array) wp_roles()->role_names ) );
			case 'slug':
				if ( ! is_string( $value ) ) {
					return new \WP_Error( 'login_armor_settings_invalid', __( 'expected a slug', 'login-armor' ) );
				}
				$slug = sanitize_title( $value );
				if ( '' === $slug ) {
					return '';
				}
				$valid = HideLogin::validate_slug( $slug );
				return is_wp_error( $valid ) ? $valid : $slug;
			case 'redirect_type':
				if ( ! is_string( $value ) ) {
					return new \WP_Error( 'login_armor_settings_invalid', __( 'expected a redirect type', 'login-armor' ) );
				}
				return HideLogin::normalize_redirect_type( $value );
			case 'object':
				if ( ! is_array( $value ) ) {
					return new \WP_Error( 'login_armor_settings_invalid', __( 'expected an object', 'login-armor' ) );
				}
				$out = array();
				foreach ( $value as $field => $field_value ) {
					if ( ! isset( $entry['fields'][ $field ] ) ) {
						continue; // Unknown fields are reported by the Importer, not applied.
					}
					$clean = self::sanitize( $entry['fields'][ $field ], $field_value );
					if ( is_wp_error( $clean ) ) {
						$clean->add( 'field', (string) $field );
						return $clean;
					}
					$out[ $field ] = $clean;
				}
				return $out;
		}
		return new \WP_Error( 'login_armor_settings_invalid', __( 'unknown setting type', 'login-armor' ) );
	}

	/**
	 * Option name for a JSON (group, key) pair; null when unknown.
	 */
	public static function option_for( string $group, ?string $key ): ?string {
		foreach ( self::entries() as $option => $entry ) {
			if ( $entry['group'] === $group && $entry['key'] === $key ) {
				return $option;
			}
		}
		return null;
	}

	/**
	 * @param string[]|int[]        $args
	 * @param array<string,mixed>   $fields
	 * @return array<string,mixed>
	 */
	private static function def(
		string $group,
		?string $key,
		string $type,
		array $args,
		mixed $default,
		string $apply = 'option',
		bool $autoload = true,
		string $sensitivity = 'normal',
		string $store = 'scalar',
		array $fields = array()
	): array {
		return array(
			'group'       => $group,
			'key'         => $key,
			'type'        => $type,
			'args'        => $args,
			'default'     => $default,
			'apply'       => $apply,
			'autoload'    => $autoload,
			'sensitivity' => $sensitivity,
			'store'       => $store,
			'fields'      => $fields,
		);
	}
}
