<?php
/**
 * Main LoginArmor class.
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
 * Core plugin class.
 *
 * Handles initialization, module loading, database setup, and shared utilities.
 */
class LoginArmor {

	/** Stable sentinel returned when no safe per-client identity can be derived. */
	public const UNKNOWN_CLIENT_IP = '0.0.0.0';

	/**
	 * Every cron hook the plugin can schedule, on any site.
	 *
	 * The first five are scheduled by schedule_site_crons() on provisioning;
	 * the next three are scheduled lazily by the modules that own them
	 * (ActivityLog::enable(), TrustedDevices::register(), and the single
	 * events LimitLogin queues to expire a rate key). The digest tick (2.7.0)
	 * is scheduled by schedule_site_crons() too, permanently and whatever the
	 * digest setting says: a tick that costs one option read when the feature
	 * is off is cheaper than a feature that has to schedule an event on the
	 * request that switches it on. The GeoIP
	 * prefetch, is conditional: schedule_site_crons() only schedules it while
	 * login_armor_geoip_enabled is on, and takes it out again when it is off
	 * (see GeoIP::sync_prefetch_schedule()). Clearing is the same gesture for
	 * all of them, so one list serves deactivate(), clear_site_crons() and
	 * uninstall.
	 *
	 * uninstall.php runs with the plugin unloaded and cannot read this
	 * constant, so it repeats the list literally. The two lists are asserted
	 * identical by tests/multisite-cycle.php: add a hook here, add it there.
	 *
	 * @since 2.6.1
	 * @var string[]
	 */
	public const CRON_HOOKS = [
		'login_armor_purge_logs',
		'login_armor_security_counters_purge',
		'login_armor_chain_repair',
		'login_armor_chain_auto_verify',
		'login_armor_webhook_dispatch',
		'login_armor_activity_purge',
		'login_armor_2fa_trusted_devices_cleanup',
		'login_armor_cleanup_rate_key',
		'login_armor_geoip_prefetch',
		'login_armor_notif_digest',
		// 2.9.0: single event, scheduled by a new usage row (AppPasswords\Usage).
		// Listed here only so deactivation and uninstall clear it: it is never
		// scheduled by schedule_site_crons() as a recurring event.
		'login_armor_app_password_review',
	];

	/**
	 * How many sites a single get_sites() page walks. Core caps `number` at 100.
	 *
	 * Public because uninstall.php has to page identically without being able to
	 * load this class; tests/multisite-cycle.php asserts the literal it uses
	 * matches this value.
	 */
	public const SITE_PAGE_SIZE = 100;

	/**
	 * Option holding the per-site provisioning lock.
	 *
	 * Not a transient: a transient is an option too, but it is read through a
	 * cache that would hide a concurrent writer, and the whole point here is to
	 * let exactly one of two simultaneous requests through.
	 */
	public const PROVISION_LOCK_OPTION = 'login_armor_provision_lock';

	/** Transient gating the once-a-day admin-side cron self-check. */
	public const CRONS_CHECKED_TRANSIENT = 'login_armor_crons_checked';

	/**
	 * Transient that spaces schema repairs to one an hour (2.8.0).
	 *
	 * The same name Incident::TRANSIENT_SCHEMA_REPAIR has used since 2.7.2,
	 * so a site upgraded with a repair pending keeps its gate.
	 */
	public const TRANSIENT_SCHEMA_REPAIR = 'login_armor_schema_repair';

	/** Seconds after which a provisioning lock is considered abandoned. */
	private const PROVISION_LOCK_TTL = 60;

	/** @var self|null Singleton instance. */
	private static ?self $instance = null;

	/** @var string|null Request-scoped client identity cache. */
	private static ?string $client_ip_cache = null;

	/** @var callable|null Injected clock. Tests only; null means microtime(). */
	private static $clock = null;

	/** @var bool|null Forced safe-mode answer. Tests only; null reads the snapshot. */
	private static ?bool $safe_mode_override = null;

	/** @var bool|null Safe mode as read once at plugin-file load. Null until then. */
	private static ?bool $safe_mode = null;

	/**
	 * Get singleton instance.
	 */
	public static function get_instance(): self {
		if ( self::$instance === null ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	/**
	 * Constructor. Loads modules and hooks.
	 *
	 * Note: textdomain is loaded automatically by WordPress since 4.6
	 * when the plugin is hosted on wordpress.org.
	 */
	private function __construct() {
		// Run any pending DB-version upgrade BEFORE module bootstrap. We're
		// already inside the plugins_loaded callback, so adding a plugins_loaded
		// hook would be too late (priority 10 > 1, and the dispatch is in
		// progress). Calling directly here guarantees the migration completes
		// before any module's hooks see stale state.
		//
		// 2.10.0: the boolean options are normalised on write and on read
		// before anything reads or writes them, the upgrade included.
		require_once LOGIN_ARMOR_DIR . 'includes/Support/Booleans.php';
		Support\Booleans::register();
		self::maybe_run_db_upgrade();

		$this->load_modules();
		$this->register_hooks();
	}

	/**
	 * Load all plugin modules.
	 */
	private function load_modules(): void {
		require_once LOGIN_ARMOR_DIR . 'includes/Support/Csv.php';
		require_once LOGIN_ARMOR_DIR . 'includes/Support/SafeUrl.php';
		require_once LOGIN_ARMOR_DIR . 'includes/Support/Syslog.php';
		require_once LOGIN_ARMOR_DIR . 'includes/class-icons.php';
		require_once LOGIN_ARMOR_DIR . 'includes/class-security-score.php';
		require_once LOGIN_ARMOR_DIR . 'includes/class-hide-login.php';
		require_once LOGIN_ARMOR_DIR . 'includes/class-limit-login.php';
		require_once LOGIN_ARMOR_DIR . 'includes/class-login-logs.php';
		require_once LOGIN_ARMOR_DIR . 'includes/class-overview.php';

		// AI facade (WP7 native AI Client). Static class, no side effects on
		// require; the interpretive layer stays invisible when no native connector
		// exists. The analyzers (IncidentExplainer / PostureAdvisor) are loaded on
		// demand inside the admin AJAX handlers: never on the front-end path.
		require_once LOGIN_ARMOR_DIR . 'includes/AI/Client.php';

		require_once LOGIN_ARMOR_DIR . 'includes/Detection/Incident.php';
		require_once LOGIN_ARMOR_DIR . 'includes/Detection/Classifier.php';
		require_once LOGIN_ARMOR_DIR . 'includes/Hardening/UsernameBlacklist.php';
		require_once LOGIN_ARMOR_DIR . 'includes/Hardening/Honeypot.php';
		require_once LOGIN_ARMOR_DIR . 'includes/class-hardening.php';
		// 2.9.0: headless mode. Must precede the construction of Hardening,
		// which reads the settings and hooks its filters; its write filter is
		// registered on every request.
		require_once LOGIN_ARMOR_DIR . 'includes/class-headless.php';
		Headless::register();
		// 2.9.0: the registry, the settings section and the monitoring AJAX
		// reference Usage; its per-request hook is registered just below.
		require_once LOGIN_ARMOR_DIR . 'includes/AppPasswords/Network.php';
		require_once LOGIN_ARMOR_DIR . 'includes/AppPasswords/Usage.php';
		AppPasswords\Usage::register();
		require_once LOGIN_ARMOR_DIR . 'includes/AppPasswords/Review.php';
		AppPasswords\Review::register();
		require_once LOGIN_ARMOR_DIR . 'includes/class-login-headers.php';
		require_once LOGIN_ARMOR_DIR . 'includes/Firewall/RuleSet.php';
		require_once LOGIN_ARMOR_DIR . 'includes/Firewall/Firewall.php';
		require_once LOGIN_ARMOR_DIR . 'includes/Lockout/LockoutPage.php';

		new HideLogin();
		new LimitLogin();
		new \LoginArmor\Lockout\LockoutPage();
		new LoginLogs();
		new Hardening();
		new LoginHeaders();
		// Request Firewall (8G-inspired PHP filter). Always instantiated; the
		// constructor registers the inspection hook only when enabled, so the
		// zero-overhead contract holds for sites that leave it off (default).
		new \LoginArmor\Firewall\Firewall();
		new \LoginArmor\Detection\Classifier();

		// Lot 21: Breach Check (HIBP + XposedOrNot). Class file is always
		// required so AJAX enable handler can instantiate it on activation.
		// The constructor early-returns when the module is disabled, so
		// the zero-overhead contract holds for admins who leave it off.
		require_once LOGIN_ARMOR_DIR . 'includes/class-breach-check.php';
		new BreachCheck();

		// Password Policy: class file always required so the AJAX settings
		// handler can statically reference it on a fresh install. Constructor
		// early-returns when the module is off; zero-overhead contract holds.
		// Loaded after BreachCheck so the compromised-password rule can reuse
		// BreachCheck::check_password().
		require_once LOGIN_ARMOR_DIR . 'includes/class-password-policy.php';
		new PasswordPolicy();

		// Session Manager: idle timeout, max session lifetime, single-session
		// enforcement. Class file always required so the AJAX settings handler
		// can statically reference it; constructor early-returns when off.
		require_once LOGIN_ARMOR_DIR . 'includes/class-session-manager.php';
		new SessionManager();

		// GeoIP: optional country-level geolocation of displayed IPs.
		// Static utility class (no constructor side effects); lookups are
		// gated by the enable option and performed lazily on admin render.
		require_once LOGIN_ARMOR_DIR . 'includes/class-geoip.php';

		// Bot Challenge (Proof-of-Work): class file always required so the
		// AJAX settings handler can statically reference it on a fresh
		// install. Constructor early-returns when off; zero-overhead contract.
		require_once LOGIN_ARMOR_DIR . 'includes/class-pow-challenge.php';
		new PowChallenge();

		if ( is_admin() ) {
			require_once LOGIN_ARMOR_DIR . 'includes/Setup/SafeBaseline.php';
			self::require_settings_transfer();
			require_once LOGIN_ARMOR_DIR . 'admin/class-admin.php';
			new Admin();

			// Tools > Site Health. Admin-only by construction: the two core
			// filters it answers are never fired on the front end, and a
			// visitor must not pay for a diagnostic screen. Both callbacks
			// are static, so nothing depends on an instance surviving.
			require_once LOGIN_ARMOR_DIR . 'includes/Support/PluginDetection.php';
			require_once LOGIN_ARMOR_DIR . 'includes/class-site-health.php';
			SiteHealth::init();
		}

		// WP-CLI commands: loaded only in CLI context.
		if ( defined( 'WP_CLI' ) && \WP_CLI ) {
			self::require_settings_transfer();
			require_once LOGIN_ARMOR_DIR . 'includes/CLI/Commands.php';
			\WP_CLI::add_command( 'login-armor', CLI\Commands::class );
		}

		// Notifications dispatcher: loaded only if a channel is configured.
		if ( get_option( 'login_armor_notif_channel', 'disabled' ) !== 'disabled' ) {
			require_once LOGIN_ARMOR_DIR . 'includes/Notifications/ChannelInterface.php';
			require_once LOGIN_ARMOR_DIR . 'includes/Notifications/Dispatcher.php';
			new Notifications\Dispatcher();
		}

		// Activity Log: class file always required so the chain initializer
		// hooked at init priority 5 (and the AJAX enable handler) can statically
		// reference ActivityLog constants/methods even when the module is off.
		// Constructor only fires when the module is on: zero-overhead contract
		// preserved (the file just declares the class).
		require_once LOGIN_ARMOR_DIR . 'includes/ActivityLog/ActivityLog.php';
		if ( get_option( 'login_armor_activity_enabled', false ) ) {
			new \LoginArmor\ActivityLog\ActivityLog();
		}

		// Two-Factor Authentication: class files always required so any future
		// hook callback that statically references \LoginArmor\TwoFactor\* survives
		// fresh installs (option not yet set). Constructor + register() are still
		// gated by the enable option: zero-overhead contract preserved (the files
		// just declare classes). Same pattern as Activity Log (V2.1.4) and
		// BreachCheck (Lot 21). V2.1.5 preventive remediation.
		require_once LOGIN_ARMOR_DIR . 'includes/TwoFactor/TwoFactor.php';
		require_once LOGIN_ARMOR_DIR . 'includes/TwoFactor/TOTP.php';
		require_once LOGIN_ARMOR_DIR . 'includes/TwoFactor/EmailOTP.php';
		require_once LOGIN_ARMOR_DIR . 'includes/TwoFactor/BackupCodes.php';
		require_once LOGIN_ARMOR_DIR . 'includes/TwoFactor/TrustedDevices.php';
		require_once LOGIN_ARMOR_DIR . 'includes/TwoFactor/Recovery.php';

		// In multisite every site challenges the enrolled accounts, whatever
		// its own switch (TwoFactor::guards_login()).
		if ( \LoginArmor\TwoFactor\TwoFactor::guards_login() ) {
			new \LoginArmor\TwoFactor\TwoFactor();
			\LoginArmor\TwoFactor\TrustedDevices::register();
		}
	}

	/**
	 * Register global hooks.
	 */
	private function register_hooks(): void {
		// Load the bundled .mo so local and non-wp.org installs get translations.
		// On wp.org-hosted installs with an approved GlotPress language pack,
		// WordPress still serves the language pack first and falls back to this.
		add_action( 'init', [ $this, 'load_textdomain' ] );

		// Create tables when a new site is added to a multisite network.
		add_action( 'wp_initialize_site', [ $this, 'on_new_site' ], 900 );

		// Schedule log purge cron.
		add_action( 'login_armor_purge_logs', [ self::class, 'purge_old_data' ] );
		add_action( 'login_armor_security_counters_purge', [ self::class, 'purge_security_counters' ] );
		add_action( 'login_armor_notif_digest', [ self::class, 'run_notif_digest' ] );

		// 2.7.0 - the e-mail channel with an empty recipient field follows
		// admin_email, so moving that address moves where the alerts go, from
		// a screen and a WP-CLI command that know nothing about this plugin.
		// Registered unconditionally and on purpose: the callback decides for
		// itself, and a fleet changes that address from the command line.
		add_action( 'update_option_admin_email', [ self::class, 'forget_notification_test_on_admin_email' ], 10, 3 );

		// 2.8.0: the Activity Log events follow their options, whatever writes
		// them (settings screen, import, WP-CLI, a restored backup that runs
		// through update_option()). See sync_activity_crons().
		foreach ( array( 'login_armor_activity_enabled', 'login_armor_webhook_enabled', 'login_armor_webhook_url' ) as $login_armor_option ) {
			add_action( 'add_option_' . $login_armor_option, [ self::class, 'sync_activity_crons' ] );
			add_action( 'update_option_' . $login_armor_option, [ self::class, 'sync_activity_crons' ] );
			add_action( 'delete_option_' . $login_armor_option, [ self::class, 'sync_activity_crons' ] );
		}
		// The table too: switched on outside the settings screen (WP-CLI, a
		// restored backup), the module had no table, and every request then
		// failed on it, starting with the chain initialisation.
		add_action( 'add_option_login_armor_activity_enabled', [ self::class, 'ensure_activity_table' ] );
		add_action( 'update_option_login_armor_activity_enabled', [ self::class, 'ensure_activity_table' ] );

		// 2.6.1 - GeoIP background resolver. Registered unconditionally: the
		// callback checks the enable option itself and takes its own event out
		// when the module is off, which is the only way a leftover event on a
		// site nobody visits can ever disappear.
		add_action( GeoIP::CRON_HOOK, [ GeoIP::class, 'run_prefetch' ] );

		// 2.6.1 - cron self-heal. A site can lose a scheduled event without
		// anything being wrong with this plugin: core rewrites the whole `cron`
		// option on every wp_schedule_event(), a migration or a restored backup
		// can drop it, and some hosts reset it. Both halves are cheap (one
		// guarded read per event) and both take the provisioning lock.
		// The daily event repairs the other four; the admin visit repairs the
		// daily event itself, which nothing else could put back.
		add_action( 'login_armor_security_counters_purge', [ self::class, 'on_daily_self_heal' ], 20 );
		add_action( 'admin_init', [ self::class, 'maybe_self_heal_site_crons' ] );

		// V2.1.1: register custom cron intervals (B6 chain repair + B8 webhook).
		// Static callback so the same filter handler is reachable from the
		// activation context (register_activation_hook fires before this
		// singleton's hooks would be wired in CLI activation flows).
		add_filter( 'cron_schedules', [ self::class, 'register_cron_intervals' ] );

		// Plugin action links.
		add_filter( 'plugin_action_links_' . LOGIN_ARMOR_BASENAME, [ $this, 'add_action_links' ] );

		// V2.1.1: initialize ActivityLog HMAC chain on first init post-upgrade.
		// Priority 5 runs BEFORE the 7 loggers register on default priority 10,
		// so the synthetic 'chain_initialized' row is row #1 of the chain.
		add_action( 'init', [ $this, 'maybe_initialize_activity_chain' ], 5 );

		// 2.7.0 - leave one trace a day while the site runs in safe mode.
		// Priority 20 runs AFTER the activity chain is initialised at 5 and
		// after the loggers register at 10, so the row lands in a signed chain
		// rather than ahead of it.
		add_action( 'init', [ $this, 'observe_safe_mode' ], 20 );
	}

	/**
	 * Register custom cron intervals for V2.1.1+ features.
	 *
	 * - login_armor_5min: chain repair (B6)
	 * - login_armor_1min: webhook dispatch when "connected" (B8)
	 * - login_armor_1hour: webhook dispatch when "disconnected" (B8)
	 *
	 * Idempotent: safe to call repeatedly. WP merges into the global schedule.
	 *
	 * 2.6.1 - the three `display` labels are only translated once `init` has
	 * fired. This is not caution, it is the contract of the hook: core calls
	 * wp_get_schedules(), and therefore this callback, from inside
	 * wp_schedule_event(), whenever a caller happens to schedule an event. One
	 * of those callers is this plugin's own DB-version upgrade, which runs in
	 * the `plugins_loaded` constructor by design (see __construct()), long
	 * before `init`. Translating there is exactly what WordPress 6.7 added
	 * _doing_it_wrong() for: "Translation loading for the login-armor domain
	 * was triggered too early". Nothing is lost by waiting, because `display`
	 * is only ever read to render a list of recurrences (Tools > Cron in WP
	 * Crontrol, wp cron schedule list), and every one of those runs after
	 * `init`; wp_schedule_event() itself reads `interval` and nothing else.
	 * Proven by tests/textdomain-timing.php.
	 *
	 * @param array<string,array{interval:int,display:string}> $schedules Existing schedules.
	 * @return array<string,array{interval:int,display:string}>
	 */
	public static function register_cron_intervals( $schedules = array() ) {
		// Untyped defensively: `cron_schedules` is filtered by many plugins;
		// unexpected values pass through untouched.
		if ( ! is_array( $schedules ) ) {
			return $schedules;
		}

		// did_action() is already 1 inside an `init` callback: core increments
		// the counter before it runs them.
		$translatable = did_action( 'init' ) > 0;

		if ( ! isset( $schedules['login_armor_5min'] ) ) {
			$schedules['login_armor_5min'] = [
				'interval' => 300,
				'display'  => $translatable ? __( 'LoginArmor every 5 minutes', 'login-armor' ) : 'LoginArmor every 5 minutes',
			];
		}
		if ( ! isset( $schedules['login_armor_1min'] ) ) {
			$schedules['login_armor_1min'] = [
				'interval' => 60,
				'display'  => $translatable ? __( 'LoginArmor every minute', 'login-armor' ) : 'LoginArmor every minute',
			];
		}
		if ( ! isset( $schedules['login_armor_1hour'] ) ) {
			$schedules['login_armor_1hour'] = [
				'interval' => 3600,
				'display'  => $translatable ? __( 'LoginArmor hourly', 'login-armor' ) : 'LoginArmor hourly',
			];
		}
		return $schedules;
	}

	/**
	 * Run any one-shot DB-version migrations.
	 *
	 * Idempotent: gated by the `login_armor_db_version` option. The first
	 * run after upgrading from V2.0.x stamps `login_armor_db_version` with
	 * LOGIN_ARMOR_VERSION; subsequent calls are no-ops.
	 *
	 * @since 2.1.0
	 */
	public static function maybe_run_db_upgrade( ?string $target = null ): void {
		$target = $target ?? LOGIN_ARMOR_VERSION;

		$stored = (string) get_option( 'login_armor_db_version', '' );
		if ( version_compare( $stored, $target, '>=' ) ) {
			return;
		}

		// One writer per site. Two first requests arriving together on a site
		// that has nothing would otherwise both provision it, and core's
		// wp_schedule_event() rewrites the whole `cron` option from the array
		// each of them read before the other wrote: the loser silently erases
		// events the winner had just scheduled. Nothing here is urgent enough to
		// wait for the lock, so a losing request simply does nothing and the
		// next one finds the work already done.
		if ( ! self::acquire_provision_lock() ) {
			return;
		}

		try {
			self::refresh_option_cache();
			self::run_db_upgrade( $stored, $target );
		} finally {
			self::release_provision_lock();
		}
	}

	/**
	 * The migration ladder itself, already serialized by the caller's lock.
	 *
	 * @param string $stored Version recorded on this site, '' when there is none.
	 * @param string $target Version to reach.
	 */
	private static function run_db_upgrade( string $stored, string $target ): void {
		// Lazy provisioning (2.6.1). No recorded version AND none of the options
		// an installed site always carries: this site was never installed. A
		// subsite the network activation's time budget did not reach, or a site
		// created while the plugin was inactive. Install it outright rather than
		// run a migration ladder against tables that do not exist.
		//
		// The legacy-option test matters: a pre-2.1.0 site also has no recorded
		// version, but it does have data and does need the ladder (the 2.1.1
		// step ALTERs an existing activity table). Treating it as fresh would
		// skip that ALTER and leave its Activity Log broken.
		if ( '' === $stored && false === get_option( 'login_armor_limit_enabled' ) ) {
			if ( ! self::is_plugin_active_here() ) {
				return;
			}
			self::provision_site();
			update_option( 'login_armor_db_version', $target, false );

			return;
		}

		global $wpdb;

		// V2.1.0: drop the V2.0.x 2FA pending transients. Their key was
		// 'login_armor_2fa_token_<clear>'; the V2.1.0 prefix is
		// 'login_armor_2fa_pending_<sha256>' so old rows are unreachable.
		// Pure hygiene: they would naturally expire within 10 min anyway.
		if ( version_compare( $stored, '2.1.0', '<' ) ) {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- One-shot upgrade purge over plugin-owned options.
			$wpdb->query(
				"DELETE FROM {$wpdb->options} WHERE option_name LIKE '\\_transient\\_login\\_armor\\_2fa\\_token\\_%' OR option_name LIKE '\\_transient\\_timeout\\_login\\_armor\\_2fa\\_token\\_%'"
			);
		}

		// V2.1.1: ALTER existing wp_login_armor_activity to add prev_hash + row_hash
		// columns + the new wp_login_armor_webhook_queue table. ActivityLog::create_table()
		// is dbDelta-idempotent so it's safe to re-run on installs that ALREADY have
		// the V2.1.1 schema (e.g. post-`wp plugin install --force` reactivation).
		// The corresponding webhook_queue table is created by self::create_tables()
		// on the activation hook, but only if the plugin is *re-activated*: `wp plugin
		// install --force` does NOT re-fire activation. Mirror it here so existing
		// admin sessions on managed hosts get the V2.1.1 schema without needing a
		// manual deactivate/activate cycle.
		if ( version_compare( $stored, '2.1.1', '<' ) ) {
			require_once LOGIN_ARMOR_DIR . 'includes/ActivityLog/ActivityLog.php';
			\LoginArmor\ActivityLog\ActivityLog::create_table();
			self::create_tables();
		}

		// V2.1.17: add the `vector` column to login_armor_incidents (attack entry
		// point: login_form / xmlrpc / rest). create_tables() is dbDelta-idempotent
		// so re-running it just issues the ALTER ADD COLUMN on existing installs.
		if ( version_compare( $stored, '2.1.17', '<' ) ) {
			self::create_tables();
		}

		// V2.1.20: baseline the activity-chain security-key fingerprint on
		// existing installs that already have an initialized chain but no
		// fingerprint yet. From this point on, a wp_salt('auth') rotation
		// (migration / restored backup / manual key change) is recognised as a
		// benign key change rather than a "TAMPERED" alarm. We baseline the
		// CURRENT key, so only FUTURE rotations are flagged: exactly right,
		// since we cannot retroactively know whether the present key is original.
		if ( version_compare( $stored, '2.1.20', '<' ) ) {
			require_once LOGIN_ARMOR_DIR . 'includes/ActivityLog/ActivityLog.php';
			if ( '' === (string) get_option( \LoginArmor\ActivityLog\ActivityLog::OPTION_CHAIN_SALT_FP, '' )
				&& \LoginArmor\ActivityLog\ActivityLog::get_chain_start_id() > 0 ) {
				\LoginArmor\ActivityLog\ActivityLog::store_salt_fingerprint();
			}
		}

		// V2.4.2: add the composite (ip, status, attempt_time) index on
		// login_armor_attempts: the hot lockout queries filter on exactly
		// these three columns. create_tables() is dbDelta-idempotent so
		// re-running it just issues the ADD KEY on existing installs.
		if ( version_compare( $stored, '2.4.2', '<' ) ) {
			self::create_tables();
		}

		// V2.4.5: add the `reason` column to login_armor_logs, the real error
		// code behind a failed login (incorrect_password, invalid_username,
		// test_cookie, or one of the plugin's own gate codes). Until 2.4.4 every
		// failure was rendered as "Wrong password" regardless of cause, which
		// made a 2FA lockout indistinguishable from an actually wrong password
		// (reported by Jean-Pol, 2026-07-21). create_tables() is dbDelta-
		// idempotent so re-running it just issues the ADD COLUMN. Existing rows
		// keep reason = '' and fall back to the legacy generic label.
		if ( version_compare( $stored, '2.4.5', '<' ) ) {
			self::create_tables();
		}

		// V2.4.7: ephemeral security counters must be reaped independently of
		// the administrator's log-retention preference.
		if ( version_compare( $stored, '2.4.7', '<' ) && ! wp_next_scheduled( 'login_armor_security_counters_purge' ) ) {
			wp_schedule_event( time() + HOUR_IN_SECONDS, 'daily', 'login_armor_security_counters_purge' );
		}

		// 2.6.1: up to 2.6.0 a network-wide activation scheduled the five events
		// once, after the per-site loop, so only the activating site had them.
		// Every other site of an upgraded network is repaired here, on its first
		// request. Idempotent, and it also covers a single site whose events
		// were dropped by a host-side cron wipe.
		if ( version_compare( $stored, '2.6.1', '<' ) ) {
			self::ensure_site_crons();
		}

		// 2.7.0: the request firewall and the bot challenge now record WHEN
		// they were switched on, so the "you have watched for a week, switch
		// to Enforce" advice can wait for real evidence. A module enabled by
		// an earlier version carries no stamp at all, and nothing on the site
		// remembers the real date. Dating it from this upgrade is the only
		// honest reading available, and it errs the safe way: the advice is
		// proposed a week from now rather than immediately.
		if ( version_compare( $stored, '2.7.0', '<' ) ) {
			self::stamp_monitor_modules();

			// 2.7.0 adds login_armor_notif_digest to CRON_HOOKS, and a version
			// that introduces an event has to schedule it: the 2.6.1 call above
			// is reached only by sites coming from 2.6.0 or earlier, so a site
			// already on 2.6.1 walked straight past it and never got the tick.
			// Measured on cours-ndrc.fr right after this upgrade: eight events
			// where nine were expected, the digest missing.
			//
			// self_heal_site_crons() does put it back, from the daily event or
			// from the next admin page, so nothing stays broken for long. That
			// is exactly why this line is needed anyway: a repair path that
			// closes the gap within a day is not an install path, it hides the
			// gap instead of removing it, and it cannot be relied on by a site
			// whose daily event is the one that went missing.
			self::ensure_site_crons();
		}

		// 2.7.1: the AI analysis of an incident moves from a 12-hour transient
		// onto the incident row (ai_analysis / ai_analysis_fp / ai_analysed_at).
		// create_tables() is dbDelta-idempotent, so on an existing install this
		// is just the three ADD COLUMN statements, and re-running it is a no-op.
		//
		// The old transients are then unreachable: their key folded the incident
		// fingerprint, nothing reads that prefix any more, and left alone they
		// would sit in wp_options until their own expiry. Delete them here rather
		// than leave dead rows behind, exactly as the 2.1.0 step did for the
		// orphaned 2FA tokens.
		if ( version_compare( $stored, '2.7.1', '<' ) ) {
			self::create_tables();

			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- One-shot upgrade purge over plugin-owned options.
			$wpdb->query(
				"DELETE FROM {$wpdb->options} WHERE option_name LIKE '\\_transient\\_login\\_armor\\_ai\\_inc\\_%' OR option_name LIKE '\\_transient\\_timeout\\_login\\_armor\\_ai\\_inc\\_%'"
			);
		}

		// 2.8.0: two changes reach existing sites here rather than on the
		// next settings save. The Activity Log events become conditional, so a
		// site with the module off loses the chain repair (every 5 minutes)
		// and the SIEM dispatcher (every minute) it never used; and the
		// "Protect system files" toggle becomes an .htaccess rule, which a
		// site that already had it on gets now.
		if ( version_compare( $stored, '2.8.0', '<' ) ) {
			self::ensure_site_crons();
			self::restore_htaccess_blocks();
			self::preload_hot_options();
		}

		// 2.8.3: the root .htaccess is in the directory the site is served
		// from, which is not ABSPATH under Bedrock or with WordPress in its own
		// directory. The root blocks are written there now, and those 2.8.0 to
		// 2.8.2 left in an ABSPATH .htaccess move with them.
		if ( version_compare( $stored, '2.8.3', '<' ) ) {
			if ( ! class_exists( Hardening::class, false ) ) {
				require_once LOGIN_ARMOR_DIR . 'includes/class-hardening.php';
			}
			Hardening::relocate_legacy_root_blocks();
		}

		// 2.9.0: the application-password usage journal. The table is created
		// here, and monitoring, on by default, dates its start now: a password
		// already in service learns its networks for its first days instead of
		// alerting on its first request. Literal option names: this runs before
		// load_modules() has required Headless and AppPasswords\Usage.
		if ( version_compare( $stored, '2.9.0', '<' ) ) {
			self::create_tables();
			// Both options are read on every request: stored, so that a later
			// update_option( X, false ) is not lost (the real core writes
			// nothing for an absent option whose new value is false).
			if ( false === get_option( 'login_armor_headless' ) ) {
				add_option( 'login_armor_headless', false );
			}
			if ( false === get_option( 'login_armor_app_password_watch' ) ) {
				add_option( 'login_armor_app_password_watch', 1 );
			}
			if ( self::to_bool( get_option( 'login_armor_app_password_watch', 1 ) ) && (int) get_option( 'login_armor_app_password_watch_since', 0 ) <= 0 ) {
				update_option( 'login_armor_app_password_watch_since', time(), false );
			}
		}

		// 2.10.0: boolean options stored as strings ("false" read as ON by
		// every reader) are rewritten as what the site does today, so nothing
		// changes state on update; from now on "false" really switches off.
		// The activity log is not loaded yet: the rewrites are announced at init.
		// The two new settings get their defaults.
		if ( version_compare( $stored, '2.10.0', '<' ) ) {
			require_once LOGIN_ARMOR_DIR . 'includes/Support/Booleans.php';
			$login_armor_bool_changes = Support\Booleans::migrate_existing();
			if ( array() !== $login_armor_bool_changes ) {
				add_action(
					'init',
					static function () use ( $login_armor_bool_changes ): void {
						do_action( 'login_armor_boolean_options_migrated', $login_armor_bool_changes );
					},
					20
				);
			}
			if ( false === get_option( 'login_armor_notif_digest_to' ) ) {
				add_option( 'login_armor_notif_digest_to', '', '', false );
			}
			if ( false === get_option( 'login_armor_syslog' ) ) {
				add_option( 'login_armor_syslog', 0 );
			}
		}

		update_option( 'login_armor_db_version', $target, false );
	}

	/**
	 * Put the options every request reads into the autoload set (2.8.0).
	 *
	 * Measured on a default site: six options were read on every public page
	 * outside the autoload set, four stored with autoload off and two not
	 * stored at all, so each page paid six extra queries without a persistent
	 * object cache. The writers now store them autoloaded; this converts the
	 * rows an existing site already has, and creates the two missing ones
	 * with their defaults.
	 */
	private static function preload_hot_options(): void {
		foreach ( array( 'login_armor_headers_sitewide', 'login_armor_webhook_enabled' ) as $login_armor_option ) {
			if ( false === get_option( $login_armor_option ) ) {
				add_option( $login_armor_option, false );
			}
		}

		wp_set_option_autoload_values(
			array(
				'login_armor_hardening'              => true,
				'login_armor_firewall'               => true,
				'login_armor_pow'                    => true,
				'login_armor_v211_chain_initialized' => true,
			)
		);
	}

	/**
	 * Give an already-enabled monitor module the stamp 2.7.0 introduced.
	 *
	 * Only ever WRITES a missing stamp: a module that is off keeps its 0, and
	 * a module that already carries a date keeps that date, so the step is
	 * idempotent and a second run never moves the monitoring period.
	 *
	 * set_enabled( true ) is deliberately NOT used here: it resets the mode to
	 * `log_only`, and an administrator who had already switched the firewall
	 * to `enforce` would silently stop being protected by an upgrade.
	 *
	 * @since 2.7.0
	 */
	private static function stamp_monitor_modules(): void {
		$now = time();

		$modules = array(
			'includes/Firewall/Firewall.php'   => '\LoginArmor\Firewall\Firewall',
			'includes/class-pow-challenge.php' => '\LoginArmor\PowChallenge',
		);

		foreach ( $modules as $file => $class ) {
			if ( ! class_exists( $class, false ) ) {
				$path = LOGIN_ARMOR_DIR . $file;
				if ( ! file_exists( $path ) ) {
					continue;
				}
				require_once $path;
			}
			if ( ! class_exists( $class, false ) ) {
				continue;
			}

			$settings = $class::get_settings();
			if ( empty( $settings['enabled'] ) || (int) ( $settings['enabled_at'] ?? 0 ) > 0 ) {
				continue;
			}

			$settings['enabled_at'] = $now;
			update_option( $class::OPTION_KEY, $settings, false );
		}
	}

	/**
	 * V2.1.1 one-shot: initialize the ActivityLog HMAC chain.
	 *
	 * Inserts a synthetic system row with sentinel prev_hash, then stores its
	 * id in OPTION_CHAIN_START_ID. verify_chain() (Task B5) skips rows below
	 * this id (pre-V2.1.1 legacy rows are kept un-signed). One-shot via the
	 * sentinel option login_armor_v211_chain_initialized.
	 *
	 * Called on the `init` action at priority 5 (before loggers register on
	 * the default priority 10). Idempotent: runs at most once per install.
	 */
	public function maybe_initialize_activity_chain(): void {
		// Defense-in-depth: even though load_modules() now always requires the
		// ActivityLog class file, a downstream regression that re-conditions the
		// require would otherwise turn this into a fatal on every request.
		if ( ! class_exists( '\LoginArmor\ActivityLog\ActivityLog' ) ) {
			return;
		}
		// 2.8.0: the module switch first. It is autoloaded, while the sentinel
		// below does not even exist on a site that never used the Activity
		// Log, so asking it first cost a query on every request of every such
		// site.
		if ( ! \LoginArmor\ActivityLog\ActivityLog::is_enabled() ) {
			return;  // Module not on: initialize on first enable instead.
		}
		if ( get_option( 'login_armor_v211_chain_initialized', 0 ) ) {
			return;
		}
		if ( ! \LoginArmor\ActivityLog\ActivityLog::acquire_chain_lock( 2 ) ) {
			return;
		}

		try {
			// Another request may have initialized the chain while this request
			// was waiting for the shared writer lock.
			if ( get_option( 'login_armor_v211_chain_initialized', 0 ) ) {
				return;
			}

			global $wpdb;
			$table = $wpdb->prefix . 'login_armor_activity';

			$row_data = [
				'user_id'     => 0,
				'user_login'  => 'system',
				'user_role'   => 'system',
				'action'      => 'chain_initialized',
				'object_type' => 'system',
				'object_id'   => 0,
				'object_name' => 'login-armor',
				'description' => 'Activity Log integrity chain initialized at upgrade to V2.1.1',
				'ip'          => '',
				'log_time'    => gmdate( 'Y-m-d H:i:s' ),
				'prev_hash'   => \LoginArmor\ActivityLog\ActivityLog::CHAIN_GENESIS_HASH,
				'row_hash'    => null,
			];

			$canonical = \LoginArmor\ActivityLog\ActivityLog::canonical_payload( $row_data );
			if ( false === $canonical ) {
				return; // Retry on the next request after an encoding failure.
			}
			$row_hash = hash_hmac(
				'sha256',
				$row_data['prev_hash'] . $canonical,
				\LoginArmor\ActivityLog\ActivityLog::get_chain_secret()
			);
			$row_data['row_hash'] = $row_hash;

			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Custom plugin table, one-shot upgrade insert.
			$wpdb->insert(
				$table,
				$row_data,
				[ '%d', '%s', '%s', '%s', '%s', '%d', '%s', '%s', '%s', '%s', '%s', '%s' ]
			);
			$new_id = (int) $wpdb->insert_id;

			// Keep the sentinel unset after an insert failure so a later request
			// can retry without leaving the chain permanently uninitialized.
			if ( $new_id <= 0 ) {
				return;
			}

			// This option is read for every activity insert.
			update_option( \LoginArmor\ActivityLog\ActivityLog::OPTION_CHAIN_START_ID, $new_id );

			// Record the current security-key fingerprint as the trusted baseline.
			\LoginArmor\ActivityLog\ActivityLog::store_salt_fingerprint();

			// 2.8.0: the sentinel is autoloaded after all, because it is read
			// on every request while the Activity Log is on. The notice flag
			// is read on admin screens only and stays out.
			update_option( 'login_armor_v211_chain_initialized', 1, true );
			update_option( 'login_armor_v211_show_chain_init_notice', 1, false );
		} finally {
			\LoginArmor\ActivityLog\ActivityLog::release_chain_lock();
		}
	}

	/**
	 * Load plugin translations from the bundled languages/ directory.
	 *
	 * Hooked on `init` because some text domains (notably ones used from the
	 * dashboard widget) are requested before `plugins_loaded` has finished on
	 * multisite. Safe to call multiple times: WP guards against double-loads.
	 */
	public function load_textdomain(): void {
		// phpcs:ignore PluginCheck.CodeAnalysis.DiscouragedFunctions.load_plugin_textdomainFound -- Needed for pre-WordPress.org distribution (direct ZIP install). Will become a no-op once the plugin ships through the wp.org language pack pipeline.
		load_plugin_textdomain(
			'login-armor',
			false,
			dirname( LOGIN_ARMOR_BASENAME ) . '/languages'
		);
	}

	/**
	 * Plugin activation callback.
	 *
	 * @param bool $network_wide Whether the plugin is being activated network-wide.
	 */
	public static function activate( $network_wide = false ): void {
		if ( $network_wide && is_multisite() ) {
			// One page of sites at a time, inside a time budget. Until 2.6.0
			// this was a single get_sites( [ 'fields' => 'ids' ] ), which core
			// caps at 100 rows: site 101 and beyond were never provisioned and
			// never reported. Whatever the budget leaves untouched is picked up
			// by maybe_run_db_upgrade() on that site's first request, so a large
			// network degrades into a lazy install instead of a timeout.
			$deadline = self::now() + self::provision_budget();
			$done     = 0;

			self::each_site(
				static function ( $site_id ) use ( $deadline, &$done ): bool {
					switch_to_blog( $site_id );
					self::provision_site();
					restore_current_blog();
					++$done;

					return self::now() < $deadline;
				}
			);

			// Say how far it got. An operator who sees "provisioned 100 of a
			// larger network" knows the rest is coming lazily, instead of
			// discovering it months later through a log that never rotated.
			if ( defined( 'WP_CLI' ) && \WP_CLI && class_exists( '\WP_CLI' ) ) {
				\WP_CLI::log( sprintf( 'Login Armor: provisioned %d site(s) of the network.', $done ) );
			}
		} else {
			self::provision_site();
		}

		// First activation: flag a one-shot redirect to the onboarding wizard.
		// Single-site interactive activation only; an install that already
		// completed onboarding is never redirected again. The redirect itself
		// (and the bulk-activation guard) lives in Admin::maybe_onboarding_redirect().
		if ( ! $network_wide && ! get_option( 'login_armor_onboarded', false ) ) {
			set_transient( 'login_armor_activation_redirect', 1, 60 );
		}

		// Invalidate any stale bytecode for plugin files. Hosts with
		// opcache.validate_timestamps=0 otherwise keep serving the previous
		// version even after re-install.
		self::invalidate_opcache();
	}

	/**
	 * Install everything the plugin needs on the CURRENT site.
	 *
	 * The single definition of "provisioned": the tables, the default options,
	 * and the scheduled events. Called by activation (once per site of the
	 * network), by wp_initialize_site for a site created later, and by
	 * maybe_run_db_upgrade() for a site that was never reached by either.
	 * Idempotent: dbDelta, add_option and wp_next_scheduled all guard
	 * themselves, so calling it on an already-provisioned site changes nothing.
	 *
	 * @since 2.6.1
	 */
	public static function provision_site(): void {
		self::create_tables();
		self::set_default_options();
		self::schedule_site_crons();
		// 2.8.0: deactivation now takes the .htaccess blocks out, so the next
		// activation puts back those whose toggle is still on. Never removes:
		// see Hardening::restore_htaccess_blocks().
		self::restore_htaccess_blocks();
	}

	/**
	 * Load the hardening class if needed and restore its .htaccess blocks (2.8.0).
	 *
	 * register_activation_hook runs before load_modules(), so the class may
	 * not be loaded yet.
	 */
	private static function restore_htaccess_blocks(): void {
		if ( ! class_exists( Hardening::class, false ) ) {
			require_once LOGIN_ARMOR_DIR . 'includes/class-hardening.php';
		}
		Hardening::restore_htaccess_blocks();
	}

	/**
	 * Load the hardening class if needed and remove its .htaccess blocks (2.8.0).
	 *
	 * @param bool $root Also the shared root .htaccess blocks.
	 */
	private static function remove_htaccess_blocks( bool $root ): void {
		if ( ! class_exists( Hardening::class, false ) ) {
			require_once LOGIN_ARMOR_DIR . 'includes/class-hardening.php';
		}
		Hardening::remove_htaccess_blocks( $root );
	}

	/**
	 * Schedule the five activation events on the CURRENT site.
	 *
	 * Ordering trap: register_activation_hook fires BEFORE plugins_loaded, so
	 * the singleton constructor (which wires register_hooks()) has not run and
	 * the `cron_schedules` filter is not registered yet. wp_schedule_event()
	 * would then fail to resolve 'login_armor_5min' / 'login_armor_1min' and
	 * silently schedule nothing. The filter is therefore added here first;
	 * WordPress de-duplicates it by callback identity when register_hooks()
	 * adds it again.
	 *
	 * @since 2.6.1
	 */
	public static function schedule_site_crons(): void {
		add_filter( 'cron_schedules', [ self::class, 'register_cron_intervals' ] );

		// Daily log purge, only when the administrator left auto-purge on.
		if ( (bool) get_option( 'login_armor_auto_purge', true ) && ! wp_next_scheduled( 'login_armor_purge_logs' ) ) {
			wp_schedule_event( time(), 'daily', 'login_armor_purge_logs' );
		}
		// V2.4.7 : ephemeral security counters, reaped independently of the
		// administrator's log-retention preference.
		if ( ! wp_next_scheduled( 'login_armor_security_counters_purge' ) ) {
			wp_schedule_event( time() + HOUR_IN_SECONDS, 'daily', 'login_armor_security_counters_purge' );
		}
		// V2.1.1 : chain repair (every 5 min), auto-verify (daily) and the SIEM
		// webhook dispatcher (every minute). 2.8.0: conditional, see
		// sync_activity_crons().
		self::sync_activity_crons();

		// 2.7.0 : the scheduled digest. A daily tick, permanent whatever the
		// digest setting says: Digest::maybe_send() returns on its first line
		// when the mode is 'off', so an unused feature costs one option read
		// a day, and switching it on never has to schedule anything.
		if ( ! wp_next_scheduled( 'login_armor_notif_digest' ) ) {
			wp_schedule_event( time() + 2 * HOUR_IN_SECONDS, 'daily', 'login_armor_notif_digest' );
		}

		// 2.7.4 : the activity log's daily purge. It was created in
		// ActivityLog::enable() and in the settings handler, and nowhere else:
		// scheduled when the module was switched on, never again afterwards.
		// That is exactly the hole this function exists to close. Core's
		// wp_schedule_event() rewrites the whole `cron` option from an array
		// read earlier, with no compare-and-swap, so two concurrent requests
		// drop each other's events; 2.6.1 gave five events a way back and left
		// this one out. A site that lost it went on writing rows and quietly
		// stopped deleting them, for good, unless an administrator happened to
		// re-save the Activity Log settings.
		//
		// Conditional on the module, like the GeoIP event below: a disabled
		// activity log has nothing to purge. The class file is required the
		// same way and for the same reason, register_activation_hook running
		// before load_modules().
		if ( ! class_exists( ActivityLog\ActivityLog::class, false ) ) {
			require_once LOGIN_ARMOR_DIR . 'includes/ActivityLog/ActivityLog.php';
		}
		if ( ActivityLog\ActivityLog::is_enabled() && ! wp_next_scheduled( ActivityLog\ActivityLog::CRON_HOOK ) ) {
			wp_schedule_event( time(), 'daily', ActivityLog\ActivityLog::CRON_HOOK );
		}

		// 2.6.1 : GeoIP prefetch. Conditional, and the only event here that is
		// also REMOVED when its module is off, so switching geolocation off in
		// any way (admin toggle, WP-CLI, settings import, restored backup)
		// eventually stops the event even if nothing called the toggle path.
		//
		// The class file is required explicitly: register_activation_hook fires
		// before plugins_loaded, so load_modules() has not run yet and
		// GeoIP would be undefined on activation.
		if ( ! class_exists( GeoIP::class, false ) ) {
			require_once LOGIN_ARMOR_DIR . 'includes/class-geoip.php';
		}
		GeoIP::sync_prefetch_schedule();

		// 2.9.0: the usage review is a single event booked by a new row, so a
		// lost event is never re-booked by anything else. Only when rows wait.
		if ( ! class_exists( AppPasswords\Usage::class, false ) ) {
			require_once LOGIN_ARMOR_DIR . 'includes/AppPasswords/Usage.php';
		}
		AppPasswords\Usage::ensure_review_scheduled();
	}

	/**
	 * Schedule the Activity Log events only while they have work, and remove them otherwise (2.8.0).
	 *
	 * Until 2.7.10 the chain repair (every 5 minutes), the chain check (daily)
	 * and the SIEM dispatcher (every minute) were scheduled on every site,
	 * while their handlers are only registered when the Activity Log is on,
	 * and forwarding is configured for the dispatcher. On a default site, where
	 * forwarding is off, WP-Cron therefore woke up about once a minute, sent a
	 * loopback request to wp-cron.php and rewrote the `cron` option, to run
	 * nothing. Same rule as the GeoIP prefetch: an event exists while its
	 * module does.
	 *
	 * Called by schedule_site_crons() (activation, upgrades, the daily
	 * self-heal) and, so that switching a module on takes effect at once
	 * whatever the path (settings screen, import, WP-CLI), by the option
	 * hooks registered in register_hooks(). An existing dispatcher event is
	 * left alone: WebhookDispatcher slows it to hourly after repeated
	 * failures, and re-scheduling it here would undo that.
	 *
	 * Untyped with a default: it is also a callback of core option hooks,
	 * which pass their own arguments.
	 *
	 * @param mixed $unused Whatever the option hook passes; ignored.
	 */
	public static function sync_activity_crons( $unused = null ): void {
		unset( $unused );
		add_filter( 'cron_schedules', [ self::class, 'register_cron_intervals' ] );

		if ( ! class_exists( ActivityLog\ActivityLog::class, false ) ) {
			require_once LOGIN_ARMOR_DIR . 'includes/ActivityLog/ActivityLog.php';
		}
		if ( ! class_exists( ActivityLog\WebhookDispatcher::class, false ) ) {
			require_once LOGIN_ARMOR_DIR . 'includes/ActivityLog/WebhookDispatcher.php';
		}
		// The same readers the handlers are registered on, so an event exists
		// exactly when something will answer it.
		$log_on  = ActivityLog\ActivityLog::is_enabled();
		$siem_on = $log_on && ActivityLog\WebhookDispatcher::is_enabled();

		if ( $log_on ) {
			if ( ! wp_next_scheduled( 'login_armor_chain_repair' ) ) {
				wp_schedule_event( time() + 300, 'login_armor_5min', 'login_armor_chain_repair' );
			}
			if ( ! wp_next_scheduled( 'login_armor_chain_auto_verify' ) ) {
				wp_schedule_event( time() + 3600, 'daily', 'login_armor_chain_auto_verify' );
			}
			// The log's own daily purge follows the same switch: switched on
			// through WP-CLI or an import, the module kept no purge until the
			// next daily self-heal.
			if ( ! wp_next_scheduled( ActivityLog\ActivityLog::CRON_HOOK ) ) {
				wp_schedule_event( time(), 'daily', ActivityLog\ActivityLog::CRON_HOOK );
			}
		} else {
			wp_unschedule_hook( 'login_armor_chain_repair' );
			wp_unschedule_hook( 'login_armor_chain_auto_verify' );
			wp_unschedule_hook( ActivityLog\ActivityLog::CRON_HOOK );
		}

		if ( $siem_on ) {
			if ( ! wp_next_scheduled( 'login_armor_webhook_dispatch' ) ) {
				wp_schedule_event( time() + 60, 'login_armor_1min', 'login_armor_webhook_dispatch' );
			}
		} else {
			wp_unschedule_hook( 'login_armor_webhook_dispatch' );
		}
	}

	/**
	 * Create the activity table when the Activity Log is switched on (2.8.0).
	 *
	 * ActivityLog::enable() creates it, and only the settings screen calls
	 * enable(). An option written by WP-CLI or a restored backup switched the
	 * module on with no table behind it. dbDelta is idempotent, so a table
	 * already there costs one DESCRIBE, on an option change only.
	 *
	 * Untyped with a default: a callback of core option hooks.
	 *
	 * @param mixed $unused Whatever the option hook passes; ignored.
	 */
	public static function ensure_activity_table( $unused = null ): void {
		unset( $unused );
		if ( ! class_exists( ActivityLog\ActivityLog::class, false ) ) {
			require_once LOGIN_ARMOR_DIR . 'includes/ActivityLog/ActivityLog.php';
		}
		if ( ActivityLog\ActivityLog::is_enabled() ) {
			ActivityLog\ActivityLog::create_table();
		}
	}

	/**
	 * Re-schedule any activation event missing from the CURRENT site.
	 *
	 * Same work as schedule_site_crons(), which is already guarded event by
	 * event. Named separately because the 2.6.1 upgrade step reads as a repair
	 * and not as an install: a network upgraded from 2.6.0 has the five events
	 * on the activating site only.
	 *
	 * @since 2.6.1
	 */
	public static function ensure_site_crons(): void {
		self::schedule_site_crons();
	}

	/**
	 * Repair the scheduled events of the CURRENT site, under the lock.
	 *
	 * Why this exists at all: core's wp_schedule_event() rewrites the WHOLE
	 * `cron` option from the array the request read earlier, with no duplicate
	 * guard and no compare-and-swap. Two requests that both read the array
	 * before either wrote it each drop the other's events, and update_option()
	 * returning false leaves the loser convinced its own array is current. That
	 * is how a freshly provisioned subsite was observed missing one of the five
	 * events on WordPress 7.1.2, and nothing in 2.6.0 ever put it back:
	 * chain_repair, chain_auto_verify and security_counters_purge had no
	 * re-scheduling path at all.
	 *
	 * So: one writer at a time (the lock), reading the events another request
	 * may have just committed (the cache refresh), and run often enough that a
	 * lost event comes back by itself.
	 *
	 * @since 2.6.1
	 *
	 * @return bool False when another request holds the lock and this call did nothing.
	 */
	public static function self_heal_site_crons(): bool {
		if ( ! self::acquire_provision_lock() ) {
			return false;
		}

		try {
			self::refresh_option_cache();
			self::ensure_site_crons();
		} finally {
			self::release_provision_lock();
		}

		return true;
	}

	/**
	 * The daily self-heal, as an action callback.
	 *
	 * A WordPress action callback must return nothing: whatever it returns is
	 * discarded by do_action(), and a callback that looks like it answers a
	 * question invites a caller to believe the answer travels somewhere. The
	 * work itself keeps its boolean, which is what says whether this request
	 * took the lock or another one already held it, and is what the tests
	 * assert on.
	 *
	 * @since 2.6.1
	 */
	public static function on_daily_self_heal(): void {
		self::self_heal_site_crons();
		self::self_heal_schema();
	}

	/**
	 * Admin-side half of the self-heal, at most once a day per site.
	 *
	 * The cron-side half rides on login_armor_security_counters_purge, which
	 * cannot help when that very event is the one that was lost. An
	 * administrator opening any admin page repairs the site instead.
	 *
	 * The transient is written BEFORE the work: a repair that somehow fataled
	 * must not be retried on every single admin request.
	 *
	 * Not on AJAX. admin_init also fires on admin-ajax.php, where the
	 * heartbeat lands every 15 to 60 seconds per open tab, and where this
	 * plugin's own 40-odd endpoints live. The daily gate is a non-autoloaded
	 * transient, so reading it costs two option rows that are not in the
	 * autoload cache; paying that on every heartbeat to answer a question
	 * about scheduled events, which only a real admin page visit needs to
	 * ask, is the kind of cost nobody ever notices and nobody ever removes.
	 * The next ordinary admin page does the repair.
	 *
	 * @since 2.6.1
	 */
	public static function maybe_self_heal_site_crons(): void {
		if ( wp_doing_ajax() ) {
			return;
		}

		if ( get_transient( self::CRONS_CHECKED_TRANSIENT ) ) {
			return;
		}

		set_transient( self::CRONS_CHECKED_TRANSIENT, 1, DAY_IN_SECONDS );
		self::self_heal_site_crons();
		self::self_heal_schema();
	}

	/**
	 * Take the per-site provisioning lock, or report that someone else has it.
	 *
	 * INSERT IGNORE on the options table: the unique index on option_name means
	 * exactly one concurrent INSERT affects a row, every other racer affects
	 * none. rows_affected is read rather than the return of query(), which
	 * cannot tell "inserted" from "ignored" without it. Same shape as
	 * LimitLogin::claim_lockout(), and for the same reason.
	 *
	 * A lock older than PROVISION_LOCK_TTL belonged to a request that died
	 * before releasing it; it is deleted and the insert retried once, so a
	 * crashed request cannot freeze provisioning forever.
	 *
	 * The takeover deletes the exact row it read, never "whatever is there
	 * now". Two requests can read the same stale timestamp; with an
	 * unconditional DELETE the second one removes the fresh lock the first has
	 * just inserted, inserts its own, and both then rewrite the `cron` option
	 * at the same time, which is the very race this lock exists to end. The
	 * compare-and-swap makes the loser's DELETE affect no row, and it stands
	 * down.
	 *
	 * @since 2.6.1
	 */
	private static function acquire_provision_lock(): bool {
		if ( self::insert_provision_lock() ) {
			return true;
		}

		global $wpdb;

		// Read the stored timestamp straight from the table: the object cache
		// may hold the miss from before the other request wrote the row.
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Fresh read of the lock we just failed to take.
		$held_raw = $wpdb->get_var(
			$wpdb->prepare( "SELECT option_value FROM {$wpdb->options} WHERE option_name = %s", self::PROVISION_LOCK_OPTION )
		);

		// The holder released it between our failed INSERT and this read.
		if ( null === $held_raw ) {
			return self::insert_provision_lock();
		}

		$held_since = (int) $held_raw;
		if ( $held_since > 0 && ( time() - $held_since ) < self::PROVISION_LOCK_TTL ) {
			return false;
		}

		if ( ! self::delete_stale_provision_lock( (string) $held_raw ) ) {
			return false;
		}

		return self::insert_provision_lock();
	}

	/**
	 * Delete the lock row ONLY if it still holds the value we read.
	 *
	 * @since 2.6.1
	 *
	 * @param string $stale The exact stored value the takeover decision was made on.
	 * @return bool True when this request is the one that removed it.
	 */
	private static function delete_stale_provision_lock( string $stale ): bool {
		global $wpdb;

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Compare-and-swap removal of an abandoned lock row.
		$wpdb->query(
			$wpdb->prepare(
				"DELETE FROM {$wpdb->options} WHERE option_name = %s AND option_value = %s",
				self::PROVISION_LOCK_OPTION,
				$stale
			)
		);

		if ( 1 !== (int) $wpdb->rows_affected ) {
			return false;
		}

		wp_cache_delete( self::PROVISION_LOCK_OPTION, 'options' );

		return true;
	}

	/**
	 * One atomic attempt at the lock row.
	 */
	private static function insert_provision_lock(): bool {
		global $wpdb;

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Atomic claim via the unique option_name index; core options table.
		$wpdb->query(
			$wpdb->prepare(
				"INSERT IGNORE INTO {$wpdb->options} (option_name, option_value, autoload) VALUES (%s, %s, 'no')",
				self::PROVISION_LOCK_OPTION,
				(string) time()
			)
		);

		return 1 === (int) $wpdb->rows_affected;
	}

	/**
	 * Drop the lock row. Always called from a finally block.
	 */
	private static function release_provision_lock(): void {
		global $wpdb;

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Releasing the lock row this request owns.
		$wpdb->query(
			$wpdb->prepare( "DELETE FROM {$wpdb->options} WHERE option_name = %s", self::PROVISION_LOCK_OPTION )
		);

		wp_cache_delete( self::PROVISION_LOCK_OPTION, 'options' );
	}

	/**
	 * Forget the cached option snapshot before reading events to rewrite.
	 *
	 * `cron` is autoloaded, so it arrives in the alloptions blob at the top of
	 * the request. Repairing from that stale blob would rewrite the option with
	 * a view of the schedule that predates whatever the previous lock holder
	 * just committed, which is the very race this lock exists to end.
	 */
	private static function refresh_option_cache(): void {
		wp_cache_delete( 'alloptions', 'options' );
		wp_cache_delete( 'cron', 'options' );
	}

	/**
	 * Clear every event the plugin can schedule on the CURRENT site.
	 *
	 * @since 2.6.1
	 */
	public static function clear_site_crons(): void {
		// 2.8.0: wp_unschedule_hook(), not wp_clear_scheduled_hook(). The
		// latter only removes the events scheduled with the arguments it is
		// given, none here, and login_armor_cleanup_rate_key is scheduled with
		// one (the rate key it cleans): those events survived deactivation and
		// uninstall. wp_unschedule_hook() removes every event of the hook,
		// whatever its arguments.
		foreach ( self::CRON_HOOKS as $login_armor_cron_hook ) {
			wp_unschedule_hook( $login_armor_cron_hook );
		}
	}

	/**
	 * Walk every site of the network, one page of 100 at a time.
	 *
	 * get_sites() caps `number` at 100 when it is not given, so a bare
	 * get_sites( [ 'fields' => 'ids' ] ) silently stops at site 100. Paging by
	 * ascending id with the meta cache off keeps memory flat on a network of
	 * any size.
	 *
	 * The callback receives the site id and is called OUTSIDE any switch: it
	 * owns its own switch_to_blog() / restore_current_blog() pair. Returning
	 * exactly false stops the walk (used by the activation time budget); any
	 * other return value continues.
	 *
	 * Keep in sync with login_armor_uninstall_site_ids() in uninstall.php,
	 * which repeats this pagination without the class.
	 *
	 * @since 2.6.1
	 *
	 * @param callable $callback fn( int $site_id ): bool|mixed
	 */
	public static function each_site( callable $callback ): void {
		$offset = 0;

		do {
			$site_ids = get_sites(
				[
					'fields'                 => 'ids',
					'number'                 => self::SITE_PAGE_SIZE,
					'offset'                 => $offset,
					'orderby'                => 'id',
					'order'                  => 'ASC',
					'update_site_meta_cache' => false,
				]
			);

			if ( ! is_array( $site_ids ) || [] === $site_ids ) {
				return;
			}

			foreach ( $site_ids as $site_id ) {
				if ( false === $callback( (int) $site_id ) ) {
					return;
				}
			}

			$offset += self::SITE_PAGE_SIZE;
		} while ( count( $site_ids ) === self::SITE_PAGE_SIZE );
	}

	/**
	 * Seconds a network-wide activation may spend provisioning sites.
	 *
	 * The budget exists to protect an HTTP activation, whose request has to come
	 * back with a rendered page. `wp plugin activate --network` has no such
	 * deadline and an operator watching a command expects it to finish the job,
	 * so WP-CLI gets no budget at all: it provisions the whole network in one
	 * go, however long that takes.
	 *
	 * Otherwise: LOGIN_ARMOR_PROVISION_BUDGET when wp-config.php defines it,
	 * else 20 seconds. The 80 percent cap on max_execution_time is applied ON
	 * TOP of that value and can only lower it. A host that allows 10 seconds
	 * gets 8, whatever the constant says; the constant raises the budget only
	 * as far as the host actually allows.
	 */
	private static function provision_budget(): float {
		if ( defined( 'WP_CLI' ) && \WP_CLI ) {
			return (float) PHP_INT_MAX;
		}

		$budget = defined( 'LOGIN_ARMOR_PROVISION_BUDGET' ) ? (float) LOGIN_ARMOR_PROVISION_BUDGET : 20.0;

		$max_execution = (float) ini_get( 'max_execution_time' );
		if ( $max_execution > 0.0 ) {
			$budget = min( $budget, $max_execution * 0.8 );
		}

		return max( 1.0, $budget );
	}

	/**
	 * Current time as a float, through the injected clock when there is one.
	 */
	private static function now(): float {
		return null === self::$clock ? microtime( true ) : (float) call_user_func( self::$clock );
	}

	/**
	 * Replace the clock used by the activation time budget.
	 *
	 * Refused outside the offline test harness: production must never run on
	 * anything but microtime().
	 *
	 * @param callable|null $clock Clock returning a float, or null to restore.
	 */
	public static function set_clock( ?callable $clock ): void {
		if ( ! defined( 'LOGIN_ARMOR_TESTING' ) ) {
			return;
		}
		self::$clock = $clock;
	}

	/**
	 * Whether the break-glass safe mode is armed.
	 *
	 * Safe mode is one line in wp-config.php:
	 *
	 *     define( 'LOGIN_ARMOR_SAFE_MODE', true );
	 *
	 * It stands down exactly the protections that can shut a legitimate
	 * administrator out of the site this plugin is supposed to protect: Hide
	 * Login stops trapping wp-login.php and /wp-admin, the second factor is not
	 * demanded, the request firewall and the bot challenge fall back to
	 * observation, and single-session enforcement pauses. Everything else,
	 * logging, detection, hardening and the brute-force lockouts, keeps
	 * running: safe mode is a way back in, not an off switch.
	 *
	 * Deliberately a constant and not a filter, and deliberately read ONCE.
	 *
	 * A filter lives inside WordPress, so any compromised theme or plugin
	 * could disarm the whole extension from there. A constant alone is not
	 * enough either: this predicate is consulted from `authenticate`, `init`
	 * and `wp_loaded`, all of which run long after themes load, so a
	 * predicate that re-read the constant on every call would be armable by a
	 * single define() in a theme's functions.php. snapshot_safe_mode() is
	 * therefore called by login-armor.php while that file loads, before the
	 * plugin registers anything, and this method only ever reports what was
	 * read there.
	 *
	 * What can still arm safe mode is exactly this, and it is what the
	 * documentation says: wp-config.php, a must-use plugin, or a plugin that
	 * loads before this one. All three require file-level write access, which
	 * is the level of access every recovery method already assumes, and all
	 * three leave a line a human can read and delete. Nothing that runs on a
	 * WordPress hook can, because by then the answer is fixed.
	 *
	 * @since 2.7.0
	 */
	public static function is_safe_mode(): bool {
		if ( null !== self::$safe_mode_override && defined( 'LOGIN_ARMOR_TESTING' ) ) {
			return self::$safe_mode_override;
		}
		if ( null === self::$safe_mode ) {
			// Reached only when the class was loaded without the plugin file:
			// the offline harness, uninstall tooling, a static analyser. In a
			// real request login-armor.php has already taken the snapshot.
			self::snapshot_safe_mode();
		}
		return self::$safe_mode;
	}

	/**
	 * Read LOGIN_ARMOR_SAFE_MODE once and keep the answer for the request.
	 *
	 * Called by login-armor.php immediately after the class is loaded and
	 * before a single hook is registered. Idempotent on purpose: a second call
	 * must NOT re-read the constant, because "read once, early" is the whole
	 * security property. See is_safe_mode().
	 *
	 * @since 2.7.0
	 */
	public static function snapshot_safe_mode(): void {
		if ( null !== self::$safe_mode ) {
			return;
		}
		self::$safe_mode = defined( 'LOGIN_ARMOR_SAFE_MODE' ) && LOGIN_ARMOR_SAFE_MODE;
	}

	/**
	 * Force the safe-mode answer from the offline test harness.
	 *
	 * Refused outside it, exactly like set_clock(): a production request must
	 * only ever read the constant. Passing null restores that.
	 *
	 * @since 2.7.0
	 *
	 * @param bool|null $active Forced answer, or null to read the constant again.
	 */
	public static function testing_set_safe_mode( ?bool $active ): void {
		if ( ! defined( 'LOGIN_ARMOR_TESTING' ) ) {
			return;
		}
		self::$safe_mode_override = $active;
	}

	/**
	 * Record, once a day, that this site is running with its guard lowered.
	 *
	 * A site can sit in safe mode for weeks: the constant is added during a
	 * lockout, access comes back, and the line is never removed. The admin
	 * notice says so to whoever opens the dashboard; this says so to whoever
	 * reads the activity log afterwards, which is the only trace that survives
	 * the session. Gated by a 24-hour transient so a busy site writes one row
	 * a day, not one row per request.
	 *
	 * @since 2.7.0
	 */
	public function observe_safe_mode(): void {
		if ( ! self::is_safe_mode() ) {
			return;
		}
		if ( false !== get_transient( 'login_armor_safe_mode_seen' ) ) {
			return;
		}

		// Both guards BEFORE the transient, not after. The Activity Log is off
		// by default, and the ordinary sequence is exactly the one that would
		// break: safe mode is armed during a lockout, the log is switched on
		// afterwards to find out what happened. A transient written by a visit
		// that recorded nothing burns the day's slot, so the row never appears
		// at all, precisely when somebody goes looking for it. The gate exists
		// to stop a second write, so only a write may arm it.
		if ( ! get_option( 'login_armor_activity_enabled', false ) ) {
			return;
		}
		if ( ! class_exists( '\LoginArmor\ActivityLog\ActivityLogger' ) ) {
			return;
		}

		set_transient( 'login_armor_safe_mode_seen', time(), DAY_IN_SECONDS );

		\LoginArmor\ActivityLog\ActivityLogger::log_system(
			'safe_mode_active',
			'LOGIN_ARMOR_SAFE_MODE',
			'Login Armor is running in safe mode: LOGIN_ARMOR_SAFE_MODE is defined in wp-config.php. Hide Login, the two-factor gate, the request firewall, the bot challenge and single-session enforcement are stood down. Brute-force lockouts remain active.'
		);
	}

	/**
	 * Whether the plugin is active on the CURRENT site.
	 *
	 * Single site: the question answers itself, this code is running. Multisite:
	 * network activation covers every site, otherwise the site's own list of
	 * active plugins decides.
	 *
	 * is_plugin_active_for_network() lives in wp-admin/includes/plugin.php,
	 * which core has loaded on every request since 6.7 (Trac #62244), and the
	 * plugin requires 6.8. The function_exists() test is therefore expected to
	 * pass always; it stays as pure defense, for a future core that stops
	 * loading that file on the front end, and the fallback reads the same
	 * network option the function reads. Neither branch loads anything.
	 */
	private static function is_plugin_active_here(): bool {
		if ( ! is_multisite() ) {
			return true;
		}

		if ( function_exists( 'is_plugin_active_for_network' ) ) {
			if ( is_plugin_active_for_network( LOGIN_ARMOR_BASENAME ) ) {
				return true;
			}
		} elseif ( isset( ( (array) get_site_option( 'active_sitewide_plugins', [] ) )[ LOGIN_ARMOR_BASENAME ] ) ) { // @codeCoverageIgnore -- unreachable on WP 6.7+, kept as defense.
			return true;
		}

		return in_array( LOGIN_ARMOR_BASENAME, (array) get_option( 'active_plugins', [] ), true );
	}

	/**
	 * Walk every PHP file in the plugin and invalidate the OPcache entry.
	 * Safe no-op when OPcache is unavailable or restricted.
	 */
	private static function invalidate_opcache(): void {
		if ( ! function_exists( 'opcache_invalidate' ) ) {
			return;
		}
		$plugin_dir = plugin_dir_path( __DIR__ );
		$directory  = new \RecursiveDirectoryIterator( $plugin_dir, \FilesystemIterator::SKIP_DOTS );
		// Never descend into a dot-directory. A released plugin has none, but a
		// developer checkout has .git, whose thousands of unreadable objects can
		// throw out of the iterator, and which holds no bytecode either way.
		$filtered = new \RecursiveCallbackFilterIterator(
			$directory,
			static function ( $current ): bool {
				return ! ( $current->isDir() && str_starts_with( $current->getFilename(), '.' ) );
			}
		);
		$iterator = new \RecursiveIteratorIterator( $filtered );
		foreach ( $iterator as $file ) {
			if ( $file->isFile() && 'php' === strtolower( $file->getExtension() ) ) {
				@opcache_invalidate( $file->getPathname(), true ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- opcache may be restricted per-file, we treat failures as harmless.
			}
		}
	}

	/**
	 * Plugin deactivation callback.
	 *
	 * Must clear every cron hook the plugin can schedule (self::CRON_HOOKS): a
	 * deactivated plugin has no callbacks, so any leftover event fires into the
	 * void on every WP-Cron run.
	 *
	 * On a network-wide deactivation WordPress passes true here (core calls
	 * `do_action( "deactivate_{$plugin}", $network_deactivating )`), and the
	 * events live on every site of the network, not on the one the
	 * administrator happened to be on. Untyped with a default, like every
	 * core-hook callback of this plugin.
	 *
	 * @param bool $network_deactivating Whether the plugin is being deactivated network-wide.
	 */
	public static function deactivate( $network_deactivating = false ): void {
		// 2.8.0: the .htaccess blocks go too, so that a deactivated plugin
		// leaves no server rule behind (each site's uploads block, and the
		// shared root blocks once). On a single site of a network the root
		// file is shared with sites where the plugin stays active, so only
		// that site's uploads block is removed.
		if ( $network_deactivating && is_multisite() ) {
			self::each_site(
				static function ( $site_id ): bool {
					switch_to_blog( $site_id );
					self::clear_site_crons();
					self::remove_htaccess_blocks( false );
					restore_current_blog();

					return true;
				}
			);
			self::remove_htaccess_blocks( true );

			return;
		}

		self::clear_site_crons();
		self::remove_htaccess_blocks( ! is_multisite() );
	}

	/**
	 * Create database tables.
	 *
	 * 2.8.0: the statements moved to table_statements(), so that the schema
	 * check (missing_schema_columns()) reads the very columns this creates
	 * instead of a second list that could drift from it.
	 */
	public static function create_tables( bool $stamp = true ): void {
		require_once ABSPATH . 'wp-admin/includes/upgrade.php';
		foreach ( self::table_statements() as $login_armor_sql ) {
			dbDelta( $login_armor_sql );
		}

		// 2.8.0: a repair does not stamp. The stamp is what the upgrade
		// routine compares to decide which version steps a site still owes;
		// a schema repair run on a request that lost the provisioning lock
		// (a failed login-log write, the daily self-heal) stamped the new
		// version before the 2.8.0 step had run, and that step was then
		// skipped for good.
		if ( $stamp ) {
			update_option( 'login_armor_db_version', LOGIN_ARMOR_VERSION );
		}
	}

	/**
	 * The CREATE TABLE statement of every table create_tables() owns.
	 *
	 * In the order create_tables() runs them, keyed by table name without the
	 * site prefix.
	 *
	 * @since 2.8.0
	 *
	 * @return array<string,string>
	 */
	public static function table_statements(): array {
		global $wpdb;

		$charset_collate = $wpdb->get_charset_collate();

		$sql_attempts = "CREATE TABLE {$wpdb->prefix}login_armor_attempts (
			id bigint(20) UNSIGNED NOT NULL AUTO_INCREMENT,
			ip varchar(100) NOT NULL,
			username varchar(200) DEFAULT '',
			attempt_time datetime NOT NULL,
			status varchar(20) NOT NULL DEFAULT 'failed',
			PRIMARY KEY (id),
			KEY ip (ip),
			KEY attempt_time (attempt_time),
			KEY ip_status_time (ip, status, attempt_time)
		) $charset_collate;";

		$sql_logs = "CREATE TABLE {$wpdb->prefix}login_armor_logs (
			id bigint(20) UNSIGNED NOT NULL AUTO_INCREMENT,
			ip varchar(100) NOT NULL,
			username varchar(200) DEFAULT '',
			log_time datetime NOT NULL,
			status varchar(20) NOT NULL,
			user_agent varchar(500) DEFAULT '',
			reason varchar(50) NOT NULL DEFAULT '',
			PRIMARY KEY (id),
			KEY ip (ip),
			KEY log_time (log_time),
			KEY status (status)
		) $charset_collate;";

		// The AI analysis of an incident lives ON the incident row (2.7.1). It was
		// a 12-hour transient, so an administrator who read an analysis, left the
		// page and came back was offered the button again and paid for a second
		// generation of the same text: the drill-down never looked the cache up
		// when it rendered, and an object cache under pressure could evict the row
		// early anyway. Three columns on the row the analysis describes make it
		// part of the incident record, bounded by construction (one per incident,
		// never more), and cleaned up for free: the retention purge and
		// uninstall.php already delete incidents, and the text goes with the row.
		//
		// `ai_analysis_fp` is the fingerprint of the state that produced the text
		// (deep cursor, last_seen_at, events_count, severity). The drill-down
		// compares it to the incident's current fingerprint so an analysis written
		// before the attack moved on is labelled as describing an earlier state
		// instead of being passed off as current.
		//
		// `vector` MUST stay backticked everywhere it appears in raw SQL: it is a
		// reserved word since MariaDB 11.7 and MySQL 9.0 (the VECTOR data type).
		// Unquoted, this CREATE TABLE is a syntax error, the incidents table is
		// never created, and the whole Detection engine fails silently on modern
		// database servers. Found on MariaDB 12.3 while testing 2.4.5. dbDelta
		// strips the backticks before comparing columns, so this stays idempotent.
		$sql_incidents = "CREATE TABLE {$wpdb->prefix}login_armor_incidents (
			id bigint(20) UNSIGNED NOT NULL AUTO_INCREMENT,
			pattern varchar(32) NOT NULL,
			severity tinyint(3) UNSIGNED NOT NULL DEFAULT 1,
			started_at datetime NOT NULL,
			last_seen_at datetime NOT NULL,
			ip varchar(100) DEFAULT '',
			subnet varchar(100) DEFAULT '',
			target_username varchar(200) DEFAULT '',
			events_count int UNSIGNED NOT NULL DEFAULT 0,
			unique_ips int UNSIGNED NOT NULL DEFAULT 0,
			unique_usernames int UNSIGNED NOT NULL DEFAULT 0,
			status varchar(20) NOT NULL DEFAULT 'active',
			`vector` varchar(20) NOT NULL DEFAULT 'login_form',
			ai_analysis longtext NULL,
			ai_analysis_fp varchar(40) NOT NULL DEFAULT '',
			ai_analysed_at datetime NULL,
			PRIMARY KEY  (id),
			KEY pattern (pattern),
			KEY last_seen_at (last_seen_at),
			KEY status (status)
		) $charset_collate;";

		// V2.1.1: Webhook queue for async signed forwarding (S-4 ActivityLog
		// integrity stack). State machine populated by WebhookDispatcher
		// (Task B7) and drained by cron (Task B8). Idempotent via dbDelta.
		$webhook_queue_table = $wpdb->prefix . 'login_armor_webhook_queue';
		$sql_webhook_queue   = "CREATE TABLE {$webhook_queue_table} (
			id bigint(20) UNSIGNED NOT NULL AUTO_INCREMENT,
			activity_id bigint(20) UNSIGNED NOT NULL,
			payload longtext NOT NULL,
			signature char(64) NOT NULL,
			state enum('new','sending','sent','dead') NOT NULL DEFAULT 'new',
			attempts tinyint(3) UNSIGNED NOT NULL DEFAULT 0,
			last_attempt_at datetime NULL,
			last_error varchar(500) NOT NULL DEFAULT '',
			created_at datetime NOT NULL,
			PRIMARY KEY  (id),
			KEY idx_state_pickup (state, last_attempt_at),
			KEY idx_activity (activity_id)
		) $charset_collate;";

		// 2.9.0: which networks each application password is used from, one row
		// per (password, address). See includes/AppPasswords/Usage.php. Inline
		// here like the other tables: create_tables() runs at activation, before
		// load_modules() has required the class.
		$sql_app_password_usage = "CREATE TABLE {$wpdb->prefix}login_armor_app_password_usage (
			id bigint(20) UNSIGNED NOT NULL AUTO_INCREMENT,
			user_id bigint(20) UNSIGNED NOT NULL DEFAULT 0,
			uuid char(36) NOT NULL,
			password_name varchar(200) NOT NULL DEFAULT '',
			ip varchar(45) NOT NULL,
			network varchar(80) NULL,
			network_label varchar(100) NOT NULL DEFAULT '',
			country char(2) NOT NULL DEFAULT '',
			first_seen datetime NOT NULL,
			last_seen datetime NOT NULL,
			hits int(10) UNSIGNED NOT NULL DEFAULT 0,
			last_route varchar(190) NOT NULL DEFAULT '',
			state varchar(10) NOT NULL DEFAULT 'pending',
			PRIMARY KEY  (id),
			UNIQUE KEY uuid_ip (uuid, ip),
			KEY uuid_network (uuid, network),
			KEY user_id (user_id),
			KEY last_seen (last_seen),
			KEY state (state)
		) $charset_collate;";

		return array(
			'login_armor_attempts'      => $sql_attempts,
			'login_armor_logs'          => $sql_logs,
			'login_armor_incidents'     => $sql_incidents,
			'login_armor_webhook_queue' => $sql_webhook_queue,
			'login_armor_app_password_usage' => $sql_app_password_usage,
		);
	}

	/**
	 * The columns each table must carry, read from the statements that create it.
	 *
	 * The activity table is included only while the Activity Log is on: it is
	 * created when the module is switched on, not at activation, so a site
	 * that never used it has no such table and nothing is missing.
	 *
	 * @since 2.8.0
	 *
	 * @return array<string,string[]> Full table name => column names, in declaration order.
	 */
	public static function declared_columns(): array {
		global $wpdb;

		$statements = self::table_statements();
		if ( class_exists( ActivityLog\ActivityLog::class, false ) && ActivityLog\ActivityLog::is_enabled() ) {
			$statements['login_armor_activity'] = ActivityLog\ActivityLog::table_statement();
		}

		$declared = array();
		foreach ( $statements as $suffix => $sql ) {
			$declared[ $wpdb->prefix . $suffix ] = self::columns_of_statement( $sql );
		}

		return $declared;
	}

	/**
	 * Column names of one CREATE TABLE statement, keys and indexes left out.
	 *
	 * @param string $sql One statement from table_statements().
	 * @return string[]
	 */
	private static function columns_of_statement( string $sql ): array {
		$open  = strpos( $sql, '(' );
		$close = strrpos( $sql, ')' );
		if ( false === $open || false === $close || $close <= $open ) {
			return array();
		}

		$columns = array();
		foreach ( explode( "\n", substr( $sql, $open + 1, $close - $open - 1 ) ) as $line ) {
			$line = trim( $line );
			if ( '' === $line || 1 === preg_match( '/^(PRIMARY|KEY|UNIQUE|INDEX|FULLTEXT|CONSTRAINT)\b/i', $line ) ) {
				continue;
			}
			if ( 1 === preg_match( '/^`?([a-z_][a-z0-9_]*)`?\s/i', $line, $match ) ) {
				$columns[] = $match[1];
			}
		}

		return $columns;
	}

	/**
	 * What each table is missing, compared with what this version declares.
	 *
	 * 2.8.0. The version stamp is written by create_tables() whatever its
	 * ALTER statements achieved, a choice argued in Incident::store_analysis(),
	 * so the stamp proves nothing about the columns. On a database that
	 * refused the ALTER of the 2.4.5 step, the login log lost its `reason`
	 * column and every login event stopped being recorded, while Site Health,
	 * which looked at the three AI columns only, kept saying "good". This
	 * reads the live tables instead.
	 *
	 * A table that is absent misses every column, and is reported so: the
	 * repair (dbDelta) creates it. Asked of information_schema first, because
	 * SHOW COLUMNS on a missing table is an SQL error, printed on a site that
	 * displays them. A table that exists but cannot be described is left out
	 * rather than reported as missing every column, for the reason
	 * Incident::missing_analysis_columns() gives: that is a different failure,
	 * with a louder symptom of its own.
	 *
	 * @return array<string,string[]> Full table name => missing column names; only tables that miss something.
	 */
	public static function missing_schema_columns(): array {
		global $wpdb;

		$missing = array();
		foreach ( self::declared_columns() as $table => $columns ) {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Schema probe: no user input, and nothing about it is cacheable.
			$exists = $wpdb->get_var( $wpdb->prepare( 'SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = %s', $table ) );
			if ( '0' === (string) $exists ) {
				$missing[ $table ] = $columns;
				continue;
			}
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Schema probe: no user input, and nothing about it is cacheable.
			$present = $wpdb->get_col( $wpdb->prepare( 'SHOW COLUMNS FROM %i', $table ) );
			if ( ! is_array( $present ) || empty( $present ) ) {
				continue;
			}
			$absent = array_values( array_diff( $columns, $present ) );
			if ( ! empty( $absent ) ) {
				$missing[ $table ] = $absent;
			}
		}

		return $missing;
	}

	/**
	 * Re-run the schema, at most once an hour (2.8.0, shared since then).
	 *
	 * dbDelta is idempotent, so on a healthy site this is a schema read and
	 * nothing else. The hour is what keeps a database that refuses ALTER from
	 * re-running every CREATE TABLE the plugin owns on every failed write.
	 * The incidents table (AI analysis, since 2.7.2) and the login log (since
	 * 2.8.0) repair through this one gate, so a broken database pays it once
	 * an hour in total, not once per caller.
	 *
	 * @return bool True when the schema was actually re-run.
	 */
	public static function repair_schema_once(): bool {
		if ( get_transient( self::TRANSIENT_SCHEMA_REPAIR ) ) {
			return false;
		}
		set_transient( self::TRANSIENT_SCHEMA_REPAIR, 1, HOUR_IN_SECONDS );

		self::create_tables( false );
		if ( class_exists( ActivityLog\ActivityLog::class, false ) && ActivityLog\ActivityLog::is_enabled() ) {
			ActivityLog\ActivityLog::create_table();
		}

		return true;
	}

	/**
	 * Repair a schema that is short of a column, when nothing else will (2.8.0).
	 *
	 * The two point-of-use repairs only run when a write fails. A site whose
	 * host restored the ALTER privilege, or whose half-restored backup lost a
	 * column on a table that is rarely written, would otherwise stay short of
	 * it. Run from the daily self-heal and from the admin's daily check: one
	 * SHOW COLUMNS per table, and the DDL only when something is missing.
	 */
	public static function self_heal_schema(): void {
		if ( empty( self::missing_schema_columns() ) ) {
			return;
		}
		self::repair_schema_once();
	}

	/**
	 * Load the settings transfer classes (2.6.0). Admin and WP-CLI only:
	 * front-end and cron requests never need them.
	 */
	private static function require_settings_transfer(): void {
		require_once LOGIN_ARMOR_DIR . 'includes/Settings/Sanitizers.php';
		require_once LOGIN_ARMOR_DIR . 'includes/Settings/Registry.php';
		require_once LOGIN_ARMOR_DIR . 'includes/Settings/Exporter.php';
		require_once LOGIN_ARMOR_DIR . 'includes/Settings/Importer.php';
	}

	/**
	 * Set default option values on first activation.
	 */
	private static function set_default_options(): void {
		$defaults = [
			'login_armor_hide_slug'          => '',
			'login_armor_redirect_type'      => 'notfound',
			'login_armor_redirect_url'       => '',
			'login_armor_limit_enabled'      => true,
			'login_armor_allowed_retries'    => 4,
			'login_armor_lockout_duration'   => 20,
			'login_armor_max_lockouts'       => 4,
			'login_armor_long_duration'      => 24,
			'login_armor_valid_duration'     => 24,
			'login_armor_whitelist_ips'      => '',
			'login_armor_notify_email'       => '',
			'login_armor_notify_threshold'   => 5,
			'login_armor_detection_enabled'  => true,
			'login_armor_log_retention_days' => 90,
			'login_armor_auto_purge'         => true,
			'login_armor_logs_auto_purge'    => 90,
			'login_armor_blocked_subnets'    => array(),
			'login_armor_notif_channel'      => 'disabled',
			'login_armor_notif_webhook_url'  => '',
			'login_armor_notif_min_severity' => 2,
			'login_armor_notif_rate_limit'   => 10,
			// The digest clock is deliberately NOT seeded here: add_option()
			// without the third argument lands autoloaded on every request,
			// while every writer of this key passes false, and
			// get_option( ..., 0 ) already yields the right default.
			'login_armor_notif_digest'       => 'off',
			'login_armor_activity_enabled'   => false,
			'login_armor_activity_retention' => 90,
			'login_armor_ip_method'          => 'REMOTE_ADDR',
			'login_armor_trusted_proxies'    => '',
			'login_armor_2fa_enabled'        => false,
			'login_armor_2fa_methods'        => [ 'totp', 'email', 'backup' ],
			'login_armor_2fa_enforce_roles'  => [],
			'login_armor_2fa_grace_days'     => 3,
			// Lot 13: Login Page Security Headers.
			// Default flipped to true in 2.1.1 (audit S-10): CSP, X-Frame-Options,
			// Referrer-Policy etc. on by default for fresh installs, mode=standard
			// (documented as never-breaks-WP-login). Existing installs preserve
			// their stored value automatically because set_default_options() uses
			// add_option() which is a no-op when the option already exists.
			'login_armor_login_headers_enabled'    => true,
			'login_armor_login_headers_mode'       => 'standard',
			'login_armor_login_headers_report_uri' => '',
			// HSTS opt-in: 'off' on existing installs to avoid surprising
			// admins mid-TLS migration. Admin UI surfaces three values:
			// 'off' | 'enabled' (180 days) | 'enabled_subdomains' (1 year + includeSubDomains).
			'login_armor_login_headers_hsts'       => 'off',
			// Lot 21: Breach Check.
			// Email sub-check defaults to false because it transmits real
			// email addresses to XposedOrNot. Admin must opt in explicitly.
			'login_armor_breach_check_enabled'     => false,
			'login_armor_breach_check_passwords'   => true,
			'login_armor_breach_check_emails'      => false,
			'login_armor_breach_check_force_reset' => false,
			// 2.8.0: two options read on every request that a fresh site did
			// not have, so each request queried the database for an absent
			// row. Stored with their defaults, they join the autoload set.
			'login_armor_headers_sitewide'         => false,
			'login_armor_webhook_enabled'          => false,
			// 2.9.0: read on every request by Hardening::get_settings(); stored so it joins the autoload set.
			'login_armor_headless'                 => false,
			// Read on every request authenticated by an application password.
			'login_armor_app_password_watch'       => true,
		];

		foreach ( $defaults as $key => $value ) {
			if ( get_option( $key ) === false ) {
				add_option( $key, $value );
			}
		}
	}

	/**
	 * Provision a new site added to the network.
	 *
	 * Until 2.6.0 this created the tables and the options but scheduled no
	 * event, so a site born after the activation never purged its own logs.
	 * provision_site() is the one definition of a provisioned site.
	 *
	 * Parameter untyped with a guard: `wp_initialize_site` may be re-fired
	 * by site-provisioning plugins with a site ID instead of a WP_Site.
	 *
	 * @param mixed $new_site The new site object (expected WP_Site).
	 */
	public function on_new_site( $new_site = null ): void {
		if ( ! $new_site instanceof \WP_Site ) {
			return;
		}

		switch_to_blog( (int) $new_site->blog_id );
		$active = self::is_plugin_active_here();
		if ( $active ) {
			self::provision_site();
		}
		restore_current_blog();
	}

	/**
	 * Cron callback of the daily digest tick.
	 *
	 * A thin wrapper rather than the class method itself: the Notifications
	 * classes are loaded conditionally, and a cron hook whose callback names a
	 * class the request never loaded is not called at all, silently. Requiring
	 * the files here is what makes the schedule and the code one thing.
	 *
	 * All THREE files, not just Digest: a failed send calls
	 * Dispatcher::store_error(), and the plugin has no autoloader, so loading
	 * only the first one left a fatal in cron behind an unwritten invariant
	 * (it held because maybe_send() returns early on the same condition that
	 * makes Dispatcher present). CLI\Commands::digest() already loads all
	 * three; this now matches it.
	 *
	 * The option is read BEFORE the requires. This tick is permanent and runs
	 * daily on every site whether or not the digest is on, and "an unused
	 * feature costs one option read a day" has to stay true of the code and
	 * not only of the intention. The literal is repeated because the class
	 * that owns it is precisely what has not been loaded yet;
	 * tests/notif-digest.php asserts it matches Digest::OPTION_MODE.
	 *
	 * @since 2.7.0
	 */
	public static function run_notif_digest(): void {
		if ( 'off' === (string) get_option( 'login_armor_notif_digest', 'off' ) ) {
			return;
		}

		require_once LOGIN_ARMOR_DIR . 'includes/Notifications/ChannelInterface.php';
		require_once LOGIN_ARMOR_DIR . 'includes/Notifications/Dispatcher.php';
		require_once LOGIN_ARMOR_DIR . 'includes/Notifications/Digest.php';
		\LoginArmor\Notifications\Digest::maybe_send();
	}

	/**
	 * Cron callback: purge old data if auto-purge is enabled.
	 */
	public static function purge_old_data(): void {
		if ( ! (bool) get_option( 'login_armor_auto_purge', true ) ) {
			return;
		}

		self::do_purge();
	}

	/**
	 * Purge short-lived security coordination rows independently of log retention.
	 *
	 * @return int Total number of deleted option rows.
	 */
	public static function purge_security_counters(): int {
		$deleted  = LimitLogin::purge_claims();
		$deleted += BreachCheck::purge_public_rate_limits();
		$deleted += \LoginArmor\TwoFactor\Recovery::purge_claims();
		$deleted += \LoginArmor\TwoFactor\TwoFactor::purge_rate_counters();
		$deleted += PowChallenge::purge_rate_counters();
		return $deleted;
	}

	/**
	 * Execute the purge logic. Called by cron (via purge_old_data) and manual purge AJAX.
	 *
	 * @param int|null $days Override retention days. Null = use configured option.
	 * @return int Total number of deleted rows.
	 */
	public static function do_purge( ?int $days = null ): int {
		if ( $days === null ) {
			$days = (int) get_option( 'login_armor_log_retention_days',
				(int) get_option( 'login_armor_logs_auto_purge', 90 )
			);
		}
		if ( $days <= 0 ) {
			return 0;
		}

		global $wpdb;
		$cutoff  = gmdate( 'Y-m-d H:i:s', time() - $days * DAY_IN_SECONDS );
		$deleted = 0;

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Custom plugin tables, retention-based cleanup, no caching layer needed.
		$deleted += (int) $wpdb->query(
			$wpdb->prepare(
				"DELETE FROM {$wpdb->prefix}login_armor_logs WHERE log_time < %s",
				$cutoff
			)
		);

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Custom plugin tables, retention-based cleanup, no caching layer needed.
		$deleted += (int) $wpdb->query(
			$wpdb->prepare(
				"DELETE FROM {$wpdb->prefix}login_armor_attempts WHERE attempt_time < %s",
				$cutoff
			)
		);

		// Purge resolved/ignored incidents if the table exists.
		$incidents_table = $wpdb->prefix . 'login_armor_incidents';
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
		if ( $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $incidents_table ) ) === $incidents_table ) {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
			$deleted += (int) $wpdb->query(
				$wpdb->prepare(
					"DELETE FROM {$wpdb->prefix}login_armor_incidents WHERE status IN ('resolved','ignored') AND last_seen_at < %s",
					$cutoff
				)
			);

			// V2.4.2: incidents left open forever must not grow the table
			// without bound: anything not seen for twice the retention window
			// is deleted regardless of status.
			$stale_cutoff = gmdate( 'Y-m-d H:i:s', time() - 2 * $days * DAY_IN_SECONDS );
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
			$deleted += (int) $wpdb->query(
				$wpdb->prepare(
					"DELETE FROM {$wpdb->prefix}login_armor_incidents WHERE last_seen_at < %s",
					$stale_cutoff
				)
			);
		}

		$deleted += self::purge_security_counters();

		// 2.9.0: application-password usage rows past the retention, and the
		// rows of passwords that no longer exist.
		if ( class_exists( AppPasswords\Usage::class ) ) {
			$deleted += AppPasswords\Usage::purge( $cutoff );
		}

		return $deleted;
	}

	/**
	 * Add Settings link in the plugins list.
	 *
	 * @param array<string> $links Existing action links.
	 * @return array<string>
	 */
	public function add_action_links( $links = array() ) {
		// Untyped defensively: unexpected values pass through untouched.
		if ( ! is_array( $links ) ) {
			return $links;
		}
		$settings_link = sprintf(
			'<a href="%s">%s</a>',
			esc_url( admin_url( 'admin.php?page=login-armor' ) ),
			esc_html__( 'Settings', 'login-armor' )
		);
		array_unshift( $links, $settings_link );
		return $links;
	}

	/**
	 * Send a fully-buffered body to the browser and terminate cleanly.
	 *
	 * The two non-obvious bits of this function are:
	 *
	 * 1. Discard every active output buffer FIRST. The helper is invoked from
	 *    a deep stack when called via `LockoutPage::render_on_trigger` (which
	 *    fires inside `wp_login_failed` inside `wp_authenticate` inside
	 *    `wp_signon` inside wp-login.php). On managed hosts, PHP's
	 *    `output_buffering=4096` auto-opens a default buffer at request start.
	 *    Without `ob_end_clean()`, our `echo $body` lands in that parent buffer
	 *    and gets mixed with whatever wp-login.php / login_init / theme plugins
	 *    have already buffered. Killing the buffers makes our body the only
	 *    thing the SAPI sees.
	 *
	 * 2. Call `fastcgi_finish_request()` after the body. NOT optional: without
	 *    it, PHP shutdown handlers (`shutdown` action subscribers from any
	 *    plugin, the wpdb close routine, etc.) run AFTER our `exit` and may
	 *    write additional bytes to the SAPI output stream. Those extra bytes
	 *    don't break HTTP/1.1 because the connection-close framing tolerates
	 *    extra trailing data (and curl just ignores it past Content-Length).
	 *    Under HTTP/2, the stream is supposed to terminate at exactly
	 *    Content-Length bytes; extra bytes after the announced length make the
	 *    browser wait forever for the "rest" of the body that never comes:
	 *    Firefox hangs on "Loading…", Chromium falls back to its built-in 429
	 *    page after timing out. `fastcgi_finish_request()` commits the request
	 *    BEFORE shutdown runs, so any post-exit output goes to /dev/null.
	 *    This was incorrectly removed in 2.0.3 and the regression was
	 *    immediately reproduced via curl: POST that crosses the lockout
	 *    threshold returned the regular wp-login form (200) instead of the
	 *    branded 429 page, because the body announced via Content-Length never
	 *    reached the wire intact. Restored in 2.0.4.
	 *
	 * Caller MUST have already called `status_header()` and any other custom
	 * headers (cache-control, content-type, etc.).
	 *
	 * @param string $body Raw response body. Caller is responsible for escaping.
	 * @return never
	 */
	public static function flush_response_and_exit( string $body ): void {
		// Discard every active output buffer so our body is the only thing the
		// SAPI receives. Same pattern as WordPress core's wp_die handler.
		while ( ob_get_level() > 0 ) {
			// phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- No-op when buffer cannot be cleaned.
			@ob_end_clean();
		}

		header( 'Content-Length: ' . strlen( $body ) );
		echo $body; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- $body is caller-escaped.

		// Commit the FastCGI request so the body is on the wire before
		// shutdown work runs. Reaches END_STREAM on standard FPM under both
		// HTTP/1.1 and HTTP/2.
		if ( function_exists( 'fastcgi_finish_request' ) ) {
			fastcgi_finish_request();
		} else {
			flush();
		}

		exit;
	}

	/**
	 * Normalize a trusted-proxy allowlist.
	 *
	 * Entries accept one exact IPv4/IPv6 address or CIDR per line. A /0 is
	 * rejected because it would make every internet host a trusted proxy and
	 * recreate the forwarding-header spoofing vulnerability this list closes.
	 */
	public static function normalize_trusted_proxies( string $raw ): string {
		$entries = preg_split( '/[\r\n,]+/', $raw );
		if ( ! is_array( $entries ) ) {
			return '';
		}

		$valid = array();
		foreach ( $entries as $entry ) {
			$entry = trim( $entry );
			if ( '' === $entry ) {
				continue;
			}
			if ( false === strpos( $entry, '/' ) ) {
				if ( filter_var( $entry, FILTER_VALIDATE_IP ) ) {
					$valid[] = $entry;
				}
				continue;
			}

			list( $subnet, $bits_raw ) = array_pad( explode( '/', $entry, 2 ), 2, '' );
			$subnet                   = trim( $subnet );
			$bits_raw                 = trim( $bits_raw );
			$packed                   = @inet_pton( $subnet ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Invalid admin input is discarded below.
			if ( false === $packed || ! ctype_digit( $bits_raw ) ) {
				continue;
			}
			$bits     = (int) $bits_raw;
			$max_bits = strlen( $packed ) * 8;
			if ( $bits <= 0 || $bits > $max_bits ) {
				continue;
			}
			$valid[] = $subnet . '/' . $bits;
		}

		return implode( "\n", array_values( array_unique( $valid ) ) );
	}

	/**
	 * Match an IP against an exact address or CIDR allowlist entry.
	 *
	 * @since 2.6.0 Public: the settings importer reuses it to refuse a
	 *              blocked-subnets list that would lock the importer out.
	 */
	public static function ip_matches_proxy_entry( string $ip, string $entry ): bool {
		if ( '' === $entry ) {
			return false;
		}
		if ( false === strpos( $entry, '/' ) ) {
			$ip_packed    = @inet_pton( $ip );    // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Invalid request input fails closed.
			$entry_packed = @inet_pton( $entry ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Normalized admin input, defensive guard below.
			return false !== $ip_packed
				&& false !== $entry_packed
				&& strlen( $ip_packed ) === strlen( $entry_packed )
				&& hash_equals( $entry_packed, $ip_packed );
		}

		list( $subnet, $bits_raw ) = array_pad( explode( '/', $entry, 2 ), 2, '' );
		$ip_packed                 = @inet_pton( $ip );     // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Invalid request input fails closed.
		$subnet_packed             = @inet_pton( $subnet ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Normalized admin input, defensive guard below.
		if ( false === $ip_packed || false === $subnet_packed || strlen( $ip_packed ) !== strlen( $subnet_packed ) ) {
			return false;
		}

		$bits = (int) $bits_raw;
		if ( $bits <= 0 || $bits > strlen( $ip_packed ) * 8 ) {
			return false;
		}
		$whole_bytes = intdiv( $bits, 8 );
		$rem_bits    = $bits % 8;
		if ( $whole_bytes > 0 && substr( $ip_packed, 0, $whole_bytes ) !== substr( $subnet_packed, 0, $whole_bytes ) ) {
			return false;
		}
		if ( 0 === $rem_bits ) {
			return true;
		}
		$mask = 0xff << ( 8 - $rem_bits ) & 0xff;
		return ( ord( $ip_packed[ $whole_bytes ] ) & $mask ) === ( ord( $subnet_packed[ $whole_bytes ] ) & $mask );
	}

	/**
	 * Whether an address is an explicitly trusted immediate proxy.
	 *
	 * @param string   $ip      Candidate proxy IP.
	 * @param string[] $entries Normalized exact IP/CIDR entries.
	 */
	private static function is_trusted_proxy( string $ip, array $entries ): bool {
		foreach ( $entries as $entry ) {
			if ( self::ip_matches_proxy_entry( $ip, $entry ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Forwarded loopback/unspecified addresses can never be real remote clients.
	 */
	private static function is_safe_forwarded_client( string $ip ): bool {
		return self::is_reliable_client_ip( $ip );
	}

	/**
	 * Normalize an IP token received from a proxy header.
	 *
	 * Some proxies append the source port to IPv4 addresses and use bracketed
	 * IPv6 literals with a port. The port is transport metadata, not part of the
	 * client identity. Unbracketed IPv6 remains untouched so its final hextet is
	 * never mistaken for a port.
	 */
	private static function normalize_forwarded_ip( string $candidate ): string {
		$candidate = trim( $candidate );
		if ( preg_match( '/^\[([^\]]+)\](?::([0-9]{1,5}))?$/', $candidate, $matches ) ) {
			if ( isset( $matches[2] ) && (int) $matches[2] > 65535 ) {
				return '';
			}
			$candidate = $matches[1];
		} elseif ( preg_match( '/^((?:[0-9]{1,3}\.){3}[0-9]{1,3}):([0-9]{1,5})$/', $candidate, $matches ) ) {
			if ( (int) $matches[2] > 65535 ) {
				return '';
			}
			$candidate = $matches[1];
		}

		$packed = @inet_pton( $candidate ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Invalid request input is rejected below.
		return false === $packed ? '' : (string) inet_ntop( $packed );
	}

	/**
	 * Whether an IP can safely identify one client for sanctions or quotas.
	 *
	 * Activity logging may retain UNKNOWN_CLIENT_IP, but lockouts and counters
	 * must ignore the unknown and loopback identities that cannot distinguish a
	 * remote client. get_client_ip() keeps a peer outside the declared proxy
	 * list as a direct client, but marks a declared shared proxy unreliable when
	 * its forwarding data cannot identify one visitor.
	 */
	public static function is_reliable_client_ip( string $ip ): bool {
		if ( '' === $ip || self::UNKNOWN_CLIENT_IP === $ip || false === filter_var( $ip, FILTER_VALIDATE_IP ) ) {
			return false;
		}
		$packed = inet_pton( $ip );
		if ( false === $packed || $packed === inet_pton( '::' ) || $packed === inet_pton( '::1' ) ) {
			return false;
		}
		if ( 4 === strlen( $packed ) ) {
			return 127 !== ord( $packed[0] );
		}
		// IPv4-mapped IPv6 loopback, for example ::ffff:127.0.0.1.
		$mapped_prefix = str_repeat( "\0", 10 ) . "\xff\xff";
		return ! ( str_starts_with( $packed, $mapped_prefix ) && 127 === ord( $packed[12] ) );
	}

	/**
	 * Clear the request-scoped identity cache after an in-request settings edit.
	 */
	public static function reset_client_ip_cache(): void {
		self::$client_ip_cache = null;
	}

	/**
	 * Cache an unusable identity reported by an explicitly trusted proxy.
	 *
	 * The TCP peer is shared infrastructure in this branch, not a visitor. It
	 * must therefore never drive a lockout or security quota. The transient
	 * surfaces the configuration problem to administrators without writing on
	 * every request while the warning is already pending.
	 */
	private static function cache_unreliable_proxy_identity(): string {
		self::$client_ip_cache = self::UNKNOWN_CLIENT_IP;
		if ( false === get_transient( 'login_armor_ip_method_misconfigured' ) ) {
			set_transient( 'login_armor_ip_method_misconfigured', time(), DAY_IN_SECONDS );
		}
		return self::$client_ip_cache;
	}

	/**
	 * Core's own rule for a boolean that arrived as text.
	 *
	 * Same semantics as rest_sanitize_boolean(): any string is true except
	 * "false" and "0" (and the empty string, which is falsy anyway).
	 *
	 * It lives here, and not next to the one module that first needed it,
	 * because `(bool) $stored` is wrong for EVERY boolean option this plugin
	 * reads back, not just for a hardening toggle. WP-CLI stores what the
	 * shell handed it: `wp option update login_armor_2fa_enabled false`
	 * writes the STRING "false", and `(bool) "false"` is true. Every reader
	 * of a stored boolean goes through here.
	 *
	 * @since 2.7.0
	 *
	 * @param mixed $value Stored value.
	 */
	public static function to_bool( $value ): bool {
		if ( is_string( $value ) ) {
			$value = strtolower( trim( $value ) );
			if ( 'false' === $value || '0' === $value ) {
				return false;
			}
		}

		return (bool) $value;
	}

	/**
	 * The explicitly trusted proxy entries: normalized, filter applied.
	 *
	 * One resolver for the two readers below, so get_client_ip() and
	 * peer_is_trusted_proxy() can never disagree on who the proxies are.
	 *
	 * @since 2.7.0
	 *
	 * @return string[] Exact IP/CIDR entries; empty when nothing is declared.
	 */
	private static function trusted_proxy_entries(): array {
		$raw_trusted = (string) get_option( 'login_armor_trusted_proxies', '' );
		/**
		 * Filters the trusted proxy IP/CIDR list after admin normalization.
		 *
		 * @param string $raw_trusted Newline-separated exact IP/CIDR entries.
		 */
		$raw_trusted = (string) apply_filters( 'login_armor_trusted_proxies', $raw_trusted );
		$normalized  = self::normalize_trusted_proxies( $raw_trusted );

		return '' === $normalized ? array() : explode( "\n", $normalized );
	}

	/**
	 * Whether the immediate network peer is an explicitly trusted proxy.
	 *
	 * Deliberately independent of `login_armor_ip_method`: that option says
	 * which header carries the client IDENTITY, and a site can sit behind a
	 * terminator it trusts for the PROTOCOL while leaving the identity on
	 * REMOTE_ADDR. The trusted list is the single decision that says "this
	 * peer's forwarding headers are ours", and it gates request_is_https()
	 * exactly as it gates the identity resolution below.
	 *
	 * @since 2.7.0
	 */
	public static function peer_is_trusted_proxy(): bool {
		$peer_raw = isset( $_SERVER['REMOTE_ADDR'] )
			? sanitize_text_field( wp_unslash( (string) $_SERVER['REMOTE_ADDR'] ) )
			: '';
		$peer     = self::normalize_forwarded_ip( $peer_raw );
		if ( '' === $peer ) {
			return false;
		}

		$trusted = self::trusted_proxy_entries();

		return ! empty( $trusted ) && self::is_trusted_proxy( $peer, $trusted );
	}

	/**
	 * One forwarding header, read the way every other request input is read.
	 *
	 * @since 2.7.0
	 */
	private static function forwarded_header( string $key ): string {
		if ( empty( $_SERVER[ $key ] ) ) {
			return '';
		}

		return trim( sanitize_text_field( wp_unslash( (string) $_SERVER[ $key ] ) ) );
	}

	/**
	 * Whether SOMETHING upstream says the original client spoke https.
	 *
	 * Says nothing about whether that claim may be believed: that is
	 * peer_is_trusted_proxy()'s job, and request_is_https() is where the two
	 * meet. This answer is also used on its own, by the loop guard, precisely
	 * in the case where the claim may NOT be believed.
	 *
	 * Five shapes, because a terminator that cannot be recognised is a site
	 * that loops:
	 *
	 *   X-Forwarded-Proto     a chain, like X-Forwarded-For: the LEFTMOST
	 *   X-Forwarded-Protocol  value is the protocol the ORIGINAL client
	 *                         spoke, and that is the one that decides
	 *   X-Forwarded-Ssl       on/off (Microsoft, and several load balancers)
	 *   Front-End-Https       on/off (IIS ARR, Exchange)
	 *   CF-Visitor            Cloudflare, JSON: {"scheme":"https"}
	 *
	 * The order is a precedence, not a search for a "yes": the first header
	 * present decides, so a terminator that reports `X-Forwarded-Proto: http`
	 * is believed to mean http even if a stale CF-Visitor also sits there.
	 *
	 * @since 2.7.0
	 */
	public static function forwarded_proto_is_https(): bool {
		foreach ( array( 'HTTP_X_FORWARDED_PROTO', 'HTTP_X_FORWARDED_PROTOCOL' ) as $key ) {
			$value = self::forwarded_header( $key );
			if ( '' !== $value ) {
				$chain = explode( ',', $value );

				return 'https' === strtolower( trim( (string) $chain[0] ) );
			}
		}

		foreach ( array( 'HTTP_X_FORWARDED_SSL', 'HTTP_FRONT_END_HTTPS' ) as $key ) {
			$value = strtolower( self::forwarded_header( $key ) );
			if ( '' !== $value ) {
				return 'on' === $value || '1' === $value;
			}
		}

		$visitor = self::forwarded_header( 'HTTP_CF_VISITOR' );
		if ( '' !== $visitor ) {
			$decoded = json_decode( $visitor, true );

			return is_array( $decoded ) && 'https' === strtolower( trim( (string) ( $decoded['scheme'] ?? '' ) ) );
		}

		return false;
	}

	/**
	 * Whether this request really reached the site over TLS.
	 *
	 * is_ssl() alone is blind behind a terminator: PHP sees a plain HTTP
	 * connection coming from the proxy. The forwarded protocol fills that gap,
	 * but ONLY when the peer that sent it is on the trusted-proxy list. A
	 * forged `X-Forwarded-Proto: https` sent straight to the backend is
	 * indistinguishable from the genuine one at the PHP layer, which is
	 * precisely what tests/ci/tls.sh measures: the decision belongs to the
	 * plugin, never to the header.
	 *
	 * @since 2.7.0
	 */
	public static function request_is_https(): bool {
		if ( is_ssl() ) {
			return true;
		}

		return self::forwarded_proto_is_https() && self::peer_is_trusted_proxy();
	}

	/**
	 * The one sentence that describes a proxy header nobody vouches for.
	 *
	 * Written once, read twice: `Settings\Importer` warns about it when a
	 * settings file arrives in that state, and the Site Health test reports it
	 * when the site is already in it. Two copies of this sentence would drift,
	 * and the copy nobody reads is the one that stays wrong.
	 *
	 * No trailing punctuation: the importer appends it to a list of issues,
	 * Site Health ends a sentence with it.
	 *
	 * @since 2.7.0
	 *
	 * @param string $method The configured `login_armor_ip_method` value.
	 * @return string Translated, unescaped.
	 */
	/**
	 * Forget the proof that a test alert arrived, when the destination moves.
	 *
	 * `login_armor_notif_last_test_ok` says one thing and one thing only: an
	 * alert was delivered, once, to the destination configured at that moment.
	 * Point the alerts somewhere else and it stops being a fact about this
	 * site, so the Site Health test must go back to asking for a test.
	 *
	 * Four writers repoint that destination and every one of them calls this:
	 * the Notifications form, the two one-click toggles beside it, and a
	 * settings import, which is the one that matters on a fleet, because both
	 * fields are exportable and a file can repoint sixty sites at once.
	 *
	 * The webhook field is part of the destination, not a detail of it: a
	 * Slack workspace swapped for another is as new a destination as a new
	 * channel, and for the e-mail channel that field IS the recipient.
	 *
	 * @since 2.7.0
	 *
	 * @param string $channel Channel about to be stored.
	 * @param string $url     Webhook field about to be stored.
	 * @return bool True when the proof was dropped.
	 */
	public static function forget_notification_test_if_moved( string $channel, string $url ): bool {
		$previous_channel = (string) get_option( 'login_armor_notif_channel', 'disabled' );
		$previous_url     = (string) get_option( 'login_armor_notif_webhook_url', '' );

		if ( $previous_channel === $channel && $previous_url === $url ) {
			return false;
		}

		delete_option( 'login_armor_notif_last_test_ok' );

		return true;
	}

	/**
	 * The e-mail channel with an empty recipient field follows `admin_email`.
	 *
	 * That is the one way the destination can move without either field this
	 * plugin compares changing, and it moves through a screen and a WP-CLI
	 * command that have nothing to do with Login Armor. The hook is registered
	 * unconditionally, so a fleet run of `wp option update admin_email` is
	 * covered exactly like the Settings screen is.
	 *
	 * Untyped with defaults: `update_option_{$option}` is a core hook.
	 *
	 * @since 2.7.0
	 *
	 * @param mixed $old_value Previous administrator address.
	 * @param mixed $value     New administrator address.
	 * @param mixed $option    Option name.
	 */
	public static function forget_notification_test_on_admin_email( $old_value = null, $value = null, $option = null ) {
		unset( $old_value, $value, $option );

		if ( 'email' !== (string) get_option( 'login_armor_notif_channel', 'disabled' ) ) {
			return;
		}
		// A recipient was typed in, so the alerts do not follow this address.
		if ( '' !== (string) get_option( 'login_armor_notif_webhook_url', '' ) ) {
			return;
		}

		delete_option( 'login_armor_notif_last_test_ok' );
	}

	public static function proxy_identity_warning( string $method ): string {
		return sprintf(
			/* translators: %s: IP method name */
			__( '%s is read from a proxy header but no trusted proxies are listed: lockouts stay paused until you add your proxy addresses', 'login-armor' ),
			$method
		);
	}

	/**
	 * Get the real client IP address without trusting attacker-controlled headers.
	 *
	 * Forwarding headers are accepted only when the immediate network peer
	 * (REMOTE_ADDR) matches the explicit trusted-proxy allowlist. X-Forwarded-For
	 * is walked from right to left: trusted hops are removed until the nearest
	 * untrusted client is found. Attacker-controlled values farther left are not
	 * parsed once that boundary is found. A peer outside the declared proxy list
	 * is a direct client and remains sanctionable. A peer inside that list is
	 * shared infrastructure, so missing or unusable forwarding data returns an
	 * explicitly unreliable identity instead of locking every visitor.
	 */
	public static function get_client_ip(): string {
		if ( null !== self::$client_ip_cache ) {
			return self::$client_ip_cache;
		}

		$peer_raw = isset( $_SERVER['REMOTE_ADDR'] )
			? sanitize_text_field( wp_unslash( (string) $_SERVER['REMOTE_ADDR'] ) )
			: '';
		$peer     = self::normalize_forwarded_ip( $peer_raw );
		if ( '' === $peer ) {
			self::$client_ip_cache = self::UNKNOWN_CLIENT_IP;
			return self::$client_ip_cache;
		}

		$method  = (string) get_option( 'login_armor_ip_method', 'REMOTE_ADDR' );
		$allowed = array( 'HTTP_CF_CONNECTING_IP', 'HTTP_X_FORWARDED_FOR', 'HTTP_X_REAL_IP' );
		if ( ! in_array( $method, $allowed, true ) ) {
			self::$client_ip_cache = $peer;
			return self::$client_ip_cache;
		}

		$trusted = self::trusted_proxy_entries();
		if ( empty( $trusted ) || ! self::is_trusted_proxy( $peer, $trusted ) ) {
			self::$client_ip_cache = $peer;
			return self::$client_ip_cache;
		}

		if ( empty( $_SERVER[ $method ] ) ) {
			return self::cache_unreliable_proxy_identity();
		}
		// Not sanitize_text_field() on the whole header: it returns '' for the
		// entire value when ONE byte is not valid UTF-8, so a client putting
		// such a byte in the part of X-Forwarded-For it controls erased the
		// address the trusted proxy appended, and every visitor behind that
		// proxy fell back to the unreliable identity, which lockouts ignore.
		// Each element is checked on its own below, and normalize_forwarded_ip()
		// keeps nothing but what inet_pton() accepts.
		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Every element is reduced to an inet_pton()/inet_ntop() round trip or rejected.
		$raw_header = (string) wp_unslash( (string) $_SERVER[ $method ] );

		if ( 'HTTP_X_FORWARDED_FOR' !== $method ) {
			$candidate             = self::normalize_forwarded_ip( $raw_header );
			if ( ! self::is_safe_forwarded_client( $candidate ) ) {
				return self::cache_unreliable_proxy_identity();
			}
			self::$client_ip_cache = $candidate;
			return self::$client_ip_cache;
		}

		$chain = explode( ',', $raw_header );
		for ( $index = count( $chain ) - 1; $index >= 0; --$index ) {
			$candidate = self::normalize_forwarded_ip( $chain[ $index ] );
			if ( '' === $candidate ) {
				return self::cache_unreliable_proxy_identity();
			}
			if ( self::is_trusted_proxy( $candidate, $trusted ) ) {
				continue;
			}
			if ( ! self::is_safe_forwarded_client( $candidate ) ) {
				return self::cache_unreliable_proxy_identity();
			}
			self::$client_ip_cache = $candidate;
			return self::$client_ip_cache;
		}

		return self::cache_unreliable_proxy_identity();
	}
}
