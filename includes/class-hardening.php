<?php
/**
 * Hardening module.
 *
 * Provides opt-in security hardening toggles stored in a single option array.
 * All toggles are off by default; zero overhead when nothing is enabled.
 *
 * @package LoginArmor
 * @since   2.0.0
 */

namespace LoginArmor;

use LoginArmor\Hardening\Honeypot;
use LoginArmor\Hardening\UsernameBlacklist;

// Exit if accessed directly.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Handles security hardening toggles.
 */
class Hardening {

	public const OPTION_KEY = 'login_armor_hardening';

	/**
	 * Admin-defined REST namespaces that stay public when `restrict_rest_api` is on.
	 *
	 * Stored outside OPTION_KEY (which only ever holds booleans), like the
	 * reserved-usernames blacklist.
	 *
	 * @since 2.5.1
	 */
	public const OPTION_REST_NAMESPACES = 'login_armor_hardening_rest_namespaces';

	/**
	 * REST namespaces kept public out of the box, whatever the admin types.
	 *
	 * @since 2.5.1
	 *
	 * @var string[]
	 */
	public const DEFAULT_REST_NAMESPACES = [ 'oembed/', 'contact-form-7/', 'wp-site-health/' ];

	/** @var int Upper bound on stored namespaces - a guard against a pasted file. */
	private const MAX_REST_NAMESPACES = 50;

	// ------------------------------------------------------------------
	// .htaccess block discipline (2.6.1)
	//
	// The marker lines carry an em dash. They are spelled here with a
	// `\u{2014}` escape so the source file itself stays free of the
	// character, while the bytes written to disk are exactly the ones
	// 2.6.0 and earlier wrote: a file produced by an older release must
	// still be recognised, and its block replaced rather than duplicated.
	// ------------------------------------------------------------------

	/** @var string BEGIN marker of the uploads PHP-block. */
	public const MARKER_UPLOADS_BEGIN = "# BEGIN LoginArmor \u{2014} Block PHP execution";

	/** @var string END marker of the uploads PHP-block. */
	public const MARKER_UPLOADS_END = "# END LoginArmor \u{2014} Block PHP execution";

	/** @var string BEGIN marker of the root directory-listing block. */
	public const MARKER_INDEXES_BEGIN = "# BEGIN LoginArmor \u{2014} Disable directory listing";

	/** @var string END marker of the root directory-listing block. */
	public const MARKER_INDEXES_END = "# END LoginArmor \u{2014} Disable directory listing";

	/** @var string BEGIN marker of the root system-files block (2.8.0). */
	public const MARKER_SYSFILES_BEGIN = '# BEGIN LoginArmor system files';

	/** @var string END marker of the root system-files block (2.8.0). */
	public const MARKER_SYSFILES_END = '# END LoginArmor system files';

	/** @var string BEGIN marker of the root rule refusing PHP under uploads (2.8.1). */
	public const MARKER_UPLOADS_ROOT_BEGIN = '# BEGIN LoginArmor uploads PHP';

	/** @var string END marker of the root rule refusing PHP under uploads (2.8.1). */
	public const MARKER_UPLOADS_ROOT_END = '# END LoginArmor uploads PHP';

	/** @var string find_marked_block(): no marker at all, the block can be appended. */
	public const BLOCK_ABSENT = 'absent';

	/** @var string find_marked_block(): exactly one BEGIN followed by exactly one END. */
	public const BLOCK_COMPLETE = 'complete';

	/** @var string find_marked_block(): the block cannot be delimited, so it is left alone. */
	public const BLOCK_AMBIGUOUS = 'ambiguous';

	/**
	 * Suffix of the one-shot backup.
	 *
	 * Appended to the .htaccess path, so the file is named
	 * `.htaccess.login-armor.bak`: it still starts with `.ht`, which both
	 * Apache and LiteSpeed deny serving out of the box.
	 *
	 * @var string
	 */
	public const HTACCESS_BACKUP_SUFFIX = '.login-armor.bak';

	/**
	 * Suffix of the advisory lock file.
	 *
	 * Also `.ht`-prefixed once appended. The file is deliberately left on
	 * disk after the lock is released: removing it would race a second
	 * process that has just opened it, and an empty `.htaccess.*.lock` is
	 * harmless.
	 *
	 * @var string
	 */
	public const HTACCESS_LOCK_SUFFIX = '.login-armor.lock';

	/** @var string Transient naming the file whose write failed (I/O). */
	public const TRANSIENT_HTACCESS_FAILED = 'login_armor_htaccess_write_failed';

	/** @var string Transient naming the file whose block could not be delimited. */
	public const TRANSIENT_HTACCESS_AMBIGUOUS = 'login_armor_htaccess_ambiguous';

	/**
	 * @var string Option holding the LAST .htaccess failure, durably.
	 *
	 * The two transients above live five minutes, which is right for an admin
	 * notice and useless for Tools > Site Health: that screen is opened days
	 * later, once something has gone wrong, and a transient would have told it
	 * nothing. Shape: array{path:string,kind:string,time:int}, autoload off.
	 * Cleared by the first sync_htaccess() that completes without a failure.
	 *
	 * @since 2.7.0
	 */
	public const OPTION_HTACCESS_LAST_FAILURE = 'login_armor_htaccess_last_failure';

	/**
	 * Every reason a write can be refused, as the code that refused it knows.
	 *
	 * 2.7.1. Before this list the nine call sites all recorded `write`, so the
	 * screen could only ever offer one explanation, and it offered the wrong
	 * one for most of them: a lock held by a concurrent save was reported as a
	 * permissions problem on a file whose permissions were correct.
	 *
	 * `write` stays in the list as the fallback for a site that forgets to
	 * name itself, so a new gate still raises something rather than nothing.
	 *
	 * @since 2.7.1
	 */
	public const KNOWN_HTACCESS_FAILURES = array(
		'backup',
		'lock_open',
		'lock_busy',
		'read',
		'partial_write',
		'rename',
		'unlink',
		'ambiguous',
		'no_rewrite',
		'write',
	);

	/**
	 * @var int Failures recorded in THIS request.
	 *
	 * sync_htaccess() clears the durable record only when its own writers
	 * recorded nothing, and the writers return void on two of the four paths.
	 * Counting is the only way to tell a clean run from a silent one without
	 * re-reading the option, which a concurrent request may have just written.
	 *
	 * @since 2.7.0
	 */
	private static int $htaccess_failures = 0;

	/**
	 * Test seam: byte count the next write reports instead of the real one.
	 *
	 * A partial write is the one failure mode that cannot be provoked from a
	 * test without filling the volume, and it is the dangerous one: a short
	 * `file_put_contents()` returns a number, not false, so a truncated temp
	 * file would be renamed over a working .htaccess. Honoured only while
	 * LOGIN_ARMOR_TESTING is defined, so it can never alter a site.
	 *
	 * @var int|null
	 */
	private static ?int $write_bytes_override = null;

	/**
	 * Default values for all toggles (all off).
	 *
	 * @var array<string, bool>
	 */
	private const DEFAULTS = [
		'disable_xmlrpc'           => false,
		'disable_file_editor'      => false,
		'hide_wp_version'          => false,
		'mask_login_errors'        => false,
		'disable_app_passwords'    => false,
		'block_php_uploads'        => false,
		'prevent_author_enum'      => false,
		'obfuscate_author_slugs'   => false,
		'restrict_rest_api'        => false,
		'protect_system_files'     => false,
		'disable_directory_listing' => false,
		'block_reserved_usernames' => false,
		'login_honeypot'           => false,
		'disable_pingbacks'        => false,
		'alert_admin_creation'     => false,
		'force_https'              => false,
	];

	/** @var array<string, bool> Resolved settings for this request. */
	private array $settings;

	/**
	 * Constructor. Registers hooks only for enabled features.
	 */
	public function __construct() {
		$this->settings = self::get_settings();

		// Bail early when every toggle is off: zero overhead.
		if ( ! in_array( true, $this->settings, true ) ) {
			return;
		}

		if ( ! empty( $this->settings['disable_xmlrpc'] ) ) {
			$this->register_disable_xmlrpc();
		}

		if ( ! empty( $this->settings['disable_file_editor'] ) ) {
			$this->register_disable_file_editor();
		}

		if ( ! empty( $this->settings['hide_wp_version'] ) ) {
			$this->register_hide_wp_version();
		}

		if ( ! empty( $this->settings['mask_login_errors'] ) ) {
			$this->register_mask_login_errors();
		}

		if ( ! empty( $this->settings['disable_app_passwords'] ) ) {
			$this->register_disable_app_passwords();
		}

		if ( ! empty( $this->settings['block_php_uploads'] ) ) {
			$this->register_block_php_uploads();
		}

		if ( ! empty( $this->settings['prevent_author_enum'] ) ) {
			$this->register_prevent_author_enum();
		}

		if ( ! empty( $this->settings['obfuscate_author_slugs'] ) ) {
			$this->register_obfuscate_author_slugs();
		}

		if ( ! empty( $this->settings['restrict_rest_api'] ) ) {
			$this->register_restrict_rest_api();
		}

		if ( ! empty( $this->settings['protect_system_files'] ) ) {
			$this->register_protect_system_files();
		}

		if ( ! empty( $this->settings['disable_directory_listing'] ) ) {
			$this->register_disable_directory_listing();
		}

		if ( ! empty( $this->settings['block_reserved_usernames'] ) ) {
			UsernameBlacklist::register();
		}

		if ( ! empty( $this->settings['login_honeypot'] ) ) {
			Honeypot::register();
		}

		if ( ! empty( $this->settings['disable_pingbacks'] ) ) {
			$this->register_disable_pingbacks();
		}

		if ( ! empty( $this->settings['alert_admin_creation'] ) ) {
			$this->register_alert_admin_creation();
		}

		if ( ! empty( $this->settings['force_https'] ) ) {
			$this->register_force_https();
		}
	}

	/**
	 * Get the current hardening settings, merged with defaults.
	 *
	 * Ensures that newly added toggle keys always have a value.
	 *
	 * @return array<string, bool>
	 */
	public static function get_settings(): array {
		$stored = get_option( self::OPTION_KEY, [] );

		if ( ! is_array( $stored ) ) {
			$stored = [];
		}

		$settings = array_merge( self::DEFAULTS, $stored );

		// 2.7.0: every value comes back a real boolean, whoever wrote it.
		// save_settings() casts, but it is not the only writer: WP-CLI stores
		// what the shell handed it, so `wp option patch update
		// login_armor_hardening force_https false` writes the STRING "false".
		// Two things went wrong with that string, and they cancelled each
		// other out in a way that looked like the feature simply not working:
		// `! empty( "false" )` is TRUE, so the toggle read as ON; and the
		// constructor's `in_array( true, $settings, true )` bail is STRICT,
		// so a module whose only enabled toggle held a string registered
		// nothing at all. The documented way out of Force HTTPS goes through
		// exactly that command, so it has to mean what an administrator
		// typed.
		foreach ( $settings as $key => $value ) {
			$settings[ $key ] = LoginArmor::to_bool( $value );
		}

		// 2.9.0: headless mode keeps the two toggles that break a headless back
		// end off. Masked here because this is what every reader goes through,
		// the export included. class_exists() without autoload: uninstall.php
		// loads this file alone, and there the mode has nothing to guard.
		if ( class_exists( Headless::class, false ) && Headless::is_enabled() ) {
			foreach ( Headless::GUARDED_TOGGLES as $key ) {
				$settings[ $key ] = false;
			}
		}

		return $settings;
	}

	/**
	 * Sanitize and save hardening settings.
	 *
	 * Only known keys are persisted; every value is cast to bool.
	 *
	 * @param array<string, mixed> $input Raw input from the settings form.
	 */
	public static function save_settings( array $input ): void {
		$clean = [];

		foreach ( self::DEFAULTS as $key => $default ) {
			$clean[ $key ] = ! empty( $input[ $key ] );
		}

		// 2.8.0: autoloaded. This option is read on every front-end request, so
		// leaving it out of the autoload set cost one query on each of them.
		update_option( self::OPTION_KEY, $clean, true );
	}

	/**
	 * Return toggle definitions for the admin view.
	 *
	 * Each entry contains:
	 *   - key         (string) Option array key.
	 *   - label       (string) Short label, translatable.
	 *   - description (string) Helper text, translatable.
	 *
	 * @return array<int, array{key: string, label: string, description: string}>
	 */
	public static function get_toggles(): array {
		return [
			[
				'key'         => 'disable_xmlrpc',
				'label'       => __( 'Disable XML-RPC', 'login-armor' ),
				'description' => __( 'Block XML-RPC requests (keep off if using Jetpack or WP mobile app).', 'login-armor' ),
			],
			[
				'key'         => 'disable_file_editor',
				'label'       => __( 'Disable file editor', 'login-armor' ),
				'description' => __( 'Block theme/plugin file editing from dashboard.', 'login-armor' ),
			],
			[
				'key'         => 'hide_wp_version',
				'label'       => __( 'Hide WordPress version', 'login-armor' ),
				'description' => __( 'Strip version from page source and feeds.', 'login-armor' ),
			],
			[
				'key'         => 'mask_login_errors',
				'label'       => __( 'Mask login errors', 'login-armor' ),
				'description' => __( 'Generic error message to prevent user enumeration.', 'login-armor' ),
			],
			[
				'key'         => 'disable_app_passwords',
				'label'       => __( 'Disable application passwords', 'login-armor' ),
				'description' => __( 'Remove REST API app password feature.', 'login-armor' ),
			],
			[
				'key'         => 'block_php_uploads',
				'label'       => __( 'Block PHP in uploads', 'login-armor' ),
				'description' => __( 'Prevent PHP execution in wp-content/uploads/. Apache/LiteSpeed only.', 'login-armor' ),
			],
			[
				'key'         => 'prevent_author_enum',
				'label'       => __( 'Prevent author enumeration', 'login-armor' ),
				'description' => __( 'Block ?author=N requests that reveal usernames.', 'login-armor' ),
			],
			[
				'key'         => 'obfuscate_author_slugs',
				'label'       => __( 'Obfuscate author slugs', 'login-armor' ),
				'description' => __( 'Replace /author/username/ with an opaque token that cannot be reversed to a login.', 'login-armor' ),
			],
			[
				'key'         => 'restrict_rest_api',
				'label'       => __( 'Restrict REST API', 'login-armor' ),
				'description' => __( 'Require authentication for REST API requests.', 'login-armor' ),
			],
			[
				'key'         => 'block_reserved_usernames',
				'label'       => __( 'Block reserved usernames', 'login-armor' ),
				'description' => __( 'Reject login and registration attempts for admin, root, test, and other well-known usernames.', 'login-armor' ),
			],
			[
				'key'         => 'login_honeypot',
				'label'       => __( 'Anti-bot honeypot', 'login-armor' ),
				'description' => __( 'Invisible trap on login, register, and lost-password forms. Bots that auto-fill every field are banned for 24 hours.', 'login-armor' ),
			],
			[
				'key'         => 'protect_system_files',
				'label'       => __( 'Protect system files', 'login-armor' ),
				'description' => __( 'Block access to readme.html, license.txt, wp-config-sample.php. Apache/LiteSpeed only, with pretty permalinks.', 'login-armor' ),
			],
			[
				'key'         => 'disable_directory_listing',
				'label'       => __( 'Disable directory listing', 'login-armor' ),
				'description' => __( 'Prevent browsing directory contents. Apache/LiteSpeed only.', 'login-armor' ),
			],
			[
				'key'         => 'disable_pingbacks',
				'label'       => __( 'Disable pingbacks', 'login-armor' ),
				'description' => __( 'Neutralize XML-RPC pingbacks (a DDoS amplification vector) and remove the X-Pingback header, even if XML-RPC stays on for other uses.', 'login-armor' ),
			],
			[
				'key'         => 'alert_admin_creation',
				'label'       => __( 'Alert on new administrator', 'login-armor' ),
				'description' => __( 'Log an activity entry and fire a notification whenever an account is created with, or promoted to, the administrator role, a common sign of compromise.', 'login-armor' ),
			],
			[
				'key'         => 'force_https',
				'label'       => __( 'Force HTTPS', 'login-armor' ),
				'description' => __( 'Four effects: plain HTTP is redirected to HTTPS (temporary redirect), the admin is served over SSL, the two authentication cookies are marked Secure, and a request forwarded by a proxy listed in Trusted proxies counts as HTTPS for the rest of that request. Enable only from an HTTPS request. Behind a terminator whose address is not listed in Trusted proxies, none of this can be believed, so the option stands down entirely and ENFORCES NOTHING until you declare that proxy: no redirect, no admin over SSL, no Secure cookies. It says so in the admin when it happens. Turning it off removes only what Login Armor adds: WordPress keeps forcing the admin when the site address is HTTPS or FORCE_SSL_ADMIN is set, and a Strict-Transport-Security header that this toggle made effective stays pinned in every browser that already received it. Way out:', 'login-armor' )
					. ' <code>wp option patch update login_armor_hardening force_https false</code>'
					. ' ' . __( 'Safe mode stands all four effects down too, without changing this setting, and enforcement comes back the moment you delete the line:', 'login-armor' )
					. ' <code>define( \'LOGIN_ARMOR_SAFE_MODE\', true );</code>',
			],
		];
	}

	// ------------------------------------------------------------------
	// Toggle: disable_xmlrpc
	// ------------------------------------------------------------------

	/**
	 * Register hooks to disable XML-RPC entirely.
	 */
	private function register_disable_xmlrpc(): void {
		add_filter( 'xmlrpc_enabled', '__return_false' );
		add_action( 'init', [ $this, 'block_xmlrpc_request' ], 1 );
	}

	/**
	 * Block direct requests to xmlrpc.php early in the request lifecycle.
	 *
	 * Sends a 403 Forbidden response and exits. Only fires when headers
	 * have not been sent yet (normal front-end request).
	 */
	public function block_xmlrpc_request(): void {
		if ( ! isset( $_SERVER['REQUEST_URI'] ) ) {
			return;
		}

		$uri = sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) );

		if ( false === stripos( $uri, 'xmlrpc.php' ) ) {
			return;
		}

		if ( headers_sent() ) {
			return;
		}

		status_header( 403 );
		header( 'Content-Type: text/plain; charset=UTF-8' );
		\LoginArmor\LoginArmor::flush_response_and_exit( 'XML-RPC is disabled.' );
	}

	// ------------------------------------------------------------------
	// Toggle: disable_file_editor
	// ------------------------------------------------------------------

	/**
	 * Disable the theme/plugin file editor.
	 *
	 * Defines DISALLOW_FILE_EDIT (the WordPress native mechanism) AND
	 * filters map_meta_cap() to force-deny edit_themes, edit_plugins,
	 * and edit_files. The filter is the deterministic path: it works
	 * even if the constant gets defined too late (cached bytecode,
	 * mu-plugins already defined it, etc.) or if another plugin
	 * short-circuits the capability resolution before the core check
	 * at wp-includes/capabilities.php:609. Belt-and-suspenders.
	 */
	private function register_disable_file_editor(): void {
		if ( ! defined( 'DISALLOW_FILE_EDIT' ) ) {
			// Plugin Check only reports this line on a site where the toggle is
			// off: the sniff skips any constant that already exists when it runs,
			// so every site that had been checked so far, with the toggle on, was
			// clean, and a fresh install was not.
			// phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedConstantFound -- A WordPress core constant: defining it is what this toggle does.
			define( 'DISALLOW_FILE_EDIT', true );
		}
		add_filter( 'map_meta_cap', [ $this, 'deny_file_editor_caps' ], 10, 2 );
	}

	/**
	 * Force-deny the edit_themes / edit_plugins / edit_files capabilities.
	 *
	 * @param array<int,string> $caps Required primitive capabilities.
	 * @param string            $cap  Capability being checked.
	 * @return array<int,string>
	 */
	public function deny_file_editor_caps( $caps = array(), $cap = '' ) {
		// Untyped defensively: `map_meta_cap` runs on every capability check
		// and third-party callers must never be able to fatal it.
		if ( 'edit_themes' === $cap || 'edit_plugins' === $cap || 'edit_files' === $cap ) {
			return [ 'do_not_allow' ];
		}
		return $caps;
	}

	// ------------------------------------------------------------------
	// Toggle: hide_wp_version
	// ------------------------------------------------------------------

	/**
	 * Register hooks to hide the WordPress version from public output.
	 *
	 * Removes the meta generator tag from wp_head, filters the generator
	 * output in RSS/Atom feeds, and strips the `?ver=X.Y.Z` query argument
	 * from `<script src="…">` and `<link rel="stylesheet" href="…">` URLs
	 * so the WP version cannot be inferred from asset URLs either.
	 */
	private function register_hide_wp_version(): void {
		remove_action( 'wp_head', 'wp_generator' );
		add_filter( 'the_generator', '__return_empty_string' );
		add_filter( 'script_loader_src', [ $this, 'strip_version_query_arg' ], 9999 );
		add_filter( 'style_loader_src', [ $this, 'strip_version_query_arg' ], 9999 );
		// WP 6.5+ ES module imports go through their own filter rather than
		// `script_loader_src`. Block the leak there too.
		add_filter( 'script_module_loader_src', [ $this, 'strip_version_query_arg' ], 9999 );
	}

	/**
	 * Drop the `ver` query arg from an enqueued asset URL.
	 *
	 * @param string $src Asset URL as composed by WP_Scripts / WP_Styles.
	 * @return string
	 */
	public function strip_version_query_arg( $src = '' ) {
		if ( ! is_scalar( $src ) ) {
			return $src; // Pass through non-scalar values from third-party filters untouched.
		}
		$src = (string) $src;
		if ( '' === $src || false === strpos( $src, 'ver=' ) ) {
			return $src;
		}

		// V2.1.3 hotfix: never strip ?ver= from LoginArmor's own assets.
		// Server-side static caches (LiteSpeed LSADC on o2switch PowerBoost,
		// Cloudflare, hosting CDNs) key on the canonical URL; without
		// ?ver=hash on our files, a stale cache entry keeps serving the
		// previous admin.css / admin.js for up to a year (cache-control
		// max-age=31557600 from default Apache ExpiresByType). The version-
		// disclosure risk this filter targets is for WP core + 3rd-party
		// plugins; we control LoginArmor releases and NEED cache-busting
		// when shipping fixes (otherwise users sit on stale CSS post-update).
		if ( false !== strpos( $src, '/plugins/login-armor/' ) ) {
			return $src;
		}

		return remove_query_arg( 'ver', $src );
	}

	// ------------------------------------------------------------------
	// Toggle: mask_login_errors
	// ------------------------------------------------------------------

	/**
	 * Register hook to mask detailed login error messages.
	 */
	private function register_mask_login_errors(): void {
		// Priority 9999 = last writer wins. LimitLogin's filter_login_errors
		// short-circuits on this same option to keep mask + remaining-attempt
		// hint mutually exclusive (audit S-9).
		add_filter( 'login_errors', [ $this, 'return_generic_login_error' ], 9999 );
	}

	/**
	 * Return a generic login error message.
	 *
	 * Replaces WordPress' default messages that reveal whether a username
	 * exists, preventing username enumeration attacks.
	 *
	 * @param string $errors Original error message HTML.
	 * @return string
	 */
	public function return_generic_login_error( $errors = '' ): string {
		// Param untyped defensively (third-party `login_errors` filters may
		// pass non-strings); the return value is always rebuilt here.
		return esc_html__( 'The login information is incorrect.', 'login-armor' );
	}

	// ------------------------------------------------------------------
	// Toggle: disable_app_passwords
	// ------------------------------------------------------------------

	/**
	 * Register hook to disable application passwords (WP 5.6+).
	 */
	private function register_disable_app_passwords(): void {
		add_filter( 'wp_is_application_passwords_available', '__return_false' );
	}

	// ------------------------------------------------------------------
	// Shared .htaccess plumbing (2.6.1)
	//
	// Four writers used to carry their own copy of "read, decide, write".
	// They now share one: find the marked block, refuse when it cannot be
	// delimited, back the file up once, take an exclusive lock, and write
	// atomically. There is a single file_put_contents() and a single
	// rename() left in this module, so no caller can grow a write path that
	// skips the backup or the lock again.
	// ------------------------------------------------------------------

	/**
	 * Locate the LoginArmor block inside an .htaccess payload.
	 *
	 * Pure: it touches no file, which is what lets the offline suite drive
	 * every branch directly.
	 *
	 * A block is usable only when exactly one BEGIN line is followed by
	 * exactly one END line. Anything else is ambiguous and must be left
	 * alone: without an END marker nothing says where the administrator's
	 * own rules resume, so guessing would be another way to lose them.
	 *
	 * @param string $content Full file contents.
	 * @param string $begin   BEGIN marker line, without its newline.
	 * @param string $end     END marker line, without its newline.
	 * @return array{status:string,start:int,end:int} Offsets bound the whole
	 *                                                block, the newline that
	 *                                                closes the END line
	 *                                                included. They are -1
	 *                                                unless the status is
	 *                                                BLOCK_COMPLETE.
	 */
	public static function find_marked_block( string $content, string $begin, string $end ): array {
		$offset       = 0;
		$begin_starts = [];
		$end_stops    = [];

		$lines = preg_split( '/(?<=\n)/', $content );
		foreach ( is_array( $lines ) ? $lines : [] as $line ) {
			$length = strlen( (string) $line );
			// Blanks on BOTH sides and the line ending are ignored: a file
			// saved with CRLF is still recognised, and so is a block someone
			// indented inside an <IfModule>. Not recognising an indented
			// block would mean appending a second one.
			$trimmed = trim( (string) $line );
			if ( $trimmed === $begin ) {
				$begin_starts[] = $offset;
			} elseif ( $trimmed === $end ) {
				$end_stops[] = $offset + $length;
			}
			$offset += $length;
		}

		if ( [] === $begin_starts && [] === $end_stops ) {
			return [
				'status' => self::BLOCK_ABSENT,
				'start'  => -1,
				'end'    => -1,
			];
		}

		if ( 1 !== count( $begin_starts ) || 1 !== count( $end_stops ) || $end_stops[0] <= $begin_starts[0] ) {
			return [
				'status' => self::BLOCK_AMBIGUOUS,
				'start'  => -1,
				'end'    => -1,
			];
		}

		return [
			'status' => self::BLOCK_COMPLETE,
			'start'  => $begin_starts[0],
			'end'    => $end_stops[0],
		];
	}

	/**
	 * Swap the bytes between two offsets, leaving every other byte in place.
	 *
	 * @param string $content Full file contents.
	 * @param int    $start   First byte of the block.
	 * @param int    $end     First byte after the block.
	 * @param string $block   Replacement block, newline-terminated.
	 * @return string The new contents.
	 */
	public static function replace_marked_block( string $content, int $start, int $end, string $block ): string {
		// A block that ended the file without a final newline keeps that
		// shape: the point is to change nothing the caller did not ask for.
		if ( ! str_ends_with( substr( $content, $start, $end - $start ), "\n" ) ) {
			$block = rtrim( $block, "\r\n" );
		}

		return substr( $content, 0, $start ) . $block . substr( $content, $end );
	}

	/**
	 * The line ending a file mostly uses.
	 *
	 * An .htaccess edited on Windows, or served from a checkout with
	 * `core.autocrlf`, is CRLF throughout. Writing an LF-only block into it
	 * would make the file mixed, and the next pass would rewrite the block
	 * again because the bytes never match. The block is therefore rendered
	 * with whichever ending already dominates.
	 *
	 * @param string $content Full file contents.
	 * @return string "\r\n" or "\n".
	 */
	public static function dominant_eol( string $content ): string {
		$crlf = substr_count( $content, "\r\n" );
		$bare = substr_count( $content, "\n" ) - $crlf;

		return $crlf > $bare ? "\r\n" : "\n";
	}

	/**
	 * Render the canonical block, which is LF-only, with a given line ending.
	 *
	 * @param string $block Canonical block.
	 * @param string $eol   Line ending to use.
	 * @return string The block, ready to be written.
	 */
	public static function render_block( string $block, string $eol ): string {
		if ( "\n" === $eol ) {
			return $block;
		}

		return str_replace( "\n", $eol, $block );
	}

	/**
	 * Append the block to a file that does not carry one yet.
	 *
	 * @param string $content Full file contents.
	 * @param string $block   Block to append, newline-terminated.
	 * @param string $eol     Line ending to close the last line with when the
	 *                        file does not end with one.
	 * @return string The new contents.
	 */
	public static function append_marked_block( string $content, string $block, string $eol = "\n" ): string {
		if ( '' === $content ) {
			return $block;
		}
		if ( ! str_ends_with( $content, "\n" ) ) {
			$content .= $eol;
		}

		return $content . $block;
	}

	/**
	 * Record, durably, that one .htaccess file could not be brought in line.
	 *
	 * Called from every path that sets one of the two short-lived transients,
	 * which are kept exactly as they were: the admin notices and
	 * Settings\Importer read them, and five minutes is the right life there.
	 * This is the copy Site Health reads, long after the notice has gone.
	 *
	 * @since 2.7.0
	 *
	 * The REASON is kept, not flattened to one word.
	 *
	 * 2.7.1: nine call sites recorded `write`, covering seven different
	 * causes, and one of them is a lock held by a concurrent save. The screen
	 * then told the administrator to check permissions on a file whose
	 * permissions were correct, about a condition that repairs itself on the
	 * next save. Measured on a real site: every gate of the write sequence
	 * succeeded when replayed as the site's own user, while the record still
	 * said `write`. The code knew which gate refused and threw it away.
	 *
	 * An unknown reason is kept as `write` rather than dropped: a new call
	 * site that forgets to name itself must still raise something, and the
	 * wording for `write` stays the cautious generic one.
	 *
	 * @param string $path Full path to the .htaccess file.
	 * @param string $kind One of KNOWN_HTACCESS_FAILURES. Anything else is
	 *                     recorded as the generic `write`.
	 */
	public static function record_htaccess_failure( string $path, string $kind ): void {
		++self::$htaccess_failures;

		update_option(
			self::OPTION_HTACCESS_LAST_FAILURE,
			array(
				'path' => $path,
				'kind' => in_array( $kind, self::KNOWN_HTACCESS_FAILURES, true ) ? $kind : 'write',
				'time' => time(),
			),
			false
		);
	}

	/**
	 * Whether a recorded failure is one that repairs itself.
	 *
	 * A lock held by another request means a second save was running at that
	 * instant, and the next save takes the lock and writes. Telling somebody
	 * to go and inspect their server for that is worse than saying nothing:
	 * it sends them looking for a fault that is not there, and it teaches
	 * them to ignore the next notice, which may be real.
	 *
	 * @param string $kind Recorded reason.
	 */
	public static function htaccess_failure_is_transient( string $kind ): bool {
		return 'lock_busy' === $kind;
	}

	/**
	 * One sentence per reason, said the same way everywhere.
	 *
	 * The notice, the answer the Hardening tab gets when it saves, and the
	 * Site Health test all read this, so an administrator who sees the problem
	 * twice sees the same words and the same advice. Three of them are
	 * genuinely about permissions and say so; the others are not, and used to
	 * say so anyway.
	 *
	 * @param string $kind Recorded reason.
	 * @param string $path Full path, already known to the caller.
	 */
	public static function htaccess_failure_message( string $kind, string $path ): string {
		$file = '' === $path ? __( 'the .htaccess file', 'login-armor' ) : $path;

		switch ( $kind ) {
			case 'lock_busy':
				return sprintf(
					/* translators: %s: full path of the .htaccess file. */
					__( 'Another save was writing %s at that moment, so this one stood aside rather than risk a half-written file. Nothing is wrong with the file: save the Hardening tab again and the rule is applied.', 'login-armor' ),
					$file
				);

			case 'lock_open':
				return sprintf(
					/* translators: %s: full path of the .htaccess file. */
					__( 'Login Armor could not create its lock file next to %s, so it changed nothing. The directory itself has to be writable, not only the file.', 'login-armor' ),
					$file
				);

			case 'backup':
				return sprintf(
					/* translators: %s: full path of the .htaccess file. */
					__( 'Login Armor could not copy %s aside, so it changed nothing: it never edits that file without a backup, because that is how hand-written rules get lost. Check that the directory is writable and that the volume is not full.', 'login-armor' ),
					$file
				);

			case 'read':
				return sprintf(
					/* translators: %s: full path of the .htaccess file. */
					__( 'Login Armor could not read %s, so it did not try to change it and a rule you switched on is saved but not applied. Check the file permissions.', 'login-armor' ),
					$file
				);

			case 'partial_write':
				return sprintf(
					/* translators: %s: full path of the .htaccess file. */
					__( 'The new %s came back short and was discarded, so the original is untouched and a rule you switched on is saved but not applied. That usually means the volume is full.', 'login-armor' ),
					$file
				);

			case 'rename':
				return sprintf(
					/* translators: %s: full path of the .htaccess file. */
					__( 'Login Armor prepared the new %s but could not put it in place, so the original is untouched and a rule you switched on is saved but not applied. Check that the directory is writable.', 'login-armor' ),
					$file
				);

			case 'unlink':
				return sprintf(
					/* translators: %s: full path of the .htaccess file. */
					__( 'The rule was removed from %s, but the now empty file could not be deleted. Nothing is broken: the file is simply still there.', 'login-armor' ),
					$file
				);

			case 'ambiguous':
				return sprintf(
					/* translators: %s: full path of the .htaccess file. */
					__( 'The Login Armor markers in %s do not form exactly one complete block, so nothing says where your own rules resume and Login Armor refuses to touch it. Repair the marker lines by hand, then save the Hardening tab again.', 'login-armor' ),
					$file
				);

			case 'no_rewrite':
				return sprintf(
					/* translators: %s: full path of the .htaccess file. */
					__( '%s runs no rewrite rules, so Login Armor did not add the one that refuses readme.html, license.txt and wp-config-sample.php: whether this server accepts it there is unknown, and a refused rule would stop the whole site. Turn on pretty permalinks (Settings, Permalinks), then save the Hardening tab again.', 'login-armor' ),
					$file
				);
		}

		return sprintf(
			/* translators: %s: full path of the .htaccess file. */
			__( 'Login Armor could not write to %s, so a rule you switched on is saved but not applied. Check the file permissions and the free space on the volume.', 'login-armor' ),
			$file
		);
	}

	/**
	 * Copy an existing .htaccess aside, once and only once.
	 *
	 * The copy is taken before the first modification and never refreshed:
	 * its value is precisely that it predates anything this plugin did. A
	 * backup that cannot be taken refuses the write, because the whole point
	 * of the 2.6.1 fix is that an administrator never loses rules silently.
	 *
	 * @param string $path Full path to the .htaccess file.
	 * @return bool True when a usable backup exists, or when there was
	 *              nothing to back up because the file does not exist yet.
	 */
	public static function backup_htaccess_once( string $path ): bool {
		if ( ! file_exists( $path ) ) {
			return true;
		}

		$backup = $path . self::HTACCESS_BACKUP_SUFFIX;
		// is_file(), not file_exists(): a directory sitting at that name is
		// not a backup, and copy() would fail on it.
		if ( is_file( $backup ) ) {
			return true;
		}

		// copy() rather than read-then-write: one syscall, and it cannot
		// half-succeed the way a truncating rewrite can.
		if ( ! @copy( $path, $backup ) ) {
			set_transient( self::TRANSIENT_HTACCESS_FAILED, $path, MINUTE_IN_SECONDS * 5 );
			self::record_htaccess_failure( $path, 'backup' );
			return false;
		}

		return true;
	}

	/**
	 * Take the exclusive advisory lock guarding one .htaccess file.
	 *
	 * Non-blocking on purpose: a busy lock means another request is already
	 * rewriting this exact file, and waiting inside a page load would be
	 * worse than refusing. The caller surfaces the refusal through the
	 * failure transient, and the admin re-toggles.
	 *
	 * @param string $path Full path to the .htaccess file.
	 * @return resource|false The locked handle, or false when the lock is busy
	 *                        or could not be created.
	 */
	private static function lock_htaccess( string $path ) {
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fopen
		$handle = @fopen( $path . self::HTACCESS_LOCK_SUFFIX, 'c' );
		if ( false === $handle ) {
			set_transient( self::TRANSIENT_HTACCESS_FAILED, $path, MINUTE_IN_SECONDS * 5 );
			self::record_htaccess_failure( $path, 'lock_open' );
			return false;
		}

		if ( ! @flock( $handle, LOCK_EX | LOCK_NB ) ) {
			// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose
			@fclose( $handle );
			set_transient( self::TRANSIENT_HTACCESS_FAILED, $path, MINUTE_IN_SECONDS * 5 );
			self::record_htaccess_failure( $path, 'lock_busy' );
			return false;
		}

		return $handle;
	}

	/**
	 * Release a lock taken by lock_htaccess().
	 *
	 * The lock file itself is left on disk: unlinking it would race a second
	 * process that has already opened it and would then be locking a name
	 * nobody else sees.
	 *
	 * @param resource $handle Handle returned by lock_htaccess().
	 */
	private static function release_htaccess_lock( $handle ): void {
		@flock( $handle, LOCK_UN );
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose
		@fclose( $handle );
	}

	/**
	 * Make the next atomic write report this byte count. Tests only.
	 *
	 * Ignored outside the offline suite: see `$write_bytes_override`.
	 *
	 * @param int|null $bytes Byte count to report, or null to stop pretending.
	 */
	public static function set_write_bytes_override( ?int $bytes ): void {
		if ( ! defined( 'LOGIN_ARMOR_TESTING' ) || ! LOGIN_ARMOR_TESTING ) {
			return;
		}
		self::$write_bytes_override = $bytes;
	}

	/**
	 * The module's one and only .htaccess write.
	 *
	 * Renders to a temp file in the same directory, then renames onto the
	 * final path, so a failed flush can never leave a truncated .htaccess.
	 * The path is always a parameter: nothing here computes it from ABSPATH,
	 * which keeps Plugin Check's ABSPATH sniff scoped to the root helpers
	 * that legitimately need it (wordpress_root_dir() and
	 * legacy_root_htaccess_path() since 2.8.3).
	 *
	 * A short write is treated exactly like a failed one. On a full volume
	 * `file_put_contents()` returns the number of bytes it managed to write
	 * rather than false, and renaming that truncated temp over the real file
	 * is the very data loss this module now exists to prevent. The temp file
	 * is removed on every failure path, including the one where the write
	 * reported false after creating it.
	 *
	 * @param string $path     Full path to the .htaccess file.
	 * @param string $contents Full new contents.
	 * @return bool True on success.
	 */
	private static function write_htaccess_atomic( string $path, string $contents ): bool {
		$tmp = $path . '.tmp-' . wp_generate_password( 8, false );
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents
		$bytes = @file_put_contents( $tmp, $contents, LOCK_EX );

		if ( null !== self::$write_bytes_override && defined( 'LOGIN_ARMOR_TESTING' ) && LOGIN_ARMOR_TESTING ) {
			$bytes = self::$write_bytes_override;
		}

		if ( false === $bytes || strlen( $contents ) !== $bytes ) {
			// phpcs:ignore WordPress.WP.AlternativeFunctions.unlink_unlink
			@unlink( $tmp );
			set_transient( self::TRANSIENT_HTACCESS_FAILED, $path, MINUTE_IN_SECONDS * 5 );
			self::record_htaccess_failure( $path, 'partial_write' );
			return false;
		}
		// phpcs:ignore WordPress.WP.AlternativeFunctions.rename_rename
		if ( ! @rename( $tmp, $path ) ) {
			// phpcs:ignore WordPress.WP.AlternativeFunctions.unlink_unlink
			@unlink( $tmp );
			set_transient( self::TRANSIENT_HTACCESS_FAILED, $path, MINUTE_IN_SECONDS * 5 );
			self::record_htaccess_failure( $path, 'rename' );
			return false;
		}

		return true;
	}

	/**
	 * Does the file already hold exactly this block? Read without the lock (2.8.0).
	 *
	 * Only ever answers "nothing to do": any other answer sends the caller to
	 * the locked path, which reads the file again before it decides anything.
	 *
	 * @param string $path  Full path to the .htaccess file.
	 * @param string $block Canonical block, newline-terminated.
	 * @param string $begin BEGIN marker line.
	 * @param string $end   END marker line.
	 */
	private static function block_already_in_place( string $path, string $block, string $begin, string $end ): bool {
		if ( ! file_exists( $path ) ) {
			return false;
		}
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents
		$peek = @file_get_contents( $path );
		if ( false === $peek ) {
			return false;
		}
		$peek  = (string) $peek;
		$found = self::find_marked_block( $peek, $begin, $end );
		if ( self::BLOCK_COMPLETE !== $found['status'] ) {
			return false;
		}
		$rendered = self::render_block( $block, self::dominant_eol( $peek ) );

		return self::replace_marked_block( $peek, $found['start'], $found['end'], $rendered ) === $peek;
	}

	/**
	 * Insert or refresh a marked block, preserving everything around it.
	 *
	 * The contract, in order:
	 *   1. take the exclusive lock, or refuse at once (failure transient);
	 *   2. read the file, or refuse when it exists and cannot be read;
	 *   3. an ambiguous block is never touched (ambiguity transient);
	 *   4. a complete block is replaced precisely, byte for byte outside it,
	 *      and rendered with the line ending the file already uses;
	 *   5. no block at all means append, on a line of its own;
	 *   6. a missing file is created with the block alone;
	 *   7. contents already correct means no write at all, and no backup;
	 *   8. otherwise back the file up once, then write atomically.
	 *
	 * @param string $path  Full path to the .htaccess file.
	 * @param string $block Canonical block, newline-terminated.
	 * @param string $begin BEGIN marker line.
	 * @param string $end   END marker line.
	 * @return bool True when the file holds the wanted block afterwards.
	 */
	private static function sync_marked_block( string $path, string $block, string $begin, string $end ): bool {
		// 2.8.0: a file that already holds the block is the common case, and
		// the directory-listing and system-files blocks are checked on every
		// request. Taking the lock first made every page view create the lock
		// file and contend for it, and two simultaneous views recorded a
		// `lock_busy` failure about a file nobody needed to write. A read
		// without the lock decides that nothing is to be done; any change
		// still happens under the lock, on a second read.
		if ( self::block_already_in_place( $path, $block, $begin, $end ) ) {
			return true;
		}

		$lock = self::lock_htaccess( $path );
		if ( false === $lock ) {
			return false;
		}

		try {
			$exists   = file_exists( $path );
			$contents = '';
			if ( $exists ) {
				// phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents
				$read = @file_get_contents( $path );
				if ( false === $read ) {
					set_transient( self::TRANSIENT_HTACCESS_FAILED, $path, MINUTE_IN_SECONDS * 5 );
					self::record_htaccess_failure( $path, 'read' );
					return false;
				}
				$contents = (string) $read;
			}

			if ( ! $exists ) {
				$wanted = $block;
			} else {
				$found = self::find_marked_block( $contents, $begin, $end );
				if ( self::BLOCK_AMBIGUOUS === $found['status'] ) {
					set_transient( self::TRANSIENT_HTACCESS_AMBIGUOUS, $path, MINUTE_IN_SECONDS * 5 );
					self::record_htaccess_failure( $path, 'ambiguous' );
					return false;
				}
				$eol      = self::dominant_eol( $contents );
				$rendered = self::render_block( $block, $eol );
				$wanted   = self::BLOCK_COMPLETE === $found['status']
					? self::replace_marked_block( $contents, $found['start'], $found['end'], $rendered )
					: self::append_marked_block( $contents, $rendered, $eol );
			}

			if ( $exists && $wanted === $contents ) {
				return true;
			}

			if ( ! self::backup_htaccess_once( $path ) ) {
				return false;
			}

			return self::write_htaccess_atomic( $path, $wanted );
		} finally {
			self::release_htaccess_lock( $lock );
		}
	}

	/**
	 * Remove a marked block, preserving everything around it.
	 *
	 * Same discipline as `sync_marked_block()`: an ambiguous block is never
	 * stripped, and the file is backed up once before it is changed.
	 *
	 * @param string $path              Full path to the .htaccess file.
	 * @param string $begin             BEGIN marker line.
	 * @param string $end               END marker line.
	 * @param string $legacy            Verbatim block written by releases that
	 *                                  predate the BEGIN/END markers, or ''.
	 * @param bool   $delete_when_empty Delete the file when stripping leaves
	 *                                  nothing but whitespace.
	 * @return bool True when the file is in the wanted state afterwards.
	 */
	private static function strip_marked_block( string $path, string $begin, string $end, string $legacy, bool $delete_when_empty ): bool {
		if ( ! file_exists( $path ) ) {
			return true;
		}

		// 2.8.0: nothing of ours in the file means nothing to do, decided
		// without the lock. Deactivation and uninstall now strip every block,
		// and taking the lock first created the lock file next to a root
		// .htaccess this plugin had never written to, and recorded a
		// `lock_open` failure where that directory is read-only.
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents
		$peek = @file_get_contents( $path );
		if ( false !== $peek
			&& self::BLOCK_ABSENT === self::find_marked_block( (string) $peek, $begin, $end )['status']
			&& ( '' === $legacy || ! str_contains( (string) $peek, $legacy ) )
		) {
			return true;
		}

		$lock = self::lock_htaccess( $path );
		if ( false === $lock ) {
			return false;
		}

		try {
			// phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents
			$read = @file_get_contents( $path );
			if ( false === $read ) {
				set_transient( self::TRANSIENT_HTACCESS_FAILED, $path, MINUTE_IN_SECONDS * 5 );
				self::record_htaccess_failure( $path, 'read' );
				return false;
			}

			$contents = (string) $read;
			if ( '' === $contents ) {
				return true;
			}

			$found = self::find_marked_block( $contents, $begin, $end );
			if ( self::BLOCK_AMBIGUOUS === $found['status'] ) {
				set_transient( self::TRANSIENT_HTACCESS_AMBIGUOUS, $path, MINUTE_IN_SECONDS * 5 );
				self::record_htaccess_failure( $path, 'ambiguous' );
				return false;
			}

			$cleaned = self::BLOCK_COMPLETE === $found['status']
				? substr( $contents, 0, $found['start'] ) . substr( $contents, $found['end'] )
				: $contents;

			if ( '' !== $legacy ) {
				$cleaned = str_replace( $legacy, '', $cleaned );
			}

			if ( $cleaned === $contents ) {
				return true;
			}

			if ( ! self::backup_htaccess_once( $path ) ) {
				return false;
			}

			if ( $delete_when_empty && '' === trim( $cleaned ) ) {
				// phpcs:ignore WordPress.WP.AlternativeFunctions.unlink_unlink
				if ( ! @unlink( $path ) ) {
					set_transient( self::TRANSIENT_HTACCESS_FAILED, $path, MINUTE_IN_SECONDS * 5 );
					self::record_htaccess_failure( $path, 'unlink' );
					return false;
				}
				return true;
			}

			return self::write_htaccess_atomic( $path, $cleaned );
		} finally {
			self::release_htaccess_lock( $lock );
		}
	}

	// ------------------------------------------------------------------
	// Toggle: block_php_uploads
	// ------------------------------------------------------------------

	/**
	 * Ensure .htaccess in uploads directory blocks PHP execution.
	 *
	 * Writes the rule on activation and removes it on deactivation
	 * via the update_option hook (see register_htaccess_sync).
	 */
	private function register_block_php_uploads(): void {
		// The .htaccess is written/removed by the save hook: nothing to do at runtime.
		// On first activation, ensure the file exists.
		$this->maybe_write_uploads_htaccess();
		// 2.8.1: and the root rule, put back by any request that finds it
		// missing, as the system-files one is. Nothing to write is decided
		// without the lock.
		self::write_uploads_root_block( self::uploads_root_htaccess_path(), false );
	}

	/**
	 * Write .htaccess to block PHP in uploads if it does not already exist.
	 */
	private function maybe_write_uploads_htaccess(): void {
		$upload_dir = wp_get_upload_dir();
		$htaccess   = trailingslashit( $upload_dir['basedir'] ) . '.htaccess';

		if ( file_exists( $htaccess ) ) {
			return;
		}

		self::write_uploads_htaccess( $htaccess );
	}

	/**
	 * Canonical block that blocks PHP execution in a directory.
	 *
	 * @return string BEGIN line, rules and END line, newline-terminated.
	 */
	public static function uploads_block(): string {
		return self::MARKER_UPLOADS_BEGIN . "\n"
			. "<Files *.php>\n"
			. "deny from all\n"
			. "</Files>\n"
			. self::MARKER_UPLOADS_END . "\n";
	}

	/**
	 * Write, or refresh, the .htaccess block that stops PHP in uploads.
	 *
	 * Until 2.6.0 this function rendered the five lines above and wrote them
	 * over the WHOLE file, on every Hardening save and on every
	 * `SafeBaseline::apply()`. An administrator's own rules (hotlink
	 * protection, MIME restrictions) were destroyed each time, although this
	 * very docblock promised the opposite. Since 2.6.1 only the marked block
	 * is ever rewritten; see `sync_marked_block()` for the full contract.
	 *
	 * @param string $path Full path to the .htaccess file.
	 * @return bool True when the file holds the wanted block afterwards.
	 */
	public static function write_uploads_htaccess( string $path ): bool {
		return self::sync_marked_block(
			$path,
			self::uploads_block(),
			self::MARKER_UPLOADS_BEGIN,
			self::MARKER_UPLOADS_END
		);
	}

	/**
	 * Remove LoginArmor's PHP-block rules from uploads/.htaccess.
	 *
	 * Strips only the LoginArmor BEGIN/END block (or the legacy marker
	 * written by v2.0.4 and earlier) so admin-authored rules are preserved.
	 * If nothing but whitespace is left, the file is removed altogether to
	 * keep the directory tidy, which is the behaviour this module has always
	 * had here.
	 *
	 * The two sidecars stay behind on purpose. `.htaccess.login-armor.bak`
	 * is the administrator's copy of the file as it was before this plugin
	 * ever touched it, and deleting it here would throw away the only thing
	 * that survives a mistake. `.htaccess.login-armor.lock` is left because
	 * unlinking it would race a process that has already opened it. Both are
	 * `.ht`-prefixed, so Apache and LiteSpeed deny serving them, and both are
	 * empty of anything an attacker could want beyond the rules themselves.
	 */
	public static function remove_uploads_htaccess(): void {
		$upload_dir = wp_get_upload_dir();
		$htaccess   = trailingslashit( $upload_dir['basedir'] ) . '.htaccess';

		self::strip_marked_block(
			$htaccess,
			self::MARKER_UPLOADS_BEGIN,
			self::MARKER_UPLOADS_END,
			// Legacy block written before BEGIN/END markers existed (v2.0.4 and earlier).
			"# LoginArmor \u{2014} Block PHP execution\n<Files *.php>\ndeny from all\n</Files>\n",
			true
		);
	}

	/**
	 * The root .htaccess rule that refuses PHP below the uploads directory (2.8.1).
	 *
	 * The uploads block above is an access-control directive. Apache applies
	 * it; OpenLiteSpeed reads nothing but rewrite rules from an .htaccess, so
	 * on such a server a PHP file dropped into uploads ran while the toggle
	 * counted in the security score. Measured on cours-ndrc.fr on 2026-10-02:
	 * a probe placed in uploads answered 200 and printed its output. A rewrite
	 * rule in the root file, next to WordPress's own, is the form that server
	 * applies; on Apache it comes on top of the uploads block. Empty when the
	 * uploads directory is not below the site's root directory, where a root
	 * rule cannot reach.
	 */
	public static function uploads_root_block(): string {
		$prefix = self::uploads_rewrite_prefix();
		if ( '' === $prefix ) {
			return '';
		}

		return self::MARKER_UPLOADS_ROOT_BEGIN . "\n"
			. "<IfModule mod_rewrite.c>\n"
			. "RewriteEngine On\n"
			. 'RewriteRule ^' . str_replace( '\-', '-', preg_quote( $prefix, '#' ) ) . '/.*\.(php[0-9]*|pht|phtml|phar)$ - [F,NC]' . "\n"
			. "</IfModule>\n"
			. self::MARKER_UPLOADS_ROOT_END . "\n";
	}

	/**
	 * The uploads directory, relative to the site's root directory, or '' (2.8.1).
	 *
	 * The network's base directory, not one site's: on a multisite every
	 * site's files live below it, in sites/<id>. 2.8.3: measured from the
	 * same root as the file that carries the rule, app/uploads under Bedrock.
	 */
	private static function uploads_rewrite_prefix(): string {
		$dir  = self::uploads_base_dir();
		$root = trailingslashit( wp_normalize_path( dirname( self::uploads_root_htaccess_path() ) ) );
		if ( '' === $dir || ! str_starts_with( trailingslashit( $dir ), $root ) ) {
			return '';
		}

		return trim( substr( $dir, strlen( $root ) ), '/' );
	}

	/**
	 * Write, or refresh, the uploads rule in the root .htaccess (2.8.1).
	 *
	 * The same gates as the system-files block: no root .htaccess, nothing is
	 * created; a file that runs no rewrite rule of its own gets none from us.
	 * That refusal is not recorded as a failure: the uploads block still
	 * protects the directory on Apache, and the system-files toggle already
	 * tells the administrator what pretty permalinks would change.
	 *
	 * @param string $path   Full path to the root .htaccess file.
	 * @param bool   $report Record a file that cannot be read (false on the per-request check).
	 * @return bool True when the file holds the rule afterwards, or when there is nothing to hold it.
	 */
	public static function write_uploads_root_block( string $path, bool $report = true ): bool {
		$block = self::uploads_root_block();
		if ( '' === $block || ! file_exists( $path ) ) {
			return true;
		}
		if ( self::block_already_in_place( $path, $block, self::MARKER_UPLOADS_ROOT_BEGIN, self::MARKER_UPLOADS_ROOT_END ) ) {
			return true;
		}

		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents
		$read = @file_get_contents( $path );
		if ( false === $read ) {
			if ( $report ) {
				set_transient( self::TRANSIENT_HTACCESS_FAILED, $path, MINUTE_IN_SECONDS * 5 );
				self::record_htaccess_failure( $path, 'read' );
			}
			return false;
		}
		if ( ! self::runs_rewrite_rules( (string) $read ) ) {
			return false;
		}

		return self::sync_marked_block( $path, $block, self::MARKER_UPLOADS_ROOT_BEGIN, self::MARKER_UPLOADS_ROOT_END );
	}

	/**
	 * Remove the uploads rule from the root .htaccess (2.8.1). The file itself stays.
	 *
	 * @param string|null $path One file, or null for every root .htaccess
	 *                          this plugin may have written to (2.8.3).
	 */
	public static function remove_uploads_root_block( ?string $path = null ): void {
		foreach ( null === $path ? self::root_htaccess_paths() : array( $path ) as $file ) {
			self::strip_marked_block( $file, self::MARKER_UPLOADS_ROOT_BEGIN, self::MARKER_UPLOADS_ROOT_END, '', false );
		}
	}

	// ------------------------------------------------------------------
	// Toggle: prevent_author_enum
	// ------------------------------------------------------------------

	/**
	 * Register hooks to prevent author enumeration via ?author=N and REST API.
	 *
	 * Scope expanded in 2.0.5: removing only the `/wp/v2/users` endpoint left
	 * three sibling leaks unaddressed: `/wp/v2/posts?_embed=1` carries
	 * `_embedded.author[].name`, the `/oembed/` family returns `author_name`
	 * and `author_url`, and `wp-sitemap-users-N.xml` enumerates every
	 * publishing account by login. All four surfaces are now gated together
	 * when an admin enables this toggle.
	 */
	private function register_prevent_author_enum(): void {
		add_action( 'init', [ $this, 'block_author_query' ], 1 );
		add_filter( 'rest_endpoints', [ $this, 'restrict_users_endpoint' ] );

		// oEmbed: drop author_name and author_url from JSON responses for unauthenticated callers.
		add_filter( 'oembed_response_data', [ $this, 'scrub_oembed_user_info' ], 99, 1 );

		// Sitemap: skip the user provider so wp-sitemap-users-N.xml returns 404 to anonymous bots.
		add_filter( 'wp_sitemaps_add_provider', [ $this, 'disable_user_sitemap_provider' ], 10, 2 );

		// REST: scrub username-equivalent fields when a `_embed` request fans out to /wp/v2/users.
		add_filter( 'rest_prepare_user', [ $this, 'scrub_rest_user_for_anon' ], 99, 1 );
	}

	/**
	 * Redirect numeric ?author= queries to the home page.
	 *
	 * Skipped in wp-admin for logged-in users with `edit_posts` so that the
	 * core author filter on edit.php (Posts/Pages list "All / Mine / <author>")
	 * keeps working. The frontend enumeration vector remains blocked.
	 */
	public function block_author_query(): void {
		if ( is_admin() && current_user_can( 'edit_posts' ) ) {
			return;
		}
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Public GET parameter.
		if ( isset( $_GET['author'] ) && absint( wp_unslash( $_GET['author'] ) ) > 0 ) {
			wp_safe_redirect( home_url(), 301 );
			exit;
		}
	}

	/**
	 * Remove the /wp/v2/users endpoint for non-authenticated requests.
	 *
	 * @param array<string, mixed> $endpoints Registered REST endpoints.
	 * @return array<string, mixed>
	 */
	public function restrict_users_endpoint( $endpoints = array() ) {
		if ( ! is_array( $endpoints ) ) {
			return $endpoints; // Untyped defensively: pass through unexpected values.
		}
		if ( ! is_user_logged_in() ) {
			unset( $endpoints['/wp/v2/users'], $endpoints['/wp/v2/users/(?P<id>[\d]+)'] );
		}
		return $endpoints;
	}

	/**
	 * Replace identifying author fields in oEmbed JSON with neutral values.
	 *
	 * The `author_name` field is the user's display name (often equal to the
	 * user_login), and `author_url` resolves to `/author/<nicename>/` which
	 * is the same enumeration vector as `?author=N`. Replacing them with a
	 * single bland string `Site` and the home URL keeps the JSON well-formed
	 * for clients that consume it (including most rich-link previews) while
	 * eliminating the leak.
	 *
	 * @param array<string, mixed> $data Raw oEmbed response.
	 * @return array<string, mixed>
	 */
	public function scrub_oembed_user_info( $data = array() ) {
		if ( ! is_array( $data ) ) {
			return $data; // Untyped defensively: pass through unexpected values.
		}
		if ( is_user_logged_in() ) {
			return $data;
		}
		if ( isset( $data['author_name'] ) ) {
			$data['author_name'] = (string) get_bloginfo( 'name' );
		}
		if ( isset( $data['author_url'] ) ) {
			$data['author_url'] = home_url( '/' );
		}
		return $data;
	}

	/**
	 * Remove the `users` provider from the sitemap so
	 * /wp-sitemap-users-1.xml returns 404 to anonymous probes.
	 *
	 * @param object|false $provider Sitemap provider instance.
	 * @param string       $name     Provider slug.
	 * @return object|false
	 */
	public function disable_user_sitemap_provider( $provider = false, $name = '' ) {
		if ( 'users' === $name ) {
			return false;
		}
		return $provider;
	}

	/**
	 * Strip identifying fields when the REST users endpoint is reached
	 * via `_embed` fan-out. Logged-in users keep the full response;
	 * anonymous callers see only the integer id.
	 *
	 * @param mixed $response WP_REST_Response from rest_prepare_user.
	 * @return mixed
	 */
	public function scrub_rest_user_for_anon( $response = null ) {
		if ( is_user_logged_in() ) {
			return $response;
		}
		if ( ! $response instanceof \WP_REST_Response ) {
			return $response;
		}
		$data = $response->get_data();
		if ( ! is_array( $data ) ) {
			return $response;
		}
		// Keep only id + a neutral name; drop everything that could
		// be reversed to a user_login.
		$scrubbed = [];
		if ( isset( $data['id'] ) ) {
			$scrubbed['id'] = (int) $data['id'];
		}
		$scrubbed['name'] = (string) get_bloginfo( 'name' );
		$response->set_data( $scrubbed );
		return $response;
	}

	// ------------------------------------------------------------------
	// Toggle: obfuscate_author_slugs
	// ------------------------------------------------------------------

	/** @var string Prefix for obfuscated author slugs (also used to detect them on incoming queries). */
	public const AUTHOR_SLUG_PREFIX = 'u-';

	/** @var string User meta key storing the cached obfuscated slug. */
	public const AUTHOR_SLUG_META_KEY = 'login_armor_author_slug';

	/**
	 * Register filters that rewrite author URLs and resolve obfuscated slugs.
	 *
	 * - `author_link` replaces the user_nicename segment with an HMAC-derived token.
	 * - `request` maps an incoming obfuscated `author_name` back to the real user.
	 * - `rest_prepare_user` scrubs `slug` so the REST API never leaks user_nicename
	 *   (defense-in-depth alongside the `restrict_rest_api` toggle).
	 */
	private function register_obfuscate_author_slugs(): void {
		add_filter( 'author_link', [ $this, 'filter_author_link' ], 10, 2 );
		add_filter( 'request', [ $this, 'filter_author_request' ] );
		add_filter( 'rest_prepare_user', [ $this, 'filter_rest_prepare_user' ], 10, 2 );
	}

	/**
	 * Compute the obfuscated slug for a user.
	 *
	 * The slug is derived with `wp_hash()` (HMAC-MD5 keyed by WP's NONCE
	 * constants) so it is deterministic on a given site but cannot be
	 * predicted without access to the site's secret keys. The result is
	 * cached in user_meta on first use to avoid recomputing and to allow
	 * fast reverse lookup via a meta_value query.
	 *
	 * @param int $user_id WordPress user ID.
	 * @return string Obfuscated slug (e.g. "u-a1b2c3d4e5f6"), or an empty string on invalid input.
	 */
	public static function get_author_slug( int $user_id ): string {
		if ( $user_id <= 0 ) {
			return '';
		}

		$cached = (string) get_user_meta( $user_id, self::AUTHOR_SLUG_META_KEY, true );
		if ( '' !== $cached ) {
			return $cached;
		}

		$token = substr( wp_hash( 'la_author_slug|' . $user_id, 'nonce' ), 0, 12 );
		$slug  = self::AUTHOR_SLUG_PREFIX . $token;

		update_user_meta( $user_id, self::AUTHOR_SLUG_META_KEY, $slug );

		return $slug;
	}

	/**
	 * Reverse-lookup an obfuscated slug to its user_id via user_meta.
	 *
	 * @param string $slug Obfuscated slug including prefix.
	 * @return int User ID, or 0 if not found.
	 */
	public static function resolve_author_slug( string $slug ): int {
		if ( '' === $slug || ! str_starts_with( $slug, self::AUTHOR_SLUG_PREFIX ) ) {
			return 0;
		}

		$users = get_users(
			[
				'meta_key'    => self::AUTHOR_SLUG_META_KEY, // phpcs:ignore WordPress.DB.SlowDBQuery.slow_db_query_meta_key
				'meta_value'  => $slug, // phpcs:ignore WordPress.DB.SlowDBQuery.slow_db_query_meta_value
				'number'      => 1,
				'fields'      => 'ID',
				'count_total' => false,
			]
		);

		if ( empty( $users ) ) {
			return 0;
		}

		return (int) $users[0];
	}

	/**
	 * Replace the user_nicename segment in an author URL with the obfuscated slug.
	 *
	 * Uses a scoped regex (`/author/<nicename>(/|$)`) so the substitution can
	 * only hit the author permalink segment: never arbitrary occurrences of
	 * the nicename elsewhere in the URL.
	 *
	 * @param string $link      The original author URL.
	 * @param int    $author_id The author's user ID.
	 * @return string
	 */
	public function filter_author_link( $link = '', $author_id = 0 ) {
		if ( ! is_string( $link ) ) {
			return $link; // Untyped defensively: pass through unexpected values.
		}
		$author_id = (int) $author_id;
		$slug      = self::get_author_slug( $author_id );
		if ( '' === $slug ) {
			return $link;
		}

		$user = get_userdata( $author_id );
		if ( ! $user || '' === (string) $user->user_nicename ) {
			return $link;
		}

		$pattern = '#/author/' . preg_quote( (string) $user->user_nicename, '#' ) . '(/|$)#';
		$result  = preg_replace( $pattern, '/author/' . $slug . '$1', $link, 1 );

		return null === $result ? $link : $result;
	}

	/**
	 * Resolve an incoming obfuscated author_name back to a real user_id.
	 *
	 * Swaps the `author_name` query var for `author` (numeric) so the query
	 * hits the correct user. Requests with a non-matching slug fall through
	 * unchanged, producing a 404: never a disclosure of valid user_logins.
	 *
	 * @param array<string, mixed> $query_vars Parsed query vars.
	 * @return array<string, mixed>
	 */
	public function filter_author_request( $query_vars = array() ) {
		if ( ! is_array( $query_vars ) ) {
			return $query_vars; // Untyped defensively: pass through unexpected values.
		}
		if ( empty( $query_vars['author_name'] ) || ! is_string( $query_vars['author_name'] ) ) {
			return $query_vars;
		}

		$name = $query_vars['author_name'];
		if ( ! str_starts_with( $name, self::AUTHOR_SLUG_PREFIX ) ) {
			return $query_vars;
		}

		$user_id = self::resolve_author_slug( $name );
		if ( $user_id > 0 ) {
			unset( $query_vars['author_name'] );
			$query_vars['author'] = $user_id;
		}

		return $query_vars;
	}

	/**
	 * Remove `slug` (user_nicename) from REST user responses for unauthenticated users.
	 *
	 * @param \WP_REST_Response $response The outgoing response.
	 * @param \WP_User          $user     The user being prepared.
	 * @return \WP_REST_Response
	 */
	public function filter_rest_prepare_user( $response = null, $user = null ) {
		if ( is_user_logged_in() ) {
			return $response;
		}

		if ( ! $response instanceof \WP_REST_Response ) {
			return $response;
		}

		$data = $response->get_data();
		if ( is_array( $data ) && isset( $data['slug'] ) ) {
			unset( $data['slug'] );
			$response->set_data( $data );
		}

		return $response;
	}

	// ------------------------------------------------------------------
	// Toggle: restrict_rest_api
	// ------------------------------------------------------------------

	/**
	 * Restrict REST API access to authenticated users.
	 *
	 * Public endpoints (oEmbed, Contact Form 7, Site Health) are preserved.
	 */
	private function register_restrict_rest_api(): void {
		add_filter( 'rest_authentication_errors', [ $this, 'require_rest_authentication' ] );
	}

	/**
	 * Normalize a raw textarea of REST namespaces into the internal form.
	 *
	 * Users type what they see, so accept `seopress/v1`, `/wp-json/seopress/v1/`
	 * or `wp-json/seopress/v1` and store the single canonical form `seopress/v1/`.
	 * The trailing slash is mandatory: matching is a prefix comparison, so a bare
	 * `seopress/v1` would also open `seopress/v1000/`.
	 *
	 * @since 2.5.1
	 *
	 * @param string $raw Raw textarea content, one namespace per line.
	 * @return array<int, string> Normalized namespaces, deduplicated and capped.
	 */
	public static function normalize_rest_namespaces( string $raw ): array {
		$lines = preg_split( '/[\r\n,]+/', $raw );
		if ( ! is_array( $lines ) ) {
			return [];
		}

		$clean = [];
		foreach ( $lines as $line ) {
			$entry = strtolower( trim( (string) $line ) );
			if ( '' === $entry ) {
				continue;
			}

			// Strip a pasted full REST URL or a leading /wp-json/ prefix.
			$parsed = wp_parse_url( $entry, PHP_URL_PATH );
			if ( is_string( $parsed ) && '' !== $parsed ) {
				$entry = $parsed;
			}
			$entry       = trim( $entry, '/' );
			$rest_prefix = trim( (string) rest_get_url_prefix(), '/' );
			if ( '' !== $rest_prefix && 0 === strpos( $entry, $rest_prefix . '/' ) ) {
				$entry = substr( $entry, strlen( $rest_prefix ) + 1 );
			}

			// Keep only characters a REST namespace can legitimately contain. The
			// dot matters: core ships `oembed/1.0`, and dropping it would turn a
			// correct entry into a silently inert `oembed/10`.
			$entry = preg_replace( '#[^a-z0-9_.\-/]#', '', (string) $entry );
			$entry = trim( (string) $entry, '/' );
			if ( '' === $entry || false !== strpos( $entry, '..' ) ) {
				continue;
			}

			// A REST namespace is always vendor + version (`wp/v2`, `oembed/1.0`,
			// `seopress/v1`). Refusing a single segment is what stops a half-typed
			// `wp` from being auto-saved as `wp/`, which would open every core
			// route to anonymous callers.
			if ( substr_count( $entry, '/' ) < 1 ) {
				continue;
			}

			$clean[] = $entry . '/';
		}

		return array_slice( array_values( array_unique( $clean ) ), 0, self::MAX_REST_NAMESPACES );
	}

	/**
	 * The admin-defined REST namespaces allowed without authentication.
	 *
	 * @since 2.5.1
	 *
	 * @return array<int, string>
	 */
	public static function get_rest_namespaces(): array {
		$stored = get_option( self::OPTION_REST_NAMESPACES, [] );

		return is_array( $stored ) ? array_values( array_filter( $stored, 'is_string' ) ) : [];
	}

	/**
	 * The entries that reopen WordPress core routes to anonymous callers.
	 *
	 * Anything under the `wp/` namespace is core content and accounts, which is
	 * exactly what this toggle exists to close. Computed server-side so the UI
	 * warning cannot drift from what the gate actually allows.
	 *
	 * @since 2.5.1
	 *
	 * @param array<int, string>|null $list Namespaces to inspect; stored ones when null.
	 * @return array<int, string> The risky entries, without their trailing slash.
	 */
	public static function risky_rest_namespaces( ?array $list = null ): array {
		$list   = null === $list ? self::get_rest_namespaces() : $list;
		$risky  = [];

		foreach ( $list as $namespace ) {
			if ( ! is_string( $namespace ) ) {
				continue;
			}
			if ( 0 === strpos( $namespace, 'wp/' ) ) {
				$risky[] = rtrim( $namespace, '/' );
			}
		}

		return $risky;
	}

	/**
	 * The stored namespaces rendered back into textarea form.
	 *
	 * The trailing slash is an implementation detail of the prefix match, so it is
	 * hidden from the field the admin reads and edits.
	 *
	 * @since 2.5.1
	 */
	public static function get_rest_namespaces_textarea(): string {
		$lines = [];
		foreach ( self::get_rest_namespaces() as $namespace ) {
			$lines[] = rtrim( $namespace, '/' );
		}

		return implode( "\n", $lines );
	}

	/**
	 * Return a WP_Error for unauthenticated REST requests, with an allowlist.
	 *
	 * @param \WP_Error|null|true $result Current authentication result.
	 * @return \WP_Error|null|true
	 */
	public function require_rest_authentication( $result = null ) {
		// Pass through if already authenticated or already errored.
		if ( true === $result || is_wp_error( $result ) ) {
			return $result;
		}

		if ( is_user_logged_in() ) {
			return $result;
		}

		// Allowlist public routes by namespace prefix on the parsed REST path,
		// so a payload like `?oembed=trick` cannot bypass the gate.
		//
		// Plain-permalinks support (V2.1.16): when permalink_structure is empty,
		// WordPress routes REST requests via `?rest_route=/<ns>/<route>` instead
		// of the `/wp-json/<ns>/<route>` rewrite. The old single-source detection
		// missed those entirely, so legitimate oEmbed/CF7/Site-Health calls
		// always returned 403. Resolve $route from both sources, with rest_route
		// taking precedence when present.
		$route = '';
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Read-only routing inspection, not form processing.
		if ( isset( $_GET['rest_route'] ) ) {
			// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- same rationale.
			$route = ltrim( sanitize_text_field( wp_unslash( (string) $_GET['rest_route'] ) ), '/' );
		} else {
			$rest_prefix = trailingslashit( rest_get_url_prefix() ); // 'wp-json/'.
			$request_uri = isset( $_SERVER['REQUEST_URI'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '';
			$path        = (string) wp_parse_url( $request_uri, PHP_URL_PATH );
			$pos         = strpos( $path, $rest_prefix );
			if ( false !== $pos ) {
				$route = ltrim( substr( $path, $pos + strlen( $rest_prefix ) ), '/' );
			}
		}

		if ( '' !== $route ) {
			/**
			 * Filter the list of REST API namespaces allowed for unauthenticated access.
			 *
			 * The list passed in is the built-in set (oembed/, contact-form-7/,
			 * wp-site-health/) plus whatever the admin entered in the Hardening
			 * section. Since 2.5.1 that field covers the common case, so this filter
			 * is only needed to compute the list dynamically or to remove an entry.
			 *
			 * Example:
			 *     add_filter( 'login_armor_rest_public_namespaces', function ( $list ) {
			 *         $list[] = 'wpforms/';
			 *         return $list;
			 *     } );
			 *
			 * @since 2.1.1
			 *
			 * @param array<int,string> $public_namespaces Namespaces (with trailing slash) allowed without auth.
			 */
			$public_namespaces = apply_filters(
				'login_armor_rest_public_namespaces',
				array_values(
					array_unique(
						array_merge( self::DEFAULT_REST_NAMESPACES, self::get_rest_namespaces() )
					)
				)
			);
			if ( is_array( $public_namespaces ) ) {
				foreach ( $public_namespaces as $namespace ) {
					if ( ! is_string( $namespace ) || '' === $namespace ) {
						continue;
					}
					if ( 0 === strpos( $route, $namespace ) ) {
						return $result;
					}
				}
			}
		}

		return new \WP_Error(
			'rest_forbidden',
			__( 'REST API access restricted to authenticated users.', 'login-armor' ),
			[ 'status' => 403 ]
		);
	}

	// ------------------------------------------------------------------
	// Toggle: protect_system_files
	// ------------------------------------------------------------------

	/**
	 * Nothing to do per request: the protection is a server rule (2.8.0).
	 *
	 * Until 2.7.10 this toggle hooked `init` and answered 403 when the URL
	 * named one of the three files. It never protected anything: readme.html
	 * and license.txt are static files, which Apache, LiteSpeed and nginx
	 * serve without starting PHP, and wp-config-sample.php dies on its
	 * database connection before any plugin loads. The only requests that
	 * ever reached the check were WordPress URLs that happened to contain
	 * "/license.txt", answered with a false 403, while the toggle counted in
	 * the security score. The rule now lives in the root .htaccess, written
	 * by sync_htaccess() like the directory-listing one, and is put back on
	 * any request that finds it missing, as that one is.
	 */
	private function register_protect_system_files(): void {
		self::write_system_files_block( self::system_files_htaccess_path(), false );
	}

	/**
	 * The root .htaccess block that refuses the three system files (2.8.0).
	 *
	 * A rewrite rule, not an access-control directive. Apache accepts
	 * `Require` in an .htaccess only under AllowOverride AuthConfig, and
	 * `Order`/`Deny` only under Limit: written where they are not allowed,
	 * either one answers 500 for the whole site, administration included.
	 * A rewrite rule needs FileInfo, which is what WordPress's own permalink
	 * rules need, and it is the one kind of .htaccess rule OpenLiteSpeed
	 * reads. The pattern matches in every directory below the root, which
	 * also covers the copies plugins and themes ship.
	 */
	public static function system_files_block(): string {
		return self::MARKER_SYSFILES_BEGIN . "\n"
			. "<IfModule mod_rewrite.c>\n"
			. "RewriteEngine On\n"
			. 'RewriteRule (^|/)(readme\.html|license\.txt|wp-config-sample\.php)$ - [F]' . "\n"
			. "</IfModule>\n"
			. self::MARKER_SYSFILES_END . "\n";
	}

	/**
	 * Write, or refresh, the system-files block in the root .htaccess (2.8.0).
	 *
	 * Same rule as the directory-listing block: a site without a root
	 * .htaccess is not running an Apache-style server, and creating one would
	 * be a surprise, so nothing is written there.
	 *
	 * Nor is anything written to a file that runs no rewrite rule of its own
	 * (WordPress writes one for pretty permalinks): whether this server
	 * allows them in an .htaccess is then unknown, and a refused directive
	 * there is a 500 on every page. The administrator is told instead.
	 *
	 * @param string $path   Full path to the root .htaccess file.
	 * @param bool   $report Record a refusal. False for the per-request check,
	 *                       which would otherwise rewrite the record on every
	 *                       page view of a site without pretty permalinks.
	 * @return bool True when the file holds the wanted block afterwards, or when there is no file to hold it.
	 */
	public static function write_system_files_block( string $path, bool $report = true ): bool {
		if ( ! file_exists( $path ) ) {
			return true;
		}
		if ( self::block_already_in_place( $path, self::system_files_block(), self::MARKER_SYSFILES_BEGIN, self::MARKER_SYSFILES_END ) ) {
			return true;
		}

		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents
		$read = @file_get_contents( $path );
		if ( false === $read ) {
			if ( $report ) {
				set_transient( self::TRANSIENT_HTACCESS_FAILED, $path, MINUTE_IN_SECONDS * 5 );
				self::record_htaccess_failure( $path, 'read' );
			}
			return false;
		}
		if ( ! self::runs_rewrite_rules( (string) $read ) ) {
			if ( $report ) {
				set_transient( self::TRANSIENT_HTACCESS_FAILED, $path, MINUTE_IN_SECONDS * 5 );
				self::record_htaccess_failure( $path, 'no_rewrite' );
			}
			return false;
		}

		return self::sync_marked_block( $path, self::system_files_block(), self::MARKER_SYSFILES_BEGIN, self::MARKER_SYSFILES_END );
	}

	/**
	 * Does this .htaccess run rewrite rules of its own, outside our blocks? (2.8.0)
	 *
	 * @param string $contents The file's contents.
	 */
	public static function runs_rewrite_rules( string $contents ): bool {
		foreach ( array( array( self::MARKER_SYSFILES_BEGIN, self::MARKER_SYSFILES_END ), array( self::MARKER_UPLOADS_ROOT_BEGIN, self::MARKER_UPLOADS_ROOT_END ) ) as $markers ) {
			$found = self::find_marked_block( $contents, $markers[0], $markers[1] );
			if ( self::BLOCK_COMPLETE === $found['status'] ) {
				$contents = substr( $contents, 0, $found['start'] ) . substr( $contents, $found['end'] );
			}
		}
		foreach ( preg_split( '/\r\n|\r|\n/', $contents ) ?: array() as $line ) {
			if ( preg_match( '/^\s*RewriteEngine\s+on\b/i', $line ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * The root .htaccess, computed in one place (2.8.0: three blocks live there now).
	 *
	 * 2.8.3: in the directory the site is served from, which is not always
	 * ABSPATH. See wordpress_root_dir().
	 */
	private static function root_htaccess_path(): string {
		return self::wordpress_root_dir() . '.htaccess';
	}

	/**
	 * Where 2.8.0 to 2.8.2 looked for the root .htaccess: ABSPATH (2.8.3).
	 *
	 * The same file as root_htaccess_path() on a standard install. Elsewhere
	 * it may still carry blocks those versions wrote, so the removers clean it
	 * too and the 2.8.3 upgrade step moves them to the root.
	 */
	private static function legacy_root_htaccess_path(): string {
		return wp_normalize_path( ABSPATH . '.htaccess' );
	}

	/**
	 * Every root .htaccess this plugin may have written to (2.8.3).
	 *
	 * @return string[] The root file, then the ABSPATH one when it differs.
	 */
	private static function root_htaccess_paths(): array {
		return array_values( array_unique( array( self::root_htaccess_path(), self::legacy_root_htaccess_path() ) ) );
	}

	/**
	 * The .htaccess whose rewrite rules govern a directory (2.8.3).
	 *
	 * Apache does not pass a parent's rewrite rules down to a directory whose
	 * own .htaccess runs rewrite rules (no `RewriteOptions Inherit` by
	 * default). So when WordPress's directory is not the root and carries an
	 * .htaccess with rewrite rules of its own, a rule for the files below it
	 * has to sit there: the root's is never read for them. Measured on the
	 * Bedrock bench: with a web/wp/.htaccess running rewrite rules, the
	 * system-files rule moved to web/.htaccess left readme.html at 200, where
	 * 2.8.2 had it at 403. Everything else goes to the root.
	 *
	 * @param string $dir The directory the rule is about.
	 */
	private static function rewrite_htaccess_path_for( string $dir ): string {
		$root   = self::root_htaccess_path();
		$legacy = self::legacy_root_htaccess_path();
		if ( $legacy === $root || ! is_file( $legacy ) || ! str_starts_with( trailingslashit( wp_normalize_path( $dir ) ), trailingslashit( wp_normalize_path( ABSPATH ) ) ) ) {
			return $root;
		}

		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents
		return self::runs_rewrite_rules( (string) @file_get_contents( $legacy ) ) ? $legacy : $root;
	}

	/**
	 * The .htaccess that carries the system-files rule (2.8.3): readme.html,
	 * license.txt and wp-config-sample.php live in WordPress's directory.
	 */
	private static function system_files_htaccess_path(): string {
		return self::rewrite_htaccess_path_for( ABSPATH );
	}

	/**
	 * The .htaccess that carries the uploads rule (2.8.3).
	 */
	private static function uploads_root_htaccess_path(): string {
		return self::rewrite_htaccess_path_for( self::uploads_base_dir() );
	}

	/**
	 * The network's uploads base directory, normalized, without a trailing slash (2.8.3).
	 *
	 * Not one site's: on a multisite every site's files live below it, in
	 * sites/<id>.
	 */
	private static function uploads_base_dir(): string {
		$upload_dir = wp_get_upload_dir();
		$dir        = untrailingslashit( wp_normalize_path( (string) ( $upload_dir['basedir'] ?? '' ) ) );

		return (string) preg_replace( '#/sites/[0-9]+$#', '', $dir );
	}

	/**
	 * The directory the site is served from, where WordPress keeps its own .htaccess (2.8.3).
	 *
	 * ABSPATH on a standard install. Under Roots Bedrock ABSPATH is web/wp/
	 * while the site is served from web/, and the same holds for any
	 * WordPress "in its own directory": up to 2.8.2 the root blocks were aimed
	 * at a file that does not exist there, and the toggles showed on with no
	 * rule behind them. Core's get_home_path() is not used: it reads
	 * $_SERVER['SCRIPT_FILENAME'], which names WordPress's directory on an
	 * admin request only, and these writers also run on front-end requests,
	 * from cron and under WP-CLI.
	 *
	 * @return string Normalized path with a trailing slash.
	 */
	public static function wordpress_root_dir(): string {
		$dir = self::root_dir_for( ABSPATH, (string) get_option( 'home', '' ), (string) get_option( 'siteurl', '' ) );

		/**
		 * Filters the directory that holds the site's root .htaccess.
		 *
		 * For a layout the derivation cannot guess. A value that is not an
		 * existing directory is ignored.
		 *
		 * @since 2.8.3
		 *
		 * @param string $dir Normalized path with a trailing slash.
		 */
		$filtered = apply_filters( 'login_armor_htaccess_root_dir', $dir );
		if ( is_string( $filtered ) && '' !== $filtered && is_dir( $filtered ) ) {
			return trailingslashit( wp_normalize_path( $filtered ) );
		}

		return $dir;
	}

	/**
	 * The site's root directory, from ABSPATH and the two stored addresses (2.8.3).
	 *
	 * When the WordPress address (`siteurl`) is the site address (`home`) plus
	 * a path, /wp under Bedrock, and ABSPATH ends with that same path, the root
	 * is ABSPATH without it, provided it holds the index.php that serves the
	 * site. Anything else keeps ABSPATH: the same address, another host with
	 * the same path (a headless network), WordPress beside the site rather
	 * than below it.
	 *
	 * @param string $abspath ABSPATH.
	 * @param string $home    The site address.
	 * @param string $siteurl The WordPress address.
	 * @return string Normalized path with a trailing slash.
	 */
	public static function root_dir_for( string $abspath, string $home, string $siteurl ): string {
		$abspath   = trailingslashit( wp_normalize_path( $abspath ) );
		$home_path = untrailingslashit( rawurldecode( (string) wp_parse_url( $home, PHP_URL_PATH ) ) );
		$site_path = untrailingslashit( rawurldecode( (string) wp_parse_url( $siteurl, PHP_URL_PATH ) ) );

		if ( '' === $site_path || ! str_starts_with( $site_path, $home_path . '/' ) ) {
			return $abspath;
		}

		$suffix = substr( $site_path, strlen( $home_path ) ) . '/';
		if ( ! str_ends_with( $abspath, $suffix ) ) {
			return $abspath;
		}

		$candidate = substr( $abspath, 0, strlen( $abspath ) - strlen( $suffix ) + 1 );

		return is_file( $candidate . 'index.php' ) ? $candidate : $abspath;
	}

	/**
	 * Move the root blocks 2.8.0 to 2.8.2 wrote into an ABSPATH .htaccess (2.8.3).
	 *
	 * Called by the 2.8.3 upgrade step. Nothing to do on a standard install,
	 * where both are the same file. Otherwise the blocks of the toggles that
	 * are on are written where they now belong, and a block leaves the old
	 * file only once the root carries it and the old file is no longer the
	 * one that governs its files: with no root .htaccess to receive them, the
	 * old blocks are the only rules in force and they stay; and a WordPress
	 * directory whose .htaccess runs rewrite rules keeps the system-files
	 * rule, which the root's could not replace there.
	 */
	public static function relocate_legacy_root_blocks(): void {
		$legacy = self::legacy_root_htaccess_path();
		$root   = self::root_htaccess_path();
		if ( $legacy === $root ) {
			return;
		}

		self::restore_htaccess_blocks();

		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents
		$in_root = file_exists( $root ) ? (string) @file_get_contents( $root ) : '';
		if ( str_contains( $in_root, self::MARKER_INDEXES_BEGIN ) ) {
			self::remove_directory_listing_htaccess( $legacy );
		}
		if ( $legacy !== self::system_files_htaccess_path() && str_contains( $in_root, self::MARKER_SYSFILES_BEGIN ) ) {
			self::remove_system_files_htaccess( $legacy );
		}
		if ( $legacy !== self::uploads_root_htaccess_path() && str_contains( $in_root, self::MARKER_UPLOADS_ROOT_BEGIN ) ) {
			self::remove_uploads_root_block( $legacy );
		}
	}

	/**
	 * Remove the system-files block from the root .htaccess (2.8.0).
	 *
	 * The root file itself is never deleted, as for the directory-listing block.
	 *
	 * @param string|null $path One file, or null for every root .htaccess
	 *                          this plugin may have written to (2.8.3).
	 */
	public static function remove_system_files_htaccess( ?string $path = null ): void {
		foreach ( null === $path ? self::root_htaccess_paths() : array( $path ) as $file ) {
			self::strip_marked_block( $file, self::MARKER_SYSFILES_BEGIN, self::MARKER_SYSFILES_END, '', false );
		}
	}

	/**
	 * Write the blocks of the toggles that are on, and never remove one (2.8.0).
	 *
	 * The counterpart of remove_htaccess_blocks(), for activation and for the
	 * 2.8.0 upgrade step. Unlike sync_htaccess() it never strips a block: on a
	 * network the root .htaccess is shared, and a site whose toggles are off
	 * must not take away the rules another site switched on.
	 */
	public static function restore_htaccess_blocks(): void {
		$settings = self::get_settings();

		if ( ! empty( $settings['block_php_uploads'] ) ) {
			$upload_dir = wp_get_upload_dir();
			self::write_uploads_htaccess( trailingslashit( $upload_dir['basedir'] ) . '.htaccess' );
			self::write_uploads_root_block( self::uploads_root_htaccess_path() );
		}
		if ( ! empty( $settings['disable_directory_listing'] ) && file_exists( self::root_htaccess_path() ) ) {
			self::write_directory_listing_block( self::root_htaccess_path() );
		}
		if ( ! empty( $settings['protect_system_files'] ) ) {
			self::write_system_files_block( self::system_files_htaccess_path() );
		}
	}

	/**
	 * Take this plugin's server rules out, on deactivation and on uninstall (2.8.0).
	 *
	 * Until 2.7.10 the blocks stayed in place once the plugin was off, and
	 * even once it was deleted: a server rule nobody could see the source of
	 * any more, for whoever needs PHP in uploads or is diagnosing a 403. Only
	 * the marked blocks go; the administrator's own rules, the .bak restore
	 * point and the .lock file stay, exactly as when a toggle is switched off.
	 * restore_htaccess_blocks() puts them back on the next activation.
	 *
	 * @param bool $root Also the root .htaccess blocks. False on a single
	 *                   site of a network: the root file is shared with the
	 *                   sites where the plugin stays active.
	 */
	public static function remove_htaccess_blocks( bool $root = true ): void {
		self::remove_uploads_htaccess();
		if ( $root ) {
			self::remove_directory_listing_htaccess();
			self::remove_system_files_htaccess();
			self::remove_uploads_root_block();
		}
	}

	// ------------------------------------------------------------------
	// Toggle: disable_directory_listing
	// ------------------------------------------------------------------

	/**
	 * Register the directory listing protection.
	 *
	 * This toggle works by sending a 403 for requests that end with / and would
	 * normally show a directory index. The actual Options -Indexes is managed
	 * via the htaccess sync hook.
	 */
	private function register_disable_directory_listing(): void {
		$this->maybe_write_directory_listing_htaccess();
	}

	/**
	 * Ensure Options -Indexes is present in root .htaccess.
	 *
	 * Atomic write via temp + rename so a failed flush does not leave the
	 * site .htaccess truncated.
	 */
	private function maybe_write_directory_listing_htaccess(): void {
		$htaccess = self::root_htaccess_path();

		// A site without a root .htaccess is not running Apache-style config;
		// creating one here would be a surprise, so this path stays read-only.
		if ( ! file_exists( $htaccess ) ) {
			return;
		}

		self::write_directory_listing_block( $htaccess );
	}

	/**
	 * Write, or refresh, the directory-listing block in an .htaccess file.
	 *
	 * Split out of `maybe_write_directory_listing_htaccess()` so the path is
	 * a parameter rather than an ABSPATH computation: the shared writers must
	 * stay reusable and testable off a real WordPress root.
	 *
	 * @param string $path Full path to the root .htaccess file.
	 * @return bool True when the file holds the wanted block afterwards.
	 */
	public static function write_directory_listing_block( string $path ): bool {
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents
		$read = @file_get_contents( $path );
		if ( false === $read ) {
			set_transient( self::TRANSIENT_HTACCESS_FAILED, $path, MINUTE_IN_SECONDS * 5 );
			self::record_htaccess_failure( $path, 'read' );
			return false;
		}

		$contents = (string) $read;
		if ( '' === $contents ) {
			return true;
		}

		// Someone else (the admin, another plugin) may already disable the
		// listing outside our markers; a second directive would be noise.
		// Our own block does not count, or the toggle could never refresh it.
		$found = self::find_marked_block( $contents, self::MARKER_INDEXES_BEGIN, self::MARKER_INDEXES_END );
		if ( self::BLOCK_ABSENT === $found['status'] && str_contains( $contents, 'Options -Indexes' ) ) {
			return true;
		}

		$block = self::MARKER_INDEXES_BEGIN . "\nOptions -Indexes\n" . self::MARKER_INDEXES_END . "\n";

		return self::sync_marked_block( $path, $block, self::MARKER_INDEXES_BEGIN, self::MARKER_INDEXES_END );
	}

	/**
	 * Remove the Options -Indexes line from root .htaccess.
	 *
	 * Strips only the bytes between the `# BEGIN/END LoginArmor` markers, so
	 * admin rules on either side survive. Falls back to the legacy block
	 * string for sites upgraded from a version that never wrote an END
	 * marker. An ambiguous block is reported and left alone. Unlike the
	 * uploads file, the root .htaccess is never deleted, even when nothing
	 * but whitespace is left: other software expects it to exist.
	 *
	 * @param string|null $path One file, or null for every root .htaccess
	 *                          this plugin may have written to (2.8.3).
	 */
	public static function remove_directory_listing_htaccess( ?string $path = null ): void {
		foreach ( null === $path ? self::root_htaccess_paths() : array( $path ) as $htaccess ) {
			self::strip_marked_block(
				$htaccess,
				self::MARKER_INDEXES_BEGIN,
				self::MARKER_INDEXES_END,
				// Legacy block written before BEGIN/END markers existed.
				"\n# LoginArmor \u{2014} Disable directory listing\nOptions -Indexes\n",
				false
			);
		}
	}

	// ------------------------------------------------------------------
	// .htaccess sync: toggle changes write/remove rules
	// ------------------------------------------------------------------

	/**
	 * Sync .htaccess rules when hardening settings are updated.
	 *
	 * Three callers, all after the toggles have been persisted:
	 *   - Admin::ajax_save_hardening(), when an admin saves the tab;
	 *   - Setup\SafeBaseline::apply(), when the guided baseline runs;
	 *   - Settings\Importer::apply(), when an import changes either of the
	 *     two toggles backed by an .htaccess file.
	 *
	 * None of them can be trusted to run on a file this plugin alone owns,
	 * which is why every writer below only ever rewrites its own block.
	 */
	public static function sync_htaccess(): bool {
		$settings = self::get_settings();
		$before   = self::$htaccess_failures;

		// Block PHP in uploads.
		$upload_dir = wp_get_upload_dir();
		$htaccess   = trailingslashit( $upload_dir['basedir'] ) . '.htaccess';

		if ( ! empty( $settings['block_php_uploads'] ) ) {
			self::write_uploads_htaccess( $htaccess );
			self::write_uploads_root_block( self::uploads_root_htaccess_path() );
		} else {
			self::remove_uploads_htaccess();
			self::remove_uploads_root_block();
		}

		// Directory listing.
		if ( ! empty( $settings['disable_directory_listing'] ) ) {
			( new self() )->maybe_write_directory_listing_htaccess();
		} else {
			self::remove_directory_listing_htaccess();
		}

		// System files (2.8.0).
		if ( ! empty( $settings['protect_system_files'] ) ) {
			self::write_system_files_block( self::system_files_htaccess_path() );
		} else {
			self::remove_system_files_htaccess();
		}

		// Nothing recorded a failure or an ambiguity: whatever went wrong last
		// time has been repaired, and a record that outlives its problem sends
		// its reader chasing something that is already fixed.
		if ( $before === self::$htaccess_failures ) {
			delete_option( self::OPTION_HTACCESS_LAST_FAILURE );

			return true;
		}

		// 2.7.1: this used to return void, and every caller ignored it because
		// there was nothing to ignore. ajax_save_hardening() therefore answered
		// `saved: true` whatever happened here, so the toggle showed as ON
		// while the file did not carry the rule. A protection displayed as
		// active but not applied is the worst thing a security plugin can put
		// on a screen, and it was reachable from one failed file write.
		return false;
	}

	// ------------------------------------------------------------------
	// Toggle: disable_pingbacks
	// ------------------------------------------------------------------

	/**
	 * Neutralize XML-RPC pingbacks without disabling XML-RPC wholesale.
	 */
	private function register_disable_pingbacks(): void {
		add_filter( 'xmlrpc_methods', [ $this, 'remove_pingback_methods' ] );
		add_filter( 'wp_headers', [ $this, 'remove_pingback_header' ] );
		add_filter( 'bloginfo_url', [ $this, 'strip_pingback_url' ], 10, 2 );
	}

	/**
	 * Remove the pingback XML-RPC methods.
	 *
	 * @param mixed $methods Registered XML-RPC methods.
	 * @return mixed
	 */
	public function remove_pingback_methods( $methods = array() ) {
		if ( is_array( $methods ) ) {
			unset( $methods['pingback.ping'], $methods['pingback.extensions.getPingbacks'] );
		}
		return $methods;
	}

	/**
	 * Strip the X-Pingback response header.
	 *
	 * @param mixed $headers Response headers.
	 * @return mixed
	 */
	public function remove_pingback_header( $headers = array() ) {
		if ( is_array( $headers ) ) {
			unset( $headers['X-Pingback'] );
		}
		return $headers;
	}

	/**
	 * Blank out the pingback URL exposed via bloginfo('pingback_url').
	 *
	 * @param string $output The bloginfo value.
	 * @param string $show   Which bloginfo key is requested.
	 * @return string
	 */
	public function strip_pingback_url( $output = '', $show = '' ) {
		if ( 'pingback_url' === $show ) {
			return '';
		}
		return $output;
	}

	// ------------------------------------------------------------------
	// Toggle: alert_admin_creation
	// ------------------------------------------------------------------

	/**
	 * Watch for new or newly-promoted administrator accounts.
	 */
	private function register_alert_admin_creation(): void {
		add_action( 'user_register', [ $this, 'check_new_user_role' ], 20, 1 );
		add_action( 'set_user_role', [ $this, 'check_role_change' ], 20, 3 );
	}

	/**
	 * Fire an alert when a freshly-created account has the administrator role.
	 *
	 * @param int $user_id The newly created user ID.
	 */
	public function check_new_user_role( $user_id = 0 ): void {
		$user = get_userdata( (int) $user_id );
		if ( $user instanceof \WP_User && in_array( 'administrator', (array) $user->roles, true ) ) {
			$this->fire_admin_alert( (int) $user_id, 'created' );
		}
	}

	/**
	 * Fire an alert when an existing account is promoted to administrator.
	 * The creation-time role assignment (empty $old_roles) is skipped: that
	 * case is already covered by {@see check_new_user_role()} on user_register.
	 *
	 * @param int      $user_id   The user whose role changed.
	 * @param string   $role      The new role.
	 * @param string[] $old_roles The previous roles.
	 */
	public function check_role_change( $user_id = 0, $role = '', $old_roles = array() ): void {
		if ( 'administrator' === $role
			&& ! empty( $old_roles )
			&& ! in_array( 'administrator', (array) $old_roles, true ) ) {
			$this->fire_admin_alert( (int) $user_id, 'promoted' );
		}
	}

	/**
	 * Notify the site administrator and fire an extensibility hook when an
	 * administrator account appears. Never blocks the operation: this is a
	 * detection signal, not an access control.
	 *
	 * @param int    $user_id The affected user ID.
	 * @param string $context Either 'created' or 'promoted'.
	 */
	private function fire_admin_alert( int $user_id, string $context ): void {
		$user  = get_userdata( $user_id );
		$login = $user instanceof \WP_User ? $user->user_login : (string) $user_id;
		$email = $user instanceof \WP_User ? $user->user_email : '';

		/**
		 * Fires when Login Armor detects a new or newly-promoted administrator.
		 *
		 * @param int    $user_id The affected user ID.
		 * @param string $context 'created' or 'promoted'.
		 */
		do_action( 'login_armor_admin_account_alert', $user_id, $context );

		$site = wp_specialchars_decode( (string) get_option( 'blogname' ), ENT_QUOTES );

		$subject = sprintf(
			/* translators: %s: site name. */
			__( '[%s] New administrator account detected', 'login-armor' ),
			$site
		);

		if ( 'promoted' === $context ) {
			$line = sprintf(
				/* translators: 1: user login, 2: user email. */
				__( 'The account "%1$s" (%2$s) was just promoted to the administrator role.', 'login-armor' ),
				$login,
				$email
			);
		} else {
			$line = sprintf(
				/* translators: 1: user login, 2: user email. */
				__( 'A new account "%1$s" (%2$s) was just created with the administrator role.', 'login-armor' ),
				$login,
				$email
			);
		}

		$body = $line . "\n\n" . __( 'If this was expected, no action is needed. If not, review the account immediately: unexpected administrator accounts are a common sign of compromise.', 'login-armor' );

		wp_mail( (string) get_option( 'admin_email' ), $subject, $body );
	}

	// ------------------------------------------------------------------
	// Toggle: force_https (2.7.0)
	//
	// Three effects, and nothing else:
	//   1. an HTTP request is answered with a redirect to the same URL on
	//      https, computed from the site's own address (never from a Host
	//      header the client controls);
	//   2. force_ssl_admin( true ), so WordPress builds admin URLs on https
	//      and auth_redirect() refuses a plain-HTTP admin;
	//   3. the two auth cookies are marked Secure.
	//
	// ROLLBACK PROMISE. Turning the toggle off removes exactly those three
	// and nothing more. It does not touch `home`, `siteurl`, `.htaccess`,
	// FORCE_SSL_ADMIN or any HSTS header: if WordPress still forces the
	// admin afterwards, it is because the site address is https:// or the
	// constant is defined in wp-config.php, and neither is ours to undo.
	//
	// A FOURTH effect, which is per-request and leaves nothing behind but is
	// the widest of the four: $_SERVER['HTTPS'] is set to 'on' when a
	// TRUSTED proxy reports https. That flips is_ssl() for the whole
	// request, and is_ssl() decides the scheme get_home_url() returns, which
	// auth cookie core writes and reads, and whether LoginHeaders sends
	// HSTS. Nothing of it survives the request, so the rollback promise
	// holds; but the enumeration would be wrong at three without it.
	//
	// BEHIND A TERMINATOR. PHP sees a plain HTTP connection from the proxy,
	// so is_ssl() is false and core's own `force_ssl_admin() && ! is_ssl()`
	// redirect in wp-login.php would bounce forever. That is why
	// $_SERVER['HTTPS'] is set to 'on' as soon as the forwarded protocol is
	// https AND the peer is on the trusted-proxy list: from that point core
	// agrees with reality and no loop can form.
	//
	// THE LOOP GUARD, and why it gates all four effects rather than just the
	// redirect. A terminator that is not on the trusted list is not a
	// hypothetical: a CDN egress range rotates, a load balancer gets a new
	// address, a site moves behind another proxy. No administrator acts, and
	// the enable-time refusal never gets a chance to fire. In that state
	// is_ssl() is false on every request, and each of the three visible
	// effects is independently fatal:
	//
	//   - the redirect sends an https client back to the same https URL,
	//     forever;
	//   - force_ssl_admin( true ) makes core's own auth_redirect() do the
	//     same for /wp-admin, so removing only our redirect would move the
	//     loop into core rather than close it;
	//   - the cookie filters are worse than either. wp_set_auth_cookie()
	//     writes SECURE_AUTH_COOKIE when the filter says secure, while
	//     wp_parse_auth_cookie() reads AUTH_COOKIE when is_ssl() is false.
	//     The cookie that gets minted is one nothing ever reads back, so
	//     nobody can stay signed in at all.
	//
	// So when something upstream says https and this site may not believe
	// it, the module registers NOTHING, records a marker, and says so in the
	// admin. The site keeps working over the TLS its terminator is already
	// doing; declaring the proxy brings every effect back, and the marker
	// removes itself. Refusing to believe the header for anything
	// security-bearing is unchanged: all an attacker gains by sending it is
	// not being redirected to https for their own request, which they could
	// have had by not following the redirect.
	// ------------------------------------------------------------------

	/**
	 * Set while a terminator reports https from an address this site does not
	 * declare as a proxy. Autoload is off: it is absent on every healthy
	 * site, so WordPress's notoptions cache makes the read free anyway.
	 *
	 * @since 2.7.0
	 */
	public const OPTION_TERMINATOR_UNDECLARED = 'login_armor_https_terminator_undeclared';

	// ------------------------------------------------------------------
	// WHOSE ADDRESS IS IN THAT MARKER, and why it is not an instruction.
	//
	// The marker is written exactly when an UNTRUSTED peer sends a
	// forwarded-protocol header claiming https. Any visitor can produce that
	// with one request. So a notice that told an administrator to add the
	// recorded address to Trusted proxies would be a way for an attacker to
	// have this plugin ask its own administrator to trust the attacker: and
	// an address on that list is believed when it declares the visitor's IP,
	// which is the identity every lockout, quota and ban in this plugin rests
	// on. That would be a worse outcome than the redirect loop the marker
	// exists to report.
	//
	// Three things keep it honest, and none of them costs the legitimate case
	// anything, because a real terminator is in front of EVERY request while
	// a probe is usually one:
	//
	//   1. the notice presents an OBSERVATION, never an instruction, and says
	//      in the same breath that anyone on the internet can cause it, so
	//      the address has to be confirmed against what the host or the CDN
	//      documents before it is trusted;
	//   2. the distinct peers are counted, to a small bound, because that is
	//      the one thing that tells the two apart: a terminator is one
	//      address or a small stable set, forgery is many. The notice says so
	//      out loud as soon as a second address appears;
	//   3. nothing is shown at all until the SAME peer has been seen twice,
	//      which a terminator reaches on its second request and a one-shot
	//      probe never reaches.
	//
	// The write rate is bounded by construction, so no amount of traffic can
	// make the notice churn: a peer whose count has reached the threshold is
	// never written again, new peers stop being recorded at the cap, and the
	// "more than we record" flag is written once. Over the whole life of the
	// situation that is at most MAX_TERMINATOR_PEERS * TERMINATOR_SIGHTINGS
	// + 1 writes, whoever sends what, in whatever order.
	// ------------------------------------------------------------------

	/** How many distinct peers are recorded before the rest become a count. */
	private const MAX_TERMINATOR_PEERS = 5;

	/** How often one peer must be seen before the notice says anything. */
	private const TERMINATOR_SIGHTINGS = 2;

	/**
	 * Whether the plugin's redirect must exit the request. Tests only.
	 *
	 * Honoured only while LOGIN_ARMOR_TESTING is defined, exactly like
	 * `$write_bytes_override`: a site can never reach this.
	 */
	private static bool $exit_on_redirect = true;

	/**
	 * Let the offline suite observe the redirect instead of dying on it.
	 *
	 * @param bool $exit Whether send_redirect() should still exit().
	 */
	public static function set_exit_on_redirect( bool $exit ): void {
		if ( ! defined( 'LOGIN_ARMOR_TESTING' ) || ! LOGIN_ARMOR_TESTING ) {
			return;
		}
		self::$exit_on_redirect = $exit;
	}

	/**
	 * Register the three effects of the toggle.
	 *
	 * WP-CLI and cron are excluded: both run without a browser, both are
	 * routinely driven over the loopback in plain HTTP, and a redirect there
	 * would turn `wp option patch update ... force_https false` (the
	 * documented way out) into a command that cannot run.
	 */
	private function register_force_https(): void {
		// SAFE MODE, and the WHOLE module rather than the redirect alone, for
		// the same reason the undeclared-terminator guard below stands it all
		// down: force_ssl_admin( true ) on its own moves the loop into core's
		// auth_redirect(), and the two cookie filters on their own are worse
		// still, because wp_set_auth_cookie() takes SECURE_AUTH_COOKIE from
		// the FILTERED value while wp_parse_auth_cookie() takes the name from
		// is_ssl(), so a session is minted that nothing reads back. Half a
		// stand-down is a hard lockout, and this constant exists to END one.
		//
		// First, before trust_forwarded_https(): that one writes to $_SERVER
		// and flips is_ssl() for everything downstream, so a check placed any
		// later would leave the widest of the four effects standing.
		if ( ! self::force_https_effective() ) {
			return;
		}

		if ( ! self::force_https_applies( defined( 'WP_CLI' ) && WP_CLI, wp_doing_cron() ) ) {
			return;
		}

		self::trust_forwarded_https();

		// The loop guard. `! request_is_https() && forwarded_proto_is_https()`
		// is exactly "something upstream says https and we may not believe
		// it": had the peer been trusted, the first half would be false.
		if ( ! LoginArmor::request_is_https() && LoginArmor::forwarded_proto_is_https() ) {
			self::flag_undeclared_terminator();
			return;
		}
		self::clear_undeclared_terminator();

		force_ssl_admin( true );
		add_filter( 'secure_auth_cookie', [ $this, 'force_secure_cookie' ] );
		add_filter( 'secure_logged_in_cookie', [ $this, 'force_secure_cookie' ] );

		// init, priority 0: after every plugin has loaded (so a site can still
		// unhook this), and before auth_redirect() and before wp-login.php's
		// own force_ssl_admin() check, both of which run after init.
		add_action( 'init', [ $this, 'maybe_redirect_to_https' ], 0 );
	}

	/**
	 * Count one sighting of an undeclared terminator, or forgery of one.
	 *
	 * Every exit that is not a write is deliberate: see the block above the
	 * two constants for why the rate is bounded and what the counts are for.
	 */
	private static function flag_undeclared_terminator(): void {
		$peer = isset( $_SERVER['REMOTE_ADDR'] )
			? sanitize_text_field( wp_unslash( (string) $_SERVER['REMOTE_ADDR'] ) )
			: '';
		if ( '' === $peer ) {
			return;
		}

		$state = self::terminator_state();

		if ( isset( $state['peers'][ $peer ] ) ) {
			if ( $state['peers'][ $peer ] >= self::TERMINATOR_SIGHTINGS ) {
				// Nothing left to learn about this one. This is what stops a
				// peer that alternates with another from making the marker,
				// and the notice, flap.
				return;
			}
			++$state['peers'][ $peer ];
		} elseif ( count( $state['peers'] ) < self::MAX_TERMINATOR_PEERS ) {
			$state['peers'][ $peer ] = 1;
		} elseif ( ! $state['more'] ) {
			// Past the cap the addresses stop mattering: what matters is that
			// there are more of them than a terminator could have.
			$state['more'] = true;
		} else {
			return;
		}

		$state['seen'] = time();
		update_option( self::OPTION_TERMINATOR_UNDECLARED, $state, false );
	}

	/**
	 * The stored marker, in a shape the rest of this file can rely on.
	 *
	 * @return array{peers:array<string,int>,more:bool,seen:int}
	 */
	private static function terminator_state(): array {
		$stored = get_option( self::OPTION_TERMINATOR_UNDECLARED, array() );
		$stored = is_array( $stored ) ? $stored : array();
		$peers  = array();
		foreach ( (array) ( $stored['peers'] ?? array() ) as $peer => $count ) {
			// An array key is always int|string, and PHP turns a numeric
			// string key into an int, so the cast is what normalises it back.
			// The cap is applied on READ as well as on write: a stored value
			// that grew by some other route still cannot be walked forever.
			if ( '' !== (string) $peer && count( $peers ) < self::MAX_TERMINATOR_PEERS ) {
				$peers[ (string) $peer ] = max( 1, (int) $count );
			}
		}

		return array(
			'peers' => $peers,
			'more'  => ! empty( $stored['more'] ),
			'seen'  => (int) ( $stored['seen'] ?? 0 ),
		);
	}

	/**
	 * Forget it again, the moment the terminator is declared.
	 *
	 * Read before write: on a healthy site the option is absent, WordPress
	 * serves that from its notoptions cache, and nothing is written.
	 */
	private static function clear_undeclared_terminator(): void {
		if ( false !== get_option( self::OPTION_TERMINATOR_UNDECLARED, false ) ) {
			delete_option( self::OPTION_TERMINATOR_UNDECLARED );
		}
	}

	/**
	 * What the admin notice is allowed to say, or null for "say nothing yet".
	 *
	 * Null until at least one peer has been seen TERMINATOR_SIGHTINGS times.
	 * A real terminator reaches that on its second request; a single forged
	 * probe never does, and a single forged probe is all it takes to write a
	 * marker, which is why the threshold exists.
	 *
	 * @return array{peers:string[],distinct:int,more:bool,seen:int}|null
	 */
	public static function undeclared_terminator(): ?array {
		if ( false === get_option( self::OPTION_TERMINATOR_UNDECLARED, false ) ) {
			return null;
		}
		$state     = self::terminator_state();
		$confirmed = array();
		foreach ( $state['peers'] as $peer => $count ) {
			if ( $count >= self::TERMINATOR_SIGHTINGS ) {
				$confirmed[] = (string) $peer;
			}
		}
		if ( empty( $confirmed ) ) {
			return null;
		}
		sort( $confirmed );

		return array(
			'peers'    => $confirmed,
			'distinct' => count( $state['peers'] ),
			'more'     => $state['more'],
			'seen'     => $state['seen'],
		);
	}

	/**
	 * Tell core the truth about a request that reached a trusted terminator
	 * over TLS.
	 *
	 * Writes to $_SERVER on purpose, and only in the one direction that can
	 * be proved: never from a header alone, always from a header sent by a
	 * peer the administrator listed as a proxy. An existing HTTPS value is
	 * left alone, so this can only ever add knowledge.
	 */
	private static function trust_forwarded_https(): void {
		if ( ! is_ssl() && LoginArmor::request_is_https() ) {
			$_SERVER['HTTPS'] = 'on';
		}
	}

	/**
	 * Mark the auth cookies Secure.
	 *
	 * Untyped with a default: `secure_auth_cookie` and
	 * `secure_logged_in_cookie` are core filters and a third party may refire
	 * them with a degraded arity.
	 *
	 * @param mixed $secure Current value.
	 * @return bool
	 */
	public function force_secure_cookie( $secure = false ) {
		unset( $secure );
		return true;
	}

	/**
	 * Send the plain-HTTP request to its https twin.
	 */
	public function maybe_redirect_to_https(): void {
		// SAFE MODE, a second time. register_force_https() already refuses to
		// hook this while the constant is set, so on the site's own path this
		// line is unreachable; the callback is PUBLIC and sits on a core hook,
		// and a theme that refires `init` or calls it outright is not on the
		// site's own path. Sending a locked-out administrator to an https
		// endpoint their site may not answer on is the one thing safe mode
		// exists to stop, so it is stopped by both routes.
		if ( ! self::force_https_effective() ) {
			return;
		}

		if ( LoginArmor::request_is_https() ) {
			return;
		}

		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized, WordPress.Security.ValidatedSanitizedInput.MissingUnslash -- force_https_target() is the sanitiser: sanitize_text_field() on a REQUEST_URI would destroy every %XX sequence (2.5.2).
		$server = $_SERVER;

		$target = self::force_https_target(
			$server,
			self::url_authority( home_url( '/' ) ),
			self::url_authority( site_url() )
		);
		if ( null === $target ) {
			return;
		}

		self::send_redirect( $target, self::force_https_status( $server ) );
	}

	/**
	 * The https URL this request should have been made to, or null.
	 *
	 * Pure: everything it reads is a parameter, so the whole decision is
	 * testable without a web server. Shaped like core's own redirect in
	 * wp-login.php ("https://" . HTTP_HOST . REQUEST_URI), with the one
	 * thing core can afford to skip there and this cannot: the Host header
	 * is validated against the site's own addresses before being reused, so
	 * a forged `Host:` can never turn this into an open redirect.
	 *
	 * @param array<string,mixed> $server    A $_SERVER-shaped array.
	 * @param string              $home_host Authority of home_url(), host[:port].
	 * @param string              $site_host Authority of site_url(), host[:port].
	 * @return string|null Absolute https URL, or null when there is nothing to do.
	 */
	public static function force_https_target( array $server, string $home_host, string $site_host ): ?string {
		$https = isset( $server['HTTPS'] ) ? strtolower( trim( (string) $server['HTTPS'] ) ) : '';
		if ( 'on' === $https || '1' === $https ) {
			return null;
		}

		$home_host = trim( $home_host );
		$raw_host  = isset( $server['HTTP_HOST'] ) ? trim( (string) $server['HTTP_HOST'] ) : '';
		if ( 1 !== preg_match( '/^[A-Za-z0-9._\-\[\]:]+$/', $raw_host ) || ! self::host_port_is_valid( $raw_host ) ) {
			$raw_host = '';
		}

		// The NAME decides which of the site's two addresses we are on; the
		// AUTHORITY, port included, always comes from that address and never
		// from the request.
		//
		// Taking the port from the request was wrong in the one shape that
		// matters here. A site whose address is example.test:8443 over TLS may
		// well also answer plain HTTP on 8080. The name matches, so the old
		// code kept `example.test:8080` and redirected to
		// https://example.test:8080, which is the port that speaks HTTP. The
		// browser cannot open that, and the visitor is stranded on the very
		// request Force HTTPS exists to rescue.
		//
		// home_url() and site_url() are what the site declares itself to be,
		// so their authority is the only one known to answer over TLS. On a
		// multisite the two can differ, hence picking the one whose name
		// matched rather than always falling back to home.
		// The exact authority wins before the name does. On a site where home
		// and site share a hostname and differ only in port (home
		// example.com, siteurl example.com:8443, the admin served on its own
		// port), matching on the name alone would always resolve to home and
		// send an admin request arriving on :8443 to port 443, where the admin
		// vhost does not live. Stranding the administrator is the one outcome
		// this feature must never produce, so the address the request is
		// actually on is preferred when the site declares it.
		$host = $home_host;
		$name = self::host_name( $raw_host );
		if ( '' !== $raw_host && $raw_host === $site_host ) {
			$host = $site_host;
		} elseif ( '' !== $raw_host && $raw_host === $home_host ) {
			$host = $home_host;
		} elseif ( '' !== $name ) {
			if ( $name === self::host_name( $home_host ) ) {
				$host = $home_host;
			} elseif ( $name === self::host_name( $site_host ) ) {
				$host = $site_host;
			}
		}

		// Lower-cased before it is used, not only before it is compared:
		// wp_validate_redirect() matches the host CASE-SENSITIVELY against
		// home_url()'s, so `Host: EXAMPLE.test` would otherwise build a target
		// core refuses, and every visitor would land on /wp-admin/ instead.
		$host = strtolower( $host );

		// The one guard on the host we ended up with, covering two cases that
		// both mean "no target can be built here".
		//
		// EMPTY: the site has no address to fall back on, and a redirect
		// built from a request header alone is an open redirect. (A Host that
		// matched site_url() is not that case: the site really is that host.)
		//
		// IPv6 LITERAL: wp_validate_redirect() rejects any host containing a
		// colon, through its strpbrk guard, so the bracketed form can only
		// ever reach the fallback, and a fallback here means sending every
		// visitor of the site to /wp-admin/. Not redirecting is the lesser of
		// the two, and it is stated rather than stumbled into.
		if ( '' === $host || '[' === $host[0] ) {
			return null;
		}

		$uri = isset( $server['REQUEST_URI'] ) ? (string) $server['REQUEST_URI'] : '/';
		$uri = self::sanitize_request_uri( $uri );
		if ( '' === $uri || '/' !== $uri[0] ) {
			// Some SAPIs hand over an absolute URI. Reusing it would move the
			// redirect to another host entirely.
			$uri = '/';
		}

		return 'https://' . $host . $uri;
	}

	/**
	 * 302 for a request a browser may safely replay, 307 for the rest.
	 *
	 * 307 preserves the method and the body, so a POST that arrived on the
	 * plain port is not silently downgraded to a GET and lost.
	 *
	 * @param array<string,mixed> $server A $_SERVER-shaped array.
	 */
	public static function force_https_status( array $server ): int {
		$method = strtoupper( trim( (string) ( $server['REQUEST_METHOD'] ?? 'GET' ) ) );

		return ( 'GET' === $method || 'HEAD' === $method ) ? 302 : 307;
	}

	/**
	 * Whether this save may switch the toggle on.
	 *
	 * Enabling from a request that is not demonstrably HTTPS is the one way
	 * to lock an administrator out of the site with this toggle, so it is
	 * refused. Everything else, turning it off included, is always allowed.
	 *
	 * @param bool $currently_on   Whether the stored toggle is already on.
	 * @param bool $request_https  Whether this very request is HTTPS.
	 */
	public static function can_enable_force_https( bool $currently_on, bool $request_https ): bool {
		return $currently_on || $request_https;
	}

	/**
	 * Whether an import may switch the toggle on.
	 *
	 * Same rule as the admin one, with the one difference WP-CLI forces: a
	 * file applied from the command line has no browser request to judge, so
	 * the site's own address is what says whether this site speaks HTTPS.
	 *
	 * @param string $source        'admin' or 'cli'.
	 * @param string $home_url      The site address, as home_url() returns it.
	 * @param bool   $request_https Whether the current request is HTTPS.
	 */
	public static function can_import_force_https( string $source, string $home_url, bool $request_https ): bool {
		if ( 'cli' === $source ) {
			return str_starts_with( strtolower( trim( $home_url ) ), 'https://' );
		}

		return $request_https;
	}

	/**
	 * Whether this execution context may be redirected at all.
	 *
	 * @param bool $is_cli  Whether WP-CLI is driving this request.
	 * @param bool $is_cron Whether this is a cron run.
	 */
	public static function force_https_applies( bool $is_cli, bool $is_cron ): bool {
		return ! $is_cli && ! $is_cron;
	}

	/**
	 * Whether the toggle enforces anything at all right now.
	 *
	 * Safe mode brings it down to nothing without touching the option, the
	 * same way Firewall::effective_mode() and PowChallenge::effective_mode()
	 * bring their modules down to observation. That matters twice over: an
	 * administrator who added LOGIN_ARMOR_SAFE_MODE to wp-config.php to get
	 * back in must not then have to remember what was armed before, and the
	 * settings screen must keep showing them the value they chose, or the next
	 * save of that form would switch off a toggle nobody asked to switch off.
	 *
	 * Deleting the line restores enforcement on the very next request, with no
	 * further action.
	 *
	 * @since 2.7.0
	 */
	public static function force_https_effective(): bool {
		if ( LoginArmor::is_safe_mode() ) {
			return false;
		}

		return ! empty( self::get_settings()['force_https'] );
	}

	/**
	 * Strip what may never travel in a redirect target, and nothing else.
	 *
	 * NUL and CR/LF only, raw or percent-encoded: a header injection is the
	 * whole risk here. Every other %XX sequence is preserved, because
	 * sanitize_text_field() removes them all and that is exactly how the
	 * password-reset link broke in 2.5.2 (login=jean%40client.fr became
	 * login=jeanclient.fr).
	 */
	private static function sanitize_request_uri( string $uri ): string {
		$uri = wp_kses_no_null( $uri );
		$uri = str_replace( array( "\r", "\n", "\t" ), '', $uri );

		return (string) _deep_replace( array( '%0d', '%0a', '%0D', '%0A', '%00' ), $uri );
	}

	/**
	 * Whether an authority's port, if it has one, is a port at all.
	 *
	 * `Host: example.test:8080abc` passes the character class above and
	 * builds a target parse_url() refuses, which wp_validate_redirect()
	 * answers with its fallback. Caught here instead.
	 */
	private static function host_port_is_valid( string $host ): bool {
		$port = '';
		if ( '' !== $host && '[' === $host[0] ) {
			$end = strpos( $host, ']' );
			if ( false === $end ) {
				return false;
			}
			$rest = substr( $host, $end + 1 );
			if ( '' === $rest ) {
				return true;
			}
			if ( ':' !== $rest[0] ) {
				return false;
			}
			$port = substr( $rest, 1 );
		} elseif ( 1 === substr_count( $host, ':' ) ) {
			$port = substr( $host, (int) strpos( $host, ':' ) + 1 );
		} else {
			return true;
		}

		return '' !== $port && ctype_digit( $port ) && (int) $port >= 1 && (int) $port <= 65535;
	}

	/**
	 * The bare hostname of an authority: no port, lower-cased, no brackets.
	 */
	private static function host_name( string $host ): string {
		$host = strtolower( trim( $host ) );
		if ( '' === $host ) {
			return '';
		}
		if ( '[' === $host[0] ) {
			$end = strpos( $host, ']' );

			return false === $end ? '' : substr( $host, 1, $end - 1 );
		}
		if ( 1 === substr_count( $host, ':' ) ) {
			return substr( $host, 0, (int) strpos( $host, ':' ) );
		}

		// No colon at all, or several: a bare IPv6 literal, kept whole.
		return $host;
	}

	/**
	 * The authority of a URL: host, bracketed when it is an IPv6 literal,
	 * with its port when the URL carries one.
	 */
	private static function url_authority( string $url ): string {
		$parts = wp_parse_url( $url );
		if ( ! is_array( $parts ) || empty( $parts['host'] ) ) {
			return '';
		}
		$host = (string) $parts['host'];
		if ( false !== strpos( $host, ':' ) && '[' !== $host[0] ) {
			$host = '[' . $host . ']';
		}

		return isset( $parts['port'] ) ? $host . ':' . (int) $parts['port'] : $host;
	}

	/**
	 * Add site_url()'s host to what wp_safe_redirect() will accept.
	 *
	 * Core allows home_url()'s host and nothing else, so on a site where
	 * WordPress lives in its own directory under another hostname, the
	 * target this module legitimately built from site_url() would be thrown
	 * away for /wp-admin/. Added for the length of our own redirect and
	 * removed immediately after, so no other redirect in the request gains
	 * anything from it.
	 *
	 * Untyped with a default: `allowed_redirect_hosts` is a core filter.
	 *
	 * @param mixed $hosts Allowed hosts so far.
	 * @return array<int,string>
	 */
	public static function allow_site_url_host( $hosts = array() ) {
		$hosts = is_array( $hosts ) ? $hosts : array();
		$host  = self::host_name( self::url_authority( site_url() ) );
		if ( '' !== $host && ! in_array( $host, $hosts, true ) ) {
			$hosts[] = $host;
		}

		return $hosts;
	}

	/**
	 * The one place this module answers a request.
	 *
	 * nocache_headers() first: without it a full-page cache or a CDN is free
	 * to store this 302 and keep serving it long after the toggle is off,
	 * which would turn a reversible setting into an outage nobody can
	 * explain.
	 */
	private static function send_redirect( string $target, int $status ): void {
		nocache_headers();

		add_filter( 'allowed_redirect_hosts', array( __CLASS__, 'allow_site_url_host' ) );
		wp_safe_redirect( $target, $status );
		remove_filter( 'allowed_redirect_hosts', array( __CLASS__, 'allow_site_url_host' ) );

		if ( self::$exit_on_redirect ) {
			exit;
		}
	}
}
