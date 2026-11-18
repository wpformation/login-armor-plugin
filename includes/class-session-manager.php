<?php
/**
 * Session Manager module.
 *
 * Opt-in control over authenticated sessions:
 *
 * - **Idle timeout**: log an account out after a configurable period of
 *   inactivity, measured on real page loads (heartbeat/AJAX traffic does
 *   not keep a session alive, otherwise an idle tab would never expire).
 *
 * - **Maximum session lifetime**: cap how long a login cookie stays valid
 *   via the core `auth_cookie_expiration` filter, independent of "remember
 *   me".
 *
 * - **Single active session**: when on, logging in from a new device
 *   revokes every other session for that account (one-device enforcement),
 *   using the core {@see \WP_Session_Tokens} API.
 *
 * - **Log out other devices**: an on-demand action that destroys every
 *   session except the current one.
 *
 * Consistent with the rest of the plugin: every behaviour is off until an
 * admin enables the module, the constructor early-returns when disabled,
 * and session destruction rides entirely on the public WP_Session_Tokens
 * API (no reliance on core-internal meta layout).
 *
 * @package LoginArmor
 * @since   2.3.0
 */

namespace LoginArmor;

// Exit if accessed directly.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Handles authenticated session policy.
 */
class SessionManager {

	public const OPTION_KEY = 'login_armor_session';

	/** User meta: unix timestamp of last observed activity (idle tracking). */
	public const META_LAST_ACTIVE = 'login_armor_last_active';

	/** Throttle: only rewrite the activity stamp once per this many seconds. */
	private const ACTIVITY_THROTTLE = 60;

	/**
	 * Default settings (module off).
	 *
	 * @var array<string, bool|int>
	 */
	private const DEFAULTS = [
		'enabled'           => false,
		'idle_timeout_min'  => 0,  // 0 = no idle timeout.
		'max_lifetime_hours' => 0, // 0 = leave WordPress default.
		'single_session'    => false,
	];

	/**
	 * Token of the session created during the current login request,
	 * captured from `set_logged_in_cookie` (the cookie is not yet readable
	 * from $_COOKIE on the login request itself).
	 *
	 * @var string
	 */
	private string $new_login_token = '';

	/**
	 * Constructor. Registers hooks only when the module is enabled.
	 */
	public function __construct() {
		if ( ! self::is_enabled() ) {
			return;
		}

		$settings = self::get_settings();

		if ( (int) $settings['idle_timeout_min'] > 0 ) {
			add_action( 'init', [ $this, 'enforce_idle_timeout' ], 1 );
			// 2.7.8 - a login is activity. set_logged_in_cookie fires on the
			// password login and on the two-factor login alike.
			add_action( 'set_logged_in_cookie', [ $this, 'mark_login_activity' ], 10, 6 );
		}

		if ( (int) $settings['max_lifetime_hours'] > 0 ) {
			add_filter( 'auth_cookie_expiration', [ $this, 'cap_cookie_lifetime' ], 50, 3 );
		}

		if ( ! empty( $settings['single_session'] ) ) {
			// Capture the freshly-created session token, then revoke the
			// others once the login is finalised.
			add_action( 'set_logged_in_cookie', [ $this, 'capture_login_token' ], 10, 6 );
			add_action( 'wp_login', [ $this, 'enforce_single_session' ], 100, 2 );
		}
	}

	/**
	 * Whether the module is enabled.
	 */
	public static function is_enabled(): bool {
		return ! empty( self::get_settings()['enabled'] );
	}

	/**
	 * Resolved settings merged with defaults.
	 *
	 * @return array<string, bool|int>
	 */
	public static function get_settings(): array {
		$stored = get_option( self::OPTION_KEY, [] );
		if ( ! is_array( $stored ) ) {
			$stored = [];
		}
		return array_merge( self::DEFAULTS, $stored );
	}

	/**
	 * Sanitize and persist settings from the admin form.
	 *
	 * @param array<string, mixed> $input Raw form input.
	 */
	public static function save_settings( array $input ): void {
		$clean = [
			'enabled'            => ! empty( $input['enabled'] ),
			'idle_timeout_min'   => max( 0, min( 1440, (int) ( $input['idle_timeout_min'] ?? 0 ) ) ),
			'max_lifetime_hours' => max( 0, min( 8760, (int) ( $input['max_lifetime_hours'] ?? 0 ) ) ),
			'single_session'     => ! empty( $input['single_session'] ),
		];
		update_option( self::OPTION_KEY, $clean, false );
	}

	// ------------------------------------------------------------------
	// Idle timeout
	// ------------------------------------------------------------------

	/**
	 * Log out an account that has been idle longer than the configured
	 * window. Runs on `init` for real page loads only: background traffic
	 * (AJAX heartbeat, cron, REST, CLI, XML-RPC) neither refreshes the
	 * activity stamp nor triggers a logout, so an unattended tab still
	 * expires on schedule.
	 */
	public function enforce_idle_timeout(): void {
		if ( ! is_user_logged_in() ) {
			return;
		}
		if ( ( defined( 'DOING_AJAX' ) && DOING_AJAX )
			|| ( defined( 'DOING_CRON' ) && DOING_CRON )
			|| ( defined( 'WP_CLI' ) && \WP_CLI )
			|| ( defined( 'REST_REQUEST' ) && REST_REQUEST )
			|| ( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST ) ) {
			return;
		}

		$idle = (int) self::get_settings()['idle_timeout_min'] * MINUTE_IN_SECONDS;
		if ( $idle <= 0 ) {
			return;
		}

		$user_id = get_current_user_id();
		$now     = time();
		$last    = (int) get_user_meta( $user_id, self::META_LAST_ACTIVE, true );

		if ( $last > 0 && ( $now - $last ) > $idle ) {
			delete_user_meta( $user_id, self::META_LAST_ACTIVE );
			wp_logout();
			wp_safe_redirect( add_query_arg( 'login_armor_idle', '1', wp_login_url() ) );
			exit;
		}

		// Throttled activity refresh.
		if ( 0 === $last || ( $now - $last ) >= self::ACTIVITY_THROTTLE ) {
			update_user_meta( $user_id, self::META_LAST_ACTIVE, $now );
		}
	}

	/**
	 * A login counts as activity: reset the account's stamp when a new login
	 * cookie is issued.
	 *
	 * 2.7.8. The stamp belongs to the account, not to a session, and only page
	 * loads refreshed it. An administrator who came back after a break longer
	 * than the window and signed in again kept the stamp of the previous
	 * visit, and enforce_idle_timeout() logged the new session out on the
	 * first page after the login screen. The second attempt worked, because
	 * that logout deletes the stamp.
	 *
	 * Parameters untyped with defaults: a third-party plugin re-firing
	 * `set_logged_in_cookie` with fewer args must not fatal cookie setting.
	 *
	 * @param mixed $logged_in_cookie The logged-in cookie value (unused).
	 * @param mixed $expire           Unix expire time (unused).
	 * @param mixed $expiration       Cookie expiration in seconds (unused).
	 * @param mixed $user_id          User the cookie is for (expected int).
	 * @param mixed $scheme           Cookie scheme (unused).
	 * @param mixed $token            Session token (unused).
	 */
	public function mark_login_activity( $logged_in_cookie = '', $expire = 0, $expiration = 0, $user_id = 0, $scheme = '', $token = '' ): void {
		if ( ! is_numeric( $user_id ) || (int) $user_id <= 0 ) {
			return;
		}
		update_user_meta( (int) $user_id, self::META_LAST_ACTIVE, time() );
	}

	// ------------------------------------------------------------------
	// Maximum session lifetime
	// ------------------------------------------------------------------

	/**
	 * Cap the login cookie lifetime to the configured maximum.
	 *
	 * Parameters untyped with defaults and the return hint removed: WP core
	 * does not enforce filter callback types; a non-numeric $length from a
	 * third-party filter is passed through untouched.
	 *
	 * @param mixed $length   Default expiration length in seconds (expected int).
	 * @param mixed $user_id  User the cookie is for (unused).
	 * @param mixed $remember Whether "remember me" was checked (unused: the cap applies either way).
	 * @return mixed
	 */
	public function cap_cookie_lifetime( $length = 0, $user_id = 0, $remember = false ) {
		if ( ! is_numeric( $length ) ) {
			return $length;
		}
		$max = (int) self::get_settings()['max_lifetime_hours'] * HOUR_IN_SECONDS;
		if ( $max <= 0 ) {
			return (int) $length;
		}
		return min( (int) $length, $max );
	}

	// ------------------------------------------------------------------
	// Single active session
	// ------------------------------------------------------------------

	/**
	 * Capture the token of the session created on this login request.
	 *
	 * Parameters untyped with defaults: a third-party plugin re-firing
	 * `set_logged_in_cookie` with fewer args must not fatal cookie setting.
	 *
	 * @param mixed $logged_in_cookie The logged-in cookie value (unused).
	 * @param mixed $expire           Unix expire time (unused).
	 * @param mixed $expiration       Cookie expiration in seconds (unused).
	 * @param mixed $user_id          User ID (unused).
	 * @param mixed $scheme           Cookie scheme (unused).
	 * @param mixed $token            Session token for the new session (expected string).
	 */
	public function capture_login_token( $logged_in_cookie = '', $expire = 0, $expiration = 0, $user_id = 0, $scheme = '', $token = '' ): void {
		$this->new_login_token = is_scalar( $token ) ? (string) $token : '';
	}

	/**
	 * On login, revoke every session except the one just created, so an
	 * account can only be active on a single device at a time.
	 *
	 * Parameters untyped with defaults: many plugins re-fire `wp_login` with
	 * a single argument; when $user is missing we resolve it from
	 * $user_login so the single-session policy still applies.
	 *
	 * @param mixed $user_login The user login (expected string).
	 * @param mixed $user       The user object (expected WP_User).
	 */
	public function enforce_single_session( $user_login = '', $user = null ): void {
		// 2.7.0 - safe mode pauses the policy. Signing in from a second device
		// while trying to recover a site is exactly what an administrator does
		// in that situation, and having the first session revoked under them
		// turns a recovery into a loop.
		if ( LoginArmor::is_safe_mode() ) {
			return;
		}

		if ( ! $user instanceof \WP_User && is_string( $user_login ) && '' !== $user_login ) {
			$user = get_user_by( 'login', $user_login );
		}
		if ( ! $user instanceof \WP_User || '' === $this->new_login_token ) {
			return;
		}
		$manager = \WP_Session_Tokens::get_instance( $user->ID );
		$manager->destroy_others( $this->new_login_token );

		if ( class_exists( '\LoginArmor\ActivityLog\ActivityLog' ) ) {
			/**
			 * Fires after Login Armor revokes other sessions on a single-session login.
			 *
			 * @param int $user_id The user whose other sessions were revoked.
			 */
			do_action( 'login_armor_other_sessions_revoked', $user->ID );
		}
	}

	/**
	 * Destroy every session for a user except the current one. Used by the
	 * "log out other devices" admin action.
	 *
	 * @param int $user_id User whose other sessions to destroy.
	 * @return bool True when a current session token was found and others were destroyed.
	 */
	public static function logout_other_devices( int $user_id ): bool {
		$token = wp_get_session_token();
		if ( '' === $token ) {
			return false;
		}
		\WP_Session_Tokens::get_instance( $user_id )->destroy_others( $token );
		return true;
	}

	/**
	 * Count the active sessions for a user, for admin surfacing.
	 *
	 * @param int $user_id User to count sessions for.
	 */
	public static function active_session_count( int $user_id ): int {
		return count( \WP_Session_Tokens::get_instance( $user_id )->get_all() );
	}
}
