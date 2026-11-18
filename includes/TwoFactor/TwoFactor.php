<?php
/**
 * Two-Factor Authentication orchestrator.
 *
 * Checks if the module is enabled globally, hooks into the WordPress login
 * flow to intercept authentication, manages the verification screen,
 * enforces per-role 2FA requirements, and handles grace periods.
 *
 * @package LoginArmor\TwoFactor
 * @since   2.2.0
 */

namespace LoginArmor\TwoFactor;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * TwoFactor module entry point.
 */
class TwoFactor {

	/** @var string Option key for module enabled state. */
	public const OPTION_ENABLED = 'login_armor_2fa_enabled';

	/** @var string Option key for allowed methods. */
	public const OPTION_METHODS = 'login_armor_2fa_methods';

	/** @var string Option key for enforced roles. */
	public const OPTION_ENFORCE_ROLES = 'login_armor_2fa_enforce_roles';

	/** @var string Option key for grace period days. */
	public const OPTION_GRACE_DAYS = 'login_armor_2fa_grace_days';

	/** @var string URL parameter for verification screen. */
	public const VERIFY_PARAM = 'login-armor-2fa';

	/**
	 * Transient prefix for hashed pending-2FA tokens (V2.1.0+).
	 *
	 * NB the renamed prefix vs V2.0.x is intentional. The V2.0.x prefix was
	 * `login_armor_2fa_token_` and the suffix was the *clear* token, leaking
	 * the token via wp_options reads. The V2.1.0 transient_key() helper
	 * concatenates `login_armor_2fa_pending_` with sha256($token) so the
	 * clear token never appears in DB rows.
	 *
	 * The V2.1.0 upgrade hook (LoginArmor::maybe_run_v210_upgrade) deletes
	 * any orphaned old-format rows on first activation/load post-upgrade.
	 *
	 * @var string
	 */
	public const TOKEN_PREFIX = 'login_armor_2fa_pending_';

	/** @var int Token validity in seconds. */
	private const TOKEN_TTL = 600; // 10 minutes.

	/** @var int Max failed verification attempts before lockout. */
	private const MAX_FAILURES = 3;

	/** @var int Lockout duration in seconds after max failures. */
	private const LOCKOUT_DURATION = 900; // 15 minutes.

	/** @var int Max failed verification attempts per IP within the sliding window. */
	private const IP_MAX_FAILURES = 10;

	/** @var int Sliding window for per-IP failure counting, in seconds. */
	private const IP_WINDOW = 900; // 15 minutes.

	/** @var string Atomic fixed-window counter prefix for one account. */
	private const ACCOUNT_FAILURES_PREFIX = 'login_armor_2fa_account_failures_';

	/** @var string Atomic fixed-window counter prefix for one reliable IP. */
	private const ATOMIC_IP_FAILURES_PREFIX = 'login_armor_2fa_ip_atomic_';

	/** @var string Atomic accepted-TOTP-step option prefix. */
	private const TOTP_STEP_PREFIX = 'login_armor_2fa_totp_step_';

	/** @var string Transient prefix for the profile setup state machine. */
	private const SETUP_PREFIX = 'login_armor_2fa_setup_';

	/** @var int Setup state validity in seconds. */
	private const SETUP_TTL = 900;

	/**
	 * Constructor. Bails early if disabled: zero overhead.
	 */
	public function __construct() {
		if ( self::is_enabled() ) {
			$this->register_hooks();
			return;
		}
		if ( self::guards_login() ) {
			$this->register_login_hooks();
		}
	}

	/**
	 * Check if the 2FA module is enabled globally.
	 */
	public static function is_enabled(): bool {
		return (bool) get_option( self::OPTION_ENABLED, false );
	}

	/**
	 * Must this site challenge the accounts enrolled in 2FA?
	 *
	 * Wherever the module is on, and on every site of a multisite network
	 * whatever its own switch says. Enrolment is user meta, shared by every
	 * site, and so is the login cookie (ms_cookie_constants() scopes it to
	 * the whole network). A site with the module off, the default for a new
	 * site, used to open a session valid on every site, the network admin
	 * included, with the password alone. There the second factor of the
	 * accounts already enrolled is still asked for; that site's own policy
	 * (enforced roles, grace periods) stays off.
	 */
	public static function guards_login(): bool {
		return self::is_enabled() || is_multisite();
	}

	/**
	 * Check if a specific method is enabled.
	 *
	 * @param string $method Method slug: 'totp', 'email', 'backup'.
	 * @return bool
	 */
	public static function is_method_enabled( string $method ): bool {
		$methods = (array) get_option( self::OPTION_METHODS, [ 'totp', 'email', 'backup' ] );
		return in_array( $method, $methods, true );
	}

	/**
	 * Check if 2FA is enabled for a specific user.
	 *
	 * @param int $user_id WordPress user ID.
	 * @return bool
	 */
	public static function is_user_enabled( int $user_id ): bool {
		return (bool) get_user_meta( $user_id, 'login_armor_2fa_enabled', true );
	}

	/**
	 * Get the user's configured 2FA method.
	 *
	 * @param int $user_id WordPress user ID.
	 * @return string Method slug ('totp' or 'email'), empty if not set.
	 */
	public static function get_user_method( int $user_id ): string {
		return (string) get_user_meta( $user_id, 'login_armor_2fa_method', true );
	}

	/**
	 * Whether a given method can legitimately be offered to this user on the
	 * verification screen. Mirrors the eligibility logic in
	 * admin/views/two-factor-verify.php so the "Use a different method" links
	 * and the screen the user lands on never disagree.
	 *
	 * @param int    $user_id WordPress user ID.
	 * @param string $method  Method slug: 'totp', 'email', 'backup'.
	 * @return bool
	 */
	public static function is_method_available_for_user( int $user_id, string $method ): bool {
		switch ( $method ) {
			case 'totp':
				return self::is_method_enabled( 'totp' )
					&& '' !== (string) get_user_meta( $user_id, 'login_armor_2fa_secret', true );
			case 'email':
				// Only to an account that chose e-mail codes, or whose TOTP can
				// no longer be used here (method switched off, no secret, a
				// secret the current AUTH_KEY cannot decrypt). Offered to every
				// TOTP account, it made the mailbox, which already resets the
				// password, enough to pass the second factor too.
				return self::is_method_enabled( 'email' )
					&& ( 'email' === self::get_user_method( $user_id ) || ! self::is_totp_usable( $user_id ) );
			case 'backup':
				require_once __DIR__ . '/BackupCodes.php';
				return self::is_method_enabled( 'backup' ) && BackupCodes::remaining( $user_id ) > 0;
			default:
				return false;
		}
	}

	/**
	 * Can this account pass the second factor with its TOTP app here?
	 *
	 * @param int $user_id WordPress user ID.
	 */
	private static function is_totp_usable( int $user_id ): bool {
		if ( ! self::is_method_available_for_user( $user_id, 'totp' ) ) {
			return false;
		}
		require_once __DIR__ . '/TOTP.php';
		return false !== TOTP::decrypt_secret( (string) get_user_meta( $user_id, 'login_armor_2fa_secret', true ) );
	}

	/**
	 * Return every verification method currently usable by one enrolled user.
	 *
	 * @param int $user_id WordPress user ID.
	 * @return string[] Ordered method slugs.
	 */
	public static function get_available_methods_for_user( int $user_id ): array {
		$available = array();
		foreach ( array( 'totp', 'email', 'backup' ) as $method ) {
			if ( self::is_method_available_for_user( $user_id, $method ) ) {
				$available[] = $method;
			}
		}
		return $available;
	}

	/**
	 * Check if a user's role requires 2FA.
	 *
	 * @param int $user_id WordPress user ID.
	 * @return bool
	 */
	public static function is_required_for_user( int $user_id ): bool {
		$enforce_roles = (array) get_option( self::OPTION_ENFORCE_ROLES, [] );
		if ( empty( $enforce_roles ) ) {
			return false;
		}

		$user = get_userdata( $user_id );
		if ( ! $user ) {
			return false;
		}

		return ! empty( array_intersect( $user->roles, $enforce_roles ) );
	}

	/**
	 * Check if a user is in the grace period.
	 *
	 * @param int $user_id WordPress user ID.
	 * @return bool True if grace period is active (user can still log in without 2FA).
	 */
	public static function is_in_grace_period( int $user_id ): bool {
		$grace_until = (int) get_user_meta( $user_id, 'login_armor_2fa_grace_until', true );
		if ( 0 === $grace_until ) {
			return false;
		}
		return time() < $grace_until;
	}

	/**
	 * Set the grace period for a user.
	 *
	 * @param int $user_id WordPress user ID.
	 */
	public static function set_grace_period( int $user_id ): void {
		$days = (int) get_option( self::OPTION_GRACE_DAYS, 3 );
		$until = time() + ( $days * DAY_IN_SECONDS );
		update_user_meta( $user_id, 'login_armor_2fa_grace_until', $until );
	}

	/**
	 * Create a temporary login token for the 2FA verification step.
	 *
	 * @param int    $user_id     WordPress user ID.
	 * @param string $redirect_to URL to redirect after verification.
	 * @return string Token string.
	 */
	public static function create_token( int $user_id, string $redirect_to = '' ): string {
		$token = bin2hex( random_bytes( 32 ) );

		set_transient( self::transient_key( $token ), [
			'user_id'     => $user_id,
			'redirect_to' => $redirect_to,
			'failures'    => 0,
			'created'     => time(),
		], self::TOKEN_TTL );

		return $token;
	}

	/**
	 * Start an isolated profile setup transaction for one user.
	 *
	 * The active method and secret are not modified until complete_setup() has
	 * consumed a server-side state that was marked verified.
	 *
	 * @return string Opaque setup token, or an empty string on storage failure.
	 */
	public static function begin_setup( int $user_id, string $method, string $encrypted_secret = '' ): string {
		if ( $user_id <= 0 || ! in_array( $method, array( 'totp', 'email' ), true ) ) {
			return '';
		}
		if ( ! self::acquire_setup_lock( $user_id ) ) {
			return '';
		}
		try {
			$token = bin2hex( random_bytes( 32 ) );
			$state = array(
				'user_id'          => $user_id,
				'token'            => $token,
				'method'           => $method,
				'encrypted_secret' => $encrypted_secret,
				'verified'         => false,
				'backup_hashes'    => array(),
				'created'          => time(),
			);
			return set_transient( self::setup_key( $user_id ), $state, self::SETUP_TTL ) ? $token : '';
		} finally {
			self::release_setup_lock( $user_id );
		}
	}

	/**
	 * Read a live setup transaction bound to the current user and token.
	 *
	 * @return array<string,mixed>|false
	 */
	public static function get_setup( int $user_id, string $token ): array|false {
		if ( $user_id <= 0 || ! preg_match( '/^[a-f0-9]{64}$/', $token ) ) {
			return false;
		}
		$state = get_transient( self::setup_key( $user_id ) );
		if ( ! is_array( $state ) || (int) ( $state['user_id'] ?? 0 ) !== $user_id ) {
			return false;
		}
		$stored = (string) ( $state['token'] ?? '' );
		if ( 64 !== strlen( $stored ) || ! hash_equals( $stored, $token ) ) {
			return false;
		}
		return $state;
	}

	/** Persist a verified setup state without changing the active 2FA data. */
	public static function mark_setup_verified( int $user_id, string $token, array $backup_hashes, int $totp_step = 0 ): bool {
		require_once __DIR__ . '/BackupCodes.php';
		if ( count( $backup_hashes ) !== BackupCodes::CODE_COUNT || ! self::acquire_setup_lock( $user_id ) ) {
			return false;
		}
		try {
			$state = self::get_setup( $user_id, $token );
			if ( false === $state ) {
				return false;
			}
			$state['verified']      = true;
			$state['backup_hashes'] = array_values( array_filter( $backup_hashes, 'is_string' ) );
			$state['totp_step']     = max( 0, $totp_step );
			return count( $state['backup_hashes'] ) === BackupCodes::CODE_COUNT
				&& set_transient( self::setup_key( $user_id ), $state, self::SETUP_TTL );
		} finally {
			self::release_setup_lock( $user_id );
		}
	}

	/** Cancel any unfinished profile setup transaction for a user. */
	public static function cancel_setup( int $user_id ): void {
		if ( ! self::acquire_setup_lock( $user_id ) ) {
			return;
		}
		try {
			delete_transient( self::setup_key( $user_id ) );
		} finally {
			self::release_setup_lock( $user_id );
		}
	}

	/** Atomically consume a verified setup transaction. */
	public static function consume_setup( int $user_id, string $token ): array|false {
		if ( ! self::acquire_setup_lock( $user_id ) ) {
			return false;
		}
		try {
			$state = self::get_setup( $user_id, $token );
			if ( false === $state || empty( $state['verified'] ) ) {
				return false;
			}
			if ( ! delete_transient( self::setup_key( $user_id ) ) ) {
				return false;
			}
			return $state;
		} finally {
			self::release_setup_lock( $user_id );
		}
	}

	/**
	 * Commit a verified setup while holding the per-user setup lock.
	 *
	 * @return array<string,mixed>|false The committed setup state.
	 */
	public static function activate_verified_setup( int $user_id, string $token ): array|false {
		if ( ! self::acquire_setup_lock( $user_id ) ) {
			return false;
		}
		try {
			$state = self::get_setup( $user_id, $token );
			if ( false === $state || empty( $state['verified'] ) || self::is_user_enabled( $user_id ) ) {
				return false;
			}
			$method = (string) ( $state['method'] ?? '' );
			if ( ! in_array( $method, array( 'totp', 'email' ), true ) || ! self::is_method_enabled( $method ) ) {
				return false;
			}

			if ( 'totp' === $method ) {
				require_once __DIR__ . '/TOTP.php';
				$encrypted = (string) ( $state['encrypted_secret'] ?? '' );
				if ( '' === $encrypted || false === TOTP::decrypt_secret( $encrypted ) ) {
					return false;
				}
				if ( empty( $state['totp_claimed'] ) ) {
					if ( ! self::claim_totp_step( $user_id, (int) ( $state['totp_step'] ?? 0 ) ) ) {
						return false;
					}
					$state['totp_claimed'] = true;
					if ( ! set_transient( self::setup_key( $user_id ), $state, self::SETUP_TTL ) ) {
						return false;
					}
				}
			}

			require_once __DIR__ . '/BackupCodes.php';
			if ( ! BackupCodes::store_hashes( $user_id, (array) ( $state['backup_hashes'] ?? array() ) ) ) {
				return false;
			}
			update_user_meta( $user_id, 'login_armor_2fa_method', $method );
			if ( 'totp' === $method ) {
				update_user_meta( $user_id, 'login_armor_2fa_secret', (string) $state['encrypted_secret'] );
			} else {
				delete_user_meta( $user_id, 'login_armor_2fa_secret' );
			}
			update_user_meta( $user_id, 'login_armor_2fa_confirmed', true );
			delete_user_meta( $user_id, 'login_armor_2fa_grace_until' );
			// Commit marker last. Any interruption before this write leaves the
			// verified setup retryable instead of exposing a half-enabled account.
			update_user_meta( $user_id, 'login_armor_2fa_enabled', true );
			$secret_ok = 'totp' !== $method
				|| hash_equals(
					(string) $state['encrypted_secret'],
					(string) get_user_meta( $user_id, 'login_armor_2fa_secret', true )
				);
			if ( self::get_user_method( $user_id ) !== $method
				|| ! $secret_ok
				|| ! (bool) get_user_meta( $user_id, 'login_armor_2fa_confirmed', true )
				|| ! self::is_user_enabled( $user_id ) ) {
				return false;
			}
			delete_transient( self::setup_key( $user_id ) );

			return $state;
		} finally {
			self::release_setup_lock( $user_id );
		}
	}

	/**
	 * Validate and retrieve a temporary login token.
	 *
	 * @param string $token Token string.
	 * @return array{user_id:int,redirect_to:string,failures:int,created:int}|false Token data or false.
	 */
	public static function get_token( string $token ): array|false {
		if ( ! preg_match( '/^[a-f0-9]{64}$/', $token ) ) {
			return false;
		}

		$data = get_transient( self::transient_key( $token ) );
		if ( ! is_array( $data ) || ! isset( $data['user_id'] ) ) {
			return false;
		}

		return $data;
	}

	/**
	 * Increment failure count for a token.
	 *
	 * @param string $token Token string.
	 * @return int New failure count.
	 */
	public static function increment_failures( string $token ): int {
		$data = self::get_token( $token );
		if ( false === $data ) {
			return 0;
		}

		$failures = self::record_account_failure( (int) $data['user_id'] );

		// If max failures reached, delete this token and create a lockout. Other
		// pending tokens for the same account are rejected by is_locked_out().
		if ( $failures >= self::MAX_FAILURES ) {
			delete_transient( self::transient_key( $token ) );
			set_transient(
				'login_armor_2fa_lockout_' . $data['user_id'],
				time() + self::LOCKOUT_DURATION,
				self::LOCKOUT_DURATION
			);
		}

		return $failures;
	}

	/**
	 * Check if a user is locked out from 2FA verification.
	 *
	 * @param int $user_id WordPress user ID.
	 * @return bool
	 */
	public static function is_locked_out( int $user_id ): bool {
		$lockout_until = get_transient( 'login_armor_2fa_lockout_' . $user_id );
		if ( false !== $lockout_until && time() < (int) $lockout_until ) {
			return true;
		}
		return self::read_fixed_window_counter( self::account_failure_key( $user_id ), self::IP_WINDOW ) >= self::MAX_FAILURES;
	}

	/**
	 * Check if the current client IP has exceeded the per-IP 2FA failure threshold.
	 *
	 * Complements the per-token counter (MAX_FAILURES) with a sliding window
	 * that blocks an attacker who cycles through fresh tokens from the same IP.
	 *
	 * @return bool True if the IP is currently throttled.
	 */
	public static function is_ip_rate_limited(): bool {
		$ip = \LoginArmor\LoginArmor::get_client_ip();
		if ( ! \LoginArmor\LoginArmor::is_reliable_client_ip( $ip ) ) {
			return false;
		}
		return self::read_fixed_window_counter( self::ip_failure_key( $ip ), self::IP_WINDOW ) >= self::IP_MAX_FAILURES;
	}

	/**
	 * Record a failed 2FA verification attempt for the current client IP.
	 *
	 * Uses the wp_options unique key and a conditional SQL update, so the count
	 * stays atomic with or without a persistent object cache.
	 */
	public static function record_ip_failure(): void {
		$ip = \LoginArmor\LoginArmor::get_client_ip();
		if ( ! \LoginArmor\LoginArmor::is_reliable_client_ip( $ip ) ) {
			return;
		}
		self::increment_fixed_window_counter( self::ip_failure_key( $ip ), self::IP_WINDOW, self::IP_MAX_FAILURES );
	}

	/** Remove expired account and IP fixed-window counter rows. */
	public static function purge_rate_counters(): int {
		global $wpdb;
		$cutoff = time() - self::IP_WINDOW;
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Maintenance cleanup of plugin-owned counters.
		$deleted = (int) $wpdb->query(
			$wpdb->prepare(
				"DELETE FROM {$wpdb->options}
				WHERE (option_name LIKE %s OR option_name LIKE %s)
				AND CAST(SUBSTRING_INDEX(option_value, '|', 1) AS UNSIGNED) < %d",
				$wpdb->esc_like( self::ACCOUNT_FAILURES_PREFIX ) . '%',
				$wpdb->esc_like( self::ATOMIC_IP_FAILURES_PREFIX ) . '%',
				$cutoff
			)
		);
		if ( $deleted > 0 ) {
			wp_cache_flush_group( 'options' );
		}
		return $deleted;
	}

	/** Return the active account-level failure count. */
	public static function get_account_failure_count( int $user_id ): int {
		return self::read_fixed_window_counter( self::account_failure_key( $user_id ), self::IP_WINDOW );
	}

	/** Clear account failures after a successful second-factor verification. */
	private static function clear_account_failures( int $user_id ): void {
		$key = self::account_failure_key( $user_id );
		delete_option( $key );
		wp_cache_delete( $key, 'options' );
	}

	/** Record one failure shared by every pending token for the account. */
	private static function record_account_failure( int $user_id ): int {
		return self::increment_fixed_window_counter( self::account_failure_key( $user_id ), self::IP_WINDOW, self::MAX_FAILURES );
	}

	/** Non-reversible option key for an account counter. */
	private static function account_failure_key( int $user_id ): string {
		return self::ACCOUNT_FAILURES_PREFIX . substr( hash_hmac( 'sha256', (string) $user_id, wp_salt( 'auth' ) ), 0, 32 );
	}

	/** Non-reversible option key for a reliable client IP counter. */
	private static function ip_failure_key( string $ip ): string {
		return self::ATOMIC_IP_FAILURES_PREFIX . substr( hash_hmac( 'sha256', $ip, wp_salt( 'auth' ) ), 0, 32 );
	}

	/** Non-reversible option key for the last accepted TOTP step. */
	private static function totp_step_key( int $user_id ): string {
		return self::TOTP_STEP_PREFIX . substr( hash_hmac( 'sha256', (string) $user_id, wp_salt( 'auth' ) ), 0, 32 );
	}

	/** Fixed transient key for the latest profile setup transaction. */
	private static function setup_key( int $user_id ): string {
		return self::SETUP_PREFIX . substr( hash_hmac( 'sha256', (string) $user_id, wp_salt( 'auth' ) ), 0, 32 );
	}

	/** Acquire the database advisory lock that serializes one user's setup. */
	private static function acquire_setup_lock( int $user_id ): bool {
		global $wpdb;
		if ( $user_id <= 0 ) {
			return false;
		}
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Short advisory lock for a security state transition.
		return 1 === (int) $wpdb->get_var(
			$wpdb->prepare( 'SELECT GET_LOCK(%s, 2)', self::setup_lock_name( $user_id ) )
		);
	}

	/** Release one user's setup advisory lock. */
	private static function release_setup_lock( int $user_id ): void {
		global $wpdb;
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Paired advisory lock release.
		$wpdb->get_var( $wpdb->prepare( 'SELECT RELEASE_LOCK(%s)', self::setup_lock_name( $user_id ) ) );
	}

	/** Build a non-reversible advisory lock name within MySQL's 64-byte limit. */
	private static function setup_lock_name( int $user_id ): string {
		return 'la_2fa_setup_' . substr( hash_hmac( 'sha256', (string) $user_id, wp_salt( 'auth' ) ), 0, 32 );
	}

	/**
	 * Claim a TOTP time step exactly once across every pending login token.
	 */
	public static function claim_totp_step( int $user_id, int $step ): bool {
		global $wpdb;

		if ( $user_id <= 0 || $step <= 0 ) {
			return false;
		}
		$legacy = (int) get_user_meta( $user_id, 'login_armor_2fa_last_totp_step', true );
		if ( $step <= $legacy ) {
			return false;
		}
		$key = self::totp_step_key( $user_id );

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.NotPrepared -- Atomic claim via unique option_name.
		$claimed = (int) $wpdb->query(
			$wpdb->prepare(
				"INSERT IGNORE INTO {$wpdb->options} (option_name, option_value, autoload) VALUES (%s, %s, 'no')",
				$key,
				(string) $step
			)
		);
		if ( 0 === $claimed ) {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Compare-and-swap on plugin-owned option.
			$claimed = (int) $wpdb->query(
				$wpdb->prepare(
					"UPDATE {$wpdb->options} SET option_value = %s WHERE option_name = %s AND CAST(option_value AS UNSIGNED) < %d",
					(string) $step,
					$key,
					$step
				)
			);
		}
		if ( 1 !== $claimed ) {
			return false;
		}
		wp_cache_delete( $key, 'options' );
		update_user_meta( $user_id, 'login_armor_2fa_last_totp_step', $step );
		return true;
	}

	/**
	 * Count one password check of the re-authentication that guards the
	 * profile's 2FA actions (2.8.0).
	 *
	 * Counted before the password is compared, and atomically, like the code
	 * counters. A transient read, then written back plus one, let a burst of
	 * parallel requests all read the same count: each burst added about one,
	 * and far more than the limit fitted in a window.
	 *
	 * @param int $user_id WordPress user ID.
	 * @param int $limit   Attempts allowed in the window.
	 * @param int $window  Window length, in seconds.
	 * @return int Attempts in the current window, this one included, capped at $limit + 1.
	 */
	public static function count_reauth_attempt( int $user_id, int $limit, int $window ): int {
		return self::increment_fixed_window_counter( 'login_armor_reauth_' . $user_id, $window, $limit + 1 );
	}

	/**
	 * Forget the re-authentication attempts of an account once its password matched (2.8.0).
	 *
	 * @param int $user_id WordPress user ID.
	 */
	public static function clear_reauth_attempts( int $user_id ): void {
		delete_option( 'login_armor_reauth_' . $user_id );
	}

	/** Read a plugin-owned fixed-window counter directly from the database. */
	private static function read_fixed_window_counter( string $key, int $window_seconds ): int {
		global $wpdb;

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Security counter requires a current read.
		$value = (string) $wpdb->get_var( $wpdb->prepare( "SELECT option_value FROM {$wpdb->options} WHERE option_name = %s", $key ) );
		list( $window, $count ) = array_pad( explode( '|', $value, 2 ), 2, '0' );
		$current = (int) floor( time() / $window_seconds ) * $window_seconds;
		return (int) $window === $current ? max( 0, (int) $count ) : 0;
	}

	/** Atomically increment and return a bounded fixed-window counter. */
	private static function increment_fixed_window_counter( string $key, int $window_seconds, int $limit ): int {
		global $wpdb;

		$window = (int) floor( time() / $window_seconds ) * $window_seconds;
		$value  = $window . '|1';
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.NotPrepared -- Atomic counter via unique option_name.
		$inserted = (int) $wpdb->query(
			$wpdb->prepare(
				"INSERT IGNORE INTO {$wpdb->options} (option_name, option_value, autoload) VALUES (%s, %s, 'no')",
				$key,
				$value
			)
		);
		if ( 0 === $inserted ) {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.NotPrepared -- Atomic fixed-window increment.
			$wpdb->query(
				$wpdb->prepare(
					"UPDATE {$wpdb->options}
					SET option_value = IF(
						CAST(SUBSTRING_INDEX(option_value, '|', 1) AS UNSIGNED) = %d,
						CONCAT(%d, '|', LEAST(%d, CAST(SUBSTRING_INDEX(option_value, '|', -1) AS UNSIGNED) + 1)),
						%s
					)
					WHERE option_name = %s",
					$window,
					$window,
					$limit,
					$value,
					$key
				)
			);
		}
		wp_cache_delete( $key, 'options' );
		return min( $limit, self::read_fixed_window_counter( $key, $window_seconds ) );
	}

	/**
	 * Consume (delete) a token after successful verification.
	 *
	 * Returns true only if THIS call actually removed the transient. A
	 * concurrent caller that wins the race gets true; the loser gets false
	 * and should reject the request. This is the atomicity primitive that
	 * makes the token single-use even under parallel POSTs.
	 *
	 * @param string $token Token string.
	 * @return bool True if the token was consumed by this call.
	 */
	public static function consume_token( string $token ): bool {
		return (bool) delete_transient( self::transient_key( $token ) );
	}

	/**
	 * Compute the transient key for a clear token.
	 *
	 * The clear token never appears in wp_options.option_name: only its
	 * sha256 digest does. An attacker reading wp_options sees a 64-hex
	 * digest, not a replayable token.
	 *
	 * @param string $token Clear 64-hex token (the value handed to the browser via cookie).
	 * @return string The full transient name (sans WP's '_transient_' prefix).
	 * @since 2.1.0
	 */
	private static function transient_key( string $token ): string {
		return self::TOKEN_PREFIX . hash( 'sha256', $token );
	}

	/**
	 * Resolve the pending-2FA token from request state.
	 *
	 * Priority: signed cookie (V2.1.0+ default) → $_GET['token'] (back-compat
	 * fallback, V2.1.0 only: TODO removed in V2.2.0) → $_POST['token']
	 * (back-compat fallback). Returns '' when no plausible token is present
	 * (caller silently redirects to login).
	 *
	 * The fallback intentionally validates only the structural shape
	 * ([a-f0-9]{64}); authenticity is enforced by the downstream
	 * get_transient(self::transient_key($token)) call, the lookup fails
	 * for any token that wasn't issued by intercept_login.
	 *
	 * @param array{user_id:int,token:string}|null $cookie PendingCookie::read() output.
	 * @param array<string,mixed>                  $get    $_GET superglobal.
	 * @param array<string,mixed>                  $post   $_POST superglobal.
	 * @return string Clear token (64 hex) or '' if none found.
	 * @since 2.1.0
	 */
	private static function resolve_pending_token( ?array $cookie, array $get, array $post ): string {
		if ( null !== $cookie ) {
			return $cookie['token'];
		}
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Used as a back-compat lookup key only; downstream get_transient() validates.
		$get_token = isset( $get['token'] ) ? sanitize_text_field( wp_unslash( (string) $get['token'] ) ) : '';
		if ( preg_match( '/^[a-f0-9]{64}$/', $get_token ) ) {
			return $get_token;
		}
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Used as a back-compat lookup key only; downstream get_transient() validates and the surrounding submit handler verifies a separate _wpnonce.
		$post_token = isset( $post['token'] ) ? sanitize_text_field( wp_unslash( (string) $post['token'] ) ) : '';
		if ( preg_match( '/^[a-f0-9]{64}$/', $post_token ) ) {
			return $post_token;
		}
		return '';
	}

	/**
	 * Complete 2FA verification: set auth cookies and redirect.
	 *
	 * @param int    $user_id     WordPress user ID.
	 * @param string $redirect_to Destination URL.
	 * @param bool   $remember    Whether to set a persistent cookie.
	 */
	public static function complete_login( int $user_id, string $redirect_to = '', bool $remember = false ): void {
		wp_set_auth_cookie( $user_id, $remember );

		// Fire the canonical wp_login cycle. Our own authenticate interception
		// mints the cookie here instead of letting wp_signon() finish, so
		// wp_login never fired on the 2FA path: leaving failed-attempt counters
		// unreset, the success unlogged, the single-session policy unenforced,
		// and any third-party wp_login subscriber skipped (finding P2). Mirror
		// wp_signon()'s order: cookie set, current user established, then
		// wp_login, exactly once, with the same (login, WP_User) signature.
		$user = get_user_by( 'id', $user_id );
		if ( $user instanceof \WP_User ) {
			wp_set_current_user( $user->ID, $user->user_login );
			/**
			 * Core login hook, re-fired for the Login Armor 2FA path so every
			 * wp_login consumer (internal and third-party) runs as it would
			 * after a password-only login.
			 *
			 * @param string   $user_login The authenticated user's login name.
			 * @param \WP_User $user       The authenticated user object.
			 */
			// phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- Intentionally re-firing the WordPress core wp_login hook, not defining a plugin hook.
			do_action( 'wp_login', $user->user_login, $user );
		}

		$redirect_to = wp_validate_redirect( $redirect_to, admin_url() );

		wp_safe_redirect( $redirect_to );
		exit;
	}

	/**
	 * Get 2FA enrollment statistics for enforced roles.
	 *
	 * @return array<string,array{total:int,enrolled:int}> Stats keyed by role slug.
	 */
	/**
	 * The two yes/no facts about enforcement, each bounded to one row.
	 *
	 * `get_enrollment_stats()` below is the right answer for the settings
	 * screen, where the per-role breakdown IS the point and the cost is
	 * expected. It is the wrong answer for anything that must stay cheap: it
	 * runs one unbounded `get_users()` per enforced role, then one uncached
	 * meta read per user returned, because `fields => ID` primes no cache. On
	 * a membership site enforcing two-factor on subscribers that is N+1
	 * queries, and Tools > Site Health must not cost that.
	 *
	 * Both queries below stop at the first matching row, so the cost does not
	 * move with the size of the site. The meta condition mirrors
	 * `is_user_enabled()`, which is `(bool) get_user_meta( ... )`: a row that
	 * exists and holds neither the empty string nor '0'.
	 *
	 * @since 2.7.0
	 *
	 * @return array{roles:array<int,string>,has_members:bool,has_enrolment:bool}
	 */
	public static function enforced_enrolment_state(): array {
		$roles = array_values( array_filter( array_map( 'strval', (array) get_option( self::OPTION_ENFORCE_ROLES, [] ) ) ) );

		if ( empty( $roles ) ) {
			return [
				'roles'         => [],
				'has_members'   => false,
				'has_enrolment' => false,
			];
		}

		$members = get_users(
			[
				'role__in' => $roles,
				'fields'   => 'ID',
				'number'   => 1,
			]
		);

		if ( empty( $members ) ) {
			return [
				'roles'         => $roles,
				'has_members'   => false,
				'has_enrolment' => false,
			];
		}

		$enrolled = get_users(
			[
				'role__in'   => $roles,
				'fields'     => 'ID',
				'number'     => 1,
				'meta_query' => [ // phpcs:ignore WordPress.DB.SlowDBQuery.slow_db_query_meta_query -- Bounded to one row; this IS the cheap shape.
					[
						'key'     => 'login_armor_2fa_enabled',
						'value'   => [ '', '0' ],
						'compare' => 'NOT IN',
					],
				],
			]
		);

		return [
			'roles'         => $roles,
			'has_members'   => true,
			'has_enrolment' => ! empty( $enrolled ),
		];
	}

	public static function get_enrollment_stats(): array {
		$enforce_roles = (array) get_option( self::OPTION_ENFORCE_ROLES, [] );
		$stats         = [];

		foreach ( $enforce_roles as $role ) {
			$users = get_users( [
				'role'   => $role,
				'fields' => 'ID',
			] );

			$enrolled = 0;
			foreach ( $users as $uid ) {
				if ( self::is_user_enabled( (int) $uid ) ) {
					$enrolled++;
				}
			}

			$stats[ $role ] = [
				'total'    => count( $users ),
				'enrolled' => $enrolled,
			];
		}

		return $stats;
	}

	/**
	 * Remove all 2FA data for a user (admin reset).
	 *
	 * By default, destroys every active session of the target user so that a
	 * stolen cookie cannot outlive the reset. Pass false when the caller is
	 * the user themself (profile self-disable) and wants to keep the current
	 * session alive: in that case the caller must invoke
	 * wp_destroy_other_sessions() separately.
	 *
	 * @param int    $user_id          WordPress user ID.
	 * @param bool   $destroy_sessions When true, destroy every active session.
	 * @param string $device_source    Trusted-device revocation source.
	 */
	public static function reset_user( int $user_id, bool $destroy_sessions = true, string $device_source = 'auto' ): void {
		// Revoke trusted-device metadata before clearing enrolment, then delete the
		// row again as a fail-safe if the short advisory lock was unavailable.
		require_once __DIR__ . '/TrustedDevices.php';
		TrustedDevices::revoke_all( $user_id, $device_source );
		delete_user_meta( $user_id, TrustedDevices::META_KEY );
		delete_user_meta( $user_id, 'login_armor_2fa_enabled' );
		delete_user_meta( $user_id, 'login_armor_2fa_method' );
		delete_user_meta( $user_id, 'login_armor_2fa_secret' );
		delete_user_meta( $user_id, 'login_armor_2fa_confirmed' );
		delete_user_meta( $user_id, 'login_armor_2fa_grace_until' );
		delete_user_meta( $user_id, 'login_armor_2fa_last_totp_step' );
		BackupCodes::delete( $user_id );
		delete_transient( self::setup_key( $user_id ) );
		delete_transient( 'login_armor_2fa_lockout_' . $user_id );
		delete_transient( 'login_armor_email_otp_' . $user_id );
		delete_transient( 'login_armor_email_otp_cooldown_' . $user_id );
		delete_option( self::account_failure_key( $user_id ) );
		delete_option( self::totp_step_key( $user_id ) );

		if ( $destroy_sessions ) {
			\WP_Session_Tokens::get_instance( $user_id )->destroy_all();
		}
	}

	// ── Private ─────────────────────────────────────────────────────

	/**
	 * Register all WordPress hooks.
	 */
	private function register_hooks(): void {
		$this->register_login_hooks();

		// Grace period banner in admin.
		add_action( 'admin_notices', [ $this, 'grace_period_notice' ] );

		// Set grace period for new users in enforced roles.
		add_action( 'user_register', [ $this, 'maybe_set_grace_for_new_user' ] );
		add_action( 'set_user_role', [ $this, 'maybe_set_grace_on_role_change' ], 10, 3 );
	}

	/**
	 * The hooks that challenge an enrolled account at login: all a site with
	 * the module off needs when guards_login() still holds (multisite).
	 */
	private function register_login_hooks(): void {
		// Intercept login: after WP authenticates credentials, before setting cookies.
		add_filter( 'authenticate', [ $this, 'intercept_login' ], 99, 3 );

		// Handle verification screen rendering.
		add_action( 'login_init', [ $this, 'maybe_render_verification' ] );

		// Handle verification form submission.
		add_action( 'login_init', [ $this, 'handle_verification_submit' ] );

		// Surface why the user landed back on the login page after a 2FA bounce
		// (lockout, or an expired/lost verification session) instead of dropping
		// them on a bare login form with no explanation.
		add_filter( 'login_message', [ $this, 'maybe_show_2fa_notice' ] );

		require_once __DIR__ . '/Recovery.php';
		Recovery::register();
	}

	/**
	 * Intercept the login process to enforce 2FA.
	 *
	 * Hooked at priority 99 on 'authenticate': after WP has verified
	 * username/password but before the auth cookie is set.
	 *
	 * Parameters untyped with defaults: `authenticate` is the most re-fired
	 * hook in the ecosystem, sometimes with fewer args or a null username.
	 * Strict hints would fatal the whole login screen.
	 *
	 * @param mixed $user     Authenticated user or error.
	 * @param mixed $username Username (expected string).
	 * @param mixed $password Password (expected string).
	 * @return \WP_User|\WP_Error|null|mixed
	 */
	public function intercept_login( $user = null, $username = '', $password = '' ) {
		// 2.7.0 - break-glass safe mode. The second factor is skipped whole,
		// not softened: the two lockouts it has to cure are a lost TOTP device
		// and e-mail codes that never arrive, and neither has a way out from
		// the login screen. Whoever added LOGIN_ARMOR_SAFE_MODE to
		// wp-config.php already has file-level access to the site.
		if ( \LoginArmor\LoginArmor::is_safe_mode() ) {
			return $user;
		}

		// Only intercept successful authentication.
		if ( ! $user instanceof \WP_User ) {
			return $user;
		}

		// Skip if user has no 2FA configured.
		if ( ! self::is_user_enabled( $user->ID ) ) {
			// 2FA is required for this user's role but they have not enrolled.
			// Only where the module is on: a multisite site guarding enrolled
			// accounts with its switch off has no enforcement policy of its own.
			if ( self::is_enabled() && self::is_required_for_user( $user->ID ) ) {
				$grace_until = (int) get_user_meta( $user->ID, 'login_armor_2fa_grace_until', true );

				// Grace never started (e.g. the admin just turned enforcement on for
				// an existing user): start the clock now and let this login through,
				// so the user actually gets their configured window with the banner.
				// Without this, the hard gate below would lock out every unenrolled
				// user (including the admin who just enabled the option) instantly.
				if ( 0 === $grace_until ) {
					self::set_grace_period( $user->ID );
					add_filter( 'login_redirect', static function () {
						return admin_url( 'profile.php#login-armor-2fa' );
					}, 999 );
					return $user;
				}

				// Still within the grace window: allow login, the profile banner nags.
				if ( self::is_in_grace_period( $user->ID ) ) {
					add_filter( 'login_redirect', static function () {
						return admin_url( 'profile.php#login-armor-2fa' );
					}, 999 );
					return $user;
				}

				// Grace has expired and the user never enrolled. Hard-enforce: block
				// the login entirely so the second-factor requirement is a real gate,
				// not a suggestion. Returning a WP_Error stops WordPress before the
				// auth cookie is set. A site can restore the old soft behaviour via
				// the filter below (e.g. a rollout that must never lock anyone out).
				//
				// No self-service enrolment from the login screen: anyone holding the
				// password could enrol THEIR OWN 2FA on the account. Recovery is
				// admin-mediated (WP-CLI `wp login-armor 2fa reset`, or the "restart
				// 2FA grace" admin action, both of which re-open a fresh window).
				/**
				 * Filters whether expired-grace unenrolled users are hard-blocked.
				 *
				 * @param bool $hard    True to block the login (default). False falls
				 *                       back to the pre-2.4.3 soft redirect behaviour.
				 * @param int  $user_id WordPress user ID being enforced.
				 */
				$hard = (bool) apply_filters( 'login_armor_2fa_hard_enforcement', true, $user->ID );

				if ( ! $hard ) {
					add_filter( 'login_redirect', static function () {
						return admin_url( 'profile.php#login-armor-2fa' );
					}, 999 );
					return $user;
				}

				/**
				 * Fires when a user is blocked at login for missing mandatory 2FA.
				 *
				 * @param int $user_id WordPress user ID that was blocked.
				 */
				do_action( 'login_armor_2fa_enforcement_blocked', $user->ID );

				return new \WP_Error(
					'login_armor_2fa_setup_required',
					__( 'Two-factor authentication is required for your account and the setup deadline has passed. Please contact a site administrator to regain access.', 'login-armor' )
				);
			}
			return $user;
		}

		// Check if user is locked out from too many failed 2FA attempts.
		if ( self::is_locked_out( $user->ID ) ) {
			return new \WP_Error(
				'login_armor_2fa_lockout',
				__( 'Too many failed verification attempts. Please try again in 15 minutes.', 'login-armor' )
			);
		}

		// Check if the client IP has been rate-limited for 2FA failures.
		if ( self::is_ip_rate_limited() ) {
			return new \WP_Error(
				'login_armor_2fa_ip_lockout',
				__( 'Too many failed verification attempts from your network. Please try again later.', 'login-armor' )
			);
		}

		// Trusted device shortcut: if the user has a valid cookie for this browser,
		// skip the 2FA challenge entirely. The cookie is HMAC-signed; a salt rotation
		// or password change invalidates it automatically (TrustedDevices listens for
		// those events and revokes).
		require_once __DIR__ . '/TrustedDevices.php';
		if ( TrustedDevices::is_current_request_trusted( $user->ID ) ) {
			/**
			 * Fires when the 2FA step is bypassed thanks to a trusted device.
			 *
			 * @param int $user_id WordPress user ID.
			 */
			do_action( 'login_armor_2fa_skipped_trusted_device', $user->ID );
			return $user;
		}

		// Fail closed with an actionable error if the account is marked as
		// enrolled but every configured verification method has since become
		// unavailable. Do not mint a pending session that can never complete.
		if ( empty( self::get_available_methods_for_user( $user->ID ) ) ) {
			return new \WP_Error(
				'login_armor_2fa_unavailable',
				__( 'No two-factor verification method is currently available for your account. Please contact a site administrator.', 'login-armor' )
			);
		}

		// Determine redirect.
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Reading redirect_to from login form, no state change.
		$raw_redirect = isset( $_POST['redirect_to'] ) ? sanitize_url( wp_unslash( $_POST['redirect_to'] ) ) : '';
		$redirect_to  = wp_validate_redirect( $raw_redirect, admin_url() );
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Reading rememberme from login form, no state change.
		$remember = ! empty( $_POST['rememberme'] );

		// Create temporary token.
		$token = self::create_token( $user->ID, $redirect_to );

		// Store remember-me preference in the token.
		$token_data              = self::get_token( $token );
		$token_data['remember']  = $remember;
		set_transient( self::transient_key( $token ), $token_data, self::TOKEN_TTL );

		// If user has email method, send the code now. Track the outcome
		// so the verification screen can tell the user when delivery fails
		// (wp_mail() returning false: SMTP misconfiguration, rate-limiting,
		// provider block). Before 2.1.4 the return was discarded and users
		// sat on the verify screen waiting for a code that was never sent.
		$email_send_failed = false;
		if ( self::get_user_method( $user->ID ) === 'email' ) {
			require_once __DIR__ . '/EmailOTP.php';
			$email_send_failed = ( false === EmailOTP::send_code( $user->ID ) );
			if ( $email_send_failed ) {
				$token_data['send_failed'] = true;
				set_transient( self::transient_key( $token ), $token_data, self::TOKEN_TTL );
			}
		}

		// Mint the pending cookie carrying the clear token. The transient key is
		// hash('sha256', $token), so the DB never sees the clear token. The URL
		// no longer carries it either: only the bare verify param.
		require_once __DIR__ . '/PendingCookie.php';
		PendingCookie::mint( $user->ID, $token );

		$verify_url = add_query_arg(
			[ self::VERIFY_PARAM => 'verify' ],
			\LoginArmor\HideLogin::get_login_url()
		);

		wp_safe_redirect( $verify_url );
		exit;
	}

	/**
	 * Render the 2FA verification screen if requested.
	 */
	public function maybe_render_verification(): void {
		// 2.7.0 - in safe mode a stale verify URL, or a pending cookie minted
		// before the constant was added, must fall through to the plain login
		// form rather than to a challenge nobody can answer.
		if ( \LoginArmor\LoginArmor::is_safe_mode() ) {
			return;
		}

		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Checking URL parameter presence only.
		if ( ! isset( $_GET[ self::VERIFY_PARAM ] ) || $_GET[ self::VERIFY_PARAM ] !== 'verify' ) {
			return;
		}

		require_once __DIR__ . '/PendingCookie.php';
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended,WordPress.Security.NonceVerification.Missing -- resolve_pending_token() is a back-compat wrapper; cookie is signed, transient lookup validates the token.
		$token      = self::resolve_pending_token( PendingCookie::read(), $_GET, $_POST );
		$token_data = '' === $token ? false : self::get_token( $token );

		if ( false === $token_data ) {
			wp_safe_redirect( add_query_arg( 'login_armor_error', '2fa_expired', \LoginArmor\HideLogin::get_login_url() ) );
			exit;
		}

		// Don't render if this is a POST (handle_verification_submit will run).
		if ( isset( $_SERVER['REQUEST_METHOD'] ) && 'POST' === $_SERVER['REQUEST_METHOD'] ) {
			return;
		}

		$user_id = (int) $token_data['user_id'];
		$user    = get_userdata( $user_id );
		if ( ! $user ) {
			self::consume_token( $token );
			wp_safe_redirect( add_query_arg( 'login_armor_error', '2fa_expired', \LoginArmor\HideLogin::get_login_url() ) );
			exit;
		}

		// Honour an explicit "Use a different method" switch. The links in the
		// template carry ?method=<slug>; before 2.1.23 this param was ignored
		// and every link re-rendered the same screen. Only accept a method the
		// user can actually use (same rules as the template), else fall back to
		// the stored method.
		$stored_method     = self::get_user_method( $user_id );
		$available_methods = self::get_available_methods_for_user( $user_id );
		if ( empty( $available_methods ) ) {
			self::consume_token( $token );
			wp_safe_redirect( add_query_arg( 'login_armor_error', '2fa_unavailable', \LoginArmor\HideLogin::get_login_url() ) );
			exit;
		}
		$method = in_array( $stored_method, $available_methods, true ) ? $stored_method : $available_methods[0];
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Method switch is gated by the validated pending cookie above; no state change beyond mailing the user their own code.
		$requested = isset( $_GET['method'] ) ? sanitize_text_field( wp_unslash( (string) $_GET['method'] ) ) : '';
		if ( '' !== $requested && in_array( $requested, $available_methods, true ) ) {
			$method = $requested;
		}

		// The initial intercept sends only when email is the stored method.
		// Send here for a legitimate switch or for a safe fallback after the
		// stored method became unavailable. A refresh never sends a second code
		// while one is pending, and a recorded delivery failure is not retried
		// automatically in a loop.
		if ( 'email' === $method ) {
			require_once __DIR__ . '/EmailOTP.php';
			if ( ! EmailOTP::has_pending_code( $user_id ) && empty( $token_data['send_failed'] ) ) {
				$switch_send_failed = ( false === EmailOTP::send_code( $user_id ) );
				if ( $requested === $method && $method !== $stored_method ) {
					$token_data['resent'] = ! $switch_send_failed;
				}
				$token_data['send_failed'] = $switch_send_failed;
				set_transient( self::transient_key( $token ), $token_data, self::TOKEN_TTL );
			}
		}

		$la_2fa_token        = $token;
		$la_2fa_user         = $user;
		$la_2fa_method       = $method;
		$la_2fa_error        = '';
		$la_2fa_failures     = max( (int) ( $token_data['failures'] ?? 0 ), self::get_account_failure_count( (int) $user_id ) );
		$la_2fa_resent       = ! empty( $token_data['resent'] );
		$la_2fa_send_failed  = ! empty( $token_data['send_failed'] );

		// One-shot flags: clear them once the notice/error has been rendered.
		if ( $la_2fa_resent || $la_2fa_send_failed ) {
			unset( $token_data['resent'] );
			unset( $token_data['send_failed'] );
			set_transient( self::transient_key( $token ), $token_data, self::TOKEN_TTL );
		}

		// Load verification template.
		require_once LOGIN_ARMOR_DIR . 'admin/views/two-factor-verify.php';
		exit;
	}

	/**
	 * Prepend an explanatory notice on the login page when the user was bounced
	 * back from the 2FA flow. Reads the `login_armor_error` query arg set by the
	 * verification handlers. Without this, every bounce (lockout, expired or lost
	 * verification session) dumped the user on a bare login form with no clue.
	 *
	 * @param string $message Existing login_message HTML.
	 * @return string
	 */
	public function maybe_show_2fa_notice( $message = '' ) {
		if ( ! is_string( $message ) ) {
			return $message; // Untyped defensively: pass through non-string values from third-party `login_message` filters.
		}
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Read-only display of a status code in a redirect target; no state change.
		$code = isset( $_GET['login_armor_error'] ) ? sanitize_key( wp_unslash( $_GET['login_armor_error'] ) ) : '';
		if ( '' === $code ) {
			return $message;
		}

		$text = match ( $code ) {
			'2fa_lockout'   => __( 'Too many incorrect verification codes. For your security, verification is locked for a few minutes. Please wait, then sign in again.', 'login-armor' ),
			'2fa_expired'   => __( 'Your verification session expired or could not be found. Please sign in again to receive a new code.', 'login-armor' ),
			'2fa_unavailable' => __( 'No two-factor verification method is currently available for your account. Please contact a site administrator.', 'login-armor' ),
			default         => '',
		};

		if ( '' === $text ) {
			return $message;
		}

		return $message . '<div id="login_error" class="notice notice-error">' . esc_html( $text ) . '</div>';
	}

	/**
	 * Handle 2FA verification form submission.
	 */
	public function handle_verification_submit(): void {
		// 2.7.0 - safe mode skips the gate whole, submission included; see
		// maybe_render_verification().
		if ( \LoginArmor\LoginArmor::is_safe_mode() ) {
			return;
		}

		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Checking URL parameter presence.
		if ( ! isset( $_GET[ self::VERIFY_PARAM ] ) || $_GET[ self::VERIFY_PARAM ] !== 'verify' ) {
			return;
		}

		if ( ! isset( $_SERVER['REQUEST_METHOD'] ) || 'POST' !== $_SERVER['REQUEST_METHOD'] ) {
			return;
		}

		// Resolve the pending verification session. The signed la_2fa_pending
		// cookie is the preferred authenticator (HMAC-signed, HttpOnly,
		// SameSite=Strict: unforgeable and not replayable cross-origin). But it
		// must NOT be the only way in: some browsers/environments fail to send (or
		// send a stale) la_2fa_pending on the verify POST, which dumped legitimate
		// users back on the login page with "session expired". Reported on
		// locationcantin.fr: the e-mail-OTP flow worked in Firefox and in scripted
		// Chrome against the same server, yet bounced on the reporter's Chrome:
		// i.e. the cookie was unusable at submit time. So we try, in order, the
		// signed cookie, the token echoed in the POST body (hidden form field) and
		// the legacy GET token, and use the FIRST one that resolves to a live
		// pending transient. The transient lookup is what authenticates the token
		// (it only exists for a token minted by intercept_login).
		require_once __DIR__ . '/PendingCookie.php';
		$signed_cookie = PendingCookie::read();

		$candidates = [];
		if ( null !== $signed_cookie ) {
			$candidates[] = [ 'token' => $signed_cookie['token'], 'from_cookie' => true ];
		}
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Lookup key only, validated by get_token() below; nonce is enforced for this non-cookie source before any state change.
		$post_token = isset( $_POST['token'] ) ? sanitize_text_field( wp_unslash( (string) $_POST['token'] ) ) : '';
		if ( preg_match( '/^[a-f0-9]{64}$/', $post_token ) ) {
			$candidates[] = [ 'token' => $post_token, 'from_cookie' => false ];
		}
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Lookup key only, validated by get_token() below; nonce is enforced for this non-cookie source before any state change.
		$get_token = isset( $_GET['token'] ) ? sanitize_text_field( wp_unslash( (string) $_GET['token'] ) ) : '';
		if ( preg_match( '/^[a-f0-9]{64}$/', $get_token ) ) {
			$candidates[] = [ 'token' => $get_token, 'from_cookie' => false ];
		}

		$token       = '';
		$token_data  = false;
		$from_cookie = false;
		foreach ( $candidates as $candidate ) {
			$data = self::get_token( $candidate['token'] );
			if ( is_array( $data ) ) {
				$token       = $candidate['token'];
				$token_data  = $data;
				$from_cookie = $candidate['from_cookie'];
				break;
			}
		}

		if ( false === $token_data ) {
			// No source resolved to a live pending session → genuinely expired or lost.
			wp_safe_redirect( add_query_arg( 'login_armor_error', '2fa_expired', \LoginArmor\HideLogin::get_login_url() ) );
			exit;
		}

		// CSRF protection. When the session came from the signed SameSite=Strict
		// cookie, that cookie already authenticates the request, so the nonce is
		// only defence-in-depth (the nonce lives in cacheable login HTML that
		// Chrome's bfcache could resubmit stale: making it the sole gate bounced
		// legitimate users). But when the session was resolved from the POST/GET
		// token instead (no usable signed cookie), the nonce is the CSRF guard and
		// IS required.
		$nonce_ok = isset( $_POST['_wpnonce'] )
			&& wp_verify_nonce( sanitize_text_field( wp_unslash( $_POST['_wpnonce'] ) ), 'login_armor_2fa_verify' );
		if ( ! $from_cookie && ! $nonce_ok ) {
			wp_safe_redirect( add_query_arg( 'login_armor_error', '2fa_expired', \LoginArmor\HideLogin::get_login_url() ) );
			exit;
		}

		$user_id = $token_data['user_id'];
		$code    = isset( $_POST['code'] ) ? sanitize_text_field( wp_unslash( $_POST['code'] ) ) : '';
		$method  = isset( $_POST['method'] ) ? sanitize_text_field( wp_unslash( $_POST['method'] ) ) : self::get_user_method( $user_id );
		$method_available = self::is_method_available_for_user( (int) $user_id, $method );

		// Reject submissions from IPs that exceeded the sliding-window failure threshold.
		if ( self::is_ip_rate_limited() ) {
			wp_safe_redirect( add_query_arg( 'login_armor_error', '2fa_lockout', \LoginArmor\HideLogin::get_login_url() ) );
			exit;
		}

		// 2.8.0: and from an ACCOUNT that is locked out. increment_failures()
		// deletes the one token that reached the threshold and relies on this
		// check for every other pending token of the same account, as its own
		// comment says; until now nothing here asked, so each token issued
		// before the lockout kept one more guess for its ten-minute life.
		if ( self::is_locked_out( (int) $user_id ) ) {
			wp_safe_redirect( add_query_arg( 'login_armor_error', '2fa_lockout', \LoginArmor\HideLogin::get_login_url() ) );
			exit;
		}

		// Handle resend request for email method.
		if ( isset( $_POST['resend'] ) && 'email' === $method && $method_available ) {
			require_once __DIR__ . '/EmailOTP.php';
			$sent = EmailOTP::send_code( $user_id );

			// Persist the "resent" flag: and the failure flag when wp_mail()
			// returned false: in the token transient so the verify screen
			// can surface either the success notice or an actionable error.
			$token_data['resent']      = true;
			$token_data['send_failed'] = ( false === $sent );
			set_transient( self::transient_key( $token ), $token_data, self::TOKEN_TTL );

			// Cookie carries the token; URL stays clean.
			$verify_url = add_query_arg(
				[ self::VERIFY_PARAM => 'verify' ],
				\LoginArmor\HideLogin::get_login_url()
			);
			wp_safe_redirect( $verify_url );
			exit;
		}

		// Validate the code.
		$valid = false;

		if ( $method_available && 'backup' === $method ) {
			require_once __DIR__ . '/BackupCodes.php';
			$valid = BackupCodes::validate( $user_id, $code );

			if ( $valid ) {
				// Fire notification if this was the last or very few remaining.
				$remaining = BackupCodes::remaining( $user_id );

				/**
				 * Fires when a backup code is used.
				 *
				 * @param int $user_id   WordPress user ID.
				 * @param int $remaining Number of remaining backup codes.
				 */
				do_action( 'login_armor_2fa_backup_used', $user_id, $remaining );
			}
		} elseif ( $method_available && 'email' === $method ) {
			require_once __DIR__ . '/EmailOTP.php';
			$valid = EmailOTP::validate( $user_id, $code );
		} elseif ( $method_available && 'totp' === $method ) {
			require_once __DIR__ . '/TOTP.php';
			$encrypted_secret = (string) get_user_meta( $user_id, 'login_armor_2fa_secret', true );
			$secret           = TOTP::decrypt_secret( $encrypted_secret );
			if ( false === $secret ) {
				/**
				 * Fires when stored TOTP secret cannot be decrypted (e.g. AUTH_KEY rotated).
				 *
				 * @param int $user_id WordPress user ID whose secret failed to decrypt.
				 */
				do_action( 'login_armor_2fa_totp_decrypt_failed', $user_id );
			} else {
				$matched_step = null;
				$valid        = TOTP::validate( $code, $secret, $matched_step );

					// Claim the accepted step through an atomic option compare-and-swap.
					// This is account-scoped, so two distinct pending login tokens cannot
					// both consume the same mathematically valid TOTP window.
					if ( $valid && null !== $matched_step ) {
						$valid = self::claim_totp_step( (int) $user_id, $matched_step );
					}
			}
		}

		if ( $valid ) {
			// Atomic consume: if another concurrent request already consumed the
			// token (race between two valid POSTs), reject this one: we never
			// want two auth cookies minted from a single 2FA challenge.
			if ( ! self::consume_token( $token ) ) {
				wp_safe_redirect( \LoginArmor\HideLogin::get_login_url() );
				exit;
			}

			self::clear_account_failures( (int) $user_id );

			// Pending cookie has done its job: discard so the browser doesn't
			// replay it on the next login attempt.
			PendingCookie::clear();

			require_once __DIR__ . '/TrustedDevices.php';
			// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Nonce is already verified at the top of handle_verification_submit.
			TrustedDevices::maybe_grant( $user_id, wp_unslash( $_POST ) );

			/**
			 * Fires on successful 2FA verification.
			 *
			 * @param int    $user_id WordPress user ID.
			 * @param string $method  The method used ('totp', 'email', 'backup').
			 */
			do_action( 'login_armor_2fa_verified', $user_id, $method );

			$remember    = ! empty( $token_data['remember'] );
			$redirect_to = $token_data['redirect_to'] ?? admin_url();

			self::complete_login( $user_id, $redirect_to, $remember );
			// complete_login calls exit.
		}

		// Invalid code.
		self::record_ip_failure();
		$failures = self::increment_failures( $token );

		/**
		 * Fires on failed 2FA verification.
		 *
		 * @param int    $user_id  WordPress user ID.
		 * @param string $method   The method attempted.
		 * @param int    $failures Number of consecutive failures.
		 */
		do_action( 'login_armor_2fa_failed', $user_id, $method, $failures );

		if ( $failures >= self::MAX_FAILURES ) {
			// Token was deleted by increment_failures: drop the now-orphaned cookie too.
			PendingCookie::clear();
			wp_safe_redirect( add_query_arg( 'login_armor_error', '2fa_lockout', \LoginArmor\HideLogin::get_login_url() ) );
			exit;
		}

		// Re-render verification screen with error.
		$user = get_userdata( $user_id );

		// Get a fresh token (failures were incremented, the token is updated).
		// Keep the user on the method they just attempted (not the stored default),
		// so a TOTP user who switched to e-mail and mistyped the code doesn't get
		// silently snapped back to the authenticator screen.
		$available_methods = self::get_available_methods_for_user( (int) $user_id );
		if ( empty( $available_methods ) ) {
			self::consume_token( $token );
			PendingCookie::clear();
			wp_safe_redirect( add_query_arg( 'login_armor_error', '2fa_unavailable', \LoginArmor\HideLogin::get_login_url() ) );
			exit;
		}
		$la_2fa_token    = $token;
		$la_2fa_user     = $user;
		$la_2fa_method   = in_array( $method, $available_methods, true ) ? $method : $available_methods[0];
		$la_2fa_error    = __( 'Invalid verification code. Please try again.', 'login-armor' );
		$la_2fa_failures = $failures;
		$la_2fa_resent   = false;

		require_once LOGIN_ARMOR_DIR . 'admin/views/two-factor-verify.php';
		exit;
	}

	/**
	 * Show grace period admin notice for users who need to set up 2FA.
	 */
	public function grace_period_notice(): void {
		$user = wp_get_current_user();
		if ( ! $user->exists() ) {
			return;
		}

		// Only show for users whose role requires 2FA.
		if ( ! self::is_required_for_user( $user->ID ) ) {
			return;
		}

		// Already configured.
		if ( self::is_user_enabled( $user->ID ) ) {
			return;
		}

		$grace_until = (int) get_user_meta( $user->ID, 'login_armor_2fa_grace_until', true );

		if ( $grace_until > 0 && time() < $grace_until ) {
			$date = wp_date( get_option( 'date_format' ), $grace_until );
			printf(
				'<div class="notice la-notice notice-warning"><p>%s <a href="%s">%s</a></p></div>',
				sprintf(
					/* translators: %s: deadline date */
					esc_html__( 'Two-factor authentication will be required for your account before %s.', 'login-armor' ),
					esc_html( $date )
				),
				esc_url( admin_url( 'profile.php#login-armor-2fa' ) ),
				esc_html__( 'Set up now', 'login-armor' )
			);
		} elseif ( 0 === $grace_until ) {
			// No grace set yet: this shouldn't happen if hooks work, but be safe.
			self::set_grace_period( $user->ID );
		}
	}

	/**
	 * Set grace period for newly registered users if their role requires 2FA.
	 *
	 * @param int $user_id New user ID.
	 */
	public function maybe_set_grace_for_new_user( $user_id = 0 ): void {
		$user_id = (int) $user_id; // Untyped defensively: `user_register` is re-fired by registration/import plugins.
		if ( $user_id <= 0 ) {
			return;
		}
		if ( self::is_required_for_user( $user_id ) ) {
			self::set_grace_period( $user_id );
		}
	}

	/**
	 * Set grace period when a user's role changes to an enforced role.
	 *
	 * Parameters untyped with defaults: `set_user_role` is re-fired by
	 * membership/role plugins, sometimes with degraded arity or types.
	 *
	 * @param mixed $user_id   User ID (expected int).
	 * @param mixed $new_role  New role (expected string).
	 * @param mixed $old_roles Previous roles (expected array).
	 */
	public function maybe_set_grace_on_role_change( $user_id = 0, $new_role = '', $old_roles = array() ): void {
		$user_id = (int) $user_id;
		if ( $user_id <= 0 || ! is_string( $new_role ) ) {
			return;
		}
		$enforce_roles = (array) get_option( self::OPTION_ENFORCE_ROLES, [] );
		if ( in_array( $new_role, $enforce_roles, true ) && ! self::is_user_enabled( $user_id ) ) {
			self::set_grace_period( $user_id );
		}
	}
}
