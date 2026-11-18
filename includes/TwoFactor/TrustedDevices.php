<?php
/**
 * Two-Factor Trusted Devices.
 *
 * After a successful 2FA verification, the user may opt in to trust the current
 * device for N days. A signed cookie is minted and the device metadata is
 * persisted in user_meta. On next login, if the cookie is present and
 * cryptographically valid, the 2FA step is skipped.
 *
 * Security boundaries enforced:
 *   1. Cookie signing uses hash_hmac with wp_salt('auth'). Rotating AUTH_KEY or
 *      AUTH_SALT automatically invalidates every cookie: no extra bookkeeping.
 *   2. All equality checks on signatures, device ids and user ids use
 *      hash_equals (constant-time).
 *   3. Devices expire via an explicit expires_at field on the user_meta record,
 *      checked on every is_trusted() call (lazy) and by a daily cron (safety
 *      net).
 *   4. Maximum 5 devices per user; the oldest is evicted when a 6th is minted.
 *   5. Auto-revoke on password_reset, after_password_reset, wp_set_password,
 *      2FA disable by user, AUTH_KEY rotation (detected via the existing
 *      login_armor_2fa_totp_decrypt_failed hook) and explicit user revoke.
 *
 * @package LoginArmor\TwoFactor
 * @since   2.0.0
 */

namespace LoginArmor\TwoFactor;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class TrustedDevices {

	/** @var string Cookie name: HttpOnly, Secure (when over HTTPS), SameSite=Lax, path=/. */
	public const COOKIE_NAME = 'la_2fa_td';

	/** @var string user_meta key storing the array of active devices. */
	public const META_KEY = 'login_armor_2fa_trusted_devices';

	/** @var string Option key: global toggle. */
	public const OPTION_ENABLED = 'login_armor_2fa_trusted_devices_enabled';

	/** @var string Option key: trust duration in days. */
	public const OPTION_DURATION_DAYS = 'login_armor_2fa_trusted_devices_duration_days';

	/** @var int[] Allowed duration values for the admin dropdown. */
	public const ALLOWED_DURATIONS = [ 7, 14, 30, 60, 90 ];

	/** @var int Default trust duration when option missing. */
	public const DEFAULT_DURATION_DAYS = 30;

	/** @var int Maximum concurrent devices per user. */
	public const MAX_DEVICES_PER_USER = 5;

	/** @var string Cron hook for expired-device cleanup. */
	public const CRON_HOOK = 'login_armor_2fa_trusted_devices_cleanup';

	/**
	 * True when the admin has globally enabled the trusted-devices feature.
	 */
	public static function is_feature_enabled(): bool {
		return (bool) get_option( self::OPTION_ENABLED, true );
	}

	/**
	 * Admin-configured trust duration in days. Bounded to ALLOWED_DURATIONS.
	 */
	public static function get_duration_days(): int {
		$raw = (int) get_option( self::OPTION_DURATION_DAYS, self::DEFAULT_DURATION_DAYS );
		if ( ! in_array( $raw, self::ALLOWED_DURATIONS, true ) ) {
			return self::DEFAULT_DURATION_DAYS;
		}
		return $raw;
	}

	/** Acquire the per-user mutation lock for the serialized device list. */
	private static function acquire_user_lock( int $user_id ): bool {
		global $wpdb;
		$database  = defined( 'DB_NAME' ) ? (string) DB_NAME : '';
		$lock_name = substr( 'login_armor_devices_' . md5( $database . '|' . $wpdb->prefix . '|' . $user_id ), 0, 64 );
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Advisory lock for serialized user-meta mutation.
		return 1 === (int) $wpdb->get_var( $wpdb->prepare( 'SELECT GET_LOCK(%s, 2)', $lock_name ) );
	}

	/** Release the per-user trusted-device mutation lock. */
	private static function release_user_lock( int $user_id ): void {
		global $wpdb;
		$database  = defined( 'DB_NAME' ) ? (string) DB_NAME : '';
		$lock_name = substr( 'login_armor_devices_' . md5( $database . '|' . $wpdb->prefix . '|' . $user_id ), 0, 64 );
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Paired advisory-lock release.
		$wpdb->get_var( $wpdb->prepare( 'SELECT RELEASE_LOCK(%s)', $lock_name ) );
	}

	/** Filter malformed and expired records without writing user meta. */
	private static function live_devices( mixed $raw ): array {
		if ( ! is_array( $raw ) ) {
			return array();
		}
		$now  = time();
		$live = array();
		foreach ( $raw as $device ) {
			if ( ! is_array( $device ) || empty( $device['id'] ) || empty( $device['expires_at'] ) ) {
				continue;
			}
			if ( (int) $device['expires_at'] <= $now ) {
				continue;
			}
			$live[] = $device;
		}
		return $live;
	}

	/**
	 * List trusted devices for a user (expired entries filtered out AND pruned).
	 *
	 * @return array<int,array{id:string,label:string,ip_at_grant:string,granted_at:int,expires_at:int,last_seen_at:int}>
	 */
	public static function list_for_user( int $user_id ): array {
		$raw = get_user_meta( $user_id, self::META_KEY, true );
		$live = self::live_devices( $raw );
		if ( is_array( $raw ) && count( $live ) !== count( $raw ) && self::acquire_user_lock( $user_id ) ) {
			try {
				$fresh = get_user_meta( $user_id, self::META_KEY, true );
				$live  = self::live_devices( $fresh );
				update_user_meta( $user_id, self::META_KEY, $live );
			} finally {
				self::release_user_lock( $user_id );
			}
		}
		return $live;
	}

	/**
	 * Build the HMAC signature for a cookie payload.
	 *
	 * The signature covers user_id, device_id, and expires_at, so tampering with
	 * any of the three invalidates the cookie. Keyed on wp_salt('auth') so a
	 * salt rotation (Lot 11) invalidates every signature site-wide.
	 */
	private static function sign( int $user_id, string $device_id, int $expires_at ): string {
		$payload = $user_id . '|' . $device_id . '|' . $expires_at;
		return hash_hmac( 'sha256', $payload, wp_salt( 'auth' ) );
	}

	/**
	 * Parse a raw cookie value into its structured parts, or null on malformed input.
	 *
	 * Format: `<user_id>.<device_id_hex>.<expires_at>.<signature_hex>`, dots chosen
	 * because they are not base64/base64url characters (id and signature are hex,
	 * user_id and expires_at are integers).
	 *
	 * @return array{user_id:int,device_id:string,expires_at:int,signature:string}|null
	 */
	private static function parse_cookie( string $raw ): ?array {
		$parts = explode( '.', $raw );
		if ( 4 !== count( $parts ) ) {
			return null;
		}
		[ $user_id_raw, $device_id, $expires_raw, $signature ] = $parts;
		if (
			! ctype_digit( $user_id_raw )
			|| ! preg_match( '/^[a-f0-9]{32}$/', $device_id )
			|| ! ctype_digit( $expires_raw )
			|| ! preg_match( '/^[a-f0-9]{64}$/', $signature )
		) {
			return null;
		}
		return [
			'user_id'    => (int) $user_id_raw,
			'device_id'  => $device_id,
			'expires_at' => (int) $expires_raw,
			'signature'  => $signature,
		];
	}

	/**
	 * Generate a new opaque device id (16 bytes → 32 hex chars).
	 */
	private static function generate_device_id(): string {
		return bin2hex( random_bytes( 16 ) );
	}

	/**
	 * Parse a User-Agent into a short human-readable label for display in the
	 * profile UI. Kept deliberately simple: no regex zoo, no MaxMind, no external
	 * lookups.
	 */
	private static function label_from_user_agent( string $ua ): string {
		$ua = trim( $ua );
		if ( '' === $ua ) {
			return __( 'Unknown device', 'login-armor' );
		}

		$browser = 'Browser';
		if ( false !== stripos( $ua, 'Edg/' ) )         { $browser = 'Edge'; }
		elseif ( false !== stripos( $ua, 'OPR/' ) )     { $browser = 'Opera'; }
		elseif ( false !== stripos( $ua, 'Firefox/' ) ) { $browser = 'Firefox'; }
		elseif ( false !== stripos( $ua, 'Chrome/' ) )  { $browser = 'Chrome'; }
		elseif ( false !== stripos( $ua, 'Safari/' ) )  { $browser = 'Safari'; }

		$os = 'OS';
		if ( false !== stripos( $ua, 'Windows' ) )        { $os = 'Windows'; }
		elseif ( false !== stripos( $ua, 'Mac OS X' ) )   { $os = 'macOS'; }
		elseif ( false !== stripos( $ua, 'Android' ) )    { $os = 'Android'; }
		elseif ( false !== stripos( $ua, 'iPhone' ) )     { $os = 'iOS'; }
		elseif ( false !== stripos( $ua, 'iPad' ) )       { $os = 'iPad'; }
		elseif ( false !== stripos( $ua, 'Linux' ) )      { $os = 'Linux'; }

		return $browser . ' on ' . $os;
	}

	/**
	 * Mint a new trusted-device cookie if the user opted in on the verify screen.
	 *
	 * Call this AFTER consume_token() succeeds and BEFORE complete_login(). Fires
	 * login_armor_2fa_device_trusted hook. Sets the cookie header directly via
	 * PHP setcookie(): no output buffering assumption.
	 *
	 * @param int                 $user_id Authenticated user ID.
	 * @param array<string,mixed> $request POST payload (must contain 'la_trust_device' to opt in).
	 */
	public static function maybe_grant( int $user_id, array $request ): void {
		if ( ! self::is_feature_enabled() ) {
			return;
		}
		if ( empty( $request['la_trust_device'] ) ) {
			return;
		}

		// Skip grant when the user picked « Backup code »: backup codes ARE the recovery
		// path. Granting trust on them is a user-hostile trap: it rewards a one-shot
		// fallback with a persistent 2FA skip.
		$method = isset( $request['method'] ) ? (string) $request['method'] : '';
		if ( 'backup' === $method ) {
			return;
		}

		$duration    = self::get_duration_days();
		$expires_at  = time() + ( $duration * DAY_IN_SECONDS );
		$device_id   = self::generate_device_id();
		$ip          = \LoginArmor\LoginArmor::get_client_ip();
		$ua          = isset( $_SERVER['HTTP_USER_AGENT'] ) ? sanitize_text_field( wp_unslash( (string) $_SERVER['HTTP_USER_AGENT'] ) ) : '';
		$label       = self::label_from_user_agent( $ua );

		$device = [
			'id'           => $device_id,
			'label'        => $label,
			'ip_at_grant'  => $ip,
			'granted_at'   => time(),
			'expires_at'   => $expires_at,
			'last_seen_at' => time(),
		];

		if ( ! self::acquire_user_lock( $user_id ) ) {
			return;
		}
		try {
			// Enforce max 5 devices: oldest-first eviction on the latest row.
			$devices = self::live_devices( get_user_meta( $user_id, self::META_KEY, true ) );
			if ( count( $devices ) >= self::MAX_DEVICES_PER_USER ) {
				usort( $devices, static fn( $a, $b ) => (int) $a['granted_at'] <=> (int) $b['granted_at'] );
				$devices = array_slice( $devices, -( self::MAX_DEVICES_PER_USER - 1 ) );
			}
			$devices[] = $device;
			update_user_meta( $user_id, self::META_KEY, $devices );
		} finally {
			self::release_user_lock( $user_id );
		}

		// Mint the cookie.
		$signature = self::sign( $user_id, $device_id, $expires_at );
		$value     = $user_id . '.' . $device_id . '.' . $expires_at . '.' . $signature;
		setcookie(
			self::COOKIE_NAME,
			$value,
			[
				'expires'  => $expires_at,
				'path'     => COOKIEPATH ?: '/',
				'domain'   => COOKIE_DOMAIN,
				'secure'   => is_ssl(),
				'httponly' => true,
				'samesite' => 'Lax',
			]
		);

		/**
		 * Fires after a trusted device has been granted for a user.
		 *
		 * @param int                                                                                                                                                            $user_id WP user id.
		 * @param array{id:string,label:string,ip_at_grant:string,granted_at:int,expires_at:int,last_seen_at:int} $device  Device metadata.
		 */
		do_action( 'login_armor_2fa_device_trusted', $user_id, $device );
	}

	/**
	 * Verify the incoming request carries a valid trusted-device cookie for $user_id.
	 *
	 * Returns true ONLY when every check passes: cookie present, well-formed,
	 * signed correctly (constant-time compare), user matches, not expired, device
	 * still exists in user_meta. Updates last_seen_at on hit.
	 */
	public static function is_current_request_trusted( int $user_id ): bool {
		if ( ! self::is_feature_enabled() ) {
			return false;
		}
		if ( empty( $_COOKIE[ self::COOKIE_NAME ] ) ) {
			return false;
		}

		$raw    = sanitize_text_field( wp_unslash( (string) $_COOKIE[ self::COOKIE_NAME ] ) );
		$parsed = self::parse_cookie( $raw );
		if ( null === $parsed ) {
			return false;
		}

		if ( ! hash_equals( (string) $user_id, (string) $parsed['user_id'] ) ) {
			return false;
		}
		if ( $parsed['expires_at'] <= time() ) {
			return false;
		}

		$expected = self::sign( $user_id, $parsed['device_id'], $parsed['expires_at'] );
		if ( ! hash_equals( $expected, $parsed['signature'] ) ) {
			return false;
		}

		if ( ! self::acquire_user_lock( $user_id ) ) {
			return false;
		}
		$found = false;
		try {
			// Device must still exist in the latest user-meta value (not revoked).
			$devices = self::live_devices( get_user_meta( $user_id, self::META_KEY, true ) );
			foreach ( $devices as $i => $device ) {
				if ( hash_equals( (string) $device['id'], $parsed['device_id'] ) ) {
					$devices[ $i ]['last_seen_at'] = time();
					$found = true;
					break;
				}
			}
			if ( $found ) {
				update_user_meta( $user_id, self::META_KEY, $devices );
			}
		} finally {
			self::release_user_lock( $user_id );
		}
		if ( ! $found ) {
			return false;
		}

		return true;
	}

	/**
	 * Revoke a single device by id. Fires login_armor_2fa_device_revoked.
	 */
	public static function revoke_device( int $user_id, string $device_id ): bool {
		if ( ! self::acquire_user_lock( $user_id ) ) {
			return false;
		}
		$devices = array();
		$kept    = [];
		$removed = null;
		try {
			$devices = self::live_devices( get_user_meta( $user_id, self::META_KEY, true ) );
			foreach ( $devices as $device ) {
				if ( hash_equals( (string) $device['id'], $device_id ) ) {
					$removed = $device;
					continue;
				}
				$kept[] = $device;
			}
			if ( null !== $removed ) {
				update_user_meta( $user_id, self::META_KEY, $kept );
			}
		} finally {
			self::release_user_lock( $user_id );
		}
		if ( null === $removed ) {
			return false;
		}

		/**
		 * Fires after a trusted device has been revoked.
		 *
		 * @param int                                                                                                                                                          $user_id WP user id.
		 * @param array{id:string,label:string,ip_at_grant:string,granted_at:int,expires_at:int,last_seen_at:int} $device  The revoked device metadata.
		 * @param string                                                                                                                                                       $source  'user' | 'admin' | 'auto'.
		 */
		do_action( 'login_armor_2fa_device_revoked', $user_id, $removed, 'user' );
		return true;
	}

	/**
	 * Revoke every device for a user. Source is one of 'user' (explicit profile
	 * click), 'admin' (admin reset), 'auto' (password reset, AUTH_KEY rotation,
	 * 2FA disable).
	 */
	public static function revoke_all( int $user_id, string $source = 'user' ): int {
		if ( ! self::acquire_user_lock( $user_id ) ) {
			return 0;
		}
		try {
			$devices = self::live_devices( get_user_meta( $user_id, self::META_KEY, true ) );
			delete_user_meta( $user_id, self::META_KEY );
		} finally {
			self::release_user_lock( $user_id );
		}
		if ( [] === $devices ) {
			return 0;
		}
		foreach ( $devices as $device ) {
			do_action( 'login_armor_2fa_device_revoked', $user_id, $device, $source );
		}
		return count( $devices );
	}

	/**
	 * Wire the auto-revoke and cron cleanup hooks. Safe to call unconditionally:
	 * handlers bail when the toggle is off or when no devices exist.
	 */
	public static function register(): void {
		// V2.1.5, defense-in-depth: TrustedDevices class file is now always
		// required (see class-login-armor.php load_modules), so register() is
		// reachable even when 2FA is disabled. Gate the actual hook wiring on
		// the 2FA enable option to preserve the zero-overhead contract: no
		// hooks attached, no cron scheduled, no work done when module is off
		// (on a single site; see TwoFactor::guards_login() for multisite).
		if ( ! TwoFactor::guards_login() ) {
			return;
		}

		// Auto-revoke on password change (WP core fires both hooks: we bind both
		// because plugins sometimes shortcut the flow).
		add_action( 'password_reset', [ self::class, 'on_password_reset' ] );
		add_action( 'after_password_reset', [ self::class, 'on_password_reset' ] );

		// Auto-revoke on direct wp_set_password() calls (e.g. admin changing a
		// user password from the user-edit screen).
		add_action( 'profile_update', [ self::class, 'on_profile_update' ], 10, 2 );

		// Auto-revoke when the user disables 2FA entirely.
		add_action( 'login_armor_2fa_user_disabled', [ self::class, 'on_2fa_disabled' ] );

		// Auto-revoke on AUTH_KEY / AUTH_SALT rotation (via existing hook from Lot 10).
		add_action( 'login_armor_2fa_totp_decrypt_failed', [ self::class, 'on_auth_key_rotation' ] );

		// A multisite site that only guards enrolled accounts (module off)
		// revokes like the others, a password changed there included, but
		// schedules nothing: the cleanup runs where the module is on.
		if ( ! TwoFactor::is_enabled() ) {
			return;
		}

		// Weekly cleanup: lazy cleanup in list_for_user() covers hot paths but
		// a safety-net cron trims abandoned accounts.
		add_action( self::CRON_HOOK, [ self::class, 'run_cleanup' ] );
		if ( ! wp_next_scheduled( self::CRON_HOOK ) ) {
			wp_schedule_event( time() + HOUR_IN_SECONDS, 'weekly', self::CRON_HOOK );
		}
	}

	public static function on_password_reset( $user_or_id = null ): void {
		$user_id = $user_or_id instanceof \WP_User ? (int) $user_or_id->ID : (int) $user_or_id;
		if ( $user_id > 0 ) {
			self::revoke_all( $user_id, 'auto' );
		}
	}

	public static function on_profile_update( $user_id = 0, $old = null ): void {
		// Untyped defensively: `profile_update` is re-fired by import/sync
		// plugins, often with a single argument. Without the old user object
		// we cannot detect a password change, so we leave devices untouched.
		$user_id = (int) $user_id;
		if ( $user_id <= 0 || ! $old instanceof \WP_User ) {
			return;
		}
		// Revoke only when the password actually changed.
		$new = get_userdata( $user_id );
		if ( ! $new instanceof \WP_User ) {
			return;
		}
		if ( $new->user_pass !== $old->user_pass ) {
			self::revoke_all( $user_id, 'auto' );
		}
	}

	public static function on_2fa_disabled( int $user_id ): void {
		self::revoke_all( $user_id, 'auto' );
	}

	public static function on_auth_key_rotation( int $user_id ): void {
		// When the decrypt fails we can't trust the TOTP secret: any previously
		// granted device is suspect too.
		self::revoke_all( $user_id, 'auto' );
	}

	/**
	 * Cron callback: prune expired devices across every user that has the meta.
	 *
	 * Implementation note: we scan user_meta directly rather than iterating every
	 * user, so the cost is O(users who ever granted a device), not O(every user).
	 */
	public static function run_cleanup(): void {
		global $wpdb;
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Cron housekeeping over plugin-owned meta rows.
		$user_ids = $wpdb->get_col(
			$wpdb->prepare(
				"SELECT DISTINCT user_id FROM {$wpdb->usermeta} WHERE meta_key = %s",
				self::META_KEY
			)
		);
		foreach ( $user_ids as $uid ) {
			// list_for_user triggers the lazy prune.
			self::list_for_user( (int) $uid );
		}
	}
}
