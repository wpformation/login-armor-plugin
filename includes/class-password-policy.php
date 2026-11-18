<?php
/**
 * Password Policy module.
 *
 * Enforces an opt-in password policy at every point where WordPress core
 * lets a password be set: front-end registration, the profile / user-edit
 * screen, and the lost-password reset form. Optionally rejects passwords
 * that appear in public breach corpora (reusing the zero-key HIBP
 * k-anonymity lookup already shipped by {@see \LoginArmor\BreachCheck}),
 * and can require a periodic password change (expiration).
 *
 * Design constraints, consistent with the rest of the plugin:
 *
 * - **Opt-in / zero overhead**: every rule is off until an admin enables
 *   the module. The constructor early-returns when disabled so a fresh
 *   install registers no hooks.
 *
 * - **Confirmed core hooks only**: enforcement rides on three hooks that
 *   have existed since WP 3.5 and fire AFTER core has verified the form
 *   nonce: `registration_errors`, `user_profile_update_errors`, and
 *   `validate_password_reset`. We never depend on a newer filter whose
 *   availability we cannot guarantee on WP 6.8.
 *
 * - **Fail-soft on breach lookup**: a compromised-password rejection only
 *   triggers on a *confirmed* leaked result. If the HIBP API is down,
 *   `BreachCheck::check_password()` returns null and we let the password
 *   through rather than blocking a legitimate reset because a third-party
 *   service is unreachable.
 *
 * - **No lockout from expiration**: expired users are nagged toward the
 *   profile password field via a redirect that uses the same `$pagenow`
 *   loop-breaker proven in BreachCheck: never a hard block.
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
 * Handles the opt-in password policy.
 */
class PasswordPolicy {

	public const OPTION_KEY = 'login_armor_password_policy';

	/** User meta: unix timestamp of the last password change we observed. */
	public const META_SET_AT = 'login_armor_password_set_at';

	/**
	 * Default settings (module off, sane baseline once enabled).
	 *
	 * @var array<string, bool|int>
	 */
	private const DEFAULTS = [
		'enabled'           => false,
		'min_length'        => 12,
		'require_lower'     => true,
		'require_upper'     => true,
		'require_number'    => true,
		'require_symbol'    => false,
		'forbid_username'   => true,
		'block_compromised' => true,
		'expiration_days'   => 0, // 0 = never expire.
	];

	/**
	 * Constructor. Registers hooks only when the module is enabled.
	 */
	public function __construct() {
		if ( ! self::is_enabled() ) {
			return;
		}

		// Enforcement at every core password-set surface. All three fire
		// after WP core has verified the relevant form nonce.
		add_filter( 'registration_errors', [ $this, 'on_registration_errors' ], 10, 1 );
		add_action( 'user_profile_update_errors', [ $this, 'on_profile_update_errors' ], 10, 3 );
		add_action( 'validate_password_reset', [ $this, 'on_validate_password_reset' ], 10, 2 );

		// Track the moment a password actually changes, for expiration.
		add_action( 'after_password_reset', [ $this, 'stamp_after_reset' ], 10, 1 );
		add_action( 'profile_update', [ $this, 'stamp_after_profile_update' ], 10, 2 );

		// Expiration nag: only wired when an expiry window is configured.
		if ( (int) self::get_settings()['expiration_days'] > 0 ) {
			// Backfill a baseline timestamp on login so existing users are
			// measured from "now", never retro-expired into a lockout.
			add_filter( 'authenticate', [ $this, 'backfill_stamp_on_login' ], 50, 1 );
			add_action( 'admin_init', [ $this, 'maybe_force_expired_reset' ] );
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
			'enabled'           => ! empty( $input['enabled'] ),
			'min_length'        => max( 6, min( 64, (int) ( $input['min_length'] ?? 12 ) ) ),
			'require_lower'     => ! empty( $input['require_lower'] ),
			'require_upper'     => ! empty( $input['require_upper'] ),
			'require_number'    => ! empty( $input['require_number'] ),
			'require_symbol'    => ! empty( $input['require_symbol'] ),
			'forbid_username'   => ! empty( $input['forbid_username'] ),
			'block_compromised' => ! empty( $input['block_compromised'] ),
			'expiration_days'   => max( 0, min( 3650, (int) ( $input['expiration_days'] ?? 0 ) ) ),
		];
		update_option( self::OPTION_KEY, $clean, false );
	}

	// ------------------------------------------------------------------
	// Validation core
	// ------------------------------------------------------------------

	/**
	 * Validate a candidate password against the active policy.
	 *
	 * Pure and side-effect free so it can be reused anywhere (admin
	 * preview, future REST endpoint, CLI). An empty password yields no
	 * errors: core treats an empty pass field as "no change", and the
	 * surrounding hooks short-circuit before calling us in that case.
	 *
	 * @param string $password Candidate plaintext password.
	 * @param string $username Optional username/login to forbid inside the password.
	 * @param string $context  Optional breach-check request context.
	 * @return array<int, string> Human-readable error messages (empty when valid).
	 */
	public static function validate( string $password, string $username = '', string $context = '' ): array {
		$errors = [];
		if ( '' === $password ) {
			return $errors;
		}

		$s      = self::get_settings();
		$min    = (int) $s['min_length'];
		$length = function_exists( 'mb_strlen' ) ? mb_strlen( $password ) : strlen( $password );

		if ( $length < $min ) {
			$errors[] = sprintf(
				/* translators: %d: minimum number of characters required in a password. */
				_n(
					'Password must be at least %d character long.',
					'Password must be at least %d characters long.',
					$min,
					'login-armor'
				),
				$min
			);
		}

		if ( ! empty( $s['require_lower'] ) && ! preg_match( '/[a-z]/', $password ) ) {
			$errors[] = __( 'Password must contain at least one lowercase letter.', 'login-armor' );
		}
		if ( ! empty( $s['require_upper'] ) && ! preg_match( '/[A-Z]/', $password ) ) {
			$errors[] = __( 'Password must contain at least one uppercase letter.', 'login-armor' );
		}
		if ( ! empty( $s['require_number'] ) && ! preg_match( '/[0-9]/', $password ) ) {
			$errors[] = __( 'Password must contain at least one number.', 'login-armor' );
		}
		if ( ! empty( $s['require_symbol'] ) && ! preg_match( '/[^A-Za-z0-9]/', $password ) ) {
			$errors[] = __( 'Password must contain at least one symbol.', 'login-armor' );
		}

		if ( ! empty( $s['forbid_username'] ) && '' !== $username && false !== stripos( $password, $username ) ) {
			$errors[] = __( 'Password must not contain your username.', 'login-armor' );
		}

		// Compromised-password check: reuse the shipped HIBP k-anonymity
		// lookup. Only rejects on a CONFIRMED leak; a null result (API down)
		// is fail-soft and lets the password through.
		if ( ! empty( $s['block_compromised'] ) && class_exists( '\LoginArmor\BreachCheck' ) ) {
			$result = BreachCheck::check_password( $password, $context );
			if ( is_array( $result ) && ! empty( $result['leaked'] ) ) {
				$errors[] = __( 'This password appears in public data breach records and is unsafe. Please choose a different one.', 'login-armor' );
			}
		}

		return $errors;
	}

	/**
	 * Pull the candidate password from the current request.
	 *
	 * Every caller runs inside a core hook that has already verified its
	 * own form nonce, so we do not re-verify here. Passwords are opaque
	 * byte strings: sanitising them would corrupt valid input, so we only
	 * unslash. WP core applies the same treatment in its own handlers.
	 *
	 * @return string Unslashed candidate password ('' when not present).
	 */
	private static function candidate_password(): string {
		// phpcs:ignore WordPress.Security.NonceVerification.Missing,WordPress.Security.NonceVerification.Recommended,WordPress.Security.ValidatedSanitizedInput.MissingUnslash,WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- core verifies the form nonce before these hooks fire; passwords are opaque bytes (sanitising mutates them); wp_unslash is applied on the next line before any use.
		$raw = isset( $_POST['pass1'] ) ? (string) $_POST['pass1'] : '';
		return (string) wp_unslash( $raw );
	}

	// ------------------------------------------------------------------
	// Enforcement hooks
	// ------------------------------------------------------------------

	/**
	 * Front-end registration. Core registration does not collect a password
	 * by default, but custom/commerce registration forms add `pass1`: we
	 * validate defensively when one is present.
	 *
	 * Parameter untyped with a default: a third-party plugin filtering
	 * `registration_errors` may pass fewer args or a non-WP_Error; we stay
	 * transparent in that case.
	 *
	 * @param mixed $errors Registration error object (expected WP_Error).
	 * @return mixed
	 */
	public function on_registration_errors( $errors = null ) {
		if ( ! $errors instanceof \WP_Error ) {
			return $errors;
		}
		$password = self::candidate_password();
		if ( '' === $password ) {
			return $errors;
		}
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- registration form nonce verified by core before this filter.
		$login = isset( $_POST['user_login'] ) ? sanitize_user( wp_unslash( (string) $_POST['user_login'] ) ) : '';
		foreach ( self::validate( $password, $login, BreachCheck::CONTEXT_PUBLIC_REGISTRATION ) as $message ) {
			$errors->add( 'login_armor_password_policy', $message );
		}
		return $errors;
	}

	/**
	 * Profile / user-edit screen password change.
	 *
	 * Parameters untyped with defaults: `user_profile_update_errors` may be
	 * re-fired by profile-editing plugins with degraded arity or types.
	 *
	 * @param mixed $errors Error object passed by reference by core (expected WP_Error).
	 * @param mixed $update Whether this is an existing-user update (expected bool).
	 * @param mixed $user   User object (raw) being saved (expected stdClass).
	 */
	public function on_profile_update_errors( $errors = null, $update = false, $user = null ): void {
		if ( ! $errors instanceof \WP_Error ) {
			return;
		}
		$password = self::candidate_password();
		if ( '' === $password ) {
			return;
		}
		$login = isset( $user->user_login ) ? (string) $user->user_login : '';
		foreach ( self::validate( $password, $login ) as $message ) {
			$errors->add( 'login_armor_password_policy', $message );
		}
	}

	/**
	 * Lost-password reset form.
	 *
	 * Parameters untyped with defaults: `validate_password_reset` is re-fired
	 * by custom reset-form plugins, sometimes with degraded arity or types.
	 *
	 * @param mixed $errors Error object to add to (expected WP_Error).
	 * @param mixed $user   User if credentials matched, else WP_Error.
	 */
	public function on_validate_password_reset( $errors = null, $user = null ): void {
		if ( ! $errors instanceof \WP_Error ) {
			return;
		}
		$password = self::candidate_password();
		if ( '' === $password ) {
			return;
		}
		$login = ( $user instanceof \WP_User ) ? (string) $user->user_login : '';
		foreach ( self::validate( $password, $login, BreachCheck::CONTEXT_PASSWORD_RESET ) as $message ) {
			$errors->add( 'login_armor_password_policy', $message );
		}
	}

	// ------------------------------------------------------------------
	// Expiration tracking
	// ------------------------------------------------------------------

	/**
	 * Record the password-set timestamp after a lost-password reset.
	 *
	 * Parameter untyped with a guard: WP core passes a WP_User here, but a
	 * third-party plugin re-firing `after_password_reset` may pass a user ID
	 * or null. A strict `WP_User` hint would fatal the reset flow.
	 *
	 * @param mixed $user User whose password was reset (expected WP_User).
	 */
	public function stamp_after_reset( $user = null ): void {
		if ( ! $user instanceof \WP_User ) {
			return;
		}
		update_user_meta( $user->ID, self::META_SET_AT, time() );
	}

	/**
	 * Record the password-set timestamp when a profile update changed it.
	 *
	 * Parameters untyped with defaults: `profile_update` is one of the most
	 * re-fired hooks (imports, migration and sync plugins), often with a
	 * single argument. Strict hints would fatal those flows.
	 *
	 * @param mixed $user_id       Updated user ID (expected int).
	 * @param mixed $old_user_data User object before the update (expected WP_User).
	 */
	public function stamp_after_profile_update( $user_id = 0, $old_user_data = null ): void {
		$user_id = (int) $user_id;
		if ( $user_id <= 0 ) {
			return;
		}
		if ( '' === self::candidate_password() ) {
			return; // No password field submitted: nothing changed.
		}
		update_user_meta( $user_id, self::META_SET_AT, time() );
	}

	/**
	 * On successful login, backfill the set-at stamp if missing so existing
	 * accounts are measured from now rather than retro-expired.
	 *
	 * Parameter untyped with a default (`authenticate` is re-fired widely).
	 *
	 * @param mixed $user Result from earlier authenticate filters.
	 * @return mixed Untouched.
	 */
	public function backfill_stamp_on_login( $user = null ) {
		if ( $user instanceof \WP_User && '' === (string) get_user_meta( $user->ID, self::META_SET_AT, true ) ) {
			update_user_meta( $user->ID, self::META_SET_AT, time() );
		}
		return $user;
	}

	/**
	 * Whether the given user's password has exceeded the expiry window.
	 *
	 * @param int $user_id User to check.
	 */
	public static function is_expired( int $user_id ): bool {
		$days = (int) self::get_settings()['expiration_days'];
		if ( $days <= 0 ) {
			return false;
		}
		$set_at = (int) get_user_meta( $user_id, self::META_SET_AT, true );
		if ( $set_at <= 0 ) {
			return false; // Unknown: backfilled on next login, never expire blindly.
		}
		return ( time() - $set_at ) > ( $days * DAY_IN_SECONDS );
	}

	/**
	 * Nag expired users toward the profile password field. Mirrors the
	 * BreachCheck force-reset routing, including the `$pagenow` loop-breaker
	 * that prevents the profile.php → profile.php redirect storm.
	 */
	public function maybe_force_expired_reset(): void {
		global $pagenow;

		if ( defined( 'DOING_AJAX' ) && DOING_AJAX ) { return; }
		if ( defined( 'DOING_CRON' ) && DOING_CRON ) { return; }
		if ( defined( 'WP_CLI' ) && \WP_CLI ) { return; }
		if ( defined( 'REST_REQUEST' ) && REST_REQUEST ) { return; }

		if ( in_array( $pagenow, [ 'wp-login.php', 'wp-signup.php', 'wp-activate.php', 'admin-ajax.php', 'admin-post.php' ], true ) ) {
			return;
		}

		// LOOP-BREAKER: never redirect away from the remediation screen.
		if ( 'profile.php' === $pagenow || 'user-edit.php' === $pagenow ) {
			return;
		}

		// Allow Login Armor's own screens so an admin can adjust the policy
		// even while their own password is expired.
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- read-only routing guard, no state mutation.
		$current_page = isset( $_GET['page'] ) ? sanitize_key( wp_unslash( (string) $_GET['page'] ) ) : '';
		if ( 'login-armor' === $current_page ) {
			return;
		}

		$user_id = get_current_user_id();
		if ( $user_id <= 0 || ! self::is_expired( $user_id ) ) {
			return;
		}

		wp_safe_redirect( admin_url( 'profile.php#password' ) );
		exit;
	}

	// ------------------------------------------------------------------
	// Admin helpers
	// ------------------------------------------------------------------

	/**
	 * Human-readable summary of the active requirements, for surfacing on
	 * the settings screen and (optionally) near password fields.
	 *
	 * @return array<int, string>
	 */
	public static function describe_requirements(): array {
		$s    = self::get_settings();
		$list = [];

		$list[] = sprintf(
			/* translators: %d: minimum number of characters required in a password. */
			_n( 'At least %d character', 'At least %d characters', (int) $s['min_length'], 'login-armor' ),
			(int) $s['min_length']
		);
		if ( ! empty( $s['require_lower'] ) ) {
			$list[] = __( 'One lowercase letter', 'login-armor' );
		}
		if ( ! empty( $s['require_upper'] ) ) {
			$list[] = __( 'One uppercase letter', 'login-armor' );
		}
		if ( ! empty( $s['require_number'] ) ) {
			$list[] = __( 'One number', 'login-armor' );
		}
		if ( ! empty( $s['require_symbol'] ) ) {
			$list[] = __( 'One symbol', 'login-armor' );
		}
		if ( ! empty( $s['block_compromised'] ) ) {
			$list[] = __( 'Not found in known data breaches', 'login-armor' );
		}

		return $list;
	}
}
