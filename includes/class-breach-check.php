<?php
/**
 * Breach Check module: Lot 21 (v2.0.5).
 *
 * Detects user passwords and email addresses that appear in public data
 * breach corpora, using two zero-key, zero-cost public APIs:
 *
 * - **Password side**: Have I Been Pwned's Pwned Passwords API
 *   (https://api.pwnedpasswords.com). Uses the k-anonymity range lookup:
 *   only the first 5 hex chars of the SHA-1 hash of the password ever
 *   leave our server. The full password and its full hash stay in
 *   process memory for the duration of the check and are never stored
 *   or logged. The API cannot infer which password we are checking.
 *
 * - **Email side**, XposedOrNot (https://api.xposedornot.com). Returns
 *   a list of breach names the email address appears in. We store the
 *   count and the breach labels on user meta for surfacing in the admin;
 *   we never store the raw API response.
 *
 * Design constraints:
 *
 * - **Fail-soft**: every API call has a short timeout (3 s) and any
 *   error (HTTP, JSON, rate-limit) causes the check to silently
 *   abort: we never block or delay a login because an external
 *   service is down.
 *
 * - **Rate-limited**: positive AND negative results are cached in
 *   WordPress transients for 24 h (key = hash prefix or email hash).
 *   A user logging in repeatedly won't re-hit the API beyond one
 *   lookup per day.
 *
 * - **Private-by-design**: we never store the raw password, its full
 *   hash, or the raw email address in plaintext on disk. Cache keys
 *   are SHA-256 of the input so an attacker with DB read access
 *   cannot recover the inputs from transient keys.
 *
 * - **Passive surfacing**: a match NEVER blocks a login. The user
 *   sees a banner on their profile page ("this password appears in
 *   public breach data, please change it"), admins see the flagged
 *   user count on the Overview. Whether to force a password reset is
 *   an admin-configurable option (off by default).
 *
 * @package LoginArmor
 * @since   2.0.5
 */

namespace LoginArmor;

// Exit if accessed directly.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Breach Check module.
 */
class BreachCheck {

	public const OPTION_ENABLED           = 'login_armor_breach_check_enabled';
	public const OPTION_CHECK_PASSWORDS   = 'login_armor_breach_check_passwords';
	public const OPTION_CHECK_EMAILS      = 'login_armor_breach_check_emails';
	public const OPTION_FORCE_RESET       = 'login_armor_breach_check_force_reset';

	public const META_PASSWORD_FLAGGED    = 'login_armor_breach_password_flagged';
	public const META_PASSWORD_COUNT      = 'login_armor_breach_password_count';
	public const META_EMAIL_FLAGGED       = 'login_armor_breach_email_flagged';
	public const META_EMAIL_BREACHES      = 'login_armor_breach_email_breaches';
	public const META_EMAIL_LAST_CHECK    = 'login_armor_breach_email_last_check';
	public const META_LAST_CHECK          = 'login_armor_breach_last_check';
	public const META_FORCE_RESET_NEEDED  = 'login_armor_breach_force_reset_needed';

	public const HIBP_API        = 'https://api.pwnedpasswords.com/range/';
	public const XPOSED_API      = 'https://api.xposedornot.com/v1/check-email/';
	public const REQUEST_TIMEOUT = 3; // seconds
	public const CACHE_TTL       = DAY_IN_SECONDS; // 24 hours
	public const USER_AGENT      = 'LoginArmor-BreachCheck/1.0';

	/** Public, unauthenticated password-policy lookup context. */
	public const CONTEXT_PUBLIC_REGISTRATION = 'public_registration';

	/** Public password-reset validation context. */
	public const CONTEXT_PASSWORD_RESET = 'password_reset';

	/** Fixed rate-limit window in seconds. */
	private const PUBLIC_RATE_WINDOW = 600;

	/** Non-autoloaded option prefix used by public HIBP rate counters. */
	private const PUBLIC_RATE_PREFIX = 'login_armor_hibp_public_rate_';

	/** Short circuit after an upstream HIBP failure. */
	private const HIBP_FAILURE_CIRCUIT = 'login_armor_hibp_failure_circuit';

	/** HIBP failure circuit duration in seconds. */
	private const HIBP_FAILURE_TTL = 300;

	/**
	 * Constructor. Registers the hooks only when the module is enabled.
	 */
	public function __construct() {
		if ( ! self::is_enabled() ) {
			return;
		}

		// Password check fires on the `authenticate` filter at priority 40,
		// AFTER WordPress has validated the password but BEFORE it returns
		// the user. We read the candidate password from $_POST on the same
		// request: it's the only event where WP hands us both the plaintext
		// password and a confirmed successful auth. We never block; we only
		// flag user meta.
		add_filter( 'authenticate', array( $this, 'maybe_check_password_on_login' ), 40, 3 );

		// Email check fires on new user creation and on email change.
		add_action( 'user_register', array( $this, 'check_user_email' ), 10, 1 );
		add_action( 'wp_login', array( $this, 'maybe_check_email_on_login' ), 10, 2 );
		add_action( 'profile_update', array( $this, 'maybe_check_email_on_profile_update' ), 10, 2 );

		// Password change events: re-check whenever a user changes their password.
		add_action( 'profile_update', array( $this, 'maybe_check_password_on_profile_update' ), 10, 2 );
		add_action( 'password_reset', array( $this, 'check_password_after_reset' ), 10, 2 );

		// Clear the flag once the user has changed their password (the new
		// password will be re-checked on the next login / save).
		add_action( 'after_password_reset', array( $this, 'clear_flags_after_reset' ), 10, 1 );

		// Surface the banner on the user's own profile.
		add_action( 'admin_notices', array( $this, 'maybe_render_profile_notice' ) );

		// Optional "force password reset": redirect flagged users to the
		// password reset flow on next admin page load when the option is on.
		if ( (bool) get_option( self::OPTION_FORCE_RESET, false ) ) {
			add_action( 'admin_init', array( $this, 'maybe_force_password_reset' ) );
		}
	}

	/**
	 * Whether the module is enabled.
	 */
	public static function is_enabled(): bool {
		return (bool) get_option( self::OPTION_ENABLED, false );
	}

	/**
	 * Whether password checks are enabled (sub-toggle). Defaults ON when
	 * the module is enabled because the password check is the headline
	 * feature and has zero cost for an admin to keep on.
	 */
	public static function is_password_check_enabled(): bool {
		return self::is_enabled() && (bool) get_option( self::OPTION_CHECK_PASSWORDS, true );
	}

	/**
	 * Whether email checks are enabled (sub-toggle). Defaults OFF because
	 * XposedOrNot is a separate external API an admin should opt into
	 * explicitly: no silent network calls to a second vendor.
	 */
	public static function is_email_check_enabled(): bool {
		return self::is_enabled() && (bool) get_option( self::OPTION_CHECK_EMAILS, false );
	}

	/**
	 * Authenticate-filter passthrough that opportunistically runs a
	 * password breach check when the login has just succeeded.
	 *
	 * @param \WP_User|\WP_Error|null $user     Result from earlier filters.
	 * @param string                  $username Username supplied.
	 * @param string                  $password Password supplied.
	 * @return \WP_User|\WP_Error|null Untouched: we never modify the auth result.
	 */
	public function maybe_check_password_on_login( $user = null, $username = '', $password = '' ) {
		if ( ! $user instanceof \WP_User ) {
			return $user; // Auth failed or not yet resolved: nothing to do.
		}
		if ( ! is_string( $password ) || '' === $password ) {
			return $user;
		}
		if ( ! self::is_password_check_enabled() ) {
			return $user;
		}

		// Fire the check but don't await: if the HTTP call takes 3 s we
		// don't want it to delay the login. In practice WP is synchronous
		// so we DO await, but the timeout cap keeps the worst case low.
		$result = self::check_password( $password );
		if ( null === $result ) {
			return $user; // API error, fail-soft.
		}

		if ( $result['leaked'] ) {
			update_user_meta( $user->ID, self::META_PASSWORD_FLAGGED, time() );
			update_user_meta( $user->ID, self::META_PASSWORD_COUNT, (int) $result['count'] );
		} else {
			// Clear any stale flag if the user has changed their password
			// to a clean one since a previous flagging.
			delete_user_meta( $user->ID, self::META_PASSWORD_FLAGGED );
			delete_user_meta( $user->ID, self::META_PASSWORD_COUNT );
		}
		update_user_meta( $user->ID, self::META_LAST_CHECK, time() );

		return $user;
	}

	/**
	 * Handle a password change via the profile screen.
	 *
	 * Parameters untyped with defaults: `profile_update` is re-fired by
	 * import/sync plugins, often with a single argument.
	 *
	 * @param mixed $user_id       The user ID being updated (expected int).
	 * @param mixed $old_user_data The user object before update (expected WP_User).
	 */
	public function maybe_check_password_on_profile_update( $user_id = 0, $old_user_data = null ): void {
		$user_id = (int) $user_id;
		if ( $user_id <= 0 ) {
			return;
		}
		if ( ! self::is_password_check_enabled() ) {
			return;
		}
		// phpcs:ignore WordPress.Security.NonceVerification.Missing,WordPress.Security.ValidatedSanitizedInput.MissingUnslash,WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- WP core verifies the profile-update nonce before this action fires; passwords are opaque bytes so sanitisation would mutate them, and wp_unslash() runs on the next line before any consumption.
		$raw_password = isset( $_POST['pass1'] ) ? (string) $_POST['pass1'] : '';
		$new_password = (string) wp_unslash( $raw_password );
		if ( '' === $new_password ) {
			return;
		}
		$result = self::check_password( $new_password );
		if ( null === $result ) {
			return;
		}
		if ( $result['leaked'] ) {
			update_user_meta( $user_id, self::META_PASSWORD_FLAGGED, time() );
			update_user_meta( $user_id, self::META_PASSWORD_COUNT, (int) $result['count'] );
		} else {
			delete_user_meta( $user_id, self::META_PASSWORD_FLAGGED );
			delete_user_meta( $user_id, self::META_PASSWORD_COUNT );
			delete_user_meta( $user_id, self::META_FORCE_RESET_NEEDED );
		}
		update_user_meta( $user_id, self::META_LAST_CHECK, time() );
	}

	/**
	 * Hook: wp_password_reset, fires after a successful lost-password reset.
	 *
	 * Parameters untyped with guards: WP core passes ( WP_User, string ) but a
	 * third-party plugin re-firing `password_reset` may pass a user ID or a
	 * non-string. Strict hints would fatal the reset flow.
	 *
	 * @param mixed $user         User whose password was reset (expected WP_User).
	 * @param mixed $new_password New plaintext password (expected string).
	 */
	public function check_password_after_reset( $user = null, $new_password = '' ): void {
		if ( ! $user instanceof \WP_User || ! is_string( $new_password ) ) {
			return;
		}
		if ( ! self::is_password_check_enabled() || '' === $new_password ) {
			return;
		}
		$result = self::check_password( $new_password );
		if ( null === $result ) {
			return;
		}
		if ( $result['leaked'] ) {
			update_user_meta( $user->ID, self::META_PASSWORD_FLAGGED, time() );
			update_user_meta( $user->ID, self::META_PASSWORD_COUNT, (int) $result['count'] );
		} else {
			delete_user_meta( $user->ID, self::META_PASSWORD_FLAGGED );
			delete_user_meta( $user->ID, self::META_PASSWORD_COUNT );
		}
		update_user_meta( $user->ID, self::META_LAST_CHECK, time() );
	}

	/**
	 * Clear the force-reset flag once the user has completed a password reset.
	 *
	 * Parameter untyped with a guard: a third-party plugin re-firing
	 * `after_password_reset` may pass a user ID or null rather than a WP_User.
	 *
	 * @param mixed $user User whose password was just reset (expected WP_User).
	 */
	public function clear_flags_after_reset( $user = null ): void {
		if ( ! $user instanceof \WP_User ) {
			return;
		}
		delete_user_meta( $user->ID, self::META_FORCE_RESET_NEEDED );
	}

	/**
	 * Email check for new users (admin-created or self-registered).
	 *
	 * Parameter untyped with a default: `user_register` is re-fired by
	 * registration/import plugins, sometimes with a numeric string or null.
	 *
	 * @param mixed $user_id The newly created user's ID (expected int).
	 */
	public function check_user_email( $user_id = 0 ): void {
		$user_id = (int) $user_id;
		if ( $user_id <= 0 ) {
			return;
		}
		if ( ! self::is_email_check_enabled() ) {
			return;
		}
		// Public self-registration must never trigger an anonymous outbound
		// lookup. Administrative creation remains checked immediately; public
		// accounts are checked after their first successful login instead.
		if ( ! is_user_logged_in() || ! current_user_can( 'create_users' ) ) {
			return;
		}
		$user = get_user_by( 'id', $user_id );
		if ( ! $user instanceof \WP_User || '' === $user->user_email ) {
			return;
		}
		$this->run_email_check( $user_id, $user->user_email );
	}

	/**
	 * Check a public registrant's email only after WordPress authenticated them.
	 *
	 * @param mixed $user_login Authenticated login name.
	 * @param mixed $user       Authenticated user object.
	 */
	public function maybe_check_email_on_login( $user_login = '', $user = null ): void {
		unset( $user_login );
		if ( ! $user instanceof \WP_User || ! self::is_email_check_enabled() || '' === (string) $user->user_email ) {
			return;
		}
		$last = (int) get_user_meta( $user->ID, self::META_EMAIL_LAST_CHECK, true );
		if ( $last > 0 && ( time() - $last ) < self::CACHE_TTL ) {
			return;
		}
		$this->run_email_check( $user->ID, (string) $user->user_email );
	}

	/**
	 * Email check on profile update, only when the email actually changed.
	 *
	 * Parameters untyped with defaults: `profile_update` is re-fired by
	 * import/sync plugins, often with a single argument. Without the old
	 * user object we cannot detect "unchanged", so we check anyway (safe
	 * default for an opt-in breach check).
	 *
	 * @param mixed $user_id       The user ID being updated (expected int).
	 * @param mixed $old_user_data The user object before update (expected WP_User).
	 */
	public function maybe_check_email_on_profile_update( $user_id = 0, $old_user_data = null ): void {
		$user_id = (int) $user_id;
		if ( $user_id <= 0 ) {
			return;
		}
		if ( ! self::is_email_check_enabled() ) {
			return;
		}
		$user = get_user_by( 'id', $user_id );
		if ( ! $user instanceof \WP_User ) {
			return;
		}
		if ( $old_user_data instanceof \WP_User && $user->user_email === $old_user_data->user_email ) {
			return; // email unchanged, nothing to do
		}
		$this->run_email_check( $user_id, $user->user_email );
	}

	/**
	 * Execute an email breach check and persist the result to user meta.
	 *
	 * @param int    $user_id User whose email is being checked.
	 * @param string $email   Email address to check.
	 */
	private function run_email_check( int $user_id, string $email ): void {
		$result = self::check_email( $email );
		if ( null === $result ) {
			return; // API error, fail-soft.
		}
		if ( $result['leaked'] ) {
			update_user_meta( $user_id, self::META_EMAIL_FLAGGED, time() );
			update_user_meta( $user_id, self::META_EMAIL_BREACHES, array_slice( $result['breaches'], 0, 20 ) );
		} else {
			delete_user_meta( $user_id, self::META_EMAIL_FLAGGED );
			delete_user_meta( $user_id, self::META_EMAIL_BREACHES );
		}
		update_user_meta( $user_id, self::META_EMAIL_LAST_CHECK, time() );
	}

	/**
	 * Look up a password against HIBP's Pwned Passwords range API using
	 * the k-anonymity model: only the first 5 hex chars of the SHA-1
	 * hash are sent. The API returns ~500-900 suffix hashes that share
	 * the prefix; we do the local suffix comparison ourselves.
	 *
	 * @param string $password Plaintext password (lives in memory only).
	 * @param string $context  Optional request context. Anonymous password-set
	 *                         forms are deliberately never allowed to call out.
	 * @return array{leaked:bool, count:int}|null `null` on API error (caller should treat as "not checked").
	 */
	public static function check_password( string $password, string $context = '' ): ?array {
		if ( '' === $password ) {
			return null;
		}
		if ( in_array( $context, array( self::CONTEXT_PUBLIC_REGISTRATION, self::CONTEXT_PASSWORD_RESET ), true ) ) {
			return null;
		}
		$hash   = strtoupper( sha1( $password ) );
		$prefix = substr( $hash, 0, 5 );
		$suffix = substr( $hash, 5 );

		$cache_key = 'la_breach_pwd_' . hash( 'sha256', $prefix );
		$cached    = get_transient( $cache_key );
		if ( false !== $cached && is_string( $cached ) ) {
			return self::match_suffix( $cached, $suffix );
		}
		if ( false !== get_transient( self::HIBP_FAILURE_CIRCUIT ) ) {
			return null;
		}

		$response = wp_remote_get(
			self::HIBP_API . $prefix,
			array(
				'timeout'    => self::REQUEST_TIMEOUT,
				'user-agent' => self::USER_AGENT,
				'headers'    => array( 'Add-Padding' => 'true' ), // HIBP returns padded responses so range sizes do not leak prefix popularity.
			)
		);
		if ( is_wp_error( $response ) ) {
			set_transient( self::HIBP_FAILURE_CIRCUIT, 1, self::HIBP_FAILURE_TTL );
			return null;
		}
		$code = (int) wp_remote_retrieve_response_code( $response );
		if ( 200 !== $code ) {
			set_transient( self::HIBP_FAILURE_CIRCUIT, 1, self::HIBP_FAILURE_TTL );
			return null;
		}
		$body = (string) wp_remote_retrieve_body( $response );
		if ( '' === $body ) {
			set_transient( self::HIBP_FAILURE_CIRCUIT, 1, self::HIBP_FAILURE_TTL );
			return null;
		}

		delete_transient( self::HIBP_FAILURE_CIRCUIT );
		set_transient( $cache_key, $body, self::CACHE_TTL );
		return self::match_suffix( $body, $suffix );
	}

	/**
	 * Remove expired public HIBP rate counters.
	 *
	 * @return int Number of deleted option rows.
	 */
	public static function purge_public_rate_limits(): int {
		global $wpdb;

		$cutoff = time() - self::PUBLIC_RATE_WINDOW;
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Maintenance cleanup of plugin-owned counters.
		$deleted = (int) $wpdb->query(
			$wpdb->prepare(
				"DELETE FROM {$wpdb->options} WHERE option_name LIKE %s AND CAST(SUBSTRING_INDEX(option_value, '|', 1) AS UNSIGNED) < %d",
				$wpdb->esc_like( self::PUBLIC_RATE_PREFIX ) . '%',
				$cutoff
			)
		);

		if ( $deleted > 0 ) {
			wp_cache_flush_group( 'options' );
		}

		return $deleted;
	}

	/**
	 * Parse a HIBP range-response body and look for a matching suffix.
	 *
	 * Response body is a CRLF list of lines `SUFFIX:COUNT[:PADDING]`.
	 *
	 * @param string $body   Full range-lookup response body.
	 * @param string $suffix 35-char SHA-1 suffix (uppercase hex) of the password we are checking.
	 * @return array{leaked:bool, count:int}
	 */
	private static function match_suffix( string $body, string $suffix ): array {
		$lines = preg_split( '/\r\n|\r|\n/', $body );
		if ( ! is_array( $lines ) ) {
			return array( 'leaked' => false, 'count' => 0 );
		}
		foreach ( $lines as $line ) {
			$parts = explode( ':', $line, 3 ); // [suffix, count, optional padding flag]
			if ( count( $parts ) < 2 ) {
				continue;
			}
			$line_suffix = trim( $parts[0] );
			if ( '' === $line_suffix ) {
				continue;
			}
			if ( hash_equals( $line_suffix, $suffix ) ) {
				return array(
					'leaked' => true,
					'count'  => (int) trim( $parts[1] ),
				);
			}
		}
		return array( 'leaked' => false, 'count' => 0 );
	}

	/**
	 * Look up an email against XposedOrNot's public check-email API.
	 *
	 * @param string $email Email address to check (normalised to lowercase before send).
	 * @return array{leaked:bool, breaches:array<int,string>}|null `null` on API error.
	 */
	public static function check_email( string $email ): ?array {
		$email = strtolower( trim( $email ) );
		if ( '' === $email || false === filter_var( $email, FILTER_VALIDATE_EMAIL ) ) {
			return null;
		}

		$cache_key = 'la_breach_email_' . hash( 'sha256', $email );
		$cached    = get_transient( $cache_key );
		if ( false !== $cached && is_array( $cached ) ) {
			return $cached;
		}

		$response = wp_remote_get(
			self::XPOSED_API . rawurlencode( $email ),
			array(
				'timeout'    => self::REQUEST_TIMEOUT,
				'user-agent' => self::USER_AGENT,
			)
		);
		if ( is_wp_error( $response ) ) {
			return null;
		}
		$code = (int) wp_remote_retrieve_response_code( $response );
		if ( 404 === $code ) {
			// XposedOrNot returns 404 for clean emails: treat as a
			// successful negative result and cache it.
			$clean = array( 'leaked' => false, 'breaches' => array() );
			set_transient( $cache_key, $clean, self::CACHE_TTL );
			return $clean;
		}
		if ( 200 !== $code ) {
			return null;
		}

		$body = (string) wp_remote_retrieve_body( $response );
		$data = json_decode( $body, true );
		if ( ! is_array( $data ) ) {
			return null;
		}

		// Response shape:
		//   {"breaches":[["Breach1","Breach2",...]]}
		// The outer array is single-element; inner is the list of breach names.
		$breaches = array();
		if ( isset( $data['breaches'] ) && is_array( $data['breaches'] ) && isset( $data['breaches'][0] ) && is_array( $data['breaches'][0] ) ) {
			foreach ( $data['breaches'][0] as $name ) {
				if ( is_string( $name ) && '' !== $name ) {
					$breaches[] = sanitize_text_field( $name );
				}
			}
		}

		$result = array(
			'leaked'   => count( $breaches ) > 0,
			'breaches' => $breaches,
		);
		set_transient( $cache_key, $result, self::CACHE_TTL );
		return $result;
	}

	/**
	 * Render the breach notice on the user's own profile page.
	 *
	 * Admins also see it on other screens: we gate to the profile page
	 * so the warning attaches to the remediation surface (password field
	 * is right there).
	 */
	public function maybe_render_profile_notice(): void {
		$screen = function_exists( 'get_current_screen' ) ? get_current_screen() : null;
		if ( ! $screen || 'profile' !== $screen->id ) {
			return;
		}
		$user_id = get_current_user_id();
		if ( $user_id <= 0 ) {
			return;
		}

		$pwd_flagged   = (int) get_user_meta( $user_id, self::META_PASSWORD_FLAGGED, true );
		$pwd_count     = (int) get_user_meta( $user_id, self::META_PASSWORD_COUNT, true );
		$email_flagged = (int) get_user_meta( $user_id, self::META_EMAIL_FLAGGED, true );
		$breaches      = (array) get_user_meta( $user_id, self::META_EMAIL_BREACHES, true );

		if ( $pwd_flagged > 0 ) {
			echo '<div class="notice la-notice notice-warning"><p><strong>' .
				esc_html__( 'Login Armor: password breach notice', 'login-armor' ) . '</strong><br>';
			if ( $pwd_count > 0 ) {
				echo esc_html(
					sprintf(
						/* translators: %s: formatted number of appearances of the current password in public breach corpora. */
						_n(
							'The password you are currently using appears in a public data breach corpus (seen %s time). This does not mean your account has been compromised, but it does mean attackers already know this password. We recommend changing it below.',
							'The password you are currently using appears in a public data breach corpus (seen %s times). This does not mean your account has been compromised, but it does mean attackers already know this password. We recommend changing it below.',
							$pwd_count,
							'login-armor'
						),
						number_format_i18n( $pwd_count )
					)
				);
			} else {
				esc_html_e( 'The password you are currently using appears in a public data breach corpus. We recommend changing it below.', 'login-armor' );
			}
			echo '</p></div>';
		}

		if ( $email_flagged > 0 && ! empty( $breaches ) ) {
			echo '<div class="notice la-notice notice-info"><p><strong>' .
				esc_html__( 'Login Armor: email breach notice', 'login-armor' ) . '</strong><br>';
			echo esc_html(
				sprintf(
					/* translators: %d: number of data breaches in which the user's email address appears. */
					_n(
						'Your email address appears in %d publicly disclosed data breach. Passwords you may have reused elsewhere could be exposed: make sure this site uses a unique password.',
						'Your email address appears in %d publicly disclosed data breaches. Passwords you may have reused elsewhere could be exposed: make sure this site uses a unique password.',
						count( $breaches ),
						'login-armor'
					),
					count( $breaches )
				)
			);
			echo '<br><small>' .
				esc_html__( 'Breach sources:', 'login-armor' ) . ' ' .
				esc_html( implode( ', ', array_slice( $breaches, 0, 5 ) ) );
			if ( count( $breaches ) > 5 ) {
				echo esc_html( sprintf( ' (+%d)', count( $breaches ) - 5 ) );
			}
			echo '</small></p></div>';
		}
	}

	/**
	 * When "force password reset" is on, flagged users are redirected to
	 * the edit-profile page on every admin load until they change their
	 * password. We don't lock them out: we just nag persistently.
	 *
	 * CRITICAL: this runs on admin_init, which fires BEFORE
	 * get_current_screen() is populated. The v2.0.5 first cut used the
	 * screen object to detect "user is already on profile.php": which
	 * returned null during admin_init, so profile.php itself triggered
	 * a redirect to profile.php → ERR_TOO_MANY_REDIRECTS. The fix is
	 * to use the $pagenow global (which IS set during admin_init) for
	 * the loop-breaking check. Confirmed on cours-ndrc.fr 2026-04-19.
	 */
	public function maybe_force_password_reset(): void {
		global $pagenow;

		// Skip non-HTML contexts where headers() can't be sent anyway.
		if ( defined( 'DOING_AJAX' ) && DOING_AJAX ) { return; }
		if ( defined( 'DOING_CRON' ) && DOING_CRON ) { return; }
		if ( defined( 'WP_CLI' ) && \WP_CLI ) { return; }
		if ( defined( 'REST_REQUEST' ) && REST_REQUEST ) { return; }

		// Skip auth flows and non-admin endpoints.
		if ( in_array( $pagenow, array( 'wp-login.php', 'wp-signup.php', 'wp-activate.php', 'admin-ajax.php', 'admin-post.php' ), true ) ) {
			return;
		}

		// LOOP-BREAKER: on profile.php the user is already on the
		// remediation screen: never redirect away from it.
		if ( 'profile.php' === $pagenow || 'user-edit.php' === $pagenow ) {
			return;
		}

		$user_id = get_current_user_id();
		if ( $user_id <= 0 ) {
			return;
		}

		// Allow Login Armor's own screens so an admin can disable the
		// feature even while their own account is flagged.
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Read-only routing guard, no state mutation here.
		$current_page = isset( $_GET['page'] ) ? sanitize_key( wp_unslash( $_GET['page'] ) ) : '';
		if ( 'login-armor' === $current_page ) {
			return;
		}

		if ( ! (int) get_user_meta( $user_id, self::META_PASSWORD_FLAGGED, true ) ) {
			return;
		}

		update_user_meta( $user_id, self::META_FORCE_RESET_NEEDED, 1 );
		wp_safe_redirect( admin_url( 'profile.php#password' ) );
		exit;
	}

	/**
	 * Scan every administrator's email address against XposedOrNot on
	 * module activation (or when the email sub-toggle flips on). We
	 * cannot do the same for passwords: WordPress stores them as
	 * one-way bcrypt/phpass hashes, so there is nothing to recover and
	 * check against HIBP in bulk. Password checks run opportunistically
	 * on each user's next login, when the plaintext is briefly in scope
	 * inside the authenticate filter.
	 *
	 * @return array{scanned:int, flagged:int}
	 */
	public static function scan_admin_emails(): array {
		$scanned = 0;
		$flagged = 0;

		$admins = get_users(
			array(
				'role'   => 'administrator',
				'fields' => array( 'ID', 'user_email' ),
				'number' => 50, // sanity cap: 99% of sites have 1-5 admins.
			)
		);

		foreach ( $admins as $admin ) {
			$email = isset( $admin->user_email ) ? (string) $admin->user_email : '';
			if ( '' === $email ) {
				continue;
			}
			$result = self::check_email( $email );
			if ( null === $result ) {
				continue; // API error for this one address, fail-soft.
			}
			++$scanned;
			if ( $result['leaked'] ) {
				update_user_meta( (int) $admin->ID, self::META_EMAIL_FLAGGED, time() );
				update_user_meta( (int) $admin->ID, self::META_EMAIL_BREACHES, array_slice( $result['breaches'], 0, 20 ) );
				++$flagged;
			} else {
				delete_user_meta( (int) $admin->ID, self::META_EMAIL_FLAGGED );
				delete_user_meta( (int) $admin->ID, self::META_EMAIL_BREACHES );
			}
		}

		return array( 'scanned' => $scanned, 'flagged' => $flagged );
	}

	/**
	 * Return the list of users currently flagged for password or email
	 * breach, for admin surfacing. We pull both dimensions so the admin
	 * can see who is affected and by what, on a single screen.
	 *
	 * @param int $limit Maximum number of users to return per dimension.
	 * @return array{password:array<int,array{id:int, login:string, display:string, edit_url:string, flagged_at:int}>, email:array<int,array{id:int, login:string, display:string, edit_url:string, flagged_at:int, breaches:array<int,string>}>}
	 */
	public static function get_flagged_users( int $limit = 20 ): array {
		// phpcs:disable WordPress.DB.SlowDBQuery.slow_db_query_meta_key,WordPress.DB.SlowDBQuery.slow_db_query_meta_value -- meta_query on a sparse user_meta key; typical site has <5 flagged users, acceptable scan.
		$pwd_users = get_users(
			array(
				'meta_key'     => self::META_PASSWORD_FLAGGED,
				'meta_value'   => 0,
				'meta_compare' => '>',
				'number'       => $limit,
				'fields'       => array( 'ID', 'user_login', 'display_name' ),
			)
		);
		$email_users = get_users(
			array(
				'meta_key'     => self::META_EMAIL_FLAGGED,
				'meta_value'   => 0,
				'meta_compare' => '>',
				'number'       => $limit,
				'fields'       => array( 'ID', 'user_login', 'display_name' ),
			)
		);
		// phpcs:enable WordPress.DB.SlowDBQuery.slow_db_query_meta_key,WordPress.DB.SlowDBQuery.slow_db_query_meta_value

		$map_pwd = array();
		foreach ( $pwd_users as $u ) {
			$map_pwd[] = array(
				'id'         => (int) $u->ID,
				'login'      => (string) $u->user_login,
				'display'    => (string) $u->display_name,
				'edit_url'   => get_edit_user_link( (int) $u->ID ),
				'flagged_at' => (int) get_user_meta( (int) $u->ID, self::META_PASSWORD_FLAGGED, true ),
			);
		}

		$map_email = array();
		foreach ( $email_users as $u ) {
			$map_email[] = array(
				'id'         => (int) $u->ID,
				'login'      => (string) $u->user_login,
				'display'    => (string) $u->display_name,
				'edit_url'   => get_edit_user_link( (int) $u->ID ),
				'flagged_at' => (int) get_user_meta( (int) $u->ID, self::META_EMAIL_FLAGGED, true ),
				'breaches'   => (array) get_user_meta( (int) $u->ID, self::META_EMAIL_BREACHES, true ),
			);
		}

		return array( 'password' => $map_pwd, 'email' => $map_email );
	}

	/**
	 * Return the current flagged-user counts, for Overview and Widget badges.
	 *
	 * @return array{password:int, email:int}
	 */
	public static function get_flagged_counts(): array {
		global $wpdb;

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- User meta count, direct scan needed for admin overview.
		$pwd = (int) $wpdb->get_var(
			$wpdb->prepare(
				"SELECT COUNT(*) FROM {$wpdb->usermeta} WHERE meta_key = %s AND CAST(meta_value AS UNSIGNED) > 0",
				self::META_PASSWORD_FLAGGED
			)
		);
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- User meta count, direct scan needed for admin overview.
		$email = (int) $wpdb->get_var(
			$wpdb->prepare(
				"SELECT COUNT(*) FROM {$wpdb->usermeta} WHERE meta_key = %s AND CAST(meta_value AS UNSIGNED) > 0",
				self::META_EMAIL_FLAGGED
			)
		);
		return array( 'password' => $pwd, 'email' => $email );
	}
}
