<?php
/**
 * Limit Login module.
 *
 * Tracks failed login attempts per IP address and enforces lockout
 * after a configurable number of failures.
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
 * Handles brute force protection via login attempt limiting.
 */
class LimitLogin {

	/**
	 * Request-scoped flag raised by trigger_lockout(). Consumed by
	 * LoginLogs::log_failure() to distinguish the triggering attempt
	 * (which must be logged as 'failed': the password was actually
	 * tested and wrong) from a post-lockout attempt (which must be
	 * logged as 'locked'). Fixed in 2.0.9 after beta tester Sébastien
	 * Pierrepack reported seeing 'Mot de passe incorrect' events after
	 * the first 'Débit limité' event for the same IP, when only 'locked'
	 * events were expected.
	 *
	 * @var bool
	 */
	private static bool $lockout_just_triggered = false;

	/**
	 * Error codes emitted by Login Armor's own `authenticate` gates.
	 *
	 * WordPress fires `wp_login_failed` after ANY WP_Error returned from the
	 * `authenticate` filter: including the ones this plugin returns itself.
	 * Counting those as brute-force strikes is a pure double count: none of
	 * them can be produced by guessing a password, and each already carries
	 * its own sanction (the honeypot bans the IP outright, the 2FA gates have
	 * their own counter and their own 15-minute lockout).
	 *
	 * The user-visible consequence of the missing exclusion, reported by
	 * Jean-Pol on 2026-07-21: after a single mistyped 2FA code, his next three
	 * logins with the CORRECT password were refused by the 2FA lockout, shown
	 * as "Wrong password", and tripped the 20-minute IP lockout on top.
	 *
	 * @var string[]
	 */
	private const SELF_EMITTED_ERROR_CODES = [
		'login_armor_locked_out',
		'login_armor_subnet_blocked',
		'login_armor_2fa_lockout',
		'login_armor_2fa_ip_lockout',
		'login_armor_2fa_setup_required',
		'honeypot_caught',
		'username_blacklisted',
		'login_armor_pow_failed',
	];

	/**
	 * 2.9.0: the application-password failures that count toward the lockout.
	 *
	 * Only an unknown account: a probe or an enumeration. A wrong password on
	 * an existing account is logged and seen by detection, never counted
	 * (spec, decision 2): nothing can be guessed there, and a script holding a
	 * revoked password locked its owner's address in seconds.
	 *
	 * @var string[]
	 */
	public const APP_PASSWORD_LOCKOUT_CODES = [ 'invalid_username', 'invalid_email' ];

	/**
	 * Whether an authentication error should count toward the brute-force
	 * threshold.
	 *
	 * Everything counts by default: core codes (`incorrect_password`,
	 * `invalid_username`) and unknown third-party codes alike, so an external
	 * auth plugin's rejections keep protecting the site. Only the plugin's own
	 * gate codes are excluded.
	 *
	 * @param mixed $error Expected WP_Error; anything else counts.
	 * @return bool
	 */
	private static function counts_as_bruteforce( $error = null ): bool {
		if ( ! $error instanceof \WP_Error ) {
			return true;
		}
		$code = $error->get_error_code();
		if ( ! is_string( $code ) || '' === $code ) {
			return true;
		}

		/**
		 * Filters the error codes that must NOT count as brute-force attempts.
		 *
		 * Lets a site exclude the rejection codes of a third-party
		 * authentication plugin whose refusals are not password guesses.
		 *
		 * @param string[] $codes Error codes exempt from the failure counter.
		 */
		$exempt = apply_filters( 'login_armor_non_bruteforce_error_codes', self::SELF_EMITTED_ERROR_CODES );
		if ( ! is_array( $exempt ) ) {
			$exempt = self::SELF_EMITTED_ERROR_CODES;
		}

		return ! in_array( $code, array_map( 'strval', $exempt ), true );
	}

	/**
	 * Whether trigger_lockout() has run in the current request.
	 *
	 * @return bool
	 */
	public static function was_lockout_just_triggered(): bool {
		return self::$lockout_just_triggered;
	}

	/**
	 * Constructor. Registers authentication hooks.
	 */
	public function __construct() {
		if ( ! (bool) get_option( 'login_armor_limit_enabled', true ) ) {
			return;
		}

		add_filter( 'authenticate', [ $this, 'check_lockout' ], 30, 3 );
		// Two args: WP 5.4+ passes the WP_Error, which tells us whether the
		// failure is a real credential guess or one of our own gates firing.
		add_action( 'wp_login_failed', [ $this, 'record_failed_attempt' ], 10, 2 );
		// 2.9.0: core authenticates application passwords on
		// determine_current_user, outside the `authenticate` filters and
		// without wp_login_failed. Its own failure action is the only signal.
		add_action( 'application_password_failed_authentication', [ $this, 'record_app_password_failure' ], 10, 1 );
		add_action( 'wp_login', [ $this, 'reset_on_success' ], 10, 2 );
		add_filter( 'login_errors', [ $this, 'filter_login_errors' ] );

		// v2.0.9: gate password-recovery surfaces for locked IPs.
		add_action( 'lostpassword_post', [ $this, 'gate_lostpassword_post' ], 5, 1 );
		add_filter( 'allow_password_reset', [ $this, 'gate_allow_password_reset' ], 10, 2 );
		add_filter( 'retrieve_password_message', [ $this, 'gate_retrieve_password_message' ], 5, 4 );
		add_filter( 'retrieve_password_notification_email', [ $this, 'gate_retrieve_password_email' ], 5, 4 );
		add_filter( 'registration_errors', [ $this, 'gate_registration_errors' ], 5, 3 );
		add_filter( 'xmlrpc_enabled', [ $this, 'gate_xmlrpc_enabled' ], 5 );
		// 2.10.0 (C01): per dispatch, with the route core resolved. Far ahead
		// of other rest_pre_dispatch filters: a response cache answering at an
		// earlier priority would otherwise serve /wp/v2/users past the gate,
		// which the rest_authentication_errors gate (run before any dispatch)
		// never allowed.
		add_filter( 'rest_pre_dispatch', [ $this, 'gate_rest_dispatch' ], -1000, 3 );
	}

	/**
	 * Check if the current IP is locked out before authentication proceeds.
	 *
	 * Parameters untyped with defaults and the return hint removed: WP core
	 * does not enforce types on filter callbacks, and `authenticate` is the
	 * most re-fired hook in the ecosystem (WooCommerce, social login,
	 * REST/XML-RPC bridges), sometimes with fewer args or a null username.
	 * Strict hints would fatal the whole login screen.
	 *
	 * @param mixed $user     The authenticated user, error, or null.
	 * @param mixed $username The username provided (expected string).
	 * @param mixed $password The password provided (expected string).
	 * @return \WP_User|\WP_Error|null|mixed
	 */
	public function check_lockout( $user = null, $username = '', $password = '' ) {
		if ( ! is_string( $username ) || $username === '' ) {
			return $user;
		}

		$ip = LoginArmor::get_client_ip();

		// See record_failed_attempt() for the placeholder rationale: a single
		// '0.0.0.0' lockout row would block every subsequent visitor whose
		// resolution also falls through to the placeholder. Skip the lockout
		// check entirely when the IP cannot be resolved.
		if ( ! LoginArmor::is_reliable_client_ip( $ip ) ) {
			return $user;
		}

		if ( self::is_whitelisted( $ip ) ) {
			return $user;
		}

		if ( self::is_ip_locked( $ip ) ) {
			$remaining = self::get_remaining_lockout_seconds( $ip );
			$minutes   = max( 1, (int) ceil( $remaining / 60 ) );

			/**
			 * Fires when a request is blocked because of an IP lockout,
			 * subnet block or honeypot catch.
			 *
			 * Canonical signature (V2.4.2): every emitter passes the attempted
			 * username as the second argument ('' when none applies to the
			 * blocked surface) and a context array as the third, with a
			 * 'source' key identifying the gate that fired: 'login_lockout',
			 * 'login_subnet', 'lostpassword', 'password_reset',
			 * 'retrieve_password', 'registration', 'xmlrpc', 'rest',
			 * 'honeypot'.
			 *
			 * @param string               $ip       The blocked IP address.
			 * @param string               $username The attempted username ('' when unknown).
			 * @param array<string,string> $context  Block context ('source' => gate identifier).
			 */
			do_action( 'login_armor_ip_blocked', $ip, $username, [ 'source' => 'login_lockout' ] );

			return new \WP_Error(
				'login_armor_locked_out',
				sprintf(
					/* translators: %d: Number of minutes remaining in lockout period. */
					__( '<strong>Error:</strong> Too many failed login attempts. Please try again in %d minutes.', 'login-armor' ),
					$minutes
				)
			);
		}

		if ( self::is_ip_in_blocked_subnet( $ip ) ) {
			do_action( 'login_armor_ip_blocked', $ip, $username, [ 'source' => 'login_subnet' ] );

			return new \WP_Error(
				'login_armor_subnet_blocked',
				__( '<strong>Access denied.</strong> Your network has been blocked by the site administrator.', 'login-armor' )
			);
		}

		return $user;
	}

	/**
	 * Record a failed login attempt and trigger lockout if threshold is reached.
	 *
	 * Parameters untyped with defaults: third-party plugins re-fire
	 * `wp_login_failed` manually, sometimes with null or nothing at all, and
	 * sometimes with the pre-WP-5.4 single-argument signature (no WP_Error).
	 * A strict hint would fatal the failed-login path. A missing error object
	 * degrades to "counts as brute force", the pre-2.4.5 behaviour.
	 *
	 * @param mixed $username The username that failed authentication (expected string).
	 * @param mixed $error    The authentication error (expected WP_Error).
	 */
	public function record_failed_attempt( $username = '', $error = null ): void {
		global $wpdb;

		if ( ! is_string( $username ) ) {
			$username = '';
		}

		// V2.4.5: a block emitted by Login Armor itself is not a password
		// guess. Recording it would move a legitimate user toward the lockout
		// they are already serving, and label the event "Wrong password".
		if ( ! self::counts_as_bruteforce( $error ) ) {
			return;
		}

		$ip = LoginArmor::get_client_ip();

		// Skip an unknown or loopback-only identity. A direct TCP peer remains a
		// valid client, but an unusable forwarding header from a declared shared
		// proxy must not group every visitor under one address. Raise a transient
		// so an administrator can inspect the network and proxy configuration.
		if ( ! LoginArmor::is_reliable_client_ip( $ip ) ) {
			set_transient( 'login_armor_ip_method_misconfigured', time(), DAY_IN_SECONDS );
			return;
		}

		if ( self::is_whitelisted( $ip ) ) {
			return;
		}

		// Do not record additional failures while already locked out.
		if ( self::is_ip_locked( $ip ) ) {
			return;
		}

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Custom plugin table, real-time write, no cache layer.
		$wpdb->insert(
			$wpdb->prefix . 'login_armor_attempts',
			[
				'ip'           => $ip,
				'username'     => sanitize_user( $username ),
				'attempt_time' => current_time( 'mysql', true ),
				'status'       => 'failed',
			],
			[ '%s', '%s', '%s', '%s' ]
		);

		// 2.10.0: one stable line for fail2ban, when the administrator asked.
		Support\Syslog::failure( $ip, $error );

		// Check if this failure triggers a lockout.
		$allowed_retries = (int) get_option( 'login_armor_allowed_retries', 3 );
		$recent_failures = self::count_recent_failures( $ip );

		if ( $recent_failures >= $allowed_retries ) {
			$this->trigger_lockout( $ip );
		}
	}

	/**
	 * Count an application-password failure, when it is an unknown account.
	 *
	 * Untyped with a default: anyone can fire a core action, with anything.
	 *
	 * @since 2.9.0
	 *
	 * @param mixed $error The authentication error (expected WP_Error).
	 */
	public function record_app_password_failure( $error = null ): void {
		if ( ! $error instanceof \WP_Error ) {
			return;
		}
		// Core also hooks wp_authenticate_application_password on `authenticate`
		// (XML-RPC, anything calling wp_authenticate()): there the same failure
		// reaches wp_login_failed, already counted by record_failed_attempt().
		// The REST Basic Auth path is not in that filter: core runs
		// wp_validate_application_password() from determine_current_user.
		if ( doing_filter( 'authenticate' ) ) {
			return;
		}
		if ( ! in_array( $error->get_error_code(), self::APP_PASSWORD_LOCKOUT_CODES, true ) ) {
			return;
		}
		$this->record_failed_attempt( self::app_password_username(), $error );
	}

	/**
	 * The login core read from Basic Auth for this request.
	 *
	 * @since 2.9.0
	 */
	public static function app_password_username(): string {
		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- sanitize_user() below; a login, not free text.
		$raw = isset( $_SERVER['PHP_AUTH_USER'] ) ? (string) wp_unslash( $_SERVER['PHP_AUTH_USER'] ) : '';
		return mb_substr( sanitize_user( $raw ), 0, 200 );
	}

	/**
	 * Reset this account's failed attempts from the IP after a successful login.
	 *
	 * Parameters untyped with defaults: many plugins re-fire `wp_login` with
	 * a single argument (the pre-WP-4.5 signature). When $user is missing we
	 * resolve it from $user_login so the attempt counter still resets.
	 *
	 * @param mixed $user_login The username that logged in (expected string).
	 * @param mixed $user       The user object (expected WP_User).
	 */
	public function reset_on_success( $user_login = '', $user = null ): void {
		global $wpdb;

		if ( ! $user instanceof \WP_User && is_string( $user_login ) && '' !== $user_login ) {
			$user = get_user_by( 'login', $user_login );
		}
		if ( ! $user instanceof \WP_User ) {
			return;
		}

		$ip = LoginArmor::get_client_ip();
		if ( ! LoginArmor::is_reliable_client_ip( $ip ) ) {
			return;
		}

		// Clear the failures of THIS account from this IP, under either name it
		// can be typed with (record_failed_attempt() stores what was typed).
		// Clearing every failure of the IP let anyone with an account of their
		// own (open registration, a shop customer) guess another account's
		// password forever: two guesses, one login to their own account, and
		// the counter was back to zero.
		$deleted = 0;
		$names   = array_unique( array_filter( [ sanitize_user( (string) $user->user_login ), sanitize_user( (string) $user->user_email ) ] ) );
		foreach ( $names as $name ) {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Custom plugin table, real-time write, no cache layer.
			$deleted += (int) $wpdb->delete( $wpdb->prefix . 'login_armor_attempts', [ 'ip' => $ip, 'status' => 'failed', 'username' => $name ], [ '%s', '%s', '%s' ] );
		}

		/**
		 * Fires after failed login attempts have been cleared following a successful login.
		 *
		 * @param string   $ip         The IP address whose attempts were cleared.
		 * @param \WP_User $user       The user who logged in successfully.
		 * @param int      $deleted    Number of attempt rows removed.
		 */
		do_action( 'login_armor_attempts_cleared', $ip, $user, $deleted );
	}

	/**
	 * Customize the login error message to show remaining attempts.
	 *
	 * Parameter untyped and normalized defensively: WP core does not enforce
	 * types on filter callback arguments, and a third-party plugin filtering
	 * `login_errors` ahead of us may pass a non-string (null, WP_Error). A
	 * strict `string` hint would fatal the whole login/lostpassword screen.
	 *
	 * @param mixed $errors Current error message HTML (expected string).
	 * @return string
	 */
	public function filter_login_errors( $errors = '' ): string {
		if ( ! is_string( $errors ) ) {
			$errors = '';
		}

		// Audit S-9: when Hardening's mask_login_errors is on, our remaining-
		// attempts hint must NOT leak. Hardening's generic error filter runs
		// at priority 9999 (last writer wins), but we still short-circuit here
		// to keep the two behaviors explicitly mutually exclusive. The toggle
		// lives inside the login_armor_hardening array option (there is no
		// standalone login_armor_mask_login_errors option).
		$la_hardening = get_option( 'login_armor_hardening', array() );
		if ( is_array( $la_hardening ) && ! empty( $la_hardening['mask_login_errors'] ) ) {
			return $errors;
		}

		$ip = LoginArmor::get_client_ip();
		if ( ! LoginArmor::is_reliable_client_ip( $ip ) ) {
			return $errors;
		}

		if ( self::is_whitelisted( $ip ) || self::is_ip_locked( $ip ) ) {
			return $errors;
		}

		$allowed   = (int) get_option( 'login_armor_allowed_retries', 3 );
		$failures  = self::count_recent_failures( $ip );
		$remaining = max( 0, $allowed - $failures );

		if ( $remaining > 0 && $remaining < $allowed ) {
			$errors .= '<br>' . sprintf(
				/* translators: %d: Number of login attempts remaining before lockout. */
				__( '<strong>%d attempt(s) remaining</strong> before your IP is temporarily locked.', 'login-armor' ),
				$remaining
			);
		}

		return $errors;
	}

	/**
	 * Trigger a lockout for the given IP.
	 *
	 * @param string $ip IP address to lock out.
	 */
	private function trigger_lockout( string $ip ): void {
		global $wpdb;

		// Serialize the "not-locked -> locked" transition. Several failures that
		// race across the threshold at once would otherwise each insert a
		// 'lockout' marker, and the escalation logic (count_lockouts) would read
		// a burst of N markers as N separate offences: jumping a first lockout
		// straight to the long ban (finding P3). An atomic per-IP claim lets
		// exactly one request of the burst write the marker; the losers bail out
		// (they are already effectively locked and will see the marker on their
		// next request via is_ip_locked()).
		if ( ! $this->claim_lockout( $ip ) ) {
			return;
		}

		// Raise the request-scoped flag so LoginLogs::log_failure()
		// knows the lockout was triggered in *this* request (the
		// triggering attempt must still be logged as 'failed', not
		// 'locked': the password was actually checked and wrong).
		self::$lockout_just_triggered = true;

		/**
		 * Fires just before an IP is locked out.
		 *
		 * @param string $ip The IP address about to be locked out.
		 */
		do_action( 'login_armor_before_lockout', $ip );

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Custom plugin table, real-time write, no cache layer.
		$wpdb->insert(
			$wpdb->prefix . 'login_armor_attempts',
			[
				'ip'           => $ip,
				'username'     => '',
				'attempt_time' => current_time( 'mysql', true ),
				'status'       => 'lockout',
			],
			[ '%s', '%s', '%s', '%s' ]
		);

		/**
		 * Fires immediately after the lockout marker has been committed
		 * to the database. Subscribers can now safely call is_ip_locked()
		 * and get_lockout_level(): the row is visible. This is the hook
		 * to use for rendering the branded 429 page on the very request
		 * that triggered the lockout (see LockoutPage::render_on_trigger).
		 *
		 * Distinct from login_armor_before_lockout, which fires BEFORE
		 * the insert and is kept for back-compat with subscribers that
		 * want to short-circuit or audit the lockout decision itself.
		 *
		 * @param string $ip The IP address that was just locked out.
		 */
		Support\Syslog::lockout( $ip, self::get_lockout_level( $ip ) );
		do_action( 'login_armor_lockout_triggered', $ip );

		$this->maybe_notify_admin( $ip );
	}

	/**
	 * Send an email notification to the admin if the lockout threshold is reached.
	 *
	 * @param string $ip The locked-out IP address.
	 */
	private function maybe_notify_admin( string $ip ): void {
		$threshold = (int) get_option( 'login_armor_notify_threshold', 5 );
		if ( $threshold <= 0 ) {
			return;
		}

		$window_hours  = (int) get_option( 'login_armor_lockout_window', 24 );
		$lockout_count = self::count_lockouts( $ip, $window_hours * HOUR_IN_SECONDS );

		// Only notify exactly at the threshold to avoid spamming.
		if ( $lockout_count !== $threshold ) {
			return;
		}

		/**
		 * Fires when one IP reaches the configured lockout notification
		 * threshold. Fired before the e-mail below, which is unchanged: this
		 * hook is what routes the same fact to Slack, Discord or a generic
		 * webhook, so an operator who reads alerts in a channel is not the
		 * only one left out.
		 *
		 * @since 2.6.1
		 *
		 * @param string $ip        The locked-out IP address.
		 * @param int    $count     Lockouts recorded for that IP in the window.
		 * @param int    $threshold The configured threshold that was reached.
		 */
		do_action( 'login_armor_lockout_threshold_reached', $ip, $lockout_count, $threshold );

		$notify_email = trim( (string) get_option( 'login_armor_notify_email', '' ) );
		if ( $notify_email === '' ) {
			$notify_email = get_option( 'admin_email' );
		}

		$subject = sprintf(
			/* translators: %s: Site name. */
			__( '[%s] LoginArmor: Multiple lockouts detected', 'login-armor' ),
			get_bloginfo( 'name' )
		);

		$message = sprintf(
			/* translators: 1: IP address, 2: Lockout count, 3: Site name. */
			__(
				"The IP address %1\$s has been locked out %2\$d times on %3\$s.\n\nThis may indicate a brute force attack. You can whitelist this IP or take further action from the LoginArmor settings page:\n%4\$s",
				'login-armor'
			),
			$ip,
			$lockout_count,
			get_bloginfo( 'name' ),
			admin_url( 'admin.php?page=login-armor&tab=limit' )
		);

		wp_mail( $notify_email, $subject, $message );
	}

	/**
	 * Check if an IP address is currently locked out.
	 *
	 * @param string $ip IP address.
	 */
	public static function is_ip_locked( string $ip ): bool {
		if ( ! LoginArmor::is_reliable_client_ip( $ip ) ) {
			return false;
		}

		global $wpdb;

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Custom plugin table, real-time read, no cache layer.
		$last_lockout = $wpdb->get_var(
			$wpdb->prepare(
				"SELECT attempt_time FROM {$wpdb->prefix}login_armor_attempts WHERE ip = %s AND status = 'lockout' ORDER BY attempt_time DESC LIMIT 1",
				$ip
			)
		);

		if ( ! $last_lockout ) {
			return false;
		}

		$effective_duration = self::get_effective_lockout_duration( $ip );
		$lockout_time       = strtotime( $last_lockout . ' UTC' );

		return time() < ( $lockout_time + $effective_duration );
	}

	/**
	 * Get the remaining lockout time in seconds for an IP.
	 *
	 * @param string $ip IP address.
	 */
	public static function get_remaining_lockout_seconds( string $ip ): int {
		if ( ! LoginArmor::is_reliable_client_ip( $ip ) ) {
			return 0;
		}

		global $wpdb;

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Custom plugin table, real-time read, no cache layer.
		$last_lockout = $wpdb->get_var(
			$wpdb->prepare(
				"SELECT attempt_time FROM {$wpdb->prefix}login_armor_attempts WHERE ip = %s AND status = 'lockout' ORDER BY attempt_time DESC LIMIT 1",
				$ip
			)
		);

		if ( ! $last_lockout ) {
			return 0;
		}

		$effective_duration = self::get_effective_lockout_duration( $ip );
		$lockout_time       = strtotime( $last_lockout . ' UTC' );
		$remaining          = ( $lockout_time + $effective_duration ) - time();

		return max( 0, $remaining );
	}

	/**
	 * Get the effective lockout duration for an IP (short or long ban).
	 *
	 * Niveau 1 = short lockout (default 20 min).
	 * Niveau 2 = long ban (default 24 h), triggered when the IP has been
	 * locked at least $max_lockouts times within the last $window_hours.
	 *
	 * @param string $ip IP address.
	 * @return int Duration in seconds.
	 */
	private static function get_effective_lockout_duration( string $ip ): int {
		$lockout_duration = (int) get_option( 'login_armor_lockout_duration', 20 );
		$max_lockouts     = (int) get_option( 'login_armor_max_lockouts', 2 );
		$long_duration    = (int) get_option( 'login_armor_long_duration', 24 );
		$window_hours     = (int) get_option( 'login_armor_lockout_window', 24 );

		$lockout_count = self::count_lockouts( $ip, $window_hours * HOUR_IN_SECONDS );

		if ( $lockout_count >= $max_lockouts ) {
			return $long_duration * HOUR_IN_SECONDS;
		}

		return $lockout_duration * MINUTE_IN_SECONDS;
	}

	/**
	 * Return the current lockout level for an IP.
	 *
	 * @param string $ip IP address.
	 * @return int 0 = no active lockout row (subnet-blocklist state NOT considered here;
	 *                call is_locked_or_blacklisted() for the combined check)
	 *             1 = Niveau 1 (short lockout, countdown shown)
	 *             2 = Niveau 2 (long ban 24 h, admin contact message)
	 */
	public static function get_lockout_level( string $ip ): int {
		if ( ! self::is_ip_locked( $ip ) ) {
			return 0;
		}

		$max_lockouts  = (int) get_option( 'login_armor_max_lockouts', 2 );
		$window_hours  = (int) get_option( 'login_armor_lockout_window', 24 );
		$lockout_count = self::count_lockouts( $ip, $window_hours * HOUR_IN_SECONDS );

		return ( $lockout_count >= $max_lockouts ) ? 2 : 1;
	}

	/**
	 * Convenience: is this IP either locked or in subnet blocklist?
	 *
	 * Used by the extended gates (lostpassword, register, XML-RPC, REST)
	 * and by the branded landing page interceptor.
	 *
	 * @param string $ip IP address.
	 * @return bool
	 */
	public static function is_locked_or_blacklisted( string $ip ): bool {
		if ( ! LoginArmor::is_reliable_client_ip( $ip ) ) {
			return false;
		}
		if ( self::is_whitelisted( $ip ) ) {
			return false;
		}
		return self::is_ip_locked( $ip ) || self::is_ip_in_blocked_subnet( $ip );
	}

	/**
	 * Count recent failed attempts for an IP since the last lockout.
	 *
	 * @param string $ip IP address.
	 */
	private static function count_recent_failures( string $ip ): int {
		global $wpdb;

		// Find the most recent lockout time for this IP.
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Custom plugin table, real-time read, no cache layer.
		$last_lockout = $wpdb->get_var(
			$wpdb->prepare(
				"SELECT attempt_time FROM {$wpdb->prefix}login_armor_attempts WHERE ip = %s AND status = 'lockout' ORDER BY attempt_time DESC LIMIT 1",
				$ip
			)
		);

		if ( $last_lockout ) {
			// Count failures since the last lockout.
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Custom plugin table, real-time read, no cache layer.
			return (int) $wpdb->get_var(
				$wpdb->prepare(
					"SELECT COUNT(*) FROM {$wpdb->prefix}login_armor_attempts WHERE ip = %s AND status = 'failed' AND attempt_time > %s",
					$ip,
					$last_lockout
				)
			);
		}

		// No previous lockout: count failures in the valid duration window.
		$valid_duration = (int) get_option( 'login_armor_valid_duration', 24 );
		$since          = gmdate( 'Y-m-d H:i:s', time() - $valid_duration * HOUR_IN_SECONDS );

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Custom plugin table, real-time read, no cache layer.
		return (int) $wpdb->get_var(
			$wpdb->prepare(
				"SELECT COUNT(*) FROM {$wpdb->prefix}login_armor_attempts WHERE ip = %s AND status = 'failed' AND attempt_time > %s",
				$ip,
				$since
			)
		);
	}

	/**
	 * Seconds a lockout claim stays valid before it is considered abandoned.
	 *
	 * The claim only has to bridge the tiny window between "threshold crossed"
	 * and "marker committed and visible to is_ip_locked()". A short TTL keeps a
	 * crashed claimer from suppressing a genuinely separate later lockout: and
	 * a legitimate next lockout can only happen after the short ban (minutes)
	 * has already elapsed, comfortably longer than this TTL.
	 */
	private const LOCKOUT_CLAIM_TTL = 60;

	/**
	 * Non-reversible, per-site option name for an IP's lockout claim.
	 *
	 * The options table is per-blog, so the key is naturally site-scoped on
	 * multisite. The raw IP is never stored: it is HMAC'd with the site auth
	 * salt so wp_options never reveals which addresses were locked.
	 *
	 * @param string $ip IP address.
	 * @return string Option name.
	 */
	private static function lockout_claim_key( string $ip ): string {
		return 'login_armor_lockout_claim_' . substr( hash_hmac( 'sha256', $ip, wp_salt( 'auth' ) ), 0, 32 );
	}

	/**
	 * Atomically claim the right to write the lockout marker for an IP.
	 *
	 * Uses `INSERT IGNORE` on the options table: the unique index on
	 * option_name means exactly one concurrent INSERT affects a row (returns 1);
	 * every other racer gets 0 and loses. A pre-existing claim older than
	 * LOCKOUT_CLAIM_TTL is treated as abandoned (the previous winner crashed
	 * before committing the marker) and taken over, so a stuck claim can never
	 * suppress lockouts forever. The claim row is intentionally NOT deleted here:
	 * removing it immediately would let a slightly-delayed request in the same
	 * burst re-acquire it and write a second marker. It is reaped later by
	 * purge_claims() / the daily purge.
	 *
	 * @param string $ip IP address.
	 * @return bool True if this call won the claim.
	 */
	private function claim_lockout( string $ip ): bool {
		global $wpdb;

		$key = self::lockout_claim_key( $ip );
		$now = time();

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.NotPrepared -- Atomic claim via unique option_name index; core options table.
		$inserted = $wpdb->query(
			$wpdb->prepare(
				"INSERT IGNORE INTO {$wpdb->options} (option_name, option_value, autoload) VALUES (%s, %s, 'no')",
				$key,
				(string) $now
			)
		);

		if ( $inserted ) {
			return true;
		}

		// Claim already present: read the real stored timestamp straight from
		// the DB (bypass the object cache, which may hold a stale miss).
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Fresh read of the claim we just failed to insert.
		$claimed_at = (int) $wpdb->get_var(
			$wpdb->prepare( "SELECT option_value FROM {$wpdb->options} WHERE option_name = %s", $key )
		);

		if ( $claimed_at > 0 && ( $now - $claimed_at ) > self::LOCKOUT_CLAIM_TTL ) {
			// Take over the abandoned claim.
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Re-arm abandoned claim.
			$wpdb->update( $wpdb->options, [ 'option_value' => (string) $now ], [ 'option_name' => $key ] );
			// Keep the object cache consistent with the row we just changed.
			wp_cache_delete( $key, 'options' );
			return true;
		}

		return false;
	}

	/**
	 * Delete lockout-claim option rows older than the claim TTL.
	 *
	 * Claims are tiny, non-autoloaded rows keyed per IP; this reaps the ones
	 * left behind after each lockout episode so wp_options does not accumulate
	 * stale claims over time. Called from the daily purge.
	 *
	 * @return int Number of claim rows removed.
	 */
	public static function purge_claims(): int {
		global $wpdb;

		$cutoff = time() - self::LOCKOUT_CLAIM_TTL;

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Maintenance cleanup of plugin claim rows.
		$deleted = (int) $wpdb->query(
			$wpdb->prepare(
				"DELETE FROM {$wpdb->options} WHERE option_name LIKE %s AND CAST(option_value AS UNSIGNED) < %d",
				$wpdb->esc_like( 'login_armor_lockout_claim_' ) . '%',
				$cutoff
			)
		);

		if ( $deleted > 0 ) {
			wp_cache_flush_group( 'options' );
		}

		return $deleted;
	}

	/**
	 * Count lockout entries for an IP within a time window.
	 *
	 * @param string $ip      IP address.
	 * @param int    $seconds Time window in seconds.
	 */
	private static function count_lockouts( string $ip, int $seconds ): int {
		global $wpdb;

		$since = gmdate( 'Y-m-d H:i:s', time() - $seconds );

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Custom plugin table, real-time read, no cache layer.
		return (int) $wpdb->get_var(
			$wpdb->prepare(
				"SELECT COUNT(*) FROM {$wpdb->prefix}login_armor_attempts WHERE ip = %s AND status = 'lockout' AND attempt_time > %s",
				$ip,
				$since
			)
		);
	}

	/**
	 * Check if an IP is in the whitelist.
	 *
	 * @param string $ip IP address to check.
	 */
	public static function is_whitelisted( string $ip ): bool {
		// Localhost is automatically trusted only for a direct connection.
		// When a forwarding header is selected, accepting a client-supplied
		// loopback value here would bypass every brute-force counter. The IP
		// resolver rejects forwarded loopback addresses too; this second guard
		// keeps the security boundary explicit at the whitelist itself.
		$ip_method = (string) get_option( 'login_armor_ip_method', 'REMOTE_ADDR' );
		if ( 'REMOTE_ADDR' === $ip_method && in_array( $ip, [ '127.0.0.1', '::1' ], true ) ) {
			return true;
		}

		return self::is_on_safelist( $ip );
	}

	/**
	 * Whether the administrator put this address on the IP safelist (2.8.0).
	 *
	 * is_whitelisted() also trusts a direct loopback connection, which nobody
	 * chose. Detection uses this narrower test to tone down an alarm only for
	 * an address an administrator vouched for by name.
	 *
	 * @param string $ip IP address to check.
	 */
	public static function is_on_safelist( string $ip ): bool {
		$whitelist = trim( (string) get_option( 'login_armor_whitelist_ips', '' ) );
		if ( $whitelist === '' ) {
			return false;
		}

		$ips = array_map( 'trim', explode( "\n", $whitelist ) );
		return in_array( $ip, $ips, true );
	}

	/**
	 * Unblock an IP by removing its lockout entries.
	 *
	 * @param string $ip IP address to unblock.
	 * @return int Number of deleted rows.
	 */
	public static function unblock_ip( string $ip ): int {
		global $wpdb;

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Custom plugin table, manual admin action.
		return (int) $wpdb->query(
			$wpdb->prepare(
				"DELETE FROM {$wpdb->prefix}login_armor_attempts WHERE ip = %s AND status IN ('lockout', 'failed', 'honeypot')",
				$ip
			)
		);
	}

	/**
	 * Return the /24 (IPv4) or /64 (IPv6) subnet string for a given IP.
	 * Returns empty string if the input is not a valid IP.
	 *
	 * IPv6 expansion: previous implementation used inet_ntop() which returns
	 * the *compressed* form (e.g. '2001:db8::1'). Naively splitting on ':'
	 * then produced fewer than 8 groups and a malformed re-imploded string
	 * ('2001:db8::1::/64'). Fixed in 2.0.5 by deriving groups from the raw
	 * 16 bytes via bin2hex() so the canonical 8-group expansion is always
	 * available before we slice the /64 prefix.
	 */
	public static function subnet_of( string $ip ): string {
		if ( ! filter_var( $ip, FILTER_VALIDATE_IP ) ) {
			return '';
		}
		if ( filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 ) ) {
			$parts = explode( '.', $ip );
			return $parts[0] . '.' . $parts[1] . '.' . $parts[2] . '.0/24';
		}
		$packed = @inet_pton( $ip ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- inet_pton emits a warning on invalid input that we already filtered.
		if ( false === $packed || 16 !== strlen( $packed ) ) {
			return '';
		}
		// 16 bytes → 32 hex chars → 8 groups of 4 hex chars (canonical, no compression).
		$groups = str_split( bin2hex( $packed ), 4 );
		if ( false === $groups || 8 !== count( $groups ) ) {
			return '';
		}
		// Take the first 4 groups (the /64 prefix); strip leading zeros for
		// readable output. Empty-after-strip stays as '0' so we never produce
		// a malformed `::` mid-string.
		$prefix = array_slice( $groups, 0, 4 );
		$prefix = array_map(
			static function ( string $g ): string {
				$stripped = ltrim( $g, '0' );
				return '' === $stripped ? '0' : $stripped;
			},
			$prefix
		);
		return implode( ':', $prefix ) . '::/64';
	}

	/**
	 * Return the list of currently blocked subnets.
	 *
	 * @return string[]
	 */
	public static function get_blocked_subnets(): array {
		$raw = get_option( 'login_armor_blocked_subnets', array() );
		if ( ! is_array( $raw ) ) {
			return array();
		}
		return array_values( array_unique( array_filter( $raw, 'is_string' ) ) );
	}

	/**
	 * Persist a new subnet in the blocklist. Duplicates are silently ignored.
	 */
	public static function add_blocked_subnet( string $subnet ): bool {
		if ( '' === $subnet ) {
			return false;
		}
		$current = self::get_blocked_subnets();
		if ( in_array( $subnet, $current, true ) ) {
			return true;
		}
		$current[] = $subnet;
		return update_option( 'login_armor_blocked_subnets', $current, false );
	}

	/**
	 * Remove a subnet from the blocklist.
	 */
	public static function remove_blocked_subnet( string $subnet ): bool {
		$current  = self::get_blocked_subnets();
		$filtered = array_values(
			array_filter(
				$current,
				static function ( $s ) use ( $subnet ) {
					return $s !== $subnet;
				}
			)
		);
		return update_option( 'login_armor_blocked_subnets', $filtered, false );
	}

	/**
	 * Check whether a given IP falls inside any currently blocked subnet.
	 */
	public static function is_ip_in_blocked_subnet( string $ip ): bool {
		if ( ! filter_var( $ip, FILTER_VALIDATE_IP ) ) {
			return false;
		}
		$subnet = self::subnet_of( $ip );
		if ( '' === $subnet ) {
			return false;
		}
		return in_array( $subnet, self::get_blocked_subnets(), true );
	}

	/**
	 * Whether blocking the network of $ip would shut out the current visitor (2.8.0).
	 *
	 * The settings import has refused this case since 2.6.0. The "Block
	 * subnet" button writes the same option and did not ask, so an
	 * administrator sharing a /24 with an attacker (same provider, same office
	 * NAT) locked themselves out with one click. An address on the safelist is
	 * checked before any block and is therefore never at risk, and an address
	 * this site cannot trust tells nothing about who is asking.
	 *
	 * @param string $ip Any address of the network about to be blocked.
	 */
	public static function would_lock_out_current_user( string $ip ): bool {
		$subnet = self::subnet_of( $ip );
		if ( '' === $subnet ) {
			return false;
		}

		$own = LoginArmor::get_client_ip();
		if ( ! LoginArmor::is_reliable_client_ip( $own ) || self::is_whitelisted( $own ) ) {
			return false;
		}

		return self::subnet_of( $own ) === $subnet;
	}

	/**
	 * Lift everything that keeps one address out (2.8.0).
	 *
	 * Lockout rows, and the blocked network that contains the address. The
	 * ways back that promise to unblock an address (`wp login-armor unblock`,
	 * `rescue --ip`, the safe-mode button) only removed the rows, answered
	 * "was not blocked" to an administrator shut out by a network block, and
	 * left the block in place. The Incidents screen's "Unblock IP" already
	 * removed both; every door now does the same thing.
	 *
	 * @param string $ip Address to release.
	 * @return array{rows:int,subnet:string} Rows deleted, and the network removed ('' when none was blocked).
	 */
	public static function release_ip( string $ip ): array {
		$rows   = self::unblock_ip( $ip );
		$subnet = '';
		if ( self::is_ip_in_blocked_subnet( $ip ) ) {
			$subnet = self::subnet_of( $ip );
			self::remove_blocked_subnet( $subnet );
		}

		return array(
			'rows'   => $rows,
			'subnet' => $subnet,
		);
	}

	/**
	 * Return the aggregate block state of an IP for UI rendering.
	 *
	 * Combines three existing checks (lockout, subnet blacklist, lockout
	 * expiry) into one call so that per-row rendering loops in the
	 * incidents UI don't hit the lockout table three times.
	 *
	 * @param string $ip IP address.
	 * @return array{locked:bool, lockout_expires_sec:int, blocked_subnet:?string}
	 *         - locked: true if a lockout row is active right now.
	 *         - lockout_expires_sec: seconds until the lockout ends (0 if not locked).
	 *         - blocked_subnet: the /24 CIDR string (e.g. "205.147.17.0/24") if
	 *           the IP falls inside a manually-blocked subnet, else null.
	 */
	public static function get_block_status( string $ip ): array {
		$locked         = self::is_ip_locked( $ip );
		$expires_sec    = $locked ? self::get_remaining_lockout_seconds( $ip ) : 0;
		$blocked_subnet = null;

		if ( self::is_ip_in_blocked_subnet( $ip ) ) {
			// is_ip_in_blocked_subnet matches via subnet_of(); derive the
			// canonical /24 CIDR string here so the UI can display it.
			// subnet_of() is O(1) and free of DB calls.
			$candidate = self::subnet_of( $ip );
			if ( '' !== $candidate ) {
				$blocked_subnet = $candidate;
			}
		}

		return array(
			'locked'              => $locked,
			'lockout_expires_sec' => (int) $expires_sec,
			'blocked_subnet'      => $blocked_subnet,
		);
	}

	/**
	 * Get a list of currently locked-out IP addresses.
	 *
	 * @return array<object{ip: string, last_lockout: string, lockout_count: int}>
	 */
	public static function get_locked_ips(): array {
		global $wpdb;

		$lockout_duration = (int) get_option( 'login_armor_lockout_duration', 20 );
		$max_lockouts     = (int) get_option( 'login_armor_max_lockouts', 2 );
		$long_duration    = (int) get_option( 'login_armor_long_duration', 24 );
		$window_hours     = (int) get_option( 'login_armor_lockout_window', 24 );

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Custom plugin table, admin UI real-time read.
		$results = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT ip, MAX(attempt_time) as last_lockout, COUNT(*) as lockout_count
				 FROM {$wpdb->prefix}login_armor_attempts
				 WHERE status = %s
				 AND attempt_time > DATE_SUB(UTC_TIMESTAMP(), INTERVAL %d HOUR)
				 GROUP BY ip",
				'lockout',
				$window_hours
			)
		);

		$locked = [];
		foreach ( $results as $entry ) {
			$effective = $entry->lockout_count >= $max_lockouts
				? $long_duration * HOUR_IN_SECONDS
				: $lockout_duration * MINUTE_IN_SECONDS;

			$lockout_time = strtotime( $entry->last_lockout . ' UTC' );
			if ( time() < ( $lockout_time + $effective ) ) {
				$locked[] = $entry;
			}
		}

		return $locked;
	}

	/**
	 * Get the count of currently locked-out IPs.
	 */
	public static function get_locked_ips_count(): int {
		return count( self::get_locked_ips() );
	}

	/**
	 * Block the lostpassword form submission from a locked IP.
	 *
	 * Parameter untyped: WP core passes ( $errors, $user_data ) here but does
	 * not enforce callback types, and a third-party plugin re-firing this hook
	 * may pass a non-WP_Error. Guarded internally so we never fatal the
	 * lostpassword screen.
	 *
	 * @param mixed $errors Running error bag passed by WP (expected WP_Error).
	 */
	public function gate_lostpassword_post( $errors = null ): void {
		$ip = LoginArmor::get_client_ip();
		if ( ! self::is_locked_or_blacklisted( $ip ) ) {
			return;
		}

		do_action( 'login_armor_ip_blocked', $ip, '', [ 'source' => 'lostpassword' ] );

		if ( $errors instanceof \WP_Error ) {
			$errors->add(
				'login_armor_locked_out',
				__( '<strong>Error:</strong> Too many failed attempts from your IP. Password recovery is temporarily disabled.', 'login-armor' )
			);
		}
	}

	/**
	 * Prevent the actual reset of a user's password if the current request
	 * originates from a locked IP. Catches the case where the lostpassword
	 * form was submitted from a free IP but the reset link is being clicked
	 * from a now-locked one.
	 *
	 * Parameters untyped: WP core does not enforce types on filter
	 * callback arguments, and third-party plugins may pass $allow as 0/1
	 * or $user_id as a string.
	 *
	 * @param mixed $allow   Whether reset is allowed (WP default true).
	 * @param mixed $user_id User ID about to reset.
	 * @return bool
	 */
	public function gate_allow_password_reset( $allow = true, $user_id = 0 ): bool {
		$ip = LoginArmor::get_client_ip();
		if ( self::is_locked_or_blacklisted( $ip ) ) {
			do_action( 'login_armor_ip_blocked', $ip, '', [ 'source' => 'password_reset' ] );
			return false;
		}
		return (bool) $allow;
	}

	/**
	 * Empty the reset-password email body when origin IP is locked.
	 *
	 * NOTE: returning an empty message does not cancel wp_mail(). The real
	 * cancellation happens via retrieve_password_notification_email below.
	 *
	 * All parameters untyped with defaults, and the return type hint removed:
	 * WP core does not enforce types on filter callbacks, and an email/branding
	 * plugin filtering `retrieve_password_message` ahead of us (WP passes the
	 * previous callback's return value as $message) may hand us a non-string
	 * such as null. A strict `string` hint fatals the lostpassword flow with a
	 * "critical error". When the IP is not locked we stay transparent and
	 * return $message untouched, preserving the filter chain.
	 *
	 * @param mixed $message    Email body (expected string).
	 * @param mixed $key        Activation key.
	 * @param mixed $user_login User login.
	 * @param mixed $user_data  User object (expected WP_User).
	 * @return mixed
	 */
	public function gate_retrieve_password_message( $message = '', $key = '', $user_login = '', $user_data = null ) {
		$ip = LoginArmor::get_client_ip();
		if ( self::is_locked_or_blacklisted( $ip ) ) {
			do_action( 'login_armor_ip_blocked', $ip, '', [ 'source' => 'retrieve_password' ] );
			return '';
		}
		return $message;
	}

	/**
	 * Block new user registration from a locked IP.
	 *
	 * Parameters untyped with defaults and the return hint removed for the
	 * same third-party-compatibility reason as the other recovery gates: a
	 * plugin filtering `registration_errors` may not pass a WP_Error. We stay
	 * transparent and return $errors untouched when it is not a WP_Error.
	 *
	 * @param mixed $errors Running error bag (expected WP_Error).
	 * @param mixed $sanitized_user_login Sanitized candidate login.
	 * @param mixed $user_email Candidate email.
	 * @return mixed
	 */
	public function gate_registration_errors( $errors = null, $sanitized_user_login = '', $user_email = '' ) {
		if ( ! $errors instanceof \WP_Error ) {
			return $errors;
		}
		$ip = LoginArmor::get_client_ip();
		if ( self::is_locked_or_blacklisted( $ip ) ) {
			do_action( 'login_armor_ip_blocked', $ip, is_string( $sanitized_user_login ) ? $sanitized_user_login : '', [ 'source' => 'registration' ] );
			$errors->add(
				'login_armor_locked_out',
				__( '<strong>Error:</strong> Registration is temporarily disabled for your IP due to suspicious activity.', 'login-armor' )
			);
		}
		return $errors;
	}

	/**
	 * Short-circuit wp_mail for password-reset email from locked IPs by
	 * zeroing the recipient list.
	 *
	 * NOTE: intentionally does NOT fire login_armor_ip_blocked:
	 * gate_retrieve_password_message already logged the event. Firing
	 * again here would double-count in the Incidents UI. This method is
	 * belt-and-suspenders only: it catches the case where a custom mailer
	 * plugin bypasses the `retrieve_password_message` filter.
	 *
	 * Parameters untyped with defaults and the return hint removed for the same
	 * third-party-compatibility reason as gate_retrieve_password_message(): a
	 * custom mailer may hand us a non-array $email or a non-WP_User $user_data.
	 * We only mutate when $email is genuinely an array, and otherwise return it
	 * untouched to preserve the filter chain.
	 *
	 * @param mixed $email      [to, subject, message, headers] (expected array).
	 * @param mixed $key        Activation key (unused).
	 * @param mixed $user_login User login (unused).
	 * @param mixed $user_data  User (unused, expected WP_User).
	 * @return mixed
	 */
	public function gate_retrieve_password_email( $email = array(), $key = '', $user_login = '', $user_data = null ) {
		if ( ! is_array( $email ) ) {
			return $email;
		}
		$ip = LoginArmor::get_client_ip();
		if ( self::is_locked_or_blacklisted( $ip ) ) {
			$email['to'] = '';
		}
		return $email;
	}

	/**
	 * Disable XML-RPC for locked IPs.
	 *
	 * Returning false here causes WP to emit an IXR fault (405) before parsing
	 * the request body, which prevents system.multicall from being used as a
	 * credential-stuffing amplifier. All XML-RPC methods are blocked for this IP.
	 * Legitimate Jetpack / app traffic from non-locked IPs is unaffected.
	 *
	 * Parameter untyped for the same reason as gate_allow_password_reset().
	 *
	 * @param mixed $enabled Whether XML-RPC is enabled (WP default true).
	 * @return bool
	 */
	public function gate_xmlrpc_enabled( $enabled = true ): bool {
		$ip = LoginArmor::get_client_ip();
		if ( self::is_locked_or_blacklisted( $ip ) ) {
			do_action( 'login_armor_ip_blocked', $ip, '', [ 'source' => 'xmlrpc' ] );
			return false;
		}
		return (bool) $enabled;
	}

	/**
	 * Short-circuit REST requests from locked IPs on user-leaking routes.
	 *
	 * Scope expanded in 2.0.5: previously only `/wp-json/wp/v2/users` was
	 * gated, which left the oEmbed API (`author_name`, `author_url`) wide
	 * open to a locked IP doing reconnaissance for the next attempt. The
	 * scope is now an explicit prefix list, so the rest of the REST API
	 * (gutenberg, block-editor, webhooks-inbound from plugins) keeps
	 * working for legitimate clients.
	 *
	 * 2.10.0: no longer registered. It read the route from the URL, and core
	 * also takes `rest_route` from the POST body, honours a method override and
	 * serves `_embed` and `batch/v1` sub-requests without running
	 * rest_authentication_errors again (Codex audit of 2.9.0, C01). The gate now
	 * runs on rest_pre_dispatch, see gate_rest_dispatch(). Kept public, with
	 * its URL reading, for a third party that calls it.
	 *
	 * @param \WP_Error|null|true $result Result so far (null = pass).
	 * @return \WP_Error|null|true
	 */
	public function gate_rest_authentication( $result = null ) {
		if ( ! empty( $result ) && ! is_bool( $result ) ) {
			// Another handler already rejected; don't override.
			return $result;
		}

		return $this->rest_gate( self::requested_rest_routes(), $result, false );
	}

	/**
	 * Refuse user-leaking routes to a locked or blocked address, per dispatch.
	 *
	 * rest_pre_dispatch runs for the main request and for every sub-request
	 * the REST server dispatches itself (`_embed`, `batch/v1`), with the route
	 * core really resolved: from the path, `?rest_route=` or the POST body,
	 * whatever the method override. By then core has already dropped the user
	 * of a cookie that came without a valid nonce.
	 *
	 * Untyped with defaults, like every callback on a core hook.
	 *
	 * @since 2.10.0
	 *
	 * @param mixed $result  Response so far; anything but null is passed on.
	 * @param mixed $server  REST server (unused).
	 * @param mixed $request The request about to be dispatched.
	 * @return mixed
	 */
	public function gate_rest_dispatch( $result = null, $server = null, $request = null ) {
		unset( $server );
		// Core dispatches unless the result is non-empty (dispatch() and the
		// batch loop both test empty()): a false or '' from an earlier filter
		// must not walk past the gate.
		if ( ! empty( $result ) || ! $request instanceof \WP_REST_Request ) {
			return $result;
		}
		// rest_do_request() outside a REST request (block-editor preloads,
		// server-side rendering) is the site talking to itself, as before.
		if ( function_exists( 'wp_is_serving_rest_request' ) && ! wp_is_serving_rest_request() ) {
			return $result;
		}

		$gated = $this->rest_gate( array( self::normalise_rest_route( (string) $request->get_route() ) ), $result, true );

		// A response, never a WP_Error: dispatch() converts an error returned
		// here, but the batch/v1 loop hands it to rest_post_dispatch and to
		// envelope_response(), which call response methods on it (fatal).
		return is_wp_error( $gated ) ? rest_convert_error_to_response( $gated ) : $gated;
	}

	/**
	 * Whether the address was already reported blocked by the REST gate in this request.
	 *
	 * One request can dispatch several protected routes (embedded authors):
	 * one `locked` row in the log, not one per author.
	 *
	 * @var bool
	 */
	private static bool $rest_block_reported = false;

	/**
	 * The gate itself, for a list of normalised routes.
	 *
	 * @param array<int,string> $routes Normalised routes this request reaches.
	 * @param mixed             $result Value to pass on when the gate stays open.
	 * @param bool              $once   Report the block once per request.
	 * @return mixed
	 */
	private function rest_gate( array $routes, $result, bool $once ) {
		// Closed list of REST route prefixes (without the URL prefix) that leak
		// user identity. `oembed/1.0` covers both `/embed` and `/proxy`.
		// 2.10.0: matched first. The gate now runs on every dispatch (each
		// embed, each batch item), and the lock check below is a query.
		$leaky_prefixes = [
			'/wp/v2/users',
			'/oembed/',
		];
		$matched = false;
		foreach ( $routes as $route ) {
			foreach ( $leaky_prefixes as $prefix ) {
				if ( 0 === strpos( $route, $prefix ) ) {
					$matched = true;
					break 2;
				}
			}
		}
		if ( ! $matched ) {
			return $result;
		}

		$ip = LoginArmor::get_client_ip();
		if ( ! self::is_locked_or_blacklisted( $ip ) ) {
			return $result;
		}

		// 2.9.0: an authenticated request is not the one this gate exists for.
		// A valid application password works from an address locked by the
		// automatic lockout (spec, decision 2), and so does a signed-in
		// administrator: refusing them users/me broke the block editor whenever
		// a script failed from the same address. A network the administrator
		// blocked by hand stays blocked, authenticated or not.
		if ( ! self::is_ip_in_blocked_subnet( $ip ) && self::rest_request_is_authenticated() ) {
			return $result;
		}

		if ( ! $once || ! self::$rest_block_reported ) {
			self::$rest_block_reported = $once;
			do_action( 'login_armor_ip_blocked', $ip, '', [ 'source' => 'rest' ] );
		}

		return new \WP_Error(
			'login_armor_rest_blocked',
			__( 'Access to this endpoint is temporarily restricted due to suspicious activity from your IP.', 'login-armor' ),
			[ 'status' => 403 ]
		);
	}

	/**
	 * REST routes this request may reach, normalised the way core matches them.
	 *
	 * Core serves a route from `?rest_route=` (plain permalinks) or from the
	 * path after the REST prefix, URL-decoded, and matches it case-insensitively.
	 * Both sources are returned, because a request can carry both and the gate
	 * must refuse if either one names a protected route. Each route starts with
	 * a single `/`, is lower-case and has no doubled slashes. Never
	 * sanitize_text_field() here: it strips every %XX sequence.
	 *
	 * @since 2.9.0
	 *
	 * @return array<int,string>
	 */
	public static function requested_rest_routes(): array {
		$routes = [];

		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Read-only routing inspection, not form processing.
		if ( isset( $_GET['rest_route'] ) && is_string( $_GET['rest_route'] ) ) {
			// phpcs:ignore WordPress.Security.NonceVerification.Recommended,WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Only compared to a closed prefix list; control characters stripped below.
			$routes[] = self::normalise_rest_route( wp_unslash( $_GET['rest_route'] ) );
		}

		$uri = isset( $_SERVER['REQUEST_URI'] ) && is_string( $_SERVER['REQUEST_URI'] )
			// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Only compared to a closed prefix list; control characters stripped below.
			? wp_unslash( $_SERVER['REQUEST_URI'] )
			: '';
		$qpos = strpos( $uri, '?' );
		$path = self::normalise_rest_route( false === $qpos ? $uri : substr( $uri, 0, $qpos ) );
		$pfx  = '/' . strtolower( trim( (string) rest_get_url_prefix(), '/' ) ) . '/';
		$pos  = strpos( $path . '/', $pfx );
		if ( false !== $pos ) {
			$routes[] = self::normalise_rest_route( substr( $path . '/', $pos + strlen( $pfx ) - 1 ) );
		}

		return $routes;
	}

	/**
	 * Decode, lower-case and tidy a REST route: leading single slash, no doubled slashes.
	 *
	 * @param string $route Raw route or path.
	 */
	private static function normalise_rest_route( string $route ): string {
		$route = strtolower( rawurldecode( $route ) );
		$route = (string) preg_replace( '/[\x00-\x1F\x7F]+/', '', $route );
		$route = (string) preg_replace( '#/+#', '/', $route );
		return '/' . ltrim( $route, '/' );
	}

	/**
	 * Whether this REST request carries an authentication core honours.
	 *
	 * The current user is already determined (WP::init() runs before the REST
	 * server). A logged-in cookie alone is not enough: without a valid
	 * wp_rest nonce, core's rest_cookie_check_errors (priority 100) treats the
	 * request as anonymous, and so does this gate.
	 *
	 * @since 2.9.0
	 */
	private static function rest_request_is_authenticated(): bool {
		if ( ! is_user_logged_in() ) {
			return false;
		}
		if ( function_exists( 'rest_get_authenticated_app_password' ) && null !== rest_get_authenticated_app_password() ) {
			return true;
		}
		$nonce = '';
		// Same order as core's rest_cookie_check_errors(): the query or body
		// parameter first, then the header.
		if ( isset( $_REQUEST['_wpnonce'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- This IS the nonce check.
			$nonce = sanitize_text_field( wp_unslash( $_REQUEST['_wpnonce'] ) );
		} elseif ( isset( $_SERVER['HTTP_X_WP_NONCE'] ) ) {
			$nonce = sanitize_text_field( wp_unslash( $_SERVER['HTTP_X_WP_NONCE'] ) );
		}
		return '' !== $nonce && false !== wp_verify_nonce( $nonce, 'wp_rest' );
	}
}
