<?php
/**
 * Login Logs module.
 *
 * Records all login events (success, failure, lockout) with metadata
 * and provides query methods for the admin dashboard.
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
 * Handles login activity logging and data retrieval.
 */
class LoginLogs {

	/** 2.9.0: rows of application-password failures kept per address and rolling hour. */
	public const APP_PASSWORD_HOURLY_CAP = 20;

	/** 2.9.0: reason of the one row written when the cap is reached. */
	public const APP_PASSWORD_THROTTLED = 'app_password_throttled';

	/** 2.9.0: refusals that say the feature is off, not that someone tried. */
	private const APP_PASSWORD_IGNORED = array( 'application_passwords_disabled', 'application_passwords_disabled_for_user' );

	/**
	 * Request-scoped flag raised by log_blocked(). Used to suppress the
	 * subsequent log_failure() that WordPress fires right after a
	 * WP_Error is returned from the `authenticate` filter, so one blocked
	 * attempt produces exactly one row ('locked') instead of two
	 * ('locked' + 'failed'). Fixed in 2.0.4 round 2 after beta feedback:
	 * 5 real attempts were showing up as 10 events in the incident.
	 *
	 * @var bool
	 */
	private bool $blocked_this_request = false;

	/**
	 * Constructor. Registers logging hooks.
	 */
	public function __construct() {
		if ( ! (bool) get_option( 'login_armor_detection_enabled', true ) ) {
			return;
		}

		add_action( 'wp_login', [ $this, 'log_success' ], 10, 2 );
		// Two args: WP 5.4+ passes the WP_Error as the second argument, which
		// carries the only authoritative statement of WHY the login failed.
		add_action( 'wp_login_failed', [ $this, 'log_failure' ], 10, 2 );
		add_action( 'login_armor_ip_blocked', [ $this, 'log_blocked' ], 10, 2 );
		// 2.9.0: application-password refusals, logged by their own path (core
		// fires no wp_login_failed for them outside the authenticate filter).
		add_action( 'application_password_failed_authentication', [ $this, 'log_app_password_failure' ], 10, 1 );
	}

	/**
	 * Log a successful login.
	 *
	 * Parameters untyped with defaults: many plugins re-fire `wp_login` with
	 * a single argument (the pre-WP-4.5 signature) or degraded types. When
	 * $user_login is unusable we fall back to the user object.
	 *
	 * @param mixed $user_login Username (expected string).
	 * @param mixed $user       User object (expected WP_User).
	 */
	public function log_success( $user_login = '', $user = null ): void {
		if ( ! is_string( $user_login ) || '' === $user_login ) {
			if ( ! $user instanceof \WP_User ) {
				return;
			}
			$user_login = $user->user_login;
		}
		$this->insert_log( $user_login, 'success' );
	}

	/**
	 * Log a failed login attempt.
	 *
	 * Parameters untyped with defaults: third-party plugins re-fire
	 * `wp_login_failed` manually, sometimes with null, sometimes with the
	 * pre-WP-5.4 single-argument signature (no WP_Error). Both cases degrade
	 * to an empty reason rather than fataling the login screen.
	 *
	 * @param mixed $username The attempted username (expected string).
	 * @param mixed $error    The authentication error (expected WP_Error).
	 */
	public function log_failure( $username = '', $error = null ): void {
		if ( ! is_string( $username ) ) {
			$username = '';
		}

		// V2.4.5: the real cause of the failure, straight from the WP_Error.
		$reason = self::error_code( $error );

		// When the `authenticate` filter has already short-circuited this
		// request via `check_lockout()`/subnet block, `log_blocked()` has
		// inserted a 'locked' row a few µs earlier: WordPress still fires
		// `wp_login_failed` afterwards, but logging it again as 'failed'
		// doubles every attempt past the lockout threshold and inflates
		// incident events_count (bug observed by beta tester: 5 real
		// attempts → 10 events reported). Skip in that exact case.
		// On the attempt that flips the IP to locked, `check_lockout` did
		// NOT fire `login_armor_ip_blocked` (the IP was still unlocked at
		// that point), so $blocked_this_request stays false and the row is
		// correctly recorded: preserving the v2.0.3 fix.
		if ( $this->blocked_this_request ) {
			return;
		}

		// v2.0.9 defensive classification (reported by beta tester 2026-04-19):
		// if the IP is currently locked AND the lockout was NOT triggered
		// by this very request, the correct classification is 'locked',
		// not 'failed'. This catches any edge case where `check_lockout`
		// ran but `login_armor_ip_blocked` was not fired (a custom auth
		// plugin short-circuiting the filter chain, a reverse-proxy IP
		// mismatch between the two points in the request, etc.). Without
		// this guard, such attempts surface in the Events tab as
		// "Mot de passe incorrect" right after a "Débit limité" row,
		// which misleads admins during incident triage.
		$ip = LoginArmor::get_client_ip();
		if ( LimitLogin::is_ip_locked( $ip ) && ! LimitLogin::was_lockout_just_triggered() ) {
			$this->insert_log( $username, 'locked', $ip, '' === $reason ? 'login_armor_locked_out' : $reason );
			return;
		}

		$this->insert_log( $username, 'failed', null, $reason );
	}

	/**
	 * Log an application-password refusal, under an hourly cap per address.
	 *
	 * Untyped with a default, like every callback on a core hook.
	 *
	 * @since 2.9.0
	 *
	 * @param mixed $error The authentication error (expected WP_Error).
	 */
	public function log_app_password_failure( $error = null ): void {
		if ( ! $error instanceof \WP_Error ) {
			return;
		}
		// Core also hooks wp_authenticate_application_password on `authenticate`
		// (XML-RPC, anything calling wp_authenticate()): there the same failure
		// reaches wp_login_failed and is logged by log_failure().
		if ( doing_filter( 'authenticate' ) ) {
			return;
		}
		$code = $error->get_error_code();
		if ( ! is_string( $code ) || '' === $code || in_array( $code, self::APP_PASSWORD_IGNORED, true ) ) {
			return;
		}

		$ip       = LoginArmor::get_client_ip();
		$username = LimitLogin::app_password_username();

		// 2.10.0 (Codex C02): count, decide and write as one step per address.
		// Concurrent refusals used to read the same count and all insert,
		// past the cap. Without the lock, nothing is inserted: the refusal is
		// added to the summary when there is one, and still counted toward the
		// lockout by LimitLogin, a separate path.
		if ( ! self::acquire_appfail_lock( $ip ) ) {
			self::bump_throttle( $ip );
			return;
		}
		try {
			switch ( self::app_password_log_decision( self::count_recent_app_password_rows( $ip ), self::has_active_summary( $ip ) ) ) {
				case 'count':
					self::bump_throttle( $ip );
					return;
				case 'summary':
					self::remember_summary_row( $ip, $this->insert_log( $username, 'failed', $ip, self::APP_PASSWORD_THROTTLED ) );
					return;
			}

			$status = ( LimitLogin::is_ip_locked( $ip ) && ! LimitLogin::was_lockout_just_triggered() ) ? 'locked' : 'failed';
			$this->insert_log( $username, $status, $ip, substr( 'app_password_' . $code, 0, 50 ) );
		} finally {
			self::release_appfail_lock( $ip );
		}
	}

	/**
	 * MySQL advisory lock of one address's application-password log rows.
	 *
	 * Shared by every PHP process on the database, unlike a transient. One
	 * second at most: a refusal is not worth holding a request longer.
	 *
	 * @since 2.10.0
	 */
	private static function acquire_appfail_lock( string $ip ): bool {
		global $wpdb;
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Advisory lock, not data.
		return 1 === (int) $wpdb->get_var( $wpdb->prepare( 'SELECT GET_LOCK(%s, %d)', self::appfail_lock_name( $ip ), 1 ) );
	}

	/** Release the lock taken by acquire_appfail_lock(). */
	private static function release_appfail_lock( string $ip ): void {
		global $wpdb;
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Advisory lock, not data.
		$wpdb->get_var( $wpdb->prepare( 'SELECT RELEASE_LOCK(%s)', self::appfail_lock_name( $ip ) ) );
	}

	/**
	 * Lock name of an address on this site: 43 characters, under MySQL's 64.
	 *
	 * Advisory locks are shared by the whole MySQL server: the database and
	 * the table prefix keep one site's lock from holding up another's.
	 */
	private static function appfail_lock_name( string $ip ): string {
		global $wpdb;
		$database = defined( 'DB_NAME' ) ? (string) DB_NAME : '';
		return 'la_appfail_' . substr( hash( 'sha256', $database . '|' . $wpdb->prefix . '|' . $ip ), 0, 32 );
	}

	/**
	 * What to do with one more application-password failure.
	 *
	 * @since 2.9.0
	 *
	 * Real rows are capped; the summary is written once per hour, whatever
	 * the real count (concurrent requests can overshoot the cap).
	 *
	 * @param int  $already     Real rows (summary rows excluded) logged for this address in the last hour.
	 * @param bool $has_summary Whether a summary row of this address is active.
	 * @return string 'log', 'summary' or 'count'.
	 */
	public static function app_password_log_decision( int $already, bool $has_summary = false ): string {
		if ( $already < self::APP_PASSWORD_HOURLY_CAP ) {
			return 'log';
		}
		return $has_summary ? 'count' : 'summary';
	}

	/** Whether the address has a summary row from the last hour. */
	private static function has_active_summary( string $ip ): bool {
		return (int) get_transient( self::throttle_key( $ip ) ) > 0;
	}

	/**
	 * Real application-password rows logged for an address in the last hour,
	 * summary rows excluded. Served by the `ip` index.
	 */
	private static function count_recent_app_password_rows( string $ip ): int {
		global $wpdb;
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Custom plugin table, real-time cap.
		return (int) $wpdb->get_var(
			$wpdb->prepare(
				"SELECT COUNT(*) FROM {$wpdb->prefix}login_armor_logs WHERE ip = %s AND reason LIKE %s AND reason <> %s AND log_time > DATE_SUB(UTC_TIMESTAMP(), INTERVAL 1 HOUR)",
				$ip,
				$wpdb->esc_like( 'app_password_' ) . '%',
				self::APP_PASSWORD_THROTTLED
			)
		);
	}

	/** Transient naming the summary row of an address, for one hour. */
	private static function throttle_key( string $ip ): string {
		return 'login_armor_appfail_last_' . substr( hash( 'sha256', $ip ), 0, 32 );
	}

	/**
	 * Remember which row summarises an address that reached the cap.
	 *
	 * @since 2.9.0
	 */
	public static function remember_summary_row( string $ip, int $log_id ): void {
		if ( $log_id > 0 ) {
			set_transient( self::throttle_key( $ip ), $log_id, HOUR_IN_SECONDS );
		}
	}

	/**
	 * Count one failure that was not logged, on the summary row of its address.
	 *
	 * @since 2.9.0
	 */
	public static function bump_throttle( string $ip ): void {
		$log_id = (int) get_transient( self::throttle_key( $ip ) );
		if ( $log_id <= 0 ) {
			return;
		}
		$key = 'login_armor_appfail_n_' . $log_id;
		set_transient( $key, (int) get_transient( $key ) + 1, 2 * DAY_IN_SECONDS );
	}

	/**
	 * Failures counted on a summary row and not logged.
	 *
	 * @since 2.9.0
	 */
	public static function throttled_count( int $log_id ): int {
		return (int) get_transient( 'login_armor_appfail_n_' . $log_id );
	}

	/**
	 * Human label for the error code stored on a failed login row.
	 *
	 * Before 2.4.5 every failure was rendered "Wrong password" whatever the
	 * cause, so a 2FA lockout or a browser blocking cookies looked exactly
	 * like a bad credential: the user report that produced this method
	 * (Jean-Pol, 2026-07-21). Rows written before the 2.4.5 migration carry an
	 * empty reason and keep the legacy generic label.
	 *
	 * Lives on the module rather than in a view helper because three tabs
	 * (Events, Overview, Incidents) render the same label and must not drift.
	 * The return value is plain text: callers still escape it.
	 *
	 * @param string $reason Stored error code ('' for pre-2.4.5 rows).
	 * @return string Translated label.
	 */
	public static function failure_reason_label( string $reason ): string {
		switch ( $reason ) {
			case '':
			case 'incorrect_password':
				return __( 'Wrong password', 'login-armor' );
			case 'invalid_username':
			case 'invalid_email':
				return __( 'Unknown account', 'login-armor' );
			case 'test_cookie':
				return __( 'Cookies blocked by the browser', 'login-armor' );
			case 'login_armor_locked_out':
			case 'login_armor_subnet_blocked':
				return __( 'Rate-limited', 'login-armor' );
			case 'login_armor_2fa_lockout':
			case 'login_armor_2fa_ip_lockout':
				return __( 'Blocked: too many failed 2FA checks', 'login-armor' );
			case 'login_armor_2fa_setup_required':
				return __( 'Blocked: mandatory 2FA not set up', 'login-armor' );
			case 'honeypot_caught':
				return __( 'Blocked: bot trap', 'login-armor' );
			case 'username_blacklisted':
				return __( 'Blocked: reserved username', 'login-armor' );
			case 'login_armor_pow_failed':
				return __( 'Blocked: bot challenge not solved', 'login-armor' );
			case 'app_password_incorrect_password':
				return __( 'Wrong application password', 'login-armor' );
			case 'app_password_invalid_username':
			case 'app_password_invalid_email':
				return __( 'Unknown account (application password)', 'login-armor' );
			case 'app_password_throttled':
				return __( 'Application password: hourly log limit reached', 'login-armor' );
		}

		if ( str_starts_with( $reason, 'app_password_' ) ) {
			return sprintf(
				/* translators: %s: error code returned by a third-party plugin. */
				__( 'Application password refused by another plugin (%s)', 'login-armor' ),
				substr( $reason, strlen( 'app_password_' ) )
			);
		}

		return sprintf(
			/* translators: %s: error code returned by a third-party plugin. */
			__( 'Refused by another plugin (%s)', 'login-armor' ),
			$reason
		);
	}

	/**
	 * Extract the error code from an authentication error, defensively.
	 *
	 * WordPress passes a WP_Error as the second argument of `wp_login_failed`
	 * since 5.4, but third-party re-fires may pass nothing, null, or a string.
	 * Anything we cannot read as a WP_Error yields an empty reason, which the
	 * Events tab renders with the legacy generic label.
	 *
	 * @param mixed $error Expected WP_Error.
	 * @return string Error code, or '' when unavailable.
	 */
	private static function error_code( $error = null ): string {
		if ( ! $error instanceof \WP_Error ) {
			return '';
		}
		$code = $error->get_error_code();
		if ( ! is_string( $code ) ) {
			return '';
		}
		return substr( $code, 0, 50 );
	}

	/**
	 * Log a blocked login attempt (IP was locked out).
	 *
	 * @param string $ip       The blocked IP address.
	 * @param string $username The attempted username.
	 */
	public function log_blocked( string $ip, string $username ): void {
		$this->blocked_this_request = true;
		$this->insert_log( $username, 'locked', $ip, 'login_armor_locked_out' );
	}

	/**
	 * Insert a log entry into the database.
	 *
	 * @param string      $username Username attempted.
	 * @param string      $status   Log status: success, failed, or locked.
	 * @param string|null $ip       IP address override. Defaults to auto-detection.
	 * @param string      $reason   Error code behind the failure ('' for successes).
	 * @return int Id of the new row, read before the hook below can insert another.
	 */
	private function insert_log( string $username, string $status, ?string $ip = null, string $reason = '' ): int {
		global $wpdb;

		$ip = $ip ?? LoginArmor::get_client_ip();

		$user_agent = isset( $_SERVER['HTTP_USER_AGENT'] )
			? substr( sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ), 0, 256 )
			: '';

		$data = [
			'ip'         => $ip,
			'username'   => sanitize_user( $username ),
			'log_time'   => current_time( 'mysql', true ),
			'status'     => $status,
			'user_agent' => $user_agent,
			'reason'     => sanitize_key( $reason ),
		];

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Custom plugin table, real-time audit log write.
		$inserted = $wpdb->insert( $wpdb->prefix . 'login_armor_logs', $data, [ '%s', '%s', '%s', '%s', '%s', '%s' ] );

		// 2.8.0: a refused write gets the same point-of-use repair as the AI
		// analysis (Incident::store_analysis()). Every row carries `reason`, so
		// a table that never received the 2.4.5 column, from a refused ALTER or
		// a half-restored backup, rejected EVERY login event, successes
		// included, and nothing said so. The repair runs at most once an hour
		// for the whole plugin, and the write is retried once after it.
		if ( false === $inserted && LoginArmor::repair_schema_once() ) {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Same write, retried after the schema repair.
			$wpdb->insert( $wpdb->prefix . 'login_armor_logs', $data, [ '%s', '%s', '%s', '%s', '%s', '%s' ] );
		}

		// Attach the request vector AFTER the insert: the login_armor_logs table
		// has no `vector` column (we don't widen the high-volume log table), but
		// downstream consumers (chiefly the Detection Classifier) read it off
		// the hook payload to stamp the incident with where the attack came from.
		$data['vector'] = self::detect_request_vector();
		$log_id         = (int) $wpdb->insert_id;

		/**
		 * Fires after a login event has been recorded in the activity log.
		 *
		 * @param string              $status  Log status: success, failed, or locked.
		 * @param array<string,mixed> $data    The log row data, plus a 'vector' key
		 *                                     ('login_form'|'xmlrpc'|'rest') not stored in the table.
		 * @param int                 $log_id  Auto-increment ID of the new log row.
		 */
		do_action( 'login_armor_log_recorded', $status, $data, $log_id );

		return $log_id;
	}

	/**
	 * Detect the entry point of the current authentication request.
	 *
	 * Hide Login only masks wp-login.php; XML-RPC and the REST API are separate
	 * endpoints that still reach `wp_authenticate`, so labelling the vector lets
	 * the Detection engine surface "these attacks bypass your hidden login URL".
	 *
	 * @return string One of Incident::VECTOR_* values.
	 */
	private static function detect_request_vector(): string {
		if ( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST ) {
			return 'xmlrpc';
		}
		if ( defined( 'REST_REQUEST' ) && REST_REQUEST ) {
			return 'rest';
		}
		return 'login_form';
	}

	/**
	 * Get paginated log entries with optional filters.
	 *
	 * @param int    $page     Page number (1-based).
	 * @param int    $per_page Items per page.
	 * @param string $status   Filter by status: success, failed, locked, or empty for all.
	 * @param string $period   Filter by period: today, 7days, 30days, or empty for all.
	 * @return array{logs: array<object>, total: int, pages: int, page: int}
	 */
	public static function get_logs( int $page = 1, int $per_page = 20, string $status = '', string $period = '' ): array {
		$status_valid = in_array( $status, [ 'success', 'failed', 'locked' ], true );
		$status_arg   = $status_valid ? $status : '';

		$total  = self::query_count( $status_arg, $period );
		$offset = max( 0, ( $page - 1 ) * $per_page );
		$rows   = self::query_rows( $status_arg, $period, $per_page, $offset );

		return [
			'logs'  => $rows,
			'total' => $total,
			'pages' => $per_page > 0 ? (int) ceil( $total / $per_page ) : 0,
			'page'  => $page,
		];
	}

	/**
	 * Run the COUNT query for the log list with optional status/period filters.
	 *
	 * Each (status, period) combination has its own prepared statement so PCP
	 * can statically validate placeholder counts.
	 *
	 * @param string $status Validated status value or empty.
	 * @param string $period Period key: today, 7days, 30days, or empty.
	 */
	private static function query_count( string $status, string $period ): int {
		global $wpdb;

		// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
		if ( $status !== '' && $period === 'today' ) {
			return (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM {$wpdb->prefix}login_armor_logs WHERE status = %s AND log_time >= %s", $status, gmdate( 'Y-m-d 00:00:00' ) ) );
		}
		if ( $status !== '' && $period === '7days' ) {
			return (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM {$wpdb->prefix}login_armor_logs WHERE status = %s AND log_time > DATE_SUB(UTC_TIMESTAMP(), INTERVAL %d DAY)", $status, 7 ) );
		}
		if ( $status !== '' && $period === '30days' ) {
			return (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM {$wpdb->prefix}login_armor_logs WHERE status = %s AND log_time > DATE_SUB(UTC_TIMESTAMP(), INTERVAL %d DAY)", $status, 30 ) );
		}
		if ( $status !== '' ) {
			return (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM {$wpdb->prefix}login_armor_logs WHERE status = %s", $status ) );
		}
		if ( $period === 'today' ) {
			return (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM {$wpdb->prefix}login_armor_logs WHERE log_time >= %s", gmdate( 'Y-m-d 00:00:00' ) ) );
		}
		if ( $period === '7days' ) {
			return (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM {$wpdb->prefix}login_armor_logs WHERE log_time > DATE_SUB(UTC_TIMESTAMP(), INTERVAL %d DAY)", 7 ) );
		}
		if ( $period === '30days' ) {
			return (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM {$wpdb->prefix}login_armor_logs WHERE log_time > DATE_SUB(UTC_TIMESTAMP(), INTERVAL %d DAY)", 30 ) );
		}
		return (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$wpdb->prefix}login_armor_logs" );
		// phpcs:enable
	}

	/**
	 * Run the paginated SELECT for the log list with optional status/period filters.
	 *
	 * @param string $status   Validated status value or empty.
	 * @param string $period   Period key: today, 7days, 30days, or empty.
	 * @param int    $per_page Row limit.
	 * @param int    $offset   Row offset.
	 * @return array<object>
	 */
	private static function query_rows( string $status, string $period, int $per_page, int $offset ): array {
		global $wpdb;

		// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
		if ( $status !== '' && $period === 'today' ) {
			$rows = $wpdb->get_results( $wpdb->prepare( "SELECT * FROM {$wpdb->prefix}login_armor_logs WHERE status = %s AND log_time >= %s ORDER BY log_time DESC LIMIT %d OFFSET %d", $status, gmdate( 'Y-m-d 00:00:00' ), $per_page, $offset ) );
		} elseif ( $status !== '' && $period === '7days' ) {
			$rows = $wpdb->get_results( $wpdb->prepare( "SELECT * FROM {$wpdb->prefix}login_armor_logs WHERE status = %s AND log_time > DATE_SUB(UTC_TIMESTAMP(), INTERVAL %d DAY) ORDER BY log_time DESC LIMIT %d OFFSET %d", $status, 7, $per_page, $offset ) );
		} elseif ( $status !== '' && $period === '30days' ) {
			$rows = $wpdb->get_results( $wpdb->prepare( "SELECT * FROM {$wpdb->prefix}login_armor_logs WHERE status = %s AND log_time > DATE_SUB(UTC_TIMESTAMP(), INTERVAL %d DAY) ORDER BY log_time DESC LIMIT %d OFFSET %d", $status, 30, $per_page, $offset ) );
		} elseif ( $status !== '' ) {
			$rows = $wpdb->get_results( $wpdb->prepare( "SELECT * FROM {$wpdb->prefix}login_armor_logs WHERE status = %s ORDER BY log_time DESC LIMIT %d OFFSET %d", $status, $per_page, $offset ) );
		} elseif ( $period === 'today' ) {
			$rows = $wpdb->get_results( $wpdb->prepare( "SELECT * FROM {$wpdb->prefix}login_armor_logs WHERE log_time >= %s ORDER BY log_time DESC LIMIT %d OFFSET %d", gmdate( 'Y-m-d 00:00:00' ), $per_page, $offset ) );
		} elseif ( $period === '7days' ) {
			$rows = $wpdb->get_results( $wpdb->prepare( "SELECT * FROM {$wpdb->prefix}login_armor_logs WHERE log_time > DATE_SUB(UTC_TIMESTAMP(), INTERVAL %d DAY) ORDER BY log_time DESC LIMIT %d OFFSET %d", 7, $per_page, $offset ) );
		} elseif ( $period === '30days' ) {
			$rows = $wpdb->get_results( $wpdb->prepare( "SELECT * FROM {$wpdb->prefix}login_armor_logs WHERE log_time > DATE_SUB(UTC_TIMESTAMP(), INTERVAL %d DAY) ORDER BY log_time DESC LIMIT %d OFFSET %d", 30, $per_page, $offset ) );
		} else {
			$rows = $wpdb->get_results( $wpdb->prepare( "SELECT * FROM {$wpdb->prefix}login_armor_logs ORDER BY log_time DESC LIMIT %d OFFSET %d", $per_page, $offset ) );
		}
		// phpcs:enable

		return is_array( $rows ) ? $rows : [];
	}

	/**
	 * Get dashboard statistics.
	 *
	 * @return array{failed_today: int, locked_ips: int, success_7days: int}
	 */
	public static function get_stats(): array {
		global $wpdb;

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Custom plugin table, real-time dashboard stats.
		$failed_today = (int) $wpdb->get_var(
			$wpdb->prepare(
				"SELECT COUNT(*) FROM {$wpdb->prefix}login_armor_logs WHERE status = %s AND log_time >= %s",
				'failed',
				gmdate( 'Y-m-d 00:00:00' )
			)
		);

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Custom plugin table, real-time dashboard stats.
		$success_7days = (int) $wpdb->get_var(
			$wpdb->prepare(
				"SELECT COUNT(*) FROM {$wpdb->prefix}login_armor_logs WHERE status = %s AND log_time > DATE_SUB(UTC_TIMESTAMP(), INTERVAL %d DAY)",
				'success',
				7
			)
		);

		return [
			'failed_today'  => $failed_today,
			'locked_ips'    => LimitLogin::get_locked_ips_count(),
			'success_7days' => $success_7days,
		];
	}

	/**
	 * Get daily failed attempt counts for charting.
	 *
	 * @param int $days Number of days to include.
	 * @return array<string, int> Associative array of date => count.
	 */
	public static function get_daily_chart_data( int $days = 30 ): array {
		global $wpdb;

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Custom plugin table, chart dataset, fixed 30-day window.
		$results = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT DATE(log_time) as log_date, COUNT(*) as total
				 FROM {$wpdb->prefix}login_armor_logs
				 WHERE status IN ('failed', 'locked')
				 AND log_time > DATE_SUB(UTC_TIMESTAMP(), INTERVAL %d DAY)
				 GROUP BY DATE(log_time)
				 ORDER BY log_date ASC",
				$days
			)
		);

		// Build a complete date range with zeros for missing days.
		$data = [];
		for ( $i = $days - 1; $i >= 0; $i-- ) {
			$date          = gmdate( 'Y-m-d', time() - $i * DAY_IN_SECONDS );
			$data[ $date ] = 0;
		}

		if ( $results ) {
			foreach ( $results as $row ) {
				if ( isset( $data[ $row->log_date ] ) ) {
					$data[ $row->log_date ] = (int) $row->total;
				}
			}
		}

		return $data;
	}

	/**
	 * Delete logs older than a given number of days.
	 *
	 * @param int $days Number of days to retain.
	 * @return int Number of deleted rows.
	 */
	public static function purge_logs( int $days ): int {
		global $wpdb;

		$cutoff = gmdate( 'Y-m-d H:i:s', time() - $days * DAY_IN_SECONDS );

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Custom plugin table, retention-based cleanup.
		return (int) $wpdb->query(
			$wpdb->prepare(
				"DELETE FROM {$wpdb->prefix}login_armor_logs WHERE log_time < %s",
				$cutoff
			)
		);
	}

	/**
	 * Delete all logs.
	 *
	 * @return int Number of deleted rows.
	 */
	public static function purge_all_logs(): int {
		global $wpdb;

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Custom plugin table, explicit admin purge action.
		return (int) $wpdb->query( "DELETE FROM {$wpdb->prefix}login_armor_logs" );
	}

	/**
	 * Filtered paginated log query for the Events tab.
	 *
	 * @param array<string,mixed> $filters Accepted keys: status, ip, username, period, source.
	 * @param int                 $limit   Max rows.
	 * @param int                 $offset  Offset.
	 * @return array<int,object>
	 */
	public static function get_filtered_logs( array $filters, int $limit = 50, int $offset = 0 ): array {
		global $wpdb;
		list( $where, $params ) = self::build_logs_where( $filters );
		$params[] = $limit;
		$params[] = $offset;

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.InterpolatedNotPrepared,WordPress.DB.PreparedSQL.NotPrepared,WordPress.DB.PreparedSQLPlaceholders.ReplacementsWrongNumber,WordPress.DB.PreparedSQLPlaceholders.UnfinishedPrepare,PluginCheck.Security.DirectDB.UnescapedDBParameter -- $where built from a validated whitelist in build_logs_where(); all user values go through %s/%d placeholders in $params passed as array, Plugin Check cannot statically count them.
		$rows = $wpdb->get_results( $wpdb->prepare( "SELECT id, ip, username, status, log_time, user_agent, reason FROM {$wpdb->prefix}login_armor_logs WHERE {$where} ORDER BY log_time DESC LIMIT %d OFFSET %d", $params ) );
		return is_array( $rows ) ? $rows : array();
	}

	/**
	 * Count matching rows for the same filter set as `get_filtered_logs()`.
	 *
	 * @param array<string,mixed> $filters Accepted keys: status, ip, username, period, source.
	 */
	public static function count_filtered_logs( array $filters ): int {
		global $wpdb;
		list( $where, $params ) = self::build_logs_where( $filters );

		if ( empty( $params ) ) {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Custom plugin table, full count.
			return (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$wpdb->prefix}login_armor_logs" );
		}
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.InterpolatedNotPrepared,WordPress.DB.PreparedSQL.NotPrepared,WordPress.DB.PreparedSQLPlaceholders.ReplacementsWrongNumber,WordPress.DB.PreparedSQLPlaceholders.UnfinishedPrepare,PluginCheck.Security.DirectDB.UnescapedDBParameter -- $where built from a validated whitelist in build_logs_where(); all user values go through %s/%d placeholders in $params passed as array, Plugin Check cannot statically count them.
		return (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM {$wpdb->prefix}login_armor_logs WHERE {$where}", $params ) );
	}

	/**
	 * Build a parameterised WHERE clause from a user filter array.
	 *
	 * @param array<string,mixed> $filters
	 * @return array{0:string,1:array<int,mixed>}
	 */
	private static function build_logs_where( array $filters ): array {
		global $wpdb;
		$clauses = array( '1=1' );
		$params  = array();

		$allowed_statuses = array( 'success', 'failed', 'locked' );

		if ( ! empty( $filters['status'] ) && in_array( $filters['status'], $allowed_statuses, true ) ) {
			$clauses[] = 'status = %s';
			$params[]  = $filters['status'];
		}
		if ( ! empty( $filters['ip'] ) && filter_var( $filters['ip'], FILTER_VALIDATE_IP ) ) {
			$clauses[] = 'ip = %s';
			$params[]  = $filters['ip'];
		}
		if ( ! empty( $filters['username'] ) ) {
			$clauses[] = 'username LIKE %s';
			$params[]  = '%' . $wpdb->esc_like( (string) $filters['username'] ) . '%';
		}
		if ( ! empty( $filters['period'] ) ) {
			$hours = 0;
			if ( '24h' === $filters['period'] ) {
				$hours = 24;
			} elseif ( '7d' === $filters['period'] ) {
				$hours = 168;
			} elseif ( '30d' === $filters['period'] ) {
				$hours = 720;
			}
			if ( $hours > 0 ) {
				$clauses[] = 'log_time > DATE_SUB(UTC_TIMESTAMP(), INTERVAL %d HOUR)';
				$params[]  = $hours;
			}
		}
		// 2.9.0: where the attempt came from. Application-password rows carry
		// the app_password_ prefix in their reason; everything else is the
		// login form (XML-RPC and REST logins go through it too).
		if ( ! empty( $filters['source'] ) ) {
			if ( 'app_password' === $filters['source'] ) {
				$clauses[] = 'reason LIKE %s';
				$params[]  = $wpdb->esc_like( 'app_password_' ) . '%';
			} elseif ( 'login_form' === $filters['source'] ) {
				$clauses[] = 'reason NOT LIKE %s';
				$params[]  = $wpdb->esc_like( 'app_password_' ) . '%';
			}
		}

		return array( implode( ' AND ', $clauses ), $params );
	}

	/**
	 * Stream all matching log rows as CSV to php://output.
	 * Caller is responsible for sending headers and terminating the request.
	 *
	 * @param array<string,mixed> $filters Accepted keys: status, ip, username, period, source.
	 */
	public static function export_csv_stream( array $filters ): void {
		global $wpdb;
		list( $where, $base_params ) = self::build_logs_where( $filters );

		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fopen -- Streaming to php://output, WP_Filesystem does not support this.
		$handle = fopen( 'php://output', 'w' );
		if ( false === $handle ) {
			return;
		}

		fputcsv( $handle, array( 'id', 'log_time_utc', 'status', 'reason', 'ip', 'username', 'user_agent' ) );

		$batch_size = 500;
		$offset     = 0;
		while ( true ) {
			$batch_params   = $base_params;
			$batch_params[] = $batch_size;
			$batch_params[] = $offset;

			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.InterpolatedNotPrepared,WordPress.DB.PreparedSQL.NotPrepared,WordPress.DB.PreparedSQLPlaceholders.ReplacementsWrongNumber,WordPress.DB.PreparedSQLPlaceholders.UnfinishedPrepare,PluginCheck.Security.DirectDB.UnescapedDBParameter -- $where built from a validated whitelist in build_logs_where(); all user values go through %s/%d placeholders in $batch_params passed as array.
			$rows = $wpdb->get_results( $wpdb->prepare( "SELECT id, log_time, status, reason, ip, username, user_agent FROM {$wpdb->prefix}login_armor_logs WHERE {$where} ORDER BY log_time ASC LIMIT %d OFFSET %d", $batch_params ) );

			if ( empty( $rows ) ) {
				break;
			}
			foreach ( $rows as $row ) {
				fputcsv(
					$handle,
					array(
						(int) $row->id,
						(string) $row->log_time,
						(string) $row->status,
						\LoginArmor\Support\Csv::neutralize_field( $row->reason ),
						(string) $row->ip,
						\LoginArmor\Support\Csv::neutralize_field( $row->username ),
						\LoginArmor\Support\Csv::neutralize_field( $row->user_agent ),
					)
				);
			}
			if ( count( $rows ) < $batch_size ) {
				break;
			}
			$offset += $batch_size;
		}

		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose -- Streaming to php://output, WP_Filesystem does not support this.
		fclose( $handle );
	}
}
