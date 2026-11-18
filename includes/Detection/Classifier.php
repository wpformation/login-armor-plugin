<?php
/**
 * Detection Classifier for LoginArmor.
 *
 * Subscribes to login_armor_log_recorded, applies 6 deterministic pattern
 * rules against a sliding window of recent events, and creates or updates
 * incidents accordingly. Fires login_armor_incident_created on every new
 * or updated incident.
 *
 * @package LoginArmor
 * @since   2.0.0
 */

namespace LoginArmor\Detection;

// Exit if accessed directly.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Deterministic rule-based login attack classifier.
 */
class Classifier {

	/** @var int Short window used for most rules, in minutes. */
	public const WINDOW_MINUTES_SHORT = 10;

	/** @var int Long window for distributed patterns. */
	public const WINDOW_MINUTES_LONG = 30;

	/** @var int Window for post-compromise detection. */
	public const WINDOW_MINUTES_COMPROMISE = 60;

	/** @var int Brute force threshold: ≥ this many failed attempts on same-user dominance. */
	public const THRESHOLD_BRUTE_FORCE = 5;

	/** @var float Brute force dominance ratio: ≥ this fraction must target same username. */
	public const RATIO_BRUTE_FORCE = 0.8;

	/** @var int Credential stuffing threshold: ≥ this many unique usernames from one IP. */
	public const THRESHOLD_CREDENTIAL_STUFFING = 5;

	/** @var int Enumeration threshold: ≥ this many invalid_username attempts from one IP. */
	public const THRESHOLD_ENUMERATION = 3;

	/** @var int Distributed threshold: ≥ this many unique IPs targeting one username. */
	public const THRESHOLD_DISTRIBUTED = 5;

	/** @var int Post-compromise threshold: ≥ this many failures before a success. */
	public const THRESHOLD_POST_COMPROMISE = 3;

	/**
	 * 2.9.0: the failures every existing rule counts.
	 *
	 * A wrong application password says that a SERVICE holds a revoked or
	 * changed password, not that someone guesses: it matched brute_force and,
	 * once the owner signed in from the same address, post_compromise at
	 * critical severity. Those rows, the summary row of the hourly cap and
	 * third-party refusals leave the metrics; unknown accounts stay, they are
	 * a probe. `%%` because the fragment is part of a prepare() template; the
	 * unescaped `_` of LIKE matches itself here, no other reason shares the
	 * prefix.
	 */
	public const COUNTED_REASONS_SQL = "( reason NOT LIKE 'app_password_%%' OR reason IN ('" . self::REASON_APP_PASSWORD_INVALID_USERNAME . "','" . self::REASON_APP_PASSWORD_INVALID_EMAIL . "') )";

	/** 2.9.0: unknown-account reasons of an application-password failure, the only ones the rules still count. Single source of COUNTED_REASONS_SQL and of is_counted_reason(). */
	public const REASON_APP_PASSWORD_INVALID_USERNAME = 'app_password_invalid_username';
	public const REASON_APP_PASSWORD_INVALID_EMAIL    = 'app_password_invalid_email';

	/** 2.9.0: wrong application passwords on one login, from one address, in the short window. */
	public const THRESHOLD_APP_PASSWORD_REFUSED = 5;

	/**
	 * Entry point of the event currently being classified: request-scoped so
	 * upsert_incident() can stamp the incident without threading it through
	 * every rule signature. Reset on each on_log_recorded() call.
	 *
	 * @var string One of Incident::VECTOR_* values.
	 */
	private string $current_vector = Incident::VECTOR_LOGIN_FORM;

	/**
	 * Constructor. Subscribes to the log recording hook.
	 */
	public function __construct() {
		if ( ! (bool) get_option( 'login_armor_detection_enabled', true ) ) {
			return;
		}

		add_action( 'login_armor_log_recorded', array( $this, 'on_log_recorded' ), 10, 3 );

		// A lockout is itself decisive evidence of a brute-force attack, even
		// when the windowed failure count in the logs table sits below the
		// brute_force threshold (the lockout counter lives in a separate
		// table, so the two can diverge). Surface every lockout as an
		// incident so a blocked IP is never invisible on the Incidents tab.
		add_action( 'login_armor_lockout_triggered', array( $this, 'on_lockout' ), 10, 1 );
	}

	/**
	 * Create or raise a brute-force incident the moment an IP is locked out.
	 * Bypasses the windowed threshold because the lockout has already decided
	 * the IP is hostile.
	 *
	 * @param string $ip The IP that was just locked out.
	 */
	public function on_lockout( string $ip ): void {
		$ip = trim( (string) $ip );
		if ( '' === $ip ) {
			return;
		}

		global $wpdb;
		// Most recent username this IP attempted, for targeting/severity.
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Custom plugin table, single windowed lookup.
		$username = (string) $wpdb->get_var(
			$wpdb->prepare(
				"SELECT username FROM {$wpdb->prefix}login_armor_logs WHERE ip = %s AND status IN ('failed','locked') AND " . self::COUNTED_REASONS_SQL . " AND username <> '' ORDER BY log_time DESC LIMIT 1", // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared -- COUNTED_REASONS_SQL is a class constant, no input reaches it.
				$ip
			)
		);

		$this->current_vector = Incident::VECTOR_LOGIN_FORM;

		$metrics = $this->collect_metrics( $ip, $username );

		// The lockout fires at `allowed_retries` failures; the logs table may
		// show fewer rows than LimitLogin's own counter, so floor the event
		// count at the lockout threshold for an accurate-looking incident.
		$allowed             = (int) get_option( 'login_armor_allowed_retries', 4 );
		$metrics['ip_total'] = max( $metrics['ip_total'], $allowed );
		if ( '' !== $username ) {
			$metrics['ip_same_username'] = max( $metrics['ip_same_username'], $metrics['ip_total'] );
		}

		$severity = ( '' !== $username && $this->is_targeted( $username ) )
			? Incident::SEVERITY_HIGH
			: Incident::SEVERITY_MEDIUM;

		$this->upsert_incident( Incident::PATTERN_BRUTE_FORCE, 'ip', $ip, $ip, $username, $metrics, $severity );
	}

	/**
	 * Hook callback: dispatches classification on every new log row.
	 *
	 * @param string              $status Log status: success, failed, locked.
	 * @param array<string,mixed> $data   Row data (ip, username, log_time, status, user_agent).
	 * @param int                 $log_id Auto-increment ID.
	 */
	public function on_log_recorded( string $status, array $data, int $log_id ): void {
		unset( $log_id );
		$ip       = isset( $data['ip'] ) ? (string) $data['ip'] : '';
		$username = isset( $data['username'] ) ? (string) $data['username'] : '';
		// Where this attempt came in (login_form / xmlrpc / rest). Stamped onto
		// any incident this event creates or updates via upsert_incident().
		$this->current_vector = isset( $data['vector'] ) ? (string) $data['vector'] : Incident::VECTOR_LOGIN_FORM;
		if ( '' === $ip ) {
			return;
		}
		// 2.9.0: an application-password refusal never reaches the attack
		// rules: classify() would add its events to an open brute_force or
		// distributed incident, stamp it with the REST vector, or open a new
		// one after the administrator resolved it. Only its own rule runs.
		$reason = isset( $data['reason'] ) ? (string) $data['reason'] : '';
		if ( ! self::is_counted_reason( $reason ) ) {
			if ( 'app_password_incorrect_password' === $reason ) {
				$this->check_app_password_refused( $ip, $username );
			}
			return;
		}
		$this->classify( $ip, $username, $status );
	}

	/**
	 * PHP twin of COUNTED_REASONS_SQL: whether a log row feeds the attack rules.
	 *
	 * @since 2.9.0
	 *
	 * @param string $reason The `reason` of the log row.
	 */
	public static function is_counted_reason( string $reason ): bool {
		return ! str_starts_with( $reason, 'app_password_' )
			|| self::REASON_APP_PASSWORD_INVALID_USERNAME === $reason
			|| self::REASON_APP_PASSWORD_INVALID_EMAIL === $reason;
	}

	/**
	 * Main classification entry point. Evaluates rules in order and creates
	 * or updates incidents as appropriate. Multiple rules can match the same
	 * event (e.g. brute_force + targeted severity bump).
	 *
	 * @param string $ip       Client IP.
	 * @param string $username Attempted username.
	 * @param string $status   Log status: success, failed, locked.
	 */
	public function classify( string $ip, string $username, string $status ): void {
		// Post-compromise: only runs on success events.
		if ( 'success' === $status ) {
			$this->check_post_compromise( $ip, $username );
			return;
		}

		// Only failed and locked events drive attack pattern detection.
		if ( 'failed' !== $status && 'locked' !== $status ) {
			return;
		}

		$metrics = $this->collect_metrics( $ip, $username );

		// Evaluate each rule. Each may or may not create/update an incident.
		$this->check_brute_force( $ip, $username, $metrics );
		$this->check_credential_stuffing( $ip, $metrics );
		$this->check_enumeration( $ip, $username, $metrics );
		$this->check_distributed( $username, $metrics );
	}

	/**
	 * Query the login_armor_logs table for sliding-window metrics used by rules.
	 *
	 * @param string $ip       Client IP.
	 * @param string $username Attempted username.
	 * @return array{ip_total:int, ip_unique_usernames:int, ip_same_username:int, distinct_ips_on_username:int, invalid_user_from_ip:int}
	 */
	private function collect_metrics( string $ip, string $username ): array {
		global $wpdb;

		// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching

		$ip_total = (int) $wpdb->get_var(
			$wpdb->prepare(
				"SELECT COUNT(*) FROM {$wpdb->prefix}login_armor_logs WHERE ip = %s AND status IN ('failed','locked') AND " . self::COUNTED_REASONS_SQL . " AND log_time > DATE_SUB(UTC_TIMESTAMP(), INTERVAL %d MINUTE)", // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared -- COUNTED_REASONS_SQL is a class constant, no input reaches it.
				$ip,
				self::WINDOW_MINUTES_SHORT
			)
		);

		$ip_unique_usernames = (int) $wpdb->get_var(
			$wpdb->prepare(
				"SELECT COUNT(DISTINCT username) FROM {$wpdb->prefix}login_armor_logs WHERE ip = %s AND status IN ('failed','locked') AND " . self::COUNTED_REASONS_SQL . " AND log_time > DATE_SUB(UTC_TIMESTAMP(), INTERVAL %d MINUTE)", // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared -- COUNTED_REASONS_SQL is a class constant, no input reaches it.
				$ip,
				self::WINDOW_MINUTES_SHORT
			)
		);

		$ip_same_username = (int) $wpdb->get_var(
			$wpdb->prepare(
				"SELECT COUNT(*) FROM {$wpdb->prefix}login_armor_logs WHERE ip = %s AND username = %s AND status IN ('failed','locked') AND " . self::COUNTED_REASONS_SQL . " AND log_time > DATE_SUB(UTC_TIMESTAMP(), INTERVAL %d MINUTE)", // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared -- COUNTED_REASONS_SQL is a class constant, no input reaches it.
				$ip,
				$username,
				self::WINDOW_MINUTES_SHORT
			)
		);

		$distinct_ips_on_username = '' === $username ? 0 : (int) $wpdb->get_var(
			$wpdb->prepare(
				"SELECT COUNT(DISTINCT ip) FROM {$wpdb->prefix}login_armor_logs WHERE username = %s AND status IN ('failed','locked') AND " . self::COUNTED_REASONS_SQL . " AND log_time > DATE_SUB(UTC_TIMESTAMP(), INTERVAL %d MINUTE)", // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared -- COUNTED_REASONS_SQL is a class constant, no input reaches it.
				$username,
				self::WINDOW_MINUTES_LONG
			)
		);
		// phpcs:enable

		// Rough proxy for invalid-username attempts from this IP: when the
		// current username does not correspond to a real user, we assume the
		// recent failures from the same IP follow the same enumeration pattern.
		$invalid_user_from_ip = 0;
		if ( '' !== $username && ! get_user_by( 'login', $username ) ) {
			$invalid_user_from_ip = $ip_total;
		}

		return array(
			'ip_total'                 => $ip_total,
			'ip_unique_usernames'      => $ip_unique_usernames,
			'ip_same_username'         => $ip_same_username,
			'distinct_ips_on_username' => $distinct_ips_on_username,
			'invalid_user_from_ip'     => $invalid_user_from_ip,
		);
	}

	/**
	 * Rule: brute_force = 1 IP, ≥5 failures, ≥80% on same username.
	 *
	 * @param string                                                                                                                  $ip       Client IP.
	 * @param string                                                                                                                  $username Attempted username.
	 * @param array{ip_total:int, ip_unique_usernames:int, ip_same_username:int, distinct_ips_on_username:int, invalid_user_from_ip:int} $metrics  Snapshot.
	 */
	private function check_brute_force( string $ip, string $username, array $metrics ): void {
		if ( $metrics['ip_total'] < self::THRESHOLD_BRUTE_FORCE ) {
			return;
		}
		if ( $metrics['ip_total'] > 0 && ( $metrics['ip_same_username'] / $metrics['ip_total'] ) < self::RATIO_BRUTE_FORCE ) {
			return;
		}
		if ( '' === $username ) {
			return;
		}
		$severity = $this->is_targeted( $username ) ? Incident::SEVERITY_HIGH : Incident::SEVERITY_MEDIUM;

		// Phase progression: an enumeration incident from the early attempts
		// (threshold 3, before brute_force's threshold 5) describes the same
		// attack. Two things to do: inherit its started_at so the brute_force
		// window covers the full run (not just from attempt #5 onwards), then
		// auto-resolve it so the Open panel shows one incident per attack.
		$existing_enum  = Incident::find_active( Incident::PATTERN_ENUMERATION, $ip, 'ip' );
		$inherited_from = ( $existing_enum instanceof Incident && $existing_enum->id > 0 )
			? $existing_enum->started_at
			: null;

		$this->upsert_incident( Incident::PATTERN_BRUTE_FORCE, 'ip', $ip, $ip, $username, $metrics, $severity, $inherited_from );

		if ( $existing_enum instanceof Incident && $existing_enum->id > 0 ) {
			Incident::resolve( $existing_enum->id );
		}
	}

	/**
	 * Rule: credential_stuffing = 1 IP, ≥5 unique usernames in short window.
	 *
	 * @param string                                                                                                                  $ip      Client IP.
	 * @param array{ip_total:int, ip_unique_usernames:int, ip_same_username:int, distinct_ips_on_username:int, invalid_user_from_ip:int} $metrics Snapshot.
	 */
	private function check_credential_stuffing( string $ip, array $metrics ): void {
		if ( $metrics['ip_unique_usernames'] < self::THRESHOLD_CREDENTIAL_STUFFING ) {
			return;
		}
		$this->upsert_incident( Incident::PATTERN_CREDENTIAL_STUFFING, 'ip', $ip, $ip, '', $metrics, Incident::SEVERITY_HIGH );
	}

	/**
	 * Rule: enumeration = 1 IP, ≥3 attempts on nonexistent users in short window.
	 *
	 * @param string                                                                                                                  $ip       Client IP.
	 * @param string                                                                                                                  $username Attempted username.
	 * @param array{ip_total:int, ip_unique_usernames:int, ip_same_username:int, distinct_ips_on_username:int, invalid_user_from_ip:int} $metrics  Snapshot.
	 */
	private function check_enumeration( string $ip, string $username, array $metrics ): void {
		if ( '' === $username ) {
			return;
		}
		if ( get_user_by( 'login', $username ) ) {
			return;
		}
		if ( $metrics['invalid_user_from_ip'] < self::THRESHOLD_ENUMERATION ) {
			return;
		}

		// Don't double up with brute_force / credential_stuffing on the same
		// snapshot: those are strictly more specific labels and will have
		// fired in the same classify() pass. Enumeration is the fallback
		// "fishing for usernames" pattern, reserved for runs that don't
		// match a higher-specificity rule.
		if (
			$metrics['ip_total'] >= self::THRESHOLD_BRUTE_FORCE
			&& $metrics['ip_total'] > 0
			&& ( $metrics['ip_same_username'] / $metrics['ip_total'] ) >= self::RATIO_BRUTE_FORCE
		) {
			return;
		}
		if ( $metrics['ip_unique_usernames'] >= self::THRESHOLD_CREDENTIAL_STUFFING ) {
			return;
		}

		$this->upsert_incident( Incident::PATTERN_ENUMERATION, 'ip', $ip, $ip, '', $metrics, Incident::SEVERITY_LOW );
	}

	/**
	 * Rule: distributed = ≥5 distinct IPs attacking same username in long window.
	 *
	 * @param string                                                                                                                  $username Attempted username.
	 * @param array{ip_total:int, ip_unique_usernames:int, ip_same_username:int, distinct_ips_on_username:int, invalid_user_from_ip:int} $metrics  Snapshot.
	 */
	private function check_distributed( string $username, array $metrics ): void {
		if ( '' === $username ) {
			return;
		}
		if ( $metrics['distinct_ips_on_username'] < self::THRESHOLD_DISTRIBUTED ) {
			return;
		}
		$severity = $this->is_targeted( $username ) ? Incident::SEVERITY_CRITICAL : Incident::SEVERITY_HIGH;
		$this->upsert_incident( Incident::PATTERN_DISTRIBUTED, 'target_username', $username, '', $username, $metrics, $severity );
	}

	/**
	 * Rule: post_compromise = success preceded by ≥3 failures from same IP in long window.
	 *
	 * @param string $ip       Client IP.
	 * @param string $username Successfully logged-in username.
	 */
	private function check_post_compromise( string $ip, string $username ): void {
		global $wpdb;

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Custom plugin table, windowed count.
		$prior_failures = (int) $wpdb->get_var(
			$wpdb->prepare(
				"SELECT COUNT(*) FROM {$wpdb->prefix}login_armor_logs WHERE ip = %s AND status IN ('failed','locked') AND " . self::COUNTED_REASONS_SQL . " AND log_time > DATE_SUB(UTC_TIMESTAMP(), INTERVAL %d MINUTE)", // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared -- COUNTED_REASONS_SQL is a class constant, no input reaches it.
				$ip,
				self::WINDOW_MINUTES_COMPROMISE
			)
		);

		if ( $prior_failures < self::THRESHOLD_POST_COMPROMISE ) {
			return;
		}

		$metrics = array(
			'ip_total'                 => $prior_failures,
			'ip_unique_usernames'      => 0,
			'ip_same_username'         => 0,
			'distinct_ips_on_username' => 0,
			'invalid_user_from_ip'     => 0,
		);
		// 2.8.0: an address on the IP safelist is one an administrator vouched
		// for by name, typically their own. Failures then a success from it is
		// someone mistyping a password, and raising it as a CRITICAL
		// "post-compromise" incident put "Attack in progress" on the dashboard
		// of the very person who typed it. It is still recorded, as an
		// observation (shown with "Include observations"). A loopback address
		// is not affected: it is trusted automatically, not chosen, and on a
		// real server it usually means a proxy nobody declared.
		$severity = \LoginArmor\LimitLogin::is_on_safelist( $ip ) ? Incident::SEVERITY_LOW : Incident::SEVERITY_CRITICAL;
		$this->upsert_incident( Incident::PATTERN_POST_COMPROMISE, 'ip', $ip, $ip, $username, $metrics, $severity );
	}

	/**
	 * Rule: app_password_refused = one address, one login, at least five
	 * wrong application passwords in the short window.
	 *
	 * Medium severity, low (an observation) from an address on the safelist,
	 * like post_compromise since 2.8.0. The usual cause is a service whose
	 * password was revoked or changed, and the incident text says so first.
	 * The summary row of the hourly cap has another reason and is not counted.
	 *
	 * @since 2.9.0
	 *
	 * @param string $ip       Client IP.
	 * @param string $username Login core read from Basic Auth.
	 */
	private function check_app_password_refused( string $ip, string $username ): void {
		global $wpdb;

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Custom plugin table, windowed count.
		$count = (int) $wpdb->get_var(
			$wpdb->prepare(
				"SELECT COUNT(*) FROM {$wpdb->prefix}login_armor_logs WHERE ip = %s AND username = %s AND reason = 'app_password_incorrect_password' AND log_time > DATE_SUB(UTC_TIMESTAMP(), INTERVAL %d MINUTE)",
				$ip,
				$username,
				self::WINDOW_MINUTES_SHORT
			)
		);
		if ( $count < self::THRESHOLD_APP_PASSWORD_REFUSED ) {
			return;
		}

		$metrics  = array(
			'ip_total'                 => $count,
			'ip_unique_usernames'      => 1,
			'ip_same_username'         => $count,
			'distinct_ips_on_username' => 0,
			'invalid_user_from_ip'     => 0,
		);
		$severity = \LoginArmor\LimitLogin::is_on_safelist( $ip ) ? Incident::SEVERITY_LOW : Incident::SEVERITY_MEDIUM;
		$this->upsert_incident( Incident::PATTERN_APP_PASSWORD_REFUSED, 'ip', $ip, $ip, $username, $metrics, $severity );
	}

	/**
	 * Return true if the given username corresponds to a user with editor+ role.
	 *
	 * @param string $username Username to check.
	 */
	private function is_targeted( string $username ): bool {
		if ( '' === $username ) {
			return false;
		}
		$user = get_user_by( 'login', $username );
		if ( ! $user instanceof \WP_User ) {
			return false;
		}
		return user_can( $user, 'edit_others_posts' );
	}

	/**
	 * Find an existing active incident with matching pattern + key and increment it,
	 * or create a new one. Fires login_armor_incident_created either way.
	 *
	 * @param string                                                                                                                  $pattern   Pattern constant.
	 * @param string                                                                                                                  $key_col   'ip' or 'target_username'.
	 * @param string                                                                                                                  $key_value Key value used to look up existing incident.
	 * @param string                                                                                                                  $ip        IP to store.
	 * @param string                                                                                                                  $target    Target username to store.
	 * @param array{ip_total:int, ip_unique_usernames:int, ip_same_username:int, distinct_ips_on_username:int, invalid_user_from_ip:int} $metrics   Metrics snapshot.
	 * @param int                                                                                                                     $severity  Severity constant.
	 * @param string|null                                                                                                             $inherited_started_at When creating a new incident, use this timestamp for started_at instead of "now": lets a promoted pattern (brute_force after enumeration) report the real attack window.
	 */
	private function upsert_incident( string $pattern, string $key_col, string $key_value, string $ip, string $target, array $metrics, int $severity, ?string $inherited_started_at = null ): void {
		$existing = Incident::find_active( $pattern, $key_value, $key_col );
		$now      = current_time( 'mysql', true );

		if ( $existing instanceof Incident ) {
			$existing->increment_occurrence(
				$severity,
				$metrics['ip_total'],
				max( $metrics['distinct_ips_on_username'], 1 ),
				max( $metrics['ip_unique_usernames'], 1 ),
				$this->current_vector
			);
			/**
			 * Fires after an incident has been created or updated.
			 *
			 * @param Incident $incident The incident.
			 * @param bool     $is_new   True for new incidents, false for updates.
			 */
			do_action( 'login_armor_incident_created', $existing, false );
			return;
		}

		$incident                   = new Incident();
		$incident->pattern          = $pattern;
		$incident->severity         = $severity;
		$incident->started_at       = $inherited_started_at ?? $now;
		$incident->last_seen_at     = $now;
		$incident->ip               = $ip;
		$incident->subnet           = $this->compute_subnet( $ip );
		$incident->target_username  = $target;
		$incident->events_count     = max( $metrics['ip_total'], 1 );
		$incident->unique_ips       = max( $metrics['distinct_ips_on_username'], 1 );
		$incident->unique_usernames = max( $metrics['ip_unique_usernames'], 1 );
		$incident->status           = Incident::STATUS_ACTIVE;
		$incident->vector           = $this->current_vector;
		$incident->insert();

		do_action( 'login_armor_incident_created', $incident, true );
	}

	/**
	 * Derive a /24 (IPv4) or /64 (IPv6) subnet string from an IP, for correlation.
	 *
	 * IPv6 note: see LimitLogin::subnet_of() for the rationale on expanding
	 * via bin2hex() rather than inet_ntop(): the latter returns the
	 * compressed form which broke the previous group-slicing approach.
	 * Behaviour aligned with LimitLogin::subnet_of() in 2.0.5.
	 *
	 * @param string $ip Client IP.
	 */
	private function compute_subnet( string $ip ): string {
		if ( filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 ) ) {
			$parts = explode( '.', $ip );
			if ( 4 === count( $parts ) ) {
				return $parts[0] . '.' . $parts[1] . '.' . $parts[2] . '.0/24';
			}
		}
		if ( filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6 ) ) {
			$packed = inet_pton( $ip );
			if ( false === $packed || 16 !== strlen( $packed ) ) {
				return '';
			}
			$groups = str_split( bin2hex( $packed ), 4 );
			if ( false === $groups || 8 !== count( $groups ) ) {
				return '';
			}
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
		return '';
	}
}
