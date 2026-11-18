<?php
/**
 * Overview data aggregator for the LoginArmor admin dashboard.
 *
 * Centralizes all read queries used by the Overview tab so that the PHP view
 * (first render) and the AJAX refresh endpoint consume exactly the same
 * source of truth.
 *
 * @package LoginArmor
 * @since   2.0.0
 */

namespace LoginArmor;

use LoginArmor\Detection\Incident;

// Exit if accessed directly.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Read-only aggregator for the Overview tab.
 * Every method is static and side-effect free.
 */
class Overview {

	public const THREAT_NORMAL   = 'normal';
	public const THREAT_ELEVATED = 'elevated';
	public const THREAT_ATTACK   = 'attack';

	/**
	 * Return the full dashboard payload consumed by the view and the AJAX refresh.
	 *
	 * @return array<string,mixed>
	 */
	public static function get_dashboard_data(): array {
		$active_incidents = self::get_active_incidents( 3 );
		$stats            = self::get_stats_24h();
		// Count + max severity are computed over ALL active incidents, not just
		// the 3 shown below, so an older CRITICAL incident cannot fall out of the
		// display list and silently reset the threat level to NORMAL (P1).
		$summary          = Incident::get_active_summary();
		$active_count     = $summary['count'];
		$all_quiet        = self::is_all_quiet( $stats, $active_count );

		return array(
			'threat'             => self::get_threat_level( $summary['max_severity'], $active_count, (int) $stats['events_24h'] ),
			'stats'              => $stats,
			'sparkline'          => self::get_hourly_activity(),
			'active_incidents'   => self::serialize_incidents( $active_incidents ),
			'recent_events'      => self::get_recent_events( 6 ),
			'last_event_ago'     => self::get_last_event_ago(),
			'server_time'        => current_time( 'mysql', true ),
			// "N active incidents require attention" must count what actually
			// requires attention: severity 2 and above (2.7.1). Severity 1 is
			// an observation, and a monitor-mode firewall produces one per
			// scanner probe, so the sentence was telling an administrator that
			// 235 of them demanded action.
			'summary_text'       => self::build_summary_text( $stats, (int) $summary['attention'] ),
			'total_blocked'      => self::get_total_blocked(),
			'all_quiet'          => $all_quiet,
			'next_advice'        => $all_quiet ? self::get_next_advice() : null,
		);
	}

	/**
	 * Build a human-readable one-line summary of the last 24 hours.
	 *
	 * @param array<string,int> $stats       Stats from get_stats_24h().
	 * @param int               $active_count Number of active incidents.
	 * @return string
	 */
	private static function build_summary_text( array $stats, int $active_count ): string {
		$events = (int) $stats['events_24h'];
		$ips    = (int) $stats['blocked_ips'];

		if ( 0 === $events ) {
			return __( 'No login attempts in the last 24 hours.', 'login-armor' );
		}

		$parts = array();

		$parts[] = sprintf(
			/* translators: 1: event count, 2: IP count. */
			_n(
				'%1$d login attempt from %2$d IP',
				'%1$d login attempts from %2$d IPs',
				$events,
				'login-armor'
			),
			$events,
			$ips
		);

		if ( $active_count > 0 ) {
			$parts[] = sprintf(
				/* translators: %d: number of active incidents. */
				_n(
					'%d active incident requires attention',
					'%d active incidents require attention',
					$active_count,
					'login-armor'
				),
				$active_count
			);
		} else {
			$parts[] = __( 'no active incidents', 'login-armor' );
		}

		return implode( '. ', $parts ) . '.';
	}

	/**
	 * Classify the global threat level from aggregate active-incident stats.
	 *
	 * Takes the pre-computed maximum severity and count over ALL active
	 * incidents (see Incident::get_active_summary()) rather than a display-
	 * limited list, so the headline never under-reports the real threat (P1).
	 *
	 * @param int $max_severity Highest severity among all active incidents (0 if none).
	 * @param int $active_count Total number of active incidents.
	 * @param int $events_24h   Total log events in the last 24 hours.
	 * @return array{level:string, label:string, active_count:int, events_24h:int}
	 */
	public static function get_threat_level( int $max_severity, int $active_count, int $events_24h ): array {
		if ( $max_severity >= Incident::SEVERITY_HIGH ) {
			$level = self::THREAT_ATTACK;
			$label = __( 'UNDER ATTACK', 'login-armor' );
		} elseif ( $max_severity >= Incident::SEVERITY_MEDIUM ) {
			$level = self::THREAT_ELEVATED;
			$label = __( 'ELEVATED', 'login-armor' );
		} else {
			$level = self::THREAT_NORMAL;
			$label = __( 'NORMAL', 'login-armor' );
		}

		return array(
			'level'        => $level,
			'label'        => $label,
			'active_count' => $active_count,
			'events_24h'   => $events_24h,
		);
	}

	/**
	 * Return the 4 headline counters for the last 24 hours window.
	 *
	 * @return array{events_24h:int, blocked_ips:int, active_lockouts:int, unique_users:int}
	 */
	public static function get_stats_24h(): array {
		global $wpdb;

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Custom plugin table, real-time dashboard stats.
		$events_24h = (int) $wpdb->get_var(
			$wpdb->prepare(
				"SELECT COUNT(*) FROM {$wpdb->prefix}login_armor_logs WHERE log_time > DATE_SUB(UTC_TIMESTAMP(), INTERVAL %d HOUR)",
				24
			)
		);

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Custom plugin table, real-time dashboard stats.
		$blocked_ips = (int) $wpdb->get_var(
			$wpdb->prepare(
				"SELECT COUNT(DISTINCT ip) FROM {$wpdb->prefix}login_armor_logs WHERE status IN ('failed','locked') AND log_time > DATE_SUB(UTC_TIMESTAMP(), INTERVAL %d HOUR)",
				24
			)
		);

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Custom plugin table, real-time dashboard stats.
		$unique_users = (int) $wpdb->get_var(
			$wpdb->prepare(
				"SELECT COUNT(DISTINCT username) FROM {$wpdb->prefix}login_armor_logs WHERE username != '' AND log_time > DATE_SUB(UTC_TIMESTAMP(), INTERVAL %d HOUR)",
				24
			)
		);

		return array(
			'events_24h'      => $events_24h,
			'blocked_ips'     => $blocked_ips,
			'active_lockouts' => LimitLogin::get_locked_ips_count(),
			'unique_users'    => $unique_users,
		);
	}

	/**
	 * Return 24 integers: one per hour bucket, oldest first, newest last.
	 * Index 0 = 24 hours ago, index 23 = current hour.
	 *
	 * @return int[] Always exactly 24 elements.
	 */
	public static function get_hourly_activity(): array {
		global $wpdb;

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Custom plugin table, sparkline data source.
		$rows = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT FLOOR((UNIX_TIMESTAMP(UTC_TIMESTAMP()) - UNIX_TIMESTAMP(log_time)) / 3600) AS hours_ago, COUNT(*) AS c
				 FROM {$wpdb->prefix}login_armor_logs
				 WHERE log_time > DATE_SUB(UTC_TIMESTAMP(), INTERVAL %d HOUR)
				 GROUP BY hours_ago",
				24
			)
		);

		$buckets = array_fill( 0, 24, 0 );
		if ( is_array( $rows ) ) {
			foreach ( $rows as $row ) {
				$hours_ago = (int) $row->hours_ago;
				if ( $hours_ago >= 0 && $hours_ago < 24 ) {
					// Reverse so index 0 = oldest, index 23 = current hour.
					$buckets[ 23 - $hours_ago ] = (int) $row->c;
				}
			}
		}
		return $buckets;
	}

	/**
	 * Return the total number of blocked login attempts (failed + locked) since install.
	 *
	 * @return int
	 */
	public static function get_total_blocked(): int {
		global $wpdb;
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Custom plugin table, dashboard hero metric.
		return (int) $wpdb->get_var(
			"SELECT COUNT(*) FROM {$wpdb->prefix}login_armor_logs WHERE status IN ('failed','locked')"
		);
	}

	/**
	 * Days of monitor-mode evidence before "switch to Enforce" is proposed.
	 *
	 * Seven, so the advice has seen a full week including the weekend: a site
	 * whose only odd traffic is a Sunday-night backup job would otherwise be
	 * asked to enforce on the strength of five office days.
	 *
	 * @since 2.7.0
	 */
	public const ENFORCE_ADVICE_MIN_DAYS = 7;

	/**
	 * Matches over the last seven days above which Enforce is NOT proposed.
	 *
	 * Ten is the line between "bots only" and "this is catching something the
	 * administrator should look at first". Above it the honest advice is to
	 * read the incidents, not to start blocking.
	 *
	 * @since 2.7.0
	 */
	public const ENFORCE_ADVICE_MAX_MATCHES = 10;

	/**
	 * Next proactive advice for the current user based on what's not yet set up.
	 *
	 * Priority: firewall / bot challenge Enforce (2.7.0, only once the site has
	 * measured a quiet week of its own) > 2FA > Hide Login > Breach Check >
	 * Notifications. Skipped entries (persisted in
	 * user_meta[login_armor_skipped_advice]) are excluded. Returns null when
	 * every known advice has been applied or dismissed.
	 *
	 * @return array{key:string, title:string, body:string, cta_url:string, cta_label:string}|null
	 */
	public static function get_next_advice(): ?array {
		$user_id      = get_current_user_id();
		$skipped      = (array) get_user_meta( $user_id, 'login_armor_skipped_advice', true );
		$settings_url = add_query_arg(
			array( 'page' => 'login-armor', 'tab' => 'settings' ),
			admin_url( 'admin.php' )
		);

		$candidates = array();

		// 2.7.0, first on the list: every other advice below asks the
		// administrator to decide something. These two only ask to confirm
		// what the site has already measured on its own traffic, so they are
		// the cheapest and the least risky action available today.
		//
		// monitoring_days() already answers 0 unless the module is enabled AND
		// still in monitor mode, so no further state test is needed here. The
		// skip test belongs in the guard and not in the loop below: these two
		// are the only candidates that COST something to build (an aggregate
		// over the incidents table, a counter read), and a user who dismissed
		// the advice would otherwise pay for it on every admin page for ever.
		$la_fw_days = class_exists( '\LoginArmor\Firewall\Firewall' )
			? \LoginArmor\Firewall\Firewall::monitoring_days()
			: 0;
		if ( $la_fw_days >= self::ENFORCE_ADVICE_MIN_DAYS && ! in_array( 'firewall-enforce', $skipped, true ) ) {
			$la_fw_matches = \LoginArmor\Firewall\Firewall::count_blocks( '7d' );
			if ( $la_fw_matches <= self::ENFORCE_ADVICE_MAX_MATCHES ) {
				$candidates[] = array(
					'key'       => 'firewall-enforce',
					'title'     => __( 'Your firewall has watched a quiet week', 'login-armor' ),
					// Two sentences, two plurals. One sentence carrying both
					// counts would have to pick ONE of them for _n(), and the
					// agreement of the other then follows the wrong number in
					// every language with more than two plural forms.
					'body'      => sprintf(
						/* translators: %d: number of days the firewall has been in monitor mode. */
						_n( 'The Request Firewall has been in monitor mode for %d day.', 'The Request Firewall has been in monitor mode for %d days.', (int) $la_fw_days, 'login-armor' ),
						(int) $la_fw_days
					) . ' ' . ( 0 === $la_fw_matches
						? __( 'It has not flagged a single legitimate request over the last week. Switching it to Enforce now blocks those requests instead of only logging them.', 'login-armor' )
						: sprintf(
							/* translators: %d: number of matches over the last 7 days. */
							_n(
								'It matched %d request over the last week. Review it in the Incidents tab, then switch to Enforce to block that traffic instead of only logging it.',
								'It matched %d requests over the last week. Review them in the Incidents tab, then switch to Enforce to block that traffic instead of only logging it.',
								(int) $la_fw_matches,
								'login-armor'
							),
							(int) $la_fw_matches
						) ),
					'cta_url'   => $settings_url . '#firewall',
					'cta_label' => __( 'Switch the firewall to Enforce', 'login-armor' ),
				);
			}
		}

		$la_pow_days = class_exists( '\LoginArmor\PowChallenge' )
			? \LoginArmor\PowChallenge::monitoring_days()
			: 0;
		if ( $la_pow_days >= self::ENFORCE_ADVICE_MIN_DAYS && ! in_array( 'pow-enforce', $skipped, true ) ) {
			$la_pow_matches = \LoginArmor\PowChallenge::get_softfail_count();
			if ( $la_pow_matches <= self::ENFORCE_ADVICE_MAX_MATCHES ) {
				$candidates[] = array(
					'key'       => 'pow-enforce',
					'title'     => __( 'Your bot challenge has watched a quiet week', 'login-armor' ),
					'body'      => sprintf(
						/* translators: %d: number of days the bot challenge has been in monitor mode. */
						_n( 'The Bot Challenge has been in monitor mode for %d day.', 'The Bot Challenge has been in monitor mode for %d days.', (int) $la_pow_days, 'login-armor' ),
						(int) $la_pow_days
					) . ' ' . ( 0 === $la_pow_matches
						? __( 'Every single login submission over the last week carried a valid proof. Switching it to Enforce now rejects the ones that do not.', 'login-armor' )
						: sprintf(
							/* translators: %d: number of submissions without a valid proof over the last 7 days. */
							_n(
								'It saw %d login submission without a valid proof over the last week. That is bot-level noise: switching to Enforce rejects it instead of only counting it.',
								'It saw %d login submissions without a valid proof over the last week. That is bot-level noise: switching to Enforce rejects them instead of only counting them.',
								(int) $la_pow_matches,
								'login-armor'
							),
							(int) $la_pow_matches
						) ),
					'cta_url'   => $settings_url . '#pow',
					'cta_label' => __( 'Switch the bot challenge to Enforce', 'login-armor' ),
				);
			}
		}

		if ( ! get_option( 'login_armor_2fa_enabled', false ) ) {
			$candidates[] = array(
				'key'       => '2fa',
				'title'     => __( 'Turn on two-factor authentication', 'login-armor' ),
				'body'      => __( 'Stop credential-stuffing attacks even when passwords leak. LoginArmor includes TOTP apps, email codes and backup codes: no external service.', 'login-armor' ),
				'cta_url'   => $settings_url . '#two-factor',
				'cta_label' => __( 'Set up 2FA', 'login-armor' ),
			);
		}

		if ( ! HideLogin::is_enabled() ) {
			$candidates[] = array(
				'key'       => 'hide-login',
				'title'     => __( 'Hide your login page', 'login-armor' ),
				'body'      => __( 'Move /wp-login.php to a private URL. Bots that scan for the default path get a 404 and move on.', 'login-armor' ),
				'cta_url'   => $settings_url . '#hide-login',
				'cta_label' => __( 'Configure Hide Login', 'login-armor' ),
			);
		}

		if ( ! (bool) get_option( 'login_armor_breach_check_enabled', false ) ) {
			$candidates[] = array(
				'key'       => 'breach-check',
				'title'     => __( 'Detect leaked passwords automatically', 'login-armor' ),
				'body'      => __( 'Quietly check each login password against the Have I Been Pwned corpus using a privacy-preserving lookup. Flagged users get a friendly warning on their profile: no one is locked out.', 'login-armor' ),
				'cta_url'   => $settings_url . '#breach-check',
				'cta_label' => __( 'Configure Breach Check', 'login-armor' ),
			);
		}

		$notif_channel = (string) get_option( 'login_armor_notif_channel', 'disabled' );
		if ( 'disabled' === $notif_channel ) {
			$candidates[] = array(
				'key'       => 'notifications',
				'title'     => __( 'Get notified when something happens', 'login-armor' ),
				'body'      => __( 'Pipe LoginArmor events to email, Slack, Discord or a custom webhook. Never miss a brute-force attempt.', 'login-armor' ),
				'cta_url'   => $settings_url . '#notifications',
				'cta_label' => __( 'Set up notifications', 'login-armor' ),
			);
		}

		foreach ( $candidates as $advice ) {
			if ( ! in_array( $advice['key'], $skipped, true ) ) {
				return $advice;
			}
		}

		return null;
	}

	/**
	 * True when the site has had zero activity in the last 24h and no active incidents.
	 *
	 * @param array<string,int> $stats  Stats from get_stats_24h().
	 * @param int               $active Active incident count.
	 * @return bool
	 */
	public static function is_all_quiet( array $stats, int $active ): bool {
		return 0 === (int) ( $stats['events_24h'] ?? 0 ) && 0 === $active;
	}

	/**
	 * Return the N most recent active incidents.
	 *
	 * @param int $limit Max rows. Clamped to [1, 20].
	 * @return Incident[]
	 */
	public static function get_active_incidents( int $limit = 3 ): array {
		$limit = max( 1, min( 20, $limit ) );
		return Incident::get_active( $limit );
	}

	/**
	 * Convert Incident objects into JSON-friendly arrays enriched with display fields.
	 *
	 * @param Incident[] $incidents List of incidents to serialize.
	 * @return array<int,array<string,mixed>>
	 */
	private static function serialize_incidents( array $incidents ): array {
		$out = array();
		foreach ( $incidents as $inc ) {
			$out[] = array(
				'id'               => $inc->id,
				'pattern'          => $inc->pattern,
				'pattern_label'    => str_replace( '_', ' ', strtoupper( $inc->pattern ) ),
				'severity'         => $inc->severity,
				'severity_label'   => self::severity_label( $inc->severity ),
				'severity_class'   => self::severity_class( $inc->severity ),
				'started_at'       => $inc->started_at,
				'started_ago'      => self::time_ago( $inc->started_at ),
				'last_seen_at'     => $inc->last_seen_at,
				'ip'               => $inc->ip,
				'subnet'           => $inc->subnet,
				'target_username'  => $inc->target_username,
				'events_count'     => $inc->events_count,
				'unique_ips'       => $inc->unique_ips,
				'unique_usernames' => $inc->unique_usernames,
			);
		}
		return $out;
	}

	/**
	 * Map a severity integer to its display label.
	 */
	private static function severity_label( int $sev ): string {
		return strtoupper( Incident::severity_slug( $sev ) );
	}

	/**
	 * Map a severity integer to its CSS class suffix.
	 */
	private static function severity_class( int $sev ): string {
		return Incident::severity_slug( $sev );
	}

	/**
	 * Return the N most recent log rows in tail-f order (newest first).
	 *
	 * @param int $limit Max rows. Clamped to [1, 50].
	 * @return array<int,array<string,mixed>>
	 */
	public static function get_recent_events( int $limit = 6 ): array {
		global $wpdb;
		$limit = max( 1, min( 50, $limit ) );

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Custom plugin table, live tail.
		$rows = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT id, ip, username, status, log_time, user_agent, reason FROM {$wpdb->prefix}login_armor_logs ORDER BY log_time DESC LIMIT %d",
				$limit
			)
		);

		$out = array();
		if ( is_array( $rows ) ) {
			foreach ( $rows as $row ) {
				$out[] = array(
					'id'           => (int) $row->id,
					'ip'           => (string) $row->ip,
					'username'     => (string) $row->username,
					'status'       => (string) $row->status,
					'log_time'     => (string) $row->log_time,
					'user_agent'   => (string) $row->user_agent,
					'reason'       => (string) $row->reason,
					// Rendered label resolved server-side so the live-tail JS
					// does not need a second copy of the code → text mapping.
					'reason_label' => LoginLogs::failure_reason_label( (string) $row->reason ),
					'time_short'   => self::short_time( (string) $row->log_time ),
					'ago'          => self::time_ago( (string) $row->log_time ),
				);
			}
		}
		return $out;
	}

	/**
	 * Return a human-readable "N seconds ago" string for the latest plugin event.
	 *
	 * Considers three sources: login attempts (logs), incident sightings, and
	 * admin activity: whichever is most recent. Falls back to an em-dash when
	 * none of the tables has any row (or exists).
	 */
	public static function get_last_event_ago(): string {
		global $wpdb;

		$timestamps = [];

		// Login events (always exists).
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Custom plugin table, dashboard header freshness indicator.
		$t = $wpdb->get_var( "SELECT log_time FROM {$wpdb->prefix}login_armor_logs ORDER BY log_time DESC LIMIT 1" );
		if ( $t ) {
			$timestamps[] = (string) $t;
		}

		// Incident sightings (always exists).
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Custom plugin table, dashboard header freshness indicator.
		$t = $wpdb->get_var( "SELECT last_seen_at FROM {$wpdb->prefix}login_armor_incidents ORDER BY last_seen_at DESC LIMIT 1" );
		if ( $t ) {
			$timestamps[] = (string) $t;
		}

		// Admin activity (optional module: table may not exist).
		$activity_table = $wpdb->prefix . 'login_armor_activity';
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.NotPrepared
		$exists = $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $activity_table ) );
		if ( $exists ) {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.InterpolatedNotPrepared,PluginCheck.Security.DirectDB.UnescapedDBParameter -- Table name built from trusted $wpdb->prefix + hard-coded suffix, no user input.
			$t = $wpdb->get_var( "SELECT log_time FROM {$activity_table} ORDER BY log_time DESC LIMIT 1" );
			if ( $t ) {
				$timestamps[] = (string) $t;
			}
		}

		if ( empty( $timestamps ) ) {
			return '';
		}

		sort( $timestamps );
		return self::time_ago( (string) end( $timestamps ) );
	}

	/**
	 * Format a UTC datetime string as a translatable compact relative time
	 * ("Ns / Nm / Nh / Nd ago"). Each unit is its own msgid so translators
	 * can pick the right abbreviation for their language.
	 */
	private static function time_ago( string $utc_datetime ): string {
		$ts = strtotime( $utc_datetime . ' UTC' );
		if ( ! $ts ) {
			return '';
		}
		$delta = max( 0, time() - $ts );
		if ( $delta < 60 ) {
			/* translators: %d: number of seconds, short compact form. */
			return sprintf( __( '%ds ago', 'login-armor' ), $delta );
		}
		if ( $delta < 3600 ) {
			/* translators: %d: number of minutes, short compact form. */
			return sprintf( __( '%dm ago', 'login-armor' ), (int) floor( $delta / 60 ) );
		}
		if ( $delta < 86400 ) {
			/* translators: %d: number of hours, short compact form. */
			return sprintf( __( '%dh ago', 'login-armor' ), (int) floor( $delta / 3600 ) );
		}
		/* translators: %d: number of days, short compact form. */
		return sprintf( __( '%dd ago', 'login-armor' ), (int) floor( $delta / 86400 ) );
	}

	/**
	 * Return HH:MM:SS in the site's configured timezone from a UTC datetime string.
	 */
	private static function short_time( string $utc_datetime ): string {
		$ts = strtotime( $utc_datetime . ' UTC' );
		if ( ! $ts ) {
			return '--:--:--';
		}
		return wp_date( 'H:i:s', $ts );
	}

	/**
	 * Delta between last 24h events and the 24h window immediately before.
	 * Positive → more attacks than yesterday. Zero if table is empty.
	 */
	public static function get_events_delta_24h(): int {
		global $wpdb;
		$table = $wpdb->prefix . 'login_armor_logs';
		$now   = current_time( 'timestamp', true );
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,PluginCheck.Security.DirectDB.UnescapedDBParameter -- $table is built from $wpdb->prefix + hard-coded suffix; freshness-sensitive dashboard counter, caching would make the metric stale.
		$r24 = (int) $wpdb->get_var(
			$wpdb->prepare(
				"SELECT COUNT(*) FROM {$table} WHERE log_time >= %s", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				gmdate( 'Y-m-d H:i:s', $now - 86400 )
			)
		);
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,PluginCheck.Security.DirectDB.UnescapedDBParameter -- see rationale above.
		$r48 = (int) $wpdb->get_var(
			$wpdb->prepare(
				"SELECT COUNT(*) FROM {$table} WHERE log_time >= %s AND log_time < %s", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				gmdate( 'Y-m-d H:i:s', $now - 172800 ),
				gmdate( 'Y-m-d H:i:s', $now - 86400 )
			)
		);
		return $r24 - $r48;
	}

	/**
	 * Distinct IPs seen in the last 24h.
	 */
	public static function get_unique_ips_24h(): int {
		global $wpdb;
		$table = $wpdb->prefix . 'login_armor_logs';
		$since = gmdate( 'Y-m-d H:i:s', current_time( 'timestamp', true ) - 86400 );
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,PluginCheck.Security.DirectDB.UnescapedDBParameter -- $table is trusted, see get_events_delta_24h() above.
		return (int) $wpdb->get_var(
			$wpdb->prepare(
				"SELECT COUNT(DISTINCT ip) FROM {$table} WHERE log_time >= %s", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				$since
			)
		);
	}

	/**
	 * Hide-Login ↔ XML-RPC misconfiguration advisory (V2.1.20).
	 *
	 * Hide Login moves /wp-login.php to a private URL, but xmlrpc.php is a
	 * second, parallel authentication endpoint that Hide Login does NOT cover.
	 * A site owner who hid their login often believes brute force can no longer
	 * reach them: yet a distributed xmlrpc attack (system.multicall) walks
	 * straight past it. This is exactly how cours-ndrc.fr was hit in 2026-05.
	 *
	 * Returns advisory data only when all three hold, so it never nags a
	 * correctly configured site and only fires on real, observed evidence:
	 *   1. Hide Login is enabled (the false sense of security exists), AND
	 *   2. the `disable_xmlrpc` hardening toggle is OFF (xmlrpc still open), AND
	 *   3. at least one incident was recorded with vector = xmlrpc in the
	 *      last 30 days (an attacker is actually using the bypass).
	 *
	 * @since 2.1.20
	 * @return array{count:int,settings_url:string}|null
	 */
	public static function get_xmlrpc_advisory(): ?array {
		if ( ! class_exists( '\LoginArmor\HideLogin' ) || ! HideLogin::is_enabled() ) {
			return null;
		}

		$hardening = class_exists( '\LoginArmor\Hardening' ) ? Hardening::get_settings() : array();
		if ( ! empty( $hardening['disable_xmlrpc'] ) ) {
			return null; // xmlrpc already blocked: nothing to advise.
		}

		global $wpdb;
		$since = gmdate( 'Y-m-d H:i:s', current_time( 'timestamp', true ) - ( 30 * DAY_IN_SECONDS ) );

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Custom plugin table, dashboard advisory; freshness matters.
		$count = (int) $wpdb->get_var(
			$wpdb->prepare(
				// `vector` backticked: reserved word since MariaDB 11.7 / MySQL 9.0.
				"SELECT COUNT(*) FROM {$wpdb->prefix}login_armor_incidents WHERE `vector` = %s AND last_seen_at >= %s",
				'xmlrpc',
				$since
			)
		);

		if ( $count < 1 ) {
			return null;
		}

		return array(
			'count'        => $count,
			'settings_url' => add_query_arg(
				array( 'page' => 'login-armor', 'tab' => 'settings' ),
				admin_url( 'admin.php' )
			) . '#hardening',
		);
	}

	/**
	 * Count of failed login attempts in the last 24h (status != 'success').
	 * Used by the overview chart footer to show "N fails blocked".
	 */
	public static function get_failed_attempts_24h(): int {
		global $wpdb;
		$table = $wpdb->prefix . 'login_armor_logs';
		$since = gmdate( 'Y-m-d H:i:s', current_time( 'timestamp', true ) - 86400 );
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,PluginCheck.Security.DirectDB.UnescapedDBParameter -- $table is trusted, see get_events_delta_24h() above.
		return (int) $wpdb->get_var(
			$wpdb->prepare(
				"SELECT COUNT(*) FROM {$table} WHERE log_time >= %s AND status != %s", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				$since,
				'success'
			)
		);
	}
}
