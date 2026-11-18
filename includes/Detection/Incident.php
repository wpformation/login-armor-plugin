<?php
/**
 * Incident model for the LoginArmor detection engine.
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
 * Represents one classified attack pattern occurrence.
 * All properties are public for simplicity: this is a data transfer object
 * plus a few static CRUD helpers, not a heavy ORM entity.
 */
class Incident {

	public const PATTERN_BRUTE_FORCE               = 'brute_force';
	public const PATTERN_CREDENTIAL_STUFFING       = 'credential_stuffing';
	public const PATTERN_ENUMERATION               = 'enumeration';
	public const PATTERN_DISTRIBUTED               = 'distributed';
	public const PATTERN_POST_COMPROMISE           = 'post_compromise';
	public const PATTERN_RESERVED_USERNAME_PROBE   = 'reserved_username_probe';
	public const PATTERN_BOT_HONEYPOT_CAUGHT       = 'bot_honeypot_caught';
	public const PATTERN_2FA_RECOVERY_REQUESTED    = '2fa_recovery_requested';
	public const PATTERN_FIREWALL_BLOCK            = 'firewall_block';
	public const PATTERN_POW_FAILED                = 'pow_failed';
	public const PATTERN_APP_PASSWORD_REFUSED      = 'app_password_refused';

	public const SEVERITY_LOW      = 1;
	public const SEVERITY_MEDIUM   = 2;
	public const SEVERITY_HIGH     = 3;
	public const SEVERITY_CRITICAL = 4;

	/**
	 * The columns 2.7.1 added, and the only ones whose absence stays quiet.
	 *
	 * Every other column of this table is written on INSERT and read through
	 * `SELECT *`, so losing one would fail loudly and immediately. These three
	 * are written by a single UPDATE long after the row exists, and read back
	 * through that same `SELECT *`: gone, they break nothing visible and drop
	 * every analysis that was paid for.
	 */
	private const ANALYSIS_COLUMNS = array( 'ai_analysis', 'ai_analysis_fp', 'ai_analysed_at' );

	/** Durable record of an analysis that could not be stored (2.7.2). */
	public const OPTION_SCHEMA_FAILURE = 'login_armor_schema_last_failure';

	/** Rate limit on re-running the schema from the point of use (2.7.2). */
	public const TRANSIENT_SCHEMA_REPAIR = 'login_armor_schema_repair';

	public const STATUS_ACTIVE   = 'active';
	public const STATUS_RESOLVED = 'resolved';
	public const STATUS_IGNORED  = 'ignored';

	/**
	 * Map a severity level to its canonical lowercase slug.
	 *
	 * Single source of truth for severity naming: presentation layers
	 * (uppercase tokens, CSS suffixes, translated labels) derive from it
	 * instead of re-declaring the SEVERITY_* → name mapping.
	 *
	 * @param int $severity One of the SEVERITY_* constants.
	 * @return string 'critical' | 'high' | 'medium' | 'low'.
	 */
	public static function severity_slug( int $severity ): string {
		switch ( $severity ) {
			case self::SEVERITY_CRITICAL:
				return 'critical';
			case self::SEVERITY_HIGH:
				return 'high';
			case self::SEVERITY_MEDIUM:
				return 'medium';
			default:
				return 'low';
		}
	}

	// Entry point the events were observed on. 'login_form' is the historical
	// default (wp-login.php / hidden slug); 'xmlrpc' and 'rest' bypass Hide Login.
	public const VECTOR_LOGIN_FORM = 'login_form';
	public const VECTOR_XMLRPC     = 'xmlrpc';
	public const VECTOR_REST       = 'rest';

	public int    $id               = 0;
	public string $pattern          = '';
	public int    $severity         = self::SEVERITY_LOW;
	public string $started_at       = '';
	public string $last_seen_at     = '';
	public string $ip               = '';
	public string $subnet           = '';
	public string $target_username  = '';
	public int    $events_count     = 0;
	public int    $unique_ips       = 0;
	public int    $unique_usernames = 0;
	public string $status           = self::STATUS_ACTIVE;
	public string $vector           = self::VECTOR_LOGIN_FORM;

	// AI analysis kept ON the incident row since 2.7.1 (was a 12-hour transient
	// the drill-down never read back). `ai_analysis_fp` fingerprints the state
	// that produced the text so a stale analysis can be labelled as such rather
	// than shown as current; see IncidentExplainer.
	public string $ai_analysis      = '';
	public string $ai_analysis_fp   = '';
	public string $ai_analysed_at   = '';

	/**
	 * Get the incidents table name.
	 */
	public static function table(): string {
		global $wpdb;
		return $wpdb->prefix . 'login_armor_incidents';
	}

	/**
	 * Insert a new incident row and return its ID. Returns 0 on failure.
	 */
	public function insert(): int {
		global $wpdb;

		$now  = current_time( 'mysql', true );
		$data = array(
			'pattern'          => $this->pattern,
			'severity'         => $this->severity,
			'started_at'       => $this->started_at !== '' ? $this->started_at : $now,
			'last_seen_at'     => $this->last_seen_at !== '' ? $this->last_seen_at : $now,
			'ip'               => $this->ip,
			'subnet'           => $this->subnet,
			'target_username'  => $this->target_username,
			'events_count'     => $this->events_count,
			'unique_ips'       => $this->unique_ips,
			'unique_usernames' => $this->unique_usernames,
			'status'           => $this->status,
			'vector'           => $this->vector,
		);
		$formats = array( '%s', '%d', '%s', '%s', '%s', '%s', '%s', '%d', '%d', '%d', '%s', '%s' );

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Custom plugin table, incident creation.
		$ok = $wpdb->insert( self::table(), $data, $formats );
		if ( ! $ok ) {
			return 0;
		}
		$this->id = (int) $wpdb->insert_id;
		return $this->id;
	}

	/**
	 * Find an active incident matching the given pattern and key within
	 * the cooldown window (default 1h). Returns null if none found.
	 *
	 * @param string $pattern           One of PATTERN_* constants.
	 * @param string $key               IP or username value to match.
	 * @param string $key_col           Column to match: 'ip', 'subnet' or 'target_username'.
	 * @param int    $cooldown_minutes  Cooldown window in minutes.
	 */
	public static function find_active( string $pattern, string $key, string $key_col = 'ip', int $cooldown_minutes = 60 ): ?self {
		global $wpdb;

		if ( ! in_array( $key_col, array( 'ip', 'subnet', 'target_username' ), true ) ) {
			return null;
		}

		// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
		if ( 'ip' === $key_col ) {
			$row = $wpdb->get_row(
				$wpdb->prepare(
					"SELECT * FROM {$wpdb->prefix}login_armor_incidents WHERE pattern = %s AND ip = %s AND status = %s AND last_seen_at > DATE_SUB(UTC_TIMESTAMP(), INTERVAL %d MINUTE) ORDER BY last_seen_at DESC LIMIT 1",
					$pattern,
					$key,
					self::STATUS_ACTIVE,
					$cooldown_minutes
				)
			);
		} elseif ( 'subnet' === $key_col ) {
			$row = $wpdb->get_row(
				$wpdb->prepare(
					"SELECT * FROM {$wpdb->prefix}login_armor_incidents WHERE pattern = %s AND subnet = %s AND status = %s AND last_seen_at > DATE_SUB(UTC_TIMESTAMP(), INTERVAL %d MINUTE) ORDER BY last_seen_at DESC LIMIT 1",
					$pattern,
					$key,
					self::STATUS_ACTIVE,
					$cooldown_minutes
				)
			);
		} else {
			$row = $wpdb->get_row(
				$wpdb->prepare(
					"SELECT * FROM {$wpdb->prefix}login_armor_incidents WHERE pattern = %s AND target_username = %s AND status = %s AND last_seen_at > DATE_SUB(UTC_TIMESTAMP(), INTERVAL %d MINUTE) ORDER BY last_seen_at DESC LIMIT 1",
					$pattern,
					$key,
					self::STATUS_ACTIVE,
					$cooldown_minutes
				)
			);
		}
		// phpcs:enable

		if ( ! $row ) {
			return null;
		}
		return self::from_row( $row );
	}

	/**
	 * Update mutable fields (last_seen_at, counts, severity, status) on an existing row.
	 */
	public function update(): bool {
		global $wpdb;
		if ( 0 === $this->id ) {
			return false;
		}

		$data = array(
			'last_seen_at'     => $this->last_seen_at,
			'events_count'     => $this->events_count,
			'unique_ips'       => $this->unique_ips,
			'unique_usernames' => $this->unique_usernames,
			'severity'         => $this->severity,
			'status'           => $this->status,
			'vector'           => $this->vector,
		);
		$formats = array( '%s', '%d', '%d', '%d', '%d', '%s', '%s' );

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Custom plugin table, incident update.
		$ok = $wpdb->update( self::table(), $data, array( 'id' => $this->id ), $formats, array( '%d' ) );
		return false !== $ok;
	}

	/**
	 * Atomically record one additional occurrence on an existing incident.
	 *
	 * @param int    $severity      Minimum severity after the update.
	 * @param int    $events_floor  Minimum event count from current metrics.
	 * @param int    $ips_floor     Minimum unique IP count.
	 * @param int    $users_floor   Minimum unique username count.
	 * @param string $vector        Current entry vector.
	 */
	public function increment_occurrence( int $severity, int $events_floor = 0, int $ips_floor = 0, int $users_floor = 0, string $vector = '' ): bool {
		global $wpdb;
		if ( $this->id <= 0 ) {
			return false;
		}
		$now    = current_time( 'mysql', true );
		$vector = '' === $vector ? $this->vector : $vector;
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Atomic incident aggregation.
		$updated = $wpdb->query(
			$wpdb->prepare(
				"UPDATE {$wpdb->prefix}login_armor_incidents
				SET last_seen_at = %s,
					events_count = GREATEST(events_count + 1, %d),
					unique_ips = GREATEST(unique_ips, %d),
					unique_usernames = GREATEST(unique_usernames, %d),
					severity = GREATEST(severity, %d),
					`vector` = %s
				WHERE id = %d",
				$now,
				max( 0, $events_floor ),
				max( 0, $ips_floor ),
				max( 0, $users_floor ),
				$severity,
				$vector,
				$this->id
			)
		);
		if ( false === $updated ) {
			return false;
		}
		$this->last_seen_at     = $now;
		$this->events_count     = max( $this->events_count + 1, $events_floor );
		$this->unique_ips       = max( $this->unique_ips, $ips_floor );
		$this->unique_usernames = max( $this->unique_usernames, $users_floor );
		$this->severity         = max( $this->severity, $severity );
		$this->vector           = $vector;
		return true;
	}

	/**
	 * Get all active incidents, optionally filtered.
	 *
	 * @param int $limit Max rows to return.
	 * @return self[]
	 */
	public static function get_active( int $limit = 50 ): array {
		global $wpdb;

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Custom plugin table, active incidents list.
		$rows = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT * FROM {$wpdb->prefix}login_armor_incidents WHERE status = %s ORDER BY last_seen_at DESC LIMIT %d",
				self::STATUS_ACTIVE,
				$limit
			)
		);

		$out = array();
		if ( is_array( $rows ) ) {
			foreach ( $rows as $row ) {
				$out[] = self::from_row( $row );
			}
		}
		return $out;
	}

	/**
	 * Aggregate stats over EVERY active incident (not just a displayed subset).
	 *
	 * The dashboard shows only the 3 most-recent active incidents, but the
	 * headline threat level and the "active incidents" counter must reflect the
	 * whole active set: a lone CRITICAL incident that is older than three recent
	 * LOW ones would otherwise fall out of the displayed list and silently drop
	 * the dashboard back to "NORMAL" (finding P1). COUNT/MAX run server-side over
	 * all active rows so the summary never depends on the display LIMIT.
	 *
	 * `severity` is a TINYINT UNSIGNED column, so MAX() is a true numeric
	 * maximum (no lexical-ordering pitfall).
	 *
	 * 2.7.1 splits the total in two, in the same pass. `attention` counts
	 * severity 2 and above; `observations` counts severity 1, which is the
	 * bottom of the scale and means "recorded, look if you like", not "act".
	 * A site watching its request firewall in monitor mode records one of
	 * those per scanner probe from the background noise of the internet: 235
	 * of them, counted as open incidents in red under a heading that said they
	 * deserved attention, is what made the plugin's own author think his site
	 * was under attack. `count` keeps its meaning, so nothing that reasons
	 * about the whole active set changes.
	 *
	 * @return array{count:int, attention:int, observations:int, max_severity:int}
	 */
	public static function get_active_summary(): array {
		global $wpdb;

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Custom plugin table, dashboard aggregate.
		$row = $wpdb->get_row(
			$wpdb->prepare(
				"SELECT COUNT(*) AS active_count, SUM(severity >= %d) AS attention_count, COALESCE(MAX(severity), 0) AS max_severity FROM {$wpdb->prefix}login_armor_incidents WHERE status = %s",
				self::SEVERITY_MEDIUM,
				self::STATUS_ACTIVE
			)
		);

		$count     = $row ? (int) $row->active_count : 0;
		$attention = $row ? (int) $row->attention_count : 0;

		return array(
			'count'        => $count,
			'attention'    => $attention,
			'observations' => max( 0, $count - $attention ),
			'max_severity' => $row ? (int) $row->max_severity : 0,
		);
	}

	/**
	 * Persist the AI analysis of an incident onto its own row (2.7.1).
	 *
	 * Writing through the row rather than a transient is what makes the
	 * analysis survive: the drill-down reads it back on every render, an object
	 * cache cannot evict it, and it is deleted with the incident it describes
	 * (retention purge and uninstall both drop rows, never a separate store).
	 *
	 * A failed write is never silent (2.7.2). The analysis has already been
	 * generated and billed by the time this runs, so losing it without a word
	 * is the one outcome worth engineering against: the administrator sees the
	 * text once, navigates away, is offered the button again, and pays a
	 * second time for the same reading. That is the exact defect the stored
	 * analysis was introduced to end, reappearing through the back door.
	 *
	 * @param int    $id          Incident row to stamp.
	 * @param string $html        Already-escaped analysis HTML.
	 * @param string $fingerprint State that produced it, from IncidentExplainer.
	 * @return bool True when the row was written.
	 */
	public static function store_analysis( int $id, string $html, string $fingerprint ): bool {
		if ( $id <= 0 || '' === $html ) {
			return false;
		}

		if ( self::write_analysis( $id, $html, $fingerprint ) ) {
			delete_option( self::OPTION_SCHEMA_FAILURE );
			return true;
		}

		// The write failed. On a converged schema that means a database
		// problem this code cannot fix, and re-running the schema would be
		// pointless; the one cause worth acting on is a table that never
		// received the three columns 2.7.1 adds.
		//
		// That is not hypothetical: it was found on this plugin's own
		// production site. An earlier build had already stamped the version,
		// so maybe_run_db_upgrade() returned on its first line and the step
		// that adds the columns never ran. It was repaired by hand, which is
		// not a repair anyone else would get. A refused ALTER reaches the same
		// state from a published release, and so does a half-restored backup.
		//
		// Converging here rather than at the migration is deliberate. The
		// version stamp written by create_tables() predates every release in
		// the changelog, is reached by six upgrade steps, and tightening it
		// would make a site whose ALTER fails re-run the entire ladder on
		// every request. Repairing at the point of use fixes the same state
		// through whichever door it came, and costs one schema read.
		if ( self::converge_schema_once() && self::write_analysis( $id, $html, $fingerprint ) ) {
			delete_option( self::OPTION_SCHEMA_FAILURE );
			return true;
		}

		update_option(
			self::OPTION_SCHEMA_FAILURE,
			array(
				'at'      => gmdate( 'Y-m-d H:i:s' ),
				'missing' => self::missing_analysis_columns(),
			),
			false
		);
		return false;
	}

	/**
	 * The one UPDATE, so the caller can retry it after repairing the schema.
	 *
	 * Impure by nature, and it has to be said out loud: static analysis sees
	 * two calls with identical arguments, assumes the second answers like the
	 * first, and concludes the retry can never succeed. Between them the
	 * schema has changed, which is the entire point.
	 *
	 * @phpstan-impure
	 *
	 * @param int    $id          Incident row to stamp.
	 * @param string $html        Already-escaped analysis HTML.
	 * @param string $fingerprint State that produced it.
	 */
	private static function write_analysis( int $id, string $html, string $fingerprint ): bool {
		global $wpdb;

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Custom plugin table, analysis write.
		$ok = $wpdb->update(
			self::table(),
			array(
				'ai_analysis'    => $html,
				'ai_analysis_fp' => substr( $fingerprint, 0, 40 ),
				'ai_analysed_at' => current_time( 'mysql', true ),
			),
			array( 'id' => $id ),
			array( '%s', '%s', '%s' ),
			array( '%d' )
		);
		return false !== $ok;
	}

	/**
	 * Which of the analysis columns the live table is missing (2.7.2).
	 *
	 * An empty array means either a converged schema or a table this code
	 * could not read at all. The two are deliberately not distinguished: this
	 * answers "is THIS the problem", and a table that cannot be described is a
	 * different problem with a louder failure of its own.
	 *
	 * @return string[] Column names, in declaration order.
	 */
	public static function missing_analysis_columns(): array {
		global $wpdb;

		// %i is the identifier placeholder core added in 6.2, and the plugin
		// requires 6.8: the table name goes through prepare() like any other
		// value, rather than being concatenated behind a silenced sniff.
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Schema probe: no user input, and nothing about it is cacheable.
		$present = $wpdb->get_col( $wpdb->prepare( 'SHOW COLUMNS FROM %i', self::table() ) );
		if ( ! is_array( $present ) || empty( $present ) ) {
			return array();
		}

		return array_values( array_diff( self::ANALYSIS_COLUMNS, $present ) );
	}

	/**
	 * Run the schema once, at most once an hour (2.7.2).
	 *
	 * dbDelta is idempotent, so on a healthy site this is a schema read and
	 * nothing else. The hour is what keeps a database that refuses ALTER from
	 * re-running every CREATE TABLE the plugin owns on every analysis.
	 *
	 * @return bool True when the schema was actually re-run.
	 */
	private static function converge_schema_once(): bool {
		// 2.8.0: the gate and the repair are shared with the login log, which
		// repairs the same way when its own write fails. Same transient name,
		// so the hour is counted once for the whole plugin.
		if ( ! class_exists( '\LoginArmor\LoginArmor', false ) ) {
			return false;
		}
		return \LoginArmor\LoginArmor::repair_schema_once();
	}

	/**
	 * Count the distinct IP addresses across the incidents matching a filter.
	 *
	 * Replaces a loop that pulled 500 whole rows just to count them in PHP: it
	 * was capped, so the figure it produced was a sample rather than a count,
	 * and since 2.7.1 a row carries its AI analysis, so `SELECT *` at that
	 * volume would now drag the analysis text along with it for nothing.
	 *
	 * @param array<string,mixed> $filters Same keys as get_filtered().
	 */
	public static function count_distinct_ips( array $filters ): int {
		global $wpdb;
		list( $where, $params ) = self::build_where( $filters );

		// The statement is written out in both branches rather than assembled
		// into a variable first: a variable defeats the static escaping check,
		// which then has to be silenced instead of satisfied. And with nothing
		// to bind, $where is exactly '1=1', so the clause is left out
		// altogether rather than interpolated: same result, nothing to excuse.
		if ( empty( $params ) ) {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Custom plugin table, aggregate with no user value in it.
			return (int) $wpdb->get_var( "SELECT COUNT(DISTINCT ip) FROM {$wpdb->prefix}login_armor_incidents WHERE ip <> ''" );
		}
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.InterpolatedNotPrepared,WordPress.DB.PreparedSQL.NotPrepared,WordPress.DB.PreparedSQLPlaceholders.ReplacementsWrongNumber,WordPress.DB.PreparedSQLPlaceholders.UnfinishedPrepare,PluginCheck.Security.DirectDB.UnescapedDBParameter -- $where built from a validated whitelist in build_where(); every user value goes through a %s/%d placeholder in $params.
		return (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(DISTINCT ip) FROM {$wpdb->prefix}login_armor_incidents WHERE ip <> '' AND {$where}", $params ) );
	}

	/**
	 * Resolve an incident by id (mark it as resolved).
	 */
	public static function resolve( int $id ): bool {
		global $wpdb;
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Custom plugin table, admin action.
		return false !== $wpdb->update( self::table(), array( 'status' => self::STATUS_RESOLVED ), array( 'id' => $id ), array( '%s' ), array( '%d' ) );
	}

	/**
	 * Ignore an incident by id.
	 */
	public static function ignore( int $id ): bool {
		global $wpdb;
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Custom plugin table, admin action.
		return false !== $wpdb->update( self::table(), array( 'status' => self::STATUS_IGNORED ), array( 'id' => $id ), array( '%s' ), array( '%d' ) );
	}

	/**
	 * Set a new status on many incidents at once.
	 *
	 * Applies to every selected incident regardless of its current status, so
	 * a "Select all → Mark resolved/Ignore" works on resolved/ignored rows too
	 * (e.g. bulk-ignoring a pile of already-resolved incidents to declutter).
	 * IDs are cast to int and de-duplicated; an empty list is a no-op.
	 *
	 * @param int[]  $ids    Incident IDs.
	 * @param string $status One of STATUS_RESOLVED or STATUS_IGNORED.
	 * @return int Number of rows updated.
	 */
	public static function bulk_set_status( array $ids, string $status ): int {
		global $wpdb;

		if ( ! in_array( $status, array( self::STATUS_RESOLVED, self::STATUS_IGNORED ), true ) ) {
			return 0;
		}
		$ids = array_values( array_unique( array_filter( array_map( 'intval', $ids ), static fn( $id ) => $id > 0 ) ) );
		if ( empty( $ids ) ) {
			return 0;
		}

		$placeholders = implode( ',', array_fill( 0, count( $ids ), '%d' ) );
		$params       = array_merge( array( $status ), $ids );

		// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.InterpolatedNotPrepared,WordPress.DB.PreparedSQL.NotPrepared,WordPress.DB.PreparedSQLPlaceholders.ReplacementsWrongNumber,WordPress.DB.PreparedSQLPlaceholders.UnfinishedPrepare,PluginCheck.Security.DirectDB.UnescapedDBParameter -- $placeholders is a fixed list of %d tokens; every value is bound via the $params array passed to prepare().
		$result = $wpdb->query(
			$wpdb->prepare(
				"UPDATE {$wpdb->prefix}login_armor_incidents SET status = %s WHERE id IN ({$placeholders})",
				$params
			)
		);
		// phpcs:enable WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.InterpolatedNotPrepared,WordPress.DB.PreparedSQL.NotPrepared,WordPress.DB.PreparedSQLPlaceholders.ReplacementsWrongNumber,WordPress.DB.PreparedSQLPlaceholders.UnfinishedPrepare,PluginCheck.Security.DirectDB.UnescapedDBParameter

		return false === $result ? 0 : (int) $result;
	}

	/**
	 * Bulk mark incidents as resolved. Returns rows updated.
	 *
	 * @param int[] $ids Incident IDs.
	 */
	public static function bulk_resolve( array $ids ): int {
		return self::bulk_set_status( $ids, self::STATUS_RESOLVED );
	}

	/**
	 * Bulk mark incidents as ignored. Returns rows updated.
	 *
	 * @param int[] $ids Incident IDs.
	 */
	public static function bulk_ignore( array $ids ): int {
		return self::bulk_set_status( $ids, self::STATUS_IGNORED );
	}

	/**
	 * Fetch a single incident by its primary key.
	 */
	public static function find_by_id( int $id ): ?self {
		global $wpdb;
		if ( $id <= 0 ) {
			return null;
		}
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Custom plugin table, drill-down lookup.
		$row = $wpdb->get_row(
			$wpdb->prepare(
				"SELECT * FROM {$wpdb->prefix}login_armor_incidents WHERE id = %d LIMIT 1",
				$id
			)
		);
		return $row ? self::from_row( $row ) : null;
	}

	/**
	 * Return a filtered, paginated list of incidents.
	 *
	 * @param array<string,mixed> $filters Accepted keys: status, pattern, severity, period.
	 * @param int                 $limit   Max rows.
	 * @param int                 $offset  Offset.
	 * @return self[]
	 */
	public static function get_filtered( array $filters, int $limit = 50, int $offset = 0 ): array {
		global $wpdb;
		list( $where, $params ) = self::build_where( $filters );
		$params[] = $limit;
		$params[] = $offset;

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.InterpolatedNotPrepared,WordPress.DB.PreparedSQL.NotPrepared,WordPress.DB.PreparedSQLPlaceholders.ReplacementsWrongNumber,WordPress.DB.PreparedSQLPlaceholders.UnfinishedPrepare,PluginCheck.Security.DirectDB.UnescapedDBParameter -- $where built from a validated whitelist in build_where(); all user values go through %s/%d placeholders in $params passed as array, Plugin Check cannot statically count them.
		$rows = $wpdb->get_results( $wpdb->prepare( "SELECT * FROM {$wpdb->prefix}login_armor_incidents WHERE {$where} ORDER BY last_seen_at DESC LIMIT %d OFFSET %d", $params ) );

		$out = array();
		if ( is_array( $rows ) ) {
			foreach ( $rows as $row ) {
				$out[] = self::from_row( $row );
			}
		}
		return $out;
	}

	/**
	 * Return the total count matching the same filters as `get_filtered()`.
	 *
	 * @param array<string,mixed> $filters Accepted keys: status, pattern, severity, period.
	 */
	public static function count_filtered( array $filters ): int {
		global $wpdb;
		list( $where, $params ) = self::build_where( $filters );

		if ( empty( $params ) ) {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Custom plugin table, full count.
			return (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$wpdb->prefix}login_armor_incidents" );
		}
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.InterpolatedNotPrepared,WordPress.DB.PreparedSQL.NotPrepared,WordPress.DB.PreparedSQLPlaceholders.ReplacementsWrongNumber,WordPress.DB.PreparedSQLPlaceholders.UnfinishedPrepare,PluginCheck.Security.DirectDB.UnescapedDBParameter -- $where built from a validated whitelist in build_where(); all user values go through %s/%d placeholders in $params passed as array, Plugin Check cannot statically count them.
		return (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM {$wpdb->prefix}login_armor_incidents WHERE {$where}", $params ) );
	}

	/**
	 * The status the incident list shows, from its `status` query value
	 * (2.7.10).
	 *
	 * The list opens on the open incidents: what is left to do. It used to
	 * open on every state, and a site whose incidents had all been dealt with
	 * still showed them, ignored and resolved, as the first thing on the tab.
	 * "All" therefore needs a value of its own, `all`, since no value now
	 * means open. Anything else unknown is the default, as no value is.
	 *
	 * @param string $raw Sanitised `status` query value, '' when absent.
	 * @return string 'all', or one of the STATUS_* constants.
	 */
	public static function list_status_choice( string $raw ): string {
		return in_array( $raw, array( 'all', self::STATUS_ACTIVE, self::STATUS_RESOLVED, self::STATUS_IGNORED ), true ) ? $raw : self::STATUS_ACTIVE;
	}

	/**
	 * Normalise a raw filter set (query string, POST body, CLI options) into
	 * the canonical array every incident query takes.
	 *
	 * ONE whitelist, reached by the list view, the bulk endpoint and WP-CLI
	 * alike (2.7.1). "Apply to all 235 matching your filter" is a promise about
	 * a set the administrator is looking at; if the screen and the UPDATE
	 * parsed their filters separately, the two could drift and the button would
	 * quietly touch rows the list never showed. Anything unrecognised is
	 * dropped rather than passed through, so `empty()` on the result is a
	 * reliable answer to "was any filter actually given?" and a destructive
	 * bulk command can refuse to run on nothing.
	 *
	 * Values are expected already unslashed; nothing here is escaped, because
	 * every one of these goes on to a %s or %d placeholder in build_where().
	 *
	 * @param array<string,mixed> $raw Anything; only known keys survive.
	 * @return array<string,mixed>
	 */
	public static function sanitize_filters( array $raw ): array {
		$out = array();

		if ( isset( $raw['status'] ) && in_array( (string) $raw['status'], array( self::STATUS_ACTIVE, self::STATUS_RESOLVED, self::STATUS_IGNORED ), true ) ) {
			$out['status'] = (string) $raw['status'];
		}
		if ( isset( $raw['pattern'] ) && in_array( (string) $raw['pattern'], self::patterns(), true ) ) {
			$out['pattern'] = (string) $raw['pattern'];
		}
		if ( isset( $raw['severity'] ) && (int) $raw['severity'] >= 1 && (int) $raw['severity'] <= 4 ) {
			$out['severity'] = (int) $raw['severity'];
		}
		if ( isset( $raw['min_severity'] ) && (int) $raw['min_severity'] > 1 && (int) $raw['min_severity'] <= 4 ) {
			$out['min_severity'] = (int) $raw['min_severity'];
		}
		if ( isset( $raw['period'] ) && in_array( (string) $raw['period'], array( '24h', '7d', '30d' ), true ) ) {
			$out['period'] = (string) $raw['period'];
		}

		return $out;
	}

	/**
	 * Every pattern the classifier and the modules can record.
	 *
	 * @return string[]
	 */
	public static function patterns(): array {
		return array(
			self::PATTERN_BRUTE_FORCE,
			self::PATTERN_CREDENTIAL_STUFFING,
			self::PATTERN_ENUMERATION,
			self::PATTERN_DISTRIBUTED,
			self::PATTERN_POST_COMPROMISE,
			self::PATTERN_RESERVED_USERNAME_PROBE,
			self::PATTERN_BOT_HONEYPOT_CAUGHT,
			self::PATTERN_2FA_RECOVERY_REQUESTED,
			self::PATTERN_FIREWALL_BLOCK,
			self::PATTERN_POW_FAILED,
			self::PATTERN_APP_PASSWORD_REFUSED,
		);
	}

	/**
	 * Largest number of incidents one filtered bulk operation may change.
	 *
	 * A bulk action driven by a filter has no natural size: "everything open"
	 * is 235 rows on the site that prompted this and could be a hundred
	 * thousand on a neglected one. Rather than hold a write lock over an
	 * unbounded set until PHP gives up halfway through, the operation works in
	 * batches up to this ceiling, reports exactly how many rows it changed, and
	 * leaves the rest for the next click. A partial result the caller is told
	 * about beats a timeout the caller has to guess at.
	 */
	public static function bulk_max(): int {
		/**
		 * Filter the ceiling of one filtered bulk incident operation.
		 *
		 * @param int $max Default 10000.
		 */
		$max = (int) apply_filters( 'login_armor_incident_bulk_max', 10000 );
		return max( 1, $max );
	}

	/** Rows changed per UPDATE statement inside a filtered bulk operation. */
	private const BULK_BATCH = 500;

	/**
	 * The same filter, narrowed to the rows a bulk operation would still change.
	 *
	 * Counting "what is left" with the plain filter reports work that does not
	 * exist: `--pattern=firewall_block` still matches every row the operation
	 * just resolved. Only rows not yet in the target status are pending.
	 *
	 * @param array<string,mixed> $filters Canonical filters.
	 * @param string              $status  Target status.
	 * @return array<string,mixed>
	 */
	public static function pending( array $filters, string $status ): array {
		$filters['not_status'] = $status;
		return $filters;
	}

	/**
	 * Apply a status to every incident matching a filter, by FILTER.
	 *
	 * The alternative was to send the administrator's browser a list of 235
	 * ids and update those. That is a second source of truth for "which rows
	 * did the button promise", it grows without bound in a POST body, and it
	 * is stale the moment anything new matches. The filter is what the screen
	 * showed, so the filter is what the UPDATE uses.
	 *
	 * `status <> target` is what makes the batched loop terminate: every batch
	 * strictly shrinks the matching set. Without it, a filter that does not
	 * name a status would keep matching the same first rows forever. Rows
	 * already in the target state are the only ones skipped, and changing them
	 * would have been a no-op anyway.
	 *
	 * @param array<string,mixed> $filters Canonical filters, from sanitize_filters().
	 * @param string              $status  STATUS_RESOLVED or STATUS_IGNORED.
	 * @return int Rows actually changed.
	 */
	public static function bulk_set_status_filtered( array $filters, string $status ): int {
		global $wpdb;

		if ( ! in_array( $status, array( self::STATUS_RESOLVED, self::STATUS_IGNORED ), true ) ) {
			return 0;
		}

		// The same WHERE the "how many are left" count uses, so the promise,
		// the write and the report are one predicate, not three.
		list( $where, $where_params ) = self::build_where( self::pending( $filters, $status ) );

		$ceiling = self::bulk_max();
		$changed = 0;

		while ( $changed < $ceiling ) {
			$batch  = min( self::BULK_BATCH, $ceiling - $changed );
			$params = array_merge( array( $status ), $where_params, array( $batch ) );

			// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.InterpolatedNotPrepared,WordPress.DB.PreparedSQL.NotPrepared,WordPress.DB.PreparedSQLPlaceholders.ReplacementsWrongNumber,WordPress.DB.PreparedSQLPlaceholders.UnfinishedPrepare,PluginCheck.Security.DirectDB.UnescapedDBParameter -- $where is built from the validated whitelist in build_where(); every value, the batch size included, goes through a %s/%d placeholder in $params passed as an array, which Plugin Check cannot statically count.
			$rows = $wpdb->query(
				$wpdb->prepare(
					"UPDATE {$wpdb->prefix}login_armor_incidents SET status = %s WHERE {$where} ORDER BY id LIMIT %d",
					$params
				)
			);
			// phpcs:enable WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.InterpolatedNotPrepared,WordPress.DB.PreparedSQL.NotPrepared,WordPress.DB.PreparedSQLPlaceholders.ReplacementsWrongNumber,WordPress.DB.PreparedSQLPlaceholders.UnfinishedPrepare,PluginCheck.Security.DirectDB.UnescapedDBParameter

			if ( false === $rows || (int) $rows <= 0 ) {
				break;
			}
			$changed += (int) $rows;
		}

		return $changed;
	}

	/**
	 * Translate a filter array into a parameterised WHERE clause.
	 *
	 * @param array<string,mixed> $filters
	 * @return array{0:string,1:array<int,mixed>}
	 */
	private static function build_where( array $filters ): array {
		$clauses = array( '1=1' );
		$params  = array();

		$allowed_status   = array( self::STATUS_ACTIVE, self::STATUS_RESOLVED, self::STATUS_IGNORED );
		$allowed_patterns = self::patterns();

		if ( ! empty( $filters['status'] ) && in_array( $filters['status'], $allowed_status, true ) ) {
			$clauses[] = 'status = %s';
			$params[]  = $filters['status'];
		}
		// 2.7.1: rows NOT already in a given status. It is what makes the
		// batched filtered UPDATE terminate (each batch strictly shrinks the
		// matching set), and it is the only honest way to count what is left
		// afterwards: a filter that never mentioned a status still matches
		// every row it just changed, so counting those would report work
		// remaining on an operation that finished.
		if ( ! empty( $filters['not_status'] ) && in_array( $filters['not_status'], $allowed_status, true ) ) {
			$clauses[] = 'status <> %s';
			$params[]  = $filters['not_status'];
		}
		if ( ! empty( $filters['pattern'] ) && in_array( $filters['pattern'], $allowed_patterns, true ) ) {
			$clauses[] = 'pattern = %s';
			$params[]  = $filters['pattern'];
		}
		if ( isset( $filters['severity'] ) && (int) $filters['severity'] >= 1 && (int) $filters['severity'] <= 4 ) {
			$clauses[] = 'severity = %d';
			$params[]  = (int) $filters['severity'];
		}
		// 2.7.1: a floor, not an exact level. The Incidents tab defaults to
		// severity 2 and above, because a severity 1 row is an observation and
		// counting 235 of them as open incidents in red is what made an
		// administrator think his site was under attack. An exact `severity`
		// filter is more specific, so it wins: asking for level 1 explicitly
		// must reach the observations, whatever the floor would have said.
		if ( ! isset( $filters['severity'] ) && isset( $filters['min_severity'] ) && (int) $filters['min_severity'] > 1 && (int) $filters['min_severity'] <= 4 ) {
			$clauses[] = 'severity >= %d';
			$params[]  = (int) $filters['min_severity'];
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
				$clauses[] = 'last_seen_at > DATE_SUB(UTC_TIMESTAMP(), INTERVAL %d HOUR)';
				$params[]  = $hours;
			}
		}

		return array( implode( ' AND ', $clauses ), $params );
	}

	/**
	 * Return raw log rows correlated to an incident.
	 * Matches by IP if set, else by target username, within [started_at, last_seen_at+5min].
	 *
	 * @return array<int,object>
	 */
	public static function get_correlated_events( int $id, int $limit = 500 ): array {
		global $wpdb;
		$inc = self::find_by_id( $id );
		if ( null === $inc ) {
			return array();
		}
		$limit = max( 1, min( 2000, $limit ) );

		/*
		 * Lookback window: the Classifier computes `events_count` /
		 * `unique_usernames` from all failures within WINDOW_MINUTES_SHORT
		 * at the moment of the pattern trigger: which can include events
		 * BEFORE `started_at` (e.g. fabrice attempts at 10:18:25 feeding
		 * metrics that push adminer at 10:18:40 past the threshold).
		 * Previously the timeline query started exactly at `started_at`,
		 * so those precursor events were invisible and the stats header
		 * appeared to "lie" (5 attempts / 2 usernames stored but only 3 /
		 * 1 visible). Mirror the Classifier's window so stats and timeline
		 * live in the same universe: Lot 18 V10.14.
		 *
		 * The window is per-pattern, because the Classifier does not use one:
		 * post_compromise counts failures over WINDOW_MINUTES_COMPROMISE and
		 * distributed counts IPs over WINDOW_MINUTES_LONG. Pinning every
		 * timeline to WINDOW_MINUTES_SHORT reintroduced the exact bug this
		 * comment describes on those two patterns: a user-reported incident
		 * announced "success after numerous failures" while showing a single
		 * failure, the others sitting 10 to 60 minutes before `started_at`.
		 */
		$lookback = 10;
		if ( class_exists( '\LoginArmor\Detection\Classifier' ) ) {
			switch ( $inc->pattern ) {
				case self::PATTERN_POST_COMPROMISE:
					$lookback = (int) \LoginArmor\Detection\Classifier::WINDOW_MINUTES_COMPROMISE;
					break;
				case self::PATTERN_DISTRIBUTED:
					$lookback = (int) \LoginArmor\Detection\Classifier::WINDOW_MINUTES_LONG;
					break;
				default:
					$lookback = (int) \LoginArmor\Detection\Classifier::WINDOW_MINUTES_SHORT;
			}
		}

		// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Custom plugin table, drill-down timeline.
		if ( '' !== $inc->ip ) {
			$rows = $wpdb->get_results(
				$wpdb->prepare(
					"SELECT id, ip, username, status, log_time, user_agent, reason FROM {$wpdb->prefix}login_armor_logs WHERE ip = %s AND log_time BETWEEN DATE_SUB(%s, INTERVAL %d MINUTE) AND DATE_ADD(%s, INTERVAL 5 MINUTE) ORDER BY log_time ASC LIMIT %d",
					$inc->ip,
					$inc->started_at,
					$lookback,
					$inc->last_seen_at,
					$limit
				)
			);
		} elseif ( '' !== $inc->target_username ) {
			$rows = $wpdb->get_results(
				$wpdb->prepare(
					"SELECT id, ip, username, status, log_time, user_agent, reason FROM {$wpdb->prefix}login_armor_logs WHERE username = %s AND log_time BETWEEN DATE_SUB(%s, INTERVAL %d MINUTE) AND DATE_ADD(%s, INTERVAL 5 MINUTE) ORDER BY log_time ASC LIMIT %d",
					$inc->target_username,
					$inc->started_at,
					$lookback,
					$inc->last_seen_at,
					$limit
				)
			);
		} else {
			$rows = array();
		}
		// phpcs:enable

		return is_array( $rows ) ? $rows : array();
	}

	/**
	 * Convert a raw $wpdb row into a typed Incident instance.
	 *
	 * @param object $row Raw DB row.
	 */
	private static function from_row( object $row ): self {
		$i                   = new self();
		$i->id               = (int) $row->id;
		$i->pattern          = (string) $row->pattern;
		$i->severity         = (int) $row->severity;
		$i->started_at       = (string) $row->started_at;
		$i->last_seen_at     = (string) $row->last_seen_at;
		$i->ip               = (string) $row->ip;
		$i->subnet           = (string) $row->subnet;
		$i->target_username  = (string) $row->target_username;
		$i->events_count     = (int) $row->events_count;
		$i->unique_ips       = (int) $row->unique_ips;
		$i->unique_usernames = (int) $row->unique_usernames;
		$i->status           = (string) $row->status;
		// `vector` column added in 2.1.17: tolerate rows from a not-yet-migrated schema.
		$i->vector           = isset( $row->vector ) ? (string) $row->vector : self::VECTOR_LOGIN_FORM;
		// AI analysis columns added in 2.7.1. Same tolerance: a site whose
		// upgrade ladder has not run yet must render its incidents normally,
		// simply without a stored analysis, never fatal on a missing property.
		$i->ai_analysis      = isset( $row->ai_analysis ) ? (string) $row->ai_analysis : '';
		$i->ai_analysis_fp   = isset( $row->ai_analysis_fp ) ? (string) $row->ai_analysis_fp : '';
		$i->ai_analysed_at   = isset( $row->ai_analysed_at ) ? (string) $row->ai_analysed_at : '';
		return $i;
	}
}
