<?php
/**
 * Activity Log orchestrator.
 *
 * Checks if the module is enabled, creates the DB table on first enable,
 * instantiates the 7 hook-driven loggers (User, Post, Media, Plugin, Theme,
 * Option, TwoFactor), and manages the daily purge cron. An 8th logger,
 * SettingsLogger, records a settings import when the importer calls it
 * directly, and since 2.7.9 a reset of the detection data, through the
 * login_armor_data_reset action it is subscribed to here.
 *
 * @package LoginArmor\ActivityLog
 * @since   2.1.0
 */

namespace LoginArmor\ActivityLog;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Activity Log module entry point.
 */
class ActivityLog {

	/** @var string Option key for module enabled state. */
	public const OPTION_ENABLED = 'login_armor_activity_enabled';

	/** @var string Option key for retention period in days. */
	public const OPTION_RETENTION = 'login_armor_activity_retention';

	/** @var string Cron hook name. */
	public const CRON_HOOK = 'login_armor_activity_purge';

	// ── Chain crypto (V2.1.1+) ──────────────────────────────────────

	/** @var string Genesis sentinel for chain start (64 hex zeros). */
	public const CHAIN_GENESIS_HASH = '0000000000000000000000000000000000000000000000000000000000000000';

	/** @var string Option key for chain start ID (set on first INSERT post-upgrade by Task B4). */
	public const OPTION_CHAIN_START_ID = 'login_armor_activity_chain_start_id';

	/**
	 * @var string Option key for the chain secret fingerprint (V2.1.20).
	 *
	 * Stores a one-way fingerprint of wp_salt('auth') so verify_chain() can tell
	 * a genuine tamper apart from a benign security-key rotation (site migration,
	 * restored backup, manual wp-config.php key change). NEVER stores the salt
	 * itself: only an HMAC of a fixed label keyed by the salt.
	 */
	public const OPTION_CHAIN_SALT_FP = 'login_armor_activity_chain_salt_fp';

	/**
	 * Canonical column order for HMAC payload: FROZEN FOREVER.
	 *
	 * NEVER reorder, remove, or append entries. Adding a new schema column in
	 * a future version (e.g. V2.2 adds `request_uri`) requires a chain reset
	 * (new OPTION_CHAIN_START_ID) and a separate CANONICAL_COLUMNS_V2 constant
	 * to keep legacy rows verifiable. Touching this array invalidates every
	 * prior row's row_hash silently: verify_chain() would report broken from
	 * the first post-upgrade row.
	 *
	 * @var array<int,string>
	 */
	public const CANONICAL_COLUMNS = [
		'user_id', 'user_login', 'user_role', 'action', 'object_type',
		'object_id', 'object_name', 'description', 'ip', 'log_time',
	];

	/**
	 * Constructor. Bails early if disabled: zero overhead.
	 */
	public function __construct() {
		if ( ! self::is_enabled() ) {
			return;
		}

		$this->init_loggers();

		// Daily purge cron.
		add_action( self::CRON_HOOK, [ self::class, 'purge' ] );

		// V2.1.1: chain integrity crons. Registered conditionally inside
		// is_enabled() so disabling the module disconnects the handlers
		// without leaving zombie events firing against a torn-down chain.
		add_action( 'login_armor_chain_repair', [ self::class, 'repair_chain' ] );
		add_action( 'login_armor_chain_auto_verify', [ self::class, 'cron_auto_verify' ] );
	}

	/**
	 * Check if the Activity Log module is enabled.
	 */
	public static function is_enabled(): bool {
		return (bool) get_option( self::OPTION_ENABLED, false );
	}

	/**
	 * Switch the module on the way the admin handler does: create the table,
	 * set the option, schedule the purge cron. Idempotent.
	 *
	 * @since 2.6.0 Shared by SafeBaseline and the settings importer.
	 */
	public static function enable(): void {
		self::create_table();
		update_option( self::OPTION_ENABLED, true );
		if ( ! wp_next_scheduled( self::CRON_HOOK ) ) {
			wp_schedule_event( time(), 'daily', self::CRON_HOOK );
		}
	}

	/**
	 * Create the activity log database table.
	 *
	 * Called on first enable (not on plugin activation).
	 */
	public static function create_table(): void {
		require_once ABSPATH . 'wp-admin/includes/upgrade.php';
		dbDelta( self::table_statement() );
	}

	/**
	 * The CREATE TABLE statement of the activity table.
	 *
	 * Split out of create_table() in 2.8.0 so the schema check
	 * (LoginArmor::missing_schema_columns()) reads the same columns.
	 */
	public static function table_statement(): string {
		global $wpdb;

		$charset_collate = $wpdb->get_charset_collate();
		$table           = $wpdb->prefix . 'login_armor_activity';

		return "CREATE TABLE {$table} (
			id bigint(20) UNSIGNED NOT NULL AUTO_INCREMENT,
			user_id bigint(20) UNSIGNED NOT NULL,
			user_login varchar(60) NOT NULL,
			user_role varchar(30) NOT NULL,
			action varchar(50) NOT NULL,
			object_type varchar(30) NOT NULL,
			object_id bigint(20) UNSIGNED NOT NULL DEFAULT 0,
			object_name varchar(255) NOT NULL DEFAULT '',
			description text NOT NULL,
			ip varchar(100) NOT NULL DEFAULT '',
			log_time datetime NOT NULL,
			prev_hash char(64) NULL,
			row_hash char(64) NULL,
			PRIMARY KEY  (id),
			KEY log_time (log_time),
			KEY user_id_time (user_id, log_time),
			KEY object_type_time (object_type, log_time),
			KEY row_hash (row_hash)
		) $charset_collate;";
	}

	/**
	 * Query activity logs with optional filters.
	 *
	 * @param array<string,string> $filters  Keys: object_type, user_id, period.
	 * @param int                  $per_page Results per page.
	 * @param int                  $offset   SQL offset.
	 * @return array<int,object>
	 */
	public static function get_logs( array $filters = [], int $per_page = 50, int $offset = 0 ): array {
		global $wpdb;

		$table  = $wpdb->prefix . 'login_armor_activity';
		$where  = [];
		$values = [];

		if ( ! empty( $filters['object_type'] ) ) {
			$where[]  = 'object_type = %s';
			$values[] = $filters['object_type'];
		}

		if ( ! empty( $filters['user_id'] ) ) {
			$where[]  = 'user_id = %d';
			$values[] = (int) $filters['user_id'];
		}

		if ( ! empty( $filters['period'] ) ) {
			$cutoff = self::period_to_cutoff( $filters['period'] );
			if ( $cutoff ) {
				$where[]  = 'log_time >= %s';
				$values[] = $cutoff;
			}
		}

		$sql = "SELECT * FROM {$table}";
		if ( ! empty( $where ) ) {
			$sql .= ' WHERE ' . implode( ' AND ', $where );
		}
		$sql .= ' ORDER BY log_time DESC, id DESC LIMIT %d OFFSET %d';

		$values[] = $per_page;
		$values[] = $offset;

		// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared,PluginCheck.Security.DirectDB.UnescapedDBParameter -- Dynamic query built safely with $wpdb->prepare().
		$sql = $wpdb->prepare( $sql, ...$values );

		// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,PluginCheck.Security.DirectDB.UnescapedDBParameter -- Dynamic query built safely with $wpdb->prepare().
		return $wpdb->get_results( $sql );
	}

	/**
	 * Count activity logs matching filters.
	 *
	 * @param array<string,string> $filters Keys: object_type, user_id, period.
	 * @return int
	 */
	public static function count_logs( array $filters = [] ): int {
		global $wpdb;

		$table  = $wpdb->prefix . 'login_armor_activity';
		$where  = [];
		$values = [];

		if ( ! empty( $filters['object_type'] ) ) {
			$where[]  = 'object_type = %s';
			$values[] = $filters['object_type'];
		}

		if ( ! empty( $filters['user_id'] ) ) {
			$where[]  = 'user_id = %d';
			$values[] = (int) $filters['user_id'];
		}

		if ( ! empty( $filters['period'] ) ) {
			$cutoff = self::period_to_cutoff( $filters['period'] );
			if ( $cutoff ) {
				$where[]  = 'log_time >= %s';
				$values[] = $cutoff;
			}
		}

		$sql = "SELECT COUNT(*) FROM {$table}";
		if ( ! empty( $where ) ) {
			$sql .= ' WHERE ' . implode( ' AND ', $where );
		}

		if ( ! empty( $values ) ) {
			// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared,PluginCheck.Security.DirectDB.UnescapedDBParameter -- Dynamic query built safely with $wpdb->prepare().
			$sql = $wpdb->prepare( $sql, ...$values );
		}

		// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,PluginCheck.Security.DirectDB.UnescapedDBParameter -- Dynamic query built safely with $wpdb->prepare().
		return (int) $wpdb->get_var( $sql );
	}

	/**
	 * Stream the filtered activity log as a CSV download to php://output.
	 *
	 * Caller must have already sent the Content-Type and Content-Disposition
	 * headers and called ob_end_clean(). Streams in batches of 500 to keep
	 * memory bounded on large logs.
	 *
	 * @param array<string,string> $filters Same keys as get_logs(): object_type, user_id, period.
	 */
	public static function export_csv_stream( array $filters = [] ): void {
		global $wpdb;

		$table  = $wpdb->prefix . 'login_armor_activity';
		$where  = [];
		$values = [];

		if ( ! empty( $filters['object_type'] ) ) {
			$where[]  = 'object_type = %s';
			$values[] = $filters['object_type'];
		}
		if ( ! empty( $filters['user_id'] ) ) {
			$where[]  = 'user_id = %d';
			$values[] = (int) $filters['user_id'];
		}
		if ( ! empty( $filters['period'] ) ) {
			$cutoff = self::period_to_cutoff( $filters['period'] );
			if ( $cutoff ) {
				$where[]  = 'log_time >= %s';
				$values[] = $cutoff;
			}
		}

		$where_sql = ! empty( $where ) ? ( 'WHERE ' . implode( ' AND ', $where ) ) : '';

		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fopen -- Streaming to php://output, WP_Filesystem does not support this.
		$handle = fopen( 'php://output', 'w' );
		if ( false === $handle ) {
			return;
		}

		// UTF-8 BOM so Excel opens the file as UTF-8 by default.
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fwrite -- Streaming to php://output, WP_Filesystem does not support this.
		fwrite( $handle, "\xEF\xBB\xBF" );

		fputcsv(
			$handle,
			[ 'id', 'log_time_utc', 'user_login', 'user_role', 'action', 'object_type', 'object_id', 'object_name', 'description', 'ip' ]
		);

		$batch_size = 500;
		$offset     = 0;

		while ( true ) {
			$batch_params   = $values;
			$batch_params[] = $batch_size;
			$batch_params[] = $offset;

			$sql = "SELECT id, log_time, user_login, user_role, action, object_type, object_id, object_name, description, ip FROM {$table} {$where_sql} ORDER BY log_time ASC, id ASC LIMIT %d OFFSET %d";

			// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,PluginCheck.Security.DirectDB.UnescapedDBParameter -- Dynamic query built safely with $wpdb->prepare(); $where_sql is a static string built from a whitelist of column names.
			$rows = $wpdb->get_results( $wpdb->prepare( $sql, ...$batch_params ) );

			if ( empty( $rows ) ) {
				break;
			}

			foreach ( $rows as $row ) {
				fputcsv(
					$handle,
					[
						(int) $row->id,
						(string) $row->log_time,
						\LoginArmor\Support\Csv::neutralize_field( $row->user_login ),
						\LoginArmor\Support\Csv::neutralize_field( $row->user_role ),
						\LoginArmor\Support\Csv::neutralize_field( $row->action ),
						\LoginArmor\Support\Csv::neutralize_field( $row->object_type ),
						(int) $row->object_id,
						\LoginArmor\Support\Csv::neutralize_field( $row->object_name ),
						\LoginArmor\Support\Csv::neutralize_field( $row->description ),
						(string) $row->ip,
					]
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

	/**
	 * Purge activity logs older than the retention period.
	 *
	 * @param int|null $days Override retention days. Null = use option.
	 * @return int Number of rows deleted.
	 */
	public static function purge( ?int $days = null ): int {
		global $wpdb;

		if ( $days === null ) {
			$days = (int) get_option( self::OPTION_RETENTION, 90 );
		}
		if ( $days <= 0 ) {
			return 0;
		}

		$cutoff = gmdate( 'Y-m-d H:i:s', time() - $days * DAY_IN_SECONDS );

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
		$deleted = (int) $wpdb->query(
			$wpdb->prepare(
				"DELETE FROM {$wpdb->prefix}login_armor_activity WHERE log_time < %s",
				$cutoff
			)
		);

		// The purge has just removed the beginning of the integrity chain, so
		// the recorded start of that chain has to follow it (2.7.3). Leaving it
		// behind is what made verification start from a row that no longer
		// existed and report the site as tampered with; verify_chain() now
		// seeds itself correctly either way, and this keeps the stored state
		// honest rather than relying on that recovery.
		if ( $deleted > 0 ) {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
			$oldest = (int) $wpdb->get_var(
				$wpdb->prepare( 'SELECT MIN(id) FROM %i', $wpdb->prefix . 'login_armor_activity' )
			);
			if ( $oldest > self::get_chain_start_id() ) {
				update_option( self::OPTION_CHAIN_START_ID, $oldest, false );
			}
		}

		return $deleted;
	}

	/**
	 * Get list of admin/editor users for the filter dropdown.
	 *
	 * @return array<int,object> Each with ->ID, ->user_login, ->display_name.
	 */
	public static function get_admin_users(): array {
		$users = get_users( [
			'role__in' => [ 'administrator', 'editor' ],
			'orderby'  => 'display_name',
			'order'    => 'ASC',
			'fields'   => [ 'ID', 'user_login', 'display_name' ],
		] );
		return $users;
	}

	/**
	 * Get the HMAC secret used to sign Activity Log rows.
	 *
	 * Aligned with TwoFactor / TrustedDevices: keyed on wp_salt('auth').
	 * AUTH_KEY rotation in wp-config.php breaks the chain cleanly: admins
	 * see a "chain reset at row N" notice on next verify, consistent with
	 * existing TOTP / TrustedDevices revoke behavior.
	 *
	 * @return string Secret string from wp_salt('auth'). Length varies by
	 *                wp-config.php (typically 64 chars; 128 when both
	 *                AUTH_KEY and SECURE_AUTH_KEY are defined). hash_hmac
	 *                accepts any non-empty length.
	 */
	public static function get_chain_secret(): string {
		return wp_salt( 'auth' );
	}

	/**
	 * Get the row ID at which the cryptographic chain begins.
	 *
	 * Set on first INSERT post-upgrade by the chain_initialized hook (Task B4).
	 * verify_chain() skips all rows with id < this value (legacy rows).
	 *
	 * @return int Row ID, or 0 if chain has not been initialized yet.
	 */
	public static function get_chain_start_id(): int {
		return (int) get_option( self::OPTION_CHAIN_START_ID, 0 );
	}

	/**
	 * Compute a one-way fingerprint of the current chain secret (V2.1.20).
	 *
	 * Used to detect a security-key rotation between two verifies. We HMAC a
	 * fixed label with the secret rather than storing the secret (or even a raw
	 * hash of it) so the option never leaks anything that could help reconstruct
	 * wp_salt('auth'). Truncated to 32 hex chars: collision risk is irrelevant
	 * for a "did this change?" equality test.
	 *
	 * @return string 32-char hex fingerprint.
	 */
	public static function salt_fingerprint(): string {
		return substr( hash_hmac( 'sha256', 'login_armor_chain_salt_fp', self::get_chain_secret() ), 0, 32 );
	}

	/**
	 * Persist the current chain-secret fingerprint as the trusted baseline.
	 *
	 * Called on first chain init, on the 2.1.20 upgrade (to baseline existing
	 * installs), and after reset_chain(). Autoload off: read only at verify time.
	 */
	public static function store_salt_fingerprint(): void {
		update_option( self::OPTION_CHAIN_SALT_FP, self::salt_fingerprint(), false );
	}

	/**
	 * Has the chain secret (wp_salt('auth')) changed since the last baseline?
	 *
	 * Returns false when no baseline has been stored yet (pre-2.1.20 installs
	 * before the upgrade runs): we cannot assert a change we never recorded,
	 * so the caller falls back to the historical "tampered" semantics.
	 *
	 * @return bool True when a baseline exists and no longer matches.
	 */
	public static function salt_changed(): bool {
		$stored = (string) get_option( self::OPTION_CHAIN_SALT_FP, '' );
		if ( '' === $stored ) {
			return false;
		}
		return ! hash_equals( $stored, self::salt_fingerprint() );
	}

	/**
	 * Coverage stats for the HMAC chain.
	 *
	 * Returns the count of rows IN the chain (id >= chain_start_id) and the
	 * count of rows BEFORE the chain (id < chain_start_id, "legacy" pre-V2.1.1
	 * rows or rows that predate the most recent chain re-init). Pre-chain rows
	 * are NOT verified by verify_chain(): surface this in the admin UI so
	 * admins know the integrity guarantee scope.
	 *
	 * @since 2.1.5
	 * @return array{scope_start_id:int,rows_covered:int,rows_pre_chain:int}
	 */
	public static function get_chain_coverage_stats(): array {
		global $wpdb;
		$table          = $wpdb->prefix . 'login_armor_activity';
		$chain_start_id = self::get_chain_start_id();

		// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
		$rows_covered = (int) $wpdb->get_var( $wpdb->prepare(
			'SELECT COUNT(*) FROM %i WHERE id >= %d',
			$table,
			$chain_start_id
		) );
		// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
		$rows_pre_chain = (int) $wpdb->get_var( $wpdb->prepare(
			'SELECT COUNT(*) FROM %i WHERE id < %d',
			$table,
			$chain_start_id
		) );

		return [
			'scope_start_id' => $chain_start_id,
			'rows_covered'   => $rows_covered,
			'rows_pre_chain' => $rows_pre_chain,
		];
	}

	/**
	 * Compute the canonical HMAC payload for a given row's data.
	 *
	 * Always uses the order defined in CANONICAL_COLUMNS: frozen forever
	 * to keep prior rows verifiable even if the DB schema gains columns.
	 *
	 * Caller contract: every key in CANONICAL_COLUMNS must be present in
	 * $row_data. Missing keys are silently coerced to empty string: this
	 * keeps the function total but masks logger bugs (e.g. a typo
	 * 'username' instead of 'user_login' produces a payload with
	 * "user_login":""). In WP_DEBUG mode the function emits _doing_it_wrong()
	 * on missing keys so CI / dev catch the omission.
	 *
	 * @param array<string,scalar|null> $row_data Row columns keyed by column name.
	 * @return string|false Canonical JSON-encoded payload, or false if
	 *                     wp_json_encode failed. Invalid UTF-8 bytes are
	 *                     replaced deterministically so one damaged field
	 *                     cannot freeze every later unsigned row.
	 */
	public static function canonical_payload( array $row_data ) {
		$ordered = [];
		foreach ( self::CANONICAL_COLUMNS as $col ) {
			if ( defined( 'WP_DEBUG' ) && WP_DEBUG && ! array_key_exists( $col, $row_data ) ) {
				_doing_it_wrong(
					__METHOD__,
					sprintf(
						/* translators: %s: missing column name */
						esc_html__( 'Missing canonical column in HMAC payload: %s', 'login-armor' ),
						esc_html( $col )
					),
					'2.1.1'
				);
			}
			$ordered[ $col ] = $row_data[ $col ] ?? '';
		}
		return wp_json_encode( $ordered, JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE );
	}

	/** Acquire the database advisory lock shared by every chain writer. */
	public static function acquire_chain_lock( int $timeout = 2 ): bool {
		global $wpdb;
		$database  = defined( 'DB_NAME' ) ? (string) DB_NAME : '';
		$lock_name = substr( 'login_armor_activity_' . md5( $database . '|' . $wpdb->prefix ), 0, 64 );
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Advisory lock for integrity-chain serialization.
		return 1 === (int) $wpdb->get_var( $wpdb->prepare( 'SELECT GET_LOCK(%s, %d)', $lock_name, max( 0, $timeout ) ) );
	}

	/** Release this connection's activity-chain advisory lock. */
	public static function release_chain_lock(): void {
		global $wpdb;
		$database  = defined( 'DB_NAME' ) ? (string) DB_NAME : '';
		$lock_name = substr( 'login_armor_activity_' . md5( $database . '|' . $wpdb->prefix ), 0, 64 );
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Paired advisory-lock release.
		$wpdb->get_var( $wpdb->prepare( 'SELECT RELEASE_LOCK(%s)', $lock_name ) );
	}

	/**
	 * Persist one activity row and finalize every pending tail row when possible.
	 *
	 * The placeholder is inserted before any chain computation. If this request
	 * owns the advisory lock, concurrent lock losers can only append higher IDs,
	 * so they cannot appear between the predecessor read and this row. A loser
	 * still inserts its unsigned row, preserving the audit event for the regular
	 * repair cron instead of silently dropping it.
	 *
	 * @param array<string,mixed> $row_data Canonical activity columns.
	 * @return array<string,mixed>|false Stored row with ID and hashes, or false on insert failure.
	 */
	public static function append_row( array $row_data ) {
		global $wpdb;

		$table         = $wpdb->prefix . 'login_armor_activity';
		$locked        = self::acquire_chain_lock( 2 );
		$new_id        = 0;
		$dispatch_rows = array();
		try {
			$row_data['prev_hash'] = null;
			$row_data['row_hash']  = null;
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery -- Custom plugin table, durable audit write.
			$inserted = $wpdb->insert(
				$table,
				$row_data,
				[ '%d', '%s', '%s', '%s', '%s', '%d', '%s', '%s', '%s', '%s', '%s', '%s' ]
			);
			$new_id = false === $inserted ? 0 : (int) $wpdb->insert_id;
			if ( $new_id <= 0 ) {
				return false;
			}
			$row_data['id'] = $new_id;

			if ( ! $locked ) {
				return $row_data;
			}

			self::repair_chain_rows_without_lock( $dispatch_rows );
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Plugin-owned table and prepared row ID.
			$stored = $wpdb->get_row( $wpdb->prepare( 'SELECT prev_hash, row_hash FROM %i WHERE id = %d', $table, $new_id ) );
			if ( $stored ) {
				$row_data['prev_hash'] = $stored->prev_hash;
				$row_data['row_hash']  = $stored->row_hash;
			}
		} finally {
			if ( $locked ) {
				self::release_chain_lock();
			}
		}

		// Webhook callbacks may write their own system events. Run them only
		// after releasing the chain lock and let ActivityLogger dispatch the
		// row created by this request exactly once.
		self::dispatch_repaired_rows( $dispatch_rows, $new_id );

		return $row_data;
	}

	/**
	 * Verify the integrity of the Activity Log HMAC chain.
	 *
	 * Reads rows ORDER BY id ASC starting from chain_start_id, recomputes
	 * each row_hash from prev row's row_hash + canonical_payload, and
	 * compares with stored row_hash via hash_equals (constant-time).
	 *
	 * Skips rows with id < chain_start_id (legacy pre-V2.1.1 rows).
	 * Skips rows with row_hash IS NULL (orphans, surfaced separately).
	 *
	 * **Cost:** O(N) reads in 1000-row batches (~5µs HMAC/row). 100k rows ≈
	 * 500ms wall time. Run from CLI / admin AJAX only: never on a public hook.
	 *
	 * **Trust gap on encoding-failed rows:** if `canonical_payload()` returns
	 * `false` at verify time (e.g. PHP version drift breaking JSON encoding),
	 * the row is reported as broken with that issue, but $prev_hash advances
	 * to the stored row_hash so downstream rows can still be verified. A
	 * downstream `intact` result is therefore *conditional* on the encoding-
	 * failed row being honest: surface this in any UI explanation.
	 *
	 * **Partial-range caveat ($from > chain_start_id):** if an orphan exists
	 * between the seed row and $from, the seed-fetch will skip backwards over
	 * it (`row_hash IS NOT NULL` filter) and the row at $from will appear
	 * broken even if its stored hash chains correctly to its true predecessor.
	 * Run `repair_chain()` before partial-range calls, or call without args
	 * for the full-range default which avoids this branch entirely.
	 *
	 * @param int|null $from Start row id (default: chain_start_id).
	 * @param int|null $to   End row id (default: latest row).
	 * @return array{status:string,total:int,broken:array<int,array{id:int,log_time:string,issue:string}>,orphans:int,verified_at:string}
	 */
	public static function verify_chain( ?int $from = null, ?int $to = null ): array {
		global $wpdb;

		$table          = $wpdb->prefix . 'login_armor_activity';
		$chain_start_id = self::get_chain_start_id();
		$from           = $from ?? max( 1, $chain_start_id );
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
		$latest_id      = (int) $wpdb->get_var( $wpdb->prepare( 'SELECT MAX(id) FROM %i', $table ) );
		$to             = $to ?? $latest_id;

		if ( $to < $from ) {
			return [ 'status' => 'intact', 'total' => 0, 'broken' => [], 'orphans' => 0, 'salt_changed' => false, 'verified_at' => gmdate( 'Y-m-d H:i:s' ) ];
		}

		$broken     = [];
		$orphans    = 0;
		$batch_size = 1000;
		$offset     = $from;
		$secret     = self::get_chain_secret();
		$prev_hash  = self::CHAIN_GENESIS_HASH;
		$pruned     = false;
		$first_id   = 0;
		// Rows actually read and checked. The id range is NOT that count: the
		// retention purge leaves holes, and a site whose first twelve rows had
		// been purged reported "58 rows signed" over 46 surviving rows.
		$verified   = 0;

		// Seed from the row immediately before $from, when one still exists.
		// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
		$seed = $wpdb->get_var( $wpdb->prepare(
			'SELECT row_hash FROM %i WHERE id < %d AND row_hash IS NOT NULL ORDER BY id DESC LIMIT 1',
			$table,
			$from
		) );

		if ( ! empty( $seed ) ) {
			$prev_hash = (string) $seed;
		} else {
			// Nothing before $from. Either this really is the first row ever
			// written, whose prev_hash IS the genesis, or everything before it
			// has been deleted by the retention purge (2.7.3).
			//
			// The purge is the reason this exists. It deletes by log_time and
			// left chain_start_id pointing at row 1, so verification started
			// from the genesis hash and met a row whose prev_hash was the
			// row_hash of a row the purge had removed ninety days earlier. It
			// reported "TAMPERED, first break at row 13" to the site owner,
			// who had done nothing but keep the plugin installed long enough.
			// Measured on a real site: rows 1 to 12 gone, 13 to 58 intact.
			//
			// Seeding from the stored prev_hash of the first surviving row is
			// what makes the surviving chain verifiable: every row after it is
			// still checked against its predecessor, so altering any payload,
			// or any prev_hash, still breaks it. What this cannot detect is the
			// deletion of the start of the chain itself, which is exactly the
			// operation the product performs on purpose every night. Detecting
			// that needs an anchor outside this table, which the plugin does
			// not have and does not claim to.
			// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
			$first = $wpdb->get_row( $wpdb->prepare(
				'SELECT id, prev_hash FROM %i WHERE id >= %d AND row_hash IS NOT NULL ORDER BY id ASC LIMIT 1',
				$table,
				$from
			) );
			if ( $first && ! empty( $first->prev_hash ) && ! hash_equals( self::CHAIN_GENESIS_HASH, (string) $first->prev_hash ) ) {
				$prev_hash = (string) $first->prev_hash;
				$pruned    = true;
				$first_id  = (int) $first->id;
			}
		}

		while ( $offset <= $to ) {
			$batch_end = min( $offset + $batch_size - 1, $to );
			// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
			$rows = $wpdb->get_results( $wpdb->prepare(
				'SELECT * FROM %i WHERE id BETWEEN %d AND %d ORDER BY id ASC',
				$table,
				$offset,
				$batch_end
			) );

			foreach ( $rows as $row ) {
				if ( $row->row_hash === null ) {
					$orphans++;
					continue;  // Orphans are fixable via repair_chain: don't break verify.
				}

				$row_data = [
					'user_id'     => (int) $row->user_id,
					'user_login'  => (string) $row->user_login,
					'user_role'   => (string) $row->user_role,
					'action'      => (string) $row->action,
					'object_type' => (string) $row->object_type,
					'object_id'   => (int) $row->object_id,
					'object_name' => (string) $row->object_name,
					'description' => (string) $row->description,
					'ip'          => (string) $row->ip,
					'log_time'    => (string) $row->log_time,
				];
				$canonical = self::canonical_payload( $row_data );
				if ( false === $canonical ) {
					$broken[] = [
						'id'       => (int) $row->id,
						'log_time' => (string) $row->log_time,
						'issue'    => 'canonical_payload encoding failed',
					];
					$prev_hash = (string) $row->row_hash;
					continue;
				}
				$expected = hash_hmac( 'sha256', $prev_hash . $canonical, $secret );

				if ( ! hash_equals( $expected, (string) $row->row_hash ) ) {
					$broken[] = [
						'id'       => (int) $row->id,
						'log_time' => (string) $row->log_time,
						'issue'    => 'row_hash mismatch',
					];
				}

				++$verified;
				$prev_hash = (string) $row->row_hash;
			}

			$offset = $batch_end + 1;
		}

		$status = empty( $broken ) ? 'intact' : 'broken';

		return [
			'status'       => $status,
			'total'        => $verified,
			'broken'       => $broken,
			'orphans'      => $orphans,
			// V2.1.20: when the chain breaks AND the security keys rotated since
			// the last baseline, the breakage is explained by the key change
			// (migration / restored backup), not by tampering. The UI uses this
			// to show an amber "keys changed" advisory + a one-click re-baseline
			// instead of a red "TAMPERED" alarm.
			'salt_changed' => 'broken' === $status ? self::salt_changed() : false,
			// 2.7.3: true when the rows preceding the chain are gone, which is
			// what the nightly retention purge does by design. The chain from
			// `pruned_from` onwards is fully verified; what came before it can
			// no longer be, because it no longer exists.
			'pruned'       => $pruned,
			'pruned_from'  => $first_id,
			'verified_at'  => gmdate( 'Y-m-d H:i:s' ),
		];
	}

	/**
	 * Recompute row_hash for unsigned rows at the current chain tail.
	 *
	 * Retained for legacy rows, interrupted upgrades and new rows preserved
	 * during temporary chain-lock contention.
	 *
	 * @return int Number of rows repaired.
	 */
	public static function repair_chain(): int {
		if ( ! self::acquire_chain_lock( 2 ) ) {
			return 0;
		}
		$dispatch_rows = array();
		$repaired      = 0;
		try {
			$repaired = self::repair_chain_rows_without_lock( $dispatch_rows );
		} finally {
			self::release_chain_lock();
		}

		self::dispatch_repaired_rows( $dispatch_rows );
		return $repaired;
	}

	/**
	 * Sign pending rows while the caller owns the shared chain lock.
	 *
	 * @param array<int,array<string,mixed>> $dispatch_rows Repaired rows whose
	 *                                                      webhook hook must run
	 *                                                      after lock release.
	 */
	private static function repair_chain_rows_without_lock( array &$dispatch_rows ): int {
		global $wpdb;
		$table = $wpdb->prefix . 'login_armor_activity';

		$chain_start_id = max( 1, self::get_chain_start_id() );
		// Never re-sign an orphan that already has a signed successor. Such a
		// legacy middle orphan is evidence and inserting it into the chain would
		// invalidate that successor. Only the unsigned suffix after the latest
		// signed row is safe to finalize automatically.
		// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
		$last_signed = $wpdb->get_row( $wpdb->prepare(
			'SELECT id, row_hash FROM %i WHERE id >= %d AND row_hash IS NOT NULL ORDER BY id DESC LIMIT 1',
			$table,
			$chain_start_id
		) );
		$tail_after = $last_signed ? (int) $last_signed->id : $chain_start_id - 1;
		$prev_hash = $last_signed
			? (string) $last_signed->row_hash
			: self::CHAIN_GENESIS_HASH;

		// New rows appended after this snapshot have higher IDs and remain a safe
		// tail for the next repair pass.
		// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
		$orphans = $wpdb->get_results( $wpdb->prepare(
			'SELECT * FROM %i WHERE row_hash IS NULL AND id > %d ORDER BY id ASC LIMIT 5000',
			$table,
			$tail_after
		) );
		if ( empty( $orphans ) ) {
			return 0;
		}

		$repaired = 0;
		$secret   = self::get_chain_secret();
		foreach ( $orphans as $row ) {
			$row_data = [
				'user_id'     => (int) $row->user_id,
				'user_login'  => (string) $row->user_login,
				'user_role'   => (string) $row->user_role,
				'action'      => (string) $row->action,
				'object_type' => (string) $row->object_type,
				'object_id'   => (int) $row->object_id,
				'object_name' => (string) $row->object_name,
				'description' => (string) $row->description,
				'ip'          => (string) $row->ip,
				'log_time'    => (string) $row->log_time,
			];
			$canonical = self::canonical_payload( $row_data );
			if ( false === $canonical ) {
				break;
			}
			$row_hash = hash_hmac( 'sha256', $prev_hash . $canonical, $secret );

			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
			$updated = $wpdb->update(
				$table,
				[ 'prev_hash' => $prev_hash, 'row_hash' => $row_hash ],
				[ 'id' => $row->id ],
				[ '%s', '%s' ],
				[ '%d' ]
			);
			if ( false === $updated ) {
				break;
			}
			$row_data['id']        = (int) $row->id;
			$row_data['prev_hash'] = $prev_hash;
			$row_data['row_hash']  = $row_hash;
			if ( 'system' !== $row_data['object_type'] ) {
				$dispatch_rows[] = $row_data;
			}
			$prev_hash = $row_hash;
			++$repaired;
		}

		return $repaired;
	}

	/**
	 * Notify external consumers about non-system rows finalized by repair.
	 *
	 * @param array<int,array<string,mixed>> $rows             Repaired rows.
	 * @param int                            $skip_activity_id Row dispatched by
	 *                                                        its ActivityLogger.
	 */
	private static function dispatch_repaired_rows( array $rows, int $skip_activity_id = 0 ): void {
		foreach ( $rows as $row ) {
			if ( $skip_activity_id > 0 && (int) $row['id'] === $skip_activity_id ) {
				continue;
			}
			do_action( 'login_armor_activity_logged', $row );
		}
	}

	/**
	 * Re-baseline the integrity chain under the current security key (V2.1.20).
	 *
	 * Intended remedy after a benign key rotation (site migration, restored
	 * backup, manual wp-config.php change) leaves pre-rotation rows unverifiable.
	 * It asserts "I trust the activity table as it stands now" and re-signs every
	 * row from MIN(id) upward under the current wp_salt('auth'), chaining each
	 * row to its predecessor exactly as ActivityLogger::log() does. The whole
	 * visible history becomes verifiable + intact again, with no row deleted.
	 *
	 * It then records the new salt fingerprint as the trusted baseline and moves
	 * chain_start_id to the first row so coverage spans the entire table.
	 *
	 * Security note: re-baselining trusts the current DB state. Run it only after
	 * a key change you performed/expected: never to silence an unexplained
	 * TAMPERED result, which is the exact signal this would erase.
	 *
	 * @since 2.1.20
	 * @return array{rows:int,chain_start_id:int}
	 */
	public static function reset_chain(): array {
		if ( ! self::acquire_chain_lock( 5 ) ) {
			return [ 'rows' => 0, 'chain_start_id' => self::get_chain_start_id() ];
		}
		try {
		global $wpdb;
		$table = $wpdb->prefix . 'login_armor_activity';

		// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,PluginCheck.Security.DirectDB.UnescapedDBParameter -- $table is $wpdb->prefix + hard-coded suffix; no user input.
		$min_id = (int) $wpdb->get_var( "SELECT MIN(id) FROM {$table}" );
		// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,PluginCheck.Security.DirectDB.UnescapedDBParameter -- $table is $wpdb->prefix + hard-coded suffix; no user input.
		$max_id = (int) $wpdb->get_var( "SELECT MAX(id) FROM {$table}" );

		if ( $min_id <= 0 ) {
			// Empty table: just baseline the fingerprint and the start id.
			self::store_salt_fingerprint();
			update_option( self::OPTION_CHAIN_START_ID, 1, false );
			return [ 'rows' => 0, 'chain_start_id' => 1 ];
		}

		$secret     = self::get_chain_secret();
		$prev_hash  = self::CHAIN_GENESIS_HASH;
		$batch_size = 1000;
		$offset     = $min_id;
		$rows_done  = 0;

		while ( $offset <= $max_id ) {
			$batch_end = min( $offset + $batch_size - 1, $max_id );
			// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared,WordPress.DB.PreparedSQL.InterpolatedNotPrepared,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,PluginCheck.Security.DirectDB.UnescapedDBParameter -- $table is $wpdb->prefix + hard-coded suffix; values bound via prepare().
			$rows = $wpdb->get_results( $wpdb->prepare(
				"SELECT * FROM {$table} WHERE id BETWEEN %d AND %d ORDER BY id ASC", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared,PluginCheck.Security.DirectDB.UnescapedDBParameter -- $table is $wpdb->prefix + hard-coded suffix; values bound via prepare().
				$offset,
				$batch_end
			) );

			foreach ( $rows as $row ) {
				$row_data = [
					'user_id'     => (int) $row->user_id,
					'user_login'  => (string) $row->user_login,
					'user_role'   => (string) $row->user_role,
					'action'      => (string) $row->action,
					'object_type' => (string) $row->object_type,
					'object_id'   => (int) $row->object_id,
					'object_name' => (string) $row->object_name,
					'description' => (string) $row->description,
					'ip'          => (string) $row->ip,
					'log_time'    => (string) $row->log_time,
				];
				$canonical = self::canonical_payload( $row_data );
				if ( false === $canonical ) {
					// Encoding failure (extremely unlikely on scalar columns):
					// advance prev to keep the chain linear and skip the re-sign.
					$prev_hash = (string) $row->row_hash;
					continue;
				}
				$row_hash = hash_hmac( 'sha256', $prev_hash . $canonical, $secret );

				// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
				$wpdb->update(
					$table,
					[ 'prev_hash' => $prev_hash, 'row_hash' => $row_hash ],
					[ 'id' => (int) $row->id ],
					[ '%s', '%s' ],
					[ '%d' ]
				);
				$prev_hash = $row_hash;
				$rows_done++;
			}

			$offset = $batch_end + 1;
		}

		update_option( self::OPTION_CHAIN_START_ID, $min_id, false );
		self::store_salt_fingerprint();

		return [ 'rows' => $rows_done, 'chain_start_id' => $min_id ];
		} finally {
			self::release_chain_lock();
		}
	}

	/**
	 * Daily cron: run verify_chain and cache result in transient.
	 *
	 * Surfaced by the admin Integrity panel (Task B11) via the cached transient.
	 * Skips if module disabled or auto-verify option is off.
	 *
	 * @return void
	 */
	/**
	 * Verify the chain now and keep the result for the Integrity panel (2.7.9).
	 *
	 * The panel shows the last verification, kept seven days. Whatever empties
	 * the table has to refresh it: after "Reset all activity entries" the
	 * panel went on reading "INTACT, 143 rows signed" over an empty log. An
	 * empty table verifies in one query.
	 *
	 * @return array<string,mixed> The verify_chain() result that was stored.
	 */
	public static function refresh_verification(): array {
		$result = self::verify_chain();
		set_transient( 'login_armor_chain_verify_last', $result, 7 * DAY_IN_SECONDS );
		return $result;
	}

	public static function cron_auto_verify(): void {
		if ( ! self::is_enabled() ) {
			return;
		}
		if ( ! get_option( 'login_armor_activity_auto_verify_daily', true ) ) {
			return;
		}

		$result = self::verify_chain();
		set_transient( 'login_armor_chain_verify_last', $result, 7 * DAY_IN_SECONDS );
	}

	// ── Private ─────────────────────────────────────────────────────

	/**
	 * Instantiate and register all loggers.
	 */
	private function init_loggers(): void {
		$dir = __DIR__ . '/Loggers/';

		require_once __DIR__ . '/ActivityLogger.php';
		require_once $dir . 'UserLogger.php';
		require_once $dir . 'PostLogger.php';
		require_once $dir . 'MediaLogger.php';
		require_once $dir . 'PluginLogger.php';
		require_once $dir . 'ThemeLogger.php';
		require_once $dir . 'OptionLogger.php';
		require_once $dir . 'TwoFactorLogger.php';

		$loggers = [
			new Loggers\UserLogger(),
			new Loggers\PostLogger(),
			new Loggers\MediaLogger(),
			new Loggers\PluginLogger(),
			new Loggers\ThemeLogger(),
			new Loggers\OptionLogger(),
			new Loggers\TwoFactorLogger(),
		];

		foreach ( $loggers as $logger ) {
			$logger->register();
		}

		// 2.7.9: "Reset all events & incidents" has announced itself on
		// login_armor_data_reset since 2.0.1, "so the wipe is auditable", and
		// nothing listened: the one action that erases a security log left no
		// trace of itself.
		require_once $dir . 'SettingsLogger.php';
		$settings_logger = new Loggers\SettingsLogger();
		add_action( 'login_armor_data_reset', [ $settings_logger, 'on_data_reset' ], 10, 4 );
		// 2.9.0: the headless mode and the application-password network events.
		add_action( 'login_armor_headless_changed', [ $settings_logger, 'on_headless_changed' ], 10, 3 );
		add_action( 'login_armor_app_password_new_network', [ $settings_logger, 'on_app_password_new_network' ], 10, 3 );
		add_action( 'login_armor_app_password_network_approved', [ $settings_logger, 'on_app_password_network_approved' ], 10, 4 );
		// 2.10.0: boolean options rewritten by the upgrade.
		add_action( 'login_armor_boolean_options_migrated', [ $settings_logger, 'on_boolean_options_migrated' ], 10, 1 );

		// V2.1.1, Webhook dispatcher: subscribes to login_armor_activity_logged
		// when admin has configured a webhook URL. Constructor self-gates on
		// is_enabled() so off-by-default sites pay zero overhead.
		require_once __DIR__ . '/WebhookDispatcher.php';
		new WebhookDispatcher();
	}

	/**
	 * Convert a period filter value to a UTC cutoff datetime string.
	 *
	 * @param string $period One of: 'today', '7d', '30d'.
	 * @return string|null UTC datetime string or null if invalid.
	 */
	private static function period_to_cutoff( string $period ): ?string {
		return match ( $period ) {
			'today' => gmdate( 'Y-m-d 00:00:00' ),
			'7d'    => gmdate( 'Y-m-d H:i:s', time() - 7 * DAY_IN_SECONDS ),
			'30d'   => gmdate( 'Y-m-d H:i:s', time() - 30 * DAY_IN_SECONDS ),
			default => null,
		};
	}
}
