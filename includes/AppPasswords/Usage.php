<?php
/**
 * Application-password usage journal (2.9.0).
 *
 * @package LoginArmor
 * @since   2.9.0
 */

namespace LoginArmor\AppPasswords;

use LoginArmor\LoginArmor;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Which networks each application password is used from.
 */
final class Usage {

	/** Monitoring switch. Autoloaded: read on every authenticated request. */
	public const OPTION_WATCH = 'login_armor_app_password_watch';

	/** Unix time monitoring first started on THIS site. Never exported. */
	public const OPTION_SINCE = 'login_armor_app_password_watch_since';

	/** Days of use per password: uuid => [ 'd' => int, 'l' => 'Y-m-d' ]. Never exported. */
	public const OPTION_DAYS = 'login_armor_app_password_days';

	/** Table name, without the site prefix. */
	public const TABLE = 'login_armor_app_password_usage';

	/** Single event that resolves and classifies new rows. */
	public const REVIEW_HOOK = 'login_armor_app_password_review';

	/** Rows kept per password on the profile. */
	public const ROWS_PER_PASSWORD = 50;

	/** Whether monitoring is on. On by default. */
	public static function is_watching(): bool {
		return LoginArmor::to_bool( get_option( self::OPTION_WATCH, true ) );
	}

	/**
	 * Switch monitoring on or off. The first switch-on dates the learning
	 * period of every password already in service (spec C.4).
	 */
	public static function set_watching( bool $on ): void {
		// 1 or 0, never a boolean: update_option( X, false ) on an option that
		// does not exist writes nothing (old and new values are both false), so
		// "off" would be lost and read back as the default, on.
		update_option( self::OPTION_WATCH, $on ? 1 : 0, true );
		if ( $on ) {
			self::stamp_since();
			// 2.10.0 (Codex C04): a review consumed while monitoring was off
			// is not rescheduled by itself; a known address only updates its
			// row, which books nothing. Resume the pending rows now.
			self::ensure_review_scheduled();
		}
	}

	/** Record when monitoring started, once. */
	public static function stamp_since(): void {
		if ( (int) get_option( self::OPTION_SINCE, 0 ) <= 0 ) {
			update_option( self::OPTION_SINCE, time(), false );
		}
	}

	/**
	 * Hook the per-request write. Registered on every request; record()
	 * checks the switch itself, so a change takes effect at once.
	 */
	public static function register(): void {
		add_action( 'application_password_did_authenticate', array( self::class, 'record' ), 10, 2 );
		// 2.10.0 (Codex C04): switching monitoring back on by any path (screen,
		// import, WP-CLI, update_option) resumes the review of pending rows.
		add_action( 'add_option_' . self::OPTION_WATCH, array( self::class, 'on_watch_option_added' ), 10, 2 );
		add_action( 'update_option_' . self::OPTION_WATCH, array( self::class, 'on_watch_option_updated' ), 10, 2 );
	}

	/**
	 * add_option_{option}: ( $option, $value ).
	 *
	 * Untyped with defaults, like every callback on a core hook.
	 *
	 * @since 2.10.0
	 *
	 * @param mixed $option Option name (unused).
	 * @param mixed $value  New value.
	 */
	public static function on_watch_option_added( $option = '', $value = null ): void {
		unset( $option );
		if ( LoginArmor::to_bool( $value ) ) {
			self::ensure_review_scheduled();
		}
	}

	/**
	 * update_option_{option}: ( $old_value, $value, $option ).
	 *
	 * Untyped with defaults, like every callback on a core hook.
	 *
	 * @since 2.10.0
	 *
	 * @param mixed $old_value Previous value (unused).
	 * @param mixed $value     New value.
	 */
	public static function on_watch_option_updated( $old_value = null, $value = null ): void {
		unset( $old_value );
		if ( LoginArmor::to_bool( $value ) ) {
			self::ensure_review_scheduled();
		}
	}

	/**
	 * application_password_did_authenticate: one row per (password, address).
	 *
	 * One statement; nothing else happens during the request, no network
	 * lookup and no mail: a new row only schedules the review.
	 *
	 * Untyped with defaults, like every callback on a core hook.
	 *
	 * @param mixed $user The authenticated user (expected WP_User).
	 * @param mixed $item The application password (expected array with uuid, name).
	 */
	public static function record( $user = null, $item = array() ): void {
		if ( ! $user instanceof \WP_User || ! is_array( $item ) || ! isset( $item['uuid'] ) || ! is_string( $item['uuid'] ) ) {
			return;
		}
		if ( ! self::is_watching() ) {
			return;
		}
		$ip = LoginArmor::get_client_ip();
		if ( ! LoginArmor::is_reliable_client_ip( $ip ) ) {
			return;
		}
		$uuid = self::clean_uuid( $item['uuid'] );
		if ( '' === $uuid ) {
			return;
		}

		global $wpdb;
		$table = $wpdb->prefix . self::TABLE;
		$name  = mb_substr( sanitize_text_field( (string) ( $item['name'] ?? '' ) ), 0, 200 );
		$route = self::current_route();
		$now   = gmdate( 'Y-m-d H:i:s' );

		$sql = $wpdb->prepare(
			"INSERT INTO {$table} (user_id, uuid, password_name, ip, first_seen, last_seen, hits, last_route, state) VALUES (%d, %s, %s, %s, %s, %s, 1, %s, 'pending') ON DUPLICATE KEY UPDATE last_seen = %s, hits = hits + 1, last_route = %s, password_name = %s", // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared,WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Only the prefixed table name is interpolated.
			(int) $user->ID,
			$uuid,
			$name,
			$ip,
			$now,
			$now,
			$route,
			$now,
			$route,
			$name
		);
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.NotPrepared -- Plugin table, one upsert per authenticated request, prepared above.
		$affected = $wpdb->query( $sql );

		// 2.10.0 (Codex C05): a table the upgrade could not create made every
		// use fail here in silence, while its day was still counted. Repair the
		// schema (once an hour at most) and try once more; count nothing
		// unless the use is really stored.
		if ( false === $affected && LoginArmor::repair_schema_once() ) {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.NotPrepared -- Same prepared upsert, after the repair.
			$affected = $wpdb->query( $sql );
		}
		if ( false === $affected ) {
			return;
		}

		// affected_rows: 1 for a new row, 2 for an updated one.
		if ( 1 === (int) $affected ) {
			self::stamp_since();
			if ( ! wp_next_scheduled( self::REVIEW_HOOK ) ) {
				wp_schedule_single_event( time() + 5, self::REVIEW_HOOK );
			}
		}

		self::count_day( $uuid, gmdate( 'Y-m-d' ) );
	}

	/** A core uuid, lowercased; '' for anything else. */
	public static function clean_uuid( string $raw ): string {
		$uuid = strtolower( (string) preg_replace( '/[^a-fA-F0-9-]/', '', $raw ) );
		return 36 === strlen( $uuid ) ? $uuid : '';
	}

	/**
	 * Count today as a day of use of a password, once a day.
	 *
	 * Autoloaded and written at most once a day per password, so the
	 * per-request cost is the upsert alone.
	 *
	 * 2.10.0 (Codex C03): the option holds every password, and two passwords
	 * counting their day at once each rewrote the whole array: the later write
	 * erased the other's day, and a password could stay in learning longer.
	 * The write now happens under one advisory lock, on the value read from
	 * the table, not from the options cache. The common case (already counted
	 * today) still costs no lock and no query.
	 */
	public static function count_day( string $uuid, string $today ): void {
		$cached = get_option( self::OPTION_DAYS, array() );
		if ( is_array( $cached ) && is_array( $cached[ $uuid ] ?? null ) && ( $cached[ $uuid ]['l'] ?? '' ) === $today ) {
			return;
		}
		self::with_days_lock(
			static function () use ( $uuid, $today ): void {
				$days  = self::read_days_fresh();
				$entry = is_array( $days[ $uuid ] ?? null ) ? $days[ $uuid ] : array( 'd' => 0, 'l' => '' );
				if ( ( $entry['l'] ?? '' ) === $today ) {
					return;
				}
				$days[ $uuid ] = array(
					'd' => (int) ( $entry['d'] ?? 0 ) + 1,
					'l' => $today,
				);
				update_option( self::OPTION_DAYS, $days, true );
			}
		);
	}

	/**
	 * Run a read-modify-write of the days option under its advisory lock.
	 *
	 * Lock not obtained within two seconds: nothing runs, and the day is
	 * counted by a later request (it is not marked as counted).
	 *
	 * @since 2.10.0
	 *
	 * @param callable $fn The read-modify-write.
	 * @return bool Whether it ran.
	 */
	private static function with_days_lock( callable $fn ): bool {
		global $wpdb;
		// Advisory locks are shared by the whole MySQL server: named after this
		// site's database and table prefix, like the activity-chain lock.
		$database  = defined( 'DB_NAME' ) ? (string) DB_NAME : '';
		$lock_name = substr( 'la_app_password_days_' . md5( $database . '|' . $wpdb->prefix ), 0, 64 );
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Advisory lock, not data.
		if ( 1 !== (int) $wpdb->get_var( $wpdb->prepare( 'SELECT GET_LOCK(%s, %d)', $lock_name, 2 ) ) ) {
			return false;
		}
		try {
			$fn();
		} finally {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Advisory lock, not data.
			$wpdb->get_var( $wpdb->prepare( 'SELECT RELEASE_LOCK(%s)', $lock_name ) );
		}
		return true;
	}

	/**
	 * The days option as stored, past the options cache.
	 *
	 * @since 2.10.0
	 *
	 * @return array<string,mixed>
	 */
	private static function read_days_fresh(): array {
		global $wpdb;
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- The cached copy is exactly what must not be trusted here.
		$raw  = $wpdb->get_var( $wpdb->prepare( "SELECT option_value FROM {$wpdb->options} WHERE option_name = %s", self::OPTION_DAYS ) );
		$days = null === $raw ? array() : maybe_unserialize( (string) $raw );
		return is_array( $days ) ? $days : array();
	}

	/** Days a password has been used on, since monitoring started. */
	public static function days_used( string $uuid ): int {
		$days = get_option( self::OPTION_DAYS, array() );
		return is_array( $days ) && isset( $days[ $uuid ]['d'] ) ? (int) $days[ $uuid ]['d'] : 0;
	}

	/**
	 * Path of the current request, without its query string.
	 *
	 * Never through sanitize_text_field(), which deletes percent-encoded
	 * sequences (2.5.2): only characters a URL path can carry are kept.
	 */
	public static function current_route(): string {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Read-only routing parameter.
		if ( isset( $_GET['rest_route'] ) && is_string( $_GET['rest_route'] ) ) {
			$path = (string) wp_unslash( $_GET['rest_route'] ); // phpcs:ignore WordPress.Security.NonceVerification.Recommended,WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Filtered by the character whitelist below.
		} else {
			// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Filtered by the character whitelist below.
			$uri  = isset( $_SERVER['REQUEST_URI'] ) ? (string) wp_unslash( $_SERVER['REQUEST_URI'] ) : '';
			$path = explode( '?', $uri, 2 )[0];
		}
		return substr( (string) preg_replace( '#[^A-Za-z0-9/_\-.~%:@+,]#', '', $path ), 0, 190 );
	}

	/**
	 * Rows waiting for review, oldest first.
	 *
	 * @return array<int,object>
	 */
	public static function pending_rows( int $limit ): array {
		global $wpdb;
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Plugin table, background review.
		$rows = $wpdb->get_results( $wpdb->prepare( "SELECT id, user_id, uuid, password_name, ip, first_seen, last_route FROM {$wpdb->prefix}login_armor_app_password_usage WHERE state = 'pending' ORDER BY id ASC LIMIT %d", $limit ) );
		return is_array( $rows ) ? $rows : array();
	}

	/**
	 * States of the OTHER resolved rows of a password on a network.
	 *
	 * @return string[]
	 */
	public static function sibling_states( string $uuid, string $network, int $exclude_id ): array {
		global $wpdb;
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Plugin table, served by the uuid_network index.
		$states = $wpdb->get_col( $wpdb->prepare( "SELECT DISTINCT state FROM {$wpdb->prefix}login_armor_app_password_usage WHERE uuid = %s AND network = %s AND id <> %d", $uuid, $network, $exclude_id ) );
		return is_array( $states ) ? array_map( 'strval', $states ) : array();
	}

	/**
	 * Store the identity and the verdict of a reviewed row, if it is still
	 * pending.
	 *
	 * The condition on the state is the claim: two passes that read the same
	 * row (one past WP_CRON_LOCK_TIMEOUT, or WP-CLI next to WP-Cron) cannot
	 * both resolve it, and only the one that did may alert.
	 *
	 * @param array{network:string,label:string,country:string} $identity
	 * @return int 1 when this call resolved the row, 0 when another did.
	 */
	public static function resolve_row( int $id, array $identity, string $state ): int {
		global $wpdb;
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Plugin table, one row.
		$changed = $wpdb->update(
			$wpdb->prefix . self::TABLE,
			array(
				'network'       => substr( $identity['network'], 0, 80 ),
				'network_label' => mb_substr( $identity['label'], 0, 100 ),
				'country'       => substr( $identity['country'], 0, 2 ),
				'state'         => $state,
			),
			array(
				'id'    => $id,
				'state' => 'pending',
			),
			array( '%s', '%s', '%s', '%s' ),
			array( '%d', '%s' )
		);
		return (int) $changed;
	}

	/**
	 * Approve a flagged network of a password: every row of it.
	 *
	 * @return int Rows changed.
	 */
	public static function approve( int $user_id, string $uuid, string $network ): int {
		global $wpdb;
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Plugin table, administrator action.
		return (int) $wpdb->query( $wpdb->prepare( "UPDATE {$wpdb->prefix}login_armor_app_password_usage SET state = 'approved' WHERE user_id = %d AND uuid = %s AND network = %s AND state = 'alerted'", $user_id, $uuid, $network ) );
	}

	/** Forget a password: its rows and its days of use. */
	public static function forget_password( string $uuid ): void {
		global $wpdb;
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Plugin table, cleanup.
		// 2.10.0: same lock as count_day(), so a concurrent day count cannot
		// write the forgotten password back. The rows go inside the lock too:
		// without it nothing is forgotten, and the rows left behind make the
		// next pass of forget_revoked() try again.
		self::with_days_lock(
			static function () use ( $uuid, $wpdb ): void {
				// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Plugin table, cleanup.
				$wpdb->delete( $wpdb->prefix . self::TABLE, array( 'uuid' => $uuid ), array( '%s' ) );
				$days = self::read_days_fresh();
				if ( isset( $days[ $uuid ] ) ) {
					unset( $days[ $uuid ] );
					update_option( self::OPTION_DAYS, $days, true );
				}
			}
		);
	}

	/**
	 * The application password behind a uuid, null when it is gone.
	 *
	 * @return array<string,mixed>|null
	 */
	public static function password( int $user_id, string $uuid ): ?array {
		if ( ! class_exists( '\WP_Application_Passwords' ) ) {
			return null;
		}
		$item = \WP_Application_Passwords::get_user_application_password( $user_id, $uuid );
		return is_array( $item ) ? $item : null;
	}

	/**
	 * Retention purge: rows last seen before the cutoff, then the rows of
	 * revoked passwords. The table holds one row per (password, address), so
	 * it stays small and a single DELETE served by the last_seen index is
	 * enough.
	 *
	 * @param string $cutoff UTC datetime, 'Y-m-d H:i:s'.
	 * @return int Rows deleted by the retention part.
	 */
	public static function purge( string $cutoff ): int {
		global $wpdb;
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Plugin table, retention cleanup.
		$deleted = (int) $wpdb->query( $wpdb->prepare( "DELETE FROM {$wpdb->prefix}login_armor_app_password_usage WHERE last_seen < %s", $cutoff ) );
		self::forget_revoked();
		return $deleted;
	}

	/**
	 * Forget every password that no longer exists (revoked, or its user
	 * deleted). One lookup per distinct password: a handful on any site.
	 */
	public static function forget_revoked(): void {
		global $wpdb;
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Plugin table, daily cleanup.
		$pairs = $wpdb->get_results( "SELECT DISTINCT user_id, uuid FROM {$wpdb->prefix}login_armor_app_password_usage" );
		foreach ( is_array( $pairs ) ? $pairs : array() as $pair ) {
			if ( null === self::password( (int) $pair->user_id, (string) $pair->uuid ) ) {
				self::forget_password( (string) $pair->uuid );
			}
		}
	}

	/**
	 * Book a review when rows wait and none is planned.
	 *
	 * record() only books on a NEW row, and a pass that dies after the event
	 * was consumed, or a concurrent write of the `cron` option, can leave
	 * pending rows with no event: they would never be reviewed. Called by the
	 * daily self-heal of the scheduled events.
	 */
	public static function ensure_review_scheduled(): void {
		if ( wp_next_scheduled( self::REVIEW_HOOK ) || ! self::is_watching() ) {
			return;
		}
		if ( self::count_by_state( 'pending' ) > 0 ) {
			wp_schedule_single_event( time() + 60, self::REVIEW_HOOK );
		}
	}

	/** Rows in a given state. */
	public static function count_by_state( string $state ): int {
		global $wpdb;
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Plugin table, status count.
		return (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM {$wpdb->prefix}login_armor_app_password_usage WHERE state = %s", $state ) );
	}

	/** Distinct (password, network) pairs in a given state. */
	public static function count_networks_by_state( string $state ): int {
		global $wpdb;
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Plugin table, status count.
		return (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(DISTINCT uuid, network) FROM {$wpdb->prefix}login_armor_app_password_usage WHERE state = %s", $state ) );
	}

	/**
	 * A user's networks, one row per (password, network), most recent first.
	 *
	 * Aggregated in SQL: a password seen from thousands of addresses (a front
	 * end on Vercel or AWS) is a handful of rows here, so it can neither hide
	 * another password nor push a flagged network out of the list. Rows still
	 * waiting for review have no network (NULL) and form one row per password.
	 *
	 * @return array<int,object>
	 */
	public static function rows_for_user( int $user_id ): array {
		global $wpdb;
		// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
		// Plugin table, profile screen. Routes and addresses never contain "|" (whitelisted characters), the separator of the two lists.
		$rows = $wpdb->get_results( $wpdb->prepare( "SELECT uuid, MAX(password_name) AS password_name, network, MAX(network_label) AS network_label, MAX(country) AS country, MIN(first_seen) AS first_at, MAX(last_seen) AS last_at, SUM(hits) AS hits, COUNT(*) AS addresses, SUBSTRING_INDEX(GROUP_CONCAT(ip ORDER BY last_seen DESC SEPARATOR '|'), '|', 5) AS ips, SUBSTRING_INDEX(GROUP_CONCAT(last_route ORDER BY last_seen DESC SEPARATOR '|'), '|', 1) AS last_route, MAX(CASE state WHEN 'alerted' THEN 5 WHEN 'pending' THEN 4 WHEN 'approved' THEN 3 WHEN 'known' THEN 2 ELSE 1 END) AS state_rank FROM {$wpdb->prefix}login_armor_app_password_usage WHERE user_id = %d GROUP BY uuid, network ORDER BY uuid ASC, last_at DESC", $user_id ) ); // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared,WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Only the prefixed table name is interpolated.
		// phpcs:enable WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
		return is_array( $rows ) ? $rows : array();
	}

	/**
	 * Aggregated rows grouped by password. Pure.
	 *
	 * Rows arrive most recent first. At most ROWS_PER_PASSWORD networks are
	 * kept per password, and a flagged network is always kept: the alert
	 * mail leads to its approve button.
	 *
	 * States read as the profile shows them: "alerted" over "pending" over
	 * "approved" over "known" (learned reads as known). A row without a
	 * network is the password's requests not yet reviewed (network key '').
	 *
	 * @param array<int,object> $rows Rows of rows_for_user().
	 * @return array<string,array{name:string,many_networks:bool,resolved:int,networks:array<string,array<string,mixed>>}>
	 */
	public static function group_by_password( array $rows ): array {
		$states = array( 5 => 'alerted', 4 => 'pending', 3 => 'approved', 2 => 'known', 1 => 'known' );
		$groups = array();
		$latest = array();
		foreach ( $rows as $row ) {
			$uuid    = (string) $row->uuid;
			$network = (string) ( $row->network ?? '' );
			$state   = $states[ (int) $row->state_rank ] ?? 'known';

			if ( ! isset( $groups[ $uuid ] ) ) {
				$groups[ $uuid ] = array( 'name' => '', 'many_networks' => false, 'resolved' => 0, 'networks' => array() );
			}
			if ( '' !== $network ) {
				++$groups[ $uuid ]['resolved'];
			}
			// The name is the one of the most recent request, whichever network it came from.
			if ( ! isset( $latest[ $uuid ] ) || (string) $row->last_at > $latest[ $uuid ] ) {
				$latest[ $uuid ]         = (string) $row->last_at;
				$groups[ $uuid ]['name'] = (string) $row->password_name;
			}
			if ( count( $groups[ $uuid ]['networks'] ) >= self::ROWS_PER_PASSWORD && 'alerted' !== $state ) {
				continue;
			}
			$groups[ $uuid ]['networks'][ $network ] = array(
				'label'     => '' !== (string) $row->network_label ? (string) $row->network_label : $network,
				'country'   => (string) $row->country,
				'state'     => $state,
				'ips'       => array_values( array_filter( explode( '|', (string) $row->ips ), static fn( $ip ) => '' !== $ip ) ),
				'addresses' => (int) $row->addresses,
				'first'     => (string) $row->first_at,
				'last'      => (string) $row->last_at,
				'hits'      => (int) $row->hits,
				'route'     => (string) $row->last_route,
			);
		}
		foreach ( $groups as $uuid => $group ) {
			$groups[ $uuid ]['many_networks'] = $group['resolved'] > 1;
		}
		return $groups;
	}
}
