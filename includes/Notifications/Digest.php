<?php
/**
 * Scheduled security digest: one summary, weekly or monthly.
 *
 * Login Armor alerts on events. An event-driven channel is silent on a quiet
 * site, and a quiet site is exactly the one whose administrator stops looking
 * at the dashboard. The digest is the opposite contract: it arrives on a fixed
 * period whether or not anything happened, and says what the period held.
 *
 * Three rules shape everything below.
 *
 * It carries NO IP ADDRESS. Not one, anywhere, in any channel. A digest is
 * forwarded, archived and read in places the incident list is not, and an
 * address is personal data in the European Union whatever the sending site
 * thinks. Counts, usernames and module states answer every question a digest
 * is for; the addresses stay on the site, in the Incidents tab.
 *
 * It bypasses the hourly caps of Dispatcher on purpose. Those caps exist so a
 * flood cannot turn the site into a mail relay; one message per week or per
 * month is not a flood, and a digest swallowed by the cap of an unrelated
 * incident storm would be silence exactly when the operator needed the summary.
 *
 * It costs nothing when it is off. The daily tick is permanent, so switching
 * the digest on never has to schedule anything, but maybe_send() returns on
 * its first line when the mode is 'off'.
 *
 * @package LoginArmor\Notifications
 * @since   2.7.0
 */

namespace LoginArmor\Notifications;

use LoginArmor\Detection\Incident;
use LoginArmor\Firewall\Firewall;
use LoginArmor\LimitLogin;
use LoginArmor\PowChallenge;
use LoginArmor\SecurityScore;
use LoginArmor\Support\SafeUrl;

// Exit if accessed directly.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Collects, renders and delivers the scheduled digest.
 */
final class Digest {

	/** Option holding the period: 'off' | 'weekly' | 'monthly'. */
	public const OPTION_MODE = 'login_armor_notif_digest';

	/** 2.10.0: the digest's own recipient. Empty: the incident channel decides, as before. */
	public const OPTION_TO = 'login_armor_notif_digest_to';

	/** Option holding the Unix time of the last digest that actually went out. */
	public const OPTION_LAST = 'login_armor_notif_digest_last';

	/** The cron hook of the daily tick. Same literal as the option, on purpose: one feature, one name. */
	public const CRON_HOOK = 'login_armor_notif_digest';

	/** Option holding the consecutive-failure counter and the last attempt. */
	public const OPTION_FAILURES = 'login_armor_notif_digest_failures';

	/** Option holding the send lock. Not a transient: see acquire_send_lock(). */
	public const SEND_LOCK_OPTION = 'login_armor_notif_digest_lock';

	/** @var string[] Accepted modes, in the order the admin select shows them. */
	public const MODES = array( 'off', 'weekly', 'monthly' );

	/** @var array<string,int> Period length of each sending mode, in days. */
	public const PERIOD_DAYS = array(
		'weekly'  => 7,
		'monthly' => 30,
	);

	/**
	 * The body sections, in the order render() emits them.
	 *
	 * A fixed order is what makes a digest scannable: the reader learns where
	 * to look once. 'suppressed' is the only conditional one.
	 *
	 * @var string[]
	 */
	public const SECTIONS = array( 'score', 'incidents', 'logins', 'targets', 'modules', 'suppressed', 'next' );

	/**
	 * The two windows a module match count can cover.
	 *
	 * WINDOW_PERIOD is the digest period itself; WINDOW_SEVEN_DAYS is the
	 * fixed rolling week of PowChallenge::get_softfail_count(), which is the
	 * only window that counter knows.
	 */
	public const WINDOW_PERIOD     = 'period';
	public const WINDOW_SEVEN_DAYS = 'last_7_days';

	/** How many targeted usernames the digest names. */
	private const TOP_USERNAMES = 5;

	/** A username is truncated at this length: a digest is not a log viewer. */
	private const USERNAME_MAX_LENGTH = 30;

	/**
	 * Discord's 2000-unit ceiling, with a margin.
	 *
	 * Discord counts UTF-16 code units, not characters: every emoji outside
	 * the Basic Multilingual Plane is two. A body measured in characters would
	 * therefore pass this test and still be refused, which is why
	 * truncate_utf16() counts what Discord counts rather than trusting a
	 * margin to absorb it.
	 */
	private const DISCORD_MAX_UNITS = 1900;

	/** Seconds to wait for a webhook. Same budget as the event channels. */
	private const HTTP_TIMEOUT = 15;

	/**
	 * Seconds after which a send lock is considered abandoned.
	 *
	 * Comfortably above the blocking HTTP budget (15 s) plus the collection
	 * queries, and well under the daily tick, so a run killed mid-send never
	 * blocks the feature for more than one tick.
	 */
	private const SEND_LOCK_TTL = 120;

	/**
	 * The exact value this request wrote into the lock row, or null.
	 *
	 * Identity, not bookkeeping: it is what release_send_lock() compares
	 * against so a holder whose TTL expired cannot delete the row of the
	 * request that took over from it.
	 *
	 * @var string|null
	 */
	private static ?string $send_lock_token = null;

	/**
	 * Consecutive failures after which the retry drops to once per period.
	 *
	 * Three is the same threshold ActivityLog\WebhookDispatcher uses before
	 * it backs off to hourly: below it a destination is "down for an hour" and
	 * deserves tomorrow's tick; at it, the destination is broken and a daily
	 * blocking call plus a daily error row buys nothing.
	 */
	private const FAILURE_BACKOFF_THRESHOLD = 3;

	/**
	 * Periods of data a single digest may ever cover.
	 *
	 * A failed send keeps the clock, so an unrepaired destination would widen
	 * the window by one period a day for ever: by day 365 the BETWEEN spans
	 * the whole retained log, and login_armor_logs carries only KEY log_time
	 * and KEY status, so the range degenerates into a scan plus a sort. Two
	 * periods is enough to carry one missed digest into the next.
	 */
	private const MAX_PERIODS_COVERED = 2;

	/**
	 * Current sending mode, always one of self::MODES.
	 */
	public static function get_mode(): string {
		$mode = (string) get_option( self::OPTION_MODE, 'off' );

		return in_array( $mode, self::MODES, true ) ? $mode : 'off';
	}

	/**
	 * Length of a REPORTING window when the configured period cannot give one.
	 *
	 * period_seconds() answers 0 when the mode is `off`. That is right for
	 * "is a digest due" and catastrophic for "how wide is this window": a
	 * zero-second window reports zeros on a site that has traffic. And `off`
	 * is precisely the state `wp login-armor digest --send` is designed to be
	 * used in, since the whole point of the command is to see what a channel
	 * receives BEFORE committing to a weekly e-mail. One helper, used by both
	 * fallbacks, so the two cannot drift apart again.
	 *
	 * @since 2.7.0
	 */
	private static function fallback_period_seconds(): int {
		$period = self::period_seconds();

		return $period > 0 ? $period : self::PERIOD_DAYS['weekly'] * DAY_IN_SECONDS;
	}

	/** Length of the configured period in seconds; 0 when the digest is off. */
	public static function period_seconds(): int {
		$mode = self::get_mode();

		return isset( self::PERIOD_DAYS[ $mode ] ) ? self::PERIOD_DAYS[ $mode ] * DAY_IN_SECONDS : 0;
	}

	/**
	 * The digest's own recipient, when one is set and valid (2.10.0).
	 *
	 * Lets a site receive the digest and no incident mail: the incident
	 * channel can stay "disabled", or point elsewhere.
	 */
	public static function own_recipient(): string {
		$to = trim( (string) get_option( self::OPTION_TO, '' ) );
		return ( '' !== $to && is_email( $to ) ) ? $to : '';
	}

	/**
	 * The channel the digest leaves by (2.10.0).
	 *
	 * Its own recipient makes it e-mail, whatever the incident channel says;
	 * otherwise the incident channel, as before 2.10.0.
	 */
	public static function channel(): string {
		if ( '' !== self::own_recipient() ) {
			return 'email';
		}
		return (string) get_option( 'login_armor_notif_channel', 'disabled' );
	}

	/**
	 * The daily tick. Sends at most one digest, and only when one is due.
	 *
	 * The first run after the feature is switched on sends NOTHING: it stamps
	 * the clock and returns. A digest whose period starts at "whenever the
	 * administrator happened to tick the box" would report three days of data
	 * under a heading that says seven, which is worse than no digest at all.
	 *
	 * A failed send deliberately leaves OPTION_LAST where it is. The next tick
	 * retries, and the period it reports still starts where the last DELIVERED
	 * digest stopped, so a week of data is never skipped by a webhook that was
	 * down for an hour. Two things bound that promise: the window is floored
	 * at MAX_PERIODS_COVERED, and past FAILURE_BACKOFF_THRESHOLD consecutive
	 * failures the retry drops to once per period.
	 *
	 * Everything from the read of OPTION_LAST to the stamp happens under a
	 * lock. Without it the decision and the stamp are separated by a blocking
	 * HTTP call, so two runs read the same clock and send the same digest
	 * twice. That is not hypothetical: core rewrites the whole cron option
	 * with no compare-and-swap (see LoginArmor::self_heal_site_crons()), the
	 * 15-second call outlives WP_CRON_LOCK_TIMEOUT, and
	 * `wp login-armor digest --send` can run beside a tick. Stamping BEFORE
	 * the send would close the race by trading a duplicate for a silence,
	 * which is the worse of the two here.
	 *
	 * @return bool True when a digest was delivered by this call.
	 */
	public static function maybe_send(): bool {
		if ( 'off' === self::get_mode() ) {
			return false;
		}

		$channel = self::channel();
		if ( 'disabled' === $channel ) {
			return false;
		}

		if ( ! self::acquire_send_lock() ) {
			return false;
		}

		try {
			$now  = time();
			$last = self::read_last();

			if ( $last <= 0 ) {
				update_option( self::OPTION_LAST, $now, false );
				return false;
			}

			if ( ! self::is_due( $now, $last ) ) {
				return false;
			}

			// null means another run took the lock over mid-flight and is doing
			// this period. The cron tick has nowhere to report a third state,
			// and nothing was sent by THIS run, so it collapses to false.
			return (bool) self::send_within_lock( $last, $now, $channel );
		} finally {
			self::release_send_lock();
		}
	}

	/**
	 * Deliver one digest immediately, whatever the period says (WP-CLI).
	 *
	 * @return bool|null True sent, false the send failed, null another run holds the lock.
	 */
	public static function send_now(): ?bool {
		$channel = self::channel();
		if ( 'disabled' === $channel ) {
			return false;
		}

		if ( ! self::acquire_send_lock() ) {
			return null;
		}

		try {
			$now  = time();
			$last = self::read_last();

			// ?bool on purpose: null travels all the way to WP-CLI, which says
			// "another run holds the lock" instead of "delivery failed". A run
			// that correctly stood down must not exit non-zero in a script.
			return self::send_within_lock( $last > 0 ? $last : $now - self::fallback_period_seconds(), $now, $channel );
		} finally {
			self::release_send_lock();
		}
	}

	/**
	 * Collect, render, deliver and record the outcome. The caller holds the lock.
	 *
	 * @param int    $last    Origin of the window, before it is floored.
	 * @param int    $now     End of the window.
	 * @param string $channel Configured channel key, for the error message.
	 */
	private static function send_within_lock( int $last, int $now, string $channel ): ?bool {
		$floor = $now - ( self::MAX_PERIODS_COVERED * self::fallback_period_seconds() );
		$from  = max( $last, $floor );
		$data  = self::collect( $from, $now );

		// The floor just dropped everything older than two periods. The Period
		// line is honest about what this digest COVERS, but on its own it
		// reads like a normal week: nothing would say that the months before
		// it were never reported at all, and an operator counting on the
		// digest would never learn there is a hole.
		if ( $last > 0 && $last < $floor ) {
			$data['dropped_before'] = gmdate( 'Y-m-d H:i:s', $from );
		}

		// The backlog of refused alerts is announced by this digest, so this
		// digest is the successful send that clears it. Dispatcher's own
		// contract says the row is cleared by exactly that and by nothing
		// else; without the call the same count came back every period, under
		// a label that prints an hour and never a date. The raw row is kept
		// for the compare-and-clear and stripped before anything renders it:
		// it is bookkeeping, not content.
		//
		// Guarded, because $data has just come back through the public filter
		// login_armor_notif_digest_data: a site callback that replaces
		// `suppressed` with a scalar would otherwise fatal here, on a cron
		// tick, in silence. render() guards the same shape everywhere.
		$announced = '';
		if ( isset( $data['suppressed'] ) && is_array( $data['suppressed'] ) ) {
			$announced = (string) ( $data['suppressed']['raw'] ?? '' );
			unset( $data['suppressed']['raw'] );
		}

		// Everything above this line is reading. Everything below sends. If the
		// lock stopped being ours while we collected, another request is
		// already doing this period, and carrying on would put the same digest
		// out twice. Standing down here is not a failure: nothing was sent, so
		// nothing is recorded, and the holder that owns the lock records the
		// outcome for both of us.
		if ( ! self::holds_send_lock() ) {
			return null;
		}

		if ( ! self::deliver( $data, self::render( $data ) ) ) {
			Dispatcher::store_error( 'Digest send failed for channel: ' . $channel );
			self::record_failure( $now );
			return false;
		}

		update_option( self::OPTION_LAST, $now, false );

		if ( '' !== $announced && class_exists( Dispatcher::class ) ) {
			Dispatcher::clear_suppressed( $announced );
		}

		// A digest that went out is the proof the channel works again. Leaving
		// the last error in place would keep an amber banner on the settings
		// screen for ever after a single bad hour.
		delete_option( 'login_armor_last_notif_error' );
		delete_option( self::OPTION_FAILURES );

		return true;
	}

	/**
	 * Whether a digest is due, period and failure backoff included.
	 *
	 * @param int $now  Current Unix time.
	 * @param int $last Unix time of the last DELIVERED digest.
	 */
	private static function is_due( int $now, int $last ): bool {
		$period = self::period_seconds();

		if ( ( $now - $last ) < $period ) {
			return false;
		}

		$failures = self::read_failures();
		if ( (int) $failures['count'] < self::FAILURE_BACKOFF_THRESHOLD ) {
			return true;
		}

		// Three consecutive failures is not a bad hour, it is a destination
		// nobody has repaired. Retrying daily then buys nothing and costs a
		// blocking 15-second call plus an error row every day; once per period
		// is still often enough to notice a repair, and the error stays on the
		// Notifications section in the meantime, so nothing is lost silently.
		return ( $now - (int) $failures['last_attempt'] ) >= $period;
	}

	/**
	 * Read OPTION_LAST past the object cache.
	 *
	 * The whole point of the lock is to read what the previous holder wrote,
	 * and a cached copy from before that write would defeat it.
	 */
	private static function read_last(): int {
		wp_cache_delete( self::OPTION_LAST, 'options' );

		return (int) get_option( self::OPTION_LAST, 0 );
	}

	/**
	 * Consecutive failures and the time of the last attempt.
	 *
	 * @return array{count:int,last_attempt:int}
	 */
	private static function read_failures(): array {
		$stored = get_option( self::OPTION_FAILURES, array() );
		if ( ! is_array( $stored ) ) {
			$stored = array();
		}

		return array(
			'count'        => max( 0, (int) ( $stored['count'] ?? 0 ) ),
			'last_attempt' => max( 0, (int) ( $stored['last_attempt'] ?? 0 ) ),
		);
	}

	/** Record one failed attempt. */
	private static function record_failure( int $now ): void {
		$failures = self::read_failures();

		update_option(
			self::OPTION_FAILURES,
			array(
				'count'        => (int) $failures['count'] + 1,
				'last_attempt' => $now,
			),
			false
		);
	}

	/**
	 * Take the send lock, or stand down.
	 *
	 * Same compare-and-swap as LoginArmor::acquire_provision_lock() and
	 * GeoIP::acquire_prefetch_lock(), for the same reason: an option row whose
	 * unique option_name index makes INSERT IGNORE an atomic claim, read back
	 * from the table rather than through a cache that may hold the miss from
	 * before the other request wrote it. A transient would not do: it is an
	 * option too, but behind a cache that hides the concurrent writer this
	 * lock exists to see.
	 */
	public static function acquire_send_lock(): bool {
		if ( self::insert_send_lock() ) {
			return true;
		}

		global $wpdb;

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Fresh read of the lock we just failed to take.
		$held_raw = $wpdb->get_var(
			$wpdb->prepare( "SELECT option_value FROM {$wpdb->options} WHERE option_name = %s", self::SEND_LOCK_OPTION )
		);

		// The holder released it between our failed INSERT and this read.
		if ( null === $held_raw ) {
			return self::insert_send_lock();
		}

		$held_since = (int) $held_raw;
		if ( $held_since > 0 && ( time() - $held_since ) < self::SEND_LOCK_TTL ) {
			return false;
		}

		if ( ! self::delete_stale_send_lock( (string) $held_raw ) ) {
			return false;
		}

		return self::insert_send_lock();
	}

	/**
	 * Drop the lock row, but ONLY while it is still the row we took.
	 *
	 * Always called from a finally block, which is exactly why the condition
	 * has to be there. The TTL hands the lock to someone else after 120
	 * seconds; it does not stop the previous holder, which may still be
	 * waiting on a slow query or a slow channel. That holder then reaches its
	 * finally and, with an unconditional DELETE, removes the lock of the
	 * request that legitimately took over. A third request walks straight in
	 * while the second is still collecting, and the same period goes out
	 * twice.
	 *
	 * The token is what makes the row identifiable: a timestamp alone cannot
	 * tell two holders of the same second apart, and `(int)` still reads the
	 * timestamp off the front of it, which is what the staleness check needs.
	 */
	public static function release_send_lock(): void {
		global $wpdb;

		$token                  = (string) self::$send_lock_token;
		self::$send_lock_token = null;

		if ( '' === $token ) {
			return;
		}

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Compare-and-swap release of the lock row this request owns.
		$wpdb->query(
			$wpdb->prepare(
				"DELETE FROM {$wpdb->options} WHERE option_name = %s AND option_value = %s",
				self::SEND_LOCK_OPTION,
				$token
			)
		);

		wp_cache_delete( self::SEND_LOCK_OPTION, 'options' );
	}

	/**
	 * Whether this request still holds the lock, read from the table.
	 *
	 * Releasing conditionally stops a late holder from removing someone
	 * else's row, but it does not stop it from carrying on and delivering a
	 * second copy of the same digest. One read immediately before the send
	 * closes that window from the whole TTL down to the duration of the
	 * delivery itself.
	 */
	private static function holds_send_lock(): bool {
		global $wpdb;

		if ( null === self::$send_lock_token ) {
			return false;
		}

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Fresh read: a cached value would hide the request that took the lock over.
		$held = $wpdb->get_var(
			$wpdb->prepare( "SELECT option_value FROM {$wpdb->options} WHERE option_name = %s", self::SEND_LOCK_OPTION )
		);

		return null !== $held && hash_equals( (string) self::$send_lock_token, (string) $held );
	}

	/** One atomic attempt at the lock row, remembering the token on success. */
	private static function insert_send_lock(): bool {
		global $wpdb;

		$token = time() . ':' . bin2hex( random_bytes( 8 ) );

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Atomic claim via the unique option_name index; core options table.
		$wpdb->query(
			$wpdb->prepare(
				"INSERT IGNORE INTO {$wpdb->options} (option_name, option_value, autoload) VALUES (%s, %s, 'no')",
				self::SEND_LOCK_OPTION,
				$token
			)
		);

		if ( 1 !== (int) $wpdb->rows_affected ) {
			return false;
		}

		self::$send_lock_token = $token;

		return true;
	}

	/**
	 * Delete the lock row ONLY if it still holds the value we read.
	 *
	 * @param string $stale The exact stored value the takeover decision was made on.
	 */
	private static function delete_stale_send_lock( string $stale ): bool {
		global $wpdb;

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Compare-and-swap removal of an abandoned lock row.
		$wpdb->query(
			$wpdb->prepare(
				"DELETE FROM {$wpdb->options} WHERE option_name = %s AND option_value = %s",
				self::SEND_LOCK_OPTION,
				$stale
			)
		);

		if ( 1 !== (int) $wpdb->rows_affected ) {
			return false;
		}

		wp_cache_delete( self::SEND_LOCK_OPTION, 'options' );

		return true;
	}

	/**
	 * Everything the digest reports, for one period. No IP address anywhere.
	 *
	 * @param int|null $from Start of the period (Unix time); defaults to one period ago.
	 * @param int|null $to   End of the period (Unix time); defaults to now.
	 * @return array<string,mixed>
	 */
	public static function collect( ?int $from = null, ?int $to = null ): array {
		global $wpdb;

		$to   = null === $to ? time() : $to;
		$days = self::PERIOD_DAYS[ self::get_mode() ] ?? self::PERIOD_DAYS['weekly'];
		$from = null === $from ? $to - ( $days * DAY_IN_SECONDS ) : $from;

		// After a long outage $from is the last DELIVERED digest, so the login
		// counts below span the real gap while the incident counts, which take
		// a named window, span the nominal period only. Deliberate: nothing is
		// dropped, and the Period line printed at the top of the body states
		// the real interval, so the two are never read as the same thing.

		$from_sql = gmdate( 'Y-m-d H:i:s', $from );
		$to_sql   = gmdate( 'Y-m-d H:i:s', $to );

		// Login outcomes over the period, one grouped read rather than three
		// counts: the table is indexed on log_time and on status, and a digest
		// must never be the heaviest query of the week.
		$logins = array(
			'failed'  => 0,
			'locked'  => 0,
			'success' => 0,
		);
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Custom plugin table, periodic digest.
		$rows = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT status, COUNT(*) AS c FROM {$wpdb->prefix}login_armor_logs WHERE log_time >= %s AND log_time <= %s GROUP BY status",
				$from_sql,
				$to_sql
			)
		);
		foreach ( is_array( $rows ) ? $rows : array() as $row ) {
			$status = (string) ( $row->status ?? '' );
			if ( array_key_exists( $status, $logins ) ) {
				$logins[ $status ] = (int) $row->c;
			}
		}

		// The accounts the period was aimed at. Usernames, never addresses:
		// "admin was tried 400 times" is the actionable half of the story.
		$targets = array();
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Custom plugin table, periodic digest.
		$target_rows = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT username, COUNT(*) AS c FROM {$wpdb->prefix}login_armor_logs
				WHERE log_time >= %s AND log_time <= %s AND status IN ('failed','locked') AND username <> ''
				GROUP BY username ORDER BY c DESC LIMIT %d",
				$from_sql,
				$to_sql,
				self::TOP_USERNAMES
			)
		);
		foreach ( is_array( $target_rows ) ? $target_rows : array() as $row ) {
			$targets[] = array(
				'username' => self::truncate( (string) ( $row->username ?? '' ), self::USERNAME_MAX_LENGTH ),
				'count'    => (int) $row->c,
			);
		}

		$period_filter = 30 === $days ? '30d' : '7d';

		$by_severity = array();
		foreach ( array( 1, 2, 3, 4 ) as $severity ) {
			$by_severity[ $severity ] = class_exists( Incident::class )
				? Incident::count_filtered(
					array(
						'status'   => Incident::STATUS_ACTIVE,
						'severity' => $severity,
					)
				)
				: 0;
		}

		$data = array(
			'site_name'        => (string) get_bloginfo( 'name' ),
			'admin_url'        => admin_url( 'admin.php?page=login-armor' ),
			'mode'             => self::get_mode(),
			'period'           => array(
				'from' => $from_sql,
				'to'   => $to_sql,
				'days' => (int) $days,
			),
			'score'            => class_exists( SecurityScore::class ) ? SecurityScore::compute() : 0,
			'incidents_active' => array(
				'total'       => class_exists( Incident::class )
					? Incident::count_filtered( array( 'status' => Incident::STATUS_ACTIVE ) )
					: 0,
				'by_severity' => $by_severity,
			),
			'incidents_new'    => class_exists( Incident::class )
				? Incident::count_filtered( array( 'period' => $period_filter ) )
				: 0,
			'logins'           => $logins,
			// class_exists() and not method_exists(): LimitLogin is loaded only
			// while brute-force protection is on, so the class may genuinely be
			// absent, but if it is there the method is there.
			'locked_ips'       => class_exists( LimitLogin::class ) ? LimitLogin::get_locked_ips_count() : 0,
			'top_usernames'    => $targets,
			'firewall'         => self::module_state( Firewall::class, $period_filter ),
			'pow'              => self::module_state( PowChallenge::class, $period_filter ),
			'next_action'      => class_exists( SecurityScore::class ) ? SecurityScore::next_action() : array(),
		);

		// The backlog of alerts the hourly caps refused. Absent when there is
		// none: a "0 alerts suppressed" line every week trains the reader to
		// skip the one week it says something else.
		if ( class_exists( Dispatcher::class ) ) {
			$suppressed = Dispatcher::get_suppressed();
			if ( $suppressed['count'] > 0 ) {
				$data['suppressed'] = array(
					'count' => (int) $suppressed['count'],
					'since' => Dispatcher::suppressed_since_label( (string) $suppressed['hour'] ) . ' UTC',
					// Internal: the exact row the compare-and-clear names after
					// a successful send. send_within_lock() strips it before
					// anything renders or transmits the digest.
					'raw'   => (string) $suppressed['raw'],
				);
			}
		}

		/**
		 * Filters the data of one scheduled digest, before it is rendered.
		 *
		 * Adding a key is safe: render() only reads the keys it knows, so a
		 * site that adds its own numbers reaches them through the generic
		 * webhook payload, which carries the whole array.
		 *
		 * @since 2.7.0
		 *
		 * @param array<string,mixed> $data Collected digest data.
		 */
		return (array) apply_filters( 'login_armor_notif_digest_data', $data );
	}

	/**
	 * Subject, plain-text body and compact fields for one collected digest.
	 *
	 * @param array<string,mixed> $data From collect().
	 * @return array{subject:string,body:string,fields:array<int,array{title:string,value:string}>}
	 */
	public static function render( array $data ): array {
		$score  = (int) ( $data['score'] ?? 0 );
		$active = (int) ( $data['incidents_active']['total'] ?? 0 );
		$mode   = (string) ( $data['mode'] ?? 'weekly' );
		$period = is_array( $data['period'] ?? null ) ? $data['period'] : array();

		// Two complete sentences, one per mode. The body is translated, so a
		// subject left in English put an English first line on every French
		// e-mail, Slack card and webhook message; and gluing a translated
		// "monthly" into a translated frame is the same defect one level down.
		$site_name = (string) ( $data['site_name'] ?? '' );
		$subject   = 'monthly' === $mode
			? sprintf(
				/* translators: 1: site name, 2: security score out of 100, 3: number of active incidents. */
				__( '[%1$s] Login Armor monthly digest: score %2$d/100, %3$d active incidents', 'login-armor' ),
				$site_name,
				$score,
				$active
			)
			: sprintf(
				/* translators: 1: site name, 2: security score out of 100, 3: number of active incidents. */
				__( '[%1$s] Login Armor weekly digest: score %2$d/100, %3$d active incidents', 'login-armor' ),
				$site_name,
				$score,
				$active
			);

		$logins = is_array( $data['logins'] ?? null ) ? $data['logins'] : array();
		$fw     = is_array( $data['firewall'] ?? null ) ? $data['firewall'] : array();
		$pow    = is_array( $data['pow'] ?? null ) ? $data['pow'] : array();

		$fields = array(
			array(
				'title' => __( 'Security score', 'login-armor' ),
				'value' => $score . '/100',
			),
			array(
				'title' => __( 'Active incidents', 'login-armor' ),
				'value' => (string) $active,
			),
			array(
				'title' => __( 'Failed logins', 'login-armor' ),
				'value' => (string) (int) ( $logins['failed'] ?? 0 ),
			),
			array(
				'title' => __( 'Locked addresses', 'login-armor' ),
				'value' => (string) (int) ( $data['locked_ips'] ?? 0 ),
			),
			array(
				'title' => __( 'Request firewall', 'login-armor' ),
				'value' => self::module_field( $fw ),
			),
			array(
				'title' => __( 'Bot challenge', 'login-armor' ),
				'value' => self::module_field( $pow ),
			),
		);

		$lines = array();

		$lines[] = sprintf(
			/* translators: 1: period start, 2: period end, both UTC. */
			__( 'Period: %1$s to %2$s UTC.', 'login-armor' ),
			(string) ( $period['from'] ?? '' ),
			(string) ( $period['to'] ?? '' )
		);

		// Said out loud, because a floored window looks exactly like an
		// ordinary one: same shape, same headings, nothing missing on the face
		// of it. Only this line distinguishes "a quiet fortnight" from "two
		// periods out of the eight that went unreported".
		if ( '' !== (string) ( $data['dropped_before'] ?? '' ) ) {
			$lines[] = sprintf(
				/* translators: %s: UTC date and time before which nothing could be reported. */
				__( 'Earlier data is not included: sending had been failing, and this digest cannot cover anything before %s UTC.', 'login-armor' ),
				(string) $data['dropped_before']
			);
		}

		$lines[] = '';

		// 1. Score.
		$lines[] = self::heading( __( 'Security score', 'login-armor' ) );
		$lines[] = sprintf(
			/* translators: %d: security score out of 100. */
			__( '%d out of 100.', 'login-armor' ),
			$score
		);
		$lines[] = '';

		// 2. Incidents.
		$lines[]     = self::heading( __( 'Active incidents', 'login-armor' ) );
		$by_severity = is_array( $data['incidents_active']['by_severity'] ?? null ) ? $data['incidents_active']['by_severity'] : array();
		$lines[]     = sprintf(
			/* translators: 1: total active incidents, 2: critical, 3: high, 4: medium, 5: low. */
			__( '%1$d active in total: %2$d critical, %3$d high, %4$d medium, %5$d low.', 'login-armor' ),
			$active,
			(int) ( $by_severity[4] ?? 0 ),
			(int) ( $by_severity[3] ?? 0 ),
			(int) ( $by_severity[2] ?? 0 ),
			(int) ( $by_severity[1] ?? 0 )
		);
		$lines[] = sprintf(
			/* translators: %d: incidents opened during the period. */
			__( '%d opened during this period.', 'login-armor' ),
			(int) ( $data['incidents_new'] ?? 0 )
		);
		$lines[] = '';

		// 3. Logins.
		$lines[] = self::heading( __( 'Login attempts', 'login-armor' ) );
		$lines[] = sprintf(
			/* translators: 1: failed logins, 2: attempts refused by a lockout, 3: successful logins. */
			__( '%1$d failed, %2$d refused by a lockout, %3$d successful.', 'login-armor' ),
			(int) ( $logins['failed'] ?? 0 ),
			(int) ( $logins['locked'] ?? 0 ),
			(int) ( $logins['success'] ?? 0 )
		);
		$lines[] = sprintf(
			/* translators: %d: number of addresses currently locked out. */
			__( '%d addresses are locked out right now.', 'login-armor' ),
			(int) ( $data['locked_ips'] ?? 0 )
		);
		$lines[] = '';

		// 4. Targets.
		$lines[] = self::heading( __( 'Most targeted usernames', 'login-armor' ) );
		$targets = is_array( $data['top_usernames'] ?? null ) ? $data['top_usernames'] : array();
		if ( empty( $targets ) ) {
			$lines[] = __( 'None: no failed login named an account during this period.', 'login-armor' );
		} else {
			foreach ( $targets as $target ) {
				$lines[] = sprintf(
					/* translators: 1: username, 2: number of attempts against it. */
					__( '%1$s: %2$d attempts', 'login-armor' ),
					(string) ( $target['username'] ?? '' ),
					(int) ( $target['count'] ?? 0 )
				);
			}
		}
		$lines[] = '';

		// 5. Modules.
		$lines[] = self::heading( __( 'Firewall and bot challenge', 'login-armor' ) );
		$lines[] = self::module_line( __( 'Request firewall', 'login-armor' ), $fw );
		$lines[] = self::module_line( __( 'Bot challenge', 'login-armor' ), $pow );
		$lines[] = '';

		// 6. Suppressed alerts, only when there is a backlog to announce.
		if ( ! empty( $data['suppressed']['count'] ) ) {
			$lines[] = self::heading( __( 'Alerts not sent', 'login-armor' ) );
			$lines[] = sprintf(
				/* translators: 1: number of alerts the hourly cap refused, 2: hour the backlog started, UTC. */
				__( 'The hourly cap refused %1$d alerts since %2$s. Raise the rate limit if this keeps happening.', 'login-armor' ),
				(int) $data['suppressed']['count'],
				(string) ( $data['suppressed']['since'] ?? '' )
			);
			$lines[]  = '';
			$fields[] = array(
				'title' => __( 'Alerts not sent', 'login-armor' ),
				'value' => (string) (int) $data['suppressed']['count'],
			);
		}

		// 7. Next action.
		$lines[]     = self::heading( __( 'Next action', 'login-armor' ) );
		$next_action = is_array( $data['next_action'] ?? null ) ? $data['next_action'] : array();
		if ( '' !== (string) ( $next_action['title'] ?? '' ) ) {
			$lines[] = (string) $next_action['title'];
		}
		if ( '' !== (string) ( $next_action['body'] ?? '' ) ) {
			$lines[] = (string) $next_action['body'];
		}
		$lines[] = '';
		$lines[] = (string) ( $data['admin_url'] ?? '' );

		return array(
			'subject' => $subject,
			'body'    => implode( "\n", $lines ),
			'fields'  => $fields,
		);
	}

	/**
	 * Send one rendered digest through the configured channel.
	 *
	 * Self-contained on purpose: it does NOT implement ChannelInterface. That
	 * contract describes one incident, with a severity, an IP and an events
	 * count, and every channel renders those four things. A digest has none of
	 * them, and bending it into that shape would mean inventing a severity and
	 * an address for a summary that has neither.
	 *
	 * @param array<string,mixed> $data     From collect().
	 * @param array<string,mixed> $rendered From render().
	 */
	public static function deliver( array $data, array $rendered ): bool {
		$channel = self::channel();
		$target  = (string) get_option( 'login_armor_notif_webhook_url', '' );
		$subject = (string) ( $rendered['subject'] ?? '' );
		$body    = (string) ( $rendered['body'] ?? '' );

		if ( 'email' === $channel ) {
			$to = self::own_recipient();
			if ( '' === $to ) {
				$to = is_email( $target ) ? $target : (string) get_option( 'admin_email', '' );
			}
			if ( '' === $to ) {
				return false;
			}
			return (bool) wp_mail( $to, $subject, $body );
		}

		// Re-validated at the egress point, not only at save time: DNS can be
		// re-pointed at a private host long after the URL was stored, and a
		// digest is the one message that leaves on a schedule nobody watches.
		if ( '' === $target || ! SafeUrl::is_safe( $target ) ) {
			return false;
		}

		$text = $subject . "\n\n" . $body;

		switch ( $channel ) {
			case 'slack':
				$payload = array( 'text' => $text );
				break;
			case 'discord':
				$payload = array( 'content' => self::truncate_utf16( $text, self::DISCORD_MAX_UNITS ) );
				break;
			case 'generic':
				$payload = array(
					'type'    => 'digest',
					'plugin'  => 'login-armor',
					'version' => defined( 'LOGIN_ARMOR_VERSION' ) ? LOGIN_ARMOR_VERSION : '',
					'site'    => (string) ( $data['site_name'] ?? '' ),
					'period'  => is_array( $data['period'] ?? null ) ? $data['period'] : array(),
					'data'    => $data,
					'fields'  => is_array( $rendered['fields'] ?? null ) ? $rendered['fields'] : array(),
				);
				break;
			default:
				return false;
		}

		$response = wp_safe_remote_post(
			$target,
			array(
				// Blocking, unlike the event channels: this runs on cron, not
				// in a visitor's request, and a digest that silently failed
				// would never be retried because nothing would know.
				'blocking'    => true,
				'timeout'     => self::HTTP_TIMEOUT,
				'sslverify'   => true,
				'redirection' => 0,
				'headers'     => array( 'Content-Type' => 'application/json' ),
				'body'        => wp_json_encode( $payload ),
			)
		);

		if ( is_wp_error( $response ) ) {
			return false;
		}

		$code = (int) wp_remote_retrieve_response_code( $response );

		return $code >= 200 && $code < 300;
	}

	/**
	 * State of one monitor-first module, with the match count it can answer.
	 *
	 * The two modules do NOT count over the same window, and pretending they
	 * do is how a monthly digest ends up overstating. The firewall counts
	 * incidents, so it answers any period the digest asks for. The bot
	 * challenge keeps a rolling seven-day counter and nothing else, so on a
	 * monthly digest its figure covers seven days out of thirty. The window is
	 * returned with the count and the wording follows it, rather than the
	 * reader being left to assume.
	 *
	 * @param string $module_class  Firewall or PowChallenge.
	 * @param string $period_filter '7d' or '30d'.
	 * @return array<string,mixed>
	 */
	private static function module_state( string $module_class, string $period_filter ): array {
		if ( ! class_exists( $module_class ) ) {
			return array(
				'enabled'         => false,
				'mode'            => 'off',
				'monitoring_days' => 0,
				'matches'         => 0,
				'window'          => self::WINDOW_PERIOD,
			);
		}

		// get_mode() and not an effective mode: a sibling branch introduces
		// Firewall::effective_mode() / PowChallenge::effective_mode() for the
		// safe-mode switch. When both land, this is where the digest should
		// report the EFFECTIVE mode, so a site running in safe mode does not
		// read a digest claiming it is enforcing.
		$enabled = $module_class::is_enabled();
		$is_fw   = Firewall::class === $module_class;
		$matches = $is_fw
			? $module_class::count_blocks( $period_filter )
			: $module_class::get_softfail_count();

		return array(
			'enabled'         => (bool) $enabled,
			'mode'            => $enabled ? $module_class::get_mode() : 'off',
			'monitoring_days' => $module_class::monitoring_days(),
			'matches'         => (int) $matches,
			'window'          => $is_fw ? self::WINDOW_PERIOD : self::WINDOW_SEVEN_DAYS,
		);
	}

	/**
	 * Compact state of a module, for the webhook cards.
	 *
	 * @param array<string,mixed> $state From module_state().
	 */
	private static function module_field( array $state ): string {
		if ( empty( $state['enabled'] ) ) {
			return __( 'off', 'login-armor' );
		}

		$mode = 'enforce' === (string) ( $state['mode'] ?? '' )
			? __( 'enforcing', 'login-armor' )
			: sprintf(
				/* translators: %d: days the module has been in monitor mode. */
				__( 'monitoring for %d days', 'login-armor' ),
				(int) ( $state['monitoring_days'] ?? 0 )
			);

		if ( self::WINDOW_SEVEN_DAYS === (string) ( $state['window'] ?? '' ) ) {
			return sprintf(
				/* translators: 1: module state, 2: number of matches over the last 7 days. */
				__( '%1$s, %2$d matches over the last 7 days', 'login-armor' ),
				$mode,
				(int) ( $state['matches'] ?? 0 )
			);
		}

		return sprintf(
			/* translators: 1: module state, 2: number of matches over the digest period. */
			__( '%1$s, %2$d matches over this period', 'login-armor' ),
			$mode,
			(int) ( $state['matches'] ?? 0 )
		);
	}

	/**
	 * One body line describing a monitor-first module.
	 *
	 * @param string              $label Module name.
	 * @param array<string,mixed> $state From module_state().
	 */
	private static function module_line( string $label, array $state ): string {
		if ( empty( $state['enabled'] ) ) {
			/* translators: %s: module name. */
			return sprintf( __( '%s: off.', 'login-armor' ), $label );
		}

		$seven   = self::WINDOW_SEVEN_DAYS === (string) ( $state['window'] ?? '' );
		$matches = (int) ( $state['matches'] ?? 0 );

		if ( 'enforce' === (string) ( $state['mode'] ?? '' ) ) {
			if ( $seven ) {
				return sprintf(
					/* translators: 1: module name, 2: number of matches over the last 7 days. */
					__( '%1$s: enforcing, %2$d matches over the last 7 days.', 'login-armor' ),
					$label,
					$matches
				);
			}
			return sprintf(
				/* translators: 1: module name, 2: number of matches over the digest period. */
				__( '%1$s: enforcing, %2$d matches over this period.', 'login-armor' ),
				$label,
				$matches
			);
		}

		if ( $seven ) {
			return sprintf(
				/* translators: 1: module name, 2: days in monitor mode, 3: number of matches over the last 7 days. */
				__( '%1$s: monitoring for %2$d days, %3$d matches over the last 7 days.', 'login-armor' ),
				$label,
				(int) ( $state['monitoring_days'] ?? 0 ),
				$matches
			);
		}

		return sprintf(
			/* translators: 1: module name, 2: days in monitor mode, 3: number of matches over the digest period. */
			__( '%1$s: monitoring for %2$d days, %3$d matches over this period.', 'login-armor' ),
			$label,
			(int) ( $state['monitoring_days'] ?? 0 ),
			$matches
		);
	}

	/** A section heading, rendered the same way everywhere. */
	private static function heading( string $title ): string {
		return '== ' . $title . ' ==';
	}

	/**
	 * Cut a string to a maximum number of CHARACTERS.
	 *
	 * Characters and not bytes, on both sides of the test: Discord counts its
	 * 2000-character ceiling in characters, and "truncated to 30 characters"
	 * is what the username rule means. Measuring the input in bytes and then
	 * cutting in characters, as this did first, could hand Discord a string
	 * longer than the ceiling it was cut to.
	 */
	private static function truncate( string $value, int $length ): string {
		if ( mb_strlen( $value ) <= $length ) {
			return $value;
		}

		return rtrim( mb_substr( $value, 0, $length ) );
	}

	/**
	 * Length in UTF-16 code units, which is what Discord counts.
	 *
	 * One unit per character, two for anything above the Basic Multilingual
	 * Plane: emoji, and the rarer CJK extensions.
	 */
	private static function utf16_length( string $value ): int {
		$astral = preg_match_all( '/[\x{10000}-\x{10FFFF}]/u', $value );

		return mb_strlen( $value ) + ( is_int( $astral ) ? $astral : 0 );
	}

	/**
	 * Cut a string to a maximum number of UTF-16 code units.
	 *
	 * Cutting to $units CHARACTERS can only ever overshoot, since every
	 * character is at least one unit; the loop then sheds characters until the
	 * unit count fits.
	 *
	 * What it must not do is shed one character per excess UNIT. An astral
	 * character is worth two units, so on a body of emoji that removed twice
	 * as many characters as there were units in surplus and came back EMPTY.
	 * Discord answers 400 to an empty body, so the send was recorded as a
	 * failure rather than as a truncation, and the failure counter started
	 * climbing for a message that was merely long. Halving the excess removes
	 * at least one character per pass and at most one unit more than the
	 * surplus, so it converges in O(log n) and never cuts the string away.
	 */
	private static function truncate_utf16( string $value, int $units ): string {
		if ( $units <= 0 ) {
			return '';
		}

		if ( self::utf16_length( $value ) <= $units ) {
			return $value;
		}

		$cut = mb_substr( $value, 0, $units );
		while ( '' !== $cut ) {
			$excess = self::utf16_length( $cut ) - $units;
			if ( $excess <= 0 ) {
				break;
			}
			$drop = max( 1, (int) ceil( $excess / 2 ) );
			$cut  = mb_substr( $cut, 0, max( 0, mb_strlen( $cut ) - $drop ) );
		}

		return rtrim( $cut );
	}
}
