<?php
/**
 * GeoIP module: optional, opt-in country-level geolocation of the IP
 * addresses Login Armor already displays.
 *
 * The design and its trade-offs are documented on the class below. The file
 * header is kept short on purpose: Plugin Check only looks for the direct
 * access guard in the first fifty lines of a file, and a long header pushes it
 * out of reach.
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
 * Country-level IP geolocation.
 *
 * Design, consistent with {@see \LoginArmor\BreachCheck}:
 *
 * - **Opt-in**: off until an admin enables it. Nothing is sent anywhere
 *   while it is off.
 *
 * - **No network during page rendering** (2.6.1). Until 2.6.0 the lookup
 *   happened inline, while the Incidents or Events screen was being built:
 *   up to fifteen sequential HTTPS calls, each allowed three seconds, could
 *   run before the first row reached the browser, and a slow or unreachable
 *   API turned every admin page load into a stall. lookup() now reads the
 *   cache and nothing else. The network belongs to prefetch(), which runs
 *   from WP-Cron, behind a single-worker lock, at most
 *   MAX_RESOLUTIONS_PER_RUN addresses every five minutes.
 *
 *   The compromise is explicit: a site with no working cron (and no system
 *   cron calling wp-cron.php) never fills the cache, so the badges stay
 *   empty. An empty badge is the failure mode we chose over a frozen
 *   dashboard.
 *
 * - **Country on screen, network in the cache**: the screens surface the ISO
 *   country code and name only. Since 2.9.0 the cache also keeps the AS
 *   number and the organisation (for the application-password usage
 *   journal). We never store city or coordinates, even though the API may
 *   return them.
 *
 * - **Fail-soft, and two different kinds of "no"**. An answer from the API
 *   that carries no country is a fact about the address: it is cached for
 *   CACHE_TTL like any other answer. A transport error, a non-200 or a body
 *   we cannot parse says nothing about the address and everything about the
 *   link: it writes a short retry marker for that IP (RETRY_TTL) and opens a
 *   circuit breaker (FAILURE_TTL) that stops the whole run. Caching a
 *   transport outage for thirty days would have blinded the feature for a
 *   month over a five-second blip.
 *
 * - **Pluggable source**: the actual lookup is wrapped in the
 *   `login_armor_geoip_lookup` filter, so a site can short-circuit it
 *   with an offline database (MaxMind, IP2Location) and make zero
 *   external calls. The bundled default is a keyless public HTTPS API.
 *
 * - **Private-by-design cache keys**: transient keys are a SHA-256 of the
 *   IP, never the raw address.
 */
class GeoIP {

	public const OPTION_ENABLED = 'login_armor_geoip_enabled';

	/** Keyless public HTTPS endpoint. The IP is appended. */
	public const API_ENDPOINT = 'https://ipwho.is/';

	/**
	 * Seconds a single lookup may spend on the wire.
	 *
	 * 1.5 rather than the former 3: nobody is waiting for this any more. A
	 * cron pass that loses an address to a slow answer simply retries it in
	 * five minutes, and a short ceiling keeps a stalled upstream from eating
	 * the whole PHP time limit of the cron request.
	 */
	public const REQUEST_TIMEOUT = 1.5;

	/** How long an ANSWER from the API is trusted, including "no country". */
	public const CACHE_TTL = 30 * DAY_IN_SECONDS;

	/**
	 * How long one address is left alone after a TEMPORARY failure.
	 *
	 * Distinct from CACHE_TTL on purpose: this marker records that the link
	 * failed, not that the address has no country.
	 */
	public const RETRY_TTL = HOUR_IN_SECONDS;

	public const USER_AGENT = 'LoginArmor-GeoIP/1.0';

	/**
	 * Background resolver hook.
	 *
	 * Listed in {@see LoginArmor::CRON_HOOKS} so deactivation and uninstall
	 * clear it like every other event, but scheduled only while the module is
	 * on: see sync_prefetch_schedule().
	 */
	public const CRON_HOOK = 'login_armor_geoip_prefetch';

	/**
	 * Option holding the single-worker lock of a prefetch pass.
	 *
	 * Not a transient, for the same reason as
	 * {@see LoginArmor::PROVISION_LOCK_OPTION}: a transient is read through a
	 * cache that would hide a concurrent writer, and the whole point is to let
	 * exactly one of two simultaneous cron requests through.
	 */
	public const PREFETCH_LOCK_OPTION = 'login_armor_geoip_prefetch_lock';

	/**
	 * Seconds after which a prefetch lock is considered abandoned.
	 *
	 * Shorter than the five-minute interval, so a request killed mid-pass
	 * cannot make the next one skip its turn.
	 */
	public const PREFETCH_LOCK_TTL = 240;

	/**
	 * Option holding the activity watermark of the last idle pass.
	 *
	 * Most sites are quiet most of the time, and on a quiet site every pass
	 * used to walk both tables and read a transient per candidate to conclude
	 * there was nothing to do, 288 times a day, forever. This holds the two
	 * MAX() values seen when a pass last ended with nothing to resolve and
	 * both tables exhausted; while they are unchanged, there cannot be a new
	 * address, so the next pass returns after two indexed MAX() reads.
	 *
	 * Never autoloaded: it is read once per pass, from cron, and never by a
	 * page render.
	 */
	public const WATERMARK_OPTION = 'login_armor_geoip_watermark';

	/** Transient opened after a temporary upstream failure. */
	public const FAILURE_CIRCUIT = 'login_armor_geoip_failure_circuit';

	/** Failure circuit duration in seconds. Mirrors BreachCheck. */
	public const FAILURE_TTL = 300;

	/**
	 * Cap on RESOLUTIONS per pass, not on candidates examined.
	 *
	 * A cap on candidates would starve: the newest addresses are the ones
	 * already resolved, so the first fifty candidates of every run are cache
	 * hits and nothing new would ever be looked up.
	 */
	public const MAX_RESOLUTIONS_PER_RUN = 20;

	/** Candidate rows read per page, per table. */
	public const CANDIDATE_PAGE_SIZE = 50;

	/** Hard bound on pages walked in one pass, so a huge table cannot loop. */
	public const MAX_PAGES_PER_RUN = 20;

	/**
	 * Whether the module is enabled.
	 */
	public static function is_enabled(): bool {
		return (bool) get_option( self::OPTION_ENABLED, false );
	}

	/**
	 * Whether an address is a public one we are allowed to send anywhere.
	 *
	 * Private and reserved ranges are pointless to geolocate and would leak
	 * internal topology to the API.
	 *
	 * @param string $ip IPv4/IPv6 address.
	 */
	public static function is_public_ip( string $ip ): bool {
		$ip = trim( $ip );
		if ( '' === $ip || false === filter_var( $ip, FILTER_VALIDATE_IP ) ) {
			return false;
		}

		return false !== filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE );
	}

	/**
	 * Transient key of a resolved answer. SHA-256, never the raw address.
	 *
	 * @param string $ip IP address.
	 */
	private static function cache_key( string $ip ): string {
		return 'la_geoip_' . hash( 'sha256', $ip );
	}

	/**
	 * Transient key of the short retry marker of a temporary failure.
	 *
	 * @param string $ip IP address.
	 */
	private static function retry_key( string $ip ): string {
		return 'la_geoip_retry_' . hash( 'sha256', $ip );
	}

	/**
	 * Resolve an IP to a country FROM THE CACHE ONLY.
	 *
	 * This is what the admin screens call, so it must never touch the
	 * network. An address nobody has resolved yet simply has no badge until
	 * the next prefetch pass reaches it.
	 *
	 * @param string $ip IPv4/IPv6 address.
	 * @return array{code:string, name:string, asn?:int, org?:string}|null Country info, or null when unknown / disabled / private IP / not resolved yet.
	 */
	public static function lookup( string $ip ): ?array {
		$ip = trim( $ip );
		if ( ! self::is_public_ip( $ip ) ) {
			return null;
		}

		/**
		 * Short-circuit the geolocation lookup, e.g. with an offline database.
		 *
		 * Return an array with `code` and `name` keys to bypass the bundled
		 * HTTPS API entirely. Return null to fall through to the default.
		 *
		 * An offline database answers in microseconds, so this filter is still
		 * honoured during rendering: the "no network while rendering" rule is
		 * about the bundled HTTPS source, which is the only one that can stall.
		 *
		 * @param array{code:string, name:string}|null $pre Pre-resolved country, or null.
		 * @param string                               $ip  The IP being resolved.
		 */
		$pre = apply_filters( 'login_armor_geoip_lookup', null, $ip );
		if ( is_array( $pre ) && isset( $pre['code'] ) ) {
			return [ 'code' => (string) $pre['code'], 'name' => (string) ( $pre['name'] ?? $pre['code'] ) ];
		}

		if ( ! self::is_enabled() ) {
			return null;
		}

		$cached = get_transient( self::cache_key( $ip ) );
		if ( is_array( $cached ) ) {
			return ( isset( $cached['code'] ) && '' !== $cached['code'] ) ? $cached : null;
		}

		return null;
	}

	/**
	 * Network facts of an address, FROM THE CACHE ONLY (2.9.0).
	 *
	 * Null when the address has not been resolved, or was resolved before
	 * 2.9.0 (no "asn" key): the usage review then resolves it again on its
	 * own budget, never the rendering path.
	 *
	 * @param string $ip IPv4/IPv6 address.
	 * @return array{asn:int, org:string, code:string}|null
	 */
	public static function cached_network( string $ip ): ?array {
		$cached = get_transient( self::cache_key( trim( $ip ) ) );
		if ( ! is_array( $cached ) || ! array_key_exists( 'asn', $cached ) ) {
			return null;
		}
		return [
			'asn'  => (int) $cached['asn'],
			'org'  => (string) ( $cached['org'] ?? '' ),
			'code' => (string) ( $cached['code'] ?? '' ),
		];
	}

	/**
	 * Resolve an IP over the network and cache the answer.
	 *
	 * Called by the prefetch pass, and public so a site operator can warm a
	 * single address by hand. Never called from a rendering path.
	 *
	 * The failure circuit is deliberately NOT consulted here. The circuit is a
	 * property of a PASS: prefetch() refuses to start while it is open, and
	 * ends the moment a resolution opens it. Checking it here too would make
	 * close_circuit() unreachable, because no success could ever happen while
	 * the circuit is open and nothing would then close it but the clock.
	 *
	 * @param string $ip IPv4/IPv6 address.
	 * @return array{code:string, name:string, asn?:int, org?:string}|null Country info, or null on any failure.
	 */
	public static function resolve( string $ip ): ?array {
		$ip = trim( $ip );
		if ( ! self::is_public_ip( $ip ) ) {
			return null;
		}

		/** This filter is documented in includes/class-geoip.php */
		$pre = apply_filters( 'login_armor_geoip_lookup', null, $ip );
		if ( is_array( $pre ) && isset( $pre['code'] ) ) {
			$offline = [
				'code' => (string) $pre['code'],
				'name' => (string) ( $pre['name'] ?? $pre['code'] ),
				// 2.9.0: an offline database may know the network too.
				'asn'  => (int) ( $pre['asn'] ?? 0 ),
				'org'  => (string) ( $pre['org'] ?? '' ),
			];
			// Cached, but NOT to spare the rendering path: lookup() consults
			// the filter before the cache, so a site with an offline database
			// never reads this entry while building a page. What it spares is
			// the pass, which skips an address that already has an answer
			// instead of calling the database again every five minutes.
			set_transient( self::cache_key( $ip ), $offline, self::CACHE_TTL );
			return $offline;
		}

		if ( ! self::is_enabled() ) {
			return null;
		}

		$response = wp_remote_get(
			self::API_ENDPOINT . rawurlencode( $ip ),
			[
				'timeout'    => self::REQUEST_TIMEOUT,
				'user-agent' => self::USER_AGENT,
			]
		);
		if ( is_wp_error( $response ) ) {
			self::remember_temporary_failure( $ip );
			return null;
		}
		$status = (int) wp_remote_retrieve_response_code( $response );

		// The free tier of ipwho.is allows 1000 requests a day per client IP,
		// then answers 429 with a Retry-After. Twenty addresses every five
		// minutes is 5760 a day, so a busy site WILL hit the quota. Retrying
		// every five minutes after that would spend the whole of the next day
		// collecting 429s, so the circuit is held open for as long as the API
		// asks, and a 429 is never mistaken for an answer about the address.
		if ( 429 === $status ) {
			self::remember_rate_limit( $ip, wp_remote_retrieve_header( $response, 'retry-after' ) );
			return null;
		}

		if ( 200 !== $status ) {
			self::remember_temporary_failure( $ip );
			return null;
		}

		$body = (string) wp_remote_retrieve_body( $response );
		$data = '' === trim( $body ) ? null : json_decode( $body, true );
		if ( ! is_array( $data ) ) {
			self::remember_temporary_failure( $ip );
			return null;
		}

		// A well-formed answer, whatever it says about this address, proves the
		// link works: close the circuit and forget the retry marker.
		self::close_circuit( $ip );

		// 2.9.0: the network of the address, read from the same answer, for
		// the application-password usage journal. ipwho.is puts it under
		// "connection"; the organisation falls back to the ISP name.
		$asn = 0;
		$org = '';
		if ( isset( $data['connection'] ) && is_array( $data['connection'] ) ) {
			$asn     = isset( $data['connection']['asn'] ) ? absint( $data['connection']['asn'] ) : 0;
			foreach ( array( 'org', 'isp' ) as $org_key ) {
				$org_raw = $data['connection'][ $org_key ] ?? '';
				$org     = is_string( $org_raw ) ? mb_substr( sanitize_text_field( $org_raw ), 0, 100 ) : '';
				if ( '' !== $org ) {
					break;
				}
			}
		}

		// Defensive parsing: accept either ipwho.is (`country_code`,
		// `country`) or a country.is-style (`country`) payload. An error
		// envelope (`success: false`) carries neither and falls through to the
		// negative cache below, which is correct: the API has answered about
		// this address and will answer the same way tomorrow.
		$code = '';
		if ( isset( $data['country_code'] ) && is_string( $data['country_code'] ) ) {
			$code = strtoupper( substr( $data['country_code'], 0, 2 ) );
		} elseif ( isset( $data['country'] ) && is_string( $data['country'] ) && 2 === strlen( $data['country'] ) ) {
			$code = strtoupper( $data['country'] );
		}

		$name = '';
		if ( isset( $data['country'] ) && is_string( $data['country'] ) && strlen( $data['country'] ) > 2 ) {
			$name = sanitize_text_field( $data['country'] );
		}

		if ( '' === $code || ! preg_match( '/^[A-Z]{2}$/', $code ) ) {
			// Definitive negative: the API answered and has no country for this
			// address. Cached as long as a positive answer.
			set_transient( self::cache_key( $ip ), [ 'code' => '', 'name' => '', 'asn' => $asn, 'org' => $org ], self::CACHE_TTL );
			return null;
		}

		$result = [ 'code' => $code, 'name' => ( '' !== $name ? $name : $code ), 'asn' => $asn, 'org' => $org ];
		set_transient( self::cache_key( $ip ), $result, self::CACHE_TTL );
		return $result;
	}

	/**
	 * Whether the failure circuit is open.
	 */
	public static function is_circuit_open(): bool {
		return false !== get_transient( self::FAILURE_CIRCUIT );
	}

	/**
	 * Record a TEMPORARY failure: one short marker for the address, one
	 * circuit for the whole module.
	 *
	 * @param string $ip IP address that failed.
	 */
	private static function remember_temporary_failure( string $ip ): void {
		set_transient( self::retry_key( $ip ), 1, self::RETRY_TTL );
		set_transient( self::FAILURE_CIRCUIT, 1, self::FAILURE_TTL );
	}

	/**
	 * Record a quota refusal (HTTP 429), honouring Retry-After.
	 *
	 * Like any other link failure this is NOT cached as an answer: the address
	 * gets the usual one-hour retry marker and nothing is written to the
	 * thirty-day cache. What differs is the circuit, which is held open for as
	 * long as the API asked rather than the usual five minutes.
	 *
	 * Retry-After may also be an HTTP-date (RFC 9110). We deliberately do not
	 * parse it: a date we misread would either hammer the API or blind the
	 * module for a day, and FAILURE_TTL is already the right answer to "come
	 * back later". A non-numeric header therefore falls back to FAILURE_TTL.
	 *
	 * @param string $ip          IP address that was refused.
	 * @param mixed  $retry_after Raw Retry-After header, as core returns it.
	 */
	private static function remember_rate_limit( string $ip, $retry_after ): void {
		$raw = is_array( $retry_after ) ? (string) reset( $retry_after ) : (string) $retry_after;
		$raw = trim( $raw );

		$seconds = ctype_digit( $raw ) ? (int) $raw : 0;
		$ttl     = min( max( $seconds, self::FAILURE_TTL ), DAY_IN_SECONDS );

		set_transient( self::retry_key( $ip ), 1, self::RETRY_TTL );
		set_transient( self::FAILURE_CIRCUIT, 1, $ttl );
	}

	/**
	 * Forget the circuit and the retry marker of an address that answered.
	 *
	 * @param string $ip IP address that answered.
	 */
	private static function close_circuit( string $ip ): void {
		delete_transient( self::FAILURE_CIRCUIT );
		delete_transient( self::retry_key( $ip ) );
	}

	// ── Scheduling ────────────────────────────────────────────────────────

	/**
	 * Schedule or unschedule the prefetch event to match the enable option.
	 *
	 * Called by LoginArmor::schedule_site_crons() (so provisioning, the
	 * multisite walk and the daily self-heal all agree), by the admin AJAX
	 * toggles and by the settings importer. Idempotent.
	 */
	public static function sync_prefetch_schedule(): void {
		if ( self::is_enabled() ) {
			self::schedule_prefetch();
			return;
		}

		self::unschedule_prefetch();
	}

	/**
	 * Schedule the prefetch event on the CURRENT site, if it is not already.
	 *
	 * Same ordering trap as LoginArmor::schedule_site_crons(): on activation
	 * the `cron_schedules` filter is not registered yet, and
	 * wp_schedule_event() would refuse the custom recurrence and schedule
	 * nothing at all. WordPress de-duplicates the filter by callback identity.
	 */
	public static function schedule_prefetch(): void {
		add_filter( 'cron_schedules', [ LoginArmor::class, 'register_cron_intervals' ] );

		if ( ! wp_next_scheduled( self::CRON_HOOK ) ) {
			wp_schedule_event( time() + 300, 'login_armor_5min', self::CRON_HOOK );
		}
	}

	/**
	 * Clear the prefetch event on the CURRENT site.
	 */
	public static function unschedule_prefetch(): void {
		wp_clear_scheduled_hook( self::CRON_HOOK );
	}

	// ── Prefetch pass ─────────────────────────────────────────────────────

	/**
	 * Cron callback. No arguments: WP-Cron passes the event args, and this
	 * event is scheduled without any.
	 */
	public static function run_prefetch(): void {
		self::prefetch();
	}

	/**
	 * Resolve up to MAX_RESOLUTIONS_PER_RUN uncached addresses.
	 *
	 * @return int Addresses actually sent to the resolver.
	 */
	public static function prefetch(): int {
		// The module may have been switched off since the event was scheduled
		// (or the option restored from a backup). Take the event out with us.
		if ( ! self::is_enabled() ) {
			self::unschedule_prefetch();
			return 0;
		}

		if ( self::is_circuit_open() ) {
			return 0;
		}

		if ( ! self::acquire_prefetch_lock() ) {
			return 0;
		}

		try {
			return self::resolve_candidates();
		} finally {
			self::release_prefetch_lock();
		}
	}

	/**
	 * Walk the candidate pages until the resolution budget is spent.
	 */
	private static function resolve_candidates(): int {
		// Nothing has happened on this site since the last pass that found
		// nothing to do: there cannot be a new address, so do not go looking
		// for one. Two indexed MAX() reads instead of a full candidate walk.
		$watermark = self::activity_watermark();
		if ( (string) get_option( self::WATERMARK_OPTION, '' ) === $watermark ) {
			return 0;
		}

		$cutoff    = self::retention_cutoff();
		$resolved  = 0;
		$offset    = 0;
		$deferred  = 0;
		$exhausted = false;

		for ( $page = 0; $page < self::MAX_PAGES_PER_RUN; $page++ ) {
			$candidates = self::candidate_page( $cutoff, self::CANDIDATE_PAGE_SIZE, $offset );
			if ( empty( $candidates ) ) {
				$exhausted = true;
				break;
			}
			$offset += self::CANDIDATE_PAGE_SIZE;

			foreach ( $candidates as $ip ) {
				if ( $resolved >= self::MAX_RESOLUTIONS_PER_RUN ) {
					return $resolved;
				}
				if ( ! self::is_public_ip( $ip ) ) {
					continue;
				}
				// Already answered for, or already known to have failed
				// recently: both are skipped without spending the budget, which
				// is what lets an uncached address sitting behind hundreds of
				// cached ones still be reached in this same pass.
				if ( false !== get_transient( self::cache_key( $ip ) ) ) {
					continue;
				}
				if ( false !== get_transient( self::retry_key( $ip ) ) ) {
					// Work POSTPONED, not work absent. Recording the watermark
					// now would mean never coming back to this address once its
					// marker expires, because nothing new would have happened
					// on the site in the meantime.
					++$deferred;
					continue;
				}

				self::resolve( $ip );
				++$resolved;

				// A temporary failure just opened the circuit: stop now rather
				// than spend nineteen more timeouts on a link that is down.
				if ( self::is_circuit_open() ) {
					return $resolved;
				}
			}
		}

		// Only a pass that saw EVERY candidate, resolved none and postponed
		// none can promise that nothing is left to do.
		if ( 0 === $resolved && 0 === $deferred && $exhausted ) {
			update_option( self::WATERMARK_OPTION, $watermark, false );
		}

		return $resolved;
	}

	/**
	 * The most recent activity of each table, as one opaque string.
	 *
	 * Deliberately not restricted to the retention window: rows leaving that
	 * window only ever REMOVE candidates, never add one, so ignoring them
	 * cannot make the resolver skip work it should have done. Both columns are
	 * indexed, so each MAX() is a single index read.
	 *
	 * An empty table contributes an empty half; a site with two empty tables
	 * has a stable watermark of its own and is skipped like any other quiet
	 * site.
	 */
	private static function activity_watermark(): string {
		global $wpdb;

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Custom plugin table, single indexed MAX() for the background resolver.
		$logs = (string) $wpdb->get_var( "SELECT MAX(log_time) FROM {$wpdb->prefix}login_armor_logs" );

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Custom plugin table, single indexed MAX() for the background resolver.
		$incidents = (string) $wpdb->get_var( "SELECT MAX(last_seen_at) FROM {$wpdb->prefix}login_armor_incidents" );

		return $logs . '|' . $incidents;
	}

	/**
	 * Oldest event date still worth a country badge.
	 *
	 * The log retention window, not twenty-four hours: an incident opened
	 * three weeks ago is still on screen, and its IP still deserves a flag.
	 */
	private static function retention_cutoff(): string {
		$days = (int) get_option(
			'login_armor_log_retention_days',
			(int) get_option( 'login_armor_logs_auto_purge', 90 )
		);
		if ( $days <= 0 ) {
			$days = 90;
		}

		return gmdate( 'Y-m-d H:i:s', time() - $days * DAY_IN_SECONDS );
	}

	/**
	 * One page of candidate addresses, newest activity first.
	 *
	 * Both tables are read, because they do not hold the same addresses: the
	 * firewall, the honeypot, the proof-of-work challenge, the username
	 * blacklist and the 2FA recovery limiter all open an incident WITHOUT
	 * writing a login-log row, so their IPs exist only in the incidents table
	 * and a logs-only candidate query would never geolocate a single one of
	 * them.
	 *
	 * Both queries aggregate: `GROUP BY ip` with `MAX(<time>)`, ordered by the
	 * aggregate alias. `SELECT DISTINCT ip ... ORDER BY log_time` is the shape
	 * to avoid here: MySQL rejects it under ONLY_FULL_GROUP_BY, which is on by
	 * default since MySQL 5.7.
	 *
	 * @param string $cutoff Oldest activity date to consider, UTC 'Y-m-d H:i:s'.
	 * @param int    $limit  Rows per table.
	 * @param int    $offset Rows skipped per table.
	 * @return string[] Addresses, most recent activity first, ties broken by address.
	 */
	private static function candidate_page( string $cutoff, int $limit, int $offset ): array {
		global $wpdb;

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Custom plugin table, aggregated scan for the background resolver.
		$log_rows = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT ip, MAX(log_time) AS seen FROM {$wpdb->prefix}login_armor_logs WHERE log_time >= %s GROUP BY ip ORDER BY seen DESC, ip ASC LIMIT %d OFFSET %d",
				$cutoff,
				$limit,
				$offset
			)
		);

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Custom plugin table, aggregated scan for the background resolver.
		$incident_rows = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT ip, MAX(last_seen_at) AS seen FROM {$wpdb->prefix}login_armor_incidents WHERE last_seen_at >= %s AND ip <> '' GROUP BY ip ORDER BY seen DESC, ip ASC LIMIT %d OFFSET %d",
				$cutoff,
				$limit,
				$offset
			)
		);

		$seen = [];
		foreach ( [ $log_rows, $incident_rows ] as $rows ) {
			foreach ( (array) $rows as $row ) {
				$ip = isset( $row->ip ) ? trim( (string) $row->ip ) : '';
				if ( '' === $ip ) {
					continue;
				}
				$when = isset( $row->seen ) ? (string) $row->seen : '';
				if ( ! isset( $seen[ $ip ] ) || $when > $seen[ $ip ] ) {
					$seen[ $ip ] = $when;
				}
			}
		}

		if ( empty( $seen ) ) {
			return [];
		}

		$ips = array_map( 'strval', array_keys( $seen ) );
		usort(
			$ips,
			static function ( string $a, string $b ) use ( $seen ): int {
				return ( $seen[ $b ] <=> $seen[ $a ] ) ?: strcmp( $a, $b );
			}
		);

		return $ips;
	}

	// ── Single-worker lock ────────────────────────────────────────────────

	/**
	 * Take the prefetch lock, or report that another cron request has it.
	 *
	 * INSERT IGNORE on the options table: the unique index on option_name
	 * means exactly one concurrent INSERT affects a row. Same shape, and the
	 * same reason, as LoginArmor::acquire_provision_lock(): two overlapping
	 * cron requests would otherwise each spend the full budget on the same
	 * addresses and double the outbound traffic.
	 *
	 * A lock older than PREFETCH_LOCK_TTL belonged to a request that died
	 * before releasing it; it is deleted and the insert retried once.
	 *
	 * The takeover deletes the exact row it read, never "whatever is there
	 * now". Two requests can read the same stale timestamp; with an
	 * unconditional DELETE the second one removes the fresh lock the first has
	 * just inserted, inserts its own, and both then believe they own the pass.
	 * The compare-and-swap makes the loser's DELETE affect no row, and it
	 * stands down.
	 */
	private static function acquire_prefetch_lock(): bool {
		if ( self::insert_prefetch_lock() ) {
			return true;
		}

		global $wpdb;

		// Read the stored timestamp straight from the table: the object cache
		// may hold the miss from before the other request wrote the row.
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Fresh read of the lock we just failed to take.
		$held_raw = $wpdb->get_var(
			$wpdb->prepare( "SELECT option_value FROM {$wpdb->options} WHERE option_name = %s", self::PREFETCH_LOCK_OPTION )
		);

		// The holder released it between our failed INSERT and this read.
		if ( null === $held_raw ) {
			return self::insert_prefetch_lock();
		}

		$held_since = (int) $held_raw;
		if ( $held_since > 0 && ( time() - $held_since ) < self::PREFETCH_LOCK_TTL ) {
			return false;
		}

		if ( ! self::delete_stale_prefetch_lock( (string) $held_raw ) ) {
			return false;
		}

		return self::insert_prefetch_lock();
	}

	/**
	 * Delete the lock row ONLY if it still holds the value we read.
	 *
	 * @param string $stale The exact stored value the takeover decision was made on.
	 * @return bool True when this request is the one that removed it.
	 */
	private static function delete_stale_prefetch_lock( string $stale ): bool {
		global $wpdb;

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Compare-and-swap removal of an abandoned lock row.
		$wpdb->query(
			$wpdb->prepare(
				"DELETE FROM {$wpdb->options} WHERE option_name = %s AND option_value = %s",
				self::PREFETCH_LOCK_OPTION,
				$stale
			)
		);

		if ( 1 !== (int) $wpdb->rows_affected ) {
			return false;
		}

		wp_cache_delete( self::PREFETCH_LOCK_OPTION, 'options' );

		return true;
	}

	/**
	 * One atomic attempt at the lock row.
	 */
	private static function insert_prefetch_lock(): bool {
		global $wpdb;

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Atomic claim via the unique option_name index; core options table.
		$wpdb->query(
			$wpdb->prepare(
				"INSERT IGNORE INTO {$wpdb->options} (option_name, option_value, autoload) VALUES (%s, %s, 'no')",
				self::PREFETCH_LOCK_OPTION,
				(string) time()
			)
		);

		return 1 === (int) $wpdb->rows_affected;
	}

	/**
	 * Drop the lock row. Always called from a finally block.
	 */
	private static function release_prefetch_lock(): void {
		global $wpdb;

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Releasing the lock row this request owns.
		$wpdb->query(
			$wpdb->prepare( "DELETE FROM {$wpdb->options} WHERE option_name = %s", self::PREFETCH_LOCK_OPTION )
		);

		wp_cache_delete( self::PREFETCH_LOCK_OPTION, 'options' );
	}

	// ── Presentation ──────────────────────────────────────────────────────

	/**
	 * Just the ISO country code for an IP, or '' when unknown.
	 *
	 * @param string $ip IP address.
	 */
	public static function country_code( string $ip ): string {
		$r = self::lookup( $ip );
		return $r ? $r['code'] : '';
	}

	/**
	 * Turn a two-letter ISO country code into a flag emoji using regional
	 * indicator symbols (e.g. "FR" → 🇫🇷). Returns '' for an invalid code.
	 *
	 * @param string $code Two-letter ISO 3166-1 alpha-2 code.
	 */
	public static function flag_emoji( string $code ): string {
		$code = strtoupper( trim( $code ) );
		if ( ! preg_match( '/^[A-Z]{2}$/', $code ) ) {
			return '';
		}
		$base  = 0x1F1E6; // Regional Indicator Symbol Letter A.
		$flag  = '';
		$flag .= mb_chr( $base + ( ord( $code[0] ) - ord( 'A' ) ), 'UTF-8' );
		$flag .= mb_chr( $base + ( ord( $code[1] ) - ord( 'A' ) ), 'UTF-8' );
		return $flag;
	}

	/**
	 * Localized country name for a code.
	 *
	 * Uses the PHP `intl` extension to render the name in the admin's own
	 * locale (e.g. "CH" → "Suisse" in French) when available. Falls back to
	 * the API-provided English name, then to the code itself. Never fatals on
	 * a host without `intl`.
	 *
	 * Returns '' when `intl` is unavailable, so the caller can keep the
	 * inline badge code-only rather than print an English name in a
	 * non-English admin.
	 *
	 * @param string $code Two-letter ISO 3166-1 alpha-2 code.
	 */
	private static function localized_name( string $code ): string {
		if ( class_exists( '\Locale' ) && method_exists( '\Locale', 'getDisplayRegion' ) ) {
			$locale = function_exists( 'get_user_locale' ) ? get_user_locale() : get_locale();
			$name   = \Locale::getDisplayRegion( '-' . $code, $locale );
			if ( is_string( $name ) && '' !== $name && strtoupper( $name ) !== $code ) {
				return $name;
			}
		}
		return '';
	}

	/**
	 * Escaped inline badge (ISO code + country name) for an IP, for use in
	 * admin lists. Returns '' when geolocation is off or the IP is not
	 * resolved yet.
	 *
	 * No flag emoji: Windows ships no glyphs for regional-indicator flag
	 * emoji, so they degrade to the bare two-letter code there. We surface
	 * the code (universally legible) and the localized country name instead.
	 *
	 * @param string $ip      IP address.
	 * @param bool   $compact When true, show the code only (for dense lists
	 *                        such as the events table); the full name still
	 *                        appears in the tooltip.
	 */
	public static function badge_html( string $ip, bool $compact = false ): string {
		$r = self::lookup( $ip );
		if ( null === $r ) {
			return '';
		}
		$code      = $r['code'];
		$localized = self::localized_name( $code );             // '' when intl absent
		$api_name  = $r['name'];                                // English, may equal code

		// Inline name only when we can localize it; otherwise code-only.
		if ( $compact || '' === $localized ) {
			$label = $code;
		} else {
			$label = $code . ' · ' . $localized;
		}

		// Tooltip: localized name, else the API (English) name, else the code.
		if ( '' !== $localized ) {
			$title = $localized;
		} elseif ( '' !== $api_name && strtoupper( $api_name ) !== $code ) {
			$title = $api_name;
		} else {
			$title = $code;
		}

		return '<span class="la-geo-badge" title="' . esc_attr( $title ) . '">' . esc_html( $label ) . '</span>';
	}
}
