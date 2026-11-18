<?php
/**
 * Request Firewall: a PHP-level port of the Perishable Press "8G" ruleset.
 *
 * Inspects every front-end request early on `init` (priority 0) and blocks
 * those matching well-known malicious patterns (bad query strings, bad request
 * URIs, disallowed HTTP methods, and (opt-in) bad user agents / spam
 * referrers). Unlike the original 8G .htaccess ruleset this runs in PHP, so it
 * works on Apache, Nginx, LiteSpeed and IIS alike, and every block is
 * observable: it is recorded as an aggregated Detection incident (one row per
 * IP per 60-minute window: never one row per request) and surfaced on the
 * dashboard.
 *
 * Prime directive, never break a legitimate site:
 *  - OFF by default (master toggle). A site that does not want it leaves it off.
 *  - First enable always starts in `log_only` (monitor / dry-run) mode: would-be
 *    blocks are recorded but the request is NOT blocked. The admin reviews the
 *    monitor log, then flips to `enforce`.
 *  - Logged-in administrators (`manage_options`) are NEVER filtered.
 *  - REST, cron, WP-CLI, admin-ajax and wp-admin contexts are skipped.
 *  - Conservative rule families are on by default; aggressive families (higher
 *    false-positive risk) are opt-in.
 *  - An IP / path allowlist short-circuits inspection entirely.
 *
 * Not scored (it is a bonus layer, like IP Geolocation) and not part of the
 * onboarding "safe baseline".
 *
 * @package LoginArmor
 * @since   2.4.0
 */

namespace LoginArmor\Firewall;

use LoginArmor\Detection\Incident;
use LoginArmor\LoginArmor;

// Exit if accessed directly.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Master orchestrator for the request firewall.
 */
final class Firewall {

	/** @var string Single serialized option holding the whole config. */
	public const OPTION_KEY = 'login_armor_firewall';

	/**
	 * Default configuration. Master OFF; on first enable the mode is forced to
	 * `log_only`. Conservative families default ON, aggressive default OFF.
	 *
	 * @var array<string,mixed>
	 */
	public const DEFAULTS = array(
		'enabled'                => false,
		'mode'                   => 'log_only', // 'log_only' | 'enforce'
		// 2.7.0 : Unix time of the off -> on transition, 0 when the module is
		// off. Deliberately NOT part of the exportable registry entry (see
		// Settings\Registry): it dates THIS site's monitoring period and would
		// be a lie on any site the export file is replayed on.
		'enabled_at'             => 0,
		// Conservative tier (very low false-positive risk): on by default.
		'query_string'           => true,
		'request_uri'            => true,
		'request_method'         => true,
		// Aggressive tier (higher false-positive risk): opt-in.
		'user_agent'             => false,
		'referer'                => false,
		'request_uri_aggressive' => false,
		// Allowlists, one entry per line. IPs accept exact + CIDR; paths are
		// substring matches against the decoded REQUEST_URI.
		'allow_ips'              => '',
		'allow_paths'            => '',
	);

	/** @var string[] The six rule families, in evaluation order. */
	public const FAMILIES = array(
		'request_method',
		'query_string',
		'request_uri',
		'request_uri_aggressive',
		'user_agent',
		'referer',
	);

	/** @var string[] Families that ship on by default (low false-positive risk). */
	public const CONSERVATIVE = array( 'query_string', 'request_uri', 'request_method' );

	/** @var array<string,mixed> Resolved settings for this request. */
	private array $settings;

	/**
	 * Constructor. Wires the inspection hook only when the module is enabled:
	 * zero overhead when off (no hook is registered).
	 */
	public function __construct() {
		$this->settings = self::get_settings();

		if ( empty( $this->settings['enabled'] ) ) {
			return;
		}

		// Earliest hook where current_user_can() is reliable (auth cookie is
		// resolved) yet WordPress is loaded enough that wp_die()/status_header()
		// work. Mirrors Hardening::block_author_query() (init, priority 1).
		add_action( 'init', array( $this, 'inspect_request' ), 0 );
	}

	// ------------------------------------------------------------------
	// Settings
	// ------------------------------------------------------------------

	/**
	 * Return the merged settings (defaults + stored), so newly added keys
	 * always resolve to a value.
	 *
	 * @return array<string,mixed>
	 */
	public static function get_settings(): array {
		$stored = get_option( self::OPTION_KEY, array() );
		if ( ! is_array( $stored ) ) {
			$stored = array();
		}
		return array_merge( self::DEFAULTS, $stored );
	}

	/** Whether the module is enabled. */
	public static function is_enabled(): bool {
		$s = self::get_settings();
		return ! empty( $s['enabled'] );
	}

	/** Current mode: 'log_only' or 'enforce'. */
	public static function get_mode(): string {
		$s    = self::get_settings();
		$mode = isset( $s['mode'] ) ? (string) $s['mode'] : 'log_only';
		return in_array( $mode, array( 'log_only', 'enforce' ), true ) ? $mode : 'log_only';
	}

	/**
	 * The mode this request is actually judged on.
	 *
	 * Safe mode brings the firewall down to observation without touching the
	 * mode stored in the option. That matters: the administrator who added
	 * LOGIN_ARMOR_SAFE_MODE to wp-config.php to get back in must not then have
	 * to remember which modules were enforcing before, and removing the line
	 * must restore the site exactly as it was.
	 *
	 * @since 2.7.0
	 */
	public static function effective_mode(): string {
		if ( LoginArmor::is_safe_mode() ) {
			return 'log_only';
		}
		return self::get_mode();
	}

	/**
	 * Enable or disable the module. Enabling ALWAYS resets the mode to
	 * `log_only` so the firewall can never start blocking traffic the very
	 * moment it is switched on: the admin must consciously flip to enforce.
	 *
	 * Because of that reset, this method must NEVER be called on a module that
	 * is already enabled: it would silently demote an enforcing firewall back
	 * to monitoring. Callers that only want to make sure the module is on test
	 * is_enabled() first (Setup\SafeBaseline, Settings\Importer).
	 *
	 * 2.7.0: the off -> on transition stamps `enabled_at`. That stamp is what
	 * "monitoring for N days" counts from, so re-enabling an already-enabled
	 * module must not restart it, and switching off must clear it.
	 */
	public static function set_enabled( bool $enabled ): void {
		$out         = self::get_settings();
		$was_enabled = ! empty( $out['enabled'] );

		$out['enabled'] = $enabled;

		if ( $enabled ) {
			$out['mode'] = 'log_only';
			// An already-enabled module keeps the date it was switched on. The
			// second test covers a site upgraded from 2.6.x that is enabled
			// but carries no stamp yet and never goes through the upgrade step
			// (a fresh enable on a site whose db_version is already current).
			if ( ! $was_enabled || (int) ( $out['enabled_at'] ?? 0 ) <= 0 ) {
				$out['enabled_at'] = time();
			}
		} else {
			$out['enabled_at'] = 0;
		}

		// 2.8.0: autoloaded. This option is read on every front-end request, so
		// leaving it out of the autoload set cost one query on each of them.
		update_option( self::OPTION_KEY, $out, true );
	}

	/**
	 * Days the module has been watching traffic without blocking it.
	 *
	 * Days IN MONITOR MODE, not days since the module was first switched on:
	 * save_settings() restarts the clock on the enforce -> monitor move, so a
	 * module that spent most of its life enforcing cannot claim that time as
	 * observation. Zero whenever the question does not apply: module off, mode
	 * `enforce`, or no stamp yet. A caller can therefore treat any positive
	 * value as "this site has N days of monitor-mode evidence" with no further
	 * test.
	 *
	 * @since 2.7.0
	 */
	public static function monitoring_days(): int {
		$settings = self::get_settings();

		if ( empty( $settings['enabled'] ) || 'log_only' !== self::get_mode() ) {
			return 0;
		}

		$since = (int) ( $settings['enabled_at'] ?? 0 );
		if ( $since <= 0 ) {
			return 0;
		}

		$elapsed = time() - $since;

		return $elapsed > 0 ? (int) floor( $elapsed / DAY_IN_SECONDS ) : 0;
	}

	/**
	 * Sanitize and persist the family toggles, mode and allowlists. Preserves
	 * the master `enabled` flag, and the `enabled_at` stamp EXCEPT when this
	 * save is the enforce -> monitor move, which restarts the monitoring
	 * period (see below). $out starts from the stored settings, so every key
	 * not named here survives untouched.
	 *
	 * @param array<string,mixed> $input Raw form input.
	 */
	public static function save_settings( array $input ): void {
		$current       = self::get_settings();
		$previous_mode = self::get_mode();
		$out           = $current; // Preserve `enabled` and `enabled_at`.

		foreach ( array( 'query_string', 'request_uri', 'request_method', 'user_agent', 'referer', 'request_uri_aggressive' ) as $key ) {
			$out[ $key ] = ! empty( $input[ $key ] );
		}

		$mode        = isset( $input['mode'] ) ? (string) $input['mode'] : (string) $current['mode'];
		$out['mode'] = in_array( $mode, array( 'log_only', 'enforce' ), true ) ? $mode : 'log_only';

		// 2.7.0: coming BACK to monitor mode restarts the monitoring period.
		// enabled_at is stamped on the off -> on edge only and preserved here,
		// so without this a module that ran eleven months in enforce and was
		// just put back to monitoring would read "monitoring for 365 days" and
		// be invited to enforce again, on the strength of a week whose matches
		// were BLOCKS and not observations. The advice claims evidence
		// gathered in monitor mode; the clock has to start when monitor mode
		// does. get_mode() and not $current['mode']: a junk stored value reads
		// as log_only everywhere else, so it must not count as a demotion.
		if ( ! empty( $out['enabled'] ) && 'log_only' === $out['mode'] && 'log_only' !== $previous_mode ) {
			$out['enabled_at'] = time();
		}

		$out['allow_ips']   = self::sanitize_lines( isset( $input['allow_ips'] ) ? (string) $input['allow_ips'] : '' );
		$out['allow_paths'] = self::sanitize_lines( isset( $input['allow_paths'] ) ? (string) $input['allow_paths'] : '' );

		// 2.8.0: autoloaded. This option is read on every front-end request, so
		// leaving it out of the autoload set cost one query on each of them.
		update_option( self::OPTION_KEY, $out, true );
	}

	/**
	 * Normalize a multi-line textarea into a clean, de-duplicated, capped
	 * newline-separated string.
	 */
	private static function sanitize_lines( string $raw ): string {
		$lines = preg_split( '/[\r\n]+/', $raw );
		$clean = array();
		if ( is_array( $lines ) ) {
			foreach ( $lines as $line ) {
				$line = sanitize_text_field( trim( $line ) );
				if ( '' !== $line ) {
					$clean[] = $line;
				}
			}
		}
		$clean = array_values( array_unique( $clean ) );
		return implode( "\n", array_slice( $clean, 0, 200 ) );
	}

	// ------------------------------------------------------------------
	// Request inspection
	// ------------------------------------------------------------------

	/**
	 * Inspect the current request and block it when a rule family matches.
	 * Hooked on `init` priority 0 only when the module is enabled.
	 */
	public function inspect_request(): void {
		if ( $this->should_skip_context() ) {
			return;
		}

		// A site owner can never lock themselves out via the firewall.
		if ( current_user_can( 'manage_options' ) ) {
			return;
		}

		$ip = LoginArmor::get_client_ip();
		if ( $this->is_ip_allowed( $ip, (string) $this->settings['allow_ips'] ) ) {
			return;
		}

		$raw_uri = $this->server_value( 'REQUEST_URI' );
		if ( $this->is_path_allowed( $raw_uri, (string) $this->settings['allow_paths'] ) ) {
			return;
		}

		$hit = $this->find_match( $raw_uri );
		if ( null !== $hit ) {
			$this->handle_block( $ip, $hit );
		}
	}

	/**
	 * Run the enabled families against the current request. Returns the matched
	 * family key on the first hit, or null. Order: cheapest/safest first.
	 *
	 * @param string $raw_uri The raw (still URL-encoded) REQUEST_URI.
	 */
	private function find_match( string $raw_uri ): ?string {
		$s = $this->settings;

		if ( ! empty( $s['request_method'] ) ) {
			$method = strtoupper( $this->server_value( 'REQUEST_METHOD' ) );
			if ( '' !== $method && null !== RuleSet::match_method( $method ) ) {
				return 'request_method';
			}
		}

		// Decode once so percent-encoded payloads (e.g. %2e%2e, %3cscript) match.
		$decoded_uri = rawurldecode( $raw_uri );

		if ( ! empty( $s['query_string'] ) ) {
			$query = rawurldecode( $this->server_value( 'QUERY_STRING' ) );
			if ( '' !== $query && null !== RuleSet::inspect( 'query_string', $query ) ) {
				return 'query_string';
			}
		}

		if ( ! empty( $s['request_uri'] ) && null !== RuleSet::inspect( 'request_uri', $decoded_uri ) ) {
			return 'request_uri';
		}

		if ( ! empty( $s['request_uri_aggressive'] ) && null !== RuleSet::inspect( 'request_uri_aggressive', $decoded_uri ) ) {
			return 'request_uri_aggressive';
		}

		if ( ! empty( $s['user_agent'] ) ) {
			$ua = $this->server_value( 'HTTP_USER_AGENT' );
			if ( '' !== $ua && null !== RuleSet::inspect( 'user_agent', $ua ) ) {
				return 'user_agent';
			}
		}

		if ( ! empty( $s['referer'] ) ) {
			$ref = $this->server_value( 'HTTP_REFERER' );
			if ( '' !== $ref && null !== RuleSet::inspect( 'referer', $ref ) ) {
				return 'referer';
			}
		}

		return null;
	}

	/**
	 * Record the (would-be) block and, in enforce mode, terminate the request.
	 *
	 * @param string $ip     Client IP.
	 * @param string $family Matched rule family key.
	 */
	private function handle_block( string $ip, string $family ): void {
		$mode = self::effective_mode();

		$this->record_block( $ip, $family, $mode );

		/**
		 * Fires when the firewall matches a request. $mode tells listeners
		 * whether the request was actually blocked ('enforce') or merely
		 * observed ('log_only').
		 *
		 * @param string $ip     Client IP.
		 * @param string $family Matched rule family.
		 * @param string $mode   'log_only' | 'enforce'.
		 */
		do_action( 'login_armor_firewall_blocked', $ip, $family, $mode );

		if ( 'enforce' === $mode ) {
			$this->send_block_response();
		}
		// log_only: do nothing further, the request proceeds normally.
	}

	/**
	 * Send a generic 403 and stop. The message is intentionally generic so a
	 * scanner cannot fingerprint the firewall.
	 */
	private function send_block_response(): void {
		if ( ! headers_sent() ) {
			status_header( 403 );
			nocache_headers();
		}
		wp_die(
			esc_html__( 'Your request was blocked for security reasons.', 'login-armor' ),
			esc_html__( 'Forbidden', 'login-armor' ),
			array( 'response' => 403 )
		);
	}

	/**
	 * Upsert an aggregated firewall incident. N blocks from one IP within the
	 * 60-minute window increment events_count on a single row: never one row
	 * per request. Severity is LOW in monitor mode, MEDIUM when enforcing, so
	 * monitor-mode blocks stay below the default notification threshold.
	 *
	 * @param string $ip     Client IP.
	 * @param string $family Matched rule family.
	 * @param string $mode   'log_only' | 'enforce'.
	 */
	private function record_block( string $ip, string $family, string $mode ): void {
		if ( '' === $ip || '0.0.0.0' === $ip ) {
			return;
		}
		if ( ! class_exists( Incident::class ) ) {
			return;
		}

		$now      = current_time( 'mysql', true );
		$severity = ( 'enforce' === $mode ) ? Incident::SEVERITY_MEDIUM : Incident::SEVERITY_LOW;
		$existing = Incident::find_active( Incident::PATTERN_FIREWALL_BLOCK, $ip, 'ip', 60 );

		if ( $existing instanceof Incident ) {
			$existing->increment_occurrence( $severity, 1, 1, 0 );
			do_action( 'login_armor_incident_created', $existing, false );
			return;
		}

		// Family is stashed in target_username (prefixed) to avoid a schema
		// migration; the dashboard reads the prefix to label the matched rule.
		$marker = ( 'enforce' === $mode ? 'fw:' : 'fw-dry:' ) . $family;

		$incident                   = new Incident();
		$incident->pattern          = Incident::PATTERN_FIREWALL_BLOCK;
		$incident->severity         = $severity;
		$incident->started_at       = $now;
		$incident->last_seen_at     = $now;
		$incident->ip               = $ip;
		$incident->subnet           = '';
		$incident->target_username  = substr( $marker, 0, 60 );
		$incident->events_count     = 1;
		$incident->unique_ips       = 1;
		$incident->unique_usernames = 0;
		$incident->status           = Incident::STATUS_ACTIVE;
		$incident->insert();
		do_action( 'login_armor_incident_created', $incident, true );
	}

	// ------------------------------------------------------------------
	// Context guards & allowlists
	// ------------------------------------------------------------------

	/**
	 * Skip contexts where filtering would cause false positives or is pointless:
	 * WP-CLI, cron, the REST API, admin-ajax and the wp-admin back-office.
	 */
	private function should_skip_context(): bool {
		if ( defined( 'WP_CLI' ) && \WP_CLI ) {
			return true;
		}
		if ( defined( 'DOING_CRON' ) && DOING_CRON ) {
			return true;
		}
		if ( function_exists( 'wp_doing_ajax' ) && wp_doing_ajax() ) {
			return true;
		}
		// Known, deliberate scope limit: the back-office is never filtered. This
		// runs at init priority 0 where matching wp-admin traffic would risk false
		// positives that lock admins out (our prime directive is "never break a
		// legitimate site"), and wp-admin is already gated by WordPress capability
		// checks. Trade-off: unauthenticated query-string probes to /wp-admin/ are
		// not inspected by this layer; the brute-force / detection engines cover
		// the auth surface there.
		if ( is_admin() ) {
			return true;
		}
		if ( $this->is_rest_request() ) {
			return true;
		}
		if ( self::is_self_request() ) {
			return true;
		}
		return false;
	}

	/**
	 * Whether the site is calling itself.
	 *
	 * WordPress loops back constantly (cron, Site Health, updates), and plugins
	 * do too: SEOPress fetches a post's own public page to build its content
	 * analysis. Those requests arrive anonymous, like any visitor. Only
	 * 127.0.0.1 was exempt, which covers local development but not production,
	 * where the call leaves and re-enters through the server's public address
	 * (hairpin NAT). A site blocking itself breaks features for no security
	 * gain, and the prime directive is never to break a legitimate site.
	 *
	 * Both sides of the comparison come from the web server, never from a
	 * client-controlled header: LoginArmor::get_client_ip() must NOT decide
	 * the exemption, since a site configured to trust X-Forwarded-For would
	 * then let an attacker skip the whole firewall by forging the server's own
	 * address. Since 2.8.2 it is consulted after the comparison, and only to
	 * withdraw the exemption (see declared_proxy_named_a_visitor()).
	 *
	 * Known trade-off: on shared hosting the public address is common to every
	 * site on the machine, so neighbours on that address are exempt too. That is
	 * a narrow exposure (an attacker must already be hosted alongside the site)
	 * against a breakage that is otherwise certain and silent.
	 *
	 * @since 2.5.1
	 */
	public static function is_self_request(): bool {
		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized, WordPress.Security.ValidatedSanitizedInput.MissingUnslash -- Both values come from the web server, not the client, and inet_pton() below rejects anything that is not a well-formed address.
		$remote = isset( $_SERVER['REMOTE_ADDR'] ) ? trim( sanitize_text_field( (string) wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) ) : '';
		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized, WordPress.Security.ValidatedSanitizedInput.MissingUnslash -- Same rationale.
		$server = isset( $_SERVER['SERVER_ADDR'] ) ? trim( sanitize_text_field( (string) wp_unslash( $_SERVER['SERVER_ADDR'] ) ) ) : '';

		if ( '' === $remote || '' === $server ) {
			return false;
		}

		// Normalise the IPv4-mapped IPv6 form so ::ffff:203.0.113.10 and
		// 203.0.113.10 are recognised as the same host: inet_pton() returns 16
		// bytes for the mapped form and 4 for the plain one, which would never
		// compare equal on their own.
		$normalize = static function ( string $ip ): string {
			$packed = @inet_pton( $ip ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Malformed input must yield false, not a notice.
			if ( false === $packed ) {
				return '';
			}
			$mapped_prefix = str_repeat( "\0", 10 ) . "\xff\xff";
			if ( 16 === strlen( $packed ) && 0 === strncmp( $packed, $mapped_prefix, 12 ) ) {
				$packed = substr( $packed, 12 );
			}
			return $packed;
		};

		$remote_packed = $normalize( $remote );
		$server_packed = $normalize( $server );

		if ( '' === $remote_packed || '' === $server_packed ) {
			return false;
		}

		if ( ! hash_equals( $server_packed, $remote_packed ) ) {
			return false;
		}

		// 2.8.2: the peer is the server, but it may be a proxy running on it
		// (nginx in front of Apache on 127.0.0.1, Varnish, a hosting panel).
		// Every visitor then arrives from the server's own address, and the
		// firewall showed "Enforcing" while it inspected nothing. When the
		// administrator has declared that proxy and it named a visitor, the
		// request is that visitor's. This can only withdraw the exemption,
		// never grant it: the exemption itself is still decided above, on
		// values the web server supplies.
		return ! self::declared_proxy_named_a_visitor( $server_packed, $normalize );
	}

	/**
	 * Whether a declared proxy at the server's own address named a visitor
	 * other than the site itself (2.8.2).
	 *
	 * LoginArmor::get_client_ip() reads the forwarding header only when the
	 * TCP peer is in the administrator's trusted-proxy list; otherwise it
	 * returns the peer, which is the server, and the answer is no. A header
	 * that is missing, malformed or names a loopback address gives an
	 * unreliable identity, and the answer is no as well: the request stays
	 * exempt, as before.
	 *
	 * The site calling itself through its own proxy is still the site: the
	 * proxy then names the server's public address, which is one of the
	 * addresses the site's host name resolves to.
	 *
	 * @param string   $server_packed The server address, packed.
	 * @param callable $normalize     The packing used by is_self_request().
	 */
	private static function declared_proxy_named_a_visitor( string $server_packed, callable $normalize ): bool {
		$client = LoginArmor::get_client_ip();
		if ( ! LoginArmor::is_reliable_client_ip( $client ) ) {
			return false;
		}
		$client_packed = $normalize( $client );
		if ( '' === $client_packed || hash_equals( $server_packed, $client_packed ) ) {
			return false;
		}
		foreach ( self::site_host_addresses() as $own ) {
			$own_packed = $normalize( $own );
			if ( '' !== $own_packed && hash_equals( $own_packed, $client_packed ) ) {
				return false;
			}
		}
		return true;
	}

	/**
	 * The addresses the site's own host name resolves to, cached for an hour
	 * (five minutes when the lookup fails). Only reached on a site whose
	 * declared proxy runs on the server itself.
	 *
	 * @return string[]
	 */
	private static function site_host_addresses(): array {
		$cached = get_transient( 'login_armor_fw_site_addrs' );
		if ( is_array( $cached ) ) {
			return $cached;
		}
		$host  = (string) wp_parse_url( home_url(), PHP_URL_HOST );
		$addrs = array();
		if ( '' !== $host ) {
			$v4 = gethostbynamel( $host );
			if ( is_array( $v4 ) ) {
				$addrs = $v4;
			}
			if ( function_exists( 'dns_get_record' ) ) {
				$v6 = @dns_get_record( $host, DNS_AAAA ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- A failed lookup must yield nothing, not a warning on every page.
				foreach ( is_array( $v6 ) ? $v6 : array() as $record ) {
					if ( ! empty( $record['ipv6'] ) ) {
						$addrs[] = (string) $record['ipv6'];
					}
				}
			}
		}
		set_transient( 'login_armor_fw_site_addrs', $addrs, empty( $addrs ) ? 5 * MINUTE_IN_SECONDS : HOUR_IN_SECONDS );
		return $addrs;
	}

	/**
	 * Detect a REST request. REST_REQUEST is not yet defined at `init` priority
	 * 0, so fall back to the REST URL prefix / rest_route query arg.
	 */
	private function is_rest_request(): bool {
		if ( defined( 'REST_REQUEST' ) && REST_REQUEST ) {
			return true;
		}
		$uri = $this->server_value( 'REQUEST_URI' );
		if ( '' === $uri ) {
			return false;
		}
		// Split path from query so REST detection cannot be smuggled through an
		// arbitrary query value (e.g. "?x=/wp-json/<payload>" or "rest_route="
		// embedded in some other parameter) to skip the whole firewall.
		$split = explode( '?', $uri, 2 );
		$path  = rawurldecode( $split[0] );
		$query = isset( $split[1] ) ? (string) $split[1] : '';

		// Pretty permalinks: the path has to START with the site's REST base,
		// as core routes it (home path, then the prefix, or index.php/ then the
		// prefix for PATHINFO permalinks), repeated slashes collapsed as core
		// ignores them. Only in the PATH, never the query. Testing "/wp-json/"
		// anywhere in the path exempted /any/wp-json/x/?q=<payload>, an
		// ordinary front-end request, from every rule.
		$prefix = function_exists( 'rest_get_url_prefix' ) ? trim( (string) rest_get_url_prefix(), '/' ) : 'wp-json';
		if ( '' !== $prefix ) {
			$route = (string) preg_replace( '#/+#', '/', $path );
			$home  = rtrim( (string) preg_replace( '#/+#', '/', (string) wp_parse_url( home_url( '/' ), PHP_URL_PATH ) ), '/' );
			foreach ( array( $home . '/' . $prefix, $home . '/index.php/' . $prefix ) as $base ) {
				if ( $route === $base || str_starts_with( $route, $base . '/' ) ) {
					return true;
				}
			}
		}

		// Plain permalinks: rest_route must be a REAL query parameter, not an
		// arbitrary substring anywhere in the URI.
		if ( '' !== $query ) {
			$args = array();
			parse_str( $query, $args );
			// Require rest_route to hold a real REST path value ("/..."), not just
			// be present. Otherwise a bare "?rest_route=" (empty), or parse_str's
			// dot/space key aliasing ("rest.route="/"rest route="), would let an
			// attacker skip the whole firewall by appending one parameter.
			if ( isset( $args['rest_route'] ) && is_string( $args['rest_route'] )
				&& isset( $args['rest_route'][0] ) && '/' === $args['rest_route'][0] ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Whether the client IP is allowlisted. Localhost is always allowed.
	 * Entries accept exact IPs and CIDR ranges (IPv4 and IPv6).
	 */
	private function is_ip_allowed( string $ip, string $allow_ips ): bool {
		if ( in_array( $ip, array( '127.0.0.1', '::1' ), true ) ) {
			return true;
		}
		$allow_ips = trim( $allow_ips );
		if ( '' === $allow_ips ) {
			return false;
		}
		$entries = preg_split( '/[\r\n]+/', $allow_ips );
		if ( ! is_array( $entries ) ) {
			return false;
		}
		foreach ( $entries as $entry ) {
			if ( self::ip_matches( $ip, trim( $entry ) ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Match an IP against a single allowlist entry (exact IP or CIDR). Handles
	 * both IPv4 and IPv6 by masking the packed byte representation.
	 */
	private static function ip_matches( string $ip, string $entry ): bool {
		if ( '' === $entry ) {
			return false;
		}
		if ( false === strpos( $entry, '/' ) ) {
			return $ip === $entry;
		}

		list( $subnet, $bits ) = array_pad( explode( '/', $entry, 2 ), 2, '' );
		$bits = (int) $bits;

		$ip_packed     = @inet_pton( $ip );     // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- invalid input is already handled by the false check below.
		$subnet_packed = @inet_pton( $subnet ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- same rationale.
		if ( false === $ip_packed || false === $subnet_packed ) {
			return false;
		}
		$len = strlen( $ip_packed );
		if ( $len !== strlen( $subnet_packed ) ) {
			return false; // Different address family.
		}
		$max_bits = $len * 8;
		if ( $bits < 0 || $bits > $max_bits ) {
			return false;
		}

		$whole_bytes = intdiv( $bits, 8 );
		$rem_bits    = $bits % 8;

		// Binary-safe comparison: packed IPs contain null bytes, so strncmp()
		// (which stops at the first \0) would give false matches: use substr.
		if ( $whole_bytes > 0 && substr( $ip_packed, 0, $whole_bytes ) !== substr( $subnet_packed, 0, $whole_bytes ) ) {
			return false;
		}
		if ( 0 === $rem_bits ) {
			return true;
		}
		$mask = 0xff << ( 8 - $rem_bits ) & 0xff;
		return ( ord( $ip_packed[ $whole_bytes ] ) & $mask ) === ( ord( $subnet_packed[ $whole_bytes ] ) & $mask );
	}

	/**
	 * Whether the request path is covered by an allowlisted path PREFIX.
	 *
	 * Prefix match (not substring): an entry like "/export" must be the START of
	 * the request path, so it cannot accidentally exempt an unrelated path such
	 * as "/x/export-shell.php". Entries are normalized to a leading slash.
	 */
	private function is_path_allowed( string $raw_uri, string $allow_paths ): bool {
		$allow_paths = trim( $allow_paths );
		if ( '' === $allow_paths ) {
			return false;
		}
		// Match the path only (strip the query string) so an allowlisted path
		// cannot be smuggled into a query parameter to bypass the firewall.
		$path = rawurldecode( explode( '?', $raw_uri, 2 )[0] );
		// A dot segment is never exempt: the server resolves "/api/../x.php"
		// to /x.php, which the prefix does not name (a backslash separates
		// segments on Windows servers).
		if ( preg_match( '#(^|[/\\\\])\.{1,2}([/\\\\]|$)#', $path ) ) {
			return false;
		}
		$entries = preg_split( '/[\r\n]+/', $allow_paths );
		if ( ! is_array( $entries ) ) {
			return false;
		}
		foreach ( $entries as $entry ) {
			$entry = trim( $entry );
			if ( '' === $entry ) {
				continue;
			}
			if ( '/' !== $entry[0] ) {
				$entry = '/' . $entry;
			}
			// Match on a path BOUNDARY: "/api" matches "/api" exactly or "/api/…",
			// never "/api-internal". A short allowlist prefix must not exempt
			// unrelated paths.
			$entry_trim = rtrim( $entry, '/' );
			if ( '' === $entry_trim || $path === $entry_trim || 0 === strpos( $path, $entry_trim . '/' ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Read a raw $_SERVER value, unslashed. NOT sanitized: the firewall must
	 * inspect the request exactly as sent (sanitizing would strip the very
	 * tokens it looks for). The value is never stored or echoed.
	 *
	 * @param string $key $_SERVER key.
	 */
	private function server_value( string $key ): string {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized, WordPress.Security.ValidatedSanitizedInput.MissingUnslash -- Public unauthenticated request filter; the raw value is needed for pattern matching and is never persisted or output.
		return isset( $_SERVER[ $key ] ) ? (string) wp_unslash( $_SERVER[ $key ] ) : '';
	}

	// ------------------------------------------------------------------
	// Dashboard helpers
	// ------------------------------------------------------------------

	/**
	 * Detect the web server family from SERVER_SOFTWARE. UI-only: the firewall
	 * is pure PHP and behaves identically everywhere.
	 *
	 * @return string apache|nginx|litespeed|iis|unknown
	 */
	public static function detect_server(): string {
		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized, WordPress.Security.ValidatedSanitizedInput.MissingUnslash -- read-only feature-detection of the server banner.
		$sw = isset( $_SERVER['SERVER_SOFTWARE'] ) ? strtolower( (string) $_SERVER['SERVER_SOFTWARE'] ) : '';
		if ( false !== strpos( $sw, 'litespeed' ) ) {
			return 'litespeed';
		}
		if ( false !== strpos( $sw, 'nginx' ) ) {
			return 'nginx';
		}
		if ( false !== strpos( $sw, 'apache' ) ) {
			return 'apache';
		}
		if ( false !== strpos( $sw, 'microsoft-iis' ) || false !== strpos( $sw, 'iis' ) ) {
			return 'iis';
		}
		return 'unknown';
	}

	/**
	 * Count firewall-block incidents over a period (default 30 days).
	 *
	 * @param string $period One of '24h' | '7d' | '30d'.
	 */
	public static function count_blocks( string $period = '30d' ): int {
		if ( ! class_exists( Incident::class ) ) {
			return 0;
		}
		return Incident::count_filtered(
			array(
				'pattern' => Incident::PATTERN_FIREWALL_BLOCK,
				'period'  => $period,
			)
		);
	}

	/**
	 * Return the most recent firewall-block incidents for the admin panel.
	 *
	 * @param int $limit Max rows.
	 * @return \LoginArmor\Detection\Incident[]
	 */
	public static function recent_blocks( int $limit = 5 ): array {
		if ( ! class_exists( Incident::class ) ) {
			return array();
		}
		return Incident::get_filtered( array( 'pattern' => Incident::PATTERN_FIREWALL_BLOCK ), $limit, 0 );
	}
}
