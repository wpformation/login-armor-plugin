<?php
/**
 * Bot Challenge (Proof-of-Work): an invisible computational challenge that
 * only a JavaScript-capable browser will solve.
 *
 * The login page fetches a random challenge from the server; a small vanilla
 * JS solver finds a counter whose SHA-256 hash carries the required number of
 * leading zero bits (a few tens of milliseconds for a human's browser) and
 * posts it in hidden fields. Verifying costs the server exactly one hash.
 * A botnet hammering the form must now pay that CPU cost on every attempt,
 * on every site: brute force becomes slow and expensive.
 *
 * Prime directive: never lock out a legitimate human:
 *  - OFF by default. First enable always starts in `log_only` (monitor) mode:
 *    submissions without a valid proof are counted but never blocked. The
 *    admin reviews the counter, then consciously flips to `enforce`.
 *  - The rejection code is exempt from the brute-force counter (a user with
 *    broken JavaScript must not escalate into an IP lockout).
 *  - XML-RPC, REST, cron, WP-CLI and AJAX authentication flows are skipped:
 *    they have no browser to solve the challenge and are guarded elsewhere.
 *  - Challenges are single-use, short-lived and bound to the client IP.
 *
 * Not scored (bonus layer, like the Request Firewall) and not part of the
 * onboarding safe baseline.
 *
 * @package LoginArmor
 * @since   2.5.0
 */

namespace LoginArmor;

use LoginArmor\Detection\Incident;

// Exit if accessed directly.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Proof-of-Work challenge for the login, registration and lost-password forms.
 */
final class PowChallenge {

	/** @var string Single serialized option holding the whole config. */
	public const OPTION_KEY = 'login_armor_pow';

	/**
	 * Default configuration. Master OFF; on first enable the mode is forced
	 * to `log_only`.
	 *
	 * @var array<string,mixed>
	 */
	public const DEFAULTS = array(
		'enabled'    => false,
		'mode'       => 'log_only', // 'log_only' | 'enforce'
		'difficulty' => 'standard', // 'low' | 'standard' | 'high'
		// 2.7.0 : Unix time of the off -> on transition, 0 when the module is
		// off. Deliberately NOT part of the exportable registry entry (see
		// Settings\Registry): it dates THIS site's monitoring period and would
		// be a lie on any site the export file is replayed on.
		'enabled_at' => 0,
	);

	/** @var string[] Allowed modes, reused by the AJAX save handler. */
	public const ALLOWED_MODES = array( 'log_only', 'enforce' );

	/**
	 * Difficulty presets, in leading zero bits of the SHA-256 digest.
	 * Expected solver work is 2^bits hashes: ~8k / ~32k / ~131k iterations,
	 * well under a second in any modern browser. Server verification is
	 * always exactly one hash.
	 *
	 * @var array<string,int>
	 */
	public const DIFFICULTY_BITS = array(
		'low'      => 13,
		'standard' => 15,
		'high'     => 17,
	);

	/** Hidden field carrying the challenge nonce. */
	public const FIELD_NONCE = 'la_pow_n';

	/** Hidden field carrying the solved counter. */
	public const FIELD_SOLUTION = 'la_pow_s';

	/** Transient prefix for issued challenges (single-use). */
	public const CHALLENGE_PREFIX = 'login_armor_pow_c_';

	/** Challenge lifetime in seconds. The JS refreshes well before expiry. */
	public const CHALLENGE_TTL = 900;

	/** Option-key prefix for the per-IP issuance rate-limit counter. */
	public const RATE_PREFIX = 'login_armor_pow_rl_';

	/** Issuance rate-limit window (seconds) and ceiling per reliable IP. */
	private const RATE_WINDOW = 300;
	private const RATE_LIMIT  = 120;

	/** Option key of the rolling soft-failure counter (7-day fixed window). */
	public const SOFTFAIL_COUNTER_KEY = 'login_armor_pow_softfails';

	/** Window of the soft-failure counter shown in the admin section. */
	private const SOFTFAIL_WINDOW = 7 * DAY_IN_SECONDS;

	/** Upper bound stored in the soft-failure counter (display cap). */
	private const SOFTFAIL_CAP = 999999;

	/** @var array<string,mixed> Resolved settings for this request. */
	private array $settings;

	/**
	 * Constructor. Wires hooks only when the module is enabled: zero
	 * overhead when off (no hook is registered).
	 */
	public function __construct() {
		$this->settings = self::get_settings();

		if ( empty( $this->settings['enabled'] ) ) {
			return;
		}

		// Challenge issuance endpoint (anonymous visitors are the norm here).
		add_action( 'wp_ajax_nopriv_login_armor_pow_challenge', array( self::class, 'ajax_challenge' ) );
		add_action( 'wp_ajax_login_armor_pow_challenge', array( self::class, 'ajax_challenge' ) );

		// Native WP forms (wp-login.php and the Hide Login slug, which runs
		// wp-login.php natively so the same actions fire).
		add_action( 'login_form', array( self::class, 'inject_field' ) );
		add_action( 'register_form', array( self::class, 'inject_field' ) );
		add_action( 'lostpassword_form', array( self::class, 'inject_field' ) );

		// WooCommerce native forms.
		add_action( 'woocommerce_login_form', array( self::class, 'inject_field' ) );
		add_action( 'woocommerce_register_form', array( self::class, 'inject_field' ) );
		add_action( 'woocommerce_lostpassword_form', array( self::class, 'inject_field' ) );

		// After the core credential handlers (20) so a failed proof blocks
		// even valid credentials; before the LimitLogin lockout gate (30).
		add_filter( 'authenticate', array( self::class, 'maybe_verify' ), 25, 3 );
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
		return in_array( $mode, self::ALLOWED_MODES, true ) ? $mode : 'log_only';
	}

	/**
	 * The mode this submission is actually judged on.
	 *
	 * Safe mode brings the challenge down to observation without touching the
	 * mode stored in the option: a browser that cannot run the solver (an old
	 * device, a strict content policy, JavaScript switched off) is one of the
	 * ways an administrator ends up locked out, and removing the wp-config.php
	 * line must put the site back exactly as it was.
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
	 * Resolved difficulty in leading zero bits.
	 */
	public static function get_difficulty_bits(): int {
		$s      = self::get_settings();
		$preset = isset( $s['difficulty'] ) ? (string) $s['difficulty'] : 'standard';
		$bits   = self::DIFFICULTY_BITS[ $preset ] ?? self::DIFFICULTY_BITS['standard'];

		/**
		 * Filters the Proof-of-Work difficulty in leading zero bits.
		 *
		 * Lets a site raise the cost under attack (e.g. from the incident
		 * hooks) or lower it for very old devices. Clamped to a sane range.
		 *
		 * @param int $bits Number of leading zero bits required.
		 */
		$bits = (int) apply_filters( 'login_armor_pow_difficulty', $bits );

		return max( 1, min( 24, $bits ) );
	}

	/**
	 * Enable or disable the module. Enabling ALWAYS resets the mode to
	 * `log_only` so the challenge can never start blocking logins the very
	 * moment it is switched on: the admin must consciously flip to enforce.
	 *
	 * Because of that reset, this method must NEVER be called on a module that
	 * is already enabled: it would silently demote an enforcing challenge back
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
	 * Days the module has been counting submissions without blocking them.
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
	 * Sanitize and persist the mode and difficulty. Preserves the master
	 * `enabled` flag, and the `enabled_at` stamp EXCEPT when this save is the
	 * enforce -> monitor move, which restarts the monitoring period (see
	 * below). $out starts from the stored settings, so every key not named
	 * here survives untouched.
	 *
	 * @param array<string,mixed> $input Raw form input.
	 */
	public static function save_settings( array $input ): void {
		$current       = self::get_settings();
		$previous_mode = self::get_mode();
		$out           = $current; // Preserve `enabled` and `enabled_at`.

		$mode        = isset( $input['mode'] ) ? (string) $input['mode'] : (string) $current['mode'];
		$out['mode'] = in_array( $mode, self::ALLOWED_MODES, true ) ? $mode : 'log_only';

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

		$difficulty        = isset( $input['difficulty'] ) ? (string) $input['difficulty'] : (string) $current['difficulty'];
		$out['difficulty'] = array_key_exists( $difficulty, self::DIFFICULTY_BITS ) ? $difficulty : 'standard';

		// 2.8.0: autoloaded. This option is read on every front-end request, so
		// leaving it out of the autoload set cost one query on each of them.
		update_option( self::OPTION_KEY, $out, true );
	}

	// ------------------------------------------------------------------
	// Challenge issuance
	// ------------------------------------------------------------------

	/**
	 * Issue a fresh single-use challenge and persist its server-side record.
	 *
	 * @param int|null $bits Difficulty override (tests); null = configured.
	 * @return array{nonce:string,bits:int}
	 */
	public static function issue_challenge( ?int $bits = null ): array {
		$bits  = null === $bits ? self::get_difficulty_bits() : max( 1, min( 24, $bits ) );
		$nonce = bin2hex( random_bytes( 16 ) );

		set_transient(
			self::challenge_key( $nonce ),
			array(
				'ip'   => self::ip_fingerprint( LoginArmor::get_client_ip() ),
				'bits' => $bits,
			),
			self::CHALLENGE_TTL
		);

		return array(
			'nonce' => $nonce,
			'bits'  => $bits,
		);
	}

	/**
	 * AJAX endpoint: hand a challenge to the login page. Anonymous by design;
	 * the response is random data, and issuance is rate-limited per IP.
	 */
	public static function ajax_challenge(): void {
		$ip = LoginArmor::get_client_ip();

		if ( LoginArmor::is_reliable_client_ip( $ip ) ) {
			$count = self::increment_fixed_window_counter( self::rate_key( $ip ), self::RATE_WINDOW, self::RATE_LIMIT );
			if ( $count >= self::RATE_LIMIT ) {
				wp_send_json_error( array( 'message' => 'rate_limited' ), 429 );
			}
		}

		nocache_headers();
		wp_send_json_success( self::issue_challenge() );
	}

	// ------------------------------------------------------------------
	// Form injection
	// ------------------------------------------------------------------

	/**
	 * Emit the hidden challenge fields and enqueue the solver script.
	 *
	 * The wrapper carries the AJAX endpoint as a data attribute so the solver
	 * script stays fully external (no inline JS, compatible with the strict
	 * CSP that Login Page Security Headers can apply to the login page).
	 */
	public static function inject_field(): void {
		echo '<span class="la-pow-wrap" data-la-pow-endpoint="' . esc_url( admin_url( 'admin-ajax.php' ) ) . '" hidden>';
		echo '<input type="hidden" name="' . esc_attr( self::FIELD_NONCE ) . '" value="" autocomplete="off">';
		echo '<input type="hidden" name="' . esc_attr( self::FIELD_SOLUTION ) . '" value="" autocomplete="off">';
		echo '</span>';

		self::enqueue_solver();
	}

	/**
	 * Enqueue the external solver. Called from within the form render, which
	 * both wp-login.php (`login_footer` prints footer scripts) and front-end
	 * pages (WooCommerce forms render before `wp_footer`) support.
	 */
	private static function enqueue_solver(): void {
		if ( wp_script_is( 'login-armor-pow', 'enqueued' ) ) {
			return;
		}

		$js_path = LOGIN_ARMOR_DIR . 'admin/assets/js/pow.js';
		// Content-hash versioning (filemtime is unreliable through symlinks).
		$version = file_exists( $js_path ) ? substr( md5_file( $js_path ), 0, 8 ) : LOGIN_ARMOR_VERSION;

		wp_enqueue_script(
			'login-armor-pow',
			LOGIN_ARMOR_URL . 'admin/assets/js/pow.js',
			array(),
			$version,
			true
		);
	}

	// ------------------------------------------------------------------
	// Verification
	// ------------------------------------------------------------------

	/**
	 * Verify the submitted proof during authentication.
	 *
	 * Runs at priority 25: after the core credential handlers so a missing
	 * or invalid proof rejects even valid credentials (a bot replaying
	 * stolen passwords), before the LimitLogin lockout gate.
	 *
	 * Defensive signature: untyped parameters with defaults, per the plugin's
	 * core-hook callback invariant (third parties re-fire `authenticate`
	 * with degraded arity).
	 *
	 * @param \WP_User|\WP_Error|null $user     Current auth result.
	 * @param string                  $username Submitted username.
	 * @param string                  $password Submitted password.
	 * @return \WP_User|\WP_Error|null
	 */
	public static function maybe_verify( $user = null, $username = '', $password = '' ) {
		if ( self::should_skip_verification( (string) $username, (string) $password ) ) {
			return $user;
		}

		$result = self::check_posted_proof();
		if ( 'pass' === $result ) {
			return $user;
		}

		$ip = LoginArmor::get_client_ip();

		/**
		 * Fires when a login submission carries no valid Proof-of-Work.
		 *
		 * Fires in both modes; only `enforce` also rejects the login.
		 *
		 * @param string $ip       Client IP.
		 * @param string $username Submitted username.
		 * @param string $reason   'missing' | 'invalid'.
		 */
		do_action( 'login_armor_pow_failed', $ip, (string) $username, $result );

		self::increment_fixed_window_counter( self::SOFTFAIL_COUNTER_KEY, self::SOFTFAIL_WINDOW, self::SOFTFAIL_CAP );

		if ( 'enforce' !== self::effective_mode() ) {
			return $user;
		}

		self::record_incident( $ip, (string) $username );

		return new \WP_Error(
			'login_armor_pow_failed',
			esc_html__( 'Your browser could not complete the security check. Please make sure JavaScript is enabled, then try again.', 'login-armor' )
		);
	}

	/**
	 * Whether the current authentication context cannot carry a browser-solved
	 * proof and must therefore be left alone.
	 *
	 * XML-RPC, REST (application passwords), cron, WP-CLI and AJAX logins have
	 * no page where the solver ran; programmatic wp_signon() calls (e.g.
	 * auto-login after registration) post no credentials pair through a form.
	 */
	private static function should_skip_verification( string $username, string $password ): bool {
		if ( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST ) {
			return true;
		}
		if ( defined( 'REST_REQUEST' ) && REST_REQUEST ) {
			return true;
		}
		if ( defined( 'WP_CLI' ) && WP_CLI ) {
			return true;
		}
		if ( function_exists( 'wp_doing_cron' ) && wp_doing_cron() ) {
			return true;
		}
		if ( function_exists( 'wp_doing_ajax' ) && wp_doing_ajax() ) {
			return true;
		}
		if ( '' === $username && '' === $password ) {
			return true;
		}

		/**
		 * Filters whether Proof-of-Work verification is skipped for the
		 * current request.
		 *
		 * Lets a site exempt a custom login flow that cannot run the solver.
		 *
		 * @param bool   $skip     Whether to skip verification.
		 * @param string $username Submitted username.
		 */
		return (bool) apply_filters( 'login_armor_pow_skip_verification', false, $username );
	}

	/**
	 * Validate the proof carried by the current POST payload.
	 *
	 * The challenge is consumed (deleted) as soon as it is looked up, before
	 * the solution is checked: single-use even on a failed attempt, so a
	 * solved proof can never be replayed across submissions.
	 *
	 * @return string 'pass' | 'missing' | 'invalid'.
	 */
	public static function check_posted_proof(): string {
		// phpcs:disable WordPress.Security.NonceVerification.Missing -- Called from the authenticate filter before nonce validation; reads two hidden fields.
		$nonce    = isset( $_POST[ self::FIELD_NONCE ] ) ? sanitize_text_field( wp_unslash( (string) $_POST[ self::FIELD_NONCE ] ) ) : '';
		$solution = isset( $_POST[ self::FIELD_SOLUTION ] ) ? sanitize_text_field( wp_unslash( (string) $_POST[ self::FIELD_SOLUTION ] ) ) : '';
		// phpcs:enable WordPress.Security.NonceVerification.Missing

		if ( '' === $nonce && '' === $solution ) {
			return 'missing';
		}
		if ( ! preg_match( '/^[a-f0-9]{32}$/', $nonce ) || ! preg_match( '/^[0-9]{1,12}$/', $solution ) ) {
			return 'invalid';
		}

		$key    = self::challenge_key( $nonce );
		$record = get_transient( $key );
		delete_transient( $key ); // Consume first: single-use.

		if ( ! is_array( $record ) || ! isset( $record['ip'], $record['bits'] ) ) {
			return 'invalid'; // Expired, replayed, or forged.
		}

		/**
		 * Filters whether the challenge must be bound to the client IP.
		 *
		 * Default true. A site whose visitors hop networks mid-login (rare)
		 * can relax the binding; the proof itself is still required.
		 *
		 * @param bool $bind Whether to require the same IP as at issuance.
		 */
		$bind_ip = (bool) apply_filters( 'login_armor_pow_bind_ip', true );
		if ( $bind_ip && ! hash_equals( (string) $record['ip'], self::ip_fingerprint( LoginArmor::get_client_ip() ) ) ) {
			return 'invalid';
		}

		if ( ! self::solution_meets_difficulty( $nonce, $solution, (int) $record['bits'] ) ) {
			return 'invalid';
		}

		return 'pass';
	}

	/**
	 * Whether sha256("nonce:solution") carries the required leading zero bits.
	 */
	public static function solution_meets_difficulty( string $nonce, string $solution, int $bits ): bool {
		if ( $bits < 1 ) {
			return false;
		}
		$digest    = hash( 'sha256', $nonce . ':' . $solution, true );
		$remaining = $bits;
		$length    = strlen( $digest );

		for ( $i = 0; $i < $length && $remaining > 0; $i++ ) {
			$byte = ord( $digest[ $i ] );
			if ( $remaining >= 8 ) {
				if ( 0 !== $byte ) {
					return false;
				}
				$remaining -= 8;
				continue;
			}
			// Partial byte: the top $remaining bits must be zero.
			return 0 === ( $byte >> ( 8 - $remaining ) );
		}

		return true;
	}

	/**
	 * Read the rolling soft-failure counter (submissions without a valid
	 * proof over the current 7-day window). Rendered in the admin section.
	 */
	public static function get_softfail_count(): int {
		return self::read_fixed_window_counter( self::SOFTFAIL_COUNTER_KEY, self::SOFTFAIL_WINDOW );
	}

	// ------------------------------------------------------------------
	// Internals
	// ------------------------------------------------------------------

	/** Transient key for a challenge nonce (the nonce never hits the DB in clear). */
	private static function challenge_key( string $nonce ): string {
		return self::CHALLENGE_PREFIX . hash( 'sha256', $nonce );
	}

	/** Non-reversible IP fingerprint stored alongside the challenge. */
	private static function ip_fingerprint( string $ip ): string {
		return hash_hmac( 'sha256', $ip, wp_salt( 'auth' ) );
	}

	/**
	 * Non-reversible option key for a reliable client IP issuance counter.
	 *
	 * One counter per IPv6 /64, the block a single subscriber is given:
	 * counted per exact address, rotating addresses inside it reset the
	 * quota at every request. Not for an address whose first 64 bits are
	 * zero (::ffff:a.b.c.d and the like): every IPv4 client mapped that way
	 * would share one counter.
	 */
	private static function rate_key( string $ip ): string {
		$packed = @inet_pton( $ip ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- A non-IP keeps its own counter, as before.
		if ( false !== $packed && 16 === strlen( $packed ) && str_repeat( "\0", 8 ) !== substr( $packed, 0, 8 ) ) {
			$ip = bin2hex( substr( $packed, 0, 8 ) ) . '::/64';
		}
		return self::RATE_PREFIX . substr( hash_hmac( 'sha256', $ip, wp_salt( 'auth' ) ), 0, 32 );
	}

	/**
	 * Upsert a detection incident for an enforced Proof-of-Work rejection.
	 * Aggregated per IP over a 60-minute window, like the honeypot.
	 */
	private static function record_incident( string $ip, string $username ): void {
		if ( ! class_exists( Incident::class ) || ! LoginArmor::is_reliable_client_ip( $ip ) ) {
			return;
		}

		$now      = current_time( 'mysql', true );
		$existing = Incident::find_active( Incident::PATTERN_POW_FAILED, $ip, 'ip', 60 );

		if ( $existing instanceof Incident ) {
			$existing->increment_occurrence( Incident::SEVERITY_MEDIUM, 1, 1, 1 );
			do_action( 'login_armor_incident_created', $existing, false );
			return;
		}

		$incident                   = new Incident();
		$incident->pattern          = Incident::PATTERN_POW_FAILED;
		$incident->severity         = Incident::SEVERITY_MEDIUM;
		$incident->started_at       = $now;
		$incident->last_seen_at     = $now;
		$incident->ip               = $ip;
		$incident->subnet           = '';
		$incident->target_username  = substr( $username, 0, 60 );
		$incident->events_count     = 1;
		$incident->unique_ips       = 1;
		$incident->unique_usernames = 1;
		$incident->status           = Incident::STATUS_ACTIVE;
		$incident->insert();
		do_action( 'login_armor_incident_created', $incident, true );
	}

	/** Remove expired issuance rate-limit counter rows (cron maintenance). */
	public static function purge_rate_counters(): int {
		global $wpdb;
		$cutoff = time() - self::RATE_WINDOW;
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Maintenance cleanup of plugin-owned counters.
		$deleted = (int) $wpdb->query(
			$wpdb->prepare(
				"DELETE FROM {$wpdb->options}
				WHERE option_name LIKE %s
				AND CAST(SUBSTRING_INDEX(option_value, '|', 1) AS UNSIGNED) < %d",
				$wpdb->esc_like( self::RATE_PREFIX ) . '%',
				$cutoff
			)
		);
		if ( $deleted > 0 ) {
			wp_cache_flush_group( 'options' );
		}
		return $deleted;
	}

	/** Read a plugin-owned fixed-window counter directly from the database. */
	private static function read_fixed_window_counter( string $key, int $window_seconds ): int {
		global $wpdb;

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Security counter requires a current read.
		$value = (string) $wpdb->get_var( $wpdb->prepare( "SELECT option_value FROM {$wpdb->options} WHERE option_name = %s", $key ) );
		list( $window, $count ) = array_pad( explode( '|', $value, 2 ), 2, '0' );
		$current = (int) floor( time() / $window_seconds ) * $window_seconds;
		return (int) $window === $current ? max( 0, (int) $count ) : 0;
	}

	/** Atomically increment and return a bounded fixed-window counter. */
	private static function increment_fixed_window_counter( string $key, int $window_seconds, int $limit ): int {
		global $wpdb;

		$window = (int) floor( time() / $window_seconds ) * $window_seconds;
		$value  = $window . '|1';
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.NotPrepared -- Atomic counter via unique option_name.
		$inserted = (int) $wpdb->query(
			$wpdb->prepare(
				"INSERT IGNORE INTO {$wpdb->options} (option_name, option_value, autoload) VALUES (%s, %s, 'no')",
				$key,
				$value
			)
		);
		if ( 0 === $inserted ) {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.NotPrepared -- Atomic fixed-window increment.
			$wpdb->query(
				$wpdb->prepare(
					"UPDATE {$wpdb->options}
					SET option_value = IF(
						CAST(SUBSTRING_INDEX(option_value, '|', 1) AS UNSIGNED) = %d,
						CONCAT(%d, '|', LEAST(%d, CAST(SUBSTRING_INDEX(option_value, '|', -1) AS UNSIGNED) + 1)),
						%s
					)
					WHERE option_name = %s",
					$window,
					$window,
					$limit,
					$value,
					$key
				)
			);
		}
		wp_cache_delete( $key, 'options' );
		return min( $limit, self::read_fixed_window_counter( $key, $window_seconds ) );
	}
}
