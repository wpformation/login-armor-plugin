<?php
/**
 * Login Honeypot: an invisible form field that only a bot would fill in.
 *
 * A hit is treated as a strong bot signal and recorded. A reliable client IP
 * is banned only after repeated hits inside a short window, avoiding a
 * one-request availability sanction against a shared or forged identity.
 * The error message returned to the browser is intentionally generic so
 * bots cannot tell a honeypot trip from a wrong password.
 *
 * @package LoginArmor
 * @since   2.0.0
 */

namespace LoginArmor\Hardening;

use LoginArmor\Detection\Incident;
use LoginArmor\LimitLogin;
use LoginArmor\LoginArmor;

// Exit if accessed directly.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Deterministic-per-site login honeypot.
 */
class Honeypot {

	/** Number of catches required before an IP lockout is written. */
	private const LOCK_THRESHOLD = 3;

	/** Sliding window for the honeypot threshold. */
	private const LOCK_WINDOW = 600;

	/**
	 * Derive a stable honeypot field name for the current site.
	 *
	 * The derivation is keyed by the nonce salts (via `wp_hash`) so it is
	 * unpredictable to attackers without access to wp-config.php, yet
	 * stable across page loads.
	 */
	public static function field_name(): string {
		$hash = wp_hash( 'la_honeypot|' . site_url(), 'nonce' );
		return 'la_hp_' . substr( $hash, 0, 12 );
	}

	/**
	 * Emit the honeypot field inside a login/register/lostpassword form.
	 *
	 * Primary protection: <input type="hidden">, HTML-level invisibility
	 * survives any theme that strips inline styles (audit S-22). Defense-in-
	 * depth layer 2: wrapping div + inject_inline_css() keep the field
	 * visually hidden even if some upstream layer mutates the type attribute.
	 */
	public static function inject_field(): void {
		$name = self::field_name();
		echo '<div class="la-hp-wrap" aria-hidden="true" style="position:absolute;left:-9999px;top:auto;width:1px;height:1px;overflow:hidden;">';
		echo '<label for="' . esc_attr( $name ) . '">' . esc_html__( 'Leave this field empty', 'login-armor' ) . '</label>';
		echo '<input type="hidden" id="' . esc_attr( $name ) . '" name="' . esc_attr( $name ) . '" tabindex="-1" autocomplete="off" value="">';
		echo '</div>';
	}

	/**
	 * Detect whether the current POST payload contains a filled honeypot.
	 */
	public static function caught(): bool {
		$name = self::field_name();
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Called from the authenticate filter before nonce is validated; only reads a single hidden field.
		if ( ! isset( $_POST[ $name ] ) ) {
			return false;
		}
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- same rationale as above.
		$value = sanitize_text_field( wp_unslash( (string) $_POST[ $name ] ) );
		return '' !== trim( $value );
	}

	/**
	 * Defensive inline CSS to keep the honeypot visually hidden even if a
	 * theme strips the inline `style` attribute on the wrapper.
	 */
	public static function inject_inline_css(): void {
		echo '<style>.la-hp-wrap{position:absolute!important;left:-9999px!important;top:auto!important;width:1px!important;height:1px!important;overflow:hidden!important;}</style>';
	}

	/**
	 * Wire up all hooks. Called from class-hardening.php only when the
	 * `login_honeypot` toggle is on.
	 *
	 * Frontend coverage strategy (V2.1.16):
	 *  - Native WP forms (login/register/lostpassword) get the field via
	 *    the matching `*_form` action.
	 *  - WooCommerce forms (account login, register, lost-password) get it
	 *    via the dedicated `woocommerce_*_form` actions.
	 *  - Third-party forms (Elementor Pro Login, Divi Login, MemberPress,
	 *    custom login forms posting to wp-login.php, etc.) are covered by
	 *    a small inline script printed in wp_footer that scans every
	 *    <form> on the page and clones the honeypot wrapper into any form
	 *    that looks like a login/register/lost-password form. Limitation:
	 *    pure-REST/AJAX login flows that build the request body in JS are
	 *    not covered: those have to use the `caught()` check directly or
	 *    extend the hook list themselves.
	 */
	public static function register(): void {
		add_action( 'login_form', [ self::class, 'inject_field' ] );
		add_action( 'register_form', [ self::class, 'inject_field' ] );
		add_action( 'lostpassword_form', [ self::class, 'inject_field' ] );
		// After the core credential handlers (20), like the anti-bot proof:
		// wp_authenticate_username_password() re-checks non-empty credentials
		// whatever it receives, so an error returned at 5 was replaced by the
		// user when the password was right, and a bot that filled the trap
		// with valid credentials was let in. Before the LimitLogin gate (30).
		add_filter( 'authenticate', [ self::class, 'maybe_block' ], 25, 3 );
		add_action( 'login_enqueue_scripts', [ self::class, 'inject_inline_css' ] );

		// WooCommerce native forms.
		add_action( 'woocommerce_login_form', [ self::class, 'inject_field' ] );
		add_action( 'woocommerce_register_form', [ self::class, 'inject_field' ] );
		add_action( 'woocommerce_lostpassword_form', [ self::class, 'inject_field' ] );

		// Generic frontend fallback for third-party login forms.
		add_action( 'wp_footer', [ self::class, 'inject_frontend_script' ], 99 );
	}

	/**
	 * Print a small inline script in wp_footer that injects the honeypot
	 * field into any frontend login/register/lost-password form not already
	 * covered by a dedicated hook.
	 *
	 * Heuristic: form has at least one of
	 *  - input[name="log"], input[name="pwd"]               (wp-login.php)
	 *  - input[name="username"], input[name="password"]     (WC, custom)
	 *  - input[name="user_login"], input[name="user_pass"]  (registration)
	 *  - action attribute containing `wp-login.php` or `my-account`
	 *
	 * The injected wrapper carries the same inline style as inject_field()
	 * so it stays visually hidden regardless of theme CSS.
	 *
	 * @since 2.1.16
	 */
	public static function inject_frontend_script(): void {
		// Skip admin and feeds: saves a few bytes on every page render.
		if ( is_admin() || is_feed() ) {
			return;
		}

		$hp_name = self::field_name();

		// Build the wrapper HTML once on the server so we keep one source of
		// truth (inject_field()) and the JS only has to clone it. The wrapper
		// already runs esc_attr() / esc_html__() internally, and we re-encode
		// via wp_json_encode() for the JS string literal: double-safe.
		ob_start();
		self::inject_field();
		$wrapper_html = (string) ob_get_clean();

		?>
<script id="login-armor-honeypot-frontend">
(function () {
	var hpName  = <?php echo wp_json_encode( $hp_name ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- wp_json_encode() returns a JSON literal safe for inline JS. ?>;
	var wrapper = <?php echo wp_json_encode( $wrapper_html ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- wp_json_encode() returns a JSON literal; $wrapper_html itself is built from esc_attr()/esc_html__() inside inject_field(). ?>;

	function inject() {
		var forms = document.querySelectorAll( 'form' );
		for ( var i = 0; i < forms.length; i++ ) {
			var form = forms[ i ];
			if ( form.querySelector( 'input[name="' + hpName + '"]' ) ) {
				continue;
			}
			var hasLoginInput =
				form.querySelector( 'input[name="log"], input[name="pwd"], input[name="username"], input[name="password"], input[name="user_login"], input[name="user_pass"]' );
			var action = ( form.getAttribute( 'action' ) || '' ).toLowerCase();
			var actionMatch =
				action.indexOf( 'wp-login.php' ) !== -1 ||
				action.indexOf( 'my-account' ) !== -1;
			if ( ! hasLoginInput && ! actionMatch ) {
				continue;
			}
			var tmp = document.createElement( 'div' );
			tmp.innerHTML = wrapper;
			while ( tmp.firstChild ) {
				form.appendChild( tmp.firstChild );
			}
		}
	}

	if ( document.readyState === 'loading' ) {
		document.addEventListener( 'DOMContentLoaded', inject );
	} else {
		inject();
	}
})();
</script>
		<?php
	}

	/**
	 * Short-circuit authentication with a generic error when the honeypot
	 * field has been filled in. Records the signal and applies the configured
	 * lockout only after the repeated-hit threshold.
	 *
	 * @param \WP_User|\WP_Error|null $user     Current auth result.
	 * @param string                  $username Submitted username.
	 * @param string                  $password Submitted password.
	 * @return \WP_User|\WP_Error|null
	 */
	public static function maybe_block( $user = null, $username = '', $password = '' ) {
		unset( $password );

		if ( ! self::caught() ) {
			return $user;
		}

		$ip = LoginArmor::get_client_ip();

		do_action( 'login_armor_honeypot_caught', $ip, (string) $username );

		$hits = self::record_hit( $ip, (string) $username );
		if ( $hits >= self::LOCK_THRESHOLD ) {
			self::ban_ip( $ip, (string) $username );
		}
		self::record_incident( $ip, (string) $username );

		return new \WP_Error(
			'honeypot_caught',
			esc_html__( 'Authentication failed.', 'login-armor' )
		);
	}

	/**
	 * Persist a honeypot signal and return the recent count for this IP.
	 */
	private static function record_hit( string $ip, string $username ): int {
		if ( ! LoginArmor::is_reliable_client_ip( $ip ) ) {
			return 0;
		}
		global $wpdb;
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Custom security event table.
		$wpdb->insert(
			$wpdb->prefix . 'login_armor_attempts',
			array(
				'ip'           => $ip,
				'username'     => sanitize_user( $username ),
				'attempt_time' => current_time( 'mysql', true ),
				'status'       => 'honeypot',
			),
			array( '%s', '%s', '%s', '%s' )
		);

		$since = gmdate( 'Y-m-d H:i:s', time() - self::LOCK_WINDOW );
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Current threshold count.
		return (int) $wpdb->get_var(
			$wpdb->prepare(
				"SELECT COUNT(*) FROM {$wpdb->prefix}login_armor_attempts WHERE ip = %s AND status = 'honeypot' AND attempt_time > %s",
				$ip,
				$since
			)
		);
	}

	/**
	 * Insert a lockout record into the LoginArmor attempts table.
	 *
	 * LimitLogin has no public ban_ip() API: lockouts are implicit rows
	 * with status='lockout' and a duration computed by the brute-force
	 * configuration. Writing a row directly keeps the honeypot consistent
	 * with the rest of the plugin's lockout view, CLI unblock, etc.
	 *
	 * @param string $ip       Client IP address.
	 * @param string $username Attempted username ('' when unknown).
	 */
	private static function ban_ip( string $ip, string $username = '' ): void {
		if ( ! LoginArmor::is_reliable_client_ip( $ip ) ) {
			return;
		}

		global $wpdb;
		$lock_name = substr( 'login_armor_honeypot_' . md5( $wpdb->prefix . '|' . $ip ), 0, 64 );
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Advisory lock serializes the lockout marker.
		$acquired = (int) $wpdb->get_var( $wpdb->prepare( 'SELECT GET_LOCK(%s, 2)', $lock_name ) );
		if ( 1 !== $acquired ) {
			return;
		}

		try {
			if ( LimitLogin::is_ip_locked( $ip ) ) {
				return;
			}
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Custom plugin table, real-time write.
			$wpdb->insert(
				$wpdb->prefix . 'login_armor_attempts',
				array(
					'ip'           => $ip,
					'username'     => '',
					'attempt_time' => current_time( 'mysql', true ),
					'status'       => 'lockout',
				),
				array( '%s', '%s', '%s', '%s' )
			);

			// V2.4.2 canonical signature: attempted username 2nd (used to pass the
			// literal 'honeypot' here), gate identifier in the context array 3rd.
			do_action( 'login_armor_ip_blocked', $ip, $username, [ 'source' => 'honeypot' ] );
		} finally {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Release this connection's advisory lock.
			$wpdb->get_var( $wpdb->prepare( 'SELECT RELEASE_LOCK(%s)', $lock_name ) );
		}
	}

	/**
	 * Upsert a detection incident for the honeypot hit.
	 *
	 * @param string $ip       Client IP.
	 * @param string $username Attempted username.
	 */
	private static function record_incident( string $ip, string $username ): void {
		if ( ! class_exists( Incident::class ) ) {
			return;
		}

		$now      = current_time( 'mysql', true );
		$existing = Incident::find_active( Incident::PATTERN_BOT_HONEYPOT_CAUGHT, $ip, 'ip', 60 );

		if ( $existing instanceof Incident ) {
			$existing->increment_occurrence( Incident::SEVERITY_HIGH, 1, 1, 1 );
			do_action( 'login_armor_incident_created', $existing, false );
			return;
		}

		$incident                   = new Incident();
		$incident->pattern          = Incident::PATTERN_BOT_HONEYPOT_CAUGHT;
		$incident->severity         = Incident::SEVERITY_HIGH;
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
}
