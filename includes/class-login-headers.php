<?php
/**
 * Login Page Security Headers module.
 *
 * Adds a curated set of HTTP security headers scoped to the login request
 * (wp-login.php and the Hide Login custom slug). Opt-in and narrow in scope:
 * clickjacking protection, MIME sniffing protection, referrer leakage
 * control, and a CSP tight enough to stop credential-stealing injections
 * without breaking WP core's own inline scripts on the login form.
 *
 * Why login-only rather than site-wide: the login form is the single most
 * valuable XSS target (steals credentials), but a site-wide CSP requires
 * per-theme/plugin tuning and often breaks admin builds. Login is a
 * controlled surface (WP core + this plugin) so a strict CSP here is
 * both effective and stable.
 *
 * @package LoginArmor
 * @since   2.0.0
 */

namespace LoginArmor;

// Exit if accessed directly.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Emits login-scoped security headers when enabled.
 */
class LoginHeaders {

	/** @var string Option key: module enabled flag. */
	public const OPTION_ENABLED = 'login_armor_login_headers_enabled';

	/** @var string Option key: CSP profile (`standard` | `strict`). */
	public const OPTION_MODE = 'login_armor_login_headers_mode';

	/** @var string Option key: optional CSP reporting endpoint. */
	public const OPTION_REPORT_URI = 'login_armor_login_headers_report_uri';

	/** @var string Option key: HSTS profile (`off` | `enabled` | `enabled_subdomains`). */
	public const OPTION_HSTS = 'login_armor_login_headers_hsts';

	/** @var string Option key: emit non-CSP security headers site-wide (opt-in). */
	public const OPTION_SITEWIDE = 'login_armor_headers_sitewide';

	/** @var string[] Allowed mode values. */
	public const ALLOWED_MODES = [ 'standard', 'strict' ];

	/** @var string[] Allowed HSTS modes. */
	public const ALLOWED_HSTS_MODES = [ 'off', 'enabled', 'enabled_subdomains' ];

	/** @var int HSTS max-age for `enabled` mode (180 days). */
	public const HSTS_MAX_AGE = 15552000;

	/** @var int HSTS max-age for `enabled_subdomains` mode (1 year). */
	public const HSTS_MAX_AGE_LONG = 31536000;

	/**
	 * Constructor. Wires the login-page hooks only when enabled.
	 *
	 * Hook choice: `login_header` (NOT `login_init`). WP 6.9 core emits its
	 * own X-Frame-Options and a narrow frame-ancestors CSP directly in
	 * wp-login.php AFTER the `login_init` action but BEFORE `login_header`.
	 * Hooking on login_init means our headers get silently overwritten by
	 * core's defaults; hooking on login_header guarantees ours win because
	 * PHP's `header()` replaces same-name headers.
	 */
	public function __construct() {
		if ( self::is_enabled() ) {
			// Fires inside login_header(): after every core `header()` call on wp-login.php.
			add_action( 'login_header', [ $this, 'send_headers' ], 1 );

			// Defensive belt-and-braces for non-standard login flows (custom auth plugins
			// that short-circuit login_header and exit earlier).
			add_action( 'login_init', [ $this, 'send_headers' ], 999 );

			// Covers the HideLogin "loginarmor" slug path, which exits before login_init
			// in some HideLogin code paths. Hooking `send_headers` guarantees coverage.
			add_action( 'send_headers', [ $this, 'maybe_send_on_front' ] );
		}

		// Site-wide non-CSP security headers: independent opt-in. Front-end
		// only: admin is same-origin and already hardened by core, and a
		// site-wide CSP is deliberately NOT emitted (it breaks themes).
		if ( self::is_sitewide_enabled() ) {
			add_action( 'send_headers', [ $this, 'send_sitewide_headers' ] );
		}
	}

	/**
	 * Check if the module is enabled.
	 */
	public static function is_enabled(): bool {
		return (bool) get_option( self::OPTION_ENABLED, false );
	}

	/**
	 * Whether the site-wide non-CSP security headers are enabled.
	 */
	public static function is_sitewide_enabled(): bool {
		return (bool) get_option( self::OPTION_SITEWIDE, false );
	}

	/**
	 * Emit the site-wide security headers on front-end responses.
	 *
	 * Excludes the CSP (theme-breaking) and uses X-Frame-Options SAMEORIGIN
	 * rather than DENY so legitimate same-origin embeds keep working.
	 */
	public function send_sitewide_headers(): void {
		if ( is_admin() || headers_sent() ) {
			return;
		}
		foreach ( self::build_sitewide_headers() as $name => $value ) {
			header( $name . ': ' . $value );
		}
	}

	/**
	 * Build the site-wide header map. Public for admin preview/introspection.
	 *
	 * @return array<string, string>
	 */
	public static function build_sitewide_headers(): array {
		$headers = [
			'X-Content-Type-Options' => 'nosniff',
			'Referrer-Policy'        => 'strict-origin-when-cross-origin',
			'Permissions-Policy'     => 'camera=(), microphone=(), geolocation=(), interest-cohort=()',
			'X-Frame-Options'        => 'SAMEORIGIN',
		];

		$hsts_mode = self::get_hsts_mode();
		if ( 'off' !== $hsts_mode && is_ssl() ) {
			$headers['Strict-Transport-Security'] = ( 'enabled_subdomains' === $hsts_mode )
				? 'max-age=' . self::HSTS_MAX_AGE_LONG . '; includeSubDomains'
				: 'max-age=' . self::HSTS_MAX_AGE;
		}

		return $headers;
	}

	/**
	 * Resolve the current mode, sanitized against the allowed set.
	 */
	public static function get_mode(): string {
		$mode = (string) get_option( self::OPTION_MODE, 'standard' );
		return in_array( $mode, self::ALLOWED_MODES, true ) ? $mode : 'standard';
	}

	/**
	 * Return the sanitized report URI, or an empty string when none is set.
	 */
	public static function get_report_uri(): string {
		$uri = (string) get_option( self::OPTION_REPORT_URI, '' );
		if ( '' === $uri ) {
			return '';
		}
		$uri = esc_url_raw( $uri );
		return str_starts_with( (string) $uri, 'https://' ) ? (string) $uri : '';
	}

	/**
	 * Return the sanitized HSTS mode value.
	 *
	 * Defaults to 'off' so existing installs upgrading from v2.0.4 do not
	 * suddenly emit HSTS on a site that may still be served partly over
	 * plain HTTP. New installs ship with the option visible in the admin
	 * UI and the default switches to `enabled` once the admin opts in.
	 */
	public static function get_hsts_mode(): string {
		$mode = (string) get_option( self::OPTION_HSTS, 'off' );
		return in_array( $mode, self::ALLOWED_HSTS_MODES, true ) ? $mode : 'off';
	}

	/**
	 * Send the configured header set on every login request.
	 */
	public function send_headers(): void {
		if ( headers_sent() ) {
			return;
		}

		$headers = $this->build_headers();

		foreach ( $headers as $name => $value ) {
			header( $name . ': ' . $value );
		}
	}

	/**
	 * Send headers on the front-end when the request hits the Hide Login slug.
	 *
	 * Uses HideLogin::get_login_url() as the authoritative source of the slug
	 * so renames stay in sync. Runs only when HideLogin is active.
	 */
	public function maybe_send_on_front(): void {
		if ( is_admin() ) {
			return;
		}

		if ( ! class_exists( '\\LoginArmor\\HideLogin' ) || ! HideLogin::is_active() ) {
			return;
		}

		$slug = trim( (string) get_option( HideLogin::OPTION_SLUG, '' ), '/' );
		if ( '' === $slug ) {
			return;
		}

		$request_uri = isset( $_SERVER['REQUEST_URI'] )
			? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) )
			: '';
		$path = (string) wp_parse_url( $request_uri, PHP_URL_PATH );
		$path = trim( $path, '/' );

		if ( $path !== $slug ) {
			return;
		}

		$this->send_headers();
	}

	/**
	 * Build the ordered header map for the current configuration.
	 *
	 * Public for introspection by the admin preview.
	 *
	 * @return array<string, string>
	 */
	public static function build_headers(): array {
		$mode        = self::get_mode();
		$report_uri  = self::get_report_uri();
		$csp         = self::build_csp( $mode, $report_uri );

		$headers = [
			'Content-Security-Policy'   => $csp,
			'X-Frame-Options'           => 'DENY',
			'Referrer-Policy'           => 'strict-origin-when-cross-origin',
			'X-Content-Type-Options'    => 'nosniff',
			'Permissions-Policy'        => 'camera=(), microphone=(), geolocation=(), interest-cohort=()',
		];

		// Strict-Transport-Security: opt-in. The login surface is the most
		// credential-sensitive part of the site, so pinning TLS aggressively
		// here pays off. We only emit when the request itself is over HTTPS:
		// sending HSTS over a plain HTTP login response would be ignored
		// by the browser anyway, and might surprise admins still mid-TLS
		// migration. `enabled_subdomains` is opt-in because the
		// `includeSubDomains` directive can break sub-sites the admin
		// hasn't migrated yet.
		$hsts_mode = self::get_hsts_mode();
		if ( 'off' !== $hsts_mode && is_ssl() ) {
			if ( 'enabled_subdomains' === $hsts_mode ) {
				$headers['Strict-Transport-Security'] = 'max-age=' . self::HSTS_MAX_AGE_LONG . '; includeSubDomains';
			} else {
				$headers['Strict-Transport-Security'] = 'max-age=' . self::HSTS_MAX_AGE;
			}
		}

		if ( '' !== $report_uri ) {
			// Modern reporting endpoint (alongside the legacy report-uri directive inside the CSP).
			$headers['Report-To'] = wp_json_encode(
				[
					'group'     => 'la-login',
					'max_age'   => 10886400,
					'endpoints' => [ [ 'url' => $report_uri ] ],
				]
			);
		}

		return $headers;
	}

	/**
	 * Compose the CSP header value for a given mode.
	 *
	 * `standard`: permissive enough to preserve WP core's inline login handlers
	 * while blocking the two critical vectors (frame ancestors = clickjacking;
	 * form-action = credential exfiltration to an attacker domain).
	 *
	 * `strict`: adds `default-src 'self'`, `font-src 'self' data:`, and
	 * `connect-src 'self'` to clamp down on out-of-origin loads. Both modes
	 * keep `'unsafe-inline'` for script-src and style-src because wp-login.php
	 * relies on inline scripts and styles emitted by WP core and themes; a
	 * nonce-based replacement would require coordination with every plugin
	 * that prints inline content on the login page. The tightening from strict
	 * is therefore at the network boundary (which origins can be loaded from)
	 * rather than at the inline-script boundary.
	 *
	 * @param string $mode       One of ALLOWED_MODES.
	 * @param string $report_uri Optional https:// reporting endpoint.
	 * @return string
	 */
	public static function build_csp( string $mode, string $report_uri ): string {
		$directives = [];

		// V2.1.12: include the parsed origins of home_url() AND site_url()
		// alongside 'self' on every directive that governs cross-origin
		// resource loads. Without this, sites that route both apex and www
		// (or that run WP-in-subdir / headless multisite / domain mapping)
		// can hit a CSP block when the login page renders on a hostname
		// different from where WP-emitted asset URLs point. 'self' alone is
		// too narrow on those setups: observed bug on dumouriez.com 2026-05-11
		// where `wp_enqueue_style()` emitted CSS links on `https://www.example.com`
		// while the page was served on `https://example.com` (apex), and the
		// browser blocked every CSS via `style-src 'self'`.
		$extra_origins = self::build_csp_extra_origins();
		$source_list   = "'self'" . ( '' !== $extra_origins ? ' ' . $extra_origins : '' );

		if ( 'strict' === $mode ) {
			$directives[] = "default-src {$source_list}";
			$directives[] = "script-src {$source_list} 'unsafe-inline'";
			$directives[] = "style-src {$source_list} 'unsafe-inline'";
			$directives[] = "img-src {$source_list} data:";
			$directives[] = "font-src {$source_list} data:";
			$directives[] = "connect-src {$source_list}";
			$directives[] = "object-src 'none'";
			// base-uri stays 'self': <base> always cross-origin = security hole.
			$directives[] = "base-uri 'self'";
		} else {
			// standard: narrower but never breaks a WP login page.
			$directives[] = "script-src {$source_list} 'unsafe-inline'";
			$directives[] = "style-src {$source_list} 'unsafe-inline'";
			$directives[] = "img-src {$source_list} data:";
			$directives[] = "object-src 'none'";
			$directives[] = "base-uri 'self'";
		}

		$directives[] = "frame-ancestors 'none'";
		// form-action also takes the expanded source list: the login form POSTs
		// to the slug URL (built from home_url / site_url), so the same
		// apex/www mismatch would otherwise cause the browser to block the
		// form submission with `'self'` alone.
		$directives[] = "form-action {$source_list}";

		if ( '' !== $report_uri ) {
			$directives[] = 'report-uri ' . $report_uri;
		}

		return implode( '; ', $directives );
	}

	/**
	 * Compute the space-separated list of CSP source origins derived from
	 * WP's `home_url()` and `site_url()`. Empty string when both reduce to
	 * the document's own origin (covered by `'self'` alone).
	 *
	 * Output format is `scheme://host[:port]` per origin, lowercased,
	 * deduplicated. Used by build_csp() to widen every cross-origin-load
	 * directive without weakening the rest of the policy.
	 *
	 * @since 2.1.12
	 */
	private static function build_csp_extra_origins(): string {
		$origins = [];
		foreach ( [ home_url(), site_url() ] as $url ) {
			$url = (string) $url;
			if ( '' === $url ) {
				continue;
			}
			$parts = wp_parse_url( $url );
			if ( empty( $parts['scheme'] ) || empty( $parts['host'] ) ) {
				continue;
			}
			$origin = strtolower( $parts['scheme'] ) . '://' . strtolower( $parts['host'] );
			if ( ! empty( $parts['port'] ) ) {
				$origin .= ':' . (int) $parts['port'];
			}
			$origins[ $origin ] = true; // dedupe by key
		}
		return implode( ' ', array_keys( $origins ) );
	}
}
