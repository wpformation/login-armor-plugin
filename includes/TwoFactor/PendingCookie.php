<?php
/**
 * Pending-2FA verification cookie.
 *
 * Replaces the 64-hex token previously transmitted via the URL query string
 * (?login-armor-2fa=verify&token=<64hex>). The cookie carries an HMAC-signed
 * payload bound to the user_id, the random token and an expiry timestamp; the
 * matching transient is keyed on sha256($token) so the clear token never
 * appears in wp_options.
 *
 * Security boundaries enforced:
 *   1. Cookie signing uses hash_hmac with wp_salt('auth'). Rotating AUTH_KEY
 *      or AUTH_SALT automatically invalidates every pending cookie.
 *   2. All equality checks on signatures use hash_equals (constant-time).
 *   3. SameSite=Strict prevents the cookie from being sent on any cross-site
 *      navigation (the pending-2FA flow has no legitimate cross-site need).
 *   4. Cookie path is scoped to the Hide Login slug when active, else to
 *      COOKIEPATH (the WP install directory).
 *
 * @package LoginArmor\TwoFactor
 * @since   2.1.0
 */

namespace LoginArmor\TwoFactor;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class PendingCookie {

	/** @var string Cookie name. */
	public const COOKIE_NAME = 'la_2fa_pending';

	/** @var int Cookie/transient TTL in seconds, mirrors TwoFactor::TOKEN_TTL. */
	public const TTL = 600;

	/**
	 * Mint the cookie. Call AFTER the transient is stored under the hashed key.
	 *
	 * @param int    $user_id WordPress user ID pending verification.
	 * @param string $token   The 64-hex token (clear): handed to the browser only.
	 */
	public static function mint( int $user_id, string $token ): void {
		$expires_at = time() + self::TTL;
		$value      = self::sign( $user_id, $token, $expires_at );

		setcookie(
			self::COOKIE_NAME,
			$value,
			[
				'expires'  => $expires_at,
				'path'     => self::get_path(),
				'domain'   => COOKIE_DOMAIN,
				'secure'   => is_ssl(),
				'httponly' => true,
				'samesite' => 'Strict',
			]
		);
	}

	/**
	 * Read the cookie. Returns parsed payload if present + signed + unexpired.
	 *
	 * @return array{user_id:int,token:string}|null
	 */
	public static function read(): ?array {
		if ( empty( $_COOKIE[ self::COOKIE_NAME ] ) ) {
			return null;
		}
		$raw    = sanitize_text_field( wp_unslash( (string) $_COOKIE[ self::COOKIE_NAME ] ) );
		$parsed = self::parse_cookie( $raw );
		if ( null === $parsed ) {
			return null;
		}
		if ( $parsed['expires_at'] <= time() ) {
			return null;
		}
		$expected = self::compute_signature( $parsed['user_id'], $parsed['token'], $parsed['expires_at'] );
		if ( ! hash_equals( $expected, $parsed['signature'] ) ) {
			return null;
		}
		return [
			'user_id' => $parsed['user_id'],
			'token'   => $parsed['token'],
		];
	}

	/**
	 * Clear the cookie. Call after consume_token, after MAX_FAILURES, on wp_login_failed.
	 */
	public static function clear(): void {
		setcookie(
			self::COOKIE_NAME,
			'',
			[
				'expires'  => time() - 3600,
				'path'     => self::get_path(),
				'domain'   => COOKIE_DOMAIN,
				'secure'   => is_ssl(),
				'httponly' => true,
				'samesite' => 'Strict',
			]
		);
		unset( $_COOKIE[ self::COOKIE_NAME ] );
	}

	/**
	 * Compute the cookie path. Uses the Hide Login slug when the module is active,
	 * else falls back to COOKIEPATH (WP install directory).
	 *
	 * V2.1.13: returns the slug WITHOUT a trailing slash. RFC 6265 §5.1.4 path-match
	 * accepts a cookie-path that's a strict prefix of the request-path as long as the
	 * first byte of the request-path beyond the cookie-path is `/`: so cookie path
	 * `/<slug>` matches request paths `/<slug>`, `/<slug>/`, and `/<slug>/...`, but
	 * does NOT match `/<slug>XYZ`. Cookie path `/<slug>/` (the V2.1.12 default) only
	 * matched `/<slug>/...` and FAILED to match a bare `/<slug>` request: which is
	 * the URL the trailing-slash normalisation in `HideLogin::handle_loaded()` emits
	 * on installs whose permalink_structure does NOT end with `/`. Result: the 2FA
	 * pending cookie was silently dropped on those installs after the trailing-slash
	 * 302, `maybe_render_verification()` saw `token_data === false`, and bounced the
	 * user back to the login page with no error message. Reported by Alexandre Puy
	 * on dumouriez.com 2026-05-11 (permalink `/%postname%` without trailing slash).
	 */
	public static function get_path(): string {
		// 2.10.0: is_active(), not is_enabled(): while Hide Login stands down
		// beside an exclusive plugin, the login form is not under the slug.
		if ( class_exists( '\\LoginArmor\\HideLogin' ) && \LoginArmor\HideLogin::is_active() ) {
			$slug = (string) get_option( 'login_armor_hide_slug', '' );
			if ( '' !== $slug ) {
				return '/' . trim( $slug, '/' );
			}
		}
		return defined( 'COOKIEPATH' ) && COOKIEPATH !== '' ? COOKIEPATH : '/';
	}

	/**
	 * Build the signed cookie value. Format: <user_id>.<token>.<expires>.<signature>.
	 * Dots are non-hex/non-base64, so they cleanly separate the three numeric/hex segments.
	 */
	private static function sign( int $user_id, string $token, int $expires_at ): string {
		$signature = self::compute_signature( $user_id, $token, $expires_at );
		return $user_id . '.' . $token . '.' . $expires_at . '.' . $signature;
	}

	private static function compute_signature( int $user_id, string $token, int $expires_at ): string {
		return hash_hmac( 'sha256', $user_id . '|' . $token . '|' . $expires_at, wp_salt( 'auth' ) );
	}

	/**
	 * Parse and structurally validate the raw cookie value.
	 *
	 * @return array{user_id:int,token:string,expires_at:int,signature:string}|null
	 */
	private static function parse_cookie( string $raw ): ?array {
		$parts = explode( '.', $raw );
		if ( 4 !== count( $parts ) ) {
			return null;
		}
		[ $user_id_raw, $token, $expires_raw, $signature ] = $parts;
		if (
			! ctype_digit( $user_id_raw )
			|| ! preg_match( '/^[a-f0-9]{64}$/', $token )
			|| ! ctype_digit( $expires_raw )
			|| ! preg_match( '/^[a-f0-9]{64}$/', $signature )
		) {
			return null;
		}
		return [
			'user_id'    => (int) $user_id_raw,
			'token'      => $token,
			'expires_at' => (int) $expires_raw,
			'signature'  => $signature,
		];
	}

	// ── Test helpers (only active when LOGIN_ARMOR_TESTING is defined) ──

	/**
	 * @internal Public only when LOGIN_ARMOR_TESTING is defined.
	 */
	public static function testing_build( int $user_id, string $token, int $expires_at ): string {
		if ( ! defined( 'LOGIN_ARMOR_TESTING' ) || ! LOGIN_ARMOR_TESTING ) {
			return '';
		}
		return self::sign( $user_id, $token, $expires_at );
	}

	// 2.8.0: testing_parse() is gone. It was a copy of the signature check of
	// read(), reachable only from tests, and no test called it: the suite
	// tests read() itself now, with a forged signature of the right shape.
}
