<?php
/**
 * SSRF-safe outbound URL validation.
 *
 * @package LoginArmor
 * @since   2.4.4
 */

namespace LoginArmor\Support;

// Exit if accessed directly.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Single source of truth for "is this outbound URL safe to POST to?".
 *
 * Every module that dispatches to an operator-supplied URL (Activity Log
 * webhook, and the Slack / Discord / generic notification channels) delegates
 * here, so the SSRF policy is defined once and re-checked at every send: not
 * only at save time. Lives in the always-loaded Support namespace so the
 * Notifications module never has to depend on the optionally-loaded Activity
 * Log module for its validation (finding P8).
 */
class SafeUrl {

	/**
	 * Whether a URL is safe to dispatch to (fails closed).
	 *
	 * `wp_http_validate_url()` alone rejects only a few literal IPv4 private
	 * ranges in the URL; it lets through the cloud link-local range
	 * (169.254.0.0/16, metadata endpoints) and IPv6 literals such as `[::1]`
	 * or `[fd00::1]`. This tightens the check: HTTPS only, then resolve the host
	 * to every A and AAAA record and reject if ANY candidate falls in a private
	 * or reserved range (`FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE`
	 * covers 127/8, 169.254/16, 10/8, 172.16/12, 192.168/16, ::1, fc00::/7,
	 * fe80::/10). Resolving AAAA too closes the dual-stack gap where a host's A
	 * record is public but its AAAA points at a private target.
	 *
	 * A host that cannot be resolved to a vettable IP is treated as unsafe
	 * rather than dispatched blindly.
	 *
	 * @param mixed $url Candidate URL (cast to string).
	 * @return bool True only if safe to send.
	 */
	public static function is_safe( $url = '' ): bool {
		$url = (string) $url;
		if ( '' === $url || 0 !== stripos( $url, 'https://' ) || ! wp_http_validate_url( $url ) ) {
			return false;
		}

		$host = (string) wp_parse_url( $url, PHP_URL_HOST );
		if ( '' === $host ) {
			return false;
		}
		// A bracketed IPv6 literal arrives as "[::1]", strip the brackets.
		$host = trim( $host, '[]' );

		$candidates = self::resolve_candidates( $host );
		if ( empty( $candidates ) ) {
			return false; // Unresolvable host: fail closed.
		}

		foreach ( $candidates as $ip ) {
			if ( false === filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE ) ) {
				return false; // Private or reserved target: refuse.
			}
		}
		return true;
	}

	/**
	 * Resolve a host to every A and AAAA address we can vet.
	 *
	 * A literal IP is returned as-is. Otherwise both IPv4 (A) and IPv6 (AAAA)
	 * records are collected so a dual-stack host cannot smuggle a private IPv6
	 * target past an IPv4-only check.
	 *
	 * @param string $host Hostname or IP literal.
	 * @return string[] Candidate IP addresses (possibly empty).
	 */
	private static function resolve_candidates( string $host ): array {
		if ( filter_var( $host, FILTER_VALIDATE_IP ) ) {
			return array( $host );
		}

		$candidates = array();

		$a = gethostbynamel( $host ); // IPv4 A records, or false.
		if ( is_array( $a ) ) {
			$candidates = $a;
		}

		// AAAA records: dns_get_record may be unavailable/disabled on some
		// hosts; guard defensively and never let a lookup failure open the gate.
		if ( function_exists( 'dns_get_record' ) ) {
			// phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Network lookup may emit a warning on failure; treated as "no AAAA".
			$aaaa = @dns_get_record( $host, DNS_AAAA );
			if ( is_array( $aaaa ) ) {
				foreach ( $aaaa as $record ) {
					if ( ! empty( $record['ipv6'] ) ) {
						$candidates[] = (string) $record['ipv6'];
					}
				}
			}
		}

		return $candidates;
	}
}
