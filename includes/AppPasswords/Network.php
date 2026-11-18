<?php
/**
 * Network identity of an address (2.9.0).
 *
 * "Which hosting provider is this?", answered without a third-party service
 * first. A front end hosted on a cloud changes its outgoing address all the
 * time: Vercel, on AWS, spreads over a great many /24 ranges, and AWS
 * announces them under several AS numbers (AS16509, AS14618). Their reverse
 * names all end in amazonaws.com. So the order is:
 *
 *  1. confirmed reverse DNS: the reverse name of the address, whose forward
 *     lookup must give the address back (anyone can write a PTR record, nobody
 *     can point amazonaws.com at their own address), reduced to its
 *     registrable domain;
 *  2. the AS number, when the administrator has switched geolocation on;
 *  3. the /24 (IPv4) or /48 (IPv6) range.
 *
 * Everything but reverse_domain() is pure, and reverse_domain() takes its two
 * resolvers from the system unless the login_armor_reverse_dns filter answers
 * first (the CI does, so the runs never depend on a resolver).
 *
 * @package LoginArmor
 * @since   2.9.0
 */

namespace LoginArmor\AppPasswords;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Hosting-provider identity of an IP address.
 */
final class Network {

	/**
	 * Second-level labels that sit under a country code (co.uk, com.au).
	 * No public suffix list: a name this rule ranges badly gives one alert too
	 * many, which "Approve this network" settles.
	 */
	public const SHORT_SECOND_LEVELS = array( 'co', 'com', 'net', 'org', 'gov', 'ac', 'edu', 'ne', 'or' );

	/**
	 * Registrable domain of a host name, '' when it is not one.
	 */
	public static function registrable_domain( string $host ): string {
		$host = strtolower( rtrim( trim( $host ), '.' ) );
		if ( '' === $host || false !== filter_var( $host, FILTER_VALIDATE_IP ) ) {
			return '';
		}
		$labels = explode( '.', $host );
		$count  = count( $labels );
		if ( $count < 2 ) {
			return '';
		}
		foreach ( $labels as $label ) {
			if ( 1 !== preg_match( '/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/', $label ) ) {
				return '';
			}
		}
		$take = 2;
		if ( $count >= 3 && 2 === strlen( $labels[ $count - 1 ] ) && in_array( $labels[ $count - 2 ], self::SHORT_SECOND_LEVELS, true ) ) {
			$take = 3;
		}
		return implode( '.', array_slice( $labels, -$take ) );
	}

	/**
	 * An IPv4-mapped IPv6 address (::ffff:a.b.c.d, what a dual-stack listener
	 * reports) as the plain IPv4 address; anything else unchanged.
	 */
	private static function unmap( string $ip ): string {
		if ( false === filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6 ) ) {
			return $ip;
		}
		$packed = inet_pton( $ip );
		if ( false === $packed || 16 !== strlen( $packed ) || str_repeat( "\0", 10 ) . "\xff\xff" !== substr( $packed, 0, 12 ) ) {
			return $ip;
		}
		$v4 = inet_ntop( substr( $packed, 12 ) );
		return false === $v4 ? $ip : $v4;
	}

	/**
	 * The /24 or /48 an address belongs to, '' for anything else.
	 */
	public static function range_of( string $ip ): string {
		$ip = self::unmap( $ip );
		if ( false !== filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 ) ) {
			$parts = explode( '.', $ip );
			return $parts[0] . '.' . $parts[1] . '.' . $parts[2] . '.0/24';
		}
		if ( false !== filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6 ) ) {
			$packed = inet_pton( $ip );
			if ( false === $packed ) {
				return '';
			}
			$prefix = inet_ntop( substr( $packed, 0, 6 ) . str_repeat( "\0", 10 ) );
			return false === $prefix ? '' : $prefix . '/48';
		}
		return '';
	}

	/**
	 * Registrable domain of an address's reverse name, when the forward lookup
	 * of that name gives the address back; '' otherwise.
	 *
	 * @param string   $ip      The address.
	 * @param callable $reverse ip => host name, or the ip itself / false when there is none (gethostbyaddr()).
	 * @param callable $forward host name => list of addresses.
	 */
	public static function confirmed_domain( string $ip, callable $reverse, callable $forward ): string {
		$ip   = self::unmap( $ip );
		$want = filter_var( $ip, FILTER_VALIDATE_IP ) ? inet_pton( $ip ) : false;
		if ( false === $want ) {
			return '';
		}
		$host = $reverse( $ip );
		if ( ! is_string( $host ) || '' === $host || $host === $ip ) {
			return '';
		}
		foreach ( (array) $forward( $host ) as $address ) {
			if ( is_string( $address ) && false !== filter_var( $address, FILTER_VALIDATE_IP ) && inet_pton( $address ) === $want ) {
				return self::registrable_domain( $host );
			}
		}
		return '';
	}

	/**
	 * Confirmed reverse domain of an address, with the system resolver.
	 *
	 * PHP's DNS functions take no timeout: the caller bounds how many of these
	 * it runs (Review::run()).
	 */
	public static function reverse_domain( string $ip ): string {
		/**
		 * Short-circuit the reverse DNS step.
		 *
		 * Return a host name or a registrable domain to use it, '' for "no
		 * confirmed name", or null to keep the system resolver.
		 *
		 * @since 2.9.0
		 *
		 * @param string|null $pre Pre-resolved name, or null.
		 * @param string      $ip  The address.
		 */
		$pre = apply_filters( 'login_armor_reverse_dns', null, $ip );
		if ( is_string( $pre ) ) {
			return self::registrable_domain( $pre );
		}
		if ( ! function_exists( 'gethostbyaddr' ) || ! function_exists( 'dns_get_record' ) ) {
			return '';
		}
		return self::confirmed_domain(
			$ip,
			static fn( string $address ) => gethostbyaddr( $address ),
			static function ( string $host ): array {
				// dns_get_record() warns and returns false on NXDOMAIN, SERVFAIL or timeout, and the reverse name is chosen by the owner of the address.
				$records = @dns_get_record( $host, DNS_A | DNS_AAAA ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- A failed lookup means "not confirmed", handled below.
				$found   = array();
				foreach ( is_array( $records ) ? $records : array() as $record ) {
					if ( isset( $record['ip'] ) ) {
						$found[] = (string) $record['ip'];
					}
					if ( isset( $record['ipv6'] ) ) {
						$found[] = (string) $record['ipv6'];
					}
				}
				return $found;
			}
		);
	}

	/**
	 * Identity of an address, from what the caller already resolved.
	 *
	 * @param string                                       $ip     The address.
	 * @param string                                       $domain Confirmed registrable domain, '' when none.
	 * @param array{asn?:int,org?:string,code?:string}|null $geo    GeoIP::cached_network(), null when unknown.
	 * @return array{network:string,label:string,country:string}
	 */
	public static function identity( string $ip, string $domain, ?array $geo ): array {
		$country = is_array( $geo ) ? (string) ( $geo['code'] ?? '' ) : '';
		$org     = is_array( $geo ) ? (string) ( $geo['org'] ?? '' ) : '';
		$asn     = is_array( $geo ) ? (int) ( $geo['asn'] ?? 0 ) : 0;

		// The key is stored in an 80-character column: a longer domain falls
		// back to the AS number or the range rather than being cut, which
		// would merge two domains.
		if ( '' !== $domain && strlen( 'dns:' . $domain ) <= 80 ) {
			return array(
				'network' => 'dns:' . $domain,
				'label'   => '' !== $org ? $domain . ' (' . $org . ')' : $domain,
				'country' => $country,
			);
		}
		if ( $asn > 0 ) {
			return array(
				'network' => 'as:' . $asn,
				'label'   => '' !== $org ? $org . ' (AS' . $asn . ')' : 'AS' . $asn,
				'country' => $country,
			);
		}
		$range = self::range_of( $ip );
		return array(
			'network' => 'net:' . $range,
			'label'   => $range,
			'country' => $country,
		);
	}
}
