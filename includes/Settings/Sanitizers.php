<?php
/**
 * Pure, typed sanitizers for the settings transfer (export / import).
 *
 * Unlike the inline validation in the AJAX handlers, which clamps or falls
 * back silently because it only ever sees values produced by the plugin's own
 * form, these reject: an imported file is untrusted input written by hand or
 * by another site, and a silently clamped value would be applied to sixty
 * sites at once. Every method returns the normalized value or a \WP_Error.
 *
 * @package LoginArmor\Settings
 * @since   2.6.0
 */

namespace LoginArmor\Settings;

use LoginArmor\LoginArmor;
use LoginArmor\Support\SafeUrl;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Sanitizers {

	/** Longest list accepted for any multi-line setting (mirrors Firewall::sanitize_lines). */
	public const MAX_LIST = 200;

	/**
	 * Strict boolean: true/false, 0/1, "0"/"1", "true"/"false".
	 */
	public static function bool( mixed $value ): bool|\WP_Error {
		if ( is_bool( $value ) ) {
			return $value;
		}
		if ( is_int( $value ) && ( 0 === $value || 1 === $value ) ) {
			return 1 === $value;
		}
		if ( is_string( $value ) ) {
			$lower = strtolower( trim( $value ) );
			if ( in_array( $lower, array( '1', 'true' ), true ) ) {
				return true;
			}
			if ( in_array( $lower, array( '0', 'false' ), true ) ) {
				return false;
			}
		}
		return self::error( __( 'expected true or false', 'login-armor' ) );
	}

	/**
	 * Integer inside [min, max]. Numeric strings accepted, nothing else.
	 */
	public static function int_range( mixed $value, int $min, int $max ): int|\WP_Error {
		if ( is_bool( $value ) || ( ! is_int( $value ) && ! ( is_string( $value ) && preg_match( '/^-?[0-9]+$/', trim( $value ) ) ) ) ) {
			return self::error( __( 'expected an integer', 'login-armor' ) );
		}
		$int = (int) $value;
		if ( $int < $min || $int > $max ) {
			return self::error( sprintf( /* translators: 1: minimum, 2: maximum */ __( 'expected an integer between %1$d and %2$d', 'login-armor' ), $min, $max ) );
		}
		return $int;
	}

	/**
	 * One of the allowed strings, case-sensitive. ip_method values are
	 * uppercase on purpose and must never be folded.
	 *
	 * @param string[] $allowed
	 */
	public static function enum( mixed $value, array $allowed ): string|\WP_Error {
		if ( is_string( $value ) && in_array( $value, $allowed, true ) ) {
			return $value;
		}
		return self::error( __( 'expected one of: ', 'login-armor' ) . implode( ', ', $allowed ) );
	}

	/**
	 * One of the allowed integers.
	 *
	 * @param int[] $allowed
	 */
	public static function enum_int( mixed $value, array $allowed ): int|\WP_Error {
		$int = self::int_range( $value, PHP_INT_MIN, PHP_INT_MAX );
		if ( is_wp_error( $int ) ) {
			return $int;
		}
		if ( ! in_array( $int, $allowed, true ) ) {
			return self::error( __( 'expected one of: ', 'login-armor' ) . implode( ', ', array_map( 'strval', $allowed ) ) );
		}
		return $int;
	}

	/**
	 * Plain text, single line.
	 */
	public static function text( mixed $value, int $max_length = 255 ): string|\WP_Error {
		if ( ! is_scalar( $value ) ) {
			return self::error( __( 'expected text', 'login-armor' ) );
		}
		return mb_substr( sanitize_text_field( (string) $value ), 0, $max_length );
	}

	/**
	 * Empty string or a valid e-mail address.
	 */
	public static function email( mixed $value ): string|\WP_Error {
		if ( ! is_string( $value ) ) {
			return self::error( __( 'expected an e-mail address', 'login-armor' ) );
		}
		if ( '' === trim( $value ) ) {
			return '';
		}
		$clean = sanitize_email( $value );
		if ( '' === $clean ) {
			return self::error( __( 'expected a valid e-mail address', 'login-armor' ) );
		}
		return $clean;
	}

	/**
	 * An https:// URL (or empty when allowed).
	 */
	public static function https_url( mixed $value, bool $allow_empty = true ): string|\WP_Error {
		if ( ! is_string( $value ) ) {
			return self::error( __( 'expected a URL', 'login-armor' ) );
		}
		$value = trim( $value );
		if ( '' === $value ) {
			return $allow_empty ? '' : self::error( __( 'a URL is required', 'login-armor' ) );
		}
		if ( ! str_starts_with( $value, 'https://' ) ) {
			return self::error( __( 'URL must start with https://', 'login-armor' ) );
		}
		$clean = esc_url_raw( $value );
		if ( '' === $clean || $clean !== $value ) {
			return self::error( __( 'expected a valid https:// URL', 'login-armor' ) );
		}
		return $clean;
	}

	/**
	 * An https:// URL that passes the SSRF policy (fail-closed, resolves DNS).
	 */
	public static function webhook_url( mixed $value ): string|\WP_Error {
		$url = self::https_url( $value, false );
		if ( is_wp_error( $url ) ) {
			return $url;
		}
		if ( ! SafeUrl::is_safe( $url ) ) {
			return self::error( __( 'URL must not point to a private, reserved or unresolvable address', 'login-armor' ) );
		}
		return $url;
	}

	/**
	 * List of valid IP addresses, trimmed, unique, junk dropped.
	 *
	 * @return string[]|\WP_Error
	 */
	public static function ip_list( mixed $value ): array|\WP_Error {
		$list = self::string_list( $value );
		if ( is_wp_error( $list ) ) {
			return $list;
		}
		$out = array();
		foreach ( $list as $entry ) {
			if ( filter_var( $entry, FILTER_VALIDATE_IP ) && ! in_array( $entry, $out, true ) ) {
				$out[] = $entry;
			}
		}
		return $out;
	}

	/**
	 * List of valid IPs or CIDR ranges (the trusted-proxies grammar).
	 *
	 * @return string[]|\WP_Error
	 */
	public static function cidr_list( mixed $value ): array|\WP_Error {
		$list = self::string_list( $value );
		if ( is_wp_error( $list ) ) {
			return $list;
		}
		$normalized = LoginArmor::normalize_trusted_proxies( implode( "\n", $list ) );
		return '' === $normalized ? array() : explode( "\n", $normalized );
	}

	/**
	 * List of non-empty single-line strings, trimmed, unique, capped.
	 *
	 * @return string[]|\WP_Error
	 */
	public static function string_list( mixed $value ): array|\WP_Error {
		if ( ! is_array( $value ) ) {
			return self::error( __( 'expected a list', 'login-armor' ) );
		}
		$out = array();
		foreach ( $value as $entry ) {
			if ( ! is_scalar( $entry ) ) {
				return self::error( __( 'expected a list of strings', 'login-armor' ) );
			}
			$entry = sanitize_text_field( (string) $entry );
			if ( '' !== $entry && ! in_array( $entry, $out, true ) ) {
				$out[] = $entry;
			}
		}
		return array_slice( $out, 0, self::MAX_LIST );
	}

	/**
	 * Members of $value that belong to $allowed, in the order given.
	 *
	 * @param string[] $allowed
	 * @return string[]|\WP_Error
	 */
	public static function subset( mixed $value, array $allowed ): array|\WP_Error {
		$list = self::string_list( $value );
		if ( is_wp_error( $list ) ) {
			return $list;
		}
		return array_values( array_intersect( $list, $allowed ) );
	}

	private static function error( string $message ): \WP_Error {
		return new \WP_Error( 'login_armor_settings_invalid', $message );
	}
}
