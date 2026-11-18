<?php
/**
 * Backup Codes implementation.
 *
 * 8 single-use codes generated on 2FA activation. Format: 8-char
 * alphanumeric with dash (e.g., a7x9-k2m4). Stored as bcrypt hashes
 * via wp_hash_password(). Each code is consumed on use.
 *
 * @package LoginArmor\TwoFactor
 * @since   2.2.0
 */

namespace LoginArmor\TwoFactor;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Backup codes handler.
 */
class BackupCodes {

	/** @var int Number of backup codes to generate. */
	public const CODE_COUNT = 8;

	/** @var string Characters used for code generation (lowercase + digits, no ambiguous). */
	private const ALPHABET = 'abcdefghjkmnpqrstuvwxyz23456789';

	/** @var string User meta key for stored hashed codes. */
	public const META_KEY = 'login_armor_2fa_backup_codes';

	/**
	 * Generate a new set of backup codes for a user.
	 *
	 * Replaces any existing codes. Returns the plain-text codes (shown once).
	 *
	 * @param int $user_id WordPress user ID.
	 * @return array<int,string> Array of 8 plain-text codes (format: xxxx-xxxx).
	 */
	public static function generate( int $user_id ): array {
		$prepared = self::prepare();
		self::store_hashes( $user_id, $prepared['hashes'] );
		return $prepared['codes'];
	}

	/**
	 * Prepare a code set without mutating the user's active recovery data.
	 *
	 * @return array{codes:array<int,string>,hashes:array<int,string>}
	 */
	public static function prepare(): array {
		$plain_codes  = [];
		$hashed_codes = [];

		for ( $i = 0; $i < self::CODE_COUNT; $i++ ) {
			$code           = self::generate_single_code();
			$plain_codes[]  = $code;
			$hashed_codes[] = wp_hash_password( self::normalize( $code ) );
		}

		return array( 'codes' => $plain_codes, 'hashes' => $hashed_codes );
	}

	/** Persist a previously prepared set of hashes. */
	public static function store_hashes( int $user_id, array $hashed_codes ): bool {
		$hashed_codes = array_values(
			array_filter(
				$hashed_codes,
				static fn( $hash ) => is_string( $hash ) && '' !== $hash
			)
		);
		if ( $user_id <= 0 || self::CODE_COUNT !== count( $hashed_codes ) ) {
			return false;
		}
		$current = get_user_meta( $user_id, self::META_KEY, true );
		if ( is_array( $current ) && array_values( $current ) === $hashed_codes ) {
			return true;
		}
		return false !== update_user_meta( $user_id, self::META_KEY, $hashed_codes );
	}

	/**
	 * Validate a backup code for a user.
	 *
	 * On success, the code is consumed (removed from stored hashes).
	 *
	 * @param int    $user_id WordPress user ID.
	 * @param string $code    The backup code entered by the user.
	 * @return bool True if the code is valid and was consumed.
	 */
	public static function validate( int $user_id, string $code ): bool {
		global $wpdb;

		// Read the exact serialized row so consuming a code can use a database
		// compare-and-swap. Two concurrent requests may validate the same hash,
		// but only one can replace this exact old value.
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Atomic single-use recovery code.
		$row = $wpdb->get_row(
			$wpdb->prepare(
				"SELECT umeta_id, meta_value FROM {$wpdb->usermeta} WHERE user_id = %d AND meta_key = %s ORDER BY umeta_id ASC LIMIT 1",
				$user_id,
				self::META_KEY
			)
		);
		if ( ! $row ) {
			return false;
		}
		$raw          = (string) $row->meta_value;
		$hashed_codes = maybe_unserialize( $raw );
		if ( ! is_array( $hashed_codes ) || empty( $hashed_codes ) ) {
			return false;
		}

		$normalized = self::normalize( $code );

		foreach ( $hashed_codes as $index => $hash ) {
			if ( is_string( $hash ) && wp_check_password( $normalized, $hash ) ) {
				// Consume the code.
				unset( $hashed_codes[ $index ] );
				$hashed_codes = array_values( $hashed_codes );
				$new_raw      = maybe_serialize( $hashed_codes );
				// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Conditional update is the single-use primitive.
				$consumed = (int) $wpdb->query(
				$wpdb->prepare(
					"UPDATE {$wpdb->usermeta} SET meta_value = %s WHERE umeta_id = %d AND BINARY meta_value = %s",
						$new_raw,
						(int) $row->umeta_id,
						$raw
					)
				);
				if ( 1 === $consumed ) {
					clean_user_cache( $user_id );
					return true;
				}
				return false;
			}
		}

		return false;
	}

	/**
	 * Get the number of remaining backup codes for a user.
	 *
	 * @param int $user_id WordPress user ID.
	 * @return int Number of remaining codes.
	 */
	public static function remaining( int $user_id ): int {
		$hashed_codes = get_user_meta( $user_id, self::META_KEY, true );
		if ( ! is_array( $hashed_codes ) ) {
			return 0;
		}
		return count( $hashed_codes );
	}

	/**
	 * Delete all backup codes for a user.
	 *
	 * @param int $user_id WordPress user ID.
	 */
	public static function delete( int $user_id ): void {
		delete_user_meta( $user_id, self::META_KEY );
	}

	/**
	 * Format backup codes as a downloadable text file content.
	 *
	 * @param array<int,string> $codes Plain-text codes.
	 * @return string Formatted text for download.
	 */
	public static function format_for_download( array $codes ): string {
		$site_name = get_bloginfo( 'name' );
		$lines     = [];
		$lines[]   = sprintf(
			/* translators: %s: site name */
			__( 'Login Armor Backup Codes: %s', 'login-armor' ),
			$site_name
		);
		$lines[] = str_repeat( '-', 40 );
		$lines[] = '';

		foreach ( $codes as $i => $code ) {
			$lines[] = sprintf( '%d. %s', $i + 1, $code );
		}

		$lines[] = '';
		$lines[] = __( 'Each code can only be used once.', 'login-armor' );
		$lines[] = __( 'Keep these codes in a safe place.', 'login-armor' );
		$lines[] = sprintf(
			/* translators: %s: date */
			__( 'Generated: %s', 'login-armor' ),
			gmdate( 'Y-m-d H:i:s' ) . ' UTC'
		);

		return implode( "\n", $lines );
	}

	// ── Private ─────────────────────────────────────────────────────

	/**
	 * Generate a single backup code in xxxx-xxxx format.
	 *
	 * @return string Backup code (e.g., "a7x9-k2m4").
	 */
	private static function generate_single_code(): string {
		$max  = strlen( self::ALPHABET ) - 1;
		$code = '';

		for ( $i = 0; $i < 8; $i++ ) {
			if ( $i === 4 ) {
				$code .= '-';
			}
			$code .= self::ALPHABET[ random_int( 0, $max ) ];
		}

		return $code;
	}

	/**
	 * Normalize a code for comparison: lowercase, strip dashes/spaces.
	 *
	 * @param string $code Raw user input.
	 * @return string Normalized code.
	 */
	private static function normalize( string $code ): string {
		return strtolower( preg_replace( '/[\s\-]/', '', $code ) );
	}
}
