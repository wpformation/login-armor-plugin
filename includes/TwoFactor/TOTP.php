<?php
/**
 * TOTP (Time-Based One-Time Password) implementation.
 *
 * Follows RFC 6238: HMAC-SHA1, 6-digit codes, 30-second time step.
 * Compatible with Google Authenticator, Authy, Microsoft Authenticator,
 * 1Password, Bitwarden.
 *
 * @package LoginArmor\TwoFactor
 * @since   2.2.0
 */

namespace LoginArmor\TwoFactor;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * TOTP method handler.
 */
class TOTP {

	/** @var int Number of digits in the OTP code. */
	private const DIGITS = 6;

	/** @var int Time step in seconds. */
	private const PERIOD = 30;

	/** @var int Number of bytes for the secret key. */
	private const SECRET_BYTES = 20;

	/** @var string Base32 alphabet. */
	private const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

	/**
	 * Generate a new random secret key.
	 *
	 * @return string Base32-encoded secret (32 characters).
	 */
	public static function generate_secret(): string {
		$bytes = random_bytes( self::SECRET_BYTES );
		return self::base32_encode( $bytes );
	}

	/**
	 * Build the otpauth:// URI for QR code generation.
	 *
	 * The account label is "login@host" (not just the login): in an
	 * authenticator holding dozens of sites, the entry is then searchable by
	 * domain and two sites with the same name (production / staging) stay
	 * distinguishable. Only new enrolments are affected; the secret and the
	 * TOTP parameters do not change.
	 *
	 * @since 2.6.0 Account label carries the host; both parts are filterable.
	 *
	 * @param string $secret     Base32-encoded secret.
	 * @param string $user_login WordPress user login.
	 * @param string $issuer     Issuer name (defaults to the site name).
	 * @param int    $user_id    Enrolling user, passed to the filters.
	 * @return string otpauth:// URI.
	 */
	public static function build_uri( string $secret, string $user_login, string $issuer = '', int $user_id = 0 ): string {
		if ( '' === $issuer ) {
			$issuer = (string) get_bloginfo( 'name' );
		}

		/**
		 * Filters the issuer shown by authenticator apps for this site.
		 *
		 * @since 2.6.0
		 *
		 * @param string $issuer  Issuer (default: site name).
		 * @param int    $user_id Enrolling user id.
		 */
		$issuer = (string) apply_filters( 'login_armor_totp_issuer', $issuer, $user_id );

		$host    = (string) wp_parse_url( home_url(), PHP_URL_HOST );
		$account = '' === $host ? $user_login : $user_login . '@' . $host;

		/**
		 * Filters the account label shown by authenticator apps.
		 *
		 * @since 2.6.0
		 *
		 * @param string $account    Account label (default: "login@host").
		 * @param string $user_login WordPress user login.
		 * @param string $host       Site host.
		 * @param int    $user_id    Enrolling user id.
		 */
		$account = (string) apply_filters( 'login_armor_totp_account_label', $account, $user_login, $host, $user_id );

		$label = rawurlencode( $issuer ) . ':' . rawurlencode( $account );

		return sprintf(
			'otpauth://totp/%s?secret=%s&issuer=%s&algorithm=SHA1&digits=%d&period=%d',
			$label,
			$secret,
			rawurlencode( $issuer ),
			self::DIGITS,
			self::PERIOD
		);
	}

	/**
	 * Validate a TOTP code against a secret.
	 *
	 * Allows a window of +/- 1 time step to account for clock drift.
	 *
	 * The matched time-step counter is written to `$matched_step` (by reference)
	 * on success so the caller can enforce single-use per time-step (RFC 6238
	 * §5.2): a code stays mathematically valid for the whole window, so without
	 * recording the last-accepted step the same code could be replayed on a
	 * second login within ~90s. `$matched_step` is left null on failure.
	 *
	 * @param string   $code         The 6-digit code entered by the user.
	 * @param string   $secret       Base32-encoded secret.
	 * @param int|null $matched_step Out: the accepted time-step counter, or null.
	 * @return bool True if the code is valid.
	 */
	public static function validate( string $code, string $secret, ?int &$matched_step = null ): bool {
		$matched_step = null;

		if ( ! preg_match( '/^\d{6}$/', $code ) ) {
			return false;
		}

		$binary_secret = self::base32_decode( $secret );
		if ( false === $binary_secret ) {
			return false;
		}

		$timestamp   = time();
		$code_int    = (int) $code;

		// Check current time step and +/- 1 window.
		for ( $offset = -1; $offset <= 1; $offset++ ) {
			$time_counter = (int) floor( ( $timestamp / self::PERIOD ) + $offset );
			$expected     = self::compute_otp( $binary_secret, $time_counter );
			if ( hash_equals( str_pad( (string) $expected, 6, '0', STR_PAD_LEFT ), str_pad( (string) $code_int, 6, '0', STR_PAD_LEFT ) ) ) {
				$matched_step = $time_counter;
				return true;
			}
		}

		return false;
	}

	/**
	 * Encrypt a TOTP secret for storage in user meta.
	 *
	 * Uses AES-256-CBC keyed on AUTH_KEY when it is defined (the normal case),
	 * falling back to wp_salt('auth') when the host's wp-config.php does not
	 * define AUTH_KEY. See encryption_key() for why the fallback exists.
	 *
	 * @param string $secret Plain Base32 secret.
	 * @return string Base64-encoded encrypted string (iv:ciphertext).
	 */
	public static function encrypt_secret( string $secret ): string {
		$key    = self::encryption_key();
		$iv     = random_bytes( 16 );
		$cipher = openssl_encrypt( $secret, 'aes-256-cbc', $key, OPENSSL_RAW_DATA, $iv );

		// openssl_encrypt returns false on cipher/key failure. Concatenating
		// false with the IV would silently produce a garbage base64 string
		// that later decrypts into junk. Fail loud instead.
		if ( false === $cipher ) {
			return '';
		}

		return base64_encode( $iv . $cipher );
	}

	/**
	 * Decrypt a stored TOTP secret.
	 *
	 * @param string $encrypted Base64-encoded encrypted string.
	 * @return string|false Plain Base32 secret or false on failure.
	 */
	public static function decrypt_secret( string $encrypted ): string|false {
		$data = base64_decode( $encrypted, true );
		if ( false === $data || strlen( $data ) < 17 ) {
			return false;
		}

		$key    = self::encryption_key();
		$iv     = substr( $data, 0, 16 );
		$cipher = substr( $data, 16 );

		$decrypted = openssl_decrypt( $cipher, 'aes-256-cbc', $key, OPENSSL_RAW_DATA, $iv );

		return $decrypted;
	}

	// ── Private ─────────────────────────────────────────────────────

	/**
	 * Derive the 32-byte AES key used to encrypt/decrypt the TOTP secret.
	 *
	 * Prefers WordPress AUTH_KEY (the original keying material, so secrets
	 * stored by earlier versions still decrypt unchanged). Some hosts ship a
	 * wp-config.php that never defines AUTH_KEY: there, referencing the bare
	 * constant raised "Uncaught Error: Undefined constant ...AUTH_KEY" and the
	 * whole setup AJAX returned HTTP 500 ("network error" in the UI). In that
	 * case fall back to wp_salt('auth'), which WordPress always resolves (it
	 * persists a generated salt when the constant is absent) and which the rest
	 * of this plugin already uses for its HMAC keys. Reported on locationcantin.fr
	 * (Infomaniak) 2026-06-11.
	 *
	 * @return string Raw 32-byte key.
	 */
	private static function encryption_key(): string {
		$material = ( defined( 'AUTH_KEY' ) && '' !== AUTH_KEY ) ? AUTH_KEY : wp_salt( 'auth' );
		return hash( 'sha256', $material, true );
	}

	/**
	 * Compute a single TOTP code for a given time counter.
	 *
	 * @param string $secret Binary secret key.
	 * @param int    $counter Time counter value.
	 * @return int The OTP as an integer.
	 */
	private static function compute_otp( string $secret, int $counter ): int {
		// Pack counter as 8-byte big-endian.
		$counter_bytes = pack( 'N*', 0, $counter );

		// HMAC-SHA1.
		$hash = hash_hmac( 'sha1', $counter_bytes, $secret, true );

		// Dynamic truncation (RFC 4226 section 5.4).
		$offset = ord( $hash[19] ) & 0x0F;
		$binary = (
			( ( ord( $hash[ $offset ] ) & 0x7F ) << 24 ) |
			( ( ord( $hash[ $offset + 1 ] ) & 0xFF ) << 16 ) |
			( ( ord( $hash[ $offset + 2 ] ) & 0xFF ) << 8 ) |
			( ord( $hash[ $offset + 3 ] ) & 0xFF )
		);

		return $binary % ( 10 ** self::DIGITS );
	}

	/**
	 * Encode binary data to Base32.
	 *
	 * @param string $data Binary data.
	 * @return string Base32-encoded string.
	 */
	private static function base32_encode( string $data ): string {
		$binary = '';
		foreach ( str_split( $data ) as $char ) {
			$binary .= str_pad( decbin( ord( $char ) ), 8, '0', STR_PAD_LEFT );
		}

		$result = '';
		$chunks = str_split( $binary, 5 );
		foreach ( $chunks as $chunk ) {
			$chunk   = str_pad( $chunk, 5, '0', STR_PAD_RIGHT );
			$result .= self::BASE32_ALPHABET[ bindec( $chunk ) ];
		}

		return $result;
	}

	/**
	 * Decode a Base32-encoded string to binary.
	 *
	 * @param string $encoded Base32 string.
	 * @return string|false Binary data or false on invalid input.
	 */
	private static function base32_decode( string $encoded ): string|false {
		$encoded = strtoupper( $encoded );
		$encoded = rtrim( $encoded, '=' );

		if ( preg_match( '/[^A-Z2-7]/', $encoded ) ) {
			return false;
		}

		$binary = '';
		foreach ( str_split( $encoded ) as $char ) {
			$index  = strpos( self::BASE32_ALPHABET, $char );
			$binary .= str_pad( decbin( $index ), 5, '0', STR_PAD_LEFT );
		}

		$result = '';
		$bytes  = str_split( $binary, 8 );
		foreach ( $bytes as $byte ) {
			if ( strlen( $byte ) < 8 ) {
				break;
			}
			$result .= chr( bindec( $byte ) );
		}

		return $result;
	}
}
