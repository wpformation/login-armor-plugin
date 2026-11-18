<?php
/**
 * Email OTP (One-Time Password) implementation.
 *
 * Sends a 6-digit numeric code via wp_mail(). Single-use, 10-minute expiry,
 * 60-second cooldown between resend requests.
 *
 * @package LoginArmor\TwoFactor
 * @since   2.2.0
 */

namespace LoginArmor\TwoFactor;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Email OTP method handler.
 */
class EmailOTP {

	/** @var int Code validity in seconds. */
	private const CODE_TTL = 600; // 10 minutes.

	/** @var int Cooldown between resend requests in seconds. */
	private const RESEND_COOLDOWN = 60;

	/** @var int Number of digits. */
	private const CODE_LENGTH = 6;

	/**
	 * Generate and send an OTP code to the user's email.
	 *
	 * @param int $user_id WordPress user ID.
	 * @return bool True if the email was sent successfully.
	 */
	public static function send_code( int $user_id ): bool {
		$user = get_userdata( $user_id );
		if ( ! $user ) {
			return false;
		}

		$code_key     = 'login_armor_email_otp_' . $user_id;
		$cooldown_key = 'login_armor_email_otp_cooldown_' . $user_id;

		// Every dispatch attempt consumes the cooldown, including a mail
		// transport failure. Otherwise an unavailable transport lets a caller
		// hammer wp_mail() continuously because the pending code is deleted.
		if ( get_transient( $cooldown_key ) ) {
			return false;
		}

		// Generate 6-digit code.
		$code = self::generate_code();

		// Store code as transient with TTL.
		set_transient( $code_key, wp_hash_password( $code ), self::CODE_TTL );

		// Set cooldown.
		set_transient( $cooldown_key, '1', self::RESEND_COOLDOWN );

		// Send email.
		$site_name = get_bloginfo( 'name' );
		$subject   = sprintf(
			/* translators: %s: site name */
			__( '[%s] Your login verification code', 'login-armor' ),
			$site_name
		);

		$message = sprintf(
			/* translators: 1: display name, 2: verification code, 3: minutes */
			__( "Hello %1\$s,\n\nYour verification code is: %2\$s\n\nThis code is valid for %3\$d minutes.\n\nIf you did not request this code, you can safely ignore this email.", 'login-armor' ),
			$user->display_name,
			$code,
			self::CODE_TTL / 60
		);

		$sent = wp_mail( $user->user_email, $subject, $message );
		if ( ! $sent ) {
			delete_transient( $code_key );
		}
		return (bool) $sent;
	}

	/**
	 * Validate an OTP code for a user.
	 *
	 * Code is single-use: deleted on successful validation.
	 *
	 * @param int    $user_id WordPress user ID.
	 * @param string $code    The 6-digit code entered by the user.
	 * @return bool True if the code is valid.
	 */
	public static function validate( int $user_id, string $code ): bool {
		if ( ! preg_match( '/^\d{6}$/', $code ) ) {
			return false;
		}

		$code_key    = 'login_armor_email_otp_' . $user_id;
		$stored_hash = get_transient( $code_key );

		if ( false === $stored_hash ) {
			return false;
		}

		if ( ! wp_check_password( $code, $stored_hash ) ) {
			return false;
		}

		// Single-use: only the request that actually deletes the pending value
		// succeeds. A concurrent validation of the same code is rejected.
		return (bool) delete_transient( $code_key );
	}

	/**
	 * Whether an unconsumed, unexpired OTP code is currently pending for a user.
	 *
	 * Lets callers (e.g. a method switch on the verification screen) decide
	 * whether a fresh code needs to be mailed, so a page refresh inside the
	 * resend cooldown is not mistaken for a delivery failure.
	 *
	 * @param int $user_id WordPress user ID.
	 * @return bool
	 */
	public static function has_pending_code( int $user_id ): bool {
		return false !== get_transient( 'login_armor_email_otp_' . $user_id );
	}

	/**
	 * Check if the resend cooldown is active for a user.
	 *
	 * @param int $user_id WordPress user ID.
	 * @return int Remaining cooldown seconds, 0 if not in cooldown.
	 */
	public static function get_cooldown_remaining( int $user_id ): int {
		$cooldown_key = 'login_armor_email_otp_cooldown_' . $user_id;
		$ttl          = get_transient( $cooldown_key );

		if ( false === $ttl ) {
			return 0;
		}

		// WordPress transients don't expose remaining TTL easily.
		// We store the expiry timestamp instead.
		return self::RESEND_COOLDOWN;
	}

	/**
	 * Generate a random 6-digit numeric code.
	 *
	 * @return string Zero-padded 6-digit code.
	 */
	private static function generate_code(): string {
		$code = random_int( 0, 999999 );
		return str_pad( (string) $code, self::CODE_LENGTH, '0', STR_PAD_LEFT );
	}
}
