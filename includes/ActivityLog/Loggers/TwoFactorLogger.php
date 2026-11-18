<?php
/**
 * Two-Factor Authentication activity logger.
 *
 * Tracks: 2fa_enabled, 2fa_disabled, 2fa_verified, 2fa_failed,
 * 2fa_backup_used, 2fa_reset_by_admin.
 *
 * @package LoginArmor\ActivityLog\Loggers
 * @since   2.2.0
 */

namespace LoginArmor\ActivityLog\Loggers;

use LoginArmor\ActivityLog\ActivityLogger;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Logger for 2FA events.
 */
class TwoFactorLogger extends ActivityLogger {

	public function get_key(): string {
		return '2fa';
	}

	public function get_label(): string {
		return 'Two-Factor';
	}

	public function register(): void {
		add_action( 'login_armor_2fa_user_enabled', [ $this, 'on_enabled' ], 10, 2 );
		add_action( 'login_armor_2fa_user_disabled', [ $this, 'on_disabled' ] );
		add_action( 'login_armor_2fa_verified', [ $this, 'on_verified' ], 10, 2 );
		add_action( 'login_armor_2fa_failed', [ $this, 'on_failed' ], 10, 3 );
		add_action( 'login_armor_2fa_backup_used', [ $this, 'on_backup_used' ], 10, 2 );
		add_action( 'login_armor_2fa_device_trusted', [ $this, 'on_device_trusted' ], 10, 2 );
		add_action( 'login_armor_2fa_device_revoked', [ $this, 'on_device_revoked' ], 10, 3 );
		add_action( 'login_armor_2fa_recovery_completed', [ $this, 'on_recovery_completed' ], 10, 2 );
		add_action( 'login_armor_2fa_enforcement_blocked', [ $this, 'on_enforcement_blocked' ] );
	}

	/**
	 * User enabled 2FA.
	 *
	 * @param int    $user_id WordPress user ID.
	 * @param string $method  Configured method.
	 */
	public function on_enabled( int $user_id, string $method ): void {
		$user = get_userdata( $user_id );
		if ( ! $user ) {
			return;
		}
		$method_label = match ( $method ) {
			'totp'  => 'Authenticator App',
			'email' => 'Email',
			default => $method,
		};
		$this->log(
			'2fa_enabled',
			'user',
			$user_id,
			$user->user_login,
			sprintf( '2FA enabled with %s.', $method_label ),
			$user_id
		);
	}

	/**
	 * User disabled 2FA.
	 *
	 * @param int $user_id WordPress user ID.
	 */
	public function on_disabled( int $user_id ): void {
		$user = get_userdata( $user_id );
		if ( ! $user ) {
			return;
		}
		$this->log(
			'2fa_disabled',
			'user',
			$user_id,
			$user->user_login,
			'2FA disabled.',
			$user_id
		);
	}

	/**
	 * Successful 2FA verification at login.
	 *
	 * Fires from TwoFactor::complete_login() before wp_set_auth_cookie(), so
	 * the explicit attribution is required: wp_get_current_user() still
	 * returns the anonymous user at this point.
	 *
	 * @param int    $user_id WordPress user ID.
	 * @param string $method  Method used.
	 */
	public function on_verified( int $user_id, string $method ): void {
		$user = get_userdata( $user_id );
		if ( ! $user ) {
			return;
		}
		$method_label = match ( $method ) {
			'totp'   => 'Authenticator App',
			'email'  => 'Email',
			'backup' => 'Backup code',
			default  => $method,
		};
		$this->log(
			'2fa_verified',
			'user',
			$user_id,
			$user->user_login,
			sprintf( '2FA verified via %s.', $method_label ),
			$user_id
		);
	}

	/**
	 * Failed 2FA verification.
	 *
	 * Same anonymous-context caveat as on_verified(): explicit user attribution.
	 *
	 * @param int    $user_id  WordPress user ID.
	 * @param string $method   Method attempted.
	 * @param int    $failures Consecutive failure count.
	 */
	public function on_failed( int $user_id, string $method, int $failures ): void {
		$user = get_userdata( $user_id );
		if ( ! $user ) {
			return;
		}
		$this->log(
			'2fa_failed',
			'user',
			$user_id,
			$user->user_login,
			sprintf( '2FA verification failed (attempt %d).', $failures ),
			$user_id
		);
	}

	/**
	 * Backup code used.
	 *
	 * Same anonymous-context caveat as on_verified(): explicit user attribution.
	 *
	 * @param int $user_id   WordPress user ID.
	 * @param int $remaining Number of remaining codes.
	 */
	public function on_backup_used( int $user_id, int $remaining ): void {
		$user = get_userdata( $user_id );
		if ( ! $user ) {
			return;
		}
		$this->log(
			'2fa_backup_used',
			'user',
			$user_id,
			$user->user_login,
			sprintf( 'Backup code used. %d remaining.', $remaining ),
			$user_id
		);
	}

	/**
	 * Trusted device granted. Fires during the 2FA verification flow, before
	 * the auth cookie is set: explicit user attribution required.
	 *
	 * @param int                                                                             $user_id WP user id.
	 * @param array{id:string,label:string,ip_at_grant:string,granted_at:int,expires_at:int}  $device  Device metadata.
	 */
	public function on_device_trusted( int $user_id, array $device ): void {
		$user = get_userdata( $user_id );
		if ( ! $user ) {
			return;
		}
		$this->log(
			'2fa_device_trusted',
			'user',
			$user_id,
			$user->user_login,
			sprintf(
				/* translators: 1: device label, 2: expiry date */
				'Trusted device granted: %1$s (expires %2$s).',
				$device['label'] ?? 'Unknown',
				wp_date( 'Y-m-d', (int) ( $device['expires_at'] ?? time() ) )
			),
			$user_id
		);
	}

	/**
	 * @param int                                                                             $user_id WP user id.
	 * @param array{id:string,label:string,ip_at_grant:string,granted_at:int,expires_at:int}  $device  Revoked device metadata.
	 * @param string                                                                          $source  'user' | 'admin' | 'auto'.
	 */
	public function on_device_revoked( int $user_id, array $device, string $source ): void {
		$user = get_userdata( $user_id );
		if ( ! $user ) {
			return;
		}
		// 'auto' = expiry/cleanup cron; 'admin' = back-office; 'user' = self-revoke
		// in profile. Only the 'user' source carries a logged-in session at this
		// point, so attribute explicitly to the device owner in all cases: the
		// log answers "whose device" first, "who revoked" via the description.
		$this->log(
			'2fa_device_revoked',
			'user',
			$user_id,
			$user->user_login,
			sprintf(
				/* translators: 1: device label, 2: revoke source */
				'Trusted device revoked: %1$s (by %2$s).',
				$device['label'] ?? 'Unknown',
				$source
			),
			$user_id
		);
	}

	/**
	 * A user was blocked at login for missing mandatory 2FA (grace expired).
	 *
	 * Fires from TwoFactor::intercept_login() before any auth cookie is set, so
	 * the anonymous-context caveat applies: explicit user attribution required.
	 *
	 * @param int $user_id WordPress user ID that was blocked.
	 */
	public function on_enforcement_blocked( $user_id = 0 ): void {
		$user_id = (int) $user_id;
		$user    = $user_id > 0 ? get_userdata( $user_id ) : false;
		if ( ! $user ) {
			return;
		}
		$this->log(
			'2fa_enforcement_blocked',
			'user',
			$user_id,
			$user->user_login,
			'Login blocked: mandatory 2FA not set up before the deadline.',
			$user_id
		);
	}

	/**
	 * Admin authorized a 2FA reset via the recovery flow.
	 *
	 * @param int $user_id  Target user id.
	 * @param int $admin_id Admin who authorized the reset.
	 */
	public function on_recovery_completed( int $user_id, int $admin_id ): void {
		$user  = get_userdata( $user_id );
		$admin = get_userdata( $admin_id );
		if ( ! $user || ! $admin ) {
			return;
		}
		// The admin is logged in when authorizing recovery: keep default
		// attribution (logged-in user = admin) so the log shows who acted.
		$this->log(
			'2fa_reset_via_recovery',
			'user',
			$user_id,
			$user->user_login,
			sprintf(
				/* translators: 1: admin login */
				'2FA reset via recovery flow (authorized by %1$s).',
				$admin->user_login
			)
		);
	}
}
