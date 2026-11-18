<?php
/**
 * User activity logger.
 *
 * Tracks: user_created, user_deleted, user_role_changed, user_email_changed, user_password_changed.
 *
 * @package LoginArmor\ActivityLog\Loggers
 * @since   2.1.0
 */

namespace LoginArmor\ActivityLog\Loggers;

use LoginArmor\ActivityLog\ActivityLogger;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class UserLogger extends ActivityLogger {

	public function get_key(): string {
		return 'user';
	}

	public function get_label(): string {
		return 'Users';
	}

	public function register(): void {
		add_action( 'user_register', [ $this, 'on_user_register' ] );
		add_action( 'deleted_user', [ $this, 'on_user_deleted' ], 10, 3 );
		add_action( 'set_user_role', [ $this, 'on_role_changed' ], 10, 3 );
		add_action( 'profile_update', [ $this, 'on_profile_update' ], 10, 3 );
		// Lost Password flow uses wp_set_password() directly, NOT wp_update_user(),
		// so profile_update never fires: `after_password_reset` is the only
		// reliable signal for password changes via the recovery email link.
		// (V2.1.16: the anti-gravity audit mis-identified profile_update as the
		// fired hook; even fixing the exists() guard wouldn't catch this flow.)
		add_action( 'after_password_reset', [ $this, 'on_after_password_reset' ] );
	}

	// All hook callbacks below are untyped with defaults: user-lifecycle
	// hooks (`user_register`, `profile_update`, `set_user_role`,
	// `deleted_user`) are re-fired by import/migration/membership plugins
	// with degraded arity or types; strict hints would fatal those flows.

	public function on_user_register( $user_id = 0 ): void {
		$user_id = (int) $user_id;
		$user    = $user_id > 0 ? get_userdata( $user_id ) : false;
		if ( ! $user ) {
			return;
		}
		// Self-registration on the frontend (WooCommerce my-account, native
		// `/wp-login.php?action=register`, MemberPress, etc.) runs anonymous:
		// without explicit attribution the entry would be dropped by the base
		// logger's exists() guard. Attribute the creation to the user that was
		// just created; the description still tells "what" happened.
		$this->log(
			'user_created',
			'user',
			$user_id,
			$user->user_login,
			sprintf( 'New user "%s" created with role "%s".', $user->user_login, implode( ', ', $user->roles ) ),
			$user_id
		);
	}

	public function on_user_deleted( $user_id = 0, $reassign = null, $user = null ): void {
		if ( ! $user instanceof \WP_User ) {
			return;
		}
		$this->log(
			'user_deleted',
			'user',
			(int) $user_id,
			$user->user_login,
			sprintf( 'User "%s" deleted.', $user->user_login )
		);
	}

	public function on_role_changed( $user_id = 0, $new_role = '', $old_roles = array() ): void {
		$user_id = (int) $user_id;
		$user    = $user_id > 0 ? get_userdata( $user_id ) : false;
		if ( ! $user || ! is_string( $new_role ) ) {
			return;
		}
		$old_roles = is_array( $old_roles ) ? $old_roles : array();
		$old       = ! empty( $old_roles ) ? implode( ', ', $old_roles ) : 'none';
		$this->log(
			'user_role_changed',
			'user',
			$user_id,
			$user->user_login,
			sprintf( 'Role changed from "%s" to "%s".', $old, $new_role )
		);
	}

	public function on_profile_update( $user_id = 0, $old_user_data = null, $userdata = array() ): void {
		$user_id = (int) $user_id;
		if ( $user_id <= 0 || ! $old_user_data instanceof \WP_User ) {
			return; // Without the old user object no change can be diffed.
		}
		$userdata = is_array( $userdata ) ? $userdata : array();
		$user     = get_userdata( $user_id );
		if ( ! $user ) {
			return;
		}

		// Detect the "Lost Password" flow (wp-login.php?action=resetpass):
		// at this point the user is NOT logged in yet, but `password_reset`
		// fires immediately before WP calls `wp_update_user()`, so checking
		// did_action() is the most reliable hook-order-based signal. Same
		// reasoning for `user_register` followed by profile update from a
		// frontend form: caller is anonymous and we must attribute explicitly.
		$is_password_reset = did_action( 'password_reset' ) > 0;
		$attribution       = ( $is_password_reset || ! is_user_logged_in() ) ? $user_id : null;

		if ( $old_user_data->user_email !== $user->user_email ) {
			$this->log(
				'user_email_changed',
				'user',
				$user_id,
				$user->user_login,
				sprintf( 'Email changed from "%s" to "%s".', $old_user_data->user_email, $user->user_email ),
				$attribution
			);
		}

		if ( isset( $userdata['user_pass'] ) && $userdata['user_pass'] !== $old_user_data->user_pass ) {
			$this->log(
				'user_password_changed',
				'user',
				$user_id,
				$user->user_login,
				'Password changed.',
				$attribution
			);
		}
	}

	/**
	 * Log a password change made through the Lost Password recovery flow.
	 *
	 * Fires after WordPress core has updated the password and cleared the
	 * activation key. Anonymous context: the user is not logged in at this
	 * point, so explicit attribution to the reset user is required.
	 *
	 * @since 2.1.16
	 *
	 * Parameter untyped with a guard: a third-party plugin re-firing
	 * `after_password_reset` may pass a user ID or null rather than a WP_User.
	 * A strict hint would fatal the reset flow.
	 *
	 * @param mixed $user User whose password was reset (expected WP_User).
	 */
	public function on_after_password_reset( $user = null ): void {
		if ( ! $user instanceof \WP_User ) {
			return;
		}
		$this->log(
			'user_password_changed',
			'user',
			$user->ID,
			$user->user_login,
			'Password changed via Lost Password recovery flow.',
			$user->ID
		);
	}
}
