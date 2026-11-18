<?php
/**
 * Abstract base class for activity loggers.
 *
 * Each concrete logger extends this class, implements register() to hook
 * into WordPress actions, and calls $this->log() to record events.
 *
 * @package LoginArmor\ActivityLog
 * @since   2.1.0
 */

namespace LoginArmor\ActivityLog;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Base activity logger.
 */
abstract class ActivityLogger {

	/**
	 * Get the logger key (slug used in object_type column).
	 *
	 * @return string e.g. 'user', 'post', 'media', 'plugin', 'theme', 'option'
	 */
	abstract public function get_key(): string;

	/**
	 * Get the human-readable label.
	 *
	 * @return string e.g. 'Users', 'Posts', 'Media'
	 */
	abstract public function get_label(): string;

	/**
	 * Register WordPress hooks for this logger.
	 */
	abstract public function register(): void;

	/**
	 * Record an activity log entry.
	 *
	 * The shared chain service persists the row before finalizing its hashes.
	 * Under normal load it is signed in the same request. Under lock contention
	 * it remains as a visible orphan for the repair cron instead of being lost.
	 * The `login_armor_activity_logged` hook notifies WebhookDispatcher only
	 * after this request has observed the finalized hashes.
	 *
	 * @since 2.1.0
	 * @since 2.1.16 Added `$explicit_user_id` parameter. Loggers can now
	 *               attribute an entry to a specific user even when the
	 *               request runs in an anonymous context (2FA verification
	 *               before auth cookies are set, self-registration on the
	 *               frontend, password reset via Lost Password flow…).
	 *               When null (default), the historical guard on
	 *               `wp_get_current_user()->exists()` still applies, so
	 *               WP-Cron and other system contexts keep being filtered
	 *               out unless a logger explicitly opts in.
	 *
	 * @param string   $action           Action slug (e.g. 'post_updated', 'user_deleted').
	 * @param string   $object_type      Object type (e.g. 'post', 'user', 'media').
	 * @param int      $object_id        Object ID (post ID, user ID, etc.). 0 if n/a.
	 * @param string   $object_name      Human-readable name (post title, plugin name, etc.).
	 * @param string   $description      Human-readable summary of what happened.
	 * @param int|null $explicit_user_id Force attribution to this user id regardless of
	 *                                   the current authentication state. Null = use the
	 *                                   logged-in user, drop the entry if none.
	 */
	protected function log(
		string $action,
		string $object_type,
		int $object_id = 0,
		string $object_name = '',
		string $description = '',
		?int $explicit_user_id = null
	): void {
		if ( null !== $explicit_user_id && $explicit_user_id > 0 ) {
			$user = get_userdata( $explicit_user_id );
			if ( ! $user ) {
				return;
			}
			$user_id    = $user->ID;
			$user_login = $user->user_login;
			$roles      = $user->roles;
			$user_role  = ! empty( $roles ) ? reset( $roles ) : '';
		} else {
			$current_user = wp_get_current_user();
			if ( ! $current_user->exists() ) {
				return;
			}
			$user_id    = $current_user->ID;
			$user_login = $current_user->user_login;
			$roles      = $current_user->roles;
			$user_role  = ! empty( $roles ) ? reset( $roles ) : '';
		}

		$row_data = [
			'user_id'     => $user_id,
			'user_login'  => $user_login,
			'user_role'   => $user_role,
			'action'      => $action,
			'object_type' => $object_type,
			'object_id'   => $object_id,
			'object_name' => mb_substr( $object_name, 0, 255 ),
			'description' => $description,
			'ip'          => \LoginArmor\LoginArmor::get_client_ip(),
			'log_time'    => gmdate( 'Y-m-d H:i:s' ),
			'prev_hash'   => null,
			'row_hash'    => null,
		];
		self::append_row( $row_data, true );
	}

	/**
	 * Append an internal system event without enqueueing another webhook.
	 */
	public static function log_system( string $action, string $object_name, string $description ): void {
		$row_data = array(
			'user_id'     => 0,
			'user_login'  => 'system',
			'user_role'   => 'system',
			'action'      => $action,
			'object_type' => 'system',
			'object_id'   => 0,
			'object_name' => mb_substr( $object_name, 0, 255 ),
			'description' => $description,
			'ip'          => '',
			'log_time'    => gmdate( 'Y-m-d H:i:s' ),
			'prev_hash'   => null,
			'row_hash'    => null,
		);
		self::append_row( $row_data, false );
	}

	/**
	 * Persist and append one activity row.
	 *
	 * ActivityLog::append_row() orders placeholder insertion before chain work.
	 * A process that cannot acquire the lock still records its row at the tail,
	 * where the repair cron can sign it without creating a fork.
	 *
	 * @param array<string,mixed> $row_data Canonical activity columns.
	 * @param bool                $dispatch Whether to notify the webhook queue.
	 */
	private static function append_row( array $row_data, bool $dispatch ): void {
		$stored = ActivityLog::append_row( $row_data );
		if ( false === $stored ) {
			return;
		}
		if ( empty( $stored['row_hash'] ) || empty( $stored['prev_hash'] ) ) {
			do_action( 'login_armor_activity_log_contention', $stored );
			return;
		}
		if ( $dispatch ) {
			do_action( 'login_armor_activity_logged', $stored );
		}
	}
}
