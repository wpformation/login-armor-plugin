<?php
/**
 * Settings transfer activity logger.
 *
 * Records a settings import (admin upload or WP-CLI). Unlike the other
 * loggers it is not hook-driven for that: the Importer calls it directly,
 * because when the import itself just switched the Activity Log on, no logger
 * was wired at plugins_loaded in that request. Since 2.7.9 it also records a
 * reset of the detection data, through login_armor_data_reset.
 *
 * @package LoginArmor\ActivityLog\Loggers
 * @since   2.6.0
 */

namespace LoginArmor\ActivityLog\Loggers;

use LoginArmor\ActivityLog\ActivityLogger;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class SettingsLogger extends ActivityLogger {

	public function get_key(): string {
		return 'settings';
	}

	public function get_label(): string {
		return 'Settings';
	}

	/**
	 * Nothing to hook: see the class docblock.
	 */
	public function register(): void {}

	/**
	 * Record one import.
	 *
	 * @param array<string,mixed> $summary Importer summary (source, source_host, applied, unchanged, unknown, errors, login_url).
	 * @param int                 $user_id Importing user; 0 = system (WP-CLI without --user).
	 */
	public function on_imported( array $summary, int $user_id ): void {
		$host        = (string) ( $summary['source_host'] ?? '' );
		$description = sprintf(
			'Settings imported via %s from %s: %d applied, %d unchanged, %d unknown ignored, %d failed. Login URL: %s',
			(string) ( $summary['source'] ?? 'admin' ),
			'' === $host ? 'an unnamed export' : 'login-armor-settings-' . $host . '.json',
			(int) ( $summary['applied'] ?? 0 ),
			(int) ( $summary['unchanged'] ?? 0 ),
			(int) ( $summary['unknown'] ?? 0 ),
			(int) ( $summary['errors'] ?? 0 ),
			(string) ( $summary['login_url'] ?? '' )
		);

		if ( $user_id > 0 ) {
			$this->log( 'settings_imported', 'settings', 0, $host, $description, $user_id );
			return;
		}
		ActivityLogger::log_system( 'settings_imported', $host, $description );
	}

	/**
	 * Record a reset of the detection data: every login event, brute-force
	 * counter and incident deleted at once (2.7.9). Subscribed to
	 * login_armor_data_reset by ActivityLog. Untyped, with defaults: anyone
	 * can fire the plugin's own action, with fewer arguments.
	 *
	 * @param mixed $scope     Which dataset was reset.
	 * @param mixed $row_count Rows deleted across the tables.
	 * @param mixed $user_id   Administrator who asked for it.
	 * @param mixed $deleted   Rows per table: events, attempts, incidents.
	 */
	public function on_data_reset( $scope = '', $row_count = 0, $user_id = 0, $deleted = array() ): void {
		// The activity log is the audit channel itself: its own reset is not
		// written back into the table that was just emptied.
		if ( 'detection' !== $scope ) {
			return;
		}
		$description = sprintf( 'All detection data reset: %d rows deleted', is_numeric( $row_count ) ? (int) $row_count : 0 );
		if ( is_array( $deleted ) && isset( $deleted['events'], $deleted['attempts'], $deleted['incidents'] ) ) {
			$description .= sprintf( ' (%d login events, %d brute-force counters, %d incidents)', (int) $deleted['events'], (int) $deleted['attempts'], (int) $deleted['incidents'] );
		}
		$description .= '. Every IP lockout was released.';
		$name         = __( 'Detection & Logs', 'login-armor' );
		$user_id      = is_numeric( $user_id ) ? (int) $user_id : 0;

		if ( $user_id > 0 ) {
			$this->log( 'detection_data_reset', 'config', 0, $name, $description, $user_id );
			return;
		}
		ActivityLogger::log_system( 'detection_data_reset', $name, $description );
	}

	/**
	 * Headless mode switched on or off (2.9.0). Untyped, with defaults.
	 *
	 * @param mixed $enabled    The new state.
	 * @param mixed $turned_off Toggles switched off by the change.
	 * @param mixed $user_id    Who asked; 0 for the system.
	 */
	public function on_headless_changed( $enabled = false, $turned_off = array(), $user_id = 0 ): void {
		$description = $enabled ? 'Headless mode turned on' : 'Headless mode turned off';
		if ( $enabled && is_array( $turned_off ) && array() !== $turned_off ) {
			$description .= '. Turned off: ' . implode( ', ', array_map( 'strval', $turned_off ) );
		}
		$description .= '.';
		$name    = __( 'Headless back end', 'login-armor' );
		$user_id = is_numeric( $user_id ) ? (int) $user_id : 0;
		if ( $user_id > 0 ) {
			$this->log( 'headless_mode_changed', 'config', 0, $name, $description, $user_id );
			return;
		}
		ActivityLogger::log_system( 'headless_mode_changed', $name, $description );
	}

	/**
	 * An application password used from a new network (2.9.0).
	 *
	 * @param mixed $user_id Owner of the password.
	 * @param mixed $uuid    Password identifier.
	 * @param mixed $facts   What the alert said.
	 */
	public function on_app_password_new_network( $user_id = 0, $uuid = '', $facts = array() ): void {
		unset( $user_id, $uuid );
		$facts       = is_array( $facts ) ? $facts : array();
		$description = sprintf(
			'Application password "%s" of %s used from a new network: %s (%s).',
			(string) ( $facts['password_name'] ?? '' ),
			(string) ( $facts['user_login'] ?? '' ),
			(string) ( $facts['network'] ?? '' ),
			(string) ( $facts['ip'] ?? '' )
		);
		ActivityLogger::log_system( 'app_password_new_network', (string) ( $facts['password_name'] ?? '' ), $description );
	}

	/**
	 * A flagged network approved by an administrator (2.9.0).
	 *
	 * @param mixed $user_id  Owner of the password.
	 * @param mixed $uuid     Password identifier.
	 * @param mixed $network  Network approved.
	 * @param mixed $approver Administrator who approved it.
	 */
	public function on_app_password_network_approved( $user_id = 0, $uuid = '', $network = '', $approver = 0 ): void {
		$description = sprintf( 'Network %s approved for application password %s of user #%d.', (string) $network, (string) $uuid, is_numeric( $user_id ) ? (int) $user_id : 0 );
		$approver    = is_numeric( $approver ) ? (int) $approver : 0;
		if ( $approver > 0 ) {
			$this->log( 'app_password_network_approved', 'user', is_numeric( $user_id ) ? (int) $user_id : 0, (string) $network, $description, $approver );
			return;
		}
		ActivityLogger::log_system( 'app_password_network_approved', (string) $network, $description );
	}

	/**
	 * Boolean options rewritten by the 2.10.0 upgrade. Untyped, with defaults.
	 *
	 * One line per rewrite: a value such as "false" ran the module (every
	 * reader cast it to true), so it is stored as 1, what the site does.
	 *
	 * @param mixed $changes Rewrites: option, key, from, to.
	 */
	public function on_boolean_options_migrated( $changes = array() ): void {
		if ( ! is_array( $changes ) ) {
			return;
		}
		foreach ( $changes as $change ) {
			if ( ! is_array( $change ) ) {
				continue;
			}
			$option      = (string) ( $change['option'] ?? '' );
			$key         = (string) ( $change['key'] ?? '' );
			$name        = '' === $key ? $option : $option . '.' . $key;
			$description = sprintf( 'Stored value "%s" read as %s by the plugin; rewritten as %d, unchanged in effect. Writing false or 0 now switches it off.', (string) ( $change['from'] ?? '' ), ! empty( $change['to'] ) ? 'on' : 'off', ! empty( $change['to'] ) ? 1 : 0 );
			ActivityLogger::log_system( 'boolean_option_normalised', $name, $description );
		}
	}
}
