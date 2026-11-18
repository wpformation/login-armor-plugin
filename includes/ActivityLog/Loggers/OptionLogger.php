<?php
/**
 * Critical option activity logger.
 *
 * Tracks changes to security-sensitive WordPress options.
 *
 * @package LoginArmor\ActivityLog\Loggers
 * @since   2.1.0
 */

namespace LoginArmor\ActivityLog\Loggers;

use LoginArmor\ActivityLog\ActivityLogger;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class OptionLogger extends ActivityLogger {

	/** @var string[] Options to watch. */
	private const WATCHED = [
		'siteurl',
		'home',
		'admin_email',
		'users_can_register',
		'default_role',
		'blogdescription',
		'blogname',
		'permalink_structure',
		'WPLANG',
	];

	public function get_key(): string {
		return 'option';
	}

	public function get_label(): string {
		return 'Options';
	}

	public function register(): void {
		foreach ( self::WATCHED as $key ) {
			// Closure params defaulted: `update_option_*` can be re-fired by
			// settings plugins with fewer args; on_option_change() accepts mixed.
			add_action( "update_option_{$key}", function ( $old_value = null, $new_value = null ) use ( $key ) {
				$this->on_option_change( $key, $old_value, $new_value );
			}, 10, 2 );
		}
	}

	private function on_option_change( string $key, mixed $old_value, mixed $new_value ): void {
		$old_str = is_scalar( $old_value ) ? (string) $old_value : wp_json_encode( $old_value );
		$new_str = is_scalar( $new_value ) ? (string) $new_value : wp_json_encode( $new_value );

		$this->log(
			'option_changed',
			'option',
			0,
			$key,
			sprintf( 'Option "%s" changed from "%s" to "%s".', $key, mb_substr( $old_str, 0, 100 ), mb_substr( $new_str, 0, 100 ) )
		);
	}
}
