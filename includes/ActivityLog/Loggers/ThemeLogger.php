<?php
/**
 * Theme activity logger.
 *
 * Tracks: theme_installed, theme_activated, theme_deleted, theme_updated.
 *
 * @package LoginArmor\ActivityLog\Loggers
 * @since   2.1.0
 */

namespace LoginArmor\ActivityLog\Loggers;

use LoginArmor\ActivityLog\ActivityLogger;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class ThemeLogger extends ActivityLogger {

	public function get_key(): string {
		return 'theme';
	}

	public function get_label(): string {
		return 'Themes';
	}

	public function register(): void {
		add_action( 'switch_theme', [ $this, 'on_switch' ], 10, 3 );
		add_action( 'deleted_theme', [ $this, 'on_deleted' ], 10, 2 );
		add_action( 'upgrader_process_complete', [ $this, 'on_upgrader_complete' ], 10, 2 );
	}

	// Callbacks untyped with defaults: theme-lifecycle hooks are re-fired
	// by managers/updaters with degraded arity or types.

	public function on_switch( $new_name = '', $new_theme = null, $old_theme = null ): void {
		if ( ! is_string( $new_name ) || '' === $new_name ) {
			return;
		}
		$old_label = $old_theme instanceof \WP_Theme ? $old_theme->get( 'Name' ) : 'unknown';
		$this->log( 'theme_activated', 'theme', 0, $new_name,
			sprintf( 'Theme switched from "%s" to "%s".', $old_label, $new_name ) );
	}

	public function on_deleted( $stylesheet = '', $deleted = false ): void {
		if ( ! is_string( $stylesheet ) || '' === $stylesheet || ! $deleted ) {
			return;
		}
		$this->log( 'theme_deleted', 'theme', 0, $stylesheet,
			sprintf( 'Theme "%s" deleted.', $stylesheet ) );
	}

	public function on_upgrader_complete( $upgrader = null, $options = array() ): void {
		if ( ! $upgrader instanceof \WP_Upgrader || ! is_array( $options ) ) {
			return;
		}
		if ( ( $options['type'] ?? '' ) !== 'theme' ) {
			return;
		}

		$action = $options['action'] ?? '';
		$themes = $options['themes'] ?? [];

		if ( 'install' === $action && ! empty( $upgrader->result ) ) {
			$name = $upgrader->result['destination_name'] ?? 'unknown';
			$this->log( 'theme_installed', 'theme', 0, $name,
				sprintf( 'Theme "%s" installed.', $name ) );
			return;
		}

		if ( 'update' === $action && is_array( $themes ) ) {
			foreach ( $themes as $theme ) {
				$theme_obj = wp_get_theme( $theme );
				$name      = $theme_obj->exists() ? $theme_obj->get( 'Name' ) : $theme;
				$this->log( 'theme_updated', 'theme', 0, $name,
					sprintf( 'Theme "%s" updated.', $name ) );
			}
		}
	}
}
