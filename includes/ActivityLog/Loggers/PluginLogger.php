<?php
/**
 * Plugin activity logger.
 *
 * Tracks: plugin_installed, plugin_activated, plugin_deactivated, plugin_deleted, plugin_updated.
 *
 * @package LoginArmor\ActivityLog\Loggers
 * @since   2.1.0
 */

namespace LoginArmor\ActivityLog\Loggers;

use LoginArmor\ActivityLog\ActivityLogger;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class PluginLogger extends ActivityLogger {

	public function get_key(): string {
		return 'plugin';
	}

	public function get_label(): string {
		return 'Plugins';
	}

	public function register(): void {
		add_action( 'activated_plugin', [ $this, 'on_activated' ] );
		add_action( 'deactivated_plugin', [ $this, 'on_deactivated' ] );
		add_action( 'deleted_plugin', [ $this, 'on_deleted' ], 10, 2 );
		add_action( 'upgrader_process_complete', [ $this, 'on_upgrader_complete' ], 10, 2 );
	}

	// Callbacks untyped with defaults: plugin-lifecycle hooks are re-fired
	// by managers/updaters with degraded arity or types.

	public function on_activated( $plugin = '' ): void {
		if ( ! is_string( $plugin ) || '' === $plugin ) {
			return;
		}
		$name = $this->get_plugin_name( $plugin );
		$this->log( 'plugin_activated', 'plugin', 0, $name,
			sprintf( 'Plugin "%s" activated.', $name ) );
	}

	public function on_deactivated( $plugin = '' ): void {
		if ( ! is_string( $plugin ) || '' === $plugin ) {
			return;
		}
		$name = $this->get_plugin_name( $plugin );
		$this->log( 'plugin_deactivated', 'plugin', 0, $name,
			sprintf( 'Plugin "%s" deactivated.', $name ) );
	}

	public function on_deleted( $plugin = '', $deleted = false ): void {
		if ( ! is_string( $plugin ) || '' === $plugin || ! $deleted ) {
			return;
		}
		$name = basename( dirname( $plugin ) );
		if ( '.' === $name ) {
			$name = basename( $plugin, '.php' );
		}
		$this->log( 'plugin_deleted', 'plugin', 0, $name,
			sprintf( 'Plugin "%s" deleted.', $name ) );
	}

	public function on_upgrader_complete( $upgrader = null, $options = array() ): void {
		if ( ! $upgrader instanceof \WP_Upgrader || ! is_array( $options ) ) {
			return;
		}
		if ( ( $options['type'] ?? '' ) !== 'plugin' ) {
			return;
		}

		$action  = $options['action'] ?? '';
		$plugins = $options['plugins'] ?? [];

		if ( 'install' === $action && ! empty( $upgrader->result ) ) {
			$name = $upgrader->result['destination_name'] ?? 'unknown';
			$this->log( 'plugin_installed', 'plugin', 0, $name,
				sprintf( 'Plugin "%s" installed.', $name ) );
			return;
		}

		if ( 'update' === $action && is_array( $plugins ) ) {
			foreach ( $plugins as $plugin ) {
				$name = $this->get_plugin_name( $plugin );
				$this->log( 'plugin_updated', 'plugin', 0, $name,
					sprintf( 'Plugin "%s" updated.', $name ) );
			}
		}
	}

	private function get_plugin_name( string $plugin ): string {
		if ( ! function_exists( 'get_plugin_data' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}
		$data = get_plugin_data( WP_PLUGIN_DIR . '/' . $plugin, false, false );
		return ! empty( $data['Name'] ) ? $data['Name'] : basename( $plugin, '.php' );
	}
}
