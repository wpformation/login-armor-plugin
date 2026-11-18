<?php
/**
 * Builds the settings export: a self-describing JSON envelope around the
 * registry's current values.
 *
 * @package LoginArmor\Settings
 * @since   2.6.0
 */

namespace LoginArmor\Settings;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Exporter {

	/**
	 * Build the export envelope.
	 *
	 * @param bool $include_webhooks Include the two webhook URLs (opt-in: they
	 *                               carry an authentication token). The HMAC
	 *                               secret is never included.
	 * @return array<string,mixed>
	 */
	public static function build( bool $include_webhooks = false ): array {
		$settings = array_fill_keys( Registry::GROUPS, array() );

		foreach ( Registry::entries() as $option => $entry ) {
			if ( 'optin' === $entry['sensitivity'] && ! $include_webhooks ) {
				continue;
			}
			$value = Registry::read( $option );
			if ( null === $entry['key'] ) {
				$settings[ $entry['group'] ] = array_merge( $settings[ $entry['group'] ], (array) $value );
			} else {
				$settings[ $entry['group'] ][ $entry['key'] ] = $value;
			}
		}

		return array(
			'plugin'           => 'login-armor',
			'plugin_version'   => LOGIN_ARMOR_VERSION,
			'schema_version'   => Importer::SCHEMA_VERSION,
			'exported_at'      => gmdate( 'Y-m-d\TH:i:s\Z' ),
			'source'           => array(
				'host'       => self::host(),
				'home_url'   => home_url(),
				'wp_version' => get_bloginfo( 'version' ),
			),
			'include_webhooks' => $include_webhooks,
			'settings'         => $settings,
		);
	}

	/**
	 * Pretty JSON, slashes unescaped, trailing newline (diff-friendly).
	 *
	 * @param array<string,mixed> $envelope
	 */
	public static function to_json( array $envelope ): string {
		$json = wp_json_encode( $envelope, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES );
		return ( false === $json ? '{}' : $json ) . "\n";
	}

	/**
	 * Download file name: host + UTC timestamp, filesystem-safe.
	 */
	public static function filename(): string {
		$host = preg_replace( '/[^a-z0-9.-]+/', '-', strtolower( self::host() ) );
		$host = trim( (string) $host, '-.' );
		return 'login-armor-settings-' . ( '' === $host ? 'site' : $host ) . '-' . gmdate( 'Ymd-His' ) . '.json';
	}

	private static function host(): string {
		$host = wp_parse_url( home_url(), PHP_URL_HOST );
		return is_string( $host ) ? $host : '';
	}
}
