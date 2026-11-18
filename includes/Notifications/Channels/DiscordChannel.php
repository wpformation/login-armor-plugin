<?php
/**
 * Discord notification channel.
 *
 * Formats incidents as Discord embeds and sends via Webhook URL.
 *
 * @package Login Armor
 * @since   2.0.0
 */

namespace LoginArmor\Notifications\Channels;

use LoginArmor\Notifications\ChannelInterface;

// Exit if accessed directly.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Sends notification to a Discord Webhook.
 */
class DiscordChannel implements ChannelInterface {

	/**
	 * Severity-to-color mapping (Discord uses decimal integers).
	 *
	 * @var array<int,int>
	 */
	private const COLORS = [
		1 => 16498733,  // #FBC02D: Low.
		2 => 16088064,  // #F57C00: Medium.
		3 => 15223854,  // #E84A2E: High.
		4 => 12076060,  // #B71C1C: Critical.
	];

	/**
	 * {@inheritDoc}
	 */
	public function get_key(): string {
		return 'discord';
	}

	/**
	 * {@inheritDoc}
	 */
	public function format( array $event ): array {
		$pattern_label = ucwords( str_replace( '_', ' ', $event['pattern'] ?? 'unknown' ) );
		$color         = self::COLORS[ $event['severity'] ?? 1 ] ?? self::COLORS[1];
		$title         = ( $event['title'] ?? '' ) !== '' ? (string) $event['title'] : sprintf( '%s Detected', $pattern_label );

		$fields = [
			[
				'name'   => 'IP',
				'value'  => ( $event['ip'] ?? '' ) !== '' ? $event['ip'] : '-',
				'inline' => true,
			],
			[
				'name'   => 'Severity',
				'value'  => $event['severity_label'] ?? 'Unknown',
				'inline' => true,
			],
			[
				'name'   => 'Events',
				'value'  => (string) ( $event['events_count'] ?? 0 ),
				'inline' => true,
			],
			[
				'name'   => 'Target',
				'value'  => ( $event['target_username'] ?? '' ) !== '' ? $event['target_username'] : '-',
				'inline' => true,
			],
		];

		// An hourly cap that swallowed alerts is never left silent.
		if ( ! empty( $event['suppressed_count'] ) ) {
			$fields[] = [
				'name'   => 'Suppressed',
				'value'  => sprintf(
					'%1$d further alerts were not sent since %2$s UTC (hourly cap).',
					(int) $event['suppressed_count'],
					(string) ( $event['suppressed_since'] ?? '' )
				),
				'inline' => false,
			];
		}

		return [
			'embeds' => [
				[
					'title'       => $title,
					'description' => sprintf( 'Login Armor Alert - %s', $event['site_name'] ?? '' ),
					'color'       => $color,
					'fields'      => $fields,
					'footer'      => [ 'text' => 'Login Armor' ],
					'timestamp'   => $event['timestamp'] ?? gmdate( 'c' ),
				],
			],
		];
	}

	/**
	 * {@inheritDoc}
	 */
	public function send( array $event, string $url, bool $blocking = false ): bool {
		// Re-validate at the egress point, not only at save time: DNS can be
		// re-pointed to a private host after the URL was stored, and this is the
		// last checkpoint before the request leaves the server (P8).
		if ( ! \LoginArmor\Support\SafeUrl::is_safe( $url ) ) {
			return false;
		}
		$payload  = $this->format( $event );
		$response = wp_safe_remote_post( $url, [
			'timeout'     => 15,
			'sslverify'   => true,
			'blocking'    => $blocking,
			'redirection' => 0,
			'headers'     => [ 'Content-Type' => 'application/json' ],
			'body'        => wp_json_encode( $payload ),
		] );

		if ( is_wp_error( $response ) ) {
			return false;
		}

		if ( $blocking ) {
			$code = wp_remote_retrieve_response_code( $response );
			return $code >= 200 && $code < 300;
		}

		return true;
	}
}
