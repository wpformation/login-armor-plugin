<?php
/**
 * Slack notification channel.
 *
 * Formats incidents as Slack attachments and sends via Incoming Webhook.
 *
 * @package LoginArmor
 * @since   2.0.0
 */

namespace LoginArmor\Notifications\Channels;

use LoginArmor\Notifications\ChannelInterface;

// Exit if accessed directly.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Sends notification to a Slack Incoming Webhook.
 */
class SlackChannel implements ChannelInterface {

	/**
	 * Severity-to-color mapping (Slack hex format).
	 *
	 * @var array<int,string>
	 */
	private const COLORS = [
		1 => '#FBC02D', // Low.
		2 => '#F57C00', // Medium.
		3 => '#E84A2E', // High.
		4 => '#B71C1C', // Critical.
	];

	/**
	 * {@inheritDoc}
	 */
	public function get_key(): string {
		return 'slack';
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
				'title' => 'IP',
				'value' => ( $event['ip'] ?? '' ) !== '' ? $event['ip'] : '-',
				'short' => true,
			],
			[
				'title' => 'Severity',
				'value' => $event['severity_label'] ?? 'Unknown',
				'short' => true,
			],
			[
				'title' => 'Events',
				'value' => (string) ( $event['events_count'] ?? 0 ),
				'short' => true,
			],
			[
				'title' => 'Target',
				'value' => ( $event['target_username'] ?? '' ) !== '' ? $event['target_username'] : '-',
				'short' => true,
			],
		];

		// An hourly cap that swallowed alerts is never left silent: the first
		// message that does get through carries the backlog with it.
		if ( ! empty( $event['suppressed_count'] ) ) {
			$fields[] = [
				'title' => 'Suppressed',
				'value' => sprintf(
					'%1$d further alerts were not sent since %2$s UTC (hourly cap).',
					(int) $event['suppressed_count'],
					(string) ( $event['suppressed_since'] ?? '' )
				),
				'short' => false,
			];
		}

		return [
			'attachments' => [
				[
					'color'   => $color,
					'pretext' => sprintf( ':shield: LoginArmor Alert - %s', $event['site_name'] ?? '' ),
					'title'   => $title,
					'fields'  => $fields,
					'footer'  => 'Login Armor',
					'ts'      => time(),
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

		// Non-blocking: assume success (fire-and-forget).
		return true;
	}
}
