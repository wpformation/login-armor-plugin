<?php
/**
 * Generic JSON webhook notification channel.
 *
 * Sends a raw JSON payload to any user-configured URL.
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
 * Sends notification as a generic JSON POST.
 */
class GenericWebhookChannel implements ChannelInterface {

	/**
	 * {@inheritDoc}
	 */
	public function get_key(): string {
		return 'generic';
	}

	/**
	 * {@inheritDoc}
	 */
	public function format( array $event ): array {
		return [
			// Back-compat: an event with no machine name is an incident, the
			// only thing this channel ever carried before 2.6.1.
			'event'     => ( $event['event'] ?? '' ) !== '' ? (string) $event['event'] : 'incident_created',
			'title'     => (string) ( $event['title'] ?? '' ),
			'timestamp' => $event['timestamp'] ?? gmdate( 'c' ),
			'site_url'  => $event['site_url'] ?? home_url(),
			'data'      => [
				'pattern'          => $event['pattern'] ?? '',
				'severity'         => $event['severity'] ?? 1,
				'severity_label'   => $event['severity_label'] ?? 'Low',
				'ip'               => $event['ip'] ?? '',
				'target_username'  => $event['target_username'] ?? '',
				'events_count'     => $event['events_count'] ?? 0,
				'unique_ips'       => $event['unique_ips'] ?? 0,
				'unique_usernames' => $event['unique_usernames'] ?? 0,
				// Alerts the hourly cap refused since suppressed_since, so an
				// automated consumer sees the gap instead of guessing.
				'suppressed_count' => (int) ( $event['suppressed_count'] ?? 0 ),
				'suppressed_since' => (string) ( $event['suppressed_since'] ?? '' ),
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
