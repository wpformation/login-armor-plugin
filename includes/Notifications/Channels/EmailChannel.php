<?php
/**
 * Email notification channel.
 *
 * Sends incident alerts via wp_mail() to the configured admin email.
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
 * Sends notification via WordPress email (wp_mail).
 */
class EmailChannel implements ChannelInterface {

	/**
	 * Severity labels for the email subject line.
	 *
	 * @var array<int,string>
	 */
	private const SEVERITY_LABELS = [
		1 => 'Low',
		2 => 'Medium',
		3 => 'High',
		4 => 'Critical',
	];

	/**
	 * {@inheritDoc}
	 */
	public function get_key(): string {
		return 'email';
	}

	/**
	 * {@inheritDoc}
	 *
	 * Returns a structured array used internally by send().
	 * Not a webhook payload: the 'body' key contains the plain-text email body.
	 */
	public function format( array $event ): array {
		$pattern_label  = ucwords( str_replace( '_', ' ', $event['pattern'] ?? 'unknown' ) );
		$severity_label = $event['severity_label'] ?? self::SEVERITY_LABELS[ $event['severity'] ?? 1 ] ?? 'Unknown';
		$site_name      = $event['site_name'] ?? '';
		$is_test        = ! empty( $event['is_test'] );
		$is_incident    = 'incident_created' === (string) ( $event['event'] ?? 'incident_created' );
		$title          = ( $event['title'] ?? '' ) !== '' ? (string) $event['title'] : sprintf( '%s Detected', $pattern_label );

		$subject_prefix = $is_test ? '[TEST] ' : '';
		$subject = $is_incident
			? sprintf(
				'%s[%s] Login Armor: %s detected (%s)',
				$subject_prefix,
				$site_name,
				$pattern_label,
				$severity_label
			)
			: sprintf(
				'%s[%s] Login Armor: %s (%s)',
				$subject_prefix,
				$site_name,
				$title,
				$severity_label
			);

		$lines = [];
		if ( $is_test ) {
			$lines[] = __( 'This is a test notification from Login Armor.', 'login-armor' );
		} elseif ( $is_incident ) {
			$lines[] = sprintf(
				/* translators: %s: site name */
				__( 'Login Armor detected a security incident on %s.', 'login-armor' ),
				$site_name
			);
		} else {
			$lines[] = sprintf(
				/* translators: %s: site name */
				__( 'Login Armor reported a security event on %s.', 'login-armor' ),
				$site_name
			);
		}
		$lines[] = '';
		$lines[] = $is_incident
			? sprintf( '%s: %s', __( 'Pattern', 'login-armor' ), $pattern_label )
			: sprintf( '%s: %s', __( 'Event', 'login-armor' ), $title );
		$lines[] = sprintf( '%s: %s', __( 'Severity', 'login-armor' ), $severity_label );
		$lines[] = sprintf( '%s: %s', __( 'Source IP', 'login-armor' ), ( $event['ip'] ?? '' ) !== '' ? $event['ip'] : '-' );
		$lines[] = sprintf( '%s: %s', __( 'Target', 'login-armor' ), ( $event['target_username'] ?? '' ) !== '' ? $event['target_username'] : '-' );
		if ( $is_incident ) {
			$lines[] = sprintf( '%s: %d', __( 'Failed attempts', 'login-armor' ), $event['events_count'] ?? 0 );
			$lines[] = sprintf( '%s: %d', __( 'Unique IPs', 'login-armor' ), $event['unique_ips'] ?? 0 );
		} else {
			$lines[] = sprintf( '%s: %d', __( 'Events', 'login-armor' ), $event['events_count'] ?? 0 );
		}
		$lines[] = '';

		// An hourly cap that swallowed alerts is never left silent.
		if ( ! empty( $event['suppressed_count'] ) ) {
			$lines[] = sprintf(
				/* translators: 1: number of alerts that were not sent, 2: start of the hour in UTC, e.g. 14:00. */
				__( '%1$d further alerts were not sent since %2$s UTC (hourly cap).', 'login-armor' ),
				(int) $event['suppressed_count'],
				(string) ( $event['suppressed_since'] ?? '' )
			);
			$lines[] = '';
		}

		if ( ! empty( $event['admin_url'] ) ) {
			$lines[] = __( 'View details:', 'login-armor' );
			$lines[] = $event['admin_url'];
			$lines[] = '';
		}

		$lines[] = '-- Login Armor';

		return [
			'subject' => $subject,
			'body'    => implode( "\n", $lines ),
		];
	}

	/**
	 * Send the notification via wp_mail().
	 *
	 * The $url parameter is repurposed as the recipient email address.
	 * If empty, falls back to the site admin email.
	 *
	 * @param array<string,mixed> $event    Normalized event data from Dispatcher.
	 * @param string              $url      Email address (stored in webhook_url field).
	 * @param bool                $blocking Ignored for email (wp_mail is always blocking).
	 * @return bool True on success, false on failure.
	 */
	public function send( array $event, string $url, bool $blocking = false ): bool {
		$to = is_email( $url ) ? $url : (string) get_option( 'admin_email', '' );

		if ( '' === $to ) {
			return false;
		}

		$payload = $this->format( $event );

		return (bool) wp_mail( $to, $payload['subject'], $payload['body'] );
	}
}
