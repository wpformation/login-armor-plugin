<?php
/**
 * Notification channel interface.
 *
 * Each notification channel (Slack, Discord, Generic JSON) implements this
 * interface. The Dispatcher iterates enabled channels and calls send().
 *
 * @package LoginArmor
 * @since   2.0.0
 */

namespace LoginArmor\Notifications;

defined( 'ABSPATH' ) || exit;

/**
 * Contract for notification delivery channels.
 *
 * Payload contract (every key is always present, filled by
 * Dispatcher::build_event(); a channel never has to test for existence):
 *
 *  - event            string  Machine name of what happened:
 *                             'incident_created', 'lockout_threshold',
 *                             'admin_account_created',
 *                             'admin_account_promoted', 'settings_imported'.
 *                             A payload without it is an incident (back-compat).
 *  - title            string  Human-readable headline for the event.
 *  - pattern          string  Detection pattern, or the event name for the
 *                             events that have no detection pattern.
 *  - severity         int     1 Low, 2 Medium, 3 High, 4 Critical.
 *  - severity_label   string  English label for the severity.
 *  - ip               string  Source IP, empty when there is none.
 *  - target_username  string  Targeted or concerned account, may be empty.
 *  - events_count     int     Event-specific count (failed attempts, lockouts,
 *                             settings applied).
 *  - unique_ips       int     Incidents only, 0 elsewhere.
 *  - unique_usernames int     Incidents only, 0 elsewhere.
 *  - site_url         string  home_url() of the site.
 *  - site_name        string  Blog name.
 *  - timestamp        string  ISO-8601 UTC.
 *  - admin_url        string  Deep link to the relevant Login Armor tab.
 *  - is_test          bool    True only for the manual test send.
 *
 * Two keys are present only when the hourly cap swallowed alerts, and a
 * channel must render them when they are:
 *
 *  - suppressed_count int     Alerts refused during the current hour.
 *  - suppressed_since string  Start of that hour, 'HH:00' UTC.
 */
interface ChannelInterface {

	/**
	 * Unique key identifying this channel (e.g. 'slack', 'discord', 'generic').
	 */
	public function get_key(): string;

	/**
	 * Format incident data into a channel-specific payload.
	 *
	 * @param array<string,mixed> $event Normalized event data from Dispatcher.
	 * @return array<string,mixed> Payload ready for wp_remote_post body encoding.
	 */
	public function format( array $event ): array;

	/**
	 * Send the notification via wp_remote_post.
	 *
	 * @param array<string,mixed> $event    Normalized event data from Dispatcher.
	 * @param string              $url      Webhook URL configured by admin.
	 * @param bool                $blocking Whether to wait for the response (true for test sends).
	 * @return bool True on success (HTTP 2xx), false on failure.
	 */
	public function send( array $event, string $url, bool $blocking = false ): bool;
}
