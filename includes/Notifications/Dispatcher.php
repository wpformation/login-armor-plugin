<?php
/**
 * Notification dispatcher.
 *
 * Subscribes to the four events an operator needs to hear about (a detected
 * incident, a repeated lockout, an administrator account appearing, a settings
 * import), applies the severity threshold and the hourly quotas, then hands the
 * event to the configured channel.
 *
 * @package LoginArmor
 * @since   2.0.0
 */

namespace LoginArmor\Notifications;

use LoginArmor\Detection\Incident;

// Exit if accessed directly.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Orchestrates notification delivery to the configured channel.
 */
class Dispatcher {

	/**
	 * Severity integer-to-label mapping.
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
	 * Severity that gets a bucket of its own.
	 */
	public const CRITICAL_SEVERITY = 4;

	/**
	 * Hourly cap for the critical bucket.
	 *
	 * Deliberately not operator-configurable: the whole point of the second
	 * bucket is that a flood of medium incidents can never consume the quota a
	 * critical alert needs, and an operator who lowers the ordinary limit to 1
	 * must not lose their critical alerts with it.
	 */
	public const CRITICAL_RATE_LIMIT = 5;

	/**
	 * Prefix shared by both hourly buckets.
	 *
	 * Kept transient-shaped on purpose: cleanup_rate_key() and the uninstall
	 * catch-all (`_transient_login_armor_%`) both key off it.
	 */
	public const RATE_KEY_PREFIX = '_transient_login_armor_notif_count_';

	/**
	 * Option holding the current hour's suppressed-alert counter.
	 */
	public const SUPPRESSED_OPTION = 'login_armor_notif_suppressed';

	/**
	 * Constructor. Subscribes to every routable security event.
	 */
	public function __construct() {
		add_action( 'login_armor_incident_created', [ $this, 'dispatch' ], 10, 2 );
		add_action( 'login_armor_lockout_threshold_reached', [ $this, 'dispatch_lockout' ], 10, 3 );
		add_action( 'login_armor_admin_account_alert', [ $this, 'dispatch_admin_account' ], 10, 2 );
		add_action( 'login_armor_settings_imported', [ $this, 'dispatch_settings_imported' ], 10, 2 );
		add_action( 'login_armor_app_password_new_network', [ $this, 'dispatch_app_password_network' ], 10, 3 );
		add_action( 'login_armor_cleanup_rate_key', [ self::class, 'cleanup_rate_key' ] );
	}

	/**
	 * Delete an expired rate-limit option row.
	 *
	 * @param string $option_name The option key to delete.
	 */
	public static function cleanup_rate_key( string $option_name ): void {
		if ( str_starts_with( $option_name, self::RATE_KEY_PREFIX ) ) {
			delete_option( $option_name );
		}
	}

	/**
	 * Handle the login_armor_incident_created hook.
	 *
	 * Parameters untyped with defaults: the plugin's own hooks are exempt from
	 * the core-hook callback audit, but a third party can re-fire them with a
	 * degraded arity and must not produce a fatal.
	 *
	 * @param mixed $incident The incident object.
	 * @param mixed $is_new   True for new incidents, false for updates.
	 */
	public function dispatch( $incident = null, $is_new = false ): void {
		// Only notify on new incidents, not updates to existing ones.
		if ( ! $incident instanceof Incident || ! $is_new ) {
			return;
		}

		$this->deliver( $this->normalize_event( $incident ), false );
	}

	/**
	 * Handle the login_armor_lockout_threshold_reached hook.
	 *
	 * Skipped on the e-mail channel: LimitLogin already mails the administrator
	 * directly at this exact moment, and two identical e-mails is noise, not
	 * reliability.
	 *
	 * @param mixed $ip        The locked-out IP.
	 * @param mixed $count     Lockouts observed for that IP in the window.
	 * @param mixed $threshold Configured threshold that was reached.
	 */
	public function dispatch_lockout( $ip = '', $count = 0, $threshold = 0 ): void {
		unset( $threshold );

		$this->deliver(
			$this->build_event(
				[
					'event'           => 'lockout_threshold',
					'pattern'         => 'lockout_threshold',
					'title'           => 'Lockout threshold reached',
					'severity'        => 3,
					'ip'              => (string) $ip,
					'events_count'    => (int) $count,
					'admin_url'       => admin_url( 'admin.php?page=login-armor&tab=limit' ),
				]
			),
			true
		);
	}

	/**
	 * Handle login_armor_app_password_new_network (2.9.0).
	 *
	 * Skipped on the e-mail channel: Review::alert() already mails the
	 * administrator, as LimitLogin does for lockouts.
	 *
	 * @param mixed $user_id Owner of the password.
	 * @param mixed $uuid    Password identifier.
	 * @param mixed $facts   What the alert says.
	 */
	public function dispatch_app_password_network( $user_id = 0, $uuid = '', $facts = array() ): void {
		unset( $user_id, $uuid );
		$facts = is_array( $facts ) ? $facts : array();
		$this->deliver(
			$this->build_event(
				[
					'event'           => 'app_password_new_network',
					'pattern'         => 'app_password_new_network',
					'title'           => 'Application password used from a new network',
					'severity'        => 3,
					'ip'              => (string) ( $facts['ip'] ?? '' ),
					'target_username' => (string) ( $facts['user_login'] ?? '' ),
					'admin_url'       => (string) ( $facts['approve_url'] ?? admin_url( 'profile.php' ) ),
				]
			),
			true
		);
	}

	/**
	 * Handle the login_armor_admin_account_alert hook.
	 *
	 * Skipped on the e-mail channel: Hardening already mails the administrator.
	 *
	 * @param mixed $user_id The affected user ID.
	 * @param mixed $context Either 'created' or 'promoted'.
	 */
	public function dispatch_admin_account( $user_id = 0, $context = '' ): void {
		$context = 'promoted' === $context ? 'promoted' : 'created';
		$user    = get_userdata( (int) $user_id );
		$login   = $user instanceof \WP_User ? $user->user_login : (string) (int) $user_id;

		$this->deliver(
			$this->build_event(
				[
					'event'           => 'admin_account_' . $context,
					'pattern'         => 'admin_account_' . $context,
					'title'           => 'promoted' === $context ? 'Administrator role granted' : 'New administrator account',
					'severity'        => self::CRITICAL_SEVERITY,
					// An unresolved client identity is 0.0.0.0, a placeholder
					// that would read as a real source address in a Slack card
					// or an e-mail. Send nothing rather than something false;
					// the channels already render an empty IP as a dash.
					'ip'              => \LoginArmor\LoginArmor::UNKNOWN_CLIENT_IP === \LoginArmor\LoginArmor::get_client_ip()
						? ''
						: \LoginArmor\LoginArmor::get_client_ip(),
					'target_username' => $login,
					'events_count'    => 1,
					'admin_url'       => admin_url( 'admin.php?page=login-armor&tab=activity' ),
				]
			),
			true
		);
	}

	/**
	 * Handle the login_armor_settings_imported hook.
	 *
	 * Sent on every channel, e-mail included: nothing else reports an import.
	 *
	 * Known limitation, by design: an import that switches the channel from
	 * `disabled` to a webhook cannot announce its own run. The dispatcher is
	 * only instantiated when a channel is already configured, so nothing is
	 * subscribed to the hook during that request.
	 *
	 * @param mixed $summary Import summary (counts, applied paths, source).
	 * @param mixed $user_id Importing user (0 from WP-CLI without --user).
	 */
	public function dispatch_settings_imported( $summary = [], $user_id = 0 ): void {
		$summary = is_array( $summary ) ? $summary : [];
		$user    = get_userdata( (int) $user_id );
		// With no resolvable user, name the entry point the import came
		// through ('admin' or 'cli', set by Importer::apply()) rather than
		// asserting WP-CLI: an administrator import whose user row has since
		// been deleted also lands here, and 'wp-cli' would then be a lie.
		$source  = (string) ( $summary['source'] ?? '' );
		$actor   = $user instanceof \WP_User
			? $user->user_login
			: ( '' !== $source ? $source : 'unknown' );

		$this->deliver(
			$this->build_event(
				[
					'event'           => 'settings_imported',
					'pattern'         => 'settings_imported',
					'title'           => 'Settings imported',
					'severity'        => 2,
					'target_username' => $actor,
					'events_count'    => (int) ( $summary['applied'] ?? 0 ),
					'admin_url'       => admin_url( 'admin.php?page=login-armor&tab=settings' ),
				]
			),
			false
		);
	}

	/**
	 * Apply the gates, then hand the event to the configured channel.
	 *
	 * @param array<string,mixed> $event              Normalized event payload.
	 * @param bool                $skip_email_channel True when the event already
	 *                                                has a direct e-mail of its own.
	 */
	private function deliver( array $event, bool $skip_email_channel = false ): void {
		$channel_key  = (string) get_option( 'login_armor_notif_channel', 'disabled' );
		$webhook_url  = (string) get_option( 'login_armor_notif_webhook_url', '' );
		$min_severity = (int) get_option( 'login_armor_notif_min_severity', 2 );
		$rate_limit   = (int) get_option( 'login_armor_notif_rate_limit', 10 );

		if ( 'disabled' === $channel_key ) {
			return;
		}

		if ( 'email' === $channel_key && $skip_email_channel ) {
			return;
		}

		// Webhook channels require a URL; email uses admin_email as fallback.
		if ( 'email' !== $channel_key && '' === $webhook_url ) {
			return;
		}

		$severity = (int) ( $event['severity'] ?? 1 );
		if ( $severity < $min_severity ) {
			return;
		}

		// Rate limiting (atomic check + increment to prevent race conditions).
		if ( ! $this->check_and_increment_rate( $rate_limit, $severity ) ) {
			$this->record_suppressed( $event );
			// phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log -- Intentional debug logging for skipped notifications.
			error_log( 'LoginArmor: notification skipped, hourly cap reached for severity ' . $severity . '.' );
			return;
		}

		$channel = $this->load_channel( $channel_key );

		if ( null === $channel ) {
			return;
		}

		// The backlog is read whatever the hour it started in. A bucket that
		// refused an alert is by definition full for the rest of that hour, so
		// the send that finally carries the news is almost always in a later
		// hour: scoping the read to the current hour made the announcement
		// unreachable in the ordinary case.
		$suppressed = self::get_suppressed();
		if ( $suppressed['count'] > 0 ) {
			$event['suppressed_count'] = $suppressed['count'];
			$event['suppressed_since'] = self::suppressed_since_label( $suppressed['hour'] );
		}

		$success = $channel->send( $event, $webhook_url, false );

		if ( ! $success ) {
			self::store_error( 'Send failed for channel: ' . $channel_key );
			return;
		}

		// Announced and delivered: clear the backlog, but only if it is still
		// exactly what was announced. A suppression that landed between the
		// read and here leaves a different row, the clear affects no row, and
		// the next successful send carries the newer count instead of it
		// being silently dropped.
		if ( $suppressed['count'] > 0 ) {
			self::clear_suppressed( $suppressed['raw'] );
		}
	}

	/**
	 * Send a test notification (blocking). Used by the AJAX test endpoint.
	 *
	 * @return array{success: bool, message: string}
	 */
	public static function send_test(): array {
		$channel_key = (string) get_option( 'login_armor_notif_channel', 'disabled' );
		$webhook_url = (string) get_option( 'login_armor_notif_webhook_url', '' );

		if ( 'disabled' === $channel_key ) {
			return [ 'success' => false, 'message' => 'Notifications are disabled.' ];
		}

		// Email channel uses admin_email as fallback - URL is optional.
		if ( 'email' !== $channel_key && '' === $webhook_url ) {
			return [ 'success' => false, 'message' => 'No webhook URL configured.' ];
		}

		$instance = new self();
		$event    = $instance->build_event(
			[
				'event'           => 'incident_created',
				'pattern'         => 'brute_force',
				'title'           => 'Brute Force Detected',
				'severity'        => 3,
				'ip'              => '203.0.113.42',
				'target_username' => 'admin',
				'events_count'    => 25,
				'is_test'         => true,
			]
		);

		$channel = $instance->load_channel( $channel_key );

		if ( null === $channel ) {
			return [ 'success' => false, 'message' => 'Unknown channel: ' . $channel_key ];
		}

		$success = $channel->send( $event, $webhook_url, true );

		if ( ! $success ) {
			self::store_error( 'Test send failed for channel: ' . $channel_key );
			return [ 'success' => false, 'message' => 'Webhook request failed. Check the URL and try again.' ];
		}

		// Clear last error on successful test.
		delete_option( 'login_armor_last_notif_error' );

		return [ 'success' => true, 'message' => 'Test notification sent successfully.' ];
	}

	/**
	 * Normalize an Incident object into a flat event array.
	 *
	 * @param Incident $incident The incident.
	 * @return array<string,mixed>
	 */
	private function normalize_event( Incident $incident ): array {
		return $this->build_event(
			[
				'event'            => 'incident_created',
				'pattern'          => $incident->pattern,
				'title'            => sprintf( '%s Detected', ucwords( str_replace( '_', ' ', $incident->pattern ) ) ),
				'severity'         => $incident->severity,
				'ip'               => $incident->ip,
				'target_username'  => $incident->target_username,
				'events_count'     => $incident->events_count,
				'unique_ips'       => $incident->unique_ips,
				'unique_usernames' => $incident->unique_usernames,
			]
		);
	}

	/**
	 * Build a complete event payload from the keys an emitter cares about.
	 *
	 * Every key of the channel payload contract is filled here, so a channel
	 * never has to guess whether a key exists. See ChannelInterface for the
	 * contract itself.
	 *
	 * @param array<string,mixed> $overrides Event-specific values.
	 * @return array<string,mixed>
	 */
	private function build_event( array $overrides ): array {
		$severity = (int) ( $overrides['severity'] ?? 1 );

		$defaults = [
			'event'            => 'incident_created',
			'pattern'          => '',
			'title'            => '',
			'severity'         => $severity,
			'severity_label'   => self::SEVERITY_LABELS[ $severity ] ?? 'Unknown',
			'ip'               => '',
			'target_username'  => '',
			'events_count'     => 0,
			'unique_ips'       => 0,
			'unique_usernames' => 0,
			'site_url'         => home_url(),
			'site_name'        => get_bloginfo( 'name' ),
			'timestamp'        => gmdate( 'c' ),
			'admin_url'        => admin_url( 'admin.php?page=login-armor&tab=incidents' ),
			'is_test'          => false,
		];

		return array_merge( $defaults, $overrides );
	}

	/**
	 * Load the channel class for the given key.
	 *
	 * @param string $key Channel key (email, slack, discord, generic).
	 * @return ChannelInterface|null
	 */
	private function load_channel( string $key ): ?ChannelInterface {
		$map = [
			'email'   => 'EmailChannel',
			'slack'   => 'SlackChannel',
			'discord' => 'DiscordChannel',
			'generic' => 'GenericWebhookChannel',
		];

		if ( ! isset( $map[ $key ] ) ) {
			return null;
		}

		$class_name = $map[ $key ];
		$file       = LOGIN_ARMOR_DIR . 'includes/Notifications/Channels/' . $class_name . '.php';

		if ( ! file_exists( $file ) ) {
			return null;
		}

		require_once $file;

		$fqcn = 'LoginArmor\\Notifications\\Channels\\' . $class_name;
		return new $fqcn();
	}

	/**
	 * Hourly bucket key for a severity.
	 *
	 * Two buckets, both under the swept prefix: the ordinary one, and a
	 * critical one so severity 4 never queues behind a flood of medium alerts.
	 *
	 * @param int $severity Event severity.
	 */
	public static function rate_key( int $severity ): string {
		$bucket = $severity >= self::CRITICAL_SEVERITY ? 'critical_' : '';

		return self::RATE_KEY_PREFIX . $bucket . gmdate( 'YmdH' );
	}

	/**
	 * Check the relevant hourly bucket and increment it atomically.
	 *
	 * The critical bucket is a floor, never a ceiling. A severity 4 alert
	 * draws on its reserve first, so a flood of medium incidents can never
	 * starve it; once that reserve is spent it falls back to the ordinary
	 * bucket like any other alert. Without the fallback a site with a
	 * configured limit of 50 would receive 5 critical alerts an hour instead
	 * of up to 50, which is the opposite of what a reserve is for.
	 *
	 * @param int $rate_limit Operator-configured ordinary cap (0 disables both caps).
	 * @param int $severity   Severity of the event about to be sent.
	 * @return bool True if the send is allowed (a counter was incremented).
	 */
	private function check_and_increment_rate( int $rate_limit, int $severity ): bool {
		if ( $rate_limit <= 0 ) {
			return true;
		}

		if ( $severity >= self::CRITICAL_SEVERITY
			&& $this->increment_bucket( self::rate_key( self::CRITICAL_SEVERITY ), self::CRITICAL_RATE_LIMIT ) ) {
			return true;
		}

		// Severity 1 maps to the ordinary bucket key, whatever the event.
		return $this->increment_bucket( self::rate_key( 1 ), $rate_limit );
	}

	/**
	 * Increment one hourly bucket, atomically, and say whether it was allowed.
	 *
	 * The counter lives in a single option row and is only ever touched by
	 * statements the database serializes, so concurrent requests cannot both
	 * read the same value and both decide they are under the cap.
	 *
	 * The retry matters. Two requests arriving in the same first second of an
	 * hour both get 0 rows from the conditional UPDATE (no row yet), both run
	 * the INSERT IGNORE, and exactly one of them creates the row. Before 2.6.1
	 * the loser returned false and its alert was dropped, although the counter
	 * it had just lost the race to stood at 1, far below the cap. A single
	 * retry of the same conditional UPDATE settles it: if the row is now below
	 * the cap the alert goes out, and if it is not, the bucket really is full.
	 *
	 * @param string $key Option name of the bucket.
	 * @param int    $max Cap for this bucket.
	 * @return bool True when the counter was incremented below the cap.
	 */
	private function increment_bucket( string $key, int $max ): bool {
		global $wpdb;

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Atomic rate-limit counter, caching would defeat the purpose.
		$updated = (int) $wpdb->query(
			$wpdb->prepare(
				"UPDATE {$wpdb->options} SET option_value = option_value + 1 WHERE option_name = %s AND option_value < %d",
				$key,
				$max
			)
		);

		if ( $updated > 0 ) {
			return true;
		}

		// Row may not exist yet - try to insert it (first alert this hour).
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
		$inserted = (int) $wpdb->query(
			$wpdb->prepare(
				"INSERT IGNORE INTO {$wpdb->options} (option_name, option_value, autoload) VALUES (%s, %s, 'no')",
				$key,
				'1'
			)
		);

		if ( $inserted > 0 ) {
			// Schedule cleanup of this transient-like option.
			wp_schedule_single_event( time() + HOUR_IN_SECONDS, 'login_armor_cleanup_rate_key', [ $key ] );
			return true;
		}

		// Another request created the row between our UPDATE and our INSERT.
		// Retry the increment once: only a second refusal means a full bucket.
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
		$retried = (int) $wpdb->query(
			$wpdb->prepare(
				"UPDATE {$wpdb->options} SET option_value = option_value + 1 WHERE option_name = %s AND option_value < %d",
				$key,
				$max
			)
		);

		return $retried > 0;
	}

	/**
	 * Count an alert the cap refused, so the silence is never total.
	 *
	 * One option row carries `YmdH|count|max_severity|last_pattern`. Both
	 * statements below are single atomic writes the database serializes: the
	 * INSERT IGNORE creates the row when there is none, and the UPDATE's IF()
	 * decides between two cases, and only two:
	 *
	 *  - the stored row is EMPTY, meaning the previous backlog was announced
	 *    by a successful send and cleared: start a new backlog at 1, stamped
	 *    with the current hour;
	 *  - the stored row is NOT empty, meaning a backlog is still waiting to be
	 *    announced: add to it in place, keeping the hour it STARTED in, taking
	 *    the worst severity seen and the latest pattern.
	 *
	 * The turn of the hour is deliberately not a reset condition. A bucket
	 * that refused an alert is full for the rest of that hour, so the send
	 * that finally announces the backlog is nearly always in a later hour;
	 * resetting on the hour made the announcement unreachable.
	 *
	 * No read-modify-write happens in PHP, so concurrent suppressions cannot
	 * lose each other's increments the way an update_option() of a decoded
	 * array would.
	 *
	 * @param array<string,mixed> $event The event that was not sent.
	 */
	private function record_suppressed( array $event ): void {
		global $wpdb;

		$hour     = gmdate( 'YmdH' );
		$severity = max( 1, min( 4, (int) ( $event['severity'] ?? 1 ) ) );
		$pattern  = (string) preg_replace(
			'/[^a-z0-9_]/',
			'',
			strtolower( (string) ( $event['pattern'] ?? $event['event'] ?? '' ) )
		);
		$fresh    = $hour . '|1|' . $severity . '|' . $pattern;

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Atomic counter via unique option_name.
		$inserted = (int) $wpdb->query(
			$wpdb->prepare(
				"INSERT IGNORE INTO {$wpdb->options} (option_name, option_value, autoload) VALUES (%s, %s, 'no')",
				self::SUPPRESSED_OPTION,
				$fresh
			)
		);

		if ( $inserted > 0 ) {
			return;
		}

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Atomic accumulator.
		$wpdb->query(
			$wpdb->prepare(
				"UPDATE {$wpdb->options} SET option_value = IF(
					option_value = '',
					%s,
					CONCAT(SUBSTRING_INDEX(option_value, '|', 1), '|', CAST(SUBSTRING_INDEX(SUBSTRING_INDEX(option_value, '|', 2), '|', -1) AS UNSIGNED) + 1, '|', GREATEST(%d, CAST(SUBSTRING_INDEX(SUBSTRING_INDEX(option_value, '|', 3), '|', -1) AS UNSIGNED)), '|', %s)
				) WHERE option_name = %s",
				$fresh,
				$severity,
				$pattern,
				self::SUPPRESSED_OPTION
			)
		);
	}

	/**
	 * Read the pending backlog of alerts the hourly caps refused.
	 *
	 * Read straight from the database, never through the options cache: the
	 * row is written by raw SQL and a cached copy would be stale.
	 *
	 * The row is a pending backlog, not an hour-scoped counter. It survives
	 * the turn of the hour and is cleared by one thing only: a successful send
	 * that announced it. `hour` is therefore the hour the backlog STARTED in,
	 * which is what the operator needs to read ("since 13:00 UTC"), and an
	 * empty row means there is nothing left to announce.
	 *
	 * `raw` is the exact stored string, so a caller can clear the row with a
	 * compare-and-clear and lose nothing that arrived in the meantime.
	 *
	 * @return array{hour:string,count:int,max_severity:int,last_pattern:string,raw:string}
	 */
	public static function get_suppressed(): array {
		global $wpdb;

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Counter requires a current read.
		$value = (string) $wpdb->get_var(
			$wpdb->prepare(
				"SELECT option_value FROM {$wpdb->options} WHERE option_name = %s",
				self::SUPPRESSED_OPTION
			)
		);

		$parts = array_pad( explode( '|', $value, 4 ), 4, '' );
		$count = max( 0, (int) $parts[1] );

		if ( '' === $value || $count < 1 ) {
			return [
				'hour'         => gmdate( 'YmdH' ),
				'count'        => 0,
				'max_severity' => 0,
				'last_pattern' => '',
				'raw'          => $value,
			];
		}

		return [
			'hour'         => (string) $parts[0],
			'count'        => $count,
			'max_severity' => max( 0, min( 4, (int) $parts[2] ) ),
			'last_pattern' => (string) $parts[3],
			'raw'          => $value,
		];
	}

	/**
	 * Human label for the hour a backlog started in, always in UTC.
	 *
	 * Single source of truth for the four surfaces that render it: the
	 * payload, the two channel cards, the e-mail body, the administrator
	 * notice and the Notifications section.
	 *
	 * @param string $hour Stored YmdH.
	 */
	public static function suppressed_since_label( string $hour ): string {
		return ( 10 === strlen( $hour ) ? substr( $hour, 8, 2 ) : gmdate( 'H' ) ) . ':00';
	}

	/**
	 * Clear the backlog, but only if it is still the one that was announced.
	 *
	 * Compare-and-clear: the WHERE names the exact value that was read, so a
	 * suppression that landed between the read and this call leaves a
	 * different row, no row is touched, and the newer count is carried by the
	 * next successful send instead of being lost.
	 *
	 * The row is emptied rather than deleted so that it keeps its
	 * `autoload = 'no'` identity and the next suppression reuses it in place.
	 *
	 * Static and public since 2.7.0: the scheduled digest announces the same
	 * backlog, and a site whose channel only ever carries a digest would
	 * otherwise read the same cumulated count for ever, under a label that
	 * prints an hour and never a date.
	 *
	 * @param string $announced The exact row value that was just announced.
	 */
	public static function clear_suppressed( string $announced ): void {
		global $wpdb;

		if ( '' === $announced ) {
			return;
		}

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Compare-and-clear, caching would defeat the purpose.
		$wpdb->query(
			$wpdb->prepare(
				"UPDATE {$wpdb->options} SET option_value = '' WHERE option_name = %s AND option_value = %s",
				self::SUPPRESSED_OPTION,
				$announced
			)
		);
	}

	/**
	 * Store the last notification error for display in the admin.
	 *
	 * Static and public since 2.7.0: the scheduled digest has no dispatcher
	 * instance and no channel object, but a digest that fails to go out is
	 * exactly the kind of silence this row exists to break. One writer, one
	 * row, one surface in the Notifications section.
	 *
	 * @param string $message Error message.
	 */
	public static function store_error( string $message ): void {
		update_option( 'login_armor_last_notif_error', [
			'message'   => $message,
			'timestamp' => time(),
		], false );

		// phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log -- Intentional debug logging for notification failures.
		error_log( 'LoginArmor: ' . $message );
	}
}
