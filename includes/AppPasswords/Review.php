<?php
/**
 * Background review of new application-password rows (2.9.0).
 *
 * A new (password, address) row only schedules this single event. The review
 * gives the row its network (Network), classifies it against the other rows of
 * the same password and network, and alerts once per (password, network) when
 * the password has finished learning.
 *
 * Bounded in rows, in time and in alerts: WP-Cron runs every due event in the
 * same request, and the publication of scheduled posts must not wait behind a
 * slow resolver. Whatever is left is picked up five minutes later.
 *
 * @package LoginArmor
 * @since   2.9.0
 */

namespace LoginArmor\AppPasswords;

use LoginArmor\GeoIP;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Resolve, classify, alert.
 */
final class Review {

	/** Rows per run. */
	public const BATCH = 20;

	/** Seconds per run, checked before each resolution. One slow lookup may overshoot. */
	public const TIME_BUDGET = 10.0;

	/** Alerts per run; the rest wait for the next run. */
	public const ALERTS_PER_RUN = 10;

	/** Days of use that end learning. */
	public const LEARNING_ACTIVE_DAYS = 7;

	/** Calendar days after which learning ends anyway. */
	public const LEARNING_MAX_DAYS = 30;

	/** Delay before the next run when work is left. */
	public const RETRY_DELAY = 300;

	/** Hook the review on its event. Always registered: run() checks the switch. */
	public static function register(): void {
		add_action( Usage::REVIEW_HOOK, array( self::class, 'run' ) );
	}

	/**
	 * One review pass.
	 */
	public static function run(): void {
		if ( ! Usage::is_watching() ) {
			return;
		}
		$rows = Usage::pending_rows( self::BATCH );
		if ( array() === $rows ) {
			return;
		}

		// The next pass is booked before the work: a pass killed midway (PHP
		// time limit, a fatal error elsewhere) must not leave rows pending with
		// no event left to review them. Withdrawn below when nothing is left.
		if ( ! wp_next_scheduled( Usage::REVIEW_HOOK ) ) {
			wp_schedule_single_event( time() + self::RETRY_DELAY, Usage::REVIEW_HOOK );
		}

		$start  = microtime( true );
		$alerts = 0;
		$left   = count( $rows ) >= self::BATCH;
		$since  = (int) get_option( Usage::OPTION_SINCE, 0 );

		foreach ( $rows as $row ) {
			if ( microtime( true ) - $start >= self::TIME_BUDGET ) {
				$left = true;
				break;
			}

			$uuid = (string) $row->uuid;
			$item = Usage::password( (int) $row->user_id, $uuid );
			if ( null === $item ) {
				// Revoked between the request and the review: nothing to judge.
				Usage::forget_password( $uuid );
				continue;
			}

			// Learning is judged when the address was first seen (stored as
			// UTC), not when the row is reviewed: a late review must not turn
			// a network seen during learning into an alert.
			$seen     = strtotime( (string) $row->first_seen . ' UTC' );
			$identity = self::identify( (string) $row->ip );
			$verdict  = self::classify(
				Usage::sibling_states( $uuid, $identity['network'], (int) $row->id ),
				self::in_learning( false === $seen ? time() : $seen, $since, (int) ( $item['created'] ?? 0 ), Usage::days_used( $uuid ) )
			);

			if ( 'alerted' === $verdict && $alerts >= self::ALERTS_PER_RUN ) {
				$left = true;
				continue;
			}

			$claimed = Usage::resolve_row( (int) $row->id, $identity, 'alerted_quiet' === $verdict ? 'alerted' : $verdict );

			// Only the pass that resolved the row alerts.
			if ( 1 === $claimed && 'alerted' === $verdict ) {
				self::alert( $row, $identity );
				++$alerts;
			}
		}

		if ( $left ) {
			return;
		}
		// Nothing left of the batch: withdraw the booked pass, unless rows
		// came in meanwhile (record() saw the booking and scheduled nothing).
		wp_unschedule_hook( Usage::REVIEW_HOOK );
		if ( Usage::count_by_state( 'pending' ) > 0 && ! wp_next_scheduled( Usage::REVIEW_HOOK ) ) {
			wp_schedule_single_event( time() + self::RETRY_DELAY, Usage::REVIEW_HOOK );
		}
	}

	/**
	 * Verdict on a newly resolved row.
	 *
	 * @param string[] $siblings States of the other rows of the same password and network.
	 * @param bool     $learning Whether the password is still learning.
	 * @return string 'known', 'alerted_quiet' (stored as alerted, no alert), 'learned' or 'alerted'.
	 */
	public static function classify( array $siblings, bool $learning ): string {
		if ( array() !== array_intersect( $siblings, array( 'learned', 'known', 'approved' ) ) ) {
			return 'known';
		}
		if ( in_array( 'alerted', $siblings, true ) ) {
			return 'alerted_quiet';
		}
		return $learning ? 'learned' : 'alerted';
	}

	/**
	 * Whether a password is still learning its networks.
	 *
	 * Until 7 days of use, or 30 days after the later of the monitoring
	 * start and the password creation. No known start means no learning: a
	 * password must never stay silent for want of a date.
	 */
	public static function in_learning( int $now, int $watch_since, int $created, int $days_used ): bool {
		$start = max( $watch_since, $created );
		if ( $start <= 0 || $days_used >= self::LEARNING_ACTIVE_DAYS ) {
			return false;
		}
		return $now < $start + self::LEARNING_MAX_DAYS * DAY_IN_SECONDS;
	}

	/**
	 * Network identity of an address, resolving what the cache lacks.
	 *
	 * @return array{network:string,label:string,country:string}
	 */
	private static function identify( string $ip ): array {
		if ( ! GeoIP::is_public_ip( $ip ) ) {
			return Network::identity( $ip, '', null );
		}
		$geo = null;
		if ( GeoIP::is_enabled() ) {
			$geo = GeoIP::cached_network( $ip );
			if ( null === $geo && ! GeoIP::is_circuit_open() ) {
				GeoIP::resolve( $ip );
				$geo = GeoIP::cached_network( $ip );
			}
		}
		return Network::identity( $ip, Network::reverse_domain( $ip ), $geo );
	}

	/**
	 * Send the alert of a new network.
	 *
	 * Same channels as the lockout alert: a direct mail, then the action the
	 * dispatcher forwards to Slack, Discord or a webhook.
	 *
	 * @param object                                            $row      Usage row.
	 * @param array{network:string,label:string,country:string} $identity Its network.
	 */
	private static function alert( object $row, array $identity ): void {
		$user_id = (int) $row->user_id;
		$user    = get_userdata( $user_id );
		$profile = add_query_arg( 'user_id', $user_id, admin_url( 'user-edit.php' ) );
		$facts   = array(
			// A plain-text mail: the stored name carries HTML entities (&#039;).
			'site'          => wp_specialchars_decode( (string) get_bloginfo( 'name' ), ENT_QUOTES ),
			'user_login'    => $user instanceof \WP_User ? $user->user_login : '#' . $user_id,
			'password_name' => (string) $row->password_name,
			'ip'            => (string) $row->ip,
			'network'       => $identity['label'],
			'country'       => $identity['country'],
			'route'         => (string) $row->last_route,
			'first_seen'    => (string) $row->first_seen,
			'approve_url'   => $profile . '#login-armor-app-password-networks',
			'revoke_url'    => $profile . '#application-passwords-section',
		);

		$message = self::alert_message( $facts );
		$to      = trim( (string) get_option( 'login_armor_notify_email', '' ) );
		if ( '' === $to ) {
			$to = (string) get_option( 'admin_email' );
		}
		wp_mail( $to, $message['subject'], $message['body'] );

		/**
		 * Fires after an application password was used from a new network.
		 *
		 * @since 2.9.0
		 *
		 * @param int                  $user_id Owner of the password.
		 * @param string               $uuid    Password identifier.
		 * @param array<string,string> $facts   What the alert says.
		 */
		do_action( 'login_armor_app_password_new_network', $user_id, (string) $row->uuid, $facts );
	}

	/**
	 * Subject and body of the alert. Pure.
	 *
	 * @param array<string,string> $f Facts, see alert().
	 * @return array{subject:string,body:string}
	 */
	public static function alert_message( array $f ): array {
		$subject = sprintf(
			/* translators: %s: site name. */
			__( '[%s] Login Armor: an application password was used from a new network', 'login-armor' ),
			$f['site']
		);

		$lines = array(
			sprintf(
				/* translators: 1: application password name, 2: account login. */
				__( 'The application password "%1$s" of the account %2$s was just used from a network it had never been used from.', 'login-armor' ),
				$f['password_name'],
				$f['user_login']
			),
			'',
			/* translators: %s: IP address. */
			sprintf( __( 'Address: %s', 'login-armor' ), $f['ip'] ),
			/* translators: %s: network or hosting provider. */
			sprintf( __( 'Network: %s', 'login-armor' ), $f['network'] ),
		);
		if ( '' !== $f['country'] ) {
			/* translators: %s: two-letter country code. */
			$lines[] = sprintf( __( 'Country: %s', 'login-armor' ), $f['country'] );
		}
		/* translators: %s: request path. */
		$lines[] = sprintf( __( 'Request: %s', 'login-armor' ), $f['route'] );
		/* translators: %s: date and time. */
		$lines[] = sprintf( __( 'First request: %s UTC', 'login-armor' ), $f['first_seen'] );
		$lines[] = '';
		$lines[] = __( 'If this is one of your services, approve the network so it is not reported again:', 'login-armor' );
		$lines[] = $f['approve_url'];
		$lines[] = __( 'If it is not, revoke the password:', 'login-armor' );
		$lines[] = $f['revoke_url'];

		return array(
			'subject' => $subject,
			'body'    => implode( "\n", $lines ),
		);
	}
}
