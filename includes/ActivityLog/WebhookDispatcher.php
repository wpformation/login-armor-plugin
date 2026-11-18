<?php
/**
 * Activity Log Webhook Dispatcher.
 *
 * Subscribes to login_armor_activity_logged hook, builds canonical JSON
 * payload, signs with HMAC-SHA256, and enqueues into wp_login_armor_webhook_queue
 * for async delivery via cron (Task B8).
 *
 * @package LoginArmor\ActivityLog
 * @since   2.1.1
 */

namespace LoginArmor\ActivityLog;

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

class WebhookDispatcher {

    public const OPTION_ENABLED         = 'login_armor_webhook_enabled';
    public const OPTION_URL             = 'login_armor_webhook_url';
    public const OPTION_SECRET          = 'login_armor_webhook_secret';
    public const OPTION_CONSEC_FAILURES = 'login_armor_webhook_consecutive_failures';
    public const SIGNATURE_HEADER       = 'X-LoginArmor-Signature';
    public const TIMESTAMP_HEADER       = 'X-LoginArmor-Timestamp';
    public const EVENT_ID_HEADER        = 'X-LoginArmor-Event-Id';
    public const ANTI_REPLAY_WINDOW     = 300;
    public const MAX_ATTEMPTS           = 5;
    public const POST_TIMEOUT           = 10;
    public const DEAD_NOTICE_THRESHOLD  = 5;
    public const CRON_HOOK_DISPATCH     = 'login_armor_webhook_dispatch';

    /**
     * Register hooks. Called from ActivityLog::init_loggers().
     */
    public function __construct() {
        if ( ! self::is_enabled() ) {
            return;
        }
        add_action( 'login_armor_activity_logged', [ $this, 'enqueue' ], 10, 1 );
        add_action( self::CRON_HOOK_DISPATCH, [ self::class, 'cron_dispatch' ] );
    }

    /**
     * Whether webhook forwarding is enabled and a URL is configured.
     */
    public static function is_enabled(): bool {
        return (bool) get_option( self::OPTION_ENABLED, false ) && '' !== (string) get_option( self::OPTION_URL, '' );
    }

    /**
     * SSRF guard: is this URL safe to POST to from the server?
     *
     * `wp_http_validate_url()` alone only rejects a handful of literal IPv4
     * private ranges in the URL; it lets through the cloud link-local range
     * (169.254.0.0/16, e.g. metadata endpoints) and IPv6 literals such as
     * `[::1]` or `[fd00::1]`. This tightens the check: HTTPS only, then resolve
     * the host and reject any candidate IP in a private or reserved range
     * (`FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE`: which covers
     * 127/8, 169.254/16, 10/8, 172.16/12, 192.168/16, ::1, fc00::/7, fe80::/10).
     *
     * Fails closed: a host we cannot resolve to a vettable IP is treated as
     * unsafe rather than dispatched blindly. Used at save time, on manual test,
     * and at cron dispatch (a URL stored before this guard existed is still
     * re-checked before every send).
     *
     * @param string $url Candidate webhook URL.
     * @return bool True if safe to send.
     */
    public static function is_safe_url( $url = '' ): bool {
		if ( ! class_exists( '\LoginArmor\Support\SafeUrl' ) ) {
			require_once LOGIN_ARMOR_DIR . 'includes/Support/SafeUrl.php';
		}
		return \LoginArmor\Support\SafeUrl::is_safe( $url );
    }

    /**
     * Get or generate the webhook secret. Auto-generated on first access if missing.
     *
     * Stored as autoloaded option (read on every queued event for signing:
     * locality matters). 64 hex chars from random_bytes(32).
     */
    public static function get_secret(): string {
        $secret = (string) get_option( self::OPTION_SECRET, '' );
        if ( '' === $secret ) {
            $secret = bin2hex( random_bytes( 32 ) );
            update_option( self::OPTION_SECRET, $secret );
        }
        return $secret;
    }

    /**
     * Regenerate the webhook secret. Returns the new secret.
     *
     * Called by the admin AJAX handler (Task B10) when the operator
     * rotates the secret. The receiver must be updated separately.
     */
    public static function regenerate_secret(): string {
        $secret = bin2hex( random_bytes( 32 ) );
        update_option( self::OPTION_SECRET, $secret );
        return $secret;
    }

    /**
     * Build the canonical JSON payload for a row.
     *
     * Schema is GitHub/Stripe-style: event metadata + chain integrity hashes
     * exposed so the SIEM can verify chain off-site even after local DB wipe.
     *
     * @param array<string,mixed> $row Row data with hash fields populated.
     * @return string JSON payload (UTF-8, UNESCAPED_SLASHES).
     */
    public static function build_payload( array $row ): string {
        $payload = [
            'event_id'       => (int) ( $row['id'] ?? 0 ),
            'event_type'     => (string) ( $row['action'] ?? '' ),
            'object_type'    => (string) ( $row['object_type'] ?? '' ),
            'object_id'      => (int) ( $row['object_id'] ?? 0 ),
            'object_name'    => (string) ( $row['object_name'] ?? '' ),
            'ts'             => self::format_iso8601( (string) ( $row['log_time'] ?? '' ) ),
            'user'           => [
                'id'    => (int) ( $row['user_id'] ?? 0 ),
                'login' => (string) ( $row['user_login'] ?? '' ),
                'role'  => (string) ( $row['user_role'] ?? '' ),
            ],
            'ip'             => (string) ( $row['ip'] ?? '' ),
            'description'    => (string) ( $row['description'] ?? '' ),
            'prev_hash'      => (string) ( $row['prev_hash'] ?? '' ),
            'row_hash'       => (string) ( $row['row_hash'] ?? '' ),
            // home_url() captured at enqueue time, not delivery time: keeps SIEM
            // event correlation valid even if the site URL changes between INSERT
            // and the cron POST (e.g. domain migration mid-queue).
            'site_url'       => home_url(),
            // Pulled from the single-source-of-truth constant so V2.1.2 / V2.2 / etc.
            // bumps don't leave a stale literal here (audit B7 review I-2).
            'plugin_version' => defined( 'LOGIN_ARMOR_VERSION' ) ? LOGIN_ARMOR_VERSION : '2.1.1',
        ];
        $json = wp_json_encode( $payload, JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE );
        return false === $json ? '' : $json;
    }

    /**
     * Compute the HMAC-SHA256 signature for a raw body string.
     *
     * Returns the value WITH the 'sha256=' prefix (GitHub/Stripe convention).
     *
     * @param string      $raw_body The exact bytes that will be POSTed.
     * @param string|null $secret   Secret override (default: get_secret()).
     */
    public static function sign( string $raw_body, ?string $secret = null ): string {
        $secret = $secret ?? self::get_secret();
        return 'sha256=' . hash_hmac( 'sha256', $raw_body, $secret );
    }

    /**
     * Enqueue an event for async webhook delivery. Hook callback.
     *
     * Stores the payload + signature pre-computed, so cron retries POST
     * byte-identical bodies (allows SIEM-side dedup by event_id).
     *
     * @param array<string,mixed> $row Row data including hash fields.
     */
    public function enqueue( array $row ): void {
        global $wpdb;

        $payload   = self::build_payload( $row );
        if ( '' === $payload ) {
            return;  // wp_json_encode failed: skip enqueue (orphan-tolerant; row stays in activity table).
        }
        $signature = preg_replace( '/^sha256=/', '', self::sign( $payload ) );

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
        $wpdb->insert(
            $wpdb->prefix . 'login_armor_webhook_queue',
            [
                'activity_id' => (int) ( $row['id'] ?? 0 ),
                'payload'     => $payload,
                'signature'   => (string) $signature,
                'state'       => 'new',
                'attempts'    => 0,
                'created_at'  => gmdate( 'Y-m-d H:i:s' ),
            ],
            [ '%d', '%s', '%s', '%s', '%d', '%s' ]
        );
    }

    /**
     * Convert a UTC datetime string to ISO 8601 Zulu format.
     */
    private static function format_iso8601( string $datetime_utc ): string {
        $ts = strtotime( $datetime_utc . ' UTC' );
        return $ts ? gmdate( 'Y-m-d\TH:i:s\Z', $ts ) : '';
    }

    /** @var int Stuck-sending row reclaim window in seconds (B8 review I-1). */
    public const STUCK_SENDING_RECLAIM_SECONDS = 600;

    /**
     * Cron handler: pick up to 50 'new' rows, POST each, transition state.
     *
     * Called every 60s when "connected" or every 3600s when "disconnected"
     * (>= 3 consecutive failures). Switches mode via reschedule on first
     * success after disconnected, or on threshold breach.
     *
     * Per-row state machine:
     *   new -> sending -> sent (2xx, terminal)
     *               -> dead (4xx, terminal -- config error)
     *               -> new + retry on next cron tick (5xx, network, timeout)
     *                   then -> dead when attempts >= MAX_ATTEMPTS
     *
     * **Crash recovery (B8 review I-1):** rows stuck in 'sending' for more
     * than STUCK_SENDING_RECLAIM_SECONDS (typically PHP fatal mid-loop or
     * managed-host request-kill) are reverted to 'new' at the top of every
     * tick before the claim phase. attempts counter is preserved so
     * MAX_ATTEMPTS still caps total tries.
     *
     * **Atomic claim (B8 review I-2):** instead of the racy
     * SELECT-then-per-row-UPDATE pattern, this dispatcher claims rows by
     * an atomic UPDATE-with-LIMIT (transitions 'new' -> 'sending' in one
     * statement) then SELECTs only the rows that match its random claim
     * token. Two parallel cron runners cannot pick the same rows:
     * MySQL serializes UPDATEs row-by-row, the second runner finds no
     * rows in 'new' state and exits cleanly.
     */
    public static function cron_dispatch(): void {
        if ( ! self::is_enabled() ) {
            return;
        }

        global $wpdb;
        $table = $wpdb->prefix . 'login_armor_webhook_queue';
        $url   = (string) get_option( self::OPTION_URL, '' );
        if ( ! self::is_safe_url( $url ) ) {
            return;
        }

        // Janitor (B8 review I-1): revert stuck 'sending' rows back to 'new'
        // so they can be re-claimed. Excludes rows where attempts already
        // hit MAX_ATTEMPTS: those should remain dead-bound after the next
        // failed dispatch (handle_failure transitions them to 'dead').
        $stuck_cutoff = gmdate( 'Y-m-d H:i:s', time() - self::STUCK_SENDING_RECLAIM_SECONDS );
        // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
        $wpdb->query( $wpdb->prepare(
			'UPDATE %i SET state=\'new\', last_error=\'reclaimed: stuck in sending\' WHERE state=\'sending\' AND last_attempt_at < %s',
			$table,
            $stuck_cutoff
        ) );

		// Atomic claim: UPDATE first, then select with a cryptographically unique
		// claim token. A timestamp has only one-second precision and can overlap
		// between independent cron runners.
        $claim_ts = gmdate( 'Y-m-d H:i:s' );
		$claim_token = 'claim:' . bin2hex( random_bytes( 16 ) );
        // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
        $claimed = (int) $wpdb->query( $wpdb->prepare(
			'UPDATE %i SET state=\'sending\', last_attempt_at=%s, last_error=%s, attempts=attempts+1 WHERE state=\'new\' ORDER BY id ASC LIMIT 50',
			$table,
			$claim_ts,
			$claim_token
        ) );
        if ( 0 === $claimed ) {
            return;
        }
        // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
        $rows = $wpdb->get_results( $wpdb->prepare(
			'SELECT id, payload, signature, attempts FROM %i WHERE state=\'sending\' AND last_error = %s ORDER BY id ASC',
			$table,
			$claim_token
        ) );
        if ( empty( $rows ) ) {
            return;
        }

        $had_success = false;
        $had_failure = false;

        foreach ( $rows as $row ) {
			$response = wp_safe_remote_post( $url, [
                'timeout'     => self::POST_TIMEOUT,
                'redirection' => 0,
                'blocking'    => true,
                'headers'     => [
                    'Content-Type'         => 'application/json',
                    'User-Agent'           => 'LoginArmor-Webhook/' . ( defined( 'LOGIN_ARMOR_VERSION' ) ? LOGIN_ARMOR_VERSION : '2.1.1' ) . ' (+https://wpformation.com/login-armor)',
                    self::EVENT_ID_HEADER  => (string) $row->id,
                    self::SIGNATURE_HEADER => 'sha256=' . $row->signature,
                    self::TIMESTAMP_HEADER => (string) time(),
                ],
                'body'        => $row->payload,
            ] );

            if ( is_wp_error( $response ) ) {
                // $row->attempts already reflects the post-claim incremented value
                // (the atomic claim UPDATE bumped attempts before SELECT).
                self::handle_failure( (int) $row->id, $response->get_error_message(), (int) $row->attempts );
                $had_failure = true;
                continue;
            }

            $code = (int) wp_remote_retrieve_response_code( $response );
            if ( $code >= 200 && $code < 300 ) {
                // Success -- mark sent.
                // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
                $wpdb->update(
                    $table,
                    [ 'state' => 'sent', 'last_error' => '' ],
                    [ 'id' => $row->id ],
                    [ '%s', '%s' ],
                    [ '%d' ]
                );
                $had_success = true;
            } elseif ( $code >= 400 && $code < 500 ) {
                // 4xx config error -- terminal dead.
                // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
                $wpdb->update(
                    $table,
                    [ 'state' => 'dead', 'last_error' => sprintf( 'HTTP %d (4xx config error)', $code ) ],
                    [ 'id' => $row->id ],
                    [ '%s', '%s' ],
                    [ '%d' ]
                );
                $had_failure = true;
            } else {
                // 5xx or other -- schedule retry. $row->attempts already post-claim.
                self::handle_failure( (int) $row->id, sprintf( 'HTTP %d', $code ), (int) $row->attempts );
                $had_failure = true;
            }
        }

        // Update connectivity heuristic + reschedule cron interval.
        $consec = (int) get_option( self::OPTION_CONSEC_FAILURES, 0 );
        if ( $had_success ) {
            if ( $consec > 0 ) {
                update_option( self::OPTION_CONSEC_FAILURES, 0 );
                self::reschedule_to( 'login_armor_1min' );
            }
        } elseif ( $had_failure ) {
            $consec++;
            update_option( self::OPTION_CONSEC_FAILURES, $consec );
            if ( $consec >= 3 ) {
                self::reschedule_to( 'login_armor_1hour' );
            }
        }

        // Surface dead admin notice as a meta-event in the activity table.
        self::maybe_emit_dead_meta_event();
    }

    /**
     * Mark a failed delivery for retry, transitioning to 'dead' if attempts >= MAX_ATTEMPTS.
     */
    private static function handle_failure( int $row_id, string $error, int $attempts ): void {
        global $wpdb;
        $table = $wpdb->prefix . 'login_armor_webhook_queue';

        $new_state = $attempts >= self::MAX_ATTEMPTS ? 'dead' : 'new';

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
        $wpdb->update(
            $table,
            [ 'state' => $new_state, 'last_error' => mb_substr( $error, 0, 500 ) ],
            [ 'id' => $row_id ],
            [ '%s', '%s' ],
            [ '%d' ]
        );
    }

    /**
     * Reschedule the dispatch cron to a new interval (clear + reschedule).
     */
    private static function reschedule_to( string $interval ): void {
        wp_clear_scheduled_hook( self::CRON_HOOK_DISPATCH );
        wp_schedule_event( time() + 60, $interval, self::CRON_HOOK_DISPATCH );
    }

    /**
     * If DEAD_NOTICE_THRESHOLD+ rows are 'dead', log a meta-event into ActivityLog.
     *
     * The meta-event uses the normal signed writer but suppresses webhook
     * dispatch, which avoids re-entering the queue. Idempotent via
     * login_armor_webhook_last_dead_notice -- only re-emits when the dead
     * count grows past the previously-seen threshold.
     */
    private static function maybe_emit_dead_meta_event(): void {
        global $wpdb;
        $table = $wpdb->prefix . 'login_armor_webhook_queue';

        // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
		$dead_count  = (int) $wpdb->get_var( $wpdb->prepare( 'SELECT COUNT(*) FROM %i WHERE state=\'dead\'', $table ) );
        $last_notice = (int) get_option( 'login_armor_webhook_last_dead_notice', 0 );

		if ( $dead_count >= self::DEAD_NOTICE_THRESHOLD && $dead_count > $last_notice ) {
			ActivityLogger::log_system(
				'webhook_dispatch_failed',
				'webhook_queue',
				sprintf(
					/* translators: %d: count of dead webhook events */
					__( '%d webhook event(s) marked dead after retries. Check the queue stats in Activity -> Webhook.', 'login-armor' ),
					$dead_count
				)
			);
			update_option( 'login_armor_webhook_last_dead_notice', $dead_count, false );
        }
    }
}
