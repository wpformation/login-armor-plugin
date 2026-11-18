<?php
/**
 * Two-Factor account recovery.
 *
 * When a user has lost access to every 2FA method, they can click
 * « Request 2FA reset » on the verify screen. The request is rate-limited
 * (1 per user per 24h, silent second request to prevent enumeration) and
 * emails a single-use HMAC-signed token to the first site admin. If the admin
 * clicks the link, TwoFactor::reset_user() is called server-side, the user
 * is back to pre-2FA state and must reconfigure from scratch.
 *
 * @package LoginArmor\TwoFactor
 * @since   2.0.0
 */

namespace LoginArmor\TwoFactor;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Recovery {

	/** @var string Option key: global toggle. */
	public const OPTION_ENABLED = 'login_armor_2fa_recovery_enabled';

	/** @var string user_meta key: last-request timestamp for 1/24h rate-limit. */
	public const META_SENT_AT = 'login_armor_2fa_recovery_sent_at';

	/** @var string Transient prefix for pending tokens. */
	public const TOKEN_PREFIX = 'login_armor_2fa_recov_';

	/** @var int Token TTL: 1 hour. */
	public const TOKEN_TTL = HOUR_IN_SECONDS;

	/** @var string URL verb on wp-login.php / Hide Login slug for the request form. */
	public const PARAM_REQUEST = 'recovery';

	/**
	 * Former URL verb of the admin confirmation step, on the login screen.
	 *
	 * Kept as a constant for code that may reference it. Since 2.8.0 the
	 * confirmation is served by admin-post.php (see ADMIN_ACTION), and the
	 * login screen no longer answers this verb.
	 */
	public const PARAM_CONFIRM = 'recovery-confirm';

	/**
	 * admin-post.php action of the admin confirmation step (2.8.0).
	 *
	 * Until 2.7.10 the e-mailed link opened the login screen, and it never
	 * worked, from 2.0.0 on: it was built with `recovery-confirm=go`, which the
	 * router does not read, and with Hide Login on, the slug sends a signed-in
	 * administrator to the dashboard before the router ever runs. The step
	 * belongs to a signed-in administrator anyway, so it now lives on the
	 * administration side, where neither the login screen nor Hide Login (nor
	 * another plugin that redirects wp-login.php) stands in the way.
	 */
	public const ADMIN_ACTION = 'login_armor_2fa_recovery_confirm';

	/** @var int Rate-limit window in seconds. */
	private const RATE_WINDOW = DAY_IN_SECONDS;

	/** @var string Per-account atomic rate-limit option prefix. */
	private const CLAIM_PREFIX = 'login_armor_2fa_recovery_claim_';

	public static function is_feature_enabled(): bool {
		return (bool) get_option( self::OPTION_ENABLED, true );
	}

	/**
	 * True when the user has requested a recovery in the last RATE_WINDOW.
	 */
	public static function is_rate_limited( int $user_id ): bool {
		global $wpdb;

		$last = (int) get_user_meta( $user_id, self::META_SENT_AT, true );
		$key  = self::claim_key( $user_id );

		// Read directly so a cached pre-claim miss cannot let a concurrent request through.
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Security rate limit requires the current atomic-claim row.
		$claimed_at = (int) $wpdb->get_var(
			$wpdb->prepare( "SELECT option_value FROM {$wpdb->options} WHERE option_name = %s", $key )
		);
		$last = max( $last, $claimed_at );

		return ( time() - $last ) < self::RATE_WINDOW;
	}

	/**
	 * Return the account from the signed pending-2FA session.
	 *
	 * The cookie is minted only after WordPress has accepted the primary
	 * password. Requiring both its HMAC and the matching live transient removes
	 * the public username/email recovery trigger entirely.
	 */
	public static function get_pending_user_id(): int {
		require_once __DIR__ . '/PendingCookie.php';

		$pending = PendingCookie::read();
		if ( ! is_array( $pending ) || empty( $pending['user_id'] ) || empty( $pending['token'] ) ) {
			return 0;
		}

		$token_data = TwoFactor::get_token( (string) $pending['token'] );
		if ( ! is_array( $token_data ) || empty( $token_data['user_id'] ) ) {
			return 0;
		}

		$user_id = (int) $pending['user_id'];
		if ( $user_id <= 0 || $user_id !== (int) $token_data['user_id'] || ! TwoFactor::is_user_enabled( $user_id ) ) {
			return 0;
		}

		return $user_id;
	}

	/**
	 * Non-reversible per-account option name for the recovery quota.
	 */
	private static function claim_key( int $user_id ): string {
		return self::CLAIM_PREFIX . substr( hash_hmac( 'sha256', (string) $user_id, wp_salt( 'auth' ) ), 0, 32 );
	}

	/**
	 * Atomically reserve this account's one recovery email per day.
	 */
	private static function acquire_claim( int $user_id ): int|false {
		global $wpdb;

		$key    = self::claim_key( $user_id );
		$now    = time();
		$cutoff = $now - self::RATE_WINDOW;

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.NotPrepared -- Atomic claim via the unique option_name index.
		$inserted = $wpdb->query(
			$wpdb->prepare(
				"INSERT IGNORE INTO {$wpdb->options} (option_name, option_value, autoload) VALUES (%s, %s, 'no')",
				$key,
				(string) $now
			)
		);

		if ( $inserted ) {
			wp_cache_delete( $key, 'options' );
			return $now;
		}

		// A single conditional update lets only one racer replace an expired claim.
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.NotPrepared -- Atomic compare-and-swap on plugin-owned option.
		$updated = $wpdb->query(
			$wpdb->prepare(
				"UPDATE {$wpdb->options} SET option_value = %s WHERE option_name = %s AND CAST(option_value AS UNSIGNED) <= %d",
				(string) $now,
				$key,
				$cutoff
			)
		);

		if ( $updated ) {
			wp_cache_delete( $key, 'options' );
			return $now;
		}

		return false;
	}

	/**
	 * Remove expired per-account recovery claims.
	 *
	 * @return int Number of deleted option rows.
	 */
	public static function purge_claims(): int {
		global $wpdb;

		$cutoff = time() - self::RATE_WINDOW;
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Maintenance cleanup of plugin-owned claims.
		$deleted = (int) $wpdb->query(
			$wpdb->prepare(
				"DELETE FROM {$wpdb->options} WHERE option_name LIKE %s AND CAST(option_value AS UNSIGNED) <= %d",
				$wpdb->esc_like( self::CLAIM_PREFIX ) . '%',
				$cutoff
			)
		);

		if ( $deleted > 0 ) {
			wp_cache_flush_group( 'options' );
		}

		return $deleted;
	}

	/**
	 * Return the site admin who receives recovery emails.
	 *
	 * First admin by ID ASC; on multisite, the first super-admin: only an
	 * account that manages the network's users may confirm the reset
	 * (handle_confirm()), so a site administrator would get a link they
	 * cannot use. Never the account being recovered: it cannot confirm its
	 * own reset, nor sign in to do it.
	 *
	 * @param int $exclude_user_id The account the reset is for.
	 */
	public static function get_recipient_admin( int $exclude_user_id = 0 ): ?\WP_User {
		if ( is_multisite() ) {
			foreach ( get_super_admins() as $login ) {
				$user = get_user_by( 'login', $login );
				if ( $user instanceof \WP_User && $user->ID !== $exclude_user_id ) {
					return $user;
				}
			}
			return null;
		}
		$admins = get_users( [
			'role'    => 'administrator',
			'orderby' => 'ID',
			'order'   => 'ASC',
			'number'  => 1,
			'exclude' => $exclude_user_id > 0 ? [ $exclude_user_id ] : [],
		] );
		return ! empty( $admins ) && $admins[0] instanceof \WP_User ? $admins[0] : null;
	}

	/**
	 * Mint an HMAC-signed recovery token, store it in a transient, return the URL.
	 *
	 * Token format: <user_id>.<nonce>.<expires_at>.<signature>, nonce is 16 bytes
	 * hex, signature is hash_hmac('sha256', user_id|nonce|expires_at, wp_salt('auth')).
	 * The transient is keyed on the nonce only (user_id is surfaced in the token)
	 * so a stolen transient key cannot be used without the HMAC. Use-once via
	 * delete_transient on consume.
	 */
	public static function mint_token( int $user_id ): array {
		$nonce      = bin2hex( random_bytes( 16 ) );
		$expires_at = time() + self::TOKEN_TTL;
		$signature  = hash_hmac(
			'sha256',
			$user_id . '|' . $nonce . '|' . $expires_at,
			wp_salt( 'auth' )
		);
		set_transient(
			self::TOKEN_PREFIX . $nonce,
			[
				'user_id'    => $user_id,
				'expires_at' => $expires_at,
				'ip'         => \LoginArmor\LoginArmor::get_client_ip(),
				'ua'         => isset( $_SERVER['HTTP_USER_AGENT'] ) ? substr( sanitize_text_field( wp_unslash( (string) $_SERVER['HTTP_USER_AGENT'] ) ), 0, 255 ) : '',
			],
			self::TOKEN_TTL
		);
		$value = $user_id . '.' . $nonce . '.' . $expires_at . '.' . $signature;
		return [ 'nonce' => $nonce, 'value' => $value, 'url' => self::confirm_url( $value ) ];
	}

	/**
	 * The URL the administrator opens to review and authorize a reset (2.8.0).
	 *
	 * @param string $token Signed token minted by mint_token().
	 */
	public static function confirm_url( string $token ): string {
		return add_query_arg(
			[
				'action' => self::ADMIN_ACTION,
				'token'  => rawurlencode( $token ),
			],
			admin_url( 'admin-post.php' )
		);
	}

	/**
	 * Verify a token returned via URL and return the user_id + transient payload
	 * on success. Returns null on any failure (expired, bad signature, missing
	 * transient, wrong format). Does NOT consume the token: the caller does.
	 *
	 * @return array{user_id:int,ip:string,ua:string,nonce:string}|null
	 */
	public static function verify_token( string $raw ): ?array {
		$parts = explode( '.', $raw );
		if ( 4 !== count( $parts ) ) { return null; }
		[ $user_id_raw, $nonce, $expires_raw, $signature ] = $parts;
		if (
			! ctype_digit( $user_id_raw )
			|| ! preg_match( '/^[a-f0-9]{32}$/', $nonce )
			|| ! ctype_digit( $expires_raw )
			|| ! preg_match( '/^[a-f0-9]{64}$/', $signature )
		) {
			return null;
		}
		$user_id    = (int) $user_id_raw;
		$expires_at = (int) $expires_raw;
		if ( $expires_at <= time() ) { return null; }

		$expected = hash_hmac(
			'sha256',
			$user_id . '|' . $nonce . '|' . $expires_at,
			wp_salt( 'auth' )
		);
		if ( ! hash_equals( $expected, $signature ) ) { return null; }

		$payload = get_transient( self::TOKEN_PREFIX . $nonce );
		if ( ! is_array( $payload ) || empty( $payload['user_id'] ) ) { return null; }
		if ( ! hash_equals( (string) $user_id, (string) $payload['user_id'] ) ) { return null; }

		return [
			'user_id' => $user_id,
			'ip'      => (string) ( $payload['ip'] ?? '' ),
			'ua'      => (string) ( $payload['ua'] ?? '' ),
			'nonce'   => $nonce,
		];
	}

	/**
	 * Consume the token. Returns true only if the transient existed and this call
	 * removed it (atomic across concurrent clicks).
	 */
	public static function consume_token( string $nonce ): bool {
		return (bool) delete_transient( self::TOKEN_PREFIX . $nonce );
	}

	/**
	 * Handle the user submitting the « Request 2FA reset » form.
	 *
	 * ALWAYS returns to the « sent » generic screen: we never expose whether the
	 * user exists, whether 2FA was on, or whether a rate-limit was hit. Silent
	 * second-request behavior per the spec.
	 *
	 * @param int $user_id Account bound to the signed pending-2FA session.
	 */
	public static function handle_request( int $user_id ): void {
		if ( ! self::is_feature_enabled() ) {
			self::render_sent_screen();
			return;
		}
		if ( $user_id <= 0 || $user_id !== self::get_pending_user_id() ) {
			self::render_sent_screen();
			return;
		}

		$user = get_userdata( $user_id );
		if ( ! $user instanceof \WP_User ) {
			self::render_sent_screen();
			return;
		}
		if ( ! TwoFactor::is_user_enabled( $user->ID ) ) {
			self::render_sent_screen();
			return;
		}
		if ( self::is_rate_limited( $user->ID ) ) {
			self::render_sent_screen();
			return;
		}

		$admin = self::get_recipient_admin( $user->ID );
		if ( ! $admin instanceof \WP_User ) {
			self::render_sent_screen();
			return;
		}

		$claimed_at = self::acquire_claim( $user->ID );
		if ( false === $claimed_at ) {
			self::render_sent_screen();
			return;
		}
		// Consumed on dispatch attempt, not on reported delivery. wp_mail() only
		// confirms that WordPress handed the message to its mail transport; false
		// is not a safe reason to reopen an otherwise atomic daily quota.
		update_user_meta( $user->ID, self::META_SENT_AT, $claimed_at );

		$token = self::mint_token( $user->ID );

		$subject = sprintf(
			/* translators: %s: site name */
			__( '[%s] 2FA reset request', 'login-armor' ),
			wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES )
		);
		$body = sprintf(
			/* translators: 1: user login, 2: user email, 3: requester IP, 4: UA, 5: confirmation URL */
			__( "A two-factor reset was requested for user %1\$s (%2\$s).\n\nIP: %3\$s\nUser-Agent: %4\$s\n\nIf you authorize this reset, sign in to your site as an administrator, then open the link below. It shows the request again and asks you to confirm. It expires in 1 hour and can only be used once.\n\n%5\$s\n\nIf you did not expect this request, ignore this email: no action will be taken.", 'login-armor' ),
			$user->user_login,
			$user->user_email,
			\LoginArmor\LoginArmor::get_client_ip(),
			isset( $_SERVER['HTTP_USER_AGENT'] ) ? substr( sanitize_text_field( wp_unslash( (string) $_SERVER['HTTP_USER_AGENT'] ) ), 0, 255 ) : '',
			$token['url']
		);
		$mail_sent = wp_mail( $admin->user_email, $subject, $body );
		if ( ! $mail_sent ) {
			delete_transient( self::TOKEN_PREFIX . $token['nonce'] );
			self::render_sent_screen();
			return;
		}

		/**
		 * Fires after a 2FA recovery request has been emailed to the admin.
		 *
		 * @param int      $user_id Requested user.
		 * @param \WP_User $admin   Recipient admin.
		 */
		do_action( 'login_armor_2fa_recovery_requested', $user->ID, $admin );

		$ip = \LoginArmor\LoginArmor::get_client_ip();
		if ( '' !== $ip ) {
			$existing = \LoginArmor\Detection\Incident::find_active( \LoginArmor\Detection\Incident::PATTERN_2FA_RECOVERY_REQUESTED, $ip, 'ip', 60 );
			$now = current_time( 'mysql', true );
			if ( $existing instanceof \LoginArmor\Detection\Incident ) {
				// 2.7.1: the SECOND request from the same address inside the
				// window is not the owner of an account being unlucky, it is
				// somebody working on that account, so it stops being an
				// observation and starts asking for attention.
				//
				// This became load-bearing in 2.7.1. Severity 1 now means
				// "observed, not something to act on", and it is filtered out
				// of the Incidents list by default. This pattern never
				// escalated, so without this line a flood of recovery requests
				// would sit for ever at the one severity the screen no longer
				// shows: the counting change would have HIDDEN an account
				// takeover attempt. A single request stays quiet, because the
				// administrator already received the e-mail that carries the
				// confirmation link, and that e-mail is the actionable channel.
				$existing->increment_occurrence( \LoginArmor\Detection\Incident::SEVERITY_MEDIUM, 1, 1, 1 );
				do_action( 'login_armor_incident_created', $existing, false );
			} else {
				$incident                   = new \LoginArmor\Detection\Incident();
				$incident->pattern          = \LoginArmor\Detection\Incident::PATTERN_2FA_RECOVERY_REQUESTED;
				$incident->severity         = \LoginArmor\Detection\Incident::SEVERITY_LOW;
				$incident->started_at       = $now;
				$incident->last_seen_at     = $now;
				$incident->ip               = $ip;
				$incident->subnet           = '';
				$incident->target_username  = substr( $user->user_login, 0, 60 );
				$incident->events_count     = 1;
				$incident->unique_ips       = 1;
				$incident->unique_usernames = 1;
				$incident->status           = \LoginArmor\Detection\Incident::STATUS_ACTIVE;
				$incident->insert();
				do_action( 'login_armor_incident_created', $incident, true );
			}
		}

		self::render_sent_screen();
	}

	/**
	 * Render the generic « request received » screen. Always the same message:
	 * no hint about account existence.
	 */
	public static function render_sent_screen(): void {
		require LOGIN_ARMOR_DIR . 'admin/views/two-factor-recovery-sent.php';
		exit;
	}

	/**
	 * admin-post.php entry point for a signed-in visitor (2.8.0).
	 *
	 * The token travels in the URL on GET and in a hidden field on POST, so
	 * it is read from either; admin-post.php has already routed on `action`.
	 */
	public static function handle_admin_post(): void {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Lookup key only: verify_token() authenticates it (HMAC + live transient), and the POST branch of handle_confirm() checks a nonce before any change.
		$token = isset( $_REQUEST['token'] ) && is_string( $_REQUEST['token'] ) ? sanitize_text_field( wp_unslash( $_REQUEST['token'] ) ) : '';
		self::handle_confirm( $token );
	}

	/**
	 * admin-post.php entry point for a visitor who is not signed in (2.8.0).
	 *
	 * Says what to do and links nowhere: printing the login URL here would
	 * hand the Hide Login slug to anyone who requests this address.
	 */
	public static function handle_admin_post_nopriv(): void {
		wp_die(
			esc_html__( 'Sign in to your site as an administrator first, then open the link from the e-mail again. It stays valid for one hour after the request.', 'login-armor' ),
			esc_html__( 'Authorize 2FA reset', 'login-armor' ),
			array( 'response' => 403 )
		);
	}

	/**
	 * Handle the admin clicking the email confirmation link.
	 *
	 * On GET: render the confirmation view (asks the admin to explicitly click
	 *         an « Authorize reset » button: CSRF-protected by the nonce on POST).
	 * On POST: verify token + nonce, reset the user, revoke devices, log.
	 */
	public static function handle_confirm( string $raw_token ): void {
		if ( ! self::is_feature_enabled() ) {
			wp_die( esc_html__( '2FA recovery is disabled on this site.', 'login-armor' ), 403 );
		}
		if ( ! is_user_logged_in() || ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You must be logged in as an administrator to authorize a 2FA reset.', 'login-armor' ), 403 );
		}

		$payload = self::verify_token( $raw_token );
		if ( null === $payload ) {
			wp_die( esc_html__( 'This 2FA reset link is invalid or has expired.', 'login-armor' ), 403 );
		}
		$target = get_userdata( $payload['user_id'] );
		if ( ! $target instanceof \WP_User ) {
			wp_die( esc_html__( 'Target user no longer exists.', 'login-armor' ), 404 );
		}
		// The same gate as the reset from the user screen: the right to edit
		// THAT account, and never one's own. manage_options alone let the
		// administrator of any site of a network clear the second factor of a
		// super administrator, which is valid on every site: in multisite,
		// core grants edit_user on another account only to whoever manages
		// the network's users.
		if ( get_current_user_id() === (int) $payload['user_id'] || ! current_user_can( 'edit_user', (int) $payload['user_id'] ) ) {
			wp_die( esc_html__( 'You are not allowed to reset two-factor authentication for this user.', 'login-armor' ), 403 );
		}

		// POST: perform the reset. GET: render the confirmation view.
		if ( isset( $_SERVER['REQUEST_METHOD'] ) && 'POST' === $_SERVER['REQUEST_METHOD'] ) {
			if ( ! isset( $_POST['_wpnonce'] ) || ! wp_verify_nonce( sanitize_text_field( wp_unslash( $_POST['_wpnonce'] ) ), 'login_armor_2fa_recovery_confirm' ) ) {
				wp_die( esc_html__( 'Security check failed.', 'login-armor' ), 403 );
			}
			if ( ! self::consume_token( $payload['nonce'] ) ) {
				wp_die( esc_html__( 'This reset link has already been used.', 'login-armor' ), 403 );
			}

			TwoFactor::reset_user( $payload['user_id'] );

			/**
			 * Fires after a 2FA recovery has been completed (user is back to pre-2FA state).
			 *
			 * @param int $user_id Target user id.
			 * @param int $admin_id Admin who authorized the reset.
			 */
			do_action( 'login_armor_2fa_recovery_completed', $payload['user_id'], get_current_user_id() );

			require LOGIN_ARMOR_DIR . 'admin/views/two-factor-recovery-confirm.php';
			exit;
		}

		// GET: show the confirmation form.
		$la_recov_target = $target;
		$la_recov_ip     = (string) $payload['ip'];
		$la_recov_ua     = (string) $payload['ua'];
		$la_recov_token  = $raw_token;
		require LOGIN_ARMOR_DIR . 'admin/views/two-factor-recovery-confirm.php';
		exit;
	}

	/**
	 * Entry-point registered from TwoFactor::register_hooks(), routes based on
	 * URL verb (recovery request form, sent screen, confirmation page).
	 */
	public static function maybe_render(): void {
		if ( ! isset( $_GET[ TwoFactor::VERIFY_PARAM ] ) ) { return; } // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Dispatch guard; POST-handling branches verify nonces individually before any state change.
		$verb = sanitize_key( wp_unslash( (string) $_GET[ TwoFactor::VERIFY_PARAM ] ) ); // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Same as above; nonces are checked before side effects.

		if ( self::PARAM_REQUEST === $verb ) {
			$user_id = self::get_pending_user_id();
			if ( $user_id <= 0 ) {
				wp_safe_redirect( add_query_arg( 'login_armor_error', '2fa_expired', \LoginArmor\HideLogin::get_login_url() ) );
				exit;
			}

			if ( isset( $_SERVER['REQUEST_METHOD'] ) && 'POST' === $_SERVER['REQUEST_METHOD'] ) {
				if ( ! isset( $_POST['_wpnonce'] ) || ! wp_verify_nonce( sanitize_text_field( wp_unslash( $_POST['_wpnonce'] ) ), 'login_armor_2fa_recovery_request' ) ) {
					wp_die( esc_html__( 'Security check failed.', 'login-armor' ), 403 );
				}
				self::handle_request( $user_id );
				return;
			}
			require LOGIN_ARMOR_DIR . 'admin/views/two-factor-recovery-request.php';
			exit;
		}

		// 2.8.0: the confirmation verb is no longer served here. The step
		// moved to admin-post.php (ADMIN_ACTION), and a reset must not be
		// reachable through two doors.
	}

	public static function register(): void {
		add_action( 'login_init', [ self::class, 'maybe_render' ] );
		add_action( 'admin_post_' . self::ADMIN_ACTION, [ self::class, 'handle_admin_post' ] );
		add_action( 'admin_post_nopriv_' . self::ADMIN_ACTION, [ self::class, 'handle_admin_post_nopriv' ] );
	}
}
