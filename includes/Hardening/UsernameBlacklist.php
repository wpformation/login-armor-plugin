<?php
/**
 * Username Blacklist: rejects login and registration attempts for
 * well-known reserved usernames (admin, root, etc.).
 *
 * Existing users whose login matches the blacklist are NOT blocked, so
 * that legitimate `admin` accounts that predate the toggle stay usable.
 * The admin UI surfaces any such overlap via a warning banner.
 *
 * @package LoginArmor
 * @since   2.0.0
 */

namespace LoginArmor\Hardening;

use LoginArmor\Detection\Incident;
use LoginArmor\LoginArmor;

// Exit if accessed directly.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Configurable username blacklist applied at login and registration.
 */
class UsernameBlacklist {

	public const OPTION_KEY = 'login_armor_hardening_username_blacklist';

	/**
	 * Default reserved names seeded on first activation.
	 *
	 * @var string[]
	 */
	public const DEFAULTS = [
		'admin', 'administrator', 'root', 'test', 'demo',
		'user', 'wp', 'www', 'webmaster', 'wordpress',
	];

	/**
	 * Return the current blacklist, lower-cased and de-duplicated.
	 *
	 * @return string[]
	 */
	public static function get_blacklist(): array {
		$stored = get_option( self::OPTION_KEY, null );
		if ( null === $stored ) {
			return self::DEFAULTS;
		}
		return is_array( $stored ) ? $stored : self::normalize( (string) $stored );
	}

	/**
	 * Confusable-character map for ASCII a-z lookalikes.
	 *
	 * Subset of the Unicode confusables list narrowed to common attack
	 * characters. iconv on Windows does not translit Latin alpha (U+0251),
	 * Cyrillic а (U+0430), or enclosed alphanumerics on its own, so we
	 * pre-fold them here before any iconv pass.
	 *
	 * Values must be lowercase ASCII; the order does not matter because
	 * strtr() applies all replacements simultaneously.
	 */
	private const CONFUSABLES = [
		"\u{0251}" => 'a', "\u{0250}" => 'a', "\u{0430}" => 'a', "\u{1FBF}" => 'a', "\u{24D0}" => 'a', "\u{FF41}" => 'a',
		"\u{0299}" => 'b', "\u{0432}" => 'b', "\u{24D1}" => 'b', "\u{FF42}" => 'b',
		"\u{03F2}" => 'c', "\u{0441}" => 'c', "\u{24D2}" => 'c', "\u{FF43}" => 'c',
		"\u{0501}" => 'd', "\u{24D3}" => 'd', "\u{FF44}" => 'd',
		"\u{0435}" => 'e', "\u{0454}" => 'e', "\u{24D4}" => 'e', "\u{FF45}" => 'e',
		"\u{24D5}" => 'f', "\u{FF46}" => 'f',
		"\u{0261}" => 'g', "\u{24D6}" => 'g', "\u{FF47}" => 'g',
		"\u{04BB}" => 'h', "\u{24D7}" => 'h', "\u{FF48}" => 'h',
		"\u{0456}" => 'i', "\u{24D8}" => 'i', "\u{FF49}" => 'i',
		"\u{0458}" => 'j', "\u{24D9}" => 'j', "\u{FF4A}" => 'j',
		"\u{043A}" => 'k', "\u{24DA}" => 'k', "\u{FF4B}" => 'k',
		"\u{0269}" => 'l', "\u{24DB}" => 'l', "\u{FF4C}" => 'l',
		"\u{043C}" => 'm', "\u{24DC}" => 'm', "\u{FF4D}" => 'm',
		"\u{0578}" => 'n', "\u{24DD}" => 'n', "\u{FF4E}" => 'n',
		"\u{043E}" => 'o', "\u{24DE}" => 'o', "\u{FF4F}" => 'o', "\u{03BF}" => 'o',
		"\u{0440}" => 'p', "\u{24DF}" => 'p', "\u{FF50}" => 'p',
		"\u{24E0}" => 'q', "\u{FF51}" => 'q',
		"\u{0433}" => 'r', "\u{24E1}" => 'r', "\u{FF52}" => 'r',
		"\u{0455}" => 's', "\u{24E2}" => 's', "\u{FF53}" => 's',
		"\u{24E3}" => 't', "\u{FF54}" => 't',
		"\u{028B}" => 'u', "\u{24E4}" => 'u', "\u{FF55}" => 'u',
		"\u{03BD}" => 'v', "\u{24E5}" => 'v', "\u{FF56}" => 'v',
		"\u{0461}" => 'w', "\u{24E6}" => 'w', "\u{FF57}" => 'w',
		"\u{0445}" => 'x', "\u{24E7}" => 'x', "\u{FF58}" => 'x',
		"\u{0443}" => 'y', "\u{24E8}" => 'y', "\u{FF59}" => 'y',
		"\u{24E9}" => 'z', "\u{FF5A}" => 'z',
	];

	/**
	 * Fold a string to its lookalike-resistant ASCII form.
	 *
	 * Three-step fold so that homoglyphs like `ɑdmin` (U+0251 Latin alpha),
	 * `аdmin` (Cyrillic а U+0430), or `ⓐdmin` (enclosed alphanumerics) all
	 * resolve to the same blacklist entry as `admin`:
	 *
	 *   1. Lowercase + trim.
	 *   2. NFD-decompose and strip combining marks via Normalizer (when intl
	 *      is available) so that diacritics like `Ådmin` lose the ring.
	 *   3. Apply the confusables map to a-z lookalikes that iconv on Windows
	 *      does not translit.
	 *   4. iconv ASCII//TRANSLIT//IGNORE as a final pass for whatever
	 *      remains.
	 *
	 * @param string $value Raw username or list entry.
	 */
	public static function fold( string $value ): string {
		$value = trim( $value );
		if ( '' === $value ) {
			return '';
		}
		// 1. Decompose first (NFD) so diacritics split off as combining marks.
		if ( class_exists( '\\Normalizer' ) ) {
			$decomposed = \Normalizer::normalize( $value, \Normalizer::FORM_KD );
			if ( is_string( $decomposed ) && '' !== $decomposed ) {
				$value = (string) preg_replace( '/\p{Mn}+/u', '', $decomposed );
			}
		}
		// 2. Lowercase via mbstring so non-ASCII uppercase (Cyrillic А, fullwidth Ａ)
		// folds before the confusables map is applied.
		$value = function_exists( 'mb_strtolower' )
			? mb_strtolower( $value, 'UTF-8' )
			: strtolower( $value );
		// 3. Map common a-z confusables (Latin alpha, Cyrillic а, fullwidth, …)
		// that iconv on Windows does not translit.
		$value = strtr( $value, self::CONFUSABLES );
		// 4. iconv ASCII//TRANSLIT//IGNORE for whatever remains. Suppress notices;
		// the //IGNORE modifier handles the failure path.
		$ascii = @iconv( 'UTF-8', 'ASCII//TRANSLIT//IGNORE', $value );
		return is_string( $ascii ) && '' !== $ascii ? $ascii : $value;
	}

	/**
	 * Normalize a raw textarea input into a clean list.
	 *
	 * @param string $raw Raw textarea contents (one per line or comma-separated).
	 * @return string[]
	 */
	public static function normalize( string $raw ): array {
		$lines = preg_split( '/[\r\n,]+/', $raw );
		$out   = [];
		if ( ! is_array( $lines ) ) {
			return $out;
		}
		foreach ( $lines as $line ) {
			$name = self::fold( (string) $line );
			if ( '' !== $name && ! in_array( $name, $out, true ) ) {
				$out[] = $name;
			}
		}
		return $out;
	}

	/**
	 * Determine whether a given username is on the blacklist.
	 *
	 * @param string $username Candidate username.
	 */
	public static function is_blacklisted( string $username ): bool {
		$needle = self::fold( $username );
		if ( '' === $needle ) {
			return false;
		}
		return in_array( $needle, self::get_blacklist(), true );
	}

	/**
	 * Return existing user_logins that match entries on the current blacklist.
	 *
	 * Used by the admin UI to warn the site owner that some of the blacklisted
	 * names correspond to real accounts: those accounts remain functional.
	 *
	 * @return string[]
	 */
	public static function existing_matching_users(): array {
		global $wpdb;
		$blacklist = self::get_blacklist();
		if ( [] === $blacklist ) {
			return [];
		}
		$placeholders = implode( ',', array_fill( 0, count( $blacklist ), '%s' ) );
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.InterpolatedNotPrepared,WordPress.DB.PreparedSQLPlaceholders.UnfinishedPrepare -- $placeholders built from a fixed count of literal %s tokens, all values pass through $wpdb->prepare().
		$sql = $wpdb->prepare(
			"SELECT user_login FROM {$wpdb->users} WHERE LOWER(user_login) IN ($placeholders)", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared,WordPress.DB.PreparedSQLPlaceholders.UnfinishedPrepare -- see phpcs comment above, $placeholders is a fixed set of %s tokens.
			$blacklist
		);
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.NotPrepared -- Already prepared above.
		$rows = $wpdb->get_col( $sql );
		return is_array( $rows ) ? array_map( 'strval', $rows ) : [];
	}

	/**
	 * Wire up all WordPress hooks enforcing the blacklist.
	 *
	 * Called from `class-hardening.php` only when the toggle is on.
	 */
	public static function register(): void {
		add_filter( 'authenticate', [ self::class, 'filter_authenticate' ], 10, 3 );
		add_filter( 'registration_errors', [ self::class, 'filter_registration_errors' ], 10, 3 );
		add_filter( 'wpmu_validate_user_signup', [ self::class, 'filter_multisite_signup' ], 10, 1 );
	}

	/**
	 * Reject a login attempt when the submitted username is blacklisted AND
	 * no matching WP_User exists (existing accounts keep working).
	 *
	 * @param \WP_User|\WP_Error|null $user     Current auth result.
	 * @param string                  $username Submitted username.
	 * @param string                  $password Submitted password.
	 * @return \WP_User|\WP_Error|null
	 */
	public static function filter_authenticate( $user = null, $username = '', $password = '' ) {
		unset( $password );

		if ( ! is_string( $username ) || '' === $username ) {
			return $user;
		}

		// Preserve existing accounts whose login happens to match the list.
		if ( get_user_by( 'login', $username ) instanceof \WP_User ) {
			return $user;
		}

		if ( ! self::is_blacklisted( $username ) ) {
			return $user;
		}

		$ip = LoginArmor::get_client_ip();
		do_action( 'login_armor_username_blacklisted', $username, 'login' );
		self::record_incident( $ip, $username );

		return new \WP_Error(
			'username_blacklisted',
			esc_html__( 'This username is reserved and cannot be used.', 'login-armor' )
		);
	}

	/**
	 * Block single-site registrations for blacklisted usernames.
	 *
	 * @param \WP_Error $errors               Errors object to append to.
	 * @param string    $sanitized_user_login The proposed user_login.
	 * @param string    $user_email           The proposed user_email.
	 * @return \WP_Error
	 */
	public static function filter_registration_errors( $errors = null, $sanitized_user_login = '', $user_email = '' ) {
		unset( $user_email );

		if ( self::is_blacklisted( (string) $sanitized_user_login ) ) {
			do_action( 'login_armor_username_blacklisted', (string) $sanitized_user_login, 'registration' );
			if ( $errors instanceof \WP_Error ) {
				$errors->add(
					'username_blacklisted',
					esc_html__( 'This username is reserved and cannot be used.', 'login-armor' )
				);
			}
		}

		return $errors;
	}

	/**
	 * Block multisite signups for blacklisted usernames.
	 *
	 * @param array<string,mixed> $result wpmu_validate_user_signup result array.
	 * @return array<string,mixed>
	 */
	public static function filter_multisite_signup( $result = array() ) {
		if ( ! is_array( $result ) || empty( $result['user_name'] ) ) {
			return $result;
		}

		if ( self::is_blacklisted( (string) $result['user_name'] ) ) {
			do_action( 'login_armor_username_blacklisted', (string) $result['user_name'], 'multisite_signup' );
			if ( isset( $result['errors'] ) && $result['errors'] instanceof \WP_Error ) {
				$result['errors']->add(
					'username_blacklisted',
					esc_html__( 'This username is reserved and cannot be used.', 'login-armor' )
				);
			}
		}

		return $result;
	}

	/**
	 * Upsert a detection incident for the blacklisted login attempt.
	 *
	 * Blacklist hits are single events (bot-certain-ish) so this does not use
	 * the Classifier's sliding-window logic: we simply bump events_count on
	 * an active incident within the last hour or create a new one.
	 *
	 * @param string $ip       Client IP.
	 * @param string $username Attempted username.
	 */
	private static function record_incident( string $ip, string $username ): void {
		if ( ! class_exists( Incident::class ) ) {
			return;
		}

		$now      = current_time( 'mysql', true );
		$existing = Incident::find_active( Incident::PATTERN_RESERVED_USERNAME_PROBE, $ip, 'ip', 60 );

		if ( $existing instanceof Incident ) {
			$existing->increment_occurrence( Incident::SEVERITY_MEDIUM, 1, 1, 1 );
			do_action( 'login_armor_incident_created', $existing, false );
			return;
		}

		$incident                   = new Incident();
		$incident->pattern          = Incident::PATTERN_RESERVED_USERNAME_PROBE;
		$incident->severity         = Incident::SEVERITY_MEDIUM;
		$incident->started_at       = $now;
		$incident->last_seen_at     = $now;
		$incident->ip               = $ip;
		$incident->subnet           = '';
		$incident->target_username  = substr( $username, 0, 60 );
		$incident->events_count     = 1;
		$incident->unique_ips       = 1;
		$incident->unique_usernames = 1;
		$incident->status           = Incident::STATUS_ACTIVE;
		$incident->insert();
		do_action( 'login_armor_incident_created', $incident, true );
	}
}
