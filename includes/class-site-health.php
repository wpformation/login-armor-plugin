<?php
/**
 * Tools > Site Health integration.
 *
 * Nine direct tests and one debug panel. Site Health is where a WordPress
 * administrator, or whoever they pay to look after the site, goes when
 * something feels wrong, and it is the screen support asks them to copy. Both
 * halves of this file exist for that moment.
 *
 * THE RULES THESE TESTS FOLLOW
 * ----------------------------
 *  - Direct tests run while the page renders, one after the other. None of
 *    them touches the network, runs an unbounded query, or writes anything.
 *    Opening a diagnostic screen must change nothing.
 *  - A test reports `recommended` only when the situation it describes is
 *    actually happening, and `good` otherwise. Never `critical`: nothing here
 *    is a site outage, and a plugin that cries critical teaches its reader to
 *    scroll past the section.
 *  - Every description says what is wrong AND what it costs, in one or two
 *    sentences, then links to the exact settings section that fixes it.
 *
 * THE RULE THE PANEL FOLLOWS
 * --------------------------
 * The Info tab has a "Copy site info to clipboard" button, and what it copies
 * ends up in public forum threads. The Hide Login slug is therefore never
 * read here, let alone printed, and trusted proxies are counted rather than
 * listed. Everything else is configuration an attacker gains nothing from.
 *
 * @package LoginArmor
 */

namespace LoginArmor;

defined( 'ABSPATH' ) || exit;

/**
 * Registers the plugin's Site Health tests and its debug panel.
 */
final class SiteHealth {

	/** @var string Section id of the debug panel. */
	public const SECTION = 'login-armor';

	/** @var string Badge colour every test wears. */
	public const BADGE_COLOR = 'blue';

	/**
	 * @var int Days of monitor mode after which switching to Enforce is advised.
	 *
	 * Strictly more than this: a module enabled exactly thirty days ago has
	 * had thirty days, not more, and firing on the boundary means firing a
	 * day early on every site in the world.
	 */
	public const MONITOR_DAYS_MAX = 30;

	/**
	 * Hook the two core filters. Called from the admin branch of the
	 * bootstrap: the Site Health screen is admin-only.
	 */
	public static function init(): void {
		add_filter( 'site_status_tests', [ __CLASS__, 'register_tests' ] );
		add_filter( 'debug_information', [ __CLASS__, 'register_debug_information' ] );
	}

	/**
	 * Add the plugin's direct tests to the ones already registered.
	 *
	 * Untyped with a default, like every callback on a core hook: a third
	 * party that re-fires `site_status_tests` with null must not fatal the
	 * screen. The incoming array is added to, never replaced.
	 *
	 * @param mixed $tests Tests registered so far.
	 * @return array<string,mixed>
	 */
	public static function register_tests( $tests = [] ) {
		if ( ! is_array( $tests ) ) {
			$tests = [];
		}
		if ( ! isset( $tests['direct'] ) || ! is_array( $tests['direct'] ) ) {
			$tests['direct'] = [];
		}

		foreach ( self::tests() as $id => $spec ) {
			$tests['direct'][ $id ] = $spec;
		}

		return $tests;
	}

	/**
	 * The nine tests, eleven in headless mode, keyed by the identifier core rows them under.
	 *
	 * @return array<string,array{label:string,test:callable}>
	 */
	public static function tests(): array {
		$tests = [
			'login_armor_cache_exclusion'       => [
				'label' => __( 'Your hidden login URL is not cached', 'login-armor' ),
				'test'  => [ __CLASS__, 'test_cache_exclusion' ],
			],
			'login_armor_htaccess'              => [
				'label' => __( 'Login Armor can write its .htaccess rules', 'login-armor' ),
				'test'  => [ __CLASS__, 'test_htaccess' ],
			],
			'login_armor_ip_identity'           => [
				'label' => __( 'Login Armor can identify your visitors', 'login-armor' ),
				'test'  => [ __CLASS__, 'test_ip_identity' ],
			],
			'login_armor_two_factor_enrollment' => [
				'label' => __( 'Two-factor authentication is actually in use', 'login-armor' ),
				'test'  => [ __CLASS__, 'test_two_factor_enrollment' ],
			],
			'login_armor_firewall_monitor'      => [
				'label' => __( 'The request firewall is blocking, not only watching', 'login-armor' ),
				'test'  => [ __CLASS__, 'test_firewall_monitor' ],
			],
			'login_armor_bot_challenge_monitor' => [
				'label' => __( 'The bot challenge is blocking, not only watching', 'login-armor' ),
				'test'  => [ __CLASS__, 'test_bot_challenge_monitor' ],
			],
			'login_armor_notification_test'     => [
				'label' => __( 'Your security alerts have been proven to arrive', 'login-armor' ),
				'test'  => [ __CLASS__, 'test_notification_test' ],
			],
			'login_armor_suppressed_alerts'     => [
				'label' => __( 'No security alert is waiting to be sent', 'login-armor' ),
				'test'  => [ __CLASS__, 'test_suppressed_alerts' ],
			],
			'login_armor_schema'                => [
				'label' => __( 'Login Armor tables have every column they need', 'login-armor' ),
				'test'  => [ __CLASS__, 'test_schema' ],
			],
		];

		// 2.9.0: two checks that only mean something on a headless back end.
		if ( class_exists( '\LoginArmor\Headless' ) && Headless::is_enabled() ) {
			$tests['login_armor_headless_indexing'] = [
				'label' => __( 'Your headless back end is not indexed', 'login-armor' ),
				'test'  => [ __CLASS__, 'test_headless_indexing' ],
			];
			$tests['login_armor_headless_users']    = [
				'label' => __( 'Your headless back end does not list its accounts', 'login-armor' ),
				'test'  => [ __CLASS__, 'test_headless_users' ],
			];
		}

		return $tests;
	}

	// ------------------------------------------------------------------
	// The tests
	// ------------------------------------------------------------------

	/**
	 * Hide Login behind a page cache whose exclusion nobody can confirm.
	 *
	 * Every cache plugin excludes URLs differently and none of them exposes
	 * that configuration in a way a third party can read, so this test does
	 * not claim to know whether the exclusion exists: it says which plugin is
	 * running and what happens when the exclusion is missing.
	 *
	 * @return array<string,mixed>
	 */
	public static function test_cache_exclusion(): array {
		$id = 'login_armor_cache_exclusion';

		if ( ! HideLogin::is_enabled() ) {
			return self::result(
				$id,
				__( 'Your hidden login URL is not cached', 'login-armor' ),
				'good',
				__( 'Hide Login is off, so no page cache can serve a stale login page.', 'login-armor' )
			);
		}

		$caches = Support\PluginDetection::active_cache_plugins();
		if ( [] === $caches ) {
			return self::result(
				$id,
				__( 'Your hidden login URL is not cached', 'login-armor' ),
				'good',
				__( 'No page cache plugin is active, so your hidden login URL is served fresh every time.', 'login-armor' )
			);
		}

		return self::result(
			$id,
			__( 'Your hidden login URL may be served from the cache', 'login-armor' ),
			'recommended',
			sprintf(
				/* translators: %s: comma-separated list of cache plugin names. */
				__( 'Hide Login is on and a page cache is running (%s). Exclude your login URL from the cache, or visitors may get a cached 404 instead of the login form, and you will not be able to sign in.', 'login-armor' ),
				implode( ', ', $caches )
			),
			'hide-login',
			__( 'Open the Hide Login settings', 'login-armor' )
		);
	}

	/**
	 * An .htaccess rule the plugin could not write, or a file it refused to
	 * touch because its Login Armor markers do not form one complete block.
	 *
	 * The two transients that carry this at the moment it happens live five
	 * minutes, which is right for an admin notice and useless here: Site
	 * Health is opened days later, once something has gone wrong. The durable
	 * record is what this reads, and a clean sync clears it.
	 *
	 * @return array<string,mixed>
	 */
	public static function test_htaccess(): array {
		$id     = 'login_armor_htaccess';
		$record = get_option( Hardening::OPTION_HTACCESS_LAST_FAILURE, [] );
		$path   = is_array( $record ) ? (string) ( $record['path'] ?? '' ) : '';

		if ( '' === $path ) {
			return self::result(
				$id,
				__( 'Login Armor can write its .htaccess rules', 'login-armor' ),
				'good',
				__( 'The last time Login Armor synchronised its .htaccess rules, every file it had to touch was written.', 'login-armor' )
			);
		}

		$kind = is_array( $record ) ? (string) ( $record['kind'] ?? 'write' ) : 'write';

		// 2.7.1: one sentence per reason, written once in Hardening and read
		// by all three surfaces that report this. This test used to carry its
		// own copy, which said "check the file permissions" for every cause
		// including a lock held by a concurrent save, and so contradicted
		// nothing except the facts.
		$description = Hardening::htaccess_failure_message( $kind, $path );

		// A cause that repairs itself is not something to send anybody
		// hunting for: the next save writes the rule.
		if ( Hardening::htaccess_failure_is_transient( $kind ) ) {
			return self::result(
				$id,
				__( 'Login Armor can write its .htaccess rules', 'login-armor' ),
				'good',
				$description
			);
		}

		return self::result(
			$id,
			__( 'Login Armor could not write an .htaccess rule', 'login-armor' ),
			'recommended',
			$description,
			'hardening',
			__( 'Open the Hardening settings', 'login-armor' )
		);
	}

	/**
	 * The plugin cannot tell one visitor from another.
	 *
	 * Two ways to get there, and they need the same answer. The settings say
	 * to read a proxy header but no proxy is trusted, so every forwarded
	 * identity is refused; or the runtime has already refused one, which the
	 * daily transient records.
	 *
	 * @return array<string,mixed>
	 */
	public static function test_ip_identity(): array {
		$id      = 'login_armor_ip_identity';
		$method  = (string) get_option( 'login_armor_ip_method', 'REMOTE_ADDR' );
		$proxies = self::trusted_proxy_count();
		$refused = false !== get_transient( 'login_armor_ip_method_misconfigured' );

		if ( 'REMOTE_ADDR' === $method && ! $refused ) {
			return self::result(
				$id,
				__( 'Login Armor can identify your visitors', 'login-armor' ),
				'good',
				__( 'Visitors are identified by the address your server sees, which nobody can forge. Lockouts, rate limits and the firewall all count on it.', 'login-armor' )
			);
		}

		if ( 'REMOTE_ADDR' !== $method && 0 === $proxies ) {
			return self::result(
				$id,
				__( 'Login Armor cannot identify your visitors', 'login-armor' ),
				'recommended',
				LoginArmor::proxy_identity_warning( $method ) . '.',
				'limit-login',
				__( 'Open the brute-force settings', 'login-armor' )
			);
		}

		if ( $refused ) {
			return self::result(
				$id,
				__( 'Login Armor cannot identify your visitors', 'login-armor' ),
				'recommended',
				__( 'One of your trusted proxies handed Login Armor an address it could not use, so that request was not counted against any lockout or quota. Check that your proxy really sends the header you selected, and that every proxy in front of this site is listed.', 'login-armor' ),
				'limit-login',
				__( 'Open the brute-force settings', 'login-armor' )
			);
		}

		return self::result(
			$id,
			__( 'Login Armor can identify your visitors', 'login-armor' ),
			'good',
			sprintf(
				/* translators: 1: IP method name, 2: number of trusted proxies. */
				__( 'Visitors are identified through %1$s, and %2$d trusted proxy addresses are declared, so a forwarded address is only believed when it comes from one of them.', 'login-armor' ),
				$method,
				$proxies
			)
		);
	}

	/**
	 * Two-factor enforced on a role nobody has enrolled in.
	 *
	 * The grace period ends silently. When it does, every account of that
	 * role is asked for a code nobody has set up, and the administrator finds
	 * out by being locked out.
	 *
	 * Two bounded queries, each stopping at the first matching row: is there
	 * anybody in the enforced roles at all, and has anybody enrolled. That is
	 * the whole question, and it is the only shape whose cost does not grow
	 * with the size of the site. See `TwoFactor::enforced_enrolment_state()`.
	 *
	 * @return array<string,mixed>
	 */
	public static function test_two_factor_enrollment(): array {
		$id    = 'login_armor_two_factor_enrollment';
		$label = __( 'Two-factor authentication is actually in use', 'login-armor' );

		if ( ! get_option( 'login_armor_2fa_enabled', false ) ) {
			return self::result( $id, $label, 'good', __( 'Two-factor authentication is off, so nothing is enforced.', 'login-armor' ) );
		}

		$state = TwoFactor\TwoFactor::enforced_enrolment_state();

		if ( [] === $state['roles'] ) {
			return self::result( $id, $label, 'good', __( 'Two-factor authentication is available but not enforced on any role, so nobody can be locked out by it.', 'login-armor' ) );
		}

		$names = self::role_names( $state['roles'] );

		if ( ! $state['has_members'] ) {
			return self::result(
				$id,
				$label,
				'good',
				sprintf(
					/* translators: %s: comma-separated role names. */
					__( 'Two-factor authentication is enforced on %s, which no account currently holds.', 'login-armor' ),
					$names
				)
			);
		}

		if ( $state['has_enrolment'] ) {
			return self::result(
				$id,
				$label,
				'good',
				sprintf(
					/* translators: %s: comma-separated role names. */
					__( 'Two-factor authentication is enforced on %s, and at least one account there has set it up.', 'login-armor' ),
					$names
				)
			);
		}

		return self::result(
			$id,
			__( 'Two-factor is enforced but nobody has set it up', 'login-armor' ),
			'recommended',
			sprintf(
				/* translators: %s: comma-separated role names. */
				__( 'Two-factor authentication is enforced on %s and nobody there has enrolled. When the grace period ends, every one of those accounts will be asked for a code nobody has, and you will be locked out of your own site.', 'login-armor' ),
				$names
			),
			'two-factor',
			__( 'Open the Two-Factor settings', 'login-armor' )
		);
	}

	/**
	 * Role slugs turned into the names an administrator sees on screen.
	 *
	 * `wp_roles()` is built from an option that is already in memory, so this
	 * costs no query. A slug with no registered role keeps its slug rather
	 * than disappearing from the sentence.
	 *
	 * @param array<int,string> $roles Role slugs.
	 * @return string Comma-separated, translated where WordPress knows them.
	 */
	private static function role_names( array $roles ): string {
		$known = [];
		if ( function_exists( 'wp_roles' ) ) {
			$known = (array) wp_roles()->role_names;
		}

		$out = [];
		foreach ( $roles as $slug ) {
			$out[] = isset( $known[ $slug ] ) ? translate_user_role( (string) $known[ $slug ] ) : (string) $slug;
		}

		return implode( ', ', $out );
	}

	/**
	 * The request firewall has been watching for longer than it is useful to.
	 *
	 * @return array<string,mixed>
	 */
	public static function test_firewall_monitor(): array {
		return self::monitor_result(
			'login_armor_firewall_monitor',
			__( 'The request firewall is blocking, not only watching', 'login-armor' ),
			__( 'The request firewall has been watching for a long time', 'login-armor' ),
			__( 'request firewall', 'login-armor' ),
			Firewall\Firewall::is_enabled() ? Firewall\Firewall::get_mode() : 'off',
			Firewall\Firewall::monitoring_days(),
			'firewall',
			__( 'Open the firewall settings', 'login-armor' )
		);
	}

	/**
	 * The bot challenge has been watching for longer than it is useful to.
	 *
	 * @return array<string,mixed>
	 */
	public static function test_bot_challenge_monitor(): array {
		return self::monitor_result(
			'login_armor_bot_challenge_monitor',
			__( 'The bot challenge is blocking, not only watching', 'login-armor' ),
			__( 'The bot challenge has been watching for a long time', 'login-armor' ),
			__( 'bot challenge', 'login-armor' ),
			PowChallenge::is_enabled() ? PowChallenge::get_mode() : 'off',
			PowChallenge::monitoring_days(),
			'pow',
			__( 'Open the bot challenge settings', 'login-armor' )
		);
	}

	/**
	 * A notification channel nobody has ever proven to work.
	 *
	 * An unreachable webhook is indistinguishable from a quiet site: both
	 * produce no messages. The difference only shows on the day it matters.
	 *
	 * @return array<string,mixed>
	 */
	public static function test_notification_test(): array {
		$id      = 'login_armor_notification_test';
		$label   = __( 'Your security alerts have been proven to arrive', 'login-armor' );
		$channel = (string) get_option( 'login_armor_notif_channel', 'disabled' );

		if ( 'disabled' === $channel ) {
			return self::result( $id, $label, 'good', __( 'Notifications are off, so there is no channel to prove.', 'login-armor' ) );
		}

		if ( (int) get_option( 'login_armor_notif_last_test_ok', 0 ) > 0 ) {
			return self::result(
				$id,
				$label,
				'good',
				sprintf(
					/* translators: %s: notification channel name. */
					__( 'A test alert was delivered successfully on your %s channel, so an alert raised tonight will reach you.', 'login-armor' ),
					$channel
				)
			);
		}

		return self::result(
			$id,
			__( 'Your security alerts have never been tested', 'login-armor' ),
			'recommended',
			sprintf(
				/* translators: %s: notification channel name. */
				__( 'Alerts are configured to go to your %s channel, but no test has ever been delivered from this site. An unreachable channel looks exactly like a quiet week until the night something happens.', 'login-armor' ),
				$channel
			),
			'notifications',
			__( 'Open the Notifications settings', 'login-armor' )
		);
	}

	/**
	 * Alerts the hourly quota refused to send, still waiting to be announced.
	 *
	 * @return array<string,mixed>
	 */
	public static function test_suppressed_alerts(): array {
		$id    = 'login_armor_suppressed_alerts';
		$label = __( 'No security alert is waiting to be sent', 'login-armor' );

		// Cheap autoloaded gate first: the counter lives in a row that has to
		// be read uncached, and nothing writes it while the module is off.
		if ( 'disabled' === (string) get_option( 'login_armor_notif_channel', 'disabled' ) ) {
			return self::result( $id, $label, 'good', __( 'Notifications are off, so nothing is being held back.', 'login-armor' ) );
		}

		if ( ! class_exists( '\LoginArmor\Notifications\Dispatcher' ) ) {
			require_once LOGIN_ARMOR_DIR . 'includes/Notifications/ChannelInterface.php';
			require_once LOGIN_ARMOR_DIR . 'includes/Notifications/Dispatcher.php';
		}

		$suppressed = Notifications\Dispatcher::get_suppressed();
		$count      = (int) $suppressed['count'];

		if ( $count < 1 ) {
			return self::result( $id, $label, 'good', __( 'Every alert this site raised was sent: the hourly notification cap has not refused any.', 'login-armor' ) );
		}

		return self::result(
			$id,
			__( 'Security alerts are waiting to be sent', 'login-armor' ),
			'recommended',
			sprintf(
				/* translators: 1: number of alerts held back, 2: start of the hour in UTC, e.g. 13:00. */
				__( 'Login Armor held back %1$d alerts since %2$s UTC because the hourly notification cap was reached. They are counted and announced with the next alert that does go out, but nobody is told about them as they happen.', 'login-armor' ),
				$count,
				Notifications\Dispatcher::suppressed_since_label( (string) $suppressed['hour'] )
			),
			'notifications',
			__( 'Open the Notifications settings', 'login-armor' )
		);
	}

	/**
	 * A table that is missing a column nothing reads out loud (2.7.2).
	 *
	 * The incidents table gained three columns in 2.7.1 and they are the only
	 * ones in the plugin whose absence is quiet: they are written by one
	 * UPDATE and read through `SELECT *`, so a table without them serves every
	 * screen perfectly while dropping each AI analysis the administrator paid
	 * to generate. Found exactly that way on a real site, where the version
	 * had already been stamped by an earlier build and the upgrade step that
	 * adds them was therefore skipped.
	 *
	 * The write path repairs this by itself now, at most once an hour. This
	 * test exists for the site where nobody has run an analysis yet, and for
	 * the one where the repair cannot work because the database refuses the
	 * ALTER: without it the only symptom is an invoice.
	 *
	 * @return array<string,mixed>
	 */
	public static function test_schema(): array {
		$id    = 'login_armor_schema';
		$label = __( 'Login Armor tables have every column they need', 'login-armor' );

		if ( ! class_exists( '\LoginArmor\Detection\Incident' ) ) {
			require_once LOGIN_ARMOR_DIR . 'includes/Detection/Incident.php';
		}

		// 2.8.0: every table, every column. This test used to look at the
		// three AI columns only, so a login log without its `reason` column,
		// which rejects every login event, was reported "good".
		$all = LoginArmor::missing_schema_columns();
		if ( empty( $all ) ) {
			return self::result( $id, $label, 'good', __( 'Every Login Armor table carries every column this version writes to: login events are recorded, and an AI analysis you generate is kept with the incident it describes.', 'login-armor' ) );
		}

		global $wpdb;
		$incidents_table = $wpdb->prefix . 'login_armor_incidents';
		$missing         = $all[ $incidents_table ] ?? array();
		$only_analysis   = 1 === count( $all ) && array() !== $missing && array() === array_diff( $missing, Detection\Incident::missing_analysis_columns() );

		if ( ! $only_analysis ) {
			$declared = LoginArmor::declared_columns();
			$parts    = array();
			foreach ( $all as $table => $columns ) {
				// A table missing entirely misses every column: said in three
				// words rather than a list of fifteen.
				if ( $columns === ( $declared[ $table ] ?? null ) ) {
					/* translators: %s: name of a database table. */
					$parts[] = sprintf( __( '%s (the whole table)', 'login-armor' ), $table );
					continue;
				}
				$parts[] = $table . ' (' . implode( ', ', $columns ) . ')';
			}

			return self::result(
				$id,
				__( 'Login Armor tables are missing columns', 'login-armor' ),
				'critical',
				sprintf(
					/* translators: %s: list of database tables, each followed by its missing columns in parentheses. */
					__( 'Missing: %s, so the database refuses every row Login Armor writes into these tables, and on the login log that means no sign-in is recorded and detection has nothing to work from. Login Armor retries the repair by itself, at most once an hour; if this is still reported later, your database user lacks the ALTER or CREATE privilege: ask your host to grant it or to add what is missing, then deactivate and reactivate Login Armor.', 'login-armor' ),
					implode( '; ', $parts )
				)
			);
		}

		return self::result(
			$id,
			__( 'A Login Armor table is missing a column', 'login-armor' ),
			'recommended',
			sprintf(
				/* translators: %s: comma-separated list of missing database column names. */
				__( 'The incidents table is missing: %s. Every screen still works, which is exactly why this is worth saying: the one thing that fails is storing an AI analysis, so each one you generate is billed and then lost, and if Login Armor keeps reporting this after an hour your database is refusing the column and your host has to add it.', 'login-armor' ),
				implode( ', ', $missing )
			)
		);
	}

	// ------------------------------------------------------------------
	// The debug panel
	// ------------------------------------------------------------------

	/**
	 * Add the plugin's section to the Site Health Info screen.
	 *
	 * Untyped with a default, like every callback on a core hook.
	 *
	 * @param mixed $info Sections registered so far.
	 * @return array<string,mixed>
	 */
	public static function register_debug_information( $info = [] ) {
		if ( ! is_array( $info ) ) {
			$info = [];
		}

		$info[ self::SECTION ] = [
			'label'       => 'Login Armor',
			'description' => __( 'Login Armor configuration, for support. The hidden login URL and your trusted proxy addresses are deliberately absent: this panel is meant to be copied into a forum thread.', 'login-armor' ),
			'show_count'  => false,
			'fields'      => self::panel_fields(),
		];

		return $info;
	}

	/**
	 * A headless back end that search engines may index (2.9.0).
	 *
	 * Only blog_public is read: a back end that sends noindex another way (an
	 * X-Robots-Tag header from a mu-plugin) is reported as indexable, and the
	 * text says how to settle it.
	 *
	 * @return array<string,mixed>
	 */
	public static function test_headless_indexing(): array {
		$id    = 'login_armor_headless_indexing';
		$label = __( 'Your headless back end is not indexed', 'login-armor' );

		if ( '0' === (string) get_option( 'blog_public', '1' ) ) {
			return self::result( $id, $label, 'good', __( 'Search engines are asked not to index this back end, so its pages do not compete with your front end.', 'login-armor' ) );
		}

		$result            = self::result(
			$id,
			__( 'Your headless back end can be indexed', 'login-armor' ),
			'recommended',
			__( 'Settings > Reading allows search engines to index this back end. Its pages can then appear in search results next to your front end, with the back-end address. Tick "Discourage search engines from indexing this site", or ignore this if the back end already sends noindex in another way.', 'login-armor' )
		);
		// The setting lives in Settings > Reading, not in a Login Armor section.
		$result['actions'] = sprintf(
			'<p><a href="%1$s">%2$s</a></p>',
			esc_url( admin_url( 'options-reading.php' ) ),
			esc_html__( 'Open the Reading settings', 'login-armor' )
		);
		return $result;
	}

	/**
	 * A headless back end that lists its accounts to anyone (2.9.0).
	 *
	 * An internal anonymous request, no network: the current user is set to 0
	 * for the call and restored, whatever happens.
	 *
	 * @return array<string,mixed>
	 */
	public static function test_headless_users(): array {
		$id    = 'login_armor_headless_users';
		$label = __( 'Your headless back end does not list its accounts', 'login-armor' );

		if ( ! function_exists( 'rest_do_request' ) || ! class_exists( '\WP_REST_Request' ) ) {
			return self::result( $id, $label, 'good', __( 'The REST API is not loaded here, so there is nothing to check.', 'login-armor' ) );
		}

		$previous = get_current_user_id();
		wp_set_current_user( 0 );
		try {
			// rest_do_request() skips rest_authentication_errors: a site that
			// closes the API to anonymous visitors through it is already good.
			if ( is_wp_error( apply_filters( 'rest_authentication_errors', null ) ) ) { // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- This evaluates the WordPress core REST authentication filter, as the REST server does.
				$response = null;
			} else {
				$response = rest_do_request( new \WP_REST_Request( 'GET', '/wp/v2/users' ) );
			}
		} finally {
			wp_set_current_user( $previous );
		}

		$verdict = null === $response ? 'good' : self::users_route_verdict( (int) $response->get_status(), $response->get_data() );
		if ( 'good' === $verdict ) {
			return self::result( $id, $label, 'good', __( 'An anonymous visitor gets no list of accounts from /wp/v2/users.', 'login-armor' ) );
		}

		return self::result(
			$id,
			__( 'Your headless back end lists its accounts', 'login-armor' ),
			'recommended',
			__( 'An anonymous visitor can read the list of accounts from /wp/v2/users, which gives an attacker the logins to try. Turn on "Prevent author enumeration" in Hardening. Your front end then no longer receives author names through _embed: check that it does not display them from there.', 'login-armor' ),
			'hardening',
			__( 'Open the Hardening settings', 'login-armor' )
		);
	}

	/**
	 * Verdict on an anonymous answer of /wp/v2/users.
	 *
	 * @since 2.9.0
	 *
	 * @param int   $status HTTP status of the internal request.
	 * @param mixed $data   Its body.
	 * @return string 'good' or 'recommended'.
	 */
	public static function users_route_verdict( int $status, $data ): string {
		return ( 200 === $status && is_array( $data ) && array() !== $data ) ? 'recommended' : 'good';
	}

	/**
	 * The panel fields, for tests/release-2-9-0.php.
	 *
	 * @return array<string,array<string,mixed>>
	 */
	public static function panel_fields_for_tests(): array {
		return self::panel_fields();
	}

	/**
	 * Every field of the panel.
	 *
	 * @return array<string,array<string,mixed>>
	 */
	private static function panel_fields(): array {
		$states  = SecurityScore::module_states();
		$machine = [];
		$active  = [];
		foreach ( $states as $option => $on ) {
			$machine[] = $option . '=' . ( $on ? '1' : '0' );
			if ( $on ) {
				$active[] = $option;
			}
		}

		$caches   = Support\PluginDetection::active_cache_plugins();
		$security = Support\PluginDetection::active_security_plugins();
		$none     = __( 'None', 'login-armor' );

		return [
			'version'             => [
				'label' => __( 'Plugin version', 'login-armor' ),
				'value' => LOGIN_ARMOR_VERSION,
			],
			'safe_mode'           => [
				'label' => __( 'Safe mode', 'login-armor' ),
				'value' => LoginArmor::is_safe_mode() ? __( 'Enabled', 'login-armor' ) : __( 'Disabled', 'login-armor' ),
				'debug' => LoginArmor::is_safe_mode() ? 'on' : 'off',
			],
			'headless'            => [
				'label' => __( 'Headless mode', 'login-armor' ),
				'value' => ( class_exists( '\LoginArmor\Headless' ) && Headless::is_enabled() ) ? __( 'Enabled', 'login-armor' ) : __( 'Disabled', 'login-armor' ),
				'debug' => ( class_exists( '\LoginArmor\Headless' ) && Headless::is_enabled() ) ? 'on' : 'off',
			],
			'app_password_watch'  => [
				'label' => __( 'Application-password monitoring', 'login-armor' ),
				'value' => ( class_exists( '\LoginArmor\AppPasswords\Usage' ) && AppPasswords\Usage::is_watching() ) ? __( 'Enabled', 'login-armor' ) : __( 'Disabled', 'login-armor' ),
				'debug' => ( class_exists( '\LoginArmor\AppPasswords\Usage' ) && AppPasswords\Usage::is_watching() ) ? 'on' : 'off',
			],
			'modules'             => [
				'label' => __( 'Active modules', 'login-armor' ),
				'value' => [] === $active ? $none : implode( ', ', $active ),
				'debug' => implode( ', ', $machine ),
			],
			'ip_method'           => [
				'label' => __( 'Visitor identification', 'login-armor' ),
				'value' => (string) get_option( 'login_armor_ip_method', 'REMOTE_ADDR' ),
			],
			'trusted_proxies'     => [
				'label' => __( 'Trusted proxies declared', 'login-armor' ),
				'value' => (string) self::trusted_proxy_count(),
				'debug' => 'count=' . self::trusted_proxy_count(),
			],
			'permalink_structure' => [
				'label' => __( 'Permalink structure', 'login-armor' ),
				'value' => '' === (string) get_option( 'permalink_structure', '' ) ? __( 'Plain', 'login-armor' ) : (string) get_option( 'permalink_structure', '' ),
			],
			'server'              => [
				'label'   => __( 'Web server', 'login-armor' ),
				'value'   => self::server_software(),
				'private' => true,
			],
			'home_host'           => [
				'label' => __( 'Home URL host', 'login-armor' ),
				'value' => self::host_of( home_url() ),
			],
			'site_host'           => [
				'label' => __( 'WordPress address host', 'login-armor' ),
				'value' => self::host_of( site_url() ),
			],
			'cache_plugins'       => [
				'label' => __( 'Page cache plugins', 'login-armor' ),
				'value' => [] === $caches ? $none : implode( ', ', $caches ),
				'debug' => implode( ', ', array_keys( $caches ) ),
			],
			'security_plugins'    => [
				'label' => __( 'Overlapping security plugins', 'login-armor' ),
				'value' => [] === $security ? $none : implode( ', ', $security ),
				'debug' => implode( ', ', array_keys( $security ) ),
			],
			'hide_login'          => [
				'label' => __( 'Hide Login', 'login-armor' ),
				'value' => HideLogin::is_enabled() ? __( 'Enabled', 'login-armor' ) : __( 'Disabled', 'login-armor' ),
				'debug' => HideLogin::is_enabled() ? 'on' : 'off',
			],
			'hsts'                => [
				'label' => __( 'HSTS mode', 'login-armor' ),
				'value' => (string) get_option( LoginHeaders::OPTION_HSTS, 'off' ),
			],
			'firewall'            => [
				'label' => __( 'Request firewall', 'login-armor' ),
				'value' => self::module_mode_line( Firewall\Firewall::get_mode(), Firewall\Firewall::is_enabled(), Firewall\Firewall::monitoring_days() ),
				'debug' => Firewall\Firewall::get_mode() . ':' . Firewall\Firewall::monitoring_days(),
			],
			'bot_challenge'       => [
				'label' => __( 'Bot challenge', 'login-armor' ),
				'value' => self::module_mode_line( PowChallenge::get_mode(), PowChallenge::is_enabled(), PowChallenge::monitoring_days() ),
				'debug' => PowChallenge::get_mode() . ':' . PowChallenge::monitoring_days(),
			],
		];
	}

	// ------------------------------------------------------------------
	// Shared shapes
	// ------------------------------------------------------------------

	/**
	 * The array WordPress documents for a Site Health test result.
	 *
	 * @param string $id           Test identifier, which core keys the row on.
	 * @param string $label        Row heading.
	 * @param string $status       good or recommended.
	 * @param string $description  One or two sentences, plain text.
	 * @param string $anchor       Settings section to link to, or '' for none.
	 * @param string $action_label Link text.
	 * @return array<string,mixed>
	 */
	private static function result( string $id, string $label, string $status, string $description, string $anchor = '', string $action_label = '' ): array {
		$actions = '';
		if ( '' !== $anchor ) {
			$actions = sprintf(
				'<p><a href="%1$s">%2$s</a></p>',
				esc_url( admin_url( 'admin.php?page=login-armor&tab=settings#' . $anchor ) ),
				esc_html( $action_label )
			);
		}

		return [
			'label'       => $label,
			'status'      => $status,
			'badge'       => [
				'label' => __( 'Security', 'login-armor' ),
				'color' => self::BADGE_COLOR,
			],
			'description' => '<p>' . esc_html( $description ) . '</p>',
			'actions'     => $actions,
			'test'        => $id,
		];
	}

	/**
	 * The shared verdict of the two monitor-mode modules.
	 *
	 * `monitoring_days()` already answers 0 unless the module is enabled AND
	 * in log_only AND carries the date it was switched on, so the advice only
	 * has to compare it with the threshold.
	 *
	 * 2.8.1: the heading said "is blocking, not only watching" whenever the
	 * advice did not fire, that is also for a module watching for fewer than
	 * thirty days and for a module switched off. On a live site in monitor
	 * mode for nine days, Site Health told its owner the firewall was
	 * blocking. The heading now names the state the module is in.
	 *
	 * @param string $id           Test identifier.
	 * @param string $good_label   Row heading for a module that enforces.
	 * @param string $bad_label    Row heading when the advice fires.
	 * @param string $module       Module name, already translated.
	 * @param string $state        'enforce', 'log_only' or 'off'.
	 * @param int    $days         Days spent in monitor mode.
	 * @param string $anchor       Settings section to link to.
	 * @param string $action_label Link text.
	 * @return array<string,mixed>
	 */
	private static function monitor_result( string $id, string $good_label, string $bad_label, string $module, string $state, int $days, string $anchor, string $action_label ): array {
		if ( 'off' === $state ) {
			return self::result(
				$id,
				/* translators: %s: module name, e.g. request firewall. */
				sprintf( __( 'The %s is off', 'login-armor' ), $module ),
				'good',
				/* translators: %s: module name, e.g. request firewall. */
				sprintf( __( 'The %s is switched off, so it is not left watching without blocking.', 'login-armor' ), $module )
			);
		}

		if ( 'enforce' !== $state && $days <= self::MONITOR_DAYS_MAX ) {
			return self::result(
				$id,
				/* translators: %s: module name, e.g. request firewall. */
				sprintf( __( 'The %s is in monitor mode', 'login-armor' ), $module ),
				'good',
				sprintf(
					/* translators: 1: module name, e.g. request firewall, 2: number of days, 3: number of days. */
					__( 'The %1$s logs what it would have stopped and stops nothing yet (%2$d days so far). Read what it caught, then switch it to Enforce; after %3$d days in this mode, this becomes a recommendation.', 'login-armor' ),
					$module,
					$days,
					self::MONITOR_DAYS_MAX
				)
			);
		}

		if ( 'enforce' === $state ) {
			return self::result(
				$id,
				$good_label,
				'good',
				sprintf(
					/* translators: %s: module name, e.g. request firewall. */
					__( 'The %s blocks what it catches, instead of only logging it.', 'login-armor' ),
					$module
				)
			);
		}

		return self::result(
			$id,
			$bad_label,
			'recommended',
			sprintf(
				/* translators: 1: module name, e.g. request firewall, 2: number of days. */
				__( 'The %1$s has been in monitor mode for %2$d days: it logs what it would have stopped and stops nothing. Read what it caught, then switch it to Enforce or turn it off.', 'login-armor' ),
				$module,
				$days
			),
			$anchor,
			$action_label
		);
	}

	/**
	 * One line describing a module that has a mode.
	 *
	 * @param string $mode    Stored mode.
	 * @param bool   $enabled Whether the module is on at all.
	 * @param int    $days    Days spent in monitor mode, 0 when not monitoring.
	 * @return string
	 */
	private static function module_mode_line( string $mode, bool $enabled, int $days ): string {
		if ( ! $enabled ) {
			return __( 'Disabled', 'login-armor' );
		}
		if ( $days > 0 ) {
			return sprintf(
				/* translators: 1: mode name, e.g. log_only, 2: number of days. */
				__( '%1$s, for %2$d days', 'login-armor' ),
				$mode,
				$days
			);
		}

		return $mode;
	}

	/**
	 * How many trusted proxies are declared. Never which ones.
	 *
	 * @return int
	 */
	private static function trusted_proxy_count(): int {
		$stored = get_option( 'login_armor_trusted_proxies', '' );
		$lines  = is_array( $stored ) ? $stored : preg_split( '/\R/', (string) $stored );

		// A stored empty string splits into one empty line, and counting that
		// would report a proxy nobody declared, which is exactly the state the
		// IP identity test above must be able to see.
		$count = 0;
		foreach ( (array) $lines as $line ) {
			if ( '' !== trim( (string) $line ) ) {
				++$count;
			}
		}

		return $count;
	}

	/**
	 * The server banner, or a readable placeholder.
	 *
	 * @return string
	 */
	private static function server_software(): string {
		$raw = isset( $_SERVER['SERVER_SOFTWARE'] ) ? sanitize_text_field( wp_unslash( $_SERVER['SERVER_SOFTWARE'] ) ) : '';

		return '' === $raw ? __( 'Unknown', 'login-armor' ) : $raw;
	}

	/**
	 * The host of a URL, without the scheme or the path.
	 *
	 * @param string $url Absolute URL.
	 * @return string
	 */
	private static function host_of( string $url ): string {
		$host = wp_parse_url( $url, PHP_URL_HOST );

		return is_string( $host ) ? $host : '';
	}
}
