<?php
/**
 * WP-CLI commands for LoginArmor.
 *
 * Registered behind defined('WP_CLI') guard. All commands are thin
 * controllers delegating to existing module classes.
 *
 * @package LoginArmor
 * @since   2.0.0
 */

namespace LoginArmor\CLI;

use LoginArmor\AppPasswords\Usage;
use LoginArmor\Detection\Incident;
use LoginArmor\Headless;
use LoginArmor\HideLogin;
use LoginArmor\LimitLogin;
use LoginArmor\LoginArmor;
use LoginArmor\Hardening;
use LoginArmor\Hardening\Honeypot;
use LoginArmor\Hardening\UsernameBlacklist;

// Exit if accessed directly.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Manage the LoginArmor security plugin.
 */
class Commands extends \WP_CLI_Command {

	/**
	 * Whether `status` keeps the hidden login address out of its output (2.10.0).
	 *
	 * @param bool                $constant   LOGIN_ARMOR_CLI_HIDE_SLUG is defined true.
	 * @param array<string,mixed> $assoc_args Named arguments of the command.
	 */
	public static function hide_slug_in_status( bool $constant, array $assoc_args ): bool {
		return $constant && empty( $assoc_args['show-slug'] );
	}

	/**
	 * Display overall plugin status.
	 *
	 * Prints the hidden login address, the recovery method for a lost one,
	 * unless LOGIN_ARMOR_CLI_HIDE_SLUG is defined true in wp-config.php (a
	 * site run by scripts or agents whose output is kept): then the address
	 * is printed only with --show-slug.
	 *
	 * ## OPTIONS
	 *
	 * [--show-slug]
	 * : Print the hidden login address even when LOGIN_ARMOR_CLI_HIDE_SLUG is set.
	 *
	 * ## EXAMPLES
	 *
	 *     wp login-armor status
	 *     wp login-armor status --show-slug
	 *
	 * @param array<int,string>    $args       Positional arguments (unused).
	 * @param array<string,string> $assoc_args Named arguments.
	 */
	public function status( array $args, array $assoc_args ): void {
		// 2.7.0 - safe mode first, because nothing printed after it means what
		// it says while the constant is defined.
		if ( LoginArmor::is_safe_mode() ) {
			\WP_CLI::line( \WP_CLI::colorize( '%RSAFE MODE: ACTIVE%n (LOGIN_ARMOR_SAFE_MODE is defined in wp-config.php)' ) );
			\WP_CLI::line( '                Hide Login, two-factor, the request firewall, the bot challenge and single-session are stood down.' );
			\WP_CLI::line( '                Brute-force lockouts are still enforced. Remove the constant to restore protection.' );
			\WP_CLI::line( '' );
		}

		// Hide Login.
		$hide_enabled = HideLogin::is_enabled();
		$hide_slug    = (string) get_option( HideLogin::OPTION_SLUG, '' );
		$exclusive    = HideLogin::get_exclusive_conflict();
		if ( $hide_enabled && false !== $exclusive ) {
			// 2.10.0: standing down beside a plugin that hides the login page.
			\WP_CLI::line( \WP_CLI::colorize( 'Hide Login:     %YSUSPENDED%n (' . $exclusive . ' is active and hides the login page)' ) );
		} elseif ( $hide_enabled && $hide_slug !== '' && self::hide_slug_in_status( defined( 'LOGIN_ARMOR_CLI_HIDE_SLUG' ) && LOGIN_ARMOR_CLI_HIDE_SLUG, $assoc_args ) ) {
			\WP_CLI::line( \WP_CLI::colorize( 'Hide Login:     %GON%n (address hidden by LOGIN_ARMOR_CLI_HIDE_SLUG; add --show-slug to print it)' ) );
		} elseif ( $hide_enabled && $hide_slug !== '' ) {
			\WP_CLI::line( \WP_CLI::colorize( 'Hide Login:     %GON%n (slug: ' . $hide_slug . ')' ) );
			// 2.8.0: this command is the recovery method the Hide Login
			// section and the recovery e-mail recommend for a lost login URL,
			// so it prints the URL itself, in the form the site really serves
			// (plain permalinks take ?slug, not /slug/).
			\WP_CLI::line( '                Login URL: ' . HideLogin::get_login_url() );
		} else {
			\WP_CLI::line( \WP_CLI::colorize( 'Hide Login:     %ROFF%n' ) );
		}

		// Brute Force.
		$limit_enabled = (bool) get_option( 'login_armor_limit_enabled', true );
		if ( $limit_enabled ) {
			$retries   = (int) get_option( 'login_armor_allowed_retries', 4 );
			$lockout   = (int) get_option( 'login_armor_lockout_duration', 20 );
			$max_lock  = (int) get_option( 'login_armor_max_lockouts', 4 );
			$long      = (int) get_option( 'login_armor_long_duration', 24 );
			$ip_method = (string) get_option( 'login_armor_ip_method', 'REMOTE_ADDR' );
			\WP_CLI::line( \WP_CLI::colorize(
				sprintf( 'Brute Force:    %%GON%%n (%d retries, %dmin lockout, %d max → %dh ban, IP: %s)', $retries, $lockout, $max_lock, $long, $ip_method )
			) );
		} else {
			\WP_CLI::line( \WP_CLI::colorize( 'Brute Force:    %ROFF%n' ) );
		}

		// Detection.
		$detect_enabled = (bool) get_option( 'login_armor_detection_enabled', true );
		if ( $detect_enabled ) {
			global $wpdb;
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- CLI status read.
			$active_count = (int) $wpdb->get_var(
				$wpdb->prepare(
					"SELECT COUNT(*) FROM {$wpdb->prefix}login_armor_incidents WHERE status = %s",
					'active'
				)
			);
			\WP_CLI::line( \WP_CLI::colorize(
				sprintf( 'Detection:      %%GON%%n (%d active incident%s)', $active_count, $active_count !== 1 ? 's' : '' )
			) );
		} else {
			\WP_CLI::line( \WP_CLI::colorize( 'Detection:      %ROFF%n' ) );
		}

		// Hardening.
		$settings = Hardening::get_settings();
		$total    = count( $settings );
		$on       = count( array_filter( $settings ) );
		$pct      = $total > 0 ? (int) round( $on / $total * 100 ) : 0;
		\WP_CLI::line( sprintf( 'Hardening:      %d/%d (score: %d%%)', $on, $total, $pct ) );

		// Notifications.
		$notif_channel = (string) get_option( 'login_armor_notif_channel', 'disabled' );
		if ( 'disabled' !== $notif_channel ) {
			$min_sev    = (int) get_option( 'login_armor_notif_min_severity', 2 );
			$sev_labels = [ 1 => 'low', 2 => 'medium', 3 => 'high', 4 => 'critical' ];
			$sev_label  = $sev_labels[ $min_sev ] ?? 'medium';
			\WP_CLI::line( \WP_CLI::colorize(
				sprintf( 'Notifications:  %%GON%%n (%s, severity >= %s)', ucfirst( $notif_channel ), $sev_label )
			) );
		} else {
			\WP_CLI::line( \WP_CLI::colorize( 'Notifications:  %ROFF%n' ) );
		}

		// Activity Log.
		$activity_on = (bool) get_option( 'login_armor_activity_enabled', false );
		if ( $activity_on ) {
			$retention = (int) get_option( 'login_armor_activity_retention', 90 );
			\WP_CLI::line( \WP_CLI::colorize(
				sprintf( 'Activity Log:   %%GON%%n (retention: %dd)', $retention )
			) );
		} else {
			\WP_CLI::line( \WP_CLI::colorize( 'Activity Log:   %ROFF%n' ) );
		}

		// Two-Factor Authentication.
		$tfa_on = (bool) get_option( 'login_armor_2fa_enabled', false );
		if ( $tfa_on ) {
			$enforce = (array) get_option( 'login_armor_2fa_enforce_roles', [] );
			$enforce_label = empty( $enforce ) ? 'voluntary' : implode( ', ', $enforce );
			\WP_CLI::line( \WP_CLI::colorize(
				sprintf( 'Two-Factor:     %%GON%%n (enforce: %s)', $enforce_label )
			) );
		} else {
			\WP_CLI::line( \WP_CLI::colorize( 'Two-Factor:     %ROFF%n' ) );
		}
	}

	/**
	 * Reset or change the Hide Login slug.
	 *
	 * ## OPTIONS
	 *
	 * [--slug=<slug>]
	 * : Custom slug to set. If omitted, a random slug is generated.
	 *
	 * [--yes]
	 * : Skip confirmation prompt.
	 *
	 * ## EXAMPLES
	 *
	 *     wp login-armor reset-slug
	 *     wp login-armor reset-slug --slug=my-secret-login
	 *
	 * @subcommand reset-slug
	 * @param array<int,string>    $args       Positional arguments (unused).
	 * @param array<string,string> $assoc_args Named arguments.
	 */
	public function reset_slug( array $args, array $assoc_args ): void {
		if ( isset( $assoc_args['slug'] ) ) {
			$slug = sanitize_title( $assoc_args['slug'] );
			if ( '' === $slug ) {
				\WP_CLI::error( 'Invalid slug.' );
			}
			if ( in_array( $slug, HideLogin::RESERVED_SLUGS, true ) ) {
				\WP_CLI::error( sprintf( 'The slug "%s" is reserved and cannot be used.', $slug ) );
			}
			// Check page/post collision.
			$collision = get_page_by_path( $slug );
			if ( $collision instanceof \WP_Post ) {
				\WP_CLI::error( sprintf( 'The slug "%s" conflicts with an existing page/post (ID %d).', $slug, $collision->ID ) );
			}
		} else {
			$slug = $this->generate_random_slug();
		}

		\WP_CLI::confirm( 'This will change your login URL. The old URL will stop working. Continue?', $assoc_args );

		update_option( HideLogin::OPTION_SLUG, $slug );
		\WP_CLI::success( sprintf( 'Login URL changed to: %s', HideLogin::build_login_url( '/' . $slug ) ) );
	}

	/**
	 * Show, or carry out, the ways back into a site this plugin has shut you out of.
	 *
	 * Without --yes this prints and changes nothing: the wp-config.php line that
	 * arms safe mode, and the existing commands that undo each lockout cause.
	 * With --yes it runs the ones the flags name, by delegating to the very
	 * subcommands printed above, so there is one implementation of each.
	 *
	 * Safe mode itself is never armed from here: writing to wp-config.php is a
	 * decision for a human with file access, and it is the one step that proves
	 * the person asking is not merely holding a stolen WP-CLI session.
	 *
	 * ## OPTIONS
	 *
	 * [--user=<login>]
	 * : Reset two-factor enrolment for this account (lost device, unreachable inbox).
	 *
	 * [--ip=<ip>]
	 * : Clear the brute-force lockout on this address.
	 *
	 * [--yes]
	 * : Actually carry out the actions the flags name, instead of printing them.
	 *
	 * ## EXAMPLES
	 *
	 *     wp login-armor rescue
	 *     wp login-armor rescue --ip=203.0.113.7 --yes
	 *     wp login-armor rescue --user=admin --yes
	 *
	 * @since 2.7.0
	 * @param array<int,string>    $args       Positional arguments (unused).
	 * @param array<string,string> $assoc_args Named arguments.
	 */
	public function rescue( array $args, array $assoc_args ): void {
		unset( $args );

		$user_login = self::user_option( $assoc_args );
		$ip         = isset( $assoc_args['ip'] ) ? (string) $assoc_args['ip'] : '';
		$apply      = ! empty( $assoc_args['yes'] );

		if ( ! $apply ) {
			\WP_CLI::line( 'Ways back in, in the order you should try them. Nothing below has been done.' );
			\WP_CLI::line( '' );
			\WP_CLI::line( '1. Forgotten login URL: print it (changes nothing), or replace it with a new one:' );
			\WP_CLI::line( '     wp login-armor status' );
			\WP_CLI::line( '     wp login-armor reset-slug' );
			\WP_CLI::line( '2. Lost two-factor device, or verification codes that never arrive:' );
			\WP_CLI::line( '     wp login-armor 2fa reset <user> --yes' );
			\WP_CLI::line( '3. Your own address locked out by the brute-force counter or by a blocked network:' );
			\WP_CLI::line( '     wp login-armor unblock <ip>' );
			\WP_CLI::line( '4. HTTPS enforcement on a site that is not reachable over HTTPS yet:' );
			\WP_CLI::line( '     wp option patch update login_armor_hardening force_https false' );
			// The constant is NOT repeated here. This list is a ladder from the
			// narrowest fix to the widest, and step 5 already IS the constant:
			// printing it twice would read as two equal choices when the
			// targeted one is strictly better, because it leaves the rest of
			// the protection standing. What step 4 owed the reader is that
			// step 5 covers this toggle too, which is one line and no second
			// define to mistype at 2am.
			\WP_CLI::line( '   (step 5 stands this toggle down too, without changing the setting.)' );
			\WP_CLI::line( '5. Everything at once, without deciding what broke: add this line to wp-config.php,' );
			\WP_CLI::line( '   then delete it once you are back in. Your settings are untouched.' );
			\WP_CLI::line( "     define( 'LOGIN_ARMOR_SAFE_MODE', true );" );
			\WP_CLI::line( '' );
			if ( LoginArmor::is_safe_mode() ) {
				\WP_CLI::warning( 'Safe mode is currently ACTIVE. Remove the constant from wp-config.php once you are back in.' );
			}
			\WP_CLI::line( 'Re-run with --user=<login> and/or --ip=<ip> plus --yes to carry out steps 2 and 3.' );
			return;
		}

		if ( '' === $user_login && '' === $ip ) {
			\WP_CLI::error( '--yes needs something to do: pass --user=<login>, --ip=<ip>, or both.' );
		}

		// Delegation, not a second copy. Each subcommand already validates its
		// own argument and prints its own result, and this command printed its
		// name a moment ago: a reimplementation here would be a second thing
		// to keep in step with the first, inside the one command that has to
		// be right on the worst day. $assoc_args carries --yes through, which
		// is what makes WP_CLI::confirm() inside do_2fa_reset() pass.
		if ( '' !== $user_login ) {
			$this->do_2fa_reset( $user_login, $assoc_args );
		}

		if ( '' !== $ip ) {
			$this->unblock( array( $ip ), $assoc_args );
		}
	}

	/**
	 * Unblock a locked-out IP address.
	 *
	 * ## OPTIONS
	 *
	 * <ip>
	 * : The IP address to unblock.
	 *
	 * ## EXAMPLES
	 *
	 *     wp login-armor unblock 192.168.1.100
	 *
	 * @param array<int,string>    $args       Positional arguments.
	 * @param array<string,string> $assoc_args Named arguments (unused).
	 */
	public function unblock( array $args, array $assoc_args ): void {
		$ip = $args[0] ?? '';
		if ( ! filter_var( $ip, FILTER_VALIDATE_IP ) ) {
			\WP_CLI::error( 'Invalid IP address.' );
		}

		// 2.8.0: release_ip() also removes the blocked network that contains
		// the address. Until then this answered "was not blocked" to an
		// administrator shut out by "Block subnet", and left the block on.
		$released = LimitLogin::release_ip( $ip );
		$deleted  = $released['rows'];

		if ( '' !== $released['subnet'] ) {
			\WP_CLI::success( sprintf( 'Blocked network %s removed from the blocklist.', $released['subnet'] ) );
		}

		if ( $deleted > 0 ) {
			\WP_CLI::success( sprintf( 'IP %s has been unblocked (%d record%s removed).', $ip, $deleted, $deleted > 1 ? 's' : '' ) );
		} elseif ( '' === $released['subnet'] ) {
			\WP_CLI::warning( sprintf( 'IP %s was not blocked.', $ip ) );
		}
	}

	/**
	 * Manage the IP safelist.
	 *
	 * ## OPTIONS
	 *
	 * <action>
	 * : Action to perform: add, remove, or list.
	 *
	 * [<ip>]
	 * : The IP address (required for add/remove).
	 *
	 * [--format=<format>]
	 * : Output format for 'list'. Default: table.
	 * ---
	 * default: table
	 * options:
	 *   - table
	 *   - json
	 *   - csv
	 *   - yaml
	 * ---
	 *
	 * ## EXAMPLES
	 *
	 *     wp login-armor whitelist list
	 *     wp login-armor whitelist add 10.0.0.1
	 *     wp login-armor whitelist remove 10.0.0.1
	 *
	 * @param array<int,string>    $args       Positional arguments.
	 * @param array<string,string> $assoc_args Named arguments.
	 */
	public function whitelist( array $args, array $assoc_args ): void {
		$action = $args[0] ?? '';

		match ( $action ) {
			'add'    => $this->do_whitelist_add( $args[1] ?? '' ),
			'remove' => $this->do_whitelist_remove( $args[1] ?? '' ),
			'list'   => $this->do_whitelist_list( $assoc_args ),
			default  => \WP_CLI::error( "Unknown whitelist action '{$action}'. Use 'add', 'remove', or 'list'." ),
		};
	}

	/**
	 * Manage security incidents.
	 *
	 * ## OPTIONS
	 *
	 * <action>
	 * : Action to perform: list, resolve, bulk-resolve, or bulk-ignore.
	 *
	 * [<id>]
	 * : Incident ID (required for resolve).
	 *
	 * [--ids=<ids>]
	 * : Comma-separated incident IDs (for bulk-resolve / bulk-ignore).
	 *
	 * [--status=<status>]
	 * : Filter by status (list, and bulk-resolve / bulk-ignore with --all).
	 *
	 * [--pattern=<pattern>]
	 * : Filter by pattern (list, and bulk-resolve / bulk-ignore with --all).
	 *
	 * [--severity=<severity>]
	 * : Filter by exact severity 1-4 (bulk-resolve / bulk-ignore with --all).
	 *
	 * [--min-severity=<severity>]
	 * : Filter by minimum severity 2-4 (bulk-resolve / bulk-ignore with --all).
	 *
	 * [--period=<period>]
	 * : Filter by recency: 24h, 7d or 30d (bulk-resolve / bulk-ignore with --all).
	 *
	 * [--all]
	 * : Apply the bulk operation to every incident matching the filters above, instead of an explicit --ids list. Refused when no filter is given.
	 *
	 * [--dry-run]
	 * : With --all, report how many incidents would change and touch nothing.
	 *
	 * [--format=<format>]
	 * : Output format for list. Default: table.
	 * ---
	 * default: table
	 * options:
	 *   - table
	 *   - json
	 *   - csv
	 *   - yaml
	 * ---
	 *
	 * [--fields=<fields>]
	 * : Limit output to specific fields (comma-separated).
	 *
	 * ## EXAMPLES
	 *
	 *     wp login-armor incidents list
	 *     wp login-armor incidents list --status=active --format=json
	 *     wp login-armor incidents resolve 42
	 *     wp login-armor incidents bulk-resolve --ids=12,13,14
	 *     wp login-armor incidents bulk-ignore --ids=20,21
	 *     wp login-armor incidents bulk-resolve --all --status=active --severity=1
	 *     wp login-armor incidents bulk-ignore --all --pattern=firewall_block --dry-run
	 *
	 * @param array<int,string>    $args       Positional arguments.
	 * @param array<string,string> $assoc_args Named arguments.
	 */
	public function incidents( array $args, array $assoc_args ): void {
		$action = $args[0] ?? '';

		match ( $action ) {
			'list'         => $this->do_incidents_list( $assoc_args ),
			'resolve'      => $this->do_incidents_resolve( $args[1] ?? '' ),
			'bulk-resolve' => $this->do_incidents_bulk( 'resolve', $assoc_args ),
			'bulk-ignore'  => $this->do_incidents_bulk( 'ignore', $assoc_args ),
			default        => \WP_CLI::error( "Unknown incidents action '{$action}'. Use 'list', 'resolve', 'bulk-resolve', or 'bulk-ignore'." ),
		};
	}

	/**
	 * Purge old logs, attempts, and resolved incidents.
	 *
	 * ## OPTIONS
	 *
	 * [--days=<days>]
	 * : Override the configured retention period (in days).
	 *
	 * [--yes]
	 * : Skip confirmation prompt.
	 *
	 * ## EXAMPLES
	 *
	 *     wp login-armor purge-logs
	 *     wp login-armor purge-logs --days=30 --yes
	 *
	 * @subcommand purge-logs
	 * @param array<int,string>    $args       Positional arguments (unused).
	 * @param array<string,string> $assoc_args Named arguments.
	 */
	public function purge_logs( array $args, array $assoc_args ): void {
		$days = isset( $assoc_args['days'] ) ? (int) $assoc_args['days'] : null;

		if ( $days !== null && $days <= 0 ) {
			\WP_CLI::error( 'The --days value must be a positive integer.' );
		}

		$display_days = $days ?? (int) get_option( 'login_armor_log_retention_days',
			(int) get_option( 'login_armor_logs_auto_purge', 90 )
		);

		\WP_CLI::confirm(
			sprintf( 'This will permanently delete logs older than %d days. Continue?', $display_days ),
			$assoc_args
		);

		$deleted = LoginArmor::do_purge( $days );
		\WP_CLI::success( sprintf( '%d record%s deleted.', $deleted, $deleted !== 1 ? 's' : '' ) );
	}

	/**
	 * View recent activity log entries or verify HMAC chain integrity.
	 *
	 * ## OPTIONS
	 *
	 * <action>
	 * : Action to perform: list | verify-chain | reset-chain.
	 *
	 * [--limit=<limit>]
	 * : (list) Number of entries to show. Default: 20.
	 *
	 * [--user=<user_login>]
	 * : (list) Filter by user login.
	 *
	 * [--type=<type>]
	 * : (list) Filter by object type (post, user, media, plugin, theme, option).
	 *
	 * [--from=<id>]
	 * : (verify-chain) Start row id. Default: chain start id.
	 *
	 * [--to=<id>]
	 * : (verify-chain) End row id. Default: latest row.
	 *
	 * [--repair-orphans]
	 * : (verify-chain) Recompute row_hash for any row where row_hash IS NULL before verifying.
	 *
	 * [--verbose]
	 * : (verify-chain) Print progress and detailed counters.
	 *
	 * [--yes]
	 * : (reset-chain) Skip the confirmation prompt.
	 *
	 * [--format=<format>]
	 * : Output format. Default: table.
	 * ---
	 * default: table
	 * options:
	 *   - table
	 *   - json
	 *   - csv
	 *   - yaml
	 * ---
	 *
	 * [--fields=<fields>]
	 * : Limit output to specific fields (comma-separated).
	 *
	 * ## EXAMPLES
	 *
	 *     wp login-armor activity list
	 *     wp login-armor activity list --type=plugin --limit=50
	 *     wp login-armor activity list --user=admin --format=json
	 *
	 *     # Verify entire chain
	 *     wp login-armor activity verify-chain
	 *
	 *     # Verify a specific range, JSON output (for CI/SIEM piping)
	 *     wp login-armor activity verify-chain --from=1000 --to=2000 --format=json
	 *
	 *     # Repair orphans first, then verify
	 *     wp login-armor activity verify-chain --repair-orphans --verbose
	 *
	 *     # Re-baseline the chain after a migration / security-key change
	 *     wp login-armor activity reset-chain --yes
	 *
	 * Exit codes (verify-chain):
	 * - 0: chain intact
	 * - 1: chain broken (one or more rows fail HMAC check)
	 * - 2: error (DB unreachable, secret missing, etc.)
	 *
	 * @param array<int,string>    $args       Positional arguments.
	 * @param array<string,string> $assoc_args Named arguments.
	 */
	public function activity( array $args, array $assoc_args ): void {
		$action = $args[0] ?? '';

		match ( $action ) {
			'list'         => $this->do_activity_list( $assoc_args ),
			'verify-chain' => $this->do_activity_verify_chain( $assoc_args ),
			'reset-chain'  => $this->do_activity_reset_chain( $assoc_args ),
			default        => \WP_CLI::error( "Unknown activity action '{$action}'. Use 'list', 'verify-chain', or 'reset-chain'." ),
		};
	}

	/**
	 * List activity log entries.
	 *
	 * @param array<string,string> $assoc_args Named arguments.
	 */
	private function do_activity_list( array $assoc_args ): void {
		require_once LOGIN_ARMOR_DIR . 'includes/ActivityLog/ActivityLog.php';

		if ( ! \LoginArmor\ActivityLog\ActivityLog::is_enabled() ) {
			\WP_CLI::error( 'Activity Log module is disabled. Enable it in Settings first.' );
		}

		$limit = isset( $assoc_args['limit'] ) ? absint( $assoc_args['limit'] ) : 20;
		if ( $limit <= 0 ) {
			$limit = 20;
		}

		$filters = [];
		if ( isset( $assoc_args['type'] ) ) {
			$filters['object_type'] = $assoc_args['type'];
		}

		$user_login = self::user_option( $assoc_args );
		if ( '' !== $user_login ) {
			$user = get_user_by( 'login', $user_login );
			if ( ! $user ) {
				\WP_CLI::error( sprintf( 'User "%s" not found.', $user_login ) );
			}
			$filters['user_id'] = (string) $user->ID;
		}

		$rows = \LoginArmor\ActivityLog\ActivityLog::get_logs( $filters, $limit, 0 );

		if ( empty( $rows ) ) {
			\WP_CLI::log( 'No activity entries found.' );
			return;
		}

		$items = array_map( static function ( $row ) {
			return [
				'id'          => $row->id,
				'log_time'    => $row->log_time,
				'user_login'  => $row->user_login,
				'user_role'   => $row->user_role,
				'action'      => $row->action,
				'object_type' => $row->object_type,
				'object_name' => $row->object_name,
				'description' => $row->description,
				'ip'          => $row->ip,
			];
		}, $rows );

		$default_fields = [ 'id', 'log_time', 'user_login', 'action', 'object_type', 'object_name', 'ip' ];
		$formatter      = new \WP_CLI\Formatter( $assoc_args, $default_fields );
		$formatter->display_items( $items );
	}

	/**
	 * Verify the HMAC chain integrity of the Activity Log.
	 *
	 * Exit codes:
	 * - 0: chain intact
	 * - 1: chain broken (one or more rows fail HMAC check) or invalid input
	 * - 2: error (DB unreachable, secret missing, etc.; surfaces as PHP fatal)
	 *
	 * @param array<string,string> $assoc_args Named arguments.
	 */
	private function do_activity_verify_chain( array $assoc_args ): void {
		require_once LOGIN_ARMOR_DIR . 'includes/ActivityLog/ActivityLog.php';

		$from           = isset( $assoc_args['from'] ) ? (int) $assoc_args['from'] : null;
		$to             = isset( $assoc_args['to'] ) ? (int) $assoc_args['to'] : null;
		$repair_orphans = isset( $assoc_args['repair-orphans'] );
		$format         = isset( $assoc_args['format'] ) ? (string) $assoc_args['format'] : 'table';
		$verbose        = isset( $assoc_args['verbose'] );

		if ( ! in_array( $format, [ 'table', 'json' ], true ) ) {
			\WP_CLI::error( "Unknown format: {$format}. Use 'table' or 'json'." );
		}

		$orphans_repaired = 0;
		if ( $repair_orphans ) {
			if ( $verbose ) {
				\WP_CLI::log( 'Repairing orphan rows...' );
			}
			$orphans_repaired = \LoginArmor\ActivityLog\ActivityLog::repair_chain();
			if ( $verbose ) {
				\WP_CLI::log( sprintf( 'Repaired %d orphan(s).', $orphans_repaired ) );
			}
		}

		if ( $verbose ) {
			\WP_CLI::log( 'Verifying chain...' );
		}
		$result = \LoginArmor\ActivityLog\ActivityLog::verify_chain( $from, $to );

		// 2.8.1: the Integrity panel shows the last verification of the whole
		// chain, which the daily check and the panel's own button keep. This
		// command did not, so verifying from the shell left the panel on
		// "UNVERIFIED" (seen on cours-ndrc.fr, whose object cache had been
		// flushed). A range is not the whole chain and leaves the panel alone.
		if ( null === $from && null === $to ) {
			set_transient( 'login_armor_chain_verify_last', $result, 7 * DAY_IN_SECONDS );
		}

		$salt_changed = ! empty( $result['salt_changed'] );

		if ( 'json' === $format ) {
			$payload = [
				'status'           => $result['status'],
				'total_verified'   => $result['total'],
				'broken_rows'      => $result['broken'],
				'first_break'      => ! empty( $result['broken'] ) ? $result['broken'][0]['id'] : null,
				'orphans_repaired' => $orphans_repaired,
				'orphans_present'  => $result['orphans'],
				'salt_changed'     => $salt_changed,
				'verified_at'      => $result['verified_at'],
			];
			\WP_CLI::log( wp_json_encode( $payload, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES ) );
		} else {
			\WP_CLI::log( '' );
			\WP_CLI::log( 'Chain status: ' . strtoupper( $result['status'] ) );
			if ( $salt_changed ) {
				\WP_CLI::log( '' );
				\WP_CLI::warning( 'Security keys changed since the last baseline (site migration, restored backup, or manual wp-config.php change). The pre-change rows can no longer be verified. Run `wp login-armor activity reset-chain` to re-baseline once you trust the current data.' );
			}
			if ( ! empty( $result['broken'] ) ) {
				$rows = array_map(
					static function ( $b ) {
						return [
							'row_id'   => $b['id'],
							'log_time' => $b['log_time'],
							'issue'    => $b['issue'],
						];
					},
					$result['broken']
				);
				\WP_CLI\Utils\format_items( 'table', $rows, [ 'row_id', 'log_time', 'issue' ] );
			}
			\WP_CLI::log( '' );
			\WP_CLI::log( '  Total rows verified: ' . number_format_i18n( $result['total'] ) );
			\WP_CLI::log( '  Broken rows: ' . count( $result['broken'] ) );
			if ( ! empty( $result['broken'] ) ) {
				\WP_CLI::log( '  First break: row ' . $result['broken'][0]['id'] );
			}
			\WP_CLI::log( '  Orphans present: ' . $result['orphans'] );
			\WP_CLI::log( '  Repaired orphans: ' . $orphans_repaired );
		}

		if ( 'broken' === $result['status'] ) {
			\WP_CLI::halt( 1 );
		}
	}

	/**
	 * Re-baseline the activity-log HMAC chain under the current security key.
	 *
	 * Remedy for a benign key rotation (site migration, restored backup, manual
	 * wp-config.php change) that leaves pre-rotation rows unverifiable. Re-signs
	 * every row under the current wp_salt('auth') and records the new baseline.
	 *
	 * @param array<string,string> $assoc_args Named arguments (expects --yes).
	 */
	private function do_activity_reset_chain( array $assoc_args ): void {
		require_once LOGIN_ARMOR_DIR . 'includes/ActivityLog/ActivityLog.php';

		if ( ! \LoginArmor\ActivityLog\ActivityLog::is_enabled() ) {
			\WP_CLI::error( 'Activity Log module is disabled. Enable it in Settings first.' );
		}

		\WP_CLI::confirm(
			'This re-signs every activity row under the current security key and trusts the table as it stands now. Only do this after a key change you expected. Continue?',
			$assoc_args
		);

		$result = \LoginArmor\ActivityLog\ActivityLog::reset_chain();

		// Re-verify and refresh the cached panel state so the admin UI updates.
		$verify = \LoginArmor\ActivityLog\ActivityLog::verify_chain();
		set_transient( 'login_armor_chain_verify_last', $verify, 7 * DAY_IN_SECONDS );

		\WP_CLI::success( sprintf(
			'%d row(s) re-signed. Chain re-based at row %d. New status: %s.',
			$result['rows'],
			$result['chain_start_id'],
			strtoupper( $verify['status'] )
		) );
	}

	/**
	 * Manage two-factor authentication.
	 *
	 * ## OPTIONS
	 *
	 * <action>
	 * : Action to perform: status, reset, or devices.
	 *
	 * [<target>]
	 * : For reset: the user login. For devices: list or revoke.
	 *
	 * [<user_login>]
	 * : For devices list and devices revoke: the user login.
	 *
	 * [--id=<id>]
	 * : For devices revoke: the device to revoke, as shown by devices list.
	 *
	 * [--all]
	 * : For devices revoke: revoke every trusted device of the user.
	 *
	 * [--yes]
	 * : Skip confirmation prompt (for reset).
	 *
	 * [--format=<format>]
	 * : Output format for status. Default: table.
	 * ---
	 * default: table
	 * options:
	 *   - table
	 *   - json
	 *   - csv
	 *   - yaml
	 * ---
	 *
	 * [--fields=<fields>]
	 * : Limit output to specific fields (comma-separated).
	 *
	 * [--user=<user>]
	 * : Limit status output to a single user (login or email). Useful for diagnosing 2FA enrollment state. For devices, an alternative to the positional user login.
	 *
	 * ## EXAMPLES
	 *
	 *     wp login-armor 2fa status
	 *     wp login-armor 2fa status --user=alice
	 *     wp login-armor 2fa reset admin --yes
	 *     wp login-armor 2fa devices list alice
	 *     wp login-armor 2fa devices revoke alice --all
	 *
	 * @subcommand 2fa
	 * @param array<int,string>    $args       Positional arguments.
	 * @param array<string,string> $assoc_args Named arguments.
	 */
	public function two_factor_auth( array $args, array $assoc_args ): void {
		$action = $args[0] ?? '';

		match ( $action ) {
			'status'  => $this->do_2fa_status( $assoc_args ),
			'reset'   => $this->do_2fa_reset( $args[1] ?? '', $assoc_args ),
			'devices' => $this->do_2fa_devices( $args, $assoc_args ),
			default   => \WP_CLI::error( "Unknown 2fa action '{$action}'. Use 'status', 'reset', or 'devices'." ),
		};
	}

	/**
	 * Display 2FA enrollment status for all users.
	 *
	 * @param array<string,string> $assoc_args Named arguments.
	 */
	private function do_2fa_status( array $assoc_args ): void {
		$module_on = (bool) get_option( 'login_armor_2fa_enabled', false );
		if ( ! $module_on ) {
			\WP_CLI::warning( '2FA module is disabled globally. Per-user enrollment data is still shown below for diagnostic purposes.' );
		}

		$user_filter = self::user_option( $assoc_args );
		if ( '' !== $user_filter ) {
			$single = get_user_by( 'login', $user_filter );
			if ( ! $single ) {
				$single = get_user_by( 'email', $user_filter );
			}
			if ( ! $single ) {
				\WP_CLI::error( sprintf( 'User "%s" not found.', $user_filter ) );
			}
			$users = [ $single ];
		} else {
			$users = get_users( [
				'orderby' => 'user_login',
				'order'   => 'ASC',
			] );
		}

		if ( empty( $users ) ) {
			\WP_CLI::log( 'No users found.' );
			return;
		}

		require_once LOGIN_ARMOR_DIR . 'includes/TwoFactor/BackupCodes.php';

		$items = [];
		foreach ( $users as $user ) {
			$enabled   = (bool) get_user_meta( $user->ID, 'login_armor_2fa_enabled', true );
			$confirmed = (bool) get_user_meta( $user->ID, 'login_armor_2fa_confirmed', true );
			$method    = (string) get_user_meta( $user->ID, 'login_armor_2fa_method', true );
			$grace     = (int) get_user_meta( $user->ID, 'login_armor_2fa_grace_until', true );
			$remaining = \LoginArmor\TwoFactor\BackupCodes::remaining( $user->ID );
			$roles     = ! empty( $user->roles ) ? implode( ', ', $user->roles ) : 'none';

			$items[] = [
				'user_login'   => $user->user_login,
				'role'         => $roles,
				'enabled'      => $enabled ? 'yes' : 'no',
				'confirmed'    => $confirmed ? 'yes' : 'no',
				'method'       => '' !== $method ? $method : '-',
				'backup_codes' => $enabled ? (string) $remaining : '-',
				'grace_until'  => $grace > 0 ? gmdate( 'Y-m-d H:i', $grace ) : '-',
			];
		}

		$default_fields = [ 'user_login', 'role', 'enabled', 'confirmed', 'method', 'backup_codes', 'grace_until' ];
		$formatter      = new \WP_CLI\Formatter( $assoc_args, $default_fields );
		$formatter->display_items( $items );
	}

	/**
	 * Reset all 2FA data for a user.
	 *
	 * @param string               $user_login User login.
	 * @param array<string,string> $assoc_args Named arguments.
	 */
	private function do_2fa_reset( string $user_login, array $assoc_args ): void {
		if ( '' === $user_login ) {
			\WP_CLI::error( 'Please provide a user login.' );
		}

		$user = get_user_by( 'login', $user_login );
		if ( ! $user ) {
			\WP_CLI::error( sprintf( 'User "%s" not found.', $user_login ) );
		}

		\WP_CLI::confirm(
			sprintf( 'This will remove all 2FA data for "%s". Continue?', $user_login ),
			$assoc_args
		);

		require_once LOGIN_ARMOR_DIR . 'includes/TwoFactor/TwoFactor.php';
		require_once LOGIN_ARMOR_DIR . 'includes/TwoFactor/BackupCodes.php';

		\LoginArmor\TwoFactor\TwoFactor::reset_user( $user->ID );

		\WP_CLI::success( sprintf( 'All 2FA data removed for "%s".', $user_login ) );
	}

	/**
	 * Route `wp login-armor 2fa devices <list|revoke> <user> [--id=<id>|--all]`.
	 *
	 * @param array<int,string>    $args       CLI positional args (starts with 'devices').
	 * @param array<string,string> $assoc_args CLI flags.
	 */
	private function do_2fa_devices( array $args, array $assoc_args ): void {
		// 2.8.0: the synopsis used to declare a single optional positional
		// after the action, so WP-CLI refused `devices list <user>` with "Too
		// many positional arguments" before this code ever ran. --user is
		// accepted too, through user_option() like every --user of this class.
		$sub        = $args[1] ?? '';
		$user_login = $args[2] ?? self::user_option( $assoc_args );
		unset( $assoc_args['user'] );
		if ( '' === $user_login ) {
			\WP_CLI::error( 'Please provide a user login.' );
		}
		$user = get_user_by( 'login', $user_login );
		if ( ! $user ) {
			\WP_CLI::error( sprintf( 'User "%s" not found.', $user_login ) );
		}

		require_once LOGIN_ARMOR_DIR . 'includes/TwoFactor/TrustedDevices.php';

		if ( 'list' === $sub ) {
			$devices = \LoginArmor\TwoFactor\TrustedDevices::list_for_user( $user->ID );
			if ( [] === $devices ) {
				\WP_CLI::log( sprintf( 'No trusted devices for "%s".', $user_login ) );
				return;
			}
			$items = array_map(
				static fn( array $d ) => [
					'id'           => $d['id'],
					'label'        => $d['label'],
					'ip_at_grant'  => $d['ip_at_grant'],
					'granted'      => wp_date( 'Y-m-d H:i', (int) $d['granted_at'] ),
					'expires'      => wp_date( 'Y-m-d H:i', (int) $d['expires_at'] ),
					'last_seen'    => wp_date( 'Y-m-d H:i', (int) $d['last_seen_at'] ),
				],
				$devices
			);
			$formatter = new \WP_CLI\Formatter(
				$assoc_args,
				[ 'id', 'label', 'ip_at_grant', 'granted', 'expires', 'last_seen' ]
			);
			$formatter->display_items( $items );
			return;
		}

		if ( 'revoke' === $sub ) {
			if ( ! empty( $assoc_args['all'] ) ) {
				$count = \LoginArmor\TwoFactor\TrustedDevices::revoke_all( $user->ID, 'admin' );
				\WP_CLI::success( sprintf( '%d device(s) revoked for "%s".', $count, $user_login ) );
				return;
			}
			$device_id = (string) ( $assoc_args['id'] ?? '' );
			if ( '' === $device_id ) {
				\WP_CLI::error( 'Pass --id=<device_id> or --all.' );
			}
			$ok = \LoginArmor\TwoFactor\TrustedDevices::revoke_device( $user->ID, $device_id );
			if ( ! $ok ) {
				\WP_CLI::error( sprintf( 'Device id "%s" not found for "%s".', $device_id, $user_login ) );
			}
			\WP_CLI::success( sprintf( 'Device "%s" revoked for "%s".', $device_id, $user_login ) );
			return;
		}

		\WP_CLI::error( "Unknown devices subcommand '{$sub}'. Use 'list' or 'revoke'." );
	}

	// ── Private helpers ──────────────────────────────────────────────

	/**
	 * The account named by --user=<login>, as a login (2.8.0).
	 *
	 * --user is one of WP-CLI's global parameters: it picks the account a
	 * command runs as, and WP-CLI files it in its runtime configuration, not
	 * in $assoc_args (only WP_CLI_STRICT_ARGS_MODE leaves a --user written
	 * after the command name to the command). Every --user= this class
	 * documents therefore arrived empty: `rescue --user=<login> --yes`
	 * answered "--yes needs something to do", `2fa status --user=` listed
	 * every account, `activity list --user=` every row. Both places are read.
	 * WP-CLI accepts an ID, a login or an e-mail there and refuses an unknown
	 * one before the command runs, so the value is read back as a login, the
	 * form these commands look accounts up by.
	 *
	 * @param array<string,string> $assoc_args Named arguments of the command.
	 */
	private static function user_option( array $assoc_args ): string {
		$value = $assoc_args['user'] ?? null;
		if ( null === $value ) {
			$config = \WP_CLI::get_runner()->config;
			$value  = is_array( $config ) ? ( $config['user'] ?? null ) : null;
		}
		$value = is_scalar( $value ) ? trim( (string) $value ) : '';
		if ( '' === $value ) {
			return '';
		}
		$user = get_user_by( 'login', $value );
		if ( ! $user && is_email( $value ) ) {
			$user = get_user_by( 'email', $value );
		}
		if ( ! $user && ctype_digit( $value ) ) {
			$user = get_user_by( 'id', (int) $value );
		}
		return $user instanceof \WP_User ? $user->user_login : $value;
	}

	/**
	 * Generate a random slug using the HideLogin alphabet.
	 */
	private function generate_random_slug(): string {
		$slug     = '';
		$alphabet = HideLogin::SLUG_ALPHABET;
		$length   = HideLogin::SLUG_LENGTH;
		$max      = strlen( $alphabet ) - 1;

		for ( $i = 0; $i < $length; $i++ ) {
			$slug .= $alphabet[ random_int( 0, $max ) ];
		}

		return $slug;
	}

	/**
	 * Parse the whitelist option into an array of IPs.
	 *
	 * @return string[]
	 */
	private function get_whitelist(): array {
		$raw = (string) get_option( 'login_armor_whitelist_ips', '' );
		if ( '' === $raw ) {
			return [];
		}
		return array_values( array_filter( array_map( 'trim', explode( "\n", $raw ) ) ) );
	}

	/**
	 * Persist the whitelist array back to the option.
	 *
	 * @param string[] $ips List of IPs.
	 */
	private function save_whitelist( array $ips ): void {
		update_option( 'login_armor_whitelist_ips', implode( "\n", $ips ) );
	}

	/**
	 * Add an IP to the safelist.
	 *
	 * @param string $ip IP address to add.
	 */
	private function do_whitelist_add( string $ip ): void {
		if ( ! filter_var( $ip, FILTER_VALIDATE_IP ) ) {
			\WP_CLI::error( 'Invalid IP address.' );
		}

		$list = $this->get_whitelist();
		if ( in_array( $ip, $list, true ) ) {
			\WP_CLI::error( sprintf( 'IP %s is already in the safelist.', $ip ) );
		}

		$list[] = $ip;
		$this->save_whitelist( $list );
		\WP_CLI::success( sprintf( 'IP %s added to safelist.', $ip ) );
	}

	/**
	 * Remove an IP from the safelist.
	 *
	 * @param string $ip IP address to remove.
	 */
	private function do_whitelist_remove( string $ip ): void {
		if ( ! filter_var( $ip, FILTER_VALIDATE_IP ) ) {
			\WP_CLI::error( 'Invalid IP address.' );
		}

		$list = $this->get_whitelist();
		$key  = array_search( $ip, $list, true );

		if ( false === $key ) {
			\WP_CLI::warning( sprintf( 'IP %s was not in the safelist.', $ip ) );
			return;
		}

		unset( $list[ $key ] );
		$this->save_whitelist( array_values( $list ) );
		\WP_CLI::success( sprintf( 'IP %s removed from safelist.', $ip ) );
	}

	/**
	 * List all safelist IPs.
	 *
	 * @param array<string,string> $assoc_args Named arguments.
	 */
	private function do_whitelist_list( array $assoc_args ): void {
		$list = $this->get_whitelist();

		if ( empty( $list ) ) {
			\WP_CLI::log( 'Safelist is empty.' );
			return;
		}

		$items = array_map( static fn( string $ip ) => [ 'ip' => $ip ], $list );

		$formatter = new \WP_CLI\Formatter( $assoc_args, [ 'ip' ] );
		$formatter->display_items( $items );
	}

	/**
	 * List incidents with optional filters.
	 *
	 * @param array<string,string> $assoc_args Named arguments.
	 */
	private function do_incidents_list( array $assoc_args ): void {
		global $wpdb;

		$where  = [];
		$values = [];

		if ( isset( $assoc_args['status'] ) ) {
			$where[]  = 'status = %s';
			$values[] = $assoc_args['status'];
		}

		if ( isset( $assoc_args['pattern'] ) ) {
			$where[]  = 'pattern = %s';
			$values[] = $assoc_args['pattern'];
		}

		// `vector` backticked: reserved word since MariaDB 11.7 / MySQL 9.0.
		$sql = "SELECT id, pattern, `vector`, severity, status, ip, target_username, events_count, unique_ips, started_at, last_seen_at FROM {$wpdb->prefix}login_armor_incidents";

		if ( ! empty( $where ) ) {
			$sql .= ' WHERE ' . implode( ' AND ', $where );
		}

		$sql .= ' ORDER BY last_seen_at DESC';

		if ( ! empty( $values ) ) {
			// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared,PluginCheck.Security.DirectDB.UnescapedDBParameter -- Dynamic query built safely with $wpdb->prepare().
			$sql = $wpdb->prepare( $sql, ...$values );
		}

		// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,PluginCheck.Security.DirectDB.UnescapedDBParameter -- Dynamic query built safely with $wpdb->prepare().
		$rows = $wpdb->get_results( $sql, ARRAY_A );

		if ( empty( $rows ) ) {
			\WP_CLI::log( 'No incidents found.' );
			return;
		}

		$default_fields = [ 'id', 'pattern', 'vector', 'severity', 'status', 'ip', 'target_username', 'events_count', 'unique_ips', 'started_at', 'last_seen_at' ];
		$formatter      = new \WP_CLI\Formatter( $assoc_args, $default_fields );
		$formatter->display_items( $rows );
	}

	/**
	 * Resolve an incident by ID.
	 *
	 * @param string $id_raw Incident ID as string from CLI args.
	 */
	private function do_incidents_resolve( string $id_raw ): void {
		$id = (int) $id_raw;
		if ( $id <= 0 ) {
			\WP_CLI::error( 'Please provide a valid incident ID.' );
		}

		global $wpdb;

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- CLI action on custom table.
		$current_status = $wpdb->get_var(
			$wpdb->prepare(
				"SELECT status FROM {$wpdb->prefix}login_armor_incidents WHERE id = %d",
				$id
			)
		);

		if ( null === $current_status ) {
			\WP_CLI::error( sprintf( 'Incident #%d not found.', $id ) );
		}

		if ( 'active' !== $current_status ) {
			\WP_CLI::error( sprintf( 'Incident #%d is already %s.', $id, $current_status ) );
		}

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- CLI action on custom table.
		$wpdb->update(
			$wpdb->prefix . 'login_armor_incidents',
			[ 'status' => 'resolved' ],
			[ 'id' => $id ],
			[ '%s' ],
			[ '%d' ]
		);

		\WP_CLI::success( sprintf( 'Incident #%d marked as resolved.', $id ) );
	}

	/**
	 * Bulk-resolve or bulk-ignore incidents from a comma-separated --ids list.
	 * Only active incidents are affected.
	 *
	 * @param string                $op         'resolve' or 'ignore'.
	 * @param array<string,string>  $assoc_args Named arguments (expects --ids).
	 */
	private function do_incidents_bulk( string $op, array $assoc_args ): void {
		$status = 'resolve' === $op
			? \LoginArmor\Detection\Incident::STATUS_RESOLVED
			: \LoginArmor\Detection\Incident::STATUS_IGNORED;

		if ( ! empty( $assoc_args['all'] ) ) {
			$this->do_incidents_bulk_filtered( $op, $status, $assoc_args );
			return;
		}

		$ids_raw = isset( $assoc_args['ids'] ) ? (string) $assoc_args['ids'] : '';
		$ids     = array_values( array_filter( array_map( 'intval', explode( ',', $ids_raw ) ), static fn( $id ) => $id > 0 ) );

		if ( empty( $ids ) ) {
			\WP_CLI::error( 'Please provide incident IDs via --ids=1,2,3, or a filter plus --all.' );
		}

		$updated = 'resolve' === $op
			? \LoginArmor\Detection\Incident::bulk_resolve( $ids )
			: \LoginArmor\Detection\Incident::bulk_ignore( $ids );

		\WP_CLI::success( sprintf( '%d incident(s) marked as %s.', $updated, $status ) );
	}

	/**
	 * Apply a bulk operation to every incident matching the given filters.
	 *
	 * Two guards, and both matter. `--all` must be present, so that a filter
	 * typed by hand can never run wider than intended by being forgotten; and
	 * at least one filter must survive validation, so `--all` on its own, or
	 * with a misspelt value, is refused instead of resolving the entire table.
	 * A misspelt `--status=activ` is the dangerous case: Incident::
	 * sanitize_filters() drops what it does not recognise, so without this
	 * check the typo would silently widen the command to everything.
	 *
	 * The filters go through the SAME sanitize_filters() the Incidents tab and
	 * the AJAX endpoint use, so a command and a click on the same filter touch
	 * the same rows.
	 *
	 * @param string               $op         'resolve' or 'ignore'.
	 * @param string               $status     Target status.
	 * @param array<string,string> $assoc_args Named arguments.
	 */
	private function do_incidents_bulk_filtered( string $op, string $status, array $assoc_args ): void {
		unset( $op );

		$raw = array(
			'status'       => isset( $assoc_args['status'] ) ? (string) $assoc_args['status'] : '',
			'pattern'      => isset( $assoc_args['pattern'] ) ? (string) $assoc_args['pattern'] : '',
			'severity'     => isset( $assoc_args['severity'] ) ? (int) $assoc_args['severity'] : 0,
			'min_severity' => isset( $assoc_args['min-severity'] ) ? (int) $assoc_args['min-severity'] : 0,
			'period'       => isset( $assoc_args['period'] ) ? (string) $assoc_args['period'] : '',
		);

		// Which options the caller actually typed, before validation: a value
		// that was given but did not survive is a typo, and a typo on a
		// destructive command must stop it, never widen it.
		$given = array();
		foreach ( array( 'status', 'pattern', 'severity', 'min-severity', 'period' ) as $option ) {
			if ( isset( $assoc_args[ $option ] ) && '' !== (string) $assoc_args[ $option ] ) {
				$given[] = $option;
			}
		}

		$filters = \LoginArmor\Detection\Incident::sanitize_filters( $raw );

		if ( empty( $given ) ) {
			\WP_CLI::error( '--all needs at least one filter: --status, --pattern, --severity, --min-severity or --period. Refusing to act on every incident.' );
		}
		if ( count( $filters ) !== count( $given ) ) {
			\WP_CLI::error(
				sprintf(
					'One of the filters was not understood (%s). Refusing to run, because an unrecognised filter would widen the operation instead of narrowing it.',
					implode( ', ', $given )
				)
			);
		}

		// Counted with the predicate the UPDATE uses: rows this operation would
		// actually change, not rows that merely match the filter.
		$pending = \LoginArmor\Detection\Incident::pending( $filters, $status );
		$matched = \LoginArmor\Detection\Incident::count_filtered( $pending );

		if ( ! empty( $assoc_args['dry-run'] ) ) {
			\WP_CLI::log( sprintf( '%d incident(s) would be marked as %s. Nothing was changed (--dry-run).', $matched, $status ) );
			return;
		}

		$updated   = \LoginArmor\Detection\Incident::bulk_set_status_filtered( $filters, $status );
		$remaining = \LoginArmor\Detection\Incident::count_filtered( $pending );

		\WP_CLI::success( sprintf( '%d of %d matching incident(s) marked as %s.', $updated, $matched, $status ) );

		// A filtered run stops at a per-request ceiling. Saying so is the
		// difference between "finished" and "looks finished".
		if ( $remaining > 0 ) {
			\WP_CLI::warning( sprintf( '%d incident(s) still match: the per-run ceiling (%d) was reached. Run the command again to continue.', $remaining, \LoginArmor\Detection\Incident::bulk_max() ) );
		}
	}

	/**
	 * Manage hardening features (Lot 14).
	 *
	 * ## OPTIONS
	 *
	 * <action>
	 * : blacklist | honeypot
	 *
	 * [<subaction>]
	 * : blacklist: list | add | remove. honeypot: status.
	 *
	 * [<value>]
	 * : Username value for blacklist add|remove.
	 *
	 * ## EXAMPLES
	 *
	 *     wp login-armor hardening blacklist list
	 *     wp login-armor hardening blacklist add admin
	 *     wp login-armor hardening blacklist remove demo
	 *     wp login-armor hardening honeypot status
	 *
	 * ## SWITCHING A TOGGLE FROM THE COMMAND LINE
	 *
	 * Toggles themselves live in one option array and are set with
	 * `wp option patch update login_armor_hardening <key> <value>`. WordPress
	 * reads that value back with its own rule: only `false` and `0` mean OFF.
	 * `off`, `no` and `disabled` are all stored as text and read as ON.
	 *
	 *     wp option patch update login_armor_hardening force_https false
	 *
	 * @param array<int,string>    $args       Positional arguments.
	 * @param array<string,string> $assoc_args Named arguments (unused).
	 */
	public function hardening( array $args, array $assoc_args ): void {
		unset( $assoc_args );

		$action = $args[0] ?? '';

		match ( $action ) {
			'blacklist' => $this->do_hardening_blacklist( $args[1] ?? '', $args[2] ?? '' ),
			'honeypot'  => $this->do_hardening_honeypot( $args[1] ?? '' ),
			default     => \WP_CLI::error( "Unknown hardening action '{$action}'. Use 'blacklist' or 'honeypot'." ),
		};
	}

	/**
	 * Show or change the headless mode (2.9.0).
	 *
	 * Headless mode keeps "Restrict REST API" and "Disable application
	 * passwords" off. Turning it on turns them off and says so; turning it
	 * off turns nothing back on.
	 *
	 * ## OPTIONS
	 *
	 * <action>
	 * : on, off or status.
	 * ---
	 * options:
	 *   - on
	 *   - off
	 *   - status
	 * ---
	 *
	 * ## EXAMPLES
	 *
	 *     wp login-armor headless status
	 *     wp login-armor headless on
	 *
	 * @param array<int,string>    $args       Positional arguments.
	 * @param array<string,string> $assoc_args Unused.
	 */
	public function headless( array $args, array $assoc_args ): void {
		unset( $assoc_args );
		$action  = $args[0] ?? 'status';
		$user_id = (int) get_current_user_id();

		if ( 'on' === $action ) {
			$was_on     = Headless::is_enabled();
			$turned_off = Headless::enable( $user_id );
			if ( array() !== $turned_off ) {
				\WP_CLI::success( 'Headless mode is on. Turned off: ' . implode( ', ', Headless::labels( $turned_off ) ) . '.' );
			} elseif ( $was_on ) {
				\WP_CLI::success( 'Headless mode is already on.' );
			} else {
				\WP_CLI::success( 'Headless mode is on.' );
			}
			return;
		}

		if ( 'off' === $action ) {
			if ( ! Headless::is_enabled() ) {
				\WP_CLI::success( 'Headless mode is already off.' );
				return;
			}
			Headless::disable( $user_id );
			\WP_CLI::success( 'Headless mode is off. Nothing was turned back on.' );
			return;
		}

		if ( 'status' !== $action ) {
			\WP_CLI::error( "Unknown headless action '{$action}'. Use 'on', 'off' or 'status'." );
		}

		$on     = Headless::is_enabled();
		$stored = get_option( Hardening::OPTION_KEY, array() );
		\WP_CLI::log( 'Headless mode: ' . ( $on ? 'on' : 'off' ) );
		foreach ( Headless::GUARDED_TOGGLES as $key ) {
			$is_stored_on = is_array( $stored ) && isset( $stored[ $key ] ) && LoginArmor::to_bool( $stored[ $key ] );
			if ( $on && $is_stored_on ) {
				\WP_CLI::log( "  {$key}: stored on, kept off by headless mode" );
			} else {
				\WP_CLI::log( "  {$key}: " . ( $is_stored_on ? 'on' : 'off' ) );
			}
		}
		\WP_CLI::log( 'Application-password monitoring: ' . ( Usage::is_watching() ? 'on' : 'off' ) );
		\WP_CLI::log( 'Usage rows waiting for review: ' . Usage::count_by_state( 'pending' ) );
		\WP_CLI::log( 'Networks flagged and not approved: ' . Usage::count_networks_by_state( 'alerted' ) );
	}

	/**
	 * Dispatch blacklist sub-actions.
	 *
	 * @param string $subaction list|add|remove.
	 * @param string $value     Username for add/remove.
	 */
	private function do_hardening_blacklist( string $subaction, string $value ): void {
		$list = UsernameBlacklist::get_blacklist();

		switch ( $subaction ) {
			case 'list':
				if ( empty( $list ) ) {
					\WP_CLI::log( '(blacklist is empty)' );
					return;
				}
				foreach ( $list as $entry ) {
					\WP_CLI::log( $entry );
				}
				return;

			case 'add':
				if ( '' === $value ) {
					\WP_CLI::error( 'Please provide a username to add.' );
				}
				$value = strtolower( trim( $value ) );
				if ( in_array( $value, $list, true ) ) {
					\WP_CLI::warning( sprintf( '"%s" is already on the blacklist.', $value ) );
					return;
				}
				$list[] = $value;
				update_option( UsernameBlacklist::OPTION_KEY, UsernameBlacklist::normalize( implode( "\n", $list ) ), false );
				\WP_CLI::success( sprintf( '"%s" added to the blacklist.', $value ) );
				return;

			case 'remove':
				if ( '' === $value ) {
					\WP_CLI::error( 'Please provide a username to remove.' );
				}
				$value = strtolower( trim( $value ) );
				if ( ! in_array( $value, $list, true ) ) {
					\WP_CLI::warning( sprintf( '"%s" is not on the blacklist.', $value ) );
					return;
				}
				$list = array_values( array_filter( $list, static fn( string $n ): bool => $n !== $value ) );
				update_option( UsernameBlacklist::OPTION_KEY, $list, false );
				\WP_CLI::success( sprintf( '"%s" removed from the blacklist.', $value ) );
				return;

			default:
				\WP_CLI::error( "Unknown blacklist subaction '{$subaction}'. Use 'list', 'add', or 'remove'." );
		}
	}

	/**
	 * Dispatch honeypot sub-actions (currently just 'status').
	 *
	 * @param string $subaction status.
	 */
	private function do_hardening_honeypot( string $subaction ): void {
		if ( 'status' !== $subaction ) {
			\WP_CLI::error( "Unknown honeypot subaction '{$subaction}'. Use 'status'." );
		}

		$settings = Hardening::get_settings();
		$enabled  = ! empty( $settings['login_honeypot'] );

		\WP_CLI::line( 'Field name: ' . Honeypot::field_name() );
		\WP_CLI::line( 'Enabled:    ' . ( $enabled ? 'yes' : 'no' ) );
	}

	/**
	 * Export or import every Login Armor setting as JSON (2.6.0).
	 *
	 * Export writes a self-describing JSON document. Webhook URLs (Slack,
	 * Discord, SIEM) carry an access token and are only included with
	 * --include-webhooks; the SIEM signing secret and users' two-factor
	 * enrolments never leave the site. Import validates the whole file
	 * first: one invalid value and nothing is applied. Switching the firewall
	 * or the bot challenge on by import always lands in monitor mode.
	 *
	 * ## OPTIONS
	 *
	 * <action>
	 * : export | import
	 *
	 * [<file>]
	 * : import: path to the JSON file ("-" reads stdin).
	 *
	 * [--file=<path>]
	 * : export: write to this path instead of stdout.
	 *
	 * [--include-webhooks]
	 * : export: include the notification and activity webhook URLs.
	 *
	 * [--dry-run]
	 * : import: show what would change, change nothing.
	 *
	 * [--yes]
	 * : import: skip the confirmation prompt.
	 *
	 * [--format=<format>]
	 * : import: diff output format.
	 * ---
	 * default: table
	 * options:
	 *   - table
	 *   - json
	 * ---
	 *
	 * ## EXAMPLES
	 *
	 *     # Export the model site
	 *     wp login-armor settings export --file=model.json
	 *
	 *     # Preview on another site, then apply
	 *     wp login-armor settings import model.json --dry-run
	 *     wp login-armor settings import model.json --yes
	 *
	 *     # Roll out to a fleet
	 *     for s in $(cat sites.txt); do wp --ssh=$s login-armor settings import model.json --yes; done
	 *
	 * Exit codes (import): 0 applied or dry-run; 1 the file was refused
	 * (validation errors, unsupported schema); 2 the file could not be read.
	 *
	 * @param array<int,string>    $args       Positional arguments.
	 * @param array<string,string> $assoc_args Named arguments.
	 */
	public function settings( array $args, array $assoc_args ): void {
		$action = $args[0] ?? '';

		match ( $action ) {
			'export' => $this->do_settings_export( $assoc_args ),
			'import' => $this->do_settings_import( $args[1] ?? '', $assoc_args ),
			default  => \WP_CLI::error( "Unknown settings action '{$action}'. Use 'export' or 'import'." ),
		};
	}

	/**
	 * Inspect or run the scheduled security digest.
	 *
	 * With no flag, prints the current state: period, last send, next due
	 * date. --preview renders the digest that would go out right now and
	 * prints it, sending nothing and touching no option: it is the way to see
	 * what a channel will receive before committing to a weekly e-mail.
	 * --send delivers one immediately through the configured channel,
	 * whatever the period says, and stamps the clock on success.
	 *
	 * The digest carries no IP address, in any channel, by design.
	 *
	 * ## OPTIONS
	 *
	 * [--preview]
	 * : render the digest and print it. Sends nothing, changes nothing.
	 *
	 * [--send]
	 * : deliver one digest now, ignoring the period.
	 *
	 * ## EXAMPLES
	 *
	 *     # What would this week's digest say?
	 *     wp login-armor digest --preview
	 *
	 *     # Send one now, to check the channel really receives it
	 *     wp login-armor digest --send
	 *
	 * Exit codes: 0 done; 1 no channel is configured, or the send failed;
	 * 2 another run holds the send lock, so nothing was attempted. Two is a
	 * distinct code on purpose: a script that retries on contention must not
	 * retry on a destination that is refusing the message.
	 *
	 * @param array<int,string>    $args       Positional arguments.
	 * @param array<string,string> $assoc_args Named arguments.
	 */
	public function digest( array $args, array $assoc_args ): void {
		unset( $args );

		require_once LOGIN_ARMOR_DIR . 'includes/Notifications/ChannelInterface.php';
		require_once LOGIN_ARMOR_DIR . 'includes/Notifications/Dispatcher.php';
		require_once LOGIN_ARMOR_DIR . 'includes/Notifications/Digest.php';

		$class   = '\LoginArmor\Notifications\Digest';
		$mode    = $class::get_mode();
		$last    = (int) get_option( $class::OPTION_LAST, 0 );
		// 2.10.0: the digest's own channel. Its own recipient makes it e-mail
		// even with alerts disabled; the alert channel decides otherwise.
		$channel = $class::channel();
		if ( '' !== $class::own_recipient() ) {
			$channel = 'email (' . $class::own_recipient() . ')';
		}

		if ( ! empty( $assoc_args['preview'] ) ) {
			$data     = $class::collect();
			$rendered = $class::render( $data );
			\WP_CLI::line( (string) $rendered['subject'] );
			\WP_CLI::line( '' );
			\WP_CLI::line( (string) $rendered['body'] );
			return;
		}

		if ( ! empty( $assoc_args['send'] ) ) {
			if ( 'disabled' === $channel ) {
				\WP_CLI::error( 'No notification channel is configured: there is nowhere to send a digest.' );
			}
			// Through send_now(), which takes the same lock the daily tick
			// takes: this command can legitimately be run beside a tick, and
			// two runs reading the same clock would send the same digest
			// twice. null means the lock was held, which is not a failure and
			// must not read like one.
			$sent = $class::send_now();
			if ( null === $sent ) {
				\WP_CLI::error( 'Another digest run holds the send lock; try again in a moment.', 2 );
			}
			if ( false === $sent ) {
				\WP_CLI::error( sprintf( 'The digest could not be delivered through the %s channel.', $channel ) );
			}
			\WP_CLI::success( sprintf( 'Digest sent through the %s channel.', $channel ) );
			return;
		}

		\WP_CLI::line( 'Period: ' . $mode );
		\WP_CLI::line( 'Channel: ' . $channel );
		\WP_CLI::line( 'Last sent: ' . ( $last > 0 ? gmdate( 'Y-m-d H:i:s', $last ) . ' UTC' : 'never' ) );

		if ( 'off' === $mode ) {
			\WP_CLI::line( 'Next: never, the digest is off.' );
			return;
		}
		if ( $last <= 0 ) {
			\WP_CLI::line( 'Next: the first daily tick starts the clock; the first digest follows one full period later.' );
			return;
		}
		\WP_CLI::line( 'Next: ' . gmdate( 'Y-m-d H:i:s', $last + $class::period_seconds() ) . ' UTC or later, on the next daily tick.' );
	}

	/**
	 * @param array<string,string> $assoc_args
	 */
	private function do_settings_export( array $assoc_args ): void {
		$json = \LoginArmor\Settings\Exporter::to_json(
			\LoginArmor\Settings\Exporter::build( ! empty( $assoc_args['include-webhooks'] ) )
		);

		if ( isset( $assoc_args['file'] ) && '' !== (string) $assoc_args['file'] ) {
			$path    = (string) $assoc_args['file'];
			$written = file_put_contents( $path, $json ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents -- WP-CLI operator-chosen path; WP_Filesystem is not initialised in CLI.
			if ( false === $written ) {
				\WP_CLI::error( sprintf( 'Could not write %s.', $path ) );
			}
			\WP_CLI::success( sprintf( 'Settings written to %s (%d bytes).', $path, $written ) );
			return;
		}

		\WP_CLI::line( rtrim( $json, "\n" ) );
	}

	/**
	 * @param array<string,string> $assoc_args
	 */
	private function do_settings_import( string $file, array $assoc_args ): void {
		if ( '' === $file ) {
			\WP_CLI::error( 'Please provide the path to a settings JSON file (or "-" for stdin).' );
		}
		$source = '-' === $file ? 'php://stdin' : $file;
		if ( '-' !== $file && ! is_readable( $file ) ) {
			\WP_CLI::warning( sprintf( 'Cannot read %s.', $file ) );
			\WP_CLI::halt( 2 );
		}
		$json = file_get_contents( $source ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- WP-CLI operator-chosen local file.
		if ( false === $json ) {
			\WP_CLI::warning( sprintf( 'Cannot read %s.', $file ) );
			\WP_CLI::halt( 2 );
		}

		$parsed = \LoginArmor\Settings\Importer::parse( (string) $json );
		if ( is_wp_error( $parsed ) ) {
			\WP_CLI::error( $parsed->get_error_message() );
		}

		$context = array(
			'source'    => 'cli',
			'user_id'   => get_current_user_id(),
			'client_ip' => '',
		);
		$plan    = \LoginArmor\Settings\Importer::plan( $parsed, $context );
		$format  = isset( $assoc_args['format'] ) && 'json' === $assoc_args['format'] ? 'json' : 'table';
		$dry_run = ! empty( $assoc_args['dry-run'] );

		if ( 'json' === $format ) {
			$payload = array(
				'source'          => $plan['envelope']['source'] ?? array(),
				'counts'          => $plan['counts'],
				'changes'         => $this->settings_diff_rows( $plan, true ),
				'warnings'        => $plan['warnings'],
				'errors'          => $plan['errors'],
				'unknown'         => $plan['unknown'],
				'login_url_after' => $plan['login_url_after'],
				'dry_run'         => $dry_run,
			);
		} else {
			$rows = $this->settings_diff_rows( $plan, false );
			\WP_CLI::log( sprintf( 'Source: %s (Login Armor %s, exported %s)', (string) ( $plan['envelope']['source']['host'] ?? '?' ), (string) ( $plan['envelope']['plugin_version'] ?? '?' ), (string) ( $plan['envelope']['exported_at'] ?? '?' ) ) );
			if ( empty( $rows ) ) {
				\WP_CLI::log( 'No difference with this site.' );
			} else {
				\WP_CLI\Utils\format_items( 'table', $rows, array( 'module', 'setting', 'current', 'incoming' ) );
			}
			foreach ( $plan['unknown'] as $unknown ) {
				\WP_CLI::log( sprintf( 'Ignored (unknown on this version): %s', $unknown ) );
			}
			foreach ( $plan['warnings'] as $warning ) {
				\WP_CLI::warning( $warning['path'] . ': ' . $warning['message'] );
			}
			foreach ( $plan['errors'] as $error ) {
				\WP_CLI::warning( 'ERROR ' . $error['path'] . ': ' . $error['message'] );
			}
			if ( null !== $plan['login_url_after'] ) {
				\WP_CLI::log( 'Login URL after import: ' . $plan['login_url_after'] );
			}
		}

		if ( ! empty( $plan['errors'] ) ) {
			if ( 'json' === $format ) {
				\WP_CLI::log( wp_json_encode( $payload, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES ) );
			}
			\WP_CLI::error( sprintf( '%d error(s): nothing applied.', count( $plan['errors'] ) ) );
		}

		if ( $dry_run ) {
			if ( 'json' === $format ) {
				\WP_CLI::log( wp_json_encode( $payload, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES ) );
			} else {
				\WP_CLI::success( sprintf( 'Dry run: %d change(s) would be applied, %d unchanged.', $plan['counts']['change'], $plan['counts']['same'] ) );
			}
			return;
		}

		if ( 0 === $plan['counts']['change'] ) {
			if ( 'json' === $format ) {
				$payload['applied'] = array();
				\WP_CLI::log( wp_json_encode( $payload, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES ) );
			} else {
				\WP_CLI::success( 'Nothing to apply: this site already matches the file.' );
			}
			return;
		}

		\WP_CLI::confirm(
			sprintf(
				'Apply %d change(s) to %s?%s',
				$plan['counts']['change'],
				home_url(),
				null !== $plan['login_url_after'] ? ' The login URL will become ' . $plan['login_url_after'] . '.' : ''
			),
			$assoc_args
		);

		$report = \LoginArmor\Settings\Importer::apply( $plan, $context );
		if ( is_wp_error( $report ) ) {
			\WP_CLI::error( $report->get_error_message() );
		}

		if ( 'json' === $format ) {
			$payload['applied']   = $report['applied'];
			$payload['warnings']  = $report['warnings'];
			$payload['errors']    = $report['errors'];
			$payload['login_url'] = $report['login_url'];
			\WP_CLI::log( wp_json_encode( $payload, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES ) );
		} else {
			foreach ( $report['warnings'] as $warning ) {
				\WP_CLI::warning( $warning['path'] . ': ' . $warning['message'] );
			}
			foreach ( $report['errors'] as $error ) {
				\WP_CLI::warning( 'FAILED ' . $error['path'] . ': ' . $error['message'] );
			}
		}
		if ( ! empty( $report['errors'] ) ) {
			\WP_CLI::error( sprintf( 'Imported with %d failure(s): %d applied, %d unchanged. Login URL: %s', count( $report['errors'] ), count( $report['applied'] ), count( $report['unchanged'] ), $report['login_url'] ) );
		}
		\WP_CLI::success( sprintf( 'Imported: %d applied, %d unchanged. Login URL: %s', count( $report['applied'] ), count( $report['unchanged'] ), $report['login_url'] ) );
	}

	/**
	 * Flatten a plan into printable rows (changes only).
	 *
	 * @param array<string,mixed> $plan
	 * @return array<int,array<string,mixed>>
	 */
	private function settings_diff_rows( array $plan, bool $raw ): array {
		$rows = array();
		foreach ( $plan['entries'] as $row ) {
			if ( 'change' !== $row['status'] ) {
				continue;
			}
			$rows[] = array(
				'module'   => $row['group'],
				'setting'  => $row['path'],
				'current'  => $raw ? $row['current'] : self::settings_value_label( $row['current'] ),
				'incoming' => $raw ? $row['incoming'] : self::settings_value_label( $row['incoming'] ),
			);
		}
		return $rows;
	}

	/**
	 * One-line, human-readable rendering of a setting value.
	 */
	private static function settings_value_label( mixed $value ): string {
		if ( is_bool( $value ) ) {
			return $value ? 'on' : 'off';
		}
		if ( is_array( $value ) ) {
			if ( array_is_list( $value ) ) {
				return empty( $value ) ? '(empty)' : implode( ', ', array_map( 'strval', $value ) );
			}
			$parts = array();
			foreach ( $value as $k => $v ) {
				$parts[] = $k . '=' . self::settings_value_label( $v );
			}
			return implode( ' ', $parts );
		}
		if ( '' === $value || null === $value ) {
			return '(empty)';
		}
		return (string) $value;
	}
}
