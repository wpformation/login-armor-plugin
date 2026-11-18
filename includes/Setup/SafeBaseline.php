<?php
/**
 * Safe Baseline: the "never breaks WordPress" starter profile.
 *
 * A single source of truth, applied by both the activation onboarding wizard
 * (Simple mode) and the permanent "Apply safe baseline" button on the Settings
 * tab. It is strictly ADDITIVE and idempotent: it only ENABLES protections that
 * carry no risk of locking a user out or breaking a theme, and never disables
 * anything. It deliberately does NOT touch the riskier, choice-driven modules:
 * Hide Login, Two-Factor, aggressive Hardening toggles, Password Policy,
 * Session Management or Breach Check. Those stay opt-in.
 *
 * 2.7.0 adds the Request Firewall and the Bot Challenge, in MONITOR mode only.
 * That is not a change of policy: in monitor mode both modules observe and
 * record, and neither can refuse a single request, so the "cannot lock you out,
 * cannot break your theme" contract holds exactly as before. What the site
 * gains is seven days of its own real traffic, which is what the "switch to
 * Enforce" advice then reads instead of asking the administrator to guess.
 *
 * 2.7.1 adds the two read-only halves the wizard was missing. state() and
 * preview() answer "what would this change?" without changing anything, so a
 * screen can be opened twice and still tell the truth; report() answers "what
 * did it change?", by comparing a snapshot taken before the writes with the
 * state after them. Until then apply() could only claim a result, and the one
 * screen that showed it threw the claim away.
 *
 * @package LoginArmor
 * @since   2.4.0
 */

namespace LoginArmor\Setup;

use LoginArmor\Hardening;
use LoginArmor\LoginHeaders;

// Exit if accessed directly.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Applies the safe baseline profile.
 */
final class SafeBaseline {

	/**
	 * The seven hardening toggles that are safe for virtually every site: the
	 * same set behind the "Apply recommended defaults" button in the Hardening
	 * section.
	 *
	 * @var string[]
	 */
	public const RECOMMENDED_HARDENING = array(
		'disable_xmlrpc',
		'disable_file_editor',
		'hide_wp_version',
		'mask_login_errors',
		'block_php_uploads',
		'prevent_author_enum',
		'disable_directory_listing',
	);

	/**
	 * The two monitor-first modules the baseline switches on, as
	 * summary key => [ class file, fully-qualified class name ].
	 *
	 * @since 2.7.0
	 * @var array<string,array{0:string,1:string}>
	 */
	private const MONITOR_MODULES = array(
		'firewall' => array( 'includes/Firewall/Firewall.php', '\LoginArmor\Firewall\Firewall' ),
		'pow'      => array( 'includes/class-pow-challenge.php', '\LoginArmor\PowChallenge' ),
	);

	/**
	 * One entry per protection the baseline covers, in reading order, as
	 * summary key => Settings-tab section id.
	 *
	 * The section id is what makes a report actionable rather than
	 * decorative: the Settings tab opens and scrolls to `#<id>`, so every
	 * line of the report is one click from the screen that owns it. A list
	 * the administrator cannot check for themselves is the same "take our
	 * word for it" the wizard used to end on.
	 *
	 * @since 2.7.1
	 * @var array<string,string>
	 */
	private const ITEM_SECTIONS = array(
		'limit'         => 'limit-login',
		'detection'     => 'detection-logs',
		'login_headers' => 'login-headers',
		'activity_log'  => 'activity-log',
		'hardening'     => 'hardening',
		'firewall'      => 'firewall',
		'pow'           => 'pow',
	);

	/**
	 * The modules the baseline deliberately never touches, as
	 * key => Settings-tab section id.
	 *
	 * Each of them can lock a user out of their own site or change what
	 * visitors see, so each is a decision only the administrator can take.
	 * Naming them WITH their current state is the difference between a
	 * second button that does nothing and a screen that says what is left.
	 *
	 * @since 2.7.1
	 * @var array<string,string>
	 */
	private const DELIBERATE_MODULES = array(
		'hide_login'      => 'hide-login',
		'two_factor'      => 'two-factor',
		'password_policy' => 'password-policy',
		'session'         => 'session',
		'breach_check'    => 'breach-check',
	);

	/**
	 * Apply the baseline. Additive + idempotent: safe to call any number of
	 * times. Returns a report of the resulting state for the UI.
	 *
	 * @return array<string,mixed>
	 */
	public static function apply(): array {
		// Snapshot BEFORE the first write. This is the only instant at which
		// "was it already on?" can still be answered, and that question is the
		// whole difference between a report and a promise: without it the
		// screen can only claim seven protections are on, never say which ones
		// it just switched on.
		$before = self::state();

		// Core defensive modules (default-on; ensure they stay on).
		update_option( 'login_armor_limit_enabled', true );
		update_option( 'login_armor_detection_enabled', true );

		// Login-page security headers: standard profile, login-scoped only, so
		// there is zero risk to the front-end or admin.
		update_option( LoginHeaders::OPTION_ENABLED, true );
		if ( ! in_array( (string) get_option( LoginHeaders::OPTION_MODE, '' ), LoginHeaders::ALLOWED_MODES, true ) ) {
			update_option( LoginHeaders::OPTION_MODE, 'standard' );
		}

		// Activity Log: opt-in, zero front-end overhead, high value for a
		// beginner who wants an audit trail.
		self::enable_activity_log();

		// The seven curated safe hardening toggles.
		self::apply_recommended_hardening();

		// 2.7.0: the request firewall and the bot challenge, in monitor mode.
		self::enable_monitor_modules();

		return self::report( $before );
	}

	/**
	 * What the baseline WOULD do, without doing any of it.
	 *
	 * Called on every render of the wizard, which is why it must not write a
	 * single option: merely looking at the screen would otherwise configure
	 * the site, and the "Review the setup assistant" link on the Settings tab
	 * makes that a routine act. The offline suite asserts that nothing at all
	 * moves across a call.
	 *
	 * The items carry an empty `was`: nobody measured a before, and inventing
	 * one here would be exactly the unverified claim this screen exists to
	 * stop making.
	 *
	 * @since 2.7.1
	 *
	 * @return array<int,array{key:string,label:string,state:string,was:string,detail:string,section:string}>
	 */
	public static function preview(): array {
		return self::items( self::state(), array() );
	}

	/**
	 * The report apply() returns: the state of every protection now, next to
	 * the state it was in before the writes.
	 *
	 * Split out of apply() so it can be exercised offline. apply() writes
	 * `wp-content/uploads/.htaccess` through the hardening module and is
	 * therefore never called by the offline suite, which would otherwise
	 * leave the distinction this whole screen rests on untested.
	 *
	 * Read only, like state().
	 *
	 * @since 2.7.1
	 *
	 * @param array<string,string> $before Result of state() taken before the writes.
	 * @return array<string,mixed>
	 */
	public static function report( array $before ): array {
		$state = self::state();

		// The flat keys are the 2.4.0 summary, kept verbatim: they are what
		// the Settings-tab handler has always answered with.
		return array(
			'limit'         => 'on' === ( $state['limit'] ?? 'off' ),
			'detection'     => 'on' === ( $state['detection'] ?? 'off' ),
			'login_headers' => 'on' === ( $state['login_headers'] ?? 'off' ),
			'activity_log'  => 'on' === ( $state['activity_log'] ?? 'off' ),
			'hardening'     => self::recommended_hardening_count(),
			'firewall'      => self::module_mode( 'firewall' ),
			'pow'           => self::module_mode( 'pow' ),
			'items'         => self::items( $state, $before ),
		);
	}

	/**
	 * State of every protection the baseline covers, touching none of them.
	 *
	 * 'on' means there is nothing left for apply() to do; 'partial' means some
	 * of it (only hardening can be partial, being seven toggles rather than
	 * one); 'off' means apply() would switch it on. A module whose class
	 * cannot be loaded reads 'off' rather than being assumed: the wizard
	 * describes what the site actually carries.
	 *
	 * @since 2.7.1
	 *
	 * @return array<string,string> summary key => 'on'|'partial'|'off'
	 */
	public static function state(): array {
		$hardening = self::recommended_hardening_count();
		$headers   = class_exists( '\LoginArmor\LoginHeaders' )
			&& LoginHeaders::is_enabled()
			&& in_array( (string) get_option( LoginHeaders::OPTION_MODE, '' ), LoginHeaders::ALLOWED_MODES, true );

		return array(
			// Both default to ON in WordPress, so the default has to be passed
			// here too: read with the wrong default, a fresh site would be told
			// the baseline is about to enable two modules it has always had.
			'limit'         => get_option( 'login_armor_limit_enabled', true ) ? 'on' : 'off',
			'detection'     => get_option( 'login_armor_detection_enabled', true ) ? 'on' : 'off',
			'login_headers' => $headers ? 'on' : 'off',
			'activity_log'  => get_option( 'login_armor_activity_enabled', false ) ? 'on' : 'off',
			'hardening'     => self::hardening_state( $hardening ),
			'firewall'      => 'off' === self::module_mode( 'firewall' ) ? 'off' : 'on',
			'pow'           => 'off' === self::module_mode( 'pow' ) ? 'off' : 'on',
		);
	}

	/**
	 * The modules the baseline never touches, with their current state, so
	 * the wizard can name what is left to decide instead of offering a second
	 * button that changes nothing.
	 *
	 * @since 2.7.1
	 *
	 * @return array<int,array{key:string,label:string,state:string,was:string,detail:string,section:string}>
	 */
	public static function deliberate_modules(): array {
		$labels = array(
			'hide_login'      => __( 'Hide Login', 'login-armor' ),
			'two_factor'      => __( 'Two-Factor Authentication', 'login-armor' ),
			'password_policy' => __( 'Password Policy', 'login-armor' ),
			'session'         => __( 'Session Management', 'login-armor' ),
			'breach_check'    => __( 'Breach Check', 'login-armor' ),
		);
		$on     = array(
			'hide_login'      => class_exists( '\LoginArmor\HideLogin' ) && \LoginArmor\HideLogin::is_enabled(),
			'two_factor'      => (bool) get_option( 'login_armor_2fa_enabled', false ),
			'password_policy' => class_exists( '\LoginArmor\PasswordPolicy' ) && \LoginArmor\PasswordPolicy::is_enabled(),
			'session'         => class_exists( '\LoginArmor\SessionManager' ) && \LoginArmor\SessionManager::is_enabled(),
			'breach_check'    => class_exists( '\LoginArmor\BreachCheck' ) && \LoginArmor\BreachCheck::is_enabled(),
		);

		$items = array();
		foreach ( self::DELIBERATE_MODULES as $key => $section ) {
			$items[] = array(
				'key'     => $key,
				'label'   => (string) ( $labels[ $key ] ?? $key ),
				'state'   => empty( $on[ $key ] ) ? 'off' : 'on',
				'was'     => '',
				'detail'  => '',
				'section' => $section,
			);
		}

		return $items;
	}

	/**
	 * Switch the request firewall and the bot challenge on, in monitor mode.
	 *
	 * Each module is enabled ONLY when it is currently off. This is not an
	 * optimisation: Firewall::set_enabled( true ) and
	 * PowChallenge::set_enabled( true ) always reset the mode to `log_only`,
	 * so calling either on a module an administrator had already switched to
	 * `enforce` would silently stop it blocking anything. The baseline is
	 * additive, and demoting a protection is not additive.
	 *
	 * A module that cannot be loaded is reported as 'off' rather than assumed:
	 * the summary describes what the site actually carries now.
	 *
	 * @since 2.7.0
	 *
	 * @return array<string,string> [ 'firewall' => 'log_only'|'enforce'|'off', 'pow' => ... ]
	 */
	public static function enable_monitor_modules(): array {
		$summary = array();

		foreach ( array_keys( self::MONITOR_MODULES ) as $key ) {
			$summary[ $key ] = 'off';

			$class = self::module_class( (string) $key );
			if ( null === $class ) {
				continue;
			}

			if ( ! $class::is_enabled() ) {
				$class::set_enabled( true );
			}

			$summary[ $key ] = $class::is_enabled() ? $class::get_mode() : 'off';
		}

		return $summary;
	}

	/**
	 * Build the per-protection list both the wizard and the report render.
	 *
	 * @param array<string,string> $state  State now, key => on|partial|off.
	 * @param array<string,string> $before State before apply(), or empty when nothing was measured.
	 * @return array<int,array{key:string,label:string,state:string,was:string,detail:string,section:string}>
	 */
	private static function items( array $state, array $before ): array {
		$labels = array(
			'limit'         => __( 'Brute Force Protection', 'login-armor' ),
			'detection'     => __( 'Detection & Logs', 'login-armor' ),
			'login_headers' => __( 'Login Page Protection Headers', 'login-armor' ),
			'activity_log'  => __( 'Activity Log', 'login-armor' ),
			'hardening'     => __( 'Hardening', 'login-armor' ),
			'firewall'      => __( 'Request Firewall', 'login-armor' ),
			'pow'           => __( 'Bot Challenge', 'login-armor' ),
		);

		$items = array();
		foreach ( self::ITEM_SECTIONS as $key => $section ) {
			$now = (string) ( $state[ $key ] ?? 'off' );

			$items[] = array(
				'key'     => $key,
				'label'   => (string) ( $labels[ $key ] ?? $key ),
				'state'   => $now,
				'was'     => isset( $before[ $key ] ) ? (string) $before[ $key ] : '',
				'detail'  => self::detail( (string) $key, $now ),
				'section' => $section,
			);
		}

		return $items;
	}

	/**
	 * The one extra word a line needs to be checkable: how many of the seven
	 * toggles are on, and whether a monitor module is recording or blocking.
	 *
	 * @param string $key   Summary key.
	 * @param string $state State of that key.
	 */
	private static function detail( string $key, string $state ): string {
		if ( 'hardening' === $key ) {
			return sprintf(
				/* translators: 1: number of recommended hardening toggles enabled, 2: total number of recommended toggles. */
				__( '%1$d of %2$d recommended toggles', 'login-armor' ),
				self::recommended_hardening_count(),
				count( self::RECOMMENDED_HARDENING )
			);
		}

		if ( 'on' === $state && isset( self::MONITOR_MODULES[ $key ] ) ) {
			// Same two words the Settings tab prints for these modules: a
			// report that renamed the states would read as a third module.
			return 'enforce' === self::module_mode( $key )
				? __( 'Enforcing', 'login-armor' )
				: __( 'Monitoring', 'login-armor' );
		}

		return '';
	}

	/**
	 * Hardening is the one item that can be half done: seven toggles, any
	 * number of them already on.
	 *
	 * @param int $count Recommended toggles currently enabled.
	 */
	private static function hardening_state( int $count ): string {
		if ( $count >= count( self::RECOMMENDED_HARDENING ) ) {
			return 'on';
		}
		return $count > 0 ? 'partial' : 'off';
	}

	/**
	 * Load a monitor module's class on demand, without enabling anything.
	 *
	 * @param string $key Key of self::MONITOR_MODULES.
	 * @return class-string|null
	 */
	private static function module_class( string $key ) {
		if ( ! isset( self::MONITOR_MODULES[ $key ] ) ) {
			return null;
		}

		list( $file, $class ) = self::MONITOR_MODULES[ $key ];

		if ( ! class_exists( $class ) ) {
			$path = LOGIN_ARMOR_DIR . $file;
			if ( ! file_exists( $path ) ) {
				return null;
			}
			require_once $path;
		}

		return class_exists( $class ) ? $class : null;
	}

	/**
	 * Mode of a monitor module: 'log_only', 'enforce', or 'off' when it is
	 * disabled or its class cannot be loaded.
	 *
	 * @param string $key Key of self::MONITOR_MODULES.
	 */
	private static function module_mode( string $key ): string {
		$class = self::module_class( $key );
		if ( null === $class || ! $class::is_enabled() ) {
			return 'off';
		}
		return (string) $class::get_mode();
	}

	/**
	 * How many of the seven recommended hardening toggles are on right now.
	 */
	private static function recommended_hardening_count(): int {
		if ( ! class_exists( '\LoginArmor\Hardening' ) ) {
			return 0;
		}

		$settings = Hardening::get_settings();
		$count    = 0;
		foreach ( self::RECOMMENDED_HARDENING as $key ) {
			if ( ! empty( $settings[ $key ] ) ) {
				++$count;
			}
		}

		return $count;
	}

	/**
	 * Enable the Activity Log the same way the AJAX enable handler does:
	 * create the table, set the option, schedule the purge cron.
	 */
	private static function enable_activity_log(): void {
		$class = '\LoginArmor\ActivityLog\ActivityLog';
		if ( ! class_exists( $class ) ) {
			$file = LOGIN_ARMOR_DIR . 'includes/ActivityLog/ActivityLog.php';
			if ( file_exists( $file ) ) {
				require_once $file;
			}
		}
		if ( ! class_exists( $class ) ) {
			return;
		}

		$class::enable();
	}

	/**
	 * Turn on the recommended hardening toggles, preserving any the user
	 * already enabled, then sync the .htaccess rules those toggles need.
	 *
	 * The count the report prints is read back by recommended_hardening_count()
	 * rather than returned from here: a filesystem that refused the .htaccess
	 * write leaves two of the seven toggles saved but not in force, and the
	 * number on the screen has to be the one the site can show, not the one
	 * this method intended.
	 */
	private static function apply_recommended_hardening(): void {
		if ( ! class_exists( '\LoginArmor\Hardening' ) ) {
			return;
		}

		// Start from the current settings so we never turn anything OFF.
		$settings = Hardening::get_settings();
		foreach ( self::RECOMMENDED_HARDENING as $key ) {
			$settings[ $key ] = true;
		}
		Hardening::save_settings( $settings );

		// block_php_uploads + disable_directory_listing write .htaccess; the
		// save path does not sync on its own (the AJAX handler does), so do it
		// here. Fail-soft: sync_htaccess handles unwritable filesystems itself.
		if ( method_exists( '\LoginArmor\Hardening', 'sync_htaccess' ) ) {
			Hardening::sync_htaccess();
		}
	}
}
