<?php
/**
 * Security score: weighted 0-100 from enabled modules.
 *
 * @package LoginArmor
 */

namespace LoginArmor;

defined( 'ABSPATH' ) || exit;

final class SecurityScore {

	/**
	 * Canonical enabled-state for every scored core module.
	 *
	 * Single source of truth so the score can never disagree with the
	 * admin UI pills again. Each entry MUST use the SAME predicate the
	 * runtime / views use for that module.
	 *
	 * Audit: the score card once read "4 of 8 modules active" (score 44)
	 * while 6 modules were actually running, because compute()/next_action()
	 * read a bare get_option() (default false) on Brute Force and Detection,
	 * both default-true modules, whereas the runtime (class-limit-login,
	 * Detection/Classifier) and the overview/settings pills read
	 * get_option( …, true ). The two default-true options below are the fix.
	 *
	 * Public since 2.7.0: the Site Health debug panel reports what is running,
	 * and a second list of predicates there could only ever disagree with the
	 * score card. One map, two readers.
	 *
	 * @return array<string,bool> Option name → whether the module is active.
	 */
	public static function module_states(): array {
		return array(
			'login_armor_hide_enabled'          => class_exists( '\LoginArmor\HideLogin' )
				? \LoginArmor\HideLogin::is_enabled()
				: (bool) get_option( 'login_armor_hide_enabled', false ),
			// Default-true: brute force protection runs unless explicitly disabled.
			'login_armor_limit_enabled'         => (bool) get_option( 'login_armor_limit_enabled', true ),
			// Default-true: detection engine runs unless explicitly disabled.
			'login_armor_detection_enabled'     => (bool) get_option( 'login_armor_detection_enabled', true ),
			'login_armor_activity_enabled'      => (bool) get_option( 'login_armor_activity_enabled', false ),
			'login_armor_2fa_enabled'           => (bool) get_option( 'login_armor_2fa_enabled', false ),
			'login_armor_login_headers_enabled' => class_exists( '\LoginArmor\LoginHeaders' )
				? \LoginArmor\LoginHeaders::is_enabled()
				: (bool) get_option( 'login_armor_login_headers_enabled', false ),
			'login_armor_breach_check_enabled'  => class_exists( '\LoginArmor\BreachCheck' )
				? \LoginArmor\BreachCheck::is_enabled()
				: (bool) get_option( 'login_armor_breach_check_enabled', false ),
			// v2.3.0 account-security modules. Same predicate the runtime /
			// settings pills use (settings['enabled']).
			'login_armor_password_policy'       => class_exists( '\LoginArmor\PasswordPolicy' )
				? \LoginArmor\PasswordPolicy::is_enabled()
				: false,
			'login_armor_session'               => class_exists( '\LoginArmor\SessionManager' )
				? \LoginArmor\SessionManager::is_enabled()
				: false,
			// v2.4.0 Request Firewall. Special-cased in compute() (monitor mode
			// earns partial points); listed here so the active-module count and
			// the UI pills agree. is_enabled() is true in monitor AND enforce.
			'login_armor_firewall'              => class_exists( '\LoginArmor\Firewall\Firewall' )
				&& \LoginArmor\Firewall\Firewall::is_enabled(),
		);
	}

	/** Weighted score computation. Totals to 100. */
	public static function compute(): int {
		$score = 0;

		// Core + account-security modules (84 points) + Request Firewall (6) = 90,
		// plus 10 prorated hardening = 100 max. v2.4.0 folds the Request Firewall
		// into the scored surface (Fabrice's call), trimming 6 points from the
		// larger weights to make room. GeoIP / Notifications / AI stay UNSCORED:
		// they are observability and block nothing. Breakdown:
		//   16+11+11+9+7+8+7 (7 core) + 9+6 (2 account) = 84, + firewall 6 = 90.
		$weights = array(
			'login_armor_2fa_enabled'            => 16,
			'login_armor_hide_enabled'           => 11,
			'login_armor_limit_enabled'          => 11,
			'login_armor_detection_enabled'      => 9,
			'login_armor_activity_enabled'       => 7,
			'login_armor_login_headers_enabled'  => 8,
			'login_armor_breach_check_enabled'   => 7,
			'login_armor_password_policy'        => 9,
			'login_armor_session'                => 6,
		);
		$states = self::module_states();
		foreach ( $weights as $option => $points ) {
			if ( ! empty( $states[ $option ] ) ) {
				$score += $points;
			}
		}

		// Request Firewall (6 points), special-cased: monitor mode logs without
		// blocking, so it earns HALF; enforce mode blocks, so it earns full.
		if ( class_exists( '\LoginArmor\Firewall\Firewall' ) && \LoginArmor\Firewall\Firewall::is_enabled() ) {
			$score += ( 'enforce' === \LoginArmor\Firewall\Firewall::get_mode() ) ? 6 : 3;
		}

		// Hardening toggles contribute a prorated 10 points.
		$settings = class_exists( '\LoginArmor\Hardening' )
			? \LoginArmor\Hardening::get_settings()
			: array();
		$toggles  = class_exists( '\LoginArmor\Hardening' )
			? \LoginArmor\Hardening::get_toggles()
			: array();
		// 2.9.0: in headless mode the two guarded toggles are not a choice the
		// administrator can make: they leave the denominator.
		$score += self::hardening_points( $settings, array_column( $toggles, 'key' ), self::hardening_excluded_keys() );

		return min( 100, $score );
	}

	/**
	 * Hardening toggles that do not count in headless mode (2.9.0).
	 *
	 * @return string[]
	 */
	public static function hardening_excluded_keys(): array {
		return ( class_exists( '\LoginArmor\Headless' ) && \LoginArmor\Headless::is_enabled() )
			? \LoginArmor\Headless::GUARDED_TOGGLES
			: array();
	}

	/**
	 * Prorated hardening points, out of 10.
	 *
	 * @since 2.9.0
	 *
	 * @param array<string,bool> $settings Toggle key => enabled.
	 * @param string[]           $keys     Every toggle key.
	 * @param string[]           $excluded Keys left out of the count.
	 */
	public static function hardening_points( array $settings, array $keys, array $excluded ): int {
		$counted = 0;
		$enabled = 0;
		foreach ( $keys as $key ) {
			if ( in_array( $key, $excluded, true ) ) {
				continue;
			}
			++$counted;
			if ( ! empty( $settings[ $key ] ) ) {
				++$enabled;
			}
		}
		return $counted > 0 ? (int) round( ( $enabled / $counted ) * 10 ) : 0;
	}

	/**
	 * Suggest the next-best action for the score copy + CTA.
	 *
	 * @return array{title:string, body:string, cta_url:string, cta_label:string}
	 */
	public static function next_action(): array {
		$settings_url = add_query_arg(
			array(
				'page' => 'login-armor',
				'tab'  => 'settings',
			),
			admin_url( 'admin.php' )
		);

		// Map of module → (name, option-name, points-it-adds, anchor).
		// 'points' MUST mirror the $weights used in compute() (firewall = monitor
		// gain), otherwise the "would raise your score to X" copy promises a number
		// the real recompute won't reach. v2.4.0 rebalance: 2FA 16, Hide 11,
		// Breach 7 (were 18/12/8 before the firewall was folded in).
		$modules = array(
			array( 'name' => __( '2FA', 'login-armor' ),             'opt' => 'login_armor_2fa_enabled',          'points' => 16, 'anchor' => '#two-factor' ),
			array( 'name' => __( 'Hide Login', 'login-armor' ),      'opt' => 'login_armor_hide_enabled',         'points' => 11, 'anchor' => '#hide-login' ),
			array( 'name' => __( 'Password Policy', 'login-armor' ), 'opt' => 'login_armor_password_policy',      'points' => 9,  'anchor' => '#password-policy' ),
			array( 'name' => __( 'Breach Check', 'login-armor' ),    'opt' => 'login_armor_breach_check_enabled',  'points' => 7,  'anchor' => '#breach-check' ),
			array( 'name' => __( 'Login Headers', 'login-armor' ),   'opt' => 'login_armor_login_headers_enabled', 'points' => 8,  'anchor' => '#login-headers' ),
			array( 'name' => __( 'Session Management', 'login-armor' ), 'opt' => 'login_armor_session',           'points' => 6,  'anchor' => '#session' ),
			// Firewall is opt-in and starts in monitor mode (+3), so it is offered
			// last: only once the core protections are already on.
			array( 'name' => __( 'Request Firewall', 'login-armor' ), 'opt' => 'login_armor_firewall',          'points' => 3,  'anchor' => '#firewall' ),
		);

		// Shared source of truth: same predicates as compute() and the UI pills.
		$states        = self::module_states();
		$total_modules = 11; // 7 core + 2 account-security + firewall + hardening as 1.
		$active_count  = count( array_filter( $states ) );

		// Hardening counts if any toggle is on.
		$hard_settings = class_exists( '\LoginArmor\Hardening' ) ? \LoginArmor\Hardening::get_settings() : array();
		if ( count( array_filter( $hard_settings ) ) > 0 ) {
			++$active_count;
		}

		$current_score = self::compute();

		// Gather missing high-impact modules in priority order.
		$missing = array();
		foreach ( $modules as $m ) {
			if ( empty( $states[ $m['opt'] ] ) ) {
				$missing[] = $m;
			}
		}

		// Clarifier appended to every body: the "X of Y" count is the scored
		// defensive protections only: not the full list of feature cards in
		// Settings. Observability/alerting features deliberately earn no points.
		$scope_note = __( 'Observability (IP Geolocation, Notifications, the AI assistant) is not scored.', 'login-armor' );

		if ( empty( $missing ) ) {
			return array(
				'title'     => __( 'Your defenses are solid.', 'login-armor' ),
				'body'      => sprintf(
					/* translators: 1: active scored-protection count, 2: total scored protections. */
					__( '%1$d of %2$d scored protections are active. Fine-tune details below.', 'login-armor' ),
					(int) $active_count,
					(int) $total_modules
				) . ' ' . $scope_note,
				'cta_url'   => $settings_url,
				'cta_label' => __( 'Review settings', 'login-armor' ),
			);
		}

		$first        = $missing[0];
		$second       = isset( $missing[1] ) ? $missing[1] : null;
		$gain         = (int) $first['points'] + ( $second ? (int) $second['points'] : 0 );
		$target_score = min( 100, $current_score + $gain );

		$body = ( $second
			? sprintf(
				/* translators: 1: active scored-protection count, 2: total scored protections, 3: first module name, 4: second module name, 5: target score. */
				__( '%1$d of %2$d scored protections are active. Enabling %3$s and %4$s would raise your score to %5$d.', 'login-armor' ),
				(int) $active_count,
				(int) $total_modules,
				(string) $first['name'],
				(string) $second['name'],
				(int) $target_score
			)
			: sprintf(
				/* translators: 1: active scored-protection count, 2: total scored protections, 3: first module name, 4: target score. */
				__( '%1$d of %2$d scored protections are active. Enabling %3$s would raise your score to %4$d.', 'login-armor' ),
				(int) $active_count,
				(int) $total_modules,
				(string) $first['name'],
				(int) $target_score
			) ) . ' ' . $scope_note;

		$title = ( 'login_armor_2fa_enabled' === $first['opt'] )
			? __( 'Good, but Two-Factor would close the gap.', 'login-armor' )
			: sprintf(
				/* translators: %s: module name. */
				__( 'Good: %s is your next quick win.', 'login-armor' ),
				(string) $first['name']
			);

		return array(
			'title'     => $title,
			'body'      => $body,
			'cta_url'   => $settings_url . (string) $first['anchor'],
			'cta_label' => sprintf(
				/* translators: %s: module name. */
				__( 'Enable %s →', 'login-armor' ),
				(string) $first['name']
			),
		);
	}
}
