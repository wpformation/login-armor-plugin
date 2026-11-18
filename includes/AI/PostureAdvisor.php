<?php
/**
 * AI security briefing, an analyst-grade read of the site: a one-line verdict,
 * the state of recent events ("all quiet for X days" vs what deserves
 * attention), the IP picture (who recurs, who is blocked, is the admin
 * whitelisted), and prioritised, data-specific recommendations.
 *
 * MINIMISATION is a cursor (Client::is_deep()):
 *   - OFF (default): only non-identifying aggregates leave the site.
 *   - ON (opt-in, explicit warning): real IPs / subnets / events are sent to the
 *     site's OWN connector so the model can name concrete actions.
 *
 * Prompt strings are NOT translated (internal model input, not UI); only
 * user-facing errors go through __().
 *
 * @package LoginArmor
 * @since   2.2.0
 */

namespace LoginArmor\AI;

use LoginArmor\Detection\Incident;

// Exit if accessed directly.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Builds the security briefing prompt (events × IPs × config) and renders the reply.
 */
class PostureAdvisor {

	/** Cache lifetime: short, since the threat picture drifts. */
	const CACHE_TTL = 3 * HOUR_IN_SECONDS;

	/** How many top source IPs to inspect. */
	const TOP_IPS = 12;

	/**
	 * Produce the briefing. Returns ready-to-display safe HTML, or a WP_Error.
	 *
	 * @param bool $force Bypass the cache and regenerate.
	 * @return string|\WP_Error
	 */
	public static function analyze( bool $force = false ) {
		$deep = Client::is_deep();

		$config   = self::collect_config();
		$events   = self::collect_events();
		$ips      = self::collect_ips( $deep );
		$threat   = self::collect_threat();
		$env      = self::collect_environment();
		$activity = self::collect_activity();
		$legit    = self::collect_legit_logins();

		// $activity and $legit MUST enter the cache key, otherwise the 3h-cached
		// briefing stays frozen while real activity drifts.
		$cache_key = self::cache_key( $deep, $config, $events, $ips, $threat, $env, $activity, $legit );
		if ( ! $force ) {
			$cached = get_transient( $cache_key );
			if ( is_string( $cached ) && '' !== $cached ) {
				return $cached;
			}
		}

		$result = Client::complete(
			self::build_prompt( $config, $events, $ips, $threat, $env, $activity, $legit, $deep ),
			array(
				'system_instruction' => self::system_instruction( $deep ),
				'max_tokens'         => 1000,
				'temperature'        => 0.25,
			)
		);
		if ( is_wp_error( $result ) ) {
			return $result;
		}

		$html = Client::format_markdown( (string) $result );
		if ( '' === trim( wp_strip_all_tags( $html ) ) ) {
			return new \WP_Error( 'login_armor_ai_empty', __( 'The AI response was empty. Try again.', 'login-armor' ) );
		}

		set_transient( $cache_key, $html, self::CACHE_TTL );
		return $html;
	}

	/**
	 * @param array<string,mixed> ...$parts
	 */
	private static function cache_key( bool $deep, array ...$parts ): string {
		$fingerprint = ( $deep ? 'd1|' : 'd0|' ) . wp_json_encode( $parts );
		return 'login_armor_ai_brief_' . substr( md5( (string) $fingerprint ), 0, 12 );
	}

	/**
	 * Deterministic security facts as safe HTML: shown when the AI layer is NOT
	 * producing advice (no connector, admin-disabled, or pending approval), so the
	 * briefing card stays useful without any AI. No PII, no network, all verified.
	 *
	 * Cached briefly (per locale) to keep the overview cheap on every load.
	 *
	 * @return string Escaped HTML.
	 */
	public static function facts_html(): string {
		// Fold the pending-update counts into the cache key so the panel refreshes
		// the INSTANT an admin updates a plugin/theme/core: otherwise this 5-min
		// HTML cache would keep showing "1 plugin to update" after it's done.
		// 2.8.2: the activity fingerprint goes in too. Without it, the panel
		// computed before an attack was served unchanged for five minutes
		// under the banner announcing that attack: "Failures: 0" and
		// "Incidents: None" beneath "Active attack in progress".
		$cache_key = 'login_armor_ai_facts_' . substr( md5( (string) get_user_locale() . '|' . self::pending_updates_fp() . '|' . self::activity_fp() ), 0, 12 );
		$cached    = get_transient( $cache_key );
		if ( is_string( $cached ) && '' !== $cached ) {
			return $cached;
		}

		$events   = self::collect_events();
		$threat   = self::collect_threat();
		$config   = self::collect_config();
		$env      = self::collect_environment();
		$ipsum    = self::collect_ip_summary();
		$changes  = self::collect_activity();
		$legit    = self::collect_legit_logins();

		// Each row is [ severity, label, value, $is_html=false ]. Values are
		// esc_html'd at render time UNLESS $is_html is true: in which case the
		// value MUST be built by a helper that escapes every dynamic fragment
		// (see env_chip()). Labels are always esc_html'd.
		$rows = array();

		// Login activity.
		if ( ! $events['ever'] || 0 === (int) $events['events_30d'] ) {
			$rows[] = array( 'ok', __( 'Login activity', 'login-armor' ), __( 'No attempts in the last 30 days: all quiet.', 'login-armor' ) );
		} else {
			$activity = sprintf(
				/* translators: 1: number of failed attempts, 2: number of successful logins (last 7 days). Label form avoids gender/number agreement. */
				__( 'Failures: %1$d · Successes: %2$d (7 days).', 'login-armor' ),
				(int) $events['failed_7d'],
				(int) $events['success_7d']
			);
			if ( '' !== $events['last_seen_ago'] ) {
				/* translators: %s: human-readable time difference, e.g. "2 days". */
				$activity .= ' ' . sprintf( __( 'Last attempt %s ago.', 'login-armor' ), $events['last_seen_ago'] );
			}
			$rows[] = array( 'info', __( 'Login activity', 'login-armor' ), $activity );
		}

		// Legitimate sign-ins (who actually logged in): local render, real roles.
		if ( (int) $legit['total_30d'] > 0 ) {
			$rows[] = array(
				'ok',
				__( 'Legitimate sign-ins', 'login-armor' ),
				sprintf(
					/* translators: 1: admins, 2: editors/authors, 3: other roles, 4: total successful sign-ins (30 days). */
					__( 'Admins: %1$d · Authors: %2$d · Others: %3$d · %4$d sign-ins (30 days).', 'login-armor' ),
					(int) $legit['by_role']['admins'],
					(int) $legit['by_role']['authors'],
					(int) $legit['by_role']['others'],
					(int) $legit['total_30d']
				),
			);
		}

		// Incidents.
		$crit       = (int) $threat['critical'];
		$inc_sev    = $crit > 0 ? 'warn' : ( (int) $threat['total'] > 0 ? 'info' : 'ok' );
		$rows[]     = array(
			$inc_sev,
			__( 'Incidents (30 days)', 'login-armor' ),
			( (int) $threat['total'] > 0 )
				? sprintf(
					/* translators: 1: total incidents, 2: critical incidents. Label form avoids agreement issues. */
					__( 'Total: %1$d · Critical: %2$d.', 'login-armor' ),
					(int) $threat['total'],
					$crit
				)
				: __( 'None.', 'login-armor' ),
		);

		// Admin IP whitelist (only surface when it is a risk).
		if ( ! $ipsum['admin_whitelisted'] ) {
			$rows[] = array( 'warn', __( 'Your admin IP', 'login-armor' ), __( 'Not whitelisted: risk of locking yourself out.', 'login-armor' ) );
		}

		// Module on/off states (Two-Factor, Password Policy, Session Management,
		// Request Firewall) and the hardening count are intentionally NOT repeated
		// here: they already appear as cards in the Overview module grid above, so
		// echoing them in this panel was pure duplication. This panel keeps only
		// what those cards don't convey: login activity, legitimate sign-ins,
		// incidents, the score, admin changes, environment and updates.
		if ( null !== $config['score'] ) {
			$score    = (int) $config['score'];
			$rows[]   = array(
				$score >= 80 ? 'ok' : ( $score >= 50 ? 'info' : 'warn' ),
				__( 'Security score', 'login-armor' ),
				sprintf(
					/* translators: %d: security score out of 100. */
					__( '%d / 100', 'login-armor' ),
					$score
				)
			);
		}

		// Admin changes (content / plugins / users …): counts only here; the
		// detailed recent events go to the AI prompt (minimised vs deep).
		if ( ! $changes['enabled'] ) {
			$rows[] = array( 'info', __( 'Admin changes', 'login-armor' ), __( 'Activity log disabled: enable it to track content and plugin changes.', 'login-armor' ) );
		} elseif ( 0 === (int) $changes['total_30d'] ) {
			$rows[] = array( 'ok', __( 'Admin changes (30 days)', 'login-armor' ), __( 'No content or plugin changes.', 'login-armor' ) );
		} else {
			$c      = $changes['counts_30d'];
			$labels = array(
				'post'   => __( 'Posts', 'login-armor' ),
				'plugin' => __( 'Plugins', 'login-armor' ),
				'theme'  => __( 'Themes', 'login-armor' ),
				'user'   => __( 'Users', 'login-armor' ),
				'option' => __( 'Settings', 'login-armor' ),
				'media'  => __( 'Media', 'login-armor' ),
			);
			$parts = array();
			foreach ( $labels as $key => $label ) {
				if ( ! empty( $c[ $key ] ) ) {
					$parts[] = $label . "\u{00A0}: " . (int) $c[ $key ];
				}
			}
			$sensitive = isset( $c['user'] ) || isset( $c['option'] );
			$rows[]    = array(
				$sensitive ? 'warn' : 'info',
				__( 'Admin changes (30 days)', 'login-armor' ),
				implode( ' · ', $parts ),
			);
		}

		// Environment: versions (PHP / database), as green-bold OK chips.
		$env_chips   = array();
		$env_chips[] = self::env_chip( 'PHP ' . $env['php_version'], ! $env['php_below_min'] );
		if ( '' !== $env['db_version'] ) {
			$env_chips[] = self::env_chip( ( $env['is_mariadb'] ? 'MariaDB ' : 'MySQL ' ) . $env['db_version'], ! $env['db_below_min'] );
		}
		$rows[] = array(
			( $env['php_below_min'] || $env['db_below_min'] ) ? 'warn' : 'ok',
			__( 'Environment', 'login-armor' ),
			implode( ' · ', $env_chips ),
			true,
		);

		// Updates: WordPress core / plugins / theme "up to date?" chips (request 3).
		// Pending chips link to the WordPress updates screen so the admin can act
		// on them directly from the briefing.
		$updates_url = admin_url( 'update-core.php' );
		$upd_chips   = array();
		$upd_chips[] = $env['core_pending']
			? self::env_chip( 'WordPress ' . $env['wp_version'], false, $updates_url )
			: self::env_chip( 'WordPress ' . $env['wp_version'], true );
		$upd_chips[] = (int) $env['plugins_pending'] > 0
			? self::env_chip( sprintf( /* translators: %d: plugins to update. */ _n( '%d plugin to update', '%d plugins to update', (int) $env['plugins_pending'], 'login-armor' ), (int) $env['plugins_pending'] ), false, $updates_url )
			: self::env_chip( __( 'Plugins', 'login-armor' ), true );
		$upd_chips[] = (int) $env['themes_pending'] > 0
			? self::env_chip( sprintf( /* translators: %d: themes to update. */ _n( '%d theme to update', '%d themes to update', (int) $env['themes_pending'], 'login-armor' ), (int) $env['themes_pending'] ), false, $updates_url )
			: self::env_chip( __( 'Theme', 'login-armor' ), true );
		$rows[] = array(
			( $env['core_pending'] || $env['plugins_pending'] || $env['themes_pending'] ) ? 'warn' : 'ok',
			__( 'Updates', 'login-armor' ),
			implode( ' · ', $upd_chips ),
			true,
		);

		// Environment: things to harden (only when present).
		$env_warn = array();
		if ( $env['auto_updates_disabled'] ) {
			$env_warn[] = __( 'core auto-updates off', 'login-armor' );
		}
		if ( $env['default_prefix'] ) {
			$env_warn[] = __( 'default database prefix', 'login-armor' );
		}
		if ( ! $env['using_https'] ) {
			$env_warn[] = __( 'HTTPS not in use', 'login-armor' );
		}
		if ( $env['debug_exposed'] && 'production' === $env['env_type'] ) {
			$env_warn[] = __( 'debug exposed in production', 'login-armor' );
		}
		if ( ! empty( $env_warn ) ) {
			$rows[] = array( 'warn', __( 'To harden', 'login-armor' ), implode( ' · ', $env_warn ) );
		}

		$html = '<div class="la-ai-facts">';
		foreach ( $rows as $r ) {
			$val   = ( ! empty( $r[3] ) ) ? $r[2] : esc_html( $r[2] );
			$html .= '<div class="la-ai-fact la-ai-fact--' . esc_attr( $r[0] ) . '">'
				. '<span class="la-ai-fact__k">' . esc_html( $r[1] ) . '</span>'
				. '<span class="la-ai-fact__v">' . $val . '</span>'
				. '</div>';
		}
		$html .= '</div>';

		set_transient( $cache_key, $html, 5 * MINUTE_IN_SECONDS );
		return $html;
	}

	/**
	 * Build one environment status chip as SAFE HTML: the dynamic $text is
	 * esc_html'd before being wrapped in a static span. This is the only path by
	 * which facts_html() emits a value without the global esc_html() (html=true).
	 */
	/**
	 * Compact fingerprint of pending core/plugin/theme updates ("c:p:t"), used in
	 * the facts cache key so the panel regenerates the moment an update is applied.
	 *
	 * @return string
	 */
	private static function pending_updates_fp(): string {
		$up = get_site_transient( 'update_plugins' );
		$p  = ( is_object( $up ) && ! empty( $up->response ) && is_array( $up->response ) ) ? count( $up->response ) : 0;
		$ut = get_site_transient( 'update_themes' );
		$t  = ( is_object( $ut ) && ! empty( $ut->response ) && is_array( $ut->response ) ) ? count( $ut->response ) : 0;
		$c  = 0;
		if ( function_exists( 'get_core_updates' ) ) {
			$cu = get_core_updates( array( 'dismissed' => false ) );
			$c  = ( is_array( $cu ) && ! empty( $cu ) && isset( $cu[0]->response )
				&& ! in_array( $cu[0]->response, array( 'development', 'latest' ), true ) ) ? 1 : 0;
		}
		return $c . ':' . $p . ':' . $t;
	}

	/**
	 * Fingerprint of everything the facts panel counts (2.8.2), used in its
	 * cache key so a new attempt, incident, admin change or setting shows on
	 * the next load instead of up to five minutes later.
	 *
	 * Cheap by construction: a maximum over a primary key, one aggregate over
	 * the small incidents table, and option reads. The newest log id covers
	 * failures and sign-ins; the incidents aggregate covers a new incident, one
	 * that grows (last_seen_at) or escalates (severity), and a purge (count).
	 *
	 * @return string
	 */
	private static function activity_fp(): string {
		global $wpdb;

		// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.InterpolatedNotPrepared,PluginCheck.Security.DirectDB.UnescapedDBParameter -- Custom plugin tables, cache-key read; table names from $wpdb->prefix.
		$logs      = (string) $wpdb->get_var( "SELECT MAX(id) FROM {$wpdb->prefix}login_armor_logs" );
		$incidents = class_exists( '\LoginArmor\Detection\Incident' )
			? (string) $wpdb->get_var( "SELECT CONCAT_WS(':', COUNT(*), MAX(id), MAX(last_seen_at), SUM(severity)) FROM {$wpdb->prefix}login_armor_incidents" )
			: '';
		$changes   = ( class_exists( '\LoginArmor\ActivityLog\ActivityLog' ) && \LoginArmor\ActivityLog\ActivityLog::is_enabled() )
			? (string) $wpdb->get_var( "SELECT MAX(id) FROM {$wpdb->prefix}login_armor_activity" )
			: 'off';
		// phpcs:enable WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.InterpolatedNotPrepared,PluginCheck.Security.DirectDB.UnescapedDBParameter

		$score = class_exists( '\LoginArmor\SecurityScore' ) ? (string) \LoginArmor\SecurityScore::compute() : '';

		return $logs . '|' . $incidents . '|' . $changes . '|' . $score . '|' . ( self::admin_ip_whitelisted() ? '1' : '0' );
	}

	private static function env_chip( string $text, bool $ok, string $href = '' ): string {
		$cls   = $ok ? 'la-ai-chip--ok' : 'la-ai-chip--warn';
		$mark  = $ok ? '✓' : '⚠';
		$inner = esc_html( $text ) . ' ' . $mark;
		// When a target is given (e.g. a pending update), the chip becomes a real
		// link so the admin can act on it straight from the briefing.
		if ( '' !== $href ) {
			return '<a class="la-ai-chip ' . $cls . ' la-ai-chip--link" href="' . esc_url( $href ) . '">' . $inner . '</a>';
		}
		return '<span class="la-ai-chip ' . $cls . '">' . $inner . '</span>';
	}

	/* ---------------------------------------------------------------------
	 * Events snapshot.
	 * ------------------------------------------------------------------- */

	/**
	 * @return array<string,mixed>
	 */
	private static function collect_events(): array {
		global $wpdb;
		$table = $wpdb->prefix . 'login_armor_logs';

		// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.InterpolatedNotPrepared,PluginCheck.Security.DirectDB.UnescapedDBParameter -- Custom plugin table, AI briefing read; table name from $wpdb->prefix.
		$last      = $wpdb->get_var( "SELECT MAX(log_time) FROM {$table}" );
		$c24       = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$table} WHERE log_time > DATE_SUB(UTC_TIMESTAMP(), INTERVAL 24 HOUR)" );
		$c7d       = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$table} WHERE log_time > DATE_SUB(UTC_TIMESTAMP(), INTERVAL 7 DAY)" );
		$c30d      = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$table} WHERE log_time > DATE_SUB(UTC_TIMESTAMP(), INTERVAL 30 DAY)" );
		$prev7d    = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$table} WHERE log_time BETWEEN DATE_SUB(UTC_TIMESTAMP(), INTERVAL 14 DAY) AND DATE_SUB(UTC_TIMESTAMP(), INTERVAL 7 DAY)" );
		$failed7d  = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$table} WHERE status='failed' AND log_time > DATE_SUB(UTC_TIMESTAMP(), INTERVAL 7 DAY)" );
		$success7d = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$table} WHERE status='success' AND log_time > DATE_SUB(UTC_TIMESTAMP(), INTERVAL 7 DAY)" );
		// phpcs:enable WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.InterpolatedNotPrepared,PluginCheck.Security.DirectDB.UnescapedDBParameter

		$quiet_for = '';
		if ( $last ) {
			$ts = strtotime( $last . ' UTC' );
			if ( $ts && ( time() - $ts ) > 0 ) {
				$quiet_for = human_time_diff( $ts, time() );
			}
		}

		return array(
			'events_24h'    => $c24,
			'events_7d'     => $c7d,
			'events_30d'    => $c30d,
			'prev_7d'       => $prev7d,
			'failed_7d'     => $failed7d,
			'success_7d'    => $success7d,
			'last_seen_ago' => $quiet_for,
			'ever'          => null !== $last,
		);
	}

	/* ---------------------------------------------------------------------
	 * IP / source snapshot (the cursor decides what is transmitted).
	 * ------------------------------------------------------------------- */

	/**
	 * @return array<string,mixed>
	 */
	private static function collect_ips( bool $deep ): array {
		global $wpdb;
		$table = $wpdb->prefix . 'login_armor_logs';

		// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.InterpolatedNotPrepared,WordPress.DB.PreparedSQL.NotPrepared,PluginCheck.Security.DirectDB.UnescapedDBParameter -- Custom plugin table; aggregate of top source IPs for the AI briefing.
		$rows = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT ip, COUNT(*) n, MAX(log_time) last, SUM(CASE WHEN status='success' THEN 1 ELSE 0 END) ok FROM {$table} WHERE ip <> '' AND log_time > DATE_SUB(UTC_TIMESTAMP(), INTERVAL 30 DAY) GROUP BY ip ORDER BY n DESC LIMIT %d",
				self::TOP_IPS
			)
		);
		// phpcs:enable WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.InterpolatedNotPrepared,WordPress.DB.PreparedSQL.NotPrepared,PluginCheck.Security.DirectDB.UnescapedDBParameter
		$rows = is_array( $rows ) ? $rows : array();

		$limit_class   = class_exists( '\LoginArmor\LimitLogin' );
		$sources       = array();
		$blocked_count = 0;
		$wl_count      = 0;
		foreach ( $rows as $r ) {
			$ip      = (string) $r->ip;
			$blocked = $limit_class ? \LoginArmor\LimitLogin::is_locked_or_blacklisted( $ip ) : false;
			$wl      = $limit_class ? \LoginArmor\LimitLogin::is_whitelisted( $ip ) : false;
			if ( $blocked ) {
				++$blocked_count;
			}
			if ( $wl ) {
				++$wl_count;
			}
			$entry = array(
				'attempts'  => (int) $r->n,
				'success'   => (int) $r->ok,
				'blocked'   => $blocked,
				'whitelist' => $wl,
			);
			if ( $deep ) {
				$entry['ip']     = $ip;
				$entry['subnet'] = $limit_class ? \LoginArmor\LimitLogin::subnet_of( $ip ) : '';
			}
			$sources[] = $entry;
		}

		$admin_ip   = class_exists( '\LoginArmor\LoginArmor' ) ? \LoginArmor\LoginArmor::get_client_ip() : '';
		$admin_wl   = ( $limit_class && '' !== $admin_ip ) ? \LoginArmor\LimitLogin::is_whitelisted( $admin_ip ) : false;
		$wl_raw     = (string) get_option( 'login_armor_whitelist_ips', '' );
		$wl_entries = array_filter( array_map( 'trim', preg_split( '/[\r\n]+/', $wl_raw ) ) );

		return array(
			'distinct_sources'  => count( $rows ),
			'blocked_sources'   => $blocked_count,
			'whitelist_sources' => $wl_count,
			'top'               => $sources,
			'locked_now'        => $limit_class ? \LoginArmor\LimitLogin::get_locked_ips_count() : 0,
			'blocked_subnets'   => $limit_class ? count( \LoginArmor\LimitLogin::get_blocked_subnets() ) : 0,
			'whitelist_size'    => count( $wl_entries ),
			'admin_whitelisted' => $admin_wl,
		);
	}

	/* ---------------------------------------------------------------------
	 * Config + threat snapshots.
	 * ------------------------------------------------------------------- */

	/**
	 * @return array<string,mixed>
	 */
	private static function collect_config(): array {
		$enforce_roles = (array) get_option( 'login_armor_2fa_enforce_roles', array() );

		return array(
			'score'         => class_exists( '\LoginArmor\SecurityScore' ) ? \LoginArmor\SecurityScore::compute() : null,
			'modules'       => self::module_states(),
			'brute_force'   => array(
				'allowed_retries'  => (int) get_option( 'login_armor_allowed_retries', 3 ),
				'lockout_duration' => (int) get_option( 'login_armor_lockout_duration', 20 ),
				'max_lockouts'     => (int) get_option( 'login_armor_max_lockouts', 2 ),
			),
			'two_factor'    => array(
				'enabled'       => (bool) get_option( 'login_armor_2fa_enabled', false ),
				'enforce_roles' => array_values( array_filter( array_map( 'strval', $enforce_roles ) ) ),
			),
			'notifications' => array(
				'channel'      => (string) get_option( 'login_armor_notif_channel', 'disabled' ),
				'min_severity' => (int) get_option( 'login_armor_notif_min_severity', 2 ),
			),
			'firewall'      => array(
				'enabled' => class_exists( '\LoginArmor\Firewall\Firewall' ) && \LoginArmor\Firewall\Firewall::is_enabled(),
				'mode'    => class_exists( '\LoginArmor\Firewall\Firewall' ) ? \LoginArmor\Firewall\Firewall::get_mode() : 'log_only',
			),
			'hardening'     => self::hardening_states(),
		);
	}

	/**
	 * @return array<string,bool>
	 */
	private static function module_states(): array {
		return array(
			'Masquage URL connexion' => class_exists( '\LoginArmor\HideLogin' ) ? \LoginArmor\HideLogin::is_enabled() : (bool) get_option( 'login_armor_hide_enabled', false ),
			'Protection force brute' => (bool) get_option( 'login_armor_limit_enabled', true ),
			'Moteur de détection'    => (bool) get_option( 'login_armor_detection_enabled', true ),
			'Journal d’activité'     => (bool) get_option( 'login_armor_activity_enabled', false ),
			'2FA'                       => (bool) get_option( 'login_armor_2fa_enabled', false ),
			'En-têtes de sécurité'      => class_exists( '\LoginArmor\LoginHeaders' ) ? \LoginArmor\LoginHeaders::is_enabled() : (bool) get_option( 'login_armor_login_headers_enabled', false ),
			'Vérification de fuites'    => class_exists( '\LoginArmor\BreachCheck' ) ? \LoginArmor\BreachCheck::is_enabled() : (bool) get_option( 'login_armor_breach_check_enabled', false ),
			'Politique de mot de passe' => class_exists( '\LoginArmor\PasswordPolicy' ) && \LoginArmor\PasswordPolicy::is_enabled(),
			'Gestion des sessions'      => class_exists( '\LoginArmor\SessionManager' ) && \LoginArmor\SessionManager::is_enabled(),
			'Pare-feu de requêtes'      => class_exists( '\LoginArmor\Firewall\Firewall' ) && \LoginArmor\Firewall\Firewall::is_enabled(),
		);
	}

	/**
	 * @return array<string,bool>
	 */
	private static function hardening_states(): array {
		if ( ! class_exists( '\LoginArmor\Hardening' ) ) {
			return array();
		}
		$settings = \LoginArmor\Hardening::get_settings();
		$toggles  = \LoginArmor\Hardening::get_toggles();
		$out      = array();
		foreach ( $toggles as $toggle ) {
			if ( ! isset( $toggle['key'] ) ) {
				continue;
			}
			$label         = isset( $toggle['label'] ) ? (string) $toggle['label'] : (string) $toggle['key'];
			$out[ $label ] = ! empty( $settings[ $toggle['key'] ] );
		}
		return $out;
	}

	/**
	 * @return array<string,mixed>
	 */
	private static function collect_threat(): array {
		// Detection module (Incident) may be disabled/unloaded: degrade to zeros
		// rather than fatal, since facts_html() runs on every overview load.
		if ( ! class_exists( '\LoginArmor\Detection\Incident' ) ) {
			return array(
				'total'    => 0,
				'patterns' => array(),
				'high'     => 0,
				'critical' => 0,
			);
		}

		$period   = array( 'period' => '30d' );
		$patterns = array(
			Incident::PATTERN_BRUTE_FORCE,
			Incident::PATTERN_CREDENTIAL_STUFFING,
			Incident::PATTERN_ENUMERATION,
			Incident::PATTERN_DISTRIBUTED,
			Incident::PATTERN_POST_COMPROMISE,
			Incident::PATTERN_RESERVED_USERNAME_PROBE,
			Incident::PATTERN_BOT_HONEYPOT_CAUGHT,
			Incident::PATTERN_2FA_RECOVERY_REQUESTED,
			Incident::PATTERN_FIREWALL_BLOCK,
		);
		$by_pattern = array();
		foreach ( $patterns as $p ) {
			$count = Incident::count_filtered( array_merge( $period, array( 'pattern' => $p ) ) );
			if ( $count > 0 ) {
				$by_pattern[ self::pattern_label( $p ) ] = $count;
			}
		}
		arsort( $by_pattern );

		return array(
			'total'    => Incident::count_filtered( $period ),
			'patterns' => $by_pattern,
			'high'     => Incident::count_filtered( array_merge( $period, array( 'severity' => Incident::SEVERITY_HIGH ) ) ),
			'critical' => Incident::count_filtered( array_merge( $period, array( 'severity' => Incident::SEVERITY_CRITICAL ) ) ),
		);
	}

	/* ---------------------------------------------------------------------
	 * Environment / Site Health snapshot: verified, 100% local, non-PII.
	 *
	 * Every signal here is read from PHP constants, $wpdb, or caches WP already
	 * filled: NO fresh network call is ever triggered. "Up to date?" signals
	 * (core/plugins) reflect the last known cached state, flagged as such.
	 * ------------------------------------------------------------------- */

	/**
	 * @return array<string,mixed>
	 */
	private static function collect_environment(): array {
		global $wpdb;

		// PHP: hard-coded thresholds keep this 100% local (Serve Happy is HTTP).
		$php_below_min = version_compare( PHP_VERSION, '7.4', '<' );
		$php_below_rec = version_compare( PHP_VERSION, '8.0', '<' );

		// Database: Site Health's own method. db_version() truncates MariaDB to
		// 5.5.5, so read the raw server string + SELECT VERSION() like core does.
		$db_raw     = method_exists( $wpdb, 'db_server_info' ) ? (string) $wpdb->db_server_info() : '';
		$is_mariadb = '' !== $db_raw && false !== stristr( $db_raw, 'mariadb' );
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- server version string, no user input, single cheap read.
		$db_full = (string) $wpdb->get_var( 'SELECT VERSION()' );
		// MariaDB may prepend a fake "5.5.5-" for old-client compat, and appends a
		// "-MariaDB" suffix; keep the leading dotted-numeric part for a clean
		// display and a correct version_compare ($is_mariadb is tracked separately).
		$db_clean     = preg_replace( '/^5\.5\.5-/', '', $db_full );
		$db_version   = preg_match( '/^[0-9]+(?:\.[0-9]+)*/', (string) $db_clean, $m ) ? $m[0] : '';
		$db_below_min = '' !== $db_version && version_compare( $db_version, '5.5', '<' );
		$db_below_rec = '' !== $db_version && ( $is_mariadb ? version_compare( $db_version, '10.6', '<' ) : version_compare( $db_version, '8.0', '<' ) );

		// Default table prefix (base_prefix is multisite-safe).
		$default_prefix = ( 'wp_' === $wpdb->base_prefix );

		// Core auto-updates, WP_Automatic_Updater::is_disabled() aggregates
		// DISALLOW_FILE_MODS + AUTOMATIC_UPDATER_DISABLED + the filter.
		$updater_file = ABSPATH . 'wp-admin/includes/class-wp-automatic-updater.php';
		if ( ! class_exists( 'WP_Automatic_Updater' ) && is_readable( $updater_file ) ) {
			require_once $updater_file;
		}
		$auto_disabled     = class_exists( 'WP_Automatic_Updater' ) ? (bool) ( new \WP_Automatic_Updater() )->is_disabled() : false;
		$core_const_blocks = defined( 'WP_AUTO_UPDATE_CORE' ) && ! in_array( WP_AUTO_UPDATE_CORE, array( true, 'beta', 'rc', 'development', 'branch-development', 'minor' ), true );

		// HTTPS (site config: avoid loopback probes).
		$using_https = function_exists( 'wp_is_using_https' ) ? wp_is_using_https() : is_ssl();

		// Debug exposed (real-risk reading: WP_DEBUG_DISPLAY defaults to true).
		$debug_on      = defined( 'WP_DEBUG' ) && WP_DEBUG;
		$display_on    = ! defined( 'WP_DEBUG_DISPLAY' ) || true === WP_DEBUG_DISPLAY;
		$debug_exposed = $debug_on && $display_on;

		// File hardening.
		$file_edit_locked = defined( 'DISALLOW_FILE_EDIT' ) && DISALLOW_FILE_EDIT;

		$env_type = function_exists( 'wp_get_environment_type' ) ? (string) wp_get_environment_type() : 'production';

		// WP core: installed version is local; "pending?" is the last cached state.
		$wp_version   = get_bloginfo( 'version' );
		$core_pending = false;
		if ( function_exists( 'get_core_updates' ) ) {
			$cu = get_core_updates( array( 'dismissed' => false ) );
			$core_pending = is_array( $cu ) && ! empty( $cu ) && isset( $cu[0]->response )
				&& ! in_array( $cu[0]->response, array( 'development', 'latest' ), true );
		}

		// Plugins / themes with a pending update: read the transients directly
		// (no caps bias). "Pending?" reflects the last cached state, like core.
		$up              = get_site_transient( 'update_plugins' );
		$plugins_pending = ( is_object( $up ) && ! empty( $up->response ) && is_array( $up->response ) ) ? count( $up->response ) : 0;
		$ut              = get_site_transient( 'update_themes' );
		$themes_pending  = ( is_object( $ut ) && ! empty( $ut->response ) && is_array( $ut->response ) ) ? count( $ut->response ) : 0;

		return array(
			'php_version'           => PHP_VERSION,
			'php_below_min'         => $php_below_min,
			'php_below_rec'         => $php_below_rec,
			'db_version'            => $db_version,
			'is_mariadb'            => $is_mariadb,
			'db_below_min'          => $db_below_min,
			'db_below_rec'          => $db_below_rec,
			'default_prefix'        => $default_prefix,
			'auto_updates_disabled' => ( $auto_disabled || $core_const_blocks ),
			'using_https'           => (bool) $using_https,
			'debug_exposed'         => $debug_exposed,
			'file_edit_locked'      => $file_edit_locked,
			'env_type'              => $env_type,
			'wp_version'            => $wp_version,
			'core_pending'          => $core_pending,
			'plugins_pending'       => $plugins_pending,
			'themes_pending'        => $themes_pending,
		);
	}

	/**
	 * Light IP summary for the deterministic facts panel: avoids the heavier
	 * top-sources GROUP BY of collect_ips(), so it is cheap on every overview load.
	 *
	 * @return array{locked_now:int, admin_whitelisted:bool}
	 */
	private static function collect_ip_summary(): array {
		return array(
			'locked_now'        => class_exists( '\LoginArmor\LimitLogin' ) ? (int) \LoginArmor\LimitLogin::get_locked_ips_count() : 0,
			'admin_whitelisted' => self::admin_ip_whitelisted(),
		);
	}

	/**
	 * Is the address of the administrator looking at the panel on the
	 * safelist? Shared by the panel and its cache key.
	 */
	private static function admin_ip_whitelisted(): bool {
		$admin_ip = class_exists( '\LoginArmor\LoginArmor' ) ? \LoginArmor\LoginArmor::get_client_ip() : '';
		return class_exists( '\LoginArmor\LimitLogin' ) && '' !== $admin_ip && \LoginArmor\LimitLogin::is_whitelisted( $admin_ip );
	}

	/* ---------------------------------------------------------------------
	 * Legitimate activity snapshots: who actually signs in, and what changed.
	 * ------------------------------------------------------------------- */

	/**
	 * Legitimate sign-ins: successful logins resolved to a role bucket. The logs
	 * table has no role, so distinct successful usernames (bounded) are resolved
	 * via get_user_by(). Cheap: very few users ever sign in successfully.
	 *
	 * @return array{by_role:array<string,int>, total_7d:int, total_30d:int, distinct_users_30d:int}
	 */
	private static function collect_legit_logins(): array {
		global $wpdb;
		$table = $wpdb->prefix . 'login_armor_logs';

		// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.InterpolatedNotPrepared,PluginCheck.Security.DirectDB.UnescapedDBParameter -- Custom plugin table, AI briefing read; table name from $wpdb->prefix.
		$total_7d  = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$table} WHERE status='success' AND log_time > DATE_SUB(UTC_TIMESTAMP(), INTERVAL 7 DAY)" );
		$total_30d = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$table} WHERE status='success' AND log_time > DATE_SUB(UTC_TIMESTAMP(), INTERVAL 30 DAY)" );
		$names     = $wpdb->get_col( "SELECT DISTINCT username FROM {$table} WHERE status='success' AND username <> '' AND log_time > DATE_SUB(UTC_TIMESTAMP(), INTERVAL 30 DAY) LIMIT 50" );
		// phpcs:enable WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.InterpolatedNotPrepared,PluginCheck.Security.DirectDB.UnescapedDBParameter

		$names   = is_array( $names ) ? $names : array();
		$by_role = array(
			'admins'  => 0,
			'authors' => 0,
			'others'  => 0,
		);
		foreach ( $names as $login ) {
			$user = get_user_by( 'login', (string) $login );
			$role = ( $user && ! empty( $user->roles ) ) ? (string) $user->roles[0] : '';
			if ( 'administrator' === $role ) {
				++$by_role['admins'];
			} elseif ( in_array( $role, array( 'editor', 'author', 'contributor' ), true ) ) {
				++$by_role['authors'];
			} else {
				++$by_role['others'];
			}
		}

		return array(
			'by_role'            => $by_role,
			'total_7d'           => $total_7d,
			'total_30d'          => $total_30d,
			'distinct_users_30d' => count( $names ),
		);
	}

	/**
	 * Administrative changes recorded by the Activity Log (content, plugins,
	 * themes, users, options, media). Degrades gracefully to enabled=false when
	 * the module is off, like collect_threat() handles a missing Incident class.
	 *
	 * @return array{enabled:bool, counts_30d:array<string,int>, counts_7d:array<string,int>, total_30d:int, recent:array<int,array<string,string>>}
	 */
	private static function collect_activity(): array {
		$disabled = array(
			'enabled'    => false,
			'counts_30d' => array(),
			'counts_7d'  => array(),
			'total_30d'  => 0,
			'recent'     => array(),
		);
		if ( ! class_exists( '\LoginArmor\ActivityLog\ActivityLog' ) || ! \LoginArmor\ActivityLog\ActivityLog::is_enabled() ) {
			return $disabled;
		}

		$types      = array( 'post', 'plugin', 'theme', 'user', 'option', 'media' );
		$counts_30d = array();
		$counts_7d  = array();
		$total_30d  = 0;
		foreach ( $types as $t ) {
			$c30 = (int) \LoginArmor\ActivityLog\ActivityLog::count_logs( array( 'object_type' => $t, 'period' => '30d' ) );
			$c7  = (int) \LoginArmor\ActivityLog\ActivityLog::count_logs( array( 'object_type' => $t, 'period' => '7d' ) );
			if ( $c30 > 0 ) {
				$counts_30d[ $t ] = $c30;
			}
			if ( $c7 > 0 ) {
				$counts_7d[ $t ] = $c7;
			}
			$total_30d += $c30;
		}

		// Recent high-signal events (last 7 days, up to 3): exclude noisy updates.
		$high_signal = array(
			'post_created', 'post_deleted', 'post_trashed',
			'plugin_activated', 'plugin_deactivated', 'plugin_installed', 'plugin_deleted', 'plugin_updated',
			'theme_activated', 'theme_installed', 'theme_deleted', 'theme_updated',
			'user_created', 'user_deleted', 'user_role_changed',
			'option_changed',
		);
		$recent = array();
		$rows   = \LoginArmor\ActivityLog\ActivityLog::get_logs( array( 'period' => '7d' ), 15, 0 );
		$rows   = is_array( $rows ) ? $rows : array();
		foreach ( $rows as $r ) {
			$action = isset( $r->action ) ? (string) $r->action : '';
			if ( ! in_array( $action, $high_signal, true ) ) {
				continue;
			}
			$ago = '';
			if ( ! empty( $r->log_time ) ) {
				$ts = strtotime( $r->log_time . ' UTC' );
				if ( $ts ) {
					$ago = human_time_diff( $ts, time() );
				}
			}
			$recent[] = array(
				'actor'  => isset( $r->user_login ) ? (string) $r->user_login : '',
				'role'   => isset( $r->user_role ) ? (string) $r->user_role : '',
				'action' => $action,
				'type'   => isset( $r->object_type ) ? (string) $r->object_type : '',
				'name'   => isset( $r->object_name ) ? (string) $r->object_name : '',
				'ago'    => $ago,
			);
			if ( count( $recent ) >= 3 ) {
				break;
			}
		}

		return array(
			'enabled'    => true,
			'counts_30d' => $counts_30d,
			'counts_7d'  => $counts_7d,
			'total_30d'  => $total_30d,
			'recent'     => $recent,
		);
	}

	/* ---------------------------------------------------------------------
	 * Prompt assembly (French literal: internal model input, never displayed).
	 * ------------------------------------------------------------------- */

	/**
	 * @param array<string,mixed> $config
	 * @param array<string,mixed> $events
	 * @param array<string,mixed> $ips
	 * @param array<string,mixed> $threat
	 * @param array<string,mixed> $env
	 * @param array<string,mixed> $activity
	 * @param array<string,mixed> $legit
	 */
	private static function build_prompt( array $config, array $events, array $ips, array $threat, array $env, array $activity, array $legit, bool $deep ): string {
		$L = array();

		// Events.
		$L[] = '## ÉVÉNEMENTS DE CONNEXION';
		if ( ! $events['ever'] || 0 === (int) $events['events_30d'] ) {
			$L[] = '- Aucune tentative enregistrée sur les 30 derniers jours (site calme).';
		} else {
			$L[] = sprintf( '- 24 h : %d | 7 j : %d (semaine précédente : %d) | 30 j : %d', (int) $events['events_24h'], (int) $events['events_7d'], (int) $events['prev_7d'], (int) $events['events_30d'] );
			$L[] = sprintf( '- Sur 7 j : %d échecs, %d connexions réussies', (int) $events['failed_7d'], (int) $events['success_7d'] );
			if ( '' !== $events['last_seen_ago'] ) {
				$L[] = '- Dernière tentative : il y a ' . $events['last_seen_ago'];
			}
		}

		// Incidents.
		$L[] = '';
		$L[] = '## INCIDENTS CLASSÉS (30 j)';
		$L[] = sprintf( '- Total : %d (gravité élevée : %d, critique : %d)', (int) $threat['total'], (int) $threat['high'], (int) $threat['critical'] );
		foreach ( $threat['patterns'] as $label => $count ) {
			$L[] = '  - ' . $label . ' : ' . (int) $count;
		}

		// Sources / IPs.
		$L[] = '';
		$L[] = '## SOURCES (ADRESSES IP)';
		$L[] = sprintf( '- %d sources distinctes sur 30 j ; %d actuellement bloquées/lockées ; %d sous-réseaux bannis ; %d IP en liste blanche', (int) $ips['distinct_sources'], (int) $ips['locked_now'], (int) $ips['blocked_subnets'], (int) $ips['whitelist_size'] );
		$L[] = $ips['admin_whitelisted']
			? '- Votre IP d’administration EST en liste blanche (pas de risque d’auto-blocage).'
			: '- ATTENTION : votre IP d’administration n’est PAS en liste blanche (risque de vous auto-bloquer en cas de lockout agressif).';

		if ( ! empty( $ips['top'] ) ) {
			if ( $deep ) {
				$L[] = '- Sources les plus actives (IP réelles, mode approfondi autorisé par l’admin) :';
				foreach ( $ips['top'] as $s ) {
					$flag  = ! empty( $s['blocked'] ) ? 'bloquée' : ( ! empty( $s['whitelist'] ) ? 'liste blanche' : 'NON bloquée' );
					$L[]   = sprintf( '  - %s (%s) : %d tentatives, %d succès, %s', $s['ip'], $s['subnet'], (int) $s['attempts'], (int) $s['success'], $flag );
				}
			} else {
				$top = $ips['top'][0];
				$L[] = sprintf(
					'- Source la plus active : %d tentatives (%s) ; %d des sources principales sont bloquées, %d en liste blanche. (Valeurs d’IP masquées, mode minimisé.)',
					(int) $top['attempts'],
					! empty( $top['blocked'] ) ? 'bloquée' : 'NON bloquée',
					(int) $ips['blocked_sources'],
					(int) $ips['whitelist_sources']
				);
			}
		}

		// Legitimate activity: who actually signs in.
		$L[] = '';
		$L[] = '## ACTIVITÉ LÉGITIME (qui se connecte)';
		if ( (int) $legit['total_30d'] > 0 ) {
			$br  = $legit['by_role'];
			$L[] = sprintf( '- Connexions réussies : 7 j = %d, 30 j = %d (%d comptes distincts).', (int) $legit['total_7d'], (int) $legit['total_30d'], (int) $legit['distinct_users_30d'] );
			$L[] = sprintf( '- Par rôle (30 j) : administrateurs = %d, éditeurs/auteurs = %d, autres = %d.', (int) $br['admins'], (int) $br['authors'], (int) $br['others'] );
		} else {
			$L[] = '- Aucune connexion réussie sur 30 jours.';
		}

		// Administrative changes (Activity Log). Recent events are anonymised in
		// minimised mode and only nominative in deep mode.
		$L[] = '';
		$L[] = '## CHANGEMENTS ADMINISTRATIFS (journal d’activité)';
		if ( ! $activity['enabled'] ) {
			$L[] = '- Journal d’activité désactivé : aucun changement de contenu/extension n’est suivi.';
		} elseif ( 0 === (int) $activity['total_30d'] ) {
			$L[] = '- Aucun changement de contenu, d’extension ou de compte sur 30 jours.';
		} else {
			$type_fr = array(
				'post'   => 'articles/pages',
				'plugin' => 'extensions',
				'theme'  => 'thèmes',
				'user'   => 'comptes',
				'option' => 'réglages critiques',
				'media'  => 'médias',
			);
			$parts = array();
			foreach ( $type_fr as $k => $lbl ) {
				if ( ! empty( $activity['counts_30d'][ $k ] ) ) {
					$parts[] = $lbl . ' = ' . (int) $activity['counts_30d'][ $k ];
				}
			}
			$L[] = '- Sur 30 j : ' . ( empty( $parts ) ? 'aucun' : implode( ', ', $parts ) ) . '.';
			if ( ! empty( $activity['recent'] ) ) {
				$L[] = '- Événements récents (7 j) :';
				foreach ( $activity['recent'] as $ev ) {
					$action = self::action_label( (string) $ev['action'] );
					if ( $deep ) {
						$name = '' !== $ev['name'] ? ( ' « ' . mb_substr( (string) $ev['name'], 0, 60 ) . ' »' ) : '';
						$who  = '' !== $ev['actor'] ? ( $ev['actor'] . ' (' . self::role_label( (string) $ev['role'] ) . ')' ) : self::role_label( (string) $ev['role'] );
						$L[]  = sprintf( '  - il y a %s, %s : %s%s', $ev['ago'], $who, $action, $name );
					} else {
						$L[] = sprintf( '  - il y a %s, %s par un %s', $ev['ago'], $action, self::role_label( (string) $ev['role'] ) );
					}
				}
			}
		}

		// Config.
		$L[] = '';
		$L[] = '## CONFIGURATION';
		if ( null !== $config['score'] ) {
			$L[] = sprintf( '- Score de sécurité : %d/100', (int) $config['score'] );
		}
		$mods = array();
		foreach ( $config['modules'] as $label => $v ) {
			$mods[] = $label . '=' . ( $v ? 'activé' : 'désactivé' );
		}
		$L[] = '- Modules : ' . implode( ', ', $mods );
		$bf  = $config['brute_force'];
		$L[] = sprintf( '- Force brute : %d essais, blocage %d min, %d blocages avant durcissement', (int) $bf['allowed_retries'], (int) $bf['lockout_duration'], (int) $bf['max_lockouts'] );
		$roles = $config['two_factor']['enforce_roles'];
		$L[]   = $config['two_factor']['enabled']
			? '- 2FA activée, imposée à : ' . ( empty( $roles ) ? 'aucun rôle' : implode( ', ', $roles ) )
			: '- 2FA désactivée';
		$notif = $config['notifications'];
		$L[]   = 'disabled' === $notif['channel']
			? '- Notifications désactivées'
			: sprintf( '- Notifications : %s (gravité min %d/4)', $notif['channel'], (int) $notif['min_severity'] );
		$fw  = $config['firewall'];
		$L[] = $fw['enabled']
			? ( 'enforce' === $fw['mode']
				? '- Pare-feu de requêtes : activé (mode blocage, bloque les requêtes malveillantes)'
				: '- Pare-feu de requêtes : activé (mode surveillance, journalise sans bloquer)' )
			: '- Pare-feu de requêtes : désactivé';
		$hard     = $config['hardening'];
		$hard_off = array();
		foreach ( $hard as $label => $state ) {
			if ( ! $state ) {
				$hard_off[] = $label;
			}
		}
		$L[] = sprintf( '- Durcissement : %d/%d actifs. Inactifs : %s', count( $hard ) - count( $hard_off ), count( $hard ), empty( $hard_off ) ? 'aucun' : implode( ', ', $hard_off ) );

		// Environment hygiene: SECONDARY. Listed last; the system instruction
		// forbids leading with it. All values are verified, local, non-PII.
		$L[] = '';
		$L[] = '## ENVIRONNEMENT DU SITE (hygiène secondaire, à ne citer qu’en complément)';
		$L[] = sprintf(
			'- WordPress %s%s ; PHP %s%s ; %s %s%s',
			$env['wp_version'],
			$env['core_pending'] ? ' (mise à jour du cœur en attente, dernier état connu)' : ' (cœur à jour, dernier état connu)',
			$env['php_version'],
			$env['php_below_min'] ? ' (NON supporté, < 7.4)' : ( $env['php_below_rec'] ? ' (ancien, < 8.0)' : ' (OK)' ),
			$env['is_mariadb'] ? 'MariaDB' : 'MySQL',
			'' !== $env['db_version'] ? $env['db_version'] : '?',
			$env['db_below_min'] ? ' (trop ancien)' : ( $env['db_below_rec'] ? ' (ancien)' : ' (OK)' )
		);
		$L[] = '- Mises à jour automatiques du cœur : ' . ( $env['auto_updates_disabled'] ? 'DÉSACTIVÉES (plus de correctifs de sécurité automatiques)' : 'activées' );
		$L[] = '- Préfixe de base de données : ' . ( $env['default_prefix'] ? 'par défaut « wp_ » (durcissement par obscurité non appliqué, bénéfice marginal)' : 'personnalisé' );
		$L[] = sprintf(
			'- Mises à jour en attente (dernier état connu) : cœur=%s, extensions=%d, thèmes=%d',
			$env['core_pending'] ? 'oui' : 'non',
			(int) $env['plugins_pending'],
			(int) $env['themes_pending']
		);
		$env_flags = array();
		if ( ! $env['using_https'] ) {
			$env_flags[] = 'HTTPS non utilisé';
		}
		if ( $env['debug_exposed'] && 'production' === $env['env_type'] ) {
			$env_flags[] = 'mode debug exposé en production';
		}
		if ( ! $env['file_edit_locked'] ) {
			$env_flags[] = 'éditeur de fichiers du tableau de bord actif (DISALLOW_FILE_EDIT absent)';
		}
		if ( ! empty( $env_flags ) ) {
			$L[] = '- Autres : ' . implode( ' ; ', $env_flags );
		}

		return implode( "\n", $L );
	}

	private static function system_instruction( bool $deep ): string {
		$locale = get_user_locale();

		$rules =
			"Tu es un analyste SOC senior. Tu produis un briefing de sécurité pour l’administrateur (non expert) d’un site WordPress protégé par LoginArmor.\n\n"
			. "ORDRE DE PRIORITÉ, respecte-le, ne l’inverse JAMAIS :\n"
			. "1. le login et les sources (IP) ; 2. les incidents classés ; 3. les événements de connexion ; 4. l’ACTIVITÉ LÉGITIME (qui se connecte) et les CHANGEMENTS ADMINISTRATIFS (journal d’activité) ; 5. les réglages LoginArmor (modules, 2FA, durcissement, notifications).\n"
			. "L’ENVIRONNEMENT / SANTÉ DU SITE (versions WP/PHP/MySQL, mises à jour en attente, préfixe, HTTPS, debug) vient EN COMPLÉMENT, jamais en tête.\n\n"
			. "STRUCTURE IMPOSÉE :\n"
			. "1. **Verdict** en une phrase : calme / sous surveillance / sous attaque.\n"
			. "2. **Ce qui se passe** : donne de la MATIÈRE. Couvre, quand les données le justifient : (a) les menaces (événements, incidents, sources non bloquées) ; (b) QUI se connecte légitimement (combien d’administrateurs/auteurs) ; (c) les CHANGEMENTS administratifs notables (extensions activées/supprimées, comptes créés, rôles modifiés, réglages critiques) ; (d) une phrase de santé du site si un point le mérite (cœur/PHP/MySQL obsolète, MAJ auto désactivées, préfixe par défaut, extensions/thème à mettre à jour). Si tout est calme, dis-le franchement (« RAS depuis X jours ») et NE FABRIQUE PAS d’urgence.\n"
			. "3. **Actions prioritaires** (2 à 5), classées, CHACUNE justifiée par une donnée précise du briefing : sécurité du login d’abord, hygiène du site ensuite.\n\n"
			. "RÈGLES STRICTES :\n"
			. "- Interdiction de te contenter de « activez le module X ». Chaque conseil s’appuie sur un chiffre, une IP, un sous-réseau, un réglage, un changement journalisé ou un fait observé.\n"
			. "- Si l’IP d’administration n’est pas en liste blanche ET que le lockout est agressif, signale le risque d’auto-blocage en priorité.\n"
			. "- Si une source très active n’est pas bloquée, dis-le et propose une action concrète (blocage IP ou de sous-réseau).\n"
			. "- Pour les CHANGEMENTS administratifs : appuie-toi UNIQUEMENT sur les événements fournis ; n’extrapole pas d’intention malveillante quand l’auteur est un administrateur légitime connu, présente-les comme information, et n’alerte que si un schéma est réellement suspect (ex. création de compte administrateur inattendue, désactivation d’un module de sécurité).\n"
			. "- N’invente AUCUNE donnée non fournie (pas de pays, pas de réputation d’IP, pas de version logicielle, pas de CVE).\n"
			. "- N’invente JAMAIS un chemin de menu ni un nom d’écran. Pour renvoyer à un réglage, utilise EXACTEMENT les libellés fournis dans ces instructions, sans rien y ajouter.\n"
			. "- Maximum 350 mots. Markdown léger (titres `##`/`###` courts, listes, gras). Réponds dans la langue de la locale WordPress « %s » (français par défaut).";

		$rules .= $deep
			? "\n- Le mode approfondi est actif : tu PEUX nommer les adresses IP, les sous-réseaux réels et les acteurs/objets des changements administratifs fournis."
			: "\n- Le mode minimisé est actif : ni les valeurs d’IP ni les noms d’acteurs/objets des changements ne te sont fournis (catégories et compteurs uniquement). Produis QUAND MÊME un briefing substantiel, ne te défausse pas sur l’absence de détails nominatifs. Tu peux, si c’est pertinent, suggérer d’activer le mode approfondi via le libellé EXACT « Réglages → Assistant IA → Analyse approfondie » pour des recommandations nominatives, sans en faire l’objet principal.";

		return sprintf( $rules, $locale );
	}

	private static function pattern_label( string $pattern ): string {
		return match ( $pattern ) {
			Incident::PATTERN_BRUTE_FORCE             => 'Force brute',
			Incident::PATTERN_CREDENTIAL_STUFFING     => 'Credential stuffing',
			Incident::PATTERN_ENUMERATION             => 'Énumération de comptes',
			Incident::PATTERN_DISTRIBUTED             => 'Attaque distribuée',
			Incident::PATTERN_POST_COMPROMISE         => 'Activité post-compromission',
			Incident::PATTERN_RESERVED_USERNAME_PROBE => 'Sondage d’identifiants réservés',
			Incident::PATTERN_BOT_HONEYPOT_CAUGHT     => 'Robot piégé (pot de miel)',
			Incident::PATTERN_2FA_RECOVERY_REQUESTED  => 'Demande de récupération 2FA',
			Incident::PATTERN_FIREWALL_BLOCK          => 'Pare-feu de requêtes',
			Incident::PATTERN_APP_PASSWORD_REFUSED    => 'Mot de passe d’application refusé',
			default                                   => $pattern,
		};
	}

	/** Activity-log action token → short French phrase (prompt input, not UI). */
	private static function action_label( string $action ): string {
		return match ( $action ) {
			'post_created'       => 'création d’article/page',
			'post_updated'       => 'modification d’article/page',
			'post_trashed'       => 'mise à la corbeille d’un article',
			'post_deleted'       => 'suppression d’article',
			'plugin_activated'   => 'activation d’extension',
			'plugin_deactivated' => 'désactivation d’extension',
			'plugin_installed'   => 'installation d’extension',
			'plugin_deleted'     => 'suppression d’extension',
			'plugin_updated'     => 'mise à jour d’extension',
			'theme_activated'    => 'changement de thème',
			'theme_installed'    => 'installation de thème',
			'theme_deleted'      => 'suppression de thème',
			'theme_updated'      => 'mise à jour de thème',
			'user_created'       => 'création de compte',
			'user_deleted'       => 'suppression de compte',
			'user_role_changed'  => 'changement de rôle',
			'option_changed'     => 'modification d’un réglage critique',
			default              => $action,
		};
	}

	/** Role slug → French label (prompt input, not UI). */
	private static function role_label( string $role ): string {
		return match ( $role ) {
			'administrator' => 'administrateur',
			'editor'        => 'éditeur',
			'author'        => 'auteur',
			'contributor'   => 'contributeur',
			'subscriber'    => 'abonné',
			default         => '' !== $role ? $role : 'compte inconnu',
		};
	}
}
