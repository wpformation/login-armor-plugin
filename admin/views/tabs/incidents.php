<?php
/**
 * LoginArmor Incidents tab: Lot 18 pixel-perfect redesign.
 *
 * Two modes:
 *   - List: summary strip + filter bar + incident cards + guide side-panel.
 *   - Drill-down (when ?incident=<id>): original timeline/UA modal preserved.
 *
 * @package LoginArmor
 *
 * @var string $active_tab
 * @var string $overview_nonce
 * @var string $admin_nonce
 * @var string $ajax_url
 */

// phpcs:disable WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use LoginArmor\Icons;

if ( ! function_exists( 'login_armor_incident_pattern_label' ) ) {
	/**
	 * Human, translatable label for an incident attack pattern (the raw value
	 * is a snake_case constant like `reserved_username_probe`).
	 */
	function login_armor_incident_pattern_label( string $pattern ): string {
		switch ( $pattern ) {
			case 'brute_force':             return __( 'Brute force', 'login-armor' );
			case 'credential_stuffing':     return __( 'Credential stuffing', 'login-armor' );
			case 'enumeration':             return __( 'Username enumeration', 'login-armor' );
			case 'distributed':             return __( 'Distributed attack', 'login-armor' );
			case 'post_compromise':         return __( 'Post-compromise activity', 'login-armor' );
			case 'reserved_username_probe': return __( 'Reserved-username probe', 'login-armor' );
			case 'bot_honeypot_caught':     return __( 'Bot caught (honeypot)', 'login-armor' );
			case '2fa_recovery_requested':  return __( '2FA recovery requested', 'login-armor' );
			case 'firewall_block':          return __( 'Request firewall', 'login-armor' );
			case 'pow_failed':              return __( 'Bot challenge failed', 'login-armor' );
			case 'app_password_refused':    return __( 'Application password refused', 'login-armor' );
			default:                        return ucwords( str_replace( '_', ' ', $pattern ) );
		}
	}
}

if ( ! function_exists( 'login_armor_incident_pattern_desc' ) ) {
	/**
	 * One-line, translatable explanation of what an attack pattern means,
	 * shown under the incident title so the type is self-explanatory.
	 */
	function login_armor_incident_pattern_desc( string $pattern ): string {
		switch ( $pattern ) {
			case 'brute_force':             return __( 'Many password guesses against a single account.', 'login-armor' );
			case 'credential_stuffing':     return __( 'Leaked username/password pairs replayed in bulk.', 'login-armor' );
			case 'enumeration':             return __( 'Probing to discover which usernames exist.', 'login-armor' );
			case 'distributed':             return __( 'The same attack spread across many IPs to slip under per-IP lockout.', 'login-armor' );
			case 'post_compromise':         return __( 'Suspicious activity right after a successful login.', 'login-armor' );
			case 'reserved_username_probe': return __( 'Login attempts on default/reserved accounts (admin, administrator…).', 'login-armor' );
			case 'bot_honeypot_caught':     return __( 'An automated bot filled the hidden honeypot field.', 'login-armor' );
			case '2fa_recovery_requested':  return __( 'A two-factor recovery or bypass was requested.', 'login-armor' );
			case 'firewall_block':          return __( 'A request matched a firewall rule (bad query string, path, method, agent or referrer).', 'login-armor' );
			case 'pow_failed':              return __( 'A login was submitted without solving the invisible proof-of-work challenge.', 'login-armor' );
			case 'app_password_refused':    return __( 'Repeated wrong application passwords for one account, usually a service whose password was revoked or changed.', 'login-armor' );
			default:                        return '';
		}
	}
}

// phpcs:disable WordPress.Security.NonceVerification.Recommended -- Read-only filter routing on GET.
$la_incident_id = isset( $_GET['incident'] ) ? (int) $_GET['incident'] : 0;
// 2.7.10: the list opens on the open incidents, and "All" is `status=all`.
// $la_status_choice is what the select shows and the links carry; $la_status
// is the status filter the list applies, '' for every state.
$la_status_choice = \LoginArmor\Detection\Incident::list_status_choice( isset( $_GET['status'] ) ? sanitize_key( wp_unslash( $_GET['status'] ) ) : '' );
$la_status        = 'all' === $la_status_choice ? '' : $la_status_choice;
$la_pattern     = isset( $_GET['pattern'] ) ? sanitize_key( wp_unslash( $_GET['pattern'] ) ) : '';
$la_severity    = isset( $_GET['severity'] ) ? (int) $_GET['severity'] : 0;
$la_period      = isset( $_GET['period'] ) ? sanitize_key( wp_unslash( $_GET['period'] ) ) : '';
$la_page_num    = isset( $_GET['paged'] ) ? max( 1, (int) $_GET['paged'] ) : 1;
// 2.7.1: include the severity 1 observations, which the list leaves out by
// default. Read here with the other filters rather than where it is used, so
// every GET the screen consumes goes through one sanitising block.
$la_show_obs    = isset( $_GET['obs'] ) && '1' === sanitize_key( wp_unslash( $_GET['obs'] ) );
// phpcs:enable WordPress.Security.NonceVerification.Recommended

// Severity int → CSS class bucket (spec: 1 low, 2 med, 3-4 high).
$la_sev_class_fn = static function ( int $sev ): string {
	if ( $sev >= 3 ) {
		return 'high';
	}
	if ( $sev >= 2 ) {
		return 'med';
	}
	return 'low';
};

$la_sev_label_fn = static function ( int $sev ): string {
	if ( $sev >= 4 ) {
		return __( 'Critical', 'login-armor' );
	}
	if ( $sev >= 3 ) {
		return __( 'High', 'login-armor' );
	}
	if ( $sev >= 2 ) {
		return __( 'Medium', 'login-armor' );
	}
	return __( 'Low', 'login-armor' );
};

// ===========================================================================
// Drill-down mode: Lot 18 V6 pixel-perfect rebuild.
// ===========================================================================

/**
 * Detect known bot / scripting user-agents for the timeline + UA card BOT pill.
 */
if ( ! function_exists( 'login_armor_is_bot_ua' ) ) {
	function login_armor_is_bot_ua( string $ua ): bool {
		if ( '' === $ua ) {
			return false;
		}
		return (bool) preg_match( '#(curl|wget|python-requests|python-urllib|Go-http-client|PHPUnit|scrapy|libwww-perl|java/|bot|crawler|spider)#i', $ua );
	}
}

/**
 * English-only duration formatter. We deliberately avoid human_time_diff()
 * here because it uses the WP site locale: on a French-configured site
 * that returned "2 secondes" / "1 heure" inside our otherwise-English
 * admin UI. Plugin i18n happens via Lot 19; until then, keep our own
 * strings in one language to avoid a mixed-locale surface.
 */
if ( ! function_exists( 'login_armor_format_duration_en' ) ) {
	function login_armor_format_duration_en( int $seconds ): string {
		$seconds = max( 0, $seconds );
		if ( $seconds < 60 ) {
			return 1 === $seconds ? '1 sec' : $seconds . ' sec';
		}
		if ( $seconds < 3600 ) {
			$m = (int) floor( $seconds / 60 );
			return 1 === $m ? '1 min' : $m . ' min';
		}
		if ( $seconds < 86400 ) {
			$h = (int) floor( $seconds / 3600 );
			return 1 === $h ? '1 hour' : $h . ' hours';
		}
		$d = (int) floor( $seconds / 86400 );
		return 1 === $d ? '1 day' : $d . ' days';
	}
}

/** Translatable compact relative-time helper: duplicated from activity.php
 * and events.php with a function_exists guard so any of the three tabs can
 * be rendered first without a redeclare error. */
if ( ! function_exists( 'login_armor_time_ago' ) ) {
	function login_armor_time_ago( string $utc_datetime ): string {
		$timestamp = strtotime( $utc_datetime . ' UTC' );
		if ( false === $timestamp || $timestamp <= 0 ) {
			return '';
		}
		$diff = max( 0, time() - $timestamp );
		if ( $diff < 60 ) {
			/* translators: %d: number of seconds, short compact form. */
			return sprintf( __( '%ds ago', 'login-armor' ), $diff );
		}
		if ( $diff < 3600 ) {
			/* translators: %d: number of minutes, short compact form. */
			return sprintf( __( '%dm ago', 'login-armor' ), (int) floor( $diff / 60 ) );
		}
		if ( $diff < 86400 ) {
			/* translators: %d: number of hours, short compact form. */
			return sprintf( __( '%dh ago', 'login-armor' ), (int) floor( $diff / 3600 ) );
		}
		if ( $diff < 604800 ) {
			/* translators: %d: number of days, short compact form. */
			return sprintf( __( '%dd ago', 'login-armor' ), (int) floor( $diff / 86400 ) );
		}
		if ( $diff < 2592000 ) {
			/* translators: %d: number of weeks, short compact form. */
			return sprintf( __( '%dw ago', 'login-armor' ), (int) floor( $diff / 604800 ) );
		}
		if ( $diff < 31536000 ) {
			/* translators: %d: number of months, short compact form. */
			return sprintf( __( '%dmo ago', 'login-armor' ), (int) floor( $diff / 2592000 ) );
		}
		/* translators: %d: number of years, short compact form. */
		return sprintf( __( '%dy ago', 'login-armor' ), (int) floor( $diff / 31536000 ) );
	}
}

/**
 * Decide whether a given log row matches the incident's classifier pattern.
 *
 * The timeline query pulls every event from the incident's IP in a ±5 min
 * window: so it can contain events that are merely correlated by IP but
 * didn't trigger the specific pattern (e.g. enumeration incidents contain
 * failures on existing users too). This helper flags each row so the UI
 * can surface "MATCH" vs "RELATED" and stop the pattern-scoped stats
 * (unique_usernames, events_count) from contradicting the raw timeline.
 */
if ( ! function_exists( 'login_armor_event_matches_incident' ) ) {
	function login_armor_event_matches_incident( object $event, object $incident ): bool {
		$pattern  = (string) ( $incident->pattern ?? '' );
		$status   = (string) ( $event->status ?? '' );
		$username = (string) ( $event->username ?? '' );
		$target   = (string) ( $incident->target_username ?? '' );

		switch ( $pattern ) {
			case 'enumeration':
				// Probing for NON-existent users.
				return '' !== $username && ! get_user_by( 'login', $username );
			case 'brute_force':
			case 'targeted':
			case 'distributed':
				// Hammering a specific real user.
				return 'failed' === $status && '' !== $target && $username === $target;
			case 'credential_stuffing':
				// Many unique usernames from one IP: every failed event contributes.
				return 'failed' === $status;
			case 'post_compromise':
				// Success preceded by failures: all events from IP relevant.
				return true;
			default:
				// Single-event patterns (honeypot, reserved username probe,
				// 2FA recovery) or unknown: don't demote anything.
				return true;
		}
	}
}

if ( $la_incident_id > 0 ) :
	$la_drill = \LoginArmor\Detection\Incident::find_by_id( $la_incident_id );
	if ( null === $la_drill ) {
		echo '<div class="la-empty-hint">' . esc_html__( 'Incident not found.', 'login-armor' ) . '</div>';
		return;
	}

	$la_events     = \LoginArmor\Detection\Incident::get_correlated_events( $la_incident_id );
	$la_event_count = count( $la_events );

	// Aggregated user-agent counts, most frequent first.
	$la_ua_counts = array();
	foreach ( $la_events as $la_ev ) {
		$la_ua = (string) ( $la_ev->user_agent ?? '' );
		if ( '' === $la_ua ) {
			continue;
		}
		if ( ! isset( $la_ua_counts[ $la_ua ] ) ) {
			$la_ua_counts[ $la_ua ] = 0;
		}
		$la_ua_counts[ $la_ua ]++;
	}
	arsort( $la_ua_counts );

	$la_back_url = add_query_arg( array( 'page' => 'login-armor', 'tab' => 'incidents' ), admin_url( 'admin.php' ) );

	$la_drill_block_status = \LoginArmor\LimitLogin::get_block_status( (string) $la_drill->ip );
	$la_drill_locked       = ! empty( $la_drill_block_status['locked'] );
	$la_drill_mins_left    = $la_drill_locked
		? max( 1, (int) ceil( ( (int) $la_drill_block_status['lockout_expires_sec'] ) / 60 ) )
		: 0;
	$la_drill_blocked_sub  = $la_drill_block_status['blocked_subnet'];

	// Pattern → explainer content (kept verbatim from the previous template).
	$la_pedagogy = array(
		'brute_force' => array(
			'title' => __( 'Brute force attack', 'login-armor' ),
			'desc'  => __( 'Same IP hammering one username with different passwords. Automated tools cycle through common passwords trying to guess yours.', 'login-armor' ),
			'todo'  => __( 'Change the targeted account\'s password immediately. Consider enabling Hide Login to conceal your login URL.', 'login-armor' ),
		),
		'credential_stuffing' => array(
			'title' => __( 'Credential stuffing', 'login-armor' ),
			'desc'  => __( 'Same IP trying many different usernames: likely using a leaked database of email/password pairs from other breached sites.', 'login-armor' ),
			'todo'  => __( 'Force a password reset for targeted users. Enable two-factor authentication when available.', 'login-armor' ),
		),
		'enumeration' => array(
			'title' => __( 'Username enumeration', 'login-armor' ),
			'desc'  => __( 'Probing for valid usernames before attempting passwords. Attackers confirm which accounts exist to target them later.', 'login-armor' ),
			'todo'  => __( 'Ensure "Mask login errors" and "Prevent author enumeration" are enabled in Hardening settings.', 'login-armor' ),
		),
		'distributed' => array(
			'title' => __( 'Distributed attack', 'login-armor' ),
			'desc'  => __( 'Multiple IPs targeting the same username: coordinated botnet or proxy network. Harder to block by IP alone.', 'login-armor' ),
			'todo'  => __( 'Block the subnet. Consider Cloudflare or CDN-level protection for additional filtering.', 'login-armor' ),
		),
		'post_compromise' => array(
			'title' => __( 'Post-compromise activity', 'login-armor' ),
			'desc'  => __( 'Successful login after many failures: possible compromised account. The attacker may have found valid credentials.', 'login-armor' ),
			'todo'  => __( 'Immediately reset the password. Check for unauthorized changes and review recent admin activity.', 'login-armor' ),
		),
		'targeted' => array(
			'title' => __( 'Targeted attack', 'login-armor' ),
			'desc'  => __( 'Focused attack on a high-privilege account (editor, admin). Attackers specifically chose this account for its permissions.', 'login-armor' ),
			'todo'  => __( 'Reset the password. Limit the number of admin accounts and use strong, unique passwords.', 'login-armor' ),
		),
		'reserved_username_probe' => array(
			'title' => __( 'Reserved username probe', 'login-armor' ),
			'desc'  => __( 'Login attempts using a username on the configured reserved-name blacklist. Often signals automated scanning for default accounts.', 'login-armor' ),
			'todo'  => __( 'Keep the Username Blacklist toggle enabled; review entries to match your deployment.', 'login-armor' ),
		),
		'bot_honeypot_caught' => array(
			'title' => __( 'Bot honeypot', 'login-armor' ),
			'desc'  => __( 'Automated bot detected via the login honeypot trap. Banned for 24 hours on first hit.', 'login-armor' ),
			'todo'  => __( 'No action required: the IP is already banned. Review source IPs if repeats occur.', 'login-armor' ),
		),
		'2fa_recovery_requested' => array(
			'title' => __( '2FA recovery requested', 'login-armor' ),
			'desc'  => __( 'A user requested a 2FA reset via the recovery flow. Informational, not a security incident per se, but surfaces coordinated abuse when multiple requests target the same account.', 'login-armor' ),
			'todo'  => __( 'Review recurring requests from the same IP. Confirm the admin only authorizes legitimate resets.', 'login-armor' ),
		),
		'firewall_block' => array(
			'title' => __( 'Request firewall', 'login-armor' ),
			'desc'  => __( 'A request matched the 8G-inspired request firewall: a malicious query string, path, HTTP method, user agent or referrer. Repeated hits from one IP are aggregated into this single incident.', 'login-armor' ),
			'todo'  => __( 'In monitor mode this was logged, not blocked: review the matches, then switch the firewall to enforce. If a legitimate request was matched, add its IP or path to the firewall allowlist.', 'login-armor' ),
		),
		'pow_failed' => array(
			'title' => __( 'Bot challenge failed', 'login-armor' ),
			'desc'  => __( 'A login was submitted without a valid proof-of-work: the invisible computation every real browser solves automatically. Almost always an automated client (bot, script) posting credentials directly. Repeated hits from one IP are aggregated into this single incident.', 'login-armor' ),
			'todo'  => __( 'Nothing to do for bots: the challenge is doing its job. If a real user reports being blocked, check that their browser runs JavaScript, or temporarily switch the bot challenge back to monitor mode.', 'login-armor' ),
		),
		'app_password_refused' => array(
			'title' => __( 'Application password refused', 'login-armor' ),
			'desc'  => __( 'One address sent at least five wrong application passwords for the same account in ten minutes. An application password is 24 random characters and WordPress never accepts the account password in its place, so this is rarely a guess: most often a script, a connector or a front end still uses a password that was revoked or changed. These failures do not lock the address.', 'login-armor' ),
			'todo'  => __( 'Find the service that calls from this address and give it a valid application password, one per service. If no service of yours runs there, revoke the account\'s application passwords from its profile.', 'login-armor' ),
		),
	);

	// Window between first-seen and last-seen. Formatted with unit (sec/min/hours/days)
	// so 2-second windows never render as "0 min" (rounded-to-zero UX bug).
	$la_window_seconds = max( 0, strtotime( (string) $la_drill->last_seen_at ) - strtotime( (string) $la_drill->started_at ) );
	$la_window_label   = login_armor_format_duration_en( $la_window_seconds );

	// Hero classes + short mono title (e.g. "BRUTE FORCE").
	$la_hero_status = ( 'resolved' === $la_drill->status ) ? 'resolved' : 'open';
	$la_sev_class   = $la_sev_class_fn( (int) $la_drill->severity );
	$la_sev_label   = $la_sev_label_fn( (int) $la_drill->severity );
	$la_short_title = login_armor_incident_pattern_label( (string) $la_drill->pattern );

	// --- Suggested actions: computed from pattern + current module state.
	$la_actions       = array();
	$la_settings_url  = add_query_arg( array( 'page' => 'login-armor', 'tab' => 'settings' ), admin_url( 'admin.php' ) );

	if ( in_array( $la_drill->pattern, array( 'brute_force', 'credential_stuffing', 'targeted', 'post_compromise' ), true ) && '' !== $la_drill->target_username ) {
		$la_actions[] = array(
			'icon'     => 'key',
			'title'    => __( 'Reset password', 'login-armor' ),
			/* translators: %s: username */
			'desc'     => sprintf( __( 'Force "%s" to pick a new password.', 'login-armor' ), $la_drill->target_username ),
			'cta'      => 'ghost',
			'cta_url'  => admin_url( 'users.php' ),
			'cta_text' => __( 'Reset password →', 'login-armor' ),
		);
	}

	$la_2fa_enabled = (bool) get_option( 'login_armor_2fa_enabled', false );
	if ( ! $la_2fa_enabled ) {
		$la_actions[] = array(
			'icon'     => 'unlock',
			'title'    => __( 'Enable Two-Factor Authentication', 'login-armor' ),
			'desc'     => __( 'Biggest single lift against credential attacks.', 'login-armor' ),
			'cta'      => 'primary',
			'cta_url'  => $la_settings_url . '#two-factor-settings',
			'cta_text' => __( 'Enable 2FA →', 'login-armor' ),
		);
	} else {
		$la_actions[] = array(
			'icon'  => 'unlock',
			'title' => __( 'Two-Factor Authentication', 'login-armor' ),
			'desc'  => __( 'Already enabled on this site.', 'login-armor' ),
			'done'  => true,
		);
	}

	$la_hide_enabled = class_exists( '\LoginArmor\HideLogin' ) && \LoginArmor\HideLogin::is_enabled();
	if ( ! $la_hide_enabled ) {
		$la_actions[] = array(
			'icon'     => 'shield',
			'title'    => __( 'Hide your login URL', 'login-armor' ),
			'desc'     => __( 'Most brute-force tools target /wp-login.php.', 'login-armor' ),
			'cta'      => 'ghost',
			'cta_url'  => $la_settings_url . '#hide-login',
			'cta_text' => __( 'Enable →', 'login-armor' ),
		);
	}

	// 2.8.0: not offered for the administrator's own network, which the
	// server now refuses to block (see LimitLogin::would_lock_out_current_user()).
	if ( '' !== $la_drill->ip && filter_var( $la_drill->ip, FILTER_VALIDATE_IP ) && ! \LoginArmor\LimitLogin::would_lock_out_current_user( $la_drill->ip ) ) {
		$la_subnet_display = '' !== $la_drill->subnet ? $la_drill->subnet : $la_drill->ip . '/24';
		$la_actions[] = array(
			'icon'       => 'circle-slash',
			'title'      => __( 'Block subnet', 'login-armor' ),
			/* translators: %s: CIDR subnet */
			'desc'       => sprintf( __( 'Blacklist %s and all siblings.', 'login-armor' ), $la_subnet_display ),
			'cta'        => 'ghost',
			'cta_action' => 'subnet-block',
			'cta_data'   => $la_drill->ip,
			/* translators: %s: CIDR subnet */
			'cta_text'   => sprintf( __( 'Block %s', 'login-armor' ), $la_subnet_display ),
		);
	}
	?>

	<a class="la-incident-back" href="<?php echo esc_url( $la_back_url ); ?>">
		<span class="la-incident-back__arrow" aria-hidden="true">&larr;</span>
		<?php esc_html_e( 'Back to incidents', 'login-armor' ); ?>
	</a>

	<section class="la-inc-hero la-inc-hero--<?php echo esc_attr( $la_hero_status ); ?>">
		<div class="la-inc-hero__top">
			<div class="la-inc-hero__title-row">
				<span class="la-pill la-pill--<?php echo esc_attr( $la_sev_class ); ?>"><?php echo esc_html( strtoupper( $la_sev_label ) ); ?></span>
				<h2 class="la-inc-hero__title la-mono"><?php echo esc_html( $la_short_title ); ?></h2>
			</div>
			<?php if ( 'resolved' === $la_drill->status ) : ?>
				<span class="la-pill la-pill--resolved"><?php esc_html_e( 'Resolved', 'login-armor' ); ?></span>
			<?php elseif ( 'ignored' === $la_drill->status ) : ?>
				<span class="la-pill la-pill--neutral"><?php esc_html_e( 'Ignored', 'login-armor' ); ?></span>
			<?php else : ?>
				<span class="la-pill la-pill--warn"><?php esc_html_e( 'Open', 'login-armor' ); ?></span>
			<?php endif; ?>
		</div>

		<dl class="la-inc-hero__metrics">
			<div>
				<dt><?php esc_html_e( 'Attempts', 'login-armor' ); ?></dt>
				<dd><?php echo esc_html( (string) $la_drill->events_count ); ?></dd>
			</div>
			<div>
				<dt><?php esc_html_e( 'Unique IPs', 'login-armor' ); ?></dt>
				<dd><?php echo esc_html( (string) $la_drill->unique_ips ); ?></dd>
			</div>
			<div>
				<dt><?php esc_html_e( 'Usernames', 'login-armor' ); ?></dt>
				<dd><?php echo esc_html( (string) $la_drill->unique_usernames ); ?></dd>
			</div>
			<div>
				<dt><?php esc_html_e( 'Window', 'login-armor' ); ?></dt>
				<dd><?php echo esc_html( $la_window_label ); ?></dd>
			</div>
		</dl>

		<dl class="la-inc-hero__tech">
			<div>
				<dt><?php esc_html_e( 'Source IP', 'login-armor' ); ?></dt>
				<dd class="la-mono"><?php
					echo esc_html( '' !== $la_drill->ip ? $la_drill->ip : '-' );
					if ( '' !== $la_drill->ip && class_exists( '\LoginArmor\GeoIP' ) ) {
						echo ' ' . wp_kses( \LoginArmor\GeoIP::badge_html( (string) $la_drill->ip ), [ 'span' => [ 'class' => [], 'title' => [] ] ] );
					}
				?></dd>
				<?php if ( $la_drill_locked || null !== $la_drill_blocked_sub ) : ?>
					<div class="la-inc-drill__block-row">
						<?php if ( $la_drill_locked ) :
							$la_drill_level = \LoginArmor\LimitLogin::get_lockout_level( (string) $la_drill->ip );
							if ( $la_drill_level >= 2 ) : ?>
								<span class="la-pill la-pill--blacklist">
									<?php esc_html_e( 'Blacklist 24h', 'login-armor' ); ?>
								</span>
							<?php else : ?>
								<span class="la-pill la-pill--locked">
									<?php
									echo esc_html(
										sprintf(
											/* translators: %d: minutes remaining in the current IP lockout. */
											_n( '%d min', '%d min', $la_drill_mins_left, 'login-armor' ),
											$la_drill_mins_left
										)
									);
									?>
									<span class="la-pill__suffix"><?php esc_html_e( 'Auth blocked', 'login-armor' ); ?></span>
								</span>
							<?php endif; ?>
						<?php endif; ?>
						<?php if ( null !== $la_drill_blocked_sub ) : ?>
							<span class="la-pill la-pill--blocked">
								<?php esc_html_e( 'Subnet blocked', 'login-armor' ); ?>
								<span class="la-pill__suffix la-mono"><?php echo esc_html( $la_drill_blocked_sub ); ?></span>
							</span>
						<?php endif; ?>
					</div>
				<?php endif; ?>
			</div>
			<div>
				<dt><?php esc_html_e( 'Target user', 'login-armor' ); ?></dt>
				<dd class="la-mono"><?php echo esc_html( '' !== $la_drill->target_username ? $la_drill->target_username : '-' ); ?></dd>
			</div>
			<div>
				<dt><?php esc_html_e( 'First seen', 'login-armor' ); ?></dt>
				<dd class="la-mono"><?php echo esc_html( (string) $la_drill->started_at ); ?></dd>
			</div>
			<div>
				<dt><?php esc_html_e( 'Last seen', 'login-armor' ); ?></dt>
				<dd class="la-mono"><?php echo esc_html( (string) $la_drill->last_seen_at ); ?></dd>
			</div>
		</dl>

		<div class="la-inc-hero__actions">
			<?php if ( '' !== $la_drill->ip && filter_var( $la_drill->ip, FILTER_VALIDATE_IP ) ) : ?>
				<?php if ( null === $la_drill_blocked_sub && \LoginArmor\LimitLogin::would_lock_out_current_user( $la_drill->ip ) ) : ?>
					<span class="la-own-network"><?php esc_html_e( 'This network contains your own address: it cannot be blocked from here.', 'login-armor' ); ?></span>
				<?php elseif ( null === $la_drill_blocked_sub ) : ?>
					<button type="button" class="la-primary-btn"
						data-la-action="subnet-block"
						data-la-ip="<?php echo esc_attr( $la_drill->ip ); ?>">
						<?php Icons::render( 'lock', '', 12 );?>
						<?php esc_html_e( 'Block subnet', 'login-armor' ); ?>
					</button>
				<?php else : ?>
					<button type="button" class="la-primary-btn"
						data-la-action="subnet-unblock"
						data-la-ip="<?php echo esc_attr( $la_drill->ip ); ?>">
						<?php esc_html_e( 'Remove from blocklist', 'login-armor' ); ?>
					</button>
				<?php endif; ?>
				<?php if ( $la_drill_locked ) : ?>
					<button type="button" class="la-ghost-btn" data-la-action="ip-unblock" data-la-ip="<?php echo esc_attr( $la_drill->ip ); ?>">
						<?php esc_html_e( 'Unblock IP', 'login-armor' ); ?>
					</button>
				<?php endif; ?>
			<?php endif; ?>
			<?php if ( 'resolved' !== $la_drill->status && 'ignored' !== $la_drill->status ) : ?>
				<button type="button" class="la-ghost-btn" data-la-action="resolve" data-la-id="<?php echo esc_attr( (string) $la_drill->id ); ?>">
					<?php esc_html_e( 'Mark resolved', 'login-armor' ); ?>
				</button>
			<?php endif; ?>
		</div>
	</section>

	<?php
	// On-demand AI threat analysis for this incident (renders nothing when no
	// native AI connector is available). The incident object goes with the id
	// so the panel can show an analysis already stored on the row instead of
	// offering to generate it a second time.
	$la_ai_context     = 'incident';
	$la_ai_incident_id = (int) $la_drill->id;
	$la_ai_incident    = $la_drill;
	include LOGIN_ARMOR_DIR . 'admin/views/sections/ai-panel.php';
	?>

	<?php if ( isset( $la_pedagogy[ $la_drill->pattern ] ) ) :
		$la_ped = $la_pedagogy[ $la_drill->pattern ]; ?>
		<div class="la-inc-explainer">
			<div class="la-inc-explainer__icon">
				<?php Icons::render( 'alert-triangle', '', 18 );?>
			</div>
			<div class="la-inc-explainer__body">
				<h4 class="la-inc-explainer__title">
					<?php
					/* translators: %s: pattern explainer title */
					printf( esc_html__( 'What happened: %s', 'login-armor' ), esc_html( $la_ped['title'] ) );
					?>
				</h4>
				<p><?php echo esc_html( $la_ped['desc'] ); ?></p>
				<p><strong><?php esc_html_e( 'What to do:', 'login-armor' ); ?></strong> <?php echo esc_html( $la_ped['todo'] ); ?></p>
			</div>
		</div>
	<?php endif; ?>

	<?php
	// Pre-compute which timeline rows match this incident's pattern. Only
	// render MATCH/RELATED badges when there's actually a mix: avoids
	// noise on single-pattern incidents.
	$la_ev_matches    = array();
	$la_matched_count = 0;
	foreach ( $la_events as $la_i => $la_ev ) {
		$la_ev_matches[ $la_i ] = login_armor_event_matches_incident( $la_ev, $la_drill );
		if ( $la_ev_matches[ $la_i ] ) {
			++$la_matched_count;
		}
	}
	$la_related_count = $la_event_count - $la_matched_count;
	$la_show_badges   = $la_related_count > 0 && $la_matched_count > 0;
	?>

	<div class="la-inc-section-head">
		<h3>
			<?php esc_html_e( 'Timeline', 'login-armor' ); ?>
			<?php if ( $la_show_badges ) : ?>
				<span class="la-pill la-pill--neutral">
					<?php
					echo esc_html(
						sprintf(
							/* translators: 1: matched count, 2: related count */
							__( '%1$d matched · %2$d related', 'login-armor' ),
							$la_matched_count,
							$la_related_count
						)
					);
					?>
				</span>
			<?php else : ?>
				<span class="la-pill la-pill--neutral">
					<?php
					echo esc_html(
						sprintf(
							/* translators: %d: event count */
							_n( '%d event', '%d events', $la_event_count, 'login-armor' ),
							$la_event_count
						)
					);
					?>
				</span>
			<?php endif; ?>
		</h3>
		<?php if ( $la_show_badges ) : ?>
			<p class="la-inc-section-subhint">
				<?php
				esc_html_e(
					'Matched events triggered this incident\'s pattern. Related events come from the same IP but are shown for context: they did not trigger the pattern.',
					'login-armor'
				);
				?>
			</p>
		<?php endif; ?>
	</div>

	<?php if ( $la_event_count > 0 ) : ?>
		<div class="la-inc-timeline-card <?php echo $la_show_badges ? 'la-inc-timeline-card--with-match' : ''; ?>">
			<?php foreach ( $la_events as $la_i => $la_ev ) :
				$la_ev_matched = ! empty( $la_ev_matches[ $la_i ] );
				$la_ev_ok       = ( 'success' === $la_ev->status );
				$la_ev_time     = (string) $la_ev->log_time;
				$la_ev_ts       = strtotime( $la_ev_time );
				$la_ev_hhmm     = mysql2date( 'H:i:s', $la_ev_time );
				$la_ev_date     = mysql2date( 'M j', $la_ev_time, true );
				$la_ev_ago      = login_armor_time_ago( $la_ev_time );
				$la_ev_ua_full  = (string) ( $la_ev->user_agent ?? '' );
				$la_ev_ua_short = function_exists( 'la_short_ua' )
					? la_short_ua( $la_ev_ua_full )
					: mb_substr( $la_ev_ua_full, 0, 24 );

				if ( $la_ev_ok ) {
					$la_ev_reason = __( 'Successful sign-in', 'login-armor' );
					$la_dot_cls   = 'la-inc-timeline__dot--ok';
					$la_badge_cls = 'la-badge--ok';
					$la_badge_txt = __( 'OK', 'login-armor' );
				} elseif ( 'locked' === $la_ev->status ) {
					$la_ev_reason = __( 'Auth blocked', 'login-armor' );
					$la_dot_cls   = 'la-inc-timeline__dot--lock';
					$la_badge_cls = 'la-badge--lock';
					$la_badge_txt = __( 'BLOCKED', 'login-armor' );
				} else {
					// V2.4.5: show the real error code recorded on the row, so a
					// 2FA lockout is not read as a password guess during triage.
					$la_ev_reason = \LoginArmor\LoginLogs::failure_reason_label(
						isset( $la_ev->reason ) ? (string) $la_ev->reason : ''
					);
					$la_dot_cls   = 'la-inc-timeline__dot--fail';
					$la_badge_cls = 'la-badge--fail';
					$la_badge_txt = __( 'FAIL', 'login-armor' );
				}

				$la_row_cls = array( $la_dot_cls );
				if ( 0 === $la_i ) {
					$la_row_cls[] = 'is-first';
				}
				if ( $la_i === $la_event_count - 1 ) {
					$la_row_cls[] = 'is-last';
				}
				if ( $la_show_badges && ! $la_ev_matched ) {
					$la_row_cls[] = 'la-inc-timeline__row--related';
				}
				?>
				<div class="la-inc-timeline__row <?php echo esc_attr( implode( ' ', $la_row_cls ) ); ?>">
					<span class="la-inc-timeline__time">
						<span class="la-mono"><?php echo esc_html( $la_ev_hhmm ); ?></span>
						<small><?php echo esc_html( $la_ev_date . ' · ' . $la_ev_ago ); ?></small>
					</span>
					<span class="la-badge <?php echo esc_attr( $la_badge_cls ); ?>"><?php echo esc_html( $la_badge_txt ); ?></span>
					<?php if ( $la_show_badges ) : ?>
						<span class="la-inc-timeline__match <?php echo $la_ev_matched ? 'la-inc-timeline__match--yes' : 'la-inc-timeline__match--no'; ?>"
							title="<?php echo esc_attr( $la_ev_matched ? __( 'This event triggered the incident\'s pattern.', 'login-armor' ) : __( 'Correlated by IP; did not trigger the pattern.', 'login-armor' ) ); ?>">
							<?php echo $la_ev_matched ? esc_html__( 'MATCH', 'login-armor' ) : esc_html__( 'RELATED', 'login-armor' ); ?>
						</span>
					<?php endif; ?>
					<span class="la-inc-timeline__ip">
						<?php Icons::render( 'globe', '', 12 );?>
						<span class="la-mono"><?php echo esc_html( (string) $la_ev->ip ); ?></span>
					</span>
					<span class="la-inc-timeline__detail">
						<b><?php echo esc_html( '' !== $la_ev->username ? (string) $la_ev->username : '-' ); ?></b>
						<small><?php echo esc_html( $la_ev_reason . ( '' !== $la_ev_ua_short ? ' · ' . $la_ev_ua_short : '' ) ); ?></small>
					</span>
					<span class="la-inc-timeline__meta la-mono">
						<?php
						/* translators: 1: current attempt number, 2: total attempt count */
						printf( esc_html__( '%1$d/%2$d attempt', 'login-armor' ), (int) ( $la_i + 1 ), (int) $la_event_count );
						?>
					</span>
				</div>
			<?php endforeach; ?>
		</div>
	<?php else : ?>
		<div class="la-empty-hint"><?php esc_html_e( 'No correlated events found.', 'login-armor' ); ?></div>
	<?php endif; ?>

	<?php if ( ! empty( $la_ua_counts ) ) :
		$la_ua_distinct = count( $la_ua_counts ); ?>
		<div class="la-inc-section-head">
			<h3>
				<?php esc_html_e( 'User agents observed', 'login-armor' ); ?>
				<span class="la-pill la-pill--neutral">
					<?php
					echo esc_html(
						sprintf(
							/* translators: %d: UA count */
							_n( '%d UA', '%d UAs', $la_ua_distinct, 'login-armor' ),
							$la_ua_distinct
						)
					);
					?>
				</span>
			</h3>
		</div>
		<div class="la-inc-ua-card">
			<?php foreach ( $la_ua_counts as $la_ua_str => $la_ua_count_n ) :
				$la_is_bot = login_armor_is_bot_ua( (string) $la_ua_str );
				?>
				<div class="la-inc-ua-card__row">
					<span class="la-inc-ua-card__icon">
						<?php Icons::render( 'monitor', '', 14 );?>
					</span>
					<span class="la-inc-ua-card__ua la-mono">
						<?php echo esc_html( (string) $la_ua_str ); ?>
						<?php if ( $la_is_bot ) : ?>
							<span class="la-pill la-pill--fail"><?php esc_html_e( 'BOT', 'login-armor' ); ?></span>
						<?php endif; ?>
					</span>
					<span class="la-inc-ua-card__count la-mono">
						<?php
						/* translators: %d: number of requests for this UA */
						printf( esc_html( _n( '%d request', '%d requests', (int) $la_ua_count_n, 'login-armor' ) ), (int) $la_ua_count_n );
						?>
					</span>
				</div>
			<?php endforeach; ?>
		</div>
	<?php endif; ?>

	<?php if ( ! empty( $la_actions ) ) : ?>
		<div class="la-inc-section-head">
			<h3><?php esc_html_e( 'Suggested actions', 'login-armor' ); ?></h3>
		</div>
		<div class="la-inc-actions-card">
			<?php foreach ( $la_actions as $la_a ) :
				$la_is_done = ! empty( $la_a['done'] );
				?>
				<div class="la-inc-action-row<?php echo $la_is_done ? ' la-inc-action-row--done' : ''; ?>">
					<span class="la-inc-action__icon<?php echo $la_is_done ? ' la-inc-action__icon--done' : ''; ?>">
						<?php Icons::render( $la_is_done ? 'check' : $la_a['icon'], '', 16 );?>
					</span>
					<span class="la-inc-action__text">
						<b><?php echo esc_html( $la_a['title'] ); ?></b>
						<small><?php echo esc_html( $la_a['desc'] ); ?></small>
					</span>
					<?php if ( $la_is_done ) : ?>
						<span class="la-pill la-pill--resolved"><?php esc_html_e( 'Done', 'login-armor' ); ?></span>
					<?php elseif ( ! empty( $la_a['cta_action'] ) ) : ?>
						<button type="button" class="la-<?php echo esc_attr( $la_a['cta'] ); ?>-btn"
							data-la-action="<?php echo esc_attr( $la_a['cta_action'] ); ?>"
							data-la-ip="<?php echo esc_attr( $la_a['cta_data'] ?? '' ); ?>">
							<?php echo esc_html( $la_a['cta_text'] ); ?>
						</button>
					<?php elseif ( ! empty( $la_a['cta_url'] ) ) : ?>
						<a class="la-<?php echo esc_attr( $la_a['cta'] ); ?>-btn" href="<?php echo esc_url( $la_a['cta_url'] ); ?>">
							<?php echo esc_html( $la_a['cta_text'] ); ?>
						</a>
					<?php endif; ?>
				</div>
			<?php endforeach; ?>
		</div>
	<?php endif; ?>

	<?php
	return;
endif;

// ===========================================================================
// List mode: Lot 18 pixel-perfect.
// ===========================================================================
$la_per_page = 25;

/*
 * Severity 1 is the bottom of a four-level scale, and it means "recorded",
 * not "act". The request firewall in monitor mode records one per scanner
 * probe, so a site that had simply been left alone for a while opened this
 * tab on 235 of them, in red, under a heading that said they deserved
 * attention. That is the defect: not the rows, the arithmetic and the words.
 *
 * So the list defaults to severity 2 and above, and the observations are one
 * tick away. Nothing is hidden and nothing is deleted: `obs=1` brings them
 * back, and choosing "Low" in the severity filter reaches them directly,
 * because an exact severity is more specific than the floor (build_where()).
 */
$la_obs_shown  = $la_show_obs || 1 === $la_severity;
$la_filters    = \LoginArmor\Detection\Incident::sanitize_filters(
	array(
		'status'       => $la_status,
		'pattern'      => $la_pattern,
		'severity'     => $la_severity,
		'min_severity' => $la_obs_shown ? 0 : \LoginArmor\Detection\Incident::SEVERITY_MEDIUM,
		'period'       => $la_period,
	)
);

// "Matching your filter" only when the administrator chose one (2.7.9). The
// list hides the observations by default, and the header called that default
// a filter of theirs: "4 matching your filter" on a page where nothing was
// chosen. Since 2.7.10 it also opens on the open incidents, and that is the
// default too, as is "All": neither narrows what the administrator asked for.
// Read from what the list applies, not from the URL: a value the list ignores
// filters nothing.
$la_user_filtered = isset( $la_filters['pattern'] ) || isset( $la_filters['severity'] ) || isset( $la_filters['period'] )
	|| in_array( $la_status_choice, array( \LoginArmor\Detection\Incident::STATUS_RESOLVED, \LoginArmor\Detection\Incident::STATUS_IGNORED ), true );

$la_total  = \LoginArmor\Detection\Incident::count_filtered( $la_filters );
$la_offset = ( $la_page_num - 1 ) * $la_per_page;
$la_rows   = \LoginArmor\Detection\Incident::get_filtered( $la_filters, $la_per_page, $la_offset );
$la_pages  = max( 1, (int) ceil( $la_total / $la_per_page ) );

// Sum-strip metrics (overall, independent of filter state so the strip always
// shows the "big picture"). Scoped to last 30 days for momentum.
$la_sum_summary      = \LoginArmor\Detection\Incident::get_active_summary();
$la_sum_open         = (int) $la_sum_summary['attention'];
$la_sum_observations = (int) $la_sum_summary['observations'];
$la_sum_resolved     = \LoginArmor\Detection\Incident::count_filtered( array( 'status' => 'resolved', 'period' => '30d' ) );
// Unique IPs over the last 30 days, counted by the database. It used to pull
// 500 whole rows and count them in PHP, which made the figure a sample rather
// than a count, and since 2.7.1 a row carries its AI analysis, so `SELECT *`
// at that volume would drag the analysis text along for nothing.
$la_sum_unique_ips   = \LoginArmor\Detection\Incident::count_distinct_ips( array( 'period' => '30d' ) );

$la_base_url = add_query_arg( array( 'page' => 'login-armor', 'tab' => 'incidents' ), admin_url( 'admin.php' ) );

// The same filter the list is showing, as the URL that reproduces it: the
// observations line and the "select everything matching" action both have to
// lead exactly where the administrator is already looking.
$la_obs_url = add_query_arg(
	array_filter(
		array(
			'page'     => 'login-armor',
			'tab'      => 'incidents',
			'status'   => 'active',
			'severity' => 1,
			'period'   => $la_period,
		),
		static fn( $v ) => '' !== $v && null !== $v
	),
	admin_url( 'admin.php' )
);
?>

<div class="la-page-header">
	<div>
		<span class="la-kicker"><?php esc_html_e( 'Incidents', 'login-armor' ); ?></span>
		<h2>
			<?php esc_html_e( 'Detected patterns', 'login-armor' ); ?>
			<span class="la-count">
				<?php
				if ( $la_user_filtered ) {
					$la_count_text =
						/* translators: %s: number of incidents matching the current filter. */
						__( '%s matching your filter', 'login-armor' );
				} elseif ( \LoginArmor\Detection\Incident::STATUS_ACTIVE === $la_status_choice && $la_obs_shown ) {
					$la_count_text =
						/* translators: %s: number of open incidents, observations included. */
						_n( '%s open incident, observations included', '%s open incidents, observations included', $la_total, 'login-armor' );
				} elseif ( \LoginArmor\Detection\Incident::STATUS_ACTIVE === $la_status_choice ) {
					$la_count_text =
						/* translators: %s: number of open incidents of severity Medium and above. */
						_n( '%s open incident', '%s open incidents', $la_total, 'login-armor' );
				} elseif ( $la_obs_shown ) {
					$la_count_text =
						/* translators: %s: number of incidents, observations included. */
						_n( '%s incident', '%s incidents', $la_total, 'login-armor' );
				} else {
					$la_count_text =
						/* translators: %s: number of incidents of severity Medium and above; the observations (severity Low) are hidden and not counted. */
						_n( '%s incident, observations excluded', '%s incidents, observations excluded', $la_total, 'login-armor' );
				}
				echo wp_kses_post( sprintf( esc_html( $la_count_text ), '<b>' . esc_html( number_format_i18n( $la_total ) ) . '</b>' ) );
				?>
			</span>
		</h2>
		<p class="la-lead"><?php esc_html_e( 'Grouped signals: multiple failed attempts, suspicious IPs, repeated brute-force. One row per pattern, not per event.', 'login-armor' ); ?></p>
	</div>
	<div class="la-page-header__actions">
		<button type="button" class="la-ghost-btn"
			data-la-action="events-export"
			data-la-status="<?php echo esc_attr( $la_status ); ?>"
			data-la-period="<?php echo esc_attr( $la_period ); ?>">
			<?php Icons::render( 'download', '', 12 );?>
			<?php esc_html_e( 'Export', 'login-armor' ); ?>
		</button>
	</div>
</div>

<div class="la-sum-strip">
	<?php
	// "Open" is the headline number, so it must mean what the word says: rows
	// that ask something of the administrator, severity 2 and above. The
	// observations get the box next door, in plain type, because they are a
	// record of what was seen, not a queue of work.
	?>
	<div class="la-sum-box <?php echo $la_sum_open > 0 ? 'la-sum-box--red' : 'la-sum-box--green'; ?>">
		<b><?php echo esc_html( number_format_i18n( $la_sum_open ) ); ?></b>
		<span><?php esc_html_e( 'Open', 'login-armor' ); ?></span>
	</div>
	<a class="la-sum-box la-sum-box--quiet" href="<?php echo esc_url( $la_obs_url ); ?>"
		title="<?php esc_attr_e( 'Lowest level of the scale: recorded and kept, nothing to do. Mostly a firewall or bot challenge in monitor mode noting internet background noise.', 'login-armor' ); ?>">
		<b><?php echo esc_html( number_format_i18n( $la_sum_observations ) ); ?></b>
		<span><?php esc_html_e( 'Observations', 'login-armor' ); ?></span>
	</a>
	<div class="la-sum-box la-sum-box--green">
		<b><?php echo esc_html( number_format_i18n( $la_sum_resolved ) ); ?></b>
		<span><?php esc_html_e( 'Resolved (30d)', 'login-armor' ); ?></span>
	</div>
	<div class="la-sum-box">
		<b><?php echo esc_html( number_format_i18n( $la_sum_unique_ips ) ); ?></b>
		<span><?php esc_html_e( 'Unique IPs (30d)', 'login-armor' ); ?></span>
	</div>
</div>

<div class="la-page-grid">
	<div>
		<form method="get" class="la-filter-bar">
			<input type="hidden" name="page" value="login-armor">
			<input type="hidden" name="tab" value="incidents">

			<div class="la-fb-field">
				<label for="la-inc-status"><?php esc_html_e( 'Status', 'login-armor' ); ?></label>
				<select id="la-inc-status" name="status">
					<option value="active" <?php selected( $la_status_choice, 'active' ); ?>><?php esc_html_e( 'Open', 'login-armor' ); ?></option>
					<option value="all" <?php selected( $la_status_choice, 'all' ); ?>><?php esc_html_e( 'All', 'login-armor' ); ?></option>
					<option value="resolved" <?php selected( $la_status_choice, 'resolved' ); ?>><?php esc_html_e( 'Resolved', 'login-armor' ); ?></option>
					<option value="ignored" <?php selected( $la_status_choice, 'ignored' ); ?>><?php esc_html_e( 'Ignored', 'login-armor' ); ?></option>
				</select>
			</div>

			<div class="la-fb-field">
				<label for="la-inc-pattern"><?php esc_html_e( 'Pattern', 'login-armor' ); ?></label>
				<select id="la-inc-pattern" name="pattern">
					<option value="" <?php selected( $la_pattern, '' ); ?>><?php esc_html_e( 'All', 'login-armor' ); ?></option>
					<option value="brute_force" <?php selected( $la_pattern, 'brute_force' ); ?>><?php esc_html_e( 'Brute force', 'login-armor' ); ?></option>
					<option value="credential_stuffing" <?php selected( $la_pattern, 'credential_stuffing' ); ?>><?php esc_html_e( 'Credential stuffing', 'login-armor' ); ?></option>
					<option value="enumeration" <?php selected( $la_pattern, 'enumeration' ); ?>><?php esc_html_e( 'Enumeration', 'login-armor' ); ?></option>
					<option value="distributed" <?php selected( $la_pattern, 'distributed' ); ?>><?php esc_html_e( 'Distributed', 'login-armor' ); ?></option>
					<option value="post_compromise" <?php selected( $la_pattern, 'post_compromise' ); ?>><?php esc_html_e( 'Post compromise', 'login-armor' ); ?></option>
					<option value="reserved_username_probe" <?php selected( $la_pattern, 'reserved_username_probe' ); ?>><?php esc_html_e( 'Reserved username probe', 'login-armor' ); ?></option>
					<option value="bot_honeypot_caught" <?php selected( $la_pattern, 'bot_honeypot_caught' ); ?>><?php esc_html_e( 'Bot honeypot', 'login-armor' ); ?></option>
					<option value="2fa_recovery_requested" <?php selected( $la_pattern, '2fa_recovery_requested' ); ?>><?php esc_html_e( '2FA recovery requested', 'login-armor' ); ?></option>
					<option value="firewall_block" <?php selected( $la_pattern, 'firewall_block' ); ?>><?php esc_html_e( 'Request firewall', 'login-armor' ); ?></option>
					<option value="pow_failed" <?php selected( $la_pattern, 'pow_failed' ); ?>><?php esc_html_e( 'Bot challenge failed', 'login-armor' ); ?></option>
					<option value="app_password_refused" <?php selected( $la_pattern, 'app_password_refused' ); ?>><?php esc_html_e( 'Application password refused', 'login-armor' ); ?></option>
				</select>
			</div>

			<div class="la-fb-field">
				<label for="la-inc-severity"><?php esc_html_e( 'Severity', 'login-armor' ); ?></label>
				<select id="la-inc-severity" name="severity">
					<option value="0" <?php selected( $la_severity, 0 ); ?>><?php esc_html_e( 'All', 'login-armor' ); ?></option>
					<option value="4" <?php selected( $la_severity, 4 ); ?>><?php esc_html_e( 'Critical', 'login-armor' ); ?></option>
					<option value="3" <?php selected( $la_severity, 3 ); ?>><?php esc_html_e( 'High', 'login-armor' ); ?></option>
					<option value="2" <?php selected( $la_severity, 2 ); ?>><?php esc_html_e( 'Medium', 'login-armor' ); ?></option>
					<option value="1" <?php selected( $la_severity, 1 ); ?>><?php esc_html_e( 'Low', 'login-armor' ); ?></option>
				</select>
			</div>

			<div class="la-fb-field">
				<label for="la-inc-period"><?php esc_html_e( 'Period', 'login-armor' ); ?></label>
				<select id="la-inc-period" name="period">
					<option value="" <?php selected( $la_period, '' ); ?>><?php esc_html_e( 'All time', 'login-armor' ); ?></option>
					<option value="24h" <?php selected( $la_period, '24h' ); ?>><?php esc_html_e( 'Last 24h', 'login-armor' ); ?></option>
					<option value="7d" <?php selected( $la_period, '7d' ); ?>><?php esc_html_e( 'Last 7 days', 'login-armor' ); ?></option>
					<option value="30d" <?php selected( $la_period, '30d' ); ?>><?php esc_html_e( 'Last 30 days', 'login-armor' ); ?></option>
				</select>
			</div>

			<?php
			// The one control that brings the observations back. It is a
			// filter like any other, so it lives in the filter bar and it
			// survives a page change: nothing is hidden, it is one tick away.
			// Disabled, and forced on, when the severity filter already asks
			// for level 1 by name: the checkbox must never contradict the list.
			?>
			<div class="la-fb-field la-fb-field--check">
				<label for="la-inc-obs">
					<input type="checkbox" id="la-inc-obs" name="obs" value="1"
						<?php checked( $la_obs_shown ); ?>
						<?php disabled( 1 === $la_severity ); ?> />
					<?php esc_html_e( 'Include observations', 'login-armor' ); ?>
				</label>
			</div>

			<div class="la-fb-actions">
				<button type="submit" class="la-ghost-btn"><?php esc_html_e( 'Filter', 'login-armor' ); ?></button>
				<a class="la-ghost-btn" href="<?php echo esc_url( $la_base_url ); ?>"><?php esc_html_e( 'Reset', 'login-armor' ); ?></a>
			</div>
		</form>

		<?php if ( empty( $la_rows ) && ! $la_user_filtered && \LoginArmor\Detection\Incident::STATUS_ACTIVE === $la_status_choice ) : ?>
			<?php
			// The default view, empty: everything has been dealt with. Said as
			// such, with the way to the rest one click away (2.7.10).
			$la_all_url = add_query_arg( array_filter( array( 'page' => 'login-armor', 'tab' => 'incidents', 'status' => 'all', 'obs' => $la_show_obs ? '1' : '' ) ), admin_url( 'admin.php' ) );
			?>
			<div class="la-empty-hint">
				<?php esc_html_e( 'No open incident: nothing left to deal with.', 'login-armor' ); ?>
				<a href="<?php echo esc_url( $la_all_url ); ?>"><?php esc_html_e( 'Show all incidents', 'login-armor' ); ?></a>
			</div>
		<?php elseif ( empty( $la_rows ) ) : ?>
			<div class="la-empty-hint"><?php esc_html_e( 'No incidents match the current filters.', 'login-armor' ); ?></div>
		<?php else : ?>
			<?php
			/*
			 * The header checkbox ticks the rows the page rendered, which is
			 * 25 of them. With 235 matching, clearing the list meant repeating
			 * the whole operation ten times. So the bar states plainly what is
			 * selected, and offers the whole filtered set as a separate,
			 * explicit action carrying its real count: the filter travels to
			 * the server, never a list of 235 ids, and the server applies the
			 * operation through the same filter parsing this list used.
			 */
			$la_bulk_more = $la_total > count( $la_rows );
			?>
			<div class="la-bulk-bar" data-la-bulk-bar
				data-la-filter-total="<?php echo esc_attr( (string) $la_total ); ?>"
				data-la-filter-status="<?php echo esc_attr( (string) ( $la_filters['status'] ?? '' ) ); ?>"
				data-la-filter-pattern="<?php echo esc_attr( (string) ( $la_filters['pattern'] ?? '' ) ); ?>"
				data-la-filter-severity="<?php echo esc_attr( (string) ( $la_filters['severity'] ?? 0 ) ); ?>"
				data-la-filter-min-severity="<?php echo esc_attr( (string) ( $la_filters['min_severity'] ?? 0 ) ); ?>"
				data-la-filter-period="<?php echo esc_attr( (string) ( $la_filters['period'] ?? '' ) ); ?>">
				<label class="la-bulk-bar__all">
					<input type="checkbox" data-la-bulk-all />
					<?php esc_html_e( 'Select all', 'login-armor' ); ?>
				</label>
				<span class="la-bulk-bar__count"><b data-la-bulk-count>0</b> <?php esc_html_e( 'selected', 'login-armor' ); ?></span>
				<span class="la-bulk-bar__spacer"></span>
				<button type="button" class="la-ghost-btn" data-la-bulk-op="resolve" disabled><?php esc_html_e( 'Mark resolved', 'login-armor' ); ?></button>
				<button type="button" class="la-ghost-btn" data-la-bulk-op="ignore" disabled><?php esc_html_e( 'Ignore', 'login-armor' ); ?></button>
			</div>

			<?php if ( $la_bulk_more ) : ?>
				<div class="la-bulk-scope" data-la-bulk-scope hidden>
					<span data-la-bulk-scope-page>
						<?php
						echo wp_kses_post(
							sprintf(
								/* translators: %s: number of incidents rendered on this page. */
								esc_html( _n( 'The %s incident on this page is selected.', 'The %s incidents on this page are selected.', count( $la_rows ), 'login-armor' ) ),
								'<b>' . esc_html( number_format_i18n( count( $la_rows ) ) ) . '</b>'
							)
						);
						?>
						<button type="button" class="la-linkish" data-la-bulk-select-all-filtered>
							<?php
							echo wp_kses_post(
								sprintf(
									/* translators: %s: total number of incidents matching the current filter. */
									esc_html( _n( 'Select the %s incident matching this filter', 'Select all %s incidents matching this filter', $la_total, 'login-armor' ) ),
									'<b>' . esc_html( number_format_i18n( $la_total ) ) . '</b>'
								)
							);
							?>
						</button>
					</span>
					<span data-la-bulk-scope-filtered hidden>
						<?php
						echo wp_kses_post(
							sprintf(
								/* translators: %s: total number of incidents matching the current filter. */
								esc_html( _n( 'The %s incident matching this filter is selected.', 'All %s incidents matching this filter are selected.', $la_total, 'login-armor' ) ),
								'<b>' . esc_html( number_format_i18n( $la_total ) ) . '</b>'
							)
						);
						?>
						<button type="button" class="la-linkish" data-la-bulk-clear-filtered>
							<?php esc_html_e( 'Select only this page', 'login-armor' ); ?>
						</button>
					</span>
				</div>
			<?php endif; ?>
			<div class="la-incidents-list">
				<?php
				foreach ( $la_rows as $la_inc ) :
					$la_sev_class = $la_sev_class_fn( $la_inc->severity );
					$la_sev_label = $la_sev_label_fn( $la_inc->severity );
					$la_is_resolved = ( 'resolved' === $la_inc->status );
					$la_is_ignored  = ( 'ignored' === $la_inc->status );

					$la_block_status   = \LoginArmor\LimitLogin::get_block_status( (string) $la_inc->ip );
					$la_is_locked      = ! empty( $la_block_status['locked'] );
					$la_lock_mins_left = $la_is_locked
						? max( 1, (int) ceil( ( (int) $la_block_status['lockout_expires_sec'] ) / 60 ) )
						: 0;
					$la_blocked_subnet = $la_block_status['blocked_subnet'];
					$la_classes = array( 'la-incident', 'la-incident--' . $la_sev_class );
					if ( $la_is_resolved || $la_is_ignored ) {
						$la_classes[] = 'la-incident--resolved';
					}

					// Status pill.
					$la_status_pill_cls   = 'la-pill la-pill--warn';
					$la_status_pill_label = __( 'Open', 'login-armor' );
					if ( $la_is_resolved ) {
						$la_status_pill_cls   = 'la-pill la-pill--resolved';
						$la_status_pill_label = __( 'Resolved', 'login-armor' );
					} elseif ( $la_is_ignored ) {
						$la_status_pill_cls   = 'la-pill la-pill--neutral';
						$la_status_pill_label = __( 'Ignored', 'login-armor' );
					}

					$la_drill_url = add_query_arg(
						array(
							'page'     => 'login-armor',
							'tab'      => 'incidents',
							'incident' => (int) $la_inc->id,
						),
						admin_url( 'admin.php' )
					);

					$la_pattern_label = login_armor_incident_pattern_label( $la_inc->pattern );
					$la_pattern_desc  = login_armor_incident_pattern_desc( $la_inc->pattern );

					// Attack entry point. xmlrpc/rest bypass Hide Login entirely, so
					// they are highlighted; login_form is the expected (masked) path.
					$la_vector        = isset( $la_inc->vector ) ? (string) $la_inc->vector : 'login_form';
					$la_vector_labels = array(
						'xmlrpc'     => 'XML-RPC',
						'rest'       => 'REST API',
						'login_form' => __( 'login form', 'login-armor' ),
					);
					$la_vector_label    = isset( $la_vector_labels[ $la_vector ] ) ? $la_vector_labels[ $la_vector ] : $la_vector;
					$la_vector_pill_cls = ( 'login_form' === $la_vector ) ? 'la-pill la-pill--neutral' : 'la-pill la-pill--warn';
					?>
					<article class="<?php echo esc_attr( implode( ' ', $la_classes ) ); ?>">
						<div class="la-incident__top">
							<div class="la-incident__top-left">
								<input type="checkbox" class="la-incident-check" value="<?php echo esc_attr( (string) $la_inc->id ); ?>"
									aria-label="<?php esc_attr_e( 'Select this incident for bulk actions', 'login-armor' ); ?>" />
								<span class="la-pill la-pill--<?php echo esc_attr( $la_sev_class ); ?>"><?php echo esc_html( $la_sev_label ); ?></span>
								<h4 class="la-mono"><?php echo esc_html( $la_pattern_label ); ?></h4>
								<?php if ( 'login_form' !== $la_vector ) : ?>
									<span class="<?php echo esc_attr( $la_vector_pill_cls ); ?>" title="<?php esc_attr_e( 'Attack entry point: bypasses the hidden login URL', 'login-armor' ); ?>">
										<?php
										/* translators: %s: attack vector name, e.g. XML-RPC. */
										echo esc_html( sprintf( __( 'via %s', 'login-armor' ), $la_vector_label ) );
										?>
									</span>
								<?php endif; ?>
							</div>
							<span class="<?php echo esc_attr( $la_status_pill_cls ); ?>"><?php echo esc_html( $la_status_pill_label ); ?></span>
						</div>

						<?php if ( '' !== $la_pattern_desc ) : ?>
							<p class="la-incident__desc"><?php echo esc_html( $la_pattern_desc ); ?></p>
						<?php endif; ?>

						<div class="la-incident__meta">
							<span><b><?php echo esc_html( number_format_i18n( $la_inc->events_count ) ); ?></b>
								<?php echo esc_html( _n( 'attempt', 'attempts', (int) $la_inc->events_count, 'login-armor' ) ); ?></span>
							<?php if ( $la_inc->unique_usernames > 0 ) : ?>
								<span><b><?php echo esc_html( number_format_i18n( $la_inc->unique_usernames ) ); ?></b>
									<?php echo esc_html( _n( 'username', 'usernames', (int) $la_inc->unique_usernames, 'login-armor' ) ); ?></span>
							<?php endif; ?>
							<?php if ( $la_inc->unique_ips > 0 ) : ?>
								<span><b><?php echo esc_html( number_format_i18n( $la_inc->unique_ips ) ); ?></b>
									<?php echo esc_html( _n( 'IP', 'IPs', (int) $la_inc->unique_ips, 'login-armor' ) ); ?></span>
							<?php endif; ?>
							<?php
							// Window between first seen and last seen. Use our own formatter so
							// the unit stays English regardless of WP site locale (Lot 18 V10.11).
							$la_start_ts = strtotime( $la_inc->started_at . ' UTC' );
							$la_end_ts   = strtotime( $la_inc->last_seen_at . ' UTC' );
							if ( $la_start_ts && $la_end_ts && $la_end_ts > $la_start_ts ) :
								?>
								<span><?php esc_html_e( 'Window', 'login-armor' ); ?> <b><?php echo esc_html( login_armor_format_duration_en( $la_end_ts - $la_start_ts ) ); ?></b></span>
							<?php endif; ?>
						</div>

						<div class="la-incident__details">
							<?php if ( '' !== $la_inc->ip ) : ?>
								<div>
									<label><?php esc_html_e( 'Source IP', 'login-armor' ); ?></label>
									<span class="la-mono"><?php
										echo esc_html( $la_inc->ip );
										if ( class_exists( '\LoginArmor\GeoIP' ) ) {
											echo ' ' . wp_kses( \LoginArmor\GeoIP::badge_html( (string) $la_inc->ip ), [ 'span' => [ 'class' => [], 'title' => [] ] ] );
										}
									?></span>
									<?php if ( $la_is_locked || null !== $la_blocked_subnet ) : ?>
										<div class="la-inc-card__block-row">
											<?php if ( $la_is_locked ) :
												$la_inc_level = \LoginArmor\LimitLogin::get_lockout_level( (string) $la_inc->ip );
												if ( $la_inc_level >= 2 ) : ?>
													<span class="la-pill la-pill--blacklist">
														<?php esc_html_e( 'Blacklist 24h', 'login-armor' ); ?>
													</span>
												<?php else : ?>
													<span class="la-pill la-pill--locked">
														<?php
														echo esc_html(
															sprintf(
																/* translators: %d: minutes remaining in the current IP lockout. */
																_n( '%d min', '%d min', $la_lock_mins_left, 'login-armor' ),
																$la_lock_mins_left
															)
														);
														?>
														<span class="la-pill__suffix"><?php esc_html_e( 'Auth blocked', 'login-armor' ); ?></span>
													</span>
												<?php endif; ?>
											<?php endif; ?>
											<?php if ( null !== $la_blocked_subnet ) : ?>
												<span class="la-pill la-pill--blocked">
													<?php esc_html_e( 'Subnet blocked', 'login-armor' ); ?>
													<span class="la-pill__suffix la-mono"><?php echo esc_html( $la_blocked_subnet ); ?></span>
												</span>
											<?php endif; ?>
										</div>
									<?php endif; ?>
								</div>
							<?php endif; ?>
							<?php if ( '' !== $la_inc->target_username ) : ?>
								<div>
									<label><?php esc_html_e( 'Target', 'login-armor' ); ?></label>
									<span><?php echo esc_html( $la_inc->target_username ); ?></span>
								</div>
							<?php endif; ?>
							<div>
								<label><?php esc_html_e( 'First seen', 'login-armor' ); ?></label>
								<span><?php echo esc_html( $la_inc->started_at ); ?> UTC</span>
							</div>
							<div>
								<label><?php esc_html_e( 'Last seen', 'login-armor' ); ?></label>
								<span><?php echo esc_html( $la_inc->last_seen_at ); ?> UTC</span>
							</div>
						</div>

						<div class="la-incident__actions">
							<a class="la-danger-btn" href="<?php echo esc_url( $la_drill_url ); ?>">
								<?php Icons::render( 'search', '', 14 );?>
								<?php esc_html_e( 'Investigate', 'login-armor' ); ?>
							</a>
							<?php if ( '' !== $la_inc->ip && filter_var( $la_inc->ip, FILTER_VALIDATE_IP ) ) : ?>
								<?php if ( null === $la_blocked_subnet && \LoginArmor\LimitLogin::would_lock_out_current_user( $la_inc->ip ) ) : ?>
									<span class="la-own-network"><?php esc_html_e( 'Your own network', 'login-armor' ); ?></span>
								<?php elseif ( null === $la_blocked_subnet ) : ?>
									<button type="button" class="la-ghost-btn"
										data-la-action="subnet-block"
										data-la-ip="<?php echo esc_attr( $la_inc->ip ); ?>">
										<?php esc_html_e( 'Block subnet', 'login-armor' ); ?>
									</button>
								<?php else : ?>
									<button type="button" class="la-ghost-btn la-ghost-btn--danger"
										data-la-action="subnet-unblock"
										data-la-ip="<?php echo esc_attr( $la_inc->ip ); ?>">
										<?php esc_html_e( 'Remove from blocklist', 'login-armor' ); ?>
									</button>
								<?php endif; ?>
							<?php endif; ?>
							<?php if ( $la_is_locked ) : ?>
								<button type="button" class="la-ghost-btn"
									data-la-action="ip-unblock"
									data-la-ip="<?php echo esc_attr( $la_inc->ip ); ?>">
									<?php esc_html_e( 'Unblock IP', 'login-armor' ); ?>
								</button>
							<?php endif; ?>
							<?php if ( ! $la_is_resolved && ! $la_is_ignored ) : ?>
								<button type="button" class="la-ghost-btn" data-la-action="resolve" data-la-id="<?php echo esc_attr( (string) $la_inc->id ); ?>">
									<?php esc_html_e( 'Mark resolved', 'login-armor' ); ?>
								</button>
								<button type="button" class="la-ghost-btn" data-la-action="ignore" data-la-id="<?php echo esc_attr( (string) $la_inc->id ); ?>">
									<?php esc_html_e( 'Ignore', 'login-armor' ); ?>
								</button>
							<?php endif; ?>
						</div>
					</article>
				<?php endforeach; ?>
			</div>

			<?php if ( count( $la_rows ) > 0 && count( $la_rows ) < 3 && $la_pages <= 1 ) : ?>
				<div class="la-empty-hint" style="margin-top: 14px;">
					<?php esc_html_e( 'No other incidents in the selected period.', 'login-armor' ); ?>
					<a class="la-link" href="<?php echo esc_url( $la_base_url ); ?>">
						<?php esc_html_e( 'Adjust filters', 'login-armor' ); ?>
					</a>
					<?php esc_html_e( 'to see more history.', 'login-armor' ); ?>
				</div>
			<?php endif; ?>

			<?php if ( $la_pages > 1 ) : ?>
				<div class="la-pagination" style="margin-top: 16px;">
					<span>
						<?php
						echo esc_html(
							sprintf(
								/* translators: 1: current page, 2: total pages, 3: total rows. */
								__( 'Page %1$d of %2$d · %3$d incidents', 'login-armor' ),
								$la_page_num,
								$la_pages,
								$la_total
							)
						);
						?>
					</span>
					<div class="la-pagination__links">
						<?php
						for ( $la_p = 1; $la_p <= $la_pages; $la_p++ ) {
							// Every filter of the list, the observations toggle
							// included: without it, page 2 fell back to the list
							// without observations (2.7.10). The status as the
							// select shows it, so that "All" stays all.
							$la_url = add_query_arg(
								array_filter(
									array(
										'page'     => 'login-armor',
										'tab'      => 'incidents',
										'status'   => $la_status_choice,
										'pattern'  => $la_pattern,
										'severity' => $la_severity,
										'period'   => $la_period,
										'obs'      => $la_show_obs ? '1' : '',
										'paged'    => $la_p,
									),
									static fn( $v ) => '' !== $v && 0 !== $v
								),
								admin_url( 'admin.php' )
							);
							if ( $la_p === $la_page_num ) {
								echo '<span class="la-pagination__current">' . esc_html( (string) $la_p ) . '</span>';
							} else {
								echo '<a href="' . esc_url( $la_url ) . '">' . esc_html( (string) $la_p ) . '</a>';
							}
						}
						?>
					</div>
				</div>
			<?php endif; ?>
		<?php endif; ?>
	</div>

	<aside>
		<?php
		$la_guide_file = LOGIN_ARMOR_DIR . 'admin/views/sidebar/incidents.php';
		if ( file_exists( $la_guide_file ) ) {
			echo '<div class="la-guide">';
			include $la_guide_file;
			echo '</div>';
		}
		include LOGIN_ARMOR_DIR . 'admin/views/sidebar/sponsored-ads.php';
		?>
	</aside>
</div>
