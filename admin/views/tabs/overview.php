<?php
/**
 * LoginArmor Overview tab (Lot 18 redesign: pixel-perfect Claude.ai design).
 *
 * Sections:
 *   1. Hero (navy gradient, 104px count-up, 3 metrics): Task 5
 *   2. Modules grid (8 protection modules): Task 6
 *   3. Activity chart (24h SVG area, animated line draw): Task 7
 *   4. Live events table + streaming + action banner: Task 8
 *
 * Preserves admin.js poll contract via data-la-* attributes + class names:
 *   #la-root, [data-la-live-events], [data-la-live-pause], [data-la-advice],
 *   [data-la-advice-key], [data-la-advice-skip], [data-la-allquiet],
 *   [data-la-last-check], .la-live-events__row (+ its children).
 *
 * @package LoginArmor
 *
 * @var string $active_tab
 * @var string $ajax_url
 */

// phpcs:disable WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

$la_data     = \LoginArmor\Overview::get_dashboard_data();
$la_stats    = (array) ( $la_data['stats'] ?? array() );
$la_events24 = (int) ( $la_stats['events_24h'] ?? 0 );
$la_delta    = \LoginArmor\Overview::get_events_delta_24h();
$la_uniq_ips = \LoginArmor\Overview::get_unique_ips_24h();
$la_locks    = (int) ( $la_stats['active_lockouts'] ?? 0 );
$la_quiet    = ! empty( $la_data['all_quiet'] );
$la_threat   = (string) ( $la_data['threat']['level'] ?? 'normal' );
$la_last_ago = (string) ( $la_data['last_event_ago'] ?? __( 'just now', 'login-armor' ) );

// Breach Check state (hoisted above hero so the top alert banner + 4th hero metric can read it).
$la_breach_on       = class_exists( '\LoginArmor\BreachCheck' ) && \LoginArmor\BreachCheck::is_enabled();
$la_breach_counts   = class_exists( '\LoginArmor\BreachCheck' ) ? \LoginArmor\BreachCheck::get_flagged_counts() : array( 'password' => 0, 'email' => 0 );
$la_breach_flagged  = (int) ( $la_breach_counts['password'] ?? 0 ) + (int) ( $la_breach_counts['email'] ?? 0 );

// Request Firewall state (hoisted above hero so the status row shows its mode
// next to the "all defenses operational" badge, like the dashboard widget does).
$la_fw_on   = class_exists( '\LoginArmor\Firewall\Firewall' ) && \LoginArmor\Firewall\Firewall::is_enabled();
$la_fw_mode = class_exists( '\LoginArmor\Firewall\Firewall' ) ? \LoginArmor\Firewall\Firewall::effective_mode() : 'log_only';
if ( ! $la_fw_on ) {
	$la_fw_pill_state = 'off';
	$la_fw_pill_text  = __( 'Firewall: off', 'login-armor' );
} elseif ( 'enforce' === $la_fw_mode ) {
	$la_fw_pill_state = 'on';
	$la_fw_pill_text  = __( 'Firewall: blocking', 'login-armor' );
} else {
	$la_fw_pill_state = 'warn';
	$la_fw_pill_text  = __( 'Firewall: monitoring', 'login-armor' );
}

$la_settings_url = add_query_arg( array( 'page' => 'login-armor', 'tab' => 'settings' ), admin_url( 'admin.php' ) );

$la_status_pill_map = array(
	'normal'   => __( 'All core defenses operational', 'login-armor' ),
	'elevated' => __( 'Elevated threat: review incidents', 'login-armor' ),
	'attack'   => __( 'Active attack in progress', 'login-armor' ),
);
$la_status_pill_text = $la_status_pill_map[ $la_threat ] ?? $la_status_pill_map['normal'];

if ( 'attack' === $la_threat ) {
	$la_hero_title = __( 'Active attack in progress.', 'login-armor' );
} elseif ( 'elevated' === $la_threat ) {
	$la_hero_title = __( 'Elevated threat: review incidents.', 'login-armor' );
} else {
	$la_hero_title = __( 'Your site is fully defended.', 'login-armor' );
}
?>


<section class="la-hero la-hero--<?php echo esc_attr( $la_threat ); ?>" data-la-allquiet="<?php echo $la_quiet ? '1' : '0'; ?>">
	<div class="la-hero__num" data-la-target="<?php echo esc_attr( (string) $la_events24 ); ?>">
		<span class="la-hero__num-value"><?php echo esc_html( (string) $la_events24 ); ?></span>
		<?php if ( 0 !== $la_delta ) : ?>
			<?php
			$la_trend_label = $la_delta > 0
				/* translators: %d: number of additional login attempts vs previous 24 hours. */
				? sprintf( __( '%d more than the previous 24 hours', 'login-armor' ), abs( $la_delta ) )
				/* translators: %d: number of fewer login attempts vs previous 24 hours. */
				: sprintf( __( '%d fewer than the previous 24 hours', 'login-armor' ), abs( $la_delta ) );
			?>
			<span
				class="la-hero__trend la-hero__trend--<?php echo $la_delta > 0 ? 'up' : 'down'; ?>"
				title="<?php echo esc_attr( $la_trend_label ); ?>"
				aria-label="<?php echo esc_attr( $la_trend_label ); ?>"
			>
				<?php echo $la_delta > 0 ? '↑' : '↓'; ?> <?php echo esc_html( (string) abs( $la_delta ) ); ?>
				<small class="la-hero__trend-note"><?php esc_html_e( 'vs prev 24h', 'login-armor' ); ?></small>
			</span>
		<?php endif; ?>
	</div>

	<div class="la-hero__mid">
		<div class="la-hero__kicker">
			<?php esc_html_e( 'Login attempts · last 24 h', 'login-armor' ); ?>
			<span class="la-hero__live" aria-label="<?php esc_attr_e( 'Live', 'login-armor' ); ?>"><?php esc_html_e( 'live', 'login-armor' ); ?></span>
		</div>
		<h2 class="la-hero__title"><?php echo esc_html( $la_hero_title ); ?></h2>
		<p class="la-hero__sub">
			<?php
			// Defense-in-depth: treat an em dash or any variant of "dash only"
			// as "no data" so legacy cached bytecode never leaks "System last checked -.".
			$la_last_ago_normalised = trim( $la_last_ago, "-\xE2\x80\x94 \t\r\n" );
			if ( '' === $la_last_ago_normalised ) {
				if ( 'normal' === $la_threat ) {
					esc_html_e( 'No login events recorded yet. All core defenses are operational.', 'login-armor' );
				} else {
					esc_html_e( 'No login events recorded yet. Review active incidents below.', 'login-armor' );
				}
			} elseif ( 'normal' === $la_threat ) {
				echo wp_kses_post(
					sprintf(
						/* translators: %s: relative time string like "4 minutes ago". */
						esc_html__( 'System last checked %s. All core defenses are operational and no active incidents require attention.', 'login-armor' ),
						'<span data-la-last-check>' . esc_html( $la_last_ago ) . '</span>'
					)
				);
			} else {
				echo wp_kses_post(
					sprintf(
						/* translators: %s: relative time string like "4 minutes ago". */
						esc_html__( 'System last checked %s. Review active incidents below.', 'login-armor' ),
						'<span data-la-last-check>' . esc_html( $la_last_ago ) . '</span>'
					)
				);
			}
			?>
		</p>
		<div class="la-hero__statusrow">
			<span class="la-hero__status"><?php echo esc_html( $la_status_pill_text ); ?></span>
			<span class="la-hero__status la-hero__status--fw-<?php echo esc_attr( $la_fw_pill_state ); ?>"><?php echo esc_html( $la_fw_pill_text ); ?></span>
		</div>
	</div>

	<div class="la-hero__metrics">
		<div class="la-hero__m">
			<b><?php echo esc_html( (string) $la_events24 ); ?></b>
			<span><?php esc_html_e( 'Login attempts', 'login-armor' ); ?></span>
		</div>
		<div class="la-hero__m">
			<b><?php echo esc_html( (string) $la_uniq_ips ); ?></b>
			<span><?php echo esc_html( _n( 'Unique IP', 'Unique IPs', $la_uniq_ips, 'login-armor' ) ); ?></span>
		</div>
		<div class="la-hero__m">
			<b><?php echo esc_html( (string) $la_locks ); ?></b>
			<span><?php echo esc_html( _n( 'Lockout', 'Lockouts', $la_locks, 'login-armor' ) ); ?></span>
		</div>
		<?php if ( $la_breach_on ) : ?>
			<div class="la-hero__m<?php echo $la_breach_flagged > 0 ? ' la-hero__m--alert' : ''; ?>">
				<b><?php echo esc_html( (string) $la_breach_flagged ); ?></b>
				<span><?php echo esc_html( _n( 'Data breach', 'Data breaches', max( 1, $la_breach_flagged ), 'login-armor' ) ); ?></span>
			</div>
		<?php endif; ?>
	</div>
</section>

<?php
// V2.1.20: Hide Login ↔ XML-RPC advisory. Surfaces only when Hide Login is on,
// XML-RPC is still open, AND an xmlrpc-vectored attack has actually been seen.
$la_xmlrpc_advisory = \LoginArmor\Overview::get_xmlrpc_advisory();
if ( null !== $la_xmlrpc_advisory ) :
	?>
	<div class="la-advisory la-advisory--xmlrpc" role="alert">
		<div class="la-advisory__icon">
			<?php \LoginArmor\Icons::render( 'alert-triangle', '', 18, 2.2 ); ?>
		</div>
		<div class="la-advisory__txt">
			<b><?php esc_html_e( 'Hide Login is on, but XML-RPC is still open.', 'login-armor' ); ?></b>
			<p>
				<?php
				echo esc_html(
					sprintf(
						/* translators: %d: number of XML-RPC attack incidents in the last 30 days. */
						_n(
							'Your login URL is hidden, yet %d attack in the last 30 days reached your site through xmlrpc.php, a separate login endpoint that bypasses Hide Login. Disable XML-RPC to close it (keep it on only if you use Jetpack or the WordPress mobile app).',
							'Your login URL is hidden, yet %d attacks in the last 30 days reached your site through xmlrpc.php, a separate login endpoint that bypasses Hide Login. Disable XML-RPC to close it (keep it on only if you use Jetpack or the WordPress mobile app).',
							$la_xmlrpc_advisory['count'],
							'login-armor'
						),
						$la_xmlrpc_advisory['count']
					)
				);
				?>
			</p>
		</div>
		<div class="la-advisory__actions">
			<a class="la-advisory__cta" href="<?php echo esc_url( $la_xmlrpc_advisory['settings_url'] ); ?>">
				<?php esc_html_e( 'Disable XML-RPC →', 'login-armor' ); ?>
			</a>
		</div>
	</div>
	<?php
endif;

$la_spark  = array_values( (array) ( $la_data['sparkline'] ?? array() ) );
while ( count( $la_spark ) < 24 ) { $la_spark[] = 0; }
$la_spark = array_slice( $la_spark, -24 );

// Module definitions.
$la_2fa_on          = (bool) get_option( 'login_armor_2fa_enabled', false );
$la_hide_on         = class_exists( '\LoginArmor\HideLogin' ) && \LoginArmor\HideLogin::is_enabled();
$la_limit_on        = (bool) get_option( 'login_armor_limit_enabled', true );
$la_detection_on    = (bool) get_option( 'login_armor_detection_enabled', true );
$la_activity_on     = (bool) get_option( 'login_armor_activity_enabled', false );
$la_headers_on      = class_exists( '\LoginArmor\LoginHeaders' ) && \LoginArmor\LoginHeaders::is_enabled();
$la_pwd_on          = class_exists( '\LoginArmor\PasswordPolicy' ) && \LoginArmor\PasswordPolicy::is_enabled();
$la_session_on      = class_exists( '\LoginArmor\SessionManager' ) && \LoginArmor\SessionManager::is_enabled();
$la_fw_on           = class_exists( '\LoginArmor\Firewall\Firewall' ) && \LoginArmor\Firewall\Firewall::is_enabled();
$la_fw_mode         = $la_fw_on ? \LoginArmor\Firewall\Firewall::effective_mode() : '';
$la_geoip_on        = class_exists( '\LoginArmor\GeoIP' ) && \LoginArmor\GeoIP::is_enabled();

$la_hard_settings = class_exists( '\LoginArmor\Hardening' ) ? \LoginArmor\Hardening::get_settings() : array();
$la_hard_toggles  = class_exists( '\LoginArmor\Hardening' ) ? \LoginArmor\Hardening::get_toggles() : array();
$la_hard_active   = 0;
// 2.9.0: in headless mode the guarded toggles are not a choice: not counted.
$la_hard_excl     = class_exists( '\LoginArmor\SecurityScore' ) ? \LoginArmor\SecurityScore::hardening_excluded_keys() : array();
$la_hard_toggles  = array_values( array_filter( $la_hard_toggles, static fn( $la_t ) => ! in_array( $la_t['key'], $la_hard_excl, true ) ) );
foreach ( $la_hard_toggles as $la_t ) {
	if ( ! empty( $la_hard_settings[ $la_t['key'] ] ) ) { ++$la_hard_active; }
}
$la_hard_total = max( 1, count( $la_hard_toggles ) );

$la_modules = array(
	array(
		'slug'  => 'hide-login',
		'icon'  => 'shield',
		'label' => __( 'Hide Login', 'login-armor' ),
		'desc'  => __( 'URL camouflaged', 'login-armor' ),
		'state' => $la_hide_on ? 'on' : 'off',
		'pill'  => $la_hide_on ? __( 'Active', 'login-armor' ) : __( 'Off', 'login-armor' ),
	),
	array(
		'slug'  => 'limit-login',
		'icon'  => 'lock',
		'label' => __( 'Brute Force', 'login-armor' ),
		'desc'  => __( 'Rate-limited', 'login-armor' ),
		'state' => $la_limit_on ? 'on' : 'off',
		'pill'  => $la_limit_on ? __( 'Active', 'login-armor' ) : __( 'Off', 'login-armor' ),
	),
	array(
		'slug'  => 'hardening',
		'icon'  => 'check',
		'label' => __( 'Hardening', 'login-armor' ),
		'desc'  => sprintf( /* translators: 1: active toggles, 2: total toggles */ __( '%1$d of %2$d toggles', 'login-armor' ), $la_hard_active, $la_hard_total ),
		'state' => $la_hard_active > 0 ? 'on' : 'off',
		'pill'  => $la_hard_active . '/' . $la_hard_total,
	),
	array(
		'slug'  => 'detection-logs',
		'icon'  => 'eye',
		'label' => __( 'Detection', 'login-armor' ),
		'desc'  => __( '30-day retention', 'login-armor' ),
		'state' => $la_detection_on ? 'on' : 'off',
		'pill'  => $la_detection_on ? __( 'Active', 'login-armor' ) : __( 'Off', 'login-armor' ),
	),
	array(
		'slug'  => 'activity-log',
		'icon'  => 'pulse',
		'label' => __( 'Activity Log', 'login-armor' ),
		'desc'  => __( 'Admin actions', 'login-armor' ),
		'state' => $la_activity_on ? 'on' : 'off',
		'pill'  => $la_activity_on ? __( 'Active', 'login-armor' ) : __( 'Off', 'login-armor' ),
	),
	array(
		'slug'  => 'two-factor',
		'icon'  => 'unlock',
		'label' => __( '2FA', 'login-armor' ),
		'desc'  => $la_2fa_on ? __( 'Enabled', 'login-armor' ) : __( 'Not configured', 'login-armor' ),
		'state' => $la_2fa_on ? 'on' : 'off',
		'pill'  => $la_2fa_on ? __( 'Active', 'login-armor' ) : __( 'Off', 'login-armor' ),
	),
	array(
		'slug'  => 'login-headers',
		'icon'  => 'shield',
		'label' => __( 'Login Headers', 'login-armor' ),
		'desc'  => __( 'HTTP protection', 'login-armor' ),
		'state' => $la_headers_on ? 'on' : 'off',
		'pill'  => $la_headers_on ? __( 'Active', 'login-armor' ) : __( 'Off', 'login-armor' ),
	),
	array(
		'slug'  => 'breach-check',
		'icon'  => 'search',
		'label' => __( 'Breach Check', 'login-armor' ),
		'desc'  => $la_breach_on
			? ( $la_breach_flagged > 0
				? sprintf(
					/* translators: %d: number of users with a flagged password or email. */
					_n( '%d account flagged', '%d accounts flagged', $la_breach_flagged, 'login-armor' ),
					$la_breach_flagged
				)
				: __( 'No flagged accounts', 'login-armor' )
			)
			: __( 'Password and email leaks', 'login-armor' ),
		// Visual state: amber warning when the module is on AND there
		// is at least one flagged account. This promotes the card from
		// neutral "Active" to attention-grabbing "Needs review" so the
		// admin sees the problem on the Overview without having to open
		// the Settings section.
		'state' => $la_breach_on
			? ( $la_breach_flagged > 0 ? 'warn' : 'on' )
			: 'off',
		'pill'  => $la_breach_on
			? ( $la_breach_flagged > 0
				? sprintf(
					/* translators: %d: number of flagged accounts, shown as a pill on the Overview Breach Check card. */
					_n( '%d flagged', '%d flagged', $la_breach_flagged, 'login-armor' ),
					$la_breach_flagged
				)
				: __( 'Active', 'login-armor' )
			)
			: __( 'Off', 'login-armor' ),
	),
	array(
		'slug'  => 'password-policy',
		'icon'  => 'key',
		'label' => __( 'Password Policy', 'login-armor' ),
		'desc'  => $la_pwd_on ? __( 'Strong passwords enforced', 'login-armor' ) : __( 'Password strength rules', 'login-armor' ),
		'state' => $la_pwd_on ? 'on' : 'off',
		'pill'  => $la_pwd_on ? __( 'Active', 'login-armor' ) : __( 'Off', 'login-armor' ),
	),
	array(
		'slug'  => 'session',
		'icon'  => 'monitor',
		'label' => __( 'Sessions', 'login-armor' ),
		'desc'  => $la_session_on ? __( 'Timeout & device limits', 'login-armor' ) : __( 'Idle timeout & device limits', 'login-armor' ),
		'state' => $la_session_on ? 'on' : 'off',
		'pill'  => $la_session_on ? __( 'Active', 'login-armor' ) : __( 'Off', 'login-armor' ),
	),
	array(
		'slug'  => 'firewall',
		'icon'  => 'circle-slash',
		'label' => __( 'Request Firewall', 'login-armor' ),
		'desc'  => $la_fw_on
			? ( 'enforce' === $la_fw_mode ? __( 'Blocking bad requests', 'login-armor' ) : __( 'Monitoring (not blocking)', 'login-armor' ) )
			: __( 'Blocks malicious requests', 'login-armor' ),
		'state' => $la_fw_on ? ( 'enforce' === $la_fw_mode ? 'on' : 'warn' ) : 'off',
		'pill'  => $la_fw_on
			? ( 'enforce' === $la_fw_mode ? __( 'Enforcing', 'login-armor' ) : __( 'Monitor', 'login-armor' ) )
			: __( 'Off', 'login-armor' ),
	),
	array(
		'slug'  => 'geoip',
		'icon'  => 'globe',
		'label' => __( 'IP Geolocation', 'login-armor' ),
		'desc'  => $la_geoip_on ? __( 'Country shown on IPs', 'login-armor' ) : __( 'Country of origin on IPs', 'login-armor' ),
		'state' => $la_geoip_on ? 'on' : 'off',
		'pill'  => $la_geoip_on ? __( 'Active', 'login-armor' ) : __( 'Off', 'login-armor' ),
	),
);

$la_active_mod_count = 0;
foreach ( $la_modules as $la_m ) {
	if ( 'on' === $la_m['state'] ) { ++$la_active_mod_count; }
}

// Build SVG chart data now (used at the right of the row).
$la_max_y = max( 1, (int) max( $la_spark ) );
$la_pts   = array();
foreach ( $la_spark as $la_i => $la_v ) {
	$la_x = (int) round( ( $la_i / 23 ) * 300 );
	$la_y = (int) round( 180 - ( ( (int) $la_v / $la_max_y ) * 160 ) );
	$la_pts[] = $la_x . ',' . $la_y;
}
/*
 * 2.7.5 - one continuous line across all twenty-four points.
 *
 * 2.7.3 drew the final segment dashed, on the belief that the last bucket was
 * the clock hour in progress and therefore a partial one. The belief was
 * wrong, and reading the query would have said so. get_hourly_activity()
 * groups on FLOOR((now - log_time) / 3600): a ROLLING sixty minutes counted
 * back from this instant, not a clock hour. Checked against real rows at
 * 02:19 UTC, the bucket thirteen hours back spans 12:19 to 13:19. Every
 * bucket is a full hour, the last one included, so there was nothing to mark.
 *
 * What the dash produced instead was a gap and a detached stub at the right
 * edge, with no legend anywhere to explain it, and readers took it for a break
 * in the data. The plugin's author did, in those words, which is how it was
 * found.
 */
$la_line_path = 'M' . implode( ' L', $la_pts );
$la_area_path = $la_line_path . ' L300,200 L0,200 Z';
$la_peak_i    = (int) array_search( max( $la_spark ), $la_spark, true );
$la_peak_x    = (int) round( ( $la_peak_i / 23 ) * 300 );
$la_peak_y    = (int) round( 180 - ( ( (int) $la_spark[ $la_peak_i ] / $la_max_y ) * 160 ) );
$la_peak_val  = (int) $la_spark[ $la_peak_i ];
$la_total_h   = (int) array_sum( $la_spark );
?>

<div class="la-row la-row--modules-chart">
	<section class="la-card la-modules">
		<div class="la-card__head">
			<h3 class="la-card__title">
				<?php esc_html_e( 'Protection modules', 'login-armor' ); ?>
				<span class="la-card__title-tiny">
					<?php
					printf(
						/* translators: 1: active module count, 2: total module count. */
						esc_html__( '%1$d of %2$d modules active', 'login-armor' ),
						(int) $la_active_mod_count,
						(int) count( $la_modules )
					);
					?>
				</span>
			</h3>
			<a href="<?php echo esc_url( $la_settings_url ); ?>" class="la-linkbtn"><?php esc_html_e( 'Manage all →', 'login-armor' ); ?></a>
		</div>

		<div class="la-modgrid">
			<?php foreach ( $la_modules as $la_m ) : ?>
				<a class="la-mod la-mod--<?php echo esc_attr( $la_m['state'] ); ?>"
					href="<?php echo esc_url( $la_settings_url . '#' . $la_m['slug'] ); ?>">
					<div class="la-mod__i"><?php \LoginArmor\Icons::render( $la_m['icon'], '', 16 ); ?></div>
					<div class="la-mod__text">
						<b><?php echo esc_html( $la_m['label'] ); ?></b>
						<small><?php echo esc_html( $la_m['desc'] ); ?></small>
					</div>
					<span class="la-mod__state"><?php echo esc_html( $la_m['pill'] ); ?></span>
				</a>
			<?php endforeach; ?>
		</div>
	</section>

	<section class="la-card la-chart-card">
		<div class="la-card__head">
			<h3 class="la-card__title">
				<?php esc_html_e( 'Activity', 'login-armor' ); ?>
				<span class="la-card__title-tiny"><?php esc_html_e( '24 H', 'login-armor' ); ?></span>
			</h3>
			<span class="la-meta">
				<b><?php echo esc_html( (string) $la_total_h ); ?></b>
				<?php echo esc_html( _n( 'event', 'events', $la_total_h, 'login-armor' ) ); ?>
				· <b><?php echo esc_html( (string) $la_uniq_ips ); ?></b>
				<?php echo esc_html( _n( 'IP', 'IPs', $la_uniq_ips, 'login-armor' ) ); ?>
			</span>
		</div>
		<div class="la-chart">
			<?php
			/*
			 * 2.7.1 - the viewBox is 300 wide, not 308. Every coordinate above is
			 * drawn to 300 and the eight spare units were only ever there to keep
			 * the peak <circle> from being clipped at the right edge. The marker
			 * left the SVG (see below), so the spare units left with it: they were
			 * a 2.6% dead strip that stopped the "now" end of the sparkline from
			 * reaching the edge of its card.
			 *
			 * preserveAspectRatio="none" stays: filling the box is the whole point
			 * of a sparkline. What it costs is that x and y are scaled by different
			 * factors, so nothing round and no stroke width survives it. The line
			 * is handled by vector-effect (CSS), the marker by leaving the
			 * coordinate system altogether.
			 */
			?>
			<svg viewBox="0 0 300 200" preserveAspectRatio="none" role="img" aria-label="<?php esc_attr_e( '24-hour activity chart', 'login-armor' ); ?>">
				<defs>
					<linearGradient id="la-chart-gradient" x1="0" x2="0" y1="0" y2="1">
						<stop offset="0" stop-color="#10b981" stop-opacity="0.3"/>
						<stop offset="1" stop-color="#10b981" stop-opacity="0"/>
					</linearGradient>
				</defs>
				<?php
				/*
				 * 2.7.3 - one reference line instead of three anonymous ones.
				 * The old grid drew rules at y=50, 100 and 150 with nothing to
				 * say what they meant: three evenly spaced lines are read as an
				 * axis, and there was no axis, no scale and no labels anywhere
				 * on the card. A reader could only guess, and every guess was
				 * wrong by a different amount depending on the day's peak.
				 *
				 * What remains is the one line that has a meaning, drawn where
				 * the busiest hour actually sits, with that hour's count beside
				 * it in the corner. The number is HTML rather than <text>: this
				 * viewBox is stretched by preserveAspectRatio="none", which
				 * would squash the glyphs exactly as it squashed the marker.
				 */
				?>
				<?php if ( $la_peak_val > 0 ) : ?>
					<line class="la-chart__rule" x1="0" y1="<?php echo esc_attr( (string) $la_peak_y ); ?>" x2="300" y2="<?php echo esc_attr( (string) $la_peak_y ); ?>"/>
				<?php endif; ?>
				<path class="la-chart__area" d="<?php echo esc_attr( $la_area_path ); ?>" fill="url(#la-chart-gradient)"/>
				<?php
				/*
				 * 2.7.8 - no pathLength, no dash, no offset. The line shipped
				 * hidden behind a dash as long as the path and was walked in by
				 * the script; the CSS that keeps its width constant lays dashes
				 * out on the screen, so on any chart drawn larger than its
				 * viewBox the dash ran out before the line did. It is whole in
				 * the markup now, and the stylesheet uncovers it (see
				 * .la-chart__line in admin.css).
				 */
				?>
				<path class="la-chart__line" d="<?php echo esc_attr( $la_line_path ); ?>" fill="none" stroke="#10b981" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"/>
			</svg>
			<?php if ( $la_peak_val > 0 ) : ?>
				<span class="la-chart__peak" style="--la-peak-y:<?php echo esc_attr( (string) round( ( $la_peak_y / 200 ) * 100, 2 ) ); ?>%">
					<?php echo esc_html( number_format_i18n( $la_peak_val ) ); ?>
				</span>
			<?php endif; ?>
			<?php if ( $la_peak_val > 0 ) : ?>
				<?php
				/*
				 * The marker is an ordinary element laid over the chart, positioned
				 * in percent of the same box the SVG fills, so it follows the line
				 * through every resize while staying a circle: border-radius owes
				 * nothing to the viewBox transform. As a <circle> it inherited the
				 * anisotropy and rendered 10 x 16 px on a 1500px desktop, which is
				 * the egg the author reported. Decorative: the chart already has
				 * its own label.
				 */
				?>
				<span
					class="la-chart__marker"
					aria-hidden="true"
					style="--la-dot-x:<?php echo esc_attr( (string) round( ( $la_peak_x / 300 ) * 100, 2 ) ); ?>%;--la-dot-y:<?php echo esc_attr( (string) round( ( $la_peak_y / 200 ) * 100, 2 ) ); ?>%"
				></span>
			<?php endif; ?>
		</div>
		<div class="la-chart__foot">
			<span><?php esc_html_e( '24h ago', 'login-armor' ); ?></span>
			<?php
			$la_failed_24h = \LoginArmor\Overview::get_failed_attempts_24h();
			if ( $la_failed_24h > 0 ) : ?>
				<span class="la-chart__highlight la-chart__highlight--fail">
					<?php
					printf(
						/* translators: %d: number of blocked failed attempts */
						esc_html( _n( '%d fail blocked', '%d fails blocked', $la_failed_24h, 'login-armor' ) ),
						(int) $la_failed_24h
					);
					?>
				</span>
			<?php elseif ( $la_total_h > 0 ) : ?>
				<span class="la-chart__highlight la-chart__highlight--ok">
					<?php esc_html_e( 'all clean', 'login-armor' ); ?>
				</span>
			<?php else : ?>
				<span class="la-chart__highlight la-chart__highlight--muted">
					<?php esc_html_e( 'no activity', 'login-armor' ); ?>
				</span>
			<?php endif; ?>
			<span><?php esc_html_e( 'now', 'login-armor' ); ?></span>
		</div>
	</section>
</div>

<?php
// AI security briefing, placed right under the protection modules. Renders
// nothing when no native AI connector is available.
$la_ai_incident_id = 0;
$la_ai_context     = 'posture';
include LOGIN_ARMOR_DIR . 'admin/views/sections/ai-panel.php';
?>

<?php
$la_events   = (array) ( $la_data['recent_events'] ?? array() );
$la_advice   = $la_data['next_advice'] ?? null;

if ( ! function_exists( 'login_armor_event_status_meta' ) ) {
	/**
	 * Map a log event status to its badge class + label.
	 *
	 * @param string $status Raw status from the logs table.
	 * @return array{cls:string, txt:string}
	 */
	function login_armor_event_status_meta( string $status ): array {
		if ( 'success' === $status ) { return array( 'cls' => 'ok',   'txt' => __( 'OK', 'login-armor' ) ); }
		if ( 'locked'  === $status ) { return array( 'cls' => 'lock', 'txt' => __( 'BLOCKED', 'login-armor' ) ); }
		return array( 'cls' => 'fail', 'txt' => __( 'FAIL', 'login-armor' ) );
	}
}

/**
 * Shorten a user-agent string to a readable platform tag.
 * Duplicated from events.php so overview can render without requiring events.php.
 */
if ( ! function_exists( 'login_armor_short_ua' ) ) {
	function login_armor_short_ua( string $ua ): string {
		if ( '' === $ua ) { return ''; }
		if ( preg_match( '#Chrome/[\d.]+#', $ua ) && false !== strpos( $ua, 'Mac OS' ) )  { return __( 'Chrome on macOS', 'login-armor' ); }
		if ( preg_match( '#Chrome/[\d.]+#', $ua ) && false !== strpos( $ua, 'Windows' ) ) { return __( 'Chrome on Windows', 'login-armor' ); }
		if ( preg_match( '#Chrome/[\d.]+#', $ua ) && false !== strpos( $ua, 'Linux' ) )   { return __( 'Chrome on Linux', 'login-armor' ); }
		if ( preg_match( '#Safari/[\d.]+#', $ua ) && false !== strpos( $ua, 'iPhone' ) )  { return __( 'Safari on iOS', 'login-armor' ); }
		if ( preg_match( '#Safari/[\d.]+#', $ua ) && false !== strpos( $ua, 'iPad' ) )    { return __( 'Safari on iPadOS', 'login-armor' ); }
		if ( preg_match( '#Safari/[\d.]+#', $ua ) && false !== strpos( $ua, 'Mac OS' ) )  { return __( 'Safari on macOS', 'login-armor' ); }
		if ( preg_match( '#Firefox/[\d.]+#', $ua ) )                                       { return __( 'Firefox', 'login-armor' ); }
		if ( preg_match( '#Edg/[\d.]+#', $ua ) )                                           { return __( 'Edge', 'login-armor' ); }
		if ( preg_match( '#curl/[\d.]+#', $ua ) )                                          { return __( 'curl', 'login-armor' ); }
		if ( preg_match( '#wget/[\d.]+#', $ua ) )                                          { return __( 'wget', 'login-armor' ); }
		if ( preg_match( '#python-requests/[\d.]+#', $ua ) )                               { return __( 'python-requests', 'login-armor' ); }
		if ( preg_match( '#Go-http-client/[\d.]+#', $ua ) )                                { return __( 'Go http-client', 'login-armor' ); }
		if ( preg_match( '#bot|spider|crawler#i', $ua ) )                                  { return __( 'Bot / crawler', 'login-armor' ); }
		// WordPress.com / Jetpack service clients (frequently spoofed in xmlrpc and login floods).
		if ( false !== stripos( $ua, 'jetpack' ) )                                         { return __( 'Jetpack (WordPress.com)', 'login-armor' ); }
		if ( false !== stripos( $ua, 'wordpress.com' ) )                                   { return __( 'WordPress.com', 'login-armor' ); }
		if ( preg_match( '#WordPress/[\d.]+#', $ua ) )                                      { return __( 'WordPress', 'login-armor' ); }
		// Generic fallback: trim to a word boundary, drop a dangling "(" and
		// trailing punctuation, append an ellipsis: never show a cut-off token
		// like "Jetpack by WordPress.com (Jetp".
		if ( mb_strlen( $ua ) <= 30 ) {
			return $ua;
		}
		$la_ua_short = mb_substr( $ua, 0, 30 );
		$la_ua_sp    = mb_strrpos( $la_ua_short, ' ' );
		if ( false !== $la_ua_sp && $la_ua_sp >= 12 ) {
			$la_ua_short = mb_substr( $la_ua_short, 0, $la_ua_sp );
		}
		return rtrim( $la_ua_short, " \t(;,/-" ) . '…';
	}
}
?>

<section class="la-card la-events-card">
	<div class="la-card__head">
		<h3 class="la-card__title">
			<?php esc_html_e( 'Live events', 'login-armor' ); ?>
			<span class="la-streaming"><?php esc_html_e( 'streaming', 'login-armor' ); ?></span>
		</h3>
		<div class="la-card__actions">
			<button type="button" class="la-ghost-btn" data-la-live-pause aria-pressed="false">
				<?php \LoginArmor\Icons::render( 'pause', '', 10 ); ?>
				<span class="la-pause-label"><?php esc_html_e( 'Pause', 'login-armor' ); ?></span>
			</button>
			<a class="la-ghost-btn" href="<?php echo esc_url( add_query_arg( array( 'page' => 'login-armor', 'tab' => 'events' ), admin_url( 'admin.php' ) ) ); ?>">
				<?php \LoginArmor\Icons::render( 'filter', '', 11 ); ?>
				<?php esc_html_e( 'Filter', 'login-armor' ); ?>
			</a>
		</div>
	</div>

	<div class="la-evt-head">
		<span><?php esc_html_e( 'Time', 'login-armor' ); ?></span>
		<span><?php esc_html_e( 'Status', 'login-armor' ); ?></span>
		<span><?php esc_html_e( 'Source IP', 'login-armor' ); ?></span>
		<span><?php esc_html_e( 'User · action', 'login-armor' ); ?></span>
		<span><?php esc_html_e( 'When', 'login-armor' ); ?></span>
	</div>

	<div class="la-live-events" data-la-live-events>
		<?php if ( empty( $la_events ) ) : ?>
			<div class="la-live-events__empty">
				<?php esc_html_e( 'No events recorded yet: your site is quiet.', 'login-armor' ); ?>
			</div>
		<?php else :
			foreach ( $la_events as $la_ev ) :
				$la_status = (string) ( $la_ev['status'] ?? '' );
				$la_meta   = login_armor_event_status_meta( $la_status );
				$la_user   = (string) ( $la_ev['username'] ?? '' );
				$la_letter = '' !== $la_user ? strtoupper( mb_substr( $la_user, 0, 1 ) ) : '-';
				if ( 'success' === $la_status ) {
					$la_action_label = __( 'Successful sign-in', 'login-armor' );
				} elseif ( 'locked' === $la_status ) {
					$la_action_label = __( 'Locked out', 'login-armor' );
				} else {
					// V2.4.5: real recorded error code, not a blanket assumption.
					$la_action_label = \LoginArmor\LoginLogs::failure_reason_label( (string) ( $la_ev['reason'] ?? '' ) );
				}
				$la_ua_short = login_armor_short_ua( (string) ( $la_ev['user_agent'] ?? '' ) );
				?>
				<div class="la-live-events__row" data-la-event-id="<?php echo esc_attr( (string) (int) $la_ev['id'] ); ?>">
					<span class="la-live-events__time"><?php echo esc_html( (string) $la_ev['time_short'] ); ?></span>
					<span class="la-badge la-badge--<?php echo esc_attr( $la_meta['cls'] ); ?>"><?php echo esc_html( $la_meta['txt'] ); ?></span>
					<span class="la-live-events__ip">
						<?php \LoginArmor\Icons::render( 'globe', 'la-live-events__globe', 12 ); ?>
						<?php echo esc_html( (string) ( $la_ev['ip'] ?? '' ) ); ?>
					</span>
					<span class="la-live-events__user<?php echo 'fail' === $la_meta['cls'] ? ' is-fail' : ''; ?>">
						<span class="la-live-events__avatar la-live-events__avatar--<?php echo esc_attr( $la_meta['cls'] ); ?>"><?php echo esc_html( $la_letter ); ?></span>
						<span class="la-live-events__detail">
							<b><?php echo esc_html( '' === $la_user ? '-' : $la_user ); ?></b>
							<small<?php echo 'fail' === $la_meta['cls'] ? ' class="is-bad"' : ''; ?>>
								<?php echo esc_html( $la_action_label ); ?>
								<?php if ( '' !== $la_ua_short ) : ?>
									<span class="la-live-events__sep">·</span> <?php echo esc_html( $la_ua_short ); ?>
								<?php endif; ?>
							</small>
						</span>
					</span>
					<span class="la-live-events__ago"><?php echo esc_html( (string) ( $la_ev['ago'] ?? '' ) ); ?></span>
				</div>
			<?php endforeach; endif; ?>
	</div>

	<?php
	// Always surface the 2FA CTA when 2FA is off, overriding get_next_advice() skip state.
	$la_2fa_on_ob = (bool) get_option( 'login_armor_2fa_enabled', false );
	$la_banner    = null;
	if ( ! $la_2fa_on_ob ) {
		$la_banner = array(
			'icon'      => 'lock',
			'title'     => __( 'One quick win: enable Two-Factor Auth.', 'login-armor' ),
			'body'      => __( 'Biggest single lift to your security score. Takes about 2 minutes per user.', 'login-armor' ),
			'cta_url'   => add_query_arg( array( 'page' => 'login-armor', 'tab' => 'settings' ), admin_url( 'admin.php' ) ) . '#two-factor',
			'cta_label' => __( 'Set up 2FA →', 'login-armor' ),
			'key'       => '2fa_cta',
			'skippable' => false,
		);
	} elseif ( $la_advice ) {
		$la_banner = array_merge( (array) $la_advice, array( 'skippable' => true ) );
	}
	if ( $la_banner ) :
	?>
		<div class="la-action-banner"<?php echo ! empty( $la_banner['skippable'] ) ? ' data-la-advice data-la-advice-key="' . esc_attr( (string) $la_banner['key'] ) . '"' : ''; ?>>
			<div class="la-action-banner__icon">
				<?php \LoginArmor\Icons::render( (string) ( $la_banner['icon'] ?? 'alert-triangle' ), '', 18, 2.5 ); ?>
			</div>
			<div class="la-action-banner__txt">
				<b><?php echo esc_html( (string) $la_banner['title'] ); ?></b>
				<p><?php echo esc_html( (string) $la_banner['body'] ); ?></p>
			</div>
			<div class="la-action-banner__actions">
				<a class="la-action-banner__cta" href="<?php echo esc_url( (string) $la_banner['cta_url'] ); ?>">
					<?php echo esc_html( (string) $la_banner['cta_label'] ); ?>
				</a>
				<?php if ( ! empty( $la_banner['skippable'] ) ) : ?>
					<button type="button" class="la-action-banner__skip" data-la-advice-skip aria-label="<?php esc_attr_e( 'Skip this advice', 'login-armor' ); ?>">
						<?php \LoginArmor\Icons::render( 'x', '', 12 ); ?>
					</button>
				<?php endif; ?>
			</div>
		</div>
	<?php endif; ?>
</section>
