<?php
/**
 * LoginArmor: WP Dashboard widget (Lot 18 V8 redesign).
 *
 * Five stacked sections:
 *   1. WP header (native: handled by WP).
 *   2. Dark navy hero with big 7-day attack count + sparkline.
 *   3. 2×4 modules grid: color-coded state chips linking to Settings.
 *   4. Next-step CTA banner (amber if a gap, green if all active).
 *   5. Footer with two links (View events / Open Login Armor).
 *
 * @package LoginArmor
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

// phpcs:disable WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound

/* -----------------------------------------------------------------
 * 1: Activity data (last 14 days, split into current + previous 7-day windows).
 * ----------------------------------------------------------------- */

$la_daily = class_exists( '\LoginArmor\LoginLogs' )
	? \LoginArmor\LoginLogs::get_daily_chart_data( 14 )
	: array();

// get_daily_chart_data returns a date-keyed assoc ordered ASC (oldest first).
$la_values    = array_values( $la_daily );
$la_values    = array_map( 'intval', $la_values );
$la_total     = count( $la_values );
$la_spark     = $la_total >= 7 ? array_slice( $la_values, -7 ) : array_pad( $la_values, 7, 0 );
$la_prev_week = $la_total >= 14 ? array_slice( $la_values, -14, 7 ) : array_fill( 0, 7, 0 );

$la_blocked_7d   = array_sum( $la_spark );
$la_blocked_prev = array_sum( $la_prev_week );

if ( $la_blocked_prev > 0 ) {
	$la_trend_pct = (int) round( ( ( $la_blocked_7d - $la_blocked_prev ) / $la_blocked_prev ) * 100 );
} elseif ( $la_blocked_7d > 0 ) {
	$la_trend_pct = 100;
} else {
	$la_trend_pct = 0;
}

/* -----------------------------------------------------------------
 * 2: Last event relative time (translatable compact form).
 * ----------------------------------------------------------------- */

global $wpdb;
// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
$la_last_event = $wpdb->get_var(
	$wpdb->prepare(
		"SELECT log_time FROM {$wpdb->prefix}login_armor_logs WHERE status IN (%s, %s) ORDER BY id DESC LIMIT 1",
		'failed',
		'locked'
	)
);

$la_last_ago = '-';
if ( $la_last_event ) {
	$la_ts = strtotime( (string) $la_last_event . ' UTC' );
	if ( $la_ts ) {
		$la_diff = max( 0, time() - $la_ts );
		if ( $la_diff < 60 ) {
			/* translators: %d: number of seconds, short compact form. */
			$la_last_ago = sprintf( __( '%ds ago', 'login-armor' ), $la_diff );
		} elseif ( $la_diff < 3600 ) {
			/* translators: %d: number of minutes, short compact form. */
			$la_last_ago = sprintf( __( '%dm ago', 'login-armor' ), (int) floor( $la_diff / 60 ) );
		} elseif ( $la_diff < 86400 ) {
			/* translators: %d: number of hours, short compact form. */
			$la_last_ago = sprintf( __( '%dh ago', 'login-armor' ), (int) floor( $la_diff / 3600 ) );
		} else {
			/* translators: %d: number of days, short compact form. */
			$la_last_ago = sprintf( __( '%dd ago', 'login-armor' ), (int) floor( $la_diff / 86400 ) );
		}
	}
}

/* -----------------------------------------------------------------
 * 3: Sparkline SVG path build (viewBox 240×32, 7 points).
 * ----------------------------------------------------------------- */

$la_spark_max = max( 1, max( $la_spark ) );
$la_points    = array();
foreach ( $la_spark as $la_i => $la_v ) {
	$la_x = $la_i * 40; // 240 / (7-1) = 40
	// Normalize into 4..44 (y) inside a 48-unit viewBox, invert (y=0 top).
	// 48 tall instead of 32 so a quiet-then-spike week actually reads as
	// a spike instead of a flat line: feedback V10.12.
	$la_y = 44 - ( ( $la_v / $la_spark_max ) * 40 );
	$la_points[ $la_i ] = array( round( $la_x, 2 ), round( $la_y, 2 ) );
}
$la_line_d = 'M ' . implode( ' L ', array_map(
	static function ( $p ) { return $p[0] . ',' . $p[1]; },
	$la_points
) );
$la_area_d = 'M 0,48 L ' . implode( ' L ', array_map(
	static function ( $p ) { return $p[0] . ',' . $p[1]; },
	$la_points
) ) . ' L 240,48 Z';

// Today is always the rightmost point: we want a "you are here" dot on
// today's value regardless of whether it's the max. The historical peak
// (if not today) gets a smaller secondary marker so the user sees both
// "what just happened" and "what the worst day was" without confusing
// the two. Previously only the max day got a marker, which landed on
// the leftmost point when prior testing had produced a bigger spike,
// reading as if the chart was backwards. (V10.16)
$la_today_idx = count( $la_spark ) - 1;
$la_today_val = (int) $la_spark[ $la_today_idx ];
$la_today     = $la_points[ $la_today_idx ];

$la_peak_idx = 0;
$la_peak_val = -1;
foreach ( $la_spark as $la_i => $la_v ) {
	if ( $la_v > $la_peak_val ) { // strict > so today wins ties.
		$la_peak_val = $la_v;
		$la_peak_idx = $la_i;
	}
}
// Only surface a historical-peak marker when the peak is NOT today and
// actually has some value.
$la_show_historical_peak = ( $la_peak_idx !== $la_today_idx ) && ( $la_peak_val > 0 );
$la_peak = $la_points[ $la_peak_idx ];

/* -----------------------------------------------------------------
 * 4: 8 modules (name, icon, state, status_text, link).
 * ----------------------------------------------------------------- */

$la_settings_url = add_query_arg(
	array( 'page' => 'login-armor', 'tab' => 'settings' ),
	admin_url( 'admin.php' )
);

$la_hard_settings = class_exists( '\LoginArmor\Hardening' ) ? \LoginArmor\Hardening::get_settings() : array();
$la_hard_toggles  = class_exists( '\LoginArmor\Hardening' ) ? \LoginArmor\Hardening::get_toggles() : array();
// 2.9.0: in headless mode the guarded toggles are not a choice: not counted.
$la_hard_excl     = class_exists( '\LoginArmor\SecurityScore' ) ? \LoginArmor\SecurityScore::hardening_excluded_keys() : array();
$la_hard_toggles  = array_values( array_filter( $la_hard_toggles, static fn( $la_t ) => ! in_array( $la_t['key'], $la_hard_excl, true ) ) );
$la_hard_active   = count( array_filter( $la_hard_settings, static fn( $la_v, $la_k ) => ! empty( $la_v ) && ! in_array( $la_k, $la_hard_excl, true ), ARRAY_FILTER_USE_BOTH ) );
$la_hard_total    = max( 1, count( $la_hard_toggles ) );

if ( 0 === $la_hard_active )               { $la_hard_state = 'off';  $la_hard_status = __( 'Off', 'login-armor' ); }
elseif ( $la_hard_active === $la_hard_total ) { $la_hard_state = 'on';   $la_hard_status = __( 'All on', 'login-armor' ); }
else                                        { $la_hard_state = 'warn'; $la_hard_status = $la_hard_active . ' / ' . $la_hard_total; }

$la_hide_on   = class_exists( '\LoginArmor\HideLogin' ) && \LoginArmor\HideLogin::is_enabled();
$la_limit_on  = (bool) get_option( 'login_armor_limit_enabled', true );
$la_det_on    = (bool) get_option( 'login_armor_detection_enabled', true );
$la_head_on   = class_exists( '\LoginArmor\LoginHeaders' ) && \LoginArmor\LoginHeaders::is_enabled();
$la_breach_on = class_exists( '\LoginArmor\BreachCheck' ) && \LoginArmor\BreachCheck::is_enabled();
$la_breach_counts = class_exists( '\LoginArmor\BreachCheck' ) ? \LoginArmor\BreachCheck::get_flagged_counts() : array( 'password' => 0, 'email' => 0 );
$la_breach_total  = (int) ( $la_breach_counts['password'] ?? 0 ) + (int) ( $la_breach_counts['email'] ?? 0 );
$la_act_on    = (bool) get_option( 'login_armor_activity_enabled', false );
$la_2fa_on    = (bool) get_option( 'login_armor_2fa_enabled', false );

$la_status_active = __( 'Active', 'login-armor' );
$la_status_off    = __( 'Off', 'login-armor' );

// Request Firewall state: surfaced as a small pill next to "PROTECTED" in the
// hero (not in the 8-module grid) so its on/off/mode reads at a glance.
$la_fw_enabled = class_exists( '\LoginArmor\Firewall\Firewall' ) && \LoginArmor\Firewall\Firewall::is_enabled();
$la_fw_mode    = class_exists( '\LoginArmor\Firewall\Firewall' ) ? \LoginArmor\Firewall\Firewall::effective_mode() : 'log_only';
if ( ! $la_fw_enabled ) {
	$la_fw_state = 'off';
	$la_fw_label = __( 'Firewall: off', 'login-armor' );
} elseif ( 'enforce' === $la_fw_mode ) {
	$la_fw_state = 'on';
	$la_fw_label = __( 'Firewall: blocking', 'login-armor' );
} else {
	$la_fw_state = 'warn';
	$la_fw_label = __( 'Firewall: monitoring', 'login-armor' );
}

$la_modules = array(
	array( 'name' => __( 'Hide Login', 'login-armor' ),  'icon' => 'shield',       'state' => $la_hide_on  ? 'on' : 'off', 'status' => $la_hide_on  ? $la_status_active : $la_status_off, 'anchor' => 'hide-login' ),
	array( 'name' => __( 'Brute Force', 'login-armor' ), 'icon' => 'circle-slash', 'state' => $la_limit_on ? 'on' : 'off', 'status' => $la_limit_on ? $la_status_active : $la_status_off, 'anchor' => 'limit-login' ),
	array( 'name' => __( 'Hardening', 'login-armor' ),   'icon' => 'lock',         'state' => $la_hard_state,              'status' => $la_hard_status,                                     'anchor' => 'hardening' ),
	array( 'name' => __( 'Detection', 'login-armor' ),   'icon' => 'eye',          'state' => $la_det_on   ? 'on' : 'off', 'status' => $la_det_on   ? $la_status_active : $la_status_off, 'anchor' => 'detection-logs' ),
	array( 'name' => __( 'Headers', 'login-armor' ),     'icon' => 'shield',       'state' => $la_head_on  ? 'on' : 'off', 'status' => $la_head_on  ? $la_status_active : $la_status_off, 'anchor' => 'login-headers' ),
	array(
		'name'   => __( 'Breach Check', 'login-armor' ),
		'icon'   => 'search',
		'state'  => $la_breach_on
			? ( $la_breach_total > 0 ? 'alert' : 'on' )
			: 'off',
		'status' => $la_breach_on
			? ( $la_breach_total > 0
				? sprintf(
					/* translators: %d: total number of accounts with a flagged password or email. */
					_n( '%d flagged', '%d flagged', $la_breach_total, 'login-armor' ),
					$la_breach_total
				)
				: $la_status_active
			)
			: $la_status_off,
		'anchor' => 'breach-check',
		'badge'  => $la_breach_on && $la_breach_total > 0,
	),
	array( 'name' => __( 'Activity', 'login-armor' ),    'icon' => 'pulse',        'state' => $la_act_on   ? 'on' : 'off', 'status' => $la_act_on   ? $la_status_active : $la_status_off, 'anchor' => 'activity-log' ),
	array( 'name' => __( '2FA', 'login-armor' ),         'icon' => 'unlock',       'state' => $la_2fa_on   ? 'on' : 'off', 'status' => $la_2fa_on   ? $la_status_active : $la_status_off, 'anchor' => 'two-factor' ),
);

/* -----------------------------------------------------------------
 * 5: Next-step CTA (gap vs all-active variants).
 * ----------------------------------------------------------------- */

$la_gap_candidates = array(
	array( 'opt' => 'login_armor_2fa_enabled',           'name' => __( '2FA', 'login-armor' ),           'points' => 20, 'anchor' => 'two-factor' ),
	array( 'opt' => 'login_armor_hide_enabled',          'name' => __( 'Hide Login', 'login-armor' ),    'points' => 15, 'anchor' => 'hide-login' ),
	array( 'opt' => 'login_armor_limit_enabled',         'name' => __( 'Brute Force', 'login-armor' ),   'points' => 15, 'anchor' => 'limit-login' ),
	array( 'opt' => 'login_armor_login_headers_enabled', 'name' => __( 'Login Headers', 'login-armor' ), 'points' => 10, 'anchor' => 'login-headers' ),
	array( 'opt' => 'login_armor_detection_enabled',     'name' => __( 'Detection', 'login-armor' ),     'points' => 10, 'anchor' => 'detection-logs' ),
	array( 'opt' => 'login_armor_activity_enabled',      'name' => __( 'Activity Log', 'login-armor' ),  'points' => 10, 'anchor' => 'activity-log' ),
	array( 'opt' => 'login_armor_breach_check_enabled',  'name' => __( 'Breach Check', 'login-armor' ),  'points' => 10, 'anchor' => 'breach-check' ),
);

$la_top_gap = null;
foreach ( $la_gap_candidates as $la_c ) {
	if ( ! get_option( $la_c['opt'] ) ) {
		$la_top_gap = $la_c;
		break;
	}
}

/* -----------------------------------------------------------------
 * 6: Icon paths (inline Lucide SVG, fallback to the Icons helper).
 * ----------------------------------------------------------------- */

$la_render_icon = static function ( string $name ): void {
	if ( class_exists( '\LoginArmor\Icons' ) ) {
		\LoginArmor\Icons::render( $name, 'la-widget__mod-icon-svg', 20, 2 );
	}
};

$la_events_url = add_query_arg( array( 'page' => 'login-armor', 'tab' => 'events' ), admin_url( 'admin.php' ) );
$la_root_url   = add_query_arg( array( 'page' => 'login-armor' ), admin_url( 'admin.php' ) );
?>
<div class="la-widget">

	<!-- SECTION 1: WP header is rendered by WordPress, nothing to emit here. -->

	<!-- SECTION 2: HERO -->
	<div class="la-widget__hero">
		<div class="la-widget__hero-top">
			<span class="la-widget__badges">
				<span class="la-widget__pill">
					<span class="la-widget__pill-dot" aria-hidden="true"></span>
					<?php esc_html_e( 'Protected', 'login-armor' ); ?>
				</span>
				<span class="la-widget__pill la-widget__pill--fw la-widget__pill--fw-<?php echo esc_attr( $la_fw_state ); ?>">
					<span class="la-widget__pill-dot" aria-hidden="true"></span>
					<?php echo esc_html( $la_fw_label ); ?>
				</span>
			</span>
			<span class="la-widget__last">
				<?php
				/* translators: %s: short relative time like "4m ago". */
				echo esc_html( sprintf( __( 'Last event %s', 'login-armor' ), $la_last_ago ) );
				?>
			</span>
		</div>

		<div class="la-widget__hero-main">
			<?php
			/* translators: %d: number of attacks blocked in the last 7 days. */
			$la_count_label = sprintf( __( '%d attacks blocked in the last 7 days', 'login-armor' ), $la_blocked_7d );
			?>
			<div class="la-widget__count" aria-label="<?php echo esc_attr( $la_count_label ); ?>">
				<b><?php echo esc_html( (string) $la_blocked_7d ); ?></b>
				<span><?php esc_html_e( 'attacks blocked', 'login-armor' ); ?></span>
			</div>
			<div class="la-widget__trend">
				<span class="la-widget__trend-label"><?php esc_html_e( 'Past 7 days', 'login-armor' ); ?></span>
				<span class="la-widget__trend-delta la-widget__trend-delta--<?php echo $la_trend_pct < 0 ? 'down' : ( $la_trend_pct > 0 ? 'up' : 'flat' ); ?>">
					<?php
					if ( 0 === $la_trend_pct ) {
						esc_html_e( '→ flat', 'login-armor' );
					} else {
						echo $la_trend_pct < 0 ? '↓ ' : '↑ ';
						/* translators: %d: percent difference vs previous 7-day window. */
						echo esc_html( sprintf( __( '%d%% vs prev', 'login-armor' ), abs( $la_trend_pct ) ) );
					}
					?>
				</span>
			</div>
			<!-- trend text is upper-cased by CSS (text-transform) so the data stays readable in HTML. -->
		</div>

		<?php
		$la_trend_word = $la_trend_pct < 0 ? __( 'fewer', 'login-armor' ) : __( 'more', 'login-armor' );
		$la_trend_aria = sprintf(
			/* translators: 1: absolute percent difference, 2: "fewer" or "more" word. */
			__( 'Trend: %1$d%% %2$s attacks than previous week', 'login-armor' ),
			abs( $la_trend_pct ),
			$la_trend_word
		);
		?>
		<?php
		/*
		 * 2.7.1 - same treatment as the Overview chart, and for the same reason,
		 * although nobody has complained about this one yet. With
		 * preserveAspectRatio="none" the two axes are scaled independently, so a
		 * <circle> in here is only ever as round as the box happens to be. This
		 * widget was not correct, it was lucky, and measurement says it was not
		 * even that: in a two-column dashboard the 240 x 48 viewBox renders about
		 * 390 x 48, so x is scaled 1.63 and y 1.00 and the "today" dot comes out
		 * 11.8 x 7.3 px, wider than it is tall by more than half. It reads as a
		 * dot only because it is small and sits on a thin strip. A dashboard
		 * column of another width moves that number, never towards 1. The markers
		 * are therefore ordinary elements over the strip, placed in percent of the
		 * same box, and the wrapper below is what they are positioned against.
		 */
		$la_spark_dots = array();
		if ( $la_show_historical_peak ) {
			$la_spark_dots[] = array(
				'class' => 'la-widget__spark-peak--past',
				'point' => $la_peak,
				/* translators: %d: attack count on the peak day of the current 7-day window. */
				'title' => sprintf( __( 'Peak this week: %d', 'login-armor' ), $la_peak_val ),
			);
		}
		if ( $la_today_val > 0 ) {
			$la_spark_dots[] = array(
				'class' => 'la-widget__spark-peak--today',
				'point' => $la_today,
				/* translators: %d: attacks blocked today so far. */
				'title' => sprintf( __( 'Today: %d', 'login-armor' ), $la_today_val ),
			);
		}
		?>
		<div class="la-widget__spark-wrap">
			<svg class="la-widget__spark" viewBox="0 0 240 48" preserveAspectRatio="none"
				role="img"
				aria-label="<?php echo esc_attr( $la_trend_aria ); ?>">
				<defs>
					<linearGradient id="la-widget-spark-fill" x1="0" x2="0" y1="0" y2="1">
						<stop offset="0" stop-color="#10b981" stop-opacity="0.4"/>
						<stop offset="1" stop-color="#10b981" stop-opacity="0"/>
					</linearGradient>
				</defs>
				<path class="la-widget__spark-area" d="<?php echo esc_attr( $la_area_d ); ?>" fill="url(#la-widget-spark-fill)"/>
				<path class="la-widget__spark-line" d="<?php echo esc_attr( $la_line_d ); ?>" fill="none" stroke="#10b981" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round"/>
			</svg>
			<?php foreach ( $la_spark_dots as $la_dot ) : ?>
				<span
					class="la-widget__spark-peak <?php echo esc_attr( $la_dot['class'] ); ?>"
					title="<?php echo esc_attr( $la_dot['title'] ); ?>"
					aria-hidden="true"
					style="--la-dot-x:<?php echo esc_attr( (string) round( ( $la_dot['point'][0] / 240 ) * 100, 2 ) ); ?>%;--la-dot-y:<?php echo esc_attr( (string) round( ( $la_dot['point'][1] / 48 ) * 100, 2 ) ); ?>%"
				></span>
			<?php endforeach; ?>
		</div>

		<div class="la-widget__spark-meta">
			<?php
			/* translators: %d: number of days, short compact form. */
			$la_sixd_ago = sprintf( __( '%dd ago', 'login-armor' ), 6 );
			?>
			<span><?php echo esc_html( $la_sixd_ago ); ?></span>
			<span><?php esc_html_e( 'Today', 'login-armor' ); ?></span>
		</div>
	</div>

	<!-- SECTION 3: MODULES GRID 2×4 -->
	<div class="la-widget__grid">
		<?php foreach ( $la_modules as $la_m ) : ?>
			<a class="la-widget__mod la-widget__mod--<?php echo esc_attr( $la_m['state'] ); ?><?php echo ! empty( $la_m['badge'] ) ? ' la-widget__mod--has-badge' : ''; ?>"
			   href="<?php echo esc_url( $la_settings_url . '#' . $la_m['anchor'] ); ?>">
				<span class="la-widget__mod-icon">
					<?php $la_render_icon( $la_m['icon'] ); ?>
					<?php if ( ! empty( $la_m['badge'] ) ) : ?>
						<span class="la-widget__mod-badge" aria-hidden="true"></span>
					<?php endif; ?>
				</span>
				<b><?php echo esc_html( $la_m['name'] ); ?></b>
				<span class="la-widget__mod-state"><?php echo esc_html( $la_m['status'] ); ?></span>
			</a>
		<?php endforeach; ?>
	</div>

	<!-- SECTION 4: NEXT-STEP CTA BANNER -->
	<?php if ( $la_top_gap ) : ?>
		<div class="la-widget__cta la-widget__cta--amber">
			<span class="la-widget__cta-icon" aria-hidden="true">
				<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
					<polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/>
				</svg>
			</span>
			<div class="la-widget__cta-text">
				<?php
				/* translators: %s: module name (e.g. 2FA, Hide Login). */
				$la_cta_title = sprintf( __( 'Quick win: enable %s', 'login-armor' ), $la_top_gap['name'] );
				/* translators: %d: security score points gained by enabling this module. */
				$la_cta_hint  = sprintf( __( 'Closes the biggest remaining gap. +%d points to your security score.', 'login-armor' ), (int) $la_top_gap['points'] );
				?>
				<b><?php echo esc_html( $la_cta_title ); ?></b>
				<span><?php echo esc_html( $la_cta_hint ); ?></span>
			</div>
			<a class="la-widget__cta-btn" href="<?php echo esc_url( $la_settings_url . '#' . $la_top_gap['anchor'] ); ?>"><?php esc_html_e( 'Set up', 'login-armor' ); ?></a>
		</div>
	<?php else : ?>
		<div class="la-widget__cta la-widget__cta--success">
			<span class="la-widget__cta-icon" aria-hidden="true">
				<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
					<path d="M20 6 9 17l-5-5"/>
				</svg>
			</span>
			<div class="la-widget__cta-text">
				<b><?php esc_html_e( 'All defenses active.', 'login-armor' ); ?></b>
				<span><?php esc_html_e( 'Keep Login Armor up to date.', 'login-armor' ); ?></span>
			</div>
		</div>
	<?php endif; ?>

	<!-- SECTION 5: FOOTER -->
	<div class="la-widget__foot">
		<a class="la-widget__foot-left" href="<?php echo esc_url( $la_events_url ); ?>">
			<svg viewBox="0 0 24 24" width="11" height="11" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
				<circle cx="11" cy="11" r="7"/>
				<path d="m21 21-4.3-4.3"/>
			</svg>
			<?php esc_html_e( 'View events', 'login-armor' ); ?>
		</a>
		<a class="la-widget__foot-right" href="<?php echo esc_url( $la_root_url ); ?>">
			<?php esc_html_e( 'Open Login Armor', 'login-armor' ); ?>
			<span class="la-widget__foot-arrow" aria-hidden="true">→</span>
		</a>
	</div>

</div>
