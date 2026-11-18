<?php
/**
 * LoginArmor Events tab: Lot 18 pixel-perfect redesign.
 *
 * Header kicker + count, 4-sum strip (total/success/failed/unique IPs),
 * filter bar, 6-col sticky table with avatar/UA, 26×26 pager.
 *
 * @package LoginArmor
 *
 * @var string $active_tab
 * @var string $admin_nonce
 * @var string $ajax_url
 */

// phpcs:disable WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use LoginArmor\Icons;

// phpcs:disable WordPress.Security.NonceVerification.Recommended -- Read-only filter routing on GET.
$la_status   = isset( $_GET['status'] ) ? sanitize_key( wp_unslash( $_GET['status'] ) ) : '';
$la_ip       = isset( $_GET['ip'] ) ? sanitize_text_field( wp_unslash( $_GET['ip'] ) ) : '';
$la_username = isset( $_GET['username'] ) ? sanitize_text_field( wp_unslash( $_GET['username'] ) ) : '';
$la_period   = isset( $_GET['period'] ) ? sanitize_key( wp_unslash( $_GET['period'] ) ) : '';
$la_source   = isset( $_GET['source'] ) ? sanitize_key( wp_unslash( $_GET['source'] ) ) : '';
if ( ! in_array( $la_source, array( 'app_password', 'login_form' ), true ) ) {
	$la_source = '';
}
$la_page_num = isset( $_GET['paged'] ) ? max( 1, (int) $_GET['paged'] ) : 1;
// phpcs:enable WordPress.Security.NonceVerification.Recommended

$la_per_page = 50;
$la_filters  = array(
	'status'   => $la_status,
	'ip'       => $la_ip,
	'username' => $la_username,
	'period'   => $la_period,
	'source'   => $la_source,
);

$la_total  = \LoginArmor\LoginLogs::count_filtered_logs( $la_filters );
$la_offset = ( $la_page_num - 1 ) * $la_per_page;
$la_rows   = \LoginArmor\LoginLogs::get_filtered_logs( $la_filters, $la_per_page, $la_offset );
$la_pages  = max( 1, (int) ceil( $la_total / $la_per_page ) );

// Sum-strip metrics: always in last 7 days, independent of active filters.
$la_sum_total    = \LoginArmor\LoginLogs::count_filtered_logs( array( 'period' => '7d' ) );
$la_sum_success  = \LoginArmor\LoginLogs::count_filtered_logs( array( 'status' => 'success', 'period' => '7d' ) );
$la_sum_failed   = \LoginArmor\LoginLogs::count_filtered_logs( array( 'status' => 'failed', 'period' => '7d' ) );
// Approximate unique-IPs from a bounded sample of recent rows.
$la_sum_sample   = \LoginArmor\LoginLogs::get_filtered_logs( array( 'period' => '7d' ), 500, 0 );
$la_unique_ips_m = array();
foreach ( $la_sum_sample as $la_s ) {
	if ( '' !== $la_s->ip ) {
		$la_unique_ips_m[ $la_s->ip ] = true;
	}
}
$la_sum_unique_ips = count( $la_unique_ips_m );

$la_base_url     = add_query_arg( array( 'page' => 'login-armor', 'tab' => 'events' ), admin_url( 'admin.php' ) );
$la_overview_url = add_query_arg( array( 'page' => 'login-armor', 'tab' => 'overview' ), admin_url( 'admin.php' ) );

/**
 * Short, human-readable User-Agent label. Guarded against re-declaration
 * because the file can be included multiple times in long admin sessions.
 */
/**
 * Translatable compact relative-time helper. Duplicated in activity.php
 * with a function_exists guard so either tab can be rendered first.
 */
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

if ( ! function_exists( 'login_armor_short_ua' ) ) {
	function login_armor_short_ua( string $ua ): string {
		if ( '' === $ua ) {
			return '';
		}
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

<div class="la-page-header">
	<div>
		<span class="la-kicker"><?php esc_html_e( 'Audit', 'login-armor' ); ?></span>
		<h2 id="la-events-title">
			<?php esc_html_e( 'Events', 'login-armor' ); ?>
			<span class="la-count">
				<?php
				echo wp_kses_post(
					sprintf(
						esc_html(
							/* translators: %s: total events in last 7 days (strong-wrapped). */
							_n( '%s event in the last 7 days', '%s events in the last 7 days', $la_sum_total, 'login-armor' )
						),
						'<b>' . esc_html( number_format_i18n( $la_sum_total ) ) . '</b>'
					)
				);
				?>
			</span>
		</h2>
		<p class="la-lead"><?php esc_html_e( 'A complete audit log: successful logins, failures, session refreshes. Filter, search, export for your records.', 'login-armor' ); ?></p>
	</div>
	<div class="la-page-header__actions">
		<span class="la-streaming"><?php esc_html_e( 'streaming', 'login-armor' ); ?></span>
		<button type="button" class="la-ghost-btn"
			data-la-action="events-export"
			data-la-status="<?php echo esc_attr( $la_status ); ?>"
			data-la-ip="<?php echo esc_attr( $la_ip ); ?>"
			data-la-username="<?php echo esc_attr( $la_username ); ?>"
			data-la-period="<?php echo esc_attr( $la_period ); ?>"
			data-la-source="<?php echo esc_attr( $la_source ); ?>">
			<?php Icons::render( 'download', '', 12 );?>
			<?php esc_html_e( 'Export CSV', 'login-armor' ); ?>
		</button>
		<a class="la-ghost-btn la-live-view-btn" href="<?php echo esc_url( $la_overview_url ); ?>">
			<span class="la-live-dot" aria-hidden="true"></span>
			<?php esc_html_e( 'Live view', 'login-armor' ); ?>
		</a>
	</div>
</div>

<div class="la-sum-strip">
	<div class="la-sum-box">
		<b><?php echo esc_html( number_format_i18n( $la_sum_total ) ); ?></b>
		<span><?php esc_html_e( 'Total (7d)', 'login-armor' ); ?></span>
	</div>
	<div class="la-sum-box la-sum-box--green">
		<b><?php echo esc_html( number_format_i18n( $la_sum_success ) ); ?></b>
		<span><?php esc_html_e( 'Successful', 'login-armor' ); ?></span>
	</div>
	<div class="la-sum-box la-sum-box--red">
		<b><?php echo esc_html( number_format_i18n( $la_sum_failed ) ); ?></b>
		<span><?php esc_html_e( 'Failed', 'login-armor' ); ?></span>
	</div>
	<div class="la-sum-box">
		<b><?php echo esc_html( number_format_i18n( $la_sum_unique_ips ) ); ?></b>
		<span><?php esc_html_e( 'Unique IPs', 'login-armor' ); ?></span>
	</div>
</div>

<div class="la-page-grid">
	<div>
		<form method="get" class="la-filter-bar">
			<input type="hidden" name="page" value="login-armor">
			<input type="hidden" name="tab" value="events">

			<div class="la-fb-field">
				<label for="la-evt-status"><?php esc_html_e( 'Status', 'login-armor' ); ?></label>
				<select id="la-evt-status" name="status">
					<option value="" <?php selected( $la_status, '' ); ?>><?php esc_html_e( 'All', 'login-armor' ); ?></option>
					<option value="success" <?php selected( $la_status, 'success' ); ?>><?php esc_html_e( 'Success', 'login-armor' ); ?></option>
					<option value="failed" <?php selected( $la_status, 'failed' ); ?>><?php esc_html_e( 'Failure', 'login-armor' ); ?></option>
					<option value="locked" <?php selected( $la_status, 'locked' ); ?>><?php esc_html_e( 'Blocked', 'login-armor' ); ?></option>
				</select>
			</div>

			<div class="la-fb-field">
				<label for="la-evt-source"><?php esc_html_e( 'Source', 'login-armor' ); ?></label>
				<select id="la-evt-source" name="source">
					<option value="" <?php selected( $la_source, '' ); ?>><?php esc_html_e( 'All', 'login-armor' ); ?></option>
					<option value="login_form" <?php selected( $la_source, 'login_form' ); ?>><?php esc_html_e( 'Login form', 'login-armor' ); ?></option>
					<option value="app_password" <?php selected( $la_source, 'app_password' ); ?>><?php esc_html_e( 'Application password', 'login-armor' ); ?></option>
				</select>
			</div>

			<div class="la-fb-field">
				<label for="la-evt-ip"><?php esc_html_e( 'IP', 'login-armor' ); ?></label>
				<input type="text" id="la-evt-ip" name="ip" value="<?php echo esc_attr( $la_ip ); ?>" placeholder="<?php echo esc_attr( sprintf( /* translators: %s: an example IP address. */ __( 'e.g. %s', 'login-armor' ), '192.0.2.1' ) ); ?>">
			</div>

			<div class="la-fb-field">
				<label for="la-evt-user"><?php esc_html_e( 'Username', 'login-armor' ); ?></label>
				<input type="text" id="la-evt-user" name="username" value="<?php echo esc_attr( $la_username ); ?>" placeholder="<?php esc_attr_e( 'e.g. admin', 'login-armor' ); ?>">
			</div>

			<div class="la-fb-field">
				<label for="la-evt-period"><?php esc_html_e( 'Period', 'login-armor' ); ?></label>
				<select id="la-evt-period" name="period">
					<option value="" <?php selected( $la_period, '' ); ?>><?php esc_html_e( 'All time', 'login-armor' ); ?></option>
					<option value="24h" <?php selected( $la_period, '24h' ); ?>><?php esc_html_e( 'Last 24h', 'login-armor' ); ?></option>
					<option value="7d" <?php selected( $la_period, '7d' ); ?>><?php esc_html_e( 'Last 7 days', 'login-armor' ); ?></option>
					<option value="30d" <?php selected( $la_period, '30d' ); ?>><?php esc_html_e( 'Last 30 days', 'login-armor' ); ?></option>
				</select>
			</div>

			<div class="la-fb-actions">
				<button type="submit" class="la-ghost-btn"><?php esc_html_e( 'Filter', 'login-armor' ); ?></button>
				<a class="la-ghost-btn" href="<?php echo esc_url( $la_base_url ); ?>"><?php esc_html_e( 'Reset', 'login-armor' ); ?></a>
			</div>
		</form>

		<?php if ( empty( $la_rows ) ) : ?>
			<?php if ( '' === $la_status && '' === $la_ip && '' === $la_username && '' === $la_period && '' === $la_source ) : ?>
				<div class="la-empty-hint"><?php esc_html_e( 'No events recorded yet. Login attempts (successes, failures, lockouts) will appear here as they happen.', 'login-armor' ); ?></div>
			<?php else : ?>
				<div class="la-empty-hint"><?php esc_html_e( 'No events match the current filters.', 'login-armor' ); ?></div>
			<?php endif; ?>
		<?php else : ?>
			<?php // 2.8.0: the table scrolls (max-height 720px), so it takes the focus to be scrolled from the keyboard, under the name of the page (axe: scrollable-region-focusable). ?>
			<div class="la-events-wrap" tabindex="0" role="region" aria-labelledby="la-events-title">
				<div class="la-evt-head">
					<span><?php esc_html_e( 'Time', 'login-armor' ); ?></span>
					<span><?php esc_html_e( 'Status', 'login-armor' ); ?></span>
					<span><?php esc_html_e( 'Source IP', 'login-armor' ); ?></span>
					<span><?php esc_html_e( 'User · action', 'login-armor' ); ?></span>
					<span><?php esc_html_e( 'User agent', 'login-armor' ); ?></span>
					<span style="text-align:right;"><?php esc_html_e( 'When', 'login-armor' ); ?></span>
				</div>

				<?php
				// 2.9.0: one query for the counters of every summary row of the page
				// (a transient is two options), instead of one read per row.
				$la_prime = array();
				foreach ( $la_rows as $la_row ) {
					if ( \LoginArmor\LoginLogs::APP_PASSWORD_THROTTLED === ( isset( $la_row->reason ) ? (string) $la_row->reason : '' ) ) {
						$la_prime[] = '_transient_login_armor_appfail_n_' . (int) $la_row->id;
						$la_prime[] = '_transient_timeout_login_armor_appfail_n_' . (int) $la_row->id;
					}
				}
				if ( array() !== $la_prime && function_exists( 'wp_prime_option_caches' ) ) {
					wp_prime_option_caches( $la_prime );
				}
				foreach ( $la_rows as $la_row ) :
					$la_reason     = isset( $la_row->reason ) ? (string) $la_row->reason : '';
					$la_pill_class = 'la-badge la-badge--fail';
					$la_pill_txt   = __( 'FAIL', 'login-armor' );
					$la_is_fail    = true;
					// V2.4.5: the stored error code is authoritative. Only fall
					// back to the username-based guess for pre-migration rows,
					// which have no reason recorded.
					$la_det_txt    = \LoginArmor\LoginLogs::failure_reason_label( $la_reason );
					if ( 'success' === $la_row->status ) {
						$la_pill_class = 'la-badge la-badge--ok';
						$la_pill_txt   = __( 'OK', 'login-armor' );
						$la_is_fail    = false;
						$la_det_txt    = __( 'Successful sign-in', 'login-armor' );
					} elseif ( 'locked' === $la_row->status ) {
						$la_pill_class = 'la-badge la-badge--lock';
						$la_pill_txt   = __( 'BLOCKED', 'login-armor' );
						// 2.9.0: an application-password refusal keeps its own
						// label from a locked address: "Rate-limited" would hide
						// where it came from.
						if ( ! str_starts_with( $la_reason, 'app_password_' ) ) {
							$la_det_txt = __( 'Rate-limited', 'login-armor' );
						}
					} elseif ( '' === $la_reason && '' === (string) $la_row->username ) {
						$la_det_txt = __( 'Unknown user', 'login-armor' );
					}
					if ( \LoginArmor\LoginLogs::APP_PASSWORD_THROTTLED === $la_reason ) {
						$la_throttled = \LoginArmor\LoginLogs::throttled_count( (int) $la_row->id );
						if ( $la_throttled > 0 ) {
							$la_det_txt .= ' ' . sprintf(
								/* translators: %d: number of failures that were counted but not logged. */
								_n( '(%d more failure not logged)', '(%d more failures not logged)', $la_throttled, 'login-armor' ),
								$la_throttled
							);
						}
					}

					$la_ts         = strtotime( $la_row->log_time . ' UTC' );
					$la_time_short = $la_ts ? wp_date( 'H:i:s', $la_ts ) : (string) $la_row->log_time;
					$la_date_short = $la_ts ? mysql2date( 'M j', gmdate( 'Y-m-d H:i:s', $la_ts ), true ) : '';
					$la_ago        = login_armor_time_ago( (string) $la_row->log_time );

					$la_user_name  = '' === (string) $la_row->username ? '-' : (string) $la_row->username;
					$la_avatar_ltr = '-' === $la_user_name ? '?' : mb_strtoupper( mb_substr( $la_user_name, 0, 1 ) );

					$la_ua_short = isset( $la_row->user_agent ) ? login_armor_short_ua( (string) $la_row->user_agent ) : '';
					?>
					<div class="la-evt-row">
						<span class="la-evt-t la-mono">
							<?php echo esc_html( $la_time_short ); ?>
							<small><?php echo esc_html( $la_date_short ); ?></small>
						</span>
						<span>
							<span class="<?php echo esc_attr( $la_pill_class ); ?>"><?php echo esc_html( $la_pill_txt ); ?></span>
						</span>
						<span class="la-evt-ip la-mono">
							<?php Icons::render( 'globe', '', 12 );?>
							<?php echo esc_html( (string) $la_row->ip ); ?>
							<?php
							if ( '' !== (string) $la_row->ip && class_exists( '\LoginArmor\GeoIP' ) ) {
								echo wp_kses(
									\LoginArmor\GeoIP::badge_html( (string) $la_row->ip, true ),
									array( 'span' => array( 'class' => array(), 'title' => array() ) )
								);
							}
							?>
						</span>
						<span class="la-evt-user<?php echo $la_is_fail ? ' is-fail' : ''; ?>">
							<span class="la-evt-avatar"><?php echo esc_html( $la_avatar_ltr ); ?></span>
							<span class="la-evt-detail">
								<b><?php echo esc_html( $la_user_name ); ?></b>
								<small class="<?php echo $la_is_fail ? 'is-bad' : ''; ?>"><?php echo esc_html( $la_det_txt ); ?></small>
							</span>
						</span>
						<span class="la-evt-ua">
							<?php if ( '' !== $la_ua_short ) : ?>
								<?php Icons::render( 'monitor', '', 12 );?>
								<?php echo esc_html( $la_ua_short ); ?>
							<?php else : ?>
								<span style="color:var(--la-slate-500);">·</span>
							<?php endif; ?>
						</span>
						<span class="la-evt-when la-mono"><?php echo esc_html( $la_ago ); ?></span>
					</div>
				<?php endforeach; ?>

				<?php if ( $la_pages > 1 ) :
					$la_window_start = max( 1, $la_page_num - 3 );
					$la_window_end   = min( $la_pages, $la_page_num + 3 );
					$la_showing_from = $la_offset + 1;
					$la_showing_to   = min( $la_offset + $la_per_page, $la_total );
					$la_link_args    = array(
						'status'   => $la_status,
						'ip'       => $la_ip,
						'username' => $la_username,
						'period'   => $la_period,
						'source'   => $la_source,
					);
					$la_page_url = static function ( int $p ) use ( $la_link_args, $la_base_url ) {
						return add_query_arg( array_merge( $la_link_args, array( 'paged' => $p ) ), $la_base_url );
					};
					?>
					<div class="la-evt-foot">
						<span>
							<?php
							echo wp_kses_post(
								sprintf(
									/* translators: 1: window start, 2: window end, 3: total. */
									esc_html__( 'Showing %1$s of %2$s', 'login-armor' ),
									'<b>' . esc_html( number_format_i18n( $la_showing_from ) ) . '-' . esc_html( number_format_i18n( $la_showing_to ) ) . '</b>',
									'<b>' . esc_html( number_format_i18n( $la_total ) ) . '</b>'
								)
							);
							?>
						</span>
						<div class="la-pager">
							<?php if ( $la_page_num > 1 ) : ?>
								<a class="la-pager__btn" href="<?php echo esc_url( $la_page_url( $la_page_num - 1 ) ); ?>" aria-label="<?php esc_attr_e( 'Previous page', 'login-armor' ); ?>">‹</a>
							<?php else : ?>
								<span class="la-pager__btn" aria-disabled="true" style="opacity:.4;">‹</span>
							<?php endif; ?>
							<?php for ( $la_p = $la_window_start; $la_p <= $la_window_end; $la_p++ ) : ?>
								<?php if ( $la_p === $la_page_num ) : ?>
									<span class="la-pager__btn is-active"><?php echo esc_html( (string) $la_p ); ?></span>
								<?php else : ?>
									<a class="la-pager__btn" href="<?php echo esc_url( $la_page_url( $la_p ) ); ?>"><?php echo esc_html( (string) $la_p ); ?></a>
								<?php endif; ?>
							<?php endfor; ?>
							<?php if ( $la_page_num < $la_pages ) : ?>
								<a class="la-pager__btn" href="<?php echo esc_url( $la_page_url( $la_page_num + 1 ) ); ?>" aria-label="<?php esc_attr_e( 'Next page', 'login-armor' ); ?>">›</a>
							<?php else : ?>
								<span class="la-pager__btn" aria-disabled="true" style="opacity:.4;">›</span>
							<?php endif; ?>
						</div>
					</div>
				<?php else : ?>
					<div class="la-evt-foot">
						<span>
							<?php
							echo wp_kses_post(
								sprintf(
									/* translators: %s: total events. */
									esc_html__( 'Showing all %s events', 'login-armor' ),
									'<b>' . esc_html( number_format_i18n( $la_total ) ) . '</b>'
								)
							);
							?>
						</span>
					</div>
				<?php endif; ?>
			</div>
		<?php endif; ?>
	</div>

	<aside>
		<?php
		$la_guide_file = LOGIN_ARMOR_DIR . 'admin/views/sidebar/events.php';
		if ( file_exists( $la_guide_file ) ) {
			echo '<div class="la-guide">';
			include $la_guide_file;
			echo '</div>';
		}
		include LOGIN_ARMOR_DIR . 'admin/views/sidebar/sponsored-ads.php';
		?>
	</aside>
</div>
