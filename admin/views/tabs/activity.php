<?php
/**
 * LoginArmor Activity tab: Lot 18 pixel-perfect redesign.
 *
 * 5-col admin-action table (time / user / action / object / IP) with
 * colored action pills (ROTATED/UPDATED → info blue, CHANGED → warn,
 * ENABLED → ok, DELETED → fail). Object cell uses a kind label + mono
 * code chip. No pagination footer → flat list like the handoff.
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

require_once LOGIN_ARMOR_DIR . 'includes/ActivityLog/ActivityLog.php';

$la_act_enabled = \LoginArmor\ActivityLog\ActivityLog::is_enabled();

if ( ! $la_act_enabled ) : ?>
	<div class="la-page-header">
		<div>
			<span class="la-kicker"><?php esc_html_e( 'Activity', 'login-armor' ); ?></span>
			<h2><?php esc_html_e( 'Activity', 'login-armor' ); ?></h2>
			<p class="la-lead"><?php esc_html_e( 'Admin actions across your site: plugin installs, user edits, option changes.', 'login-armor' ); ?></p>
		</div>
	</div>
	<div class="la-empty-hint" style="padding: 48px 20px;">
		<p style="margin: 0 0 14px;"><?php esc_html_e( 'Activity logging is disabled. Enable it in Settings to start tracking admin actions.', 'login-armor' ); ?></p>
		<a class="la-primary-btn" href="<?php echo esc_url( add_query_arg( [ 'page' => 'login-armor', 'tab' => 'settings' ], admin_url( 'admin.php' ) ) . '#activity-log' ); ?>">
			<?php esc_html_e( 'Go to Settings', 'login-armor' ); ?>
		</a>
	</div>
<?php
	return;
endif;

// phpcs:disable WordPress.Security.NonceVerification.Recommended -- Read-only filter routing on GET.
$la_act_type    = isset( $_GET['object_type'] ) ? sanitize_key( wp_unslash( $_GET['object_type'] ) ) : '';
$la_act_user    = isset( $_GET['user_id'] ) ? absint( wp_unslash( $_GET['user_id'] ) ) : 0;
$la_act_period  = isset( $_GET['period'] ) ? sanitize_key( wp_unslash( $_GET['period'] ) ) : '';
$la_act_page    = isset( $_GET['paged'] ) ? max( 1, (int) $_GET['paged'] ) : 1;
// phpcs:enable WordPress.Security.NonceVerification.Recommended

$la_act_per_page = 50;
$la_act_filters  = [
	'object_type' => $la_act_type,
	'user_id'     => $la_act_user > 0 ? (string) $la_act_user : '',
	'period'      => $la_act_period,
];

$la_act_total  = \LoginArmor\ActivityLog\ActivityLog::count_logs( $la_act_filters );
$la_act_offset = ( $la_act_page - 1 ) * $la_act_per_page;
$la_act_rows   = \LoginArmor\ActivityLog\ActivityLog::get_logs( $la_act_filters, $la_act_per_page, $la_act_offset );
$la_act_pages  = max( 1, (int) ceil( $la_act_total / $la_act_per_page ) );

$la_act_base_url = add_query_arg( [ 'page' => 'login-armor', 'tab' => 'activity' ], admin_url( 'admin.php' ) );
$la_act_users    = \LoginArmor\ActivityLog\ActivityLog::get_admin_users();

// Sum-strip metrics: last 7 days, independent of active filters.
$la_act_sum_7d    = \LoginArmor\ActivityLog\ActivityLog::count_logs( [ 'period' => '7d' ] );
$la_act_sum_total = \LoginArmor\ActivityLog\ActivityLog::count_logs( [] );

global $wpdb;
$la_act_tbl    = $wpdb->prefix . 'login_armor_activity';
$la_act_since  = gmdate( 'Y-m-d H:i:s', current_time( 'timestamp', true ) - ( 7 * 86400 ) );

// Distinct users (7d).
// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,PluginCheck.Security.DirectDB.UnescapedDBParameter -- $la_act_tbl is $wpdb->prefix + hard-coded suffix; freshness-sensitive summary, caching would stale the numbers.
$la_act_sum_users = (int) $wpdb->get_var(
	$wpdb->prepare(
		"SELECT COUNT(DISTINCT user_id) FROM {$la_act_tbl} WHERE log_time >= %s AND user_id > 0", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared,PluginCheck.Security.DirectDB.UnescapedDBParameter
		$la_act_since
	)
);

// Plugin / theme changes (7d).
// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,PluginCheck.Security.DirectDB.UnescapedDBParameter -- same rationale as above.
$la_act_sum_plugins = (int) $wpdb->get_var(
	$wpdb->prepare(
		"SELECT COUNT(*) FROM {$la_act_tbl} WHERE log_time >= %s AND object_type IN ('plugin', 'theme')", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared,PluginCheck.Security.DirectDB.UnescapedDBParameter
		$la_act_since
	)
);

// Config rotations (7d): salt rotations + generic "rotat" verbs.
// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,PluginCheck.Security.DirectDB.UnescapedDBParameter -- same rationale as above.
$la_act_sum_rotations = (int) $wpdb->get_var(
	$wpdb->prepare(
		"SELECT COUNT(*) FROM {$la_act_tbl} WHERE log_time >= %s AND (action LIKE %s OR action = %s)", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared,PluginCheck.Security.DirectDB.UnescapedDBParameter
		$la_act_since,
		'%rotat%',
		'salt_rotated'
	)
);

/**
 * Map an action verb (usually an "_"-separated string ending in the verb)
 * to a pill CSS class. Falls back to neutral.
 */
if ( ! function_exists( 'login_armor_activity_pill_class' ) ) {
	function login_armor_activity_pill_class( string $verb ): string {
		$v = strtolower( $verb );
		if ( str_contains( $v, 'delete' ) || str_contains( $v, 'trash' ) )                { return 'fail'; }
		if ( str_contains( $v, 'change' ) || str_contains( $v, 'deactivat' )
			|| str_contains( $v, 'detect' ) )                                             { return 'warn'; }
		if ( str_contains( $v, 'enable' )  || str_contains( $v, 'activat' )
			|| str_contains( $v, 'create' ) || str_contains( $v, 'restore' )
			|| str_contains( $v, 'upload' ) || str_contains( $v, 'approve' ) )            { return 'ok'; }
		if ( str_contains( $v, 'rotat' )   || str_contains( $v, 'update' )
			|| str_contains( $v, 'install' ) )                                            { return 'info'; }
		return 'neutral';
	}
}

/**
 * Translatable compact relative-time helper used across the activity and
 * events tabs. Uses short forms ("5h ago", "2d ago") so the table cells
 * stay narrow; each unit is its own msgid so translators can pick the
 * right abbreviation in French / German / etc. without %s stitching.
 *
 * function_exists guard so events.php and activity.php can both include
 * this file without a redeclare error.
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

/**
 * Translatable label for an Activity Log action verb (CHANGED / UPDATED /
 * ROTATED / ENABLED / …). The verb comes from the DB in lowercase and is
 * uppercased by the renderer, so the msgids are uppercase-English.
 *
 * Unknown verbs fall back to their uppercased raw form.
 */
if ( ! function_exists( 'login_armor_action_label' ) ) {
	function login_armor_action_label( string $verb_upper ): string {
		switch ( $verb_upper ) {
			case 'CREATED':     return __( 'CREATED', 'login-armor' );
			case 'UPDATED':     return __( 'UPDATED', 'login-armor' );
			case 'DELETED':     return __( 'DELETED', 'login-armor' );
			case 'CHANGED':     return __( 'CHANGED', 'login-armor' );
			case 'ROTATED':     return __( 'ROTATED', 'login-armor' );
			case 'ENABLED':     return __( 'ENABLED', 'login-armor' );
			case 'DISABLED':    return __( 'DISABLED', 'login-armor' );
			case 'UPLOADED':    return __( 'UPLOADED', 'login-armor' );
			case 'INSTALLED':   return __( 'INSTALLED', 'login-armor' );
			case 'ACTIVATED':   return __( 'ACTIVATED', 'login-armor' );
			case 'DEACTIVATED': return __( 'DEACTIVATED', 'login-armor' );
			case 'TRASHED':     return __( 'TRASHED', 'login-armor' );
			case 'RESTORED':    return __( 'RESTORED', 'login-armor' );
			case 'ENFORCED':    return __( 'ENFORCED', 'login-armor' );
			case 'VERIFIED':    return __( 'VERIFIED', 'login-armor' );
			case 'FAILED':      return __( 'FAILED', 'login-armor' );
			case 'INITIALIZED': return __( 'INITIALIZED', 'login-armor' );
			case 'USED':        return __( 'USED', 'login-armor' );
			case 'TRUSTED':     return __( 'TRUSTED', 'login-armor' );
			case 'REVOKED':     return __( 'REVOKED', 'login-armor' );
			case 'RECOVERY':    return __( 'RECOVERY', 'login-armor' );
			case 'REQUESTED':   return __( 'REQUESTED', 'login-armor' );
			case 'RESET':       return __( 'RESET', 'login-armor' );
			case 'BLOCKED':     return __( 'BLOCKED', 'login-armor' );
			case 'REGISTERED':  return __( 'REGISTERED', 'login-armor' );
			case 'LOCKED':      return __( 'LOCKED', 'login-armor' );
			case 'UNLOCKED':    return __( 'UNLOCKED', 'login-armor' );
			case 'PURGED':      return __( 'PURGED', 'login-armor' );
			case 'DETECTED':    return __( 'DETECTED', 'login-armor' );
			case 'APPROVED':    return __( 'APPROVED', 'login-armor' );
			default:            return $verb_upper;
		}
	}
}

/**
 * Translatable label for an Activity Log object type (USER / POST / CONFIG
 * / PLUGIN / MEDIA / …). The kind comes from the DB in lowercase; we map
 * each known kind to a translated uppercase short label. Unknown kinds
 * fall back to the input uppercased.
 */
if ( ! function_exists( 'login_armor_object_label' ) ) {
	function login_armor_object_label( string $kind ): string {
		switch ( strtolower( $kind ) ) {
			case 'user':    return __( 'USER', 'login-armor' );
			case 'post':    return __( 'POST', 'login-armor' );
			case 'page':    return __( 'PAGE', 'login-armor' );
			case 'config':  return __( 'CONFIG', 'login-armor' );
			case 'plugin':  return __( 'PLUGIN', 'login-armor' );
			case 'media':   return __( 'MEDIA', 'login-armor' );
			case 'theme':   return __( 'THEME', 'login-armor' );
			case 'option':  return __( 'OPTION', 'login-armor' );
			case 'comment': return __( 'COMMENT', 'login-armor' );
			case 'menu':    return __( 'MENU', 'login-armor' );
			case 'role':    return __( 'ROLE', 'login-armor' );
			case 'device':  return __( 'DEVICE', 'login-armor' );
			case 'settings': return __( 'SETTINGS', 'login-armor' );
			case '':        return '';
			default:        return strtoupper( $kind );
		}
	}
}
?>

<div class="la-page-header">
	<div>
		<span class="la-kicker"><?php esc_html_e( 'Activity', 'login-armor' ); ?></span>
		<h2>
			<?php esc_html_e( 'Activity', 'login-armor' ); ?>
			<span class="la-count">
				<?php
				echo wp_kses_post(
					sprintf(
						esc_html(
							/* translators: %s: actions in last 7 days (wrapped in <b>). */
							_n( '%s action in the last 7 days', '%s actions in the last 7 days', $la_act_sum_7d, 'login-armor' )
						),
						'<b>' . esc_html( number_format_i18n( $la_act_sum_7d ) ) . '</b>'
					)
				);
				?>
			</span>
		</h2>
		<p class="la-lead"><?php esc_html_e( 'Track what changed and who changed it. Plugin installs, config edits, user role changes, all captured with IP and timestamp.', 'login-armor' ); ?></p>
	</div>
	<div class="la-page-header__actions">
		<button type="button" class="la-ghost-btn"
			data-la-action="activity-export"
			data-la-object-type="<?php echo esc_attr( (string) $la_act_type ); ?>"
			data-la-user-id="<?php echo esc_attr( (string) $la_act_user ); ?>"
			data-la-period="<?php echo esc_attr( (string) $la_act_period ); ?>">
			<?php Icons::render( 'download', '', 12 );?>
			<?php esc_html_e( 'Export CSV', 'login-armor' ); ?>
		</button>
	</div>
</div>

<div class="la-sum-strip">
	<div class="la-sum-box">
		<b><?php echo esc_html( number_format_i18n( $la_act_sum_7d ) ); ?></b>
		<span><?php esc_html_e( 'Actions', 'login-armor' ); ?></span>
	</div>
	<div class="la-sum-box">
		<b><?php echo esc_html( number_format_i18n( $la_act_sum_users ) ); ?></b>
		<span><?php esc_html_e( 'Users', 'login-armor' ); ?></span>
	</div>
	<div class="la-sum-box">
		<b><?php echo esc_html( number_format_i18n( $la_act_sum_plugins ) ); ?></b>
		<span><?php esc_html_e( 'Plugin changes', 'login-armor' ); ?></span>
	</div>
	<div class="la-sum-box">
		<b><?php echo esc_html( number_format_i18n( $la_act_sum_rotations ) ); ?></b>
		<span><?php esc_html_e( 'Config rotations', 'login-armor' ); ?></span>
	</div>
</div>

<?php
// V2.1.1: Integrity panel (chain verification status).
$la_integrity         = get_transient( 'login_armor_chain_verify_last' );
$la_integrity_status  = is_array( $la_integrity ) && isset( $la_integrity['status'] ) ? (string) $la_integrity['status'] : 'never';
$la_integrity_total   = is_array( $la_integrity ) ? (int) ( $la_integrity['total'] ?? 0 ) : 0;
$la_integrity_when    = is_array( $la_integrity ) ? (string) ( $la_integrity['verified_at'] ?? '' ) : '';
$la_integrity_broken  = is_array( $la_integrity ) ? (array) ( $la_integrity['broken'] ?? [] ) : [];
$la_integrity_orphans = is_array( $la_integrity ) ? (int) ( $la_integrity['orphans'] ?? 0 ) : 0;
$la_integrity_salt    = is_array( $la_integrity ) && ! empty( $la_integrity['salt_changed'] );

// V2.1.20: a broken chain whose security key rotated since the last baseline
// is a benign key change (migration / restored backup), not tampering. Promote
// it to a distinct amber "keys changed" state with a one-click re-baseline.
$la_integrity_keys_changed = ( 'broken' === $la_integrity_status && $la_integrity_salt );

$la_status_class = $la_integrity_keys_changed
	? 'la-integrity--keys'
	: match ( $la_integrity_status ) {
		'intact' => 'la-integrity--intact',
		'broken' => 'la-integrity--broken',
		default  => 'la-integrity--never',
	};

$la_integrity_when_relative = '';
$la_integrity_when_full     = '';
if ( '' !== $la_integrity_when ) {
	$la_integrity_when_relative = login_armor_time_ago( $la_integrity_when );
	$la_ts                      = strtotime( $la_integrity_when . ' UTC' );
	$la_integrity_when_full     = $la_ts ? wp_date( 'Y-m-d H:i:s T', $la_ts ) : $la_integrity_when;
}
?>
<div class="la-integrity-bar <?php echo esc_attr( $la_status_class ); ?>" data-la-integrity-panel
	title="<?php esc_attr_e( 'Each row of the activity log is cryptographically signed and chained. Direct database edits, malicious plugins, or attackers tampering with the table break the chain and surface here.', 'login-armor' ); ?>">
	<svg class="la-integrity-bar__icon" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
		<path d="M12 2 4 5v6c0 5 3.4 9.5 8 11 4.6-1.5 8-6 8-11V5l-8-3z"/>
		<path d="m9 12 2 2 4-4"/>
	</svg>
	<span class="la-integrity-bar__title"><?php esc_html_e( 'Activity Log Integrity', 'login-armor' ); ?></span>
	<?php if ( 'intact' === $la_integrity_status ) : ?>
		<span class="la-status-pill la-status-pill--on"><?php esc_html_e( 'INTACT', 'login-armor' ); ?></span>
	<?php elseif ( $la_integrity_keys_changed ) : ?>
		<span class="la-status-pill la-status-pill--warn"><?php esc_html_e( 'KEYS CHANGED', 'login-armor' ); ?></span>
	<?php elseif ( 'broken' === $la_integrity_status ) : ?>
		<span class="la-status-pill la-status-pill--danger"><?php esc_html_e( 'TAMPERED', 'login-armor' ); ?></span>
	<?php else : ?>
		<span class="la-status-pill la-status-pill--off"><?php esc_html_e( 'UNVERIFIED', 'login-armor' ); ?></span>
	<?php endif; ?>
	<span class="la-integrity-bar__meta" data-la-integrity-meta>
		<?php if ( 'intact' === $la_integrity_status ) : ?>
			<?php
			echo esc_html(
				sprintf(
					/* translators: %s: row count formatted (e.g. "1 234"). */
					_n( '%s row signed', '%s rows signed', $la_integrity_total, 'login-armor' ),
					number_format_i18n( $la_integrity_total )
				)
			);
			// 2.7.3: say so when older rows are simply gone. The nightly purge
			// deletes them by design, and the chain that survives is verified
			// in full; claiming to have checked rows that no longer exist would
			// be the same overstatement that "TAMPERED" was.
			if ( ! empty( $la_integrity['pruned'] ) ) :
				?>
				<span class="la-integrity-bar__sep" aria-hidden="true">&middot;</span>
				<span title="<?php esc_attr_e( 'Rows older than your retention period are deleted every night. The chain is verified from the oldest row that is still here.', 'login-armor' ); ?>">
					<?php esc_html_e( 'older rows purged', 'login-armor' ); ?>
				</span>
				<?php
			endif;
			if ( '' !== $la_integrity_when_relative ) :
				?>
				<span class="la-integrity-bar__sep" aria-hidden="true">&middot;</span>
				<span title="<?php echo esc_attr( $la_integrity_when_full ); ?>">
					<?php
					echo esc_html(
						sprintf(
							/* translators: %s: relative time (e.g. "5m ago"). */
							__( 'verified %s', 'login-armor' ),
							$la_integrity_when_relative
						)
					);
					?>
				</span>
				<?php
			endif;
		elseif ( $la_integrity_keys_changed ) :
			esc_html_e( 'Security keys changed since the last baseline', 'login-armor' );
		elseif ( 'broken' === $la_integrity_status ) :
			$first_break = isset( $la_integrity_broken[0]['id'] ) ? (int) $la_integrity_broken[0]['id'] : 0;
			echo esc_html(
				sprintf(
					/* translators: %d: row id */
					__( 'first break at row %d', 'login-armor' ),
					$first_break
				)
			);
		else :
			esc_html_e( 'Run a check to verify the chain.', 'login-armor' );
		endif;
		?>
	</span>
	<button type="button" class="la-btn la-btn--outline la-btn--small la-integrity-bar__btn" data-la-action="activity-verify-chain">
		<?php esc_html_e( 'Verify now', 'login-armor' ); ?>
	</button>
</div>

<?php
// V2.1.5: surface chain coverage scope. verify_chain() skips rows
// before chain_start_id (legacy pre-V2.1.1 rows or rows that predate
// the most recent chain re-init). Make this explicit so admins know
// the integrity guarantee scope.
$la_chain_stats = \LoginArmor\ActivityLog\ActivityLog::get_chain_coverage_stats();
if ( $la_chain_stats['rows_pre_chain'] > 0 ) :
	?>
<div class="la-integrity-coverage-note" role="note">
	<svg class="la-icon" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false">
		<circle cx="12" cy="12" r="10"></circle>
		<line x1="12" y1="8" x2="12" y2="12"></line>
		<line x1="12" y1="16" x2="12.01" y2="16"></line>
	</svg>
	<span>
		<?php
		echo esc_html(
			sprintf(
				/* translators: 1: number of rows before chain start, 2: chain start row id */
				_n(
					'%1$s row before the integrity chain (id < %2$s) is not covered by Verify. These legacy rows can be modified without detection.',
					'%1$s rows before the integrity chain (id < %2$s) are not covered by Verify. These legacy rows can be modified without detection.',
					$la_chain_stats['rows_pre_chain'],
					'login-armor'
				),
				number_format_i18n( $la_chain_stats['rows_pre_chain'] ),
				number_format_i18n( $la_chain_stats['scope_start_id'] )
			)
		);
		?>
	</span>
</div>
<?php endif; ?>

<?php if ( $la_integrity_keys_changed ) : ?>
<div class="la-integrity-alert la-integrity-alert--keys">
	<p>
		<strong><?php esc_html_e( 'Security keys changed, not tampering.', 'login-armor' ); ?></strong>
		<?php esc_html_e( 'The activity log is signed with your site security keys (wp_salt). Those keys changed since the chain was last sealed: typically after a site migration, a restored backup, or a manual wp-config.php key change. Rows recorded before the change can no longer be verified, but they have not been altered. Re-baseline the chain to trust the current log and restore the integrity guarantee going forward.', 'login-armor' ); ?>
	</p>
	<button type="button" class="la-btn la-btn--primary la-btn--small" data-la-action="activity-reset-chain"
		data-la-confirm="<?php esc_attr_e( 'Re-sign every activity row under the current security key and trust the log as it stands now? Only do this after a key change you expected.', 'login-armor' ); ?>">
		<?php esc_html_e( 'Re-baseline chain', 'login-armor' ); ?>
	</button>
</div>
<?php endif; ?>

<?php if ( ( 'broken' === $la_integrity_status && ! $la_integrity_keys_changed ) || $la_integrity_orphans > 0 ) : ?>
<div class="la-integrity-alert">
	<?php if ( 'broken' === $la_integrity_status && ! $la_integrity_keys_changed ) : ?>
		<p>
			<strong><?php esc_html_e( 'Tampering detected.', 'login-armor' ); ?></strong>
			<?php
			$first_break = isset( $la_integrity_broken[0]['id'] ) ? (int) $la_integrity_broken[0]['id'] : 0;
			echo esc_html(
				sprintf(
					/* translators: %d: row id where the chain first breaks. */
					__( 'The chain breaks at row %d. Inspect that row and the rows immediately before and after it for signs of unauthorized modification.', 'login-armor' ),
					$first_break
				)
			);
			?>
		</p>
	<?php endif; ?>
	<?php if ( $la_integrity_orphans > 0 ) : ?>
		<button type="button" class="la-btn la-btn--secondary la-btn--small" data-la-action="activity-repair-chain">
			<?php
			echo esc_html(
				sprintf(
					/* translators: %d: orphan count */
					__( 'Repair %d orphan(s)', 'login-armor' ),
					$la_integrity_orphans
				)
			);
			?>
		</button>
	<?php endif; ?>
</div>
<?php endif; ?>

<div class="la-page-grid">
	<div>
		<form method="get" class="la-filter-bar">
			<input type="hidden" name="page" value="login-armor">
			<input type="hidden" name="tab" value="activity">

			<div class="la-fb-field">
				<label for="la-act-type"><?php esc_html_e( 'Type', 'login-armor' ); ?></label>
				<select id="la-act-type" name="object_type">
					<option value="" <?php selected( $la_act_type, '' ); ?>><?php esc_html_e( 'All', 'login-armor' ); ?></option>
					<option value="post" <?php selected( $la_act_type, 'post' ); ?>><?php esc_html_e( 'Posts', 'login-armor' ); ?></option>
					<option value="media" <?php selected( $la_act_type, 'media' ); ?>><?php esc_html_e( 'Media', 'login-armor' ); ?></option>
					<option value="user" <?php selected( $la_act_type, 'user' ); ?>><?php esc_html_e( 'Users', 'login-armor' ); ?></option>
					<option value="plugin" <?php selected( $la_act_type, 'plugin' ); ?>><?php esc_html_e( 'Plugins', 'login-armor' ); ?></option>
					<option value="theme" <?php selected( $la_act_type, 'theme' ); ?>><?php esc_html_e( 'Themes', 'login-armor' ); ?></option>
					<option value="option" <?php selected( $la_act_type, 'option' ); ?>><?php esc_html_e( 'Options', 'login-armor' ); ?></option>
					<option value="settings" <?php selected( $la_act_type, 'settings' ); ?>><?php esc_html_e( 'Settings imports', 'login-armor' ); ?></option>
				</select>
			</div>

			<div class="la-fb-field">
				<label for="la-act-user"><?php esc_html_e( 'User', 'login-armor' ); ?></label>
				<select id="la-act-user" name="user_id">
					<option value="" <?php selected( $la_act_user, 0 ); ?>><?php esc_html_e( 'All', 'login-armor' ); ?></option>
					<?php foreach ( $la_act_users as $la_u ) : ?>
						<option value="<?php echo esc_attr( $la_u->ID ); ?>" <?php selected( $la_act_user, (int) $la_u->ID ); ?>>
							<?php echo esc_html( $la_u->display_name . ' (' . $la_u->user_login . ')' ); ?>
						</option>
					<?php endforeach; ?>
				</select>
			</div>

			<div class="la-fb-field">
				<label for="la-act-period"><?php esc_html_e( 'Period', 'login-armor' ); ?></label>
				<select id="la-act-period" name="period">
					<option value="" <?php selected( $la_act_period, '' ); ?>><?php esc_html_e( 'All time', 'login-armor' ); ?></option>
					<option value="today" <?php selected( $la_act_period, 'today' ); ?>><?php esc_html_e( 'Today', 'login-armor' ); ?></option>
					<option value="7d" <?php selected( $la_act_period, '7d' ); ?>><?php esc_html_e( 'Last 7 days', 'login-armor' ); ?></option>
					<option value="30d" <?php selected( $la_act_period, '30d' ); ?>><?php esc_html_e( 'Last 30 days', 'login-armor' ); ?></option>
				</select>
			</div>

			<div class="la-fb-actions">
				<button type="submit" class="la-ghost-btn"><?php esc_html_e( 'Filter', 'login-armor' ); ?></button>
				<a class="la-ghost-btn" href="<?php echo esc_url( $la_act_base_url ); ?>"><?php esc_html_e( 'Reset', 'login-armor' ); ?></a>
			</div>
		</form>

		<?php if ( empty( $la_act_rows ) ) : ?>
			<?php if ( '' === $la_act_type && 0 === $la_act_user && '' === $la_act_period ) : ?>
				<div class="la-empty-hint"><?php esc_html_e( 'No admin activity recorded yet. Actions like user edits, plugin changes and settings updates will appear here as they happen.', 'login-armor' ); ?></div>
			<?php else : ?>
				<div class="la-empty-hint"><?php esc_html_e( 'No activity matches the current filters.', 'login-armor' ); ?></div>
			<?php endif; ?>
		<?php else : ?>
			<div class="la-act-wrap">
				<div class="la-act-head">
					<span><?php esc_html_e( 'Time', 'login-armor' ); ?></span>
					<span><?php esc_html_e( 'User', 'login-armor' ); ?></span>
					<span><?php esc_html_e( 'Action', 'login-armor' ); ?></span>
					<span><?php esc_html_e( 'Object', 'login-armor' ); ?></span>
					<span><?php esc_html_e( 'IP', 'login-armor' ); ?></span>
				</div>

				<?php
				foreach ( $la_act_rows as $la_row ) :
					$la_ts         = strtotime( $la_row->log_time . ' UTC' );
					$la_time_short = $la_ts ? wp_date( 'H:i:s', $la_ts ) : (string) $la_row->log_time;
					$la_time_full  = $la_ts ? wp_date( 'Y-m-d H:i:s T', $la_ts ) : '';
					$la_ago        = login_armor_time_ago( (string) $la_row->log_time );

					$la_action_parts = explode( '_', (string) $la_row->action );
					// 2.9.0: the one action whose last word is not its verb.
					$la_action_verb  = 'app_password_new_network' === (string) $la_row->action ? 'DETECTED' : strtoupper( end( $la_action_parts ) );
					$la_action_text  = login_armor_action_label( $la_action_verb );
					$la_pill_kind    = login_armor_activity_pill_class( $la_action_verb );

					$la_user_name  = (string) $la_row->user_login;
					$la_avatar_ltr = '' === $la_user_name ? '?' : mb_strtoupper( mb_substr( $la_user_name, 0, 1 ) );

					$la_obj_kind = login_armor_object_label( (string) $la_row->object_type );
					$la_obj_name = (string) $la_row->object_name;
					?>
					<div class="la-act-row" title="<?php echo esc_attr( (string) $la_row->description ); ?>">
						<span class="la-act-t la-mono" title="<?php echo esc_attr( $la_time_full ); ?>">
							<?php echo esc_html( $la_time_short ); ?>
							<small><?php echo esc_html( $la_ago ); ?></small>
						</span>
						<span class="la-act-user">
							<span class="la-evt-avatar"><?php echo esc_html( $la_avatar_ltr ); ?></span>
							<span class="la-act-user-text">
								<b><?php echo esc_html( '' === $la_user_name ? '-' : $la_user_name ); ?></b>
								<?php
								$la_role_slug  = (string) $la_row->user_role;
								$la_role_label = '';
								if ( '' !== $la_role_slug ) {
									$la_role_names = wp_roles()->role_names;
									$la_role_label = translate_user_role( $la_role_names[ $la_role_slug ] ?? ucfirst( $la_role_slug ) );
								}
								?>
								<small><?php echo esc_html( $la_role_label ); ?></small>
							</span>
						</span>
						<span>
							<span class="la-pill la-pill--<?php echo esc_attr( $la_pill_kind ); ?>"><?php echo esc_html( $la_action_text ); ?></span>
						</span>
						<span class="la-act-obj">
							<?php if ( '' !== $la_obj_kind ) : ?>
								<span class="la-act-kind"><?php echo esc_html( $la_obj_kind ); ?>:</span>
							<?php endif; ?>
							<?php if ( '' !== $la_obj_name ) : ?>
								<code class="la-act-code"><?php echo esc_html( $la_obj_name ); ?></code>
							<?php else : ?>
								<span style="color:var(--la-slate-500);">·</span>
							<?php endif; ?>
						</span>
						<?php // 2.10.0: a system entry has no address; an empty cell collapsed and the row lost its fifth column. ?>
						<?php if ( '' !== (string) $la_row->ip ) : ?>
							<span class="la-act-ip la-mono"><?php echo esc_html( (string) $la_row->ip ); ?></span>
						<?php else : ?>
							<span class="la-act-ip la-mono" style="color:var(--la-slate-500);">·</span>
						<?php endif; ?>
					</div>
				<?php endforeach; ?>
			</div>

			<?php if ( $la_act_pages > 1 ) : ?>
				<div class="la-pagination" style="margin-top:16px;">
					<span>
						<?php
						echo esc_html(
							sprintf(
								/* translators: 1: current page, 2: total pages, 3: total entries. */
								__( 'Page %1$d of %2$d · %3$d entries', 'login-armor' ),
								$la_act_page,
								$la_act_pages,
								$la_act_total
							)
						);
						?>
					</span>
					<div class="la-pagination__links">
						<?php
						$la_act_start = max( 1, $la_act_page - 4 );
						$la_act_end   = min( $la_act_pages, $la_act_page + 4 );
						for ( $la_p = $la_act_start; $la_p <= $la_act_end; $la_p++ ) {
							$la_url = add_query_arg(
								[
									'page'        => 'login-armor',
									'tab'         => 'activity',
									'object_type' => $la_act_type,
									'user_id'     => $la_act_user > 0 ? $la_act_user : '',
									'period'      => $la_act_period,
									'paged'       => $la_p,
								],
								admin_url( 'admin.php' )
							);
							if ( $la_p === $la_act_page ) {
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
		$la_guide_file = LOGIN_ARMOR_DIR . 'admin/views/sidebar/activity.php';
		if ( file_exists( $la_guide_file ) ) {
			echo '<div class="la-guide">';
			include $la_guide_file;
			echo '</div>';
		}
		include LOGIN_ARMOR_DIR . 'admin/views/sidebar/sponsored-ads.php';
		?>
	</aside>
</div>
