<?php
/**
 * LoginArmor v2 admin page shell (Lot 18 redesign).
 *
 * @var string $active_tab       One of: overview, incidents, events, activity, settings
 * @var string $overview_nonce   Overview AJAX refresh nonce
 * @var string $admin_nonce      Admin-action AJAX nonce
 * @var string $ajax_url         admin-ajax.php URL
 *
 * @package LoginArmor
 */

// phpcs:disable WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

// The badge counts what deserves attention: severity 2 and above. A severity 1
// row is an observation, and a firewall in monitor mode records one per
// scanner probe, so counting them here painted a permanent red number on the
// menu for background noise (2.7.1). The observations stay one click away on
// the Incidents tab, which names and counts them separately.
$la_open_incidents = \LoginArmor\Detection\Incident::get_active_summary()['attention'];

$la_tabs = array(
	'overview'  => array( 'label' => __( 'Overview', 'login-armor' ) ),
	'incidents' => array( 'label' => __( 'Incidents', 'login-armor' ), 'badge' => $la_open_incidents ),
	'events'    => array( 'label' => __( 'Events', 'login-armor' ) ),
	'activity'  => array( 'label' => __( 'Activity', 'login-armor' ) ),
	'settings'  => array( 'label' => __( 'Settings', 'login-armor' ) ),
);
?>
<div
	id="la-root"
	class="la-root"
	data-la-overview-nonce="<?php echo esc_attr( $overview_nonce ); ?>"
	data-la-admin-nonce="<?php echo esc_attr( $admin_nonce ); ?>"
	data-la-ajax="<?php echo esc_url( $ajax_url ); ?>"
	data-la-active-tab="<?php echo esc_attr( $active_tab ); ?>"
>
	<header class="la-topbar">
		<?php
		$la_overview_url = add_query_arg(
			array( 'page' => 'login-armor', 'tab' => 'overview' ),
			admin_url( 'admin.php' )
		);
		$la_brand_is_home = ( 'overview' === $active_tab );
		?>
		<a
			class="la-brand"
			href="<?php echo esc_url( $la_overview_url ); ?>"
			<?php echo $la_brand_is_home ? 'aria-current="page"' : ''; ?>
			aria-label="<?php esc_attr_e( 'Login Armor: go to Overview', 'login-armor' ); ?>"
		>
			<span class="la-brand__logo-wrap">
				<img
					class="la-brand__logo"
					src="<?php echo esc_url( LOGIN_ARMOR_URL . 'admin/assets/img/icon-128x128.png' ); ?>"
					alt=""
					width="40"
					height="40"
				/>
			</span>
			<span class="la-brand__text">
				<span class="la-brand__name">Login Armor</span>
				<span class="la-brand__tag"><?php esc_html_e( 'Hide · Block · Watch', 'login-armor' ); ?></span>
			</span>
		</a>

		<nav class="la-topnav" aria-label="<?php esc_attr_e( 'Login Armor sections', 'login-armor' ); ?>">
			<?php foreach ( $la_tabs as $la_slug => $la_tab ) :
				$la_is_active = ( $la_slug === $active_tab );
				$la_url       = add_query_arg(
					array(
						'page' => 'login-armor',
						'tab'  => $la_slug,
					),
					admin_url( 'admin.php' )
				);
				?>
				<a
					class="la-topnav__item<?php echo $la_is_active ? ' is-active' : ''; ?>"
					href="<?php echo esc_url( $la_url ); ?>"
					<?php echo $la_is_active ? 'aria-current="page"' : ''; ?>
				>
					<?php echo esc_html( $la_tab['label'] ); ?>
					<?php if ( ! empty( $la_tab['badge'] ) ) : ?>
						<span class="la-topnav__badge"><?php echo esc_html( (string) (int) $la_tab['badge'] ); ?></span>
					<?php endif; ?>
				</a>
			<?php endforeach; ?>
		</nav>

	</header>

	<main class="la-content">
		<?php
		$la_tab_file = LOGIN_ARMOR_DIR . 'admin/views/tabs/' . $active_tab . '.php';
		if ( file_exists( $la_tab_file ) ) {
			include $la_tab_file;
		}
		?>
	</main>
</div>
