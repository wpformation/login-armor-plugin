<?php
/**
 * Profile section: networks seen per application password (2.9.0).
 *
 * Rendered after core's application-password table (show_user_profile /
 * edit_user_profile fire after it in user-edit.php), so the revoke button is
 * right above.
 *
 * @package LoginArmor
 *
 * @var \WP_User                          $la_user        Profile owner.
 * @var array<string,array<string,mixed>> $la_networks    Usage::group_by_password() (one row per network, already aggregated).
 * @var bool                              $la_can_approve Whether the viewer may approve.
 * @var bool                              $la_watching    Whether monitoring is on.
 */

// phpcs:disable WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

$la_state_labels = array(
	'pending'  => __( 'Being checked', 'login-armor' ),
	'known'    => __( 'Known', 'login-armor' ),
	'approved' => __( 'Approved', 'login-armor' ),
	'alerted'  => __( 'New network, reported', 'login-armor' ),
);
?>
<h2 id="login-armor-app-password-networks"><?php esc_html_e( 'Networks seen per application password', 'login-armor' ); ?></h2>
<?php if ( ! $la_watching ) : ?>
	<p class="description"><?php esc_html_e( 'Login Armor no longer records new uses: application-password monitoring is off.', 'login-armor' ); ?></p>
<?php endif; ?>
<?php if ( array() === $la_networks ) : ?>
	<p class="description"><?php esc_html_e( 'No application password of this account has been used since monitoring started.', 'login-armor' ); ?></p>
<?php endif; ?>
<?php foreach ( $la_networks as $la_uuid => $la_group ) : ?>
	<h3><?php echo esc_html( '' !== $la_group['name'] ? $la_group['name'] : $la_uuid ); ?></h3>
	<?php if ( $la_group['many_networks'] ) : ?>
		<p class="description">
			<?php
			echo esc_html(
				sprintf(
					/* translators: %d: number of networks. */
					_n( 'This password is used from %d network.', 'This password is used from %d networks. One password per service lets you revoke one service without cutting off the others.', $la_group['resolved'], 'login-armor' ),
					$la_group['resolved']
				)
			);
			?>
		</p>
	<?php endif; ?>
	<table class="widefat striped">
		<thead>
			<tr>
				<th><?php esc_html_e( 'Network', 'login-armor' ); ?></th>
				<th><?php esc_html_e( 'Country', 'login-armor' ); ?></th>
				<th><?php esc_html_e( 'Addresses', 'login-armor' ); ?></th>
				<th><?php esc_html_e( 'First / last request (UTC)', 'login-armor' ); ?></th>
				<th><?php esc_html_e( 'Requests', 'login-armor' ); ?></th>
				<th><?php esc_html_e( 'Last request', 'login-armor' ); ?></th>
				<th><?php esc_html_e( 'State', 'login-armor' ); ?></th>
			</tr>
		</thead>
		<tbody>
		<?php foreach ( $la_group['networks'] as $la_network => $la_net ) : ?>
			<tr>
				<td><?php echo esc_html( '' !== $la_net['label'] ? $la_net['label'] : '-' ); ?></td>
				<td><?php echo esc_html( '' !== $la_net['country'] ? $la_net['country'] : '-' ); ?></td>
				<td><code><?php echo esc_html( implode( ', ', $la_net['ips'] ) . ( $la_net['addresses'] > count( $la_net['ips'] ) ? ', …' : '' ) ); ?></code></td>
				<td><?php echo esc_html( $la_net['first'] . ' / ' . $la_net['last'] ); ?></td>
				<td><?php echo (int) $la_net['hits']; ?></td>
				<td><code><?php echo esc_html( $la_net['route'] ); ?></code></td>
				<td>
					<?php echo esc_html( $la_state_labels[ $la_net['state'] ] ?? $la_net['state'] ); ?>
					<?php if ( 'alerted' === $la_net['state'] && $la_can_approve && '' !== (string) $la_network ) : ?>
						<br />
						<a class="button button-small" href="<?php echo esc_url( wp_nonce_url( admin_url( 'admin-post.php?action=login_armor_approve_network&user=' . (int) $la_user->ID . '&uuid=' . rawurlencode( (string) $la_uuid ) . '&network=' . rawurlencode( (string) $la_network ) ), 'login_armor_approve_network_' . (int) $la_user->ID . '_' . $la_uuid ) ); ?>">
							<?php esc_html_e( 'Approve this network', 'login-armor' ); ?>
						</a>
					<?php endif; ?>
				</td>
			</tr>
		<?php endforeach; ?>
		</tbody>
	</table>
<?php endforeach; ?>
