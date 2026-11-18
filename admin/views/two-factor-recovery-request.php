<?php
/**
 * Two-factor recovery: request form.
 *
 * Standalone screen displayed when the user clicks « Request 2FA reset ».
 * The account comes from the signed pending-2FA session. No public account
 * lookup is accepted by this endpoint.
 *
 * @package LoginArmor
 */

if ( ! defined( 'ABSPATH' ) ) { exit; }

\LoginArmor\TwoFactor\TwoFactor::class; // phpcs:ignore -- autoload guard
$login_armor_recov_url = add_query_arg(
	[ \LoginArmor\TwoFactor\TwoFactor::VERIFY_PARAM => \LoginArmor\TwoFactor\Recovery::PARAM_REQUEST ],
	\LoginArmor\HideLogin::get_login_url()
);

login_header( esc_html__( '2FA recovery', 'login-armor' ) );
?>
<style>
.la-2fa-recov-form { max-width: 420px; margin: 48px auto; padding: 32px; background: #fff; border: 1px solid #DCDCDE; border-radius: 8px; font-family: -apple-system, BlinkMacSystemFont, Segoe UI, sans-serif; }
.la-2fa-recov-form h1 { font-size: 20px; margin: 0 0 8px; }
.la-2fa-recov-form p { font-size: 14px; color: #50575E; margin: 0 0 16px; }
.la-2fa-recov-form button { margin-top: 16px; width: 100%; padding: 10px; background: #C73D24; color: #fff; border: 0; border-radius: 4px; font-size: 14px; font-weight: 600; cursor: pointer; }
.la-2fa-recov-form button:hover { background: #A8331F; } /* 2.8.0: white on #E84A2E read 3.9:1 */
.la-2fa-recov-back { display: block; text-align: center; margin-top: 12px; font-size: 13px; color: #50575E; text-decoration: none; }
</style>
<form method="post" action="<?php echo esc_url( $login_armor_recov_url ); ?>" class="la-2fa-recov-form">
	<h1><?php esc_html_e( 'Request 2FA reset', 'login-armor' ); ?></h1>
	<p><?php esc_html_e( 'If you lost access to every second factor, request a reset for the account whose password you just confirmed. A site administrator will be emailed and must authorize the operation. Every successful request is recorded in the activity log.', 'login-armor' ); ?></p>

	<?php wp_nonce_field( 'login_armor_2fa_recovery_request' ); ?>
	<button type="submit"><?php esc_html_e( 'Request reset', 'login-armor' ); ?></button>
	<a class="la-2fa-recov-back" href="<?php echo esc_url( \LoginArmor\HideLogin::get_login_url() ); ?>"><?php esc_html_e( '← Back to login', 'login-armor' ); ?></a>
</form>
<?php
login_footer();
