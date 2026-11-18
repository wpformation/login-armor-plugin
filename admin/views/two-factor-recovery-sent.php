<?php
/**
 * Two-factor recovery: generic « request received » confirmation.
 *
 * Shown AFTER a POST to the request form regardless of whether a matching
 * user was found: prevents enumeration.
 *
 * @package LoginArmor
 */
if ( ! defined( 'ABSPATH' ) ) { exit; }
login_header( esc_html__( '2FA recovery', 'login-armor' ) );
?>
<style>
.la-2fa-recov-sent { max-width: 420px; margin: 48px auto; padding: 32px; background: #fff; border: 1px solid #DCDCDE; border-radius: 8px; text-align: center; font-family: -apple-system, BlinkMacSystemFont, Segoe UI, sans-serif; }
.la-2fa-recov-sent h1 { font-size: 20px; margin: 0 0 8px; }
.la-2fa-recov-sent p { font-size: 14px; color: #50575E; margin: 0 0 16px; }
.la-2fa-recov-sent a { color: #C73D24; text-decoration: none; } /* 2.8.0: #E84A2E read 3.9:1 */
</style>
<div class="la-2fa-recov-sent">
	<h1><?php esc_html_e( 'Request received', 'login-armor' ); ?></h1>
	<p><?php esc_html_e( 'If the account exists and 2FA is enabled, a site administrator has been emailed. The link expires in one hour.', 'login-armor' ); ?></p>
	<p><a href="<?php echo esc_url( \LoginArmor\HideLogin::get_login_url() ); ?>"><?php esc_html_e( '← Back to login', 'login-armor' ); ?></a></p>
</div>
<?php
login_footer();
