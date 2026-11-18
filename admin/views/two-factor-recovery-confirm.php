<?php
/**
 * Two-factor recovery: admin confirmation.
 *
 * Renders:
 *   - GET:  confirmation form with context (target user, IP, UA)
 *   - POST: success view after the reset has been applied
 *
 * Called from Recovery::handle_confirm() which guarantees the caller has
 * manage_options and a valid token.
 *
 * 2.8.0: served by admin-post.php instead of the login screen, so the page
 * is a document of its own. login_header() and login_footer() only exist
 * inside wp-login.php, and the form posts back to admin-post.php with the
 * action and the token as hidden fields.
 *
 * @package LoginArmor
 *
 * @var \WP_User $la_recov_target
 * @var string   $la_recov_ip
 * @var string   $la_recov_ua
 * @var string   $la_recov_token
 */
if ( ! defined( 'ABSPATH' ) ) { exit; }
// phpcs:disable WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound

$la_recov_is_post = isset( $_SERVER['REQUEST_METHOD'] ) && 'POST' === $_SERVER['REQUEST_METHOD'];
$la_recov_title   = $la_recov_is_post ? __( '2FA reset complete', 'login-armor' ) : __( 'Authorize 2FA reset', 'login-armor' );

nocache_headers();
header( 'Content-Type: text/html; charset=UTF-8' );
?><!DOCTYPE html>
<html <?php language_attributes(); ?>>
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title><?php echo esc_html( $la_recov_title ); ?></title>
<style>
body { margin: 0; padding: 16px; background: #f0f0f1; color: #1d2327; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
.la-2fa-recov-ok, .la-2fa-recov-cf { box-sizing: border-box; max-width: 520px; margin: 48px auto; padding: 32px; background: #fff; border: 1px solid #dcdcde; border-radius: 8px; }
.la-2fa-recov-ok { text-align: center; }
.la-2fa-recov-ok h1, .la-2fa-recov-cf h1 { font-size: 20px; margin: 0 0 8px; }
.la-2fa-recov-ok h1 { color: #1e6b24; }
.la-2fa-recov-ok p, .la-2fa-recov-cf p { font-size: 14px; line-height: 1.5; color: #50575e; margin: 0 0 16px; }
.la-2fa-recov-cf dl { margin: 16px 0; font-size: 13px; }
.la-2fa-recov-cf dt { font-weight: 600; color: #1d2327; margin-top: 8px; }
.la-2fa-recov-cf dd { margin: 0 0 4px; color: #50575e; overflow-wrap: anywhere; }
.la-2fa-recov-cf button { margin-top: 16px; padding: 10px 16px; background: #b32d2e; color: #fff; border: 0; border-radius: 4px; font-size: 14px; font-weight: 600; cursor: pointer; }
.la-2fa-recov-cf button:hover { background: #8f2425; }
.la-2fa-recov-cf button:focus-visible, .la-2fa-recov-ok a:focus-visible { outline: 2px solid #2271b1; outline-offset: 2px; }
.la-2fa-recov-ok a { color: #2271b1; }
</style>
</head>
<body>
<main>
<?php if ( $la_recov_is_post ) : ?>
	<div class="la-2fa-recov-ok">
		<h1><?php esc_html_e( '2FA has been reset', 'login-armor' ); ?></h1>
		<p><?php esc_html_e( 'The target user is back to the pre-2FA state and must reconfigure it before their next sensitive action. Every active session of that user has been destroyed.', 'login-armor' ); ?></p>
		<p><a href="<?php echo esc_url( admin_url() ); ?>"><?php esc_html_e( '← Back to dashboard', 'login-armor' ); ?></a></p>
	</div>
<?php else : ?>
	<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" class="la-2fa-recov-cf">
		<h1><?php esc_html_e( 'Authorize 2FA reset', 'login-armor' ); ?></h1>
		<p><?php esc_html_e( 'A 2FA reset was requested for the account below. Authorizing this action will remove every 2FA credential, revoke every trusted device, and destroy every active session of that user.', 'login-armor' ); ?></p>

		<dl>
			<dt><?php esc_html_e( 'User', 'login-armor' ); ?></dt>
			<dd><?php echo esc_html( $la_recov_target->user_login ); ?> (<?php echo esc_html( $la_recov_target->user_email ); ?>)</dd>

			<dt><?php esc_html_e( 'Requester IP', 'login-armor' ); ?></dt>
			<dd><?php echo esc_html( '' === $la_recov_ip ? '-' : $la_recov_ip ); ?></dd>

			<dt><?php esc_html_e( 'Requester User-Agent', 'login-armor' ); ?></dt>
			<dd><?php echo esc_html( '' === $la_recov_ua ? '-' : $la_recov_ua ); ?></dd>
		</dl>

		<input type="hidden" name="action" value="<?php echo esc_attr( \LoginArmor\TwoFactor\Recovery::ADMIN_ACTION ); ?>">
		<input type="hidden" name="token" value="<?php echo esc_attr( $la_recov_token ); ?>">
		<?php wp_nonce_field( 'login_armor_2fa_recovery_confirm' ); ?>
		<button type="submit"><?php esc_html_e( 'Authorize reset', 'login-armor' ); ?></button>
	</form>
<?php endif; ?>
</main>
</body>
</html>
<?php
