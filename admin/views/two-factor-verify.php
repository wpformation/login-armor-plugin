<?php
/**
 * Standalone 2FA verification screen.
 *
 * Rendered outside WP admin chrome: minimal design like wp-login.php.
 * Variables set by TwoFactor::maybe_render_verification():
 *   $la_2fa_token, $la_2fa_user, $la_2fa_method, $la_2fa_error, $la_2fa_failures, $la_2fa_resent
 *
 * @package LoginArmor
 * @since   2.2.0
 */

// phpcs:disable WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

// Harden the verification screen. nocache_headers() emits no-store, which also
// disables Chrome's back/forward cache (bfcache): without it the browser could
// restore this form from cache and resubmit a stale nonce, bouncing the user
// back to login with "session expired" (locationcantin.fr, 2026-06-11). Plus
// clickjacking + MIME sniff + referrer-leak protection.
if ( ! headers_sent() ) {
	nocache_headers();
	header( 'X-Frame-Options: DENY' );
	header( 'X-Content-Type-Options: nosniff' );
	header( 'Referrer-Policy: same-origin' );
}

$la_2fa_methods_available = \LoginArmor\TwoFactor\TwoFactor::get_available_methods_for_user( $la_2fa_user->ID );

if ( ! isset( $la_2fa_resent ) ) {
	$la_2fa_resent = false;
}
if ( ! isset( $la_2fa_send_failed ) ) {
	$la_2fa_send_failed = false;
}

require_once LOGIN_ARMOR_DIR . 'includes/TwoFactor/TrustedDevices.php';
$la_2fa_td_enabled       = \LoginArmor\TwoFactor\TrustedDevices::is_feature_enabled();
$la_2fa_td_duration_days = \LoginArmor\TwoFactor\TrustedDevices::get_duration_days();

$la_2fa_input_label = match ( $la_2fa_method ) {
	'email'  => __( 'Email verification code', 'login-armor' ),
	'backup' => __( 'Backup code', 'login-armor' ),
	default  => __( 'Authenticator verification code', 'login-armor' ),
};
?>
<!DOCTYPE html>
<html <?php language_attributes(); ?>>
<head>
	<meta charset="<?php bloginfo( 'charset' ); ?>">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<meta name="robots" content="noindex, nofollow">
	<?php /* translators: %s: site name */ ?>
	<title><?php echo esc_html( sprintf( __( 'Verify Your Identity: %s', 'login-armor' ), get_bloginfo( 'name' ) ) ); ?></title>
	<?php // phpcs:ignore WordPress.WP.EnqueuedResources.NonEnqueuedStylesheet -- Standalone screen outside WP admin chrome; wp_head/wp_footer hooks are not emitted, so enqueue is not possible. ?>
	<link rel="stylesheet" href="<?php echo esc_url( plugins_url( 'admin/assets/css/two-factor.css', LOGIN_ARMOR_FILE ) ); ?>?ver=<?php echo esc_attr( LOGIN_ARMOR_VERSION ); ?>">
</head>
<body class="la-2fa-body">
	<div class="la-2fa-wrap">
		<div class="la-2fa-card">
			<div class="la-2fa-header">
				<svg class="la-2fa-logo" viewBox="0 0 24 24" fill="none" width="32" height="32">
					<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" stroke="currentColor" stroke-width="1.5"/>
					<path d="M9 12l2 2 4-4" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
				</svg>
				<span class="la-2fa-header__brand"><?php esc_html_e( 'Login Armor', 'login-armor' ); ?></span>
			</div>

			<div class="la-2fa-user">
				<?php echo get_avatar( $la_2fa_user->ID, 40, '', '', [ 'class' => 'la-2fa-user__avatar' ] ); ?>
				<span class="la-2fa-user__name"><?php echo esc_html( $la_2fa_user->display_name ); ?></span>
			</div>

			<h1 class="la-2fa-title"><?php esc_html_e( 'Verify your identity', 'login-armor' ); ?></h1>

			<?php if ( '' !== $la_2fa_error ) : ?>
				<div class="la-2fa-error"><?php echo esc_html( $la_2fa_error ); ?></div>
			<?php endif; ?>

			<?php if ( $la_2fa_send_failed ) : ?>
				<div class="la-2fa-error"><?php esc_html_e( 'We could not send the verification code by email. Your site may have a mail-delivery issue. Click “Resend code” below to try again, or contact the site administrator.', 'login-armor' ); ?></div>
			<?php elseif ( $la_2fa_resent ) : ?>
				<div class="la-2fa-success"><?php esc_html_e( 'A new code has been sent to your email.', 'login-armor' ); ?></div>
			<?php endif; ?>

			<p class="la-2fa-desc" id="la-2fa-desc">
				<?php
				match ( $la_2fa_method ) {
					'email'  => esc_html_e( 'Enter the 6-digit code sent to your email address.', 'login-armor' ),
					'backup' => esc_html_e( 'Enter one of your backup codes.', 'login-armor' ),
					default  => esc_html_e( 'Enter the 6-digit code from your authenticator app.', 'login-armor' ),
				};
				?>
			</p>

			<form method="post" class="la-2fa-form" id="la-2fa-form">
				<?php wp_nonce_field( 'login_armor_2fa_verify' ); ?>
				<input type="hidden" name="method" value="<?php echo esc_attr( $la_2fa_method ); ?>" id="la-2fa-method">
				<?php
				/*
				 * Echo the pending token in a hidden POST field as a fallback for the
				 * signed la_2fa_pending cookie. Some browsers/environments fail to send
				 * that cookie on the verify POST (reported on locationcantin.fr: the flow
				 * worked in Firefox and in scripted Chrome, yet bounced to "session
				 * expired" on the reporter's Chrome: i.e. the cookie was unusable at
				 * submit time). The handler resolves the session from the cookie first
				 * and only falls back to this field; the token is validated by the
				 * transient lookup and, when it is NOT backed by the signed cookie, a
				 * valid nonce is required. Unlike the pre-2.1.0 URL token this lives in
				 * the POST body, so it does not leak via Referer, history or access logs.
				 */
				?>
				<input type="hidden" name="token" value="<?php echo esc_attr( $la_2fa_token ); ?>">

				<?php if ( 'backup' === $la_2fa_method ) : ?>
					<input
						type="text"
						name="code"
						class="la-2fa-input la-2fa-input--backup"
						placeholder="xxxx-xxxx"
						aria-label="<?php echo esc_attr( $la_2fa_input_label ); ?>"
						aria-describedby="la-2fa-desc"
						autocomplete="off"
						autocapitalize="off"
						spellcheck="false"
						autofocus
						required
					>
				<?php else : ?>
					<input
						type="text"
						name="code"
						class="la-2fa-input"
						inputmode="numeric"
						pattern="[0-9]{6}"
						maxlength="6"
						placeholder="000000"
						aria-label="<?php echo esc_attr( $la_2fa_input_label ); ?>"
						aria-describedby="la-2fa-desc"
						autocomplete="one-time-code"
						autofocus
						required
					>
				<?php endif; ?>

				<?php if ( $la_2fa_td_enabled && 'backup' !== $la_2fa_method ) : ?>
					<label class="la-2fa-trust">
						<input type="checkbox" name="la_trust_device" value="1">
						<?php
						printf(
							/* translators: %d: trust duration in days */
							esc_html__( 'Trust this device for %d days', 'login-armor' ),
							(int) $la_2fa_td_duration_days
						);
						?>
					</label>
				<?php endif; ?>

				<button type="submit" class="la-2fa-btn"><?php esc_html_e( 'Verify', 'login-armor' ); ?></button>

				<?php if ( 'email' === $la_2fa_method ) : ?>
					<button type="submit" name="resend" value="1" class="la-2fa-link la-2fa-resend" id="la-2fa-resend">
						<?php esc_html_e( 'Resend code', 'login-armor' ); ?>
					</button>
				<?php endif; ?>
			</form>

			<?php if ( count( $la_2fa_methods_available ) > 1 ) : ?>
				<div class="la-2fa-alt">
					<button type="button" class="la-2fa-link" id="la-2fa-toggle-methods">
						<?php esc_html_e( 'Use a different method', 'login-armor' ); ?>
					</button>
					<div class="la-2fa-methods" id="la-2fa-methods" hidden>
						<?php foreach ( $la_2fa_methods_available as $la_m ) : ?>
							<?php if ( $la_m === $la_2fa_method ) { continue; } ?>
							<a href="<?php echo esc_url( add_query_arg( [
								\LoginArmor\TwoFactor\TwoFactor::VERIFY_PARAM => 'verify',
								'method' => $la_m,
							], wp_login_url() ) ); ?>" class="la-2fa-method-link">
								<?php
								match ( $la_m ) {
									'totp'   => esc_html_e( 'Authenticator app', 'login-armor' ),
									'email'  => esc_html_e( 'Email code', 'login-armor' ),
									'backup' => esc_html_e( 'Backup code', 'login-armor' ),
									default  => '',
								};
								?>
							</a>
						<?php endforeach; ?>
					</div>
				</div>
			<?php endif; ?>

			<?php if ( in_array( 'backup', $la_2fa_methods_available, true ) && 'backup' !== $la_2fa_method ) : ?>
				<div class="la-2fa-footer">
					<a href="<?php echo esc_url( add_query_arg( [
						\LoginArmor\TwoFactor\TwoFactor::VERIFY_PARAM => 'verify',
						'method' => 'backup',
					], wp_login_url() ) ); ?>" class="la-2fa-link la-2fa-link--dim">
						<?php esc_html_e( 'Lost your device? Use a backup code', 'login-armor' ); ?>
					</a>
				</div>
			<?php endif; ?>

			<?php if ( \LoginArmor\TwoFactor\Recovery::is_feature_enabled() && $la_2fa_failures >= 2 ) : ?>
				<div class="la-2fa-footer">
					<a href="<?php echo esc_url( add_query_arg(
						[ \LoginArmor\TwoFactor\TwoFactor::VERIFY_PARAM => \LoginArmor\TwoFactor\Recovery::PARAM_REQUEST ],
						\LoginArmor\HideLogin::get_login_url()
					) ); ?>" class="la-2fa-link la-2fa-link--dim">
						<?php esc_html_e( 'Lost access? Request 2FA reset', 'login-armor' ); ?>
					</a>
				</div>
			<?php endif; ?>
		</div>

		<p class="la-2fa-back">
			<a href="<?php echo esc_url( wp_login_url() ); ?>">&larr; <?php esc_html_e( 'Back to login', 'login-armor' ); ?></a>
		</p>
	</div>

	<?php // phpcs:ignore WordPress.WP.EnqueuedResources.NonEnqueuedScript -- Standalone screen outside WP admin chrome; wp_head/wp_footer hooks are not emitted, so enqueue is not possible. ?>
	<script src="<?php echo esc_url( plugins_url( 'admin/assets/js/two-factor.js', LOGIN_ARMOR_FILE ) ); ?>?ver=<?php echo esc_attr( LOGIN_ARMOR_VERSION ); ?>"></script>
</body>
</html>
