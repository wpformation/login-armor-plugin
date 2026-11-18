<?php
/**
 * Two-Factor Authentication section for the user Profile page.
 *
 * Shows setup wizard when 2FA is not configured, status view when active.
 * Injected via show_user_profile / edit_user_profile hooks.
 *
 * @package LoginArmor
 * @since   2.2.0
 *
 * @var \WP_User $la_2fa_profile_user The user being edited.
 */

// phpcs:disable WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

$la_2fa_is_own_profile = ( get_current_user_id() === $la_2fa_profile_user->ID );
$la_2fa_user_enabled   = \LoginArmor\TwoFactor\TwoFactor::is_user_enabled( $la_2fa_profile_user->ID );
$la_2fa_user_method    = \LoginArmor\TwoFactor\TwoFactor::get_user_method( $la_2fa_profile_user->ID );
$la_2fa_user_confirmed = (bool) get_user_meta( $la_2fa_profile_user->ID, 'login_armor_2fa_confirmed', true );
$la_2fa_backup_remaining = \LoginArmor\TwoFactor\BackupCodes::remaining( $la_2fa_profile_user->ID );
$la_2fa_totp_available = \LoginArmor\TwoFactor\TwoFactor::is_method_enabled( 'totp' );
$la_2fa_email_available = \LoginArmor\TwoFactor\TwoFactor::is_method_enabled( 'email' );
$la_2fa_required = \LoginArmor\TwoFactor\TwoFactor::is_required_for_user( $la_2fa_profile_user->ID );
?>

<div class="la-2fa-profile" id="login-armor-2fa">
	<div class="la-2fa-profile__card">
		<div class="la-2fa-profile__header">
			<svg class="la-2fa-profile__icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
				<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
				<path d="M12 8v4M12 16h.01"/>
			</svg>
			<h2 class="la-2fa-profile__title">
				<?php esc_html_e( 'Login Armor: Two-Factor Authentication', 'login-armor' ); ?>
				<?php if ( $la_2fa_user_enabled && $la_2fa_user_confirmed ) : ?>
					<span class="la-2fa-profile__status la-2fa-profile__status--active"><?php esc_html_e( 'Active', 'login-armor' ); ?></span>
				<?php else : ?>
					<span class="la-2fa-profile__status la-2fa-profile__status--inactive"><?php esc_html_e( 'Not configured', 'login-armor' ); ?></span>
				<?php endif; ?>
			</h2>
		</div>

		<div class="la-2fa-profile__sep"></div>

		<?php if ( $la_2fa_user_enabled && $la_2fa_user_confirmed ) : ?>
			<!-- Status View -->
			<div class="la-2fa-status__row">
				<span class="la-2fa-status__label"><?php esc_html_e( 'Method', 'login-armor' ); ?></span>
				<span class="la-2fa-status__value">
					<?php
					match ( $la_2fa_user_method ) {
						'totp'  => esc_html_e( 'Authenticator App', 'login-armor' ),
						'email' => esc_html_e( 'Email', 'login-armor' ),
						default => esc_html_e( 'Unknown', 'login-armor' ),
					};
					?>
				</span>
			</div>

			<div class="la-2fa-status__row">
				<span class="la-2fa-status__label"><?php esc_html_e( 'Backup codes', 'login-armor' ); ?></span>
				<?php /* translators: %d: number of unused backup codes remaining */ ?>
				<span class="la-2fa-status__value"><?php echo esc_html( sprintf( __( '%d remaining', 'login-armor' ), $la_2fa_backup_remaining ) ); ?></span>
			</div>

			<?php
			require_once LOGIN_ARMOR_DIR . 'includes/TwoFactor/TrustedDevices.php';
			$la_2fa_td_enabled = \LoginArmor\TwoFactor\TrustedDevices::is_feature_enabled();
			$la_2fa_td_devices = $la_2fa_td_enabled ? \LoginArmor\TwoFactor\TrustedDevices::list_for_user( $la_2fa_profile_user->ID ) : [];
			$la_2fa_td_count   = count( $la_2fa_td_devices );
			?>
			<?php if ( $la_2fa_td_enabled ) : ?>
				<div class="la-2fa-status__row">
					<span class="la-2fa-status__label"><?php esc_html_e( 'Trusted devices', 'login-armor' ); ?></span>
					<span class="la-2fa-status__value">
						<?php
						echo esc_html(
							sprintf(
								/* translators: %d: number of active trusted devices */
								_n( '%d active', '%d active', $la_2fa_td_count, 'login-armor' ),
								$la_2fa_td_count
							)
						);
						?>
					</span>
				</div>

				<?php if ( $la_2fa_is_own_profile && $la_2fa_td_count > 0 ) : ?>
					<div class="la-2fa-devices" data-la-2fa-devices>
						<?php foreach ( $la_2fa_td_devices as $la_device ) : ?>
							<div class="la-2fa-device" data-device-id="<?php echo esc_attr( $la_device['id'] ); ?>">
								<div class="la-2fa-device__meta">
									<strong class="la-2fa-device__label"><?php echo esc_html( $la_device['label'] ); ?></strong>
									<div class="la-2fa-device__sub">
										<span><?php echo esc_html( $la_device['ip_at_grant'] ); ?></span>
										<span aria-hidden="true">&middot;</span>
										<span>
											<?php
											printf(
												/* translators: 1: granted date, 2: expires date */
												esc_html__( 'granted %1$s · expires %2$s', 'login-armor' ),
												esc_html( wp_date( 'Y-m-d', (int) $la_device['granted_at'] ) ),
												esc_html( wp_date( 'Y-m-d', (int) $la_device['expires_at'] ) )
											);
											?>
										</span>
									</div>
								</div>
								<button type="button" class="la-2fa-profile__btn la-2fa-profile__btn--danger la-2fa-device__revoke" data-la-2fa-action="revoke-device" data-device-id="<?php echo esc_attr( $la_device['id'] ); ?>">
									<?php esc_html_e( 'Revoke', 'login-armor' ); ?>
								</button>
							</div>
						<?php endforeach; ?>

						<div class="la-2fa-devices__footer">
							<button type="button" class="la-2fa-profile__btn la-2fa-profile__btn--danger" data-la-2fa-action="revoke-all-devices">
								<?php esc_html_e( 'Revoke all devices', 'login-armor' ); ?>
							</button>
						</div>
					</div>
				<?php endif; ?>
			<?php endif; ?>

			<div class="la-2fa-profile__sep"></div>

			<?php if ( $la_2fa_is_own_profile ) : ?>
				<div class="la-2fa-profile__actions">
					<?php if ( ! $la_2fa_required ) : ?>
						<button type="button" class="la-2fa-profile__btn la-2fa-profile__btn--danger" data-la-2fa-action="disable">
							<?php esc_html_e( 'Disable 2FA', 'login-armor' ); ?>
						</button>
					<?php endif; ?>
					<button type="button" class="la-2fa-profile__btn" data-la-2fa-action="regenerate-codes">
						<?php esc_html_e( 'Regenerate backup codes', 'login-armor' ); ?>
					</button>
				</div>
				<?php if ( $la_2fa_required ) : ?>
					<p class="la-2fa-profile__info"><?php esc_html_e( 'Two-factor authentication is required for your role. A site administrator must authorize any reset.', 'login-armor' ); ?></p>
				<?php endif; ?>
			<?php elseif ( current_user_can( 'manage_options' ) ) : ?>
				<div class="la-2fa-profile__actions">
					<button type="button" class="la-2fa-profile__btn la-2fa-profile__btn--danger" data-la-2fa-action="admin-reset" data-user-id="<?php echo esc_attr( $la_2fa_profile_user->ID ); ?>">
						<?php esc_html_e( 'Reset 2FA for this user', 'login-armor' ); ?>
					</button>
				</div>
			<?php endif; ?>

		<?php else : ?>
			<!-- Setup View -->
			<?php if ( $la_2fa_is_own_profile ) : ?>
				<p class="la-2fa-profile__info">
					<?php esc_html_e( 'Protect your account with a second factor. Choose your preferred method:', 'login-armor' ); ?>
				</p>

				<div class="la-2fa-profile__actions">
					<?php if ( $la_2fa_totp_available ) : ?>
						<button type="button" class="la-2fa-profile__btn la-2fa-profile__btn--primary" data-la-2fa-action="start-totp">
							<?php esc_html_e( 'Set up Authenticator App', 'login-armor' ); ?>
						</button>
					<?php endif; ?>
					<?php if ( $la_2fa_email_available ) : ?>
						<button type="button" class="la-2fa-profile__btn" data-la-2fa-action="start-email">
							<?php esc_html_e( 'Set up Email', 'login-armor' ); ?>
						</button>
					<?php endif; ?>
				</div>
			<?php else : ?>
				<p class="la-2fa-profile__info"><?php esc_html_e( 'This user has not configured two-factor authentication.', 'login-armor' ); ?></p>
			<?php endif; ?>
		<?php endif; ?>

		<?php if ( $la_2fa_is_own_profile ) : ?>
		<!-- Setup Wizard (hidden by default, shown via JS) -->
		<div id="la-2fa-wizard" class="la-2fa-wizard" hidden>
			<!-- Step 0: QR Code (TOTP only) -->
			<div class="la-2fa-wizard__step">
				<p class="la-2fa-wizard__help"><?php esc_html_e( 'Open your authenticator app, tap +, and scan this QR code:', 'login-armor' ); ?></p>
				<div class="la-2fa-wizard__qr"></div>
				<div class="la-2fa-wizard__secret">
					<span class="la-2fa-wizard__secret-text"></span>
					<button type="button" class="la-2fa-wizard__copy"><?php esc_html_e( 'Copy', 'login-armor' ); ?></button>
				</div>
				<p class="la-2fa-wizard__help"><?php esc_html_e( 'Or enter this key manually in your app.', 'login-armor' ); ?></p>
				<div class="la-2fa-profile__sep"></div>
				<p class="la-2fa-wizard__help" id="la-2fa-wizard-totp-desc"><?php esc_html_e( 'Enter the 6-digit code from your app to verify:', 'login-armor' ); ?></p>
				<input type="text" class="la-2fa-wizard__verify-input" inputmode="numeric" pattern="[0-9]{6}" maxlength="6" placeholder="000000" autocomplete="one-time-code" aria-label="<?php esc_attr_e( 'Authenticator verification code', 'login-armor' ); ?>" aria-describedby="la-2fa-wizard-totp-desc">
				<div class="la-2fa-wizard__error" role="alert" aria-live="polite"></div>
				<div class="la-2fa-profile__actions" style="margin-top:12px;">
					<button type="button" class="la-2fa-profile__btn la-2fa-profile__btn--primary" data-la-2fa-action="verify-setup"><?php esc_html_e( 'Verify and continue', 'login-armor' ); ?></button>
				</div>
			</div>

			<!-- Step 1: Verify (Email method, code sent to email) -->
			<div class="la-2fa-wizard__step">
				<p class="la-2fa-wizard__help" id="la-2fa-wizard-email-desc"><?php esc_html_e( 'A verification code has been sent to your email. Enter it below:', 'login-armor' ); ?></p>
				<input type="text" class="la-2fa-wizard__verify-input" inputmode="numeric" pattern="[0-9]{6}" maxlength="6" placeholder="000000" autocomplete="one-time-code" aria-label="<?php esc_attr_e( 'Email verification code', 'login-armor' ); ?>" aria-describedby="la-2fa-wizard-email-desc">
				<div class="la-2fa-wizard__error" role="alert" aria-live="polite"></div>
				<div class="la-2fa-profile__actions" style="margin-top:12px;">
					<button type="button" class="la-2fa-profile__btn la-2fa-profile__btn--primary" data-la-2fa-action="verify-setup"><?php esc_html_e( 'Verify and continue', 'login-armor' ); ?></button>
				</div>
			</div>

			<!-- Step 2: Backup Codes -->
			<div class="la-2fa-wizard__step">
				<p class="la-2fa-wizard__help"><?php esc_html_e( 'Save these backup codes in a safe place. Each can only be used once.', 'login-armor' ); ?></p>
				<div class="la-2fa-wizard__codes"></div>
				<div class="la-2fa-profile__actions">
					<button type="button" class="la-2fa-profile__btn" data-la-2fa-action="download-codes"><?php esc_html_e( 'Download codes', 'login-armor' ); ?></button>
				</div>
				<label class="la-2fa-wizard__confirm">
					<input type="checkbox">
					<?php esc_html_e( "I've saved my backup codes", 'login-armor' ); ?>
				</label>
				<div class="la-2fa-profile__actions" style="margin-top:12px;">
					<button type="button" class="la-2fa-profile__btn la-2fa-profile__btn--primary" data-la-2fa-action="complete-setup" disabled><?php esc_html_e( 'Complete setup', 'login-armor' ); ?></button>
				</div>
				<div class="la-2fa-wizard__error" role="alert" aria-live="polite"></div>
			</div>
		</div>
		<?php endif; ?>
	</div>
</div>
