<?php
/**
 * Two-Factor Authentication section: Settings tab.
 *
 * When disabled, shows a CTA to enable 2FA module.
 * When enabled, shows method selection, enforcement, grace period.
 *
 * @package LoginArmor
 *
 * @var bool   $la_2fa_enabled     Whether 2FA module is globally on.
 * @var array  $la_2fa_methods     Active methods array.
 * @var array  $la_2fa_enforce     Enforced roles array.
 * @var int    $la_2fa_grace       Grace period in days.
 */

// phpcs:disable WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

$la_all_roles    = wp_roles()->role_names;
$la_2fa_stats    = $la_2fa_enabled ? \LoginArmor\TwoFactor\TwoFactor::get_enrollment_stats() : [];
?>
<section class="la-card la-card--section" id="la-section-two-factor" data-la-section="two-factor">
	<header class="la-card-header">
		<div class="la-card-header__left">
			<div class="la-card-icon">
				<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
					<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
					<path d="M12 8v4M12 16h.01"/>
				</svg>
			</div>
			<div>
				<h2 class="la-card-title">
					<?php esc_html_e( 'Two-Factor Authentication', 'login-armor' ); ?>
					<?php if ( $la_2fa_enabled ) : ?>
						<span class="la-status-pill la-status-pill--on"><?php esc_html_e( 'ACTIVE', 'login-armor' ); ?></span>
					<?php else : ?>
						<span class="la-status-pill la-status-pill--off"><?php esc_html_e( 'DISABLED', 'login-armor' ); ?></span>
					<?php endif; ?>
				</h2>
				<p class="la-card-subtitle">
					<?php if ( $la_2fa_enabled ) : ?>
						<?php esc_html_e( 'Require a second factor for admin logins.', 'login-armor' ); ?>
					<?php else : ?>
						<?php esc_html_e( 'Add authenticator app or email verification to logins.', 'login-armor' ); ?>
					<?php endif; ?>
				</p>
			</div>
		</div>
		<?php if ( $la_2fa_enabled ) : ?>
			<button type="button" class="la-btn la-btn--danger la-btn--small" data-la-action="2fa-disable">
				<?php esc_html_e( 'Disable', 'login-armor' ); ?>
			</button>
		<?php endif; ?>
	</header>

	<div class="la-card-sep"></div>

	<?php if ( ! $la_2fa_enabled ) : ?>

		<div class="la-card-body">
			<div class="la-hide-disabled">
				<div class="la-hide-disabled__warning">
					<div class="la-hide-disabled__warning-icon">
						<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
							<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
							<path d="M12 8v4M12 16h.01"/>
						</svg>
					</div>
					<div class="la-hide-disabled__warning-text">
						<strong><?php esc_html_e( 'Two-factor authentication is disabled', 'login-armor' ); ?></strong>
						<span><?php esc_html_e( 'Accounts are protected by passwords only. Compromised credentials allow immediate access.', 'login-armor' ); ?></span>
					</div>
				</div>
				<div class="la-hide-disabled__body">
					<p class="la-hide-disabled__desc">
						<?php esc_html_e( 'When enabled, users can set up an authenticator app (TOTP), email verification codes, or backup codes as a second factor. You can enforce 2FA for specific roles.', 'login-armor' ); ?>
					</p>
				</div>
				<div class="la-hide-disabled__actions">
					<button type="button" class="la-btn la-btn--primary la-btn--amber" data-la-action="2fa-enable">
						<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="width:16px;height:16px;margin-right:6px;">
							<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
						</svg>
						<?php esc_html_e( 'Enable Two-Factor Authentication', 'login-armor' ); ?>
					</button>
				</div>
			</div>
		</div>

	<?php else : ?>

		<div class="la-card-body">
			<div data-la-2fa-settings-form>

				<!-- Field 1: Methods -->
				<div class="la-field">
					<h4 class="la-field__label"><?php esc_html_e( 'Allowed Methods', 'login-armor' ); ?></h4>
					<p class="la-field__desc"><?php esc_html_e( 'Choose which authentication methods users can use.', 'login-armor' ); ?></p>

					<div class="la-inline-fields" style="flex-direction:column;gap:8px;">
						<label class="la-toggle-label">
							<input type="checkbox" name="method_totp" value="totp" <?php checked( in_array( 'totp', $la_2fa_methods, true ) ); ?>>
							<?php esc_html_e( 'Authenticator App (TOTP)', 'login-armor' ); ?>
						</label>
						<label class="la-toggle-label">
							<input type="checkbox" name="method_email" value="email" <?php checked( in_array( 'email', $la_2fa_methods, true ) ); ?>>
							<?php esc_html_e( 'Email verification code', 'login-armor' ); ?>
						</label>
						<label class="la-toggle-label">
							<input type="checkbox" name="method_backup" value="backup" <?php checked( in_array( 'backup', $la_2fa_methods, true ) ); ?>>
							<?php esc_html_e( 'Backup codes', 'login-armor' ); ?>
						</label>
					</div>
				</div>

				<div class="la-inner-sep"></div>

				<!-- Field 2: Enforcement -->
				<div class="la-field">
					<h4 class="la-field__label"><?php esc_html_e( 'Enforcement', 'login-armor' ); ?></h4>
					<p class="la-field__desc"><?php esc_html_e( 'Select roles that must use 2FA. Leave empty for voluntary-only.', 'login-armor' ); ?></p>

					<div class="la-inline-fields" style="flex-direction:column;gap:8px;">
						<?php foreach ( $la_all_roles as $la_role_slug => $la_role_name ) : ?>
							<label class="la-toggle-label">
								<input type="checkbox" name="enforce_roles[]" value="<?php echo esc_attr( $la_role_slug ); ?>" <?php checked( in_array( $la_role_slug, $la_2fa_enforce, true ) ); ?>>
								<?php echo esc_html( translate_user_role( $la_role_name ) ); ?>
							</label>
						<?php endforeach; ?>
					</div>
				</div>

				<div class="la-inner-sep"></div>

				<!-- Field 3: Grace Period -->
				<div class="la-field">
					<?php // 2.8.0: named by its heading (aria-labelledby): it had no accessible name. ?>
					<h4 class="la-field__label" id="la-lbl-grace-days"><?php esc_html_e( 'Grace Period', 'login-armor' ); ?></h4>
					<p class="la-field__desc"><?php esc_html_e( 'How long users in enforced roles have to set up 2FA after it becomes required.', 'login-armor' ); ?></p>

					<div class="la-inline-fields">
						<div class="la-inline-field">
							<select class="la-select" name="grace_days" aria-labelledby="la-lbl-grace-days">
								<?php
								$la_grace_options = [ 1, 3, 7, 14 ];
								foreach ( $la_grace_options as $la_days ) :
									$la_label = sprintf(
										/* translators: %d: number of days */
										_n( '%d day', '%d days', $la_days, 'login-armor' ),
										$la_days
									);
								?>
									<option value="<?php echo esc_attr( $la_days ); ?>" <?php selected( $la_2fa_grace, $la_days ); ?>><?php echo esc_html( $la_label ); ?></option>
								<?php endforeach; ?>
							</select>
						</div>
					</div>
				</div>

				<div class="la-inner-sep"></div>

				<?php
				$la_2fa_td_enabled   = (bool) get_option( \LoginArmor\TwoFactor\TrustedDevices::OPTION_ENABLED, true );
				$la_2fa_td_duration  = \LoginArmor\TwoFactor\TrustedDevices::get_duration_days();
				$la_2fa_td_durations = \LoginArmor\TwoFactor\TrustedDevices::ALLOWED_DURATIONS;
				?>
				<!-- Field: Trusted Devices -->
				<div class="la-field">
					<h4 class="la-field__label"><?php esc_html_e( 'Trusted Devices', 'login-armor' ); ?></h4>
					<p class="la-field__desc"><?php esc_html_e( 'Let users trust their browser for N days after a successful 2FA verification. Disable for strict compliance (every login requires a second factor).', 'login-armor' ); ?></p>

					<div class="la-inline-fields" style="flex-direction:column;gap:8px;">
						<label class="la-toggle-label">
							<input type="checkbox" name="allow_trusted_devices" value="1" <?php checked( $la_2fa_td_enabled ); ?>>
							<?php esc_html_e( 'Allow trusted devices', 'login-armor' ); ?>
						</label>
					</div>

					<div class="la-inline-fields" style="margin-top:8px;">
						<div class="la-inline-field">
							<label class="la-field__inline-label" for="la-2fa-td-duration"><?php esc_html_e( 'Duration', 'login-armor' ); ?></label>
							<select id="la-2fa-td-duration" class="la-select" name="trusted_devices_duration_days" <?php disabled( ! $la_2fa_td_enabled ); ?>>
								<?php foreach ( $la_2fa_td_durations as $la_d ) : ?>
									<?php
									$la_td_label = sprintf(
										/* translators: %d: number of days */
										_n( '%d day', '%d days', $la_d, 'login-armor' ),
										$la_d
									);
									?>
									<option value="<?php echo esc_attr( $la_d ); ?>" <?php selected( $la_2fa_td_duration, $la_d ); ?>><?php echo esc_html( $la_td_label ); ?></option>
								<?php endforeach; ?>
							</select>
						</div>
					</div>
				</div>

				<div class="la-inner-sep"></div>

				<?php
				$la_2fa_recov_enabled = (bool) get_option( \LoginArmor\TwoFactor\Recovery::OPTION_ENABLED, true );
				?>
				<!-- Field: 2FA Recovery -->
				<div class="la-field">
					<h4 class="la-field__label"><?php esc_html_e( '2FA Recovery', 'login-armor' ); ?></h4>
					<p class="la-field__desc"><?php esc_html_e( 'Allow users who have lost every 2FA method to request a reset. The request is emailed to the first site administrator, who must authorize it. Disable for strict compliance.', 'login-armor' ); ?></p>

					<div class="la-inline-fields" style="flex-direction:column;gap:8px;">
						<label class="la-toggle-label">
							<input type="checkbox" name="allow_2fa_recovery" value="1" <?php checked( $la_2fa_recov_enabled ); ?>>
							<?php esc_html_e( 'Allow account recovery when 2FA is lost', 'login-armor' ); ?>
						</label>
					</div>
				</div>

				<div class="la-inner-sep"></div>

				<!-- Field 4: Enrollment Status (read-only) -->
				<?php if ( ! empty( $la_2fa_stats ) ) : ?>
					<div class="la-field">
						<h4 class="la-field__label"><?php esc_html_e( 'Enrollment Status', 'login-armor' ); ?></h4>
						<?php foreach ( $la_2fa_stats as $la_role_slug => $la_stat ) : ?>
							<p class="la-field__desc">
								<?php
								echo esc_html( sprintf(
									/* translators: 1: enrolled count, 2: total count, 3: role name */
									__( '%1$d of %2$d %3$s users have 2FA active', 'login-armor' ),
									$la_stat['enrolled'],
									$la_stat['total'],
									translate_user_role( wp_roles()->role_names[ $la_role_slug ] ?? $la_role_slug )
								) );
								?>
							</p>
						<?php endforeach; ?>
					</div>
				<?php endif; ?>

				<div class="la-inner-sep"></div>

				<!-- Your 2FA status -->
				<?php
				$la_2fa_current_user_on = (bool) get_user_meta( get_current_user_id(), 'login_armor_2fa_enabled', true );
				?>
				<div class="la-field">
					<h4 class="la-field__label"><?php esc_html_e( 'Your Account', 'login-armor' ); ?></h4>
					<?php if ( $la_2fa_current_user_on ) : ?>
						<p class="la-field__desc"><?php esc_html_e( 'Two-factor authentication is active on your account.', 'login-armor' ); ?></p>
						<a href="<?php echo esc_url( admin_url( 'profile.php#login-armor-2fa' ) ); ?>" class="la-btn la-btn--small">
							<?php esc_html_e( 'Manage your 2FA', 'login-armor' ); ?>
						</a>
					<?php else : ?>
						<p class="la-field__desc"><?php esc_html_e( 'You have not set up two-factor authentication yet.', 'login-armor' ); ?></p>
						<a href="<?php echo esc_url( admin_url( 'profile.php#login-armor-2fa' ) ); ?>" class="la-btn la-btn--primary la-btn--small">
							<?php esc_html_e( 'Set up your 2FA', 'login-armor' ); ?>
						</a>
					<?php endif; ?>
				</div>

				</div>
		</div>

	<?php endif; ?>
</section>
