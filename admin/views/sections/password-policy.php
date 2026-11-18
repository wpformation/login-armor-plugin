<?php
/**
 * Password Policy section: Settings tab.
 *
 * Enforces password rules at every core password-set surface (registration,
 * profile edit, lost-password reset), optionally rejecting compromised
 * passwords (reusing the shipped HIBP k-anonymity lookup) and requiring a
 * periodic change.
 *
 * @package LoginArmor
 *
 * @var bool                     $la_pwpolicy_enabled Whether the module is on.
 * @var array<string, bool|int>  $la_pwpolicy         Resolved settings from PasswordPolicy::get_settings().
 */

// phpcs:disable WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}
?>
<section class="la-card la-card--section" id="la-section-password-policy" data-la-section="password-policy">
	<header class="la-card-header">
		<div class="la-card-header__left">
			<div class="la-card-icon">
				<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
					<rect x="3" y="11" width="18" height="11" rx="2"/>
					<path d="M7 11V7a5 5 0 0 1 10 0v4"/>
				</svg>
			</div>
			<div>
				<h2 class="la-card-title">
					<?php esc_html_e( 'Password Policy', 'login-armor' ); ?>
					<?php if ( $la_pwpolicy_enabled ) : ?>
						<span class="la-status-pill la-status-pill--on"><?php esc_html_e( 'ACTIVE', 'login-armor' ); ?></span>
					<?php else : ?>
						<span class="la-status-pill la-status-pill--off"><?php esc_html_e( 'DISABLED', 'login-armor' ); ?></span>
					<?php endif; ?>
				</h2>
				<p class="la-card-subtitle">
					<?php if ( $la_pwpolicy_enabled ) : ?>
						<?php esc_html_e( 'New and changed passwords must meet your rules before they are accepted.', 'login-armor' ); ?>
					<?php else : ?>
						<?php esc_html_e( 'Require strong, unique passwords at registration, profile update, and password reset.', 'login-armor' ); ?>
					<?php endif; ?>
				</p>
			</div>
		</div>
		<?php if ( $la_pwpolicy_enabled ) : ?>
			<button type="button" class="la-btn la-btn--danger la-btn--small" data-la-action="password-policy-disable">
				<?php esc_html_e( 'Disable', 'login-armor' ); ?>
			</button>
		<?php endif; ?>
	</header>

	<div class="la-card-sep"></div>

	<?php if ( ! $la_pwpolicy_enabled ) : ?>

		<div class="la-card-body">
			<div class="la-hide-disabled">
				<div class="la-hide-disabled__warning">
					<div class="la-hide-disabled__warning-icon">
						<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
							<circle cx="12" cy="12" r="10"/>
							<path d="M12 16v-4"/>
							<path d="M12 8h.01"/>
						</svg>
					</div>
					<div class="la-hide-disabled__warning-text">
						<strong><?php esc_html_e( 'Password policy is disabled', 'login-armor' ); ?></strong>
						<span><?php esc_html_e( 'WordPress accepts any password by default, including ones already exposed in public breaches. A policy stops weak and reused passwords at the door.', 'login-armor' ); ?></span>
					</div>
				</div>
				<div class="la-hide-disabled__body">
					<p class="la-hide-disabled__desc">
						<?php esc_html_e( 'When enabled, Login Armor validates every password as it is set: at registration, on the profile screen, and during a lost-password reset. You choose the minimum length and character requirements, and can reject passwords found in public data breaches using the same privacy-preserving Have I Been Pwned lookup as Breach Check.', 'login-armor' ); ?>
					</p>
				</div>
				<div class="la-hide-disabled__actions">
					<button type="button" class="la-btn la-btn--primary la-btn--amber" data-la-action="password-policy-enable">
						<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="width:16px;height:16px;margin-right:6px;">
							<rect x="3" y="11" width="18" height="11" rx="2"/>
							<path d="M7 11V7a5 5 0 0 1 10 0v4"/>
						</svg>
						<?php esc_html_e( 'Enable Password Policy', 'login-armor' ); ?>
					</button>
				</div>
			</div>
		</div>

	<?php else : ?>

		<div class="la-card-body">
			<div data-la-password-policy-form>

				<!-- Minimum length -->
				<div class="la-field">
					<?php // 2.8.0: the number fields are named by their heading and unit (aria-labelledby): none had an accessible name. ?>
					<h4 class="la-field__label" id="la-lbl-min-length"><?php esc_html_e( 'Minimum length', 'login-armor' ); ?></h4>
					<p class="la-field__desc">
						<?php esc_html_e( 'Reject any password shorter than this many characters. NIST recommends at least 12.', 'login-armor' ); ?>
					</p>
					<div class="la-bf-field">
						<input
							type="number"
							class="la-bf-field__input"
							name="min_length"
							aria-labelledby="la-lbl-min-length"
							min="6"
							max="64"
							value="<?php echo esc_attr( (string) (int) $la_pwpolicy['min_length'] ); ?>"
						/>
						<span class="la-bf-field__suffix"><?php esc_html_e( 'characters', 'login-armor' ); ?></span>
					</div>
				</div>

				<div class="la-inner-sep"></div>

				<!-- Character requirements -->
				<div class="la-field">
					<?php // 2.8.0: each switch is named by the sentence beside it: its <label> holds no text. ?>
					<h4 class="la-field__label"><?php esc_html_e( 'Character requirements', 'login-armor' ); ?></h4>
					<p class="la-field__desc">
						<?php esc_html_e( 'Require a mix of character classes. Each enabled rule must be satisfied by the password.', 'login-armor' ); ?>
					</p>

					<div class="la-toggle-row">
						<label class="la-toggle">
							<input type="checkbox" name="require_lower" value="1" <?php checked( ! empty( $la_pwpolicy['require_lower'] ) ); ?> aria-labelledby="la-lbl-pw-lower" />
							<span class="la-toggle__track"></span>
						</label>
						<span class="la-toggle-row__label" id="la-lbl-pw-lower"><?php esc_html_e( 'At least one lowercase letter', 'login-armor' ); ?></span>
					</div>
					<div class="la-toggle-row">
						<label class="la-toggle">
							<input type="checkbox" name="require_upper" value="1" <?php checked( ! empty( $la_pwpolicy['require_upper'] ) ); ?> aria-labelledby="la-lbl-pw-upper" />
							<span class="la-toggle__track"></span>
						</label>
						<span class="la-toggle-row__label" id="la-lbl-pw-upper"><?php esc_html_e( 'At least one uppercase letter', 'login-armor' ); ?></span>
					</div>
					<div class="la-toggle-row">
						<label class="la-toggle">
							<input type="checkbox" name="require_number" value="1" <?php checked( ! empty( $la_pwpolicy['require_number'] ) ); ?> aria-labelledby="la-lbl-pw-number" />
							<span class="la-toggle__track"></span>
						</label>
						<span class="la-toggle-row__label" id="la-lbl-pw-number"><?php esc_html_e( 'At least one number', 'login-armor' ); ?></span>
					</div>
					<div class="la-toggle-row">
						<label class="la-toggle">
							<input type="checkbox" name="require_symbol" value="1" <?php checked( ! empty( $la_pwpolicy['require_symbol'] ) ); ?> aria-labelledby="la-lbl-pw-symbol" />
							<span class="la-toggle__track"></span>
						</label>
						<span class="la-toggle-row__label" id="la-lbl-pw-symbol"><?php esc_html_e( 'At least one symbol', 'login-armor' ); ?></span>
					</div>
					<div class="la-toggle-row">
						<label class="la-toggle">
							<input type="checkbox" name="forbid_username" value="1" <?php checked( ! empty( $la_pwpolicy['forbid_username'] ) ); ?> aria-labelledby="la-lbl-pw-username" />
							<span class="la-toggle__track"></span>
						</label>
						<span class="la-toggle-row__label" id="la-lbl-pw-username"><?php esc_html_e( 'Must not contain the username', 'login-armor' ); ?></span>
					</div>
				</div>

				<div class="la-inner-sep"></div>

				<!-- Block compromised -->
				<div class="la-field">
					<h4 class="la-field__label"><?php esc_html_e( 'Block compromised passwords', 'login-armor' ); ?></h4>
					<p class="la-field__desc">
						<?php esc_html_e( 'Reject passwords that appear in the public Have I Been Pwned corpus. Only the first 5 characters of a one-way hash ever leave your server. If the service is unreachable, the password is allowed (fail-soft) so a reset is never blocked by a third-party outage.', 'login-armor' ); ?>
					</p>
					<div class="la-toggle-row">
						<label class="la-toggle">
							<input type="checkbox" name="block_compromised" value="1" <?php checked( ! empty( $la_pwpolicy['block_compromised'] ) ); ?> aria-labelledby="la-lbl-pw-compromised" />
							<span class="la-toggle__track"></span>
						</label>
						<span class="la-toggle-row__label" id="la-lbl-pw-compromised"><?php esc_html_e( 'Reject passwords found in public data breaches', 'login-armor' ); ?></span>
					</div>
				</div>

				<div class="la-inner-sep"></div>

				<!-- Expiration -->
				<div class="la-field">
					<h4 class="la-field__label" id="la-lbl-expiration-days"><?php esc_html_e( 'Password expiration', 'login-armor' ); ?></h4>
					<p class="la-field__desc">
						<?php esc_html_e( 'Nag users to change their password after this many days. Set to 0 to never expire. Users are redirected to their profile until they change it: they are never locked out. Existing accounts are measured from their next login, never retro-expired.', 'login-armor' ); ?>
					</p>
					<div class="la-bf-field">
						<input
							type="number"
							class="la-bf-field__input"
							name="expiration_days"
							aria-labelledby="la-lbl-expiration-days"
							min="0"
							max="3650"
							value="<?php echo esc_attr( (string) (int) $la_pwpolicy['expiration_days'] ); ?>"
						/>
						<span class="la-bf-field__suffix"><?php esc_html_e( 'days (0 = never)', 'login-armor' ); ?></span>
					</div>
				</div>

			</div>
		</div>

	<?php endif; ?>
</section>
