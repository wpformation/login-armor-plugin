<?php
/**
 * Session Manager section: Settings tab.
 *
 * Idle timeout, maximum session lifetime, single active session, and an
 * on-demand "log out other devices" action.
 *
 * @package LoginArmor
 *
 * @var bool                    $la_session_enabled Whether the module is on.
 * @var array<string, bool|int> $la_session         Settings from SessionManager::get_settings().
 * @var int                     $la_session_count   Active sessions for the current admin.
 */

// phpcs:disable WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}
?>
<section class="la-card la-card--section" id="la-section-session" data-la-section="session">
	<header class="la-card-header">
		<div class="la-card-header__left">
			<div class="la-card-icon">
				<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
					<circle cx="12" cy="12" r="9"/>
					<path d="M12 7v5l3 2"/>
				</svg>
			</div>
			<div>
				<h2 class="la-card-title">
					<?php esc_html_e( 'Session Management', 'login-armor' ); ?>
					<?php if ( $la_session_enabled ) : ?>
						<span class="la-status-pill la-status-pill--on"><?php esc_html_e( 'ACTIVE', 'login-armor' ); ?></span>
					<?php else : ?>
						<span class="la-status-pill la-status-pill--off"><?php esc_html_e( 'DISABLED', 'login-armor' ); ?></span>
					<?php endif; ?>
				</h2>
				<p class="la-card-subtitle">
					<?php if ( $la_session_enabled ) : ?>
						<?php esc_html_e( 'Idle accounts are logged out and session lifetime is capped.', 'login-armor' ); ?>
					<?php else : ?>
						<?php esc_html_e( 'Log out idle accounts, cap how long a login lasts, and limit logins to one device.', 'login-armor' ); ?>
					<?php endif; ?>
				</p>
			</div>
		</div>
		<?php if ( $la_session_enabled ) : ?>
			<button type="button" class="la-btn la-btn--danger la-btn--small" data-la-action="session-disable">
				<?php esc_html_e( 'Disable', 'login-armor' ); ?>
			</button>
		<?php endif; ?>
	</header>

	<div class="la-card-sep"></div>

	<?php if ( ! $la_session_enabled ) : ?>

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
						<strong><?php esc_html_e( 'Session management is disabled', 'login-armor' ); ?></strong>
						<span><?php esc_html_e( 'By default a WordPress login stays valid for up to 14 days on any number of devices, even if the computer is left unattended. Session management closes that window.', 'login-armor' ); ?></span>
					</div>
				</div>
				<div class="la-hide-disabled__body">
					<p class="la-hide-disabled__desc">
						<?php esc_html_e( 'When enabled, you can automatically log out accounts that have been idle for a set time, cap the maximum lifetime of any login, and optionally restrict each account to a single active device: logging in elsewhere ends the previous session.', 'login-armor' ); ?>
					</p>
				</div>
				<div class="la-hide-disabled__actions">
					<button type="button" class="la-btn la-btn--primary la-btn--amber" data-la-action="session-enable">
						<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="width:16px;height:16px;margin-right:6px;">
							<circle cx="12" cy="12" r="9"/>
							<path d="M12 7v5l3 2"/>
						</svg>
						<?php esc_html_e( 'Enable Session Management', 'login-armor' ); ?>
					</button>
				</div>
			</div>
		</div>

	<?php else : ?>

		<div class="la-card-body">
			<div data-la-session-form>

				<!-- Idle timeout -->
				<div class="la-field">
					<?php // 2.8.0: the number fields are named by their heading and unit (aria-labelledby): none had an accessible name. ?>
					<h4 class="la-field__label" id="la-lbl-idle-timeout"><?php esc_html_e( 'Idle timeout', 'login-armor' ); ?></h4>
					<p class="la-field__desc">
						<?php esc_html_e( 'Log an account out after this many minutes of inactivity. Inactivity is measured on real page loads: background heartbeat traffic does not keep a session alive. Set to 0 to disable.', 'login-armor' ); ?>
					</p>
					<div class="la-bf-field">
						<input
							type="number"
							class="la-bf-field__input"
							name="idle_timeout_min"
							aria-labelledby="la-lbl-idle-timeout la-lbl-idle-timeout-unit"
							min="0"
							max="1440"
							value="<?php echo esc_attr( (string) (int) $la_session['idle_timeout_min'] ); ?>"
						/>
						<span class="la-bf-field__suffix" id="la-lbl-idle-timeout-unit"><?php esc_html_e( 'minutes (0 = off)', 'login-armor' ); ?></span>
					</div>
				</div>

				<div class="la-inner-sep"></div>

				<!-- Max lifetime -->
				<div class="la-field">
					<h4 class="la-field__label" id="la-lbl-max-lifetime"><?php esc_html_e( 'Maximum session lifetime', 'login-armor' ); ?></h4>
					<p class="la-field__desc">
						<?php esc_html_e( 'Cap how long any login cookie stays valid, regardless of "remember me". WordPress allows up to 14 days by default. Set to 0 to leave the WordPress default unchanged.', 'login-armor' ); ?>
					</p>
					<div class="la-bf-field">
						<input
							type="number"
							class="la-bf-field__input"
							name="max_lifetime_hours"
							aria-labelledby="la-lbl-max-lifetime"
							min="0"
							max="8760"
							value="<?php echo esc_attr( (string) (int) $la_session['max_lifetime_hours'] ); ?>"
						/>
						<span class="la-bf-field__suffix"><?php esc_html_e( 'hours (0 = WordPress default)', 'login-armor' ); ?></span>
					</div>
				</div>

				<div class="la-inner-sep"></div>

				<!-- Single session -->
				<div class="la-field">
					<h4 class="la-field__label"><?php esc_html_e( 'Single active session', 'login-armor' ); ?></h4>
					<p class="la-field__desc">
						<?php esc_html_e( 'Restrict each account to one device at a time. Logging in from a new device ends every other session for that account. Useful for shared admin accounts and to limit credential sharing.', 'login-armor' ); ?>
					</p>
					<div class="la-toggle-row">
						<label class="la-toggle">
							<input type="checkbox" name="single_session" value="1" <?php checked( ! empty( $la_session['single_session'] ) ); ?> aria-labelledby="la-lbl-single-session" />
							<span class="la-toggle__track"></span>
						</label>
						<?php // 2.8.0: the switch is named by the sentence beside it: its <label> holds no text. ?>
						<span class="la-toggle-row__label" id="la-lbl-single-session"><?php esc_html_e( 'Allow only one active session per account', 'login-armor' ); ?></span>
					</div>
				</div>

				<div class="la-inner-sep"></div>

				<!-- Log out other devices -->
				<div class="la-field">
					<h4 class="la-field__label"><?php esc_html_e( 'Your active sessions', 'login-armor' ); ?></h4>
					<p class="la-field__desc">
						<?php
						echo esc_html(
							sprintf(
								/* translators: %d: number of active sessions for the current administrator account. */
								_n(
									'Your account currently has %d active session.',
									'Your account currently has %d active sessions.',
									(int) $la_session_count,
									'login-armor'
								),
								(int) $la_session_count
							)
						);
						?>
					</p>
					<button type="button" class="la-btn la-btn--ghost la-btn--small" data-la-action="session-logout-others">
						<?php esc_html_e( 'Sign out all other devices', 'login-armor' ); ?>
					</button>
				</div>

			</div>
		</div>

	<?php endif; ?>
</section>
