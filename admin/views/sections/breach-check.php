<?php
/**
 * Breach Check section: Settings tab.
 *
 * Enables the HIBP password check + optional XposedOrNot email check,
 * and lets the admin opt into forcing a password reset for flagged users.
 * No API key required: both services are called via zero-cost public
 * endpoints (HIBP uses k-anonymity; XposedOrNot is keyless).
 *
 * @package LoginArmor
 *
 * @var bool  $la_breach_enabled             Whether the module is on.
 * @var bool  $la_breach_check_passwords     Whether HIBP password check is on.
 * @var bool  $la_breach_check_emails        Whether XposedOrNot email check is on.
 * @var bool  $la_breach_force_reset         Whether flagged users are forced to reset.
 * @var array $la_breach_flagged_counts      ['password'=>int,'email'=>int] from BreachCheck::get_flagged_counts().
 * @var array $la_breach_flagged_users       Detailed list of flagged users, from BreachCheck::get_flagged_users().
 */

// phpcs:disable WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}
?>
<section class="la-card la-card--section" id="la-section-breach-check" data-la-section="breach-check">
	<header class="la-card-header">
		<div class="la-card-header__left">
			<div class="la-card-icon">
				<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
					<circle cx="11" cy="11" r="7"/>
					<path d="m21 21-4.3-4.3"/>
				</svg>
			</div>
			<div>
				<h2 class="la-card-title">
					<?php esc_html_e( 'Breach Check', 'login-armor' ); ?>
					<?php if ( $la_breach_enabled ) : ?>
						<span class="la-status-pill la-status-pill--on"><?php esc_html_e( 'ACTIVE', 'login-armor' ); ?></span>
					<?php else : ?>
						<span class="la-status-pill la-status-pill--off"><?php esc_html_e( 'DISABLED', 'login-armor' ); ?></span>
					<?php endif; ?>
				</h2>
				<p class="la-card-subtitle">
					<?php if ( $la_breach_enabled ) : ?>
						<?php esc_html_e( 'Passwords and email addresses are checked against public data breach corpora on login and profile update.', 'login-armor' ); ?>
					<?php else : ?>
						<?php esc_html_e( 'Detect if your users are logging in with a password or email that appears in public data leaks.', 'login-armor' ); ?>
					<?php endif; ?>
				</p>
			</div>
		</div>
		<?php if ( $la_breach_enabled ) : ?>
			<button type="button" class="la-btn la-btn--danger la-btn--small" data-la-action="breach-check-disable">
				<?php esc_html_e( 'Disable', 'login-armor' ); ?>
			</button>
		<?php endif; ?>
	</header>

	<div class="la-card-sep"></div>

	<?php if ( ! $la_breach_enabled ) : ?>

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
						<strong><?php esc_html_e( 'Breach Check is disabled', 'login-armor' ); ?></strong>
						<span><?php esc_html_e( 'The first cause of account takeover today is credential reuse: users logging in with a password that already leaked somewhere else. This module detects that condition passively, without blocking anyone.', 'login-armor' ); ?></span>
					</div>
				</div>
				<div class="la-hide-disabled__body">
					<p class="la-hide-disabled__desc">
						<?php esc_html_e( 'When a user logs in, Login Armor checks the password against the public Have I Been Pwned corpus using a privacy-preserving range lookup: only the first 5 characters of a one-way hash ever leave your server. If a match is found, the user gets a friendly warning on their profile page inviting them to change their password. Admins see the count of flagged users on the overview.', 'login-armor' ); ?>
					</p>
					<p class="la-hide-disabled__desc">
						<strong><?php esc_html_e( 'Zero dependencies, zero keys.', 'login-armor' ); ?></strong>
						<?php
						// 2.8.0: the sentence said emails never leave the server in
						// readable form. The optional email check sends the address
						// itself to XposedOrNot (readme, External Services).
						esc_html_e( 'The APIs are free and keyless. Passwords never leave the server in readable form. The optional email check, off by default, sends the email address itself to XposedOrNot.', 'login-armor' );
						?>
					</p>
				</div>
				<div class="la-hide-disabled__actions">
					<button type="button" class="la-btn la-btn--primary la-btn--amber" data-la-action="breach-check-enable">
						<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="width:16px;height:16px;margin-right:6px;">
							<circle cx="11" cy="11" r="7"/>
							<path d="m21 21-4.3-4.3"/>
						</svg>
						<?php esc_html_e( 'Enable Breach Check', 'login-armor' ); ?>
					</button>
				</div>
			</div>
		</div>

	<?php else : ?>

		<div class="la-card-body">
			<div data-la-breach-check-form>

				<!-- Info banner: explain the bulk-scan scope on module activation -->
				<div class="la-breach-info">
					<div class="la-breach-info__icon" aria-hidden="true">
						<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round">
							<circle cx="12" cy="12" r="10"/>
							<path d="M12 16v-4"/>
							<path d="M12 8h.01"/>
						</svg>
					</div>
					<div class="la-breach-info__text">
						<strong><?php esc_html_e( 'What gets checked, and when', 'login-armor' ); ?></strong>
						<p>
							<strong><?php esc_html_e( 'Email addresses:', 'login-armor' ); ?></strong>
							<?php esc_html_e( 'every administrator account is tested against the public breach list the moment you enable the email check. The counters below update straight away.', 'login-armor' ); ?>
						</p>
						<p>
							<strong><?php esc_html_e( 'Passwords:', 'login-armor' ); ?></strong>
							<?php esc_html_e( 'existing passwords cannot be tested in bulk. WordPress only keeps a one-way fingerprint of each password, which by design cannot be reversed into the original text. Each password is therefore tested the next time its user logs in, while WordPress briefly handles the plaintext to authenticate them. No login is ever blocked. A flagged user just sees a friendly heads-up on their profile page, inviting them to change the password.', 'login-armor' ); ?>
						</p>
					</div>
				</div>

				<div class="la-inner-sep"></div>

				<!-- Field 1: Password check toggle -->
				<div class="la-field">
					<h4 class="la-field__label"><?php esc_html_e( 'Password check', 'login-armor' ); ?></h4>
					<p class="la-field__desc">
						<?php esc_html_e( 'On each successful login, check the password against the Have I Been Pwned corpus via its k-anonymity range API. Only the first 5 characters of a SHA-1 hash of the password leave your server: the password itself is never transmitted, not even in hashed form.', 'login-armor' ); ?>
					</p>
					<div class="la-toggle-row">
						<label class="la-toggle">
							<input
								type="checkbox"
								name="breach_check_passwords"
								aria-labelledby="la-lbl-breach-passwords"
								value="1"
								<?php checked( (bool) $la_breach_check_passwords ); ?>
							/>
							<span class="la-toggle__track"></span>
						</label>
						<?php // 2.8.0: each switch is named by the sentence beside it: its <label> holds no text. ?>
						<span class="la-toggle-row__label" id="la-lbl-breach-passwords"><?php esc_html_e( 'Check passwords on login and profile update', 'login-armor' ); ?></span>
					</div>
				</div>

				<div class="la-inner-sep"></div>

				<!-- Field 2: Email check toggle -->
				<div class="la-field">
					<h4 class="la-field__label"><?php esc_html_e( 'Email check', 'login-armor' ); ?></h4>
					<p class="la-field__desc">
						<?php esc_html_e( 'When a new user is created or an email is changed, check the address against the XposedOrNot public breach list. The API returns the names of the breaches that contain the address, so users can know which passwords they may have reused.', 'login-armor' ); ?>
						<?php esc_html_e( 'Unlike the password check, this sends the email address itself to XposedOrNot.', 'login-armor' ); ?>
					</p>
					<div class="la-toggle-row">
						<label class="la-toggle">
							<input
								type="checkbox"
								name="breach_check_emails"
								aria-labelledby="la-lbl-breach-emails"
								value="1"
								<?php checked( (bool) $la_breach_check_emails ); ?>
							/>
							<span class="la-toggle__track"></span>
						</label>
						<span class="la-toggle-row__label" id="la-lbl-breach-emails"><?php esc_html_e( 'Check email addresses on user creation and email change', 'login-armor' ); ?></span>
					</div>
				</div>

				<div class="la-inner-sep"></div>

				<!-- Field 3: Force password reset -->
				<div class="la-field">
					<h4 class="la-field__label"><?php esc_html_e( 'Force password reset for flagged users', 'login-armor' ); ?></h4>
					<p class="la-field__desc">
						<?php esc_html_e( 'When on, a user whose password has been flagged as breached is automatically redirected to their profile page on every admin screen until they change the password. The user is not locked out: they can still access their account, they are just nagged until the issue is resolved. Off by default; turn on if you want zero-tolerance enforcement.', 'login-armor' ); ?>
					</p>
					<div class="la-toggle-row">
						<label class="la-toggle">
							<input
								type="checkbox"
								name="breach_check_force_reset"
								aria-labelledby="la-lbl-breach-force-reset"
								value="1"
								<?php checked( (bool) $la_breach_force_reset ); ?>
							/>
							<span class="la-toggle__track"></span>
						</label>
						<span class="la-toggle-row__label" id="la-lbl-breach-force-reset"><?php esc_html_e( 'Redirect flagged users to their profile until they change their password', 'login-armor' ); ?></span>
					</div>
				</div>

				<div class="la-inner-sep"></div>

				<!-- Field 4: Stats -->
				<div class="la-field">
					<h4 class="la-field__label"><?php esc_html_e( 'Current status', 'login-armor' ); ?></h4>
					<div class="la-breach-stats">
						<div class="la-breach-stat">
							<div class="la-breach-stat__number"><?php echo esc_html( number_format_i18n( (int) ( $la_breach_flagged_counts['password'] ?? 0 ) ) ); ?></div>
							<div class="la-breach-stat__label"><?php esc_html_e( 'users with a flagged password', 'login-armor' ); ?></div>
						</div>
						<div class="la-breach-stat">
							<div class="la-breach-stat__number"><?php echo esc_html( number_format_i18n( (int) ( $la_breach_flagged_counts['email'] ?? 0 ) ) ); ?></div>
							<div class="la-breach-stat__label"><?php esc_html_e( 'users with a flagged email', 'login-armor' ); ?></div>
						</div>
					</div>
					<?php
					$la_pwd_users   = isset( $la_breach_flagged_users['password'] ) ? (array) $la_breach_flagged_users['password'] : array();
					$la_email_users = isset( $la_breach_flagged_users['email'] ) ? (array) $la_breach_flagged_users['email'] : array();
					?>

					<?php if ( ! empty( $la_pwd_users ) ) : ?>
						<div class="la-breach-list la-breach-list--pwd">
							<h5 class="la-breach-list__title"><?php esc_html_e( 'Accounts with a password flagged as breached', 'login-armor' ); ?></h5>
							<ul class="la-breach-list__items">
								<?php foreach ( $la_pwd_users as $la_u ) : ?>
									<li class="la-breach-list__item">
										<a class="la-breach-list__link" href="<?php echo esc_url( $la_u['edit_url'] ); ?>">
											<span class="la-breach-list__display"><?php echo esc_html( $la_u['display'] ); ?></span>
											<span class="la-breach-list__login la-mono"><?php echo esc_html( $la_u['login'] ); ?></span>
										</a>
										<?php if ( $la_u['flagged_at'] > 0 ) : ?>
											<span class="la-breach-list__when">
												<?php
												echo esc_html(
													sprintf(
														/* translators: %s: localized date when the account was flagged. */
														__( 'Flagged %s', 'login-armor' ),
														wp_date( get_option( 'date_format' ), $la_u['flagged_at'] )
													)
												);
												?>
											</span>
										<?php endif; ?>
									</li>
								<?php endforeach; ?>
							</ul>
						</div>
					<?php endif; ?>

					<?php if ( ! empty( $la_email_users ) ) : ?>
						<div class="la-breach-list la-breach-list--email">
							<h5 class="la-breach-list__title"><?php esc_html_e( 'Accounts with an email address in a public data breach', 'login-armor' ); ?></h5>
							<ul class="la-breach-list__items">
								<?php foreach ( $la_email_users as $la_u ) : ?>
									<li class="la-breach-list__item">
										<a class="la-breach-list__link" href="<?php echo esc_url( $la_u['edit_url'] ); ?>">
											<span class="la-breach-list__display"><?php echo esc_html( $la_u['display'] ); ?></span>
											<span class="la-breach-list__login la-mono"><?php echo esc_html( $la_u['login'] ); ?></span>
										</a>
										<?php if ( ! empty( $la_u['breaches'] ) ) : ?>
											<span class="la-breach-list__breaches">
												<?php echo esc_html( implode( ', ', array_slice( (array) $la_u['breaches'], 0, 3 ) ) ); ?>
												<?php if ( count( (array) $la_u['breaches'] ) > 3 ) : ?>
													<?php echo esc_html( sprintf( ' (+%d)', count( (array) $la_u['breaches'] ) - 3 ) ); ?>
												<?php endif; ?>
											</span>
										<?php endif; ?>
									</li>
								<?php endforeach; ?>
							</ul>
						</div>
					<?php endif; ?>

					<p class="la-field__desc" style="margin-top:10px;">
						<?php esc_html_e( 'An account stays flagged until its owner changes the password or email. The counters update as users log in or update their profile. No background scan runs on your site.', 'login-armor' ); ?>
					</p>
				</div>

			</div>
		</div>

	<?php endif; ?>
</section>
