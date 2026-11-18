<?php
/**
 * Hide Login section: Settings tab.
 *
 * Hide Login is opt-in. When disabled, this section shows a CTA to enable
 * the feature (with a URL preview). When enabled, it shows the full form
 * (slug, copy, regenerate, redirect target, reset) plus a disable toggle
 * in the header and the collapsible "Forgot your URL?" recovery panel.
 *
 * @package LoginArmor
 *
 * @var bool   $la_enabled       Whether Hide Login is currently on.
 * @var string $la_slug          Current slug.
 * @var string $la_login_url     Full login URL.
 * @var string $la_redirect_type 'notfound' or 'url'.
 * @var string $la_redirect_url  Custom redirect URL when type = 'url'.
 */

// phpcs:disable WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}
?>
<section class="la-card la-card--section" id="la-section-hide-login" data-la-section="hide-login">
	<header class="la-card-header">
		<div class="la-card-header__left">
			<div class="la-card-icon">
				<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
					<path d="M12 2L4 5.5v5c0 5.25 3.4 10.2 8 11.5 4.6-1.3 8-6.25 8-11.5v-5L12 2z"/>
					<path d="M9 12l2 2 4-4"/>
				</svg>
			</div>
			<div>
				<h2 class="la-card-title">
					<?php esc_html_e( 'Hide Login', 'login-armor' ); ?>
					<?php if ( $la_enabled ) : ?>
						<span class="la-status-pill la-status-pill--on"><?php esc_html_e( 'PROTECTED', 'login-armor' ); ?></span>
					<?php else : ?>
						<span class="la-status-pill la-status-pill--off"><?php esc_html_e( 'DISABLED', 'login-armor' ); ?></span>
					<?php endif; ?>
				</h2>
				<p class="la-card-subtitle">
					<?php if ( $la_enabled ) : ?>
						<?php esc_html_e( 'Your login URL is hidden. Direct access attempts return a 404.', 'login-armor' ); ?>
					<?php else : ?>
						<?php esc_html_e( 'Move your login page to a secret URL. Your /wp-login.php is currently reachable.', 'login-armor' ); ?>
					<?php endif; ?>
				</p>
			</div>
		</div>
		<?php if ( $la_enabled ) : ?>
			<button type="button" class="la-btn la-btn--danger la-btn--small" data-la-action="hide-disable">
				<?php esc_html_e( 'Disable', 'login-armor' ); ?>
			</button>
		<?php endif; ?>
	</header>

	<div class="la-card-sep"></div>

	<?php if ( ! $la_enabled ) : ?>

		<div class="la-card-body">
			<div class="la-hide-disabled">
				<div class="la-hide-disabled__warning">
					<div class="la-hide-disabled__warning-icon">
						<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
							<path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/>
							<line x1="12" y1="9" x2="12" y2="13"/>
							<line x1="12" y1="17" x2="12.01" y2="17"/>
						</svg>
					</div>
					<div class="la-hide-disabled__warning-text">
						<strong><?php esc_html_e( 'Your login page is publicly accessible', 'login-armor' ); ?></strong>
						<span><?php esc_html_e( 'Bots and attackers can find /wp-login.php. Enabling Hide Login is strongly recommended.', 'login-armor' ); ?></span>
					</div>
				</div>
				<div class="la-hide-disabled__body">
					<p class="la-hide-disabled__desc">
						<?php esc_html_e( 'When you enable Hide Login, your login page will move to a secret URL. Direct access to /wp-login.php and /wp-admin will return a 404.', 'login-armor' ); ?>
					</p>
					<div class="la-hide-disabled__preview">
						<span class="la-hide-disabled__preview-label"><?php esc_html_e( 'Your new login URL will be:', 'login-armor' ); ?></span>
						<code class="la-hide-disabled__preview-url"><?php echo esc_html( $la_login_url ); ?></code>
					</div>
					<p class="la-hide-disabled__note">
						<?php esc_html_e( 'Bookmark this URL the moment you enable the feature. You can change the slug anytime from the settings.', 'login-armor' ); ?>
					</p>
				</div>
				<div class="la-hide-disabled__actions">
					<button type="button" class="la-btn la-btn--primary la-btn--amber" data-la-action="hide-enable">
						<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="width:16px;height:16px;margin-right:6px;">
							<path d="M12 2L4 5.5v5c0 5.25 3.4 10.2 8 11.5 4.6-1.3 8-6.25 8-11.5v-5L12 2z"/>
						</svg>
						<?php esc_html_e( 'Enable Hide Login', 'login-armor' ); ?>
					</button>
				</div>
			</div>
		</div>

	<?php else : ?>

		<div class="la-card-body">
			<form data-la-hide-form onsubmit="return false;">
				<div class="la-field">
					<label class="la-field__label" for="la-hide-slug"><?php esc_html_e( 'Secret Login URL', 'login-armor' ); ?></label>
					<p class="la-field__desc"><?php esc_html_e( 'Edit the slug below to choose your own, or use Regenerate for a random one. Allowed: a-z, 0-9, hyphens.', 'login-armor' ); ?></p>
					<div class="la-lab">
						<div class="la-lab__prefix">
							<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
								<rect x="3" y="11" width="18" height="11" rx="2"/>
								<path d="M7 11V7a5 5 0 0110 0v4"/>
							</svg>
						</div>
						<input
							type="text"
							id="la-hide-slug"
							name="slug"
							class="la-lab__input"
							value="<?php echo esc_attr( $la_slug ); ?>"
							autocomplete="off"
							spellcheck="false"
						/>
						<div class="la-lab__actions">
							<button type="button" class="la-lab__btn" data-la-action="hide-copy" data-la-copy-target="#la-hide-slug">
								<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
									<rect x="9" y="9" width="13" height="13" rx="2"/>
									<path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1"/>
								</svg>
								<?php esc_html_e( 'Copy', 'login-armor' ); ?>
							</button>
							<button type="button" class="la-lab__btn" data-la-action="hide-regenerate">
								<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
									<path d="M1 4v6h6"/>
									<path d="M3.51 15a9 9 0 102.13-9.36L1 10"/>
								</svg>
								<?php esc_html_e( 'Regenerate', 'login-armor' ); ?>
							</button>
						</div>
					</div>
						<div class="la-slug-result">
						<span class="la-slug-result__label"><?php esc_html_e( 'Your login is at:', 'login-armor' ); ?></span>
						<a class="la-slug-result__url" href="<?php echo esc_url( $la_login_url ); ?>" target="_blank" data-la-hide-url><?php
						// 2.8.0: a line may break after a slash, never inside the
						// host: on a phone the URL, one unbroken run of thirty
						// characters or more, spilled out of its box.
						echo wp_kses( (string) preg_replace( '#/(?!/)#', '/<wbr>', esc_html( $la_login_url ) ), array( 'wbr' => array() ) );
						?></a>
						<span class="la-slug-result__note" data-la-redirect-note
							data-note-404="<?php echo esc_attr__( 'All other paths (/wp-login.php, /wp-admin) return a 404 to scanners and bots.', 'login-armor' ); ?>"
							data-note-url="<?php echo esc_attr__( 'All other paths (/wp-login.php, /wp-admin) redirect to your custom URL.', 'login-armor' ); ?>"
						><?php
							echo 'url' === $la_redirect_type
								? esc_html__( 'All other paths (/wp-login.php, /wp-admin) redirect to your custom URL.', 'login-armor' )
								: esc_html__( 'All other paths (/wp-login.php, /wp-admin) return a 404 to scanners and bots.', 'login-armor' );
						?></span>
					</div>
				</div>

				<div class="la-field" role="radiogroup" aria-label="<?php esc_attr_e( 'Blocked Access Redirect', 'login-armor' ); ?>">
					<label class="la-field__label"><?php esc_html_e( 'Blocked Access Redirect', 'login-armor' ); ?></label>
					<p class="la-field__desc"><?php esc_html_e( 'What happens when someone tries to access /wp-login.php or /wp-admin directly.', 'login-armor' ); ?></p>
					<div class="la-radio-grid">
						<label class="la-radio-opt <?php echo 'notfound' === $la_redirect_type ? 'la-radio-opt--active' : ''; ?>">
							<div class="la-radio-opt__top">
								<input type="radio" name="redirect_type" value="notfound" <?php checked( $la_redirect_type, 'notfound' ); ?>>
								<span class="la-radio-opt__title"><?php esc_html_e( '404 Page', 'login-armor' ); ?></span>
								<span class="la-radio-opt__tag"><?php esc_html_e( 'Recommended', 'login-armor' ); ?></span>
							</div>
							<p class="la-radio-opt__desc">
								<?php esc_html_e( 'Login page appears to not exist', 'login-armor' ); ?>
							</p>
						</label>
						<label class="la-radio-opt <?php echo 'url' === $la_redirect_type ? 'la-radio-opt--active' : ''; ?>">
							<div class="la-radio-opt__top">
								<input type="radio" name="redirect_type" value="url" <?php checked( $la_redirect_type, 'url' ); ?>>
								<span class="la-radio-opt__title"><?php esc_html_e( 'Custom URL', 'login-armor' ); ?></span>
							</div>
							<p class="la-radio-opt__desc">
								<?php esc_html_e( 'Redirect to any page', 'login-armor' ); ?>
							</p>
							<input type="url" name="redirect_url" class="la-input" value="<?php echo esc_attr( $la_redirect_url ); ?>" placeholder="https://example.com/not-found">
						</label>
					</div>
				</div>
			</form>
		</div>

	<?php endif; ?>
</section>

<?php if ( $la_enabled ) : ?>
<details class="la-section-subhint la-recovery">
	<summary>
		<span><?php esc_html_e( 'Forgot your login URL?', 'login-armor' ); ?></span>
		<span class="la-section-subhint__chevron" aria-hidden="true"></span>
	</summary>
	<div class="la-section-subhint__body la-recovery__body">
		<p>
			<?php esc_html_e( "If you're locked out, use one of these methods:", 'login-armor' ); ?>
		</p>
		<ol class="la-recovery__list">
			<?php
			$la_methods = \LoginArmor\HideLogin::get_recovery_instructions();
			foreach ( $la_methods as $la_method ) :
				$la_is_ftp = ( false !== stripos( $la_method['title'], 'FTP' ) );
				?>
				<li>
					<strong><?php echo esc_html( $la_method['title'] ); ?></strong>
					<span class="la-recovery__desc"><?php echo esc_html( $la_method['body'] ); ?></span>
					<?php if ( ! empty( $la_method['code'] ) ) : ?>
						<code class="la-cli"><?php echo esc_html( $la_method['code'] ); ?></code>
					<?php endif; ?>
					<?php if ( $la_is_ftp ) : ?>
						<div class="la-danger-note">
							<?php \LoginArmor\Icons::render( 'alert-triangle', '', 14 ); ?>
							<span><strong><?php esc_html_e( 'Heads up:', 'login-armor' ); ?></strong> <?php esc_html_e( 'This disables Login Armor entirely, protection included. Try every other method first, safe mode below included.', 'login-armor' ); ?></span>
						</div>
					<?php endif; ?>
				</li>
			<?php endforeach; ?>
		</ol>
		<div class="la-recovery__foot">
			<button type="button" class="la-primary-btn" data-la-action="hide-email">
				<?php \LoginArmor\Icons::render( 'mail', '', 14 ); ?>
				<?php esc_html_e( 'Email me this URL', 'login-armor' ); ?>
			</button>
			<span class="la-recovery__hint">
				<?php esc_html_e( 'Sent to admin email.', 'login-armor' ); ?>
			</span>
		</div>
	</div>
</details>
<?php endif; ?>
