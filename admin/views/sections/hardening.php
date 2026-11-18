<?php
/**
 * Hardening section: Settings tab (Lot 18 V8 redesign).
 *
 * Renders a navy hero strip with the current X/16 enabled count +
 * progress bar, then groups the 16 toggles into four categories
 * (Surface reduction / Credential hardening / Request filtering /
 * Account monitoring). Each row surfaces a RECOMMENDED pill for the 7
 * default toggles.
 *
 * @package LoginArmor
 *
 * @var array<string, bool>  $la_hardening Current hardening settings (key => enabled).
 * @var array<int, array{key: string, label: string, description: string}> $la_toggles Toggle definitions.
 * @var bool $la_hard_https_on        Whether force_https is STORED on.
 * @var bool $la_hard_https_effective Whether force_https is enforcing anything right now.
 */

// phpcs:disable WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/*
 * Group taxonomy. Keys reference the 16 toggle keys in DEFAULTS.
 * Order inside each group is the display order in the UI. Every toggle in
 * get_toggles() MUST appear in exactly one group, or the rendered rows will
 * disagree with the "X of Y" header count (which is count(get_toggles())).
 */
$la_hard_groups = [
	'surface'    => [
		'label' => __( 'Surface reduction', 'login-armor' ),
		'hint'  => __( 'Remove entry points attackers probe first.', 'login-armor' ),
		'keys'  => [ 'disable_xmlrpc', 'disable_pingbacks', 'disable_file_editor', 'hide_wp_version', 'disable_app_passwords', 'obfuscate_author_slugs' ],
	],
	'credential' => [
		'label' => __( 'Credential hardening', 'login-armor' ),
		'hint'  => __( 'Stop username enumeration.', 'login-armor' ),
		'keys'  => [ 'mask_login_errors', 'prevent_author_enum', 'block_reserved_usernames' ],
	],
	'request'    => [
		'label' => __( 'Request filtering', 'login-armor' ),
		'hint'  => __( 'Block malformed, malicious, or automated requests.', 'login-armor' ),
		'keys'  => [ 'block_php_uploads', 'disable_directory_listing', 'restrict_rest_api', 'protect_system_files', 'login_honeypot', 'force_https' ],
	],
	'monitoring' => [
		'label' => __( 'Account monitoring', 'login-armor' ),
		'hint'  => __( 'Get alerted when an account gains administrator access.', 'login-armor' ),
		'keys'  => [ 'alert_admin_creation' ],
	],
];

// Recommended defaults: the 7 toggles set by "Apply recommended defaults".
// Must match the recommendedKeys array in admin.js (Lot 14 hardening UX).
$la_hard_recommended = [
	'disable_xmlrpc',
	'disable_file_editor',
	'hide_wp_version',
	'mask_login_errors',
	'block_php_uploads',
	'prevent_author_enum',
	'disable_directory_listing',
];

// Build a key-indexed lookup of toggle definitions from the numeric $la_toggles array.
$la_toggle_by_key = [];
foreach ( $la_toggles as $la_t ) {
	$la_toggle_by_key[ $la_t['key'] ] = $la_t;
}

// Reserved-usernames blacklist data. Rendered inline under the
// block_reserved_usernames toggle (Credential hardening group) so the list
// sits right beside the option that turns it on, not orphaned at the bottom.
$la_blacklist_visible  = ! empty( $la_hardening['block_reserved_usernames'] );
$la_blacklist          = \LoginArmor\Hardening\UsernameBlacklist::get_blacklist();
$la_blacklist_matches  = \LoginArmor\Hardening\UsernameBlacklist::existing_matching_users();
$la_blacklist_textarea = implode( "\n", $la_blacklist );

// Public REST namespaces (2.5.1). Rendered under the Request filtering group,
// beside the restrict_rest_api toggle it qualifies. Restricting the REST API is
// all-or-nothing otherwise, and a third-party plugin whose namespace must stay
// public used to require a PHP filter.
$la_rest_ns_visible = ! empty( $la_hardening['restrict_rest_api'] );
$la_rest_ns_text    = \LoginArmor\Hardening::get_rest_namespaces_textarea();
$la_rest_ns_count   = count( \LoginArmor\Hardening::get_rest_namespaces() );
$la_rest_ns_risky   = \LoginArmor\Hardening::risky_rest_namespaces();
$la_rest_ns_default = [];
foreach ( \LoginArmor\Hardening::DEFAULT_REST_NAMESPACES as $la_ns ) {
	$la_rest_ns_default[] = rtrim( $la_ns, '/' );
}
$la_rest_ns_default = implode( ', ', $la_rest_ns_default );

?>
<section class="la-card la-card--section" id="la-section-hardening" data-la-section="hardening">
	<div class="la-card-body la-harden-body">

		<div data-la-hardening-form>
			<?php foreach ( $la_hard_groups as $la_gkey => $la_group ) :
				// Count active toggles in this group for the "N / M" pill.
				$la_g_total  = count( $la_group['keys'] );
				$la_g_active = 0;
				foreach ( $la_group['keys'] as $la_k ) {
					// 2.9.0: a toggle headless mode keeps off is not a choice, so it leaves the count.
					if ( class_exists( '\LoginArmor\Headless' ) && \LoginArmor\Headless::is_enabled() && in_array( $la_k, \LoginArmor\Headless::GUARDED_TOGGLES, true ) ) {
						--$la_g_total;
						continue;
					}
					if ( ! empty( $la_hardening[ $la_k ] ) ) { ++$la_g_active; }
				}
			?>
				<div class="la-harden-group" data-la-harden-group="<?php echo esc_attr( $la_gkey ); ?>">
					<div class="la-harden-group__head">
						<h4 class="la-harden-group__label">
							<?php echo esc_html( $la_group['label'] ); ?>
							<span class="la-harden-group__count" data-la-harden-group-count>
								<?php echo esc_html( (string) $la_g_active ); ?> / <?php echo esc_html( (string) $la_g_total ); ?>
							</span>
						</h4>
						<p class="la-harden-group__hint"><?php echo esc_html( $la_group['hint'] ); ?></p>
					</div>

					<div class="la-harden-group__list">
						<?php foreach ( $la_group['keys'] as $la_key ) :
							if ( ! isset( $la_toggle_by_key[ $la_key ] ) ) { continue; }
							$la_toggle = $la_toggle_by_key[ $la_key ];
							$la_is_on  = ! empty( $la_hardening[ $la_key ] );
							$la_is_rec = in_array( $la_key, $la_hard_recommended, true );
							$la_row_state = $la_is_on ? 'la-harden-row--on' : 'la-harden-row--off';
							// 2.9.0: kept off by headless mode, shown greyed with the reason.
							$la_is_headless_locked = class_exists( '\LoginArmor\Headless' )
								&& \LoginArmor\Headless::is_enabled()
								&& in_array( $la_key, \LoginArmor\Headless::GUARDED_TOGGLES, true );
						?>
							<div class="la-harden-row <?php echo esc_attr( $la_row_state ); ?>" data-la-toggle data-la-harden-key="<?php echo esc_attr( $la_key ); ?>"<?php echo $la_is_headless_locked ? ' data-la-headless-locked' : ''; ?>>
								<div class="la-harden-row__text">
									<?php // 2.8.0: the switch of the row is named by this title and described by the line under it: its <label> holds no text. ?>
									<b id="la-lbl-harden-<?php echo esc_attr( $la_key ); ?>">
										<?php echo esc_html( $la_toggle['label'] ); ?>
										<?php if ( $la_is_rec ) : ?>
											<span class="la-pill la-pill--recommended"><?php esc_html_e( 'RECOMMENDED', 'login-armor' ); ?></span>
										<?php endif; ?>
									</b>
									<small id="la-desc-harden-<?php echo esc_attr( $la_key ); ?>"><?php echo wp_kses( $la_toggle['description'], [ 'code' => [], 'strong' => [], 'em' => [] ] ); ?></small>
									<?php
									/*
									 * 2.7.0: the one toggle safe mode stands down, said on its own
									 * row. Same note, same class and same lead sentence as the
									 * firewall and bot-challenge cards, so the three read as one
									 * interface rather than three inventions. Shown exactly when
									 * the stored state and the applied one disagree, which on a
									 * boolean toggle can only mean "stored on, enforcing nothing".
									 * The switch beside it keeps the STORED value on purpose:
									 * pre-unchecking it would turn the next save of this form into
									 * a silent rollback of a toggle the administrator armed.
									 */
									?>
									<?php if ( 'force_https' === $la_key && $la_hard_https_on && $la_hard_https_on !== $la_hard_https_effective ) : ?>
										<div class="la-danger-note" data-la-https-safe-mode>
											<?php \LoginArmor\Icons::render( 'alert-triangle', '', 14 ); ?>
											<span>
												<strong><?php esc_html_e( 'Safe mode is active.', 'login-armor' ); ?></strong>
												<?php esc_html_e( 'Force HTTPS enforces nothing right now, whatever the switch beside it shows. Your setting is untouched and comes back the moment you remove LOGIN_ARMOR_SAFE_MODE from wp-config.php.', 'login-armor' ); ?>
											</span>
										</div>
									<?php endif; ?>
									<?php if ( $la_is_headless_locked ) : ?>
										<div class="la-danger-note" id="la-lock-harden-<?php echo esc_attr( $la_key ); ?>">
											<?php \LoginArmor\Icons::render( 'alert-triangle', '', 14 ); ?>
											<span><?php esc_html_e( 'Turned off by headless mode. Disable headless mode first to change it.', 'login-armor' ); ?></span>
										</div>
									<?php endif; ?>
								</div>
								<label class="la-toggle">
									<input type="checkbox" name="<?php echo esc_attr( $la_key ); ?>" value="1" <?php checked( $la_is_on ); ?><?php disabled( $la_is_headless_locked ); ?> aria-labelledby="la-lbl-harden-<?php echo esc_attr( $la_key ); ?>" aria-describedby="la-desc-harden-<?php echo esc_attr( $la_key ); ?><?php echo $la_is_headless_locked ? ' la-lock-harden-' . esc_attr( $la_key ) : ''; ?>" />
									<span class="la-toggle__track"></span>
								</label>
							</div>
						<?php endforeach; ?>
					</div>
					<?php if ( in_array( 'restrict_rest_api', $la_group['keys'], true ) ) : ?>
						<div class="la-sub-panel" data-la-restns-panel<?php echo $la_rest_ns_visible ? '' : ' hidden'; ?>>
							<div class="la-sub-panel__head">
								<h3 class="la-sub-panel__title" id="la-lbl-rest-namespaces"><?php esc_html_e( 'REST API exceptions', 'login-armor' ); ?></h3>
								<p class="la-sub-panel__desc">
									<?php esc_html_e( 'Some plugins need part of the REST API to stay public. List one namespace per line, exactly as it appears after /wp-json/, for example seopress/v1. Changes auto-save.', 'login-armor' ); ?>
								</p>
							</div>
							<label class="la-field">
								<textarea
									rows="4"
									cols="40"
									class="la-input la-input--mono"
									name="rest_public_namespaces"
									aria-labelledby="la-lbl-rest-namespaces"
									placeholder="seopress/v1"
									data-la-restns-input
								><?php echo esc_textarea( $la_rest_ns_text ); ?></textarea>
							</label>
							<p class="la-muted la-sub-panel__counter">
								<span data-la-restns-count><?php echo (int) $la_rest_ns_count; ?></span>
								<?php esc_html_e( 'namespace(s) kept public, on top of the built-in ones:', 'login-armor' ); ?>
								<code><?php echo esc_html( $la_rest_ns_default ); ?></code>
							</p>
							<div class="la-warning-banner" data-la-restns-warning<?php echo empty( $la_rest_ns_risky ) ? ' hidden' : ''; ?>>
								<span class="la-warning-banner__icon" aria-hidden="true">
									<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
								</span>
								<span>
									<strong data-la-restns-warning-list><?php echo esc_html( implode( ', ', $la_rest_ns_risky ) ); ?></strong>
									<?php esc_html_e( 'reopens WordPress core routes, including your content and your list of accounts, to anyone. That is exactly what this option prevents. Remove it unless you know one of your plugins needs it.', 'login-armor' ); ?>
								</span>
							</div>
						</div>
					<?php endif; ?>
					<?php if ( in_array( 'block_reserved_usernames', $la_group['keys'], true ) ) : ?>
						<div class="la-sub-panel" data-la-blacklist-panel<?php echo $la_blacklist_visible ? '' : ' hidden'; ?>>
							<div class="la-sub-panel__head">
								<h3 class="la-sub-panel__title" id="la-lbl-username-blacklist"><?php esc_html_e( 'Reserved usernames', 'login-armor' ); ?></h3>
								<p class="la-sub-panel__desc"><?php esc_html_e( 'One username per line. Case-insensitive. Changes auto-save.', 'login-armor' ); ?></p>
							</div>
							<label class="la-field">
								<textarea
									rows="6"
									cols="40"
									class="la-input la-input--mono"
									name="username_blacklist"
									aria-labelledby="la-lbl-username-blacklist"
									data-la-blacklist-input
								><?php echo esc_textarea( $la_blacklist_textarea ); ?></textarea>
							</label>
							<p class="la-muted la-sub-panel__counter">
								<span data-la-blacklist-count><?php echo (int) count( $la_blacklist ); ?></span>
								<?php esc_html_e( 'usernames blocked', 'login-armor' ); ?>
							</p>
							<div
								class="la-warning-banner"
								data-la-blacklist-warning
								<?php echo empty( $la_blacklist_matches ) ? 'hidden' : ''; ?>
							>
								<span class="la-warning-banner__icon" aria-hidden="true">
									<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
								</span>
								<span>
									<strong data-la-blacklist-warning-count><?php echo (int) count( $la_blacklist_matches ); ?></strong>
									<?php esc_html_e( 'existing user(s) match this blacklist:', 'login-armor' ); ?>
									<span data-la-blacklist-warning-list><?php echo esc_html( implode( ', ', $la_blacklist_matches ) ); ?></span>.
									<br>
									<?php esc_html_e( 'These users will continue to log in normally: the blacklist applies only to new login attempts and registrations.', 'login-armor' ); ?>
								</span>
							</div>
						</div>
					<?php endif; ?>
				</div>
			<?php endforeach; ?>

			<!-- Footer: Apply recommended + hint -->
			<div class="la-hardening-defaults">
				<button type="button" class="la-btn la-btn--secondary" data-la-hardening-defaults>
					<?php esc_html_e( 'Apply recommended defaults', 'login-armor' ); ?>
				</button>
				<span class="la-hardening-defaults__hint"><?php esc_html_e( 'Enables the 7 most common security toggles at once.', 'login-armor' ); ?></span>
			</div>
		</div>
	</div>
</section>
