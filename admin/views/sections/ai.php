<?php
/**
 * Settings section: AI Assistant (WP7 native AI Client).
 *
 * Connector status, opt-out, the deep-analysis cursor (with a clear privacy
 * warning), the usage counter, and a link to the native AI Connectors screen.
 * Reuses the shared settings primitives (la-card--section, la-card-header,
 * la-field, la-status-pill) so it matches every other module visually.
 *
 * @package LoginArmor
 */

// phpcs:disable WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

$la_ai_enabled_opt = \LoginArmor\AI\Client::is_enabled();
$la_ai_deep_opt    = \LoginArmor\AI\Client::is_deep();
$la_ai_native      = \LoginArmor\AI\Client::native_available();
$la_ai_has_cred    = \LoginArmor\AI\Client::native_has_credentials();
$la_ai_needs_ok    = \LoginArmor\AI\Client::needs_approval();
$la_ai_usage       = \LoginArmor\AI\Client::get_usage();
$la_ai_connectors  = \LoginArmor\AI\Client::connectors_url();
$la_ai_ready       = ( $la_ai_native && $la_ai_has_cred );
?>
<section class="la-card la-card--section" id="la-section-ai-assistant" data-la-section="ai-assistant">
	<header class="la-card-header">
		<div class="la-card-header__left">
			<div class="la-card-icon">
				<?php \LoginArmor\Icons::render( 'shield', '', 20 ); ?>
			</div>
			<div>
				<h2 class="la-card-title">
					<?php esc_html_e( 'AI Assistant', 'login-armor' ); ?>
					<?php if ( $la_ai_ready && $la_ai_enabled_opt ) : ?>
						<span class="la-status-pill la-status-pill--on"><?php esc_html_e( 'ACTIVE', 'login-armor' ); ?></span>
					<?php elseif ( $la_ai_ready ) : ?>
						<span class="la-status-pill la-status-pill--off"><?php esc_html_e( 'OFF', 'login-armor' ); ?></span>
					<?php else : ?>
						<span class="la-status-pill la-status-pill--off"><?php esc_html_e( 'NEEDS WP 7', 'login-armor' ); ?></span>
					<?php endif; ?>
				</h2>
				<p class="la-card-subtitle">
					<?php esc_html_e( 'On-demand AI analysis through your own WordPress 7 connector: explains incidents and advises on hardening. The plugin works fully without it.', 'login-armor' ); ?>
				</p>
			</div>
		</div>
	</header>

	<div class="la-card-sep"></div>

	<div class="la-card-body">
		<?php if ( ! $la_ai_native ) : ?>

			<div class="la-field">
				<p class="la-field__desc">
					<?php esc_html_e( 'AI features require WordPress 7 (or the AI Building Blocks feature plugin) with a configured AI connector. They stay hidden until then.', 'login-armor' ); ?>
				</p>
			</div>

		<?php elseif ( ! $la_ai_has_cred ) : ?>

			<div class="la-field">
				<h4 class="la-field__label"><?php esc_html_e( 'No usable AI connector', 'login-armor' ); ?></h4>
				<p class="la-field__desc">
					<?php esc_html_e( 'WordPress 7 is detected, but no connector can generate text yet. Configure one to unlock the AI analysis.', 'login-armor' ); ?>
				</p>
				<a class="la-btn la-btn--ghost" href="<?php echo esc_url( $la_ai_connectors ); ?>"><?php esc_html_e( 'Manage AI connectors', 'login-armor' ); ?></a>
			</div>

		<?php else : ?>

			<?php if ( $la_ai_needs_ok ) : ?>
				<div class="la-field">
					<div class="la-ai-warn">
						<strong><?php esc_html_e( 'Authorisation required', 'login-armor' ); ?></strong>
						<span><?php esc_html_e( 'A connector is configured but LoginArmor is not yet allowed to use it.', 'login-armor' ); ?></span>
						<button type="button" class="la-btn la-btn--primary la-btn--small" data-la-ai-approve><?php esc_html_e( 'Authorise LoginArmor', 'login-armor' ); ?></button>
					</div>
				</div>
				<div class="la-inner-sep"></div>
			<?php endif; ?>

			<!-- AI toggles: persisted through the standard Settings "Save" bar, like
			     every other module. Deep mode sends real IPs out, so it must be an
			     explicit confirmed save, not an instant on-change toggle. -->
			<div class="la-ai-settings-form" data-la-ai-settings-form>

				<!-- Enable AI -->
				<div class="la-field">
					<label class="la-ai-toggle">
						<input type="checkbox" name="ai_enabled" value="1" <?php checked( $la_ai_enabled_opt ); ?> />
						<span class="la-ai-toggle__track"><span class="la-ai-toggle__thumb"></span></span>
						<span class="la-ai-toggle__text">
							<b><?php esc_html_e( 'Enable AI analysis', 'login-armor' ); ?></b>
							<small><?php esc_html_e( 'Show the AI panels and allow on-demand analysis.', 'login-armor' ); ?></small>
						</span>
					</label>
				</div>

				<div class="la-inner-sep"></div>

				<!-- Deep analysis cursor -->
				<div class="la-field">
					<label class="la-ai-toggle">
						<input type="checkbox" name="ai_deep" value="1" data-la-ai-deep-toggle <?php checked( $la_ai_deep_opt ); ?> />
						<span class="la-ai-toggle__track"><span class="la-ai-toggle__thumb"></span></span>
						<span class="la-ai-toggle__text">
							<b><?php esc_html_e( 'Deep analysis', 'login-armor' ); ?></b>
							<small><?php esc_html_e( 'Send real IP addresses and events to your connector for named, IP-level recommendations. Off = anonymised signals only.', 'login-armor' ); ?></small>
						</span>
					</label>
					<div class="la-ai-warn la-ai-warn--amber" data-la-ai-deep-warn <?php echo $la_ai_deep_opt ? '' : 'hidden'; ?>>
						<span><?php esc_html_e( 'Deep mode is on: concrete IP addresses and event details leave your site for your own AI connector. Use it only if your connector and provider agreement are acceptable for that data.', 'login-armor' ); ?></span>
					</div>
				</div>

			</div>

			<div class="la-inner-sep"></div>

			<!-- Usage -->
			<div class="la-field">
				<p class="la-field__desc">
					<?php
					echo esc_html(
						sprintf(
							/* translators: %d: number of AI calls in the last 30 days. */
							_n( '%d AI call in the last 30 days.', '%d AI calls in the last 30 days.', (int) $la_ai_usage['rolling_30d'], 'login-armor' ),
							(int) $la_ai_usage['rolling_30d']
						)
					);
					?>
					<a href="<?php echo esc_url( $la_ai_connectors ); ?>"><?php esc_html_e( 'Manage connectors', 'login-armor' ); ?></a>
				</p>
			</div>

		<?php endif; ?>

		<div class="la-inner-sep"></div>

		<p class="la-ai-settings__privacy">
			<?php esc_html_e( 'Privacy: analysis is opt-in per click. Nothing is sent to WPFormation: the request goes directly to your own AI connector. In default (minimised) mode, no IP address or username is ever sent in clear.', 'login-armor' ); ?>
		</p>
	</div>
</section>
