<?php
/**
 * Reusable on-demand AI analysis panel (WP7 native AI Client).
 *
 * Expects locals (set by the including view):
 *   $la_ai_context      string 'incident' | 'posture'
 *   $la_ai_incident_id  int    (incident context only)
 *   $la_ai_incident     Incident (incident context only, optional): lets the
 *                       panel replay an analysis already stored on the row.
 *
 * INCIDENT context: renders nothing when the AI layer is unavailable and no
 * approval is pending: the drill-down stays clean.
 *
 * POSTURE (briefing) context: ALWAYS renders, and ALWAYS leads with the
 * deterministic security facts snapshot (incidents, activity, hardening,
 * environment/site-health). The AI briefing is layered on top when available;
 * otherwise an invitation to enable the AI assistant is shown. LoginArmor
 * delivers value with or without AI.
 *
 * @package LoginArmor
 */

// phpcs:disable WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

$la_ai_context     = isset( $la_ai_context ) ? (string) $la_ai_context : 'posture';
$la_ai_incident_id = isset( $la_ai_incident_id ) ? (int) $la_ai_incident_id : 0;
$la_ai_is_posture  = ( 'incident' !== $la_ai_context );

$la_ai_available = \LoginArmor\AI\Client::is_available();
$la_ai_needs_ok  = \LoginArmor\AI\Client::needs_approval();
$la_ai_has_cred  = \LoginArmor\AI\Client::native_has_credentials();
$la_ai_deep      = \LoginArmor\AI\Client::is_deep();

// The incident drill-down stays invisible when there is nothing to run or
// approve. The overview briefing always shows (deterministic facts fallback).
if ( ! $la_ai_is_posture && ! $la_ai_available && ! $la_ai_needs_ok ) {
	return;
}

// The briefing always renders a deterministic facts snapshot: make sure the
// advisor is loaded (no autoloader; it is otherwise required on demand in AJAX).
if ( $la_ai_is_posture && ! class_exists( '\LoginArmor\AI\PostureAdvisor' ) && defined( 'LOGIN_ARMOR_DIR' ) ) {
	require_once LOGIN_ARMOR_DIR . 'includes/AI/PostureAdvisor.php';
}

/*
 * An analysis already written for this incident is replayed here (2.7.1).
 * Until 2.7.0 the drill-down never looked one up: the text was generated,
 * cached, and then forgotten the moment the administrator navigated away, so
 * coming back to the same incident offered the button again and charged a
 * second generation of the same reading.
 *
 * This is a row read and nothing else. No AI call is ever made while a page
 * renders: generation stays behind the button, on the AJAX endpoint.
 */
$la_ai_stored     = null;
$la_ai_stored_age = '';
if ( ! $la_ai_is_posture && isset( $la_ai_incident ) && $la_ai_incident instanceof \LoginArmor\Detection\Incident ) {
	if ( ! class_exists( '\LoginArmor\AI\IncidentExplainer' ) && defined( 'LOGIN_ARMOR_DIR' ) ) {
		require_once LOGIN_ARMOR_DIR . 'includes/AI/IncidentExplainer.php';
	}
	$la_ai_stored = \LoginArmor\AI\IncidentExplainer::stored( $la_ai_incident );

	if ( null !== $la_ai_stored && '' !== $la_ai_stored['produced_at'] ) {
		// Stored in UTC, shown in the site's own format and timezone: an
		// administrator reading "14:12" must be reading their own clock.
		$la_ai_stored_ts = strtotime( $la_ai_stored['produced_at'] . ' UTC' );
		if ( false !== $la_ai_stored_ts ) {
			$la_ai_stored_age = wp_date(
				get_option( 'date_format' ) . ' ' . get_option( 'time_format' ),
				$la_ai_stored_ts
			);
		}
	}
}

switch ( $la_ai_context ) {
	case 'incident':
		$la_ai_title  = __( 'AI threat analysis', 'login-armor' );
		$la_ai_intro  = __( 'Get a plain-language explanation of this incident and what to do about it.', 'login-armor' );
		$la_ai_btn    = __( 'Explain with AI', 'login-armor' );
		$la_ai_action = 'explain-incident';
		break;
	default: // posture / briefing.
		$la_ai_title  = __( 'AI security briefing', 'login-armor' );
		$la_ai_intro  = __( 'A verdict on your site, the IP picture, and prioritised actions from the last 30 days of real activity.', 'login-armor' );
		$la_ai_btn    = __( 'Analyse my security', 'login-armor' );
		$la_ai_action = 'posture';
		break;
}
?>
<section class="la-card la-ai-panel" data-la-ai-context="<?php echo esc_attr( $la_ai_context ); ?>">
	<div class="la-ai-panel__head">
		<span class="la-ai-panel__badge"><?php \LoginArmor\Icons::render( 'shield', '', 14 ); ?> <?php esc_html_e( 'AI', 'login-armor' ); ?></span>
		<div class="la-ai-panel__head-txt">
			<h3 class="la-ai-panel__title"><?php echo esc_html( $la_ai_title ); ?></h3>
			<p class="la-ai-panel__intro"><?php echo esc_html( $la_ai_intro ); ?></p>
		</div>
	</div>

	<?php
	if ( $la_ai_is_posture ) {
		// Deterministic facts (incidents, activity, hardening, site health):
		// always shown so the environment/health is visible with or without AI.
		// Already-escaped HTML built by facts_html() (every value esc_html'd).
		echo \LoginArmor\AI\PostureAdvisor::facts_html(); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
	}
	?>

	<?php if ( $la_ai_needs_ok ) : ?>

		<div class="la-ai-panel__approve">
			<p><?php esc_html_e( 'WordPress needs your permission for LoginArmor to use the AI connector you configured.', 'login-armor' ); ?></p>
			<button type="button" class="la-primary-btn" data-la-ai-approve>
				<?php esc_html_e( 'Authorise LoginArmor', 'login-armor' ); ?>
			</button>
		</div>

	<?php elseif ( $la_ai_available ) : ?>

		<div class="la-ai-panel__actions">
			<button
				type="button"
				class="la-primary-btn"
				data-la-ai-action="<?php echo esc_attr( $la_ai_action ); ?>"
				<?php if ( $la_ai_incident_id > 0 ) : ?>data-la-ai-id="<?php echo esc_attr( (string) $la_ai_incident_id ); ?>"<?php endif; ?>
				<?php echo null !== $la_ai_stored ? 'hidden' : ''; ?>
			>
				<?php \LoginArmor\Icons::render( 'search', '', 14 ); ?>
				<?php echo esc_html( $la_ai_btn ); ?>
			</button>
			<button type="button" class="la-ghost-btn la-ai-panel__regen" data-la-ai-regen title="<?php esc_attr_e( 'Run the analysis again on the incident as it stands now', 'login-armor' ); ?>" <?php echo null !== $la_ai_stored ? '' : 'hidden'; ?>>
				<?php esc_html_e( 'Regenerate', 'login-armor' ); ?>
			</button>
		</div>

		<?php if ( null !== $la_ai_stored ) : ?>
			<p class="la-ai-panel__stamp" data-la-ai-stamp>
				<?php
				if ( '' !== $la_ai_stored_age ) {
					printf(
						/* translators: %s: date and time the analysis was produced. */
						esc_html__( 'Analysis of %s.', 'login-armor' ),
						esc_html( $la_ai_stored_age )
					);
				} else {
					esc_html_e( 'Analysis kept with this incident.', 'login-armor' );
				}
				?>
				<?php if ( $la_ai_stored['stale'] ) : ?>
					<span class="la-ai-panel__stale">
						<?php esc_html_e( 'The incident has changed since: this reading describes an earlier state. Regenerate for the current one.', 'login-armor' ); ?>
					</span>
				<?php endif; ?>
			</p>
		<?php endif; ?>

		<div class="la-ai-panel__state" data-la-ai-state hidden></div>
		<div class="la-ai-panel__result" data-la-ai-result <?php echo null !== $la_ai_stored ? '' : 'hidden'; ?>>
			<?php
			if ( null !== $la_ai_stored ) {
				// Built by Client::format_markdown(), which esc_html's every line
				// before injecting its own tags: already safe, escaping it again
				// would print the markup instead of rendering it.
				echo $la_ai_stored['html']; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
			}
			?>
		</div>

		<p class="la-ai-panel__regen-hint" data-la-ai-regen-hint <?php echo null !== $la_ai_stored ? '' : 'hidden'; ?>>
			<?php if ( $la_ai_is_posture ) : ?>
				<?php esc_html_e( 'This briefing is cached for about 3 hours: use Regenerate for a fresh run.', 'login-armor' ); ?>
			<?php else : ?>
				<?php esc_html_e( 'This analysis is kept with the incident and reappears every time you open it. It is regenerated only when you ask.', 'login-armor' ); ?>
			<?php endif; ?>
		</p>

		<p class="la-ai-panel__privacy">
			<?php if ( $la_ai_deep ) : ?>
				<?php esc_html_e( 'Deep analysis is ON: real IP addresses and event details are sent to the AI connector configured in your WordPress.', 'login-armor' ); ?>
			<?php else : ?>
				<?php esc_html_e( 'Sent to the AI connector configured in your WordPress: no IP address or username in clear, only anonymised signals.', 'login-armor' ); ?>
			<?php endif; ?>
		</p>

	<?php else : ?>

		<?php $la_ai_settings_url = add_query_arg( array( 'page' => 'login-armor', 'tab' => 'settings' ), admin_url( 'admin.php' ) ) . '#ai-assistant'; ?>
		<div class="la-ai-panel__enable">
			<?php if ( $la_ai_has_cred ) : ?>
				<p><?php esc_html_e( 'Enable the AI assistant in settings to get a personalised briefing and prioritised advice on top of these facts.', 'login-armor' ); ?></p>
				<a class="la-primary-btn" href="<?php echo esc_url( $la_ai_settings_url ); ?>"><?php esc_html_e( 'Enable AI in settings', 'login-armor' ); ?></a>
			<?php else : ?>
				<p><?php esc_html_e( 'Personalised AI advice needs WordPress 7 with a configured AI connector. The facts above are always available, with or without AI.', 'login-armor' ); ?></p>
				<a class="la-ghost-btn" href="<?php echo esc_url( \LoginArmor\AI\Client::connectors_url() ); ?>"><?php esc_html_e( 'Manage AI connectors', 'login-armor' ); ?></a>
			<?php endif; ?>
		</div>

	<?php endif; ?>
</section>
