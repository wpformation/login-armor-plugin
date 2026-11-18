<?php
/**
 * Sidebar sponsored cards: OGEEAT (free plugin) + WPFormation Crash-Test.
 *
 * Rendered inside the `<aside>` of the Incidents, Events, Activity and
 * Settings tabs (never on Overview). Two house ads for WPFormation
 * properties, localized via the `login-armor` textdomain.
 *
 * @package LoginArmor
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

$login_armor_ogeeat_banner = LOGIN_ARMOR_URL . 'admin/assets/images/sponsored/ogeeat-banner.png';
?>
<div class="wpf-ads" role="complementary" aria-label="<?php esc_attr_e( 'Sponsored: WPFormation', 'login-armor' ); ?>">
	<div class="wpf-ads__label">
		<span><?php esc_html_e( 'Sponsored', 'login-armor' ); ?></span>
		<span class="wpf-ads__ad-tag"><?php esc_html_e( 'Ad', 'login-armor' ); ?></span>
	</div>

	<a href="https://wpformation.com/ogeeat-wordpress/" target="_blank" rel="noopener" class="wpf-card">
		<div class="wpf-card__hero">
			<img
				src="<?php echo esc_url( $login_armor_ogeeat_banner ); ?>"
				alt="<?php esc_attr_e( 'OGEEAT: Generative Engine Optimization', 'login-armor' ); ?>"
				width="772"
				height="250"
				loading="lazy"
			/>
		</div>
		<div class="wpf-card__body">
			<span class="wpf-card__eyebrow"><?php esc_html_e( 'Free plugin', 'login-armor' ); ?></span>
			<h4 class="wpf-card__title"><?php esc_html_e( 'Get cited by ChatGPT, Perplexity &amp; Gemini', 'login-armor' ); ?></h4>
			<p class="wpf-card__copy"><?php esc_html_e( 'OGEEAT adds E-E-A-T schemas, GEO scoring and an llms.txt generator so AI engines actually understand your site.', 'login-armor' ); ?></p>
			<div class="wpf-card__foot">
				<span class="wpf-card__meta">
					<?php
					printf(
						/* translators: %s: number of modules in OGEEAT. */
						wp_kses( __( '<b>%s modules</b> · WordPress.org', 'login-armor' ), array( 'b' => array() ) ),
						esc_html( '11' )
					);
					?>
				</span>
				<span class="wpf-card__cta"><?php esc_html_e( 'Install', 'login-armor' ); ?></span>
			</div>
		</div>
	</a>

	<a href="https://wpformation.com/crash-test/" target="_blank" rel="noopener" class="wpf-card wpf-card--crashtest">
		<div class="wpf-crash-hero">
			<div class="wpf-crash-hero__badge" aria-hidden="true">
				<svg viewBox="0 0 92 108" xmlns="http://www.w3.org/2000/svg" focusable="false">
					<defs>
						<linearGradient id="la-crash-badge-top" x1="0" y1="0" x2="0" y2="1">
							<stop offset="0" stop-color="#f59e0b"/>
							<stop offset="1" stop-color="#d97706"/>
						</linearGradient>
						<linearGradient id="la-crash-badge-bot" x1="0" y1="0" x2="0" y2="1">
							<stop offset="0" stop-color="#1e293b"/>
							<stop offset="1" stop-color="#0b1220"/>
						</linearGradient>
					</defs>
					<path d="M46 3 L86 15 V58 C86 82 68 98 46 105 C24 98 6 82 6 58 V15 Z" fill="url(#la-crash-badge-top)" stroke="#1e293b" stroke-width="2"/>
					<path d="M6 62 C8 82 24 98 46 105 C68 98 84 82 86 62 Z" fill="url(#la-crash-badge-bot)"/>
					<path d="M6 62 L86 62" stroke="#f4d03f" stroke-width="1.5" opacity="0.6"/>
					<path d="M33 35 L42 44 L60 25" fill="none" stroke="#fff" stroke-width="4.5" stroke-linecap="round" stroke-linejoin="round"/>
					<text x="46" y="56" text-anchor="middle" font-family="Inter, sans-serif" font-size="8" font-weight="800" letter-spacing="0.8" fill="#1e293b">CRASH-TEST</text>
					<text x="46" y="82" text-anchor="middle" font-family="Inter, sans-serif" font-size="7" font-weight="800" letter-spacing="1.2" fill="#f4d03f">WPFORMATION</text>
					<circle cx="46" cy="92" r="1.5" fill="#f4d03f"/>
					<circle cx="40" cy="92" r="1" fill="#f4d03f" opacity="0.7"/>
					<circle cx="52" cy="92" r="1" fill="#f4d03f" opacity="0.7"/>
				</svg>
			</div>
			<div class="wpf-crash-hero__text">
				<div class="wpf-crash-hero__tagline"><?php esc_html_e( 'Zero complacency', 'login-armor' ); ?></div>
				<h5 class="wpf-crash-hero__headline">
					<?php
					echo wp_kses(
						/* translators: <em> highlights the offer, keep the <em> tag. */
						__( 'Get a <em>deep-dive review</em> on WPFormation', 'login-armor' ),
						array( 'em' => array() )
					);
					?>
				</h5>
				<p class="wpf-crash-hero__meta">
					<?php
					echo wp_kses(
						/* translators: <b> is the target audience, keep the <b> tag. */
						__( '<b>For plugin, theme &amp; SaaS editors.</b> Real-world test, published article, social blast, trust badge.', 'login-armor' ),
						array( 'b' => array() )
					);
					?>
				</p>
			</div>
			<span class="wpf-crash-hero__stamp" aria-hidden="true"><?php esc_html_e( 'Submit', 'login-armor' ); ?></span>
		</div>
		<div class="wpf-card__body">
			<span class="wpf-card__eyebrow wpf-card__eyebrow--amber"><?php esc_html_e( 'Service for editors', 'login-armor' ); ?></span>
			<h4 class="wpf-card__title"><?php esc_html_e( 'Crash-Test: A published review worth citing', 'login-armor' ); ?></h4>
			<p class="wpf-card__copy"><?php esc_html_e( '2,000-3,000-word deep dive, dedicated test site, video option. SEO-optimized to rank for years. Delivered in 5-10 business days.', 'login-armor' ); ?></p>
			<div class="wpf-card__foot">
				<span class="wpf-card__meta">
					<?php
					echo wp_kses(
						/* translators: <b> highlights the format, keep the <b> tag. */
						__( '<b>Deep-dive</b> · By Fabrice Ducarme', 'login-armor' ),
						array( 'b' => array() )
					);
					?>
				</span>
				<span class="wpf-card__cta"><?php esc_html_e( 'Apply', 'login-armor' ); ?></span>
			</div>
		</div>
	</a>
</div>
