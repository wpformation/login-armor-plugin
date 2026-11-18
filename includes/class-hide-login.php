<?php
/**
 * Hide Login module.
 *
 * Intercepts requests to wp-login.php and redirects them. Allows access
 * only through a custom slug defined by the site administrator.
 *
 * @package LoginArmor
 * @since   1.0.0
 */

namespace LoginArmor;

// Exit if accessed directly.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Handles login URL hiding.
 */
class HideLogin {

	public const SLUG_LENGTH          = 8;
	public const SLUG_ALPHABET        = 'abcdefghjkmnpqrstuvwxyz23456789';
	public const OPTION_ENABLED       = 'login_armor_hide_enabled';
	public const OPTION_SLUG          = 'login_armor_hide_slug';
	public const OPTION_REDIRECT_TYPE = 'login_armor_redirect_type';
	public const OPTION_REDIRECT_URL  = 'login_armor_redirect_url';
	public const OPTION_ACK           = 'login_armor_activation_acknowledged';
	public const REDIRECT_NOT_FOUND   = 'notfound';
	public const REDIRECT_URL         = 'url';

	public const RESERVED_SLUGS = array(
		'wp-admin', 'wp-content', 'wp-includes', 'wp-json', 'wp-login',
		'wp-signup', 'wp-register', 'wp-cron', 'wp-links-opml', 'wp-mail',
		'wp-trackback', 'xmlrpc', 'readme', 'license',
		'admin', 'login', 'logout', 'signin', 'signout', 'signup', 'register',
		'dashboard', 'user', 'users', 'account', 'my-account', 'profile',
		'feed', 'rss', 'rss2', 'atom', 'rdf', 'comments', 'trackback',
		'author', 'category', 'tag', 'page', 'date', 'search', 'embed',
		'robots', 'sitemap', 'sitemap_index',
		'shop', 'cart', 'checkout', 'members', 'groups', 'forum', 'forums', 'bbp',
	);

	/** @var string Custom login slug. */
	private readonly string $slug;

	/** @var string Redirect URL for blocked access (empty = 404). */
	private readonly string $redirect_url;

	/** @var bool Flag set by intercept_request() when a wp-login.php request is trapped. */
	private bool $wp_login_php = false;

	/** @var bool Flag set when an anonymous wp-admin request is trapped. */
	private bool $wp_admin_request = false;

	/**
	 * Flag set when safe mode let a core login endpoint through untouched.
	 *
	 * @since 2.7.0
	 * @var bool
	 */
	private bool $safe_mode_passthrough = false;

	/**
	 * True while an anonymous password-protected post form is handed to
	 * wp-login.php (2.8.0). Nothing core prints or redirects to during that
	 * request may carry the slug: see handle_loaded().
	 *
	 * @since 2.8.0
	 * @var bool
	 */
	private bool $postpass_passthrough = false;

	/**
	 * Constructor. Sets up hooks if a custom slug is configured.
	 */
	public function __construct() {
		$enabled = (int) get_option( self::OPTION_ENABLED, 0 );
		if ( 1 !== $enabled ) {
			return;
		}

		$slug         = trim( (string) get_option( self::OPTION_SLUG, '' ) );
		$redirect_url = trim( (string) get_option( self::OPTION_REDIRECT_URL, '' ) );

		// 2.8.0: an enabled module with no slug stands down. Deleting the slug
		// option is the way back that the readme, the Hide Login section and
		// every recovery e-mail sent up to 2.7.10 give to someone who lost the
		// URL. Until now this branch answered it by generating a NEW random
		// slug, unannounced, so wp-login.php stayed closed and the person
		// following the instructions ended up behind a second URL they had
		// never seen. Switching the module off is the only reading of that
		// gesture that lets them in, and it is said out loud: the option, the
		// screen and the score all show Hide Login as off afterwards.
		if ( '' === $slug ) {
			update_option( self::OPTION_ENABLED, 0 );
			/**
			 * Fires when Hide Login switched itself off because no slug was stored.
			 *
			 * @since 2.8.0
			 */
			do_action( 'login_armor_hide_login_stood_down' );
			return;
		}

		// 2.10.0: beside a plugin whose only job is hiding the login page, two
		// hidden addresses would fight over wp-login.php. The screen refuses to
		// switch Hide Login on in that case; when both end up on anyway (WP-CLI,
		// the database, the other plugin activated afterwards), Login Armor
		// stands down and says so, and the stored setting is left alone:
		// deactivating the other plugin gives the address back.
		if ( false !== self::get_exclusive_conflict() ) {
			add_action( 'admin_notices', array( self::class, 'render_suspended_notice' ) );
			add_action( 'network_admin_notices', array( self::class, 'render_suspended_notice' ) );
			return;
		}

		$this->slug         = $slug;
		$this->redirect_url = $redirect_url;

		remove_action( 'template_redirect', 'wp_redirect_admin_locations', 1000 );

		add_action( 'plugins_loaded', array( $this, 'intercept_request' ), 9999 );
		add_action( 'wp_loaded', array( $this, 'handle_loaded' ) );
		add_action( 'setup_theme', array( $this, 'block_customize_for_anonymous' ), 1 );
		add_action( 'init', array( $this, 'block_signup_activate' ) );

		add_filter( 'site_url', array( $this, 'filter_site_url' ), 10, 4 );
		add_filter( 'network_site_url', array( $this, 'filter_network_site_url' ), 10, 3 );
		add_filter( 'wp_redirect', array( $this, 'filter_wp_redirect' ), 10, 2 );
		add_filter( 'login_url', array( $this, 'filter_login_url' ), 10, 3 );
		add_filter( 'register_url', array( $this, 'filter_register_url' ) );
		add_filter( 'lostpassword_url', array( $this, 'filter_lostpassword_url' ), 10, 2 );
		add_filter( 'logout_url', array( $this, 'filter_logout_url' ), 10, 2 );
		add_filter( 'wp_signup_location', array( $this, 'filter_signup_location' ) );

		add_filter( 'user_request_action_email_content', array( $this, 'filter_gdpr_email' ), 999, 2 );
		add_filter( 'site_option_welcome_email', array( $this, 'filter_welcome_email' ) );
		add_filter( 'site_status_tests', array( $this, 'remove_loopback_test' ) );
		add_action( 'template_redirect', array( $this, 'redirect_gdpr_confirmaction' ) );

		if ( is_multisite() ) {
			add_action( 'wp_before_admin_bar_render', array( $this, 'rewrite_admin_bar' ), 999 );
			add_filter( 'manage_sites_action_links', array( $this, 'rewrite_sites_links' ), 10, 3 );
		}
	}

	/**
	 * Block customize.php for unauthenticated visitors at setup_theme prio 1.
	 */
	public function block_customize_for_anonymous(): void {
		global $pagenow;
		if ( ! is_user_logged_in() && isset( $pagenow ) && 'customize.php' === $pagenow ) {
			$this->block_access();
		}
	}

	/**
	 * Block wp-signup.php and wp-activate.php on non-multisite installs.
	 */
	public function block_signup_activate(): void {
		if ( is_multisite() ) {
			return;
		}

		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized, WordPress.Security.ValidatedSanitizedInput.MissingUnslash -- Used only for URL path string matching, not output.
		$raw = strtolower( rawurldecode( $_SERVER['REQUEST_URI'] ?? '' ) );

		if (
			false !== strpos( $raw, 'wp-signup' )
			|| false !== strpos( $raw, 'wp-activate' )
		) {
			if ( apply_filters( 'login_armor_block_signup', true ) ) {
				wp_die(
					esc_html__( 'This feature is not enabled.', 'login-armor' ),
					esc_html__( 'Forbidden', 'login-armor' ),
					array( 'response' => 403 )
				);
			}
		}
	}

	/**
	 * Intercept login-related requests at the earliest possible hook.
	 *
	 * Runs at `plugins_loaded` priority 9999 (same as WPS Hide Login). This is
	 * the first opportunity to rewrite $_SERVER['REQUEST_URI'] before WordPress
	 * processes the request through its rewrite engine.
	 *
	 * Three cases:
	 * 1. Request targets wp-login.php → flag it, rewrite URI to garbage, set
	 *    pagenow to index.php so WP serves a natural 404 later.
	 * 2. Request targets the custom slug → set pagenow to wp-login.php so WP
	 *    knows we want the login page.
	 * 3. Request targets wp-register.php (ghost endpoint) → same as case 1.
	 */
	public function intercept_request(): void {
		global $pagenow;

		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized, WordPress.Security.ValidatedSanitizedInput.MissingUnslash -- Used only for URL path string matching, not output.
		$raw_uri = rawurldecode( $_SERVER['REQUEST_URI'] ?? '' );
		$request = wp_parse_url( $raw_uri );
		$path    = $request['path'] ?? '';

		// V2.1.12: canonicalise the request host BEFORE any URI rewriting.
		// Hide Login intercepts at plugins_loaded 9999, which is earlier than
		// WP core's redirect_canonical (template_redirect). Without our own
		// pre-emption, a request that lands on a non-canonical host (e.g.
		// apex `example.com/<slug>` when siteurl/home are `https://www.example.com`)
		// gets served HTML whose asset URLs and Login Page Security Headers
		// `'self'` CSP all reference the canonical host: and the browser then
		// blocks every cross-origin asset, producing the unstyled "wp-login
		// plain HTML" symptom on shared-hosting setups that route both apex
		// and www to the same WordPress without an HTTP-level 301.
		if ( $this->is_intercepted_path( $raw_uri, $request ) ) {
			$this->maybe_canonical_redirect();
		}

		// 2.7.0 - break-glass safe mode. A forgotten slug is the single most
		// common way a site owner shuts themselves out, so the three traps
		// below stand down while LOGIN_ARMOR_SAFE_MODE is defined: wp-login.php
		// and wp-register.php are served, and anonymous /wp-admin requests are
		// left alone.
		//
		// Case 2 is NOT skipped, and neither is the canonical-host redirect
		// above. The custom slug has to keep answering: a bookmark, a mailed
		// recovery URL or a password-reset link must not break because safe
		// mode was turned on, and an apex/www mismatch must still be
		// canonicalised or the login page is served unstyled.
		$la_safe_mode = LoginArmor::is_safe_mode();

		/*
		 * Prepare anonymous wp-admin requests as front-end requests before theme
		 * setup and init. Waiting until wp_loaded leaves themes and block plugins
		 * partially initialised in admin mode, which produces an incomplete 404.
		 *
		 * 2.8.0: no action is exempt any more. `?action=enter_recovery_mode`
		 * used to be, a line carried over from another plugin, and it served no
		 * core flow: WordPress builds the recovery-mode link on wp_login_url(),
		 * never on /wp-admin/. What the exemption did do was let the request
		 * reach auth_redirect(), which answered an anonymous visitor with a
		 * Location header pointing at the hidden slug. One request, default
		 * settings, and the login URL this module exists to hide was out.
		 */
		if (
			! $la_safe_mode
			&& defined( 'WP_ADMIN' )
			&& WP_ADMIN
			&& ! is_user_logged_in()
			&& ! defined( 'WP_CLI' )
			&& ! defined( 'DOING_AJAX' )
			&& ! defined( 'DOING_CRON' )
			&& 'admin-post.php' !== $pagenow
		) {
			$this->wp_admin_request    = true;
			$_SERVER['REQUEST_URI']    = $this->user_trailingslashit( '/' . str_repeat( '-/', 10 ) );
			$pagenow                   = 'index.php'; // phpcs:ignore WordPress.WP.GlobalVariablesOverride.Prohibited
			$this->set_front_screen();
			return;
		}

		// Case 1: request targets wp-login.php directly.
		// Match against BOTH home_url and site_url relative paths so the trap
		// fires regardless of which base the request actually arrived on
		// (matters on WP-in-subdir where they differ: /wp/wp-login vs /wp-login,
		// and on multisite + domain mapping where home and siteurl diverge).
		if (
			false !== stripos( $raw_uri, 'wp-login.php' )
			|| (
				isset( $request['path'] )
				&& (
					untrailingslashit( $request['path'] ) === site_url( 'wp-login', 'relative' )
					|| untrailingslashit( $request['path'] ) === home_url( 'wp-login', 'relative' )
				)
			)
		) {
			// 2.7.0 - safe mode: hand the request to core untouched and stop
			// here. Returning matters as much as not trapping: what follows is
			// the slug matching, and a wp-login.php request is not a slug
			// request. The flag makes handle_loaded() stand down for this
			// request too, which is not optional: see the comment there.
			if ( $la_safe_mode ) {
				$this->safe_mode_passthrough = true;
				return;
			}
			// 2.8.0: core redirects a recovery-mode link to wp-login.php when
			// it handles the link before this module's filters exist, which is
			// every time a plugin fatals as it loads. The session it opened is
			// proof of the mailed key: its holder is sent on to the slug,
			// where the 404 below used to stop them.
			if ( self::recovery_session_active() ) {
				// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized, WordPress.Security.ValidatedSanitizedInput.MissingUnslash -- Sanitised by sanitize_query_string(), which keeps percent-encoding.
				$query  = (string) ( $_SERVER['QUERY_STRING'] ?? '' );
				$target = self::get_login_url();
				if ( '' !== $query ) {
					$target .= ( str_contains( $target, '?' ) ? '&' : '?' ) . $this->sanitize_query_string( $query );
				}
				wp_safe_redirect( $target );
				exit;
			}
			$this->wp_login_php = true;
			$_SERVER['REQUEST_URI'] = $this->user_trailingslashit( '/' . str_repeat( '-/', 10 ) );
			$pagenow               = 'index.php';
			return;
		}

		// Case 2: request targets the custom slug.
		// Accept BOTH home_url and site_url as valid bases: see V2.1.11 fix
		// for multisite + domain mapping where the slug URL is generated on
		// home_url (mapped domain) but site_url points to the original network
		// path. Both relative paths are usually identical (just `/<slug>`),
		// they only diverge in WP-in-subdir setups, where matching either
		// is the correct behaviour.
		$slug_match = (
			isset( $request['path'] )
			&& (
				untrailingslashit( $request['path'] ) === home_url( $this->slug, 'relative' )
				|| untrailingslashit( $request['path'] ) === site_url( $this->slug, 'relative' )
			)
		);
		// phpcs:disable WordPress.Security.NonceVerification.Recommended -- Read-only slug detection, not form processing.
		$query_match = (
			! get_option( 'permalink_structure' )
			&& isset( $_GET[ $this->slug ] )
			&& '' === $_GET[ $this->slug ]
		);
		// phpcs:enable WordPress.Security.NonceVerification.Recommended

		if ( $slug_match || $query_match ) {
			$pagenow = 'wp-login.php';
			$this->maybe_begin_recovery_mode();
			return;
		}

		// Case 3: wp-register.php ghost endpoint (removed WP 3.1). Same
		// dual-base matching as Case 1 for the same reasons.
		if (
			false !== stripos( $raw_uri, 'wp-register.php' )
			|| (
				isset( $request['path'] )
				&& (
					untrailingslashit( $request['path'] ) === site_url( 'wp-register', 'relative' )
					|| untrailingslashit( $request['path'] ) === home_url( 'wp-register', 'relative' )
				)
			)
		) {
			// 2.7.0 - same passthrough as case 1.
			if ( $la_safe_mode ) {
				$this->safe_mode_passthrough = true;
				return;
			}
			$this->wp_login_php = true;
			$_SERVER['REQUEST_URI'] = $this->user_trailingslashit( '/' . str_repeat( '-/', 10 ) );
			$pagenow               = 'index.php';
		}
	}

	/**
	 * Quick detection: would this request fall into one of the three cases
	 * intercept_request() rewrites? Used to decide whether to pre-emptively
	 * canonicalise the host on apex/www mismatches.
	 *
	 * Mirrors the detection logic of intercept_request() exactly. Kept as a
	 * standalone helper so the canonical-redirect step does not need to
	 * duplicate (and risk drifting from) the matching rules.
	 *
	 * NEVER VERIFY THESE COMPARISONS THROUGH WP-CLI. The six of them below,
	 * and the ones in cases 1, 2 and 3 of intercept_request(), rest on
	 * home_url( $path, 'relative' ) and site_url( $path, 'relative' ) giving a
	 * relative path. WP-CLI overrides both helpers with a priority-0 filter of
	 * its own (`vendor/wp-cli/wp-cli/php/WP_CLI/Runner.php`, comment: "Don't
	 * apply set_url_scheme in get_home_url() or get_site_url()"), which
	 * rebuilds the value from get_option( 'home' ) and DISCARDS the scheme
	 * argument. Under `wp eval` they therefore come back ABSOLUTE, on every
	 * WordPress version, and these branches look dead when they are not.
	 * Measured on WordPress 7.1.2: in a real HTTP request
	 * home_url( 'x', 'relative' ) is '/x' and has_filter( 'home_url' ) is
	 * false; through `wp eval`, on the same site, it is
	 * 'http://host/x' and the filter is present. Measure in a request, or
	 * read get_home_url() in core.
	 *
	 * @since 2.1.12
	 *
	 * @param string                                $raw_uri Raw REQUEST_URI (URL-decoded).
	 * @param array<string, string|int|null>|false  $request Output of wp_parse_url() on $raw_uri.
	 */
	private function is_intercepted_path( string $raw_uri, $request ): bool {
		if ( false !== stripos( $raw_uri, 'wp-login.php' ) ) {
			return true;
		}
		if ( false !== stripos( $raw_uri, 'wp-register.php' ) ) {
			return true;
		}

		if ( is_array( $request ) && isset( $request['path'] ) ) {
			$path = untrailingslashit( $request['path'] );
			if (
				$path === site_url( 'wp-login', 'relative' )
				|| $path === home_url( 'wp-login', 'relative' )
				|| $path === site_url( 'wp-register', 'relative' )
				|| $path === home_url( 'wp-register', 'relative' )
				|| $path === home_url( $this->slug, 'relative' )
				|| $path === site_url( $this->slug, 'relative' )
			) {
				return true;
			}
		}

		// Query-string slug variant (when permalinks are disabled).
		// phpcs:disable WordPress.Security.NonceVerification.Recommended -- Read-only slug detection, not form processing.
		if (
			! get_option( 'permalink_structure' )
			&& isset( $_GET[ $this->slug ] )
			&& '' === $_GET[ $this->slug ]
		) {
			return true;
		}
		// phpcs:enable WordPress.Security.NonceVerification.Recommended

		return false;
	}

	/**
	 * Canonicalise the request host before Hide Login proceeds with rewriting.
	 *
	 * Strategy: if the current HTTP_HOST matches NEITHER home_url's host nor
	 * site_url's host, 301-redirect to the home_url host preserving the full
	 * REQUEST_URI. Matching either is acceptable: site_url is the canonical
	 * back-end host (multisite headless / WP-in-subdir), home_url is the
	 * canonical front-end host (default + multisite domain mapping).
	 *
	 * Comparison is host-only (not scheme/port) on purpose: a scheme mismatch
	 * usually indicates a misconfigured reverse-proxy (WP thinks HTTP because
	 * the proxy strips X-Forwarded-Proto). Including scheme in the comparison
	 * would loop-redirect those setups. Hosting that legitimately runs apex
	 * and www on different schemes is vanishingly rare; the CSP host-aware
	 * fix in LoginHeaders V2.1.12 covers the same root cause from a second
	 * angle.
	 *
	 * Skips: WP-CLI, cron, AJAX (these don't go through Hide Login
	 * interception anyway: defensive). Filterable via
	 * `login_armor_canonical_host_redirect` for proxy setups that legitimately
	 * accept arbitrary inbound hostnames and don't want a 301.
	 *
	 * @since 2.1.12
	 */
	private function maybe_canonical_redirect(): void {
		if ( defined( 'WP_CLI' ) && WP_CLI ) {
			return;
		}
		if ( defined( 'DOING_CRON' ) && DOING_CRON ) {
			return;
		}
		if ( defined( 'DOING_AJAX' ) && DOING_AJAX ) {
			return;
		}
		if ( empty( $_SERVER['HTTP_HOST'] ) ) {
			return;
		}

		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Sanitised on next line.
		$http_host = sanitize_text_field( wp_unslash( $_SERVER['HTTP_HOST'] ) );
		$http_host = strtolower( (string) strtok( $http_host, ':' ) ); // strip port if present
		if ( '' === $http_host ) {
			return;
		}

		$home_host = strtolower( (string) wp_parse_url( home_url(), PHP_URL_HOST ) );
		$site_host = strtolower( (string) wp_parse_url( site_url(), PHP_URL_HOST ) );

		// Already on a canonical host → nothing to canonicalise.
		if ( $http_host === $home_host || $http_host === $site_host ) {
			return;
		}

		/**
		 * Filter whether to canonicalise the host on Hide Login interception.
		 *
		 * Returning false skips the 301, letting the request proceed on the
		 * alternate hostname. Useful for proxy setups, dev environments, or
		 * multisite configurations that legitimately route the login page
		 * through a third hostname WP itself doesn't know about.
		 *
		 * @since 2.1.12
		 *
		 * @param bool   $should_redirect Default true.
		 * @param string $http_host       Current request host (lowercased, port stripped).
		 * @param string $home_host       Parsed host of home_url().
		 * @param string $site_host       Parsed host of site_url().
		 */
		$should_redirect = (bool) apply_filters(
			'login_armor_canonical_host_redirect',
			true,
			$http_host,
			$home_host,
			$site_host
		);
		if ( ! $should_redirect ) {
			return;
		}

		$request_uri = $this->canonical_target_uri();

		// Build target on home_url's scheme + host + port. home_url is the
		// canonical front-end URL per WP convention; site_url points at the
		// back-end which is the right answer only on headless multisite (and
		// in that case HTTP_HOST already matches site_host, so we don't get
		// here). Using home_url() to source the parts keeps scheme/port
		// tracking exactly what the admin configured.
		$home_parts = wp_parse_url( home_url() );
		if ( empty( $home_parts['scheme'] ) || empty( $home_parts['host'] ) ) {
			return; // Defensive: can't construct a safe target.
		}
		$target = $home_parts['scheme'] . '://' . $home_parts['host'];
		if ( ! empty( $home_parts['port'] ) ) {
			$target .= ':' . (int) $home_parts['port'];
		}
		$target .= $request_uri;

		$this->refuse_page_cache();
		wp_safe_redirect( $target, 301 );
		exit;
	}

	/**
	 * Sanitise a raw QUERY_STRING for reuse in a redirect target or in a
	 * rebuilt `$_SERVER['REQUEST_URI']`.
	 *
	 * `sanitize_text_field()` must NEVER be used for this. It strips every
	 * percent-encoded sequence from the value (`%40`, `%20`, `%C3%A9`...),
	 * which silently corrupts any encoded parameter. On the password-reset
	 * flow that turns `login=jean%40client.fr` into `login=jeanclient.fr`,
	 * so `check_password_reset_key()` can no longer resolve the account and
	 * the user is bounced to `?action=lostpassword&error=invalidkey`: the
	 * "this link is no longer valid" dead end, on every single attempt,
	 * for every site whose logins are e-mail addresses. Same damage on
	 * `redirect_to=https%3A%2F%2F...` after a normal login.
	 *
	 * Percent-encoding is therefore preserved verbatim. Only what could
	 * corrupt the response is removed: NUL bytes and CR/LF, raw or encoded,
	 * the header-injection vectors. On the redirect paths `wp_safe_redirect()`
	 * additionally applies core's `wp_sanitize_redirect()`, which enforces a
	 * character allow-list while keeping `%XX` intact.
	 *
	 * @since 2.5.2
	 *
	 * @param string $query Raw query string (already unslashed).
	 * @return string Safe query string, percent-encoding preserved.
	 */
	/**
	 * The request URI to carry into the canonical-host 301, percent-encoding intact.
	 *
	 * Until 2.7.0 this was one call to `sanitize_text_field()` on the whole
	 * URI, query string included. That is the exact defect 2.5.2 fixed at the
	 * three `QUERY_STRING` sites, and this fourth site was missed: the core
	 * sanitiser removes EVERY percent-encoded sequence from the value, so on a
	 * site whose apex and www both reach WordPress, a password-reset link for
	 * `login=jean%40client.fr` arriving on the non-canonical host was 301'd to
	 * `login=jeanclient.fr`, `check_password_reset_key()` no longer resolved
	 * the account, and the user landed on `?action=lostpassword&error=invalidkey`
	 * every single time. An encoded `redirect_to` was destroyed the same way.
	 * Nothing later could compensate: this runs at `plugins_loaded` 9999,
	 * before any other decision this plugin makes.
	 *
	 * The URI is therefore split at the first `?` and both halves go through
	 * `sanitize_query_string()`, which preserves `%XX` and removes only what
	 * could corrupt the response: NUL bytes and CR/LF, raw or encoded. A path
	 * can carry percent-encoding too, so it gets the same treatment. On top of
	 * that, `wp_safe_redirect()` applies core's `wp_sanitize_redirect()`,
	 * an allow-list that also keeps `%XX` intact.
	 *
	 * @since 2.7.0
	 */
	private function canonical_target_uri(): string {
		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- sanitize_query_string() below is the sanitiser; sanitize_text_field() would strip every %XX sequence and corrupt the URL.
		$raw = isset( $_SERVER['REQUEST_URI'] ) ? (string) wp_unslash( $_SERVER['REQUEST_URI'] ) : '/';

		$split = strpos( $raw, '?' );
		$path  = false === $split ? $raw : substr( $raw, 0, $split );
		$query = false === $split ? '' : substr( $raw, $split + 1 );

		$path = $this->sanitize_query_string( $path );
		if ( '' === $path || '/' !== $path[0] ) {
			$path = '/' . ltrim( $path, '/' );
		}

		if ( '' === $query ) {
			return $path;
		}
		return $path . '?' . $this->sanitize_query_string( $query );
	}

	/**
	 * Let WordPress's own recovery-mode link work through the slug (2.8.0).
	 *
	 * When a plugin fatals, WordPress mails the administrator a link built on
	 * wp_login_url(), so with this module on it points at the slug. Core
	 * handles that link in wp_recovery_mode()->initialize(), which runs from
	 * wp-settings.php BEFORE any plugin loads and acts only when $pagenow is
	 * 'wp-login.php'. A slug request is served through index.php, so at that
	 * moment $pagenow said 'index.php': the link was ignored, the visitor got
	 * the plain login form, and recovery mode never started. Measured on
	 * 2.7.10: no recovery cookie through the slug, the cookie and the 302
	 * through wp-login.php with the module off.
	 *
	 * So the same core entry point is run again, with $pagenow set to
	 * 'wp-login.php'. It validates the key and the token itself, sets the
	 * cookie and redirects to wp_login_url(); without those three parameters
	 * it does nothing.
	 *
	 * When: from login-armor.php, while plugins are still being included,
	 * as close as a plugin gets to the moment core would have done it. The
	 * link is mailed because something fatals, and a fatal in a plugin's
	 * plugins_loaded callback killed the slug request before this module's
	 * own callback, at priority 9999, ever ran: the link answered with the
	 * critical error page. The redirect that follows goes to wp-login.php,
	 * this module's filters not being registered yet; intercept_request()
	 * sends a validated recovery session on to the slug.
	 */
	public static function begin_recovery_mode_early(): void {
		// phpcs:disable WordPress.Security.NonceVerification.Recommended -- Presence and routing tests only: core validates the recovery key and token itself.
		if ( ! isset( $_GET['action'], $_GET['rm_token'], $_GET['rm_key'] ) || ! is_string( $_GET['action'] ) || 'enter_recovery_mode' !== $_GET['action'] ) {
			return;
		}
		// phpcs:enable WordPress.Security.NonceVerification.Recommended
		if ( 1 !== (int) get_option( self::OPTION_ENABLED, 0 ) ) {
			return;
		}
		$slug = trim( (string) get_option( self::OPTION_SLUG, '' ) );
		if ( '' === $slug || ! self::request_names_slug( $slug ) ) {
			return;
		}
		if ( is_multisite() || ! function_exists( 'wp_recovery_mode' ) || ! function_exists( 'wp_is_fatal_error_handler_enabled' ) || ! wp_is_fatal_error_handler_enabled() ) {
			return;
		}

		// Once the link is accepted, core redirects to wp_login_url(). This
		// module's filters do not exist yet, so that would be wp-login.php;
		// the slug is given here, for this one call.
		$login_url = self::get_login_url();
		$to_slug   = static function () use ( $login_url ): string {
			return $login_url;
		};
		add_filter( 'login_url', $to_slug, PHP_INT_MAX );

		global $pagenow;
		$previous = $pagenow;
		$pagenow  = 'wp-login.php'; // phpcs:ignore WordPress.WP.GlobalVariablesOverride.Prohibited -- The page core requires to act on its own link; restored below.
		wp_recovery_mode()->initialize();
		// Not reached for a link core recognises: it redirects or dies.
		$pagenow = $previous; // phpcs:ignore WordPress.WP.GlobalVariablesOverride.Prohibited
		remove_filter( 'login_url', $to_slug, PHP_INT_MAX );
	}

	/**
	 * Does the request name the slug? Case 2 of intercept_request(), for a
	 * caller that runs before this module is constructed (2.8.0).
	 *
	 * @param string $slug The stored slug.
	 */
	private static function request_names_slug( string $slug ): bool {
		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized, WordPress.Security.ValidatedSanitizedInput.MissingUnslash -- Used only for path matching, never output.
		$request = wp_parse_url( rawurldecode( (string) ( $_SERVER['REQUEST_URI'] ?? '' ) ) );
		if ( is_array( $request ) && isset( $request['path'] ) ) {
			$path = untrailingslashit( $request['path'] );
			if ( $path === home_url( $slug, 'relative' ) || $path === site_url( $slug, 'relative' ) ) {
				return true;
			}
		}
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Read-only slug detection, not form processing.
		return ! get_option( 'permalink_structure' ) && isset( $_GET[ $slug ] ) && '' === $_GET[ $slug ];
	}

	/**
	 * Is this request carried by a recovery-mode session core has validated?
	 *
	 * Only the key mailed to the administrator creates one, so its holder
	 * may be told where the login screen is (2.8.0).
	 */
	private static function recovery_session_active(): bool {
		return ! is_multisite()
			&& function_exists( 'wp_recovery_mode' )
			&& wp_recovery_mode()->is_active();
	}

	/**
	 * The fallback of begin_recovery_mode_early(), once the module is up.
	 *
	 * Kept for a site whose home URL a plugin rewrites (a language prefix,
	 * for instance): such a filter is not there yet when the early test
	 * reads the slug, and is by plugins_loaded. Running core's entry point
	 * twice costs nothing: add_action() does not register a callback twice,
	 * and the link exits the request the first time it is recognised.
	 */
	private function maybe_begin_recovery_mode(): void {
		// phpcs:disable WordPress.Security.NonceVerification.Recommended -- Presence test only: core validates the recovery key and token itself.
		if ( ! isset( $_GET['action'], $_GET['rm_token'], $_GET['rm_key'] ) || 'enter_recovery_mode' !== sanitize_key( wp_unslash( $_GET['action'] ) ) ) {
			return;
		}
		// phpcs:enable WordPress.Security.NonceVerification.Recommended
		if ( is_multisite() || ! function_exists( 'wp_recovery_mode' ) || ! function_exists( 'wp_is_fatal_error_handler_enabled' ) || ! wp_is_fatal_error_handler_enabled() ) {
			return;
		}

		wp_recovery_mode()->initialize();
	}

	/**
	 * The login action as wp-login.php will see it.
	 *
	 * Core reads $_REQUEST['action'], and wp_magic_quotes() rebuilds
	 * $_REQUEST as array_merge( $_GET, $_POST ), so a value in the request
	 * body overrides the same key in the URL. Every routing decision this
	 * module takes about an action has to agree with that, or a request can
	 * look like one action here and be processed as another by core.
	 *
	 * The value is compared exactly, as core compares it: wp-login.php takes
	 * the string as it is and runs any action it does not know as "login".
	 * This used to go through sanitize_key(), which lowercases and strips
	 * punctuation, so "PostPass" read as "postpass" here while core ran a
	 * login on the hidden wp-login.php.
	 *
	 * @since 2.8.0
	 */
	private static function request_action(): string {
		// phpcs:disable WordPress.Security.NonceVerification.Recommended, WordPress.Security.NonceVerification.Missing, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Read-only routing decision, compared exactly against a literal, never output.
		$action = isset( $_POST['action'] ) ? wp_unslash( $_POST['action'] ) : wp_unslash( $_GET['action'] ?? '' );
		// An array (a crafted action[]=) is not a string for core either: it
		// runs "login".
		return is_string( $action ) ? $action : '';
		// phpcs:enable WordPress.Security.NonceVerification.Recommended, WordPress.Security.NonceVerification.Missing, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
	}

	private function sanitize_query_string( string $query ): string {
		$query = wp_kses_no_null( $query );
		$query = str_replace( array( "\r", "\n", "\t" ), '', $query );
		return (string) _deep_replace( array( '%0d', '%0a', '%0D', '%0A' ), $query );
	}

	private function use_trailing_slashes(): bool {
		return '/' === substr( (string) get_option( 'permalink_structure' ), -1, 1 );
	}

	private function user_trailingslashit( string $string ): string {
		return $this->use_trailing_slashes()
			? trailingslashit( $string )
			: untrailingslashit( $string );
	}

	/**
	 * Gatekeeper at wp_loaded: handle the post-interception state.
	 *
	 * By this point, intercept_request() has already rewritten REQUEST_URI
	 * for wp-login.php requests and set $pagenow for slug requests.
	 */
	public function handle_loaded(): void {
		global $pagenow;

		// 2.7.0 - safe mode let a genuine wp-login.php (or wp-register.php)
		// request through at plugins_loaded. This module must then do nothing
		// at all for it, and the two things below are why a partial stand-down
		// was not enough:
		//
		//  - the trailing-slash canonicalisation fires on any $pagenow of
		//    wp-login.php, which core sets for a real /wp-login.php request:
		//    it answered a 302 to the hidden slug, the one URL the person
		//    arming safe mode no longer has;
		//  - the last branch serves the login page by requiring wp-login.php,
		//    which is already the running script, so require_once is a no-op
		//    and the response came back 200 with an EMPTY body.
		//
		// Both were caught by tests/ci/flows.sh journey (f) against a running
		// site, one after the other, before any of this shipped.
		if ( $this->safe_mode_passthrough ) {
			return;
		}

		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized, WordPress.Security.ValidatedSanitizedInput.MissingUnslash -- Used only for URL path string matching, not output.
		$request = wp_parse_url( rawurldecode( $_SERVER['REQUEST_URI'] ?? '' ) );

		// Let the password-protected post form through, and nothing else.
		//
		// 2.8.0: the action is read the way wp-login.php will read it. Core
		// switches on $_REQUEST['action'], which wp_magic_quotes() builds as
		// array_merge( $_GET, $_POST ): the BODY wins. This used to read the
		// URL first, so a POST to /wp-login.php?action=postpass carrying
		// action=login in its body passed this test as "postpass" and was then
		// processed by core as a login, on the very wp-login.php this module
		// hides. The pass is also limited to a trapped wp-login.php request:
		// on /wp-admin/ it skipped block_access(), and auth_redirect() then
		// answered with the slug in its Location header.
		//
		// Core still runs wp-login.php for that request, and nothing of what
		// it prints or redirects to may name the slug: a target that points
		// at wp-login.php (redirect_to, or the Referer) used to come back as
		// the slug, and so did the screens core switches to by itself when
		// the URL carries key (an invalid reset link) or checkemail. Those two
		// are refused outright; for the rest, the URL filters leave
		// wp-login.php as it is, which answers 404 to the visitor.
		$action = self::request_action();
		// phpcs:ignore WordPress.Security.NonceVerification.Missing, WordPress.Security.NonceVerification.Recommended -- Presence tests only; core's postpass handler validates the field itself.
		if ( $this->wp_login_php && 'postpass' === $action && isset( $_POST['post_password'] ) && ! isset( $_GET['key'] ) && ! isset( $_GET['checkemail'] ) ) {
			$this->postpass_passthrough = true;
			return;
		}

		// Block /wp-admin for unauthenticated, non-CLI, non-AJAX, non-cron.
		// 2.7.0 - not while safe mode is armed: the whole point of the constant
		// is that /wp-admin answers again for someone who lost the slug.
		if (
			! LoginArmor::is_safe_mode()
			&& ( $this->wp_admin_request || is_admin() )
			&& ! is_user_logged_in()
			&& ! defined( 'WP_CLI' )
			&& ! defined( 'DOING_AJAX' )
			&& ! defined( 'DOING_CRON' )
			&& $pagenow !== 'admin-post.php'
		) {
			$this->block_access();
			return;
		}

		// Trailing slash normalization. Canonicalises the CUSTOM SLUG, whose
		// path has to match the site's permalink convention (RFC 6265 path
		// matching, the 2.1.13 PendingCookie lesson). A genuine wp-login.php
		// request never reaches here: see the safe-mode return at the top.
		if (
			'wp-login.php' === $pagenow
			&& isset( $request['path'] )
			&& $request['path'] !== $this->user_trailingslashit( $request['path'] )
			&& get_option( 'permalink_structure' )
		) {
			$query = ! empty( $_SERVER['QUERY_STRING'] )
				// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- sanitize_query_string() is the sanitiser here; sanitize_text_field() would strip every %XX sequence and corrupt the query.
				? '?' . $this->sanitize_query_string( wp_unslash( $_SERVER['QUERY_STRING'] ) )
				: '';
			wp_safe_redirect( $this->user_trailingslashit( $this->new_login_url() ) . $query );
			exit;
		}

		// wp-login.php was trapped by intercept_request() → serve 404.
		if ( $this->wp_login_php ) {
			// Handle wp-activate.php referer (multisite signup confirmation).
			$referer = wp_get_referer();
			if (
				is_string( $referer )
				&& false !== strpos( $referer, 'wp-activate.php' )
				&& ( $ref_parsed = wp_parse_url( $referer ) )
				&& ! empty( $ref_parsed['query'] )
			) {
				parse_str( $ref_parsed['query'], $ref_params );
				if ( ! empty( $ref_params['key'] ) ) {
					require_once WPINC . '/ms-functions.php';
					$result = wpmu_activate_signup( $ref_params['key'] );
					if (
						is_wp_error( $result )
						&& in_array( $result->get_error_code(), array( 'already_active', 'blog_taken' ), true )
					) {
						$query = ! empty( $_SERVER['QUERY_STRING'] )
							// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- See sanitize_query_string(): percent-encoding must survive.
							? '?' . $this->sanitize_query_string( wp_unslash( $_SERVER['QUERY_STRING'] ) )
							: '';
						wp_safe_redirect( $this->new_login_url() . $query );
						exit;
					}
				}
			}

			$this->redirect_blocked_access();
			$this->serve_404_template();
			return;
		}

		// Slug was matched by intercept_request() → serve wp-login.php.
		if ( 'wp-login.php' === $pagenow ) {
			// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Read-only check for login redirect routing.
			if ( is_user_logged_in() && ! isset( $_REQUEST['action'] ) ) {
				wp_safe_redirect( admin_url() );
				exit;
			}
			$this->serve_login_page();
		}
	}

	/**
	 * Replace wp-login.php in site_url().
	 *
	 * Parameters intentionally untyped: WP core does not enforce types on
	 * filter callback arguments, and third-party plugins (e.g. WP Fastest
	 * Cache) routinely call get_site_url() with $blog_id as a string. A
	 * strict ?int signature here would fatal the caller.
	 *
	 * @param mixed $url     The complete site URL.
	 * @param mixed $path    Path relative to the site URL.
	 * @param mixed $scheme  URL scheme.
	 * @param mixed $blog_id Blog ID, or null for the current blog.
	 * @return mixed
	 */
	public function filter_site_url( $url = '', $path = '', $scheme = null, $blog_id = null ) {
		if ( ! is_string( $url ) ) {
			return $url; // Pass through unexpected values from third-party filters.
		}
		return $this->rewrite_login_url( $url );
	}

	/**
	 * Replace wp-login.php in network_site_url().
	 *
	 * Parameters untyped for the same reason as filter_site_url() above.
	 *
	 * @param mixed $url    The complete network site URL.
	 * @param mixed $path   Path relative to the network site URL.
	 * @param mixed $scheme URL scheme.
	 * @return mixed
	 */
	public function filter_network_site_url( $url = '', $path = '', $scheme = null ) {
		if ( ! is_string( $url ) ) {
			return $url; // Pass through unexpected values from third-party filters.
		}
		return $this->rewrite_login_url( $url );
	}

	/**
	 * Rewrite any redirect targeting wp-login.php to use the custom slug.
	 *
	 * Skips redirects to wordpress.com/wp-login.php (Jetpack SSO).
	 *
	 * Parameters untyped: $status may legitimately be passed as a string by
	 * third-party redirect helpers.
	 *
	 * The return hint is removed on purpose: `wp_redirect` filters may
	 * legitimately receive/return `false` to cancel a redirect, and that
	 * value must pass through untouched.
	 *
	 * @param mixed $location Redirect target URL.
	 * @param mixed $status   HTTP status code.
	 * @return mixed
	 */
	public function filter_wp_redirect( $location = '', $status = 302 ) {
		if ( ! is_string( $location ) ) {
			return $location; // false = cancelled redirect; pass through as-is.
		}
		if ( false !== strpos( $location, 'https://wordpress.com/wp-login.php' ) ) {
			return $location;
		}
		return $this->rewrite_login_url( $location );
	}

	/**
	 * Filter the login URL.
	 *
	 * Conditioned on $force_reauth: when falsy, return the URL as-is.
	 * On 404 pages, return '#' to avoid leaking the login URL in source.
	 *
	 * Parameters untyped: WP core may pass $force_reauth as int 0/1 on some
	 * code paths, and third-party plugins routinely pass strings.
	 *
	 * @param mixed $login_url     Default login URL.
	 * @param mixed $redirect      Redirect target after login.
	 * @param mixed $force_reauth  Whether to force reauthentication.
	 * @return mixed
	 */
	public function filter_login_url( $login_url = '', $redirect = '', $force_reauth = false ) {
		// 2.8.0: is_404() before the main query exists is a _doing_it_wrong()
		// notice, and the recovery-mode link asks for the login URL that early.
		// On a site that displays notices, it was printed ahead of the
		// redirect and the redirect was lost.
		if ( isset( $GLOBALS['wp_query'] ) && is_404() ) {
			return '#';
		}
		if ( ! is_string( $login_url ) ) {
			return $login_url; // Pass through unexpected values from third-party filters.
		}
		if ( empty( $force_reauth ) ) {
			return $login_url;
		}
		return $this->rewrite_login_url( $login_url );
	}

	/**
	 * Filter the registration URL.
	 *
	 * Untyped defensively (third-party re-fires); non-strings pass through.
	 *
	 * @param mixed $url The registration URL (expected string).
	 * @return mixed
	 */
	public function filter_register_url( $url = '' ) {
		if ( ! is_string( $url ) ) {
			return $url;
		}
		return $this->rewrite_login_url( $url );
	}

	/**
	 * Filter the lost password URL.
	 *
	 * Untyped defensively (third-party re-fires); non-strings pass through.
	 *
	 * @param mixed $url      The lost password URL (expected string).
	 * @param mixed $redirect Redirect destination.
	 * @return mixed
	 */
	public function filter_lostpassword_url( $url = '', $redirect = '' ) {
		if ( ! is_string( $url ) ) {
			return $url;
		}
		return $this->rewrite_login_url( $url );
	}

	/**
	 * Filter the logout URL.
	 *
	 * Untyped defensively (third-party re-fires); non-strings pass through.
	 *
	 * @param mixed $url      The logout URL (expected string).
	 * @param mixed $redirect Redirect destination.
	 * @return mixed
	 */
	public function filter_logout_url( $url = '', $redirect = '' ) {
		if ( ! is_string( $url ) ) {
			return $url;
		}
		return $this->rewrite_login_url( $url );
	}

	/**
	 * Filter the signup location for multisite.
	 *
	 * Untyped defensively (third-party re-fires); non-strings pass through.
	 *
	 * @param mixed $url Signup URL (expected string).
	 * @return mixed
	 */
	public function filter_signup_location( $url = '' ) {
		if ( ! is_string( $url ) ) {
			return $url;
		}
		return $this->rewrite_login_url( $url );
	}

	/**
	 * Rewrite GDPR export/erasure confirmation email URLs.
	 *
	 * Untyped defensively (third-party re-fires); unexpected types pass through.
	 *
	 * @param mixed $email_text Email body (expected string).
	 * @param mixed $email_data Email data (expected array).
	 * @return mixed
	 */
	public function filter_gdpr_email( $email_text = '', $email_data = array() ) {
		if ( ! is_string( $email_text ) || ! is_array( $email_data ) ) {
			return $email_text;
		}
		if ( isset( $email_data['confirm_url'] ) ) {
			$email_text = str_replace(
				'###CONFIRM_URL###',
				esc_url_raw( str_replace( $this->slug . '/', 'wp-login.php', $email_data['confirm_url'] ) ),
				$email_text
			);
		}
		return $email_text;
	}

	/**
	 * Rewrite the multisite welcome email to use the custom slug.
	 *
	 * Untyped defensively (third-party re-fires); non-strings pass through.
	 *
	 * @param mixed $value Welcome email text (expected string).
	 * @return mixed
	 */
	public function filter_welcome_email( $value = '' ) {
		if ( ! is_string( $value ) ) {
			return $value;
		}
		return str_replace( 'wp-login.php', trailingslashit( $this->slug ), $value );
	}

	/**
	 * Remove the Site Health loopback test (false negative with hidden login).
	 *
	 * Untyped defensively (third-party re-fires); unexpected shapes pass through.
	 *
	 * @param mixed $tests Site Health tests (expected array).
	 * @return mixed
	 */
	public function remove_loopback_test( $tests = array() ) {
		if ( is_array( $tests ) && isset( $tests['async'] ) && is_array( $tests['async'] ) ) {
			unset( $tests['async']['loopback_requests'] );
		}
		return $tests;
	}

	/**
	 * Redirect GDPR confirmation links to the custom slug.
	 */
	public function redirect_gdpr_confirmaction(): void {
		// phpcs:disable WordPress.Security.NonceVerification.Recommended -- GDPR confirmation links carry their own request_id + confirm_key validation.
		if (
			! empty( $_GET['action'] )
			&& 'confirmaction' === $_GET['action']
			&& ! empty( $_GET['request_id'] )
			&& ! empty( $_GET['confirm_key'] )
		) {
			$request_id = (int) $_GET['request_id'];
			$key        = sanitize_text_field( wp_unslash( $_GET['confirm_key'] ) );
			// phpcs:enable WordPress.Security.NonceVerification.Recommended
			$result     = wp_validate_user_request_key( $request_id, $key );
			if ( ! is_wp_error( $result ) ) {
				wp_safe_redirect(
					add_query_arg(
						array(
							'action'      => 'confirmaction',
							'request_id'  => $request_id,
							'confirm_key' => $key,
						),
						$this->new_login_url()
					)
				);
				exit;
			}
		}
	}

	/**
	 * Rewrite "My Sites" admin bar menu links in multisite.
	 */
	public function rewrite_admin_bar(): void {
		global $wp_admin_bar;
		if ( ! is_object( $wp_admin_bar ) ) {
			return;
		}

		foreach ( $wp_admin_bar->get_nodes() as $node ) {
			if ( preg_match( '/^blog-(\d+)(.*)/', $node->id, $matches ) ) {
				$blog_id = (int) $matches[1];
				$suffix  = $matches[2];
				$slug    = (string) get_blog_option( $blog_id, self::OPTION_SLUG, '' );
				if ( '' === $slug ) {
					continue;
				}
				if ( ! $suffix || '-d' === $suffix ) {
					$args       = $node;
					$old_href   = $args->href;
					$args->href = preg_replace( '/wp-admin\/$/', "$slug/", $old_href );
					if ( $old_href !== $args->href ) {
						$wp_admin_bar->add_node( $args );
					}
				} elseif ( is_string( $node->href ) && false !== strpos( $node->href, '/wp-admin/' ) ) {
					$wp_admin_bar->remove_node( $node->id );
				}
			}
		}
	}

	/**
	 * Rewrite "Dashboard" link in Network Admin > Sites list.
	 *
	 * Untyped defensively (third-party re-fires); unexpected types pass through.
	 *
	 * @param mixed $actions  Row action links (expected array).
	 * @param mixed $blog_id  Site ID (expected int).
	 * @param mixed $blogname Site name (unused).
	 * @return mixed
	 */
	public function rewrite_sites_links( $actions = array(), $blog_id = 0, $blogname = '' ) {
		if ( ! is_array( $actions ) ) {
			return $actions;
		}
		$blog_id = (int) $blog_id;
		$slug    = (string) get_blog_option( $blog_id, self::OPTION_SLUG, '' );
		if ( '' !== $slug && 1 === (int) get_blog_option( $blog_id, self::OPTION_ENABLED, 0 ) ) {
			$actions['backend'] = sprintf(
				'<a href="%1$s" class="edit">%2$s</a>',
				esc_url( get_site_url( $blog_id, $slug ) ),
				__( 'Dashboard', 'login-armor' )
			);
		}
		return $actions;
	}

	/**
	 * Generate a cryptographically random login slug.
	 */
	public static function generate_slug(): string {
		$alphabet = self::SLUG_ALPHABET;
		$max      = strlen( $alphabet ) - 1;
		$out      = '';
		for ( $i = 0; $i < self::SLUG_LENGTH; $i++ ) {
			$out .= $alphabet[ random_int( 0, $max ) ];
		}
		return $out;
	}

	/**
	 * Normalize redirect option values used by current and legacy releases.
	 *
	 * @param string $redirect_type Stored redirect type.
	 */
	public static function normalize_redirect_type( string $redirect_type ): string {
		return in_array( $redirect_type, array( self::REDIRECT_URL, 'custom' ), true )
			? self::REDIRECT_URL
			: self::REDIRECT_NOT_FOUND;
	}

	/**
	 * Validate a slug candidate.
	 *
	 * @return true|\WP_Error
	 */
	public static function validate_slug( string $slug ) {
		$generic = new \WP_Error(
			'invalid_slug',
			__( 'This slug cannot be used. Try Regenerate for a safe random slug.', 'login-armor' )
		);

		if ( ! preg_match( '/^[a-z0-9][a-z0-9\-]{2,63}$/', $slug ) ) {
			return $generic;
		}

		$query_vars = array();
		$wp_obj     = isset( $GLOBALS['wp'] ) ? $GLOBALS['wp'] : null;
		if ( $wp_obj instanceof \WP ) {
			$query_vars = array_merge(
				(array) $wp_obj->public_query_vars,
				(array) $wp_obj->private_query_vars
			);
		}

		$reserved = apply_filters(
			'login_armor_reserved_slugs',
			array_values( array_unique( array_merge( self::RESERVED_SLUGS, $query_vars ) ) )
		);
		if ( in_array( $slug, (array) $reserved, true ) ) {
			return $generic;
		}

		$existing = get_page_by_path( $slug, OBJECT, array( 'page', 'post' ) );
		if ( $existing instanceof \WP_Post ) {
			return $generic;
		}

		return true;
	}

	/**
	 * Return the full login URL for the current site.
	 *
	 * Returns the custom slug URL only when Hide Login is enabled AND a
	 * slug is stored. Otherwise falls back to the native wp_login_url()
	 * so that callers (2FA redirect, email notifications, etc.) always
	 * point to a routable URL even if an admin toggled the module off
	 * without clearing the stored slug.
	 *
	 * Honours plain permalinks (no `permalink_structure`) by emitting the
	 * `?<slug>` query-string form expected by intercept_request(). Without
	 * this branch, all callers (2FA redirect, admin emails) point to a
	 * non-routable `/slug/` URL that produces a 404 on plain-permalinks
	 * installs. Mirrors new_login_url() so both helpers stay consistent.
	 */
	public static function get_login_url(): string {
		$slug    = (string) get_option( self::OPTION_SLUG, '' );
		$enabled = 1 === (int) get_option( self::OPTION_ENABLED, 0 );
		if ( '' === $slug || ! $enabled ) {
			return wp_login_url();
		}
		if ( get_option( 'permalink_structure' ) ) {
			return self::build_login_url( '/' . $slug . '/' );
		}
		return self::build_login_url( '/' ) . '?' . $slug;
	}

	/**
	 * Build the base URL Hide Login uses for the rewritten slug.
	 *
	 * Host-aware: chooses between home_url() and site_url() based on the
	 * current request's HTTP_HOST. This covers simultaneously:
	 *
	 *  - Standard install (siteurl == home): both branches return the same
	 *    string, no observable difference.
	 *  - Multisite headless / WordPress-in-subdir / reverse-proxy with
	 *    WP_HOME ≠ WP_SITEURL: when the request arrives on the siteurl host
	 *    (the WP back-end hostname), build URLs on site_url so they're
	 *    routable. This is the case V2.1.9 fixed.
	 *  - Multisite + domain mapping (typical WP MU Domain Mapping setup):
	 *    when the request arrives on the home_url host (the mapped external
	 *    domain), build URLs on home_url. site_url here points to the
	 *    original network path which is NOT how the user accesses the site.
	 *    This is the case V2.1.11 fixes (V2.1.9 regression).
	 *  - CLI / cron / email rendering (no HTTP_HOST): fallback to home_url
	 *    so admin emails carry the public-facing URL the admin recognises.
	 *
	 * Filterable via `login_armor_login_url_base` for any other scenario
	 * (third hostname behind a reverse-proxy, subdomain mapping plugin
	 * rewriting the admin URL, etc.).
	 *
	 * @since 2.1.9
	 * @since 2.1.11 Default base is host-aware (home_url or site_url) instead
	 *               of always site_url, fixing the V2.1.9 regression on
	 *               multisite + domain mapping setups.
	 *
	 * @param string      $path   Path appended to the base URL.
	 * @param string|null $scheme URL scheme ('http', 'https', 'login', 'relative', null).
	 * @return string
	 */
	public static function build_login_url( string $path = '', ?string $scheme = null ): string {
		$slug = (string) get_option( self::OPTION_SLUG, '' );

		$home_host = strtolower( (string) wp_parse_url( home_url(), PHP_URL_HOST ) );
		$site_host = strtolower( (string) wp_parse_url( site_url(), PHP_URL_HOST ) );

		$request_host = '';
		if ( isset( $_SERVER['HTTP_HOST'] ) ) {
			// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Sanitised on next line.
			$raw_host     = sanitize_text_field( wp_unslash( $_SERVER['HTTP_HOST'] ) );
			$request_host = strtolower( strtok( $raw_host, ':' ) ); // strip port if any
		}

		if ( '' !== $request_host && $request_host === $home_host ) {
			$url = home_url( $path, $scheme );
		} elseif ( '' !== $request_host && $request_host === $site_host ) {
			$url = site_url( $path, $scheme );
		} else {
			// No request OR request host matches neither (proxy without
			// X-Forwarded-Host rewrite, CLI, cron), fallback to home_url:
			// it covers the V2.1.8 baseline (multisite domain mapping
			// included) and is what the admin recognises in emails.
			$url = home_url( $path, $scheme );
		}

		/**
		 * Filter the base URL Hide Login uses to build the rewritten login URL.
		 *
		 * @since 2.1.9
		 * @since 2.1.11 Default base is now host-aware (home_url or site_url
		 *               depending on HTTP_HOST), no longer always site_url.
		 *
		 * @param string      $url    Base URL (default: host-aware home_url or site_url).
		 * @param string      $path   Requested path.
		 * @param string|null $scheme URL scheme.
		 * @param string      $slug   Current Hide Login slug.
		 */
		return (string) apply_filters( 'login_armor_login_url_base', $url, $path, $scheme, $slug );
	}

	/**
	 * Return the four recovery methods.
	 *
	 * Body is a short one-line description. Code (optional) is the exact
	 * command or SQL snippet to run: rendered on its own line in the UI
	 * so each method reads as "title / desc / code" instead of a prose
	 * paragraph with the command buried inside.
	 *
	 * @return array<int, array{title: string, body: string, code: string}>
	 */
	public static function get_recovery_instructions(): array {
		global $wpdb;
		$prefix = $wpdb ? $wpdb->prefix : 'wp_';

		return array(
			// 2.8.0: both methods READ the slug. Until 2.7.10 they deleted it,
			// and the module answered a deleted slug by generating a new random
			// one that nobody was told about: the reader stayed locked out. A
			// deleted slug now switches Hide Login off instead (see the
			// constructor), so the old instructions still lead back in, but
			// reading what is stored is the gentler way and changes nothing.
			array(
				'title' => __( 'Method 1: WP-CLI (recommended)', 'login-armor' ),
				'body'  => __( 'Run from your server shell. It prints your login URL and changes nothing.', 'login-armor' ),
				'code'  => 'wp login-armor status',
			),
			array(
				'title' => __( 'Method 2: Database (phpMyAdmin, Adminer)', 'login-armor' ),
				'body'  => sprintf(
					/* translators: %s: database table prefix. */
					__( 'Run this SQL query to read your slug. Your login URL is your site address followed by /slug/, or by /?slug when your permalinks are set to Plain. Replace %s with your own prefix if different.', 'login-armor' ),
					$prefix
				),
				'code'  => sprintf(
					"SELECT option_value FROM %soptions WHERE option_name = 'login_armor_hide_slug';",
					$prefix
				),
			),
			array(
				'title' => __( 'Method 3: FTP last resort', 'login-armor' ),
				'body'  => __( 'Rename the plugin folder via FTP. WordPress auto-deactivates on the next admin load.', 'login-armor' ),
				'code'  => '/wp-content/plugins/login-armor/ → login-armor.off',
			),
			array(
				'title' => __( 'Method 4: Safe mode', 'login-armor' ),
				'body'  => __( 'Add this line to wp-config.php. wp-login.php answers again, two-factor is not required, the firewall and the bot challenge only log. Your settings are untouched: delete the line once you are back in.', 'login-armor' ),
				'code'  => "define( 'LOGIN_ARMOR_SAFE_MODE', true );",
			),
		);
	}

	/**
	 * Send the recovery email to the site administrator.
	 *
	 * @param string $context 'reminder' or 'regenerated'.
	 */
	public static function send_recovery_email( string $context = 'reminder' ): bool {
		$to   = (string) get_option( 'admin_email', '' );
		$site = (string) get_bloginfo( 'name' );
		$url  = self::get_login_url();

		$subject = 'regenerated' === $context
			/* translators: %s: site name. */
			? sprintf( __( '[%s] LoginArmor: your login URL was regenerated', 'login-armor' ), $site )
			/* translators: %s: site name. */
			: sprintf( __( '[%s] LoginArmor: your login URL', 'login-armor' ), $site );

		$lines   = array();
		$lines[] = 'regenerated' === $context
			? __( 'Your LoginArmor login URL was just regenerated.', 'login-armor' )
			: __( 'Here is your current LoginArmor login URL.', 'login-armor' );
		$lines[] = '';
		$lines[] = __( 'Login URL:', 'login-armor' );
		$lines[] = $url;
		$lines[] = '';
		$lines[] = __( 'Bookmark this URL now. If you lose it, use one of these recovery methods:', 'login-armor' );
		$lines[] = '';
		foreach ( self::get_recovery_instructions() as $method ) {
			$lines[] = $method['title'];
			$lines[] = $method['body'];
			if ( ! empty( $method['code'] ) ) {
				$lines[] = '    ' . $method['code'];
			}
			$lines[] = '';
		}
		$lines[] = __( '-- LoginArmor', 'login-armor' );

		return (bool) wp_mail( $to, $subject, implode( "\n", $lines ) );
	}

	/**
	 * Check if the Hide Login module is currently enabled.
	 */
	public static function is_enabled(): bool {
		return 1 === (int) get_option( self::OPTION_ENABLED, 0 );
	}

	/**
	 * The active plugin whose only job is hiding the login page, if any (2.10.0).
	 *
	 * Unlike get_conflicting_plugin(), which also lists security suites whose
	 * hidden login is optional (Wordfence, Solid Security...), these always
	 * take wp-login.php over. Read from the active plugin lists themselves, so
	 * the front end never loads wp-admin/includes/plugin.php.
	 *
	 * @return string|false Plugin name, or false.
	 */
	public static function get_exclusive_conflict() {
		$known = apply_filters(
			'login_armor_exclusive_hide_login_plugins',
			array(
				'wps-hide-login/wps-hide-login.php'   => 'WPS Hide Login',
				'rename-wp-login/rename-wp-login.php' => 'Rename wp-login.php',
			)
		);
		if ( ! is_array( $known ) || array() === $known ) {
			return false;
		}

		$active = get_option( 'active_plugins', array() );
		$active = is_array( $active ) ? $active : array();
		if ( is_multisite() ) {
			$network = get_site_option( 'active_sitewide_plugins', array() );
			$active  = array_merge( $active, is_array( $network ) ? array_keys( $network ) : array() );
		}

		foreach ( $known as $plugin_path => $plugin_name ) {
			if ( in_array( (string) $plugin_path, $active, true ) ) {
				return (string) $plugin_name;
			}
		}
		return false;
	}

	/**
	 * Whether Hide Login is switched on but standing down beside an exclusive plugin (2.10.0).
	 */
	public static function is_suspended(): bool {
		return self::is_enabled() && false !== self::get_exclusive_conflict();
	}

	/**
	 * Whether Login Armor really serves the hidden login address right now (2.10.0).
	 *
	 * is_enabled() is the setting; this is what the site does. Anything that
	 * builds a URL or a cookie path on the slug asks this one.
	 */
	public static function is_active(): bool {
		return self::is_enabled() && false === self::get_exclusive_conflict();
	}

	/**
	 * Permanent notice while Hide Login stands down (2.10.0).
	 */
	public static function render_suspended_notice(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}
		$conflict = self::get_exclusive_conflict();
		if ( false === $conflict ) {
			return;
		}
		printf(
			'<div class="notice notice-warning"><p>%s</p></div>',
			esc_html(
				sprintf(
					/* translators: 1: plugin name, 2: same plugin name. */
					__( 'Login Armor\'s hidden login address is suspended while %1$s is active: %1$s hides the login page instead. Deactivate %2$s to give the hidden address back to Login Armor.', 'login-armor' ),
					$conflict,
					$conflict
				)
			)
		);
	}

	/**
	 * Check if a conflicting login-rewriting / security plugin is active.
	 *
	 * Detected plugins claim ownership of `wp-login.php` and would compete
	 * with LoginArmor's Hide Login: a silent winner-takes-all situation
	 * where the admin believes their slug is hiding wp-login while another
	 * plugin still serves it on a different path. Audit S-20.
	 *
	 * The list is filterable so the community can extend coverage as new
	 * plugins ship comparable features:
	 *
	 *     add_filter( 'login_armor_conflicting_hide_login_plugins', function ( $list ) {
	 *         $list['custom-login-rewriter/plugin.php'] = 'Custom Login Rewriter';
	 *         return $list;
	 *     } );
	 *
	 * @since 2.1.1 Expanded from a single hardcoded check to 6 known plugins + filter.
	 *
	 * @return string|false The conflicting plugin name, or false.
	 */
	public static function get_conflicting_plugin() {
		if ( ! function_exists( 'is_plugin_active' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}

		$known = apply_filters(
			'login_armor_conflicting_hide_login_plugins',
			[
				'rename-wp-login/rename-wp-login.php'                 => 'Rename wp-login.php',
				'wps-hide-login/wps-hide-login.php'                   => 'WPS Hide Login',
				'defender-security/wp-defender.php'                   => 'Defender Security',
				'better-wp-security/better-wp-security.php'           => 'Solid Security (formerly iThemes)',
				'wordfence/wordfence.php'                             => 'Wordfence Security',
				'all-in-one-wp-security-and-firewall/wp-security.php' => 'All-In-One WP Security',
			]
		);

		foreach ( $known as $plugin_path => $plugin_name ) {
			if ( is_plugin_active( $plugin_path ) ) {
				return $plugin_name;
			}
		}

		return false;
	}

	/**
	 * Replace wp-login.php with the custom slug in any URL.
	 *
	 * @param string $url URL to rewrite.
	 * @return string
	 */
	private function rewrite_login_url( string $url ): string {
		if ( ! str_contains( $url, 'wp-login.php' ) ) {
			return $url;
		}
		if ( $this->postpass_passthrough ) {
			return $url;
		}
		if ( str_contains( $url, 'action=postpass' ) ) {
			return $url;
		}
		$referer = wp_get_referer();
		if ( is_string( $referer ) && str_contains( $referer, 'wp-login.php' ) ) {
			return $url;
		}

		$slug_with_slash = $this->user_trailingslashit( $this->slug );
		$rewritten       = str_replace( 'wp-login.php', $slug_with_slash, $url );

		// WP core's wp_safe_redirect()/wp_validate_redirect() resolves bare
		// relative targets (e.g. 'wp-login.php?checkemail=confirm' from the
		// lostpassword flow) against the spoofed REQUEST_URI '/<slug>/?...',
		// producing '/<slug>/wp-login.php?...'. Naive str_replace would then
		// double the slug to '/<slug>/<slug>/?...' → 404. Collapse the pattern
		// back to a single slug segment.
		if ( '' !== $this->slug && get_option( 'permalink_structure' ) ) {
			$double = '/' . $this->slug . '/' . $slug_with_slash;
			$single = '/' . $slug_with_slash;
			if ( str_contains( $rewritten, $double ) ) {
				$rewritten = str_replace( $double, $single, $rewritten );
			}
		}

		// Defensive: if a plugin called wp_redirect() directly with the bare
		// relative form (skipping wp_safe_redirect's resolver), the rewritten
		// URL stays bare-relative. Prepend '/' so the browser doesn't resolve
		// it against the current /<slug>/ base (same double-slug 404 risk).
		if ( 0 === strpos( $url, 'wp-login.php' ) ) {
			$rewritten = '/' . $rewritten;
		}

		return $rewritten;
	}

	/**
	 * Build the login URL from the already-loaded slug property.
	 */
	private function new_login_url( ?string $scheme = null ): string {
		if ( get_option( 'permalink_structure' ) ) {
			return $this->user_trailingslashit( self::build_login_url( '/', $scheme ) . $this->slug );
		}
		return self::build_login_url( '/', $scheme ) . '?' . $this->slug;
	}

	/**
	 * Serve the login page by including wp-login.php.
	 *
	 * When the custom slug is accessed through WordPress (via index.php),
	 * we manually include wp-login.php. Since wp-load.php uses require_once
	 * internally, WordPress will not be loaded twice.
	 */
	private function serve_login_page(): void {
		// Prevent caching plugins and proxies from caching the custom login page.
		$this->refuse_page_cache();

		// HTTP/2 stream-termination guard: wp-login.php uses its own exit() at
		// many points (after wp_safe_redirect, after rendering the form, etc.).
		// On LiteSpeed/LSAPI + HTTP/2, those exits without an explicit
		// fastcgi_finish_request() can leave Firefox stuck on "Loading…",
		// observed on cours-ndrc.fr. We register a shutdown function so the
		// FastCGI stream is signalled cleanly regardless of which path
		// wp-login.php takes. Same rationale as LockoutPage v2.1.2.
		register_shutdown_function(
			static function (): void {
				if ( function_exists( 'fastcgi_finish_request' ) ) {
					fastcgi_finish_request();
				}
			}
		);

		// Set pagenow so wp-login.php works correctly.
		// phpcs:ignore WordPress.WP.GlobalVariablesOverride.Prohibited
		$GLOBALS['pagenow'] = 'wp-login.php';

		// Simulate a direct request to wp-login.php for compatibility.
		$_SERVER['REQUEST_URI'] = $this->build_login_request_uri();

		// Declare globals expected by wp-login.php.
		global $error, $interim_login, $action, $user_login;

		// Include wp-login.php. WordPress is already loaded, so the require_once
		// calls inside wp-load.php / wp-config.php / wp-settings.php are no-ops.
		require_once ABSPATH . 'wp-login.php';
		exit;
	}

	/**
	 * Build the REQUEST_URI that wp-login.php expects.
	 *
	 * Crucial: we use the *slug* path, not `/wp-login.php`. wp-login.php
	 * only reads REQUEST_URI to derive `$rp_path` for the password-reset
	 * cookie scope and for `remove_query_arg()` redirect targets: both
	 * must round-trip through our slug, otherwise:
	 *
	 *   - Reset cookie scoped to `/wp-login.php` is never sent back when
	 *     the browser follows WP's post-setcookie redirect to `/<slug>/…`,
	 *     so the next request fails the cookie check and the user lands
	 *     on `?action=lostpassword&error=invalidkey` ("link expired").
	 *   - `wp_safe_redirect( remove_query_arg( [ 'key', 'login' ] ) )`
	 *     would produce a `/wp-login.php?action=rp` relative URL that
	 *     intercept_request() immediately 404s.
	 *
	 * Both failure modes block `wp-login.php?action=rp`, making admin
	 * password recovery impossible whenever Hide Login is enabled.
	 */
	private function build_login_request_uri(): string {
		if ( get_option( 'permalink_structure' ) ) {
			$path = $this->user_trailingslashit( self::build_login_url( '/' . $this->slug, 'relative' ) );
		} else {
			// With query-string slug (?slug), the path is always /.
			$path = self::build_login_url( '/', 'relative' );
		}

		$query = isset( $_SERVER['QUERY_STRING'] )
			// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- See sanitize_query_string(): percent-encoding must survive.
			? $this->sanitize_query_string( wp_unslash( $_SERVER['QUERY_STRING'] ) )
			: '';
		if ( $query !== '' ) {
			$sep   = str_contains( $path, '?' ) ? '&' : '?';
			$path .= $sep . $query;
		}

		return $path;
	}

	/**
	 * Refuse the page cache, in the terms each cache layer actually reads.
	 *
	 * MEASURED, on the author's production LiteSpeed site, 2026-09-23. The
	 * response this module sends for `/wp-login.php` already carried
	 * `cache-control: no-cache, must-revalidate, max-age=0, no-store, private`
	 * from nocache_headers(). LiteSpeed stored it and served it back with
	 * `x-litespeed-cache: hit` for days. Standard cache headers are therefore
	 * not, on their own, an opt-out: this is why the calls below are not
	 * redundant with the one they sit next to.
	 *
	 * What that cost: `/wp-login.php` and `/wp-admin/` are decoys whose answer
	 * is a decision the administrator can change at any moment (404, or a
	 * redirect to a page of their choosing). A stored copy freezes that
	 * decision. Switching Blocked Access Redirect from 404 to a custom URL
	 * appeared to do nothing at all, because the cache kept replaying the old
	 * 404, while `/wp-admin/` (not cached) obeyed the new setting: the site
	 * contradicted itself and the setting looked broken.
	 *
	 * Two vendor mechanisms, both read from the vendors' own published source
	 * rather than assumed:
	 *
	 *  - `DONOTCACHEPAGE`, the de facto constant. LiteSpeed Cache tests it in
	 *    `Control::output()` (src/control.cls.php), W3 Total Cache in
	 *    PgCache_ContentGrabber.php, WP Super Cache in wp-cache-phase1.php,
	 *    WP Fastest Cache in inc/cache.php. WP Rocket documents overriding it,
	 *    which is only meaningful because it honours it.
	 *  - `X-LiteSpeed-Cache-Control: no-cache`, which LiteSpeed Web Server
	 *    reads in preference to `Cache-Control` (LSCache developer guide,
	 *    Basic Controls; the name is `Control::X_HEADER` in the plugin). Sent
	 *    unconditionally, because a LiteSpeed host caches at the server with
	 *    no plugin installed to ask, and that is the one case no constant can
	 *    reach. An unknown header costs nothing anywhere else.
	 *
	 * Deliberately NOT done: reading or writing any cache plugin's own
	 * exclusion list. Five products, five private formats, and a wrong "all
	 * good" is worse than the warning it would replace.
	 *
	 * @since 2.7.1
	 */
	private function refuse_page_cache(): void {
		nocache_headers();

		if ( ! defined( 'DONOTCACHEPAGE' ) ) {
			// phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedConstantFound -- Cross-vendor cache opt-out, matched by that exact name in every page cache.
			define( 'DONOTCACHEPAGE', true );
		}

		// LiteSpeed Cache's own documented switch. Registered by its API class
		// as an action, so this is a no-op without the plugin, and it puts a
		// named reason in its debug log instead of leaving an operator to
		// guess why a page stopped being cached.
		// phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- Third-party API hook, its name belongs to LiteSpeed.
		do_action( 'litespeed_control_set_nocache', 'Login Armor: hidden login endpoint' );

		if ( ! headers_sent() ) {
			header( 'X-LiteSpeed-Cache-Control: no-cache' );
		}
	}

	/**
	 * Block access by redirecting to custom URL or serving a 404 page.
	 *
	 * Routes through serve_404_template() so the response carries the
	 * proper WP_Query 404 state (`is_404()`, body class `error404`,
	 * Yoast/SEO `noindex` meta, theme conditional CSS) and renders as
	 * a clean theme 404 instead of a half-bootstrapped page with a
	 * duplicated header (the V2.1.9 and earlier behaviour, observed
	 * on Astra Pro / FSE themes when /wp-admin/ was hit by an anon).
	 */
	private function block_access(): void {
		$this->redirect_blocked_access();
		$this->serve_404_template();
	}

	/**
	 * Redirect a blocked login or admin request when the option is enabled.
	 */
	private function redirect_blocked_access(): void {
		$redirect_type = self::normalize_redirect_type(
			(string) get_option( self::OPTION_REDIRECT_TYPE, self::REDIRECT_NOT_FOUND )
		);

		if ( self::REDIRECT_URL === $redirect_type && '' !== $this->redirect_url ) {
			// Until 2.7.1 this branch sent no cache headers at all, while the
			// 404 branch did. A stored 302 is the same failure as a stored
			// 404 and lasts just as long: it keeps sending visitors to a
			// destination the administrator has since changed.
			$this->refuse_page_cache();
			if ( wp_safe_redirect( $this->redirect_url, 302 ) ) {
				exit;
			}
		}
	}

	/**
	 * Render a WordPress 404 page and terminate the request.
	 *
	 * wp-login.php bootstraps itself via wp-load.php, while wp-admin enters
	 * through the admin bootstrap. Neither path reaches the normal front-end
	 * template loader after this wp_loaded callback, so the front query and
	 * template hooks must run explicitly before the response is terminated.
	 *
	 * The standard 404 hierarchy and template_include filter are used without
	 * directly requiring WordPress's core template loader.
	 */
	private function serve_404_template(): void {
		global $pagenow, $wp_query;

		$_SERVER['REQUEST_URI'] = $this->user_trailingslashit( '/' . str_repeat( '-/', 10 ) );
		$pagenow               = 'index.php'; // phpcs:ignore WordPress.WP.GlobalVariablesOverride.Prohibited

		if ( ! defined( 'WP_USE_THEMES' ) ) {
			// phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedConstantFound -- WordPress core constant required for theme rendering.
			define( 'WP_USE_THEMES', true );
		}

		/*
		 * WP_ADMIN cannot be undefined, but WordPress gives the current screen
		 * precedence in is_admin(). A front screen lets theme, toolbar, and asset
		 * logic behave as it would through index.php.
		 */
		$this->set_front_screen();

		wp();
		if ( $wp_query instanceof \WP_Query ) {
			$wp_query->set_404();
		}
		status_header( 404 );
		$this->refuse_page_cache();

		if ( defined( 'WP_ADMIN' ) && WP_ADMIN ) {
			/*
			 * Core registered the combined asset set while this was still an admin
			 * request during init. Enqueue that public fallback explicitly so all
			 * block styles used by the FSE 404 template are available.
			 */
			wp_enqueue_style( 'wp-block-library' );
		}
		show_admin_bar( false );

		if ( wp_using_themes() ) {
			/*
			 * This request is intentionally a 404. Core must not guess a canonical
			 * destination for the synthetic URI and redirect it to an existing page.
			 */
			remove_action( 'template_redirect', 'redirect_canonical' );
			do_action( 'template_redirect' ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- This invokes the WordPress core front-end lifecycle hook.
		}

		$template = get_404_template();
		$body     = '';
		if ( $template ) {
			$template = apply_filters( 'template_include', $template ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- This invokes the WordPress core template-selection filter.
		}
		if ( is_string( $template ) && is_file( $template ) && is_readable( $template ) ) {
			ob_start();
			include $template;
			$body = (string) ob_get_clean();
		}

		\LoginArmor\LoginArmor::flush_response_and_exit( $body );
	}

	/**
	 * Switch WordPress conditionals to a public screen for theme rendering.
	 */
	private function set_front_screen(): void {
		if ( ! function_exists( 'set_current_screen' ) ) {
			require_once ABSPATH . 'wp-admin/includes/class-wp-screen.php';
			require_once ABSPATH . 'wp-admin/includes/screen.php';
		}
		set_current_screen( 'front' );
	}
}
