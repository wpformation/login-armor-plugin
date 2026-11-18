<?php
/**
 * Branded lockout landing page.
 *
 * Renders a self-contained HTML document when a locked IP attempts to
 * reach the login URL (wp-login.php or the Hide Login slug). Two
 * variants: Niveau 1 with countdown, Niveau 2 blacklist message.
 *
 * @package LoginArmor
 * @since   2.0.9
 */

namespace LoginArmor\Lockout;

use LoginArmor\HideLogin;
use LoginArmor\LimitLogin;
use LoginArmor\LoginArmor;

// Exit if accessed directly.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Full-page takeover for locked IPs on the login URL.
 */
class LockoutPage {

	/**
	 * Constructor. Registers the interception hook.
	 */
	public function __construct() {
		add_action( 'plugins_loaded', [ $this, 'maybe_intercept' ], 9998 );
		// 2.10.0 (issue #23): last on both hooks. The page ends the request, so
		// whatever subscribes after it never runs: the triggering attempt was
		// missing from the log and the detection never saw the lockout.
		add_action( 'login_armor_lockout_triggered', [ $this, 'render_on_trigger' ], PHP_INT_MAX, 1 );
		add_action( 'wp_login_failed', [ $this, 'finish_on_login_failed' ], PHP_INT_MAX, 2 );
	}

	/**
	 * The lockout page owed to this request, once wp_login_failed is over.
	 *
	 * @var array{ip:string,target:string,level:int}|null
	 */
	private static ?array $pending = null;

	/**
	 * Show the user the branded lockout page on the very request that
	 * crossed the threshold, instead of waiting for them to submit the
	 * form a second time.
	 *
	 * Hooked to `login_armor_lockout_triggered`, fired by trigger_lockout()
	 * AFTER the lockout marker has been committed to the database.
	 *
	 * **Why we 302-redirect instead of rendering inline.** `wp_login_failed`
	 * fires deep inside `wp_authenticate` inside `wp_signon` inside
	 * wp-login.php. Calling `render() + exit` inline at this point
	 * triggers a server-side hang under HTTP/2 on LiteSpeed (LSAPI /
	 * o2switch PowerBoost): the response body sits on the wire complete
	 * but LSAPI never flags END_STREAM until the PHP worker actually
	 * terminates, which can take 30+ seconds because of WordPress shutdown
	 * subscribers and PHP shutdown_function callbacks. Verified on
	 * cours-ndrc.fr 2026-04-28: under HTTP/1.1 (curl) the inline render
	 * returned in 0.4s; under HTTP/2 (Firefox 150, Chromium, httpx)
	 * the same response timed out at 30/120s. By contrast, the
	 * `maybe_intercept` path that fires from `plugins_loaded` (a much
	 * shallower stack) renders the same body cleanly under HTTP/2 in
	 * ~0.5s end-to-end.
	 *
	 * The 302 redirect to the Hide Login slug is a tiny response
	 * (~250 bytes, no DB work after the marker insert), terminates the
	 * HTTP/2 stream cleanly, and the browser's automatic follow-up
	 * GET to `/[slug]/` immediately hits `maybe_intercept`, sees the
	 * fresh lockout marker, and renders the branded page in the
	 * shallow stack where HTTP/2 termination works. From the user's
	 * perspective the brandée page appears at attempt #N as intended,
	 * with no perceptible delay vs. the inline render.
	 *
	 * Skips CLI/cron contexts (no HTTP surface) and falls through to
	 * inline render if no slug is configured (Hide Login disabled:
	 * the request is on /wp-login.php directly, where the redirect
	 * loop would be wrong).
	 *
	 * @param string $ip The IP that was just locked out.
	 */
	public function render_on_trigger( string $ip ): void {
		if ( ( defined( 'WP_CLI' ) && \WP_CLI ) || wp_doing_cron() ) {
			return;
		}

		// 2.8.0: only the login FORM is taken over. `wp_login_failed` also
		// fires for XML-RPC, for the REST API and for any third-party form that
		// calls wp_signon(), and this method used to answer all of them with a
		// 302 to the Hide Login slug: whoever was hammering xmlrpc.php got the
		// hidden login URL in the Location header of the response that locked
		// them out. Those channels keep their own failure response; the lockout
		// itself is already committed, and enforced on their next attempt.
		if ( ! self::is_login_form_request() ) {
			return;
		}

		$slug = (string) get_option( 'login_armor_hide_slug', '' );

		// The slug is only named when the request came through it. Hide Login
		// switched off, or safe mode serving the real wp-login.php: the
		// visitor is on wp-login.php, and redirecting them to the slug would
		// publish it. They get the page inline instead, as a site without
		// Hide Login always did.
		if ( ! HideLogin::is_active() || self::is_wp_login_script() ) {
			$slug = '';
		}

		if ( '' === $slug ) {
			// Hide Login disabled: render inline. This path doesn't have
			// the LSAPI HTTP/2 hang because the lockout-trigger request
			// would have come in on /wp-login.php directly, and on that
			// URL the maybe_intercept handler at plugins_loaded prio 9998
			// will catch the very next request anyway.
			$level = LimitLogin::get_lockout_level( $ip );
			if ( 0 === $level ) {
				$level = 1;
			}
			if ( $this->defer( $ip, '', $level ) ) {
				return;
			}
			$this->render( $level, $ip );
			exit;
		}

		// Fast 302 redirect to the slug. The follow-up GET hits
		// maybe_intercept, which renders the branded page in the shallow
		// `plugins_loaded` stack where HTTP/2 termination works.
		//
		// Cache-buster query argument is required: many managed hosts
		// front the WordPress login slug with a public page cache
		// (LiteSpeed Cache, WP Rocket, Cloudflare full-page cache,
		// hosting-level reverse-proxy cache). Without a unique query
		// string, the redirected GET would hit the cached login form
		// instead of running PHP: `maybe_intercept` would never fire
		// and the user would see the form again instead of the branded
		// page. Confirmed live on cours-ndrc.fr 2026-04-28: GET /[slug]/
		// returned a cached form in 0.1s, GET /[slug]/?_la_locked=1
		// (cache-buster) hit PHP, maybe_intercept rendered the branded
		// page in 2s.
		$target = add_query_arg(
			'_la_locked',
			(string) time(),
			HideLogin::build_login_url( '/' . trim( $slug, '/' ) . '/' )
		);
		if ( $this->defer( $ip, $target, 0 ) ) {
			return;
		}
		nocache_headers();
		wp_safe_redirect( $target, 302 );
		exit;
	}

	/**
	 * Keep the page for the end of wp_login_failed when the lockout fired inside it.
	 *
	 * The form path always does: LimitLogin::record_failed_attempt() runs on
	 * wp_login_failed and triggers the lockout from there. Ending the request
	 * at that point cut off every later wp_login_failed subscriber, including
	 * LoginLogs::log_failure(), which records the very attempt that locked the
	 * address (2.10.0, issue #23).
	 *
	 * @param string $ip     Locked address.
	 * @param string $target Redirect target, or '' to render inline.
	 * @param int    $level  Lockout level for the inline page.
	 * @return bool True when the page was deferred.
	 */
	private function defer( string $ip, string $target, int $level ): bool {
		if ( ! doing_action( 'wp_login_failed' ) ) {
			return false;
		}
		self::$pending = array(
			'ip'     => $ip,
			'target' => $target,
			'level'  => $level,
		);
		return true;
	}

	/**
	 * Serve the lockout page once every other wp_login_failed subscriber has run.
	 *
	 * Untyped with defaults, like every callback on a core hook.
	 *
	 * @since 2.10.0
	 *
	 * @param mixed $username Login attempted (unused).
	 * @param mixed $error    Failure (unused).
	 */
	public function finish_on_login_failed( $username = '', $error = null ): void {
		unset( $username, $error );
		if ( null === self::$pending ) {
			return;
		}
		$pending       = self::$pending;
		self::$pending = null;

		if ( '' === $pending['target'] ) {
			$this->render( $pending['level'], $pending['ip'] );
			exit;
		}
		nocache_headers();
		wp_safe_redirect( $pending['target'], 302 );
		exit;
	}

	/**
	 * Whether this request is a visit to the login form (2.8.0).
	 *
	 * `$pagenow` is 'wp-login.php' for the real script and for the Hide Login
	 * slug, which sets it at plugins_loaded. XML-RPC, the REST API and
	 * admin-ajax.php are excluded by their own markers, so is a third-party
	 * form, whose `$pagenow` is whatever page carries it.
	 */
	public static function is_login_form_request(): bool {
		if ( ( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST ) || ( defined( 'REST_REQUEST' ) && REST_REQUEST ) || wp_doing_ajax() ) {
			return false;
		}

		return 'wp-login.php' === ( $GLOBALS['pagenow'] ?? '' );
	}

	/**
	 * Whether the running script is wp-login.php itself, not the slug (2.8.0).
	 *
	 * A slug request is served through index.php and only relabelled by Hide
	 * Login, so the script name is what tells the two apart.
	 */
	private static function is_wp_login_script(): bool {
		$script = isset( $_SERVER['SCRIPT_NAME'] ) ? (string) wp_unslash( $_SERVER['SCRIPT_NAME'] ) : ''; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Compared to a constant, never output.

		return 'wp-login.php' === strtolower( basename( $script ) );
	}

	/**
	 * Runs before Hide Login (priority 9999). If the current request
	 * targets the login URL and the IP is locked, renders the branded
	 * page and exits. Otherwise returns silently to let Hide Login and
	 * the rest of WP process the request normally.
	 */
	public function maybe_intercept(): void {
		if ( ! $this->is_login_url_request() ) {
			return;
		}

		$ip = LoginArmor::get_client_ip();

		if ( ! LimitLogin::is_locked_or_blacklisted( $ip ) ) {
			return;
		}

		$level = LimitLogin::get_lockout_level( $ip );
		if ( $level === 0 ) {
			$level = 2; // Subnet-blocked: no individual counter, render as blacklist.
		}

		$this->render( $level, $ip );
		exit;
	}

	/**
	 * True if the current request is aimed at the login URL, either
	 * via /wp-login.php or the configured Hide Login slug.
	 */
	private function is_login_url_request(): bool {
		$uri = isset( $_SERVER['REQUEST_URI'] )
			? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) )
			: '';

		// Case-insensitive: Windows IIS and Apache rewrites with the [NC]
		// flag serve /WP-LOGIN.PHP too. Matching lowercase-only lets
		// attackers bypass the branded page on those hosts.
		if ( stripos( $uri, 'wp-login.php' ) !== false ) {
			return true;
		}

		$slug = (string) get_option( 'login_armor_hide_slug', '' );
		if ( '' === $slug ) {
			return false;
		}

		$path = (string) wp_parse_url( $uri, PHP_URL_PATH );
		$path = trim( $path, '/' );
		// Case-insensitive slug match, same rationale as above.
		return 0 === strcasecmp( $path, $slug ) || 0 === strncasecmp( $path, $slug . '/', strlen( $slug ) + 1 );
	}

	/**
	 * Output the branded lockout page and NEVER return (caller must exit).
	 *
	 * @param int    $level 1 or 2.
	 * @param string $ip    IP address being served.
	 */
	private function render( int $level, string $ip ): void {
		$accent   = '#E84A2E';
		$logo_url = plugins_url( 'admin/assets/img/icon-128x128.png', LOGIN_ARMOR_FILE );

		$remaining = 0;
		if ( $level === 1 ) {
			$remaining = LimitLogin::get_remaining_lockout_seconds( $ip );
		}

		// Buffer the whole document so we can set Content-Length explicitly.
		// Without an explicit length, HTTP/2 termination under LiteSpeed/LSAPI
		// can hang the client indefinitely when we exit() mid-stream: Firefox
		// stays on "Loading…" forever, Chrome shows a network error. Observed
		// on o2switch + LiteSpeed in 2.1.1; fixed in 2.1.2. On HTTP/1.1 the
		// stream close alone is enough, so 2.1.0/2.1.1 accidentally worked
		// only for clients that had negotiated down to HTTP/1.1.
		ob_start();
		// Output a minimal, self-contained HTML doc. No theme, no wp-login.php.
		?><!doctype html>
<html lang="<?php echo esc_attr( get_locale() ); ?>">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title><?php echo $level === 2 ? esc_html__( 'IP blacklisted', 'login-armor' ) : esc_html__( 'Too many failed attempts', 'login-armor' ); ?></title>
<style>
:root { --la-accent: <?php echo esc_attr( $accent ); ?>; }
* { box-sizing: border-box; }
body {
    margin: 0; padding: 0;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
    background: #f3f4f6;
    color: #1f2937;
    display: flex; align-items: center; justify-content: center;
    min-height: 100vh;
}
.la-card {
    background: #fff;
    border-radius: 12px;
    box-shadow: 0 10px 40px rgba(0,0,0,.08);
    max-width: 440px;
    width: calc(100% - 32px);
    padding: 40px 32px;
    text-align: center;
}
.la-logo { width: 56px; height: 56px; margin: 0 auto 24px; display: block; }
.la-title { font-size: 22px; font-weight: 600; margin: 0 0 12px; color: #111827; }
.la-text { font-size: 15px; line-height: 1.55; color: #4b5563; margin: 0 0 24px; }
.la-countdown {
    display: inline-block;
    padding: 12px 20px;
    background: var(--la-accent);
    color: #fff;
    border-radius: 8px;
    font-variant-numeric: tabular-nums;
    font-size: 24px;
    font-weight: 600;
    letter-spacing: 2px;
    margin-top: 8px;
}
.la-blacklist { color: var(--la-accent); font-weight: 600; }
</style>
</head>
<body>
<main class="la-card" role="main">
    <img class="la-logo" src="<?php echo esc_url( $logo_url ); ?>" alt="Login Armor" />
    <?php if ( $level === 2 ) : ?>
        <h1 class="la-title la-blacklist"><?php esc_html_e( 'IP blacklisted', 'login-armor' ); ?></h1>
        <p class="la-text"><?php esc_html_e( 'Your IP has been blacklisted. Please contact the administrator of this site.', 'login-armor' ); ?></p>
    <?php else : ?>
        <h1 class="la-title"><?php esc_html_e( 'Too many failed attempts', 'login-armor' ); ?></h1>
        <p class="la-text"><?php esc_html_e( 'You are blocked for 20 minutes. Please come back later.', 'login-armor' ); ?></p>
        <div class="la-countdown" data-remaining="<?php echo (int) $remaining; ?>">--:--</div>
    <?php endif; ?>
</main>
<?php if ( $level === 1 ) : ?>
<script>
(function () {
    var el = document.querySelector('.la-countdown');
    if (!el) return;
    var remaining = parseInt(el.dataset.remaining, 10) || 0;
    function pad(n) { return n < 10 ? '0' + n : '' + n; }
    function tick() {
        if (remaining <= 0) { window.location.reload(); return; }
        var m = Math.floor(remaining / 60);
        var s = remaining % 60;
        el.textContent = pad(m) + ':' + pad(s);
        remaining -= 1;
    }
    tick();
    setInterval(tick, 1000);
})();
</script>
<?php endif; ?>
</body>
</html>
		<?php
		$body = (string) ob_get_clean();

		// Headers must be set BEFORE flush_response_and_exit(), which discards
		// parent ob buffers and writes body straight to the SAPI. status_header
		// stays in PHP's internal state until the first byte of body output, so
		// it is correctly applied even after ob_end_clean.
		nocache_headers();
		header( 'Cache-Control: no-store, private, max-age=0' );
		header( 'X-Robots-Tag: noindex, nofollow', true );
		// The branded page carries no interactive CTA, but deny framing anyway
		// for consistency with the rest of the login surface (class-login-headers.php).
		header( 'X-Frame-Options: DENY' );
		status_header( $level >= 2 ? 403 : 429 );

		// Hand off to the shared helper. It discards parent buffers (essential
		// when render() is called from inside wp_login_failed: see helper's
		// docblock), adds Content-Length, echoes the body, finishes the FastCGI
		// request, and exits.
		LoginArmor::flush_response_and_exit( $body );
	}
}
