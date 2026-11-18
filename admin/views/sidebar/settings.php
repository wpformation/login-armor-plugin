<?php
/**
 * Sidebar content for the Settings tab.
 *
 * Each section is a native <details>/<summary> accordion: zero JS, keyboard
 * accessible, state held in the DOM for the lifetime of the page. Closed by
 * default so the sidebar stays scannable even with ~10 modules.
 *
 * @package LoginArmor
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}
?>
<h3 class="la-sidebar__title"><?php esc_html_e( 'Settings Guide', 'login-armor' ); ?></h3>

<details class="la-sidebar__section">
	<summary class="la-sidebar__section-title"><?php esc_html_e( 'Hide Login', 'login-armor' ); ?></summary>
	<p class="la-sidebar__text"><?php esc_html_e( 'Replaces wp-login.php with a custom secret URL. Anyone visiting the old URL gets a 404.', 'login-armor' ); ?></p>
</details>

<details class="la-sidebar__section">
	<summary class="la-sidebar__section-title"><?php esc_html_e( 'Hardening', 'login-armor' ); ?></summary>
	<p class="la-sidebar__text"><?php esc_html_e( 'One-click security toggles. Each toggle hardens a specific attack surface. Per-category counts show how many toggles are enabled in each group.', 'login-armor' ); ?></p>
</details>

<details class="la-sidebar__section">
	<summary class="la-sidebar__section-title"><?php esc_html_e( 'Headless back end', 'login-armor' ); ?></summary>
	<p class="la-sidebar__text"><?php esc_html_e( 'For a WordPress that serves its REST API to a separate front end. Headless mode keeps two toggles off, Restrict REST API and Disable application passwords, because either one breaks the front end or the scripts that write to it.', 'login-armor' ); ?></p>
	<p class="la-sidebar__text"><?php esc_html_e( 'The request firewall does not inspect REST requests: brute-force protection, two-factor authentication and application-password monitoring cover the API instead.', 'login-armor' ); ?></p>
</details>

<details class="la-sidebar__section">
	<summary class="la-sidebar__section-title"><?php esc_html_e( 'Brute Force', 'login-armor' ); ?></summary>
	<ul class="la-sidebar__list">
		<li><strong><?php esc_html_e( 'Lockout duration', 'login-armor' ); ?></strong>: <?php esc_html_e( 'how long an IP is locked. Default: 20 min.', 'login-armor' ); ?></li>
		<li><strong><?php esc_html_e( 'Reset period', 'login-armor' ); ?></strong>: <?php esc_html_e( 'failures forgotten after this time. Default: 24h.', 'login-armor' ); ?></li>
		<li><strong><?php esc_html_e( 'Max lockouts', 'login-armor' ); ?></strong>: <?php esc_html_e( 'triggers a long ban. Default: 4.', 'login-armor' ); ?></li>
		<li><strong><?php esc_html_e( 'Long ban', 'login-armor' ); ?></strong>: <?php esc_html_e( 'extended ban for repeat offenders. Default: 24h.', 'login-armor' ); ?></li>
		<li><strong><?php esc_html_e( 'IP safelist', 'login-armor' ); ?></strong>: <?php esc_html_e( 'IPs never locked out. Add yours.', 'login-armor' ); ?></li>
	</ul>
</details>

<details class="la-sidebar__section">
	<summary class="la-sidebar__section-title"><?php esc_html_e( 'Detection & Logs', 'login-armor' ); ?></summary>
	<ul class="la-sidebar__list">
		<li><strong><?php esc_html_e( 'Log retention', 'login-armor' ); ?></strong>: <?php esc_html_e( 'how long logs are kept.', 'login-armor' ); ?></li>
		<li><strong><?php esc_html_e( 'Auto-purge', 'login-armor' ); ?></strong>: <?php esc_html_e( 'auto-deletes old logs daily.', 'login-armor' ); ?></li>
	</ul>
</details>

<details class="la-sidebar__section">
	<summary class="la-sidebar__section-title"><?php esc_html_e( 'Activity Log', 'login-armor' ); ?></summary>
	<p class="la-sidebar__text"><?php esc_html_e( 'Tracks admin actions (post edits, plugin changes, user modifications) to detect compromised accounts. Opt-in: zero overhead when disabled.', 'login-armor' ); ?></p>
</details>

<details class="la-sidebar__section">
	<summary class="la-sidebar__section-title"><?php esc_html_e( 'Two-Factor Authentication', 'login-armor' ); ?></summary>
	<ul class="la-sidebar__list">
		<li><strong><?php esc_html_e( 'Authenticator App', 'login-armor' ); ?></strong>: <?php esc_html_e( 'works with Google Authenticator, Authy, 1Password, Bitwarden. Most secure option.', 'login-armor' ); ?></li>
		<li><strong><?php esc_html_e( 'Email code', 'login-armor' ); ?></strong>: <?php esc_html_e( '6-digit code sent to user email. Good fallback but depends on email delivery.', 'login-armor' ); ?></li>
		<li><strong><?php esc_html_e( 'Backup codes', 'login-armor' ); ?></strong>: <?php esc_html_e( 'single-use recovery codes. Always enabled alongside the primary method.', 'login-armor' ); ?></li>
		<li><strong><?php esc_html_e( 'Enforcement', 'login-armor' ); ?></strong>: <?php esc_html_e( 'require 2FA for specific roles. Users get a grace period to set up.', 'login-armor' ); ?></li>
		<li><strong><?php esc_html_e( 'Setup', 'login-armor' ); ?></strong>: <?php esc_html_e( 'each user sets up 2FA in their Profile page.', 'login-armor' ); ?></li>
		<li><strong><?php esc_html_e( 'Recovery', 'login-armor' ); ?></strong>: <?php esc_html_e( 'use a backup code, or ask an admin to reset your 2FA via WP-CLI.', 'login-armor' ); ?></li>
	</ul>
</details>

<details class="la-sidebar__section">
	<summary class="la-sidebar__section-title"><?php esc_html_e( 'Login Page Headers', 'login-armor' ); ?></summary>
	<ul class="la-sidebar__list">
		<li><strong><?php esc_html_e( 'Standard', 'login-armor' ); ?></strong>: <?php esc_html_e( 'safe defaults. Blocks clickjacking and credential exfiltration without breaking WP login.', 'login-armor' ); ?></li>
		<li><strong><?php esc_html_e( 'Strict', 'login-armor' ); ?></strong>: <?php esc_html_e( 'full CSP lockdown. Test if you use custom login themes or third-party login plugins.', 'login-armor' ); ?></li>
		<li><strong><?php esc_html_e( 'Scope', 'login-armor' ); ?></strong>: <?php esc_html_e( 'headers are applied only on the login page, never on the front-end or WP admin.', 'login-armor' ); ?></li>
	</ul>
</details>

<details class="la-sidebar__section">
	<summary class="la-sidebar__section-title"><?php esc_html_e( 'Breach Check', 'login-armor' ); ?></summary>
	<ul class="la-sidebar__list">
		<li><strong><?php esc_html_e( 'What', 'login-armor' ); ?></strong>: <?php esc_html_e( 'detects if a user password or email address appears in publicly disclosed data breaches.', 'login-armor' ); ?></li>
		<li><strong><?php esc_html_e( 'Privacy', 'login-armor' ); ?></strong>: <?php esc_html_e( 'the password itself never leaves your server. Only the first 5 characters of a SHA-1 hash are sent to the public Have I Been Pwned API (k-anonymity lookup); your server compares the rest locally.', 'login-armor' ); ?></li>
		<li><strong><?php esc_html_e( 'Effect', 'login-armor' ); ?></strong>: <?php esc_html_e( 'flagged users get a friendly notice on their profile page. No one is locked out unless you turn on "force password reset".', 'login-armor' ); ?></li>
		<li><strong><?php esc_html_e( 'Cost', 'login-armor' ); ?></strong>: <?php esc_html_e( 'free. No API key, no account. Cached 24 h per password prefix so the API is not hit on every login.', 'login-armor' ); ?></li>
	</ul>
</details>

<details class="la-sidebar__section">
	<summary class="la-sidebar__section-title"><?php esc_html_e( 'Password Policy', 'login-armor' ); ?></summary>
	<ul class="la-sidebar__list">
		<li><strong><?php esc_html_e( 'Minimum length', 'login-armor' ); ?></strong>: <?php esc_html_e( 'enforce a minimum character count on new and changed passwords.', 'login-armor' ); ?></li>
		<li><strong><?php esc_html_e( 'Complexity', 'login-armor' ); ?></strong>: <?php esc_html_e( 'require lower/upper case, a number, and optionally a symbol.', 'login-armor' ); ?></li>
		<li><strong><?php esc_html_e( 'Block compromised', 'login-armor' ); ?></strong>: <?php esc_html_e( 'reject passwords found in public breaches. The password never leaves your server (Have I Been Pwned k-anonymity).', 'login-armor' ); ?></li>
		<li><strong><?php esc_html_e( 'Expiration', 'login-armor' ); ?></strong>: <?php esc_html_e( 'optionally force a reset after N days. 0 = never expires.', 'login-armor' ); ?></li>
		<li><strong><?php esc_html_e( 'Scope', 'login-armor' ); ?></strong>: <?php esc_html_e( 'applies at registration, profile update and password reset. Fails soft if the breach API is unreachable.', 'login-armor' ); ?></li>
	</ul>
</details>

<details class="la-sidebar__section">
	<summary class="la-sidebar__section-title"><?php esc_html_e( 'Session Management', 'login-armor' ); ?></summary>
	<ul class="la-sidebar__list">
		<li><strong><?php esc_html_e( 'Idle timeout', 'login-armor' ); ?></strong>: <?php esc_html_e( 'sign out accounts after a period of inactivity. 0 = off.', 'login-armor' ); ?></li>
		<li><strong><?php esc_html_e( 'Max lifetime', 'login-armor' ); ?></strong>: <?php esc_html_e( 'cap how long a session stays valid regardless of activity.', 'login-armor' ); ?></li>
		<li><strong><?php esc_html_e( 'Single session', 'login-armor' ); ?></strong>: <?php esc_html_e( 'one active device per account; logging in elsewhere ends the older session.', 'login-armor' ); ?></li>
		<li><strong><?php esc_html_e( 'Sign out others', 'login-armor' ); ?></strong>: <?php esc_html_e( 'end every other session for your own account from your profile.', 'login-armor' ); ?></li>
	</ul>
</details>

<details class="la-sidebar__section">
	<summary class="la-sidebar__section-title"><?php esc_html_e( 'IP Geolocation', 'login-armor' ); ?></summary>
	<p class="la-sidebar__text"><?php esc_html_e( 'Shows the country of origin next to IP addresses in Incidents and Events. Lookups use the keyless ipwho.is service, are cached, and never affect the security score. Purely informational.', 'login-armor' ); ?></p>
</details>

<details class="la-sidebar__section">
	<summary class="la-sidebar__section-title"><?php esc_html_e( 'Request Firewall', 'login-armor' ); ?></summary>
	<ul class="la-sidebar__list">
		<li><strong><?php esc_html_e( 'Monitor', 'login-armor' ); ?></strong>: <?php esc_html_e( 'logs would-be blocks as incidents without blocking. Always start here.', 'login-armor' ); ?></li>
		<li><strong><?php esc_html_e( 'Enforce', 'login-armor' ); ?></strong>: <?php esc_html_e( 'actually blocks matching requests with a 403. Switch once the monitor log looks clean.', 'login-armor' ); ?></li>
		<li><strong><?php esc_html_e( 'Conservative rules', 'login-armor' ); ?></strong>: <?php esc_html_e( 'bad query strings, paths and HTTP methods. Very low false-positive risk; on by default.', 'login-armor' ); ?></li>
		<li><strong><?php esc_html_e( 'Aggressive rules', 'login-armor' ); ?></strong>: <?php esc_html_e( 'user-agent and referrer filtering, XML-RPC and author probes. Higher false-positive risk; opt-in.', 'login-armor' ); ?></li>
		<li><strong><?php esc_html_e( 'Allowlist', 'login-armor' ); ?></strong>: <?php esc_html_e( 'IPs (incl. CIDR) and paths never inspected. Logged-in administrators are always exempt.', 'login-armor' ); ?></li>
	</ul>
</details>

<details class="la-sidebar__section">
	<summary class="la-sidebar__section-title"><?php esc_html_e( 'Bot Challenge', 'login-armor' ); ?></summary>
	<ul class="la-sidebar__list">
		<li><strong><?php esc_html_e( 'Proof-of-work', 'login-armor' ); ?></strong>: <?php esc_html_e( 'the browser silently solves a small cryptographic puzzle before the login form is accepted. An invisible CAPTCHA with no external service.', 'login-armor' ); ?></li>
		<li><strong><?php esc_html_e( 'Monitor', 'login-armor' ); ?></strong>: <?php esc_html_e( 'counts submissions without a valid proof without blocking. Always start here.', 'login-armor' ); ?></li>
		<li><strong><?php esc_html_e( 'Enforce', 'login-armor' ); ?></strong>: <?php esc_html_e( 'rejects logins without a valid proof, even with correct credentials. Requires JavaScript on the login page.', 'login-armor' ); ?></li>
		<li><strong><?php esc_html_e( 'Difficulty', 'login-armor' ); ?></strong>: <?php esc_html_e( 'how much CPU each attempt costs the sender. Standard suits almost every site.', 'login-armor' ); ?></li>
	</ul>
</details>

<details class="la-sidebar__section">
	<summary class="la-sidebar__section-title"><?php esc_html_e( 'Notifications', 'login-armor' ); ?></summary>
	<p class="la-sidebar__text"><?php esc_html_e( 'Get alerted via Slack, Discord, or a custom webhook when attacks reach a threshold. Use the Test button to verify your URL.', 'login-armor' ); ?></p>
</details>

<details class="la-sidebar__section">
	<summary class="la-sidebar__section-title"><?php esc_html_e( 'AI Assistant', 'login-armor' ); ?></summary>
	<p class="la-sidebar__text"><?php esc_html_e( 'Optional analysis layer on the WordPress 7 native AI client. Explains incidents in plain language and advises on hardening. Minimized by default: only deterministic, local facts are shared and no API key is stored. Needs a WordPress 7 AI connector to activate.', 'login-armor' ); ?></p>
</details>

<details class="la-sidebar__section">
	<summary class="la-sidebar__section-title"><?php esc_html_e( 'Export / Import', 'login-armor' ); ?></summary>
	<p class="la-sidebar__text"><?php esc_html_e( 'Copy your setup to other sites: export a JSON file here, import it there with a preview first. Webhook URLs travel only if you tick the box; the signing secret and users’ two-factor enrolments never do. The same file works with WP-CLI: wp login-armor settings import file.json --dry-run.', 'login-armor' ); ?></p>
</details>
