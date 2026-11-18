<?php
/**
 * Request Firewall rule tables.
 *
 * Pattern families inspired by the Perishable Press "nG" firewall
 * (6G / 7G / 8G) by Jeff Starr, https://perishablepress.com/8g-firewall/.
 * This is NOT a verbatim copy of the .htaccess ruleset: the Apache mod_rewrite
 * regexes do not translate 1:1 to PHP/PCRE, and the patterns here have been
 * re-curated for a PHP request filter and tuned for a low false-positive rate
 * on WordPress. Credit to the original ruleset is retained as required by its
 * license.
 *
 * Each family is a list of PCRE fragments combined lazily into a single
 * case-insensitive alternation and matched once per request. Matching is
 * fail-open: a malformed combined pattern returns "no match" rather than
 * blocking, so the firewall can never hard-fail a site.
 *
 * @package LoginArmor
 * @since   2.4.0
 */

namespace LoginArmor\Firewall;

// Exit if accessed directly.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Static rule tables + the matching engine.
 */
final class RuleSet {

	/** @var int Cap the inspected value length (defends against pathological inputs / ReDoS). */
	private const MAX_LEN = 8192;

	/** @var string[] HTTP methods that are never legitimate and are always blocked. */
	public const BLOCKED_METHODS = array( 'CONNECT', 'TRACE', 'TRACK', 'DEBUG' );

	/** @var array<string,string> Compiled-regex cache, keyed by family. */
	private static array $compiled = array();

	/**
	 * Bad query-string tokens. CONSERVATIVE: these essentially never appear in
	 * a legitimate WordPress query string (SQLi, code-exec, traversal, XSS,
	 * PHP superglobal injection, file disclosure).
	 *
	 * @return string[]
	 */
	private static function query_string(): array {
		return array(
			'\.\./',
			'%2e%2e',
			'\bunion\b[\s+/*]+\bselect\b',
			'information_schema',
			'group_concat\s*\(',
			'\bbenchmark\s*\(\s*\d',
			'\bsleep\s*\(\s*\d+\s*\)',
			'base64_(de|en)code',
			'\beval\s*\(',
			'gzinflate\s*\(',
			'str_rot13',
			'\bsystem\s*\(',
			'\bpassthru\s*\(',
			'shell_exec',
			'proc_open',
			'<script',
			'%3cscript',
			'javascript:',
			'onmouseover\s*=',
			'onerror\s*=',
			'document\.cookie',
			'etc/passwd',
			'proc/self/environ',
			'globals\s*(\[|=)',
			'_(request|server)\s*(\[|%5b)',
		);
	}

	/**
	 * Bad request-path tokens. CONSERVATIVE: traversal, sensitive system
	 * files, backup/source-file extensions, null bytes, known web shells, and
	 * the phpunit eval-stdin RCE path.
	 *
	 * @return string[]
	 */
	private static function request_uri(): array {
		return array(
			'\.\./',
			'\.\.%2f',
			'%2e%2e/',
			'/etc/passwd',
			'/etc/shadow',
			'/boot\.ini',
			'proc/self/environ',
			'%00',
			'\x00',
			'\.(bak|sql|swp|swo|save|orig)(\?|$)',
			'(c99|r57|wso|b374k|webshell|backdoor)\.(php|txt|aspx?)',
			'eval-stdin\.php',
			'<script',
		);
	}

	/**
	 * Higher-FP path tokens. AGGRESSIVE / opt-in: xmlrpc, author enumeration,
	 * exposed dev/source files. These can hit legitimate surfaces (Jetpack
	 * xmlrpc, author archives), so they are off by default.
	 *
	 * @return string[]
	 */
	private static function request_uri_aggressive(): array {
		return array(
			'xmlrpc\.php',
			'[?&]author=\d',
			'/author/',
			'wp-content/.+\.(sql|bak|old|log|txt)',
			'(\.git/|\.svn/|\.env|\.htpasswd|composer\.(json|lock)|package\.json|\.ds_store)',
			'(mosconfig|envtype|allow_url_include)',
			'/(vendor|phpunit)/.+\.php',
		);
	}

	/**
	 * Bad / scanner user agents. AGGRESSIVE / opt-in: also catches generic
	 * HTTP libraries (curl, wget, python-requests, java) which legitimate
	 * server-to-server callers may use, hence opt-in.
	 *
	 * @return string[]
	 */
	private static function user_agent(): array {
		return array(
			'(sqlmap|nikto|nessus|nmap|masscan|zgrab|acunetix|netsparker|wpscan|havij|jorgee|arachni|dirbuster|gobuster|fimap|joomscan|whatweb|zmeu|morfeus|webinspect|paros|w3af|skipfish)',
			'(libwww-perl|python-requests|python-urllib|curl/|wget/|java/|go-http-client|winhttp|scrapy|mechanize)',
			'(harvest|extractorpro|emailcollector|emailsiphon|emailwolf|cherrypicker|webbandit|webcopier|webzip|teleport|siteripper)',
		);
	}

	/**
	 * Spam referrer tokens. AGGRESSIVE / opt-in and best-effort: referrers are
	 * attacker-controlled and the spam-domain list ages quickly.
	 *
	 * @return string[]
	 */
	private static function referer(): array {
		return array(
			'(semalt|kambasoft|savetubevideo|buttons-for-website|darodar|7makemoney|priceg|blackhatworth|hulfington|ilovevitaly|econom|cenoval|descargar-musica|videos-for-adults|video--production|social-buttons|simple-share-buttons|forum69|sharebutton)',
		);
	}

	/**
	 * Return the fragment list for a family, or an empty array for an unknown
	 * family.
	 *
	 * @param string $family Family key.
	 * @return string[]
	 */
	private static function fragments( string $family ): array {
		switch ( $family ) {
			case 'query_string':
				return self::query_string();
			case 'request_uri':
				return self::request_uri();
			case 'request_uri_aggressive':
				return self::request_uri_aggressive();
			case 'user_agent':
				return self::user_agent();
			case 'referer':
				return self::referer();
			default:
				return array();
		}
	}

	/**
	 * Inspect a value against a rule family. Returns the matched substring on a
	 * hit, or null. Fail-open on a regex error.
	 *
	 * @param string $family One of the regex families.
	 * @param string $value  The (already decoded) value to test.
	 */
	public static function inspect( string $family, string $value ): ?string {
		if ( '' === $value ) {
			return null;
		}
		if ( strlen( $value ) > self::MAX_LEN ) {
			$value = substr( $value, 0, self::MAX_LEN );
		}

		if ( ! isset( self::$compiled[ $family ] ) ) {
			$fragments = self::fragments( $family );
			if ( empty( $fragments ) ) {
				self::$compiled[ $family ] = '';
			} else {
				// '#' delimiter avoids escaping the many '/' in the fragments.
				self::$compiled[ $family ] = '#(' . implode( '|', $fragments ) . ')#i';
			}
		}

		$pattern = self::$compiled[ $family ];
		if ( '' === $pattern ) {
			return null;
		}

		$matches = array();
		$result  = preg_match( $pattern, $value, $matches );
		if ( 1 !== $result ) {
			// 0 = no match, false = regex error (fail-open).
			return null;
		}
		return substr( (string) $matches[0], 0, 100 );
	}

	/**
	 * Check an HTTP method. Returns the method string when it should be blocked,
	 * or null when allowed.
	 *
	 * Blocklist (not allowlist) on purpose: only methods that are never
	 * legitimate (CONNECT, TRACE, TRACK, DEBUG) and malformed methods (anything
	 * that is not pure uppercase letters) are blocked. Uncommon-but-valid verbs
	 * (PUT, PATCH, DELETE, OPTIONS and WebDAV/CalDAV methods like PROPFIND or
	 * REPORT) are allowed, so the firewall never breaks a legitimate API/sync
	 * client.
	 *
	 * @param string $method Uppercased request method.
	 */
	public static function match_method( string $method ): ?string {
		if ( '' === $method ) {
			return null;
		}
		if ( in_array( $method, self::BLOCKED_METHODS, true ) ) {
			return $method;
		}
		if ( 1 === preg_match( '/[^A-Z]/', $method ) ) {
			return $method;
		}
		return null;
	}
}
