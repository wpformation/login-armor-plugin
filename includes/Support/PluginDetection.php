<?php
/**
 * Detection of third-party plugins whose surface overlaps Login Armor.
 *
 * Two questions are asked in two different places and must be answered the
 * same way in both: which security plugins duplicate a protection this plugin
 * already provides, and which page caches are running. Until 2.7.0 the maps
 * lived inside the admin conflict notice, so the Site Health test could only
 * have had a second copy of them, and two copies of a plugin list drift the
 * first time a competitor renames its main file.
 *
 * Read-only by design: nothing here deactivates, activates or writes anything.
 *
 * @package LoginArmor
 */

namespace LoginArmor\Support;

defined( 'ABSPATH' ) || exit;

/**
 * Which overlapping plugins are active on this site.
 */
final class PluginDetection {

	/**
	 * Security plugins mapped to the Login Armor surfaces they duplicate.
	 *
	 * The overlap keys are resolved to sentences by the admin notice, which
	 * owns that wording; this class owns only the facts.
	 *
	 * @return array<string,array{name:string,overlaps:array<int,string>}>
	 */
	public static function security_plugin_map(): array {
		return [
			'wordfence/wordfence.php'                   => [
				'name'     => 'Wordfence Security',
				'overlaps' => [ 'brute', 'firewall', '2fa' ],
			],
			'better-wp-security/better-wp-security.php' => [
				'name'     => 'Solid Security (iThemes)',
				'overlaps' => [ 'brute', 'hide', '2fa', 'hardening' ],
			],
			'ithemes-security-pro/ithemes-security-pro.php' => [
				'name'     => 'Solid Security Pro',
				'overlaps' => [ 'brute', 'hide', '2fa', 'hardening' ],
			],
			'sucuri-scanner/sucuri.php'                 => [
				'name'     => 'Sucuri Security',
				'overlaps' => [ 'firewall', 'hardening' ],
			],
			'all-in-one-wp-security-and-firewall/wp-security.php' => [
				'name'     => 'All-In-One Security (AIOS)',
				'overlaps' => [ 'brute', 'firewall', 'hide', 'hardening' ],
			],
			'wps-hide-login/wps-hide-login.php'         => [
				'name'     => 'WPS Hide Login',
				'overlaps' => [ 'hide' ],
			],
			'wps-limit-login/wps-limit-login.php'       => [
				'name'     => 'WPS Limit Login',
				'overlaps' => [ 'brute', 'limit' ],
			],
			'secupress/secupress.php'                   => [
				'name'     => 'SecuPress',
				'overlaps' => [ 'brute', 'firewall', '2fa', 'hide', 'hardening' ],
			],
			'defender-security/wp-defender.php'         => [
				'name'     => 'Defender Security',
				'overlaps' => [ 'brute', 'firewall', '2fa', 'hide' ],
			],
			'wp-cerber/wp-cerber.php'                   => [
				'name'     => 'WP Cerber',
				'overlaps' => [ 'brute', 'hide', '2fa', 'limit' ],
			],
			'wp-simple-firewall/icwp-wpsf.php'          => [
				'name'     => 'Shield Security',
				'overlaps' => [ 'brute', 'firewall', '2fa', 'hide' ],
			],
			'limit-login-attempts-reloaded/limit-login-attempts-reloaded.php' => [
				'name'     => 'Limit Login Attempts Reloaded',
				'overlaps' => [ 'brute', 'limit' ],
			],
			'malcare-security/malcare.php'              => [
				'name'     => 'MalCare Security',
				'overlaps' => [ 'firewall', 'brute' ],
			],
		];
	}

	/**
	 * Page caches, mapped to their display name.
	 *
	 * Only a problem when Hide Login is on: the secret slug can be served
	 * from the page cache as a stale 404.
	 *
	 * @return array<string,string>
	 */
	public static function cache_plugin_map(): array {
		return [
			'wp-rocket/wp-rocket.php'             => 'WP Rocket',
			'litespeed-cache/litespeed-cache.php' => 'LiteSpeed Cache',
			'w3-total-cache/w3-total-cache.php'   => 'W3 Total Cache',
			'wp-super-cache/wp-cache.php'         => 'WP Super Cache',
			'wp-fastest-cache/wpFastestCache.php' => 'WP Fastest Cache',
		];
	}

	/**
	 * Active security plugins, in map order.
	 *
	 * @return array<string,string> Plugin file => display name.
	 */
	public static function active_security_plugins(): array {
		$found = [];
		foreach ( self::security_plugin_map() as $file => $info ) {
			if ( self::is_active( $file ) ) {
				$found[ $file ] = (string) $info['name'];
			}
		}

		return $found;
	}

	/**
	 * Active page caches, in map order.
	 *
	 * @return array<string,string> Plugin file => display name.
	 */
	public static function active_cache_plugins(): array {
		$found = [];
		foreach ( self::cache_plugin_map() as $file => $name ) {
			if ( self::is_active( $file ) ) {
				$found[ $file ] = $name;
			}
		}

		return $found;
	}

	/**
	 * Stable identity of the page caches running right now.
	 *
	 * The cache notice is dismissed against this string instead of a bare
	 * true. An administrator who dismisses it is confirming one exclusion
	 * rule, in the product they had at that moment; installing a second cache
	 * six months later is a new exclusion nobody has written, and a boolean
	 * would have silenced that warning forever.
	 *
	 * Sorted, because active_cache_plugins() answers in map order: reordering
	 * the map for readability would otherwise invalidate the dismissal on
	 * every site that has two caches, and the notice would come back with
	 * nothing having changed on the site.
	 *
	 * @since 2.7.1
	 *
	 * @return string Comma-joined plugin files, empty when no cache is active.
	 */
	public static function cache_set_key(): string {
		$files = array_keys( self::active_cache_plugins() );
		sort( $files, SORT_STRING );

		return implode( ',', $files );
	}

	/**
	 * Ask WordPress whether one plugin file is running.
	 *
	 * `is_plugin_active()` lives in an admin include that is not always
	 * loaded: the Site Health screen reaches this class through a filter that
	 * fires before the plugins screen ever does. It is network-aware on
	 * multisite (it answers true for a plugin activated for the whole
	 * network), which is the behaviour the admin notice has always had.
	 *
	 * @param string $file Plugin file, as WordPress keys it.
	 * @return bool
	 */
	private static function is_active( string $file ): bool {
		if ( ! function_exists( 'is_plugin_active' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}

		return is_plugin_active( $file );
	}
}
