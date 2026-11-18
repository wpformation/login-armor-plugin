<?php
/**
 * Boolean options written as strings (2.10.0).
 *
 * `wp option update login_armor_geoip_enabled false` stores the string
 * "false", which PHP reads as true: the module came ON. Every boolean option
 * of the plugin, and every boolean key of a grouped setting, is now brought
 * back to a real boolean when it is written and when it is read. The list is
 * the registry's (`bool` entries), written out here because this class is
 * loaded on every request and the registry is not; tests/release-2-10-0.php
 * holds the two in step.
 *
 * The sixteen hardening toggles are not here: Hardening::get_settings()
 * already reads them through LoginArmor::to_bool() (2.7.0).
 *
 * @package LoginArmor
 */

namespace LoginArmor\Support;

use LoginArmor\LoginArmor;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Normalisation of the plugin's boolean options.
 */
final class Booleans {

	/**
	 * Standalone boolean options, stored as 1 or 0.
	 *
	 * @var array<int,string>
	 */
	public const STANDALONE = array(
		'login_armor_hide_enabled',
		'login_armor_limit_enabled',
		'login_armor_syslog',
		'login_armor_detection_enabled',
		'login_armor_auto_purge',
		'login_armor_activity_enabled',
		'login_armor_activity_auto_verify_daily',
		'login_armor_webhook_enabled',
		'login_armor_2fa_enabled',
		'login_armor_2fa_trusted_devices_enabled',
		'login_armor_2fa_recovery_enabled',
		'login_armor_login_headers_enabled',
		'login_armor_headers_sitewide',
		'login_armor_breach_check_enabled',
		'login_armor_breach_check_passwords',
		'login_armor_breach_check_emails',
		'login_armor_breach_check_force_reset',
		'login_armor_geoip_enabled',
		'login_armor_ai_enabled',
		'login_armor_ai_deep',
		'login_armor_headless',
		'login_armor_app_password_watch',
	);

	/**
	 * Grouped settings and their boolean keys, stored as PHP booleans.
	 *
	 * @var array<string,array<int,string>>
	 */
	public const STRUCT = array(
		'login_armor_password_policy' => array( 'enabled', 'require_lower', 'require_upper', 'require_number', 'require_symbol', 'forbid_username', 'block_compromised' ),
		'login_armor_session'         => array( 'enabled', 'single_session' ),
		'login_armor_firewall'        => array( 'enabled', 'query_string', 'request_uri', 'request_method', 'user_agent', 'referer', 'request_uri_aggressive' ),
		'login_armor_pow'             => array( 'enabled' ),
	);

	/**
	 * Hook the write and read filters of every listed option.
	 */
	public static function register(): void {
		foreach ( self::STANDALONE as $option ) {
			add_filter( 'sanitize_option_' . $option, array( self::class, 'normalise_standalone' ) );
			add_filter( 'option_' . $option, array( self::class, 'normalise_standalone' ) );
		}
		foreach ( array_keys( self::STRUCT ) as $option ) {
			add_filter( 'sanitize_option_' . $option, array( self::class, 'normalise_struct_' . self::slot( $option ) ) );
			add_filter( 'option_' . $option, array( self::class, 'normalise_struct_' . self::slot( $option ) ) );
		}
	}

	/**
	 * A standalone boolean as 1 or 0.
	 *
	 * Untyped with a default, like every callback on a core hook.
	 *
	 * @param mixed $value Stored or written value.
	 */
	public static function normalise_standalone( $value = null ): int {
		return LoginArmor::to_bool( $value ) ? 1 : 0;
	}

	/**
	 * The boolean keys of a grouped setting as booleans, the rest untouched.
	 *
	 * @param mixed             $value Stored or written value.
	 * @param array<int,string> $keys  Its boolean keys.
	 * @return mixed
	 */
	public static function normalise_struct( $value, array $keys ) {
		if ( ! is_array( $value ) ) {
			return $value;
		}
		foreach ( $keys as $key ) {
			if ( array_key_exists( $key, $value ) ) {
				$value[ $key ] = LoginArmor::to_bool( $value[ $key ] );
			}
		}
		return $value;
	}

	/**
	 * Filter callbacks of the four grouped settings: one per option, so each
	 * knows its keys. Untyped with a default.
	 *
	 * @param mixed $value Stored or written value.
	 * @return mixed
	 */
	public static function normalise_struct_password_policy( $value = null ) {
		return self::normalise_struct( $value, self::STRUCT['login_armor_password_policy'] );
	}

	/**
	 * @param mixed $value Stored or written value.
	 * @return mixed
	 */
	public static function normalise_struct_session( $value = null ) {
		return self::normalise_struct( $value, self::STRUCT['login_armor_session'] );
	}

	/**
	 * @param mixed $value Stored or written value.
	 * @return mixed
	 */
	public static function normalise_struct_firewall( $value = null ) {
		return self::normalise_struct( $value, self::STRUCT['login_armor_firewall'] );
	}

	/**
	 * @param mixed $value Stored or written value.
	 * @return mixed
	 */
	public static function normalise_struct_pow( $value = null ) {
		return self::normalise_struct( $value, self::STRUCT['login_armor_pow'] );
	}

	/** Suffix of the struct callback of an option. */
	private static function slot( string $option ): string {
		return substr( $option, strlen( 'login_armor_' ) );
	}

	/**
	 * Upgrade to 2.10.0: rewrite every stored string as what the site does today.
	 *
	 * A site holding "false" runs most modules, since most readers cast the
	 * value with (bool). Honouring the string now would switch protections off
	 * on update without anyone asking, and casting everything with (bool)
	 * would switch on what a stricter reader kept off (Hide Login, headless
	 * mode). Each value is rewritten as what its own 2.9.0 reader made of it
	 * (state_before_2_10_0()), so no site changes state. Only after this do
	 * "false" and "0" switch off. Read straight from the table, past the
	 * filters above.
	 *
	 * @return array<int,array{option:string,key:string,from:string,to:int}> One line per rewrite.
	 */
	public static function migrate_existing(): array {
		$changes = array();

		foreach ( self::STANDALONE as $option ) {
			$raw = self::stored( $option );
			if ( null === $raw || in_array( $raw, array( '', '0', '1' ), true ) ) {
				continue;
			}
			$to = self::state_before_2_10_0( $option, maybe_unserialize( $raw ) ) ? 1 : 0;
			self::write_raw( $option, (string) $to );
			$changes[] = array(
				'option' => $option,
				'key'    => '',
				'from'   => substr( $raw, 0, 40 ),
				'to'     => $to,
			);
		}

		foreach ( self::STRUCT as $option => $keys ) {
			$raw = self::stored( $option );
			if ( null === $raw ) {
				continue;
			}
			$value = maybe_unserialize( $raw );
			if ( ! is_array( $value ) ) {
				continue;
			}
			$changed = false;
			foreach ( $keys as $key ) {
				if ( isset( $value[ $key ] ) && is_string( $value[ $key ] ) ) {
					$from            = $value[ $key ];
					$value[ $key ]   = (bool) $from;
					$changed         = true;
					$changes[]       = array(
						'option' => $option,
						'key'    => $key,
						'from'   => substr( $from, 0, 40 ),
						'to'     => $value[ $key ] ? 1 : 0,
					);
				}
			}
			if ( $changed ) {
				self::write_raw( $option, maybe_serialize( $value ) );
			}
		}

		if ( array() !== $changes ) {
			wp_cache_delete( 'alloptions', 'options' );
			foreach ( $changes as $change ) {
				wp_cache_delete( $change['option'], 'options' );
			}
		}
		return $changes;
	}

	/**
	 * What the 2.9.0 reader of an option made of a stored value.
	 *
	 * Not all of them cast with (bool): Hide Login compares to the integer 1
	 * ("false" and "true" both read off), headless mode, application-password
	 * monitoring and the syslog switch (new, never stored as a string by the
	 * plugin) go through LoginArmor::to_bool() ("false" reads off). Every other
	 * reader cast with (bool) or tested the value as is.
	 *
	 * @param string $option Option name.
	 * @param mixed  $value  Stored value, unserialized.
	 */
	public static function state_before_2_10_0( string $option, $value ): bool {
		if ( 'login_armor_hide_enabled' === $option ) {
			return 1 === (int) ( is_scalar( $value ) ? $value : 0 );
		}
		if ( in_array( $option, array( 'login_armor_headless', 'login_armor_app_password_watch', 'login_armor_syslog' ), true ) ) {
			return LoginArmor::to_bool( $value );
		}
		return (bool) $value;
	}

	/** The option as the table holds it, or null when absent. */
	private static function stored( string $option ): ?string {
		global $wpdb;
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- One-time upgrade read, past the option filters on purpose.
		$raw = $wpdb->get_var( $wpdb->prepare( "SELECT option_value FROM {$wpdb->options} WHERE option_name = %s", $option ) );
		return null === $raw ? null : (string) $raw;
	}

	/** Write the option as is, past the option filters. */
	private static function write_raw( string $option, string $value ): void {
		global $wpdb;
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- One-time upgrade write; caches cleared by the caller.
		$wpdb->update( $wpdb->options, array( 'option_value' => $value ), array( 'option_name' => $option ) );
	}
}
