<?php
/**
 * Headless mode (2.9.0).
 *
 * A headless back end serves its REST API to a separate front end and takes
 * writes through application passwords. Two hardening toggles break exactly
 * that: "Restrict REST API" and "Disable application passwords". While the
 * mode is on they are kept off, whoever asks: the settings screen, an import,
 * `wp option patch update`, the guided setup.
 *
 * Two layers, on purpose. Hardening::get_settings() masks them, which is the
 * run-time truth and what an export reads. The pre_update_option filter keeps
 * the STORED value off as well, so that switching the mode off later cannot
 * resurrect a toggle nobody asked for.
 *
 * The Request Firewall is not guarded: it skips every REST request
 * (Firewall::should_skip_context()), measured on a clone of a real headless
 * back end, docs/audit/2026-10-07-headless-clone/preuves/pare-feu-blocage.txt.
 *
 * @package LoginArmor
 * @since   2.9.0
 */

namespace LoginArmor;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Headless mode: one option, two guarded toggles.
 */
final class Headless {

	/** Option holding the mode. Autoloaded: read on every request. */
	public const OPTION = 'login_armor_headless';

	/** The hardening toggles that break a headless back end, in display order. */
	public const GUARDED_TOGGLES = array( 'restrict_rest_api', 'disable_app_passwords' );

	/** Whether the mode is on. The string "false" WP-CLI writes means off. */
	public static function is_enabled(): bool {
		return LoginArmor::to_bool( get_option( self::OPTION, false ) );
	}

	/**
	 * Hook the write filter. Registered on every request: it decides for
	 * itself, so a mode switched on during the request is honoured at once.
	 */
	public static function register(): void {
		add_filter( 'pre_update_option_' . Hardening::OPTION_KEY, array( self::class, 'filter_hardening_write' ), 10, 2 );
	}

	/**
	 * The guarded toggles a set of toggles switches on.
	 *
	 * @param array<string,mixed> $toggles Toggle key => value, any truthiness.
	 * @return string[] Guarded keys that are on, in GUARDED_TOGGLES order.
	 */
	public static function conflicts( array $toggles ): array {
		$on = array();
		foreach ( self::GUARDED_TOGGLES as $key ) {
			if ( isset( $toggles[ $key ] ) && LoginArmor::to_bool( $toggles[ $key ] ) ) {
				$on[] = $key;
			}
		}
		return $on;
	}

	/**
	 * pre_update_option_login_armor_hardening: keep the guarded toggles off.
	 *
	 * Untyped with defaults, like every callback on a core hook.
	 *
	 * @param mixed $value     The value about to be stored.
	 * @param mixed $old_value The stored value.
	 * @return mixed
	 */
	public static function filter_hardening_write( $value = array(), $old_value = null ) {
		unset( $old_value );
		if ( ! is_array( $value ) || ! self::is_enabled() ) {
			return $value;
		}
		foreach ( self::GUARDED_TOGGLES as $key ) {
			if ( array_key_exists( $key, $value ) ) {
				$value[ $key ] = false;
			}
		}
		return $value;
	}

	/**
	 * Switch the mode on and turn the guarded toggles off.
	 *
	 * The conflicts are read from the STORED toggles: get_settings() already
	 * masks them when the mode was switched on directly (`wp option update`),
	 * and the stored values would come back when the mode is switched off.
	 * Announces only a real change: a repeat on a clean site fires nothing.
	 *
	 * @param int $user_id Who asked; 0 for the system (WP-CLI without --user).
	 * @return string[] The toggles that were on and are now off.
	 */
	public static function enable( int $user_id = 0 ): array {
		$was_enabled = self::is_enabled();
		$stored      = get_option( Hardening::OPTION_KEY, array() );
		$turned_off  = self::conflicts( is_array( $stored ) ? $stored : array() );

		update_option( self::OPTION, true, true );

		if ( array() !== $turned_off ) {
			// get_settings() now masks the guarded keys, so saving what it
			// returns stores them off and keeps every other toggle as it was.
			Hardening::save_settings( Hardening::get_settings() );
		}

		if ( $was_enabled && array() === $turned_off ) {
			return array();
		}

		/**
		 * Fires when the headless mode is switched on or off.
		 *
		 * @since 2.9.0
		 *
		 * @param bool     $enabled    The new state.
		 * @param string[] $turned_off Toggles switched off by this change.
		 * @param int      $user_id    Who asked; 0 for the system.
		 */
		do_action( 'login_armor_headless_changed', true, $turned_off, $user_id );

		return $turned_off;
	}

	/**
	 * Switch the mode off. Nothing is turned back on (spec A.4).
	 * Does nothing, and announces nothing, when the mode is already off.
	 *
	 * @param int $user_id Who asked; 0 for the system.
	 */
	public static function disable( int $user_id = 0 ): void {
		if ( ! self::is_enabled() ) {
			return;
		}
		update_option( self::OPTION, false, true );

		/** This action is documented in includes/class-headless.php */
		do_action( 'login_armor_headless_changed', false, array(), $user_id );
	}

	/**
	 * Human labels of hardening toggle keys, for messages.
	 *
	 * @param string[] $keys Toggle keys.
	 * @return string[] Labels, in the order given.
	 */
	public static function labels( array $keys ): array {
		$by_key = array();
		foreach ( Hardening::get_toggles() as $toggle ) {
			$by_key[ $toggle['key'] ] = $toggle['label'];
		}
		$labels = array();
		foreach ( $keys as $key ) {
			$labels[] = $by_key[ $key ] ?? $key;
		}
		return $labels;
	}
}
