<?php
/**
 * Settings import: parse -> plan (pure dry-run) -> apply.
 *
 * A file is either applied whole or not at all: on a fleet of sites, a
 * half-applied import is worse than a refused one. Validation errors block;
 * warnings inform. Side effects go through the owning module (firewall
 * activation lands in monitor mode, hardening syncs .htaccess, the activity
 * log creates its table) and Hide Login is written last, so the login URL
 * only moves once everything else succeeded.
 *
 * @package LoginArmor\Settings
 * @since   2.6.0
 */

namespace LoginArmor\Settings;

use LoginArmor\ActivityLog\ActivityLog;
use LoginArmor\ActivityLog\WebhookDispatcher;
use LoginArmor\Firewall\Firewall;
use LoginArmor\GeoIP;
use LoginArmor\AppPasswords\Usage;
use LoginArmor\Hardening;
use LoginArmor\Headless;
use LoginArmor\HideLogin;
use LoginArmor\LoginArmor;
use LoginArmor\PasswordPolicy;
use LoginArmor\PowChallenge;
use LoginArmor\SessionManager;
use LoginArmor\TwoFactor\TwoFactor;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Importer {

	/** Bump when the JSON layout changes in a way older readers cannot handle. */
	public const SCHEMA_VERSION = 1;

	/** Largest accepted file (a full export is a few KB). */
	public const MAX_BYTES = 262144;

	/** Groups written through a module, in the order they are applied (after plain options). */
	private const GROUP_ORDER = array( 'password_policy', 'session', 'bot_challenge', 'firewall', 'activity_log', 'headless', 'hardening', 'hide_login' );

	// ------------------------------------------------------------------
	// Parse
	// ------------------------------------------------------------------

	/**
	 * Decode and vet the envelope. Returns the envelope (without settings)
	 * and the settings object, or a \WP_Error explaining the refusal.
	 *
	 * @return array{envelope:array<string,mixed>,settings:array<string,mixed>}|\WP_Error
	 */
	public static function parse( string $json ): array|\WP_Error {
		if ( strlen( $json ) > self::MAX_BYTES ) {
			return new \WP_Error( 'login_armor_settings_too_large', sprintf( /* translators: %d: size in KB */ __( 'File is larger than %d KB.', 'login-armor' ), (int) ( self::MAX_BYTES / 1024 ) ) );
		}
		$data = json_decode( $json, true, 16 );
		if ( ! is_array( $data ) || array_is_list( $data ) ) {
			return new \WP_Error( 'login_armor_settings_invalid_json', __( 'Not a valid Login Armor settings file (JSON object expected).', 'login-armor' ) );
		}
		if ( 'login-armor' !== ( $data['plugin'] ?? '' ) ) {
			return new \WP_Error( 'login_armor_settings_wrong_plugin', __( 'Not a Login Armor settings file.', 'login-armor' ) );
		}
		$schema = (int) ( $data['schema_version'] ?? 0 );
		if ( $schema < 1 ) {
			return new \WP_Error( 'login_armor_settings_no_schema', __( 'The file does not declare a schema version.', 'login-armor' ) );
		}
		if ( $schema > self::SCHEMA_VERSION ) {
			return new \WP_Error( 'login_armor_settings_schema_newer', sprintf( /* translators: 1: schema version in the file, 2: schema version this site reads */ __( 'This file was exported by a newer Login Armor (schema %1$d, this site reads %2$d). Update this site first.', 'login-armor' ), $schema, self::SCHEMA_VERSION ) );
		}
		if ( ! isset( $data['settings'] ) || ! is_array( $data['settings'] ) || ( ! empty( $data['settings'] ) && array_is_list( $data['settings'] ) ) ) {
			return new \WP_Error( 'login_armor_settings_no_settings', __( 'The file has no settings object.', 'login-armor' ) );
		}
		$settings = $data['settings'];
		unset( $data['settings'] );

		return array(
			'envelope' => $data,
			'settings' => self::migrate( $settings, $schema ),
		);
	}

	/**
	 * Upgrade an older schema to the current one. Nothing to do at schema 1.
	 *
	 * @param array<string,mixed> $settings
	 * @return array<string,mixed>
	 */
	private static function migrate( array $settings, int $from ): array {
		unset( $from );
		return $settings;
	}

	// ------------------------------------------------------------------
	// Plan
	// ------------------------------------------------------------------

	/**
	 * Validate every value and compute the diff against this site. Writes
	 * nothing. $context: source ('admin'|'cli'), user_id, client_ip.
	 *
	 * @param array{envelope:array<string,mixed>,settings:array<string,mixed>} $parsed
	 * @param array<string,mixed>                                              $context
	 * @return array<string,mixed>
	 */
	public static function plan( array $parsed, array $context ): array {
		$registry = Registry::entries();
		$errors   = array();
		$warnings = array();
		$unknown  = array();
		$incoming = array(); // option => sanitized JSON value (objects: only the fields present).
		$raw      = array(); // option => raw JSON value, for "what was dropped" warnings.

		foreach ( $parsed['settings'] as $group => $values ) {
			$group = (string) $group;
			if ( ! in_array( $group, Registry::GROUPS, true ) ) {
				$unknown[] = $group;
				continue;
			}
			if ( ! is_array( $values ) ) {
				$errors[] = self::issue( $group, __( 'expected an object', 'login-armor' ) );
				continue;
			}
			$whole = Registry::option_for( $group, null );
			if ( null !== $whole ) {
				$entry = $registry[ $whole ];
				foreach ( array_keys( $values ) as $field ) {
					if ( ! isset( $entry['fields'][ $field ] ) ) {
						$unknown[] = $group . '.' . $field;
					}
				}
				$clean = Registry::sanitize( $entry, $values );
				if ( is_wp_error( $clean ) ) {
					$errors[] = self::issue( $group . self::field_suffix( $clean ), $clean->get_error_message() );
				} else {
					$incoming[ $whole ] = $clean;
					$raw[ $whole ]      = $values;
				}
				continue;
			}
			foreach ( $values as $key => $value ) {
				$option = Registry::option_for( $group, (string) $key );
				if ( null === $option ) {
					$unknown[] = $group . '.' . $key;
					continue;
				}
				$entry = $registry[ $option ];
				if ( 'object' === $entry['type'] && is_array( $value ) ) {
					foreach ( array_keys( $value ) as $field ) {
						if ( ! isset( $entry['fields'][ $field ] ) ) {
							$unknown[] = $group . '.' . $key . '.' . $field;
						}
					}
				}
				$clean = Registry::sanitize( $entry, $value );
				if ( is_wp_error( $clean ) ) {
					$errors[] = self::issue( $group . '.' . $key . self::field_suffix( $clean ), $clean->get_error_message() );
					continue;
				}
				$incoming[ $option ] = $clean;
				$raw[ $option ]      = $value;
			}
		}

		// Effective values: partial objects are merged over the current value.
		$entries = array();
		foreach ( $incoming as $option => $value ) {
			$entry   = $registry[ $option ];
			$current = Registry::read( $option );
			$entries[ $option ] = array(
				'group'    => $entry['group'],
				'key'      => $entry['key'],
				'path'     => self::path( $entry ),
				'current'  => $current,
				'incoming' => 'object' === $entry['type'] ? array_merge( (array) $current, (array) $value ) : $value,
				'status'   => 'same',
			);
		}

		$state = array(
			'entries'  => $entries,
			'errors'   => $errors,
			'warnings' => $warnings,
			'raw'      => $raw,
			'context'  => $context,
		);
		self::check_notifications( $state );
		self::check_activity_webhook( $state );
		self::check_hide_login( $state );
		self::check_two_factor( $state );
		self::check_brute_force( $state );
		self::check_hardening( $state );
		self::check_headless( $state );
		self::check_monitor_modules( $state );

		$counts = array( 'change' => 0, 'same' => 0 );
		foreach ( $state['entries'] as $option => $row ) {
			$status = $row['incoming'] === $row['current'] ? 'same' : 'change';
			$state['entries'][ $option ]['status'] = $status;
			++$counts[ $status ];
		}

		$login_url_after = null;
		$hide_changed    = false;
		foreach ( $state['entries'] as $row ) {
			if ( 'hide_login' === $row['group'] && 'change' === $row['status'] ) {
				$hide_changed = true;
			}
		}
		if ( $hide_changed && empty( $state['errors'] ) ) {
			$login_url_after = self::predict_login_url( $state['entries'] );
		}

		return array(
			'envelope'         => $parsed['envelope'],
			'entries'          => $state['entries'],
			'errors'           => $state['errors'],
			'warnings'         => $state['warnings'],
			'unknown'          => array_values( array_unique( $unknown ) ),
			'counts'           => $counts,
			'login_url_before' => HideLogin::get_login_url(),
			'login_url_after'  => $login_url_after,
		);
	}

	// ------------------------------------------------------------------
	// Apply
	// ------------------------------------------------------------------

	/**
	 * Write a clean plan. Refuses a plan that carries errors.
	 *
	 * @param array<string,mixed> $plan    Output of plan().
	 * @param array<string,mixed> $context Same context as plan().
	 * @return array<string,mixed>|\WP_Error Report: applied, unchanged, warnings, errors, login_url.
	 */
	public static function apply( array $plan, array $context ): array|\WP_Error {
		if ( ! empty( $plan['errors'] ) ) {
			return new \WP_Error( 'login_armor_settings_plan_errors', sprintf( /* translators: %d: number of errors */ __( 'The file has %d error(s); nothing was applied.', 'login-armor' ), count( $plan['errors'] ) ) );
		}

		$registry  = Registry::entries();
		$applied   = array();
		$unchanged = array();
		$errors    = array();
		$warnings  = $plan['warnings'];
		$entries   = $plan['entries'];

		$changed = array();
		foreach ( $entries as $option => $row ) {
			if ( 'change' === $row['status'] ) {
				$changed[ $option ] = $row;
			} else {
				$unchanged[] = $row['path'];
			}
		}

		// 1. Plain options, with their few per-option side effects.
		foreach ( $changed as $option => $row ) {
			$entry = $registry[ $option ];
			if ( 'option' !== $entry['apply'] ) {
				continue;
			}
			try {
				update_option( $option, Registry::to_stored_value( $entry, $row['incoming'] ), $entry['autoload'] );
				if ( 'login_armor_auto_purge' === $option ) {
					if ( $row['incoming'] ) {
						if ( ! wp_next_scheduled( 'login_armor_purge_logs' ) ) {
							wp_schedule_event( time(), 'daily', 'login_armor_purge_logs' );
						}
					} else {
						wp_clear_scheduled_hook( 'login_armor_purge_logs' );
					}
				}
				// 2.6.1 : geolocation resolves from a scheduled event, so an
				// import that switches it on (or off) has to schedule it (or
				// take it out) right here. Waiting for the next
				// ensure_site_crons() would leave a freshly imported site with
				// the module on and no badge ever filling, until an
				// administrator happens to open an admin page.
				if ( GeoIP::OPTION_ENABLED === $option ) {
					GeoIP::sync_prefetch_schedule();
				}
				$applied[] = $row['path'];
			} catch ( \Throwable $e ) {
				$errors[] = self::issue( $row['path'], $e->getMessage() );
			}
		}
		if ( array_intersect_key( $changed, array_flip( array( 'login_armor_ip_method', 'login_armor_trusted_proxies' ) ) ) ) {
			LoginArmor::reset_client_ip_cache();
		}

		// 2.7.0 : an import repoints the alerts, and on a fleet it repoints
		// sixty sites from one file. Both fields are exportable, so without
		// this the Site Health test would answer that a test alert was
		// delivered successfully to a destination nobody has ever tested.
		// `$changed` already means the stored value differs from the incoming
		// one, so being in it IS the move.
		if ( array_intersect_key( $changed, array_flip( array( 'login_armor_notif_channel', 'login_armor_notif_webhook_url' ) ) ) ) {
			delete_option( 'login_armor_notif_last_test_ok' );
		}

		// 2. Module-owned groups, in a safe order; Hide Login last.
		foreach ( self::GROUP_ORDER as $group ) {
			$rows = array_filter( $changed, static fn( array $r ) => $r['group'] === $group );
			if ( empty( $rows ) ) {
				continue;
			}
			try {
				$group_warnings = self::apply_group( $group, $rows, $entries );
				foreach ( $group_warnings as $w ) {
					$warnings[] = $w;
				}
				foreach ( $rows as $row ) {
					$applied[] = $row['path'];
				}
			} catch ( \Throwable $e ) {
				foreach ( $rows as $row ) {
					$errors[] = self::issue( $row['path'], $e->getMessage() );
				}
			}
		}

		$login_url = HideLogin::get_login_url();
		$summary   = array(
			'source'      => (string) ( $context['source'] ?? 'admin' ),
			'source_host' => (string) ( $plan['envelope']['source']['host'] ?? '' ),
			'applied'     => count( $applied ),
			'unchanged'   => count( $unchanged ),
			'unknown'     => count( $plan['unknown'] ?? array() ),
			'errors'      => count( $errors ),
			'paths'       => $applied,
			'login_url'   => $login_url,
		);
		$user_id   = (int) ( $context['user_id'] ?? 0 );

		self::record_activity( $summary, $user_id );

		/**
		 * Fires after a settings file was applied.
		 *
		 * @since 2.6.0
		 *
		 * @param array<string,mixed> $summary Counts, applied paths, source host, login URL.
		 * @param int                 $user_id Importing user (0 from WP-CLI without --user).
		 */
		do_action( 'login_armor_settings_imported', $summary, $user_id );

		return array(
			'applied'   => $applied,
			'unchanged' => $unchanged,
			'warnings'  => $warnings,
			'errors'    => $errors,
			'login_url' => $login_url,
		);
	}

	/**
	 * Write one module-owned group. Returns extra warnings.
	 *
	 * @param array<string,array<string,mixed>> $rows    Changed entries of the group.
	 * @param array<string,array<string,mixed>> $entries All plan entries.
	 * @return array<int,array{path:string,message:string}>
	 */
	private static function apply_group( string $group, array $rows, array $entries ): array {
		$warnings = array();
		$value    = static function ( string $option ) use ( $rows ): mixed {
			return $rows[ $option ]['incoming'] ?? null;
		};

		switch ( $group ) {
			case 'password_policy':
				PasswordPolicy::save_settings( (array) $value( PasswordPolicy::OPTION_KEY ) );
				break;

			case 'session':
				SessionManager::save_settings( (array) $value( SessionManager::OPTION_KEY ) );
				break;

			case 'firewall':
				$incoming = (array) $value( Firewall::OPTION_KEY );
				if ( (bool) $incoming['enabled'] !== Firewall::is_enabled() ) {
					Firewall::set_enabled( (bool) $incoming['enabled'] );
				}
				Firewall::save_settings( (array) Registry::to_stored_value( Registry::entries()[ Firewall::OPTION_KEY ], $incoming ) );
				break;

			case 'bot_challenge':
				$incoming = (array) $value( PowChallenge::OPTION_KEY );
				if ( (bool) $incoming['enabled'] !== PowChallenge::is_enabled() ) {
					PowChallenge::set_enabled( (bool) $incoming['enabled'] );
				}
				PowChallenge::save_settings( $incoming );
				break;

			case 'activity_log':
				$enabled = $value( ActivityLog::OPTION_ENABLED );
				if ( null !== $enabled ) {
					if ( $enabled ) {
						ActivityLog::enable();
					} else {
						update_option( ActivityLog::OPTION_ENABLED, false );
						wp_clear_scheduled_hook( ActivityLog::CRON_HOOK );
					}
				}
				break;

			case 'headless':
				$enabled = $value( 'login_armor_headless' );
				if ( null !== $enabled ) {
					if ( (bool) $enabled ) {
						$turned_off = Headless::enable( (int) get_current_user_id() );
						if ( array() !== $turned_off ) {
							$warnings[] = self::issue(
								'headless.enabled',
								sprintf(
									/* translators: %s: comma-separated list of hardening toggle names. */
									__( 'headless mode turned off: %s', 'login-armor' ),
									implode( ', ', Headless::labels( $turned_off ) )
								)
							);
						}
					} else {
						Headless::disable( (int) get_current_user_id() );
					}
				}
				$watch = $value( 'login_armor_app_password_watch' );
				if ( null !== $watch ) {
					Usage::set_watching( (bool) $watch );
				}
				break;

			case 'hardening':
				$registry = Registry::entries();
				$toggles  = $value( Hardening::OPTION_KEY );
				if ( null !== $toggles ) {
					$before = Hardening::get_settings();
					Hardening::save_settings( (array) $toggles );
					$after = Hardening::get_settings();
					// 2.8.0: protect_system_files is the third toggle backed
					// by an .htaccess block.
					if ( ( $before['block_php_uploads'] ?? false ) !== ( $after['block_php_uploads'] ?? false )
						|| ( $before['disable_directory_listing'] ?? false ) !== ( $after['disable_directory_listing'] ?? false )
						|| ( $before['protect_system_files'] ?? false ) !== ( $after['protect_system_files'] ?? false ) ) {
						// Both transients are cleared first, so what is read
						// back can only have been set by this very sync.
						delete_transient( 'login_armor_htaccess_write_failed' );
						delete_transient( 'login_armor_htaccess_ambiguous' );
						Hardening::sync_htaccess();
						$failed = get_transient( 'login_armor_htaccess_write_failed' );
						if ( false !== $failed && '' !== $failed ) {
							$warnings[] = self::issue( 'hardening.toggles', __( 'The toggle is saved but its .htaccess rule could not be written: ', 'login-armor' ) . ( is_scalar( $failed ) ? (string) $failed : __( 'see the admin notice', 'login-armor' ) ) );
						}
						// 2.6.1: the file was readable but its Login Armor
						// markers do not form exactly one complete block, so
						// nothing was rewritten. The toggle is saved and the
						// file disagrees until a human repairs the markers.
						$ambiguous = get_transient( 'login_armor_htaccess_ambiguous' );
						if ( false !== $ambiguous && '' !== $ambiguous ) {
							$warnings[] = self::issue( 'hardening.toggles', __( 'The toggle is saved but this .htaccess file was left untouched, because it contains Login Armor markers that do not form exactly one complete block: ', 'login-armor' ) . ( is_scalar( $ambiguous ) ? (string) $ambiguous : __( 'see the admin notice', 'login-armor' ) ) );
						}
					}
				}
				foreach ( array( \LoginArmor\Hardening\UsernameBlacklist::OPTION_KEY, Hardening::OPTION_REST_NAMESPACES ) as $option ) {
					$list = $value( $option );
					if ( null !== $list ) {
						update_option( $option, Registry::to_stored_value( $registry[ $option ], $list ), $registry[ $option ]['autoload'] );
					}
				}
				break;

			case 'hide_login':
				// Order matters: the slug and redirect settle before the switch flips.
				foreach ( array( HideLogin::OPTION_SLUG, HideLogin::OPTION_REDIRECT_TYPE, HideLogin::OPTION_REDIRECT_URL ) as $option ) {
					$v = $value( $option );
					if ( null !== $v ) {
						update_option( $option, $v );
					}
				}
				$enabled = $value( HideLogin::OPTION_ENABLED );
				if ( null !== $enabled ) {
					update_option( HideLogin::OPTION_ENABLED, $enabled ? 1 : 0 );
				}
				break;
		}
		unset( $entries );
		return $warnings;
	}

	// ------------------------------------------------------------------
	// Group checks (plan time)
	// ------------------------------------------------------------------

	/**
	 * Effective value of an option after the import: incoming when present,
	 * else the current value.
	 *
	 * @param array<string,mixed> $state
	 */
	private static function effective( array $state, string $option ): mixed {
		if ( isset( $state['entries'][ $option ] ) ) {
			return $state['entries'][ $option ]['incoming'];
		}
		return Registry::read( $option );
	}

	/** @param array<string,mixed> $state */
	private static function set_incoming( array &$state, string $option, mixed $value ): void {
		if ( isset( $state['entries'][ $option ] ) ) {
			$state['entries'][ $option ]['incoming'] = $value;
		}
	}

	/** @param array<string,mixed> $state */
	private static function check_notifications( array &$state ): void {
		$channel = (string) self::effective( $state, 'login_armor_notif_channel' );
		if ( ! isset( $state['entries']['login_armor_notif_channel'] ) && ! isset( $state['entries']['login_armor_notif_webhook_url'] ) ) {
			return;
		}
		$url = (string) self::effective( $state, 'login_armor_notif_webhook_url' );
		if ( 'email' === $channel ) {
			$clean = Sanitizers::email( $url );
			if ( is_wp_error( $clean ) ) {
				$state['errors'][] = self::issue( 'notifications.webhook_url', __( 'for the email channel this must be an e-mail address (or empty for the admin address)', 'login-armor' ) );
				return;
			}
			self::set_incoming( $state, 'login_armor_notif_webhook_url', $clean );
			return;
		}
		if ( in_array( $channel, array( 'slack', 'discord', 'generic' ), true ) ) {
			$clean = Sanitizers::webhook_url( $url );
			if ( is_wp_error( $clean ) ) {
				$state['errors'][] = self::issue( 'notifications.webhook_url', '' === $url ? sprintf( /* translators: %s: channel name */ __( 'the %s channel needs a webhook URL (export with "include webhook URLs" or set it on this site first)', 'login-armor' ), $channel ) : $clean->get_error_message() );
				return;
			}
			self::set_incoming( $state, 'login_armor_notif_webhook_url', $clean );
		}
	}

	/** @param array<string,mixed> $state */
	private static function check_activity_webhook( array &$state ): void {
		if ( ! isset( $state['entries']['login_armor_webhook_enabled'] ) && ! isset( $state['entries']['login_armor_webhook_url'] ) ) {
			return;
		}
		$enabled = (bool) self::effective( $state, 'login_armor_webhook_enabled' );
		$url     = (string) self::effective( $state, 'login_armor_webhook_url' );
		if ( '' !== $url ) {
			$clean = Sanitizers::webhook_url( $url );
			if ( is_wp_error( $clean ) ) {
				$state['errors'][] = self::issue( 'activity_webhook.url', $clean->get_error_message() );
				return;
			}
			self::set_incoming( $state, 'login_armor_webhook_url', $clean );
		} elseif ( $enabled ) {
			$state['errors'][] = self::issue( 'activity_webhook.url', __( 'the activity webhook is enabled but has no URL (export with "include webhook URLs" or set it on this site first)', 'login-armor' ) );
			return;
		}
		if ( $enabled && '' === (string) get_option( WebhookDispatcher::OPTION_SECRET, '' ) ) {
			$state['warnings'][] = self::issue( 'activity_webhook', __( 'the signing secret is never transferred: this site will generate its own on first use; copy it to your SIEM from the Activity tab.', 'login-armor' ) );
		}
	}

	/** @param array<string,mixed> $state */
	private static function check_hide_login( array &$state ): void {
		$touched = false;
		foreach ( array( HideLogin::OPTION_ENABLED, HideLogin::OPTION_SLUG, HideLogin::OPTION_REDIRECT_TYPE, HideLogin::OPTION_REDIRECT_URL ) as $option ) {
			if ( isset( $state['entries'][ $option ] ) ) {
				$touched = true;
			}
		}
		if ( ! $touched ) {
			return;
		}
		foreach ( $state['errors'] as $error ) {
			if ( 'hide_login.slug' === $error['path'] ) {
				return; // The slug itself was refused; one error is enough.
			}
		}
		$enabled = (bool) self::effective( $state, HideLogin::OPTION_ENABLED );
		$slug    = (string) self::effective( $state, HideLogin::OPTION_SLUG );
		if ( $enabled && '' === $slug ) {
			$state['errors'][] = self::issue( 'hide_login.slug', __( 'Hide Login is enabled but no slug is set (neither in the file nor on this site)', 'login-armor' ) );
		}
		// 2.10.0: the screen refuses it, so does the import. Only a file that
		// switches Hide Login ON is refused: one that keeps it on, or off,
		// changes nothing about the conflict.
		$exclusive = HideLogin::get_exclusive_conflict();
		if ( $enabled && ! HideLogin::is_enabled() && false !== $exclusive ) {
			$state['errors'][] = self::issue(
				'hide_login.enabled',
				sprintf(
					/* translators: %s: plugin name, e.g. WPS Hide Login. */
					__( '%s already hides the login page on this site: deactivate it before importing a file that switches Hide Login on', 'login-armor' ),
					$exclusive
				)
			);
		}
		$type = (string) self::effective( $state, HideLogin::OPTION_REDIRECT_TYPE );
		if ( HideLogin::REDIRECT_URL !== $type ) {
			self::set_incoming( $state, HideLogin::OPTION_REDIRECT_URL, '' );
		}
	}

	/** @param array<string,mixed> $state */
	private static function check_two_factor( array &$state ): void {
		if ( isset( $state['entries']['login_armor_2fa_methods'] ) && empty( $state['entries']['login_armor_2fa_methods']['incoming'] ) ) {
			$state['errors'][] = self::issue( 'two_factor.methods', __( 'select at least one two-factor method (totp, email, backup): users cannot verify their sign-in without one', 'login-armor' ) );
		}
		if ( ! isset( $state['entries']['login_armor_2fa_enforce_roles'] ) ) {
			return;
		}
		$clean   = (array) $state['entries']['login_armor_2fa_enforce_roles']['incoming'];
		$raw     = $state['raw']['login_armor_2fa_enforce_roles'] ?? array();
		$dropped = array();
		foreach ( is_array( $raw ) ? $raw : array() as $role ) {
			if ( is_scalar( $role ) && ! in_array( (string) $role, $clean, true ) ) {
				$dropped[] = (string) $role;
			}
		}
		if ( ! empty( $dropped ) ) {
			$state['warnings'][] = self::issue( 'two_factor.enforce_roles', __( 'roles unknown on this site were ignored: ', 'login-armor' ) . implode( ', ', $dropped ) );
		}
		$user_id = (int) ( $state['context']['user_id'] ?? 0 );
		$enabled = (bool) self::effective( $state, 'login_armor_2fa_enabled' );
		if ( $user_id > 0 && $enabled && ! empty( $clean ) ) {
			$user = get_userdata( $user_id );
			if ( $user && ! empty( array_intersect( (array) $user->roles, $clean ) ) && ! TwoFactor::is_user_enabled( $user_id ) ) {
				$days = (int) self::effective( $state, 'login_armor_2fa_grace_days' );
				$state['warnings'][] = self::issue(
					'two_factor.enforce_roles',
					sprintf( /* translators: 1: user login, 2: grace days, 3: user login */ __( 'your own account (%1$s) has not enrolled in two-factor yet: you get a %2$d-day grace period, then sign-in is blocked until you enrol. Recovery: "wp login-armor 2fa reset %3$s" or the "Restart 2FA grace" action on the Users screen.', 'login-armor' ), $user->user_login, $days, $user->user_login )
				);
			}
		}
	}

	/** @param array<string,mixed> $state */
	private static function check_brute_force( array &$state ): void {
		$client_ip = (string) ( $state['context']['client_ip'] ?? '' );

		if ( isset( $state['entries']['login_armor_blocked_subnets'] ) ) {
			$subnets = (array) $state['entries']['login_armor_blocked_subnets']['incoming'];
			if ( ! empty( $subnets ) ) {
				$hit = '';
				foreach ( $subnets as $entry ) {
					if ( '' !== $client_ip && LoginArmor::ip_matches_proxy_entry( $client_ip, (string) $entry ) ) {
						$hit = (string) $entry;
						break;
					}
				}
				if ( '' !== $hit ) {
					$state['errors'][] = self::issue( 'brute_force.blocked_subnets', sprintf( /* translators: 1: subnet, 2: IP address */ __( 'the blocked subnet %1$s contains your own address (%2$s): importing it would lock you out', 'login-armor' ), $hit, $client_ip ) );
				} else {
					$state['warnings'][] = self::issue( 'brute_force.blocked_subnets', __( 'these subnets will be blocked on this site: ', 'login-armor' ) . implode( ', ', array_map( 'strval', $subnets ) ) );
				}
			}
		}

		if ( isset( $state['entries']['login_armor_whitelist_ips'] ) ) {
			$ips = (array) $state['entries']['login_armor_whitelist_ips']['incoming'];
			if ( ! empty( $ips ) ) {
				$state['warnings'][] = self::issue( 'brute_force.whitelist_ips', __( 'these addresses will never be locked out on this site: ', 'login-armor' ) . implode( ', ', array_map( 'strval', $ips ) ) );
			}
		}

		if ( isset( $state['entries']['login_armor_ip_method'] ) || isset( $state['entries']['login_armor_trusted_proxies'] ) ) {
			$method  = (string) self::effective( $state, 'login_armor_ip_method' );
			$proxies = (array) self::effective( $state, 'login_armor_trusted_proxies' );
			if ( 'REMOTE_ADDR' !== $method && empty( $proxies ) ) {
				// One sentence, one home: \LoginArmor\LoginArmor owns client
				// identity, and the Site Health test says the same thing about
				// a site that is already in this state.
				$state['warnings'][] = self::issue( 'brute_force.ip_method', \LoginArmor\LoginArmor::proxy_identity_warning( $method ) );
			}
		}
	}

	/**
	 * 2.7.0: Force HTTPS is the one hardening toggle that can make the admin
	 * unreachable. An import may only switch it ON when this site is
	 * demonstrably able to answer over TLS; switching it off is always
	 * allowed, because that is the documented rollback.
	 *
	 * @param array<string,mixed> $state
	 */
	private static function check_hardening( array &$state ): void {
		if ( ! isset( $state['entries'][ Hardening::OPTION_KEY ] ) ) {
			return;
		}
		$incoming = (array) $state['entries'][ Hardening::OPTION_KEY ]['incoming'];
		if ( empty( $incoming['force_https'] ) ) {
			return;
		}

		// The current state is read from the MODULE, not from the plan's own
		// `current`. Both should now agree, since Registry and Hardening share
		// one boolean rule, but this guard is the last thing between an import
		// and an unreachable admin: it asks the code that actually decides
		// whether the toggle is on, rather than a copy made upstream.
		if ( ! empty( Hardening::get_settings()['force_https'] ) ) {
			return;
		}

		$source = (string) ( $state['context']['source'] ?? 'admin' );
		if ( Hardening::can_import_force_https( $source, (string) home_url( '/' ), LoginArmor::request_is_https() ) ) {
			return;
		}

		$state['errors'][] = self::issue(
			'hardening.force_https',
			__( 'Force HTTPS can only be enabled from an HTTPS request or on a site whose address is HTTPS: importing it here would make the admin unreachable', 'login-armor' )
		);
	}

	/**
	 * 2.9.0: headless mode keeps two hardening toggles off. A file that itself
	 * asks for one of them on while the mode ends on is refused whole, like
	 * every other error of the importer. A toggle that is on only because the
	 * SITE has it on is not the file's doing: the preview says the mode will
	 * turn it off, and the incoming value is set to off so that preview and
	 * application agree.
	 *
	 * @param array<string,mixed> $state
	 */
	private static function check_headless( array &$state ): void {
		if ( ! (bool) self::effective( $state, 'login_armor_headless' ) ) {
			return;
		}

		$from_file = array();
		if ( isset( $state['entries'][ Hardening::OPTION_KEY ] ) ) {
			$raw_toggles = $state['raw'][ Hardening::OPTION_KEY ] ?? array();
			$from_file   = Headless::conflicts( is_array( $raw_toggles ) ? $raw_toggles : array() );
			foreach ( $from_file as $key ) {
				$state['errors'][] = self::issue(
					'hardening.toggles.' . $key,
					__( 'cannot be on while headless mode is on: it breaks the front end of a headless site', 'login-armor' )
				);
			}
			// What the site has on is switched off by the mode, not refused.
			$incoming = (array) $state['entries'][ Hardening::OPTION_KEY ]['incoming'];
			foreach ( Headless::conflicts( $incoming ) as $key ) {
				if ( ! in_array( $key, $from_file, true ) ) {
					$incoming[ $key ] = false;
				}
			}
			self::set_incoming( $state, Hardening::OPTION_KEY, $incoming );
		}

		if ( Headless::is_enabled() ) {
			return;
		}

		// The mode goes from off to on: Headless::enable() will turn off what
		// the stored toggles have on, whatever the hardening group of the file
		// says. Hardening::get_settings() reads the site unmasked while the
		// mode is off.
		$turned_off = Headless::conflicts( Hardening::get_settings() );
		if ( array() !== $turned_off ) {
			$state['warnings'][] = self::issue(
				'headless.enabled',
				sprintf(
					/* translators: %s: comma-separated list of hardening toggle names. */
					__( 'headless mode will turn off: %s', 'login-armor' ),
					implode( ', ', Headless::labels( $turned_off ) )
				)
			);
		}
	}

	/**
	 * Firewall and bot challenge: switching them on always lands in monitor
	 * mode, whatever the file says. The "never blocks the moment it is
	 * enabled" promise is per site.
	 *
	 * @param array<string,mixed> $state
	 */
	private static function check_monitor_modules( array &$state ): void {
		$modules = array(
			Firewall::OPTION_KEY     => array( 'firewall', Firewall::is_enabled(), __( 'request firewall', 'login-armor' ) ),
			PowChallenge::OPTION_KEY => array( 'bot_challenge', PowChallenge::is_enabled(), __( 'bot challenge', 'login-armor' ) ),
		);
		foreach ( $modules as $option => list( $path, $currently_on, $label ) ) {
			if ( ! isset( $state['entries'][ $option ] ) ) {
				continue;
			}
			$incoming = (array) $state['entries'][ $option ]['incoming'];
			if ( ! empty( $incoming['enabled'] ) && ! $currently_on && 'enforce' === ( $incoming['mode'] ?? '' ) ) {
				$incoming['mode'] = 'log_only';
				$state['entries'][ $option ]['incoming'] = $incoming;
				$state['warnings'][] = self::issue( $path . '.mode', sprintf( /* translators: %s: module name */ __( 'the %s is being switched on by this import, so it starts in monitor mode; review its log on this site, then flip it to enforce', 'login-armor' ), $label ) );
			}
		}
	}

	// ------------------------------------------------------------------
	// Helpers
	// ------------------------------------------------------------------

	/**
	 * Login URL this site will answer on once the planned Hide Login values
	 * are applied. Mirrors HideLogin::get_login_url() without writing.
	 *
	 * @param array<string,array<string,mixed>> $entries
	 */
	private static function predict_login_url( array $entries ): string {
		$enabled = isset( $entries[ HideLogin::OPTION_ENABLED ] ) ? (bool) $entries[ HideLogin::OPTION_ENABLED ]['incoming'] : HideLogin::is_enabled();
		$slug    = isset( $entries[ HideLogin::OPTION_SLUG ] ) ? (string) $entries[ HideLogin::OPTION_SLUG ]['incoming'] : (string) get_option( HideLogin::OPTION_SLUG, '' );
		if ( ! $enabled || '' === $slug ) {
			return wp_login_url();
		}
		if ( get_option( 'permalink_structure' ) ) {
			return HideLogin::build_login_url( '/' . $slug . '/' );
		}
		return HideLogin::build_login_url( '/' ) . '?' . $slug;
	}

	/**
	 * Record the import in the activity log when the module is on. Called
	 * directly rather than through a hook: when the import itself just
	 * enabled the log, no logger is wired in this request yet.
	 *
	 * @param array<string,mixed> $summary
	 */
	private static function record_activity( array $summary, int $user_id ): void {
		if ( ! class_exists( ActivityLog::class ) || ! ActivityLog::is_enabled() ) {
			return;
		}
		if ( ! class_exists( \LoginArmor\ActivityLog\Loggers\SettingsLogger::class ) ) {
			require_once LOGIN_ARMOR_DIR . 'includes/ActivityLog/ActivityLogger.php';
			require_once LOGIN_ARMOR_DIR . 'includes/ActivityLog/Loggers/SettingsLogger.php';
		}
		( new \LoginArmor\ActivityLog\Loggers\SettingsLogger() )->on_imported( $summary, $user_id );
	}

	/**
	 * @param array<string,mixed> $entry
	 */
	private static function path( array $entry ): string {
		return null === $entry['key'] ? (string) $entry['group'] : $entry['group'] . '.' . $entry['key'];
	}

	private static function field_suffix( \WP_Error $error ): string {
		foreach ( $error->errors as $e ) {
			if ( 'field' === ( $e['code'] ?? '' ) ) {
				return '.' . $e['message'];
			}
		}
		return '';
	}

	/**
	 * @return array{path:string,message:string}
	 */
	private static function issue( string $path, string $message ): array {
		return array(
			'path'    => $path,
			'message' => $message,
		);
	}
}
