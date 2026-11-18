<?php
/**
 * LoginArmor Uninstall Handler.
 *
 * Cleans up all plugin data when the plugin is deleted through the
 * WordPress admin interface. Removes database tables and options.
 *
 * @package LoginArmor
 * @since   1.0.0
 */

// Exit if not called by WordPress uninstall.
if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
	exit;
}

/**
 * Every cron hook the plugin can schedule, on any site.
 *
 * Keep in sync with LoginArmor::CRON_HOOKS (includes/class-login-armor.php).
 * uninstall.php runs with the plugin unloaded, so the class constant is
 * unreachable here and the list has to be repeated literally. The two lists
 * are asserted identical by tests/multisite-cycle.php.
 *
 * @since 2.6.1
 *
 * @return string[]
 */
function login_armor_uninstall_cron_hooks(): array {
	return array(
		'login_armor_purge_logs',
		'login_armor_security_counters_purge',
		'login_armor_chain_repair',
		'login_armor_chain_auto_verify',
		'login_armor_webhook_dispatch',
		'login_armor_activity_purge',
		'login_armor_2fa_trusted_devices_cleanup',
		'login_armor_cleanup_rate_key',
		'login_armor_geoip_prefetch',
		'login_armor_notif_digest',
		'login_armor_app_password_review',
	);
}

/**
 * One page of site ids, ascending.
 *
 * Keep in sync with LoginArmor::each_site(): same page size, same ordering,
 * same meta-cache opt-out. get_sites() caps `number` at 100 when it is not
 * given, so the bare get_sites( [ 'fields' => 'ids' ] ) this replaces left the
 * data of site 101 and beyond on disk forever.
 *
 * @since 2.6.1
 *
 * @param int $offset Rows to skip.
 * @param int $number Page size.
 * @return int[]
 */
function login_armor_uninstall_site_ids( int $offset, int $number = 100 ): array {
	$ids = get_sites(
		array(
			'fields'                 => 'ids',
			'number'                 => $number,
			'offset'                 => $offset,
			'orderby'                => 'id',
			'order'                  => 'ASC',
			'update_site_meta_cache' => false,
		)
	);

	return is_array( $ids ) ? $ids : array();
}

/**
 * Load the class that owns the .htaccess blocks (2.8.0).
 *
 * uninstall.php runs with the plugin unloaded. The class file only declares
 * the class, and its block removers need nothing else from the plugin.
 */
function login_armor_uninstall_load_hardening(): void {
	if ( ! class_exists( 'LoginArmor\Hardening', false ) ) {
		require_once __DIR__ . '/includes/class-hardening.php';
	}
}

/**
 * Remove all plugin data for a single site.
 */
function login_armor_uninstall_site(): void {
	global $wpdb;

	// 2.8.0: the uploads .htaccess block of this site goes with the plugin.
	// Until 2.7.10 it outlived the uninstall, a server rule nobody could trace
	// back any more. Only the marked block is removed: the administrator's own
	// rules and the .bak restore point stay (see the readme FAQ). Done first,
	// while the options a failure record would be written to still exist.
	login_armor_uninstall_load_hardening();
	\LoginArmor\Hardening::remove_htaccess_blocks( false );

	// Drop custom tables.
	// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.DirectDatabaseQuery.SchemaChange -- Uninstall cleanup of plugin-owned tables.
	$wpdb->query( "DROP TABLE IF EXISTS {$wpdb->prefix}login_armor_attempts" );
	// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.DirectDatabaseQuery.SchemaChange -- Uninstall cleanup of plugin-owned tables.
	$wpdb->query( "DROP TABLE IF EXISTS {$wpdb->prefix}login_armor_logs" );
	// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.DirectDatabaseQuery.SchemaChange -- Uninstall cleanup of plugin-owned tables.
	$wpdb->query( "DROP TABLE IF EXISTS {$wpdb->prefix}login_armor_incidents" );
	// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.DirectDatabaseQuery.SchemaChange -- Uninstall cleanup of plugin-owned tables.
	$wpdb->query( "DROP TABLE IF EXISTS {$wpdb->prefix}login_armor_activity" );
	// V2.1.1: drop webhook queue table (added in V2.1.5 cleanup).
	// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.DirectDatabaseQuery.SchemaChange -- Uninstall cleanup of plugin-owned tables.
	$wpdb->query( "DROP TABLE IF EXISTS {$wpdb->prefix}login_armor_webhook_queue" );
	// 2.9.0: application-password usage journal.
	// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.DirectDatabaseQuery.SchemaChange -- Uninstall cleanup of plugin-owned tables.
	$wpdb->query( "DROP TABLE IF EXISTS {$wpdb->prefix}login_armor_app_password_usage" );

	// Delete all plugin options.
	$options = [
		'login_armor_hide_slug',
		'login_armor_hide_enabled',
		'login_armor_redirect_url',
		'login_armor_redirect_type',
		'login_armor_allowed_retries',
		'login_armor_lockout_duration',
		'login_armor_max_lockouts',
		'login_armor_long_duration',
		'login_armor_lockout_window',
		'login_armor_valid_duration',
		'login_armor_whitelist_ips',
		'login_armor_notify_email',
		'login_armor_notify_threshold',
		'login_armor_limit_enabled',
		'login_armor_detection_enabled',
		'login_armor_log_retention_days',
		'login_armor_auto_purge',
		'login_armor_logs_auto_purge',
		'login_armor_blocked_subnets',
		'login_armor_db_version',
		'login_armor_notif_channel',
		'login_armor_notif_webhook_url',
		'login_armor_notif_min_severity',
		'login_armor_notif_rate_limit',
		'login_armor_last_notif_error',
		'login_armor_notif_suppressed',
		// 2.7.0 : scheduled digest. The first name is both an option and a
		// cron hook; the two live in different tables and both are cleaned.
		'login_armor_notif_digest',
		'login_armor_notif_digest_last',
		'login_armor_notif_digest_failures',
		'login_armor_notif_digest_lock',
		'login_armor_https_terminator_undeclared',
		// 2.7.0 : when a test alert was last delivered from this site.
		'login_armor_notif_last_test_ok',
		'login_armor_activity_enabled',
		'login_armor_activity_retention',
		'login_armor_ip_method',
		'login_armor_trusted_proxies',
		'login_armor_hardening',
		'login_armor_headless',
		// 2.9.0: application-password monitoring.
		'login_armor_app_password_watch',
		'login_armor_app_password_watch_since',
		'login_armor_app_password_days',
		// 2.10.0: digest recipient, syslog lines for fail2ban.
		'login_armor_notif_digest_to',
		'login_armor_syslog',
		// 2.7.0 : the last .htaccess file this site could not write, or whose
		// markers it refused to touch. Read by the Site Health test, which
		// runs long after the five-minute transients have gone.
		'login_armor_htaccess_last_failure',
		// 2.7.2 : an AI analysis the incidents table would not take, almost
		// always a column the schema never received. Same reasoning as the
		// .htaccess record above: durable, because the symptom is noticed long
		// after the write failed.
		'login_armor_schema_last_failure',
		// Lot 14, Hardening: Username Blacklist.
		'login_armor_hardening_username_blacklist',
		// 2.5.1 : Hardening, public REST namespaces allowlist.
		'login_armor_hardening_rest_namespaces',
		'login_armor_activation_acknowledged',
		// V2.1.1: Activity Log integrity chain (added in V2.1.5 cleanup).
		'login_armor_v211_chain_initialized',
		'login_armor_activity_chain_start_id',
		// V2.1.1: Activity Log auto-verify cron flag (added in V2.1.6 cleanup).
		'login_armor_activity_auto_verify_daily',
		// V2.1.1: Admin notice flag for chain initialization (added in V2.1.6 cleanup).
		'login_armor_v211_show_chain_init_notice',
		// V2.1.1: Webhook dispatcher (added in V2.1.5 cleanup).
		'login_armor_webhook_enabled',
		'login_armor_webhook_url',
		'login_armor_webhook_secret',
		'login_armor_webhook_consecutive_failures',
		'login_armor_webhook_last_dead_notice',
		// V2.0.5: Login Page Security Headers (added in V2.1.6 cleanup).
		'login_armor_login_headers_hsts',
		'login_armor_login_headers_preset',
		'login_armor_2fa_enabled',
		'login_armor_2fa_methods',
		'login_armor_2fa_enforce_roles',
		'login_armor_2fa_grace_days',
		// Lot 16: 2FA Trusted Devices.
		'login_armor_2fa_trusted_devices_enabled',
		'login_armor_2fa_trusted_devices_duration_days',
		// Lot 16: 2FA Recovery.
		'login_armor_2fa_recovery_enabled',
		// Lot 13: Login Page Security Headers.
		'login_armor_login_headers_enabled',
		'login_armor_login_headers_mode',
		'login_armor_login_headers_report_uri',
		// Lot 21: Breach Check.
		'login_armor_breach_check_enabled',
		'login_armor_breach_check_passwords',
		'login_armor_breach_check_emails',
		'login_armor_breach_check_force_reset',
		// V2.1.x: Activity Log chain salt fingerprint (added in V2.4.2 cleanup).
		'login_armor_activity_chain_salt_fp',
		// V2.2.0: AI Security Briefing (added in V2.4.2 cleanup).
		'login_armor_ai_enabled',
		'login_armor_ai_usage',
		'login_armor_ai_deep',
		// V2.3.0: Password Policy, Session Management, GeoIP, site-wide headers (added in V2.4.2 cleanup).
		'login_armor_password_policy',
		'login_armor_session',
		'login_armor_geoip_enabled',
		'login_armor_headers_sitewide',
		// V2.4.0: Request Firewall + onboarding flag (added in V2.4.2 cleanup).
		'login_armor_firewall',
		'login_armor_onboarded',
		// V2.5.0: Bot Challenge (Proof-of-Work) settings + soft-failure counter.
		'login_armor_pow',
		'login_armor_pow_softfails',
		// 2.6.1 : per-site provisioning lock (INSERT IGNORE claim row, never
		// autoloaded). Normally deleted in a finally block; a request killed
		// mid-provisioning can leave one behind.
		'login_armor_provision_lock',
		// 2.6.1 : single-worker lock of the GeoIP prefetch pass (INSERT IGNORE
		// claim row, never autoloaded). Normally deleted in a finally block; a
		// cron request killed mid-pass can leave one behind.
		'login_armor_geoip_prefetch_lock',
		// 2.6.1 : activity watermark that lets a quiet site skip a resolver
		// pass. Per-site bookkeeping, never autoloaded.
		'login_armor_geoip_watermark',
		// 2.7.1 : the set of caching plugins whose exclusion an administrator
		// confirmed, so the cache notice stops coming back. Never autoloaded,
		// per site, and meaningless once the plugin is gone.
		'login_armor_cache_notice_dismissed',
		// Legacy pre-release option name for the hardening toggles (superseded
		// by login_armor_hardening; still present on very early installs).
		'login_armor_hardening_options',
	];

	foreach ( $options as $option ) {
		delete_option( $option );
	}

	// V2.4.4: per-IP lockout claim rows (atomic-claim bookkeeping, one option
	// per locked IP, non-autoloaded).
	// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Uninstall cleanup.
	$wpdb->query(
		"DELETE FROM {$wpdb->options} WHERE option_name LIKE 'login_armor_lockout_claim_%'"
	);

	// V2.4.7 - security rate-limit counters, one-time TOTP steps and recovery claims.
	// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Uninstall cleanup.
	$wpdb->query(
		"DELETE FROM {$wpdb->options} WHERE option_name LIKE 'login_armor_hibp_public_rate_%' OR option_name LIKE 'login_armor_2fa_recovery_claim_%' OR option_name LIKE 'login_armor_2fa_account_failures_%' OR option_name LIKE 'login_armor_2fa_ip_atomic_%' OR option_name LIKE 'login_armor_2fa_totp_step_%'"
	);

	// V2.5.0 - Bot Challenge per-IP issuance rate-limit counters.
	// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Uninstall cleanup.
	$wpdb->query(
		"DELETE FROM {$wpdb->options} WHERE option_name LIKE 'login_armor_pow_rl_%'"
	);

	// Remove per-user theme preferences (v2.0.0).
	// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Uninstall cleanup of plugin-owned user meta.
	$wpdb->query(
		$wpdb->prepare(
			"DELETE FROM {$wpdb->usermeta} WHERE meta_key = %s",
			'login_armor_theme'
		)
	);

	// Remove Lot 21: Breach Check per-user flags (v2.0.5).
	$la_breach_meta_keys = array(
		'login_armor_breach_password_flagged',
		'login_armor_breach_password_count',
		'login_armor_breach_email_flagged',
		'login_armor_breach_email_breaches',
		'login_armor_breach_email_last_check',
		'login_armor_breach_last_check',
		'login_armor_breach_force_reset_needed',
	);
	foreach ( $la_breach_meta_keys as $la_breach_meta_key ) {
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Uninstall cleanup of plugin-owned user meta.
		$wpdb->query(
			$wpdb->prepare(
				"DELETE FROM {$wpdb->usermeta} WHERE meta_key = %s",
				$la_breach_meta_key
			)
		);
	}

	// Remove Lot 12: Obfuscate Author Slugs cached tokens.
	// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Uninstall cleanup of plugin-owned user meta.
	$wpdb->query(
		$wpdb->prepare(
			"DELETE FROM {$wpdb->usermeta} WHERE meta_key = %s",
			'login_armor_author_slug'
		)
	);

	// Remove Lot 17: Overview "All quiet" skipped-advice preferences.
	delete_metadata( 'user', 0, 'login_armor_skipped_advice', '', true );

	// Remove Lot 16: 2FA Trusted Devices per-user records.
	delete_metadata( 'user', 0, 'login_armor_2fa_trusted_devices', '', true );

	// Remove Lot 16: 2FA Recovery per-user rate-limit timestamps.
	delete_metadata( 'user', 0, 'login_armor_2fa_recovery_sent_at', '', true );

	// Remove V2.3.0: Password Policy set-at timestamps + Session last-active markers (added in V2.4.2 cleanup).
	delete_metadata( 'user', 0, 'login_armor_password_set_at', '', true );
	delete_metadata( 'user', 0, 'login_armor_last_active', '', true );

	// Delete 2FA user meta.
	$la_2fa_meta_keys = [
		'login_armor_2fa_enabled',
		'login_armor_2fa_method',
		'login_armor_2fa_secret',
		'login_armor_2fa_confirmed',
		'login_armor_2fa_backup_codes',
		'login_armor_2fa_grace_until',
		'login_armor_2fa_last_totp_step',
	];
	foreach ( $la_2fa_meta_keys as $la_2fa_key ) {
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Uninstall cleanup of plugin-owned user meta.
		$wpdb->query(
			$wpdb->prepare(
				"DELETE FROM {$wpdb->usermeta} WHERE meta_key = %s",
				$la_2fa_key
			)
		);
	}

	// Clear any transients.
	delete_transient( 'login_armor_settings_errors' );
	delete_transient( 'login_armor_activation_acknowledged' );
	// 2.6.1 : daily gate of the admin-side cron self-check.
	delete_transient( 'login_armor_crons_checked' );

	// V2.1.6: generalized catch-all for any login_armor_* transient
	// (covers 2fa_pending, email_otp, chain_verify_last, and any future
	// transient added without updating uninstall.php).
	// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Uninstall cleanup.
	$wpdb->query(
		"DELETE FROM {$wpdb->options} WHERE option_name LIKE '_transient_login_armor_%' OR option_name LIKE '_transient_timeout_login_armor_%'"
	);

	// V2.4.2: short-prefix transients (Breach Check + GeoIP caches use the
	// compact `la_` prefix; targeted per-family to avoid touching options of
	// unrelated plugins that might also start with `la_`).
	//
	// 2.6.1 : la_geoip_retry_ (the one-hour marker of a TEMPORARY geolocation
	// failure) is named explicitly even though la_geoip_% already covers it.
	// The family is what tests/uninstall-coverage.php reads, and an explicit
	// line is what survives a future narrowing of the geoip prefix.
	// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Uninstall cleanup.
	$wpdb->query(
		"DELETE FROM {$wpdb->options} WHERE option_name LIKE '_transient_la_breach_pwd_%' OR option_name LIKE '_transient_timeout_la_breach_pwd_%' OR option_name LIKE '_transient_la_breach_email_%' OR option_name LIKE '_transient_timeout_la_breach_email_%' OR option_name LIKE '_transient_la_geoip_%' OR option_name LIKE '_transient_timeout_la_geoip_%' OR option_name LIKE '_transient_la_geoip_retry_%' OR option_name LIKE '_transient_timeout_la_geoip_retry_%'"
	);

	// Clear notification rate-limit transients (current and recent hours).
	for ( $i = 0; $i < 3; $i++ ) {
		delete_transient( 'login_armor_notif_count_' . gmdate( 'YmdH', time() - $i * HOUR_IN_SECONDS ) );
	}

	// 2.6.1 : scheduled events belong to the site, exactly like the tables and
	// the options above. Until 2.6.0 they were cleared once, after the loop,
	// which on multisite meant the current site only: every other site of the
	// network kept firing five events at a plugin that no longer existed.
	// 2.8.0: wp_unschedule_hook() removes the events of a hook whatever
	// their arguments; wp_clear_scheduled_hook() without arguments left the
	// login_armor_cleanup_rate_key events, which carry one, behind.
	foreach ( login_armor_uninstall_cron_hooks() as $la_cron_hook ) {
		wp_unschedule_hook( $la_cron_hook );
	}
}

// 2.8.0: the root .htaccess blocks (directory listing, system files) are
// shared by the whole network, so they are removed once, before the sites
// are walked: a failure record it leaves is then deleted with the options.
login_armor_uninstall_load_hardening();
\LoginArmor\Hardening::remove_htaccess_blocks( true );

// Handle multisite uninstall, one page of sites at a time.
if ( is_multisite() ) {
	$login_armor_offset = 0;

	do {
		$login_armor_site_ids = login_armor_uninstall_site_ids( $login_armor_offset );
		if ( array() === $login_armor_site_ids ) {
			break;
		}

		foreach ( $login_armor_site_ids as $login_armor_site_id ) {
			switch_to_blog( (int) $login_armor_site_id );
			login_armor_uninstall_site();
			restore_current_blog();
		}

		$login_armor_offset += 100;
	} while ( count( $login_armor_site_ids ) === 100 );
} else {
	login_armor_uninstall_site();
}

// Defense in depth. The loop above already cleared the current site, and every
// other one; this repeats the gesture for the site the uninstall runs on, so a
// network that fails halfway through still leaves nothing scheduled here.
foreach ( login_armor_uninstall_cron_hooks() as $login_armor_cron_hook ) {
	wp_unschedule_hook( $login_armor_cron_hook );
}
