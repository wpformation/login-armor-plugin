<?php
/**
 * Syslog lines for fail2ban (2.10.0).
 *
 * Opt-in (`login_armor_syslog`, off by default). Once on, one line per
 * failure that counts toward the lockout and one per lockout, in a stable
 * format a fail2ban filter can match whatever the web server logs:
 *
 *     login-armor[<pid>]: auth_failure ip=<address> vector=<form|xmlrpc|rest|other> reason=<code>
 *     login-armor[<pid>]: lockout ip=<address> level=<1|2>
 *
 * Never the login typed. Wrong application passwords of a known account never
 * reach these lines, since they do not count: fail2ban would ban the site's
 * own integrations. Allow-listed addresses never count either. The plugin
 * writes the lines; configuring fail2ban stays a root task (readme FAQ).
 *
 * @package LoginArmor
 */

namespace LoginArmor\Support;

use LoginArmor\LoginArmor;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * One stable syslog line per counted failure and per lockout.
 */
final class Syslog {

	/** The setting. */
	public const OPTION = 'login_armor_syslog';

	/** Failure codes written as they are; any other is written "other". */
	public const REASONS = array( 'incorrect_password', 'invalid_username', 'invalid_email', 'empty_username', 'empty_password', 'authentication_failed', 'spammer_account' );

	/** Vectors written as they are; any other is written "other". */
	public const VECTORS = array( 'form', 'xmlrpc', 'rest', 'other' );

	/** Whether the administrator switched the lines on. */
	public static function is_enabled(): bool {
		return LoginArmor::to_bool( get_option( self::OPTION, 0 ) );
	}

	/** Whether this PHP can write to the system log at all (hosts may disable it). */
	public static function is_available(): bool {
		return function_exists( 'openlog' ) && function_exists( 'syslog' ) && function_exists( 'closelog' );
	}

	/**
	 * A failure that counts toward the lockout.
	 *
	 * @param string $ip    Client address.
	 * @param mixed  $error The failure (WP_Error expected).
	 */
	public static function failure( string $ip, $error = null ): void {
		if ( ! self::is_enabled() ) {
			return;
		}
		$code = $error instanceof \WP_Error ? (string) $error->get_error_code() : '';
		self::write( self::line_failure( $ip, self::vector(), $code ) );
	}

	/**
	 * A lockout.
	 *
	 * @param string $ip    Locked address.
	 * @param int    $level Lockout level, 1 or 2.
	 */
	public static function lockout( string $ip, int $level ): void {
		if ( ! self::is_enabled() ) {
			return;
		}
		self::write( self::line_lockout( $ip, $level ) );
	}

	/** Where the failure came from. */
	public static function vector(): string {
		if ( doing_action( 'application_password_failed_authentication' ) ) {
			return 'rest';
		}
		if ( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST ) {
			return 'xmlrpc';
		}
		if ( defined( 'REST_REQUEST' ) && REST_REQUEST ) {
			return 'rest';
		}
		if ( class_exists( \LoginArmor\Lockout\LockoutPage::class, false ) && \LoginArmor\Lockout\LockoutPage::is_login_form_request() ) {
			return 'form';
		}
		return 'other';
	}

	/**
	 * The failure line, or '' for an address that is not one.
	 *
	 * @param string $ip     Client address.
	 * @param string $vector Where it came from.
	 * @param string $code   Failure code.
	 */
	public static function line_failure( string $ip, string $vector, string $code ): string {
		if ( false === filter_var( $ip, FILTER_VALIDATE_IP ) ) {
			return '';
		}
		$vector = in_array( $vector, self::VECTORS, true ) ? $vector : 'other';
		$reason = in_array( $code, self::REASONS, true ) ? $code : 'other';
		return 'auth_failure ip=' . $ip . ' vector=' . $vector . ' reason=' . $reason;
	}

	/**
	 * The lockout line, or '' for an address that is not one.
	 *
	 * @param string $ip    Locked address.
	 * @param int    $level Lockout level.
	 */
	public static function line_lockout( string $ip, int $level ): string {
		if ( false === filter_var( $ip, FILTER_VALIDATE_IP ) ) {
			return '';
		}
		return 'lockout ip=' . $ip . ' level=' . ( $level >= 2 ? 2 : 1 );
	}

	/**
	 * Write one line under the `login-armor` identity, facility auth.
	 *
	 * The filter `login_armor_syslog_writer` may return a callable that
	 * receives the line instead (tests, or a host that routes it elsewhere).
	 *
	 * @param string $line The line, without the identity prefix.
	 */
	public static function write( string $line ): void {
		if ( '' === $line ) {
			return;
		}
		$writer = apply_filters( 'login_armor_syslog_writer', null );
		if ( is_callable( $writer ) ) {
			$writer( $line );
			return;
		}
		if ( ! self::is_available() ) {
			return;
		}
		openlog( 'login-armor', LOG_PID | LOG_ODELAY, LOG_AUTH );
		syslog( LOG_NOTICE, $line );
		closelog();
	}
}
