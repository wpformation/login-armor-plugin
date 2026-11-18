<?php
/**
 * Login Armor
 *
 * @package     LoginArmor
 * @author      Fabrice Ducarme
 * @copyright   2025 Fabrice Ducarme
 * @license     GPLv2 or later
 *
 * @wordpress-plugin
 * Plugin Name: Login Armor
 * Plugin URI:  https://wpformation.com/login-armor
 * Description: Hide your login URL, block brute force attacks, harden WordPress, and monitor all admin activity.
 * Version:     2.10.1
 * Author:      Fabrice Ducarme
 * Author URI:  https://wpformation.com
 * License:     GPLv2 or later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain: login-armor
 * Domain Path: /languages
 * Requires at least: 6.8
 * Requires PHP: 8.1
 * Network:     true
 */

// Exit if accessed directly.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

// Plugin constants.
define( 'LOGIN_ARMOR_VERSION', '2.10.1' );
define( 'LOGIN_ARMOR_FILE', __FILE__ );
define( 'LOGIN_ARMOR_DIR', plugin_dir_path( __FILE__ ) );
define( 'LOGIN_ARMOR_URL', plugin_dir_url( __FILE__ ) );
define( 'LOGIN_ARMOR_BASENAME', plugin_basename( __FILE__ ) );

// Load main class.
require_once LOGIN_ARMOR_DIR . 'includes/class-login-armor.php';

// Read the break-glass constant ONCE, here, before this file registers a
// single hook. Safe mode is consulted from `authenticate`, `init` and
// `wp_loaded`, all of which run long after themes load: a predicate that
// re-read LOGIN_ARMOR_SAFE_MODE on every call could be armed by one define()
// in a theme's functions.php, which is precisely the kind of code an attacker
// gets to write. Taking the answer here fixes it before anything can run, so
// only wp-config.php, a must-use plugin or an earlier-loading plugin can arm
// it, and all three need write access to the filesystem.
\LoginArmor\LoginArmor::snapshot_safe_mode();

// WordPress's recovery-mode link, when Hide Login has put it on the hidden
// URL: taken here, before any hook runs, because the link is mailed when
// something fatals and the fatal may sit in a plugins_loaded callback. See
// HideLogin::begin_recovery_mode_early(). Nothing is loaded without the
// link's own parameters.
// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Presence test only; core validates the recovery key and token.
if ( isset( $_GET['rm_token'], $_GET['rm_key'] ) ) {
	require_once LOGIN_ARMOR_DIR . 'includes/class-hide-login.php';
	\LoginArmor\HideLogin::begin_recovery_mode_early();
}

// Activation and deactivation hooks.
register_activation_hook( __FILE__, [ \LoginArmor\LoginArmor::class, 'activate' ] );
register_deactivation_hook( __FILE__, [ \LoginArmor\LoginArmor::class, 'deactivate' ] );

// Initialize plugin after all plugins are loaded.
add_action( 'plugins_loaded', static function (): void {
	\LoginArmor\LoginArmor::get_instance();
} );
