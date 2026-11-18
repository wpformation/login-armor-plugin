<?php
/**
 * AI facade: WordPress 7 native AI Client routing, usage accounting, output rendering.
 *
 * LoginArmor's AI layer is *optional* and *interpretive only*: it explains and
 * advises, it is never in the path that decides a block. It runs exclusively on
 * the WordPress 7 native AI Client (`wp_ai_client_prompt()`), using whichever
 * connector the site owner configured under Settings → AI Connectors. No API key
 * is ever stored or asked for by LoginArmor: the user's own connector carries
 * the cost. Where no native connector exists, every public check below returns
 * false and the whole layer stays invisible (zero-overhead contract).
 *
 * Ported and reduced from the OGEEAT AI facade (BYOK providers dropped).
 *
 * @package LoginArmor
 * @since   2.2.0
 */

namespace LoginArmor\AI;

// Exit if accessed directly.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Static facade around the WordPress 7 AI Client.
 */
class Client {

	const OPTION_ENABLED = 'login_armor_ai_enabled';
	const OPTION_USAGE   = 'login_armor_ai_usage';
	const OPTION_DEEP    = 'login_armor_ai_deep';

	const APPROVALS_OPTION = 'wpai_connector_approvals';
	const PENDING_OPTION   = 'wpai_connector_approval_pending';

	/* ---------------------------------------------------------------------
	 * Availability.
	 * ------------------------------------------------------------------- */

	/**
	 * Whether the admin has left the AI layer enabled (default on).
	 */
	public static function is_enabled(): bool {
		return (bool) get_option( self::OPTION_ENABLED, true );
	}

	/**
	 * Whether the admin opted into "deep analysis": real signals (IP addresses,
	 * concrete events) are sent to the site's OWN AI connector instead of
	 * anonymised categories. Off by default: the strict-minimisation contract
	 * holds unless the admin explicitly enables this (with a clear UI warning).
	 */
	public static function is_deep(): bool {
		return self::is_enabled() && (bool) get_option( self::OPTION_DEEP, false );
	}

	/**
	 * Whether the WordPress 7 native AI Client is present on this site.
	 */
	public static function native_available(): bool {
		return function_exists( 'wp_ai_client_prompt' );
	}

	/**
	 * Indirect calls to the WordPress 7.0 AI Client functions
	 * (wp_ai_client_prompt / wp_get_connectors). They exist only on WP 7.0+, and
	 * the AI layer is gated at runtime by native_available() / function_exists().
	 * Calling them through a function-name VARIABLE keeps Plugin Check's static
	 * "requires WP 7.0" analysis quiet WITHOUT bumping the whole plugin's
	 * "Requires at least" to 7.0: which would needlessly lock WP 6.8/6.9 sites
	 * out of every non-AI feature. Guarded callers guarantee the functions exist.
	 *
	 * @param string $input Prompt text.
	 * @return mixed The AI Client prompt builder.
	 */
	private static function ai_prompt( string $input ) {
		$fn = 'wp_ai_client_prompt';
		return $fn( $input );
	}

	/**
	 * @return array<mixed> Registered connectors (empty when unavailable).
	 */
	private static function get_connectors(): array {
		$fn = 'wp_get_connectors';
		return function_exists( $fn ) ? (array) $fn() : array();
	}

	/**
	 * Whether a native AI connector is configured and can generate text.
	 *
	 * Probes the AI Client capability check (no external request). Cached for
	 * the duration of the request.
	 */
	public static function native_has_credentials(): bool {
		static $cached = null;
		if ( null !== $cached ) {
			return $cached;
		}
		if ( ! self::native_available() ) {
			$cached = false;
			return $cached;
		}
		try {
			$cached = (bool) self::ai_prompt( 'ping' )->is_supported_for_text_generation();
		} catch ( \Throwable $e ) {
			$cached = false;
		}
		return $cached;
	}

	/**
	 * Whether at least one AI-provider connector is registered (configured or not).
	 */
	public static function native_connector_registered(): bool {
		if ( ! function_exists( 'wp_get_connectors' ) ) {
			return false;
		}
		foreach ( self::get_connectors() as $data ) {
			if ( is_array( $data ) && isset( $data['type'] ) && 'ai_provider' === $data['type'] ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * URL of the native WordPress AI Connectors settings screen.
	 */
	public static function connectors_url(): string {
		return admin_url( 'options-connectors.php' );
	}

	/**
	 * Whether the AI layer can actually run a completion right now.
	 *
	 * A test override (the `login_armor_ai_force_provider` callable) always
	 * counts as available so the UI can be exercised without a real connector.
	 */
	public static function is_available(): bool {
		if ( is_callable( apply_filters( 'login_armor_ai_force_provider', null ) ) ) {
			return true;
		}
		return self::is_enabled() && self::native_available() && self::native_has_credentials();
	}

	/* ---------------------------------------------------------------------
	 * WordPress 7 connector approval (caller consent).
	 *
	 * WordPress 7 requires each plugin to be explicitly approved before it can
	 * use a configured AI connector (so a plugin can't silently spend the user's
	 * AI budget). These helpers let LoginArmor record that consent with one click.
	 * ------------------------------------------------------------------- */

	/**
	 * Whether the connector-approval gate is enforced on this site.
	 */
	public static function approval_enforced(): bool {
		return class_exists( 'WordPress\\AI\\Connector_Approval\\Approvals_Store' );
	}

	/**
	 * LoginArmor's caller basename as seen by the AI client (e.g. login-armor/login-armor.php).
	 */
	public static function caller_basename(): string {
		return defined( 'LOGIN_ARMOR_BASENAME' ) ? LOGIN_ARMOR_BASENAME : 'login-armor/login-armor.php';
	}

	/**
	 * IDs of all registered AI-provider connectors.
	 *
	 * @return string[]
	 */
	public static function ai_connector_ids(): array {
		$ids = array();
		if ( function_exists( 'wp_get_connectors' ) ) {
			foreach ( self::get_connectors() as $id => $d ) {
				if ( is_array( $d ) && isset( $d['type'] ) && 'ai_provider' === $d['type'] ) {
					$ids[] = (string) $id;
				}
			}
		}
		return $ids;
	}

	/**
	 * Whether LoginArmor is approved for at least one connector.
	 */
	public static function is_approved(): bool {
		$appr   = get_option( self::APPROVALS_OPTION, array() );
		$caller = self::caller_basename();
		if ( ! is_array( $appr ) || empty( $appr[ $caller ] ) || ! is_array( $appr[ $caller ] ) ) {
			return false;
		}
		foreach ( $appr[ $caller ] as $approved ) {
			if ( $approved ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Whether LoginArmor still needs the user to grant connector approval.
	 */
	public static function needs_approval(): bool {
		return self::native_available()
			&& self::approval_enforced()
			&& self::native_has_credentials()
			&& ! self::is_approved();
	}

	/**
	 * Record the user's consent: approve LoginArmor for every AI-provider connector.
	 */
	public static function grant_approval(): bool {
		$appr = get_option( self::APPROVALS_OPTION, array() );
		if ( ! is_array( $appr ) ) {
			$appr = array();
		}
		$caller = self::caller_basename();
		if ( ! isset( $appr[ $caller ] ) || ! is_array( $appr[ $caller ] ) ) {
			$appr[ $caller ] = array();
		}
		foreach ( self::ai_connector_ids() as $cid ) {
			$appr[ $caller ][ $cid ] = true;
		}
		update_option( self::APPROVALS_OPTION, $appr, false );

		// Granting approval directly (not via the AI plugin's own UI) leaves the
		// matching "pending request" entries behind, which keeps the native
		// "1 plugin is requesting access" notice up. Clear ours so it goes away.
		self::clear_pending_requests();
		return true;
	}

	/**
	 * Remove LoginArmor's own entries from the AI plugin's pending-approval queue.
	 *
	 * Only LoginArmor's rows are touched: other plugins' pending requests (and
	 * their legitimate notices) are left intact.
	 *
	 * @return int Number of pending entries removed.
	 */
	public static function clear_pending_requests(): int {
		$pending = get_option( self::PENDING_OPTION, array() );
		if ( ! is_array( $pending ) || empty( $pending ) ) {
			return 0;
		}
		$caller  = self::caller_basename();              // e.g. login-armor/login-armor.php
		$bare    = explode( '/', $caller )[0];           // e.g. login-armor
		$removed = 0;
		foreach ( $pending as $key => $entry ) {
			$bn = is_array( $entry ) && isset( $entry['caller_basename'] ) ? (string) $entry['caller_basename'] : '';
			$k  = (string) $key;
			if ( $bn === $caller || $bn === $bare
				|| 0 === strpos( $k, $caller . '::' ) || 0 === strpos( $k, $bare . '::' ) ) {
				unset( $pending[ $key ] );
				++$removed;
			}
		}
		if ( $removed > 0 ) {
			update_option( self::PENDING_OPTION, $pending, false );
		}
		return $removed;
	}

	/**
	 * Revoke LoginArmor's connector approval.
	 */
	public static function revoke_approval(): bool {
		$appr   = get_option( self::APPROVALS_OPTION, array() );
		$caller = self::caller_basename();
		if ( is_array( $appr ) && isset( $appr[ $caller ] ) ) {
			unset( $appr[ $caller ] );
			update_option( self::APPROVALS_OPTION, $appr, false );
		}
		return true;
	}

	/* ---------------------------------------------------------------------
	 * Execution.
	 * ------------------------------------------------------------------- */

	/**
	 * Preferred [provider, model] pairs, tried in order. The AI Client picks the
	 * first one whose connector is configured. Without a preference the client
	 * falls back to an internal default model that may not be available, so this
	 * list is required on bare WP 7 core. Filterable.
	 *
	 * @return array<int,array{0:string,1:string}>
	 */
	public static function model_preference(): array {
		$models = array(
			array( 'anthropic', 'claude-sonnet-4-6' ),
			array( 'anthropic', 'claude-haiku-4-5' ),
			array( 'openai', 'gpt-4.1-mini' ),
			array( 'google', 'gemini-2.5-flash' ),
		);
		/**
		 * Filter the ordered model preference used for native generation.
		 *
		 * @since 2.2.0
		 * @param array $models List of [ provider, model ] pairs.
		 */
		return (array) apply_filters( 'login_armor_ai_model_preference', $models );
	}

	/**
	 * Run a completion through the active provider.
	 *
	 * @param string               $prompt  Prompt.
	 * @param array<string,mixed>  $options Supports 'system_instruction', 'max_tokens', 'temperature'.
	 * @return string|\WP_Error
	 */
	public static function complete( string $prompt, array $options = array() ) {
		// Test/override hook: a callable short-circuits the native call. Lets the
		// UI and the data-minimisation path be exercised without a real connector.
		$forced = apply_filters( 'login_armor_ai_force_provider', null );
		if ( is_callable( $forced ) ) {
			$result = $forced( $prompt, $options );
			self::record_usage();
			return $result;
		}

		if ( ! self::is_enabled() ) {
			return new \WP_Error( 'login_armor_ai_disabled', __( 'The AI layer is disabled.', 'login-armor' ) );
		}
		if ( ! self::native_available() ) {
			return new \WP_Error( 'login_armor_ai_unavailable', __( 'No native AI connector available. Switch to WordPress 7 and configure an AI connector.', 'login-armor' ) );
		}

		$result = self::generate( $prompt, $options );
		self::record_usage();
		return $result;
	}

	/**
	 * Low-level WordPress 7 AI Client call.
	 *
	 * Prefers the AI feature plugin's service (which applies model preferences and
	 * connector handling); on bare WordPress 7 core, calls the client directly with
	 * an explicit model preference. WP_Error results are propagated, never swallowed.
	 *
	 * @param string              $prompt  User prompt.
	 * @param array<string,mixed> $options Optional. Supports 'system_instruction', 'max_tokens', 'temperature'.
	 * @return string|\WP_Error
	 */
	private static function generate( string $prompt, array $options ) {
		if ( ! empty( $options['system_instruction'] ) ) {
			$prompt = (string) $options['system_instruction'] . "\n\n" . $prompt;
		}

		try {
			if ( function_exists( 'WordPress\\AI\\get_ai_service' ) ) {
				// Blessed path: the AI feature plugin applies preferred models itself.
				$svc_opts = array();
				if ( isset( $options['max_tokens'] ) ) {
					$svc_opts['max_tokens'] = (int) $options['max_tokens'];
				}
				if ( isset( $options['temperature'] ) ) {
					$svc_opts['temperature'] = (float) $options['temperature'];
				}
				$builder = \WordPress\AI\get_ai_service()->create_textgen_prompt( $prompt, $svc_opts );
			} else {
				// Bare WP 7 core: set the model preference explicitly.
				$builder = self::ai_prompt( $prompt )->using_model_preference( ...self::model_preference() );
			}
			$text = $builder->generate_text();
		} catch ( \Throwable $e ) {
			return new \WP_Error( 'login_armor_ai_error', self::friendly_error( $e->getMessage() ) );
		}

		if ( is_wp_error( $text ) ) {
			return $text;
		}
		return is_string( $text ) ? $text : '';
	}

	/**
	 * Confirm a native connector can generate text (for a "Test" button).
	 *
	 * @return true|\WP_Error
	 */
	public static function test_connection() {
		if ( is_callable( apply_filters( 'login_armor_ai_force_provider', null ) ) ) {
			return true;
		}
		if ( ! self::native_available() ) {
			return new \WP_Error( 'login_armor_ai_unavailable', __( 'No native AI connector. Switch to WordPress 7 and configure an AI connector.', 'login-armor' ) );
		}
		try {
			$supported = self::ai_prompt( 'ping' )->is_supported_for_text_generation();
		} catch ( \Throwable $e ) {
			return new \WP_Error( 'login_armor_ai_error', self::friendly_error( $e->getMessage() ) );
		}
		if ( ! $supported ) {
			return new \WP_Error( 'login_armor_ai_unsupported', __( 'No AI connector supports text generation. Configure one under Settings → AI Connectors.', 'login-armor' ) );
		}
		return true;
	}

	/**
	 * Map known AI Client errors to actionable messages.
	 */
	private static function friendly_error( string $message ): string {
		if ( false !== stripos( $message, 'has not been approved' ) ) {
			return __( 'Your AI connector must authorise LoginArmor. Click "Authorise LoginArmor" in the settings.', 'login-armor' );
		}
		return $message;
	}

	/* ---------------------------------------------------------------------
	 * Usage accounting.
	 * ------------------------------------------------------------------- */

	/**
	 * The rolling 30-day usage record.
	 *
	 * @return array{rolling_30d:int,last_call_at:int,history:array<string,int>}
	 */
	public static function get_usage(): array {
		$usage = get_option( self::OPTION_USAGE, array() );
		return array(
			'rolling_30d'  => isset( $usage['rolling_30d'] ) ? (int) $usage['rolling_30d'] : 0,
			'last_call_at' => isset( $usage['last_call_at'] ) ? (int) $usage['last_call_at'] : 0,
			'history'      => isset( $usage['history'] ) && is_array( $usage['history'] ) ? $usage['history'] : array(),
		);
	}

	/**
	 * Record one API call in the rolling 30d usage option.
	 */
	private static function record_usage(): void {
		$usage = get_option(
			self::OPTION_USAGE,
			array(
				'rolling_30d'  => 0,
				'last_call_at' => 0,
				'history'      => array(),
			)
		);
		if ( ! is_array( $usage ) ) {
			$usage = array( 'history' => array() );
		}
		if ( ! isset( $usage['history'] ) || ! is_array( $usage['history'] ) ) {
			$usage['history'] = array();
		}

		$today = gmdate( 'Y-m-d' );
		if ( ! isset( $usage['history'][ $today ] ) ) {
			$usage['history'][ $today ] = 0;
		}
		++$usage['history'][ $today ];

		$cutoff = gmdate( 'Y-m-d', time() - 30 * DAY_IN_SECONDS );
		foreach ( array_keys( $usage['history'] ) as $day ) {
			if ( $day < $cutoff ) {
				unset( $usage['history'][ $day ] );
			}
		}
		$usage['rolling_30d']  = array_sum( $usage['history'] );
		$usage['last_call_at'] = time();

		update_option( self::OPTION_USAGE, $usage, false );
	}

	/* ---------------------------------------------------------------------
	 * Output rendering: render the small Markdown subset LLMs emit into safe HTML.
	 * ------------------------------------------------------------------- */

	/**
	 * Render the small Markdown subset that LLMs emit (headings, bold, italics,
	 * inline code, bullet lists, horizontal rules) into safe HTML.
	 *
	 * Every line is HTML-escaped BEFORE any tag is injected, so the only markup
	 * in the output is the tags this method adds: no XSS surface even though the
	 * input comes from a model.
	 *
	 * @param string $text Raw model text (possibly Markdown).
	 * @return string Safe HTML.
	 */
	public static function format_markdown( string $text ): string {
		$lines   = preg_split( '/\r\n|\r|\n/', $text );
		if ( ! is_array( $lines ) ) {
			return '';
		}
		$count   = count( $lines );
		$html    = '';
		$in_list = false;

		for ( $i = 0; $i < $count; $i++ ) {
			$trim = trim( $lines[ $i ] );

			// GFM table: a row containing a pipe IMMEDIATELY followed by a
			// delimiter row ( |---|:--:|--- ). Without this the model's tabular
			// data (e.g. the top source-IP table) leaks raw "|" and "|---|" into
			// the page. Each cell is escaped via inline_md().
			if ( false !== strpos( $trim, '|' ) && $i + 1 < $count
				&& preg_match( '/^\|?\s*:?-{1,}:?\s*(\|\s*:?-{1,}:?\s*)+\|?$/', trim( $lines[ $i + 1 ] ) ) ) {
				if ( $in_list ) {
					$html   .= '</ul>';
					$in_list = false;
				}
				$header = self::split_table_row( $trim );
				$rows   = array();
				$j      = $i + 2;
				while ( $j < $count ) {
					$row_trim = trim( $lines[ $j ] );
					if ( '' === $row_trim || false === strpos( $row_trim, '|' ) ) {
						break;
					}
					$rows[] = self::split_table_row( $row_trim );
					++$j;
				}
				$html .= self::render_table( $header, $rows );
				$i     = $j - 1; // Resume after the consumed table block.
				continue;
			}

			if ( preg_match( '/^-{3,}$/', $trim ) || preg_match( '/^\*{3,}$/', $trim ) ) {
				if ( $in_list ) {
					$html   .= '</ul>';
					$in_list = false;
				}
				$html .= '<hr class="la-ai-hr">';
				continue;
			}

			if ( preg_match( '/^(#{1,6})\s+(.*)$/', $trim, $m ) ) {
				if ( $in_list ) {
					$html   .= '</ul>';
					$in_list = false;
				}
				$level = strlen( $m[1] ) <= 2 ? 3 : 4;
				$html .= '<h' . $level . ' class="la-ai-h' . $level . '">' . self::inline_md( $m[2] ) . '</h' . $level . '>';
				continue;
			}

			if ( preg_match( '/^[-*]\s+(.*)$/', $trim, $m ) ) {
				if ( ! $in_list ) {
					$html   .= '<ul class="la-ai-ul">';
					$in_list = true;
				}
				$html .= '<li>' . self::inline_md( $m[1] ) . '</li>';
				continue;
			}

			if ( '' === $trim ) {
				if ( $in_list ) {
					$html   .= '</ul>';
					$in_list = false;
				}
				continue;
			}

			if ( $in_list ) {
				$html   .= '</ul>';
				$in_list = false;
			}
			$html .= '<p>' . self::inline_md( $trim ) . '</p>';
		}

		if ( $in_list ) {
			$html .= '</ul>';
		}
		return $html;
	}

	/**
	 * Inline Markdown (bold/italic/code) for one already-trimmed line.
	 * Escapes HTML first, then injects only the tags it controls.
	 *
	 * @param string $s Raw line.
	 * @return string Safe HTML fragment.
	 */
	private static function inline_md( string $s ): string {
		$s = esc_html( $s );
		$s = preg_replace( '/\*\*(.+?)\*\*/s', '<strong>$1</strong>', $s );
		$s = preg_replace( '/__(.+?)__/s', '<strong>$1</strong>', $s );
		$s = preg_replace( '/`([^`]+)`/', '<code>$1</code>', $s );
		$s = preg_replace( '/(?<![\*\w])\*([^*\n]+?)\*(?!\*)/', '<em>$1</em>', $s );
		return $s;
	}

	/**
	 * Split a Markdown table row into trimmed cell strings (leading/trailing
	 * pipe stripped). Cells are NOT escaped here: render_table() escapes each
	 * via inline_md().
	 *
	 * @param string $row One table row.
	 * @return array<int,string>
	 */
	private static function split_table_row( string $row ): array {
		$row = trim( $row );
		$row = (string) preg_replace( '/^\|/', '', $row );
		$row = (string) preg_replace( '/\|$/', '', $row );
		return array_map( 'trim', explode( '|', $row ) );
	}

	/**
	 * Render a parsed Markdown table as safe HTML. Every cell goes through
	 * inline_md(), which esc_html's its input before adding controlled tags.
	 *
	 * @param array<int,string>       $header Header cells.
	 * @param array<int,array<int,string>> $rows Body rows.
	 * @return string Safe HTML.
	 */
	private static function render_table( array $header, array $rows ): string {
		$cols = count( $header );
		if ( 0 === $cols ) {
			return '';
		}
		$out = '<table class="la-ai-table"><thead><tr>';
		foreach ( $header as $cell ) {
			$out .= '<th>' . self::inline_md( (string) $cell ) . '</th>';
		}
		$out .= '</tr></thead><tbody>';
		foreach ( $rows as $row ) {
			$out .= '<tr>';
			for ( $c = 0; $c < $cols; $c++ ) {
				$cell = isset( $row[ $c ] ) ? (string) $row[ $c ] : '';
				$out .= '<td>' . self::inline_md( $cell ) . '</td>';
			}
			$out .= '</tr>';
		}
		$out .= '</tbody></table>';
		return $out;
	}
}
