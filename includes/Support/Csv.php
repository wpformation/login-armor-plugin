<?php
/**
 * CSV export helpers.
 *
 * @package LoginArmor
 * @since   2.4.4
 */

namespace LoginArmor\Support;

// Exit if accessed directly.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Small, side-effect-free helpers shared by every CSV export in the plugin.
 */
class Csv {

	/**
	 * Neutralize CSV formula injection in a text cell.
	 *
	 * Exported fields such as User-Agent and username are attacker-controlled
	 * from an unauthenticated request. A spreadsheet (Excel, LibreOffice, Google
	 * Sheets) interprets any cell whose first significant character is `=`, `+`,
	 * `-` or `@` as a formula, so a crafted `=HYPERLINK(...)` / `=cmd|...` /
	 * `=WEBSERVICE(...)` value runs when an admin opens the export. Prefixing the
	 * value with a single quote forces the whole cell to be treated as literal
	 * text, which every major spreadsheet honors and strips on display.
	 *
	 * Leading whitespace or a leading TAB/CR is also neutralized: it can hide a
	 * trigger character from a naive first-byte check while the spreadsheet still
	 * parses the formula. The stored database value is never altered: only the
	 * exported copy is quoted.
	 *
	 * @param mixed $value Raw cell value (cast to string).
	 * @return string Safe-to-export value.
	 */
	public static function neutralize_field( $value ): string {
		$value = (string) $value;
		if ( '' === $value ) {
			return $value;
		}

		// A raw leading TAB or CR is itself a spreadsheet-significant character
		// an attacker can use to smuggle a formula past first-byte checks.
		if ( "\t" === $value[0] || "\r" === $value[0] ) {
			return "'" . $value;
		}

		// Skip leading spaces only, then test the first meaningful character.
		$significant = ltrim( $value, ' ' );
		if ( '' !== $significant
			&& in_array( $significant[0], [ '=', '+', '-', '@' ], true ) ) {
			return "'" . $value;
		}

		return $value;
	}
}
