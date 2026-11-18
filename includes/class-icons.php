<?php
/**
 * Icons: Lucide-style SVG icon registry.
 *
 * @package LoginArmor
 */

namespace LoginArmor;

defined( 'ABSPATH' ) || exit;

final class Icons {

	/**
	 * Lucide-style SVG paths, viewBox 0 0 24 24, stroke=currentColor.
	 * Stroke width is applied at render time (default 2).
	 */
	private const PATHS = [
		'shield'         => '<path d="M12 2 L20 6 V12 C20 17 16 21 12 22 C8 21 4 17 4 12 V6 Z"/>',
		'lock'           => '<rect x="5" y="11" width="14" height="10" rx="2"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/>',
		'unlock'         => '<rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 9.9-1"/>',
		'check'          => '<path d="M20 6L9 17l-5-5"/>',
		'x'              => '<path d="M18 6 6 18"/><path d="m6 6 12 12"/>',
		'eye'            => '<circle cx="12" cy="12" r="3"/><path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7-10-7-10-7z"/>',
		'eye-off'        => '<path d="M9.88 9.88a3 3 0 1 0 4.24 4.24"/><path d="M10.73 5.08A10.43 10.43 0 0 1 12 5c7 0 11 7 11 7a13.16 13.16 0 0 1-1.67 2.68"/><path d="M6.61 6.61A13.526 13.526 0 0 0 1 12s4 7 11 7a9.74 9.74 0 0 0 5.39-1.61"/><line x1="2" x2="22" y1="2" y2="22"/>',
		'pulse'          => '<path d="M3 12h4l3-9 4 18 3-9h4"/>',
		'refresh'        => '<path d="M21 12a9 9 0 1 1-3-6.7"/><path d="M21 4v6h-6"/>',
		'bell'           => '<path d="M6 8a6 6 0 0 1 12 0c0 7 3 9 3 9H3s3-2 3-9"/><path d="M10.3 21a1.94 1.94 0 0 0 3.4 0"/>',
		'file'           => '<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2v6h6"/>',
		'circle-slash'   => '<circle cx="12" cy="12" r="10"/><path d="m4.93 4.93 14.14 14.14"/>',
		'alert-triangle' => '<path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"/><path d="M12 9v4"/><path d="M12 17h.01"/>',
		'alert-circle'   => '<circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/>',
		'info'           => '<circle cx="12" cy="12" r="10"/><path d="M12 16v-4"/><path d="M12 8h.01"/>',
		'settings'       => '<circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 8.91 20a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/>',
		'key'            => '<circle cx="7.5" cy="15.5" r="5.5"/><path d="m21 2-9.6 9.6"/><path d="m15.5 7.5 3 3L22 7l-3-3"/>',
		'mail'           => '<rect width="20" height="16" x="2" y="4" rx="2"/><path d="m22 7-8.97 5.7a1.94 1.94 0 0 1-2.06 0L2 7"/>',
		'globe'          => '<circle cx="12" cy="12" r="10"/><line x1="2" x2="22" y1="12" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/>',
		'monitor'        => '<rect width="20" height="14" x="2" y="3" rx="2"/><line x1="8" x2="16" y1="21" y2="21"/><line x1="12" x2="12" y1="17" y2="21"/>',
		'search'         => '<circle cx="11" cy="11" r="7"/><path d="m21 21-4.3-4.3"/>',
		'filter'         => '<path d="M22 3H2l8 9.46V19l4 2v-8.54L22 3z"/>',
		'play'           => '<path d="M5 3l14 9-14 9V3z"/>',
		'pause'          => '<rect x="6" y="4" width="4" height="16"/><rect x="14" y="4" width="4" height="16"/>',
		'download'       => '<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" x2="12" y1="15" y2="3"/>',
		'chevron-right'  => '<polyline points="9 18 15 12 9 6"/>',
		'chevron-down'   => '<polyline points="6 9 12 15 18 9"/>',
	];

	/**
	 * Allowlist of SVG tags + attributes used by the icons in self::PATHS.
	 * Passed to wp_kses() in self::print() so every echo'd icon goes through
	 * an explicit escape boundary: the pattern WP.org plugin review expects.
	 *
	 * @var array<string, array<string, bool>>
	 */
	private const ALLOWED_SVG = [
		'svg'      => [
			'width'           => true,
			'height'          => true,
			'viewbox'         => true,
			'fill'            => true,
			'stroke'          => true,
			'stroke-width'    => true,
			'stroke-linecap'  => true,
			'stroke-linejoin' => true,
			'class'           => true,
			'aria-hidden'     => true,
			'xmlns'           => true,
		],
		'path'     => [ 'd' => true, 'fill' => true ],
		'rect'     => [ 'x' => true, 'y' => true, 'width' => true, 'height' => true, 'rx' => true, 'fill' => true ],
		'circle'   => [ 'cx' => true, 'cy' => true, 'r' => true, 'fill' => true ],
		'line'     => [ 'x1' => true, 'y1' => true, 'x2' => true, 'y2' => true ],
		'polyline' => [ 'points' => true ],
		'polygon'  => [ 'points' => true ],
	];

	/**
	 * Return an inline SVG for a named icon.
	 *
	 * Callers that immediately echo this value should prefer self::render()
	 * instead, that path goes through wp_kses() with self::ALLOWED_SVG,
	 * which is the escape boundary WP.org plugin review expects. This
	 * getter still exists for callers that compose the SVG into a larger
	 * pre-escaped string.
	 *
	 * @param string $name    Icon key from self::PATHS.
	 * @param string $classes Optional CSS class(es) to add.
	 * @param int    $size    Pixel size (square). Defaults to 16.
	 * @param float  $stroke  Stroke width. Defaults to 2.
	 * @return string SVG markup (safe HTML, icon library is author-controlled).
	 */
	public static function get( string $name, string $classes = '', int $size = 16, float $stroke = 2 ): string {
		if ( ! isset( self::PATHS[ $name ] ) ) {
			return '';
		}
		$class_attr = $classes !== '' ? ' class="' . esc_attr( $classes ) . '"' : '';
		return sprintf(
			'<svg%s width="%d" height="%d" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="%s" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">%s</svg>',
			$class_attr,
			$size,
			$size,
			esc_attr( (string) $stroke ),
			self::PATHS[ $name ]
		);
	}

	/**
	 * Echo an inline SVG icon through wp_kses() with the SVG allowlist.
	 *
	 * Preferred over `echo Icons::get(...)` because the escape boundary is
	 * explicit and deterministic. Satisfies WordPress.Security.EscapeOutput
	 * without needing a phpcs:ignore at every call site.
	 *
	 * @param string $name    Icon key from self::PATHS.
	 * @param string $classes Optional CSS class(es) to add.
	 * @param int    $size    Pixel size (square). Defaults to 16.
	 * @param float  $stroke  Stroke width. Defaults to 2.
	 */
	public static function render( string $name, string $classes = '', int $size = 16, float $stroke = 2 ): void {
		echo wp_kses( self::get( $name, $classes, $size, $stroke ), self::ALLOWED_SVG );
	}

	/** Available icon keys (for debug / tests). */
	public static function available(): array {
		return array_keys( self::PATHS );
	}
}
