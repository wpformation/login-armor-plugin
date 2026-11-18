<?php
/**
 * Minimal QR Code to SVG generator.
 *
 * Pure PHP implementation: no external libraries, no Composer, no CDN.
 * Supports only alphanumeric + URI characters needed for otpauth:// URIs.
 * Uses byte-mode encoding with error correction level M.
 *
 * @package LoginArmor
 * @since   2.2.0
 */

namespace LoginArmor;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Generate QR codes as inline SVG.
 */
class QRCode {

	/** @var int Module (pixel) size in SVG units. */
	private const MODULE_SIZE = 4;

	/** @var int Quiet zone (margin) in modules. */
	private const QUIET_ZONE = 4;

	/**
	 * Generate an SVG string for a QR code encoding the given data.
	 *
	 * Uses a simplified encoding suitable for short URIs (< 256 bytes).
	 * For otpauth:// URIs this is always sufficient.
	 *
	 * @param string $data The data to encode (e.g., otpauth:// URI).
	 * @return string SVG markup string.
	 */
	public static function to_svg( string $data ): string {
		$matrix = self::encode( $data );
		$size   = count( $matrix );

		$total  = ( $size + self::QUIET_ZONE * 2 ) * self::MODULE_SIZE;

		$svg  = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ' . $total . ' ' . $total . '" width="' . $total . '" height="' . $total . '">';
		$svg .= '<rect width="100%" height="100%" fill="#ffffff"/>';
		$svg .= '<path d="';

		for ( $y = 0; $y < $size; $y++ ) {
			for ( $x = 0; $x < $size; $x++ ) {
				if ( $matrix[ $y ][ $x ] ) {
					$px = ( $x + self::QUIET_ZONE ) * self::MODULE_SIZE;
					$py = ( $y + self::QUIET_ZONE ) * self::MODULE_SIZE;
					$svg .= 'M' . $px . ',' . $py . 'h' . self::MODULE_SIZE . 'v' . self::MODULE_SIZE . 'h-' . self::MODULE_SIZE . 'z';
				}
			}
		}

		$svg .= '" fill="#000000"/>';
		$svg .= '</svg>';

		return $svg;
	}

	// ── QR Encoding Engine ──────────────────────────────────────────

	/**
	 * Encode data into a QR code matrix.
	 *
	 * This is a simplified but functional QR encoder that handles
	 * byte-mode data with error correction level M, versions 1-6.
	 *
	 * @param string $data Raw data string.
	 * @return array<int,array<int,int>> 2D matrix of modules (1 = dark, 0 = light).
	 */
	private static function encode( string $data ): array {
		$length = strlen( $data );

		// Determine QR version (1-10) based on byte-mode capacity at EC level M.
		$capacities = [
			1 => 14, 2 => 26, 3 => 42, 4 => 62, 5 => 84,
			6 => 106, 7 => 122, 8 => 152, 9 => 180, 10 => 213,
		];

		$version = 0;
		foreach ( $capacities as $v => $cap ) {
			if ( $length <= $cap ) {
				$version = $v;
				break;
			}
		}

		if ( 0 === $version ) {
			// Fallback: data too large. Truncate to version 10.
			$version = 10;
			$data    = substr( $data, 0, 213 );
			$length  = 213;
		}

		$size = 17 + $version * 4;

		// Build data codewords.
		$bits = self::build_data_bits( $data, $version );

		// Add error correction.
		$codewords = self::add_error_correction( $bits, $version );

		// Initialize matrix.
		$matrix   = array_fill( 0, $size, array_fill( 0, $size, 0 ) );
		$reserved = array_fill( 0, $size, array_fill( 0, $size, false ) );

		// Place finder patterns.
		self::place_finder( $matrix, $reserved, 0, 0 );
		self::place_finder( $matrix, $reserved, $size - 7, 0 );
		self::place_finder( $matrix, $reserved, 0, $size - 7 );

		// Place timing patterns.
		self::place_timing( $matrix, $reserved, $size );

		// Place alignment patterns (versions >= 2).
		if ( $version >= 2 ) {
			self::place_alignment( $matrix, $reserved, $version, $size );
		}

		// Reserve format info areas.
		self::reserve_format( $reserved, $size );

		// Reserve version info areas (versions >= 7).
		if ( $version >= 7 ) {
			self::reserve_version( $reserved, $size );
		}

		// Place data bits.
		self::place_data( $matrix, $reserved, $codewords, $size );

		// Apply mask (pattern 0: (y + x) % 2 == 0).
		self::apply_mask( $matrix, $reserved, $size );

		// Write format info.
		self::write_format_info( $matrix, $size );

		// Write version info (versions >= 7).
		if ( $version >= 7 ) {
			self::write_version_info( $matrix, $version, $size );
		}

		return $matrix;
	}

	/**
	 * Build data bits in byte mode.
	 *
	 * @param string $data    Raw data.
	 * @param int    $version QR version.
	 * @return string Binary string of bits.
	 */
	private static function build_data_bits( string $data, int $version ): string {
		$length      = strlen( $data );
		$char_count_bits = $version <= 9 ? 8 : 16;

		// Mode indicator: 0100 (byte mode).
		$bits = '0100';

		// Character count indicator.
		$bits .= str_pad( decbin( $length ), $char_count_bits, '0', STR_PAD_LEFT );

		// Data bytes.
		for ( $i = 0; $i < $length; $i++ ) {
			$bits .= str_pad( decbin( ord( $data[ $i ] ) ), 8, '0', STR_PAD_LEFT );
		}

		// Terminator (up to 4 bits of zeros).
		$bits .= '0000';

		// Pad to byte boundary.
		$remainder = strlen( $bits ) % 8;
		if ( $remainder > 0 ) {
			$bits .= str_repeat( '0', 8 - $remainder );
		}

		// Total data codewords needed for this version at EC level M.
		$total_codewords = self::get_total_data_codewords( $version );
		$pads            = [ '11101100', '00010001' ];
		$pad_index       = 0;

		while ( strlen( $bits ) < $total_codewords * 8 ) {
			$bits     .= $pads[ $pad_index ];
			$pad_index = ( $pad_index + 1 ) % 2;
		}

		// Truncate if overflows.
		$bits = substr( $bits, 0, $total_codewords * 8 );

		return $bits;
	}

	/**
	 * Get total data codewords for a version at EC level M.
	 *
	 * @param int $version QR version.
	 * @return int Number of data codewords.
	 */
	private static function get_total_data_codewords( int $version ): int {
		// Data codewords (not including EC) for EC level M, versions 1-10.
		$map = [
			1 => 16, 2 => 28, 3 => 44, 4 => 64, 5 => 86,
			6 => 108, 7 => 124, 8 => 154, 9 => 182, 10 => 216,
		];
		return $map[ $version ] ?? 216;
	}

	/**
	 * Get total codewords (data + EC) for a version.
	 *
	 * @param int $version QR version.
	 * @return int Total codewords.
	 */
	private static function get_total_codewords( int $version ): int {
		// Total codewords for versions 1-10.
		$map = [
			1 => 26, 2 => 44, 3 => 70, 4 => 100, 5 => 134,
			6 => 172, 7 => 196, 8 => 242, 9 => 292, 10 => 346,
		];
		return $map[ $version ] ?? 346;
	}

	/**
	 * Get EC codewords per block for EC level M.
	 *
	 * @param int $version QR version.
	 * @return int EC codewords per block.
	 */
	private static function get_ec_per_block( int $version ): int {
		$map = [
			1 => 10, 2 => 16, 3 => 26, 4 => 18, 5 => 24,
			6 => 16, 7 => 18, 8 => 22, 9 => 22, 10 => 26,
		];
		return $map[ $version ] ?? 26;
	}

	/**
	 * Get block structure for EC level M: array of [count, dataCodewords].
	 *
	 * @param int $version QR version.
	 * @return array<int,array{0:int,1:int}> Block groups.
	 */
	private static function get_block_structure( int $version ): array {
		// [number_of_blocks, data_codewords_per_block] groups for EC level M.
		$map = [
			1  => [ [ 1, 16 ] ],
			2  => [ [ 1, 28 ] ],
			3  => [ [ 1, 44 ] ],
			4  => [ [ 2, 32 ] ],
			5  => [ [ 2, 43 ] ],
			6  => [ [ 4, 27 ] ],
			7  => [ [ 4, 31 ] ],
			8  => [ [ 2, 38 ], [ 2, 39 ] ],
			9  => [ [ 3, 36 ], [ 2, 37 ] ],
			10 => [ [ 4, 43 ], [ 1, 44 ] ],
		];
		return $map[ $version ] ?? [ [ 1, 16 ] ];
	}

	/**
	 * Add Reed-Solomon error correction to data bits.
	 *
	 * @param string $bits    Binary data string.
	 * @param int    $version QR version.
	 * @return array<int,int> Final interleaved codewords (data + EC).
	 */
	private static function add_error_correction( string $bits, int $version ): array {
		// Convert bits to codeword array.
		$data_codewords = [];
		$byte_strings   = str_split( $bits, 8 );
		foreach ( $byte_strings as $byte_str ) {
			$data_codewords[] = bindec( str_pad( $byte_str, 8, '0', STR_PAD_RIGHT ) );
		}

		$ec_per_block    = self::get_ec_per_block( $version );
		$block_structure = self::get_block_structure( $version );

		$data_blocks = [];
		$ec_blocks   = [];
		$offset      = 0;

		foreach ( $block_structure as $group ) {
			$count          = $group[0];
			$data_per_block = $group[1];

			for ( $b = 0; $b < $count; $b++ ) {
				$block        = array_slice( $data_codewords, $offset, $data_per_block );
				$data_blocks[] = $block;
				$ec_blocks[]   = self::reed_solomon( $block, $ec_per_block );
				$offset       += $data_per_block;
			}
		}

		// Interleave data blocks.
		$result    = [];
		$max_data  = max( array_map( 'count', $data_blocks ) );

		for ( $i = 0; $i < $max_data; $i++ ) {
			foreach ( $data_blocks as $block ) {
				if ( isset( $block[ $i ] ) ) {
					$result[] = $block[ $i ];
				}
			}
		}

		// Interleave EC blocks.
		for ( $i = 0; $i < $ec_per_block; $i++ ) {
			foreach ( $ec_blocks as $block ) {
				if ( isset( $block[ $i ] ) ) {
					$result[] = $block[ $i ];
				}
			}
		}

		return $result;
	}

	/**
	 * Compute Reed-Solomon error correction codewords.
	 *
	 * Uses polynomial long division over GF(256).
	 * All arithmetic in normal (non-log) form.
	 *
	 * @param array<int,int> $data         Data codewords (normal form).
	 * @param int            $ec_count     Number of EC codewords to generate.
	 * @return array<int,int> EC codewords.
	 */
	private static function reed_solomon( array $data, int $ec_count ): array {
		$gen = self::get_generator_polynomial( $ec_count );

		// Polynomial long division.
		$remainder = array_merge( $data, array_fill( 0, $ec_count, 0 ) );

		for ( $i = 0, $data_len = count( $data ); $i < $data_len; $i++ ) {
			$coeff = $remainder[ $i ];
			if ( 0 === $coeff ) {
				continue;
			}

			for ( $j = 0, $gen_len = count( $gen ); $j < $gen_len; $j++ ) {
				$remainder[ $i + $j ] ^= self::gf_mul( $coeff, $gen[ $j ] );
			}
		}

		return array_slice( $remainder, count( $data ) );
	}

	/**
	 * Get generator polynomial for given EC codeword count.
	 *
	 * Computes the product: (x + a^0)(x + a^1)...(x + a^(degree-1))
	 * Coefficients stored in normal (non-log) form.
	 *
	 * @param int $degree Number of EC codewords.
	 * @return array<int,int> Generator polynomial coefficients (normal form).
	 */
	private static function get_generator_polynomial( int $degree ): array {
		// Start with polynomial "1" (constant).
		$gen = [ 1 ];

		for ( $i = 0; $i < $degree; $i++ ) {
			// Multiply gen by (x + a^i).
			$alpha_i = self::$gf_exp[ $i ];
			$new_gen = array_fill( 0, count( $gen ) + 1, 0 );

			for ( $j = 0, $len = count( $gen ); $j < $len; $j++ ) {
				$new_gen[ $j + 1 ] ^= $gen[ $j ];                          // x * gen[j].
				$new_gen[ $j ]     ^= self::gf_mul( $gen[ $j ], $alpha_i ); // a^i * gen[j].
			}

			$gen = $new_gen;
		}

		return $gen;
	}

	/**
	 * Multiply two values in GF(256) using log/exp tables.
	 *
	 * @param int $a First operand (normal form).
	 * @param int $b Second operand (normal form).
	 * @return int Product in normal form.
	 */
	private static function gf_mul( int $a, int $b ): int {
		if ( 0 === $a || 0 === $b ) {
			return 0;
		}
		return self::$gf_exp[ ( self::$gf_log[ $a ] + self::$gf_log[ $b ] ) % 255 ];
	}

	/** @var array<int,int> GF(256) exponent table. */
	private static array $gf_exp = [];

	/** @var array<int,int> GF(256) logarithm table. */
	private static array $gf_log = [];

	/**
	 * Initialize GF(256) lookup tables.
	 */
	private static function init_gf(): void {
		if ( ! empty( self::$gf_exp ) ) {
			return;
		}

		self::$gf_exp = array_fill( 0, 512, 0 );
		self::$gf_log = array_fill( 0, 256, 0 );

		$x = 1;
		for ( $i = 0; $i < 255; $i++ ) {
			self::$gf_exp[ $i ] = $x;
			self::$gf_log[ $x ] = $i;
			$x <<= 1;
			if ( $x >= 256 ) {
				$x ^= 0x11D; // Primitive polynomial for QR: x^8 + x^4 + x^3 + x^2 + 1.
			}
		}
		for ( $i = 255; $i < 512; $i++ ) {
			self::$gf_exp[ $i ] = self::$gf_exp[ $i - 255 ];
		}
	}

	/**
	 * Place a 7x7 finder pattern at the given position.
	 *
	 * @param array<int,array<int,int>>  &$matrix   QR matrix.
	 * @param array<int,array<int,bool>> &$reserved Reserved map.
	 * @param int $row Top row.
	 * @param int $col Left column.
	 */
	private static function place_finder( array &$matrix, array &$reserved, int $row, int $col ): void {
		$pattern = [
			[ 1, 1, 1, 1, 1, 1, 1 ],
			[ 1, 0, 0, 0, 0, 0, 1 ],
			[ 1, 0, 1, 1, 1, 0, 1 ],
			[ 1, 0, 1, 1, 1, 0, 1 ],
			[ 1, 0, 1, 1, 1, 0, 1 ],
			[ 1, 0, 0, 0, 0, 0, 1 ],
			[ 1, 1, 1, 1, 1, 1, 1 ],
		];

		$size = count( $matrix );

		for ( $r = -1; $r <= 7; $r++ ) {
			for ( $c = -1; $c <= 7; $c++ ) {
				$mr = $row + $r;
				$mc = $col + $c;
				if ( $mr < 0 || $mr >= $size || $mc < 0 || $mc >= $size ) {
					continue;
				}
				if ( $r >= 0 && $r < 7 && $c >= 0 && $c < 7 ) {
					$matrix[ $mr ][ $mc ] = $pattern[ $r ][ $c ];
				} else {
					$matrix[ $mr ][ $mc ] = 0; // Separator.
				}
				$reserved[ $mr ][ $mc ] = true;
			}
		}
	}

	/**
	 * Place timing patterns.
	 *
	 * @param array<int,array<int,int>>  &$matrix   QR matrix.
	 * @param array<int,array<int,bool>> &$reserved Reserved map.
	 * @param int $size Matrix size.
	 */
	private static function place_timing( array &$matrix, array &$reserved, int $size ): void {
		for ( $i = 8; $i < $size - 8; $i++ ) {
			$val = ( $i % 2 === 0 ) ? 1 : 0;

			if ( ! $reserved[6][ $i ] ) {
				$matrix[6][ $i ]   = $val;
				$reserved[6][ $i ] = true;
			}
			if ( ! $reserved[ $i ][6] ) {
				$matrix[ $i ][6]   = $val;
				$reserved[ $i ][6] = true;
			}
		}
	}

	/**
	 * Place alignment patterns for versions >= 2.
	 *
	 * @param array<int,array<int,int>>  &$matrix   QR matrix.
	 * @param array<int,array<int,bool>> &$reserved Reserved map.
	 * @param int $version QR version.
	 * @param int $size    Matrix size.
	 */
	private static function place_alignment( array &$matrix, array &$reserved, int $version, int $size ): void {
		$positions = self::get_alignment_positions( $version );

		foreach ( $positions as $cy ) {
			foreach ( $positions as $cx ) {
				// Skip if overlapping with finder patterns.
				if ( $reserved[ $cy ][ $cx ] ) {
					continue;
				}

				for ( $r = -2; $r <= 2; $r++ ) {
					for ( $c = -2; $c <= 2; $c++ ) {
						$val = ( abs( $r ) === 2 || abs( $c ) === 2 || ( $r === 0 && $c === 0 ) ) ? 1 : 0;
						$matrix[ $cy + $r ][ $cx + $c ]   = $val;
						$reserved[ $cy + $r ][ $cx + $c ] = true;
					}
				}
			}
		}
	}

	/**
	 * Get alignment pattern center positions for a version.
	 *
	 * @param int $version QR version.
	 * @return array<int,int> Center positions.
	 */
	private static function get_alignment_positions( int $version ): array {
		$map = [
			2  => [ 6, 18 ],
			3  => [ 6, 22 ],
			4  => [ 6, 26 ],
			5  => [ 6, 30 ],
			6  => [ 6, 34 ],
			7  => [ 6, 22, 38 ],
			8  => [ 6, 24, 42 ],
			9  => [ 6, 26, 46 ],
			10 => [ 6, 28, 50 ],
		];
		return $map[ $version ] ?? [];
	}

	/**
	 * Reserve format info areas.
	 *
	 * @param array<int,array<int,bool>> &$reserved Reserved map.
	 * @param int $size Matrix size.
	 */
	private static function reserve_format( array &$reserved, int $size ): void {
		// Around top-left finder.
		for ( $i = 0; $i <= 8; $i++ ) {
			$reserved[8][ $i ] = true;
			$reserved[ $i ][8] = true;
		}

		// Around top-right finder.
		for ( $i = $size - 8; $i < $size; $i++ ) {
			$reserved[8][ $i ] = true;
		}

		// Around bottom-left finder.
		for ( $i = $size - 7; $i < $size; $i++ ) {
			$reserved[ $i ][8] = true;
		}

		// Dark module.
		$reserved[ $size - 8 ][8] = true;
	}

	/**
	 * Reserve version info areas.
	 *
	 * @param array<int,array<int,bool>> &$reserved Reserved map.
	 * @param int $size Matrix size.
	 */
	private static function reserve_version( array &$reserved, int $size ): void {
		for ( $i = 0; $i < 6; $i++ ) {
			for ( $j = $size - 11; $j < $size - 8; $j++ ) {
				$reserved[ $i ][ $j ] = true;
				$reserved[ $j ][ $i ] = true;
			}
		}
	}

	/**
	 * Place data codewords in the matrix.
	 *
	 * @param array<int,array<int,int>>  &$matrix   QR matrix.
	 * @param array<int,array<int,bool>> &$reserved Reserved map.
	 * @param array<int,int>             $codewords Data + EC codewords.
	 * @param int $size Matrix size.
	 */
	private static function place_data( array &$matrix, array &$reserved, array $codewords, int $size ): void {
		// Convert codewords to bit array.
		$bits = [];
		foreach ( $codewords as $cw ) {
			for ( $b = 7; $b >= 0; $b-- ) {
				$bits[] = ( $cw >> $b ) & 1;
			}
		}

		$bit_index = 0;
		$total_bits = count( $bits );

		// Traverse the matrix in the standard QR upward/downward zigzag.
		$col = $size - 1;
		while ( $col > 0 ) {
			// Skip timing pattern column.
			if ( $col === 6 ) {
				$col--;
			}

			for ( $row = 0; $row < $size; $row++ ) {
				// Determine actual row based on direction.
				// Even column-pairs go upward, odd go downward.
				$col_pair = ( $size - 1 - $col ) / 2;
				$actual_row = ( (int) $col_pair % 2 === 0 ) ? $size - 1 - $row : $row;

				for ( $dc = 0; $dc < 2; $dc++ ) {
					$actual_col = $col - $dc;
					if ( $actual_col < 0 ) {
						continue;
					}
					if ( $reserved[ $actual_row ][ $actual_col ] ) {
						continue;
					}
					if ( $bit_index < $total_bits ) {
						$matrix[ $actual_row ][ $actual_col ] = $bits[ $bit_index ];
						$bit_index++;
					}
				}
			}

			$col -= 2;
		}
	}

	/**
	 * Apply masking pattern 0: (row + column) % 2 == 0.
	 *
	 * @param array<int,array<int,int>>  &$matrix   QR matrix.
	 * @param array<int,array<int,bool>> &$reserved Reserved map.
	 * @param int $size Matrix size.
	 */
	private static function apply_mask( array &$matrix, array &$reserved, int $size ): void {
		for ( $r = 0; $r < $size; $r++ ) {
			for ( $c = 0; $c < $size; $c++ ) {
				if ( $reserved[ $r ][ $c ] ) {
					continue;
				}
				if ( ( $r + $c ) % 2 === 0 ) {
					$matrix[ $r ][ $c ] ^= 1;
				}
			}
		}
	}

	/**
	 * Write format information bits.
	 *
	 * EC level M (01) + mask pattern 0 (000) = 01000.
	 * Format info with BCH: 101010000010010 (pre-computed).
	 *
	 * @param array<int,array<int,int>> &$matrix QR matrix.
	 * @param int $size Matrix size.
	 */
	private static function write_format_info( array &$matrix, int $size ): void {
		// Format string for EC level M, mask 0: 101010000010010.
		$format_bits = '101010000010010';

		// Positions around top-left.
		$positions_tl = [
			[ 0, 8 ], [ 1, 8 ], [ 2, 8 ], [ 3, 8 ], [ 4, 8 ],
			[ 5, 8 ], [ 7, 8 ], [ 8, 8 ], [ 8, 7 ], [ 8, 5 ],
			[ 8, 4 ], [ 8, 3 ], [ 8, 2 ], [ 8, 1 ], [ 8, 0 ],
		];

		for ( $i = 0; $i < 15; $i++ ) {
			$matrix[ $positions_tl[ $i ][0] ][ $positions_tl[ $i ][1] ] = (int) $format_bits[ $i ];
		}

		// Positions around top-right and bottom-left.
		$positions_tr_bl = [
			[ 8, $size - 1 ], [ 8, $size - 2 ], [ 8, $size - 3 ],
			[ 8, $size - 4 ], [ 8, $size - 5 ], [ 8, $size - 6 ],
			[ 8, $size - 7 ], [ 8, $size - 8 ],
			[ $size - 7, 8 ], [ $size - 6, 8 ], [ $size - 5, 8 ],
			[ $size - 4, 8 ], [ $size - 3, 8 ], [ $size - 2, 8 ],
			[ $size - 1, 8 ],
		];

		for ( $i = 0; $i < 15; $i++ ) {
			$matrix[ $positions_tr_bl[ $i ][0] ][ $positions_tr_bl[ $i ][1] ] = (int) $format_bits[ $i ];
		}

		// Dark module.
		$matrix[ $size - 8 ][8] = 1;
	}

	/**
	 * Write version information bits (versions >= 7).
	 *
	 * @param array<int,array<int,int>> &$matrix QR matrix.
	 * @param int $version QR version.
	 * @param int $size    Matrix size.
	 */
	private static function write_version_info( array &$matrix, int $version, int $size ): void {
		// Pre-computed version info strings for versions 7-10.
		$version_info = [
			7  => '000111110010010100',
			8  => '001000010110111100',
			9  => '001001101010011001',
			10 => '001010010011010011',
		];

		if ( ! isset( $version_info[ $version ] ) ) {
			return;
		}

		$bits = $version_info[ $version ];

		for ( $i = 0; $i < 18; $i++ ) {
			$bit = (int) $bits[ $i ];
			$row = (int) floor( $i / 3 );
			$col = $size - 11 + ( $i % 3 );

			$matrix[ $row ][ $col ] = $bit;
			$matrix[ $col ][ $row ] = $bit;
		}
	}

	/**
	 * Static initializer: call before any encoding.
	 */
	public static function init(): void {
		self::init_gf();
	}
}

// Initialize GF tables on load.
QRCode::init();
