/**
 * Login Armor: Minimal QR Code generator (client-side SVG).
 *
 * Byte-mode encoding, EC level M, versions 1-10.
 * Generates inline SVG suitable for otpauth:// URIs.
 *
 * @package LoginArmor
 * @since   2.2.0
 */
var LoginArmorQR = (function () {
	'use strict';

	// ── GF(256) arithmetic ──────────────────────────────────────

	var GF_EXP = new Array(512);
	var GF_LOG = new Array(256);

	(function initGF() {
		var x = 1;
		for (var i = 0; i < 255; i++) {
			GF_EXP[i] = x;
			GF_LOG[x] = i;
			x <<= 1;
			if (x >= 256) { x ^= 0x11D; }
		}
		for (var i = 255; i < 512; i++) {
			GF_EXP[i] = GF_EXP[i - 255];
		}
	})();

	function gfMul(a, b) {
		if (a === 0 || b === 0) { return 0; }
		return GF_EXP[(GF_LOG[a] + GF_LOG[b]) % 255];
	}

	// ── Reed-Solomon ────────────────────────────────────────────

	function rsGeneratorPoly(degree) {
		// Coefficients stored highest-degree-first (gen[0] = leading = 1).
		var gen = [1];
		for (var i = 0; i < degree; i++) {
			var ng = new Array(gen.length + 1);
			for (var k = 0; k < ng.length; k++) { ng[k] = 0; }
			var ai = GF_EXP[i];
			for (var j = 0; j < gen.length; j++) {
				ng[j] ^= gen[j];                  // x * gen[j] → same position (shifted array grows right).
				ng[j + 1] ^= gfMul(gen[j], ai);   // a^i * gen[j] → one position lower.
			}
			gen = ng;
		}
		return gen;
	}

	function rsEncode(data, ecCount) {
		var gen = rsGeneratorPoly(ecCount);
		var rem = new Array(data.length + ecCount);
		for (var i = 0; i < data.length; i++) { rem[i] = data[i]; }
		for (var i = data.length; i < rem.length; i++) { rem[i] = 0; }
		for (var i = 0; i < data.length; i++) {
			var c = rem[i];
			if (c !== 0) {
				for (var j = 0; j < gen.length; j++) {
					rem[i + j] ^= gfMul(c, gen[j]);
				}
			}
		}
		return rem.slice(data.length);
	}

	// ── QR Tables ───────────────────────────────────────────────

	// Byte-mode capacity at EC level M, versions 1-10.
	var CAPACITIES = [0, 14, 26, 42, 62, 84, 106, 122, 152, 180, 213];

	// Total codewords (data + EC) per version.
	var TOTAL_CW = [0, 26, 44, 70, 100, 134, 172, 196, 242, 292, 346];

	// Data codewords per version at EC level M.
	var DATA_CW = [0, 16, 28, 44, 64, 86, 108, 124, 154, 182, 216];

	// EC codewords per block at EC level M.
	var EC_PER_BLOCK = [0, 10, 16, 26, 18, 24, 16, 18, 22, 22, 26];

	// Block structure: [[count, dataPerBlock], ...] at EC level M.
	var BLOCKS = [
		[],
		[[1, 16]],
		[[1, 28]],
		[[1, 44]],
		[[2, 32]],
		[[2, 43]],
		[[4, 27]],
		[[4, 31]],
		[[2, 38], [2, 39]],
		[[3, 36], [2, 37]],
		[[4, 43], [1, 44]]
	];

	// Alignment pattern positions.
	var ALIGN_POS = [
		[], [], [6, 18], [6, 22], [6, 26], [6, 30],
		[6, 34], [6, 22, 38], [6, 24, 42], [6, 26, 46], [6, 28, 50]
	];

	// ── Encoding ────────────────────────────────────────────────

	function encodeData(text) {
		var bytes = [];
		for (var i = 0; i < text.length; i++) {
			var code = text.charCodeAt(i);
			if (code < 128) {
				bytes.push(code);
			} else if (code < 2048) {
				bytes.push(0xC0 | (code >> 6), 0x80 | (code & 0x3F));
			} else {
				bytes.push(0xE0 | (code >> 12), 0x80 | ((code >> 6) & 0x3F), 0x80 | (code & 0x3F));
			}
		}

		// Determine version.
		var version = 0;
		for (var v = 1; v <= 10; v++) {
			if (bytes.length <= CAPACITIES[v]) { version = v; break; }
		}
		if (version === 0) { version = 10; bytes = bytes.slice(0, 213); }

		var charCountBits = version <= 9 ? 8 : 16;
		var totalDataCw = DATA_CW[version];

		// Build bit string: mode(4) + count + data + terminator + padding.
		var bits = '';
		bits += '0100'; // byte mode
		bits += padBin(bytes.length, charCountBits);
		for (var i = 0; i < bytes.length; i++) {
			bits += padBin(bytes[i], 8);
		}
		bits += '0000'; // terminator
		// Pad to byte boundary.
		var r = bits.length % 8;
		if (r > 0) { bits += '00000000'.substr(0, 8 - r); }
		// Pad bytes.
		var pads = ['11101100', '00010001'];
		var pi = 0;
		while (bits.length < totalDataCw * 8) {
			bits += pads[pi]; pi = (pi + 1) % 2;
		}
		bits = bits.substr(0, totalDataCw * 8);

		// Convert to codeword array.
		var codewords = [];
		for (var i = 0; i < bits.length; i += 8) {
			codewords.push(parseInt(bits.substr(i, 8), 2));
		}

		return { version: version, codewords: codewords };
	}

	function padBin(val, len) {
		var s = val.toString(2);
		while (s.length < len) { s = '0' + s; }
		return s;
	}

	// ── Error Correction + Interleaving ─────────────────────────

	function addEC(codewords, version) {
		var ecPerBlock = EC_PER_BLOCK[version];
		var blockDefs = BLOCKS[version];
		var dataBlocks = [];
		var ecBlocks = [];
		var offset = 0;

		for (var g = 0; g < blockDefs.length; g++) {
			var count = blockDefs[g][0];
			var dataPer = blockDefs[g][1];
			for (var b = 0; b < count; b++) {
				var block = codewords.slice(offset, offset + dataPer);
				dataBlocks.push(block);
				ecBlocks.push(rsEncode(block, ecPerBlock));
				offset += dataPer;
			}
		}

		// Interleave data blocks.
		var result = [];
		var maxData = 0;
		for (var i = 0; i < dataBlocks.length; i++) {
			if (dataBlocks[i].length > maxData) { maxData = dataBlocks[i].length; }
		}
		for (var i = 0; i < maxData; i++) {
			for (var j = 0; j < dataBlocks.length; j++) {
				if (i < dataBlocks[j].length) { result.push(dataBlocks[j][i]); }
			}
		}
		// Interleave EC blocks.
		for (var i = 0; i < ecPerBlock; i++) {
			for (var j = 0; j < ecBlocks.length; j++) {
				if (i < ecBlocks[j].length) { result.push(ecBlocks[j][i]); }
			}
		}

		return result;
	}

	// ── Matrix Construction ─────────────────────────────────────

	function createMatrix(version) {
		var size = 17 + version * 4;
		var matrix = [];
		var reserved = [];
		for (var r = 0; r < size; r++) {
			matrix[r] = new Array(size);
			reserved[r] = new Array(size);
			for (var c = 0; c < size; c++) {
				matrix[r][c] = 0;
				reserved[r][c] = false;
			}
		}
		return { matrix: matrix, reserved: reserved, size: size };
	}

	function placeFinder(m, res, size, row, col) {
		var pat = [
			[1,1,1,1,1,1,1],
			[1,0,0,0,0,0,1],
			[1,0,1,1,1,0,1],
			[1,0,1,1,1,0,1],
			[1,0,1,1,1,0,1],
			[1,0,0,0,0,0,1],
			[1,1,1,1,1,1,1]
		];
		for (var r = -1; r <= 7; r++) {
			for (var c = -1; c <= 7; c++) {
				var mr = row + r, mc = col + c;
				if (mr < 0 || mr >= size || mc < 0 || mc >= size) { continue; }
				if (r >= 0 && r < 7 && c >= 0 && c < 7) {
					m[mr][mc] = pat[r][c];
				} else {
					m[mr][mc] = 0;
				}
				res[mr][mc] = true;
			}
		}
	}

	function placeTiming(m, res, size) {
		for (var i = 8; i < size - 8; i++) {
			var v = (i % 2 === 0) ? 1 : 0;
			if (!res[6][i]) { m[6][i] = v; res[6][i] = true; }
			if (!res[i][6]) { m[i][6] = v; res[i][6] = true; }
		}
	}

	function placeAlignment(m, res, version, size) {
		var positions = ALIGN_POS[version];
		if (!positions || positions.length === 0) { return; }
		for (var yi = 0; yi < positions.length; yi++) {
			for (var xi = 0; xi < positions.length; xi++) {
				var cy = positions[yi], cx = positions[xi];
				// Skip only if overlapping with finder patterns (not timing).
				if ((cy <= 8 && cx <= 8) || (cy <= 8 && cx >= size - 8) || (cy >= size - 8 && cx <= 8)) { continue; }
				for (var r = -2; r <= 2; r++) {
					for (var c = -2; c <= 2; c++) {
						var v = (Math.abs(r) === 2 || Math.abs(c) === 2 || (r === 0 && c === 0)) ? 1 : 0;
						m[cy + r][cx + c] = v;
						res[cy + r][cx + c] = true;
					}
				}
			}
		}
	}

	function reserveFormat(res, size) {
		for (var i = 0; i <= 8; i++) { res[8][i] = true; res[i][8] = true; }
		for (var i = size - 8; i < size; i++) { res[8][i] = true; }
		for (var i = size - 7; i < size; i++) { res[i][8] = true; }
		res[size - 8][8] = true;
	}

	function reserveVersion(res, size) {
		for (var i = 0; i < 6; i++) {
			for (var j = size - 11; j < size - 8; j++) {
				res[i][j] = true;
				res[j][i] = true;
			}
		}
	}

	function placeData(m, res, codewords, size) {
		var bits = [];
		for (var i = 0; i < codewords.length; i++) {
			for (var b = 7; b >= 0; b--) {
				bits.push((codewords[i] >> b) & 1);
			}
		}

		var bi = 0;
		var col = size - 1;
		while (col > 0) {
			if (col === 6) { col--; }
			for (var row = 0; row < size; row++) {
				var colPair = Math.floor((size - 1 - col) / 2);
				var actualRow = (colPair % 2 === 0) ? size - 1 - row : row;
				for (var dc = 0; dc < 2; dc++) {
					var ac = col - dc;
					if (ac < 0 || res[actualRow][ac]) { continue; }
					if (bi < bits.length) {
						m[actualRow][ac] = bits[bi++];
					}
				}
			}
			col -= 2;
		}
	}

	// ── Masking ─────────────────────────────────────────────────

	var MASK_FNS = [
		function (r, c) { return (r + c) % 2 === 0; },
		function (r, c) { return r % 2 === 0; },
		function (r, c) { return c % 3 === 0; },
		function (r, c) { return (r + c) % 3 === 0; },
		function (r, c) { return (Math.floor(r / 2) + Math.floor(c / 3)) % 2 === 0; },
		function (r, c) { return (r * c) % 2 + (r * c) % 3 === 0; },
		function (r, c) { return ((r * c) % 2 + (r * c) % 3) % 2 === 0; },
		function (r, c) { return ((r + c) % 2 + (r * c) % 3) % 2 === 0; }
	];

	// Pre-computed format info strings (EC level M, masks 0-7) with BCH.
	var FORMAT_INFO = [
		'101010000010010', '101000100100101', '101111001111100', '101101101001011',
		'100010111111001', '100000011001110', '100111110010111', '100101010100000'
	];

	function applyMask(m, res, size, maskIdx) {
		var fn = MASK_FNS[maskIdx];
		for (var r = 0; r < size; r++) {
			for (var c = 0; c < size; c++) {
				if (!res[r][c] && fn(r, c)) { m[r][c] ^= 1; }
			}
		}
	}

	function writeFormatInfo(m, size, maskIdx) {
		var bits = FORMAT_INFO[maskIdx];

		// First copy: row 8 left-to-right (skip col 6), then col 8 bottom-to-top (skip row 6).
		var tlPos = [
			[8,0],[8,1],[8,2],[8,3],[8,4],[8,5],[8,7],[8,8],
			[7,8],[5,8],[4,8],[3,8],[2,8],[1,8],[0,8]
		];
		for (var i = 0; i < 15; i++) {
			m[tlPos[i][0]][tlPos[i][1]] = parseInt(bits[i], 10);
		}

		// Second copy: col 8 bottom-to-top, then row 8 left-to-right.
		var otherPos = [
			[size-1,8],[size-2,8],[size-3,8],[size-4,8],[size-5,8],[size-6,8],[size-7,8],
			[8,size-8],[8,size-7],[8,size-6],[8,size-5],[8,size-4],[8,size-3],[8,size-2],[8,size-1]
		];
		for (var i = 0; i < 15; i++) {
			m[otherPos[i][0]][otherPos[i][1]] = parseInt(bits[i], 10);
		}

		m[size - 8][8] = 1; // dark module
	}

	function writeVersionInfo(m, version, size) {
		var VI = {
			7: '000111110010010100', 8: '001000010110111100',
			9: '001001101010011001', 10: '001010010011010011'
		};
		if (!VI[version]) { return; }
		var bits = VI[version];
		for (var i = 0; i < 18; i++) {
			var bit = parseInt(bits[17 - i], 10);
			var row = Math.floor(i / 3);
			var col = size - 11 + (i % 3);
			m[row][col] = bit;
			m[col][row] = bit;
		}
	}

	// ── Penalty scoring (for mask selection) ────────────────────

	function penalty(m, size) {
		var score = 0;

		// Rule 1: runs of same color.
		for (var r = 0; r < size; r++) {
			var run = 1;
			for (var c = 1; c < size; c++) {
				if (m[r][c] === m[r][c - 1]) { run++; } else { if (run >= 5) { score += run - 2; } run = 1; }
			}
			if (run >= 5) { score += run - 2; }
		}
		for (var c = 0; c < size; c++) {
			var run = 1;
			for (var r = 1; r < size; r++) {
				if (m[r][c] === m[r - 1][c]) { run++; } else { if (run >= 5) { score += run - 2; } run = 1; }
			}
			if (run >= 5) { score += run - 2; }
		}

		// Rule 2: 2x2 blocks.
		for (var r = 0; r < size - 1; r++) {
			for (var c = 0; c < size - 1; c++) {
				var v = m[r][c];
				if (v === m[r][c+1] && v === m[r+1][c] && v === m[r+1][c+1]) { score += 3; }
			}
		}

		return score;
	}

	// ── Main entry ──────────────────────────────────────────────

	function generateSVG(text, moduleSize) {
		moduleSize = moduleSize || 4;
		var quietZone = 4;

		var encoded = encodeData(text);
		var version = encoded.version;
		var size = 17 + version * 4;

		var finalCw = addEC(encoded.codewords, version);

		// Try all 8 masks and pick the best.
		var bestMask = 0;
		var bestPenalty = Infinity;

		for (var mask = 0; mask < 8; mask++) {
			var q = createMatrix(version);
			placeFinder(q.matrix, q.reserved, size, 0, 0);
			placeFinder(q.matrix, q.reserved, size, size - 7, 0);
			placeFinder(q.matrix, q.reserved, size, 0, size - 7);
			placeTiming(q.matrix, q.reserved, size);
			if (version >= 2) { placeAlignment(q.matrix, q.reserved, version, size); }
			reserveFormat(q.reserved, size);
			if (version >= 7) { reserveVersion(q.reserved, size); }
			placeData(q.matrix, q.reserved, finalCw, size);
			applyMask(q.matrix, q.reserved, size, mask);
			writeFormatInfo(q.matrix, size, mask);
			if (version >= 7) { writeVersionInfo(q.matrix, version, size); }

			var p = penalty(q.matrix, size);
			if (p < bestPenalty) { bestPenalty = p; bestMask = mask; }
		}

		// Build final matrix with best mask.
		var q = createMatrix(version);
		placeFinder(q.matrix, q.reserved, size, 0, 0);
		placeFinder(q.matrix, q.reserved, size, size - 7, 0);
		placeFinder(q.matrix, q.reserved, size, 0, size - 7);
		placeTiming(q.matrix, q.reserved, size);
		if (version >= 2) { placeAlignment(q.matrix, q.reserved, version, size); }
		reserveFormat(q.reserved, size);
		if (version >= 7) { reserveVersion(q.reserved, size); }
		placeData(q.matrix, q.reserved, finalCw, size);
		applyMask(q.matrix, q.reserved, size, bestMask);
		writeFormatInfo(q.matrix, size, bestMask);
		if (version >= 7) { writeVersionInfo(q.matrix, version, size); }

		// Render SVG.
		var total = (size + quietZone * 2) * moduleSize;
		var svg = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ' + total + ' ' + total + '" width="' + total + '" height="' + total + '">';
		svg += '<rect width="100%" height="100%" fill="#ffffff"/>';
		svg += '<path d="';
		for (var y = 0; y < size; y++) {
			for (var x = 0; x < size; x++) {
				if (q.matrix[y][x]) {
					var px = (x + quietZone) * moduleSize;
					var py = (y + quietZone) * moduleSize;
					svg += 'M' + px + ',' + py + 'h' + moduleSize + 'v' + moduleSize + 'h-' + moduleSize + 'z';
				}
			}
		}
		svg += '" fill="#000000"/></svg>';
		return svg;
	}

	return { toSVG: generateSVG };
})();
