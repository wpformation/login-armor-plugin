/**
 * Login Armor: Proof-of-Work solver (Bot Challenge module).
 *
 * Fetches a random challenge from the server, then searches for a counter
 * whose SHA-256 digest of "nonce:counter" carries the required number of
 * leading zero bits. Work happens in small chunks between timeouts so the
 * page stays responsive; a human's browser finishes in tens to hundreds of
 * milliseconds. The result is posted through two hidden fields.
 *
 * Fully self-contained vanilla JS: no library, no Web Crypto dependency
 * (crypto.subtle is unavailable on plain HTTP and its per-call overhead is
 * far too high for iterated hashing), no inline script (strict-CSP safe).
 */
(function () {
	'use strict';

	/* ------------------------------------------------------------------ */
	/* SHA-256 (FIPS 180-4), byte-array in, byte-array out.                */
	/* ------------------------------------------------------------------ */

	var K = [
		0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
		0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
		0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
		0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
		0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
		0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
		0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
		0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
	];

	function rotr( x, n ) {
		return ( x >>> n ) | ( x << ( 32 - n ) );
	}

	function sha256( bytes ) {
		var H0 = 0x6a09e667, H1 = 0xbb67ae85, H2 = 0x3c6ef372, H3 = 0xa54ff53a;
		var H4 = 0x510e527f, H5 = 0x9b05688c, H6 = 0x1f83d9ab, H7 = 0x5be0cd19;

		var l   = bytes.length;
		var msg = bytes.slice();
		msg.push( 0x80 );
		while ( msg.length % 64 !== 56 ) {
			msg.push( 0 );
		}
		var hi = ( l / 0x20000000 ) | 0;
		var lo = ( l << 3 ) >>> 0;
		msg.push( ( hi >>> 24 ) & 255, ( hi >>> 16 ) & 255, ( hi >>> 8 ) & 255, hi & 255 );
		msg.push( ( lo >>> 24 ) & 255, ( lo >>> 16 ) & 255, ( lo >>> 8 ) & 255, lo & 255 );

		var w = new Array( 64 );
		for ( var i = 0; i < msg.length; i += 64 ) {
			var t;
			for ( t = 0; t < 16; t++ ) {
				w[ t ] = ( msg[ i + t * 4 ] << 24 ) | ( msg[ i + t * 4 + 1 ] << 16 ) | ( msg[ i + t * 4 + 2 ] << 8 ) | msg[ i + t * 4 + 3 ];
			}
			for ( t = 16; t < 64; t++ ) {
				var s0 = rotr( w[ t - 15 ], 7 ) ^ rotr( w[ t - 15 ], 18 ) ^ ( w[ t - 15 ] >>> 3 );
				var s1 = rotr( w[ t - 2 ], 17 ) ^ rotr( w[ t - 2 ], 19 ) ^ ( w[ t - 2 ] >>> 10 );
				w[ t ] = ( w[ t - 16 ] + s0 + w[ t - 7 ] + s1 ) | 0;
			}

			var a = H0, b = H1, c = H2, d = H3, e = H4, f = H5, g = H6, h = H7;
			for ( t = 0; t < 64; t++ ) {
				var S1    = rotr( e, 6 ) ^ rotr( e, 11 ) ^ rotr( e, 25 );
				var ch    = ( e & f ) ^ ( ~e & g );
				var temp1 = ( h + S1 + ch + K[ t ] + w[ t ] ) | 0;
				var S0    = rotr( a, 2 ) ^ rotr( a, 13 ) ^ rotr( a, 22 );
				var maj   = ( a & b ) ^ ( a & c ) ^ ( b & c );
				var temp2 = ( S0 + maj ) | 0;
				h = g; g = f; f = e; e = ( d + temp1 ) | 0;
				d = c; c = b; b = a; a = ( temp1 + temp2 ) | 0;
			}
			H0 = ( H0 + a ) | 0; H1 = ( H1 + b ) | 0; H2 = ( H2 + c ) | 0; H3 = ( H3 + d ) | 0;
			H4 = ( H4 + e ) | 0; H5 = ( H5 + f ) | 0; H6 = ( H6 + g ) | 0; H7 = ( H7 + h ) | 0;
		}

		var words = [ H0, H1, H2, H3, H4, H5, H6, H7 ];
		var out   = new Array( 32 );
		for ( var j = 0; j < 8; j++ ) {
			out[ j * 4 ]     = ( words[ j ] >>> 24 ) & 255;
			out[ j * 4 + 1 ] = ( words[ j ] >>> 16 ) & 255;
			out[ j * 4 + 2 ] = ( words[ j ] >>> 8 ) & 255;
			out[ j * 4 + 3 ] = words[ j ] & 255;
		}
		return out;
	}

	function asciiBytes( str ) {
		var out = new Array( str.length );
		for ( var i = 0; i < str.length; i++ ) {
			out[ i ] = str.charCodeAt( i ) & 255;
		}
		return out;
	}

	function leadingZeroBits( digest ) {
		var bits = 0;
		for ( var i = 0; i < digest.length; i++ ) {
			var byte = digest[ i ];
			if ( byte === 0 ) {
				bits += 8;
				continue;
			}
			for ( var b = 7; b >= 0; b-- ) {
				if ( ( byte >>> b ) & 1 ) {
					return bits;
				}
				bits++;
			}
		}
		return bits;
	}

	// Known-answer self-test: sha256("abc"). If the engine miscompiles the
	// implementation, do nothing: fields stay empty and log_only reveals it.
	function selfTest() {
		var d = sha256( asciiBytes( 'abc' ) );
		return d[ 0 ] === 0xba && d[ 1 ] === 0x78 && d[ 2 ] === 0x16 && d[ 3 ] === 0xbf && d[ 31 ] === 0xad;
	}

	/* ------------------------------------------------------------------ */
	/* Challenge lifecycle per form.                                       */
	/* ------------------------------------------------------------------ */

	var CHUNK       = 2048;   // Hashes per timeout slice.
	var MAX_ITER    = 33554432; // 2^25 hard stop, far beyond any preset.
	var REFRESH_MS  = 600000; // Re-fetch a fresh challenge every 10 minutes.
	var RETRY_MS    = 2000;   // One retry after a failed fetch.

	function createState( wrapper ) {
		var form = wrapper.closest( 'form' );
		if ( ! form ) {
			return null;
		}
		return {
			form: form,
			endpoint: wrapper.getAttribute( 'data-la-pow-endpoint' ),
			nonceInput: wrapper.querySelector( 'input[name="la_pow_n"]' ),
			solInput: wrapper.querySelector( 'input[name="la_pow_s"]' ),
			generation: 0,
			solving: false,
			solved: false,
			pendingSubmit: false,
			retried: false
		};
	}

	function fetchChallenge( state ) {
		state.generation++;
		state.solving = true;
		state.solved  = false;
		var gen = state.generation;

		var xhr = new XMLHttpRequest();
		xhr.open( 'POST', state.endpoint, true );
		xhr.setRequestHeader( 'Content-Type', 'application/x-www-form-urlencoded; charset=UTF-8' );
		xhr.onreadystatechange = function () {
			if ( xhr.readyState !== 4 || gen !== state.generation ) {
				return;
			}
			var payload = null;
			try {
				payload = JSON.parse( xhr.responseText );
			} catch ( e ) {
				payload = null;
			}
			if ( xhr.status === 200 && payload && payload.success && payload.data && payload.data.nonce ) {
				solve( state, gen, String( payload.data.nonce ), parseInt( payload.data.bits, 10 ) || 15 );
			} else if ( ! state.retried ) {
				state.retried = true;
				window.setTimeout( function () {
					if ( gen === state.generation ) {
						state.generation--; // fetchChallenge re-increments.
						fetchChallenge( state );
					}
				}, RETRY_MS );
			} else {
				state.solving = false;
			}
		};
		xhr.send( 'action=login_armor_pow_challenge' );
	}

	function solve( state, gen, nonce, bits ) {
		var prefix  = asciiBytes( nonce + ':' );
		var counter = 0;

		function chunk() {
			if ( gen !== state.generation ) {
				return; // A newer challenge superseded this one.
			}
			var end = counter + CHUNK;
			for ( ; counter < end; counter++ ) {
				var digest = sha256( prefix.concat( asciiBytes( String( counter ) ) ) );
				if ( leadingZeroBits( digest ) >= bits ) {
					state.nonceInput.value = nonce;
					state.solInput.value   = String( counter );
					state.solving          = false;
					state.solved           = true;
					if ( state.pendingSubmit ) {
						state.pendingSubmit = false;
						state.form.submit();
					}
					return;
				}
			}
			if ( counter < MAX_ITER ) {
				window.setTimeout( chunk, 0 );
			} else {
				state.solving = false;
			}
		}

		chunk();
	}

	function bindForm( state ) {
		state.form.addEventListener( 'submit', function ( event ) {
			if ( state.solved || ( ! state.solving && ! state.pendingSubmit ) ) {
				return; // Solved, or solver gave up: let the server decide.
			}
			// Still solving: hold the submission and fire it once solved.
			event.preventDefault();
			state.pendingSubmit = true;
		} );

		// Periodic refresh: a form left open past the challenge TTL would
		// otherwise submit an expired proof.
		window.setInterval( function () {
			if ( ! state.pendingSubmit ) {
				state.retried = false;
				fetchChallenge( state );
			}
		}, REFRESH_MS );

		// bfcache restore: the DOM may carry an already-consumed proof.
		window.addEventListener( 'pageshow', function ( event ) {
			if ( event.persisted ) {
				state.retried = false;
				fetchChallenge( state );
			}
		} );
	}

	function init() {
		if ( ! selfTest() ) {
			return;
		}
		var wrappers = document.querySelectorAll( '.la-pow-wrap[data-la-pow-endpoint]' );
		for ( var i = 0; i < wrappers.length; i++ ) {
			var state = createState( wrappers[ i ] );
			if ( state && state.nonceInput && state.solInput && state.endpoint ) {
				bindForm( state );
				fetchChallenge( state );
			}
		}
	}

	if ( document.readyState === 'loading' ) {
		document.addEventListener( 'DOMContentLoaded', init );
	} else {
		init();
	}
})();
