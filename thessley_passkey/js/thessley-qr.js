/**
 * Renders a QR code as inline SVG (vector, no canvas, no PNG data URL) into
 * the given element, using the bundled qrcode-generator library.
 *
 * The SVG carries its own white background and the four-module quiet zone
 * required by QR scanners. The outer wrapper's padding is only visual spacing.
 *
 * Usage: ThessleyQR.render( element, text, maxSizeInPixels )
 *
 * Every module (square) is drawn a whole number of CSS pixels wide, never
 * fractional — a fractional module size blurs the edges and makes dense
 * codes unreliable to scan, especially at 1x pixel density. The module
 * size is the largest whole number that fits maxSizeInPixels, capped at
 * 5 px (so a short payload does not balloon into a huge code) and floored
 * at 3 px (so a long payload may come out slightly wider than
 * maxSizeInPixels rather than unreadably small).
 */
( function ( global ) {
	'use strict';

	var MIN_MODULE_PX = 3;
	var MAX_MODULE_PX = 5;

	global.ThessleyQR = {
		render: function ( el, text, maxSize ) {
			// The payload is a percent-encoded URI (ASCII only), but make sure
			// any stray non-ASCII character is encoded as UTF-8 rather than
			// silently truncated to a byte.
			global.qrcode.stringToBytes = global.qrcode.stringToBytesFuncs[ 'UTF-8' ];

			// Version chosen automatically; error correction M is plenty for a
			// code shown on a screen (H would only make it needlessly dense).
			var qr = global.qrcode( 0, 'M' );
			qr.addData( text, 'Byte' );
			qr.make();

			var modules   = qr.getModuleCount();
			var quietZone = 4;
			var grid      = modules + quietZone * 2;
			var available = maxSize;
			if ( el.parentElement && el.parentElement.clientWidth ) {
				available = Math.min( available, el.parentElement.clientWidth );
			}
			var px  = Math.max( MIN_MODULE_PX, Math.min( MAX_MODULE_PX, Math.floor( available / grid ) ) );
			var dim = grid * px;

			// cellSize 1 preserves integer module coordinates. The viewBox includes
			// the quiet zone, and the SVG stays at its calculated pixel size instead
			// of stretching to the full width of its container.
			el.style.display = 'block';
			el.style.width = '100%';
			el.style.boxSizing = 'border-box';
			el.style.border = '1px solid #c3c4c7';
			el.innerHTML = qr.createSvgTag( { cellSize: 1, margin: quietZone, scalable: true } );

			var svg = el.querySelector( 'svg' );
			if ( svg ) {
				svg.setAttribute( 'width', dim );
				svg.setAttribute( 'height', dim );
				// Fit the available area without needlessly enlarging or distorting
				// the integer-pixel modules. max-width handles very narrow screens.
				svg.style.width = dim + 'px';
				svg.style.height = 'auto';
				svg.style.maxWidth = '100%';
				svg.style.display = 'block';
				svg.style.margin = '0 auto';
				svg.setAttribute( 'shape-rendering', 'crispEdges' );
				svg.setAttribute( 'role', 'img' );
				svg.setAttribute( 'aria-label', 'QR code' );
			}
		}
	};
}( window ) );
