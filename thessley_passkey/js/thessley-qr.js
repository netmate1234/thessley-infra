/**
 * Renders a QR code as inline SVG (vector, no canvas, no PNG data URL) into
 * the given element, using the bundled qrcode-generator library.
 *
 * The SVG carries its own white background and no quiet-zone margin: the
 * caller's wrapper supplies the white padding around it, so the code stays
 * crisp and scannable at any size or screen density.
 *
 * Usage: ThessleyQR.render( element, text, maxSizeInPixels )
 *
 * Every module (square) is drawn a whole number of CSS pixels wide, never
 * fractional — a fractional module size blurs the edges and makes dense
 * codes unreliable to scan, especially at 1x pixel density. The module
 * size is the largest whole number that fits maxSizeInPixels, capped at
 * 4 px (so a short payload does not balloon into a huge code) and floored
 * at 3 px (so a long payload may come out slightly wider than
 * maxSizeInPixels rather than unreadably small).
 */
( function ( global ) {
	'use strict';

	var MIN_MODULE_PX = 3;
	var MAX_MODULE_PX = 4;

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

			var modules = qr.getModuleCount();
			var px      = Math.max( MIN_MODULE_PX, Math.min( MAX_MODULE_PX, Math.floor( maxSize / modules ) ) );
			var dim     = modules * px;

			// cellSize 1 + scalable: the viewBox is exactly the module grid, so
			// the code scales cleanly to any width (crispEdges keeps the squares sharp).
			// The padded white holder spans the available width; the code inside
			// scales to it (see below).
			el.style.display = 'block';
			el.style.width = '100%';
			el.style.boxSizing = 'border-box';
			el.innerHTML = qr.createSvgTag( { cellSize: 1, margin: 0, scalable: true } );

			var svg = el.querySelector( 'svg' );
			if ( svg ) {
				svg.setAttribute( 'width', dim );
				svg.setAttribute( 'height', dim );
				// The code fills the width of its holder (100%) and stays square
				// through the viewBox, so it can never run past a narrow screen.
				// The width/height attributes above are only the fallback size.
				svg.style.width = '100%';
				svg.style.height = 'auto';
				svg.style.display = 'block';
				svg.setAttribute( 'shape-rendering', 'crispEdges' );
				svg.setAttribute( 'role', 'img' );
				svg.setAttribute( 'aria-label', 'QR code' );
			}
		}
	};
}( window ) );
