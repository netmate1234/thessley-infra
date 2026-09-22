<?php
/**
 * Plugin Name: Crawler Nets Updater
 * Description: Keeps crawler-nets.conf's vendor sections current from
 *              each vendor's own published IP-range list, without ever
 *              touching anything else in the file. Deployed as a
 *              mu-plugin on wp-opsec.eagleeye-intelligence.com, writing
 *              to that same site's own wp-content/uploads/wp-opsec/ —
 *              deliberately, not the system-level
 *              /etc/eagleeye/crawler-nets.conf (root:root, also feeds a
 *              separate iptables deployment script): this file lives
 *              entirely inside a normal WordPress install, so the
 *              www-data user that WP-Cron runs as can write it directly
 *              with no privilege boundary to cross. Every Thessley
 *              Security install's Whitelist tab points at this URL by default
 *              (see whitelist/module.php's DEFAULT_URL) and re-fetches
 *              it daily, so a change here reaches the whole fleet
 *              through the mechanism that already exists — no
 *              per-install action needed.
 *
 * Not part of the Thessley Security Hardening plugin itself: this is single-host
 * infrastructure automation for eagleeye's own crawler-nets.conf, not
 * something every Thessley Security Hardening install should run. Kept in the
 * wp_opsec repo (infra/, sibling to the plugin's own opsec/ directory)
 * purely for version control — it is
 * never bundled into the distributable plugin zip.
 *
 * Design: crawler-nets.conf is hand-curated (friend IPs, protected own
 * infrastructure, a backup server, a dozen crawler vendors) — nothing here
 * should ever be silently dropped just because an automated source no
 * longer lists it. This only ever APPENDS ranges that are genuinely new
 * (not already present anywhere in the file, in any section), into the
 * matching existing section, with a dated comment matching the file's
 * own established annotation style. It never removes or rewrites an
 * existing line.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

define( 'THESSLEY_CNU_TARGET_FILE', WP_CONTENT_DIR . '/uploads/wp-opsec/crawler-nets.conf' );

define(
	'THESSLEY_CNU_SOURCES',
	array(
		'Googlebot'   => array(
			'url'     => 'https://developers.google.com/static/search/apis/ipranges/googlebot.json',
			'heading' => '# Googlebot / Google infrastructure',
			'format'  => 'json_prefixes',
		),
		// Google publishes its crawler fleet as three separate official
		// feeds, not one — this covers AdsBot-Google (ad-quality checks)
		// and Google-Inspection / user-triggered fetch tools respectively,
		// both genuinely distinct bots seen in real traffic, both Google's
		// own infrastructure. Same section as the main Googlebot feed.
		'Google special-crawlers'        => array(
			'url'     => 'https://developers.google.com/static/search/apis/ipranges/special-crawlers.json',
			'heading' => '# Googlebot / Google infrastructure',
			'format'  => 'json_prefixes',
		),
		'Google user-triggered-fetchers' => array(
			'url'     => 'https://developers.google.com/static/search/apis/ipranges/user-triggered-fetchers.json',
			'heading' => '# Googlebot / Google infrastructure',
			'format'  => 'json_prefixes',
		),
		'Bingbot'     => array(
			'url'     => 'https://www.bing.com/toolbox/bingbot.json',
			'heading' => '# Bingbot / MSN (Microsoft)',
			'format'  => 'json_prefixes',
		),
		'DuckDuckGo'  => array(
			'url'     => 'https://duckduckgo.com/duckduckbot.json',
			'heading' => '# DuckDuckGo (DuckDuckBot) — Azure-hosted crawler (2026-05-24)',
			'format'  => 'json_prefixes',
		),
		'OpenAI GPTBot' => array(
			'url'     => 'https://openai.com/gptbot.json',
			'heading' => '# OpenAI GPTBot — AI search crawler (2026-05-24)',
			'format'  => 'json_prefixes',
		),
		// OpenAI publishes three separate bot feeds too: GPTBot (training
		// data), ChatGPT-User (live browsing on a user's behalf), and
		// OAI-SearchBot (their search product) — same section, since
		// they're all OpenAI's own infrastructure.
		'ChatGPT-User' => array(
			'url'     => 'https://openai.com/chatgpt-user.json',
			'heading' => '# OpenAI GPTBot — AI search crawler (2026-05-24)',
			'format'  => 'json_prefixes',
		),
		'OAI-SearchBot' => array(
			'url'     => 'https://openai.com/searchbot.json',
			'heading' => '# OpenAI GPTBot — AI search crawler (2026-05-24)',
			'format'  => 'json_prefixes',
		),
		'Cloudflare'  => array(
			'url'     => 'https://www.cloudflare.com/ips-v4',
			'heading' => '# Cloudflare CDN proxy (AS13335) — legitimate CDN traffic',
			'format'  => 'plain_cidr_list',
		),
	)
);

define( 'THESSLEY_CNU_CRON_HOOK', 'thessley_cnu_refresh' );

// mu-plugins bypass the standard activation lifecycle entirely — there is
// no activation hook to bind to, this file just runs on every request —
// so this direct check is the real (idempotent) bootstrap for a fresh
// deploy: schedules once, then no-ops on every subsequent request.
if ( ! wp_next_scheduled( THESSLEY_CNU_CRON_HOOK ) ) {
	wp_schedule_event( time() + ( 5 * MINUTE_IN_SECONDS ), 'weekly', THESSLEY_CNU_CRON_HOOK );
}

add_action( THESSLEY_CNU_CRON_HOOK, 'thessley_cnu_run' );

function thessley_cnu_run() {
	if ( ! is_readable( THESSLEY_CNU_TARGET_FILE ) || ! is_writable( THESSLEY_CNU_TARGET_FILE ) ) {
		thessley_cnu_log( 'target file missing or not writable: ' . THESSLEY_CNU_TARGET_FILE );
		return;
	}

	$content = file_get_contents( THESSLEY_CNU_TARGET_FILE );
	if ( false === $content ) {
		thessley_cnu_log( 'failed to read target file' );
		return;
	}

	// Every CIDR already present anywhere in the file, as [start, end]
	// integer ranges — not just exact strings. Google in particular
	// republishes some of its space as many small /27s that are already
	// fully covered by a broader range already in the file (e.g. an
	// existing 66.249.64.0/19 already contains dozens of the /27s it now
	// lists individually); a plain string-equality dedupe would add all
	// of those as pointless, redundant lines. Containment catches that
	// a plain set never would.
	$existing = array();
	foreach ( preg_split( '/\r\n|\r|\n/', $content ) as $line ) {
		$line = trim( $line );
		if ( '' !== $line && '#' !== $line[0] && false !== strpos( $line, '/' ) ) {
			$range = thessley_cnu_cidr_to_range( $line );
			if ( null !== $range ) {
				$existing[] = $range;
			}
		}
	}

	$added_total = 0;

	foreach ( THESSLEY_CNU_SOURCES as $label => $source ) {
		$fetched = thessley_cnu_fetch( $source['url'], $source['format'] );
		if ( false === $fetched ) {
			thessley_cnu_log( "{$label}: fetch failed, skipped" );
			continue;
		}

		$new = array();
		foreach ( $fetched as $cidr ) {
			$range = thessley_cnu_cidr_to_range( $cidr );
			if ( null === $range || thessley_cnu_range_covered( $range, $existing ) ) {
				continue;
			}
			$new[]      = $cidr;
			$existing[] = $range; // dedupe within this same run too
		}

		if ( empty( $new ) ) {
			thessley_cnu_log( "{$label}: {$source ['url']} — nothing new (" . count( $fetched ) . ' ranges checked)' );
			continue;
		}

		sort( $new );
		$content = thessley_cnu_insert_into_section( $content, $source['heading'], $label, $new );
		$added_total += count( $new );
		thessley_cnu_log( "{$label}: added " . count( $new ) . ' new range(s)' );
	}

	if ( $added_total > 0 ) {
		$tmp = THESSLEY_CNU_TARGET_FILE . '.tmp-' . bin2hex( random_bytes( 4 ) );
		file_put_contents( $tmp, $content, LOCK_EX );
		rename( $tmp, THESSLEY_CNU_TARGET_FILE );
		thessley_cnu_log( "wrote {$added_total} new range(s) total" );
	}
}

/** @return array{0:int,1:int}|null [start, end] as unsigned 32-bit integers, or null if unparseable */
function thessley_cnu_cidr_to_range( $cidr ) {
	if ( false === strpos( $cidr, '/' ) ) {
		return null;
	}
	list( $ip, $prefix ) = explode( '/', $cidr, 2 );
	$prefix = (int) $prefix;
	$long   = ip2long( trim( $ip ) );
	if ( false === $long || $prefix < 0 || $prefix > 32 ) {
		return null;
	}
	// Same bitmask approach used throughout the rest of this codebase
	// (e.g. ip-blocklist's compiler) — PHP ints are 64-bit on every host
	// this runs on, so ip2long()'s result needs no unsigned conversion.
	$mask = 32 === $prefix ? 0xFFFFFFFF : ( 0xFFFFFFFF << ( 32 - $prefix ) ) & 0xFFFFFFFF;
	$net  = $long & $mask;
	return array( $net, $net | ( ~$mask & 0xFFFFFFFF ) );
}

/** @param array{0:int,1:int} $range @param array<int,array{0:int,1:int}> $existing */
function thessley_cnu_range_covered( array $range, array $existing ) {
	foreach ( $existing as $e ) {
		if ( $e[0] <= $range[0] && $range[1] <= $e[1] ) {
			return true;
		}
	}
	return false;
}

/** @return string[]|false CIDR strings (IPv4 only — this file has never carried IPv6), or false on fetch failure */
function thessley_cnu_fetch( $url, $format ) {
	$response = wp_remote_get( $url, array( 'timeout' => 20, 'user-agent' => 'thessley-security-hardening-crawler-nets-updater/1.0' ) );
	if ( is_wp_error( $response ) || 200 !== wp_remote_retrieve_response_code( $response ) ) {
		return false;
	}
	$body = wp_remote_retrieve_body( $response );

	switch ( $format ) {
		case 'json_prefixes':
			return thessley_cnu_parse_json_prefixes( $body );
		case 'plain_cidr_list':
			return thessley_cnu_parse_plain_cidr_list( $body );
		default:
			return false;
	}
}

/** Google/Bing/DuckDuckGo/OpenAI all publish this same {"prefixes":[{"ipv4Prefix":"..."}]} shape. */
function thessley_cnu_parse_json_prefixes( $body ) {
	$data = json_decode( $body, true );
	if ( empty( $data['prefixes'] ) || ! is_array( $data['prefixes'] ) ) {
		return false;
	}

	$out = array();
	foreach ( $data['prefixes'] as $entry ) {
		if ( ! empty( $entry['ipv4Prefix'] ) ) {
			$out[] = $entry['ipv4Prefix'];
		}
	}
	return $out;
}

/** Cloudflare's ips-v4 endpoint: bare CIDR, one per line, no wrapper. */
function thessley_cnu_parse_plain_cidr_list( $body ) {
	$out = array();
	foreach ( preg_split( '/\r\n|\r|\n/', $body ) as $line ) {
		$line = trim( $line );
		if ( '' !== $line && false !== strpos( $line, '/' ) ) {
			$out[] = $line;
		}
	}
	return $out ?: false;
}

/**
 * Appends $new_cidrs at the end of the contiguous block that starts at
 * $heading (a "# ..." line already in the file) — i.e. right before the
 * next blank line or the next "# " section header, whichever comes
 * first. If the heading isn't found at all, appends a brand-new section
 * at the end of the file instead, so a source is never silently dropped.
 */
function thessley_cnu_insert_into_section( $content, $heading, $label, array $new_cidrs ) {
	$lines = preg_split( '/\r\n|\r|\n/', $content );
	// The original file ends with a single trailing newline, which
	// preg_split turns into a trailing "" element — drop it so
	// implode(...) . "\n" below reproduces exactly that, not a doubled
	// blank line at EOF.
	if ( '' === end( $lines ) ) {
		array_pop( $lines );
	}

	$start = null;
	foreach ( $lines as $i => $line ) {
		if ( trim( $line ) === trim( $heading ) ) {
			$start = $i;
			break;
		}
	}

	$date       = current_time( 'Y-m-d' );
	$new_block  = array( "# {$label} — auto-added by crawler-nets-updater {$date}" );
	foreach ( $new_cidrs as $cidr ) {
		$new_block[] = $cidr;
	}

	if ( null === $start ) {
		// Heading not found (shouldn't normally happen) — append a whole
		// new section at the end rather than lose the data.
		$lines[] = '';
		$lines[] = $heading;
		$lines   = array_merge( $lines, $new_block );
		return implode( "\n", $lines ) . "\n";
	}

	// Every section in this file is blank-line-terminated — including
	// ones with dated sub-comments interspersed among their CIDR lines
	// (e.g. "# Googlebot 192.178.x.x ranges (verified ...)"), which are
	// never themselves followed by a blank line until the section
	// actually ends. So the first blank line after the heading is always
	// the real end of this section, full stop.
	$end = count( $lines );
	for ( $i = $start + 1; $i < count( $lines ); $i++ ) {
		if ( '' === trim( $lines[ $i ] ) ) {
			$end = $i;
			break;
		}
	}

	array_splice( $lines, $end, 0, $new_block );
	return implode( "\n", $lines ) . "\n";
}

function thessley_cnu_log( $message ) {
	error_log( '[crawler-nets-updater] ' . $message );
}
