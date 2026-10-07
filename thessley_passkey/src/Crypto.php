<?php

namespace Drupal\thessley_passkey;

/**
 * Signature verification for the Android app's responses.
 *
 * The app signs a short, explicit, pipe-joined string (not raw JSON —
 * deterministic byte-for-byte on both sides, no canonicalization
 * ambiguity) that always starts with a fixed version+type prefix, so a
 * signature produced for one request type/version can never verify
 * against a different one. This is the same "domain separation" idea
 * behind WebAuthn's clientDataJSON.type.
 */
class Crypto {

	const SIG_VERSION     = 'thessley_passkey_v1';
	const TIMESTAMP_SKEW  = 60; // seconds, both directions

	/**
	 * @param string $type    'login' or 'enroll'.
	 * @param string $request_id
	 * @param string $origin  Always this site's own home_url() — never
	 *                        taken from the client, so the app and server
	 *                        only ever agree when the request was actually
	 *                        issued for this site (closes the QR-relay
	 *                        phishing gap: a relayed QR carries a
	 *                        request_id/nonce minted by the *attacker's*
	 *                        site, so the app would show the attacker's
	 *                        domain, not this one).
	 * @param string $nonce
	 * @param int    $timestamp
	 * @param string $action  'approve' | 'deny' | 'register'.
	 */
	public static function canonical_string( $type, $request_id, $origin, $nonce, $timestamp, $action ) {
		return implode(
			'|',
			array( self::SIG_VERSION, $type, $request_id, $origin, $nonce, (string) $timestamp, $action )
		);
	}

	public static function timestamp_fresh( $timestamp ) {
		return abs( time() - (int) $timestamp ) <= self::TIMESTAMP_SKEW;
	}

	/**
	 * @param string $public_key_b64 base64 (not base64url) DER SubjectPublicKeyInfo, EC P-256.
	 * @param string $signature_b64  base64 ECDSA signature (DER-encoded r,s — PHP openssl's native format).
	 */
	public static function verify( $public_key_b64, $message, $signature_b64 ) {
		$der = base64_decode( $public_key_b64, true );
		if ( false === $der ) {
			return false;
		}

		$pem = self::der_to_pem( $der );
		$pub = openssl_pkey_get_public( $pem );
		if ( false === $pub ) {
			return false;
		}

		$signature = base64_decode( $signature_b64, true );
		if ( false === $signature ) {
			return false;
		}

		$result = openssl_verify( $message, $signature, $pub, OPENSSL_ALGO_SHA256 );

		return 1 === $result;
	}

	private static function der_to_pem( $der ) {
		return "-----BEGIN PUBLIC KEY-----\n"
			. chunk_split( base64_encode( $der ), 64, "\n" )
			. "-----END PUBLIC KEY-----\n";
	}
}
