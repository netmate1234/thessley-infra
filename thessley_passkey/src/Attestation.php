<?php

namespace Drupal\thessley_passkey;

/**
 * Verifies the Android Keystore hardware attestation chain an enrolling
 * device submits. Against Google's own published data — the root public
 * key and the ASN.1 field layout below are taken directly from Google's
 * official google/android-key-attestation library
 * (src/main/java/com/google/android/attestation/Constants.java),
 * fetched at the time this was written — not reconstructed from memory.
 *
 * LOG-ONLY, matching how every other new check in this plugin has
 * shipped (Query Guard, Geo Blocker, etc. all launched log-only before
 * enforcing) — attestation parsing is genuinely finicky (OEM-specific
 * chain quirks are a known real-world source of false negatives in every
 * attestation verifier, including Google's own), and this has had no
 * real-device testing. A silently-broken hard gate that rejects every
 * real enrollment would be strictly worse than not having this at all.
 * Promote rest_enroll_respond() to actually reject on failure only after
 * confirming this passes cleanly against real hardware.
 */
class Attestation {

	const KEY_DESCRIPTION_OID = '1.3.6.1.4.1.11129.2.1.17';

	// From Constants.java: index of each field inside the KeyDescription
	// top-level ASN.1 SEQUENCE.
	const IDX_SECURITY_LEVEL = 1;
	const IDX_CHALLENGE      = 4;

	const SECURITY_LEVEL_SOFTWARE = 0;
	const SECURITY_LEVEL_TEE      = 1;
	const SECURITY_LEVEL_STRONGBOX = 2;

	// Google's attestation root public key (SubjectPublicKeyInfo, DER,
	// base64) — verifying a certificate's signature against this proves
	// that certificate was actually signed by Google's private key,
	// regardless of what the certificate itself claims to contain.
	const GOOGLE_ROOT_PUBLIC_KEY_B64 = 'MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAr7bHgiuxpwHsK7Qui8xU' .
		'FmOr75gvMsd/dTEDDJdSSxtf6An7xyqpRR90PL2abxM1dEqlXnf2tqw1Ne4Xwl5j' .
		'lRfdnJLmN0pTy/4lj4/7tv0Sk3iiKkypnEUtR6WfMgH0QZfKHM1+di+y9TFRtv6y' .
		'//0rb+T+W8a9nsNL/ggjnar86461qO0rOs2cXjp3kOG1FEJ5MVmFmBGtnrKpa73X' .
		'pXyTqRxB/M0n1n/W9nGqC4FSYa04T6N5RIZGBN2z2MT5IKGbFlbC8UrW0DxW7AYI' .
		'mQQcHtGl/m00QLVWutHQoVJYnFPlXTcHYvASLu+RhhsbDmxMgJJ0mcDpvsC4PjvB' .
		'+TxywElgS70vE0XmLD+OJtvsBslHZvPBKCOdT0MS+tgSOIfga+z1Z1g7+DVagf7q' .
		'uvmag8jfPioyKvxnK/EgsTUVi2ghzq8wm27ud/mIM7AY2qEORR8Go3TVB4HzWQgp' .
		'Zrt3i5MIlCaY504LzSRiigHCzAPlHws+W0rB5N+er5/2pJKnfBSDiCiFAVtCLOZ7' .
		'gLiMm0jhO2B6tUXHI/+MRPjy02i59lINMRRev56GKtcd9qO/0kUJWdZTdA2XoS82' .
		'ixPvZtXQpUpuL12ab+9EaDK8Z4RHJYYfCT3Q5vNAXaiWQ+8PTWm2QgBR/bkwSWc+' .
		'NpUFgNPN9PvQi8WEg5UmAGMCAwEAAQ==';

	/**
	 * @param string[] $der_certs_b64 Base64 DER certificates, leaf-first.
	 * @param string   $expected_challenge Raw bytes the attestation challenge must match (this plugin uses the enroll request's own nonce, UTF-8 bytes).
	 * @param string   $registered_public_key_b64 Base64 DER SubjectPublicKeyInfo of the key actually stored as this credential's public key (same format/value Crypto::verify() takes) — pass '' to skip this check.
	 * @return array{ok:bool, reason?:string, security_level?:int, security_level_name?:string, chain_length?:int}
	 */
	public static function verify( array $der_certs_b64, $expected_challenge, $registered_public_key_b64 = '' ) {
		if ( empty( $der_certs_b64 ) ) {
			return array( 'ok' => false, 'reason' => 'no_chain' );
		}

		$pems = array();
		foreach ( $der_certs_b64 as $b64 ) {
			$der = base64_decode( $b64, true );
			if ( false === $der ) {
				return array( 'ok' => false, 'reason' => 'bad_base64' );
			}
			$pems[] = self::der_to_pem_cert( $der );
		}

		// Chain linkage: each certificate must be signed by the next
		// one's public key, ending in a root whose signature verifies
		// against Google's known key — not just "is self-signed", which
		// would trivially accept any certificate signed by anything.
		$count = count( $pems );
		for ( $i = 0; $i < $count - 1; $i++ ) {
			$issuer_pubkey = openssl_pkey_get_public( $pems[ $i + 1 ] );
			if ( ! $issuer_pubkey ) {
				return array( 'ok' => false, 'reason' => 'bad_issuer_cert_at_' . $i );
			}
			if ( 1 !== openssl_x509_verify( $pems[ $i ], $issuer_pubkey ) ) {
				return array( 'ok' => false, 'reason' => 'chain_broken_at_' . $i );
			}
		}

		$google_root = openssl_pkey_get_public( self::der_to_pem_key( base64_decode( self::GOOGLE_ROOT_PUBLIC_KEY_B64 ) ) );
		if ( 1 !== openssl_x509_verify( $pems[ $count - 1 ], $google_root ) ) {
			return array( 'ok' => false, 'reason' => 'root_not_google' );
		}

		// Leaf certificate carries the actual attestation data.
		$leaf = openssl_x509_parse( $pems[0], true );
		if ( ! $leaf || empty( $leaf['extensions'][ self::KEY_DESCRIPTION_OID ] ) ) {
			return array( 'ok' => false, 'reason' => 'no_attestation_extension' );
		}

		$fields = self::parse_key_description( $leaf['extensions'][ self::KEY_DESCRIPTION_OID ] );
		if ( null === $fields ) {
			return array( 'ok' => false, 'reason' => 'attestation_parse_failed' );
		}

		if ( ! hash_equals( (string) $expected_challenge, (string) $fields['challenge'] ) ) {
			return array( 'ok' => false, 'reason' => 'challenge_mismatch' );
		}

		// Without this, a valid attestation chain for *any* key (e.g. a
		// disposable one generated purely to produce a passing chain)
		// could be submitted alongside a completely unrelated key as
		// the credential's actual registered public key — fully
		// defeating hardware-attestation enforcement the moment this
		// stops being log-only and starts being an enforced gate. The
		// attestation extension proves things about *the leaf
		// certificate's own key*, not about whatever key_param the rest
		// of the enroll request separately claims is the credential.
		if ( '' !== $registered_public_key_b64 ) {
			$leaf_pubkey = openssl_pkey_get_public( $pems[0] );
			$details     = $leaf_pubkey ? openssl_pkey_get_details( $leaf_pubkey ) : false;
			if ( ! $details || empty( $details['key'] ) ) {
				return array( 'ok' => false, 'reason' => 'leaf_pubkey_unreadable' );
			}

			$leaf_der       = self::pem_to_der( $details['key'] );
			$registered_der = base64_decode( $registered_public_key_b64, true );
			if ( false === $registered_der || ! hash_equals( (string) $registered_der, (string) $leaf_der ) ) {
				return array( 'ok' => false, 'reason' => 'key_mismatch' );
			}
		}

		$level_names = array(
			self::SECURITY_LEVEL_SOFTWARE  => 'software',
			self::SECURITY_LEVEL_TEE       => 'tee',
			self::SECURITY_LEVEL_STRONGBOX => 'strongbox',
		);

		return array(
			'ok'                  => true,
			'security_level'      => $fields['security_level'],
			'security_level_name' => $level_names[ $fields['security_level'] ] ?? 'unknown',
			'chain_length'        => $count,
		);
	}

	/**
	 * Reads the top-level elements of the KeyDescription SEQUENCE just
	 * far enough to pull out attestationSecurityLevel and
	 * attestationChallenge (indices 1 and 4) — the nested softwareEnforced/
	 * teeEnforced SEQUENCEs (indices 6, 7) are read as opaque blobs and
	 * never descended into, since nothing here needs their contents.
	 */
	private static function parse_key_description( $der ) {
		// openssl_x509_parse() may hand back either the extnValue's inner
		// content directly (a SEQUENCE, tag 0x30) or the whole OCTET
		// STRING wrapper (tag 0x04) depending on PHP/OpenSSL version —
		// unwrap one layer if what we got isn't already a SEQUENCE.
		if ( isset( $der[0] ) && "\x04" === $der[0] ) {
			$outer = self::read_tlv( $der, 0 );
			if ( null === $outer ) {
				return null;
			}
			$der = $outer['value'];
		}

		if ( ! isset( $der[0] ) || "\x30" !== $der[0] ) {
			return null;
		}

		$seq = self::read_tlv( $der, 0 );
		if ( null === $seq ) {
			return null;
		}

		$elements = array();
		$offset   = 0;
		$content  = $seq['value'];
		$len      = strlen( $content );
		while ( $offset < $len ) {
			$tlv = self::read_tlv( $content, $offset );
			if ( null === $tlv ) {
				break;
			}
			$elements[] = $tlv;
			$offset     = $tlv['next_offset'];
		}

		if ( count( $elements ) <= max( self::IDX_SECURITY_LEVEL, self::IDX_CHALLENGE ) ) {
			return null;
		}

		return array(
			'security_level' => self::der_integer_to_int( $elements[ self::IDX_SECURITY_LEVEL ]['value'] ),
			'challenge'       => $elements[ self::IDX_CHALLENGE ]['value'],
		);
	}

	/** Minimal DER TLV reader: tag (1 byte) + length (short or long form) + value. Not a general ASN.1 parser — only handles what a top-level SEQUENCE's immediate children need. */
	private static function read_tlv( $bytes, $offset ) {
		$len_total = strlen( $bytes );
		if ( $offset >= $len_total ) {
			return null;
		}

		$tag = $bytes[ $offset ];
		$pos = $offset + 1;
		if ( $pos >= $len_total ) {
			return null;
		}

		$first_len_byte = ord( $bytes[ $pos ] );
		$pos++;

		if ( $first_len_byte < 0x80 ) {
			$length = $first_len_byte;
		} else {
			$num_bytes = $first_len_byte & 0x7F;
			if ( 0 === $num_bytes || $pos + $num_bytes > $len_total ) {
				return null;
			}
			$length = 0;
			for ( $i = 0; $i < $num_bytes; $i++ ) {
				$length = ( $length << 8 ) | ord( $bytes[ $pos + $i ] );
			}
			$pos += $num_bytes;
		}

		if ( $pos + $length > $len_total ) {
			return null;
		}

		return array(
			'tag'         => $tag,
			'value'       => substr( $bytes, $pos, $length ),
			'next_offset' => $pos + $length,
		);
	}

	private static function der_integer_to_int( $bytes ) {
		$value = 0;
		for ( $i = 0, $len = strlen( $bytes ); $i < $len; $i++ ) {
			$value = ( $value << 8 ) | ord( $bytes[ $i ] );
		}
		return $value;
	}

	private static function der_to_pem_cert( $der ) {
		return "-----BEGIN CERTIFICATE-----\n" . chunk_split( base64_encode( $der ), 64, "\n" ) . "-----END CERTIFICATE-----\n";
	}

	private static function der_to_pem_key( $der ) {
		return "-----BEGIN PUBLIC KEY-----\n" . chunk_split( base64_encode( $der ), 64, "\n" ) . "-----END PUBLIC KEY-----\n";
	}

	/** Inverse of der_to_pem_key() — strips the PEM header/footer/line-wrapping openssl_pkey_get_details() returns and decodes back to raw DER. */
	private static function pem_to_der( $pem ) {
		$body = preg_replace( '/-----(BEGIN|END) PUBLIC KEY-----|\s+/', '', $pem );
		return (string) base64_decode( $body, true );
	}
}
