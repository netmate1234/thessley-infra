"""Strict validation helpers for the disabled AD certificate-sign-in pilot."""

from __future__ import annotations

import hashlib
import hmac
import re

from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

_SHA256 = re.compile(r"^[a-f0-9]{64}$")
_PILOT_SUBJECT = re.compile(r"^Thessley temporary sign-in [a-f0-9]{32}$")
_RSA_SHA256_SIGNATURE_OID = "1.2.840.113549.1.1.11"
_ECDSA_SHA256_SIGNATURE_OID = "1.2.840.10045.4.3.2"


class CertificateRequestError(ValueError):
    """A CSR is malformed or does not match the approved pilot profile."""


def validate_approved_csr(der: bytes, expected_sha256: str) -> dict[str, str | int]:
    """Validate an exact DER PKCS#10 request before a future CA broker uses it.

    This function does not authorize the principal, consume phone approval,
    contact a CA, or issue a certificate. Its constraints match the isolated
    Windows machine-key generator and a possible Android Keystore key: one
    random CN, no requested extensions, and either RSA-3072/SHA-256 or
    ECDSA P-256/SHA-256. This validates syntax and proof of possession; it
    does not establish which device owns the private key.
    """
    if not isinstance(der, bytes) or not 256 <= len(der) <= 64 * 1024:
        raise CertificateRequestError("The DER certificate request has an invalid size.")
    if not isinstance(expected_sha256, str) or not _SHA256.fullmatch(expected_sha256):
        raise CertificateRequestError("The approved CSR digest is malformed.")
    digest = hashlib.sha256(der).hexdigest()
    if not hmac.compare_digest(digest, expected_sha256):
        raise CertificateRequestError("The certificate request does not match the approved digest.")
    try:
        request = x509.load_der_x509_csr(der)
        public_key = request.public_key()
        common_names = request.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        subject_attributes = [attribute for rdn in request.subject.rdns for attribute in rdn]
        rsa_profile = (isinstance(public_key, rsa.RSAPublicKey)
                       and public_key.key_size == 3072
                       and request.signature_algorithm_oid.dotted_string == _RSA_SHA256_SIGNATURE_OID)
        ec_profile = (isinstance(public_key, ec.EllipticCurvePublicKey)
                      and isinstance(public_key.curve, ec.SECP256R1)
                      and request.signature_algorithm_oid.dotted_string == _ECDSA_SHA256_SIGNATURE_OID)
        if (not request.is_signature_valid
                or not (rsa_profile or ec_profile)
                or len(subject_attributes) != 1 or len(common_names) != 1
                or not _PILOT_SUBJECT.fullmatch(common_names[0].value)
                or len(request.extensions) != 0):
            raise CertificateRequestError("The CSR does not match the approved RSA-3072 or EC P-256 profile.")
    except CertificateRequestError:
        raise
    except (ValueError, TypeError, UnsupportedAlgorithm) as exc:
        raise CertificateRequestError("The certificate request is not valid DER PKCS#10.") from exc
    spki = public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return {
        "sha256": digest,
        "subject": request.subject.rfc4514_string(),
        "public_key_spki_sha256": hashlib.sha256(spki).hexdigest(),
        "public_key_bits": public_key.key_size,
        "public_key_algorithm": "rsa" if isinstance(public_key, rsa.RSAPublicKey) else "ec-p256",
    }
