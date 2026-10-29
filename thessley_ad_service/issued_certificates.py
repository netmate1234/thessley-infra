"""Strict validation for certificates returned by a future AD CS broker."""

from __future__ import annotations

import hashlib
import hmac
import re
from datetime import datetime, timezone

from cryptography import x509
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import ExtensionOID, ObjectIdentifier

from .certificate_requests import validate_approved_csr

_SHA256 = re.compile(r"^[a-f0-9]{64}$")
_SID = re.compile(r"^S-1-(?:[0-9]+-)+[0-9]+$")
_RSA_SHA256_SIGNATURE_OID = "1.2.840.113549.1.1.11"
_TEMPLATE_EXTENSION_OID = ObjectIdentifier("1.3.6.1.4.1.311.21.7")
_SID_EXTENSION_OID = ObjectIdentifier("1.3.6.1.4.1.311.25.2")
_SID_OTHER_NAME_OID = "1.3.6.1.4.1.311.25.2.1"
_SMART_CARD_LOGON_OID = ObjectIdentifier("1.3.6.1.4.1.311.20.2.2")


class IssuedCertificateError(ValueError):
    """An issued certificate does not satisfy the pilot's pinned profile."""


def _read_tlv(data: bytes, offset: int) -> tuple[int, bytes, int]:
    if offset < 0 or offset + 2 > len(data):
        raise ValueError("truncated DER value")
    tag = data[offset]
    first_length = data[offset + 1]
    cursor = offset + 2
    if first_length & 0x80:
        count = first_length & 0x7F
        if count == 0 or count > 4 or cursor + count > len(data) or data[cursor] == 0:
            raise ValueError("invalid DER length")
        length = int.from_bytes(data[cursor:cursor + count], "big")
        if length < 128:
            raise ValueError("noncanonical DER length")
        cursor += count
    else:
        length = first_length
    end = cursor + length
    if end > len(data):
        raise ValueError("truncated DER contents")
    return tag, data[cursor:end], end


def _decode_oid(contents: bytes) -> str:
    if not contents:
        raise ValueError("empty DER object identifier")
    values: list[int] = []
    value = 0
    in_value = False
    for octet in contents:
        if not in_value and octet == 0x80:
            raise ValueError("noncanonical DER object identifier")
        value = (value << 7) | (octet & 0x7F)
        in_value = bool(octet & 0x80)
        if not in_value:
            values.append(value)
            value = 0
    if in_value or not values:
        raise ValueError("truncated DER object identifier")
    first = values.pop(0)
    if first < 40:
        arcs = [0, first]
    elif first < 80:
        arcs = [1, first - 40]
    else:
        arcs = [2, first - 80]
    arcs.extend(values)
    return ".".join(str(arc) for arc in arcs)


def _sequence_values(data: bytes) -> list[tuple[int, bytes]]:
    tag, contents, end = _read_tlv(data, 0)
    if tag != 0x30 or end != len(data):
        raise ValueError("expected one DER sequence")
    result = []
    cursor = 0
    while cursor < len(contents):
        child_tag, child_contents, cursor = _read_tlv(contents, cursor)
        result.append((child_tag, child_contents))
    return result


def _template_oid(extension: x509.Extension) -> str:
    values = _sequence_values(extension.value.value)
    if not 1 <= len(values) <= 3 or values[0][0] != 0x06:
        raise ValueError("invalid certificate template extension")
    for tag, integer in values[1:]:
        if (tag != 0x02 or not integer or integer[0] & 0x80
                or len(integer) > 5 or int.from_bytes(integer, "big") > 0xFFFFFFFF):
            raise ValueError("invalid certificate template version")
    return _decode_oid(values[0][1])


def _sid_from_extension(extension: x509.Extension) -> str:
    values = _sequence_values(extension.value.value)
    if (len(values) != 2 or values[0][0] != 0x06 or values[1][0] != 0x04
            or _decode_oid(values[0][1]) != _SID_OTHER_NAME_OID):
        raise ValueError("invalid AD SID extension")
    raw = values[1][1]
    if len(raw) < 12 or raw[0] != 1 or not 1 <= raw[1] <= 15 or len(raw) != 8 + 4 * raw[1]:
        raise ValueError("invalid binary AD SID")
    authority = int.from_bytes(raw[2:8], "big")
    subauthorities = [
        str(int.from_bytes(raw[8 + index * 4:12 + index * 4], "little"))
        for index in range(raw[1])
    ]
    return "S-" + "-".join([str(raw[0]), str(authority), *subauthorities])


def validate_issued_certificate(
    *,
    certificate_der: bytes,
    csr_der: bytes,
    approved_csr_sha256: str,
    expected_sid: str,
    expected_template_oid: str,
    issuer_certificate_der: bytes,
    expected_issuer_sha256: str,
    now: datetime | None = None,
) -> dict[str, str | int]:
    """Check an issued leaf against the approved CSR, SID, template, and CA pin.

    Supports direct issuance by a configured RSA/SHA-256 CA certificate. This
    function does not retrieve the certificate, alter AD, install a key, or
    perform a Windows logon.
    """
    if (not isinstance(certificate_der, bytes) or not 256 <= len(certificate_der) <= 64 * 1024
            or not isinstance(issuer_certificate_der, bytes) or not 256 <= len(issuer_certificate_der) <= 64 * 1024
            or not isinstance(expected_sid, str) or not _SID.fullmatch(expected_sid)
            or not isinstance(expected_template_oid, str)
            or not re.fullmatch(r"[0-2](?:\.[0-9]+)+", expected_template_oid)
            or not isinstance(expected_issuer_sha256, str) or not _SHA256.fullmatch(expected_issuer_sha256)):
        raise IssuedCertificateError("The certificate validation policy is malformed.")
    try:
        csr_metadata = validate_approved_csr(csr_der, approved_csr_sha256)
        certificate = x509.load_der_x509_certificate(certificate_der)
        issuer = x509.load_der_x509_certificate(issuer_certificate_der)
        if certificate.public_bytes(serialization.Encoding.DER) != certificate_der:
            raise IssuedCertificateError("The issued certificate is not canonical DER.")
        issuer_digest = hashlib.sha256(issuer.public_bytes(serialization.Encoding.DER)).hexdigest()
        if not hmac.compare_digest(issuer_digest, expected_issuer_sha256):
            raise IssuedCertificateError("The certificate issuer does not match the configured CA pin.")
        ca_constraints = issuer.extensions.get_extension_for_class(x509.BasicConstraints).value
        ca_usage = issuer.extensions.get_extension_for_class(x509.KeyUsage).value
        if not ca_constraints.ca or not ca_usage.key_cert_sign:
            raise IssuedCertificateError("The configured issuer certificate is not authorized to sign certificates.")
        issuer_key = issuer.public_key()
        if (not isinstance(issuer_key, rsa.RSAPublicKey) or issuer_key.key_size < 2048
                or certificate.signature_algorithm_oid.dotted_string != _RSA_SHA256_SIGNATURE_OID
                or certificate.signature_hash_algorithm.name.lower() != "sha256"
                or certificate.issuer != issuer.subject):
            raise IssuedCertificateError("The issued certificate does not use the configured direct RSA/SHA-256 issuer.")
        issuer_key.verify(
            certificate.signature, certificate.tbs_certificate_bytes,
            padding.PKCS1v15(), hashes.SHA256(),
        )

        current = now or datetime.now(timezone.utc)
        if current.tzinfo is None or current.utcoffset() is None:
            raise IssuedCertificateError("Certificate validation time must include a timezone.")
        if not issuer.not_valid_before_utc <= current <= issuer.not_valid_after_utc:
            raise IssuedCertificateError("The configured CA certificate is not currently valid.")
        if not certificate.not_valid_before_utc <= current <= certificate.not_valid_after_utc:
            raise IssuedCertificateError("The issued certificate is not currently valid.")
        if certificate.subject != x509.load_der_x509_csr(csr_der).subject:
            raise IssuedCertificateError("The issued certificate subject differs from the approved CSR.")
        public_key = certificate.public_key()
        cert_spki = public_key.public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        csr = x509.load_der_x509_csr(csr_der)
        csr_spki = csr.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        if not hmac.compare_digest(cert_spki, csr_spki):
            raise IssuedCertificateError("The issued certificate public key differs from the approved CSR.")

        extensions = certificate.extensions
        template_extension = extensions.get_extension_for_oid(_TEMPLATE_EXTENSION_OID)
        sid_extension = extensions.get_extension_for_oid(_SID_EXTENSION_OID)
        if _template_oid(template_extension) != expected_template_oid:
            raise IssuedCertificateError("The issued certificate uses an unexpected template.")
        if _sid_from_extension(sid_extension) != expected_sid:
            raise IssuedCertificateError("The issued certificate SID does not match the approved AD account.")
        eku = extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        if _SMART_CARD_LOGON_OID not in eku:
            raise IssuedCertificateError("The issued certificate lacks the Smart Card Logon EKU.")
        key_usage = extensions.get_extension_for_class(x509.KeyUsage).value
        if not key_usage.digital_signature:
            raise IssuedCertificateError("The issued certificate cannot sign a smart-card logon.")
        try:
            if extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
                raise IssuedCertificateError("The issued certificate is a CA certificate.")
        except x509.ExtensionNotFound:
            pass
        allowed_critical = {
            ExtensionOID.BASIC_CONSTRAINTS,
            ExtensionOID.KEY_USAGE,
            ExtensionOID.EXTENDED_KEY_USAGE,
        }
        if any(extension.critical and extension.oid not in allowed_critical for extension in extensions):
            raise IssuedCertificateError("The issued certificate contains an unexpected critical extension.")
    except IssuedCertificateError:
        raise
    except (ValueError, TypeError, InvalidSignature, UnsupportedAlgorithm, x509.ExtensionNotFound) as exc:
        raise IssuedCertificateError("The issued certificate failed profile validation.") from exc
    return {
        "certificate_sha256": hashlib.sha256(certificate_der).hexdigest(),
        "issuer_sha256": issuer_digest,
        "csr_sha256": csr_metadata["sha256"],
        "public_key_spki_sha256": csr_metadata["public_key_spki_sha256"],
        "sid": expected_sid,
        "template_oid": expected_template_oid,
        "serial_number": certificate.serial_number,
    }
