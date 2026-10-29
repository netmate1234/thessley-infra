"""Strict verifier for the Android app's SID-bound Windows PAM v2 signatures.

This module is deliberately transport- and storage-free. It is the shared
cryptographic boundary for the standalone AD service; it must not depend on
Drupal or the generic per-user PAM store.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import re
import time

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

PHONE_SIGNATURE_DOMAIN = "thessley_win_pam_v2"
PHONE_CERTIFICATE_SIGNATURE_DOMAIN = "thessley_win_cert_request_v1"
CLOCK_SKEW_SECONDS = 60

_TOKEN = re.compile(r"^[A-Za-z0-9_-]{8,128}$")
_MACHINE_ID = re.compile(r"^[a-f0-9]{32}$")
_SID_HASH = re.compile(r"^[a-f0-9]{64}$")
_CERTIFICATE_SHA256 = re.compile(r"^[a-f0-9]{64}$")
_CERTIFICATE_TEMPLATE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
_SID = re.compile(r"^S-1-(?:[0-9]+-)+[0-9]+$")
_USERNAME = re.compile(r"^[a-z_][a-z0-9_.-]{0,31}$", re.IGNORECASE)
_AUTHORITY = re.compile(r"^[A-Za-z0-9_.@-]{1,128}$")
_FIELD_CONTROL = re.compile(r"[|\s\x00-\x1f\x7f]")

_ACTIONS = {"register", "approve", "deny"}
_CONTEXTS = {"enrollment", "interactive", "unlock", "ssh", "admin-web"}


def validate_certificate_template(value: str | None) -> str | None:
    """Validate an optional AD CS template short name from protected service config."""
    if value is None:
        return None
    if not isinstance(value, str) or not _CERTIFICATE_TEMPLATE.fullmatch(value):
        raise ValueError("invalid certificate template")
    return value


def principal_id_from_sid(sid: str) -> str:
    """Return the stable SID digest used by the Android Windows-v2 protocol."""
    if not isinstance(sid, str) or not _SID.fullmatch(sid):
        raise ValueError("invalid Windows SID")
    return hashlib.sha256(sid.encode("ascii")).hexdigest()


def canonical_phone_message(
    *,
    type_: str,
    request_id: str,
    machine_id: str,
    principal_id: str,
    principal_type: str,
    authority: str,
    username: str,
    context: str,
    nonce: str,
    timestamp: int,
    action: str,
) -> bytes:
    """Build bytes exactly matching Android PamCanonicalString.buildWindowsV2."""
    string_fields = (
        type_, request_id, machine_id, principal_id, principal_type, authority,
        username, context, nonce, action,
    )
    if not all(isinstance(value, str) for value in string_fields):
        raise ValueError("signed fields must be strings")
    if type_ not in ("enroll", "login"):
        raise ValueError("unsupported request type")
    if action not in _ACTIONS:
        raise ValueError("unsupported action")
    if (type_ == "enroll" and action != "register") or (type_ == "login" and action == "register"):
        raise ValueError("action does not match request type")
    if context not in _CONTEXTS:
        raise ValueError("unsupported Windows context")
    if (type_ == "enroll") != (context == "enrollment"):
        raise ValueError("request type and context do not match")
    if not _TOKEN.fullmatch(request_id) or not _TOKEN.fullmatch(nonce):
        raise ValueError("invalid request token")
    if not _MACHINE_ID.fullmatch(machine_id):
        raise ValueError("invalid machine id")
    if not _SID_HASH.fullmatch(principal_id):
        raise ValueError("invalid principal id")
    if principal_type not in ("local", "domain"):
        raise ValueError("invalid principal type")
    if not _AUTHORITY.fullmatch(authority) or not _USERNAME.fullmatch(username):
        raise ValueError("invalid Windows account")
    if isinstance(timestamp, bool) or not isinstance(timestamp, int):
        raise ValueError("invalid timestamp")
    ts = timestamp

    fields = (
        PHONE_SIGNATURE_DOMAIN,
        type_,
        request_id,
        machine_id,
        principal_id,
        principal_type,
        authority,
        username,
        context,
        nonce,
        str(ts),
        action,
    )
    if any(not value or _FIELD_CONTROL.search(value) for value in fields):
        raise ValueError("invalid signed field")
    return "|".join(fields).encode("utf-8")


def canonical_certificate_approval_message(
    *,
    request_id: str,
    machine_id: str,
    principal_id: str,
    principal_type: str,
    authority: str,
    username: str,
    context: str,
    nonce: str,
    expires_at: int,
    certificate_request_sha256: str,
    certificate_template: str,
    timestamp: int,
    action: str,
) -> bytes:
    """Build the separate v3 proof binding phone approval to one exact DER CSR.

    This is intentionally not a variant of the TPM/password-gating v2 message.
    A certificate approval is only accepted for interactive domain sign-in and
    includes the immutable expiry, CSR digest, and template name.
    """
    fields = (
        PHONE_CERTIFICATE_SIGNATURE_DOMAIN,
        "login",
        request_id,
        machine_id,
        principal_id,
        principal_type,
        authority,
        username,
        context,
        nonce,
        str(expires_at),
        certificate_request_sha256,
        certificate_template,
        str(timestamp),
        action,
    )
    if any(not isinstance(value, str) for value in fields):
        raise ValueError("signed fields must be strings")
    if not _TOKEN.fullmatch(request_id) or not _TOKEN.fullmatch(nonce):
        raise ValueError("invalid request token")
    if not _MACHINE_ID.fullmatch(machine_id) or not _SID_HASH.fullmatch(principal_id):
        raise ValueError("invalid machine or principal id")
    if principal_type != "domain" or context != "interactive":
        raise ValueError("certificate approval is limited to interactive domain sign-in")
    if not _AUTHORITY.fullmatch(authority) or not _USERNAME.fullmatch(username):
        raise ValueError("invalid Windows account")
    if not _CERTIFICATE_SHA256.fullmatch(certificate_request_sha256):
        raise ValueError("invalid certificate request digest")
    if not _CERTIFICATE_TEMPLATE.fullmatch(certificate_template):
        raise ValueError("invalid certificate template")
    if isinstance(expires_at, bool) or not isinstance(expires_at, int) or expires_at <= 0:
        raise ValueError("invalid request expiry")
    if isinstance(timestamp, bool) or not isinstance(timestamp, int):
        raise ValueError("invalid timestamp")
    if action not in ("approve", "deny"):
        raise ValueError("unsupported action")
    if any(not value or _FIELD_CONTROL.search(value) for value in fields):
        raise ValueError("invalid signed field")
    return "|".join(fields).encode("utf-8")


def timestamp_is_fresh(timestamp: int, now: float | None = None) -> bool:
    """Accept only phone approvals within the app's existing one-minute clock window."""
    if isinstance(timestamp, bool):
        return False
    try:
        ts = int(timestamp)
    except (TypeError, ValueError, OverflowError):
        return False
    current = time.time() if now is None else now
    return abs(ts - current) <= CLOCK_SKEW_SECONDS


def verify_phone_signature(public_key_spki_b64: str, signature_b64: str, message: bytes) -> bool:
    """Verify a DER ECDSA/SHA-256 signature from a P-256 Android Keystore key."""
    try:
        public_der = base64.b64decode(public_key_spki_b64, validate=True)
        signature_der = base64.b64decode(signature_b64, validate=True)
        key = serialization.load_der_public_key(public_der)
        if not isinstance(key, ec.EllipticCurvePublicKey) or key.curve.name != "secp256r1":
            return False
        key.verify(signature_der, message, ec.ECDSA(hashes.SHA256()))
        return True
    except (binascii.Error, InvalidSignature, ValueError, TypeError):
        return False
