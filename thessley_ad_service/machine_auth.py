"""Machine request authentication for the standalone Thessley AD service.

This module deliberately does not decide how machine public keys are enrolled
or stored. Callers must load the key only from the dedicated AD-service
registry, never from the request body. Machine requests use a separate signing
domain from Android phone approvals.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import re
import time
from collections.abc import Callable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

MACHINE_SIGNATURE_DOMAIN = "thessley_ad_machine_v1"
CLOCK_SKEW_SECONDS = 60
MAX_BODY_BYTES = 64 * 1024

_MACHINE_ID = re.compile(r"^[a-f0-9]{32}$")
_NONCE = re.compile(r"^[A-Za-z0-9_-]{22,86}$")
_METHOD = re.compile(r"^[A-Z]{3,10}$")
_PATH = re.compile(r"^/thessley-ad/v1/[a-z0-9_/-]{1,160}$")
_SIGNATURE = re.compile(r"^[A-Za-z0-9+/]+={0,2}$")


def canonical_request(
    *, method: str, path: str, machine_id: str, timestamp: int, nonce: str, body: bytes
) -> bytes:
    """Return the exact bytes a Windows agent signs for one API request.

    The body is hashed as transmitted, so JSON whitespace and field ordering
    cannot be normalized differently by the client and server. The HTTP layer
    must pass the original body bytes, not a re-serialized parsed object.
    """
    if not isinstance(method, str) or not _METHOD.fullmatch(method):
        raise ValueError("invalid HTTP method")
    if not isinstance(path, str) or not _PATH.fullmatch(path) or "?" in path or "#" in path:
        raise ValueError("invalid API path")
    if not isinstance(machine_id, str) or not _MACHINE_ID.fullmatch(machine_id):
        raise ValueError("invalid machine id")
    if isinstance(timestamp, bool) or not isinstance(timestamp, int) or timestamp <= 0:
        raise ValueError("invalid timestamp")
    if not isinstance(nonce, str) or not _NONCE.fullmatch(nonce):
        raise ValueError("invalid request nonce")
    if not isinstance(body, bytes) or len(body) > MAX_BODY_BYTES:
        raise ValueError("invalid request body")

    fields = (
        MACHINE_SIGNATURE_DOMAIN,
        method,
        path,
        machine_id,
        str(timestamp),
        nonce,
        hashlib.sha256(body).hexdigest(),
    )
    return "\n".join(fields).encode("ascii")


def verify_machine_signature(public_key_spki_b64: str, signature_b64: str, message: bytes) -> bool:
    """Verify an ECDSA/SHA-256 machine signature using an enrolled P-256 key."""
    try:
        if not isinstance(public_key_spki_b64, str) or not isinstance(signature_b64, str):
            return False
        if len(public_key_spki_b64) > 4096 or len(signature_b64) > 256 or not _SIGNATURE.fullmatch(signature_b64):
            return False
        public_der = base64.b64decode(public_key_spki_b64, validate=True)
        signature_der = base64.b64decode(signature_b64, validate=True)
        key = serialization.load_der_public_key(public_der)
        if not isinstance(key, ec.EllipticCurvePublicKey) or key.curve.name != "secp256r1":
            return False
        key.verify(signature_der, message, ec.ECDSA(hashes.SHA256()))
        return True
    except (binascii.Error, InvalidSignature, ValueError, TypeError):
        return False


def timestamp_is_fresh(timestamp: int, now: float | None = None) -> bool:
    if isinstance(timestamp, bool) or not isinstance(timestamp, int):
        return False
    current = time.time() if now is None else now
    return abs(timestamp - current) <= CLOCK_SKEW_SECONDS


class ReplayGuard:
    """Thread-safe nonce guard for an already authenticated machine request.

    The supplied ``claim`` callback must atomically persist ``(machine_id,
    nonce, expires_at)`` and return false for an existing nonce. A process-local
    fallback is available for isolated development only; production callers
    should provide a transactional, persistent claim function so restarts do
    not reopen the replay window.
    """

    def __init__(self, claim: Callable[[str, str, float], bool]):
        if not callable(claim):
            raise TypeError("a persistent atomic nonce-claim function is required")
        self._claim = claim

    def claim(self, machine_id: str, nonce: str, *, now: float | None = None) -> bool:
        current = time.time() if now is None else now
        expiry = current + CLOCK_SKEW_SECONDS
        return bool(self._claim(machine_id, nonce, expiry))


def verify_request(
    *,
    public_key_spki_b64: str,
    signature_b64: str,
    method: str,
    path: str,
    machine_id: str,
    timestamp: int,
    nonce: str,
    body: bytes,
    replay_guard: ReplayGuard,
    now: float | None = None,
) -> bool:
    """Validate freshness, signature, then atomically claim its nonce.

    Callers must resolve ``public_key_spki_b64`` from the trusted machine
    registry using ``machine_id`` before calling this function. Nonces are
    claimed only after a valid signature, preventing unauthenticated cache
    exhaustion.
    """
    if not timestamp_is_fresh(timestamp, now):
        return False
    try:
        message = canonical_request(
            method=method,
            path=path,
            machine_id=machine_id,
            timestamp=timestamp,
            nonce=nonce,
            body=body,
        )
    except (TypeError, ValueError):
        return False
    if not verify_machine_signature(public_key_spki_b64, signature_b64, message):
        return False
    return replay_guard.claim(machine_id, nonce, now=now)

