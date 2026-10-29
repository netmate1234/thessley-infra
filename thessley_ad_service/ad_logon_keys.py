"""Account-bound public keys reserved for the future phone-held AD logon flow.

This registry is deliberately separate from phone approval credentials. It
stores public material only and never treats Android key-attestation evidence
as verified; certificate issuance and Windows sign-in must remain disabled
until a trusted attestation verifier and phone signing bridge exist.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
import secrets
import sqlite3
import time
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from .phone_registry import CENTRAL_AD_MACHINE_ID, _CREDENTIAL_ID, _LABEL
from .protocol import timestamp_is_fresh, verify_phone_signature
from .state_permissions import finish_private_sqlite, prepare_private_sqlite

_PRINCIPAL_ID = re.compile(r"^[a-f0-9]{64}$")
_REQUEST_ID = re.compile(r"^[A-Za-z0-9_-]{16,96}$")
_NONCE = re.compile(r"^[A-Za-z0-9_-]{16,96}$")
_KEY_ID = re.compile(r"^[A-Za-z0-9_-]{32,64}$")
_SHA256 = re.compile(r"^[a-f0-9]{64}$")
_SIGNATURE_DOMAIN = "thessley_ad_logon_key_enroll_v1"


class AdLogonKeyRegistry:
    """Store phone-held AD logon public keys, isolated from approval keys.

    A registration must be signed by an active, centrally enrolled AD phone
    credential and by the new key itself. A short-lived timestamp plus unique
    request ID prevents a captured registration from being replayed. Android
    attestation is retained as evidence but always reported as unverified.
    """

    def __init__(self, path: str | Path):
        self.path = Path(path)
        prepare_private_sqlite(self.path, description="AD logon-key registry")
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=5, isolation_level=None)
        connection.execute("PRAGMA busy_timeout = 5000")
        return connection

    def _initialize(self) -> None:
        connection = self._connect()
        try:
            connection.execute("PRAGMA journal_mode = DELETE")
            connection.execute(
                """CREATE TABLE IF NOT EXISTS ad_logon_keys (
                       key_id TEXT PRIMARY KEY,
                       request_id TEXT NOT NULL UNIQUE,
                       principal_id TEXT NOT NULL,
                       approval_credential_id TEXT NOT NULL,
                       public_key_spki_b64 TEXT NOT NULL,
                       public_key_sha256 TEXT NOT NULL,
                       label TEXT NOT NULL,
                       attestation_chain_json TEXT NOT NULL,
                       attestation_status TEXT NOT NULL DEFAULT 'unverified',
                       created_at REAL NOT NULL,
                       revoked_at REAL,
                       revoked_by TEXT
                   ) WITHOUT ROWID"""
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS ad_logon_keys_principal "
                "ON ad_logon_keys(principal_id, revoked_at, created_at)"
            )
            connection.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS ad_logon_keys_active_spki "
                "ON ad_logon_keys(principal_id, public_key_sha256) WHERE revoked_at IS NULL"
            )
        finally:
            connection.close()
        finish_private_sqlite(self.path)

    @staticmethod
    def _key_der(encoded: str) -> tuple[bytes, str] | None:
        if not isinstance(encoded, str) or len(encoded) > 4096:
            return None
        try:
            der = base64.b64decode(encoded, validate=True)
            if base64.b64encode(der).decode("ascii") != encoded:
                return None
            key = serialization.load_der_public_key(der)
            if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(key.curve, ec.SECP256R1):
                return None
            canonical = key.public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            if canonical != der:
                return None
            return der, hashlib.sha256(der).hexdigest()
        except (binascii.Error, ValueError, TypeError):
            return None

    @staticmethod
    def _attestation_chain(values: object) -> str | None:
        if not isinstance(values, list) or not 1 <= len(values) <= 10:
            return None
        decoded: list[str] = []
        total = 0
        try:
            for value in values:
                if not isinstance(value, str) or not 256 <= len(value) <= 16384:
                    return None
                der = base64.b64decode(value, validate=True)
                if base64.b64encode(der).decode("ascii") != value or not 128 <= len(der) <= 12288:
                    return None
                certificate = x509.load_der_x509_certificate(der)
                if certificate.public_bytes(serialization.Encoding.DER) != der:
                    return None
                total += len(der)
                # Keep base64 JSON comfortably below the shared API's 64 KiB
                # body cap, including signatures and request metadata.
                if total > 30 * 1024:
                    return None
                decoded.append(value)
        except (binascii.Error, ValueError, TypeError):
            return None
        return json.dumps(decoded, separators=(",", ":"))

    @staticmethod
    def enrollment_message(*, request_id: str, principal_id: str, credential_id: str,
                           public_key_sha256: str, nonce: str, timestamp: int, label: str) -> bytes | None:
        if (not isinstance(request_id, str) or not _REQUEST_ID.fullmatch(request_id)
                or not isinstance(principal_id, str) or not _PRINCIPAL_ID.fullmatch(principal_id)
                or not isinstance(credential_id, str) or not _CREDENTIAL_ID.fullmatch(credential_id)
                or not isinstance(public_key_sha256, str) or not _SHA256.fullmatch(public_key_sha256)
                or not isinstance(nonce, str) or not _NONCE.fullmatch(nonce)
                or isinstance(timestamp, bool) or not isinstance(timestamp, int)
                or not isinstance(label, str) or not _LABEL.fullmatch(label)):
            return None
        fields = (_SIGNATURE_DOMAIN, request_id, principal_id, credential_id,
                  public_key_sha256, nonce, str(timestamp), label)
        return "|".join(fields).encode("utf-8")

    def register(self, *, request_id: str, principal_id: str, credential_id: str,
                 approval_public_key_spki_b64: str, public_key_spki_b64: str,
                 label: str, nonce: str, timestamp: int,
                 approval_signature_b64: str, proof_signature_b64: str,
                 attestation_chain: object, now: float | None = None) -> dict | None:
        """Record a new key after two independent signatures verify.

        The caller must obtain ``approval_public_key_spki_b64`` by looking up
        ``credential_id`` for ``CENTRAL_AD_MACHINE_ID`` and this exact
        ``principal_id``. Callers must never accept that key from the request.
        """
        new_key = self._key_der(public_key_spki_b64)
        approval_key = self._key_der(approval_public_key_spki_b64)
        chain_json = self._attestation_chain(attestation_chain)
        current = time.time() if now is None else now
        if (new_key is None or approval_key is None or chain_json is None
                or not timestamp_is_fresh(timestamp, now)
                or not isinstance(label, str) or not _LABEL.fullmatch(label)):
            return None
        _, key_digest = new_key
        message = self.enrollment_message(
            request_id=request_id, principal_id=principal_id, credential_id=credential_id,
            public_key_sha256=key_digest, nonce=nonce, timestamp=timestamp, label=label,
        )
        if message is None:
            return None
        if (not verify_phone_signature(approval_public_key_spki_b64, approval_signature_b64, message)
                or not verify_phone_signature(public_key_spki_b64, proof_signature_b64, message)):
            return None
        key_id = secrets.token_urlsafe(24)
        if not _KEY_ID.fullmatch(key_id):
            return None
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                """INSERT INTO ad_logon_keys
                   (key_id, request_id, principal_id, approval_credential_id,
                    public_key_spki_b64, public_key_sha256, label,
                    attestation_chain_json, attestation_status, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'unverified', ?)""",
                (key_id, request_id, principal_id, credential_id, public_key_spki_b64,
                 key_digest, label, chain_json, current),
            )
            connection.execute("COMMIT")
            return {"key_id": key_id, "public_key_sha256": key_digest,
                    "attestation_status": "unverified", "created_at": current}
        except sqlite3.IntegrityError:
            try:
                connection.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            return None
        except sqlite3.Error:
            try:
                connection.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            return None
        finally:
            connection.close()

    def list_for_principal(self, principal_id: str) -> list[dict]:
        if not isinstance(principal_id, str) or not _PRINCIPAL_ID.fullmatch(principal_id):
            return []
        connection = self._connect()
        try:
            rows = connection.execute(
                """SELECT key_id, public_key_sha256, label, attestation_status,
                          created_at, revoked_at, revoked_by
                   FROM ad_logon_keys WHERE principal_id = ? ORDER BY created_at, key_id""",
                (principal_id,),
            ).fetchall()
            return [dict(key_id=row[0], public_key_sha256=row[1], label=row[2],
                         attestation_status=row[3], created_at=row[4], revoked_at=row[5],
                         revoked_by=row[6]) for row in rows]
        except sqlite3.Error:
            return []
        finally:
            connection.close()

    def revoke(self, *, key_id: str, administrator: str, now: float | None = None) -> bool:
        if (not isinstance(key_id, str) or not _KEY_ID.fullmatch(key_id)
                or not isinstance(administrator, str) or not administrator
                or len(administrator) > 256 or any(ord(char) < 32 for char in administrator)):
            return False
        connection = self._connect()
        try:
            cursor = connection.execute(
                "UPDATE ad_logon_keys SET revoked_at = ?, revoked_by = ? "
                "WHERE key_id = ? AND revoked_at IS NULL",
                (time.time() if now is None else now, administrator, key_id),
            )
            return cursor.rowcount == 1
        except sqlite3.Error:
            return False
        finally:
            connection.close()

    def active_public_key(self, *, principal_id: str, key_id: str) -> str | None:
        if (not isinstance(principal_id, str) or not _PRINCIPAL_ID.fullmatch(principal_id)
                or not isinstance(key_id, str) or not _KEY_ID.fullmatch(key_id)):
            return None
        connection = self._connect()
        try:
            row = connection.execute(
                "SELECT public_key_spki_b64 FROM ad_logon_keys "
                "WHERE key_id = ? AND principal_id = ? AND revoked_at IS NULL "
                "AND attestation_status = 'verified'",
                (key_id, principal_id),
            ).fetchone()
            return row[0] if row else None
        except sqlite3.Error:
            return None
        finally:
            connection.close()
