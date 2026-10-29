"""Account-bound public keys for the phone-held AD logon prototype.

This registry is deliberately separate from phone approval credentials. It
stores public material only and records verified Android key-attestation
levels. Windows sign-in remains a separate provider integration; software or
unverifiable keys remain usable only with the app's explicit warning.
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

from .android_attestation import verify_android_key_attestation
from .phone_registry import CENTRAL_AD_MACHINE_ID
from .protocol import timestamp_is_fresh, verify_phone_signature
from .state_permissions import finish_private_sqlite, prepare_private_sqlite

_PRINCIPAL_ID = re.compile(r"^[a-f0-9]{64}$")
_REQUEST_ID = re.compile(r"^[A-Za-z0-9_-]{16,96}$")
_NONCE = re.compile(r"^[A-Za-z0-9_-]{16,96}$")
_KEY_ID = re.compile(r"^[A-Za-z0-9_-]{32,64}$")
_CREDENTIAL_ID = re.compile(r"^[A-Za-z0-9_-]{32,64}$")
_LABEL = re.compile(r"^[^|\x00-\x1f\x7f]{1,64}$")
_SHA256 = re.compile(r"^[a-f0-9]{64}$")
_SIGNATURE_DOMAIN = "thessley_ad_logon_key_enroll_v2"


class AdLogonKeyRegistry:
    """Store phone-held AD logon public keys, isolated from approval keys.

    A registration must be signed by an active, centrally enrolled AD phone
    credential and by the new key itself. A short-lived timestamp plus unique
    request ID prevents a captured registration from being replayed. The
    attestation status is recorded for transparency; the user's policy allows
    a software-backed key to sign in after an explicit warning in the app.
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
            connection.execute(
                """CREATE TABLE IF NOT EXISTS ad_logon_key_enrollments (
                       request_id TEXT PRIMARY KEY,
                       principal_id TEXT NOT NULL,
                       username TEXT NOT NULL,
                       authority TEXT NOT NULL,
                       nonce TEXT NOT NULL,
                       expires_at REAL NOT NULL,
                       status TEXT NOT NULL,
                       pairing_code TEXT NOT NULL DEFAULT '',
                       credential_id TEXT NOT NULL DEFAULT '',
                       public_key_spki_b64 TEXT NOT NULL DEFAULT '',
                       public_key_sha256 TEXT NOT NULL DEFAULT '',
                       label TEXT NOT NULL DEFAULT '',
                       attestation_chain_json TEXT NOT NULL DEFAULT '[]',
                       attestation_status TEXT NOT NULL DEFAULT 'unverified',
                       key_id TEXT NOT NULL DEFAULT '',
                       created_at REAL NOT NULL
                   ) WITHOUT ROWID"""
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
        if not isinstance(values, list) or len(values) > 10:
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
                           public_key_sha256: str, nonce: str, timestamp: int, label: str,
                           pairing_code: str) -> bytes | None:
        if (not isinstance(request_id, str) or not _REQUEST_ID.fullmatch(request_id)
                or not isinstance(principal_id, str) or not _PRINCIPAL_ID.fullmatch(principal_id)
                or not isinstance(credential_id, str) or not _CREDENTIAL_ID.fullmatch(credential_id)
                or not isinstance(public_key_sha256, str) or not _SHA256.fullmatch(public_key_sha256)
                or not isinstance(nonce, str) or not _NONCE.fullmatch(nonce)
                or isinstance(timestamp, bool) or not isinstance(timestamp, int)
                or not isinstance(label, str) or not _LABEL.fullmatch(label)
                or not isinstance(pairing_code, str) or not re.fullmatch(r"[0-9]{3} [0-9]{3}", pairing_code)):
            return None
        fields = (_SIGNATURE_DOMAIN, request_id, principal_id, credential_id,
                  public_key_sha256, nonce, str(timestamp), label, pairing_code)
        return "|".join(fields).encode("utf-8")

    def register(self, *, request_id: str, principal_id: str, credential_id: str,
                 approval_public_key_spki_b64: str, public_key_spki_b64: str,
                 label: str, nonce: str, timestamp: int,
                 approval_signature_b64: str, proof_signature_b64: str,
                 attestation_chain: object, pairing_code: str = "", now: float | None = None) -> dict | None:
        """Stage a new key after two signatures and attestation verify.

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
                or not isinstance(label, str) or not _LABEL.fullmatch(label)
                or not isinstance(pairing_code, str) or not re.fullmatch(r"[0-9]{3} [0-9]{3}", pairing_code)):
            return None
        _, key_digest = new_key
        message = self.enrollment_message(
            request_id=request_id, principal_id=principal_id, credential_id=credential_id,
            public_key_sha256=key_digest, nonce=nonce, timestamp=timestamp, label=label,
            pairing_code=pairing_code,
        )
        if message is None:
            return None
        if (not verify_phone_signature(approval_public_key_spki_b64, approval_signature_b64, message)
                or not verify_phone_signature(public_key_spki_b64, proof_signature_b64, message)):
            return None
        attestation = verify_android_key_attestation(
            attestation_chain,
            expected_challenge=request_id.encode("ascii"),
            expected_public_key_spki=new_key[0],
        )
        attestation_status = attestation["status"]
        key_id = secrets.token_urlsafe(24)
        if not _KEY_ID.fullmatch(key_id):
            return None
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            request = connection.execute(
                "SELECT principal_id, nonce, expires_at, status FROM ad_logon_key_enrollments WHERE request_id = ?",
                (request_id,),
            ).fetchone()
            if (request is None or request[0] != principal_id or request[1] != nonce
                    or request[2] <= current or request[3] not in ("pending", "ready")):
                connection.execute("ROLLBACK")
                return None
            if request[3] == "ready":
                existing = connection.execute(
                    "SELECT credential_id, public_key_sha256, label, pairing_code, key_id "
                    "FROM ad_logon_key_enrollments WHERE request_id = ?", (request_id,),
                ).fetchone()
                if existing and existing[:3] == (credential_id, key_digest, label):
                    connection.execute("COMMIT")
                    return {"result": "pending_confirmation", "pairing_code": existing[3],
                            "key_id": existing[4], "public_key_sha256": key_digest,
                            "attestation_status": attestation_status, "already_recorded": True}
                connection.execute("ROLLBACK")
                return None
            connection.execute(
                """UPDATE ad_logon_key_enrollments SET status='ready', pairing_code=?, credential_id=?,
                   public_key_spki_b64=?, public_key_sha256=?, label=?, attestation_chain_json=?,
                   attestation_status=?, key_id=? WHERE request_id=? AND status='pending'""",
                (pairing_code, credential_id, public_key_spki_b64, key_digest, label,
                 chain_json, attestation_status, key_id, request_id),
            )
            connection.execute("COMMIT")
            return {"result": "pending_confirmation", "key_id": key_id,
                    "public_key_sha256": key_digest, "attestation_status": attestation_status,
                    "pairing_code": pairing_code, "already_recorded": False}
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

    def create_enrollment(self, *, principal_id: str, username: str, authority: str,
                          now: float | None = None, lifetime_seconds: int = 300) -> dict | None:
        if (not isinstance(principal_id, str) or not _PRINCIPAL_ID.fullmatch(principal_id)
                or not isinstance(username, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,20}", username)
                or not isinstance(authority, str) or not re.fullmatch(r"[A-Za-z0-9_.@-]{1,128}", authority)
                or not isinstance(lifetime_seconds, int) or not 60 <= lifetime_seconds <= 600):
            return None
        current = time.time() if now is None else now
        request_id, nonce = secrets.token_urlsafe(24), secrets.token_urlsafe(24)
        connection = self._connect()
        try:
            connection.execute(
                "DELETE FROM ad_logon_key_enrollments WHERE "
                "(expires_at <= ? AND status IN ('pending','ready')) OR "
                "(created_at < ? AND status IN ('confirmed','cancelled'))",
                (current, current - 86400),
            )
            connection.execute(
                "INSERT INTO ad_logon_key_enrollments(request_id, principal_id, username, authority, nonce, expires_at, status, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, 'pending', ?)",
                (request_id, principal_id, username, authority, nonce, current + lifetime_seconds, current),
            )
            return {"request_id": request_id, "principal_id": principal_id, "username": username,
                    "authority": authority, "nonce": nonce, "expires_at": current + lifetime_seconds}
        except sqlite3.Error:
            return None
        finally:
            connection.close()

    def enrollment_status(self, request_id: str, *, now: float | None = None) -> dict | None:
        if not isinstance(request_id, str) or not _REQUEST_ID.fullmatch(request_id):
            return None
        current = time.time() if now is None else now
        connection = self._connect()
        try:
            row = connection.execute(
                "SELECT principal_id, username, authority, expires_at, status, pairing_code, key_id, public_key_sha256, attestation_status "
                "FROM ad_logon_key_enrollments WHERE request_id=?", (request_id,),
            ).fetchone()
            if not row:
                return None
            status = "expired" if row[3] <= current and row[4] not in ("confirmed", "cancelled") else row[4]
            return {"principal_id": row[0], "username": row[1], "authority": row[2], "expires_at": row[3],
                    "status": status, "pairing_code": row[5], "key_id": row[6],
                    "public_key_sha256": row[7], "attestation_status": row[8]}
        except sqlite3.Error:
            return None
        finally:
            connection.close()

    def phone_status(self, request_id: str, *, now: float | None = None) -> dict | None:
        """Report whether a phone-held key is still active, including revocation."""
        if not isinstance(request_id, str) or not _REQUEST_ID.fullmatch(request_id):
            return None
        current = time.time() if now is None else now
        connection = self._connect()
        try:
            row = connection.execute(
                """SELECT e.expires_at, e.status, e.attestation_status, e.key_id,
                          k.revoked_at, k.key_id
                   FROM ad_logon_key_enrollments AS e
                   LEFT JOIN ad_logon_keys AS k ON k.request_id = e.request_id
                   WHERE e.request_id = ?""",
                (request_id,),
            ).fetchone()
            if not row:
                return None
            status = row[1]
            if row[0] <= current and status not in ("confirmed", "cancelled"):
                status = "expired"
            elif status == "confirmed" and row[5] is not None and row[4] is not None:
                status = "revoked"
            return {
                "status": status,
                "attestation_status": row[2],
                "key_id": row[3] if status == "confirmed" else "",
            }
        except sqlite3.Error:
            return None
        finally:
            connection.close()

    def confirm_enrollment(self, *, request_id: str, pairing_code: str,
                           administrator: str, now: float | None = None) -> bool:
        if (not isinstance(request_id, str) or not _REQUEST_ID.fullmatch(request_id)
                or not isinstance(pairing_code, str) or not re.fullmatch(r"[0-9]{3} [0-9]{3}", pairing_code)
                or not isinstance(administrator, str) or not administrator or len(administrator) > 256):
            return False
        current = time.time() if now is None else now
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT principal_id, credential_id, public_key_spki_b64, public_key_sha256, label, attestation_chain_json, attestation_status, key_id, created_at, expires_at, status, pairing_code "
                "FROM ad_logon_key_enrollments WHERE request_id=?", (request_id,),
            ).fetchone()
            if not row or row[9] <= current or row[10] != "ready" or not secrets.compare_digest(row[11], pairing_code):
                connection.execute("ROLLBACK")
                return False
            connection.execute(
                "INSERT INTO ad_logon_keys(key_id, request_id, principal_id, approval_credential_id, public_key_spki_b64, public_key_sha256, label, attestation_chain_json, attestation_status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (row[7], request_id, row[0], row[1], row[2], row[3], row[4], row[5], row[6], row[8]),
            )
            connection.execute("UPDATE ad_logon_key_enrollments SET status='confirmed', pairing_code='', credential_id='' WHERE request_id=?", (request_id,))
            connection.execute("COMMIT")
            return True
        except sqlite3.Error:
            try: connection.execute("ROLLBACK")
            except sqlite3.Error: pass
            return False
        finally:
            connection.close()

    def cancel_enrollment(self, request_id: str) -> bool:
        if not isinstance(request_id, str) or not _REQUEST_ID.fullmatch(request_id):
            return False
        connection = self._connect()
        try:
            cursor = connection.execute(
                "UPDATE ad_logon_key_enrollments SET status='cancelled', pairing_code='', credential_id='' "
                "WHERE request_id=? AND status IN ('pending','ready')", (request_id,),
            )
            return cursor.rowcount == 1
        except sqlite3.Error:
            return False
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

    def revoke_for_approval_credential(self, credential_id: str, *, administrator: str,
                                       now: float | None = None) -> int | None:
        """Disable every AD logon key authorized through a revoked phone key.

        Keep revoked rows for audit, but make them ineligible immediately.
        """
        if (not isinstance(credential_id, str) or not _CREDENTIAL_ID.fullmatch(credential_id)
                or not isinstance(administrator, str) or not administrator
                or len(administrator) > 256 or any(ord(char) < 32 for char in administrator)):
            return 0
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            cursor = connection.execute(
                "UPDATE ad_logon_keys SET revoked_at = ?, revoked_by = ? "
                "WHERE approval_credential_id = ? AND revoked_at IS NULL",
                (time.time() if now is None else now, administrator, credential_id),
            )
            revoked = cursor.rowcount
            connection.execute(
                "UPDATE ad_logon_key_enrollments SET status='cancelled', pairing_code='', credential_id='' "
                "WHERE credential_id = ? AND status IN ('pending','ready')",
                (credential_id,),
            )
            connection.execute("COMMIT")
            return revoked
        except sqlite3.Error:
            try:
                connection.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            return None
        finally:
            connection.close()

    def revoke_without_active_approval_key(self, *, administrator: str = "system:startup-reconcile",
                                           now: float | None = None) -> int | None:
        """Repair historical AD keys left active after their phone key was revoked.

        Revoked records remain for audit. Central AD phones use the reserved
        machine ID; workstation-scoped keys require their originating machine
        to remain active as well.
        """
        if (not isinstance(administrator, str) or not administrator or len(administrator) > 256
                or any(ord(char) < 32 for char in administrator)):
            return None
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            current = time.time() if now is None else now
            cursor = connection.execute(
                """UPDATE ad_logon_keys SET revoked_at = ?, revoked_by = ?
                   WHERE revoked_at IS NULL AND NOT EXISTS (
                       SELECT 1 FROM phone_credentials AS p
                       LEFT JOIN machines AS m ON m.machine_id = p.machine_id
                       WHERE p.credential_id = ad_logon_keys.approval_credential_id
                         AND p.revoked_at IS NULL
                         AND (p.machine_id = ? OR (m.machine_id IS NOT NULL AND m.revoked_at IS NULL))
                   )""",
                (current, administrator, CENTRAL_AD_MACHINE_ID),
            )
            revoked = cursor.rowcount
            connection.execute(
                """UPDATE ad_logon_key_enrollments SET status='cancelled', pairing_code='', credential_id=''
                   WHERE status IN ('pending','ready') AND credential_id <> '' AND NOT EXISTS (
                       SELECT 1 FROM phone_credentials AS p
                       LEFT JOIN machines AS m ON m.machine_id = p.machine_id
                       WHERE p.credential_id = ad_logon_key_enrollments.credential_id
                         AND p.revoked_at IS NULL
                         AND (p.machine_id = ? OR (m.machine_id IS NOT NULL AND m.revoked_at IS NULL))
                   )""",
                (CENTRAL_AD_MACHINE_ID,),
            )
            connection.execute("COMMIT")
            return revoked
        except sqlite3.Error:
            try:
                connection.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            return None
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
                "WHERE key_id = ? AND principal_id = ? AND revoked_at IS NULL",
                (key_id, principal_id),
            ).fetchone()
            return row[0] if row else None
        except sqlite3.Error:
            return None
        finally:
            connection.close()
