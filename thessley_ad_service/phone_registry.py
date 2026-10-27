"""SID- and machine-scoped Android approval keys for the standalone AD service."""

from __future__ import annotations

import base64
import binascii
import hashlib
import os
import re
import secrets
import sqlite3
import stat
import time
from pathlib import Path
from .protocol import canonical_phone_message, principal_id_from_sid, timestamp_is_fresh, verify_phone_signature

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

_MACHINE_ID = re.compile(r"^[a-f0-9]{32}$")
_PRINCIPAL_ID = re.compile(r"^[a-f0-9]{64}$")
_CREDENTIAL_ID = re.compile(r"^[A-Za-z0-9_-]{32,64}$")
_LABEL = re.compile(r"^[^\x00-\x1f\x7f]{1,64}$")


class PhoneRegistry:
    """Store phone P-256 public keys bound to one AD SID and one machine.

    ``enroll`` is a privileged internal operation. Its caller must first
    complete the phone's signed enrollment and the human pairing-code check;
    this class does not accept Android attestation as verified evidence.
    """

    def __init__(self, path: str | os.PathLike[str]):
        self.path = Path(path)
        self._prepare_file()
        self._initialize()

    def _prepare_file(self) -> None:
        try:
            parent = os.stat(self.path.parent, follow_symlinks=False)
        except OSError as exc:
            raise RuntimeError("AD service state directory must exist") from exc
        if not stat.S_ISDIR(parent.st_mode) or parent.st_uid != os.geteuid() or parent.st_mode & 0o022:
            raise RuntimeError("AD service state directory has unsafe ownership or permissions")
        try:
            fd = os.open(self.path, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
        except OSError as exc:
            raise RuntimeError("Could not safely open phone registry") from exc
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
                raise RuntimeError("Phone registry has unsafe ownership or permissions")
            os.fchmod(fd, 0o600)
        finally:
            os.close(fd)

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=5, isolation_level=None)
        connection.execute("PRAGMA busy_timeout = 5000")
        return connection

    def _initialize(self) -> None:
        connection = self._connect()
        try:
            connection.execute("PRAGMA journal_mode = DELETE")
            connection.execute(
                """CREATE TABLE IF NOT EXISTS phone_credentials (
                       credential_id TEXT PRIMARY KEY,
                       machine_id TEXT NOT NULL,
                       principal_id TEXT NOT NULL,
                       public_key_spki_b64 TEXT NOT NULL,
                       label TEXT NOT NULL,
                       enrolled_at REAL NOT NULL,
                       revoked_at REAL
                   ) WITHOUT ROWID"""
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS phone_credentials_binding "
                "ON phone_credentials(machine_id, principal_id, revoked_at)"
            )
            connection.execute(
                """CREATE TABLE IF NOT EXISTS phone_enrollments (
                       request_id TEXT PRIMARY KEY,
                       machine_id TEXT NOT NULL,
                       principal_id TEXT NOT NULL,
                       username TEXT NOT NULL,
                       authority TEXT NOT NULL,
                       nonce TEXT NOT NULL UNIQUE,
                       expires_at REAL NOT NULL,
                       status TEXT NOT NULL,
                       public_key_spki_b64 TEXT,
                       label TEXT,
                       credential_id TEXT UNIQUE,
                       pairing_code TEXT,
                       confirm_attempts INTEGER NOT NULL DEFAULT 0
                   ) WITHOUT ROWID"""
            )
        finally:
            connection.close()
        os.chmod(self.path, 0o600)

    def create_enrollment(self, *, machine_id: str, sid: str, username: str, authority: str,
                          lifetime_seconds: int = 120, now: float | None = None) -> dict | None:
        """Create a short-lived phone-key enrollment bound to one machine and AD SID."""
        if not isinstance(machine_id, str) or not _MACHINE_ID.fullmatch(machine_id):
            return None
        try:
            principal_id = principal_id_from_sid(sid)
            canonical_phone_message(
                type_="enroll", request_id="A" * 32, machine_id=machine_id,
                principal_id=principal_id, principal_type="domain", authority=authority,
                username=username, context="enrollment", nonce="B" * 32,
                timestamp=int(time.time() if now is None else now), action="register",
            )
        except (TypeError, ValueError):
            return None
        if isinstance(lifetime_seconds, bool) or not isinstance(lifetime_seconds, int) or not 60 <= lifetime_seconds <= 300:
            return None
        current = time.time() if now is None else now
        request_id = secrets.token_urlsafe(24)
        nonce = secrets.token_urlsafe(24)
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute("DELETE FROM phone_enrollments WHERE expires_at <= ?", (current,))
            machine = connection.execute(
                "SELECT 1 FROM machines WHERE machine_id = ? AND revoked_at IS NULL", (machine_id,)
            ).fetchone()
            if machine is None:
                connection.execute("ROLLBACK")
                return None
            connection.execute(
                """INSERT INTO phone_enrollments
                   (request_id, machine_id, principal_id, username, authority, nonce, expires_at, status)
                   VALUES (?, ?, ?, ?, ?, ?, ?, 'pending')""",
                (request_id, machine_id, principal_id, username, authority, nonce, current + lifetime_seconds),
            )
            connection.execute("COMMIT")
            return {"request_id": request_id, "machine_id": machine_id, "principal_id": principal_id,
                    "principal_type": "domain", "username": username, "authority": authority,
                    "context": "enrollment", "nonce": nonce, "expires_at": current + lifetime_seconds}
        except sqlite3.Error:
            try:
                connection.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            return None
        finally:
            connection.close()

    def submit_enrollment(self, *, request_id: str, public_key_spki_b64: str, label: str,
                          timestamp: int, signature_b64: str, now: float | None = None) -> bool:
        """Verify proof of possession and stage a key until the Windows user confirms the pairing code."""
        if (not isinstance(request_id, str) or not re.fullmatch(r"[A-Za-z0-9_-]{8,128}", request_id)
                or not self._valid_key(public_key_spki_b64) or not isinstance(label, str)
                or not _LABEL.fullmatch(label) or not timestamp_is_fresh(timestamp, now)):
            return False
        current = time.time() if now is None else now
        connection = self._connect()
        try:
            row = connection.execute(
                "SELECT machine_id, principal_id, username, authority, nonce, expires_at, status "
                "FROM phone_enrollments WHERE request_id = ?", (request_id,)
            ).fetchone()
            if row is None:
                return False
            machine_id, principal_id, username, authority, nonce, expires_at, status = row
            if status != "pending" or expires_at <= current:
                return False
            message = canonical_phone_message(
                type_="enroll", request_id=request_id, machine_id=machine_id,
                principal_id=principal_id, principal_type="domain", authority=authority,
                username=username, context="enrollment", nonce=nonce,
                timestamp=timestamp, action="register",
            )
            if not verify_phone_signature(public_key_spki_b64, signature_b64, message):
                return False
            digest = hashlib.sha256(base64.b64decode(public_key_spki_b64, validate=True)).digest()
            code_number = int.from_bytes(digest[:4], "big") % 1_000_000
            pairing_code = f"{code_number:06d}"[:3] + " " + f"{code_number:06d}"[3:]
            credential_id = secrets.token_urlsafe(24)
            connection.execute("BEGIN IMMEDIATE")
            cursor = connection.execute(
                "UPDATE phone_enrollments SET status = 'ready', public_key_spki_b64 = ?, label = ?, "
                "credential_id = ?, pairing_code = ? WHERE request_id = ? AND status = 'pending' AND expires_at > ?",
                (public_key_spki_b64, label, credential_id, pairing_code, request_id, current),
            )
            connection.execute("COMMIT")
            return cursor.rowcount == 1
        except (sqlite3.Error, TypeError, ValueError):
            try:
                connection.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            return False
        finally:
            connection.close()

    def enrollment_status(self, *, machine_id: str, request_id: str, now: float | None = None) -> dict | None:
        if (not isinstance(machine_id, str) or not _MACHINE_ID.fullmatch(machine_id)
                or not isinstance(request_id, str) or not re.fullmatch(r"[A-Za-z0-9_-]{8,128}", request_id)):
            return None
        current = time.time() if now is None else now
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT status, expires_at, pairing_code, username FROM phone_enrollments "
                "WHERE request_id = ? AND machine_id = ?", (request_id, machine_id)
            ).fetchone()
            if row is None:
                connection.execute("COMMIT")
                return None
            status, expires_at, pairing_code, username = row
            if status in ("pending", "ready") and expires_at <= current:
                connection.execute("UPDATE phone_enrollments SET status = 'expired' WHERE request_id = ?", (request_id,))
                status = "expired"
            connection.execute("COMMIT")
            result = {"status": status, "username": username}
            if status == "ready":
                result["pairing_code"] = pairing_code
            return result
        except sqlite3.Error:
            try:
                connection.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            return None
        finally:
            connection.close()

    def confirm_enrollment(self, *, machine_id: str, request_id: str, pairing_code: str,
                           now: float | None = None) -> bool:
        if (not isinstance(machine_id, str) or not _MACHINE_ID.fullmatch(machine_id)
                or not isinstance(request_id, str) or not re.fullmatch(r"[A-Za-z0-9_-]{8,128}", request_id)
                or not isinstance(pairing_code, str) or not re.fullmatch(r"[0-9]{3} [0-9]{3}", pairing_code)):
            return False
        current = time.time() if now is None else now
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT principal_id, public_key_spki_b64, label, credential_id, pairing_code, expires_at, confirm_attempts "
                "FROM phone_enrollments WHERE request_id = ? AND machine_id = ? AND status = 'ready'",
                (request_id, machine_id),
            ).fetchone()
            if row is None:
                connection.execute("ROLLBACK")
                return False
            principal_id, public_key, label, credential_id, expected_code, expires_at, attempts = row
            if expires_at <= current:
                connection.execute(
                    "UPDATE phone_enrollments SET status = 'expired' WHERE request_id = ?", (request_id,)
                )
                connection.execute("COMMIT")
                return False
            if not secrets.compare_digest(pairing_code, expected_code):
                attempts += 1
                connection.execute(
                    "UPDATE phone_enrollments SET confirm_attempts = ?, status = ? WHERE request_id = ?",
                    (attempts, "denied" if attempts >= 5 else "ready", request_id),
                )
                connection.execute("COMMIT")
                return False
            connection.execute(
                "INSERT INTO phone_credentials "
                "(credential_id, machine_id, principal_id, public_key_spki_b64, label, enrolled_at) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (credential_id, machine_id, principal_id, public_key, label, current),
            )
            connection.execute(
                "UPDATE phone_enrollments SET status = 'confirmed' WHERE request_id = ? AND status = 'ready'",
                (request_id,),
            )
            connection.execute("COMMIT")
            return True
        except sqlite3.Error:
            try:
                connection.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            return False
        finally:
            connection.close()

    def cancel_enrollment(self, *, machine_id: str, request_id: str) -> bool:
        if (not isinstance(machine_id, str) or not _MACHINE_ID.fullmatch(machine_id)
                or not isinstance(request_id, str) or not re.fullmatch(r"[A-Za-z0-9_-]{8,128}", request_id)):
            return False
        connection = self._connect()
        try:
            cursor = connection.execute(
                "UPDATE phone_enrollments SET status = 'denied', public_key_spki_b64 = NULL, label = NULL, "
                "credential_id = NULL, pairing_code = NULL "
                "WHERE request_id = ? AND machine_id = ? AND status IN ('pending', 'ready')",
                (request_id, machine_id),
            )
            return cursor.rowcount == 1
        finally:
            connection.close()

    def wait_enrollment(self, request_id: str, timeout: int = 115) -> dict | None:
        """Wait briefly for the paired Windows console to confirm the displayed code."""
        if not isinstance(request_id, str) or not re.fullmatch(r"[A-Za-z0-9_-]{8,128}", request_id):
            return None
        deadline = time.monotonic() + max(1, min(timeout, 120))
        while time.monotonic() < deadline:
            connection = self._connect()
            try:
                row = connection.execute(
                    "SELECT status, expires_at, credential_id, username FROM phone_enrollments WHERE request_id = ?",
                    (request_id,),
                ).fetchone()
            finally:
                connection.close()
            if row is None:
                return None
            status, expires_at, credential_id, username = row
            if status == "confirmed":
                return {"status": "confirmed", "credential_id": credential_id, "username": username}
            if status == "denied":
                return {"status": "denied"}
            if status == "expired" or expires_at <= time.time():
                return {"status": "expired"}
            time.sleep(0.5)
        return {"status": "pending"}

    @staticmethod
    def _valid_key(public_key_spki_b64: str) -> bool:
        if not isinstance(public_key_spki_b64, str) or len(public_key_spki_b64) > 4096:
            return False
        try:
            der = base64.b64decode(public_key_spki_b64, validate=True)
            if base64.b64encode(der).decode("ascii") != public_key_spki_b64:
                return False
            key = serialization.load_der_public_key(der)
            return isinstance(key, ec.EllipticCurvePublicKey) and key.curve.name == "secp256r1"
        except (binascii.Error, ValueError, TypeError):
            return False

    def enroll(self, *, machine_id: str, principal_id: str, public_key_spki_b64: str,
               label: str, now: float | None = None) -> str | None:
        """Persist an already-approved key and return its random credential id."""
        if not isinstance(machine_id, str) or not _MACHINE_ID.fullmatch(machine_id):
            return None
        if not isinstance(principal_id, str) or not _PRINCIPAL_ID.fullmatch(principal_id):
            return None
        if not self._valid_key(public_key_spki_b64) or not isinstance(label, str) or not _LABEL.fullmatch(label):
            return None
        credential_id = secrets.token_urlsafe(24)
        if not _CREDENTIAL_ID.fullmatch(credential_id):
            return None
        enrolled_at = time.time() if now is None else now
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            machine = connection.execute(
                "SELECT 1 FROM machines WHERE machine_id = ? AND revoked_at IS NULL", (machine_id,)
            ).fetchone()
            if machine is None:
                connection.execute("ROLLBACK")
                return None
            connection.execute(
                """INSERT INTO phone_credentials
                   (credential_id, machine_id, principal_id, public_key_spki_b64, label, enrolled_at)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (credential_id, machine_id, principal_id, public_key_spki_b64, label, enrolled_at),
            )
            connection.execute("COMMIT")
            return credential_id
        except sqlite3.Error:
            try:
                connection.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            return None
        finally:
            connection.close()

    def public_key_for(self, credential_id: str, machine_id: str, principal_id: str) -> str | None:
        if not isinstance(credential_id, str) or not _CREDENTIAL_ID.fullmatch(credential_id):
            return None
        if not isinstance(machine_id, str) or not _MACHINE_ID.fullmatch(machine_id):
            return None
        if not isinstance(principal_id, str) or not _PRINCIPAL_ID.fullmatch(principal_id):
            return None
        connection = self._connect()
        try:
            row = connection.execute(
                """SELECT p.public_key_spki_b64 FROM phone_credentials AS p
                   JOIN machines AS m ON m.machine_id = p.machine_id
                   WHERE p.credential_id = ? AND p.machine_id = ? AND p.principal_id = ?
                     AND p.revoked_at IS NULL AND m.revoked_at IS NULL""",
                (credential_id, machine_id, principal_id),
            ).fetchone()
            return None if row is None else str(row[0])
        finally:
            connection.close()

    def revoke(self, credential_id: str, *, now: float | None = None) -> bool:
        if not isinstance(credential_id, str) or not _CREDENTIAL_ID.fullmatch(credential_id):
            return False
        connection = self._connect()
        try:
            cursor = connection.execute(
                "UPDATE phone_credentials SET revoked_at = ? WHERE credential_id = ? AND revoked_at IS NULL",
                (time.time() if now is None else now, credential_id),
            )
            return cursor.rowcount == 1
        finally:
            connection.close()
