"""SID- and machine-scoped Android approval keys for the standalone AD service."""

from __future__ import annotations

import base64
import binascii
import os
import re
import secrets
import sqlite3
import stat
import time
from pathlib import Path

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
        finally:
            connection.close()
        os.chmod(self.path, 0o600)

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
