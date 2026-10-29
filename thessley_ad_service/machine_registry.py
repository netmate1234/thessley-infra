"""Dedicated storage for one-use machine pairing codes and enrolled keys."""

from __future__ import annotations

import base64
import binascii
import hashlib
import math
import os
import re
import secrets
import sqlite3
import time
from pathlib import Path
from .state_permissions import finish_private_sqlite, prepare_private_sqlite

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

_MACHINE_ID = re.compile(r"^[a-f0-9]{32}$")
_CODE = re.compile(r"^[A-Za-z0-9_-]{32,128}$")
_MACHINE_NAME = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")


class MachineRegistry:
    """Store machine keys separately from generic Thessley PAM device data.

    The code-creation method must only be exposed through a separately
    authenticated administrator flow. This class intentionally has no HTTP
    handler and does not decide who is an administrator.
    """

    def __init__(self, path: str | os.PathLike[str]):
        self.path = Path(path)
        self._prepare_file()
        self._initialize()

    def _prepare_file(self) -> None:
        prepare_private_sqlite(self.path, description="machine registry")

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=5, isolation_level=None)
        connection.execute("PRAGMA busy_timeout = 5000")
        return connection

    def _initialize(self) -> None:
        connection = self._connect()
        try:
            connection.execute("PRAGMA journal_mode = DELETE")
            connection.execute(
                """CREATE TABLE IF NOT EXISTS machine_enrollment_codes (
                       code_hash TEXT PRIMARY KEY,
                       created_at REAL NOT NULL,
                       expires_at REAL NOT NULL,
                       consumed_at REAL
                   ) WITHOUT ROWID"""
            )
            connection.execute(
                """CREATE TABLE IF NOT EXISTS machines (
                       machine_id TEXT PRIMARY KEY,
                       machine_name TEXT NOT NULL,
                       public_key_spki_b64 TEXT NOT NULL UNIQUE,
                       created_at REAL NOT NULL,
                       revoked_at REAL
                   ) WITHOUT ROWID"""
            )
        finally:
            connection.close()
        finish_private_sqlite(self.path)

    def create_enrollment_code(self, *, lifetime_seconds: int = 600, now: float | None = None) -> str:
        """Create a one-use code; caller must enforce admin authorization."""
        if isinstance(lifetime_seconds, bool) or not isinstance(lifetime_seconds, int):
            raise ValueError("invalid enrollment-code lifetime")
        if not 60 <= lifetime_seconds <= 1800:
            raise ValueError("enrollment-code lifetime must be between 60 and 1800 seconds")
        created = time.time() if now is None else now
        if isinstance(created, bool) or not isinstance(created, (int, float)) or not math.isfinite(created):
            raise ValueError("invalid creation time")
        code = secrets.token_urlsafe(32)
        digest = hashlib.sha256(code.encode("ascii")).hexdigest()
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute("DELETE FROM machine_enrollment_codes WHERE expires_at <= ?", (created,))
            connection.execute(
                "INSERT INTO machine_enrollment_codes(code_hash, created_at, expires_at) VALUES (?, ?, ?)",
                (digest, created, created + lifetime_seconds),
            )
            connection.execute("COMMIT")
            return code
        except sqlite3.Error:
            try:
                connection.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise RuntimeError("Could not create machine enrollment code")
        finally:
            connection.close()

    @staticmethod
    def _valid_public_key(public_key_spki_b64: str) -> bool:
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

    def enroll(self, *, code: str, machine_name: str, public_key_spki_b64: str, now: float | None = None) -> str | None:
        """Consume an admin-issued code and store one P-256 machine public key."""
        if not isinstance(code, str) or not _CODE.fullmatch(code):
            return None
        if not isinstance(machine_name, str) or not _MACHINE_NAME.fullmatch(machine_name):
            return None
        if not self._valid_public_key(public_key_spki_b64):
            return None
        current = time.time() if now is None else now
        if isinstance(current, bool) or not isinstance(current, (int, float)) or not math.isfinite(current):
            return None
        digest = hashlib.sha256(code.encode("ascii")).hexdigest()
        machine_id = secrets.token_hex(16)
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            cursor = connection.execute(
                "UPDATE machine_enrollment_codes SET consumed_at = ? "
                "WHERE code_hash = ? AND consumed_at IS NULL AND expires_at > ?",
                (current, digest, current),
            )
            if cursor.rowcount != 1:
                connection.execute("ROLLBACK")
                return None
            connection.execute(
                "INSERT INTO machines(machine_id, machine_name, public_key_spki_b64, created_at) "
                "VALUES (?, ?, ?, ?)",
                (machine_id, machine_name, public_key_spki_b64, current),
            )
            connection.execute("COMMIT")
            return machine_id
        except sqlite3.Error:
            try:
                connection.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            return None
        finally:
            connection.close()

    def public_key(self, machine_id: str) -> str | None:
        if not isinstance(machine_id, str) or not _MACHINE_ID.fullmatch(machine_id):
            return None
        connection = self._connect()
        try:
            row = connection.execute(
                "SELECT public_key_spki_b64 FROM machines WHERE machine_id = ? AND revoked_at IS NULL",
                (machine_id,),
            ).fetchone()
            return None if row is None else str(row[0])
        finally:
            connection.close()

    def machine_name(self, machine_id: str) -> str | None:
        if not isinstance(machine_id, str) or not _MACHINE_ID.fullmatch(machine_id):
            return None
        connection = self._connect()
        try:
            row = connection.execute(
                "SELECT machine_name FROM machines WHERE machine_id = ? AND revoked_at IS NULL",
                (machine_id,),
            ).fetchone()
            return None if row is None else str(row[0])
        finally:
            connection.close()

    def list_active(self) -> list[dict[str, str]]:
        """List paired workstation metadata without exposing public keys."""
        connection = self._connect()
        try:
            rows = connection.execute(
                "SELECT machine_id,machine_name FROM machines WHERE revoked_at IS NULL ORDER BY machine_name COLLATE NOCASE,machine_id"
            ).fetchall()
            return [{"machine_id": str(row[0]), "machine_name": str(row[1])} for row in rows]
        finally:
            connection.close()

    def revoke(self, machine_id: str, *, now: float | None = None) -> bool:
        if not isinstance(machine_id, str) or not _MACHINE_ID.fullmatch(machine_id):
            return False
        connection = self._connect()
        try:
            cursor = connection.execute(
                "UPDATE machines SET revoked_at = ? WHERE machine_id = ? AND revoked_at IS NULL",
                (time.time() if now is None else now, machine_id),
            )
            return cursor.rowcount == 1
        finally:
            connection.close()
