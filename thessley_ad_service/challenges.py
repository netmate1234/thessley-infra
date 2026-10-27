"""Persistent, one-use state for SID-bound Windows sign-in requests."""

from __future__ import annotations

import os
import re
import secrets
import sqlite3
import stat
import time
from pathlib import Path
from typing import Callable

from .protocol import canonical_phone_message, principal_id_from_sid, timestamp_is_fresh, verify_phone_signature

_MACHINE_ID = re.compile(r"^[a-f0-9]{32}$")
_PRINCIPAL_ID = re.compile(r"^[a-f0-9]{64}$")
_CREDENTIAL_ID = re.compile(r"^[A-Za-z0-9_-]{8,128}$")


class ChallengeStore:
    """Store login challenges; phone keys are resolved by a trusted callback.

    ``public_key_lookup`` must return a key only when the credential is
    enrolled for the exact machine and principal. Callers must resolve and
    authorize the domain SID against AD before creating a challenge, and must
    authenticate the machine before polling its result.
    """

    def __init__(self, path: str | os.PathLike[str], public_key_lookup: Callable[[str, str, str], str | None]):
        self.path = Path(path)
        self.public_key_lookup = public_key_lookup
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
            raise RuntimeError("Could not safely open AD challenge database") from exc
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
                raise RuntimeError("AD challenge database has unsafe ownership or permissions")
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
                """CREATE TABLE IF NOT EXISTS login_challenges (
                       request_id TEXT PRIMARY KEY,
                       machine_id TEXT NOT NULL,
                       principal_id TEXT NOT NULL,
                       principal_type TEXT NOT NULL,
                       authority TEXT NOT NULL,
                       username TEXT NOT NULL,
                       context TEXT NOT NULL,
                       nonce TEXT NOT NULL UNIQUE,
                       created_at REAL NOT NULL,
                       expires_at REAL NOT NULL,
                       status TEXT NOT NULL,
                       credential_id TEXT,
                       response_at REAL,
                       delivered_at REAL
                   ) WITHOUT ROWID"""
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS login_challenges_expiry ON login_challenges(expires_at)"
            )
        finally:
            connection.close()
        os.chmod(self.path, 0o600)

    def create(self, *, machine_id: str, sid: str, username: str, authority: str,
               context: str, lifetime_seconds: int = 90, now: float | None = None) -> dict:
        if not isinstance(machine_id, str) or not _MACHINE_ID.fullmatch(machine_id):
            raise ValueError("invalid machine id")
        if isinstance(lifetime_seconds, bool) or not isinstance(lifetime_seconds, int) or not 30 <= lifetime_seconds <= 180:
            raise ValueError("challenge lifetime must be between 30 and 180 seconds")
        current = time.time() if now is None else now
        principal_id = principal_id_from_sid(sid)
        request_id = secrets.token_urlsafe(24)
        nonce = secrets.token_urlsafe(24)
        expires = current + lifetime_seconds
        # Run protocol-level field validation before creating durable state.
        canonical_phone_message(
            type_="login", request_id=request_id, machine_id=machine_id,
            principal_id=principal_id, principal_type="domain", authority=authority,
            username=username, context=context, nonce=nonce, timestamp=int(current), action="approve",
        )
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute("DELETE FROM login_challenges WHERE expires_at <= ?", (current,))
            connection.execute(
                """INSERT INTO login_challenges
                   (request_id, machine_id, principal_id, principal_type, authority, username,
                    context, nonce, created_at, expires_at, status)
                   VALUES (?, ?, ?, 'domain', ?, ?, ?, ?, ?, ?, 'pending')""",
                (request_id, machine_id, principal_id, authority, username, context, nonce, current, expires),
            )
            connection.execute("COMMIT")
            return {
                "request_id": request_id,
                "nonce": nonce,
                "machine_id": machine_id,
                "principal_id": principal_id,
                "principal_type": "domain",
                "authority": authority,
                "username": username,
                "context": context,
                "expires_at": expires,
            }
        except sqlite3.Error as exc:
            try:
                connection.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise RuntimeError("Could not create login challenge") from exc
        finally:
            connection.close()

    def respond(self, *, request_id: str, credential_id: str, action: str, timestamp: int,
                signature_b64: str, now: float | None = None) -> bool:
        if not isinstance(request_id, str) or not re.fullmatch(r"[A-Za-z0-9_-]{8,128}", request_id):
            return False
        if not isinstance(credential_id, str) or not _CREDENTIAL_ID.fullmatch(credential_id):
            return False
        if action not in ("approve", "deny") or not timestamp_is_fresh(timestamp, now):
            return False

        connection = self._connect()
        try:
            row = connection.execute(
                "SELECT machine_id, principal_id, principal_type, authority, username, context, nonce, expires_at, status "
                "FROM login_challenges WHERE request_id = ?",
                (request_id,),
            ).fetchone()
            if row is None:
                return False
            machine_id, principal_id, principal_type, authority, username, context, nonce, expires_at, status = row
            current = time.time() if now is None else now
            if status != "pending" or expires_at <= current:
                return False
            public_key = self.public_key_lookup(credential_id, machine_id, principal_id)
            if not public_key:
                return False
            try:
                message = canonical_phone_message(
                    type_="login", request_id=request_id, machine_id=machine_id,
                    principal_id=principal_id, principal_type=principal_type, authority=authority,
                    username=username, context=context, nonce=nonce, timestamp=timestamp, action=action,
                )
            except ValueError:
                return False
            if not verify_phone_signature(public_key, signature_b64, message):
                return False

            connection.execute("BEGIN IMMEDIATE")
            cursor = connection.execute(
                "UPDATE login_challenges SET status = ?, credential_id = ?, response_at = ? "
                "WHERE request_id = ? AND status = 'pending' AND expires_at > ?",
                (action, credential_id, current, request_id, current),
            )
            connection.execute("COMMIT")
            return cursor.rowcount == 1
        except sqlite3.Error:
            try:
                connection.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            return False
        finally:
            connection.close()

    def consume_result(self, *, machine_id: str, request_id: str, now: float | None = None) -> dict | None:
        if not isinstance(machine_id, str) or not _MACHINE_ID.fullmatch(machine_id):
            return None
        if not isinstance(request_id, str) or not re.fullmatch(r"[A-Za-z0-9_-]{8,128}", request_id):
            return None
        current = time.time() if now is None else now
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT status, expires_at, delivered_at FROM login_challenges "
                "WHERE request_id = ? AND machine_id = ?",
                (request_id, machine_id),
            ).fetchone()
            if row is None:
                connection.execute("COMMIT")
                return None
            status, expires_at, delivered_at = row
            if status == "pending" and expires_at <= current:
                connection.execute(
                    "UPDATE login_challenges SET status = 'expired' WHERE request_id = ? AND status = 'pending'",
                    (request_id,),
                )
                status = "expired"
            if status in ("approve", "deny"):
                if delivered_at is not None:
                    connection.execute("COMMIT")
                    return {"status": "consumed"}
                connection.execute(
                    "UPDATE login_challenges SET delivered_at = ? WHERE request_id = ? AND delivered_at IS NULL",
                    (current, request_id),
                )
                connection.execute("COMMIT")
                return {"status": "approved" if status == "approve" else "denied"}
            connection.execute("COMMIT")
            return {"status": status}
        except sqlite3.Error:
            try:
                connection.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            return None
        finally:
            connection.close()
