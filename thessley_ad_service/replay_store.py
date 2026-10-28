"""Persistent, atomic nonce claims for machine-authenticated AD requests."""

from __future__ import annotations

import os
import math
import re
import sqlite3
import time
from pathlib import Path
from .state_permissions import finish_private_sqlite, prepare_private_sqlite

_MACHINE_ID = re.compile(r"^[a-f0-9]{32}$")
_NONCE = re.compile(r"^[A-Za-z0-9_-]{22,86}$")


class SQLiteReplayStore:
    """SQLite-backed nonce store suitable for the root-owned AD service.

    The database directory must already exist and be owned by the service user
    without group/other write permission. The database is created mode 0600;
    an existing symlink, non-regular file, wrong owner, or permissive mode is
    rejected. One connection and ``BEGIN IMMEDIATE`` per claim makes duplicate
    nonce submissions atomic across concurrent handler threads.
    """

    def __init__(self, path: str | os.PathLike[str]):
        self.path = Path(path)
        self._prepare_file()
        self._initialize()

    def _prepare_file(self) -> None:
        prepare_private_sqlite(self.path, description="AD service replay database")

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=5, isolation_level=None)
        connection.execute("PRAGMA busy_timeout = 5000")
        return connection

    def _initialize(self) -> None:
        connection = self._connect()
        try:
            connection.execute("PRAGMA journal_mode = DELETE")
            connection.execute(
                """CREATE TABLE IF NOT EXISTS machine_request_nonces (
                       machine_id TEXT NOT NULL,
                       nonce TEXT NOT NULL,
                       expires_at REAL NOT NULL,
                       PRIMARY KEY (machine_id, nonce)
                   ) WITHOUT ROWID"""
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS machine_request_nonces_expiry "
                "ON machine_request_nonces (expires_at)"
            )
        finally:
            connection.close()
        finish_private_sqlite(self.path)

    def claim(self, machine_id: str, nonce: str, expires_at: float) -> bool:
        """Return true exactly once for a machine/nonce pair before expiry."""
        if not isinstance(machine_id, str) or not _MACHINE_ID.fullmatch(machine_id):
            return False
        if not isinstance(nonce, str) or not _NONCE.fullmatch(nonce):
            return False
        if isinstance(expires_at, bool) or not isinstance(expires_at, (int, float)):
            return False
        now = time.time()
        if not math.isfinite(expires_at):
            return False
        if expires_at <= now or expires_at > now + 120:
            return False

        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute("DELETE FROM machine_request_nonces WHERE expires_at <= ?", (now,))
            cursor = connection.execute(
                "INSERT INTO machine_request_nonces(machine_id, nonce, expires_at) "
                "VALUES (?, ?, ?) ON CONFLICT(machine_id, nonce) DO NOTHING",
                (machine_id, nonce, float(expires_at)),
            )
            claimed = cursor.rowcount == 1
            connection.execute("COMMIT")
            return claimed
        except sqlite3.Error:
            try:
                connection.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            return False
        finally:
            connection.close()
