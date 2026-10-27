"""Persistent, atomic nonce claims for machine-authenticated AD requests."""

from __future__ import annotations

import os
import math
import re
import sqlite3
import stat
import time
from pathlib import Path

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
        directory = self.path.parent
        try:
            directory_stat = os.stat(directory, follow_symlinks=False)
        except OSError as exc:
            raise RuntimeError("AD service state directory must exist") from exc
        if (
            not stat.S_ISDIR(directory_stat.st_mode)
            or directory_stat.st_uid != os.geteuid()
            or directory_stat.st_mode & 0o022
        ):
            raise RuntimeError("AD service state directory has unsafe ownership or permissions")

        flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
        try:
            fd = os.open(self.path, flags, 0o600)
        except OSError as exc:
            raise RuntimeError("Could not safely open AD service replay database") from exc
        try:
            file_stat = os.fstat(fd)
            if (
                not stat.S_ISREG(file_stat.st_mode)
                or file_stat.st_uid != os.geteuid()
                or file_stat.st_mode & 0o077
            ):
                raise RuntimeError("AD service replay database has unsafe ownership or permissions")
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
        os.chmod(self.path, 0o600)

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
