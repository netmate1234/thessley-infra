"""Central AD sign-in method policy with fail-closed method selection."""

from __future__ import annotations

import os
import re
import sqlite3
from contextlib import contextmanager
from pathlib import Path

from .state_permissions import finish_private_sqlite, prepare_private_sqlite
from .directory import validate_group_sid_allowlist

METHOD_TPM = "tpm_smartcard"
METHOD_WINDOWS = "windows_native"
METHOD_EPHEMERAL_CERT = "phone_ephemeral_certificate"
METHOD_LABELS = {
    METHOD_TPM: "Phone approval + this PC's TPM smart card",
    METHOD_WINDOWS: "Windows password / Hello (Thessley QR off)",
    METHOD_EPHEMERAL_CERT: "Phone-approved short-lived certificate (not validated yet)",
}
_ACTIVE_METHODS = frozenset({METHOD_TPM, METHOD_WINDOWS})
_ALL_METHODS = frozenset(METHOD_LABELS)
_MACHINE_ID = re.compile(r"^[a-f0-9]{32}$")


class PolicyError(ValueError):
    """A policy entry is malformed, conflicting, or not yet supported."""


class LoginPolicyStore:
    """Store policy rules in the protected AD service state database.

    A paired-PC override wins over a matching nested AD-group rule. The
    highest-priority group rule wins; ties with different methods fail closed.
    The domain default is used when neither override applies.
    """

    def __init__(self, path: str | os.PathLike[str]):
        self.path = Path(path)
        prepare_private_sqlite(self.path, description="AD login policy")
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=5, isolation_level=None)
        connection.execute("PRAGMA busy_timeout = 5000")
        return connection

    @contextmanager
    def _connection(self):
        connection = self._connect()
        try:
            yield connection
        finally:
            connection.close()

    def _initialize(self) -> None:
        connection = self._connect()
        try:
            connection.execute("PRAGMA journal_mode = DELETE")
            connection.execute(
                """CREATE TABLE IF NOT EXISTS login_policy_settings (
                       setting TEXT PRIMARY KEY,
                       value TEXT NOT NULL,
                       updated_at REAL NOT NULL,
                       updated_by TEXT NOT NULL
                   ) WITHOUT ROWID"""
            )
            connection.execute(
                """CREATE TABLE IF NOT EXISTS login_policy_groups (
                       group_sid TEXT PRIMARY KEY,
                       method TEXT NOT NULL,
                       priority INTEGER NOT NULL,
                       updated_at REAL NOT NULL,
                       updated_by TEXT NOT NULL
                   ) WITHOUT ROWID"""
            )
            connection.execute(
                """CREATE TABLE IF NOT EXISTS login_policy_machines (
                       machine_id TEXT PRIMARY KEY,
                       method TEXT NOT NULL,
                       updated_at REAL NOT NULL,
                       updated_by TEXT NOT NULL
                   ) WITHOUT ROWID"""
            )
            connection.execute(
                "INSERT OR IGNORE INTO login_policy_settings(setting,value,updated_at,updated_by) "
                "VALUES('default_method',?,?,?)", (METHOD_TPM, 0, "system")
            )
        finally:
            connection.close()
        finish_private_sqlite(self.path)

    @staticmethod
    def validate_method(method: str) -> str:
        if not isinstance(method, str):
            raise PolicyError("Unknown Thessley sign-in method.")
        if method not in _ALL_METHODS:
            raise PolicyError("Unknown Thessley sign-in method.")
        if method not in _ACTIVE_METHODS:
            raise PolicyError("That sign-in method is not enabled until its AD/KDC proof is complete.")
        return method

    @staticmethod
    def _actor(actor: str) -> str:
        if not isinstance(actor, str) or not re.fullmatch(r"S-1-(?:[0-9]+-)+[0-9]+", actor):
            raise PolicyError("The authenticated administrator SID is invalid.")
        return actor

    def set_default(self, method: str, *, actor: str, now: float) -> None:
        method = self.validate_method(method)
        actor = self._actor(actor)
        with self._connection() as connection:
            connection.execute(
                "INSERT INTO login_policy_settings(setting,value,updated_at,updated_by) VALUES(?,?,?,?) "
                "ON CONFLICT(setting) DO UPDATE SET value=excluded.value,updated_at=excluded.updated_at,updated_by=excluded.updated_by",
                ("default_method", method, now, actor),
            )

    def set_group(self, group_sid: str, method: str, priority: int, *, actor: str, now: float) -> None:
        try:
            canonical = next(iter(validate_group_sid_allowlist([group_sid])))
        except (TypeError, ValueError) as exc:
            raise PolicyError("Enter a valid AD security-group SID.") from exc
        method = self.validate_method(method)
        actor = self._actor(actor)
        if isinstance(priority, bool) or not isinstance(priority, int) or not 0 <= priority <= 1000:
            raise PolicyError("Group priority must be between 0 and 1000.")
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                "INSERT INTO login_policy_groups(group_sid,method,priority,updated_at,updated_by) VALUES(?,?,?,?,?) "
                "ON CONFLICT(group_sid) DO UPDATE SET method=excluded.method,priority=excluded.priority,updated_at=excluded.updated_at,updated_by=excluded.updated_by",
                (canonical, method, priority, now, actor),
            )
            self._ensure_no_tied_conflict(connection)
            connection.execute("COMMIT")
        except Exception:
            try:
                connection.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise
        finally:
            connection.close()

    @staticmethod
    def _ensure_no_tied_conflict(connection: sqlite3.Connection) -> None:
        rows = connection.execute(
            "SELECT priority, COUNT(DISTINCT method) FROM login_policy_groups GROUP BY priority HAVING COUNT(DISTINCT method)>1"
        ).fetchone()
        if rows:
            raise PolicyError("Rules with equal priority cannot select different sign-in methods.")

    def remove_group(self, group_sid: str) -> bool:
        try:
            canonical = next(iter(validate_group_sid_allowlist([group_sid])))
        except (TypeError, ValueError):
            return False
        with self._connection() as connection:
            cursor = connection.execute("DELETE FROM login_policy_groups WHERE group_sid=?", (canonical,))
            return cursor.rowcount == 1

    def set_machine(self, machine_id: str, method: str | None, *, actor: str, now: float) -> None:
        if not isinstance(machine_id, str) or not _MACHINE_ID.fullmatch(machine_id):
            raise PolicyError("Select a paired workstation.")
        actor = self._actor(actor)
        if method is None:
            with self._connection() as connection:
                connection.execute("DELETE FROM login_policy_machines WHERE machine_id=?", (machine_id,))
            return
        method = self.validate_method(method)
        with self._connection() as connection:
            connection.execute(
                "INSERT INTO login_policy_machines(machine_id,method,updated_at,updated_by) VALUES(?,?,?,?) "
                "ON CONFLICT(machine_id) DO UPDATE SET method=excluded.method,updated_at=excluded.updated_at,updated_by=excluded.updated_by",
                (machine_id, method, now, actor),
            )

    def snapshot(self) -> dict:
        with self._connection() as connection:
            default = connection.execute(
                "SELECT value,updated_at,updated_by FROM login_policy_settings WHERE setting='default_method'"
            ).fetchone()
            groups = connection.execute(
                "SELECT group_sid,method,priority,updated_at,updated_by FROM login_policy_groups ORDER BY priority DESC,group_sid"
            ).fetchall()
            machines = connection.execute(
                "SELECT machine_id,method,updated_at,updated_by FROM login_policy_machines ORDER BY machine_id"
            ).fetchall()
        return {
            "default": {"method": default[0], "updated_at": default[1], "updated_by": default[2]},
            "groups": [{"group_sid": r[0], "method": r[1], "priority": r[2], "updated_at": r[3], "updated_by": r[4]} for r in groups],
            "machines": [{"machine_id": r[0], "method": r[1], "updated_at": r[2], "updated_by": r[3]} for r in machines],
        }

    def resolve(self, machine_id: str, group_sids) -> dict:
        if not isinstance(machine_id, str) or not _MACHINE_ID.fullmatch(machine_id):
            raise PolicyError("The paired workstation identity is invalid.")
        groups = validate_group_sid_allowlist(group_sids)
        with self._connection() as connection:
            machine = connection.execute(
                "SELECT method FROM login_policy_machines WHERE machine_id=?", (machine_id,)
            ).fetchone()
            if machine:
                method = self.validate_method(machine[0])
                return {"method": method, "source": "workstation"}
            matching = connection.execute(
                "SELECT group_sid,method,priority FROM login_policy_groups WHERE group_sid IN (%s) ORDER BY priority DESC"
                % (",".join("?" for _ in groups) if groups else "NULL"), tuple(groups)
            ).fetchall()
            default = connection.execute(
                "SELECT value FROM login_policy_settings WHERE setting='default_method'"
            ).fetchone()
        if matching:
            top_priority = matching[0][2]
            top = [row for row in matching if row[2] == top_priority]
            methods = {row[1] for row in top}
            if len(methods) != 1:
                raise PolicyError("Matching AD groups select conflicting methods at equal priority.")
            return {"method": self.validate_method(next(iter(methods))), "source": "group",
                    "group_sids": sorted(row[0] for row in top)}
        if not default:
            raise PolicyError("The domain sign-in method has not been configured.")
        return {"method": self.validate_method(default[0]), "source": "domain-default"}
