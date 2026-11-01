"""One-use relay for phone-held PIV ECDSA/RSA signatures."""

from __future__ import annotations

import base64
import binascii
import math
import re
import secrets
import sqlite3
import time
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa, utils

from .state_permissions import finish_private_sqlite, prepare_private_sqlite

_TOKEN = re.compile(r"^[A-Za-z0-9_-]{8,128}$")
_MACHINE = re.compile(r"^[a-f0-9]{32}$")
_PRINCIPAL = re.compile(r"^[a-f0-9]{64}$")
_CREDENTIAL = re.compile(r"^[A-Za-z0-9_-]{32,64}$")
_SHA256 = re.compile(r"^[a-f0-9]{64}$")
_B64_SHA256 = re.compile(r"^[A-Za-z0-9+/]{43}=$")
_B64_SIG = re.compile(r"^[A-Za-z0-9+/]{80,512}={0,2}$")
_RSA_DIGEST_INFO = {
    bytes.fromhex("3021300906052b0e03021a05000414"): ("RSA_SHA1", 20, hashes.SHA1),
    bytes.fromhex("3031300d060960864801650304020105000420"): ("RSA_SHA256", 32, hashes.SHA256),
    bytes.fromhex("3041300d060960864801650304020205000430"): ("RSA_SHA384", 48, hashes.SHA384),
    bytes.fromhex("3051300d060960864801650304020305000440"): ("RSA_SHA512", 64, hashes.SHA512),
}
SIGNATURE_LIFETIME_SECONDS = 90
LOGIN_SIGNATURE_WINDOW_SECONDS = 180


def _rsa_digest_info(value: bytes):
    for prefix, (name, digest_size, hash_type) in _RSA_DIGEST_INFO.items():
        if value.startswith(prefix) and len(value) == len(prefix) + digest_size:
            return name, value[len(prefix):], hash_type()
    return None


class PivSignatureStore:
    """Store short-lived Windows digests bound to a pending phone-approved login."""

    def __init__(self, path: str | Path, ad_logon_keys):
        self.path = Path(path)
        self.ad_logon_keys = ad_logon_keys
        prepare_private_sqlite(self.path, description="AD PIV-signature state")
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
                """CREATE TABLE IF NOT EXISTS piv_sign_requests (
                       sign_request_id TEXT PRIMARY KEY,
                       request_id TEXT NOT NULL UNIQUE,
                       machine_id TEXT NOT NULL,
                       principal_id TEXT NOT NULL,
                       credential_id TEXT NOT NULL,
                       ad_logon_key_sha256 TEXT NOT NULL,
                       digest BLOB NOT NULL,
                       created_at REAL NOT NULL,
                       expires_at REAL NOT NULL,
                       status TEXT NOT NULL,
                       signature BLOB
                   ) WITHOUT ROWID"""
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS piv_sign_expiry ON piv_sign_requests(expires_at)"
            )
            # Older Windows AD-service builds named this binding column
            # approval_credential_id. The current protocol uses credential_id
            # for the same value. CREATE TABLE IF NOT EXISTS does not update
            # an existing SQLite table, so migrate it in place before any
            # route queries the table. Keep all existing request rows intact.
            columns = {
                str(row[1]) for row in connection.execute(
                    "PRAGMA table_info(piv_sign_requests)"
                )
            }
            if "credential_id" not in columns and "approval_credential_id" in columns:
                connection.execute(
                    "ALTER TABLE piv_sign_requests "
                    "RENAME COLUMN approval_credential_id TO credential_id"
                )
        finally:
            connection.close()
        finish_private_sqlite(self.path)

    @staticmethod
    def _now(value: float | None) -> float | None:
        current = time.time() if value is None else value
        if isinstance(current, bool) or not isinstance(current, (int, float)) or not math.isfinite(current):
            return None
        return float(current)

    @staticmethod
    def _active_key(connection: sqlite3.Connection, principal_id: str,
                    key_hash: str, credential_id: str) -> bytes | None:
        row = connection.execute(
            "SELECT public_key_spki_b64 FROM ad_logon_keys "
            "WHERE principal_id=? AND public_key_sha256=? AND approval_credential_id=? "
            "AND revoked_at IS NULL ORDER BY created_at DESC LIMIT 1",
            (principal_id, key_hash, credential_id),
        ).fetchone()
        if not row:
            return None
        try:
            return base64.b64decode(row[0], validate=True)
        except (TypeError, ValueError, binascii.Error):
            return None

    @staticmethod
    def _active_key_for_principal(connection: sqlite3.Connection, principal_id: str,
                                  key_hash: str) -> bytes | None:
        """Resolve an active AD key before the approving phone is known."""
        row = connection.execute(
            "SELECT public_key_spki_b64 FROM ad_logon_keys "
            "WHERE principal_id=? AND public_key_sha256=? AND revoked_at IS NULL "
            "ORDER BY created_at DESC LIMIT 1",
            (principal_id, key_hash),
        ).fetchone()
        if not row:
            return None
        try:
            return base64.b64decode(row[0], validate=True)
        except (TypeError, ValueError, binascii.Error):
            return None

    def purge_expired(self, *, now: float | None = None) -> int:
        """Delete expired one-use digests and signatures promptly."""
        current = self._now(now)
        if current is None:
            raise ValueError("invalid PIV-signature cleanup time")
        connection = self._connect()
        try:
            cursor = connection.execute(
                "DELETE FROM piv_sign_requests WHERE expires_at <= ?", (current,)
            )
            return cursor.rowcount
        except sqlite3.Error as exc:
            raise RuntimeError("Could not purge expired PIV signature state") from exc
        finally:
            connection.close()

    def create_for_machine(self, *, machine_id: str, request_id: str,
                           ad_logon_key_sha256: str, digest: bytes,
                           now: float | None = None) -> dict | None:
        current = self._now(now)
        if (current is None or not isinstance(machine_id, str) or not _MACHINE.fullmatch(machine_id)
                or not isinstance(request_id, str) or not _TOKEN.fullmatch(request_id)
                or not isinstance(ad_logon_key_sha256, str) or not _SHA256.fullmatch(ad_logon_key_sha256)
                or not isinstance(digest, bytes)
                or not (len(digest) == 32 or _rsa_digest_info(digest) is not None)):
            return None
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute("DELETE FROM piv_sign_requests WHERE expires_at <= ?", (current,))
            row = connection.execute(
                "SELECT principal_id, context, credential_id, status, response_at, delivered_at, piv_signing, expires_at "
                "FROM login_challenges WHERE request_id=? AND machine_id=?",
                (request_id, machine_id),
            ).fetchone()
            if row is None:
                connection.execute("ROLLBACK")
                return None
            (principal_id, context, credential_id, status, response_at, delivered_at,
             piv_signing, challenge_expires_at) = row
            pending_login = (
                status == "pending" and credential_id is None and response_at is None
                and delivered_at is None and current < challenge_expires_at
            )
            approved_login = (
                status == "approve" and isinstance(credential_id, str)
                and isinstance(response_at, (int, float))
                and response_at <= current <= response_at + LOGIN_SIGNATURE_WINDOW_SECONDS
            )
            if (not isinstance(principal_id, str) or not _PRINCIPAL.fullmatch(principal_id)
                    or context != "interactive" or not (pending_login or approved_login)
                    or piv_signing != 1):
                connection.execute("ROLLBACK")
                return None
            active_key = (
                self._active_key_for_principal(connection, principal_id, ad_logon_key_sha256)
                if pending_login else
                self._active_key(connection, principal_id, ad_logon_key_sha256, credential_id)
            )
            if active_key is None:
                connection.execute("ROLLBACK")
                return None
            existing = connection.execute(
                "SELECT sign_request_id, digest, expires_at, status, ad_logon_key_sha256 "
                "FROM piv_sign_requests WHERE request_id=?", (request_id,),
            ).fetchone()
            if existing:
                sign_id, old_digest, expires_at, old_status, old_hash = existing
                if (old_digest != digest or old_hash != ad_logon_key_sha256
                        or old_status == "expired" or current > expires_at):
                    connection.execute("ROLLBACK")
                    return None
                connection.execute("COMMIT")
                return {"sign_request_id": sign_id, "expires_at": expires_at, "status": old_status}
            sign_id = secrets.token_urlsafe(32)
            expires_at = min(
                current + SIGNATURE_LIFETIME_SECONDS,
                challenge_expires_at if pending_login else response_at + LOGIN_SIGNATURE_WINDOW_SECONDS,
            )
            if expires_at <= current:
                connection.execute("ROLLBACK")
                return None
            stored_credential_id = "" if pending_login else credential_id
            connection.execute(
                "INSERT INTO piv_sign_requests(sign_request_id,request_id,machine_id,principal_id,credential_id,"
                "ad_logon_key_sha256,digest,created_at,expires_at,status) VALUES(?,?,?,?,?,?,?,?,?,'pending')",
                (sign_id, request_id, machine_id, principal_id, stored_credential_id,
                 ad_logon_key_sha256, digest, current, expires_at),
            )
            connection.execute("COMMIT")
            return {"sign_request_id": sign_id, "expires_at": expires_at, "status": "pending"}
        except sqlite3.Error:
            try:
                connection.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            return None
        finally:
            connection.close()

    def for_phone(self, *, request_id: str, credential_id: str,
                  ad_logon_key_sha256: str, now: float | None = None) -> dict | None:
        current = self._now(now)
        if (current is None or not isinstance(request_id, str) or not _TOKEN.fullmatch(request_id)
                or not isinstance(credential_id, str) or not _CREDENTIAL.fullmatch(credential_id)
                or not isinstance(ad_logon_key_sha256, str) or not _SHA256.fullmatch(ad_logon_key_sha256)):
            return None
        connection = self._connect()
        try:
            row = connection.execute(
                "SELECT p.sign_request_id,p.principal_id,p.credential_id,p.ad_logon_key_sha256,"
                "p.digest,p.expires_at,p.status,l.status,l.credential_id,l.response_at,l.delivered_at,"
                "l.piv_signing,l.username,l.authority,l.expires_at FROM piv_sign_requests p "
                "JOIN login_challenges l ON l.request_id=p.request_id WHERE p.request_id=?",
                (request_id,),
            ).fetchone()
            if row is None:
                return {"status": "pending"}
            (sign_id, principal_id, bound_credential, bound_hash, digest, expires_at,
             status, login_status, login_credential, response_at, delivered_at,
             piv_signing, username, authority, challenge_expires_at) = row
            if current > expires_at or status == "expired":
                return {"status": "expired"}
            pending_login = (
                login_status == "pending" and login_credential is None
                and response_at is None and delivered_at is None and current < challenge_expires_at
            )
            approved_login = (
                login_status == "approve" and login_credential == credential_id
                and isinstance(response_at, (int, float))
                and response_at <= current <= response_at + LOGIN_SIGNATURE_WINDOW_SECONDS
            )
            # On the combined one-prompt path the machine does not yet know
            # which enrolled phone will approve. Bind the phone's credential
            # only when it proves possession of the active AD signing key.
            if ((bound_credential and bound_credential != credential_id)
                    or bound_hash != ad_logon_key_sha256):
                return {"status": "pending"}
            if (piv_signing != 1 or not (pending_login or approved_login)
                    or self._active_key(connection, principal_id, ad_logon_key_sha256, credential_id) is None):
                return None
            public_key = serialization.load_der_public_key(self._active_key(
                connection, principal_id, ad_logon_key_sha256, credential_id))
            if isinstance(public_key, ec.EllipticCurvePublicKey):
                if len(digest) != 32:
                    return None
                signature_algorithm = "ECDSA_SHA256"
            elif isinstance(public_key, rsa.RSAPublicKey):
                parsed = _rsa_digest_info(digest)
                if public_key.key_size != 2048 or parsed is None:
                    return None
                signature_algorithm = parsed[0]
            else:
                return None
            if status != "pending":
                return {"status": status}
            return {"status": "sign", "sign_request_id": sign_id,
                    "digest_b64": base64.b64encode(digest).decode("ascii"),
                    "signature_algorithm": signature_algorithm,
                    "username": username, "authority": authority, "expires_at": expires_at}
        except sqlite3.Error:
            return None
        finally:
            connection.close()

    def complete_from_phone(self, *, request_id: str, sign_request_id: str,
                            credential_id: str, ad_logon_key_sha256: str,
                            signature_b64: str, now: float | None = None) -> bool:
        current = self._now(now)
        if (current is None or not isinstance(request_id, str) or not _TOKEN.fullmatch(request_id)
                or not isinstance(sign_request_id, str) or not _TOKEN.fullmatch(sign_request_id)
                or not isinstance(credential_id, str) or not _CREDENTIAL.fullmatch(credential_id)
                or not isinstance(ad_logon_key_sha256, str) or not _SHA256.fullmatch(ad_logon_key_sha256)
                or not isinstance(signature_b64, str) or not _B64_SIG.fullmatch(signature_b64)):
            return False
        try:
            signature = base64.b64decode(signature_b64, validate=True)
            if base64.b64encode(signature).decode("ascii") != signature_b64 or not 64 <= len(signature) <= 512:
                return False
        except (ValueError, binascii.Error):
            return False
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT p.principal_id,p.credential_id,p.ad_logon_key_sha256,p.digest,p.expires_at,"
                "p.status,p.signature,l.status,l.credential_id,l.response_at,l.delivered_at,l.piv_signing,"
                "l.expires_at "
                "FROM piv_sign_requests p JOIN login_challenges l ON l.request_id=p.request_id "
                "WHERE p.request_id=? AND p.sign_request_id=?",
                (request_id, sign_request_id),
            ).fetchone()
            if row is None:
                connection.execute("ROLLBACK")
                return False
            (principal_id, bound_credential, bound_hash, digest, expires_at, status, old_signature,
             login_status, login_credential, response_at, delivered_at, piv_signing,
             challenge_expires_at) = row
            pending_login = (
                login_status == "pending" and login_credential is None and response_at is None
                and delivered_at is None and current < challenge_expires_at
            )
            approved_login = (
                login_status == "approve" and login_credential == credential_id
                and isinstance(response_at, (int, float))
                and response_at <= current <= response_at + LOGIN_SIGNATURE_WINDOW_SECONDS
            )
            if ((bound_credential and bound_credential != credential_id)
                    or bound_hash != ad_logon_key_sha256
                    or current > expires_at or piv_signing != 1
                    or not (pending_login or approved_login)):
                connection.execute("ROLLBACK")
                return False
            spki_b64 = self._active_key(connection, principal_id, ad_logon_key_sha256, credential_id)
            if spki_b64 is None:
                connection.execute("ROLLBACK")
                return False
            if status == "signed":
                same = isinstance(old_signature, bytes) and secrets.compare_digest(old_signature, signature)
                connection.execute("COMMIT" if same else "ROLLBACK")
                return same
            if status != "pending":
                connection.execute("ROLLBACK")
                return False
            public_key = serialization.load_der_public_key(spki_b64)
            if isinstance(public_key, ec.EllipticCurvePublicKey) and public_key.curve.name == "secp256r1":
                if len(digest) != 32 or not 64 <= len(signature) <= 72:
                    connection.execute("ROLLBACK")
                    return False
                public_key.verify(signature, digest, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
            elif isinstance(public_key, rsa.RSAPublicKey) and public_key.key_size == 2048:
                parsed = _rsa_digest_info(digest)
                if parsed is None or len(signature) != 256:
                    connection.execute("ROLLBACK")
                    return False
                _name, raw_digest, hash_algorithm = parsed
                public_key.verify(
                    signature, raw_digest, padding.PKCS1v15(), utils.Prehashed(hash_algorithm),
                )
            else:
                connection.execute("ROLLBACK")
                return False
            cursor = connection.execute(
                "UPDATE piv_sign_requests SET status='signed',signature=?,credential_id=? "
                "WHERE sign_request_id=? AND status='pending' AND expires_at>=?",
                (signature, credential_id, sign_request_id, current),
            )
            if cursor.rowcount != 1:
                connection.execute("ROLLBACK")
                return False
            if pending_login:
                approval = connection.execute(
                    "UPDATE login_challenges SET status='approve', credential_id=?, response_at=? "
                    "WHERE request_id=? AND status='pending' AND piv_signing=1 AND expires_at>? "
                    "AND credential_id IS NULL AND response_at IS NULL AND delivered_at IS NULL",
                    (credential_id, current, request_id, current),
                )
                if approval.rowcount != 1:
                    connection.execute("ROLLBACK")
                    return False
            connection.execute("COMMIT")
            return True
        except (sqlite3.Error, InvalidSignature, ValueError, TypeError, binascii.Error):
            try:
                connection.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            return False
        finally:
            connection.close()

    def result_for_machine(self, *, machine_id: str, request_id: str,
                           sign_request_id: str, now: float | None = None) -> dict | None:
        current = self._now(now)
        if (current is None or not isinstance(machine_id, str) or not _MACHINE.fullmatch(machine_id)
                or not isinstance(request_id, str) or not _TOKEN.fullmatch(request_id)
                or not isinstance(sign_request_id, str) or not _TOKEN.fullmatch(sign_request_id)):
            return None
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT p.signature,p.expires_at,p.status,p.principal_id,p.credential_id,"
                "p.ad_logon_key_sha256,l.status,l.credential_id,l.response_at,l.delivered_at,l.piv_signing "
                "FROM piv_sign_requests p JOIN login_challenges l ON l.request_id=p.request_id "
                "WHERE p.machine_id=? AND p.request_id=? AND p.sign_request_id=?",
                (machine_id, request_id, sign_request_id),
            ).fetchone()
            if row is None:
                connection.execute("ROLLBACK")
                return None
            (signature, expires_at, status, principal_id, credential_id, key_hash,
             login_status, login_credential, response_at, delivered_at, piv_signing) = row
            if current > expires_at:
                connection.execute("COMMIT")
                return {"status": "expired"}
            if login_status == "pending" and status == "pending":
                connection.execute("COMMIT")
                return {"status": "pending"}
            if (login_status != "approve" or login_credential != credential_id or piv_signing != 1
                    or not isinstance(response_at, (int, float))
                    or current < response_at or current > response_at + LOGIN_SIGNATURE_WINDOW_SECONDS
                    or self._active_key(connection, principal_id, key_hash, credential_id) is None):
                connection.execute("ROLLBACK")
                return None
            if status == "delivered":
                connection.execute("COMMIT")
                return {"status": "consumed"}
            if status != "signed" or not isinstance(signature, bytes):
                connection.execute("COMMIT")
                return {"status": "pending"}
            cursor = connection.execute(
                "UPDATE piv_sign_requests SET status='delivered' "
                "WHERE sign_request_id=? AND machine_id=? AND status='signed' AND expires_at>=?",
                (sign_request_id, machine_id, current),
            )
            if cursor.rowcount != 1:
                connection.execute("ROLLBACK")
                return {"status": "consumed"}
            connection.execute("COMMIT")
            return {"status": "signed", "signature_b64": base64.b64encode(signature).decode("ascii")}
        except sqlite3.Error:
            try:
                connection.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            return None
        finally:
            connection.close()
