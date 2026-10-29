"""Persistent, one-use state for SID-bound Windows sign-in requests."""

from __future__ import annotations

import hashlib
import math
import os
import re
import secrets
import sqlite3
import time
from pathlib import Path
from typing import Callable
from .state_permissions import finish_private_sqlite, prepare_private_sqlite

from .protocol import (
    canonical_certificate_approval_message,
    canonical_phone_message,
    principal_id_from_sid,
    timestamp_is_fresh,
    verify_phone_signature,
)

_MACHINE_ID = re.compile(r"^[a-f0-9]{32}$")
_PRINCIPAL_ID = re.compile(r"^[a-f0-9]{64}$")
_CREDENTIAL_ID = re.compile(r"^[A-Za-z0-9_-]{8,128}$")
_CERTIFICATE_SHA256 = re.compile(r"^[a-f0-9]{64}$")
_CERTIFICATE_TEMPLATE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
CERTIFICATE_ISSUANCE_RETENTION_SECONDS = 24 * 60 * 60
_CERTIFICATE_UPLOAD_RETENTION_SECONDS = 10 * 60


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
        prepare_private_sqlite(self.path, description="AD challenge database")

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
                       principal_sid TEXT,
                       principal_type TEXT NOT NULL,
                       authority TEXT NOT NULL,
                       username TEXT NOT NULL,
                       context TEXT NOT NULL,
                       nonce TEXT NOT NULL UNIQUE,
                       created_at REAL NOT NULL,
                       expires_at REAL NOT NULL,
                       status TEXT NOT NULL,
                       credential_id TEXT,
                       certificate_request_sha256 TEXT,
                       certificate_template TEXT,
                       certificate_request_der BLOB,
                       certificate_request_received_at REAL,
                       certificate_issuance_claimed_at REAL,
                       certificate_issued_der BLOB,
                       certificate_issued_sha256 TEXT,
                       certificate_issued_at REAL,
                       response_at REAL,
                       delivered_at REAL
                   ) WITHOUT ROWID"""
            )
            columns = {row[1] for row in connection.execute("PRAGMA table_info(login_challenges)")}
            if "principal_sid" not in columns:
                connection.execute("ALTER TABLE login_challenges ADD COLUMN principal_sid TEXT")
            if "certificate_request_sha256" not in columns:
                connection.execute("ALTER TABLE login_challenges ADD COLUMN certificate_request_sha256 TEXT")
            if "certificate_template" not in columns:
                connection.execute("ALTER TABLE login_challenges ADD COLUMN certificate_template TEXT")
            if "certificate_request_der" not in columns:
                connection.execute("ALTER TABLE login_challenges ADD COLUMN certificate_request_der BLOB")
            if "certificate_request_received_at" not in columns:
                connection.execute("ALTER TABLE login_challenges ADD COLUMN certificate_request_received_at REAL")
            if "certificate_issuance_claimed_at" not in columns:
                connection.execute("ALTER TABLE login_challenges ADD COLUMN certificate_issuance_claimed_at REAL")
            if "certificate_issued_der" not in columns:
                connection.execute("ALTER TABLE login_challenges ADD COLUMN certificate_issued_der BLOB")
            if "certificate_issued_sha256" not in columns:
                connection.execute("ALTER TABLE login_challenges ADD COLUMN certificate_issued_sha256 TEXT")
            if "certificate_issued_at" not in columns:
                connection.execute("ALTER TABLE login_challenges ADD COLUMN certificate_issued_at REAL")
            connection.execute(
                "CREATE INDEX IF NOT EXISTS login_challenges_expiry ON login_challenges(expires_at)"
            )
        finally:
            connection.close()
        finish_private_sqlite(self.path)

    def purge_expired(self, *, now: float | None = None) -> int:
        """Remove expired challenges and retained CSR blobs; return removed rows."""
        current = time.time() if now is None else now
        if (isinstance(current, bool) or not isinstance(current, (int, float))
                or not math.isfinite(current)):
            raise ValueError("invalid cleanup time")
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            cursor = connection.execute(
                "DELETE FROM login_challenges WHERE "
                "(certificate_request_der IS NULL AND expires_at <= ?) OR "
                "(certificate_request_der IS NOT NULL AND certificate_request_received_at IS NOT NULL AND ("
                "(certificate_issuance_claimed_at IS NULL AND certificate_request_received_at <= ?) OR "
                "(certificate_issuance_claimed_at IS NOT NULL AND certificate_issuance_claimed_at <= ?)))",
                (current, current - _CERTIFICATE_UPLOAD_RETENTION_SECONDS,
                 current - CERTIFICATE_ISSUANCE_RETENTION_SECONDS),
            )
            connection.execute("COMMIT")
            return cursor.rowcount
        except sqlite3.Error as exc:
            try:
                connection.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise RuntimeError("Could not purge expired AD challenges") from exc
        finally:
            connection.close()

    def create(self, *, machine_id: str, sid: str, username: str, authority: str,
               context: str, lifetime_seconds: int = 90, now: float | None = None,
               certificate_request_sha256: str | None = None,
               certificate_template: str | None = None) -> dict:
        if not isinstance(machine_id, str) or not _MACHINE_ID.fullmatch(machine_id):
            raise ValueError("invalid machine id")
        if isinstance(lifetime_seconds, bool) or not isinstance(lifetime_seconds, int) or not 30 <= lifetime_seconds <= 180:
            raise ValueError("challenge lifetime must be between 30 and 180 seconds")
        current = time.time() if now is None else now
        principal_id = principal_id_from_sid(sid)
        if (certificate_request_sha256 is None) != (certificate_template is None):
            raise ValueError("certificate digest and template must be supplied together")
        if certificate_request_sha256 is not None:
            if (not isinstance(certificate_request_sha256, str)
                    or not isinstance(certificate_template, str)
                    or not _CERTIFICATE_SHA256.fullmatch(certificate_request_sha256)
                    or not _CERTIFICATE_TEMPLATE.fullmatch(certificate_template)
                    or context != "interactive"):
                raise ValueError("invalid certificate sign-in request")
        request_id = secrets.token_urlsafe(24)
        nonce = secrets.token_urlsafe(24)
        expires = current + lifetime_seconds
        # Run protocol-level field validation before creating durable state.
        if certificate_request_sha256 is None:
            canonical_phone_message(
                type_="login", request_id=request_id, machine_id=machine_id,
                principal_id=principal_id, principal_type="domain", authority=authority,
                username=username, context=context, nonce=nonce, timestamp=int(current), action="approve",
            )
        else:
            canonical_certificate_approval_message(
                request_id=request_id, machine_id=machine_id, principal_id=principal_id,
                principal_type="domain", authority=authority, username=username,
                context=context, nonce=nonce, expires_at=int(expires),
                certificate_request_sha256=certificate_request_sha256,
                certificate_template=str(certificate_template), timestamp=int(current), action="approve",
            )
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                "DELETE FROM login_challenges WHERE "
                "(certificate_request_der IS NULL AND expires_at <= ?) OR "
                "(certificate_request_der IS NOT NULL AND certificate_request_received_at IS NOT NULL AND ("
                "(certificate_issuance_claimed_at IS NULL AND certificate_request_received_at <= ?) OR "
                "(certificate_issuance_claimed_at IS NOT NULL AND certificate_issuance_claimed_at <= ?)))",
                (current, current - _CERTIFICATE_UPLOAD_RETENTION_SECONDS,
                 current - CERTIFICATE_ISSUANCE_RETENTION_SECONDS),
            )
            connection.execute(
                """INSERT INTO login_challenges
                   (request_id, machine_id, principal_id, principal_sid, principal_type, authority, username,
                    context, nonce, created_at, expires_at, status,
                    certificate_request_sha256, certificate_template)
                   VALUES (?, ?, ?, ?, 'domain', ?, ?, ?, ?, ?, ?, 'pending', ?, ?)""",
                (request_id, machine_id, principal_id,
                 sid if certificate_request_sha256 is not None else None,
                 authority, username, context, nonce, current, expires,
                 certificate_request_sha256, certificate_template),
            )
            connection.execute("COMMIT")
            request = {
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
            if certificate_request_sha256 is not None:
                request.update({
                    "certificate_request_sha256": certificate_request_sha256,
                    "certificate_template": certificate_template,
                })
            return request
        except sqlite3.Error as exc:
            try:
                connection.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise RuntimeError("Could not create login challenge") from exc
        finally:
            connection.close()

    def claim_certificate_issuance(self, *, machine_id: str, request_id: str,
                                   now: float | None = None) -> dict | None:
        """Atomically hand one approved CSR to the trusted issuer process.

        This is an internal store operation, not an HTTP route. It returns the
        original AD SID and requester identity only for a delivered approval,
        after the machine uploaded the exact CSR bound to that approval. A
        claim is one-use; recovery after a crash must start a fresh sign-in.
        """
        if (not isinstance(machine_id, str) or not _MACHINE_ID.fullmatch(machine_id)
                or not isinstance(request_id, str) or not re.fullmatch(r"[A-Za-z0-9_-]{8,128}", request_id)):
            return None
        current = time.time() if now is None else now
        if (isinstance(current, bool) or not isinstance(current, (int, float))
                or not math.isfinite(current)):
            return None
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT principal_id, principal_sid, authority, username, context, status, delivered_at, response_at, "
                "certificate_request_sha256, certificate_template, certificate_request_der, "
                "certificate_request_received_at, certificate_issuance_claimed_at "
                "FROM login_challenges WHERE request_id = ? AND machine_id = ?",
                (request_id, machine_id),
            ).fetchone()
            if row is None:
                connection.execute("ROLLBACK")
                return None
            (principal_id, sid, authority, username, context, status, delivered_at, response_at, expected_digest,
             template, csr_der, csr_received_at, claimed_at) = row
            if (not isinstance(sid, str) or not re.fullmatch(r"S-1-(?:[0-9]+-)+[0-9]+", sid)
                    or not isinstance(principal_id, str) or not _PRINCIPAL_ID.fullmatch(principal_id)
                    or not secrets.compare_digest(principal_id_from_sid(sid), principal_id)
                    or not isinstance(authority, str) or not re.fullmatch(r"[A-Za-z0-9_.@-]{1,128}", authority)
                    or not isinstance(username, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", username)
                    or context != "interactive" or status != "approve" or delivered_at is None
                    or not isinstance(response_at, (int, float)) or current > response_at + 180
                    or not isinstance(expected_digest, str) or not _CERTIFICATE_SHA256.fullmatch(expected_digest)
                    or not isinstance(template, str) or not _CERTIFICATE_TEMPLATE.fullmatch(template)
                    or not isinstance(csr_der, bytes) or not 256 <= len(csr_der) <= 32 * 1024
                    or not isinstance(csr_received_at, (int, float)) or current > csr_received_at + 600
                    or claimed_at is not None):
                connection.execute("ROLLBACK")
                return None
            from .certificate_requests import validate_approved_csr

            metadata = validate_approved_csr(csr_der, expected_digest)
            cursor = connection.execute(
                "UPDATE login_challenges SET certificate_issuance_claimed_at = ? "
                "WHERE request_id = ? AND machine_id = ? AND certificate_issuance_claimed_at IS NULL",
                (current, request_id, machine_id),
            )
            if cursor.rowcount != 1:
                connection.execute("ROLLBACK")
                return None
            connection.execute("COMMIT")
            return {
                "request_id": request_id,
                "machine_id": machine_id,
                "sid": sid,
                "requester_name": f"{authority}\\{username}",
                "certificate_template": template,
                "certificate_request_sha256": expected_digest,
                "certificate_request_der": csr_der,
                "public_key_spki_sha256": metadata["public_key_spki_sha256"],
                "claimed_at": current,
            }
        except (sqlite3.Error, TypeError, ValueError):
            try:
                connection.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            return None
        finally:
            connection.close()

    def complete_certificate_issuance(self, *, machine_id: str, request_id: str,
                                      certificate_der: bytes, expected_template_name: str,
                                      expected_template_oid: str,
                                      issuer_certificate_der: bytes, expected_issuer_sha256: str,
                                      now: float | None = None) -> dict | None:
        """Store one CA response after it matches the claimed CSR and AD SID.

        This internal operation is intentionally separate from CA submission
        and certificate delivery. The caller supplies only pinned issuer policy
        from protected service configuration. No HTTP route calls this yet.
        """
        if (not isinstance(machine_id, str) or not _MACHINE_ID.fullmatch(machine_id)
                or not isinstance(request_id, str) or not re.fullmatch(r"[A-Za-z0-9_-]{8,128}", request_id)
                or not isinstance(certificate_der, bytes) or not 256 <= len(certificate_der) <= 64 * 1024
                or not isinstance(issuer_certificate_der, bytes)
                or not 256 <= len(issuer_certificate_der) <= 64 * 1024
                or not isinstance(expected_template_name, str)
                or not _CERTIFICATE_TEMPLATE.fullmatch(expected_template_name)
                or not isinstance(expected_template_oid, str)
                or not re.fullmatch(r"[0-2](?:\.[0-9]+)+", expected_template_oid)
                or not isinstance(expected_issuer_sha256, str)
                or not _CERTIFICATE_SHA256.fullmatch(expected_issuer_sha256)):
            return None
        current = time.time() if now is None else now
        if (isinstance(current, bool) or not isinstance(current, (int, float))
                or not math.isfinite(current)):
            return None
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT principal_sid, certificate_request_sha256, certificate_template, "
                "certificate_request_der, certificate_request_received_at, certificate_issuance_claimed_at, "
                "certificate_issued_der FROM login_challenges "
                "WHERE request_id = ? AND machine_id = ? AND status = 'approve' AND delivered_at IS NOT NULL",
                (request_id, machine_id),
            ).fetchone()
            if row is None:
                connection.execute("ROLLBACK")
                return None
            sid, csr_sha256, template, csr_der, csr_received_at, claimed_at, existing_certificate = row
            if (not isinstance(sid, str) or not isinstance(csr_sha256, str)
                    or not isinstance(template, str) or not isinstance(csr_der, bytes)
                    or not isinstance(csr_received_at, (int, float))
                    or not isinstance(claimed_at, (int, float))
                    or not math.isfinite(claimed_at)
                    or current > claimed_at + CERTIFICATE_ISSUANCE_RETENTION_SECONDS
                    or existing_certificate is not None):
                connection.execute("ROLLBACK")
                return None
            if template != expected_template_name:
                connection.execute("ROLLBACK")
                return None
            from .issued_certificates import IssuedCertificateError, validate_issued_certificate

            try:
                metadata = validate_issued_certificate(
                    certificate_der=certificate_der,
                    csr_der=csr_der,
                    approved_csr_sha256=csr_sha256,
                    expected_sid=sid,
                    expected_template_oid=expected_template_oid,
                    issuer_certificate_der=issuer_certificate_der,
                    expected_issuer_sha256=expected_issuer_sha256,
                    now=None,
                )
            except IssuedCertificateError:
                connection.execute("ROLLBACK")
                return None
            cursor = connection.execute(
                "UPDATE login_challenges SET certificate_issued_der = ?, certificate_issued_sha256 = ?, "
                "certificate_issued_at = ? WHERE request_id = ? AND machine_id = ? "
                "AND certificate_issuance_claimed_at IS NOT NULL AND certificate_issued_der IS NULL",
                (certificate_der, metadata["certificate_sha256"], current, request_id, machine_id),
            )
            if cursor.rowcount != 1:
                connection.execute("ROLLBACK")
                return None
            connection.execute("COMMIT")
            return {key: metadata[key] for key in (
                "certificate_sha256", "issuer_sha256", "csr_sha256", "public_key_spki_sha256",
                "sid", "template_oid", "serial_number",
            )}
        except sqlite3.Error:
            try:
                connection.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            return None
        finally:
            connection.close()

    def get_issued_certificate(self, *, machine_id: str, request_id: str,
                               now: float | None = None) -> dict | None:
        """Return a validated certificate only to its originating machine.

        Reads are retry-safe: a dropped HTTPS response does not consume the
        result. The challenge and certificate remain available only until the
        bounded issuer-job expiry recorded when the one-use claim is made.
        """
        if (not isinstance(machine_id, str) or not _MACHINE_ID.fullmatch(machine_id)
                or not isinstance(request_id, str) or not re.fullmatch(r"[A-Za-z0-9_-]{8,128}", request_id)):
            return None
        current = time.time() if now is None else now
        if (isinstance(current, bool) or not isinstance(current, (int, float))
                or not math.isfinite(current)):
            return None
        connection = self._connect()
        try:
            row = connection.execute(
                "SELECT certificate_issuance_claimed_at, certificate_issued_der, "
                "certificate_issued_sha256, certificate_issued_at FROM login_challenges "
                "WHERE request_id = ? AND machine_id = ? AND status = 'approve' AND delivered_at IS NOT NULL",
                (request_id, machine_id),
            ).fetchone()
            if row is None:
                return None
            claimed_at, certificate_der, certificate_sha256, issued_at = row
            if (not isinstance(claimed_at, (int, float)) or not math.isfinite(claimed_at)
                    or current > claimed_at + CERTIFICATE_ISSUANCE_RETENTION_SECONDS
                    or not isinstance(certificate_der, bytes) or not 256 <= len(certificate_der) <= 64 * 1024
                    or not isinstance(certificate_sha256, str) or not _CERTIFICATE_SHA256.fullmatch(certificate_sha256)
                    or not isinstance(issued_at, (int, float))
                    or not secrets.compare_digest(hashlib.sha256(certificate_der).hexdigest(), certificate_sha256)):
                return None
            return {
                "request_id": request_id,
                "certificate_der": certificate_der,
                "certificate_sha256": certificate_sha256,
                "issued_at": issued_at,
            }
        except sqlite3.Error:
            return None
        finally:
            connection.close()

    def respond(self, *, request_id: str, credential_id: str, action: str, timestamp: int,
                signature_b64: str | None, nonce: str | None = None, now: float | None = None) -> bool:
        if not isinstance(request_id, str) or not re.fullmatch(r"[A-Za-z0-9_-]{8,128}", request_id):
            return False
        if not isinstance(credential_id, str) or not _CREDENTIAL_ID.fullmatch(credential_id):
            return False
        if action not in ("approve", "deny") or not timestamp_is_fresh(timestamp, now):
            return False
        if action == "approve" and (not isinstance(signature_b64, str) or nonce is not None):
            return False
        if action == "deny" and not (
            (isinstance(signature_b64, str) and nonce is None)
            or (signature_b64 is None and isinstance(nonce, str))
        ):
            return False

        connection = self._connect()
        try:
            row = connection.execute(
                "SELECT machine_id, principal_id, principal_type, authority, username, context, nonce, expires_at, status, "
                "certificate_request_sha256, certificate_template "
                "FROM login_challenges WHERE request_id = ?",
                (request_id,),
            ).fetchone()
            if row is None:
                return False
            (machine_id, principal_id, principal_type, authority, username, context, challenge_nonce,
             expires_at, status, certificate_request_sha256, certificate_template) = row
            current = time.time() if now is None else now
            if status != "pending" or expires_at <= current:
                return False
            public_key = self.public_key_lookup(credential_id, machine_id, principal_id)
            if not public_key:
                return False
            if action == "deny" and signature_b64 is None:
                if not isinstance(nonce, str) or not secrets.compare_digest(nonce, challenge_nonce):
                    return False
            else:
                try:
                    if certificate_request_sha256 is None:
                        message = canonical_phone_message(
                            type_="login", request_id=request_id, machine_id=machine_id,
                            principal_id=principal_id, principal_type=principal_type, authority=authority,
                            username=username, context=context, nonce=challenge_nonce,
                            timestamp=timestamp, action=action,
                        )
                    else:
                        message = canonical_certificate_approval_message(
                            request_id=request_id, machine_id=machine_id, principal_id=principal_id,
                            principal_type=principal_type, authority=authority, username=username,
                            context=context, nonce=challenge_nonce, expires_at=int(expires_at),
                            certificate_request_sha256=certificate_request_sha256,
                            certificate_template=certificate_template, timestamp=timestamp, action=action,
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
                "SELECT status, expires_at, delivered_at, credential_id, "
                "certificate_request_sha256, certificate_template FROM login_challenges "
                "WHERE request_id = ? AND machine_id = ?",
                (request_id, machine_id),
            ).fetchone()
            if row is None:
                connection.execute("COMMIT")
                return None
            status, expires_at, delivered_at, credential_id, certificate_request_sha256, certificate_template = row
            if status == "pending" and expires_at <= current:
                connection.execute(
                    "UPDATE login_challenges SET status = 'expired' WHERE request_id = ? AND status = 'pending'",
                    (request_id,),
                )
                status = "expired"
            if status in ("approve", "deny"):
                if delivered_at is not None:
                    connection.execute("COMMIT")
                    if status == "approve" and certificate_request_sha256 is not None:
                        return {
                            "status": "approved",
                            "certificate_request_sha256": certificate_request_sha256,
                            "certificate_template": certificate_template,
                        }
                    return {"status": "consumed"}
                connection.execute(
                    "UPDATE login_challenges SET delivered_at = ? WHERE request_id = ? AND delivered_at IS NULL",
                    (current, request_id),
                )
                connection.execute("COMMIT")
                if status == "approve":
                    result = {"status": "approved", "credential_id": credential_id}
                    if certificate_request_sha256 is not None:
                        result.update({
                            "certificate_request_sha256": certificate_request_sha256,
                            "certificate_template": certificate_template,
                        })
                    return result
                return {"status": "denied"}
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

    def accept_certificate_request(self, *, machine_id: str, request_id: str, der: bytes,
                                   now: float | None = None) -> dict | None:
        """Store one exact CSR only after its phone approval was delivered.

        The caller must authenticate the enrolled machine. This operation only
        validates and retains the public CSR; it never contacts AD CS. The
        service purges expired CSR rows during its periodic state cleanup.
        """
        if (not isinstance(machine_id, str) or not _MACHINE_ID.fullmatch(machine_id)
                or not isinstance(request_id, str) or not re.fullmatch(r"[A-Za-z0-9_-]{8,128}", request_id)
                or not isinstance(der, bytes) or not 256 <= len(der) <= 32 * 1024):
            return None
        current = time.time() if now is None else now
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT certificate_request_sha256, certificate_template, status, delivered_at, response_at, "
                "certificate_request_der FROM login_challenges WHERE request_id = ? AND machine_id = ?",
                (request_id, machine_id),
            ).fetchone()
            if row is None:
                connection.execute("ROLLBACK")
                return None
            expected_sha256, template, status, delivered_at, response_at, existing_der = row
            if (not expected_sha256 or not template or status != "approve" or delivered_at is None
                    or not isinstance(response_at, (int, float)) or current > response_at + 180):
                connection.execute("ROLLBACK")
                return None
            from .certificate_requests import validate_approved_csr

            metadata = validate_approved_csr(der, expected_sha256)
            if existing_der is not None:
                connection.execute("ROLLBACK")
                return metadata if secrets.compare_digest(existing_der, der) else None
            cursor = connection.execute(
                "UPDATE login_challenges SET certificate_request_der = ?, certificate_request_received_at = ? "
                "WHERE request_id = ? AND machine_id = ? AND status = 'approve' "
                "AND delivered_at IS NOT NULL AND certificate_request_der IS NULL",
                (der, current, request_id, machine_id),
            )
            connection.execute("COMMIT")
            if cursor.rowcount != 1:
                return None
            return {**metadata, "certificate_template": template}
        except sqlite3.Error:
            try:
                connection.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            return None
        finally:
            connection.close()
