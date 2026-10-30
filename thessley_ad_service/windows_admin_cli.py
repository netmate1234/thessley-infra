"""Elevated local administration for the Windows-hosted AD API."""

from __future__ import annotations

import argparse
import base64
import hashlib
import ctypes
import hmac
import json
import math
import os
import re
import stat
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(os.environ.get("PROGRAMDATA", r"C:\ProgramData")) / "ThessleyAD"
STATE_DB = ROOT / "state.sqlite3"
ISSUANCE_ROOT = ROOT / "certificate-issuance"
_REQUEST_ID = re.compile(r"^[A-Za-z0-9_-]{8,128}$")
_MACHINE_ID = re.compile(r"^[a-f0-9]{32}$")
_SID = re.compile(r"^S-1-(?:[0-9]+-)+[0-9]+$")
_SHA256 = re.compile(r"^[a-f0-9]{64}$")


def _protect_issuance_path(path: Path, *, directory: bool) -> None:
    """Restrict a manually exported issuer artifact to SYSTEM and Administrators."""
    grants = ("*S-1-5-18:(OI)(CI)F", "*S-1-5-32-544:(OI)(CI)F") if directory else (
        "*S-1-5-18:F", "*S-1-5-32-544:F",
    )
    try:
        result = subprocess.run(
            ["icacls.exe", str(path), "/inheritance:r", "/grant:r", *grants,
             "/setowner", "*S-1-5-18"],
            capture_output=True, text=True, errors="replace", timeout=15, check=False,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise RuntimeError("Could not secure the certificate issuance artifact") from exc
    if result.returncode:
        raise RuntimeError("Could not secure the certificate issuance artifact")


def _write_new_private_file(path: Path, data: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    descriptor = os.open(path, flags, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            descriptor = -1
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        if descriptor >= 0:
            os.close(descriptor)
        raise
    _protect_issuance_path(path, directory=False)


def _read_bounded(path: str | os.PathLike[str], maximum: int) -> bytes:
    with open(path, "rb") as stream:
        data = stream.read(maximum + 1)
    if not data or len(data) > maximum:
        raise ValueError("file is empty or exceeds its size limit")
    return data


def _certificate_claim(machine_id: str, request_id: str) -> int:
    if not _MACHINE_ID.fullmatch(machine_id) or not _REQUEST_ID.fullmatch(request_id):
        raise ValueError("The machine ID or request ID is malformed.")
    if not ROOT.is_dir() or not STATE_DB.is_file():
        raise RuntimeError("The protected AD service state is unavailable.")
    from .challenges import CERTIFICATE_ISSUANCE_RETENTION_SECONDS, ChallengeStore
    from .phone_registry import PhoneRegistry
    from .ad_logon_keys import AdLogonKeyRegistry
    from .state_permissions import verify_private_windows_paths

    verify_private_windows_paths([ROOT, STATE_DB])
    try:
        ISSUANCE_ROOT.mkdir()
    except FileExistsError:
        verify_private_windows_paths([ISSUANCE_ROOT])
    else:
        _protect_issuance_path(ISSUANCE_ROOT, directory=True)
        verify_private_windows_paths([ISSUANCE_ROOT])
    job_dir = ISSUANCE_ROOT / request_id
    try:
        job_dir.mkdir()
    except FileExistsError as exc:
        raise RuntimeError("An issuer job already exists for this request ID.") from exc
    try:
        _protect_issuance_path(job_dir, directory=True)
        verify_private_windows_paths([job_dir])
    except Exception:
        try:
            job_dir.rmdir()
        except OSError:
            pass
        raise

    claimed = None
    try:
        phones = PhoneRegistry(STATE_DB)
        ad_logon_keys = AdLogonKeyRegistry(STATE_DB)
        challenges = ChallengeStore(
            STATE_DB, phones.public_key_for, ad_logon_keys.active_key_matches_public_key,
        )
        claimed = challenges.claim_certificate_issuance(machine_id=machine_id, request_id=request_id)
        if claimed is None:
            raise RuntimeError("No unclaimed, delivered, approved certificate request is available.")
        csr_der = claimed["certificate_request_der"]
        if not isinstance(csr_der, bytes) or not 128 <= len(csr_der) <= 32 * 1024:
            raise RuntimeError("The approved certificate request is unavailable or malformed.")
        csr_path = job_dir / "request.csr.der"
        job = {
            "version": 1,
            "request_id": request_id,
            "machine_id": machine_id,
            "sid": claimed["sid"],
            "requester_name": claimed["requester_name"],
            "certificate_template": claimed["certificate_template"],
            "certificate_request_sha256": claimed["certificate_request_sha256"],
            "public_key_spki_sha256": claimed["public_key_spki_sha256"],
            "claimed_at": claimed["claimed_at"],
            "expires_at": claimed["claimed_at"] + CERTIFICATE_ISSUANCE_RETENTION_SECONDS,
            "csr_path": str(csr_path),
            "csr_der_b64": base64.b64encode(csr_der).decode("ascii"),
        }
        job_path = job_dir / "issuer-job.json"
        _write_new_private_file(
            job_path, (json.dumps(job, separators=(",", ":"), ensure_ascii=True) + "\n").encode("ascii"),
        )
        _write_new_private_file(csr_path, csr_der)
        verify_private_windows_paths([job_path, csr_path])
        print(json.dumps({
            "status": "one_use_issuer_job_claimed",
            "request_id": request_id,
            "machine_id": machine_id,
            "requester_name": claimed["requester_name"],
            "certificate_template": claimed["certificate_template"],
            "certificate_request_sha256": claimed["certificate_request_sha256"],
            "expires_at": job["expires_at"],
            "job_json": str(job_path),
            "csr_der": str(csr_path),
            "claim_replayable": False,
        }, separators=(",", ":")), flush=True)
        return 0
    except Exception:
        # The claim is intentionally one-use. Preserve any protected artifact
        # already written so an operator can inspect/recover it; never replay.
        if claimed is None:
            try:
                job_dir.rmdir()
            except OSError:
                pass
        raise


def _certificate_import(machine_id: str, request_id: str, certificate_path: str,
                        issuer_certificate_path: str, expected_issuer_sha256: str,
                        expected_template_oid: str) -> int:
    if not _MACHINE_ID.fullmatch(machine_id) or not _REQUEST_ID.fullmatch(request_id):
        raise ValueError("The machine ID or request ID is malformed.")
    if not _SHA256.fullmatch(expected_issuer_sha256):
        raise ValueError("The expected issuer SHA-256 must be 64 lowercase hexadecimal characters.")
    if not re.fullmatch(r"[0-2](?:\.[0-9]+)+", expected_template_oid):
        raise ValueError("The expected certificate template OID is malformed.")
    from .state_permissions import verify_private_windows_paths
    from .challenges import CERTIFICATE_ISSUANCE_RETENTION_SECONDS, ChallengeStore
    from .phone_registry import PhoneRegistry
    from cryptography.exceptions import UnsupportedAlgorithm
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization

    job_dir = ISSUANCE_ROOT / request_id
    job_path = job_dir / "issuer-job.json"
    csr_path = job_dir / "request.csr.der"
    verify_private_windows_paths([ROOT, STATE_DB, ISSUANCE_ROOT, job_dir, job_path, csr_path])
    try:
        job_bytes = _read_bounded(job_path, 64 * 1024)
        job = json.loads(job_bytes.decode("ascii"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise RuntimeError("The protected issuer job is unreadable or malformed.") from exc
    fields = {
        "version", "request_id", "machine_id", "sid", "requester_name",
        "certificate_template", "certificate_request_sha256", "public_key_spki_sha256",
        "claimed_at", "expires_at", "csr_path", "csr_der_b64",
    }
    job_fields = set(job) if isinstance(job, dict) else set()
    has_ca_request = {"ca_config", "ca_request_id"}.issubset(job_fields)
    if (not isinstance(job, dict) or job_fields not in (fields, fields | {"ca_config", "ca_request_id"})
            or isinstance(job.get("version"), bool) or job.get("version") != 1
            or job.get("request_id") != request_id or job.get("machine_id") != machine_id
            or not isinstance(job.get("sid"), str) or not _SID.fullmatch(job["sid"])
            or not isinstance(job.get("certificate_request_sha256"), str)
            or not _SHA256.fullmatch(job["certificate_request_sha256"])
            or not isinstance(job.get("public_key_spki_sha256"), str)
            or not _SHA256.fullmatch(job["public_key_spki_sha256"])
            or not isinstance(job.get("certificate_template"), str)
            or not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", job["certificate_template"])
            or not isinstance(job.get("requester_name"), str)
            or not re.fullmatch(r"[A-Za-z0-9_.@-]{1,128}\\[A-Za-z0-9_.-]{1,64}", job["requester_name"])
            or isinstance(job.get("claimed_at"), bool)
            or not isinstance(job.get("claimed_at"), (int, float))
            or not math.isfinite(job["claimed_at"])
            or isinstance(job.get("expires_at"), bool)
            or not isinstance(job.get("expires_at"), (int, float))
            or not math.isfinite(job["expires_at"])
            or job["expires_at"] != job["claimed_at"] + CERTIFICATE_ISSUANCE_RETENTION_SECONDS
            or time.time() > job["expires_at"]
            or (has_ca_request and (
                not isinstance(job.get("ca_config"), str)
                or not re.fullmatch(r"[A-Za-z0-9.-]{1,253}\\[A-Za-z0-9_. -]{1,64}", job["ca_config"])
                or isinstance(job.get("ca_request_id"), bool)
                or not isinstance(job.get("ca_request_id"), int)
                or not 1 <= job["ca_request_id"] <= 2**31 - 1
            ))
            or job.get("csr_path") != str(job_dir / "request.csr.der")
            or not isinstance(job.get("csr_der_b64"), str)):
        raise RuntimeError("The protected issuer job fields are invalid.")
    try:
        csr_der = base64.b64decode(job["csr_der_b64"].encode("ascii"), validate=True)
        if (not 128 <= len(csr_der) <= 32 * 1024
                or base64.b64encode(csr_der).decode("ascii") != job["csr_der_b64"]
                or not hmac.compare_digest(hashlib.sha256(csr_der).hexdigest(),
                                           job["certificate_request_sha256"])):
            raise ValueError
        from .certificate_requests import validate_approved_csr
        csr_metadata = validate_approved_csr(csr_der, job["certificate_request_sha256"])
        if not hmac.compare_digest(csr_metadata["public_key_spki_sha256"],
                                   job["public_key_spki_sha256"]):
            raise ValueError
        if _read_bounded(csr_path, 32 * 1024) != csr_der:
            raise ValueError
        certificate_data = _read_bounded(certificate_path, 128 * 1024)
        issuer_data = _read_bounded(issuer_certificate_path, 128 * 1024)
        certificate = (x509.load_pem_x509_certificate(certificate_data)
                       if certificate_data.lstrip().startswith(b"-----BEGIN CERTIFICATE-----")
                       else x509.load_der_x509_certificate(certificate_data))
        issuer = (x509.load_pem_x509_certificate(issuer_data)
                  if issuer_data.lstrip().startswith(b"-----BEGIN CERTIFICATE-----")
                  else x509.load_der_x509_certificate(issuer_data))
        certificate_der = certificate.public_bytes(serialization.Encoding.DER)
        issuer_der = issuer.public_bytes(serialization.Encoding.DER)
    except (OSError, ValueError, TypeError, UnsupportedAlgorithm) as exc:
        raise RuntimeError("The returned certificate, issuer certificate, or approved CSR is invalid.") from exc

    phones = PhoneRegistry(STATE_DB)
    from .ad_logon_keys import AdLogonKeyRegistry
    ad_logon_keys = AdLogonKeyRegistry(STATE_DB)
    challenges = ChallengeStore(
        STATE_DB, phones.public_key_for, ad_logon_keys.active_key_matches_public_key,
    )
    receipt = challenges.complete_certificate_issuance(
        machine_id=machine_id, request_id=request_id,
        certificate_der=certificate_der,
        expected_template_name=job["certificate_template"],
        expected_template_oid=expected_template_oid,
        issuer_certificate_der=issuer_der,
        expected_issuer_sha256=expected_issuer_sha256,
    )
    if receipt is None:
        raise RuntimeError("The certificate did not match the claimed request and configured issuer policy.")
    try:
        (job_dir / "issued.cer.der").unlink(missing_ok=True)
        (job_dir / "request.csr.der").unlink(missing_ok=True)
        job_path.unlink()
        job_dir.rmdir()
    except OSError:
        print("Warning: certificate stored, but the protected temporary issuer job could not be removed.",
              file=sys.stderr)
    print(json.dumps({
        "status": "issued_certificate_validated_and_stored",
        "request_id": request_id,
        "machine_id": machine_id,
        "certificate_sha256": receipt["certificate_sha256"],
        "certificate_template_oid": receipt["template_oid"],
        "issuer_sha256": receipt["issuer_sha256"],
    }, separators=(",", ":")), flush=True)
    return 0


def _certificate_record_ca_request(machine_id: str, request_id: str,
                                   ca_config: str, ca_request_id: int) -> int:
    from .challenges import CERTIFICATE_ISSUANCE_RETENTION_SECONDS
    from .state_permissions import verify_private_windows_paths

    if not _MACHINE_ID.fullmatch(machine_id) or not _REQUEST_ID.fullmatch(request_id):
        raise ValueError("The Thessley machine ID or request ID is malformed.")
    if (not isinstance(ca_config, str)
            or not re.fullmatch(r"[A-Za-z0-9.-]{1,253}\\[A-Za-z0-9_. -]{1,64}", ca_config)):
        raise ValueError("CAConfig must be a configured CA name in ComputerName\\CAName form.")
    if isinstance(ca_request_id, bool) or not isinstance(ca_request_id, int) or not 1 <= ca_request_id <= 2**31 - 1:
        raise ValueError("The CA request ID must be a positive 32-bit integer.")

    job_dir = ISSUANCE_ROOT / request_id
    job_path = job_dir / "issuer-job.json"
    verify_private_windows_paths([ROOT, STATE_DB, ISSUANCE_ROOT, job_dir, job_path])
    try:
        job = json.loads(_read_bounded(job_path, 64 * 1024).decode("ascii"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise RuntimeError("The protected issuer job is unreadable or malformed.") from exc
    expected_fields = {
        "version", "request_id", "machine_id", "sid", "requester_name",
        "certificate_template", "certificate_request_sha256", "public_key_spki_sha256",
        "claimed_at", "expires_at", "csr_path", "csr_der_b64",
    }
    if (not isinstance(job, dict) or job.get("version") != 1
            or set(job) not in (expected_fields, expected_fields | {"ca_config", "ca_request_id"})
            or job.get("request_id") != request_id or job.get("machine_id") != machine_id
            or not isinstance(job.get("sid"), str) or not _SID.fullmatch(job["sid"])
            or not isinstance(job.get("requester_name"), str)
            or not isinstance(job.get("certificate_template"), str)
            or not _TEMPLATE_NAME.fullmatch(job["certificate_template"])
            or not isinstance(job.get("certificate_request_sha256"), str)
            or not _SHA256.fullmatch(job["certificate_request_sha256"])
            or not isinstance(job.get("public_key_spki_sha256"), str)
            or not _SHA256.fullmatch(job["public_key_spki_sha256"])
            or isinstance(job.get("claimed_at"), bool)
            or not isinstance(job.get("claimed_at"), (int, float))
            or not math.isfinite(job["claimed_at"])
            or isinstance(job.get("expires_at"), bool)
            or not isinstance(job.get("expires_at"), (int, float))
            or not math.isfinite(job["expires_at"])
            or job["expires_at"] != job["claimed_at"] + CERTIFICATE_ISSUANCE_RETENTION_SECONDS
            or job.get("csr_path") != str(job_dir / "request.csr.der")
            or not isinstance(job.get("csr_der_b64"), str)
            or time.time() > job["claimed_at"] + CERTIFICATE_ISSUANCE_RETENTION_SECONDS):
        raise RuntimeError("The protected issuer job is invalid or expired.")
    existing_config = job.get("ca_config")
    existing_id = job.get("ca_request_id")
    if (existing_config is not None or existing_id is not None) and (
            existing_config != ca_config or existing_id != ca_request_id):
        raise RuntimeError("A different CA request is already recorded for this Thessley request.")
    job["ca_config"] = ca_config
    job["ca_request_id"] = ca_request_id
    temporary_path = job_path.with_name("issuer-job.json.tmp")
    _write_new_private_file(
        temporary_path, (json.dumps(job, separators=(",", ":"), ensure_ascii=True) + "\n").encode("ascii"),
    )
    try:
        os.replace(temporary_path, job_path)
        verify_private_windows_paths([job_path])
    except Exception:
        # Keep a protected temporary copy for recovery; never replace with
        # partially written metadata.
        raise
    print(json.dumps({
        "status": "ca_request_recorded",
        "request_id": request_id,
        "ca_request_id": ca_request_id,
        "ca_config": ca_config,
    }, separators=(",", ":")), flush=True)
    return 0


def _certificate_cleanup(request_id: str | None = None, *, ca_request_closed: bool = False) -> int:
    from .challenges import CERTIFICATE_ISSUANCE_RETENTION_SECONDS
    from .state_permissions import verify_private_windows_paths

    if request_id is not None and not _REQUEST_ID.fullmatch(request_id):
        raise ValueError("The certificate request ID is malformed.")
    if not ISSUANCE_ROOT.exists():
        print("No certificate issuer jobs are present.")
        return 0
    verify_private_windows_paths([ROOT, STATE_DB, ISSUANCE_ROOT])
    if request_id is None:
        directories = sorted(ISSUANCE_ROOT.iterdir(), key=lambda item: item.name)
    else:
        selected = ISSUANCE_ROOT / request_id
        if not selected.exists():
            raise RuntimeError("No issuer job exists for that request ID.")
        directories = [selected]

    removed = 0
    current = time.time()
    for job_dir in directories:
        verify_private_windows_paths([job_dir])
        if not job_dir.is_dir() or not _REQUEST_ID.fullmatch(job_dir.name):
            raise RuntimeError("The issuer job folder is unexpected; nothing in it was removed.")
        job_path = job_dir / "issuer-job.json"
        verify_private_windows_paths([job_path])
        try:
            job = json.loads(_read_bounded(job_path, 64 * 1024).decode("ascii"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
            raise RuntimeError("The issuer job is unreadable; it was not removed.") from exc
        if (not isinstance(job, dict) or isinstance(job.get("version"), bool)
                or job.get("version") != 1
                or job.get("request_id") != job_dir.name
                or not isinstance(job.get("machine_id"), str)
                or not _MACHINE_ID.fullmatch(job["machine_id"])
                or isinstance(job.get("claimed_at"), bool)
                or not isinstance(job.get("claimed_at"), (int, float))
                or not math.isfinite(job["claimed_at"])
                or isinstance(job.get("expires_at"), bool)
                or not isinstance(job.get("expires_at"), (int, float))
                or not math.isfinite(job["expires_at"])
                or job["expires_at"] != job["claimed_at"] + CERTIFICATE_ISSUANCE_RETENTION_SECONDS):
            raise RuntimeError("The issuer job metadata is invalid; it was not removed.")
        has_ca_request = "ca_config" in job or "ca_request_id" in job
        if has_ca_request and (
                not isinstance(job.get("ca_config"), str)
                or not re.fullmatch(r"[A-Za-z0-9.-]{1,253}\\[A-Za-z0-9_. -]{1,64}", job["ca_config"])
                or isinstance(job.get("ca_request_id"), bool)
                or not isinstance(job.get("ca_request_id"), int)
                or not 1 <= job["ca_request_id"] <= 2**31 - 1):
            raise RuntimeError("The issuer job's CA request reference is invalid; it was not removed.")
        if current <= job["expires_at"]:
            continue
        if has_ca_request and not ca_request_closed:
            raise RuntimeError(
                "This job has a CA request ID. Deny the pending request or revoke any issued certificate, "
                "then rerun cleanup with --ca-request-closed."
            )
        allowed_names = {"issuer-job.json", "request.csr.der", "issued.cer.der"}
        entries = list(job_dir.iterdir())
        if any(entry.name not in allowed_names | {"issuer-job.json.tmp"} for entry in entries):
            raise RuntimeError("The expired issuer job contains unexpected files; it was not removed.")
        for entry in entries:
            info = os.stat(entry, follow_symlinks=False)
            if (not stat.S_ISREG(info.st_mode)
                    or getattr(info, "st_file_attributes", 0) & 0x400):
                raise RuntimeError("The expired issuer job contains a non-file entry; it was not removed.")
            _protect_issuance_path(entry, directory=False)
        verify_private_windows_paths(entries)
        for name in allowed_names | {"issuer-job.json.tmp"}:
            (job_dir / name).unlink(missing_ok=True)
        job_dir.rmdir()
        removed += 1
    print(f"Removed {removed} expired certificate issuer job(s).")
    return 0


def _require_admin() -> bool:
    if os.name != "nt":
        return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError):
        return False


def main(argv: list[str] | None = None) -> int:
    if not _require_admin():
        print("Open PowerShell as Administrator to manage the AD API.", file=sys.stderr)
        return 1
    from .machine_registry import MachineRegistry
    from .phone_registry import PhoneRegistry

    parser = argparse.ArgumentParser(prog="thessley-ad-admin")
    commands = parser.add_subparsers(dest="command", required=True)
    issue = commands.add_parser("issue-machine-code", help="issue a one-use code for a domain-joined Windows client")
    issue.add_argument("--lifetime", type=int, default=600)
    revoke_machine = commands.add_parser("revoke-machine", help="revoke a paired Windows client")
    revoke_machine.add_argument("machine_id")
    revoke_phone = commands.add_parser("revoke-phone", help="revoke an Android phone key")
    revoke_phone.add_argument("credential_id")
    certificate_claim = commands.add_parser(
        "certificate-claim",
        help="consume one approved certificate challenge and write a protected issuer job",
    )
    certificate_claim.add_argument("--machine-id", required=True)
    certificate_claim.add_argument("--request-id", required=True)
    certificate_import = commands.add_parser(
        "certificate-import",
        help="validate and store an issued leaf against its claimed job and explicit issuer policy",
    )
    certificate_import.add_argument("--machine-id", required=True)
    certificate_import.add_argument("--request-id", required=True)
    certificate_import.add_argument("--certificate", required=True, help="issued leaf certificate (DER or PEM)")
    certificate_import.add_argument("--issuer-certificate", required=True,
                                    help="pinned direct issuer certificate (DER or PEM)")
    certificate_import.add_argument("--issuer-sha256", required=True,
                                    help="SHA-256 of the issuer's canonical DER certificate")
    certificate_import.add_argument("--template-oid", required=True,
                                    help="expected AD CS certificate template OID")
    certificate_record = commands.add_parser(
        "certificate-record-ca-request", help="attach a CA pending-request ID to its protected issuer job",
    )
    certificate_record.add_argument("--machine-id", required=True)
    certificate_record.add_argument("--request-id", required=True, help="Thessley approval request ID")
    certificate_record.add_argument("--ca-config", required=True, help="CA in ComputerName\\CAName form")
    certificate_record.add_argument("--ca-request-id", required=True, type=int)
    certificate_cleanup = commands.add_parser(
        "certificate-cleanup", help="remove protected issuer jobs after their 24-hour window expires",
    )
    certificate_cleanup.add_argument("--request-id", help="clean one expired issuer job instead of sweeping")
    certificate_cleanup.add_argument(
        "--ca-request-closed", action="store_true",
        help="confirm any recorded CA request was denied or its issued certificate revoked",
    )
    args = parser.parse_args(argv)
    if not STATE_DB.is_file():
        print("The AD API has not created its protected state database yet.", file=sys.stderr)
        return 1
    if args.command == "certificate-claim":
        try:
            return _certificate_claim(args.machine_id, args.request_id)
        except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as exc:
            print(str(exc), file=sys.stderr)
            return 1
    if args.command == "certificate-import":
        try:
            return _certificate_import(
                args.machine_id, args.request_id, args.certificate, args.issuer_certificate,
                args.issuer_sha256, args.template_oid,
            )
        except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as exc:
            print(str(exc), file=sys.stderr)
            return 1
    if args.command == "certificate-record-ca-request":
        try:
            return _certificate_record_ca_request(
                args.machine_id, args.request_id, args.ca_config, args.ca_request_id,
            )
        except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as exc:
            print(str(exc), file=sys.stderr)
            return 1
    if args.command == "certificate-cleanup":
        try:
            return _certificate_cleanup(args.request_id, ca_request_closed=args.ca_request_closed)
        except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as exc:
            print(str(exc), file=sys.stderr)
            return 1
    if args.command == "issue-machine-code":
        try:
            code = MachineRegistry(STATE_DB).create_enrollment_code(lifetime_seconds=args.lifetime)
        except (ValueError, RuntimeError) as exc:
            print(str(exc), file=sys.stderr)
            return 1
        expiry = datetime.fromtimestamp(time.time() + args.lifetime, timezone.utc).isoformat(timespec="seconds")
        print(f"One-use machine pairing code (expires {expiry} UTC):\n{code}")
        return 0
    if args.command == "revoke-machine":
        changed = MachineRegistry(STATE_DB).revoke(args.machine_id)
    else:
        changed = PhoneRegistry(STATE_DB).revoke(args.credential_id)
    print("Revoked." if changed else "No active matching credential was found.")
    return 0 if changed else 1


if __name__ == "__main__":
    raise SystemExit(main())
