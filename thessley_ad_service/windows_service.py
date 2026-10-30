"""Standalone Windows-hosted runtime for the Thessley AD API prototype."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import logging
import os
import re
import signal
import ssl
import sys
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from .https_server import make_server
from .state_permissions import UnsafeState, verify_private_windows_paths

ROOT = Path(os.environ.get("PROGRAMDATA", r"C:\ProgramData")) / "ThessleyAD"
CONFIG_PATH = ROOT / "service.json"
STATE_PATH = ROOT / "state.sqlite3"
CERT_PATH = ROOT / "https-cert.pem"
KEY_PATH = ROOT / "https-key.pem"
LOG_PATH = ROOT / "service.log"
API_PORT = 47810
ADMIN_PORT = 47820


def _read_config() -> dict:
    verify_private_windows_paths([CONFIG_PATH])
    try:
        data = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError("The protected AD service configuration could not be read") from exc
    required = {"version", "bind_address", "public_host", "authority", "allowed_group_sids"}
    if not isinstance(data, dict) or set(data) not in (required, required | {"certificate_template"}):
        raise RuntimeError("Invalid AD service configuration")
    if data["version"] != 1 or isinstance(data["version"], bool):
        raise RuntimeError("Unsupported AD service configuration version")
    try:
        address = ipaddress.ip_address(data["bind_address"])
    except (TypeError, ValueError) as exc:
        raise RuntimeError("The AD service bind address must be an IPv4 address") from exc
    if not isinstance(address, ipaddress.IPv4Address) or address.is_unspecified or address.is_multicast:
        raise RuntimeError("The AD service bind address is invalid")
    if not isinstance(data["public_host"], str) or not re.fullmatch(r"[A-Za-z0-9.-]{1,253}", data["public_host"]):
        raise RuntimeError("The AD service public host is invalid")
    from .directory import validate_group_sid_allowlist
    from .protocol import validate_certificate_template
    from .windows_directory import WindowsDirectoryConfig

    WindowsDirectoryConfig(data["authority"])
    data["allowed_group_sids"] = validate_group_sid_allowlist(data["allowed_group_sids"])
    try:
        data["certificate_template"] = validate_certificate_template(data.get("certificate_template"))
    except ValueError as exc:
        raise RuntimeError("The configured AD CS certificate template is invalid") from exc
    return data


def _ensure_tls_identity(host: str) -> str:
    if not CERT_PATH.exists() and not KEY_PATH.exists():
        private_key = ec.generate_private_key(ec.SECP256R1())
        now = datetime.now(timezone.utc)
        try:
            ip = ipaddress.ip_address(host)
            san = x509.SubjectAlternativeName([x509.IPAddress(ip)])
        except ValueError:
            san = x509.SubjectAlternativeName([x509.DNSName(host)])
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host[:64])])
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5))
            .not_valid_after(now + timedelta(days=1825))
            .add_extension(san, critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(
                digital_signature=True, content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False, key_cert_sign=False,
                crl_sign=False, encipher_only=None, decipher_only=None,
            ), critical=True)
            .sign(private_key, hashes.SHA256())
        )
        key_temp = KEY_PATH.with_suffix(".pem.new")
        cert_temp = CERT_PATH.with_suffix(".pem.new")
        key_temp.write_bytes(private_key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        ))
        cert_temp.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        os.replace(key_temp, KEY_PATH)
        os.replace(cert_temp, CERT_PATH)
    elif not CERT_PATH.is_file() or not KEY_PATH.is_file():
        raise RuntimeError("The HTTPS certificate and key must either both exist or both be absent")
    verify_private_windows_paths([CERT_PATH, KEY_PATH])
    try:
        cert_pem = CERT_PATH.read_bytes()
        key_pem = KEY_PATH.read_bytes()
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(certfile=str(CERT_PATH), keyfile=str(KEY_PATH))
        key = serialization.load_pem_private_key(key_pem, password=None)
        cert_public = x509.load_pem_x509_certificate(cert_pem).public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        key_public = key.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        if cert_public != key_public:
            raise ValueError("Certificate and private key do not match")
    except (OSError, ValueError, TypeError) as exc:
        raise RuntimeError("The HTTPS certificate identity is invalid") from exc
    return hashlib.sha256(
        x509.load_pem_x509_certificate(CERT_PATH.read_bytes()).public_bytes(serialization.Encoding.DER)
    ).hexdigest()


def _setup_log() -> None:
    LOG_PATH.touch(exist_ok=True)
    verify_private_windows_paths([LOG_PATH])
    handler = logging.FileHandler(LOG_PATH, encoding="utf-8", delay=False)
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.INFO)
    root_logger.handlers.clear()
    root_logger.addHandler(handler)


def main() -> int:
    if os.name != "nt":
        raise SystemExit("The Windows AD service runtime runs on Windows only.")
    if not hasattr(os, "geteuid"):
        # The service task is configured to run as LocalSystem. Verify token SID
        # directly rather than relying on a username that may be localized.
        import ctypes
        if not ctypes.windll.shell32.IsUserAnAdmin():
            raise SystemExit("Run the Thessley AD service as LocalSystem.")
    _setup_log()
    try:
        config = _read_config()
        verify_private_windows_paths([ROOT])
        certificate_pin = _ensure_tls_identity(config["public_host"])
        from .challenges import ChallengeStore
        from .windows_directory import WindowsActiveDirectory, WindowsDirectoryConfig
        from .http_api import create_routes
        from .machine_auth import ReplayGuard
        from .machine_registry import MachineRegistry
        from .login_policy import LoginPolicyStore
        from .phone_registry import PhoneRegistry
        from .ad_logon_keys import AdLogonKeyRegistry
        from .replay_store import SQLiteReplayStore
        from .admin_web import AdminWeb

        registry = MachineRegistry(STATE_PATH)
        login_policy = LoginPolicyStore(STATE_PATH)
        phones = PhoneRegistry(STATE_PATH)
        ad_logon_keys = AdLogonKeyRegistry(STATE_PATH)
        reconciled_ad_keys = ad_logon_keys.revoke_without_active_approval_key()
        if reconciled_ad_keys is None:
            raise RuntimeError("Could not reconcile AD logon keys against active phone credentials")
        if reconciled_ad_keys:
            logging.warning("revoked_orphaned_ad_logon_keys count=%d", reconciled_ad_keys)
        challenges = ChallengeStore(
            STATE_PATH, phones.public_key_for, ad_logon_keys.active_key_matches_public_key,
        )
        challenges.purge_expired()
        replay_store = SQLiteReplayStore(STATE_PATH)
        directory = WindowsActiveDirectory(WindowsDirectoryConfig(config["authority"]))
        routes = create_routes(
            registry, ReplayGuard(replay_store.claim), directory, config["allowed_group_sids"],
            challenges, config["public_host"], certificate_pin, phones, login_policy,
            config["certificate_template"],
            ad_logon_keys,
        )
        admin_web = AdminWeb(
            directory=directory,
            phones=phones,
            challenges=challenges,
            allowed_group_sids=config["allowed_group_sids"],
            authority=config["authority"],
            public_host=config["public_host"],
            certificate_fingerprint=certificate_pin,
            login_policy=login_policy,
            machines=registry,
            ad_logon_keys=ad_logon_keys,
        )
        api_server = make_server((config["bind_address"], API_PORT), str(CERT_PATH), str(KEY_PATH), routes)
        try:
            admin_server = make_server(
                (config["bind_address"], ADMIN_PORT), str(CERT_PATH), str(KEY_PATH), {}, admin_web,
            )
        except Exception:
            api_server.server_close()
            raise
        stopped = threading.Event()
        for sig in (getattr(signal, "SIGTERM", None), getattr(signal, "SIGINT", None)):
            if sig is not None:
                signal.signal(sig, lambda _sig, _frame: stopped.set())
        logging.info("AD login API ready at https://%s:%d/ (TLS SHA-256 %s)",
                     config["public_host"], API_PORT, certificate_pin)
        logging.info("AD administrator site ready at https://%s:%d/admin/", config["public_host"], ADMIN_PORT)
        servers = (api_server, admin_server)
        threads = [
            threading.Thread(target=server.serve_forever, name=name, daemon=True)
            for server, name in zip(servers, ("thessley-ad-api", "thessley-ad-admin"), strict=True)
        ]
        def cleanup_expired_challenges() -> None:
            while not stopped.wait(60):
                try:
                    challenges.purge_expired()
                except Exception:
                    logging.exception("Could not purge expired AD challenge state")

        cleanup_thread = threading.Thread(
            target=cleanup_expired_challenges, name="thessley-ad-state-cleanup", daemon=True,
        )
        for thread in threads:
            thread.start()
        cleanup_thread.start()
        try:
            stopped.wait()
        finally:
            stopped.set()
            for server in servers:
                server.shutdown()
                server.server_close()
            for thread in threads:
                thread.join(timeout=5)
            cleanup_thread.join(timeout=5)
        return 0
    except Exception:
        logging.exception("AD API startup or runtime failure")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
