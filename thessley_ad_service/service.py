"""Root service entry point for the standalone Thessley AD API."""

from __future__ import annotations

import os
import signal
import stat
import sys
import threading
import tomllib
from pathlib import Path

CONFIG_FILE = Path("/etc/thessley-ad/service.toml")
STATE_DIR = Path("/var/lib/thessley-ad")
STATE_DB = STATE_DIR / "state.sqlite3"
PAM_LIBRARY = "/usr/local/lib/thessley-pam"


def _read_config() -> dict:
    fd = os.open(CONFIG_FILE, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o077:
            raise RuntimeError("AD service config must be root-owned and mode 0600")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            data = tomllib.load(stream)
    finally:
        os.close(fd)
    if set(data) != {"service", "directory"}:
        raise RuntimeError("AD service config must contain exactly [service] and [directory]")
    return data


def _ensure_state_dir() -> None:
    STATE_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = os.stat(STATE_DIR, follow_symlinks=False)
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o077:
        raise RuntimeError("AD service state directory must be root-owned and mode 0700")
    os.chmod(STATE_DIR, 0o700)


def main() -> int:
    if os.geteuid() != 0:
        raise SystemExit("The Thessley AD service must run as root to register with the shared listener.")
    sys.path.insert(0, PAM_LIBRARY)
    config = _read_config()
    service = config["service"]
    directory_config = config["directory"]
    required_service_options = {"public_host", "allowed_group_sids"}
    if set(service) not in (required_service_options, required_service_options | {"certificate_template"}):
        raise RuntimeError("Invalid [service] options")
    allowed_group_sids = service["allowed_group_sids"]
    if not isinstance(allowed_group_sids, list):
        raise RuntimeError("service.allowed_group_sids must be a list")
    if set(directory_config) != {"host", "base_dn", "bind_dn", "password_file", "ca_file", "authority"}:
        raise RuntimeError("Invalid [directory] options")

    from thessley_pam import machine
    from thessley_pam.listener import RawBodyRoute as ListenerRawBodyRoute, SHARED_PORT, listening

    from .challenges import ChallengeStore
    from .directory import ActiveDirectory, DirectoryConfig, validate_group_sid_allowlist
    from .http_api import create_routes
    from .protocol import validate_certificate_template
    from .machine_auth import ReplayGuard
    from .machine_registry import MachineRegistry
    from .login_policy import LoginPolicyStore
    from .phone_registry import PhoneRegistry
    from .ad_logon_keys import AdLogonKeyRegistry
    from .replay_store import SQLiteReplayStore

    _ensure_state_dir()
    registry = MachineRegistry(STATE_DB)
    login_policy = LoginPolicyStore(STATE_DB)
    phones = PhoneRegistry(STATE_DB)
    ad_logon_keys = AdLogonKeyRegistry(STATE_DB)
    challenges = ChallengeStore(STATE_DB, phones.public_key_for)
    challenges.purge_expired()
    replay_store = SQLiteReplayStore(STATE_DB)
    directory = ActiveDirectory(DirectoryConfig(**directory_config))
    group_sids = validate_group_sid_allowlist(allowed_group_sids)
    try:
        certificate_template = validate_certificate_template(service.get("certificate_template"))
    except ValueError as exc:
        raise RuntimeError("service.certificate_template is invalid") from exc
    certificate_pin = {"value": ""}
    routes = create_routes(
        registry,
        ReplayGuard(replay_store.claim),
        directory,
        group_sids,
        challenges,
        service["public_host"],
        lambda: certificate_pin["value"],
        phones,
        login_policy,
        certificate_template,
        ad_logon_keys,
    )
    listener_routes = {
        path: ListenerRawBodyRoute(route.handler, response_wait=route.response_wait)
        for path, route in routes.items()
    }
    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda _signal, _frame: stop.set())
    signal.signal(signal.SIGINT, lambda _signal, _frame: stop.set())
    with listening(machine.lan_ip(), listener_routes, SHARED_PORT) as listener:
        certificate_pin["value"] = listener.fingerprint.lower()
        print(f"Thessley AD API registered at https://{service['public_host']}:{listener.port}/", flush=True)
        def cleanup_expired_challenges() -> None:
            while not stop.wait(60):
                try:
                    challenges.purge_expired()
                except Exception as exc:
                    print(f"Could not purge expired AD challenge state: {exc}", flush=True)

        cleanup_thread = threading.Thread(
            target=cleanup_expired_challenges, name="thessley-ad-state-cleanup", daemon=True,
        )
        cleanup_thread.start()
        try:
            stop.wait()
        finally:
            stop.set()
            cleanup_thread.join(timeout=5)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
