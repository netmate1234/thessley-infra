"""Elevated local administration for the Windows-hosted AD API."""

from __future__ import annotations

import argparse
import ctypes
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(os.environ.get("PROGRAMDATA", r"C:\ProgramData")) / "ThessleyAD"
STATE_DB = ROOT / "state.sqlite3"


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
    args = parser.parse_args(argv)
    if not STATE_DB.is_file():
        print("The AD API has not created its protected state database yet.", file=sys.stderr)
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
