"""Local root-only administration for the standalone Thessley AD service."""

from __future__ import annotations

import argparse
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from .machine_registry import MachineRegistry
from .phone_registry import PhoneRegistry

STATE_DB = Path("/var/lib/thessley-ad/state.sqlite3")


def main(argv: list[str] | None = None) -> int:
    if os.geteuid() != 0:
        print("Run this command with sudo; it changes the local AD service registry.", file=sys.stderr)
        return 1
    parser = argparse.ArgumentParser(prog="thessley-ad-admin")
    commands = parser.add_subparsers(dest="command", required=True)
    issue = commands.add_parser("issue-machine-code", help="create a one-use code for a Windows machine")
    issue.add_argument("--lifetime", type=int, default=600, help="seconds, 60 to 1800 (default 600)")
    revoke_machine = commands.add_parser("revoke-machine", help="revoke a Windows machine key")
    revoke_machine.add_argument("machine_id")
    revoke_phone = commands.add_parser("revoke-phone", help="revoke an Android approval key")
    revoke_phone.add_argument("credential_id")
    args = parser.parse_args(argv)

    if not STATE_DB.parent.is_dir():
        print("The AD service is not installed or its state directory is missing.", file=sys.stderr)
        return 1
    if args.command == "issue-machine-code":
        try:
            code = MachineRegistry(STATE_DB).create_enrollment_code(lifetime_seconds=args.lifetime)
        except (ValueError, RuntimeError) as exc:
            print(str(exc), file=sys.stderr)
            return 1
        expiry = datetime.fromtimestamp(time.time() + args.lifetime, timezone.utc).isoformat(timespec="seconds")
        print(f"One-time machine enrollment code (expires {expiry} UTC):\n{code}")
        return 0
    if args.command == "revoke-machine":
        changed = MachineRegistry(STATE_DB).revoke(args.machine_id)
    else:
        changed = PhoneRegistry(STATE_DB).revoke(args.credential_id)
    print("Revoked." if changed else "No active matching credential was found.")
    return 0 if changed else 1


if __name__ == "__main__":
    raise SystemExit(main())
