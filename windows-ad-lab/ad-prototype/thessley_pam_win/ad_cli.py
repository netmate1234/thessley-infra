"""Isolated command-line entry point for the experimental AD login agent.

This deliberately does not import the existing local Windows QR/PAM CLI or
register/change a Windows credential provider.
"""

from __future__ import annotations

import argparse
import ctypes
import getpass
import json
import re
import subprocess
import sys
import threading
import time

from . import ad_agent, qr


# The enrollment UI is a windowed app. Windows otherwise creates a visible
# console for each PowerShell child even though we capture its output.
_NO_CONSOLE = getattr(subprocess, "CREATE_NO_WINDOW", 0)


def _is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError):
        return False


def _sid_for_account(account: str) -> str:
    if not isinstance(account, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}\\[A-Za-z0-9_.-]{1,64}", account):
        raise ValueError("Use a qualified account such as THESSLEYLAB\\martin.")
    script = (
        "$ErrorActionPreference='Stop'; "
        f"$account=[System.Security.Principal.NTAccount]::new('{account}'); "
        "$account.Translate([System.Security.Principal.SecurityIdentifier]).Value"
    )
    result = subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
        capture_output=True, text=True, errors="replace", timeout=15, check=False,
        creationflags=_NO_CONSOLE,
    )
    sid = result.stdout.strip()
    if result.returncode or not re.fullmatch(r"S-1-(?:[0-9]+-)+[0-9]+", sid, re.IGNORECASE):
        raise ValueError(result.stderr.strip()[:240] or "Windows could not resolve that account SID.")
    return sid


def _current_user_sid() -> str:
    script = (
        "$ErrorActionPreference='Stop'; "
        "$identity=[System.Security.Principal.WindowsIdentity]::GetCurrent(); "
        "$local=Get-CimInstance Win32_UserAccount -Filter 'LocalAccount=True' | "
        "Where-Object { $_.SID -eq $identity.User.Value }; "
        "if ($local) { 'LOCAL_ACCOUNT' } else { $identity.User.Value }"
    )
    result = subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
        capture_output=True, text=True, errors="replace", timeout=15, check=False,
        creationflags=_NO_CONSOLE,
    )
    sid = result.stdout.strip()
    if sid == "LOCAL_ACCOUNT":
        raise ValueError(
            "This is a local Windows account. Sign in to the domain account first, "
            "or use enroll-phone --user DOMAIN\\name from an administrator shell."
        )
    if result.returncode or not re.fullmatch(r"S-1-(?:[0-9]+-)+[0-9]+", sid, re.IGNORECASE):
        raise ValueError(result.stderr.strip()[:240] or "Windows could not resolve the signed-in account SID.")
    return sid


def _require_domain_joined() -> None:
    script = (
        "$ErrorActionPreference='Stop'; "
        "[bool](Get-CimInstance Win32_ComputerSystem).PartOfDomain"
    )
    try:
        result = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
            capture_output=True, text=True, errors="replace", timeout=15, check=False,
            creationflags=_NO_CONSOLE,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise ValueError("Windows could not check domain membership.") from exc
    if result.returncode or result.stdout.strip().lower() != "true":
        raise ValueError(
            "AD phone sign-in requires a domain-joined Windows Pro or higher PC. "
            "Use the local Thessley QR tile on Windows Home."
        )


def _show_qr(link: str) -> None:
    rows = qr.lines(link, border=2)
    if rows:
        print("\n".join(rows))
    else:
        print("QR rendering is unavailable; open this complete link on the phone:")
        print(link)


def _phone_enroll(account: str | None = None, sid: str | None = None) -> int:
    try:
        _require_domain_joined()
        sid = sid or _sid_for_account(account)
        started = ad_agent.start_phone_enrollment(sid)
    except (ad_agent.AgentError, OSError, ValueError, subprocess.SubprocessError) as exc:
        print(f"Could not start AD phone enrollment: {exc}", file=sys.stderr)
        return 1
    print(f"Scan with Thessley Passkey to enroll for {started['authority']}\\{started['username']}:")
    _show_qr(started["link"])
    print(f"Complete enrollment link (phone-app fallback): {started['link']}")
    print("\nWaiting for the phone. Compare the pairing codes before confirming.", flush=True)
    deadline = time.monotonic() + 115
    while time.monotonic() < deadline:
        try:
            state = ad_agent.phone_enrollment_status(started["request_id"])
        except (ad_agent.AgentError, OSError, ValueError) as exc:
            print(f"Could not check phone enrollment: {exc}", file=sys.stderr)
            return 1
        if state["status"] == "ready":
            code = state["pairing_code"]
            print(f"Pairing code: {code}")
            try:
                matched = input("Does the phone show the same code? Confirm only if it matches [y/N]: ")
            except (EOFError, KeyboardInterrupt):
                matched = ""
            if matched.strip().lower() not in ("y", "yes"):
                try:
                    ad_agent.cancel_phone_enrollment(started["request_id"])
                except (ad_agent.AgentError, OSError, ValueError):
                    pass
                print("Enrollment cancelled; no phone key was activated.")
                return 1
            try:
                ad_agent.confirm_phone_enrollment(started["request_id"], code)
            except (ad_agent.AgentError, OSError, ValueError) as exc:
                print(f"Could not confirm phone enrollment: {exc}", file=sys.stderr)
                return 1
            print("Phone enrolled for this domain account and Windows computer.")
            return 0
        if state["status"] in ("expired", "denied"):
            print("Phone enrollment expired or was cancelled.")
            return 1
        time.sleep(1)
    try:
        ad_agent.cancel_phone_enrollment(started["request_id"])
    except (ad_agent.AgentError, OSError, ValueError):
        pass
    print("Phone enrollment timed out. No phone key was activated.")
    return 1


def _approval_test(account: str, context: str) -> int:
    try:
        _require_domain_joined()
        started = ad_agent.start_login(_sid_for_account(account), context)
    except (ad_agent.AgentError, OSError, ValueError, subprocess.SubprocessError) as exc:
        print(f"Could not start AD phone-approval test: {exc}", file=sys.stderr)
        return 1
    print(f"Scan with Thessley Passkey for {account} ({context}):")
    _show_qr(started["link"])
    print(f"Complete approval link: {started['link']}", flush=True)
    print("This test checks QR approval only. It does not log in to Windows.", flush=True)
    try:
        approved = ad_agent.poll_login(
            started["request_id"], threading.Event(), say=lambda message: print(message, flush=True), timeout=175,
        )
    except (ad_agent.AgentError, OSError, ValueError) as exc:
        print(f"AD phone-approval test failed: {exc}", file=sys.stderr)
        return 1
    return 0 if approved else 1


def _approval_start(sid: str, context: str) -> int:
    """Machine-authenticated, quiet JSON interface for a future native tile."""
    if not re.fullmatch(r"S-1-(?:[0-9]+-)+[0-9]+", sid, re.IGNORECASE):
        raise ValueError("The selected account SID is malformed.")
    _require_domain_joined()
    started = ad_agent.start_login(sid, context)
    print(json.dumps({
        "request_id": started["request_id"],
        "link": started["link"],
        "credential_method": started["credential_method"],
        "policy_source": started["policy_source"],
        "qr_matrix": started["qr_matrix"],
    }, separators=(",", ":")), flush=True)
    return 0


def _approval_poll(request_id: str, timeout: int) -> int:
    if not re.fullmatch(r"[A-Za-z0-9_-]{8,128}", request_id):
        raise ValueError("The approval request ID is malformed.")
    approved = ad_agent.poll_login(
        request_id, threading.Event(), say=lambda _message: None, timeout=timeout,
    )
    print(json.dumps({"status": "approved" if approved else "not_approved"}), flush=True)
    return 0 if approved else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="thessley-ad-test", description="Isolated Thessley AD sign-in prototype")
    commands = parser.add_subparsers(dest="command", required=True)
    pair = commands.add_parser("pair-machine", help="pair this Windows PC to the standalone AD service")
    pair.add_argument("--server", required=True, help="pinned HTTPS service origin")
    pair.add_argument("--tls-sha256", required=True, help="64-character TLS certificate SHA-256")
    commands.add_parser("status", help="show machine pairing state")
    commands.add_parser("check", help="check the pinned machine-authenticated service connection")
    authorize = commands.add_parser("authorization-check", help="check the selected domain account against the AD group policy")
    authorize.add_argument("--user", required=True, help="qualified domain account")
    resolve = commands.add_parser("resolve-user", help="resolve one authorized AD account for the generic sign-in tile")
    resolve.add_argument("--account", required=True, help="SAM account name, optionally DOMAIN\\name")
    enroll = commands.add_parser("enroll-phone", help="admin-assisted phone enrollment for a domain account")
    enroll.add_argument("--user", required=True, help="qualified domain account, e.g. THESSLEYLAB\\martin")
    commands.add_parser("enroll-current-user", help="enroll a phone for the currently signed-in AD account")
    approval = commands.add_parser("approval-test", help="test phone approval without changing Windows logon")
    approval.add_argument("--user", required=True, help="qualified domain account")
    approval.add_argument("--context", choices=("interactive", "unlock", "ssh"), default="interactive")
    start = commands.add_parser("approval-start", help="start an AD sign-in approval and return JSON for the native tile")
    start.add_argument("--sid", required=True)
    start.add_argument("--context", choices=("interactive", "unlock"), required=True)
    poll = commands.add_parser("approval-poll", help="poll an AD sign-in approval and return JSON for the native tile")
    poll.add_argument("--request-id", required=True)
    poll.add_argument("--timeout", type=int, default=175, choices=range(1, 176))
    args = parser.parse_args(argv)

    try:
        if args.command == "pair-machine":
            if not _is_admin():
                print("Run pair-machine from an Administrator PowerShell window.", file=sys.stderr)
                return 1
            _require_domain_joined()
            code = getpass.getpass("One-time AD machine-pairing code: ").strip()
            machine_id = ad_agent.enroll_machine(args.server, args.tls_sha256, code)
            print(f"This Windows PC is paired with Thessley AD ({machine_id}).")
            return 0
        if args.command == "status":
            if not ad_agent.configured():
                print("This Windows PC is not paired with Thessley AD.")
                return 1
            config, _key, host, port, pin = ad_agent._load()
            print(f"Service: https://{host}:{port}\nMachine ID: {config['machine_id']}\nTLS SHA-256: {pin}")
            return 0
        if args.command == "check":
            result = ad_agent.check_connection()
            print(f"Signed service check succeeded for machine {result['machine_id']}.")
            return 0
        if args.command == "authorization-check":
            _require_domain_joined()
            result = ad_agent.check_domain_authorization(_sid_for_account(args.user))
            state = "authorized" if result["authorized"] else "not authorized"
            print(f"AD policy: {result['authority']}\\{result['username']} is {state} on this prototype; "
                  f"sign-in method is {result['credential_method']} ({result['policy_source']}).")
            return 0 if result["authorized"] else 1
        if args.command == "resolve-user":
            _require_domain_joined()
            result = ad_agent.resolve_domain_account(args.account)
            print(f"Resolved {result['authority']}\\{result['username']} (SID {result['sid']}); "
                  f"policy {result['credential_method']} ({result['policy_source']}).")
            return 0
        if args.command == "enroll-phone":
            return _phone_enroll(args.user)
        if args.command == "enroll-current-user":
            return _phone_enroll(sid=_current_user_sid())
        if args.command == "approval-test":
            return _approval_test(args.user, args.context)
        if args.command == "approval-start":
            return _approval_start(args.sid, args.context)
        if args.command == "approval-poll":
            return _approval_poll(args.request_id, args.timeout)
    except (ad_agent.AgentError, OSError, ValueError, subprocess.SubprocessError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
