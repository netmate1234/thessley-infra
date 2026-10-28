"""Cross-platform checks for the AD service's private SQLite state directory."""

from __future__ import annotations

import json
import os
import re
import stat
import subprocess
import base64
from pathlib import Path


class UnsafeState(RuntimeError):
    """State storage is writable by an untrusted principal or is a reparse point."""


def _has_reparse_point(info: os.stat_result) -> bool:
    attributes = getattr(info, "st_file_attributes", 0)
    return bool(attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))


def _windows_acls(paths: list[Path]) -> list[str]:
    encoded_paths = [base64.b64encode(str(path).encode("utf-8")).decode("ascii") for path in paths]
    literals = ",".join("[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('%s'))" % item for item in encoded_paths)
    script = rf"""
$ErrorActionPreference = 'Stop'
$items = @({literals})
$result = foreach ($path in $items) {{
    $acl = Get-Acl -LiteralPath $path -ErrorAction Stop
    [pscustomobject]@{{ path = $path; sddl = $acl.GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::Access); owner = $acl.GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::Owner) }}
}}
[Console]::Out.WriteLine((ConvertTo-Json -InputObject @($result) -Compress -Depth 3))
"""
    command = base64.b64encode(script.encode("utf-16le")).decode("ascii")
    try:
        result = subprocess.run(
            ["powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand", command],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            # PowerShell can take several seconds to initialize its first
            # process under SYSTEM after boot (especially on a cold VM). An
            # eight-second timeout makes the API task exit before it binds,
            # leaving enrollment unavailable until somebody restarts it.
            # Keep the ACL verification mandatory, but allow cold start time.
            timeout=45,
            check=False,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise UnsafeState("Could not verify Windows state ACLs") from exc
    if result.returncode:
        raise UnsafeState("Could not verify Windows state ACLs")
    try:
        value = json.loads(result.stdout.strip())
        if isinstance(value, dict):
            value = [value]
        if not isinstance(value, list) or len(value) != len(paths):
            raise ValueError
        for entry, expected in zip(value, paths, strict=True):
            if not isinstance(entry, dict) or Path(entry.get("path", "")).resolve() != expected.resolve():
                raise ValueError
            sddl = entry.get("sddl")
            owner = entry.get("owner")
            if not isinstance(sddl, str) or not isinstance(owner, str):
                raise ValueError
            if owner not in ("O:SY", "O:BA", "O:S-1-5-18", "O:S-1-5-32-544"):
                raise ValueError
            dacl_match = re.search(r"(?:^|:)D:(.*?)(?::S:|$)", sddl)
            if not dacl_match:
                raise ValueError
            aces = re.findall(r"\(([^()]*)\)", dacl_match.group(1))
            if not aces:
                raise ValueError
            principals: set[str] = set()
            for ace in aces:
                parts = ace.split(";")
                if len(parts) != 6 or parts[0] != "A" or parts[2] not in ("FA", "0x001f01ff"):
                    raise ValueError
                if parts[5] not in ("SY", "BA"):
                    raise ValueError
                principals.add(parts[5])
            if principals != {"SY", "BA"}:
                raise ValueError
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise UnsafeState("Windows state ACL must grant full access only to SYSTEM and Administrators") from exc
    return [entry["sddl"] for entry in value]


def verify_private_windows_paths(paths: list[str | os.PathLike[str]]) -> None:
    """Require plain filesystem paths and a SYSTEM/Administrators-only DACL."""
    resolved = [Path(path) for path in paths]
    for path in resolved:
        try:
            info = os.stat(path, follow_symlinks=False)
        except OSError as exc:
            raise UnsafeState("A protected AD service file is unavailable") from exc
        if _has_reparse_point(info):
            raise UnsafeState("A protected AD service file must not be a reparse point")
    _windows_acls(resolved)


def prepare_private_sqlite(path: str | os.PathLike[str], *, description: str) -> None:
    """Create/open one private SQLite file and reject weak POSIX or Windows ACLs."""
    target = Path(path)
    try:
        parent = os.stat(target.parent, follow_symlinks=False)
    except OSError as exc:
        raise UnsafeState("AD service state directory must exist") from exc
    if not stat.S_ISDIR(parent.st_mode) or _has_reparse_point(parent):
        raise UnsafeState("AD service state directory is not a plain directory")
    if os.name == "nt":
        fd = None
        try:
            fd = os.open(target, os.O_RDWR | os.O_CREAT | getattr(os, "O_BINARY", 0), 0o600)
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or _has_reparse_point(info):
                raise UnsafeState(f"{description} is not a regular file")
        except OSError as exc:
            raise UnsafeState(f"Could not safely open {description}") from exc
        finally:
            if fd is not None:
                os.close(fd)
        _windows_acls([target.parent, target])
        return

    owner = os.geteuid()
    if parent.st_uid != owner or parent.st_mode & 0o022:
        raise UnsafeState("AD service state directory has unsafe ownership or permissions")
    try:
        fd = os.open(target, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
    except OSError as exc:
        raise UnsafeState(f"Could not safely open {description}") from exc
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != owner or info.st_mode & 0o077:
            raise UnsafeState(f"{description} has unsafe ownership or permissions")
        os.fchmod(fd, 0o600)
    finally:
        os.close(fd)


def finish_private_sqlite(path: str | os.PathLike[str]) -> None:
    """Keep SQLite file mode private after schema creation on POSIX."""
    if os.name != "nt":
        os.chmod(path, 0o600)
