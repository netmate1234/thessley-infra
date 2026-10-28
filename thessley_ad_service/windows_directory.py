"""Active Directory lookups using Windows LDAP and the machine identity."""

from __future__ import annotations

import base64
import json
import os
import re
import subprocess
from dataclasses import dataclass

from .directory import (
    DirectoryPrincipal,
    DirectoryUnavailable,
    PrincipalNotFound,
    sid_to_bytes,
    validate_group_sid_allowlist,
)
from .protocol import principal_id_from_sid

_USERNAME = re.compile(r"^[a-z_][a-z0-9_.-]{0,31}$", re.IGNORECASE)


@dataclass(frozen=True)
class WindowsDirectoryConfig:
    authority: str

    def __post_init__(self) -> None:
        if not isinstance(self.authority, str) or not re.fullmatch(r"[A-Za-z0-9_.@-]{1,128}", self.authority):
            raise ValueError("Invalid AD authority")


class WindowsActiveDirectory:
    """Resolve domain identity and nested security groups through Windows LDAP.

    The service runs as LocalSystem on a domain-joined host. Windows SSPI uses
    the computer account for LDAP authentication; no RSAT module, domain
    password, or bind secret is stored by the service.
    """

    def __init__(self, config: WindowsDirectoryConfig, *, timeout_seconds: int = 12):
        if os.name != "nt":
            raise DirectoryUnavailable("The Windows AD directory provider is available only on Windows.")
        if isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, int) or not 3 <= timeout_seconds <= 30:
            raise ValueError("Windows AD lookup timeout must be between 3 and 30 seconds")
        self.config = config
        self.timeout_seconds = timeout_seconds

    @staticmethod
    def _script_for_sid(sid: str, authority: str) -> str:
        # Validate fields before embedding only base64 representations in the
        # PowerShell script; no user-controlled PowerShell syntax is accepted.
        sid_to_bytes(sid)
        encoded_sid = base64.b64encode(sid.encode("ascii")).decode("ascii")
        encoded_authority = base64.b64encode(authority.encode("ascii")).decode("ascii")
        return rf"""
$ErrorActionPreference = 'Stop'
$sid = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{encoded_sid}'))
$authority = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{encoded_authority}'))
Add-Type -AssemblyName System.DirectoryServices -ErrorAction Stop
$root = [ADSI]'LDAP://RootDSE'
$baseDn = [string]$root.Properties['defaultNamingContext'][0]
$configurationDn = [string]$root.Properties['configurationNamingContext'][0]
if ([string]::IsNullOrWhiteSpace($baseDn) -or [string]::IsNullOrWhiteSpace($configurationDn)) {{
    throw 'LDAP RootDSE did not return the expected naming contexts.'
}}
$dnsAuthority = (($baseDn -split ',') | Where-Object {{ $_ -like 'DC=*' }} | ForEach-Object {{ $_.Substring(3) }}) -join '.'
$partition = [System.DirectoryServices.DirectorySearcher]::new([ADSI]"LDAP://CN=Partitions,$configurationDn")
$partition.Filter = "(&(objectClass=crossRef)(nCName=$baseDn))"
[void]$partition.PropertiesToLoad.Add('nETBIOSName')
$domainRef = $partition.FindOne()
$netbiosAuthority = if ($domainRef) {{ [string]$domainRef.Properties['netbiosname'][0] }} else {{ '' }}
$partition.Dispose()
if ($authority -ine $dnsAuthority -and $authority -ine $netbiosAuthority) {{
    throw 'The configured AD authority does not match this Windows host domain.'
}}
$binarySid = [Security.Principal.SecurityIdentifier]::new($sid)
$sidBytes = New-Object byte[] $binarySid.BinaryLength
$binarySid.GetBinaryForm($sidBytes, 0)
$sidFilter = -join ($sidBytes | ForEach-Object {{ '\' + $_.ToString('X2') }})
$base = [ADSI]"LDAP://$baseDn"
$userSearch = [System.DirectoryServices.DirectorySearcher]::new($base)
$userSearch.Filter = "(&(objectCategory=person)(objectClass=user)(objectSid=$sidFilter))"
foreach ($property in @('objectSid','sAMAccountName','userAccountControl','distinguishedName','primaryGroupID')) {{
    [void]$userSearch.PropertiesToLoad.Add($property)
}}
$user = $userSearch.FindOne()
if (-not $user) {{
    [Console]::Out.WriteLine('{{"not_found":true}}')
    $userSearch.Dispose()
    exit 0
}}
$returnedSid = [Security.Principal.SecurityIdentifier]::new([byte[]]$user.Properties['objectsid'][0], 0).Value
if ($returnedSid -ne $sid) {{ throw 'AD returned a different SID.' }}
$accountFlags = [int]$user.Properties['useraccountcontrol'][0]
if (($accountFlags -band 0x2) -ne 0) {{
    [Console]::Out.WriteLine('{{"not_found":true}}')
    $userSearch.Dispose()
    exit 0
}}
$userDn = [string]$user.Properties['distinguishedname'][0]
$escapedDn = $userDn.Replace('\','\5c').Replace('*','\2a').Replace('(','\28').Replace(')','\29')
$groupSearch = [System.DirectoryServices.DirectorySearcher]::new($base)
$groupSearch.Filter = "(&(objectCategory=group)(groupType:1.2.840.113556.1.4.803:=2147483648)(member:1.2.840.113556.1.4.1941:=$escapedDn))"
[void]$groupSearch.PropertiesToLoad.Add('objectSid')
$groupSids = @($groupSearch.FindAll() | ForEach-Object {{
    [Security.Principal.SecurityIdentifier]::new([byte[]]$_.Properties['objectsid'][0], 0).Value
}})
$primaryGroupId = [int]$user.Properties['primarygroupid'][0]
$domainSid = $sid.Substring(0, $sid.LastIndexOf('-'))
$primaryGroupSid = "$domainSid-$primaryGroupId"
$primarySid = [Security.Principal.SecurityIdentifier]::new($primaryGroupSid)
$primaryBytes = New-Object byte[] $primarySid.BinaryLength
$primarySid.GetBinaryForm($primaryBytes, 0)
$primaryFilter = -join ($primaryBytes | ForEach-Object {{ '\' + $_.ToString('X2') }})
$primarySearch = [System.DirectoryServices.DirectorySearcher]::new($base)
$primarySearch.Filter = "(&(objectCategory=group)(objectSid=$primaryFilter)(groupType:1.2.840.113556.1.4.803:=2147483648))"
[void]$primarySearch.PropertiesToLoad.Add('objectSid')
$primaryResult = $primarySearch.FindOne()
if ($primaryResult) {{ $groupSids += $primaryGroupSid }}
$groups = @($groupSids | Sort-Object -Unique)
$result = [ordered]@{{
    sid = $returnedSid
    username = [string]$user.Properties['samaccountname'][0]
    group_sids = $groups
}}
[Console]::Out.WriteLine(($result | ConvertTo-Json -Compress -Depth 3))
$userSearch.Dispose()
$groupSearch.Dispose()
$primarySearch.Dispose()
"""

    def resolve_user_sid(self, sid: str) -> DirectoryPrincipal:
        try:
            script = self._script_for_sid(sid, self.config.authority)
        except (TypeError, ValueError) as exc:
            raise PrincipalNotFound("SID is invalid") from exc
        encoded_script = base64.b64encode(script.encode("utf-16le")).decode("ascii")
        try:
            result = subprocess.run(
                ["powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded_script],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=self.timeout_seconds,
                check=False,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise DirectoryUnavailable("Windows could not query Active Directory") from exc
        if result.returncode:
            message = result.stderr.lower()
            if "adidentitynotfoundexception" in message or any(
                marker in message for marker in ("cannot find", "object not found", "could not find")
            ):
                raise PrincipalNotFound("SID does not resolve to an enabled AD user")
            raise DirectoryUnavailable("Windows could not query AD group authorization")
        try:
            data = json.loads(result.stdout.strip())
            if data == {"not_found": True}:
                raise PrincipalNotFound("SID does not resolve to an enabled AD user")
            if not isinstance(data, dict) or set(data) != {"sid", "username", "group_sids"}:
                raise ValueError
            if data["sid"] != sid or not isinstance(data["username"], str) or not _USERNAME.fullmatch(data["username"]):
                raise ValueError
            groups = data["group_sids"]
            if not isinstance(groups, list) or any(not isinstance(item, str) for item in groups):
                raise ValueError
            group_sids = validate_group_sid_allowlist(groups)
        except PrincipalNotFound:
            raise
        except (json.JSONDecodeError, TypeError, ValueError) as exc:
            raise DirectoryUnavailable("Windows returned an invalid AD lookup response") from exc
        return DirectoryPrincipal(
            sid=sid,
            principal_id=principal_id_from_sid(sid),
            username=data["username"],
            authority=self.config.authority,
            group_sids=group_sids,
        )

    def user_in_any_group(self, sid: str, allowed_group_sids: set[str] | frozenset[str]) -> bool:
        if not allowed_group_sids:
            return False
        principal = self.resolve_user_sid(sid)
        return bool(principal.group_sids.intersection(allowed_group_sids))
