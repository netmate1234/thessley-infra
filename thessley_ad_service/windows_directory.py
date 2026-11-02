"""Active Directory lookups using Windows LDAP and the machine identity."""

from __future__ import annotations

import base64
import json
import logging
import os
import re
import socket
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
_AD_ERROR_MESSAGES = {
    "exists": "That username already exists.",
    "not_found": "The AD account could not be found.",
    "protected": "Built-in, protected, and privileged AD accounts cannot be changed or deleted here.",
    "permission": "AD denied this change. The administrator account needs permission on the target object or group.",
    "password_policy": "The temporary password does not meet the domain password policy: it is too short, lacks complexity, is a banned word, or repeats a recent password. Choose a different one.",
    "group_missing": "The configured workstation sign-in group was not found in Active Directory.",
    "failed": "AD rejected the change. Check the account settings and directory logs.",
}


def _reject_ad_change(operation: str, response: dict) -> None:
    """Log the directory's short error detail and raise a user-facing message."""
    detail = response.get("detail")
    if isinstance(detail, str) and detail:
        logging.getLogger("thessley.ad.directory").warning(
            "ad_account_change_rejected operation=%s code=%s detail=%s",
            operation, response.get("error"), detail[:300].replace("\n", " "),
        )
    raise ValueError(_AD_ERROR_MESSAGES.get(response.get("error"), "AD rejected the account change."))


_SID = re.compile(r"^S-1-(?:[0-9]+-)+[0-9]+$")


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

    @property
    def dns_domain(self) -> str:
        """The DNS suffix of this domain, accepted as an alias for the NetBIOS authority."""
        try:
            fqdn = socket.getfqdn()
        except OSError:
            return ""
        return fqdn.split(".", 1)[1] if "." in fqdn else ""

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

    def resolve_username(self, username: str) -> DirectoryPrincipal:
        """Resolve an exact SAM account name without requiring RSAT/ADWS."""
        if not isinstance(username, str) or not _USERNAME.fullmatch(username):
            raise PrincipalNotFound("Account name is invalid")
        encoded_username = base64.b64encode(username.encode("ascii")).decode("ascii")
        script = rf"""
$ErrorActionPreference = 'Stop'
$username = [Text.Encoding]::ASCII.GetString([Convert]::FromBase64String('{encoded_username}'))
$timeoutSeconds = {self.timeout_seconds}
Add-Type -AssemblyName System.DirectoryServices -ErrorAction Stop
$root = [ADSI]'LDAP://RootDSE'
$baseDn = [string]$root.Properties['defaultNamingContext'][0]
if ([string]::IsNullOrWhiteSpace($baseDn)) {{ throw 'LDAP RootDSE did not return the domain naming context.' }}
$base = [ADSI]"LDAP://$baseDn"
$userSearch = [System.DirectoryServices.DirectorySearcher]::new($base)
$userSearch.Filter = "(&(objectCategory=person)(objectClass=user)(sAMAccountName=$username))"
$userSearch.SizeLimit = 2
$userSearch.ServerTimeLimit = [TimeSpan]::FromSeconds($timeoutSeconds)
[void]$userSearch.PropertiesToLoad.Add('objectSid')
$results = $userSearch.FindAll()
if ($results.Count -ne 1) {{
    if ($results.Count -eq 0) {{ [Console]::Out.WriteLine('{{"not_found":true}}'); exit 0 }}
    throw 'The account name did not resolve uniquely.'
}}
$sid = [Security.Principal.SecurityIdentifier]::new([byte[]]$results[0].Properties['objectsid'][0], 0).Value
[Console]::Out.WriteLine((ConvertTo-Json -InputObject ([PSCustomObject]@{{ sid = $sid }}) -Compress))
$results.Dispose()
$userSearch.Dispose()
$base.Dispose()
$root.Dispose()
"""
        encoded_script = base64.b64encode(script.encode("utf-16le")).decode("ascii")
        try:
            result = subprocess.run(
                ["powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded_script],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=self.timeout_seconds + 3,
                check=False,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise DirectoryUnavailable("Windows could not query Active Directory") from exc
        if result.returncode:
            raise DirectoryUnavailable("Windows could not query the AD account name")
        try:
            data = json.loads(result.stdout.strip())
            if data == {"not_found": True}:
                raise PrincipalNotFound("Account name does not resolve to an enabled AD user")
            if not isinstance(data, dict) or set(data) != {"sid"}:
                raise ValueError
            sid = data["sid"]
            if not isinstance(sid, str) or not _SID.fullmatch(sid):
                raise ValueError
            sid_to_bytes(sid)
        except PrincipalNotFound:
            raise
        except (json.JSONDecodeError, TypeError, ValueError) as exc:
            raise DirectoryUnavailable("Windows returned an invalid AD account lookup response") from exc
        return self.resolve_user_sid(sid)

    def user_in_any_group(self, sid: str, allowed_group_sids: set[str] | frozenset[str]) -> bool:
        if not allowed_group_sids:
            return False
        principal = self.resolve_user_sid(sid)
        return bool(principal.group_sids.intersection(allowed_group_sids))

    def list_users(self, allowed_group_sids: set[str] | frozenset[str], *, limit: int = 1000) -> dict:
        """Return a bounded read-only user directory snapshot and effective policy membership.

        This endpoint is called only through the machine-signature-authenticated
        API. The allowed group SIDs come from protected service configuration;
        no LDAP filter or group is accepted from a workstation request.
        """
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 1000:
            raise ValueError("AD directory result limit is invalid")
        allowed = validate_group_sid_allowlist(allowed_group_sids)
        encoded_groups = base64.b64encode(json.dumps(sorted(allowed), separators=(",", ":")).encode("ascii")).decode("ascii")
        encoded_authority = base64.b64encode(self.config.authority.encode("ascii")).decode("ascii")
        script = rf"""
$ErrorActionPreference = 'Stop'
try {{
    $allowedJson = [Text.Encoding]::ASCII.GetString([Convert]::FromBase64String('{encoded_groups}'))
    $allowed = ConvertFrom-Json -InputObject $allowedJson
    if ($allowed -isnot [System.Array]) {{ $allowed = @($allowed) }}
    $authority = [Text.Encoding]::ASCII.GetString([Convert]::FromBase64String('{encoded_authority}'))
    $limit = {limit}
    $timeoutSeconds = {self.timeout_seconds}
    Add-Type -AssemblyName System.DirectoryServices -ErrorAction Stop
    $root = [System.DirectoryServices.DirectoryEntry]::new('LDAP://RootDSE')
    $baseDn = [string]$root.Properties['defaultNamingContext'][0]
    $configurationDn = [string]$root.Properties['configurationNamingContext'][0]
    if ([string]::IsNullOrWhiteSpace($baseDn)) {{ throw 'LDAP RootDSE did not return the domain naming context.' }}
    $domain = (($baseDn -split ',') | Where-Object {{ $_ -like 'DC=*' }} | ForEach-Object {{ $_.Substring(3) }}) -join '.'
    $partition = [System.DirectoryServices.DirectorySearcher]::new(
        [System.DirectoryServices.DirectoryEntry]::new("LDAP://CN=Partitions,$configurationDn"))
    $partition.Filter = "(&(objectClass=crossRef)(nCName=$baseDn))"
    [void]$partition.PropertiesToLoad.Add('nETBIOSName')
    $domainRef = $partition.FindOne()
    $netbiosDomain = if ($domainRef) {{ [string]$domainRef.Properties['netbiosname'][0] }} else {{ '' }}
    $partition.Dispose()
    if ($authority -ine $domain -and $authority -ine $netbiosDomain) {{ throw 'AD authority does not match the configured domain.' }}
    $base = [System.DirectoryServices.DirectoryEntry]::new("LDAP://$baseDn")
    $authorizedSams = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($groupSid in $allowed) {{
        $sidObject = [Security.Principal.SecurityIdentifier]::new([string]$groupSid)
        $sidBytes = New-Object byte[] $sidObject.BinaryLength
        $sidObject.GetBinaryForm($sidBytes, 0)
        $sidFilter = -join ($sidBytes | ForEach-Object {{ '\' + $_.ToString('X2') }})
        $groupSearch = [System.DirectoryServices.DirectorySearcher]::new($base)
        $groupSearch.Filter = "(&(objectCategory=group)(objectSid=$sidFilter))"
        $groupSearch.ServerTimeLimit = [TimeSpan]::FromSeconds($timeoutSeconds)
        [void]$groupSearch.PropertiesToLoad.Add('distinguishedName')
        $group = $groupSearch.FindOne()
        if ($group) {{
            $groupDn = [string]$group.Properties['distinguishedname'][0]
            $escapedDn = $groupDn.Replace('\', '\5c').Replace('*', '\2a').Replace('(', '\28').Replace(')', '\29').Replace([string][char]0, '\00')
            $memberSearch = [System.DirectoryServices.DirectorySearcher]::new($base)
            $memberSearch.Filter = "(&(objectCategory=person)(objectClass=user)(memberOf:1.2.840.113556.1.4.1941:=$escapedDn))"
            $memberSearch.PageSize = 500
            $memberSearch.SizeLimit = 1001
            $memberSearch.ServerTimeLimit = [TimeSpan]::FromSeconds($timeoutSeconds)
            [void]$memberSearch.PropertiesToLoad.Add('sAMAccountName')
            $members = $memberSearch.FindAll()
            foreach ($member in $members) {{
                if ($member.Properties['samaccountname'].Count -gt 0) {{
                    [void]$authorizedSams.Add([string]$member.Properties['samaccountname'][0])
                }}
            }}
            $members.Dispose()
            $memberSearch.Dispose()
        }}
        $groupSearch.Dispose()
    }}

    # Report DC administration separately from the configured workstation
    # sign-in group. This is read-only and uses nested AD membership just like
    # the configured policy group above.
    $dcAdministratorSams = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $adminSid = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
    $adminSidBytes = New-Object byte[] $adminSid.BinaryLength
    $adminSid.GetBinaryForm($adminSidBytes, 0)
    $adminSidFilter = -join ($adminSidBytes | ForEach-Object {{ '\' + $_.ToString('X2') }})
    $adminGroupSearch = [System.DirectoryServices.DirectorySearcher]::new($base)
    $adminGroupSearch.Filter = "(&(objectCategory=group)(objectSid=$adminSidFilter))"
    $adminGroupSearch.ServerTimeLimit = [TimeSpan]::FromSeconds($timeoutSeconds)
    [void]$adminGroupSearch.PropertiesToLoad.Add('distinguishedName')
    $adminGroup = $adminGroupSearch.FindOne()
    if ($adminGroup) {{
        $adminGroupDn = [string]$adminGroup.Properties['distinguishedname'][0]
        $escapedAdminGroupDn = $adminGroupDn.Replace('\', '\5c').Replace('*', '\2a').Replace('(', '\28').Replace(')', '\29').Replace([string][char]0, '\00')
        $adminMemberSearch = [System.DirectoryServices.DirectorySearcher]::new($base)
        $adminMemberSearch.Filter = "(&(objectCategory=person)(objectClass=user)(memberOf:1.2.840.113556.1.4.1941:=$escapedAdminGroupDn))"
        $adminMemberSearch.PageSize = 500
        $adminMemberSearch.SizeLimit = 1001
        $adminMemberSearch.ServerTimeLimit = [TimeSpan]::FromSeconds($timeoutSeconds)
        [void]$adminMemberSearch.PropertiesToLoad.Add('sAMAccountName')
        $adminMembers = $adminMemberSearch.FindAll()
        foreach ($adminMember in $adminMembers) {{
            if ($adminMember.Properties['samaccountname'].Count -gt 0) {{
                [void]$dcAdministratorSams.Add([string]$adminMember.Properties['samaccountname'][0])
            }}
        }}
        $adminMembers.Dispose()
        $adminMemberSearch.Dispose()
    }}
    $adminGroupSearch.Dispose()

    $userSearch = [System.DirectoryServices.DirectorySearcher]::new($base)
    $userSearch.Filter = '(&(objectCategory=person)(objectClass=user))'
    $userSearch.PageSize = 500
    $userSearch.SizeLimit = $limit + 1
    $userSearch.ServerTimeLimit = [TimeSpan]::FromSeconds($timeoutSeconds)
    foreach ($property in @('sAMAccountName', 'name', 'userPrincipalName', 'userAccountControl', 'objectSid')) {{
        [void]$userSearch.PropertiesToLoad.Add($property)
    }}
    $results = $userSearch.FindAll()
    $truncated = $results.Count -gt $limit
    $users = @(
        foreach ($entry in ($results | Select-Object -First $limit)) {{
            $p = $entry.Properties
            if ($p['samaccountname'].Count -eq 0) {{ continue }}
            $sam = [string]$p['samaccountname'][0]
            $display = if ($p['name'].Count -gt 0) {{ [string]$p['name'][0] }} else {{ $sam }}
            $upn = if ($p['userprincipalname'].Count -gt 0) {{ [string]$p['userprincipalname'][0] }} else {{ '' }}
            if ($p['objectsid'].Count -eq 0) {{ continue }}
            $sid = ([Security.Principal.SecurityIdentifier]::new([byte[]]$p['objectsid'][0], 0)).Value
            $flags = if ($p['useraccountcontrol'].Count -gt 0) {{ [int]$p['useraccountcontrol'][0] }} else {{ 0 }}
            $enabled = (($flags -band 2) -eq 0)
            [PSCustomObject]@{{
                sam = $sam
                sid = $sid
                name = $display
                upn = $upn
                enabled = $enabled
                authorized = ($enabled -and $authorizedSams.Contains($sam))
                dc_administrator = $dcAdministratorSams.Contains($sam)
            }}
        }}
    ) | Sort-Object sam
    $results.Dispose()
    $userSearch.Dispose()
    $base.Dispose()
    $root.Dispose()
    [Console]::Out.WriteLine((ConvertTo-Json -InputObject ([PSCustomObject]@{{ domain = $domain; users = @($users); truncated = $truncated }}) -Compress -Depth 4))
}} catch {{
    [Console]::Error.WriteLine(('Active Directory user listing failed: ' + $_.Exception.GetType().FullName + ': ' + $_.Exception.Message))
    exit 1
}}
"""
        encoded = base64.b64encode(script.encode("utf-16le")).decode("ascii")
        try:
            result = subprocess.run(
                ["powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded],
                capture_output=True, text=True, encoding="utf-8", errors="replace",
                timeout=self.timeout_seconds + 3, check=False,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise DirectoryUnavailable("Windows could not query the AD user directory") from exc
        if result.returncode:
            detail = result.stderr.strip()[-1200:]
            cause = RuntimeError(detail) if detail else None
            raise DirectoryUnavailable("Windows could not query the AD user directory") from cause
        try:
            payload = json.loads(result.stdout.strip())
            users = payload.get("users") if isinstance(payload, dict) else None
            domain = payload.get("domain") if isinstance(payload, dict) else None
            truncated = payload.get("truncated") if isinstance(payload, dict) else None
            if (not isinstance(users, list) or not isinstance(domain, str) or not isinstance(truncated, bool)
                    or len(users) > limit):
                raise ValueError
            clean = []
            for user in users:
                if not isinstance(user, dict):
                    raise ValueError
                sam, sid, name, upn = (user.get("sam"), user.get("sid"),
                                       user.get("name"), user.get("upn", ""))
                if (not isinstance(sam, str) or not sam or len(sam) > 64
                        or not isinstance(sid, str) or not _SID.fullmatch(sid)
                        or not isinstance(name, str) or len(name) > 256
                        or not isinstance(upn, str) or len(upn) > 256
                        or not isinstance(user.get("enabled"), bool)
                        or not isinstance(user.get("authorized"), bool)
                        or not isinstance(user.get("dc_administrator"), bool)):
                    raise ValueError
                sid_to_bytes(sid)
                clean.append({"sam": sam, "sid": sid, "name": name, "upn": upn,
                              "enabled": user["enabled"], "authorized": user["authorized"],
                              "dc_administrator": user["dc_administrator"]})
            return {"domain": domain[:256], "users": clean, "truncated": truncated}
        except (json.JSONDecodeError, TypeError, ValueError) as exc:
            raise DirectoryUnavailable("Windows returned an invalid AD user directory response") from exc

    def _manage_user(self, operation: str, *, administrator: str, password: str,
                     username: str = "", display_name: str = "", initial_password: str = "",
                     enabled: bool = True, must_change: bool = True) -> str:
        """Perform one audited AD user change using freshly supplied admin credentials.

        The admin password is sent to a short-lived PowerShell child over stdin,
        never in its command line or logs, and is not retained by this service.
        """
        if operation not in {"create", "update", "delete", "disable", "password"}:
            raise ValueError("Unsupported AD user operation")
        if not isinstance(administrator, str) or not _USERNAME.fullmatch(administrator):
            raise ValueError("Invalid administrator account")
        if not isinstance(password, str) or not password or len(password) > 1024 or "\x00" in password:
            raise ValueError("Enter the administrator password to confirm this change")
        if operation != "create" and (not isinstance(username, str) or not _USERNAME.fullmatch(username)):
            raise ValueError("Invalid AD username")
        if operation in {"create", "update"}:
            if (not isinstance(display_name, str) or not display_name.strip() or len(display_name) > 256
                    or any(ord(char) < 32 for char in display_name)):
                raise ValueError("Enter a display name of at most 256 characters")
        if operation == "create":
            if not isinstance(username, str) or not _USERNAME.fullmatch(username):
                raise ValueError("Enter a username using letters, numbers, dot, dash, or underscore")
            if (not isinstance(initial_password, str) or len(initial_password) < 8
                    or len(initial_password) > 256 or "\x00" in initial_password):
                raise ValueError("The temporary password must be between 8 and 256 characters")
        if operation == "update" and not isinstance(enabled, bool):
            raise ValueError("Invalid account state")
        if not isinstance(must_change, bool):
            raise ValueError("Invalid password-change policy")
        if operation == "password":
            if (not isinstance(initial_password, str) or len(initial_password) < 8
                    or len(initial_password) > 256 or "\x00" in initial_password):
                raise ValueError("The new password must be between 8 and 256 characters")

        script = r"""
$ErrorActionPreference = 'Stop'
# The Active Directory module renders progress bars; keep stdout pure JSON.
$ProgressPreference = 'SilentlyContinue'
try {
    $data = ConvertFrom-Json -InputObject ([Console]::In.ReadToEnd())
    $authUser = "$($data.authority)\$($data.administrator)"
    $authType = [System.DirectoryServices.AuthenticationTypes]::Secure
    Add-Type -AssemblyName System.DirectoryServices -ErrorAction Stop
    $root = [System.DirectoryServices.DirectoryEntry]::new('LDAP://RootDSE', $authUser, [string]$data.password, $authType)
    $baseDn = [string]$root.Properties['defaultNamingContext'][0]
    $dnsDomain = (($baseDn -split ',') | Where-Object { $_ -like 'DC=*' } | ForEach-Object { $_.Substring(3) }) -join '.'
    if ([string]::IsNullOrWhiteSpace($baseDn) -or [string]::IsNullOrWhiteSpace($dnsDomain)) { throw 'domain_lookup_failed' }
    $base = [System.DirectoryServices.DirectoryEntry]::new("LDAP://$baseDn", $authUser, [string]$data.password, $authType)
    $sam = [string]$data.username
    $found = $null
    if ($data.operation -ne 'create') {
        $search = [System.DirectoryServices.DirectorySearcher]::new($base)
        $search.Filter = "(&(objectCategory=person)(objectClass=user)(sAMAccountName=$sam))"
        $search.SizeLimit = 2
        $search.ServerTimeLimit = [TimeSpan]::FromSeconds(10)
        foreach ($property in @('distinguishedName','objectSid','userAccountControl','isCriticalSystemObject')) {
            [void]$search.PropertiesToLoad.Add($property)
        }
        $result = $search.FindOne()
        $search.Dispose()
        if (-not $result) { [Console]::Out.WriteLine('{"ok":false,"error":"not_found"}'); exit 0 }
        $sid = [Security.Principal.SecurityIdentifier]::new([byte[]]$result.Properties['objectsid'][0], 0).Value
        if ($sid.EndsWith('-500') -or ($result.Properties['iscriticalsystemobject'].Count -gt 0 -and [bool]$result.Properties['iscriticalsystemobject'][0])) {
            [Console]::Out.WriteLine('{"ok":false,"error":"protected"}')
            exit 0
        }
        $userDn = [string]$result.Properties['distinguishedname'][0]
        $found = [System.DirectoryServices.DirectoryEntry]::new("LDAP://$userDn", $authUser, [string]$data.password, $authType)
        if ([string]$data.operation -in @('disable','delete','password')) {
            $found.RefreshCache(@('tokenGroups'))
            $domainSid = $sid.Substring(0, $sid.LastIndexOf('-'))
            $protectedSids = @('S-1-5-32-544', "$domainSid-512", "$domainSid-518", "$domainSid-519")
            foreach ($groupSidBytes in $found.Properties['tokenGroups']) {
                $groupSid = [Security.Principal.SecurityIdentifier]::new([byte[]]$groupSidBytes, 0).Value
                if ($protectedSids -contains $groupSid) {
                    [Console]::Out.WriteLine('{"ok":false,"error":"protected"}')
                    exit 0
                }
            }
        }
    }
    switch ([string]$data.operation) {
        'create' {
            $container = [System.DirectoryServices.DirectoryEntry]::new("LDAP://CN=Users,$baseDn", $authUser, [string]$data.password, $authType)
            $exists = [System.DirectoryServices.DirectorySearcher]::new($base)
            $exists.Filter = "(&(objectCategory=person)(objectClass=user)(sAMAccountName=$sam))"
            $exists.SizeLimit = 1
            if ($exists.FindOne()) {
                [Console]::Out.WriteLine('{"ok":false,"error":"exists"}')
                $exists.Dispose()
                exit 0
            }
            $exists.Dispose()
            $newUser = $container.Children.Add("CN=$sam", 'user')
            $newUser.Properties['sAMAccountName'].Value = $sam
            $newUser.Properties['displayName'].Value = [string]$data.display_name
            $newUser.Properties['userPrincipalName'].Value = "$sam@$dnsDomain"
            $newUser.Properties['userAccountControl'].Value = 514
            $newUser.CommitChanges()
            try {
                # A password write is refused over an unencrypted LDAP connection
                # (0x80072035), so reset the password through AD Web Services,
                # which is TLS-protected and present on every domain controller.
                Import-Module ActiveDirectory -ErrorAction Stop | Out-Null
                $adminCredential = [System.Management.Automation.PSCredential]::new(
                    $authUser, (ConvertTo-SecureString ([string]$data.password) -AsPlainText -Force))
                Set-ADAccountPassword -Identity $sam -Reset -Credential $adminCredential `
                    -NewPassword (ConvertTo-SecureString ([string]$data.initial_password) -AsPlainText -Force) -ErrorAction Stop
                Enable-ADAccount -Identity $sam -Credential $adminCredential -ErrorAction Stop
                Set-ADUser -Identity $sam -ChangePasswordAtLogon ([bool]$data.must_change) -Credential $adminCredential -ErrorAction Stop
            } catch {
                try { $container.Children.Remove($newUser); $container.CommitChanges() } catch {}
                throw
            }
            # The SID is only guaranteed readable after the object is re-fetched:
            # the creation commit and the ADWS password reset are separate calls.
            $newUser.RefreshCache(@('objectSid'))
            $sid = [Security.Principal.SecurityIdentifier]::new([byte[]]$newUser.Properties['objectSid'].Value, 0).Value
            [Console]::Out.WriteLine((ConvertTo-Json -Compress -InputObject @{ ok = $true; sid = $sid }))
            $newUser.Dispose()
            $container.Dispose()
        }
        'update' {
            $found.Properties['displayName'].Value = [string]$data.display_name
            $flags = [int]$found.Properties['userAccountControl'].Value
            if ([bool]$data.enabled) { $flags = $flags -band (-bnot 2) } else { $flags = $flags -bor 2 }
            $found.Properties['userAccountControl'].Value = $flags
            $found.CommitChanges()
            [Console]::Out.WriteLine((ConvertTo-Json -Compress -InputObject @{ ok = $true; sid = $sid }))
            $found.Dispose()
        }
        'disable' {
            $flags = [int]$found.Properties['userAccountControl'].Value
            $found.Properties['userAccountControl'].Value = $flags -bor 2
            $found.CommitChanges()
            [Console]::Out.WriteLine((ConvertTo-Json -Compress -InputObject @{ ok = $true; sid = $sid }))
            $found.Dispose()
        }
        'password' {
            # Reset through AD Web Services: LDAP/389 refuses password writes
            # (0x80072035). The user must choose a new password at next sign-in.
            Import-Module ActiveDirectory -ErrorAction Stop | Out-Null
            $adminCredential = [System.Management.Automation.PSCredential]::new(
                $authUser, (ConvertTo-SecureString ([string]$data.password) -AsPlainText -Force))
            Set-ADAccountPassword -Identity $sam -Reset -Credential $adminCredential `
                -NewPassword (ConvertTo-SecureString ([string]$data.initial_password) -AsPlainText -Force) -ErrorAction Stop
            Set-ADUser -Identity $sam -ChangePasswordAtLogon ([bool]$data.must_change) -Credential $adminCredential -ErrorAction Stop
            [Console]::Out.WriteLine((ConvertTo-Json -Compress -InputObject @{ ok = $true; sid = $sid }))
            $found.Dispose()
        }
        'delete' {
            $parent = $found.Parent
            $parent.Children.Remove($found)
            $parent.CommitChanges()
            [Console]::Out.WriteLine((ConvertTo-Json -Compress -InputObject @{ ok = $true; sid = $sid }))
            $parent.Dispose()
            $found.Dispose()
        }
    }
    $base.Dispose()
    $root.Dispose()
} catch {
    $errorText = [string]$_.Exception.Message
    if ($_.Exception.InnerException) { $errorText = $errorText + ' ' + [string]$_.Exception.InnerException.Message }
    $errorCode = if ($errorText -match '(?i)access is denied|insufficient access') { 'permission' }
                 elseif ($errorText -match '(?i)already exists|object exists') { 'exists' }
                 elseif ($errorText -match '(?i)password does not meet|complexity|history requirement|password policy|0x8007202F') { 'password_policy' }
                 else { 'failed' }
    [Console]::Out.WriteLine((ConvertTo-Json -Compress -InputObject @{
        ok = $false; error = $errorCode; detail = $errorText.Substring(0, [Math]::Min(300, $errorText.Length))
    }))
    exit 0
}
"""
        payload = {
            "operation": operation, "authority": self.config.authority, "administrator": administrator,
            "password": password, "username": username, "display_name": display_name,
            "initial_password": initial_password, "enabled": enabled,
            "must_change": must_change,
        }
        encoded_script = base64.b64encode(script.encode("utf-16le")).decode("ascii")
        try:
            result = subprocess.run(
                ["powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded_script],
                input=json.dumps(payload, ensure_ascii=True, separators=(",", ":")),
                capture_output=True, text=True, encoding="utf-8", errors="replace",
                timeout=self.timeout_seconds + 8, check=False,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise DirectoryUnavailable("Windows could not perform the AD account change") from exc
        if result.returncode:
            raise DirectoryUnavailable("Windows could not perform the AD account change")
        try:
            response = json.loads(result.stdout.strip())
        except (json.JSONDecodeError, TypeError) as exc:
            raise DirectoryUnavailable("Windows returned an invalid AD account change response") from exc
        if not isinstance(response, dict) or not isinstance(response.get("ok"), bool):
            raise DirectoryUnavailable("Windows returned an invalid AD account change response")
        if not response["ok"]:
            _reject_ad_change(operation, response)
        sid = response.get("sid")
        if not isinstance(sid, str) or not _SID.fullmatch(sid):
            raise DirectoryUnavailable("Windows returned an invalid AD account change response")
        try:
            sid_to_bytes(sid)
        except ValueError as exc:
            raise DirectoryUnavailable("Windows returned an invalid AD account SID") from exc
        return sid

    def create_user(self, *, administrator: str, password: str, username: str,
                    display_name: str, initial_password: str, must_change: bool = True) -> str:
        return self._manage_user("create", administrator=administrator, password=password,
                                username=username, display_name=display_name,
                                initial_password=initial_password, must_change=must_change)

    def update_user(self, *, administrator: str, password: str, username: str,
                    display_name: str, enabled: bool) -> str:
        return self._manage_user("update", administrator=administrator, password=password,
                                username=username, display_name=display_name, enabled=enabled)

    def disable_user(self, *, administrator: str, password: str, username: str) -> str:
        return self._manage_user("disable", administrator=administrator, password=password,
                                username=username)

    def delete_user(self, *, administrator: str, password: str, username: str) -> str:
        return self._manage_user("delete", administrator=administrator, password=password,
                                username=username)

    def set_user_password(self, *, administrator: str, password: str, username: str,
                          new_password: str, must_change: bool = True) -> str:
        """Reset a non-privileged account's password; optionally force a change."""
        return self._manage_user("password", administrator=administrator, password=password,
                                username=username, initial_password=new_password,
                                must_change=must_change)

    def set_workstation_access(self, *, administrator: str, password: str, username: str,
                               allowed_group_sids, allow: bool) -> str:
        """Grant or revoke the workstation QR right by group membership.

        Granting adds the account to the first configured sign-in group; revoking
        removes it from every configured group so no stale membership survives a
        configuration change. Membership changes go through ADWS with the
        administrator credential, matching the password paths.
        """
        if not isinstance(administrator, str) or not _USERNAME.fullmatch(administrator):
            raise ValueError("Invalid administrator account")
        if not isinstance(password, str) or not password or len(password) > 1024 or "\x00" in password:
            raise ValueError("Enter the administrator password to confirm this change")
        if not isinstance(username, str) or not _USERNAME.fullmatch(username):
            raise ValueError("Invalid AD username")
        if not isinstance(allow, bool):
            raise ValueError("Invalid access state")
        groups = []
        for sid in (allowed_group_sids or ()):
            if not isinstance(sid, str) or not _SID.fullmatch(sid):
                raise ValueError("Invalid workstation sign-in group")
            groups.append(sid)
        if not groups:
            raise ValueError("No workstation sign-in group is configured")

        script = r"""
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
try {
    $data = ConvertFrom-Json -InputObject ([Console]::In.ReadToEnd())
    $authUser = "$($data.authority)\$($data.administrator)"
    Import-Module ActiveDirectory -ErrorAction Stop | Out-Null
    $adminCredential = [System.Management.Automation.PSCredential]::new(
        $authUser, (ConvertTo-SecureString ([string]$data.password) -AsPlainText -Force))
    $target = Get-ADUser -Identity ([string]$data.username) -Credential $adminCredential `
        -Properties memberOf, objectSid -ErrorAction Stop
    $resolved = @()
    foreach ($sid in @($data.group_sids)) {
        try { $resolved += Get-ADGroup -Identity ([string]$sid) -Credential $adminCredential -ErrorAction Stop } catch { }
    }
    if ($resolved.Count -eq 0) {
        [Console]::Out.WriteLine('{"ok":false,"error":"group_missing"}')
        exit 0
    }
    if ([bool]$data.allow) {
        Add-ADGroupMember -Identity $resolved[0].DistinguishedName -Members $target.DistinguishedName `
            -Credential $adminCredential -Confirm:$false -ErrorAction Stop
    } else {
        foreach ($group in $resolved) {
            if (@($target.MemberOf) -contains $group.DistinguishedName) {
                Remove-ADGroupMember -Identity $group.DistinguishedName -Members $target.DistinguishedName `
                    -Credential $adminCredential -Confirm:$false -ErrorAction Stop
            }
        }
    }
    $sid = [string]$target.SID.Value
    [Console]::Out.WriteLine((ConvertTo-Json -Compress -InputObject @{ ok = $true; sid = $sid }))
} catch {
    $errorText = [string]$_.Exception.Message
    if ($_.Exception.InnerException) { $errorText = $errorText + ' ' + [string]$_.Exception.InnerException.Message }
    $errorCode = if ($errorText -match '(?i)access is denied|insufficient access') { 'permission' }
                 elseif ($errorText -match '(?i)cannot be found|not found|adidentitynotfoundexception') { 'not_found' }
                 else { 'failed' }
    [Console]::Out.WriteLine((ConvertTo-Json -Compress -InputObject @{
        ok = $false; error = $errorCode; detail = $errorText.Substring(0, [Math]::Min(300, $errorText.Length))
    }))
    exit 0
}
"""
        payload = {
            "authority": self.config.authority, "administrator": administrator,
            "password": password, "username": username,
            "group_sids": groups, "allow": allow,
        }
        encoded_script = base64.b64encode(script.encode("utf-16le")).decode("ascii")
        try:
            result = subprocess.run(
                ["powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded_script],
                input=json.dumps(payload, ensure_ascii=True, separators=(",", ":")),
                capture_output=True, text=True, encoding="utf-8", errors="replace",
                timeout=self.timeout_seconds + 8, check=False,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise DirectoryUnavailable("Windows could not change the workstation sign-in group") from exc
        if result.returncode:
            raise DirectoryUnavailable("Windows could not change the workstation sign-in group")
        try:
            response = json.loads(result.stdout.strip())
        except (json.JSONDecodeError, TypeError) as exc:
            raise DirectoryUnavailable("Windows returned an invalid group membership response") from exc
        if not isinstance(response, dict) or not isinstance(response.get("ok"), bool):
            raise DirectoryUnavailable("Windows returned an invalid group membership response")
        if not response["ok"]:
            _reject_ad_change("workstation", response)
        sid = response.get("sid")
        if not isinstance(sid, str) or not _SID.fullmatch(sid):
            raise DirectoryUnavailable("Windows returned an invalid AD account SID")
        try:
            sid_to_bytes(sid)
        except ValueError as exc:
            raise DirectoryUnavailable("Windows returned an invalid AD account SID") from exc
        return sid
