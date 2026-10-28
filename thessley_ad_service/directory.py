"""Read-only, certificate-validated Active Directory lookups over LDAPS."""

from __future__ import annotations

import os
import re
import ssl
import stat
from dataclasses import dataclass
from pathlib import Path

_SID = re.compile(r"^S-([0-9]+)-([0-9]+)((?:-[0-9]+)*)$")
_AUTHORITY = re.compile(r"^[A-Za-z0-9_.@-]{1,128}$")
_USERNAME = re.compile(r"^[a-z_][a-z0-9_.-]{0,31}$", re.IGNORECASE)
_DNS_NAME = re.compile(r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")


class DirectoryUnavailable(RuntimeError):
    """AD could not be queried safely; callers must fail closed."""


class PrincipalNotFound(RuntimeError):
    """The supplied SID does not identify an enabled domain user."""


@dataclass(frozen=True)
class DirectoryConfig:
    host: str
    base_dn: str
    bind_dn: str
    password_file: str
    ca_file: str
    authority: str
    port: int = 3269
    timeout_seconds: int = 5

    def __post_init__(self):
        if not isinstance(self.host, str) or not _DNS_NAME.fullmatch(self.host):
            raise ValueError("LDAPS host must be a fully qualified DNS name for certificate validation")
        if not self.base_dn or not self.bind_dn or not _AUTHORITY.fullmatch(self.authority):
            raise ValueError("Invalid AD directory configuration")
        if self.port != 3269:
            raise ValueError("Use implicit-TLS Global Catalog LDAPS on port 3269 for tokenGroups")
        if (isinstance(self.timeout_seconds, bool) or not isinstance(self.timeout_seconds, int)
                or not 1 <= self.timeout_seconds <= 15):
            raise ValueError("Directory timeout must be between 1 and 15 seconds")
        if not os.path.isabs(self.password_file) or not os.path.isabs(self.ca_file):
            raise ValueError("LDAPS credential and CA paths must be absolute")


@dataclass(frozen=True)
class DirectoryPrincipal:
    sid: str
    principal_id: str
    username: str
    authority: str
    group_sids: frozenset[str]


def sid_to_bytes(sid: str) -> bytes:
    """Encode a canonical Windows SID as the binary AD objectSid value."""
    if not isinstance(sid, str):
        raise ValueError("invalid SID")
    match = _SID.fullmatch(sid)
    if not match:
        raise ValueError("invalid SID")
    revision = int(match.group(1))
    authority = int(match.group(2))
    subauthorities = [int(value) for value in match.group(3).split("-") if value]
    if revision != 1 or not 0 <= authority < (1 << 48) or not 1 <= len(subauthorities) <= 15:
        raise ValueError("SID is outside the supported range")
    if any(not 0 <= value <= 0xFFFFFFFF for value in subauthorities):
        raise ValueError("SID is outside the supported range")
    return bytes((revision, len(subauthorities))) + authority.to_bytes(6, "big") + b"".join(
        value.to_bytes(4, "little") for value in subauthorities
    )


def sid_from_bytes(value: bytes) -> str:
    if not isinstance(value, bytes) or len(value) < 8:
        raise ValueError("invalid binary SID")
    revision, count = value[0], value[1]
    if revision == 0 or count > 15 or len(value) != 8 + 4 * count:
        raise ValueError("invalid binary SID")
    authority = int.from_bytes(value[2:8], "big")
    subauthorities = [
        str(int.from_bytes(value[8 + 4 * index : 12 + 4 * index], "little"))
        for index in range(count)
    ]
    return "S-" + str(revision) + "-" + str(authority) + "".join("-" + item for item in subauthorities)


def validate_group_sid_allowlist(values) -> frozenset[str]:
    if not isinstance(values, (set, frozenset, list, tuple)):
        raise ValueError("AD group allowlist must be a sequence of SIDs")
    result = set()
    for sid in values:
        canonical = sid_from_bytes(sid_to_bytes(sid))
        if canonical != sid:
            raise ValueError("AD group SID must use canonical decimal formatting")
        result.add(canonical)
    return frozenset(result)


def _ldap_escape_binary(value: bytes) -> str:
    return "".join(f"\\{byte:02x}" for byte in value)


def _read_bind_password(path: str) -> str:
    try:
        parent = os.stat(os.path.dirname(path), follow_symlinks=False)
        if not stat.S_ISDIR(parent.st_mode) or parent.st_uid != 0 or parent.st_mode & 0o022:
            raise DirectoryUnavailable("AD credential directory has unsafe ownership or permissions")
        info = os.stat(path, follow_symlinks=False)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o077:
            raise DirectoryUnavailable("AD bind password file has unsafe ownership or permissions")
        secret = Path(path).read_text(encoding="utf-8").rstrip("\r\n")
    except OSError as exc:
        raise DirectoryUnavailable("AD bind password file is unavailable") from exc
    if not secret or "\x00" in secret:
        raise DirectoryUnavailable("AD bind password file is empty or invalid")
    return secret


class ActiveDirectory:
    """Minimal read-only AD client. It never accepts a client-provided group list."""

    def __init__(self, config: DirectoryConfig):
        self.config = config
        try:
            ca_parent = os.stat(os.path.dirname(config.ca_file), follow_symlinks=False)
            if not stat.S_ISDIR(ca_parent.st_mode) or ca_parent.st_uid != 0 or ca_parent.st_mode & 0o022:
                raise DirectoryUnavailable("LDAPS CA directory has unsafe ownership or permissions")
            ca_stat = os.stat(config.ca_file, follow_symlinks=False)
            if not stat.S_ISREG(ca_stat.st_mode) or ca_stat.st_uid != 0 or ca_stat.st_mode & 0o022:
                raise DirectoryUnavailable("LDAPS CA file has unsafe ownership or permissions")
        except OSError as exc:
            raise DirectoryUnavailable("LDAPS CA file is unavailable") from exc

    def _connect(self):
        try:
            from ldap3 import Connection, NONE, SIMPLE, SYNC, Server, Tls

            tls = Tls(validate=ssl.CERT_REQUIRED, ca_certs_file=self.config.ca_file)
            server = Server(
                self.config.host,
                port=self.config.port,
                use_ssl=True,
                tls=tls,
                get_info=NONE,
                connect_timeout=self.config.timeout_seconds,
            )
            connection = Connection(
                server,
                user=self.config.bind_dn,
                password=_read_bind_password(self.config.password_file),
                authentication=SIMPLE,
                client_strategy=SYNC,
                auto_bind=True,
                auto_referrals=False,
                read_only=True,
                receive_timeout=self.config.timeout_seconds,
                raise_exceptions=True,
            )
            return connection
        except DirectoryUnavailable:
            raise
        except Exception as exc:
            raise DirectoryUnavailable("Could not establish a validated, read-only LDAPS connection") from exc

    def resolve_user_sid(self, sid: str) -> DirectoryPrincipal:
        """Resolve an enabled AD user by SID and return AD-computed group SIDs.

        Retrieve this only when starting a new login; do not repeat the
        tokenGroups query on each phone poll or cache its authorization result.
        """
        binary_sid = sid_to_bytes(sid)
        filter_text = f"(objectSid={_ldap_escape_binary(binary_sid)})"
        connection = self._connect()
        try:
            from ldap3 import BASE, SUBTREE

            connection.search(
                search_base=self.config.base_dn,
                search_filter=filter_text,
                search_scope=SUBTREE,
                attributes=["objectSid", "objectClass", "sAMAccountName", "userAccountControl"],
                size_limit=2,
                time_limit=self.config.timeout_seconds,
            )
            entries = connection.entries
            if len(entries) != 1:
                raise PrincipalNotFound("SID does not resolve to exactly one AD principal")
            entry = entries[0]
            attrs = {str(name).lower(): values for name, values in entry.entry_raw_attributes.items()}
            object_classes = {item.decode("utf-8", "ignore").lower() for item in attrs.get("objectclass", [])}
            if "user" not in object_classes or "computer" in object_classes:
                raise PrincipalNotFound("SID is not a user account")
            returned_sid = attrs.get("objectsid", [])
            if len(returned_sid) != 1 or sid_from_bytes(returned_sid[0]) != sid:
                raise PrincipalNotFound("AD returned a different SID")
            account_flags = attrs.get("useraccountcontrol", [])
            if len(account_flags) != 1:
                raise PrincipalNotFound("AD account flags are unavailable")
            try:
                if int(account_flags[0].decode("ascii")) & 0x2:
                    raise PrincipalNotFound("AD account is disabled")
            except (ValueError, UnicodeDecodeError) as exc:
                raise PrincipalNotFound("AD account flags are invalid") from exc
            account_names = attrs.get("samaccountname", [])
            if len(account_names) != 1:
                raise PrincipalNotFound("AD account name is unavailable")
            username = account_names[0].decode("utf-8")
            if not _USERNAME.fullmatch(username):
                raise PrincipalNotFound("AD account name is invalid")
            # AD computes tokenGroups only for a base-object query. Asking for
            # it in the initial subtree search can fail with LDAP unwillingToPerform
            # or silently leave the attribute absent, which would break group gating.
            entry_dn = str(getattr(entry, "entry_dn", ""))
            if not entry_dn or "\x00" in entry_dn:
                raise DirectoryUnavailable("AD did not return a valid user distinguished name")
            connection.search(
                search_base=entry_dn,
                search_filter="(objectClass=*)",
                search_scope=BASE,
                attributes=["tokenGroups"],
                size_limit=1,
                time_limit=self.config.timeout_seconds,
            )
            group_entries = connection.entries
            if len(group_entries) != 1:
                raise DirectoryUnavailable("AD did not return tokenGroups for the user")
            group_attrs = {
                str(name).lower(): values for name, values in group_entries[0].entry_raw_attributes.items()
            }
            if "tokengroups" not in group_attrs:
                raise DirectoryUnavailable("AD did not return tokenGroups for the user")
            group_sids = frozenset(sid_from_bytes(group) for group in group_attrs["tokengroups"])
            from .protocol import principal_id_from_sid

            return DirectoryPrincipal(
                sid=sid,
                principal_id=principal_id_from_sid(sid),
                username=username,
                authority=self.config.authority,
                group_sids=group_sids,
            )
        except (PrincipalNotFound, DirectoryUnavailable):
            raise
        except Exception as exc:
            raise DirectoryUnavailable("AD SID/group lookup failed") from exc
        finally:
            try:
                connection.unbind()
            except Exception:
                pass

    def user_in_any_group(self, sid: str, allowed_group_sids: set[str] | frozenset[str]) -> bool:
        """Check configured group SIDs against AD's transitive tokenGroups result."""
        if not allowed_group_sids:
            return False
        principal = self.resolve_user_sid(sid)
        return bool(principal.group_sids.intersection(allowed_group_sids))
