"""Small Windows-domain-admin website for centrally managed AD phone keys."""

from __future__ import annotations

import base64
import ctypes
import html
import hashlib
import io
import json
import sqlite3
import logging
import os
import re
import secrets
import threading
import time
from http.cookies import SimpleCookie
from urllib.parse import parse_qs, urlencode, urlsplit

from .phone_registry import CENTRAL_AD_MACHINE_ID
from .protocol import principal_id_from_sid

_LOG = logging.getLogger("thessley.ad.admin")
_SAM = re.compile(r"^[A-Za-z0-9_.-]{1,20}$")
_REQUEST_ID = re.compile(r"^[A-Za-z0-9_-]{8,128}$")
_CREDENTIAL_ID = re.compile(r"^[A-Za-z0-9_-]{32,64}$")
_AD_LOGON_KEY_ID = re.compile(r"^[A-Za-z0-9_-]{32,64}$")
_ADMINISTRATORS_SID = "S-1-5-32-544"
_SESSION_COOKIE = "thessley_ad_admin"
_PREAUTH_COOKIE = "thessley_ad_preauth"
_SESSION_SECONDS = 900
_SESSION_ABSOLUTE_SECONDS = 7 * 24 * 3600


class AdminSessionStore:
    """Admin web sessions that survive a service restart or reboot.

    Tokens are stored hashed; the cookie keeps its 15-minute idle timeout and
    gains a hard 7-day lifetime so a stolen cookie does not last forever.
    """

    def __init__(self, path):
        self.path = str(path)
        self._initialize()

    def _connect(self):
        connection = sqlite3.connect(self.path, timeout=5, isolation_level=None)
        connection.execute("PRAGMA busy_timeout = 5000")
        return connection

    def _initialize(self):
        connection = self._connect()
        try:
            connection.executescript(
                "CREATE TABLE IF NOT EXISTS admin_sessions ("
                " token_hash TEXT PRIMARY KEY, sid TEXT NOT NULL, username TEXT NOT NULL,"
                " csrf TEXT NOT NULL, created_at REAL NOT NULL, last_seen REAL NOT NULL)"
            )
        finally:
            connection.close()

    @staticmethod
    def _hash(token: str) -> str:
        return hashlib.sha256(token.encode("utf-8")).hexdigest()

    def create(self, token: str, session: dict) -> None:
        now = time.time()
        connection = self._connect()
        try:
            connection.execute(
                "DELETE FROM admin_sessions WHERE last_seen < ? OR created_at < ?",
                (now - _SESSION_SECONDS, now - _SESSION_ABSOLUTE_SECONDS),
            )
            connection.execute(
                "INSERT OR REPLACE INTO admin_sessions(token_hash, sid, username, csrf, created_at, last_seen) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (self._hash(token), session["sid"], session["user"], session["csrf"], now, now),
            )
        finally:
            connection.close()

    def lookup(self, token: str) -> dict | None:
        now = time.time()
        connection = self._connect()
        try:
            row = connection.execute(
                "SELECT sid, username, csrf, created_at, last_seen FROM admin_sessions WHERE token_hash = ?",
                (self._hash(token),),
            ).fetchone()
            if row is None:
                return None
            sid, username, csrf, created_at, last_seen = row
            if now - last_seen > _SESSION_SECONDS or now - created_at > _SESSION_ABSOLUTE_SECONDS:
                connection.execute("DELETE FROM admin_sessions WHERE token_hash = ?", (self._hash(token),))
                return None
            if now - last_seen > 30:
                connection.execute("UPDATE admin_sessions SET last_seen = ? WHERE token_hash = ?",
                                   (now, self._hash(token)))
            return {"sid": sid, "user": username, "csrf": csrf, "last": time.monotonic()}
        except sqlite3.Error:
            return None
        finally:
            connection.close()

    def delete(self, token: str) -> None:
        connection = self._connect()
        try:
            connection.execute("DELETE FROM admin_sessions WHERE token_hash = ?", (self._hash(token),))
        finally:
            connection.close()


class WindowsAdminLogin:
    """Validate a domain password without retaining it; require DC Administrators."""

    @staticmethod
    def authenticate(username: str, password: str, authority: str) -> str | None:
        if os.name != "nt" or not _SAM.fullmatch(username) or not password or len(password) > 1024:
            return None
        advapi = ctypes.WinDLL("advapi32", use_last_error=True)
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        token = ctypes.c_void_p()
        advapi.LogonUserW.argtypes = [ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_wchar_p,
                                      ctypes.c_ulong, ctypes.c_ulong, ctypes.POINTER(ctypes.c_void_p)]
        advapi.LogonUserW.restype = ctypes.c_int
        advapi.CheckTokenMembership.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_int)]
        advapi.CheckTokenMembership.restype = ctypes.c_int
        advapi.ConvertStringSidToSidW.argtypes = [ctypes.c_wchar_p, ctypes.POINTER(ctypes.c_void_p)]
        advapi.ConvertStringSidToSidW.restype = ctypes.c_int
        advapi.GetTokenInformation.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p,
                                               ctypes.c_ulong, ctypes.POINTER(ctypes.c_ulong)]
        advapi.GetTokenInformation.restype = ctypes.c_int
        advapi.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_wchar_p)]
        advapi.ConvertSidToStringSidW.restype = ctypes.c_int
        kernel.LocalFree.argtypes = [ctypes.c_void_p]
        kernel.LocalFree.restype = ctypes.c_void_p
        kernel.CloseHandle.argtypes = [ctypes.c_void_p]
        kernel.CloseHandle.restype = ctypes.c_int
        if not advapi.LogonUserW(
            username, authority, password, 3, 0, ctypes.byref(token)
        ):
            return None
        sid_ptr = ctypes.c_void_p()
        try:
            if not advapi.ConvertStringSidToSidW(_ADMINISTRATORS_SID, ctypes.byref(sid_ptr)):
                return None
            member = ctypes.c_int(0)
            if not advapi.CheckTokenMembership(token, sid_ptr, ctypes.byref(member)) or not member.value:
                return None
            # Resolve the authenticated token SID for audit display, without
            # impersonating the request or retaining its credentials.
            needed = ctypes.c_ulong(0)
            advapi.GetTokenInformation(token, 1, None, 0, ctypes.byref(needed))
            if not needed.value or needed.value > 65536:
                return None
            buffer = ctypes.create_string_buffer(needed.value)
            if not advapi.GetTokenInformation(token, 1, buffer, needed.value, ctypes.byref(needed)):
                return None
            user_sid = ctypes.cast(buffer, ctypes.POINTER(ctypes.c_void_p))[0]
            sid_text = ctypes.c_wchar_p()
            if not advapi.ConvertSidToStringSidW(user_sid, ctypes.byref(sid_text)):
                return None
            try:
                return sid_text.value
            finally:
                kernel.LocalFree(sid_text)
        finally:
            if sid_ptr:
                kernel.LocalFree(sid_ptr)
            kernel.CloseHandle(token)


class AdminWeb:
    """Cookie-session management UI, mounted under /admin on the DC HTTPS API."""

    PAGE_SIZE = 20

    def __init__(self, *, directory, phones, challenges, allowed_group_sids, authority: str,
                 public_host: str, certificate_fingerprint: str, login_policy=None, machines=None,
                 ad_logon_keys=None, log_path=None, session_store=None):
        self.directory = directory
        self.phones = phones
        self.challenges = challenges
        self.allowed_group_sids = frozenset(allowed_group_sids)
        self.log_path = log_path
        self.session_store = session_store
        self.authority = authority
        self.public_host = public_host
        self.certificate_fingerprint = certificate_fingerprint
        self.login_policy = login_policy
        self.machines = machines
        self.ad_logon_keys = ad_logon_keys
        self._sessions: dict[str, dict] = {}
        self._preauth: dict[str, float] = {}
        self._login_attempts: dict[str, list[float]] = {}
        self._enrollment_qrs: dict[str, tuple[str, str, float]] = {}
        self._ad_logon_key_qrs: dict[str, tuple[str, str, float]] = {}
        self._qr_logins: dict[str, dict] = {}
        self._lock = threading.RLock()

    @staticmethod
    def _json(status: int, payload: dict):
        raw = json.dumps(payload, ensure_ascii=True, separators=(",", ":")).encode("utf-8")
        return status, [("Content-Type", "application/json; charset=utf-8"),
                        ("Cache-Control", "no-store"),
                        ("X-Content-Type-Options", "nosniff"),
                        ("Content-Length", str(len(raw)))], raw

    @staticmethod
    def _response(status: int, body: str, content_type: str = "text/html; charset=utf-8",
                  extra_headers: tuple[tuple[str, str], ...] = (),
                  script_nonce: str | None = None) -> tuple[int, list[tuple[str, str]], bytes]:
        data = body.encode("utf-8")
        csp = ("default-src 'none'; img-src data:; style-src 'unsafe-inline'; "
               "connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
        if isinstance(script_nonce, str) and re.fullmatch(r"[A-Za-z0-9_-]{16,64}", script_nonce):
            csp += f"; script-src 'nonce-{script_nonce}'"
        headers = [
            ("Content-Type", content_type),
            ("Cache-Control", "no-store"),
            ("X-Content-Type-Options", "nosniff"),
            ("Referrer-Policy", "no-referrer"),
            ("Strict-Transport-Security", "max-age=31536000"),
            ("Content-Security-Policy", csp),
            ("Content-Length", str(len(data))),
            ("Connection", "close"),
        ]
        headers.extend(extra_headers)
        return status, headers, data

    @staticmethod
    def _icon(name: str, *, decorative: bool = True) -> str:
        paths = {
            "shield": '<path d="M12 3 20 6v5c0 5-3.4 8.3-8 10-4.6-1.7-8-5-8-10V6l8-3Z"/><path d="m9 12 2 2 4-4"/>',
            "users": '<path d="M16 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="10" cy="7" r="4"/><path d="M20 21v-2a4 4 0 0 0-3-3.9M16 3.2a4 4 0 0 1 0 7.6"/>',
            "monitor": '<rect x="3" y="4" width="18" height="13" rx="2"/><path d="M8 21h8m-4-4v4"/>',
            "admin": '<path d="M12 3 20 6v5c0 5-3.4 8.3-8 10-4.6-1.7-8-5-8-10V6l8-3Z"/><path d="M12 8v4m0 4h.01"/>',
            "phone": '<rect x="6" y="2.5" width="12" height="19" rx="2.2"/><path d="M10 18.5h4"/>',
            "key": '<circle cx="8" cy="15" r="4"/><path d="m11 12 8-8 2 2-2 2 2 2-3 3-2-2-3 3"/>',
            "lock": '<rect x="4" y="10" width="16" height="11" rx="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3m-4 5v2"/>',
            "plus": '<path d="M12 5v14M5 12h14"/>',
            "logout": '<path d="M10 17l5-5-5-5m5 5H3"/><path d="M12 3h6a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2h-6"/>',
            "settings": '<circle cx="12" cy="12" r="3"/><path d="m19.4 15 .1.1 1.4 1.1-1.4 2.4-1.7-.7a8 8 0 0 1-1.7 1l-.3 1.8h-2.8l-.3-1.8a8 8 0 0 1-1.7-1l-1.7.7-1.4-2.4L7.3 15a8 8 0 0 1 0-2l-1.4-1.1 1.4-2.4 1.7.7a8 8 0 0 1 1.7-1l.3-1.8h2.8l.3 1.8a8 8 0 0 1 1.7 1l1.7-.7 1.4 2.4-1.4 1.1a8 8 0 0 1-.1 2Z"/>',
            "check": '<path d="m5 12 4 4L19 6"/>',
            "warning": '<path d="m10.3 3.9-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.7-3.1l-8-14a2 2 0 0 0-3.4 0Z"/><path d="M12 9v4m0 4h.01"/>',
            "chevron": '<path d="m9 18 6-6-6-6"/>',
        }
        if name not in paths:
            return ""
        aria = ' aria-hidden="true" focusable="false"' if decorative else ' role="img"'
        return f'<svg class="icon icon-{name}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"{aria}>{paths[name]}</svg>'

    @staticmethod
    def _page(title: str, content: str) -> str:
        back_link = ""
        if title == "Approve admin sign-in":
            back_link = f'<nav class="back-link"><a class="button secondary small" href="/admin/">{AdminWeb._icon("chevron")} Back to sign-in</a></nav>'
        elif title not in ("Administrator sign-in", "AD accounts") and 'href="/admin/' not in content:
            back_link = f'<nav class="back-link"><a class="button secondary small" href="/admin/">{AdminWeb._icon("chevron")} Back to accounts</a></nav>'
        return """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>""" + html.escape(title) + """ · Thessley AD</title>
<style>
:root{color-scheme:dark;--ink:#edf3f8;--muted:#aab8c6;--line:#2d4051;--blue:#80bdff;--bg:#0b1219;--surface:#121d27;--raised:#192633;--field:#0d1720;--good:#8be0ad;--warn:#f2c66d;--bad:#ff8991}
*{box-sizing:border-box}body{margin:0;background:radial-gradient(ellipse at 50% -30%,#172b3c 0,transparent 55%),var(--bg);color:var(--ink);font:16px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif;overflow-wrap:anywhere}
main{width:min(100% - 32px,960px);margin:24px auto 48px}.brand{display:flex;align-items:center;gap:9px;font-weight:750;color:var(--blue);font-size:1.06rem;letter-spacing:.01em;margin-bottom:22px;text-decoration:none}.brand:hover,.brand:focus-visible{color:#b9dcff;text-decoration:underline;text-underline-offset:3px}.brand-mark{width:34px;height:34px;display:grid;place-items:center;border:1px solid #33506a;border-radius:11px;background:#13283a}.icon{width:18px;height:18px;flex:none}.brand-mark .icon{width:21px;height:21px}
h1{font-size:clamp(1.4rem,4vw,1.8rem);line-height:1.2;margin:0 0 1rem;letter-spacing:-.02em}h1 .icon{vertical-align:-.12em;margin-right:5px}h2{font-size:1.12rem;line-height:1.3;margin:0}.muted{color:var(--muted)}p{margin:.65rem 0 1rem}
.card{min-width:0;overflow-wrap:anywhere;background:linear-gradient(145deg,#15222d,var(--surface));border:1px solid var(--line);border-radius:16px;padding:20px;margin:14px 0;box-shadow:0 10px 28px #0003}
.page-head{display:flex;justify-content:space-between;align-items:center;gap:12px;margin:0 0 14px}.page-head>div,.page-actions,.row{min-width:0}.page-head h1{margin:0}.page-actions,.row{display:flex;gap:9px;align-items:center;flex-wrap:wrap}.page-actions form,.account-actions form,.inline-form{margin:0}
.page-actions .button,.page-actions button{padding-inline:11px}
.header-actions{display:flex;gap:9px;align-items:center;justify-content:flex-end;flex-wrap:wrap;margin-left:auto}.header-actions form{margin:0}
.account-card{padding:0;overflow:hidden;scroll-margin-top:1.5rem}.account-card:target{outline:2px solid var(--blue);outline-offset:2px;border-color:var(--blue)}.account-top{display:flex;justify-content:space-between;align-items:flex-start;gap:14px;padding:18px 20px}.account-name{display:flex;align-items:flex-start;gap:12px;min-width:0}.account-avatar{width:42px;height:42px;display:grid;place-items:center;flex:none;border-radius:14px;background:#20384a;color:#acd5fa}.account-heading{min-width:0}.account-heading h2{overflow-wrap:anywhere}.account-id{color:var(--muted);font-size:.9rem;overflow-wrap:anywhere}.rights{display:flex;gap:7px;flex-wrap:wrap;margin-top:9px}.trust-summary{display:grid;gap:7px;min-width:150px}.trust-label{display:block;color:var(--muted);font-size:.7rem;font-weight:750;letter-spacing:.08em;text-transform:uppercase}.trust-icons{display:flex;gap:5px;flex-wrap:wrap}.trust-icons .badge{font-size:.75rem;padding:4px 7px}.badge{display:inline-flex;align-items:center;gap:6px;border-radius:999px;padding:5px 9px;background:#263744;color:#dce7f0;font-size:.8rem;line-height:1.25;font-weight:700}.badge .icon{width:15px;height:15px}.badge.yes{background:#153a2a;color:var(--good)}.badge.no{background:#3d2226;color:#ffadb2}.badge.medium{background:#44391f;color:var(--warn)}.badge.neutral{background:#293541;color:#c6d1db}
.account-actions{display:flex;gap:8px;flex-wrap:wrap;padding:0 20px 16px}.account-details{border-top:1px solid var(--line);padding:0 20px}.account-details details{border-bottom:1px solid #263745}.account-details details:last-child{border-bottom:0}.account-details summary{display:flex;align-items:center;gap:9px;min-height:50px;cursor:pointer;list-style:none;font-weight:700}.account-details summary::-webkit-details-marker{display:none}.account-details summary::after{content:"";width:8px;height:8px;margin-left:8px;border-right:2px solid var(--muted);border-bottom:2px solid var(--muted);transform:rotate(45deg);transition:transform .16s}.account-details details[open] summary::after{transform:rotate(225deg)}.summary-count{margin-left:auto;color:var(--muted);font-size:.88rem;font-weight:600}.detail-body{padding:0 0 14px 28px}.key-item{display:flex;justify-content:space-between;align-items:center;gap:14px;padding:12px;margin:8px 0;border:1px solid #2a3b49;border-radius:12px;background:#0f1922}.key-main{min-width:0}.key-title{font-weight:700;overflow-wrap:anywhere}.key-meta{font-size:.86rem;color:var(--muted);overflow-wrap:anywhere}.key-actions{margin-top:8px}.empty{font-size:.92rem;color:var(--muted);padding:3px 0}.help details{border-radius:12px}.help summary{display:flex;align-items:center;gap:9px;cursor:pointer;font-weight:700}.help p{color:var(--muted);margin-bottom:0}.qr-login{text-align:center;max-width:600px;margin:0 auto;padding:0 16px}.qr-login .card{text-align:center}.qr-login .status-line{justify-content:center}.qr-login .button{margin-inline:auto}.log-card{padding:0}.log-list{list-style:none;margin:0;padding:0}.log-row{display:grid;grid-template-columns:auto 76px minmax(0,1fr);gap:10px;align-items:baseline;padding:10px 16px;border-bottom:1px solid #223141;font-size:.9rem}.log-row:last-child{border-bottom:0}.log-when{color:var(--muted);font-variant-numeric:tabular-nums;font-size:.82rem}.log-msg{overflow-wrap:anywhere}.log-detail{display:block;color:var(--muted);font-size:.8rem;margin-top:2px}.log-tail{margin:0;max-height:70vh;overflow:auto;padding:1rem;border-radius:10px;background:#0d1720;color:#dbe7f2;font-size:.84rem;line-height:1.45}.log-tail code{white-space:pre-wrap;overflow-wrap:anywhere}
.search-tools{margin:14px 0}.search-row{display:flex;align-items:center;gap:8px}.search-row input{flex:1;min-width:0}.search-row button{flex:none}.empty-results[hidden]{display:none}.empty-results{color:var(--muted)}
.form-actions{display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin:12px 0}.form-actions form{margin:0}.form-actions button,.form-actions .button{margin:0}
label{display:block;font-weight:650;margin:12px 0 5px}label.check-row{display:flex;align-items:center;gap:9px;font-weight:600}label.check-row input{width:auto;margin:0}input,select{font:inherit;padding:10px 12px;border:1px solid #485d70;border-radius:9px;width:100%;max-width:100%;background:var(--field);color:var(--ink)}input:focus-visible,select:focus-visible,button:focus-visible,.button:focus-visible,summary:focus-visible{outline:3px solid #9acbff;outline-offset:2px}
button,.button{font:inherit;font-weight:700;background:var(--blue);color:#071522;border:0;border-radius:10px;height:46px;min-height:46px;padding:0 17px;cursor:pointer;text-decoration:none;display:inline-flex;align-items:center;justify-content:center;gap:8px;line-height:1.2;white-space:nowrap}
button:hover,.button:hover{filter:brightness(1.08)}button.danger,.button.danger{background:#71343b;color:#ffe7e9;border:1px solid #9e4d55}.button.secondary,button.secondary{background:#213545;border:1px solid #3b566c;color:#d9ebfa}.small{font-size:.9rem;height:46px;min-height:46px;padding:0 13px}form>.danger+.button{margin-left:8px}.qr-wrap{display:flex;justify-content:center;align-items:center;width:100%;max-width:100%;overflow:hidden;margin:14px 0}.qr{display:block;width:100%;max-width:min(320px,calc(100vw - 64px));height:auto;aspect-ratio:1;object-fit:contain;background:#fff;border:1px solid var(--line);border-radius:10px;padding:8px;margin:0}.back-link{margin:0 0 12px}.back-link .icon{transform:rotate(180deg)}
code{overflow-wrap:anywhere}.status{font-weight:700}.error{background:#351b20;border-color:#7b343e}.success{background:#183324;border-color:#35714b}.status-line{display:flex;align-items:center;gap:8px}.icon-good{color:var(--good)}.icon-warn{color:var(--warn)}.icon-bad{color:var(--bad)}
@media(max-width:680px){.log-row{grid-template-columns:auto minmax(0,1fr);row-gap:4px;padding:10px 12px}.log-msg{grid-column:1 / -1}.log-when{justify-self:end}.log-card{margin:10px 0}main{width:min(100% - 24px,960px);margin:14px auto 32px}.brand{margin-bottom:17px}.card{padding:16px;margin:11px 0;border-radius:14px}.page-head{align-items:flex-start}.page-head h1{max-width:65%}.header-actions{width:100%;justify-content:flex-start;margin-left:0}.header-actions form,.header-actions .button{flex:0 0 auto}.account-top{padding:16px;display:block}.account-name{gap:10px}.account-avatar{width:38px;height:38px;border-radius:12px}.trust-summary{display:flex;gap:15px;margin:12px 0 0 48px}.trust-summary>div{min-width:0}.rights{gap:6px}.badge{font-size:.76rem;padding:5px 8px}.account-actions{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:8px;padding:0 16px 14px}.account-actions form,.account-actions>.button{min-width:0;width:100%;margin:0}.account-actions button,.account-actions>.button{width:100%;min-height:48px;white-space:normal;text-align:center;padding:9px 8px}.account-details{padding:0 16px}.detail-body{padding-left:0}.key-item{align-items:flex-start;display:block}.key-actions form,.key-actions button{width:100%}.page-actions{gap:7px}.page-actions button,.page-actions .button{min-height:46px}.row{gap:8px}.admin-user-form input,.admin-user-form select{font-size:16px}.admin-user-form .form-actions>*{flex:1 1 145px;min-height:48px}}
@media(max-width:390px){main{width:calc(100% - 20px)}.page-head{display:block}.page-head h1{max-width:none;margin-bottom:10px}.page-actions>*{flex:1}.page-actions button,.page-actions .button{width:100%;font-size:.9rem}.account-details summary{font-size:.95rem}.form-actions>*{flex:1 1 100%}.form-actions button,.form-actions .button{width:100%}}
@media(max-width:340px){.account-actions{grid-template-columns:minmax(0,1fr)}}
</style></head><body><main><a class="brand" href="/" aria-label="Thessley Active Directory home"><span class="brand-mark">""" + AdminWeb._icon("shield") + """</span><span>Thessley <span class="muted">· Active Directory</span></span></a>""" + back_link + content + "</main></body></html>"

    @staticmethod
    def _cookie(headers, name: str) -> str:
        cookie = SimpleCookie()
        try:
            cookie.load(headers.get("Cookie", ""))
            return cookie[name].value if name in cookie else ""
        except Exception:
            return ""

    def _session(self, headers) -> tuple[str, dict] | tuple[None, None]:
        token = self._cookie(headers, _SESSION_COOKIE)
        if self.session_store is not None:
            if not token:
                return None, None
            session = self.session_store.lookup(token)
            return (token, session) if session else (None, None)
        now = time.monotonic()
        with self._lock:
            session = self._sessions.get(token)
            if not session:
                return None, None
            if now - session["last"] > _SESSION_SECONDS:
                self._sessions.pop(token, None)
                return None, None
            session["last"] = now
            return token, session

    @staticmethod
    def _form(raw_body: bytes) -> dict[str, str] | None:
        if len(raw_body) > 16 * 1024:
            return None
        try:
            parsed = parse_qs(raw_body.decode("utf-8"), keep_blank_values=True, strict_parsing=True,
                              max_num_fields=16)
        except (UnicodeDecodeError, ValueError):
            return None
        if any(len(values) != 1 for values in parsed.values()):
            return None
        return {key: values[0] for key, values in parsed.items()}

    @staticmethod
    def _cookie_header(name: str, value: str, *, path: str = "/admin", max_age: int = _SESSION_SECONDS) -> tuple[str, str]:
        return ("Set-Cookie", f"{name}={value}; Path={path}; Max-Age={max_age}; Secure; HttpOnly; SameSite=Strict")

    def handle(self, method: str, target: str, headers, body: bytes, client_ip: str):
        try:
            parsed = urlsplit(target)
        except ValueError:
            return self._response(400, self._page("Bad request", "<section class=card>Invalid request.</section>"))
        if parsed.path != "/" and parsed.path != "/admin" and not parsed.path.startswith("/admin/"):
            return None
        if parsed.query and ("#" in target or len(parsed.query) > 512):
            return self._response(400, self._page("Bad request", "<section class=card>Invalid request.</section>"))
        if method not in ("GET", "POST"):
            return self._response(405, self._page("Method not allowed", "<section class=card>Method not allowed.</section>"))
        if method == "GET":
            return self._get(parsed.path, parsed.query, headers, client_ip)
        if headers.get_content_type() != "application/x-www-form-urlencoded":
            return self._response(415, self._page("Unsupported request", "<section class=card>Unsupported request.</section>"))
        form = self._form(body)
        if form is None:
            return self._response(400, self._page("Bad request", "<section class=card>Invalid form.</section>"))
        return self._post(parsed.path, form, headers, client_ip)

    _NOTICES = {
        "user-created": "AD user created.",
        "user-updated": "AD user updated.",
        "user-password": "AD password changed.",
        "user-deleted": "AD user deleted and its Thessley keys revoked.",
        "phone-revoked": "Phone revoked. Linked AD sign-in keys were revoked with it.",
        "logon-key-revoked": "AD sign-in key revoked.",
        "enrollment-confirmed": "Phone enrollment confirmed. The account is active on paired PCs.",
        "ad-key-confirmed": "AD sign-in key confirmed and active.",
        "enrollment-cancelled": "Phone enrollment cancelled.",
        "ad-key-enrollment-cancelled": "AD sign-in key enrollment cancelled.",
        "workstation-qr-allowed": "Workstation QR allowed. The account can now use QR sign-in at paired workstations.",
        "workstation-qr-revoked": "Workstation QR revoked. The account can no longer sign in at paired workstations.",
    }

    @classmethod
    def _notice_text(cls, notice: str) -> str:
        return cls._NOTICES.get(notice, "")

    def _get(self, path: str, query: str, headers, client_ip: str):
        if path == "/":
            return self._response(303, "", extra_headers=(("Location", "/admin/"),))
        if path == "/admin/account":
            token, session = self._session(headers)
            if not session:
                return self._login_page(headers)
            params = parse_qs(query, keep_blank_values=True)
            sid_values = params.get("sid", [])
            if len(sid_values) != 1 or not re.fullmatch(r"S-1-(?:[0-9]+-)+[0-9]+", sid_values[0]):
                return self._response(400, self._page("AD account", '<section class="card error">Invalid account reference.</section>'))
            notice = params.get("notice", [""])[0] if len(params.get("notice", [])) == 1 else ""
            return self._directory_page(session, notice=self._notice_text(notice), single_sid=sid_values[0])
        if path in ("/admin", "/admin/"):
            token, session = self._session(headers)
            if not session:
                return self._login_page(headers)
            params = parse_qs(query, keep_blank_values=True)
            notice = params.get("notice", [""])[0] if len(params.get("notice", [])) == 1 else ""
            query_text = params.get("q", [""])[0] if len(params.get("q", [])) == 1 else ""
            page_value = params.get("page", ["1"])[0] if len(params.get("page", [])) == 1 else "1"
            page_number = int(page_value) if page_value.isdigit() else 1
            return self._directory_page(session, notice=self._notice_text(notice),
                                        page=page_number, query=query_text)
        if path == "/admin/policy":
            token, session = self._session(headers)
            if not session:
                return self._login_page(headers)
            return self._policy_page(session)
        if path in ("/admin/enrollment-status", "/admin/ad-logon-key-status"):
            token, session = self._session(headers)
            if not session:
                return self._json(401, {"status": "unauthenticated"})
            params = parse_qs(query, keep_blank_values=True)
            request_ids = params.get("id", [])
            if len(request_ids) != 1 or not _REQUEST_ID.fullmatch(request_ids[0]):
                return self._json(400, {"status": "invalid"})
            if path == "/admin/enrollment-status":
                state = self.phones.enrollment_status(
                    machine_id=CENTRAL_AD_MACHINE_ID, request_id=request_ids[0])
            else:
                state = (self.ad_logon_keys.enrollment_status(request_ids[0])
                         if self.ad_logon_keys is not None else None)
            return self._json(200, {"status": state["status"] if state else "gone"})
        if path == "/admin/log":
            token, session = self._session(headers)
            if not session:
                return self._login_page(headers)
            params = parse_qs(query, keep_blank_values=True)
            page_value = params.get("page", ["1"])[0] if len(params.get("page", [])) == 1 else "1"
            return self._log_page(session, page=int(page_value) if page_value.isdigit() else 1)
        if path == "/admin/qr-status":
            params = parse_qs(query, keep_blank_values=True)
            request_ids = params.get("id", [])
            if len(request_ids) != 1 or not _REQUEST_ID.fullmatch(request_ids[0]):
                return self._json(400, {"status": "invalid"})
            request_id = request_ids[0]
            cookie_nonce = self._cookie(headers, _PREAUTH_COOKIE)
            with self._lock:
                pending = self._qr_logins.get(request_id)
            if (not pending or not secrets.compare_digest(cookie_nonce, pending["preauth"])
                    or not secrets.compare_digest(client_ip, pending["client_ip"])
                    or pending["expires_at"] <= time.time()):
                with self._lock:
                    self._qr_logins.pop(request_id, None)
                return self._json(200, {"status": "expired"})
            status = self.challenges.peek_result(
                machine_id=CENTRAL_AD_MACHINE_ID, request_id=request_id) or "pending"
            return self._json(200, {"status": status})
        if path == "/admin/qr-login":
            params = parse_qs(query, keep_blank_values=True)
            request_ids = params.get("id", [])
            if len(request_ids) != 1 or not _REQUEST_ID.fullmatch(request_ids[0]):
                return self._login_page(headers, "That phone sign-in request is invalid or expired.")
            return self._qr_login_page(request_ids[0], headers, client_ip)
        token, session = self._session(headers)
        if not session:
            return self._login_page(headers)
        if path == "/admin/users/new":
            return self._user_form(session)
        if path == "/admin/user/password":
            params = parse_qs(query, keep_blank_values=True)
            sid_values = params.get("sid", [])
            if len(sid_values) != 1 or not re.fullmatch(r"S-1-(?:[0-9]+-)+[0-9]+", sid_values[0]):
                return self._response(400, self._page("AD user", '<section class="card error">Invalid account reference.</section>'))
            user = self._find_user(sid_values[0])
            if not user:
                return self._response(404, self._page("AD user", '<section class="card error">Account not found in Active Directory.</section>'))
            if secrets.compare_digest(sid_values[0], session["sid"]):
                return self._response(400, self._page("Change AD password", '<section class="card error">Use your own sign-in to change your password.</section>'))
            if user.get("dc_administrator") or sid_values[0].endswith("-500"):
                return self._response(403, self._page("Change AD password", '<section class="card error">Passwords for privileged and built-in administrator accounts cannot be changed here. Use a separate AD administration tool.</section>'))
            return self._user_password_page(session, user)
        if path == "/admin/workstation-qr":
            params = parse_qs(query, keep_blank_values=True)
            sid_values = params.get("sid", [])
            allow_values = params.get("action", [])
            if (len(sid_values) != 1 or not re.fullmatch(r"S-1-(?:[0-9]+-)+[0-9]+", sid_values[0])
                    or allow_values != ["allow"] and allow_values != ["revoke"]):
                return self._response(400, self._page("Workstation QR", '<section class="card error">Invalid access change.</section>'))
            user = self._find_user(sid_values[0])
            if not user:
                return self._response(404, self._page("Workstation QR", '<section class="card error">Account not found in Active Directory.</section>'))
            if secrets.compare_digest(sid_values[0], session["sid"]):
                return self._response(403, self._page("Workstation QR", '<section class="card error">You cannot change your own workstation sign-in right.</section>'))
            if user.get("dc_administrator"):
                return self._response(400, self._page("Workstation QR", '<section class="card error">This account already signs in as a DC administrator; its workstation right is controlled by group membership outside this page.</section>'))
            return self._workstation_qr_page(session, user, allow=allow_values == ["allow"])
        if path in ("/admin/user/edit", "/admin/user/delete"):
            params = parse_qs(query, keep_blank_values=True)
            sid_values = params.get("sid", [])
            if len(sid_values) != 1 or not re.fullmatch(r"S-1-(?:[0-9]+-)+[0-9]+", sid_values[0]):
                return self._response(400, self._page("AD user", '<section class="card error">Invalid account reference.</section>'))
            user = self._find_user(sid_values[0])
            if not user:
                return self._response(404, self._page("AD user", '<section class="card error">Account not found in Active Directory.</section>'))
            return (self._user_form(session, user=user) if path == "/admin/user/edit"
                    else self._user_delete_page(session, user))
        if path == "/admin/enrollment":
            params = parse_qs(query, keep_blank_values=True)
            request_ids = params.get("id", [])
            if len(request_ids) != 1 or not _REQUEST_ID.fullmatch(request_ids[0]):
                return self._response(400, self._page("Enrollment", "<section class=card>Invalid enrollment ID.</section>"))
            qr_data, app_link, _expires = self._enrollment_qrs.get(request_ids[0], ("", "", 0))
            return self._enrollment_page(request_ids[0], session, qr_data=qr_data, app_link=app_link,
                                         sid=_query_sid(params))
        if path == "/admin/ad-logon-key-enrollment":
            params = parse_qs(query, keep_blank_values=True)
            request_ids = params.get("id", [])
            if len(request_ids) != 1 or not _REQUEST_ID.fullmatch(request_ids[0]):
                return self._response(400, self._page("AD key enrollment", "<section class=card>Invalid enrollment ID.</section>"))
            qr_data, app_link, _expires = self._ad_logon_key_qrs.get(request_ids[0], ("", "", 0))
            return self._ad_logon_key_enrollment_page(
                request_ids[0], session, qr_data=qr_data, app_link=app_link,
                sid=_query_sid(params),
            )
        if path == "/admin/logout":
            return self._response(405, self._page("Sign out", "<section class=card>Use the sign-out button.</section>"))
        return self._response(404, self._page("Not found", "<section class=card>Page not found.</section>"))

    def _login_page(self, headers, message: str = ""):
        nonce = self._cookie(headers, _PREAUTH_COOKIE)
        now = time.monotonic()
        with self._lock:
            self._preauth = {key: expiry for key, expiry in self._preauth.items() if expiry > now}
            if nonce not in self._preauth:
                nonce = secrets.token_urlsafe(24)
                self._preauth[nonce] = now + 300
        alert = f'<section class="card error">{html.escape(message)}</section>' if message else ""
        body = alert + f"""<h1>Administrator sign-in</h1><section class="card">
<h2>QR approval required</h2>
<p class="muted">Sign in with Thessley Passkey. Only a phone already enrolled centrally for this {html.escape(self.authority)} administrator account can open this page.</p>
<form method="post" action="/admin/qr-login"><input type="hidden" name="preauth" value="{html.escape(nonce)}">
<label for="qr-user">Account name (without the domain prefix)</label><input id="qr-user" name="user" autocomplete="username" required maxlength="20">
<p><button type="submit">Continue to QR approval</button></p></form>
<p class="muted small">Password sign-in is disabled. The phone must approve each new web session.</p></section>"""
        return self._response(200, self._page("Administrator sign-in", body), extra_headers=(self._cookie_header(_PREAUTH_COOKIE, nonce, max_age=300),))

    def _consume_login_preauth(self, form: dict[str, str], headers, client_ip: str) -> bool:
        cookie_nonce = self._cookie(headers, _PREAUTH_COOKIE)
        supplied_nonce = form.get("preauth", "")
        with self._lock:
            expiry = self._preauth.pop(cookie_nonce, 0)
            attempts = [t for t in self._login_attempts.get(client_ip, []) if time.monotonic() - t < 60]
            if cookie_nonce != supplied_nonce or not expiry or expiry <= time.monotonic() or len(attempts) >= 6:
                self._login_attempts[client_ip] = attempts
                return False
            attempts.append(time.monotonic())
            self._login_attempts[client_ip] = attempts
        return True

    def _new_admin_session(self, sid: str, username: str, client_ip: str, method: str):
        token = secrets.token_urlsafe(32)
        csrf = secrets.token_urlsafe(32)
        with self._lock:
            session = {"sid": sid, "user": username, "csrf": csrf, "last": time.monotonic()}
            self._sessions[token] = session
            if self.session_store is not None:
                self.session_store.create(token, session)
        _LOG.info("admin_login_ok method=%s sid=%s source=%s", method, sid, client_ip)
        return self._response(303, "", extra_headers=(
            ("Location", "/admin/"), self._cookie_header(_SESSION_COOKIE, token),
            ("Set-Cookie", f"{_PREAUTH_COOKIE}=; Path=/admin; Max-Age=0; Secure; HttpOnly; SameSite=Strict"),
        ))

    def _qr_admin_principal(self, username: str):
        if not isinstance(username, str) or not _SAM.fullmatch(username):
            return None
        try:
            principal = self.directory.resolve_username(username)
        except Exception:
            return None
        if (principal.username.casefold() != username.casefold()
                or principal.authority.casefold() != self.authority.casefold()
                or _ADMINISTRATORS_SID not in principal.group_sids):
            return None
        return principal

    def _start_qr_admin_login(self, form: dict[str, str], headers, client_ip: str):
        if not self._consume_login_preauth(form, headers, client_ip):
            return self._login_page(headers, "Sign-in request expired or rate limit reached. Refresh and try again.")
        now = time.time()
        with self._lock:
            self._qr_logins = {key: item for key, item in self._qr_logins.items() if item["expires_at"] > now}
            per_ip = sum(item["client_ip"] == client_ip for item in self._qr_logins.values())
            if per_ip >= 3 or len(self._qr_logins) >= 128:
                return self._login_page(headers, "Too many phone sign-in requests are active. Wait briefly and retry.")
        principal = self._qr_admin_principal(form.get("user", ""))
        if principal is None:
            _LOG.warning("admin_qr_login_rejected source=%s", client_ip)
            return self._login_page(headers, "That account could not be authorized for phone sign-in.")
        principal_id = principal_id_from_sid(principal.sid)
        if not any(item.get("central") for item in self.phones.list_for_principal(principal_id)):
            _LOG.warning("admin_qr_login_unenrolled sid=%s source=%s", principal.sid, client_ip)
            return self._login_page(headers, "No centrally enrolled phone is available for that account.")
        preauth_nonce = self._cookie(headers, _PREAUTH_COOKIE)
        try:
            challenge = self.challenges.create(
                machine_id=CENTRAL_AD_MACHINE_ID, sid=principal.sid,
                username=principal.username, authority=principal.authority,
                context="admin-web", lifetime_seconds=180,
            )
            params = {
                "h": self.public_host, "p": "47810", "fp": self.certificate_fingerprint,
                "id": challenge["request_id"], "n": challenge["nonce"],
                "m": CENTRAL_AD_MACHINE_ID, "hn": self.authority, "u": principal.username,
                "pv": "2", "sid": principal_id, "scope": "domain", "auth": principal.authority,
                "ctx": "admin-web", "api": "ad", "global": "1",
            }
            client_address = client_ip if re.fullmatch(r"[0-9A-Fa-f.:]{1,45}", client_ip) else ""
            if client_address:
                params["r"] = client_address
            link = "thessleypam://login?" + urlencode(params)
            qr_data = _qr_data_uri(link)
        except Exception:
            _LOG.exception("admin_qr_login_start_failed source=%s", client_ip)
            return self._login_page(headers, "Could not start phone sign-in. Check the account and try again.")
        with self._lock:
            self._qr_logins[challenge["request_id"]] = {
                "sid": principal.sid, "principal_id": principal_id, "username": principal.username,
                "client_ip": client_ip, "preauth": preauth_nonce,
                "expires_at": challenge["expires_at"], "qr": qr_data, "link": link,
            }
        _LOG.info("admin_qr_login_started sid=%s source=%s", principal.sid, client_ip)
        return self._response(303, "", extra_headers=(("Location", f"/admin/qr-login?id={challenge['request_id']}"),))

    def _qr_login_page(self, request_id: str, headers, client_ip: str):
        cookie_nonce = self._cookie(headers, _PREAUTH_COOKIE)
        with self._lock:
            pending = self._qr_logins.get(request_id)
        if (not pending or not secrets.compare_digest(cookie_nonce, pending["preauth"])
                or not secrets.compare_digest(client_ip, pending["client_ip"])
                or pending["expires_at"] <= time.time()):
            with self._lock:
                self._qr_logins.pop(request_id, None)
            return self._login_page(headers, "Phone sign-in expired. Start a new request.")
        result = self.challenges.consume_result(
            machine_id=CENTRAL_AD_MACHINE_ID, request_id=request_id,
        )
        if result and result.get("status") == "approved":
            credential_id = result.get("credential_id")
            active = any(item.get("central") and item.get("credential_id") == credential_id
                         for item in self.phones.list_for_principal(pending["principal_id"]))
            principal = self._qr_admin_principal(pending["username"])
            if active and principal and principal.sid == pending["sid"]:
                with self._lock:
                    self._qr_logins.pop(request_id, None)
                _LOG.info("admin_qr_login_ok sid=%s source=%s", principal.sid, pending["client_ip"])
                return self._new_admin_session(principal.sid, principal.username, pending["client_ip"], "phone")
            result = {"status": "denied"}
        status = result.get("status") if result else "pending"
        if status == "pending":
            script_nonce = secrets.token_urlsafe(18)
            refresh = ""
            link = html.escape(pending["link"], quote=True)
            qr = html.escape(pending["qr"], quote=True)
            account = html.escape(self.authority + chr(92) + pending["username"])
            content = f"""{refresh}<div class="qr-login"><h1>Approve admin sign-in</h1><section class="card">
<p>Scan with Thessley Passkey for <strong>{account}</strong>. The phone must already be enrolled centrally for this account.</p>
<div class="qr-wrap"><img class="qr" alt="Thessley AD administrator sign-in QR code" src="{qr}"></div>
<p><a class="button" href="{link}">{self._icon('phone')} Open Thessley Passkey</a></p>
<p class="status status-line">{self._icon('lock')} Waiting for approval</p>
<p class="muted small">After approving, return to this tab. It checks automatically.</p>
<p><a class="button secondary small" href="/admin/qr-login?id={html.escape(request_id)}">Refresh status</a></p>
<p class="muted small">This request expires shortly. Password sign-in is disabled.</p></section></div>"""
            resume_script = f'''<script nonce="{script_nonce}">
(()=>{{
 const target = "/admin/qr-login?id={request_id}";
 const line = document.querySelector(".status-line");
 const say = (text) => {{ if (line) {{ line.textContent = text; }} }};
 let done = false, busy = false;
 const started = Date.now();
 const stop = () => {{ clearInterval(timer); }};
 const finish = (text) => {{
  if (done) return;
  done = true; stop();
  if (text) {{ say(text); }} else {{ location.replace(target); }}
 }};
 async function poll() {{
  if (done || busy) return;
  if (Date.now() - started > 300000) return finish("This request expired. Start a new sign-in.");
  busy = true;
  try {{
   const response = await fetch("/admin/qr-status?id={request_id}", {{cache: "no-store", headers: {{Accept: "application/json"}}}});
   if (!response.ok) return;
   const data = await response.json();
   if (data.status === "approved") return finish(null);
   if (data.status === "denied") return finish("Approval was denied. Start a new sign-in.");
   if (data.status === "expired") return finish("This request expired. Start a new sign-in.");
   say("Waiting for approval on the phone…");
  }} catch (error) {{
   // A failed poll is not a reason to reload the page; keep waiting quietly.
  }} finally {{
   busy = false;
  }}
 }}
 const timer = setInterval(poll, 2000);
 poll();
 document.addEventListener("visibilitychange", () => {{ if (!document.hidden) {{ done ? null : poll(); }} }});
}})();
</script>'''
            return self._response(200, self._page("Approve admin sign-in", content + resume_script),
                                  script_nonce=script_nonce)
        with self._lock:
            self._qr_logins.pop(request_id, None)
        _LOG.warning("admin_qr_login_not_approved sid=%s source=%s status=%s",
                     pending["sid"], pending["client_ip"], status)
        return self._login_page(headers, "Phone sign-in expired or was denied. Start a new QR request.")

    def _reauthenticate_admin(self, session: dict, form: dict[str, str]) -> bool:
        password = form.pop("admin_password", "")
        try:
            sid = WindowsAdminLogin.authenticate(session["user"], password, self.authority)
            if sid and secrets.compare_digest(sid, session["sid"]):
                form["_admin_password"] = password
                return True
            return False
        finally:
            password = ""

    def _find_user(self, sid: str) -> dict | None:
        if not isinstance(sid, str) or not re.fullmatch(r"S-1-(?:[0-9]+-)+[0-9]+", sid):
            return None
        try:
            snapshot = self.directory.list_users(self.allowed_group_sids, limit=1000)
            return next((user for user in snapshot.get("users", []) if user.get("sid") == sid), None)
        except Exception:
            _LOG.exception("admin_ad_user_lookup_failed target_sid=%s", sid)
            return None

    def _user_form(self, session: dict, *, user: dict | None = None, message: str = ""):
        csrf = html.escape(session["csrf"])
        alert = f'<section class="card error">{html.escape(message)}</section>' if message else ""
        if user is None:
            body = f'''<h1>{self._icon("plus")} Add AD user</h1>{alert}
<section class="card"><form class="admin-user-form" method="post" action="/admin/users/create">
<input type="hidden" name="csrf" value="{csrf}">
<label for="new-username">Username</label><input id="new-username" name="username" required maxlength="20" pattern="[A-Za-z0-9_.-]+" autocomplete="off" autocapitalize="none">
<p class="muted small">The sign-in name is permanent after creation.</p>
<label for="new-display-name">Display name</label><input id="new-display-name" name="display_name" required maxlength="256" autocomplete="name">
<label for="new-password">Temporary password</label><input id="new-password" name="initial_password" type="password" required minlength="8" maxlength="256" autocomplete="new-password">
<p class="muted small">The new user must change this password at first sign-in.</p>
<label class="check-row"><input type="checkbox" name="must_change" value="yes" checked> Require a password change at first sign-in</label>
<p class="muted small">Leave this on unless the account is a service or test account: the administrator otherwise keeps a working password.</p>
<label for="admin-confirm-password">Your administrator password</label><input id="admin-confirm-password" name="admin_password" type="password" required autocomplete="current-password">
<p class="muted small">Re-enter it to confirm this directory change. It is not saved.</p>
<div class="form-actions"><button>{self._icon("plus")} Create user</button><a class="button secondary" href="/admin/">Cancel</a></div>
</form></section>'''
            return self._response(200, self._page("Add AD user", body))
        sid = str(user["sid"])
        name = html.escape(str(user.get("name") or user.get("sam", "")), quote=True)
        username = html.escape(str(user.get("sam", "")), quote=True)
        enabled = bool(user.get("enabled"))
        body = f'''<h1>{self._icon("users")} Edit AD user</h1>{alert}
<section class="card"><p><strong>{name}</strong><br><span class="muted">{html.escape(self.authority + chr(92))}{username}</span></p>
<form class="admin-user-form" method="post" action="/admin/users/update">
<input type="hidden" name="csrf" value="{csrf}"><input type="hidden" name="sid" value="{html.escape(sid)}">
<label for="edit-display-name">Display name</label><input id="edit-display-name" name="display_name" value="{name}" required maxlength="256" autocomplete="name">
<label for="edit-state">Account status</label><select id="edit-state" name="enabled"><option value="yes"{' selected' if enabled else ''}>Enabled</option><option value="no"{' selected' if not enabled else ''}>Disabled</option></select>
<label for="edit-admin-password">Your administrator password</label><input id="edit-admin-password" name="admin_password" type="password" required autocomplete="current-password">
<p class="muted small">Re-enter it to confirm this directory change. It is not saved.</p>
<div class="form-actions"><button>{self._icon("check")} Save changes</button><a class="button secondary" href="/admin/account?sid={sid}">Cancel</a></div>
</form></section>'''
        return self._response(200, self._page("Edit AD user", body))

    def _workstation_qr_page(self, session: dict, user: dict, *, allow: bool, message: str = ""):
        sid = html.escape(str(user["sid"]))
        account = html.escape(self.authority + chr(92) + str(user.get("sam", "")))
        alert = f'<section class="card error">{html.escape(message)}</section>' if message else ""
        if allow:
            title, verb, effect = "Allow workstation QR", "allow", (
                "The account joins the Thessley sign-in group and can then approve a QR sign-in "
                "at paired workstations with its enrolled phone.")
        else:
            title, verb, effect = "Disallow workstation QR", "disallow", (
                "The account leaves the Thessley sign-in group. Phone enrolment and AD sign-in keys "
                "are kept, but the account can no longer use QR sign-in at paired workstations.")
        body = f'''<h1>{self._icon("monitor")} {title}</h1>{alert}
<section class="card {'error' if not allow else ''}"><p><strong>{account}</strong></p>
<p>{effect}</p>
<p class="muted small">Effective immediately; no reboot or re-enrolment is needed.</p>
<form class="admin-user-form" method="post" action="/admin/workstation-qr">
<input type="hidden" name="csrf" value="{html.escape(session["csrf"])}"><input type="hidden" name="sid" value="{sid}">
<input type="hidden" name="action" value="{'allow' if allow else 'revoke'}">
<label for="workstation-admin-password">Your administrator password</label>
<input id="workstation-admin-password" name="admin_password" type="password" required autocomplete="current-password">
<p class="muted small">Re-enter it to confirm this directory change. It is not saved.</p>
<div class="form-actions"><button{'' if allow else ' class="danger"'}>{self._icon("monitor")} {title}</button><a class="button secondary" href="/admin/account?sid={sid}">Cancel</a></div>
</form></section>'''
        return self._response(200, self._page(title, body))

    def _user_password_page(self, session: dict, user: dict, message: str = ""):
        sid = html.escape(str(user["sid"]))
        username = html.escape(str(user.get("sam", "")))
        alert = f'<section class="card error">{html.escape(message)}</section>' if message else ""
        body = f'''<h1>{self._icon("key")} Change AD password</h1>{alert}
<section class="card"><p>Set a new temporary password for <strong>{html.escape(self.authority + chr(92) + str(user.get("sam", "")))}</strong>.
The account must change it at next sign-in.</p>
<form class="admin-user-form" method="post" action="/admin/users/password">
<input type="hidden" name="csrf" value="{html.escape(session["csrf"])}"><input type="hidden" name="sid" value="{sid}">
<label for="new-account-password">New temporary password</label>
<input id="new-account-password" name="new_password" type="password" required minlength="8" maxlength="256" autocomplete="new-password">
<p class="muted small">The domain password policy still applies: minimum length, complexity, banned words and password history.</p>
<label class="check-row"><input type="checkbox" name="must_change" value="yes" checked> Require a password change at next sign-in</label>
<label for="change-admin-password">Your administrator password</label>
<input id="change-admin-password" name="admin_password" type="password" required autocomplete="current-password">
<p class="muted small">Re-enter it to confirm this directory change. It is not saved.</p>
<div class="form-actions"><button>{self._icon("key")} Set password</button><a class="button secondary" href="/admin/account?sid={sid}">Cancel</a></div>
</form></section>'''
        return self._response(200, self._page("Change AD password", body))

    def _user_delete_page(self, session: dict, user: dict, message: str = ""):
        sid = html.escape(str(user["sid"]))
        username = html.escape(str(user.get("sam", "")))
        alert = f'<section class="card error">{html.escape(message)}</section>' if message else ""
        body = f'''<h1>{self._icon("warning")} Delete AD user</h1>{alert}
<section class="card error"><p>Delete <strong>{username}</strong> permanently from Active Directory?</p>
<p>This first disables the account, then revokes its enrolled Thessley phone and sign-in keys before deleting it. If deletion fails, the account remains disabled so access stays blocked.</p>
<form class="admin-user-form" method="post" action="/admin/users/delete">
<input type="hidden" name="csrf" value="{html.escape(session["csrf"])}"><input type="hidden" name="sid" value="{sid}">
<label for="delete-confirm-name">Type <strong>{username}</strong> to confirm</label><input id="delete-confirm-name" name="confirm_username" required autocomplete="off" autocapitalize="none">
<label for="delete-admin-password">Your administrator password</label><input id="delete-admin-password" name="admin_password" type="password" required autocomplete="current-password">
<div class="form-actions"><button class="danger">{self._icon("warning")} Delete permanently</button><a class="button secondary" href="/admin/account?sid={sid}">Cancel</a></div>
</form></section>'''
        return self._response(200, self._page("Delete AD user", body))

    def _post(self, path: str, form: dict[str, str], headers, client_ip: str):
        if path == "/admin/login":
            _LOG.warning("admin_password_login_blocked source=%s", client_ip)
            return self._login_page(headers, "Password-only web sign-in is disabled. Use the enrolled phone QR approval.")

        if path == "/admin/qr-login":
            return self._start_qr_admin_login(form, headers, client_ip)

        token, session = self._session(headers)
        if not session or not secrets.compare_digest(form.get("csrf", ""), session["csrf"]):
            return self._response(403, self._page("Session expired", '<section class="card error">Session expired. Sign in again.</section>'))
        if path == "/admin/users/create":
            if not self._reauthenticate_admin(session, form):
                return self._user_form(session, message="Enter your current administrator password to confirm user creation.")
            username = form.get("username", "").strip()
            display_name = form.get("display_name", "").strip()
            initial_password = form.pop("initial_password", "")
            try:
                if not callable(getattr(self.directory, "create_user", None)):
                    raise ValueError("AD user creation is unavailable on this service.")
                sid = self.directory.create_user(
                    administrator=session["user"], password=form.pop("_admin_password", ""),
                    username=username, display_name=display_name, initial_password=initial_password,
                    must_change=form.get("must_change") == "yes",
                )
            except ValueError as exc:
                return self._user_form(session, message=str(exc))
            except Exception:
                _LOG.exception("admin_ad_user_create_failed actor=%s target=%s",
                               session["sid"], username[:20])
                return self._user_form(session, message="AD could not create the account. Check permissions and password policy.")
            finally:
                initial_password = ""
            _LOG.warning("admin_ad_user_created actor=%s target_sid=%s username=%s",
                         session["sid"], sid, username)
            return self._accounts_redirect("user-created", sid)
        if path == "/admin/workstation-qr":
            sid = form.get("sid", "")
            action = form.get("action", "")
            if action not in ("allow", "revoke"):
                return self._response(400, self._page("Workstation QR", '<section class="card error">Invalid access change.</section>'))
            allow = action == "allow"
            user = self._find_user(sid)
            if not user:
                return self._response(404, self._page("Workstation QR", '<section class="card error">Account not found. Refresh the account list.</section>'))
            if secrets.compare_digest(sid, session["sid"]):
                return self._response(403, self._page("Workstation QR", '<section class="card error">You cannot change your own workstation sign-in right.</section>'))
            if user.get("dc_administrator"):
                return self._response(400, self._page("Workstation QR", '<section class="card error">This account already signs in as a DC administrator.</section>'))
            if not self._reauthenticate_admin(session, form):
                return self._workstation_qr_page(session, user, allow=allow,
                                                 message="Enter your current administrator password to confirm this change.")
            try:
                if not callable(getattr(self.directory, "set_workstation_access", None)):
                    raise ValueError("Workstation sign-in changes are unavailable on this service.")
                changed_sid = self.directory.set_workstation_access(
                    administrator=session["user"], password=form.pop("_admin_password", ""),
                    username=user["sam"], allowed_group_sids=self.allowed_group_sids, allow=allow,
                )
            except ValueError as exc:
                return self._workstation_qr_page(session, user, allow=allow, message=str(exc))
            except Exception:
                _LOG.exception("admin_workstation_qr_change_failed actor=%s target_sid=%s",
                               session["sid"], sid)
                return self._workstation_qr_page(session, user, allow=allow,
                                                 message="AD could not change the group membership. Check permissions and the group configuration.")
            _LOG.warning("admin_workstation_qr_changed actor=%s target_sid=%s allowed=%s",
                         session["sid"], changed_sid, allow)
            notice = "workstation-qr-allowed" if allow else "workstation-qr-revoked"
            return self._accounts_redirect(notice, changed_sid)
        if path == "/admin/users/password":
            sid = form.get("sid", "")
            user = self._find_user(sid)
            if not user:
                return self._response(404, self._page("AD user", '<section class="card error">Account not found. Refresh the account list.</section>'))
            if secrets.compare_digest(sid, session["sid"]):
                return self._response(400, self._page("Change AD password", '<section class="card error">Use your own sign-in to change your password.</section>'))
            if user.get("dc_administrator") or sid.endswith("-500"):
                return self._response(403, self._page("Change AD password", '<section class="card error">Passwords for privileged and built-in administrator accounts cannot be changed here. Use a separate AD administration tool.</section>'))
            if not self._reauthenticate_admin(session, form):
                return self._user_password_page(session, user, message="Enter your current administrator password to confirm this change.")
            new_password = form.pop("new_password", "")
            try:
                if not callable(getattr(self.directory, "set_user_password", None)):
                    raise ValueError("AD password changes are unavailable on this service.")
                changed_sid = self.directory.set_user_password(
                    administrator=session["user"], password=form.pop("_admin_password", ""),
                    username=user["sam"], new_password=new_password,
                    must_change=form.get("must_change") == "yes",
                )
            except ValueError as exc:
                return self._user_password_page(session, user, message=str(exc))
            except Exception:
                _LOG.exception("admin_ad_password_change_failed actor=%s target_sid=%s",
                               session["sid"], sid)
                return self._user_password_page(session, user, message="AD could not change the password. Check permissions and the password policy.")
            finally:
                new_password = ""
            _LOG.warning("admin_ad_password_changed actor=%s target_sid=%s",
                         session["sid"], changed_sid)
            return self._accounts_redirect("user-password", changed_sid)
        if path == "/admin/users/update":
            sid = form.get("sid", "")
            user = self._find_user(sid)
            if not user:
                return self._response(404, self._page("AD user", '<section class="card error">Account not found. Refresh the account list.</section>'))
            enabled = form.get("enabled") == "yes"
            if (not enabled and secrets.compare_digest(sid, session["sid"])):
                return self._user_form(session, user=user, message="You cannot disable the account used for this session.")
            if (not enabled and user.get("dc_administrator")):
                return self._user_form(session, user=user, message="Use a separate AD administration tool to disable a DC administrator.")
            if not self._reauthenticate_admin(session, form):
                return self._user_form(session, user=user, message="Enter your current administrator password to confirm this change.")
            try:
                if not callable(getattr(self.directory, "update_user", None)):
                    raise ValueError("AD user editing is unavailable on this service.")
                changed_sid = self.directory.update_user(
                    administrator=session["user"], password=form.pop("_admin_password", ""),
                    username=user["sam"], display_name=form.get("display_name", "").strip(),
                    enabled=enabled,
                )
            except ValueError as exc:
                return self._user_form(session, user=user, message=str(exc))
            except Exception:
                _LOG.exception("admin_ad_user_update_failed actor=%s target_sid=%s",
                               session["sid"], sid)
                return self._user_form(session, user=user, message="AD could not update the account. Check permissions and the supplied values.")
            _LOG.warning("admin_ad_user_updated actor=%s target_sid=%s enabled=%s",
                         session["sid"], changed_sid, enabled)
            return self._accounts_redirect("user-updated", changed_sid)
        if path == "/admin/users/delete":
            sid = form.get("sid", "")
            user = self._find_user(sid)
            if not user:
                return self._response(404, self._page("AD user", '<section class="card error">Account not found. Refresh the account list.</section>'))
            if secrets.compare_digest(sid, session["sid"]):
                return self._user_delete_page(session, user, "You cannot delete the account used for this session.")
            if user.get("dc_administrator") or sid.endswith("-500"):
                return self._user_delete_page(session, user, "Privileged and built-in administrator accounts cannot be deleted here.")
            confirmation = form.get("confirm_username", "").strip()
            if not secrets.compare_digest(confirmation.casefold(), user["sam"].casefold()):
                return self._user_delete_page(session, user, "Type the exact username to confirm deletion.")
            if not self._reauthenticate_admin(session, form):
                return self._user_delete_page(session, user, "Enter your current administrator password to confirm deletion.")
            principal_id = principal_id_from_sid_safe(sid)
            admin_password = form.pop("_admin_password", "")
            try:
                if not callable(getattr(self.directory, "disable_user", None)) or not callable(getattr(self.directory, "delete_user", None)):
                    raise ValueError("AD user deletion is unavailable on this service.")
                # Disable first. If key cleanup or deletion fails, the account
                # remains safely disabled and the administrator can retry.
                self.directory.disable_user(
                    administrator=session["user"], password=admin_password,
                    username=user["sam"],
                )
                for phone in self.phones.list_for_principal(principal_id):
                    if self.ad_logon_keys is not None:
                        revoked = self.ad_logon_keys.revoke_for_approval_credential(
                            phone["credential_id"], administrator=session["sid"],
                        )
                        if revoked is None:
                            raise ValueError("The account was disabled, but linked sign-in keys could not be revoked. Retry deletion.")
                    if not self.phones.revoke(phone["credential_id"]):
                        raise ValueError("The account was disabled, but a phone key could not be revoked. Retry deletion.")
                if self.ad_logon_keys is not None:
                    for key in self.ad_logon_keys.list_for_principal(principal_id):
                        if key["revoked_at"] is None and not self.ad_logon_keys.revoke(
                            key_id=key["key_id"], administrator=session["sid"],
                        ):
                            raise ValueError("The account was disabled, but an AD key could not be revoked. Retry deletion.")
                deleted_sid = self.directory.delete_user(
                    administrator=session["user"], password=admin_password,
                    username=user["sam"],
                )
            except ValueError as exc:
                return self._user_delete_page(session, user, str(exc))
            except Exception:
                _LOG.exception("admin_ad_user_delete_failed actor=%s target_sid=%s",
                               session["sid"], sid)
                return self._user_delete_page(session, user, "The account was disabled, but AD deletion did not finish. Check permissions, then retry.")
            finally:
                admin_password = ""
            _LOG.warning("admin_ad_user_deleted actor=%s target_sid=%s", session["sid"], deleted_sid)
            return self._accounts_redirect("user-deleted")
        if path == "/admin/logout":
            with self._lock:
                self._sessions.pop(token, None)
            if self.session_store is not None:
                self.session_store.delete(token)
            return self._response(303, "", extra_headers=(("Location", "/admin/"),
                ("Set-Cookie", f"{_SESSION_COOKIE}=; Path=/admin; Max-Age=0; Secure; HttpOnly; SameSite=Strict")))
        if path in ("/admin/policy/default", "/admin/policy/group", "/admin/policy/group/remove",
                    "/admin/policy/machine"):
            if self.login_policy is None:
                return self._response(503, self._page("Sign-in policy", '<section class="card error">The policy store is unavailable.</section>'))
            try:
                if path == "/admin/policy/default":
                    self.login_policy.set_default(form.get("method", ""), actor=session["sid"], now=time.time())
                    _LOG.warning("admin_login_policy_default_changed actor=%s method=%s", session["sid"], form.get("method", ""))
                elif path == "/admin/policy/group":
                    try:
                        priority = int(form.get("priority", ""), 10)
                    except ValueError as exc:
                        raise ValueError("Enter a group priority between 0 and 1000.") from exc
                    self.login_policy.set_group(form.get("group_sid", ""), form.get("method", ""), priority,
                                                actor=session["sid"], now=time.time())
                    _LOG.warning("admin_login_policy_group_changed actor=%s group_sid=%s method=%s priority=%d",
                                 session["sid"], form.get("group_sid", ""), form.get("method", ""), priority)
                elif path == "/admin/policy/group/remove":
                    if not self.login_policy.remove_group(form.get("group_sid", "")):
                        return self._response(404, self._policy_page(session, "No matching group rule was found."))
                    _LOG.warning("admin_login_policy_group_removed actor=%s group_sid=%s",
                                 session["sid"], form.get("group_sid", ""))
                else:
                    machine_id = form.get("machine_id", "")
                    method = form.get("method", "")
                    if self.machines is None or not any(
                        item["machine_id"] == machine_id for item in self.machines.list_active()
                    ):
                        raise ValueError("Select a currently paired workstation.")
                    self.login_policy.set_machine(machine_id, None if method == "inherit" else method,
                                                  actor=session["sid"], now=time.time())
                    _LOG.warning("admin_login_policy_machine_changed actor=%s machine_id=%s method=%s",
                                 session["sid"], machine_id, method)
            except (ValueError, TypeError) as exc:
                return self._response(400, self._policy_page(session, str(exc)))
            return self._response(303, "", extra_headers=(("Location", "/admin/policy"),))
        if path == "/admin/enroll":
            sid = form.get("sid", "")
            try:
                principal = self.directory.resolve_user_sid(sid)
            except Exception:
                _LOG.warning("admin_enroll_lookup_failed actor=%s target_sid_hash=%s", session["sid"], principal_id_from_sid_safe(sid))
                return self._response(503, self._page("Enrollment", '<section class="card error">Could not verify that AD account. Refresh and retry.</section>'))
            if (not principal.group_sids.intersection(self.allowed_group_sids)
                    and _ADMINISTRATORS_SID not in principal.group_sids):
                return self._response(403, self._page("Enrollment", '<section class="card error">That account is neither in the configured workstation sign-in group nor a DC administrator.</section>'))
            enrollment = self.phones.create_central_ad_enrollment(
                sid=principal.sid, username=principal.username, authority=principal.authority,
            )
            if not enrollment:
                return self._response(503, self._page("Enrollment", '<section class="card error">Could not start enrollment.</section>'))
            params = {
                "h": self.public_host, "p": "47810", "fp": self.certificate_fingerprint,
                "id": enrollment["request_id"], "n": enrollment["nonce"],
                "m": CENTRAL_AD_MACHINE_ID, "hn": self.authority, "u": principal.username,
                "pv": "2", "sid": enrollment["principal_id"], "scope": "domain",
                "auth": principal.authority, "ctx": "enrollment", "api": "ad", "global": "1",
            }
            link = "thessleypam://enroll?" + urlencode(params)
            try:
                qr_data = _qr_data_uri(link)
            except Exception:
                self.phones.cancel_enrollment(machine_id=CENTRAL_AD_MACHINE_ID, request_id=enrollment["request_id"])
                return self._response(503, self._page("Enrollment", '<section class="card error">QR rendering is unavailable on this DC. No enrollment was started.</section>'))
            with self._lock:
                now = time.time()
                self._enrollment_qrs = {key: value for key, value in self._enrollment_qrs.items() if value[2] > now}
                self._enrollment_qrs[enrollment["request_id"]] = (qr_data, link, enrollment["expires_at"])
            _LOG.info("admin_enrollment_started actor=%s target=%s", session["sid"], principal.sid)
            return self._response(303, "", extra_headers=((
                "Location", f"/admin/enrollment?id={enrollment['request_id']}&sid={principal.sid}"),))
        if path == "/admin/enroll-ad-logon-key":
            sid = form.get("sid", "")
            if self.ad_logon_keys is None:
                return self._response(503, self._page("AD key enrollment", '<section class="card error">AD logon-key registry is unavailable.</section>'))
            try:
                principal = self.directory.resolve_user_sid(sid)
            except Exception:
                _LOG.exception("admin_ad_logon_key_target_lookup_failed actor=%s", session["sid"])
                return self._response(503, self._page("AD key enrollment", '<section class="card error">Could not verify that AD account. Refresh and retry.</section>'))
            if (principal.authority.casefold() != self.authority.casefold()
                    or (not principal.group_sids.intersection(self.allowed_group_sids)
                        and _ADMINISTRATORS_SID not in principal.group_sids)):
                return self._response(403, self._page("AD key enrollment", '<section class="card error">That account is not authorized for Thessley AD sign-in.</section>'))
            principal_id = principal_id_from_sid(principal.sid)
            request = self.ad_logon_keys.create_enrollment(
                principal_id=principal_id, username=principal.username, authority=principal.authority,
            )
            if not request:
                return self._response(503, self._page("AD key enrollment", '<section class="card error">Could not start the key enrollment.</section>'))
            link = "thessleypam://ad-key-enroll?" + urlencode({
                "h": self.public_host, "p": "47810", "fp": self.certificate_fingerprint,
                "ep": "47811",
                "id": request["request_id"], "n": request["nonce"], "m": CENTRAL_AD_MACHINE_ID,
                "hn": self.authority, "u": principal.username, "pv": "2", "sid": principal_id,
                # PamRequest accepts the shared enrollment context for both
                # phone and AD-logon-key enrollment requests.
                "scope": "domain", "auth": principal.authority, "ctx": "enrollment",
                "api": "ad", "global": "1",
            })
            try:
                qr = _qr_data_uri(link)
            except Exception:
                self.ad_logon_keys.cancel_enrollment(request["request_id"])
                return self._response(503, self._page("AD key enrollment", '<section class="card error">Could not render an enrollment QR. No key was activated.</section>'))
            with self._lock:
                now = time.time()
                self._ad_logon_key_qrs = {
                    key: value for key, value in self._ad_logon_key_qrs.items() if value[2] > now
                }
                self._ad_logon_key_qrs[request["request_id"]] = (qr, link, request["expires_at"])
            _LOG.info("admin_ad_logon_key_enrollment_started actor=%s target=%s request=%s",
                      session["sid"], principal.sid, request["request_id"])
            return self._response(303, "", extra_headers=((
                "Location", f"/admin/ad-logon-key-enrollment?id={request['request_id']}&sid={principal.sid}"),))
        if path == "/admin/confirm-ad-logon-key":
            request_id = form.get("id", "")
            pairing = form.get("pairing_code", "")
            if self.ad_logon_keys is None or not _REQUEST_ID.fullmatch(request_id):
                return self._response(400, self._page("AD key enrollment", '<section class="card error">Invalid enrollment confirmation.</section>'))
            if not self.ad_logon_keys.confirm_enrollment(
                request_id=request_id, pairing_code=pairing, administrator=session["sid"],
            ):
                return self._ad_logon_key_enrollment_page(request_id, session, message="The code did not match or the request expired.")
            _LOG.info("admin_ad_logon_key_enrollment_confirmed actor=%s request=%s", session["sid"], request_id)
            return self._accounts_redirect(
                "ad-key-confirmed", _query_sid({"sid": [form.get("sid", "")]}))
        if path == "/admin/cancel-ad-logon-key":
            request_id = form.get("id", "")
            if self.ad_logon_keys is not None and _REQUEST_ID.fullmatch(request_id):
                self.ad_logon_keys.cancel_enrollment(request_id)
                with self._lock:
                    self._ad_logon_key_qrs.pop(request_id, None)
            return self._accounts_redirect("ad-key-enrollment-cancelled", _query_sid({"sid": [form.get("sid", "")]}))
        if path == "/admin/confirm-enrollment":
            request_id = form.get("id", "")
            if not _REQUEST_ID.fullmatch(request_id) or form.get("confirm") != "match":
                return self._response(400, self._page("Enrollment", '<section class="card error">Invalid confirmation.</section>'))
            enrollment_state = self.phones.enrollment_status(
                machine_id=CENTRAL_AD_MACHINE_ID, request_id=request_id,
            )
            pairing = enrollment_state.get("pairing_code", "") if enrollment_state else ""
            if (not enrollment_state or enrollment_state.get("status") != "ready"
                    or not re.fullmatch(r"[0-9]{3} [0-9]{3}", pairing)):
                return self._enrollment_page(request_id, session, message="The enrollment is not ready to confirm or has expired.")
            if not self.phones.confirm_enrollment(machine_id=CENTRAL_AD_MACHINE_ID,
                                                  request_id=request_id, pairing_code=pairing):
                _LOG.warning("admin_enrollment_confirmation_failed actor=%s request=%s", session["sid"], request_id)
                return self._enrollment_page(request_id, session, message="The code did not match or expired.")
            _LOG.info("admin_enrollment_confirmed actor=%s request=%s", session["sid"], request_id)
            return self._accounts_redirect(
                "enrollment-confirmed", _query_sid({"sid": [form.get("sid", "")]}))
        if path == "/admin/cancel-enrollment":
            request_id = form.get("id", "")
            if not _REQUEST_ID.fullmatch(request_id):
                return self._response(400, self._page("Enrollment", '<section class="card error">Invalid enrollment reference.</section>'))
            self.phones.cancel_enrollment(machine_id=CENTRAL_AD_MACHINE_ID, request_id=request_id)
            with self._lock:
                self._enrollment_qrs.pop(request_id, None)
            _LOG.info("admin_enrollment_cancelled actor=%s request=%s", session["sid"], request_id)
            return self._accounts_redirect("enrollment-cancelled", _query_sid({"sid": [form.get("sid", "")]}))
        if path == "/admin/revoke":
            credential = form.get("credential_id", "")
            principal_id = form.get("principal_id", "")
            if not _CREDENTIAL_ID.fullmatch(credential) or not re.fullmatch(r"[a-f0-9]{64}", principal_id):
                return self._response(400, self._page("Revoke key", '<section class="card error">Invalid key reference.</section>'))
            matching = next((item for item in self.phones.list_for_principal(principal_id)
                             if item["credential_id"] == credential), None)
            if not matching:
                return self._response(404, self._page("Revoke key", '<section class="card error">No active matching phone key was found.</section>'))
            anchor_sid = self._anchor_sid(form.get("sid", ""), principal_id)
            cancel_href = f"/admin/account?sid={anchor_sid}" if anchor_sid else "/admin/"
            label = html.escape(str(matching.get("label", "Phone")))
            machine_name = html.escape(str(matching.get("machine_name", "")))
            content = f'''<h1>Confirm phone revocation</h1>
<section class="card error"><p>You are about to revoke <strong>{label}</strong> on <strong>{machine_name}</strong>.</p>
<p>This phone will no longer approve sign-ins. AD logon keys enrolled through this phone will also be revoked. Revocation is permanent; audit records are retained.</p>
<form method="post" action="/admin/confirm-revoke"><input type="hidden" name="csrf" value="{html.escape(session['csrf'])}">
<input type="hidden" name="credential_id" value="{html.escape(credential)}"><input type="hidden" name="principal_id" value="{html.escape(principal_id)}"><input type="hidden" name="sid" value="{html.escape(anchor_sid)}">
<div class="form-actions"><button class="danger">Yes, revoke this phone</button><a class="button" href="{cancel_href}">Cancel</a></div></form></section>'''
            return self._response(200, self._page("Confirm phone revocation", content))
        if path == "/admin/confirm-revoke":
            credential = form.get("credential_id", "")
            principal_id = form.get("principal_id", "")
            if (not _CREDENTIAL_ID.fullmatch(credential)
                    or not re.fullmatch(r"[a-f0-9]{64}", principal_id)):
                return self._response(400, self._page("Revoke key", '<section class="card error">Invalid key reference.</section>'))
            matching = any(item["credential_id"] == credential
                           for item in self.phones.list_for_principal(principal_id))
            if not matching:
                return self._response(404, self._page("Revoke key", '<section class="card error">No active matching phone key was found.</section>'))
            linked_ad_keys = self.ad_logon_keys.revoke_for_approval_credential(
                credential, administrator=session["sid"],
            ) if self.ad_logon_keys is not None else 0
            if linked_ad_keys is None:
                _LOG.error("admin_phone_revoke_ad_key_cleanup_failed actor=%s principal_id=%s credential_id=%s",
                           session["sid"], principal_id, credential)
                return self._response(503, self._page("Revoke key", '<section class="card error">Could not safely revoke the linked AD keys. The phone key was left active; retry in a moment.</section>'))
            if not self.phones.revoke(credential):
                return self._response(409, self._page("Revoke key", '<section class="card error">The phone key changed while revocation was in progress. Refresh before retrying.</section>'))
            _LOG.warning("admin_phone_revoked actor=%s principal_id=%s credential_id=%s linked_ad_keys_revoked=%d",
                         session["sid"], principal_id, credential, linked_ad_keys)
            return self._accounts_redirect("phone-revoked", self._anchor_sid(form.get("sid", ""), principal_id))
        if path in ("/admin/revoke-logon-key", "/admin/confirm-revoke-logon-key"):
            key_id = form.get("key_id", "")
            principal_id = form.get("principal_id", "")
            if (self.ad_logon_keys is None or not _AD_LOGON_KEY_ID.fullmatch(key_id)
                    or not re.fullmatch(r"[a-f0-9]{64}", principal_id)):
                return self._response(400, self._page("AD logon key", '<section class="card error">Invalid key reference.</section>'))
            key = next((item for item in self.ad_logon_keys.list_for_principal(principal_id)
                        if item["key_id"] == key_id and item["revoked_at"] is None), None)
            if key is None:
                return self._response(404, self._page("AD logon key", '<section class="card error">No active matching key was found.</section>'))
            if path == "/admin/revoke-logon-key":
                anchor_sid = self._anchor_sid(form.get("sid", ""), principal_id)
                cancel_href = f"/admin/account?sid={anchor_sid}" if anchor_sid else "/admin/"
                content = f'''<h1>Confirm AD logon-key revocation</h1>
<section class="card error"><p>Revoke <strong>{html.escape(key["label"])}</strong> for this AD account?</p>
<p>Fingerprint: <code>{html.escape(key["public_key_sha256"])}</code></p>
<p>This public key is not currently eligible for sign-in. Revocation is permanent.</p>
<form method="post" action="/admin/confirm-revoke-logon-key"><input type="hidden" name="csrf" value="{html.escape(session['csrf'])}">
<input type="hidden" name="key_id" value="{html.escape(key_id)}"><input type="hidden" name="principal_id" value="{html.escape(principal_id)}"><input type="hidden" name="sid" value="{html.escape(anchor_sid)}">
<div class="form-actions"><button class="danger">Yes, revoke this key</button><a class="button" href="{cancel_href}">Cancel</a></div></form></section>'''
                return self._response(200, self._page("Confirm AD logon-key revocation", content))
            if not self.ad_logon_keys.revoke(key_id=key_id, administrator=session["sid"]):
                return self._response(409, self._page("AD logon key", '<section class="card error">The key was already revoked or could not be updated.</section>'))
            _LOG.warning("admin_ad_logon_key_revoked actor=%s principal_id=%s key_id=%s",
                         session["sid"], principal_id, key_id)
            return self._accounts_redirect("logon-key-revoked", self._anchor_sid(form.get("sid", ""), principal_id))
        return self._response(404, self._page("Not found", "<section class=card>Page not found.</section>"))

    @staticmethod
    def _status_poll(current: str, url: str, nonce: str = "", interval: int = 2) -> tuple[str, str]:
        """Watch a status endpoint and reload once, only when it changes."""
        nonce = nonce or secrets.token_urlsafe(18)
        tag = f'''<script nonce="{html.escape(nonce, quote=True)}">
(()=>{{
 const initial={json.dumps(current)};
 let failures=0;
 const poll=async()=>{{
  try {{
   const response=await fetch({json.dumps(url)},{{cache:"no-store"}});
   if (!response.ok) {{ throw new Error("status"); }}
   const data=await response.json();
   failures=0;
   if (data.status!==initial) {{ location.reload(); }}
  }} catch (error) {{
   failures+=1;
   if (failures>=3) {{ location.reload(); }}
  }}
 }};
 setInterval(poll,{int(interval) * 1000});
 document.addEventListener("visibilitychange",()=>{{ if(!document.hidden) poll(); }});
}})();
</script>'''
        return tag, nonce

    @staticmethod
    def _anchor_sid(sid, principal_id: str) -> str:
        """Return the SID only when it provably belongs to this principal."""
        if isinstance(sid, str) and principal_id_from_sid_safe(sid) == principal_id:
            return sid
        return ""

    @staticmethod
    def _accounts_redirect(notice: str, sid: str = ""):
        """Send the operator back to the account they just changed.

        A single-account view is used instead of an anchor in the list, so the
        operator lands on the same card regardless of paging, filtering or how
        many accounts the directory holds.
        """
        if isinstance(sid, str) and re.fullmatch(r"S-1-(?:[0-9]+-)+[0-9]+", sid):
            location = f"/admin/account?sid={sid}&notice={notice}"
        else:
            location = f"/admin/?notice={notice}"
        return AdminWeb._response(303, "", extra_headers=(("Location", location),))

    def _directory_page(self, session: dict, *, notice: str = "", page: int = 1,
                        query: str = "", single_sid: str = ""):
        try:
            snapshot = self.directory.list_users(self.allowed_group_sids, limit=1000)
        except Exception:
            _LOG.exception("admin_directory_query_failed sid=%s", session.get("sid", "unknown"))
            return self._response(503, self._page("Directory unavailable", '<section class="card error">Active Directory could not be queried. Try again shortly.</section>'))
        everyone = list(snapshot.get("users", []))
        single = None
        total, pages = len(everyone), 1
        if single_sid:
            single = next((item for item in everyone if str(item.get("sid", "")) == single_sid), None)
            if single is None:
                return self._response(404, self._page(
                    "AD account", '<section class="card error">Account not found in Active Directory.</section>'))
            users = [single]
        else:
            needle = (query or "").strip().casefold()
            if needle:
                everyone = [
                    item for item in everyone
                    if needle in f"{item.get('name') or ''} {item.get('sam') or ''}".casefold()
                ]
            total = len(everyone)
            pages = max(1, -(-total // self.PAGE_SIZE))
            page = min(max(page, 1), pages)
            users = everyone[(page - 1) * self.PAGE_SIZE: page * self.PAGE_SIZE]
        notice_html = f'<section class="card success">{html.escape(notice)}</section>' if notice else ""
        signed_in = html.escape(self.authority + chr(92) + session['user'])
        help_card = f'''<section class="card help"><details><summary>{self._icon("admin")} About access rights</summary>
<p><strong>Workstation QR</strong> means the account is in the configured Thessley sign-in group and can approve QR sign-in at paired workstations. It can be allowed or revoked below. <strong>DC admin</strong> means the account belongs to this domain controller’s Administrators group; that right is read-only here.</p></details></section>'''
        if single_sid:
            single_name = html.escape(str(single.get("name") or single.get("sam", "")))
            content = f'''<header class="page-head"><div><h1>{self._icon("users")} {single_name}</h1>
<div class="muted">{html.escape(self.authority + chr(92) + str(single.get("sam", "")))}</div></div>
<div class="header-actions"><nav class="page-actions" aria-label="Account"><a class="button secondary" href="/admin/">{self._icon("chevron")} All accounts</a></nav><form method="post" action="/admin/logout"><input type="hidden" name="csrf" value="{html.escape(session['csrf'])}"><button class="danger secondary small">{self._icon('logout')} Sign out</button></form></div></header>
{notice_html}
<p class="muted">Signed in as <strong>{signed_in}</strong>. This view shows one account; use All accounts to pick another.</p>'''
        else:
            search_value = html.escape((query or "").strip(), quote=True)
            content = f'''<header class="page-head"><div><h1>{self._icon("users")} AD accounts</h1>
<div class="muted">Manage phone approvals and AD sign-in keys.</div></div>
<div class="header-actions"><nav class="page-actions" aria-label="Administration">
<a class="button" href="/admin/users/new">{self._icon("plus")} Add user</a>
<a class="button secondary" href="/admin/policy">{self._icon("settings")} Policy</a>
<a class="button secondary" href="/admin/log">{self._icon("admin")} Log</a>
</nav><form method="post" action="/admin/logout"><input type="hidden" name="csrf" value="{html.escape(session['csrf'])}"><button class="danger secondary small">{self._icon('logout')} Sign out</button></form></div></header>
{notice_html}
<p class="muted">Signed in as <strong>{signed_in}</strong> · <span id="account-count" aria-live="polite">{total} account{'s' if total != 1 else ''}</span>. Phone approvals are stored centrally and work on paired PCs.</p>
<section class="search-tools" role="search"><form method="get" action="/admin/"><label for="account-search">Find an account</label>
<div class="search-row"><input id="account-search" name="q" type="search" value="{search_value}" autocomplete="off" placeholder="Name or username" aria-label="Search accounts by name or username">
<button type="submit" class="secondary small">Search</button> <a class="button secondary small" href="/admin/">Clear</a></div></form></section>'''
        content += help_card
        for user in users:
            sid = str(user.get("sid", ""))
            principal_id = principal_id_from_sid_safe(sid)
            if not principal_id:
                continue
            authorized = bool(user.get("authorized"))
            dc_administrator = bool(user.get("dc_administrator"))
            # Only surface DC administrator status when it applies.
            dc_badge = (f'<span class="badge yes">{self._icon("admin")} DC admin</span>'
                        if dc_administrator else "")
            display_name = html.escape(user.get("name") or user.get("sam", ""))
            account_name = html.escape(self.authority + chr(92) + user.get("sam", ""))
            status_badge = '<span class="badge neutral">Disabled</span>' if not user.get("enabled") else ""
            keys = self.phones.list_for_principal(principal_id)
            logon_keys = self.ad_logon_keys.list_for_principal(principal_id) if self.ad_logon_keys else []
            active_logon_keys = [key for key in logon_keys if key["revoked_at"] is None]
            phone_markers = "".join(self._protection_badge(key.get("attestation_status", "unverified"), compact=True)
                                    for key in keys[:3])
            if len(keys) > 3:
                phone_markers += f'<span class="badge neutral">+{len(keys) - 3}</span>'
            if not keys:
                phone_markers = f'<span class="badge neutral">{self._icon("phone")} No phone</span>'
            logon_markers = "".join(self._protection_badge(key.get("attestation_status", "unverified"), compact=True)
                                     for key in active_logon_keys[:2])
            if len(active_logon_keys) > 2:
                logon_markers += f'<span class="badge neutral">+{len(active_logon_keys) - 2}</span>'
            content += f'''<section class="card account-card" id="account-{html.escape(sid)}"><div class="account-top"><div class="account-name">
<span class="account-avatar">{self._icon("users")}</span><div class="account-heading"><h2>{display_name}</h2><div class="account-id">{account_name}</div>
<div class="rights">{status_badge}<span class="badge {'yes' if authorized else 'no'}">{self._icon('monitor')} Workstation QR · {'Allowed' if authorized else 'Not allowed'}</span>
{dc_badge}</div></div></div>
<div class="trust-summary"><div><span class="trust-label">Phone</span><div class="trust-icons">{phone_markers}</div></div>
<div><span class="trust-label">AD sign-in</span><div class="trust-icons">{logon_markers or '<span class="badge neutral">Not active</span>'}</div></div></div></div>'''
            phone_items = []
            for key in keys:
                attestation = str(key.get("attestation_status", "unverified"))
                reason = str(key.get("attestation_reason", ""))
                enrolled = time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(key["enrolled_at"]))
                extra = (f'<details class="key-extra"><summary>Verification details</summary><p class="key-meta">{html.escape(reason)}</p></details>'
                         if attestation == "unverified" and reason else "")
                phone_items.append(f'''<article class="key-item"><div class="key-main"><div class="key-title">{html.escape(key['label'])}</div>
<div class="key-meta">{html.escape(key['machine_name'])} · Enrolled {html.escape(enrolled)}</div>
{self._protection_badge(attestation)}{extra}
<div class="key-actions"><form method="post" action="/admin/revoke"><input type="hidden" name="csrf" value="{html.escape(session['csrf'])}"><input type="hidden" name="credential_id" value="{html.escape(key['credential_id'])}"><input type="hidden" name="principal_id" value="{principal_id}"><input type="hidden" name="sid" value="{html.escape(sid)}"><button class="danger small">Revoke phone</button></form></div></div></article>''')
            phone_summary = f'{len(keys)} enrolled' if keys else 'None enrolled'
            logon_items = []
            if active_logon_keys:
                for key in active_logon_keys:
                    fingerprint = html.escape(key["public_key_sha256"])
                    attestation = str(key.get("attestation_status", "unverified"))
                    logon_items.append(f'''<article class="key-item"><div class="key-main"><div class="key-title">{html.escape(key["label"])}</div>
<div class="key-meta">SHA-256 · {fingerprint}</div>{self._protection_badge(attestation)}
<div class="key-actions"><form method="post" action="/admin/revoke-logon-key"><input type="hidden" name="csrf" value="{html.escape(session['csrf'])}"><input type="hidden" name="key_id" value="{html.escape(key['key_id'])}"><input type="hidden" name="principal_id" value="{principal_id}"><input type="hidden" name="sid" value="{html.escape(sid)}"><button class="danger small">Revoke key</button></form></div></div></article>''')
            else:
                logon_items.append('<p class="empty">No AD sign-in key enrolled.</p>')
            logon_summary = f'{len(active_logon_keys)} active' if active_logon_keys else 'None enrolled'
            content += f'''<div class="account-details"><details><summary>{self._icon('phone')} Phone approvals<span class="summary-count">{phone_summary}</span></summary>
<div class="detail-body">{''.join(phone_items) if phone_items else '<p class="empty">No phone enrolled for this account.</p>'}
<p class="muted small">Revoking a phone also revokes AD sign-in keys that it enrolled.</p></div></details>
<details><summary>{self._icon('key')} AD sign-in keys<span class="summary-count">{logon_summary}</span></summary>
<div class="detail-body"><p class="muted small">These keys are separate from phone approvals. Sign-in remains off until the Windows signing bridge is validated.</p>{''.join(logon_items)}</div></details></div>
<div class="account-actions">'''
            if user.get("enabled") and (authorized or dc_administrator):
                content += f'''<form method="post" action="/admin/enroll"><input type="hidden" name="csrf" value="{html.escape(session['csrf'])}"><input type="hidden" name="sid" value="{html.escape(sid)}"><button>{self._icon('plus')} Enroll phone</button></form>'''
                content += f'''<form method="post" action="/admin/enroll-ad-logon-key"><input type="hidden" name="csrf" value="{html.escape(session['csrf'])}"><input type="hidden" name="sid" value="{html.escape(sid)}"><button class="secondary small">{self._icon('key')} Add AD sign-in key</button></form>'''
            content += f'''<a class="button secondary small" href="/admin/user/edit?sid={html.escape(sid)}">{self._icon('settings')} Edit</a>'''
            if sid != session["sid"] and not dc_administrator and not sid.endswith("-500"):
                content += f'''<a class="button secondary small" href="/admin/user/password?sid={html.escape(sid)}">{self._icon('key')} Change password</a>'''
            if sid != session["sid"] and not dc_administrator:
                if authorized:
                    content += f'''<a class="button danger small" href="/admin/workstation-qr?sid={html.escape(sid)}&action=revoke">{self._icon('monitor')} Disallow workstation QR</a>'''
                else:
                    content += f'''<a class="button secondary small" href="/admin/workstation-qr?sid={html.escape(sid)}&action=allow">{self._icon('monitor')} Allow workstation QR</a>'''
            if sid != session["sid"] and not dc_administrator and not sid.endswith("-500"):
                content += f'''<a class="button danger small" href="/admin/user/delete?sid={html.escape(sid)}">{self._icon('warning')} Delete</a>'''
            content += '</div></section>'
        if not single_sid:
            if snapshot.get("truncated"):
                content += '<section class="card">Directory listing reached its 1,000-account limit.</section>'
            if pages > 1:
                base = "/admin/?q=" + html.escape((query or "").strip(), quote=True) + "&page="
                prev_link = (f'<a class="button secondary small" href="{base}{page - 1}">Previous</a>'
                             if page > 1 else '<span class="badge neutral">Previous</span>')
                next_link = (f'<a class="button secondary small" href="{base}{page + 1}">Next</a>'
                             if page < pages else '<span class="badge neutral">Next</span>')
                content += (f'<nav class="pager" aria-label="Account pages">{prev_link}'
                            f'<span class="muted small">Page {page} of {pages}</span>{next_link}</nav>')
        elif not users:
            content += '<section class="card">This account has no directory entry.</section>'
        return self._response(200, self._page("AD accounts" if not single_sid else "AD account", content))

    @staticmethod
    def _protection(attestation: str) -> tuple[str, str, str, str]:
        return {
            "verified_tee": ("TEE verified", "yes", "TEE", "lock"),
            "verified_strongbox": ("StrongBox verified", "yes", "StrongBox", "lock"),
            "verified_software": ("Software-backed", "medium", "Software", "lock"),
        }.get(str(attestation), ("Not verified", "no", "Unverified", "warning"))

    @classmethod
    def _protection_badge(cls, attestation: str, *, compact: bool = False) -> str:
        label, level, short, icon = cls._protection(str(attestation))
        text = short if compact else label
        return f'<span class="badge {level}" title="{html.escape(label, quote=True)}">{cls._icon(icon)} {text}</span>'

    def _ad_logon_key_enrollment_page(self, request_id: str, session: dict, qr_data: str = "",
                                      message: str = "", app_link: str = "", sid: str = ""):
        if not qr_data or not app_link:
            stored_qr, stored_link, _expires = self._ad_logon_key_qrs.get(request_id, ("", "", 0))
            if not qr_data:
                qr_data = stored_qr
            if not app_link:
                app_link = stored_link
        if self.ad_logon_keys is None:
            return self._response(503, self._page("AD key enrollment", '<section class="card error">AD logon-key registry is unavailable.</section>'))
        state = self.ad_logon_keys.enrollment_status(request_id)
        if state is None:
            return self._response(404, self._page("AD key enrollment", '<section class="card error">Enrollment request not found.</section>'))
        account = html.escape(state["authority"] + chr(92) + state["username"])
        if state["status"] == "confirmed":
            body = f'<h1>AD key confirmed</h1><section class="card success">The key for <strong>{account}</strong> is active. Protection: {html.escape(state["attestation_status"])}.</section><a class="button" href="/admin/">Back to accounts</a>'
        elif state["status"] in ("expired", "cancelled"):
            body = '<h1>Enrollment ended</h1><section class="card error">This request expired or was cancelled. Start a new request from AD accounts.</section><a class="button" href="/admin/">Back to accounts</a>'
        else:
            # Keep reloading until the request reaches a terminal state. Browsers
            # throttle meta refresh in background tabs, which is exactly where this
            # page sits while the administrator scans the QR, so a page left on
            # "waiting" must recover by itself once the phone submits its key.
            sid_query = f"&sid={html.escape(sid, quote=True)}" if sid else ""
            refresh, refresh_nonce = self._status_poll(
                state["status"], f"/admin/ad-logon-key-status?id={request_id}")
            reload_href = html.escape(f"/admin/ad-logon-key-enrollment?id={request_id}{sid_query}", quote=True)
            reload_link = f'<a class="button secondary small" href="{reload_href}">Reload status</a>'
            error = f'<section class="card error">{html.escape(message)}</section>' if message else ''
            qr = f'<div class="qr-wrap"><img class="qr" alt="AD logon key enrollment QR" src="{html.escape(qr_data, quote=True)}"></div>' if qr_data else ''
            open_app = (f'<p><a class="button" href="{html.escape(app_link, quote=True)}">'
                        f'{self._icon("phone")} Open Thessley Passkey on this device</a></p>' if app_link else '')
            body = refresh + f'<h1>Add AD logon key for {account}</h1>{error}<section class="card"><p>Open Thessley Passkey on this device, or scan the QR with another device. The phone creates the key and displays a six-digit code. Confirm only when the phone and this page show the same code.</p>{open_app}{qr}'
            if state["status"] == "pending":
                body += '<p class="status">Waiting for the phone to create and submit its key…</p>'
            elif state["status"] == "ready":
                body += f'<p class="status">Pairing code: <strong>{html.escape(state["pairing_code"])}</strong></p><p class="muted">Protection reported by Android: {html.escape(state["attestation_status"])}. A code match verifies the request, not the phone manufacturer or hardware beyond the attestation result.</p><form method="post" action="/admin/confirm-ad-logon-key"><input type="hidden" name="csrf" value="{html.escape(session["csrf"])}"><input type="hidden" name="sid" value="{html.escape(sid)}"><input type="hidden" name="id" value="{html.escape(request_id)}"><input type="hidden" name="pairing_code" value="{html.escape(state["pairing_code"])}"><button>Codes match — activate key</button></form>'
            body += '</section><div class="form-actions"><form method="post" action="/admin/cancel-ad-logon-key"><input type="hidden" name="csrf" value="' + html.escape(session["csrf"]) + '"><input type="hidden" name="sid" value="' + html.escape(sid) + '"><input type="hidden" name="id" value="' + html.escape(request_id) + '"><button class="danger">Cancel</button></form>' + reload_link + '<a class="button" href="/admin/' + (('account?sid=' + sid) if sid else '') + '">Return to accounts</a></div>'
        return self._response(200, self._page("AD logon-key enrollment", body),
                              script_nonce=locals().get("refresh_nonce"))

    LOG_PAGE_SIZE = 50
    LOG_MAX_BYTES = 2 * 1024 * 1024
    _LOG_LEVELS = ("ERROR", "WARNING", "INFO")

    @staticmethod
    def _log_entries(text: str) -> list[tuple[str, str, str]]:
        """Split log lines into (timestamp, level, message), newest last."""
        import re as _re
        pattern = _re.compile(r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3}) (ERROR|WARNING|INFO) (.*)$")
        entries = []
        for line in text.splitlines():
            match = pattern.match(line)
            if match:
                entries.append((match.group(1), match.group(2), match.group(3)))
            elif line.strip():
                entries.append(("", "INFO", line.strip()))
        return entries

    _LOG_ACTIVITY = {
        "admin_login_ok": ("login", "Administrator signed in"),
        "admin_qr_login_ok": ("login", "Administrator approved phone sign-in"),
        "admin_qr_login_started": ("login", "Administrator requested phone sign-in"),
        "admin_enrollment_started": ("enroll", "Phone enrollment started"),
        "admin_enrollment_confirmed": ("enroll", "Phone enrollment confirmed"),
        "admin_enrollment_cancelled": ("revoke", "Phone enrollment cancelled"),
        "ad_logon_key_staged": ("enroll", "AD sign-in key submitted by phone"),
        "admin_ad_logon_key_enrollment_started": ("enroll", "AD sign-in key enrollment started"),
        "admin_ad_logon_key_enrollment_confirmed": ("enroll", "AD sign-in key confirmed"),
        "admin_ad_logon_key_enrollment_cancelled": ("revoke", "AD sign-in key enrollment cancelled"),
        "admin_phone_revoked": ("revoke", "Phone approval revoked"),
        "admin_ad_logon_key_revoked": ("revoke", "AD sign-in key revoked"),
        "admin_ad_user_created": ("user", "AD user created"),
        "admin_ad_user_updated": ("user", "AD user updated"),
        "admin_ad_user_deleted": ("user", "AD user deleted"),
        "admin_ad_password_changed": ("user", "AD password changed"),
        "admin_workstation_qr_changed": ("access", "Workstation QR access changed"),
        "admin_logon_key_revoked": ("revoke", "AD sign-in key revoked"),
    }

    @classmethod
    def _log_activity(cls, timestamp: str, level: str, message: str):
        """Map a raw log line to (category, label, detail) or None for noise."""
        event = message.split(" ", 1)[0]
        mapped = cls._LOG_ACTIVITY.get(event)
        detail = message[len(event):].strip()
        if mapped:
            category, label = mapped
            if level == "WARNING" and "failed" in message.lower():
                label += " (failed)"
            return category, label, detail
        if level in ("ERROR", "WARNING"):
            return ("error" if level == "ERROR" else "warn"), message[:200], ""
        # Anything that is clearly a state change is worth showing even when it
        # is not in the curated map above; plain chatter stays hidden.
        import re as _re
        if level == "INFO" and _re.search(
                r"^(admin_|ad_|piv_|thessley_)|_(ok|started|confirmed|cancelled|staged|revoked|"
                r"created|updated|deleted|changed|failed)$", event):
            category = "piv" if event.startswith("piv_") else (
                "keys" if event.startswith("ad_") else "access")
            return category, event.replace("_", " "), detail[:200]
        return None
        return None

    def _log_page(self, session: dict, page: int = 1, show_all: bool = False):
        if not self.log_path:
            return self._response(503, self._page(
                "Service log", '<section class="card error">No log file is configured for this service.</section>'))
        try:
            from pathlib import Path as _Path
            path = _Path(self.log_path)
            if not path.is_file():
                raise OSError("missing")
            size = path.stat().st_size
            with path.open("rb") as handle:
                handle.seek(max(0, size - self.LOG_MAX_BYTES))
                text = handle.read().decode("utf-8", "replace")
            truncated = size > self.LOG_MAX_BYTES
        except OSError:
            _LOG.exception("admin_log_read_failed sid=%s", session.get("sid", "unknown"))
            return self._response(503, self._page(
                "Service log", '<section class="card error">The service log could not be read.</section>'))

        entries = self._log_entries(text)
        total = len(entries)
        activities = []
        for timestamp, level, message in entries:
            mapped = self._log_activity(timestamp, level, message)
            if mapped:
                activities.append((timestamp, mapped[0], mapped[1], mapped[2]))
        important = activities
        if show_all:
            shown = [(timestamp, "raw", level, message) for timestamp, level, message in entries]
        else:
            shown = activities
        shown = list(reversed(shown))          # newest first
        pages = max(1, -(-len(shown) // self.LOG_PAGE_SIZE))
        page = min(max(page, 1), pages)
        start = (page - 1) * self.LOG_PAGE_SIZE
        chunk = shown[start:start + self.LOG_PAGE_SIZE]

        query = "all=1&" if show_all else ""
        prev_link = (f'<a class="button secondary small" href="/admin/log?{query}page={page - 1}">Newer</a>'
                     if page > 1 else '<span class="badge neutral">Newer</span>')
        next_link = (f'<a class="button secondary small" href="/admin/log?{query}page={page + 1}">Older</a>'
                     if page < pages else '<span class="badge neutral">Older</span>')
        pager = (f'<nav class="pager" aria-label="Log pages">{prev_link}'
                 f'<span class="muted small">Page {page} of {pages} · {len(shown)} shown</span>{next_link}</nav>')
        toggle = ('<a class="button secondary small" href="/admin/log">Important only</a>' if show_all
                  else f'<a class="button secondary small" href="/admin/log?all=1&page=1">Show all {total}</a>')
        note = ('<p class="muted small">Only the most recent 2 MiB are read.</p>' if truncated else '')

        badge_for = {"login": ("yes", "login"), "enroll": ("yes", "enroll"),
                     "revoke": ("no", "revoke"), "user": ("neutral", "user"),
                     "keys": ("neutral", "keys"), "piv": ("medium", "piv"),
                     "access": ("medium", "access"), "warn": ("medium", "warning"),
                     "error": ("no", "error"), "raw": ("neutral", "raw")}
        rows = []
        for timestamp, category, label, detail in chunk:
            css, text = badge_for.get(category, ("neutral", category))
            when = html.escape(timestamp[11:19] if timestamp else "")
            day = html.escape(timestamp[:10] if timestamp else "")
            extra = (f'<span class="log-detail">{html.escape(detail)}</span>' if detail else "")
            rows.append(
                f'<li class="log-row"><span class="badge {css}">{text}</span>'
                f'<span class="log-when" title="{day}">{when}</span>'
                f'<span class="log-msg">{html.escape(label)}{extra}</span></li>')
        if not rows:
            rows.append('<li class="log-row"><span class="badge yes">OK</span>'
                        '<span class="log-msg">No important events in the read window.</span></li>')

        body = (f'<header class="page-head"><div><h1>{self._icon("admin")} Service log</h1>'
                f'<div class="muted">{len(important)} events of {total} log lines · {html.escape(str(self.log_path))}</div></div>'
                f'<div class="header-actions"><nav class="page-actions">'
                f'<a class="button secondary small" href="/admin/log">Refresh</a>{toggle}'
                f'<a class="button secondary small" href="/admin/">{self._icon("chevron")} All accounts</a>'
                f'</nav></div></header>'
                + pager + note +
                '<section class="card log-card"><ul class="log-list">' + "".join(rows) + '</ul></section>' + pager)
        return self._response(200, self._page("Service log", body))

    def _policy_page(self, session: dict, message: str = ""):
        if self.login_policy is None:
            return self._response(503, self._page("Sign-in policy", '<section class="card error">The policy store is unavailable.</section>'))
        try:
            snapshot = self.login_policy.snapshot()
            machines = self.machines.list_active() if self.machines is not None else []
        except Exception:
            _LOG.exception("admin_login_policy_read_failed actor=%s", session["sid"])
            return self._response(503, self._page("Sign-in policy", '<section class="card error">Could not load the current policy.</section>'))
        def options(selected: str) -> str:
            items = (
                ("tpm_smartcard", "Phone approval + this PC TPM smart card"),
                ("windows_native", "Windows password / Hello (Thessley QR off)"),
            )
            return "".join(
                f'<option value="{value}"{" selected" if value == selected else ""}>{label}</option>'
                for value, label in items
            )
        error = f'<section class="card error">{html.escape(message)}</section>' if message else ""
        content = error + f'''<h1>AD sign-in method policy</h1>
<p class="muted">Precedence: workstation override, then highest-priority matching AD group, then domain default. Windows password and Hello remain available as recovery.</p>
<section class="card"><h2>Domain default</h2><form method="post" action="/admin/policy/default">
<input type="hidden" name="csrf" value="{html.escape(session['csrf'])}"><label for="default-method">Method</label>
<select id="default-method" name="method">{options(snapshot['default']['method'])}</select><p><button>Save domain default</button></p>
<p class="muted small">Current: {html.escape(self._method_label(snapshot['default']['method']))}. The short-lived phone certificate method is unavailable until its KDC proof is complete.</p></form></section>
<section class="card"><h2>AD group override</h2><p class="muted">Use the security group's SID. Higher priority wins; rules tied at the same priority must select the same method.</p>
<form method="post" action="/admin/policy/group"><input type="hidden" name="csrf" value="{html.escape(session['csrf'])}">
<label for="group-sid">Group SID</label><input id="group-sid" name="group_sid" maxlength="184" required placeholder="S-1-5-21-…">
<label for="group-priority">Priority (0–1000)</label><input id="group-priority" name="priority" type="number" min="0" max="1000" value="100" required>
<label for="group-method">Method</label><select id="group-method" name="method">{options('tpm_smartcard')}</select><p><button>Save group rule</button></p></form>'''
        if snapshot["groups"]:
            for rule in snapshot["groups"]:
                content += f'''<div class="phone"><strong>{html.escape(rule['group_sid'])}</strong> · {html.escape(self._method_label(rule['method']))} · priority {rule['priority']}
<form method="post" action="/admin/policy/group/remove"><input type="hidden" name="csrf" value="{html.escape(session['csrf'])}"><input type="hidden" name="group_sid" value="{html.escape(rule['group_sid'])}"><button class="danger small">Remove rule</button></form></div>'''
        else:
            content += '<p class="muted">No group overrides.</p>'
        content += '</section><section class="card"><h2>Workstation override</h2>'
        if machines:
            content += f'''<form method="post" action="/admin/policy/machine"><input type="hidden" name="csrf" value="{html.escape(session['csrf'])}">
<label for="machine-id">Paired workstation</label><select id="machine-id" name="machine_id" required>'''
            for machine in machines:
                label = f"{machine['machine_name']} ({machine['machine_id'][:8]})"
                content += f'<option value="{html.escape(machine["machine_id"])}">{html.escape(label)}</option>'
            overrides = {rule["machine_id"]: rule["method"] for rule in snapshot["machines"]}
            content += f'''</select><label for="machine-method">Method</label><select id="machine-method" name="method"><option value="inherit">Inherit group/default</option>{options("tpm_smartcard")}</select><p><button>Save workstation rule</button></p></form>'''
            for machine in machines:
                if machine["machine_id"] in overrides:
                    label = f"{machine['machine_name']} ({machine['machine_id'][:8]})"
                    content += f'<div class="phone"><strong>{html.escape(label)}</strong> · {html.escape(self._method_label(overrides[machine["machine_id"]]))}</div>'
        else:
            content += '<p class="muted">No paired workstations yet.</p>'
        content += '</section><p><a class="button" href="/admin/">Back to accounts</a></p>'
        return self._response(200, self._page("AD sign-in policy", content))

    @staticmethod
    def _method_label(method: str) -> str:
        from .login_policy import METHOD_LABELS
        return METHOD_LABELS.get(method, "Unknown method")

    def _enrollment_page(self, request_id: str, session: dict, *, qr_data: str = "", app_link: str = "",
                         message: str = "", status_code: int = 200, sid: str = ""):
        if not qr_data:
            qr_data, stored_link, _expires = self._enrollment_qrs.get(request_id, ("", "", 0))
            if not app_link:
                app_link = stored_link
        state = self.phones.enrollment_status(machine_id=CENTRAL_AD_MACHINE_ID, request_id=request_id)
        if state is None:
            return self._response(404, self._page("Phone enrollment", '<section class="card error">Enrollment not found. It may have expired.</section>'))
        if state["status"] == "confirmed":
            with self._lock:
                self._enrollment_qrs.pop(request_id, None)
            back = (f'<a class="button" href="/admin/account?sid={html.escape(sid, quote=True)}">Back to accounts</a>'
                    if sid else '<a class="button" href="/admin/">Back to accounts</a>')
            content = '<h1>Phone enrolled</h1><section class="card success">The AD account phone is now active across paired PCs.</section>' + back
        elif state["status"] in ("expired", "denied"):
            with self._lock:
                self._enrollment_qrs.pop(request_id, None)
            back = (f'<a class="button" href="/admin/account?sid={html.escape(sid, quote=True)}">Back to accounts</a>'
                    if sid else '<a class="button" href="/admin/">Back to accounts</a>')
            content = '<h1>Enrollment ended</h1><section class="card error">This request expired or was cancelled. Start a fresh enrollment from the account list.</section>' + back
        else:
            # Same throttling hazard as the AD key page: reload until terminal.
            sid_query = f"&sid={html.escape(sid, quote=True)}" if sid else ""
            refresh, refresh_nonce = self._status_poll(
                state["status"], f"/admin/enrollment-status?id={request_id}")
            reload_href = html.escape(f"/admin/enrollment?id={request_id}{sid_query}", quote=True)
            reload_link = f'<a class="button secondary small" href="{reload_href}">Reload status</a>'
            pairing = state.get("pairing_code")
            qr = f'<div class="qr-wrap"><img class="qr" alt="Thessley phone enrollment QR code" src="{qr_data}"></div>' if qr_data else ""
            open_app = (f'<p><a class="button" href="{html.escape(app_link, quote=True)}">'
                        f'{self._icon("phone")} Open Thessley Passkey on this device</a></p>' if app_link else "")
            error = f'<section class="card error">{html.escape(message)}</section>' if message else ""
            content = refresh + '<h1>Enroll ' + html.escape(self.authority + chr(92) + state["username"]) + '</h1>' + error
            content += '<section class="card"><p>Open Thessley Passkey on this device, or scan the QR with another device. Compare the six-digit code below with the phone; only confirm when both match.</p>' + open_app + qr
            if state["status"] == "pending":
                content += '<p class="status">Waiting for phone approval…</p>'
            elif pairing:
                content += '<p class="status">Pairing code: <strong>' + html.escape(pairing) + '</strong></p>'
                content += f'''<form method="post" action="/admin/confirm-enrollment"><input type="hidden" name="csrf" value="{html.escape(session['csrf'])}"><input type="hidden" name="sid" value="{html.escape(sid)}"><input type="hidden" name="id" value="{html.escape(request_id)}"><button name="confirm" value="match">The codes match — confirm enrollment</button></form>'''
            content += f'''</section><div class="form-actions"><form method="post" action="/admin/cancel-enrollment"><input type="hidden" name="csrf" value="{html.escape(session['csrf'])}"><input type="hidden" name="sid" value="{html.escape(sid)}"><input type="hidden" name="id" value="{html.escape(request_id)}"><button class="danger">Cancel enrollment</button></form>''' + reload_link + '<a class="button" href="/admin/' + (('account?sid=' + sid) if sid else '') + '">Return to accounts</a></div>'
        return self._response(status_code, self._page("Phone enrollment", content),
                              script_nonce=locals().get("refresh_nonce"))


def _query_sid(params) -> str:
    """Read an optional SID used only to scroll back to the account on return."""
    values = params.get("sid", [])
    if len(values) == 1 and re.fullmatch(r"S-1-(?:[0-9]+-)+[0-9]+", values[0]):
        return values[0]
    return ""


def principal_id_from_sid_safe(sid: str) -> str:
    try:
        return principal_id_from_sid(sid)
    except (TypeError, ValueError):
        return ""


def _qr_data_uri(link: str) -> str:
    import qrcode
    from qrcode.image.svg import SvgPathImage

    qr = qrcode.QRCode(version=None, error_correction=qrcode.constants.ERROR_CORRECT_M,
                       box_size=7, border=2)
    qr.add_data(link)
    qr.make(fit=True)
    image = qr.make_image(image_factory=SvgPathImage)
    output = io.BytesIO()
    image.save(output)
    return "data:image/svg+xml;base64," + base64.b64encode(output.getvalue()).decode("ascii")
