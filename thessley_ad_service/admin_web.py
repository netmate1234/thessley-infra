"""Small Windows-domain-admin website for centrally managed AD phone keys."""

from __future__ import annotations

import base64
import ctypes
import html
import io
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

    def __init__(self, *, directory, phones, challenges, allowed_group_sids, authority: str,
                 public_host: str, certificate_fingerprint: str, login_policy=None, machines=None,
                 ad_logon_keys=None):
        self.directory = directory
        self.phones = phones
        self.challenges = challenges
        self.allowed_group_sids = frozenset(allowed_group_sids)
        self.authority = authority
        self.public_host = public_host
        self.certificate_fingerprint = certificate_fingerprint
        self.login_policy = login_policy
        self.machines = machines
        self.ad_logon_keys = ad_logon_keys
        self._sessions: dict[str, dict] = {}
        self._preauth: dict[str, float] = {}
        self._login_attempts: dict[str, list[float]] = {}
        self._enrollment_qrs: dict[str, tuple[str, float]] = {}
        self._ad_logon_key_qrs: dict[str, tuple[str, float]] = {}
        self._qr_logins: dict[str, dict] = {}
        self._lock = threading.RLock()

    @staticmethod
    def _response(status: int, body: str, content_type: str = "text/html; charset=utf-8",
                  extra_headers: tuple[tuple[str, str], ...] = ()) -> tuple[int, list[tuple[str, str]], bytes]:
        data = body.encode("utf-8")
        headers = [
            ("Content-Type", content_type),
            ("Cache-Control", "no-store"),
            ("X-Content-Type-Options", "nosniff"),
            ("Referrer-Policy", "no-referrer"),
            ("Strict-Transport-Security", "max-age=31536000"),
            ("Content-Security-Policy", "default-src 'none'; img-src data:; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"),
            ("Content-Length", str(len(data))),
            ("Connection", "close"),
        ]
        headers.extend(extra_headers)
        return status, headers, data

    @staticmethod
    def _page(title: str, content: str) -> str:
        return """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>""" + html.escape(title) + """ · Thessley AD</title>
<style>
:root{color-scheme:dark;--ink:#edf3f8;--muted:#b2bfcc;--line:#344555;--blue:#77b7ff;--bg:#0c131a;--surface:#151f29;--field:#0e1720}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:16px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif}
main{max-width:1100px;margin:28px auto;padding:0 18px}.brand{font-weight:750;color:var(--blue);font-size:1.25rem}
h1{font-size:1.65rem;margin:.4rem 0 1.1rem}h2{font-size:1.2rem;margin:0 0 .7rem}.muted{color:var(--muted)}
.card{background:var(--surface);border:1px solid var(--line);border-radius:12px;padding:18px;margin:14px 0;box-shadow:0 8px 24px #0004}
.user{display:grid;grid-template-columns:minmax(220px,1fr) minmax(260px,1.2fr) auto;gap:12px;align-items:center}
.phone{border-top:1px solid var(--line);margin-top:12px;padding-top:10px}.row{display:flex;gap:10px;align-items:center;flex-wrap:wrap}
.rights{display:flex;gap:6px;flex-wrap:wrap;margin-top:8px}.badge{display:inline-block;border-radius:999px;padding:2px 9px;background:#283847;color:#e1ebf4;font-size:.82rem;font-weight:650}.badge.yes{background:#173a27;color:#a8e6b8}.badge.no{background:#2a3037;color:#c1cbd4}
label{display:block;font-weight:600;margin:8px 0 4px}input{font:inherit;padding:9px 10px;border:1px solid #526475;border-radius:7px;max-width:100%;background:var(--field);color:var(--ink)}input:focus-visible,button:focus-visible,.button:focus-visible{outline:3px solid #9acbff;outline-offset:2px}
button,.button{font:inherit;font-weight:700;background:var(--blue);color:#091522;border:0;border-radius:7px;padding:9px 13px;cursor:pointer;text-decoration:none;display:inline-block}
button.danger{background:#d46a73;color:#210b0d}.small{font-size:.9rem}.qr{width:min(310px,82vw);height:auto;background:white;border:1px solid var(--line);border-radius:8px;padding:8px}
code{overflow-wrap:anywhere}.status{font-weight:700}.error{background:#351b20;border-color:#7b343e}.success{background:#183324;border-color:#35714b}
@media(max-width:720px){main{margin:14px auto}.user{grid-template-columns:1fr}.card{padding:14px}}
</style></head><body><main><div class="brand">Thessley · Active Directory</div>""" + content + "</main></body></html>"

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

    def _get(self, path: str, query: str, headers, client_ip: str):
        if path == "/":
            return self._response(303, "", extra_headers=(("Location", "/admin/"),))
        if path in ("/admin", "/admin/"):
            token, session = self._session(headers)
            if not session:
                return self._login_page(headers)
            return self._directory_page(session)
        if path == "/admin/policy":
            token, session = self._session(headers)
            if not session:
                return self._login_page(headers)
            return self._policy_page(session)
        if path == "/admin/qr-login":
            params = parse_qs(query, keep_blank_values=True)
            request_ids = params.get("id", [])
            if len(request_ids) != 1 or not _REQUEST_ID.fullmatch(request_ids[0]):
                return self._login_page(headers, "That phone sign-in request is invalid or expired.")
            return self._qr_login_page(request_ids[0], headers, client_ip)
        token, session = self._session(headers)
        if not session:
            return self._login_page(headers)
        if path == "/admin/enrollment":
            params = parse_qs(query, keep_blank_values=True)
            request_ids = params.get("id", [])
            if len(request_ids) != 1 or not _REQUEST_ID.fullmatch(request_ids[0]):
                return self._response(400, self._page("Enrollment", "<section class=card>Invalid enrollment ID.</section>"))
            qr_data = self._enrollment_qrs.get(request_ids[0], ("", 0))[0]
            return self._enrollment_page(request_ids[0], session, qr_data=qr_data)
        if path == "/admin/ad-logon-key-enrollment":
            params = parse_qs(query, keep_blank_values=True)
            request_ids = params.get("id", [])
            if len(request_ids) != 1 or not _REQUEST_ID.fullmatch(request_ids[0]):
                return self._response(400, self._page("AD key enrollment", "<section class=card>Invalid enrollment ID.</section>"))
            return self._ad_logon_key_enrollment_page(
                request_ids[0], session, self._ad_logon_key_qrs.get(request_ids[0], ("", 0))[0]
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
<p class="muted">Sign in with a {html.escape(self.authority)} account that is an administrator on this domain controller.</p>
<form method="post" action="/admin/login"><input type="hidden" name="preauth" value="{html.escape(nonce)}">
<label for="user">Account name (without the domain prefix)</label><input id="user" name="user" autocomplete="username" required maxlength="20">
<label for="password">Password</label><input id="password" name="password" type="password" autocomplete="current-password" required maxlength="1024">
<p><button type="submit">Sign in with password</button></p></form></section>
<section class="card"><h2>Sign in with Thessley Passkey</h2>
<p class="muted">Use a phone already enrolled centrally for this AD account. The account must be an administrator on this domain controller.</p>
<form method="post" action="/admin/qr-login"><input type="hidden" name="preauth" value="{html.escape(nonce)}">
<label for="qr-user">Account name (without the domain prefix)</label><input id="qr-user" name="user" autocomplete="username" required maxlength="20">
<p><button type="submit">Continue with phone</button></p></form></section>"""
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
            self._sessions[token] = {"sid": sid, "user": username, "csrf": csrf, "last": time.monotonic()}
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
            return self._login_page(headers, "Could not start phone sign-in. Try again or use the password option.")
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
            refresh = f'<meta http-equiv="refresh" content="2;url=/admin/qr-login?id={html.escape(request_id)}">'
            link = html.escape(pending["link"], quote=True)
            qr = html.escape(pending["qr"], quote=True)
            account = html.escape(self.authority + chr(92) + pending["username"])
            content = f"""{refresh}<h1>Approve admin sign-in</h1><section class="card">
<p>Scan with Thessley Passkey for <strong>{account}</strong>. The phone must already be enrolled centrally for this account.</p>
<img class="qr" alt="Thessley AD administrator sign-in QR code" src="{qr}">
<p><a class="button" href="{link}">Open Thessley Passkey</a></p><p class="status">Waiting for phone approval…</p>
<p class="muted small">This request expires shortly. Password sign-in remains available.</p></section>"""
            return self._response(200, self._page("Approve admin sign-in", content))
        with self._lock:
            self._qr_logins.pop(request_id, None)
        _LOG.warning("admin_qr_login_not_approved sid=%s source=%s status=%s",
                     pending["sid"], pending["client_ip"], status)
        return self._login_page(headers, "Phone sign-in expired or was denied. You can try again or use your password.")

    def _post(self, path: str, form: dict[str, str], headers, client_ip: str):
        if path == "/admin/login":
            if not self._consume_login_preauth(form, headers, client_ip):
                return self._login_page(headers, "Sign-in failed. Refresh and try again.")
            username = form.get("user", "")
            password = form.pop("password", "")
            sid = WindowsAdminLogin.authenticate(username, password, self.authority)
            del password
            if not sid:
                _LOG.warning("admin_login_failed source=%s", client_ip)
                return self._login_page(headers, "Sign-in failed. Check the account and password, then try again.")
            return self._new_admin_session(sid, username, client_ip, "password")

        if path == "/admin/qr-login":
            return self._start_qr_admin_login(form, headers, client_ip)

        token, session = self._session(headers)
        if not session or not secrets.compare_digest(form.get("csrf", ""), session["csrf"]):
            return self._response(403, self._page("Session expired", '<section class="card error">Session expired. Sign in again.</section>'))
        if path == "/admin/logout":
            with self._lock:
                self._sessions.pop(token, None)
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
                self._enrollment_qrs = {key: value for key, value in self._enrollment_qrs.items() if value[1] > now}
                self._enrollment_qrs[enrollment["request_id"]] = (qr_data, enrollment["expires_at"])
            _LOG.info("admin_enrollment_started actor=%s target=%s", session["sid"], principal.sid)
            return self._response(303, "", extra_headers=((
                "Location", f"/admin/enrollment?id={enrollment['request_id']}"),))
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
                    key: value for key, value in self._ad_logon_key_qrs.items() if value[1] > now
                }
                self._ad_logon_key_qrs[request["request_id"]] = (qr, request["expires_at"])
            _LOG.info("admin_ad_logon_key_enrollment_started actor=%s target=%s request=%s",
                      session["sid"], principal.sid, request["request_id"])
            return self._response(303, "", extra_headers=((
                "Location", f"/admin/ad-logon-key-enrollment?id={request['request_id']}"),))
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
            return self._response(303, "", extra_headers=((
                "Location", f"/admin/ad-logon-key-enrollment?id={request_id}"),))
        if path == "/admin/cancel-ad-logon-key":
            request_id = form.get("id", "")
            if self.ad_logon_keys is not None and _REQUEST_ID.fullmatch(request_id):
                self.ad_logon_keys.cancel_enrollment(request_id)
                with self._lock:
                    self._ad_logon_key_qrs.pop(request_id, None)
            return self._response(303, "", extra_headers=(("Location", "/admin/"),))
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
            return self._response(303, "", extra_headers=(("Location", f"/admin/enrollment?id={request_id}"),))
        if path == "/admin/cancel-enrollment":
            request_id = form.get("id", "")
            if not _REQUEST_ID.fullmatch(request_id):
                return self._response(400, self._page("Enrollment", '<section class="card error">Invalid enrollment reference.</section>'))
            self.phones.cancel_enrollment(machine_id=CENTRAL_AD_MACHINE_ID, request_id=request_id)
            with self._lock:
                self._enrollment_qrs.pop(request_id, None)
            _LOG.info("admin_enrollment_cancelled actor=%s request=%s", session["sid"], request_id)
            return self._response(303, "", extra_headers=(("Location", "/admin/"),))
        if path == "/admin/revoke":
            credential = form.get("credential_id", "")
            principal_id = form.get("principal_id", "")
            if not _CREDENTIAL_ID.fullmatch(credential) or not re.fullmatch(r"[a-f0-9]{64}", principal_id):
                return self._response(400, self._page("Revoke key", '<section class="card error">Invalid key reference.</section>'))
            matching = next((item for item in self.phones.list_for_principal(principal_id)
                             if item["credential_id"] == credential), None)
            if not matching:
                return self._response(404, self._page("Revoke key", '<section class="card error">No active matching phone key was found.</section>'))
            label = html.escape(str(matching.get("label", "Phone")))
            machine_name = html.escape(str(matching.get("machine_name", "")))
            content = f'''<h1>Confirm phone revocation</h1>
<section class="card error"><p>You are about to revoke <strong>{label}</strong> on <strong>{machine_name}</strong>.</p>
<p>This phone will no longer approve sign-ins. AD logon keys enrolled through this phone will also be revoked. Revocation is permanent; audit records are retained.</p>
<form method="post" action="/admin/confirm-revoke"><input type="hidden" name="csrf" value="{html.escape(session['csrf'])}">
<input type="hidden" name="credential_id" value="{html.escape(credential)}"><input type="hidden" name="principal_id" value="{html.escape(principal_id)}">
<button class="danger">Yes, revoke this phone</button> <a class="button" href="/admin/">Cancel</a></form></section>'''
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
            return self._response(303, "", extra_headers=(("Location", "/admin/"),))
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
                content = f'''<h1>Confirm AD logon-key revocation</h1>
<section class="card error"><p>Revoke <strong>{html.escape(key["label"])}</strong> for this AD account?</p>
<p>Fingerprint: <code>{html.escape(key["public_key_sha256"])}</code></p>
<p>This public key is not currently eligible for sign-in. Revocation is permanent.</p>
<form method="post" action="/admin/confirm-revoke-logon-key"><input type="hidden" name="csrf" value="{html.escape(session['csrf'])}">
<input type="hidden" name="key_id" value="{html.escape(key_id)}"><input type="hidden" name="principal_id" value="{html.escape(principal_id)}">
<button class="danger">Yes, revoke this key</button> <a class="button" href="/admin/">Cancel</a></form></section>'''
                return self._response(200, self._page("Confirm AD logon-key revocation", content))
            if not self.ad_logon_keys.revoke(key_id=key_id, administrator=session["sid"]):
                return self._response(409, self._page("AD logon key", '<section class="card error">The key was already revoked or could not be updated.</section>'))
            _LOG.warning("admin_ad_logon_key_revoked actor=%s principal_id=%s key_id=%s",
                         session["sid"], principal_id, key_id)
            return self._response(303, "", extra_headers=(("Location", "/admin/"),))
        return self._response(404, self._page("Not found", "<section class=card>Page not found.</section>"))

    def _directory_page(self, session: dict):
        try:
            snapshot = self.directory.list_users(self.allowed_group_sids, limit=1000)
        except Exception:
            _LOG.exception("admin_directory_query_failed sid=%s", session.get("sid", "unknown"))
            return self._response(503, self._page("Directory unavailable", '<section class="card error">Active Directory could not be queried. Try again shortly.</section>'))
        content = f"""<div class="row" style="justify-content:space-between"><h1>AD accounts</h1>
<form method="post" action="/admin/logout"><input type="hidden" name="csrf" value="{html.escape(session['csrf'])}"><button class="danger">Sign out</button></form></div>
<p><a class="button" href="/admin/policy">Sign-in method policy</a></p>
<p class="muted">Signed in as {html.escape(self.authority + chr(92) + session['user'])}. Enrollments are central to the AD account and work on every paired PC.</p>
<section class="card small"><strong>Rights:</strong> Workstation QR shows membership in the configured Thessley sign-in group. DC admin shows membership in the domain controller's built-in Administrators group; that right is required for this management site. The indicators are independent and read-only.</section>"""
        for user in snapshot.get("users", []):
            if not user.get("enabled"):
                continue
            sid = str(user.get("sid", ""))
            principal_id = principal_id_from_sid_safe(sid)
            if not principal_id:
                continue
            authorized = bool(user.get("authorized"))
            dc_administrator = bool(user.get("dc_administrator"))
            content += '<section class="card user"><div><h2>' + html.escape(user.get("name") or user.get("sam", "")) + '</h2><div class="muted">' + html.escape(self.authority + chr(92) + user.get("sam", "")) + '</div>'
            content += '<div class="rights"><span class="badge ' + ("yes" if authorized else "no") + '">Workstation QR: ' + ("allowed" if authorized else "not allowed") + '</span>'
            content += '<span class="badge ' + ("yes" if dc_administrator else "no") + '">DC admin: ' + ("yes" if dc_administrator else "no") + '</span></div></div><div>'
            keys = self.phones.list_for_principal(principal_id)
            if keys:
                for key in keys:
                    attestation = str(key.get("attestation_status", "unverified"))
                    reason = str(key.get("attestation_reason", ""))
                    protection, protection_class = {
                        "verified_tee": ("TEE-protected · server verified", "yes"),
                        "verified_strongbox": ("StrongBox-protected · server verified", "yes"),
                        "verified_software": ("Software-backed · server verified", "no"),
                    }.get(attestation, ("Not verified · treat as software-backed", "no"))
                    content += '<div class="phone"><div><strong>' + html.escape(key["label"]) + '</strong> · ' + html.escape(key["machine_name"]) + '</div><div class="muted small">Enrolled ' + html.escape(time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(key["enrolled_at"]))) + '</div>'
                    content += f'<div class="badge {protection_class}">Phone-key protection: {protection}</div>'
                    if attestation == "unverified" and reason:
                        content += '<div class="muted small">Server check: ' + html.escape(reason) + '</div>'
                    content += f'''<form method="post" action="/admin/revoke" class="row"><input type="hidden" name="csrf" value="{html.escape(session['csrf'])}"><input type="hidden" name="credential_id" value="{html.escape(key['credential_id'])}"><input type="hidden" name="principal_id" value="{principal_id}"><button class="danger small">Revoke phone…</button></form></div>'''
            else:
                content += '<div class="muted">No phone enrolled.</div>'
            content += '<div class="muted small">Phone-key protection is checked by the server during enrollment. AD logon keys are separate sign-in credentials, but revoking the phone key that enrolled them also revokes those linked AD keys.</div>'
            logon_keys = self.ad_logon_keys.list_for_principal(principal_id) if self.ad_logon_keys else []
            active_logon_keys = [key for key in logon_keys if key["revoked_at"] is None]
            content += '<div class="phone"><strong>AD logon keys</strong><div class="muted small">Separate from phone approvals; sign-in is disabled until attestation and the Windows signing bridge are validated.</div>'
            if active_logon_keys:
                for key in active_logon_keys:
                    fingerprint = html.escape(key["public_key_sha256"])
                    attestation = str(key.get("attestation_status", "unverified"))
                    protection, protection_class = {
                        "verified_tee": ("TEE-protected · verified", "yes"),
                        "verified_strongbox": ("StrongBox-protected · verified", "yes"),
                        "verified_software": ("Software-backed · verified", "no"),
                    }.get(attestation, ("Not verified · treat as software-backed", "no"))
                    content += f'''<div class="phone"><strong>{html.escape(key["label"])}</strong>
<div class="muted small">SHA-256 {fingerprint}</div>
<div class="badge {protection_class}">Key protection: {protection}</div>
<form method="post" action="/admin/revoke-logon-key" class="row"><input type="hidden" name="csrf" value="{html.escape(session['csrf'])}"><input type="hidden" name="key_id" value="{html.escape(key['key_id'])}"><input type="hidden" name="principal_id" value="{principal_id}"><button class="danger small">Revoke key…</button></form></div>'''
            else:
                content += '<div class="muted small">No AD logon key enrolled.</div>'
            content += '</div>'
            content += '</div><div>'
            if authorized or dc_administrator:
                content += f'''<form method="post" action="/admin/enroll"><input type="hidden" name="csrf" value="{html.escape(session['csrf'])}"><input type="hidden" name="sid" value="{html.escape(sid)}"><button>Enroll phone</button></form>'''
                content += f'''<form method="post" action="/admin/enroll-ad-logon-key"><input type="hidden" name="csrf" value="{html.escape(session['csrf'])}"><input type="hidden" name="sid" value="{html.escape(sid)}"><button class="small">Add AD logon key…</button></form>'''
            content += '</div></section>'
        if snapshot.get("truncated"):
            content += '<section class="card">Directory listing reached its 1,000-account limit.</section>'
        return self._response(200, self._page("AD accounts", content))

    def _ad_logon_key_enrollment_page(self, request_id: str, session: dict, qr_data: str = "", message: str = ""):
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
            refresh = '<meta http-equiv="refresh" content="2">' if state["status"] == "pending" else ''
            error = f'<section class="card error">{html.escape(message)}</section>' if message else ''
            qr = f'<img class="qr" alt="AD logon key enrollment QR" src="{html.escape(qr_data, quote=True)}">' if qr_data else ''
            body = refresh + f'<h1>Add AD logon key for {account}</h1>{error}<section class="card"><p>Scan with Thessley Passkey. The phone creates the key and displays a six-digit code. Confirm only when the phone and this page show the same code.</p>{qr}'
            if state["status"] == "pending":
                body += '<p class="status">Waiting for the phone to create and submit its key…</p>'
            elif state["status"] == "ready":
                body += f'<p class="status">Pairing code: <strong>{html.escape(state["pairing_code"])}</strong></p><p class="muted">Protection reported by Android: {html.escape(state["attestation_status"])}. A code match verifies the request, not the phone manufacturer or hardware beyond the attestation result.</p><form method="post" action="/admin/confirm-ad-logon-key"><input type="hidden" name="csrf" value="{html.escape(session["csrf"])}"><input type="hidden" name="id" value="{html.escape(request_id)}"><input type="hidden" name="pairing_code" value="{html.escape(state["pairing_code"])}"><button>Codes match — activate key</button></form>'
            body += '</section><form method="post" action="/admin/cancel-ad-logon-key"><input type="hidden" name="csrf" value="' + html.escape(session["csrf"]) + '"><input type="hidden" name="id" value="' + html.escape(request_id) + '"><button class="danger">Cancel</button> <a class="button" href="/admin/">Return to accounts</a></form>'
        return self._response(200, self._page("AD logon-key enrollment", body))

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

    def _enrollment_page(self, request_id: str, session: dict, *, qr_data: str = "", message: str = "", status_code: int = 200):
        if not qr_data:
            qr_data = self._enrollment_qrs.get(request_id, ("", 0))[0]
        state = self.phones.enrollment_status(machine_id=CENTRAL_AD_MACHINE_ID, request_id=request_id)
        if state is None:
            return self._response(404, self._page("Phone enrollment", '<section class="card error">Enrollment not found. It may have expired.</section>'))
        if state["status"] == "confirmed":
            with self._lock:
                self._enrollment_qrs.pop(request_id, None)
            content = '<h1>Phone enrolled</h1><section class="card success">The AD account phone is now active across paired PCs.</section><a class="button" href="/admin/">Back to accounts</a>'
        elif state["status"] in ("expired", "denied"):
            with self._lock:
                self._enrollment_qrs.pop(request_id, None)
            content = '<h1>Enrollment ended</h1><section class="card error">This request expired or was cancelled. Start a fresh enrollment from the account list.</section><a class="button" href="/admin/">Back to accounts</a>'
        else:
            refresh = '<meta http-equiv="refresh" content="2">' if state["status"] == "pending" else ""
            pairing = state.get("pairing_code")
            qr = f'<img class="qr" alt="Thessley phone enrollment QR code" src="{qr_data}">' if qr_data else ""
            error = f'<section class="card error">{html.escape(message)}</section>' if message else ""
            content = refresh + '<h1>Enroll ' + html.escape(self.authority + chr(92) + state["username"]) + '</h1>' + error
            content += '<section class="card"><p>Scan this QR with Thessley Passkey. Compare the six-digit code below with the phone; only confirm when both match.</p>' + qr
            if state["status"] == "pending":
                content += '<p class="status">Waiting for phone approval…</p>'
            elif pairing:
                content += '<p class="status">Pairing code: <strong>' + html.escape(pairing) + '</strong></p>'
                content += f'''<form method="post" action="/admin/confirm-enrollment"><input type="hidden" name="csrf" value="{html.escape(session['csrf'])}"><input type="hidden" name="id" value="{html.escape(request_id)}"><button name="confirm" value="match">The codes match — confirm enrollment</button></form>'''
            content += f'''</section><form method="post" action="/admin/cancel-enrollment"><input type="hidden" name="csrf" value="{html.escape(session['csrf'])}"><input type="hidden" name="id" value="{html.escape(request_id)}"><button class="danger">Cancel enrollment</button> <a class="button" href="/admin/">Return to accounts</a></form>'''
        return self._response(status_code, self._page("Phone enrollment", content))


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
