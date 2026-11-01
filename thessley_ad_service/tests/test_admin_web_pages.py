import pathlib
import re
import tempfile
import threading
import unittest

from infra.thessley_ad_service.admin_web import AdminWeb

REQUEST_ID = "A" * 32
CSRF = "c" * 32


class _StubRegistry:
    def __init__(self, state):
        self.state = state

    def enrollment_status(self, request_id, *, now=None):
        return dict(self.state) if request_id == REQUEST_ID else None


class _StubPhones:
    def __init__(self, state):
        self.state = state

    def enrollment_status(self, *, machine_id, request_id, now=None):
        return dict(self.state) if request_id == REQUEST_ID else None


def _ad_web(status, pairing_code=""):
    web = object.__new__(AdminWeb)
    web.authority = "THESSLEYLAB"
    web._lock = threading.Lock()
    web._ad_logon_key_qrs = {}
    web.ad_logon_keys = _StubRegistry({
        "principal_id": "a" * 64,
        "username": "martin",
        "authority": "THESSLEYLAB",
        "expires_at": 0,
        "status": status,
        "pairing_code": pairing_code,
        "key_id": "k" * 32,
        "public_key_sha256": "b" * 64,
        "attestation_status": "verified_tee",
    })
    return web


def _phone_web(status, pairing_code=""):
    web = object.__new__(AdminWeb)
    web.authority = "THESSLEYLAB"
    web._lock = threading.Lock()
    web._enrollment_qrs = {}
    web.phones = _StubPhones({
        "status": status,
        "username": "martin",
        "pairing_code": pairing_code,
        "attestation_status": "verified_tee",
    })
    return web


def _html(response) -> str:
    _status, _headers, body = response
    return body.decode("utf-8")


def _has_poll(html: str) -> bool:
    return "setInterval(poll," in html


class AdLogonKeyEnrollmentPageTest(unittest.TestCase):
    def render(self, status, pairing_code=""):
        return _html(_ad_web(status, pairing_code)._ad_logon_key_enrollment_page(
            REQUEST_ID, {"csrf": CSRF}))

    def test_pending_page_reloads_every_two_seconds(self):
        html = self.render("pending")
        self.assertTrue(_has_poll(html))
        self.assertIn("Reload status", html)
        self.assertNotIn("Pairing code", html)

    def test_ready_page_still_reloads_so_a_stale_tab_recovers(self):
        # A browser tab left open while the QR is scanned is throttled; it must
        # still pick up the pairing code instead of waiting forever.
        html = self.render("ready", "123 456")
        self.assertTrue(_has_poll(html))
        self.assertIn("Pairing code: <strong>123 456</strong>", html)
        self.assertIn('action="/admin/confirm-ad-logon-key"', html)
        self.assertIn("Reload status", html)

    def test_terminal_pages_do_not_reload(self):
        for status in ("confirmed", "expired", "cancelled"):
            with self.subTest(status=status):
                html = self.render(status)
                self.assertFalse(_has_poll(html))
                self.assertNotIn("Reload status", html)

    def test_reload_link_keeps_the_request_id(self):
        html = self.render("ready", "123 456")
        self.assertIn(f'href="/admin/ad-logon-key-enrollment?id={REQUEST_ID}"', html)


class AccountPasswordActionTest(unittest.TestCase):
    SESSION_SID = "S-1-5-21-1-2-3-500"

    def _render_accounts(self, user):
        web = object.__new__(AdminWeb)
        web.authority = "THESSLEYLAB"
        web._lock = threading.Lock()
        web.allowed_group_sids = frozenset({"S-1-5-21-1-2-3-1105"})

        class _Dir:
            def list_users(self, groups, limit=1000):
                return {"users": [user]}

        class _NoKeys:
            def list_for_principal(self, principal_id):
                return []

        web.directory = _Dir()
        web.phones = _NoKeys()
        web.ad_logon_keys = _NoKeys()
        return _html(web._directory_page({"sid": self.SESSION_SID, "user": "Administrator", "csrf": CSRF}))

    @staticmethod
    def _user(sid, *, dc_admin=False, enabled=True):
        return {"sid": sid, "sam": "target", "name": "Target User", "enabled": enabled,
                "authorized": True, "dc_administrator": dc_admin}

    def test_change_password_action_is_offered_for_a_normal_account(self):
        html = self._render_accounts(self._user("S-1-5-21-1-2-3-1108"))
        self.assertIn("Change password", html)
        self.assertIn("/admin/user/password?sid=S-1-5-21-1-2-3-1108", html)

    def test_change_password_action_is_hidden_for_a_dc_administrator(self):
        html = self._render_accounts(self._user("S-1-5-21-1-2-3-1108", dc_admin=True))
        self.assertNotIn("Change password", html)

    def test_change_password_action_is_hidden_for_the_signed_in_account(self):
        html = self._render_accounts(self._user(self.SESSION_SID))
        self.assertNotIn("Change password", html)

    def test_password_form_posts_to_the_reset_route(self):
        web = object.__new__(AdminWeb)
        web.authority = "THESSLEYLAB"
        html = _html(web._user_password_page({"csrf": CSRF}, self._user("S-1-5-21-1-2-3-1108")))
        self.assertIn('action="/admin/users/password"', html)
        self.assertIn('name="new_password"', html)
        self.assertIn('name="admin_password"', html)
        self.assertIn('name="sid" value="S-1-5-21-1-2-3-1108"', html)
        self.assertIn("must change it at next sign-in", html)


class WorkstationQrActionTest(unittest.TestCase):
    SESSION_SID = "S-1-5-21-1-2-3-500"

    def _render_accounts(self, user):
        web = object.__new__(AdminWeb)
        web.authority = "THESSLEYLAB"
        web._lock = threading.Lock()
        web.allowed_group_sids = frozenset({"S-1-5-21-1-2-3-1105"})

        class _Dir:
            def list_users(self, groups, limit=1000):
                return {"users": [user]}

        class _NoKeys:
            def list_for_principal(self, principal_id):
                return []

        web.directory = _Dir()
        web.phones = _NoKeys()
        web.ad_logon_keys = _NoKeys()
        return _html(web._directory_page({"sid": self.SESSION_SID, "user": "Administrator",
                                          "csrf": CSRF}))

    @staticmethod
    def _user(sid, *, authorized=False, dc_admin=False):
        return {"sid": sid, "sam": "target", "name": "Target User", "enabled": True,
                "authorized": authorized, "dc_administrator": dc_admin}

    def test_allow_action_offered_when_not_authorized(self):
        html = self._render_accounts(self._user("S-1-5-21-1-2-3-1108"))
        self.assertIn("Allow workstation QR", html)
        self.assertIn("/admin/workstation-qr?sid=S-1-5-21-1-2-3-1108&action=allow", html)
        self.assertNotIn("Disallow workstation QR", html)

    def test_disallow_action_offered_when_authorized(self):
        html = self._render_accounts(self._user("S-1-5-21-1-2-3-1108", authorized=True))
        self.assertIn("Disallow workstation QR", html)
        self.assertIn("action=revoke", html)

    def test_actions_hidden_for_self_and_dc_administrators(self):
        self.assertNotIn("workstation QR", self._render_accounts(self._user(self.SESSION_SID)))
        self.assertNotIn("workstation QR",
                         self._render_accounts(self._user("S-1-5-21-1-2-3-1108", dc_admin=True)))

    def test_confirmation_page_requests_the_admin_password(self):
        web = object.__new__(AdminWeb)
        web.authority = "THESSLEYLAB"
        user = self._user("S-1-5-21-1-2-3-1108")
        for allow, verb in ((True, "Allow workstation QR"), (False, "Disallow workstation QR")):
            with self.subTest(allow=allow):
                html = _html(web._workstation_qr_page({"csrf": CSRF}, user, allow=allow))
                self.assertIn('action="/admin/workstation-qr"', html)
                self.assertIn('name="admin_password"', html)
                self.assertIn(verb, html)
                self.assertIn(f'value="{"allow" if allow else "revoke"}"', html)


class AccountFocusTest(unittest.TestCase):
    SID = "S-1-5-21-1-2-3-1108"

    def test_redirect_returns_to_the_operated_account(self):
        status, headers, _body = AdminWeb._accounts_redirect("user-updated", self.SID)
        self.assertEqual(status, 303)
        location = dict(headers)["Location"]
        self.assertEqual(location, f"/admin/account?sid={self.SID}&notice=user-updated")

    def test_redirect_without_a_sid_has_no_fragment(self):
        _status, headers, _body = AdminWeb._accounts_redirect("user-deleted")
        self.assertEqual(dict(headers)["Location"], "/admin/?notice=user-deleted")

    def test_redirect_ignores_a_malformed_sid(self):
        _status, headers, _body = AdminWeb._accounts_redirect("user-updated", "not-a-sid")
        self.assertEqual(dict(headers)["Location"], "/admin/?notice=user-updated")

    def test_account_cards_carry_a_scroll_target(self):
        web = object.__new__(AdminWeb)
        web.authority = "THESSLEYLAB"
        web._lock = threading.Lock()
        web.allowed_group_sids = frozenset({"S-1-5-21-1-2-3-1105"})

        class _Dir:
            def list_users(self, groups, limit=1000):
                return {"users": [{"sid": self_sid, "sam": "target", "name": "Target",
                                   "enabled": True, "authorized": True, "dc_administrator": False}]}

        class _NoKeys:
            def list_for_principal(self, principal_id):
                return []

        self_sid = self.SID
        web.directory = _Dir()
        web.phones = _NoKeys()
        web.ad_logon_keys = _NoKeys()
        html = _html(web._directory_page({"sid": "S-1-5-21-1-2-3-500", "user": "Administrator",
                                          "csrf": CSRF}))
        self.assertIn(f'id="account-{self.SID}"', html)


class RevokeReturnTest(unittest.TestCase):
    SID = "S-1-5-21-1-2-3-1108"

    def test_anchor_requires_a_sid_that_matches_the_principal(self):
        from infra.thessley_ad_service.protocol import principal_id_from_sid
        pid = principal_id_from_sid(self.SID)
        self.assertEqual(AdminWeb._anchor_sid(self.SID, pid), self.SID)
        self.assertEqual(AdminWeb._anchor_sid(self.SID, "f" * 64), "")
        self.assertEqual(AdminWeb._anchor_sid("not-a-sid", pid), "")

    def test_revoke_forms_on_the_card_carry_the_sid(self):
        web = object.__new__(AdminWeb)
        web.authority = "THESSLEYLAB"
        web._lock = threading.Lock()
        web.allowed_group_sids = frozenset({"S-1-5-21-1-2-3-1105"})

        class _Dir:
            def list_users(self, groups, limit=1000):
                return {"users": [{"sid": "S-1-5-21-1-2-3-1108", "sam": "target", "name": "Target",
                                   "enabled": True, "authorized": True, "dc_administrator": False}]}

        class _Phones:
            def list_for_principal(self, principal_id):
                return [{"credential_id": "c" * 32, "label": "Phone", "machine_name": "PC",
                         "enrolled_at": 1700000000, "attestation_status": "verified_tee",
                         "attestation_reason": ""}]

        class _Keys:
            def list_for_principal(self, principal_id):
                return [{"key_id": "k" * 32, "label": "AD key", "public_key_sha256": "a" * 64,
                         "attestation_status": "verified_tee", "revoked_at": None}]

        web.directory = _Dir()
        web.phones = _Phones()
        web.ad_logon_keys = _Keys()
        html = _html(web._directory_page({"sid": "S-1-5-21-1-2-3-500", "user": "Administrator",
                                          "csrf": CSRF}))
        self.assertIn('action="/admin/revoke"', html)
        self.assertIn('action="/admin/revoke-logon-key"', html)
        for action in ("/admin/revoke", "/admin/revoke-logon-key"):
            with self.subTest(action=action):
                form = re.search(r'<form method="post" action="' + re.escape(action) + r'">.*?</form>',
                                 html, re.S)
                self.assertIsNotNone(form, f"no form for {action}")
                self.assertIn('name="sid" value="S-1-5-21-1-2-3-1108"', form.group(0))

    def test_revoke_redirects_return_to_the_account(self):
        for notice in ("phone-revoked", "logon-key-revoked"):
            with self.subTest(notice=notice):
                _status, headers, _body = AdminWeb._accounts_redirect(notice, self.SID)
                self.assertEqual(dict(headers)["Location"],
                                 f"/admin/account?sid={self.SID}&notice={notice}")

    def _stub_web(self):
        from infra.thessley_ad_service.protocol import principal_id_from_sid
        pid = principal_id_from_sid(self.SID)
        cred, key = "c" * 32, "k" * 32
        web = object.__new__(AdminWeb)
        web.authority = "THESSLEYLAB"
        web._lock = threading.Lock()
        web._session = lambda headers: ("token", {"sid": "S-1-5-21-1-2-3-500",
                                                  "user": "Administrator", "csrf": CSRF})

        class _Phones:
            def list_for_principal(self, principal_id):
                return [{"credential_id": cred, "label": "Phone", "machine_name": "PC",
                         "enrolled_at": 1700000000, "attestation_status": "verified_tee",
                         "attestation_reason": ""}]

        class _Keys:
            def list_for_principal(self, principal_id):
                return [{"key_id": key, "label": "AD key", "public_key_sha256": "a" * 64,
                         "attestation_status": "verified_tee", "revoked_at": None}]

        web.phones = _Phones()
        web.ad_logon_keys = _Keys()
        return web, pid, cred, key

    def test_phone_revocation_confirmation_links_back_to_the_account(self):
        web, pid, cred, _key = self._stub_web()
        form = {"csrf": CSRF, "credential_id": cred, "principal_id": pid, "sid": self.SID}
        status, _headers, body = web._post("/admin/revoke", form, {}, "127.0.0.1")
        html = body.decode("utf-8")
        self.assertEqual(status, 200)
        self.assertIn(f'action="/admin/confirm-revoke"', html)
        self.assertIn(f'href="/admin/account?sid={self.SID}"', html)
        self.assertIn(f'name="sid" value="{self.SID}"', html)

    def test_logon_key_revocation_confirmation_links_back_to_the_account(self):
        web, pid, _cred, key = self._stub_web()
        form = {"csrf": CSRF, "key_id": key, "principal_id": pid, "sid": self.SID}
        status, _headers, body = web._post("/admin/revoke-logon-key", form, {}, "127.0.0.1")
        html = body.decode("utf-8")
        self.assertEqual(status, 200)
        self.assertIn('action="/admin/confirm-revoke-logon-key"', html)
        self.assertIn(f'href="/admin/account?sid={self.SID}"', html)

    def test_confirmation_ignores_a_sid_for_another_principal(self):
        web, pid, cred, _key = self._stub_web()
        other = "S-1-5-21-1-2-3-9999"
        form = {"csrf": CSRF, "credential_id": cred, "principal_id": pid, "sid": other}
        _status, _headers, body = web._post("/admin/revoke", form, {}, "127.0.0.1")
        html = body.decode("utf-8")
        self.assertNotIn(other, html)
        self.assertIn('name="sid" value=""', html)


class DirectoryPagingTest(unittest.TestCase):
    def _web(self, count):
        web = object.__new__(AdminWeb)
        web.authority = "THESSLEYLAB"
        web._lock = threading.Lock()
        web.allowed_group_sids = frozenset({"S-1-5-21-1-2-3-1105"})
        users = [{"sid": f"S-1-5-21-1-2-3-{2000 + i}", "sam": f"user{i:02d}",
                  "name": f"User {i:02d}", "enabled": True, "authorized": False,
                  "dc_administrator": False} for i in range(count)]

        class _Dir:
            def list_users(self, groups, limit=1000):
                return {"users": users}

        class _NoKeys:
            def list_for_principal(self, principal_id):
                return []

        web.directory = _Dir()
        web.phones = _NoKeys()
        web.ad_logon_keys = _NoKeys()
        return web

    @staticmethod
    def _cards(html):
        return html.count('class="card account-card"')

    def render(self, web, **kwargs):
        return _html(web._directory_page({"sid": "S-1-5-21-1-2-3-500", "user": "Administrator",
                                          "csrf": CSRF}, **kwargs))

    def test_first_page_is_capped_and_offers_next(self):
        html = self.render(self._web(45))
        self.assertEqual(self._cards(html), AdminWeb.PAGE_SIZE)
        self.assertIn("Page 1 of 3", html)
        self.assertIn("page=2", html)
        self.assertNotIn("page=0", html)

    def test_last_page_holds_the_remainder(self):
        html = self.render(self._web(45), page=3)
        self.assertEqual(self._cards(html), 5)
        self.assertIn("Page 3 of 3", html)
        self.assertIn("page=2", html)
        self.assertNotIn("page=4", html)

    def test_page_beyond_the_end_is_clamped(self):
        html = self.render(self._web(25), page=99)
        self.assertEqual(self._cards(html), 5)
        self.assertIn("Page 2 of 2", html)

    def test_search_filters_before_paging(self):
        html = self.render(self._web(45), query="user4")
        self.assertEqual(self._cards(html), 5)           # user40..user44 only
        self.assertNotIn("Page 1 of", html)              # one page, so no pager
        self.assertIn("5 accounts", html)

    def test_single_account_view_shows_only_that_account(self):
        web = self._web(45)
        sid = "S-1-5-21-1-2-3-2007"
        html = self.render(web, single_sid=sid)
        self.assertEqual(self._cards(html), 1)
        self.assertIn('id="account-' + sid + '"', html)
        self.assertNotIn("Page 1 of", html)
        self.assertIn('href="/admin/"', html)            # All accounts

    def test_sign_out_is_in_the_top_right_of_the_page_header(self):
        html = self.render(self._web(5))
        header = html.split("<header", 1)[1].split("</header>", 1)[0]
        self.assertIn('action="/admin/logout"', header)
        self.assertIn('class="header-actions"', header)
        self.assertEqual(html.count('action="/admin/logout"'), 1)
        self.assertNotIn('class="session-actions"', html)

    def test_single_account_view_also_has_sign_out_in_the_header(self):
        html = self.render(self._web(5), single_sid="S-1-5-21-1-2-3-2003")
        header = html.split("<header", 1)[1].split("</header>", 1)[0]
        self.assertIn('action="/admin/logout"', header)

    def test_unknown_single_account_is_a_404(self):
        status, _headers, _body = self._web(3)._directory_page(
            {"sid": "S-1-5-21-1-2-3-500", "user": "Administrator", "csrf": CSRF},
            single_sid="S-1-5-21-1-2-3-999999")
        self.assertEqual(status, 404)


class QrLoginPageTest(unittest.TestCase):
    REQ = "B" * 32

    def _web(self, status="pending", expires_in=60):
        import time as _time
        web = object.__new__(AdminWeb)
        web.authority = "THESSLEYLAB"
        web._lock = threading.Lock()

        class _Challenges:
            def peek_result(self, *, machine_id, request_id, now=None):
                return status

            def consume_result(self, *, machine_id, request_id, now=None):
                return None

        class _Phones:
            def list_for_principal(self, principal_id):
                return []

        web.challenges = _Challenges()
        web.phones = _Phones()
        web._qr_logins = {self.REQ: {
            "sid": "S-1-5-21-1-2-3-500", "principal_id": "a" * 64, "username": "Administrator",
            "client_ip": "10.0.0.5", "preauth": "cookie-nonce",
            "expires_at": _time.time() + expires_in, "qr": "data:image/svg+xml;base64,AA",
            "link": "thessleypam://login?x=1",
        }}
        return web

    @staticmethod
    def _headers():
        return {"Cookie": "thessley_ad_preauth=cookie-nonce"}

    def test_page_polls_instead_of_reloading(self):
        web = self._web()
        status, headers, body = web._get(f"/admin/qr-login", f"id={self.REQ}", self._headers(), "10.0.0.5")
        html = body.decode()
        self.assertEqual(status, 200)
        self.assertIn("fetch(\"/admin/qr-status?id=", html)
        self.assertIn("setInterval(poll,2000)", html)
        self.assertNotIn("setTimeout", html)
        self.assertIn('class="qr-login"', html)
        csp = dict(headers)["Content-Security-Policy"]
        self.assertIn("connect-src 'self'", csp)
        self.assertIn("script-src 'nonce-", csp)
        self.assertIn("failures+=1", html)

    def test_status_endpoint_reports_the_challenge_state(self):
        for state, expected in (("pending", "pending"), ("approved", "approved"), ("denied", "denied")):
            with self.subTest(state=state):
                web = self._web(status=state)
                status, _headers, body = web._get("/admin/qr-status", f"id={self.REQ}", self._headers(), "10.0.0.5")
                self.assertEqual(status, 200)
                self.assertEqual(body.decode(), '{"status":"%s"}' % expected)

    def test_status_endpoint_rejects_another_client(self):
        web = self._web()
        _s, _h, body = web._get("/admin/qr-status", f"id={self.REQ}", self._headers(), "10.9.9.9")
        self.assertIn("expired", body.decode())


class LogPageTest(unittest.TestCase):
    def _web(self, path):
        web = object.__new__(AdminWeb)
        web.log_path = path
        web._lock = threading.Lock()
        return web

    def test_first_page_shows_newest_lines_first(self):
        with tempfile.TemporaryDirectory() as tmp:
            log = pathlib.Path(tmp) / "service.log"
            log.write_text("\n".join(f"line {i}" for i in range(1200)) + "\n")
            status, _headers, body = self._web(str(log))._log_page(
                {"sid": "S-1", "user": "Administrator", "csrf": CSRF})
        html = body.decode()
        self.assertEqual(status, 200)
        self.assertIn("line 1199", html)
        self.assertIn("line 700", html)          # 500 lines per page: 1199..700
        self.assertNotIn("line 699", html)
        self.assertIn("Page 1 of 3", html)
        self.assertIn("/admin/log?page=2", html)
        self.assertNotIn("?page=0", html)

    def test_last_page_has_the_remainder_and_no_older_link(self):
        with tempfile.TemporaryDirectory() as tmp:
            log = pathlib.Path(tmp) / "service.log"
            log.write_text("\n".join(f"line {i}" for i in range(1200)) + "\n")
            status, _headers, body = self._web(str(log))._log_page(
                {"sid": "S-1", "user": "Administrator", "csrf": CSRF}, page=3)
        html = body.decode()
        self.assertEqual(status, 200)
        self.assertIn("Page 3 of 3", html)
        self.assertIn("line 0", html)
        self.assertNotIn("?page=4", html)

    def test_page_beyond_the_end_is_clamped(self):
        with tempfile.TemporaryDirectory() as tmp:
            log = pathlib.Path(tmp) / "service.log"
            log.write_text("\n".join(f"line {i}" for i in range(40)) + "\n")
            status, _headers, body = self._web(str(log))._log_page(
                {"sid": "S-1", "user": "Administrator", "csrf": CSRF}, page=99)
        self.assertEqual(status, 200)
        self.assertIn("Page 1 of 1", body.decode())

    def test_log_escapes_markup(self):
        with tempfile.TemporaryDirectory() as tmp:
            log = pathlib.Path(tmp) / "service.log"
            log.write_text("<script>alert(1)</script>\n")
            _s, _h, body = self._web(str(log))._log_page(
                {"sid": "S-1", "user": "Administrator", "csrf": CSRF})
        html = body.decode()
        self.assertNotIn("<script>alert(1)</script>", html)
        self.assertIn("&lt;script&gt;", html)

    def test_missing_log_is_a_503(self):
        status, _headers, _body = self._web("/nonexistent/service.log")._log_page(
            {"sid": "S-1", "user": "Administrator", "csrf": CSRF})
        self.assertEqual(status, 503)

    def test_unconfigured_log_is_a_503(self):
        status, _headers, _body = self._web(None)._log_page(
            {"sid": "S-1", "user": "Administrator", "csrf": CSRF})
        self.assertEqual(status, 503)


class ConfirmationRedirectTest(unittest.TestCase):
    def test_confirmation_notices_land_on_the_account(self):
        sid = "S-1-5-21-1-2-3-1108"
        for notice in ("ad-key-confirmed", "enrollment-confirmed"):
            with self.subTest(notice=notice):
                self.assertIn("confirmed", AdminWeb._notice_text(notice).lower())
                _s, headers, _b = AdminWeb._accounts_redirect(notice, sid)
                self.assertEqual(dict(headers)["Location"],
                                 f"/admin/account?sid={sid}&notice={notice}")


class EnrollmentStatusTest(unittest.TestCase):
    REQ = "C" * 32

    def _web(self, state):
        web = object.__new__(AdminWeb)
        web._lock = threading.Lock()
        web._session = lambda headers: ("token", {"sid": "S-1", "user": "Administrator", "csrf": CSRF})

        class _Phones:
            def enrollment_status(self, *, machine_id, request_id, now=None):
                return state

        class _Keys:
            def enrollment_status(self, request_id, now=None):
                return state

        web.phones = _Phones()
        web.ad_logon_keys = _Keys()
        return web

    def test_phone_enrollment_status_is_json(self):
        status, headers, body = self._web({"status": "ready"})._get(
            "/admin/enrollment-status", f"id={self.REQ}", {}, "127.0.0.1")
        self.assertEqual(status, 200)
        self.assertEqual(dict(headers)["Content-Type"], "application/json; charset=utf-8")
        self.assertEqual(body.decode(), '{"status":"ready"}')

    def test_ad_key_status_is_json(self):
        _s, _h, body = self._web({"status": "confirmed"})._get(
            "/admin/ad-logon-key-status", f"id={self.REQ}", {}, "127.0.0.1")
        self.assertEqual(body.decode(), '{"status":"confirmed"}')

    def test_unknown_request_reports_gone(self):
        _s, _h, body = self._web(None)._get(
            "/admin/enrollment-status", f"id={self.REQ}", {}, "127.0.0.1")
        self.assertEqual(body.decode(), '{"status":"gone"}')

    def test_invalid_id_is_rejected(self):
        status, _h, _b = self._web({"status": "ready"})._get(
            "/admin/enrollment-status", "id=short", {}, "127.0.0.1")
        self.assertEqual(status, 400)


class PasswordChangeOptionTest(unittest.TestCase):
    def test_create_and_reset_forms_offer_the_option(self):
        web = object.__new__(AdminWeb)
        web.authority = "THESSLEYLAB"
        user = {"sid": "S-1-5-21-1-2-3-1108", "sam": "target", "name": "Target",
                "enabled": True, "authorized": True, "dc_administrator": False}
        for html in (_html(web._user_form({"csrf": CSRF})),
                     _html(web._user_password_page({"csrf": CSRF}, user))):
            with self.subTest(page=html[:40]):
                self.assertIn('name="must_change" value="yes" checked', html)


class PhoneEnrollmentPageTest(unittest.TestCase):
    def render(self, status, pairing_code=""):
        return _html(_phone_web(status, pairing_code)._enrollment_page(
            REQUEST_ID, {"csrf": CSRF}))

    def test_pending_page_reloads_every_two_seconds(self):
        self.assertTrue(_has_poll(self.render("pending")))

    def test_ready_page_still_reloads(self):
        html = self.render("ready", "123 456")
        self.assertTrue(_has_poll(html))
        self.assertIn("Pairing code: <strong>123 456</strong>", html)

    def test_confirmed_page_does_not_reload(self):
        self.assertFalse(_has_poll(self.render("confirmed")))


if __name__ == "__main__":
    unittest.main()
