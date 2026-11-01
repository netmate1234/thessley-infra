import re
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


def _refresh_seconds(html: str):
    match = re.search(r'<meta http-equiv="refresh" content="(\d+)"', html)
    return int(match.group(1)) if match else None


class AdLogonKeyEnrollmentPageTest(unittest.TestCase):
    def render(self, status, pairing_code=""):
        return _html(_ad_web(status, pairing_code)._ad_logon_key_enrollment_page(
            REQUEST_ID, {"csrf": CSRF}))

    def test_pending_page_reloads_every_two_seconds(self):
        html = self.render("pending")
        self.assertEqual(_refresh_seconds(html), 2)
        self.assertIn("Reload status", html)
        self.assertNotIn("Pairing code", html)

    def test_ready_page_still_reloads_so_a_stale_tab_recovers(self):
        # A browser tab left open while the QR is scanned is throttled; it must
        # still pick up the pairing code instead of waiting forever.
        html = self.render("ready", "123 456")
        self.assertEqual(_refresh_seconds(html), 10)
        self.assertIn("Pairing code: <strong>123 456</strong>", html)
        self.assertIn('action="/admin/confirm-ad-logon-key"', html)
        self.assertIn("Reload status", html)

    def test_terminal_pages_do_not_reload(self):
        for status in ("confirmed", "expired", "cancelled"):
            with self.subTest(status=status):
                html = self.render(status)
                self.assertIsNone(_refresh_seconds(html))
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
        self.assertIn("Change password…", html)
        self.assertIn("/admin/user/password?sid=S-1-5-21-1-2-3-1108", html)

    def test_change_password_action_is_hidden_for_a_dc_administrator(self):
        html = self._render_accounts(self._user("S-1-5-21-1-2-3-1108", dc_admin=True))
        self.assertNotIn("Change password…", html)

    def test_change_password_action_is_hidden_for_the_signed_in_account(self):
        html = self._render_accounts(self._user(self.SESSION_SID))
        self.assertNotIn("Change password…", html)

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
        self.assertIn("Allow workstation QR…", html)
        self.assertIn("/admin/workstation-qr?sid=S-1-5-21-1-2-3-1108&action=allow", html)
        self.assertNotIn("Disallow workstation QR…", html)

    def test_disallow_action_offered_when_authorized(self):
        html = self._render_accounts(self._user("S-1-5-21-1-2-3-1108", authorized=True))
        self.assertIn("Disallow workstation QR…", html)
        self.assertIn("action=revoke", html)

    def test_actions_hidden_for_self_and_dc_administrators(self):
        self.assertNotIn("workstation QR…", self._render_accounts(self._user(self.SESSION_SID)))
        self.assertNotIn("workstation QR…",
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


class PhoneEnrollmentPageTest(unittest.TestCase):
    def render(self, status, pairing_code=""):
        return _html(_phone_web(status, pairing_code)._enrollment_page(
            REQUEST_ID, {"csrf": CSRF}))

    def test_pending_page_reloads_every_two_seconds(self):
        self.assertEqual(_refresh_seconds(self.render("pending")), 2)

    def test_ready_page_still_reloads(self):
        html = self.render("ready", "123 456")
        self.assertEqual(_refresh_seconds(html), 10)
        self.assertIn("Pairing code: <strong>123 456</strong>", html)

    def test_confirmed_page_does_not_reload(self):
        self.assertIsNone(_refresh_seconds(self.render("confirmed")))


if __name__ == "__main__":
    unittest.main()
