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
