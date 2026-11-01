import base64
import json
import subprocess
import unittest
from unittest.mock import patch

from infra.thessley_ad_service.directory import DirectoryUnavailable, PrincipalNotFound
from infra.thessley_ad_service.windows_directory import WindowsActiveDirectory, WindowsDirectoryConfig


USER_SID = "S-1-5-21-1719900462-4250469598-2954734011-1101"
GROUP_SID = "S-1-5-21-1719900462-4250469598-2954734011-1105"


class WindowsDirectoryTest(unittest.TestCase):
    def setUp(self):
        self.directory = object.__new__(WindowsActiveDirectory)
        self.directory.config = WindowsDirectoryConfig("THESSLEYLAB")
        self.directory.timeout_seconds = 12

    @staticmethod
    def _script_from(run):
        command = run.call_args.args[0]
        return base64.b64decode(command[-1]).decode("utf-16le")

    def test_queries_sid_and_returns_ad_group_sids(self):
        payload = {"sid": USER_SID, "username": "martin", "group_sids": [GROUP_SID]}
        completed = subprocess.CompletedProcess([], 0, json.dumps(payload), "")
        with patch("infra.thessley_ad_service.windows_directory.subprocess.run", return_value=completed) as run:
            result = self.directory.resolve_user_sid(USER_SID)
        self.assertEqual(result.username, "martin")
        self.assertEqual(result.group_sids, frozenset({GROUP_SID}))
        script = self._script_from(run)
        # The lookup uses LDAP only, so no RSAT module or domain bind secret is needed.
        self.assertNotIn("Get-ADUser", script)
        self.assertIn("[ADSI]'LDAP://RootDSE'", script)
        self.assertIn("(objectSid=$sidFilter)", script)
        # Nested groups resolve recursively and the primary group is added separately.
        self.assertIn("member:1.2.840.113556.1.4.1941:=$escapedDn", script)
        self.assertIn("primaryGroupID", script)
        self.assertIn(base64.b64encode(USER_SID.encode()).decode(), script)

    def test_disabled_user_is_rejected(self):
        # The account-disable bit is turned into not_found by the LDAP query, and
        # not_found must fail closed instead of authenticating the account.
        completed = subprocess.CompletedProcess([], 0, json.dumps({"not_found": True}), "")
        with patch("infra.thessley_ad_service.windows_directory.subprocess.run", return_value=completed) as run:
            with self.assertRaisesRegex(PrincipalNotFound, "enabled"):
                self.directory.resolve_user_sid(USER_SID)
        self.assertIn("-band 0x2", self._script_from(run))

    def test_invalid_sid_is_rejected_before_powershell(self):
        with patch("infra.thessley_ad_service.windows_directory.subprocess.run") as run:
            with self.assertRaises(PrincipalNotFound):
                self.directory.resolve_user_sid("S-1-5-21-invalid")
            run.assert_not_called()

    def test_sid_mismatch_in_response_fails_closed(self):
        payload = {"sid": GROUP_SID, "username": "martin", "group_sids": []}
        completed = subprocess.CompletedProcess([], 0, json.dumps(payload), "")
        with patch("infra.thessley_ad_service.windows_directory.subprocess.run", return_value=completed):
            with self.assertRaises(DirectoryUnavailable):
                self.directory.resolve_user_sid(USER_SID)

    def test_unexpected_response_shape_fails_closed(self):
        payload = {"sid": USER_SID, "username": "martin"}
        completed = subprocess.CompletedProcess([], 0, json.dumps(payload), "")
        with patch("infra.thessley_ad_service.windows_directory.subprocess.run", return_value=completed):
            with self.assertRaises(DirectoryUnavailable):
                self.directory.resolve_user_sid(USER_SID)

    def test_create_writes_the_password_over_adws_not_ldap(self):
        # LDAP/389 refuses password writes (0x80072035), so creation must use
        # AD Web Services, which is TLS-protected on every domain controller.
        completed = subprocess.CompletedProcess([], 0, json.dumps({"ok": True, "sid": USER_SID}), "")
        with patch("infra.thessley_ad_service.windows_directory.subprocess.run", return_value=completed) as run:
            sid = self.directory.create_user(
                administrator="Administrator", password="Admin-Secret-1!",
                username="newuser", display_name="New User",
                initial_password="Temp-Secret-1!",
            )
        self.assertEqual(sid, USER_SID)
        script = base64.b64decode(run.call_args.args[0][-1]).decode("utf-16le")
        self.assertIn("Set-ADAccountPassword", script)
        self.assertIn("Enable-ADAccount", script)
        self.assertNotIn("Invoke('SetPassword'", script)

    def test_credentials_are_sent_over_stdin_only(self):
        completed = subprocess.CompletedProcess([], 0, json.dumps({"ok": True, "sid": USER_SID}), "")
        with patch("infra.thessley_ad_service.windows_directory.subprocess.run", return_value=completed) as run:
            self.directory.create_user(
                administrator="Administrator", password="Admin-Secret-1!",
                username="newuser", display_name="New User",
                initial_password="Temp-Secret-1!",
            )
        command_line = " ".join(run.call_args.args[0])
        self.assertNotIn("Admin-Secret-1!", command_line)
        self.assertNotIn("Temp-Secret-1!", command_line)
        payload = json.loads(run.call_args.kwargs["input"])
        self.assertEqual(payload["password"], "Admin-Secret-1!")
        self.assertEqual(payload["initial_password"], "Temp-Secret-1!")

    def test_password_policy_rejection_is_explained(self):
        completed = subprocess.CompletedProcess([], 0, json.dumps({
            "ok": False, "error": "password_policy",
            "detail": "The password does not meet the length, complexity, or history requirement of the domain.",
        }), "")
        with patch("infra.thessley_ad_service.windows_directory.subprocess.run", return_value=completed):
            with self.assertRaisesRegex(ValueError, "password policy"):
                self.directory.create_user(
                    administrator="Administrator", password="Admin-Secret-1!",
                    username="newuser", display_name="New User",
                    initial_password="Temp-Secret-1!",
                )

    def test_password_reset_uses_adws_and_guards_privileged_accounts(self):
        completed = subprocess.CompletedProcess([], 0, json.dumps({"ok": True, "sid": USER_SID}), "")
        with patch("infra.thessley_ad_service.windows_directory.subprocess.run", return_value=completed) as run:
            sid = self.directory.set_user_password(
                administrator="Administrator", password="Admin-Secret-1!",
                username="martin", new_password="Fresh-Secret-2!",
            )
        self.assertEqual(sid, USER_SID)
        script = base64.b64decode(run.call_args.args[0][-1]).decode("utf-16le")
        self.assertIn("Set-ADAccountPassword", script)
        self.assertIn("ChangePasswordAtLogon $true", script)
        # Privileged accounts must be refused before any password write.
        self.assertIn("-in @('disable','delete','password')", script)
        self.assertNotIn("Invoke('SetPassword'", script)
        payload = json.loads(run.call_args.kwargs["input"])
        self.assertEqual(payload["operation"], "password")
        self.assertEqual(payload["initial_password"], "Fresh-Secret-2!")
        self.assertNotIn("Fresh-Secret-2!", " ".join(run.call_args.args[0]))

    def test_short_replacement_password_is_rejected_before_powershell(self):
        with patch("infra.thessley_ad_service.windows_directory.subprocess.run") as run:
            with self.assertRaisesRegex(ValueError, "8 and 256"):
                self.directory.set_user_password(
                    administrator="Administrator", password="Admin-Secret-1!",
                    username="martin", new_password="short",
                )
            run.assert_not_called()

    def test_workstation_access_grant_adds_the_configured_group(self):
        completed = subprocess.CompletedProcess([], 0, json.dumps({"ok": True, "sid": USER_SID}), "")
        with patch("infra.thessley_ad_service.windows_directory.subprocess.run", return_value=completed) as run:
            sid = self.directory.set_workstation_access(
                administrator="Administrator", password="Admin-Secret-1!", username="martin",
                allowed_group_sids={GROUP_SID}, allow=True,
            )
        self.assertEqual(sid, USER_SID)
        script = base64.b64decode(run.call_args.args[0][-1]).decode("utf-16le")
        self.assertIn("Add-ADGroupMember", script)
        self.assertIn("Remove-ADGroupMember", script)
        self.assertIn("-Confirm:$false", script)
        payload = json.loads(run.call_args.kwargs["input"])
        self.assertTrue(payload["allow"])
        self.assertEqual(payload["group_sids"], [GROUP_SID])
        self.assertNotIn("Admin-Secret-1!", " ".join(run.call_args.args[0]))

    def test_workstation_access_revoke_removes_every_configured_group(self):
        completed = subprocess.CompletedProcess([], 0, json.dumps({"ok": True, "sid": USER_SID}), "")
        second = "S-1-5-21-1719900462-4250469598-2954734011-1109"
        with patch("infra.thessley_ad_service.windows_directory.subprocess.run", return_value=completed) as run:
            self.directory.set_workstation_access(
                administrator="Administrator", password="Admin-Secret-1!", username="martin",
                allowed_group_sids=[GROUP_SID, second], allow=False,
            )
        payload = json.loads(run.call_args.kwargs["input"])
        self.assertFalse(payload["allow"])
        self.assertEqual(payload["group_sids"], [GROUP_SID, second])

    def test_workstation_access_requires_a_configured_group(self):
        with patch("infra.thessley_ad_service.windows_directory.subprocess.run") as run:
            with self.assertRaisesRegex(ValueError, "No workstation sign-in group"):
                self.directory.set_workstation_access(
                    administrator="Administrator", password="Admin-Secret-1!", username="martin",
                    allowed_group_sids=[], allow=True,
                )
            run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
