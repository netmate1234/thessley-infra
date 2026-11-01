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


if __name__ == "__main__":
    unittest.main()
