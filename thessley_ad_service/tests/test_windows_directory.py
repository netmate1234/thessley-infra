import base64
import json
import subprocess
import unittest
from unittest.mock import patch

from infra.thessley_ad_service.windows_directory import WindowsActiveDirectory, WindowsDirectoryConfig


USER_SID = "S-1-5-21-1719900462-4250469598-2954734011-1101"
GROUP_SID = "S-1-5-21-1719900462-4250469598-2954734011-1105"


class WindowsDirectoryTest(unittest.TestCase):
    def setUp(self):
        self.directory = object.__new__(WindowsActiveDirectory)
        self.directory.config = WindowsDirectoryConfig("THESSLEYLAB")
        self.directory.timeout_seconds = 12

    def test_queries_sid_and_returns_ad_group_sids(self):
        payload = {
            "sid": USER_SID,
            "username": "martin",
            "user_account_control": 512,
            "group_sids": [GROUP_SID],
        }
        completed = subprocess.CompletedProcess([], 0, json.dumps(payload), "")
        with patch("infra.thessley_ad_service.windows_directory.subprocess.run", return_value=completed) as run:
            result = self.directory.resolve_user_sid(USER_SID)
        self.assertEqual(result.username, "martin")
        self.assertEqual(result.group_sids, frozenset({GROUP_SID}))
        command = run.call_args.args[0]
        encoded = command[-1]
        script = base64.b64decode(encoded).decode("utf-16le")
        self.assertIn("Get-ADUser -Identity $sid", script)
        self.assertIn("Get-ADAccountAuthorizationGroup -Identity $sid", script)
        self.assertIn(base64.b64encode(USER_SID.encode()).decode(), script)

    def test_disabled_user_is_rejected(self):
        payload = {"sid": USER_SID, "username": "martin", "user_account_control": 514, "group_sids": []}
        completed = subprocess.CompletedProcess([], 0, json.dumps(payload), "")
        with patch("infra.thessley_ad_service.windows_directory.subprocess.run", return_value=completed):
            with self.assertRaisesRegex(RuntimeError, "disabled"):
                self.directory.resolve_user_sid(USER_SID)

    def test_invalid_sid_is_rejected_before_powershell(self):
        with patch("infra.thessley_ad_service.windows_directory.subprocess.run") as run:
            with self.assertRaises(RuntimeError):
                self.directory.resolve_user_sid("S-1-5-21-invalid")
            run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
