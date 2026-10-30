import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from infra.thessley_ad_service.state_permissions import UnsafeState, _windows_acls


class WindowsAclTest(unittest.TestCase):
    def test_accepts_only_system_and_admin_full_control(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "state.sqlite3"
            sddl = "D:(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
            result = subprocess.CompletedProcess(
                [], 0, json.dumps([{"path": str(path), "sddl": sddl, "owner": "O:SY"}]), ""
            )
            with patch("infra.thessley_ad_service.state_permissions.subprocess.run", return_value=result):
                _windows_acls([path])

    def test_rejects_an_additional_user_ace(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "state.sqlite3"
            sddl = "D:(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;AU)"
            result = subprocess.CompletedProcess(
                [], 0, json.dumps([{"path": str(path), "sddl": sddl, "owner": "O:SY"}]), ""
            )
            with patch("infra.thessley_ad_service.state_permissions.subprocess.run", return_value=result):
                with self.assertRaises(UnsafeState):
                    _windows_acls([path])


if __name__ == "__main__":
    unittest.main()
