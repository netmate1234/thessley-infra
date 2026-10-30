import hashlib
import unittest
from unittest.mock import patch

from thessley_pam_win import ad_agent


SID = "S-1-5-21-1719900462-4250469598-2954734011-1101"


class AuthorizationCheckTest(unittest.TestCase):
    def test_returns_ad_identity_and_boolean_without_group_list(self):
        response = {
            "result": "resolved",
            "principal": {
                "sid": SID,
                "principal_id": hashlib.sha256(SID.encode("ascii")).hexdigest(),
                "principal_type": "domain",
                "authority": "THESSLEYLAB",
                "username": "martin",
            },
            "authorized": True,
        }
        with patch.object(ad_agent, "_signed_post", return_value=response) as request:
            result = ad_agent.check_domain_authorization(SID)
        self.assertEqual(result, {
            "sid": SID, "authority": "THESSLEYLAB", "username": "martin", "authorized": True,
        })
        request.assert_called_once_with("/thessley-ad/v1/principals/resolve", {"sid": SID})

    def test_rejects_a_response_for_a_different_sid(self):
        response = {
            "result": "resolved",
            "principal": {
                "sid": SID,
                "principal_id": "0" * 64,
                "principal_type": "domain",
                "authority": "THESSLEYLAB",
                "username": "martin",
            },
            "authorized": True,
        }
        with patch.object(ad_agent, "_signed_post", return_value=response):
            with self.assertRaises(ad_agent.AgentError):
                ad_agent.check_domain_authorization(SID)


if __name__ == "__main__":
    unittest.main()
