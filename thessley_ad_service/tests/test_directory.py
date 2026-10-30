import sys
import types
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from infra.thessley_ad_service.directory import ActiveDirectory, DirectoryConfig, sid_to_bytes


class FakeConnection:
    def __init__(self, user_entry, group_entry):
        self.user_entry = user_entry
        self.group_entry = group_entry
        self.entries = []
        self.searches = []

    def search(self, **kwargs):
        self.searches.append(kwargs)
        if kwargs["search_scope"] == "SUBTREE":
            self.entries = [self.user_entry]
        elif kwargs["search_scope"] == "BASE":
            self.entries = [self.group_entry]
        else:
            raise AssertionError("Unexpected LDAP scope")
        return True

    def unbind(self):
        pass


class DirectoryLookupTest(unittest.TestCase):
    def test_resolves_identity_then_reads_token_groups_with_base_scope(self):
        user_sid = "S-1-5-21-1719900462-4250469598-2954734011-1101"
        group_sid = "S-1-5-21-1719900462-4250469598-2954734011-1105"
        user = SimpleNamespace(
            entry_dn="CN=martin,CN=Users,DC=lab,DC=thessley,DC=test",
            entry_raw_attributes={
                "objectClass": [b"top", b"person", b"user"],
                "objectSid": [sid_to_bytes(user_sid)],
                "sAMAccountName": [b"martin"],
                "userAccountControl": [b"512"],
            },
        )
        groups = SimpleNamespace(entry_raw_attributes={"tokenGroups": [sid_to_bytes(group_sid)]})
        connection = FakeConnection(user, groups)
        ldap3 = types.ModuleType("ldap3")
        ldap3.BASE = "BASE"
        ldap3.SUBTREE = "SUBTREE"
        config = DirectoryConfig(
            host="dc.lab.thessley.test",
            base_dn="DC=lab,DC=thessley,DC=test",
            bind_dn="CN=reader,DC=lab,DC=thessley,DC=test",
            password_file="/unused/password",
            ca_file="/unused/ca.pem",
            authority="THESSLEYLAB",
        )
        directory = object.__new__(ActiveDirectory)
        directory.config = config
        with patch.dict(sys.modules, {"ldap3": ldap3}), patch.object(directory, "_connect", return_value=connection):
            result = directory.resolve_user_sid(user_sid)

        self.assertEqual(result.sid, user_sid)
        self.assertEqual(result.username, "martin")
        self.assertEqual(result.group_sids, frozenset({group_sid}))
        self.assertEqual([query["search_scope"] for query in connection.searches], ["SUBTREE", "BASE"])
        self.assertNotIn("tokenGroups", connection.searches[0]["attributes"])
        self.assertEqual(connection.searches[1]["attributes"], ["tokenGroups"])


if __name__ == "__main__":
    unittest.main()
