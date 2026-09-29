"""tools/make_fixtures.py: the pure parts of the harvest -> fixture step.

The tool itself reads a harvest directory and a mapping file that live
outside the repository; the battery locks in the rules a fixture set depends
on — how a variant capture is named, which user names a device's own texts
reveal, how retired literals are rewritten, and that the leak scan counts a
real value in every spelling without ever naming one. Stdlib only.
"""

import importlib.util
import pathlib
import re
import unittest

_TOOL = pathlib.Path(__file__).resolve().parents[1] / "tools" / "make_fixtures.py"
_spec = importlib.util.spec_from_file_location("make_fixtures", _TOOL)
make_fixtures = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(make_fixtures)

FIXTURES = pathlib.Path(__file__).resolve().parent / "fixtures"


class TestTable(unittest.TestCase):
    def test_every_harvest_file_maps_to_one_iosxe_fixture(self):
        names = list(make_fixtures.TABLE.values())
        self.assertEqual(len(names), len(set(names)))
        for source, name in make_fixtures.TABLE.items():
            self.assertTrue(source.startswith(("get__data_", "ssh__")), source)
            self.assertTrue(name.startswith("iosxe_"), name)
            self.assertEqual(source.rsplit(".", 1)[1], name.rsplit(".", 1)[1], source)

    def test_every_table_fixture_is_committed(self):
        # the baseline harvest wrote every entry; a renamed entry would orphan a fixture
        for name in make_fixtures.TABLE.values():
            self.assertTrue((FIXTURES / name).exists(), name)


class TestNaming(unittest.TestCase):
    def test_variant_suffix_replaces_lab_or_lands_before_the_extension(self):
        self.assertEqual(
            make_fixtures.fixture_name("iosxe_stp_details_lab.json"), "iosxe_stp_details_lab.json"
        )
        self.assertEqual(
            make_fixtures.fixture_name("iosxe_stp_details_lab.json", "_lab_hairpin"),
            "iosxe_stp_details_lab_hairpin.json",
        )
        self.assertEqual(
            make_fixtures.fixture_name("iosxe_show_logging.txt", "_lab_hairpin"),
            "iosxe_show_logging_lab_hairpin.txt",
        )
        self.assertEqual(make_fixtures.fixture_name("noext", "_x"), "noext_x")


class TestUsersAndLiterals(unittest.TestCase):
    def test_users_come_from_config_and_login_lines_and_markers_are_not_users(self):
        texts = [
            "username labadmin privilege 15 secret 9 <hex:40>\nusername ops secret 5 x\n",
            "! Last configuration change at 18:30:25 UTC Tue Sep 29 2026 by labadmin\n"
            "! NVRAM configuration last updated at 18:30:37 UTC Tue Sep 29 2026 by auditor\n",
            "%SEC_LOGIN-5-LOGIN_SUCCESS: Login Success [user: ***scrubbed***] [Source: x]\n"
            "%SEC_LOGIN-5-LOGIN_SUCCESS: Login Success [user: rw-user] [Source: x]\n",
        ]
        self.assertEqual(
            make_fixtures.discover_users(texts), ["auditor", "labadmin", "ops", "rw-user"]
        )
        self.assertEqual(make_fixtures.discover_users([]), [])

    def test_literals_rewrite_longest_first(self):
        literals = {"17.0.1": "17.9.9", "17.0.1.0.99": "17.9.9.0.11"}
        self.assertEqual(
            make_fixtures.apply_literals("image 17.0.1.0.99 (17.0.1)", literals),
            "image 17.9.9.0.11 (17.9.9)",
        )
        self.assertEqual(make_fixtures.apply_literals("unchanged", {}), "unchanged")


class TestLeakScan(unittest.TestCase):
    MAPPING = {
        "hosts": {"sw-real-01": "sw-lab-1"},
        "serials": {"ABC1234D5EF": "ABC9999ZZZZ"},
        "ips": {"10.0.0.148": "192.0.2.148"},
        "ipv6": {"fe80::211:22ff:fe33:4455": "fe80::1"},
        "macs": {"001122334455": "aabbccddeeff"},
        "literals": {"17.0.1.0.99": "17.9.9.0.11"},
        "users": {"labadmin": "netops"},
    }

    def test_real_values_cover_every_mac_spelling(self):
        values = make_fixtures.real_values(self.MAPPING)
        for spelling in (
            "001122334455",
            "0011.2233.4455",
            "00:11:22:33:44:55",
            "00-11-22-33-44-55",
        ):
            self.assertIn(spelling, values)
        self.assertIn("sw-real-01", values)
        self.assertIn("17.0.1.0.99", values)
        self.assertNotIn("netops", values)  # inventions are never scanned for

    def test_hits_are_counted_case_insensitively_and_tokens_whole(self):
        values = make_fixtures.real_values(self.MAPPING)
        tokens = [re.compile(make_fixtures.sanitize_trace._TOKEN_EDGE % "labadmin")]
        clean = "hostname sw-lab-1\nmac aabb.ccdd.eeff\nadmin-status up\n"
        self.assertEqual(make_fixtures.leak_hits(clean, values, tokens), 0)
        leaky = "hostname SW-REAL-01\nmac 0011.2233.4455 by labadmin\n"
        self.assertEqual(make_fixtures.leak_hits(leaky, values, tokens), 3)
        self.assertEqual(make_fixtures.leak_hits("sublabadmin labadmin-x", values, tokens), 0)


if __name__ == "__main__":
    unittest.main()
