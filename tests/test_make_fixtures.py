"""tools/make_fixtures.py: the pure parts of the harvest -> fixture step.

The tool itself reads a harvest directory and a mapping file that live
outside the repository; the battery locks in the rules a fixture set depends
on — how a variant capture is named, which user names a device's own texts
(and a BMC's log messages) reveal, how retired literals are rewritten, that
the leak scan counts a real value in every spelling without ever naming one,
and — over an invented BMC harvest in a temporary directory — that every
payload is learned from before the first one is sanitized. Stdlib only.
"""

import contextlib
import importlib.util
import io
import json
import pathlib
import re
import tempfile
import unittest

_TOOL = pathlib.Path(__file__).resolve().parents[1] / "tools" / "make_fixtures.py"
_spec = importlib.util.spec_from_file_location("make_fixtures", _TOOL)
make_fixtures = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(make_fixtures)

FIXTURES = pathlib.Path(__file__).resolve().parent / "fixtures"


class TestTable(unittest.TestCase):
    def test_every_harvest_file_maps_to_one_fixture_of_its_family(self):
        names = list(make_fixtures.TABLE.values())
        self.assertEqual(len(names), len(set(names)))
        for source, name in make_fixtures.TABLE.items():
            if source.startswith("get__redfish_v1"):
                # a BMC harvest: Redfish JSON only, lab fixtures in the xcc_ family
                self.assertTrue(name.startswith("xcc_") and name.endswith("_lab.json"), name)
                self.assertTrue(source.endswith(".json"), source)
                continue
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


class TestBmcUsers(unittest.TestCase):
    MESSAGES = [
        "Remote Login Successful. Login ID: opsmary using default authentication from WEB.",
        "The UEFI setting has been changed to the latest by user system.",
        "User LXPM has mounted file diag_boot.img from Local.",
        "Flash of SN#   Z1AB2345 from (192.0.2.7) succeeded for user opstom .",
        "Userid is opsbob.",
        "Login ID: ***scrubbed*** from WEB at IP address 192.0.2.7 has logged off.",
    ]

    def test_lenovo_log_messages_name_users_and_the_bmc_actors_do_not(self):
        self.assertEqual(
            make_fixtures.discover_users(self.MESSAGES), ["opsbob", "opsmary", "opstom"]
        )

    def test_log_users_come_from_message_leaves_only(self):
        payloads = [
            {
                "Members": [
                    {"Message": message, "MessageArgs": ["opsnobody"]} for message in self.MESSAGES
                ]
            },
            {"Description": "User VLAN for the lab", "Name": "User Account"},
        ]
        self.assertEqual(
            make_fixtures.discover_log_users(payloads), ["opsbob", "opsmary", "opstom"]
        )
        self.assertEqual(make_fixtures.discover_log_users([]), [])

    def test_harvest_json_lists_log_pages_first_and_every_file_once(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        base = pathlib.Path(folder.name)
        names = (
            "get__redfish_v1_AccountService_Accounts.json",
            "get__redfish_v1_Systems_1_LogServices_StandardLog_Entries.json",
            "results.json",
            "ssh__show_version.txt",
        )
        for name in names:
            (base / name).write_text("{}")
        self.assertEqual(
            [path.name for path in make_fixtures.harvest_json(base)],
            [names[1], names[0], names[2]],
        )


class TestBmcLeakScan(unittest.TestCase):
    MAPPING = {
        "hosts": {"xcc": "bmc-lab-1", "bmc-rack7-a.plant.acme-corp.net": "bmc-lab-1.lab.example"},
        "serials": {"Z1AB2345": "Q4KM7702", "240801A00017": "913377K40219"},
        "uuids": {"4a1b2c3d-1111-4222-8333-0023456789ab": "9f8e7d6c-5b4a-4392-a1b0-c9d8e7f6a5b4"},
        "assets": {"IT-004711": "QX-730155"},
        "users": {"opsjane": "user-lab-1", "Administrator": "user-lab-2"},
    }

    def test_real_values_cover_the_bmc_categories_and_word_hosts_are_tokens(self):
        values = make_fixtures.real_values(self.MAPPING)
        for real in ("Z1AB2345", "240801A00017", "IT-004711", "bmc-rack7-a.plant.acme-corp.net"):
            self.assertIn(real, values)
        self.assertIn("4a1b2c3d-1111-4222-8333-0023456789ab", values)
        self.assertNotIn("xcc", values)  # a vendor default is a word, not a substring
        tokens = make_fixtures.real_tokens(self.MAPPING, {"capture_ro"})
        leaky = "UUID 4A1B2C3D-1111-4222-8333-0023456789AB by opsjane on xcc"
        self.assertEqual(make_fixtures.leak_hits(leaky, values, tokens), 3)
        clean = "XCC Web, lnvgy_fw_xcc_x.uxz, RoleId Administrator, by user-lab-1"
        self.assertEqual(make_fixtures.leak_hits(clean, values, tokens), 0)
        self.assertEqual(make_fixtures.leak_hits("by capture_ro", values, tokens), 1)


class TestBmcHarvestEndToEnd(unittest.TestCase):
    """make_fixtures over an invented BMC harvest in a temporary directory."""

    SYSTEM = {
        "@odata.id": "/redfish/v1/Systems/1",
        "SerialNumber": "Z1AB2345",
        "UUID": "4A1B2C3D-1111-4222-8333-0023456789AB",
        "HostName": "bmc-rack7-a",
    }
    ACCOUNTS = {
        "Members": [
            {"UserName": "opsjane", "Password": None, "RoleId": "Administrator"},
            {"UserName": "capture_ro", "Password": None, "RoleId": "ReadOnly"},
        ]
    }
    ENTRIES = {
        "Members": [
            {
                "Message": "ENET[CIM:ep1] IP-Cfg:HstName=XCC-7X99-Z1AB2345, IP@=10.20.30.40 .",
                "MessageArgs": ["CIM:ep1", "XCC-7X99-Z1AB2345", "10.20.30.40"],
            },
            {"Message": "Login ID: opsmary from WEB at IP address 10.20.30.41 has logged off."},
            {"Message": "Login ID: capture_ro from WEB at IP address 10.20.30.41 has logged off."},
        ]
    }
    REAL = ("Z1AB2345", "4A1B2C3D", "bmc-rack7-a", "opsjane", "opsmary", "capture_ro", "10.20.30.4")

    def test_every_payload_is_learned_before_the_first_is_sanitized(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        base = pathlib.Path(folder.name)
        harvest, out = base / "harvest", base / "fixtures"
        harvest.mkdir()
        out.mkdir()
        files = {
            # sorts before the system resource that names the serial as a leaf
            "get__redfish_v1_Managers_1_LogServices_Log_Entries.json": self.ENTRIES,
            "get__redfish_v1_AccountService_Accounts__fabc123.json": self.ACCOUNTS,
            "get__redfish_v1_Systems_1.json": self.SYSTEM,
        }
        for name, payload in files.items():
            (harvest / name).write_text(json.dumps(payload, indent=1))
        env = base / "bmc.env"
        env.write_text("username=capture_ro\npassword=pw-Secret-1\nhost=10.20.30.40\n")
        original = make_fixtures.TABLE
        self.addCleanup(setattr, make_fixtures, "TABLE", original)
        make_fixtures.TABLE = {name: "xcc_%d_lab.json" % i for i, name in enumerate(sorted(files))}
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            code = make_fixtures.main(
                ["--payloads", str(harvest), "--map", str(base / "map.json"), "--out", str(out)]
                + ["--env", str(env)]
            )
        self.assertEqual(code, 0, stdout.getvalue())
        self.assertIn("0 file(s) with leaks", stdout.getvalue())
        self.assertNotIn("pw-Secret-1", stdout.getvalue())
        written = {path.name: path.read_text() for path in out.iterdir()}
        self.assertEqual(len(written), 3)
        for text in written.values():
            for real in self.REAL:
                self.assertNotIn(real, text)
        system = json.loads(written["xcc_2_lab.json"])
        entries = json.loads(written["xcc_1_lab.json"])
        accounts = json.loads(written["xcc_0_lab.json"])
        serial = system["SerialNumber"]
        self.assertRegex(serial, r"^[A-Z]\d[A-Z]{2}\d{4}$")
        self.assertIn("HstName=XCC-7X99-%s," % serial, entries["Members"][0]["Message"])
        self.assertEqual(entries["Members"][0]["MessageArgs"][1], "XCC-7X99-" + serial)
        self.assertEqual(system["HostName"], "bmc-lab-1")
        self.assertEqual(
            [member["UserName"] for member in accounts["Members"]], ["user-lab-2", "netops"]
        )
        self.assertIn("Login ID: user-lab-1 ", entries["Members"][1]["Message"])
        self.assertIn("Login ID: netops ", entries["Members"][2]["Message"])
        mapping = (base / "map.json").read_text()
        for credential in ("capture_ro", "pw-Secret-1"):
            self.assertNotIn(credential, mapping)


if __name__ == "__main__":
    unittest.main()
