"""checks_iosxe_layer2: VLANs, trunks, spanning tree and the MAC table.

Driven with synthetic fixtures shaped after the published 17.12.1 vlan-oper,
spanning-tree-oper and matm-oper models plus real IOS-XE CLI layouts
(tests/fixtures/iosxe_vlan_oper.json, iosxe_stp_details.json,
iosxe_matm_table.json, iosxe_show_interfaces_trunk.txt,
iosxe_show_vtp_status.txt); MACs and addresses are documentation-range values.
No Nautobot, no network.
"""

import copy
import unittest

if __package__:
    from . import _loader
else:  # unittest discover -s tests imports test modules as top-level
    import _loader

l2 = _loader.load("checks_iosxe_layer2")
registry = _loader.registry
diffcore = _loader.diffcore
J = _loader.fixture_json
T = _loader.fixture_text

EXPECTED_IDS = {"iosxe_vlans", "iosxe_trunks", "iosxe_stp", "iosxe_mac_table"}


class _Http(Exception):
    """Stand-in for RestconfError: carries the HTTP status the fetch helper inspects."""

    def __init__(self, status):
        super().__init__("HTTP %s" % (status,))
        self.status_code = status


class _Ctx:
    """Duck-typed CollectorContext.

    GET paths route to payloads by the LONGEST token found in the resource
    path (the part before any ?fields=). A payload may be an exception
    (raised) or a callable (called with the full path). Unknown paths answer
    None under ok_404 (the 404 case). ``ssh`` maps commands to outputs; an
    exception value is raised; ``ssh=None`` means no SSH transport.
    """

    def __init__(self, payloads=None, ssh=None):
        self.payloads = payloads or {}
        self.ssh_outputs = ssh
        self.calls = []
        self.ssh_calls = []
        self.platform = "iosxe"
        self.device_name = "sw-test"

    def get(self, path, **kwargs):
        self.calls.append(path)
        resource = path.split("?", 1)[0]
        tokens = sorted((t for t in self.payloads if t in resource), key=len, reverse=True)
        if not tokens:
            if kwargs.get("ok_404"):
                return None
            raise AssertionError("unexpected GET %s" % (path,))
        payload = self.payloads[tokens[0]]
        if isinstance(payload, Exception):
            raise payload
        if callable(payload):
            return payload(path)
        return payload

    @property
    def has_ssh(self):
        return self.ssh_outputs is not None

    def run_ssh(self, command, **kwargs):
        self.ssh_calls.append(command)
        output = self.ssh_outputs.get(command, "")
        if isinstance(output, Exception):
            raise output
        return output


def _reject_fields(fixture_name):
    """A payload callable: HTTP 400 for the filtered path, the fixture unfiltered."""

    def answer(path):
        if "?fields=" in path:
            raise _Http(400)
        return J(fixture_name)

    return answer


REJECTED = "% Invalid input detected at '^' marker."


class TestHelpers(unittest.TestCase):
    def test_node_and_entries_accept_list_and_container_forms(self):
        list_form = {"mod:matm-table": [{"a": 1}]}
        container_form = {"mod:matm-oper-data": {"matm-table": [{"a": 1}]}}
        single = {"mod:matm-table": {"a": 1}}
        for payload in (list_form, container_form, single):
            self.assertEqual(l2._entries(payload, "matm-table"), [{"a": 1}])
        self.assertEqual(l2._entries({}, "matm-table"), [])
        self.assertEqual(l2._entries(None, "matm-table"), [])

    def test_vlan_range_canonicalisation(self):
        self.assertEqual(l2._vlan_ranges("1,10,20-30"), "1,10,20-30")
        self.assertEqual(l2._vlan_ranges("30-20,10,1"), "1,10,20-30")
        self.assertEqual(l2._vlan_ranges("20,21,22,23,10,1"), "1,10,20-23")
        self.assertEqual(l2._vlan_ranges("1, 2,3 ,5"), "1-3,5")
        self.assertEqual(l2._vlan_ranges("none"), "")
        self.assertEqual(l2._vlan_ranges(""), "")
        self.assertEqual(l2._vlan_ranges(None), "")
        self.assertEqual(l2._vlan_ranges("all"), "1-4094")
        self.assertEqual(l2._vlan_ranges("1-4094"), "1-4094")
        self.assertEqual(l2._vlan_ranges("junk,7,x-y"), "7")
        # The same set always renders the same string, whatever the spelling.
        self.assertEqual(l2._vlan_ranges("100-105,200"), l2._vlan_ranges("200,100,101-105"))

    def test_wrapped_line_joins_on_either_side_of_the_comma(self):
        self.assertEqual(l2._join_wrapped("1,2,", "3,4"), "1,2,3,4")
        self.assertEqual(l2._join_wrapped("1,2", ",3,4"), "1,2,3,4")
        self.assertEqual(l2._join_wrapped("1,2", "3,4"), "1,2,3,4")
        self.assertEqual(l2._join_wrapped("1,20-", "30"), "1,20-30")

    def test_member_from_port_name(self):
        self.assertEqual(l2._member_of("GigabitEthernet1/0/1"), 1)
        self.assertEqual(l2._member_of("TwoGigabitEthernet2/0/48"), 2)
        self.assertEqual(l2._member_of("Te3/1/4"), 3)
        self.assertIsNone(l2._member_of("Port-channel1"))
        self.assertIsNone(l2._member_of("Vlan10"))
        self.assertIsNone(l2._member_of("CPU"))
        self.assertIsNone(l2._member_of(None))

    def test_cli_rejection_and_enum_helpers(self):
        self.assertTrue(l2._cli_rejected(REJECTED))
        self.assertTrue(l2._cli_rejected("Command authorization failed."))
        self.assertFalse(l2._cli_rejected("Port        Mode"))
        self.assertFalse(l2._cli_rejected(None))
        self.assertEqual(l2._short("stp-mode-rapid-pvst", "stp-mode-"), "rapid-pvst")
        self.assertEqual(l2._short("weird", "stp-"), "weird")
        self.assertIsNone(l2._short(None, "stp-"))


class TestFetchFallback(unittest.TestCase):
    def test_fields_rejection_falls_back_once_and_is_noted(self):
        ctx = _Ctx({"stp-details": _reject_fields("iosxe_stp_details.json")})
        notes = []
        payload, path = l2._get_filtered(ctx, l2._STP_PATH, l2._STP_FIELDS, notes, "stp-details")
        self.assertEqual(path, l2._STP_PATH)
        self.assertIn("stp-details", str(payload))
        self.assertEqual(len(ctx.calls), 2)
        self.assertIn("?fields=", ctx.calls[0])
        self.assertNotIn("?fields=", ctx.calls[1])
        self.assertEqual(
            notes, ["stp-details: fields filter rejected (HTTP 400); unfiltered read used"]
        )

    def test_other_http_errors_propagate(self):
        ctx = _Ctx({"stp-details": _Http(500)})
        with self.assertRaises(_Http):
            l2._get_filtered(ctx, l2._STP_PATH, l2._STP_FIELDS, [], "stp-details")

    def test_absent_model_is_none_with_the_filtered_path(self):
        payload, path = l2._get_filtered(_Ctx(), l2._STP_PATH, l2._STP_FIELDS, [], "stp-details")
        self.assertIsNone(payload)
        self.assertIn("?fields=", path)


class TestVlans(unittest.TestCase):
    def setUp(self):
        self.payload = J("iosxe_vlan_oper.json")
        self.normalized, self.context = l2._normalize_vlans(self.payload)

    def test_keys_name_and_status(self):
        self.assertEqual(self.normalized["vlan|10"], {"name": "USERS", "status": "active"})
        self.assertEqual(self.normalized["vlan|99"], {"name": "OLD-MGMT", "status": "suspend"})
        self.assertEqual(len(self.normalized), 9)
        self.assertNotIn("vtp", self.normalized)
        for value in self.normalized.values():
            self.assertEqual(set(value), {"name", "status"})

    def test_per_port_maps_are_context_and_inverted_from_both_lists(self):
        ports = self.context["ports"]
        self.assertEqual(ports["GigabitEthernet1/0/1"], [10, 20])  # access + voice
        self.assertEqual(ports["GigabitEthernet1/0/3"], [30])  # bare-dict single entry
        self.assertNotIn("GigabitEthernet1/1/1", ports)
        self.assertEqual(self.context["vlan_interfaces"]["GigabitEthernet1/1/1"], [10])
        self.assertEqual(self.context["ports_listed"], 7)
        self.assertEqual(self.context["vlan_interfaces_listed"], 7)
        self.assertFalse(self.context["lists_agree"])
        self.assertEqual(self.context["vlan_total"], 9)
        self.assertEqual(self.context["active"], 8)
        self.assertEqual(self.context["suspended"], 1)
        self.assertFalse(any(key.startswith("port|") for key in self.normalized))

    def test_agreeing_lists_are_reported(self):
        payload = {
            "Cisco-IOS-XE-vlan-oper:vlans": {
                "vlan": [
                    {
                        "id": 5,
                        "name": "X",
                        "status": "active",
                        "ports": [{"interface": "Gi1/0/1"}],
                        "vlan-interfaces": [{"interface": "Gi1/0/1"}],
                    }
                ]
            }
        }
        _, context = l2._normalize_vlans(payload)
        self.assertTrue(context["lists_agree"])

    def test_vtp_status_v2_layout(self):
        self.assertEqual(
            l2._parse_vtp_status(T("iosxe_show_vtp_status.txt")),
            {
                "mode": "server",
                "domain": "CAMPUS",
                "version": 2,
                "pruning": False,
                "revision": 42,
                "existing_vlans": 9,
            },
        )

    def test_vtp_status_v1_layout_and_v3_feature_blocks(self):
        old = (
            "VTP Version                     : running VTP2\n"
            "Configuration Revision          : 0\n"
            "Maximum VLANs supported locally : 1005\n"
            "Number of existing VLANs        : 5\n"
            "VTP Operating Mode              : Transparent\n"
            "VTP Domain Name                 : \n"
            "VTP Pruning Mode                : Enabled\n"
        )
        self.assertEqual(
            l2._parse_vtp_status(old),
            {
                "mode": "transparent",
                "domain": "",
                "version": 2,
                "pruning": True,
                "revision": 0,
                "existing_vlans": 5,
            },
        )
        v3 = (
            "VTP version running             : 3\n"
            "VTP Domain Name                 : CAMPUS\n"
            "VTP Pruning Mode                : Disabled\n\n"
            "Feature VLAN:\n--------------\n"
            "VTP Operating Mode                : Primary Server\n"
            "Number of existing VLANs          : 12\n"
            "Configuration Revision            : 7\n\n"
            "Feature MST:\n--------------\n"
            "VTP Operating Mode                : Transparent\n"
            "Configuration Revision            : 0\n"
        )
        parsed = l2._parse_vtp_status(v3)
        self.assertEqual(parsed["mode"], "primary server")
        self.assertEqual(parsed["revision"], 7)
        self.assertEqual(parsed["version"], 3)
        self.assertEqual(l2._parse_vtp_status(""), {})

    def test_collector_with_ssh_enrichment(self):
        ctx = _Ctx({"vlans": self.payload}, ssh={"show vtp status": T("iosxe_show_vtp_status.txt")})
        outcome = l2._collect_vlans(ctx)
        self.assertEqual(
            outcome["normalized"]["vtp"],
            {"mode": "server", "domain": "CAMPUS", "version": 2, "pruning": False, "revision": 42},
        )
        self.assertEqual(outcome["context"]["vtp_existing_vlans"], 9)
        self.assertEqual(outcome["normalized"]["vlan|10"], {"name": "USERS", "status": "active"})
        self.assertIs(outcome["raw"][l2._VLAN_PATH], self.payload)
        # The digest is password-derived material: redacted from raw, the
        # updater address and the parser's lines kept.
        stored = outcome["raw"]["show vtp status"]
        self.assertIn("MD5 digest                        : <redacted>", stored)
        self.assertNotIn("0x8A", stored)
        self.assertNotIn("0x11 0xD4", stored)
        self.assertIn("192.0.2.10", stored)
        self.assertIsNone(outcome["raw"]["note"])
        self.assertEqual(ctx.ssh_calls, ["show vtp status"])
        self.assertTrue(all(c.startswith("show ") for c in ctx.ssh_calls))

    def test_vtp_redaction_keeps_what_the_parser_reads(self):
        text = T("iosxe_show_vtp_status.txt")
        redacted = l2._redact_vtp_status(text)
        self.assertNotIn("0x", redacted)
        self.assertIn("<redacted>", redacted)
        self.assertEqual(l2._parse_vtp_status(redacted), l2._parse_vtp_status(text))
        # A digest that fits one line, and a layout without one, both survive.
        one_line = "MD5 digest : 0xAA 0xBB\nVTP Pruning Mode : Enabled\n"
        self.assertEqual(
            l2._redact_vtp_status(one_line), "MD5 digest : <redacted>\nVTP Pruning Mode : Enabled\n"
        )
        self.assertEqual(
            l2._redact_vtp_status("VTP Operating Mode : Server\n"), "VTP Operating Mode : Server\n"
        )
        self.assertEqual(l2._redact_vtp_status(None), "")

    def test_vtp_read_passes_the_redactor_to_the_transport(self):
        seen = {}

        class _RedactCtx(_Ctx):
            def run_ssh(self, command, **kwargs):
                seen.update(kwargs)
                return super().run_ssh(command, **kwargs)

        ctx = _RedactCtx(
            {"vlans": self.payload}, ssh={"show vtp status": T("iosxe_show_vtp_status.txt")}
        )
        l2._collect_vlans(ctx)
        self.assertIs(seen.get("redact"), l2._redact_vtp_status)

    def test_celery_abort_during_the_vtp_read_is_never_a_note(self):
        class SoftTimeLimitExceeded(Exception):
            pass

        ctx = _Ctx({"vlans": self.payload}, ssh={"show vtp status": SoftTimeLimitExceeded()})
        with self.assertRaises(SoftTimeLimitExceeded):
            l2._collect_vlans(ctx)

    def test_collector_without_ssh_or_with_ssh_trouble_still_succeeds(self):
        outcome = l2._collect_vlans(_Ctx({"vlans": self.payload}))
        self.assertNotIn("vtp", outcome["normalized"])
        self.assertIn("no SSH transport", outcome["raw"]["note"])

        rejected = l2._collect_vlans(
            _Ctx({"vlans": self.payload}, ssh={"show vtp status": REJECTED})
        )
        self.assertNotIn("vtp", rejected["normalized"])
        self.assertIn("rejected", rejected["raw"]["note"])
        self.assertEqual(rejected["raw"]["show vtp status"], REJECTED)

        failed = l2._collect_vlans(
            _Ctx({"vlans": self.payload}, ssh={"show vtp status": RuntimeError("timed out")})
        )
        self.assertNotIn("vtp", failed["normalized"])
        self.assertIn("timed out", failed["raw"]["note"])

        empty = l2._collect_vlans(_Ctx({"vlans": self.payload}, ssh={"show vtp status": ""}))
        self.assertNotIn("vtp", empty["normalized"])
        self.assertIn("no VTP fields", empty["raw"]["note"])

    def test_absent_model_and_empty_database_are_not_present(self):
        with self.assertRaises(registry.SkipCheck) as absent:
            l2._collect_vlans(_Ctx())
        self.assertIn("model absent", str(absent.exception))
        with self.assertRaises(registry.SkipCheck) as empty:
            l2._collect_vlans(_Ctx({"vlans": {"Cisco-IOS-XE-vlan-oper:vlans": {}}}))
        # Every switch holds VLAN 1: an empty answer is the model, not the database.
        self.assertIn("served no VLAN entries", str(empty.exception))
        self.assertIn("Not-present", l2.SEMANTICS["iosxe_vlans"])


class TestTrunks(unittest.TestCase):
    def setUp(self):
        self.text = T("iosxe_show_interfaces_trunk.txt")
        self.rows = l2._parse_interfaces_trunk(self.text)

    def test_rows_and_canonical_sets(self):
        self.assertEqual(set(self.rows), {"Gi1/0/47", "Gi1/1/1", "Gi2/1/1", "Po1"})
        self.assertEqual(
            self.rows["Gi1/1/1"],
            {
                "mode": "on",
                "encapsulation": "802.1q",
                "status": "trunking",
                "native_vlan": 1,
                "allowed": "1-4094",
                "active": "1,10,20,30,99",
                "forwarding": "1,10,20,30,99",
            },
        )
        self.assertEqual(self.rows["Gi2/1/1"]["encapsulation"], "n-802.1q")
        self.assertEqual(self.rows["Gi2/1/1"]["mode"], "desirable")
        self.assertEqual(self.rows["Gi2/1/1"]["forwarding"], "")  # 'none'
        self.assertEqual(self.rows["Gi1/0/47"]["status"], "trunk-inbndl (Po1)")
        self.assertEqual(self.rows["Gi1/0/47"]["native_vlan"], 999)
        self.assertNotIn("allowed", self.rows["Gi1/0/47"])

    def test_wrapped_continuation_lines_are_joined_before_canonicalising(self):
        # 'allowed' wraps after a comma, 'active' wraps before one: same canonical result.
        self.assertEqual(self.rows["Po1"]["allowed"], "1,10,20-30,40,100-105,200-245")
        self.assertEqual(self.rows["Po1"]["active"], "1,10,20,30,40,100-105,200-245")
        self.assertEqual(self.rows["Po1"]["forwarding"], "1,10,20,30,40,100-105,200-245")

    def test_status_continuation_line_joins_the_bundle_note(self):
        text = (
            "Port        Mode             Encapsulation  Status        Native vlan\n"
            "Gi1/0/48    on               802.1q         trunk-inbndl  1\n"
            "                                            (Po2)\n"
            "\n"
            "Port        Vlans allowed on trunk\n"
            "Po2         10-12\n"
        )
        rows = l2._parse_interfaces_trunk(text)
        self.assertEqual(rows["Gi1/0/48"]["status"], "trunk-inbndl (Po2)")
        self.assertEqual(rows["Po2"], {"allowed": "10-12"})

    def test_context_names_active_vlans_that_are_not_forwarding(self):
        context = l2._trunk_context(self.rows)
        self.assertEqual(context["trunk_total"], 4)
        self.assertEqual(context["trunking"], 3)
        self.assertEqual(context["forwarding_vlans"], {"Gi1/1/1": 5, "Gi2/1/1": 0, "Po1": 57})
        self.assertEqual(context["active_not_forwarding"], {"Gi2/1/1": "1,10,20,30,99"})

    def test_empty_and_header_only_output_parse_to_nothing(self):
        self.assertEqual(l2._parse_interfaces_trunk(""), {})
        self.assertEqual(l2._parse_interfaces_trunk(None), {})
        headers = "Port        Mode             Encapsulation  Status        Native vlan\n\n"
        self.assertEqual(l2._parse_interfaces_trunk(headers), {})

    def test_collector_end_to_end(self):
        # VTP pruning disabled (the fixture): forwarding stays a keyed field.
        vtp = T("iosxe_show_vtp_status.txt")
        ctx = _Ctx(ssh={"show interfaces trunk": self.text, "show vtp status": vtp})
        outcome = l2._collect_trunks(ctx)
        self.assertEqual(
            set(outcome["normalized"]),
            {"trunk|Gi1/0/47", "trunk|Gi1/1/1", "trunk|Gi2/1/1", "trunk|Po1"},
        )
        self.assertEqual(outcome["normalized"]["trunk|Po1"]["native_vlan"], 999)
        self.assertEqual(
            outcome["normalized"]["trunk|Po1"]["forwarding"], "1,10,20,30,40,100-105,200-245"
        )
        self.assertEqual(outcome["raw"]["show interfaces trunk"], self.text)
        self.assertEqual(outcome["raw"]["show vtp status"], l2._redact_vtp_status(vtp))
        self.assertNotIn("note", outcome["raw"])
        self.assertEqual(outcome["context"]["trunk_total"], 4)
        self.assertIs(outcome["context"]["vtp_pruning"], False)
        self.assertEqual(outcome["context"]["forwarding"], {})
        self.assertEqual(ctx.ssh_calls, ["show interfaces trunk", "show vtp status"])
        self.assertTrue(all(c.startswith("show ") for c in ctx.ssh_calls))

    def test_forwarding_moves_to_context_where_vtp_pruning_is_on(self):
        pruned = T("iosxe_show_vtp_status.txt").replace(
            "VTP Pruning Mode                : Disabled",
            "VTP Pruning Mode                : Enabled",
        )
        ctx = _Ctx(ssh={"show interfaces trunk": self.text, "show vtp status": pruned})
        outcome = l2._collect_trunks(ctx)
        self.assertIs(outcome["context"]["vtp_pruning"], True)
        for row in outcome["normalized"].values():
            self.assertNotIn("forwarding", row)
        self.assertEqual(
            outcome["normalized"]["trunk|Po1"],
            {
                "mode": "on",
                "encapsulation": "802.1q",
                "status": "trunking",
                "native_vlan": 999,
                "allowed": "1,10,20-30,40,100-105,200-245",
                "active": "1,10,20,30,40,100-105,200-245",
            },
        )
        self.assertEqual(
            outcome["context"]["forwarding"],
            {"Gi1/1/1": "1,10,20,30,99", "Gi2/1/1": "", "Po1": "1,10,20,30,40,100-105,200-245"},
        )
        self.assertEqual(outcome["context"]["active_not_forwarding"], {"Gi2/1/1": "1,10,20,30,99"})
        # VLAN 40's last downstream endpoint slept and pruning withdrew it from
        # Po1: context moved, the compare passes. With pruning off the same
        # text is a changed key.
        quiet = self.text.replace(
            "Po1         1,10,20,30,40,100-105,200-245", "Po1         1,10,20,30,100-105,200-245"
        )
        compare = registry.CHECKS["iosxe_trunks"].compare
        later = l2._collect_trunks(
            _Ctx(ssh={"show interfaces trunk": quiet, "show vtp status": pruned})
        )
        self.assertEqual(
            diffcore.diff_check(outcome["normalized"], later["normalized"], compare)["result"],
            "pass",
        )
        self.assertEqual(later["context"]["forwarding"]["Po1"], "1,10,20,30,100-105,200-245")
        unpruned = T("iosxe_show_vtp_status.txt")
        before = l2._collect_trunks(
            _Ctx(ssh={"show interfaces trunk": self.text, "show vtp status": unpruned})
        )
        after = l2._collect_trunks(
            _Ctx(ssh={"show interfaces trunk": quiet, "show vtp status": unpruned})
        )
        diff = diffcore.diff_check(before["normalized"], after["normalized"], compare)
        self.assertEqual(diff["result"], "diffs")
        self.assertEqual([c["key"] for c in diff["changed"]], ["trunk|Po1"])

    def test_unknown_pruning_keeps_forwarding_keyed_and_notes_the_cause(self):
        for name, vtp in (
            ("rejected", REJECTED),
            ("failed", RuntimeError("timed out")),
            ("unrecognised", ""),
        ):
            with self.subTest(name):
                ctx = _Ctx(ssh={"show interfaces trunk": self.text, "show vtp status": vtp})
                outcome = l2._collect_trunks(ctx)
                self.assertIsNone(outcome["context"]["vtp_pruning"])
                self.assertEqual(
                    outcome["normalized"]["trunk|Gi1/1/1"]["forwarding"], "1,10,20,30,99"
                )
                self.assertEqual(outcome["context"]["forwarding"], {})
                self.assertTrue(outcome["raw"]["note"])

    def test_celery_abort_during_the_vtp_read_is_raised(self):
        class SoftTimeLimitExceeded(Exception):
            pass

        ctx = _Ctx(
            ssh={"show interfaces trunk": self.text, "show vtp status": SoftTimeLimitExceeded()}
        )
        with self.assertRaises(SoftTimeLimitExceeded):
            l2._collect_trunks(ctx)

    def test_not_present_without_ssh_when_rejected_or_when_no_trunks(self):
        with self.assertRaises(registry.SkipCheck):
            l2._collect_trunks(_Ctx())
        with self.assertRaises(registry.SkipCheck):
            l2._collect_trunks(_Ctx(ssh={"show interfaces trunk": REJECTED}))
        with self.assertRaises(registry.SkipCheck):
            l2._collect_trunks(_Ctx(ssh={"show interfaces trunk": ""}))


class TestStp(unittest.TestCase):
    def setUp(self):
        self.payload = J("iosxe_stp_details.json")
        self.normalized, self.context = l2._normalize_stp(self.payload)

    def test_global_key(self):
        self.assertEqual(
            self.normalized["stp"],
            {
                "mode": "rapid-pvst",
                "bridge_assurance": False,
                "loop_guard": False,
                "bpdu_guard": True,
                "bpdu_filter": False,
                "etherchannel_misconfig_guard": True,
            },
        )

    def test_instance_keys_resolve_root_port_and_root_status(self):
        self.assertEqual(
            self.normalized["instance|VLAN0001"],
            {
                "bridge_priority": 32769,
                "root_address": "00:00:5e:00:53:01",
                "root_priority": 24577,
                "root_cost": 4,
                "root_port": "GigabitEthernet1/1/1",
                "is_root": False,
            },
        )
        root = self.normalized["instance|VLAN0010"]
        self.assertTrue(root["is_root"])
        self.assertNotIn("root_port", root)
        self.assertEqual(root["root_cost"], 0)

    def test_only_non_designated_forwarding_ports_are_keyed(self):
        port_keys = sorted(k for k in self.normalized if k.startswith("port|"))
        self.assertEqual(
            port_keys,
            [
                "port|VLAN0001|GigabitEthernet1/0/3",
                "port|VLAN0001|GigabitEthernet1/1/1",
                "port|VLAN0001|GigabitEthernet2/1/1",
            ],
        )
        self.assertEqual(
            self.normalized["port|VLAN0001|GigabitEthernet2/1/1"],
            {
                "role": "alternate",
                "state": "blocking",
                "guard": "loop",
                "bpdu_guard": "default",
                "link_type": "point-to-point",
            },
        )
        self.assertEqual(
            self.normalized["port|VLAN0001|GigabitEthernet1/0/3"]["state"], "listening"
        )
        self.assertEqual(self.normalized["port|VLAN0001|GigabitEthernet1/1/1"]["role"], "root")
        # The link-down port the fixture lists as stp-disabled is not a key.
        self.assertNotIn("port|VLAN0001|GigabitEthernet1/0/7", self.normalized)
        self.assertEqual(self.context["disabled_ports_listed"], 1)

    def test_disabled_rows_come_and_go_without_a_diff(self):
        # An endpoint that powers on (its stp-disabled row vanishes) or off (a
        # row appears) between captures diffs to nothing.
        payload = copy.deepcopy(self.payload)
        detail = payload["Cisco-IOS-XE-spanning-tree-oper:stp-details"]["stp-detail"][0]
        detail["interfaces"]["interface"] = [
            p for p in detail["interfaces"]["interface"] if p["state"] != "stp-disabled"
        ]
        woke, woke_ctx = l2._normalize_stp(payload)
        self.assertEqual(woke, self.normalized)
        self.assertEqual(woke_ctx["disabled_ports_listed"], 0)
        compare = registry.CHECKS["iosxe_stp"].compare
        self.assertEqual(diffcore.diff_check(self.normalized, woke, compare)["result"], "pass")
        # A disabled row with a non-designated role is still not a key: the
        # state, not the role, is what says the port has no place in the tree.
        detail["interfaces"]["interface"].append(
            {"name": "GigabitEthernet1/0/8", "role": "stp-alternate", "state": "stp-disabled"}
        )
        again, again_ctx = l2._normalize_stp(payload)
        self.assertEqual(again, self.normalized)
        self.assertEqual(again_ctx["ports_by_state"]["disabled"], 1)

    def test_counters_and_times_live_in_context(self):
        self.assertEqual(
            self.context["instances"]["VLAN0001"],
            {
                "topology_changes": 7,
                "last_topology_change": "2026-09-20T10:11:12.000+00:00",
                "designated_forwarding": 2,
                "ports": 6,
            },
        )
        self.assertEqual(self.context["instance_total"], 2)
        self.assertEqual(self.context["ports_keyed"], 3)
        self.assertEqual(self.context["disabled_ports_listed"], 1)
        self.assertEqual(
            self.context["ports_by_role"], {"alternate": 1, "designated": 5, "root": 1}
        )
        self.assertEqual(
            self.context["ports_by_state"],
            {"blocking": 1, "disabled": 1, "forwarding": 4, "listening": 1},
        )
        for value in self.normalized.values():
            self.assertNotIn("topology_changes", value)
            self.assertNotIn("last_topology_change", value)

    def test_root_status_falls_back_to_root_port_and_unresolved_port_num_is_kept(self):
        detail = {"instance": "MST0", "root-port": 0}
        self.assertTrue(l2._stp_is_root(detail))
        self.assertIsNone(l2._stp_is_root({"instance": "MST0"}))
        payload = {
            "Cisco-IOS-XE-spanning-tree-oper:stp-details": {
                "stp-detail": {"instance": "MST0", "root-port": 77, "root-cost": 20000},
                "stp-global": {
                    "mode": "stp-mode-mst",
                    "loop-guard": [None],
                    "mst-only": {
                        "mst-config-name": "CAMPUS",
                        "mst-config-revision": 3,
                        "max-hops": 20,
                    },
                },
            }
        }
        normalized, context = l2._normalize_stp(payload)
        self.assertEqual(
            normalized["instance|MST0"], {"root_cost": 20000, "root_port": "77", "is_root": False}
        )
        self.assertEqual(normalized["stp"]["mode"], "mst")
        self.assertTrue(normalized["stp"]["loop_guard"])
        self.assertEqual(normalized["stp"]["mst_name"], "CAMPUS")
        self.assertEqual(normalized["stp"]["mst_revision"], 3)
        self.assertEqual(context["instances"]["MST0"], {"designated_forwarding": 0, "ports": 0})
        self.assertEqual(context["disabled_ports_listed"], 0)

    def test_collector_end_to_end_with_the_fields_filter(self):
        ctx = _Ctx({"stp-details": self.payload})
        outcome = l2._collect_stp(ctx)
        self.assertEqual(outcome["normalized"], self.normalized)
        self.assertEqual(outcome["context"], self.context)
        self.assertEqual(len(ctx.calls), 1)
        self.assertIn("?fields=stp-detail(", ctx.calls[0])
        self.assertEqual(list(outcome["raw"]), [ctx.calls[0]])

    def test_collector_retries_unfiltered_on_400(self):
        ctx = _Ctx({"stp-details": _reject_fields("iosxe_stp_details.json")})
        outcome = l2._collect_stp(ctx)
        self.assertEqual(len(ctx.calls), 2)
        self.assertIn("fields filter rejected", outcome["raw"]["note"])
        self.assertIn(l2._STP_PATH, outcome["raw"])
        self.assertEqual(outcome["normalized"]["stp"]["mode"], "rapid-pvst")

    def test_absent_model_and_empty_container_are_not_present(self):
        with self.assertRaises(registry.SkipCheck):
            l2._collect_stp(_Ctx())
        with self.assertRaises(registry.SkipCheck):
            l2._collect_stp(
                _Ctx({"stp-details": {"Cisco-IOS-XE-spanning-tree-oper:stp-details": {}}})
            )

    def test_global_only_answer_is_real_data(self):
        payload = {
            "Cisco-IOS-XE-spanning-tree-oper:stp-details": {"stp-global": {"mode": "stp-mode-pvst"}}
        }
        outcome = l2._collect_stp(_Ctx({"stp-details": payload}))
        self.assertEqual(list(outcome["normalized"]), ["stp"])
        self.assertEqual(outcome["context"]["instance_total"], 0)


class TestMacTable(unittest.TestCase):
    def setUp(self):
        self.payload = J("iosxe_matm_table.json")
        self.normalized, self.context, self.rows = l2._normalize_mac_table(self.payload)

    def test_capability_buckets_count_dynamic_entries_only(self):
        self.assertEqual(
            self.normalized,
            {
                "total": 10,
                "vlan|1": 2,
                "vlan|10": 7,
                "vlan|20": 1,
                "member|1": 8,
                "member|2": 1,
                "port|GigabitEthernet1/0/1": 2,
                "port|GigabitEthernet1/1/1": 6,
                "port|GigabitEthernet2/0/1": 1,
                "port|Port-channel1": 1,
            },
        )
        # The capability diff contract: flat int values only.
        for key, value in self.normalized.items():
            self.assertIsInstance(value, int, key)
        self.assertNotIn("port|CPU", self.normalized)
        self.assertNotIn("port|Vlan10", self.normalized)

    def test_context_and_rows(self):
        self.assertEqual(self.context["entries_total"], 14)
        self.assertEqual(self.context["dynamic_total"], 10)
        self.assertEqual(self.context["static_total"], 4)
        self.assertEqual(self.context["by_type"], {"dynamic": 10, "static": 4})
        self.assertEqual(self.context["by_table_type"], {"vlan": 12, "vlan-independent": 2})
        self.assertEqual(self.context["ports_with_dynamic"], 4)
        self.assertEqual(self.context["aging_time"], 300)
        self.assertEqual(self.context["aging_time_by_vlan"], {})
        self.assertEqual(len(self.rows), 14)
        self.assertEqual(
            self.rows[-1],
            {
                "mac": "00:00:5e:00:53:21",
                "vlan": 20,
                "port": "GigabitEthernet1/0/1",
                "type": "dynamic",
                "table": "vlan",
            },
        )
        for row in self.rows:
            self.assertEqual(set(row) - {"vlan", "port"}, {"mac", "type", "table"})

    def test_differing_aging_times_are_reported_per_vlan(self):
        payload = copy.deepcopy(self.payload)
        payload["Cisco-IOS-XE-matm-oper:matm-table"][1]["aging-time"] = 600
        _, context, _ = l2._normalize_mac_table(payload)
        self.assertIsNone(context["aging_time"])
        self.assertEqual(context["aging_time_by_vlan"], {"1": 300, "10": 600, "20": 300})

    def test_collector_end_to_end_and_raw_cap(self):
        ctx = _Ctx({"matm-table": self.payload})
        outcome = l2._collect_mac_table(ctx)
        self.assertEqual(outcome["normalized"], self.normalized)
        path = ctx.calls[0]
        self.assertIn("?fields=table-type;vlan-id-number;aging-time;matm-mac-entry(", path)
        self.assertEqual(outcome["raw"][path]["rows_total"], 14)
        self.assertFalse(outcome["raw"][path]["truncated"])
        self.assertEqual(len(outcome["raw"][path]["rows"]), 14)
        self.assertNotIn("note", outcome["raw"])

        original = l2.MAC_TABLE_RAW_MAX
        l2.MAC_TABLE_RAW_MAX = 3
        try:
            capped = l2._collect_mac_table(_Ctx({"matm-table": self.payload}))
        finally:
            l2.MAC_TABLE_RAW_MAX = original
        self.assertEqual(len(capped["raw"][path]["rows"]), 3)
        self.assertTrue(capped["raw"][path]["truncated"])
        self.assertIn("capped at 3 of 14", capped["raw"]["note"])

    def test_collector_retries_unfiltered_on_400(self):
        ctx = _Ctx({"matm-table": _reject_fields("iosxe_matm_table.json")})
        outcome = l2._collect_mac_table(ctx)
        self.assertEqual(len(ctx.calls), 2)
        self.assertIn("fields filter rejected", outcome["raw"]["note"])
        self.assertIn(l2._MATM_PATH, outcome["raw"])
        self.assertEqual(outcome["normalized"]["total"], 10)

    def test_absent_model_is_not_present_but_an_empty_table_is_zero(self):
        with self.assertRaises(registry.SkipCheck):
            l2._collect_mac_table(_Ctx())
        outcome = l2._collect_mac_table(_Ctx({"matm-table": {}}))
        self.assertEqual(outcome["normalized"], {"total": 0})
        self.assertEqual(outcome["context"]["entries_total"], 0)

    def test_no_username_or_hostname_is_ever_requested(self):
        for token in ("username", "hostname", "device-name", "user"):
            self.assertNotIn(token, l2._MATM_FIELDS)
            self.assertNotIn(token, l2._STP_FIELDS)


class TestStability(unittest.TestCase):
    """Two healthy captures of an unchanged device must diff to nothing."""

    def _outcomes(self):
        ssh = {
            "show vtp status": T("iosxe_show_vtp_status.txt"),
            "show interfaces trunk": T("iosxe_show_interfaces_trunk.txt"),
        }
        payloads = {
            "vlans": J("iosxe_vlan_oper.json"),
            "stp-details": J("iosxe_stp_details.json"),
            "matm-table": J("iosxe_matm_table.json"),
        }
        return {
            check_id: registry.CHECKS[check_id].collector(_Ctx(payloads, ssh=ssh))
            for check_id in EXPECTED_IDS
        }

    def test_identical_captures_pass_under_each_registered_compare(self):
        pre, post = self._outcomes(), self._outcomes()
        for check_id in EXPECTED_IDS:
            diff = diffcore.diff_check(
                pre[check_id]["normalized"],
                post[check_id]["normalized"],
                registry.CHECKS[check_id].compare,
            )
            self.assertEqual(diff["result"], "pass", check_id)

    def test_a_moved_counter_changes_context_not_normalized(self):
        payload = J("iosxe_stp_details.json")
        bumped = copy.deepcopy(payload)
        bumped["Cisco-IOS-XE-spanning-tree-oper:stp-details"]["stp-detail"][0][
            "topology-changes"
        ] = 8
        before, before_ctx = l2._normalize_stp(payload)
        after, after_ctx = l2._normalize_stp(bumped)
        self.assertEqual(before, after)
        self.assertNotEqual(before_ctx, after_ctx)


class TestRegistrations(unittest.TestCase):
    def test_this_module_owns_exactly_its_catalog(self):
        owned = {
            check_id
            for check_id, check in registry.CHECKS.items()
            if check.collector.__module__ == l2.__name__
        }
        self.assertEqual(owned, EXPECTED_IDS)
        for check_id in EXPECTED_IDS:
            check = registry.CHECKS[check_id]
            self.assertEqual(check.platform, "iosxe", check_id)
            self.assertIn(check.tier, (1, 2, 3), check_id)
            self.assertIn(check.compare.get("mode", "equality_set"), diffcore.MODES, check_id)
            self.assertTrue(callable(check.collector), check_id)
            self.assertTrue(check.miss_meaning, check_id)
            self.assertIn("layer2", check.tags, check_id)
        self.assertEqual(
            {c.id for c in registry.checks_for("iosxe") if c.id in EXPECTED_IDS}, EXPECTED_IDS
        )

    def test_tiers_and_compare_modes_follow_the_plan(self):
        for check_id in ("iosxe_vlans", "iosxe_trunks", "iosxe_stp"):
            self.assertEqual(registry.CHECKS[check_id].tier, 1, check_id)
            self.assertEqual(registry.CHECKS[check_id].compare, {"mode": "equality_set"}, check_id)
        mac = registry.CHECKS["iosxe_mac_table"]
        self.assertEqual(mac.tier, 2)
        self.assertEqual(
            mac.compare,
            {"mode": "capability", "floor_pre": 5, "min_post": 1, "absent_post": "zero"},
        )

    def test_an_absent_mac_bucket_post_reads_as_zero(self):
        pre, _context, _rows = l2._normalize_mac_table(J("iosxe_matm_table.json"))
        diff = diffcore.diff_check(pre, {"total": 0}, registry.CHECKS["iosxe_mac_table"].compare)
        self.assertEqual(diff["result"], "diffs")
        notes = {e["key"]: e.get("note") for e in diff["evaluations"] if e["ok"] is False}
        self.assertIn("port|GigabitEthernet1/1/1", notes)
        for key, note in notes.items():
            if key != "total":
                self.assertEqual(note, "absent post (counts as zero)", key)
        self.assertIn("counts as zero", l2.SEMANTICS["iosxe_mac_table"])

    def test_semantics_merged_into_the_registry(self):
        for check_id in EXPECTED_IDS:
            self.assertIn(check_id, registry.SEMANTICS, check_id)
            self.assertGreater(len(registry.SEMANTICS[check_id]), 40, check_id)
            self.assertEqual(registry.SEMANTICS[check_id], l2.SEMANTICS[check_id])
        self.assertIn("802.1X", l2.SEMANTICS["iosxe_vlans"])  # why the port map is context
        self.assertIn("vtp_pruning", l2.SEMANTICS["iosxe_trunks"])  # the pruning branch
        self.assertIn("disabled", l2.SEMANTICS["iosxe_stp"])  # never keys
        self.assertIn("redacted", l2.SEMANTICS["iosxe_vlans"])  # the digest

    def test_key_models_for_the_shakedown(self):
        self.assertEqual(
            l2.KEY_MODELS,
            ("Cisco-IOS-XE-vlan-oper", "Cisco-IOS-XE-spanning-tree-oper", "Cisco-IOS-XE-matm-oper"),
        )

    def test_raw_cap_constant_mirrors_the_client_cap(self):
        self.assertEqual(l2.MAC_TABLE_RAW_MAX, _loader.constants.WLC_CLIENT_RAW_MAX)


if __name__ == "__main__":
    unittest.main()
