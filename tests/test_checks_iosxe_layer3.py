"""checks_iosxe_layer3: FHRP roles and the EIGRP / IS-IS adjacencies.

Driven with fixtures built from the sanitized Catalyst 9300 lab payloads
(tests/fixtures/iosxe_vrrp_oper.json and iosxe_eigrp_oper.json copy the real
lab shapes: one VRRPv3 master group, one EIGRP instance with two interfaces
and no neighbour element) plus hand-built rows from the published 17.15.1
models where the lab could not produce one (HSRP and IS-IS are not in its
licence; the adjacency rows for every protocol). Addresses are
documentation-range values. No Nautobot, no network.
"""

import copy
import re
import unittest

if __package__:
    from . import _loader
else:  # unittest discover -s tests imports test modules as top-level
    import _loader

l3 = _loader.load("checks_iosxe_layer3")
registry = _loader.registry
diffcore = _loader.diffcore
J = _loader.fixture_json

EXPECTED_IDS = {"iosxe_fhrp", "iosxe_eigrp_neighbors", "iosxe_isis_neighbors"}


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
    None under ok_404 (the 404 case).
    """

    def __init__(self, payloads=None):
        self.payloads = payloads or {}
        self.calls = []
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
        return False


def _reject_fields(fixture_name):
    """A payload callable: HTTP 400 for the filtered path, the fixture unfiltered."""

    def answer(path):
        if "?fields=" in path:
            raise _Http(400)
        return J(fixture_name)

    return answer


def _no_diff(check_id, pre, post):
    """True when diffcore sees nothing between two normalized views."""
    diff = diffcore.diff_check(pre, post, registry.CHECKS[check_id].compare)
    return not any(diff.get(bucket) for bucket in ("added", "removed", "changed", "misses"))


class TestHelpers(unittest.TestCase):
    def test_address_drops_unresolved_spellings(self):
        self.assertEqual(l3._address(" 198.18.4.2 "), "198.18.4.2")
        self.assertIsNone(l3._address("0.0.0.0"))
        self.assertIsNone(l3._address("::"))
        self.assertIsNone(l3._address(""))
        self.assertIsNone(l3._address(None))

    def test_presence_leaves_and_flags(self):
        self.assertTrue(l3._present({"passive": [None]}, "passive"))
        self.assertFalse(l3._present({}, "passive"))
        self.assertFalse(l3._present(None, "passive"))
        names = (("stubbed", "stub"), ("receive-only", "receive_only"))
        self.assertEqual(
            l3._flags({"stubbed": [None]}, names), {"stub": True, "receive_only": False}
        )
        self.assertEqual(l3._flags(None, names), {"stub": None, "receive_only": None})

    def test_address_family_router_id_and_version(self):
        self.assertEqual(l3._af("ipv4-address"), "ipv4")
        self.assertEqual(l3._af("ipv6-address"), "ipv6")
        self.assertEqual(l3._af("unknown"), "unknown")
        self.assertIsNone(l3._af(None))
        self.assertEqual(l3._dotted(3221226132), "192.0.2.148")
        self.assertEqual(l3._dotted("3221226132"), "192.0.2.148")
        self.assertEqual(l3._dotted("192.0.2.1"), "192.0.2.1")
        self.assertIsNone(l3._dotted(None))
        self.assertEqual(l3._version({"a": 17, "b": "15"}, "a", "b"), "17.15")
        self.assertIsNone(l3._version({"a": 17}, "a", "b"))
        self.assertIsNone(l3._version(None, "a", "b"))

    def test_secret_scrub_walks_lists_and_dicts(self):
        payload = {
            "x": [{"auth-key": {"key-chain": "kc", "sha256-password": "s3"}}, 1],
            "Password": "p",
            "name": "n",
        }
        scrubbed = l3._scrub_secrets(payload)
        self.assertEqual(
            scrubbed,
            {
                "x": [{"auth-key": {"key-chain": "kc", "sha256-password": "***scrubbed***"}}, 1],
                "Password": "***scrubbed***",
                "name": "n",
            },
        )
        # A copy: the caller's payload is untouched.
        self.assertEqual(payload["x"][0]["auth-key"]["sha256-password"], "s3")

    def test_model_status_text(self):
        self.assertEqual(l3._model_status(None, 0, "groups"), "not served (404)")
        self.assertEqual(l3._model_status({}, 0, "groups"), "served, no groups")
        self.assertEqual(l3._model_status({}, 2, "groups"), "2 groups")
        self.assertEqual(l3._model_status({}, 1, "groups"), "1 group")


class TestFetchFallback(unittest.TestCase):
    def test_fields_rejection_falls_back_once_and_is_noted(self):
        ctx = _Ctx({"vrrp-oper-data": _reject_fields("iosxe_vrrp_oper.json")})
        notes = []
        payload, path = l3._get_filtered(ctx, l3._VRRP_PATH, l3._VRRP_FIELDS, notes, "vrrp-oper")
        self.assertEqual(path, l3._VRRP_PATH)
        self.assertIn("vrrp-oper-state", payload["Cisco-IOS-XE-vrrp-oper:vrrp-oper-data"])
        self.assertEqual(len(ctx.calls), 2)
        self.assertEqual(
            notes, ["vrrp-oper: fields filter rejected (HTTP 400); unfiltered read used"]
        )

    def test_other_http_errors_propagate(self):
        ctx = _Ctx({"eigrp-oper-data": _Http(500)})
        with self.assertRaises(_Http):
            l3._get_filtered(ctx, l3._EIGRP_PATH, l3._EIGRP_FIELDS, [], "eigrp-oper")

    def test_absent_model_is_none_with_the_filtered_path(self):
        payload, path = l3._get_filtered(_Ctx(), l3._ISIS_PATH, l3._ISIS_FIELDS, [], "isis-oper")
        self.assertIsNone(payload)
        self.assertEqual(path, "%s?fields=%s" % (l3._ISIS_PATH, l3._ISIS_FIELDS))


class TestFhrp(unittest.TestCase):
    def setUp(self):
        self.hsrp = J("iosxe_hsrp_oper.json")
        self.vrrp = J("iosxe_vrrp_oper.json")

    def test_keys_and_role_facts(self):
        normalized, _ = l3._normalize_fhrp(self.hsrp, self.vrrp)
        self.assertEqual(
            normalized,
            {
                "hsrp|Vlan10|10": {
                    "state": "active",
                    "vip": "198.18.10.1",
                    "priority": 110,
                    "preempt": True,
                    "active_ip": "198.18.10.2",
                    "standby_ip": "198.18.10.3",
                },
                "hsrp|Vlan11|11": {
                    "state": "standby",
                    "vip": "198.18.11.1",
                    "priority": 90,
                    "preempt": False,
                    "active_ip": "198.18.11.3",
                    "standby_ip": "198.18.11.2",
                },
                # priority and preempt string-ified; no standby router -> None.
                "hsrp|Vlan12|12": {
                    "state": "active",
                    "vip": "198.18.12.1",
                    "priority": 100,
                    "preempt": True,
                    "active_ip": "198.18.12.2",
                    "standby_ip": None,
                },
                # The lab's real row: master, the local SVI address as master_ip.
                "vrrp|Vlan4|4|ipv4": {
                    "state": "master",
                    "vip": "198.18.4.1",
                    "priority": 110,
                    "preempt": True,
                    "owner": False,
                    "master_ip": "198.18.4.2",
                },
                "vrrp|Vlan20|20|ipv4": {
                    "state": "backup",
                    "vip": "198.18.20.1",
                    "priority": 100,
                    "preempt": False,
                    "owner": False,
                    "master_ip": "198.18.20.3",
                },
                # IPv6 group still in init: master '::' reads None.
                "vrrp|Vlan6|6|ipv6": {
                    "state": "init",
                    "vip": "fe80::5e:0:2:6",
                    "priority": 100,
                    "preempt": True,
                    "owner": False,
                    "master_ip": None,
                },
            },
        )

    def test_transitions_tracks_and_neighbours_are_context(self):
        _, context = l3._normalize_fhrp(self.hsrp, self.vrrp)
        self.assertEqual(context["models"], {"hsrp-oper": "3 groups", "vrrp-oper": "3 groups"})
        self.assertEqual((context["hsrp_groups"], context["vrrp_groups"]), (3, 3))
        self.assertEqual(
            context["vrrp"]["vrrp|Vlan4|4|ipv4"],
            {
                "master_transitions": 2,
                "new_master_reason": "master-no-response",
                "last_state_change": "2026-09-29T15:43:25.342+00:00",
                "tracks": {},
                "version": "vrrp-v3",
                "virtual_mac": "00:00:5e:00:01:04",
                "secondary_vips": [],
                "omp_state": "omp-down",
            },
        )
        backup = context["vrrp"]["vrrp|Vlan20|20|ipv4"]
        self.assertEqual(backup["tracks"], {"10": "resolved", "20": "unresolved"})
        self.assertEqual(backup["state_change_reason"], "not-master")
        self.assertEqual(backup["new_master_reason"], "not-master")
        self.assertEqual(backup["secondary_vips"], ["198.18.20.2"])
        self.assertEqual(
            (backup["bfd_enabled"], backup["bfd_state"]), (False, "vrrp-bfd-state-down")
        )
        self.assertEqual(
            context["hsrp_neighbors"],
            {
                "Vlan10": [
                    {
                        "address": "198.18.10.3",
                        "active_groups": [],
                        "standby_groups": [10],
                        "passive": False,
                        "passive_timer_remaining": 0,
                        "bfd_enabled": False,
                    }
                ]
            },
        )

    def test_either_model_alone_and_neither(self):
        hsrp_only, context = l3._normalize_fhrp(self.hsrp, None)
        self.assertEqual(sorted(hsrp_only), ["hsrp|Vlan10|10", "hsrp|Vlan11|11", "hsrp|Vlan12|12"])
        self.assertEqual(context["models"]["vrrp-oper"], "not served (404)")
        self.assertEqual(context["vrrp"], {})
        vrrp_only, context = l3._normalize_fhrp(None, self.vrrp)
        self.assertEqual(len(vrrp_only), 3)
        self.assertEqual(context["models"]["hsrp-oper"], "not served (404)")
        self.assertEqual(context["hsrp_neighbors"], {})
        self.assertEqual(l3._normalize_fhrp(None, None), ({}, l3._normalize_fhrp(None, None)[1]))
        empty = {"Cisco-IOS-XE-vrrp-oper:vrrp-oper-data": {}}
        normalized, context = l3._normalize_fhrp({}, empty)
        self.assertEqual(normalized, {})
        self.assertEqual(
            context["models"], {"hsrp-oper": "served, no groups", "vrrp-oper": "served, no groups"}
        )

    def test_rows_missing_their_keys_are_skipped(self):
        payload = {
            "Cisco-IOS-XE-hsrp-oper:hsrp-oper-data": {
                "hsrp-group-info": [{"group-id": 1}, {"if-name": "Vlan1"}, "junk"]
            }
        }
        self.assertEqual(l3._normalize_fhrp(payload, None)[0], {})

    def test_counters_and_times_moving_diff_to_nothing(self):
        later = copy.deepcopy(self.vrrp)
        row = later["Cisco-IOS-XE-vrrp-oper:vrrp-oper-data"]["vrrp-oper-state"][0]
        row["advertisement-sent"] += 500
        row["master-transitions"] += 1
        row["last-state-change-time"] = "2026-09-29T16:43:25.342+00:00"
        pre, _ = l3._normalize_fhrp(self.hsrp, self.vrrp)
        post, _ = l3._normalize_fhrp(self.hsrp, later)
        self.assertEqual(pre, post)
        self.assertTrue(_no_diff("iosxe_fhrp", pre, post))

    def test_a_role_flip_is_a_change(self):
        flipped = copy.deepcopy(self.vrrp)
        row = flipped["Cisco-IOS-XE-vrrp-oper:vrrp-oper-data"]["vrrp-oper-state"][0]
        row["vrrp-state"] = "proto-state-backup"
        row["master-ip"] = "198.18.4.3"
        pre, _ = l3._normalize_fhrp(None, self.vrrp)
        post, _ = l3._normalize_fhrp(None, flipped)
        self.assertFalse(_no_diff("iosxe_fhrp", pre, post))

    def test_lab_vrrp_fixture_normalizes_to_the_master_row(self):
        normalized, context = l3._normalize_fhrp(None, J("iosxe_vrrp_oper_lab.json"))
        self.assertEqual(list(normalized), ["vrrp|Vlan4|4|ipv4"])
        self.assertEqual(normalized["vrrp|Vlan4|4|ipv4"]["state"], "master")
        self.assertEqual(context["vrrp"]["vrrp|Vlan4|4|ipv4"]["master_transitions"], 1)

    def test_collector_end_to_end_with_both_filters(self):
        ctx = _Ctx({"hsrp-oper-data": self.hsrp, "vrrp-oper-data": self.vrrp})
        outcome = l3._collect_fhrp(ctx)
        self.assertEqual(len(outcome["normalized"]), 6)
        self.assertEqual(
            sorted(outcome["raw"]),
            sorted(
                [
                    "%s?fields=%s" % (l3._HSRP_PATH, l3._HSRP_FIELDS),
                    "%s?fields=%s" % (l3._VRRP_PATH, l3._VRRP_FIELDS),
                ]
            ),
        )
        self.assertNotIn("note", outcome["raw"])
        self.assertEqual(outcome["context"]["models"]["hsrp-oper"], "3 groups")

    def test_collector_with_hsrp_absent_keeps_the_404_in_raw(self):
        outcome = l3._collect_fhrp(_Ctx({"vrrp-oper-data": self.vrrp}))
        self.assertEqual(len(outcome["normalized"]), 3)
        self.assertIsNone(outcome["raw"]["%s?fields=%s" % (l3._HSRP_PATH, l3._HSRP_FIELDS)])
        self.assertEqual(outcome["context"]["models"]["hsrp-oper"], "not served (404)")

    def test_collector_retries_unfiltered_on_400_and_notes_it(self):
        ctx = _Ctx(
            {
                "hsrp-oper-data": _reject_fields("iosxe_hsrp_oper.json"),
                "vrrp-oper-data": _reject_fields("iosxe_vrrp_oper.json"),
            }
        )
        outcome = l3._collect_fhrp(ctx)
        self.assertEqual(sorted(outcome["raw"]), sorted([l3._HSRP_PATH, l3._VRRP_PATH, "note"]))
        self.assertIn("hsrp-oper: fields filter rejected", outcome["raw"]["note"])
        self.assertIn("vrrp-oper: fields filter rejected", outcome["raw"]["note"])
        self.assertEqual(len(ctx.calls), 4)

    def test_not_present_when_both_models_are_absent_or_empty(self):
        with self.assertRaises(registry.SkipCheck) as absent:
            l3._collect_fhrp(_Ctx())
        self.assertIn("hsrp-oper not served (404)", str(absent.exception))
        with self.assertRaises(registry.SkipCheck) as empty:
            l3._collect_fhrp(
                _Ctx(
                    {
                        "hsrp-oper-data": {"Cisco-IOS-XE-hsrp-oper:hsrp-oper-data": {}},
                        "vrrp-oper-data": {},
                    }
                )
            )
        self.assertIn("vrrp-oper served, no groups", str(empty.exception))

    def test_other_errors_propagate(self):
        with self.assertRaises(_Http):
            l3._collect_fhrp(_Ctx({"hsrp-oper-data": _Http(500)}))


class TestEigrp(unittest.TestCase):
    def setUp(self):
        self.payload = J("iosxe_eigrp_oper.json")

    def test_keys_and_peer_facts(self):
        normalized, _ = l3._normalize_eigrp_neighbors(self.payload)
        self.assertEqual(
            normalized,
            {
                "ipv4|1|default|Vlan3|203.0.113.1": {
                    "stub": True,
                    "receive_only": False,
                    "static": False,
                    "sw_version": "17.15",
                    "tlv_version": "3.0",
                }
            },
        )

    def test_instances_interfaces_and_readings_are_context(self):
        _, context = l3._normalize_eigrp_neighbors(self.payload)
        self.assertEqual(
            context["instances"],
            {
                "ipv4|1|default": {
                    "router_id": "192.0.2.148",
                    "named_mode": False,
                    "interfaces": {
                        "Vlan3": {"passive": False, "hello_interval": 5, "hold_timer": 15},
                        "Vlan4": {"passive": True, "hello_interval": 5, "hold_timer": 15},
                    },
                    "neighbors": 1,
                }
            },
        )
        self.assertEqual(
            context["neighbors"],
            {
                "ipv4|1|default|Vlan3|203.0.113.1": {
                    "srtt": 12,
                    "rto": 100,
                    "retransmit_count": 3,
                    "retry_count": 0,
                    "last_seq_number": 41,
                }
            },
        )

    def test_missing_stub_container_and_named_mode(self):
        payload = {
            "Cisco-IOS-XE-eigrp-oper:eigrp-oper-data": {
                "eigrp-instance": {
                    "afi": "eigrp-af-ipv6",
                    "vrf-name": "CAMPUS",
                    "as-num": "100",
                    "named-mode": [None],
                    "name": "CAMPUS-EIGRP",
                    "eigrp-interface": {
                        "name": "Vlan50",
                        "eigrp-nbr": [
                            {"afi": "eigrp-af-ipv6", "nbr-address": "fe80::1"},
                            {"afi": "eigrp-af-ipv6"},
                        ],
                    },
                }
            }
        }
        normalized, context = l3._normalize_eigrp_neighbors(payload)
        self.assertEqual(
            normalized,
            {
                "ipv6|100|CAMPUS|Vlan50|fe80::1": {
                    "stub": None,
                    "receive_only": None,
                    "static": None,
                    "sw_version": None,
                    "tlv_version": None,
                }
            },
        )
        self.assertEqual(
            context["instances"]["ipv6|100|CAMPUS"],
            {
                "name": "CAMPUS-EIGRP",
                "named_mode": True,
                "interfaces": {"Vlan50": {"passive": False}},
                "neighbors": 1,
            },
        )
        self.assertEqual(context["neighbors"], {"ipv6|100|CAMPUS|Vlan50|fe80::1": {}})

    def test_lab_fixture_is_an_instance_without_neighbours(self):
        normalized, context = l3._normalize_eigrp_neighbors(J("iosxe_eigrp_oper_lab.json"))
        self.assertEqual(normalized, {})
        self.assertEqual(list(context["instances"]), ["ipv4|1|default"])
        self.assertEqual(context["instances"]["ipv4|1|default"]["neighbors"], 0)
        self.assertEqual(
            sorted(context["instances"]["ipv4|1|default"]["interfaces"]), ["Vlan3", "Vlan4"]
        )

    def test_readings_moving_diff_to_nothing(self):
        later = copy.deepcopy(self.payload)
        inst = later["Cisco-IOS-XE-eigrp-oper:eigrp-oper-data"]["eigrp-instance"][0]
        nbr = inst["eigrp-interface"][0]["eigrp-nbr"]
        nbr["srtt"], nbr["rto"], nbr["retransmit-count"], nbr["last-seq-number"] = 40, 240, 9, 99
        pre, _ = l3._normalize_eigrp_neighbors(self.payload)
        post, _ = l3._normalize_eigrp_neighbors(later)
        self.assertEqual(pre, post)
        self.assertTrue(_no_diff("iosxe_eigrp_neighbors", pre, post))

    def test_collector_end_to_end_scrubs_secrets_from_raw(self):
        ctx = _Ctx({"eigrp-oper-data": self.payload})
        outcome = l3._collect_eigrp_neighbors(ctx)
        path = "%s?fields=%s" % (l3._EIGRP_PATH, l3._EIGRP_FIELDS)
        self.assertEqual(list(outcome["raw"]), [path])
        self.assertEqual(len(outcome["normalized"]), 1)
        self.assertNotIn("fixture-only-secret", repr(outcome["raw"]))
        self.assertIn("***scrubbed***", repr(outcome["raw"]))
        # The device payload itself is untouched (the per-run cache hands it out again).
        self.assertIn("fixture-only-secret", repr(self.payload))

    def test_collector_retries_unfiltered_on_400(self):
        ctx = _Ctx({"eigrp-oper-data": _reject_fields("iosxe_eigrp_oper.json")})
        outcome = l3._collect_eigrp_neighbors(ctx)
        self.assertEqual(sorted(outcome["raw"]), [l3._EIGRP_PATH, "note"])
        self.assertIn("eigrp-oper: fields filter rejected", outcome["raw"]["note"])
        self.assertNotIn("fixture-only-secret", repr(outcome["raw"]))

    def test_instance_without_neighbours_is_an_empty_success(self):
        outcome = l3._collect_eigrp_neighbors(
            _Ctx({"eigrp-oper-data": J("iosxe_eigrp_oper_lab.json")})
        )
        self.assertEqual(outcome["normalized"], {})
        self.assertEqual(outcome["context"]["instances"]["ipv4|1|default"]["neighbors"], 0)

    def test_not_present_when_the_model_is_absent_or_lists_no_instance(self):
        with self.assertRaises(registry.SkipCheck) as absent:
            l3._collect_eigrp_neighbors(_Ctx())
        self.assertIn("not served", str(absent.exception))
        for empty in ({}, {"Cisco-IOS-XE-eigrp-oper:eigrp-oper-data": {}}):
            with self.assertRaises(registry.SkipCheck) as skip:
                l3._collect_eigrp_neighbors(_Ctx({"eigrp-oper-data": empty}))
            self.assertIn("no EIGRP instance", str(skip.exception))

    def test_other_errors_propagate(self):
        with self.assertRaises(_Http):
            l3._collect_eigrp_neighbors(_Ctx({"eigrp-oper-data": _Http(503)}))


class TestIsis(unittest.TestCase):
    def setUp(self):
        self.payload = J("iosxe_isis_oper.json")

    def test_keys_state_and_addresses(self):
        normalized, context = l3._normalize_isis_neighbors(self.payload)
        self.assertEqual(
            normalized,
            {
                "CORE|level-2|TenGigabitEthernet1/1/1|00:00:00:00:00:12": {
                    "state": "up",
                    "ipv4_address": "198.18.1.2",
                    "ipv6_address": "2001:db8:1::2",
                },
                "CORE|level-1|TenGigabitEthernet1/1/1|00:00:00:00:00:12": {
                    "state": "init",
                    "ipv4_address": "198.18.1.2",
                    "ipv6_address": None,
                },
            },
        )
        self.assertEqual(context["instances"], {"CORE": {"neighbors": 2}, "EDGE": {"neighbors": 0}})
        self.assertEqual(
            context["holdtime"],
            {
                "CORE|level-2|TenGigabitEthernet1/1/1|00:00:00:00:00:12": 27,
                "CORE|level-1|TenGigabitEthernet1/1/1|00:00:00:00:00:12": 9,
            },
        )

    def test_bare_dict_rows_and_missing_keys(self):
        payload = {
            "Cisco-IOS-XE-isis-oper:isis-oper-data": {
                "isis-instance": {
                    "tag": "",
                    "isis-neighbor": {"system-id": "00:00:00:00:00:AA", "if-name": "Gi1/0/1"},
                }
            }
        }
        normalized, context = l3._normalize_isis_neighbors(payload)
        self.assertEqual(
            normalized,
            {
                "default|unknown|Gi1/0/1|00:00:00:00:00:aa": {
                    "state": None,
                    "ipv4_address": None,
                    "ipv6_address": None,
                }
            },
        )
        self.assertEqual(context, {"instances": {"default": {"neighbors": 1}}, "holdtime": {}})
        headless = {
            "Cisco-IOS-XE-isis-oper:isis-oper-data": {
                "isis-instance": [{"tag": "X", "isis-neighbor": [{"level": "isis-level-1"}]}]
            }
        }
        self.assertEqual(l3._normalize_isis_neighbors(headless)[0], {})

    def test_holdtime_countdown_diffs_to_nothing(self):
        later = copy.deepcopy(self.payload)
        for row in later["Cisco-IOS-XE-isis-oper:isis-oper-data"]["isis-instance"][0][
            "isis-neighbor"
        ]:
            row["holdtime"] -= 5
        pre, _ = l3._normalize_isis_neighbors(self.payload)
        post, _ = l3._normalize_isis_neighbors(later)
        self.assertEqual(pre, post)
        self.assertTrue(_no_diff("iosxe_isis_neighbors", pre, post))

    def test_collector_end_to_end_and_retry(self):
        outcome = l3._collect_isis_neighbors(_Ctx({"isis-oper-data": self.payload}))
        self.assertEqual(list(outcome["raw"]), ["%s?fields=%s" % (l3._ISIS_PATH, l3._ISIS_FIELDS)])
        self.assertEqual(len(outcome["normalized"]), 2)
        retried = l3._collect_isis_neighbors(
            _Ctx({"isis-oper-data": _reject_fields("iosxe_isis_oper.json")})
        )
        self.assertEqual(sorted(retried["raw"]), [l3._ISIS_PATH, "note"])

    def test_not_present_when_absent_or_no_instance_and_empty_success_otherwise(self):
        with self.assertRaises(registry.SkipCheck) as absent:
            l3._collect_isis_neighbors(_Ctx())
        self.assertIn("not served", str(absent.exception))
        with self.assertRaises(registry.SkipCheck) as skip:
            l3._collect_isis_neighbors(
                _Ctx({"isis-oper-data": {"Cisco-IOS-XE-isis-oper:isis-oper-data": {}}})
            )
        self.assertIn("no IS-IS instance", str(skip.exception))
        quiet = {"Cisco-IOS-XE-isis-oper:isis-oper-data": {"isis-instance": [{"tag": "EDGE"}]}}
        outcome = l3._collect_isis_neighbors(_Ctx({"isis-oper-data": quiet}))
        self.assertEqual(outcome["normalized"], {})
        self.assertEqual(outcome["context"]["instances"], {"EDGE": {"neighbors": 0}})


class TestRegistration(unittest.TestCase):
    def test_checks_registered_with_semantics_modes_and_models(self):
        owned = {
            c.id for c in registry.checks_for("iosxe") if c.collector.__module__ == l3.__name__
        }
        self.assertEqual(owned, EXPECTED_IDS)
        for check_id in EXPECTED_IDS:
            check = registry.CHECKS[check_id]
            self.assertEqual(check.platform, "iosxe")
            self.assertEqual(check.tier, 1)
            self.assertEqual(check.compare["mode"], "equality_set")
            self.assertIn(check.compare["mode"], diffcore.MODES)
            self.assertEqual(check.collector.__module__, l3.__name__)
            self.assertIn(check_id, registry.SEMANTICS)
            self.assertIs(registry.SEMANTICS[check_id], l3.SEMANTICS[check_id])
        self.assertEqual(
            l3.KEY_MODELS,
            (
                "Cisco-IOS-XE-hsrp-oper",
                "Cisco-IOS-XE-vrrp-oper",
                "Cisco-IOS-XE-eigrp-oper",
                "Cisco-IOS-XE-isis-oper",
            ),
        )

    def test_fields_filters_never_request_the_secret_or_the_topology(self):
        self.assertNotIn("auth", l3._EIGRP_FIELDS)
        self.assertNotIn("eigrp-topo", l3._EIGRP_FIELDS)
        for fields in (l3._HSRP_FIELDS, l3._VRRP_FIELDS, l3._EIGRP_FIELDS, l3._ISIS_FIELDS):
            self.assertNotIn(" ", fields)

    def test_fixtures_hold_no_site_identifiers(self):
        for name in ("iosxe_hsrp_oper", "iosxe_vrrp_oper", "iosxe_eigrp_oper", "iosxe_isis_oper"):
            text = _loader.fixture_text(name + ".json")
            # Shape rules, not a deny-list of real names: every dotted quad sits in a
            # documentation or benchmark range (or is a mask/multicast) and nothing
            # reads like a login.
            for quad in re.findall(r"(?<![\d.])\d{1,3}(?:\.\d{1,3}){3}(?![\d.])", text):
                self.assertTrue(_loader.allowed_lab_address(quad), quad)
            self.assertNotRegex(text, r"\badmin\b")


if __name__ == "__main__":
    unittest.main()
