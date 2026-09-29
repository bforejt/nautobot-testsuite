"""checks_iosxe normalizers driven directly with committed RESTCONF fixtures."""

import unittest

if __package__:
    from . import _loader
else:  # unittest discover -s tests imports test modules as top-level
    import _loader

checks = _loader.checks_iosxe
registry = _loader.registry


class TestRibNormalizer(unittest.TestCase):
    def setUp(self):
        self.payload = _loader.fixture_json("iosxe_rib_routing_state.json")

    def test_full_normalized_view(self):
        self.assertEqual(
            checks._normalize_rib(self.payload),
            {
                "default|0.0.0.0/0": {
                    "protocol": "static",
                    "preference": 1,
                    "next_hops": [{"ip": "192.0.2.1", "interface": "Vlan925"}],
                },
                "default|172.16.5.0/24": {
                    "protocol": "ospfv2",
                    "preference": 110,
                    "next_hops": [{"ip": "10.0.0.2", "interface": "TenGigabitEthernet1/0/1"}],
                },
                "default|10.10.0.0/16": {
                    "protocol": "ospfv2",
                    "preference": 110,
                    # Fixture lists 10.0.0.6 first; normalization must sort.
                    "next_hops": [
                        {"ip": "10.0.0.2", "interface": "TenGigabitEthernet1/0/1"},
                        {"ip": "10.0.0.6", "interface": "TenGigabitEthernet1/0/2"},
                    ],
                },
                "default|192.0.2.0/30": {
                    "protocol": "direct",
                    "preference": 0,
                    "next_hops": [{"interface": "Vlan925"}],
                },
                "default|2001:db8:100::/64": {
                    "protocol": "ospfv2",
                    "preference": 110,
                    "next_hops": [{"ip": "fe80::1", "interface": "Vlan925"}],
                },
                "mgmt|0.0.0.0/0": {
                    "protocol": "static",
                    "preference": 1,
                    "next_hops": [{"ip": "10.255.0.1"}],
                },
                "mgmt|10.255.0.0/24": {
                    "protocol": "direct",
                    "preference": 0,
                    "next_hops": [{"interface": "GigabitEthernet0/0"}],
                },
            },
        )

    def test_active_route_wins_regardless_of_order(self):
        # 0.0.0.0/0: active static first, backup bgp second -> static stays.
        # 172.16.5.0/24: backup static first, active ospf second -> ospf wins.
        view = checks._normalize_rib(self.payload)
        self.assertEqual(view["default|0.0.0.0/0"]["protocol"], "static")
        self.assertEqual(view["default|172.16.5.0/24"]["protocol"], "ospfv2")
        self.assertEqual(view["default|172.16.5.0/24"]["preference"], 110)

    def test_single_dict_shape_everywhere(self):
        # RESTCONF quirk: every list may arrive as a bare dict.
        payload = {
            "ietf-routing:routing-state": {
                "routing-instance": {
                    "name": "default",
                    "ribs": {
                        "rib": {
                            "name": "ipv4-default",
                            "routes": {
                                "route": {
                                    "destination-prefix": "0.0.0.0/0",
                                    "route-preference": 1,
                                    "source-protocol": "ietf-routing:static",
                                    "active": [None],
                                    "next-hop": {
                                        "next-hop-address": "192.0.2.1",
                                        "outgoing-interface": "Vlan925",
                                    },
                                }
                            },
                        }
                    },
                }
            }
        }
        self.assertEqual(
            checks._normalize_rib(payload),
            {
                "default|0.0.0.0/0": {
                    "protocol": "static",
                    "preference": 1,
                    "next_hops": [{"ip": "192.0.2.1", "interface": "Vlan925"}],
                }
            },
        )

    def test_bare_container_name_fallback(self):
        rekeyed = {"routing-state": self.payload["ietf-routing:routing-state"]}
        self.assertEqual(checks._normalize_rib(rekeyed), checks._normalize_rib(self.payload))

    def test_empty_payload(self):
        self.assertEqual(checks._normalize_rib({}), {})
        self.assertEqual(checks._normalize_rib(None), {})


class TestRouteRollups(unittest.TestCase):
    def test_counts_by_stripped_protocol(self):
        payload = _loader.fixture_json("iosxe_rib_routing_state.json")
        self.assertEqual(
            checks._normalize_route_rollups(payload),
            {"total": 7, "static": 2, "ospfv2": 3, "direct": 2},
        )

    def test_ssh_trouble_is_a_note_but_the_celery_abort_is_raised(self):
        class SoftTimeLimitExceeded(Exception):
            pass

        payload = _loader.fixture_json("iosxe_rib_routing_state.json")

        class _Ctx:
            has_ssh = True

            def __init__(self, failure):
                self.failure = failure

            def get(self, path, **kwargs):
                return payload

            def run_ssh(self, command, **kwargs):
                raise self.failure

        result = checks._collect_route_rollups(_Ctx(RuntimeError("timed out")))
        self.assertIn("timed out", result["raw"]["note"])
        self.assertEqual(result["normalized"]["total"], 7)
        with self.assertRaises(SoftTimeLimitExceeded):
            checks._collect_route_rollups(_Ctx(SoftTimeLimitExceeded()))


class TestRouteSummaryParser(unittest.TestCase):
    def test_ospf_type_splits_summed_across_processes(self):
        text = _loader.fixture_text("iosxe_route_summary.txt")
        self.assertEqual(
            checks._parse_route_summary(text),
            {
                "ospf_intra": 28,  # 25 + 3
                "ospf_inter": 13,  # 12 + 1
                "ospf_e1": 2,  # 2 + 0, NSSA lines must not bleed in
                "ospf_e2": 6,  # 4 + 2
                "ospf_n1": 0,
                "ospf_n2": 0,
            },
        )

    def test_no_ospf_lines(self):
        self.assertEqual(checks._parse_route_summary("connected  0  14\nstatic  2  3\n"), {})
        self.assertEqual(checks._parse_route_summary(""), {})
        self.assertEqual(checks._parse_route_summary(None), {})


class TestFibNormalizer(unittest.TestCase):
    def test_full_normalized_view(self):
        payload = _loader.fixture_json("iosxe_fib_oper.json")
        self.assertEqual(
            checks._normalize_fib(payload),
            {
                "default|0.0.0.0/0": {"next_hops": [{"ip": "192.0.2.1", "interface": "Vlan925"}]},
                "default|10.10.0.0/16": {
                    "next_hops": [
                        {"ip": "10.0.0.2", "interface": "TenGigabitEthernet1/0/1"},
                        {"ip": "10.0.0.6", "interface": "TenGigabitEthernet1/0/2"},
                    ]
                },
                "default|192.0.2.0/30": {"next_hops": [{"interface": "Vlan925"}]},
                # fib-entries and fib-nexthop-entries both arrive as bare dicts here.
                "mgmt|10.255.0.0/24": {"next_hops": [{"interface": "GigabitEthernet0/0"}]},
            },
        )


class TestBgpNormalizer(unittest.TestCase):
    def test_full_normalized_view(self):
        payload = _loader.fixture_json("iosxe_bgp_neighbors.json")
        self.assertEqual(
            checks._normalize_bgp_peers(payload),
            {
                "ipv4-unicast|default|203.0.113.9": {
                    "state": "fsm-established",
                    "as": 64512,
                    "installed_prefixes": 187,
                },
                # vrf-name missing -> default; "as" arrives string-ified.
                "ipv4-unicast|default|10.0.0.2": {
                    "state": "fsm-idle",
                    "as": 65010,
                    "installed_prefixes": 0,
                },
            },
        )

    def test_empty(self):
        self.assertEqual(checks._normalize_bgp_peers({}), {})


class TestOspfNormalizer(unittest.TestCase):
    def test_full_normalized_view(self):
        payload = _loader.fixture_json("iosxe_ospf_oper.json")
        self.assertEqual(
            checks._normalize_ospf_neighbors(payload),
            {
                "10|0|Vlan925|10.10.255.3": {
                    "state": "ospf-nbr-full",
                    "address": "10.10.9.2",
                },
                "10|0|Vlan925|10.10.255.4": {
                    "state": "ospf-nbr-two-way",
                    "address": "10.10.9.3",
                },
                # This neighbor arrives as a bare dict, not a one-item list.
                "10|0|TenGigabitEthernet1/0/1|10.10.255.2": {
                    "state": "ospf-nbr-full",
                    "address": "10.0.0.2",
                },
            },
        )


class TestArpNormalizer(unittest.TestCase):
    def test_full_normalized_view(self):
        payload = _loader.fixture_json("iosxe_arp_oper.json")
        self.assertEqual(
            checks._normalize_arp(payload),
            {
                "default|192.0.2.1": {"mac": "00:00:5e:00:53:01", "interface": "Vlan925"},
                "default|10.10.9.2": {"mac": "00:00:5e:00:53:02", "interface": "Vlan925"},
                # mgmt arp-entry arrives as a bare dict; the address-less
                # default-vrf entry is dropped.
                "mgmt|10.255.0.1": {
                    "mac": "00:00:5e:00:53:03",
                    "interface": "GigabitEthernet0/0",
                },
            },
        )


class TestNeighborNormalizers(unittest.TestCase):
    def test_cdp(self):
        payload = _loader.fixture_json("iosxe_cdp_neighbors.json")
        self.assertEqual(
            checks._normalize_cdp(payload),
            {
                # native-vlan 1 advertised, vvid 0: the model's "not received".
                "cdp|core-sw-02.example.net|TenGigabitEthernet1/0/48": {
                    "port": "TenGigabitEthernet1/0/48",
                    "caps": "Router Switch IGMP",
                    "native_vlan": 1,
                    "duplex": "cdp-full-duplex",
                    "voice_vlan": None,
                    "platform": "cisco C9500-48Y4C",
                },
                # Second entry uses the plural "capabilities" leaf; native-vlan
                # 0 and no vvid leaf both read None.
                "cdp|ap-lab-01|GigabitEthernet1/0/12": {
                    "port": "GigabitEthernet0",
                    "caps": "Trans-Bridge Source-Route-Bridge IGMP",
                    "native_vlan": None,
                    "duplex": "cdp-full-duplex",
                    "voice_vlan": None,
                    "platform": "cisco AIR-AP2802I-B-K9",
                },
                # A phone: voice VLAN advertised, duplex mismatch reported verbatim.
                "cdp|SEP00000A000001|GigabitEthernet1/0/7": {
                    "port": "Port 1",
                    "caps": "Host Phone Two-port Mac Relay",
                    "native_vlan": 10,
                    "duplex": "cdp-full-duplex-mismatch",
                    "voice_vlan": 20,
                    "platform": "Cisco IP Phone 8845",
                },
            },
        )

    def test_cdp_platform_tolerates_the_bare_spelling_and_blank(self):
        # The model's leaf is platform-name; a bare 'platform' is read too, and
        # blank / absent both read None.
        def view(extra):
            payload = {
                "Cisco-IOS-XE-cdp-oper:cdp-neighbor-details": {
                    "cdp-neighbor-detail": {"device-id": "n", "local-intf-name": "Gi1/0/1", **extra}
                }
            }
            return checks._normalize_cdp(payload)["cdp|n|Gi1/0/1"]["platform"]

        self.assertEqual(view({"platform-name": " cisco WS-C2960X "}), "cisco WS-C2960X")
        self.assertEqual(view({"platform": "cisco C9200L"}), "cisco C9200L")
        self.assertIsNone(view({"platform-name": ""}))
        self.assertIsNone(view({}))

    def test_cdp_vlan_leaves_keep_one_type(self):
        # RESTCONF may string-ify numbers; junk never becomes a value.
        payload = {
            "Cisco-IOS-XE-cdp-oper:cdp-neighbor-details": {
                "cdp-neighbor-detail": {
                    "device-id": "sw",
                    "local-intf-name": "Gi1/0/1",
                    "native-vlan": "30",
                    "vvid": "n/a",
                    "duplex": "Cisco-IOS-XE-cdp-oper:cdp-half-duplex",
                }
            }
        }
        view = checks._normalize_cdp(payload)["cdp|sw|Gi1/0/1"]
        self.assertEqual(
            (view["native_vlan"], view["voice_vlan"], view["duplex"]), (30, None, "cdp-half-duplex")
        )

    def test_lldp(self):
        payload = _loader.fixture_json("iosxe_lldp_entries.json")
        self.assertEqual(
            checks._normalize_lldp(payload),
            {
                "lldp|fw-edge-01|TenGigabitEthernet1/0/47": {"port": "ethernet1/2"},
                "lldp|core-sw-02.example.net|TenGigabitEthernet1/0/48": {
                    "port": "TenGigabitEthernet1/0/48"
                },
            },
        )

    def test_combined_views_do_not_collide(self):
        cdp = checks._normalize_cdp(_loader.fixture_json("iosxe_cdp_neighbors.json"))
        lldp = checks._normalize_lldp(_loader.fixture_json("iosxe_lldp_entries.json"))
        combined = dict(cdp)
        combined.update(lldp)
        # Same physical link seen by both protocols stays two distinct keys.
        self.assertEqual(len(combined), len(cdp) + len(lldp))
        self.assertIn("cdp|core-sw-02.example.net|TenGigabitEthernet1/0/48", combined)
        self.assertIn("lldp|core-sw-02.example.net|TenGigabitEthernet1/0/48", combined)


class _IfaceCtx:
    """Fake CollectorContext for the interfaces GET: payload per path, an exception
    per path on cue, every GET recorded; SSH output per command when given."""

    def __init__(self, payloads, raise_for=None, outputs=None):
        self.payloads = payloads
        self.raise_for = raise_for or {}
        self.outputs = outputs
        self.gets = []
        self.commands = []

    @property
    def has_ssh(self):
        return self.outputs is not None

    def get(self, path, **kwargs):
        self.gets.append((path, dict(kwargs)))
        if path in self.raise_for:
            raise self.raise_for[path]
        return self.payloads.get(path)

    def run_ssh(self, command, **kwargs):
        self.commands.append(command)
        return self.outputs[command]


class _RestconfError(Exception):
    def __init__(self, message, status_code=None):
        super().__init__(message)
        self.status_code = status_code


def _iface_payload(*entries):
    return {"Cisco-IOS-XE-interfaces-oper:interfaces": {"interface": list(entries)}}


_UP = {"admin-status": "if-state-up", "oper-status": "if-oper-state-ready"}
_ETHER_1G = {"negotiated-duplex-mode": "full-duplex", "negotiated-port-speed": "speed-1gb"}
_UNSET = {
    "ipv4": None,
    "mask": None,
    "vrf": None,
    "ipv6": [],
    "mtu": None,
    "acl_in": None,
    "acl_out": None,
    "qos_in": None,
    "qos_out": None,
    "speed": None,
    "duplex": None,
    "mgig_downshift": None,
    "autoneg": None,
    "storm": [],
}
_ACCESS_CTX_KWARGS = {"ok_404": True}


def _vlan_payload(*port_names):
    """A vlan-oper payload whose VLAN 10 lists the given interfaces as assigned ports."""
    return {
        "Cisco-IOS-XE-vlan-oper:vlans": {
            "vlan": [
                {
                    "id": 10,
                    "name": "USERS",
                    "status": "active",
                    "ports": [{"interface": name, "subinterface": 0} for name in port_names],
                }
            ]
        }
    }


class TestInterfacesNormalizer(unittest.TestCase):
    def setUp(self):
        self.payload = _loader.fixture_json("iosxe_interfaces_oper.json")

    def test_full_normalized_view(self):
        self.assertEqual(
            checks._normalize_interfaces(self.payload),
            {
                # SVI: effective config only; no ether-state, so no speed/duplex.
                # ipv6-addrs arrive link-local first and are sorted; "" vrf is global.
                "Vlan925": {
                    "admin": "if-state-up",
                    "oper": "if-oper-state-ready",
                    "ipv4": "10.10.9.1",
                    "mask": "255.255.255.252",
                    "vrf": None,
                    "ipv6": ["2001:db8:100::1", "fe80::1"],
                    "mtu": 1500,
                    "acl_in": "ACL-TRANSIT-IN",
                    "acl_out": None,
                    "qos_in": "PM-INGRESS",
                    "qos_out": "PM-EGRESS",
                    "speed": None,
                    "duplex": None,
                    "mgig_downshift": None,
                    "autoneg": None,
                    "storm": [],
                },
                # Uplink, up: negotiated values emitted; the model's 'Global' vrf is None.
                "TenGigabitEthernet1/0/1": {
                    "admin": "if-state-up",
                    "oper": "if-oper-state-ready",
                    "ipv4": "10.0.0.1",
                    "mask": "255.255.255.252",
                    "vrf": None,
                    "ipv6": [],
                    "mtu": 9198,
                    "acl_in": None,
                    "acl_out": None,
                    "qos_in": None,
                    "qos_out": None,
                    "speed": "speed-10gb",
                    "duplex": "full-duplex",
                    "mgig_downshift": False,
                    "autoneg": True,
                    "storm": [],
                },
                # Down and err-disabled: ether-state served but the negotiated
                # values not emitted (autoneg, a config fact, is); the err-disable
                # leaves are iosxe_errdisable's, so nothing of them here.
                "TenGigabitEthernet1/0/5": {
                    "admin": "if-state-down",
                    "oper": "if-oper-state-no-pass",
                    "ipv4": None,
                    "mask": None,
                    "vrf": None,
                    "ipv6": [],
                    "mtu": 1500,
                    "acl_in": None,
                    "acl_out": None,
                    "qos_in": None,
                    "qos_out": None,
                    "speed": None,
                    "duplex": None,
                    "mgig_downshift": False,
                    "autoneg": True,
                    "storm": [],
                },
                # Access port: two traffic types blocking (sorted, rates ignored),
                # mGig downshifted. No VLAN database given: link scope 'all', so
                # its negotiated values are here.
                "TwoGigabitEthernet1/0/12": {
                    "admin": "if-state-up",
                    "oper": "if-oper-state-ready",
                    "ipv4": None,
                    "mask": None,
                    "vrf": None,
                    "ipv6": [],
                    "mtu": 1500,
                    "acl_in": None,
                    "acl_out": None,
                    "qos_in": None,
                    "qos_out": None,
                    "speed": "speed-1gb",
                    "duplex": "full-duplex",
                    "mgig_downshift": True,
                    "autoneg": True,
                    "storm": ["broadcast", "unknown-unicast"],
                },
                # Management port: no extended state at all -> None, not absence.
                "GigabitEthernet0/0": {
                    "admin": "if-state-up",
                    "oper": "if-oper-state-ready",
                    "ipv4": "10.255.0.5",
                    "mask": "255.255.255.0",
                    "vrf": "mgmt",
                    "ipv6": [],
                    "mtu": 1500,
                    "acl_in": None,
                    "acl_out": None,
                    "qos_in": None,
                    "qos_out": None,
                    "speed": "speed-1gb",
                    "duplex": "full-duplex",
                    "mgig_downshift": None,
                    "autoneg": True,
                    "storm": [],
                },
            },
        )

    def test_autoneg_is_a_config_fact_read_whatever_the_oper_state(self):
        # A hard-set port: autoneg False, negotiated values None (the model
        # defines them only under auto-negotiation) — not a fault. The leaf is
        # read down as well as up, and a string-ified boolean is tolerated;
        # junk is None.
        for oper, leaf, expected in (
            ("if-oper-state-ready", False, False),
            ("if-oper-state-no-pass", False, False),
            ("if-oper-state-ready", "false", False),
            ("if-oper-state-ready", "TRUE", True),
            ("if-oper-state-ready", "maybe", None),
        ):
            with self.subTest(oper=oper, leaf=leaf):
                entry = {
                    "name": "Te1/1/1",
                    "oper-status": oper,
                    "ether-state": {
                        "auto-negotiate": leaf,
                        "negotiated-port-speed": "speed-unknown",
                    },
                }
                view = checks._normalize_interfaces(_iface_payload(entry))["Te1/1/1"]
                self.assertIs(view["autoneg"], expected)
        entry = {"name": "Te1/1/1", "oper-status": "if-oper-state-ready", "ether-state": {}}
        self.assertIsNone(checks._normalize_interfaces(_iface_payload(entry))["Te1/1/1"]["autoneg"])

    def test_access_ports_keep_link_state_in_context_not_normalized(self):
        # The VLAN database names TwoGigabitEthernet1/0/12 as an assigned port:
        # its negotiated values move to context access_link and read None in
        # normalized; the uplink (absent from every ports list) keeps its own.
        access = checks._access_ports(_vlan_payload("TwoGigabitEthernet1/0/12"))
        self.assertEqual(access, {"TwoGigabitEthernet1/0/12"})
        normalized = checks._normalize_interfaces(self.payload, access)
        host = normalized["TwoGigabitEthernet1/0/12"]
        self.assertEqual(
            (host["speed"], host["duplex"], host["mgig_downshift"]), (None, None, None)
        )
        self.assertIs(host["autoneg"], True)  # a config fact stays keyed
        self.assertEqual(host["storm"], ["broadcast", "unknown-unicast"])
        uplink = normalized["TenGigabitEthernet1/0/1"]
        self.assertEqual((uplink["speed"], uplink["duplex"]), ("speed-10gb", "full-duplex"))
        context = checks._interfaces_context(self.payload, access)
        self.assertEqual(context["link_scope"], "trunks_and_routed")
        self.assertEqual(context["access_ports_listed"], 1)
        self.assertEqual(
            context["access_link"],
            {
                "TwoGigabitEthernet1/0/12": {
                    "speed": "speed-1gb",
                    "duplex": "full-duplex",
                    "mgig_downshift": True,
                }
            },
        )
        # No VLAN database (404): scope 'all', every value normalized, no access_link.
        self.assertIsNone(checks._access_ports(None))
        context = checks._interfaces_context(self.payload, None)
        self.assertEqual(context["link_scope"], "all")
        self.assertIsNone(context["access_ports_listed"])
        self.assertEqual(context["access_link"], {})
        self.assertEqual(
            checks._normalize_interfaces(self.payload, None)["TwoGigabitEthernet1/0/12"]["speed"],
            "speed-1gb",
        )
        # An empty VLAN database is served-but-lists-nothing: scope stays
        # trunks_and_routed with zero access ports.
        empty = checks._access_ports({"Cisco-IOS-XE-vlan-oper:vlans": {}})
        self.assertEqual(empty, set())
        self.assertEqual(checks._interfaces_context(self.payload, empty)["access_ports_listed"], 0)

    def test_sleeping_host_flip_lands_in_context_not_normalized(self):
        # An access port whose endpoint went to standby: link still up, the
        # negotiated rate fell to 10 Mb/s half duplex and the mGig downshift
        # cleared. Under the trunks_and_routed scope the check's own compare
        # passes and only context moved.
        asleep = _loader.fixture_json("iosxe_interfaces_oper.json")
        for entry in asleep["Cisco-IOS-XE-interfaces-oper:interfaces"]["interface"]:
            if entry["name"] == "TwoGigabitEthernet1/0/12":
                entry["ether-state"].update(
                    {"negotiated-port-speed": "speed-10mb", "negotiated-duplex-mode": "half-duplex"}
                )
                entry["intf-ext-state"]["mgig-downshift-enabled"] = False
        access = checks._access_ports(_vlan_payload("TwoGigabitEthernet1/0/12"))
        pre = checks._normalize_interfaces(self.payload, access)
        post = checks._normalize_interfaces(asleep, access)
        self.assertEqual(pre, post)
        compare = registry.CHECKS["iosxe_interfaces"].compare
        self.assertEqual(_loader.diffcore.diff_check(pre, post, compare)["result"], "pass")
        before = checks._interfaces_context(self.payload, access)["access_link"]
        after = checks._interfaces_context(asleep, access)["access_link"]
        self.assertEqual(
            after["TwoGigabitEthernet1/0/12"],
            {"speed": "speed-10mb", "duplex": "half-duplex", "mgig_downshift": False},
        )
        self.assertNotEqual(before, after)
        # The same flip under scope 'all' (no VLAN database) is three changed fields.
        diff = _loader.diffcore.diff_check(
            checks._normalize_interfaces(self.payload),
            checks._normalize_interfaces(asleep),
            compare,
        )
        self.assertEqual(diff["result"], "diffs")

    def test_speed_and_duplex_follow_oper_state(self):
        # The same negotiated leaves: emitted only while oper is ready.
        for oper, expected in (
            ("if-oper-state-ready", ("speed-1gb", "full-duplex")),
            ("if-oper-state-no-pass", (None, None)),
            ("if-oper-state-lower-layer-down", (None, None)),
            (None, (None, None)),
        ):
            with self.subTest(oper=oper):
                entry = {"name": "Gi1/0/1", "admin-status": "if-state-up", "ether-state": _ETHER_1G}
                if oper is not None:
                    entry["oper-status"] = oper
                view = checks._normalize_interfaces(_iface_payload(entry))["Gi1/0/1"]
                self.assertEqual((view["speed"], view["duplex"]), expected)

    def test_single_dict_shape_and_module_prefixes(self):
        # RESTCONF quirk: bare dicts for one-entry lists, and identityref-style
        # prefixes on enums; two policies in one direction join sorted.
        payload = {
            "Cisco-IOS-XE-interfaces-oper:interfaces": {
                "interface": {
                    "name": "Gi1/0/2",
                    "oper-status": "if-oper-state-ready",
                    "mtu": "1500",
                    "ipv6-addrs": "FE80::2",
                    "diffserv-info": [
                        {"direction": "qos-inbound", "policy-name": "B"},
                        {"direction": "qos-inbound", "policy-name": "A"},
                    ],
                    "storm-control": {"unicast": {"filter-state": "x:blocking"}},
                    "ether-state": {
                        "negotiated-port-speed": "Cisco-IOS-XE-interfaces-oper:speed-100mb",
                        "negotiated-duplex-mode": "half-duplex",
                    },
                    "intf-ext-state": {"mgig-downshift-enabled": "true"},
                }
            }
        }
        view = checks._normalize_interfaces(payload)["Gi1/0/2"]
        self.assertEqual(view["mtu"], 1500)
        self.assertEqual(view["ipv6"], ["fe80::2"])
        self.assertEqual(view["qos_in"], "A,B")
        self.assertEqual(view["storm"], ["unicast"])
        self.assertEqual((view["speed"], view["duplex"]), ("speed-100mb", "half-duplex"))
        # A non-boolean downshift leaf is not a value.
        self.assertIsNone(view["mgig_downshift"])
        self.assertEqual(view["admin"], None)

    def test_err_disable_leaves_never_normalized_here(self):
        # One event reported once: the err-disabled port carries no reason field.
        view = checks._normalize_interfaces(self.payload)["TenGigabitEthernet1/0/5"]
        self.assertFalse(set(view) & {"reason", "error_type", "error-type", "port-error-reason"})

    def test_context_counters_and_leaves_seen(self):
        self.assertEqual(
            checks._interfaces_context(self.payload),
            {
                "ports_total": 5,
                "ports_oper_up": 4,
                # Nonzero only, and only the three: discards and rates stay in raw.
                "counters": {
                    "TenGigabitEthernet1/0/1": {"crc": 3, "in_errors": 3, "flaps": 2},
                    "TwoGigabitEthernet1/0/12": {"flaps": 7},
                },
                "leaves_seen": {
                    "ether-state": True,
                    "intf-ext-state": True,
                    "storm-control": True,
                    "diffserv-info": True,
                    "statistics": True,
                    "ipv6-addrs": True,
                },
                "link_scope": "all",
                "access_ports_listed": None,
                "access_link": {},
            },
        )

    def test_context_on_a_six_leaf_reply(self):
        # A release that answers the old six-leaf shape: every widened
        # container reads unseen, no counters, and the normalized fields are
        # None / [] rather than absent.
        payload = _iface_payload(
            {"name": "Gi1/0/1", "description": "x", "vrf": "", "ipv4": "10.0.0.1", **_UP}
        )
        context = checks._interfaces_context(payload)
        self.assertEqual(context["counters"], {})
        self.assertEqual(set(context["leaves_seen"].values()), {False})
        self.assertEqual(
            checks._normalize_interfaces(payload)["Gi1/0/1"],
            {**_UNSET, "admin": "if-state-up", "oper": "if-oper-state-ready", "ipv4": "10.0.0.1"},
        )

    def test_raw_statistics_tuple_names_only_model_leaves(self):
        # Grouping intf-statistics (17.12.1) defines these 64-bit counters and
        # no in-octets-64 (in-octets is already uint64).
        self.assertNotIn("in-octets-64", checks._IFACE_STATS_LEAVES)
        for leaf in ("in-discards-64", "in-errors-64", "in-unknown-protos-64", "out-octets-64"):
            self.assertIn(leaf, checks._IFACE_STATS_LEAVES)
        self.assertEqual(len(checks._IFACE_STATS_LEAVES), len(set(checks._IFACE_STATS_LEAVES)))

    def test_raw_statistics_curated_and_capped(self):
        curated = checks._interface_statistics(self.payload)
        # GigabitEthernet0/0 serves no statistics: no row, not an empty one.
        self.assertEqual(
            sorted(curated),
            [
                "TenGigabitEthernet1/0/1",
                "TenGigabitEthernet1/0/5",
                "TwoGigabitEthernet1/0/12",
                "Vlan925",
            ],
        )
        self.assertEqual(curated["TenGigabitEthernet1/0/1"]["in-crc-errors"], 3)
        self.assertEqual(curated["TenGigabitEthernet1/0/1"]["num-flaps"], 2)
        self.assertEqual(curated["Vlan925"]["discontinuity-time"], "2026-07-11T03:12:44+00:00")
        # Unknown leaves are not copied.
        big = _iface_payload(
            *[
                {"name": "Gi1/0/%d" % (i,), "statistics": {"in-octets": i, "junk": 1}}
                for i in range(3)
            ]
        )
        self.assertNotIn("junk", checks._interface_statistics(big)["Gi1/0/1"])
        original = checks._IFACE_STATS_RAW_MAX
        checks._IFACE_STATS_RAW_MAX = 2
        try:
            self.assertEqual(len(checks._interface_statistics(big)), 2)
        finally:
            checks._IFACE_STATS_RAW_MAX = original
        stripped = checks._interfaces_without_statistics(self.payload)
        entries = stripped["Cisco-IOS-XE-interfaces-oper:interfaces"]["interface"]
        self.assertFalse(any("statistics" in e for e in entries))
        self.assertEqual(len(entries), 5)
        # The source payload is untouched.
        self.assertIn(
            "statistics", self.payload["Cisco-IOS-XE-interfaces-oper:interfaces"]["interface"][0]
        )

    def test_healthy_captures_normalize_identically(self):
        # Counters and storm rates drift between healthy captures; the
        # normalized view does not, and the check's own compare passes.
        drifted = _loader.fixture_json("iosxe_interfaces_oper.json")
        for entry in drifted["Cisco-IOS-XE-interfaces-oper:interfaces"]["interface"]:
            for leaf in entry.get("statistics", {}):
                if leaf != "discontinuity-time":
                    entry["statistics"][leaf] += 5
            for state in entry.get("storm-control", {}).values():
                if "current-rate" in state:
                    state["current-rate"]["pps"] += 100
        pre = checks._normalize_interfaces(self.payload)
        post = checks._normalize_interfaces(drifted)
        self.assertEqual(pre, post)
        compare = registry.CHECKS["iosxe_interfaces"].compare
        self.assertEqual(_loader.diffcore.diff_check(pre, post, compare)["result"], "pass")
        self.assertNotEqual(
            checks._interfaces_context(self.payload), checks._interfaces_context(drifted)
        )

    def test_collector_widened_get_is_the_shared_path(self):
        ctx = _IfaceCtx({checks._IFACE_PATH: self.payload})
        result = checks._collect_interfaces(ctx)
        # The VLAN database rides beside it, ok_404 and with the kwargs
        # iosxe_vlans uses, so the per-run cache serves both checks once.
        self.assertEqual(
            ctx.gets, [(checks._IFACE_PATH, {}), (checks._VLAN_PATH, _ACCESS_CTX_KWARGS)]
        )
        self.assertEqual(checks._VLAN_PATH, "/data/Cisco-IOS-XE-vlan-oper:vlans")
        self.assertEqual(result["context"]["fields_filter"], "accepted")
        self.assertEqual(result["context"]["link_scope"], "all")  # 404 here
        self.assertNotIn("note", result["raw"])
        self.assertEqual(sorted(result["raw"]), ["interfaces", "statistics"])
        self.assertEqual(result["normalized"]["Vlan925"]["qos_out"], "PM-EGRESS")
        # The filter names every widened leaf of the interface-state grouping.
        for leaf in (
            "ipv4-subnet-mask",
            "ipv6-addrs",
            "mtu",
            "input-security-acl",
            "output-security-acl",
            "diffserv-info(direction;policy-name)",
            "storm-control",
            "intf-ext-state-support",
            "intf-ext-state",
            "statistics",
            "negotiated-port-speed",
            "negotiated-duplex-mode",
        ):
            self.assertIn(leaf, checks._IFACE_PATH)
        self.assertNotIn(";speed;", checks._IFACE_PATH)
        self.assertIn("auto-negotiate", checks._IFACE_PATH)

    def test_collector_link_scope_follows_the_vlan_database(self):
        # Served: the listed access port's link state is context, the scope says so.
        ctx = _IfaceCtx(
            {
                checks._IFACE_PATH: self.payload,
                checks._VLAN_PATH: _vlan_payload("TwoGigabitEthernet1/0/12"),
            }
        )
        result = checks._collect_interfaces(ctx)
        self.assertEqual(result["context"]["link_scope"], "trunks_and_routed")
        self.assertIsNone(result["normalized"]["TwoGigabitEthernet1/0/12"]["speed"])
        self.assertEqual(
            result["context"]["access_link"]["TwoGigabitEthernet1/0/12"]["speed"], "speed-1gb"
        )
        self.assertNotIn("note", result["raw"])
        # A failed VLAN read is a note and scope 'all', never a failed check.
        ctx = _IfaceCtx(
            {checks._IFACE_PATH: self.payload},
            raise_for={checks._VLAN_PATH: _RestconfError("GET: HTTP 500", 500)},
        )
        result = checks._collect_interfaces(ctx)
        self.assertEqual(result["context"]["link_scope"], "all")
        self.assertEqual(result["context"]["fields_filter"], "accepted")
        self.assertIn("vlan-oper read failed", result["raw"]["note"])
        self.assertEqual(result["normalized"]["TwoGigabitEthernet1/0/12"]["speed"], "speed-1gb")

    def test_collector_celery_abort_on_the_vlan_read_is_never_a_note(self):
        class SoftTimeLimitExceeded(Exception):
            pass

        ctx = _IfaceCtx(
            {checks._IFACE_PATH: self.payload},
            raise_for={checks._VLAN_PATH: SoftTimeLimitExceeded()},
        )
        with self.assertRaises(SoftTimeLimitExceeded):
            checks._collect_interfaces(ctx)

    def test_collector_retries_unfiltered_once_on_http_400(self):
        rejection = _RestconfError("GET %s: HTTP 400" % (checks._IFACE_PATH,), status_code=400)
        ctx = _IfaceCtx(
            {checks._IFACE_BASE_PATH: self.payload}, raise_for={checks._IFACE_PATH: rejection}
        )
        result = checks._collect_interfaces(ctx)
        # The unfiltered reply is the whole model: it gets the big-GET budget.
        self.assertEqual(
            ctx.gets,
            [
                (checks._IFACE_PATH, {}),
                (checks._IFACE_BASE_PATH, {"timeout": _loader.constants.BIG_GET_TIMEOUT}),
                (checks._VLAN_PATH, _ACCESS_CTX_KWARGS),
            ],
        )
        self.assertIn("HTTP 400", result["raw"]["note"])
        self.assertEqual(result["context"]["fields_filter"], "rejected (HTTP 400); unfiltered read")
        self.assertEqual(result["normalized"], checks._normalize_interfaces(self.payload))

    def test_collector_other_errors_and_missing_container_fail(self):
        for status in (401, 500, None):
            with self.subTest(status=status):
                ctx = _IfaceCtx({}, raise_for={checks._IFACE_PATH: _RestconfError("x", status)})
                with self.assertRaises(_RestconfError):
                    checks._collect_interfaces(ctx)
                self.assertEqual(len(ctx.gets), 1)  # no retry
        with self.assertRaises(registry.CollectError):
            checks._collect_interfaces(_IfaceCtx({checks._IFACE_PATH: {"other": {}}}))


def _hardware_with(leaves):
    """The committed 9500 fixture with device-system-data leaves added or replaced.

    The fixture holds neither reboot leaf, although the model defines both.
    It was hand-built (it carries values outside the model), so that absence
    is no field evidence; the added values are YANG-shaped, not field-captured.
    """
    payload = _loader.fixture_json("iosxe_device_hardware.json")
    container = payload["Cisco-IOS-XE-device-hardware-oper:device-hardware-data"]
    container["device-hardware"]["device-system-data"].update(leaves)
    return payload


class _HealthCtx:
    """Fake CollectorContext: RESTCONF payload per path, every GET recorded with its kwargs."""

    def __init__(self, payloads):
        self.payloads = payloads
        self.gets = []

    def get(self, path, **kwargs):
        self.gets.append((path, kwargs))
        return self.payloads.get(path)


class TestPlatformHealthNormalizer(unittest.TestCase):
    NEITHER_SERVED = {
        "reboot_leaves_not_served": ["last-reboot-reason", "reason-severity"],
        "readings": {},
    }
    # Every served current-reading with its units, keyed like normalized; the
    # 'Not Present' supply slot serves no reading and so has no entry.
    READINGS = {
        "env|Switch 1 R0/Temp: Coretemp": {"reading": 43, "units": "celsius"},
        "env|Switch 1 R0/Temp: OutletTemp": {"reading": 51, "units": "celsius"},
        "env|Switch 1 P0/P0 Vout": {"reading": 12000, "units": "millivolts"},
        "env|Switch 1 P0/P0 Iin": {"reading": 1, "units": "amperes"},
    }

    def test_hardware_plus_environment(self):
        hardware = _loader.fixture_json("iosxe_device_hardware.json")
        env = _loader.fixture_json("iosxe_environment_sensors.json")
        normalized, _context = checks._normalize_platform_health(hardware, env)
        self.assertEqual(
            normalized,
            {
                "boot-time": {"value": "2026-07-11T03:12:44+00:00"},
                "alarm|1058|1": {"desc": "Te1/0/5: Link down"},
                "env|Switch 1 R0/Temp: Coretemp": {"state": "Normal"},
                "env|Switch 1 R0/Temp: OutletTemp": {"state": "Normal"},
                "env|Switch 1 P0/P0 Vout": {"state": "Normal"},
                "env|Switch 1 P0/P0 Iin": {"state": "Normal"},
                # A supply slot without input is a sensor state, visible here.
                "env|Switch 1 P1/P1 Vout": {"state": "Not Present"},
            },
        )
        self.assertEqual(_context["readings"], self.READINGS)

    def test_readings_are_context_never_normalized(self):
        hardware = _loader.fixture_json("iosxe_device_hardware.json")
        env = _loader.fixture_json("iosxe_environment_sensors.json")
        normalized, context = checks._normalize_platform_health(hardware, env)
        for facts in normalized.values():
            self.assertNotIn("reading", facts)
        self.assertEqual(set(context["readings"]) - set(normalized), set())
        # A string-ified reading is still a number; junk is no reading.
        sensors = env["Cisco-IOS-XE-environment-oper:environment-sensors"]["environment-sensor"]
        sensors[0]["current-reading"] = "44"
        sensors[1]["current-reading"] = "n/a"
        _normalized, context = checks._normalize_platform_health(hardware, env)
        self.assertEqual(context["readings"]["env|Switch 1 R0/Temp: Coretemp"]["reading"], 44)
        self.assertNotIn("env|Switch 1 R0/Temp: OutletTemp", context["readings"])

    def test_environment_payload_absent(self):
        hardware = _loader.fixture_json("iosxe_device_hardware.json")
        normalized, _context = checks._normalize_platform_health(hardware, None)
        self.assertEqual(
            normalized,
            {
                "boot-time": {"value": "2026-07-11T03:12:44+00:00"},
                "alarm|1058|1": {"desc": "Te1/0/5: Link down"},
            },
        )

    def test_last_reboot_both_leaves_served(self):
        # RESTCONF may pad strings; the served values are stripped, never reworded.
        hardware = _hardware_with(
            {"last-reboot-reason": " Reload Command ", "reason-severity": "normal"}
        )
        normalized, context = checks._normalize_platform_health(hardware, None)
        self.assertEqual(
            normalized,
            {
                "boot-time": {"value": "2026-07-11T03:12:44+00:00"},
                "last-reboot": {"reason": "Reload Command", "severity": "normal"},
                "alarm|1058|1": {"desc": "Te1/0/5: Link down"},
            },
        )
        self.assertEqual(context, {"reboot_leaves_not_served": [], "readings": {}})

    def test_last_reboot_one_leaf_served(self):
        # Only what the device served: no placeholder for the missing field.
        cases = (
            (
                {"last-reboot-reason": "Reload Command"},
                {"reason": "Reload Command"},
                "reason-severity",
            ),
            ({"reason-severity": "abnormal"}, {"severity": "abnormal"}, "last-reboot-reason"),
        )
        for leaves, expected, not_served in cases:
            with self.subTest(leaves=leaves):
                normalized, context = checks._normalize_platform_health(
                    _hardware_with(leaves), None
                )
                self.assertEqual(normalized["last-reboot"], expected)
                self.assertEqual(
                    context, {"reboot_leaves_not_served": [not_served], "readings": {}}
                )

    def test_last_reboot_neither_leaf_served(self):
        # The committed fixture as-is: no key, nothing fabricated, both leaves
        # named in context (boot-time was served, so it is not).
        hardware = _loader.fixture_json("iosxe_device_hardware.json")
        normalized, context = checks._normalize_platform_health(hardware, None)
        self.assertNotIn("last-reboot", normalized)
        self.assertEqual(context, self.NEITHER_SERVED)

    def test_device_system_data_absent_names_every_reload_leaf(self):
        hardware = {"Cisco-IOS-XE-device-hardware-oper:device-hardware-data": {}}
        for payload in (hardware, None):
            normalized, context = checks._normalize_platform_health(payload, None)
            self.assertEqual(normalized, {})
            self.assertEqual(
                context,
                {
                    "reboot_leaves_not_served": [
                        "boot-time",
                        "last-reboot-reason",
                        "reason-severity",
                    ],
                    "readings": {},
                },
            )

    def test_last_reboot_values_keep_one_type(self):
        # A normalized value never changes type between captures: a
        # non-conforming encoder sending the enum's integer still yields text,
        # and 0 (normal's enum value) is a served leaf, not an absent one.
        for value, text in ((0, "0"), (1, "1")):
            with self.subTest(value=value):
                normalized, context = checks._normalize_platform_health(
                    _hardware_with({"reason-severity": value}), None
                )
                self.assertEqual(normalized["last-reboot"], {"severity": text})
                self.assertEqual(
                    context, {"reboot_leaves_not_served": ["last-reboot-reason"], "readings": {}}
                )

    def test_blank_reason_is_served_not_absent(self):
        # A served-but-blank leaf is what the device said: kept as '', and
        # context never claims the device omitted it, empty or padded.
        for blank in ("", "  "):
            with self.subTest(reason=blank):
                normalized, context = checks._normalize_platform_health(
                    _hardware_with({"last-reboot-reason": blank, "reason-severity": "normal"}),
                    None,
                )
                self.assertEqual(normalized["last-reboot"], {"reason": "", "severity": "normal"})
                self.assertEqual(context, {"reboot_leaves_not_served": [], "readings": {}})

    def test_healthy_captures_normalize_identically(self):
        # Two healthy captures of an unchanged device: identical payloads, and
        # payloads apart only in volatile leaves (the device clock beside the
        # reboot leaves, every sensor reading), give one normalized view, one
        # context apart from the readings it keeps for the reader, and a
        # diffcore 'pass' under the check's own compare.
        leaves = {"last-reboot-reason": "Reload Command", "reason-severity": "normal"}
        env_fixture = "iosxe_environment_sensors.json"
        pre, pre_context = checks._normalize_platform_health(
            _hardware_with(leaves), _loader.fixture_json(env_fixture)
        )
        drifted_env = _loader.fixture_json(env_fixture)
        sensors = drifted_env["Cisco-IOS-XE-environment-oper:environment-sensors"]
        for sensor in sensors["environment-sensor"]:
            if "current-reading" in sensor:
                sensor["current-reading"] += 1
        drifted = _hardware_with({**leaves, "current-time": "2026-08-24T02:47:31+00:00"})
        compare = registry.CHECKS["iosxe_platform_health"].compare
        for name, hardware, env_payload, same_readings in (
            ("identical", _hardware_with(leaves), _loader.fixture_json(env_fixture), True),
            ("volatile drift", drifted, drifted_env, False),
        ):
            with self.subTest(name):
                post, post_context = checks._normalize_platform_health(hardware, env_payload)
                self.assertEqual(post, pre)
                self.assertEqual(
                    post_context["reboot_leaves_not_served"],
                    pre_context["reboot_leaves_not_served"],
                )
                self.assertEqual(post_context["readings"] == pre_context["readings"], same_readings)
                self.assertEqual(_loader.diffcore.diff_check(pre, post, compare)["result"], "pass")

    def test_changed_reason_diffs_under_the_checks_own_compare(self):
        # A reload between captures: boot-time moves, and last-reboot says why
        # field by field. The reason strings are synthetic, shaped like the
        # free text the model defines.
        compare = registry.CHECKS["iosxe_platform_health"].compare
        pre, _ = checks._normalize_platform_health(
            _hardware_with({"last-reboot-reason": "Reload Command", "reason-severity": "normal"}),
            None,
        )
        post, _ = checks._normalize_platform_health(
            _hardware_with(
                {
                    "boot-time": "2026-08-23T20:41:07+00:00",
                    "last-reboot-reason": "Critical software exception",
                    "reason-severity": "abnormal",
                }
            ),
            None,
        )
        diff = _loader.diffcore.diff_check(pre, post, compare)
        self.assertEqual(diff["result"], "diffs")
        self.assertEqual((diff["added"], diff["removed"]), ([], []))
        self.assertEqual(
            diff["changed"],
            [
                {
                    "key": "boot-time",
                    "field": "value",
                    "old": "2026-07-11T03:12:44+00:00",
                    "new": "2026-08-23T20:41:07+00:00",
                },
                {
                    "key": "last-reboot",
                    "field": "reason",
                    "old": "Reload Command",
                    "new": "Critical software exception",
                },
                {"key": "last-reboot", "field": "severity", "old": "normal", "new": "abnormal"},
            ],
        )

    def test_collector_reads_the_reboot_leaves_from_the_existing_get(self):
        hardware = _hardware_with(
            {"last-reboot-reason": "Reload Command", "reason-severity": "normal"}
        )
        env = _loader.fixture_json("iosxe_environment_sensors.json")
        ctx = _HealthCtx({checks._HW_PATH: hardware, checks._ENV_PATH: env})
        result = checks._collect_platform_health(ctx)
        self.assertEqual(
            result["normalized"]["last-reboot"], {"reason": "Reload Command", "severity": "normal"}
        )
        self.assertEqual(
            result["context"], {"reboot_leaves_not_served": [], "readings": self.READINGS}
        )
        self.assertEqual(result["raw"], {"device-hardware": hardware, "environment-sensors": env})
        # No request of its own: the same two GETs as before the reboot leaves.
        self.assertEqual(ctx.gets, [(checks._HW_PATH, {}), (checks._ENV_PATH, {"ok_404": True})])

    def test_collector_records_unserved_leaves_without_failing(self):
        hardware = _loader.fixture_json("iosxe_device_hardware.json")
        ctx = _HealthCtx({checks._HW_PATH: hardware})  # environment-sensors 404s
        result = checks._collect_platform_health(ctx)
        self.assertNotIn("last-reboot", result["normalized"])
        self.assertEqual(result["context"], self.NEITHER_SERVED)
        self.assertIn("environment-sensors path absent", result["raw"]["note"])


class TestSyslogErrorParser(unittest.TestCase):
    def test_counts_severity_three_and_worse_only(self):
        text = _loader.fixture_text("iosxe_show_logging.txt")
        # %SYS-5-CONFIG_I and %LINEPROTO-5-UPDOWN are sev 5: never counted.
        self.assertEqual(
            checks._parse_syslog_errors(text),
            {
                "sev3|%LINK-3-UPDOWN": {"count": 2},
                "sev3|%OSPF-3-DBEXIST": {"count": 1},
            },
        )

    def test_empty(self):
        self.assertEqual(checks._parse_syslog_errors(""), {})
        self.assertEqual(checks._parse_syslog_errors(None), {})


class TestSvlNormalizer(unittest.TestCase):
    PAYLOAD = {
        "Cisco-IOS-XE-switch-cp-svl-oper:switch-cp-svl-oper-data": {
            "location": [
                {
                    "fru": "fru-rp",
                    "slot": 0,
                    "bay": 0,
                    "chassis": 1,
                    "node": 0,
                    "svl-link-info": [
                        {
                            "link-num": 1,
                            "svl-link-member-port": [
                                {
                                    "port-name": "FortyGigabitEthernet1/1/1",
                                    "bundled": "true",
                                    "is-control-port": True,
                                    "lmp-tx": 120,
                                    "lmp-rx": 118,
                                },
                                {
                                    "port-name": "FortyGigabitEthernet1/1/2",
                                    "bundled": "true",
                                    "is-control-port": False,
                                    # RESTCONF may string-ify numbers.
                                    "lmp-tx": "88",
                                    "lmp-rx": 91,
                                },
                            ],
                        }
                    ],
                },
                {
                    "fru": "fru-rp",
                    "slot": 0,
                    "bay": 0,
                    "chassis": 2,
                    "node": 0,
                    # Bare-dict shape for both the link and its member port.
                    "svl-link-info": {
                        "link-num": 1,
                        "svl-link-member-port": {
                            "port-name": "FortyGigabitEthernet2/1/1",
                            "bundled": "false",
                            "sdp-tx": 5,
                        },
                    },
                },
            ]
        }
    }

    def test_membership_bundled_and_counters(self):
        normalized, context = checks._normalize_svl(self.PAYLOAD)
        self.assertEqual(
            normalized,
            {
                "svl-link|1/1": {
                    "member_ports": [
                        "FortyGigabitEthernet1/1/1",
                        "FortyGigabitEthernet1/1/2",
                    ],
                    "bundled": True,
                },
                "svl-link|2/1": {
                    "member_ports": ["FortyGigabitEthernet2/1/1"],
                    "bundled": False,
                },
            },
        )
        # Numeric leaves sum per link; identity/flag leaves are not counters.
        self.assertEqual(
            context,
            {
                "counters|1/1": {"lmp-tx": 208, "lmp-rx": 209},
                "counters|2/1": {"sdp-tx": 5},
            },
        )

    def test_locations_without_recognizable_link_fields(self):
        # A drifted release spelling the link identity differently: the walk
        # found locations but recognized nothing — empty view, not garbage.
        payload = {
            "switch-cp-svl-oper-data": {
                "location": [{"chassis": 1, "svl-link-info": [{"weird-num": 9}]}]
            }
        }
        self.assertEqual(checks._normalize_svl(payload), ({}, {}))

    def test_empty(self):
        self.assertEqual(checks._normalize_svl({}), ({}, {}))
        self.assertEqual(checks._normalize_svl(None), ({}, {}))


class TestNtpNormalizer(unittest.TestCase):
    def test_status_leaves(self):
        payload = {
            "Cisco-IOS-XE-ntp-oper:ntp-oper-data": {
                "ntp-status-info": {
                    "sys-status": "clock is synchronized",
                    # RESTCONF may string-ify numbers.
                    "sys-stratum": "3",
                    "sys-refid": "203.0.113.10",
                    # Jitter leaves must never leak into normalized.
                    "sys-offset": 0.42,
                    "sys-root-dispersion": 12.1,
                }
            }
        }
        self.assertEqual(
            checks._normalize_ntp(payload),
            {
                "synchronized": "clock is synchronized",
                "stratum": 3,
                "server": "203.0.113.10",
            },
        )

    def test_server_falls_back_to_selected_association(self):
        payload = {
            "ntp-oper-data": {
                "ntp-status-info": {
                    "ntp-associations": [
                        {"assoc-id": 1, "status": "candidate", "refid": "10.0.0.9"},
                        {"assoc-id": 2, "status": "sys-peer", "refid": "203.0.113.10"},
                    ]
                }
            }
        }
        self.assertEqual(checks._normalize_ntp(payload), {"server": "203.0.113.10"})

    def test_missing_leaves_emit_nothing(self):
        self.assertEqual(checks._normalize_ntp({}), {})
        self.assertEqual(checks._normalize_ntp({"Cisco-IOS-XE-ntp-oper:ntp-oper-data": {}}), {})


class TestRegistrations(unittest.TestCase):
    EXPECTED_IDS = {
        "iosxe_routes_rib",
        "iosxe_route_rollups",
        "iosxe_routes_fib",
        "iosxe_bgp_peers",
        "iosxe_ospf_neighbors",
        "iosxe_arp",
        "iosxe_neighbors",
        "iosxe_interfaces",
        "iosxe_platform_health",
        "iosxe_dhcp",
        "iosxe_syslog_errors",
        "iosxe_svl_health",
        "iosxe_ntp",
        "iosxe_routing_config",
        "iosxe_config",
        "iosxe_optics",
        "iosxe_crash_files",
        "iosxe_errdisable",
        "iosxe_port_channels",
        "iosxe_switch_stack",
        "iosxe_inventory",
    }

    # Other catalog modules (checks_iosxe_wireless) register under platform
    # "iosxe" too, so these assertions scope to the checks THIS module owns.
    def test_all_registered_once(self):
        registered = {
            check_id
            for check_id, check in registry.CHECKS.items()
            if check.platform == "iosxe" and check.collector.__module__ == checks.__name__
        }
        self.assertEqual(registered, self.EXPECTED_IDS)

    def test_checks_for_filters_by_platform(self):
        ids = {
            check.id
            for check in registry.checks_for("iosxe")
            if check.collector.__module__ == checks.__name__
        }
        self.assertEqual(ids, self.EXPECTED_IDS)

    def test_every_check_has_collector_and_valid_mode(self):
        diffcore = _loader.diffcore
        for check in registry.CHECKS.values():
            if check.platform != "iosxe":
                continue
            self.assertTrue(callable(check.collector), check.id)
            self.assertIn(check.compare.get("mode", "equality_set"), diffcore.MODES, check.id)


class TestRoutingConfig(unittest.TestCase):
    def test_scrub_masks_credential_keys_recursively(self):
        node = {
            "router": {
                "bgp": [
                    {
                        "id": 65000,
                        "neighbor": [{"id": "203.0.113.9", "password": {"text": "hunter2"}}],
                    }
                ],
                "ospf": {"authentication-key": "k3y", "area": [{"id": 0}]},
            }
        }
        scrubbed = checks._scrub_secrets(node)
        self.assertEqual(scrubbed["router"]["bgp"][0]["neighbor"][0]["password"], "***scrubbed***")
        self.assertEqual(scrubbed["router"]["ospf"]["authentication-key"], "***scrubbed***")
        self.assertEqual(scrubbed["router"]["ospf"]["area"], [{"id": 0}])

    def test_collector_sections_and_skip(self):
        class _Ctx:
            def __init__(self, payloads):
                self.payloads = payloads

            def get(self, path, **kwargs):
                return self.payloads.get(path)

        payloads = {
            "/data/Cisco-IOS-XE-native:native/ip/route": {
                "Cisco-IOS-XE-native:route": {"ip-route-interface-forwarding-list": []}
            }
        }
        result = checks._collect_routing_config(_Ctx(payloads))
        self.assertIn("ip-route", result["normalized"])
        self.assertNotIn("router", result["normalized"])
        with self.assertRaises(checks.SkipCheck):
            checks._collect_routing_config(_Ctx({}))


class TestOpticsAndCrashFiles(unittest.TestCase):
    def test_optics_table_parse(self):
        output = (
            "           Temperature  Voltage  Current   Tx Power  Rx Power\n"
            "Port       (Celsius)    (Volts)  (mA)      (dBm)     (dBm)\n"
            "---------  -----------  -------  --------  --------  --------\n"
            "Te1/0/1      31.9       3.28      6.1       -2.5      -3.1\n"
            "Te1/0/2      30.0       3.28      0.0       N/A       -30.0\n"
        )
        normalized = checks._parse_optics_table(output)
        self.assertEqual(normalized["Te1/0/1"], {"tx_dbm": -2.5, "rx_dbm": -3.1})
        self.assertEqual(normalized["Te1/0/2"], {"rx_dbm": -30.0})

    def test_optics_detail_sections_and_alarm_flags(self):
        # Field-verified format: separate per-metric tables; violation
        # markers beside out-of-range values become *_flag entries. A
        # negative THRESHOLD after the value must never read as a marker.
        output = (
            "                          High Alarm  High Warn  Low Warn   Low Alarm\n"
            "     Temperature          Threshold   Threshold  Threshold  Threshold\n"
            "Port (Celsius)            (Celsius)   (Celsius)  (Celsius)  (Celsius)\n"
            "---- -------------------- ----------  ---------  ---------  ---------\n"
            "Te1/1/1   28.5               75.0        70.0        0.0       -5.0\n"
            "\n"
            "     Optical              High Alarm  High Warn  Low Warn   Low Alarm\n"
            "     Transmit Power       Threshold   Threshold  Threshold  Threshold\n"
            "Port (dBm)                (dBm)       (dBm)      (dBm)      (dBm)\n"
            "---- -------------------- ----------  ---------  ---------  ---------\n"
            "Te1/1/1   -2.1                1.6         0.6       -8.2      -9.2\n"
            "\n"
            "     Optical              High Alarm  High Warn  Low Warn   Low Alarm\n"
            "     Receive Power        Threshold   Threshold  Threshold  Threshold\n"
            "Port (dBm)                (dBm)       (dBm)      (dBm)      (dBm)\n"
            "---- -------------------- ----------  ---------  ---------  ---------\n"
            "Te1/1/1   -3.4                2.4         1.4      -13.2     -15.2\n"
            "Te1/1/2  -30.1 --             2.4         1.4      -13.2     -15.2\n"
        )
        normalized = checks._parse_optics_detail(output)
        self.assertEqual(normalized["Te1/1/1"], {"tx_dbm": -2.1, "rx_dbm": -3.4})
        self.assertEqual(normalized["Te1/1/2"], {"rx_dbm": -30.1, "rx_flag": "--"})

    def test_optics_collector_falls_back_and_skips(self):
        class _Ctx:
            has_ssh = True

            def __init__(self, outputs):
                self.outputs = outputs
                self.commands = []

            def run_ssh(self, command, **kwargs):
                self.commands.append(command)
                return self.outputs[command]

        rejected = "% Invalid input detected at marker"
        table = (
            "Port       (Celsius)    (Volts)  (mA)      (dBm)     (dBm)\n"
            "Te1/0/1      31.9       3.28      6.1       -2.5      -3.1\n"
        )
        ctx = _Ctx(
            {
                "show interfaces transceiver detail": rejected,
                "show interfaces transceiver": table,
            }
        )
        result = checks._collect_optics(ctx)
        self.assertEqual(result["normalized"]["Te1/0/1"], {"tx_dbm": -2.5, "rx_dbm": -3.1})
        both = _Ctx(
            {
                "show interfaces transceiver detail": rejected,
                "show interfaces transceiver": rejected,
            }
        )
        with self.assertRaises(checks.SkipCheck):
            checks._collect_optics(both)

    def test_crash_dir_recency_window(self):
        from datetime import datetime, timezone

        now = datetime(2026, 8, 24, tzinfo=timezone.utc)
        output = (
            "Directory of crashinfo:/\n"
            "  14  -rw-  1234567   Aug 22 2026 18:22:11 +00:00  "
            "system-report_1_20260822.tar.gz\n"
            "  15  -rw-  7654321   Jan 02 2024 03:00:00 +00:00  crashinfo_old.txt\n"
        )
        recent, older = checks._parse_crash_dir(output, now, 7)
        self.assertEqual(list(recent), ["system-report_1_20260822.tar.gz"])
        self.assertEqual(recent["system-report_1_20260822.tar.gz"]["modified"], "2026-08-22")
        self.assertEqual(older, 1)

    def test_crash_dir_skips_directories(self):
        # Field finding (9300 stack): crashinfo:tracelogs is a directory that
        # routine logging rewrites daily, so it read as a same-day "crash" on
        # every member. Directories are neither keyed nor counted as older.
        from datetime import datetime, timezone

        now = datetime(2026, 9, 24, tzinfo=timezone.utc)
        output = (
            "Directory of crashinfo:/\n"
            "30177  drwx             4096  Sep 24 2026 22:40:12 +00:00  tracelogs\n"
            "   11  drwx             4096  Jan 02 2024 03:00:00 +00:00  core\n"
            "   13  drwx             4096  Mar 03 2025 09:00:00 +00:00  old_subdir\n"
            "   12  -rw-                0  Nov 01 2019 10:00:00 +00:00  koops.dat\n"
            "   14  -rw-          1234567  Sep 23 2026 18:22:11 +00:00  "
            "system-report_1_20260923.tar.gz\n"
        )
        recent, older = checks._parse_crash_dir(output, now, 7)
        self.assertEqual(recent, {"system-report_1_20260923.tar.gz": {"modified": "2026-09-23"}})
        self.assertEqual(older, 1)  # koops.dat only; old_subdir is a directory

    def test_crash_files_healthy_stack_with_tracelogs_everywhere_is_empty(self):
        # The field scenario end to end (the 4-member 9300 in the field): every
        # member's filesystem holds a freshly written tracelogs/ and
        # license_evlog/ directory plus a zero-byte koops.dat from 2019, which
        # is the healthy state. crashinfo-1: on the active answers with the
        # alias's own "Directory of crashinfo:/" header.
        from datetime import datetime, timezone

        now = datetime(2026, 9, 25, tzinfo=timezone.utc)

        def listing(header):
            return (
                "Directory of %s/\n\n"
                "70993  drwx            16384  Sep 24 2026 23:28:44 -04:00  tracelogs\n"
                "78881  drwx             4096  Oct 15 2025 22:01:40 -04:00  license_evlog\n"
                "   11  -rw-                0  Jul 31 2019 00:59:17 -04:00  koops.dat\n"
                "\n1651314688 bytes total (1517166592 bytes free)" % (header,)
            )

        ctx = _StackCtx(
            {
                "show switch detail": _loader.fixture_text("iosxe_show_switch_detail.txt"),
                "dir crashinfo-1:": listing("crashinfo:"),
                "dir crashinfo-2:": listing("crashinfo-2:"),
                "dir crashinfo-3:": listing("crashinfo-3:"),
                "dir crashinfo-4:": listing("crashinfo-4:"),
            }
        )
        result = checks._collect_crash_files(ctx, now=now)
        self.assertEqual(result["normalized"], {})
        self.assertEqual(
            result["context"]["filesystems_listed"],
            ["crashinfo-1:", "crashinfo-2:", "crashinfo-3:", "crashinfo-4:"],
        )
        self.assertEqual(result["context"]["older_files_ignored"], 4)

    def test_crash_files_stack_lists_every_member_by_number(self):
        # Every member, the active and standby included, is listed on its own
        # crashinfo-<N>: and keyed member<N>; the role aliases are never asked
        # when the numbered filesystems answer. An old dump is counted, never
        # keyed.
        from datetime import datetime, timezone

        now = datetime(2026, 8, 24, tzinfo=timezone.utc)
        ctx = _StackCtx(
            {
                "show switch detail": _loader.fixture_text("iosxe_show_switch_detail.txt"),
                "dir crashinfo-1:": _dir_listing(
                    "crashinfo:", ("system-report_1_20260822.tar.gz", "Aug 22 2026")
                ),
                "dir crashinfo-2:": _dir_listing("crashinfo-2:"),
                "dir crashinfo-3:": _dir_listing(
                    "crashinfo-3:",
                    ("system-report_3_20260823.tar.gz", "Aug 23 2026"),
                    ("crashinfo_RP_00_00_20240102-030000-UTC.txt", "Jan 02 2024"),
                ),
                "dir crashinfo-4:": _dir_listing("crashinfo-4:"),
            }
        )
        result = checks._collect_crash_files(ctx, now=now)
        self.assertEqual(
            ctx.commands,
            [
                "show switch detail",
                "dir crashinfo-1:",
                "dir crashinfo-2:",
                "dir crashinfo-3:",
                "dir crashinfo-4:",
            ],
        )
        self.assertEqual(
            result["normalized"],
            {
                "member1|system-report_1_20260822.tar.gz": {"modified": "2026-08-22"},
                "member3|system-report_3_20260823.tar.gz": {"modified": "2026-08-23"},
            },
        )
        self.assertEqual(
            result["context"],
            {
                "older_files_ignored": 1,
                "recent_window_days": 7,
                "filesystems_listed": [
                    "crashinfo-1:",
                    "crashinfo-2:",
                    "crashinfo-3:",
                    "crashinfo-4:",
                ],
                "active_member": 1,
                "standby_member": 2,
                # No payload canned for the supplement: the fake answers None,
                # which is how the context reads an ok_404 miss.
                "q_filesystem": {"status": "not served (404)"},
            },
        )
        self.assertIn("show switch detail", result["raw"])
        self.assertIsNone(result["raw"]["q-filesystem"])
        self.assertNotIn("note", result["raw"])

    def test_crash_files_keys_survive_a_switchover(self):
        # The same old-but-recent file on member 1, captured before and after
        # a switchover that made member 2 active: the key must not move.
        from datetime import datetime, timezone

        now = datetime(2026, 8, 24, tzinfo=timezone.utc)
        before = _loader.fixture_text("iosxe_show_switch_detail.txt")
        after = before.replace("*1       Active ", "*1       Standby").replace(
            " 2       Standby", " 2       Active "
        )
        views = []
        for detail in (before, after):
            ctx = _StackCtx(
                {
                    "show switch detail": detail,
                    "dir crashinfo-1:": _dir_listing(
                        "crashinfo:", ("system-report_1_20260822.tar.gz", "Aug 22 2026")
                    ),
                    "dir crashinfo-2:": _dir_listing("crashinfo-2:"),
                    "dir crashinfo-3:": _dir_listing("crashinfo-3:"),
                    "dir crashinfo-4:": _dir_listing("crashinfo-4:"),
                }
            )
            views.append(checks._collect_crash_files(ctx, now=now))
        self.assertEqual(views[0]["normalized"], views[1]["normalized"])
        self.assertEqual(views[1]["context"]["active_member"], 2)
        self.assertEqual(views[1]["context"]["standby_member"], 1)

    def test_crash_files_numbered_failure_falls_back_to_the_role_alias(self):
        # crashinfo-1: and crashinfo-2: do not answer, so the active and standby
        # fall back to crashinfo: / stby-crashinfo: — still keyed by member
        # number. A provisioned member's filesystem does not exist and is
        # recorded in raw plus context, never a failure.
        from datetime import datetime, timezone

        now = datetime(2026, 8, 24, tzinfo=timezone.utc)
        detail = (
            "Switch/Stack Mac Address : 00a1.b2c3.0100 - Local Mac Address\n"
            "Switch#   Role    Mac Address     Priority Version  State \n"
            "*1       Active   00a1.b2c3.0100     15     V02     Ready\n"
            " 2       Standby  00a1.b2c3.0200     14     V02     Ready\n"
            " 3       Member   00a1.b2c3.0300     1      V02     Ready\n"
            " 4       Member   0000.0000.0000     1              Provisioned\n"
        )
        missing = "%%Error opening %s/ (No such device)"
        ctx = _StackCtx(
            {
                "show switch detail": detail,
                "dir crashinfo-1:": missing % ("crashinfo-1:",),
                "dir crashinfo:": _dir_listing("crashinfo:"),
                "dir crashinfo-2:": missing % ("crashinfo-2:",),
                "dir stby-crashinfo:": _dir_listing(
                    "stby-crashinfo:", ("system-report_2_20260823.tar.gz", "Aug 23 2026")
                ),
                "dir crashinfo-3:": _dir_listing("crashinfo-3:"),
                "dir crashinfo-4:": missing % ("crashinfo-4:",),
            }
        )
        result = checks._collect_crash_files(ctx, now=now)
        self.assertEqual(
            ctx.commands,
            [
                "show switch detail",
                "dir crashinfo-1:",
                "dir crashinfo:",
                "dir crashinfo-2:",
                "dir stby-crashinfo:",
                "dir crashinfo-3:",
                "dir crashinfo-4:",
            ],
        )
        self.assertEqual(
            result["normalized"],
            {"member2|system-report_2_20260823.tar.gz": {"modified": "2026-08-23"}},
        )
        self.assertEqual(
            result["context"]["filesystems_listed"],
            ["crashinfo:", "stby-crashinfo:", "crashinfo-3:"],
        )
        self.assertEqual(result["context"]["members_not_listed"], [4])
        self.assertEqual(result["context"]["standby_member"], 2)

    def test_dir_listed_keys_on_the_listing_header(self):
        # The open-error spelling carries the word "directory"; it once passed
        # for a listing. A real listing may hold a file named like an error.
        self.assertFalse(
            checks._dir_listed("%Error opening crashinfo-1:/ (No such file or directory)")
        )
        self.assertFalse(checks._dir_listed("%Error opening crashinfo-4:/ (No such device)"))
        self.assertFalse(checks._dir_listed("% Invalid input detected at '^' marker."))
        self.assertFalse(checks._dir_listed(""))
        self.assertFalse(checks._dir_listed(None))
        self.assertTrue(checks._dir_listed(_dir_listing("crashinfo-3:")))
        self.assertTrue(
            checks._dir_listed(_dir_listing("crashinfo:", ("error_report.txt", "Aug 22 2026")))
        )

    def test_crash_files_no_such_file_or_directory_falls_back_to_the_alias(self):
        from datetime import datetime, timezone

        now = datetime(2026, 8, 24, tzinfo=timezone.utc)
        ctx = _StackCtx(
            {
                "show switch detail": _loader.fixture_text("iosxe_show_switch_detail.txt"),
                "dir crashinfo-1:": "%Error opening crashinfo-1:/ (No such file or directory)",
                "dir crashinfo:": _dir_listing(
                    "crashinfo:", ("system-report_1_20260822.tar.gz", "Aug 22 2026")
                ),
                "dir crashinfo-2:": _dir_listing("crashinfo-2:"),
                "dir crashinfo-3:": _dir_listing("crashinfo-3:"),
                "dir crashinfo-4:": _dir_listing("crashinfo-4:"),
            }
        )
        result = checks._collect_crash_files(ctx, now=now)
        self.assertEqual(ctx.commands[1:3], ["dir crashinfo-1:", "dir crashinfo:"])
        self.assertEqual(list(result["normalized"]), ["member1|system-report_1_20260822.tar.gz"])
        self.assertEqual(result["context"]["filesystems_listed"][0], "crashinfo:")
        self.assertNotIn("members_not_listed", result["context"])

    def test_crash_files_non_stack_platform_lists_only_the_aliases(self):
        from datetime import datetime, timezone

        now = datetime(2026, 8, 24, tzinfo=timezone.utc)
        ctx = _StackCtx(
            {
                "show switch detail": "% Invalid input detected at '^' marker.",
                "dir crashinfo:": _dir_listing(
                    "crashinfo:", ("system-report_1_20260822.tar.gz", "Aug 22 2026")
                ),
                "dir stby-crashinfo:": _dir_listing("stby-crashinfo:"),
            }
        )
        result = checks._collect_crash_files(ctx, now=now)
        self.assertEqual(
            ctx.commands, ["show switch detail", "dir crashinfo:", "dir stby-crashinfo:"]
        )
        self.assertEqual(list(result["normalized"]), ["active|system-report_1_20260822.tar.gz"])
        self.assertEqual(result["context"]["filesystems_listed"], ["crashinfo:", "stby-crashinfo:"])
        self.assertNotIn("active_member", result["context"])
        self.assertNotIn("members_not_listed", result["context"])

    def test_crash_files_ignore_removals(self):
        # A file that ages out of the recency window between captures reads
        # as REMOVED; only an ADDED file means a crash, so removals never diff.
        diffcore = _loader.diffcore
        compare = registry.CHECKS["iosxe_crash_files"].compare
        aged = {"member1|system-report_1_20260818.tar.gz": {"modified": "2026-08-18"}}
        diff = diffcore.diff_check(aged, {}, compare)
        self.assertEqual(diff["result"], "pass")
        self.assertEqual(diff["removed"], [])
        self.assertEqual(len(diff["removed_ignored"]), 1)
        fresh = {"member3|system-report_3_20260825.tar.gz": {"modified": "2026-08-25"}}
        self.assertEqual(diffcore.diff_check(aged, fresh, compare)["result"], "diffs")

    def test_crash_files_nothing_listable_is_not_present(self):
        ctx = _StackCtx(
            {
                "dir crashinfo:": "% Invalid input detected at '^' marker.",
                "dir stby-crashinfo:": "% Invalid input detected at '^' marker.",
                "show switch detail": "% Invalid input detected at '^' marker.",
            }
        )
        with self.assertRaises(checks.SkipCheck):
            checks._collect_crash_files(ctx)
        # The dir listings alone decide presence: the q-filesystem supplement
        # is never read for a check that is not present.
        self.assertEqual(ctx.paths, [])

    def test_crash_dir_dates_are_utc_from_the_listing_offset(self):
        # Field format (4-member 9300): `dir` prints the device's local time
        # with its offset, -04:00. 22:15 local is 02:15 UTC the next day, and
        # the window is cut on UTC dates, so a file whose printed local date
        # is just outside the 7-day window can be inside it. A line printed
        # without an offset keeps its printed date, and its name is never
        # split.
        from datetime import datetime, timezone

        now = datetime(2026, 8, 24, tzinfo=timezone.utc)
        output = (
            "Directory of crashinfo-2:/\n\n"
            "70993  drwx    16384  Aug 23 2026 23:28:44 -04:00  tracelogs\n"
            "   14  -rw-  1234567  Aug 22 2026 22:15:03 -04:00  "
            "system-report_2_20260823-021503-UTC.tar.gz\n"
            "   15  -rw-     2048  Aug 16 2026 21:30:00 -04:00  crashinfo_RP_00_00_20260817\n"
            "   16  -rw-     2048  Aug 16 2026 19:59:59 -04:00  crashinfo_RP_00_00_20260816\n"
            "   11  -rw-        0  Jul 31 2019 00:59:17 -04:00  koops.dat\n"
            "   17  -rw-      512  Aug 23 2026 10:00:00  printed_without_offset.txt\n"
            "\n1651314688 bytes total (1517166592 bytes free)"
        )
        recent, older = checks._parse_crash_dir(output, now, 7)
        self.assertEqual(
            recent,
            {
                "system-report_2_20260823-021503-UTC.tar.gz": {"modified": "2026-08-23"},
                "crashinfo_RP_00_00_20260817": {"modified": "2026-08-17"},
                "printed_without_offset.txt": {"modified": "2026-08-23"},
            },
        )
        self.assertEqual(older, 2)  # the 19:59:59 local file (UTC Aug 16) and koops.dat


class TestCrashFilesQFilesystem(unittest.TestCase):
    """iosxe_crash_files' q-filesystem supplement, and the shakedown's summary of it.

    Both q-filesystem fixtures are SYNTHETIC, shaped per the 17.9.1 YANG
    (Cisco-IOS-XE-platform-software-oper, revision 2022-07-01), and NOT field
    captures: iosxe_q_filesystem_model_shape.json is the check's narrowed read
    and iosxe_q_filesystem_full_model_shape.json the shakedown's full list
    read. Which locations, partitions and core files a 9300 really reports is
    what the next shakedown settles; sanitized captures replace them then.
    """

    REPORT = "system-report_1_20260823-021503-UTC.tar.gz"
    REPORT_KEY = "member1|" + REPORT
    CORE_KEY = "member3|linux_iosd-imag_3_RP_0_4242_20260823-101010-UTC.core.gz"

    @staticmethod
    def _now():
        from datetime import datetime, timezone

        return datetime(2026, 8, 24, tzinfo=timezone.utc)

    @classmethod
    def _member1_listing(cls):
        # crashinfo-1: on the active answers with the alias's own header, and
        # prints local time: 22:15:03 at -04:00 is 02:15:03 UTC on Aug 23.
        return (
            "Directory of crashinfo:/\n\n"
            "70993  drwx    16384  Aug 23 2026 21:04:12 -04:00  tracelogs\n"
            "   14  -rw-  1234567  Aug 22 2026 22:15:03 -04:00  %s\n"
            "\n1651314688 bytes total (1517166592 bytes free)" % (cls.REPORT,)
        )

    @classmethod
    def _stack_ctx(cls, detail=None, member1=None, payloads=None, raise_for=None, ctx_class=None):
        if detail is None:
            detail = _loader.fixture_text("iosxe_show_switch_detail.txt")
        outputs = {
            "show switch detail": detail,
            "dir crashinfo-1:": cls._member1_listing() if member1 is None else member1,
            "dir crashinfo:": _dir_listing("crashinfo:"),
            "dir crashinfo-2:": _dir_listing("crashinfo-2:"),
            "dir crashinfo-3:": _dir_listing("crashinfo-3:"),
            "dir crashinfo-4:": _dir_listing("crashinfo-4:"),
        }
        return (ctx_class or _StackCtx)(outputs, payloads=payloads, raise_for=raise_for)

    @staticmethod
    def _one_location(chassis, *core_files):
        return {
            "Cisco-IOS-XE-platform-software-oper:cisco-platform-software": {
                "q-filesystem": [
                    {
                        "fru": "fru-rp",
                        "slot": 0,
                        "bay": 0,
                        "chassis": chassis,
                        "partitions": [{"name": "bootflash:"}],
                        "core-files": list(core_files),
                    }
                ]
            }
        }

    def test_core_files_merge_with_dir_keys_and_shared_files_collapse(self):
        """Model-shaped fixture, NOT a field capture: chassis N read as switch N.

        The chassis-1 system report is also on member 1's dir listing, so the
        two sources collapse into one key with one value; member 3's core sits
        in core/, which the dir listing never descends into, so only the model
        keys it. Old cores (chassis 1 and 4) are counted, never keyed.
        """
        payload = _loader.fixture_json("iosxe_q_filesystem_model_shape.json")
        ctx = self._stack_ctx(payloads={checks._Q_FS_PATH: payload})
        result = checks._collect_crash_files(ctx, now=self._now())
        self.assertEqual(ctx.paths, [checks._Q_FS_PATH])
        self.assertEqual(
            ctx.commands,
            [
                "show switch detail",
                "dir crashinfo-1:",
                "dir crashinfo-2:",
                "dir crashinfo-3:",
                "dir crashinfo-4:",
            ],
        )
        self.assertEqual(
            result["normalized"],
            {
                self.REPORT_KEY: {"modified": "2026-08-23"},
                self.CORE_KEY: {"modified": "2026-08-23"},
            },
        )
        both = ["bootflash:", "crashinfo:"]
        self.assertEqual(
            result["context"]["q_filesystem"],
            {
                "status": "served",
                "locations": {
                    "fru-rp/0/0/1": {"core_files": 2, "partitions": both, "member": 1},
                    "fru-rp/0/0/2": {"core_files": 0, "partitions": both, "member": 2},
                    "fru-rp/0/0/3": {"core_files": 1, "partitions": both, "member": 3},
                    "fru-rp/0/0/4": {"core_files": 1, "partitions": ["crashinfo:"], "member": 4},
                },
                "core_files_keyed": 2,
                "core_files_older": 2,
                "keys_also_listed_by_dir": 1,
                "keys_from_model_only": 1,
                "dates_disagreeing_with_dir": 0,
            },
        )
        self.assertEqual(result["context"]["older_files_ignored"], 0)
        self.assertEqual(result["raw"]["q-filesystem"], payload)
        self.assertNotIn("note", result["raw"])

    def test_a_shared_key_keeps_the_dir_value_and_counts_the_date_disagreement(self):
        # Both sources name member 1's system report, but the model dates it a
        # UTC day before the dir listing's mtime: the dir listing, the
        # field-verified source, keeps its value, and the disagreement is
        # counted as evidence about what the model's time leaf means.
        payload = self._one_location(
            1, {"filename": self.REPORT, "time": "2026-08-22T01:00:00+00:00"}
        )
        ctx = self._stack_ctx(payloads={checks._Q_FS_PATH: payload})
        result = checks._collect_crash_files(ctx, now=self._now())
        self.assertEqual(result["normalized"], {self.REPORT_KEY: {"modified": "2026-08-23"}})
        q_filesystem = result["context"]["q_filesystem"]
        self.assertEqual(q_filesystem["keys_also_listed_by_dir"], 1)
        self.assertEqual(q_filesystem["keys_from_model_only"], 0)
        self.assertEqual(q_filesystem["dates_disagreeing_with_dir"], 1)

    def test_entries_meeting_on_one_key_resolve_alike_in_any_listed_order(self):
        # Two locations share chassis 1 and one file name: whichever order the
        # device lists them in, the key keeps the value of the location whose
        # text sorts first (fru-fp before fru-rp). One name in two directories
        # resolves by filename order the same way. core_files_keyed counts
        # every in-window entry, the ones that met another on a key included.
        rp = {
            "fru": "fru-rp",
            "slot": 0,
            "bay": 0,
            "chassis": 1,
            "partitions": [{"name": "crashinfo:"}, {"name": "bootflash:"}],
            "core-files": [
                {"filename": "/crashinfo/core/shared.core.gz", "time": "2026-08-23T10:00:00Z"},
                {"filename": "/crashinfo/core/dup.core.gz", "time": "2026-08-22T10:00:00Z"},
                {"filename": "/bootflash/core/dup.core.gz", "time": "2026-08-21T10:00:00Z"},
                # The colon spellings key by the file's own name too.
                {"filename": "crashinfo:core/colon_path.core.gz", "time": "2026-08-23T00:00:00Z"},
                {"filename": "crashinfo:colon_top.core.gz", "time": "2026-08-23T00:00:00Z"},
            ],
        }
        fp = {
            "fru": "fru-fp",
            "slot": 0,
            "bay": 0,
            "chassis": 1,
            "partitions": {"name": "bootflash:"},
            "core-files": {
                "filename": "/bootflash/core/shared.core.gz",
                "time": "2026-08-20T10:00:00Z",
            },
        }
        results = [
            checks._q_filesystem_core_files(
                {
                    "Cisco-IOS-XE-platform-software-oper:cisco-platform-software": {
                        "q-filesystem": order
                    }
                },
                {"1"},
                self._now(),
                7,
            )
            for order in ([rp, fp], [fp, rp])
        ]
        self.assertEqual(results[0], results[1])
        recent, locations, keyed, older = results[0]
        self.assertEqual(
            recent,
            {
                "member1|colon_path.core.gz": {"modified": "2026-08-23"},
                "member1|colon_top.core.gz": {"modified": "2026-08-23"},
                "member1|dup.core.gz": {"modified": "2026-08-21"},
                "member1|shared.core.gz": {"modified": "2026-08-20"},
            },
        )
        self.assertEqual((keyed, older), (6, 0))
        self.assertEqual(
            locations,
            {
                "fru-fp/0/0/1": {"core_files": 1, "partitions": ["bootflash:"], "member": 1},
                "fru-rp/0/0/1": {
                    "core_files": 5,
                    "partitions": ["bootflash:", "crashinfo:"],
                    "member": 1,
                },
            },
        )

    def test_the_check_reads_only_the_narrowed_fields_and_tolerates_404(self):
        # The one guard against an unbounded read: partition-content lists
        # every file on every partition, so the check's read is pinned to the
        # location keys, core-files and partition names, asked with ok_404.
        # The full list path belongs to the shakedown alone.
        self.assertEqual(
            checks._Q_FS_PATH,
            "/data/Cisco-IOS-XE-platform-software-oper:cisco-platform-software"
            "?fields=q-filesystem(fru;slot;bay;chassis;core-files;partitions(name))",
        )
        self.assertNotIn("partition-content", checks._Q_FS_PATH)

        class _KwargsCtx(_StackCtx):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                self.get_kwargs = []

            def get(self, path, **kwargs):
                self.get_kwargs.append(kwargs)
                return super().get(path, **kwargs)

        ctx = self._stack_ctx(ctx_class=_KwargsCtx)
        checks._collect_crash_files(ctx, now=self._now())
        self.assertEqual(ctx.paths, [checks._Q_FS_PATH])
        self.assertEqual(ctx.get_kwargs, [{"ok_404": True}])

    def test_location_keys_when_chassis_is_not_a_roster_member(self):
        core = {
            "filename": "/crashinfo/core/fed_RP_0_99_20260823-101010-UTC.core.gz",
            "time": "2026-08-23T10:10:10+00:00",
        }
        # A roster, but none of its member numbers is the location's chassis.
        ctx = self._stack_ctx(payloads={checks._Q_FS_PATH: self._one_location(-1, core)})
        result = checks._collect_crash_files(ctx, now=self._now())
        self.assertEqual(
            result["normalized"],
            {
                self.REPORT_KEY: {"modified": "2026-08-23"},
                "core@fru-rp/0/0/-1|fed_RP_0_99_20260823-101010-UTC.core.gz": {
                    "modified": "2026-08-23"
                },
            },
        )
        self.assertEqual(
            result["context"]["q_filesystem"]["locations"],
            {"fru-rp/0/0/-1": {"core_files": 1, "partitions": ["bootflash:"]}},
        )
        # No roster at all: even chassis 1 keys by the location, beside the
        # role-keyed alias listings.
        ctx = _StackCtx(
            {
                "show switch detail": "% Invalid input detected at '^' marker.",
                "dir crashinfo:": _dir_listing("crashinfo:"),
                "dir stby-crashinfo:": _dir_listing("stby-crashinfo:"),
            },
            payloads={checks._Q_FS_PATH: self._one_location(1, core)},
        )
        result = checks._collect_crash_files(ctx, now=self._now())
        self.assertEqual(
            list(result["normalized"]),
            ["core@fru-rp/0/0/1|fed_RP_0_99_20260823-101010-UTC.core.gz"],
        )

    def test_core_file_window_is_utc_and_unreadable_times_fail_safe(self):
        # The bare list-read shape, with its one entry as a bare object.
        payload = {
            "Cisco-IOS-XE-platform-software-oper:q-filesystem": {
                "fru": "fru-rp",
                "slot": 0,
                "bay": 0,
                "chassis": 1,
                "core-files": [
                    {"filename": "a_inside.core.gz", "time": "2026-08-17T01:30:00+00:00"},
                    {"filename": "b_outside.core.gz", "time": "2026-08-16T23:59:59Z"},
                    # 21:30 at -04:00 is 01:30 UTC on Aug 17: inside.
                    {"filename": "c_offset.core.gz", "time": "2026-08-16T21:30:00-04:00"},
                    {"filename": "d_unreadable.core.gz", "time": "yesterday"},
                    {"filename": "e_no_time.core.gz"},
                ],
            }
        }
        recent, locations, keyed, older = checks._q_filesystem_core_files(
            payload, {"1", "2"}, self._now(), 7
        )
        self.assertEqual(
            recent,
            {
                "member1|a_inside.core.gz": {"modified": "2026-08-17"},
                "member1|c_offset.core.gz": {"modified": "2026-08-17"},
                "member1|d_unreadable.core.gz": {"modified": "yesterday"},
                # A string like every other value: never a type change when
                # the dir listing dates the same key in another capture.
                "member1|e_no_time.core.gz": {"modified": "unknown"},
            },
        )
        self.assertEqual((keyed, older), (4, 1))
        self.assertEqual(
            locations, {"fru-rp/0/0/1": {"core_files": 5, "partitions": [], "member": 1}}
        )

    def test_model_not_served_leaves_the_dir_view_untouched(self):
        ctx = self._stack_ctx()
        result = checks._collect_crash_files(ctx, now=self._now())
        self.assertEqual(ctx.paths, [checks._Q_FS_PATH])
        self.assertEqual(result["normalized"], {self.REPORT_KEY: {"modified": "2026-08-23"}})
        context = dict(result["context"])
        self.assertEqual(context.pop("q_filesystem"), {"status": "not served (404)"})
        self.assertEqual(
            context,
            {
                "older_files_ignored": 0,
                "recent_window_days": 7,
                "filesystems_listed": [
                    "crashinfo-1:",
                    "crashinfo-2:",
                    "crashinfo-3:",
                    "crashinfo-4:",
                ],
                "active_member": 1,
                "standby_member": 2,
            },
        )
        self.assertIsNone(result["raw"]["q-filesystem"])
        self.assertNotIn("note", result["raw"])

    def test_transport_error_is_a_note_and_the_check_still_succeeds(self):
        failure = ConnectionError("read timed out")
        ctx = self._stack_ctx(raise_for={checks._Q_FS_PATH: failure})
        result = checks._collect_crash_files(ctx, now=self._now())
        self.assertEqual(result["normalized"], {self.REPORT_KEY: {"modified": "2026-08-23"}})
        self.assertEqual(result["context"]["q_filesystem"], {"status": "read failed"})
        self.assertIsNone(result["raw"]["q-filesystem"])
        self.assertIn("q-filesystem supplement failed: read timed out", result["raw"]["note"])

    def test_rejected_narrowed_read_is_recorded_and_never_retried_unnarrowed(self):
        class RestconfError(Exception):
            def __init__(self, message, status_code=None):
                super().__init__(message)
                self.status_code = status_code

        rejection = RestconfError("GET %s: HTTP 400" % (checks._Q_FS_PATH,), status_code=400)
        ctx = self._stack_ctx(raise_for={checks._Q_FS_PATH: rejection})
        result = checks._collect_crash_files(ctx, now=self._now())
        self.assertEqual(ctx.paths, [checks._Q_FS_PATH])
        self.assertEqual(result["context"]["q_filesystem"], {"status": "rejected (HTTP 400)"})
        self.assertIn("not retried unnarrowed", result["raw"]["note"])
        self.assertEqual(result["normalized"], {self.REPORT_KEY: {"modified": "2026-08-23"}})

        # Only a 400 is a verdict on the fields filter (how a release refuses
        # one): an auth refusal, a DMI backend 5xx or a non-JSON 2xx is a
        # failed read, never reported as a rejected narrowing.
        for status_code, status in (
            (403, "read failed (HTTP 403)"),
            (500, "read failed (HTTP 500)"),
            (200, "read failed"),
        ):
            failure = RestconfError(
                "GET %s: HTTP %d" % (checks._Q_FS_PATH, status_code), status_code=status_code
            )
            ctx = self._stack_ctx(raise_for={checks._Q_FS_PATH: failure})
            result = checks._collect_crash_files(ctx, now=self._now())
            self.assertEqual(ctx.paths, [checks._Q_FS_PATH])
            self.assertEqual(result["context"]["q_filesystem"], {"status": status})
            self.assertEqual(
                result["raw"]["note"], "q-filesystem supplement failed: %s" % (failure,)
            )
            self.assertEqual(result["normalized"], {self.REPORT_KEY: {"modified": "2026-08-23"}})

    def test_boundary_year_times_fail_safe_and_never_fail_the_check(self):
        # A time its offset shifts past the calendar's edge raises
        # OverflowError, not ValueError. The dir listing keeps the printed
        # date (year 1 is old, year 9999 recent), an absurd day fails safe as
        # recent with its raw text, and the model's time counts as
        # unparseable: recent, with its raw text. Nothing fails the check.
        member1 = (
            "Directory of crashinfo:/\n\n"
            "   14  -rw-  1234  Jan 01 0001 00:00:00 +05:00  year_one.bin\n"
            "   15  -rw-  1234  Dec 31 9999 23:00:00 -05:00  year_max.bin\n"
            "   16  -rw-  1234  Aug 99999999999999999999 2026 10:00:00 -04:00  huge_day.bin\n"
            "\n1651314688 bytes total (1517166592 bytes free)"
        )
        payload = self._one_location(
            1,
            {"filename": "year_one.core.gz", "time": "0001-01-01T00:00:00+05:00"},
            {"filename": "year_max.core.gz", "time": "9999-12-31T23:00:00-05:00"},
        )
        ctx = self._stack_ctx(member1=member1, payloads={checks._Q_FS_PATH: payload})
        result = checks._collect_crash_files(ctx, now=self._now())
        self.assertEqual(
            result["normalized"],
            {
                "member1|year_max.bin": {"modified": "9999-12-31"},
                "member1|huge_day.bin": {"modified": "Aug 99999999999999999999 2026"},
                "member1|year_one.core.gz": {"modified": "0001-01-01T00:00:00+05:00"},
                "member1|year_max.core.gz": {"modified": "9999-12-31T23:00:00-05:00"},
            },
        )
        self.assertEqual(result["context"]["older_files_ignored"], 1)  # year_one.bin
        self.assertEqual(result["context"]["q_filesystem"]["status"], "served")
        self.assertEqual(result["context"]["q_filesystem"]["core_files_keyed"], 2)

    def test_a_parse_failure_is_a_status_and_the_dir_view_survives(self):
        # Parsing unverified device data never fails the check either. A bare
        # JSON Infinity decodes to a float that int() refuses with
        # OverflowError: the supplement records the failure beside its
        # payload, and the dir view stands as it would without the model.
        payload = self._one_location(float("inf"), {"filename": "x.core.gz"})
        ctx = self._stack_ctx(payloads={checks._Q_FS_PATH: payload})
        result = checks._collect_crash_files(ctx, now=self._now())
        self.assertEqual(result["normalized"], {self.REPORT_KEY: {"modified": "2026-08-23"}})
        self.assertEqual(result["context"]["q_filesystem"], {"status": "parse failed"})
        self.assertIs(result["raw"]["q-filesystem"], payload)
        self.assertTrue(
            result["raw"]["note"].startswith(
                "q-filesystem supplement could not be parsed: OverflowError:"
            )
        )

        class SoftTimeLimitExceeded(Exception):
            pass

        class AbortingEntry(dict):
            # The Celery abort signal is asynchronous and can land mid-parse;
            # the parse guard re-raises it like the read's.
            def get(self, key, default=None):
                raise SoftTimeLimitExceeded()

        aborting = {
            "Cisco-IOS-XE-platform-software-oper:cisco-platform-software": {
                "q-filesystem": [AbortingEntry()]
            }
        }
        ctx = self._stack_ctx(payloads={checks._Q_FS_PATH: aborting})
        with self.assertRaises(SoftTimeLimitExceeded):
            checks._collect_crash_files(ctx, now=self._now())

    def test_supplement_never_swallows_the_celery_abort_signal(self):
        class SoftTimeLimitExceeded(Exception):
            pass

        ctx = self._stack_ctx(raise_for={checks._Q_FS_PATH: SoftTimeLimitExceeded()})
        with self.assertRaises(SoftTimeLimitExceeded):
            checks._collect_crash_files(ctx, now=self._now())

    def test_keys_hold_across_a_switchover_and_whichever_source_answered(self):
        payload = _loader.fixture_json("iosxe_q_filesystem_model_shape.json")
        before = _loader.fixture_text("iosxe_show_switch_detail.txt")
        after = before.replace("*1       Active ", "*1       Standby").replace(
            " 2       Standby", " 2       Active "
        )
        views = [
            checks._collect_crash_files(
                self._stack_ctx(detail=detail, payloads={checks._Q_FS_PATH: payload}),
                now=self._now(),
            )["normalized"]
            for detail in (before, after)
        ]
        self.assertEqual(views[0], views[1])

        # The shared file's key and value are the same whether only the dir
        # listing saw it (model not served) or only the model did (member 1's
        # filesystems not listable), so the two captures diff to nothing.
        missing = "%Error opening crashinfo:/ (No such device)"
        dir_only = self._stack_ctx()
        dir_only_view = checks._collect_crash_files(dir_only, now=self._now())["normalized"]
        model_only = self._stack_ctx(
            member1=missing,
            payloads={
                checks._Q_FS_PATH: self._one_location(
                    1, {"filename": self.REPORT, "time": "2026-08-23T02:15:03+00:00"}
                )
            },
        )
        model_only.outputs["dir crashinfo:"] = missing
        model_only_result = checks._collect_crash_files(model_only, now=self._now())
        self.assertEqual(model_only_result["context"]["members_not_listed"], [1])
        self.assertEqual(model_only_result["normalized"], dir_only_view)
        compare = registry.CHECKS["iosxe_crash_files"].compare
        diff = _loader.diffcore.diff_check(dir_only_view, model_only_result["normalized"], compare)
        self.assertEqual(diff["result"], "pass")

    def test_shakedown_summary_of_the_full_read(self):
        """Model-shaped fixture, NOT a field capture: the shakedown's full list read."""
        summary = checks._summarize_q_filesystem(
            _loader.fixture_json("iosxe_q_filesystem_full_model_shape.json")
        )
        self.assertTrue(summary["served"])
        self.assertEqual(sorted(summary["locations"]), ["fru-rp/0/0/1", "fru-rp/0/0/2"])
        first = summary["locations"]["fru-rp/0/0/1"]
        self.assertEqual(
            first["partitions"],
            {
                "bootflash:": {"file": 2, "other": 1, "directory": 3},
                "crashinfo:": {"directory": 2, "file": 3},
            },
        )
        # Matched on the entry's own name: crashinfo's tracelogs/ files sit
        # under a path containing "crash" and are never echoed.
        self.assertEqual(
            [item["full-path"] for item in first["crash_related"]],
            [
                "/bootflash/core",
                "/bootflash/core/fed_1_RP_0_31337_20250102-030000-UTC.core.gz",
                "/crashinfo/koops.dat",
                "/crashinfo/system-report_1_20260823-021503-UTC.tar.gz",
            ],
        )
        self.assertEqual(
            first["crash_related"][2],
            {
                "partition": "crashinfo:",
                "full-path": "/crashinfo/koops.dat",
                "size": "0",
                "type": "file",
                "modified-time": "2019-07-31T04:59:17+00:00",
            },
        )
        self.assertEqual(first["crash_related_total"], 4)
        self.assertEqual(first["core_files"], 1)
        self.assertEqual(
            first["core_files_sample"],
            [
                {
                    "filename": "/bootflash/core/fed_1_RP_0_31337_20250102-030000-UTC.core.gz",
                    "time": "2025-01-02T03:00:00+00:00",
                }
            ],
        )
        # A partition with no partition-content, given as a bare object.
        self.assertEqual(
            summary["locations"]["fru-rp/0/0/2"],
            {
                "partitions": {"crashinfo:": {}},
                "crash_related": [],
                "crash_related_total": 0,
                "core_files": 0,
                "core_files_sample": [],
            },
        )

    def test_shakedown_summary_caps_echoed_entries_and_reads_absence(self):
        self.assertEqual(checks._summarize_q_filesystem(None), {"served": False})
        cores = [
            {"full-path": "/crashinfo/core/proc_%02d.core.gz" % (n,), "type": "file"}
            for n in range(25)
        ]
        payload = {
            "Cisco-IOS-XE-platform-software-oper:cisco-platform-software": {
                "q-filesystem": {
                    "fru": "fru-rp",
                    "slot": 0,
                    "bay": 0,
                    "chassis": 1,
                    "partitions": {"name": "crashinfo:", "partition-content": cores},
                    "core-files": [{"filename": "proc_%02d.core.gz" % (n,)} for n in range(25)],
                }
            }
        }
        location = checks._summarize_q_filesystem(payload)["locations"]["fru-rp/0/0/1"]
        self.assertEqual(len(location["crash_related"]), checks._Q_FS_SAMPLE_MAX)
        self.assertEqual(location["crash_related_total"], 25)
        self.assertEqual(location["core_files"], 25)
        self.assertEqual(len(location["core_files_sample"]), checks._Q_FS_SAMPLE_MAX)


class TestErrdisableAndPortChannels(unittest.TestCase):
    def test_errdisable_parse_and_healthy_empty(self):
        output = (
            "Port      Name               Status       Reason\n"
            "Te1/0/5   server-cab-3       err-disabled psecure-violation\n"
        )
        self.assertEqual(
            checks._parse_errdisable(output), {"Te1/0/5": {"reason": "psecure-violation"}}
        )
        self.assertEqual(checks._parse_errdisable("Port  Name  Status  Reason\n"), {})

    ERRDISABLED_CLI = (
        "Port      Name               Status       Reason\n"
        "Te1/0/5   server-cab-3       err-disabled bpduguard\n"
    )
    HEALTHY_CLI = "Port      Name               Status       Reason\n"

    def test_errdisable_normalized_from_ext_state(self):
        payload = _loader.fixture_json("iosxe_interfaces_oper.json")
        normalized, ext_states = checks._normalize_errdisable(payload)
        self.assertEqual(normalized, {"TenGigabitEthernet1/0/5": {"reason": "port-err-bpduguard"}})
        # Every interface serving the leaves, whether or not disabled; none for
        # the interfaces without the container.
        self.assertEqual(
            sorted(ext_states),
            ["TenGigabitEthernet1/0/1", "TenGigabitEthernet1/0/5", "TwoGigabitEthernet1/0/12"],
        )
        self.assertEqual(
            ext_states["TenGigabitEthernet1/0/1"],
            {"error-type": "port-error-none", "port-error-reason": "port-err-none"},
        )
        # Prefixed enums and a missing reason: the type decides, the reason may be None.
        payload = _iface_payload(
            {"name": "Gi1/0/9", "intf-ext-state": {"error-type": "x:port-error-disable"}}
        )
        self.assertEqual(checks._normalize_errdisable(payload)[0], {"Gi1/0/9": {"reason": None}})

    def test_errdisable_collector_primary_is_the_interfaces_get(self):
        payload = _loader.fixture_json("iosxe_interfaces_oper.json")
        ctx = _IfaceCtx({checks._IFACE_PATH: payload}, outputs={})
        result = checks._collect_errdisable(ctx)
        # Same path and kwargs as iosxe_interfaces: one GET for both; no SSH.
        self.assertEqual(ctx.gets, [(checks._IFACE_PATH, {})])
        self.assertEqual(ctx.commands, [])
        self.assertEqual(
            result["normalized"], {"TenGigabitEthernet1/0/5": {"reason": "port-err-bpduguard"}}
        )
        self.assertEqual(
            result["context"],
            {"source": "intf-ext-state", "ports_with_ext_state": 3, "ports_errdisabled": 1},
        )
        self.assertEqual(sorted(result["raw"]), ["intf-ext-state"])
        self.assertIn("TenGigabitEthernet1/0/1", result["raw"]["intf-ext-state"])
        # iosxe_interfaces on the same ctx reports the port as down, without the reason.
        iface = checks._collect_interfaces(ctx)["normalized"]["TenGigabitEthernet1/0/5"]
        self.assertEqual(iface["oper"], "if-oper-state-no-pass")
        self.assertNotIn("reason", iface)

    def test_errdisable_healthy_model_source_is_empty(self):
        payload = _iface_payload(
            {
                "name": "Gi1/0/1",
                "intf-ext-state": {
                    "error-type": "port-error-none",
                    "port-error-reason": "port-err-none",
                },
            }
        )
        result = checks._collect_errdisable(_IfaceCtx({checks._IFACE_PATH: payload}))
        self.assertEqual(result["normalized"], {})
        self.assertEqual(result["context"]["source"], "intf-ext-state")

    def test_errdisable_falls_back_to_cli_without_ext_state(self):
        # No interface serves intf-ext-state (an older release, or the leaves
        # unfilled): the CLI is the source, and raw's note says so.
        payload = _iface_payload({"name": "Gi1/0/1", **_UP})
        ctx = _IfaceCtx(
            {checks._IFACE_PATH: payload},
            outputs={"show interfaces status err-disabled": self.ERRDISABLED_CLI},
        )
        result = checks._collect_errdisable(ctx)
        self.assertEqual(ctx.commands, ["show interfaces status err-disabled"])
        self.assertEqual(result["normalized"], {"Te1/0/5": {"reason": "bpduguard"}})
        self.assertEqual(
            result["context"],
            {
                "source": "show interfaces status err-disabled",
                "ports_with_ext_state": 0,
                "ports_errdisabled": 1,
            },
        )
        self.assertIn("intf-ext-state served on no interface", result["raw"]["note"])
        self.assertIn("show interfaces status err-disabled", result["raw"])
        # Healthy CLI output: empty, still recorded.
        ctx.outputs["show interfaces status err-disabled"] = self.HEALTHY_CLI
        self.assertEqual(checks._collect_errdisable(ctx)["normalized"], {})

    def test_errdisable_falls_back_to_cli_when_the_get_fails(self):
        for failure in (
            _RestconfError("GET: HTTP 500", 500),
            RuntimeError("no HTTP GET transport"),
        ):
            with self.subTest(failure=type(failure).__name__):
                ctx = _IfaceCtx(
                    {},
                    raise_for={checks._IFACE_PATH: failure},
                    outputs={"show interfaces status err-disabled": self.HEALTHY_CLI},
                )
                result = checks._collect_errdisable(ctx)
                self.assertEqual(result["normalized"], {})
                self.assertIn("interfaces-oper read failed", result["raw"]["note"])
                self.assertEqual(result["context"]["source"], "show interfaces status err-disabled")
        # The 400 retry also serves this check; the unfiltered reply is used.
        payload = _loader.fixture_json("iosxe_interfaces_oper.json")
        ctx = _IfaceCtx(
            {checks._IFACE_BASE_PATH: payload},
            raise_for={checks._IFACE_PATH: _RestconfError("GET: HTTP 400", 400)},
        )
        result = checks._collect_errdisable(ctx)
        # The same kwargs iosxe_interfaces uses on this path, so the unfiltered
        # read is the cache hit (the rejected filtered GET is never cached).
        self.assertEqual(
            ctx.gets,
            [
                (checks._IFACE_PATH, {}),
                (checks._IFACE_BASE_PATH, {"timeout": _loader.constants.BIG_GET_TIMEOUT}),
            ],
        )
        self.assertEqual(result["context"]["source"], "intf-ext-state")
        self.assertIn("HTTP 400", result["raw"]["note"])

    def test_errdisable_celery_abort_is_never_a_note(self):
        class SoftTimeLimitExceeded(Exception):
            pass

        ctx = _IfaceCtx({}, raise_for={checks._IFACE_PATH: SoftTimeLimitExceeded()}, outputs={})
        with self.assertRaises(SoftTimeLimitExceeded):
            checks._collect_errdisable(ctx)

    def test_errdisable_not_present_only_without_any_source(self):
        payload = _iface_payload({"name": "Gi1/0/1", **_UP})
        with self.assertRaises(registry.SkipCheck):
            checks._collect_errdisable(_IfaceCtx({checks._IFACE_PATH: payload}))
        ctx = _IfaceCtx(
            {checks._IFACE_PATH: payload},
            outputs={"show interfaces status err-disabled": "% Invalid input detected"},
        )
        with self.assertRaises(registry.SkipCheck):
            checks._collect_errdisable(ctx)

    def test_etherchannel_parse_with_wrapped_members(self):
        output = (
            "Group  Port-channel  Protocol    Ports\n"
            "------+-------------+-----------+----------------------------------\n"
            "1      Po1(SU)         LACP      Te1/0/47(P) Te1/0/48(P)\n"
            "2      Po2(SD)         LACP      Te2/0/1(s)\n"
            "                                 Te2/0/2(D)\n"
        )
        normalized = checks._parse_etherchannel(output)
        self.assertEqual(normalized["Po1"]["flags"], "SU")
        self.assertEqual(normalized["Po1"]["members"]["Te1/0/48"], "P")
        self.assertEqual(normalized["Po2"]["members"], {"Te2/0/1": "s", "Te2/0/2": "D"})


class _StackCtx:
    """Fake CollectorContext: canned SSH output per command, RESTCONF payload per path."""

    has_ssh = True

    def __init__(self, outputs, payloads=None, raise_for=None):
        self.outputs = outputs
        self.payloads = payloads or {}
        self.raise_for = raise_for or {}
        self.commands = []
        self.paths = []

    def run_ssh(self, command, **kwargs):
        self.commands.append(command)
        return self.outputs[command]

    def get(self, path, **kwargs):
        self.paths.append(path)
        if path in self.raise_for:
            raise self.raise_for[path]
        return self.payloads.get(path)


# A 4-member stack's hardware inventory, shaped like the field capture: the
# chassis entries carry hw-dev-index 1, 8, 15 and 20 — physical inventory
# indexes, NOT switch numbers — so members find theirs by serial. Serials are
# synthetic (one keeps the trailing blank the parser strips); the PEM entry
# shares index 1 with a chassis and must be ignored.
_STACK_INVENTORY = (
    {
        "hw-type": "hw-type-chassis",
        "hw-dev-index": 1,
        "part-number": "C9300-48UXM",
        "serial-number": "FOC0000A001 ",
    },
    {
        "hw-type": "hw-type-chassis",
        "hw-dev-index": 8,
        "part-number": "C9300-48UXM",
        "serial-number": "FOC0000A002",
    },
    {
        "hw-type": "hw-type-chassis",
        "hw-dev-index": 15,
        "part-number": "C9300-48U",
        "serial-number": "FOC0000A003",
    },
    {
        "hw-type": "hw-type-chassis",
        "hw-dev-index": 20,
        "part-number": "C9300-24UX",
        "serial-number": "FOC0000A004",
    },
    {
        "hw-type": "hw-type-pem",
        "hw-dev-index": 1,
        "part-number": "PWR-C1-1100WAC-P",
        "serial-number": "DTN0000A001",
    },
)


def _hardware(entries):
    """A device-hardware-data payload whose device-inventory lists ``entries``."""
    return {
        "Cisco-IOS-XE-device-hardware-oper:device-hardware-data": {
            "device-hardware": {"device-inventory": [dict(entry) for entry in entries]}
        }
    }


_STACK_HARDWARE = _hardware(_STACK_INVENTORY)


class _StackIdentityCtx(_StackCtx):
    """_StackCtx that also records each GET's kwargs and fails SSH commands on cue.

    raise_for may name a command as well as a path; gets lists (path, kwargs)
    in call order, so a test pins each read's exact per-run cache key.
    """

    def __init__(self, outputs, payloads=None, raise_for=None):
        super().__init__(outputs, payloads=payloads, raise_for=raise_for)
        self.gets = []

    def run_ssh(self, command, **kwargs):
        if command in self.raise_for:
            self.commands.append(command)
            raise self.raise_for[command]
        return super().run_ssh(command, **kwargs)

    def get(self, path, **kwargs):
        self.gets.append((path, dict(kwargs)))
        return super().get(path, **kwargs)


def _stack_members():
    """The 'switch|<n>' entries every healthy capture of the standard stack yields."""
    roster = (
        ("1", "Active", 15, "C9300-48UXM"),
        ("2", "Standby", 12, "C9300-48UXM"),
        ("3", "Member", 9, "C9300-48U"),
        ("4", "Member", 6, "C9300-24UX"),
    )
    return {
        "switch|%s" % (number,): {
            "role": role,
            "state": "Ready",
            "priority": priority,
            "hw_version": "V02",
            "mac": "00a1.b2c3.0%s00" % (number,),
            "model": model,
            "serial": "FOC0000A00%s" % (number,),
            "reload_reason": "Image Install",
        }
        for number, role, priority, model in roster
    }


def _dir_listing(filesystem, *entries):
    """A `dir <filesystem>` listing; entries are (name, 'Mon DD YYYY') pairs."""
    lines = ["Directory of %s/" % (filesystem,)]
    for index, (name, date) in enumerate(entries, 14):
        lines.append("  %d  -rw-  1234567   %s 18:22:11 +00:00  %s" % (index, date, name))
    lines += ["", "11353194496 bytes total (10000000000 bytes free)"]
    return "\n".join(lines)


class TestSwitchStack(unittest.TestCase):
    def setUp(self):
        self.detail = _loader.fixture_text("iosxe_show_switch_detail.txt")
        self.summary = _loader.fixture_text("iosxe_show_switch_stack_ports_summary.txt")
        # Shaped exactly like the field capture of a 4-member 9300 (leaf
        # spellings, value types, one stack-node per member keyed by
        # chassis-number), with synthetic serials, MACs, counters and times.
        # Every node repeats one set of sp-stats and one sp-stats-time, as each
        # field node seen does: not every stack-node leaf is the member's own.
        # chassis-number 2 was not in the field photos; it follows the roster.
        self.stack_oper = _loader.fixture_json("iosxe_stack_oper.json")
        # Synthetic, not field-captured: the standard IOS-XE layout.
        self.inventory = _loader.fixture_text("iosxe_show_inventory_9300_stack.txt")

    def _collect(
        self,
        stack_oper=True,
        hardware=_STACK_HARDWARE,
        inventory=None,
        detail=None,
        summary=None,
        raise_for=None,
    ):
        """Run the collector on canned answers; (ctx, result).

        stack_oper True serves the field-shaped fixture, None answers 404, a
        dict is served as given. raise_for maps a path or a command to the
        exception it raises. `show inventory` answers only when inventory is
        given (or raise_for names it): running it otherwise fails the test,
        which pins that the collector never needed it — the fake's KeyError
        alone would not, as the collector turns a failed show inventory into
        a note.
        """
        outputs = {
            "show switch detail": self.detail if detail is None else detail,
            "show switch stack-ports summary": self.summary if summary is None else summary,
        }
        if inventory is not None:
            outputs["show inventory"] = inventory
        if stack_oper is True:
            stack_oper = self.stack_oper
        payloads = {checks._HW_PATH: hardware}
        if stack_oper is not None:
            payloads[checks._STACK_OPER_PATH] = stack_oper
        ctx = _StackIdentityCtx(outputs, payloads=payloads, raise_for=raise_for)
        result = checks._collect_switch_stack(ctx)
        unasked = [c for c in ctx.commands if c not in outputs and c not in ctx.raise_for]
        self.assertEqual(unasked, [], "commands the collector had no need to run")
        return ctx, result

    def _nodes(self):
        return self.stack_oper["Cisco-IOS-XE-stack-oper:stack-oper-data"]["stack-node"]

    def test_detail_parses_header_members_and_ports(self):
        stack, members, ports = checks._parse_switch_detail(self.detail)
        self.assertEqual(
            stack,
            {"mac": "00a1.b2c3.0100", "mac_origin": "local", "mac_persistency": "Indefinite"},
        )
        self.assertEqual(sorted(members), ["1", "2", "3", "4"])
        # The leading * (the switch the session is on) is not a fact.
        self.assertEqual(
            members["1"],
            {
                "role": "Active",
                "state": "Ready",
                "priority": 15,
                "hw_version": "V02",
                "mac": "00a1.b2c3.0100",
            },
        )
        self.assertEqual(members["3"]["role"], "Member")
        self.assertEqual(members["3"]["priority"], 9)
        self.assertEqual(len(ports), 8)
        self.assertEqual(ports["1/1"], {"status": "OK", "neighbor": 2})
        self.assertEqual(ports["3/2"], {"status": "OK", "neighbor": 2})

    def test_detail_degraded_states_and_missing_hw_version(self):
        # Multi-word state, a foreign stack MAC after a switchover, a
        # provisioned member printing no hardware version, and a DOWN port
        # whose neighbor is the literal None.
        output = (
            "Switch/Stack Mac Address : 00a1.b2c3.0200 - Foreign Mac Address\n"
            "Mac persistency wait time: 4 mins\n"
            "                                             H/W   Current\n"
            "Switch#   Role    Mac Address     Priority Version  State \n"
            "----------------------------------------------------------------\n"
            "*1       Active   00a1.b2c3.0100     15     V02     Ready\n"
            " 2       Member   00a1.b2c3.0200     14     V02     Version Mismatch\n"
            " 3       Member   0000.0000.0000     1              Provisioned\n"
            "\n"
            "         Stack Port Status             Neighbors     \n"
            "Switch#  Port 1     Port 2           Port 1   Port 2 \n"
            "--------------------------------------------------------\n"
            "  1         OK       DOWN               2     None \n"
            "  2       DOWN         OK            None        1 \n"
        )
        stack, members, ports = checks._parse_switch_detail(output)
        self.assertEqual(stack["mac_origin"], "foreign")
        self.assertEqual(stack["mac_persistency"], "4 mins")
        self.assertEqual(members["2"]["state"], "Version Mismatch")
        self.assertEqual(members["2"]["hw_version"], "V02")
        self.assertEqual(members["3"]["state"], "Provisioned")
        self.assertNotIn("hw_version", members["3"])
        self.assertEqual(ports["1/2"], {"status": "DOWN", "neighbor": "None"})
        self.assertEqual(ports["2/1"], {"status": "DOWN", "neighbor": "None"})
        self.assertEqual(ports["2/2"], {"status": "OK", "neighbor": 1})

    def test_stack_ports_summary_parse(self):
        # Field-verified shape (4-member 9300): the neighbor column is the far
        # end's switch/port and a 1 m cable prints as '100cm'.
        ports = checks._parse_stack_ports_summary(self.summary)
        self.assertEqual(len(ports), 8)
        self.assertEqual(
            ports["1/2"],
            {
                "status": "OK",
                "neighbor": 4,
                "neighbor_port": "4/1",
                "cable": "100cm",
                "link_ok": True,
                "link_active": True,
                "sync_ok": True,
                "link_ok_changes": 1,
                "loopback": False,
            },
        )

    def test_neighbor_facts_forms(self):
        # Every form yields an int 'neighbor', so the value never changes type
        # between captures when only one of the two commands parses.
        self.assertEqual(checks._neighbor_facts("2/2"), {"neighbor": 2, "neighbor_port": "2/2"})
        self.assertEqual(checks._neighbor_facts(" 4/1 "), {"neighbor": 4, "neighbor_port": "4/1"})
        self.assertEqual(checks._neighbor_facts("3"), {"neighbor": 3})
        self.assertEqual(checks._neighbor_facts("None"), {"neighbor": "None"})

    def test_detail_accepts_switch_port_neighbors(self):
        output = (
            "Switch/Stack Mac Address : 00a1.b2c3.0100 - Local Mac Address\n"
            "Switch#   Role    Mac Address     Priority Version  State \n"
            "*1       Active   00a1.b2c3.0100     15     V02     Ready\n"
            " 2       Standby  00a1.b2c3.0200     14     V02     Ready\n"
            "         Stack Port Status             Neighbors     \n"
            "Switch#  Port 1     Port 2           Port 1   Port 2 \n"
            "  1         OK         OK             2/2      2/1 \n"
            "  2         OK         OK             1/2      1/1 \n"
        )
        _stack, _members, ports = checks._parse_switch_detail(output)
        self.assertEqual(ports["1/1"], {"status": "OK", "neighbor": 2, "neighbor_port": "2/2"})
        self.assertEqual(ports["2/2"], {"status": "OK", "neighbor": 1, "neighbor_port": "1/1"})

    def test_stack_ports_summary_down_port_with_two_word_cable_length(self):
        output = (
            "Sw#/Port#  Port      Neighbor   Cable    Link  Link    Sync  #Changes  In\n"
            "           Status               Length   OK    Active  OK    to LinkOK Loopback\n"
            "-----------------------------------------------------------------------------\n"
            "  1/1       OK        2          50cm     Yes   Yes     Yes   1         No\n"
            "  1/2       DOWN      None       No cable No    No      No    3         No\n"
        )
        ports = checks._parse_stack_ports_summary(output)
        self.assertEqual(ports["1/2"]["status"], "DOWN")
        self.assertEqual(ports["1/2"]["neighbor"], "None")
        self.assertEqual(ports["1/2"]["cable"], "No cable")
        self.assertFalse(ports["1/2"]["link_ok"])
        self.assertEqual(ports["1/2"]["link_ok_changes"], 3)
        self.assertEqual(checks._parse_stack_ports_summary("Sw#/Port#  Port\n"), {})

    def test_chassis_inventory_keys_by_hw_dev_index_as_evidence_only(self):
        # The index is the device's physical inventory index (1, 8, 15, 20 in
        # the field), kept for raw; the PEM entry is skipped, serials stripped.
        chassis = checks._chassis_inventory(_STACK_HARDWARE)
        self.assertEqual(sorted(chassis, key=int), ["1", "8", "15", "20"])
        self.assertEqual(chassis["1"], {"model": "C9300-48UXM", "serial": "FOC0000A001"})
        self.assertEqual(chassis["8"], {"model": "C9300-48UXM", "serial": "FOC0000A002"})
        self.assertEqual(checks._chassis_inventory({}), {})

    def test_stack_nodes_keyed_by_chassis_number(self):
        nodes = checks._stack_nodes(self.stack_oper)
        self.assertEqual(sorted(nodes), ["1", "2", "3", "4"])
        self.assertEqual(nodes["3"]["serial-number"], "FOC0000A003")
        self.assertEqual(nodes["3"]["reload-reason"], "Image Install")
        # One node may arrive as a bare object, the container without its
        # module prefix, and chassis-number string-ified.
        single = {"stack-oper-data": {"stack-node": {"chassis-number": "2", "serial-number": "X"}}}
        self.assertEqual(list(checks._stack_nodes(single)), ["2"])
        self.assertEqual(checks._stack_nodes(None), {})
        self.assertEqual(checks._stack_nodes({}), {})
        # Leaves are read stripped; blank or missing reads as unserved.
        padded = {"serial-number": " FOC0000A003 ", "reload-reason": "  "}
        self.assertEqual(checks._stack_leaf(padded, "serial-number"), "FOC0000A003")
        self.assertIsNone(checks._stack_leaf(padded, "reload-reason"))
        self.assertIsNone(checks._stack_leaf(None, "serial-number"))

    def test_show_inventory_member_entries_of_a_9300_stack(self):
        # Only 'Switch <n>' counts: the stack-level 'c93xx Stack' entry (the
        # active's PID/SN again), power supplies, uplink modules and optics
        # never name a member.
        self.assertEqual(
            checks._parse_show_inventory(self.inventory),
            {
                "1": {"model": "C9300-48UXM", "serial": "FOC0000A001"},
                "2": {"model": "C9300-48UXM", "serial": "FOC0000A002"},
                "3": {"model": "C9300-48U", "serial": "FOC0000A003"},
                "4": {"model": "C9300-24UX", "serial": "FOC0000A004"},
            },
        )

    def test_show_inventory_member_entries_of_an_svl_pair(self):
        # 'Chassis <n>' on a StackWise Virtual pair; 'Chassis 1 Fan Tray' (an
        # item with blank VID and SN) is a sub-item, not a member.
        output = _loader.fixture_text("iosxe_show_inventory_9500_svl.txt")
        self.assertEqual(
            checks._parse_show_inventory(output),
            {
                "1": {"model": "C9500-48Y4C", "serial": "FCW0000A0AA"},
                "2": {"model": "C9500-48Y4C", "serial": "FCW0000A0BB"},
            },
        )

    def test_show_inventory_blank_serial_and_ambiguous_member(self):
        output = (
            'NAME: "Switch 1", DESCR: "C9300-48UXM"\n'
            "PID: C9300-48UXM       , VID: V02  , SN:\n"
            'NAME: "Switch 2", DESCR: "C9300-48UXM"\n'
            "PID: C9300-48UXM       , VID: V02  , SN: FOC0000A002\n"
            'NAME: "Switch 2", DESCR: "C9300-48UXM"\n'
            "PID: C9300-48UXM       , VID: V02  , SN: FOC0000A0F2\n"
        )
        self.assertEqual(
            checks._parse_show_inventory(output), {"1": {"model": "C9300-48UXM"}, "2": None}
        )
        self.assertEqual(checks._parse_show_inventory(""), {})

    def test_member_identity_pairs_a_lone_member_only_after_show_inventory(self):
        # Pairing is the last resort: before show inventory was consulted the
        # member stays unresolved, so the collector asks show inventory first.
        members = {"1": {"role": "Active"}}
        chassis = {"1": {"model": "C9500-24Y4C", "serial": "FCW0000A0CC"}}
        identity, _notes = checks._member_identity(members, {}, chassis)
        self.assertIsNone(identity["1"]["serial"])
        unnumbered = (
            'NAME: "Chassis", DESCR: "Cisco Catalyst 9500 Series Chassis"\n'
            "PID: C9500-24Y4C       , VID: V01  , SN: FCW0000A0CC\n"
        )
        identity, notes = checks._member_identity(members, {}, chassis, unnumbered)
        paired = {
            "serial": "FCW0000A0CC",
            "model": "C9500-24Y4C",
            "serial_source": "device-inventory lone chassis",
            "model_source": "device-inventory",
        }
        self.assertEqual(identity["1"], paired)
        self.assertEqual(notes, [])
        # A show inventory that failed outright was consulted too: the pairing
        # still stands, being unambiguous without it.
        identity, notes = checks._member_identity(members, {}, chassis, inventory_failed=True)
        self.assertEqual(identity["1"], paired)
        self.assertEqual(notes, [])

    def test_collector_joins_every_member_by_serial(self):
        # The field bug: the chassis entries carry hw-dev-index 1, 8, 15 and
        # 20, so a join on the index named member 1 alone. Joined by serial,
        # every member carries its own serial and model, stack-oper adds each
        # member's reload reason, and show inventory is never needed.
        ctx, result = self._collect()
        normalized = result["normalized"]
        for key, expected in _stack_members().items():
            self.assertEqual(normalized[key], expected, key)
        self.assertEqual(
            normalized["stack"],
            {"mac": "00a1.b2c3.0100", "mac_origin": "local", "mac_persistency": "Indefinite"},
        )
        # Detail's status/neighbor plus the summary's link facts, one key per port;
        # both views agree the far end is switch 2, and the summary names its port.
        self.assertEqual(
            normalized["stack-port|1/1"],
            {
                "status": "OK",
                "neighbor": 2,
                "neighbor_port": "2/2",
                "cable": "50cm",
                "link_ok": True,
                "link_active": True,
                "sync_ok": True,
                "link_ok_changes": 1,
                "loopback": False,
            },
        )
        self.assertEqual(len([k for k in normalized if k.startswith("stack-port|")]), 8)
        self.assertEqual(len(normalized), 13)
        self.assertEqual(
            result["context"],
            {
                "members_total": 4,
                "members_ready": 4,
                "stack_ports_total": 8,
                "stack_ports_ok": 8,
                "serial_source": dict.fromkeys(("1", "2", "3", "4"), "stack-oper"),
                "model_source": dict.fromkeys(("1", "2", "3", "4"), "device-inventory"),
                "stack_oper": "served",
            },
        )
        raw = result["raw"]
        self.assertEqual(raw["show switch detail"], self.detail)
        self.assertEqual(raw["show switch stack-ports summary"], self.summary)
        self.assertIs(raw["stack-oper"], self.stack_oper)
        # hw-dev-index stays in raw as the device's own evidence.
        self.assertEqual(sorted(raw["device-inventory chassis"], key=int), ["1", "8", "15", "20"])
        self.assertNotIn("note", raw)
        self.assertNotIn("show inventory", ctx.commands)
        # Each read keeps its per-run cache key: the inventory platform_health's
        # (path, no kwargs), stack-oper the wireless platform check's (path and
        # ok_404 alike).
        self.assertEqual(
            ctx.gets, [(checks._HW_PATH, {}), (checks._STACK_OPER_PATH, {"ok_404": True})]
        )

    def test_join_ignores_inventory_order_and_index_values(self):
        # Re-indexed so no index lines up with a switch number (member 2's
        # chassis now sits at index 1, where an index join would hand it to
        # member 1) and listed in reverse: identity follows the serial alone.
        reindex = {"FOC0000A001 ": 20, "FOC0000A002": 1, "FOC0000A003": 8, "FOC0000A004": 15}
        shuffled = []
        for entry in reversed(_STACK_INVENTORY):
            index = reindex.get(entry["serial-number"], entry["hw-dev-index"])
            shuffled.append(dict(entry, **{"hw-dev-index": index}))
        _ctx, result = self._collect(hardware=_hardware(shuffled))
        for key, expected in _stack_members().items():
            self.assertEqual(result["normalized"][key], expected, key)
        self.assertNotIn("note", result["raw"])

    def test_stack_oper_absent_falls_back_to_show_inventory(self):
        # A release that does not serve stack-oper (404): the 'Switch <n>'
        # entries of show inventory give each member's serial, and the model
        # still comes from the hardware inventory by that serial. Without
        # stack-oper there is no reload reason to record.
        ctx, result = self._collect(stack_oper=None, inventory=self.inventory)
        self.assertEqual(ctx.commands[-1], "show inventory")
        for key, expected in _stack_members().items():
            del expected["reload_reason"]
            self.assertEqual(result["normalized"][key], expected, key)
        context = result["context"]
        self.assertEqual(
            context["serial_source"], dict.fromkeys(("1", "2", "3", "4"), "show inventory")
        )
        self.assertEqual(
            context["model_source"], dict.fromkeys(("1", "2", "3", "4"), "device-inventory")
        )
        self.assertEqual(context["stack_oper"], "not served")
        raw = result["raw"]
        self.assertEqual(raw["show inventory"], self.inventory)
        self.assertIsNone(raw["stack-oper"])
        self.assertEqual(
            raw["note"],
            "stack-oper not served on this release: no reload reasons, member serials from "
            "the fallbacks",
        )

    def test_svl_pair_falls_back_to_show_inventory_chassis_entries(self):
        # A 9500 StackWise Virtual pair that does not serve stack-oper: show
        # inventory names its members 'Chassis 1' / 'Chassis 2'. The hardware
        # inventory's indexes are arbitrary here; only the serial joins.
        detail = (
            "Switch/Stack Mac Address : 00a1.b2c3.1100 - Local Mac Address\n"
            "Mac persistency wait time: Indefinite\n"
            "                                             H/W   Current\n"
            "Switch#   Role    Mac Address     Priority Version  State \n"
            "-------------------------------------------------------------------------------------\n"
            "*1       Active   00a1.b2c3.1100     15     V02     Ready\n"
            " 2       Standby  00a1.b2c3.2200     10     V02     Ready\n"
        )
        hardware = _hardware(
            (
                {
                    "hw-type": "hw-type-chassis",
                    "hw-dev-index": 1,
                    "part-number": "C9500-48Y4C",
                    "serial-number": "FCW0000A0AA",
                },
                {
                    "hw-type": "hw-type-chassis",
                    "hw-dev-index": 9,
                    "part-number": "C9500-48Y4C",
                    "serial-number": "FCW0000A0BB",
                },
                {
                    "hw-type": "hw-type-pem",
                    "hw-dev-index": 1,
                    "part-number": "C9K-PWR-650WAC-R",
                    "serial-number": "ART0000A001",
                },
            )
        )
        _ctx, result = self._collect(
            stack_oper=None,
            hardware=hardware,
            inventory=_loader.fixture_text("iosxe_show_inventory_9500_svl.txt"),
            detail=detail,
            summary="% Invalid input detected at '^' marker.",
        )
        normalized = result["normalized"]
        self.assertEqual(normalized["switch|1"]["serial"], "FCW0000A0AA")
        self.assertEqual(
            normalized["switch|2"],
            {
                "role": "Standby",
                "state": "Ready",
                "priority": 10,
                "hw_version": "V02",
                "mac": "00a1.b2c3.2200",
                "model": "C9500-48Y4C",
                "serial": "FCW0000A0BB",
            },
        )
        self.assertEqual(
            result["context"]["serial_source"], {"1": "show inventory", "2": "show inventory"}
        )
        self.assertNotIn("no serial", result["raw"]["note"])
        self.assertNotIn("on no member", result["raw"]["note"])

    def test_stack_oper_missing_a_member_consults_show_inventory_for_it(self):
        # stack-oper serves members 1-3 only: member 4's serial comes from its
        # 'Switch 4' entry and it alone goes without a reload reason.
        del self._nodes()[3]
        ctx, result = self._collect(inventory=self.inventory)
        self.assertIn("show inventory", ctx.commands)
        expected = _stack_members()
        del expected["switch|4"]["reload_reason"]
        for key, facts in expected.items():
            self.assertEqual(result["normalized"][key], facts, key)
        self.assertEqual(
            result["context"]["serial_source"],
            {"1": "stack-oper", "2": "stack-oper", "3": "stack-oper", "4": "show inventory"},
        )
        self.assertNotIn("note", result["raw"])

    def test_model_falls_back_to_the_show_inventory_pid(self):
        # The hardware inventory lists no chassis for member 4: its model is
        # show inventory's PID, taken because that entry's SN is the member's
        # stack-oper serial.
        hardware = _hardware(_STACK_INVENTORY[:3] + _STACK_INVENTORY[4:])
        ctx, result = self._collect(hardware=hardware, inventory=self.inventory)
        self.assertIn("show inventory", ctx.commands)
        self.assertEqual(result["normalized"]["switch|4"], _stack_members()["switch|4"])
        self.assertEqual(result["context"]["serial_source"]["4"], "stack-oper")
        self.assertEqual(result["context"]["model_source"]["4"], "show inventory")
        self.assertNotIn("note", result["raw"])

    def test_show_inventory_entry_with_another_serial_never_lends_its_pid(self):
        hardware = _hardware(_STACK_INVENTORY[:3] + _STACK_INVENTORY[4:])
        inventory = self.inventory.replace("SN: FOC0000A004", "SN: FOC0000A0F4")
        self.assertNotEqual(inventory, self.inventory)
        _ctx, result = self._collect(hardware=hardware, inventory=inventory)
        entry = result["normalized"]["switch|4"]
        self.assertEqual(entry["serial"], "FOC0000A004")
        self.assertNotIn("model", entry)
        self.assertIsNone(result["context"]["model_source"]["4"])
        self.assertEqual(
            result["raw"]["note"],
            "switch 4: no model (no device-inventory chassis part-number for its serial; "
            "its show inventory entry carries another SN)",
        )

    def test_lone_member_pairs_with_the_only_chassis(self):
        # A single-member roster on a release serving neither stack-oper nor a
        # numbered chassis entry (this show inventory names it plain
        # 'Chassis'): one member beside one chassis serial is unambiguous.
        detail = (
            "Switch/Stack Mac Address : 00a1.b2c3.0100 - Local Mac Address\n"
            "Mac persistency wait time: Indefinite\n"
            "Switch#   Role    Mac Address     Priority Version  State \n"
            "*1       Active   00a1.b2c3.0100     1      V01     Ready\n"
        )
        inventory = (
            'NAME: "Chassis", DESCR: "Cisco Catalyst 9500 Series Chassis"\n'
            "PID: C9500-24Y4C       , VID: V01  , SN: FCW0000A0CC\n"
        )
        lone = {
            "hw-type": "hw-type-chassis",
            "hw-dev-index": 1,
            "part-number": "C9500-24Y4C",
            "serial-number": "FCW0000A0CC",
        }
        _ctx, result = self._collect(
            stack_oper=None,
            hardware=_hardware((lone,)),
            inventory=inventory,
            detail=detail,
            summary="% Invalid input detected at '^' marker.",
        )
        entry = result["normalized"]["switch|1"]
        self.assertEqual((entry["serial"], entry["model"]), ("FCW0000A0CC", "C9500-24Y4C"))
        self.assertEqual(result["context"]["serial_source"], {"1": "device-inventory lone chassis"})
        self.assertEqual(result["context"]["model_source"], {"1": "device-inventory"})

        # A second chassis serial makes the pairing ambiguous: nothing is
        # guessed, and the note says why and names both chassis.
        second = dict(lone, **{"hw-dev-index": 2, "serial-number": "FCW0000A0DD"})
        _ctx, result = self._collect(
            stack_oper=None,
            hardware=_hardware((lone, second)),
            inventory=inventory,
            detail=detail,
            summary="% Invalid input detected at '^' marker.",
        )
        entry = result["normalized"]["switch|1"]
        self.assertNotIn("serial", entry)
        self.assertNotIn("model", entry)
        note = result["raw"]["note"]
        self.assertIn(
            "switch 1: no serial or model (no stack-oper serial-number; show inventory names "
            "no Switch/Chassis entry for it; not a lone member beside a lone chassis entry)",
            note,
        )
        self.assertIn(
            "device-inventory chassis serials on no member: FCW0000A0CC (hw-dev-index 1), "
            "FCW0000A0DD (hw-dev-index 2)",
            note,
        )

        # The same chassis listed twice is still one chassis, and pairs; an
        # extra chassis entry without a serial could be the member's own, and
        # blocks the pairing.
        repeat = dict(lone, **{"hw-dev-index": 2})
        blank = {"hw-type": "hw-type-chassis", "hw-dev-index": 2, "part-number": "C9500-24Y4C"}
        for extra, pairs in ((repeat, True), (blank, False)):
            _ctx, result = self._collect(
                stack_oper=None,
                hardware=_hardware((lone, extra)),
                inventory=inventory,
                detail=detail,
                summary="% Invalid input detected at '^' marker.",
            )
            self.assertEqual("serial" in result["normalized"]["switch|1"], pairs, extra)

    def test_lone_chassis_never_pairs_with_one_of_two_members(self):
        # A pair serving neither stack-oper nor show inventory, beside a
        # hardware inventory naming a single chassis: nothing says which
        # member it is, so neither gets it.
        detail = (
            "Switch/Stack Mac Address : 00a1.b2c3.1100 - Local Mac Address\n"
            "Switch#   Role    Mac Address     Priority Version  State \n"
            "*1       Active   00a1.b2c3.1100     15     V02     Ready\n"
            " 2       Standby  00a1.b2c3.2200     10     V02     Ready\n"
        )
        _ctx, result = self._collect(
            stack_oper=None,
            hardware=_hardware(_STACK_INVENTORY[:1]),
            inventory="% Invalid input detected at '^' marker.",
            detail=detail,
            summary="% Invalid input detected at '^' marker.",
        )
        for number in ("1", "2"):
            entry = result["normalized"]["switch|%s" % (number,)]
            self.assertNotIn("serial", entry)
            self.assertNotIn("model", entry)
        self.assertEqual(result["context"]["serial_source"], {"1": None, "2": None})
        self.assertIn(
            "switch 1, 2: no serial or model (no stack-oper serial-number; show inventory "
            "rejected; not a lone member beside a lone chassis entry)",
            result["raw"]["note"],
        )

    def test_provisioned_member_has_no_serial_or_model(self):
        # Member 4 is configured but absent: the roster lists it Provisioned
        # with no hardware version, its stack-node carries an empty serial and
        # no reload reason, and neither inventory knows it. Its entry keeps
        # what the roster says and nothing else; the note says why.
        detail = self.detail.replace(
            " 4       Member   00a1.b2c3.0400     6      V02     Ready",
            " 4       Member   0000.0000.0000     6              Provisioned",
        )
        self.assertNotEqual(detail, self.detail)
        node = self._nodes()[3]
        node.update(
            {
                "serial-number": "",
                "node-state": "state-provisioned",
                "mac-address": "00:00:00:00:00:00",
            }
        )
        del node["reload-reason"]
        inventory = self.inventory.split('NAME: "Switch 4"')[0]
        hardware = _hardware(_STACK_INVENTORY[:3] + _STACK_INVENTORY[4:])
        ctx, result = self._collect(hardware=hardware, inventory=inventory, detail=detail)
        self.assertIn("show inventory", ctx.commands)
        self.assertEqual(
            result["normalized"]["switch|4"],
            {"role": "Member", "state": "Provisioned", "priority": 6, "mac": "0000.0000.0000"},
        )
        self.assertEqual(result["normalized"]["switch|3"], _stack_members()["switch|3"])
        context = result["context"]
        self.assertIsNone(context["serial_source"]["4"])
        self.assertIsNone(context["model_source"]["4"])
        self.assertEqual(context["serial_source"]["3"], "stack-oper")
        self.assertEqual(context["members_ready"], 3)
        self.assertEqual(
            result["raw"]["note"],
            "switch 4: no serial or model (no stack-oper serial-number; show inventory names "
            "no Switch/Chassis entry for it; not a lone member beside a lone chassis entry)",
        )

    def test_replaced_member_is_a_serial_diff(self):
        # Member 3 swapped for a new chassis of the same model: its serial,
        # MAC and reload reason change, and nothing else about the members.
        # Joined by hw-dev-index, member 3 carried no serial at all and the
        # swap read as a MAC change only.
        diffcore = _loader.diffcore
        compare = registry.CHECKS["iosxe_switch_stack"].compare
        _ctx, pre = self._collect()
        post_oper = _loader.fixture_json("iosxe_stack_oper.json")
        post_oper["Cisco-IOS-XE-stack-oper:stack-oper-data"]["stack-node"][2].update(
            {
                "serial-number": "FOC0000A0B3",
                "mac-address": "00:a1:b2:c3:03:01",
                "reload-reason": "Reload Command",
            }
        )
        swapped = [
            dict(entry, **{"hw-dev-index": 22, "serial-number": "FOC0000A0B3"})
            if entry["serial-number"] == "FOC0000A003"
            else entry
            for entry in _STACK_INVENTORY
        ]
        detail = self.detail.replace("00a1.b2c3.0300", "00a1.b2c3.0301")
        _ctx, post = self._collect(stack_oper=post_oper, hardware=_hardware(swapped), detail=detail)
        diff = diffcore.diff_check(pre["normalized"], post["normalized"], compare)
        self.assertEqual(diff["result"], "diffs")
        self.assertEqual((diff["added"], diff["removed"]), ([], []))
        self.assertEqual(
            diff["changed"],
            [
                {
                    "key": "switch|3",
                    "field": "mac",
                    "old": "00a1.b2c3.0300",
                    "new": "00a1.b2c3.0301",
                },
                {
                    "key": "switch|3",
                    "field": "reload_reason",
                    "old": "Image Install",
                    "new": "Reload Command",
                },
                {"key": "switch|3", "field": "serial", "old": "FOC0000A003", "new": "FOC0000A0B3"},
            ],
        )

    def test_two_captures_of_an_unchanged_stack_diff_to_nothing(self):
        # Nothing changed on the device, but everything volatile in stack-oper
        # moved between the captures — port statistics and their timestamp,
        # keepalive counters, latency — and none of it may reach the diff.
        diffcore = _loader.diffcore
        compare = registry.CHECKS["iosxe_switch_stack"].compare
        _ctx, first = self._collect()
        self.stack_oper = _loader.fixture_json("iosxe_stack_oper.json")
        for node in self._nodes():
            node["latency"] = 120
            node["keepalive-counters"].update({"received": "4411", "sent": "4412"})
            for port in node["stack-ports"]:
                stats = port["sp-stats"]
                for counter in ("rac-copied", "rac-inserted"):
                    stats[counter] = str(int(stats[counter]) + 987654)
                port["sp-stats-time"] = "2026-09-26T04:00:00.000000+00:00"
        self.assertNotEqual(self.stack_oper, _loader.fixture_json("iosxe_stack_oper.json"))
        _ctx, second = self._collect()
        self.assertEqual(
            diffcore.diff_check(first["normalized"], second["normalized"], compare),
            {"result": "pass", "added": [], "removed": [], "changed": []},
        )
        self.assertEqual(first["context"], second["context"])

    def test_a_serial_source_change_moves_no_serial_or_model(self):
        # One capture from stack-oper, the next from show inventory after a
        # stack-oper outage: the sources differ (context only), the serials
        # and models do not; only the reload reasons go unmeasured, and
        # context's stack_oper says so.
        diffcore = _loader.diffcore
        compare = registry.CHECKS["iosxe_switch_stack"].compare
        _ctx, first = self._collect()
        _ctx, second = self._collect(stack_oper=None, inventory=self.inventory)
        diff = diffcore.diff_check(first["normalized"], second["normalized"], compare)
        self.assertEqual((diff["added"], diff["removed"]), ([], []))
        self.assertEqual(
            {(change["key"], change["field"], change["new"]) for change in diff["changed"]},
            {("switch|%d" % (number,), "reload_reason", None) for number in range(1, 5)},
        )
        self.assertNotEqual(first["context"]["serial_source"], second["context"]["serial_source"])
        self.assertEqual(
            (first["context"]["stack_oper"], second["context"]["stack_oper"]),
            ("served", "not served"),
        )

    def test_chassis_serial_on_no_member_is_noted(self):
        # A chassis entry no roster member carries (index 27): named by serial
        # and index in the note, never attached to a member.
        extra = _STACK_INVENTORY + (
            {
                "hw-type": "hw-type-chassis",
                "hw-dev-index": 27,
                "part-number": "C9300-48P",
                "serial-number": "FOC0000A009",
            },
        )
        ctx, result = self._collect(hardware=_hardware(extra))
        self.assertNotIn("show inventory", ctx.commands)
        for key, expected in _stack_members().items():
            self.assertEqual(result["normalized"][key], expected, key)
        self.assertEqual(
            result["raw"]["note"],
            "device-inventory chassis serials on no member: FOC0000A009 (hw-dev-index 27)",
        )

    def test_stack_oper_node_without_roster_member_is_noted(self):
        nodes = self._nodes()
        nodes.append(dict(nodes[3], **{"chassis-number": 5, "serial-number": "FOC0000A005"}))
        _ctx, result = self._collect()
        self.assertNotIn("switch|5", result["normalized"])
        self.assertEqual(
            result["raw"]["note"], "stack-oper chassis-numbers with no roster member: 5"
        )

    def test_show_inventory_rejected_leaves_identity_absent_and_says_why(self):
        _ctx, result = self._collect(
            stack_oper=None, inventory="% Invalid input detected at '^' marker."
        )
        for number in ("1", "2", "3", "4"):
            entry = result["normalized"]["switch|%s" % (number,)]
            self.assertNotIn("serial", entry)
            self.assertNotIn("model", entry)
        self.assertEqual(result["context"]["serial_source"], dict.fromkeys(("1", "2", "3", "4")))
        note = result["raw"]["note"]
        self.assertIn(
            "switch 1, 2, 3, 4: no serial or model (no stack-oper serial-number; show inventory "
            "rejected; not a lone member beside a lone chassis entry)",
            note,
        )
        self.assertIn(
            "device-inventory chassis serials on no member: FOC0000A001 (hw-dev-index 1), "
            "FOC0000A002 (hw-dev-index 8), FOC0000A003 (hw-dev-index 15), "
            "FOC0000A004 (hw-dev-index 20)",
            note,
        )

    def test_repeated_stack_oper_serial_names_no_member(self):
        # A release copying the active's serial-number onto every stack-node,
        # as the field release copies sp-stats: that serial names none of
        # them, so show inventory serves each member's own and a replacement
        # stays visible.
        for node in self._nodes():
            node["serial-number"] = "FOC0000A001"
        ctx, result = self._collect(inventory=self.inventory)
        self.assertIn("show inventory", ctx.commands)
        for key, expected in _stack_members().items():
            self.assertEqual(result["normalized"][key], expected, key)
        self.assertEqual(
            result["context"]["serial_source"],
            dict.fromkeys(("1", "2", "3", "4"), "show inventory"),
        )
        self.assertEqual(
            result["raw"]["note"],
            "stack-oper repeats serial-number FOC0000A001 on chassis-number 1, 2, 3, 4: used "
            "for none of them",
        )
        # Without show inventory, nothing is guessed.
        _ctx, result = self._collect(inventory="% Invalid input detected at '^' marker.")
        for key in _stack_members():
            self.assertNotIn("serial", result["normalized"][key])
        self.assertIn(
            "switch 1, 2, 3, 4: no serial or model (its stack-oper serial-number repeats on "
            "another stack-node; show inventory rejected; not a lone member beside a lone "
            "chassis entry)",
            result["raw"]["note"],
        )

    def test_one_serial_on_two_members_is_withdrawn_from_both(self):
        # stack-oper lacks member 4, and show inventory's 'Switch 4' carries
        # member 1's serial: the sources contradict each other, so neither
        # member keeps that serial (nor a model from it); the note says why.
        del self._nodes()[3]
        inventory = self.inventory.replace("SN: FOC0000A004", "SN: FOC0000A001")
        self.assertNotEqual(inventory, self.inventory)
        _ctx, result = self._collect(inventory=inventory)
        normalized = result["normalized"]
        for number in ("1", "4"):
            self.assertNotIn("serial", normalized["switch|%s" % (number,)])
            self.assertNotIn("model", normalized["switch|%s" % (number,)])
        self.assertEqual(normalized["switch|2"], _stack_members()["switch|2"])
        self.assertEqual(
            result["context"]["serial_source"],
            {"1": None, "2": "stack-oper", "3": "stack-oper", "4": None},
        )
        self.assertEqual(
            result["raw"]["note"],
            "switch 1, 4: no serial or model (one serial for more than one member: "
            "FOC0000A001); device-inventory chassis serials on no member: FOC0000A001 "
            "(hw-dev-index 1), FOC0000A004 (hw-dev-index 20)",
        )

    def test_serial_join_ignores_case(self):
        # A lower-case stack-oper serial still finds its chassis entry, and
        # reads upper-cased: a change of source never flips the spelling.
        self._nodes()[2]["serial-number"] = "foc0000a003"
        ctx, result = self._collect()
        self.assertNotIn("show inventory", ctx.commands)
        self.assertEqual(result["normalized"]["switch|3"], _stack_members()["switch|3"])

    def test_stack_oper_without_stack_nodes_falls_back_to_show_inventory(self):
        # stack-oper answers without a stack-node list: no serials or reload
        # reasons from it, show inventory serves the serials, and context
        # says the read came back empty.
        empty = {"Cisco-IOS-XE-stack-oper:stack-oper-data": {"stack-info": {"size": 4}}}
        ctx, result = self._collect(stack_oper=empty, inventory=self.inventory)
        self.assertIn("show inventory", ctx.commands)
        for key, expected in _stack_members().items():
            del expected["reload_reason"]
            self.assertEqual(result["normalized"][key], expected, key)
        self.assertEqual(result["context"]["stack_oper"], "served without stack-node entries")
        self.assertEqual(result["raw"]["note"], "stack-oper answered without stack-node entries")

    def test_show_inventory_failure_keeps_the_roster_and_ring(self):
        # stack-oper unserved and show inventory failing outright (a read
        # timeout): the members go without serial and model this capture, the
        # roster and ring survive, and the note says why.
        ctx, result = self._collect(
            stack_oper=None, raise_for={"show inventory": TimeoutError("Pattern not detected")}
        )
        self.assertEqual(ctx.commands[-1], "show inventory")
        normalized = result["normalized"]
        self.assertEqual(len(normalized), 13)
        self.assertEqual(normalized["stack-port|2/1"]["link_ok_changes"], 1)
        for key, expected in _stack_members().items():
            for field in ("serial", "model", "reload_reason"):
                del expected[field]
            self.assertEqual(normalized[key], expected, key)
        self.assertNotIn("show inventory", result["raw"])
        self.assertEqual(result["context"]["serial_source"], dict.fromkeys(("1", "2", "3", "4")))
        note = result["raw"]["note"]
        self.assertIn("show inventory failed (Pattern not detected)", note)
        self.assertIn(
            "switch 1, 2, 3, 4: no serial or model (no stack-oper serial-number; show inventory "
            "failed; not a lone member beside a lone chassis entry)",
            note,
        )

    def test_show_inventory_never_swallows_the_celery_abort_signal(self):
        class SoftTimeLimitExceeded(Exception):
            pass

        with self.assertRaises(SoftTimeLimitExceeded):
            self._collect(stack_oper=None, raise_for={"show inventory": SoftTimeLimitExceeded()})

    def test_collector_skips_when_platform_does_not_stack(self):
        ctx = _StackCtx({"show switch detail": "% Invalid input detected at '^' marker."})
        with self.assertRaises(checks.SkipCheck):
            checks._collect_switch_stack(ctx)
        self.assertEqual(ctx.commands, ["show switch detail"])

    def test_collector_fails_loudly_on_unparsed_member_table(self):
        garbled = (
            "Switch/Stack Mac Address : 00a1.b2c3.0100 - Local Mac Address\n"
            "Switch#   Role    Mac Address     Priority Version  State \n"
            " one      Active  not-a-mac          15     V02     Ready\n"
        )
        ctx = _StackCtx({"show switch detail": garbled})
        with self.assertRaises(checks.CollectError):
            checks._collect_switch_stack(ctx)

    def test_collector_without_member_table_is_not_present(self):
        ctx = _StackCtx({"show switch detail": "Switch stacking is not supported on this chassis"})
        with self.assertRaises(checks.SkipCheck):
            checks._collect_switch_stack(ctx)

    def test_summary_rejected_keeps_detail_ports_and_notes_it(self):
        _ctx, result = self._collect(
            stack_oper=None,
            inventory=self.inventory,
            summary="% Invalid input detected at '^' marker.",
        )
        self.assertEqual(result["normalized"]["stack-port|2/1"], {"status": "OK", "neighbor": 3})
        self.assertIn("stack-ports summary rejected", result["raw"]["note"])
        # No stack-oper payload (404) is a note, never a failure.
        self.assertIn("stack-oper not served", result["raw"]["note"])
        self.assertIsNone(result["raw"]["stack-oper"])

    def test_stack_oper_transport_failure_is_a_note(self):
        _ctx, result = self._collect(
            inventory=self.inventory,
            raise_for={checks._STACK_OPER_PATH: RuntimeError("HTTP 500")},
        )
        # 'stack' + 4 'switch|' + 8 'stack-port|' keys: the full view survives,
        # member serials from show inventory.
        self.assertEqual(len(result["normalized"]), 13)
        self.assertEqual(result["normalized"]["switch|3"]["serial"], "FOC0000A003")
        self.assertEqual(
            result["raw"]["note"],
            "stack-oper read failed (HTTP 500): no reload reasons, member serials from the "
            "fallbacks",
        )
        # Context tells this apart from a release that lacks the model.
        self.assertEqual(result["context"]["stack_oper"], "read failed")

    def test_stack_oper_never_swallows_the_celery_abort_signal(self):
        class SoftTimeLimitExceeded(Exception):
            pass

        with self.assertRaises(SoftTimeLimitExceeded):
            self._collect(raise_for={checks._STACK_OPER_PATH: SoftTimeLimitExceeded()})


class _InventoryCtx(_IfaceCtx):
    """_IfaceCtx whose SSH commands can be rejected on cue."""

    def run_ssh(self, command, **kwargs):
        self.commands.append(command)
        if command in self.raise_for:
            raise self.raise_for[command]
        return self.outputs[command]


class TestInventory(unittest.TestCase):
    CHASSIS = {
        "model": "C9500-48Y4C",
        "serial": "FCW0000A0AA",
        "description": "Cisco Catalyst 9500 Series Switch",
        "version": "V02",
    }

    def setUp(self):
        self.hardware = _loader.fixture_json("iosxe_device_hardware.json")

    def test_model_view_keys_and_classes(self):
        normalized, facts = checks._normalize_inventory(self.hardware)
        self.assertEqual(
            sorted(normalized),
            [
                "chassis|Chassis 1",
                "fan|Chassis 1 Fan Tray",
                # No dev-name: keyed by serial.
                "module|sn:FOC0000B101",
                # The hw-type-unknown row has neither name, serial nor part
                # number: counted in context unidentified, never keyed.
                "psu|Chassis 1 Power Supply Module 0",
                "psu|Chassis 1 Power Supply Module 1",
                "transceiver|TwentyFiveGigE1/0/1",
            ],
        )
        self.assertEqual(normalized["chassis|Chassis 1"], self.CHASSIS)
        # Serial padded and lower-cased by the encoder: stripped and upper-cased.
        self.assertEqual(normalized["psu|Chassis 1 Power Supply Module 0"]["serial"], "ART0000A001")
        # Blank leaves are None, not '' — a fan tray with no serial.
        self.assertEqual(
            normalized["fan|Chassis 1 Fan Tray"],
            {
                "model": "C9K-T1-FANTRAY",
                "serial": None,
                "description": "Cisco Catalyst 9500 Series Fan Tray",
                "version": None,
            },
        )
        self.assertEqual(
            facts,
            {
                "items_by_class": {
                    "chassis": 1,
                    "psu": 2,
                    "fan": 1,
                    "transceiver": 1,
                    "module": 1,
                    "other": 1,
                },
                "keyed_by_part_number": [],
                "unidentified": {"other": 1},
                # On-board parts are counted, never keyed: no cpu0 / disk0 rows.
                "internal_skipped": {"hw-type-cpu": 1, "hw-type-ssd": 1},
            },
        )
        for facts_ in normalized.values():
            self.assertEqual(sorted(facts_), ["description", "model", "serial", "version"])

    def test_model_view_never_keys_an_index(self):
        # Every key starts with its class and none carries the hw-dev-index:
        # renumbering the nameless, serial-less row (a reload re-walks the
        # inventory) diffs to nothing.
        normalized, _facts = checks._normalize_inventory(self.hardware)
        for key in normalized:
            self.assertRegex(key, r"^(chassis|module|psu|fan|transceiver|other)\|")
            self.assertNotIn("idx:", key)
        renumbered = _loader.fixture_json("iosxe_device_hardware.json")
        for entry in checks._inventory_entries(renumbered):
            if entry.get("hw-type") == "hw-type-unknown":
                entry["hw-dev-index"] = 11
        self.assertEqual(checks._normalize_inventory(renumbered)[0], normalized)

    def test_model_view_part_number_keys_and_ordinal_collisions(self):
        # No name, no serial, a part number: keyed on it and named in context.
        # Two such identical parts (fan trays) are told apart by an ordinal,
        # never by the index; a serial, when one of them has it, wins.
        entries = [
            {"hw-type": "hw-type-fantray", "hw-dev-index": 30, "part-number": "C9K-T1-FANTRAY"},
            {"hw-type": "hw-type-fantray", "hw-dev-index": 31, "part-number": "C9K-T1-FANTRAY"},
            {
                "hw-type": "hw-type-fantray",
                "hw-dev-index": 32,
                "part-number": "C9K-T1-FANTRAY",
                "hw-description": "spare",
            },
            {"hw-type": "hw-type-unknown", "hw-dev-index": 33},
            {"hw-type": "hw-type-pem", "hw-dev-index": 34, "hw-description": "blank slot"},
        ]
        normalized, facts = checks._normalize_inventory(_hardware(entries))
        # The second identical tray carries the same facts, so it folds into the
        # first key; the third differs (description) and gets the ordinal.
        self.assertEqual(sorted(normalized), ["fan|pn:C9K-T1-FANTRAY", "fan|pn:C9K-T1-FANTRAY|#2"])
        self.assertEqual(normalized["fan|pn:C9K-T1-FANTRAY|#2"]["description"], "spare")
        self.assertEqual(
            facts["keyed_by_part_number"], ["fan|pn:C9K-T1-FANTRAY", "fan|pn:C9K-T1-FANTRAY|#2"]
        )
        self.assertEqual(facts["unidentified"], {"other": 1, "psu": 1})
        self.assertEqual(facts["items_by_class"], {"fan": 3, "other": 1, "psu": 1})

    def test_model_view_stack_shape_and_collisions(self):
        # A 4-member stack whose chassis carry the physical indexes 1, 8, 15
        # and 20, dev-named 'Switch <n>'; a PEM sharing index 1 with a chassis;
        # two items with one dev-name are told apart by serial.
        entries = [
            {
                "hw-type": "hw-type-chassis",
                "hw-dev-index": idx,
                "part-number": "C9300-48UXM",
                "serial-number": "FOC0000A00%d" % (n,),
                "dev-name": "Switch %d" % (n,),
            }
            for n, idx in ((1, 1), (2, 8), (3, 15), (4, 20))
        ]
        entries.append(
            {
                "hw-type": "hw-type-pem",
                "hw-dev-index": 1,
                "part-number": "PWR-C1-1100WAC-P",
                "serial-number": "DTN0000A001",
                "dev-name": "Switch 1 - Power Supply A",
            }
        )
        entries.append(
            {
                "hw-type": "hw-type-pem",
                "hw-dev-index": 2,
                "part-number": "PWR-C1-1100WAC-P",
                "serial-number": "DTN0000A002",
                "dev-name": "Switch 1 - Power Supply A",
            }
        )
        normalized, facts = checks._normalize_inventory(_hardware(entries))
        self.assertEqual(
            sorted(normalized),
            [
                "chassis|Switch 1",
                "chassis|Switch 2",
                "chassis|Switch 3",
                "chassis|Switch 4",
                "psu|Switch 1 - Power Supply A",
                "psu|Switch 1 - Power Supply A|sn:DTN0000A002",
            ],
        )
        self.assertEqual(normalized["chassis|Switch 3"]["serial"], "FOC0000A003")
        self.assertEqual(facts["keyed_by_part_number"], [])
        self.assertEqual(facts["unidentified"], {})
        # Single-dict list, prefixed enum, unknown future hw-type -> other.
        payload = _hardware([{"hw-type": "m:hw-type-newthing", "hw-dev-index": 3, "dev-name": "x"}])
        payload_c = payload["Cisco-IOS-XE-device-hardware-oper:device-hardware-data"]
        payload_c["device-hardware"]["device-inventory"] = payload_c["device-hardware"][
            "device-inventory"
        ][0]
        self.assertEqual(list(checks._normalize_inventory(payload)[0]), ["other|x"])

    def test_cli_view_9300_stack(self):
        normalized, facts = checks._normalize_inventory_cli(
            _loader.fixture_text("iosxe_show_inventory_9300_stack.txt")
        )
        self.assertEqual(
            sorted(normalized),
            [
                "chassis|Switch 1",
                "chassis|Switch 2",
                "chassis|Switch 3",
                "chassis|Switch 4",
                "module|Switch 1 FRU Uplink Module 1",
                "module|Switch 2 FRU Uplink Module 1",
                "psu|Switch 1 - Power Supply A",
                "psu|Switch 1 - Power Supply B",
                "psu|Switch 2 - Power Supply A",
                "psu|Switch 3 - Power Supply A",
                "psu|Switch 4 - Power Supply A",
                "transceiver|Te1/1/1",
                "transceiver|Te2/1/1",
            ],
        )
        self.assertEqual(
            normalized["chassis|Switch 2"],
            {
                "model": "C9300-48UXM",
                "serial": "FOC0000A002",
                "description": "C9300-48UXM",
                "version": "V02",
            },
        )
        self.assertEqual(
            normalized["transceiver|Te1/1/1"],
            {
                "model": "SFP-10G-SR",
                "serial": "AGD0000C001",
                "description": "SFP-10GBase-SR",
                "version": "V03",
            },
        )
        # The stack-level pseudo entry (the active's PID and SN again) is skipped, by name.
        self.assertEqual(
            facts,
            {
                "items_by_class": {"chassis": 4, "psu": 5, "module": 2, "transceiver": 2},
                "keyed_by_part_number": [],
                "unidentified": {},
                "skipped": ["c93xx Stack"],
            },
        )

    def test_cli_view_9500_svl_pair(self):
        normalized, facts = checks._normalize_inventory_cli(
            _loader.fixture_text("iosxe_show_inventory_9500_svl.txt")
        )
        self.assertEqual(
            facts["items_by_class"], {"chassis": 2, "psu": 3, "fan": 2, "transceiver": 2}
        )
        self.assertEqual(facts["skipped"], [])
        # 'Power Supply Module' is a psu, not a module; a blank VID/SN is None.
        self.assertIn("psu|Chassis 2 Power Supply Module 0", normalized)
        self.assertEqual(
            normalized["fan|Chassis 2 Fan Tray"],
            {
                "model": "C9K-T1-FANTRAY",
                "serial": None,
                "description": "Cisco Catalyst 9500 Series Fan Tray",
                "version": None,
            },
        )
        self.assertEqual(normalized["chassis|Chassis 2"]["serial"], "FCW0000A0BB")
        # The two views name the same chassis serials the stack check joins on.
        cli_serials = {v["serial"] for k, v in normalized.items() if k.startswith("chassis|")}
        self.assertEqual(cli_serials, {"FCW0000A0AA", "FCW0000A0BB"})

    def test_cli_items_parser_and_member_parser_agree(self):
        output = _loader.fixture_text("iosxe_show_inventory_9300_stack.txt")
        items = checks._inventory_items(output)
        self.assertEqual(len(items), 14)  # the stack entry, 4 chassis, 5 PSUs, 2 modules, 2 optics
        self.assertEqual(
            items[1],
            {
                "name": "Switch 1",
                "descr": "C9300-48UXM",
                "pid": "C9300-48UXM",
                "vid": "V02",
                "sn": "FOC0000A001",
            },
        )
        # A PID line with no NAME before it is ignored; a NAME without DESCR parses.
        self.assertEqual(checks._inventory_items("PID: X , VID: , SN: 1\n"), [])
        self.assertEqual(
            checks._inventory_items('NAME: "Fan 1"\nPID: F , VID: , SN:\n'),
            [{"name": "Fan 1", "descr": "", "pid": "F", "vid": "", "sn": ""}],
        )
        # The stack check's member parser still reads the same output.
        members = checks._parse_show_inventory(output)
        self.assertEqual(members["2"], {"model": "C9300-48UXM", "serial": "FOC0000A002"})

    def test_collector_model_source(self):
        ctx = _InventoryCtx({checks._HW_PATH: self.hardware}, outputs={})
        result = checks._collect_inventory(ctx)
        # The platform-health GET, cached: same path, same kwargs; no SSH.
        self.assertEqual(ctx.gets, [(checks._HW_PATH, {})])
        self.assertEqual(ctx.commands, [])
        self.assertEqual(result["normalized"]["chassis|Chassis 1"], self.CHASSIS)
        self.assertEqual(result["context"]["source"], "device-inventory")
        self.assertEqual(result["context"]["unidentified"], {"other": 1})
        self.assertNotIn("keyed_by_index", result["context"])
        self.assertEqual(len(result["raw"]["device-inventory"]), 9)
        self.assertNotIn("note", result["raw"])
        self.assertEqual(
            _loader.diffcore.diff_check(
                result["normalized"],
                checks._collect_inventory(ctx)["normalized"],
                registry.CHECKS["iosxe_inventory"].compare,
            )["result"],
            "pass",
        )

    def test_collector_raw_cap(self):
        entries = [
            {"hw-type": "hw-type-transceiver", "hw-dev-index": i, "dev-name": "Te1/1/%d" % (i,)}
            for i in range(5)
        ]
        original = checks._INVENTORY_RAW_MAX
        checks._INVENTORY_RAW_MAX = 3
        try:
            result = checks._collect_inventory(_InventoryCtx({checks._HW_PATH: _hardware(entries)}))
        finally:
            checks._INVENTORY_RAW_MAX = original
        self.assertEqual(len(result["raw"]["device-inventory"]), 3)
        self.assertEqual(len(result["normalized"]), 5)

    def test_collector_empty_model_inventory_falls_back_to_cli(self):
        output = _loader.fixture_text("iosxe_show_inventory_9300_stack.txt")
        for name, entries in (
            ("no entries", []),
            ("internal only", [{"hw-type": "hw-type-cpu", "hw-dev-index": 1}]),
        ):
            with self.subTest(name):
                ctx = _InventoryCtx(
                    {checks._HW_PATH: _hardware(entries)}, outputs={"show inventory": output}
                )
                result = checks._collect_inventory(ctx)
                self.assertEqual(ctx.commands, ["show inventory"])
                self.assertEqual(result["context"]["source"], "show inventory")
                self.assertEqual(result["context"]["skipped"], ["c93xx Stack"])
                self.assertEqual(result["normalized"]["chassis|Switch 4"]["serial"], "FOC0000A004")
                self.assertIn("device-inventory served no", result["raw"]["note"])
                self.assertEqual(result["raw"]["show inventory"], output)

    def test_collector_empty_inventory_is_a_failed_read_never_not_present(self):
        empty = _hardware([])
        cases = (
            ("no SSH", _InventoryCtx({checks._HW_PATH: empty})),
            (
                "CLI rejected",
                _InventoryCtx(
                    {checks._HW_PATH: empty}, outputs={"show inventory": "% Invalid input"}
                ),
            ),
            ("CLI empty", _InventoryCtx({checks._HW_PATH: empty}, outputs={"show inventory": ""})),
            ("container missing", _InventoryCtx({checks._HW_PATH: {"other": {}}}, outputs={})),
            ("no reply", _InventoryCtx({}, outputs={})),
        )
        for name, ctx in cases:
            with self.subTest(name):
                with self.assertRaises(registry.CollectError):
                    checks._collect_inventory(ctx)
        # Transport failures propagate as they are: never a skip.
        ctx = _InventoryCtx({}, raise_for={checks._HW_PATH: RuntimeError("boom")}, outputs={})
        with self.assertRaises(RuntimeError):
            checks._collect_inventory(ctx)

    def test_registration(self):
        check = registry.CHECKS["iosxe_inventory"]
        self.assertEqual((check.tier, check.compare), (1, {"mode": "equality_set"}))
        self.assertIn("iosxe_switch_stack", registry.SEMANTICS["iosxe_inventory"])
        self.assertIn("iosxe_inventory", registry.SEMANTICS["iosxe_switch_stack"])
        self.assertIn("iosxe_inventory", registry.SEMANTICS["iosxe_platform_health"])


if __name__ == "__main__":
    unittest.main()
