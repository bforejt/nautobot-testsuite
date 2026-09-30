"""Real IOS-XE shapes, harvested from a Catalyst 9300 lab switch and sanitized.

Every ``*_lab`` fixture under tests/fixtures/ is a payload the device actually
returned (a single-member C9300-48UXM, harvested with tools/harvest_live.py
and run through tools/make_fixtures.py: invented serials and MACs,
documentation-range addresses, ``sw-lab-1`` / ``sw-lab-2`` / ``ap-lab-1`` for
the switch, the managed switch behind its trunk and its access point,
``netops`` for the user). The hand-built fixtures of the same name stay beside
them because they are richer (a four-member stack, voice VLANs, a non-root
bridge, a StackPower ring); this module pins what every normalizer reads from
the real ones, so a parser rewritten against the published model never drifts
from what a switch fills in. The ``*_lab_hairpin`` fixtures are the same
switch with one port hairpinned into the LAN its uplink sits on — the one
capture where the anomaly shapes (a root port, a MAC table seen twice, a
switch that is its own CDP neighbour) are real, used only in TestHairpin.

The ``xcc_*_lab.json`` fixtures are the same for a server's BMC: every
Redfish payload a gen-1 ThinkSystem SE350 on XCC 6.10 served to a ReadOnly
account (tools/harvest_live.py --platform bmc, which already passes each read
through the bmc family's redactors, then tools/make_fixtures.py: invented
serials, UUIDs and MACs, ``192.0.2.0/24`` for the management subnet,
``bmc-lab-1`` for the BMC's host name, ``netops`` for the capture account and
``user-lab-<n>`` for the other local accounts). The Bmc* classes below guard
them and pin what the bmc family reads from them.
No Nautobot, no network.
"""

import ipaddress
import json
import re
import unittest

if __package__:
    from . import _loader
    from .test_checks_bmc import _FakeCtx
else:  # unittest discover -s tests imports test modules as top-level
    import _loader
    from test_checks_bmc import _FakeCtx

checks = _loader.checks_iosxe
l2 = _loader.CHECK_MODULES["checks_iosxe_layer2"]
poe = _loader.CHECK_MODULES["checks_iosxe_poe"]
diffcore = _loader.diffcore
J = _loader.fixture_json
T = _loader.fixture_text

LAB_FIXTURES = sorted(
    path.name
    for path in _loader.FIXTURES.iterdir()
    if path.name.startswith("iosxe_") and "_lab" in path.name
)
BRIDGE_MAC = "44:01:e4:b4:5b:26"  # the sanitized chassis MAC, the same in every fixture
BRIDGE_MAC_DOTTED = "4401.e4b4.5b26"
UPLINK = "TwoGigabitEthernet1/0/1"  # access port in VLAN 2 toward the LAN the switch lives on
TRUNK_47 = "TenGigabitEthernet1/0/47"  # trunk, native 999, allowed 3-4,999, to the managed switch
TRUNK_48 = "TenGigabitEthernet1/0/48"  # trunk, native 1, allowed 1,3-4, to a silent switch
AP_PORT = "TwoGigabitEthernet1/0/14"


# What the sanitizer is allowed to have produced, by shape — an allow-list, so
# the guard names nothing real and a re-harvest from another device (a new
# serial, a new AP) is caught rather than waved through. The serials are the
# invented tokens the sanitize map produced for the lab harvest (chassis, PSU,
# stack member and licensing UDI); the hostnames are the --host targets (the
# access point's advertised name in full and as the LLDP model truncates it).
INVENTED_SERIALS = frozenset({"FOC8704M57A", "DCC0394P6GA", "FOC3364KXJL", "FOC91710ZLR"})
INVENTED_HOSTS = frozenset(
    {"sw-lab-1", "sw-lab-2", "ap-lab-1", "ap-lab-1.lab.example", "ap-lab-1.lab.example.net"}
)
_SERIAL = re.compile(r"(?<![A-Z0-9])[A-Z]{3}\d{4}[A-Z0-9]{4}(?![A-Z0-9])")
_QUAD = re.compile(r"(?<![\d.])\d{1,3}(?:\.\d{1,3}){3}(?![\d.])")
_DOTTED_MAC = re.compile(r"^[0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4}$")
# An IPv6 address; the sanitizer's targets are link-local (a rebuilt EUI-64
# identifier) and 2001:db8::/32, plus the prefixes that name nobody.
_IPV6 = re.compile(r"(?<![0-9A-Za-z:.])[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7}(?![0-9A-Za-z:.])")
_IPV6_ALLOWED = re.compile(r"^(?:fe80::|2001:db8:|ff0[0-9a-f]::|::)", re.IGNORECASE)
# Where a device names itself or a neighbor: the config's hostname line, the
# CLI's CDP/LLDP 'Device ID' and 'System Name', the models' device-id /
# system-name leaves.
_NAME_TOKENS = re.compile(
    r"(?:^hostname\s+(\S+)|Device ID:\s*(\S+)|System Name:\s*(\S+)"
    r"|\"(?:device-id|system-name)\":\s*\"([^\"]*)\")",
    re.MULTILINE,
)


class TestNothingRealSurvives(unittest.TestCase):
    """The leak guard: every identifier in a lab fixture is one the sanitizer invents."""

    def test_lab_fixtures_exist(self):
        self.assertGreater(len(LAB_FIXTURES), 60)
        self.assertEqual(len([n for n in LAB_FIXTURES if "_lab_hairpin" in n]), 3)

    def test_every_serial_address_and_name_is_an_invented_one(self):
        for name in LAB_FIXTURES:
            text = T(name)
            for serial in _SERIAL.findall(text):
                self.assertIn(serial, INVENTED_SERIALS, "%s: serial %s" % (name, serial))
            for quad in _QUAD.findall(text):
                self.assertTrue(_loader.allowed_lab_address(quad), "%s: %s" % (name, quad))
            for address in _IPV6.findall(text):
                if address.count(":") >= 2 and "::" in address or address.count(":") == 7:
                    self.assertRegex(address, _IPV6_ALLOWED, "%s: %s" % (name, address))
            for match in _NAME_TOKENS.finditer(text):
                token = next(group for group in match.groups() if group is not None)
                if not token or _DOTTED_MAC.match(token):
                    continue  # unnamed, or an LLDP neighbor named by its sanitized chassis MAC
                self.assertIn(token, INVENTED_HOSTS, "%s: name %s" % (name, token))
            # a certificate chain body is material, never a fixture
            self.assertIsNone(re.search(r"^\s+[0-9A-F]{8} [0-9A-F]{8} ", text, re.M), name)

    def test_the_same_chassis_mac_everywhere(self):
        stp, _ = l2._normalize_stp(J("iosxe_stp_details_lab.json"))
        self.assertEqual(stp["instance|VLAN0001"]["root_address"], BRIDGE_MAC)
        detail = checks._parse_switch_detail(T("iosxe_show_switch_detail_lab.txt"))
        self.assertEqual(detail[0]["mac"], BRIDGE_MAC_DOTTED)
        self.assertEqual(checks.common.mac_canonical(detail[0]["mac"]), BRIDGE_MAC)
        system = J("iosxe_device_system_data_lab.json")[
            "Cisco-IOS-XE-device-hardware-oper:device-system-data"
        ]
        self.assertEqual(system["mac-address"], BRIDGE_MAC)
        stack = J("iosxe_stack_oper_lab.json")["Cisco-IOS-XE-stack-oper:stack-oper-data"]
        self.assertEqual(stack["stack-info"]["stack-mac-address"], BRIDGE_MAC)

    def test_the_access_point_link_local_is_rebuilt_from_its_invented_mac(self):
        # The CDP model serves the AP's EUI-64 link-local: it must carry the
        # same invented MAC as neighbor-port-mac, never the real one.
        detail = J("iosxe_cdp_neighbors_lab.json")["Cisco-IOS-XE-cdp-oper:cdp-neighbor-details"][
            "cdp-neighbor-detail"
        ][0]
        mac = bytes.fromhex(detail["neighbor-port-mac"].replace(":", ""))
        eui64 = bytes([mac[0] ^ 0x02]) + mac[1:3] + b"\xff\xfe" + mac[3:6]
        expected = ipaddress.IPv6Address(b"\xfe\x80" + bytes(6) + eui64).compressed
        self.assertEqual(detail["ipv6-address"], expected)
        self.assertIn(expected.upper(), T("iosxe_show_cdp_neighbors_detail_lab.txt"))


class TestLayer2(unittest.TestCase):
    def test_vlans_ports_list_is_empty_and_vlan_interfaces_carries_every_port(self):
        normalized, context = l2._normalize_vlans(J("iosxe_vlan_oper_lab.json"))
        self.assertEqual(
            normalized,
            {
                "vlan|1": {"name": "default", "status": "active"},
                "vlan|2": {"name": "home-lab", "status": "active"},
                "vlan|3": {"name": "lab-hsrp", "status": "active"},
                "vlan|4": {"name": "lab-vrrp", "status": "active"},
                "vlan|999": {"name": "lab-native", "status": "active"},
                "vlan|1002": {"name": "fddi-default", "status": "suspend"},
                "vlan|1003": {"name": "token-ring-default", "status": "suspend"},
                "vlan|1004": {"name": "fddinet-default", "status": "suspend"},
                "vlan|1005": {"name": "trnet-default", "status": "suspend"},
            },
        )
        # The device fills vlan-interfaces (access ports AND the trunks, up or
        # down) and leaves ports empty: the field answer to plan §9 item 9.
        self.assertEqual(context["ports"], {})
        self.assertEqual(context["ports_listed"], 0)
        self.assertEqual(context["vlan_interfaces_listed"], 49)
        self.assertFalse(context["lists_agree"])
        # A trunk is listed under VLAN 1 only — not under its native VLAN
        # (Te1/0/47's is 999) and not under its allowed VLANs: trunk
        # membership is not in this model, 'show interfaces trunk' is. Access
        # ports list their VLAN, up or down; the port-channel is absent.
        self.assertEqual(context["vlan_interfaces"][TRUNK_47], [1])
        self.assertEqual(context["vlan_interfaces"][TRUNK_48], [1])
        self.assertEqual(context["vlan_interfaces"]["TwoGigabitEthernet1/0/22"], [1])
        self.assertEqual(context["vlan_interfaces"]["TwoGigabitEthernet1/0/20"], [3])
        self.assertEqual(context["vlan_interfaces"][UPLINK], [2])
        self.assertNotIn("Port-channel1", context["vlan_interfaces"])
        self.assertEqual(
            (context["vlan_total"], context["active"], context["suspended"]), (9, 5, 4)
        )

    def test_vtp_status_v1_layout(self):
        self.assertEqual(
            l2._parse_vtp_status(T("iosxe_show_vtp_status_lab.txt")),
            {
                "mode": "server",
                "domain": "",
                "pruning": False,
                "revision": 4,
                "version": 1,
                "existing_vlans": 9,
            },
        )

    def test_trunk_table_with_two_trunks(self):
        rows = l2._parse_interfaces_trunk(T("iosxe_show_interfaces_trunk_lab.txt"))
        self.assertEqual(
            rows,
            {
                "Te1/0/47": {
                    "mode": "on",
                    "encapsulation": "802.1q",
                    "status": "trunking",
                    "native_vlan": 999,
                    "allowed": "3-4,999",
                    "active": "3-4,999",
                    "forwarding": "3-4,999",
                },
                "Te1/0/48": {
                    "mode": "on",
                    "encapsulation": "802.1q",
                    "status": "trunking",
                    "native_vlan": 1,
                    "allowed": "1,3-4",
                    "active": "1,3-4",
                    "forwarding": "1,3-4",
                },
            },
        )
        self.assertEqual(
            l2._trunk_context(rows),
            {
                "trunk_total": 2,
                "trunking": 2,
                "forwarding_vlans": {"Te1/0/47": 3, "Te1/0/48": 3},
                "active_not_forwarding": {},
            },
        )

    def test_stp_root_bridge_with_raised_priority_keys_no_ports(self):
        normalized, context = l2._normalize_stp(J("iosxe_stp_details_lab.json"))
        self.assertEqual(
            normalized["stp"],
            {
                "mode": "rapid-pvst",
                "bridge_assurance": True,
                "loop_guard": False,
                "bpdu_guard": False,
                "bpdu_filter": False,
                "etherchannel_misconfig_guard": True,
                "mst_name": "",
                "mst_revision": 0,
                "mst_max_hops": 20,
            },
        )
        for vlan in (1, 2, 3, 4):
            self.assertEqual(
                normalized["instance|VLAN%04d" % vlan],
                {
                    "bridge_priority": 61440 + vlan,
                    "root_address": BRIDGE_MAC,
                    "root_priority": 61440 + vlan,
                    "root_cost": 0,
                    "is_root": True,
                },
            )
        # the native VLAN of the new trunk runs at the default priority
        self.assertEqual(
            normalized["instance|VLAN0999"],
            {
                "bridge_priority": 32768 + 999,
                "root_address": BRIDGE_MAC,
                "root_priority": 32768 + 999,
                "root_cost": 0,
                "is_root": True,
            },
        )
        # every port is designated-forwarding: no port keys, counts in context
        self.assertFalse([key for key in normalized if key.startswith("port|")])
        self.assertEqual(context["ports_by_role"], {"designated": 10})
        self.assertEqual(context["ports_by_state"], {"forwarding": 10})
        self.assertEqual(context["disabled_ports_listed"], 0)
        self.assertEqual(context["instances"]["VLAN0001"]["designated_forwarding"], 3)
        self.assertEqual(context["instances"]["VLAN0999"]["ports"], 1)

    def test_mac_table_buckets_and_the_vlan_independent_table(self):
        normalized, context, rows = l2._normalize_mac_table(J("iosxe_matm_table_lab.json"))
        self.assertEqual(
            normalized,
            {
                "total": 52,
                "vlan|1": 1,
                "vlan|2": 50,
                "vlan|999": 1,
                "member|1": 52,
                "port|" + UPLINK: 50,
                "port|" + AP_PORT: 1,
                "port|" + TRUNK_47: 1,
            },
        )
        self.assertEqual(context["by_type"], {"dynamic": 52, "static": 27})
        self.assertEqual(context["by_table_type"], {"vlan": 58, "vlan-independent": 21})
        self.assertEqual(context["aging_time"], 300)
        self.assertEqual(context["port_name_form"], "long")
        # group addresses are not identifying and survive sanitizing verbatim
        self.assertIn(
            {
                "mac": "01:00:0c:cc:cc:cc",
                "port": "CPU",
                "table": "vlan-independent",
                "type": "static",
                "vlan": 1,
            },
            rows,
        )
        static_ports = {row["port"] for row in rows if row["type"] == "static"}
        self.assertIn("TwoGigabitEthernet1/0/21", static_ports)  # the configured static entry

    def test_lacp_model_lists_the_bundle_with_both_members_down(self):
        data = J("iosxe_lacp_oper_lab.json")["Cisco-IOS-XE-lacp-oper:lag-oper-data"]
        self.assertEqual(
            [
                (g["channel-group"], g["total-no-of-links"], g["port-channel-up"])
                for g in data["lag-info"]
            ],
            [(1, 2, False)],
        )
        members = data["lacp-port-channel"][0]["lacp-member-state"]
        self.assertEqual(
            [(m["if-name"], m["state"], m["partner-id"]) for m in members],
            [
                ("TwoGigabitEthernet1/0/22", "lacp-down", "00:00:00:00:00:00"),
                ("TwoGigabitEthernet1/0/23", "lacp-down", "00:00:00:00:00:00"),
            ],
        )
        self.assertEqual({m["system-id"] for m in members}, {BRIDGE_MAC})


class TestPoe(unittest.TestCase):
    def test_single_member_upoe_switch_with_one_access_point(self):
        payload = J("iosxe_poe_oper_lab.json")
        self.assertEqual(
            poe._normalize_poe(payload),
            {
                "port|" + AP_PORT: {"admin": "auto", "oper": "on", "class": "ieee4"},
                "stack|Powerstack-1": {
                    "mode": "sharing",
                    "topology": "standalone",
                    "switches": 1,
                    "supplies": 1,
                    "total_watts": 1100,
                },
                "switch|1": {"port_one": "not-connected", "port_two": "not-connected"},
            },
        )
        # The device fills poe-port-detail (plan §9 item 13) for the ONE
        # powered port only: unpowered PoE-capable ports are absent from the
        # model, and the module's num-ports says how many there are.
        detail = payload["Cisco-IOS-XE-poe-oper:poe-oper-data"]["poe-port-detail"]
        self.assertEqual([row["intf-name"] for row in detail], [AP_PORT])
        self.assertNotIn("poe-port", payload["Cisco-IOS-XE-poe-oper:poe-oper-data"])
        context = poe._poe_context(payload)
        self.assertEqual((context["ports_total"], context["poe_ports"]), (1, 48))
        self.assertEqual(context["module|1"]["free_ports"], 47)


class TestInterfaces(unittest.TestCase):
    def setUp(self):
        self.normalized = checks._normalize_interfaces(J("iosxe_interfaces_oper_lab.json"))

    def test_every_leaf_of_the_widened_filter_is_served(self):
        self.assertEqual(len(self.normalized), 71)
        for trunk in (TRUNK_47, TRUNK_48):
            facts = self.normalized[trunk]
            self.assertEqual(
                (facts["speed"], facts["duplex"], facts["oper"]),
                ("speed-2500mb", "full-duplex", "if-oper-state-ready"),
            )
            self.assertEqual(facts["mtu"], 1500)
        ap_port = self.normalized[AP_PORT]
        self.assertEqual(
            (ap_port["speed"], ap_port["duplex"], ap_port["mgig_downshift"]),
            ("speed-1gb", "full-duplex", False),
        )
        svi = self.normalized["Vlan3"]
        self.assertEqual(
            (svi["ipv4"], svi["mask"], svi["acl_in"], svi["acl_out"]),
            ("203.0.113.2", "255.255.255.0", "LAB-V3-IN", None),
        )
        self.assertEqual(self.normalized["Vlan2"]["mask"], "255.255.254.0")
        self.assertEqual(self.normalized["TwoGigabitEthernet1/0/20"]["qos_in"], "LAB-MARK")
        bundle = self.normalized["Port-channel1"]
        self.assertEqual(
            (bundle["oper"], bundle["speed"], bundle["duplex"]),
            ("if-oper-state-lower-layer-down", None, None),
        )
        for facts in self.normalized.values():
            self.assertEqual(
                set(facts),
                {
                    "admin",
                    "oper",
                    "ipv4",
                    "mask",
                    "vrf",
                    "ipv6",
                    "mtu",
                    "acl_in",
                    "acl_out",
                    "qos_in",
                    "qos_out",
                    "speed",
                    "duplex",
                    "autoneg",
                    "mgig_downshift",
                    "storm",
                },
            )
            self.assertEqual(facts["storm"], [])

    def test_errdisable_reads_the_extended_state_of_every_port(self):
        normalized, ext_states = checks._normalize_errdisable(J("iosxe_interfaces_oper_lab.json"))
        self.assertEqual(normalized, {})
        self.assertEqual(len(ext_states), 71)
        self.assertEqual(
            ext_states["GigabitEthernet1/1/1"],
            {"error-type": "port-error-none", "port-error-reason": "port-err-none"},
        )
        self.assertEqual(
            checks._parse_errdisable(T("iosxe_show_interfaces_status_err_disabled_lab.txt")), {}
        )

    def test_a_single_interface_read_is_a_one_element_list(self):
        # interfaces/interface=<name> answers the list entry wrapped in a list
        for name, fixture in (
            (TRUNK_48, "iosxe_interface_trunk_port_lab.json"),
            (AP_PORT, "iosxe_interface_wap_port_lab.json"),
            ("Vlan3", "iosxe_interface_svi_lab.json"),
        ):
            rows = J(fixture)["Cisco-IOS-XE-interfaces-oper:interface"]
            self.assertEqual([row["name"] for row in rows], [name])
            self.assertIn("statistics", rows[0])


class TestPlatform(unittest.TestCase):
    def test_platform_health_on_a_9300(self):
        normalized, context = checks._normalize_platform_health(
            J("iosxe_device_hardware_lab.json"), J("iosxe_environment_sensors_lab.json")
        )
        self.assertEqual(
            normalized["last-reboot"], {"reason": "Image Install", "severity": "normal"}
        )
        # The epoch second (the check's compare tolerates 60 s of the
        # device's own jitter), the served string in context.
        self.assertEqual(normalized["boot-time"], {"epoch": 1790703284, "text": None})
        self.assertEqual(context["boot_time"], "2026-09-29T17:34:44+00:00")
        states = {
            key: facts["state"] for key, facts in normalized.items() if key.startswith("env|")
        }
        # This release serves Norm / Shut (older ones spelled the same
        # sensors GREEN / Normal / Shutdown): one vocabulary in the key, the
        # served word in context.
        self.assertEqual(
            states,
            {
                "env|Switch 1/Inlet Temp Sensor": "normal",
                "env|Switch 1/Outlet Temp Sensor": "normal",
                "env|Switch 1/HotSpot Temp Sensor": "normal",
                "env|Switch 1/FAN - T1 1": "normal",
                "env|Switch 1/FAN - T1 2": "normal",
                "env|Switch 1/FAN - T1 3": "normal",
                "env|Switch 1/Power Supply A": "normal",
                "env|Switch 1/Power Supply B": "shutdown",
            },
        )
        self.assertEqual(context["env_states"]["env|Switch 1/Power Supply B"], "Shut")
        self.assertEqual(context["env_states"]["env|Switch 1/Inlet Temp Sensor"], "Norm")
        self.assertEqual(context["reboot_leaves_not_served"], [])
        self.assertEqual(
            context["readings"]["env|Switch 1/Inlet Temp Sensor"],
            {"reading": 28, "units": "celsius"},
        )
        self.assertEqual(
            context["readings"]["env|Switch 1/Power Supply A"], {"reading": 0, "units": "watts"}
        )

    def test_device_system_data_serves_the_unsaved_config_leaf_and_reload_history(self):
        data = J("iosxe_device_system_data_lab.json")[
            "Cisco-IOS-XE-device-hardware-oper:device-system-data"
        ]
        self.assertEqual(
            set(data),
            {
                "current-time",
                "boot-time",
                "software-version",
                "rommon-version",
                "last-reboot-reason",
                "reason-severity",
                "unsaved-config",
                "reload-history-support",
                "reload-history",
                "mac-address",
            },
        )
        self.assertIs(data["unsaved-config"], False)
        self.assertEqual(data["rommon-version"], "IOS-XE ROMMON")  # a literal, not a version
        self.assertTrue(data["software-version"].startswith("Cisco IOS Software [IOSXE]"))
        history = data["reload-history"]["rl-history"]
        self.assertEqual(
            [(h["reload-category"], h["reload-desc"], h["reload-severity"]) for h in history],
            [("rc-img-install", "Image Install", "normal"), ("rc-other", "PowerOn", "abnormal")],
        )

    def test_inventory_from_the_model_and_from_the_cli_agree(self):
        model, model_facts = checks._normalize_inventory(J("iosxe_device_hardware_lab.json"))
        cli, cli_facts = checks._normalize_inventory_cli(T("iosxe_show_inventory_9300_lab.txt"))
        self.assertEqual(model, cli)
        self.assertEqual(
            set(model),
            {
                "chassis|Switch 1",
                "module|Switch 1 FRU Uplink Module 1",
                "psu|Switch 1 - Power Supply A",
            },
        )
        self.assertEqual(model["chassis|Switch 1"]["model"], "C9300-48UXM")
        self.assertRegex(model["chassis|Switch 1"]["serial"], r"^FOC\d{4}[A-Z0-9]{4}$")
        self.assertEqual(
            model_facts["internal_skipped"],
            {"hw-type-cpu": 1, "hw-type-dram": 1, "hw-type-emmc": 1},
        )
        self.assertEqual(cli_facts["skipped"], ["c93xx Stack"])

    def test_single_member_stack_views(self):
        detail = checks._parse_switch_detail(T("iosxe_show_switch_detail_lab.txt"))
        self.assertEqual(
            detail[1],
            {
                "1": {
                    "hw_version": "V02",
                    "mac": BRIDGE_MAC_DOTTED,
                    "priority": 15,
                    "role": "Active",
                    "state": "Ready",
                }
            },
        )
        self.assertEqual(
            detail[2],
            {
                "1/1": {"neighbor": "None", "status": "DOWN"},
                "1/2": {"neighbor": "None", "status": "DOWN"},
            },
        )
        ports = checks._parse_stack_ports_summary(
            T("iosxe_show_switch_stack_ports_summary_lab.txt")
        )
        self.assertEqual(ports["1/1"]["cable"], "No cable")
        self.assertEqual(ports["1/2"]["neighbor"], "NONE/NONE")
        stack = J("iosxe_stack_oper_lab.json")["Cisco-IOS-XE-stack-oper:stack-oper-data"]
        self.assertEqual(len(stack["stack-node"]), 1)
        self.assertIs(stack["stack-node"][0]["sso-ready-flag"], False)
        self.assertEqual(
            (stack["stack-info"]["size"], stack["stack-info"]["ring-status"]), (1, "standalone")
        )
        self.assertEqual(
            checks._parse_etherchannel(T("iosxe_show_etherchannel_summary_lab.txt")),
            {
                "Po1": {
                    "flags": "SD",
                    "protocol": "LACP",
                    "members": {"Tw1/0/22": "D", "Tw1/0/23": "D"},
                }
            },
        )
        svl = J("iosxe_svl_oper_locations_only_lab.json")[
            "Cisco-IOS-XE-switch-cp-svl-oper:switch-cp-svl-oper-data"
        ]
        self.assertEqual(
            svl, {"location": [{"fru": "fru-fp", "slot": 0, "bay": 0, "chassis": 1, "node": 0}]}
        )

    def test_ha_and_install_state(self):
        ha = J("iosxe_ha_oper_lab.json")["Cisco-IOS-XE-ha-oper:ha-oper-data"]["ha-infra"]
        self.assertEqual(
            (ha["ha-state"], ha["peer-state"], ha["ha-enabled"], ha["has-switchover-occured"]),
            ("db-rf-active", "db-rf-disabled", False, False),
        )
        rows = J("iosxe_install_location_information_lab.json")[
            "Cisco-IOS-XE-install-oper:install-location-information"
        ]
        self.assertEqual(
            [(r["fru"], r["slot"], r["bay"], r["chassis"]) for r in rows], [("fru-rp", 0, 0, 1)]
        )
        versions = {v["version"]: v["current"] for v in rows[0]["install-version-info"]}
        # the committed running image beside an older image left on flash
        self.assertEqual(
            versions,
            {
                "17.15.06.0.770": "install-version-state-provisioned-committed",
                "17.12.04.0.5766": "install-version-state-present",
            },
        )
        self.assertEqual(
            rows[0]["oper-state"],
            {
                "auto-abort-timer": {"state": "install-timer-state-inactive"},
                "boot-mode": "install-boot-mode-install",
            },
        )
        # the rec-1 fields filter was accepted and this release fills commit-type
        self.assertEqual(
            [v["commit-type"] for v in rows[0]["install-version-info"]],
            ["install-commit-user", "install-commit-pend"],
        )

    def test_licence_state_and_usage(self):
        state = J("iosxe_smart_license_state_lab.json")["cisco-smart-license:state"]
        self.assertEqual(
            [u["license-name"] for u in state["state-info"]["usage"]],
            ["network-essentials", "dna-essentials"],
        )
        self.assertEqual(
            state["state-info"]["registration"]["registration-state"], "reg-state-not-registered"
        )
        self.assertRegex(state["state-info"]["udi"]["sn"], r"^FOC\d{4}[A-Z0-9]{4}$")
        self.assertIn("network-essentials", T("iosxe_show_license_summary_lab.txt"))
        self.assertIn("Access template", T("iosxe_show_sdm_prefer_lab.txt"))


class TestLayer3AndNeighbors(unittest.TestCase):
    def test_rib_fib_and_rollups(self):
        rib = checks._normalize_rib(J("iosxe_rib_routing_state_lab.json"))
        self.assertEqual(
            rib["default|0.0.0.0/0"],
            {
                "next_hops": [{"interface": "", "ip": "192.0.2.1"}],
                "preference": 254,
                "protocol": "static",
            },
        )
        self.assertEqual(rib["default|203.0.113.0/24"]["protocol"], "direct")
        self.assertEqual(
            checks._normalize_route_rollups(J("iosxe_rib_routing_state_lab.json")),
            {"direct": 10, "static": 1, "total": 11},
        )
        self.assertEqual(
            checks._parse_route_summary(T("iosxe_route_summary_lab.txt")),
            {
                "ospf_intra": 0,
                "ospf_inter": 0,
                "ospf_e1": 0,
                "ospf_e2": 0,
                "ospf_n1": 0,
                "ospf_n2": 0,
            },
        )
        fib = checks._normalize_fib(J("iosxe_fib_oper_lab.json"))
        self.assertEqual(
            fib["IPv4:Default|0.0.0.0/0"],
            {"next_hops": [{"interface": "Vlan2", "ip": "192.0.2.1/32"}]},
        )
        self.assertIn("IPv4:Mgmt-vrf|0.0.0.0/0", fib)

    def test_arp_is_read_from_arp_entry_and_the_flat_list_carries_the_same_rows(self):
        # This release fills both per-VRF lists with the same eight rows; the
        # view reads arp-entry first and context names the list it read.
        payload = J("iosxe_arp_oper_lab.json")
        vrfs = payload["Cisco-IOS-XE-arp-oper:arp-data"]["arp-vrf"]
        self.assertEqual(
            [(v["vrf"], len(v.get("arp-entry", [])), len(v.get("arp-oper", []))) for v in vrfs],
            [("Default", 8, 8), ("Mgmt-vrf", 0, 0)],
        )
        normalized = checks._normalize_arp(payload)
        self.assertEqual(len(normalized), 8)
        self.assertEqual(normalized["Default|198.18.4.1"]["mac"], "00:00:5e:00:01:04")  # VRRP
        self.assertEqual(normalized["Default|203.0.113.2"]["interface"], "Vlan3")
        self.assertEqual(
            checks._arp_context(payload), {"source": "arp-entry", "entries": 8, "vrfs": 2}
        )

    def test_lldp_names_the_neighbor_by_its_system_name_or_its_chassis_mac(self):
        # The access point advertises a system name (the model truncates it
        # to 20 characters); the managed switch on two ports advertises none
        # and is named by its chassis MAC, the same on both.
        self.assertEqual(
            checks._normalize_lldp(J("iosxe_lldp_entries_lab.json")),
            {
                "lldp|ap-lab-1.lab.example|Tw1/0/14": {"port": "Gi0"},
                "lldp|c092.2a31.3508|Te1/0/47": {"port": "MGI8"},
                "lldp|c092.2a31.3508|Tw1/0/1": {"port": "MGI10"},
            },
        )
        self.assertIn("ap-lab-1.lab.example.net", T("iosxe_show_lldp_neighbors_detail_lab.txt"))
        # cdp-oper lists the AP alone (the managed switch has CDP off toward
        # us and the silent switch on Te1/0/48 sends nothing)
        self.assertEqual(
            checks._normalize_cdp(J("iosxe_cdp_neighbors_lab.json")),
            {
                "cdp|2041|TwoGigabitEthernet1/0/14": {
                    "caps": "Trans-Bridge Source-Route-Bridge IGMP ",
                    "duplex": "cdp-full-duplex",
                    "native_vlan": None,
                    "platform": "cisco AIR-CAP3702I-B-K9",
                    "port": "GigabitEthernet0",
                    "voice_vlan": None,
                }
            },
        )
        self.assertIn("ap-lab-1", T("iosxe_show_cdp_neighbors_detail_lab.txt"))

    def test_routing_protocols_without_adjacencies(self):
        self.assertEqual(checks._normalize_ospf_neighbors(J("iosxe_ospf_oper_lab.json")), {})
        self.assertEqual(checks._normalize_bgp_peers(J("iosxe_bgp_neighbors_lab.json")), {})
        full = J("iosxe_ospf_oper_full_lab.json")["Cisco-IOS-XE-ospf-oper:ospf-oper-data"]
        self.assertEqual(set(full), {"ospf-state", "ospfv2-instance"})
        # router-id is served as an integer: the sanitizer maps it as an address
        self.assertEqual(
            checks._ospf_context(J("iosxe_ospf_oper_lab.json"))["instances"]["1|default"][
                "router_id"
            ],
            "203.0.113.2",
        )
        eigrp = J("iosxe_eigrp_oper_lab.json")["Cisco-IOS-XE-eigrp-oper:eigrp-oper-data"][
            "eigrp-instance"
        ]
        self.assertEqual(
            [(i["as-num"], sorted(x["name"] for x in i["eigrp-interface"])) for i in eigrp],
            [(1, ["Vlan3", "Vlan4"])],
        )
        self.assertNotIn("eigrp-nbr", eigrp[0])
        bgp = J("iosxe_bgp_state_data_lab.json")["Cisco-IOS-XE-bgp-oper:bgp-state-data"]
        self.assertEqual(set(bgp), {"bgp-route-rds", "bgp-route-vrfs"})
        self.assertIn("Invalid input", T("iosxe_show_standby_brief_refused_lab.txt"))
        self.assertIn("Invalid input", T("iosxe_show_isis_neighbors_refused_lab.txt"))
        # advertised models with nothing configured answer an empty container
        for fixture in ("iosxe_hsrp_oper_lab.json", "iosxe_isis_oper_lab.json"):
            self.assertEqual(J(fixture), {}, fixture)

    def test_vrrp_master_and_the_protocol_virtual_mac(self):
        state = J("iosxe_vrrp_oper_lab.json")["Cisco-IOS-XE-vrrp-oper:vrrp-oper-data"][
            "vrrp-oper-state"
        ]
        self.assertEqual(len(state), 1)
        group = state[0]
        self.assertEqual(
            (group["if-name"], group["group-id"], group["version"], group["vrrp-state"]),
            ("Vlan4", 4, "vrrp-v3", "proto-state-master"),
        )
        self.assertEqual(
            (
                group["virtual-ip"],
                group["master-ip"],
                group["priority"],
                group["preempt"],
                group["is-owner"],
            ),
            ("198.18.4.1", "198.18.4.2", 110, True, False),
        )
        self.assertEqual(
            group["virtual-mac"], "00:00:5e:00:01:04"
        )  # IANA VRRP block, never rewritten
        self.assertEqual(group["master-transitions"], 1)

    def test_ntp_oper_fills_refid_stratum_and_peer_selection(self):
        status = J("iosxe_ntp_oper_lab.json")["Cisco-IOS-XE-ntp-oper:ntp-oper-data"][
            "ntp-status-info"
        ]
        self.assertEqual(status["stratum"], 2)
        self.assertIn("ip-addr", status["refid"])
        selections = [a["peer-selection-status"] for a in status["ntp-associations"]]
        self.assertEqual(selections.count("ntp-peer-sys-peer"), 1)
        self.assertEqual(len(selections), 3)
        normalized = checks._normalize_ntp(J("iosxe_ntp_oper_lab.json"))
        self.assertEqual((normalized["stratum"], normalized["synchronized"]), (2, True))
        self.assertIn("Clock is synchronized", T("iosxe_show_ntp_status_lab.txt"))


class TestIdentityAndConfig(unittest.TestCase):
    def test_identity_and_port_security_reads_are_empty_containers_without_sessions(self):
        self.assertEqual(J("iosxe_identity_session_context_lab.json"), {})
        self.assertEqual(J("iosxe_psecure_oper_lab.json"), {})
        self.assertEqual(J("iosxe_poe_health_oper_lab.json"), {})

    def test_config_text_is_redacted_sanitized_and_free_of_certificate_bodies(self):
        running = T("iosxe_show_running_config_lab.txt")
        self.assertIn("username netops", running)
        # the transport's redactor masked the account in both header lines
        # before the text reached the trace; the clocks stay
        self.assertRegex(
            running, r"Last configuration change at \d\d:\d\d:\d\d UTC .* by \*\*\*scrubbed\*\*\*"
        )
        self.assertEqual(running.count("***scrubbed***"), 4)
        self.assertIsNone(re.search(r"^\s+[0-9A-F]{8} [0-9A-F]{8}", running, re.MULTILINE))
        self.assertGreater(running.count("<hex:"), 40)
        self.assertNotIn("CANARY", running)
        self.assertEqual(checks._redact_config_text(running), running)  # already clean: a no-op
        startup = T("iosxe_show_startup_config_lab.txt")
        self.assertIn("spanning-tree vlan 1-4 priority 61440", startup)
        self.assertIn("switchport trunk native vlan 999", startup)

    def test_show_logging_is_the_real_buffer(self):
        counts = checks._parse_syslog_errors(T("iosxe_show_logging.txt"))
        self.assertEqual(counts["sev1|%SELINUX-1-VIOLATION"], {"count": 228})
        self.assertEqual(counts["sev4|%CDP-4-NATIVE_VLAN_MISMATCH"], {"count": 48})
        text = T("iosxe_show_logging.txt")
        self.assertNotIn("[user: ", text.replace("[user: ***scrubbed***]", ""))


class TestHairpin(unittest.TestCase):
    """The same switch with Te1/0/47 as an access port hairpinned into the LAN its
    Tw1/0/1 uplink sits on: the one capture where the anomaly shapes are real."""

    def test_self_echoed_bpdus_key_a_root_port_on_the_root_bridge(self):
        normalized, context = l2._normalize_stp(J("iosxe_stp_details_lab_hairpin.json"))
        # VLAN 2 hears the bridge's own VLAN-1 BPDUs (priority 61441) through
        # the hairpin: the root address is this bridge's MAC, yet the instance
        # carries a root cost and a root port — the self-echo signature.
        self.assertEqual(
            normalized["instance|VLAN0002"],
            {
                "bridge_priority": 61442,
                "root_address": BRIDGE_MAC,
                "root_priority": 61441,
                "root_cost": 8000,
                "root_port": UPLINK,
                "is_root": True,
            },
        )
        self.assertEqual(
            normalized["port|VLAN0002|" + UPLINK],
            {
                "role": "root",
                "state": "forwarding",
                "guard": "default",
                "bpdu_guard": "default",
                "link_type": "auto",
            },
        )
        self.assertEqual(context["ports_by_role"], {"designated": 7, "root": 1})
        self.assertEqual(context["ports_keyed"], 1)
        # against the clean capture the anomaly is one added port key and the
        # root facts of one instance; the extra VLAN 999 instance is the
        # trunk config that replaced the hairpin
        clean, _ = l2._normalize_stp(J("iosxe_stp_details_lab.json"))
        diff = diffcore.diff_check(clean, normalized, _loader.registry.CHECKS["iosxe_stp"].compare)
        self.assertEqual(diff["result"], "diffs")
        self.assertEqual([a["key"] for a in diff["added"]], ["port|VLAN0002|" + UPLINK])
        self.assertEqual([r["key"] for r in diff["removed"]], ["instance|VLAN0999"])
        self.assertEqual({c["key"] for c in diff["changed"]}, {"instance|VLAN0002"})
        self.assertEqual(
            {c["field"] for c in diff["changed"]}, {"root_priority", "root_cost", "root_port"}
        )

    def test_the_lan_is_learned_twice_one_vlan_per_port(self):
        normalized, context, rows = l2._normalize_mac_table(J("iosxe_matm_table_lab_hairpin.json"))
        self.assertEqual(
            normalized,
            {
                "total": 110,
                "vlan|1": 55,
                "vlan|2": 55,
                "member|1": 110,
                "port|" + UPLINK: 55,
                "port|" + TRUNK_47: 54,
                "port|" + AP_PORT: 1,
            },
        )
        self.assertEqual(context["ports_with_dynamic"], 3)
        via_uplink = {r["mac"] for r in rows if r["port"] == UPLINK and r["type"] == "dynamic"}
        via_hairpin = {r["mac"] for r in rows if r["port"] == TRUNK_47 and r["type"] == "dynamic"}
        self.assertEqual(len(via_uplink & via_hairpin), 53)  # the dual-attachment signature
        self.assertEqual({r["vlan"] for r in rows if r["port"] == UPLINK}, {2})
        self.assertEqual({r["vlan"] for r in rows if r["port"] == TRUNK_47}, {1})
        # the statics are the same 27 rows as on the clean capture
        self.assertEqual(context["by_type"], {"dynamic": 110, "static": 27})

    def test_the_switch_is_its_own_cdp_neighbour_with_a_native_vlan_mismatch(self):
        cdp = checks._normalize_cdp(J("iosxe_cdp_neighbors_lab_hairpin.json"))
        self.assertEqual(len(cdp), 3)
        echoes = {
            key: facts for key, facts in cdp.items() if facts["platform"] == "cisco C9300-48UXM"
        }
        self.assertEqual(
            {
                (key.split("|")[2], facts["port"], facts["native_vlan"])
                for key, facts in echoes.items()
            },
            {(UPLINK, TRUNK_47, 1), (TRUNK_47, UPLINK, 2)},
        )
        # the mismatch the switch logs about itself, once a second while it lasted
        counts = checks._parse_syslog_errors(T("iosxe_show_logging.txt"))
        self.assertEqual(counts["sev4|%CDP-4-NATIVE_VLAN_MISMATCH"], {"count": 48})
        self.assertIn(
            "Native VLAN mismatch discovered on TwoGigabitEthernet1/0/1 (2), "
            "with sw-lab-1 TenGigabitEthernet1/0/47 (1).",
            T("iosxe_show_logging.txt"),
        )


class TestStability(unittest.TestCase):
    def test_every_lab_normalizer_is_deterministic_and_diffs_to_nothing(self):
        cases = (
            ("iosxe_vlans", lambda: l2._normalize_vlans(J("iosxe_vlan_oper_lab.json"))[0]),
            ("iosxe_stp", lambda: l2._normalize_stp(J("iosxe_stp_details_lab.json"))[0]),
            ("iosxe_mac_table", lambda: l2._normalize_mac_table(J("iosxe_matm_table_lab.json"))[0]),
            ("iosxe_poe", lambda: poe._normalize_poe(J("iosxe_poe_oper_lab.json"))),
            (
                "iosxe_interfaces",
                lambda: checks._normalize_interfaces(J("iosxe_interfaces_oper_lab.json")),
            ),
            (
                "iosxe_inventory",
                lambda: checks._normalize_inventory(J("iosxe_device_hardware_lab.json"))[0],
            ),
        )
        for check_id, build in cases:
            with self.subTest(check_id):
                pre, post = build(), build()
                self.assertEqual(pre, post)
                json.dumps(pre)
                compare = _loader.registry.CHECKS[check_id].compare
                self.assertEqual(diffcore.diff_check(pre, post, compare)["result"], "pass")


# --- BMC: a gen-1 ThinkSystem SE350 on XCC 6.10 (Redfish) --------------------
# Every xcc_*_lab.json is a payload the lab XCC served (tools/harvest_live.py
# --platform bmc, through the family's own redactors, then tools/make_fixtures.py);
# the hand-built xcc_*.json fixtures stay beside them. The lab context below
# serves each fixture at the path the XCC served it from — the resource's own
# @odata.id, with the $expand query for an *_expanded_lab fixture — so a
# collector runs against the real payload set exactly as it would live.

bmc = _loader.checks_bmc
XCC_LAB_FIXTURES = sorted(
    path.name
    for path in _loader.FIXTURES.iterdir()
    if path.name.startswith("xcc_") and path.name.endswith("_lab.json")
)
_XCC_EXPAND = "?$expand=.($levels=1)"


def _xcc_lab_payloads():
    """{request path: payload} for every xcc lab fixture."""
    payloads = {}
    for name in XCC_LAB_FIXTURES:
        payload = J(name)
        path = payload.get("@odata.id") if isinstance(payload, dict) else None
        if not path:
            continue
        if name.endswith("_expanded_lab.json"):
            path += _XCC_EXPAND
        payloads[path] = payload
    return payloads


def _xcc_lab_ctx():
    return _FakeCtx(_xcc_lab_payloads())


def _xcc_leaves(node, key=None):
    """(key, value) for every scalar leaf of a JSON value."""
    if isinstance(node, dict):
        for name, value in node.items():
            yield from _xcc_leaves(value, name)
    elif isinstance(node, list):
        for value in node:
            yield from _xcc_leaves(value, key)
    else:
        yield key, node


# The inventions the sanitizer produced for the lab harvest (its mapping file
# lives beside the raw harvest, outside the repository): an allow-list, so a
# re-harvest of another unit is caught rather than waved through.
XCC_INVENTED_SERIALS = frozenset(
    {
        "176878677394",
        "2190G9896651",
        "4696K2804906",
        "54NY63974089W45DM1",
        "58QY20254747L42JKZ",
        "C1ME31X334E",
        "H9CS5AS72LA",
        "L261500J",
        "Q1054325",
        "S2AQ3W89896",
        "08B11RU4",
        "54P01SKA",
        "P2PW9G3282Y",
        "Z0HT09B249M",
        "Z5KB45U71HV",
    }
)
XCC_INVENTED_UUIDS = frozenset({"7fa59b17-2c3c-1cc6-b740-167c4fea6c9f", "<hex:32>"})
XCC_INVENTED_HOSTS = frozenset({"bmc-lab-1", "bmc-lab-1.lab.example"})
XCC_INVENTED_ACCOUNTS = frozenset({"", "netops", "user-lab-1", "user-lab-2"})
# Lenovo logs some actions as done by these service pseudo-users; the family's
# redactor scrubs the word in those rows anyway, and neither names a person.
_XCC_SERVICE_ACTORS = frozenset({"system", "LXPM"})
_XCC_LOG_NAME = re.compile(r"(?:Login ID:|[Bb]y user|[Ff]or user)\s+(\S+?)(?=[.,:;]?(?:\s|$))")


class TestBmcNothingRealSurvives(unittest.TestCase):
    """The leak guard for the BMC fixtures: every identifier is one the sanitizer invents."""

    def test_lab_fixtures_exist(self):
        self.assertGreaterEqual(len(XCC_LAB_FIXTURES), 140)
        self.assertIn("/redfish/v1/", _xcc_lab_payloads())

    def test_every_identifier_is_an_invented_one(self):
        for name in XCC_LAB_FIXTURES:
            payload = J(name)
            for key, value in _xcc_leaves(payload):
                if not isinstance(value, str) or not value:
                    continue
                if key and key.endswith("SerialNumber") and value != "N/A":
                    self.assertIn(value, XCC_INVENTED_SERIALS, "%s: %s" % (name, key))
                if key == "UUID":
                    self.assertIn(value.lower(), XCC_INVENTED_UUIDS, name)
                if key in ("HostName", "FQDN"):
                    self.assertIn(value, XCC_INVENTED_HOSTS, name)
                if key == "UserName":
                    self.assertIn(value, XCC_INVENTED_ACCOUNTS, name)
                for token in re.findall(r"SN[#:]\s*([A-Za-z0-9-]+)", value):
                    self.assertIn(token, XCC_INVENTED_SERIALS, "%s: SN token" % (name,))
                for login in _XCC_LOG_NAME.findall(value) if key == "Message" else ():
                    self.assertIn(
                        login, _XCC_SERVICE_ACTORS | {"***scrubbed***"}, "%s: log name" % (name,)
                    )
            text = T(name)
            for quad in _QUAD.findall(text):
                self.assertTrue(_loader.allowed_lab_address(quad), "%s: %s" % (name, quad))
            for address in _IPV6.findall(text):
                if address.count(":") >= 2 and "::" in address or address.count(":") == 7:
                    self.assertRegex(address, _IPV6_ALLOWED, "%s: %s" % (name, address))
            self.assertNotIn("-----BEGIN", text, name)


class TestBmcLabIdentity(unittest.TestCase):
    """bmc_system, bmc_chassis and bmc_security on the lab payloads."""

    def test_system(self):
        result = bmc._collect_system(_xcc_lab_ctx())
        view, context = result["normalized"], result["context"]
        self.assertEqual(view["manufacturer"], "Lenovo")
        self.assertEqual(view["serial"], "L261500J")
        self.assertEqual(view["power_state"], "On")
        self.assertEqual(view["system_status"], "OSBooted")
        self.assertIsNone(view["bmc_health"])  # the Manager serves a State only
        self.assertEqual(view["bmc_state"], "Enabled")
        self.assertEqual(view["eth_member_used"], "NIC")
        self.assertEqual(view["bmc_ip"], "192.0.2.39")
        self.assertEqual(view["bmc_hostname"], "bmc-lab-1")
        self.assertEqual(context["resolution"]["vendor_source"], "ServiceRoot.Vendor")
        self.assertIsNone(context["resolution"]["product"])  # XCC 6.10 serves none

    def test_system_policy_leaves_absent_on_6_10_read_none(self):
        # The DMTF power-restore, delay, power-mode and host-console leaves are not
        # served by XCC 6.10: None, never assumed. The watchdog and the TPM list are.
        result = bmc._collect_system(_xcc_lab_ctx())
        view, context = result["normalized"], result["context"]
        for field in (
            "power_restore_policy",
            "power_on_delay_s",
            "power_off_delay_s",
            "power_cycle_delay_s",
            "power_mode",
            "serial_console_enabled",
            "graphical_console_enabled",
            "virtual_media_service_enabled",
            "front_panel_usb_mode",  # FrontPanelUSB serves PortEnabled only
        ):
            self.assertIn(field, view)
            self.assertIsNone(view[field], field)
        self.assertIs(view["host_watchdog_enabled"], False)
        self.assertEqual(view["host_watchdog_timeout_action"], "PowerCycle")
        self.assertEqual(view["host_watchdog_warning_action"], "None")  # the enum, verbatim
        self.assertEqual(
            (view["tpm_count"], view["tpm_interface_types"], view["tpm_firmware"]),
            (1, ["TPM2_0"], []),  # the module serves its firmware version as null
        )
        self.assertIs(view["front_panel_usb_port_enabled"], True)
        self.assertIs(view["tpm_rpp_enabled"], True)
        # the Manager's console blocks are the BMC's own services, not the host console
        self.assertEqual(
            (
                view["bmc_serial_console_enabled"],
                view["bmc_graphical_console_enabled"],
                view["bmc_command_shell_enabled"],
            ),
            (True, False, True),
        )
        self.assertEqual(context["release_name"], "purley_gp_23-2")
        self.assertEqual((context["reboot_count"], context["power_on_hours"]), (46, 40199))
        for field in ("last_reset_time", "manager_last_reset_time", "location_indicator_active"):
            self.assertIsNone(context[field], field)
        self.assertEqual(context["boot_progress"], {"last_state": None, "last_state_time": None})
        self.assertEqual(context["serial_console_protocols"], {})

    def test_chassis(self):
        view = bmc._collect_chassis_location(_xcc_lab_ctx())["normalized"]
        self.assertEqual(view["chassis_type"], "StandAlone")
        self.assertIsNone(view["intrusion_sensor"])  # no PhysicalSecurity on this unit
        self.assertEqual(view["placement_rack_offset"], 1)

    def test_chassis_leds_identity_and_empty_location_fields(self):
        ctx = _xcc_lab_ctx()
        result = bmc._collect_chassis_location(ctx)
        view, context = result["normalized"], result["context"]
        # four LEDs with unique Names (their Location repeats): keyed by Name alone
        self.assertEqual(
            {key: view[key] for key in view if key.startswith("led|")},
            {
                "led|BMC Heartbeat": {"color": "Green", "state": "Blink", "location": "Planar"},
                "led|Identify": {
                    "color": "Blue",
                    "state": "Off",
                    "location": "Front Panel, Rear Panel",
                },
                "led|Power": {
                    "color": "Green",
                    "state": "On",
                    "location": "Front Panel, Rear Panel",
                },
                "led|Fault": {
                    "color": "Yellow",
                    "state": "Off",
                    "location": "Front Panel, Rear Panel",
                },
            },
        )
        self.assertEqual(ctx.gets[-1], "/redfish/v1/Chassis/1/Oem/Lenovo/LEDs" + _XCC_EXPAND)
        self.assertEqual(context["leds"]["strategy"], "expand")
        self.assertEqual(view["indicator_led"], "Off")
        self.assertIsNone(view["location_indicator_active"])  # not served on 6.10
        self.assertEqual(view["system_board_serial"], "S2AQ3W89896")
        self.assertEqual(view["product_name"], "ThinkSystem SE350")
        self.assertEqual(view["fru_part_number"], "02JJ056")
        self.assertIs(view["has_switch_board"], False)
        # the operator left these empty: None, never ''
        for field in ("postal_building", "postal_location", "postal_room", "placement_rack"):
            self.assertIsNone(view[field], field)
        self.assertNotIn("", view.values())
        self.assertEqual((context["height_mm"], context["environmental_class"]), (44.45, "A4"))

    def test_security_is_keyed_leaf_by_leaf_without_thinkedge(self):
        ctx = _xcc_lab_ctx()
        result = bmc._collect_security_state(ctx)
        view, context = result["normalized"], result["context"]
        self.assertEqual(
            {key: value for key, value in view.items() if "|" in key},
            {
                "security|Configurator.FWRollback": "Enabled",
                "security|CryptographyManagement.MinTLSLevel": "TLSLevel1_2",
                "security|CryptographyManagement.TLSSecurityMode": "NistCompliant",
                "security|EncapSettings.EncapMode": "NormalMode",
                "security|EncapSettings.WhiteList": [],
                "security|SSLSettings.EnableCIMOverHttps": False,
                "security|SSLSettings.EnableHttps": True,
                "security|SSLSettings.EnableLDAPS": False,
                "security|SecurityCapabilities.SupportedActions": ["CreateKeyPair"],
                # the key manager serves nothing but its two certificate collections
                "sklm|ClientCertificate.Members@odata.count": 0,
                "sklm|ServerCertificate.Members@odata.count": 0,
            },
        )
        thinkedge = [key for key in view if "|" not in key]
        self.assertEqual(len(thinkedge), 8)
        self.assertTrue(all(view[key] is None for key in thinkedge))  # no Security Pack
        self.assertEqual(context["property_sources"], {})
        self.assertEqual(context["readings"], {})
        self.assertEqual(
            ctx.gets[-3:],
            [
                "/redfish/v1/Managers/1/Oem/Lenovo/SecureKeyLifecycleService",
                "/redfish/v1/Managers/1/Oem/Lenovo/SecureKeyLifecycleService/ClientCertificate",
                "/redfish/v1/Managers/1/Oem/Lenovo/SecureKeyLifecycleService/ServerCertificate",
            ],
        )


class TestBmcLabInventory(unittest.TestCase):
    """bmc_inventory, bmc_storage and bmc_firmware on the lab payloads."""

    # device|function: the BMC's VGA, the X722 and I350 LOMs, the slot-6 add-in NIC
    FUNCTIONS = ("ob_1|ob_1.00", "ob_2|ob_2.00", "ob_2|ob_2.01", "ob_4|ob_4.00")
    FUNCTIONS += ("ob_4|ob_4.01", "slot_6|slot_6.00")

    @staticmethod
    def _walked():
        """(payloads, errors): the lab set as a firmware refusing every $expand would serve it.

        Every collection link-only, every member at its own @odata.id, every $expand
        answered HTTP 501, and the System stripped of its Links, so the id resolution
        costs its full five GETs: the worst case each budget is sized for.
        """
        lab = _xcc_lab_payloads()
        payloads = {path: body for path, body in lab.items() if not path.endswith(_XCC_EXPAND)}
        errors = {}
        for path, body in lab.items():
            if not path.endswith(_XCC_EXPAND) or not isinstance(body.get("Members"), list):
                continue  # (CertificateLocations is a resource, not a collection)
            errors[path] = 501
            links = [{"@odata.id": member["@odata.id"]} for member in body["Members"]]
            payloads.setdefault(path[: -len(_XCC_EXPAND)], dict(body, Members=links))
            for member in body["Members"]:
                payloads.setdefault(member["@odata.id"], member)
        del payloads["/redfish/v1/Systems/1"]["Links"]
        return payloads, errors

    def test_inventory(self):
        ctx = _xcc_lab_ctx()
        result = bmc._collect_inventory(ctx)
        view, context = result["normalized"], result["context"]
        self.assertEqual(
            sorted(view),
            sorted(
                ["dimm|1", "dimm|2", "dimm|3", "dimm|4", "cpu|1"]
                + ["pcie|ob_1", "pcie|ob_2", "pcie|ob_4", "pcie|slot_6"]
                + ["pciefn|" + row for row in self.FUNCTIONS]
            ),
        )
        # the two empty DIMM slots are listed: keyed, Absent, identity null, nothing assumed
        absent = [key for key, row in view.items() if row.get("state") == "Absent"]
        self.assertEqual(sorted(absent), ["dimm|2", "dimm|3"])
        for key in absent:
            for field in ("serial", "capacity_mib", "rank_count", "fru_part_number"):
                self.assertIsNone(view[key][field], (key, field))
            self.assertEqual(view[key]["allowed_speeds_mhz"], [])  # served as an empty list
        dimm = view["dimm|1"]
        self.assertEqual(
            {field: dimm[field] for field in sorted(dimm) if field != "serial"},
            {
                "allowed_speeds_mhz": [2933],
                "base_module_type": "RDIMM",
                "bus_width_bits": 72,
                "capacity_mib": 32768,
                "data_width_bits": 64,
                "error_correction": None,  # not served on XCC 6.10
                "fru_part_number": "01DE974",
                "health": "OK",
                "manufacture_date": "year 2020 week 07",
                "manufacturer": "Samsung",
                "mpfa_health_major": None,  # no MPFA block on XCC 6.10
                "mpfa_health_minor": None,
                "part_number": "M393A4K40CB2-CVF",
                "rank_count": 1,
                "service_label": "DIMM 1",
                "slot": "DIMM 1",
                "socket": 1,
                "speed_mhz": 2400,
                "state": "Enabled",
                "type": "DDR4",
            },
        )
        self.assertEqual(
            view["cpu|1"],
            {
                "model": "Intel(R) Xeon(R) D-2123IT CPU @ 2.20GHz",
                "socket": "CPU 1",
                "cores": 4,
                "enabled_cores": 4,
                "threads": 8,
                "health": "OK",
                "state": "Enabled",
                "effective_family": "0x06",
                "effective_model": "0x55",
                "step": "0x04",
                "microcode": None,  # MicrocodeInfo is served null
                "max_speed_mhz": 3000,
                "tdp_w": 60,
                "turbo_state": None,  # not served on XCC 6.10
                "serial": None,  # served ''
            },
        )
        # the clock the DMTF leaves do not carry here comes from Lenovo's OEM leaf
        self.assertEqual(context["clock_speed_mhz"], {"1": 2200})
        self.assertEqual(context["clock_speed_source"], {"1": "Oem.Lenovo.CurrentClockSpeedMHz"})
        caches = context["cpu_caches"]["1"]
        self.assertEqual(caches["source"], "Oem.Lenovo.CacheInfo")
        self.assertEqual(
            [(c["level"], c["installed_kib"]) for c in caches["caches"]],
            [("L1", 256), ("L2", 4096), ("L3", 8448)],
        )
        # the devices the BMC names by nothing are named by their functions' PCI ids
        for device in ("pcie|ob_1", "pcie|slot_6"):
            self.assertEqual((view[device]["manufacturer"], view[device]["model"]), (None, None))
        self.assertEqual(
            view["pciefn|slot_6|slot_6.00"],
            {
                "function_type": "Physical",
                "device_class": "NetworkController",
                "class_code": "0x020000",
                "vendor_id": "0x10ec",
                "device_id": "0x8125",
                "subsystem_id": "0x0123",
                "subsystem_vendor_id": "0x10ec",
                "enabled": None,  # no Enabled leaf on XCC 6.10: null, never inferred
                "state": "Enabled",
            },
        )
        self.assertEqual(view["pciefn|ob_1|ob_1.00"]["device_class"], "DisplayController")
        self.assertEqual(
            {view["pciefn|" + row]["vendor_id"] for row in self.FUNCTIONS[1:5]}, {"0x8086"}
        )
        # one $expand GET per device's PCIeFunctions collection, after the three collections
        self.assertEqual(
            {device: report["members"] for device, report in context["pcie_functions"].items()},
            {"ob_1": 1, "ob_2": 2, "ob_4": 2, "slot_6": 1},
        )
        self.assertEqual(
            {report["strategy"] for report in context["pcie_functions"].values()}, {"expand"}
        )
        self.assertEqual(len(ctx.gets), 3 + 3 + 4)

    def test_storage_one_ahci_controller_per_m2_slot(self):
        ctx = _xcc_lab_ctx()
        result = bmc._collect_storage(ctx)
        view, context = result["normalized"], result["context"]
        controllers = [key for key in view if key.startswith("controller|")]
        drives = [key for key in view if key.startswith("drive|")]
        self.assertEqual(len(controllers), 4)
        self.assertEqual(sorted(drives), ["drive|Drive.Slot_%d" % (slot,) for slot in (2, 3, 4, 5)])
        self.assertFalse([key for key in view if key.startswith("volume|")])
        # AHCI controllers: none of the RAID leaves is served — present, and None
        for key in controllers:
            for field in ("cache_size_mib", "battery_operational_status", "mode"):
                self.assertIsNone(view[key][field], (key, field))
            self.assertIsNone(view[key]["supported_raid_levels"], key)
        self.assertEqual(set(context["controller_source"].values()), {"StorageControllers"})
        self.assertEqual(context["controllers_collection"], {})  # no Controllers link here
        self.assertEqual(context["battery"], {})
        drive = view["drive|Drive.Slot_2"]
        self.assertEqual(
            {
                field: drive[field]
                for field in (
                    "negotiated_speed_gbs",
                    "rotation_rpm",
                    "block_size_bytes",
                    "hotspare_type",
                    "write_cache_enabled",
                    "drive_status",
                )
            },
            {
                "negotiated_speed_gbs": None,
                "rotation_rpm": 0,
                "block_size_bytes": None,
                "hotspare_type": "None",
                "write_cache_enabled": None,
                "drive_status": None,  # the Lenovo drive block carries only its type
            },
        )
        self.assertEqual(set(context["drive_temperature_c"].values()), {None})
        # the Chassis links no Drives collection and an empty Links.Drives on XCC 6.10
        self.assertEqual(
            context["chassis_drives"],
            {"source": None, "strategy": None, "members": 0, "unlisted": 0},
        )
        self.assertEqual(ctx.gets[-1], "/redfish/v1/Chassis/1")
        self.assertEqual(len(ctx.gets), 3 + 1 + 4 + 4 + 1)

    def test_firmware_keeps_the_pending_members(self):
        ctx = _xcc_lab_ctx()
        result = bmc._collect_firmware(ctx)
        view = result["normalized"]
        self.assertEqual(len([key for key in view if key.startswith("fw|")]), 15)
        self.assertIn("fw|BMC-Primary-Pending", view)
        self.assertIsNone(view["fw|BMC-Primary-Pending"]["version"])
        self.assertIsNone(view["fw|UEFI-Pending"]["version"])
        self.assertEqual(view["manager_active_image"], "BMC-Primary")
        self.assertIs(view["backup_auto_promote"], False)
        self.assertEqual(len(view), 17)  # no SoftwareInventory: no sw| rows
        self.assertEqual(result["context"]["software_inventory"], {"linked": False})
        self.assertEqual(result["context"]["update_service"], "/redfish/v1/UpdateService")
        self.assertFalse([path for path in ctx.gets if "SoftwareInventory" in path])
        # the M.2 drives' firmware is their Revision: the Disk<N> rows carry the same strings
        storage = bmc._collect_storage(ctx)["normalized"]
        self.assertEqual(
            sorted(row["revision"] for key, row in storage.items() if key.startswith("drive|")),
            sorted(view["fw|Disk%d" % (index,)]["version"] for index in (1, 2, 3, 4)),
        )

    def test_every_budget_covers_the_lab_layout_without_expand(self):
        # resolution 5, then: Memory 1+1+4 (the $expand refusal is paid there, once),
        # Processors 1+1, PCIeDevices 1+4, functions 4+6
        payloads, errors = self._walked()
        ctx = _FakeCtx(payloads, errors=errors)
        result = bmc._collect_inventory(ctx)
        self.assertEqual(len([key for key in result["normalized"] if key.startswith("pciefn|")]), 6)
        self.assertEqual(
            {report["strategy"] for report in result["context"]["pcie_functions"].values()},
            {"members"},
        )
        self.assertEqual(len(ctx.gets), 5 + 6 + 2 + 5 + 10)
        self.assertLessEqual(len(ctx.gets), bmc._BUDGET_INVENTORY)
        # resolution 5, then: Storage 1+1+4, drives 4, Volumes 4 (never re-tried), the Chassis
        ctx = _FakeCtx(payloads, errors=errors)
        self.assertEqual(
            len([key for key in bmc._collect_storage(ctx)["normalized"] if "drive|" in key]), 4
        )
        self.assertEqual(len(ctx.gets), 5 + 6 + 4 + 4 + 1)
        self.assertLessEqual(len(ctx.gets), bmc._BUDGET_STORAGE)
        # resolution 5, then: FirmwareInventory 1+1+15, the Manager, the UpdateService
        ctx = _FakeCtx(payloads, errors=errors)
        self.assertEqual(len(bmc._collect_firmware(ctx)["normalized"]), 17)
        self.assertEqual(len(ctx.gets), 5 + 17 + 1 + 1)
        self.assertLessEqual(len(ctx.gets), bmc._BUDGET_FIRMWARE)


class TestBmcLabLogsBios(unittest.TestCase):
    """bmc_event_log and bmc_bios on the lab payloads."""

    RESOLVE = ["/redfish/v1/", "/redfish/v1/Systems", "/redfish/v1/Systems/1"]
    LS = "/redfish/v1/Systems/1/LogServices"
    BIOS = "/redfish/v1/Systems/1/Bios"

    def test_event_log(self):
        ctx = _xcc_lab_ctx()
        result = bmc._collect_event_log(ctx)
        context = result["context"]
        # healthy: nothing Warning or Critical in the platform log, no active condition
        self.assertEqual(result["normalized"], {})
        # one $expand GET inlines all six services; then the three logs that link Entries
        self.assertEqual(
            ctx.gets,
            self.RESOLVE
            + [self.LS + _XCC_EXPAND]
            + [self.LS + "/%s/Entries" % (name,) for name in ("StandardLog", "ActiveLog")]
            + [self.LS + "/MaintenanceLog/Entries"],
        )
        self.assertEqual(context["log_services_strategy"], "expand")
        self.assertEqual(
            context["log_services_served"],
            ["ActiveLog", "DiagnosticLog", "MaintenanceLog", "SEL", "SaLog", "StandardLog"],
        )
        self.assertEqual(context["entries_total"], 316)
        self.assertEqual(context["log_service_used"], "StandardLog")
        self.assertEqual((context["first_seq_num"], context["last_seq_num"]), (1, 140))
        # the audit counters are the StandardLog SERVICE resource's; its audit rows are
        # counted by log type (the firmware's own spelling, sic), never keyed
        self.assertEqual(context["audit_log_seq"], {"first": 1, "last": 176})
        self.assertEqual(
            context["audit_log_seq_source"],
            "StandardLog Oem.Lenovo.AuditFirstSeqNum/AuditLastSeqNum",
        )
        self.assertEqual(
            context["entries_by_log_type"],
            {"StardandLogEntry-Audit": 176, "StardandLogEntry-Platform": 140},
        )
        # the SEL is a probe (no Entries link here); its wrapping flag is on the SEL service
        self.assertEqual(
            context["sel"],
            {
                "served": True,
                "service_enabled": True,
                "max_records": 511,
                "overwrite_policy": "NeverOverWrites",
                "entries_link": False,
            },
        )
        self.assertIs(context["sel_wrapping_enabled"], False)
        self.assertEqual(context["sel_wrapping_source"], "SEL Oem.Lenovo.EnableSELWrapping")
        self.assertEqual(
            (context["active_log"]["served"], context["active_log"]["entries_total"]), (True, 0)
        )
        history = context["maintenance_log"]
        self.assertEqual(
            (history["entries_total"], history["first_id"], history["newest_id"]), (73, 1, 73)
        )
        self.assertEqual(history["newest_created"], "2026-09-05T17:56:53Z")
        self.assertEqual(history["by_event_group_id"], {"0": 19, "1": 54})  # firmware / parts
        self.assertEqual((history["max_records"], history["at_capacity"]), (750, False))
        rows = result["raw"][self.LS + "/MaintenanceLog/Entries"]["Members"]
        self.assertEqual((len(rows), rows[0]["Id"]), (73, "73"))
        platform = result["raw"][self.LS + "/StandardLog/Entries"]["Members"]
        self.assertEqual(sum("***scrubbed***" in (row["Message"] or "") for row in platform), 107)
        # no account name in any log's raw rows, the maintenance history included
        for path, record in result["raw"].items():
            if not path.endswith("/Entries"):
                continue
            for row in record["Members"]:
                for login in _XCC_LOG_NAME.findall(row["Message"] or ""):
                    self.assertIn(login, _XCC_SERVICE_ACTORS | {"***scrubbed***"}, path)
        self.assertEqual(
            {row["LogType"] for row in platform},
            {"StardandLogEntry-Audit", "StardandLogEntry-Platform"},
        )

    def test_event_log_without_expand_reads_only_the_services_it_uses(self):
        payloads = _xcc_lab_payloads()
        for member in payloads.pop(self.LS + _XCC_EXPAND)["Members"]:
            payloads.setdefault(member["@odata.id"], member)  # the StandardLog keeps its own
        ctx = _FakeCtx(payloads)
        result = bmc._collect_event_log(ctx)
        self.assertEqual(
            ctx.gets,
            self.RESOLVE
            + [self.LS + _XCC_EXPAND, self.LS]
            + [self.LS + "/" + name for name in ("StandardLog", "ActiveLog", "MaintenanceLog")]
            + [self.LS + "/SEL"]
            + [self.LS + "/%s/Entries" % (name,) for name in ("StandardLog", "ActiveLog")]
            + [self.LS + "/MaintenanceLog/Entries"],
        )
        self.assertEqual(result["context"]["log_services_strategy"], "members")
        expanded = bmc._collect_event_log(_xcc_lab_ctx())
        self.assertEqual(result["normalized"], expanded["normalized"])
        for key in (
            "audit_log_seq",
            "sel",
            "sel_wrapping_enabled",
            "active_log",
            "maintenance_log",
        ):
            self.assertEqual(result["context"][key], expanded["context"][key], key)

    def test_keyed_rows_read_the_real_entry_shapes(self):
        # Nothing on the lab unit is Warning or Critical, so two real rows are
        # raised here: a platform row that names its FRU and an audit row.
        rows = {
            row["Id"]: row
            for row in J("xcc_system_logservices_standardlog_entries_lab.json")["Members"]
        }
        rows["7"]["Severity"] = "Warning"
        rows["15"]["Severity"] = "Critical"
        view, _context = bmc._normalize_event_log([rows["7"], rows["15"]])
        self.assertEqual(
            view["sel|FQXSPPR0000I|7"],
            {
                "severity": "Warning",
                "source": "System",
                "serviceable": False,  # 'Not Serviceable', a string on XCC 6.10
                "serviceable_by": None,
                "event_id": "0x806f00251001ffff",
                "hidden": False,
                "failing_fru": [{"part": "01PF614", "serial": "C1ME31X334E"}],
                "log_type": "StardandLogEntry-Platform",
            },
        )
        audit = view["sel|FQXSPEM4009I|15"]
        self.assertEqual(
            (audit["serviceable"], audit["failing_fru"], audit["log_type"]),
            (False, [], "StardandLogEntry-Audit"),  # the empty FRU placeholder is no part
        )

    def test_bios(self):
        ctx = _xcc_lab_ctx()
        result = bmc._collect_bios(ctx)
        view, context = result["normalized"], result["context"]
        self.assertEqual(ctx.gets, self.RESOLVE + [self.BIOS, self.BIOS + "/Pending"])
        self.assertEqual(len([key for key in view if key.startswith("bios|")]), 126)
        self.assertEqual(context["attributes_total"], 126)
        self.assertEqual(context["password_attributes_dropped"], 0)
        self.assertEqual(view["bios|Processors_HyperThreading"], "Enable")
        self.assertEqual(view["bios|NetworkStackSettings_PXEbootwaittime"], 0)  # ints verbatim
        # Bios/Pending holds all 126 attributes and none differs: nothing is armed
        self.assertFalse([key for key in view if key.startswith("pending|")])
        self.assertEqual(
            (context["pending_total"], context["settings_object_attributes"]), (0, 126)
        )
        self.assertEqual(context["settings_object"], self.BIOS + "/Pending")
        self.assertIsNone(view["reset_to_defaults_pending"])  # not served on XCC 6.10
        self.assertIs(view["uefi_admin_password_set"], False)
        self.assertIs(view["uefi_power_on_password_set"], False)
        self.assertEqual(
            context["attribute_registry"],
            {
                "id": "BiosAttributeRegistry.1.0.0",
                "name": "BiosAttributeRegistry",
                "version": "1.0.0",
            },
        )
        self.assertEqual(context["settings_apply_time"], "2026-09-05T17:47:47-05:00")
        self.assertEqual(context["supported_apply_times"], ["OnReset"])
        self.assertEqual(context["settings_messages"], [])
        for path in (self.BIOS, self.BIOS + "/Pending"):
            self.assertEqual(len(result["raw"][path]["Attributes"]), 126, path)

    def test_bios_pending_is_the_one_attribute_that_differs(self):
        payloads = _xcc_lab_payloads()
        payloads[self.BIOS + "/Pending"]["Attributes"]["Processors_HyperThreading"] = "Disable"
        view = bmc._collect_bios(_FakeCtx(payloads))["normalized"]
        self.assertEqual(
            {key: value for key, value in view.items() if key.startswith("pending|")},
            {"pending|Processors_HyperThreading": "Disable"},
        )
        self.assertEqual(view["bios|Processors_HyperThreading"], "Enable")


class TestBmcLabEnvironmentNetwork(unittest.TestCase):
    """bmc_thermal, bmc_power, bmc_host_nics and bmc_manager_network on the lab payloads."""

    CH = "/redfish/v1/Chassis/1"
    MGR = "/redfish/v1/Managers/1"

    def test_thermal(self):
        result = bmc._collect_thermal(_xcc_lab_ctx())
        view, context = result["normalized"], result["context"]
        self.assertEqual(
            sorted(view),
            ["fan|Fan 1 Tach", "fan|Fan 2 Tach", "fan|Fan 3 Tach"]
            + ["temp|Ambient Temp", "temp|CPU DTS", "temp|CPU Temp"],
        )
        self.assertEqual(view["temp|Ambient Temp"]["reading_c"], 21)
        self.assertIsNone(view["temp|CPU DTS"]["reading_c"])
        self.assertEqual(view["fan|Fan 1 Tach"]["reading_units"], "RPM")
        # the DTS reads -51: headroom below the throttle point, not a temperature
        self.assertEqual(context["readings_c"]["temp|CPU DTS"], -51)
        self.assertEqual(context["margins"], ["temp|CPU DTS"])
        # ThermalMetrics serves the ambient and intake summary only
        self.assertEqual(
            context["temperature_summary_c"],
            {"ambient": 21, "intake": 21, "exhaust": None, "internal": None},
        )
        self.assertEqual(
            context["temperature_summary_source"], self.CH + "/ThermalSubsystem/ThermalMetrics"
        )
        self.assertEqual(context["temperatures_source"], self.CH + "/Thermal")
        self.assertEqual(context["fans_source"], self.CH + "/Thermal")
        self.assertEqual(context["fan_redundancy"], [])

    def test_thermal_subsystem_fans_key_the_same_way(self):
        payloads = _xcc_lab_payloads()
        legacy = bmc._collect_thermal(_FakeCtx(payloads))["normalized"]
        del payloads[self.CH + "/Thermal"]
        ctx = _FakeCtx(payloads)
        result = bmc._collect_thermal(ctx)
        # the Fan resources give the legacy keys and rows (SpeedRPM, not the RPM figure
        # this firmware also puts in the percent Reading); no temperature is keyed there
        self.assertEqual(
            result["normalized"],
            {key: row for key, row in legacy.items() if key.startswith("fan|")},
        )
        context = result["context"]
        self.assertEqual(context["fans_source"], self.CH + "/ThermalSubsystem/Fans")
        self.assertIsNone(context["temperatures_source"])
        self.assertEqual(context["fans_collection"]["strategy"], "expand")
        self.assertEqual(context["temperature_summary_c"]["ambient"], 21)
        self.assertIn(self.CH + "/ThermalSubsystem", ctx.gets)

    def test_power_rails_only(self):
        ctx = _xcc_lab_ctx()
        result = bmc._collect_power(ctx)
        view = result["normalized"]
        self.assertEqual(len(view), 4)
        self.assertTrue(all(key.startswith("voltage|") for key in view))  # no supplies
        self.assertEqual(result["context"]["psu_total"], 0)
        self.assertEqual(result["context"]["psu_source"], self.CH + "/Power")
        self.assertEqual(result["context"]["power_consumed_w"], 43)
        # the rails populate: the PowerSubsystem (no PowerSupplies either) is not read
        self.assertNotIn(self.CH + "/PowerSubsystem", ctx.gets)

    def test_power_subsystem_alone_models_no_supply(self):
        payloads = _xcc_lab_payloads()
        del payloads[self.CH + "/Power"]
        with self.assertRaises(_loader.registry.SkipCheck) as caught:
            bmc._collect_power(_FakeCtx(payloads))
        self.assertIn(self.CH + "/PowerSubsystem models no supply", str(caught.exception))

    def test_host_nics_all_nolink(self):
        result = bmc._collect_host_nics(_xcc_lab_ctx())
        view = result["normalized"]
        self.assertEqual(sorted(view), ["nic|NIC1", "nic|NIC2", "nic|NIC3", "nic|NIC4"])
        self.assertEqual({row["link_status"] for row in view.values()}, {"NoLink"})
        self.assertEqual(
            result["context"]["port_source"], "/redfish/v1/Systems/1/EthernetInterfaces"
        )

    def test_manager_network(self):
        result = bmc._collect_manager_network(_xcc_lab_ctx())
        view, context = result["normalized"], result["context"]
        self.assertEqual(view["ipv4_address"], "192.0.2.39")
        self.assertEqual((view["dns_servers"], view["static_dns_servers"]), ([], []))
        self.assertIs(view["snmp_enabled"], False)
        self.assertEqual(context["snmp_source"], "Oem.Lenovo.SNMP.SNMPv3Agent")
        expected = {
            "ipv6_gateway": None,  # served as '::'
            "nic_mode": "Dedicated",
            "failover_mode": None,  # not served on a dedicated port
            "ipv4_assigned_by": "Static",
            "domain_name": None,  # served as ''
            "hostname_from_dhcp": False,
            "dns_enabled": False,
            "dns_preferred_family": "IPv4",
            "dns_configured_servers": [],  # six placeholder slots
            "ddns": [{"enabled": False, "domain_name_source": "DHCP", "domain_name": None}],
            "lxca_discovery_enabled": False,
            "time_setting_method": "SyncwithNTP",
            "time_ntp_servers": ["192.0.2.1"],
            "utc_offset": "-5:00-Eastern",
            "auto_dst": True,
            "ntp_sync_interval_min": 600,
            "host_interface_enabled": True,
            "host_interface_externally_accessible": False,
            "credential_bootstrapping_enabled": True,
            "credential_bootstrapping_role": "Administrator",
            "credential_bootstrapping_enable_after_reset": True,
            "cimoverhttps_enabled": False,
            "cimoverhttps_port": 5989,
            "slp_enabled": False,
            "slp_port": 427,
            "sftp_enabled": False,
            "sftp_port": 115,
            "webhttps_enabled": True,
            "open_ports": [22, 80, 443, 3389, 3900, 5900],
            "snmpv3_agent_enabled": False,
            "snmp_traps_enabled": False,
            "kcs_enabled": False,
        }
        self.assertEqual({key: view[key] for key in expected}, expected)
        self.assertEqual(context["bmc_datetime"], "2026-09-29T22:30:15-05:00")
        self.assertEqual(context["bmc_datetime_offset"], "-05:00")
        self.assertIsNone(context["time_zone_name"])  # not served on XCC 6.10
        self.assertEqual(context["dns_source"], self.MGR + "/NetworkProtocol/Oem/Lenovo/DNS")
        self.assertEqual(context["host_interfaces"]["members"], ["1"])

    def test_manager_network_os_address_from_the_usb_lan_interface(self):
        # The harvest kept the USB-LAN interface only inside the expanded collection;
        # serve that real member at its own @odata.id, as the XCC does.
        payloads = _xcc_lab_payloads()
        expanded = payloads[self.MGR + "/EthernetInterfaces" + _XCC_EXPAND]
        for member in expanded["Members"]:
            payloads.setdefault(member["@odata.id"], member)
        ctx = _FakeCtx(payloads)
        result = bmc._collect_manager_network(ctx)
        context, view = result["context"], result["normalized"]
        self.assertEqual(
            (context["os_ipv4_address"], context["os_ipv4_address_member"]),
            ("198.18.54.120", "ToHost"),
        )
        # found through the host interface's ManagerEthernetInterface link, read once
        self.assertEqual(ctx.gets.count(self.MGR + "/EthernetInterfaces/ToHost"), 1)
        self.assertEqual(context["host_interface_usb_lan_member"], "ToHost")
        # the BMC's own side of the USB LAN, and Lenovo's mode for it, as served
        self.assertEqual(
            (view["host_interface_address"], view["host_interface_address_mode"]),
            ("198.18.54.118", "IPv6LLA"),
        )


class TestBmcLabFamily(unittest.TestCase):
    """The whole bmc family on the lab payloads: statuses, GETs, hygiene, stability."""

    def test_every_check_reads_the_real_shapes(self):
        ctx = _xcc_lab_ctx()
        statuses = {}
        for check in _loader.registry.checks_for("bmc"):
            try:
                result = check.collector(ctx)
                statuses[check.id] = "ok" if result["normalized"] else "empty"
            except _loader.registry.SkipCheck:
                statuses[check.id] = "not-present"
        self.assertEqual(statuses.pop("bmc_security"), "ok")  # keyed leaf by leaf
        self.assertEqual(statuses.pop("bmc_event_log"), "empty")  # healthy: nothing keyed
        self.assertEqual(set(statuses.values()), {"ok"}, statuses)
        # the widened family on the real payloads: measured, kept tight on purpose
        # (+ bmc_sensors: its Sensors $expand and EnvironmentMetrics; the ThermalMetrics read
        # it makes first is the one bmc_thermal then finds in the cache)
        # (+ bmc_boot's 5: BootSettings, VirtualMedia, RemoteControl and MountImages
        # twice — the harvest kept that collection's plain form only)
        # (+ bmc_power_policy's 4: Controls, ScheduledPowerActions, Watchdogs and Jobs)
        self.assertLessEqual(len(ctx.gets), 57)

    def test_normalizers_are_deterministic_and_diff_to_nothing(self):
        for check in _loader.registry.checks_for("bmc"):
            with self.subTest(check.id):
                try:
                    pre = check.collector(_xcc_lab_ctx())["normalized"]
                    post = check.collector(_xcc_lab_ctx())["normalized"]
                except _loader.registry.SkipCheck:
                    continue
                self.assertEqual(pre, post)
                json.dumps(pre)
                self.assertEqual(diffcore.diff_check(pre, post, check.compare)["result"], "pass")


class TestBmcLabSensors(unittest.TestCase):
    """bmc_sensors on the lab payloads: the SE350's 89 sensors — the only view it gives of its
    external power adapters, chassis intrusion and movement, and lockdown state — with its
    EnvironmentMetrics and the ThermalMetrics summary."""

    CH = "/redfish/v1/Chassis/1"
    RESOLVE = ["/redfish/v1/", "/redfish/v1/Systems", "/redfish/v1/Systems/1"]
    # the twelve sensors that serve a unit (ReadingUnits): the numeric ones
    NUMERIC = (
        "Ambient Temp",
        "CPU Temp",
        "SysBrd 3.3V",
        "SysBrd 5V",
        "SysBrd 12V",
        "CMOS Battery",
        "Sys Power",
        "CPU Power",
        "Mem Power",
        "Fan 1 Tach",
        "Fan 2 Tach",
        "Fan 3 Tach",
    )
    UTILISATION = ("Sys Utilization", "CPU Utilization", "Mem Utilization", "IO Utilization")
    SECURITY = {
        "chassis_intrusion": ["sensor|Chassis"],
        "chassis_movement": ["sensor|Chassis Movement"],
        "lockdown_mode": ["sensor|Lockdown Mode"],
        "low_security_jumper": ["sensor|Low Security Jmp"],
        "power_adapters": ["sensor|Power Adapter 1", "sensor|Power Adapter 2"],
    }

    @staticmethod
    def _keys(*names):
        return sorted("sensor|" + name for name in names)

    def test_one_expand_get_keys_all_89_sensors_by_name(self):
        ctx = _xcc_lab_ctx()
        result = bmc._collect_sensors(ctx)
        self.assertEqual(
            ctx.gets,
            self.RESOLVE
            + [
                self.CH,
                self.CH + "/EnvironmentMetrics",
                self.CH + "/ThermalSubsystem/ThermalMetrics",
                self.CH + "/Sensors" + _XCC_EXPAND,
            ],
        )
        view, context = result["normalized"], result["context"]
        self.assertEqual(len(view), 89)
        self.assertEqual([key for key in view if key.count("|") != 1], [])  # every Name unique
        self.assertEqual(context["sensors_collection"]["strategy"], "expand")
        # classified by ReadingUnits: 12 numeric, 77 discrete (ReadingType would say 21 / 68)
        self.assertEqual(
            context["counts"],
            {
                "total": 89,
                "numeric": 12,
                "discrete": 77,
                "by_reading_type": {
                    "AirFlow": 3,
                    "Current": 3,
                    "Power": 4,
                    "Temperature": 6,
                    "Voltage": 5,
                    "none": 68,
                },
            },
        )
        self.assertEqual(sorted(context["readings"]), self._keys(*self.NUMERIC))
        self.assertEqual(context["readings"]["sensor|Sys Power"], 50)
        self.assertEqual(context["host_power_state"], "On")
        self.assertIsNone(context["security_sensors_note"])
        self.assertEqual(
            set(result["raw"]),
            {
                self.CH + "/Sensors" + _XCC_EXPAND,
                self.CH + "/EnvironmentMetrics",
                self.CH + "/ThermalSubsystem/ThermalMetrics",
            },
        )
        self.assertNotIn("@odata.etag", json.dumps(result["raw"]))

    def test_reading_type_is_verbatim_and_never_the_classification(self):
        view = bmc._collect_sensors(_xcc_lab_ctx())["normalized"]

        def typed(name):
            row = view["sensor|" + name]
            return row["reading_type"], row["reading_units"]

        # numeric: watts typed Current, fan tachometers typed AirFlow (read in RPM)
        self.assertEqual(typed("Sys Power"), ("Current", "Watts"))
        self.assertEqual(typed("Fan 1 Tach"), ("AirFlow", "RPM"))
        self.assertEqual(typed("SysBrd 12V"), ("Voltage", "V"))
        self.assertEqual(typed("Ambient Temp"), ("Temperature", "C"))
        # discrete whatever the type: presence sensors typed Power, fault latches typed
        # Temperature or Voltage, the DTS margin typed Temperature with no unit
        self.assertEqual(typed("Power Adapter 1"), ("Power", None))
        self.assertEqual(typed("Host Power"), ("Power", None))
        self.assertEqual(typed("CPU Overtemp"), ("Temperature", None))
        self.assertEqual(typed("SysBrd Vol Fault"), ("Voltage", None))
        self.assertEqual(typed("CPU DTS"), ("Temperature", None))
        self.assertEqual(typed("Chassis Movement"), (None, None))
        self.assertEqual(view["sensor|Ambient Temp"]["physical_context"], "Intake")
        self.assertEqual(view["sensor|DIMM 1"]["physical_context"], "Memory")
        self.assertEqual({row["physical_sub_context"] for row in view.values()}, {None})

    def test_thresholds_are_the_served_readings(self):
        view = bmc._collect_sensors(_xcc_lab_ctx())["normalized"]
        served = {key: row["thresholds"] for key, row in view.items() if row["thresholds"]}
        self.assertEqual(
            served,
            {
                "sensor|Ambient Temp": {
                    "upper_caution": 57,
                    "upper_critical": 59,
                    "upper_fatal": 61,
                },
                "sensor|SysBrd 3.3V": {"lower_critical": 2.964, "upper_critical": 3.6348},
                "sensor|SysBrd 5V": {"lower_critical": 4.508, "upper_critical": 5.497},
                "sensor|SysBrd 12V": {"lower_critical": 10.615, "upper_critical": 13.2},
                "sensor|CMOS Battery": {"lower_caution": 2.392, "lower_critical": 2.249},
                "sensor|Fan 1 Tach": {"lower_critical": 1552},
                "sensor|Fan 2 Tach": {"lower_critical": 1552},
                "sensor|Fan 3 Tach": {"lower_critical": 1552},
            },
        )
        # a Thresholds block with nothing set reads {}; the discrete sensors serve no block
        self.assertEqual(
            sorted(key for key, row in view.items() if row["thresholds"] == {}),
            self._keys(
                "CPU DTS", "CPU Temp", "Sys Power", "CPU Power", "Mem Power", *self.UTILISATION
            ),
        )
        self.assertEqual(sum(row["thresholds"] is None for row in view.values()), 72)

    def test_only_the_ambient_sensor_keys_a_reading(self):
        view = bmc._collect_sensors(_xcc_lab_ctx())["normalized"]
        self.assertEqual(
            {key: row["reading"] for key, row in view.items() if row["reading"] is not None},
            {"sensor|Ambient Temp": 21},
        )

    def test_every_discrete_sensor_reads_0_on_this_healthy_unit(self):
        result = bmc._collect_sensors(_xcc_lab_ctx())
        view, context = result["normalized"], result["context"]
        asserted = {}
        for key, row in view.items():
            asserted.setdefault(row["asserted"], []).append(key)
        self.assertNotIn(True, asserted)
        self.assertEqual(len(asserted[False]), 70)
        # null: the numeric sensors, the two Disabled ones (null reading), the utilisation
        # sensors and the DTS margin — whose readings ride in context
        self.assertEqual(
            sorted(asserted[None]),
            self._keys(*(self.NUMERIC + self.UTILISATION + ("M2 Drive 0", "Progress", "CPU DTS"))),
        )
        self.assertEqual(
            (view["sensor|M2 Drive 0"]["state"], view["sensor|M2 Drive 0"]["health"]),
            ("Disabled", None),
        )
        self.assertEqual(
            context["utilisation_readings"],
            {
                "sensor|Sys Utilization": 1,
                "sensor|CPU Utilization": 0,
                "sensor|Mem Utilization": 0,
                "sensor|IO Utilization": 0,
            },
        )
        self.assertEqual(context["margin_readings"], {"sensor|CPU DTS": -51})

    def test_the_security_sensors_are_the_only_view_of_adapters_intrusion_and_lockdown(self):
        ctx = _xcc_lab_ctx()
        result = bmc._collect_sensors(ctx)
        self.assertEqual(result["context"]["security_sensors"], self.SECURITY)
        for keys in self.SECURITY.values():
            for key in keys:
                row = result["normalized"][key]
                self.assertEqual(
                    (row["state"], row["health"], row["asserted"]), ("Enabled", "OK", False), key
                )
        # nowhere else on this firmware: no PhysicalSecurity, no supplies, no ThinkEdge leaves
        self.assertNotIn("PhysicalSecurity", J("xcc_chassis_lab.json"))
        self.assertIsNone(bmc._collect_chassis_location(ctx)["normalized"]["intrusion_sensor"])
        self.assertNotIn("PowerSupplies", J("xcc_chassis_powersubsystem_lab.json"))
        self.assertEqual(bmc._collect_power(ctx)["context"]["psu_total"], 0)
        security = bmc._collect_security_state(ctx)["normalized"]
        for field in ("lockdown_mode", "motion_detection_enabled", "chassis_intrusion_enabled"):
            self.assertIsNone(security[field], field)

    def test_environment_metrics_and_the_temperature_summary_as_served(self):
        context = bmc._collect_sensors(_xcc_lab_ctx())["context"]
        self.assertEqual(
            context["environment"],
            {
                "power_watts": 40,
                "energy_kwh": None,  # not served
                "temperature_celsius": 21,
                "humidity_percent": None,  # not served
                # RPM figures in the percent field, as this firmware serves them
                "fan_speeds_percent": {
                    "sensor|Fan 1 Tach": {"reading": 6014, "speed_rpm": None},
                    "sensor|Fan 2 Tach": {"reading": 6014, "speed_rpm": None},
                    "sensor|Fan 3 Tach": {"reading": 6208, "speed_rpm": None},
                },
                "sources": {
                    "power_watts": "sensor|Sys Power",
                    "energy_kwh": None,
                    "temperature_celsius": "sensor|Ambient Temp",
                    "humidity_percent": None,
                },
            },
        )
        self.assertEqual(
            context["temperature_summary_c"],
            {"ambient": 21, "intake": 21, "exhaust": None, "internal": None},
        )
        self.assertEqual(context["environment_source"], self.CH + "/EnvironmentMetrics")
        # no ReadingTime and no PeakReading on this firmware: empty, and fine
        self.assertEqual((context["reading_times"], context["peak_readings"]), ({}, {}))

    def test_the_chassis_and_thermal_metrics_reads_are_shared_with_bmc_thermal(self):
        ctx = _xcc_lab_ctx()
        bmc._collect_sensors(ctx)
        bmc._collect_thermal(ctx)
        self.assertEqual(ctx.gets.count(self.CH), 1)
        self.assertEqual(ctx.gets.count(self.CH + "/ThermalSubsystem/ThermalMetrics"), 1)

    def test_without_expand_the_89_members_are_refused_before_any_is_read(self):
        payloads, errors = TestBmcLabInventory._walked()
        ctx = _FakeCtx(payloads, errors=errors)
        with self.assertRaises(bmc.CollectError) as caught:
            bmc._collect_sensors(ctx)
        self.assertIn(
            "89 members to fetch but only 25 GET(s) left in the budget of 35",
            str(caught.exception),
        )
        self.assertFalse([path for path in ctx.gets if path.startswith(self.CH + "/Sensors/")])
        # resolution 5, the Chassis, EnvironmentMetrics, ThermalMetrics, the refused
        # attempt and the collection
        self.assertEqual(len(ctx.gets), 5 + 1 + 2 + 1 + 1)


class TestBmcLabBoot(unittest.TestCase):
    """bmc_boot on the lab payloads: the boot order lives only in Lenovo's boot manager."""

    SYS = "/redfish/v1/Systems/1"
    MGR = "/redfish/v1/Managers/1"
    SETTINGS = SYS + "/Oem/Lenovo/BootSettings"
    MEDIA = SYS + "/VirtualMedia"
    RC = MGR + "/Oem/Lenovo/RemoteControl"
    MAIN = [
        "TrueNAS-0",
        "proxmox",
        "Linux Boot Manager",
        "CD/DVD Rom",
        "Hard Disk",
        "Network",
    ]

    def test_boot(self):
        ctx = _xcc_lab_ctx()
        result = bmc._collect_boot(ctx)
        view, context = result["normalized"], result["context"]
        # XCC 6.10 serves the override trio and the retry policy; the DMTF order, BootNext,
        # the retry count, the fault and TPM policies and the HTTP boot URI are not served
        self.assertEqual(
            {key: value for key, value in view.items() if "|" not in key},
            {
                "boot_order": None,
                "alias_boot_order": None,
                "boot_order_property_selection": None,
                "boot_override": "Disabled",
                "boot_override_target": "None",
                "boot_override_mode": "UEFI",
                "uefi_target": None,  # served null
                "boot_next": None,
                "automatic_retry_config": "RetryAlways",
                "automatic_retry_attempts": None,
                "stop_boot_on_fault": None,
                "trusted_module_required_to_boot": None,
                "http_boot_uri": None,
            },
        )
        # no BootOptions collection at all: no option| key, nothing requested for it
        self.assertFalse([key for key in view if key.startswith("option|")])
        self.assertEqual(
            context["boot_options"]["note"], "the System's Boot block links no BootOptions"
        )
        # the five boot-manager members, both lists in the firmware's order
        orders = {key: row for key, row in view.items() if key.startswith("order|")}
        self.assertEqual(
            sorted(orders),
            [
                "order|BootOrder.BootOrder",
                "order|BootOrder.CDDVDROMBootOrder",
                "order|BootOrder.HardDiskBootOrder",
                "order|BootOrder.NetworkBootOrder",
                "order|BootOrder.USBBootOrder",
            ],
        )
        self.assertEqual(
            orders["order|BootOrder.BootOrder"], {"current": self.MAIN, "next": self.MAIN}
        )
        for empty in ("CDDVDROMBootOrder", "USBBootOrder"):  # no such boot device: [] and real
            self.assertEqual(orders["order|BootOrder." + empty], {"current": [], "next": []})
        disks = orders["order|BootOrder.HardDiskBootOrder"]["current"]
        self.assertEqual(len(disks), 5)
        # the entries embed the drive's model and (sanitized) serial: what a reorder shows
        self.assertEqual(disks[0], "LEGACY: ATPAF480GSTIC-LV2    61DP455Y6L93096 LEN")
        self.assertTrue(disks[4].startswith("UEFI:   ATPAF480GSTIC-LV2"))
        self.assertEqual(len(orders["order|BootOrder.NetworkBootOrder"]["next"]), 8)
        # the supported lists are context: USB Storage is bootable but not in the order
        supported = context["boot_order_supported"]
        self.assertEqual(supported["BootOrder.BootOrder"], self.MAIN + ["USB Storage"])
        self.assertEqual(supported["BootOrder.USBBootOrder"], [])
        # the two RDOC slots, empty and write-protected
        for slot in ("RDOC1", "RDOC2"):
            self.assertEqual(
                view["vmedia|" + slot],
                {
                    "inserted": False,
                    "image": None,
                    "image_name": None,
                    "media_types": ["CD", "DVD", "Floppy", "USBStick"],
                    "connected_via": "NotConnected",
                    "write_protected": True,
                    "transfer_protocol_type": None,
                    "transfer_method": None,
                    "verify_certificate": False,
                },
            )
        self.assertEqual(
            (context["virtual_media"]["owner"], context["virtual_media"]["resource"]),
            ("System", self.MEDIA),
        )
        # the remote-control service is enabled and holds no image: an empty view, ok
        self.assertFalse([key for key in view if key.startswith("mount|")])
        self.assertIs(context["remote_control_enabled"], True)
        self.assertEqual(context["mount_images"]["members"], 0)
        self.assertEqual(context["mount_image_sizes"], {})
        self.assertEqual(context["host_power_state"], "On")
        self.assertIsNone(context["remaining_automatic_retry_attempts"])
        self.assertEqual(len(context["override_targets_allowable"]), 8)
        # one $expand GET per collection; the harvest read MountImages plain only, so its
        # $expand form answers 404 here and the plain read follows
        self.assertEqual(
            ctx.gets,
            ["/redfish/v1/", "/redfish/v1/Systems", self.SYS, self.MGR]
            + [self.SETTINGS + _XCC_EXPAND, self.MEDIA + _XCC_EXPAND, self.RC]
            + [self.RC + "/MountImages" + _XCC_EXPAND, self.RC + "/MountImages"],
        )
        self.assertEqual(context["mount_images"]["expand_refused"], "HTTP 404")
        self.assertNotIn(self.RC + "/Sessions", ctx.gets)
        self.assertNotIn("Actions", result["raw"][self.RC])

    def test_the_managers_virtual_media_is_the_same_pair(self):
        # why one collection is read: the Manager's lists the same two slots, leaf for leaf
        system = bmc._boot_media_rows(J("xcc_system_virtualmedia_expanded_lab.json")["Members"])
        manager = bmc._boot_media_rows(J("xcc_manager_virtualmedia_expanded_lab.json")["Members"])
        self.assertEqual(system, manager)
        self.assertEqual(sorted(system), ["vmedia|RDOC1", "vmedia|RDOC2"])

    def test_the_budget_covers_the_lab_layout_without_expand(self):
        # resolution 5, the Manager, BootSettings 1 + 1 + 5 (the refusal is paid there,
        # once), VirtualMedia 1 + 2, RemoteControl, MountImages 1 (empty, never re-tried)
        payloads, errors = TestBmcLabInventory._walked()
        ctx = _FakeCtx(payloads, errors=errors)
        result = bmc._collect_boot(ctx)
        self.assertEqual(result["normalized"], bmc._collect_boot(_xcc_lab_ctx())["normalized"])
        self.assertEqual(len(ctx.gets), 5 + 1 + 7 + 3 + 1 + 1)
        self.assertLessEqual(len(ctx.gets), bmc._BUDGET_BOOT)
        self.assertEqual(
            [path for path in ctx.gets if path.endswith(_XCC_EXPAND)],
            [self.SETTINGS + _XCC_EXPAND],
        )
        self.assertEqual(result["context"]["boot_settings"]["expand_refused"], "HTTP 501")

    def test_a_reorder_and_an_armed_change_are_changed_rows(self):
        compare = _loader.registry.CHECKS["bmc_boot"].compare
        pre = bmc._collect_boot(_xcc_lab_ctx())["normalized"]
        payloads = _xcc_lab_payloads()
        members = {
            member["Id"]: member for member in payloads[self.SETTINGS + _XCC_EXPAND]["Members"]
        }
        # the operator moved proxmox first; the change applies at the next boot
        members["BootOrder.BootOrder"]["BootOrderNext"] = ["proxmox", "TrueNAS-0"] + self.MAIN[2:]
        # a disk dropped out of the hard-disk sub-order (and out of what the UEFI can boot)
        disks = members["BootOrder.HardDiskBootOrder"]
        for leaf in ("BootOrderCurrent", "BootOrderNext", "BootOrderSupported"):
            disks[leaf] = disks[leaf][:2] + disks[leaf][3:]
        post = bmc._collect_boot(_FakeCtx(payloads))["normalized"]
        diff = diffcore.diff_check(pre, post, compare)
        self.assertEqual(
            [(row["key"], row["field"]) for row in diff["changed"]],
            [
                ("order|BootOrder.BootOrder", "next"),
                ("order|BootOrder.HardDiskBootOrder", "current"),
                ("order|BootOrder.HardDiskBootOrder", "next"),
            ],
        )
        self.assertEqual((diff["added"], diff["removed"]), ([], []))

    def test_a_boot_manager_the_uefi_has_not_populated_is_refused(self):
        payloads = _xcc_lab_payloads()
        for member in payloads[self.SETTINGS + _XCC_EXPAND]["Members"]:
            for leaf in ("BootOrderCurrent", "BootOrderNext", "BootOrderSupported"):
                member[leaf] = []
        with self.assertRaises(_loader.registry.CollectError) as caught:
            bmc._collect_boot(_FakeCtx(payloads))
        self.assertIn("host PowerState On", str(caught.exception))
        self.assertIn("unmeasured", str(caught.exception))


class TestBmcLabPowerPolicy(unittest.TestCase):
    """bmc_power_policy on the lab payloads: what XCC 6.10 serves, and what it does not."""

    SYS = "/redfish/v1/Systems/1"
    CH = "/redfish/v1/Chassis/1"
    MGR = "/redfish/v1/Managers/1"
    JOBS = "/redfish/v1/JobService/Jobs"

    def test_every_key_the_lab_unit_serves(self):
        ctx = _xcc_lab_ctx()
        result = bmc._collect_power_policy(ctx)
        view, context = result["normalized"], result["context"]
        slot = {"activated": False, "interval": "Daily", "time": "00:00"}
        unset = {"timer_s": None, "timeout_interval_s": None}
        self.assertEqual(
            view,
            {
                # neither AC-restore leaf is served on XCC 6.10: null, never assumed
                "power_restore_policy": None,
                "lenovo_power_restore_policy": None,
                "wake_on_lan": True,
                "power_on_permission": True,
                "local_power_control": True,
                "random_delay": None,
                "host_watchdog_enabled": False,
                "host_watchdog_timeout_action": "PowerCycle",
                "host_watchdog_warning_action": "None",  # the enum, verbatim
                # no PowerLimit, no Lenovo capping block, no redundancy group on an SE350
                "power_limit_w": None,
                "power_limit_exception": None,
                "power_limit_correction_ms": None,
                "power_capping_enabled": None,
                "limit_mode": None,
                "guaranteed_w": None,
                "capping_min_w": None,
                "capping_max_w": None,
                "power_redundancy_policy": None,
                "max_power_limit_w": None,
                "power_failure_limit": None,
                # a programmable power control with no set point and no mode: no cap set
                "control|PowerLimit": {
                    "control_type": "Power",
                    "control_mode": None,
                    "set_point": None,
                    "set_point_units": "Watt",
                    "set_point_type": "Single",
                    "setting_min": None,
                    "setting_max": None,
                    "allowable_min": None,
                    "allowable_max": None,
                    "implementation": "Programmable",
                    "physical_context": "Chassis",
                    "health": "OK",
                    "state": "Enabled",
                },
                "sched|1": dict(slot, type="On"),
                "sched|2": dict(slot, type="GracefulShutdown"),
                "sched|3": dict(slot, type="GracefulRestart"),
                "watchdog|1": dict(unset, type="OSBootProcess", state="Disabled"),
                "watchdog|2": dict(unset, type="OS", state="Disabled"),
                "watchdog|3": dict(unset, type="BIOSBootProcess", state="EnabledButOffline"),
                "watchdog|4": {
                    "type": "IPMI",
                    "state": "Enabled",
                    "timer_s": 15,
                    "timeout_interval_s": 15,
                },
            },
        )
        self.assertEqual(
            context["watchdog_expired"], {"watchdog|%d" % (n,): False for n in (1, 2, 3, 4)}
        )
        # the control's sensor reads the chassis power: a reading, context only
        self.assertEqual(
            context["control_readings"],
            {
                "control|PowerLimit": {
                    "reading": 50,
                    "data_source": self.CH + "/Sensors/204L0",
                    "set_point_update_time": None,
                }
            },
        )
        # the JobService twins of the three scheduled power actions, suspended
        self.assertEqual(sorted(context["jobs"]), ["PowerOff", "PowerOn", "Restart"])
        self.assertEqual({job["state"] for job in context["jobs"].values()}, {"Suspended"})
        schedule = context["jobs"]["PowerOff"]["schedule"]
        self.assertEqual(
            (schedule["name"], schedule["enabled_days_of_week"]), ("Lenovo:Power Off", [])
        )
        self.assertEqual(context["host_power_state"], "On")
        self.assertEqual(context["lenovo_capabilities_source"], "Power Oem.Lenovo")
        self.assertEqual(context["power_control_member"], "0")
        self.assertIsNone(context["redundancy_member"])
        self.assertIsNone(context["non_redundant_available_power_w"])
        self.assertIsNone(context["unmapped"])
        self.assertEqual(
            {
                family: (row["strategy"], row["members"])
                for family, row in context["collections"].items()
            },
            {
                "controls": ("expand", 1),
                "scheduled_power_actions": ("expand", 3),
                "watchdogs": ("expand", 4),
                "jobs": ("expand", 3),
            },
        )
        collections = (
            self.CH + "/Controls",
            self.SYS + "/Oem/Lenovo/ScheduledPowerActions",
            self.MGR + "/Oem/Lenovo/Watchdogs",
            self.JOBS,
        )
        self.assertEqual(
            ctx.gets,
            ["/redfish/v1/", "/redfish/v1/Systems", self.SYS, self.CH, self.CH + "/Power", self.MGR]
            + [path + _XCC_EXPAND for path in collections],
        )
        self.assertIn((self.JOBS + _XCC_EXPAND, "_power_policy_redact_jobs"), ctx.redacted)

    def test_what_xcc_6_10_does_not_serve(self):
        # the AC-restore policy: in neither the System nor Lenovo's capabilities block
        self.assertNotIn("PowerRestorePolicy", J("xcc_system_lab.json"))
        power = J("xcc_chassis_power_lab.json")
        capabilities = power["Oem"]["Lenovo"]
        self.assertEqual(capabilities["@odata.type"], "#LenovoPower.v1_0_0.Capabilities")
        for leaf in ("PowerRestorePolicy", "RandomDelay"):
            self.assertNotIn(leaf, capabilities)
        # no cap, no Lenovo capping block and no redundancy group on the SE350
        self.assertNotIn("Redundancy", power)
        for member in power["PowerControl"]:
            self.assertNotIn("PowerLimit", member)
            self.assertNotIn("PowerUtilization", member.get("Oem", {}).get("Lenovo", {}))
        # the PowerLimit control carries neither a set point nor a mode nor limits
        control = J("xcc_chassis_controls_expanded_lab.json")["Members"][0]
        for leaf in ("SetPoint", "ControlMode", "AllowableMin", "AllowableMax"):
            self.assertNotIn(leaf, control)
        # the JobService twins hide their payloads
        jobs = J("xcc_jobservice_jobs_expanded_lab.json")["Members"]
        self.assertEqual({(job["HidePayload"], "Payload" in job) for job in jobs}, {(True, False)})

    def test_the_lab_layout_without_expand_fits_the_budget(self):
        # resolution 5, then the Chassis, Power and the Manager, the Controls 1 + 1 + 1 (the
        # $expand refusal is paid there, once), the scheduled actions 1 + 3, the watchdogs
        # 1 + 4, the jobs 1 + 3
        payloads, errors = TestBmcLabInventory._walked()
        ctx = _FakeCtx(payloads, errors=errors)
        walked = bmc._collect_power_policy(ctx)
        self.assertEqual(len(ctx.gets), 5 + 3 + 3 + 4 + 5 + 4)
        self.assertLessEqual(len(ctx.gets), bmc._BUDGET_POWER_POLICY)
        self.assertEqual(
            [path for path in ctx.gets if "?" in path], [self.CH + "/Controls" + _XCC_EXPAND]
        )
        expanded = bmc._collect_power_policy(_xcc_lab_ctx())
        self.assertEqual(walked["normalized"], expanded["normalized"])
        self.assertEqual(walked["context"]["jobs"], expanded["context"]["jobs"])

    def test_a_firmware_without_the_power_resource_reads_the_flags_from_the_subsystem(self):
        payloads = _xcc_lab_payloads()
        del payloads[self.CH]["Power"]
        del payloads[self.CH + "/Power"]
        ctx = _FakeCtx(payloads)
        result = bmc._collect_power_policy(ctx)
        self.assertEqual(
            result["context"]["lenovo_capabilities_source"], "PowerSubsystem Oem.Lenovo"
        )
        self.assertIn(self.CH + "/PowerSubsystem", ctx.gets)
        # the same three flags, so the same view: nothing else came from Power on this unit
        self.assertEqual(
            result["normalized"], bmc._collect_power_policy(_xcc_lab_ctx())["normalized"]
        )
        # a Power resource the Chassis links that answers 404 is a failed read, never "none"
        payloads = _xcc_lab_payloads()
        del payloads[self.CH + "/Power"]
        with self.assertRaises(_loader.registry.CollectError):
            bmc._collect_power_policy(_FakeCtx(payloads))


if __name__ == "__main__":
    unittest.main()
