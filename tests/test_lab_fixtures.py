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
No Nautobot, no network.
"""

import ipaddress
import json
import re
import unittest

if __package__:
    from . import _loader
else:  # unittest discover -s tests imports test modules as top-level
    import _loader

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


if __name__ == "__main__":
    unittest.main()
