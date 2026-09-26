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
                "cdp|core-sw-02.example.net|TenGigabitEthernet1/0/48": {
                    "port": "TenGigabitEthernet1/0/48",
                    "caps": "Router Switch IGMP",
                },
                # Second entry uses the plural "capabilities" leaf.
                "cdp|ap-lab-01|GigabitEthernet1/0/12": {
                    "port": "GigabitEthernet0",
                    "caps": "Trans-Bridge Source-Route-Bridge IGMP",
                },
            },
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


class TestInterfacesNormalizer(unittest.TestCase):
    def test_full_normalized_view(self):
        payload = _loader.fixture_json("iosxe_interfaces_oper.json")
        self.assertEqual(
            checks._normalize_interfaces(payload),
            {
                "Vlan925": {
                    "admin": "if-state-up",
                    "oper": "if-oper-state-ready",
                    "ipv4": "10.10.9.1",
                },
                "TenGigabitEthernet1/0/1": {
                    "admin": "if-state-up",
                    "oper": "if-oper-state-ready",
                    "ipv4": "10.0.0.1",
                },
                # No ipv4 leaf at all -> explicit None, not absence.
                "TenGigabitEthernet1/0/5": {
                    "admin": "if-state-down",
                    "oper": "if-oper-state-no-pass",
                    "ipv4": None,
                },
                "GigabitEthernet0/0": {
                    "admin": "if-state-up",
                    "oper": "if-oper-state-ready",
                    "ipv4": "10.255.0.5",
                },
            },
        )


class TestPlatformHealthNormalizer(unittest.TestCase):
    def test_hardware_plus_environment(self):
        hardware = _loader.fixture_json("iosxe_device_hardware.json")
        env = _loader.fixture_json("iosxe_environment_sensors.json")
        self.assertEqual(
            checks._normalize_platform_health(hardware, env),
            {
                "boot-time": {"value": "2026-07-11T03:12:44+00:00"},
                "alarm|1058|1": {"desc": "Te1/0/5: Link down"},
                "env|Switch 1 R0/Temp: Coretemp": {"state": "Normal"},
                "env|Switch 1 R0/Temp: OutletTemp": {"state": "Normal"},
                "env|Switch 1 P0/P0 Vout": {"state": "Normal"},
            },
        )

    def test_environment_payload_absent(self):
        hardware = _loader.fixture_json("iosxe_device_hardware.json")
        self.assertEqual(
            checks._normalize_platform_health(hardware, None),
            {
                "boot-time": {"value": "2026-07-11T03:12:44+00:00"},
                "alarm|1058|1": {"desc": "Te1/0/5: Link down"},
            },
        )


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
        "iosxe_optics",
        "iosxe_crash_files",
        "iosxe_errdisable",
        "iosxe_port_channels",
        "iosxe_switch_stack",
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


# A 4-member stack's hardware inventory: chassis entries carry hw-dev-index ==
# switch number; the PSU entry must be ignored.
_STACK_HARDWARE = {
    "Cisco-IOS-XE-device-hardware-oper:device-hardware-data": {
        "device-hardware": {
            "device-inventory": [
                {
                    "hw-type": "hw-type-chassis",
                    "hw-dev-index": 1,
                    "part-number": "C9300-48P",
                    "serial-number": "FOC0000A0A1 ",
                },
                {
                    "hw-type": "hw-type-chassis",
                    "hw-dev-index": 2,
                    "part-number": "C9300-48P",
                    "serial-number": "FOC0000A0A2",
                },
                {
                    "hw-type": "hw-type-chassis",
                    "hw-dev-index": 3,
                    "part-number": "C9300-48U",
                    "serial-number": "FOC0000A0A3",
                },
                {
                    "hw-type": "hw-type-chassis",
                    "hw-dev-index": 4,
                    "part-number": "C9300-48P",
                    "serial-number": "FOC0000A0A4",
                },
                {
                    "hw-type": "hw-type-power-supply",
                    "hw-dev-index": 1,
                    "part-number": "PWR-C1-715WAC",
                    "serial-number": "DTN0000A0A1",
                },
            ]
        }
    }
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

    def test_chassis_inventory_skips_non_chassis_and_strips_serials(self):
        chassis = checks._chassis_inventory(_STACK_HARDWARE)
        self.assertEqual(sorted(chassis), ["1", "2", "3", "4"])
        self.assertEqual(chassis["1"], {"model": "C9300-48P", "serial": "FOC0000A0A1"})
        self.assertEqual(checks._chassis_inventory({}), {})

    def test_collector_merges_cli_views_and_inventory(self):
        ctx = _StackCtx(
            {"show switch detail": self.detail, "show switch stack-ports summary": self.summary},
            payloads={checks._HW_PATH: _STACK_HARDWARE, checks._STACK_OPER_PATH: {"x": 1}},
        )
        result = checks._collect_switch_stack(ctx)
        normalized = result["normalized"]
        self.assertEqual(
            normalized["stack"],
            {"mac": "00a1.b2c3.0100", "mac_origin": "local", "mac_persistency": "Indefinite"},
        )
        self.assertEqual(
            normalized["switch|3"],
            {
                "role": "Member",
                "state": "Ready",
                "priority": 9,
                "hw_version": "V02",
                "mac": "00a1.b2c3.0300",
                "model": "C9300-48U",
                "serial": "FOC0000A0A3",
            },
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
        self.assertEqual(
            result["context"],
            {
                "members_total": 4,
                "members_ready": 4,
                "stack_ports_total": 8,
                "stack_ports_ok": 8,
            },
        )
        raw = result["raw"]
        self.assertEqual(raw["show switch detail"], self.detail)
        self.assertEqual(raw["show switch stack-ports summary"], self.summary)
        self.assertEqual(raw["stack-oper"], {"x": 1})
        self.assertNotIn("note", raw)
        # The inventory read shares platform_health's exact path (per-run cache).
        self.assertIn(checks._HW_PATH, ctx.paths)

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
        ctx = _StackCtx(
            {
                "show switch detail": self.detail,
                "show switch stack-ports summary": "% Invalid input detected at '^' marker.",
            },
            payloads={checks._HW_PATH: _STACK_HARDWARE},
        )
        result = checks._collect_switch_stack(ctx)
        self.assertEqual(result["normalized"]["stack-port|2/1"], {"status": "OK", "neighbor": 3})
        self.assertIn("stack-ports summary rejected", result["raw"]["note"])
        # No stack-oper payload (404) is a note, never a failure.
        self.assertIn("stack-oper data not served", result["raw"]["note"])
        self.assertIsNone(result["raw"]["stack-oper"])

    def test_inventory_without_matching_member_is_noted_not_applied(self):
        hardware = {
            "device-hardware-data": {
                "device-hardware": {
                    "device-inventory": [
                        {"hw-type": "hw-type-chassis", "hw-dev-index": 9, "serial-number": "X"}
                    ]
                }
            }
        }
        ctx = _StackCtx(
            {"show switch detail": self.detail, "show switch stack-ports summary": self.summary},
            payloads={checks._HW_PATH: hardware},
        )
        result = checks._collect_switch_stack(ctx)
        self.assertNotIn("serial", result["normalized"]["switch|1"])
        self.assertIn("no member row: 9", result["raw"]["note"])

    def test_stack_oper_transport_failure_is_a_note(self):
        ctx = _StackCtx(
            {"show switch detail": self.detail, "show switch stack-ports summary": self.summary},
            payloads={checks._HW_PATH: _STACK_HARDWARE},
            raise_for={checks._STACK_OPER_PATH: RuntimeError("HTTP 500")},
        )
        result = checks._collect_switch_stack(ctx)
        # 'stack' + 4 'switch|' + 8 'stack-port|' keys: the full view survives.
        self.assertEqual(len(result["normalized"]), 13)
        self.assertIn("stack-oper supplement failed: HTTP 500", result["raw"]["note"])

    def test_stack_oper_never_swallows_the_celery_abort_signal(self):
        class SoftTimeLimitExceeded(Exception):
            pass

        ctx = _StackCtx(
            {"show switch detail": self.detail, "show switch stack-ports summary": self.summary},
            payloads={checks._HW_PATH: _STACK_HARDWARE},
            raise_for={checks._STACK_OPER_PATH: SoftTimeLimitExceeded()},
        )
        with self.assertRaises(SoftTimeLimitExceeded):
            checks._collect_switch_stack(ctx)


if __name__ == "__main__":
    unittest.main()
