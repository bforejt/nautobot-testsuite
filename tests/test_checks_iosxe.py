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
        # The field scenario end to end: every member's filesystem holds only a
        # freshly written tracelogs/ directory (the 4-member 9300 in the field),
        # which is the healthy state.
        from datetime import datetime, timezone

        now = datetime(2026, 9, 24, tzinfo=timezone.utc)

        def listing(filesystem):
            return (
                "Directory of %s/\n"
                "30177  drwx             4096  Sep 24 2026 22:40:12 +00:00  tracelogs\n"
                "\n11353194496 bytes total (10000000000 bytes free)" % (filesystem,)
            )

        ctx = _StackCtx(
            {
                "dir crashinfo:": listing("crashinfo:"),
                "dir stby-crashinfo:": listing("stby-crashinfo:"),
                "show switch detail": _loader.fixture_text("iosxe_show_switch_detail.txt"),
                "dir crashinfo-3:": listing("crashinfo-3:"),
                "dir crashinfo-4:": listing("crashinfo-4:"),
            }
        )
        result = checks._collect_crash_files(ctx, now=now)
        self.assertEqual(result["normalized"], {})
        self.assertEqual(
            result["context"]["filesystems_listed"],
            ["crashinfo:", "stby-crashinfo:", "crashinfo-3:", "crashinfo-4:"],
        )
        self.assertEqual(result["context"]["older_files_ignored"], 0)

    def test_crash_files_stack_lists_every_other_member(self):
        # Members 1 (active) and 2 (standby) are the crashinfo:/stby-crashinfo:
        # aliases and must never be listed again by number; members 3 and 4 have
        # their own filesystems. An old dump on member 3 is counted, never keyed.
        from datetime import datetime, timezone

        now = datetime(2026, 8, 24, tzinfo=timezone.utc)
        ctx = _StackCtx(
            {
                "dir crashinfo:": _dir_listing(
                    "crashinfo:", ("system-report_1_20260822.tar.gz", "Aug 22 2026")
                ),
                "dir stby-crashinfo:": _dir_listing("stby-crashinfo:"),
                "show switch detail": _loader.fixture_text("iosxe_show_switch_detail.txt"),
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
                "dir crashinfo:",
                "dir stby-crashinfo:",
                "show switch detail",
                "dir crashinfo-3:",
                "dir crashinfo-4:",
            ],
        )
        self.assertEqual(
            result["normalized"],
            {
                "active|system-report_1_20260822.tar.gz": {"modified": "2026-08-22"},
                "member3|system-report_3_20260823.tar.gz": {"modified": "2026-08-23"},
            },
        )
        self.assertEqual(
            result["context"],
            {
                "older_files_ignored": 1,
                "recent_window_days": 7,
                "filesystems_listed": [
                    "crashinfo:",
                    "stby-crashinfo:",
                    "crashinfo-3:",
                    "crashinfo-4:",
                ],
                "active_member": 1,
                "standby_member": 2,
            },
        )
        self.assertIn("show switch detail", result["raw"])

    def test_crash_files_alias_failure_falls_back_to_the_member_filesystem(self):
        # stby-crashinfo: errors, so the standby's own crashinfo-2: is listed
        # instead; a provisioned member's filesystem does not exist and is
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
        ctx = _StackCtx(
            {
                "dir crashinfo:": _dir_listing("crashinfo:"),
                "dir stby-crashinfo:": "%Error opening stby-crashinfo:/ (No such device)",
                "show switch detail": detail,
                "dir crashinfo-2:": _dir_listing(
                    "crashinfo-2:", ("system-report_2_20260823.tar.gz", "Aug 23 2026")
                ),
                "dir crashinfo-3:": _dir_listing("crashinfo-3:"),
                "dir crashinfo-4:": "%Error opening crashinfo-4:/ (No such device)",
            }
        )
        result = checks._collect_crash_files(ctx, now=now)
        self.assertEqual(
            ctx.commands[2:],
            ["show switch detail", "dir crashinfo-2:", "dir crashinfo-3:", "dir crashinfo-4:"],
        )
        self.assertEqual(
            result["normalized"],
            {"member2|system-report_2_20260823.tar.gz": {"modified": "2026-08-23"}},
        )
        self.assertEqual(
            result["context"]["filesystems_listed"], ["crashinfo:", "crashinfo-2:", "crashinfo-3:"]
        )
        self.assertEqual(result["context"]["members_not_listed"], [4])
        self.assertEqual(result["context"]["standby_member"], 2)

    def test_crash_files_non_stack_platform_lists_only_the_aliases(self):
        from datetime import datetime, timezone

        now = datetime(2026, 8, 24, tzinfo=timezone.utc)
        ctx = _StackCtx(
            {
                "dir crashinfo:": _dir_listing(
                    "crashinfo:", ("system-report_1_20260822.tar.gz", "Aug 22 2026")
                ),
                "dir stby-crashinfo:": _dir_listing("stby-crashinfo:"),
                "show switch detail": "% Invalid input detected at '^' marker.",
            }
        )
        result = checks._collect_crash_files(ctx, now=now)
        self.assertEqual(
            ctx.commands, ["dir crashinfo:", "dir stby-crashinfo:", "show switch detail"]
        )
        self.assertEqual(list(result["normalized"]), ["active|system-report_1_20260822.tar.gz"])
        self.assertEqual(result["context"]["filesystems_listed"], ["crashinfo:", "stby-crashinfo:"])
        self.assertNotIn("active_member", result["context"])
        self.assertNotIn("members_not_listed", result["context"])

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


if __name__ == "__main__":
    unittest.main()
