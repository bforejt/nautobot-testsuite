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
    }

    def test_all_registered_once(self):
        registered = {
            check_id for check_id, check in registry.CHECKS.items() if check.platform == "iosxe"
        }
        self.assertEqual(registered, self.EXPECTED_IDS)

    def test_checks_for_filters_by_platform(self):
        ids = {check.id for check in registry.checks_for("iosxe")}
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


if __name__ == "__main__":
    unittest.main()
