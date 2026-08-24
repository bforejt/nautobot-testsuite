"""checks_panos parsers driven with committed CLI captures (XML + prompt noise)."""

import unittest

if __package__:
    from . import _loader
else:  # unittest discover -s tests imports test modules as top-level
    import _loader

checks = _loader.checks_panos
registry = _loader.registry


class _FakeCtx:
    """Duck-typed CollectorContext: canned output per exact command string."""

    def __init__(self, outputs):
        self.outputs = outputs
        self.commands = []
        self.device_name = "fw-test"
        self.logger = None

    def run_ssh(self, command, **kwargs):
        self.commands.append(command)
        if command not in self.outputs:
            raise AssertionError("collector ran unexpected command: %r" % (command,))
        return self.outputs[command]

    @property
    def has_ssh(self):
        return True


_EMPTY_RESULT = '<response status="success"><result/></response>'


def _matrix_outputs(zones, interfaces, per_pair_output, unfiltered_output=_EMPTY_RESULT):
    """Canned _FakeCtx outputs for a full matrix sweep (intra-zone included)."""
    outputs = {
        "show interface all": interfaces,
        "show session info": _loader.fixture_text("panos_session_info.txt"),
        "show session all filter count yes": unfiltered_output,
    }
    for src in zones:
        for dst in zones:
            outputs["show session all filter count yes from %s to %s" % (src, dst)] = (
                per_pair_output
            )
    return outputs


class TestSessionMatrix(unittest.TestCase):
    def test_unparsed_pair_lands_as_none_not_omitted(self):
        # An unreadable count must reach the capability differ as None — the
        # sentinel for "unreadable" — never vanish (which would read as zero).
        interfaces = _loader.fixture_text("panos_interfaces.txt")
        zones = checks._parse_zones(interfaces)
        self.assertGreaterEqual(len(zones), 2)
        a, b = zones[0], zones[1]
        good = (
            '<response status="success"><result><member>'
            "Number of sessions that match filter: 12</member></result></response>"
        )
        outputs = _matrix_outputs(zones, interfaces, good)
        broken = "show session all filter count yes from %s to %s" % (a, b)
        outputs[broken] = "Server error: unexpected response"
        result = checks._collect_session_matrix(_FakeCtx(outputs))
        pair = "%s>%s" % (a, b)
        self.assertIn(pair, result["normalized"])
        self.assertIsNone(result["normalized"][pair])
        self.assertEqual(result["raw"]["unparsed_pairs"], [pair])
        # Intra-zone pairs are swept too — without them the matrix could never
        # reconcile with the active-session total.
        self.assertIn("%s>%s" % (a, a), result["normalized"])

    def test_zero_match_pairs_read_as_zero_without_false_alarm(self):
        # Field regression: every pair empty (<result/>) must be a measured 0,
        # not unparseable. With the unfiltered filter-count ALSO at zero, the
        # matrix agrees with its own engine — no missing-traffic warning even
        # though num-active is large; the num-active gap is an informational
        # note (predict/mcast/closing sessions are not filter-enumerable).
        interfaces = _loader.fixture_text("panos_interfaces.txt")
        zones = checks._parse_zones(interfaces)
        result = checks._collect_session_matrix(
            _FakeCtx(_matrix_outputs(zones, interfaces, _EMPTY_RESULT))
        )
        self.assertEqual(result["raw"]["unparsed_pairs"], [])
        self.assertTrue(all(count == 0 for count in result["normalized"].values()))
        self.assertEqual(result["raw"]["matrix_total"], 0)
        self.assertEqual(result["raw"]["filterable_at_sweep"], 0)
        self.assertEqual(result["raw"]["session_info_at_sweep"]["active"], 48213)
        self.assertNotIn("sanity_warning", result["raw"])
        self.assertIn("not missing traffic", result["raw"]["note_active_vs_filterable"])

    def test_matrix_far_below_unfiltered_count_warns_missing_traffic(self):
        # The same filter engine reports far more sessions than the swept
        # pairs sum to: pairs are genuinely missing (zones absent, multi-vsys).
        interfaces = _loader.fixture_text("panos_interfaces.txt")
        zones = checks._parse_zones(interfaces)
        good = (
            '<response status="success"><result><member>'
            "Number of sessions that match filter: 12</member></result></response>"
        )
        unfiltered = (
            '<response status="success"><result><member>'
            "Number of sessions that match filter: 12000</member></result></response>"
        )
        result = checks._collect_session_matrix(
            _FakeCtx(_matrix_outputs(zones, interfaces, good, unfiltered))
        )
        self.assertEqual(result["raw"]["filterable_at_sweep"], 12000)
        self.assertIn("missing traffic", result["raw"]["sanity_warning"])


class TestSystemInfo(unittest.TestCase):
    def test_versions_and_identity_only(self):
        output = _loader.fixture_text("panos_system_info.txt")
        self.assertEqual(
            checks._normalize_system_info(output),
            {
                "sw_version": "11.1.4-h7",
                "app_version": "8934-9236",
                "threat_version": "8934-9236",
                "av_version": "5124-5648",
                "wildfire_version": "1032894-1036512",
                "model": "PA-5250",
                "serial": "013201000001",
                "hostname": "fw-edge-01",
                "multi_vsys": "off",
            },
        )

    def test_missing_system_element_raises(self):
        with self.assertRaises(checks.PanosParseError):
            checks._normalize_system_info(
                '<response status="success"><result><other/></result></response>'
            )


class TestHa(unittest.TestCase):
    def test_enabled_group_shape(self):
        output = _loader.fixture_text("panos_ha_enabled.txt")
        self.assertEqual(
            checks._normalize_ha(output),
            {
                "enabled": "yes",
                "local_state": "active",
                "peer_state": "passive",
                "config_sync": "synchronized",
            },
        )

    def test_enabled_top_level_shape(self):
        output = (
            '<response status="success"><result>'
            "<enabled>yes</enabled>"
            "<local-info><state>active</state></local-info>"
            "<peer-info><state>passive</state></peer-info>"
            "<running-sync>synchronized</running-sync>"
            "</result></response>"
        )
        self.assertEqual(
            checks._normalize_ha(output),
            {
                "enabled": "yes",
                "local_state": "active",
                "peer_state": "passive",
                "config_sync": "synchronized",
            },
        )

    def test_disabled(self):
        output = _loader.fixture_text("panos_ha_disabled.txt")
        self.assertEqual(checks._normalize_ha(output), {"enabled": "no"})

    def test_missing_enabled_leaf_reads_as_disabled(self):
        output = '<response status="success"><result><group/></result></response>'
        self.assertEqual(checks._normalize_ha(output), {"enabled": "no"})


class TestSessionInfo(unittest.TestCase):
    def test_counts_only(self):
        output = _loader.fixture_text("panos_session_info.txt")
        self.assertEqual(
            checks._normalize_session_info(output),
            {"active": 48213, "tcp": 30290, "udp": 17777, "icmp": 103},
        )

    def test_no_counters_raises(self):
        with self.assertRaises(checks.PanosParseError):
            checks._normalize_session_info(
                '<response status="success"><result><cps>1</cps></result></response>'
            )


class TestSessionMeter(unittest.TestCase):
    def test_per_vsys_counts_and_key_normalization(self):
        output = (
            '<response status="success"><result><meters><entry>'
            "<vsys>1</vsys><current>6134</current><maximum>0</maximum>"
            "</entry><entry>"
            "<vsys>vsys2</vsys><current>0</current><maximum>0</maximum>"
            "</entry><entry><vsys>3</vsys></entry>"  # no <current>: skipped
            "</meters></result></response>"
        )
        self.assertEqual(checks._parse_session_meter(output), {"vsys1": 6134, "vsys2": 0})

    def test_collector_skips_when_empty(self):
        ctx = _FakeCtx({"show session meter": '<response status="success"><result/></response>'})
        with self.assertRaises(checks.SkipCheck):
            checks._collect_session_meter(ctx)


class TestSystemInfoMultiVsys(unittest.TestCase):
    def test_multi_vsys_flag_is_captured(self):
        output = (
            '<response status="success"><result><system>'
            "<hostname>fw-test</hostname><multi-vsys>on</multi-vsys>"
            "</system></result></response>"
        )
        normalized = checks._normalize_system_info(output)
        self.assertEqual(normalized["multi_vsys"], "on")


class TestSessionCountParser(unittest.TestCase):
    def test_xml_member_form(self):
        output = _loader.fixture_text("panos_session_count_xml.txt")
        self.assertEqual(checks._parse_session_count(output), 1842)

    def test_xml_count_element_form(self):
        output = '<response status="success"><result><count>23</count></result></response>'
        self.assertEqual(checks._parse_session_count(output), 23)

    def test_xml_bare_result_text_form(self):
        output = '<response status="success"><result>7</result></response>'
        self.assertEqual(checks._parse_session_count(output), 7)

    def test_xml_count_phrase_directly_under_result(self):
        # PANW's own parsers prove free-text op output is inconsistently
        # wrapped: some commands put the line directly under <result> as
        # character data (no <member>). Both shapes must parse identically.
        output = (
            '<response status="success"><result>'
            "Number of sessions that match filter: 512"
            "</result></response>"
        )
        self.assertEqual(checks._parse_session_count(output), 512)

    def test_count_phrase_wins_over_earlier_digits(self):
        # Phrase-anchored extraction: a stray digit earlier in the blob must
        # never be mistaken for the count.
        output = (
            '<response status="success"><result><member>vsys1</member>'
            "<member>Number of sessions that match filter: 33</member>"
            "</result></response>"
        )
        self.assertEqual(checks._parse_session_count(output), 33)

    def test_plain_text_form(self):
        output = _loader.fixture_text("panos_session_count_text.txt")
        self.assertEqual(checks._parse_session_count(output), 23)

    def test_zero_count(self):
        output = "Number of sessions that match filter: 0\n"
        self.assertEqual(checks._parse_session_count(output), 0)

    def test_empty_result_on_success_means_zero(self):
        # PAN-OS answers a zero-match count query with an empty <result/> — a
        # valid zero, not an unparseable response (field finding: the old None
        # here flooded "unparseable" for every quiet zone pair).
        self.assertEqual(
            checks._parse_session_count('<response status="success"><result/></response>'), 0
        )
        self.assertEqual(
            checks._parse_session_count(
                "show session all filter count yes from a to b\n"
                '<response status="success"><result>\n</result></response>\n\n'
            ),
            0,
        )

    def test_no_active_sessions_means_zero(self):
        self.assertEqual(
            checks._parse_session_count(
                '<response status="success"><result><member>No Active Sessions'
                "</member></result></response>"
            ),
            0,
        )
        self.assertEqual(checks._parse_session_count("No Active Sessions\n"), 0)

    def test_error_response_is_never_zero(self):
        output = '<response status="error"><msg><line>Invalid filter</line></msg></response>'
        self.assertIsNone(checks._parse_session_count(output))

    def test_garbage_is_none(self):
        self.assertIsNone(checks._parse_session_count("Server error : Invalid syntax."))
        self.assertIsNone(checks._parse_session_count(""))
        self.assertIsNone(checks._parse_session_count(None))


class TestProtocolFromFlags(unittest.TestCase):
    def test_mappings(self):
        self.assertEqual(checks._protocol_from_flags("A S  "), "static")
        self.assertEqual(checks._protocol_from_flags("A C  "), "connect")
        self.assertEqual(checks._protocol_from_flags("A B  "), "bgp")
        self.assertEqual(checks._protocol_from_flags("A H  "), "host")
        self.assertEqual(checks._protocol_from_flags("A R  "), "rip")

    def test_any_o_token_is_ospf(self):
        for flags in ("A O  ", "A Oi ", "A Oo ", "A O1 ", "A O2 E"):
            self.assertEqual(checks._protocol_from_flags(flags), "ospf", flags)

    def test_preferred_star_and_modifiers_ignored(self):
        self.assertEqual(checks._protocol_from_flags("A*S"), "static")
        self.assertEqual(checks._protocol_from_flags("A E S"), "static")

    def test_unknown(self):
        self.assertEqual(checks._protocol_from_flags(""), "unknown")
        self.assertEqual(checks._protocol_from_flags(None), "unknown")
        self.assertEqual(checks._protocol_from_flags("A E"), "unknown")


class TestRouteParser(unittest.TestCase):
    def test_full_parse_with_ecmp_merge(self):
        output = _loader.fixture_text("panos_routes.txt")
        self.assertEqual(
            checks._parse_routes(output),
            {
                "default|0.0.0.0/0": {
                    "protocol": "static",
                    "interface": "ethernet1/1",
                    "next_hops": ["203.0.113.1"],
                },
                # Two ECMP entries collapse into one key with sorted hops; the
                # first entry's interface wins.
                "default|10.20.0.0/16": {
                    "protocol": "ospf",
                    "interface": "ethernet1/2",
                    "next_hops": ["10.10.9.1", "10.10.9.5"],
                },
                "default|203.0.113.0/28": {
                    "protocol": "connect",
                    "interface": "ethernet1/1",
                    "next_hops": ["203.0.113.10"],
                },
                "default|203.0.113.10/32": {
                    "protocol": "host",
                    "interface": None,
                    "next_hops": ["0.0.0.0"],
                },
                "b2b-vr|172.31.0.0/16": {
                    "protocol": "bgp",
                    "interface": "tunnel.10",
                    "next_hops": ["10.99.0.2"],
                },
            },
        )

    def test_later_entry_fills_missing_interface(self):
        output = (
            '<response status="success"><result>'
            "<entry><virtual-router>default</virtual-router>"
            "<destination>10.30.0.0/16</destination><nexthop>10.10.9.1</nexthop>"
            "<flags>A O2 E</flags></entry>"
            "<entry><virtual-router>default</virtual-router>"
            "<destination>10.30.0.0/16</destination><nexthop>10.10.9.5</nexthop>"
            "<flags>A O2 E</flags><interface>ethernet1/3</interface></entry>"
            "</result></response>"
        )
        parsed = checks._parse_routes(output)
        self.assertEqual(parsed["default|10.30.0.0/16"]["interface"], "ethernet1/3")
        self.assertEqual(parsed["default|10.30.0.0/16"]["next_hops"], ["10.10.9.1", "10.10.9.5"])


class TestRoutesCollector(unittest.TestCase):
    def test_legacy_engine_pseudo_entry(self):
        ctx = _FakeCtx({"show routing route": _loader.fixture_text("panos_routes.txt")})
        result = checks._collect_routes(ctx)
        self.assertEqual(result["normalized"]["engine|detected"], {"value": "legacy"})
        self.assertIn("default|0.0.0.0/0", result["normalized"])
        self.assertEqual(ctx.commands, ["show routing route"])
        self.assertIn("show routing route", result["raw"])

    def test_advanced_engine_fallback(self):
        ctx = _FakeCtx(
            {
                "show routing route": "Unknown command: show routing route",
                "show advanced-routing route": _loader.fixture_text("panos_routes.txt"),
            }
        )
        result = checks._collect_routes(ctx)
        self.assertEqual(result["normalized"]["engine|detected"], {"value": "advanced"})
        self.assertEqual(ctx.commands, ["show routing route", "show advanced-routing route"])
        self.assertIn("show advanced-routing route", result["raw"])

    def test_zero_routes_from_both_engines_is_collect_error(self):
        empty = '<response status="success"><result/></response>'
        ctx = _FakeCtx({"show routing route": empty, "show advanced-routing route": empty})
        with self.assertRaises(checks.CollectError):
            checks._collect_routes(ctx)


class TestInterfacesParser(unittest.TestCase):
    def test_zone_ip_keying_and_na_skipping(self):
        output = _loader.fixture_text("panos_interfaces.txt")
        normalized, name_map = checks._parse_interfaces(output)
        self.assertEqual(
            normalized,
            {
                "untrust|203.0.113.10/28": {"vr": "default", "state": "up", "mtu": 1500},
                "trust|10.10.9.2/30": {"vr": "default", "state": "up", "mtu": 9192},
                # Subinterface absent from <hw>: state unknown, no mtu key.
                "dmz|172.16.50.1/24": {"vr": "default", "state": "unknown"},
            },
        )
        # tunnel.10 and vlan carry ip N/A and must not appear at all.
        self.assertNotIn("vpn|N/A", normalized)
        # Interface names live only in the mapping destined for raw.
        self.assertEqual(
            name_map,
            {
                "untrust|203.0.113.10/28": "ethernet1/1",
                "trust|10.10.9.2/30": "ethernet1/2",
                "dmz|172.16.50.1/24": "ethernet1/2.100",
            },
        )
        for body in normalized.values():
            self.assertNotIn("name", body)

    def test_collector_exposes_name_map_in_raw_only(self):
        output = _loader.fixture_text("panos_interfaces.txt")
        ctx = _FakeCtx({"show interface all": output})
        result = checks._collect_interfaces(ctx)
        self.assertEqual(result["raw"]["interface_names"]["untrust|203.0.113.10/28"], "ethernet1/1")
        self.assertNotIn("interface_names", result["normalized"])


class TestZonesParser(unittest.TestCase):
    def test_sorted_unique_nonempty(self):
        output = _loader.fixture_text("panos_interfaces.txt")
        self.assertEqual(checks._parse_zones(output), ["dmz", "trust", "untrust", "vpn"])


class TestArp(unittest.TestCase):
    def test_status_per_ip(self):
        output = _loader.fixture_text("panos_arp.txt")
        self.assertEqual(
            checks._normalize_arp(output),
            {
                "203.0.113.1": {"status": "c"},
                "10.10.9.1": {"status": "e"},
                "172.16.50.9": {"status": "i"},
            },
        )


class TestVpnSaParsers(unittest.TestCase):
    def test_ike_flat_entries(self):
        output = _loader.fixture_text("panos_ike_sa.txt")
        self.assertEqual(checks._parse_sa_names(output), ["gw-partner-east", "gw-partner-west"])

    def test_ipsec_nested_entries_keep_rekey_duplicates(self):
        output = _loader.fixture_text("panos_ipsec_sa.txt")
        self.assertEqual(
            checks._parse_sa_names(output),
            ["tun-partner-east", "tun-partner-east", "tun-partner-west"],
        )

    def test_collector_collapses_duplicates_and_prefixes(self):
        ctx = _FakeCtx(
            {
                "show vpn ike-sa": _loader.fixture_text("panos_ike_sa.txt"),
                "show vpn ipsec-sa": _loader.fixture_text("panos_ipsec_sa.txt"),
            }
        )
        result = checks._collect_ipsec(ctx)
        self.assertEqual(
            result["normalized"],
            {
                "ike|gw-partner-east": {"up": True},
                "ike|gw-partner-west": {"up": True},
                "tunnel|tun-partner-east": {"up": True},
                "tunnel|tun-partner-west": {"up": True},
            },
        )

    def test_collector_skips_when_no_sas(self):
        empty = '<response status="success"><result/></response>'
        ctx = _FakeCtx({"show vpn ike-sa": empty, "show vpn ipsec-sa": empty})
        with self.assertRaises(checks.SkipCheck):
            checks._collect_ipsec(ctx)


class TestLicenses(unittest.TestCase):
    def test_expired_flags_per_feature(self):
        output = _loader.fixture_text("panos_licenses.txt")
        self.assertEqual(
            checks._normalize_licenses(output),
            {
                "Threat Prevention": {"expired": "no"},
                "PAN-DB URL Filtering": {"expired": "no"},
                "WildFire License": {"expired": "yes"},
                "Premium": {"expired": "no"},
            },
        )


class TestRegistrations(unittest.TestCase):
    EXPECTED_IDS = {
        "panos_system_info",
        "panos_ha",
        "panos_session_info",
        "panos_session_meter",
        "panos_session_matrix",
        "panos_routes",
        "panos_interfaces",
        "panos_arp",
        "panos_ipsec",
        "panos_licenses",
        "panos_resources",
    }

    def test_all_registered_once(self):
        registered = {
            check_id for check_id, check in registry.CHECKS.items() if check.platform == "panos"
        }
        self.assertEqual(registered, self.EXPECTED_IDS)

    def test_firewall_package_resolves_to_panos_only(self):
        ids = registry.package_check_ids("fw-cutover-firewall", "panos")
        self.assertEqual(set(ids), self.EXPECTED_IDS)
        self.assertEqual(registry.package_check_ids("fw-cutover-firewall", "iosxe"), [])

    def test_every_check_has_collector_and_valid_mode(self):
        diffcore = _loader.diffcore
        for check in registry.CHECKS.values():
            if check.platform != "panos":
                continue
            self.assertTrue(callable(check.collector), check.id)
            self.assertIn(check.compare.get("mode", "equality_set"), diffcore.MODES, check.id)


if __name__ == "__main__":
    unittest.main()
