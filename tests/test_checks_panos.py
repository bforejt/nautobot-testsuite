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


def _count_response(value):
    return (
        '<response status="success"><result><member>'
        "Number of sessions that match filter: %d</member></result></response>" % (value,)
    )


def _matrix_outputs(zones, interfaces, per_pair_output, unfiltered_output=_EMPTY_RESULT):
    """Canned _FakeCtx outputs for a full pair sweep (pair form ONLY).

    No single-sided from/to entries exist here on purpose: _FakeCtx raises on
    any unexpected command, so this helper doubles as proof the collector
    never sends the session-poisoning single-sided form again.
    """
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
    def test_unparsed_pair_poisons_derived_totals_not_other_rows(self):
        # An unreadable count reaches the capability differ as None — and any
        # derived row/column total containing it is None too (unreadable),
        # never a fabricated partial sum. Other rows stay numeric.
        interfaces = _loader.fixture_text("panos_interfaces.txt")
        zones = checks._parse_zones(interfaces)
        self.assertGreaterEqual(len(zones), 2)
        a, b = zones[0], zones[1]
        outputs = _matrix_outputs(zones, interfaces, _count_response(12))
        broken = "show session all filter count yes from %s to %s" % (a, b)
        outputs[broken] = "Server error: unexpected response"
        result = checks._collect_session_matrix(_FakeCtx(outputs))
        pair = "%s>%s" % (a, b)
        self.assertIsNone(result["normalized"][pair])
        self.assertEqual(result["raw"]["unparsed_pairs"], [pair])
        self.assertIn("%s>%s" % (a, a), result["normalized"])  # intra-zone swept
        self.assertIsNone(result["normalized"]["%s>*" % (a,)])  # row holds the break
        self.assertIsNone(result["normalized"]["*>%s" % (b,)])  # column holds it too
        self.assertEqual(result["normalized"]["%s>*" % (b,)], 12 * len(zones))
        self.assertEqual(result["normalized"]["*>%s" % (a,)], 12 * len(zones))

    def test_zero_match_pairs_read_as_zero_without_false_alarm(self):
        # Field regression: every count empty (<result/>) must be a measured 0,
        # not unparseable. With the unfiltered filter-count ALSO at zero, the
        # sweep agrees with its own engine — no missing-traffic warning even
        # though num-active is large; that gap is an informational note.
        interfaces = _loader.fixture_text("panos_interfaces.txt")
        zones = checks._parse_zones(interfaces)
        result = checks._collect_session_matrix(
            _FakeCtx(_matrix_outputs(zones, interfaces, _EMPTY_RESULT))
        )
        self.assertEqual(result["raw"]["unparsed_pairs"], [])
        self.assertTrue(all(count == 0 for count in result["normalized"].values()))
        self.assertEqual(result["raw"]["matrix_total"], 0)
        self.assertEqual(result["raw"]["from_zone_total"], 0)
        self.assertEqual(result["raw"]["filterable_at_sweep"], 0)
        self.assertEqual(result["raw"]["session_info_at_sweep"]["active"], 48213)
        self.assertNotIn("sanity_warning", result["raw"])
        self.assertIn("not missing traffic", result["raw"]["note_active_vs_filterable"])

    def test_from_totals_far_below_unfiltered_count_warns_missing_traffic(self):
        # Derived from-totals cover every discovered zone, so summing far
        # below the same engine's unfiltered count means zone discovery
        # itself missed traffic.
        interfaces = _loader.fixture_text("panos_interfaces.txt")
        zones = checks._parse_zones(interfaces)
        result = checks._collect_session_matrix(
            _FakeCtx(
                _matrix_outputs(zones, interfaces, _count_response(12), _count_response(12000))
            )
        )
        self.assertEqual(result["raw"]["filterable_at_sweep"], 12000)
        self.assertIn("zone discovery missed traffic", result["raw"]["sanity_warning"])

    def test_derived_totals_are_row_and_column_sums(self):
        interfaces = _loader.fixture_text("panos_interfaces.txt")
        zones = checks._parse_zones(interfaces)
        self.assertGreaterEqual(len(zones), 3)
        outputs = _matrix_outputs(zones, interfaces, _EMPTY_RESULT, _count_response(500))
        values = {}
        for i, src in enumerate(zones):
            for j, dst in enumerate(zones):
                value = i * 10 + j
                values[(src, dst)] = value
                outputs["show session all filter count yes from %s to %s" % (src, dst)] = (
                    _count_response(value)
                )
        result = checks._collect_session_matrix(_FakeCtx(outputs))
        for zone in zones:
            self.assertEqual(
                result["normalized"]["%s>*" % (zone,)],
                sum(values[(zone, dst)] for dst in zones),
            )
            self.assertEqual(
                result["normalized"]["*>%s" % (zone,)],
                sum(values[(src, zone)] for src in zones),
            )

    def test_all_unreadable_aborts_fast(self):
        # A poisoned session or wrong syntax must not be hammered with
        # hundreds more queries — the sweep aborts after the first
        # _SWEEP_ABORT_AFTER consecutive unreadable responses.
        interfaces = _loader.fixture_text("panos_interfaces.txt")
        zones = checks._parse_zones(interfaces)
        self.assertGreaterEqual(len(zones) * len(zones), checks._SWEEP_ABORT_AFTER + 1)
        outputs = _matrix_outputs(zones, interfaces, "Server error : Invalid syntax.")
        ctx = _FakeCtx(outputs)
        with self.assertRaises(checks.CollectError):
            checks._collect_session_matrix(ctx)
        pair_commands = [command for command in ctx.commands if " from " in command]
        self.assertEqual(len(pair_commands), checks._SWEEP_ABORT_AFTER)

    def test_zone_ceiling_refuses_never_truncates(self):
        interfaces = _loader.fixture_text("panos_interfaces.txt")
        constants = _loader.constants
        original = constants.SESSION_MATRIX_MAX_PAIR_QUERIES
        constants.SESSION_MATRIX_MAX_PAIR_QUERIES = 4  # any fixture has >2 zones
        try:
            with self.assertRaises(checks.CollectError):
                checks._collect_session_matrix(_FakeCtx({"show interface all": interfaces}))
        finally:
            constants.SESSION_MATRIX_MAX_PAIR_QUERIES = original

    def test_record_raw_truncates_dumps(self):
        raw = {}
        checks._record_raw(raw, "cmd", "x" * (checks._RAW_OUTPUT_CAP + 5000))
        self.assertIn("truncated 5000 chars", raw["cmd"])
        self.assertLess(len(raw["cmd"]), checks._RAW_OUTPUT_CAP + 100)
        checks._record_raw(raw, "small", "ok")
        self.assertEqual(raw["small"], "ok")

    def test_sweep_announces_itself_and_emits_milestones(self):
        # Liveness: a healthy multi-minute sweep must never look hung. With
        # _PROGRESS_EVERY lowered below the pair count, at least one
        # percentage milestone must appear alongside the opening banner.
        class _FakeLogger:
            def __init__(self):
                self.infos = []

            def info(self, message, *args, **kwargs):
                self.infos.append(message % args if args else message)

            def warning(self, message, *args, **kwargs):
                pass

        interfaces = _loader.fixture_text("panos_interfaces.txt")
        zones = checks._parse_zones(interfaces)
        ctx = _FakeCtx(_matrix_outputs(zones, interfaces, _count_response(3)))
        ctx.logger = _FakeLogger()
        original = checks._PROGRESS_EVERY
        checks._PROGRESS_EVERY = 2
        try:
            checks._collect_session_matrix(ctx)
        finally:
            checks._PROGRESS_EVERY = original
        banner = [line for line in ctx.logger.infos if "sweeping" in line]
        milestones = [line for line in ctx.logger.infos if "remaining" in line]
        self.assertEqual(len(banner), 1)
        self.assertGreaterEqual(len(milestones), 1)
        self.assertIn("%", milestones[0])

    def test_fmt_duration(self):
        self.assertEqual(checks._fmt_duration(42), "42s")
        self.assertEqual(checks._fmt_duration(65), "1m05s")
        self.assertEqual(checks._fmt_duration(3601), "60m01s")


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

    def test_per_dataplane_members_are_summed(self):
        # Multi-DP platforms answer one count member per dataplane, no
        # aggregate phrase. The label's own digit (DP0) must not win — last
        # integer per member, summed.
        output = (
            '<response status="success"><result>'
            "<member>DP0: 6134</member><member>DP1: 6510</member>"
            "</result></response>"
        )
        self.assertEqual(checks._parse_session_count(output), 12644)

    def test_single_member_number_with_words(self):
        output = (
            '<response status="success"><result><member>Sessions: 1234</member></result></response>'
        )
        self.assertEqual(checks._parse_session_count(output), 1234)

    def test_member_without_integer_is_skipped_in_sum(self):
        output = (
            '<response status="success"><result>'
            "<member>counts follow</member><member>DP0: 40</member>"
            "</result></response>"
        )
        self.assertEqual(checks._parse_session_count(output), 40)

    def test_session_dump_is_never_misread_as_counts(self):
        # A response with <entry> children is a session dump — digits inside
        # it (ids, ports) must never be summed into a "count".
        output = (
            '<response status="success"><result>'
            "<entry><idx>4211</idx><dport>443</dport></entry>"
            "<entry><idx>4212</idx><dport>53</dport></entry>"
            "</result></response>"
        )
        self.assertIsNone(checks._parse_session_count(output))

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

    def test_non_xml_empty_reply_is_not_present_not_failed(self):
        # Field finding: a box with zero SAs answers `show vpn ike-sa` with NO
        # XML payload at all. For a presence enumeration that IS the answer —
        # not-present, never a failed check.
        ctx = _FakeCtx({"show vpn ike-sa": "\n\n", "show vpn ipsec-sa": ""})
        with self.assertRaises(checks.SkipCheck):
            checks._collect_ipsec(ctx)

    def test_one_side_non_xml_still_collects_the_other(self):
        ctx = _FakeCtx(
            {
                "show vpn ike-sa": _loader.fixture_text("panos_ike_sa.txt"),
                "show vpn ipsec-sa": "\n",
            }
        )
        result = checks._collect_ipsec(ctx)
        self.assertTrue(any(key.startswith("ike|") for key in result["normalized"]))
        self.assertFalse(any(key.startswith("tunnel|") for key in result["normalized"]))

    def test_rejected_commands_skip_with_reason(self):
        rejected = "Invalid syntax."
        ctx = _FakeCtx({"show vpn ike-sa": rejected, "show vpn ipsec-sa": rejected})
        with self.assertRaises(checks.SkipCheck) as caught:
            checks._collect_ipsec(ctx)
        self.assertIn("rejected", str(caught.exception))


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


class TestLoggingStatus(unittest.TestCase):
    def test_rejected_command_skips(self):
        ctx = _FakeCtx({"show logging-status": "Invalid syntax."})
        with self.assertRaises(checks.SkipCheck):
            checks._collect_logging_status(ctx)

    def test_xml_entries_counted_into_context(self):
        output = (
            '<response status="success"><result>'
            "<entry><name>log-collector-1</name></entry>"
            "<entry><name>log-collector-2</name></entry>"
            "</result></response>"
        )
        ctx = _FakeCtx({"show logging-status": output})
        result = checks._collect_logging_status(ctx)
        self.assertEqual(result["raw"]["show logging-status"], output)
        self.assertEqual(result["context"]["destination_entries"], 2)
        self.assertEqual(result["normalized"], {})

    def test_non_xml_output_keeps_raw_without_entry_count(self):
        # Shape unverified on 11.2: a non-XML reply still records raw for the
        # shakedown to refine against — never a failed read.
        output = "Log forwarding agent is active.\n"
        ctx = _FakeCtx({"show logging-status": output})
        result = checks._collect_logging_status(ctx)
        self.assertEqual(result["raw"]["show logging-status"], output)
        self.assertNotIn("destination_entries", result["context"])
        self.assertEqual(result["normalized"], {})

    def test_oversized_output_is_capped_in_raw(self):
        output = "x" * (checks._RAW_OUTPUT_CAP + 5000)
        ctx = _FakeCtx({"show logging-status": output})
        result = checks._collect_logging_status(ctx)
        self.assertIn("truncated 5000 chars", result["raw"]["show logging-status"])


class TestUrlCloud(unittest.TestCase):
    def test_rejected_command_skips_unlicensed(self):
        ctx = _FakeCtx({"show url-cloud status": "Unknown command: url-cloud"})
        with self.assertRaises(checks.SkipCheck):
            checks._collect_url_cloud(ctx)

    def test_connected_in_xml_text(self):
        output = (
            '<response status="success"><result>'
            "PAN-DB cloud connection: connected"
            "</result></response>"
        )
        ctx = _FakeCtx({"show url-cloud status": output})
        result = checks._collect_url_cloud(ctx)
        self.assertEqual(result["normalized"], {"cloud": {"value": "connected"}})

    def test_not_connected_wins_over_its_connected_substring(self):
        # "not connected" contains "connected" — the negative must win.
        ctx = _FakeCtx({"show url-cloud status": "Cloud connection status: Not Connected\n"})
        result = checks._collect_url_cloud(ctx)
        self.assertEqual(result["normalized"], {"cloud": {"value": "not-connected"}})

    def test_disconnected_reads_as_not_connected(self):
        ctx = _FakeCtx({"show url-cloud status": "Status: Disconnected"})
        result = checks._collect_url_cloud(ctx)
        self.assertEqual(result["normalized"], {"cloud": {"value": "not-connected"}})

    def test_unknown_shape_keeps_raw_with_empty_normalized(self):
        output = "URL cloud telemetry unavailable"
        ctx = _FakeCtx({"show url-cloud status": output})
        result = checks._collect_url_cloud(ctx)
        self.assertEqual(result["normalized"], {})
        self.assertEqual(result["raw"]["show url-cloud status"], output)


class TestNtp(unittest.TestCase):
    def test_rejected_command_skips(self):
        ctx = _FakeCtx({"show ntp": "Invalid syntax."})
        with self.assertRaises(checks.SkipCheck):
            checks._collect_ntp(ctx)

    def test_synched_leaf(self):
        output = (
            '<response status="success"><result><synched>10.0.0.1</synched></result></response>'
        )
        ctx = _FakeCtx({"show ntp": output})
        result = checks._collect_ntp(ctx)
        self.assertEqual(result["normalized"], {"synched": {"value": "10.0.0.1"}})

    def test_sync_spelling_variant(self):
        output = '<response status="success"><result><sync>yes</sync></result></response>'
        ctx = _FakeCtx({"show ntp": output})
        result = checks._collect_ntp(ctx)
        self.assertEqual(result["normalized"], {"synched": {"value": "yes"}})

    def test_nested_synched_leaf(self):
        output = (
            '<response status="success"><result><ntp-servers>'
            "<synched>LOCAL</synched>"
            "</ntp-servers></result></response>"
        )
        ctx = _FakeCtx({"show ntp": output})
        result = checks._collect_ntp(ctx)
        self.assertEqual(result["normalized"], {"synched": {"value": "LOCAL"}})

    def test_unknown_shape_keeps_raw_with_empty_normalized(self):
        output = '<response status="success"><result><clock>ok</clock></result></response>'
        ctx = _FakeCtx({"show ntp": output})
        result = checks._collect_ntp(ctx)
        self.assertEqual(result["normalized"], {})
        self.assertEqual(result["raw"]["show ntp"], output)


class TestPendingChanges(unittest.TestCase):
    def test_rejected_command_skips(self):
        ctx = _FakeCtx({"check pending-changes": "Unknown command: check"})
        with self.assertRaises(checks.SkipCheck):
            checks._collect_pending_changes(ctx)

    def test_xml_yes(self):
        output = '<response status="success"><result>yes</result></response>'
        ctx = _FakeCtx({"check pending-changes": output})
        result = checks._collect_pending_changes(ctx)
        self.assertEqual(result["normalized"], {"pending": "yes"})

    def test_xml_no(self):
        output = '<response status="success"><result>no</result></response>'
        ctx = _FakeCtx({"check pending-changes": output})
        result = checks._collect_pending_changes(ctx)
        self.assertEqual(result["normalized"], {"pending": "no"})

    def test_plain_text_yes(self):
        ctx = _FakeCtx({"check pending-changes": "Yes\n"})
        result = checks._collect_pending_changes(ctx)
        self.assertEqual(result["normalized"], {"pending": "yes"})

    def test_plain_text_no(self):
        ctx = _FakeCtx({"check pending-changes": "No\n"})
        result = checks._collect_pending_changes(ctx)
        self.assertEqual(result["normalized"], {"pending": "no"})

    def test_yes_wins_when_both_words_present(self):
        ctx = _FakeCtx({"check pending-changes": "yes (no pending commit locks)"})
        result = checks._collect_pending_changes(ctx)
        self.assertEqual(result["normalized"], {"pending": "yes"})

    def test_no_never_matches_inside_another_word(self):
        # "Nothing" starts with "no" — word-anchoring must keep it from
        # fabricating a "no" answer; unknown shape keeps raw, normalized {}.
        output = "Nothing to report"
        ctx = _FakeCtx({"check pending-changes": output})
        result = checks._collect_pending_changes(ctx)
        self.assertEqual(result["normalized"], {})
        self.assertEqual(result["raw"]["check pending-changes"], output)


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
        "panos_bgp_peers",
        "panos_globalprotect",
        "panos_dhcp",
        "panos_logging_status",
        "panos_url_cloud",
        "panos_ntp",
        "panos_pending_changes",
        "panos_pbf",
        "panos_drop_counters",
        "panos_nat_pools",
        "panos_rule_hit_counts",
        "panos_ospf_neighbors",
        "panos_crash_files",
    }

    def test_all_registered_once(self):
        registered = {
            check_id for check_id, check in registry.CHECKS.items() if check.platform == "panos"
        }
        self.assertEqual(registered, self.EXPECTED_IDS)

    def test_checks_for_filters_by_platform(self):
        ids = {check.id for check in registry.checks_for("panos")}
        self.assertEqual(ids, self.EXPECTED_IDS)

    def test_every_check_has_collector_and_valid_mode(self):
        diffcore = _loader.diffcore
        for check in registry.CHECKS.values():
            if check.platform != "panos":
                continue
            self.assertTrue(callable(check.collector), check.id)
            self.assertIn(check.compare.get("mode", "equality_set"), diffcore.MODES, check.id)

    def test_every_registered_check_has_semantics(self):
        # The self-description contract: snapshots must explain themselves,
        # so a check without SEMANTICS text ships an unreadable section.
        for check_id in registry.CHECKS:
            self.assertIn(check_id, registry.SEMANTICS, check_id)
            self.assertGreater(len(registry.SEMANTICS[check_id]), 40, check_id)

    def test_matrix_collector_exposes_reconciliation_context(self):
        interfaces = _loader.fixture_text("panos_interfaces.txt")
        zones = checks._parse_zones(interfaces)
        result = checks._collect_session_matrix(
            _FakeCtx(_matrix_outputs(zones, interfaces, _count_response(12)))
        )
        context = result["context"]
        self.assertEqual(context["matrix_total"], 12 * len(zones) * len(zones))
        self.assertIn("filterable_at_sweep", context)
        self.assertIn("session_info_at_sweep", context)
        self.assertEqual(context["zones"], zones)


class TestTierBChecks(unittest.TestCase):
    def test_pbf_entries_and_empty_skip(self):
        output = (
            '<response status="success"><result><entry name="pbf-voip">'
            "<action>forward</action><egress-if>ethernet1/5</egress-if>"
            "</entry></result></response>"
        )
        result = checks._collect_pbf(_FakeCtx({"show pbf rule all": output}))
        self.assertEqual(
            result["normalized"]["pbf|pbf-voip"], {"action": "forward", "egress": "ethernet1/5"}
        )
        with self.assertRaises(checks.SkipCheck):
            checks._collect_pbf(_FakeCtx({"show pbf rule all": _EMPTY_RESULT}))
        with self.assertRaises(checks.SkipCheck):
            checks._collect_pbf(_FakeCtx({"show pbf rule all": "Invalid syntax."}))

    def test_drop_counters_top_by_value(self):
        entries = "".join(
            "<entry><name>ctr%d</name><value>%d</value></entry>" % (i, i * 10) for i in range(50)
        )
        output = '<response status="success"><result>%s</result></response>' % (entries,)
        ctx = _FakeCtx({"show counter global filter severity drop": output})
        result = checks._collect_drop_counters(ctx)
        self.assertEqual(len(result["normalized"]), 40)  # top-40 cap
        self.assertIn("ctr49", result["normalized"])  # biggest kept
        self.assertNotIn("ctr0", result["normalized"])  # smallest dropped
        self.assertEqual(result["context"]["counter_count"], 50)

    def test_nat_pools_raw_first_and_skip_when_all_rejected(self):
        pool = '<response status="success"><result><entry/></result></response>'
        outputs = {
            "show running ippool": pool,
            "show running global-ippool": "Invalid syntax.",
        }
        result = checks._collect_nat_pools(_FakeCtx(outputs))
        self.assertEqual(result["context"]["entries"]["show running ippool"], 1)
        self.assertEqual(result["normalized"], {})
        rejected = {command: "Invalid syntax." for command in outputs}
        with self.assertRaises(checks.SkipCheck):
            checks._collect_nat_pools(_FakeCtx(rejected))

    def test_rule_hit_counts_fallback_form_and_parse(self):
        hit = (
            '<response status="success"><result><entry name="allow-web">'
            "<hit-count>120345</hit-count><last-hit-timestamp>2026/08/24 10:00:01"
            "</last-hit-timestamp></entry></result></response>"
        )
        primary = "show rule-hit-count vsys vsys-name vsys1 rule-base security rules all"
        outputs = {
            primary: "Invalid syntax.",
            "show running rule-use hit-count vsys vsys1 rule-base security rules all": hit,
            "show running rule-use hit-count vsys vsys1 rule-base nat rules all": _EMPTY_RESULT,
        }
        ctx = _FakeCtx(outputs)
        result = checks._collect_rule_hit_counts(ctx)
        self.assertEqual(
            result["normalized"]["security|allow-web"],
            {"hit_count": 120345, "last_hit": "2026/08/24 10:00:01"},
        )
        # Once the fallback form is accepted, the primary form is not retried
        # for the second rulebase.
        self.assertNotIn(
            "show rule-hit-count vsys vsys-name vsys1 rule-base nat rules all", ctx.commands
        )
        both_rejected = {
            form % (rulebase,): "Invalid syntax."
            for rulebase in ("security", "nat")
            for form in (
                "show rule-hit-count vsys vsys-name vsys1 rule-base %s rules all",
                "show running rule-use hit-count vsys vsys1 rule-base %s rules all",
            )
        }
        with self.assertRaises(checks.SkipCheck):
            checks._collect_rule_hit_counts(_FakeCtx(both_rejected))


class TestOspfAndCrashFiles(unittest.TestCase):
    def test_ospf_neighbors_legacy_form(self):
        output = (
            '<response status="success"><result><entry>'
            "<neighbor-router-id>10.9.25.2</neighbor-router-id>"
            "<neighbor-address>10.9.25.2</neighbor-address><status>full</status>"
            "</entry></result></response>"
        )
        ctx = _FakeCtx({"show routing protocol ospf neighbor": output})
        result = checks._collect_ospf_neighbors(ctx)
        self.assertEqual(
            result["normalized"]["ospf|10.9.25.2"],
            {"state": "full", "address": "10.9.25.2"},
        )

    def test_ospf_falls_back_to_advanced_then_skips(self):
        ctx = _FakeCtx(
            {
                "show routing protocol ospf neighbor": "Invalid syntax.",
                "show advanced-routing ospf neighbor": _EMPTY_RESULT,
            }
        )
        with self.assertRaises(checks.SkipCheck):
            checks._collect_ospf_neighbors(ctx)

    def test_core_files_ls_semantics_and_window(self):
        from datetime import datetime, timezone

        now = datetime(2026, 8, 24, tzinfo=timezone.utc)
        output = (
            "total 3\n"
            "-rw-r--r-- 1 root root 123456 Aug 22 18:22 core.pan_task.1234\n"
            "-rw-r--r-- 1 root root 123456 Dec 30 11:00 core.wrapped_year\n"
            "-rw-r--r-- 1 root root 123456 Aug 22 2024 core.ancient\n"
        )
        recent, older = checks._parse_core_files(output, now, 7)
        self.assertEqual(list(recent), ["core.pan_task.1234"])  # time-form, this year
        self.assertEqual(older, 2)  # Dec 30 wraps to 2025 (old); explicit 2024 old

    def test_crash_collector_window_and_context(self):
        from datetime import datetime, timezone

        now = datetime(2026, 8, 24, tzinfo=timezone.utc)
        output = (
            "-rw-r--r-- 1 root root 1 Aug 23 01:00 core.fresh\n"
            "-rw-r--r-- 1 root root 1 Jan 05 2023 core.ancient\n"
        )
        ctx = _FakeCtx({"show system files": output})
        result = checks._collect_crash_files(ctx, now=now)
        self.assertEqual(list(result["normalized"]), ["core.fresh"])
        self.assertEqual(result["context"]["older_files_ignored"], 1)


if __name__ == "__main__":
    unittest.main()
