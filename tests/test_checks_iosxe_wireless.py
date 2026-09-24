"""checks_iosxe_wireless: the controller gate, every normalizer, and the collectors.

Driven with synthetic RESTCONF fixtures shaped after the published 17.12.1
wireless YANG models (tests/fixtures/wlc_*); the shakedown harvest replaces
them with sanitized real captures one by one. No Nautobot, no network.
"""

import json
import unittest

if __package__:
    from . import _loader
else:  # unittest discover -s tests imports test modules as top-level
    import _loader

wlc = _loader.load("checks_iosxe_wireless")
registry = _loader.registry
constants = _loader.constants
J = _loader.fixture_json
T = _loader.fixture_text

HW_9800 = "wlc_device_hardware_9800.json"
HW_9500 = "iosxe_device_hardware.json"

EXPECTED_IDS = {
    "wlc_ap_inventory",
    "wlc_ap_radios",
    "wlc_ap_uplinks",
    "wlc_ap_join_stats",
    "wlc_clients_summary",
    "wlc_client_table",
    "wlc_wlan_config",
    "wlc_tag_config",
    "wlc_mobility",
    "wlc_platform",
    "iosxe_aaa_servers",
}


class _Http(Exception):
    """Stand-in for RestconfError: carries the HTTP status the fetch helper inspects."""

    def __init__(self, status):
        super().__init__("HTTP %s" % (status,))
        self.status_code = status


class _Ctx:
    """Duck-typed CollectorContext.

    GET paths route to payloads by the LONGEST token found in the resource
    path (the part before any ?fields=), so a fields filter that happens to
    mention another list's name never misroutes. A payload may be an
    exception (raised) or a callable (called with the full path).
    """

    def __init__(self, payloads, ssh=None):
        self.payloads = payloads
        self.ssh_outputs = ssh
        self.calls = []
        self.ssh_calls = []
        self.platform = "iosxe"
        self.device_name = "wlc-test"

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
        return self.ssh_outputs.get(command, "")

    def resources(self):
        return sorted({path.split("?", 1)[0] for path in self.calls})


def _controller(**extra):
    payloads = {
        "device-hardware-data": J(HW_9800),
        "ap-name-mac-map": J("wlc_ap_name_mac_map.json"),
    }
    payloads.update(extra)
    return payloads


def _reject_fields(fixture_name):
    """A payload callable: HTTP 400 for the filtered path, the fixture unfiltered."""

    def answer(path):
        if "?fields=" in path:
            raise _Http(400)
        return J(fixture_name)

    return answer


WIRELESS_COLLECTORS = [
    check.collector
    for check_id, check in sorted(registry.CHECKS.items())
    if check_id.startswith("wlc_")
]


class TestHelpers(unittest.TestCase):
    def test_node_and_entries_accept_list_and_container_forms(self):
        list_form = {"mod:capwap-data": [{"name": "a"}]}
        container_form = {"mod:access-point-oper-data": {"capwap-data": [{"name": "a"}]}}
        single = {"mod:capwap-data": {"name": "a"}}
        for payload in (list_form, container_form, single):
            self.assertEqual(wlc._entries(payload, "capwap-data"), [{"name": "a"}])
        self.assertEqual(wlc._entries({}, "capwap-data"), [])
        self.assertEqual(wlc._entries(None, "capwap-data"), [])
        self.assertIsNone(wlc._node({"mod:other": 1}, "capwap-data"))

    def test_enum_and_value_helpers(self):
        self.assertEqual(wlc._short("client-status-run", "client-status-"), "run")
        self.assertEqual(wlc._short("weird", "client-status-"), "weird")
        self.assertIsNone(wlc._short(None, "x-"))
        self.assertEqual(wlc._ap_mode("local-mode"), "local")
        self.assertEqual(wlc._ap_mode("mode-flex-connect"), "flex-connect")
        self.assertEqual(wlc._config_source("config-auto"), "auto")
        self.assertEqual(wlc._config_source("customized"), "static")
        self.assertTrue(wlc._yes("true"))
        self.assertFalse(wlc._yes(False))
        self.assertIsNone(wlc._yes(None))
        self.assertEqual(wlc._compact({"a": 1, "b": None, "c": False}), {"a": 1, "c": False})
        self.assertEqual(wlc._mac("00:11:22:33:44:0F"), "00:11:22:33:44:0f")

    def test_scrub_masks_secret_leaves_but_keeps_the_flags(self):
        node = {
            "psk": "x",
            "psk-type": "ascii",
            "auth-key-mgmt-psk": True,
            "mpsk-key": "y",
            "wep-key": "z",
            "wep-key-size": 40,
            "password": "p",
            "nested": [{"radius-key": "k", "shared-secret": "s", "description": "ok"}],
        }
        wlc._scrub(node)
        for key in ("psk", "mpsk-key", "wep-key", "password"):
            self.assertEqual(node[key], "***scrubbed***", key)
        self.assertEqual(node["nested"][0]["radius-key"], "***scrubbed***")
        self.assertEqual(node["nested"][0]["shared-secret"], "***scrubbed***")
        self.assertEqual(node["nested"][0]["description"], "ok")
        self.assertEqual(node["psk-type"], "ascii")
        self.assertIs(node["auth-key-mgmt-psk"], True)
        self.assertEqual(node["wep-key-size"], 40)


class TestControllerGate(unittest.TestCase):
    def test_9800_model_is_a_controller_without_probing(self):
        ctx = _Ctx({"device-hardware-data": J(HW_9800)})
        facts = wlc._controller(ctx)
        self.assertEqual(facts["model"], "C9800-CL-K9")
        self.assertEqual(facts["identified_by"], "chassis model")
        self.assertFalse(any("ap-name-mac-map" in path for path in ctx.calls))

    def test_switch_serving_wireless_data_is_a_controller(self):
        ctx = _Ctx(
            {"device-hardware-data": J(HW_9500), "ap-name-mac-map": J("wlc_ap_name_mac_map.json")}
        )
        facts = wlc._controller(ctx)
        self.assertEqual(facts["model"], "C9500-48Y4C")
        self.assertEqual(facts["identified_by"], "wireless oper data")

    def test_switch_without_wireless_data_is_not_present_after_one_probe(self):
        ctx = _Ctx({"device-hardware-data": J(HW_9500)})
        for collector in WIRELESS_COLLECTORS:
            with self.assertRaises(registry.SkipCheck):
                collector(ctx)
        # Every wireless check asked the same two things and nothing else: the
        # hardware read platform-health already makes, and the one probe.
        self.assertEqual(
            ctx.resources(),
            [
                "/data/Cisco-IOS-XE-device-hardware-oper:device-hardware-data",
                "/data/Cisco-IOS-XE-wireless-access-point-oper:access-point-oper-data/ap-name-mac-map",
            ],
        )

    def test_empty_probe_on_a_switch_is_not_present(self):
        ctx = _Ctx({"device-hardware-data": J(HW_9500), "ap-name-mac-map": {}})
        with self.assertRaises(registry.SkipCheck):
            wlc._controller(ctx)

    def test_controller_without_roster_is_a_failed_read(self):
        ctx = _Ctx(_controller())  # no capwap-data: the fetch sees a 404
        with self.assertRaises(registry.CollectError) as raised:
            wlc._collect_ap_inventory(ctx)
        self.assertIn("404", str(raised.exception))
        self.assertIn("C9800-CL-K9", str(raised.exception))

    def test_positively_empty_roster_is_real_data(self):
        ctx = _Ctx(_controller(**{"capwap-data": {}}))
        outcome = wlc._collect_ap_inventory(ctx)
        self.assertEqual(outcome["normalized"], {})
        self.assertEqual(outcome["context"]["ap_count"], 0)


class TestFetchFallback(unittest.TestCase):
    def test_fields_rejection_falls_back_to_the_unfiltered_list(self):
        ctx = _Ctx(_controller(**{"capwap-data": _reject_fields("wlc_capwap_data.json")}))
        outcome = wlc._collect_ap_inventory(ctx)
        self.assertEqual(len(outcome["normalized"]), 3)
        self.assertIn("fields filter rejected", outcome["raw"]["note"])
        unfiltered = [p for p in ctx.calls if p.endswith("/capwap-data")]
        self.assertEqual(len(unfiltered), 1)

    def test_other_http_errors_propagate(self):
        ctx = _Ctx(_controller(**{"capwap-data": _Http(500)}))
        with self.assertRaises(_Http):
            wlc._collect_ap_inventory(ctx)


class TestApInventory(unittest.TestCase):
    def setUp(self):
        self.entries = wlc._entries(J("wlc_capwap_data.json"), "capwap-data")
        self.normalized = wlc._normalize_ap_inventory(self.entries)

    def test_keys_and_identity(self):
        self.assertEqual(
            set(self.normalized),
            {"ap|AP-3F-EAST-01", "ap|AP-3F-WEST-02", "ap|AP-LOBBY-03"},
        )
        east = self.normalized["ap|AP-3F-EAST-01"]
        self.assertEqual(east["model"], "C9130AXI-B")
        self.assertEqual(east["serial"], "FGL0000AB01")
        self.assertEqual(east["mac"], "00:11:22:33:44:00")
        self.assertEqual(east["eth_mac"], "00:11:22:33:44:01")
        self.assertEqual(east["ip"], "10.20.30.11")
        self.assertEqual(east["sw_version"], "17.12.4.42")
        self.assertEqual(east["mode"], "local")
        self.assertEqual(east["admin_state"], "enabled")
        self.assertEqual(east["oper_state"], "registered")
        self.assertEqual(east["country"], "US")
        self.assertEqual(east["location"], "Building A floor 3 east")
        self.assertEqual(east["radio_slots"], 3)
        self.assertIs(east["lag"], False)

    def test_tags_resolved_with_source(self):
        east = self.normalized["ap|AP-3F-EAST-01"]
        self.assertEqual(
            (east["policy_tag"], east["site_tag"], east["rf_tag"]), ("PT-HQ", "ST-HQ-3F", "RF-HQ")
        )
        self.assertEqual(east["tag_source"], "static")
        self.assertIs(east["misconfigured"], False)
        self.assertEqual(east["flex_profile"], "FLEX-HQ")
        west = self.normalized["ap|AP-3F-WEST-02"]
        self.assertEqual(west["mode"], "flex-connect")
        self.assertEqual(west["tag_source"], "default")
        self.assertIs(west["misconfigured"], True)
        self.assertEqual(west["policy_tag"], "default-policy-tag")

    def test_sparse_entry_omits_unpublished_facets(self):
        lobby = self.normalized["ap|AP-LOBBY-03"]
        self.assertEqual(lobby["oper_state"], "downloading")
        self.assertEqual(lobby["sw_version"], "17.9.5.47")
        for absent in ("policy_tag", "mode", "location", "tag_source", "misconfigured"):
            self.assertNotIn(absent, lobby)

    def test_context_counts(self):
        context = wlc._ap_context(self.normalized)
        self.assertEqual(context["ap_count"], 3)
        self.assertEqual(context["registered"], 2)
        self.assertEqual(context["not_registered"], 1)
        self.assertEqual(context["misconfigured"], 1)
        self.assertEqual(context["by_mode"], {"local": 1, "flex-connect": 1, "unknown": 1})
        self.assertEqual(context["by_version"], {"17.12.4.42": 2, "17.9.5.47": 1})

    def test_collector_end_to_end(self):
        ctx = _Ctx(_controller(**{"capwap-data": J("wlc_capwap_data.json")}))
        outcome = wlc._collect_ap_inventory(ctx)
        self.assertEqual(len(outcome["normalized"]), 3)
        self.assertEqual(outcome["context"]["controller"]["identified_by"], "chassis model")
        self.assertIn("capwap-data", outcome["raw"])
        self.assertNotIn("note", outcome["raw"])


class TestRadios(unittest.TestCase):
    def setUp(self):
        ctx = _Ctx(_controller())
        self.names = wlc._ap_names(ctx)
        self.entries = wlc._entries(J("wlc_radio_oper_data.json"), "radio-oper-data")
        self.normalized = wlc._normalize_radios(self.entries, self.names)

    def test_keys_use_ap_names_and_fall_back_to_the_mac(self):
        self.assertEqual(
            set(self.normalized),
            {
                "radio|AP-3F-EAST-01|0",
                "radio|AP-3F-EAST-01|1",
                "radio|AP-3F-EAST-01|2",
                "radio|AP-3F-WEST-02|0",
                "radio|AP-3F-WEST-02|1",
                "radio|00:11:22:33:44:99|0",
            },
        )

    def test_channel_power_and_their_sources(self):
        slot0 = self.normalized["radio|AP-3F-EAST-01|0"]
        self.assertEqual(slot0["band"], "2.4GHz")
        self.assertEqual(slot0["oper_state"], "up")
        self.assertEqual((slot0["channel"], slot0["width"]), (6, 20))
        self.assertEqual(slot0["channel_source"], "auto")
        self.assertEqual((slot0["power_level"], slot0["power_dbm"]), (3, 14))
        self.assertEqual(slot0["power_source"], "auto")
        self.assertEqual(slot0["bssid"], "00:11:22:33:44:0f")
        slot1 = self.normalized["radio|AP-3F-EAST-01|1"]
        self.assertEqual(slot1["band"], "5GHz")
        self.assertEqual((slot1["channel"], slot1["width"]), (36, 40))
        self.assertEqual(slot1["channel_source"], "static")
        self.assertEqual(slot1["power_source"], "static")
        self.assertEqual(slot1["power_dbm"], 20)

    def test_down_radio_and_current_band_selection(self):
        six = self.normalized["radio|AP-3F-EAST-01|2"]
        self.assertEqual(six["band"], "6GHz")
        self.assertEqual(six["oper_state"], "down")
        self.assertNotIn("channel", six)
        west1 = self.normalized["radio|AP-3F-WEST-02|1"]
        self.assertEqual((west1["power_level"], west1["power_dbm"]), (2, 17))
        self.assertEqual(west1["bands"], 2)
        west0 = self.normalized["radio|AP-3F-WEST-02|0"]
        self.assertEqual(west0["admin_state"], "disabled")

    def test_context_totals_and_device_corroboration(self):
        context = wlc._radio_context(self.normalized, J("wlc_ewlc_ap_stats.json"))
        self.assertEqual(context["radios_total"], 6)
        self.assertEqual(context["radios_up"], 4)
        self.assertEqual(context["radios_down"], 2)
        self.assertEqual(context["radios_admin_disabled"], 1)
        self.assertEqual(context["per_band"]["5GHz"], {"total": 2, "up": 2, "down": 0})
        self.assertEqual(context["device_reported"]["all"], {"total": 6, "up": 4, "down": 2})
        self.assertEqual(context["device_reported_misconfigured_aps"], 1)

    def test_collector_notes_missing_device_stats(self):
        ctx = _Ctx(_controller(**{"radio-oper-data": J("wlc_radio_oper_data.json")}))
        outcome = wlc._collect_ap_radios(ctx)
        self.assertEqual(len(outcome["normalized"]), 6)
        self.assertIn("ewlc-ap-stats not served", outcome["raw"]["note"])
        self.assertNotIn("device_reported", outcome["context"])


class TestUplinks(unittest.TestCase):
    def test_cdp_lldp_and_ethernet_views(self):
        ctx = _Ctx(
            _controller(
                **{
                    "cdp-cache-data": J("wlc_cdp_cache_data.json"),
                    "lldp-neigh": J("wlc_lldp_neigh.json"),
                    "ethernet-if-stats": J("wlc_ethernet_if_stats.json"),
                }
            )
        )
        outcome = wlc._collect_ap_uplinks(ctx)
        normalized = outcome["normalized"]
        cdp = normalized["cdp|AP-3F-EAST-01|GigabitEthernet0"]
        self.assertEqual(cdp["neighbor"], "SW-HQ-3F-STACK.example.net")
        self.assertEqual(cdp["neighbor_port"], "GigabitEthernet1/0/12")
        self.assertEqual(cdp["neighbor_platform"], "cisco C9300-48U")
        self.assertEqual(cdp["neighbor_ip"], "10.20.30.2")
        lldp = normalized["lldp|AP-3F-EAST-01|GigabitEthernet0"]
        self.assertEqual(lldp["neighbor"], "SW-HQ-3F-STACK")
        self.assertEqual(lldp["neighbor_port"], "Gi1/0/12")
        self.assertEqual(normalized["eth|AP-LOBBY-03|GigabitEthernet0"]["link"], "down")
        self.assertEqual(normalized["eth|AP-3F-WEST-02|GigabitEthernet0"]["speed"], 100)
        context = outcome["context"]
        self.assertEqual(context["aps_with_cdp"], 2)
        self.assertEqual(context["aps_with_lldp"], 1)
        self.assertEqual(context["eth_ports"], 3)
        self.assertEqual(context["eth_ports_down"], 1)
        self.assertEqual(context["eth_ports_below_1g"], ["eth|AP-3F-WEST-02|GigabitEthernet0"])

    def test_cdp_entry_without_ap_name_resolves_through_the_mac_map(self):
        names = wlc._ap_names(_Ctx(_controller()))
        cdp = [
            {
                "mac-addr": "00:11:22:33:44:11",
                "wtp-mac-addr": "00:11:22:33:44:10",
                "cdp-cache-device-id": "SW",
                "cdp-cache-local-port": "GigabitEthernet0",
            }
        ]
        normalized = wlc._normalize_uplinks(cdp, [], [], names)
        self.assertIn("cdp|AP-3F-WEST-02|GigabitEthernet0", normalized)


class TestJoinStats(unittest.TestCase):
    def test_history_merged_with_current_roster(self):
        ctx = _Ctx(
            _controller(
                **{
                    "ap-join-stats": J("wlc_ap_join_stats.json"),
                    "capwap-data": J("wlc_capwap_data.json"),
                }
            )
        )
        outcome = wlc._collect_ap_join_stats(ctx)
        normalized = outcome["normalized"]
        self.assertEqual(
            set(normalized),
            {"ap|AP-3F-EAST-01", "ap|AP-3F-WEST-02", "ap|AP-LOBBY-03", "ap|AP-OLD-04"},
        )
        east = normalized["ap|AP-3F-EAST-01"]
        self.assertIs(east["joined"], True)
        self.assertEqual(east["boot_time"], "2026-09-01T08:00:00+00:00")
        self.assertEqual(east["join_time"], "2026-09-01T08:03:12+00:00")
        self.assertEqual(east["join_time_taken_s"], 45)
        self.assertEqual(east["join_requests"], 1)
        # capwap's current reboot reason wins over the history list's.
        self.assertEqual(east["reboot_reason"], "reboot-reason-reload-command")
        west = normalized["ap|AP-3F-WEST-02"]
        self.assertEqual(
            (west["join_requests"], west["join_successes"], west["join_failures"]), (3, 2, 1)
        )
        self.assertEqual(west["last_error"], "join-timeout")
        self.assertEqual(west["dtls_ctrl_failures"], 1)
        old = normalized["ap|AP-OLD-04"]
        self.assertIs(old["joined"], False)
        self.assertEqual(old["disconnect_reason"], "disconnect-reason-heartbeat-timeout")
        self.assertNotIn("boot_time", old)
        lobby = normalized["ap|AP-LOBBY-03"]
        self.assertIs(lobby["joined"], True)
        self.assertEqual(outcome["context"], {"known_total": 4, "joined": 3, "not_joined": 1})


def _client_payloads():
    return {
        "client-live-stats": J("wlc_client_live_stats.json"),
        "wlan-info": J("wlc_wlan_info.json"),
        "common-oper-data": J("wlc_client_common_oper_data.json"),
        "policy-data": J("wlc_client_policy_data.json"),
        "dot11-oper-data": J("wlc_client_dot11_oper_data.json"),
        "sisf-db-mac": J("wlc_sisf_db_mac.json"),
        "exclusion-data": J("wlc_client_exclusion_data.json"),
    }


class TestClientsSummary(unittest.TestCase):
    def setUp(self):
        self.ctx = _Ctx(_controller(**_client_payloads()))
        self.outcome = wlc._collect_clients_summary(self.ctx)

    def test_capability_buckets(self):
        normalized = self.outcome["normalized"]
        expected = {
            "total": 8,
            "run-state": 6,
            "wlan|CORP": 5,
            "wlan|GUEST": 3,
            "wlan|IOT": 0,
            "ap|AP-3F-EAST-01": 4,
            "ap|AP-3F-WEST-02": 4,
            "band|5GHz": 7,
            "band|2.4GHz": 1,
            "vlan|120": 4,
            "vlan|130": 3,
        }
        self.assertEqual(normalized, expected)
        # The capability diff contract: flat numeric (or None) values only.
        for key, value in normalized.items():
            self.assertTrue(value is None or isinstance(value, int), key)
        self.assertFalse(any(key.startswith("state|") for key in normalized))

    def test_context_carries_the_state_distribution_and_reconciliation(self):
        context = self.outcome["context"]
        self.assertEqual(
            context["live_states"],
            {"auth": 1, "mobility": 0, "iplearn": 1, "webauth": 0, "run": 6, "delete": 0},
        )
        self.assertEqual(context["live_total"], 8)
        self.assertEqual(context["random_mac_clients"], 3)
        self.assertEqual(context["table_total"], 8)
        self.assertEqual(
            context["table_by_state"], {"run": 6, "ip-learning": 1, "authenticating": 1}
        )
        self.assertEqual(context["not_run_state"], 2)
        self.assertEqual(context["wlan_total"], 8)
        self.assertEqual(context["aps_with_clients"], 2)
        self.assertEqual(context["vlan_names"], {"120": "CORP-USERS", "130": "GUEST-VLAN"})
        self.assertEqual(context["excluded_total"], 1)
        self.assertEqual(context["excluded_by_reason"], {"dot1x-auth-fail": 1})

    def test_raw_keeps_only_the_small_views(self):
        raw = self.outcome["raw"]
        self.assertIn("client-live-stats", raw)
        self.assertIn("wlan-info", raw)
        self.assertNotIn("common-oper-data", raw)
        self.assertNotIn("rows", raw)

    def test_usernames_are_never_requested(self):
        self.assertNotIn("username", wlc._CLIENT_FIELDS)
        for path in self.ctx.calls:
            self.assertNotIn("username", path)
            self.assertNotIn("dc-info", path)
            self.assertNotIn("client-wsa-info", path)


class TestClientTable(unittest.TestCase):
    def test_rows_join_the_four_lists(self):
        clients = wlc._entries(J("wlc_client_common_oper_data.json"), "common-oper-data")
        dot11 = wlc._entries(J("wlc_client_dot11_oper_data.json"), "dot11-oper-data")
        policies = wlc._entries(J("wlc_client_policy_data.json"), "policy-data")
        sisf = wlc._entries(J("wlc_sisf_db_mac.json"), "sisf-db-mac")
        rows = wlc._client_rows(clients, dot11, policies, sisf)
        self.assertEqual(len(rows), 8)
        one = rows["aa:bb:cc:00:00:01"]
        self.assertEqual(one["ap"], "AP-3F-EAST-01")
        self.assertEqual(one["band"], "5GHz")
        self.assertEqual(
            (one["wlan_id"], one["ssid"], one["policy_profile"]), (1, "Corp-WiFi", "PP-CORP")
        )
        self.assertEqual(one["state"], "run")
        self.assertEqual((one["vlan"], one["vlan_name"]), (120, "CORP-USERS"))
        self.assertEqual(one["ip"], "10.120.0.11")
        self.assertEqual(one["switching"], "central")
        stuck = rows["aa:bb:cc:00:00:04"]
        self.assertEqual(stuck["state"], "ip-learning")
        self.assertEqual(stuck["vlan"], 120)
        self.assertNotIn("ip", stuck)
        auth = rows["aa:bb:cc:00:00:05"]
        self.assertEqual(auth["state"], "authenticating")
        self.assertNotIn("vlan", auth)
        self.assertNotIn("username", json.dumps(rows).lower())

    def test_cap_keeps_every_non_run_client(self):
        clients = wlc._entries(J("wlc_client_common_oper_data.json"), "common-oper-data")
        rows = wlc._client_rows(clients, [], [], [])
        kept, omitted = wlc._cap_client_rows(rows, 3)
        self.assertEqual(len(kept), 3)
        self.assertEqual(omitted, 5)
        self.assertIn("client|aa:bb:cc:00:00:04", kept)
        self.assertIn("client|aa:bb:cc:00:00:05", kept)
        kept_all, omitted_all = wlc._cap_client_rows(rows, 100)
        self.assertEqual((len(kept_all), omitted_all), (8, 0))

    def test_collector_applies_the_configured_cap(self):
        ctx = _Ctx(_controller(**_client_payloads()))
        original = wlc.C.WLC_CLIENT_TABLE_MAX
        wlc.C.WLC_CLIENT_TABLE_MAX = 3
        try:
            outcome = wlc._collect_client_table(ctx)
        finally:
            wlc.C.WLC_CLIENT_TABLE_MAX = original
        self.assertEqual(outcome["context"]["clients_total"], 8)
        self.assertEqual(outcome["context"]["emitted"], 3)
        self.assertEqual(outcome["context"]["omitted_run_state"], 5)
        self.assertEqual(outcome["context"]["cap"], 3)
        self.assertEqual(
            outcome["context"]["by_state"], {"run": 6, "ip-learning": 1, "authenticating": 1}
        )
        self.assertEqual(len(outcome["raw"]["rows"]), 8)
        self.assertNotIn("note", outcome["raw"])


class TestWlanConfig(unittest.TestCase):
    def setUp(self):
        self.ctx = _Ctx(
            _controller(
                **{
                    "wlan-cfg-entry": J("wlc_wlan_cfg_entries.json"),
                    "wlan-policies/wlan-policy": J("wlc_wlan_policies.json"),
                    "policy-list-entry": J("wlc_policy_list_entries.json"),
                }
            )
        )
        self.outcome = wlc._collect_wlan_config(self.ctx)

    def test_wlans_policies_and_tags(self):
        normalized = self.outcome["normalized"]
        corp = normalized["wlan|CORP"]
        self.assertEqual(corp["wlan_id"], 1)
        self.assertEqual(corp["ssid"], "Corp-WiFi")
        self.assertIs(corp["enabled"], True)
        self.assertIs(corp["broadcast_ssid"], True)
        self.assertIs(corp["security_wpa"], True)
        self.assertEqual(corp["dot11_auth_type"], "open-system")
        self.assertIs(corp["webauth"], False)
        self.assertIs(normalized["wlan|IOT"]["enabled"], False)
        self.assertIs(normalized["wlan|GUEST"]["webauth"], True)
        pp = normalized["policy|PP-CORP"]
        self.assertEqual(pp["vlan"], "120")
        self.assertIs(pp["enabled"], True)
        self.assertIs(pp["central_switching"], True)
        self.assertIs(pp["central_dhcp"], True)
        self.assertIs(pp["vlan_central_switching"], False)
        self.assertIs(normalized["policy|PP-GUEST"]["central_switching"], False)
        self.assertEqual(normalized["policy|PP-GUEST"]["vlan"], "GUEST-VLAN")
        self.assertEqual(
            normalized["policy-tag|PT-HQ"]["wlans"], {"CORP": "PP-CORP", "GUEST": "PP-GUEST"}
        )
        self.assertEqual(normalized["policy-tag|default-policy-tag"]["wlans"], {})
        self.assertEqual(
            self.outcome["context"],
            {"wlans": 3, "wlans_enabled": 2, "policy_profiles": 3, "policy_tags": 2},
        )

    def test_no_key_material_leaves_the_collector(self):
        blob = json.dumps(self.outcome)
        for secret in ("s3cret-psk", "mpsk-s3cret", "deadbeef00", "iot-s3cret"):
            self.assertNotIn(secret, blob)
        raw_blob = json.dumps(self.outcome["raw"])
        self.assertIn('"psk-type": "ascii"', raw_blob)
        self.assertIn('"auth-key-mgmt-psk": true', raw_blob)
        self.assertIn('"wep-key-size": 40', raw_blob)
        self.assertIn("***scrubbed***", raw_blob)


class TestTagConfig(unittest.TestCase):
    def setUp(self):
        self.outcome = wlc._collect_tag_config(
            _Ctx(
                _controller(
                    **{
                        "site-tag-config": J("wlc_site_tag_configs.json"),
                        "rf-tags/rf-tag": J("wlc_rf_tags.json"),
                        "flex-policy-entry": J("wlc_flex_policy_entries.json"),
                        "ap-tags/ap-tag": J("wlc_ap_tags.json"),
                    }
                )
            )
        )

    def test_site_rf_flex_and_static_ap_tags(self):
        normalized = self.outcome["normalized"]
        self.assertEqual(
            normalized["site-tag|ST-HQ-3F"],
            {
                "flex_profile": "FLEX-HQ",
                "ap_join_profile": "AP-JOIN-HQ",
                "local_site": True,
                "description": "HQ 3rd floor",
            },
        )
        rf = normalized["rf-tag|RF-HQ"]
        self.assertEqual(
            (rf["rf_profile_24ghz"], rf["rf_profile_5ghz"], rf["rf_profile_6ghz"]),
            ("HQ-24G", "HQ-5G", "HQ-6G"),
        )
        flex = normalized["flex|FLEX-HQ"]
        self.assertEqual(flex["native_vlan"], 1)
        self.assertIs(flex["vlan_support"], True)
        self.assertIs(flex["local_roaming"], False)
        self.assertEqual(flex["radius_group"], "ISE-GROUP")
        self.assertEqual(flex["vlan_map"], {"CORP-USERS": 120, "GUEST-VLAN": 130})
        joined = normalized["ap-tag|00:11:22:33:44:01"]
        self.assertEqual(joined["ap_name"], "AP-3F-EAST-01")
        self.assertEqual(joined["policy_tag"], "PT-HQ")
        self.assertNotIn("ap_name", normalized["ap-tag|00:11:22:33:44:31"])
        context = self.outcome["context"]
        self.assertEqual(context["static_ap_tags"], 2)
        self.assertEqual(context["static_ap_tags_joined"], 1)

    def test_local_auth_password_is_scrubbed(self):
        blob = json.dumps(self.outcome)
        self.assertNotIn("hunter2", blob)
        self.assertIn("svc-flex", json.dumps(self.outcome["raw"]))


class TestMobility(unittest.TestCase):
    def _payloads(self, **extra):
        payloads = {
            "mm-global-data": J("wlc_mm_global_data.json"),
            "mobility-config": J("wlc_mobility_config.json"),
            "mobility-node-data": J("wlc_mobility_node_data.json"),
            "ap-peer-list": J("wlc_ap_peer_list.json"),
        }
        payloads.update(extra)
        return _controller(**payloads)

    def test_self_and_peers(self):
        outcome = wlc._collect_mobility(_Ctx(self._payloads()))
        normalized = outcome["normalized"]
        self.assertEqual(
            normalized["self"], {"mobility_mac": "00:1e:14:aa:bb:cc", "group": "HQ-MOBILITY"}
        )
        up = normalized["peer|10.99.0.2"]
        self.assertEqual(up["group"], "HQ-MOBILITY")
        self.assertEqual(up["status"], "up")
        self.assertIs(up["control_link"], True)
        self.assertIs(up["data_peer"], True)
        self.assertEqual((up["control_flaps"], up["data_flaps"]), (0, 1))
        self.assertIs(up["tunnel_plumbed"], True)
        self.assertEqual(up["clients"], 12)
        self.assertEqual(up["ap_count"], 40)
        self.assertNotIn("nat_ip", up)
        down = normalized["peer|10.99.0.3"]
        self.assertEqual(down["status"], "ctrl-data-path-down")
        self.assertIs(down["control_link"], False)
        self.assertEqual(down["control_flaps"], 4)
        self.assertEqual(down["nat_ip"], "203.0.113.9")
        self.assertNotIn("ap_count", down)
        self.assertEqual(
            outcome["context"],
            {"peers_total": 2, "peers_up": 1, "peer_groups": ["DR-MOBILITY", "HQ-MOBILITY"]},
        )

    def test_missing_config_model_is_a_note_not_a_failure(self):
        payloads = self._payloads()
        del payloads["mobility-config"]
        outcome = wlc._collect_mobility(_Ctx(payloads))
        self.assertNotIn("group", outcome["normalized"]["self"])
        self.assertIn("mobility-config not served", outcome["raw"]["note"])

    def test_no_peers_is_a_real_answer(self):
        outcome = wlc._collect_mobility(_Ctx(self._payloads(**{"mobility-node-data": {}})))
        self.assertEqual(set(outcome["normalized"]), {"self"})
        self.assertEqual(outcome["context"]["peers_total"], 0)


class TestPlatform(unittest.TestCase):
    def _payloads(self, **extra):
        payloads = {
            "mgmt-intf-data": J("wlc_mgmt_intf_data.json"),
            "emltd-join-count-stat": J("wlc_joined_aps_count.json"),
            "stack-oper-data": J("wlc_stack_oper.json"),
        }
        payloads.update(extra)
        return _controller(**payloads)

    def test_parse_show_redundancy_standalone(self):
        parsed = wlc._parse_show_redundancy(T("wlc_show_redundancy_standalone.txt"))
        self.assertEqual(parsed["hardware_mode"], "Simplex")
        self.assertEqual(parsed["configured_mode"], "Non-redundant")
        self.assertEqual(parsed["operating_mode"], "Non-redundant")
        self.assertEqual(parsed["switchovers"], 0)
        self.assertEqual(parsed["last_switchover_reason"], "none")
        self.assertEqual(parsed["active_state"], "ACTIVE")
        self.assertEqual(parsed["peer_state"], "not available (DISABLED)")

    def test_parse_show_redundancy_sso_pair(self):
        parsed = wlc._parse_show_redundancy(T("wlc_show_redundancy_sso.txt"))
        self.assertEqual(parsed["hardware_mode"], "Duplex")
        self.assertEqual(parsed["operating_mode"], "sso")
        self.assertEqual(parsed["communications"], "Up")
        self.assertEqual(parsed["switchovers"], 1)
        self.assertEqual(parsed["last_switchover_reason"], "user forced")
        self.assertEqual(parsed["active_state"], "ACTIVE")
        self.assertEqual(parsed["peer_state"], "STANDBY HOT")
        self.assertEqual(wlc._parse_show_redundancy(""), {})

    def test_collector_with_ssh(self):
        ctx = _Ctx(
            self._payloads(), ssh={"show redundancy": T("wlc_show_redundancy_standalone.txt")}
        )
        outcome = wlc._collect_platform(ctx)
        normalized = outcome["normalized"]
        self.assertEqual(normalized["controller"]["model"], "C9800-CL-K9")
        self.assertEqual(normalized["controller"]["identified_by"], "chassis model")
        self.assertEqual(
            normalized["mgmt-intf"],
            {
                "name": "Vlan10",
                "type": "intf-type-vlan",
                "ip": "10.10.10.5",
                "netmask": "255.255.255.0",
                "mac": "00:1e:14:aa:bb:cc",
            },
        )
        self.assertEqual(normalized["joined-aps"], {"count": 3})
        chassis = normalized["chassis|1"]
        self.assertEqual((chassis["role"], chassis["state"]), ("active", "ready"))
        self.assertEqual(chassis["serial"], "9ABCDEF0123")
        self.assertIs(chassis["sso_ready"], False)
        self.assertEqual(normalized["redundancy"]["hardware_mode"], "Simplex")
        self.assertEqual(outcome["context"]["chassis_total"], 1)
        self.assertEqual(outcome["context"]["chassis_active"], 1)
        self.assertEqual(ctx.ssh_calls, ["show redundancy"])
        self.assertNotIn("note", outcome["raw"])

    def test_collector_without_ssh_or_with_a_rejected_command(self):
        outcome = wlc._collect_platform(_Ctx(self._payloads()))
        self.assertNotIn("redundancy", outcome["normalized"])
        self.assertIn("no SSH transport", outcome["raw"]["note"])
        rejected = _Ctx(
            self._payloads(), ssh={"show redundancy": "% Invalid input detected at '^' marker."}
        )
        outcome = wlc._collect_platform(rejected)
        self.assertNotIn("redundancy", outcome["normalized"])
        self.assertIn("rejected", outcome["raw"]["note"])
        unparsed = _Ctx(self._payloads(), ssh={"show redundancy": "some new format"})
        outcome = wlc._collect_platform(unparsed)
        self.assertIn("nothing parsed", outcome["raw"]["note"])

    def test_missing_optional_models_are_notes(self):
        payloads = self._payloads()
        del payloads["stack-oper-data"]
        del payloads["emltd-join-count-stat"]
        outcome = wlc._collect_platform(_Ctx(payloads))
        self.assertFalse(any(key.startswith("chassis|") for key in outcome["normalized"]))
        self.assertNotIn("joined-aps", outcome["normalized"])
        self.assertIn("stack-oper-data not served", outcome["raw"]["note"])
        self.assertIn("emltd-join-count-stat not served", outcome["raw"]["note"])

    def test_missing_management_interface_is_a_failed_read(self):
        payloads = self._payloads()
        del payloads["mgmt-intf-data"]
        with self.assertRaises(registry.CollectError):
            wlc._collect_platform(_Ctx(payloads))


class TestAaaServers(unittest.TestCase):
    def test_states_and_context(self):
        ctx = _Ctx({"aaa-radius-stats": J("iosxe_aaa_radius_stats.json")})
        outcome = wlc._collect_aaa_servers(ctx)
        normalized = outcome["normalized"]
        self.assertEqual(
            normalized["radius|ISE-GROUP|10.50.0.11:1812"],
            {
                "state": "alive",
                "instances": 2,
                "instances_alive": 2,
                "acct_port": 1813,
                "radsec": False,
            },
        )
        self.assertEqual(normalized["radius|ISE-GROUP|10.50.0.12:1812"]["state"], "mixed")
        self.assertEqual(normalized["radius|ISE-GROUP|10.50.0.12:1812"]["instances_alive"], 1)
        self.assertEqual(
            outcome["context"],
            {
                "servers_total": 2,
                "servers_not_alive": 1,
                "authen_accepts": 1500,
                "authen_rejects": 17,
                "authen_timeouts": 40,
            },
        )
        # Not gated on the controller: no hardware read, no probe.
        self.assertEqual(len(ctx.resources()), 1)

    def test_absent_model_and_no_servers_are_not_present(self):
        with self.assertRaises(registry.SkipCheck):
            wlc._collect_aaa_servers(_Ctx({}))
        with self.assertRaises(registry.SkipCheck):
            wlc._collect_aaa_servers(_Ctx({"aaa-radius-stats": {}}))

    def test_fields_rejection_falls_back(self):
        ctx = _Ctx({"aaa-radius-stats": _reject_fields("iosxe_aaa_radius_stats.json")})
        outcome = wlc._collect_aaa_servers(ctx)
        self.assertEqual(len(outcome["normalized"]), 2)
        self.assertIn("fields filter rejected", outcome["raw"]["note"])

    def test_normalize_handles_servers_without_detail(self):
        normalized = wlc._normalize_aaa_servers(
            [
                {
                    "group-name": "G",
                    "radius-server-ip": "10.0.0.1",
                    "auth-port": 1812,
                    "acct-port": 1813,
                }
            ]
        )
        self.assertEqual(normalized, {"radius|G|10.0.0.1:1812": {"acct_port": 1813}})


class TestRegistrations(unittest.TestCase):
    def test_this_module_owns_exactly_its_catalog(self):
        owned = {
            check_id
            for check_id, check in registry.CHECKS.items()
            if check.collector.__module__ == wlc.__name__
        }
        self.assertEqual(owned, EXPECTED_IDS)
        for check_id in EXPECTED_IDS:
            check = registry.CHECKS[check_id]
            self.assertEqual(check.platform, "iosxe", check_id)
            self.assertIn(check.tier, (1, 2, 3), check_id)
            self.assertIn(
                check.compare.get("mode", "equality_set"), _loader.diffcore.MODES, check_id
            )
            self.assertTrue(callable(check.collector), check_id)
            self.assertTrue(check.miss_meaning, check_id)
        self.assertEqual(
            {c.id for c in registry.checks_for("iosxe") if c.id in EXPECTED_IDS}, EXPECTED_IDS
        )

    def test_wireless_checks_are_tagged_and_the_generic_one_is_not(self):
        for check_id in EXPECTED_IDS:
            tags = registry.CHECKS[check_id].tags
            if check_id.startswith("wlc_"):
                self.assertIn("wireless", tags, check_id)
            else:
                self.assertNotIn("wireless", tags, check_id)

    def test_semantics_merged_into_the_registry(self):
        for check_id in EXPECTED_IDS:
            self.assertIn(check_id, registry.SEMANTICS, check_id)
            self.assertGreater(len(registry.SEMANTICS[check_id]), 40, check_id)
            self.assertEqual(registry.SEMANTICS[check_id], wlc.SEMANTICS[check_id])

    def test_key_models_for_the_shakedown(self):
        self.assertTrue(wlc.KEY_MODELS)
        for model in wlc.KEY_MODELS:
            self.assertTrue(model.startswith("Cisco-IOS-XE-"), model)
        self.assertIn("Cisco-IOS-XE-wireless-access-point-oper", wlc.KEY_MODELS)

    def test_capability_mode_config_for_the_client_summary(self):
        compare = registry.CHECKS["wlc_clients_summary"].compare
        self.assertEqual(compare["mode"], "capability")
        self.assertGreaterEqual(compare["floor_pre"], 1)
        self.assertGreaterEqual(compare["min_post"], 1)


if __name__ == "__main__":
    unittest.main()
