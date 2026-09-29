"""checks_iosxe_poe: enum vocabularies, the normalizers, context, and the collector.

Driven by tests/fixtures/iosxe_poe_oper.json, hand-built from the published
17.12.1 Cisco-IOS-XE-poe-oper.yang: a two-member stack whose port table is
served in BOTH list shapes (poe-port-detail and poe-port, each in its own
enum vocabulary), a StackPower ring with three supplies, sanitized neighbor
MACs. The shakedown harvest replaces it with a sanitized real capture. No
Nautobot, no network.
"""

import copy
import json
import unittest

if __package__:
    from . import _loader
else:  # unittest discover -s tests imports test modules as top-level
    import _loader

poe = _loader.load("checks_iosxe_poe")
registry = _loader.registry
diffcore = _loader.diffcore
J = _loader.fixture_json

FIXTURE = "iosxe_poe_oper.json"
CONTAINER = "Cisco-IOS-XE-poe-oper:poe-oper-data"

EXPECTED_IDS = {"iosxe_poe"}


class _Http(Exception):
    """Stand-in for RestconfError: carries the HTTP status the collector inspects."""

    def __init__(self, status):
        super().__init__("HTTP %s" % (status,))
        self.status_code = status


class _Ctx:
    """Duck-typed CollectorContext.

    GET paths route to payloads by the LONGEST token found in the resource
    path (the part before any ?fields=). A payload may be an exception
    (raised) or a callable (called with the full path).
    """

    def __init__(self, payloads):
        self.payloads = payloads
        self.calls = []
        self.kwargs = []
        self.platform = "iosxe"
        self.device_name = "poe-test"

    def get(self, path, **kwargs):
        self.calls.append(path)
        self.kwargs.append(kwargs)
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


def _reject_fields(payload):
    """A payload callable: HTTP 400 for the filtered path, ``payload`` unfiltered."""

    def answer(path):
        if "?fields=" in path:
            raise _Http(400)
        return payload

    return answer


def _plain_only():
    """The fixture with poe-port-detail removed: a release that fills poe-port only."""
    payload = copy.deepcopy(J(FIXTURE))
    del payload[CONTAINER]["poe-port-detail"]
    return payload


def _stack_only():
    """A non-PoE member's view: StackPower rows, no port lists at all."""
    payload = copy.deepcopy(J(FIXTURE))
    for name in ("poe-port-detail", "poe-port", "poe-module"):
        del payload[CONTAINER][name]
    return payload


class TestEnumVocabularies(unittest.TestCase):
    def test_oper_state_from_both_lists_reduces_to_one_vocabulary(self):
        # poe-port: ilpower-pd-power-state
        for raw, word in (
            ("pd-power-on", "on"),
            ("pd-power-off", "off"),
            ("pd-power-faulty", "faulty"),
            ("pd-power-deny", "deny"),
            ("pd-power-overdrawn", "overdrawn"),
        ):
            self.assertEqual(poe._oper_state(raw), word, raw)
        # poe-port-detail: poe-pd-power-state
        for raw, word in (
            ("on", "on"),
            ("off", "off"),
            ("faulty", "faulty"),
            ("power-deny", "deny"),
            ("error-disable", "error-disable"),
        ):
            self.assertEqual(poe._oper_state(raw), word, raw)
        self.assertIsNone(poe._oper_state(None))
        self.assertEqual(poe._oper_state("something-new"), "something-new")

    def test_pd_class_from_both_lists(self):
        self.assertEqual(poe._pd_class("poe-ieee4"), "ieee4")
        self.assertEqual(poe._pd_class("pd-ieee4"), "ieee4")
        self.assertEqual(poe._pd_class("pd-ieee8"), "ieee8")
        self.assertEqual(poe._pd_class("poe-cisco"), "cisco")
        self.assertEqual(poe._pd_class("pd-mismatch"), "mismatch")
        self.assertEqual(poe._pd_class("poe-ieee-unknown-class"), "ieee-unknown-class")
        self.assertEqual(poe._pd_class("pd-unknown"), "unknown")
        # 'not available' is unmeasured, from either list
        self.assertIsNone(poe._pd_class("pd-null"))
        self.assertIsNone(poe._pd_class("poe-null"))
        self.assertIsNone(poe._pd_class(None))

    def test_admin_and_stack_enums(self):
        self.assertEqual(poe._admin_state("admin-state-auto"), "auto")
        self.assertEqual(poe._admin_state("admin-state-static"), "static")
        self.assertEqual(poe._admin_state("admin-state-off"), "off")
        self.assertIsNone(poe._admin_state("admin-state-null"))
        self.assertEqual(poe._stack_mode("stack-mode-sharing-strict"), "sharing-strict")
        self.assertEqual(poe._stack_mode("stack-mode-rps"), "rps")
        self.assertIsNone(poe._stack_mode("stack-mode-null"))
        for topo in ("ring", "star", "standalone", "none"):
            self.assertEqual(poe._stack_topology("stack-topo-" + topo), topo)
        for status in ("connected", "not-connected", "shut", "unknown"):
            self.assertEqual(poe._stack_port_status("stack-port-status-" + status), status)

    def test_container_lookup_tolerates_every_wrapper(self):
        payload = J(FIXTURE)
        inner = payload[CONTAINER]
        self.assertIs(poe._poe_container(payload), inner)
        self.assertEqual(poe._poe_container({"poe-oper-data": inner}), inner)
        self.assertEqual(poe._poe_container(inner), inner)
        self.assertEqual(poe._poe_container({}), {})
        self.assertEqual(poe._poe_container(None), {})
        self.assertEqual(poe._poe_container({"mod:other": {}}), {})


class TestPortSource(unittest.TestCase):
    def test_detail_preferred_when_it_carries_states(self):
        name, entries = poe._port_source(J(FIXTURE)[CONTAINER])
        self.assertEqual(name, "poe-port-detail")
        self.assertEqual(len(entries), 12)

    def test_plain_list_when_detail_is_absent(self):
        name, entries = poe._port_source(_plain_only()[CONTAINER])
        self.assertEqual(name, "poe-port")
        self.assertEqual(len(entries), 12)

    def test_detail_without_states_yields_to_a_plain_list_with_them(self):
        container = copy.deepcopy(J(FIXTURE)[CONTAINER])
        container["poe-port-detail"] = [{"intf-name": "TwoGigabitEthernet1/0/1"}]
        name, _entries = poe._port_source(container)
        self.assertEqual(name, "poe-port")
        # ...but names-only rows still count when nothing carries a state
        container["poe-port"] = [{"intf-name": "TwoGigabitEthernet1/0/1"}]
        name, entries = poe._port_source(container)
        self.assertEqual(name, "poe-port-detail")
        self.assertEqual(len(entries), 1)

    def test_no_lists_at_all(self):
        self.assertEqual(poe._port_source({}), (None, []))
        self.assertEqual(
            poe._port_source({"poe-port": {"intf-name": "Gi1/0/1"}})[1], [{"intf-name": "Gi1/0/1"}]
        )


class TestNormalizeFixture(unittest.TestCase):
    def setUp(self):
        self.normalized = poe._normalize_poe(J(FIXTURE))

    def test_port_keys_cover_every_poe_capable_port(self):
        ports = {k: v for k, v in self.normalized.items() if k.startswith("port|")}
        self.assertEqual(len(ports), 12)
        self.assertEqual(
            ports["port|TwoGigabitEthernet1/0/1"], {"admin": "auto", "oper": "on", "class": "ieee4"}
        )
        # nothing attached: class unmeasured, the key stays
        self.assertEqual(ports["port|TwoGigabitEthernet1/0/3"], {"admin": "auto", "oper": "off"})
        self.assertEqual(
            ports["port|TwoGigabitEthernet1/0/4"],
            {"admin": "auto", "oper": "faulty", "class": "unknown"},
        )
        self.assertEqual(
            ports["port|TwoGigabitEthernet1/0/5"],
            {"admin": "auto", "oper": "deny", "class": "ieee4"},
        )
        self.assertEqual(ports["port|TwoGigabitEthernet1/0/6"], {"admin": "off", "oper": "off"})
        self.assertEqual(
            ports["port|TwoGigabitEthernet2/0/1"], {"admin": "auto", "oper": "on", "class": "ieee6"}
        )
        self.assertEqual(
            ports["port|TwoGigabitEthernet2/0/4"],
            {"admin": "static", "oper": "on", "class": "cisco"},
        )
        self.assertEqual(
            ports["port|TenGigabitEthernet2/0/38"],
            {"admin": "auto", "oper": "error-disable", "class": "ieee4"},
        )

    def test_stack_key_reads_the_misspelled_topology_leaf(self):
        self.assertEqual(
            self.normalized["stack|Powerstack-1"],
            {
                "mode": "sharing",
                "topology": "ring",
                "switches": 2,
                "supplies": 3,
                "total_watts": 3300,
            },
        )

    def test_switch_keys_are_the_stackpower_cable_ports_only(self):
        self.assertEqual(
            self.normalized["switch|1"], {"port_one": "connected", "port_two": "connected"}
        )
        self.assertEqual(
            self.normalized["switch|2"], {"port_one": "connected", "port_two": "connected"}
        )
        # neighbor MACs, budgets and wattages never reach normalized
        for value in self.normalized.values():
            self.assertFalse(set(value) & {"budget", "allocated", "ps_a", "neighbor"}, value)

    def test_no_volatile_values_and_stable_types(self):
        self.assertEqual(
            set(self.normalized),
            {k for k in self.normalized if k.split("|")[0] in ("port", "stack", "switch")},
        )
        for key, facts in self.normalized.items():
            for facet, value in facts.items():
                self.assertIsInstance(value, (str, int), "%s.%s" % (key, facet))
                self.assertNotIsInstance(value, bool, "%s.%s" % (key, facet))
        json.dumps(self.normalized)

    def test_two_healthy_captures_diff_to_nothing(self):
        again = poe._normalize_poe(copy.deepcopy(J(FIXTURE)))
        self.assertEqual(self.normalized, again)
        diff = diffcore.diff_check(self.normalized, again, {"mode": "equality_set"})
        self.assertEqual(diff["result"], "pass")

    def test_plain_port_shape_normalizes_to_the_same_words(self):
        plain = poe._normalize_poe(_plain_only())
        detail = self.normalized
        self.assertEqual(set(plain), set(detail))
        for key in detail:
            if not key.startswith("port|"):
                self.assertEqual(plain[key], detail[key], key)
                continue
            self.assertEqual(plain[key].get("admin"), detail[key].get("admin"), key)
            if key == "port|TenGigabitEthernet2/0/38":
                # the one state the two vocabularies name differently: the
                # older list says the device overdrew, the richer list says the
                # port was error-disabled for it
                self.assertEqual(plain[key]["oper"], "overdrawn")
                self.assertEqual(detail[key]["oper"], "error-disable")
            else:
                self.assertEqual(plain[key].get("oper"), detail[key].get("oper"), key)
            if key == "port|TwoGigabitEthernet2/0/1":
                # ilpower-pd-class stops at ieee5; a class-6 UPOE device reads
                # ieee-unknown-class there and ieee6 in the richer list
                self.assertEqual(plain[key]["class"], "ieee-unknown-class")
                self.assertEqual(detail[key]["class"], "ieee6")
            else:
                self.assertEqual(plain[key].get("class"), detail[key].get("class"), key)

    def test_rows_without_keys_are_skipped(self):
        self.assertEqual(poe._normalize_ports([{"oper-state": "on"}, "junk"]), {})
        self.assertEqual(poe._normalize_stacks([{"mode": "stack-mode-sharing"}, None]), {})
        self.assertEqual(poe._normalize_switches([{"switch-num": "x"}, 7]), {})
        self.assertEqual(poe._normalize_poe({}), {})


class TestContext(unittest.TestCase):
    def test_context_on_the_fixture(self):
        context = poe._poe_context(J(FIXTURE))
        self.assertEqual(context["port_source"], "poe-port-detail")
        self.assertEqual(context["ports_total"], 12)
        self.assertEqual(
            context["ports_by_oper"],
            {"deny": 1, "error-disable": 1, "faulty": 1, "off": 4, "on": 5},
        )
        self.assertEqual(context["ports_police_overdrawn"], 1)
        self.assertEqual(context["watts_drawn"], 86.0)
        self.assertEqual(context["watts_remaining"], 1628.0)
        self.assertEqual(
            context["module|2"],
            {
                "chassis": 2,
                "available": 857.0,
                "used": 66.5,
                "remaining": 790.5,
                "ports": 48,
                "used_ports": 3,
                "free_ports": 45,
            },
        )
        self.assertEqual(
            context["stack|Powerstack-1"], {"reserved": 0, "allocated": 1714, "unused": 1586}
        )
        self.assertEqual(
            context["switch|2"],
            {
                "power_stack": "Powerstack-1",
                "budget": 1650,
                "allocated": 857,
                "available": 793,
                "consumed_poe": 67,
                "consumed_system": 215,
                "ps_a": 1100,
                "ps_b": 0,
            },
        )

    def test_context_from_the_plain_list_and_from_nothing(self):
        context = poe._poe_context(_plain_only())
        self.assertEqual(context["port_source"], "poe-port")
        self.assertEqual(context["ports_total"], 12)
        self.assertEqual(context["ports_by_oper"]["overdrawn"], 1)
        self.assertEqual(context["watts_drawn"], 86.0)
        empty = poe._poe_context({})
        self.assertEqual(
            empty,
            {
                "port_source": None,
                "ports_total": 0,
                "ports_by_oper": {},
                "ports_police_overdrawn": 0,
                "watts_drawn": None,
                "watts_remaining": None,
            },
        )


class TestCollector(unittest.TestCase):
    def test_filtered_read_raw_keyed_by_the_exact_path(self):
        ctx = _Ctx({"poe-oper-data": J(FIXTURE)})
        outcome = poe._collect_poe(ctx)
        self.assertEqual(ctx.calls, [poe._POE_PATH])
        self.assertIn("?fields=poe-port-detail(", poe._POE_PATH)
        self.assertTrue(ctx.kwargs[0].get("ok_404"))
        self.assertEqual(set(outcome["raw"]), {poe._POE_PATH})
        self.assertIs(outcome["raw"][poe._POE_PATH], ctx.payloads["poe-oper-data"])
        self.assertEqual(len(outcome["normalized"]), 12 + 1 + 2)
        self.assertEqual(outcome["context"]["port_source"], "poe-port-detail")

    def test_404_is_not_present(self):
        with self.assertRaises(registry.SkipCheck) as caught:
            poe._collect_poe(_Ctx({}))
        self.assertIn("not served", str(caught.exception))

    def test_empty_answers_are_not_present(self):
        for payload in ({}, {CONTAINER: {}}, {CONTAINER: {"poe-port": []}}):
            with self.assertRaises(registry.SkipCheck) as caught:
                poe._collect_poe(_Ctx({"poe-oper-data": payload}))
            self.assertIn("non-PoE SKU", str(caught.exception))

    def test_stackpower_without_ports_keeps_the_stack_keys(self):
        ctx = _Ctx({"poe-oper-data": _stack_only()})
        outcome = poe._collect_poe(ctx)
        self.assertEqual(set(outcome["normalized"]), {"stack|Powerstack-1", "switch|1", "switch|2"})
        self.assertEqual(outcome["context"]["ports_total"], 0)
        self.assertIsNone(outcome["context"]["port_source"])
        self.assertIn("no PoE ports reported", outcome["raw"]["note"])

    def test_fields_rejection_retries_unfiltered_once_and_notes_it(self):
        ctx = _Ctx({"poe-oper-data": _reject_fields(J(FIXTURE))})
        outcome = poe._collect_poe(ctx)
        self.assertEqual(ctx.calls, [poe._POE_PATH, poe._POE_OPER])
        self.assertEqual(ctx.kwargs[1].get("timeout"), _loader.constants.BIG_GET_TIMEOUT)
        self.assertIn("fields filter rejected (HTTP 400)", outcome["raw"]["note"])
        self.assertIn(poe._POE_OPER, outcome["raw"])
        self.assertNotIn(poe._POE_PATH, outcome["raw"])
        self.assertEqual(len(outcome["normalized"]), 15)

    def test_unfiltered_404_after_a_400_is_not_present(self):
        ctx = _Ctx({"poe-oper-data": _reject_fields(None)})
        with self.assertRaises(registry.SkipCheck):
            poe._collect_poe(ctx)
        self.assertEqual(len(ctx.calls), 2)

    def test_other_http_errors_propagate(self):
        with self.assertRaises(_Http):
            poe._collect_poe(_Ctx({"poe-oper-data": _Http(500)}))

    def test_raw_port_rows_are_capped_but_normalized_is_complete(self):
        payload = copy.deepcopy(J(FIXTURE))
        rows = payload[CONTAINER]["poe-port-detail"]
        template = rows[0]
        for index in range(poe._RAW_PORT_ROWS_MAX + 5 - len(rows)):
            row = dict(template)
            row["intf-name"] = "GigabitEthernet9/0/%d" % (index + 1,)
            rows.append(row)
        ctx = _Ctx({"poe-oper-data": payload})
        outcome = poe._collect_poe(ctx)
        ports = [k for k in outcome["normalized"] if k.startswith("port|")]
        self.assertEqual(len(ports), poe._RAW_PORT_ROWS_MAX + 5)
        raw_rows = outcome["raw"][poe._POE_PATH][CONTAINER]["poe-port-detail"]
        self.assertEqual(len(raw_rows), poe._RAW_PORT_ROWS_MAX)
        self.assertIn("rows kept in raw", outcome["raw"]["note"])
        # the plain list, under the cap, is untouched
        self.assertEqual(len(outcome["raw"][poe._POE_PATH][CONTAINER]["poe-port"]), 12)
        # and the device's payload was not mutated
        self.assertEqual(len(payload[CONTAINER]["poe-port-detail"]), poe._RAW_PORT_ROWS_MAX + 5)


class TestRegistrations(unittest.TestCase):
    def test_this_module_owns_exactly_its_catalog(self):
        owned = {
            check_id
            for check_id, check in registry.CHECKS.items()
            if check.collector.__module__ == poe.__name__
        }
        self.assertEqual(owned, EXPECTED_IDS)
        for check_id in EXPECTED_IDS:
            check = registry.CHECKS[check_id]
            self.assertEqual(check.platform, "iosxe", check_id)
            self.assertEqual(check.tier, 1, check_id)
            self.assertEqual(check.compare, {"mode": "equality_set"}, check_id)
            self.assertIn(check.compare["mode"], diffcore.MODES, check_id)
            self.assertTrue(callable(check.collector), check_id)
            self.assertTrue(check.miss_meaning, check_id)
            self.assertIn("not-present", check.description, check_id)
        self.assertEqual(
            {c.id for c in registry.checks_for("iosxe") if c.id in EXPECTED_IDS}, EXPECTED_IDS
        )

    def test_semantics_merged_into_the_registry(self):
        for check_id in EXPECTED_IDS:
            self.assertIn(check_id, registry.SEMANTICS, check_id)
            self.assertEqual(registry.SEMANTICS[check_id], poe.SEMANTICS[check_id])
        text = poe.SEMANTICS["iosxe_poe"].lower()
        for phrase in ("power twin", "topology", "port_source", "not-present", "never compared"):
            self.assertIn(phrase, text, phrase)

    def test_key_models_for_the_shakedown(self):
        self.assertEqual(poe.KEY_MODELS, ("Cisco-IOS-XE-poe-oper",))

    def test_fields_filter_names_only_model_leaves(self):
        # Every leaf in the filter exists in the 17.12.1 model's groupings;
        # 'topolgy' is deliberately not filtered (poe-stack comes whole).
        detail_leaves = set(poe._PORT_DETAIL_FIELDS.split(";"))
        plain_leaves = set(poe._PORT_FIELDS.split(";"))
        self.assertIn("intf-name", detail_leaves)
        self.assertIn("intf-name", plain_leaves)
        self.assertNotIn("device-name", detail_leaves)
        self.assertNotIn("module", detail_leaves)  # detail spells it module-id
        self.assertIn("module-id", detail_leaves)
        self.assertNotIn("module-id", plain_leaves)
        self.assertTrue(poe._POE_FIELDS.endswith(";poe-module;poe-stack;poe-switch"))


if __name__ == "__main__":
    unittest.main()
