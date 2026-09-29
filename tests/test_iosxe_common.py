"""jobs/iosxe_common: the helpers every IOS-XE checks module shares.

Pure, fixture-driven, no network. Locks in (1) the filtered-GET helper's
contract — the exact kwargs it sends, so a read moved behind it keeps its
per-run cache key; the one retry on HTTP 400 and its note — (2) the
interface-name and MAC helpers, (3) the ``show inventory`` parsers on the
committed fixtures, and (4) that every historical private name in the four
checks modules is still bound, to the very object iosxe_common defines.
"""

import unittest

if __package__:
    from . import _loader
else:  # unittest discover -s tests imports test modules as top-level
    import _loader

common = _loader.load("iosxe_common")
checks = _loader.checks_iosxe
l2 = _loader.load("checks_iosxe_layer2")
poe = _loader.load("checks_iosxe_poe")
wlc = _loader.load("checks_iosxe_wireless")
constants = _loader.constants
registry = _loader.registry
J = _loader.fixture_json
T = _loader.fixture_text


class _Http(Exception):
    def __init__(self, status):
        super().__init__("HTTP %s" % (status,))
        self.status_code = status


class _Ctx:
    """Duck-typed CollectorContext.get: records (path, kwargs), answers by exact path.

    A payload may be an exception instance, which is raised instead.
    """

    def __init__(self, payloads):
        self.payloads = payloads
        self.gets = []

    def get(self, path, **kwargs):
        self.gets.append((path, dict(kwargs)))
        answer = self.payloads.get(path)
        if isinstance(answer, Exception):
            raise answer
        return answer


class TestPayloadHelpers(unittest.TestCase):
    def test_aslist(self):
        self.assertEqual(common.aslist(None), [])
        self.assertEqual(common.aslist({"a": 1}), [{"a": 1}])
        self.assertEqual(common.aslist([1, 2]), [1, 2])

    def test_container_is_strict_with_bare_fallback(self):
        self.assertEqual(common.container({"m:c": 1}, "m:c"), 1)
        self.assertEqual(common.container({"c": 2}, "m:c"), 2)
        self.assertIsNone(common.container({"other:c": 3}, "m:c"))
        self.assertIsNone(common.container("junk", "m:c"))

    def test_node_and_entries_accept_both_read_shapes(self):
        as_list = {"mod:item": [{"k": 1}, "junk"]}
        as_container = {"mod:top": {"item": {"k": 1}}}
        self.assertEqual(common.node(as_list, "item"), [{"k": 1}, "junk"])
        self.assertEqual(common.entries(as_list, "item"), [{"k": 1}])
        self.assertEqual(common.entries(as_container, "item"), [{"k": 1}])
        self.assertEqual(common.entries(None, "item"), [])

    def test_sub_and_leaf(self):
        payload = {"a": {"b": {"c": 5}}}
        self.assertEqual(common.sub(payload, "a", "b"), {"c": 5})
        self.assertEqual(common.sub(payload, "a", "x"), {})
        self.assertEqual(common.leaf(payload, "a", "b", "c"), 5)
        self.assertIsNone(common.leaf(payload, "a", "x", "c"))

    def test_scalars(self):
        self.assertEqual(common.to_int("7"), 7)
        self.assertIsNone(common.to_int("seven"))
        self.assertEqual(common.to_float("13.20"), 13.2)
        self.assertIsNone(common.to_float(None))
        self.assertIs(common.yes("TRUE"), True)
        self.assertIs(common.yes("no"), False)
        self.assertIsNone(common.yes(None))
        self.assertEqual(common.short("stp-mode-rapid-pvst", "stp-mode-"), "rapid-pvst")
        self.assertIsNone(common.short(None, "x"))
        self.assertEqual(common.strip_module("ietf-routing:static"), "static")
        self.assertIsNone(common.text_or_none("  "))
        self.assertEqual(common.text_or_none(" x "), "x")
        self.assertEqual(common.compact({"a": None, "b": 0}), {"b": 0})


class TestMac(unittest.TestCase):
    def test_mac_preserves_shape(self):
        self.assertEqual(common.mac(" AABB.CCDD.EEFF "), "aabb.ccdd.eeff")
        self.assertIsNone(common.mac(""))
        self.assertIsNone(common.mac(None))

    def test_mac_canonical(self):
        want = "aa:bb:cc:dd:ee:ff"
        for spelling in (
            "aabb.ccdd.eeff",
            "AA:BB:CC:DD:EE:FF",
            "aa-bb-cc-dd-ee-ff",
            "AABBCCDDEEFF",
        ):
            self.assertEqual(common.mac_canonical(spelling), want, spelling)
        self.assertEqual(common.mac_canonical("not a mac"), "not a mac")
        self.assertIsNone(common.mac_canonical(None))


class TestInterfaceNames(unittest.TestCase):
    def test_round_trip_every_prefix(self):
        for long_, short_ in common.IFNAME_PREFIXES:
            self.assertEqual(common.short_ifname(long_ + "1/0/1"), short_ + "1/0/1")
            self.assertEqual(common.long_ifname(short_ + "1/0/1"), long_ + "1/0/1")
            self.assertEqual(common.long_ifname(long_ + "1/0/1"), long_ + "1/0/1")
            self.assertEqual(common.short_ifname(short_ + "1/0/1"), short_ + "1/0/1")

    def test_ambiguous_short_prefixes(self):
        self.assertEqual(common.long_ifname("Twe1/0/1"), "TwentyFiveGigE1/0/1")
        self.assertEqual(common.long_ifname("Tw1/0/1"), "TwoGigabitEthernet1/0/1")
        self.assertEqual(common.long_ifname("Fo1/1/1"), "FortyGigabitEthernet1/1/1")
        self.assertEqual(common.long_ifname("Fa0/1"), "FastEthernet0/1")

    def test_case_and_pass_through(self):
        self.assertEqual(common.long_ifname("gi1/0/1"), "GigabitEthernet1/0/1")
        self.assertEqual(common.short_ifname("gigabitethernet1/0/1.100"), "Gi1/0/1.100")
        self.assertEqual(common.long_ifname("CPU"), "CPU")
        self.assertEqual(common.short_ifname("Powerstack-1"), "Powerstack-1")
        self.assertEqual(common.long_ifname("Xx1/0/1"), "Xx1/0/1")
        self.assertIsNone(common.long_ifname(None))
        self.assertEqual(common.short_ifname(""), "")

    def test_member_of(self):
        self.assertEqual(common.member_of("GigabitEthernet1/0/1"), 1)
        self.assertEqual(common.member_of("Te3/1/4"), 3)
        self.assertEqual(common.member_of("TwoGigabitEthernet2/0/48"), 2)
        self.assertIsNone(common.member_of("Port-channel1"))
        self.assertIsNone(common.member_of("Vlan2"))
        self.assertIsNone(common.member_of("CPU"))
        self.assertIsNone(common.member_of(None))


class TestCliRejected(unittest.TestCase):
    def test_refusals(self):
        for text in ("% Invalid input detected", "Command authorization failed", "Access denied"):
            self.assertTrue(common.cli_rejected(text), text)
        self.assertFalse(common.cli_rejected("Port  Mode  Encapsulation"))
        self.assertFalse(common.cli_rejected(None))


class TestGetFiltered(unittest.TestCase):
    PATH = "/data/mod:top/list"

    def test_accepted_filter_sends_only_what_was_asked(self):
        ctx = _Ctx({self.PATH + "?fields=a;b": {"mod:list": []}})
        read = common.get_filtered(ctx, self.PATH, "a;b")
        self.assertEqual(ctx.gets, [(self.PATH + "?fields=a;b", {})])
        self.assertEqual(read.payload, {"mod:list": []})
        self.assertEqual(read.path, self.PATH + "?fields=a;b")
        self.assertTrue(read.filtered)
        self.assertIsNone(read.note)
        self.assertEqual(read.fields_filter, common.FILTER_ACCEPTED)

    def test_kwargs_reach_ctx_only_when_asked(self):
        ctx = _Ctx({self.PATH + "?fields=a": None})
        common.get_filtered(ctx, self.PATH, "a", ok_404=True, timeout=42)
        self.assertEqual(ctx.gets, [(self.PATH + "?fields=a", {"ok_404": True, "timeout": 42})])

    def test_400_retries_unfiltered_once_with_the_big_timeout(self):
        ctx = _Ctx({self.PATH + "?fields=a": _Http(400), self.PATH: {"mod:list": [1]}})
        notes = []
        read = common.get_filtered(ctx, self.PATH, "a", ok_404=True, notes=notes)
        self.assertEqual(
            ctx.gets,
            [
                (self.PATH + "?fields=a", {"ok_404": True}),
                (self.PATH, {"ok_404": True, "timeout": constants.BIG_GET_TIMEOUT}),
            ],
        )
        self.assertEqual(read.payload, {"mod:list": [1]})
        self.assertEqual(read.path, self.PATH)
        self.assertFalse(read.filtered)
        self.assertEqual(read.note, "list: fields filter rejected (HTTP 400); unfiltered read used")
        self.assertEqual(notes, [read.note])
        self.assertEqual(read.fields_filter, common.FILTER_REJECTED)

    def test_label_and_retry_timeout_none(self):
        ctx = _Ctx({self.PATH + "?fields=a": _Http(400), self.PATH: {}})
        read = common.get_filtered(ctx, self.PATH, "a", label="x", timeout=5, retry_timeout=None)
        self.assertEqual(ctx.gets[1], (self.PATH, {}))
        self.assertTrue(read.note.startswith("x: "))

    def test_other_errors_and_a_second_400_propagate(self):
        ctx = _Ctx({self.PATH + "?fields=a": _Http(500)})
        with self.assertRaises(_Http):
            common.get_filtered(ctx, self.PATH, "a")
        ctx = _Ctx({self.PATH + "?fields=a": _Http(400), self.PATH: _Http(400)})
        with self.assertRaises(_Http):
            common.get_filtered(ctx, self.PATH, "a")
        self.assertEqual(len(ctx.gets), 2)

    def test_no_fields_is_a_plain_get(self):
        ctx = _Ctx({self.PATH: {"k": 1}})
        read = common.get_filtered(ctx, self.PATH, None, ok_404=True)
        self.assertEqual(ctx.gets, [(self.PATH, {"ok_404": True})])
        self.assertEqual((read.path, read.filtered, read.note), (self.PATH, True, None))


class TestFetchInterfaces(unittest.TestCase):
    def test_reads_the_widened_path_and_returns_a_filtered_get(self):
        payload = J("iosxe_interfaces_oper.json")
        ctx = _Ctx({common.IFACE_PATH: payload})
        read = common.fetch_interfaces(ctx)
        self.assertEqual(ctx.gets, [(common.IFACE_PATH, {})])
        self.assertIs(read.payload, payload)
        self.assertTrue(read.filtered)

    def test_retry_and_missing_container(self):
        payload = J("iosxe_interfaces_oper.json")
        ctx = _Ctx({common.IFACE_PATH: _Http(400), common.IFACE_BASE_PATH: payload})
        read = common.fetch_interfaces(ctx)
        self.assertEqual(
            ctx.gets[1], (common.IFACE_BASE_PATH, {"timeout": constants.BIG_GET_TIMEOUT})
        )
        self.assertEqual(
            read.note, "interfaces: fields filter rejected (HTTP 400); unfiltered read used"
        )
        with self.assertRaises(registry.CollectError):
            common.fetch_interfaces(_Ctx({common.IFACE_PATH: {"unexpected": {}}}))


class TestInventory(unittest.TestCase):
    def test_parse_show_inventory_member_chassis(self):
        members = common.parse_show_inventory(T("iosxe_show_inventory_9300_stack.txt"))
        self.assertEqual(members["1"], {"model": "C9300-48UXM", "serial": "FOC0000A001"})
        self.assertEqual(members["2"], {"model": "C9300-48UXM", "serial": "FOC0000A002"})
        items = common.inventory_items(T("iosxe_show_inventory_9300_stack.txt"))
        self.assertEqual(items[0]["name"], "c93xx Stack")
        self.assertEqual(
            items[5],
            {
                "name": "Te1/1/1",
                "descr": "SFP-10GBase-SR",
                "pid": "SFP-10G-SR",
                "vid": "V03",
                "sn": "AGD0000C001",
            },
        )
        self.assertEqual(common.parse_show_inventory("% Invalid input"), {})

    def test_device_inventory(self):
        rows = common.device_inventory(J("iosxe_device_hardware.json"))
        self.assertEqual(len(rows), 9)
        self.assertEqual(rows[0]["hw-type"], "hw-type-chassis")
        self.assertEqual(common.device_inventory({"junk": 1}), [])
        self.assertEqual(common.device_inventory(None), [])


class TestHistoricalNamesStayBound(unittest.TestCase):
    """Every private name a checks module used to define is still importable from it,
    bound to the object iosxe_common defines (tests, shakedown_job and older callers
    keep working); the wrappers keep their historical return shapes."""

    ALIASES = {
        checks: {
            "_aslist": "aslist",
            "_container": "container",
            "_to_int": "to_int",
            "_strip_module": "strip_module",
            "_text_or_none": "text_or_none",
            "_HW_PATH": "HW_PATH",
            "_VLAN_PATH": "VLAN_PATH",
            "_STACK_OPER_PATH": "STACK_OPER_PATH",
            "_IFACE_BASE_PATH": "IFACE_BASE_PATH",
            "_IFACE_FIELDS": "IFACE_FIELDS",
            "_IFACE_PATH": "IFACE_PATH",
            "_inventory_entries": "device_inventory",
            "_inventory_items": "inventory_items",
            "_parse_show_inventory": "parse_show_inventory",
            "_INVENTORY_MEMBER_NAME": "INVENTORY_MEMBER_NAME",
            "_INVENTORY_NAME_LINE": "INVENTORY_NAME_LINE",
            "_INVENTORY_PID_LINE": "INVENTORY_PID_LINE",
            "_INVENTORY_DESCR": "INVENTORY_DESCR",
        },
        l2: {
            "_aslist": "aslist",
            "_node": "node",
            "_entries": "entries",
            "_to_int": "to_int",
            "_short": "short",
            "_mac": "mac",
            "_compact": "compact",
            "_member_of": "member_of",
            "_cli_rejected": "cli_rejected",
            "_CLI_REFUSAL": "CLI_REFUSAL",
            "_MEMBER_PORT": "MEMBER_PORT",
            "_VLAN_PATH": "VLAN_PATH",
        },
        poe: {
            "_aslist": "aslist",
            "_to_int": "to_int",
            "_to_float": "to_float",
            "_short": "short",
            "_compact": "compact",
        },
        wlc: {
            "_aslist": "aslist",
            "_node": "node",
            "_entries": "entries",
            "_sub": "sub",
            "_leaf": "leaf",
            "_to_int": "to_int",
            "_yes": "yes",
            "_short": "short",
            "_mac": "mac",
            "_compact": "compact",
            "_HW_PATH": "HW_PATH",
            "_STACK_OPER_PATH": "STACK_OPER_PATH",
        },
    }

    def test_every_alias_is_the_common_object(self):
        for module, names in self.ALIASES.items():
            for old, new in names.items():
                self.assertIs(
                    getattr(module, old), getattr(common, new), "%s.%s" % (module.__name__, old)
                )

    def test_shared_paths_are_spelled_once(self):
        self.assertEqual(checks._HW_PATH, wlc._HW_PATH)
        self.assertEqual(checks._STACK_OPER_PATH, wlc._STACK_OPER_PATH)
        self.assertEqual(checks._VLAN_PATH, l2._VLAN_PATH)
        self.assertEqual(poe._POE_PATH, "%s?fields=%s" % (poe._POE_OPER, poe._POE_FIELDS))

    def test_wrappers_keep_their_historical_shapes(self):
        payload = J("iosxe_interfaces_oper.json")
        self.assertEqual(
            checks._fetch_interfaces(_Ctx({common.IFACE_PATH: payload})), (payload, [])
        )
        ctx = _Ctx({common.IFACE_PATH: _Http(400), common.IFACE_BASE_PATH: payload})
        self.assertEqual(
            checks._fetch_interfaces(ctx),
            (payload, ["interfaces: fields filter rejected (HTTP 400); unfiltered read used"]),
        )
        notes = []
        ctx = _Ctx({"/p?fields=f": {"mod:x": []}})
        self.assertEqual(
            l2._get_filtered(ctx, "/p", "f", notes, "x"), ({"mod:x": []}, "/p?fields=f")
        )
        self.assertEqual(ctx.gets, [("/p?fields=f", {"ok_404": True})])
        self.assertEqual(notes, [])

    def test_common_is_not_a_catalog(self):
        self.assertFalse(common.__name__.rsplit(".", 1)[-1].startswith("checks_"))
        self.assertFalse(
            [c for c in registry.CHECKS.values() if c.collector.__module__ == common.__name__]
        )
        self.assertFalse(hasattr(common, "SEMANTICS"))
        self.assertFalse(hasattr(common, "KEY_MODELS"))


if __name__ == "__main__":
    unittest.main()
