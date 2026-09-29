"""diffcore: every compare mode and scrub."""

import unittest

if __package__:
    from . import _loader
else:  # unittest discover -s tests imports test modules as top-level
    import _loader

diffcore = _loader.diffcore


class TestEqualitySet(unittest.TestCase):
    def test_pass_when_identical(self):
        view = {"default|10.0.0.0/24": {"protocol": "ospf"}}
        diff = diffcore.diff_check(view, dict(view), {"mode": "equality_set"})
        self.assertEqual(diff["result"], "pass")
        self.assertEqual(diff["added"], [])
        self.assertEqual(diff["removed"], [])
        self.assertEqual(diff["changed"], [])

    def test_added_removed_sorted(self):
        pre = {"b": 1, "z": 2}
        post = {"b": 1, "a": 3, "c": 4}
        diff = diffcore.diff_check(pre, post, {"mode": "equality_set"})
        self.assertEqual(diff["result"], "diffs")
        self.assertEqual(diff["added"], [{"key": "a", "value": 3}, {"key": "c", "value": 4}])
        self.assertEqual(diff["removed"], [{"key": "z", "value": 2}])
        self.assertNotIn("removed_ignored", diff)

    def test_ignore_removed_keeps_evidence_but_never_diffs(self):
        compare = {"mode": "equality_set", "ignore_removed": True}
        diff = diffcore.diff_check({"b": 1, "z": 2}, {"b": 1}, compare)
        self.assertEqual(diff["result"], "pass")
        self.assertEqual(diff["removed"], [])
        self.assertEqual(diff["removed_ignored"], [{"key": "z", "value": 2}])
        diff = diffcore.diff_check({"z": 2}, {"a": 3}, compare)
        self.assertEqual(diff["result"], "diffs")
        self.assertEqual(diff["added"], [{"key": "a", "value": 3}])

    def test_changed_dict_values_per_field(self):
        pre = {"peer1": {"state": "Established", "installed_prefixes": 100}}
        post = {"peer1": {"state": "Idle", "installed_prefixes": 100}}
        diff = diffcore.diff_check(pre, post, {"mode": "equality_set"})
        self.assertEqual(
            diff["changed"],
            [{"key": "peer1", "field": "state", "old": "Established", "new": "Idle"}],
        )
        self.assertEqual(diff["result"], "diffs")

    def test_changed_non_dict_values(self):
        diff = diffcore.diff_check({"k": "a"}, {"k": "b"}, {"mode": "equality_set"})
        self.assertEqual(diff["changed"], [{"key": "k", "field": None, "old": "a", "new": "b"}])

    def test_per_field_tolerance_override_within(self):
        compare = {
            "mode": "equality_set",
            "fields": {"installed_prefixes": {"tolerance": {"abs": 3}}},
        }
        pre = {"peer1": {"state": "Established", "installed_prefixes": 100}}
        post = {"peer1": {"state": "Established", "installed_prefixes": 102}}
        diff = diffcore.diff_check(pre, post, compare)
        self.assertEqual(diff["result"], "pass")
        self.assertEqual(diff["changed"], [])

    def test_per_field_tolerance_override_exceeded(self):
        compare = {
            "mode": "equality_set",
            "fields": {"installed_prefixes": {"tolerance": {"abs": 3}}},
        }
        pre = {"peer1": {"state": "Established", "installed_prefixes": 100}}
        post = {"peer1": {"state": "Established", "installed_prefixes": 104}}
        diff = diffcore.diff_check(pre, post, compare)
        self.assertEqual(diff["result"], "diffs")
        self.assertEqual(
            diff["changed"],
            [{"key": "peer1", "field": "installed_prefixes", "old": 100, "new": 104}],
        )

    def test_tolerance_ignored_for_non_numeric_field(self):
        # A tolerance band on a string field must not swallow the change.
        compare = {"mode": "equality_set", "fields": {"state": {"tolerance": {"abs": 3}}}}
        pre = {"peer1": {"state": "Established"}}
        post = {"peer1": {"state": "Idle"}}
        diff = diffcore.diff_check(pre, post, compare)
        self.assertEqual(diff["result"], "diffs")
        self.assertEqual(len(diff["changed"]), 1)

    def test_field_appearing_in_dict_value(self):
        pre = {"k": {"a": 1}}
        post = {"k": {"a": 1, "b": 2}}
        diff = diffcore.diff_check(pre, post, {"mode": "equality_set"})
        self.assertEqual(diff["changed"], [{"key": "k", "field": "b", "old": None, "new": 2}])

    def test_none_compare_defaults_to_equality_set(self):
        diff = diffcore.diff_check({"a": 1}, {}, None)
        self.assertEqual(diff["removed"], [{"key": "a", "value": 1}])


class TestEqualityScalar(unittest.TestCase):
    def test_pass(self):
        view = {"version": "17.12.4", "model": "C9500-48Y4C"}
        diff = diffcore.diff_check(view, dict(view), {"mode": "equality_scalar"})
        self.assertEqual(diff["result"], "pass")
        self.assertEqual(diff["changed"], [])

    def test_changed_and_missing_fields(self):
        pre = {"version": "17.9.4", "model": "C9500-48Y4C"}
        post = {"version": "17.12.4", "serial": "FCW0000A0AA"}
        diff = diffcore.diff_check(pre, post, {"mode": "equality_scalar"})
        self.assertEqual(diff["result"], "diffs")
        self.assertEqual(
            diff["changed"],
            [
                {"key": "model", "field": None, "old": "C9500-48Y4C", "new": None},
                {"key": "serial", "field": None, "old": None, "new": "FCW0000A0AA"},
                {"key": "version", "field": None, "old": "17.9.4", "new": "17.12.4"},
            ],
        )
        self.assertEqual(diff["added"], [])
        self.assertEqual(diff["removed"], [])


class TestTolerance(unittest.TestCase):
    def test_band_pass_pct(self):
        compare = {"mode": "tolerance", "fields": {"total": {"pct": 10}}}
        diff = diffcore.diff_check({"total": 100}, {"total": 105}, compare)
        self.assertEqual(diff["result"], "pass")
        (entry,) = diff["evaluations"]
        self.assertEqual(entry["field"], "total")
        self.assertEqual(entry["old"], 100)
        self.assertEqual(entry["new"], 105)
        self.assertEqual(entry["delta"], 5)
        self.assertEqual(entry["delta_pct"], 5.0)
        self.assertIs(entry["within"], True)

    def test_band_fail_pct(self):
        compare = {"mode": "tolerance", "fields": {"total": {"pct": 10}}}
        diff = diffcore.diff_check({"total": 100}, {"total": 120}, compare)
        self.assertEqual(diff["result"], "diffs")
        self.assertIs(diff["evaluations"][0]["within"], False)

    def test_band_pass_abs(self):
        compare = {"mode": "tolerance", "fields": {"total": {"abs": 3}}}
        diff = diffcore.diff_check({"total": 10}, {"total": 7}, compare)
        self.assertIs(diff["evaluations"][0]["within"], True)

    def test_pct_on_zero_baseline(self):
        compare = {"mode": "tolerance", "fields": {"n": {"pct": 30}}}
        stayed = diffcore.diff_check({"n": 0}, {"n": 0}, compare)
        self.assertIs(stayed["evaluations"][0]["within"], True)
        self.assertIsNone(stayed["evaluations"][0]["delta_pct"])
        appeared = diffcore.diff_check({"n": 0}, {"n": 1}, compare)
        self.assertIs(appeared["evaluations"][0]["within"], False)
        self.assertEqual(appeared["result"], "diffs")

    def test_default_band_from_compare(self):
        # No fields declared: numeric union of both sides, each under the default band.
        compare = {"mode": "tolerance", "band": {"abs": 3}}
        diff = diffcore.diff_check({"ospf": 10, "bgp": 5}, {"ospf": 12, "bgp": 50}, compare)
        self.assertEqual(diff["result"], "diffs")
        by_field = {entry["field"]: entry for entry in diff["evaluations"]}
        self.assertEqual(sorted(by_field), ["bgp", "ospf"])
        self.assertIs(by_field["ospf"]["within"], True)
        self.assertIs(by_field["bgp"]["within"], False)

    def test_direction_min_only(self):
        compare = {"mode": "tolerance", "fields": {"n": {"direction": "min_only"}}}
        grew = diffcore.diff_check({"n": 10}, {"n": 500}, compare)
        self.assertIs(grew["evaluations"][0]["within"], True)
        shrank = diffcore.diff_check({"n": 10}, {"n": 9}, compare)
        self.assertIs(shrank["evaluations"][0]["within"], False)

    def test_direction_max_only_with_abs_bound(self):
        compare = {"mode": "tolerance", "fields": {"n": {"direction": "max_only", "abs": 2}}}
        dropped = diffcore.diff_check({"n": 10}, {"n": 0}, compare)
        self.assertIs(dropped["evaluations"][0]["within"], True)
        rose_within = diffcore.diff_check({"n": 10}, {"n": 12}, compare)
        self.assertIs(rose_within["evaluations"][0]["within"], True)
        rose_out = diffcore.diff_check({"n": 10}, {"n": 13}, compare)
        self.assertIs(rose_out["evaluations"][0]["within"], False)

    def test_non_numeric_notes_and_does_not_fail(self):
        compare = {"mode": "tolerance", "fields": {"n": {"abs": 1}}}
        diff = diffcore.diff_check({"n": "many"}, {"n": 5}, compare)
        (entry,) = diff["evaluations"]
        self.assertIsNone(entry["within"])
        self.assertEqual(entry["note"], "not numeric on both sides")
        self.assertEqual(diff["result"], "pass")

    def test_no_band_at_all_requires_exact(self):
        compare = {"mode": "tolerance", "fields": {"n": {}}}
        self.assertEqual(diffcore.diff_check({"n": 5}, {"n": 5}, compare)["result"], "pass")
        self.assertEqual(diffcore.diff_check({"n": 5}, {"n": 6}, compare)["result"], "diffs")


class TestPresenceOnly(unittest.TestCase):
    def test_pass_ignores_value_changes(self):
        pre = {"Gi1/0/1": {"oper": "up"}}
        post = {"Gi1/0/1": {"oper": "down"}}
        diff = diffcore.diff_check(pre, post, {"mode": "presence_only"})
        self.assertEqual(diff["result"], "pass")
        self.assertEqual(diff["changed"], [])

    def test_added_removed(self):
        diff = diffcore.diff_check({"a": 1, "b": 2}, {"b": 9, "c": 3}, {"mode": "presence_only"})
        self.assertEqual(diff["result"], "diffs")
        self.assertEqual(diff["added"], [{"key": "c"}])
        self.assertEqual(diff["removed"], [{"key": "a"}])


class TestCapability(unittest.TestCase):
    def test_floor_gating_and_min_post(self):
        compare = {"mode": "capability", "floor_pre": 5, "min_post": 1}
        pre = {"trust|untrust": 1842, "trust|dmz": 10, "dmz|untrust": 2}
        post = {"trust|untrust": 3, "trust|dmz": 0, "dmz|untrust": 0}
        diff = diffcore.diff_check(pre, post, compare)
        self.assertEqual(diff["result"], "diffs")
        by_key = {entry["key"]: entry for entry in diff["evaluations"]}
        # Carried 1842 pre: gating, and 3 post proves the path.
        self.assertIs(by_key["trust|untrust"]["gating"], True)
        self.assertIs(by_key["trust|untrust"]["ok"], True)
        # Gating pair at zero post is the miss.
        self.assertIs(by_key["trust|dmz"]["gating"], True)
        self.assertIs(by_key["trust|dmz"]["ok"], False)
        # Below the floor: not gating, ok is None (not False).
        self.assertIs(by_key["dmz|untrust"]["gating"], False)
        self.assertIsNone(by_key["dmz|untrust"]["ok"])

    def test_defaults_and_missing_sides(self):
        # floor_pre defaults to 5, min_post to 1; a gating pair absent from the
        # post sweep fails closed with a note, never a fabricated zero.
        diff = diffcore.diff_check({"a|b": 5}, {}, {"mode": "capability"})
        self.assertEqual(diff["result"], "diffs")
        (entry,) = diff["evaluations"]
        self.assertEqual(entry["old"], 5)
        self.assertIsNone(entry["new"])
        self.assertIs(entry["ok"], False)
        self.assertIn("not measured post", entry["note"])

    def test_absent_post_can_be_declared_a_zero(self):
        # A check whose buckets are counted rows declares absent_post "zero":
        # the verdict is the same miss, the note says what absent means there.
        compare = {"mode": "capability", "absent_post": "zero"}
        diff = diffcore.diff_check({"a|b": 5, "c": 2}, {}, compare)
        self.assertEqual(diff["result"], "diffs")
        by_key = {entry["key"]: entry for entry in diff["evaluations"]}
        self.assertIs(by_key["a|b"]["ok"], False)
        self.assertEqual(by_key["a|b"]["note"], "absent post (counts as zero)")
        self.assertIsNone(by_key["c"]["ok"])  # below the floor: never gating
        # Any other value keeps the sweep wording.
        diff = diffcore.diff_check({"a|b": 5}, {}, {"mode": "capability", "absent_post": "x"})
        self.assertIn("sweep mismatch", diff["evaluations"][0]["note"])

    def test_all_non_gating_passes(self):
        diff = diffcore.diff_check({"a|b": 1}, {"a|b": 0}, {"mode": "capability"})
        self.assertEqual(diff["result"], "pass")

    def test_unreadable_pre_is_visible_not_silently_nongating(self):
        # None = collector saw the bucket but could not parse its count.
        diff = diffcore.diff_check({"a|b": None}, {"a|b": 0}, {"mode": "capability"})
        self.assertEqual(diff["result"], "pass")  # unknown gating is not a miss...
        (entry,) = diff["evaluations"]
        self.assertIsNone(entry["gating"])  # ...but it is visibly unknown
        self.assertIsNone(entry["ok"])
        self.assertIn("pre count unreadable", entry["note"])

    def test_unreadable_post_on_gating_pair_fails_closed(self):
        diff = diffcore.diff_check({"a|b": 50}, {"a|b": None}, {"mode": "capability"})
        self.assertEqual(diff["result"], "diffs")
        (entry,) = diff["evaluations"]
        self.assertIs(entry["ok"], False)
        self.assertIn("post count unreadable", entry["note"])

    def test_new_pair_post_side_never_gates(self):
        diff = diffcore.diff_check({}, {"a|b": 7}, {"mode": "capability"})
        self.assertEqual(diff["result"], "pass")
        (entry,) = diff["evaluations"]
        self.assertIs(entry["gating"], False)
        self.assertIsNone(entry["ok"])


class TestInfoAndUnknown(unittest.TestCase):
    def test_info_only(self):
        diff = diffcore.diff_check({"x": 1}, {"y": 2}, {"mode": "info_only"})
        self.assertEqual(diff, {"result": "info"})

    def test_unknown_mode_raises(self):
        with self.assertRaises(ValueError):
            diffcore.diff_check({}, {}, {"mode": "fuzzy"})


class TestScrub(unittest.TestCase):
    def test_wildcard_paths(self):
        data = {
            "vrfs": {
                "default": {"routes": {"r1": {"age": 5, "next_hop": "192.0.2.1"}}},
                "mgmt": {"routes": {"r2": {"age": 9, "next_hop": "10.0.0.1"}}},
            },
            "system": {"uptime": 12345, "hostname": "core-sw-01"},
        }
        result = diffcore.scrub(data, ["vrfs.*.routes.*.age", "*.uptime"])
        self.assertIs(result, data)
        self.assertEqual(data["vrfs"]["default"]["routes"]["r1"], {"next_hop": "192.0.2.1"})
        self.assertEqual(data["vrfs"]["mgmt"]["routes"]["r2"], {"next_hop": "10.0.0.1"})
        self.assertEqual(data["system"], {"hostname": "core-sw-01"})

    def test_missing_paths_are_harmless(self):
        data = {"a": {"b": 1}}
        diffcore.scrub(data, ["a.zzz", "nope.*.deep", "a.b.c.d"])
        self.assertEqual(data, {"a": {"b": 1}})


if __name__ == "__main__":
    unittest.main()
