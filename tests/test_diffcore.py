"""diffcore: every compare mode, scrub, expectations, and classification."""

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


class TestNormalizeExpectations(unittest.TestCase):
    def test_none_and_non_list(self):
        self.assertEqual(diffcore.normalize_expectations(None), ([], []))
        exps, problems = diffcore.normalize_expectations({"op": "added"})
        self.assertEqual(exps, [])
        self.assertEqual(problems, ["expectations must be a JSON list of objects"])

    def test_id_assignment_defaults_and_bad_entries(self):
        raw = [
            {"op": "added"},
            "junk",
            {"op": "bogus"},
            {"id": "mine", "op": "removed", "key": "trust|*"},
        ]
        exps, problems = diffcore.normalize_expectations(raw)
        self.assertEqual(len(exps), 2)
        first, last = exps
        # Ids are positional, so the valid 4th entry keeps its own id and the
        # first gets exp-1 even with rejects between them.
        self.assertEqual(first["id"], "exp-1")
        self.assertEqual(first["key"], "*")
        self.assertEqual(first["op"], "added")
        self.assertEqual(last["id"], "mine")
        self.assertEqual(len(problems), 2)
        self.assertIn("expectation #2 is not an object", problems[0])
        self.assertIn("bogus", problems[1])
        self.assertIn("exp-3", problems[1])

    def test_no_selector_entry_is_rejected_not_wildcarded(self):
        # {"note": ...} defaulting to key="*"/op="any" would bless every diff.
        exps, problems = diffcore.normalize_expectations([{"note": "oops"}, {}])
        self.assertEqual(exps, [])
        self.assertEqual(len(problems), 2)
        self.assertIn("no selector keys", problems[0])

    def test_explicit_wildcard_still_works(self):
        exps, problems = diffcore.normalize_expectations([{"key": "*"}])
        self.assertEqual(problems, [])
        self.assertEqual(len(exps), 1)

    def test_device_selector_scoping(self):
        exps, problems = diffcore.normalize_expectations(
            [
                {"id": "a", "key": "*", "device": "core-9500-a"},
                {"id": "b", "key": "*", "device": "fw-*"},
                {"id": "c", "key": "*"},
            ]
        )
        self.assertEqual(problems, [])
        scoped = diffcore.expectations_for_device(exps, ("core-9500-a",))
        self.assertEqual([exp["id"] for exp in scoped], ["a", "c"])
        # A replacement pair matches on either name.
        scoped = diffcore.expectations_for_device(exps, ("old-5250", "fw-vm500-a"))
        self.assertEqual([exp["id"] for exp in scoped], ["b", "c"])


class TestClassifyDiff(unittest.TestCase):
    def _diff(self):
        return {
            "added": [{"key": "trust|198.51.100.5", "value": {"zone": "trust"}}],
            "removed": [{"key": "legacy|203.0.113.9", "value": {"zone": "legacy"}}],
            "changed": [
                {"key": "peer1", "field": "state", "old": "Established", "new": "Idle"},
                {"key": "peer2", "field": "state", "old": "Idle", "new": "Established"},
            ],
        }

    def test_expected_unexpected_counts_and_annotation(self):
        exps, problems = diffcore.normalize_expectations(
            [
                {"id": "e-add", "op": "added", "key": "trust|*"},
                {
                    "id": "e-chg",
                    "op": "changed",
                    "key": "peer1",
                    "field": "state",
                    "to_contains": "Idle",
                },
                {"id": "e-never", "op": "removed", "key": "nomatch|*"},
            ]
        )
        self.assertEqual(problems, [])
        diff = self._diff()
        matched = set()
        expected, unexpected = diffcore.classify_diff("panos_arp", diff, exps, matched)
        self.assertEqual((expected, unexpected), (2, 2))
        self.assertEqual(matched, {"e-add", "e-chg"})
        self.assertEqual(diff["added"][0]["classification"], "expected")
        self.assertEqual(diff["added"][0]["expectation_id"], "e-add")
        self.assertEqual(diff["removed"][0]["classification"], "unexpected")
        self.assertEqual(diff["changed"][0]["classification"], "expected")
        self.assertEqual(diff["changed"][1]["classification"], "unexpected")

    def test_check_filter(self):
        exps, _ = diffcore.normalize_expectations(
            [{"id": "e1", "check": "other_check", "op": "removed", "key": "*"}]
        )
        diff = self._diff()
        matched = set()
        expected, unexpected = diffcore.classify_diff("panos_arp", diff, exps, matched)
        self.assertEqual(expected, 0)
        self.assertEqual(unexpected, 4)
        self.assertEqual(matched, set())

    def test_check_filter_exact_match(self):
        exps, _ = diffcore.normalize_expectations(
            [{"id": "e1", "check": "panos_arp", "op": "removed", "key": "legacy|*"}]
        )
        diff = self._diff()
        expected, _ = diffcore.classify_diff("panos_arp", diff, exps, set())
        self.assertEqual(expected, 1)

    def test_op_any_matches_all_buckets(self):
        exps, _ = diffcore.normalize_expectations([{"id": "e1", "key": "*"}])
        diff = self._diff()
        expected, unexpected = diffcore.classify_diff("c", diff, exps, set())
        self.assertEqual((expected, unexpected), (4, 0))

    def test_field_filter(self):
        exps, _ = diffcore.normalize_expectations(
            [{"id": "e1", "op": "changed", "key": "*", "field": "uptime"}]
        )
        diff = self._diff()
        expected, unexpected = diffcore.classify_diff("c", diff, exps, set())
        self.assertEqual(expected, 0)
        self.assertEqual(unexpected, 4)

    def test_to_exact_value(self):
        exps, _ = diffcore.normalize_expectations(
            [{"id": "e1", "op": "changed", "key": "peer2", "to": "Established"}]
        )
        diff = self._diff()
        matched = set()
        expected, _ = diffcore.classify_diff("c", diff, exps, matched)
        self.assertEqual(expected, 1)
        self.assertEqual(matched, {"e1"})
        # Wrong target value does not match.
        exps2, _ = diffcore.normalize_expectations(
            [{"id": "e2", "op": "changed", "key": "peer2", "to": "Idle"}]
        )
        expected2, _ = diffcore.classify_diff("c", self._diff(), exps2, set())
        self.assertEqual(expected2, 0)

    def test_matched_ids_accumulate_across_checks(self):
        exps, _ = diffcore.normalize_expectations([{"id": "e1", "op": "added", "key": "*"}])
        matched = set()
        diffcore.classify_diff("check_a", {"added": [{"key": "x"}]}, exps, matched)
        diffcore.classify_diff("check_b", {"added": [{"key": "y"}]}, exps, matched)
        self.assertEqual(matched, {"e1"})

    def test_first_matching_expectation_wins(self):
        exps, _ = diffcore.normalize_expectations(
            [
                {"id": "first", "op": "added", "key": "*"},
                {"id": "second", "op": "added", "key": "*"},
            ]
        )
        diff = {"added": [{"key": "x"}]}
        matched = set()
        diffcore.classify_diff("c", diff, exps, matched)
        self.assertEqual(diff["added"][0]["expectation_id"], "first")
        self.assertEqual(matched, {"first"})

    def test_capability_miss_can_be_declared_expected(self):
        # A planned zone decommission: its pair going to zero is expected.
        exps, _ = diffcore.normalize_expectations(
            [{"id": "e-cap", "check": "panos_session_matrix", "key": "legacy>*", "op": "changed"}]
        )
        diff = diffcore.diff_check(
            {"legacy>untrust": 40, "trust>untrust": 900},
            {"legacy>untrust": 0, "trust>untrust": 3},
            {"mode": "capability"},
        )
        matched = set()
        expected, unexpected = diffcore.classify_diff("panos_session_matrix", diff, exps, matched)
        self.assertEqual((expected, unexpected), (1, 0))
        self.assertEqual(matched, {"e-cap"})
        by_key = {entry["key"]: entry for entry in diff["evaluations"]}
        self.assertEqual(by_key["legacy>untrust"]["classification"], "expected")
        self.assertEqual(by_key["legacy>untrust"]["expectation_id"], "e-cap")
        # The healthy gating pair is not a miss, so it gets no classification.
        self.assertNotIn("classification", by_key["trust>untrust"])

    def test_tolerance_miss_matches_by_field_name(self):
        exps, _ = diffcore.normalize_expectations(
            [{"id": "e-tol", "key": "active", "op": "changed"}]
        )
        diff = diffcore.diff_check(
            {"active": 1000, "tcp": 800},
            {"active": 10, "tcp": 790},
            {"mode": "tolerance", "band": {"pct": 30}},
        )
        matched = set()
        expected, unexpected = diffcore.classify_diff("panos_session_info", diff, exps, matched)
        self.assertEqual((expected, unexpected), (1, 0))
        by_field = {entry["field"]: entry for entry in diff["evaluations"]}
        self.assertEqual(by_field["active"]["classification"], "expected")

    def test_unmatched_numeric_miss_is_unexpected(self):
        diff = diffcore.diff_check({"a>b": 100}, {"a>b": 0}, {"mode": "capability"})
        matched = set()
        expected, unexpected = diffcore.classify_diff("m", diff, [], matched)
        self.assertEqual((expected, unexpected), (0, 1))
        self.assertEqual(diff["evaluations"][0]["classification"], "unexpected")


if __name__ == "__main__":
    unittest.main()
