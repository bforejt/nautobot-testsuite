"""envelope: sanitizer, snapshot round trip, report summarization, timestamps."""

import unittest
from datetime import datetime, timezone

if __package__:
    from . import _loader
else:  # unittest discover -s tests imports test modules as top-level
    import _loader

envelope = _loader.envelope
registry = _loader.registry
C = _loader.constants


def _checkdef(check_id="iosxe_arp", tier=1, compare=None):
    return registry.CheckDef(
        id=check_id,
        platform="iosxe",
        description="test check",
        tier=tier,
        compare=compare if compare is not None else {"mode": "equality_set"},
        miss_meaning="something moved",
    )


class TestSafeName(unittest.TestCase):
    def test_passthrough(self):
        self.assertEqual(envelope.safe_name("fw-edge-01.example.net"), "fw-edge-01.example.net")

    def test_collapses_runs_of_bad_chars(self):
        self.assertEqual(envelope.safe_name("core sw/1 (lab)"), "core-sw-1-lab")

    def test_all_bad_chars_falls_back(self):
        self.assertEqual(envelope.safe_name("***"), "unnamed")

    def test_non_string_input(self):
        self.assertEqual(envelope.safe_name(42), "42")


class TestEnvelopeRoundTrip(unittest.TestCase):
    def test_new_envelope_record_summary(self):
        env = envelope.new_envelope(
            device_info={"name": "core-sw-01", "platform": "iosxe"},
            change_id="CHG0012345",
            kind="pre",
            package="fw-cutover-core-switch",
            check_ids=["iosxe_routes_rib", "iosxe_arp"],
            job_info={"job_result_id": "abc"},
        )
        self.assertEqual(env["schema_version"], C.SCHEMA_VERSION)
        self.assertEqual(env["kind"], "pre")
        self.assertEqual(env["change_id"], "CHG0012345")
        self.assertEqual(env["framework"], {"name": C.FRAMEWORK_NAME, "version": C.JOB_VERSION})
        self.assertEqual(env["device"], {"name": "core-sw-01", "platform": "iosxe"})
        self.assertEqual(env["requested_checks"], ["iosxe_arp", "iosxe_routes_rib"])
        self.assertEqual(env["checks"], {})
        # captured_at is our own ISO format and must round-trip through parse_iso.
        self.assertIsNotNone(envelope.parse_iso(env["captured_at"]))

        check = _checkdef("iosxe_arp", tier=1, compare={"mode": "equality_set"})
        envelope.record_check(
            env,
            check,
            "success",
            normalized={"Vlan10|192.0.2.1": "aa:bb:cc:00:00:01"},
            duration_s=1.23456,
            collector_meta={"source": "restconf"},
        )
        envelope.record_check(env, _checkdef("iosxe_routes_rib"), "failed", error="timeout")
        envelope.record_check(env, _checkdef("iosxe_ospf_neighbors"), "skipped")
        envelope.record_check(env, _checkdef("iosxe_bgp_peers"), "not-present")
        envelope.record_check(env, _checkdef("iosxe_fib"), "failed", error="boom")

        body = env["checks"]["iosxe_arp"]
        self.assertEqual(body["status"], "success")
        self.assertIsNone(body["error"])
        self.assertEqual(body["duration_s"], 1.23)
        self.assertEqual(body["tier"], 1)
        self.assertEqual(body["compare"], {"mode": "equality_set"})
        self.assertEqual(body["collector"], {"source": "restconf"})
        self.assertEqual(body["normalized"], {"Vlan10|192.0.2.1": "aa:bb:cc:00:00:01"})

        failed = env["checks"]["iosxe_routes_rib"]
        self.assertEqual(failed["error"], "timeout")
        self.assertIsNone(failed["duration_s"])
        self.assertEqual(failed["normalized"], {})
        self.assertEqual(failed["collector"], {})

        self.assertEqual(
            envelope.envelope_summary(env),
            {"success": 1, "failed": 2, "skipped": 1, "not-present": 1},
        )


class TestReport(unittest.TestCase):
    def _pre_post(self):
        pre = envelope.new_envelope(
            {"name": "fw-edge-01", "platform": "panos"}, "CHG1", "pre", "full", [], {}
        )
        post = envelope.new_envelope(
            {"name": "fw-edge-01", "platform": "panos"}, "CHG1", "post", "full", [], {}
        )
        return pre, post

    def test_new_report_header(self):
        pre, post = self._pre_post()
        report = envelope.new_report(pre, post, "fw-edge-01")
        self.assertEqual(report["schema_version"], C.SCHEMA_VERSION)
        self.assertEqual(report["change_id"], "CHG1")
        self.assertEqual(report["device"], "fw-edge-01")
        self.assertEqual(report["pre"]["device"], "fw-edge-01")
        self.assertEqual(report["pre"]["captured_at"], pre["captured_at"])
        self.assertEqual(report["pre"]["framework_version"], C.JOB_VERSION)
        self.assertEqual(report["post"]["captured_at"], post["captured_at"])
        self.assertEqual(report["checks"], {})
        self.assertEqual(report["expectations"], {"matched": [], "unmatched": []})

    def test_summarize_report_totals(self):
        pre, post = self._pre_post()
        report = envelope.new_report(pre, post, "fw-edge-01")
        report["checks"] = {
            "clean": {"result": "pass", "added": [], "removed": [], "changed": []},
            "set_diffs": {
                "result": "diffs",
                "added": [{"key": "k1", "classification": "expected"}],
                "removed": [],
                "changed": [
                    {"key": "k2", "classification": "unexpected"},
                    {"key": "k3"},  # no classification at all counts unexpected
                ],
            },
            "numeric": {
                "result": "diffs",
                "evaluations": [
                    {"field": "a", "within": True},
                    {"field": "b", "within": False},
                    {"key": "z1|z2", "ok": False, "gating": True},
                    {"key": "z3|z4", "ok": None, "gating": False},
                ],
            },
            "broken": {"result": "failed", "error": "collector blew up"},
            "context": {"result": "info"},
            "absent": {"result": "skipped"},
        }
        expectations = [
            {"id": "e-hit", "note": "planned add"},
            {"id": "e-miss", "note": "route we expected to vanish"},
        ]
        matched = {"e-hit"}
        result = envelope.summarize_report(report, expectations, matched)
        self.assertIs(result, report)
        self.assertEqual(
            report["summary"],
            {
                "checks_total": 6,
                "checks_passed": 1,
                "checks_with_diffs": 2,
                "checks_failed": 1,
                "checks_skipped": 2,  # skipped + info
                "diffs_total": 5,  # 3 bucket entries + 2 failed evaluations
                "expected": 1,
                "unexpected": 4,
                "expectations_unmatched": 1,
            },
        )
        self.assertEqual(report["expectations"]["matched"], ["e-hit"])
        self.assertEqual(
            report["expectations"]["unmatched"],
            [{"id": "e-miss", "note": "route we expected to vanish", "status": "not_observed"}],
        )


class TestParseIso(unittest.TestCase):
    def test_good(self):
        stamp = envelope.parse_iso("2026-08-23T01:02:03Z")
        self.assertEqual(stamp, datetime(2026, 8, 23, 1, 2, 3, tzinfo=timezone.utc))
        self.assertIsNotNone(stamp.tzinfo)

    def test_bad(self):
        self.assertIsNone(envelope.parse_iso("not-a-date"))
        self.assertIsNone(envelope.parse_iso(None))
        self.assertIsNone(envelope.parse_iso("2026-08-23 01:02:03"))

    def test_round_trip_with_utcnow(self):
        self.assertIsNotNone(envelope.parse_iso(envelope.utcnow_iso()))


if __name__ == "__main__":
    unittest.main()
