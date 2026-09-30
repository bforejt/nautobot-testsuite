"""Registry selection: checks_for and parse_check_ids (the dev shakedown's id filter)."""

import unittest

if __package__:
    from . import _loader
else:  # unittest discover -s tests imports test modules as top-level
    import _loader

registry = _loader.registry


def _two_ids(platform):
    ids = sorted(check.id for check in registry.checks_for(platform))
    return ids[0], ids[1]


class TestParseCheckIds(unittest.TestCase):
    def test_blank_means_no_filter(self):
        for raw in (None, "", "   ", " , ,"):
            with self.subTest(raw=raw):
                self.assertIsNone(registry.parse_check_ids(raw))

    def test_ids_are_trimmed_and_keep_their_order(self):
        first, second = _two_ids("iosxe")
        self.assertEqual(registry.parse_check_ids(" %s ,,%s," % (second, first)), [second, first])

    def test_duplicates_collapse_to_one_run(self):
        first, _second = _two_ids("iosxe")
        self.assertEqual(registry.parse_check_ids("%s,%s" % (first, first)), [first])

    def test_unknown_ids_raise_naming_each_and_listing_the_valid_ones(self):
        known, _second = _two_ids("bmc")
        with self.assertRaises(ValueError) as caught:
            registry.parse_check_ids("%s,nope_b,nope_a" % known)
        message = str(caught.exception)
        self.assertIn("nope_a, nope_b", message)
        self.assertIn("Valid ids:", message)
        self.assertIn(known, message.split("Valid ids:", 1)[1])


class TestChecksForSelection(unittest.TestCase):
    def test_no_ids_returns_every_check_of_the_platform(self):
        expected = {check.id for check in registry.CHECKS.values() if check.platform == "bmc"}
        self.assertTrue(expected)
        self.assertEqual({check.id for check in registry.checks_for("bmc")}, expected)

    def test_ids_narrow_each_platform_to_its_own_named_checks(self):
        iosxe_id, _ = _two_ids("iosxe")
        bmc_id, _ = _two_ids("bmc")
        both = [iosxe_id, bmc_id]
        self.assertEqual([check.id for check in registry.checks_for("iosxe", both)], [iosxe_id])
        self.assertEqual([check.id for check in registry.checks_for("bmc", both)], [bmc_id])

    def test_ids_naming_only_another_platform_select_nothing(self):
        iosxe_id, _ = _two_ids("iosxe")
        self.assertEqual(registry.checks_for("panos", [iosxe_id]), [])


if __name__ == "__main__":
    unittest.main()
