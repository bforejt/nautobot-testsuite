"""bmc_target: the BMC interface naming rule, address preference, ambiguity refusal."""

import unittest

if __package__:
    from . import _loader
else:  # unittest discover -s tests imports test modules as top-level
    import _loader

bmc_target = _loader.load("bmc_target")


class TestNamingRule(unittest.TestCase):
    def test_first_word_matches(self):
        cases = {
            "xcc": "xcc",
            "XCC": "xcc",
            "XCC-mgmt": "xcc",
            "xcc_dedicated": "xcc",
            "iLO 5": "ilo",
            "ilo5": "ilo",
            "idrac-1": "idrac",
            "iDRAC9": "idrac",
            "bmc0": "bmc",
            "BMC": "bmc",
            "imm2": "imm",
            "xclarity": "xclarity",
            "cimc": "cimc",
            "ipmi": "ipmi",
            "-xcc": "xcc",  # a leading separator is not a word
        }
        for name, token in cases.items():
            with self.subTest(name=name):
                self.assertEqual(bmc_target.match_bmc_interface(name), token)

    def test_non_matches(self):
        for name in (
            "mgmt-xcc",
            "eth0",
            "vmk0",
            "vmnic0",
            "xccmgmt",  # one word that is not a token
            "ilom",  # Oracle, not a token yet (plan §11 decision 4)
            "irmc",
            "",
            None,
            "---",
            "Ethernet1/1",
            "management",
        ):
            with self.subTest(name=name):
                self.assertIsNone(bmc_target.match_bmc_interface(name))

    def test_tokens_are_the_constant(self):
        self.assertEqual(
            _loader.constants.BMC_INTERFACE_NAMES,
            ("xcc", "xclarity", "imm", "idrac", "ilo", "cimc", "bmc", "ipmi"),
        )


class TestAddressPreference(unittest.TestCase):
    def test_lowest_ipv4_wins_and_every_address_is_named(self):
        chosen, seen = bmc_target.pick_address(
            ["2001:db8::5", "192.0.2.20/24", "192.0.2.3", "192.0.2.20"]
        )
        self.assertEqual(chosen, "192.0.2.3")
        self.assertEqual(seen, ["192.0.2.3", "192.0.2.20", "2001:db8::5"])

    def test_numeric_not_lexical_order(self):
        chosen, _ = bmc_target.pick_address(["192.0.2.100", "192.0.2.9"])
        self.assertEqual(chosen, "192.0.2.9")

    def test_ipv6_only(self):
        chosen, seen = bmc_target.pick_address(["2001:db8::20", "2001:db8::3/64"])
        self.assertEqual(chosen, "2001:db8::3")
        self.assertEqual(seen, ["2001:db8::3", "2001:db8::20"])

    def test_a_link_local_address_only_when_nothing_else_is_assigned(self):
        chosen, seen = bmc_target.pick_address(["169.254.95.118", "192.0.2.40"])
        self.assertEqual(chosen, "192.0.2.40")
        self.assertEqual(seen, ["192.0.2.40", "169.254.95.118"])
        self.assertEqual(bmc_target.pick_address(["169.254.95.118"])[0], "169.254.95.118")
        self.assertEqual(bmc_target.pick_address(["fe80::1", "2001:db8::9"])[0], "2001:db8::9")

    def test_nothing_usable(self):
        self.assertEqual(bmc_target.pick_address([]), (None, []))
        self.assertEqual(bmc_target.pick_address(None), (None, []))
        self.assertEqual(bmc_target.pick_address(["not-an-address", ""]), (None, []))


class TestFindBmc(unittest.TestCase):
    def test_one_match_with_address(self):
        target = bmc_target.find_bmc(
            [
                ("vmk0", ["198.51.100.5"], "a"),
                ("XCC-mgmt", ["192.0.2.30", "192.0.2.4"], "b"),
                ("vmnic0", [], "c"),
            ]
        )
        self.assertEqual(target.interface_name, "XCC-mgmt")
        self.assertEqual(target.token, "xcc")
        self.assertEqual(target.address, "192.0.2.4")
        self.assertEqual(target.addresses_seen, ("192.0.2.4", "192.0.2.30"))
        self.assertEqual(target.interface_id, "b")

    def test_no_match_is_none(self):
        self.assertIsNone(bmc_target.find_bmc([("vmk0", ["198.51.100.5"], "a")]))
        self.assertIsNone(bmc_target.find_bmc([]))

    def test_match_without_address(self):
        target = bmc_target.find_bmc([("xcc", [], "a")])
        self.assertEqual(target.interface_name, "xcc")
        self.assertIsNone(target.address)
        self.assertEqual(target.addresses_seen, ())

    def test_two_matches_refused_naming_both(self):
        with self.assertRaises(bmc_target.AmbiguousBmc) as caught:
            bmc_target.find_bmc([("xcc", ["192.0.2.4"], "a"), ("bmc0", ["192.0.2.5"], "b")])
        self.assertIn("bmc0, xcc", str(caught.exception))
        self.assertIn("2 interfaces", str(caught.exception))


class TestBlock(unittest.TestCase):
    def test_block_shapes(self):
        self.assertIsNone(bmc_target.bmc_block(None, captured=False))
        target = bmc_target.find_bmc([("xcc", ["192.0.2.4"], "a")])
        block = bmc_target.bmc_block(target, captured=True, vendor="Lenovo", product="SE350")
        self.assertEqual(
            block,
            {
                "interface": "xcc",
                "token": "xcc",
                "address": "192.0.2.4",
                "addresses_seen": ["192.0.2.4"],
                "transport": "redfish",
                "vendor": "Lenovo",
                "product": "SE350",
                "captured": True,
                "note": None,
            },
        )

    def test_block_without_address_names_why(self):
        target = bmc_target.find_bmc([("xcc", [], "a")])
        block = bmc_target.bmc_block(target, captured=False, note="no address assigned")
        self.assertIsNone(block["address"])
        self.assertIsNone(block["transport"])
        self.assertFalse(block["captured"])
        self.assertEqual(block["note"], "no address assigned")


if __name__ == "__main__":
    unittest.main()
