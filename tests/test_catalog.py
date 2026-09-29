"""jobs/catalog.py: the pure catalog walk the shakedown reports through.

``catalog_key_models`` merges the platform base list with every catalog
module's ``KEY_MODELS`` (first occurrence wins); it is reachable in CI only
here, since shakedown_job imports Nautobot and the transports.
"""

import unittest

if __package__:
    from . import _loader
else:  # unittest discover -s tests imports test modules as top-level
    import _loader

catalog = _loader.load("catalog")
registry = _loader.registry


class TestCatalogKeyModels(unittest.TestCase):
    def test_iosxe_merge_is_deduplicated_and_starts_with_the_base_list(self):
        merged = catalog.catalog_key_models("iosxe")
        self.assertEqual(len(merged), len(set(merged)))
        base = catalog.IOSXE_KEY_MODELS
        self.assertEqual(merged[: len(base)], base)
        self.assertEqual(catalog.PLATFORM_KEY_MODELS, {"iosxe": base})

    def test_every_layer_modules_models_are_present(self):
        merged = catalog.catalog_key_models("iosxe")
        contributors = 0
        for name, module in _loader.CHECK_MODULES.items():
            owned = [
                c for c in registry.checks_for("iosxe") if c.collector.__module__ == module.__name__
            ]
            declared = getattr(module, "KEY_MODELS", ())
            if not owned:
                for model in declared:
                    self.assertNotIn(model, merged, "%s leaked %s" % (name, model))
                continue
            contributors += 1
            for model in declared:
                self.assertIn(model, merged, "%s: %s" % (name, model))
        self.assertGreaterEqual(contributors, 5)  # core plus the four layer modules
        for expected in (
            "Cisco-IOS-XE-vlan-oper",
            "Cisco-IOS-XE-hsrp-oper",
            "Cisco-IOS-XE-poe-oper",
        ):
            self.assertIn(expected, merged)

    def test_other_platforms_report_nothing(self):
        self.assertEqual(catalog.catalog_key_models("panos"), ())
        self.assertEqual(catalog.catalog_key_models("no-such-platform"), ())

    def test_a_string_key_models_is_one_model_never_characters(self):
        # A module that spells KEY_MODELS as a bare string is a mistake the
        # merge must not turn into single-letter "models".
        module = next(iter(_loader.CHECK_MODULES.values()))
        for candidate in _loader.CHECK_MODULES.values():
            if any(
                c.collector.__module__ == candidate.__name__ for c in registry.checks_for("iosxe")
            ):
                module = candidate
                break
        original = module.KEY_MODELS
        try:
            module.KEY_MODELS = "Cisco-IOS-XE-only-oper"
            merged = catalog.catalog_key_models("iosxe")
        finally:
            module.KEY_MODELS = original
        self.assertIn("Cisco-IOS-XE-only-oper", merged)
        self.assertNotIn("C", merged)

    def test_catalog_modules_are_the_discovered_checks_modules(self):
        names = [module.__name__.rsplit(".", 1)[-1] for module in catalog.catalog_modules()]
        self.assertEqual(names, sorted(_loader.CHECK_MODULES))


if __name__ == "__main__":
    unittest.main()
