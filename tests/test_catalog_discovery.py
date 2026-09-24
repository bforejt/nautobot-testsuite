"""The catalog auto-discovery contract.

jobs/__init__.py imports every ``jobs/checks_*.py`` by name (pkgutil), and
tests/_loader.py mirrors that loop. A catalog module that neither loads
registers nothing — silently — so this locks in that the two agree, that
nothing on disk is missed, and that every module actually registers checks.
"""

import pkgutil
import unittest

if __package__:
    from . import _loader
else:  # unittest discover -s tests imports test modules as top-level
    import _loader

registry = _loader.registry


class TestCatalogDiscovery(unittest.TestCase):
    def test_loader_mirrors_the_package_discovery_loop(self):
        on_disk = sorted(
            module.name
            for module in pkgutil.iter_modules([str(_loader.ROOT / "jobs")])
            if module.name.startswith("checks_")
        )
        self.assertEqual(sorted(_loader.CHECK_MODULES), on_disk)
        for expected in ("checks_iosxe", "checks_panos", "checks_iosxe_wireless"):
            self.assertIn(expected, on_disk)

    def test_every_catalog_module_registers_checks(self):
        for name, module in _loader.CHECK_MODULES.items():
            owned = [
                check
                for check in registry.CHECKS.values()
                if check.collector.__module__ == module.__name__
            ]
            self.assertTrue(owned, "%s registered no checks" % (name,))

    def test_every_registered_check_has_a_valid_mode_and_semantics(self):
        for check_id, check in registry.CHECKS.items():
            self.assertIn(
                check.compare.get("mode", "equality_set"), _loader.diffcore.MODES, check_id
            )
            self.assertIn(check_id, registry.SEMANTICS, check_id)


if __name__ == "__main__":
    unittest.main()
