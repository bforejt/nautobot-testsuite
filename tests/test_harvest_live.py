"""tools/harvest_live.py: the bmc spec's extra reads, driven offline.

The harvest talks to a device and runs outside CI; the battery locks in the
parts that decide what a BMC harvest reads and how each read is redacted:
the redactor chosen per path, links refused by the fence never sent, and one
failing read never stopping the rest. Stdlib only (the transports are
imported inside main()).
"""

import contextlib
import importlib.util
import io
import pathlib
import unittest

if __package__:
    from . import _loader
    from .test_checks_bmc import CH, MGR, SYS, _base_payloads, _FakeCtx
else:  # unittest discover -s tests imports test modules as top-level
    import _loader
    from test_checks_bmc import CH, MGR, SYS, _base_payloads, _FakeCtx

_TOOL = pathlib.Path(__file__).resolve().parents[1] / "tools" / "harvest_live.py"
_spec = importlib.util.spec_from_file_location("harvest_live", _TOOL)
harvest = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(harvest)

checks = _loader.checks_bmc


class TestBmcExtras(unittest.TestCase):
    def test_each_path_gets_the_family_redactor(self):
        pick = lambda path: harvest._bmc_redactor(checks, path)  # noqa: E731
        self.assertIs(pick(SYS + "/LogServices/StandardLog/Entries"), checks._redact_log_page)
        self.assertIs(
            pick("/redfish/v1/AccountService/Accounts?$expand=.($levels=1)"),
            checks._scrub_accounts,
        )
        self.assertIs(pick(MGR + "/NetworkProtocol"), checks._scrub_payload)

    def test_extras_read_collections_expanded_and_never_send_a_refused_link(self):
        payloads = _base_payloads()
        payloads[CH]["Oem"]["Lenovo"]["LEDs"] = {"@odata.id": CH + "/Oem/Lenovo/LEDs"}
        payloads[CH + "/Oem/Lenovo/LEDs"] = {"Members": [{"@odata.id": CH + "/Oem/Lenovo/LEDs/1"}]}
        payloads[MGR]["Oem"]["Lenovo"]["Bad"] = {"@odata.id": MGR + "/Actions/Oem/x"}
        ctx = _FakeCtx(payloads, errors={MGR + "/Oem/Lenovo/Security": 500})
        with contextlib.redirect_stdout(io.StringIO()):  # the per-read lines
            harvest.run_bmc_extras(ctx)
        self.assertIn(CH + "/Oem/Lenovo/LEDs", ctx.gets)
        self.assertIn(CH + "/Oem/Lenovo/LEDs" + checks._EXPAND, ctx.gets)
        self.assertFalse([path for path in ctx.gets if "/Actions/" in path])
        # the failing read did not stop the ones after it
        self.assertIn(SYS + "/Memory" + checks._EXPAND, ctx.gets)
        for path, redactor in ctx.redacted:
            self.assertIsNotNone(redactor, path)


if __name__ == "__main__":
    unittest.main()
