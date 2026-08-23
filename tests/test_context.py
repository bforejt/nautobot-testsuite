"""CollectorContext transport trace/caching and the shakedown advisory helper."""

import unittest

if __package__:
    from . import _loader
else:  # unittest discover -s tests imports test modules as top-level
    import _loader

context = _loader.context
registry = _loader.registry


class _FakeRestconf:
    def __init__(self):
        self.calls = []
        self.closed = False

    def get(self, path, **kwargs):
        self.calls.append(path)
        if path == "/boom":
            raise RuntimeError("bad path")
        if path == "/missing":
            return None
        return {"data": path}

    def close(self):
        self.closed = True


class _FakeSsh:
    def __init__(self):
        self.closed = False

    def run(self, command, **kwargs):
        if command == "boom":
            raise RuntimeError("bad command")
        return "out:" + command

    def close(self):
        self.closed = True


class TestContextTrace(unittest.TestCase):
    def _ctx(self, debug=False):
        return context.CollectorContext(
            "dev1", "iosxe", restconf=_FakeRestconf(), ssh=_FakeSsh(), debug=debug
        )

    def test_get_caches_and_traces(self):
        ctx = self._ctx()
        first = ctx.get("/a")
        second = ctx.get("/a")
        self.assertIs(first, second)
        self.assertEqual(ctx.restconf.calls, ["/a"])  # one backend call
        self.assertEqual([entry["outcome"] for entry in ctx.trace], ["ok", "cache-hit"])
        self.assertEqual(ctx.trace[0]["target"], "/a")
        self.assertIn("elapsed_ms", ctx.trace[0])
        # Non-debug trace stays light: no payload copies.
        self.assertNotIn("payload", ctx.trace[0])

    def test_debug_captures_payload_and_output(self):
        ctx = self._ctx(debug=True)
        ctx.get("/a")
        ctx.run_ssh("show x")
        self.assertEqual(ctx.trace[0]["payload"], {"data": "/a"})
        self.assertEqual(ctx.trace[1]["output"], "out:show x")
        self.assertEqual(ctx.trace[1]["chars"], len("out:show x"))

    def test_ok404_none_is_cached_and_traced_not_found(self):
        ctx = self._ctx()
        self.assertIsNone(ctx.get("/missing", ok_404=True))
        self.assertIsNone(ctx.get("/missing", ok_404=True))
        self.assertEqual(ctx.restconf.calls, ["/missing"])
        self.assertEqual(ctx.trace[0]["outcome"], "not-found")
        self.assertEqual(ctx.trace[0]["kwargs"], {"ok_404": True})

    def test_errors_are_traced_and_reraised(self):
        ctx = self._ctx()
        with self.assertRaises(RuntimeError):
            ctx.get("/boom")
        with self.assertRaises(RuntimeError):
            ctx.run_ssh("boom")
        self.assertEqual([entry["outcome"] for entry in ctx.trace], ["error", "error"])
        self.assertIn("bad path", ctx.trace[0]["error"])
        self.assertIn("bad command", ctx.trace[1]["error"])

    def test_missing_transports_raise(self):
        ctx = context.CollectorContext("dev1", "iosxe")
        with self.assertRaises(RuntimeError):
            ctx.get("/a")
        with self.assertRaises(RuntimeError):
            ctx.run_ssh("show x")
        self.assertFalse(ctx.has_ssh)

    def test_close_closes_both_transports(self):
        ctx = self._ctx()
        ctx.close()
        self.assertTrue(ctx.restconf.closed)
        self.assertTrue(ctx.ssh.closed)


class TestShakedownAdvice(unittest.TestCase):
    def test_ok(self):
        self.assertEqual(registry.shakedown_advice("ok", None, 12, True), "ok")

    def test_parsed_but_empty_points_at_leaf_names(self):
        advice = registry.shakedown_advice("ok", None, 0, True)
        self.assertIn("leaf/element names", advice)

    def test_not_present(self):
        advice = registry.shakedown_advice("not-present", "BGP not running", 0, False)
        self.assertIn("BGP not running", advice)

    def test_failed_after_fetch_vs_nothing_fetched(self):
        after = registry.shakedown_advice("failed", "KeyError: x", 0, True)
        self.assertIn("payload shape", after)
        nothing = registry.shakedown_advice("failed", "404", 0, False)
        self.assertIn("transport/path problem", nothing)


if __name__ == "__main__":
    unittest.main()
