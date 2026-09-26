"""CollectorContext transport trace/caching and the shakedown advisory helper."""

import logging
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


class _FakeApi:
    """Duck-typed api-slot client: canned answers, records calls, labels its trace."""

    transport_label = "fake-api"

    def __init__(self):
        self.calls = []
        self.closed = False

    def call(self, operation, **kwargs):
        self.calls.append((operation, kwargs))
        if operation == "Boom":
            raise RuntimeError("bad operation")
        if operation == "Nothing":
            return None
        return {"operation": operation, "kwargs": kwargs}

    def close(self):
        self.closed = True


class _FakeRedfish(_FakeRestconf):
    """A restconf-slot client that labels its own trace entries and offers a budget."""

    transport_label = "redfish"

    def __init__(self):
        super().__init__()
        self.budgets = []

    def budget(self, label, max_gets):
        self.budgets.append((label, max_gets))
        return _Budget()


class _Budget:
    entered = False

    def __enter__(self):
        self.entered = True
        return self

    def __exit__(self, *exc):
        return False


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

    def _api_ctx(self, debug=False):
        return context.CollectorContext("esx1", "vmware", api=_FakeApi(), debug=debug)

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

    def test_close_closes_every_transport(self):
        ctx = context.CollectorContext(
            "dev1", "vmware", restconf=_FakeRestconf(), ssh=_FakeSsh(), api=_FakeApi()
        )
        ctx.close()
        self.assertTrue(ctx.restconf.closed)
        self.assertTrue(ctx.ssh.closed)
        self.assertTrue(ctx.api.closed)

    def test_close_survives_a_transport_that_raises(self):
        class _Angry:
            def close(self):
                raise RuntimeError("no")

        ctx = context.CollectorContext(
            "dev1", "vmware", restconf=_Angry(), ssh=_FakeSsh(), api=_FakeApi()
        )
        ctx.close()  # must not raise
        self.assertTrue(ctx.ssh.closed)
        self.assertTrue(ctx.api.closed)

    def test_default_trace_label_is_restconf(self):
        # The original RestconfClient predates transport_label; the trace
        # must keep reading "restconf" for it.
        ctx = self._ctx()
        ctx.get("/a")
        self.assertEqual(ctx.trace[0]["transport"], "restconf")

    def test_duck_typed_get_client_labels_its_trace(self):
        ctx = context.CollectorContext("xcc1", "xcc", restconf=_FakeRedfish())
        ctx.get("/a")
        ctx.get("/a")
        self.assertEqual([e["transport"] for e in ctx.trace], ["redfish", "redfish"])
        self.assertEqual([e["outcome"] for e in ctx.trace], ["ok", "cache-hit"])

    def test_budget_delegates_to_a_transport_that_offers_one(self):
        ctx = context.CollectorContext("xcc1", "xcc", restconf=_FakeRedfish())
        with ctx.budget("xcc_inventory", 16) as budget:
            self.assertTrue(budget.entered)
        self.assertEqual(ctx.restconf.budgets, [("xcc_inventory", 16)])
        # ...and is a harmless null context everywhere else, so collectors
        # can declare a budget unconditionally.
        with self._ctx().budget("iosxe_arp", 3):
            pass
        with context.CollectorContext("dev1", "panos").budget("panos_arp", 3):
            pass


class TestContextCall(unittest.TestCase):
    def _ctx(self, debug=False):
        return context.CollectorContext("esx1", "vmware", api=_FakeApi(), debug=debug)

    def test_call_caches_and_traces_with_the_client_label(self):
        ctx = self._ctx()
        first = ctx.call("RetrievePropertiesEx", type="HostSystem", moids=["ha-host"])
        second = ctx.call("RetrievePropertiesEx", type="HostSystem", moids=["ha-host"])
        self.assertIs(first, second)
        self.assertEqual(len(ctx.api.calls), 1)
        self.assertEqual([e["outcome"] for e in ctx.trace], ["ok", "cache-hit"])
        self.assertEqual(ctx.trace[0]["transport"], "fake-api")
        self.assertEqual(ctx.trace[0]["target"], "RetrievePropertiesEx")
        self.assertEqual(ctx.trace[0]["kwargs"], {"type": "HostSystem", "moids": ["ha-host"]})
        self.assertIn("elapsed_ms", ctx.trace[0])
        self.assertNotIn("payload", ctx.trace[0])
        # The client receives the kwargs as given (lists stay lists).
        self.assertEqual(
            ctx.api.calls[0], ("RetrievePropertiesEx", {"type": "HostSystem", "moids": ["ha-host"]})
        )

    def test_list_and_dict_kwargs_are_cacheable(self):
        # Regression: a list-valued pathSet used to raise TypeError: unhashable
        # type on the cache-key build (first vmware collector hit it).
        ctx = self._ctx()
        kwargs = {
            "type": "HostSystem",
            "moids": ["ha-host"],
            "paths": ["config.network", "config.option"],
            "traverse": {"path": "vm", "type": "VirtualMachine", "paths": ["name"]},
            "tags": {"b", "a"},
        }
        ctx.call("RetrievePropertiesEx", **kwargs)
        # Same content in a different container/ordering is the same fetch.
        ctx.call(
            "RetrievePropertiesEx",
            paths=("config.network", "config.option"),
            moids=("ha-host",),
            type="HostSystem",
            traverse={"paths": ["name"], "type": "VirtualMachine", "path": "vm"},
            tags=frozenset({"a", "b"}),
        )
        self.assertEqual(len(ctx.api.calls), 1)
        self.assertEqual([e["outcome"] for e in ctx.trace], ["ok", "cache-hit"])
        # Different path ORDER is a different key: builders sort, but the
        # cache must never guess at equivalence the client did not declare.
        ctx.call(
            "RetrievePropertiesEx",
            type="HostSystem",
            moids=["ha-host"],
            paths=["config.option", "config.network"],
            traverse=kwargs["traverse"],
            tags={"a", "b"},
        )
        self.assertEqual(len(ctx.api.calls), 2)

    def test_canonical_kwargs_helper(self):
        self.assertEqual(
            context.canonical_kwargs({"b": [1, {"y": 2, "x": [3]}], "a": {"s", "r"}}),
            (("a", ("r", "s")), ("b", (1, (("x", (3,)), ("y", 2))))),
        )
        hash(context.canonical_kwargs({"paths": ["a", "b"], "opts": {"k": [1]}}))

    def test_none_answer_is_not_found_and_cached(self):
        ctx = self._ctx()
        self.assertIsNone(ctx.call("Nothing"))
        self.assertIsNone(ctx.call("Nothing"))
        self.assertEqual(len(ctx.api.calls), 1)
        self.assertEqual([e["outcome"] for e in ctx.trace], ["not-found", "cache-hit"])

    def test_errors_are_traced_and_reraised(self):
        ctx = self._ctx()
        with self.assertRaises(RuntimeError):
            ctx.call("Boom")
        self.assertEqual(ctx.trace[0]["outcome"], "error")
        self.assertIn("bad operation", ctx.trace[0]["error"])
        # An error is never cached: the next call reaches the client again.
        with self.assertRaises(RuntimeError):
            ctx.call("Boom")
        self.assertEqual(len(ctx.api.calls), 2)

    def test_debug_captures_payload(self):
        ctx = self._ctx(debug=True)
        ctx.call("QueryNetworkHint", network_system="networkSystem")
        self.assertEqual(ctx.trace[0]["payload"]["operation"], "QueryNetworkHint")

    def test_missing_api_raises_and_has_api(self):
        ctx = context.CollectorContext("dev1", "iosxe")
        self.assertFalse(ctx.has_api)
        with self.assertRaises(RuntimeError):
            ctx.call("RetrievePropertiesEx")
        self.assertTrue(self._ctx().has_api)

    def test_get_and_call_caches_do_not_collide(self):
        ctx = context.CollectorContext("dev1", "vmware", restconf=_FakeRestconf(), api=_FakeApi())
        ctx.get("/x")
        ctx.call("/x")
        self.assertEqual(len(ctx.restconf.calls), 1)
        self.assertEqual(len(ctx.api.calls), 1)
        self.assertEqual([e["outcome"] for e in ctx.trace], ["ok", "ok"])


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


class _RecordingSsh:
    """An SSH-slot client that answers one canned text and records each call's kwargs."""

    def __init__(self, output="enable secret 9 CANARYE1", error=None):
        self.output = output
        self.error = error
        self.calls = []

    def run(self, command, **kwargs):
        self.calls.append((command, kwargs))
        if self.error is not None:
            raise self.error
        return self.output

    def close(self):
        pass


def _mask(text):
    return text.replace("CANARYE1", "***")


class TestRunSshRedaction(unittest.TestCase):
    """The redact hook: config reads keep only a redacted copy in the debug trace."""

    def _ctx(self, ssh, debug=True):
        return context.CollectorContext("dev1", "iosxe", ssh=ssh, debug=debug)

    def test_trace_keeps_only_the_redacted_copy(self):
        ssh = _RecordingSsh()
        ctx = self._ctx(ssh)
        output = ctx.run_ssh("show running-config", redact=_mask, timeout=300)
        # The caller still receives the verbatim text: it redacts what it stores.
        self.assertEqual(output, "enable secret 9 CANARYE1")
        self.assertEqual(ctx.trace[0]["output"], "enable secret 9 ***")
        self.assertEqual(ctx.trace[0]["chars"], len(output))
        # The hook never reaches the transport; every other kwarg does.
        self.assertEqual(ssh.calls, [("show running-config", {"timeout": 300})])

    def test_without_debug_nothing_is_kept_or_redacted(self):
        seen = []

        def redact(text):
            seen.append(text)
            return text

        ctx = self._ctx(_RecordingSsh(), debug=False)
        ctx.run_ssh("show running-config", redact=redact)
        self.assertNotIn("output", ctx.trace[0])
        self.assertEqual(seen, [])

    def test_a_traced_error_is_redacted(self):
        ssh = _RecordingSsh(error=RuntimeError("died after: enable secret 9 CANARYE1"))
        ctx = self._ctx(ssh, debug=False)
        with self.assertRaises(RuntimeError):
            ctx.run_ssh("show running-config", redact=_mask)
        self.assertEqual(ctx.trace[0]["outcome"], "error")
        self.assertEqual(ctx.trace[0]["error"], "RuntimeError: died after: enable secret 9 ***")

    def test_a_failing_redactor_withholds_instead_of_leaking(self):
        def broken(text):
            raise ValueError("bad pattern")

        ctx = self._ctx(_RecordingSsh())
        output = ctx.run_ssh("show running-config", redact=broken)
        self.assertEqual(output, "enable secret 9 CANARYE1")
        self.assertNotIn("CANARYE1", ctx.trace[0]["output"])
        self.assertIn("withheld", ctx.trace[0]["output"])

    def test_the_abort_signal_escapes_the_redactor(self):
        class SoftTimeLimitExceeded(Exception):
            pass

        def aborting(text):
            raise SoftTimeLimitExceeded()

        ctx = self._ctx(_RecordingSsh())
        with self.assertRaises(SoftTimeLimitExceeded):
            ctx.run_ssh("show running-config", redact=aborting)

    def test_without_a_redactor_the_trace_is_verbatim(self):
        ctx = self._ctx(_RecordingSsh(output="Cisco IOS XE Software"))
        ctx.run_ssh("show version")
        self.assertEqual(ctx.trace[0]["output"], "Cisco IOS XE Software")


class _EchoingSsh(_RecordingSsh):
    """Logs each read the way netmiko does: DEBUG records carrying the channel data."""

    def run(self, command, **kwargs):
        logging.getLogger("netmiko").debug("read_channel: enable secret 9 CANARYE1")
        logging.getLogger("netmiko.base_connection").debug("Pattern found: # CANARYE1")
        logging.getLogger("netmiko").info("%s sent", command)
        return super().run(command, **kwargs)


class _Collected(logging.Handler):
    def __init__(self):
        super().__init__(logging.DEBUG)
        self.messages = []

    def emit(self, record):
        self.messages.append(record.getMessage())


class TestRunSshWithholdsTheChannelEcho(unittest.TestCase):
    """A worker at DEBUG never logs a redacted read's text through the SSH library."""

    def setUp(self):
        self.netmiko = logging.getLogger("netmiko")
        self.level = self.netmiko.level
        self.netmiko.setLevel(logging.DEBUG)
        self.collected = _Collected()
        self.netmiko.addHandler(self.collected)

    def tearDown(self):
        self.netmiko.removeHandler(self.collected)
        self.netmiko.setLevel(self.level)

    def test_a_redacted_read_holds_the_debug_echo_back(self):
        ctx = context.CollectorContext("dev1", "iosxe", ssh=_EchoingSsh())
        ctx.run_ssh("show running-config", redact=_mask)
        self.assertNotIn("CANARYE1", " ".join(self.collected.messages))
        self.assertIn("show running-config sent", self.collected.messages)  # INFO still flows
        self.assertEqual(self.netmiko.level, logging.DEBUG)  # restored afterwards

    def test_restored_when_the_read_fails(self):
        ssh = _EchoingSsh(error=RuntimeError("stream died"))
        ctx = context.CollectorContext("dev1", "iosxe", ssh=ssh)
        with self.assertRaises(RuntimeError):
            ctx.run_ssh("show running-config", redact=_mask)
        self.assertNotIn("CANARYE1", " ".join(self.collected.messages))
        self.assertEqual(self.netmiko.level, logging.DEBUG)

    def test_an_ordinary_read_is_left_alone(self):
        ctx = context.CollectorContext("dev1", "iosxe", ssh=_EchoingSsh())
        ctx.run_ssh("show version")
        self.assertIn("read_channel: enable secret 9 CANARYE1", self.collected.messages)


if __name__ == "__main__":
    unittest.main()
