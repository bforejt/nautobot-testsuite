"""GET-only transport tested through fake requests; no third-party test dependency."""

import json
import sys
import types
import unittest
from unittest.mock import patch

if __package__:
    from . import _loader
else:
    import _loader


class RequestException(Exception):
    pass


class Response:
    def __init__(self, data=None, status=200, reason="", content=None):
        self.data, self.status_code, self.reason = data, status, reason
        self.content = (
            content
            if content is not None
            else b"invalid JSON"
            if isinstance(data, Exception)
            else json.dumps(data).encode("utf-8")
        )

    def json(self):
        if isinstance(self.data, Exception):
            raise self.data
        return self.data


class Session:
    def __init__(self):
        self.headers = {}
        self.calls = []
        self.responses = []
        self.closed = False

    def get(self, url, **kwargs):
        self.calls.append((url, kwargs))
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response

    def close(self):
        self.closed = True


requests = types.ModuleType("requests")
requests.Session = Session
requests.RequestException = RequestException
urllib3 = types.ModuleType("urllib3")
urllib3.disable_warnings = lambda warning: None
urllib3.exceptions = types.SimpleNamespace(InsecureRequestWarning=RuntimeWarning)
with patch.dict(sys.modules, {"requests": requests, "urllib3": urllib3}):
    transport = _loader.load("transport_proxmox")


class TestProxmoxTransport(unittest.TestCase):
    def setUp(self):
        self.client = transport.ProxmoxClient("203.0.113.20", "auditor@pve!monitor", "TOKEN-SECRET")

    def test_token_only_auth_envelope_and_redirect_refusal(self):
        self.client.session.responses.append(
            Response({"data": {"version": "9", "password": "NO-STORE"}, "total": 1})
        )
        out = self.client.get("/version")
        self.assertEqual(out["total"], 1)
        self.assertNotIn("NO-STORE", str(out))
        url, kwargs = self.client.session.calls[0]
        self.assertEqual(url, "https://203.0.113.20:8006/api2/json/version")
        self.assertFalse(kwargs["allow_redirects"])
        self.assertEqual(
            self.client.session.headers["Authorization"],
            "PVEAPIToken=auditor@pve!monitor=TOKEN-SECRET",
        )
        self.assertFalse(self.client.session.trust_env)
        self.assertFalse(hasattr(self.client, "post"))

    def test_fence_runs_before_request_and_budget(self):
        for path in (
            "https://other.invalid/version",
            "/nodes/pve-a/execute",
            "/version?token=TOKEN-SECRET",
        ):
            with self.assertRaises(transport.ProxmoxError) as raised:
                self.client.get(path)
            self.assertNotIn("TOKEN-SECRET", str(raised.exception))
        self.assertEqual(self.client.gets, 0)
        self.assertEqual(self.client.session.calls, [])

    def test_failure_bodies_headers_and_exception_echo_never_escape(self):
        for response in (
            Response({"message": "TOKEN-SECRET password=NO-STORE"}, 403),
            RequestException("TOKEN-SECRET URL?token=NO-STORE"),
            Response(ValueError("NO-STORE")),
            Response({}, 200),
            Response({"data": None}, 302),
        ):
            self.client.session.responses.append(response)
            with self.assertRaises(transport.ProxmoxError) as raised:
                self.client.get("/version")
            self.assertNotIn("TOKEN-SECRET", str(raised.exception))
            self.assertNotIn("NO-STORE", str(raised.exception))

    def test_only_optional404_is_tolerated(self):
        self.client.session.responses.append(Response({"message": "opaque"}, 404))
        self.assertIsNone(self.client.get("/cluster/sdn", ok_404=True))
        self.client.session.responses.append(Response({"message": "opaque"}, 403))
        with self.assertRaises(transport.ProxmoxError):
            self.client.get("/cluster/sdn", ok_404=True)

    def test_budget_refuses_before_request_and_restores_outer(self):
        self.client.session.responses.extend([Response({"data": {}}), Response({"data": {}})])
        with self.client.budget("one", 1):
            self.client.get("/version")
            with self.assertRaises(transport.ProxmoxError):
                self.client.get("/version")
        self.client.get("/version")
        self.assertEqual(self.client.gets, 2)

    def test_probe_is_safe_and_discovery_uses_observed_local_marker(self):
        self.client.session.responses.append(Response({"data": {"version": "9.1.1"}}))
        self.assertEqual(self.client.probe()["status"], 200)
        self.client.session.responses.extend(
            [
                Response({"data": {"version": "9.1.1"}}),
                Response({"data": [{"type": "node", "name": "pve-a", "local": 1}]}),
                Response({"data": {"/": {"Sys.Audit": 1}}}),
                Response({"data": [{"name": "qemu"}]}),
            ]
        )
        out = self.client.discovery()
        self.assertEqual(out["node"], "pve-a")
        self.assertIn("/access/permissions", out["sources"])
        self.assertIn("/nodes/pve-a/capabilities", out["sources"])
        self.assertNotIn("TOKEN-SECRET", str(out))

    def test_probe_raises_on_unusable_endpoint_and_ping_reports_false(self):
        for response in (
            RequestException("TOKEN-SECRET"),
            Response({"data": None}, 401),
            Response({"data": {"version": "arbitrary-service"}}),
            Response({"data": []}),
        ):
            self.client.session.responses.append(response)
            with self.assertRaises(transport.ProxmoxError):
                self.client.probe()
            self.assertIsNotNone(self.client.last_probe["error"])
            self.assertNotIn("TOKEN-SECRET", str(self.client.last_probe))
        self.client.session.responses.append(Response({"data": None}, 503))
        self.assertFalse(self.client.ping())
        self.client.session.responses.append(Response({"data": None}, 403))
        self.assertEqual(self.client.probe_get("/version")["status"], 403)

    def test_exact_ceph_absence_classified_without_error_text(self):
        self.client.session.responses.append(
            Response({"data": None}, 500, "binary not installed: /usr/bin/ceph-mon")
        )
        with self.assertRaises(transport.ProxmoxError) as raised:
            self.client.get("/nodes/pve-a/ceph/status")
        self.assertTrue(raised.exception.feature_absent)
        self.assertEqual(str(raised.exception), "Proxmox GET HTTP 500")
        self.client.session.responses.append(
            Response({"message": "other failure TOKEN-SECRET"}, 500)
        )
        with self.assertRaises(transport.ProxmoxError) as raised:
            self.client.get("/nodes/pve-a/ceph/status")
        self.assertFalse(raised.exception.feature_absent)

    def test_structured_journal_preserves_native_records_and_scrubs_messages(self):
        records = [
            {"ty": "cursor", "c": "s=native-cursor"},
            {"ty": "host", "h": "pve-a"},
            {"ty": "reboot", "t": 1700000000000000},
            {
                "t": 1700000000000000,
                "id": "pvedaemon",
                "p": 6,
                "pid": 12,
                "msg": "auditor@pve password=NO-STORE",
                "unknown": "complete",
            },
        ]
        self.client.session.responses.append(Response({"data": records, "success": 1}))
        out = self.client.get("/nodes/pve-a/journal?structured=1&since=1000&until=2000")
        self.assertEqual(out["source_format"], "proxmox-journal-json-envelope")
        self.assertEqual(len(out["data"]), len(records))
        self.assertEqual(out["data"][-1]["unknown"], "complete")
        self.assertNotIn("NO-STORE", str(out))
        self.assertNotIn("auditor@pve", str(out))

    def test_journal_fallback_requires_the_exact_unknown_schema_error(self):
        path = "/nodes/pve-a/journal?structured=1&since=1000&until=2000"
        error = (
            "property is not defined in schema and the schema does not allow additional properties"
        )
        self.client.session.responses.append(Response({"errors": {"structured": error}}, 400))
        with self.assertRaises(transport.ProxmoxError) as raised:
            self.client.get(path)
        self.assertTrue(raised.exception.feature_absent)
        self.assertEqual(raised.exception.kind, "structured-journal-unavailable")
        for response in (
            Response({"errors": {"since": error}}, 400),
            Response({"errors": {"structured": "unrelated TOKEN-SECRET"}}, 400),
            Response({"errors": {"structured": error}}, 403),
            Response({"errors": {"structured": error}}, 500),
            Response({"data": [{"msg": "partial"}], "success": 0, "error": "TOKEN-SECRET"}),
            Response({"data": ["pre-rendered lines"], "success": 1}),
            Response(ValueError("truncated TOKEN-SECRET")),
            Response(content=b'{"data":[{"msg":"\xff"}],"success":1}'),
        ):
            self.client.session.responses.append(response)
            with self.assertRaises(transport.ProxmoxError) as raised:
                self.client.get(path)
            self.assertFalse(raised.exception.feature_absent)
            self.assertNotIn("TOKEN-SECRET", str(raised.exception))

    def test_ipv6_and_credential_validation(self):
        client = transport.ProxmoxClient("2001:db8::1", "auditor@pve!monitor", "TOKEN-SECRET")
        self.assertIn("[2001:db8::1]:8006", client.base)
        for host, user, secret in (
            ("https://host", "a@pve!m", "s"),
            ("host", "root@pam", "s"),
            ("host", "a@pve!m", "s\n"),
        ):
            with self.assertRaises(transport.ProxmoxError):
                transport.ProxmoxClient(host, user, secret)

    def _task(self, actor="operator-canary@pve!personal-token", *, pid="000000A1"):
        native = "UPID:pve-a:%s:123456789:65FA0010:vzdump:100:%s:" % (pid, actor)
        row = {
            "upid": native,
            "node": "pve-a",
            "pid": int(pid, 16),
            "pstart": int("123456789", 16),
            "starttime": int("65FA0010", 16),
            "type": "vzdump",
            "id": "100",
            "user": actor.partition("!")[0],
            "tokenid": actor.partition("!")[2],
            "unknown": {"actor_hint": actor, "guest_reference": "100"},
        }
        return native, row

    def test_task_actor_is_removed_before_context_cache_trace_and_complete_raw(self):
        native, row = self._task()
        self.client.session.responses.append(Response({"data": [row], "total": 1}))
        ctx = _loader.context.CollectorContext("pve-a", "proxmox", restconf=self.client, debug=True)
        cap = _loader.load("proxmox_common").Capture(ctx)
        listed = cap.rows("/nodes/pve-a/tasks", params={"source": "active"})
        alias = listed[0]["upid"]
        self.assertEqual(alias, native.rsplit(":", 2)[0] + ":redacted@redacted:")
        self.assertEqual(listed[0]["id"], "100")
        self.assertEqual(listed[0]["unknown"]["guest_reference"], "100")
        self.client.session.responses.extend(
            [
                Response({"data": dict(row, status="stopped", exitstatus="TASK OK")}),
                Response(
                    {
                        "data": [
                            {
                                "n": 1,
                                "t": "operator-canary started " + native,
                                "unknown": "token actor " + row["user"],
                            },
                            {"n": 2, "t": "tail retained " + "x" * 25000},
                        ],
                        "total": 2,
                    }
                ),
            ]
        )
        status = cap.read("/nodes/pve-a/tasks/" + alias + "/status")
        lines = cap.rows("/nodes/pve-a/tasks/" + alias + "/log")
        self.assertEqual(status["upid"], alias)
        self.assertEqual(len(lines[-1]["t"]), len("tail retained ") + 25000)
        for payload in (listed, status, lines, ctx.trace, ctx._cache, cap.raw, cap.context):
            self.assertNotIn("operator-canary", str(payload))
            self.assertNotIn("personal-token", str(payload))
        self.assertIn(native + "/status", self.client.session.calls[1][0])
        self.assertIn(native + "/log", self.client.session.calls[2][0])
        self.assertIn(alias, str(cap.raw.keys()))
        self.assertEqual(self.client.footprint()["gets"], 3)
        self.client.close()
        with self.assertRaises(transport.ProxmoxError):
            self.client.get("/nodes/pve-a/tasks/" + alias + "/status")
        self.assertEqual(len(self.client.session.calls), 3)

    def test_only_observed_aliases_resolve_and_node_or_suffix_injection_is_refused(self):
        native, row = self._task()
        alias = native.rsplit(":", 2)[0] + ":redacted@redacted:"
        for path in (
            "/nodes/pve-a/tasks/" + alias + "/status",
            "/nodes/pve-a/tasks/" + native + "/status",
            "/nodes/pve-a/tasks/" + alias + "/stop",
            "/nodes/pve-a/tasks/" + alias + "/log?download=1",
        ):
            with self.assertRaises(transport.ProxmoxError) as caught:
                self.client.get(path)
            self.assertNotIn("canary", str(caught.exception))
        self.assertEqual(self.client.session.calls, [])
        self.assertEqual(self.client.gets, 0)
        self.client.session.responses.append(Response({"data": [row]}))
        self.client.get("/cluster/tasks")
        with self.assertRaises(transport.ProxmoxError):
            self.client.get("/nodes/pve-b/tasks/" + alias + "/status")
        self.assertEqual(len(self.client.session.calls), 1)

    def test_task_alias_collision_and_duplicate_list_refuse_atomically(self):
        native, row = self._task()
        _, other = self._task(actor="different-canary@pam")
        alias = native.rsplit(":", 2)[0] + ":redacted@redacted:"
        for rows in ([row, other], [row, row]):
            self.client.session.responses.append(Response({"data": rows}))
            with self.assertRaises(transport.ProxmoxError) as caught:
                self.client.get("/nodes/pve-a/tasks")
            self.assertNotIn("canary", str(caught.exception))
            with self.assertRaises(transport.ProxmoxError):
                self.client.get("/nodes/pve-a/tasks/" + alias + "/status")
        self.assertEqual(len(self.client.session.calls), 2)

    def test_task_status_cannot_substitute_an_unobserved_reference_and_errors_are_safe(self):
        native, row = self._task()
        self.client.session.responses.append(Response({"data": [row]}))
        alias = self.client.get("/nodes/pve-a/tasks")["data"][0]["upid"]
        other, other_row = self._task(pid="000000A2")
        self.client.session.responses.append(Response({"data": other_row}))
        with self.assertRaises(transport.ProxmoxError) as caught:
            self.client.get("/nodes/pve-a/tasks/" + alias + "/status")
        self.assertNotIn("canary", str(caught.exception))
        for response in (
            RequestException("failed URL " + native),
            Response({"message": "not found " + native}, 500),
            Response(ValueError("invalid body " + other)),
        ):
            self.client.session.responses.append(response)
            with self.assertRaises(transport.ProxmoxError) as caught:
                self.client.get("/nodes/pve-a/tasks/" + alias + "/log")
            self.assertNotIn("canary", str(caught.exception))

    def test_task_path_hook_masks_unobserved_or_malformed_refs_without_authorizing(self):
        native, _ = self._task()
        alias = native.rsplit(":", 2)[0] + ":redacted@redacted:"
        for value in (native, "UPID:malformed:operator-canary@pve:"):
            path = "/nodes/pve-a/tasks/" + value + "/status"
            label = self.client.public_path(path)
            self.assertNotIn("canary", label)
            with self.assertRaises(transport.ProxmoxError):
                self.client.get(path)
        self.assertEqual(
            self.client.public_path("/nodes/pve-a/tasks/" + alias + "/log"),
            "/nodes/pve-a/tasks/" + alias + "/log",
        )
        self.assertNotIn(
            "canary", self.client.public_path("/nodes/pve-a/tasks?userfilter=operator-canary%40pve")
        )
        self.assertNotIn(
            "canary", self.client.public_path("/nodes/pve-a/tasks?unexpected=operator-canary%40pve")
        )
        self.assertNotIn(
            "canary", str(self.client.probe_get("/nodes/pve-a/tasks/" + native + "/status"))
        )
        self.assertNotIn("canary", str(self.client.last_probe))
        self.assertEqual(self.client.session.calls, [])

    def test_refused_native_task_label_cannot_enter_context_trace_or_raw_source_labels(self):
        native, _ = self._task()
        ctx = _loader.context.CollectorContext("pve-a", "proxmox", restconf=self.client, debug=True)
        cap = _loader.load("proxmox_common").Capture(ctx)
        for reference in (native, "UPID:malformed:operator-canary@pve:"):
            with self.assertRaises((_loader.registry.CollectError, transport.ProxmoxError)):
                cap.read("/nodes/pve-a/tasks/" + reference + "/status")
        self.assertNotIn("canary", str(ctx.trace))
        self.assertNotIn("canary", str(cap.context))
        self.assertNotIn("canary", str(cap.raw))
        self.assertEqual(ctx._cache, {})

    def test_task_aliases_preserve_distinct_headers_and_placeholder_actor_idempotence(self):
        native, row = self._task(actor="redacted@redacted")
        _, other = self._task(pid="000000A2")
        self.client.session.responses.append(Response({"data": [row, other], "total": 2}))
        result = self.client.get("/nodes/pve-a/tasks")
        self.assertEqual(result["data"][0]["upid"], native)
        self.assertNotEqual(result["data"][0]["upid"], result["data"][1]["upid"])
        self.assertEqual(_loader.load("proxmox_common").scrub(result), result)


if __name__ == "__main__":
    unittest.main()
