"""Complete envelopes, strict identity/shape checks and pre-cache secret redaction."""

import unittest
from unittest.mock import patch

if __package__:
    from . import _loader
else:
    import _loader

common = _loader.load("proxmox_common")


class Context:
    def __init__(self, responses):
        self.responses = responses
        self.calls = []

    def get(self, path, **kwargs):
        self.calls.append((path, kwargs))
        response = self.responses[path]
        return kwargs["redact"](response)


class TestProxmoxCapture(unittest.TestCase):
    def test_native_envelope_attrs_and_unknown_fields_are_preserved(self):
        ctx = Context(
            {
                "/nodes/pve-a/network": {
                    "data": [{"iface": "vmbr0", "new": 1}],
                    "changes": "pending evidence",
                }
            }
        )
        cap = common.Capture(ctx)
        self.assertEqual(cap.rows("/nodes/pve-a/network"), [{"iface": "vmbr0", "new": 1}])
        self.assertEqual(cap.raw["/nodes/pve-a/network"]["changes"], "pending evidence")
        self.assertIs(ctx._proxmox_capture, cap)
        self.assertEqual(cap.result({"x": 1})["normalized"], {"x": 1})

    def test_queries_have_exact_sorted_encoded_raw_keys(self):
        path = "/nodes/pve-a/tasks?limit=500&source=all&start=0"
        cap = common.Capture(Context({path: {"data": [], "total": 0}}))
        cap.rows("/nodes/pve-a/tasks", params={"start": 0, "limit": 500, "source": "all"})
        self.assertIn(path, cap.raw)

    def test_node_requires_one_local_marker_and_never_uses_device_name(self):
        for data in (
            [],
            [{"type": "node", "name": "pve-a"}],
            [
                {"type": "node", "name": "pve-a", "local": 1},
                {"type": "node", "name": "pve-b", "local": 1},
            ],
        ):
            with self.assertRaises(common.CollectError):
                common.Capture(Context({"/cluster/status": {"data": data}})).node()
        cap = common.Capture(
            Context({"/cluster/status": {"data": [{"type": "node", "name": "pve-a", "local": 1}]}})
        )
        self.assertEqual(cap.node(), "pve-a")
        self.assertIn("/cluster/status", cap.raw)

    def test_invalid_rows_and_non_envelopes_refuse(self):
        for answer in ({}, {"data": {}}, {"data": ["text"]}, {"data": None}):
            with self.assertRaises(common.CollectError):
                common.Capture(Context({"/nodes": answer})).rows("/nodes")

    def test_optional_absence_is_explicit(self):
        cap = common.Capture(Context({"/cluster/sdn": None}))
        self.assertIsNone(cap.rows("/cluster/sdn", optional=True))
        self.assertEqual(cap.context["unsupported"], ["/cluster/sdn"])

    def test_budget_refuses_before_request_but_allows_cache_hits(self):
        ctx = Context({"/version": {"data": {"version": "9.1.1"}}, "/nodes": {"data": []}})
        ctx._cache = {}
        cap = common.Capture(ctx)
        with patch.object(common.C, "PROXMOX_MAX_CHECK_BUDGET", 1):
            cap.read("/version")
            ctx._cache[("proxmox", "/version", (("ok_404", False),))] = ctx.responses["/version"]
            cap.read("/version")
            with self.assertRaises(common.CollectError):
                cap.rows("/nodes")
        self.assertEqual([path for path, _ in ctx.calls], ["/version", "/version"])
        self.assertEqual(cap.context["sources"]["/nodes"]["reason"], "budget-exhausted")

    def test_effective_zero_privilege_is_a_nonpropagating_grant(self):
        cap = common.Capture(
            Context(
                {
                    "/cluster/status": {"data": [{"type": "node", "name": "pve-a", "local": 1}]},
                    "/access/permissions?path=%2Fvms%2F100": {
                        "data": {"/vms/100": {"VM.Audit": 0}}
                    },
                }
            )
        )
        self.assertEqual(cap.visibility({"/vms/100": ("VM.Audit",)}), {"/vms/100": {"VM.Audit": 0}})

    def test_verified_feature_absence_keeps_the_specific_source_reason(self):
        class Absent(Exception):
            feature_absent = True
            kind = "structured-journal-unavailable"
            status_code = 400

        ctx = Context({})
        ctx.get = lambda *args, **kwargs: (_ for _ in ()).throw(Absent())
        cap = common.Capture(ctx)
        path = "/nodes/pve-a/journal"
        query = {"structured": 1, "since": 1000, "until": 2000}
        self.assertIsNone(cap.rows(path, params=query, optional=True))
        request = common.request_path(path, query)
        self.assertEqual(cap.raw[request]["feature_absent"], "structured-journal-unavailable")
        self.assertEqual(
            cap.context["sources"][request]["unavailable_reason"], "structured-journal-unavailable"
        )

    def test_paging_exhausts_source_and_keeps_every_envelope(self):
        cap = common.Capture(
            Context(
                {
                    "/nodes/pve-a/tasks?limit=2&start=0": {
                        "data": [{"id": 1}, {"id": 2}],
                        "total": 3,
                    },
                    "/nodes/pve-a/tasks?limit=2&start=2": {"data": [{"id": 3}], "total": 3},
                }
            )
        )
        with patch.object(common.C, "PROXMOX_PAGE_SIZE", 2):
            self.assertEqual(len(cap.paged("/nodes/pve-a/tasks")), 3)
        self.assertEqual(len(cap.raw), 2)

    def test_repeated_or_changing_pages_refuse(self):
        for second in (
            {"data": [{"id": 1}], "total": 2},
            {"data": [{"id": 2}], "total": 3},
            {"data": [], "total": 2},
        ):
            cap = common.Capture(
                Context(
                    {
                        "/nodes/pve-a/tasks?limit=1&start=0": {"data": [{"id": 1}], "total": 2},
                        "/nodes/pve-a/tasks?limit=1&start=1": second,
                    }
                )
            )
            with (
                patch.object(common.C, "PROXMOX_PAGE_SIZE", 1),
                self.assertRaises(common.CollectError),
            ):
                cap.paged("/nodes/pve-a/tasks")


class TestProxmoxHelpers(unittest.TestCase):
    def test_credentials_personal_fields_and_text_masked_before_return(self):
        payload = {
            "data": {
                "userid": "auditor@pve",
                "tokenid": "monitor",
                "email": "person@example.invalid",
                "password": "supersecret",
                "firstname": "Example",
                "password-policy": 8,
                "content": "password=hidden\noperator auditor@pve https://example.invalid/path?signature=hidden",
            }
        }
        out = common.scrub(payload)
        self.assertEqual(out["data"]["userid"], "auditor@pve")
        self.assertEqual(out["data"]["tokenid"], "monitor")
        self.assertEqual(out["data"]["password-policy"], 8)
        self.assertNotIn("supersecret", str(out))
        self.assertNotIn("person@example.invalid", str(out))
        self.assertNotIn("signature=hidden", str(out))
        self.assertNotIn("auditor@pve", out["data"]["content"])
        self.assertEqual(common.scrub(out), out)
        self.assertEqual(payload["data"]["password"], "supersecret")

    def test_pending_options_and_multiline_keys_masked(self):
        out = common.scrub({"data": [{"key": "cipassword", "value": "secret", "pending": "next"}]})
        self.assertEqual(out["data"][0]["key"], "cipassword")
        self.assertEqual(out["data"][0]["value"], common.SCRUBBED)
        self.assertNotIn(
            "private-content",
            common.scrub_text(
                "-----BEGIN PRIVATE KEY-----\nprivate-content\n-----END PRIVATE KEY-----"
            ),
        )
        self.assertIn("withheld", common.scrub_text("password: |\n  opaque-secret"))
        with self.assertRaises(TypeError):
            common.scrub({"unsafe": object()})

    def test_native_credentials_and_unknown_large_values_are_complete(self):
        payload = {
            "boot_cmdline": (
                "root=/dev/sda iscsi_password=ISCSI-SECRET "
                "rd.iscsi.username=LOGIN --password ARG-SECRET"
            ),
            "data": "[client]\nkey = CEPH-KEY\nkeyring = /etc/pve/keyring",
            "content": "password: |\n  OPAQUE-SECRET",
            "unknown": "x" * 300000,
        }
        out = common.scrub(payload)
        for secret in ("ISCSI-SECRET", "LOGIN", "ARG-SECRET", "CEPH-KEY", "OPAQUE-SECRET"):
            self.assertNotIn(secret, str(out))
        self.assertIn("root=/dev/sda", out["boot_cmdline"])
        self.assertIn("keyring = /etc/pve/keyring", out["data"])
        self.assertEqual(out["unknown"], payload["unknown"])
        self.assertEqual(common.scrub(out), out)

    def test_pending_setting_names_and_native_acl_accounts_survive(self):
        out = common.scrub(
            {
                "pending": [{"key": "memory", "pending": 2048}],
                "acl": {"secretuser@pve": {"roles": {"PVEAuditor": 0}}},
            }
        )
        self.assertEqual(out["pending"][0]["key"], "memory")
        self.assertIn("secretuser@pve", out["acl"])
        out = common.scrub(
            {
                "users": {
                    "secretuser@pve": {
                        "tokens": {
                            "secret-monitor": {
                                "expire": 0,
                                "comment": "API audit",
                                "password": "NESTED-PASSWORD",
                                "secret": {"opaque": "NESTED-SECRET"},
                            }
                        },
                        "roles": {"SecretAuditor": 0},
                        "password": 12345,
                    }
                },
                "groups": {"secret-group": {"users": {"secretuser@pve": 1}}},
                "acl_root": {
                    "groups": {"secret-group": {"SecretAuditor": 1}},
                    "tokens": {"secretuser@pve!secret-monitor": {"SecretAuditor": 0}},
                    "children": {
                        "secret-storage": {
                            "users": {"secretuser@pve": {"SecretAuditor": 0}},
                            "password": "ACL-NESTED-SECRET",
                        }
                    },
                },
            }
        )
        user = out["users"]["secretuser@pve"]
        self.assertEqual(user["tokens"]["secret-monitor"]["expire"], 0)
        self.assertEqual(user["roles"]["SecretAuditor"], 0)
        self.assertEqual(user["password"], common.SCRUBBED)
        self.assertEqual(out["groups"]["secret-group"]["users"]["secretuser@pve"], 1)
        self.assertEqual(out["acl_root"]["groups"]["secret-group"]["SecretAuditor"], 1)
        self.assertEqual(
            out["acl_root"]["tokens"]["secretuser@pve!secret-monitor"]["SecretAuditor"], 0
        )
        self.assertNotIn("NESTED-PASSWORD", str(out))
        self.assertNotIn("NESTED-SECRET", str(out))
        self.assertEqual(
            out["acl_root"]["children"]["secret-storage"]["users"]["secretuser@pve"][
                "SecretAuditor"
            ],
            0,
        )
        self.assertNotIn("ACL-NESTED-SECRET", str(out))
        with self.assertRaises(TypeError):
            common.scrub({"tokens": {"secret-monitor": "RAW-TOKEN-SECRET"}})
        self.assertEqual(
            common.scrub({"users": {"x@pve": {"password": 1}}})["users"]["x@pve"]["password"],
            common.SCRUBBED,
        )

    def test_numeric_credentials_contacts_and_partial_key_material_are_withheld(self):
        payload = {
            "password": 12345,
            "token": 12345,
            "key": False,
            "password_min_length": 12,
            "password_expire": False,
            "mailto": "person@example.invalid",
            "from-address": "person@example.invalid",
            "opaque": "-----BEGIN PRIVATE KEY-----\nUNFINISHED-KEY",
        }
        out = common.scrub(payload)
        self.assertEqual(out["password"], common.SCRUBBED)
        self.assertEqual(out["token"], common.SCRUBBED)
        self.assertEqual(out["key"], common.SCRUBBED)
        self.assertEqual(out["password_min_length"], 12)
        self.assertIs(out["password_expire"], False)
        self.assertNotIn("person@example.invalid", str(out))
        self.assertNotIn("UNFINISHED-KEY", str(out))

    def test_generated_cloudinit_dump_masks_all_authorized_key_formats_and_comments(self):
        path = "/nodes/pve-a/qemu/100/cloudinit/dump?type=user"
        native = (
            "#cloud-config\nhostname: guest100\nuser: configured-login\n"
            "password: GENERATED-SECRET\nssh_authorized_keys:\n"
            "  - sk-ssh-ed25519@openssh.com SK-KEY personal-key-comment\n"
            "  - ssh-dss DSS-KEY personal-comment\n"
            "  - ssh-rsa-cert-v01@openssh.com CERT-KEY certificate-comment\n"
            "chpasswd:\n  expire: False\npackage_upgrade: true\n"
        )
        ctx = Context({path: {"data": native}})
        cap = common.Capture(ctx)
        out = cap.read("/nodes/pve-a/qemu/100/cloudinit/dump", params={"type": "user"})
        self.assertIn("hostname: guest100", out)
        self.assertIn("user: configured-login", out)
        self.assertIn("chpasswd:\n  expire: False", out)
        for secret in (
            "GENERATED-SECRET",
            "SK-KEY",
            "DSS-KEY",
            "CERT-KEY",
            "personal-key-comment",
            "personal-comment",
            "certificate-comment",
        ):
            self.assertNotIn(secret, str(cap.raw))
        self.assertEqual(common.scrub(out), out)

    def test_native_storage_and_pool_ids_preserve_only_typed_policy_metadata(self):
        payload = {
            "storage": {
                "ids": {"secret-pbs": {"type": "pbs", "password": "STORAGE-SECRET", "new": 1}}
            },
            "access": {
                "pools": {
                    "secret-pool/subpool": {
                        "storage": {"secret-pbs": 1},
                        "vms": {"100": 1},
                        "new": 1,
                        "password": "POOL-SECRET",
                    }
                }
            },
        }
        out = common.scrub(payload)
        self.assertEqual(out["storage"]["ids"]["secret-pbs"]["type"], "pbs")
        pool = out["access"]["pools"]["secret-pool/subpool"]
        self.assertEqual(pool["storage"], {"secret-pbs": 1})
        self.assertEqual(pool["vms"], {"100": 1})
        self.assertEqual(pool["new"], 1)
        self.assertNotIn("STORAGE-SECRET", str(out))
        self.assertNotIn("POOL-SECRET", str(out))
        self.assertEqual(common.scrub(out), out)
        with self.assertRaises(TypeError):
            common.scrub({"storage": {"ids": {"secret-pbs": "RAW-SECRET"}}})
        with self.assertRaises(TypeError):
            common.scrub(
                {"access": {"pools": {"secret-pool": {"storage": {"secret-pbs": "RAW-SECRET"}}}}}
            )

    def test_native_properties_and_stable_objects_keep_unknown_fields(self):
        self.assertEqual(
            common.property_string("local:vm-100-disk-0,size=16G,new-key=a=b"),
            {"value": "local:vm-100-disk-0", "size": "16G", "new-key": "a=b"},
        )
        self.assertEqual(common.property_string("1"), {"value": "1"})
        with self.assertRaises(common.CollectError):
            common.property_string("a=1,a=2")
        self.assertEqual(
            common.stable({"known": 1, "new": 2, "cpu": 0.4}, omit=("cpu",)), {"known": 1, "new": 2}
        )

    def test_keyed_refuses_absent_or_duplicate_identifiers(self):
        self.assertEqual(
            common.keyed([{"id": 100, "new": True}], "id", prefix="vm:"),
            {"vm:100": {"id": 100, "new": True}},
        )
        for rows in ([{}], [{"id": "a"}, {"id": "a"}], [{"id": None}]):
            with self.assertRaises(common.CollectError):
                common.keyed(rows, "id")


if __name__ == "__main__":
    unittest.main()
