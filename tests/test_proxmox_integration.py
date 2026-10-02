"""Platform scope, exact Linux reads and lossless evidence at attachment limits."""

import contextlib
import io
import json
import os
import random
import stat
import unittest
from types import SimpleNamespace
from unittest import mock
from urllib.parse import parse_qs, urlsplit

from . import _loader

bundle = _loader.load("bundle")
scope = _loader.load("scope")
lazy = _loader.load("proxmox_ssh")
sources = _loader.load("proxmox_sources")
visibility = _loader.load("checks_proxmox_visibility")
C = _loader.constants


class TestProxmoxScope(unittest.TestCase):
    def test_explicit_platform_and_legacy_fallback(self):
        for fields in (
            ("proxmox", "", ""),
            ("", "Proxmox VE", ""),
            ("", "", "proxmox-ve"),
            ("linux", "Proxmox VE", ""),
        ):
            self.assertEqual(scope.map_platform(*fields)[0], "proxmox")
        self.assertIsNone(scope.map_platform("linux")[0])
        self.assertIsNone(scope.map_platform("proxmox", "Cisco NXOS")[0])


class TestLazyLinuxCredentials(unittest.TestCase):
    def test_credentials_resolve_only_on_first_allowed_read(self):
        credentials = mock.Mock(return_value=("collector", "ssh-password"))
        runner = mock.Mock()
        factory = mock.Mock(return_value=runner)
        client = lazy.LazySsh(credentials, factory)
        client.close()
        credentials.assert_not_called()
        for command in C.PROXMOX_SSH_COMMANDS[:2]:
            client.run(command)
        credentials.assert_called_once_with()
        factory.assert_called_once_with("collector", "ssh-password")
        self.assertEqual(runner.run.call_count, 2)
        client.close()
        runner.close.assert_called_once_with()

    def test_refused_read_and_api_token_never_open_ssh(self):
        credentials = mock.Mock(return_value=("collector@pve!read", "token-value"))
        factory = mock.Mock()
        client = lazy.LazySsh(credentials, factory)
        with self.assertRaisesRegex(ValueError, "not allowlisted"):
            client.run("ip -j link show; reboot")
        credentials.assert_not_called()
        with self.assertRaisesRegex(ValueError, "separate Linux SSH credentials"):
            client.run(C.PROXMOX_SSH_COMMANDS[0])
        factory.assert_not_called()


class TestEvidenceParts(unittest.TestCase):
    def _parts(self):
        rng = random.Random(22)
        payload = {
            "rows": [{"extra": "".join(rng.choices("abcdef0123456789", k=500))} for _ in range(60)],
            "text": "\u00e9\U0001f4a1" * 1000,
        }
        records = bundle.artifact_parts("raw_node_CHG1.json", payload, 8192)
        part_bytes = {name: bundle.json_bytes(body) for name, body in records[:-1]}
        return payload, records, part_bytes

    def test_full_unicode_evidence_reassembles_and_every_part_fits(self):
        payload, records, parts = self._parts()
        self.assertGreater(len(records), 2)
        self.assertTrue(all(len(bundle.json_bytes(body)) < 8192 for _, body in records))
        self.assertEqual(bundle.reassemble(records[-1][1], parts), bundle.json_bytes(payload))
        self.assertEqual(json.loads(bundle.reassemble(records[-1][1], parts)), payload)

    def test_missing_or_corrupt_part_is_refused(self):
        _, records, parts = self._parts()
        name = next(iter(parts))
        missing = dict(parts)
        del missing[name]
        with self.assertRaisesRegex(ValueError, "missing artifact part"):
            bundle.reassemble(records[-1][1], missing)
        parts[name] += b" "
        with self.assertRaisesRegex(ValueError, "checksum mismatch"):
            bundle.reassemble(records[-1][1], parts)

    def test_small_artifact_keeps_original_contract(self):
        payload = {"rows": [1, 2, 3]}
        self.assertEqual(
            bundle.artifact_parts("raw_node.json", payload, 8192), [("raw_node.json", payload)]
        )


class TestNativeSourceQuery(unittest.TestCase):
    def _query(self, files, links=None, denied=(), missing=()):
        stdout = io.StringIO()
        opened = []
        directories = {"/"}
        for path in list(files) + list(denied):
            parent = path if path in denied else os.path.dirname(path)
            while parent != "/":
                directories.add(parent)
                parent = os.path.dirname(parent)

        def attributes(path, **kwargs):
            if path in missing:
                raise FileNotFoundError(path)
            if path in directories:
                return SimpleNamespace(st_mode=stat.S_IFDIR)
            if path in files:
                return SimpleNamespace(st_mode=stat.S_IFREG)
            raise FileNotFoundError(path)

        @contextlib.contextmanager
        def scan(path):
            if path in denied:
                raise PermissionError(path)
            if path not in directories:
                raise FileNotFoundError(path)
            children = {
                name.rsplit("/", 1)[-1]
                for name in set(files) | directories
                if name != path and os.path.dirname(name) == path
            }
            yield iter(SimpleNamespace(name=name) for name in sorted(children))

        def read(path, mode, **kwargs):
            self.assertEqual(mode, "r")
            opened.append(path)
            return io.StringIO(files[path])

        with (
            contextlib.redirect_stdout(stdout),
            mock.patch("builtins.open", side_effect=read),
            mock.patch("os.stat", side_effect=attributes),
            mock.patch("os.path.lexists", side_effect=lambda path: path in files),
            mock.patch("os.scandir", side_effect=scan),
            mock.patch(
                "os.path.realpath",
                side_effect=lambda path: (links or {}).get(path, os.path.normpath(path)),
            ),
        ):
            exec(compile(sources.CONFIG_SCRIPT, "<native configuration read>", "exec"), {})
        return json.loads(stdout.getvalue()), opened

    def test_included_native_configuration_is_preserved_as_one_complete_source(self):
        files = {
            "/etc/network/interfaces": "source interfaces.d/*\nauto vmbr0\n",
            "/etc/network/interfaces.d/uplink": "iface bond0 inet manual\n",
        }
        result, opened = self._query(files)
        self.assertEqual(result["errors"], [])
        self.assertEqual({row["path"]: row["content"] for row in result["files"]}, files)
        self.assertEqual(opened, list(files))

    def test_include_cannot_read_a_secret_or_escape_through_a_symlink(self):
        files = {
            "/etc/network/interfaces": "source interfaces.d/*\n",
            "/etc/network/interfaces.d/evil": "secret-canary",
        }
        result, opened = self._query(files, {"/etc/network/interfaces.d/evil": "/etc/shadow"})
        self.assertTrue(result["errors"])
        self.assertEqual(opened, ["/etc/network/interfaces"])
        self.assertNotIn("secret-canary", json.dumps(result))

    def test_missing_required_native_configuration_is_a_failure(self):
        result, opened = self._query({})
        self.assertIn("required network configuration is absent", result["errors"][0])
        self.assertEqual(opened, [])

    def test_denied_dropin_directory_and_matched_dangling_link_refuse(self):
        files = {"/etc/network/interfaces": "auto lo\n"}
        result, _ = self._query(files, denied=("/etc/chrony/conf.d",))
        self.assertIn("PermissionError", result["errors"][0])
        files["/etc/network/interfaces"] = "source interfaces.d/*\n"
        files["/etc/network/interfaces.d/broken"] = ""
        result, opened = self._query(files, missing=("/etc/network/interfaces.d/broken",))
        self.assertIn("dangling configuration source link", result["errors"][0])
        self.assertEqual(opened, ["/etc/network/interfaces"])

    def test_chrony_directives_are_case_insensitive_and_dhcp_sources_are_named(self):
        files = {
            "/etc/network/interfaces": "auto lo\n",
            "/etc/chrony/chrony.conf": (
                "InClUdE /etc/chrony/extra.conf\n"
                "CoNfDiR /etc/chrony/custom.d\n"
                "SoUrCeDiR /var/run/chrony-dhcp\n"
            ),
            "/etc/chrony/extra.conf": "server ntp.example.net\n",
            "/etc/chrony/custom.d/site.conf": "makestep 1 3\n",
            "/var/run/chrony-dhcp/eth0.sources": "server 192.0.2.1\n",
        }
        links = {
            "/var/run/chrony-dhcp/*.sources": "/run/chrony-dhcp/*.sources",
            "/var/run/chrony-dhcp/eth0.sources": "/run/chrony-dhcp/eth0.sources",
        }
        result, opened = self._query(files, links)
        self.assertEqual(result["errors"], [])
        self.assertEqual({row["path"]: row["content"] for row in result["files"]}, files)
        self.assertEqual(set(opened), set(files))
        self.assertTrue(
            any(
                row["matches"] == ["/var/run/chrony-dhcp/eth0.sources"]
                for row in result["includes"]
            )
        )

    def test_chrony_empty_source_directory_is_healthy_but_missing_include_is_not(self):
        files = {
            "/etc/network/interfaces": "auto lo\n",
            "/etc/chrony/chrony.conf": "sourcedir /run/chrony-dhcp\n",
        }
        result, _ = self._query(files)
        self.assertEqual(result["errors"], [])
        files["/etc/chrony/chrony.conf"] = "include /etc/chrony/missing.conf\n"
        result, _ = self._query(files)
        self.assertIn("required configuration include matched no files", result["errors"][0])
        self.assertEqual(len(result["files"]), 2)

    def test_all_documented_systemd_main_and_dropin_roots_are_preserved(self):
        files = {"/etc/network/interfaces": "auto lo\n"}
        for base in ("/etc/systemd", "/run/systemd", "/usr/local/lib/systemd", "/usr/lib/systemd"):
            for name in ("timesyncd.conf", "journald.conf"):
                files[base + "/" + name] = "# main " + base + "\n"
                files[base + "/" + name + ".d/50-site.conf"] = "# drop-in " + base + "\n"
        result, opened = self._query(files)
        self.assertEqual(result["errors"], [])
        self.assertEqual({row["path"]: row["content"] for row in result["files"]}, files)
        self.assertEqual(set(opened), set(files))

    def test_systemd_devnull_masks_retain_each_filename_without_opening_target(self):
        files = {
            "/etc/network/interfaces": "auto lo\n",
            "/etc/systemd/journald.conf": "",
            "/etc/systemd/journald.conf.d/50-vendor.conf": "",
            "/etc/systemd/timesyncd.conf.d/50-vendor.conf": "",
        }
        links = {path: "/dev/null" for path in files if path != "/etc/network/interfaces"}
        result, opened = self._query(files, links)
        self.assertEqual(result["errors"], [])
        self.assertEqual(opened, ["/etc/network/interfaces"])
        masks = {row["path"]: row for row in result["files"] if row.get("masked")}
        self.assertEqual(set(masks), set(links))
        for row in masks.values():
            self.assertEqual(row["content"], "")
            self.assertEqual(row["resolved_path"], "/dev/null")
        result, _ = self._query(
            {"/etc/network/interfaces": ""}, {"/etc/network/interfaces": "/dev/null"}
        )
        self.assertIn("outside approved roots", result["errors"][0])

    def test_active_include_cycle_refuses_but_completed_sources_deduplicate(self):
        files = {
            "/etc/network/interfaces": "source /etc/network/loop\n",
            "/etc/network/loop": "source /etc/network/interfaces\n",
        }
        result, opened = self._query(files)
        self.assertIn("include cycle detected", result["errors"][0])
        self.assertEqual(opened, list(files))
        self.assertEqual({row["path"]: row["content"] for row in result["files"]}, files)
        files["/etc/network/interfaces"] = "source /etc/network/loop /etc/network/loop\n"
        files["/etc/network/loop"] = "iface vmbr0 inet manual\n"
        result, opened = self._query(files)
        self.assertEqual(result["errors"], [])
        self.assertEqual(opened, list(files))

    def test_dpkg_machine_inventory_preserves_complete_array_and_package_states(self):
        records = [
            {
                "package": "libsample%d:amd64" % number,
                "version": "1:2.0-1",
                "architecture": "amd64",
                "status": "installed" if number % 2 else "config-files",
            }
            for number in range(601)
        ]
        stdout = io.StringIO()
        reply = mock.Mock(stdout="\n".join(json.dumps(row) for row in records) + "\n")
        with (
            contextlib.redirect_stdout(stdout),
            mock.patch("subprocess.run", return_value=reply) as run,
        ):
            exec(compile(sources.PACKAGES_SCRIPT, "<dpkg package read>", "exec"), {})
        self.assertEqual(json.loads(stdout.getvalue()), records)
        command = run.call_args.args[0]
        self.assertEqual(command[:2], ["dpkg-query", "--show"])
        self.assertIn("${binary:Package}", command[2])
        self.assertIn("${db:Status-Status}", command[2])
        self.assertTrue(run.call_args.kwargs["check"])


class TestAuthoritativeVisibility(unittest.TestCase):
    def _ctx(
        self,
        observed=(100,),
        audit=True,
        hidden_peer=False,
        hidden_pool=False,
        hidden_mapping=False,
        sdn_migration=False,
        hidden_sdn=False,
        hidden_node=False,
    ):
        def inventory(entries):
            return {
                "outcome": "complete",
                "source": "native fixture",
                "module": "PVE::Fixture",
                "config": {"ids": entries},
                "identities": sorted(entries),
                "entries": [
                    {"identity": identity, "config": config} for identity, config in entries.items()
                ],
            }

        inventories = {
            family: inventory({})
            for family in (
                "mapping_pci",
                "mapping_usb",
                "mapping_dir",
                "replication",
                "sdn_zones",
                "sdn_vnets",
                "sdn_controllers",
                "sdn_dns",
                "sdn_ipams",
                "sdn_subnets",
                "sdn_fabrics",
                "sdn_fabric_nodes",
                "sdn_prefix_lists",
                "sdn_route_maps",
            )
        }
        inventories.update(
            {
                "sdn_running": {"outcome": "complete", "families": {}},
                "sdn_pending": {"outcome": "complete", "families": {}},
            }
        )
        if hidden_mapping:
            inventories["mapping_pci"] = inventory(
                {"secret-device": {"map": "node=pve-lab,id=0000:01:00.0"}}
            )
        if sdn_migration:
            inventories["sdn_zones"] = inventory({"old-zone": {}, "new-zone": {}})
            inventories["sdn_vnets"] = inventory(
                {"vnet-a": {"zone": "old-zone", "pending": {"zone": "new-zone"}}}
            )
        authority = {
            "access": {
                "users": {"collector@pve": {"enable": 1, "email": "personal-canary"}},
                "pools": {"lab-pool": {"comment": "configured pool"}},
            },
            "guests": {
                "ids": {
                    "100": {"type": "qemu", "node": "pve-lab"},
                    "101": {"type": "qemu", "node": "pve-peer"},
                }
            },
            "storage": {"ids": {"local": {"type": "dir", "path": "/var/lib/vz"}}},
            "inventories": inventories,
            "nodes": ["pve-lab", "pve-peer"],
        }

        class Api:
            def get(self, path, **kwargs):
                query = parse_qs(urlsplit(path).query)
                resource = query.get("path", [""])[0]
                if resource.startswith("/mapping/"):
                    return {"data": {resource: {} if hidden_mapping else {"Mapping.Audit": 0}}}
                if resource.startswith("/sdn/"):
                    denied = hidden_sdn and resource == "/sdn/zones/new-zone/vnet-a"
                    return {"data": {resource: {} if denied else {"SDN.Audit": 0}}}
                answers = {
                    "/cluster/status": [
                        {"type": "node", "name": "pve-lab", "local": 1},
                        {"type": "node", "name": "pve-peer", "local": 0},
                    ],
                    "/nodes/pve-lab/qemu": [{"vmid": vmid} for vmid in observed],
                    "/nodes/pve-lab/lxc": [],
                    "/storage": [{"storage": "local", "type": "dir"}],
                    "/pools": [] if hidden_pool else [{"poolid": "lab-pool"}],
                    "/access/permissions?path=%2F": {"/": {"Sys.Audit": 1}},
                    "/access/permissions?path=%2Fvms%2F100": {"/vms/100": {"VM.Audit": 0}},
                    "/access/permissions?path=%2Fvms%2F101": {
                        "/vms/101": {} if hidden_peer else {"VM.Audit": 0}
                    },
                    "/access/permissions?path=%2Fstorage%2Flocal": {
                        "/storage/local": {"Datastore.Audit": 0}
                    },
                    "/access/permissions?path=%2Fpool%2Flab-pool": {
                        "/pool/lab-pool": {"Pool.Audit": 0}
                    },
                    "/access/permissions?path=%2Fnodes%2Fpve-lab": {
                        "/nodes/pve-lab": {"Sys.Audit": 0} if audit else {}
                    },
                    "/access/permissions?path=%2Fnodes%2Fpve-peer": {
                        "/nodes/pve-peer": {} if hidden_node else {"Sys.Audit": 0}
                    },
                }
                return {"data": answers[path]}

        class Ssh:
            def run(self, command, **kwargs):
                if command != C.PROXMOX_ACCESS_COMMAND:
                    raise AssertionError("unexpected SSH command")
                return json.dumps(authority)

        return _loader.context.CollectorContext(
            "pve-lab", "proxmox", restconf=Api(), ssh=Ssh(), debug=True
        )

    def test_authoritative_inventory_detects_filtered_successful_api_lists(self):
        ctx = self._ctx(observed=())
        with self.assertRaisesRegex(_loader.registry.CollectError, "filtered or changed"):
            visibility._collect_visibility(ctx)
        self.assertEqual(ctx._proxmox_capture.context["visibility_mismatch"]["missing"], ["100"])
        self.assertTrue(ctx._proxmox_capture.raw)

    def test_nonpropagating_audit_grant_is_still_granted(self):
        ctx = self._ctx()
        result = visibility._collect_visibility(ctx)
        self.assertTrue(result["normalized"]["scope"]["visibility_verified"])
        self.assertEqual(result["context"]["guests_total"], 1)
        self.assertNotIn("personal-canary", json.dumps(result))
        self.assertNotIn("personal-canary", json.dumps(ctx.trace))

    def test_missing_effective_selected_node_audit_is_refused(self):
        with self.assertRaisesRegex(_loader.registry.CollectError, "Sys.Audit"):
            visibility._collect_visibility(self._ctx(audit=False))

    def test_peer_guest_exclusion_and_filtered_pool_inventory_fail_visibility(self):
        with self.assertRaisesRegex(_loader.registry.CollectError, "Sys.Audit at /nodes/pve-peer"):
            visibility._collect_visibility(self._ctx(hidden_node=True))
        with self.assertRaisesRegex(_loader.registry.CollectError, "VM.Audit at /vms/101"):
            visibility._collect_visibility(self._ctx(hidden_peer=True))
        with self.assertRaisesRegex(_loader.registry.CollectError, "pool inventory is filtered"):
            visibility._collect_visibility(self._ctx(hidden_pool=True))

    def test_hidden_mapping_and_pending_vnet_zone_require_exact_audit_grants(self):
        with self.assertRaisesRegex(
            _loader.registry.CollectError, "Mapping.Audit at /mapping/pci/secret-device"
        ):
            visibility._collect_visibility(self._ctx(hidden_mapping=True))
        with self.assertRaisesRegex(
            _loader.registry.CollectError, "SDN.Audit at /sdn/zones/new-zone/vnet-a"
        ):
            visibility._collect_visibility(self._ctx(sdn_migration=True, hidden_sdn=True))
        ctx = self._ctx(sdn_migration=True)
        visibility._collect_visibility(ctx)
        targets = [row.get("target", "") for row in ctx.trace]
        self.assertTrue(any("path=%2Fsdn%2Fzones%2Fold-zone%2Fvnet-a" in path for path in targets))
        self.assertTrue(any("path=%2Fsdn%2Fzones%2Fnew-zone%2Fvnet-a" in path for path in targets))


if __name__ == "__main__":
    unittest.main()
