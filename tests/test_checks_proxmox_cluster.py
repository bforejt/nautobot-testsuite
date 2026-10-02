"""Exact cluster families, ordered policy, complete paging and timezone coverage."""

import copy
import json
import unittest
from datetime import datetime, timezone
from unittest import mock
from urllib.parse import parse_qs, urlsplit

from . import _loader
from .test_checks_proxmox_guests import FakeContext, fixture

checks = _loader.load("checks_proxmox_cluster")
C = _loader.constants
CollectError = _loader.registry.CollectError


def native_wrapper(configs=None, *, absent=False):
    if absent:
        return {
            "outcome": "not-present",
            "module": "PVE::Review::Fixture",
            "source": "fixture.cfg",
            "unavailable_reason": "module-not-installed",
        }
    configs = configs or {}
    return {
        "outcome": "complete",
        "module": "PVE::Review::Fixture",
        "source": "fixture.cfg",
        "config": {"ids": copy.deepcopy(configs)},
        "identities": sorted(configs),
        "entries": [
            {"identity": identity, "config": copy.deepcopy(configs[identity])}
            for identity in sorted(configs)
        ],
    }


def native_sources(data, **inventories):
    data["SSH " + C.PROXMOX_ACCESS_COMMAND] = {"inventories": inventories}
    return data


def sdn_sources(data, configured=None, running=None, pending=None):
    configured, running, pending = configured or {}, running or {}, pending or {}
    keys = {
        "zones": "sdn_zones",
        "controllers": "sdn_controllers",
        "vnets": "sdn_vnets",
        "subnets": "sdn_subnets",
        "dns": "sdn_dns",
        "ipams": "sdn_ipams",
        "fabrics": "sdn_fabrics",
        "nodes": "sdn_fabric_nodes",
        "prefix-lists": "sdn_prefix_lists",
        "route-maps": "sdn_route_maps",
    }
    inventories = {
        source: native_wrapper(configured.get(family)) for family, source in keys.items()
    }
    for state, config in (("running", running), ("pending", pending)):
        inventories["sdn_" + state] = {
            "outcome": "complete",
            "config": {},
            "families": {family: native_wrapper(rows) for family, rows in config.items()},
        }
    return native_sources(data, **inventories)


class PagingContext(FakeContext):
    def get(self, path, **kwargs):
        split = urlsplit(path)
        query = parse_qs(split.query)
        if "start" in query:
            self.calls.append(path)
            source = self.sources[split.path]
            if callable(source):
                return source(query)
            start, size = int(query["start"][0]), int(query["limit"][0])
            return {"data": copy.deepcopy(source[start : start + size]), "total": len(source)}
        return super().get(path, **kwargs)


class ClusterCapture(unittest.TestCase):
    def test_cluster_topology_preserves_unknown_raw_fields_without_detailed_remote_reads(self):
        data = fixture()
        data.update(
            {
                "/cluster/resources": [
                    {
                        "id": "qemu/101",
                        "node": "pve-other",
                        "mem": 500,
                        "future": "raw-and-normalized",
                    }
                ],
                "/cluster/config/nodes": [{"node": "pve-lab", "ring0_addr": "192.0.2.10"}],
                "/cluster/config/totem": {"cluster_name": "lab", "future-setting": 9},
                "/cluster/config/qdevice": {"model": "net"},
            }
        )
        ctx = FakeContext(data)
        result = checks._collect_cluster(ctx)
        self.assertEqual(
            result["normalized"]["corosync"]["nodes"]["pve-lab"]["ring0_addr"], "192.0.2.10"
        )
        self.assertEqual(result["raw"]["/cluster/resources"]["data"][0]["mem"], 500)
        self.assertNotIn("mem", result["normalized"]["resources"]["qemu/101"])
        self.assertFalse(any("/nodes/pve-other/" in path for path in ctx.calls))

    def test_pools_preserve_members_and_empty_pool(self):
        data = {
            "/pools": [{"poolid": "empty"}, {"poolid": "all"}],
            "/pools?poolid=empty": [{"poolid": "empty", "members": [], "comment": "empty valid"}],
            "/pools?poolid=all": [
                {
                    "poolid": "all",
                    "members": [
                        {"id": "qemu/101", "vmid": 101},
                        {"id": "storage/shared", "storage": "shared"},
                    ],
                    "future-option": 1,
                }
            ],
        }
        data["SSH " + C.PROXMOX_ACCESS_COMMAND] = {
            "access": {
                "pools": {
                    "empty": {"vms": {}, "storage": {}},
                    "all": {"vms": {"101": 1}, "storage": {"shared": 1}},
                }
            }
        }
        result = checks._collect_pools(FakeContext(data))
        self.assertEqual(result["normalized"]["empty"]["members"], {})
        self.assertEqual(len(result["normalized"]["all"]["members"]), 2)

    def test_nested_pool_and_stale_members_are_complete_while_usage_remains_raw(self):
        data = {
            "/pools": [{"poolid": "parent/secret-child"}],
            "/pools?poolid=parent%2Fsecret-child": [
                {
                    "poolid": "parent/secret-child",
                    "members": [{"id": "qemu/101", "vmid": 101, "cpu": 0.9, "unknown_runtime": 7}],
                }
            ],
            "SSH " + C.PROXMOX_ACCESS_COMMAND: {
                "access": {
                    "pools": {
                        "parent/secret-child": {
                            "vms": {"101": 1, "999": 1},
                            "storage": {},
                            "comment": "kept",
                        }
                    }
                }
            },
        }
        ctx = FakeContext(data)
        result = checks._collect_pools(ctx)
        self.assertEqual(result["normalized"]["parent/secret-child"]["config"]["vms"]["999"], 1)
        self.assertNotIn("cpu", result["normalized"]["parent/secret-child"]["members"]["qemu/101"])
        self.assertEqual(
            result["raw"]["/pools?poolid=parent%2Fsecret-child"]["data"][0]["members"][0][
                "unknown_runtime"
            ],
            7,
        )
        self.assertFalse(any(path.startswith("/pools/") for path in ctx.calls))
        data["/pools"] = []
        with self.assertRaisesRegex(CollectError, "filtered"):
            checks._collect_pools(FakeContext(data))

    def test_resource_mappings_read_each_full_detail_without_a_row_cap(self):
        mappings = [{"id": "pci%04d" % i} for i in range(700)]
        data = {
            "/cluster/mapping/pci": mappings,
            "/cluster/mapping/usb": [],
            "/cluster/mapping/dir": [],
        }
        for row in mappings:
            data["/cluster/mapping/pci/" + row["id"]] = {
                "map": ["node=pve-lab,path=0000:03:00.0"],
                "future": "kept",
            }
        native_sources(
            data,
            mapping_pci=native_wrapper({row["id"]: {"future": "kept"} for row in mappings}),
            mapping_usb=native_wrapper(),
            mapping_dir=native_wrapper(),
        )
        result = checks._collect_mappings(FakeContext(data))
        self.assertEqual(len(result["normalized"]), 700)
        self.assertEqual(result["normalized"]["pci|pci0699"]["api"]["future"], "kept")
        self.assertEqual(result["normalized"]["pci|pci0699"]["config"]["future"], "kept")

    def test_security_policy_keeps_rule_order_all_scopes_and_set_members(self):
        data = fixture()
        data["/nodes/pve-lab/qemu"] = []
        data["/nodes/pve-lab/lxc"] = []
        for base in ("/cluster/firewall", "/nodes/pve-lab/firewall"):
            data[base + "/options"] = {"enable": 0, "policy_in": "DROP"}
            data[base + "/rules"] = [
                {"pos": 2, "action": "DROP"},
                {"pos": 0, "action": "ACCEPT", "source": "+trusted"},
            ]
        data.update(
            {
                "/cluster/firewall/aliases": [{"name": "router", "cidr": "192.0.2.1"}],
                "/cluster/firewall/ipset": [{"name": "trusted"}],
                "/cluster/firewall/ipset/trusted": [{"cidr": "192.0.2.0/24", "nomatch": 0}],
                "/cluster/firewall/groups": [{"group": "secure"}],
                "/cluster/firewall/groups/secure": [{"pos": 0, "action": "DROP"}],
            }
        )
        result = checks._collect_firewall(FakeContext(data))
        self.assertEqual(
            [row["action"] for row in result["normalized"]["cluster"]["rules"]], ["ACCEPT", "DROP"]
        )
        self.assertEqual(
            result["normalized"]["cluster"]["ipsets"]["trusted"]["members"]["192.0.2.0/24"][
                "nomatch"
            ],
            0,
        )
        self.assertEqual(result["normalized"]["cluster"]["options"]["enable"], 0)

    def test_duplicate_policy_position_refuses_instead_of_overwriting(self):
        data = {"/rules": [{"pos": 0, "action": "DROP"}, {"pos": 0, "action": "ACCEPT"}]}
        with self.assertRaises(CollectError):
            checks._ordered_rules(checks.Capture(FakeContext(data)), "/rules")

    def test_access_keeps_token_metadata_and_scrubs_tfa_credentials(self):
        data = {
            "/access/users?full=1": [{"userid": "svc@pve"}],
            "/access/users/svc@pve": {
                "enable": 1,
                "keys": "canary-tfa-material",
                "firstname": "canary-person",
                "future": 9,
            },
            "/access/users/svc@pve/token": [{"tokenid": "capture", "privsep": 1}],
            "/access/users/svc@pve/token/capture": {"privsep": 1, "expire": 0},
            "/access/groups": [{"groupid": "audit"}],
            "/access/groups/audit": {"users": ["svc@pve"]},
            "/access/roles": [{"roleid": "Audit"}],
            "/access/roles/Audit": {"privs": "Sys.Audit,VM.Audit"},
            "/access/domains": [{"realm": "pve"}],
            "/access/domains/pve": {"type": "pve"},
            "/access/acl": [
                {"path": "/", "ugid": "svc@pve", "type": "user", "roleid": "Audit", "propagate": 1}
            ],
            "/access/permissions": {"/": {"Sys.Audit": 1}},
        }
        data["SSH " + C.PROXMOX_ACCESS_COMMAND] = {
            "access": {
                "users": {
                    "svc@pve": {
                        "enable": 1,
                        "keys": "canary-tfa-material",
                        "firstname": "canary-person",
                        "tokens": {"capture": {"privsep": 1, "expire": 0}},
                    }
                },
                "acl": {"/": {"users": {"svc@pve": {"Audit": 1}}}},
                "future-policy": 9,
            }
        }
        ctx = FakeContext(data)
        result = checks._collect_access(ctx)
        self.assertFalse(any("/token" in path or path == "/access/acl" for path in ctx.calls))
        self.assertEqual(result["normalized"]["acl"]["/"]["users"]["svc@pve"]["Audit"], 1)
        self.assertEqual(result["normalized"]["future-policy"], 9)
        self.assertEqual(
            result["normalized"]["users"]["svc@pve"]["tokens"]["capture"]["privsep"], 1
        )
        self.assertIn("svc@pve", result["normalized"]["users"])
        self.assertNotIn("canary-person", json.dumps(result))
        self.assertNotIn("canary-tfa-material", json.dumps(result))

    def test_notification_configuration_reads_all_endpoint_types_without_test_actions(self):
        data = {}
        for family in ("sendmail", "gotify", "smtp", "webhook"):
            base = "/cluster/notifications/endpoints/" + family
            data[base] = [{"name": family}]
            data[base + "/" + family] = {
                "name": family,
                "password": "canary-password",
                "future": {"kept": 1},
            }
        data["/cluster/notifications/matchers"] = [{"name": "all"}]
        data["/cluster/notifications/matchers/all"] = {
            "target": "smtp",
            "match-field": "severity=error",
        }
        data["/cluster/notifications/targets"] = [{"name": "smtp"}]
        ctx = FakeContext(data)
        result = checks._collect_notifications(ctx)
        self.assertEqual(len(result["normalized"]), 5)
        self.assertNotIn("canary-password", json.dumps(result))
        self.assertFalse(any("test" in path for path in ctx.calls))

    def test_unsupported_new_feature_is_explained_but_denial_is_failed(self):
        data = native_sources(
            {}, **{"mapping_" + kind: native_wrapper(absent=True) for kind in ("pci", "usb", "dir")}
        )
        ctx = FakeContext(data)
        with self.assertRaises(_loader.registry.SkipCheck):
            checks._collect_mappings(ctx)
        self.assertEqual(len(ctx._proxmox_capture.context["unsupported"]), 3)
        data["/cluster/mapping/pci"] = CollectError("HTTP 403")
        with self.assertRaises(CollectError):
            checks._collect_mappings(FakeContext(data))

    def test_filtered_mapping_api_refuses_and_native_config_survives_api_absence(self):
        data = native_sources(
            {"/cluster/mapping/pci": []},
            mapping_pci=native_wrapper({"pci-secret": {"unknown-option": 8}}),
            mapping_usb=native_wrapper(),
            mapping_dir=native_wrapper(),
        )
        ctx = FakeContext(data)
        with self.assertRaisesRegex(CollectError, "filtered"):
            checks._collect_mappings(ctx)
        self.assertIn("SSH " + C.PROXMOX_ACCESS_COMMAND, ctx._proxmox_capture.raw)
        del data["/cluster/mapping/pci"]
        result = checks._collect_mappings(FakeContext(data))
        self.assertEqual(result["normalized"]["pci|pci-secret"]["config"]["unknown-option"], 8)

    def test_services_keep_failed_and_inactive_units(self):
        data = fixture()
        data["/nodes/pve-lab/services"] = [
            {"service": "pveproxy", "state": "running"},
            {"service": "pve-ha-lrm", "state": "failed"},
        ]
        for unit in ("pveproxy", "pve-ha-lrm"):
            data["/nodes/pve-lab/services/%s/state" % unit] = {
                "state": "running" if unit == "pveproxy" else "failed"
            }
        result = checks._collect_services(FakeContext(data))
        self.assertEqual(result["normalized"]["pve-ha-lrm"]["observed_state"]["state"], "failed")

    def test_ceph_precise_absence_leaves_explicit_source_outcome(self):
        ctx = FakeContext(fixture())
        with self.assertRaises(_loader.registry.SkipCheck):
            checks._collect_ceph(ctx)
        self.assertIn("/nodes/pve-lab/ceph/status", ctx._proxmox_capture.context["unsupported"])

    def test_initialized_ceph_keeps_health_topology_full_config_and_unknown_raw_metrics(self):
        data = fixture()
        base = "/nodes/pve-lab/ceph"
        data[base + "/status"] = {
            "health": {
                "status": "HEALTH_WARN",
                "checks": {"OSD_DOWN": {"severity": "HEALTH_WARN", "summary": {"count": 1}}},
            },
            "future_usage": 123,
        }
        data[base + "/osd"] = {
            "root": {
                "id": -1,
                "type": "root",
                "children": [
                    {"id": 0, "name": "osd.0", "type": "osd", "status": "up", "in": 1, "usage": 99}
                ],
            }
        }
        for family in ("mds", "mgr", "mon", "fs", "rules", "cfg/db"):
            data[base + "/" + family] = []
        data["SSH ceph osd crush dump --format json"] = {
            "devices": [{"id": 0, "name": "osd.0", "class": "ssd"}],
            "buckets": [{"id": -1, "name": "default", "items": [{"id": 0, "weight": 65536}]}],
            "rules": [{"rule_id": 0, "steps": [{"op": "take", "item": -1}]}],
            "tunables": {"choose_local_tries": 0},
            "future_crush_option": {"unknown": "kept"},
        }
        data[base + "/pool"] = [{"pool_name": "volumes", "bytes_used": 99}]
        data[base + "/pool/volumes"] = {"size": 3, "min_size": 2, "future": 1}
        data[base + "/pool/volumes/status?verbose=1"] = {"bytes_used": 99}
        data[base + "/osd/0/metadata"] = {"ceph_version": "19.2", "rotational": "0"}
        data[base + "/cfg/raw"] = "[global]\nfsid = lab\n[client.admin]\nkey = canary-ceph-key\n"
        data["/cluster/ceph/status"] = {"health": {"status": "HEALTH_WARN"}}
        data["/cluster/ceph/metadata"] = {"osd": {"0": {"version": "19.2"}}}
        data["/cluster/ceph/flags"] = [{"name": "noout", "value": 0}]
        data["/cluster/ceph/health-mute"] = []
        ctx = FakeContext(data)
        result = checks._collect_ceph(ctx)
        self.assertEqual(result["normalized"]["crush"]["future_crush_option"], {"unknown": "kept"})
        self.assertNotIn(base + "/crush", ctx.calls)
        self.assertEqual(result["normalized"]["health"]["status"], "HEALTH_WARN")
        self.assertEqual(result["normalized"]["osd|0"]["status"], "up")
        self.assertEqual(result["raw"][base + "/status"]["data"]["future_usage"], 123)
        self.assertNotIn("canary-ceph-key", json.dumps(result))
        self.assertEqual(result["context"]["unstructured_reads"][0]["class"], "justified")

    def test_sdn_native_all_states_subnets_and_firewall_avoid_write_privilege_details(self):
        configured = {
            "zones": {"zone1": {"type": "vlan", "bridge": "vmbr0", "future": 7}},
            "controllers": {"ctl1": {"type": "bgp", "asn": 64512}},
            "vnets": {"vnetlab": {"tag": 200, "zone": "zone1", "future": "kept"}},
            "subnets": {"zone1-192.0.2.0-24": {"vnet": "vnetlab", "gateway": "192.0.2.1"}},
            "dns": {"dns1": {"type": "powerdns", "url": "https://dns.invalid", "secret": "canary"}},
            "ipams": {"pve": {"type": "pve"}},
        }
        running = {
            "zones": configured["zones"],
            "controllers": configured["controllers"],
            "vnets": {
                "vnetlab": {"tag": 100, "zone": "zone1"},
                "oldvnet": {"tag": 10, "zone": "zone1"},
            },
            "subnets": configured["subnets"],
        }
        pending = {
            "zones": configured["zones"],
            "controllers": configured["controllers"],
            "vnets": {
                "vnetlab": {
                    "tag": 100,
                    "zone": "zone1",
                    "pending": {"tag": 200},
                    "state": "changed",
                },
                "oldvnet": {"tag": 10, "zone": "zone1", "state": "deleted"},
            },
            "subnets": configured["subnets"],
        }
        data = sdn_sources({}, configured, running, pending)
        for state, native in (
            ("configured", configured),
            ("running", running),
            ("pending", pending),
        ):
            suffix = "" if state == "configured" else "?%s=1" % state
            for family, field in (
                ("zones", "zone"),
                ("controllers", "controller"),
                ("vnets", "vnet"),
            ):
                data["/cluster/sdn/" + family + suffix] = [
                    {field: identity} for identity in native[family]
                ]
            data["/cluster/sdn/vnets/vnetlab/subnets" + suffix] = [{"subnet": "zone1-192.0.2.0-24"}]
        data["/cluster/sdn/dns"] = [{"dns": "dns1"}]
        data["/cluster/sdn/ipams"] = [{"ipam": "pve"}]
        data["/cluster/sdn/ipams/pve/status"] = {"state": "ok"}
        for name in ("vnetlab", "oldvnet"):
            data["/cluster/sdn/vnets/%s/firewall/options" % name] = {"enable": 1}
            data["/cluster/sdn/vnets/%s/firewall/rules" % name] = [{"pos": 0, "action": "DROP"}]
        ctx = FakeContext(data)
        result = checks._collect_sdn(ctx)
        self.assertIn("vnet-firewall|oldvnet", result["normalized"])
        self.assertEqual(result["normalized"]["vnets|configured|vnetlab"]["tag"], 200)
        self.assertEqual(result["normalized"]["vnets|running|vnetlab"]["tag"], 100)
        self.assertEqual(result["normalized"]["vnets|pending|vnetlab"]["pending"]["tag"], 200)
        self.assertEqual(result["normalized"]["vnets|pending|oldvnet"]["state"], "deleted")
        self.assertEqual(result["normalized"]["zones|configured|zone1"]["future"], 7)
        self.assertNotIn("canary", json.dumps(result))
        self.assertFalse(
            any(
                "/zones/zone1" in path or "/controllers/ctl1" in path or "/dns/dns1" in path
                for path in ctx.calls
            )
        )
        self.assertFalse(any("/oldvnet/subnets" in path for path in ctx.calls))
        data["/cluster/sdn/vnets"] = []
        with self.assertRaisesRegex(CollectError, "filtered"):
            checks._collect_sdn(FakeContext(data))

    def test_sdn_newer_native_models_preserve_all_fabric_nodes_prefix_and_route_entries(self):
        rows = {
            "fabrics": {"fab1": {"id": "fab1", "protocol": "openfabric"}},
            "nodes": {"pve-lab": {"node_id": "pve-lab", "fabric_id": "fab1", "future": 7}},
            "prefix-lists": {
                "secret-prefix": {
                    "id": "secret-prefix",
                    "entries": [{"order": 10, "prefix": "192.0.2.0/24"}],
                }
            },
            "route-maps": {
                "map1:20": {"route-map-id": "map1", "order": 20, "action": "permit", "unknown": 8}
            },
        }
        data = sdn_sources({}, rows, rows, rows)
        for state in ("configured", "running", "pending"):
            suffix = "" if state == "configured" else "?%s=1" % state
            data["/cluster/sdn/fabrics/all" + suffix] = {
                "fabrics": list(rows["fabrics"].values()),
                "nodes": list(rows["nodes"].values()),
            }
            data["/cluster/sdn/prefix-lists" + suffix] = [{"id": "secret-prefix"}]
            data["/cluster/sdn/route-maps/entries" + suffix] = list(rows["route-maps"].values())
        result = checks._collect_sdn(FakeContext(data))
        self.assertEqual(result["normalized"]["fabric-nodes|configured|pve-lab"]["future"], 7)
        self.assertEqual(
            result["normalized"]["prefix-lists|pending|secret-prefix"]["entries"][0]["order"], 10
        )
        self.assertEqual(result["normalized"]["route-maps|running|map1:20"]["unknown"], 8)
        data["/cluster/sdn/fabrics/all"]["nodes"] = []
        with self.assertRaisesRegex(CollectError, "filtered"):
            checks._collect_sdn(FakeContext(data))

    def test_tasks_exhaust_pages_and_logs_with_a_fixed_window(self):
        data = fixture()
        taskbase = "/nodes/pve-lab/tasks"

        def tasks(query):
            rows = (
                []
                if query["source"] == ["active"]
                else [
                    {
                        "upid": "UPID:pve-lab:%08X:00000001:00000001:vzdump:101:capture@pve:" % i,
                        "type": "backup",
                        "status": "OK",
                    }
                    for i in range(5)
                ]
            )
            start, size = int(query["start"][0]), int(query["limit"][0])
            return {"data": rows[start : start + size], "total": len(rows)}

        data[taskbase] = tasks
        for i in range(5):
            taskid = "UPID:pve-lab:%08X:00000001:00000001:vzdump:101:capture@pve:" % i
            data[taskbase + "/" + taskid + "/status"] = {"status": "stopped", "exitstatus": "OK"}
            data[taskbase + "/" + taskid + "/log"] = [
                {"n": j, "t": "line %s secret=canary-token" % j} for j in range(7)
            ]
        ctx = PagingContext(data)
        with mock.patch.object(C, "PROXMOX_PAGE_SIZE", 2):
            result = checks._collect_tasks(ctx)
        self.assertEqual(result["context"]["tasks"], 5)
        self.assertFalse(result["normalized"])
        self.assertTrue(any("start=4" in path for path in ctx.calls))
        self.assertNotIn("canary-token", json.dumps(result))
        self.assertTrue(result["context"]["unstructured_reads"])

    def test_replication_reads_every_local_status_and_entire_retained_log(self):
        data = fixture()
        data["/cluster/replication"] = [{"id": "101-0"}]
        data["/cluster/replication/101-0"] = {
            "target": "pve-other",
            "schedule": "*/15",
            "disable": 0,
        }
        data["/nodes/pve-lab/replication"] = [{"id": "101-0", "last_sync": 1700000000}]
        data["/nodes/pve-lab/replication/101-0/status"] = {"last_sync": 1700000000, "fail_count": 0}
        data["/nodes/pve-lab/replication/101-0/log"] = [
            {"n": i, "t": "sync line %s" % i} for i in range(9)
        ]
        native_sources(
            data,
            replication=native_wrapper(
                {"101-0": {"guest": 101, "target": "pve-other", "future": 9}}
            ),
        )
        with mock.patch.object(C, "PROXMOX_PAGE_SIZE", 2):
            result = checks._collect_replication(PagingContext(data))
        self.assertEqual(result["normalized"]["101-0"]["api"]["target"], "pve-other")
        self.assertEqual(result["normalized"]["101-0"]["config"]["future"], 9)
        self.assertEqual(result["context"]["local_jobs"], 1)
        log_paths = [path for path in result["raw"] if "/log?" in path]
        self.assertEqual(len(log_paths), 5)
        self.assertTrue(result["context"]["unstructured_reads"])

    def test_filtered_replication_config_list_fails_even_if_http_read_succeeds(self):
        data = native_sources(
            {"/cluster/replication": []},
            replication=native_wrapper({"999-0": {"guest": 999, "target": "pve-other"}}),
        )
        with self.assertRaisesRegex(CollectError, "filtered"):
            checks._collect_replication(FakeContext(data))
        data = native_sources(
            fixture(), replication=native_wrapper({"999-0": {"guest": 999, "target": "pve-other"}})
        )
        result = checks._collect_replication(FakeContext(data))
        self.assertEqual(result["normalized"]["999-0"]["config"]["guest"], 999)
        self.assertIn("/cluster/replication", result["context"]["unsupported"])

    def test_backup_defaults_and_jobs_preserve_full_options_without_extract_write_privileges(self):
        data = fixture()
        data["/cluster/backup"] = [{"id": "daily"}]
        data["/cluster/backup/daily"] = {
            "schedule": "daily",
            "prune-backups": "keep-last=3",
            "future-setting": 8,
        }
        data["/cluster/backup/daily/included_volumes"] = [
            {"vmid": 101, "volumes": ["local:vm-101-disk-0"]}
        ]
        data["/cluster/backup-info/not-backed-up"] = []
        data["/nodes/pve-lab/vzdump/defaults"] = {"mode": "snapshot", "compress": "zstd"}
        ctx = FakeContext(data)
        result = checks._collect_backup(ctx)
        self.assertEqual(result["normalized"]["daily"]["config"]["future-setting"], 8)
        self.assertEqual(result["normalized"]["node_defaults"]["compress"], "zstd")
        self.assertFalse(any("extractconfig" in path for path in ctx.calls))
        self.assertIn("archive_configuration_gap", result["context"])
        self.assertEqual(len(result["context"]["data_gaps"]), 1)
        self.assertIn("VM.Backup", result["context"]["data_gaps"][0]["reason"])

    def test_bounded_syslog_uses_node_timezone_and_dst_expansion(self):
        data = fixture()
        data["/nodes/pve-lab/qemu"] = []
        data["/nodes/pve-lab/lxc"] = []
        data["/nodes/pve-lab/time"] = {"timezone": "America/New_York"}
        data["/nodes/pve-lab/syslog"] = [{"n": 1, "t": "native event"}]
        data["/nodes/pve-lab/firewall/log"] = []
        until = datetime(2026, 11, 1, 12, tzinfo=timezone.utc)
        since = datetime(2026, 10, 31, 12, tzinfo=timezone.utc)
        ctx = PagingContext(data)
        with mock.patch.object(checks, "_window", return_value=(until, since)):
            result = checks._collect_logs(ctx)
        window = result["context"]["syslog_window"]
        self.assertEqual(window["timezone"], "America/New_York")
        self.assertEqual(window["dst_margin_seconds"], 3600)
        self.assertEqual(window["local_since"], "2026-10-31 07:00:00")
        self.assertTrue(any("since=" in path for path in ctx.calls if "/syslog?" in path))
        self.assertTrue(any("/journal?" in path for path in ctx.calls))

    def test_structured_journal_preserves_all_records_unknown_fields_without_syslog_fallback(self):
        data = fixture()
        data["/nodes/pve-lab/qemu"] = []
        data["/nodes/pve-lab/lxc"] = []
        until = datetime(2026, 10, 2, 12, tzinfo=timezone.utc)
        since = datetime(2026, 10, 1, 12, tzinfo=timezone.utc)
        path = "/nodes/pve-lab/journal?since=%s&structured=1&until=%s" % (
            int(since.timestamp()),
            int(until.timestamp()),
        )
        data[path] = {
            "data": [
                {"ty": "cursor", "c": "cursor-id"},
                {
                    "t": 1700000000000000,
                    "id": "pvedaemon",
                    "msg": "fault password=canary-token",
                    "p": 3,
                    "future": {"preserved": True},
                },
            ],
            "success": 1,
        }
        data["/nodes/pve-lab/firewall/log"] = []
        ctx = PagingContext(data)
        with mock.patch.object(checks, "_window", return_value=(until, since)):
            result = checks._collect_logs(ctx)
        self.assertEqual(result["context"]["journal"]["records"], 2)
        self.assertEqual(result["raw"][path]["data"][1]["future"], {"preserved": True})
        self.assertNotIn("canary-token", json.dumps(result))
        self.assertFalse(any("/syslog" in call or "/time" in call for call in ctx.calls))
        self.assertEqual(len(result["context"]["unstructured_reads"]), 1)

    def test_missing_timezone_fails_without_an_unbounded_syslog_read(self):
        data = fixture()
        data["/nodes/pve-lab/time"] = {}
        ctx = FakeContext(data)
        with self.assertRaises(CollectError):
            checks._collect_logs(ctx)
        self.assertFalse(any("/syslog" in path for path in ctx.calls))


if __name__ == "__main__":
    unittest.main()
