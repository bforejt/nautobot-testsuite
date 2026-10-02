"""Proxmox host capture: completeness, source gaps, joins and trace hygiene."""

import copy
import json
import unittest

from . import _loader

checks = _loader.load("checks_proxmox")
paths = _loader.load("proxmox_paths")
C = _loader.constants
CollectError = _loader.registry.CollectError


class Api:
    transport_label = "proxmox"

    def __init__(self, data):
        self.data = data
        self.calls = []

    def get(self, path, **_kwargs):
        path = paths.fence_path(path)
        self.calls.append(path)
        if path not in self.data:
            raise RuntimeError("required fixture endpoint missing: " + path)
        value = self.data[path]
        if isinstance(value, Exception):
            raise value
        return copy.deepcopy(value)


class Ssh:
    def __init__(self, data):
        self.data = data
        self.calls = []

    def run(self, command):
        if command not in C.PROXMOX_SSH_COMMANDS:
            raise RuntimeError("collector command is outside the read-only fence")
        self.calls.append(command)
        value = self.data[command]
        return value if isinstance(value, str) else json.dumps(value)


def envelope(data, **attrs):
    return {"data": data, **attrs}


def fixture():
    api = {
        "/cluster/status": envelope([{"type": "node", "local": 1, "name": "pve-a"}]),
        "/nodes/pve-a/version": envelope({"version": "9.0.3", "release": "9.0", "repoid": "test"}),
        "/nodes/pve-a/status": envelope(
            {
                "cpuinfo": {"cpus": 8},
                "memory": {"total": 8192, "used": 12},
                "cpu": 0.5,
                "uptime": 100,
                "new-feature": {"enabled": True},
            }
        ),
        "/nodes/pve-a/hardware/pci?pci-class-blacklist=&verbose=1": envelope(
            [{"id": "0000:01:00.0", "iommugroup": 7, "future-device-field": "retained"}]
        ),
        "/nodes/pve-a/network": envelope(
            [
                {
                    "iface": "vmbr0",
                    "type": "bridge",
                    "bridge_ports": "eno1",
                    "bridge_vlan_aware": 1,
                    "future-option": "complete",
                }
            ],
            changes="- mtu 1500\n+ mtu 9000",
        ),
        "/nodes/pve-a/time": envelope({"time": 100, "localtime": 100, "timezone": "UTC"}),
        "/nodes/pve-a/config": envelope({"acme": "domains=pve.example", "future": {"x": 1}}),
        "/cluster/options": envelope(
            {"migration": "type=secure", "future": {"large": "z" * 25000}}
        ),
        "/nodes/pve-a/dns": envelope({"dns1": "192.0.2.53", "search": "example.test"}),
        "/storage": envelope([{"storage": "local", "unknown": True}, {"storage": "remote-only"}]),
        "/storage/local": envelope(
            {"storage": "local", "type": "dir", "path": "/var/lib/vz", "unknown-config": {"x": 1}}
        ),
        "/storage/remote-only": envelope(
            {"storage": "remote-only", "type": "dir", "nodes": "pve-b"}
        ),
        "/nodes/pve-a/storage": envelope([{"storage": "local", "enabled": 1, "active": 1}]),
        "/nodes/pve-a/storage/local/status": envelope(
            {"type": "dir", "enabled": 1, "active": 1, "total": 100000, "used": 100, "avail": 99900}
        ),
        "/nodes/pve-a/storage/local/content": envelope(
            [
                {
                    "volid": "local:100/vm-100-disk-0.raw",
                    "vmid": 100,
                    "size": 1000,
                    "format": "raw",
                    "future-volume": "kept",
                }
            ]
        ),
        "/nodes/pve-a/storage/local/content/local%3A100%2Fvm-100-disk-0.raw": envelope(
            {
                "path": "/var/lib/vz/images/100/vm-100-disk-0.raw",
                "size": 1000,
                "format": "raw",
                "notes": "Complete note\nwith a second line",
                "protected": True,
                "future-attribute": {"all": True},
            }
        ),
        "/nodes/pve-a/subscription": envelope(
            {
                "status": "active",
                "key": "PRIVATE-SUBSCRIPTION-KEY",
                "signature": "PRIVATE-SIGNATURE",
                "checktime": 99,
                "level": "s",
            }
        ),
        "/nodes/pve-a/certificates/info": envelope(
            [
                {
                    "filename": "pve-ssl.pem",
                    "subject": "CN=pve.example",
                    "pem": (
                        "-----BEGIN CERTIFICATE-----\nPRIVATE-CERT-BODY\n-----END CERTIFICATE-----"
                    ),
                    "public-key-bits": 2048,
                    "public-key-type": "rsaEncryption",
                }
            ]
        ),
        "/nodes/pve-a/rrddata?cf=AVERAGE&timeframe=day": envelope([{"time": 100, "cpu": 0.5}]),
        "/nodes/pve-a/storage/local/rrddata?cf=AVERAGE&timeframe=day": envelope(
            [{"time": 100, "used": 100}]
        ),
    }
    ssh = {
        C.PROXMOX_HARDWARE_COMMAND: {
            "pci": [
                {
                    "id": "0000:01:00.0",
                    "driver": "/sys/bus/pci/drivers/ixgbe",
                    "sriov_numvfs": "2",
                    "sriov_totalvfs": "64",
                    "iommu_group": "/sys/kernel/iommu_groups/7",
                }
            ],
            "iommu_groups": [{"id": "7", "devices": ["0000:01:00.0"]}],
            "net": [{"name": "eno1", "speed": "10000", "duplex": "full"}],
            "cpu": {"online": "0-7", "isolated": "2-7", "nohz_full": "2-7"},
            "hugepages": [
                {"node": "node0", "size_kb": "2048", "nr_hugepages": "256", "free_hugepages": "12"}
            ],
            "numa": [{"id": "node0", "cpulist": "0-7", "distance": "10"}],
            "sysctl": {"vm.nr_hugepages": "256"},
            "kvm": {"/sys/module/kvm/parameters/ignore_msrs": "N"},
            "boot_cmdline": "quiet intel_iommu=on isolcpus=2-7",
            "errors": [],
            "unavailable": [],
        },
        checks._HARDWARE: {
            "id": "pve-a",
            "class": "system",
            "serial": "LAB-SERIAL",
            "children": [
                {
                    "id": "network:0",
                    "class": "network",
                    "businfo": "pci@0000:01:00.0",
                    "logicalname": "eno1",
                    "configuration": {"driver": "ixgbe", "speed": "10Gbit/s", "ip": "192.0.2.10"},
                }
            ],
        },
        checks._LINK: [
            {
                "ifname": "eno1",
                "ifindex": 2,
                "operstate": "UP",
                "mtu": 1500,
                "stats64": {"rx": {"bytes": 999}},
            },
            {
                "ifname": "vmbr0",
                "ifindex": 3,
                "mtu": 9000,
                "linkinfo": {"info_kind": "bridge", "future": 3},
            },
        ],
        checks._ADDRESS: [
            {
                "ifname": "vmbr0",
                "addr_info": [
                    {
                        "local": "192.0.2.10",
                        "prefixlen": 24,
                        "valid_life_time": 100,
                        "preferred_life_time": 90,
                    }
                ],
            }
        ],
        checks._SYNC: {"type": "b", "data": [True]},
        C.PROXMOX_CONFIG_COMMAND: {
            "files": [
                {
                    "path": "/etc/network/interfaces",
                    "category": "network",
                    "content": (
                        "auto vmbr0\niface vmbr0 inet static\n"
                        " source interfaces.d/*\n password=DO-NOT-TRACE"
                    ),
                }
            ],
            "absent": ["/etc/chrony.conf"],
            "includes": [
                {"source": "/etc/network/interfaces", "pattern": "interfaces.d/*", "matches": []}
            ],
            "errors": [],
        },
        "ip -j -4 route show table all": [
            {
                "table": "main",
                "dst": "default",
                "gateway": "192.0.2.1",
                "dev": "vmbr0",
                "metric": 100,
            }
        ],
        "ip -j -6 route show table all": [],
        "ip -j rule show": [{"priority": 0, "table": "local", "src": "all"}],
        "ip -j neighbor show": [
            {
                "dst": "192.0.2.1",
                "dev": "vmbr0",
                "lladdr": "00:00:00:00:00:01",
                "state": ["REACHABLE"],
            }
        ],
        checks._NEIGHBORS: {
            "lldp": [
                {
                    "interface": [
                        {
                            "name": "eno1",
                            "via": "LLDP",
                            "rid": "1",
                            "age": "0 day",
                            "chassis": [
                                {
                                    "id": [{"type": "mac", "value": "00:00:00:00:00:01"}],
                                    "name": [{"value": "switch-a"}],
                                }
                            ],
                            "port": [
                                {
                                    "id": [{"type": "ifname", "value": "Ethernet1"}],
                                    "ttl": [{"value": "120"}],
                                }
                            ],
                        }
                    ]
                }
            ]
        },
    }
    return api, ssh


def context(api=None, ssh=None):
    default_api, default_ssh = fixture()
    return _loader.context.CollectorContext(
        "pve-a",
        "proxmox",
        restconf=Api(default_api if api is None else api),
        ssh=Ssh(default_ssh if ssh is None else ssh),
        debug=True,
    )


class ProxmoxHostCapture(unittest.TestCase):
    def test_packages_include_every_debian_state_beyond_api_subset(self):
        api, ssh = fixture()
        api["/nodes/pve-a/apt/versions"] = envelope([{"Package": "pve-manager", "Version": "9.0"}])
        api["/nodes/pve-a/apt/update"] = envelope([])
        api["/nodes/pve-a/apt/repositories"] = envelope({"files": [], "errors": []})
        ssh[C.PROXMOX_PACKAGES_COMMAND] = [
            {
                "package": "pkg%d:amd64" % index,
                "version": "1.0",
                "architecture": "amd64",
                "status": "installed" if index % 2 else "config-files",
            }
            for index in range(600)
        ]
        result = checks._collect_packages(context(api, ssh))
        self.assertEqual(result["context"]["installed_packages"], 600)
        self.assertEqual(
            result["normalized"]["installed_package|pkg599:amd64"]["status"], "installed"
        )
        self.assertEqual(
            result["normalized"]["installed_package|pkg598:amd64"]["status"], "config-files"
        )
        self.assertEqual(len(result["raw"]["SSH " + C.PROXMOX_PACKAGES_COMMAND]), 600)

    def test_shared_full_reads_preserve_unknown_fields_without_caps(self):
        ctx = context()
        identity = checks._collect_host_identity(ctx)
        hardware = checks._collect_hardware_inventory(ctx)
        pnics = checks._collect_pnics(ctx)
        config = checks._collect_host_config(ctx)
        self.assertEqual(ctx.ssh.calls.count(checks._HARDWARE), 1)
        self.assertEqual(identity["normalized"]["status|pve-a"]["new-feature"], {"enabled": True})
        self.assertEqual(
            hardware["normalized"]["pci|0000:01:00.0"]["future-device-field"], "retained"
        )
        self.assertEqual(hardware["normalized"]["pci_runtime|0000:01:00.0"]["sriov_numvfs"], "2")
        self.assertEqual(hardware["normalized"]["cpu_runtime"]["isolated"], "2-7")
        self.assertEqual(ctx.ssh.calls.count(C.PROXMOX_HARDWARE_COMMAND), 1)
        nic = next(iter(pnics["normalized"].values()))
        self.assertEqual(nic["interfaces"]["eno1"]["operstate"], "UP")
        self.assertEqual(nic["kernel_interfaces"]["eno1"]["speed"], "10000")
        self.assertNotIn("ip", nic["configuration"])
        self.assertEqual(len(config["normalized"]["datacenter"]["future"]["large"]), 25000)

    def test_pending_network_and_applied_runtime_remain_distinct(self):
        result = checks._collect_network(context())
        self.assertEqual(result["raw"]["/nodes/pve-a/network"]["changes"], "- mtu 1500\n+ mtu 9000")
        self.assertTrue(result["context"]["pending_changes_present"])
        self.assertEqual(result["normalized"]["config|vmbr0"]["future-option"], "complete")
        self.assertEqual(result["normalized"]["link|vmbr0"]["mtu"], 9000)
        self.assertNotIn("valid_life_time", result["normalized"]["address|vmbr0"]["addr_info"][0])
        self.assertTrue(result["context"]["unstructured_reads"])

    def test_large_network_roster_retains_last_object(self):
        api, ssh = fixture()
        api["/nodes/pve-a/network"] = envelope(
            [{"iface": "vmbr%d" % i, "future": "x" * 100} for i in range(600)]
        )
        result = checks._collect_network(context(api, ssh))
        self.assertEqual(result["normalized"]["config|vmbr599"]["future"], "x" * 100)
        self.assertEqual(len(result["raw"]["/nodes/pve-a/network"]["data"]), 600)

    def test_duplicate_identity_refuses_overwrite(self):
        api, ssh = fixture()
        api["/nodes/pve-a/network"]["data"] *= 2
        with self.assertRaises(CollectError):
            checks._collect_network(context(api, ssh))

    def test_native_reader_gap_and_missing_ssh_are_failures(self):
        api, ssh = fixture()
        ssh[C.PROXMOX_CONFIG_COMMAND]["errors"] = ["unsafe include"]
        with self.assertRaises(CollectError):
            checks._collect_host_config(context(api, ssh))
        ssh[C.PROXMOX_CONFIG_COMMAND]["errors"] = []
        ssh[C.PROXMOX_CONFIG_COMMAND]["includes"] = [{"source": "/etc/network/interfaces"}]
        with self.assertRaises(CollectError):
            checks._collect_host_config(context(api, ssh))
        ctx = context()
        ctx.ssh = None
        with self.assertRaises(CollectError):
            checks._collect_network(ctx)

    def test_malformed_structured_reply_withholds_even_partial_json_credentials(self):
        api, ssh = fixture()
        ssh[C.PROXMOX_CONFIG_COMMAND] = '{"password":"MALFORMED-CREDENTIAL-CANARY"'
        ctx = context(api, ssh)
        with self.assertRaises(CollectError):
            checks._collect_host_config(ctx)
        evidence = json.dumps(ctx._proxmox_capture.raw) + json.dumps(ctx.trace)
        self.assertNotIn("MALFORMED-CREDENTIAL-CANARY", evidence)
        self.assertTrue(ctx._proxmox_capture.context["unstructured_reads"])

    def test_secret_and_certificate_bodies_never_reach_trace(self):
        ctx = context()
        results = [
            checks._collect_host_config(ctx),
            checks._collect_subscription(ctx),
            checks._collect_certificates(ctx),
        ]
        rendered = json.dumps(results) + json.dumps(ctx.trace)
        for token in (
            "DO-NOT-TRACE",
            "PRIVATE-SUBSCRIPTION-KEY",
            "PRIVATE-CERT-BODY",
            "PRIVATE-SIGNATURE",
        ):
            self.assertFalse(token in rendered, "secret escaped redaction")
        cert = results[2]["normalized"]["certificate|pve-ssl.pem"]
        self.assertEqual(cert["public-key-bits"], 2048)
        self.assertNotIn("pem", cert)

    def test_storage_definition_scope_and_volume_join_are_complete(self):
        ctx = context()
        result = checks._collect_storage(ctx)
        self.assertEqual(result["normalized"]["volume|local:100/vm-100-disk-0.raw"]["vmid"], 100)
        attrs = result["normalized"]["volume|local:100/vm-100-disk-0.raw"]["attributes"]
        self.assertEqual(attrs["notes"], "Complete note\nwith a second line")
        self.assertTrue(attrs["protected"])
        self.assertEqual(attrs["future-attribute"], {"all": True})
        self.assertEqual(
            result["normalized"]["storage_config|local"]["definition"]["unknown-config"], {"x": 1}
        )
        self.assertIn("storage_config|remote-only", result["normalized"])
        self.assertNotIn("/nodes/pve-a/storage/remote-only/status", ctx.restconf.calls)

    def test_missing_local_store_status_is_failed_evidence(self):
        api, ssh = fixture()
        api["/nodes/pve-a/storage"] = envelope([])
        with self.assertRaises(CollectError):
            checks._collect_storage(context(api, ssh))

    def test_disk_partition_pool_and_smart_evidence_are_complete(self):
        api, ssh = fixture()
        base = "/nodes/pve-a/disks"
        api[base + "/list?include-partitions=1"] = envelope(
            [
                {"devpath": "/dev/sda", "serial": "LAB-DRIVE", "size": 10000},
                {"devpath": "/dev/sda1", "parent": "/dev/sda", "size": 9000},
            ]
        )
        api[base + "/directory"] = envelope(
            [{"path": "/var/lib/vz", "device": "/dev/sda1", "type": "ext4"}]
        )
        api[base + "/lvm"] = envelope(
            {
                "children": [
                    {
                        "name": "pve",
                        "size": 9000,
                        "free": 30,
                        "children": [{"name": "/dev/sda1", "size": 9000, "free": 30}],
                    }
                ]
            }
        )
        api[base + "/lvmthin"] = envelope(
            [{"vg": "pve", "lv": "data", "lv_size": 8000, "used": 3, "metadata_used": 4}]
        )
        api[base + "/zfs"] = envelope([{"name": "tank", "size": 1000, "health": "ONLINE"}])
        api[base + "/zfs/tank"] = envelope(
            {"name": "tank", "state": "ONLINE", "children": [{"name": "sdb", "read": 2}]}
        )
        api[base + "/smart?disk=%2Fdev%2Fsda&healthonly=0"] = envelope(
            {"health": "PASSED", "attributes": [{"id": 1}], "text": "x" * 25000}
        )
        ssh[checks._BLOCK] = {
            "blockdevices": [
                {
                    "name": "sda",
                    "wwn": "LAB-WWN",
                    "children": [{"name": "sda1", "uuid": "LAB-FS-UUID", "fsused": 9}],
                }
            ]
        }
        result = checks._collect_storage_devices(context(api, ssh))
        self.assertEqual(result["normalized"]["disk|/dev/sda1"]["parent"], "/dev/sda")
        self.assertEqual(result["normalized"]["directory|/var/lib/vz"]["device"], "/dev/sda1")
        self.assertEqual(result["normalized"]["block|/sda/sda1"]["uuid"], "LAB-FS-UUID")
        self.assertNotIn("fsused", result["normalized"]["block|/sda/sda1"])
        self.assertNotIn("free", result["normalized"]["lvm|/pve"])
        self.assertNotIn("read", result["normalized"]["zpool_status|tank"]["children"][0])
        self.assertEqual(
            len(result["raw"][base + "/smart?disk=%2Fdev%2Fsda&healthonly=0"]["data"]["text"]),
            25000,
        )
        self.assertTrue(result["context"]["unstructured_reads"])

    def test_lldp_json0_uses_native_identity_and_keeps_unknowns(self):
        api, ssh = fixture()
        ssh[checks._NEIGHBORS]["lldp"][0]["interface"][0]["future-tlv"] = [{"value": "preserved"}]
        result = checks._collect_neighbors(context(api, ssh))
        row = next(iter(result["normalized"].values()))
        self.assertEqual(row["future-tlv"], [{"value": "preserved"}])
        self.assertNotIn("ttl", row["port"][0])
        self.assertNotIn("age", row)
        ssh[checks._NEIGHBORS] = {"lldp": [{"interface": []}]}
        self.assertEqual(checks._collect_neighbors(context(api, ssh))["normalized"], {})
        ssh[checks._NEIGHBORS] = "lldpcli: command not found"
        with self.assertRaises(CollectError):
            checks._collect_neighbors(context(api, ssh))
        api, ssh = fixture()
        del ssh[checks._NEIGHBORS]["lldp"][0]["interface"][0]["chassis"][0]["id"]
        with self.assertRaises(CollectError):
            checks._collect_neighbors(context(api, ssh))

    def test_time_sync_requires_typed_boolean(self):
        result = checks._collect_host_time(context())
        self.assertTrue(result["normalized"]["ntp_synchronized"])
        api, ssh = fixture()
        ssh[checks._SYNC] = {"type": "b", "data": ["false"]}
        with self.assertRaises(CollectError):
            checks._collect_host_time(context(api, ssh))

    def test_rrd_capture_keeps_all_samples_outside_normalized_assertions(self):
        api, ssh = fixture()
        api["/nodes/pve-a/rrddata?cf=AVERAGE&timeframe=day"] = envelope(
            [{"time": i, "cpu": 0.5, "future-metric": 3} for i in range(1000)]
        )
        result = checks._collect_metrics(context(api, ssh))
        self.assertEqual(result["normalized"], {})
        self.assertEqual(result["context"]["sample_counts"]["node"], 1000)
        self.assertEqual(
            result["raw"]["/nodes/pve-a/rrddata?cf=AVERAGE&timeframe=day"]["data"][-1][
                "future-metric"
            ],
            3,
        )


if __name__ == "__main__":
    unittest.main()
