"""Complete guest inventories, native property grammar and stable evidence."""

import copy
import json
import unittest

from . import _loader

checks = _loader.load("checks_proxmox_guests")
common = _loader.load("proxmox_common")
CollectError = _loader.registry.CollectError
BASE = "/nodes/pve-lab/qemu/101"
KEY = "cluster:lab|qemu|101"


class FakeContext:
    def __init__(self, sources):
        self.sources = sources
        self.calls = []
        self._cache = {}

    def run_ssh(self, command, **kwargs):
        self.calls.append("SSH " + command)
        value = self.sources["SSH " + command]
        output = json.dumps(value)
        redact = kwargs.get("redact")
        return redact(output) if redact else output

    def get(self, path, **kwargs):
        self.calls.append(path)
        if path not in self.sources:
            if kwargs.get("ok_404"):
                return None
            raise CollectError("missing required fixture " + path)
        value = self.sources[path]
        if isinstance(value, Exception):
            raise value
        return copy.deepcopy(
            value if isinstance(value, dict) and "data" in value else {"data": value}
        )


def fixture():
    return {
        "/cluster/status": [
            {"id": "cluster", "type": "cluster", "name": "lab"},
            {"id": "node/pve-lab", "type": "node", "name": "pve-lab", "local": 1},
        ],
        "/nodes/pve-lab/qemu": [
            {"vmid": 101, "name": "guest-a", "status": "running", "cpu": 0.2},
            {"vmid": 102, "name": "template-a", "status": "stopped", "template": 1},
        ],
        "/nodes/pve-lab/lxc": [{"vmid": 103, "name": "container-a", "status": "stopped"}],
    }


def configs(sources, **overrides):
    for kind, vmid in (("qemu", 101), ("qemu", 102), ("lxc", 103)):
        path = "/nodes/pve-lab/%s/%s" % (kind, vmid)
        sources[path + "/config?current=1"] = {
            "name": "guest",
            "memory": 4096,
            "future-option": "unmodelled",
            "digest": "revision",
            **overrides,
        }
    return sources


class GuestCapture(unittest.TestCase):
    def test_stopped_templates_and_containers_are_always_inventoried(self):
        data = fixture()
        for kind, vmid, state in (
            ("qemu", 101, "running"),
            ("qemu", 102, "stopped"),
            ("lxc", 103, "stopped"),
        ):
            data["/nodes/pve-lab/%s/%s/status/current" % (kind, vmid)] = {
                "status": state,
                "maxmem": 4096,
                "uptime": 71,
                "mem": 777,
                "pid": 200,
                "new-counter": 99,
            }
        result = checks._collect_inventory(FakeContext(data))
        self.assertEqual(len(result["normalized"]), 3)
        self.assertEqual(result["normalized"]["cluster:lab|qemu|102"]["template"], 1)
        self.assertEqual(result["normalized"][KEY]["node"], "pve-lab")
        self.assertNotIn("new-counter", result["normalized"][KEY])
        self.assertEqual(result["raw"][BASE + "/status/current"]["data"]["new-counter"], 99)

    def test_runtime_usage_does_not_change_stable_view(self):
        data = fixture()
        for kind, vmid in (("qemu", 101), ("qemu", 102), ("lxc", 103)):
            data["/nodes/pve-lab/%s/%s/status/current" % (kind, vmid)] = {
                "status": "running",
                "mem": 500,
                "uptime": 2,
                "cpu": 0.2,
            }
        first = checks._collect_inventory(FakeContext(data))
        data[BASE + "/status/current"].update(mem=900, uptime=50, cpu=0.9)
        second = checks._collect_inventory(FakeContext(data))
        self.assertEqual(first["normalized"], second["normalized"])
        self.assertNotEqual(first["raw"], second["raw"])

    def test_pending_deletions_unknown_options_and_large_fields_are_preserved(self):
        data = configs(fixture())
        large = "x" * 300000
        data[BASE + "/config?current=1"]["future-large"] = large
        for kind, vmid in (("qemu", 101), ("qemu", 102), ("lxc", 103)):
            data["/nodes/pve-lab/%s/%s/pending" % (kind, vmid)] = [
                {"key": "net1", "value": "virtio=aa:bb:cc:dd:ee:ff", "delete": 1},
                {
                    "key": "cipassword",
                    "value": "not-a-real-password",
                    "pending": "new-not-a-real-password",
                },
            ]
        result = checks._collect_config(FakeContext(data))
        self.assertEqual(result["normalized"][KEY]["current"]["future-large"], large)
        self.assertEqual(result["normalized"][KEY]["pending"]["net1"]["delete"], 1)
        self.assertNotIn("not-a-real-password", json.dumps(result))
        self.assertIn("future-option", result["normalized"][KEY]["current"])
        self.assertNotIn("digest", result["normalized"][KEY]["current"])

    def test_disks_and_nics_include_unused_mounts_and_passthrough(self):
        data = configs(
            fixture(),
            scsi0="local-lvm:vm-101-disk-0,discard=on,future=enabled",
            unused7="shared:old",
            net0="virtio=aa:bb:cc:dd:ee:ff,bridge=vmbr0,tag=200,trunks=201;202",
            hostpci0="0000:03:00.0,pcie=1",
        )
        data["/nodes/pve-lab/lxc/103/config?current=1"].update(
            rootfs="local:subvol-103,size=8G", mp0="/srv/data,mp=/data,backup=1"
        )
        disks = checks._device_collector(checks._DISK)(FakeContext(data))
        self.assertEqual(disks["normalized"][KEY + "|scsi0"]["future"], "enabled")
        self.assertIn(KEY + "|unused7", disks["normalized"])
        self.assertIn("cluster:lab|lxc|103|rootfs", disks["normalized"])
        nics = checks._device_collector(checks._NIC)(FakeContext(data))
        self.assertEqual(nics["normalized"][KEY + "|net0"]["trunks"], "201;202")
        self.assertIn(KEY + "|hostpci0", nics["normalized"])

    def test_snapshot_tree_keeps_saved_config_and_skips_current_pseudo_snapshot(self):
        data = fixture()
        for kind, vmid in (("qemu", 101), ("qemu", 102), ("lxc", 103)):
            base = "/nodes/pve-lab/%s/%s" % (kind, vmid)
            data[base + "/snapshot"] = [
                {"name": "current", "parent": "before"},
                {"name": "before", "snaptime": 1700000000},
            ]
            data[base + "/snapshot/before/config"] = {"memory": 1024, "unknown": "kept"}
        ctx = FakeContext(data)
        result = checks._collect_snapshots(ctx)
        self.assertEqual(len(result["normalized"]), 3)
        self.assertEqual(
            result["normalized"][KEY + "|snapshot|before"]["config"]["unknown"], "kept"
        )
        self.assertFalse(any("snapshot/current/config" in path for path in ctx.calls))

    def test_cloudinit_reads_only_guests_with_cloudinit_volume(self):
        data = configs(fixture())
        data[BASE + "/config?current=1"]["ide2"] = "local-lvm:vm-101-cloudinit,media=cdrom"
        data[BASE + "/cloudinit"] = [
            {"key": "ipconfig0", "value": "ip=dhcp", "pending": "ip=192.0.2.101/24"}
        ]
        data[BASE + "/cloudinit/dump?type=user"] = (
            "#cloud-config\npassword: canary-cloud-password\nssh_authorized_keys:\n"
            "  - sk-ssh-ed25519@openssh.com AAAAcanarykey canary-key-comment\n"
            "chpasswd:\n  expire: False\n"
        )
        data[BASE + "/cloudinit/dump?type=network"] = "version: 1\nconfig: []\n"
        data[BASE + "/cloudinit/dump?type=meta"] = "instance-id: generated-101\n"
        ctx = FakeContext(data)
        result = checks._collect_cloudinit(ctx)
        self.assertEqual(result["normalized"][KEY]["ipconfig0"]["value"], "ip=dhcp")
        self.assertEqual(len(result["normalized"]), 1)
        self.assertNotIn("data_gaps", result["context"])
        self.assertEqual(len(result["context"]["unstructured_reads"]), 3)
        self.assertNotIn("canary-", json.dumps(result))
        self.assertIn(
            "instance-id: generated-101", result["raw"][BASE + "/cloudinit/dump?type=meta"]["data"]
        )
        data[BASE + "/config?current=1"]["cicustom"] = "user=local:snippets/custom-user.yaml"
        custom = checks._collect_cloudinit(FakeContext(data))
        self.assertEqual(len(custom["context"]["data_gaps"]), 1)
        self.assertIn("redaction", custom["context"]["data_gaps"][0]["reason"])
        self.assertEqual(
            custom["raw"][BASE + "/config?current=1"]["data"]["cicustom"],
            "user=local:snippets/custom-user.yaml",
        )

    def test_agent_allowlist_never_reads_users_or_initiates_guest_actions(self):
        data = configs(fixture(), agent="1")
        for command in checks._AGENT_READS:
            data[BASE + "/agent/" + command] = {"result": {"supported": True}}
        data[BASE + "/agent/info"] = {
            "result": {
                "supported_commands": [
                    {"name": "guest-" + command, "enabled": True} for command in checks._AGENT_READS
                ]
            }
        }
        ctx = FakeContext(data)
        result = checks._collect_agent(ctx)
        self.assertEqual(result["normalized"][KEY], {"agent_configured": True})
        self.assertTrue(any("agent/network-get-interfaces" in path for path in ctx.calls))
        self.assertFalse(
            any("get-users" in path or "exec" in path or "file-read" in path for path in ctx.calls)
        )
        self.assertFalse(any("/qemu/102/agent/" in path for path in ctx.calls))

    def test_agent_permission_failure_remains_failed_with_operator_guidance(self):
        data = configs(fixture(), agent="1")
        denied = CollectError("Proxmox GET returned HTTP 403")
        denied.status_code = 403
        data[BASE + "/agent/info"] = denied
        ctx = FakeContext(data)
        with self.assertRaisesRegex(CollectError, "VM.GuestAgent.Audit.*vms/101"):
            checks._collect_agent(ctx)
        cap = ctx._proxmox_capture
        self.assertEqual(cap.context["sources"][BASE + "/agent/info"]["status"], 403)
        self.assertEqual(cap.context["sources"][BASE + "/agent/info"]["outcome"], "refused")
        self.assertIn(BASE + "/config?current=1", cap.raw)
        self.assertIn("VM.GuestAgent.Audit", cap.context["permission_guidance"])

    def test_all_guest_day_history_includes_stopped_templates_and_unknown_fields(self):
        data = fixture()
        sources = []
        for kind, vmid in (("qemu", 101), ("qemu", 102), ("lxc", 103)):
            source = "/nodes/pve-lab/%s/%s/rrddata?cf=AVERAGE&timeframe=day" % (kind, vmid)
            sources.append(source)
            data[source] = (
                [{"time": n, "cpu": 0.1, "unknown_numeric": n + 0.5} for n in range(1500)]
                if vmid != 102
                else []
            )
        ctx = FakeContext(data)
        result = checks._collect_metrics(ctx)
        self.assertEqual(len(result["normalized"]), 3)
        self.assertEqual(result["context"]["metrics"]["samples"], 3000)
        self.assertTrue(all(source in ctx.calls for source in sources))
        self.assertEqual(result["raw"][sources[0]]["data"][-1]["unknown_numeric"], 1499.5)
        self.assertNotIn("cpu", result["normalized"][KEY])
        self.assertNotIn("unstructured_reads", result["context"])
        data[sources[0]][0]["cpu"] = 0.9
        again = checks._collect_metrics(FakeContext(data))
        self.assertEqual(result["normalized"], again["normalized"])
        self.assertNotEqual(result["raw"], again["raw"])

    def test_missing_required_config_and_duplicate_guest_identity_fail(self):
        with self.assertRaises(CollectError):
            checks._collect_config(FakeContext(fixture()))
        data = fixture()
        data["/nodes/pve-lab/qemu"].append({"vmid": 101})
        with self.assertRaises(CollectError):
            checks.guests(common.Capture(FakeContext(data)))

    def test_node_migration_does_not_rekey_cluster_guest(self):
        data = fixture()
        first = checks.guests(common.Capture(FakeContext(data)))[0][0]
        moved = {key.replace("pve-lab", "pve-other"): value for key, value in data.items()}
        moved["/cluster/status"][1] = {"type": "node", "name": "pve-other", "local": 1}
        second = checks.guests(common.Capture(FakeContext(moved)))[0][0]
        self.assertEqual(first, second)

    def test_custom_cpu_models_and_unmodelled_tuning_are_captured(self):
        data = configs(fixture(), numa0="cpus=0-1,memory=1024", future_tuning="kept")
        data["/cluster/qemu/custom-cpu-models"] = [{"cputype": "custom-nfv", "flags": "+aes"}]
        data["/cluster/qemu/custom-cpu-models/custom-nfv"] = {
            "cputype": "custom-nfv",
            "flags": "+aes;+pcid",
            "future-flag": 1,
        }
        result = checks._collect_tuning(FakeContext(data))
        self.assertEqual(result["normalized"]["cpu-model|custom-nfv"]["future-flag"], 1)
        self.assertEqual(result["normalized"][KEY]["future_tuning"], "kept")

    def test_all_stopped_or_unconfigured_agents_are_not_present(self):
        data = configs(fixture())
        ctx = FakeContext(data)
        with self.assertRaises(_loader.registry.SkipCheck):
            checks._collect_agent(ctx)
        self.assertFalse(any("/agent/" in path for path in ctx.calls))

    def test_native_vmid_upper_bound_refuses_before_child_reads(self):
        data = fixture()
        data["/nodes/pve-lab/qemu"] = [{"vmid": 1000000000}]
        with self.assertRaises(CollectError):
            checks.guests(common.Capture(FakeContext(data)))

    def test_every_guest_check_is_registered_and_self_describing(self):
        for identity, semantics in checks.SEMANTICS.items():
            self.assertIn(identity, _loader.registry.CHECKS)
            self.assertTrue(semantics)


if __name__ == "__main__":
    unittest.main()
