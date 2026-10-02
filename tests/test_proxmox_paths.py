"""Verified safe Proxmox resource/query shapes and refusal before any HTTP request."""

import unittest

if __package__:
    from . import _loader
else:
    import _loader

paths = _loader.load("proxmox_paths")


class TestProxmoxPaths(unittest.TestCase):
    def test_reviewed_component_reads(self):
        for path in (
            "/version",
            "/cluster/status",
            "/nodes/pve-a/status",
            "/nodes/pve-a/qemu/100/config?current=1",
            "/nodes/pve-a/lxc/101/snapshot/initial/config",
            "/nodes/pve-a/qemu/100/agent/network-get-interfaces",
            "/nodes/pve-a/qemu/100/cloudinit/dump?type=user",
            "/nodes/pve-a/qemu/100/cloudinit/dump?type=network",
            "/nodes/pve-a/qemu/100/cloudinit/dump?type=meta",
            "/cluster/config/qdevice",
            "/cluster/ha/resources/vm:100",
            "/cluster/sdn/vnets/vnet1/subnets",
            "/nodes/pve-a/hardware/pci?verbose=1&pci-class-blacklist=",
            "/nodes/pve-a/disks/smart?disk=%2Fdev%2Fnvme0n1&healthonly=0",
            "/nodes/pve-a/disks/list?include-partitions=1",
            "/access/users/auditor@pve/token/monitor",
            "/nodes/pve-a/vzdump/defaults?storage=pbs",
            "/cluster/ceph/health-mute",
            "/cluster/qemu/custom-cpu-models/custom-epyc",
            "/nodes/pve-a/journal?structured=1&since=1000&until=2000",
            "/nodes/pve-a/syslog?since=2026-10-02+00%3A00%3A00&start=0&limit=500",
        ):
            self.assertTrue(paths.is_allowed_path(path), path)

    def test_dangerous_or_unknown_reads_are_not_accepted_by_prefix(self):
        for path in (
            "/nodes/pve-a/qemu/100/agent/file-read",
            "/nodes/pve-a/qemu/100/agent/exec-status",
            "/nodes/pve-a/qemu/100/agent/get-users",
            "/nodes/pve-a/qemu/100/cloudinit/dump",
            "/nodes/pve-a/qemu/100/cloudinit/dump?type=vendor",
            "/nodes/pve-a/qemu/100/vncwebsocket",
            "/nodes/pve-a/hardware/usb",
            "/cluster/sdn/dry-run",
            "/access/ticket",
            "/nodes/pve-a/execute",
            "/nodes/pve-a/unknown",
            "/nodes/pve-a/qemu/100/status/start",
        ):
            self.assertFalse(paths.is_allowed_path(path), path)

    def test_encoding_traversal_and_host_injection_refused(self):
        for path in (
            "https://other.example/version",
            "//other.example/version",
            "/nodes/pve-a/../status",
            "/nodes/pve-a/%2e%2e/status",
            "/nodes/%70ve-a/status",
            "/nodes/pve-a/status#fragment",
            "/nodes/pve-a/status\n",
            "/nodes/pve-a/status?token=secret",
            "/version?path=%2F..%2Fprivate",
            "/version?foo=1",
            "/nodes/pve-a/qemu/100/config?current=1&current=0",
            "/nodes/pve-a/qemu/100/config?current=5",
            "/nodes/pve-a/disks/smart?disk=%2Fdev%2F..%2Fsda",
            "/nodes/pve-a/rrddata?timeframe=forever",
            "/nodes/pve-a/journal",
            "/nodes/pve-a/journal?structured=0&since=1000&until=2000",
            "/nodes/pve-a/journal?structured=1&since=1000&until=2000&lastentries=10",
            "/nodes/pve-a/journal?structured=1&since=2000&until=1000",
        ):
            self.assertFalse(paths.is_allowed_path(path), path)

    def test_canonical_query_sorting_and_api_prefix(self):
        self.assertEqual(
            paths.fence_path("/api2/json/nodes/pve-a/tasks?start=0&limit=500&source=all"),
            "/nodes/pve-a/tasks?limit=500&source=all&start=0",
        )

    def test_volume_metadata_encodes_observed_native_ids(self):
        for storage, volume, suffix in (
            ("local", "local:100/vm-100-disk-0.raw", "local%3A100%2Fvm-100-disk-0.raw"),
            (
                "pbs",
                "pbs:backup/vm/100/2026-10-02T01:02:03Z",
                "pbs%3Abackup%2Fvm%2F100%2F2026-10-02T01%3A02%3A03Z",
            ),
        ):
            path = paths.volume_path("pve-a", storage, volume)
            self.assertTrue(path.endswith(suffix))
            self.assertEqual(paths.fence_path(path), path)
            self.assertEqual(
                paths.fence_path("/nodes/pve-a/storage/%s/content/%s" % (storage, volume)), path
            )
        for volume in (
            "other:100/disk.raw",
            "local:../disk.raw",
            "local:100/./disk.raw",
            "local:100//disk.raw",
            "local:100/%2e%2e/disk.raw",
            "local:100/disk.raw?download=1",
            "local:100/disk.raw#fragment",
        ):
            with self.assertRaises(paths.ProxmoxPathRefused):
                paths.volume_path("pve-a", "local", volume)
        for suffix in ("local%3A100%2F%252e%252e%2Fdisk.raw", "local%3A100%2F..%2Fdisk.raw", "%ZZ"):
            self.assertFalse(paths.is_allowed_path("/nodes/pve-a/storage/local/content/" + suffix))
        self.assertFalse(paths.is_allowed_path(path + "?download=1"))


if __name__ == "__main__":
    unittest.main()
