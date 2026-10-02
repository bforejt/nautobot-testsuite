"""Applied bridge policy preserves complete JSON evidence without learned-MAC diffs."""

import json
import unittest

from . import _loader

checks = _loader.load("checks_proxmox_linux")


class TestBridgeCapture(unittest.TestCase):
    def _ctx(self, vlan, forwarding):
        answers = {"bridge -j -s vlan show": vlan, "bridge -j -s fdb show": forwarding}

        class Ssh:
            def run(self, command):
                return json.dumps(answers[command])

        return _loader.context.CollectorContext("pve-lab", "proxmox", ssh=Ssh(), debug=True)

    def test_policy_and_unknown_fields_survive_while_all_fdb_rows_remain_raw(self):
        vlan = [
            {
                "ifname": "vmbr0",
                "future": True,
                "vlans": [
                    {
                        "vlan": 100,
                        "flags": ["PVID", "Egress Untagged"],
                        "rx_bytes": 42,
                        "future_policy": "preserved",
                    },
                ],
            }
        ]
        fdb = [{"mac": "02:00:00:00:00:01", "dev": "tap100i0", "state": "permanent"}]
        result = checks._collect_bridges(self._ctx(vlan, fdb))
        row = result["normalized"]["interface|vmbr0"]
        self.assertTrue(row["future"])
        self.assertEqual(row["vlans"][0]["future_policy"], "preserved")
        self.assertNotIn("rx_bytes", row["vlans"][0])
        self.assertEqual(result["raw"]["SSH bridge -j -s vlan show"], vlan)
        self.assertEqual(result["raw"]["SSH bridge -j -s fdb show"], fdb)
        self.assertEqual(result["context"]["forwarding_entries"], 1)

    def test_empty_unconfigured_tables_are_valid(self):
        self.assertEqual(checks._collect_bridges(self._ctx([], []))["normalized"], {})

    def test_duplicate_interface_and_malformed_json_refuse(self):
        for vlan in ([{"ifname": "vmbr0"}, {"ifname": "vmbr0"}], {"unparsed": "table"}):
            with self.subTest(vlan=vlan), self.assertRaises(_loader.registry.CollectError):
                checks._collect_bridges(self._ctx(vlan, []))
