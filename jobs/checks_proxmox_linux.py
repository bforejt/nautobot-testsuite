"""Structured Linux bridge policy and forwarding evidence for the selected host."""

from .checks_proxmox import _rows, _ssh
from .proxmox_common import Capture, keyed, stable
from .registry import EMPTY_OK_TAG, SEMANTICS, CheckDef, register


def _collect_bridges(ctx):
    cap = Capture(ctx)
    vlan = _rows(_ssh(cap, "bridge -j -s vlan show"), "bridge VLAN table")
    forwarding = _rows(_ssh(cap, "bridge -j -s fdb show"), "bridge forwarding table")
    view = keyed(vlan, "ifname", "interface|")
    for row in view.values():
        entries = _rows(row.get("vlans", []), "bridge VLAN membership")
        row["vlans"] = [
            stable(entry, ("stats", "rx_bytes", "tx_bytes", "rx_packets", "tx_packets"))
            for entry in entries
        ]
    cap.context["forwarding_entries"] = len(forwarding)
    cap.context["vlan_interfaces"] = len(vlan)
    cap.context["forwarding_source"] = "complete bridge JSON FDB retained in raw"
    return cap.result(view)


SEMANTICS["proxmox_bridge_state"] = (
    "Every Linux bridge VLAN table row is keyed by interface name, retaining VLAN and PVID/"
    "untagged policy while numerical counters remain in raw. The complete learned/static "
    "forwarding database is raw diagnostic evidence; MAC learning and aging do not create "
    "stable comparison keys. Empty tables are valid on a host without Linux bridges."
)
register(
    CheckDef(
        id="proxmox_bridge_state",
        platform="proxmox",
        tier=2,
        description="Applied bridge VLAN policy and complete MAC forwarding evidence",
        compare={"mode": "equality_set"},
        miss_meaning="Bridge VLAN policy or membership changed.",
        collector=_collect_bridges,
        tags=(EMPTY_OK_TAG,),
    )
)
