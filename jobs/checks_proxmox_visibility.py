"""Reconcile API visibility with authoritative, structured host inventories."""

from . import constants as C
from .checks_proxmox import _ssh
from .checks_proxmox_cluster import _native_inventory
from .proxmox_common import Capture, keyed
from .registry import SEMANTICS, CheckDef, CollectError, register


def _require(cap, path, privilege):
    answer = cap.read("/access/permissions", params={"path": path})
    rights = answer.get(path) if isinstance(answer, dict) else None
    if (
        not isinstance(rights, dict)
        or privilege not in rights
        or type(rights[privilege]) not in (bool, int)
        or rights[privilege] not in (0, 1)
    ):
        raise CollectError("Proxmox capture requires effective %s at %s" % (privilege, path))


def _prove_sdn(cap, inventories):
    configured = {}
    families = {
        "zones": "zones",
        "vnets": "vnets",
        "controllers": "controllers",
        "dns": "dns",
        "ipams": "ipams",
        "subnets": "subnets",
        "fabrics": "fabrics",
        "fabric_nodes": "nodes",
        "prefix_lists": "prefix-lists",
        "route_maps": "route-maps",
    }
    for source, family in families.items():
        configured[family] = _native_inventory(
            cap, inventories.get("sdn_" + source), "sdn_" + source
        )
    states = [configured]
    for state in ("running", "pending"):
        wrapper = inventories.get("sdn_" + state)
        if not isinstance(wrapper, dict):
            raise CollectError("authoritative SDN %s inventory is missing" % state)
        if wrapper.get("outcome") == "not-present":
            _native_inventory(cap, wrapper, "sdn_" + state)
            continue
        if wrapper.get("outcome") != "complete" or not isinstance(wrapper.get("families"), dict):
            raise CollectError("authoritative SDN %s families are incomplete" % state)
        native = {}
        for family, value in wrapper["families"].items():
            if family not in families.values():
                raise CollectError("unknown authoritative SDN audit scope family")
            native[family] = _native_inventory(cap, value, "sdn_%s/%s" % (state, family))
        states.append(native)
    scopes = set()
    simple = {"zones", "controllers", "dns", "ipams", "fabrics", "prefix-lists"}
    for state in states:
        for family in simple:
            scopes.update(
                ("/sdn/%s/%s" % (family, identity), "SDN.Audit")
                for identity in state.get(family) or {}
            )
        for identity, config in (state.get("vnets") or {}).items():
            pending = config.get("pending", {})
            if not isinstance(pending, dict):
                raise CollectError("authoritative VNet pending configuration is malformed")
            zones = {config.get("zone"), pending.get("zone")}
            zones.discard(None)
            if not zones:
                zones = {
                    other.get("vnets", {}).get(identity, {}).get("zone")
                    for other in states
                    if other.get("vnets")
                }
                zones.discard(None)
            if not zones or any(not isinstance(zone, str) or not zone for zone in zones):
                raise CollectError("authoritative VNet has no auditable zone")
            scopes.update(("/sdn/zones/%s/%s" % (zone, identity), "SDN.Audit") for zone in zones)
        for identity, config in (state.get("route-maps") or {}).items():
            pending = config.get("pending", {})
            if not isinstance(pending, dict) or not isinstance(config.get("route-map-id"), str):
                raise CollectError("authoritative route-map entry has no auditable resource scope")
            route_ids = {identity, config["route-map-id"], pending.get("route-map-id")}
            route_ids.discard(None)
            scopes.update(("/sdn/route-maps/" + route_id, "SDN.Audit") for route_id in route_ids)
        for config in (state.get("nodes") or {}).values():
            node = config.get("node_id")
            if not isinstance(node, str) or not node:
                raise CollectError("authoritative fabric node has no auditable node scope")
            scopes.add(("/nodes/" + node, "Sys.Audit"))
            fabric = config.get("fabric_id")
            if fabric:
                scopes.add(("/sdn/fabrics/" + fabric, "SDN.Audit"))
    for path, privilege in sorted(scopes):
        _require(cap, path, privilege)
    cap.context["sdn_audit_scopes"] = len(scopes)


def _collect_visibility(ctx):
    cap = Capture(ctx)
    node = cap.node()
    authority = _ssh(cap, C.PROXMOX_ACCESS_COMMAND)
    if not isinstance(authority, dict) or not all(
        isinstance(authority.get(field), dict) for field in ("access", "guests", "storage")
    ):
        raise CollectError("authoritative Proxmox policy/inventory query is incomplete")
    guests = authority["guests"].get("ids")
    storage = authority["storage"].get("ids")
    if not isinstance(guests, dict) or not isinstance(storage, dict):
        raise CollectError("authoritative Proxmox inventory lacks its ids maps")
    nodes = authority.get("nodes")
    if (
        not isinstance(nodes, list)
        or not nodes
        or any(not isinstance(identity, str) or not identity for identity in nodes)
        or len(set(nodes)) != len(nodes)
    ):
        raise CollectError("authoritative Proxmox node inventory is malformed")
    for identity in nodes:
        _require(cap, "/nodes/" + identity, "Sys.Audit")
    observed_nodes = {
        row.get("name") for row in cap.rows("/cluster/status") if row.get("type") == "node"
    }
    if observed_nodes != set(nodes):
        raise CollectError("Proxmox API node inventory is filtered or changed during capture")
    expected = {"qemu": set(), "lxc": set()}
    for identity, row in guests.items():
        if not isinstance(row, dict) or row.get("type") not in expected or not row.get("node"):
            raise CollectError("authoritative Proxmox guest inventory is malformed")
        if row["node"] == node:
            expected[row["type"]].add(str(identity))
        # Shared cluster resource/replication inventories include peer guests.
        # Prove each authoritative identity, including NoAccess descendants.
        _require(cap, "/vms/" + str(identity), "VM.Audit")
    for kind in expected:
        observed = set(keyed(cap.rows("/nodes/%s/%s" % (node, kind)), "vmid"))
        if observed != expected[kind]:
            cap.context["visibility_mismatch"] = {
                "family": kind,
                "missing": sorted(expected[kind] - observed),
                "unexpected": sorted(observed - expected[kind]),
            }
            raise CollectError("Proxmox API guest inventory is filtered or changed during capture")
    observed_storage = set(keyed(cap.rows("/storage"), "storage"))
    if observed_storage != set(storage):
        cap.context["visibility_mismatch"] = {
            "family": "storage",
            "missing": sorted(set(storage) - observed_storage),
            "unexpected": sorted(observed_storage - set(storage)),
        }
        raise CollectError("Proxmox API storage inventory is filtered or changed during capture")
    for identity in storage:
        _require(cap, "/storage/" + identity, "Datastore.Audit")
    pools = authority["access"].get("pools", {})
    if not isinstance(pools, dict):
        raise CollectError("authoritative Proxmox pool inventory is malformed")
    for identity in pools:
        _require(cap, "/pool/" + identity, "Pool.Audit")
    if set(keyed(cap.rows("/pools"), "poolid")) != set(pools):
        raise CollectError("Proxmox API pool inventory is filtered or changed during capture")
    inventories = authority.get("inventories")
    if not isinstance(inventories, dict):
        raise CollectError("authoritative shared inventory wrappers are missing")
    for family in ("pci", "usb", "dir"):
        entries = _native_inventory(cap, inventories.get("mapping_" + family), "mapping_" + family)
        for identity in entries or {}:
            _require(cap, "/mapping/%s/%s" % (family, identity), "Mapping.Audit")
    replication = _native_inventory(cap, inventories.get("replication"), "replication")
    for config in (replication or {}).values():
        guest = config.get("guest")
        if guest is None:
            raise CollectError("authoritative replication job has no guest scope")
        _require(cap, "/vms/" + str(guest), "VM.Audit")
    _prove_sdn(cap, inventories)
    _require(cap, "/", "Sys.Audit")
    _require(cap, "/nodes/" + node, "Sys.Audit")
    cap.context["visibility"] = "authoritative guest/storage/pool inventory and scoped audit proofs"
    cap.context["guests_total"] = sum(len(rows) for rows in expected.values())
    cap.context["storage_total"] = len(storage)
    cap.context["cluster_guests_total"] = len(guests)
    cap.context["pools_total"] = len(pools)
    cap.context["nodes_total"] = len(nodes)
    return cap.result(
        {"scope": {"node": node, "visibility_verified": True}, "access_policy": authority["access"]}
    )


SEMANTICS["proxmox_capture_visibility"] = (
    "The selected host's native Proxmox parsers provide full configured access policy, "
    "node/guest registration, pools, storage, mappings, replication and SDN inventories as JSON. "
    "Exact node/VM/storage/pool/mapping/SDN grants cover configured, applied and pending scopes. "
    "API inventories reconcile with native identities; filtered lists cannot claim completeness. "
    "A mismatch or unreadable authority fails this check and the device; partial evidence remains "
    "available. Effective audit grants are tested by key presence because values are propagation "
    "flags. Policy data preserves configured identities and masks personal/credential material."
)
register(
    CheckDef(
        id="proxmox_capture_visibility",
        platform="proxmox",
        tier=1,
        description="Authoritative access policy and proof of complete API inventory visibility",
        compare={"mode": "equality_set"},
        miss_meaning="Inventory visibility was not proven.",
        collector=_collect_visibility,
    )
)
