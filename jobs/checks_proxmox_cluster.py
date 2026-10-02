"""Complete shared cluster configuration and local service evidence.

Exact API families are named here. Child reads follow only identifiers from
those inventories; no recursively discovered links or action endpoints run.
"""

from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from . import constants as C
from . import registry
from .checks_proxmox import _ssh
from .checks_proxmox_guests import guests
from .proxmox_common import Capture, keyed, stable
from .registry import EMPTY_OK_TAG, CheckDef, CollectError, SkipCheck, register

SEMANTICS = {}


def _object(cap, path, **kwargs):
    value = cap.read(path, **kwargs)
    if value is None and kwargs.get("optional"):
        return None
    if not isinstance(value, dict):
        raise CollectError("%s did not return an object" % path)
    return stable(value, omit=("digest",))


def _table(cap, path, field, **kwargs):
    rows = cap.rows(path, **kwargs)
    if rows is None:
        return None
    return {key: stable(row, omit=("digest",)) for key, row in keyed(rows, field).items()}


def _collect_cluster(ctx):
    cap = Capture(ctx)
    status = _table(cap, "/cluster/status", "id")
    status = {
        identity: stable(row, omit=("uptime", "cpu", "mem", "disk", "level"))
        for identity, row in status.items()
    }
    resources = _table(cap, "/cluster/resources", "id")
    for key, row in resources.items():
        resources[key] = stable(
            row, omit=("cpu", "mem", "disk", "uptime", "diskread", "diskwrite", "netin", "netout")
        )
    config = {}
    if any(row.get("type") == "cluster" for row in status.values()):
        config["nodes"] = _table(cap, "/cluster/config/nodes", "node")
        config["totem"] = _object(cap, "/cluster/config/totem")
        config["qdevice"] = _object(cap, "/cluster/config/qdevice", optional=True)
    cap.context["inventory_scope"] = "shared topology; detailed guest/host reads are local only"
    return cap.result({"status": status, "resources": resources, "corosync": config})


def _collect_pools(ctx):
    cap = Capture(ctx)
    authority = _ssh(cap, C.PROXMOX_ACCESS_COMMAND)
    policy = authority.get("access") if isinstance(authority, dict) else None
    pools = policy.get("pools") if isinstance(policy, dict) else None
    if not isinstance(pools, dict) or any(not isinstance(value, dict) for value in pools.values()):
        raise CollectError("authoritative access policy has no complete configured pools")
    observed = _table(cap, "/pools", "poolid")
    if set(observed) != set(pools):
        raise CollectError("pool API inventory is filtered or changed during capture")
    view = {}
    fields = (
        "id",
        "type",
        "node",
        "vmid",
        "storage",
        "status",
        "template",
        "maxcpu",
        "maxmem",
        "maxdisk",
        "hastate",
        "tags",
        "lock",
    )
    for poolid, config in pools.items():
        # The deprecated /pools/{poolid} path cannot address nested pools.
        # The supported query returns exactly one row, even for a nested ID.
        selected = _table(cap, "/pools", "poolid", params={"poolid": poolid})
        if set(selected) != {poolid}:
            raise CollectError("selected pool API query did not return exactly its configured pool")
        detail = selected[poolid]
        members = detail.get("members")
        if not isinstance(members, list) or any(not isinstance(row, dict) for row in members):
            raise CollectError("selected pool API query has no structured membership")
        item = stable(detail, omit=("members", "digest"))
        item["config"] = config
        item["members"] = {
            identity: {field: row[field] for field in fields if field in row}
            for identity, row in keyed(members, "id").items()
        }
        view[poolid] = item
    cap.context["configuration_source"] = (
        "Parsed user.cfg preserves every configured membership reference, including stale IDs "
        "the API omits. Supported poolid query covers nested pools; full member readings are raw."
    )
    return cap.result(view)


def _collect_mappings(ctx):
    cap = Capture(ctx)
    authority = _ssh(cap, C.PROXMOX_ACCESS_COMMAND)
    inventories = authority.get("inventories") if isinstance(authority, dict) else None
    if not isinstance(inventories, dict):
        raise CollectError("authoritative mapping source has no native inventories")
    view = {}
    served = 0
    for kind in ("pci", "usb", "dir"):
        native = _native_inventory(cap, inventories.get("mapping_" + kind), "mapping_" + kind)
        rows = _table(cap, "/cluster/mapping/" + kind, "id", optional=True)
        if native is None:
            if rows is not None:
                raise CollectError("mapping API inventory has no authoritative native proof")
            continue
        served += 1
        if rows is not None and set(rows) != set(native):
            raise CollectError("mapping API inventory is filtered or changed during capture")
        for identity, config in native.items():
            item = {"config": config}
            if rows is not None:
                item["api"] = _object(cap, "/cluster/mapping/%s/%s" % (kind, identity))
            view[kind + "|" + identity] = item
    if not served:
        raise SkipCheck("resource mapping native modules and APIs are unavailable on this release")
    return cap.result(view)


def _collect_ha(ctx):
    cap = Capture(ctx)
    view = {}
    for family, field in (("resources", "sid"), ("groups", "group"), ("rules", "rule")):
        rows = _table(cap, "/cluster/ha/" + family, field, optional=family in ("groups", "rules"))
        if rows is None:
            continue
        for identity in rows:
            view[family + "|" + identity] = _object(cap, "/cluster/ha/%s/%s" % (family, identity))
    current = _table(cap, "/cluster/ha/status/current", "id")
    for identity, row in current.items():
        view["status|" + identity] = stable(
            row, omit=("timestamp", "last_change", "last_timestamp")
        )
    cap.read("/cluster/ha/status/manager_status")
    cap.context["manager_status"] = "full point-in-time manager/LRM state retained in raw"
    return cap.result(view)


def _collect_backup(ctx):
    cap = Capture(ctx)
    cap.context["data_gaps"] = [
        {
            "source": "backup archive embedded configuration",
            "reason": "API extractconfig requires VM.Backup and Datastore.AllocateSpace privileges",
            "value": (
                "Captured job definitions and backup-volume metadata do not prove archive "
                "configuration"
            ),
        }
    ]
    view = {}
    for identity in _table(cap, "/cluster/backup", "id"):
        view[identity] = {
            "config": _object(cap, "/cluster/backup/" + identity),
            "included_volumes": cap.read("/cluster/backup/%s/included_volumes" % identity),
        }
    cap.read("/cluster/backup-info/not-backed-up", optional=True)
    view["node_defaults"] = _object(cap, "/nodes/%s/vzdump/defaults" % cap.node())
    cap.context["archive_configuration_gap"] = (
        "API extractconfig requires VM.Backup and Datastore.AllocateSpace privileges; archive "
        "bodies are not requested using the read-only account. Full backup-volume attributes are "
        "in the storage check."
    )
    return cap.result(view)


def _collect_replication(ctx):
    cap = Capture(ctx)
    authority = _ssh(cap, C.PROXMOX_ACCESS_COMMAND)
    inventories = authority.get("inventories") if isinstance(authority, dict) else None
    if not isinstance(inventories, dict):
        raise CollectError("authoritative replication source has no native inventories")
    native = _native_inventory(cap, inventories.get("replication"), "replication")
    rows = _table(cap, "/cluster/replication", "id", optional=True)
    if native is None:
        if rows is not None:
            raise CollectError("replication API inventory has no authoritative native proof")
        raise SkipCheck("replication native module and API are unavailable on this release")
    if rows is not None and set(rows) != set(native):
        raise CollectError("replication API inventory is filtered or changed during capture")
    view = {}
    for identity, config in native.items():
        item = {"config": config}
        if rows is not None:
            item["api"] = _object(cap, "/cluster/replication/" + identity)
        view[identity] = item
    node = cap.node()
    # Node replication status carries transient attempt/error state, retained whole in raw.
    base = "/nodes/%s/replication" % node
    local = _table(cap, base, "id", optional=True)
    for identity in local or {}:
        if identity not in native:
            raise CollectError("node replication inventory changed during capture")
        cap.context.setdefault("unstructured_reads", []).append(
            {
                "source": base + "/" + identity + "/log",
                "class": "justified",
                "gap": (
                    "Replication job log details are native line records without structured "
                    "equivalents."
                ),
                "value": (
                    "Complete retained replication logs explain failed synchronization and "
                    "recovery state beside structured status."
                ),
                "exit": "Replace when structured API serves every retained replication log fact.",
            }
        )
        cap.read(base + "/" + identity + "/status")
        cap.paged(base + "/" + identity + "/log")
    cap.context["local_jobs"] = len(local or {})
    return cap.result(view)


def _collect_access(ctx):
    cap = Capture(ctx)
    authority = _ssh(cap, C.PROXMOX_ACCESS_COMMAND)
    policy = authority.get("access") if isinstance(authority, dict) else None
    if not isinstance(policy, dict) or not isinstance(policy.get("users"), dict):
        raise CollectError("authoritative access reader did not return parsed access policy")
    # user.cfg's parser retains all configured policy, including ACLs that the
    # auditor API intentionally hides and tokens whose API needs User.Modify.
    view = stable(policy)
    view["realms"] = {}
    for user in _table(cap, "/access/users", "userid", params={"full": 1}):
        _object(cap, "/access/users/" + user)
    for family, field in (("groups", "groupid"), ("roles", "roleid"), ("domains", "realm")):
        for identity in _table(cap, "/access/" + family, field):
            detail = _object(cap, "/access/%s/%s" % (family, identity))
            if family == "domains":
                view["realms"][identity] = detail
    realm_jobs = _table(cap, "/cluster/jobs/realm-sync", "id", optional=True)
    view["realm_sync_jobs"] = {}
    for identity in realm_jobs or {}:
        detail = _object(cap, "/cluster/jobs/realm-sync/" + identity)
        view["realm_sync_jobs"][identity] = stable(detail, omit=("last-run", "next-run"))
    view["effective_capture_permissions"] = _object(cap, "/access/permissions")
    cap.context["policy_source"] = (
        "Proxmox's parsed user.cfg; API ACLs are visibility-filtered and per-user token APIs "
        "require User.Modify. Configured users/token metadata/ACLs remain complete from the "
        "audited filesystem source."
    )
    return cap.result(view)


def _ordered_rules(cap, path):
    rows = cap.rows(path)
    by_pos = keyed(rows, "pos")
    try:
        return [stable(by_pos[pos], omit=("digest",)) for pos in sorted(by_pos, key=int)]
    except ValueError as exc:
        raise CollectError("firewall rule has a non-numeric position") from exc


def _firewall_scope(cap, base, *, aliases=False, ipsets=False):
    view = {
        "options": _object(cap, base + "/options"),
        "rules": _ordered_rules(cap, base + "/rules"),
    }
    if aliases:
        view["aliases"] = _table(cap, base + "/aliases", "name")
    if ipsets:
        sets = _table(cap, base + "/ipset", "name")
        view["ipsets"] = {
            name: {"config": row, "members": _table(cap, base + "/ipset/" + name, "cidr")}
            for name, row in sets.items()
        }
    return view


def _collect_firewall(ctx):
    cap = Capture(ctx)
    view = {
        "cluster": _firewall_scope(cap, "/cluster/firewall", aliases=True, ipsets=True),
        "node|" + cap.node(): _firewall_scope(cap, "/nodes/%s/firewall" % cap.node()),
    }
    groups = _table(cap, "/cluster/firewall/groups", "group")
    view["security_groups"] = {
        group: {"config": row, "rules": _ordered_rules(cap, "/cluster/firewall/groups/" + group)}
        for group, row in groups.items()
    }
    for identity, _kind, base, _row in guests(cap):
        view[identity] = _firewall_scope(cap, base + "/firewall", aliases=True, ipsets=True)
    return cap.result(view)


def _native_inventory(cap, wrapper, family):
    if not isinstance(wrapper, dict):
        raise CollectError("authoritative %s inventory wrapper is missing" % family)
    source = "native " + family
    outcome = wrapper.get("outcome")
    cap.context["sources"][source] = {
        "outcome": outcome,
        "source": wrapper.get("source"),
        "module": wrapper.get("module"),
    }
    if outcome == "not-present":
        reason = wrapper.get("unavailable_reason")
        if not isinstance(reason, str) or not reason:
            raise CollectError("authoritative %s absence lacks its source reason" % family)
        cap.context["sources"][source]["unavailable_reason"] = reason
        return None
    if outcome != "complete" or not isinstance(wrapper.get("config"), dict):
        raise CollectError("authoritative %s inventory is incomplete" % family)
    entries, identities = wrapper.get("entries"), wrapper.get("identities")
    if (
        not isinstance(entries, list)
        or any(not isinstance(row, dict) for row in entries)
        or not isinstance(identities, list)
        or any(not isinstance(identity, str) or not identity for identity in identities)
    ):
        raise CollectError("authoritative %s identities are malformed" % family)
    by_id = keyed(entries, "identity")
    if len(set(identities)) != len(identities) or set(by_id) != set(identities):
        raise CollectError("authoritative %s entries do not match its identities" % family)
    if any(not isinstance(row.get("config"), dict) for row in entries):
        raise CollectError("authoritative %s entry config is not an object" % family)
    return {identity: stable(row["config"], omit=("digest",)) for identity, row in by_id.items()}


def _sdn_reconcile(cap, path, field, expected, *, params=None):
    rows = _table(cap, path, field, params=params, optional=True)
    if rows is None:
        # The complete native source still captures configured state on a
        # release that does not serve this read-only API shape.
        return None
    if expected is None or set(rows) != set(expected):
        cap.context["visibility_mismatch"] = {
            "source": path,
            "missing": sorted(set(expected or {}) - set(rows)),
            "unexpected": sorted(set(rows) - set(expected or {})),
        }
        raise CollectError("SDN API inventory is filtered or changed during capture")
    return rows


def _route_entry_keys(rows):
    keys = set()
    for row in rows:
        name, order = row.get("route-map-id"), row.get("order")
        if not isinstance(name, str) or type(order) is not int:
            raise CollectError("SDN route-map entry lacks its native identity fields")
        key = (name, order)
        if key in keys:
            raise CollectError("SDN route-map entry identity is duplicated")
        keys.add(key)
    return keys


def _collect_sdn(ctx):
    cap = Capture(ctx)
    authority = _ssh(cap, C.PROXMOX_ACCESS_COMMAND)
    inventories = authority.get("inventories") if isinstance(authority, dict) else None
    if not isinstance(inventories, dict):
        raise CollectError("authoritative SDN source has no native inventories")
    families = (
        ("zones", "sdn_zones"),
        ("controllers", "sdn_controllers"),
        ("vnets", "sdn_vnets"),
        ("subnets", "sdn_subnets"),
        ("ipams", "sdn_ipams"),
        ("dns", "sdn_dns"),
        ("fabrics", "sdn_fabrics"),
        ("fabric-nodes", "sdn_fabric_nodes"),
        ("prefix-lists", "sdn_prefix_lists"),
        ("route-maps", "sdn_route_maps"),
    )
    states = {"configured": {}, "running": {}, "pending": {}}
    for family, source in families:
        states["configured"][family] = _native_inventory(cap, inventories.get(source), source)
    for state in ("running", "pending"):
        wrapper = inventories.get("sdn_" + state)
        if not isinstance(wrapper, dict):
            raise CollectError("authoritative SDN %s source is missing" % state)
        if wrapper.get("outcome") == "not-present":
            _native_inventory(cap, wrapper, "sdn_" + state)
            continue
        if wrapper.get("outcome") != "complete" or not isinstance(wrapper.get("families"), dict):
            raise CollectError("authoritative SDN %s families are incomplete" % state)
        for family, native in wrapper["families"].items():
            normalized_family = "fabric-nodes" if family == "nodes" else family
            states[state][normalized_family] = _native_inventory(
                cap, native, "sdn_%s/%s" % (state, family)
            )
    view = {}
    for state, native_families in states.items():
        for family, entries in native_families.items():
            for identity, config in (entries or {}).items():
                view["%s|%s|%s" % (family, state, identity)] = config
    # Detail GETs for zones/controllers/IPAM/DNS demand SDN.Allocate.
    # Native parsers supply complete configuration without write grants.
    for family, field in (("zones", "zone"), ("controllers", "controller"), ("vnets", "vnet")):
        for state in ("configured", "running", "pending"):
            expected = states[state].get(family)
            if expected is None and state != "configured":
                # Never-applied running configuration has no family key.
                expected = {} if states["configured"].get(family) is not None else None
            params = None if state == "configured" else {state: 1}
            _sdn_reconcile(cap, "/cluster/sdn/" + family, field, expected, params=params)
    for family, field in (("ipams", "ipam"), ("dns", "dns")):
        _sdn_reconcile(cap, "/cluster/sdn/" + family, field, states["configured"].get(family))
        if family == "ipams":
            for identity in states["configured"].get(family) or {}:
                cap.read("/cluster/sdn/ipams/%s/status" % identity)
    for vnet in states["configured"].get("vnets") or {}:
        for state in ("configured", "running", "pending"):
            subnets = states[state].get("subnets") or {}
            expected = {
                identity: config
                for identity, config in subnets.items()
                if config.get("vnet", config.get("pending", {}).get("vnet")) == vnet
            }
            _sdn_reconcile(
                cap,
                "/cluster/sdn/vnets/%s/subnets" % vnet,
                "subnet",
                expected,
                params=None if state == "configured" else {state: 1},
            )
    vnets = set()
    for state in states.values():
        vnets.update(state.get("vnets") or {})
    for identity in sorted(vnets):
        fwbase = "/cluster/sdn/vnets/%s/firewall" % identity
        options = _object(cap, fwbase + "/options", optional=True)
        if options is not None:
            view["vnet-firewall|" + identity] = {
                "options": options,
                "rules": _ordered_rules(cap, fwbase + "/rules"),
            }
    for state in ("configured", "running", "pending"):
        params = None if state == "configured" else {state: 1}
        fabrics = cap.read("/cluster/sdn/fabrics/all", params=params, optional=True)
        if fabrics is not None:
            if not isinstance(fabrics, dict):
                raise CollectError("SDN fabric inventory is not an object")
            for family, field, member in (
                ("fabrics", "id", "fabrics"),
                ("fabric-nodes", "node_id", "nodes"),
            ):
                rows = fabrics.get(member)
                if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
                    raise CollectError("SDN fabric inventory lacks its complete %s array" % member)
                expected = states[state].get(family) or {}
                if set(keyed(rows, field)) != set(expected):
                    raise CollectError(
                        "SDN fabric API inventory is filtered or changed during capture"
                    )
        _sdn_reconcile(
            cap,
            "/cluster/sdn/prefix-lists",
            "id",
            states[state].get("prefix-lists") or {},
            params=params,
        )
        rows = cap.rows("/cluster/sdn/route-maps/entries", params=params, optional=True)
        if rows is not None:
            expected = (states[state].get("route-maps") or {}).values()
            if _route_entry_keys(rows) != _route_entry_keys(expected):
                raise CollectError(
                    "SDN route-map API inventory is filtered or changed during capture"
                )
    if not any(value is not None for value in states["configured"].values()):
        raise SkipCheck("SDN native configuration modules are unavailable on this release")
    cap.context["configuration_source"] = (
        "Full native configured, running and pending SDN parser output; audit-visible API lists "
        "are reconciled against exact native identities. APIs requiring SDN.Allocate are unused."
    )
    return cap.result(view)


def _collect_notifications(ctx):
    cap = Capture(ctx)
    view = {}
    for family in ("sendmail", "gotify", "smtp", "webhook"):
        base = "/cluster/notifications/endpoints/" + family
        rows = _table(cap, base, "name", optional=True)
        for identity in rows or {}:
            view[family + "|" + identity] = _object(cap, base + "/" + identity)
    rows = _table(cap, "/cluster/notifications/matchers", "name", optional=True)
    for identity in rows or {}:
        view["matcher|" + identity] = _object(cap, "/cluster/notifications/matchers/" + identity)
    cap.read("/cluster/notifications/targets", optional=True)
    if not any(value["outcome"] == "complete" for value in cap.context["sources"].values()):
        raise SkipCheck("notification APIs are unavailable on this release")
    return cap.result(view)


def _collect_metrics(ctx):
    cap = Capture(ctx)
    view = {}
    destinations = _table(cap, "/cluster/metrics/server", "id", optional=True)
    if destinations is None:
        raise SkipCheck("metric-server configuration API is unavailable on this release")
    for identity in destinations:
        view[identity] = _object(cap, "/cluster/metrics/server/" + identity)
    cap.context["metric_values"] = (
        "history/export streams are excluded; destination configuration is captured"
    )
    return cap.result(view)


def _collect_services(ctx):
    cap = Capture(ctx)
    base = "/nodes/%s/services" % cap.node()
    view = _table(cap, base, "service")
    for service in view:
        view[service]["observed_state"] = _object(cap, base + "/" + service + "/state")
    return cap.result(view)


def _collect_ceph(ctx):
    cap = Capture(ctx)
    base = "/nodes/%s/ceph" % cap.node()
    # Only verified absence is optional; authorization and other source errors fail.
    index = cap.read(base + "/status", optional=True)
    if index is None:
        raise SkipCheck(
            "PVE-managed Ceph is unavailable or not initialized; source outcome records "
            "the precise evidence"
        )
    health = index.get("health") if isinstance(index, dict) else None
    if not isinstance(health, dict) or not isinstance(health.get("status"), str):
        raise CollectError("Ceph status lacks its required structured health status")
    conditions = health.get("checks", {})
    if not isinstance(conditions, dict) or any(
        not isinstance(detail, dict) for detail in conditions.values()
    ):
        raise CollectError("Ceph health checks are not structured objects")
    view = {
        "health": {
            "status": health["status"],
            "checks": {
                code: {"severity": detail.get("severity")} for code, detail in conditions.items()
            },
        }
    }
    for endpoint in (
        "status",
        "osd",
        "mds",
        "mgr",
        "mon",
        "fs",
        "pool",
        "rules",
        "cfg/db",
    ):
        value = cap.read(base + "/" + endpoint)
        if endpoint in ("status", "osd", "pool"):
            cap.context.setdefault("volatile_ceph_sources", []).append(endpoint)
        else:
            view[endpoint] = value
    # The API /crush returns decompiled CRUSH text. Ceph's native JSON dump
    # preserves devices, buckets, rules, tunables and unmodelled fields.
    crush = _ssh(cap, "ceph osd crush dump --format json")
    if not isinstance(crush, dict):
        raise CollectError("Ceph CRUSH dump did not return a structured object")
    view["crush"] = crush
    cap.context["unstructured_reads"] = [
        {
            "source": base + "/cfg/raw",
            "class": "justified",
            "gap": (
                "Native ceph.conf includes sections and directives beyond the runtime config "
                "database."
            ),
            "value": (
                "Complete Ceph persistent configuration complements structured "
                "health/topology/config database."
            ),
            "exit": "Replace when structured API serves the entire persistent Ceph configuration.",
        }
    ]
    cap.read(base + "/cfg/raw")
    pools = cap.rows(base + "/pool")
    for name in keyed(pools, "pool_name"):
        view["pool|" + name] = stable(
            _object(cap, base + "/pool/" + name),
            omit=(
                "bytes_used",
                "percent_used",
                "stored",
                "objects",
                "read_bytes",
                "write_bytes",
                "read_op_per_sec",
                "write_op_per_sec",
            ),
        )
        cap.read(base + "/pool/%s/status" % name, params={"verbose": 1})
    # CRUSH tree determines OSD identifiers, avoiding an action/status probe.
    osd = cap.read(base + "/osd")

    def visit(row):
        if not isinstance(row, dict):
            raise CollectError("Ceph CRUSH node is not an object")
        if row.get("type") == "osd":
            identity = row.get("id")
            if not isinstance(identity, int) or isinstance(identity, bool) or identity < 0:
                raise CollectError("Ceph OSD has invalid id")
            view["osd|" + str(identity)] = {
                field: row[field]
                for field in ("id", "name", "status", "in", "weight", "reweight", "type")
                if field in row
            }
            view["osd-metadata|" + str(identity)] = _object(
                cap, base + "/osd/%s/metadata" % identity
            )
        children = row.get("children", [])
        if not isinstance(children, list):
            raise CollectError("Ceph CRUSH children are not a list")
        for child in children:
            visit(child)

    if not isinstance(osd, dict) or not isinstance(osd.get("root"), dict):
        raise CollectError("Ceph OSD inventory lacks its structured CRUSH root")
    visit(osd["root"])
    cap.read("/cluster/ceph/status")
    cap.read("/cluster/ceph/metadata")
    view["flags"] = cap.read("/cluster/ceph/flags")
    view["health_mute"] = cap.read("/cluster/ceph/health-mute", optional=True)
    return cap.result(view)


def _window():
    until = datetime.now(timezone.utc)
    since = until - timedelta(hours=C.LOG_WINDOW_HOURS)
    return until, since


def _collect_tasks(ctx):
    cap = Capture(ctx)
    until, since = _window()
    base = "/nodes/%s/tasks" % cap.node()
    active = cap.paged(base, params={"source": "active"})
    recent = cap.paged(
        base,
        params={
            "source": "archive",
            "since": int(since.timestamp()),
            "until": int(until.timestamp()),
        },
    )
    entries = {}
    for row in active + recent:
        identity = row.get("upid")
        if not isinstance(identity, str) or not identity:
            raise CollectError("task row has no UPID")
        if identity in entries and entries[identity] != row:
            raise CollectError("task moved during capture; retry")
        entries[identity] = row
    cap.context["unstructured_reads"] = [
        {
            "source": base + "/<upid>/log",
            "class": "justified",
            "gap": "Task details are native line records without structured field equivalents.",
            "value": (
                "Full retained logs explain backup, replication, storage, migration and "
                "lifecycle task outcomes."
            ),
            "exit": "Replace when structured task evidence provides every retained log fact.",
        }
    ]
    for identity in entries:
        cap.read(base + "/" + identity + "/status")
        cap.paged(base + "/" + identity + "/log")
    cap.context.update(
        {
            "since": since.isoformat(),
            "until": until.isoformat(),
            "active": len(active),
            "recent": len(recent),
            "tasks": len(entries),
        }
    )

    return cap.result({})


def _collect_logs(ctx):
    cap = Capture(ctx)
    until, since = _window()
    nodebase = "/nodes/%s" % cap.node()
    epochs = {"since": int(since.timestamp()), "until": int(until.timestamp())}
    journal = cap.rows(nodebase + "/journal", params={"structured": 1, **epochs}, optional=True)
    cap.context["unstructured_reads"] = []
    if journal is not None:
        cap.context["journal"] = {
            "source": "complete structured journal envelope",
            "records": len(journal),
            "window": epochs,
        }
    else:
        # Older APIs reject only the 'structured' parameter. The transport
        # recognizes that precise capability absence; other errors fail.
        time_config = _object(cap, nodebase + "/time")
        zone_name = time_config.get("timezone")
        if not isinstance(zone_name, str) or not zone_name:
            raise CollectError("bounded syslog capture requires the node timezone")
        try:
            zone = ZoneInfo(zone_name)
        except ZoneInfoNotFoundError as exc:
            raise CollectError("node timezone is unavailable to the capture worker") from exc
        offsets = {
            moment.astimezone(zone).utcoffset()
            for moment in (since - timedelta(days=1), since, until, until + timedelta(days=1))
        }
        margin = max(offsets) - min(offsets)
        local_since = (since.astimezone(zone).replace(tzinfo=None) - margin).strftime(
            "%Y-%m-%d %H:%M:%S"
        )
        local_until = (until.astimezone(zone).replace(tzinfo=None) + margin).strftime(
            "%Y-%m-%d %H:%M:%S"
        )
        cap.context["unstructured_reads"].append(
            {
                "source": nodebase + "/syslog",
                "class": "justified",
                "gap": (
                    "This node does not serve the verified structured journal response; "
                    "bounded syslog serves native lines."
                ),
                "value": (
                    "Full retained events in the window explain transient "
                    "service/kernel/storage/network faults."
                ),
                "exit": "Replace when this node serves the verified structured journal capability.",
            }
        )
        cap.paged(nodebase + "/syslog", params={"since": local_since, "until": local_until})
        cap.context["syslog_window"] = {
            "timezone": zone_name,
            "local_since": local_since,
            "local_until": local_until,
            "dst_margin_seconds": int(margin.total_seconds()),
            "source": "bounded native syslog fallback",
        }
    cap.context["unstructured_reads"].append(
        {
            "source": nodebase + "/firewall/log and local guest firewall/log",
            "class": "justified",
            "gap": (
                "The firewall API serves complete native event lines with no structured "
                "packet/event field equivalent."
            ),
            "value": (
                "Every retained line in the window explains policy drops and packet faults "
                "absent from current rules."
            ),
            "exit": "Replace when the firewall API serves complete structured event objects.",
        }
    )
    cap.paged(nodebase + "/firewall/log", params=epochs)
    for _identity, _kind, base, _row in guests(cap):
        cap.paged(base + "/firewall/log", params=epochs)
    cap.context.update(
        {
            "since": since.isoformat(),
            "until": until.isoformat(),
            "timezone": "UTC",
            "since_epoch": epochs["since"],
            "until_epoch": epochs["until"],
        }
    )
    return cap.result({})


def _add(name, description, collector, semantics, tier=1):
    check_id = "proxmox_" + name
    SEMANTICS[check_id] = semantics
    registry.SEMANTICS[check_id] = semantics
    register(
        CheckDef(
            id=check_id,
            platform="proxmox",
            description=description,
            tier=tier,
            compare={"mode": "equality_set"},
            miss_meaning=(
                "Missing keys indicate changed configured state; a failed API read "
                "records missing evidence, never absence."
            ),
            collector=collector,
            tags=(EMPTY_OK_TAG,),
        )
    )


_add(
    "cluster",
    "Cluster membership/quorum/resources and persistent Corosync configuration",
    _collect_cluster,
    (
        "Shared cluster status and resource topology include all visible nodes/guests/storage. "
        "Instantaneous usage and uptime remain in raw. Corosync nodes/totem/qdevice are captured "
        "when clustered; detailed host/guest capture stays on the selected local node. Failed "
        "visibility proof must fail capture."
    ),
)
_add(
    "pools",
    "Complete resource pool definitions and membership",
    _collect_pools,
    (
        "Every native pool definition and configured membership is retained, including nested "
        "pool IDs and stale references omitted by API runtime membership. API lists must match "
        "native identities; modern poolid query selection preserves complete detail evidence. "
        "Empty configured pools are legitimate; duplicate member identities fail."
    ),
    2,
)
_add(
    "mappings",
    "PCI/USB/directory resource mappings",
    _collect_mappings,
    (
        "Keys kind|id capture complete native mapping definitions, including every per-node "
        "mapping and unknown field. API lists must match native identities; an unavailable API "
        "does not discard configured native evidence. Release capability absence is explicit; "
        "authorization failure is not absence."
    ),
    2,
)
_add(
    "ha",
    "HA resources/groups/affinity rules and observed cluster states",
    _collect_ha,
    (
        "Every configured HA resource, group and affinity rule is captured with full "
        "detail. Shared "
        "HA current states are keyed by id without heartbeat timestamps; full manager/LRM "
        "point-in-time state remains in raw."
    ),
)
_add(
    "backup",
    "Backup schedules, included volumes and uncovered guest evidence",
    _collect_backup,
    (
        "Each backup job retains full schedule/retention/options and its complete included-volume "
        "view. Uncovered guest inventory is raw. Empty schedules are legitimate; external PBS "
        "internals are outside this PVE capture."
    ),
    2,
)
_add(
    "replication",
    "Replication jobs/configuration and local operational status",
    _collect_replication,
    (
        "Each native replication id keeps every configured job field, including references to "
        "deleted guests. API lists must match native identities. Full local status and retained "
        "logs are raw rather than stable assertions; no job is omitted because it is disabled "
        "or failing, or because its API is unavailable."
    ),
)
_add(
    "access",
    "Users/groups/roles/realms/tokens/ACL and effective capture permissions",
    _collect_access,
    (
        "Every configured access identity, token metadata, role, group, realm and ACL is captured; "
        "credentials, TFA key material and personal contacts are scrubbed. Effective caller "
        "permissions are explicit. Local configured account names identify "
        "configuration; logged-in "
        "operators are not inventory."
    ),
    2,
)
_add(
    "firewall",
    "Datacenter/node/guest firewall policy with ordered rules and all sets",
    _collect_firewall,
    (
        "Cluster, selected node and every local guest carry effective options and "
        "complete rules in "
        "numeric position order. Cluster/guest aliases and IP sets include every member; security "
        "groups retain their ordered rules. Disabled policy remains captured."
    ),
    2,
)
_add(
    "sdn",
    "SDN configured/running/pending state and all subnet/firewall definitions",
    _collect_sdn,
    (
        "Authoritative native configured, running and pending SDN state retains all objects and "
        "unknown fields, including deleted and pending objects. Served API lists must match "
        "native identities. Zones/controllers/VNets/subnets, IPAM/DNS, fabrics and nodes, prefix "
        "lists, route-map entries and ordered VNet firewall rules are captured. Unsupported "
        "release families are explicit; permission failures fail the read."
    ),
    2,
)
_add(
    "notifications",
    "Notification endpoint/matcher/target configuration",
    _collect_notifications,
    (
        "All available sendmail/Gotify/SMTP/webhook endpoints and matchers retain every non-secret "
        "option; target resolution is full raw. No test-send action runs. An absent "
        "notification API "
        "on older releases is explained."
    ),
    2,
)
_add(
    "metric_config",
    "Configured external metric destinations",
    _collect_metrics,
    (
        "Every configured metric-server id retains complete destination/options with credentials "
        "scrubbed. Time-series values/history/export streams are intentionally excluded; "
        "this check "
        "records the persistent collection configuration."
    ),
)
_add(
    "host_services",
    "Every API-reported local service and observed state",
    _collect_services,
    (
        "Services are keyed by native unit identity with state/detail. Every "
        "API-reported service is "
        "read, including inactive or failed units; arbitrary host processes and logs are "
        "not used as "
        "stable identities."
    ),
)
_add(
    "ceph",
    "Ceph configuration/topology/storage/health and complete local evidence",
    _collect_ceph,
    (
        "PVE-managed Ceph retains config database and native config text, CRUSH topology, all OSD "
        "metadata, monitors/managers/MDS/filesystems/pools/rules/flags/mutes. Full "
        "health, usage and "
        "status payloads are raw; native configuration text is a declared justified read. An "
        "uninitialized Ceph capability is explicitly not-present; other failures remain failed."
    ),
    2,
)
_add(
    "tasks",
    "All active tasks and complete recent retained task logs",
    _collect_tasks,
    (
        "All active tasks plus every archived task in a fixed 24-hour UTC window are paged to "
        "exhaustion; every retained task status/log is raw, with no row or byte cap. "
        "Context states "
        "coverage and counts. Churning task identities/outcomes are informational, not stable diff "
        "keys."
    ),
    3,
)
_add(
    "event_logs",
    "Complete retained syslog and node/guest firewall event evidence",
    _collect_logs,
    (
        "Complete structured journal records and node/local-guest firewall event lines in the "
        "configured UTC window are captured. Unsupported structured journal capability uses "
        "bounded syslog paged to exhaustion. Syslog wall-clock filters use the node timezone "
        "and expand "
        "around DST "
        "ambiguity; context states the exact queried interval. All redacted native lines and API "
        "envelopes remain raw; times/messages are informational. Pagination failure cannot be "
        "reported as a complete empty log."
    ),
    3,
)
