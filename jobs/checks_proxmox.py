"""Complete Proxmox VE host, Linux network, and storage capture.

API envelopes and structured Linux replies are retained without curation or caps.
Only explicitly volatile fields leave normalized views; unknown configuration
fields survive. Fixed SSH supplements run through the same read-only context.
"""

import copy
import json
import re

from . import constants as C
from .proxmox_common import Capture, keyed, scrub, scrub_text, stable
from .proxmox_paths import volume_path
from .registry import SEMANTICS as REGISTRY_SEMANTICS
from .registry import CheckDef, CollectError, register

_LINK = "ip -j -s -d link show"
_ADDRESS = "ip -j address show"
_HARDWARE = "lshw -json"
_BLOCK = "lsblk --json --bytes --output-all"
_NEIGHBORS = "lldpcli -f json0 show neighbors details hidden"
_SYNC = (
    "busctl --json=short get-property org.freedesktop.timedate1 "
    "/org/freedesktop/timedate1 org.freedesktop.timedate1 NTPSynchronized"
)


def _object(value, source):
    if not isinstance(value, dict):
        raise CollectError("%s: expected a structured object" % source)
    return value


def _rows(value, source):
    if not isinstance(value, list) or any(not isinstance(row, dict) for row in value):
        raise CollectError("%s: expected a list of structured objects" % source)
    return value


def _ssh(cap, command):
    """Cache complete, redacted JSON; reject missing tools and shell diagnostics."""
    cache = cap.ctx._cache
    key = ("proxmox-ssh-json", command)
    label = {
        C.PROXMOX_CONFIG_COMMAND: "native configuration JSON reader",
        C.PROXMOX_HARDWARE_COMMAND: "named kernel hardware JSON reader",
        C.PROXMOX_ACCESS_COMMAND: "authoritative Proxmox policy and inventory JSON reader",
        C.PROXMOX_PACKAGES_COMMAND: "complete Debian package JSON reader",
    }.get(command, command)

    def redact(text):
        # A command diagnostic is not parsed as data, but is still sanitized
        # before the SSH trace can retain it.
        try:
            return json.dumps(scrub(json.loads(text)), ensure_ascii=False)
        except (ValueError, TypeError):
            return "[withheld: malformed structured SSH output]" if text else ""

    if key not in cache:
        try:
            output = cap.ctx.run_ssh(command, redact=redact)
        except Exception as exc:
            if type(exc).__name__ == "SoftTimeLimitExceeded":
                raise
            evidence = getattr(cap.ctx, "_last_ssh_result", None)
            if evidence is not None:
                cap.raw["SSH " + command] = copy.deepcopy(evidence)
            cap.context["sources"]["SSH " + label] = {"outcome": "refused"}
            raise CollectError(
                "%s: required Linux supplement failed: %s" % (label, scrub_text(str(exc)))
            ) from exc
        try:
            cache[key] = scrub(json.loads(output))
        except (ValueError, TypeError) as exc:
            cap.raw["SSH " + command] = {"diagnostic": scrub_text(output)}
            cap.context["sources"]["SSH " + label] = {"outcome": "malformed"}
            raise CollectError(
                "%s: required Linux supplement did not return JSON (tool, privilege or service gap)"
                % label
            ) from exc
        evidence = getattr(cap.ctx, "_last_ssh_result", None)
        if evidence is not None:
            cache[("proxmox-ssh-evidence", command)] = copy.deepcopy(evidence)
    value = copy.deepcopy(cache[key])
    cap.raw["SSH " + command] = value
    evidence = cache.get(("proxmox-ssh-evidence", command))
    if evidence is not None and evidence.get("stderr"):
        cap.raw["SSH " + command + " stderr"] = evidence["stderr"]
    cap.context["sources"]["SSH " + label] = {"outcome": "complete", "format": "json"}
    return value


def _config_sources(cap):
    cap.context["unstructured_reads"] = [
        {
            "source": "named network, time and logging configuration files and native includes",
            "class": "justified",
            "gap": "API does not preserve complete native applied host configuration",
            "value": "complete native configuration and included-source provenance",
            "exit": "structured source demonstrated complete on the fleet release",
        }
    ]
    data = _object(_ssh(cap, C.PROXMOX_CONFIG_COMMAND), "native configuration reader")
    files = _rows(data.get("files"), "native configuration files")
    if not isinstance(data.get("errors"), list) or data["errors"]:
        raise CollectError("native configuration reader reported an incomplete read")
    absent = data.get("absent")
    if not isinstance(absent, list) or any(not isinstance(path, str) for path in absent):
        raise CollectError("native configuration absent-source provenance is malformed")
    for include in _rows(data.get("includes"), "native included-source provenance"):
        if (
            not isinstance(include.get("source"), str)
            or not isinstance(include.get("pattern"), str)
            or not isinstance(include.get("matches"), list)
            or any(not isinstance(path, str) for path in include["matches"])
        ):
            raise CollectError("native configuration include resolution is malformed")
    seen = set()
    declarations = []
    for item in files:
        path, content = item.get("path"), item.get("content")
        if not isinstance(path, str) or not isinstance(content, str) or path in seen:
            raise CollectError("native configuration source identity or content is malformed")
        seen.add(path)
        declarations.append(
            {
                "source": path,
                "class": "justified",
                "gap": "API does not preserve complete native applied %s configuration"
                % item.get("category", "host"),
                "value": "complete native configuration and included-source provenance",
                "exit": "structured source demonstrated complete on the fleet release",
            }
        )
    cap.context["unstructured_reads"] = declarations
    cap.context["native_files"] = len(files)
    cap.context["native_absent"] = absent
    return data


def _hardware(cap):
    value = _ssh(cap, _HARDWARE)
    roots = value if isinstance(value, list) else [value]
    return _rows(roots, _HARDWARE)


def _kernel(cap):
    cap.context.setdefault("unstructured_reads", []).append(
        {
            "source": "/proc/cmdline",
            "class": "justified",
            "gap": "API does not expose complete applied kernel boot arguments",
            "value": "native boot command line including unknown options",
            "exit": "structured boot argument source demonstrated complete on fleet release",
        }
    )
    facts = _object(_ssh(cap, C.PROXMOX_HARDWARE_COMMAND), "kernel hardware reader")
    if not isinstance(facts.get("errors"), list) or facts["errors"]:
        raise CollectError("kernel hardware reader reported an incomplete read")
    return facts


def _tree(rows, prefix, omit=()):
    """Flatten a hardware/tree API without replacing native identities with array positions."""
    out = {}

    def walk(items, parent):
        seen = set()
        for item in _rows(items, prefix):
            identity = item.get("id", item.get("name"))
            if not isinstance(identity, str) or not identity or identity in seen:
                raise CollectError("%s: missing or duplicate tree identity" % prefix)
            seen.add(identity)
            path = parent + "/" + identity
            out[prefix + path] = stable(item, ("children",) + tuple(omit))
            children = item.get("children", [])
            walk(children, path)

    walk(rows, "")
    return out


def _collect_host_identity(ctx):
    cap = Capture(ctx)
    node = cap.node()
    version = _object(cap.read("/nodes/%s/version" % node), "node version")
    status = _object(cap.read("/nodes/%s/status" % node), "node status")
    roots = _hardware(cap)
    systems = [row for row in roots if row.get("class") == "system"]
    if len(systems) != 1:
        raise CollectError("lshw did not identify exactly one physical system")
    normalized = {"node|" + node: {"version": version, "system": stable(systems[0], ("children",))}}
    state = stable(
        status, ("cpu", "wait", "loadavg", "uptime", "idle", "ksm", "memory", "swap", "rootfs")
    )
    for field in ("memory", "swap", "rootfs"):
        if field in status:
            state[field] = stable(
                _object(status[field], field), ("free", "used", "avail", "available")
            )
    normalized["status|" + node] = state
    cap.context["uptime_seconds"] = status.get("uptime")
    return cap.result(normalized)


def _collect_hardware_inventory(ctx):
    cap = Capture(ctx)
    node = cap.node()
    pci = cap.rows(
        "/nodes/%s/hardware/pci" % node, params={"verbose": 1, "pci-class-blacklist": ""}
    )
    normalized = keyed(pci, "id", "pci|")
    hardware = _tree(_hardware(cap), "hardware|")
    for device in hardware.values():
        if isinstance(device.get("configuration"), dict):
            device["configuration"] = stable(device["configuration"], ("ip",))
    normalized.update(hardware)
    kernel = _kernel(cap)
    normalized.update(keyed(_rows(kernel.get("pci"), "kernel PCI"), "id", "pci_runtime|"))
    normalized.update(
        keyed(_rows(kernel.get("iommu_groups"), "IOMMU groups"), "id", "iommu_group|")
    )
    normalized["cpu_runtime"] = _object(kernel.get("cpu"), "kernel CPU topology")
    normalized["sysctl"] = _object(kernel.get("sysctl"), "kernel settings")
    normalized["kvm"] = _object(kernel.get("kvm"), "KVM module parameters")
    normalized.update(keyed(_rows(kernel.get("numa"), "NUMA nodes"), "id", "numa|"))
    hugepages = _rows(kernel.get("hugepages"), "hugepage allocations")
    normalized.update(
        _sequence_rows(
            [
                stable(row, ("free_hugepages", "surplus_hugepages", "resv_hugepages"))
                for row in hugepages
            ],
            "hugepages|",
            ("node", "size_kb"),
        )
    )
    cap.context["pci_devices"] = len(pci)
    cap.context["hardware_devices"] = len(hardware)
    cap.context["kernel_unavailable_attributes"] = len(kernel.get("unavailable", []))
    cap.context["usb_source"] = "lshw JSON (USB API requires Sys.Modify)"
    return cap.result(normalized)


def _network(cap):
    node = cap.node()
    path = "/nodes/%s/network" % node
    configured = cap.rows(path)
    links = _rows(_ssh(cap, _LINK), _LINK)
    addresses = _rows(_ssh(cap, _ADDRESS), _ADDRESS)
    return path, configured, links, addresses


def _collect_network(ctx):
    cap = Capture(ctx)
    path, configured, links, addresses = _network(cap)
    normalized = keyed(configured, "iface", "config|")
    normalized.update(
        keyed(
            [stable(row, ("stats", "stats64", "statistics", "xstats")) for row in links],
            "ifname",
            "link|",
        )
    )
    address_state = []
    for address in addresses:
        row = stable(address)
        if "addr_info" in row:
            row["addr_info"] = [
                stable(item, ("valid_life_time", "preferred_life_time"))
                for item in _rows(row["addr_info"], "interface addresses")
            ]
        address_state.append(row)
    normalized.update(keyed(address_state, "ifname", "address|"))
    # The API returns the pending table and the diff as an ENVELOPE attribute.
    # Preserve that distinction; operational Linux JSON is the applied state.
    changes = cap.envelope(path).get("changes")
    cap.context["pending_changes_present"] = changes not in (None, "", [], {})
    cap.context["configured_interfaces"] = len(configured)
    cap.context["runtime_interfaces"] = len(links)
    _config_sources(cap)
    return cap.result(normalized)


def _collect_pnics(ctx):
    cap = Capture(ctx)
    _path, _configured, links, _addresses = _network(cap)
    link_map = keyed(links, "ifname")
    kernel = _kernel(cap)
    kernel_links = keyed(_rows(kernel.get("net"), "kernel network interfaces"), "name")
    normalized = {}
    for path, device in _tree(_hardware(cap), "hardware|").items():
        if device.get("class") != "network":
            continue
        names = device.get("logicalname", [])
        names = [names] if isinstance(names, str) else names
        if not isinstance(names, list):
            raise CollectError("lshw network logical names are malformed")
        row = stable(device)
        config = row.get("configuration")
        if isinstance(config, dict):
            row["configuration"] = stable(config, ("ip",))
        row["interfaces"] = {
            name: stable(link_map[name], ("stats", "stats64", "statistics", "xstats"))
            for name in names
            if name in link_map
        }
        row["unresolved_interfaces"] = [name for name in names if name not in link_map]
        row["kernel_interfaces"] = {
            name: kernel_links[name] for name in names if name in kernel_links
        }
        normalized["pnic|" + path[len("hardware|") :]] = row
    cap.context["physical_nics"] = len(normalized)
    return cap.result(normalized)


def _sequence_rows(rows, prefix, fields):
    out = {}
    for row in _rows(rows, prefix):
        identity = json.dumps(
            [row.get(field) for field in fields], separators=(",", ":"), sort_keys=True
        )
        key = prefix + identity
        if key in out:
            raise CollectError("%s: duplicate natural identity" % prefix)
        out[key] = stable(row, ("expires", "used", "lastuse", "confirmed", "updated"))
    return out


def _collect_host_routes(ctx):
    cap = Capture(ctx)
    node = cap.node()
    normalized = {"dns": _object(cap.read("/nodes/%s/dns" % node), "node DNS")}
    for family in (4, 6):
        command = "ip -j -%d route show table all" % family
        normalized.update(
            _sequence_rows(
                _ssh(cap, command),
                "route|ipv%d|" % family,
                ("table", "dst", "metric", "type", "tos", "dev"),
            )
        )
    normalized.update(
        _sequence_rows(
            _ssh(cap, "ip -j rule show"),
            "rule|",
            ("priority", "src", "dst", "table", "fwmark", "iif", "oif"),
        )
    )
    # ARP/NDP is complete diagnostic data, but ages/probe state are not stable configuration.
    neighbors = _rows(_ssh(cap, "ip -j neighbor show"), "ARP/NDP")
    cap.context["neighbor_entries"] = len(neighbors)
    return cap.result(normalized)


def _collect_neighbors(ctx):
    cap = Capture(ctx)
    reply = _object(_ssh(cap, _NEIGHBORS), "LLDP")
    roots = _rows(reply.get("lldp"), "LLDP roots")
    interfaces = []
    for root in roots:
        interfaces.extend(_rows(root.get("interface", []), "LLDP interfaces"))
    # json0 deliberately uses arrays, unlike the ambiguous single-element JSON format.
    interfaces = _rows(interfaces, "LLDP interfaces")
    normalized = {}
    for item in interfaces:
        name = item.get("name")
        if not isinstance(name, str) or not name:
            raise CollectError("LLDP local interface name is missing")
        chassis = _rows(item.get("chassis"), "LLDP chassis")
        ports = _rows(item.get("port"), "LLDP port")
        if not chassis or not ports:
            raise CollectError("LLDP neighbor has no chassis or port identity")
        for endpoint in chassis + ports:
            ids = _rows(endpoint.get("id"), "LLDP endpoint identifiers")
            if not ids or any(not row.get("type") or not row.get("value") for row in ids):
                raise CollectError("LLDP neighbor identity is incomplete")
        identity = json.dumps(
            [[row.get("id") for row in chassis], [row.get("id") for row in ports]],
            sort_keys=True,
            separators=(",", ":"),
        )
        key = "lldp|" + name + "|" + identity
        if key in normalized:
            raise CollectError("duplicate LLDP neighbor identity")
        row = stable(item, ("age", "rid"))
        row["port"] = [stable(port, ("ttl",)) for port in ports]
        normalized[key] = row
    cap.context["lldp_neighbors"] = len(normalized)
    return cap.result(normalized)


def _collect_host_time(ctx):
    cap = Capture(ctx)
    node = cap.node()
    time = _object(cap.read("/nodes/%s/time" % node), "node time")
    sync = _object(_ssh(cap, _SYNC), "time synchronization")
    if (
        sync.get("type") != "b"
        or not isinstance(sync.get("data"), list)
        or len(sync["data"]) != 1
        or not isinstance(sync["data"][0], bool)
    ):
        raise CollectError("time synchronization reply is not a D-Bus boolean")
    normalized = {"time": stable(time, ("time", "localtime")), "ntp_synchronized": sync["data"][0]}
    _config_sources(cap)
    return cap.result(normalized)


def _collect_packages(ctx):
    cap = Capture(ctx)
    node = cap.node()
    versions = cap.rows("/nodes/%s/apt/versions" % node)
    updates = cap.rows("/nodes/%s/apt/update" % node)
    repositories = _object(cap.read("/nodes/%s/apt/repositories" % node), "repositories")
    normalized = keyed(versions, "Package", "package|")
    normalized.update(keyed(updates, "Package", "update|"))
    normalized["repositories"] = repositories
    installed = _rows(_ssh(cap, C.PROXMOX_PACKAGES_COMMAND), "complete package inventory")
    normalized.update(keyed(installed, "package", "installed_package|"))
    cap.context["package_scope"] = (
        "all dpkg package states plus API Proxmox package metadata; "
        "update list from existing cache, never refreshed"
    )
    cap.context["installed_packages"] = len(installed)
    cap.context["packages"] = len(versions)
    cap.context["updates"] = len(updates)
    return cap.result(normalized)


def _collect_host_config(ctx):
    cap = Capture(ctx)
    node = cap.node()
    normalized = {
        "node": _object(cap.read("/nodes/%s/config" % node), "node configuration"),
        "datacenter": _object(cap.read("/cluster/options"), "datacenter options"),
    }
    _config_sources(cap)
    return cap.result(normalized)


def _local_definition(row, node):
    nodes = row.get("nodes")
    if isinstance(nodes, str):
        return node in nodes.split(",")
    if isinstance(nodes, list):
        return node in nodes
    if nodes is None:
        return True
    raise CollectError("storage node restriction has a malformed type")


def _collect_storage(ctx):
    cap = Capture(ctx)
    node = cap.node()
    definitions = cap.rows("/storage")
    listed = cap.rows("/nodes/%s/storage" % node)
    status_map = keyed(listed, "storage")
    normalized = {}
    volume_count = 0
    for storage, listed_definition in keyed(definitions, "storage").items():
        path = "/storage/" + storage
        definition = _object(cap.read(path), "storage definition")
        # List entries can expose extension fields not repeated by the detail.
        normalized["storage_config|" + storage] = {
            "listing": listed_definition,
            "definition": definition,
        }
        if not _local_definition(definition, node):
            continue
        if storage not in status_map:
            raise CollectError(
                "local configured storage %s omitted from node status listing" % storage
            )
        status = _object(
            cap.read("/nodes/%s/storage/%s/status" % (node, storage)), "storage status"
        )
        normalized["storage|" + storage] = stable(status, ("avail", "used", "used_fraction"))
        if not status.get("enabled") or not status.get("active"):
            cap.context.setdefault("content_unavailable", []).append(storage)
            continue
        contents = cap.rows("/nodes/%s/storage/%s/content" % (node, storage))
        volumes = keyed(contents, "volid", "volume|")
        for key, volume in volumes.items():
            if key in normalized:
                raise CollectError("duplicate storage volume identity")
            normalized[key] = stable(volume, ("used", "ctime", "verification"))
            attributes = _object(
                cap.read(volume_path(node, storage, volume["volid"])), "volume attributes"
            )
            normalized[key]["attributes"] = stable(attributes, ("used",))
        volume_count += len(volumes)
    extra = sorted(set(status_map) - set(keyed(definitions, "storage")))
    if extra:
        raise CollectError("node storage listing contains unlisted definitions")
    cap.context["storage_definitions"] = len(definitions)
    cap.context["local_storage"] = len(listed)
    cap.context["volumes"] = volume_count
    return cap.result(normalized)


def _collect_storage_devices(ctx):
    cap = Capture(ctx)
    node = cap.node()
    base = "/nodes/%s/disks" % node
    disks = cap.rows(base + "/list", params={"include-partitions": 1})
    normalized = keyed(disks, "devpath", "disk|")
    directory = cap.rows(base + "/directory")
    normalized.update(keyed(directory, "path", "directory|"))
    lvm = _object(cap.read(base + "/lvm"), "LVM")
    normalized.update(_tree(_rows(lvm.get("children", []), "LVM groups"), "lvm|", ("free",)))
    thin = cap.rows(base + "/lvmthin")
    normalized.update(
        _sequence_rows(
            [stable(row, ("metadata_used", "used")) for row in thin], "lvmthin|", ("vg", "lv")
        )
    )
    pools = cap.rows(base + "/zfs")
    for name, pool in keyed(pools, "name").items():
        normalized["zpool|" + name] = stable(pool, ("alloc", "free", "frag", "dedup"))
        detail = _object(cap.read(base + "/zfs/" + name), "ZFS pool detail")

        def without_counters(value):
            if isinstance(value, dict):
                return {
                    key: without_counters(item)
                    for key, item in value.items()
                    if key not in ("scan", "read", "write", "cksum")
                }
            if isinstance(value, list):
                return [without_counters(item) for item in value]
            return value

        normalized["zpool_status|" + name] = without_counters(detail)
    block = _object(_ssh(cap, _BLOCK), "block inventory")
    normalized.update(
        _tree(
            _rows(block.get("blockdevices"), "block devices"),
            "block|",
            ("fsavail", "fsused", "fsuse%", "disc-aln"),
        )
    )
    for disk in disks:
        if disk.get("parent"):
            continue
        path = disk["devpath"]
        if not isinstance(path, str) or re.fullmatch(r"/dev/[A-Za-z0-9_.+-]+", path) is None:
            raise CollectError("malformed disk device path")
        smart = _object(cap.read(base + "/smart", params={"disk": path, "healthonly": 0}), "SMART")
        normalized["smart|" + path] = stable(smart, ("attributes", "text"))
        if smart.get("text"):
            cap.context.setdefault("unstructured_reads", []).append(
                {
                    "source": base + "/smart?disk=" + path,
                    "class": "justified",
                    "gap": "SMART API exposes device detail in native text",
                    "value": "complete SMART diagnostic evidence alongside structured attributes",
                    "exit": "structured SMART source demonstrated complete for this disk type",
                }
            )
    cap.context["disks_and_partitions"] = len(disks)
    cap.context["zfs_pools"] = len(pools)
    return cap.result(normalized)


def _collect_subscription(ctx):
    cap = Capture(ctx)
    node = cap.node()
    subscription = _object(cap.read("/nodes/%s/subscription" % node), "subscription")
    return cap.result(
        {"subscription": stable(subscription, ("checktime", "key", "signature", "serverid"))}
    )


def _collect_certificates(ctx):
    cap = Capture(ctx)
    rows = cap.rows("/nodes/%s/certificates/info" % cap.node())
    normalized = keyed([stable(row, ("pem",)) for row in rows], "filename", "certificate|")
    cap.context["certificates"] = len(rows)
    return cap.result(normalized)


def _collect_metrics(ctx):
    cap = Capture(ctx)
    node = cap.node()
    params = {"timeframe": "day", "cf": "AVERAGE"}
    host = cap.rows("/nodes/%s/rrddata" % node, params=params)
    statuses = cap.rows("/nodes/%s/storage" % node)
    counts = {"node": len(host)}
    for storage, status in keyed(statuses, "storage").items():
        if status.get("enabled") and status.get("active"):
            points = cap.rows("/nodes/%s/storage/%s/rrddata" % (node, storage), params=params)
            counts[storage] = len(points)
    cap.context["sample_counts"] = counts
    cap.context["window"] = "device RRD day archive (24 hours), AVERAGE; source timestamps retained"
    return cap.result({})


SEMANTICS = {
    "proxmox_host_identity": (
        "Node identity, PVE version and complete lshw system metadata; boot mode, kernel and "
        "CPU topology from node status. Memory/rootfs/swap totals are stable; live usage and "
        "uptime remain in full raw. Unknown fields survive."
    ),
    "proxmox_hardware_inventory": (
        "Every PCI function (empty class blacklist, verbose) and complete lshw hardware tree "
        "including CPUs, memory, USB and driver bindings. Native id/name tree paths are "
        "keys; duplicates fail. Named kernel JSON includes applied driver/VF/IOMMU bindings, "
        "CPU isolation, NUMA, hugepage allocations, KVM parameters and sysctl values; boot "
        "arguments remain justified native text in raw. USB comes from Linux because its "
        "API requires Sys.Modify."
    ),
    "proxmox_network": (
        "Complete API network configuration, including unknown options, keyed by iface; the "
        "API top-level changes diff is retained in raw and flags pending changes in context. "
        "Linux link/address JSON proves applied state. Native applied files and includes are "
        "retained only because the API does not expose their complete contents."
    ),
    "proxmox_pnics": (
        "Every lshw network device with logical-interface joins to full Linux link state; "
        "driver, firmware, capability, speed/duplex, MAC and PCI/USB provenance remain "
        "available wherever served. Statistics and dynamic hardware IP are raw-only; "
        "unresolved interfaces are explicit."
    ),
    "proxmox_host_routes": (
        "Complete IPv4/IPv6 routes from every table and policy rules, keyed by native "
        "route/rule facets, plus API DNS. Expiry/age readings and full ARP/NDP rows remain "
        "in raw. Equal natural keys are refused rather than overwritten."
    ),
    "proxmox_neighbors": (
        "Complete LLDP neighbors from json0 structured output with local-interface and "
        "native chassis identity; timers remain raw. Missing lldpcli, service/privilege "
        "failure and malformed output are failed evidence reads; a healthy empty neighbor "
        "list is empty data."
    ),
    "proxmox_host_time": (
        "Timezone and live NTP synchronization from node/time and typed D-Bus JSON. Native "
        "time/logging daemon sources and includes remain complete in raw with unstructured "
        "justification; clocks remain raw to avoid comparing advancing time."
    ),
    "proxmox_packages": (
        "Every Debian package/version/architecture/status record, important Proxmox package "
        "records served by apt/versions, the full existing "
        "cached update listing, and complete repository definitions/errors. No package "
        "database refresh or update is performed. Unknown extension fields survive."
    ),
    "proxmox_host_config": (
        "Complete structured node configuration and datacenter options, retaining unknown "
        "fields. Applied network, time and logging native sources and all safely resolved "
        "includes are complete text evidence with source/absence/include provenance; "
        "incomplete reader results fail."
    ),
    "proxmox_storage": (
        "Every cluster storage definition and complete per-local-store "
        "configuration/status/content metadata. Storage ids join volumes by volid. "
        "Disabled/inactive stores are explicit unavailable content sources; a missing status "
        "for a locally configured store fails. Usage/time readings remain raw."
    ),
    "proxmox_storage_devices": (
        "Every disk/partition, directory filesystem, LVM group/PV, thin pool, ZFS pool/vdev "
        "and full Linux block tree with native identity links. SMART structured health is "
        "normalized; complete attributes and necessary diagnostic text remain raw. No device "
        "is silently filtered or capped."
    ),
    "proxmox_subscription": (
        "Subscription status, level, product, socket entitlement and dates; "
        "key/signature/server identifier are withheld and last-check time remains raw. No "
        "subscription revalidation is triggered."
    ),
    "proxmox_certificates": (
        "Every node certificate metadata record keyed by filename, including "
        "issuer/subject/SAN/validity/fingerprint and public-key type/bits. PEM certificate "
        "bodies are redacted before trace/cache/raw and omitted from normalized."
    ),
    "proxmox_metrics": (
        "Complete node and enabled active storage RRD day archives (24 hours, AVERAGE) with "
        "timestamps and all served readings in raw. Context contains only sample "
        "counts/window; the informational collector makes no assertions about normal "
        "utilization."
    ),
}

_COLLECTORS = (
    ("host_identity", _collect_host_identity, 1, "platform"),
    ("hardware_inventory", _collect_hardware_inventory, 2, "hardware"),
    ("network", _collect_network, 1, "interfaces"),
    ("pnics", _collect_pnics, 1, "interfaces"),
    ("host_routes", _collect_host_routes, 2, "routing"),
    ("neighbors", _collect_neighbors, 2, "topology"),
    ("host_time", _collect_host_time, 1, "services"),
    ("packages", _collect_packages, 2, "platform"),
    ("host_config", _collect_host_config, 2, "config"),
    ("storage", _collect_storage, 1, "storage"),
    ("storage_devices", _collect_storage_devices, 1, "storage"),
    ("subscription", _collect_subscription, 3, "licensing"),
    ("certificates", _collect_certificates, 1, "security"),
    ("metrics", _collect_metrics, 3, "metrics"),
)
for _suffix, _collector, _tier, _tag in _COLLECTORS:
    _id = "proxmox_" + _suffix
    register(
        CheckDef(
            id=_id,
            platform="proxmox",
            description=SEMANTICS[_id].split(".")[0],
            tier=_tier,
            compare={"mode": "info_only" if _suffix == "metrics" else "equality_set"},
            miss_meaning=(
                "Observed Proxmox platform state differs; use complete source evidence "
                "and declared read gaps to interpret it."
            ),
            collector=_collector,
            tags=(_tag,),
        )
    )
REGISTRY_SEMANTICS.update(SEMANTICS)
