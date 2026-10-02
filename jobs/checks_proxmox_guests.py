"""Read-only QEMU and LXC capture, independent of change intent.

The API's property-string values are a configuration grammar, not display
text. Preserve the original JSON in raw and parse that grammar into named
fields for device joins. No guest, template, stopped guest or device is capped.
"""

import re

from . import registry
from .proxmox_common import Capture, keyed, property_string, stable
from .registry import EMPTY_OK_TAG, CheckDef, CollectError, SkipCheck, register

SEMANTICS = {}
_DEVICE = re.compile(r"^(net|ide|sata|scsi|virtio|hostpci|usb|mp|unused|efidisk|tpmstate)\d+$")
_DISK = re.compile(r"^(ide|sata|scsi|virtio|mp|unused|efidisk|tpmstate)\d+$|^rootfs$")
_NIC = re.compile(r"^net\d+$|^hostpci\d+$|^usb\d+$")
_VOLATILE = ("cpu", "mem", "disk", "diskread", "diskwrite", "netin", "netout", "uptime", "pid")


def guests(cap):
    """Enumerate both local guest families without a running/status filter."""
    node = cap.node()
    status = cap.rows("/cluster/status")
    cluster = next((row.get("name") for row in status if row.get("type") == "cluster"), None)
    scope = "cluster:" + str(cluster) if cluster else "node:" + node
    cap.context["guest_scope"] = scope
    result = []
    seen = set()
    for kind in ("qemu", "lxc"):
        for row in cap.rows("/nodes/%s/%s" % (node, kind)):
            vmid = str(row.get("vmid", ""))
            if not vmid.isascii() or not vmid.isdigit() or not 100 <= int(vmid) <= 999999999:
                raise CollectError("%s inventory row has no valid vmid" % kind)
            key = "%s|%s|%s" % (scope, kind, vmid)
            if key in seen:
                raise CollectError("duplicate guest identity %s" % key)
            seen.add(key)
            result.append((key, kind, "/nodes/%s/%s/%s" % (node, kind, vmid), row))
    cap.context["guests_total"] = len(result)
    return result


def _config(cap, base):
    answer = cap.read(base + "/config", params={"current": 1})
    if not isinstance(answer, dict) or not answer:
        raise CollectError("%s current config is empty or not an object" % base)
    return answer


def _collect_inventory(ctx):
    cap = Capture(ctx)
    view = {}
    for key, kind, base, row in guests(cap):
        current = cap.read(base + "/status/current")
        if not isinstance(current, dict) or "status" not in current:
            raise CollectError("%s status lacks required status field" % base)
        merged = {**row, **current, "kind": kind, "node": cap.node()}
        fields = (
            "vmid",
            "kind",
            "node",
            "name",
            "status",
            "qmpstatus",
            "template",
            "lock",
            "tags",
            "hastate",
            "cpus",
            "maxcpu",
            "maxmem",
            "maxdisk",
            "running-machine",
            "running-qemu",
            "agent",
        )
        view[key] = {field: merged[field] for field in fields if field in merged}
    cap.context["runtime_readings"] = (
        "Complete per-guest status/current envelopes in raw retain CPU, memory, I/O, uptime and "
        "unknown readings."
    )
    return cap.result(view)


def _collect_config(ctx):
    cap = Capture(ctx)
    view = {}
    for key, _kind, base, _row in guests(cap):
        current = _config(cap, base)
        pending = cap.rows(base + "/pending")
        view[key] = {
            "current": stable(current, omit=("digest",)),
            "pending": keyed(pending, "key"),
        }
    cap.context["configuration_sources"] = "current=1 and pending; deletions retained"
    return cap.result(view)


def _device_collector(pattern):
    def collect(ctx):
        cap = Capture(ctx)
        view = {}
        for key, kind, base, _row in guests(cap):
            config = _config(cap, base)
            for name, value in config.items():
                if pattern.fullmatch(name):
                    parsed = property_string(value)
                    if not isinstance(parsed, dict):
                        raise CollectError("%s %s is not a property string" % (base, name))
                    view[key + "|" + name] = {"kind": kind, "slot": name, **parsed}
        return cap.result(view)

    return collect


def _collect_tuning(ctx):
    cap = Capture(ctx)
    view = {}
    models = cap.rows("/cluster/qemu/custom-cpu-models", optional=True)
    for name in keyed(models or [], "cputype"):
        detail = cap.read("/cluster/qemu/custom-cpu-models/" + name)
        view["cpu-model|" + name] = stable(detail, omit=("digest",))
    for key, _kind, base, _row in guests(cap):
        config = _config(cap, base)
        view[key] = stable(
            {
                name: value
                for name, value in config.items()
                if not _DEVICE.fullmatch(name) and name not in ("rootfs", "digest")
            }
        )
    return cap.result(view)


def _collect_snapshots(ctx):
    cap = Capture(ctx)
    view = {}
    for key, _kind, base, _row in guests(cap):
        snapshots = cap.rows(base + "/snapshot")
        for name, row in keyed(snapshots, "name").items():
            if name == "current":
                cap.context.setdefault("current_snapshot_parent", {})[key] = row.get("parent")
                continue
            config = cap.read(base + "/snapshot/" + name + "/config")
            if not isinstance(config, dict):
                raise CollectError("snapshot %s config is not an object" % name)
            view[key + "|snapshot|" + name] = {
                "snapshot": stable(row, omit=("snaptime", "ctime")),
                "config": stable(config, omit=("snaptime", "ctime")),
            }
            cap.context.setdefault("snapshot_times", {})[key + "|" + name] = row.get("snaptime")
    return cap.result(view)


def _collect_cloudinit(ctx):
    cap = Capture(ctx)
    view = {}
    for key, kind, base, _row in guests(cap):
        if kind != "qemu":
            continue
        config = _config(cap, base)
        if not any(
            "cloudinit" in str(value) for name, value in config.items() if _DISK.fullmatch(name)
        ):
            cap.context.setdefault("not_configured", []).append(key)
            continue
        custom = config.get("cicustom")
        if custom:
            cap.context.setdefault("data_gaps", []).append(
                {
                    "source": base + "/config cicustom",
                    "reason": "Arbitrary custom snippet credential redaction is unverified",
                    "value": (
                        "Configured snippet references remain complete; generated dumps do not "
                        "prove their effective custom content"
                    ),
                }
            )
        rows = cap.rows(base + "/cloudinit")
        view[key] = keyed(rows, "key")
        # The supported dump endpoint directly generates default documents;
        # it never reads arbitrary cicustom snippet bodies.
        for document in ("user", "network", "meta"):
            source = base + "/cloudinit/dump?type=" + document
            cap.context.setdefault("unstructured_reads", []).append(
                {
                    "source": source,
                    "class": "justified",
                    "gap": (
                        "Rendered cloud-init documents carry generated host/network directives "
                        "not represented completely by the structured property settings"
                    ),
                    "value": (
                        "Complete redacted generated documents support joins between settings "
                        "and the configuration presented to the guest"
                    ),
                    "exit": "Replace when the API serves complete structured generated documents",
                }
            )
            content = cap.read(base + "/cloudinit/dump", params={"type": document})
            if not isinstance(content, str):
                raise CollectError("cloud-init generated document did not return a string")
    if not view:
        raise SkipCheck("no local QEMU guest has a cloud-init volume configured")
    cap.context["document_source"] = (
        "Native dumps are automatically generated default user/network/meta documents; custom "
        "snippet references are configured data and their unserved bodies are explicit gaps"
    )
    return cap.result(view)


_AGENT_READS = (
    "info",
    "get-host-name",
    "get-osinfo",
    "network-get-interfaces",
    "get-fsinfo",
    "get-vcpus",
    "get-memory-blocks",
    "get-memory-block-info",
    "get-timezone",
)


def _agent_read(cap, base, command):
    try:
        return cap.read(base + "/agent/" + command)
    except Exception as exc:
        if getattr(exc, "status_code", None) != 403:
            raise
        vmid = base.rsplit("/", 1)[-1]
        guidance = (
            "Guest agent GET was denied with HTTP 403; verify VM.GuestAgent.Audit "
            "at /vms/%s for the capture token and its owning user on this Proxmox release" % vmid
        )
        cap.context["permission_guidance"] = guidance
        raise CollectError(guidance) from exc


def _collect_agent(ctx):
    cap = Capture(ctx)
    view = {}
    for key, kind, base, row in guests(cap):
        if kind == "lxc":
            if row.get("status") == "running":
                cap.rows(base + "/interfaces")
                view[key] = {"interfaces_observed": True}
            else:
                cap.context.setdefault("not_running", []).append(key)
            continue
        config = _config(cap, base)
        agent = property_string(config.get("agent", "0"))
        enabled = agent.get("enabled", agent.get("value", "0"))
        if str(enabled).lower() not in ("1", "yes", "true", "on"):
            cap.context.setdefault("agent_not_configured", []).append(key)
            continue
        if row.get("status") != "running":
            cap.context.setdefault("not_running", []).append(key)
            continue
        info = _agent_read(cap, base, "info")
        supported = (
            info.get("result", {}).get("supported_commands") if isinstance(info, dict) else None
        )
        if not isinstance(supported, list) or any(not isinstance(item, dict) for item in supported):
            raise CollectError("guest agent info has no structured supported-command inventory")
        capabilities = keyed(supported, "name")
        for command in _AGENT_READS:
            if command == "info":
                continue
            feature = capabilities.get("guest-" + command)
            if feature is None or feature.get("enabled") not in (True, 1):
                continue
            _agent_read(cap, base, command)
        # These observations are point-in-time guest evidence, not stable assertions.
        cap.context.setdefault("agent_observation_keys", []).append(key)
        view[key] = {"agent_configured": True}
    if not view:
        raise SkipCheck(
            "no running local guest offers configured agent observations or LXC live interfaces"
        )
    return cap.result(view)


def _collect_metrics(ctx):
    cap = Capture(ctx)
    view = {}
    samples = 0
    params = {"cf": "AVERAGE", "timeframe": "day"}
    for key, kind, base, row in guests(cap):
        samples += len(cap.rows(base + "/rrddata", params=params))
        view[key] = {"kind": kind, "vmid": row["vmid"], "node": cap.node()}
    cap.context["metrics"] = {
        "timeframe": "day",
        "cf": "AVERAGE",
        "guests": len(view),
        "samples": samples,
        "source": "complete resident RRD arrays in raw, including unknown numeric fields",
    }
    return cap.result(view)


def _collect_autostart(ctx):
    cap = Capture(ctx)
    view = {}
    for key, _kind, base, _row in guests(cap):
        config = _config(cap, base)
        view[key] = {
            "onboot": config.get("onboot", 0),
            "startup": property_string(config.get("startup", "")),
            "protection": config.get("protection", 0),
        }
    return cap.result(view)


def _add(check_id, description, collector, semantics, tier=1):
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
                "A missing guest/device key records changed inventory; failed reads are "
                "missing evidence."
            ),
            collector=collector,
            tags=(EMPTY_OK_TAG,),
        )
    )


_add(
    "proxmox_guests",
    "Every local QEMU/LXC guest, including stopped guests and templates",
    _collect_inventory,
    (
        "Keys scope|kind|vmid keep node placement in the value, so a cluster migration does not "
        "rename a guest. Status and configured capacity are retained; instantaneous CPU, "
        "memory, I/O "
        "and uptime readings are context/raw. Both guest families are read without status filters."
    ),
)
_add(
    "proxmox_guest_config",
    "Complete current and pending guest configuration",
    _collect_config,
    (
        "Each guest carries every current configuration field and every pending property row, "
        "including pending deletion markers and unknown fields. Native property strings remain in "
        "configuration; parsed device views are separate. Digests are transport "
        "concurrency metadata "
        "in raw."
    ),
    2,
)
_add(
    "proxmox_guest_disks",
    "All QEMU disks and LXC roots/mount points, including unused volumes",
    _device_collector(_DISK),
    (
        "Keys scope|kind|vmid|slot identify every disk, EFI/TPM volume, unused volume, "
        "LXC root and "
        "mount point. Property-string grammar is parsed into named fields without display-text "
        "scraping; full original values remain in raw."
    ),
)
_add(
    "proxmox_guest_nics",
    "Guest NICs, PCI and USB passthrough configuration",
    _device_collector(_NIC),
    (
        "Every net, hostpci and usb slot is retained and parsed into named configuration fields, "
        "including unknown options. MAC, bridge, VLAN/trunk, firewall, queues, rate and "
        "passthrough "
        "backing remain where the source serves them."
    ),
)
_add(
    "proxmox_guest_tuning",
    "Guest CPU/memory/boot/security/tuning and unmodelled configuration",
    _collect_tuning,
    (
        "Every non-device current configuration option is retained, including future options. CPU, "
        "NUMA, memory, ballooning, boot, machine, OS type, EFI/security, hooks and "
        "custom arguments "
        "remain represented; secrets are redacted before cache and raw."
    ),
)
_add(
    "proxmox_guest_snapshots",
    "Every retained guest snapshot and complete saved configuration",
    _collect_snapshots,
    (
        "Keys guest|snapshot|name retain snapshot topology and every saved configuration "
        "option. The "
        "current pseudo-snapshot is context only. Snapshot creation times remain in context/raw; "
        "parent and state remain stable assertions."
    ),
    2,
)
_add(
    "proxmox_guest_cloudinit",
    "Cloud-init current/generated-image and pending configuration",
    _collect_cloudinit,
    (
        "Every QEMU guest with a cloud-init volume carries the complete structured cloud-init "
        "current and pending property rows and native generated user/network/meta documents in "
        "raw. Passwords/key material are redacted. Custom snippet bodies are explicit gaps. "
        "Guests without a "
        "cloud-init volume are explained in context; LXC does not expose this QEMU API."
    ),
    2,
)
_add(
    "proxmox_guest_agent",
    "Read-only guest agent observations and LXC interfaces",
    _collect_agent,
    (
        "Configured running QEMU agents are queried only through the fixed GET observation "
        "allowlist. Full redacted observations are raw, because guest users, uptime, addresses and "
        "file-system use are point-in-time data. Stopped guests and absent agent configuration are "
        "named in context; LXC live interfaces come from its structured API."
    ),
    3,
)
_add(
    "proxmox_autostart",
    "Guest boot ordering, onboot and protection",
    _collect_autostart,
    (
        "Each guest keeps its onboot flag, startup order/delays and protection setting. Absence of "
        "optional fields uses the documented configuration default, and the original complete "
        "configuration remains in raw."
    ),
)

_add(
    "proxmox_guest_metrics",
    "Complete resident day RRD history for every local guest",
    _collect_metrics,
    (
        "Every local QEMU/LXC guest, including stopped guests and templates, carries its complete "
        "served day/AVERAGE RRD array in raw. Numeric history and unknown fields remain intact. "
        "Stable scope metadata supports guest joins; context records only total sample counts "
        "and the fixed query window."
    ),
    3,
)
