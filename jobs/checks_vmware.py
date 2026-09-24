"""VMware ESXi (standalone hostd, vim25 SOAP) check catalog — ESXi as NFV compute.

Every collector reaches the host only through ``ctx.call`` on the api slot
(the VsphereClient: six read-only operations, Read-only role server-side);
this module imports nothing but stdlib and the jobs package's pure modules,
so the CI battery can import it and drive every ``_normalize_*`` function
directly with parsed fixture bodies.

The platform is modelled as "a hypervisor set up as NFV compute" in general:
every check is always-on and a feature that is not in use records loudly as
not-present. Collectors gather as much self-describing state as the property
collector exposes — volatile readings go to context or raw, never dropped.

Shared-fetch rule (the ``_fetch_rib`` pattern from checks_iosxe): checks that
read the same property group call ``ctx.call`` with IDENTICAL kwargs — the
module-level path tuples below are the only spellings used — so the per-run
cache issues one ``RetrievePropertiesEx`` per group (``config.network`` once
for six checks, ``config.option`` once for three, one per-VM property set for
five). A pathSet entry is a bare dotted property path, every one a member of
``vsphere_soap.PROPERTY_PATHS``; field selection is client-side.

Wire-shape rules the normalizers follow (verified against hostd):

- leaves inside data objects are UNTYPED strings (``speedMb`` = "10000",
  ``vendorId`` = "-32634"); only top-level ``<val xsi:type="xsd:*">`` and
  ``OptionValue.value`` arrive typed — hence ``to_int``/``to_bool``;
- xsd:short PCI ids arrive signed and are rendered as unsigned hex;
- an unset optional property is simply absent from the propSet (never a
  fault) and reads as None; a ``missingSet`` entry is a failed read on the
  host object and a tolerated, recorded gap on a VM object;
- an EMPTY array is omitted from the propSet too (no proxySwitch, no
  snapshot, no cpuAffinity), so "absent" also means "empty";
- hostd's empty ``<security/>`` container on an inheriting port group parses
  to None, the repo's "unset" sentinel.

Raw is keyed by the exact request (operation, type, moids, paths) and holds
each returned property set CURATED first (bulk-only fields dropped, secrets
scrubbed) and capped second, with an honest truncation marker; normalized is
always computed from the full response, never from capped raw.
"""

import json
import re

from . import constants as C
from .registry import CheckDef, CollectError, SkipCheck, register
from .vsphere_soap import aslist, to_bool, to_int, to_unsigned_short

# --- property groups (one cached fetch each) ---------------------------------

# The one HostSystem a standalone hostd manages. Well-known on every ESXi
# release; a vCenter (where hosts are host-NNN) is refused by the transport.
_HOST_MOID = "ha-host"

_IDENTITY_PATHS = (
    "hardware.systemInfo",
    "hardware.biosInfo",
    "config.product",
    "summary.hardware",
    "config.hyperThread",
    "summary.config.name",
    "runtime.bootTime",
    "summary.rebootRequired",
    "runtime.inMaintenanceMode",
    "runtime.powerState",
    "runtime.standbyMode",
    "config.powerSystemInfo",
    "config.powerSystemCapability",
    "config.ipmi",
    "runtime.tpmPcrValues",
)
# Identity paths a build or role may withhold (a missingSet on one of these
# is recorded in context.unreadable, never fatal); the rest are answered by
# every release and a missingSet there is a failed read.
_IDENTITY_TOLERATED = frozenset(
    {
        "runtime.inMaintenanceMode",
        "runtime.powerState",
        "runtime.standbyMode",
        "config.powerSystemInfo",
        "config.powerSystemCapability",
        "config.ipmi",
        "runtime.tpmPcrValues",
    }
)
_HARDWARE_PATHS = (
    "hardware.memorySize",
    "hardware.cpuPkg",
    "hardware.numaInfo",
    "hardware.pciDevice",
    "config.pciPassthruInfo",
)
# Shared by pnics / pnic_neighbors / vswitches / portgroups / vmknics /
# host_routes / vlan_hints: config.network is fetched ONCE and sliced.
_NETWORK_PATHS = (
    "config.network",
    "config.virtualNicManagerInfo",
    "configManager.networkSystem",
)
_TIME_PATHS = ("config.dateTimeInfo",)
# Shared by time_syslog and host_services.
_SERVICE_PATHS = ("config.service", "config.lockdownMode", "summary.managementServerIp")
# Shared by time_syslog / host_services / advanced_options; ~1 200
# OptionValues on 8.0U3, hence the big timeout.
_OPTION_PATHS = ("config.option",)
_FIREWALL_PATHS = ("config.firewall",)
_DATASTORE_HOST_PATHS = ("datastore", "config.fileSystemVolume.mountInfo")
_DATASTORE_PATHS = ("summary", "info")
_STORAGE_PATHS = ("config.storageDevice.hostBusAdapter", "config.storageDevice.scsiLun")
_HEALTH_PATHS = ("runtime.healthSystemRuntime",)
_AUTOSTART_PATHS = ("config.autoStart",)
_LICENSE_PATHS = ("licenses",)
_HOST_VM_PATHS = ("vm",)
# The per-VM property set shared by vms / vm_nics / vm_tuning / vm_disks /
# autostart — one RetrievePropertiesEx for every registered VM.
_VM_PATHS = (
    "name",
    "config.uuid",
    "config.instanceUuid",
    "config.version",
    "config.guestId",
    "config.files.vmPathName",
    "config.hardware.numCPU",
    "config.hardware.numCoresPerSocket",
    "config.hardware.autoCoresPerSocket",
    "config.hardware.memoryMB",
    "config.hardware.device",
    "config.cpuAllocation",
    "config.memoryAllocation",
    "config.memoryReservationLockedToMax",
    "config.latencySensitivity",
    "config.cpuAffinity",
    "config.extraConfig",
    "runtime.powerState",
    "runtime.connectionState",
    "runtime.bootTime",
    "runtime.question",
    "guest.guestState",
    "guest.toolsStatus",
    "guest.toolsRunningStatus",
    "guest.toolsVersionStatus2",
    "guest.toolsVersion",
    "guest.hostName",
    "guest.net",
    "snapshot",
    "config.changeVersion",
    "config.modified",
    "config.vmxConfigChecksum",
    "config.flags",
    "config.bootOptions",
    "config.firmware",
    "config.cpuHotAddEnabled",
    "config.memoryHotAddEnabled",
    "config.tools",
)
_TASK_TRAVERSE = {"path": "recentTask", "type": "Task", "paths": ["info"]}
_EVENT_PATHS = ("latestEvent",)


# --- shared helpers ----------------------------------------------------------


def _strip(value):
    """Trimmed string, None for None/empty (hostd pads vendor/model with spaces)."""
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _lower(value):
    text = _strip(value)
    return text.lower() if text is not None else None


def _hex16(value):
    """Signed xsd:short id -> '0x8086' style unsigned hex, None when unreadable."""
    number = to_unsigned_short(value)
    return "0x%04x" % (number,) if number is not None else None


def _datastore_of(vm_path):
    """'[datastore1] fw-a/fw-a.vmx' -> 'datastore1'; None when the form is off."""
    match = re.match(r"^\[([^\]]+)\]", str(vm_path or ""))
    return match.group(1) if match else None


def _dicts(value):
    """aslist() restricted to dict items — the shape every vim25 array member has."""
    return [item for item in aslist(value) if isinstance(item, dict)]


def _get(node, *path):
    """Nested dict lookup tolerant of None/non-dict intermediates."""
    for part in path:
        if not isinstance(node, dict):
            return None
        node = node.get(part)
    return node


# --- raw bundle curation ------------------------------------------------------

# Cap per stored property set (same figure as the PAN-OS raw cap). Curation
# happens BEFORE the cap so the marker is honest about what was cut.
_RAW_CAP = 20000

# Option/extraConfig keys whose values are masked in raw. Snapshots get
# pasted into LLM conversations; a credential must never ride along.
_SECRET_KEY_TOKENS = ("secret", "token", "community", "passphrase", "privkey", "credential")
# "password" is a token too, except for the policy knobs that merely spell it.
_PASSWORD_POLICY_KEYS = frozenset({"Security.PasswordQualityControl", "Security.PasswordHistory"})


def _secret_key(key):
    lowered = str(key).lower()
    if key in _PASSWORD_POLICY_KEYS:
        return False
    return "password" in lowered or any(token in lowered for token in _SECRET_KEY_TOKENS)


class _Precapped(dict):
    """A curated raw value its curator already capped block by block; _capped passes it through."""


def _capped_text(text):
    """Sorted key=value text capped with an honest marker (same form as the XCC raw remainder)."""
    if len(text) <= _RAW_CAP:
        return text
    return text[:_RAW_CAP] + "\n...[truncated %d chars]" % (len(text) - _RAW_CAP,)


def _capped(value):
    """The value itself when its JSON form fits the cap, else a truncation record.

    A list is cut BETWEEN items so what is kept stays parseable (items_kept
    of items_total); anything else is cut as JSON text (head). A _Precapped
    dict was capped per block by its curator and passes through unchanged.
    """
    if isinstance(value, _Precapped):
        return dict(value)
    text = json.dumps(value, sort_keys=True, default=str)
    if len(text) <= _RAW_CAP:
        return value
    if isinstance(value, list):
        kept, used = [], 2  # the enclosing brackets
        for item in value:
            item_text = json.dumps(item, sort_keys=True, default=str)
            if used + len(item_text) + 2 > _RAW_CAP:
                break
            kept.append(item)
            used += len(item_text) + 2
        if kept:
            return {
                "truncated": True,
                "chars_total": len(text),
                "items_total": len(value),
                "items_kept": len(kept),
                "items": kept,
            }
    return {
        "truncated": True,
        "chars_total": len(text),
        "chars_kept": _RAW_CAP,
        "head": text[:_RAW_CAP],
    }


def _prune(node, drop):
    """Copy of a parsed structure without the named keys at any depth (bulk-only fields)."""
    if isinstance(node, dict):
        return {key: _prune(value, drop) for key, value in node.items() if key not in drop}
    if isinstance(node, list):
        return [_prune(item, drop) for item in node]
    return node


def _request_key(mo_type, moids, paths):
    return "RetrievePropertiesEx %s[%s] %s" % (mo_type, ",".join(moids), ",".join(paths))


def _raw_objects(result, curate=None):
    """Raw-bundle view of a RetrieveResult: per object, per property set, curated then capped."""
    raw = {}
    for obj in result.get("objects") or []:
        entry = {}
        for path, value in (obj.get("props") or {}).items():
            if curate is not None:
                value = curate(path, value)
            entry[path] = _capped(value)
        if obj.get("missing"):
            entry["missing"] = obj["missing"]
        raw[_get(obj, "obj", "moid") or "?"] = entry
    return raw


def _curated_options(options, curated_keys):
    """config.option / extraConfig for raw: curated keys uncapped, every other
    key as sorted key=value lines grouped by top-level prefix (Net, Mem,
    UserVars, ethernet0 ...), each group capped on its own with an honest
    marker so one bulky family never hides another; secrets masked. The
    result is _Precapped: _raw_objects stores it as-is instead of cutting it
    a second time as JSON text."""
    curated = {}
    groups = {}
    for option in _dicts(options):
        key = option.get("key")
        if key is None:
            continue
        value = option.get("value")
        if _secret_key(key):
            value = "***scrubbed***"
        if key in curated_keys:
            curated[key] = value
        else:
            groups.setdefault(str(key).split(".", 1)[0], []).append("%s=%s" % (key, value))
    remainder = {prefix: _capped_text("\n".join(sorted(lines))) for prefix, lines in groups.items()}
    return _Precapped(
        {
            "curated": curated,
            "remainder_count": sum(len(lines) for lines in groups.values()),
            "remainder": dict(sorted(remainder.items())),
        }
    )


# --- transport helpers ---------------------------------------------------------


def _retrieve(ctx, mo_type, moids, paths, **options):
    """RetrievePropertiesEx through the per-run cache; the drained result dict.

    kwargs are built the same way every time (lists from the module tuples,
    options in the caller's fixed spelling) so sibling checks hit the cache.
    A leftover continuation token means the transport did not drain — a
    partial answer is refused, never normalized.
    """
    result = ctx.call(
        "RetrievePropertiesEx", type=mo_type, moids=list(moids), paths=list(paths), **options
    )
    if not isinstance(result, dict) or "objects" not in result:
        raise CollectError("RetrievePropertiesEx %s: unexpected result shape" % (mo_type,))
    if result.get("token"):
        raise CollectError(
            "RetrievePropertiesEx %s: continuation token left undrained — partial result refused"
            % (mo_type,)
        )
    return result


def _object_by_moid(result, moid):
    for obj in result.get("objects") or []:
        if _get(obj, "obj", "moid") == moid:
            return obj
    return None


def _refuse_missing(obj, label, tolerated=frozenset()):
    """A missingSet entry on a host-level object is a failed read, never emptiness.

    Entries for a ``tolerated`` path are returned (sorted paths) instead, for
    the caller to record as a gap.
    """
    unreadable = []
    for entry in obj.get("missing") or []:
        if entry.get("path") in tolerated:
            unreadable.append(str(entry.get("path")))
            continue
        raise CollectError(
            "%s: property %s not returned: %s: %s"
            % (label, entry.get("path"), entry.get("fault"), entry.get("message"))
        )
    return sorted(unreadable)


def _fetch_host(ctx, paths, tolerated=frozenset(), **options):
    """One host property group -> (props, result). Unset optionals are absent from props.

    ``tolerated`` paths may come back in the missingSet without failing the
    read; ``result["unreadable"]`` then lists them.
    """
    result = _retrieve(ctx, "HostSystem", (_HOST_MOID,), paths, **options)
    host = _object_by_moid(result, _HOST_MOID)
    if host is None:
        raise CollectError("HostSystem %s not in the RetrievePropertiesEx answer" % (_HOST_MOID,))
    result["unreadable"] = _refuse_missing(host, "HostSystem %s" % (_HOST_MOID,), tolerated)
    return host["props"], result


def _fetch_option_group(ctx):
    return _fetch_host(ctx, _OPTION_PATHS, timeout=C.VSPHERE_BIG_CALL_TIMEOUT)


def _fetch_network_group(ctx):
    props, result = _fetch_host(ctx, _NETWORK_PATHS)
    network = props.get("config.network")
    if not isinstance(network, dict):
        raise CollectError("config.network absent from the host answer")
    return props, network, result


def _service_content(ctx):
    content = ctx.call("RetrieveServiceContent")
    if not isinstance(content, dict):
        raise CollectError("RetrieveServiceContent returned no service content")
    return content


def _manager_moid(content, name):
    moid = _get(content, name, "moid")
    if not moid:
        raise CollectError("service content lacks %s" % (name,))
    return moid


# --- vmware_host_identity ------------------------------------------------------


def _serial_of(system_info):
    """(serial, source): serialNumber (6.7+), else the ServiceTag / SerialNumberTag entry."""
    serial = _strip(_get(system_info, "serialNumber"))
    if serial:
        return serial, "serialNumber"
    for wanted in ("ServiceTag", "SerialNumberTag"):
        for info in _dicts(_get(system_info, "otherIdentifyingInfo")):
            if _get(info, "identifierType", "key") == wanted and _strip(
                info.get("identifierValue")
            ):
                return _strip(info.get("identifierValue")), wanted
    return None, None


def _tpm_pcrs(values):
    """runtime.tpmPcrValues -> [{index, digest_method, digest (hex), object_name}], by index.

    digestValue is a byte array on the wire (repeated signed-byte leaves);
    rendered as lowercase hex. A digest that arrives in another form is kept
    verbatim rather than guessed at.
    """
    rows = []
    for info in _dicts(values):
        raw_digest = aslist(info.get("digestValue"))
        octets = [to_int(item) for item in raw_digest]
        if octets and all(item is not None for item in octets):
            digest = "".join("%02x" % (item & 0xFF,) for item in octets)
        else:
            digest = "".join(str(item) for item in raw_digest) or None
        rows.append(
            {
                "index": to_int(info.get("pcrNumber")),
                "digest_method": _strip(info.get("digestMethod")),
                "digest": digest,
                "object_name": _strip(info.get("objectName")),
            }
        )
    return sorted(rows, key=lambda row: (row["index"] is None, row["index"] or 0))


def _normalize_host_identity(props):
    """Identity property group -> flat scalars; boot time / reboot flag / TPM PCRs to context."""
    system = props.get("hardware.systemInfo") or {}
    bios = props.get("hardware.biosInfo") or {}
    product = props.get("config.product") or {}
    summary = props.get("summary.hardware") or {}
    hyper = props.get("config.hyperThread")
    power = props.get("config.powerSystemInfo")
    power = power if isinstance(power, dict) else {}
    capability = props.get("config.powerSystemCapability")
    capability = capability if isinstance(capability, dict) else {}
    ipmi = props.get("config.ipmi")
    ipmi = ipmi if isinstance(ipmi, dict) else {}
    serial, serial_source = _serial_of(system)
    normalized = {
        "vendor": _strip(system.get("vendor")),
        "model": _strip(system.get("model")),
        "serial": serial,
        "serial_source": serial_source,
        "uuid": _lower(system.get("uuid")),
        "bios_version": _strip(bios.get("biosVersion")),
        # ISO date string kept verbatim; never re-parsed (py3.9 fromisoformat
        # rejects hostd's forms).
        "bios_release_date": _strip(bios.get("releaseDate")),
        "esxi_version": _strip(product.get("version")),
        "esxi_build": _strip(product.get("build")),
        "api_type": _strip(product.get("apiType")),
        "api_version": _strip(product.get("apiVersion")),
        "hostname": _strip(props.get("summary.config.name")),
        "cpu_model": _strip(summary.get("cpuModel")),
        "cpu_pkgs": to_int(summary.get("numCpuPkgs")),
        "cpu_cores": to_int(summary.get("numCpuCores")),
        "cpu_threads": to_int(summary.get("numCpuThreads")),
        # None when the host does not expose hyperthreading scheduling at all.
        "hyperthreading_active": to_bool(hyper.get("active")) if isinstance(hyper, dict) else None,
        "memory_bytes": to_int(summary.get("memorySize")),
        # A host left in maintenance mode answers every other check green
        # and refuses to power any VM on.
        "maintenance_mode": to_bool(props.get("runtime.inMaintenanceMode")),
        "power_state": _strip(props.get("runtime.powerState")),
        "standby_mode": _strip(props.get("runtime.standbyMode")),
        # The APPLIED power policy (static/dynamic/low/custom); the
        # Power.CpuPolicy advanced option is only the knob.
        "power_policy": _strip(_get(power, "currentPolicy", "shortName")),
        # The BMC address the host itself holds: the join from this envelope
        # to the out-of-band one. Never the BMC login.
        "bmc_ip": _strip(ipmi.get("bmcIpAddress")),
        "bmc_mac": _lower(ipmi.get("bmcMacAddress")),
    }
    context = {
        "boot_time": props.get("runtime.bootTime"),
        "reboot_required": to_bool(props.get("summary.rebootRequired")),
        "cpu_mhz": to_int(summary.get("cpuMhz")),
        "num_nics": to_int(summary.get("numNics")),
        "num_hbas": to_int(summary.get("numHBAs")),
        "hyperthreading_available": to_bool(hyper.get("available"))
        if isinstance(hyper, dict)
        else None,
        "power_policy_name": _strip(_get(power, "currentPolicy", "name")),
        "power_policies_available": sorted(
            _strip(policy.get("shortName"))
            for policy in _dicts(capability.get("availablePolicy"))
            if _strip(policy.get("shortName"))
        ),
        # The PCR set the TPM-sealed configuration archive depends on: a
        # changed digest after a BIOS/boot-config change explains a sealed
        # config that would no longer unseal. Absent (empty) without a TPM.
        "tpm_pcr_values": _tpm_pcrs(props.get("runtime.tpmPcrValues")),
    }
    return normalized, context


def _curate_identity(path, value):
    if path == "config.ipmi":
        # bmcIpAddress/bmcMacAddress are the evidence; the BMC login and any
        # password field never enter a snapshot.
        return _prune(value, {"login", "password"})
    return value


def _collect_host_identity(ctx):
    props, result = _fetch_host(ctx, _IDENTITY_PATHS, tolerated=_IDENTITY_TOLERATED)
    normalized, context = _normalize_host_identity(props)
    context["unreadable"] = result["unreadable"]
    raw = {
        _request_key("HostSystem", (_HOST_MOID,), _IDENTITY_PATHS): _raw_objects(
            result, _curate_identity
        )
    }
    return {"raw": raw, "normalized": normalized, "context": context}


# --- vmware_hardware_inventory -------------------------------------------------

_SRIOV_FIELDS = (
    ("sriovCapable", "sriov_capable"),
    ("sriovEnabled", "sriov_enabled"),
    ("sriovActive", "sriov_active"),
)


def _normalize_hardware_inventory(props):
    """cpu|<index>, pci|<id>, numa|nodes, memory|bytes rows.

    PCI ids are xsd:short on the wire: masked & 0xFFFF and rendered hex so
    0x8086 never reads as -32634. A VF is its own pci| row (is_vf by the
    device name — hostd carries no VF flag); passthrough/SR-IOV state joins
    from config.pciPassthruInfo by id, with the HostSriovInfo subtype
    supplying the sriov_* and VF-count fields (None on plain entries).
    Hz/busHz/cpuFeature/threadId are excluded (raw only).
    """
    normalized = {}
    for package in _dicts(props.get("hardware.cpuPkg")):
        index = to_int(package.get("index"))
        if index is None:
            continue
        normalized["cpu|%d" % (index,)] = {
            "vendor": _strip(package.get("vendor")),
            "description": _strip(package.get("description")),
        }
    passthru = {}
    for entry in _dicts(props.get("config.pciPassthruInfo")):
        if entry.get("id"):
            passthru[entry["id"]] = entry
    for device in _dicts(props.get("hardware.pciDevice")):
        pci_id = _strip(device.get("id"))
        if pci_id is None:
            continue
        info = passthru.get(pci_id) or {}
        sriov = info.get("_type") == "HostSriovInfo"
        row = {
            "vendor_name": _strip(device.get("vendorName")),
            "device_name": _strip(device.get("deviceName")),
            "vendor_id": _hex16(device.get("vendorId")),
            "device_id": _hex16(device.get("deviceId")),
            "class_id": _hex16(device.get("classId")),
            "sub_vendor_id": _hex16(device.get("subVendorId")),
            "sub_device_id": _hex16(device.get("subDeviceId")),
            "parent_bridge": _strip(device.get("parentBridge")),
            "is_vf": "virtual function" in (device.get("deviceName") or "").lower(),
            "passthru_capable": to_bool(info.get("passthruCapable")),
            "passthru_enabled": to_bool(info.get("passthruEnabled")),
            "passthru_active": to_bool(info.get("passthruActive")),
        }
        for wire, field in _SRIOV_FIELDS:
            row[field] = to_bool(info.get(wire)) if sriov else None
        row["num_vf_requested"] = to_int(info.get("numVirtualFunctionRequested")) if sriov else None
        row["num_vf"] = to_int(info.get("numVirtualFunction")) if sriov else None
        normalized["pci|%s" % (pci_id,)] = row
    numa = props.get("hardware.numaInfo")
    normalized["numa|nodes"] = {
        "value": to_int(numa.get("numNodes")) if isinstance(numa, dict) else None
    }
    normalized["memory|bytes"] = {"value": to_int(props.get("hardware.memorySize"))}
    return normalized


def _curate_hardware(path, value):
    if path == "hardware.cpuPkg":
        return _prune(value, {"cpuFeature", "threadId"})
    return value


def _collect_hardware_inventory(ctx):
    props, result = _fetch_host(ctx, _HARDWARE_PATHS)
    normalized = _normalize_hardware_inventory(props)
    context = {
        "pci_devices": sum(1 for key in normalized if key.startswith("pci|")),
        "passthru_entries": len(_dicts(props.get("config.pciPassthruInfo"))),
        "numa_type": _get(props.get("hardware.numaInfo"), "type"),
    }
    raw = {
        _request_key("HostSystem", (_HOST_MOID,), _HARDWARE_PATHS): _raw_objects(
            result, _curate_hardware
        )
    }
    return {"raw": raw, "normalized": normalized, "context": context}


# --- vmware_pnics ----------------------------------------------------------------


def _normalize_pnics(network):
    """config.network.pnic -> pnic|vmnicN rows.

    link_up is the presence of linkSpeed (hostd omits it on a down port);
    duplex is a bool (true = full); configured_* None means auto-negotiate.
    driver/firmware versions exist on 8.0 U1+ only — None before.
    """
    normalized = {}
    for pnic in _dicts(network.get("pnic")):
        device = _strip(pnic.get("device"))
        if device is None:
            continue
        link = pnic.get("linkSpeed") if isinstance(pnic.get("linkSpeed"), dict) else None
        configured = _get(pnic, "spec", "linkSpeed")
        configured = configured if isinstance(configured, dict) else None
        normalized["pnic|%s" % (device,)] = {
            "mac": _lower(pnic.get("mac")),
            "pci": _strip(pnic.get("pci")),
            "driver": _strip(pnic.get("driver")),
            "driver_version": _strip(pnic.get("driverVersion")),
            "firmware_version": _strip(pnic.get("firmwareVersion")),
            "link_up": link is not None,
            "speed_mb": to_int(link.get("speedMb")) if link else None,
            "duplex": to_bool(link.get("duplex")) if link else None,
            "autoneg_supported": to_bool(pnic.get("autoNegotiateSupported")),
            "configured_speed_mb": to_int(configured.get("speedMb")) if configured else None,
            "configured_duplex": to_bool(configured.get("duplex")) if configured else None,
            "ens_enabled": to_bool(_get(pnic, "spec", "enableEnhancedNetworkingStack")),
        }
    return normalized


# candidateVnic is a bulk copy of every vmk per nic type; portgroup[].port is
# the attached-port list (one entry per VM port, summarised as a count in the
# portgroups check's raw["attached_ports"]).
_NETWORK_RAW_DROP = frozenset({"candidateVnic"})


def _curate_network(path, value):
    """config.network split per sub-array (pnic, vswitch, portgroup, vnic, netStackInstance,
    routeTableInfo, dnsConfig ...) so each carries its own cap and marker and one bulky
    family never turns the raw evidence of the other six network checks into a text head."""
    if path == "config.network" and isinstance(value, dict):
        curated = _Precapped()
        for sub, node in value.items():
            if sub == "portgroup":
                node = _prune(node, {"port"})
            curated[sub] = _capped(_prune(node, _NETWORK_RAW_DROP))
        return curated
    return _prune(value, _NETWORK_RAW_DROP)


def _network_raw(result):
    """The shared network fetch for raw, curated per sub-array before the cap."""
    return {
        _request_key("HostSystem", (_HOST_MOID,), _NETWORK_PATHS): _raw_objects(
            result, _curate_network
        )
    }


def _collect_pnics(ctx):
    _props, network, result = _fetch_network_group(ctx)
    normalized = _normalize_pnics(network)
    context = {
        "pnics_total": len(normalized),
        "links_up": sum(1 for row in normalized.values() if row["link_up"]),
    }
    return {"raw": _network_raw(result), "normalized": normalized, "context": context}


# --- vmware_pnic_neighbors -------------------------------------------------------


def _discovery_by_vswitch(network):
    """vSwitch name -> {bridge_type, protocol, operation} (None fields when no bond bridge).

    spec.bridge is polymorphic and optional: only HostVirtualSwitchBondBridge
    carries linkDiscoveryProtocolConfig, and an unset config means the ESXi
    default (cdp / listen).
    """
    discovery = {}
    for vswitch in _dicts(network.get("vswitch")):
        name = _strip(vswitch.get("name"))
        if name is None:
            continue
        bridge = _get(vswitch, "spec", "bridge")
        bridge = bridge if isinstance(bridge, dict) else None
        entry = {"bridge_type": bridge.get("_type") if bridge else None}
        if bridge and bridge.get("_type") == "HostVirtualSwitchBondBridge":
            config = bridge.get("linkDiscoveryProtocolConfig")
            config = config if isinstance(config, dict) else {}
            entry["protocol"] = _strip(config.get("protocol")) or "cdp"
            entry["operation"] = _strip(config.get("operation")) or "listen"
        else:
            entry["protocol"] = None
            entry["operation"] = None
        discovery[name] = entry
    return discovery


def _neighbors_expected(discovery):
    """True when at least one bond-bridged vSwitch is configured to HEAR neighbors.

    ``advertise`` is treated like ``none``: the host sends but does not listen,
    so the hint table is empty by configuration, not by cabling.
    """
    return any(
        entry["operation"] in ("listen", "both")
        for entry in discovery.values()
        if entry["bridge_type"] == "HostVirtualSwitchBondBridge"
    )


def _normalize_pnic_neighbors(hints):
    """QueryNetworkHint -> cdp|vmnicN and lldp|vmnicN rows.

    Excludes samples/timeout/ttl/cdpVersion (volatile) and software version
    (raw). native_vlan is CdpInfo.vlan — None when the switch does not
    advertise it.
    """
    normalized = {}
    for hint in _dicts(hints):
        device = _strip(hint.get("device"))
        if device is None:
            continue
        cdp = hint.get("connectedSwitchPort")
        if isinstance(cdp, dict):
            normalized["cdp|%s" % (device,)] = {
                "device_id": _strip(cdp.get("devId")),
                "port_id": _strip(cdp.get("portId")),
                "platform": _strip(cdp.get("hardwarePlatform")),
                "native_vlan": to_int(cdp.get("vlan")),
                "mtu": to_int(cdp.get("mtu")),
                "mgmt_addr": _strip(cdp.get("mgmtAddr")),
                "address": _strip(cdp.get("address")),
                "full_duplex": to_bool(cdp.get("fullDuplex")),
            }
        lldp = hint.get("lldpInfo")
        if isinstance(lldp, dict):
            parameters = {}
            for parameter in _dicts(lldp.get("parameter")):
                if parameter.get("key") is not None:
                    parameters[str(parameter["key"])] = _strip(parameter.get("value"))
            normalized["lldp|%s" % (device,)] = {
                "chassis_id": _strip(lldp.get("chassisId")),
                "port_id": _strip(lldp.get("portId")),
                "parameters": parameters,
            }
    return normalized


def _fetch_hints(ctx, props):
    network_system = _get(props.get("configManager.networkSystem"), "moid")
    if not network_system:
        raise CollectError("configManager.networkSystem absent — cannot QueryNetworkHint")
    # <device> omitted on purpose: every pnic in one call.
    hints = ctx.call("QueryNetworkHint", network_system=network_system)
    if not isinstance(hints, list):
        raise CollectError("QueryNetworkHint returned no hint list")
    return network_system, hints


def _collect_pnic_neighbors(ctx):
    props, network, result = _fetch_network_group(ctx)
    discovery = _discovery_by_vswitch(network)
    network_system, hints = _fetch_hints(ctx, props)
    raw = _network_raw(result)
    raw["QueryNetworkHint %s" % (network_system,)] = _capped(hints)
    normalized = _normalize_pnic_neighbors(hints)
    context = {
        "discovery": discovery,
        "pnics_with_hints": len(_dicts(hints)),
        "cdp_neighbors": sum(1 for key in normalized if key.startswith("cdp|")),
        "lldp_neighbors": sum(1 for key in normalized if key.startswith("lldp|")),
    }
    if not _neighbors_expected(discovery):
        raise SkipCheck(
            "no bond-bridged vSwitch listens for CDP/LLDP (operation none/advertise or no "
            "uplinked vSwitch) — the host hears no neighbors by configuration"
        )
    # An empty table with discovery listening is a FINDING (the far port does
    # not advertise, or the link is down), never not-present.
    return {"raw": raw, "normalized": normalized, "context": context}


# --- vmware_vswitches ------------------------------------------------------------

_PNIC_KEY_PREFIX = "key-vim.host.PhysicalNic-"
_PORTGROUP_KEY_PREFIX = "key-vim.host.PortGroup-"


def _key_maps(network):
    """(pnic key -> device, portgroup key -> name) with prefix-strip fallbacks."""
    pnics = {}
    for pnic in _dicts(network.get("pnic")):
        if pnic.get("key") and pnic.get("device"):
            pnics[pnic["key"]] = pnic["device"]
    portgroups = {}
    for portgroup in _dicts(network.get("portgroup")):
        name = _get(portgroup, "spec", "name")
        if portgroup.get("key") and name:
            portgroups[portgroup["key"]] = name
    return pnics, portgroups


def _resolve(key, mapping, prefix):
    if key in mapping:
        return mapping[key]
    text = str(key)
    return text[len(prefix) :] if text.startswith(prefix) else text


def _teaming_fields(teaming):
    """HostNicTeamingPolicy -> the comparable teaming leaves (order of NICs preserved)."""
    teaming = teaming if isinstance(teaming, dict) else {}
    order = teaming.get("nicOrder") if isinstance(teaming.get("nicOrder"), dict) else {}
    return {
        "teaming_policy": _strip(teaming.get("policy")),
        # Failover ORDER is the contract; never sorted.
        "active_uplinks": [str(nic) for nic in aslist(order.get("activeNic"))],
        "standby_uplinks": [str(nic) for nic in aslist(order.get("standbyNic"))],
        "notify_switches": to_bool(teaming.get("notifySwitches")),
        "rolling_order": to_bool(teaming.get("rollingOrder")),
        "beacon_probing": to_bool(_get(teaming, "failureCriteria", "checkBeacon")),
    }


def _security_fields(security):
    security = security if isinstance(security, dict) else {}
    return {
        "promiscuous": to_bool(security.get("allowPromiscuous")),
        "mac_changes": to_bool(security.get("macChanges")),
        "forged_transmits": to_bool(security.get("forgedTransmits")),
    }


def _normalize_vswitches(network):
    """vswitch|<name> rows plus proxyswitch|count; runtime port counts to context."""
    pnic_names, portgroup_names = _key_maps(network)
    discovery = _discovery_by_vswitch(network)
    normalized = {}
    runtime = {}
    for vswitch in _dicts(network.get("vswitch")):
        name = _strip(vswitch.get("name"))
        if name is None:
            continue
        spec = vswitch.get("spec") if isinstance(vswitch.get("spec"), dict) else {}
        policy = spec.get("policy") if isinstance(spec.get("policy"), dict) else {}
        row = {
            "mtu": to_int(vswitch.get("mtu")),
            "num_ports_configured": to_int(spec.get("numPorts")),
            "uplinks": sorted(
                _resolve(key, pnic_names, _PNIC_KEY_PREFIX) for key in aslist(vswitch.get("pnic"))
            ),
            "portgroups": sorted(
                _resolve(key, portgroup_names, _PORTGROUP_KEY_PREFIX)
                for key in aslist(vswitch.get("portgroup"))
            ),
            "bridge_type": discovery[name]["bridge_type"],
            "discovery_protocol": discovery[name]["protocol"],
            "discovery_operation": discovery[name]["operation"],
            "shaping_enabled": to_bool(_get(policy, "shapingPolicy", "enabled")),
        }
        row.update(_security_fields(policy.get("security")))
        row.update(_teaming_fields(policy.get("nicTeaming")))
        normalized["vswitch|%s" % (name,)] = row
        # Runtime numPorts is elastic (1536/2560 on 8.x) — context, not diffed.
        runtime[name] = {
            "num_ports": to_int(vswitch.get("numPorts")),
            "num_ports_available": to_int(vswitch.get("numPortsAvailable")),
        }
    # Absent property (no vCenter, no DVS) reads as zero proxy switches.
    normalized["proxyswitch|count"] = {"value": len(_dicts(network.get("proxySwitch")))}
    return normalized, runtime


def _collect_vswitches(ctx):
    _props, network, result = _fetch_network_group(ctx)
    normalized, runtime = _normalize_vswitches(network)
    context = {"vswitches_total": len(runtime), "runtime_ports": runtime}
    return {"raw": _network_raw(result), "normalized": normalized, "context": context}


# --- vmware_portgroups -----------------------------------------------------------

_TEAMING_LEAVES = ("policy", "notifySwitches", "rollingOrder", "nicOrder", "failureCriteria")


def _overridden(container, leaves):
    """True when the port group's OWN spec sets any of the leaves.

    hostd emits an empty container (parsed to None) when the group inherits;
    a nested container (nicOrder, failureCriteria) counts as set when any of
    its own leaves is set.
    """
    if not isinstance(container, dict):
        return False
    for leaf in leaves:
        value = container.get(leaf)
        if isinstance(value, dict):
            if any(item is not None for key, item in value.items() if key != "_type"):
                return True
        elif value is not None:
            return True
    return False


def _normalize_portgroups(network):
    """portgroup|<name> rows from computedPolicy (the EFFECTIVE policy) plus
    per-leaf override flags from spec.policy. Port counts move with VM power
    state and stay raw-only."""
    normalized = {}
    for portgroup in _dicts(network.get("portgroup")):
        spec = portgroup.get("spec") if isinstance(portgroup.get("spec"), dict) else {}
        name = _strip(spec.get("name"))
        if name is None:
            continue
        computed = portgroup.get("computedPolicy")
        computed = computed if isinstance(computed, dict) else {}
        own = spec.get("policy") if isinstance(spec.get("policy"), dict) else {}
        row = {
            "vswitch": _strip(spec.get("vswitchName")),
            # 4095 = VGT trunk (guest tagging).
            "vlan_id": to_int(spec.get("vlanId")),
        }
        row.update(_security_fields(computed.get("security")))
        row.update(_teaming_fields(computed.get("nicTeaming")))
        row["security_overridden"] = _overridden(
            own.get("security"), ("allowPromiscuous", "macChanges", "forgedTransmits")
        )
        row["teaming_overridden"] = _overridden(own.get("nicTeaming"), _TEAMING_LEAVES)
        normalized["portgroup|%s" % (name,)] = row
    return normalized


def _collect_portgroups(ctx):
    _props, network, result = _fetch_network_group(ctx)
    normalized = _normalize_portgroups(network)
    ports = {}
    for portgroup in _dicts(network.get("portgroup")):
        name = _get(portgroup, "spec", "name")
        if name:
            ports[name] = len(_dicts(portgroup.get("port")))
    raw = _network_raw(result)
    raw["attached_ports"] = ports
    return {"raw": raw, "normalized": normalized, "context": {"portgroups_total": len(normalized)}}


# --- vmware_vmknics ----------------------------------------------------------------


def _services_by_vnic_key(manager_info):
    """virtualNicManagerInfo.netConfig[].selectedVnic ('<nicType>.<vnic key>') -> key -> [types]."""
    services = {}
    for config in _dicts(_get(manager_info, "netConfig")):
        nic_type = _strip(config.get("nicType"))
        if nic_type is None:
            continue
        for selected in aslist(config.get("selectedVnic")):
            text = str(selected)
            # Joined on the vnic KEY (the part after the first dot), never the
            # device name — the key is what hostd writes in selectedVnic.
            if "." not in text:
                continue
            _prefix, key = text.split(".", 1)
            services.setdefault(key, []).append(nic_type)
    return services


def _normalize_vmknics(network, manager_info):
    """vmk|vmkN rows. ipv6_static keeps origin == manual addresses only (link-local
    and autoconf churn); services resolve through selectedVnic by key."""
    services = _services_by_vnic_key(manager_info)
    normalized = {}
    for vnic in _dicts(network.get("vnic")):
        device = _strip(vnic.get("device"))
        if device is None:
            continue
        spec = vnic.get("spec") if isinstance(vnic.get("spec"), dict) else {}
        ip = spec.get("ip") if isinstance(spec.get("ip"), dict) else {}
        static_v6 = []
        for address in _dicts(_get(ip, "ipV6Config", "ipV6Address")):
            if _strip(address.get("origin")) == "manual" and address.get("ipAddress"):
                static_v6.append(
                    "%s/%s" % (address["ipAddress"], to_int(address.get("prefixLength")))
                )
        normalized["vmk|%s" % (device,)] = {
            # None on a DVS/opaque-network vmk (no standard port group name).
            "portgroup": _strip(vnic.get("portgroup")) or _strip(spec.get("portgroup")),
            "ip": _strip(ip.get("ipAddress")),
            "netmask": _strip(ip.get("subnetMask")),
            "dhcp": to_bool(ip.get("dhcp")),
            "ipv6_static": sorted(static_v6),
            "mtu": to_int(spec.get("mtu")),
            "mac": _lower(spec.get("mac")),
            "netstack": _strip(spec.get("netStackInstanceKey")) or "defaultTcpipStack",
            "services": sorted(set(services.get(vnic.get("key"), []))),
            "pinned_pnic": _strip(spec.get("pinnedPnic")),
        }
    return normalized


def _collect_vmknics(ctx):
    props, network, result = _fetch_network_group(ctx)
    normalized = _normalize_vmknics(network, props.get("config.virtualNicManagerInfo"))
    context = {
        "vmknics_total": len(normalized),
        "ipv6_enabled": to_bool(network.get("ipV6Enabled")),
    }
    return {"raw": _network_raw(result), "normalized": normalized, "context": context}


# --- vmware_host_routes -------------------------------------------------------------

_DEFAULT_STACK = "defaultTcpipStack"


def _route_rows(entries, family):
    rows = {}
    for entry in _dicts(entries):
        if entry.get("network") is None:
            continue
        prefix = "%s/%s" % (entry["network"], to_int(entry.get("prefixLength")))
        rows[prefix] = {
            "gateway": _strip(entry.get("gateway")),
            "device": _strip(entry.get("deviceName")),
            "family": family,
        }
    return rows


def _normalize_host_routes(network):
    """route|<stack>|<net>/<len>, gateway|<stack> and dns|* rows.

    Config routes come from every netStackInstance's routeTableConfig
    (HostIpRouteOp unwrapped); the default stack's routeTableInfo (state,
    deprecated since 5.5 but populated on 8.x — recorded in context either
    way) overlays in_state on the default stack only. IPv6 routes are
    included with family "ipv6".
    """
    normalized = {}
    stacks = []
    for stack in _dicts(network.get("netStackInstance")):
        key = _strip(stack.get("key")) or _strip(stack.get("name"))
        if key is None:
            continue
        stacks.append(key)
        table = stack.get("routeTableConfig")
        table = table if isinstance(table, dict) else {}
        rows = {}
        for wire, family in (("ipRoute", "ipv4"), ("ipv6Route", "ipv6")):
            routes = [op.get("route") for op in _dicts(table.get(wire))]
            rows.update(_route_rows(routes, family))
        for prefix, row in rows.items():
            row["in_config"] = True
            row["in_state"] = False if key == _DEFAULT_STACK else None
            normalized["route|%s|%s" % (key, prefix)] = row
        route_config = stack.get("ipRouteConfig")
        route_config = route_config if isinstance(route_config, dict) else {}
        normalized["gateway|%s" % (key,)] = {
            "ipv4": _strip(route_config.get("defaultGateway")),
            "ipv4_device": _strip(route_config.get("gatewayDevice")),
            "ipv6": _strip(route_config.get("ipV6DefaultGateway")),
            "ipv6_device": _strip(route_config.get("ipV6GatewayDevice")),
        }
    if _DEFAULT_STACK not in stacks:
        # Older shape without netStackInstance: the host-level ipRouteConfig.
        route_config = network.get("ipRouteConfig")
        route_config = route_config if isinstance(route_config, dict) else {}
        normalized["gateway|%s" % (_DEFAULT_STACK,)] = {
            "ipv4": _strip(route_config.get("defaultGateway")),
            "ipv4_device": _strip(route_config.get("gatewayDevice")),
            "ipv6": _strip(route_config.get("ipV6DefaultGateway")),
            "ipv6_device": _strip(route_config.get("ipV6GatewayDevice")),
        }
    table_info = network.get("routeTableInfo")
    table_present = isinstance(table_info, dict)
    if table_present:
        state = _route_rows(table_info.get("ipRoute"), "ipv4")
        state.update(_route_rows(table_info.get("ipv6Route"), "ipv6"))
        for prefix, row in state.items():
            key = "route|%s|%s" % (_DEFAULT_STACK, prefix)
            if key in normalized:
                normalized[key]["in_state"] = True
            else:
                row["in_config"] = False
                row["in_state"] = True
                normalized[key] = row
    dns = network.get("dnsConfig") if isinstance(network.get("dnsConfig"), dict) else {}
    normalized["dns|hostname"] = {"value": _strip(dns.get("hostName"))}
    normalized["dns|domain"] = {"value": _strip(dns.get("domainName"))}
    # Ordered on purpose: a primary/secondary swap is a signal.
    normalized["dns|servers"] = {"value": [str(item) for item in aslist(dns.get("address"))]}
    normalized["dns|search"] = {"value": [str(item) for item in aslist(dns.get("searchDomain"))]}
    normalized["dns|dhcp"] = {"value": to_bool(dns.get("dhcp"))}
    context = {
        "stacks": stacks,
        "route_table_info_present": table_present,
        "routes_total": sum(1 for key in normalized if key.startswith("route|")),
        "ipv6_routes": sum(
            1
            for key, row in normalized.items()
            if key.startswith("route|") and row.get("family") == "ipv6"
        ),
    }
    return normalized, context


def _collect_host_routes(ctx):
    _props, network, result = _fetch_network_group(ctx)
    normalized, context = _normalize_host_routes(network)
    return {"raw": _network_raw(result), "normalized": normalized, "context": context}


# --- vmware_time_syslog --------------------------------------------------------------

_SYSLOG_OPTIONS = {
    "Syslog.global.logHost": "syslog_loghost",
    "Syslog.global.logDir": "syslog_logdir",
    "Syslog.global.logDirUnique": "syslog_logdir_unique",
    "Syslog.global.logCheckSSLCerts": "syslog_check_ssl_certs",
    "Syslog.global.logLevel": "syslog_log_level",
}


def _options_dict(options):
    """config.option / extraConfig OptionValue list -> {key: value} (typed values kept)."""
    result = {}
    for option in _dicts(options):
        if option.get("key") is not None:
            result[str(option["key"])] = option.get("value")
    return result


def _services_dict(service_info):
    return {
        service["key"]: service
        for service in _dicts(_get(service_info, "service"))
        if service.get("key")
    }


def _ntp_servers(ntp_config):
    """Union of ntpConfig.server[] and the 'server X' lines of configFile[] (7.0U3+
    may leave server[] empty while the config file still names the peers)."""
    servers = {str(item) for item in aslist(_get(ntp_config, "server")) if item}
    for line in aslist(_get(ntp_config, "configFile")):
        parts = str(line).split()
        if len(parts) >= 2 and parts[0] in ("server", "peer", "pool"):
            servers.add(parts[1])
    return sorted(servers)


def _normalize_time_syslog(date_time, services, options):
    """dateTimeInfo + ntpd/ptpd services + Syslog.global.* options -> flat scalars."""
    date_time = date_time if isinstance(date_time, dict) else {}
    ntpd = services.get("ntpd") or {}
    ptpd = services.get("ptpd") or {}
    loghost = options.get("Syslog.global.logHost")
    normalized = {
        "ntp_servers": _ntp_servers(date_time.get("ntpConfig")),
        # 7.0.3+ fields; None on older builds.
        "time_services_enabled": to_bool(date_time.get("enabled")),
        "clock_protocol": _strip(date_time.get("systemClockProtocol")),
        "ntp_service_sync": to_bool(date_time.get("serviceSync")),
        "fallback_disabled": to_bool(date_time.get("disableFallback")),
        "ntp_running": to_bool(ntpd.get("running")),
        "ntp_policy": _strip(ntpd.get("policy")),
        "ptp_running": to_bool(ptpd.get("running")),
        "ptp_policy": _strip(ptpd.get("policy")),
        # 8.x stores comma-separated multi-targets; sorted so order is not a diff.
        "syslog_loghost": sorted(
            item.strip() for item in str(loghost or "").split(",") if item.strip()
        ),
    }
    for key, field in _SYSLOG_OPTIONS.items():
        if field == "syslog_loghost":
            continue
        normalized[field] = options.get(key)
    context = {
        "timezone": _get(date_time, "timeZone", "key"),
        "last_sync_time": date_time.get("lastSyncTime"),
        "remote_ntp_server": date_time.get("remoteNtpServer"),
        "ntp_run_time": to_int(date_time.get("ntpRunTime")),
        "syslog_options_present": sorted(key for key in _SYSLOG_OPTIONS if key in options),
    }
    return normalized, context


def _curate_service_group(path, value):
    if path == "config.service":
        return _prune(value, {"sourcePackage"})
    return value


def _curate_option_group(path, value):
    if path == "config.option":
        return _curated_options(value, _CURATED_OPTIONS | set(_SYSLOG_OPTIONS))
    return value


def _collect_time_syslog(ctx):
    time_props, time_result = _fetch_host(ctx, _TIME_PATHS)
    service_props, service_result = _fetch_host(ctx, _SERVICE_PATHS)
    option_props, option_result = _fetch_option_group(ctx)
    normalized, context = _normalize_time_syslog(
        time_props.get("config.dateTimeInfo"),
        _services_dict(service_props.get("config.service")),
        _options_dict(option_props.get("config.option")),
    )
    raw = {
        _request_key("HostSystem", (_HOST_MOID,), _TIME_PATHS): _raw_objects(time_result),
        _request_key("HostSystem", (_HOST_MOID,), _SERVICE_PATHS): _raw_objects(
            service_result, _curate_service_group
        ),
        _request_key("HostSystem", (_HOST_MOID,), _OPTION_PATHS): _raw_objects(
            option_result, _curate_option_group
        ),
    }
    return {"raw": raw, "normalized": normalized, "context": context}


# --- vmware_host_services -------------------------------------------------------------

_MOB_OPTION = "Config.HostAgent.plugins.solo.enableMob"


def _normalize_host_services(service_info, lockdown_mode, management_server, options):
    """service|<key> rows (whatever hostd lists — never a fixed set) plus the
    lockdown / MOB / vCenter-membership scalars."""
    normalized = {}
    for key, service in sorted(_services_dict(service_info).items()):
        normalized["service|%s" % (key,)] = {
            "running": to_bool(service.get("running")),
            "policy": _strip(service.get("policy")),
            "required": to_bool(service.get("required")),
            "label": _strip(service.get("label")),
        }
    normalized["lockdown|mode"] = {"value": _strip(lockdown_mode)}
    normalized["mob|enabled"] = {"value": to_bool(options.get(_MOB_OPTION))}
    # None on a standalone host — the real "was it joined to vCenter" signal.
    normalized["vcenter|management_server"] = {"value": _strip(management_server)}
    return normalized


def _collect_host_services(ctx):
    service_props, service_result = _fetch_host(ctx, _SERVICE_PATHS)
    option_props, option_result = _fetch_option_group(ctx)
    normalized = _normalize_host_services(
        service_props.get("config.service"),
        service_props.get("config.lockdownMode"),
        service_props.get("summary.managementServerIp"),
        _options_dict(option_props.get("config.option")),
    )
    context = {
        "services_total": sum(1 for key in normalized if key.startswith("service|")),
        "services_running": sorted(
            key.split("|", 1)[1]
            for key, row in normalized.items()
            if key.startswith("service|") and row["running"]
        ),
    }
    raw = {
        _request_key("HostSystem", (_HOST_MOID,), _SERVICE_PATHS): _raw_objects(
            service_result, _curate_service_group
        ),
        _request_key("HostSystem", (_HOST_MOID,), _OPTION_PATHS): _raw_objects(
            option_result, _curate_option_group
        ),
    }
    return {"raw": raw, "normalized": normalized, "context": context}


# --- vmware_advanced_options -------------------------------------------------------------

# The curated advanced-option set (full keys). Net.NetNetqRxQueueFeatPairEnable
# is deliberately absent: it is esxcli-only, not exposed via OptionManager.
_CURATED_OPTIONS = frozenset(
    {
        "UserVars.ESXiShellTimeOut",
        "UserVars.ESXiShellInteractiveTimeOut",
        "UserVars.SuppressShellWarning",
        "Config.HostAgent.plugins.solo.enableMob",
        "Net.MaxNetifTxQueueLen",
        "Net.CoalesceDefaultOn",
        "Net.TcpipHeapMax",
        "Mem.AllocGuestLargePage",
        "Mem.ShareForceSalting",
        "Power.CpuPolicy",
        "Numa.LocalityWeightActionAffinity",
        "Misc.BlueScreenTimeout",
        "Security.AccountLockFailures",
        "Security.PasswordQualityControl",
    }
)


def _normalize_advanced_options(options):
    """opt|<key> rows for the curated set; values keep the type OptionValue.value
    carried (int/long -> int, boolean -> bool, string -> str)."""
    normalized = {}
    absent = []
    for key in sorted(_CURATED_OPTIONS):
        if key in options:
            normalized["opt|%s" % (key,)] = {"value": options[key]}
        else:
            absent.append(key)
    return normalized, absent


def _collect_advanced_options(ctx):
    props, result = _fetch_option_group(ctx)
    options = _options_dict(props.get("config.option"))
    normalized, absent = _normalize_advanced_options(options)
    context = {"options_total": len(options), "curated_absent": absent}
    raw = {
        _request_key("HostSystem", (_HOST_MOID,), _OPTION_PATHS): _raw_objects(
            result, _curate_option_group
        )
    }
    return {"raw": raw, "normalized": normalized, "context": context}


# --- vmware_firewall_rulesets -------------------------------------------------------------


def _normalize_firewall(firewall):
    """ruleset|<key> rows plus the two default-policy scalars."""
    normalized = {}
    for ruleset in _dicts(_get(firewall, "ruleset")):
        key = _strip(ruleset.get("key"))
        if key is None:
            continue
        allowed_hosts = ruleset.get("allowedHosts")
        allowed = []
        if isinstance(allowed_hosts, dict):
            allowed.extend(str(item) for item in aslist(allowed_hosts.get("ipAddress")))
            for net in _dicts(allowed_hosts.get("ipNetwork")):
                allowed.append("%s/%s" % (net.get("network"), to_int(net.get("prefixLength"))))
            all_ip = to_bool(allowed_hosts.get("allIp"))
        else:
            all_ip = True  # no allowedHosts block = unrestricted
        normalized["ruleset|%s" % (key,)] = {
            "enabled": to_bool(ruleset.get("enabled")),
            "all_ip": all_ip,
            "allowed": sorted(allowed),
            "service": _strip(ruleset.get("service")),
            # 8.0U2+ optionals.
            "user_controllable": to_bool(ruleset.get("userControllable")),
            "ip_list_user_configurable": to_bool(ruleset.get("ipListUserConfigurable")),
        }
    normalized["firewall|incoming_blocked"] = {
        "value": to_bool(_get(firewall, "defaultPolicy", "incomingBlocked"))
    }
    normalized["firewall|outgoing_blocked"] = {
        "value": to_bool(_get(firewall, "defaultPolicy", "outgoingBlocked"))
    }
    return normalized


def _collect_firewall_rulesets(ctx):
    props, result = _fetch_host(ctx, _FIREWALL_PATHS)
    firewall = props.get("config.firewall")
    if not isinstance(firewall, dict):
        raise SkipCheck("config.firewall not present on this host (firewallInfo unset)")
    normalized = _normalize_firewall(firewall)
    context = {
        "rulesets_total": sum(1 for key in normalized if key.startswith("ruleset|")),
        "rulesets_enabled": sorted(
            key.split("|", 1)[1]
            for key, row in normalized.items()
            if key.startswith("ruleset|") and row["enabled"]
        ),
    }
    # Port definitions are static package content; dropped from raw.
    raw = {
        _request_key("HostSystem", (_HOST_MOID,), _FIREWALL_PATHS): _raw_objects(
            result, lambda path, value: _prune(value, {"rule"})
        )
    }
    return {"raw": raw, "normalized": normalized, "context": context}


# --- vmware_datastores -------------------------------------------------------------------


def _mounts_by_url(mount_info):
    """mountInfo.path -> HostFileSystemMountInfo; joins to summary.url stripped of ds://."""
    mounts = {}
    for entry in _dicts(mount_info):
        path = _strip(_get(entry, "mountInfo", "path"))
        if path:
            mounts[path.rstrip("/")] = entry
    return mounts


def _normalize_datastores(datastore_objects, mount_info):
    """datastore|<summary.name> rows; the key set is driven by the Datastore objects."""
    mounts = _mounts_by_url(mount_info)
    normalized = {}
    for obj in datastore_objects:
        props = obj.get("props") or {}
        summary = props.get("summary") if isinstance(props.get("summary"), dict) else {}
        name = _strip(summary.get("name"))
        if name is None:
            continue
        info = props.get("info") if isinstance(props.get("info"), dict) else {}
        url = str(summary.get("url") or "")
        path = url[len("ds://") :] if url.startswith("ds://") else url
        mount = mounts.get(path.rstrip("/")) or {}
        volume = mount.get("volume") if isinstance(mount.get("volume"), dict) else {}
        vmfs = info.get("vmfs") if isinstance(info.get("vmfs"), dict) else None
        nas = info.get("nas") if isinstance(info.get("nas"), dict) else None
        accessible = to_bool(summary.get("accessible"))
        uuid = None
        local = None
        if vmfs is not None:
            uuid = _lower(vmfs.get("uuid"))
            local = to_bool(vmfs.get("local"))
        elif volume.get("_type") in ("HostVmfsVolume", "HostVffsVolume"):
            uuid = _lower(volume.get("uuid"))
            local = to_bool(volume.get("local"))
        remote = None
        if nas is not None:
            remote = "%s:%s" % (nas.get("remoteHost"), nas.get("remotePath"))
        elif volume.get("_type") == "HostNasVolume":
            remote = "%s:%s" % (volume.get("remoteHost"), volume.get("remotePath"))
        normalized["datastore|%s" % (name,)] = {
            "type": _strip(summary.get("type")),
            "uuid": uuid,
            "remote": remote,
            "local": local,
            "capacity_bytes": to_int(summary.get("capacity")) if accessible else None,
            "free_bytes": to_int(summary.get("freeSpace")) if accessible else None,
            "accessible": accessible,
            # None when the datastore did not join a mountInfo entry.
            "mounted": to_bool(_get(mount, "mountInfo", "mounted")) if mount else None,
        }
    return normalized


def _collect_datastores(ctx):
    host_props, host_result = _fetch_host(ctx, _DATASTORE_HOST_PATHS)
    refs = [ref["moid"] for ref in _dicts(host_props.get("datastore")) if ref.get("moid")]
    raw = {
        _request_key("HostSystem", (_HOST_MOID,), _DATASTORE_HOST_PATHS): _raw_objects(host_result)
    }
    mount_info = host_props.get("config.fileSystemVolume.mountInfo")
    context = {
        "datastores_total": len(refs),
        "mounted_volumes_total": len(_dicts(mount_info)),
    }
    if not refs:
        # A successful read of an empty list is {} — the removal of every
        # datastore is reported with its old identity, never as not-present.
        return {"raw": raw, "normalized": {}, "context": context}
    result = _retrieve(ctx, "Datastore", refs, _DATASTORE_PATHS)
    for obj in result.get("objects") or []:
        _refuse_missing(obj, "Datastore %s" % (_get(obj, "obj", "moid"),))
    raw[_request_key("Datastore", refs, _DATASTORE_PATHS)] = _raw_objects(result)
    normalized = _normalize_datastores(result.get("objects") or [], mount_info)
    context["unjoined_volumes"] = sorted(
        str(_get(entry, "volume", "name"))
        for entry in _dicts(mount_info)
        if "datastore|%s" % (_get(entry, "volume", "name"),) not in normalized
    )
    return {"raw": raw, "normalized": normalized, "context": context}


# --- vmware_storage_devices -----------------------------------------------------------------


def _normalize_storage_devices(hbas, luns):
    """hba|vmhbaN rows for every adapter; lun|<canonicalName> rows for
    HostScsiDisk entries whose deviceType is disk (a BMC virtual-media
    CD-ROM comes and goes with the mount, so it is counted, never keyed)."""
    normalized = {}
    other_luns = {}
    for hba in _dicts(hbas):
        device = _strip(hba.get("device"))
        if device is None:
            continue
        normalized["hba|%s" % (device,)] = {
            "type": hba.get("_type"),
            "driver": _strip(hba.get("driver")),
            "model": _strip(hba.get("model")),
            # Diffed, never asserted: 'unknown' is normal for usb-storage.
            "status": _strip(hba.get("status")),
            "storage_protocol": _strip(hba.get("storageProtocol")),
            "pci": _strip(hba.get("pci")),
        }
    for lun in _dicts(luns):
        device_type = _strip(lun.get("deviceType"))
        if lun.get("_type") != "HostScsiDisk" or device_type != "disk":
            other_luns[device_type or "unknown"] = other_luns.get(device_type or "unknown", 0) + 1
            continue
        name = _strip(lun.get("canonicalName"))
        if name is None:
            continue
        capacity = lun.get("capacity") if isinstance(lun.get("capacity"), dict) else {}
        block_size = to_int(capacity.get("blockSize"))
        blocks = to_int(capacity.get("block"))
        normalized["lun|%s" % (name,)] = {
            "vendor": _strip(lun.get("vendor")),
            "model": _strip(lun.get("model")),
            "capacity_bytes": block_size * blocks
            if block_size is not None and blocks is not None
            else None,
            "device_type": device_type,
            "operational_state": sorted(str(item) for item in aslist(lun.get("operationalState"))),
            "ssd": to_bool(lun.get("ssd")),
            "local": to_bool(lun.get("localDisk")),
            "protocol": _strip(lun.get("applicationProtocol")),
            "disk_type": _strip(lun.get("scsiDiskType")),
        }
    return normalized, other_luns


def _collect_storage_devices(ctx):
    props, result = _fetch_host(ctx, _STORAGE_PATHS)
    for path in _STORAGE_PATHS:
        if path not in props:
            # A host without any HBA/LUN list is not a state — it is a read
            # the property collector did not answer.
            raise CollectError("%s absent from the host answer" % (path,))
    normalized, other_luns = _normalize_storage_devices(
        props.get("config.storageDevice.hostBusAdapter"), props.get("config.storageDevice.scsiLun")
    )
    context = {
        "hbas_total": sum(1 for key in normalized if key.startswith("hba|")),
        "disks_total": sum(1 for key in normalized if key.startswith("lun|")),
        "non_disk_luns": other_luns,
    }
    raw = {
        _request_key("HostSystem", (_HOST_MOID,), _STORAGE_PATHS): _raw_objects(
            result,
            lambda path, value: _prune(
                value, {"standardInquiry", "durableName", "descriptor", "alternateName"}
            ),
        )
    }
    return {"raw": raw, "normalized": normalized, "context": context}


# --- vmware_health_sensors ------------------------------------------------------------------

# hostd appends the discrete state to the sensor name: "Fan Redundancy --- Fully Redundant".
_SENSOR_SUFFIX = re.compile(r"\s+---\s+.*$")
# Numeric sensors whose reading is a physical quantity worth carrying in context.
_PHYSICAL_UNITS = frozenset({"degrees c", "volts", "rpm", "watts", "amps", "percent"})
_STATUS_HALVES = (
    ("cpuStatusInfo", "cpu"),
    ("memoryStatusInfo", "memory"),
    ("storageStatusInfo", "storage"),
)


def _scaled_reading(sensor):
    reading = to_int(sensor.get("currentReading"))
    modifier = to_int(sensor.get("unitModifier"))
    if reading is None:
        return None
    if modifier is None or modifier == 0:
        return reading
    return reading * (10**modifier)


def _sensor_state(raw_name):
    """The discrete reading hostd appends to the name ('Fully Redundant'); None for numeric ones."""
    match = _SENSOR_SUFFIX.search(raw_name)
    return _strip(match.group(0).split("---", 1)[1]) if match else None


def _normalize_health_sensors(runtime):
    """sensor|<base-name> rows (suffix-stripped; |<id> when a base name repeats;
    |<id>|<state> when hostd lists one discrete sensor once per asserted state)
    and status|<half>|<name> rows; physical readings to context."""
    normalized = {}
    readings = {}
    sensors = _dicts(_get(runtime, "systemHealthInfo", "numericSensorInfo"))
    by_base = {}
    for sensor in sensors:
        raw_name = _strip(sensor.get("name"))
        if raw_name is None:
            continue
        by_base.setdefault(_SENSOR_SUFFIX.sub("", raw_name), []).append(sensor)
    for base, group in by_base.items():
        ids = {}
        for sensor in group:
            ids[_strip(sensor.get("id"))] = ids.get(_strip(sensor.get("id")), 0) + 1
        ordinals = {}
        for sensor in group:
            state = _sensor_state(_strip(sensor.get("name")))
            key = "sensor|%s" % (base,)
            if len(group) > 1:
                # Same base name from different sensor ids: keep both, disambiguated.
                sensor_id = _strip(sensor.get("id"))
                key = "sensor|%s|%s" % (base, sensor_id)
                if ids[sensor_id] > 1:
                    # One IPMI discrete sensor listed once per asserted state:
                    # each state is its own row (a state no longer asserted is
                    # a removed key), never a later entry overwriting an earlier one.
                    ordinals[sensor_id] = ordinals.get(sensor_id, 0) + 1
                    key = "%s|%s" % (key, state or ordinals[sensor_id])
            normalized[key] = {
                "health": _lower(_get(sensor, "healthState", "key")),
                "type": _strip(sensor.get("sensorType")),
                "state": state,
            }
            if _lower(sensor.get("baseUnits")) in _PHYSICAL_UNITS:
                readings[key.split("|", 1)[1]] = {
                    "reading": _scaled_reading(sensor),
                    "units": _strip(sensor.get("baseUnits")),
                }
    status_total = 0
    for wire, half in _STATUS_HALVES:
        for element in _dicts(_get(runtime, "hardwareStatusInfo", wire)):
            name = _strip(element.get("name"))
            if name is None:
                continue
            status_total += 1
            normalized["status|%s|%s" % (half, name)] = {
                # Capitalised enum on the wire (Green/Yellow/Red/Unknown).
                "health": _lower(_get(element, "status", "key")),
            }
    context = {"sensors_total": len(sensors), "status_elements_total": status_total}
    return normalized, readings, context


def _collect_health_sensors(ctx):
    props, result = _fetch_host(ctx, _HEALTH_PATHS)
    runtime = props.get("runtime.healthSystemRuntime")
    if not isinstance(runtime, dict):
        raise SkipCheck("runtime.healthSystemRuntime not present (no IPMI/health provider)")
    normalized, readings, context = _normalize_health_sensors(runtime)
    if not normalized:
        raise SkipCheck("health runtime present but both sensor halves are empty")
    context["readings"] = readings
    raw = {_request_key("HostSystem", (_HOST_MOID,), _HEALTH_PATHS): _raw_objects(result)}
    return {"raw": raw, "normalized": normalized, "context": context}


# --- per-VM property set (shared by the VM checks and autostart) ------------------------------


def _vm_records(result):
    """VM objects -> [{"moid", "name", "props", "missing"}] with unique names.

    A duplicate name gets a |<moid> suffix; an object without a name keys by
    moid. missingSet entries are tolerated here (orphaned/inaccessible
    registrations) and surfaced in context by the callers.
    """
    records = []
    for obj in result.get("objects") or []:
        moid = _get(obj, "obj", "moid") or "?"
        props = obj.get("props") or {}
        records.append(
            {
                "moid": moid,
                "name": _strip(props.get("name")) or moid,
                "props": props,
                "missing": obj.get("missing") or [],
            }
        )
    counts = {}
    for record in records:
        counts[record["name"]] = counts.get(record["name"], 0) + 1
    for record in records:
        if counts[record["name"]] > 1:
            record["name"] = "%s|%s" % (record["name"], record["moid"])
    return records


def _fetch_vm_set(ctx):
    """(records, raw, context) for every registered VM; records is [] when none."""
    host_props, host_result = _fetch_host(ctx, _HOST_VM_PATHS)
    moids = [ref["moid"] for ref in _dicts(host_props.get("vm")) if ref.get("moid")]
    raw = {_request_key("HostSystem", (_HOST_MOID,), _HOST_VM_PATHS): _raw_objects(host_result)}
    context = {"vms_total": len(moids)}
    if not moids:
        return [], raw, context
    result = _retrieve(ctx, "VirtualMachine", moids, _VM_PATHS, timeout=C.VSPHERE_BIG_CALL_TIMEOUT)
    records = _vm_records(result)
    context["pages"] = result.get("pages")
    context["unreadable"] = {
        record["name"]: sorted(str(entry.get("path")) for entry in record["missing"])
        for record in records
        if record["missing"]
    }
    raw[_request_key("VirtualMachine", moids, _VM_PATHS)] = _raw_objects(result, _curate_vm)
    return records, raw, context


def _require_vms(ctx):
    records, raw, context = _fetch_vm_set(ctx)
    if not records:
        raise SkipCheck("no virtual machines registered on this host")
    return records, raw, context


def _device_projection(device):
    """The identity/binding facets of one VirtualDevice for raw (bulk backing fields dropped)."""
    backing = device.get("backing") if isinstance(device.get("backing"), dict) else {}
    return {
        "type": device.get("_type"),
        "key": device.get("key"),
        "label": _get(device, "deviceInfo", "label"),
        "controller_key": device.get("controllerKey"),
        "unit_number": device.get("unitNumber"),
        "pci_slot": _get(device, "slotInfo", "pciSlotNumber"),
        "mac": device.get("macAddress"),
        "address_type": device.get("addressType"),
        "backing_type": backing.get("_type"),
        "backing_name": backing.get("deviceName") or backing.get("fileName") or backing.get("id"),
        "connected": _get(device, "connectable", "connected"),
        "start_connected": _get(device, "connectable", "startConnected"),
        "capacity_kb": device.get("capacityInKB"),
    }


def _curate_vm(path, value):
    if path == "config.hardware.device":
        return [_device_projection(device) for device in _dicts(value)]
    if path == "config.extraConfig":
        return _curated_options(value, _TUNING_KEYS)
    return value


# --- vmware_vms ----------------------------------------------------------------------------


def _count_snapshots(tree):
    total = 0
    for node in _dicts(tree):
        total += 1 + _count_snapshots(node.get("childSnapshotList"))
    return total


def _affinity(props):
    affinity = props.get("config.cpuAffinity")
    if not isinstance(affinity, dict):
        return None
    cpus = [to_int(item) for item in aslist(affinity.get("affinitySet"))]
    return sorted(cpu for cpu in cpus if cpu is not None)


_BOOT_DEVICE_PREFIX = "VirtualMachineBootOptionsBootable"


def _boot_order(boot_options):
    """bootOrder[] -> ['disk:2000', 'ethernet:4000', 'cdrom'] in order; None without bootOptions,
    [] when the VM boots in firmware default order."""
    if not isinstance(boot_options, dict):
        return None
    order = []
    for device in _dicts(boot_options.get("bootOrder")):
        kind = str(device.get("_type") or "device")
        if kind.startswith(_BOOT_DEVICE_PREFIX):
            kind = kind[len(_BOOT_DEVICE_PREFIX) :]
        if kind.endswith("Device"):
            kind = kind[: -len("Device")]
        kind = kind.lower()
        key = to_int(device.get("deviceKey"))
        order.append("%s:%d" % (kind, key) if key is not None else kind)
    return order


def _normalize_vms(records):
    """vm|<name> rows with a FIXED field set (absent optionals -> None)."""
    normalized = {}
    for record in records:
        props = record["props"]
        cpu = props.get("config.cpuAllocation")
        cpu = cpu if isinstance(cpu, dict) else {}
        mem = props.get("config.memoryAllocation")
        mem = mem if isinstance(mem, dict) else {}
        flags = props.get("config.flags")
        flags = flags if isinstance(flags, dict) else {}
        boot = props.get("config.bootOptions")
        boot = boot if isinstance(boot, dict) else {}
        tools = props.get("config.tools")
        tools = tools if isinstance(tools, dict) else {}
        normalized["vm|%s" % (record["name"],)] = {
            # The hypervisor-side VM identity (BIOS uuid, the join key to a
            # guest's own uuid report).
            "uuid": _lower(props.get("config.uuid")),
            # Typically unset on never-vCenter-managed VMs; None is not identity loss.
            "instance_uuid": _lower(props.get("config.instanceUuid")),
            "hw_version": _strip(props.get("config.version")),
            "guest_id": _strip(props.get("config.guestId")),
            "power_state": _strip(props.get("runtime.powerState")),
            "connection_state": _strip(props.get("runtime.connectionState")),
            "num_cpu": to_int(props.get("config.hardware.numCPU")),
            "cores_per_socket": to_int(props.get("config.hardware.numCoresPerSocket")),
            "auto_cores_per_socket": to_bool(props.get("config.hardware.autoCoresPerSocket")),
            "memory_mb": to_int(props.get("config.hardware.memoryMB")),
            "cpu_reservation_mhz": to_int(cpu.get("reservation")),
            "cpu_limit_mhz": to_int(cpu.get("limit")),
            "cpu_shares": to_int(_get(cpu, "shares", "shares")),
            "cpu_shares_level": _strip(_get(cpu, "shares", "level")),
            "mem_reservation_mb": to_int(mem.get("reservation")),
            "mem_limit_mb": to_int(mem.get("limit")),
            "mem_shares_level": _strip(_get(mem, "shares", "level")),
            "mem_locked_to_max": to_bool(props.get("config.memoryReservationLockedToMax")),
            "latency_sensitivity": _strip(_get(props.get("config.latencySensitivity"), "level")),
            "cpu_affinity": _affinity(props),
            "tools_status": _strip(props.get("guest.toolsStatus")),
            "tools_running": _strip(props.get("guest.toolsRunningStatus")),
            "tools_version_status": _strip(props.get("guest.toolsVersionStatus2")),
            "guest_state": _strip(props.get("guest.guestState")),
            "guest_hostname": _strip(props.get("guest.hostName")),
            "datastore": _datastore_of(props.get("config.files.vmPathName")),
            "snapshot_count": _count_snapshots(_get(props.get("snapshot"), "rootSnapshotList")),
            # The "moved or copied?" detector: powerState reads on, the guest never boots.
            "has_pending_question": isinstance(props.get("runtime.question"), dict),
            "firmware": _strip(props.get("config.firmware")),
            "efi_secure_boot": to_bool(boot.get("efiSecureBootEnabled")),
            "boot_delay_ms": to_int(boot.get("bootDelay")),
            "boot_order": _boot_order(props.get("config.bootOptions")),
            # vIOMMU (a DPDK / VF-in-guest VNF needs it) and virtualization-based security.
            "vvtd_enabled": to_bool(flags.get("vvtdEnabled")),
            "vbs_enabled": to_bool(flags.get("vbsEnabled")),
            # Hot-add on disables vNUMA for the guest.
            "cpu_hot_add": to_bool(props.get("config.cpuHotAddEnabled")),
            "memory_hot_add": to_bool(props.get("config.memoryHotAddEnabled")),
            "tools_sync_time_with_host": to_bool(tools.get("syncTimeWithHost")),
        }
    return normalized


def _guest_net(props):
    """guest.net -> per adapter {mac, ip_addresses (sorted), connected, network, device_config_id}.

    Tools-reported and volatile: context, never diffed.
    """
    rows = []
    for nic in _dicts(props.get("guest.net")):
        rows.append(
            {
                "mac": _lower(nic.get("macAddress")),
                "ip_addresses": sorted(str(item) for item in aslist(nic.get("ipAddress")) if item),
                "connected": to_bool(nic.get("connected")),
                "network": _strip(nic.get("network")),
                "device_config_id": to_int(nic.get("deviceConfigId")),
            }
        )
    return rows


def _collect_vms(ctx):
    records, raw, context = _require_vms(ctx)
    normalized = _normalize_vms(records)
    context["powered_on"] = sorted(
        record["name"]
        for record in records
        if record["props"].get("runtime.powerState") == "poweredOn"
    )
    context["moids"] = {record["name"]: record["moid"] for record in records}
    context["boot_times"] = {
        record["name"]: record["props"].get("runtime.bootTime")
        for record in records
        if record["props"].get("runtime.bootTime") is not None
    }
    context["questions"] = {
        record["name"]: _strip(_get(record["props"].get("runtime.question"), "text"))
        for record in records
        if isinstance(record["props"].get("runtime.question"), dict)
    }
    # The whole-.vmx fingerprint hostd hands back: an unchanged
    # vmx_config_checksum proves the configuration is byte-identical without
    # curating; change_version/modified say when it last moved. Verbatim strings.
    context["config_versions"] = {
        record["name"]: {
            "change_version": _strip(record["props"].get("config.changeVersion")),
            "modified": _strip(record["props"].get("config.modified")),
            "vmx_config_checksum": _strip(record["props"].get("config.vmxConfigChecksum")),
        }
        for record in records
    }
    # The guest's own per-MAC address report (Tools-driven, volatile): context.
    context["guest_net"] = {
        record["name"]: _guest_net(record["props"])
        for record in records
        if record["props"].get("guest.net") is not None
    }
    return {"raw": raw, "normalized": normalized, "context": context}


# --- vmware_vm_nics -------------------------------------------------------------------------


def _devices(props):
    return _dicts(props.get("config.hardware.device"))


def _label_of(device):
    return _strip(_get(device, "deviceInfo", "label")) or "key-%s" % (device.get("key"),)


def _pci_hex_string(value):
    """A bare hex device id ('37d0', the Fixed DirectPath backing form) -> '0x37d0', the same
    rendering the host's pci| rows use so the two views join byte-for-byte; lowercase verbatim
    when it does not parse as hex."""
    text = _strip(value)
    if text is None:
        return None
    try:
        return "0x%04x" % (int(text, 16) & 0xFFFF,)
    except ValueError:
        return text.lower()


def _nic_backing(backing):
    """(name, type) — the port group for standard backing, dvport:/opaque: forms otherwise."""
    if not isinstance(backing, dict):
        return None, None
    btype = backing.get("_type")
    if backing.get("deviceName") is not None:
        return _strip(backing.get("deviceName")), btype
    port = backing.get("port")
    if isinstance(port, dict):
        return "dvport:%s/%s" % (port.get("switchUuid"), port.get("portgroupKey")), btype
    if backing.get("opaqueNetworkId") is not None:
        return "opaque:%s" % (backing.get("opaqueNetworkId"),), btype
    return None, btype


def _normalize_vm_nics(records):
    """vnic|<vm>|<label> for every device carrying macAddress (any VirtualEthernetCard
    subclass) and pcidev|<vm>|<label> for VirtualPCIPassthrough devices."""
    normalized = {}
    for record in records:
        props = record["props"]
        powered_on = props.get("runtime.powerState") == "poweredOn"
        for device in _devices(props):
            label = _label_of(device)
            connectable = device.get("connectable")
            connectable = connectable if isinstance(connectable, dict) else {}
            pci_slot = to_int(_get(device, "slotInfo", "pciSlotNumber"))
            if device.get("macAddress") is not None:
                backing_name, backing_type = _nic_backing(device.get("backing"))
                normalized["vnic|%s|%s" % (record["name"], label)] = {
                    "adapter_type": device.get("_type"),
                    "mac": _lower(device.get("macAddress")),
                    # generated on a standalone host; assigned = vCenter-managed.
                    "address_type": _strip(device.get("addressType")),
                    "backing": backing_name,
                    "backing_type": backing_type,
                    # SR-IOV physical function id; may read 'Automatic-...'.
                    "pf": _strip(_get(device, "sriovBacking", "physicalFunctionBacking", "id")),
                    # Only meaningful while powered on; None otherwise so a
                    # power-state change never masquerades as an adapter change.
                    "connected": to_bool(connectable.get("connected")) if powered_on else None,
                    "start_connected": to_bool(connectable.get("startConnected")),
                    "pci_slot": pci_slot,
                    "unit_number": to_int(device.get("unitNumber")),
                    "upt_compatible": to_bool(device.get("uptCompatibilityEnabled")),
                }
            elif device.get("_type") == "VirtualPCIPassthrough":
                backing = device.get("backing") if isinstance(device.get("backing"), dict) else {}
                allowed = sorted(
                    "%s:%s" % (_hex16(entry.get("vendorId")), _hex16(entry.get("deviceId")))
                    for entry in _dicts(backing.get("allowedDevice"))
                )
                normalized["pcidev|%s|%s" % (record["name"], label)] = {
                    "backing_type": backing.get("_type"),
                    # Fixed DirectPath has .id; Dynamic DirectPath has allowedDevice instead.
                    "pci_id": _strip(backing.get("id")),
                    "device_name": _strip(backing.get("deviceName")),
                    "vendor_id": _hex16(backing.get("vendorId")),
                    "device_id": _pci_hex_string(backing.get("deviceId")),
                    "allowed_devices": allowed,
                    "custom_label": _strip(backing.get("customLabel")),
                    "vgpu": _strip(backing.get("vgpu")),
                    "connected": to_bool(connectable.get("connected")) if powered_on else None,
                    "start_connected": to_bool(connectable.get("startConnected")),
                    "pci_slot": pci_slot,
                    "unit_number": to_int(device.get("unitNumber")),
                }
    return normalized


def _collect_vm_nics(ctx):
    records, raw, context = _require_vms(ctx)
    normalized = _normalize_vm_nics(records)
    context["vnics_total"] = sum(1 for key in normalized if key.startswith("vnic|"))
    context["passthrough_total"] = sum(1 for key in normalized if key.startswith("pcidev|"))
    return {"raw": raw, "normalized": normalized, "context": context}


# --- vmware_vm_tuning -----------------------------------------------------------------------

# Exact .vmx keys. NEVER a bare numa.* prefix: hostd rewrites numa.autosize.cookie
# at every power-on.
_TUNING_KEYS = frozenset(
    {
        "sched.cpu.latencySensitivity",
        "sched.cpu.min",
        "sched.cpu.affinity",
        "sched.mem.min",
        "sched.mem.pin",
        "sched.mem.lpage.enable1GPage",
        "sched.mem.pshare.enable",
        "numa.nodeAffinity",
        "numa.autosize",
        "numa.vcpu.preferHT",
        "numa.vcpu.maxPerVirtualNode",
        "hypervisor.cpuid.v0",
        "uuid.action",
        "monitor_control.disable_mmu_largepages",
    }
)
_TUNING_PATTERNS = (
    re.compile(r"ethernet\d+\.(coalescingScheme|pnicFeatures|ctxPerDev|filter.*)"),
    re.compile(r"pciPassthru\.(use64bitMMIO|64bitMMIOSizeGB)"),
)


def _tuning_key(key):
    if key in _TUNING_KEYS:
        return True
    return any(pattern.fullmatch(key) for pattern in _TUNING_PATTERNS)


def _coerce(value):
    """extraConfig / modeled values to str (None stays None; bools lowercase)."""
    if value is None:
        return None
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def _normalize_vm_tuning(records):
    """tune|<vm>|<vmx key> for the curated .vmx set plus the api: modeled fallbacks."""
    normalized = {}
    for record in records:
        props = record["props"]
        name = record["name"]
        options = _options_dict(props.get("config.extraConfig"))
        for key in sorted(options):
            if _tuning_key(key):
                normalized["tune|%s|%s" % (name, key)] = {"value": _coerce(options[key])}
        # Absent and "all" normalise equal (the Host Client writes "all" on any CPU edit).
        affinity_key = "tune|%s|sched.cpu.affinity" % (name,)
        if affinity_key not in normalized:
            normalized[affinity_key] = {"value": "all"}
        affinity = _affinity(props)
        modeled = {
            "api:latencySensitivity": _get(props.get("config.latencySensitivity"), "level"),
            "api:cpuReservationMHz": to_int(_get(props.get("config.cpuAllocation"), "reservation")),
            "api:memReservationMB": to_int(
                _get(props.get("config.memoryAllocation"), "reservation")
            ),
            "api:memPinned": to_bool(props.get("config.memoryReservationLockedToMax")),
            "api:cpuAffinity": ",".join(str(cpu) for cpu in affinity) if affinity else "all",
        }
        for key, value in modeled.items():
            normalized["tune|%s|%s" % (name, key)] = {"value": _coerce(value)}
    return normalized


def _collect_vm_tuning(ctx):
    records, raw, context = _require_vms(ctx)
    normalized = _normalize_vm_tuning(records)
    context["tuning_rows"] = len(normalized)
    return {"raw": raw, "normalized": normalized, "context": context}


# --- vmware_vm_disks ------------------------------------------------------------------------


def _normalize_vm_disks(records):
    """vdisk|<vm>|<label> rows from VirtualDisk devices; controller resolved to its label."""
    normalized = {}
    for record in records:
        devices = _devices(record["props"])
        labels = {to_int(device.get("key")): _label_of(device) for device in devices}
        for device in devices:
            if device.get("_type") != "VirtualDisk":
                continue
            backing = device.get("backing") if isinstance(device.get("backing"), dict) else {}
            normalized["vdisk|%s|%s" % (record["name"], _label_of(device))] = {
                "capacity_kb": to_int(device.get("capacityInKB")),
                "backing_file": _strip(backing.get("fileName")),
                "datastore": _datastore_of(backing.get("fileName")),
                "backing_type": backing.get("_type"),
                "thin": to_bool(backing.get("thinProvisioned")),
                "eager_zeroed": to_bool(backing.get("eagerlyScrub")),
                "disk_mode": _strip(backing.get("diskMode")),
                "controller": labels.get(to_int(device.get("controllerKey"))),
                "unit_number": to_int(device.get("unitNumber")),
            }
    return normalized


def _collect_vm_disks(ctx):
    records, raw, context = _require_vms(ctx)
    normalized = _normalize_vm_disks(records)
    context["disks_total"] = len(normalized)
    return {"raw": raw, "normalized": normalized, "context": context}


# --- vmware_autostart ------------------------------------------------------------------------

_AUTOSTART_DEFAULTS = (
    ("enabled", "enabled", to_bool),
    ("startDelay", "start_delay", to_int),
    ("stopDelay", "stop_delay", to_int),
    ("waitForHeartbeat", "wait_for_heartbeat", to_bool),
    ("stopAction", "stop_action", _strip),
)


def _normalize_autostart(config, names):
    """defaults|<field> scalars plus autostart|<vm> rows for EVERY registered VM
    (configured False when absent from powerInfo) and for stale powerInfo
    entries whose VM is no longer registered (vm_registered False)."""
    normalized = {}
    defaults = _get(config, "defaults")
    defaults = defaults if isinstance(defaults, dict) else {}
    for wire, field, convert in _AUTOSTART_DEFAULTS:
        normalized["defaults|%s" % (field,)] = {"value": convert(defaults.get(wire))}
    seen = set()
    for info in _dicts(_get(config, "powerInfo")):
        moid = _get(info, "key", "moid")
        if not moid:
            continue
        seen.add(moid)
        name = names.get(moid, moid)
        normalized["autostart|%s" % (name,)] = {
            "configured": True,
            "vm_registered": moid in names,
            "start_order": to_int(info.get("startOrder")),
            "start_delay": to_int(info.get("startDelay")),
            "start_action": _strip(info.get("startAction")),
            "stop_delay": to_int(info.get("stopDelay")),
            "stop_action": _strip(info.get("stopAction")),
            "wait_for_heartbeat": _strip(info.get("waitForHeartbeat")),
        }
    for moid, name in names.items():
        if moid in seen:
            continue
        normalized["autostart|%s" % (name,)] = {
            "configured": False,
            "vm_registered": True,
            "start_order": None,
            "start_delay": None,
            "start_action": None,
            "stop_delay": None,
            "stop_action": None,
            "wait_for_heartbeat": None,
        }
    return normalized


def _collect_autostart(ctx):
    props, result = _fetch_host(ctx, _AUTOSTART_PATHS)
    config = props.get("config.autoStart")
    if not isinstance(config, dict):
        raise SkipCheck("config.autoStart not present (no autostart manager on this host)")
    # Names resolve through the shared per-VM set; an empty host is fine here.
    records, vm_raw, vm_context = _fetch_vm_set(ctx)
    names = {record["moid"]: record["name"] for record in records}
    normalized = _normalize_autostart(config, names)
    context = {
        "vms_total": vm_context.get("vms_total"),
        "configured": sorted(
            key.split("|", 1)[1]
            for key, row in normalized.items()
            if key.startswith("autostart|") and row["configured"]
        ),
        "unconfigured": sorted(
            key.split("|", 1)[1]
            for key, row in normalized.items()
            if key.startswith("autostart|") and not row["configured"]
        ),
    }
    raw = {_request_key("HostSystem", (_HOST_MOID,), _AUTOSTART_PATHS): _raw_objects(result)}
    raw.update(vm_raw)
    return {"raw": raw, "normalized": normalized, "context": context}


# --- vmware_vlan_hints ------------------------------------------------------------------------


def _normalize_vlan_hints(hints):
    """vlans|vmnicN -> sorted observed vlanIds (one row per hinted pnic, [] when silent)."""
    normalized = {}
    subnets = {}
    for hint in _dicts(hints):
        device = _strip(hint.get("device"))
        if device is None:
            continue
        vlans = set()
        seen_subnets = set()
        for subnet in _dicts(hint.get("subnet")):
            vlan = to_int(subnet.get("vlanId"))
            if vlan is not None:
                vlans.add(vlan)
            if subnet.get("ipSubnet"):
                seen_subnets.add("%s@%s" % (subnet["ipSubnet"], vlan))
        normalized["vlans|%s" % (device,)] = {"vlan_ids": sorted(vlans)}
        subnets[device] = sorted(seen_subnets)
    return normalized, subnets


def _collect_vlan_hints(ctx):
    props, _network, result = _fetch_network_group(ctx)
    network_system, hints = _fetch_hints(ctx, props)
    if not _dicts(hints):
        raise SkipCheck("QueryNetworkHint returned no physical NIC hints")
    normalized, subnets = _normalize_vlan_hints(hints)
    raw = _network_raw(result)
    raw["QueryNetworkHint %s" % (network_system,)] = _capped(hints)
    context = {
        "pnics_with_hints": len(normalized),
        # Observed subnets churn with broadcast activity: context, not diffed.
        "subnets": subnets,
    }
    return {"raw": raw, "normalized": normalized, "context": context}


# --- vmware_host_license ---------------------------------------------------------------------


def _license_properties(license_info):
    """KeyAnyValue[] -> {key: value} with the repeated 'feature' entries as a sorted key list."""
    properties = {}
    features = []
    for entry in _dicts(_get(license_info, "properties")):
        key = entry.get("key")
        value = entry.get("value")
        if key == "feature":
            feature = _get(value, "key") if isinstance(value, dict) else value
            if feature is not None:
                features.append(str(feature))
        elif key is not None:
            properties[str(key)] = value
    properties["feature"] = sorted(features)
    return properties


def _redact_key(license_key):
    text = _strip(license_key)
    if text is None:
        return None
    return "...%s" % (text[-5:],)


def _normalize_host_license(licenses):
    """The host's (first, by editionKey) license as flat scalars; key redacted to its tail."""
    entries = sorted(_dicts(licenses), key=lambda item: str(item.get("editionKey")))
    if not entries:
        return {}, {"licenses_total": 0}
    entry = entries[0]
    properties = _license_properties(entry)
    normalized = {
        "edition_key": _strip(entry.get("editionKey")),
        "name": _strip(entry.get("name")),
        "total": to_int(entry.get("total")),
        "used": to_int(entry.get("used")),
        "cost_unit": _strip(entry.get("costUnit")),
        "license_key_tail": _redact_key(entry.get("licenseKey")),
        # Verbatim timestamp string; absent on a perpetual key.
        "expiration": properties.get("expirationDate"),
        "product_name": properties.get("ProductName"),
        "product_version": properties.get("ProductVersion"),
        "features": properties["feature"],
    }
    context = {
        "licenses_total": len(entries),
        "expiration_hours": to_int(properties.get("expirationHours")),
    }
    return normalized, context


def _curate_license(path, value):
    if path == "licenses":
        curated = []
        for entry in _dicts(value):
            copy = dict(entry)
            copy["licenseKey"] = _redact_key(entry.get("licenseKey"))
            curated.append(copy)
        return curated
    return value


def _collect_host_license(ctx):
    content = _service_content(ctx)
    moid = _manager_moid(content, "licenseManager")
    result = _retrieve(ctx, "LicenseManager", (moid,), _LICENSE_PATHS)
    manager = _object_by_moid(result, moid)
    if manager is None:
        raise CollectError("LicenseManager %s not in the answer" % (moid,))
    _refuse_missing(manager, "LicenseManager %s" % (moid,))
    normalized, context = _normalize_host_license(manager["props"].get("licenses"))
    raw = {
        _request_key("LicenseManager", (moid,), _LICENSE_PATHS): _raw_objects(
            result, _curate_license
        )
    }
    return {"raw": raw, "normalized": normalized, "context": context}


# --- vmware_recent_tasks ---------------------------------------------------------------------


def _normalize_recent_tasks(task_objects):
    """task|<info.key> rows from the Task objects a recentTask traversal returned."""
    normalized = {}
    for obj in task_objects:
        if _get(obj, "obj", "type") != "Task":
            continue
        info = _get(obj, "props", "info")
        if not isinstance(info, dict):
            continue
        key = _strip(info.get("key")) or _get(obj, "obj", "moid")
        reason = info.get("reason")
        normalized["task|%s" % (key,)] = {
            "description_id": _strip(info.get("descriptionId")),
            "state": _strip(info.get("state")),
            "entity": _strip(info.get("entityName")),
            "entity_type": _get(info, "entity", "type"),
            # userName for an operator-initiated task (TaskReasonUser); None
            # for system/schedule/alarm reasons (a childless typed element
            # loses its type on the wire).
            "user": _strip(reason.get("userName")) if isinstance(reason, dict) else None,
            "queue_time": info.get("queueTime"),
            "complete_time": info.get("completeTime"),
        }
    return normalized


def _normalize_latest_event(event):
    if not isinstance(event, dict):
        return None
    return {
        "type": event.get("_type"),
        "created_time": event.get("createdTime"),
        "user_name": _strip(event.get("userName")),
        "message": _strip(event.get("fullFormattedMessage")),
        # Almost always the suite's own Login: the honest claim is "quiescent
        # right now", never "who touched it last".
        "is_own_login": event.get("_type") == "UserLoginSessionEvent",
    }


def _collect_recent_tasks(ctx):
    content = _service_content(ctx)
    task_manager = _manager_moid(content, "taskManager")
    event_manager = _manager_moid(content, "eventManager")
    tasks = _retrieve(ctx, "TaskManager", (task_manager,), ("recentTask",), traverse=_TASK_TRAVERSE)
    events = _retrieve(ctx, "EventManager", (event_manager,), _EVENT_PATHS)
    for obj in (tasks.get("objects") or []) + (events.get("objects") or []):
        _refuse_missing(obj, "%s %s" % (_get(obj, "obj", "type"), _get(obj, "obj", "moid")))
    normalized = _normalize_recent_tasks(tasks.get("objects") or [])
    event_obj = _object_by_moid(events, event_manager)
    latest = _normalize_latest_event(_get(event_obj, "props", "latestEvent"))
    context = {
        "task_count": len(normalized),
        "tasks_running": sorted(
            key.split("|", 1)[1]
            for key, row in normalized.items()
            if row["state"] in ("running", "queued")
        ),
        "latest_event": latest,
    }
    raw = {
        "RetrievePropertiesEx TaskManager[%s] recentTask traverse Task.info"
        % (task_manager,): _raw_objects(tasks),
        _request_key("EventManager", (event_manager,), _EVENT_PATHS): _raw_objects(events),
    }
    return {"raw": raw, "normalized": normalized, "context": context}


# --- registrations ------------------------------------------------------------------------------

register(
    CheckDef(
        id="vmware_host_identity",
        platform="vmware",
        description="Host identity: vendor/model/serial/UUID, BIOS, ESXi build, CPU/memory totals",
        tier=1,
        compare={"mode": "equality_scalar"},
        miss_meaning=(
            "The hypervisor's identity or firmware differs — a different chassis answered, "
            "the BIOS was updated, ESXi was patched or reinstalled, or the hostname was "
            "re-addressed; CPU/memory totals moving means hardware was unseated or "
            "hyperthreading was toggled."
        ),
        collector=_collect_host_identity,
        tags=("platform",),
    )
)

register(
    CheckDef(
        id="vmware_hardware_inventory",
        platform="vmware",
        description="CPU packages, PCI devices (ids in hex) with passthrough/SR-IOV state, NUMA",
        tier=2,
        compare={"mode": "equality_set"},
        miss_meaning=(
            "A PCI device is missing, moved address, or changed its passthrough/SR-IOV "
            "state — an unseated card, a re-enumerated bus, or a VF count edit; VFs are "
            "their own rows so a VF change is N keys plus one flipped sriov flag."
        ),
        collector=_collect_hardware_inventory,
        tags=("platform", "hardware"),
    )
)

register(
    CheckDef(
        id="vmware_pnics",
        platform="vmware",
        description="Physical NICs: MAC, PCI, driver/firmware, link state, speed/duplex",
        tier=1,
        compare={"mode": "equality_set"},
        miss_meaning=(
            "An uplink is down, negotiated a different speed/duplex, or answers with a "
            "different MAC/PCI address — the host-side half of every cabling and "
            "transceiver question."
        ),
        collector=_collect_pnics,
        tags=("interfaces",),
    )
)

register(
    CheckDef(
        id="vmware_pnic_neighbors",
        platform="vmware",
        description="CDP/LLDP neighbor per physical NIC (not-present when discovery is off)",
        tier=1,
        compare={"mode": "equality_set"},
        miss_meaning=(
            "An uplink terminates on a different switch/port than before, or hears no "
            "neighbor at all — re-cabled, moved, or link down; with discovery listening, "
            "an empty table is a finding, not an absence."
        ),
        collector=_collect_pnic_neighbors,
        tags=("topology",),
    )
)

register(
    CheckDef(
        id="vmware_vswitches",
        platform="vmware",
        description="Standard vSwitches: MTU, uplinks, teaming order, security, discovery",
        tier=1,
        compare={"mode": "equality_set"},
        miss_meaning=(
            "A vSwitch lost an uplink, changed MTU, teaming order or security policy — "
            "the VNF data path is shaped here; a restored/reinstalled host resets these."
        ),
        collector=_collect_vswitches,
        tags=("interfaces",),
    )
)

register(
    CheckDef(
        id="vmware_portgroups",
        platform="vmware",
        description="Port groups: VLAN, effective security trio, teaming, override flags",
        tier=1,
        compare={"mode": "equality_set"},
        miss_meaning=(
            "A port group's VLAN or effective security/teaming policy changed — a VNF "
            "that needs promiscuous/MAC-change/forged-transmit Accept (L2 passthrough, "
            "floating HA MACs) blackholes when these flip to Reject."
        ),
        collector=_collect_portgroups,
        tags=("interfaces",),
    )
)

register(
    CheckDef(
        id="vmware_vmknics",
        platform="vmware",
        description="VMkernel NICs: port group, IP/mask, DHCP, MTU, netstack, services",
        tier=1,
        compare={"mode": "equality_set"},
        miss_meaning=(
            "A vmk was re-addressed, lost/gained a service role, or changed MTU/netstack "
            "— management reachability, storage and HA-sync paths depend on these."
        ),
        collector=_collect_vmknics,
        tags=("interfaces", "management"),
    )
)

register(
    CheckDef(
        id="vmware_host_routes",
        platform="vmware",
        description="Per-netstack routes and gateways plus DNS configuration",
        tier=1,
        compare={"mode": "equality_set"},
        miss_meaning=(
            "A gateway, static route or DNS server changed — the observable failure is a "
            "CHANGED default gateway, not a vanished one (that fails the capture at "
            "transport)."
        ),
        collector=_collect_host_routes,
        tags=("routing", "management"),
    )
)

register(
    CheckDef(
        id="vmware_time_syslog",
        platform="vmware",
        description="NTP/PTP configuration and live sync state; syslog targets and options",
        tier=1,
        compare={"mode": "equality_scalar"},
        miss_meaning=(
            "Time sync or log forwarding differs — an NTP/syslog target that became "
            "unreachable shows here without any interface going down; ntp_service_sync "
            "is the live in-sync flag."
        ),
        collector=_collect_time_syslog,
        tags=("services", "logging"),
    )
)

register(
    CheckDef(
        id="vmware_host_services",
        platform="vmware",
        description="Host services (running/policy), lockdown mode, MOB, vCenter membership",
        tier=1,
        compare={"mode": "equality_set"},
        miss_meaning=(
            "A service was left running or its startup policy changed (troubleshooting "
            "left SSH/shell on), lockdown mode moved, or the host joined/left vCenter."
        ),
        collector=_collect_host_services,
        tags=("services", "security"),
    )
)

register(
    CheckDef(
        id="vmware_advanced_options",
        platform="vmware",
        description="Curated advanced options (shell timeouts, MOB, network/memory/power knobs)",
        tier=1,
        compare={"mode": "equality_set"},
        miss_meaning=(
            "A curated advanced option differs — either an operator edit, or an unclean "
            "power-off reverted every option edited since the last hourly/clean-shutdown "
            "persist of state.tgz."
        ),
        collector=_collect_advanced_options,
        tags=("services", "config"),
    )
)

register(
    CheckDef(
        id="vmware_firewall_rulesets",
        platform="vmware",
        description="ESXi firewall rulesets: enabled, allowed sources, default policies",
        tier=2,
        compare={"mode": "equality_set"},
        miss_meaning=(
            "A firewall ruleset was enabled/disabled or its allowed-source list changed — "
            "a tamper detector for services opened during hands-on work."
        ),
        collector=_collect_firewall_rulesets,
        tags=("security",),
    )
)

register(
    CheckDef(
        id="vmware_datastores",
        platform="vmware",
        description="Datastores: type, VMFS uuid, locality, capacity/free within tolerance",
        tier=1,
        compare={
            "mode": "equality_set",
            "fields": {"free_bytes": {"tolerance": {"pct": 10, "abs": 10737418240}}},
        },
        miss_meaning=(
            "A datastore vanished, became inaccessible, or carries a different VMFS uuid "
            "under the same name (reformatted) — a resignature shows as removed+added."
        ),
        collector=_collect_datastores,
        tags=("storage",),
    )
)

register(
    CheckDef(
        id="vmware_storage_devices",
        platform="vmware",
        description="HBAs and local disks (HostScsiDisk): model, capacity, state, ssd/local",
        tier=1,
        compare={"mode": "equality_set"},
        miss_meaning=(
            "A disk or HBA is gone, renumbered, or reports a different operational state "
            "— separates 'drive gone' from 'volume not mounted' (see vmware_datastores)."
        ),
        collector=_collect_storage_devices,
        tags=("storage", "hardware"),
    )
)

register(
    CheckDef(
        id="vmware_health_sensors",
        platform="vmware",
        description="IPMI sensor health states and hardware element status (readings in context)",
        tier=1,
        compare={"mode": "equality_set"},
        miss_meaning=(
            "A sensor or hardware element left green — fan, PSU, temperature, DIMM or "
            "drive trouble the hypervisor sees; unknown right after boot is the IPMI "
            "refresh timer, not damage."
        ),
        collector=_collect_health_sensors,
        tags=("platform", "hardware"),
    )
)

register(
    CheckDef(
        id="vmware_autostart",
        platform="vmware",
        description="Autostart defaults and per-VM start order/delay/actions",
        tier=1,
        compare={"mode": "equality_set"},
        miss_meaning=(
            "Autostart was disabled, a VM dropped out of the start list, or the order "
            "changed — on a standalone host this is the only thing that brings VNFs back "
            "after a power-on."
        ),
        collector=_collect_autostart,
        tags=("vms", "availability"),
    )
)

register(
    CheckDef(
        id="vmware_vlan_hints",
        platform="vmware",
        description="VLANs observed on each physical NIC from broadcast hints",
        tier=2,
        compare={"mode": "equality_set"},
        miss_meaning=(
            "An uplink no longer hears the VLANs it used to (or hears new ones) — the "
            "far switch port's trunk allowed-list changed or the cable landed elsewhere; "
            "hints need minutes of link-up to populate."
        ),
        collector=_collect_vlan_hints,
        tags=("topology",),
    )
)

register(
    CheckDef(
        id="vmware_host_license",
        platform="vmware",
        description="Host license edition, usage, expiration and feature set (key redacted)",
        tier=3,
        compare={"mode": "equality_scalar"},
        miss_meaning=(
            "The license edition or expiration changed — someone re-licensed, or an "
            "evaluation clock is running out (expiry blocks powering VMs on)."
        ),
        collector=_collect_host_license,
        tags=("licensing",),
    )
)

register(
    CheckDef(
        id="vmware_vm_disks",
        platform="vmware",
        description="Virtual disks per VM: capacity, backing file/datastore, provisioning, mode",
        tier=2,
        compare={"mode": "equality_set"},
        miss_meaning=(
            "A VM's disk backing moved, was resized or re-provisioned — a restore from "
            "another host or a datastore resignature changes backing_file."
        ),
        collector=_collect_vm_disks,
        tags=("vms", "storage"),
    )
)

register(
    CheckDef(
        id="vmware_recent_tasks",
        platform="vmware",
        description="Recent hostd tasks and the latest event (quiescence evidence)",
        tier=3,
        compare={"mode": "info_only"},
        miss_meaning="",
        collector=_collect_recent_tasks,
        tags=("system",),
    )
)

register(
    CheckDef(
        id="vmware_vms",
        platform="vmware",
        description="Registered VMs: identity, hardware, reservations, power state, snapshots",
        tier=1,
        compare={"mode": "equality_set"},
        miss_meaning=(
            "A VM is missing, powered differently, re-sized, lost a reservation, gained "
            "snapshots, or is stuck on a pending question — a VNF did not come back as "
            "it was."
        ),
        collector=_collect_vms,
        tags=("vms",),
    )
)

register(
    CheckDef(
        id="vmware_vm_nics",
        platform="vmware",
        description="VM network adapters and PCI passthrough devices: MAC, backing, slot, state",
        tier=1,
        compare={"mode": "equality_set"},
        miss_meaning=(
            "A VM adapter changed port group, MAC, PCI slot or connection state, or a "
            "passthrough device is gone — the chain vNIC -> port group -> vSwitch -> "
            "uplink -> switch port is broken at the first link."
        ),
        collector=_collect_vm_nics,
        tags=("vms", "interfaces"),
    )
)

register(
    CheckDef(
        id="vmware_vm_tuning",
        platform="vmware",
        description="Per-VM NFV tuning: curated .vmx keys plus the modeled reservation fallbacks",
        tier=1,
        compare={"mode": "equality_set"},
        miss_meaning=(
            "A latency-sensitivity, reservation, pinning, NUMA or adapter-tuning key "
            "differs — hands-on edits during troubleshooting or a rebuild from OVA; "
            "re-registration never strips keys."
        ),
        collector=_collect_vm_tuning,
        tags=("vms", "config"),
    )
)
