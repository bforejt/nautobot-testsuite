"""Lenovo XClarity Controller (ThinkSystem SE350 BMC) check catalog — Redfish, GET only.

Collectors reach the BMC only through ``ctx.get``: the CollectorContext's
restconf slot holds a RedfishClient duck-typed to the RESTCONF client, so
every ``xcc_*`` check shares one per-run cache and ``Systems/1`` /
``Managers/1`` / the service root are fetched once for the whole family.
This module imports nothing but stdlib and the jobs package's pure modules,
so the CI battery loads it and drives every ``_normalize_*`` function with
fixture payloads hand-built from Lenovo's XCC REST API guide examples.

Redfish specifics that shape every collector here:

- *Fence before follow.* A server-supplied ``@odata.id`` passes through
  ``redfish_paths.fence_path`` before it is fetched; a link outside the
  read-only surface fails the check instead of being sent (the client fences
  again — this is the belt to its braces).
- *Budget per check.* ``ctx.budget(check_id, n)`` caps the real GETs one
  check may issue; the GET that would exceed it raises before being sent, so
  a capture is complete-or-refused, never silently partial. Collectors that
  walk collections pre-check the member count against what is left of the
  budget and raise CollectError with both numbers rather than walking into
  the wall.
- *One GET per collection.* ``?$expand=.($levels=1)`` inlines a collection's
  members; when the firmware refuses it (HTTP error) or ignores it (members
  come back as bare links) the collector walks the members one by one and
  records which strategy answered in context.
- *Keys by Id.* Redfish ``Name`` may be null or duplicated (Lenovo's own
  samples); ``MemberId``/``Id`` is the stable identity wherever a key needs
  one, and Name is only used where the documentation shows it unique.
- *Enums are never pinned.* Status/state strings are carried verbatim; the
  SEMANTICS text explains the values the documentation names and the
  analyst reads the rest.
- *Raw is curated before it is stored.* ``Actions`` blocks, etags and any
  leaf whose name looks like key material are dropped from every payload;
  per-check raw is keyed by the exact request path; bulk remainders are
  capped with an honest truncation marker. Normalized is always computed
  from the full response, never from capped raw.

Power-state caveat, once for the family: the XCC answers with the host off,
but Memory/PCIe inventory, storage and host-NIC link state are populated at
POST or via sideband, so those views are trustworthy only after the host has
completed POST; thermal, power, the event log and the security state are
host-independent. ``Systems/1.PowerState`` rides in context wherever it
matters.
"""

import re

from .redfish_paths import RedfishPathRefused, fence_path
from .registry import CheckDef, CollectError, SkipCheck, register

# --- Redfish paths -----------------------------------------------------------

_ROOT = "/redfish/v1/"
_SYSTEM = "/redfish/v1/Systems/1"
_MANAGER = "/redfish/v1/Managers/1"
_CHASSIS = "/redfish/v1/Chassis/1"
_SECURE_BOOT = _SYSTEM + "/SecureBoot"
_MANAGER_NIC = _MANAGER + "/EthernetInterfaces/NIC"
_MANAGER_NICS = _MANAGER + "/EthernetInterfaces"
_SECURITY = _MANAGER + "/Oem/Lenovo/Security"
_THERMAL = _CHASSIS + "/Thermal"
_POWER = _CHASSIS + "/Power"
_MEMORY = _SYSTEM + "/Memory"
_PROCESSORS = _SYSTEM + "/Processors"
_PCIE = _CHASSIS + "/PCIeDevices"
_HOST_NICS = _SYSTEM + "/EthernetInterfaces"
_FIRMWARE = "/redfish/v1/UpdateService/FirmwareInventory"
_LOG_SERVICES = _SYSTEM + "/LogServices"
_BIOS = _SYSTEM + "/Bios"
_STORAGE = _SYSTEM + "/Storage"
_NETWORK_PROTOCOL = _MANAGER + "/NetworkProtocol"

# One paced GET inlines a whole collection when the firmware honours it
# (gen-1 XCC advertises ProtocolFeaturesSupported.ExpandQuery.ExpandAll).
_EXPAND = "?$expand=.($levels=1)"

# --- per-check GET budgets ---------------------------------------------------
# Every Basic-auth GET is an XCC login and an AuditLog entry, and the SE350
# Redfish service has been reported to fold under request stress, so each
# check declares the most it may spend. Cache hits never count. Sized from
# Lenovo's own samples (15 FirmwareInventory members, 4 onboard NICs plus a
# LOM, one M.2 mirror kit) with room for the per-member fallback walk.
_BUDGET_SYSTEM = 8
_BUDGET_SECURITY = 4
_BUDGET_THERMAL = 2
_BUDGET_POWER = 2
_BUDGET_INVENTORY = 16
_BUDGET_HOST_NICS = 12
_BUDGET_FIRMWARE = 24
_BUDGET_EVENT_LOG = 12
_BUDGET_BIOS = 2
_BUDGET_STORAGE = 16
_BUDGET_MANAGER_NETWORK = 6
_BUDGET_CHASSIS = 2

# --- raw curation ------------------------------------------------------------
# Dropped from every stored payload: Actions blocks are POST targets, not
# evidence of state; etags/contexts churn on every capture. Scrubbed: any
# leaf whose NAME looks like key material (the ThinkEdge SED_AK setting is
# action-valued and must never be echoed).
_DROP_KEYS = frozenset({"Actions", "@odata.etag", "@odata.context"})
_SECRET_TOKENS = ("sed_ak", "password", "passphrase", "secret", "privatekey", "authkey")
_SCRUBBED = "***scrubbed***"
_RAW_TEXT_CAP = 20000  # chars kept for a sorted key=value remainder in raw
_RAW_LOG_ENTRIES = 500  # newest event-log entries kept in raw (curated, per entry)


def _looks_secret(key):
    lowered = str(key).lower()
    return any(token in lowered for token in _SECRET_TOKENS)


def _curate(node):
    """Deep copy of a payload fit for the raw bundle (see _DROP_KEYS / _SECRET_TOKENS)."""
    if isinstance(node, dict):
        out = {}
        for key, value in node.items():
            if key in _DROP_KEYS:
                continue
            if _looks_secret(key):
                out[key] = _SCRUBBED
                continue
            out[key] = _curate(value)
        return out
    if isinstance(node, list):
        return [_curate(item) for item in node]
    return node


def _capped_lines(pairs):
    """Sorted ``key=value`` lines joined and capped with an honest marker."""
    text = "\n".join("%s=%s" % (key, value) for key, value in sorted(pairs))
    if len(text) > _RAW_TEXT_CAP:
        return text[:_RAW_TEXT_CAP] + "\n...[truncated %d chars]" % (len(text) - _RAW_TEXT_CAP,)
    return text


# --- shared helpers ----------------------------------------------------------


def _aslist(node):
    if node is None:
        return []
    if isinstance(node, list):
        return node
    return [node]


def _dicts(node):
    return [item for item in _aslist(node) if isinstance(item, dict)]


def _dig(node, *keys):
    """Nested lookup tolerant of missing/non-dict levels: None when any step fails."""
    for key in keys:
        if not isinstance(node, dict):
            return None
        node = node.get(key)
    return node


def _to_int(value):
    if isinstance(value, bool):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _to_float(value):
    if isinstance(value, bool):
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _to_bool(value):
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in ("true", "enabled", "yes", "on"):
            return True
        if lowered in ("false", "disabled", "no", "off"):
            return False
    return None


def _text(value):
    """Non-empty string or None — Redfish nulls and empty strings both mean unset."""
    if value is None:
        return None
    value = str(value).strip()
    return value or None


def _mac(value):
    """MACs lower-cased so they join to the ESXi-side pnic view byte-for-byte."""
    value = _text(value)
    return value.lower() if value else None


def _status(node):
    """(health, state) from a Redfish Status block; both None when absent."""
    return _text(_dig(node, "Status", "Health")), _text(_dig(node, "Status", "State"))


def _leaf_id(link):
    """Last path segment of an @odata.id (query/fragment stripped)."""
    resource = str(link).partition("?")[0].partition("#")[0].rstrip("/")
    return resource.rsplit("/", 1)[-1]


def _member_id(member):
    """Stable identity of a collection member: Id, then MemberId, then the link leaf."""
    if not isinstance(member, dict):
        return None
    for key in ("Id", "MemberId"):
        if _text(member.get(key)) is not None:
            return _text(member.get(key))
    link = member.get("@odata.id")
    return _leaf_id(link) if link else None


def _fenced_link(node, label):
    """The fenced @odata.id of ``node`` (a link dict), or None when it has none.

    A link the fence refuses fails the check: a firmware handing back a
    reference into Actions/ must never be followed, and silently skipping it
    would hide that the resource tree looks wrong.
    """
    link = _dig(node, "@odata.id") if isinstance(node, dict) else None
    if link is None:
        return None
    try:
        return fence_path(link)
    except RedfishPathRefused as exc:
        raise CollectError("%s: server-supplied link refused: %s" % (label, exc)) from exc


def _member_links(collection, label):
    """Fenced links of every Members[] entry of a collection resource."""
    links = []
    for member in _dicts(_dig(collection, "Members")):
        link = _fenced_link(member, label)
        if link is not None:
            links.append(link)
    return links


def _http_status(exc):
    """HTTP status carried by a transport error (None for fence/budget/network errors)."""
    return getattr(exc, "status_code", None)


def _get(ctx, path):
    """Required resource: a 404 is a failed read (the transport raises)."""
    return ctx.get(path)


def _get_optional(ctx, path):
    """Optional resource: None on 404. Always the same kwargs so the cache is shared."""
    return ctx.get(path, ok_404=True)


def _budget_left(budget):
    """GETs still allowed under a transport budget manager; None when the transport has none."""
    max_gets = getattr(budget, "max_gets", None)
    used = getattr(budget, "used", None)
    if isinstance(max_gets, int) and isinstance(used, int):
        return max_gets - used
    return None


def _require_budget(budget, needed, label, what):
    """Refuse a walk that cannot complete: partial inventories are never recorded."""
    left = _budget_left(budget)
    if left is not None and needed > left:
        raise CollectError(
            "%s: %d %s to fetch but only %d GET(s) left in the budget of %d — the "
            "collector would be silently partial; $expand was not usable here"
            % (label, needed, what, left, budget.max_gets)
        )


def _expand_advertised(root):
    """True/False when the service root states $expand support, None when it is silent."""
    expand = _dig(root, "ProtocolFeaturesSupported", "ExpandQuery")
    if not isinstance(expand, dict):
        return None
    expand_all, no_links = expand.get("ExpandAll"), expand.get("NoLinks")
    if not isinstance(expand_all, bool) and not isinstance(no_links, bool):
        return None
    return bool(expand_all) or bool(no_links)


def _expanded(members):
    """True when every member came back as a resource, not a bare @odata.id link."""
    return all(any(key != "@odata.id" for key in member) for member in members)


def _fetch_collection(ctx, path, label, *, ok_404=False, exclude=frozenset(), budget=None):
    """Members of a Redfish collection as full resources: (members, meta, raw).

    Strategy, recorded in ``meta["strategy"]``: ``expand`` (one GET, members
    inline), ``members`` (collection GET plus one GET per member), or
    ``absent`` (404 with ok_404 — members is None). ``exclude`` names member
    ids (lower-cased) that are dropped *before* any GET is spent on them.
    ``raw`` maps each request path actually sent to its curated payload.
    """
    raw = {}
    meta = {"strategy": None, "members_total": 0, "excluded": [], "expand_advertised": None}
    meta["expand_advertised"] = _expand_advertised(_get(ctx, _ROOT))
    if meta["expand_advertised"] is not False:
        expanded_path = path + _EXPAND
        try:
            payload = _get_optional(ctx, expanded_path)
        except Exception as exc:  # transport error class is not importable here
            if _http_status(exc) is None:
                raise  # budget, fence or network failure — never a fallback trigger
            meta["expand_refused"] = "HTTP %s" % (_http_status(exc),)
            payload = None
        if payload is not None:
            members = _dicts(payload.get("Members"))
            if _expanded(members):
                raw[expanded_path] = _curate(payload)
                kept, excluded = [], []
                for member in members:
                    member_id = _member_id(member)
                    if member_id is not None and member_id.lower() in exclude:
                        excluded.append(member_id)
                    else:
                        kept.append(member)
                meta.update(strategy="expand", members_total=len(members), excluded=excluded)
                return kept, meta, raw
            meta["expand_refused"] = "members returned as links"
    collection = _get_optional(ctx, path) if ok_404 else _get(ctx, path)
    if collection is None:
        meta["strategy"] = "absent"
        return None, meta, raw
    raw[path] = _curate(collection)
    links = _member_links(collection, label)
    kept, excluded = [], []
    for link in links:
        if _leaf_id(link).lower() in exclude:
            excluded.append(_leaf_id(link))
        else:
            kept.append(link)
    _require_budget(budget, len(kept), label, "members")
    members = []
    for link in kept:
        member = _get(ctx, link)
        raw[link] = _curate(member)
        members.append(member)
    meta.update(strategy="members", members_total=len(links), excluded=excluded)
    return members, meta, raw


def _first_ipv4(nic):
    return next(iter(_dicts(_dig(nic, "IPv4Addresses"))), {})


# --- xcc_system --------------------------------------------------------------

# The XCC's own management port is the documented ``NIC`` member; gen-1 also
# serves ``ToHost`` (the USB-LAN link to the host OS, 169.254.x) and the
# collection order is not guaranteed — so the collection is a 404 fallback
# only and "first member" is never taken.
_USB_LAN_IDS = frozenset({"tohost", "tomanager"})


def _fetch_manager_nic(ctx):
    """(payload, meta, raw) for the XCC's management interface; payload None when absent.

    ``raw`` maps every request path sent to its curated payload; ``meta``
    records which member answered and how it was found.
    """
    raw = {}
    nic = _get_optional(ctx, _MANAGER_NIC)
    if nic is not None:
        raw[_MANAGER_NIC] = _curate(nic)
        return nic, {"member": _member_id(nic) or "NIC", "source": "direct"}, raw
    collection = _get_optional(ctx, _MANAGER_NICS)
    if collection is None:
        return None, {"member": None, "source": "absent"}, raw
    raw[_MANAGER_NICS] = _curate(collection)
    candidates = [
        link
        for link in _member_links(collection, "xcc manager EthernetInterfaces")
        if _leaf_id(link).lower() not in _USB_LAN_IDS
    ]
    chosen = None
    for link in candidates:
        payload = _get_optional(ctx, link)
        if payload is None:
            continue
        raw[link] = _curate(payload)
        if chosen is None:
            chosen = payload
        address = _text(_first_ipv4(payload).get("Address"))
        if address and not address.startswith("169.254."):
            chosen = payload
            break
    if chosen is None:
        return None, {"member": None, "source": "collection-empty"}, raw
    return chosen, {"member": _member_id(chosen), "source": "collection"}, raw


def _normalize_system(system, secure_boot, manager, nic, eth_member_used):
    """Flat identity/health/boot scalars from Systems/1, SecureBoot, Managers/1 and its NIC.

    Every field is always present (None when the resource or leaf is absent)
    so pre and post compare field-for-field. SecureBoot's three fields are
    None as a trio when the resource 404s.
    """
    system = system if isinstance(system, dict) else {}
    secure_boot = secure_boot if isinstance(secure_boot, dict) else {}
    manager = manager if isinstance(manager, dict) else {}
    nic = nic if isinstance(nic, dict) else {}
    health, state = _status(system)
    xcc_health, xcc_state = _status(manager)
    ipv4 = _first_ipv4(nic)
    vlan_enabled = _to_bool(_dig(nic, "VLAN", "VLANEnable"))
    return {
        "power_state": _text(system.get("PowerState")),
        "health": health,
        "health_rollup": _text(_dig(system, "Status", "HealthRollup")),
        "state": state,
        "manufacturer": _text(system.get("Manufacturer")),
        "model": _text(system.get("Model")),
        "serial": _text(system.get("SerialNumber")),
        "sku": _text(system.get("SKU")),
        "part_number": _text(system.get("PartNumber")),
        "uuid": _text(system.get("UUID")),
        "asset_tag": _text(system.get("AssetTag")),
        "hostname": _text(system.get("HostName")),
        "bios_version": _text(system.get("BiosVersion")),
        "cpu_count": _to_int(_dig(system, "ProcessorSummary", "Count")),
        "cpu_model": _text(_dig(system, "ProcessorSummary", "Model")),
        "cpu_health": _text(_dig(system, "ProcessorSummary", "Status", "Health")),
        "memory_gib": _to_float(_dig(system, "MemorySummary", "TotalSystemMemoryGiB")),
        "memory_health": _text(_dig(system, "MemorySummary", "Status", "Health")),
        # Strings, never booleans: Disabled | Once | Continuous.
        "boot_override": _text(_dig(system, "Boot", "BootSourceOverrideEnabled")),
        "boot_override_target": _text(_dig(system, "Boot", "BootSourceOverrideTarget")),
        "boot_override_mode": _text(_dig(system, "Boot", "BootSourceOverrideMode")),
        "secure_boot_enabled": _to_bool(secure_boot.get("SecureBootEnable")),
        "secure_boot_current": _text(secure_boot.get("SecureBootCurrentBoot")),
        "secure_boot_mode": _text(secure_boot.get("SecureBootMode")),
        "system_status": _text(_dig(system, "Oem", "Lenovo", "SystemStatus")),
        "xcc_firmware": _text(manager.get("FirmwareVersion")),
        "xcc_model": _text(manager.get("Model")),
        "xcc_uuid": _text(manager.get("UUID")),
        "xcc_health": xcc_health or xcc_state,
        "xcc_hostname": _text(nic.get("HostName")),
        "xcc_ip": _text(ipv4.get("Address")),
        "xcc_ip_origin": _text(ipv4.get("AddressOrigin")),
        "xcc_subnet_mask": _text(ipv4.get("SubnetMask")),
        "xcc_gateway": _text(ipv4.get("Gateway")),
        "xcc_vlan_enabled": vlan_enabled,
        "xcc_vlan": _to_int(_dig(nic, "VLAN", "VLANId")) if vlan_enabled else None,
        "xcc_mac": _mac(nic.get("MACAddress")),
        "eth_member_used": eth_member_used,
    }


def _system_context(system, manager, nic_meta, secure_boot):
    """Volatile or bulky facts an analyst wants next to the identity scalars."""
    modules = []
    for module in _dicts(_dig(system, "TrustedModules")):
        modules.append(
            {
                "interface_type": _text(module.get("InterfaceType")),
                "firmware": _text(module.get("FirmwareVersion")),
                "state": _text(_dig(module, "Status", "State")),
            }
        )
    return {
        "reboot_count": _to_int(_dig(system, "Oem", "Lenovo", "NumberOfReboots")),
        "power_on_hours": _to_int(_dig(system, "Oem", "Lenovo", "TotalPowerOnHours")),
        "indicator_led": _text(_dig(system, "IndicatorLED")),
        "xcc_datetime": _text(_dig(manager, "DateTime")),
        "xcc_datetime_offset": _text(_dig(manager, "DateTimeLocalOffset")),
        "xcc_power_state": _text(_dig(manager, "PowerState")),
        "secure_boot_resource": secure_boot is not None,
        "trusted_modules": modules,
        "manager_nic": nic_meta,
    }


def _collect_system(ctx):
    with ctx.budget("xcc_system", _BUDGET_SYSTEM):
        system = _get(ctx, _SYSTEM)
        if not isinstance(system, dict) or not system:
            raise CollectError("Systems/1 answered without a resource body")
        secure_boot = _get_optional(ctx, _SECURE_BOOT)
        manager = _get(ctx, _MANAGER)
        nic, nic_meta, nic_raw = _fetch_manager_nic(ctx)
    raw = {_SYSTEM: _curate(system), _MANAGER: _curate(manager)}
    raw[_SECURE_BOOT] = _curate(secure_boot) if secure_boot is not None else None
    raw.update(nic_raw)
    normalized = _normalize_system(system, secure_boot, manager, nic, nic_meta["member"])
    return {
        "raw": raw,
        "normalized": normalized,
        "context": _system_context(system, manager, nic_meta, secure_boot),
    }


# --- xcc_security_state ------------------------------------------------------

# ThinkEdge (Security Pack) properties on the Managers/1 Oem/Lenovo/Security
# resource. The resource exists on mainstream ThinkSystem too, so presence of
# the check is decided by these properties, never by the link. Property names
# are candidates: each field takes the first leaf (by dotted path) whose
# last segment is one of its names; every field is optional — gen-1 and V2
# spell the motion model differently and the lockdown names are unverified.
_SECURITY_FIELDS = (
    ("lockdown_mode", ("LockdownMode", "SystemLockdownMode", "LockdownStatus", "Lockdown")),
    ("lockdown_control", ("LockdownControl", "LockdownControlMode", "LockdownManagedBy")),
    (
        "motion_detection_enabled",
        ("MotionDetection", "MotionDetectionEnabled", "MotionDetectionEnable"),
    ),
    ("motion_threshold", ("ThresholdLevel", "StepCounter", "MotionSensitivity", "Sensitivity")),
    ("motion_orientation", ("Orientation", "MotionOrientation")),
    (
        "chassis_intrusion_enabled",
        ("ChassisIntrusionDetection", "ChassisIntrusion", "IntrusionDetection"),
    ),
    ("host_shutdown_on_tamper", ("HostShutdown", "HostShutdownOnTamper")),
    ("sed_encryption_enabled", ("EncryptionEnabled", "SEDEncryptionEnabled", "SEDEncryption")),
)
_FLATTEN_SKIP = ("@odata.", "Actions", "Links", "Id", "Name", "Description")


def _flatten(node, prefix=""):
    """Dotted-path -> scalar leaves of a resource (metadata, Actions and secrets skipped)."""
    leaves = {}
    if isinstance(node, dict):
        for key, value in node.items():
            if str(key).startswith("@") or (not prefix and key in _FLATTEN_SKIP):
                continue
            if _looks_secret(key):
                continue
            leaves.update(_flatten(value, "%s.%s" % (prefix, key) if prefix else str(key)))
    elif isinstance(node, list):
        for index, value in enumerate(node):
            leaves.update(_flatten(value, "%s[%d]" % (prefix, index)))
    elif prefix:
        leaves[prefix] = node
    return leaves


def _pick_leaf(leaves, names):
    """(path, value) of the first leaf whose last segment is in ``names``; (None, None) if none."""
    for name in names:
        for path in sorted(leaves):
            if path.rsplit(".", 1)[-1] == name:
                return path, leaves[path]
    return None, None


def _normalize_security_state(security):
    """(normalized, sources) — every _SECURITY_FIELDS entry, None when the leaf is absent.

    ``sources`` maps each populated field to the dotted path it came from so
    the shakedown can pin the real property names. Booleans arrive as bools
    or Enabled/Disabled strings; both become bools. Anything else is verbatim.
    """
    leaves = _flatten(security)
    normalized = {}
    sources = {}
    for field, names in _SECURITY_FIELDS:
        path, value = _pick_leaf(leaves, names)
        if path is None:
            normalized[field] = None
            continue
        sources[field] = path
        as_bool = _to_bool(value)
        normalized[field] = as_bool if as_bool is not None else value
    return normalized, sources


def _collect_security_state(ctx):
    with ctx.budget("xcc_security_state", _BUDGET_SECURITY):
        manager = _get(ctx, _MANAGER)
        link = _fenced_link(_dig(manager, "Oem", "Lenovo", "Security"), "xcc_security_state")
        security_path = link or _SECURITY
        security = _get_optional(ctx, security_path)
        if security is None:
            raise SkipCheck(
                "no Oem/Lenovo/Security resource on this XCC (%s answered 404)" % (security_path,)
            )
        normalized, sources = _normalize_security_state(security)
        if not sources:
            raise SkipCheck(
                "Security resource present but carries no ThinkEdge properties "
                "(lockdown/motion/intrusion/SED) — not a Security Pack unit or this "
                "firmware does not expose them"
            )
        # External key-manager (SKLM/KMIP) configuration is context only: it is
        # where SED keys are escrowed, not the SED state itself.
        sklm_link = _fenced_link(
            _dig(manager, "Oem", "Lenovo", "SecureKeyLifecycleService"), "xcc_security_state"
        )
        sklm = _get_optional(ctx, sklm_link) if sklm_link else None
    raw = {security_path: _curate(security)}
    key_management = None
    if sklm is not None:
        raw[sklm_link] = _curate(sklm)
        key_management = {path: value for path, value in sorted(_flatten(sklm).items())}
    return {
        "raw": raw,
        "normalized": normalized,
        "context": {
            "security_resource": security_path,
            "property_sources": sources,
            "properties_seen": sorted(_flatten(security)),
            "key_management": key_management,
        },
    }


# --- xcc_thermal -------------------------------------------------------------

# Only environment-class sensors carry a comparable reading: CPU/DIMM/PCH
# temperatures are load-driven (and a post capture may follow a VNF reboot),
# so those readings ride in context. Matched on Name, not PhysicalContext —
# gen-1 says Intake where later firmware says Board.
_AMBIENT_TOKENS = ("ambient", "inlet", "intake", "exhaust", "outlet")


def _sensor_key(kind, name, member_id, name_counts):
    """'<kind>|<Name>'; '|<MemberId>' appended when Name repeats; '<kind>|<MemberId>' when null."""
    if name is None:
        return "%s|%s" % (kind, member_id)
    if name_counts.get(name, 0) > 1:
        return "%s|%s|%s" % (kind, name, member_id)
    return "%s|%s" % (kind, name)


def _name_counts(items):
    counts = {}
    for item in items:
        name = _text(item.get("Name"))
        if name is not None:
            counts[name] = counts.get(name, 0) + 1
    return counts


def _thresholds(sensor):
    """Non-null threshold leaves of a sensor, snake_cased; {} when none."""
    found = {}
    for key in (
        "UpperThresholdNonCritical",
        "UpperThresholdCritical",
        "UpperThresholdFatal",
        "LowerThresholdNonCritical",
        "LowerThresholdCritical",
        "LowerThresholdFatal",
    ):
        value = _to_float(sensor.get(key))
        if value is not None:
            found[_snake(key)] = value
    return found


def _snake(name):
    return re.sub(r"(?<!^)(?=[A-Z])", "_", str(name)).lower()


def _is_ambient(name):
    lowered = (name or "").lower()
    return any(token in lowered for token in _AMBIENT_TOKENS)


def _normalize_thermal(thermal):
    """(normalized, context) from Chassis/1/Thermal.

    ``temp|<Name>`` -> health, state, physical_context, reading_c (ambient/
    intake/exhaust class only; None on the rest). ``fan|<Name>`` -> health,
    state, reading, reading_units. State == Absent means no key. Every
    reading and every non-null threshold is recorded in context.
    """
    normalized = {}
    context = {
        "temperatures_total": 0,
        "fans_total": 0,
        "absent": [],
        "readings_c": {},
        "fan_readings": {},
        "thresholds": {},
        "fan_redundancy": [],
    }
    temperatures = _dicts(_dig(thermal, "Temperatures"))
    counts = _name_counts(temperatures)
    for sensor in temperatures:
        context["temperatures_total"] += 1
        name = _text(sensor.get("Name"))
        member_id = _text(sensor.get("MemberId")) or _text(sensor.get("Id")) or "?"
        key = _sensor_key("temp", name, member_id, counts)
        health, state = _status(sensor)
        if state == "Absent":
            context["absent"].append(key)
            continue
        reading = _to_float(sensor.get("ReadingCelsius"))
        normalized[key] = {
            "health": health,
            "state": state,
            "physical_context": _text(sensor.get("PhysicalContext")),
            "reading_c": reading if _is_ambient(name) else None,
        }
        context["readings_c"][key] = reading
        thresholds = _thresholds(sensor)
        if thresholds:
            context["thresholds"][key] = thresholds
    fans = _dicts(_dig(thermal, "Fans"))
    counts = _name_counts(fans)
    for fan in fans:
        context["fans_total"] += 1
        name = _text(fan.get("Name")) or _text(fan.get("FanName"))
        member_id = _text(fan.get("MemberId")) or _text(fan.get("Id")) or "?"
        key = _sensor_key("fan", name, member_id, counts)
        health, state = _status(fan)
        if state == "Absent":
            context["absent"].append(key)
            continue
        reading = _to_float(fan.get("Reading"))
        normalized[key] = {
            "health": health,
            "state": state,
            "reading": reading,
            "reading_units": _text(fan.get("ReadingUnits")),
        }
        context["fan_readings"][key] = reading
        thresholds = _thresholds(fan)
        if thresholds:
            context["thresholds"][key] = thresholds
    for group in _dicts(_dig(thermal, "Redundancy")):
        context["fan_redundancy"].append(
            {
                "member_id": _text(group.get("MemberId")),
                "mode": _text(group.get("Mode")),
                "state": _text(_dig(group, "Status", "State")),
                "health": _text(_dig(group, "Status", "Health")),
                "member_count": len(_dicts(group.get("RedundancySet"))),
            }
        )
    return normalized, context


def _collect_thermal(ctx):
    with ctx.budget("xcc_thermal", _BUDGET_THERMAL):
        thermal = _get(ctx, _THERMAL)
    if not _dicts(_dig(thermal, "Temperatures")):
        # A 2xx JSON body with no sensors is a broken read, never a chassis
        # with no thermal sensors.
        raise CollectError("Chassis/1/Thermal answered with an empty Temperatures[]")
    normalized, context = _normalize_thermal(thermal)
    return {"raw": {_THERMAL: _curate(thermal)}, "normalized": normalized, "context": context}


# --- xcc_power ---------------------------------------------------------------


def _input_in_range(reading, ranges):
    """True/False when a line-input reading and at least one Min/Max range exist; else None."""
    if reading is None:
        return None
    verdicts = []
    for band in _dicts(ranges):
        low = _to_float(band.get("MinimumVoltage"))
        high = _to_float(band.get("MaximumVoltage"))
        if low is None or high is None:
            continue
        verdicts.append(low <= reading <= high)
    if not verdicts:
        return None
    return any(verdicts)


def _in_threshold(reading, sensor):
    """True/False against the critical (else fatal) thresholds; None without both sides' data."""
    if reading is None:
        return None
    for suffix in ("Critical", "Fatal"):
        low = _to_float(sensor.get("LowerThreshold" + suffix))
        high = _to_float(sensor.get("UpperThreshold" + suffix))
        if low is not None or high is not None:
            return (low is None or reading >= low) and (high is None or reading <= high)
    return None


def _normalize_power(power):
    """(normalized, context) from Chassis/1/Power.

    ``psu|<MemberId>`` (Name may be null on Lenovo) -> state/health verbatim,
    line_input_voltage, input_in_range, capacity_w, identity strings (None,
    never ''). ``redundancy|<MemberId>`` only when Redundancy[] exists.
    ``voltage|<MemberId>`` -> state, in_threshold, health (Lenovo's sample has
    no Health on Voltages, so it is usually None). Consumption and readings
    go to context.
    """
    normalized = {}
    context = {
        "power_consumed_w": None,
        "power_capacity_w": None,
        "power_limit_w": None,
        "psu_readings": {},
        "voltage_readings": {},
        "psu_total": 0,
    }
    control = next(iter(_dicts(_dig(power, "PowerControl"))), {})
    context["power_consumed_w"] = _to_float(control.get("PowerConsumedWatts"))
    context["power_capacity_w"] = _to_float(control.get("PowerCapacityWatts"))
    context["power_limit_w"] = _to_float(_dig(control, "PowerLimit", "LimitInWatts"))
    for psu in _dicts(_dig(power, "PowerSupplies")):
        context["psu_total"] += 1
        member_id = _text(psu.get("MemberId")) or _text(psu.get("Id")) or "?"
        health, state = _status(psu)
        line_v = _to_float(psu.get("LineInputVoltage"))
        normalized["psu|%s" % (member_id,)] = {
            "name": _text(psu.get("Name")),
            "state": state,
            "health": health,
            "power_supply_type": _text(psu.get("PowerSupplyType")),
            "line_input_voltage_type": _text(psu.get("LineInputVoltageType")),
            "line_input_voltage": line_v,
            "input_in_range": _input_in_range(line_v, psu.get("InputRanges")),
            "capacity_w": _to_float(psu.get("PowerCapacityWatts")),
            "serial": _text(psu.get("SerialNumber")),
            "model": _text(psu.get("Model")),
            "part_number": _text(psu.get("PartNumber")),
            "manufacturer": _text(psu.get("Manufacturer")),
            "firmware": _text(psu.get("FirmwareVersion")),
        }
        context["psu_readings"][member_id] = {
            "input_w": _to_float(psu.get("PowerInputWatts")),
            "output_w": _to_float(psu.get("PowerOutputWatts")),
            "last_output_w": _to_float(psu.get("LastPowerOutputWatts")),
        }
    for group in _dicts(_dig(power, "Redundancy")):
        member_id = _text(group.get("MemberId")) or _text(group.get("Id")) or "?"
        health, state = _status(group)
        normalized["redundancy|%s" % (member_id,)] = {
            "mode": _text(group.get("Mode")),
            "state": state,
            "health": health,
            "member_count": len(_dicts(group.get("RedundancySet"))),
        }
    for sensor in _dicts(_dig(power, "Voltages")):
        member_id = _text(sensor.get("MemberId")) or _text(sensor.get("Id")) or "?"
        health, state = _status(sensor)
        reading = _to_float(sensor.get("ReadingVolts"))
        normalized["voltage|%s" % (member_id,)] = {
            "name": _text(sensor.get("Name")),
            "state": state,
            "health": health,
            "in_threshold": _in_threshold(reading, sensor),
        }
        context["voltage_readings"][member_id] = reading
    return normalized, context


def _collect_power(ctx):
    with ctx.budget("xcc_power", _BUDGET_POWER):
        power = _get(ctx, _POWER)
    if not isinstance(power, dict) or not power:
        raise CollectError("Chassis/1/Power answered without a resource body")
    normalized, context = _normalize_power(power)
    if not normalized:
        raise CollectError(
            "Chassis/1/Power carries no PowerSupplies/Voltages/Redundancy members — "
            "this firmware may serve PowerSubsystem instead, which is not read yet"
        )
    return {"raw": {_POWER: _curate(power)}, "normalized": normalized, "context": context}


# --- xcc_inventory -----------------------------------------------------------


def _service_label(node):
    """Best-effort physical location of a part: Lenovo OEM, then DMTF Location, then Slot."""
    for path in (
        ("Oem", "Lenovo", "Location", "PartLocation", "ServiceLabel"),
        ("Location", "PartLocation", "ServiceLabel"),
        ("PhysicalLocation", "PartLocation", "ServiceLabel"),
        ("Slot", "Location", "PartLocation", "ServiceLabel"),
        ("Slot", "Location", "Info"),
    ):
        value = _text(_dig(node, *path))
        if value is not None:
            return value
    return None


def _normalize_inventory(memory, processors, pcie):
    """'dimm|<Id>' / 'cpu|<Id>' / 'pcie|<Id>' identity rows; each list may be None (absent)."""
    normalized = {}
    for dimm in _dicts(memory):
        health, state = _status(dimm)
        normalized["dimm|%s" % (_member_id(dimm) or "?",)] = {
            "slot": _text(dimm.get("DeviceLocator")),
            "socket": _to_int(_dig(dimm, "MemoryLocation", "Socket")),
            "service_label": _service_label(dimm),
            "capacity_mib": _to_int(dimm.get("CapacityMiB")),
            "type": _text(dimm.get("MemoryDeviceType")),
            # Firmware-scaled (Lenovo's example shows 21333): stored as-is, never banded.
            "speed_mhz": _to_int(dimm.get("OperatingSpeedMhz")),
            "serial": _text(dimm.get("SerialNumber")),
            "part_number": _text(dimm.get("PartNumber")),
            "manufacturer": _text(dimm.get("Manufacturer")),
            "health": health,
            "state": state,
        }
    for cpu in _dicts(processors):
        health, state = _status(cpu)
        # The SE350 CPU is soldered: identity plus health is all this family carries.
        normalized["cpu|%s" % (_member_id(cpu) or "?",)] = {
            "model": _text(cpu.get("Model")),
            "socket": _text(cpu.get("Socket")),
            "cores": _to_int(cpu.get("TotalCores")),
            "enabled_cores": _to_int(cpu.get("TotalEnabledCores")),
            "threads": _to_int(cpu.get("TotalThreads")),
            "health": health,
            "state": state,
        }
    for device in _dicts(pcie):
        health, state = _status(device)
        normalized["pcie|%s" % (_member_id(device) or "?",)] = {
            "manufacturer": _text(device.get("Manufacturer")),
            "model": _text(device.get("Model")),
            "device_type": _text(device.get("DeviceType")),
            "firmware": _text(device.get("FirmwareVersion")),
            "serial": _text(device.get("SerialNumber")),
            "part_number": _text(device.get("PartNumber")),
            "health": health,
            "state": state,
            "location": _service_label(device),
        }
    return normalized


def _cpu_clock_speeds(processors):
    """{cpu Id: CurrentClockSpeedMHz} — a load-driven reading, kept as context, never diffed."""
    speeds = {}
    for cpu in _dicts(processors):
        speeds[_member_id(cpu) or "?"] = _to_int(cpu.get("CurrentClockSpeedMHz"))
    return speeds


def _collect_inventory(ctx):
    raw = {}
    collections = {}
    context = {"host_power_state": None, "collections": {}, "unmeasured": []}
    with ctx.budget("xcc_inventory", _BUDGET_INVENTORY) as budget:
        system = _get(ctx, _SYSTEM)
        context["host_power_state"] = _text(_dig(system, "PowerState"))
        for family, path in (("memory", _MEMORY), ("processors", _PROCESSORS), ("pcie", _PCIE)):
            members, meta, family_raw = _fetch_collection(
                ctx, path, "xcc_inventory %s" % (family,), ok_404=True, budget=budget
            )
            collections[family] = members
            context["collections"][family] = dict(
                meta, members=len(members) if members is not None else None
            )
            raw.update(family_raw)
    if all(members is None for members in collections.values()):
        raise SkipCheck("Memory, Processors and PCIeDevices collections all answered 404")
    # Inventory is POST-populated (UEFI / Host Interface). An empty 200
    # collection is unmeasured — with the host off, or On but still in POST,
    # or on a firmware that never enumerates the family — and a diff cannot
    # tell "unmeasured" from "every part gone", so the read is refused
    # whatever the power state says; a Memory or Processors collection is
    # never legitimately empty on a server.
    for family, members in collections.items():
        if members is not None and not members:
            context["unmeasured"].append(family)
    if context["unmeasured"]:
        raise CollectError(
            "%s answered with zero members (host PowerState %s) — inventory is populated "
            "at POST and an empty collection is unmeasured, never 'all parts gone'; capture "
            "again after the host completes POST"
            % (", ".join(context["unmeasured"]), context["host_power_state"])
        )
    normalized = _normalize_inventory(
        collections["memory"], collections["processors"], collections["pcie"]
    )
    # Clock speed is load-driven (and this CPU is soldered): a reading, so it
    # rides in context next to the identity rows and stays in raw, never diffed.
    context["clock_speed_mhz"] = _cpu_clock_speeds(collections["processors"])
    return {"raw": raw, "normalized": normalized, "context": context}


# --- xcc_host_nics -----------------------------------------------------------

# ``ToManager`` is the USB Redfish Host Interface (host OS <-> BMC), not a
# port; it is filtered by id before any GET is spent on it.
_HOST_NIC_EXCLUDE = frozenset({"tomanager"})


def _normalize_host_nics(members):
    """(normalized, context): 'nic|<Id>' -> link_status, permanent_mac, health, state, ...

    speed_mbps is context only — null on gen-1 documentation, 0 on later
    firmware; both read as None. The constant vendor Description is dropped.
    """
    normalized = {}
    context = {"speed_mbps": {}, "mac_source": {}, "full_duplex": {}}
    for nic in _dicts(members):
        nic_id = _member_id(nic) or "?"
        health, state = _status(nic)
        permanent = _mac(nic.get("PermanentMACAddress"))
        source = "PermanentMACAddress"
        if permanent is None:
            permanent = _mac(nic.get("MACAddress"))
            source = "MACAddress" if permanent else None
        normalized["nic|%s" % (nic_id,)] = {
            "name": _text(nic.get("Name")),
            "link_status": _text(nic.get("LinkStatus")),
            "permanent_mac": permanent,
            "interface_enabled": _to_bool(nic.get("InterfaceEnabled")),
            "health": health,
            "state": state,
        }
        speed = _to_int(nic.get("SpeedMbps"))
        context["speed_mbps"][nic_id] = speed if speed else None
        context["mac_source"][nic_id] = source
        context["full_duplex"][nic_id] = _to_bool(nic.get("FullDuplex"))
    return normalized, context


def _collect_host_nics(ctx):
    with ctx.budget("xcc_host_nics", _BUDGET_HOST_NICS) as budget:
        system = _get(ctx, _SYSTEM)
        members, meta, raw = _fetch_collection(
            ctx, _HOST_NICS, "xcc_host_nics", ok_404=True, exclude=_HOST_NIC_EXCLUDE, budget=budget
        )
    if members is None:
        raise SkipCheck("Systems/1/EthernetInterfaces is not served by this firmware")
    if not members:
        raise SkipCheck(
            "Systems/1/EthernetInterfaces lists no host ports (excluded: %s)"
            % (", ".join(meta["excluded"]) or "none",)
        )
    normalized, context = _normalize_host_nics(members)
    if all(row["link_status"] is None for row in normalized.values()):
        # A firmware that never reports host link state would otherwise diff
        # false-green on every capture.
        raise SkipCheck("LinkStatus is null on every host port — link state not reported")
    context.update(meta)
    context["host_power_state"] = _text(_dig(system, "PowerState"))
    return {"raw": raw, "normalized": normalized, "context": context}


# --- xcc_firmware ------------------------------------------------------------


def _normalize_firmware(members):
    """'fw|<Id>' -> name, version (verbatim), software_id, updateable, health.

    Status.State is never emitted: the backup XCC bank toggles between
    StandbyOffline and Enabled after a BMC reboot. ReleaseDate, etags,
    LowestSupportedVersion, Description and Oem.* are excluded.
    """
    normalized = {}
    for member in sorted(_dicts(members), key=lambda item: _member_id(item) or ""):
        health, _state = _status(member)
        normalized["fw|%s" % (_member_id(member) or "?",)] = {
            "name": _text(member.get("Name")),
            "version": _text(member.get("Version")),
            "software_id": _text(member.get("SoftwareId")),
            "updateable": _to_bool(member.get("Updateable")),
            "health": health,
        }
    return normalized


def _collect_firmware(ctx):
    with ctx.budget("xcc_firmware", _BUDGET_FIRMWARE) as budget:
        members, meta, raw = _fetch_collection(ctx, _FIRMWARE, "xcc_firmware", budget=budget)
    if not members:
        raise CollectError("UpdateService/FirmwareInventory lists no members")
    return {
        "raw": raw,
        "normalized": _normalize_firmware(members),
        "context": dict(meta, members=len(members)),
    }


# --- xcc_event_log -----------------------------------------------------------

_KEYED_SEVERITIES = frozenset({"warning", "critical"})


def _pick_log_service(links):
    """PlatformLog (gen-1 guide, V2 too) else StandardLog (Purley era) else a lone member."""
    by_id = {_leaf_id(link): link for link in links}
    for wanted in ("PlatformLog", "StandardLog"):
        if wanted in by_id:
            return by_id[wanted], wanted
    if len(links) == 1:
        return links[0], _leaf_id(links[0])
    raise CollectError(
        "Systems/1/LogServices offers neither PlatformLog nor StandardLog (members: %s)"
        % (", ".join(sorted(by_id)) or "none",)
    )


def _entry_sort_id(entry):
    value = _to_int(entry.get("Id"))
    return (0, value) if value is not None else (1, str(entry.get("Id")))


def _normalize_event_log(entries, log_service=None):
    """(normalized, context) over the whole Entries collection.

    Keys 'sel|<CommonEventID>|<Id>' for Severity Warning/Critical only — the
    event code sits in the key so an expectation glob can bless a declared
    addition. Every other entry is counted per CommonEventID in context.
    Ids are the monotonic EventSequenceNumber. Whether the log was cleared
    is a cross-capture fact (a post newest_id below the pre newest_id) that
    one capture cannot know, so context carries the facts the comparison
    needs — first_id, newest_id, the service's own FirstSeqNum/LastSeqNum,
    entries_total — and ``at_capacity`` (the log holds MaxNumberOfRecords
    entries, so the next event overwrites the oldest) as the one wrap-related
    fact a single capture can state.
    """
    normalized = {}
    informational = {}
    hidden_total = 0
    ids = []
    newest = None
    for entry in _dicts(entries):
        entry_id = _text(entry.get("Id")) or "?"
        code = _text(_dig(entry, "Oem", "Lenovo", "CommonEventID")) or "unknown"
        severity = _text(entry.get("Severity"))
        hidden = _to_bool(_dig(entry, "Oem", "Lenovo", "Hidden"))
        if hidden:
            hidden_total += 1
        numeric = _to_int(entry.get("Id"))
        if numeric is not None:
            ids.append(numeric)
        if newest is None or _entry_sort_id(entry) > _entry_sort_id(newest):
            newest = entry
        if (severity or "").lower() in _KEYED_SEVERITIES:
            normalized["sel|%s|%s" % (code, entry_id)] = {
                "severity": severity,
                "source": _text(_dig(entry, "Oem", "Lenovo", "Source"))
                or _text(entry.get("SensorType")),
                "serviceable": _to_bool(_dig(entry, "Oem", "Lenovo", "Serviceable")),
                "event_id": _text(entry.get("EventId")),
                "hidden": bool(hidden),
            }
        else:
            informational[code] = informational.get(code, 0) + 1
    max_records = _to_int(_dig(log_service, "MaxNumberOfRecords"))
    overwrite_policy = _text(_dig(log_service, "OverWritePolicy"))
    at_capacity = None
    if max_records is not None:
        at_capacity = len(_dicts(entries)) >= max_records
    context = {
        "entries_total": len(_dicts(entries)),
        "keyed_entries": len(normalized),
        "hidden_entries": hidden_total,
        "informational_by_code": dict(sorted(informational.items())),
        "first_id": min(ids) if ids else None,
        "newest_id": max(ids) if ids else None,
        "newest_created": _text(newest.get("Created")) if newest else None,
        "at_capacity": at_capacity,
        "max_records": max_records,
        "overwrite_policy": overwrite_policy,
        "first_seq_num": _to_int(_dig(log_service, "Oem", "Lenovo", "FirstSeqNum")),
        "last_seq_num": _to_int(_dig(log_service, "Oem", "Lenovo", "LastSeqNum")),
    }
    return normalized, context


def _curate_entries(entries):
    """Per-entry audit rows for raw (newest first, capped): Id, Created, Severity, code, Message."""
    ordered = sorted(_dicts(entries), key=_entry_sort_id, reverse=True)
    rows = []
    for entry in ordered[:_RAW_LOG_ENTRIES]:
        rows.append(
            {
                "Id": entry.get("Id"),
                "Created": entry.get("Created"),
                "Severity": entry.get("Severity"),
                "EventId": entry.get("EventId"),
                "CommonEventID": _dig(entry, "Oem", "Lenovo", "CommonEventID"),
                "Hidden": _dig(entry, "Oem", "Lenovo", "Hidden"),
                "Message": entry.get("Message"),
            }
        )
    return rows, max(0, len(ordered) - _RAW_LOG_ENTRIES)


def _collect_event_log(ctx):
    with ctx.budget("xcc_event_log", _BUDGET_EVENT_LOG):
        services = _get(ctx, _LOG_SERVICES)
        service_link, service_id = _pick_log_service(_member_links(services, "xcc_event_log"))
        service = _get(ctx, service_link)
        entries_link = _fenced_link(service.get("Entries"), "xcc_event_log") or (
            service_link + "/Entries"
        )
        # The whole collection, no query string: $top is undocumented on XCC
        # and where honoured returns the OLDEST entries first. A firmware that
        # pages hands back Members@odata.nextLink; the fence lets its $skip /
        # $skiptoken through and refuses a link carrying $top (or anything
        # else) loudly rather than reading a partial log.
        page = _get(ctx, entries_link)
        entries = list(_dicts(page.get("Members")))
        pages = [entries_link]
        while _text(page.get("Members@odata.nextLink")):
            next_link = _fenced_link(
                {"@odata.id": page["Members@odata.nextLink"]}, "xcc_event_log continuation"
            )
            page = _get(ctx, next_link)
            entries.extend(_dicts(page.get("Members")))
            pages.append(next_link)
    normalized, context = _normalize_event_log(entries, service)
    rows, omitted = _curate_entries(entries)
    raw = {
        _LOG_SERVICES: _curate(services),
        service_link: _curate(service),
        entries_link: {
            "Members@odata.count": page.get("Members@odata.count", len(entries)),
            "Members": rows,
            "entries_omitted_from_raw": omitted,
            "pages_fetched": pages,
        },
    }
    context.update({"log_service_used": service_id, "pages": len(pages)})
    return {"raw": raw, "normalized": normalized, "context": context}


# --- xcc_bios ----------------------------------------------------------------

# UEFI attribute names are Lenovo's (``Processors_HyperThreading``,
# ``BootModes_SystemBootMode`` ...) and are harvested at shakedown; the
# curated set is therefore a token list matched case-insensitively on the
# attribute name: virtualisation, SR-IOV, hyper-threading, operating mode,
# C-states/C1E, turbo, boot mode, MMIO above 4G, TPM/secure boot, NUMA.
_BIOS_TOKENS = (
    "hyperthread",
    "hyper-thread",
    "turbo",
    "cstate",
    "c-state",
    "c1e",
    "operatingmode",
    "vtd",
    "vt-d",
    "iommu",
    "directedio",
    "sriov",
    "sr-iov",
    "bootmode",
    "mmio",
    "above4g",
    "mmconfig",
    "tpm",
    "tcm",
    "secureboot",
    "powerperformance",
    "energyefficient",
    "numa",
    "speedstep",
    "pstate",
    "p-state",
    "prefetch",
    "uncore",
    "hwpm",
)


def _bios_selected(name):
    lowered = str(name).lower()
    return any(token in lowered for token in _BIOS_TOKENS)


def _normalize_bios(bios):
    """'bios|<attribute>' -> value for the curated (token-matched) attributes; scalars verbatim."""
    attributes = _dig(bios, "Attributes")
    normalized = {}
    if not isinstance(attributes, dict):
        return normalized
    for name in sorted(attributes):
        if _bios_selected(name) and not _looks_secret(name):
            normalized["bios|%s" % (name,)] = attributes[name]
    return normalized


def _collect_bios(ctx):
    with ctx.budget("xcc_bios", _BUDGET_BIOS):
        bios = _get_optional(ctx, _BIOS)
    if bios is None:
        raise SkipCheck("Systems/1/Bios is not served by this firmware")
    attributes = _dig(bios, "Attributes")
    if not isinstance(attributes, dict) or not attributes:
        raise CollectError("Systems/1/Bios answered without an Attributes block")
    normalized = _normalize_bios(bios)
    selected = {key.split("|", 1)[1] for key in normalized}
    curated = _curate(bios)
    curated.pop("Attributes", None)
    curated["attributes_selected"] = {name: attributes[name] for name in sorted(selected)}
    curated["attributes_other"] = _capped_lines(
        (name, value)
        for name, value in attributes.items()
        if name not in selected and not _looks_secret(name)
    )
    return {
        "raw": {_BIOS: curated},
        "normalized": normalized,
        "context": {
            "attributes_total": len(attributes),
            "attributes_selected": len(selected),
            "attribute_registry": _text(bios.get("AttributeRegistry")),
        },
    }


# --- xcc_storage -------------------------------------------------------------


def _normalize_storage(controllers, drives, volumes):
    """(normalized, context) over Storage members, their Drives[] and Volumes.

    ``controllers`` is the list of Storage member payloads; ``drives`` and
    ``volumes`` map a controller id to its member payloads. Keys are
    'controller|<Id>', 'drive|<Id>' and 'volume|<Id>'; a drive/volume id that
    repeats across controllers is prefixed with the controller id.
    """
    normalized = {}
    context = {"life_left_pct": {}, "drives_total": 0, "volumes_total": 0}
    drive_ids = [_member_id(d) for rows in drives.values() for d in _dicts(rows)]
    volume_ids = [_member_id(v) for rows in volumes.values() for v in _dicts(rows)]

    def _key(kind, controller_id, item_id, all_ids):
        if all_ids.count(item_id) > 1:
            return "%s|%s|%s" % (kind, controller_id, item_id)
        return "%s|%s" % (kind, item_id)

    for controller in _dicts(controllers):
        controller_id = _member_id(controller) or "?"
        first = next(iter(_dicts(controller.get("StorageControllers"))), {})
        health, state = _status(controller)
        normalized["controller|%s" % (controller_id,)] = {
            "name": _text(controller.get("Name")),
            "model": _text(first.get("Model")),
            "manufacturer": _text(first.get("Manufacturer")),
            "firmware": _text(first.get("FirmwareVersion")),
            "serial": _text(first.get("SerialNumber")),
            "health": health or _text(_dig(first, "Status", "Health")),
            "state": state or _text(_dig(first, "Status", "State")),
            "drive_count": len(_dicts(drives.get(controller_id))),
            "volume_count": len(_dicts(volumes.get(controller_id))),
        }
        for drive in _dicts(drives.get(controller_id)):
            context["drives_total"] += 1
            drive_id = _member_id(drive) or "?"
            key = _key("drive", controller_id, drive_id, drive_ids)
            health, state = _status(drive)
            normalized[key] = {
                "serial": _text(drive.get("SerialNumber")),
                "model": _text(drive.get("Model")),
                "manufacturer": _text(drive.get("Manufacturer")),
                "revision": _text(drive.get("Revision")),
                "capacity_bytes": _to_int(drive.get("CapacityBytes")),
                "media_type": _text(drive.get("MediaType")),
                "protocol": _text(drive.get("Protocol")),
                "health": health,
                "state": state,
                "failure_predicted": _to_bool(drive.get("FailurePredicted")),
                "encryption_ability": _text(drive.get("EncryptionAbility")),
                "encryption_status": _text(drive.get("EncryptionStatus")),
                "location": _service_label(drive) or _text(_dig(drive, "PhysicalLocation", "Info")),
            }
            context["life_left_pct"][key] = _to_float(drive.get("PredictedMediaLifeLeftPercent"))
        for volume in _dicts(volumes.get(controller_id)):
            context["volumes_total"] += 1
            volume_id = _member_id(volume) or "?"
            key = _key("volume", controller_id, volume_id, volume_ids)
            health, state = _status(volume)
            member_drives = sorted(
                _leaf_id(item["@odata.id"])
                for item in _dicts(_dig(volume, "Links", "Drives"))
                if item.get("@odata.id")
            )
            normalized[key] = {
                "name": _text(volume.get("Name")),
                "raid_type": _text(volume.get("RAIDType")) or _text(volume.get("VolumeType")),
                "capacity_bytes": _to_int(volume.get("CapacityBytes")),
                "health": health,
                "state": state,
                "encrypted": _to_bool(volume.get("Encrypted")),
                "drives": member_drives,
            }
    return normalized, context


def _collect_storage(ctx):
    drives = {}
    volumes = {}
    with ctx.budget("xcc_storage", _BUDGET_STORAGE) as budget:
        system = _get(ctx, _SYSTEM)
        controllers, meta, raw = _fetch_collection(
            ctx, _STORAGE, "xcc_storage", ok_404=True, budget=budget
        )
        if controllers is None:
            raise SkipCheck("Systems/1/Storage is not served by this firmware")
        if not controllers:
            raise SkipCheck(
                "Systems/1/Storage lists no controllers (host PowerState %s; non-RAID M.2 "
                "may not enumerate at all)" % (_text(_dig(system, "PowerState")),)
            )
        for controller in controllers:
            controller_id = _member_id(controller) or "?"
            drive_links = []
            for item in _dicts(controller.get("Drives")):
                link = _fenced_link(item, "xcc_storage")
                if link:
                    drive_links.append(link)
            _require_budget(budget, len(drive_links), "xcc_storage", "drives")
            drives[controller_id] = []
            for link in drive_links:
                drive = _get(ctx, link)
                raw[link] = _curate(drive)
                drives[controller_id].append(drive)
            volumes_link = _fenced_link(controller.get("Volumes"), "xcc_storage")
            volumes[controller_id] = []
            if volumes_link:
                members, _vmeta, vraw = _fetch_collection(
                    ctx, volumes_link, "xcc_storage volumes", ok_404=True, budget=budget
                )
                raw.update(vraw)
                volumes[controller_id] = members or []
    normalized, context = _normalize_storage(controllers, drives, volumes)
    context.update(meta)
    context["host_power_state"] = _text(_dig(system, "PowerState"))
    return {"raw": raw, "normalized": normalized, "context": context}


# --- xcc_manager_network -----------------------------------------------------

_PROTOCOLS = ("HTTP", "HTTPS", "SSH", "IPMI", "SNMP", "VirtualMedia", "KVMIP", "SSDP", "Telnet")


def _normalize_manager_network(protocol, nic):
    """Flat scalars: NTP, per-protocol enabled/port, host names, and the NIC's addressing."""
    protocol = protocol if isinstance(protocol, dict) else {}
    nic = nic if isinstance(nic, dict) else {}
    ipv4 = _first_ipv4(nic)
    ntp = _dig(protocol, "NTP") if isinstance(_dig(protocol, "NTP"), dict) else {}
    normalized = {
        "hostname": _text(protocol.get("HostName")),
        "fqdn": _text(protocol.get("FQDN")),
        "ntp_enabled": _to_bool(ntp.get("ProtocolEnabled")),
        "ntp_servers": [_text(s) for s in _aslist(ntp.get("NTPServers")) if _text(s)],
    }
    for name in _PROTOCOLS:
        block = protocol.get(name) if isinstance(protocol.get(name), dict) else {}
        normalized["%s_enabled" % (name.lower(),)] = _to_bool(block.get("ProtocolEnabled"))
        normalized["%s_port" % (name.lower(),)] = _to_int(block.get("Port"))
    vlan_enabled = _to_bool(_dig(nic, "VLAN", "VLANEnable"))
    normalized.update(
        {
            "nic_hostname": _text(nic.get("HostName")),
            "nic_fqdn": _text(nic.get("FQDN")),
            "ipv4_address": _text(ipv4.get("Address")),
            "ipv4_origin": _text(ipv4.get("AddressOrigin")),
            "ipv4_subnet_mask": _text(ipv4.get("SubnetMask")),
            "ipv4_gateway": _text(ipv4.get("Gateway")),
            "dhcpv4_enabled": _to_bool(_dig(nic, "DHCPv4", "DHCPEnabled")),
            "dns_servers": [_text(s) for s in _aslist(nic.get("NameServers")) if _text(s)],
            "static_dns_servers": [
                _text(s) for s in _aslist(nic.get("StaticNameServers")) if _text(s)
            ],
            "ipv6_address_count": len(_dicts(nic.get("IPv6Addresses"))),
            "ipv6_gateway": _text(nic.get("IPv6DefaultGateway")),
            "mtu": _to_int(nic.get("MTUSize")),
            "autoneg": _to_bool(nic.get("AutoNeg")),
            "vlan_enabled": vlan_enabled,
            "vlan_id": _to_int(_dig(nic, "VLAN", "VLANId")) if vlan_enabled else None,
            "interface_enabled": _to_bool(nic.get("InterfaceEnabled")),
        }
    )
    return normalized


def _collect_manager_network(ctx):
    with ctx.budget("xcc_manager_network", _BUDGET_MANAGER_NETWORK):
        protocol = _get(ctx, _NETWORK_PROTOCOL)
        nic, nic_meta, nic_raw = _fetch_manager_nic(ctx)
    raw = {_NETWORK_PROTOCOL: _curate(protocol)}
    raw.update(nic_raw)
    return {
        "raw": raw,
        "normalized": _normalize_manager_network(protocol, nic),
        "context": {
            "manager_nic": nic_meta,
            "nic_speed_mbps": _to_int(_dig(nic, "SpeedMbps")) if nic else None,
            "nic_link_status": _text(_dig(nic, "LinkStatus")) if nic else None,
        },
    }


# --- xcc_chassis_location ----------------------------------------------------


def _normalize_chassis_location(chassis):
    """Flat scalars: chassis identity, Location.PostalAddress/Placement leaves, intrusion sensor.

    PostalAddress and Placement are passed through generically as
    'postal_<field>' / 'placement_<field>' so whichever leaves this firmware
    fills are compared; the operator-maintained record is expected to be
    edited when the chassis is relocated.
    """
    chassis = chassis if isinstance(chassis, dict) else {}
    health, state = _status(chassis)
    normalized = {
        "chassis_type": _text(chassis.get("ChassisType")),
        "manufacturer": _text(chassis.get("Manufacturer")),
        "model": _text(chassis.get("Model")),
        "serial": _text(chassis.get("SerialNumber")),
        "part_number": _text(chassis.get("PartNumber")),
        "asset_tag": _text(chassis.get("AssetTag")),
        "health": health,
        "state": state,
        "power_state": _text(chassis.get("PowerState")),
        "location_info": _text(_dig(chassis, "Location", "Info")),
        "location_info_format": _text(_dig(chassis, "Location", "InfoFormat")),
        "intrusion_sensor": _text(_dig(chassis, "PhysicalSecurity", "IntrusionSensor")),
        "intrusion_sensor_rearm": _text(_dig(chassis, "PhysicalSecurity", "IntrusionSensorReArm")),
    }
    for block, prefix in (("PostalAddress", "postal_"), ("Placement", "placement_")):
        node = _dig(chassis, "Location", block)
        if not isinstance(node, dict):
            continue
        for key in sorted(node):
            value = node[key]
            if isinstance(value, (dict, list)) or str(key).startswith("@"):
                continue
            normalized[prefix + _snake(key)] = value
    return normalized


def _collect_chassis_location(ctx):
    with ctx.budget("xcc_chassis_location", _BUDGET_CHASSIS):
        chassis = _get(ctx, _CHASSIS)
    if not isinstance(chassis, dict) or not chassis:
        raise CollectError("Chassis/1 answered without a resource body")
    return {
        "raw": {_CHASSIS: _curate(chassis)},
        "normalized": _normalize_chassis_location(chassis),
        "context": {
            "indicator_led": _text(chassis.get("IndicatorLED")),
            "location_present": isinstance(chassis.get("Location"), dict),
            "physical_security_present": isinstance(chassis.get("PhysicalSecurity"), dict),
        },
    }


# --- registrations -----------------------------------------------------------

register(
    CheckDef(
        id="xcc_system",
        platform="xcc",
        description="System identity, health, boot settings, SecureBoot and the XCC's own address.",
        tier=1,
        compare={"mode": "equality_scalar"},
        miss_meaning=(
            "An identity field (serial/uuid/model/BIOS/XCC firmware) differs — a different "
            "chassis or a firmware change; a boot/SecureBoot change means the host was "
            "not booted the intended way; an XCC address change means the BMC was "
            "re-addressed or re-leased."
        ),
        collector=_collect_system,
        tags=("platform", "identity"),
    )
)

register(
    CheckDef(
        id="xcc_security_state",
        platform="xcc",
        description="ThinkEdge Security Pack state: lockdown, motion/intrusion detection, SED.",
        tier=1,
        compare={"mode": "equality_scalar"},
        miss_meaning=(
            "The tamper-protection state changed: an active lockdown denies SED keys until "
            "re-activation; motion detection flipping off together with lockdown Active is "
            "the lockdown itself, not an operator edit."
        ),
        collector=_collect_security_state,
        tags=("platform", "security"),
    )
)

register(
    CheckDef(
        id="xcc_thermal",
        platform="xcc",
        description="Chassis temperature sensors and fans: health/state, ambient-class readings.",
        tier=1,
        compare={
            "mode": "equality_set",
            "fields": {
                "reading_c": {"tolerance": {"abs": 8}},
                "reading": {"tolerance": {"pct": 25}},
            },
        },
        miss_meaning=(
            "A sensor or fan degraded, vanished, or the ambient/intake reading moved more "
            "than 8 °C — the thermal environment or the chassis cooling changed; SE350 fans "
            "are internal and non-hot-swap."
        ),
        collector=_collect_thermal,
        tags=("platform", "environment"),
    )
)

register(
    CheckDef(
        id="xcc_power",
        platform="xcc",
        description="Power supplies/adapters, redundancy and voltage rails from Chassis/1/Power.",
        tier=1,
        compare={
            "mode": "equality_set",
            "fields": {"line_input_voltage": {"tolerance": {"pct": 10}}},
        },
        miss_meaning=(
            "A feed was lost or changed: a supply not Enabled/OK, input out of its declared "
            "range, redundancy degraded, or a rail outside its thresholds."
        ),
        collector=_collect_power,
        tags=("platform", "environment"),
    )
)

register(
    CheckDef(
        id="xcc_inventory",
        platform="xcc",
        description="DIMM, processor and PCIe device inventory with per-part identity and health.",
        tier=2,
        compare={"mode": "equality_set"},
        miss_meaning=(
            "A part is missing, replaced or unhealthy — a DIMM or riser that did not come "
            "back is a missing key, a swapped part is a serial change."
        ),
        collector=_collect_inventory,
        tags=("platform", "inventory"),
    )
)

register(
    CheckDef(
        id="xcc_host_nics",
        platform="xcc",
        description="Host network ports as the BMC sees them: link status and burned-in MAC.",
        tier=1,
        compare={"mode": "equality_set"},
        miss_meaning=(
            "A host port's link state changed independently of ESXi — a cable not "
            "reconnected (NoLink) or connected but not up (LinkDown)."
        ),
        collector=_collect_host_nics,
        tags=("interfaces",),
    )
)

register(
    CheckDef(
        id="xcc_firmware",
        platform="xcc",
        description="Firmware inventory: every component's version and SoftwareId.",
        tier=2,
        compare={"mode": "equality_set"},
        miss_meaning=(
            "A firmware version changed or a component vanished from the inventory — an "
            "undeclared update, or an adapter that did not enumerate."
        ),
        collector=_collect_firmware,
        tags=("platform", "firmware"),
    )
)

register(
    CheckDef(
        id="xcc_event_log",
        platform="xcc",
        description="BMC platform event log: Warning/Critical entries keyed by event code and id.",
        tier=2,
        compare={"mode": "equality_set"},
        miss_meaning=(
            "A Warning/Critical event was logged between captures — a hardware finding "
            "unless its event code was declared; a removed key means the log was cleared "
            "or wrapped."
        ),
        collector=_collect_event_log,
        tags=("platform", "logs"),
    )
)

register(
    CheckDef(
        id="xcc_bios",
        platform="xcc",
        description="Curated UEFI settings: VT-d, SR-IOV, HT, power/turbo, boot mode, TPM.",
        tier=2,
        compare={"mode": "equality_set"},
        miss_meaning=(
            "A UEFI setting reverted or changed — a defaults load, CMOS/RTC reset or an "
            "operator edit; the VNF tuning depends on these."
        ),
        collector=_collect_bios,
        tags=("platform", "bios"),
    )
)

register(
    CheckDef(
        id="xcc_storage",
        platform="xcc",
        description="Storage controllers, physical drives (health, SED status) and RAID volumes.",
        tier=1,
        compare={"mode": "equality_set"},
        miss_meaning=(
            "A drive or volume degraded, vanished or was replaced — a RAID1 member failure "
            "is invisible to the hypervisor's LUN view; an encryption flag change is a "
            "key-management event."
        ),
        collector=_collect_storage,
        tags=("platform", "storage"),
    )
)

register(
    CheckDef(
        id="xcc_manager_network",
        platform="xcc",
        description="XCC network services: NTP, DNS, enabled protocols/ports, addressing origin.",
        tier=2,
        compare={"mode": "equality_scalar"},
        miss_meaning=(
            "The BMC's own network/time configuration changed — NTP or DNS lost means "
            "back-dated event-log timestamps and a broken portal reactivation path."
        ),
        collector=_collect_manager_network,
        tags=("platform", "management"),
    )
)

register(
    CheckDef(
        id="xcc_chassis_location",
        platform="xcc",
        description="Operator-maintained chassis Location record and the intrusion sensor state.",
        tier=3,
        compare={"mode": "equality_scalar"},
        miss_meaning=(
            "The location record changed (expected when a chassis is relocated — declare it) "
            "or the intrusion sensor left Normal."
        ),
        collector=_collect_chassis_location,
        tags=("platform", "location"),
    )
)
