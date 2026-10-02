"""Resolve inventory scope before any transport opens.

Only the standard library and shared constants are imported. The job narrows
location/dynamic-group members through Nautobot's filter set, then supplies
plain device and controller rows here. Explicit picks are added without those
filters; controllers are pulled in before exclusions apply. No runtime failure
can become a skip because this module never performs collection.
"""

import re
from collections import Counter
from copy import deepcopy

from . import constants as C

_WORD_SPLIT = re.compile(r"[^A-Za-z0-9]+")
_SOURCE_ORDER = ("location", "dynamic_group", "explicit", "controller_of")


def _denied_tokens(driver, name, slug):
    words = {
        word.lower()
        for value in (driver, name, slug)
        for word in _WORD_SPLIT.split(str(value or ""))
        if word
    }
    return [token for token in C.PLATFORM_DENY_TOKENS if token in words]


def map_platform(driver, name="", slug=""):
    """Return (check family, selected driver), preserving the legacy fallback.

    Family precedence is PAN-OS, VMware/ESXi, then Cisco. Deny words in *any*
    platform field take precedence, including when its driver says cisco_ios.
    A blank driver falls back to the legacy slug, then the platform name.
    """
    selected = str(driver or slug or name or "").lower()
    if _denied_tokens(driver, name, slug):
        return None, selected
    if "panos" in selected or "paloalto" in selected:
        return "panos", selected
    if "vmware" in selected or "esxi" in selected:
        return "vmware", selected
    if "cisco" in selected:
        return "iosxe", selected
    return None, selected


def _identity(row):
    return str(row.get("pk", row.get("id", "")))


def _sources(value):
    return [value] if isinstance(value, str) else list(value or ())


def _ordered_sources(values):
    return sorted(
        set(values),
        key=lambda value: (
            _SOURCE_ORDER.index(value) if value in _SOURCE_ORDER else len(_SOURCE_ORDER),
            value,
        ),
    )


def _sort_device(row):
    return (str(row.get("name", "")).casefold(), str(row.get("name", "")), _identity(row))


def _supported(row):
    return bool(
        map_platform(row.get("platform_driver"), row.get("platform"), row.get("platform_slug"))[0]
        or row.get("has_bmc")
    )


def _unsupported_reason(row):
    denied = _denied_tokens(
        row.get("platform_driver"), row.get("platform"), row.get("platform_slug")
    )
    platform = (
        row.get("platform") or row.get("platform_driver") or row.get("platform_slug") or "unset"
    )
    if denied:
        return (
            f"Platform '{platform}' contains unsupported token(s) {', '.join(denied)}; "
            "set its managed-device group/controller when applicable, or exclude the device"
        )
    return (
        f"Unsupported platform '{platform}'; set a supported cisco, panos/paloalto or "
        "vmware/esxi platform, or model the host's BMC interface"
    )


def resolve(
    rows,
    controllers=(),
    *,
    locations=(),
    dynamic_group=None,
    explicit_devices=(),
    exclude_devices=(),
    roles=(),
    statuses=(),
    tags=(),
    include_controllers=True,
    dryrun=False,
    max_capture=C.SCOPE_MAX_CAPTURE,
):
    """Return ordered manifests, capture ids, counts and preflight diagnostics.

    Device rows contain pk/name, platform_driver/platform/platform_slug,
    has_bmc, location/role/status/source, and optional managed_group with
    controller_pk and capabilities. Controller rows contain pk/name,
    capabilities, device (a device row or None), and has_redundancy_group.
    Exclusions accept device rows or primary keys. All identities become strings.

    ``rows`` are already narrowed by the ORM. ``roles``, ``statuses`` and
    ``tags`` describe those filters; they never narrow explicit picks here.
    ``errors`` refuse collection, while dry-run size warnings allow preview.
    Returning the full resolution lets the caller attach evidence of refusal.
    """
    del roles, statuses, tags  # Their narrowing belongs to DeviceFilterSet.
    explicit_devices = list(explicit_devices)
    exclude_devices = list(exclude_devices)
    anchored = bool(locations or dynamic_group)
    errors = []
    warnings = []
    devices = {}
    controller_map = {_identity(row): deepcopy(row) for row in controllers}
    explicit_ids = set()
    pulled_by = {}
    relevant_controllers = set()

    def add(row, source=()):
        identifier = _identity(row)
        if not identifier:
            raise ValueError("Every scope device row needs a primary key")
        incoming = deepcopy(row)
        incoming["pk"] = identifier
        incoming["source"] = _ordered_sources(_sources(incoming.get("source")) + list(source))
        if identifier in devices:
            devices[identifier]["source"] = _ordered_sources(
                devices[identifier]["source"] + incoming["source"]
            )
        else:
            devices[identifier] = incoming

    if not anchored and not explicit_devices:
        errors.append(
            "Pick at least one device, location or dynamic group; narrowing filters need a "
            "location or dynamic-group anchor"
        )
    if anchored:
        fallback_sources = (["location"] if locations else []) + (
            ["dynamic_group"] if dynamic_group else []
        )
        for row in rows:
            add(row, fallback_sources if not row.get("source") else ())
    for row in explicit_devices:
        add(row, ("explicit",))
        explicit_ids.add(_identity(row))

    # A controller can itself be managed. Close over the modelled chain once
    # per device, so nested or circular inventory cannot repeat work forever.
    inspected = set()
    while True:
        pending = [row for identifier, row in devices.items() if identifier not in inspected]
        if not pending:
            break
        for row in pending:
            identifier = _identity(row)
            inspected.add(identifier)
            group = row.get("managed_group") or {}
            controller_pk = group.get("controller_pk")
            if not controller_pk:
                continue
            controller_pk = str(controller_pk)
            relevant_controllers.add(controller_pk)
            controller = controller_map.get(controller_pk)
            target = controller.get("device") if controller else None
            if target is not None:
                target_id = _identity(target)
                if target_id != identifier:
                    pulled_by.setdefault(target_id, set()).add(str(row.get("name", identifier)))
                    if include_controllers:
                        add(target, ("controller_of",))

    # Explicit exclusions remain evidence even when status/anchor filters no
    # longer select a device. Add them after expansion so they cannot pull in
    # unrelated controllers or become capture candidates.
    for row in exclude_devices:
        if isinstance(row, dict) and _identity(row) not in devices:
            add(row, ("exclude_devices",))
    excluded = {_identity(row) if isinstance(row, dict) else str(row) for row in exclude_devices}
    disposition = {}
    reasons = {}
    dependencies = {}
    controller_device_ids = set()

    # First classify independent devices. Managed wireless devices (or
    # unsupported managed devices when capabilities are empty) depend on a
    # controller whose device must actually resolve to capture.
    for identifier, row in devices.items():
        group = row.get("managed_group") or {}
        controller_pk = str(group.get("controller_pk") or "")
        controller = controller_map.get(controller_pk)
        target = controller.get("device") if controller else None
        target_id = _identity(target) if target else None
        if target_id:
            controller_device_ids.add(target_id)
        if identifier in excluded:
            disposition[identifier] = "excluded"
            reasons[identifier] = "Selected in exclude_devices"
            continue
        supported = _supported(row)
        platform_family = map_platform(
            row.get("platform_driver"), row.get("platform"), row.get("platform_slug")
        )[0]
        capabilities = set(_sources(group.get("capabilities"))) | set(
            _sources(controller.get("capabilities") if controller else ())
        )
        managed_coverage = (
            bool(group)
            and identifier != target_id
            and ("wireless" in capabilities or (not capabilities and platform_family is None))
        )
        if managed_coverage:
            dependencies[identifier] = (controller_pk, controller, target_id)
        elif supported:
            disposition[identifier] = "capture"
            reasons[identifier] = None
        else:
            disposition[identifier] = "skipped_unsupported"
            reasons[identifier] = _unsupported_reason(row)

    for identifier, (controller_pk, controller, target_id) in dependencies.items():
        controller_name = (
            str(controller.get("name", controller_pk)) if controller else controller_pk
        )
        if not controller_pk:
            reason = "Managed-device group has no controller; set the group's Controller"
        elif controller and controller.get("has_redundancy_group"):
            reason = (
                f"Controller '{controller_name}': controller redundancy groups are not "
                "supported yet; set Controller device"
            )
        elif not target_id:
            reason = (
                f"Controller '{controller_name}' has no Controller device; set Controller device"
            )
        elif target_id in excluded:
            reason = (
                f"Controller '{controller_name}' device is excluded; remove it from "
                "exclude_devices to capture its managed devices"
            )
        elif target_id not in devices:
            reason = (
                f"Controller '{controller_name}' device is not selected; enable "
                "include_controllers or select its device explicitly"
            )
        elif disposition.get(target_id) != "capture":
            reason = (
                f"Controller '{controller_name}' device is not capturable; set a supported "
                "platform or model its BMC"
            )
        else:
            disposition[identifier] = "covered_by_controller"
            reasons[identifier] = (
                f"Covered by controller '{controller_name}' "
                f"(device '{devices[target_id].get('name', target_id)}')"
            )
            continue
        disposition[identifier] = "controller_not_capturable"
        reasons[identifier] = reason

    capture_ids = sorted(
        (identifier for identifier, value in disposition.items() if value == "capture"),
        key=lambda identifier: (
            identifier not in controller_device_ids,
            _sort_device(devices[identifier]),
        ),
    )
    ordered_ids = capture_ids + sorted(
        (identifier for identifier in devices if identifier not in capture_ids),
        key=lambda identifier: _sort_device(devices[identifier]),
    )
    manifest_devices = []
    for identifier in ordered_ids:
        row = devices[identifier]
        value = disposition[identifier]
        entry = {
            "pk": identifier,
            "id": identifier,
            "name": str(row.get("name", identifier)),
            "location": row.get("location"),
            "role": row.get("role"),
            "platform": row.get("platform"),
            "status": row.get("status"),
            "source": list(row["source"]),
            "disposition": value,
            "reason": reasons[identifier],
            "outcome": "not_visited" if value == "capture" else None,
            "duration_s": None,
            "files": [],
        }
        if identifier in pulled_by and "controller_of" in entry["source"]:
            entry["pulled_in_by"] = sorted(
                pulled_by[identifier], key=lambda name: (name.casefold(), name)
            )
        manifest_devices.append(entry)
        if value == "controller_not_capturable":
            warnings.append(f"{entry['name']}: {entry['reason']}")
        if identifier in explicit_ids and value == "skipped_unsupported":
            errors.append(
                f"Explicit device '{entry['name']}' cannot be captured: {entry['reason']}"
            )

    manifest_controllers = []
    for identifier in sorted(
        relevant_controllers,
        key=lambda value: (str(controller_map.get(value, {}).get("name", value)).casefold(), value),
    ):
        controller = controller_map.get(identifier, {})
        target = controller.get("device")
        target_id = _identity(target) if target else None
        covers = sorted(
            (
                str(devices[device_id].get("name", device_id))
                for device_id, dependency in dependencies.items()
                if dependency[0] == identifier and disposition[device_id] == "covered_by_controller"
            ),
            key=lambda name: (name.casefold(), name),
        )
        manifest_controllers.append(
            {
                "id": identifier,
                "name": str(controller.get("name", identifier)),
                "devices": [str(target.get("name", target_id))] if target else [],
                "covers": covers,
            }
        )

    if not capture_ids and not errors:
        errors.append(
            "Scope resolves to zero capturable devices; select a supported device or a "
            "capturable controller"
        )
    if len(capture_ids) > max_capture:
        message = (
            f"Scope resolves to {len(capture_ids)} captures, above the limit of {max_capture}; "
            "pick a Site rather than a Company, or split the run"
        )
        if dryrun:
            warnings.append(f"The real run would refuse: {message}")
        else:
            errors.append(message)
    return {
        "devices": manifest_devices,
        "controllers": manifest_controllers,
        "capture_ids": capture_ids,
        "counts": dict(Counter(disposition.values())),
        "errors": errors,
        "warnings": warnings,
    }
