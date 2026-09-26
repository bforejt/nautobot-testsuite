"""Collector Shakedown — development-only collector validation against one device.

Runs every registered check for the device's platform through a debug
CollectorContext and reports, per check, what worked, what the device answered
but the normalizer could not read (the leaf-name-mismatch signal), what is
absent, and what failed outright — with the full transport trace attached so
every verdict comes with its evidence. The trace doubles as the fixture
harvest for the CI battery: sanitize real captures before committing them.

This job never participates in pre/post comparison and check failures do not
fail the JobResult — finding them is its purpose. It is hidden from the
default job list (development tooling, not an operator surface).
"""

import json
import time

from nautobot.apps.jobs import Job, ObjectVar
from nautobot.dcim.models import Device
from nautobot.extras.models import SecretsGroup

from . import checks_iosxe_wireless, creds, envelope, registry
from . import constants as C
from .checks_iosxe import _Q_FS_LIST_PATH, _summarize_q_filesystem
from .checks_vmware import (
    _HARDWARE_PATHS,
    _HEALTH_PATHS,
    _HOST_MOID,
    _NETWORK_PATHS,
    _OPTION_PATHS,
    _SERVICE_PATHS,
)
from .checks_xcc import (
    _FIRMWARE,
    _HOST_NICS,
    _LOG_SERVICES,
    _MANAGER,
    _MANAGER_NICS,
    _MEMORY,
    _PCIE,
    _PROCESSORS,
    _ROOT,
    _STORAGE,
    _SYSTEM,
)
from .context import CollectorContext
from .registry import SkipCheck
from .snapshot_job import (
    PLATFORM_HINT,
    PLATFORM_NAMES,
    SoftTimeLimitExceeded,
    _attach_artifact,
    _device_host,
    _map_platform,
)
from .transport_redfish import RedfishClient
from .transport_redfish import probe_hint as redfish_probe_hint
from .transport_restconf import RestconfClient, probe_hint
from .transport_ssh import SshRunner
from .transport_vsphere import VsphereClient, VsphereError
from .transport_vsphere import probe_hint as vsphere_probe_hint

# Jobs-UI grouping header (house convention).
name = C.UI_GROUP

# Models the IOS-XE catalog reads from — presence/revision is reported so a
# shakedown immediately shows which collectors CAN work on this image.
IOSXE_KEY_MODELS = (
    "ietf-routing",
    "Cisco-IOS-XE-fib-oper",
    "Cisco-IOS-XE-bgp-oper",
    "Cisco-IOS-XE-ospf-oper",
    "Cisco-IOS-XE-arp-oper",
    "Cisco-IOS-XE-cdp-oper",
    "Cisco-IOS-XE-lldp-oper",
    "Cisco-IOS-XE-interfaces-oper",
    "Cisco-IOS-XE-device-hardware-oper",
    "Cisco-IOS-XE-environment-oper",
    "Cisco-IOS-XE-platform-software-oper",
    "Cisco-IOS-XE-matm-oper",
    "Cisco-IOS-XE-switch-cp-svl-oper",
    # Read raw-only by iosxe_switch_stack; its presence here tells a 9300
    # shakedown whether a structured stack view is available to refine into.
    "Cisco-IOS-XE-stack-oper",
)


def _aslist(value):
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _module_inventory(ctx):
    """{model: revision} for the device's yang-library, plus the total count."""
    payload = ctx.get(
        "/data/ietf-yang-library:modules-state?fields=module(name;revision)", ok_404=True
    )
    modules = {}
    container = (payload or {}).get("ietf-yang-library:modules-state") or {}
    for module in _aslist(container.get("module")):
        if isinstance(module, dict) and module.get("name"):
            modules[module["name"]] = module.get("revision")
    return modules


def _rib_names(ctx):
    """{instance-name: [rib names]} — the naming the RIB collectors must not hard-code."""
    payload = ctx.get("/data/ietf-routing:routing-state?depth=4", ok_404=True)
    names = {}
    container = (payload or {}).get("ietf-routing:routing-state") or {}
    for instance in _aslist(container.get("routing-instance")):
        if not isinstance(instance, dict):
            continue
        ribs = _aslist((instance.get("ribs") or {}).get("rib"))
        names[instance.get("name")] = [rib.get("name") for rib in ribs if isinstance(rib, dict)]
    return names


def _fib_instances(ctx):
    """FIB network-instance names (the fib-ni-entry keys) with address family."""
    payload = ctx.get(
        "/data/Cisco-IOS-XE-fib-oper:fib-oper-data?fields=fib-ni-entry(instance-name;af)",
        ok_404=True,
    )
    container = (payload or {}).get("Cisco-IOS-XE-fib-oper:fib-oper-data") or {}
    return [
        {"instance": entry.get("instance-name"), "af": entry.get("af")}
        for entry in _aslist(container.get("fib-ni-entry"))
        if isinstance(entry, dict)
    ]


# The full q-filesystem read, in characters of JSON, past which its trace
# entry keeps a marker instead of the payload. The debug trace holds every
# payload, and one unbounded list (thousands of tracelog files per member,
# unverified) must never push the trace past the 10 MB artifact limit, where
# it is dropped whole — every check's payload and the dir listings with it.
Q_FILESYSTEM_TRACE_MAX_CHARS = 1000000


def _q_filesystem(ctx):
    """The FULL q-filesystem, partition-content included, summarized per location.

    iosxe_crash_files reads this model narrowed (location keys, core files,
    partition names) because partition-content lists every file on every
    partition — unbounded, so it is read here only, on one device at a time.
    Beside the member `dir crashinfo-<N>:` listings in the same trace, the
    summary settles the check's best guess: whether chassis is the stack
    member number, what core-files holds, and which partitions list crashinfo.
    payload_chars sizes the read; past Q_FILESYSTEM_TRACE_MAX_CHARS the trace
    keeps a marker in its place (trace_payload_trimmed), and the summary plus
    the check's own narrowed read, also in the trace, still answer all three.
    """
    start = len(ctx.trace)
    payload = ctx.get(_Q_FS_LIST_PATH, ok_404=True, timeout=C.BIG_GET_TIMEOUT)
    summary = _summarize_q_filesystem(payload)
    if payload is not None:
        chars = len(json.dumps(payload, default=str))
        summary["payload_chars"] = chars
        if chars > Q_FILESYSTEM_TRACE_MAX_CHARS:
            marker = (
                "trimmed: %d characters of JSON over the %d cap; its summary is "
                "discovery.q_filesystem in the shakedown report"
                % (chars, Q_FILESYSTEM_TRACE_MAX_CHARS)
            )
            for entry in ctx.trace[start:]:
                if "payload" in entry:
                    entry["payload"] = marker
            summary["trace_payload_trimmed"] = True
    return summary


# --- xcc discovery -----------------------------------------------------------
# The Redfish questions the collectors were written around (plan §8). Every
# path is the collectors' own spelling, so the per-run cache serves both.

# Collections the inventory/firmware/storage/NIC checks walk: their member
# counts with the host on AND off are what sizes the per-check GET budgets.
XCC_COLLECTIONS = (
    ("memory", _MEMORY),
    ("processors", _PROCESSORS),
    ("pcie_devices", _PCIE),
    ("host_nics", _HOST_NICS),
    ("firmware_inventory", _FIRMWARE),
    ("storage", _STORAGE),
    ("manager_nics", _MANAGER_NICS),
)


def _xcc_service_root(ctx):
    """RedfishVersion and ProtocolFeaturesSupported ($expand decides the GET budget strategy)."""
    root = ctx.get(_ROOT) or {}
    return {
        "redfish_version": root.get("RedfishVersion"),
        "protocol_features": root.get("ProtocolFeaturesSupported"),
        "vendor": root.get("Vendor"),
        "product": root.get("Product"),
    }


def _xcc_manager_links(ctx):
    """Which Oem.Lenovo resources Managers/1 links — Security is the ThinkEdge one."""
    manager = ctx.get(_MANAGER) or {}
    oem = (manager.get("Oem") or {}).get("Lenovo") or {}
    links, scalars = {}, []
    for key, value in sorted(oem.items()):
        if isinstance(value, dict) and value.get("@odata.id"):
            links[key] = value["@odata.id"]
        elif not isinstance(value, (dict, list)):
            scalars.append(key)
    return {
        "firmware_version": manager.get("FirmwareVersion"),
        "model": manager.get("Model"),
        "oem_lenovo_links": links,
        "oem_lenovo_scalars": scalars,
    }


def _xcc_log_services(ctx):
    """LogServices members under Systems/1 (PlatformLog vs StandardLog picks the log branch)."""
    services = ctx.get(_LOG_SERVICES) or {}
    return {
        "members": [
            member.get("@odata.id")
            for member in _aslist(services.get("Members"))
            if isinstance(member, dict)
        ]
    }


def _xcc_collection_counts(ctx):
    """Member count per collection with the host power state (inventory is POST-populated)."""
    system = ctx.get(_SYSTEM) or {}
    counts = {}
    for label, path in XCC_COLLECTIONS:
        payload = ctx.get(path, ok_404=True)
        if payload is None:
            counts[label] = "absent (404)"
            continue
        count = payload.get("Members@odata.count")
        counts[label] = count if isinstance(count, int) else len(_aslist(payload.get("Members")))
    return {"host_power_state": system.get("PowerState"), "collections": counts}


# --- vmware discovery --------------------------------------------------------
# The ESXi questions from plan §8 that the collectors cannot answer for
# themselves. Each probe requests a property group with the collectors' own
# kwargs, so the cache issues one RetrievePropertiesEx for both.


def _host_props(ctx, paths, **options):
    """One HostSystem property group: (props, missing paths). Unset optionals are absent."""
    result = ctx.call(
        "RetrievePropertiesEx",
        type="HostSystem",
        moids=[_HOST_MOID],
        paths=list(paths),
        **options,
    )
    for obj in (result or {}).get("objects") or []:
        if (obj.get("obj") or {}).get("moid") == _HOST_MOID:
            missing = [entry.get("path") for entry in obj.get("missing") or []]
            return obj.get("props") or {}, missing
    return {}, ["%s not in the answer" % (_HOST_MOID,)]


def _esxi_lockdown(ctx):
    """config.lockdownMode as the Read-only user reads it, plus vCenter membership."""
    props, missing = _host_props(ctx, _SERVICE_PATHS)
    services = _aslist((props.get("config.service") or {}).get("service"))
    return {
        "lockdown_mode": props.get("config.lockdownMode"),
        "management_server_ip": props.get("summary.managementServerIp"),
        "services_total": len(services),
        "missing": missing,
    }


def _esxi_network_shape(ctx):
    """PhysicalNic version leaves, live route table, proxySwitch, selectedVnic form, and
    whether each uplink hears a CDP/LLDP far port (QueryNetworkHint connectedSwitchPort)."""
    props, missing = _host_props(ctx, _NETWORK_PATHS)
    network = props.get("config.network") or {}
    pnics = [pnic for pnic in _aslist(network.get("pnic")) if isinstance(pnic, dict)]
    manager = props.get("config.virtualNicManagerInfo") or {}
    selected = []
    for net_config in _aslist(manager.get("netConfig")):
        if isinstance(net_config, dict):
            selected.extend(_aslist(net_config.get("selectedVnic")))
    report = {
        "pnics": {
            pnic.get("device"): {
                "driver": pnic.get("driver"),
                "driver_version_present": "driverVersion" in pnic,
                "firmware_version_present": "firmwareVersion" in pnic,
            }
            for pnic in pnics
        },
        "vswitches": len(_aslist(network.get("vswitch"))),
        "portgroups": len(_aslist(network.get("portgroup"))),
        "proxy_switches": len(_aslist(network.get("proxySwitch"))),
        "route_table_info_present": isinstance(network.get("routeTableInfo"), dict),
        "selected_vnics": selected,
        "network_system": (props.get("configManager.networkSystem") or {}).get("moid"),
        "missing": missing,
    }
    if report["network_system"]:
        # <device> omitted, exactly as the neighbor/vlan collectors ask.
        hints = ctx.call("QueryNetworkHint", network_system=report["network_system"])
        report["hints"] = {
            hint.get("device"): {
                "connected_switch_port": isinstance(hint.get("connectedSwitchPort"), dict),
                "lldp_info": isinstance(hint.get("lldpInfo"), dict),
                "subnets": len(_aslist(hint.get("subnet"))),
                "networks": len(_aslist(hint.get("network"))),
            }
            for hint in _aslist(hints)
            if isinstance(hint, dict)
        }
    return report


def _esxi_health_runtime(ctx):
    """Whether runtime.healthSystemRuntime is populated with wbem off, and which half."""
    props, missing = _host_props(ctx, _HEALTH_PATHS)
    runtime = props.get("runtime.healthSystemRuntime") or {}
    sensors = _aslist((runtime.get("systemHealthInfo") or {}).get("numericSensorInfo"))
    status = runtime.get("hardwareStatusInfo") or {}
    halves = {
        half: len(_aslist(status.get(half)))
        for half in ("cpuStatusInfo", "memoryStatusInfo", "storageStatusInfo")
    }
    return {
        "numeric_sensors": len(sensors),
        "hardware_status": halves,
        "populated": bool(sensors) or any(halves.values()),
        "missing": missing,
    }


def _esxi_hardware_shape(ctx):
    """HostPciDevice id form and whether pciPassthruInfo has a row per device or per capable one."""
    props, missing = _host_props(ctx, _HARDWARE_PATHS)
    pci = [
        device for device in _aslist(props.get("hardware.pciDevice")) if isinstance(device, dict)
    ]
    return {
        "pci_devices": len(pci),
        "pci_id_sample": pci[0].get("id") if pci else None,
        "passthru_rows": len(_aslist(props.get("config.pciPassthruInfo"))),
        "missing": missing,
    }


def _esxi_option_size(ctx):
    """config.option: OptionValue count and JSON size — what the raw cap is up against."""
    props, missing = _host_props(ctx, _OPTION_PATHS, timeout=C.VSPHERE_BIG_CALL_TIMEOUT)
    options = _aslist(props.get("config.option"))
    return {
        "options_total": len(options),
        "json_chars": len(json.dumps(options, default=str)),
        "missing": missing,
    }


# Discovery probes per platform, run best-effort before the checks; each
# answer lands under report["discovery"][label] (an error record on failure).
DISCOVERY_PROBES = {
    "iosxe": (
        ("modules", _module_inventory),
        ("rib_names", _rib_names),
        ("fib_instances", _fib_instances),
        ("q_filesystem", _q_filesystem),
    ),
    "panos": (),
    "xcc": (
        ("service_root", _xcc_service_root),
        ("manager", _xcc_manager_links),
        ("log_services", _xcc_log_services),
        ("collections", _xcc_collection_counts),
    ),
    "vmware": (
        ("lockdown", _esxi_lockdown),
        ("network", _esxi_network_shape),
        ("health_runtime", _esxi_health_runtime),
        ("hardware", _esxi_hardware_shape),
        ("option_size", _esxi_option_size),
    ),
}


class CollectorShakedown(Job):
    """Run every collector against one device and report what needs tweaking."""

    device = ObjectVar(
        model=Device,
        description="One device to shake the collectors down against.",
    )
    secrets_group = ObjectVar(
        model=SecretsGroup,
        required=False,
        description="Per-run credential override; falls back to the device's Secrets Group.",
    )

    class Meta:
        name = "Test Suite Shakedown (dev)"
        description = (
            "Development tool: runs every registered check for this device's "
            "platform in debug mode and attaches `shakedown_*.json` (per-check "
            "verdicts with advisories, module inventory, discovered naming) plus "
            "`shakedown-trace_*.json` (every transport interaction WITH full "
            "payloads — the fixture harvest; sanitize before committing). Check "
            "failures do not fail the JobResult: surfacing them is the point."
        )
        has_sensitive_variables = False
        read_only = True
        hidden = True
        # Budget: one device, every check serially, debug payload capture.
        soft_time_limit = 1500
        time_limit = 1800
        field_order = ["device", "secrets_group"]

    def run(self, *, device=None, secrets_group=None):
        """Shake down one device. Every kwarg defaults (ScheduledJob rule)."""
        self.logger.info("Test Suite Shakedown — %s v%s", C.FRAMEWORK_NAME, C.JOB_VERSION)
        if device is None:
            raise RuntimeError("Pick a device.")
        log_extra = {"object": device}

        platform, driver = _map_platform(device)
        if platform is None:
            raise RuntimeError(
                "%s: cannot map platform (%r) to %s — %s."
                % (device.name, driver, PLATFORM_NAMES, PLATFORM_HINT)
            )
        host = _device_host(device)
        username, password = creds.resolve_credentials(
            device, C.TRANSPORT_FOR[platform], override_group=secrets_group
        )

        restconf = None
        ssh = None
        api = None
        probe_record = None
        if platform == "iosxe":
            restconf = RestconfClient(host, username, password, logger=self.logger)
            if not restconf.ping():
                record = restconf.probe_get(C.DATA_DEVICE_SYSTEM, timeout=30)
                restconf.close()
                raise RuntimeError(
                    "%s: RESTCONF unreachable at %s — %s (probe: %s)"
                    % (device.name, host, probe_hint(record), record)
                )
            ssh = SshRunner("cisco_xe", host, username, password, logger=self.logger)
        elif platform == "panos":
            ssh = SshRunner("paloalto_panos", host, username, password, logger=self.logger)
            ssh.open()
        elif platform == "xcc":
            if not C.XCC_ENABLED:
                raise RuntimeError(
                    "%s: the xcc platform is disabled (constants.XCC_ENABLED is False — "
                    "the XCCs are unreachable at the current sites)." % (device.name,)
                )
            restconf = RedfishClient(host, username, password, logger=self.logger)
            if not restconf.ping():
                record = restconf.probe_get(C.REDFISH_PROBE_SYSTEM, timeout=30)
                restconf.close()
                raise RuntimeError(
                    "%s: Redfish unreachable at %s — %s (probe: %s)"
                    % (device.name, host, redfish_probe_hint(record), record)
                )
        elif platform == "vmware":
            api = VsphereClient(host, username, password, logger=self.logger)
            try:
                probe_record = api.probe()
                api.login()
            except VsphereError as exc:
                api.close()
                raise RuntimeError(
                    "%s: vSphere SOAP at %s unusable — %s (%s)"
                    % (device.name, host, vsphere_probe_hint(exc), exc)
                ) from exc
        else:  # unreachable: _map_platform only returns the four names above
            raise RuntimeError("%s: no transport for platform %r" % (device.name, platform))

        checks = registry.checks_for(platform)
        checks = sorted(checks, key=lambda check: (check.tier, check.id))
        report = {
            "schema": 1,
            "generated_at": envelope.utcnow_iso(),
            "framework": {"name": C.FRAMEWORK_NAME, "version": C.JOB_VERSION},
            "device": {"name": device.name, "platform": driver, "host": host},
            "checks": {},
            "discovery": {},
        }
        ctx = CollectorContext(
            device.name,
            platform,
            restconf=restconf,
            ssh=ssh,
            api=api,
            logger=self.logger,
            debug=True,
        )
        needs_attention = []
        try:
            if platform == "vmware":
                # Answered by the SOAP probe itself: which vim25 namespace
                # versions hostd advertised (or that the fallback SOAPAction
                # was used), apiType, build/version, TLS mode.
                report["discovery"]["probe"] = probe_record
            for label, probe in DISCOVERY_PROBES[platform]:
                try:
                    report["discovery"][label] = probe(ctx)
                except SoftTimeLimitExceeded:
                    raise
                except Exception as exc:  # discovery is best-effort: record, never abort
                    report["discovery"][label] = {"error": str(exc)}
            if platform == "iosxe":
                modules = report["discovery"].get("modules")
                if isinstance(modules, dict) and modules:
                    # Each catalog module names the models its collectors read;
                    # the wireless list rides beside the switch list so a 9800
                    # shakedown shows at once which wireless collectors CAN work.
                    key_models = IOSXE_KEY_MODELS + checks_iosxe_wireless.KEY_MODELS
                    report["discovery"]["key_models"] = {
                        model: modules.get(model) for model in key_models
                    }

            for index, check in enumerate(checks, 1):
                self.logger.info("[%d/%d] %s ...", index, len(checks), check.id, extra=log_extra)
                trace_start = len(ctx.trace)
                started = time.monotonic()
                status, error, normalized = "ok", None, {}
                try:
                    outcome = check.collector(ctx)
                    normalized = (outcome or {}).get("normalized") or {}
                except SkipCheck as exc:
                    status, error = "not-present", str(exc)
                except SoftTimeLimitExceeded:
                    raise
                except Exception as exc:
                    status, error = "failed", "%s: %s" % (type(exc).__name__, exc)
                fetched = any(
                    entry.get("outcome") in ("ok", "cache-hit") for entry in ctx.trace[trace_start:]
                )
                advice = registry.shakedown_advice(status, error, len(normalized), fetched)
                report["checks"][check.id] = {
                    "status": status,
                    "error": error,
                    "duration_s": round(time.monotonic() - started, 2),
                    "normalized_count": len(normalized),
                    "sample_keys": sorted(normalized)[:5],
                    "advice": advice,
                }
                if advice == "ok":
                    self.logger.info(
                        "%s: %d normalized entries in %.1fs — ok",
                        check.id,
                        len(normalized),
                        time.monotonic() - started,
                        extra=log_extra,
                    )
                else:
                    needs_attention.append(check.id)
                    self.logger.warning("%s: %s", check.id, advice, extra=log_extra)
        except SoftTimeLimitExceeded:
            self.logger.error(
                "Soft time limit reached — attaching what was gathered so far.",
                extra=log_extra,
            )
        finally:
            ctx.close()

        for transport in (restconf, api):
            if getattr(transport, "footprint", None) is not None:
                report.setdefault("transport", {})[transport.transport_label] = (
                    transport.footprint()
                )

        safe_device = envelope.safe_name(device.name)
        _attach_artifact(self, C.SHAKEDOWN_FILENAME.format(device=safe_device), report)
        _attach_artifact(
            self,
            C.SHAKEDOWN_TRACE_FILENAME.format(device=safe_device),
            {"schema": 1, "device": device.name, "trace": ctx.trace},
        )
        ok_count = sum(1 for body in report["checks"].values() if body["advice"] == "ok")
        summary = "%s: %d/%d collectors ok; needs attention: %s" % (
            device.name,
            ok_count,
            len(report["checks"]),
            ", ".join(needs_attention) or "none",
        )
        self.logger.info("%s", summary, extra=log_extra)
        return summary
