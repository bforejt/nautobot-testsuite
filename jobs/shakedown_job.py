"""Collector Shakedown — development-only collector validation against one device.

Runs every registered check for the device's platform through a debug
CollectorContext and reports, per check, what worked, what the device answered
but the normalizer could not read (the leaf-name-mismatch signal), what is
absent, and what failed outright — with the full transport trace attached so
every verdict comes with its evidence. The trace doubles as the fixture
harvest for the CI battery: sanitize real captures before committing them.

A BMC modelled as an interface on the device (jobs/bmc_target.py) is shaken
down in the same run: its ``bmc`` family runs through a second debug context,
``discovery["bmc"]`` answers the questions a first run against a new BMC
vendor or firmware must (service root, resolved ids, OEM links, log services,
collection sizes, ``$expand`` depth, legacy versus subsystem environment
resources, the security resource's properties, the capture account's role and
privileges, and the platform log's sequence numbers before and after the run),
and every report entry names its ``target``.

This job never participates in pre/post comparison and check failures do not
fail the JobResult — finding them is its purpose. It is hidden from the
default job list (development tooling, not an operator surface).
"""

import json
import time

from nautobot.apps.jobs import Job, ObjectVar
from nautobot.dcim.models import Device
from nautobot.extras.models import SecretsGroup

from . import bmc_target, catalog, checks_bmc, creds, envelope, registry
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
from .context import CollectorContext
from .registry import SkipCheck
from .snapshot_job import (
    PLATFORM_HINT,
    PLATFORM_NAMES,
    SoftTimeLimitExceeded,
    _attach_artifact,
    _device_host,
    _find_bmc,
    _map_platform,
    _open_bmc,
)
from .transport_restconf import RestconfClient, probe_hint
from .transport_ssh import SshRunner
from .transport_vsphere import VsphereClient, VsphereError
from .transport_vsphere import probe_hint as vsphere_probe_hint

# Jobs-UI grouping header (house convention).
name = C.UI_GROUP

# The IOS-XE base model list and the catalog walk live in jobs/catalog.py (pure,
# so CI tests them); the historical names are kept here for callers.
IOSXE_KEY_MODELS = catalog.IOSXE_KEY_MODELS
PLATFORM_KEY_MODELS = catalog.PLATFORM_KEY_MODELS
_catalog_modules = catalog.catalog_modules
_catalog_key_models = catalog.catalog_key_models


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


# --- bmc discovery ---------------------------------------------------------
# The BMC probes are pure and live beside the checks they describe
# (checks_bmc.DISCOVERY_PROBES), so CI drives them without Nautobot.


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
        """Shake down one device and its modelled BMC. Every kwarg defaults (ScheduledJob rule)."""
        self.logger.info("Test Suite Shakedown — %s v%s", C.FRAMEWORK_NAME, C.JOB_VERSION)
        if device is None:
            raise RuntimeError("Pick a device.")
        log_extra = {"object": device}

        platform, driver = _map_platform(device)
        try:
            bmc, bmc_interface = _find_bmc(device)
        except bmc_target.AmbiguousBmc as exc:
            raise RuntimeError("%s: %s" % (device.name, exc)) from exc
        bmc_addressed = bmc is not None and bmc.address is not None
        if platform is None and not bmc_addressed:
            raise RuntimeError(
                "%s: cannot map platform (%r) to %s, and no BMC interface with an address is "
                "modelled on it — %s." % (device.name, driver, PLATFORM_NAMES, PLATFORM_HINT)
            )
        host = _device_host(device)

        restconf = ssh = api = None
        probe_record = None
        host_error = None
        bmc_client, bmc_error = None, None
        try:
            # The BMC first (Basic auth: no session to leave behind), so the
            # host's own login is the last step before the contexts own both.
            if bmc_addressed:
                bmc_client, bmc_error = _open_bmc(bmc, bmc_interface, device, self.logger)
                if bmc_error is not None:
                    self.logger.error("%s: %s", device.name, bmc_error, extra=log_extra)
            elif bmc is not None:
                self.logger.warning(
                    "%s: BMC interface %s has no IP address assigned — not shaken down.",
                    device.name,
                    bmc.interface_name,
                    extra=log_extra,
                )
            if platform is None:
                self.logger.warning(
                    "%s: the host platform (%r) is not supported yet — shaking down its BMC "
                    "(interface %s) alone.",
                    device.name,
                    driver,
                    bmc.interface_name,
                    extra=log_extra,
                )
            else:
                restconf, ssh, api, probe_record, host_error = self._open_host(
                    device, platform, host, secrets_group
                )
                if host_error is not None:
                    self.logger.error("%s: %s", device.name, host_error, extra=log_extra)
        except BaseException:
            for transport in (bmc_client, restconf, ssh, api):
                if transport is not None:
                    try:
                        transport.close()
                    except Exception:
                        pass
            raise
        bmc_live = bmc_client is not None and bmc_error is None
        if not bmc_live and (platform is None or host_error is not None):
            # Nothing left to shake down: say why, as the job's failure.
            raise RuntimeError(
                "%s: %s" % (device.name, "; ".join(e for e in (host_error, bmc_error) if e))
            )

        order = lambda check: (check.tier, check.id)  # noqa: E731
        families = []
        host_ctx = bmc_ctx = None
        if platform is not None and host_error is None:
            host_ctx = CollectorContext(
                device.name,
                platform,
                restconf=restconf,
                ssh=ssh,
                api=api,
                logger=self.logger,
                debug=True,
            )
            families.append(("host", host_ctx, sorted(registry.checks_for(platform), key=order)))
        if bmc_live:
            bmc_ctx = CollectorContext(
                device.name, "bmc", restconf=bmc_client, logger=self.logger, debug=True
            )
            families.append(("bmc", bmc_ctx, sorted(registry.checks_for("bmc"), key=order)))
        report = {
            "schema": 1,
            "generated_at": envelope.utcnow_iso(),
            "framework": {"name": C.FRAMEWORK_NAME, "version": C.JOB_VERSION},
            "device": {
                "name": device.name,
                "platform": driver,
                "platform_supported": platform is not None,
                "host": host,
                "bmc": bmc_target.bmc_block(
                    bmc,
                    captured=bmc_ctx is not None,
                    note=bmc_error
                    or (None if bmc is None or bmc_addressed else "no address assigned"),
                ),
            },
            "checks": {},
            "discovery": {},
        }
        total = sum(len(checks) for _target, _ctx, checks in families)
        needs_attention = []
        try:
            if platform == "vmware":
                # Answered by the SOAP probe itself: which vim25 namespace
                # versions hostd advertised (or that the fallback SOAPAction
                # was used), apiType, build/version, TLS mode.
                report["discovery"]["probe"] = probe_record
            if host_ctx is not None:
                self._discover(report["discovery"], DISCOVERY_PROBES[platform], host_ctx)
            if platform == "iosxe":
                modules = report["discovery"].get("modules")
                if isinstance(modules, dict) and modules:
                    # Each catalog module names the models its collectors read
                    # (KEY_MODELS); merged together, a switch or 9800 shakedown
                    # shows at once which collectors of every module CAN work.
                    report["discovery"]["key_models"] = {
                        model: modules.get(model) for model in _catalog_key_models(platform)
                    }
            if bmc_ctx is not None:
                # The log's sequence numbers before any other GET of this run,
                # and again (past the cache) after everything: what did the
                # run itself add to the log?
                report["discovery"]["bmc"] = {}
                self._discover(
                    report["discovery"]["bmc"],
                    (("log_sequence_before", checks_bmc._discover_log_sequence),),
                    bmc_ctx,
                )

            index = 0
            for target, ctx, checks in families:
                for check in checks:
                    index += 1
                    self.logger.info("[%d/%d] %s ...", index, total, check.id, extra=log_extra)
                    self._shake(report, needs_attention, ctx, check, target, log_extra)
            if bmc_ctx is not None:
                # After the checks, so each check met its own budget as in a
                # capture (only the id resolution and the log-service reads
                # were warmed by log_sequence_before); the probes reuse the cache.
                self._discover(report["discovery"]["bmc"], checks_bmc.DISCOVERY_PROBES, bmc_ctx)
                self._discover(
                    report["discovery"]["bmc"],
                    (
                        (
                            "log_sequence_after",
                            lambda ctx: checks_bmc._discover_log_sequence(ctx, fresh=True),
                        ),
                    ),
                    bmc_ctx,
                )
        except SoftTimeLimitExceeded:
            self.logger.error(
                "Soft time limit reached — attaching what was gathered so far.",
                extra=log_extra,
            )
        finally:
            for ctx in (host_ctx, bmc_ctx):
                if ctx is not None:
                    ctx.close()
            if bmc_client is not None and bmc_ctx is None:
                bmc_client.close()

        for transport in (restconf, api, bmc_client):
            if getattr(transport, "footprint", None) is not None:
                report.setdefault("transport", {})[transport.transport_label] = (
                    transport.footprint()
                )
        if bmc_error is not None:
            report["bmc_error"] = bmc_error
        if host_error is not None:
            report["host_error"] = host_error

        trace = (host_ctx.trace if host_ctx else []) + (bmc_ctx.trace if bmc_ctx else [])
        safe_device = envelope.safe_name(device.name)
        _attach_artifact(self, C.SHAKEDOWN_FILENAME.format(device=safe_device), report)
        _attach_artifact(
            self,
            C.SHAKEDOWN_TRACE_FILENAME.format(device=safe_device),
            {"schema": 1, "device": device.name, "trace": trace},
        )
        ok_count = sum(1 for body in report["checks"].values() if body["advice"].startswith("ok"))
        summary = "%s: %d/%d collectors ok; needs attention: %s%s" % (
            device.name,
            ok_count,
            len(report["checks"]),
            ", ".join(needs_attention) or "none",
            "; BMC unusable: %s" % (bmc_error,) if bmc_error else "",
        )
        self.logger.info("%s", summary, extra=log_extra)
        return summary

    def _open_host(self, device, platform, host, secrets_group):
        """(restconf, ssh, api, probe record, error): the host platform's transports, probed.

        ``error`` is an operator-facing sentence (every transport closed again,
        a refused vSphere client returned closed for its footprint).
        """
        try:
            username, password = creds.resolve_credentials(
                device, C.TRANSPORT_FOR[platform], override_group=secrets_group
            )
        except creds.CredentialsError as exc:
            return None, None, None, None, str(exc)
        if platform == "iosxe":
            restconf = RestconfClient(host, username, password, logger=self.logger)
            if not restconf.ping():
                record = restconf.probe_get(C.DATA_DEVICE_SYSTEM, timeout=30)
                restconf.close()
                error = "RESTCONF unreachable at %s — %s (probe: %s)" % (
                    host,
                    probe_hint(record),
                    record,
                )
                return None, None, None, None, error
            ssh = SshRunner("cisco_xe", host, username, password, logger=self.logger)
            return restconf, ssh, None, None, None
        if platform == "panos":
            ssh = SshRunner("paloalto_panos", host, username, password, logger=self.logger)
            try:
                ssh.open()
            except Exception as exc:
                error = "SSH connect to %s failed: %s: %s" % (host, type(exc).__name__, exc)
                return None, None, None, None, error
            return None, ssh, None, None, None
        if platform == "vmware":
            api = VsphereClient(host, username, password, logger=self.logger)
            try:
                probe_record = api.probe()
                api.login()
            except VsphereError as exc:
                api.close()
                error = "vSphere SOAP at %s unusable — %s (%s)" % (
                    host,
                    vsphere_probe_hint(exc),
                    exc,
                )
                return None, None, api, None, error
            return None, None, api, probe_record, None
        # unreachable: _map_platform returns three names
        return None, None, None, None, "no transport for platform %r" % (platform,)

    def _discover(self, into, probes, ctx):
        """Run discovery probes best-effort: each answer, or an error record, lands in ``into``."""
        for label, probe in probes:
            try:
                into[label] = probe(ctx)
            except SoftTimeLimitExceeded:
                raise
            except Exception as exc:  # discovery is best-effort: record, never abort
                into[label] = {"error": "%s: %s" % (type(exc).__name__, exc)}

    def _shake(self, report, needs_attention, ctx, check, target, log_extra):
        """Run one check through its family's debug context and record its verdict."""
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
        advice = registry.shakedown_advice(
            status,
            error,
            len(normalized),
            fetched,
            empty_ok=registry.EMPTY_OK_TAG in (check.tags or ()),
        )
        report["checks"][check.id] = {
            "target": target,
            "status": status,
            "error": error,
            "duration_s": round(time.monotonic() - started, 2),
            "normalized_count": len(normalized),
            "sample_keys": sorted(normalized)[:5],
            "advice": advice,
        }
        if advice.startswith("ok"):
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
