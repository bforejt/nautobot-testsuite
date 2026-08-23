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

import time

from nautobot.apps.jobs import Job, ObjectVar
from nautobot.dcim.models import Device
from nautobot.extras.models import SecretsGroup

from . import constants as C
from . import creds, envelope, registry
from .context import CollectorContext
from .registry import SkipCheck
from .snapshot_job import (
    SoftTimeLimitExceeded,
    _attach_artifact,
    _device_host,
    _map_platform,
)
from .transport_restconf import RestconfClient
from .transport_ssh import SshRunner

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
    "Cisco-IOS-XE-matm-oper",
    "Cisco-IOS-XE-switch-cp-svl-oper",
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
        name = "Collector Shakedown (dev)"
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
        self.logger.info("Collector Shakedown — %s v%s", C.FRAMEWORK_NAME, C.JOB_VERSION)
        if device is None:
            raise RuntimeError("Pick a device.")
        log_extra = {"object": device}

        platform, driver = _map_platform(device)
        if platform is None:
            raise RuntimeError(
                "%s: cannot map platform (%r) to iosxe or panos — set the device "
                "platform's network_driver." % (device.name, driver)
            )
        host = _device_host(device)
        username, password = creds.resolve_credentials(
            device, "ssh" if platform == "panos" else "restconf", override_group=secrets_group
        )

        restconf = None
        ssh = None
        if platform == "iosxe":
            restconf = RestconfClient(host, username, password, logger=self.logger)
            if not restconf.ping():
                record = restconf.probe_get(C.DATA_DEVICE_SYSTEM, timeout=30)
                restconf.close()
                raise RuntimeError(
                    "%s: RESTCONF unreachable at %s (probe: %s)" % (device.name, host, record)
                )
            ssh = SshRunner("cisco_xe", host, username, password, logger=self.logger)
        else:
            ssh = SshRunner("paloalto_panos", host, username, password, logger=self.logger)
            ssh.open()

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
            device.name, platform, restconf=restconf, ssh=ssh, logger=self.logger, debug=True
        )
        needs_attention = []
        try:
            if platform == "iosxe":
                for label, probe in (
                    ("modules", _module_inventory),
                    ("rib_names", _rib_names),
                    ("fib_instances", _fib_instances),
                ):
                    try:
                        report["discovery"][label] = probe(ctx)
                    except SoftTimeLimitExceeded:
                        raise
                    except Exception as exc:  # discovery is best-effort: record, never abort
                        report["discovery"][label] = {"error": str(exc)}
                modules = report["discovery"].get("modules")
                if isinstance(modules, dict) and modules:
                    report["discovery"]["key_models"] = {
                        model: modules.get(model) for model in IOSXE_KEY_MODELS
                    }

            for check in checks:
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
