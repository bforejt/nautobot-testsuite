"""Capture Snapshot job — read-only per-device operational snapshots.

This module (with shakedown_job and creds) is the only place allowed to import
Nautobot and the device transports. Check collectors never see either: each
device gets a CollectorContext wired to the right transport, and everything a
check learns lands in a versioned envelope attached to the JobResult as JSON
artifacts (one snapshot envelope plus one raw evidence bundle per device).

A server's BMC is modelled as an Interface on the host Device (the first word
of its name a BMC token, an IP address assigned — jobs/bmc_target.py) and is
captured in the SAME envelope: a second CollectorContext runs the ``bmc``
family against the interface's address with the Secrets Group the
``bmc_secrets_group`` Relationship associates with it, and every entry records
``target: "host"`` or ``"bmc"``. There is no switch: a modelled BMC is always
captured, an unmodelled one never is (docs/plans/bmc-capture-handoff.md §1c).

Fail-closed doctrine: a device with any failed check fails the run — a bad
baseline must be loud — but its envelope is still attached so partial
evidence is never lost. One device's failure never stops the batch.
"""

import json
import time

try:  # celery is present in every Nautobot worker; absent only in bare dev envs
    from celery.exceptions import SoftTimeLimitExceeded
except ImportError:  # pragma: no cover

    class SoftTimeLimitExceeded(Exception):
        pass


from nautobot.apps.jobs import (
    BooleanVar,
    ChoiceVar,
    DryRunVar,
    Job,
    MultiObjectVar,
    ObjectVar,
    StringVar,
)
from nautobot.dcim.models import Device
from nautobot.extras.models import SecretsGroup

from . import bmc_target, creds, envelope, registry
from . import constants as C
from .context import CollectorContext
from .panos_xml import PanosParseError
from .registry import CollectError, SkipCheck
from .transport_redfish import RedfishClient, RedfishError
from .transport_redfish import probe_hint as redfish_probe_hint
from .transport_restconf import RestconfClient, RestconfError, probe_hint
from .transport_ssh import SshCommandRefused, SshRunner
from .transport_vsphere import VsphereClient, VsphereError
from .transport_vsphere import probe_hint as vsphere_probe_hint

# Jobs-UI grouping header (house convention).
name = C.UI_GROUP

KINDS = (("pre", "pre"), ("post", "post"), ("rollback", "rollback"), ("adhoc", "adhoc"))


PLATFORM_NAMES = "iosxe, panos or vmware"
PLATFORM_HINT = (
    "set the device platform's network_driver to a cisco, panos/paloalto or vmware/esxi "
    "value; a server's BMC is captured through an interface on the host device whose name "
    "starts with %s and carries the BMC's address, never through a Device of its own"
    % ("/".join(C.BMC_INTERFACE_NAMES),)
)


def _map_platform(device):
    """Map a Device to ("iosxe"|"panos"|"vmware"|None, driver_string).

    Uses platform.network_driver, falling back to slug/name (older records),
    lowercased. None means the host's own platform is not supported — the
    device can still be captured when a BMC is modelled on it (decision 2 of
    the BMC handoff). Order matters — panos > vmware/esxi > cisco: "PAN-OS
    VM-Series on VMware" stays panos, and the hypervisor is tested before the
    bare "cisco" substring, so "Cisco UCS ESXi" maps to vmware. BMC vendor
    tokens (xcc, redfish, lenovo) map nothing: a BMC is an interface on the
    host Device, never a platform.
    """
    platform = getattr(device, "platform", None)
    driver = ""
    if platform is not None:
        driver = (
            getattr(platform, "network_driver", None)
            or getattr(platform, "slug", None)
            or getattr(platform, "name", None)
            or ""
        )
    driver = str(driver).lower()
    if "panos" in driver or "paloalto" in driver:
        return "panos", driver
    if "vmware" in driver or "esxi" in driver:
        return "vmware", driver
    if "cisco" in driver:
        return "iosxe", driver
    return None, driver


def _find_bmc(device):
    """(BmcTarget, the Interface) for the device's modelled BMC, or (None, None).

    Walks the device's interfaces and applies the naming rule of
    ``bmc_target``; only a matching interface's addresses are read. Raises
    ``bmc_target.AmbiguousBmc`` when two interfaces match (the device must
    fail before any transport opens).
    """
    rows, by_id = [], {}
    # all_interfaces (Nautobot 2.3+) includes the interfaces of installed
    # modules; plain interfaces is the fallback for older records.
    interfaces = getattr(device, "all_interfaces", None) or device.interfaces
    for interface in interfaces.all():
        if bmc_target.match_bmc_interface(interface.name) is None:
            continue
        addresses = [str(ip.host) for ip in interface.ip_addresses.all()]
        rows.append((interface.name, addresses, interface.pk))
        by_id[interface.pk] = interface
    target = bmc_target.find_bmc(rows)
    if target is None:
        return None, None
    return target, by_id[target.interface_id]


def _open_bmc(target, interface, device, logger):
    """(RedfishClient or None, error or None) for a modelled, addressed BMC.

    Resolves the interface's credentials through the bmc_secrets_group
    Relationship and probes the service root anonymously, then the Systems
    collection with the credentials. On a failed probe the client is closed
    but returned, so its GET footprint is still recorded; the error names
    what the operator must fix (a pending first-login password change has its
    own hint, from the probe that actually failed). Any other exception (a
    credential the HTTP library cannot encode, an ORM error) becomes the error
    too, so the BMC stays fail-closed without failing the batch; the Celery
    soft time limit still propagates.
    """
    client = None
    try:
        username, password = creds.resolve_bmc_credentials(interface, device)
        client = RedfishClient(target.address, username, password, logger=logger)
        if client.ping():
            return client, None
        record = client.last_probe or client.probe_get(C.REDFISH_PROBE_SYSTEMS, timeout=30)
        client.close()
        return client, "BMC Redfish unreachable at %s:%s (interface %s) — %s (probe: %s)" % (
            target.address,
            C.REDFISH_PORT,
            target.interface_name,
            redfish_probe_hint(record),
            record,
        )
    except creds.CredentialsError as exc:
        return None, "BMC credentials: %s" % (exc,)
    except SoftTimeLimitExceeded:
        if client is not None:
            client.close()
        raise
    except Exception as exc:
        if client is not None:
            client.close()
        return client, "BMC probe failed unexpectedly: %s: %s" % (type(exc).__name__, exc)


def _bmc_vendor(env):
    """(vendor, product) the BMC's service root named, from any bmc check's context."""
    for body in env["checks"].values():
        if body.get("target") != "bmc":
            continue
        resolution = (body.get("context") or {}).get("resolution") or {}
        if resolution.get("vendor"):
            return resolution.get("vendor"), resolution.get("product")
    return None, None


def _device_host(device):
    """Primary IP when assigned, else the device name (DNS-resolvable by convention)."""
    primary_ip = getattr(device, "primary_ip", None)
    if primary_ip is not None and getattr(primary_ip, "address", None) is not None:
        return str(primary_ip.address.ip)
    return device.name


def _describe_check(check):
    """Self-description embedded with every check entry (schema 1.1)."""
    return {
        "description": check.description,
        "semantics": registry.SEMANTICS.get(check.id, ""),
        "miss_meaning": check.miss_meaning,
    }


def _attach_artifact(job, filename, payload):
    """Attach a JSON artifact to the running job's JobResult; never fatal.

    create_file raises ValueError past the platform size cap (10MB) — an
    oversized or otherwise unattachable artifact is logged and dropped rather
    than failing the device (the collection itself already succeeded).
    """
    if not hasattr(job, "create_file"):
        job.logger.warning(
            "This Nautobot has no Job.create_file; artifact %s not attached", filename
        )
        return
    try:
        job.create_file(filename, json.dumps(payload, indent=1, sort_keys=True))
    except SoftTimeLimitExceeded:
        raise
    except Exception as exc:
        job.logger.warning(
            "Failed to attach artifact %s: %s: %s", filename, type(exc).__name__, exc
        )


class CaptureSnapshot(Job):
    """Capture a pre/post/rollback/adhoc operational snapshot per device."""

    devices = MultiObjectVar(
        model=Device,
        description="Devices to snapshot; processed serially, one at a time.",
    )
    change_id = StringVar(
        description=(
            "Change/ticket identifier. Tags the attached artifacts and pairs a pre "
            "snapshot with its post snapshot in Compare Snapshots."
        ),
    )
    change_description = StringVar(
        required=False,
        description=(
            "One or two sentences describing WHAT the change is (e.g. 'Replace "
            "PA-5250 with VM-500; default route and ~24 prefixes move from VL909 "
            "to VL925'). Embedded in every snapshot so any later reader — human "
            "or LLM — knows the intent behind the capture."
        ),
    )
    kind = ChoiceVar(
        choices=KINDS,
        default="pre",
        description="Which side of the change this capture is.",
    )
    secrets_group = ObjectVar(
        model=SecretsGroup,
        required=False,
        description=(
            "Per-run credential override for the host platforms — the per-job secret. "
            "Falls back to each device's own Secrets Group when left empty. A modelled "
            "BMC always uses the Secrets Group its interface's bmc_secrets_group "
            "Relationship names, never this override."
        ),
    )
    dryrun = DryRunVar(
        description=(
            "Validate platform mapping, credentials and reachability only; "
            "collect nothing and attach nothing."
        ),
    )
    debug = BooleanVar(
        required=False,
        default=False,
        description=(
            "Attach a `debug_*.json` transport trace per device: every RESTCONF/"
            "Redfish path, SSH command and SOAP operation with timing, outcome, and "
            "the FULL payload (configuration text redacted) — "
            "so a failed check keeps its evidence. Payload-heavy; use on one or "
            "two devices at a time, not a fleet."
        ),
    )

    class Meta:
        name = "Test Suite Capture"
        description = (
            "Collects a read-only operational snapshot from each selected device and "
            "attaches it to this JobResult as one `snapshot_*.json` envelope plus one "
            "`raw_*.json` evidence bundle per device. The device platform picks the "
            "transport (RESTCONF plus allowlisted read-only SSH commands for IOS-XE, SSH "
            "for PAN-OS — all structurally read-only — and a six-operation read-only SOAP "
            "allowlist for VMware ESXi); a server's BMC, modelled as an interface on the "
            "device named xcc/idrac/ilo/bmc/... with its address assigned, is captured in "
            "the same envelope over GET-only Redfish. Every check the platform supports "
            "runs by doctrine — features not in use record loudly as not-present — and "
            "each records a normalized view alongside its raw evidence. Run once as `pre` "
            "before the change and "
            "once as `post` after it, with the same change id, then download the "
            "snapshot files and analyze them with your test-plan prompt "
            "(docs/llm-test-plans.md; tools/diff_snapshots.py builds an optional "
            "deterministic diff index). A device with any failed check marks the run "
            "FAILED (a bad baseline must be loud) but its envelope is still attached."
        )
        has_sensitive_variables = False
        read_only = True
        dryrun_default = False
        # Budget: serial device loop; worst case per device is ~6 heavyweight checks
        # x BIG_GET_TIMEOUT (300s) plus SSH sweeps. 3300s soft leaves headroom to
        # record partial envelopes and attach artifacts before the 3600s hard kill.
        soft_time_limit = 3300
        time_limit = 3600
        field_order = [
            "devices",
            "change_id",
            "change_description",
            "kind",
            "secrets_group",
            "dryrun",
            "debug",
        ]

    def run(
        self,
        *,
        devices=None,
        change_id="",
        change_description="",
        kind="pre",
        package="full",
        secrets_group=None,
        dryrun=False,
        debug=False,
    ):
        """Snapshot every selected device. Every kwarg defaults (ScheduledJob rule)."""
        self.logger.info("Test Suite Capture starting — %s v%s", C.FRAMEWORK_NAME, C.JOB_VERSION)
        device_list = list(devices) if devices is not None else []
        if not device_list:
            raise RuntimeError("No devices selected — pick at least one device.")
        change_id = str(change_id or "").strip()
        if not change_id:
            raise RuntimeError(
                "change_id is required — it names the artifacts and pairs pre with post."
            )
        if kind not in dict(KINDS):
            raise RuntimeError("kind must be one of: %s" % (", ".join(dict(KINDS)),))
        if package not in ("", "full", None):
            # Retired input, kept in the signature so stored ScheduledJob
            # kwargs replay cleanly. Capture is always-everything by doctrine.
            self.logger.info(
                "package %r is retired — capturing every check the platform "
                "supports (subset at analysis time instead).",
                package,
            )

        succeeded, failed = [], []
        for index, device in enumerate(device_list):
            try:
                ok = self._capture_device(
                    device,
                    change_id=change_id,
                    change_description=str(change_description or "").strip(),
                    kind=kind,
                    package=package,
                    secrets_group=secrets_group,
                    dryrun=dryrun,
                    debug=debug,
                )
            except SoftTimeLimitExceeded:
                # The soft/hard gap exists to persist what we have — the current
                # device's partial envelope is already attached by _capture_device.
                # Moving on to another device would burn the gap on fresh I/O.
                not_visited = [dev.name for dev in device_list[index + 1 :]]
                raise RuntimeError(
                    "Soft time limit reached during %s — partial artifacts attached; "
                    "device(s) not visited: %s. Succeeded so far: %s"
                    % (
                        device.name,
                        ", ".join(not_visited) or "none",
                        ", ".join(succeeded) or "none",
                    )
                ) from None
            except Exception as exc:  # one device must never stop the batch
                self.logger.error(
                    "%s: unexpected device-level failure: %s: %s",
                    device.name,
                    type(exc).__name__,
                    exc,
                    extra={"object": device},
                )
                ok = False
            (succeeded if ok else failed).append(device.name)

        if failed:
            raise RuntimeError(
                "Snapshot failed for %d of %d device(s) — failed: %s; succeeded: %s"
                % (
                    len(failed),
                    len(device_list),
                    ", ".join(failed),
                    ", ".join(succeeded) or "none",
                )
            )
        return "Captured %s snapshot for %d device(s) under change %s: %s" % (
            kind,
            len(succeeded),
            change_id,
            ", ".join(succeeded),
        )

    def _open_host(self, device, platform, host, secrets_group):
        """(restconf, ssh, api, error): the host platform's transports, opened and probed.

        ``error`` is an operator-facing sentence when the credentials or the
        transport are unusable; every transport is closed again then (a
        refused vSphere client is returned closed, for its footprint).
        """
        try:
            username, password = creds.resolve_credentials(
                device, C.TRANSPORT_FOR[platform], override_group=secrets_group
            )
        except creds.CredentialsError as exc:
            return None, None, None, str(exc)
        restconf = ssh = api = None
        if platform == "iosxe":
            restconf = RestconfClient(host, username, password, logger=self.logger)
            if not restconf.ping():
                # Re-probe for the evidence record: HTTP 401/403 vs pure
                # connectivity failures live in it, so the operator hint is concrete.
                record = restconf.probe_get(C.DATA_DEVICE_SYSTEM, timeout=30)
                restconf.close()
                return (
                    None,
                    None,
                    None,
                    "RESTCONF unreachable at %s:%s — %s (probe: %s)"
                    % (
                        host,
                        C.RESTCONF_PORT,
                        probe_hint(record),
                        record,
                    ),
                )
            # Unopened on purpose: only the SSH-based rollup check pays the
            # connect cost, with the same credentials.
            ssh = SshRunner("cisco_xe", host, username, password, logger=self.logger)
        elif platform == "panos":
            ssh = SshRunner("paloalto_panos", host, username, password, logger=self.logger)
            try:
                ssh.open()
            except Exception as exc:
                return (
                    None,
                    None,
                    None,
                    "SSH connect to %s failed: %s: %s"
                    % (
                        host,
                        type(exc).__name__,
                        exc,
                    ),
                )
        elif platform == "vmware":
            # probe() refuses a vCenter answering; login() is the one Login of
            # this capture and fails the device early exactly like ssh.open().
            api = VsphereClient(host, username, password, logger=self.logger)
            try:
                api.probe()
                api.login()
            except VsphereError as exc:
                api.close()
                # Returned closed: its footprint (the refused Login) is evidence
                # the envelope records when a BMC keeps the device's capture going.
                return (
                    None,
                    None,
                    api,
                    "vSphere SOAP at %s%s unusable — %s (%s)"
                    % (
                        host,
                        C.VSPHERE_SDK_PATH,
                        vsphere_probe_hint(exc),
                        exc,
                    ),
                )
        else:  # unreachable: _map_platform only returns the three names above
            return None, None, None, "no transport for platform %r" % (platform,)
        return restconf, ssh, api, None

    def _record_all_failed(self, env, checks, error, target):
        """Every check of a family whose transport never opened, recorded failed with why."""
        for check in checks:
            envelope.record_check(
                env, check, "failed", error=error, describe=_describe_check(check), target=target
            )

    def _run_checks(self, device, ctx, checks, env, raw_bundle, *, target, first, total):
        """Run one family's checks through its context; returns (failed count, soft timeout)."""
        log_extra = {"object": device}
        failed_checks = 0
        for index, check in enumerate(checks, first):
            # Liveness: a healthy long check (the session-matrix sweep runs
            # minutes) must never leave the job log silent — the JobResult
            # page shows these lines as they are written.
            self.logger.info(
                "%s: [%d/%d] %s ...",
                device.name,
                index,
                total,
                check.id,
                extra=log_extra,
            )
            started = time.monotonic()
            try:
                outcome = check.collector(ctx)
                if not isinstance(outcome, dict):
                    raise CollectError(
                        "collector returned %s, expected dict" % (type(outcome).__name__,)
                    )
                envelope.record_check(
                    env,
                    check,
                    "success",
                    normalized=outcome.get("normalized"),
                    duration_s=time.monotonic() - started,
                    describe=_describe_check(check),
                    context=outcome.get("context"),
                    target=target,
                )
                raw_bundle[check.id] = outcome.get("raw")
                self.logger.info(
                    "%s: [%d/%d] %s ok — %d normalized entr%s in %.1fs",
                    device.name,
                    index,
                    total,
                    check.id,
                    len(outcome.get("normalized") or {}),
                    "y" if len(outcome.get("normalized") or {}) == 1 else "ies",
                    time.monotonic() - started,
                    extra=log_extra,
                )
            except SkipCheck as exc:
                envelope.record_check(
                    env,
                    check,
                    "not-present",
                    error=str(exc),
                    duration_s=time.monotonic() - started,
                    describe=_describe_check(check),
                    target=target,
                )
                self.logger.info(
                    "%s: %s not present: %s",
                    device.name,
                    check.id,
                    exc,
                    extra=log_extra,
                )
            except SoftTimeLimitExceeded:
                # Must outrank the blanket handler: the soft/hard gap is the
                # only budget left to attach what was collected so far.
                envelope.record_check(
                    env,
                    check,
                    "failed",
                    error="aborted: Celery soft time limit reached",
                    duration_s=time.monotonic() - started,
                    describe=_describe_check(check),
                    target=target,
                )
                self.logger.error(
                    "%s: soft time limit reached during %s — attaching the "
                    "partial snapshot and stopping.",
                    device.name,
                    check.id,
                    extra=log_extra,
                )
                return failed_checks + 1, True
            except (
                CollectError,
                RestconfError,
                RedfishError,
                VsphereError,
                SshCommandRefused,
                PanosParseError,
            ) as exc:
                envelope.record_check(
                    env,
                    check,
                    "failed",
                    error=str(exc),
                    duration_s=time.monotonic() - started,
                    describe=_describe_check(check),
                    target=target,
                )
                self.logger.warning(
                    "%s: check %s failed: %s",
                    device.name,
                    check.id,
                    exc,
                    extra=log_extra,
                )
                failed_checks += 1
            except Exception as exc:
                envelope.record_check(
                    env,
                    check,
                    "failed",
                    error="%s: %s" % (type(exc).__name__, exc),
                    duration_s=time.monotonic() - started,
                    describe=_describe_check(check),
                    target=target,
                )
                self.logger.warning(
                    "%s: check %s failed unexpectedly (%s): %s",
                    device.name,
                    check.id,
                    type(exc).__name__,
                    exc,
                    extra=log_extra,
                )
                failed_checks += 1
        return failed_checks, False

    def _capture_device(
        self,
        device,
        *,
        change_id,
        kind,
        package,
        secrets_group,
        dryrun,
        debug=False,
        change_description="",
    ):
        """Snapshot one device — its host platform and its modelled BMC — into one envelope.

        Returns True when the device counts as succeeded. The BMC cases
        (docs/plans/bmc-capture-handoff.md §1c): no interface matches -> host
        only, ``device.bmc`` null; a match without an address -> host only
        with a warning; two matches -> the device fails before any transport
        opens; credentials or reachability failing -> every bmc check failed
        with the reason (device FAILED); the host platform unsupported -> the
        BMC captured alone with a warning, ``host_captured`` false, and the
        device succeeds when its BMC checks do.
        """
        log_extra = {"object": device}
        started_device = time.monotonic()

        platform, driver = _map_platform(device)
        try:
            bmc, bmc_interface = _find_bmc(device)
        except bmc_target.AmbiguousBmc as exc:
            self.logger.error("%s: %s", device.name, exc, extra=log_extra)
            return False
        bmc_addressed = bmc is not None and bmc.address is not None
        if platform is None and not bmc_addressed:
            self.logger.error(
                "%s: cannot map platform (network_driver/slug/name gave %r) to %s, and no BMC "
                "interface with an address is modelled on it — %s.",
                device.name,
                driver,
                PLATFORM_NAMES,
                PLATFORM_HINT,
                extra=log_extra,
            )
            return False
        if platform is None:
            self.logger.warning(
                "%s: the host platform (%r) is not supported yet — capturing its BMC "
                "(interface %s) alone; device.host_captured is false in the snapshot.",
                device.name,
                driver,
                bmc.interface_name,
                extra=log_extra,
            )
        bmc_note = None
        if bmc is not None and not bmc_addressed:
            bmc_note = "no address assigned"
            self.logger.warning(
                "%s: BMC interface %s has no IP address assigned — host capture only; "
                "assign the BMC's address to the interface to capture it.",
                device.name,
                bmc.interface_name,
                extra=log_extra,
            )

        order = lambda check: (check.tier, check.id)  # noqa: E731
        host_checks = sorted(registry.checks_for(platform), key=order)
        if platform is None:
            host_checks = []
        bmc_checks = []
        if bmc_addressed:
            bmc_checks = sorted(registry.checks_for("bmc"), key=order)
        check_ids = [check.id for check in host_checks + bmc_checks]

        host = _device_host(device)
        restconf = ssh = api = None
        host_error = None
        bmc_client, bmc_error = None, None
        try:
            # The BMC first: Basic auth leaves no session on it, so the host's
            # own login (a vSphere Login is a session) is the last step before
            # the contexts own every transport.
            if bmc_checks:
                bmc_client, bmc_error = _open_bmc(bmc, bmc_interface, device, self.logger)
                if bmc_error is not None:
                    self.logger.error("%s: %s", device.name, bmc_error, extra=log_extra)
            if host_checks:
                restconf, ssh, api, host_error = self._open_host(
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
        if host_error is not None and not bmc_checks:
            return False
        # A failed host with a modelled BMC continues: the BMC's view is valid
        # whatever state the host is in, and the host checks record why they
        # have no data.
        bmc_live = bool(bmc_checks) and bmc_error is None

        env = envelope.new_envelope(
            device_info={
                "name": device.name,
                "id": str(device.pk),
                "platform": driver,
                "platform_supported": platform is not None,
                "host_captured": bool(host_checks) and host_error is None,
                "primary_ip": host,
                "role": str(getattr(device, "role", "") or ""),
                "location": str(getattr(device, "location", "") or ""),
                # captured and note are final only after the run (below)
                "bmc": bmc_target.bmc_block(bmc, captured=False, note=bmc_note),
            },
            change_id=change_id,
            change_description=change_description,
            kind=kind,
            package="full",
            check_ids=check_ids,
            job_info={
                "job_result_id": str(self.job_result.pk),
                "user": str(self.user),
            },
        )
        raw_bundle = {}
        failed_checks = 0
        soft_timeout = False
        host_ctx = None
        if host_checks and host_error is None:
            host_ctx = CollectorContext(
                device.name,
                platform,
                restconf=restconf,
                ssh=ssh,
                api=api,
                logger=self.logger,
                debug=debug,
            )
        bmc_ctx = None
        if bmc_live:
            # A second context: its own cache, budgets and trace, so nothing
            # is shared with the host's transports.
            bmc_ctx = CollectorContext(
                device.name, "bmc", restconf=bmc_client, logger=self.logger, debug=debug
            )
        total = len(host_checks) + len(bmc_checks)
        bmc_ran = False
        try:
            if dryrun:
                ok = host_error is None and bmc_error is None
                self.logger.info(
                    "%s: DRY-RUN %s: host %s, would run %d check(s) (%s); BMC %s, would run "
                    "%d check(s) (%s)",
                    device.name,
                    "ok" if ok else "FAILED",
                    "unreachable" if host_error else ("ready" if host_checks else "not captured"),
                    len(host_checks),
                    ", ".join(check.id for check in host_checks) or "none",
                    "unusable"
                    if bmc_error
                    else ("ready" if bmc_checks else (bmc_note or "not modelled")),
                    len(bmc_checks),
                    ", ".join(check.id for check in bmc_checks) or "none",
                    extra=log_extra,
                )
                return ok
            if host_error is not None:
                self._record_all_failed(env, host_checks, host_error, "host")
                failed_checks += len(host_checks)
            elif host_checks:
                failed, soft_timeout = self._run_checks(
                    device,
                    host_ctx,
                    host_checks,
                    env,
                    raw_bundle,
                    target="host",
                    first=1,
                    total=total,
                )
                failed_checks += failed
            if bmc_checks and not soft_timeout:
                if bmc_error is not None:
                    self._record_all_failed(env, bmc_checks, bmc_error, "bmc")
                    failed_checks += len(bmc_checks)
                else:
                    bmc_ran = True
                    failed, soft_timeout = self._run_checks(
                        device,
                        bmc_ctx,
                        bmc_checks,
                        env,
                        raw_bundle,
                        target="bmc",
                        first=len(host_checks) + 1,
                        total=total,
                    )
                    failed_checks += failed
        finally:
            for ctx in (host_ctx, bmc_ctx):
                if ctx is not None:
                    ctx.close()

        block = env["device"]["bmc"]
        if block is not None:
            vendor, product = _bmc_vendor(env)
            block.update(vendor=vendor, product=product, captured=bmc_ran)
            if bmc_error is not None:
                block["note"] = "credentials or reachability failed (see the bmc checks' error)"
            elif bmc_checks and not bmc_ran:
                block["note"] = "not run: the soft time limit was reached during the host checks"
        # After close(), so the vSphere logout outcome is final: the suite's own
        # footprint (account, login/logout, call and GET counts) rides in the
        # envelope for whoever audits the host's or the BMC's session log.
        for transport in (restconf, api, bmc_client):
            if getattr(transport, "footprint", None) is not None:
                envelope.record_transport(env, transport.transport_label, transport.footprint())

        safe_device = envelope.safe_name(device.name)
        safe_change = envelope.safe_name(change_id)
        _attach_artifact(
            self,
            C.SNAPSHOT_FILENAME.format(device=safe_device, change_id=safe_change),
            env,
        )
        if raw_bundle:
            _attach_artifact(
                self,
                C.RAW_FILENAME.format(device=safe_device, change_id=safe_change),
                raw_bundle,
            )
        trace = (host_ctx.trace if host_ctx else []) + (bmc_ctx.trace if bmc_ctx else [])
        if debug and trace:
            # The trace keeps evidence even for FAILED checks (collectors raise
            # before returning raw), which is exactly what debugging needs;
            # every entry names its transport (restconf/ssh/vsphere/redfish).
            _attach_artifact(
                self,
                C.DEBUG_FILENAME.format(device=safe_device, change_id=safe_change),
                {"schema": 1, "device": device.name, "trace": trace},
            )

        counts = envelope.envelope_summary(env)
        counts_text = (
            ", ".join("%s=%d" % (status, counts[status]) for status in sorted(counts))
            or "no checks"
        )
        self.logger.info(
            "%s: snapshot complete — %d check(s) (%d host, %d bmc): %s in %.1fs",
            device.name,
            total,
            len(host_checks),
            len(bmc_checks),
            counts_text,
            time.monotonic() - started_device,
            extra=log_extra,
        )
        if soft_timeout:
            # Artifacts are attached; now surface the timeout to run(), which
            # stops the batch instead of starting the next device's I/O.
            raise SoftTimeLimitExceeded()
        if failed_checks:
            # Fail-closed: a baseline with failed reads is not trustworthy, so the
            # device counts as failed — its envelope stays attached as evidence.
            self.logger.error(
                "%s: %d check(s) failed — this snapshot is not a trustworthy baseline.",
                device.name,
                failed_checks,
                extra=log_extra,
            )
            return False
        return True
