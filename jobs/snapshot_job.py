"""Capture Snapshot job — read-only per-device operational snapshots.

This module (with compare_job and creds) is the only place allowed to import
Nautobot and the device transports. Check collectors never see either: each
device gets a CollectorContext wired to the right transport, and everything a
check learns lands in a versioned envelope attached to the JobResult as JSON
artifacts (one snapshot envelope plus one raw evidence bundle per device).

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

from . import constants as C
from . import creds, envelope, registry
from .context import CollectorContext
from .panos_xml import PanosParseError
from .registry import CollectError, SkipCheck
from .transport_restconf import RestconfClient, RestconfError, probe_hint
from .transport_ssh import SshCommandRefused, SshRunner

# Jobs-UI grouping header (house convention).
name = C.UI_GROUP

KINDS = (("pre", "pre"), ("post", "post"), ("rollback", "rollback"), ("adhoc", "adhoc"))


def _map_platform(device):
    """Map a Device to ("iosxe"|"panos"|None, driver_string).

    Uses platform.network_driver, falling back to slug/name (older records),
    lowercased. None platform means the device cannot be snapshotted.
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
    if "cisco" in driver:
        return "iosxe", driver
    return None, driver


def _device_host(device):
    """Primary IP when assigned, else the device name (DNS-resolvable by convention)."""
    primary_ip = getattr(device, "primary_ip", None)
    if primary_ip is not None and getattr(primary_ip, "address", None) is not None:
        return str(primary_ip.address.ip)
    return device.name


def _parse_override_checks(raw):
    """None when blank; else the validated id list. Unknown ids abort the whole run."""
    ids = [token.strip() for token in str(raw or "").split(",") if token.strip()]
    if not ids:
        return None
    unknown = sorted(set(ids) - set(registry.CHECKS))
    if unknown:
        raise RuntimeError(
            "Unknown check id(s) in override_checks: %s. Valid ids: %s"
            % (", ".join(unknown), ", ".join(sorted(registry.CHECKS)))
        )
    return ids


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
    override_checks = StringVar(
        required=False,
        description="Comma-separated check ids replacing the package selection.",
    )
    secrets_group = ObjectVar(
        model=SecretsGroup,
        required=False,
        description=(
            "Per-run credential override — the per-job secret. Falls back to each "
            "device's own Secrets Group when left empty."
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
            "Attach a `debug_*.json` transport trace per device: every RESTCONF "
            "path and SSH command with timing, outcome, and the FULL payload — "
            "so a failed check keeps its evidence. Payload-heavy; use on one or "
            "two devices at a time, not a fleet."
        ),
    )

    class Meta:
        name = "Capture Snapshot"
        description = (
            "Collects a read-only operational snapshot from each selected device and "
            "attaches it to this JobResult as one `snapshot_*.json` envelope plus one "
            "`raw_*.json` evidence bundle per device. The device platform picks the "
            "transport (RESTCONF for IOS-XE, SSH for PAN-OS — both structurally "
            "read-only), every check the platform supports runs by doctrine — features "
            "not in use record loudly as not-present — and each records a normalized "
            "view alongside its raw evidence. Run once as `pre` before the change and "
            "once as `post` after "
            "it, with the same change id, then feed both JobResults to *Compare "
            "Snapshots*. A device with any failed check marks the run FAILED (a bad "
            "baseline must be loud) but its envelope is still attached."
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
            "override_checks",
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
        override_checks="",
        secrets_group=None,
        dryrun=False,
        debug=False,
    ):
        """Snapshot every selected device. Every kwarg defaults (ScheduledJob rule)."""
        self.logger.info("Capture Snapshot starting — %s v%s", C.FRAMEWORK_NAME, C.JOB_VERSION)
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
        override_ids = _parse_override_checks(override_checks)
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
                    override_ids=override_ids,
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

    def _capture_device(
        self,
        device,
        *,
        change_id,
        kind,
        package,
        override_ids,
        secrets_group,
        dryrun,
        debug=False,
        change_description="",
    ):
        """Snapshot one device end to end; returns True when it counts as succeeded."""
        log_extra = {"object": device}
        started_device = time.monotonic()

        platform, driver = _map_platform(device)
        if platform is None:
            self.logger.error(
                "%s: cannot map platform (network_driver/slug/name gave %r) to iosxe "
                "or panos — set the device platform's network_driver to a cisco or "
                "panos/paloalto value.",
                device.name,
                driver,
                extra=log_extra,
            )
            return False
        host = _device_host(device)

        try:
            username, password = creds.resolve_credentials(
                device,
                "ssh" if platform == "panos" else "restconf",
                override_group=secrets_group,
            )
        except creds.CredentialsError as exc:
            self.logger.error("%s: %s", device.name, exc, extra=log_extra)
            return False

        restconf = None
        ssh = None
        if platform == "iosxe":
            restconf = RestconfClient(host, username, password, logger=self.logger)
            if not restconf.ping():
                # Re-probe for the evidence record: HTTP 401/403 vs pure
                # connectivity failures live in it, so the operator hint is concrete.
                record = restconf.probe_get(C.DATA_DEVICE_SYSTEM, timeout=30)
                restconf.close()
                self.logger.error(
                    "%s: RESTCONF unreachable at %s:%s — %s (probe: %s)",
                    device.name,
                    host,
                    C.RESTCONF_PORT,
                    probe_hint(record),
                    record,
                    extra=log_extra,
                )
                return False
            # Unopened on purpose: only the SSH-based rollup check pays the
            # connect cost, with the same credentials.
            ssh = SshRunner("cisco_xe", host, username, password, logger=self.logger)
        else:
            ssh = SshRunner("paloalto_panos", host, username, password, logger=self.logger)
            try:
                ssh.open()
            except Exception as exc:
                self.logger.error(
                    "%s: SSH connect to %s failed: %s: %s",
                    device.name,
                    host,
                    type(exc).__name__,
                    exc,
                    extra=log_extra,
                )
                return False

        if override_ids is not None:
            checks = registry.checks_for(platform, override_ids)
        else:
            checks = registry.checks_for(platform)
        checks = sorted(checks, key=lambda check: (check.tier, check.id))
        check_ids = [check.id for check in checks]
        if not checks:
            # An empty selection is operator error (wrong package for the platform),
            # and an empty "baseline" would pass every later compare — fail loudly.
            self.logger.error(
                "%s: no checks in the selection apply to platform %s — fix override_checks.",
                device.name,
                platform,
                extra=log_extra,
            )
            if restconf is not None:
                restconf.close()
            if ssh is not None:
                ssh.close()
            return False

        env = envelope.new_envelope(
            device_info={
                "name": device.name,
                "id": str(device.pk),
                "platform": driver,
                "primary_ip": host,
                "role": str(getattr(device, "role", "") or ""),
                "location": str(getattr(device, "location", "") or ""),
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
        ctx = CollectorContext(
            device.name, platform, restconf=restconf, ssh=ssh, logger=self.logger, debug=debug
        )
        try:
            if dryrun:
                self.logger.info(
                    "%s: DRY-RUN ok: would run %d checks (%s)",
                    device.name,
                    len(check_ids),
                    ", ".join(check_ids),
                    extra=log_extra,
                )
                return True
            for index, check in enumerate(checks, 1):
                # Liveness: a healthy long check (the session-matrix sweep runs
                # minutes) must never leave the job log silent — the JobResult
                # page shows these lines as they are written.
                self.logger.info(
                    "%s: [%d/%d] %s ...",
                    device.name,
                    index,
                    len(checks),
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
                    )
                    raw_bundle[check.id] = outcome.get("raw")
                    self.logger.info(
                        "%s: [%d/%d] %s ok — %d normalized entr%s in %.1fs",
                        device.name,
                        index,
                        len(checks),
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
                    )
                    self.logger.error(
                        "%s: soft time limit reached during %s — attaching the "
                        "partial snapshot and stopping.",
                        device.name,
                        check.id,
                        extra=log_extra,
                    )
                    failed_checks += 1
                    soft_timeout = True
                    break
                except (CollectError, RestconfError, SshCommandRefused, PanosParseError) as exc:
                    envelope.record_check(
                        env,
                        check,
                        "failed",
                        error=str(exc),
                        duration_s=time.monotonic() - started,
                        describe=_describe_check(check),
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
        finally:
            ctx.close()

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
        if debug and ctx.trace:
            # The trace keeps evidence even for FAILED checks (collectors raise
            # before returning raw), which is exactly what debugging needs.
            _attach_artifact(
                self,
                C.DEBUG_FILENAME.format(device=safe_device, change_id=safe_change),
                {"schema": 1, "device": device.name, "trace": ctx.trace},
            )

        counts = envelope.envelope_summary(env)
        counts_text = (
            ", ".join("%s=%d" % (status, counts[status]) for status in sorted(counts))
            or "no checks"
        )
        self.logger.info(
            "%s: snapshot complete — %d check(s): %s in %.1fs",
            device.name,
            len(checks),
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
