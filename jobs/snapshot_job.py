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
from nautobot.core.utils.config import get_settings_or_config
from nautobot.dcim.filters import DeviceFilterSet
from nautobot.dcim.models import Device, Location
from nautobot.extras.models import DynamicGroup, Role, SecretsGroup, Status, Tag

from . import bmc_target, bundle, creds, envelope, registry, scope
from . import constants as C
from .context import CollectorContext
from .panos_xml import PanosParseError
from .proxmox_ssh import LazySsh
from .registry import CollectError, SkipCheck
from .transport_proxmox import ProxmoxClient, ProxmoxError
from .transport_redfish import RedfishClient, RedfishError
from .transport_redfish import probe_hint as redfish_probe_hint
from .transport_restconf import RestconfClient, RestconfError, probe_hint
from .transport_ssh import SshCommandRefused, SshRunner
from .transport_vsphere import VsphereClient, VsphereError
from .transport_vsphere import probe_hint as vsphere_probe_hint

# Jobs-UI grouping header (house convention).
name = C.UI_GROUP

KINDS = (("pre", "pre"), ("post", "post"), ("rollback", "rollback"), ("adhoc", "adhoc"))


PLATFORM_NAMES = "iosxe, panos, vmware or proxmox"
PLATFORM_HINT = (
    "set the device platform's network_driver to a cisco, panos/paloalto, vmware/esxi or proxmox "
    "value; a server's BMC is captured through an interface on the host device whose name "
    "starts with %s and carries the BMC's address, never through a Device of its own"
    % ("/".join(C.BMC_INTERFACE_NAMES),)
)


def _map_platform(device):
    """Read model metadata; the pure mapper checks every field for deny words."""
    platform = getattr(device, "platform", None)
    return scope.map_platform(
        getattr(platform, "network_driver", ""),
        getattr(platform, "name", ""),
        getattr(platform, "slug", ""),
    )


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


def _filtered_devices(queryset, filters):
    """Use the same validated filter semantics as Nautobot's Devices view."""
    filterset = DeviceFilterSet(data=filters, queryset=queryset)
    if not filterset.is_valid():
        raise RuntimeError("Invalid device scope filters: %s" % filterset.errors.as_text())
    return filterset.qs.select_related(
        "platform", "location", "role", "status", "controller_managed_device_group__controller"
    )


def _scope_inventory(selected):
    """Build plain rows and controller dependencies using model reads only.

    ``selected`` contains (Device, source-list) pairs. The controller chain is
    walked once per device, including central controllers outside the anchor.
    Ambiguous BMCs remain capture candidates so collection fails loudly.
    """
    device_rows, controller_rows, devices = {}, {}, {}
    pending = list(selected)
    while pending:
        device, sources = pending.pop(0)
        identifier = str(device.pk)
        if identifier in device_rows:
            device_rows[identifier]["source"] = sorted(
                set(device_rows[identifier]["source"]) | set(sources)
            )
            continue
        devices[identifier] = device
        platform = getattr(device, "platform", None)
        try:
            bmc, _ = _find_bmc(device)
            has_bmc = bmc is not None and bmc.address is not None
        except bmc_target.AmbiguousBmc:
            has_bmc = True
        group = getattr(device, "controller_managed_device_group", None)
        controller = getattr(group, "controller", None) if group is not None else None
        device_rows[identifier] = {
            "pk": identifier,
            "name": device.name,
            "platform_driver": getattr(platform, "network_driver", ""),
            "platform_slug": getattr(platform, "slug", ""),
            "platform": str(platform or ""),
            "has_bmc": has_bmc,
            "address": _device_host(device),
            "location": str(getattr(device, "location", "") or ""),
            "role": str(getattr(device, "role", "") or ""),
            "status": str(getattr(device, "status", "") or ""),
            "source": list(sources),
            "managed_group": {
                "controller_pk": str(controller.pk) if controller is not None else None,
                "capabilities": list(getattr(group, "capabilities", None) or ()),
            }
            if group is not None
            else None,
        }
        if controller is None or str(controller.pk) in controller_rows:
            continue
        target = getattr(controller, "controller_device", None)
        controller_rows[str(controller.pk)] = {
            "pk": str(controller.pk),
            "name": controller.name,
            "capabilities": list(getattr(controller, "capabilities", None) or ()),
            "has_redundancy_group": bool(
                getattr(controller, "controller_device_redundancy_group_id", None)
            ),
            "device_id": str(target.pk) if target is not None else None,
        }
        if target is not None:
            pending.append((target, []))
    for controller in controller_rows.values():
        controller["device"] = device_rows.get(controller.pop("device_id"))
    return device_rows, list(controller_rows.values()), devices


def _describe_check(check):
    """Self-description embedded with every check entry (schema 1.1)."""
    return {
        "description": check.description,
        "semantics": registry.SEMANTICS.get(check.id, ""),
        "miss_meaning": check.miss_meaning,
    }


def _proxmox_ssh(device, host, secrets_group, logger):
    """API tokens are never reused for SSH; resolve Linux credentials lazily."""
    return LazySsh(
        lambda: creds.resolve_credentials(device, "ssh", override_group=secrets_group),
        lambda username, password: SshRunner("linux", host, username, password, logger=logger),
    )


def _create_file(job, filename, content):
    """Attach serialized evidence; an attachment failure never fails collection.

    create_file raises ValueError past the platform size cap (10MB) — an
    oversized or otherwise unattachable artifact is logged and dropped rather
    than failing the device (the collection itself already succeeded).
    """
    if not hasattr(job, "create_file"):
        job.logger.warning(
            "This Nautobot has no Job.create_file; artifact %s not attached", filename
        )
        return False
    try:
        # A soft limit can arrive just after create_file persists a download.
        # Finalization retries must not attach that same part a second time.
        if getattr(job, "_artifact_finalizing", False):
            if job.job_result.files.filter(name=filename).exists():
                return True
        job.create_file(filename, content)
        return True
    except SoftTimeLimitExceeded:
        raise
    except Exception as exc:
        job.logger.warning(
            "Failed to attach artifact %s: %s: %s", filename, type(exc).__name__, exc
        )
        return False


def _attach_artifact(job, filename, payload, *, split=False):
    """Route capture artifacts to the run sink; Shakedown still attaches directly."""
    if split:
        try:
            parts = bundle.artifact_parts(filename, payload, _artifact_max_bytes())
        except SoftTimeLimitExceeded:
            raise
        except Exception as exc:
            job.logger.warning("Cannot preserve complete artifact %s: %s", filename, exc)
            row = getattr(job, "_artifact_device", None)
            if row is not None:
                row["files"].append(
                    {"name": filename, "bytes": 0, "sha256": None, "not_attached": True}
                )
            return False
        outcomes = [
            _attach_artifact_part(job, name, body, independent=True) for name, body in parts
        ]
        return all(outcomes)
    return _attach_artifact_part(job, filename, payload)


def _attach_artifact_part(job, filename, payload, *, independent=False):
    sink = getattr(job, "_artifact_sink", None)
    if sink is None:
        try:
            content = bundle.json_bytes(payload)
        except SoftTimeLimitExceeded:
            raise
        except Exception as exc:
            job.logger.warning(
                "Failed to serialize artifact %s: %s: %s", filename, type(exc).__name__, exc
            )
            return False
        return _create_file(job, filename, content)
    row = job._artifact_device
    metadata = {"name": filename, "bytes": 0, "sha256": None}
    row["files"].append(metadata)
    try:
        sink.add(filename, payload, device=None if independent else row["id"], metadata=metadata)
    except SoftTimeLimitExceeded:
        metadata["not_attached"] = True
        raise
    except Exception as exc:
        metadata["not_attached"] = True
        job.logger.warning("Failed to stage artifact %s: %s: %s", filename, type(exc).__name__, exc)
    return not metadata.get("not_attached", False)


def _artifact_max_bytes():
    """The same configured byte limit Job.create_file enforces."""
    return int(get_settings_or_config("JOB_CREATE_FILE_MAX_SIZE", fallback=C.ARTIFACT_MAX_BYTES))


class CaptureSnapshot(Job):
    """Capture a pre/post/rollback/adhoc operational snapshot per device."""

    devices = MultiObjectVar(
        model=Device,
        required=False,
        description="Explicit devices added after scope filters, captured one at a time.",
    )
    locations = MultiObjectVar(
        model=Location,
        required=False,
        description="Devices at these locations and all descendant floors or rooms.",
    )
    dynamic_group = ObjectVar(
        model=DynamicGroup,
        required=False,
        query_params={"content_type": "dcim.device"},
        description="Add the current members of a saved Device Dynamic Group.",
    )
    roles = MultiObjectVar(
        model=Role,
        required=False,
        query_params={"content_types": "dcim.device"},
        description="Narrow location and group members to these device roles.",
    )
    statuses = MultiObjectVar(
        model=Status,
        required=False,
        query_params={"content_types": "dcim.device"},
        description="Narrow location and group members by status. Empty means Active.",
    )
    tags = MultiObjectVar(
        model=Tag,
        required=False,
        query_params={"content_types": "dcim.device"},
        description="Narrow location and group members to devices with all selected tags.",
    )
    exclude_devices = MultiObjectVar(
        model=Device,
        required=False,
        description="Remove these devices last, including pulled-in controllers.",
    )
    include_controllers = BooleanVar(
        required=False,
        default=True,
        description="Pull in the controller devices of in-scope managed devices.",
    )
    change_id = StringVar(
        description="The change or ticket ID that names the artifacts and pairs pre with post.",
    )
    change_description = StringVar(
        required=False,
        description="What the change is, in a sentence, embedded in every snapshot.",
    )
    kind = ChoiceVar(
        choices=KINDS,
        default="pre",
        description="Which side of the change this capture is.",
    )
    secrets_group = ObjectVar(
        model=SecretsGroup,
        required=False,
        description="A Secrets Group to use for the hosts instead of each device's own.",
    )
    dryrun = DryRunVar(
        description="Preview scope and model/credential readiness without device connections.",
    )
    debug = BooleanVar(
        required=False,
        default=False,
        description="Attach a full-payload transport trace per device to diagnose a failed check.",
    )
    artifact_format = ChoiceVar(
        choices=(("files", "Separate JSON files"), ("zip", "One zip file")),
        default="files",
        description="Attach each device's files separately, or all of them in one zip.",
    )

    class Meta:
        name = "Test Suite Capture"
        description = (
            "Resolves devices, sites and Dynamic Groups, then collects a read-only "
            "operational snapshot from each capturable device and "
            "attaches it to this JobResult as one `snapshot_*.json` envelope plus one "
            "`raw_*.json` evidence bundle per device, with a run manifest "
            "and optional zip download."
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
            "change_id",
            "change_description",
            "kind",
            "locations",
            "dynamic_group",
            "devices",
            "roles",
            "statuses",
            "tags",
            "exclude_devices",
            "include_controllers",
            "secrets_group",
            "artifact_format",
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
        artifact_format="files",
        locations=None,
        dynamic_group=None,
        roles=None,
        statuses=None,
        tags=None,
        exclude_devices=None,
        include_controllers=True,
    ):
        """Resolve modelled scope, then capture. Every kwarg defaults for schedules."""
        self.logger.info("Test Suite Capture starting — %s v%s", C.FRAMEWORK_NAME, C.JOB_VERSION)
        explicit_devices = list(devices) if devices is not None else []
        locations = list(locations) if locations is not None else []
        roles = list(roles) if roles is not None else []
        statuses = list(statuses) if statuses is not None else []
        tags = list(tags) if tags is not None else []
        exclude_devices = list(exclude_devices) if exclude_devices is not None else []
        change_id = str(change_id or "").strip()
        if not change_id:
            raise RuntimeError(
                "change_id is required — it names the artifacts and pairs pre with post."
            )
        if kind not in dict(KINDS):
            raise RuntimeError("kind must be one of: %s" % (", ".join(dict(KINDS)),))
        if artifact_format not in ("files", "zip"):
            raise RuntimeError("artifact_format must be one of: files, zip")
        if package not in ("", "full", None):
            # Retired input, kept in the signature so stored ScheduledJob
            # kwargs replay cleanly. Capture is always-everything by doctrine.
            self.logger.info(
                "package %r is retired — capturing every check the platform "
                "supports (subset at analysis time instead).",
                package,
            )

        filters = {
            "status": [str(status.pk) for status in statuses]
            if statuses
            else list(C.SCOPE_DEFAULT_STATUSES),
        }
        if not statuses:
            self.logger.info(
                "Scope statuses left empty — using %s for location and group members; "
                "explicit devices are added without these filters.",
                ", ".join(C.SCOPE_DEFAULT_STATUSES),
            )
        if roles:
            filters["role"] = [str(role.pk) for role in roles]
        if tags:
            filters["tags"] = [str(tag.pk) for tag in tags]
        selected = []
        if locations:
            location_filters = {**filters, "location": [str(location.pk) for location in locations]}
            selected.extend(
                (device, ["location"])
                for device in _filtered_devices(Device.objects.all(), location_filters)
            )
        if dynamic_group is not None:
            if dynamic_group.content_type.model_class() is not Device:
                raise RuntimeError("dynamic_group must contain Devices.")
            # Public membership is shared with the Members tab. Refresh a
            # Dynamic Group outside this read-only job when its cache is stale.
            selected.extend(
                (device, ["dynamic_group"])
                for device in _filtered_devices(dynamic_group.members, filters)
            )
        selected.extend((device, ["explicit"]) for device in explicit_devices)
        selected.extend((device, ["exclude_devices"]) for device in exclude_devices)
        rows, controllers, devices_by_id = _scope_inventory(selected)
        resolution = scope.resolve(
            [row for row in rows.values() if {"location", "dynamic_group"} & set(row["source"])],
            controllers,
            locations=[location.name for location in locations],
            dynamic_group=dynamic_group.name if dynamic_group is not None else None,
            explicit_devices=[rows[str(device.pk)] for device in explicit_devices],
            exclude_devices=[rows[str(device.pk)] for device in exclude_devices],
            roles=[role.name for role in roles],
            statuses=[status.name for status in statuses] or list(C.SCOPE_DEFAULT_STATUSES),
            tags=[tag.name for tag in tags],
            include_controllers=include_controllers,
            dryrun=dryrun,
        )
        device_list = [devices_by_id[identifier] for identifier in resolution["capture_ids"]]
        try:
            bundle.validate_device_names(device.name for device in device_list)
        except ValueError as exc:
            resolution["errors"].append(
                "%s — capture them in separate runs or use distinct names." % exc
            )
        manifest_devices = resolution["devices"]
        for row in manifest_devices:
            row.pop("pk", None)
            if dryrun:
                row["outcome"] = None
        manifest_by_id = {row["id"]: row for row in manifest_devices}

        manifest = {
            "schema": 1,
            "change_id": change_id,
            "kind": kind,
            "job_result_id": str(self.job_result.pk),
            "user": str(self.user),
            "job_version": C.JOB_VERSION,
            "started": envelope.utcnow_iso(),
            "finished": None,
            # Only names and actual capture inputs; never a credential or secret value.
            "inputs": {
                "locations": [location.name for location in locations],
                "dynamic_group": dynamic_group.name if dynamic_group is not None else None,
                "devices": [device.name for device in explicit_devices],
                "roles": [role.name for role in roles],
                "statuses": [status.name for status in statuses] or list(C.SCOPE_DEFAULT_STATUSES),
                "tags": [tag.name for tag in tags],
                "exclude_devices": [device.name for device in exclude_devices],
                "include_controllers": bool(include_controllers),
                "artifact_format": artifact_format,
                "debug": bool(debug),
                "dryrun": bool(dryrun),
            },
            "devices": manifest_devices,
            "controllers": resolution["controllers"],
        }
        attach = lambda filename, content: _create_file(self, filename, content)  # noqa: E731
        if artifact_format == "zip":
            self._artifact_sink = bundle.ZipSink(
                attach,
                kind=kind,
                filename=C.ZIP_FILENAME.format(
                    change_id=envelope.safe_name(change_id),
                    kind=kind,
                    timestamp=manifest["started"][:16].replace("-", "").replace(":", "") + "Z",
                ),
                max_bytes=_artifact_max_bytes(),
                warn=self.logger.warning,
            )
        else:
            self._artifact_sink = bundle.FileSink(attach, warn=self.logger.warning)
        succeeded, failed = [], []
        try:
            self._log_scope(resolution, devices_by_id)
            if resolution["errors"]:
                raise RuntimeError(
                    "Scope refused before device I/O: %s" % "; ".join(resolution["errors"])
                )
            if dryrun:
                for device in device_list:
                    ok = self._preview_device(device, secrets_group)
                    (succeeded if ok else failed).append(device.name)
                if failed:
                    raise RuntimeError(
                        "Scope preview: %d device(s) need readiness fixes: %s; "
                        "no device connections made." % (len(failed), ", ".join(failed))
                    )
                return (
                    "Scope preview: %d capture, %d covered, %d skipped, %d excluded; "
                    "no device connections made."
                ) % (
                    len(device_list),
                    resolution["counts"].get("covered_by_controller", 0),
                    self._scope_skipped(resolution),
                    resolution["counts"].get("excluded", 0),
                )
            for index, device in enumerate(device_list):
                self._artifact_device = manifest_by_id[str(device.pk)]
                started_device = time.monotonic()
                ok = False
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
                    # Finalize the partial run instead of spending the soft/hard gap on fresh I/O.
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
                finally:
                    self._artifact_device["outcome"] = "succeeded" if ok else "failed"
                    self._artifact_device["duration_s"] = round(
                        time.monotonic() - started_device, 3
                    )
                (succeeded if ok else failed).append(device.name)

            if failed:
                raise RuntimeError(
                    "Snapshot failed for %d of %d device(s) — failed: %s; succeeded: %s; "
                    "skipped: %d; covered: %d"
                    % (
                        len(failed),
                        len(device_list),
                        ", ".join(failed),
                        ", ".join(succeeded) or "none",
                        self._scope_skipped(resolution),
                        resolution["counts"].get("covered_by_controller", 0),
                    )
                )
            return (
                "Captured %s snapshot for %d device(s) under change %s: %s; "
                "skipped: %d; covered: %d"
            ) % (
                kind,
                len(succeeded),
                change_id,
                ", ".join(succeeded),
                self._scope_skipped(resolution),
                resolution["counts"].get("covered_by_controller", 0),
            )
        finally:
            manifest["finished"] = envelope.utcnow_iso()
            manifest_filename = C.MANIFEST_FILENAME.format(
                change_id=envelope.safe_name(change_id), kind=kind
            )
            self._artifact_finalizing = True
            finalize_timed_out = False
            try:
                for attempt in range(2):
                    try:
                        if artifact_format == "files":
                            # A signal can arrive after create_file persists a file but before
                            # add returns. Reconcile interrupted attachments before the manifest.
                            attached = set(self.job_result.files.values_list("name", flat=True))
                            for row in manifest["devices"]:
                                for item in row["files"]:
                                    if item["name"] in attached:
                                        item.pop("not_attached", None)
                        self._artifact_sink.finish(manifest_filename, manifest)
                        break
                    except SoftTimeLimitExceeded:
                        finalize_timed_out = True
                        if attempt:
                            raise
                        self.logger.warning(
                            "Soft time limit reached while packaging artifacts — "
                            "retrying finalization in the cleanup window."
                        )
                    except Exception as exc:
                        self.logger.warning(
                            "Failed to finalize capture artifacts: %s: %s",
                            type(exc).__name__,
                            exc,
                        )
                        break
            finally:
                self._artifact_sink.close()
                self._artifact_sink = None
                self._artifact_device = None
                self._artifact_finalizing = False
            if finalize_timed_out:
                raise RuntimeError(
                    "Soft time limit reached while packaging artifacts — "
                    "finalization was retried; check the downloads and warnings."
                ) from None

    @staticmethod
    def _scope_skipped(resolution):
        return sum(
            resolution["counts"].get(disposition, 0)
            for disposition in ("skipped_unsupported", "controller_not_capturable")
        )

    def _log_scope(self, resolution, devices):
        """Summarize resolution and link every non-captured inventory object."""
        counts = resolution["counts"]
        pulled = [row["name"] for row in resolution["devices"] if "controller_of" in row["source"]]
        self.logger.info(
            "%d resolved: %d capture, %d covered by controller, %d unsupported, "
            "%d controller not capturable, %d excluded; %d controller dependencies (%s).",
            len(resolution["devices"]),
            counts.get("capture", 0),
            counts.get("covered_by_controller", 0),
            counts.get("skipped_unsupported", 0),
            counts.get("controller_not_capturable", 0),
            counts.get("excluded", 0),
            len(pulled),
            ", ".join(pulled) or "none",
        )
        for row in resolution["devices"]:
            if row["disposition"] == "capture":
                continue
            log = (
                self.logger.warning
                if row["disposition"] == "controller_not_capturable"
                else self.logger.info
            )
            log(
                "%s: %s — %s",
                row["name"],
                row["disposition"],
                row["reason"],
                extra={"object": devices[row["id"]]},
            )
        for warning in resolution["warnings"]:
            self.logger.warning("Scope: %s", warning)

    def _preview_device(self, device, secrets_group):
        """Check model and credential readiness without opening a transport."""
        log_extra = {"object": device}
        platform, _ = _map_platform(device)
        try:
            bmc, interface = _find_bmc(device)
        except bmc_target.AmbiguousBmc as exc:
            self.logger.error("%s: DRY-RUN %s", device.name, exc, extra=log_extra)
            return False
        addressed = bmc is not None and bmc.address is not None
        ok = True
        host_state = "not captured"
        if platform is not None:
            try:
                creds.resolve_credentials(
                    device, C.TRANSPORT_FOR[platform], override_group=secrets_group
                )
                if platform == "proxmox":
                    ssh_user, _ = creds.resolve_credentials(
                        device, "ssh", override_group=secrets_group
                    )
                    if "!" in ssh_user:
                        raise creds.CredentialsError(
                            "Separate Linux SSH credentials are required "
                            "for Proxmox host observations"
                        )
                host_state = "credentials ready"
            except creds.CredentialsError as exc:
                ok = False
                host_state = "credentials unusable"
                self.logger.error("%s: DRY-RUN host: %s", device.name, exc, extra=log_extra)
        bmc_state = "not modelled" if bmc is None else "no address assigned"
        if addressed:
            try:
                creds.resolve_bmc_credentials(interface, device)
                bmc_state = "credentials ready"
            except creds.CredentialsError as exc:
                ok = False
                bmc_state = "credentials unusable"
                self.logger.error("%s: DRY-RUN BMC: %s", device.name, exc, extra=log_extra)
        host_checks = len(registry.checks_for(platform)) if platform is not None else 0
        bmc_checks = len(registry.checks_for("bmc")) if addressed else 0
        self.logger.info(
            "%s: DRY-RUN %s: host %s (%s), would run %d check(s); BMC %s, "
            "would run %d check(s). Reachability not checked; no device connections made.",
            device.name,
            "ready" if ok else "needs fixes",
            platform or "unsupported",
            host_state,
            host_checks,
            bmc_state,
            bmc_checks,
            extra=log_extra,
        )
        return ok

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
        elif platform == "proxmox":
            try:
                restconf = ProxmoxClient(host, username, password, logger=self.logger)
                restconf.probe()
            except ProxmoxError as exc:
                if restconf is not None:
                    restconf.close()
                return (
                    restconf,
                    None,
                    None,
                    "Proxmox API at %s:%s unusable — %s" % (host, C.PROXMOX_PORT, exc),
                )
            ssh = _proxmox_ssh(device, host, secrets_group, self.logger)
        else:  # unreachable: only recognized platform families reach here
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
            ctx._proxmox_capture = None
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
                for read in (outcome.get("context") or {}).get("unstructured_reads", []):
                    self.logger.warning(
                        "%s: unstructured read %s (%s): %s",
                        device.name,
                        read.get("source", read.get("command", "unknown")),
                        check.id,
                        read.get("gap", read.get("reason", "source object requires text")),
                        extra=log_extra,
                    )
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
                ProxmoxError,
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
            finally:
                evidence = getattr(ctx, "_proxmox_capture", None)
                if ctx.platform == "proxmox" and evidence is not None:
                    if check.id not in raw_bundle:
                        raw_bundle[check.id] = evidence.raw
                        body = env["checks"].get(check.id)
                        if body is not None:
                            body["context"] = evidence.context
                        envelope.record_unstructured_reads(env, check.id, evidence.context, target)
                        for read in evidence.context.get("unstructured_reads", []):
                            self.logger.warning(
                                "%s: unstructured read %s (%s): %s",
                                device.name,
                                read.get("source", "unknown"),
                                check.id,
                                read.get("gap", "source object requires text"),
                                extra=log_extra,
                            )
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
            split=platform == "proxmox",
        )
        if raw_bundle:
            _attach_artifact(
                self,
                C.RAW_FILENAME.format(device=safe_device, change_id=safe_change),
                raw_bundle,
                split=platform == "proxmox",
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
                split=platform == "proxmox",
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
