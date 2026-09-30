#!/usr/bin/env python3
"""Harvest every payload the check catalog reads from one live device, read-only.

Runs every registered check for a platform through a real ``CollectorContext``
(``debug=True``, so the transport trace keeps each payload), then the extra
read-only GETs and ``show`` commands a fixture set wants beyond what the checks
request, and saves every payload and command output under ``OUT/TAG/`` with a
manifest. Everything saved is UNSANITIZED: keep the output directory outside
the repository and turn it into fixtures with ``tools/make_fixtures.py``.

Usage (from the repository root; the login comes from the environment, never
from the command line, and is never printed or written):

    set -a; . /path/to/device.env; set +a
    python3 tools/harvest_live.py --host 192.0.2.10 --platform iosxe --tag baseline \\
        --out /path/outside/the/repo \\
        [--interface TenGigabitEthernet1/0/48 ...] [--device-name sw-lab-1] \\
        [--user-env HARVEST_USER] [--password-env HARVEST_PASSWORD]

    set -a; . /path/to/bmc.env; set +a
    python3 tools/harvest_live.py --host-env host --platform bmc --tag baseline \\
        --out /path/outside/the/repo --user-env username --password-env password

``--platform bmc`` harvests a server's BMC over Redfish (GET only, fenced,
paced, Basic auth — the worker's own RedfishClient): every ``bmc_*`` check,
then the reads a fixture set wants beyond them — every collection the family
walks with and without ``$expand``, the pending BIOS settings object, the
registries collection, every OEM link under the System, Manager, Chassis and
NetworkProtocol, and the resources the next checks read (sensors, boot
settings, virtual media, controls, watchdogs, PCIe slots, network-adapter
ports and functions, accounts and roles, event service and subscriptions,
certificates, licences, tasks and jobs). Each read passes the family's own
redactor, so secrets, people's names and logged-in users never reach the
harvest (local account names are kept: they are configuration). ``--host-env``
names an environment variable holding the address instead of ``--host``, so
the address never appears on a command line either.

``--user-env`` / ``--password-env`` name the environment variables that hold
the login (defaults ``HARVEST_USER`` and ``HARVEST_PASSWORD``); an env file
that exports ``user`` and ``pass`` is used with ``--user-env user
--password-env pass``. ``--interface`` (repeatable, long interface names) adds
one unfiltered model read and one ``show interfaces`` per port, for the full
leaf set of a port of interest (a trunk, an access point's port, an SVI).

The tool runs outside the worker and outside the test battery, so it imports
the transports (requests, netmiko) lazily; the checks themselves are loaded
through a synthetic ``jobs`` package exactly as the test loader does, so
Nautobot is not needed. Nothing here writes to the device: the checks are
collectors, the extra reads are GETs and ``show`` commands through the same
allowlisted transports the worker uses.

Output files: ``get__<path>.json`` per RESTCONF read (a ``__f<hash>`` suffix
distinguishes filtered reads of one path), ``ssh__<command>.txt`` per command,
``results.json`` (per check: status, normalized, context, raw), ``trace.json``
(the full transport trace) and ``manifest.json`` (per request: file, bytes,
outcome, elapsed; per check: status, key counts, requests issued). The exit
status is 1 when any check FAILED (an exception other than a not-present
skip); every payload is still saved.
"""

import argparse
import hashlib
import importlib
import json
import logging
import os
import pathlib
import re
import sys
import time
import types

ROOT = pathlib.Path(__file__).resolve().parents[1]

# Per platform: the netmiko device type, the extra read-only reads a fixture
# set wants beyond what the checks request (whole containers beside the
# checks' filtered reads, models a check may not read yet), and the show
# commands whose layouts the parsers are pinned against. Paths carry no
# site identity; the interface reads come from --interface.
_INSTALL_FIELDS = (
    "fru;slot;bay;chassis;install-version-info(version;is-default;current;commit-type);"
    "oper-state(auto-abort-timer;boot-mode)"
)
_IDENTITY_FIELDS = "mac;intf-name;method-id;domain;state;authorized;vlan-id;policy-name"
PLATFORMS = {
    "iosxe": {
        "device_type": "cisco_xe",
        # (label, path, kwargs)
        "gets": [
            (
                "install-location-information (filtered)",
                "/data/Cisco-IOS-XE-install-oper:install-oper-data/install-location-information"
                "?fields=" + _INSTALL_FIELDS,
                {"ok_404": True},
            ),
            ("install-oper-data (whole)", "/data/Cisco-IOS-XE-install-oper:install-oper-data", {}),
            (
                "session-context-data (filtered only: the unfiltered list may carry names)",
                "/data/Cisco-IOS-XE-identity-oper:identity-oper-data/session-context-data"
                "?fields=" + _IDENTITY_FIELDS,
                {},
            ),
            ("hsrp-oper", "/data/Cisco-IOS-XE-hsrp-oper:hsrp-oper-data", {}),
            ("vrrp-oper", "/data/Cisco-IOS-XE-vrrp-oper:vrrp-oper-data", {}),
            ("eigrp-oper", "/data/Cisco-IOS-XE-eigrp-oper:eigrp-oper-data", {}),
            ("isis-oper", "/data/Cisco-IOS-XE-isis-oper:isis-oper-data", {}),
            ("bgp-oper", "/data/Cisco-IOS-XE-bgp-oper:bgp-state-data", {}),
            ("ospf-oper", "/data/Cisco-IOS-XE-ospf-oper:ospf-oper-data", {}),
            ("lacp-oper", "/data/Cisco-IOS-XE-lacp-oper:lag-oper-data", {}),
            ("ntp-oper", "/data/Cisco-IOS-XE-ntp-oper:ntp-oper-data", {}),
            ("crypto-pki-oper", "/data/Cisco-IOS-XE-crypto-pki-oper:crypto-pki-oper-data", {}),
            ("tcam-oper", "/data/Cisco-IOS-XE-tcam-oper:tcam-details", {}),
            (
                "switch-dp-resources-oper",
                "/data/Cisco-IOS-XE-switch-dp-resources-oper:switch-dp-resources-oper-data",
                {},
            ),
            ("smart-license state", "/data/cisco-smart-license:licensing/state", {}),
            ("smart-license (whole)", "/data/cisco-smart-license:licensing", {}),
            ("ha-oper", "/data/Cisco-IOS-XE-ha-oper:ha-oper-data", {}),
            ("psecure-oper", "/data/Cisco-IOS-XE-psecure-oper:psecure-oper-data", {}),
            ("poe-oper (whole)", "/data/Cisco-IOS-XE-poe-oper:poe-oper-data", {}),
            ("poe-health-oper", "/data/Cisco-IOS-XE-poe-health-oper:poe-health-oper-data", {}),
            ("vlan-oper (whole)", "/data/Cisco-IOS-XE-vlan-oper:vlans", {}),
            ("stp-details (whole)", "/data/Cisco-IOS-XE-spanning-tree-oper:stp-details", {}),
            ("matm-oper (whole)", "/data/Cisco-IOS-XE-matm-oper:matm-oper-data", {}),
            ("stack-oper", "/data/Cisco-IOS-XE-stack-oper:stack-oper-data", {}),
            (
                "device-system-data",
                "/data/Cisco-IOS-XE-device-hardware-oper:device-hardware-data/device-hardware"
                "/device-system-data",
                {},
            ),
            ("lldp-oper (whole)", "/data/Cisco-IOS-XE-lldp-oper:lldp-entries", {}),
            ("cdp-oper (whole)", "/data/Cisco-IOS-XE-cdp-oper:cdp-neighbor-details", {}),
            ("platform-oper", "/data/Cisco-IOS-XE-platform-oper:components", {"timeout": 120}),
            ("environment-oper", "/data/Cisco-IOS-XE-environment-oper:environment-sensors", {}),
            ("yang-library", "/data/ietf-yang-library:modules-state", {"timeout": 120}),
            ("native ip dhcp", "/data/Cisco-IOS-XE-native:native/ip/dhcp", {}),
            ("native router", "/data/Cisco-IOS-XE-native:native/router", {}),
        ],
        "interface_get": "/data/Cisco-IOS-XE-interfaces-oper:interfaces/interface=%s",
        "shows": [
            "show license summary",
            "show sdm prefer",
            "show standby brief",
            "show vrrp brief",
            "show ip eigrp neighbors",
            "show isis neighbors",
            "show interfaces trunk",
            "show vlan brief",
            "show vtp status",
            "show power inline",
            "show cdp neighbors detail",
            "show lldp neighbors detail",
            "show etherchannel summary",
            "show ntp status",
            "show ntp associations",
            "show crypto pki certificates",
            "show interfaces status err-disabled",
            "show interfaces status",
            "show spanning-tree",
            "show spanning-tree summary",
            "show ip route",
            "show ip ospf neighbor",
            "show ip ospf interface brief",
            "show ip eigrp interfaces",
            "show port-security",
            "show mac address-table",
            "show install summary",
            "show version",
            "show ip interface brief",
            "show storm-control",
            "show errdisable recovery",
            "show clock",
            "show ip dhcp pool",
            "show access-lists",
            "show policy-map interface",
            "show inventory",
            "show switch detail",
            "show switch stack-ports summary",
            "show platform",
            "show environment all",
            "show ip protocols",
            "show lldp neighbors",
            "show cdp neighbors",
            "show boot",
            "show logging | include -4-|-5-",
        ],
        "interface_show": "show interfaces %s",
        "port_show": "show power inline %s detail",
    },
    # A server's BMC over Redfish: no SSH, no --interface reads; the extra
    # reads are BMC_COLLECTIONS / BMC_SINGLETONS and the links they carry.
    "bmc": {"transport": "redfish"},
}


def slug(text):
    """File-name stem for a request: the path's word characters, a hash for a fields filter."""
    base = re.sub(r"[^A-Za-z0-9]+", "_", text.split("?", 1)[0]).strip("_")
    if "?" in text:
        base += "__f" + hashlib.sha1(text.encode("utf-8")).hexdigest()[:6]
    return base[:120]


def describe(payload):
    """One line about a payload for the manifest: shape, never content."""
    if payload is None:
        return "not-found (404)"
    if payload == {}:
        return "empty 2xx ({})"
    if isinstance(payload, dict):
        parts = []
        for key, value in payload.items():
            if isinstance(value, dict):
                parts.append("%s: dict keys=%s" % (key, sorted(value)[:12]))
            elif isinstance(value, list):
                parts.append("%s: list len=%d" % (key, len(value)))
            else:
                parts.append("%s: <%s>" % (key, type(value).__name__))
        return "; ".join(parts)[:400]
    return type(payload).__name__


# --platform bmc: the reads beyond the checks, as paths under the resolved
# System ({system}), Manager ({manager}) and Chassis ({chassis}). Collections
# are read twice (plain and $expand), singletons once; links found in the
# payloads (OEM blocks, per-member sub-collections) are followed by
# bmc_link_reads(). TelemetryService is deliberately absent (decision 7).
BMC_COLLECTIONS = (
    "{system}/Memory",
    "{system}/Processors",
    "{system}/EthernetInterfaces",
    "{system}/NetworkInterfaces",
    "{system}/Storage",
    "{system}/LogServices",
    "{system}/VirtualMedia",
    "{system}/BootOptions",
    "{system}/PCIeDevices",
    "{system}/PCIeFunctions",
    "{chassis}/PCIeDevices",
    "{chassis}/NetworkAdapters",
    "{chassis}/Sensors",
    "{chassis}/Controls",
    "{chassis}/Drives",
    "{chassis}/ThermalSubsystem/Fans",
    "{chassis}/PowerSubsystem/PowerSupplies",
    "{manager}/EthernetInterfaces",
    "{manager}/HostInterfaces",
    "{manager}/SerialInterfaces",
    "{manager}/VirtualMedia",
    "{manager}/NetworkProtocol/HTTPS/Certificates",
    "/redfish/v1/UpdateService/FirmwareInventory",
    "/redfish/v1/UpdateService/SoftwareInventory",
    "/redfish/v1/AccountService/Accounts",
    "/redfish/v1/AccountService/Roles",
    "/redfish/v1/EventService/Subscriptions",
    "/redfish/v1/TaskService/Tasks",
    "/redfish/v1/JobService/Jobs",
    "/redfish/v1/LicenseService/Licenses",
    "/redfish/v1/CertificateService/CertificateLocations",
    "/redfish/v1/Registries",
    "/redfish/v1/Systems",
    "/redfish/v1/Managers",
    "/redfish/v1/Chassis",
)
BMC_SINGLETONS = (
    "{system}/SecureBoot",
    "{system}/Bios",
    "{chassis}/Thermal",
    "{chassis}/Power",
    "{chassis}/PCIeSlots",
    "{chassis}/EnvironmentMetrics",
    "{chassis}/ThermalSubsystem",
    "{chassis}/ThermalSubsystem/ThermalMetrics",
    "{chassis}/PowerSubsystem",
    "{manager}/NetworkProtocol",
    "{manager}/SecurityPolicy",
    "/redfish/v1/UpdateService",
    "/redfish/v1/AccountService",
    "/redfish/v1/EventService",
    "/redfish/v1/TaskService",
    "/redfish/v1/JobService",
    "/redfish/v1/LicenseService",
    "/redfish/v1/CertificateService",
)


def load_jobs():
    """Import the pure jobs modules through a synthetic package (no Nautobot)."""
    if "jobs" not in sys.modules:
        package = types.ModuleType("jobs")
        package.__path__ = [str(ROOT / "jobs")]
        sys.modules["jobs"] = package
    registry = importlib.import_module("jobs.registry")
    context = importlib.import_module("jobs.context")
    for path in sorted((ROOT / "jobs").glob("checks_*.py")):
        importlib.import_module("jobs." + path.stem)
    return registry, context


def run_checks(ctx, registry, platform, host=None):
    """Every registered check of the platform, in catalog order; nothing raises past here.

    ``host`` is replaced by ``<host>`` in what is printed (a connection error names it).
    """
    results, summary = {}, {}
    for check in registry.checks_for(platform):
        status, note, out, first, started = "ok", None, {}, len(ctx.trace), time.monotonic()
        try:
            out = check.collector(ctx) or {}
        except registry.SkipCheck as exc:
            status, note = "not-present", str(exc)
        except Exception as exc:  # noqa: BLE001 - a harvest records failures, it does not stop
            status, note = "FAILED", "%s: %s" % (type(exc).__name__, exc)
        normalized = out.get("normalized") or {}
        results[check.id] = {
            "status": status,
            "note": note,
            "normalized": normalized,
            "context": out.get("context"),
            "raw": out.get("raw"),
        }
        summary[check.id] = {
            "status": status,
            "note": note,
            "normalized_keys": len(normalized),
            "context_keys": sorted(out["context"])
            if isinstance(out.get("context"), dict)
            else None,
            "raw_keys": sorted(out["raw"]) if isinstance(out.get("raw"), dict) else None,
            "elapsed_ms": int((time.monotonic() - started) * 1000),
            "requests": [entry.get("target") for entry in ctx.trace[first:]],
        }
        shown = (note or "").replace(host, "<host>") if host else (note or "")
        print("%-28s %-12s keys=%-4d %s" % (check.id, status, len(normalized), shown[:90]))
    return results, summary


def run_extras(ctx, spec, interfaces):
    """The platform's extra reads; each outcome printed, every payload lands in the trace."""
    gets = list(spec["gets"])
    shows = list(spec["shows"])
    for name in interfaces:
        gets.append(("interface %s" % name, spec["interface_get"] % name.replace("/", "%2F"), {}))
        shows.append(spec["interface_show"] % name)
        if "/" in name:  # a physical port: its PoE detail too
            shows.append(spec["port_show"] % name)
    for label, path, kwargs in gets:
        kwargs = dict({"ok_404": True}, **kwargs)
        try:
            payload = ctx.get(path, **kwargs)
            outcome = "ok" if payload is not None else "not-found"
        except Exception as exc:  # noqa: BLE001
            outcome = "error: %s" % (exc,)
        print("GET %-70s %s" % (label, outcome[:100]))
    for command in shows:
        try:
            ctx.run_ssh(command)
            print("SSH %-70s ok" % command)
        except Exception as exc:  # noqa: BLE001
            print("SSH %-70s ERROR %s" % (command, exc))


def _bmc_redactor(checks_bmc, path):
    """The family's redactor for one path: log pages, account collections, else the scrubber."""
    resource = path.split("?", 1)[0]
    if resource.endswith("/Entries"):
        return checks_bmc._redact_log_page
    if "/AccountService/Accounts" in resource:
        return checks_bmc._scrub_accounts
    return checks_bmc._scrub_payload


def _bmc_read(ctx, checks_bmc, path, seen):
    """One extra read (404 tolerated, errors printed by type only, each path once).

    The payload, or None when the path was read already, is absent or failed.
    """
    if path in seen:
        return None
    seen.add(path)
    try:
        payload = ctx.get(path, ok_404=True, redact=_bmc_redactor(checks_bmc, path))
        outcome = "ok" if payload is not None else "not-found"
    except Exception as exc:  # noqa: BLE001 - a harvest records failures, it does not stop
        payload, outcome = None, "error: %s" % (type(exc).__name__,)
    print("GET %-78s %s" % (path[:78], outcome[:40]))
    return payload


def _bmc_cached(ctx, checks_bmc, path):
    """A resource the checks read already, from the per-run cache (their spelling); or None."""
    try:
        return ctx.get(path, redact=_bmc_redactor(checks_bmc, path))
    except Exception as exc:  # noqa: BLE001
        print("GET %-78s error: %s" % (path[:78], type(exc).__name__))
        return None


def _bmc_link(checks_bmc, node):
    """The fenced @odata.id of a link object; None when absent or refused (never sent)."""
    link = node.get("@odata.id") if isinstance(node, dict) else None
    if not isinstance(link, str) or not link:
        return None
    try:
        return checks_bmc.fence_path(link)
    except ValueError:
        print("LINK refused by the fence: %s" % (link[:78],))
        return None


def bmc_link_reads(checks_bmc, payload, keys):
    """Fenced links found under ``keys`` of a payload's Oem.<vendor> block and top level."""
    links = []
    vendor = checks_bmc._oem_key(payload)
    blocks = [payload]
    if vendor:
        blocks.append(checks_bmc._dig(payload, "Oem", vendor))
    for block in blocks:
        for key, value in sorted((block or {}).items()):
            if keys is not None and key not in keys:
                continue
            link = _bmc_link(checks_bmc, value)
            if link is not None:
                links.append(link)
    return links


def run_bmc_extras(ctx):
    """The bmc spec's reads beyond the checks (see BMC_COLLECTIONS / BMC_SINGLETONS)."""
    checks_bmc = importlib.import_module("jobs.checks_bmc")
    expand = checks_bmc._EXPAND
    try:
        targets = checks_bmc._targets(ctx)
    except Exception as exc:  # noqa: BLE001
        print("the id resolution failed (%s): no extra reads" % (type(exc).__name__,))
        return
    fill = dict(system=targets["system"], manager=targets["manager"], chassis=targets["chassis"])
    seen = set()
    collections = [template.format(**fill) for template in BMC_COLLECTIONS]
    for path in [template.format(**fill) for template in BMC_SINGLETONS]:
        payload = _bmc_read(ctx, checks_bmc, path, seen)
        settings = checks_bmc._dig(payload, "@Redfish.Settings", "SettingsObject")
        link = _bmc_link(checks_bmc, settings)
        if link is not None:
            _bmc_read(ctx, checks_bmc, link, seen)
    # every OEM link of the System, Manager, Chassis and NetworkProtocol (read by
    # the checks already: the cache answers); a link that answers as a
    # collection is read expanded as well
    parents = [targets["system"], targets["manager"], targets["chassis"]]
    parents.append(fill["manager"] + "/NetworkProtocol")
    oem_links = []
    for parent in parents:
        payload = _bmc_cached(ctx, checks_bmc, parent)
        vendor = checks_bmc._oem_key(payload)
        block = checks_bmc._dig(payload, "Oem", vendor) if vendor else None
        for _key, value in sorted((block or {}).items()):
            link = _bmc_link(checks_bmc, value)
            if link is not None:
                oem_links.append(link)
    for path in oem_links:
        payload = _bmc_read(ctx, checks_bmc, path, seen)
        if isinstance(payload, dict) and isinstance(payload.get("Members"), list):
            collections.append(path)
        for nested in bmc_link_reads(checks_bmc, payload or {}, None):
            if nested.startswith(path + "/"):
                _bmc_read(ctx, checks_bmc, nested, seen)
    for path in collections:
        if path in seen:
            # read already (an OEM link that answered as a collection): the
            # cache serves it again, and only the expanded form is new
            plain = ctx.get(path, ok_404=True, redact=_bmc_redactor(checks_bmc, path))
        else:
            plain = _bmc_read(ctx, checks_bmc, path, seen)
        if plain is None:
            continue
        expanded = _bmc_read(ctx, checks_bmc, path + expand, seen)
        members = checks_bmc._dicts((expanded or plain).get("Members"))
        # per-member sub-collections $levels=2 does not inline (adapters, PCIe
        # devices, storage, log services), read expanded
        for member in members:
            for key in (
                "Ports",
                "NetworkPorts",
                "NetworkDeviceFunctions",
                "PCIeFunctions",
                "Volumes",
                "StoragePools",
                "Controllers",
                "Entries",
                "Certificates",
            ):
                link = _bmc_link(checks_bmc, member.get(key))
                if link is None:
                    link = _bmc_link(checks_bmc, checks_bmc._dig(member, "Links", key))
                if link is None:
                    continue
                if key == "Entries":
                    _bmc_read(ctx, checks_bmc, link, seen)
                else:
                    _bmc_read(ctx, checks_bmc, link + expand, seen)


def save_trace(ctx, out_dir):
    """One file per traced request (cache hits skipped); returns the manifest rows."""
    rows = []
    for entry in ctx.trace:
        if entry.get("outcome") == "cache-hit":
            continue
        target = entry.get("target")
        if entry.get("transport") == "ssh":
            name = "ssh__" + slug(target) + ".txt"
            body = entry.get("output")
            if body is None and entry.get("outcome") == "error":
                body = "ERROR: " + str(entry.get("error"))
            (out_dir / name).write_text(body or "", encoding="utf-8")
            note = "%d chars" % len(body or "")
            if body and re.search(r"invalid input|incomplete command", body, re.I):
                note += "; CLI refused"
        else:
            name = "get__" + slug(target) + ".json"
            payload = entry.get("payload")
            if entry.get("outcome") == "error":
                payload = {"__error__": entry.get("error")}
                note = "error: %s" % entry.get("error")
            else:
                note = describe(payload)
            (out_dir / name).write_text(json.dumps(payload, indent=1) + "\n", encoding="utf-8")
        rows.append(
            {
                "transport": entry.get("transport"),
                "request": target,
                "kwargs": entry.get("kwargs"),
                "outcome": entry.get("outcome"),
                "elapsed_ms": entry.get("elapsed_ms"),
                "file": name,
                "bytes": (out_dir / name).stat().st_size,
                "notes": note,
            }
        )
    return rows


def main(argv=None):
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument("--host", help="device address or name to connect to")
    target.add_argument("--host-env", help="env var holding the address (never printed)")
    parser.add_argument("--platform", required=True, choices=sorted(PLATFORMS))
    parser.add_argument("--tag", required=True, help="name of this harvest (OUT/TAG/)")
    parser.add_argument("--out", required=True, help="directory OUTSIDE the repository")
    parser.add_argument("--device-name", help="context device name (default: --host)")
    parser.add_argument(
        "--interface", action="append", default=[], help="long interface name to read in full"
    )
    parser.add_argument("--user-env", default="HARVEST_USER", help="env var holding the login")
    parser.add_argument(
        "--password-env", default="HARVEST_PASSWORD", help="env var holding the password"
    )
    args = parser.parse_args(argv)

    username = os.environ.get(args.user_env)
    password = os.environ.get(args.password_env)
    if not username or not password:
        parser.error(
            "set %s and %s in the environment (never on the command line)"
            % (args.user_env, args.password_env)
        )
    host = args.host or os.environ.get(args.host_env or "")
    if not host:
        parser.error("set %s in the environment" % (args.host_env,))
    out_dir = pathlib.Path(args.out) / args.tag
    if ROOT in out_dir.resolve().parents or out_dir.resolve() == ROOT:
        parser.error("--out must be outside the repository (the harvest is unsanitized)")
    out_dir.mkdir(parents=True, exist_ok=True)

    logging.basicConfig(level=logging.ERROR)
    log = logging.getLogger("harvest")
    registry, context = load_jobs()
    spec = PLATFORMS[args.platform]
    if spec.get("transport") == "redfish":
        redfish = importlib.import_module("jobs.transport_redfish")
        client = redfish.RedfishClient(host, username, password, logger=log)
        if not client.ping():
            record = client.probe_get(redfish.C.REDFISH_PROBE_SYSTEMS, timeout=30)
            client.close()
            # A connection error names the address; the harvest never prints it.
            hint = str(redfish.probe_hint(record)).replace(host, "<host>")
            raise SystemExit("Redfish probe failed: %s" % (hint,))
        ctx = context.CollectorContext(
            args.device_name or "bmc-lab-1", args.platform, restconf=client, logger=log, debug=True
        )
    else:
        restconf = importlib.import_module("jobs.transport_restconf")
        ssh = importlib.import_module("jobs.transport_ssh")
        client = restconf.RestconfClient(host, username, password, logger=log)
        if not client.ping():
            raise SystemExit("RESTCONF ping to %s failed" % (host,))
        runner = ssh.SshRunner(spec["device_type"], host, username, password, logger=log)
        ctx = context.CollectorContext(
            args.device_name or host,
            args.platform,
            restconf=client,
            ssh=runner,
            logger=log,
            debug=True,
        )
    manifest = {
        "tag": args.tag,
        "platform": args.platform,
        "started": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    try:
        results, manifest["checks"] = run_checks(ctx, registry, args.platform, host=host)
        try:
            if spec.get("transport") == "redfish":
                run_bmc_extras(ctx)
            else:
                run_extras(ctx, spec, args.interface)
        except Exception as exc:  # noqa: BLE001 - what was read is still saved below
            manifest["extras_stopped"] = type(exc).__name__
            print(
                "extra reads stopped early: %s (everything read so far is saved)"
                % (type(exc).__name__,)
            )
    finally:
        ctx.close()
    if getattr(client, "footprint", None) is not None:
        manifest["footprint"] = client.footprint()
        manifest["footprint"].pop("account", None)
    manifest["requests"] = save_trace(ctx, out_dir)
    (out_dir / "results.json").write_text(
        json.dumps(results, indent=1, default=str), encoding="utf-8"
    )
    (out_dir / "trace.json").write_text(json.dumps(ctx.trace, indent=1, default=str), "utf-8")
    (out_dir / "manifest.json").write_text(json.dumps(manifest, indent=1), encoding="utf-8")
    statuses = [row["status"] for row in manifest["checks"].values()]
    print(
        "%d checks: %d ok, %d not-present, %d FAILED; %d files under %s"
        % (
            len(statuses),
            statuses.count("ok"),
            statuses.count("not-present"),
            statuses.count("FAILED"),
            len(manifest["requests"]),
            out_dir,
        )
    )
    return 1 if "FAILED" in statuses else 0


if __name__ == "__main__":
    sys.exit(main())
