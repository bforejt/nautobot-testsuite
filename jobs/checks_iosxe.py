"""Catalyst 9500 / 9300 (IOS-XE 17.x) check catalog.

Collectors reach the device only through the CollectorContext (``ctx.get`` /
``ctx.run_ssh``); this module imports nothing but stdlib and the jobs
package's pure modules, so the CI test battery can import it and drive every
``_normalize_*`` / ``_parse_*`` function directly with fixture payloads.
RESTCONF paths were verified against the published 17.12.1 YANG set; the
CLI-backed checks (optics, errdisable, port-channels, switch stacks, ...)
ride the read-only ``show`` allowlist over SSH.

The full-RIB fetch is deliberately shared: iosxe_routes_rib and
iosxe_route_rollups call ``ctx.get`` with the identical path and kwargs, so
the per-run cache issues one GET for both checks.
"""

import difflib
import re
from datetime import datetime, timezone

from . import constants as C
from .registry import CheckDef, CollectError, SkipCheck, register

# --- RESTCONF paths ----------------------------------------------------------

_RIB_PATH = "/data/ietf-routing:routing-state"
_FIB_PATH = (
    "/data/Cisco-IOS-XE-fib-oper:fib-oper-data"
    "?fields=fib-ni-entry(instance-name;af;num-pfx;"
    "fib-entries(ip-addr;fib-nexthop-entries(nh-addr;ifname)))"
)
_BGP_PATH = "/data/Cisco-IOS-XE-bgp-oper:bgp-state-data/neighbors"
_OSPF_PATH = (
    "/data/Cisco-IOS-XE-ospf-oper:ospf-oper-data"
    "?fields=ospfv2-instance(instance-id;vrf-name;"
    "ospfv2-area(area-id;ospfv2-interface(name;state;"
    "ospfv2-neighbor(nbr-id;address;state))))"
)
_ARP_PATH = "/data/Cisco-IOS-XE-arp-oper:arp-data"
_IFACE_PATH = (
    "/data/Cisco-IOS-XE-interfaces-oper:interfaces"
    "?fields=interface(name;description;admin-status;oper-status;vrf;ipv4)"
)
_CDP_PATH = "/data/Cisco-IOS-XE-cdp-oper:cdp-neighbor-details"
_LLDP_PATH = "/data/Cisco-IOS-XE-lldp-oper:lldp-entries"
_HW_PATH = "/data/Cisco-IOS-XE-device-hardware-oper:device-hardware-data"
_ENV_PATH = "/data/Cisco-IOS-XE-environment-oper:environment-sensors"


# --- shared helpers ----------------------------------------------------------


def _aslist(node):
    """RESTCONF quirk: a single list entry may arrive as a bare dict, absent as None."""
    if node is None:
        return []
    if isinstance(node, list):
        return node
    return [node]


def _container(payload, qualified_name):
    """Top-level container by its module-qualified name (bare-name fallback)."""
    if not isinstance(payload, dict):
        return None
    if qualified_name in payload:
        return payload[qualified_name]
    return payload.get(qualified_name.split(":", 1)[-1])


def _to_int(value):
    """int() that tolerates None and non-numeric junk; RESTCONF may string-ify numbers."""
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _strip_module(identityref):
    """'ietf-routing:static' -> 'static'; identityrefs carry their YANG module prefix."""
    if identityref is None:
        return None
    return str(identityref).split(":")[-1]


def _hop(ip, interface):
    """Next-hop dict carrying only the facets the device actually reported."""
    hop = {}
    if ip is not None:
        hop["ip"] = ip
    if interface is not None:
        hop["interface"] = interface
    return hop


def _sorted_hops(hops):
    """Deduplicate and order next-hop dicts so list equality is order-independent."""
    unique = {(h.get("ip"), h.get("interface")): h for h in hops if h}
    return [unique[key] for key in sorted(unique, key=lambda t: (t[0] or "", t[1] or ""))]


# --- RIB (ietf-routing:routing-state) ----------------------------------------


def _rib_next_hops(nh_container):
    """Flatten the route's next-hop choice: single address/interface or a next-hop-list."""
    nh_container = nh_container if isinstance(nh_container, dict) else {}
    nh_list = nh_container.get("next-hop-list")
    if isinstance(nh_list, dict):
        candidates = _aslist(nh_list.get("next-hop"))
    else:
        candidates = [nh_container]
    hops = []
    for cand in candidates:
        if not isinstance(cand, dict):
            continue
        hop = _hop(cand.get("next-hop-address"), cand.get("outgoing-interface"))
        if hop:
            hops.append(hop)
    return _sorted_hops(hops)


def _normalize_rib(payload):
    """'vrf|prefix' -> protocol / preference / next_hops, across v4 and v6 ribs.

    'active' is a presence leaf; when a prefix appears more than once in a rib,
    the active route wins so a backup path never masks the installed one.
    Volatile leaves (last-updated, metric) are never emitted.
    """
    container = _container(payload, "ietf-routing:routing-state") or {}
    normalized = {}
    seen_active = {}
    for instance in _aslist(container.get("routing-instance")):
        if not isinstance(instance, dict):
            continue
        vrf = instance.get("name") or "default"
        ribs = instance.get("ribs") if isinstance(instance.get("ribs"), dict) else {}
        for rib in _aslist(ribs.get("rib")):
            if not isinstance(rib, dict):
                continue
            routes = rib.get("routes") if isinstance(rib.get("routes"), dict) else {}
            for route in _aslist(routes.get("route")):
                if not isinstance(route, dict):
                    continue
                prefix = route.get("destination-prefix")
                if prefix is None:
                    continue
                key = "%s|%s" % (vrf, prefix)
                is_active = "active" in route
                if seen_active.get(key) and not is_active:
                    continue
                normalized[key] = {
                    "protocol": _strip_module(route.get("source-protocol")),
                    "preference": _to_int(route.get("route-preference")),
                    "next_hops": _rib_next_hops(route.get("next-hop")),
                }
                seen_active[key] = is_active
    return normalized


def _normalize_route_rollups(payload):
    """Flat per-protocol route counts derived from the normalized RIB view."""
    rib = _normalize_rib(payload)
    counts = {"total": len(rib)}
    for entry in rib.values():
        protocol = entry.get("protocol") or "unknown"
        counts[protocol] = counts.get(protocol, 0) + 1
    return counts


# "  Intra-area: N Inter-area: N External-1: N External-2: N" (+ NSSA variants)
# under each OSPF process in "show ip route summary". The fixed-width lookbehind
# keeps plain External-N from also matching the NSSA line.
_ROUTE_SUMMARY_TOKENS = (
    ("ospf_intra", re.compile(r"\bIntra-area:\s*(\d+)")),
    ("ospf_inter", re.compile(r"\bInter-area:\s*(\d+)")),
    ("ospf_e1", re.compile(r"(?<!NSSA )\bExternal-1:\s*(\d+)")),
    ("ospf_e2", re.compile(r"(?<!NSSA )\bExternal-2:\s*(\d+)")),
    ("ospf_n1", re.compile(r"NSSA External-1:\s*(\d+)")),
    ("ospf_n2", re.compile(r"NSSA External-2:\s*(\d+)")),
)


def _parse_route_summary(text):
    """OSPF type splits out of ``show ip route summary``; {} when none found.

    Multiple OSPF processes each print their own split line; values are summed.
    """
    found = {}
    for key, pattern in _ROUTE_SUMMARY_TOKENS:
        matches = pattern.findall(text or "")
        if matches:
            found[key] = sum(int(m) for m in matches)
    return found


def _fetch_rib(ctx):
    """The shared cached RIB GET — identical path/kwargs from both route checks."""
    payload = ctx.get(_RIB_PATH, timeout=C.BIG_GET_TIMEOUT)
    if _container(payload, "ietf-routing:routing-state") is None:
        raise CollectError("routing-state container missing from RESTCONF reply")
    return payload


def _collect_routes_rib(ctx):
    payload = _fetch_rib(ctx)
    return {"raw": {"routing-state": payload}, "normalized": _normalize_rib(payload)}


def _collect_route_rollups(ctx):
    payload = _fetch_rib(ctx)
    normalized = _normalize_route_rollups(payload)
    raw = {"derived_from": _RIB_PATH, "route_summary": None, "note": None}
    if ctx.has_ssh:
        # Best-effort enrichment only: any SSH or parse trouble is recorded in
        # raw and the RIB-derived counts above still satisfy the check.
        try:
            output = ctx.run_ssh("show ip route summary")
            raw["route_summary"] = output
            splits = _parse_route_summary(output)
            if splits:
                normalized.update(splits)
            else:
                raw["note"] = "no OSPF type-split lines found in route summary output"
        except Exception as exc:  # transport failure modes vary by SSH stack
            raw["note"] = "ssh 'show ip route summary' failed: %s" % (exc,)
    else:
        raw["note"] = "no SSH transport; OSPF type splits unavailable"
    return {"raw": raw, "normalized": normalized}


# --- FIB ---------------------------------------------------------------------


def _normalize_fib(payload):
    """'instance|prefix' -> sorted programmed next-hops."""
    container = _container(payload, "Cisco-IOS-XE-fib-oper:fib-oper-data") or {}
    normalized = {}
    for ni_entry in _aslist(container.get("fib-ni-entry")):
        if not isinstance(ni_entry, dict):
            continue
        instance = ni_entry.get("instance-name") or "default"
        for entry in _aslist(ni_entry.get("fib-entries")):
            if not isinstance(entry, dict):
                continue
            prefix = entry.get("ip-addr")
            if prefix is None:
                continue
            hops = []
            for nh_entry in _aslist(entry.get("fib-nexthop-entries")):
                if not isinstance(nh_entry, dict):
                    continue
                hop = _hop(nh_entry.get("nh-addr"), nh_entry.get("ifname"))
                if hop:
                    hops.append(hop)
            normalized["%s|%s" % (instance, prefix)] = {"next_hops": _sorted_hops(hops)}
    return normalized


def _collect_routes_fib(ctx):
    payload = ctx.get(_FIB_PATH, timeout=C.BIG_GET_TIMEOUT)
    if _container(payload, "Cisco-IOS-XE-fib-oper:fib-oper-data") is None:
        raise CollectError("fib-oper-data container missing from RESTCONF reply")
    return {"raw": {"fib-oper": payload}, "normalized": _normalize_fib(payload)}


# --- BGP ---------------------------------------------------------------------


def _normalize_bgp_peers(payload):
    """'afi|vrf|neighbor' -> session state, remote AS, installed prefixes."""
    container = _container(payload, "Cisco-IOS-XE-bgp-oper:neighbors") or {}
    normalized = {}
    for neighbor in _aslist(container.get("neighbor")):
        if not isinstance(neighbor, dict):
            continue
        neighbor_id = neighbor.get("neighbor-id")
        if neighbor_id is None:
            continue
        key = "%s|%s|%s" % (
            neighbor.get("afi-safi") or "unknown",
            neighbor.get("vrf-name") or "default",
            neighbor_id,
        )
        normalized[key] = {
            "state": neighbor.get("session-state"),
            "as": _to_int(neighbor.get("as")),
            "installed_prefixes": _to_int(neighbor.get("installed-prefixes")),
        }
    return normalized


def _collect_bgp_peers(ctx):
    payload = ctx.get(_BGP_PATH, ok_404=True)
    if payload is None:
        raise SkipCheck("BGP not running")
    normalized = _normalize_bgp_peers(payload)
    if not normalized:
        raise SkipCheck("BGP not running")
    return {"raw": {"bgp-neighbors": payload}, "normalized": normalized}


# --- OSPF --------------------------------------------------------------------


def _normalize_ospf_neighbors(payload):
    """'instance|area|interface|nbr-id' -> adjacency state and neighbor address."""
    container = _container(payload, "Cisco-IOS-XE-ospf-oper:ospf-oper-data") or {}
    normalized = {}
    for inst in _aslist(container.get("ospfv2-instance")):
        if not isinstance(inst, dict):
            continue
        instance_id = inst.get("instance-id")
        for area in _aslist(inst.get("ospfv2-area")):
            if not isinstance(area, dict):
                continue
            area_id = area.get("area-id")
            for iface in _aslist(area.get("ospfv2-interface")):
                if not isinstance(iface, dict):
                    continue
                if_name = iface.get("name")
                for neighbor in _aslist(iface.get("ospfv2-neighbor")):
                    if not isinstance(neighbor, dict):
                        continue
                    nbr_id = neighbor.get("nbr-id")
                    if nbr_id is None:
                        continue
                    key = "%s|%s|%s|%s" % (instance_id, area_id, if_name, nbr_id)
                    normalized[key] = {
                        "state": neighbor.get("state"),
                        "address": neighbor.get("address"),
                    }
    return normalized


def _collect_ospf_neighbors(ctx):
    payload = ctx.get(_OSPF_PATH, ok_404=True)
    if payload is None:
        raise SkipCheck("OSPF not running")
    container = _container(payload, "Cisco-IOS-XE-ospf-oper:ospf-oper-data") or {}
    if not _aslist(container.get("ospfv2-instance")):
        raise SkipCheck("OSPF not running")
    return {"raw": {"ospf-oper": payload}, "normalized": _normalize_ospf_neighbors(payload)}


# --- ARP ---------------------------------------------------------------------


def _normalize_arp(payload):
    """'vrf|address' -> mac / interface, from arp-vrf's arp-entry list.

    The flat arp-oper list under arp-vrf is deprecated in 17.x and ignored
    here. The volatile 'time' leaf is never emitted.
    """
    container = _container(payload, "Cisco-IOS-XE-arp-oper:arp-data") or {}
    normalized = {}
    for vrf_entry in _aslist(container.get("arp-vrf")):
        if not isinstance(vrf_entry, dict):
            continue
        vrf = vrf_entry.get("vrf") or "default"
        for entry in _aslist(vrf_entry.get("arp-entry")):
            if not isinstance(entry, dict):
                continue
            address = entry.get("address")
            if address is None:
                continue
            normalized["%s|%s" % (vrf, address)] = {
                "mac": entry.get("hardware"),
                "interface": entry.get("interface"),
            }
    return normalized


def _collect_arp(ctx):
    payload = ctx.get(_ARP_PATH)
    if _container(payload, "Cisco-IOS-XE-arp-oper:arp-data") is None:
        raise CollectError("arp-data container missing from RESTCONF reply")
    return {"raw": {"arp-data": payload}, "normalized": _normalize_arp(payload)}


# --- CDP + LLDP --------------------------------------------------------------


def _normalize_cdp(payload):
    """'cdp|device-id|local-intf' -> remote port and capability string."""
    container = _container(payload, "Cisco-IOS-XE-cdp-oper:cdp-neighbor-details") or {}
    normalized = {}
    for entry in _aslist(container.get("cdp-neighbor-detail")):
        if not isinstance(entry, dict):
            continue
        device_id = entry.get("device-id")
        local = entry.get("local-intf-name")
        if device_id is None or local is None:
            continue
        normalized["cdp|%s|%s" % (device_id, local)] = {
            "port": entry.get("port-id"),
            # 17.12 emits "capability"; tolerate the plural seen on other trains
            "caps": entry.get("capability", entry.get("capabilities")),
        }
    return normalized


def _normalize_lldp(payload):
    """'lldp|device-id|local-interface' -> remote connecting interface."""
    container = _container(payload, "Cisco-IOS-XE-lldp-oper:lldp-entries") or {}
    normalized = {}
    for entry in _aslist(container.get("lldp-entry")):
        if not isinstance(entry, dict):
            continue
        device_id = entry.get("device-id")
        local = entry.get("local-interface")
        if device_id is None or local is None:
            continue
        normalized["lldp|%s|%s" % (device_id, local)] = {
            "port": entry.get("connecting-interface"),
        }
    return normalized


def _collect_neighbors(ctx):
    cdp = ctx.get(_CDP_PATH, ok_404=True)
    lldp = ctx.get(_LLDP_PATH, ok_404=True)
    if cdp is None and lldp is None:
        raise SkipCheck("neither CDP nor LLDP oper data present")
    normalized = {}
    if cdp is not None:
        normalized.update(_normalize_cdp(cdp))
    if lldp is not None:
        normalized.update(_normalize_lldp(lldp))
    return {"raw": {"cdp": cdp, "lldp": lldp}, "normalized": normalized}


# --- interfaces --------------------------------------------------------------


def _normalize_interfaces(payload):
    """interface name -> admin/oper status and IPv4 address (None when unset).

    Description is deliberately raw-only: cosmetic edits must not fail a
    change window.
    """
    container = _container(payload, "Cisco-IOS-XE-interfaces-oper:interfaces") or {}
    normalized = {}
    for entry in _aslist(container.get("interface")):
        if not isinstance(entry, dict):
            continue
        name = entry.get("name")
        if name is None:
            continue
        normalized[name] = {
            "admin": entry.get("admin-status"),
            "oper": entry.get("oper-status"),
            "ipv4": entry.get("ipv4"),
        }
    return normalized


def _collect_interfaces(ctx):
    payload = ctx.get(_IFACE_PATH)
    if _container(payload, "Cisco-IOS-XE-interfaces-oper:interfaces") is None:
        raise CollectError("interfaces container missing from RESTCONF reply")
    return {"raw": {"interfaces": payload}, "normalized": _normalize_interfaces(payload)}


# --- platform health ---------------------------------------------------------


def _normalize_platform_health(hardware_payload, env_payload):
    """boot-time, active alarms, and env sensor states; env_payload may be None.

    Volatile current-reading values are never emitted — only each sensor's
    state word.
    """
    container = (
        _container(hardware_payload, "Cisco-IOS-XE-device-hardware-oper:device-hardware-data") or {}
    )
    hardware = container.get("device-hardware")
    hardware = hardware if isinstance(hardware, dict) else {}
    normalized = {}
    system = hardware.get("device-system-data")
    system = system if isinstance(system, dict) else {}
    boot_time = system.get("boot-time")
    if boot_time is not None:
        normalized["boot-time"] = {"value": str(boot_time)}
    for alarm in _aslist(hardware.get("device-alarm")):
        if not isinstance(alarm, dict):
            continue
        key = "alarm|%s|%s" % (alarm.get("alarm-id"), alarm.get("alarm-instance"))
        normalized[key] = {"desc": alarm.get("alarm-description")}
    env_container = (
        _container(env_payload, "Cisco-IOS-XE-environment-oper:environment-sensors") or {}
    )
    for sensor in _aslist(env_container.get("environment-sensor")):
        if not isinstance(sensor, dict):
            continue
        key = "env|%s/%s" % (sensor.get("location"), sensor.get("name"))
        normalized[key] = {"state": sensor.get("state")}
    return normalized


def _collect_platform_health(ctx):
    hardware = ctx.get(_HW_PATH)
    if _container(hardware, "Cisco-IOS-XE-device-hardware-oper:device-hardware-data") is None:
        raise CollectError("device-hardware-data container missing from RESTCONF reply")
    env = ctx.get(_ENV_PATH, ok_404=True)
    raw = {"device-hardware": hardware, "environment-sensors": env}
    if env is None:
        raw["note"] = "environment-sensors path absent on this release/SKU; env portion skipped"
    return {"raw": raw, "normalized": _normalize_platform_health(hardware, env)}


# --- registrations -----------------------------------------------------------

register(
    CheckDef(
        id="iosxe_routes_rib",
        platform="iosxe",
        description="Full RIB (all VRFs, v4+v6): prefix -> protocol, preference, next-hops.",
        tier=2,
        compare={"mode": "equality_set"},
        miss_meaning=(
            "A prefix vanished or changed next-hop outside the declared expectations — "
            "collateral routing damage, or an expected change that was not declared."
        ),
        collector=_collect_routes_rib,
        tags=("routing",),
    )
)

register(
    CheckDef(
        id="iosxe_route_rollups",
        platform="iosxe",
        description="Per-protocol route counts from the RIB, plus best-effort OSPF type splits.",
        tier=1,
        compare={"mode": "tolerance", "band": {"abs": C.ROUTE_ROLLUP_TOLERANCE_ABS}},
        miss_meaning=(
            "A per-protocol or per-type route count moved more than a couple — a peer is "
            "likely down or not advertising; see iosxe_bgp_peers / iosxe_ospf_neighbors "
            "to name it."
        ),
        collector=_collect_route_rollups,
        tags=("routing",),
    )
)

register(
    CheckDef(
        id="iosxe_routes_fib",
        platform="iosxe",
        description="CEF FIB: programmed prefix -> next-hops per forwarding instance.",
        tier=2,
        compare={"mode": "equality_set"},
        miss_meaning=(
            "RIB and FIB disagree or a forwarding entry vanished — the control plane "
            "decided but CEF did not program it."
        ),
        collector=_collect_routes_fib,
        tags=("routing", "forwarding"),
    )
)

register(
    CheckDef(
        id="iosxe_bgp_peers",
        platform="iosxe",
        description="BGP sessions per AFI/VRF/peer: state, remote AS, installed prefixes.",
        tier=1,
        compare={
            "mode": "equality_set",
            "fields": {"installed_prefixes": {"tolerance": {"abs": C.PEER_PREFIX_TOLERANCE_ABS}}},
        },
        miss_meaning=(
            "A BGP peer changed state or its prefix count moved beyond tolerance — session "
            "down, or up but not advertising / being filtered."
        ),
        collector=_collect_bgp_peers,
        tags=("routing", "bgp"),
    )
)

register(
    CheckDef(
        id="iosxe_ospf_neighbors",
        platform="iosxe",
        description="OSPFv2 adjacencies per instance/area/interface: neighbor state, address.",
        tier=1,
        compare={"mode": "equality_set"},
        miss_meaning=(
            "An OSPF adjacency is missing or not FULL — the new Vlan925 neighbors must "
            "form and every other adjacency must be untouched."
        ),
        collector=_collect_ospf_neighbors,
        tags=("routing", "ospf"),
    )
)

register(
    CheckDef(
        id="iosxe_arp",
        platform="iosxe",
        description="ARP tables, all VRFs: resolved MAC and interface per address.",
        tier=2,
        compare={"mode": "equality_set"},
        miss_meaning=(
            "An adjacency did not resolve — a missing or incomplete entry for the new "
            "Vlan925 next-hop means the VM-500 is not answering ARP."
        ),
        collector=_collect_arp,
        tags=("adjacency",),
    )
)

register(
    CheckDef(
        id="iosxe_neighbors",
        platform="iosxe",
        description="CDP and LLDP neighbor tables combined: who is on which local port.",
        tier=2,
        compare={"mode": "equality_set"},
        miss_meaning=(
            "A neighbor disappeared or moved — a link was bounced or mis-cabled during the "
            "physical work."
        ),
        collector=_collect_neighbors,
        tags=("topology",),
    )
)

register(
    CheckDef(
        id="iosxe_interfaces",
        platform="iosxe",
        description="All interfaces: admin/oper status and IPv4 address.",
        tier=2,
        compare={"mode": "equality_set"},
        miss_meaning=("A port that was up is no longer up (outside the declared firewall ports)."),
        collector=_collect_interfaces,
        tags=("interfaces",),
    )
)

register(
    CheckDef(
        id="iosxe_platform_health",
        platform="iosxe",
        description="Boot time, active hardware alarms, environment sensor states.",
        tier=3,
        compare={"mode": "equality_set"},
        miss_meaning=(
            "The core itself changed — a reload (boot-time), a new alarm, or a degraded "
            "sensor during the window."
        ),
        collector=_collect_platform_health,
        tags=("platform",),
    )
)


# --- iosxe_dhcp (always-on optional feature) ----------------------------------
# Doctrine: always ask, even where DHCP is not expected — "not-present" is a
# recorded fact. Config, not oper: stable and equality-comparable.


def _collect_dhcp_config(ctx):
    payload = ctx.get("/data/Cisco-IOS-XE-native:native/ip/dhcp", ok_404=True)
    if not payload:
        raise SkipCheck("no DHCP server/relay configuration present")
    # The container key carries an augment-module prefix that varies by train;
    # store the inner config as one stable blob rather than guessing leaves.
    container = next(iter(payload.values())) if isinstance(payload, dict) else payload
    normalized = {"dhcp-config": {"value": container}}
    return {"raw": {"native/ip/dhcp": payload}, "normalized": normalized}


register(
    CheckDef(
        id="iosxe_dhcp",
        platform="iosxe",
        description="DHCP server/relay configuration (not-present when unused)",
        tier=3,
        compare={"mode": "equality_set"},
        miss_meaning=(
            "The switch's DHCP configuration changed — pools or relay behavior differ "
            "from the baseline."
        ),
        collector=_collect_dhcp_config,
        tags=("services",),
    )
)


# --- iosxe_syslog_errors (informational) --------------------------------------
# The finite logging buffer reduced to counts of error-and-worse events
# (%FACILITY-N-MNEMONIC, severity 0..3). What an analyst reads across captures
# is NOVELTY — an event type the baseline never logged. Severity 4+ (warnings,
# config notices) is deliberately not counted.

# IOS syslog tag %FACILITY-SEVERITY-MNEMONIC; only severities 0..3 match.
_SYSLOG_ERROR = re.compile(r"%([A-Z0-9_]+)-([0-3])-([A-Z0-9_]+)")

# The buffer is bounded, but raw artifacts should stay small: keep the tail,
# where the newest (most relevant) events live. Counting runs on full output.
_SYSLOG_RAW_TAIL_CHARS = 20000


def _parse_syslog_errors(text):
    """'sev<N>|%FAC-N-MNEMONIC' -> {'count': n} for severity<=3 events in the buffer."""
    counts = {}
    for facility, severity, mnemonic in _SYSLOG_ERROR.findall(text or ""):
        key = "sev%s|%%%s-%s-%s" % (severity, facility, severity, mnemonic)
        counts.setdefault(key, {"count": 0})["count"] += 1
    return counts


def _collect_syslog_errors(ctx):
    if not ctx.has_ssh:
        raise SkipCheck("no SSH transport")
    output = ctx.run_ssh("show logging")
    normalized = _parse_syslog_errors(output)
    context = {
        "error_events_total": sum(entry["count"] for entry in normalized.values()),
        "distinct_event_types": len(normalized),
    }
    raw = {"show logging": (output or "")[-_SYSLOG_RAW_TAIL_CHARS:]}
    return {"raw": raw, "normalized": normalized, "context": context}


register(
    CheckDef(
        id="iosxe_syslog_errors",
        platform="iosxe",
        description="Error-and-worse syslog event counts from the logging buffer",
        tier=3,
        compare={"mode": "info_only"},
        miss_meaning="",
        collector=_collect_syslog_errors,
        tags=("platform", "logs"),
    )
)


# --- iosxe_svl_health (always-on optional feature) ----------------------------
# The StackWise Virtual link is the virtual-switch backbone: every packet
# crossing chassis rides it. The 17.12.1 model nests location (keys fru/slot/
# bay/chassis/node) -> svl-link-info -> member-port lists, but leaf spellings
# drift across releases, so the walk recognizes members by shape rather than
# trusting one spelling; when it finds locations but no recognizable link
# fields it returns an empty view and the shakedown advisory drives refinement
# against the live payload.

_SVL_PATH = "/data/Cisco-IOS-XE-switch-cp-svl-oper:switch-cp-svl-oper-data"

# Leaf-name candidates, most-likely spelling first.
_SVL_LINK_NUM_LEAVES = ("link-num", "svl-link-num", "link-number")
_SVL_PORT_LEAVES = ("port-name", "if-name", "port", "name")
_SVL_BUNDLED_LEAVES = ("bundled", "is-bundled", "link-bundled")

# Identity and state leaves are never counters.
_SVL_NON_COUNTERS = frozenset(
    _SVL_LINK_NUM_LEAVES + _SVL_BUNDLED_LEAVES + ("fru", "slot", "bay", "chassis", "node")
)


def _first_leaf(entry, names):
    """First present-and-non-None leaf by candidate name; None when none exist."""
    for name in names:
        value = entry.get(name)
        if value is not None:
            return value
    return None


def _svl_bool(value):
    """Coerce a drift-prone bundled/state leaf to True/False; None when unreadable."""
    if isinstance(value, bool):
        return value
    text = str(value).strip().lower()
    if text in ("true", "yes", "1", "up", "ready"):
        return True
    if text in ("false", "no", "0", "down"):
        return False
    return None


def _svl_counters(node, counters):
    """Sum every numeric leaf under node into counters by leaf name, recursively.

    Which leaves are LMP/SDP counters varies by release; deltas are the
    analyst's job, so everything numeric is kept (bools and identities are not
    counters).
    """
    if isinstance(node, dict):
        for name, value in node.items():
            if isinstance(value, (dict, list)):
                _svl_counters(value, counters)
                continue
            if isinstance(value, bool) or name in _SVL_NON_COUNTERS:
                continue
            number = _to_int(value)
            if number is not None:
                counters[name] = counters.get(name, 0) + number
    elif isinstance(node, list):
        for item in node:
            _svl_counters(item, counters)


def _normalize_svl(payload):
    """('svl-link|<chassis>/<link-num>' view, 'counters|<link>' context) as a pair.

    Membership and bundled state are the comparable facts; every numeric leaf
    under a link sums into context — counters are informational, never
    equality-compared.
    """
    container = _container(payload, "Cisco-IOS-XE-switch-cp-svl-oper:switch-cp-svl-oper-data")
    container = container if isinstance(container, dict) else {}
    normalized = {}
    context = {}
    for location in _aslist(container.get("location")):
        if not isinstance(location, dict):
            continue
        chassis = _first_leaf(location, ("chassis", "node", "slot"))
        chassis = chassis if chassis is not None else "unknown"
        for link in _aslist(location.get("svl-link-info")):
            if not isinstance(link, dict):
                continue
            link_num = _first_leaf(link, _SVL_LINK_NUM_LEAVES)
            if link_num is None:
                continue
            link_id = "%s/%s" % (chassis, link_num)
            ports = []
            bundled_states = []
            for value in link.values():
                # Member-port list names drift; recognize members by shape.
                for member in _aslist(value):
                    if not isinstance(member, dict):
                        continue
                    port = _first_leaf(member, _SVL_PORT_LEAVES)
                    if port is not None:
                        ports.append(str(port))
                    bundled = _svl_bool(_first_leaf(member, _SVL_BUNDLED_LEAVES))
                    if bundled is not None:
                        bundled_states.append(bundled)
            entry = {}
            if ports:
                entry["member_ports"] = sorted(set(ports))
            if bundled_states:
                entry["bundled"] = all(bundled_states)
            normalized["svl-link|%s" % (link_id,)] = entry
            counters = {}
            _svl_counters(link, counters)
            if counters:
                context["counters|%s" % (link_id,)] = counters
    return normalized, context


def _collect_svl_health(ctx):
    payload = ctx.get(_SVL_PATH, ok_404=True)
    container = _container(payload, "Cisco-IOS-XE-switch-cp-svl-oper:switch-cp-svl-oper-data")
    if not container:
        raise SkipCheck("no StackWise Virtual data (not an SVL system)")
    normalized, context = _normalize_svl(payload)
    return {"raw": {"switch-cp-svl-oper": payload}, "normalized": normalized, "context": context}


register(
    CheckDef(
        id="iosxe_svl_health",
        platform="iosxe",
        description="StackWise Virtual links: member ports and bundled state per chassis/link.",
        tier=3,
        compare={"mode": "equality_set"},
        miss_meaning=(
            "An SVL link's membership or bundled state changed — the virtual-switch "
            "backbone degraded, which multiplies every other risk during a change."
        ),
        collector=_collect_svl_health,
        tags=("platform", "svl"),
    )
)


# --- iosxe_ntp (always-on) ----------------------------------------------------
# Time sync is the trust anchor for every timestamp this framework records.
# ntp-status-info leaf spellings drift across releases; emit only what is
# findable — an empty view is honest and the shakedown advisory drives
# refinement. Offset/delay/dispersion are jitter: raw only.

_NTP_PATH = "/data/Cisco-IOS-XE-ntp-oper:ntp-oper-data"

_NTP_SYNC_LEAVES = ("sys-status", "clock-state", "assoc-status", "status")
_NTP_STRATUM_LEAVES = ("sys-stratum", "stratum")
_NTP_REFID_LEAVES = ("sys-refid", "refid", "server")


def _ntp_selected_refid(status):
    """The selected (syspeer) association's refid/address, when one is marked."""
    for value in status.values():
        for assoc in _aslist(value):
            if not isinstance(assoc, dict):
                continue
            marker = str(_first_leaf(assoc, _NTP_SYNC_LEAVES) or "").lower()
            if "syspeer" not in marker.replace("-", ""):
                continue
            refid = _first_leaf(assoc, _NTP_REFID_LEAVES + ("address", "ip-address"))
            if refid is not None:
                return refid
    return None


def _normalize_ntp(payload):
    """Best-effort {'synchronized', 'stratum', 'server'} scalars from ntp-status-info."""
    container = _container(payload, "Cisco-IOS-XE-ntp-oper:ntp-oper-data") or {}
    status = container.get("ntp-status-info")
    status = status if isinstance(status, dict) else {}
    normalized = {}
    sync = _first_leaf(status, _NTP_SYNC_LEAVES)
    if sync is not None:
        normalized["synchronized"] = str(sync)
    stratum = _to_int(_first_leaf(status, _NTP_STRATUM_LEAVES))
    if stratum is not None:
        normalized["stratum"] = stratum
    server = _first_leaf(status, _NTP_REFID_LEAVES)
    if server is None:
        server = _ntp_selected_refid(status)
    if server is not None:
        normalized["server"] = str(server)
    return normalized


def _collect_ntp(ctx):
    payload = ctx.get(_NTP_PATH, ok_404=True)
    if not payload:
        raise SkipCheck("NTP oper data not available")
    return {"raw": {"ntp-oper": payload}, "normalized": _normalize_ntp(payload)}


register(
    CheckDef(
        id="iosxe_ntp",
        platform="iosxe",
        description="NTP sync status: synchronized state, stratum, selected server.",
        tier=3,
        compare={"mode": "equality_scalar"},
        miss_meaning=(
            "Time sync changed — timestamps in every other capture and in device logs "
            "become suspect."
        ),
        collector=_collect_ntp,
        tags=("services",),
    )
)


# --- iosxe_routing_config (approved: intended-change vs network-reaction) -----
# Captures what a human TYPED (static routes + router stanzas), not what the
# control plane decided — separating operator error from network behavior, and
# catching mid-window edits with no immediate RIB effect. Config is perfectly
# stable, so two healthy captures diff to nothing.

_SECRET_KEY_TOKENS = ("password", "secret", "community", "authentication-key", "auth-key")


def _scrub_secrets(node):
    """Recursively mask values whose key names suggest credentials.

    Router stanzas can carry neighbor passwords and auth keys; these artifacts
    get downloaded and pasted into LLM conversations, so secrets must never
    leave the device inside a snapshot. Masks in place, returns the node.
    """
    if isinstance(node, dict):
        for key in list(node):
            if any(token in key.lower() for token in _SECRET_KEY_TOKENS):
                node[key] = "***scrubbed***"
            else:
                _scrub_secrets(node[key])
    elif isinstance(node, list):
        for item in node:
            _scrub_secrets(item)
    return node


def _collect_routing_config(ctx):
    sections = (
        ("ip-route", "/data/Cisco-IOS-XE-native:native/ip/route"),
        ("ipv6-route", "/data/Cisco-IOS-XE-native:native/ipv6/route"),
        ("router", "/data/Cisco-IOS-XE-native:native/router"),
    )
    raw = {}
    normalized = {}
    for label, path in sections:
        payload = ctx.get(path, ok_404=True)
        raw[path] = payload
        if not payload:
            continue
        inner = next(iter(payload.values())) if isinstance(payload, dict) else payload
        normalized[label] = {"value": _scrub_secrets(inner)}
    if not normalized:
        raise SkipCheck("no static-route or router configuration present")
    return {"raw": raw, "normalized": normalized}


register(
    CheckDef(
        id="iosxe_routing_config",
        platform="iosxe",
        description="Static-route and router-stanza configuration (secrets scrubbed)",
        tier=2,
        compare={"mode": "equality_set"},
        miss_meaning=(
            "The routing CONFIGURATION changed — either the planned edit (verify it "
            "matches the change plan exactly) or a mid-window edit nobody declared. "
            "Config-vs-state separates operator error from network reaction."
        ),
        collector=_collect_routing_config,
        tags=("routing", "config"),
    )
)


# --- iosxe_config (the whole running-config + startup-config, redacted) -------
# The configuration as the operator reads it: `show running-config` and
# `show startup-config` over SSH. The CLI text is the ground truth — the
# native RESTCONF model is a translation of the running config, and the saved
# startup-config is not reachable through RESTCONF at all — and it covers
# everything the per-feature config checks slice out. Each text is ONE
# normalized object, {"lines": [...]}, so the pretty-printed snapshot stays
# readable in an editor and the text_diff compare mode reports a change as
# line-level hunks rather than one enormous changed value.
#
# Secrets: these artifacts are downloaded and pasted into LLM conversations,
# so every line is redacted before it is stored ANYWHERE — normalized,
# context, raw, error messages, and (through run_ssh's redact hook) the debug
# trace the Collector Shakedown attaches. The verbatim text never outlives
# one collection's local variables. Redaction is line by line: explicit
# rules for the known secret-bearing command shapes keep the keyword and the
# encryption-type digit (a type-7 password stays visibly type 7) and replace
# the value with the house marker, and a fail-closed catch-all masks the
# rest of any line holding a secret-looking word no rule explained.
# Over-redaction is acceptable; a leak is not.

_SECRET_MARK = "***scrubbed***"
# An IOS encryption-type digit between a secret keyword and its value (0
# cleartext, 4/5/8/9 hashes, 6 AES, 7 the reversible legacy cipher). Kept only
# when another token follows it — a lone trailing digit is the secret itself.
_TYPE_DIGIT = r"(?:\s+[045-9](?=\s+\S))?"
_TYPE_DIGIT_AT = re.compile(r"\s+[045-9](?=\s+\S)")
# A variable or option name that says it holds a secret: some '_', '-' or '.'
# separated part of it ends in one of these (TEAGENT_ACCOUNT_TOKEN,
# PROXY_PASS, _smtp_pw, _apikey, AUTH_TYPE). Used with IGNORECASE.
_SECRET_NAME = (
    r"(?:pass(?:wd|word|phrase)?|pwd|pw|secret|token|key|psk|pin|pmk|auth"
    r"|cred(?:ential)?s?|bearer|cookie)"
)

# Whole lines that carry a secret-looking word but, by their grammar, no
# secret; matched against the full line, so nothing else can ride along.
_BENIGN_CONFIG_LINES = tuple(
    re.compile(pattern)
    for pattern in (
        r"\s*(?:no\s+)?password\s+encryption\s+aes\s*",
        r"\s*security\s+passwords\s+min-length\s+\d+\s*",
        r"\s*ip\s+ssh\s+server\s+algorithm\s+authentication"
        r"(?:\s+(?:password|keyboard|publickey))+\s*",
        r"\s*mka\s+pre-shared-key\s+key-chain\s+\S+(?:\s+fallback\s+key-chain\s+\S+)?\s*",
        r"\s*ntp\s+trusted-key\s+\d+(?:\s*-\s*\d+)?\s*",  # key NUMBERS
        # BGP communities are routing attributes, not SNMP community strings.
        r"\s*ip\s+(?:ext|large-)?community-list\s.*",
        r"\s*ip\s+bgp-community\s+new-format\s*",
        r"\s*(?:set|match)\s+(?:ext|large-)?community(?:\s.*)?",
        r"\s*(?:neighbor\s+\S+\s+)?send-community(?:\s+(?:both|standard|extended|large))*\s*",
    )
)

# scheme://user:password@host in archive paths and kron/EEM copy commands:
# everything between '://' and the LAST '@' of the token goes, so an '@'
# inside the password cannot split it.
_URL_USERINFO = re.compile(r"(?P<scheme>\b[A-Za-z][A-Za-z0-9+.-]*://)\S*@")
# The same credential with no scheme: call-home's `mail-server
# user:password@host` (the SMTP login; Cisco-IOS-XE-call-home documents that
# format, either part possibly empty) and EEM `mail server "user:pw@host"`.
# From the token's start to its LAST '@' goes; a ':' followed by '//' is a
# URL the rule above has already masked.
_BARE_USERINFO = re.compile(r"(?<![^\s\"'(=,])[^\s\"'@:/]*:(?!//)\S*@")

# Full-line shapes whose secret is ONE token followed by keywords worth
# keeping; only that token is replaced. A line that misses its shape falls
# through to the mask rules below, which mask everything after the keyword.
_CONFIG_VALUE_RULES = (
    # ntp authentication-key <id> <algorithm> <value> [<type>] — the type TRAILS.
    # The algorithm is spelled out: an unknown second token must never be
    # mistaken for one and kept (the mask rules then take the whole tail).
    re.compile(
        r"(?P<keep>\s*ntp\s+(?P<kw>authentication-key)\s+\d+\s+"
        r"(?:md5|sha1|sha2|cmac-aes-128|hmac-sha1|hmac-sha2-256)\s+)(?P<secret>\S+)"
        r"(?P<rest>\s+[0-9])?\s*"
    ),
    # crypto isakmp key [<type>] <value> address <peer> [<mask>] [no-xauth] | hostname <name>
    re.compile(
        r"(?P<keep>\s*crypto\s+isakmp\s+(?P<kw>key)\s+(?:[045-9]\s+)?)(?P<secret>\S+)"
        r"(?P<rest>\s+(?:address|hostname)\s+\S+(?:\s+\S+)?(?:\s+no-xauth)?)\s*"
    ),
    # snmp-server community <string> [view <v>] [RO|RW] [ipv6 <acl>] [<acl>]; a
    # leading digit is masked WITH the string, never read as a type.
    re.compile(
        r"(?P<keep>\s*snmp-server\s+(?P<kw>community)\s+)(?P<secret>(?:[0-9]\s+)?\S+)"
        r"(?P<rest>(?:\s+view\s+\S+)?(?:\s+(?:RO|RW|ro|rw))?(?:\s+ipv6\s+\S+)?(?:\s+\S+)?)\s*"
    ),
)


def _benign_key(line, match, parent):
    """True where the bare word 'key' names or numbers a key instead of introducing one."""
    after = line[match.end("kw") :]
    if re.match(r"\s+chain\b", after) or re.fullmatch(r"\s*crypto\s+", line[: match.start("kw")]):
        return True  # `key chain <name>`, `crypto key pubkey-chain rsa`
    if re.match(r"\s*ntp\s+(?:server|peer)\b", line) and re.match(r"\s+\d+(?:\s|$)", after):
        return True  # `ntp server <address> key <key-id>`
    # ` key <id>` directly under `key chain <name>` numbers the key; its
    # key-string line carries the secret.
    return parent.startswith("key chain") and bool(re.fullmatch(r"\s+key\s+[0-9A-Fa-f]+\s*", line))


# (pattern, benign-predicate) pairs: after a match the rest of the line is
# secret. The 'kw' group is the keyword the rule explains (the catch-all does
# not cut there again); the match ends where masking starts, after any kept
# encryption-type digit.
_CONFIG_MASK_RULES = (
    # snmp-server host <addr> [vrf <v>] [informs|traps] [version 1|2c|3 [auth|noauth|priv]]
    # <community> ... — the v1/v2c community is positional, so everything past
    # the recognized keywords goes, notification types included.
    (
        re.compile(
            r"^\s*(?P<kw>snmp-server\s+host)\s+\S+(?:\s+vrf\s+\S+)?(?:\s+(?:informs|traps))?"
            r"(?:\s+version\s+(?:1|2c|3(?:\s+(?:auth|noauth|priv))?))?"
        ),
        None,
    ),
    # snmp-server user <u> <g> ... v3 auth <algorithm> <password> [priv <alg> <password>];
    # whichever of auth/priv comes first starts the mask. The key lengths are
    # the model's enumerations (sha-2 256|384|512, aes 128|192|256) and are
    # kept only when a password follows, so an all-digit password is never
    # mistaken for one.
    (
        re.compile(
            r"^\s*snmp-server\s+user\b.*?(?<![\w-])(?P<kw>auth|priv)(?![\w-])"
            r"(?:\s+(?:md5|sha-2(?:\s+(?:256|384|512)(?=\s+\S))?|sha|3des|des"
            r"|aes(?:\s+(?:128|192|256)(?=\s+\S))?))?"
        ),
        None,
    ),
    # HSRP/VRRP/GLBP plain-text authentication; the md5 forms carry a
    # key-string (the catch-all's) or a key-chain NAME (no secret).
    (
        re.compile(
            r"^\s*(?:standby|vrrp|glbp)(?:\s+\d+)?\s+(?P<kw>authentication)(?!\s+md5\b)"
            r"(?:\s+text)?"
        ),
        None,
    ),
    # OSPF (interface or virtual/sham link) message-digest-key <id> md5 [<type>] <value>
    (re.compile(r"\b(?P<kw>message-digest-key)(?:\s+\d+\s+md5)?" + _TYPE_DIGIT), None),
    # OSPFv3 IPsec: ... {authentication|encryption} ipsec spi <n> <algorithms and keys>
    (re.compile(r"\b(?P<kw>(?:authentication|encryption)\s+ipsec\s+spi\s+\d+)"), None),
    # Named-mode EIGRP: authentication mode hmac-sha-256 [<type>] <password>
    (re.compile(r"\b(?P<kw>authentication\s+mode\s+hmac-sha-256)" + _TYPE_DIGIT), None),
    (re.compile(r"\b(?P<kw>(?:ip|ipv6)\s+nhrp\s+authentication)\b"), None),
    # 9800 WLAN PSK / MPSK: [psk] set-key {ascii|hex} [<type>] <value>
    (re.compile(r"(?P<kw>(?:\bpsk\s+)?\bset-key)(?:\s+(?:ascii|hex))?" + _TYPE_DIGIT), None),
    (re.compile(r"\b(?P<kw>wpa-psk)(?:\s+(?:ascii|hex))?" + _TYPE_DIGIT), None),
    # IKEv2 keyring pre-shared-key [local|remote] [<type>] <value>; IKEv1
    # keyring pre-shared-key {address|hostname} <peer> [<mask>] key [<type>] <value>
    (
        re.compile(
            r"\b(?P<kw>pre-shared-key)(?:\s+(?:local|remote))?"
            r"(?:\s+(?:address|hostname)\s+\S+(?:\s+\S+)?\s+key\b)?" + _TYPE_DIGIT
        ),
        None,
    ),
    # IKEv2 profile: authentication {local|remote} pre-share key [<type>] <value>
    (re.compile(r"\b(?P<kw>pre-share\s+key)" + _TYPE_DIGIT), None),
    # Umbrella/OpenDNS parameter-map device token
    (re.compile(r"^\s*(?P<kw>token)\b"), None),
    (re.compile(r"(?<![\w-])(?P<kw>cak)(?![\w-])" + _TYPE_DIGIT), None),
    # HTTP credentials in a raw request (IP SLA http-raw-request lines).
    (
        re.compile(
            r"(?<![\w-])(?P<kw>(?:proxy-)?authorization|(?:set-)?cookie)\s*:", re.IGNORECASE
        ),
        None,
    ),
    # A variable named for a secret: EEM `event manager environment _smtp_pw
    # <value>`, and NAME=VALUE options such as the ThousandEyes agent's
    # app-hosting `run-opts 1 "-e TEAGENT_ACCOUNT_TOKEN=<token>"`.
    (
        re.compile(
            r"^\s*event\s+manager\s+environment\s+(?P<kw>\S*?" + _SECRET_NAME + r"(?![^_.\s-])\S*)",
            re.IGNORECASE,
        ),
        None,
    ),
    (
        re.compile(
            r"(?<![^\s\"'(,;:=?&/])(?P<kw>[\w.-]*?" + _SECRET_NAME + r"(?![^_.=-])[\w.-]*)(?==)",
            re.IGNORECASE,
        ),
        None,
    ),
    # The bare word 'key' (lowercase, as IOS prints keywords): tacacs/radius
    # server `key [6|7] <value>`, `pac key`, tacacs-server/radius-server key,
    # server-private ... key, crypto isakmp client group `key`, key
    # config-key, tunnel key, LISP map-server and fabric control-plane keys.
    (re.compile(r"(?<![\w-])(?P<kw>key)(?![\w-])" + _TYPE_DIGIT), _benign_key),
)

# Fail-closed catch-all: a token holding one of these words (any case) that
# no rule explained masks the rest of its line — descriptions, banners,
# remarks, EEM strings and commands no rule knows included. Besides the plain
# words (token covers auth-token, idtoken, the 9800's `nmsp cloud-services
# server token` and DNA/WSA tokens): any compound on '-key' or '_key'
# (server-key, session-key, api-key, authentication-key, _api_key ...) or
# '-pin'/'_pin' (user-pin), and a bare 'pin' or 'pmk' (TrustSec SAP's
# Pre-Master Key, the switch-to-switch MACsec keying beside MKA: interface
# `cts manual` / ` sap pmk <key> [mode-list ...]`, and ` default pmk [0|6]
# <key>` — Cisco-IOS-XE-cts; the type digit stays). As whole words only,
# the shorthand free text uses ("pw ...", "pass: ...", "creds: ..."), and a
# 'Key' that labels a value ("Key: ...", "KEY=...") — never 'Key West'.
_CATCH_ALL_WORDS = re.compile(
    r"password|passwd|secret|community|passphrase|psk|pre-share|key-string|token|bearer"
    r"|keyhash|(?<=[A-Za-z0-9])[-_](?:key|pin)|(?<![A-Za-z0-9-])(?:pin|pmk)(?![A-Za-z])"
    r"|(?<![\w-])(?:pw|pwd|pass|passcode|creds?)(?![\w-])|(?<![\w-])key(?=[:=])",
    re.IGNORECASE,
)
# What may follow the word inside its token and leave the token an IOS
# keyword (password-encryption, community-map, psk-sha256, passwords,
# "Password:") — the cut then falls after the token. Anything else is taken
# for a value glued onto the word (password=x, password-x, key-string:x) and
# the cut falls right after the word.
_KEYWORD_TAIL = re.compile(r"(?:s|-encryption|-recovery|-prompt|-list|-map|-sha\d+)?[\"'():;,.]*")
_TOKEN = re.compile(r"\S+")

# Grammar-fixed tokens the catch-all must not cut at. On these lines an
# operator-chosen name — a route-map, prefix-list, ACL, class or policy, VRF,
# VLAN, user, key chain, server group, or a 9800 WLAN's profile, SSID and
# policy profile — sits at a fixed place from the start of the line. A
# secret-looking word inside it (SET-COMMUNITY, CORP-PSK, PL-KEY-SERVERS)
# would otherwise mask the rest of the line and hide a real change — a
# permit turned deny, a WLAN moved to another policy profile — from the diff
# and from in_sync. Anchored at the line start, so a description, remark or
# EEM string never forms one, and never applied inside a banner's text; the
# explicit rules above still see every token, and a secret word elsewhere on
# the line still masks.
_CONFIG_NAME_POSITIONS = tuple(
    re.compile(pattern)
    for pattern in (
        r"\s*(?:no\s+)?route-map\s+(?P<n1>\S+)",
        r"\s*(?:ip|ipv6)\s+prefix-list\s+(?P<n1>\S+)",
        r"\s*(?:ip|ipv6|mac)\s+access-list\s+(?:(?:standard|extended|role-based)\s+)?(?P<n1>\S+)",
        r"\s*(?:ip|ipv6)\s+(?:access-group|traffic-filter)\s+(?P<n1>\S+)",
        r"\s*(?:ipv6\s+)?access-class\s+(?P<n1>\S+)",
        r"\s*class-map\s+(?:type\s+\S+\s+)?(?:match-(?:any|all|none)\s+)?(?P<n1>\S+)",
        r"\s*policy-map\s+(?:type\s+(?:control\s+subscriber|\S+)\s+)?(?P<n1>\S+)",
        r"\s*class\s+(?:type\s+\S+\s+)?(?P<n1>\S+)",
        r"\s*service-policy\s+(?:type\s+(?:control\s+subscriber|\S+)\s+)?"
        r"(?:(?:input|output)\s+)?(?P<n1>\S+)",
        r"\s*(?:vrf\s+(?:definition|forwarding|member)|ip\s+vrf(?:\s+forwarding)?)\s+(?P<n1>\S+)",
        r"\s*address-family\s+\S+(?:\s+(?:unicast|multicast))?\s+vrf\s+(?P<n1>\S+)",
        r"\s*name\s+(?P<n1>\S+)",
        r"\s*username\s+(?P<n1>\S+)",
        r"\s*key\s+chain\s+(?P<n1>\S+)",
        r"\s*neighbor\s+(?P<n1>\S+)"
        r"(?:\s+(?:route-map|prefix-list|peer-group|filter-list)\s+(?P<n2>\S+))?",
        r"\s*match\s+(?:ip|ipv6)\s+address\s+(?:prefix-list\s+)?(?P<n1>\S+)",
        r"\s*redistribute\s+\S+(?:\s+\S+)*?\s+route-map\s+(?P<n1>\S+)",
        r"\s*(?:ip\s+policy|default-information\s+originate(?:\s+always)?)\s+route-map"
        r"\s+(?P<n1>\S+)",
        r"\s*wlan\s+(?P<n1>\S+)(?:\s+\d+\s+(?P<n2>\S+)|\s+policy\s+(?P<n3>\S+))?",
        r"\s*(?:wireless\s+(?:tag|profile)\s+\S+|policy-tag|site-tag|rf-tag)\s+(?P<n1>\S+)",
        r"\s*aaa\s+group\s+server\s+\S+\s+(?P<n1>\S+)",
        # `crypto pki token <label> ...`: 'token' names a USB token here; its
        # user-pin still masks.
        r"\s*crypto\s+pki\s+(?P<n1>token)\s+(?P<n2>\S+)",
    )
)


# A name is an identifier: anything else in a name position (a glued
# 'password=x', a quoted string) gets no exemption.
_CONFIG_NAME = re.compile(r"[\w.-]+")


def _name_spans(line):
    """Spans of the grammar-fixed name tokens on one (non-free-text) line."""
    spans = []
    for rule in _CONFIG_NAME_POSITIONS:
        match = rule.match(line)
        if match is None:
            continue
        for name, value in match.groupdict().items():
            if value and _CONFIG_NAME.fullmatch(value):
                spans.append(match.span(name))
    return spans


def _catch_all_cut(line, explained, cut):
    """Where the first unexplained secret-looking token starts masking, capped at ``cut``."""
    for token in _TOKEN.finditer(line):
        if cut is not None and token.start() >= cut:
            break
        text = token.group()
        hit = _CATCH_ALL_WORDS.search(text)
        if hit is None:
            continue
        offset = len(text) if _KEYWORD_TAIL.fullmatch(text[hit.end() :]) else hit.end()
        if any(start < token.end() and token.start() < end for start, end in explained):
            continue
        position = token.start() + offset
        digit = _TYPE_DIGIT_AT.match(line, position)
        if digit is not None:
            position = digit.end()
        return position if cut is None else min(cut, position)
    return cut


def _redact_config_line(line, parent="", free_text=False):
    """One configuration line with every secret value replaced by the house marker.

    ``parent`` is the enclosing top-level line (a key chain's key numbers are
    not secrets); ``free_text`` marks a line of a banner's text, where no
    token is a grammar-fixed name. A line holding nothing secret-looking
    comes back unchanged.
    """
    if any(rule.fullmatch(line) for rule in _BENIGN_CONFIG_LINES):
        return line
    line = _URL_USERINFO.sub(lambda match: match.group("scheme") + _SECRET_MARK + "@", line)
    line = _BARE_USERINFO.sub(_SECRET_MARK + "@", line)
    explained = []
    cut = None
    for rule in _CONFIG_VALUE_RULES:
        match = rule.fullmatch(line)
        if match is not None:
            explained.append(match.span("kw"))
            line = match.group("keep") + _SECRET_MARK + (match.group("rest") or "")
            break
    else:
        for rule, benign in _CONFIG_MASK_RULES:
            for match in rule.finditer(line):
                explained.append(match.span("kw"))
                if benign is not None and benign(line, match, parent):
                    continue
                if cut is None or match.end() < cut:
                    cut = match.end()
                break
    if not free_text and _CATCH_ALL_WORDS.search(line):
        explained.extend(_name_spans(line))
    cut = _catch_all_cut(line, explained, cut)
    if cut is None or not line[cut:].strip():
        return line
    return line[:cut].rstrip() + " " + _SECRET_MARK


# EEM applets that answer a CLI prompt: an action that waits for a prompt
# (`cli command "..." pattern "..."`) is followed by a `cli command` action
# whose whole argument is the answer — a password as often as an address or
# a file name (`pattern "word:"`, `pattern ":"`), with no keyword on its own
# line — so every such answer is masked; an empty "" answer (just Enter)
# stays.
_EEM_PROMPT = re.compile(r"\bcli\s+command\b.*\bpattern\b")
_EEM_CLI_COMMAND = re.compile(r"\bcli\s+command\b")
_EEM_EMPTY_ANSWER = re.compile(r'\s*""(?:\s|$)')
# IOS prints a banner's (and a line's vacant/refuse message's) delimiter as
# ^C: the text between an opening and a closing ^C is free text.
_TEXT_DELIMITER = "^C"


def _redact_config_lines(lines):
    """Redact configuration lines one by one; the result aligns 1:1 with the input.

    Three facts carry from line to line: the enclosing top-level line, whether
    the line sits inside a ^C-delimited banner text, and inside an EEM applet
    a pending prompt, whose answer is the argument of the next `cli command`
    action.
    """
    redacted = []
    parent = ""
    answer_pending = False
    in_text = False
    for line in lines:
        free_text = in_text
        if line.count(_TEXT_DELIMITER) % 2:
            in_text = not in_text
        if not free_text and line[:1] not in ("", " ", "\t", "!"):
            parent = line.strip()
            answer_pending = False  # a new stanza: no prompt carries over
        out = _redact_config_line(line, parent, free_text=free_text)
        if parent.startswith("event manager applet"):
            command = _EEM_CLI_COMMAND.search(out) if answer_pending else None
            if command is not None:
                answer_pending = False
                answer = out[command.end() :]
                if answer.strip() and not _EEM_EMPTY_ANSWER.match(answer):
                    out = out[: command.end()] + " " + _SECRET_MARK
            if _EEM_PROMPT.search(line):
                answer_pending = True
        redacted.append(out)
    return redacted


def _redact_config_text(text):
    """Whole-output form of _redact_config_lines — also ctx.run_ssh's trace hook."""
    return "\n".join(_redact_config_lines(str(text).splitlines()))


# Framing IOS prints around the configuration, never part of it, and each
# line changes without a configuration change: the byte counts move with
# every edit and differ between running and startup by construction, and the
# comment lines move with every edit, save and reload. They are dropped from
# the normalized text and their facts lifted into context; the '!'
# separators around them are text and stay.
_CONFIG_HEADER = tuple(
    (re.compile(pattern), constant)
    for pattern, constant in (
        (r"Building configuration\.\.\.", {}),
        (r"Current configuration\s*:\s*(?P<bytes>\d+)\s+bytes", {}),
        (
            r"Using\s+(?P<bytes>\d+)\s+out\s+of\s+(?P<nvram_bytes_total>\d+)\s+bytes"
            r"(?:,\s*uncompressed\s+size\s*=\s*(?P<uncompressed_bytes>\d+)\s+bytes)?",
            {},
        ),
        (
            r"Uncompressed configuration from\s+\d+\s+bytes\s+to\s+"
            r"(?P<uncompressed_bytes>\d+)\s+bytes",
            {},
        ),
        (
            r"! Last configuration change at (?P<last_change_at>.+?)"
            r"(?: by (?P<last_change_by>.+?))?",
            {},
        ),
        (
            r"! NVRAM config last updated at (?P<nvram_updated_at>.+?)"
            r"(?: by (?P<nvram_updated_by>.+?))?",
            {},
        ),
        (r"! No configuration change since last restart", {"no_change_since_restart": True}),
        # `exec prompt timestamp` on the vty lines prefixes every show output
        # with the CPU load and the clock — different on every capture.
        (r"Load for five secs:.*", {}),
        (r"(?:Time source is |No time source, ).*", {}),
        # netmiko's echo of the command, should one ever survive strip_command
        (r"(?:[\w.:/()-]+[#>])?\s*show\s+(?:running|startup)-config", {}),
    )
)
# The one body line known to change with no configuration change: IOS
# rewrites `ntp clock-period` as NTP disciplines the clock (and saves the
# value of the moment with every `write memory`), so it would diff between
# two healthy captures.
_CONFIG_VOLATILE_BODY = re.compile(r"ntp\s+clock-period\s+\d+")
# A trailing CLI prompt netmiko failed to strip ("switch#").
_PROMPT_LINE = re.compile(r"[\w.:/()-]+[#>]")
# Never saved ("startup-config is not present"), or no NVRAM file to read.
_STARTUP_ABSENT = re.compile(r"\bnot present\b|no such file or directory", re.IGNORECASE)
# How IOS refuses a command (a privilege or command-authorization boundary),
# as opposed to answering it.
_CLI_REFUSAL = re.compile(
    r"invalid input|incomplete command|ambiguous command|authorization failed"
    r"|not authorized|permission denied|access denied",
    re.IGNORECASE,
)
_PRIVILEGE_LINE = re.compile(r"Current privilege level is (\d+)")
# Lines of the startup-vs-running unified diff kept in raw (redacted text).
_CONFIG_DIFF_RAW_LINES = 2000
_CONFIGS = (("running-config", "show running-config"), ("startup-config", "show startup-config"))


def _config_end(lines):
    """Index of the configuration's final 'end' line; None when the text stops short.

    Only blank lines, or one CLI prompt netmiko left behind, may follow it.
    """
    texts = [index for index, line in enumerate(lines) if line.strip()]
    if texts and lines[texts[-1]].strip() == "end":
        return texts[-1]
    if (
        len(texts) >= 2
        and _PROMPT_LINE.fullmatch(lines[texts[-1]].strip())
        and lines[texts[-2]].strip() == "end"
    ):
        return texts[-2]
    return None


def _classify_config_output(lines, startup):
    """What one config command answered: (kind, detail).

    'config' (detail: index of the final 'end'), 'absent' (startup only, never
    saved), 'rejected' (the refusal line), 'error' (startup only: the device's
    %-message), 'truncated' (the first line) or 'empty'. A refusal or an
    error is a short answer, judged without the framing a show prints around
    any answer (exec prompt timestamp lines, a leftover command echo or
    prompt); anything else without its final 'end' is a read cut short, and
    on the running side a device error too — never a configuration.
    """
    texts = [line.strip() for line in lines if line.strip()]
    if not texts:
        return "empty", None
    end = _config_end(lines)
    if end is not None:
        return "config", end
    answer = [
        text
        for text in texts
        if _config_header_facts(text) is None and not _PROMPT_LINE.fullmatch(text)
    ]
    if not answer:
        return "empty", None
    if len(answer) <= 5:
        for text in answer:
            if startup and _STARTUP_ABSENT.search(text):
                return "absent", text
        for text in answer:
            if _CLI_REFUSAL.search(text):
                return "rejected", text
        # NVRAM busy (a save or archive in progress) or unreadable (bad
        # checksum): the saved side is unknown, the running text still good.
        if startup and answer[0].startswith("%"):
            return "error", answer[0]
    return "truncated", texts[0]


def _config_header_facts(text):
    """The facts one header line states, or None when the line is configuration."""
    for pattern, constant in _CONFIG_HEADER:
        match = pattern.fullmatch(text)
        if match is None:
            continue
        facts = dict(constant)
        for name, value in match.groupdict().items():
            if value is not None:
                facts[name] = int(value) if name.endswith(("bytes", "bytes_total")) else value
        return facts
    return None


def _config_body(lines, end):
    """(indexes of the normalized text, lifted header facts, volatile lines dropped).

    The header region is the leading run of blank, '!' and header lines —
    blank and header lines are dropped there, '!' lines kept. The body runs
    from the first other line through the final 'end'.
    """
    keep = []
    facts = {}
    index = 0
    while index < end:
        text = lines[index].strip()
        if text == "!":
            keep.append(index)
        elif text:
            header = _config_header_facts(text)
            if header is None:
                break
            facts.update(header)
        index += 1
    volatile = 0
    for position in range(index, end + 1):
        if _CONFIG_VOLATILE_BODY.fullmatch(lines[position].strip()):
            volatile += 1
        else:
            keep.append(position)
    return keep, facts, volatile


def _ssh_failure(command, exc):
    """A redacted one-line account of a failed SSH read (the error text may echo output)."""
    return "'%s' failed: %s" % (command, _redact_config_text("%s: %s" % (type(exc).__name__, exc)))


def _config_read(ctx, command, **kwargs):
    """One SSH read traced through the redact hook; a failure fails the check, redacted."""
    try:
        output = ctx.run_ssh(command, redact=_redact_config_text, **kwargs)
    except Exception as exc:
        if type(exc).__name__ == "SoftTimeLimitExceeded":
            raise  # the Celery abort signal is never wrapped
        raise CollectError(_ssh_failure(command, exc)) from None
    return output if isinstance(output, str) else ""


def _session_privilege(ctx, raw, notes):
    """This session's privilege level from `show privilege` (best-effort; None when unread)."""
    command = "show privilege"
    try:
        output = _config_read(ctx, command)
    except CollectError as exc:
        notes.append(str(exc))
        return None
    raw[command] = _redact_config_lines(output.splitlines())
    match = _PRIVILEGE_LINE.search(output)
    if match is None:
        first = next((line.strip() for line in output.splitlines() if line.strip()), "")
        notes.append(
            "'%s' reported no privilege level: %s" % (command, _redact_config_line(first)[:120])
        )
        return None
    return int(match.group(1))


def _unsaved_config_leaf(ctx):
    """(value, note) of device-system-data's unsaved-config leaf; (None, None) when not served.

    Read from the hardware GET platform-health and the stack check make —
    identical path and kwargs, so the per-run cache answers it without a
    request of its own. Defined in the 17.9.1 and 17.12.1 models; the
    committed 17.12.04 capture does not carry it.
    """
    try:
        payload = ctx.get(_HW_PATH)
    except Exception as exc:
        if type(exc).__name__ == "SoftTimeLimitExceeded":
            raise
        return None, "device-hardware read for the unsaved-config leaf failed: %s" % (exc,)
    container = _container(payload, "Cisco-IOS-XE-device-hardware-oper:device-hardware-data")
    hardware = container.get("device-hardware") if isinstance(container, dict) else None
    system = hardware.get("device-system-data") if isinstance(hardware, dict) else None
    value = system.get("unsaved-config") if isinstance(system, dict) else None
    if isinstance(value, bool):
        return value, None
    if str(value).lower() in ("true", "false"):
        return str(value).lower() == "true", None
    return None, None


def _config_delta(startup, running):
    """(lines only in running, lines only in startup, capped unified diff) of two bodies."""
    only_running = only_startup = 0
    for tag, i1, i2, j1, j2 in difflib.SequenceMatcher(None, startup, running).get_opcodes():
        if tag != "equal":
            only_startup += i2 - i1
            only_running += j2 - j1
    diff = list(
        difflib.unified_diff(startup, running, "startup-config", "running-config", lineterm="")
    )
    if len(diff) > _CONFIG_DIFF_RAW_LINES:
        dropped = len(diff) - _CONFIG_DIFF_RAW_LINES
        diff = diff[:_CONFIG_DIFF_RAW_LINES] + ["... [%d more diff lines truncated]" % (dropped,)]
    return only_running, only_startup, diff


def _collect_config(ctx):
    if not ctx.has_ssh:
        raise SkipCheck("no SSH transport")
    raw = {}
    context = {}
    notes = []
    texts = {}  # label -> (redacted body, verbatim body); verbatim never leaves here
    unread = {}  # label -> why the device gave no text: its refusal or error (redacted)
    for label, command in _CONFIGS:
        lines = _config_read(ctx, command, timeout=C.SSH_CONFIG_READ_TIMEOUT).splitlines()
        kind, detail = _classify_config_output(lines, startup=label == "startup-config")
        if kind == "empty":
            raise CollectError("'%s' returned no output" % (command,))
        if kind == "truncated":
            raise CollectError(
                "'%s' output has no final 'end' (%d lines received, starting %r) — a read "
                "cut short or a device error; nothing stored"
                % (command, len(lines), _redact_config_line(detail)[:120])
            )
        redacted = _redact_config_lines(lines)
        raw[command] = redacted
        if kind == "absent":
            context[label] = {"present": False, "device_says": _redact_config_line(detail)[:200]}
            continue
        if kind in ("rejected", "error"):
            unread[label] = "'%s' %s: %s" % (
                command,
                "rejected" if kind == "rejected" else "answered with a device error",
                _redact_config_line(detail)[:200],
            )
            context[label] = {"error": unread[label]}
            continue
        keep, facts, volatile = _config_body(lines, detail)
        body = [redacted[index] for index in keep]
        texts[label] = (body, [lines[index] for index in keep])
        facts["line_count"] = len(body)
        if volatile:
            facts["volatile_lines_stripped"] = volatile
        context[label] = facts
    if not texts:
        # Every IOS-XE device has a running-config, so reading none is a failed
        # read (registry doctrine), never an absence — typically an account
        # below privilege 15 or refused by command authorization.
        reasons = [unread[label] for label, _command in _CONFIGS if label in unread]
        if "startup-config" not in unread:
            reasons.append("startup-config is not present")
        raise CollectError(
            "no configuration text readable (check the account's privilege and command "
            "authorization): %s" % ("; ".join(reasons),)
        )

    privilege = _session_privilege(ctx, raw, notes)
    running = texts.get("running-config")
    startup = texts.get("startup-config")
    if privilege is not None:
        context["session_privilege"] = privilege
        if privilege < 15 and running is not None:
            notes.append(
                "session privilege %d is below 15: IOS shows a lower-privileged session only "
                "the configuration it may itself use, so running-config may be partial"
                % (privilege,)
            )
    if running is not None:
        if "bytes" not in context["running-config"]:
            notes.append(
                "running-config printed no 'Current configuration' header — the text may be "
                "partial (a privilege-limited view)"
            )
        if not any(line.startswith("version ") for line in running[0]):
            notes.append("running-config has no 'version' line — the text may be partial")

    sync = {}
    if running is not None and startup is not None:
        in_sync = running[0] == startup[0]
        # The same comparison before redaction, as one bit: false while
        # in_sync is true means only a masked value differs — a rotated TACACS
        # key or SNMP community that was never saved, which the redacted texts
        # (and so the hunks) cannot show, and which a reload would undo.
        verbatim_in_sync = running[1] == startup[1]
        only_running, only_startup, diff = _config_delta(startup[0], running[0])
        sync["only_in_running"] = only_running
        sync["only_in_startup"] = only_startup
        if diff:
            raw["startup-vs-running diff"] = diff
    elif running is not None and "startup-config" not in unread:
        # never saved: nothing on NVRAM matches the running text
        in_sync = verbatim_in_sync = False
    else:
        in_sync = verbatim_in_sync = None  # one side unread: unknown, never a guess
    leaf, leaf_note = _unsaved_config_leaf(ctx)
    if leaf is not None:
        sync["unsaved_config_leaf"] = leaf
    if leaf_note:
        notes.append(leaf_note)
    context["running-vs-startup"] = sync
    if notes:
        context["notes"] = notes

    normalized = {
        label: {"lines": texts[label][0]} for label, _command in _CONFIGS if label in texts
    }
    normalized["running-vs-startup"] = {"in_sync": in_sync, "verbatim_in_sync": verbatim_in_sync}
    return {"raw": raw, "normalized": normalized, "context": context}


register(
    CheckDef(
        id="iosxe_config",
        platform="iosxe",
        description=(
            "Full running-config and startup-config text (secrets redacted) and whether they match"
        ),
        tier=2,
        compare={"mode": "text_diff"},
        miss_meaning=(
            "The configuration TEXT changed — each contiguous run of changed lines is its own "
            "hunk: the planned edit (verify it matches the change plan exactly) or an edit "
            "nobody declared. A running-config change without the same startup-config change "
            "was not saved and does not survive a reload."
        ),
        collector=_collect_config,
        tags=("config",),
    )
)


# --- iosxe_optics + iosxe_crash_files (approved TAC-lens additions) -----------

_OPTICS_TABLE_LINE = re.compile(
    r"^(\S+\d\S*)\s+(-?[\d.]+)\s+(-?[\d.]+)\s+(-?[\d.]+)\s+(-?[\d.]+|N/A)\s+(-?[\d.]+|N/A)\s*$"
)


def _parse_optics_table(cli_output):
    """Bare 'show interfaces transceiver' combined table -> {iface: {tx_dbm, rx_dbm}}."""
    normalized = {}
    for line in (cli_output or "").splitlines():
        match = _OPTICS_TABLE_LINE.match(line.strip())
        if not match:
            continue
        iface, _temp, _volt, _cur, tx, rx = match.groups()
        if "/" not in iface:
            continue
        value = {}
        if tx != "N/A":
            value["tx_dbm"] = float(tx)
        if rx != "N/A":
            value["rx_dbm"] = float(rx)
        if value:
            normalized[iface] = value
    return normalized


# Detail-format sections we keep; everything else (temperature/voltage/
# current) is environmental jitter and stays in raw.
_OPTICS_SECTIONS = (
    ("transmit power", "tx"),
    ("receive power", "rx"),
    ("temperature", None),
    ("voltage", None),
    ("current", None),
)
# Value line: port, current value, then an optional threshold-violation marker
# (++ high alarm, -- low alarm, + / - warns). Lookaheads keep a single +/-
# marker from swallowing the sign of the negative THRESHOLD that follows.
_OPTICS_DETAIL_LINE = re.compile(r"^(\S+\d/\S*)\s+(-?[\d.]+)\s*(\+\+|--|\+(?![\d.])|-(?![\d.]))?")


def _parse_optics_detail(cli_output):
    """'show interfaces transceiver detail' -> {iface: {tx_dbm, rx_dbm, *flags}}.

    Field-verified format: detail prints SEPARATE per-metric tables, each
    port per line with the live value, threshold columns, and a violation
    marker beside out-of-range values — the marker rides along as
    tx_flag/rx_flag (an alarm the optic itself is raising).
    """
    normalized = {}
    section = None
    for line in (cli_output or "").splitlines():
        lowered = line.lower()
        matched_section = False
        for token, tag in _OPTICS_SECTIONS:
            if token in lowered:
                section = tag
                matched_section = True
                break
        if matched_section:
            continue
        if section is None:
            continue
        match = _OPTICS_DETAIL_LINE.match(line.strip())
        if not match:
            continue
        iface, value, flag = match.groups()
        entry = normalized.setdefault(iface, {})
        entry["%s_dbm" % (section,)] = float(value)
        if flag:
            entry["%s_flag" % (section,)] = flag
    return {iface: entry for iface, entry in normalized.items() if entry}


def _collect_optics(ctx):
    if not ctx.has_ssh:
        raise SkipCheck("no SSH transport")
    raw = {}
    accepted = False
    # Field-verified: this platform requires the `detail` keyword (the bare
    # form answers "Incomplete command"); other platforms accept the bare
    # combined table, kept as the fallback.
    for command, parser in (
        ("show interfaces transceiver detail", _parse_optics_detail),
        ("show interfaces transceiver", _parse_optics_table),
    ):
        output = ctx.run_ssh(command)
        raw[command] = output
        lowered = (output or "").lower()
        if "invalid input" in lowered or "incomplete command" in lowered:
            continue
        accepted = True
        normalized = parser(output)
        if normalized:
            return {"raw": raw, "normalized": normalized}
    if accepted:
        raise SkipCheck("no DOM-capable transceivers reported (or format needs shakedown)")
    raise SkipCheck("transceiver command forms rejected on this platform")


_MONTHS = {
    "Jan": 1,
    "Feb": 2,
    "Mar": 3,
    "Apr": 4,
    "May": 5,
    "Jun": 6,
    "Jul": 7,
    "Aug": 8,
    "Sep": 9,
    "Oct": 10,
    "Nov": 11,
    "Dec": 12,
}
# `dir` listing line: "  14  -rw-  123456   Aug 24 2026 18:22:11 +00:00  name".
# The permissions column is captured so directories ("drwx") can be told
# apart from files: field-verified on a 9300 stack, crashinfo:tracelogs is a
# directory rewritten by routine logging and read as a same-day "crash" on
# every member until directories were excluded.
_DIR_LINE = re.compile(
    r"^\s*\d+\s+(\S+)\s+\d+\s+([A-Z][a-z]{2})\s+(\d+)\s+(\d{4})\s+[\d:]+\s+\S*\s*(\S+)\s*$"
)


def _parse_crash_dir(cli_output, now, recent_days):
    """(recent {name: {modified}}, older_count) from a `dir crashinfo:` listing.

    Only files inside the recency window become normalized keys — a fresh
    crash during a change window must surface as an ADDED key, while ancient
    dumps must never create diff noise (operator requirement). Directories
    are neither keyed nor counted: crash dumps and system reports are files,
    while a directory's date moves whenever anything inside it is written
    (tracelogs/ on every member). Unparseable dates fail safe: included as
    recent with the raw date string.
    """
    recent = {}
    older = 0
    for line in (cli_output or "").splitlines():
        match = _DIR_LINE.match(line)
        if not match:
            continue
        perms, month, day, year, name = match.groups()
        if perms.lower().startswith("d"):
            continue
        if name.lower() in ("core", "crashinfo:", ".", ".."):
            continue
        month_num = _MONTHS.get(month)
        if month_num is None:
            recent[name] = {"modified": "%s %s %s" % (month, day, year)}
            continue
        modified = datetime(int(year), month_num, int(day), tzinfo=timezone.utc)
        if (now - modified).days <= recent_days:
            recent[name] = {"modified": modified.strftime("%Y-%m-%d")}
        else:
            older += 1
    return recent, older


def _dir_listed(output):
    """True when a `dir` answered with a listing — not a refusal or an open error."""
    lowered = (output or "").lower()
    if _cli_rejected(output):
        return False
    return not ("error" in lowered and "directory" not in lowered)


def _crash_listing(ctx, command, side, now, raw, normalized):
    """List one crashinfo filesystem into raw/normalized; (listed, older_count).

    An absent filesystem (no standby, a removed or provisioned member) answers
    with an open error: recorded in raw, nothing normalized, never a failure.
    """
    output = ctx.run_ssh(command)
    raw[command] = output
    if not _dir_listed(output):
        return False, 0
    recent, older = _parse_crash_dir(output, now, C.CRASH_RECENT_DAYS)
    for name, value in recent.items():
        normalized["%s|%s" % (side, name)] = value
    return True, older


def _collect_crash_files(ctx, now=None):
    if not ctx.has_ssh:
        raise SkipCheck("no SSH transport")
    if now is None:
        now = datetime.now(timezone.utc)
    raw = {}
    normalized = {}
    older_total = 0
    listed = []
    # The two role aliases: crashinfo: is the active member's own
    # crashinfo-<N>:, stby-crashinfo: the standby's.
    alias_listed = {}
    for command, side in (("dir crashinfo:", "active"), ("dir stby-crashinfo:", "stby")):
        ok, older = _crash_listing(ctx, command, side, now, raw, normalized)
        alias_listed[side] = ok
        older_total += older
        if ok:
            listed.append(command.split(None, 1)[1])

    # Every other stack member keeps its own filesystem, reachable only by
    # number; the roster comes from `show switch detail` (rejected on
    # platforms that do not stack — recorded in raw, nothing more to list).
    # A member an alias already listed is never listed again by number; a
    # member whose alias listing failed falls back to its own filesystem.
    detail = ctx.run_ssh("show switch detail")
    raw["show switch detail"] = detail
    members = {} if _cli_rejected(detail) else _parse_switch_detail(detail)[1]
    roles = {number: str(facts.get("role") or "").lower() for number, facts in members.items()}
    not_listed = []
    for number in sorted(members, key=int):
        if roles[number] == "active" and alias_listed["active"]:
            continue
        if roles[number] == "standby" and alias_listed["stby"]:
            continue
        ok, older = _crash_listing(
            ctx, "dir crashinfo-%s:" % (number,), "member%s" % (number,), now, raw, normalized
        )
        older_total += older
        if ok:
            listed.append("crashinfo-%s:" % (number,))
        else:
            not_listed.append(int(number))
    if not listed:
        raise SkipCheck("crashinfo filesystems not listable on this platform")
    context = {
        "older_files_ignored": older_total,
        "recent_window_days": C.CRASH_RECENT_DAYS,
        "filesystems_listed": listed,
    }
    for fact, role in (("active_member", "active"), ("standby_member", "standby")):
        holders = [int(number) for number, held in roles.items() if held == role]
        if len(holders) == 1:
            context[fact] = holders[0]
    if not_listed:
        context["members_not_listed"] = not_listed
    return {"raw": raw, "normalized": normalized, "context": context}


register(
    CheckDef(
        id="iosxe_optics",
        platform="iosxe",
        description="Transceiver DOM light levels (tx/rx dBm) per optical port",
        tier=3,
        compare={"mode": "info_only"},
        miss_meaning="",
        collector=_collect_optics,
        tags=("platform",),
    )
)

register(
    CheckDef(
        id="iosxe_crash_files",
        platform="iosxe",
        description="Crash/system-report files within the recency window, on every stack member",
        tier=1,
        compare={"mode": "equality_set"},
        miss_meaning=(
            "A crash or system-report file appeared during the window — something on "
            "that chassis or stack member crashed even if it recovered before anyone "
            "looked."
        ),
        collector=_collect_crash_files,
        tags=("platform",),
    )
)


# --- iosxe_errdisable + iosxe_port_channels (approved TAC-lens additions) -----

_ERRDISABLE_LINE = re.compile(r"^(\S+\d\S*)\s+(?:.*?\s+)?err-?disabled?\s+(\S+)\s*$", re.IGNORECASE)


def _parse_errdisable(cli_output):
    """'show interfaces status err-disabled' -> {iface: {"reason": ...}}.

    Healthy output is empty (header only) — an ADDED key between captures is a
    port knocked into errdisable during the work, which reads as merely
    'down' everywhere else while carrying the reason here."""
    normalized = {}
    for line in (cli_output or "").splitlines():
        match = _ERRDISABLE_LINE.match(line.strip())
        if match and "/" in match.group(1):
            normalized[match.group(1)] = {"reason": match.group(2)}
    return normalized


def _collect_errdisable(ctx):
    if not ctx.has_ssh:
        raise SkipCheck("no SSH transport")
    command = "show interfaces status err-disabled"
    output = ctx.run_ssh(command)
    lowered = (output or "").lower()
    if "invalid input" in lowered or "incomplete command" in lowered:
        raise SkipCheck("err-disabled status form rejected on this platform")
    return {"raw": {command: output}, "normalized": _parse_errdisable(output)}


_PO_LINE = re.compile(r"^\d+\s+(Po\d+)\(([\w-]*)\)\s+(\S+)\s*(.*)$")
_PO_MEMBER = re.compile(r"([A-Za-z]{2}[A-Za-z]*[\d/\.]+)\(([\w-]+)\)")


def _parse_etherchannel(cli_output):
    """'show etherchannel summary' -> {Po: {flags, protocol, members{port: flags}}}.

    Member flags are the silent-capacity signal: (P) bundled is healthy;
    (s) suspended / (D) down / (w) waiting members quietly halve a bundle
    without downing the port-channel. Wrapped member lines attach to the
    most recent port-channel row."""
    normalized = {}
    current = None
    for line in (cli_output or "").splitlines():
        match = _PO_LINE.match(line.strip())
        if match:
            po, flags, protocol, member_text = match.groups()
            current = po
            normalized[po] = {"flags": flags, "protocol": protocol, "members": {}}
            for member, member_flags in _PO_MEMBER.findall(member_text):
                normalized[po]["members"][member] = member_flags
            continue
        if current is not None and line.startswith((" ", "\t")):
            for member, member_flags in _PO_MEMBER.findall(line):
                normalized[current]["members"][member] = member_flags
    return normalized


def _collect_port_channels(ctx):
    if not ctx.has_ssh:
        raise SkipCheck("no SSH transport")
    command = "show etherchannel summary"
    output = ctx.run_ssh(command)
    lowered = (output or "").lower()
    if "invalid input" in lowered or "incomplete command" in lowered:
        raise SkipCheck("etherchannel summary rejected on this platform")
    normalized = _parse_etherchannel(output)
    if not normalized:
        raise SkipCheck("no port-channels configured")
    return {"raw": {command: output}, "normalized": normalized}


register(
    CheckDef(
        id="iosxe_errdisable",
        platform="iosxe",
        description="Ports in err-disabled state with the triggering reason",
        tier=1,
        compare={"mode": "equality_set"},
        miss_meaning=(
            "A port was knocked into err-disable during the work — it reads as merely "
            "'down' everywhere else; the reason here says why (security violation, "
            "link-flap, UDLD...)."
        ),
        collector=_collect_errdisable,
        tags=("interfaces",),
    )
)

register(
    CheckDef(
        id="iosxe_port_channels",
        platform="iosxe",
        description="Port-channel bundles with per-member LACP flags",
        tier=1,
        compare={"mode": "equality_set"},
        miss_meaning=(
            "A bundle's membership or a member's flags changed — a suspended or "
            "standalone member quietly halves capacity without downing the "
            "port-channel."
        ),
        collector=_collect_port_channels,
        tags=("interfaces",),
    )
)


# --- iosxe_switch_stack (Catalyst 9300 StackWise) -----------------------------
# A stack's membership, roles, and ring are invisible everywhere else in the
# catalog: a member that reloaded and rejoined, a stack port that flapped, or
# an active/standby swap all read as "everything up" in the interface and
# routing checks. The CLI forms are the operator's own view — `show switch
# detail` for members plus port topology, `show switch stack-ports summary`
# for per-port link health — enriched with each member's model and serial
# from the hardware inventory (chassis entries carry hw-dev-index == switch
# number; field-verified roster source in nautobot-upgrades) and the
# structured stack-oper payload kept as raw evidence. Always asked by
# doctrine: platforms that do not stack reject the command and record as
# not-present; a standalone switch or an SVL pair answers with one or two
# members.

_STACK_OPER_PATH = "/data/Cisco-IOS-XE-stack-oper:stack-oper-data"

_MAC = r"[0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4}"
# "Switch/Stack Mac Address : 00a1.b2c3.0100 - Local Mac Address"
_STACK_MAC_LINE = re.compile(
    r"^Switch/Stack Mac Address\s*:\s*(%s)(?:\s*-\s*(\w+) Mac Address)?" % (_MAC,), re.IGNORECASE
)
_STACK_PERSIST_LINE = re.compile(r"^Mac persistency wait time\s*:\s*(.+?)\s*$", re.IGNORECASE)
# "*1  Active  00a1.b2c3.0100  15  V02  Ready" — the leading * marks the switch
# the session is on. The tail after priority is "<hw-version> <state...>";
# the state can be several words ("Version Mismatch", "HA Sync in Progress")
# and a provisioned-but-absent member may print no hardware version at all.
_STACK_MEMBER_LINE = re.compile(
    r"^\*?\s*(\d+)\s+(\S+)\s+(%s)\s+(\d+)\s+(.+?)\s*$" % (_MAC,), re.IGNORECASE
)
# "  1/1  OK  3  50cm  Yes  Yes  Yes  1  No" — cable length may be two words
# ("No cable"), hence the lazy middle group bounded by the Yes/No columns.
_STACK_PORT_SUMMARY_LINE = re.compile(
    r"^(\d+)/(\d+)\s+(\S+)\s+(\S+)\s+(.+?)\s+(Yes|No)\s+(Yes|No)\s+(Yes|No)\s+(\d+)\s+(Yes|No)$",
    re.IGNORECASE,
)


def _cli_rejected(output):
    """True when IOS-XE refused the command form rather than answering it."""
    lowered = (output or "").lower()
    return "invalid input" in lowered or "incomplete command" in lowered


def _yes(token):
    return str(token).strip().lower() == "yes"


_NEIGHBOR_PORT = re.compile(r"^(\d+)/(\d+)$")


def _neighbor_facts(token):
    """{'neighbor': peer switch number[, 'neighbor_port': '<switch>/<port>']}.

    Field-verified on a 4-member 9300: the stack-ports summary prints the far
    end as a switch/port pair ('2/2'), not a bare switch number. Both forms
    yield the same int 'neighbor', so the value never changes type between
    captures when one of the two commands fails to parse; the pair rides
    along as neighbor_port. Anything else (the literal 'None' on a port with
    no neighbor) stays the device's own token.
    """
    token = str(token).strip()
    if token.isdigit():
        return {"neighbor": int(token)}
    pair = _NEIGHBOR_PORT.match(token)
    if pair:
        return {"neighbor": int(pair.group(1)), "neighbor_port": token}
    return {"neighbor": token}


def _parse_switch_detail(cli_output):
    """(stack, members, ports) from ``show switch detail``.

    stack: header scalars (mac, mac_origin local/foreign, mac_persistency);
    members: '<n>' -> role/state/priority/mac (+ hw_version when printed);
    ports: '<n>/<p>' -> status/neighbor from the Stack Port Status table,
    which lists every port's status followed by the same number of neighbor
    columns (two ports per member on StackWise; the split is by count, so a
    platform with more ports parses unchanged).
    """
    stack = {}
    members = {}
    ports = {}
    section = "members"
    for line in (cli_output or "").splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        mac_match = _STACK_MAC_LINE.match(stripped)
        if mac_match:
            stack["mac"] = mac_match.group(1).lower()
            if mac_match.group(2):
                stack["mac_origin"] = mac_match.group(2).lower()
            continue
        persist_match = _STACK_PERSIST_LINE.match(stripped)
        if persist_match:
            stack["mac_persistency"] = persist_match.group(1)
            continue
        if "stack port status" in stripped.lower():
            section = "ports"
            continue
        if section == "members":
            match = _STACK_MEMBER_LINE.match(stripped)
            if not match:
                continue
            number, role, mac, priority, tail = match.groups()
            tail_tokens = tail.split(None, 1)
            entry = {"role": role, "priority": int(priority), "mac": mac.lower()}
            if len(tail_tokens) == 2:
                entry["hw_version"] = tail_tokens[0]
                entry["state"] = tail_tokens[1].strip()
            else:
                entry["state"] = tail_tokens[0]
            members[number] = entry
            continue
        tokens = stripped.split()
        if len(tokens) < 3 or not tokens[0].isdigit() or len(tokens) % 2 == 0:
            continue
        half = (len(tokens) - 1) // 2
        statuses, neighbors = tokens[1 : 1 + half], tokens[1 + half :]
        if not all(tok.isalpha() for tok in statuses):
            continue
        if not all(
            tok.isdigit() or tok.lower() == "none" or _NEIGHBOR_PORT.match(tok) for tok in neighbors
        ):
            continue
        for index, (status, neighbor) in enumerate(zip(statuses, neighbors), 1):
            entry = {"status": status.upper()}
            entry.update(_neighbor_facts(neighbor))
            ports["%s/%d" % (tokens[0], index)] = entry
    return stack, members, ports


def _parse_stack_ports_summary(cli_output):
    """'<n>/<p>' -> per-port link facts from ``show switch stack-ports summary``.

    link_ok_changes is the device's '#Changes to LinkOK' column: a
    link-transition count, not a traffic counter — identical across healthy
    captures, it moves only when the stack link bounced. Field-verified on a
    4-member 9300: the neighbor column prints the far-end switch/port ('2/2')
    and a 1 m cable prints as '100cm'.
    """
    ports = {}
    for line in (cli_output or "").splitlines():
        match = _STACK_PORT_SUMMARY_LINE.match(line.strip())
        if not match:
            continue
        switch, port, status, neighbor, cable, link_ok, active, sync_ok, changes, loop = (
            match.groups()
        )
        entry = {"status": status.upper()}
        entry.update(_neighbor_facts(neighbor))
        entry.update(
            {
                "cable": cable.strip(),
                "link_ok": _yes(link_ok),
                "link_active": _yes(active),
                "sync_ok": _yes(sync_ok),
                "link_ok_changes": int(changes),
                "loopback": _yes(loop),
            }
        )
        ports["%s/%s" % (switch, port)] = entry
    return ports


def _chassis_inventory(hardware_payload):
    """'<hw-dev-index>' -> {model, serial} for chassis entries of device-inventory.

    On a stack every member is a chassis entry whose hw-dev-index is its
    switch number (the roster source nautobot-upgrades gates member rejoin
    on); power supplies, fans and modules are skipped.
    """
    container = (
        _container(hardware_payload, "Cisco-IOS-XE-device-hardware-oper:device-hardware-data") or {}
    )
    hardware = container.get("device-hardware")
    hardware = hardware if isinstance(hardware, dict) else {}
    chassis = {}
    for entry in _aslist(hardware.get("device-inventory")):
        if not isinstance(entry, dict):
            continue
        if "chassis" not in str(entry.get("hw-type") or "").lower():
            continue
        index = entry.get("hw-dev-index")
        if index is None:
            continue
        facts = {}
        if entry.get("part-number"):
            facts["model"] = str(entry["part-number"]).strip()
        if entry.get("serial-number"):
            facts["serial"] = str(entry["serial-number"]).strip()
        chassis[str(index)] = facts
    return chassis


def _collect_switch_stack(ctx):
    if not ctx.has_ssh:
        raise SkipCheck("no SSH transport")
    raw = {}
    notes = []
    detail_command = "show switch detail"
    detail = ctx.run_ssh(detail_command)
    raw[detail_command] = detail
    if _cli_rejected(detail):
        raise SkipCheck("switch stacking commands rejected (platform does not stack)")
    stack, members, ports = _parse_switch_detail(detail)
    if not members:
        lowered = (detail or "").lower()
        if "switch/stack mac address" in lowered or "switch#" in lowered:
            raise CollectError(
                "'show switch detail' printed a member table but no member rows parsed — "
                "format needs shakedown"
            )
        first_line = next((ln.strip() for ln in (detail or "").splitlines() if ln.strip()), "")
        raise SkipCheck("no stack member table in 'show switch detail' output: %s" % (first_line,))

    summary_command = "show switch stack-ports summary"
    summary = ctx.run_ssh(summary_command)
    raw[summary_command] = summary
    if _cli_rejected(summary):
        notes.append("stack-ports summary rejected (no physical stack ports on this platform)")
    else:
        summary_ports = _parse_stack_ports_summary(summary)
        if not summary_ports:
            notes.append("stack-ports summary answered but no port rows parsed — needs shakedown")
        for key, facts in summary_ports.items():
            ports.setdefault(key, {}).update(facts)

    # Member model/serial ride on the hardware inventory the platform-health
    # check also reads — identical path and kwargs, so the per-run cache
    # issues one GET for both.
    hardware = ctx.get(_HW_PATH)
    chassis = _chassis_inventory(hardware)
    raw["device-inventory chassis"] = chassis
    unmatched = sorted(set(chassis) - set(members), key=lambda k: (len(k), k))
    if unmatched:
        notes.append("chassis inventory indexes with no member row: %s" % (", ".join(unmatched),))

    # Structured supplement, raw only: the model's presence and leaf spellings
    # on stacking platforms are unverified, so it is evidence for the
    # shakedown, never the source of the normalized view.
    try:
        stack_oper = ctx.get(_STACK_OPER_PATH, ok_404=True)
    except Exception as exc:  # best-effort read; transport failure modes vary
        if type(exc).__name__ == "SoftTimeLimitExceeded":
            raise  # the Celery abort signal is never a note
        stack_oper = None
        notes.append("stack-oper supplement failed: %s" % (exc,))
    raw["stack-oper"] = stack_oper
    if stack_oper is None:
        notes.append("stack-oper data not served on this release (supplement skipped)")

    normalized = {}
    if stack:
        normalized["stack"] = stack
    for number, facts in members.items():
        entry = dict(facts)
        entry.update(chassis.get(number, {}))
        normalized["switch|%s" % (number,)] = entry
    for key, facts in ports.items():
        normalized["stack-port|%s" % (key,)] = facts
    context = {
        "members_total": len(members),
        "members_ready": sum(1 for m in members.values() if m.get("state", "").lower() == "ready"),
        "stack_ports_total": len(ports),
        "stack_ports_ok": sum(1 for p in ports.values() if p.get("status") == "OK"),
    }
    if notes:
        raw["note"] = "; ".join(notes)
    return {"raw": raw, "normalized": normalized, "context": context}


register(
    CheckDef(
        id="iosxe_switch_stack",
        platform="iosxe",
        description="Switch stack members (role, state, model, serial) and stack-port ring health",
        tier=1,
        compare={"mode": "equality_set"},
        miss_meaning=(
            "A stack member changed role or state, vanished, or was replaced, or a stack "
            "port went DOWN / flapped — the ring degraded or a member reloaded during the "
            "window, which every other check reads as merely 'up'."
        ),
        collector=_collect_switch_stack,
        tags=("platform", "stack"),
    )
)
