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
