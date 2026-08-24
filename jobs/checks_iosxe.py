"""Catalyst 9500 (IOS-XE 17.12 RESTCONF) check catalog.

Collectors reach the device only through the CollectorContext (``ctx.get`` /
``ctx.run_ssh``); this module imports nothing but stdlib and the jobs
package's pure modules, so the CI test battery can import it and drive every
``_normalize_*`` / ``_parse_*`` function directly with fixture payloads.
RESTCONF paths were verified against the published 17.12.1 YANG set.

The full-RIB fetch is deliberately shared: iosxe_routes_rib and
iosxe_route_rollups call ``ctx.get`` with the identical path and kwargs, so
the per-run cache issues one GET for both checks.
"""

import re

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
