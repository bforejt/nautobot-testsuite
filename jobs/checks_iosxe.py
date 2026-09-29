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
from . import iosxe_common as common
from .checks_iosxe_layer2 import _parse_interfaces_trunk
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
    "?fields=ospfv2-instance(instance-id;vrf-name;router-id;"
    "ospfv2-area(area-id;ospfv2-interface(name;state;"
    "ospfv2-neighbor(nbr-id;address;state))))"
)
_ARP_PATH = "/data/Cisco-IOS-XE-arp-oper:arp-data"
# Paths more than one module reads live in iosxe_common so the per-run cache
# issues each GET once: the widened interfaces read (iosxe_interfaces and
# iosxe_errdisable), the VLAN database (iosxe_interfaces reads it, ok_404, to
# tell access ports from trunks and routed ports; iosxe_vlans makes the same
# GET), device hardware and the stack roster.
_IFACE_BASE_PATH = common.IFACE_BASE_PATH
_IFACE_FIELDS = common.IFACE_FIELDS
_IFACE_PATH = common.IFACE_PATH
_CDP_PATH = "/data/Cisco-IOS-XE-cdp-oper:cdp-neighbor-details"
_VLAN_PATH = common.VLAN_PATH
_LLDP_PATH = "/data/Cisco-IOS-XE-lldp-oper:lldp-entries"
_HW_PATH = common.HW_PATH
_ENV_PATH = "/data/Cisco-IOS-XE-environment-oper:environment-sensors"

# yang-library module names this module's collectors read, reported by the
# shakedown (merged with the platform base list, first occurrence wins) so a
# switch shakedown shows at once which of these collectors CAN work on the
# image. Every path below was checked against the 17.15.1 models on disk.
KEY_MODELS = (
    "ietf-routing",
    "Cisco-IOS-XE-fib-oper",
    "Cisco-IOS-XE-bgp-oper",
    "Cisco-IOS-XE-ospf-oper",
    "Cisco-IOS-XE-arp-oper",
    "Cisco-IOS-XE-cdp-oper",
    "Cisco-IOS-XE-lldp-oper",
    "Cisco-IOS-XE-interfaces-oper",
    "Cisco-IOS-XE-vlan-oper",
    "Cisco-IOS-XE-device-hardware-oper",
    "Cisco-IOS-XE-environment-oper",
    "Cisco-IOS-XE-platform-software-oper",
    "Cisco-IOS-XE-switch-cp-svl-oper",
    "Cisco-IOS-XE-ntp-oper",
    "Cisco-IOS-XE-lacp-oper",
    "Cisco-IOS-XE-stack-oper",
)


# --- shared helpers (jobs/iosxe_common; historical names kept for callers) ---

_aslist = common.aslist
_container = common.container
_to_int = common.to_int
_short = common.short
_strip_module = common.strip_module
_text_or_none = common.text_or_none


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
            if type(exc).__name__ == "SoftTimeLimitExceeded":
                raise  # the Celery abort signal is never a note
            raw["note"] = "ssh 'show ip route summary' failed: %s" % (exc,)
    else:
        raw["note"] = "no SSH transport; OSPF type splits unavailable"
    return {"raw": raw, "normalized": normalized}


# --- FIB ---------------------------------------------------------------------


def _address_of(value):
    """The address part of 'a.b.c.d/len' (or of a bare address); '' for None."""
    return "" if value is None else str(value).split("/", 1)[0]


def _attached_host(prefix, nh_entries):
    """True for a CEF attached-host adjacency: a host route (/32 or /128) whose
    every next-hop is the host itself, on the connected interface.

    CEF programs one for each host the switch has resolved on a connected
    subnet (a glean that completed); it follows ARP — appears when a host
    sends or is sent traffic, ages out when it goes quiet — so it says
    nothing about routing and never becomes a key. Field-verified on the
    lab 9300 (17.15.6): 'ip-addr' 10.x.y.z/32 with one 'fib-nexthop-entries'
    row 'nh-addr' 10.x.y.z/32 on the SVI, added between two captures five
    minutes apart with the RIB unchanged.
    """
    if not str(prefix).endswith(("/32", "/128")) or not nh_entries:
        return False
    address = _address_of(prefix)
    return all(_address_of(nh.get("nh-addr")) == address for nh in nh_entries)


def _fib_entries(payload):
    """(instance, entry dict, next-hop dict rows) per FIB entry with a prefix."""
    container = _container(payload, "Cisco-IOS-XE-fib-oper:fib-oper-data") or {}
    for ni_entry in _aslist(container.get("fib-ni-entry")):
        if not isinstance(ni_entry, dict):
            continue
        instance = ni_entry.get("instance-name") or "default"
        for entry in _aslist(ni_entry.get("fib-entries")):
            if not isinstance(entry, dict) or entry.get("ip-addr") is None:
                continue
            hops = [nh for nh in _aslist(entry.get("fib-nexthop-entries")) if isinstance(nh, dict)]
            yield instance, entry, hops


def _normalize_fib(payload):
    """'instance|prefix' -> sorted programmed next-hops; attached-host adjacencies left out."""
    normalized = {}
    for instance, entry, nh_entries in _fib_entries(payload):
        prefix = entry["ip-addr"]
        if _attached_host(prefix, nh_entries):
            continue
        hops = []
        for nh_entry in nh_entries:
            hop = _hop(nh_entry.get("nh-addr"), nh_entry.get("ifname"))
            if hop:
                hops.append(hop)
        normalized["%s|%s" % (instance, prefix)] = {"next_hops": _sorted_hops(hops)}
    return normalized


def _fib_context(payload):
    """What the view left out and why: the attached-host adjacencies per interface
    (they follow ARP), their total, and the entry counts."""
    attached = {}
    entries = 0
    for _instance, entry, nh_entries in _fib_entries(payload):
        entries += 1
        if not _attached_host(entry["ip-addr"], nh_entries):
            continue
        ifname = str(nh_entries[0].get("ifname"))
        attached[ifname] = attached.get(ifname, 0) + 1
    total = sum(attached.values())
    return {
        "attached_hosts": dict(sorted(attached.items())),
        "attached_hosts_total": total,
        "entries": entries,
        "keyed": entries - total,
    }


def _collect_routes_fib(ctx):
    payload = ctx.get(_FIB_PATH, timeout=C.BIG_GET_TIMEOUT)
    if _container(payload, "Cisco-IOS-XE-fib-oper:fib-oper-data") is None:
        raise CollectError("fib-oper-data container missing from RESTCONF reply")
    return {
        "raw": {"fib-oper": payload},
        "normalized": _normalize_fib(payload),
        "context": _fib_context(payload),
    }


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


def _ospf_context(payload):
    """Why the view holds what it holds: every instance, area and interface.

    ``instances`` is keyed ``'<instance-id>|<vrf>'`` (the model's empty vrf-name
    is the default VRF) with the router-id as a dotted quad, the areas and,
    per area, each interface's state word (``ospfv2-interface-state-dr`` reads
    ``dr``) and neighbor count; ``neighbors`` is the total. An empty
    normalized view is then self-explaining: an instance whose interfaces
    are all DR/DROTHER with zero neighbors has nothing across its links.
    Timers, LSDB contents and the DR/BDR addresses are excluded.
    """
    container = _container(payload, "Cisco-IOS-XE-ospf-oper:ospf-oper-data") or {}
    instances = {}
    total = 0
    for inst in _aslist(container.get("ospfv2-instance")):
        if not isinstance(inst, dict):
            continue
        vrf = _text_or_none(inst.get("vrf-name")) or "default"
        key = "%s|%s" % (inst.get("instance-id"), vrf)
        areas = {}
        for area in _aslist(inst.get("ospfv2-area")):
            if not isinstance(area, dict):
                continue
            interfaces = {}
            for iface in _aslist(area.get("ospfv2-interface")):
                if not isinstance(iface, dict):
                    continue
                state = _text_or_none(iface.get("state"))
                if state is not None:
                    for prefix in ("ospfv2-interface-state-", "ospf-iface-state-"):
                        if state.startswith(prefix):
                            state = state[len(prefix) :]
                            break
                count = len(
                    [n for n in _aslist(iface.get("ospfv2-neighbor")) if isinstance(n, dict)]
                )
                total += count
                interfaces[str(iface.get("name"))] = {"state": state, "neighbors": count}
            areas[str(area.get("area-id"))] = {"interfaces": interfaces}
        instances[key] = {"router_id": common.dotted(inst.get("router-id")), "areas": areas}
    return {"instances": instances, "neighbors": total}


def _collect_ospf_neighbors(ctx):
    payload = ctx.get(_OSPF_PATH, ok_404=True)
    if payload is None:
        raise SkipCheck("OSPF not running")
    container = _container(payload, "Cisco-IOS-XE-ospf-oper:ospf-oper-data") or {}
    if not _aslist(container.get("ospfv2-instance")):
        raise SkipCheck("OSPF not running")
    return {
        "raw": {"ospf-oper": payload},
        "normalized": _normalize_ospf_neighbors(payload),
        "context": _ospf_context(payload),
    }


# --- ARP ---------------------------------------------------------------------


# The two per-VRF lists of arp-oper, in the order read: arp-entry (the list
# the 17.x model keeps; the lab 9300 fills it) and the flat arp-oper list the
# model marks deprecated, which older releases fill alone (the lab fills both
# with the same rows). Both carry address, hardware, interface and the same
# mode words; a VRF is read from the first list that has rows.
_ARP_LISTS = (("arp-entry", "arp-entry"), ("arp-oper", "arp-oper (deprecated flat list)"))


def _arp_vrfs(payload):
    """(vrf name, rows, source word) per arp-vrf entry; rows [] and source None when empty."""
    container = _container(payload, "Cisco-IOS-XE-arp-oper:arp-data") or {}
    for vrf_entry in _aslist(container.get("arp-vrf")):
        if not isinstance(vrf_entry, dict):
            continue
        vrf = vrf_entry.get("vrf") or "default"
        for list_name, source in _ARP_LISTS:
            rows = [e for e in _aslist(vrf_entry.get(list_name)) if isinstance(e, dict)]
            if rows:
                yield vrf, rows, source
                break
        else:
            yield vrf, [], None


def _normalize_arp(payload):
    """'vrf|address' -> mac / interface, from each VRF's arp-entry list or, where a
    release fills only the deprecated flat arp-oper list, from that one.

    The volatile 'time' leaf is never emitted.
    """
    normalized = {}
    for vrf, rows, _source in _arp_vrfs(payload):
        for entry in rows:
            address = entry.get("address")
            if address is None:
                continue
            normalized["%s|%s" % (vrf, address)] = {
                "mac": entry.get("hardware"),
                "interface": entry.get("interface"),
            }
    return normalized


def _arp_context(payload):
    """Which list the release filled ('arp-entry', 'arp-oper (deprecated flat
    list)', both joined with ' + ' should VRFs differ, None when no VRF had a
    row), the row and VRF counts."""
    sources = []
    entries = 0
    vrfs = 0
    for _vrf, rows, source in _arp_vrfs(payload):
        vrfs += 1
        entries += len(rows)
        if source is not None and source not in sources:
            sources.append(source)
    return {"source": " + ".join(sources) if sources else None, "entries": entries, "vrfs": vrfs}


def _collect_arp(ctx):
    payload = ctx.get(_ARP_PATH)
    if _container(payload, "Cisco-IOS-XE-arp-oper:arp-data") is None:
        raise CollectError("arp-data container missing from RESTCONF reply")
    return {
        "raw": {"arp-data": payload},
        "normalized": _normalize_arp(payload),
        "context": _arp_context(payload),
    }


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
            # The neighbor's native VLAN and appliance (voice) VLAN as it
            # advertises them; the model defines 0 as "not received", so 0
            # and an absent leaf both read None. duplex is the cdp-duplex
            # enum verbatim (cdp-full-duplex, cdp-half-duplex-mismatch, ...).
            "native_vlan": _vlan_or_none(entry.get("native-vlan")),
            "duplex": _strip_module(entry.get("duplex")),
            "voice_vlan": _vlan_or_none(entry.get("vvid")),
            # The model's platform-name ("cisco C9300-48P", "Cisco IP Phone
            # 8845"): a stable identity string on the same GET; the bare
            # spelling is tolerated the way the capability leaf's plural is.
            "platform": _text_or_none(entry.get("platform-name", entry.get("platform"))),
        }
    return normalized


def _vlan_or_none(value):
    """A CDP VLAN id as int; None when absent, non-numeric or 0 (the model's 'not received')."""
    number = _to_int(value)
    return number if number else None


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


def _neighbor_source(payload, count):
    """How a neighbor model answered: not served (404), served with an empty
    container, or with n neighbors — so an empty cdp| set is a recorded model
    fact (the lab 9300 served cdp-oper empty on earlier harvests while `show cdp
    neighbors detail` listed its AP, and one to three neighbors on later runs),
    never mistaken for no neighbors."""
    if payload is None:
        return "not served (404)"
    if count:
        return "%d neighbors" % (count,)
    return "served, empty"


def _collect_neighbors(ctx):
    cdp = ctx.get(_CDP_PATH, ok_404=True)
    lldp = ctx.get(_LLDP_PATH, ok_404=True)
    if cdp is None and lldp is None:
        raise SkipCheck("neither CDP nor LLDP oper data present")
    cdp_view = {} if cdp is None else _normalize_cdp(cdp)
    lldp_view = {} if lldp is None else _normalize_lldp(lldp)
    normalized = dict(cdp_view)
    normalized.update(lldp_view)
    context = {
        "sources": {
            "cdp-oper": _neighbor_source(cdp, len(cdp_view)),
            "lldp-oper": _neighbor_source(lldp, len(lldp_view)),
        },
        "cdp_neighbors": len(cdp_view),
        "lldp_neighbors": len(lldp_view),
    }
    return {"raw": {"cdp": cdp, "lldp": lldp}, "normalized": normalized, "context": context}


# --- interfaces --------------------------------------------------------------

_IFACE_UP = "if-oper-state-ready"
# A port whose hardware is not there (an uplink-module slot with no
# transceiver, a module bay left empty): its statistics container is served
# but never counted, so nothing in it is a reading.
_IFACE_NOT_PRESENT = "if-oper-state-not-present"
# Field finding (C9300-48UXM, 17.15.6): num-flaps read 18446744073109295496 on
# every not-present port and on two SVIs — a uint64 that wrapped below zero
# (2^64 - N). No counter this module reads can honestly reach 2^63, so any
# value at or above it is a wrapped register, not a reading.
_COUNTER_INVALID_FROM = 2**63
# The address value an unaddressed interface serves for ipv4 and
# ipv4-subnet-mask (field finding on every lab capture): no address, so None.
_UNADDRESSED = "0.0.0.0"

# The statistics leaves raw keeps per interface (intf-statistics grouping),
# in model order: the byte/packet totals, the error and discard counters, the
# CRC and flap counters and the rate estimates. The counters are read as
# deltas by the analyst; nothing here is ever normalized.
_IFACE_STATS_LEAVES = (
    "discontinuity-time",
    "in-octets",
    "in-unicast-pkts",
    "in-broadcast-pkts",
    "in-multicast-pkts",
    "in-discards",
    "in-errors",
    "in-unknown-protos",
    "out-octets",
    "out-unicast-pkts",
    "out-broadcast-pkts",
    "out-multicast-pkts",
    "out-discards",
    "out-errors",
    "rx-pps",
    "rx-kbps",
    "tx-pps",
    "tx-kbps",
    "num-flaps",
    "in-crc-errors",
    "in-discards-64",
    "in-errors-64",
    "in-unknown-protos-64",
    "out-octets-64",
)
# The per-port counters context surfaces when nonzero, (leaf, context field).
_IFACE_CONTEXT_COUNTERS = (
    ("in-crc-errors", "crc"),
    ("in-errors", "in_errors"),
    ("num-flaps", "flaps"),
)
# The storm-control traffic-type containers of the interface-sc-state grouping.
_STORM_TYPES = ("broadcast", "multicast", "unicast", "unknown-unicast")
# The widened containers whose presence on at least one interface context
# reports, so a capture says which the release populated.
_IFACE_WIDENED = (
    "ether-state",
    "intf-ext-state",
    "storm-control",
    "diffserv-info",
    "statistics",
    "ipv6-addrs",
)
# Raw keeps curated statistics for at most this many interfaces.
_IFACE_STATS_RAW_MAX = 1024


def _interface_entries(payload):
    """The interface list entries of an interfaces-oper payload (dicts only)."""
    container = _container(payload, "Cisco-IOS-XE-interfaces-oper:interfaces") or {}
    return [entry for entry in _aslist(container.get("interface")) if isinstance(entry, dict)]


def _ipv4_or_none(value):
    """An ipv4 / ipv4-subnet-mask leaf; None when absent, blank or the 0.0.0.0 an
    unaddressed port serves (a switchport has no address, whatever the device
    prints in the slot)."""
    text = _text_or_none(value)
    return None if text == _UNADDRESSED else text


def _counters(entry):
    """(valid counters, wrapped leaves, not_present) of one interface's statistics.

    valid: leaf -> int for every statistics leaf that is a reading; wrapped:
    the sorted leaves whose value is a wrapped uint64 (at or above 2^63);
    not_present: True when the port's oper state is not-present, in which
    case nothing it serves is a reading and valid is empty.
    """
    stats = entry.get("statistics")
    stats = stats if isinstance(stats, dict) else {}
    not_present = entry.get("oper-status") == _IFACE_NOT_PRESENT
    valid, wrapped = {}, []
    for leaf, raw in stats.items():
        if isinstance(raw, bool):
            continue
        value = _to_int(raw)
        if value is None:
            continue
        if value >= _COUNTER_INVALID_FROM:
            wrapped.append(leaf)
        elif not not_present:
            valid[leaf] = value
    return valid, sorted(wrapped), not_present


def _vrf_or_none(value):
    """The vrf leaf; None for the global table, which the model spells 'Global' and a
    device may leave blank."""
    text = _text_or_none(value)
    if text is None or text.lower() == "global":
        return None
    return text


def _qos_policies(entry):
    """(inbound, outbound) diffserv policy names, each the sorted names joined by ','
    or None; the list key is (direction, policy-name)."""
    names = {"qos-inbound": [], "qos-outbound": []}
    for info in _aslist(entry.get("diffserv-info")):
        if not isinstance(info, dict):
            continue
        direction = _strip_module(info.get("direction"))
        name = _text_or_none(info.get("policy-name"))
        if direction in names and name is not None:
            names[direction].append(name)
    return tuple(",".join(sorted(set(names[d]))) or None for d in ("qos-inbound", "qos-outbound"))


def _storm_blocking(entry):
    """Sorted traffic types whose storm-control filter-state is 'blocking'."""
    storm = entry.get("storm-control")
    storm = storm if isinstance(storm, dict) else {}
    blocking = []
    for traffic in _STORM_TYPES:
        state = storm.get(traffic)
        state = state if isinstance(state, dict) else {}
        if _strip_module(state.get("filter-state")) == "blocking":
            blocking.append(traffic)
    return blocking


def _ext_state(entry):
    """The intf-ext-state container, {} when absent; the model marks it valid only
    beside the intf-ext-state-support presence leaf, but a device that serves the
    container without the flag is read rather than ignored."""
    ext = entry.get("intf-ext-state")
    return ext if isinstance(ext, dict) else {}


def _access_ports(vlan_payload, trunk_ports=()):
    """The access ports a vlan-oper payload names, or None when the model was
    not served (404) so every port keeps its negotiated link state.

    The switchport set is whichever list the release fills — the assigned
    `ports` list where it is filled, else `vlan-interfaces` (the lab 9300 fills
    only that one, on every release captured; common.switchports is the one
    rule iosxe_vlans shares). `vlan-interfaces` lists a trunk under VLAN 1
    whatever its native VLAN, so the trunk ports the caller names (long names, from
    `show interfaces trunk`) are taken back out: a trunk's link rate follows
    no endpoint and stays a keyed fact.
    """
    if vlan_payload is None:
        return None
    names, _source = common.switchports(vlan_payload)
    return names - set(trunk_ports)


_TRUNK_COMMAND = "show interfaces trunk"


def _trunk_ports(ctx, notes):
    """(long names of the ports `show interfaces trunk` lists, source word).

    Best-effort and read-only: no SSH transport, a refused command or a failed
    read each cost only the trunk exclusion (those ports' link state then rides
    in context access_link like an access port's), never the check. The same
    command iosxe_trunks runs (SSH reads are not cached).
    """
    if not ctx.has_ssh:
        return set(), "no SSH transport"
    try:
        output = ctx.run_ssh(_TRUNK_COMMAND)
    except Exception as exc:  # best-effort read; transport failure modes vary
        if type(exc).__name__ == "SoftTimeLimitExceeded":
            raise  # the Celery abort signal is never a note
        notes.append("'%s' failed (%s); trunk link state rides in context" % (_TRUNK_COMMAND, exc))
        return set(), "read failed"
    if common.cli_rejected(output):
        return set(), "rejected"
    return {common.long_ifname(port) for port in _parse_interfaces_trunk(output)}, _TRUNK_COMMAND


def _link_state(entry):
    """(speed, duplex, mgig_downshift, autoneg) of one interface entry.

    speed and duplex are the ether-state negotiated values, only while oper is
    up (a down port negotiated nothing); mgig_downshift is the intf-ext-state
    flag; autoneg is the auto-negotiate leaf, a config fact read whatever the
    oper state (the model defines the negotiated leaves only when it is true).
    """
    oper = entry.get("oper-status")
    ether = entry.get("ether-state")
    ether = ether if isinstance(ether, dict) else {}
    negotiated = ether if oper == _IFACE_UP else {}
    downshift = _ext_state(entry).get("mgig-downshift-enabled")
    autoneg = ether.get("auto-negotiate")
    if isinstance(autoneg, str):
        autoneg = {"true": True, "false": False}.get(autoneg.strip().lower())
    return (
        _strip_module(negotiated.get("negotiated-port-speed")),
        _strip_module(negotiated.get("negotiated-duplex-mode")),
        downshift if isinstance(downshift, bool) else None,
        autoneg if isinstance(autoneg, bool) else None,
    )


def _normalize_interfaces(payload, access_ports=None):
    """interface name -> stable state and effective config (None when unset).

    State: admin/oper status; speed and duplex (ether-state negotiated values,
    only while oper is up — a down port negotiated nothing); mgig_downshift;
    autoneg (the auto-negotiate leaf: a hard-set port reads False with None
    speed/duplex); storm (traffic types storm-control is blocking). Effective
    config: ipv4, mask, vrf, ipv6 (sorted), mtu, acl_in/acl_out,
    qos_in/qos_out. Description is deliberately raw-only: cosmetic edits must
    not fail a change window. The err-disable leaves of intf-ext-state are
    iosxe_errdisable's, so one event is reported once; counters are context
    and raw, never here.

    access_ports: the interfaces the VLAN database lists as assigned ports.
    Their negotiated speed, duplex and mgig_downshift follow the endpoint's
    power state (a docked laptop that sleeps drops its link rate with the
    port still up), so for them the three read None here and the values ride
    in context (_interfaces_context's access_link). None (the model was not
    served) keeps every port's values here.
    """
    normalized = {}
    access = access_ports or set()
    for entry in _interface_entries(payload):
        name = entry.get("name")
        if name is None:
            continue
        oper = entry.get("oper-status")
        speed, duplex, downshift, autoneg = _link_state(entry)
        if name in access:
            speed = duplex = downshift = None
        qos_in, qos_out = _qos_policies(entry)
        normalized[name] = {
            "admin": entry.get("admin-status"),
            "oper": oper,
            "ipv4": _ipv4_or_none(entry.get("ipv4")),
            "mask": _ipv4_or_none(entry.get("ipv4-subnet-mask")),
            "vrf": _vrf_or_none(entry.get("vrf")),
            "ipv6": sorted(str(addr).lower() for addr in _aslist(entry.get("ipv6-addrs"))),
            "mtu": _to_int(entry.get("mtu")),
            "acl_in": _text_or_none(entry.get("input-security-acl")),
            "acl_out": _text_or_none(entry.get("output-security-acl")),
            "qos_in": qos_in,
            "qos_out": qos_out,
            "speed": speed,
            "duplex": duplex,
            "mgig_downshift": downshift,
            "autoneg": autoneg,
            "storm": _storm_blocking(entry),
        }
    return normalized


def _interfaces_context(payload, access_ports=None):
    """Counters and coverage facts: nonzero CRC / in-error / flap counters per port
    (read as deltas), port totals, which widened containers the device served,
    and the link scope: link_scope 'trunks_and_routed' when the VLAN database
    named the access ports (their negotiated speed, duplex and mgig_downshift
    then ride here under access_link, never in normalized), 'all' when it was
    not served and every port's values stay normalized. counters_invalid names,
    per port, the statistics leaves whose value is a wrapped uint64, and
    counters_not_present the ports whose oper state is not-present: neither
    ever reaches counters.
    """
    entries = _interface_entries(payload)
    counters = {}
    counters_invalid = {}
    counters_not_present = []
    access_link = {}
    access = access_ports or set()
    seen = {leaf: False for leaf in _IFACE_WIDENED}
    for entry in entries:
        for leaf in _IFACE_WIDENED:
            if entry.get(leaf) not in (None, [], {}):
                seen[leaf] = True
        if entry.get("name") in access:
            speed, duplex, downshift, _autoneg = _link_state(entry)
            access_link[entry["name"]] = {
                "speed": speed,
                "duplex": duplex,
                "mgig_downshift": downshift,
            }
        valid, wrapped, not_present = _counters(entry)
        nonzero = {}
        for leaf, field in _IFACE_CONTEXT_COUNTERS:
            if valid.get(leaf):
                nonzero[field] = valid[leaf]
        if nonzero and entry.get("name") is not None:
            counters[entry["name"]] = nonzero
        if wrapped and entry.get("name") is not None:
            counters_invalid[entry["name"]] = wrapped
        if not_present and entry.get("name") is not None and "statistics" in entry:
            counters_not_present.append(entry["name"])
    return {
        "ports_total": len(entries),
        "ports_oper_up": sum(1 for e in entries if e.get("oper-status") == _IFACE_UP),
        "counters": counters,
        "counters_invalid": dict(sorted(counters_invalid.items())),
        "counters_not_present": sorted(counters_not_present),
        "leaves_seen": seen,
        "link_scope": "all" if access_ports is None else "trunks_and_routed",
        "access_ports_listed": None if access_ports is None else len(access_ports),
        "access_link": dict(sorted(access_link.items())),
    }


def _interface_statistics(payload):
    """interface name -> the curated statistics leaves the device served, for raw
    (capped at _IFACE_STATS_RAW_MAX interfaces, in payload order)."""
    curated = {}
    for entry in _interface_entries(payload):
        stats = entry.get("statistics")
        name = entry.get("name")
        if name is None or not isinstance(stats, dict):
            continue
        curated[name] = {leaf: stats[leaf] for leaf in _IFACE_STATS_LEAVES if leaf in stats}
        if len(curated) >= _IFACE_STATS_RAW_MAX:
            break
    return curated


def _interfaces_without_statistics(payload):
    """The payload with each interface's statistics container dropped, so raw holds
    the counters once, curated, beside the rest of the reply."""
    container = _container(payload, "Cisco-IOS-XE-interfaces-oper:interfaces")
    if not isinstance(container, dict):
        return payload
    stripped = [
        {k: v for k, v in entry.items() if k != "statistics"} if isinstance(entry, dict) else entry
        for entry in _aslist(container.get("interface"))
    ]
    return {"Cisco-IOS-XE-interfaces-oper:interfaces": {"interface": stripped}}


def _fetch_interfaces(ctx):
    """(payload, notes): the widened interfaces GET, retried once unfiltered on HTTP 400.

    Shared by iosxe_interfaces and iosxe_errdisable; the second caller is a
    cache hit. CollectError when the reply lacks the interfaces container.
    The historical (payload, notes) shape of common.fetch_interfaces.
    """
    read = common.fetch_interfaces(ctx)
    return read.payload, ([read.note] if read.note else [])


_NO_LINK_SCOPE = {"access_port_source": None, "trunk_ports_excluded": [], "trunk_source": None}


def _fetch_access_ports(ctx, notes):
    """(access-port names, scope facts for context).

    The names are None when the VLAN database is absent (context's link_scope
    records that) or the read failed (noted). A cache hit beside iosxe_vlans,
    best-effort — a failed read costs the link scope, never the check. The
    scope facts say which vlan-oper list named the switchports
    (access_port_source), which trunk ports were taken back out
    (trunk_ports_excluded) and where they came from (trunk_source).
    """
    try:
        vlan_payload = ctx.get(_VLAN_PATH, ok_404=True)
    except Exception as exc:  # best-effort read; transport failure modes vary
        if type(exc).__name__ == "SoftTimeLimitExceeded":
            raise  # the Celery abort signal is never a note
        notes.append("vlan-oper read failed (%s); link state kept for every port" % (exc,))
        return None, dict(_NO_LINK_SCOPE)
    if vlan_payload is None:
        return None, dict(_NO_LINK_SCOPE)
    switchports, source = common.switchports(vlan_payload)
    trunks, trunk_source = (set(), None) if not switchports else _trunk_ports(ctx, notes)
    scope = {
        "access_port_source": source,
        "trunk_ports_excluded": sorted(switchports & trunks),
        "trunk_source": trunk_source,
    }
    return _access_ports(vlan_payload, trunks), scope


def _collect_interfaces(ctx):
    payload, notes = _fetch_interfaces(ctx)
    filter_rejected = bool(notes)
    access_ports, scope = _fetch_access_ports(ctx, notes)
    raw = {
        "interfaces": _interfaces_without_statistics(payload),
        "statistics": _interface_statistics(payload),
    }
    context = _interfaces_context(payload, access_ports)
    context.update(scope)
    context["fields_filter"] = (
        "rejected (HTTP 400); unfiltered read" if filter_rejected else "accepted"
    )
    if context["counters_invalid"]:
        notes.append(
            "%d interface(s) served wrapped counter values (a uint64 at or above 2^63, not "
            "a reading): left out of context counters, named in context counters_invalid, "
            "verbatim in raw statistics" % (len(context["counters_invalid"]),)
        )
    if context["counters_not_present"]:
        notes.append(
            "%d not-present interface(s) served statistics that count nothing: left out of "
            "context counters, named in context counters_not_present"
            % (len(context["counters_not_present"]),)
        )
    if notes:
        raw["note"] = "; ".join(notes)
    return {
        "raw": raw,
        "normalized": _normalize_interfaces(payload, access_ports),
        "context": context,
    }


# --- platform health ---------------------------------------------------------

# The last reload as device-system-data records it, in YANG order: boot-time
# says when, last-reboot-reason (free text) says why, and reason-severity
# (reboot-reason-type, revision 2020-07-01) says whether the device judged it
# "normal and intentional" (normal) or "abnormal or unintentional" (abnormal).
# The container is singular: one record per device, never one per stack
# member. 17.9.1 and 17.12.1 define all three with no 9300/9500 deviation;
# 17.12.1 (revision 2023-03-01) adds reload-history beside them (up to 10
# reloads, each with its own severity), which rides in raw only. The committed
# iosxe_device_hardware.json holds only boot-time of the three, but it was
# hand-built at scaffold time (its combined-power-capacity leaf and
# 'alarm-minor' category are in neither model), so it says nothing about what
# a device serves; whether a 9300/9500 fills the other two awaits a shakedown.
# An absent leaf is recorded in context, never an error and never a
# fabricated value.
_REBOOT_LEAVES = ("boot-time", "last-reboot-reason", "reason-severity")
# boot-time is derived by the device (now minus uptime) and jitters by a second
# between two reads of a switch that never reloaded (the lab 9300 read :30, :31,
# :30 on three healthy reads and :44 / :43 on two more). Cutting the string to
# the minute only moved the failure to the minute boundary (:59 -> :00 on the
# next read), so the key holds the value as integer UTC seconds and the check's
# compare gives that field an absolute tolerance: the jitter passes, a reload
# (which moves the value by at least the reload's own minutes) diffs. The
# exact served string rides in context.
_BOOT_TIME_TOLERANCE_S = 60

# The environment sensor state word is free text per release (the model's
# `leaf state { type string }`): the lab 9300 serves 'Norm' / 'Shut', and older
# releases spelled the same sensors 'Normal' / 'Shutdown' / 'GREEN'. The
# key holds one vocabulary so an upgrade between captures does not move every
# env key at once; the served word rides in context env_states.
_ENV_STATE_WORDS = {
    "norm": "normal",
    "normal": "normal",
    "green": "normal",
    "ok": "normal",
    "good": "normal",
    "shut": "shutdown",
    "shutdown": "shutdown",
    "not present": "not-present",
    "notpresent": "not-present",
    "absent": "not-present",
    "yellow": "warning",
    "warning": "warning",
    "warn": "warning",
    "minor": "warning",
    "red": "critical",
    "critical": "critical",
    "major": "critical",
    "fault": "fault",
    "faulty": "fault",
    "fail": "fault",
    "failed": "fault",
    "failure": "fault",
    "bad": "fault",
}

# The 'last-reboot' field each leaf feeds (boot-time keeps its own key).
_LAST_REBOOT_FIELDS = (("last-reboot-reason", "reason"), ("reason-severity", "severity"))


def _normalize_platform_health(hardware_payload, env_payload):
    """(normalized, context): boot-time, last reboot, active alarms, env sensor states.

    env_payload may be None. 'last-reboot' carries only the reason/severity
    leaves the device served, as stripped strings, and is absent when it
    served neither; context names every reload leaf it did not serve.
    Volatile current-reading values are never normalized — only each sensor's
    state word; context 'readings' keeps each served reading with its units
    under the same 'env|location/sensor' key, for the reader, never diffed.
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
        normalized["boot-time"] = _boot_time_fields(boot_time)
    last_reboot = {}
    for leaf, field in _LAST_REBOOT_FIELDS:
        if system.get(leaf) is not None:
            # str(): the value keeps one type across captures whatever the encoder sent.
            last_reboot[field] = str(system[leaf]).strip()
    if last_reboot:
        normalized["last-reboot"] = last_reboot
    for alarm in _aslist(hardware.get("device-alarm")):
        if not isinstance(alarm, dict):
            continue
        key = "alarm|%s|%s" % (alarm.get("alarm-id"), alarm.get("alarm-instance"))
        normalized[key] = {"desc": alarm.get("alarm-description")}
    env_container = (
        _container(env_payload, "Cisco-IOS-XE-environment-oper:environment-sensors") or {}
    )
    readings = {}
    env_states = {}
    for sensor in _aslist(env_container.get("environment-sensor")):
        if not isinstance(sensor, dict):
            continue
        key = "env|%s/%s" % (sensor.get("location"), sensor.get("name"))
        normalized[key] = {"state": _env_state(sensor.get("state"))}
        env_states[key] = _text_or_none(sensor.get("state"))
        reading = _to_int(sensor.get("current-reading"))
        if reading is not None:
            readings[key] = {"reading": reading, "units": _strip_module(sensor.get("sensor-units"))}
    context = {
        "reboot_leaves_not_served": [leaf for leaf in _REBOOT_LEAVES if system.get(leaf) is None],
        "boot_time": None if boot_time is None else str(boot_time),
        "readings": readings,
        "env_states": env_states,
    }
    return normalized, context


def _boot_time_fields(value):
    """The boot-time key's fields: epoch (integer UTC seconds of the served
    yang:date-and-time) and text (None; the served string only when it did not
    parse, so a reload still diffs on a device that serves another shape).
    """
    stamp = common.parse_iso(value)
    if stamp is None:
        return {"epoch": None, "text": str(value)}
    return {"epoch": int(stamp.timestamp()), "text": None}


def _env_state(value):
    """A sensor's state word in one vocabulary: normal (Norm, Normal, GREEN),
    shutdown (Shut, Shutdown), not-present, warning (YELLOW), critical (RED),
    fault (Fault, Failed); any other word lower-cased with spaces hyphenated;
    None when the leaf is absent."""
    text = _text_or_none(value)
    if text is None:
        return None
    word = " ".join(text.lower().split())
    return _ENV_STATE_WORDS.get(word, word.replace(" ", "-"))


def _collect_platform_health(ctx):
    hardware = ctx.get(_HW_PATH)
    if _container(hardware, "Cisco-IOS-XE-device-hardware-oper:device-hardware-data") is None:
        raise CollectError("device-hardware-data container missing from RESTCONF reply")
    env = ctx.get(_ENV_PATH, ok_404=True)
    raw = {"device-hardware": hardware, "environment-sensors": env}
    if env is None:
        raw["note"] = "environment-sensors path absent on this release/SKU; env portion skipped"
    normalized, context = _normalize_platform_health(hardware, env)
    return {"raw": raw, "normalized": normalized, "context": context}


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
        description=(
            "CEF FIB: programmed prefix -> next-hops per forwarding instance (attached-host "
            "/32 adjacencies, which follow ARP, are counted in context, never keyed)."
        ),
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
        description=(
            "OSPFv2 adjacencies per instance/area/interface: neighbor state, address; "
            "every instance, area and interface state in context, so an empty view "
            "is explained."
        ),
        tier=1,
        compare={"mode": "equality_set"},
        miss_meaning=(
            "An OSPF adjacency is missing or not FULL — a neighbor the baseline had went "
            "away or never re-formed, or one the change was expected to add did not form."
        ),
        collector=_collect_ospf_neighbors,
        tags=("routing", "ospf"),
    )
)

register(
    CheckDef(
        id="iosxe_arp",
        platform="iosxe",
        description=(
            "ARP tables, all VRFs: resolved MAC and interface per address, from arp-entry "
            "or, where a release fills only the deprecated flat arp-oper list, from that "
            "one (context source says which)."
        ),
        tier=2,
        compare={"mode": "equality_set"},
        miss_meaning=(
            "An adjacency did not resolve — a missing or incomplete entry for a next-hop "
            "or gateway address means the device at that address is not answering ARP; a "
            "MAC change for the same address means another device now answers it."
        ),
        collector=_collect_arp,
        tags=("adjacency",),
    )
)

register(
    CheckDef(
        id="iosxe_neighbors",
        platform="iosxe",
        description=(
            "CDP and LLDP neighbor tables combined: who is on which local port, with the "
            "CDP neighbor's native VLAN, duplex and voice VLAN."
        ),
        tier=2,
        compare={"mode": "equality_set"},
        miss_meaning=(
            "A neighbor disappeared or moved — a link was bounced or mis-cabled during the "
            "window — or a CDP neighbor now advertises another native VLAN, duplex or voice "
            "VLAN across the same link."
        ),
        collector=_collect_neighbors,
        tags=("topology",),
    )
)

register(
    CheckDef(
        id="iosxe_interfaces",
        platform="iosxe",
        description=(
            "All interfaces: admin/oper status, negotiated speed and duplex, storm-control "
            "blocking, mGig downshift, and the effective config (IPv4/mask, VRF, IPv6, MTU, "
            "ACLs, QoS policies); CRC, error and flap counters in context"
        ),
        tier=2,
        compare={"mode": "equality_set"},
        miss_meaning=(
            "A port changed state outside the declared expectations — down, renegotiated to "
            "another speed or duplex, blocking a traffic type, or carrying a different "
            "address, VRF, MTU, ACL or QoS policy than before."
        ),
        collector=_collect_interfaces,
        tags=("interfaces",),
    )
)

register(
    CheckDef(
        id="iosxe_platform_health",
        platform="iosxe",
        description=(
            "Boot time (epoch seconds with a 60 s tolerance for the device's own jitter), "
            "last reboot reason and severity, active hardware alarms, environment sensor "
            "states in one vocabulary (served words and readings in context)."
        ),
        tier=3,
        compare={
            "mode": "equality_set",
            "fields": {"epoch": {"tolerance": {"abs": _BOOT_TIME_TOLERANCE_S}}},
        },
        miss_meaning=(
            "The device itself changed — a reload (boot-time moved; last-reboot gives the "
            "latest reload's reason, and severity 'abnormal' means the device did not "
            "intend it), a new alarm, or a degraded sensor during the window."
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
        raise SkipCheck(
            "no DHCP configuration present: native/ip/dhcp holds no server pools, "
            "excluded addresses, relay options or DHCP-snooping globals"
        )
    # The container key carries an augment-module prefix that varies by train;
    # store the inner config as one stable blob rather than guessing leaves.
    container = next(iter(payload.values())) if isinstance(payload, dict) else payload
    normalized = {"dhcp-config": {"value": container}}
    return {"raw": {"native/ip/dhcp": payload}, "normalized": normalized}


register(
    CheckDef(
        id="iosxe_dhcp",
        platform="iosxe",
        description=(
            "DHCP configuration under native/ip/dhcp: server pools, excluded addresses, "
            "relay options and the DHCP-snooping globals (not-present when unused)"
        ),
        tier=3,
        compare={"mode": "equality_set"},
        miss_meaning=(
            "The switch's DHCP configuration changed — pools, excluded addresses, relay "
            "options or the DHCP-snooping globals differ from the baseline."
        ),
        collector=_collect_dhcp_config,
        tags=("services",),
    )
)


# --- iosxe_syslog_errors (informational) --------------------------------------
# The finite logging buffer reduced to counts of events (%FACILITY-N-MNEMONIC):
# every severity 0-3 event, and the severity 4-5 events of a fixed facility
# allowlist — the transients that heal before a capture and leave no trace in
# any state check (an err-disable that recovered, an FHRP or STP change, a MAC
# flap, a PoE denial, an 802.1X failure, a duplicate address). What an analyst
# reads across captures is NOVELTY — an event type the baseline never logged.
# Severity 6-7 and every other severity-4/5 facility (%LINEPROTO-5-UPDOWN,
# %SYS-5-CONFIG_I, %SEC_LOGIN-5-*) are deliberately not counted: noise.
# Context keeps the buffer header facts and the oldest buffered line's
# timestamp and tag, never a line's text: log lines name users and, with
# `archive log config` and no hidekeys, carry typed commands.

# IOS syslog tag %FACILITY-SEVERITY-MNEMONIC, any severity.
_SYSLOG_TAG = re.compile(r"%([A-Z0-9_]+)-([0-7])-([A-Z0-9_]+)")
# Severities counted for every facility.
_SYSLOG_ALWAYS_MAX_SEVERITY = 3
# The facilities whose severity-4 and -5 events are counted as well (the
# plan's rec. 8 allowlist: port and link; redundancy and routing; edge
# services; platform and address). Field capture (C9300-48UXM): the
# buffer carried %STACKMGR-4-SWITCH_ADDED, %SPANTREE-5-EXTENDED_SYSID,
# %ILPOWER-5-DETECT and %ILPOWER-5-POWER_GRANTED from this list, beside 41
# %LINEPROTO-5-UPDOWN and 15 %SEC_LOGIN-5-LOGIN_SUCCESS that stay uncounted.
_SYSLOG_CURATED_FACILITIES = frozenset(
    (
        "PM",
        "SPANTREE",
        "EC",
        "UDLD",
        "CDP",
        "HSRP",
        "VRRP",
        "OSPF",
        "BGP",
        "DUAL",
        "ILPOWER",
        "DOT1X",
        "MAB",
        "SESSION_MGR",
        "AUTHMGR",
        "RADIUS",
        "DHCP_SNOOPING",
        "SW_DAI",
        "STACKMGR",
        "PLATFORM_STACKPOWER",
        "SW_MATM",
        "IP",
    )
)
_SYSLOG_CURATED_MAX_SEVERITY = 5

# The buffer is bounded, but raw artifacts should stay small: keep the tail,
# where the newest (most relevant) events live. Counting runs on full output.
_SYSLOG_RAW_TAIL_CHARS = 20000

# The `show logging` header, as IOS prints it (field-verified on the lab 9300):
#   Syslog logging: enabled (0 messages dropped, 2 messages rate-limited,
#                            0 flushes, 0 overruns, xml disabled, ...)
#   Buffer logging:  level debugging, 189 messages logged, xml disabled,
#   Log Buffer (102400 bytes):
_SYSLOG_HEADER_RULES = (
    (re.compile(r"Syslog logging:\s*(?P<syslog>enabled|disabled)"), None),
    (re.compile(r"(?P<dropped>\d+) messages? dropped"), None),
    (re.compile(r"(?P<rate_limited>\d+) messages? rate-limited"), None),
    (re.compile(r"(?P<flushes>\d+) flushes"), None),
    (re.compile(r"(?P<overruns>\d+) overruns"), None),
    (
        re.compile(
            r"Buffer logging:\s*(?:level\s+(?P<level>\S+),\s*)?"
            r"(?:(?P<messages_logged>\d+) messages? logged|(?P<buffer>disabled))"
        ),
        None,
    ),
    (re.compile(r"Log Buffer \((?P<bytes>\d+) bytes\)"), None),
)
_SYSLOG_HEADER_FIELDS = (
    "syslog",
    "level",
    "messages_logged",
    "bytes",
    "dropped",
    "rate_limited",
    "flushes",
    "overruns",
)
_SYSLOG_BUFFER_START = re.compile(r"^Log Buffer \(\d+ bytes\):")
# A buffered line: an optional sequence number, an optional clock marker ('*'
# the clock was never set, '.' NTP not in sync), the timestamp `service
# timestamps log datetime [msec] [localtime] [show-timezone] [year]` prints,
# and the tag. A line without timestamps (service timestamps off) still has
# its tag.
_SYSLOG_LINE = re.compile(
    r"^(?:\d+:\s+)?"
    r"(?:[*.]?(?P<timestamp>[A-Z][a-z]{2}\s+\d{1,2}(?:\s+\d{4})?\s+\d{2}:\d{2}:\d{2}"
    r"(?:\.\d+)?(?:\s+[A-Za-z]+)?):\s+)?"
    r"(?P<tag>%[A-Z0-9_]+-[0-7]-[A-Z0-9_]+)"
)


def _syslog_counted(facility, severity):
    """Whether one event type is counted: severity 0-3 always, 4-5 for the allowlist."""
    if severity <= _SYSLOG_ALWAYS_MAX_SEVERITY:
        return True
    return severity <= _SYSLOG_CURATED_MAX_SEVERITY and facility in _SYSLOG_CURATED_FACILITIES


def _parse_syslog_errors(text):
    """'sev<N>|%FAC-N-MNEMONIC' -> {'count': n} for every counted event in the buffer."""
    counts = {}
    for facility, severity, mnemonic in _SYSLOG_TAG.findall(text or ""):
        if not _syslog_counted(facility, int(severity)):
            continue
        key = "sev%s|%%%s-%s-%s" % (severity, facility, severity, mnemonic)
        counts.setdefault(key, {"count": 0})["count"] += 1
    return counts


def _parse_syslog_header(text):
    """The buffer header facts and the oldest buffered line, for context.

    buffer: syslog (enabled/disabled), level (the buffered level), messages_logged,
    bytes (the buffer size), dropped, rate_limited, flushes, overruns — None
    where the header does not print the fact. oldest: the timestamp text and
    tag of the first buffered line that carries a tag (None when the buffer
    holds none), so a reader sees how far back the buffer reaches; never the
    line's text. uncounted_events: tags in the buffer the counting rules skip.
    """
    header = dict.fromkeys(_SYSLOG_HEADER_FIELDS)
    oldest = None
    in_buffer = False
    uncounted = 0
    for line in (text or "").splitlines():
        stripped = line.strip()
        if not in_buffer:
            for rule, _unused in _SYSLOG_HEADER_RULES:
                match = rule.search(stripped)
                if match is None:
                    continue
                for name, value in match.groupdict().items():
                    if value is None or name == "buffer":
                        continue
                    header[name] = int(value) if value.isdigit() else value
                if match.groupdict().get("buffer") == "disabled":
                    header["level"] = "disabled"
            if _SYSLOG_BUFFER_START.match(stripped):
                in_buffer = True
            continue
        match = _SYSLOG_LINE.match(stripped)
        if match is None:
            continue
        if oldest is None:
            oldest = {"timestamp": match.group("timestamp"), "tag": match.group("tag")}
        facility, severity, _mnemonic = _SYSLOG_TAG.match(match.group("tag")).groups()
        if not _syslog_counted(facility, int(severity)):
            uncounted += 1
    return {"buffer": header, "oldest": oldest, "uncounted_events": uncounted}


# Redaction of the buffer text before it enters the debug trace, raw or the
# parser (ctx.run_ssh applies it to the output): the message part of a
# tagged line, never its timestamp or tag, so counting still works.
# The shapes the field buffer showed, and the CFGLOG one:
#   %SEC_LOGIN-5-LOGIN_SUCCESS: Login Success [user: <name>] [Source: ...]
#   %SEC_LOGIN-4-LOGIN_FAILED: Login failed [user: <name>] ...
#   %SYS-6-LOGOUT: User <name> has exited tty session 1(...)
#   %DMI-5-AUTH_PASSED: ... dmiauthd: User '<name>' authenticated successfully ...
#   %SYS-5-CONFIG_I: Configured from console by <name> on vty0 (...)
#   %PARSER-5-CFGLOG_LOGGEDCMD: User:<name>  logged command:<the typed line>
# then the config-text rules for key / password / secret / community tokens
# on whatever is left (over-redaction of a message is acceptable; a leak is
# not).
_SYSLOG_TAGGED = re.compile(r"^(?P<head>.*?%[A-Z0-9_]+-[0-7]-[A-Z0-9_]+:)(?P<message>.*)$")
_SYSLOG_USER_BRACKET = re.compile(r"(\[user:\s*)[^\]]*(\])", re.IGNORECASE)
# The token after the word "user" in any of its spellings — "User:<name>",
# "User <name>", "User '<name>'", "user '<name>'" — quotes kept around the mark.
# 'user jdoe', 'User:jdoe', "user 'jdoe'" and, from the %AAA-6-USERNAME_* and
# USER_PRIVILEGE_UPDATE events a local-user edit logs, 'username: jdoe'.
_SYSLOG_USER_WORD = re.compile(r"(\buser(?:name)?\b\s*:?\s*'?)[^\s'\]]+('?)", re.IGNORECASE)
_SYSLOG_CONFIGURED_BY = re.compile(r"(\bConfigured from \S+ by )\S+")
_SYSLOG_LOGGED_COMMAND = re.compile(r"(logged command:).*$")


def _redact_syslog_line(line):
    """One `show logging` line with usernames, logged commands and secrets masked."""
    match = _SYSLOG_TAGGED.match(line)
    if match is None:
        return _redact_config_line(line)
    message = match.group("message")
    message = _SYSLOG_USER_BRACKET.sub(lambda m: m.group(1) + _SECRET_MARK + m.group(2), message)
    message = _SYSLOG_USER_WORD.sub(lambda m: m.group(1) + _SECRET_MARK + m.group(2), message)
    message = _SYSLOG_CONFIGURED_BY.sub(lambda m: m.group(1) + _SECRET_MARK, message)
    message = _SYSLOG_LOGGED_COMMAND.sub(lambda m: m.group(1) + " " + _SECRET_MARK, message)
    return match.group("head") + _redact_config_line(message)


def _redact_syslog_text(text):
    """Whole-output form of _redact_syslog_line — ctx.run_ssh's hook for `show logging`."""
    return "\n".join(_redact_syslog_line(line) for line in str(text).splitlines())


def _collect_syslog_errors(ctx):
    if not ctx.has_ssh:
        raise SkipCheck("no SSH transport")
    # The hook redacts the output before the trace keeps it and before it is
    # returned: nothing below ever sees a username or a logged command.
    output = ctx.run_ssh("show logging", redact=_redact_syslog_text)
    normalized = _parse_syslog_errors(output)
    header = _parse_syslog_header(output)
    context = {
        "error_events_total": sum(
            entry["count"]
            for key, entry in normalized.items()
            if int(key[3 : key.index("|")]) <= _SYSLOG_ALWAYS_MAX_SEVERITY
        ),
        "curated_events_total": sum(
            entry["count"]
            for key, entry in normalized.items()
            if int(key[3 : key.index("|")]) > _SYSLOG_ALWAYS_MAX_SEVERITY
        ),
        "distinct_event_types": len(normalized),
        "uncounted_events": header["uncounted_events"],
        "buffer": header["buffer"],
        "oldest": header["oldest"],
    }
    raw = {"show logging": (output or "")[-_SYSLOG_RAW_TAIL_CHARS:]}
    return {"raw": raw, "normalized": normalized, "context": context}


register(
    CheckDef(
        id="iosxe_syslog_errors",
        platform="iosxe",
        description=(
            "Syslog event counts from the logging buffer: every severity 0-3 event plus the "
            "severity 4-5 events of the port, redundancy, edge-service and platform "
            "facilities (buffer header and oldest-line facts in context; usernames and "
            "logged commands redacted)"
        ),
        tier=3,
        compare={"mode": "info_only"},
        miss_meaning="",
        collector=_collect_syslog_errors,
        tags=("platform", "logs"),
    )
)


# --- iosxe_svl_health (always-on optional feature) ----------------------------
# The StackWise Virtual link is the virtual-switch backbone: every packet
# crossing chassis rides it. Cisco-IOS-XE-switch-cp-svl-oper (17.15.1, the
# same shape since its first revision) nests location (keys fru/slot/bay/
# chassis/node) -> svl-link-info[link-num] -> member-port (if-name, bundled,
# is-control-port, the LMP counters) beside the link's SDP and OOB counters.
# Field finding: the lab's standalone 9300 serves the container with ONE
# location (fru-fp/0/0/chassis 1/node 0) and no svl-link-info at all, while
# older releases do not serve the path (404) — both are "not an SVL system", so the
# check reads not-present unless some location carries a link. The walk keeps
# a few alternative spellings behind the model's own, so a release that
# drifts still reads rather than silently emptying.

_SVL_PATH = "/data/Cisco-IOS-XE-switch-cp-svl-oper:switch-cp-svl-oper-data"

# Leaf-name candidates, the 17.15.1 model's spelling first.
_SVL_LINK_NUM_LEAVES = ("link-num", "svl-link-num", "link-number")
_SVL_PORT_LEAVES = ("if-name", "port-name", "port", "name")
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


def _svl_locations(payload):
    """The location entries (dicts) of a switch-cp-svl-oper-data payload; [] when unserved."""
    container = _container(payload, "Cisco-IOS-XE-switch-cp-svl-oper:switch-cp-svl-oper-data")
    container = container if isinstance(container, dict) else {}
    return [entry for entry in _aslist(container.get("location")) if isinstance(entry, dict)]


def _svl_links(location):
    """The svl-link-info entries (dicts) of one location; [] when it carries none."""
    return [link for link in _aslist(location.get("svl-link-info")) if isinstance(link, dict)]


def _normalize_svl(payload):
    """('svl-link|<chassis>/<link-num>' view, 'counters|<link>' context) as a pair.

    Membership and bundled state are the comparable facts; every numeric leaf
    under a link sums into context — counters are informational, never
    equality-compared.
    """
    normalized = {}
    context = {}
    for location in _svl_locations(payload):
        chassis = _first_leaf(location, ("chassis", "node", "slot"))
        chassis = chassis if chassis is not None else "unknown"
        for link in _svl_links(location):
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
        raise SkipCheck("no StackWise Virtual data: the model is not served (not an SVL system)")
    locations = _svl_locations(payload)
    if not any(_svl_links(location) for location in locations):
        raise SkipCheck(
            "no StackWise Virtual links: the model serves %d location(s) with no svl-link-info "
            "(not an SVL system)" % (len(locations),)
        )
    normalized, context = _normalize_svl(payload)
    context["locations"] = len(locations)
    return {"raw": {"switch-cp-svl-oper": payload}, "normalized": normalized, "context": context}


register(
    CheckDef(
        id="iosxe_svl_health",
        platform="iosxe",
        description=(
            "StackWise Virtual links: member ports and bundled state per chassis/link "
            "(not-present when no location carries a link)"
        ),
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
# Read from Cisco-IOS-XE-ntp-oper (17.15.1; the lab fills the same leaves):
# ntp-status-info is a presence container (absent until NTP is configured)
# built from the grouping ntp-container-data — `stratum`, a `refid` container
# holding ONE case of the choice refid-pkt-type-choice (ip-addr; kod-data/
# kod-type; ref-clk-src-data/ref-clk-src-type; exception-code) and the
# ntp-associations list, each with `peer-selection-status` (the
# peer-select-status enum), `peer-reach`, `peer-stratum`, `serv-type`,
# `peer-authentication-status`, its own `refid` and its `ntp-address`
# (ip-addr + vrf-name). The model has no synchronized leaf: it is derived.
# Field finding (three reads, 8 minutes apart): the sys-peer moves between
# healthy servers as the selection algorithm re-runs, so the system refid
# address and each association's exact selection status are context; what
# normalized keeps is what a healthy device holds steady — the stratum, the
# KIND of reference (an address, a KoD code, a reference clock), and each
# association's health class. Offset, delay, dispersion and reach are jitter:
# raw and context only.

_NTP_PATH = "/data/Cisco-IOS-XE-ntp-oper:ntp-oper-data"
_NTP_CONTAINER = "Cisco-IOS-XE-ntp-oper:ntp-oper-data"

# The refid choice cases, (leaf or container name, refid_kind) in model order.
_NTP_REFID_CASES = (
    ("ip-addr", "ip-addr"),
    ("kod-data", "kod"),
    ("ref-clk-src-data", "clock-source"),
    ("exception-code", "exception"),
)
# peer-select-status values that make an association a usable time source
# (selected, a candidate, or a survivor beyond the first six) against the
# values that discard it (a loop, unreachable, bad distance, false ticker,
# beyond the first ten, an outlier).
_NTP_SELECTED = ("ntp-peer-sys-peer", "ntp-peer-pps-peer")
_NTP_USABLE = _NTP_SELECTED + ("ntp-peer-candidate", "ntp-peer-as-backup")
_NTP_REJECTED = (
    "ntp-peer-rejected",
    "ntp-peer-false-ticker",
    "ntp-peer-excess",
    "ntp-peer-outlier",
)
# NTP's unsynchronized stratum.
_NTP_STRATUM_UNSYNC = 16


def _ntp_status(payload):
    """The ntp-status-info container of a payload; {} when absent (NTP unconfigured)."""
    container = _container(payload, _NTP_CONTAINER) or {}
    status = container.get("ntp-status-info") if isinstance(container, dict) else None
    return status if isinstance(status, dict) else {}


def _ntp_refid(refid):
    """(kind, value) of a refid container: which case of the choice the device filled.

    kind is ip-addr, kod, clock-source or exception (None when the container
    is absent or fills no case); value the address, the KoD code (kod-type,
    'ntp-ref-init' style), the clock source type or the exception code as
    text.
    """
    if not isinstance(refid, dict):
        return None, None
    for name, kind in _NTP_REFID_CASES:
        if name not in refid:
            continue
        inner = refid[name]
        if isinstance(inner, dict):
            value = _text_or_none(inner.get("kod-type") or inner.get("ref-clk-src-type"))
            if value is None:
                value = _text_or_none(",".join("%s=%s" % item for item in sorted(inner.items())))
        else:
            value = _text_or_none(inner)
        return kind, value
    return None, None


def _ntp_association_key(assoc):
    """'<vrf>|<address>' of an association, else 'id:<assoc-id>' when it names no address."""
    address = assoc.get("ntp-address")
    address = address if isinstance(address, dict) else {}
    ip = _text_or_none(address.get("ip-addr"))
    if ip is not None:
        return "%s|%s" % (_text_or_none(address.get("vrf-name")) or "default", ip)
    return "id:%s" % (assoc.get("assoc-id"),)


def _ntp_health(assoc):
    """The association's health class: unreachable, usable, rejected or unknown."""
    reach = _to_int(assoc.get("peer-reach"))
    if reach == 0:
        return "unreachable"
    selection = _strip_module(assoc.get("peer-selection-status"))
    if selection in _NTP_USABLE:
        return "usable"
    if selection in _NTP_REJECTED:
        return "rejected"
    return "unknown"


def _ntp_associations(payload):
    """The association entries (dicts) of ntp-status-info, in payload order."""
    return [a for a in _aslist(_ntp_status(payload).get("ntp-associations")) if isinstance(a, dict)]


def _ntp_synchronized(stratum, refid_kind, associations):
    """Whether the clock is synchronized, derived (the model has no leaf for it).

    True: a stratum below 16, a reference that is an address or a reference
    clock, and — when associations are listed — one selected as the sys peer
    (or PPS peer). False: stratum 16, a KoD or exception reference, or
    associations with none selected. None: nothing served to judge by.
    """
    if stratum is None and refid_kind is None and not associations:
        return None
    if stratum is not None and stratum >= _NTP_STRATUM_UNSYNC:
        return False
    if refid_kind in ("kod", "exception"):
        return False
    if associations:
        selections = [_strip_module(a.get("peer-selection-status")) for a in associations]
        if not any(selection in _NTP_SELECTED for selection in selections):
            return False
    if stratum is None and refid_kind is None:
        return None
    return True


def _normalize_ntp(payload):
    """Flat scalars: synchronized, stratum, refid_kind, and 'association|<vrf>|<address>'
    -> health class (usable / rejected / unreachable / unknown) per association."""
    status = _ntp_status(payload)
    stratum = _to_int(status.get("stratum"))
    refid_kind, _value = _ntp_refid(status.get("refid"))
    associations = _ntp_associations(payload)
    normalized = {
        "synchronized": _ntp_synchronized(stratum, refid_kind, associations),
        "stratum": stratum,
        "refid_kind": refid_kind,
    }
    for assoc in associations:
        normalized["association|%s" % (_ntp_association_key(assoc),)] = _ntp_health(assoc)
    return normalized


def _ntp_context(payload):
    """The moving parts: the system refid value and the peer it points at, and per
    association its exact selection status, reach, stratum, type, authentication
    status and refid."""
    status = _ntp_status(payload)
    _kind, refid = _ntp_refid(status.get("refid"))
    associations = {}
    sys_peer = None
    for assoc in _ntp_associations(payload):
        key = _ntp_association_key(assoc)
        selection = _strip_module(assoc.get("peer-selection-status"))
        if selection in _NTP_SELECTED and sys_peer is None:
            sys_peer = key
        _peer_kind, peer_refid = _ntp_refid(assoc.get("refid"))
        associations[key] = {
            "selection": selection,
            "reach": _to_int(assoc.get("peer-reach")),
            "stratum": _to_int(assoc.get("peer-stratum")),
            "type": _short(assoc.get("serv-type"), "ntp-"),
            "auth": _short(assoc.get("peer-authentication-status"), "ntp-auth-"),
            "refid": peer_refid,
        }
    return {
        "refid": refid,
        "sys_peer": sys_peer,
        "sys_poll": _to_int(status.get("sys-poll")),
        "associations": dict(sorted(associations.items())),
    }


def _collect_ntp(ctx):
    payload = ctx.get(_NTP_PATH, ok_404=True)
    if not payload or not _ntp_status(payload):
        raise SkipCheck(
            "NTP not configured: ntp-oper-data serves no ntp-status-info (the presence "
            "container appears once an ntp server or peer is configured)"
        )
    return {
        "raw": {"ntp-oper": payload},
        "normalized": _normalize_ntp(payload),
        "context": _ntp_context(payload),
    }


register(
    CheckDef(
        id="iosxe_ntp",
        platform="iosxe",
        description=(
            "NTP sync: synchronized (derived), stratum, the kind of reference (address, KoD "
            "code, reference clock) and each association's health class; the selected peer "
            "in context"
        ),
        tier=3,
        compare={"mode": "equality_scalar"},
        miss_meaning=(
            "Time sync changed — the clock lost or gained synchronization, moved stratum, "
            "or an NTP association became unusable — so timestamps in every other capture "
            "and in device logs become suspect."
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
    """Whole-output form of _redact_config_lines (secrets only; see _redact_config_output)."""
    return "\n".join(_redact_config_lines(str(text).splitlines()))


# The two header comments that name the account that last changed or saved
# the configuration ("! Last configuration change at <clock> by <user>",
# "! NVRAM config last updated at <clock> by <user>"). Usernames never enter
# a snapshot: the name is masked and the clock kept, wherever the header
# line is stored (raw, the debug trace) — the normalized text drops the line.
_CONFIG_HEADER_USER = re.compile(
    r"^(?P<keep>\s*! (?:Last configuration change|NVRAM config last updated) at .+?\s+by\s+)"
    r"\S.*$"
)


def _scrub_config_header_user(line):
    """A header line with its 'by <user>' account masked; any other line unchanged."""
    match = _CONFIG_HEADER_USER.match(line)
    if match is None:
        return line
    return match.group("keep") + _SECRET_MARK


def _redact_config_output(text):
    """Every secret redacted AND the header accounts masked — ctx.run_ssh's trace hook
    for the config reads, and the form raw stores."""
    return "\n".join(
        _scrub_config_header_user(line) for line in _redact_config_lines(str(text).splitlines())
    )


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
        # The clock is lifted; the account after 'by' is matched and never
        # captured, so no snapshot part — context included — carries a name.
        (r"! Last configuration change at (?P<last_change_at>.+?)(?: by .+?)?", {}),
        (r"! NVRAM config last updated at (?P<nvram_updated_at>.+?)(?: by .+?)?", {}),
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
    """One SSH read traced through the redact hook; a failure fails the check, redacted.

    The verbatim text comes back (return_verbatim): running-vs-startup's
    verbatim_in_sync compares the two texts before redaction and stores
    neither; everything stored below is redacted here, line by line.
    """
    try:
        output = ctx.run_ssh(command, redact=_redact_config_output, return_verbatim=True, **kwargs)
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
    raw[command] = _redact_config_output(output).splitlines()
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
        raw[command] = [_scrub_config_header_user(line) for line in redacted]
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
# `dir` listing line: "  14  -rw-  123456   Aug 24 2026 18:22:11 -04:00  name".
# The permissions column is captured so directories ("drwx") can be told
# apart from files: field-verified on a 9300 stack, crashinfo:tracelogs is a
# directory rewritten by routine logging and read as a same-day "crash" on
# every member until directories were excluded. The clock and the UTC offset
# are captured too: the field stack prints its local time ("-04:00"), and a
# file's date is keyed in UTC so both crash-file sources date it alike. The
# offset is optional, and a name is never split when it is missing.
_DIR_LINE = re.compile(
    r"^\s*\d+\s+(\S+)\s+\d+\s+([A-Z][a-z]{2})\s+(\d+)\s+(\d{4})\s+([\d:]+)(?:\.\d+)?\s+"
    r"(?:(\S+)\s+)?(\S+)\s*$"
)


def _dir_modified(month, day, year, clock, offset):
    """UTC moment of one `dir` timestamp; None when its date does not parse.

    The printed wall-clock time is the device's local time and converts with
    the listing's own offset. A clock or offset of any other shape (or none)
    leaves the printed date standing as a UTC date, which is how every listing
    was read before offsets were honoured; so does a moment the offset would
    shift past the calendar's edge (year 1 or 9999 raises OverflowError, not
    ValueError, and must never fail the check).
    """
    month_num = _MONTHS.get(month)
    if month_num is None:
        return None
    try:
        printed = datetime(int(year), month_num, int(day), tzinfo=timezone.utc)
    except (ValueError, OverflowError):
        return None
    stamp = "%s %s %s" % (printed.strftime("%Y-%m-%d"), clock, offset or "")
    try:
        return datetime.strptime(stamp, "%Y-%m-%d %H:%M:%S %z").astimezone(timezone.utc)
    except (ValueError, OverflowError):
        return printed


def _window_date(moment, now, recent_days):
    """(UTC date 'YYYY-MM-DD', inside the recency window) for an aware moment.

    The cut compares UTC midnights, the window arithmetic the dir parser has
    always used, so the dir listings and the q-filesystem model place one file
    identically.
    """
    utc = moment.astimezone(timezone.utc)
    midnight = datetime(utc.year, utc.month, utc.day, tzinfo=timezone.utc)
    return midnight.strftime("%Y-%m-%d"), (now - midnight).days <= recent_days


def _parse_crash_dir(cli_output, now, recent_days):
    """(recent {name: {modified}}, older_count) from a `dir crashinfo:` listing.

    Only files inside the recency window become normalized keys — a fresh
    crash during a change window must surface as an ADDED key, while ancient
    dumps must never create diff noise (operator requirement). Directories
    are neither keyed nor counted: crash dumps and system reports are files,
    while a directory's date moves whenever anything inside it is written
    (tracelogs/ on every member). Dates are UTC (see _dir_modified), and so
    is the window. Unparseable dates fail safe: included as recent with the
    raw date string.
    """
    recent = {}
    older = 0
    for line in (cli_output or "").splitlines():
        match = _DIR_LINE.match(line)
        if not match:
            continue
        perms, month, day, year, clock, offset, name = match.groups()
        if perms.lower().startswith("d"):
            continue
        if name.lower() in ("core", "crashinfo:", ".", ".."):
            continue
        moment = _dir_modified(month, day, year, clock, offset)
        if moment is None:
            recent[name] = {"modified": "%s %s %s" % (month, day, year)}
            continue
        modified, is_recent = _window_date(moment, now, recent_days)
        if is_recent:
            recent[name] = {"modified": modified}
        else:
            older += 1
    return recent, older


def _dir_listed(output):
    """True when a `dir` answered with a listing — not a refusal or an open error.

    A listing always opens with its "Directory of <fs>/" header, and an open
    error never carries it. Keying on the header, not on the word "error",
    matters both ways: "%Error opening crashinfo-1:/ (No such file or
    directory)" contains "directory" and once passed for a listing (skipping
    the alias fallback and hiding the member from members_not_listed), while
    a real listing may hold a file whose name contains "error".
    """
    if _cli_rejected(output):
        return False
    return "directory of" in (output or "").lower()


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


# The q-filesystem list of Cisco-IOS-XE-platform-software-oper (17.9.1
# revision 2022-07-01, advertised by the 9300; unchanged in 17.12.1 but for
# the yang-version) is a second crash-file source, and a BEST GUESS until a
# shakedown settles it. The model keys one entry per internal location
# (fru/slot/bay/chassis) and gives each a core-files list (filename + time,
# described only as "Core file information"), its partitions, and under each
# partition a partition-content list of every file on it. What a 9300 fills
# in is unverified: whether chassis is the stack member number, whether
# core-files holds system reports and crashinfo files or only the process
# and kernel cores IOS-XE writes into a core/ subdirectory (which the dir
# listings never descend into), and whether filename is a name or a path.
# The check reads it narrowed to the location keys, core files and partition
# names — partition-content is unbounded and never read here; the shakedown
# reads the full list (_summarize_q_filesystem).
_Q_FS_PATH = (
    "/data/Cisco-IOS-XE-platform-software-oper:cisco-platform-software"
    "?fields=q-filesystem(fru;slot;bay;chassis;core-files;partitions(name))"
)
_Q_FS_LIST_PATH = "/data/Cisco-IOS-XE-platform-software-oper:cisco-platform-software/q-filesystem"

# yang:date-and-time ("2026-09-25T03:28:44+00:00", fractions of any length).
_YANG_TIME = re.compile(
    r"^(\d{4}-\d{2}-\d{2})[Tt ](\d{2}:\d{2}:\d{2})(?:\.\d+)?\s*([Zz]|[+-]\d{2}:?\d{2})?$"
)

# Shakedown summary: entry names that look crash-related, and the cap on how
# many entries of a list are echoed per location.
_Q_FS_CRASH_TOKENS = ("crash", "core", "system-report", "koops")
_Q_FS_SAMPLE_MAX = 20


def _yang_moment(value):
    """UTC moment of a yang:date-and-time leaf; None when absent or unparseable.

    A moment UTC cannot hold (year 1 or 9999 shifted past the calendar's
    edge) is unparseable too, never an OverflowError out of the check.
    """
    match = _YANG_TIME.match(str(value).strip()) if value is not None else None
    if match is None:
        return None
    date, clock, offset = match.groups()
    stamp = "%s %s %s" % (date, clock, (offset or "+00:00").upper())
    try:
        return datetime.strptime(stamp, "%Y-%m-%d %H:%M:%S %z").astimezone(timezone.utc)
    except (ValueError, OverflowError):
        return None


def _basename(path):
    """A file's own name from either path spelling ('/crashinfo/core/x', 'crashinfo:x')."""
    return str(path or "").rstrip("/").rsplit("/", 1)[-1].rsplit(":", 1)[-1]


def _q_filesystem_entries(payload):
    """q-filesystem list entries from the container read or the bare list read."""
    container = _container(payload, "Cisco-IOS-XE-platform-software-oper:cisco-platform-software")
    if isinstance(container, dict):
        entries = container.get("q-filesystem")
    else:
        entries = _container(payload, "Cisco-IOS-XE-platform-software-oper:q-filesystem")
    return [entry for entry in _aslist(entries) if isinstance(entry, dict)]


def _fs_location(entry):
    """'<fru>/<slot>/<bay>/<chassis>': the entry's own list keys, verbatim."""
    return "/".join(str(entry.get(leaf)) for leaf in ("fru", "slot", "bay", "chassis"))


def _q_filesystem_core_files(payload, member_numbers, now, recent_days):
    """(recent {key: {modified}}, per-location summary, keyed, older) from q-filesystem.

    A location whose chassis is a roster member number keys its files
    'member<N>|<name>' — the best guess that chassis is the switch number, so
    a file the dir listings also see collapses into their key. Any other
    location keys 'core@<fru>/<slot>/<bay>/<chassis>|<name>', stable by
    construction (the model's own list keys). Names are basenames, whatever
    form filename takes. The window is the dir parser's, in UTC; a time that
    does not parse fails safe as recent, keeping the raw text ("unknown" when
    the leaf is absent — a string like every other value, so a key's value
    never changes type with the source that answered). keyed/older count
    core-file entries in and outside it. Locations are read in the order of
    their location text and each one's files in filename order, so when two
    entries meet on one key (two locations sharing a chassis number, or one
    name in two directories) the value kept never depends on the order the
    device listed them in.
    """
    recent = {}
    locations = {}
    keyed = older = 0
    for entry in sorted(_q_filesystem_entries(payload), key=_fs_location):
        location = _fs_location(entry)
        chassis = _to_int(entry.get("chassis"))
        member = chassis if chassis is not None and str(chassis) in member_numbers else None
        prefix = "core@%s" % (location,) if member is None else "member%d" % (member,)
        files = [item for item in _aslist(entry.get("core-files")) if isinstance(item, dict)]
        partitions = [p for p in _aslist(entry.get("partitions")) if isinstance(p, dict)]
        summary = {
            "core_files": len(files),
            "partitions": sorted(str(partition.get("name")) for partition in partitions),
        }
        if member is not None:
            summary["member"] = member
        locations[location] = summary
        for item in sorted(files, key=lambda core: str(core.get("filename"))):
            name = _basename(item.get("filename"))
            if not name:
                continue
            moment = _yang_moment(item.get("time"))
            if moment is None:
                leaf = item.get("time")
                value = {"modified": "unknown" if leaf is None else str(leaf)}
            else:
                modified, is_recent = _window_date(moment, now, recent_days)
                if not is_recent:
                    older += 1
                    continue
                value = {"modified": modified}
            keyed += 1
            recent.setdefault("%s|%s" % (prefix, name), value)
    return recent, locations, keyed, older


def _read_q_filesystem(ctx):
    """(payload, status, note) of the one best-effort narrowed q-filesystem read.

    Follows the stack-oper supplement: a 404 is "not served", a transport
    failure is a note, and neither ever fails or skips the check. HTTP 400 is
    how a release refuses a fields filter (checks_iosxe_wireless._fetch), so
    only a 400 records the narrowed read as rejected; it is never retried
    unnarrowed, because the full list carries partition-content, whose size
    is unknown and unbounded. Any other HTTP error (401/403, a 5xx from the
    DMI backend) is a failed read with its status code, not a verdict on the
    fields expression.
    """
    try:
        payload = ctx.get(_Q_FS_PATH, ok_404=True)
    except Exception as exc:  # best-effort read; transport failure modes vary
        if type(exc).__name__ == "SoftTimeLimitExceeded":
            raise  # the Celery abort signal is never a note
        status_code = getattr(exc, "status_code", None)
        if status_code == 400:
            note = (
                "q-filesystem narrowed read rejected (HTTP 400), not retried unnarrowed "
                "(partition-content is unbounded): %s" % (exc,)
            )
            return None, "rejected (HTTP 400)", note
        status = "read failed"
        if isinstance(status_code, int) and status_code >= 400:
            status = "read failed (HTTP %d)" % (status_code,)
        return None, status, "q-filesystem supplement failed: %s" % (exc,)
    if payload is None:
        return None, "not served (404)", None
    return payload, "served", None


def _merge_q_filesystem(ctx, member_numbers, now, raw, normalized):
    """The q-filesystem context summary, once its keys are merged into normalized.

    The model's keys merge in without displacing a dir key — a file both
    sources see keeps the dir listing's value — and how often the two met (or
    disagreed on the date), and how many keys only the model produced, is
    counted: evidence for the chassis-is-member guess, and for reading an
    ADDED key when the model answered on one side only. Nothing here fails the
    check: parsing unverified device data under a best guess is guarded like
    the read, and a failure is a status plus a raw note, the dir view intact.
    """
    payload, status, note = _read_q_filesystem(ctx)
    raw["q-filesystem"] = payload
    summary = {"status": status}
    if payload is not None:
        try:
            found, locations, keyed, older = _q_filesystem_core_files(
                payload, member_numbers, now, C.CRASH_RECENT_DAYS
            )
        except Exception as exc:  # best guess over unverified device data
            if type(exc).__name__ == "SoftTimeLimitExceeded":
                raise  # the Celery abort signal is never a note
            summary["status"] = "parse failed"
            note = "q-filesystem supplement could not be parsed: %s: %s" % (
                type(exc).__name__,
                exc,
            )
        else:
            shared = disagreeing = 0
            for key, value in found.items():
                if key not in normalized:
                    normalized[key] = value
                    continue
                shared += 1
                if normalized[key] != value:
                    disagreeing += 1
            summary.update(
                {
                    "locations": locations,
                    "core_files_keyed": keyed,
                    "core_files_older": older,
                    "keys_also_listed_by_dir": shared,
                    "keys_from_model_only": len(found) - shared,
                    "dates_disagreeing_with_dir": disagreeing,
                }
            )
    if note:
        raw["note"] = note
    return summary


def _summarize_q_filesystem(payload):
    """Per-location shape of a FULL q-filesystem read, for the Collector Shakedown.

    Answers what the check's narrowed read cannot see: per location, every
    partition's partition-content entry counts by type ({} when the partition
    lists nothing), the entries whose own name looks crash-related (the first
    _Q_FS_SAMPLE_MAX, verbatim, with the partition they sit on, plus the total),
    and the core-files count with the first entries verbatim. Names, not full
    paths, are matched: crashinfo's tracelogs/ holds hundreds of files under a
    path containing "crash", and they would crowd out everything else.
    """
    if payload is None:
        return {"served": False}
    locations = {}
    for entry in _q_filesystem_entries(payload):
        partitions = {}
        crash_related = []
        for partition in _aslist(entry.get("partitions")):
            if not isinstance(partition, dict):
                continue
            name = str(partition.get("name"))
            counts = {}
            for item in _aslist(partition.get("partition-content")):
                if not isinstance(item, dict):
                    continue
                kind = str(item.get("type") or "unknown")
                counts[kind] = counts.get(kind, 0) + 1
                own_name = _basename(item.get("full-path")).lower()
                if any(token in own_name for token in _Q_FS_CRASH_TOKENS):
                    crash_related.append({"partition": name, **item})
            partitions[name] = counts
        core_files = [item for item in _aslist(entry.get("core-files")) if isinstance(item, dict)]
        locations[_fs_location(entry)] = {
            "partitions": partitions,
            "crash_related": crash_related[:_Q_FS_SAMPLE_MAX],
            "crash_related_total": len(crash_related),
            "core_files": len(core_files),
            "core_files_sample": core_files[:_Q_FS_SAMPLE_MAX],
        }
    return {"served": True, "locations": locations}


def _collect_crash_files(ctx, now=None):
    if not ctx.has_ssh:
        raise SkipCheck("no SSH transport")
    if now is None:
        now = datetime.now(timezone.utc)
    raw = {}
    normalized = {}
    older_total = 0
    listed = []

    # The roster comes first: `show switch detail` is rejected on platforms
    # that do not stack (recorded in raw, nothing more to learn from it).
    detail = ctx.run_ssh("show switch detail")
    raw["show switch detail"] = detail
    members = {} if _cli_rejected(detail) else _parse_switch_detail(detail)[1]
    roles = {number: str(facts.get("role") or "").lower() for number, facts in members.items()}

    # Keys carry the member NUMBER, never the role: a switchover or stack
    # reload between captures swaps which member answers crashinfo: and
    # stby-crashinfo:, and a role-keyed file would read as removed on one
    # side and added on the other with nothing new on flash. Field-verified
    # on a 4-member 9300: crashinfo-<N>: answers for the active and standby
    # members too, so every member is listed by number; the two role aliases
    # (crashinfo: the active's own filesystem, stby-crashinfo: the standby's)
    # are the fallback when a member's numbered filesystem does not answer.
    not_listed = []
    for number in sorted(members, key=int):
        side = "member%s" % (number,)
        filesystem = "crashinfo-%s:" % (number,)
        ok, older = _crash_listing(ctx, "dir " + filesystem, side, now, raw, normalized)
        alias = {"active": "crashinfo:", "standby": "stby-crashinfo:"}.get(roles[number])
        if not ok and alias:
            filesystem = alias
            ok, older = _crash_listing(ctx, "dir " + alias, side, now, raw, normalized)
        older_total += older
        if ok:
            listed.append(filesystem)
        else:
            not_listed.append(int(number))

    # No roster (a router, or a chassis switch with dual supervisors): only
    # the role aliases exist, and there is no member number to key by.
    if not members:
        for filesystem, side in (("crashinfo:", "active"), ("stby-crashinfo:", "stby")):
            ok, older = _crash_listing(ctx, "dir " + filesystem, side, now, raw, normalized)
            older_total += older
            if ok:
                listed.append(filesystem)

    if not listed:
        raise SkipCheck("crashinfo filesystems not listable on this platform")

    # The q-filesystem supplement (the best guess described at _Q_FS_PATH)
    # runs once the dir listings answered: they alone decide whether the
    # check is present.
    q_filesystem = _merge_q_filesystem(ctx, set(members), now, raw, normalized)

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
    context["q_filesystem"] = q_filesystem
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
        compare={"mode": "equality_set", "ignore_removed": True},
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
_ERRDISABLE_COMMAND = "show interfaces status err-disabled"
# The port-error-code enum value (Cisco-IOS-XE-ios-common-oper) that marks a
# port err-disabled; the other value is port-error-none.
_PORT_ERROR_DISABLE = "port-error-disable"
# Raw keeps the extended-state rows of at most this many interfaces.
_ERRDISABLE_RAW_MAX = 1024


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


def _normalize_errdisable(payload):
    """(normalized, ext_states) from the interfaces-oper intf-ext-state leaves.

    ext_states: interface name -> {error-type, port-error-reason} for every
    interface serving an error-type leaf, {} when no interface does (the
    caller then falls back to the CLI). normalized: the interfaces whose
    error-type is port-error-disable -> {"reason": <port-err-* enum>}; healthy
    is EMPTY. Enum values keep the model's spelling (port-err-bpduguard).
    """
    normalized = {}
    ext_states = {}
    for entry in _interface_entries(payload):
        name = entry.get("name")
        ext = _ext_state(entry)
        if name is None or ext.get("error-type") is None:
            continue
        error_type = _strip_module(ext.get("error-type"))
        reason = _strip_module(ext.get("port-error-reason"))
        ext_states[name] = {"error-type": error_type, "port-error-reason": reason}
        if error_type == _PORT_ERROR_DISABLE:
            normalized[name] = {"reason": reason}
    return normalized, ext_states


def _collect_errdisable(ctx):
    # Primary source: the intf-ext-state container of the interfaces GET
    # iosxe_interfaces makes (identical path and kwargs: a cache hit when the
    # fields filter was accepted; on the HTTP 400 path the rejected filtered
    # request is re-issued, since a failed GET is never cached, and only the
    # unfiltered read is the cache hit). The read stays best-effort — a failed
    # GET costs the model source, never the check — and the CLI form is the
    # fallback wherever no interface serves the leaves (older releases, or a
    # fields filter that dropped them). Which source answered rides in context.
    raw = {}
    notes = []
    try:
        payload, fetch_notes = _fetch_interfaces(ctx)
    except Exception as exc:  # best-effort read; transport failure modes vary
        if type(exc).__name__ == "SoftTimeLimitExceeded":
            raise  # the Celery abort signal is never a note
        notes.append("interfaces-oper read failed (%s); CLI fallback used" % (exc,))
    else:
        notes.extend(fetch_notes)
        normalized, ext_states = _normalize_errdisable(payload)
        if ext_states:
            raw["intf-ext-state"] = dict(sorted(ext_states.items())[:_ERRDISABLE_RAW_MAX])
            if notes:
                raw["note"] = "; ".join(notes)
            context = {
                "source": "intf-ext-state",
                "ports_with_ext_state": len(ext_states),
                "ports_errdisabled": len(normalized),
            }
            return {"raw": raw, "normalized": normalized, "context": context}
        notes.append("intf-ext-state served on no interface; CLI fallback used")
    if not ctx.has_ssh:
        raise SkipCheck("intf-ext-state not served and no SSH transport for the CLI fallback")
    output = ctx.run_ssh(_ERRDISABLE_COMMAND)
    raw[_ERRDISABLE_COMMAND] = output
    lowered = (output or "").lower()
    if "invalid input" in lowered or "incomplete command" in lowered:
        raise SkipCheck("err-disabled status form rejected on this platform")
    normalized = _parse_errdisable(output)
    raw["note"] = "; ".join(notes)
    context = {
        "source": _ERRDISABLE_COMMAND,
        "ports_with_ext_state": 0,
        "ports_errdisabled": len(normalized),
    }
    return {"raw": raw, "normalized": normalized, "context": context}


_PO_LINE = re.compile(r"^\d+\s+(Po\d+)\(([\w-]*)\)\s+(\S+)\s*(.*)$")
_PO_MEMBER = re.compile(r"([A-Za-z]{2}[A-Za-z]*[\d/\.]+)\(([\w-]+)\)")

# LACP partner identity from Cisco-IOS-XE-lacp-oper (17.15.1, revision
# 2024-03-01; older releases do not advertise it and answer 404):
# lag-oper-data -> lag-info[channel-group] (link totals, port-channel-up,
# layer-type) and lacp-port-channel[channel-group] -> lacp-member-state
# [if-name] (system-id, partner-id, partner-key, oper-key, port-num,
# partner-port-num, state ∈ lacp-bndl / -susp / -hot-sby / -indiv / -indep /
# -down / -unkn, counters). `show etherchannel summary` stays the source of
# the bundle keys (it is the operator's view and answers on every release);
# the model adds per-member keys naming the far end. No port-channel existed
# on the lab while the model was advertised, so what an empty release
# answers ({} or a container with empty lists) is tolerated either way and
# context records which source answered.
_LACP_PATH = "/data/Cisco-IOS-XE-lacp-oper:lag-oper-data"
_LACP_CONTAINER = "Cisco-IOS-XE-lacp-oper:lag-oper-data"
_LACP_NO_PARTNER = "00:00:00:00:00:00"


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


def _lacp_lists(payload):
    """(lag-info entries, lacp-port-channel entries) of a lag-oper-data payload."""
    container = _container(payload, _LACP_CONTAINER)
    container = container if isinstance(container, dict) else {}
    info = [e for e in _aslist(container.get("lag-info")) if isinstance(e, dict)]
    channels = [e for e in _aslist(container.get("lacp-port-channel")) if isinstance(e, dict)]
    return info, channels


def _lacp_partner_mac(value):
    """A partner-id / system-id as canonical MAC text; None when absent or all-zero
    (no partner: the port is down or hears no LACPDUs)."""
    text = common.mac_canonical(value)
    return None if text in (None, _LACP_NO_PARTNER) else text


def _normalize_lacp(payload):
    """'PoN|<member>' -> LACP state and the partner's identity, from lacp-port-channel.

    Members are keyed by the short interface name (the spelling `show
    etherchannel summary` uses for the same port). state is the model's
    port-state enum without its 'lacp-' prefix (bndl, susp, hot-sby, indiv,
    indep, down, unkn); partner_system_id the far end's system MAC (None
    when all-zero: no partner), partner_key and partner_port its key and port
    number (None without a partner), oper_key this side's key. The LACPDU
    counters never come here.
    """
    normalized = {}
    _info, channels = _lacp_lists(payload)
    for channel in channels:
        group = _to_int(channel.get("channel-group"))
        if group is None:
            continue
        for member in _aslist(channel.get("lacp-member-state")):
            if not isinstance(member, dict):
                continue
            name = _text_or_none(member.get("if-name"))
            if name is None:
                continue
            partner = _lacp_partner_mac(member.get("partner-id"))
            normalized["Po%d|%s" % (group, common.short_ifname(name))] = {
                "state": _short(_strip_module(member.get("state")), "lacp-"),
                "partner_system_id": partner,
                "partner_key": _to_int(member.get("partner-key")) if partner else None,
                "partner_port": _to_int(member.get("partner-port-num")) if partner else None,
                "oper_key": _to_int(member.get("oper-key")),
            }
    return normalized


def _lacp_context(payload):
    """Per channel-group the lag-info totals and up flag, and this side's system-id
    per member (the local stack MAC: moves with the active, so context)."""
    info, channels = _lacp_lists(payload)
    groups = {}
    for entry in info:
        group = _to_int(entry.get("channel-group"))
        if group is None:
            continue
        groups["Po%d" % (group,)] = {
            "up": common.yes(entry.get("port-channel-up")),
            "layer": _short(_strip_module(entry.get("layer-type")), ""),
            "links": _to_int(entry.get("total-no-of-links")),
            "bundled": _to_int(entry.get("total-no-of-links-bundled")),
            "standby": _to_int(entry.get("total-no-of-links-standby")),
            "down": _to_int(entry.get("total-no-of-links-down")),
            "suspended": _to_int(entry.get("total-no-of-links-suspended")),
        }
    system_ids = {}
    for channel in channels:
        for member in _aslist(channel.get("lacp-member-state")):
            if isinstance(member, dict) and member.get("if-name"):
                system_ids[common.short_ifname(str(member["if-name"]))] = common.mac_canonical(
                    member.get("system-id")
                )
    return {"groups": dict(sorted(groups.items())), "system_id": dict(sorted(system_ids.items()))}


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
    raw = {command: output}
    notes = []
    # Best-effort widening: a failed model read costs the partner identity,
    # never the check; context says which source answered.
    try:
        lacp = ctx.get(_LACP_PATH, ok_404=True)
    except Exception as exc:  # best-effort read; transport failure modes vary
        if type(exc).__name__ == "SoftTimeLimitExceeded":
            raise  # the Celery abort signal is never a note
        lacp = None
        lacp_source = "read failed"
        notes.append("lacp-oper read failed (%s): no partner identity this capture" % (exc,))
    else:
        if lacp is None:
            lacp_source = "not served"
        elif not any(_lacp_lists(lacp)):
            lacp_source = "served, empty"
        else:
            lacp_source = "served"
    raw[_LACP_PATH] = lacp
    members = _normalize_lacp(lacp) if lacp else {}
    normalized.update(members)
    context = {
        "sources": {"show etherchannel summary": "answered", "lacp-oper": lacp_source},
        "port_channels": sum(1 for key in normalized if "|" not in key),
        "members_listed": sum(len(v["members"]) for k, v in normalized.items() if "|" not in k),
        "members_bundled": sum(
            1
            for k, v in normalized.items()
            if "|" not in k
            for flags in v["members"].values()
            if "P" in flags
        ),
        "lacp_members": len(members),
    }
    context.update(_lacp_context(lacp) if lacp else {"groups": {}, "system_id": {}})
    if notes:
        raw["note"] = "; ".join(notes)
    return {"raw": raw, "normalized": normalized, "context": context}


register(
    CheckDef(
        id="iosxe_errdisable",
        platform="iosxe",
        description=(
            "Ports in err-disabled state with the triggering reason, from the interfaces "
            "model's extended state (CLI fallback)"
        ),
        tier=1,
        compare={"mode": "equality_set"},
        miss_meaning=(
            "A port was knocked into err-disable during the window — it reads as merely "
            "'down' everywhere else; the reason here says why (BPDU guard, port security, "
            "link-flap, UDLD, storm-control, inline power...)."
        ),
        collector=_collect_errdisable,
        tags=("interfaces",),
    )
)

register(
    CheckDef(
        id="iosxe_port_channels",
        platform="iosxe",
        description=(
            "Port-channel bundles with per-member flags, plus each member's LACP state and "
            "partner identity (system-id, key, port) where lacp-oper is served"
        ),
        tier=1,
        compare={"mode": "equality_set"},
        miss_meaning=(
            "A bundle's membership or a member's flags changed — a suspended or "
            "standalone member quietly halves capacity without downing the "
            "port-channel — or a member now bundles with another partner system or "
            "port, meaning the far end was re-cabled or replaced."
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
# detail` for the member roster plus port topology, `show switch stack-ports
# summary` for per-port link health. Each member's identity joins on its
# switch number only where the device itself keys by it: stack-oper's
# stack-node list is keyed by chassis-number (the switch number) and carries
# the member's serial and a reload reason (leaf spellings field-verified on
# a 4-member 9300), and the model is the part number of the device-inventory
# chassis entry carrying that SERIAL. device-inventory's hw-dev-index is not
# a switch number: the YANG calls it only "the physical index of the
# inventory item", and the field stack's four chassis entries carry 1, 8, 15
# and 20 — joined on it, members 2-4 had no identity and a replaced member
# went unnoticed. Not every stack-node leaf is the member's own: the field
# release repeats identical sp-stats and sp-stats-time on every node seen,
# and the YANG describes reload-reason as "Reload reason for all stack
# members" (the field's "Image Install" on members 1, 3 and 4 cannot tell
# per-member from stack-wide), so a serial repeated across stack-nodes
# names none of them.
# Where stack-oper is not served or misses a member (older releases; an SVL
# pair may not serve it), `show inventory` names each member's chassis, and
# a lone member pairs with a lone chassis entry. Always asked by doctrine:
# platforms that do not stack reject the command and record as not-present;
# a standalone switch or an SVL pair answers with one or two members.

_STACK_OPER_PATH = common.STACK_OPER_PATH

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

    Keyed by hw-dev-index for the raw evidence only: the index is the item's
    physical inventory index, not its switch number (a field-verified
    4-member 9300 carries 1, 8, 15 and 20), so members find their chassis
    entry by serial. Power supplies, fans and modules are skipped.
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


def _stack_leaf(node, name):
    """A leaf of a stack-node (or any entry) as stripped text; None when absent or blank."""
    value = node.get(name) if isinstance(node, dict) else None
    text = "" if value is None else str(value).strip()
    return text or None


def _stack_nodes(stack_oper_payload):
    """'<chassis-number>' -> stack-node entry of stack-oper-data; {} when not served.

    Field-verified on a 4-member 9300: one entry per member, chassis-number
    equal to the switch number, carrying serial-number, role, node-state,
    priority, mac-address, reload-reason and the stack-ports list.
    """
    container = _container(stack_oper_payload, "Cisco-IOS-XE-stack-oper:stack-oper-data")
    container = container if isinstance(container, dict) else {}
    nodes = {}
    for node in _aslist(container.get("stack-node")):
        if not isinstance(node, dict):
            continue
        number = _to_int(node.get("chassis-number"))
        if number is not None:
            nodes[str(number)] = node
    return nodes


# `show inventory` parsing (NAME/DESCR + PID/VID/SN pairs, the member chassis
# entries) lives in iosxe_common; the historical names stay bound here.
_INVENTORY_NAME_LINE = common.INVENTORY_NAME_LINE
_INVENTORY_PID_LINE = common.INVENTORY_PID_LINE
_INVENTORY_MEMBER_NAME = common.INVENTORY_MEMBER_NAME
_INVENTORY_DESCR = common.INVENTORY_DESCR
_inventory_items = common.inventory_items
_parse_show_inventory = common.parse_show_inventory


# serial_source value for the last-resort pairing of a lone roster member
# with the lone chassis entry of the hardware inventory.
_LONE_CHASSIS = "device-inventory lone chassis"


def _member_identity(members, nodes, chassis, inventory_output=None, inventory_failed=False):
    """Each roster member's serial and model, with their sources; (identity, notes).

    identity: '<n>' -> {serial, model, serial_source, model_source}, None where
    unresolved. serial: the member's stack-oper stack-node (keyed by
    chassis-number, the switch number); else — once ``show inventory`` was
    consulted (its output given, or inventory_failed) — its 'Switch <n>' /
    'Chassis <n>' entry; else, for a lone member beside a lone device-inventory
    chassis entry, that chassis. A serial names one chassis: one stack-oper
    repeats across stack-nodes names none of them, and one that still lands
    on two members is withdrawn from both. Serials read upper-cased, as the
    join compares them, so a change of source never flips the spelling.
    model: the part number of the device-inventory chassis entry carrying the
    serial; else show inventory's PID when its entry for the member carries
    the same SN. hw-dev-index plays no part. notes say why a member has no
    serial or model, and name the chassis serials no member carries (a member
    whose serial differs between the sources, or inventory beyond the roster).
    """
    by_serial = {}
    for facts in chassis.values():
        if facts.get("serial"):
            by_serial.setdefault(facts["serial"].upper(), facts)
    consulted = inventory_failed or inventory_output is not None
    rejected = _cli_rejected(inventory_output)
    listed = {} if rejected else _parse_show_inventory(inventory_output)
    # One member beside one chassis is unambiguous only when every chassis
    # entry carries that serial: a repeated entry is still one chassis, one
    # without a serial could be the member's own.
    lone_serial = None
    if len(members) == 1 and len(by_serial) == 1 and all(f.get("serial") for f in chassis.values()):
        lone_serial = next(iter(by_serial.values()))["serial"]
    oper_serials = {key: _stack_leaf(node, "serial-number") for key, node in nodes.items()}
    holders = {}
    for key, serial in oper_serials.items():
        if serial is not None:
            holders.setdefault(serial.upper(), []).append(key)
    repeated = {serial: keys for serial, keys in holders.items() if len(keys) > 1}
    notes = [
        "stack-oper repeats serial-number %s on chassis-number %s: used for none of them"
        % (serial, ", ".join(sorted(keys, key=int)))
        for serial, keys in sorted(repeated.items())
    ]
    identity = {}
    whys = {}
    for number in sorted(members, key=int):
        key = str(int(number))
        facts = dict.fromkeys(("serial", "model", "serial_source", "model_source"))
        serial_why, model_why = [], []
        # show inventory's own entry for this member, or why it cannot serve.
        entry = listed.get(key) or {}
        if not consulted:
            miss = "show inventory not consulted"
        elif inventory_failed:
            miss = "show inventory failed"
        elif rejected:
            miss = "show inventory rejected"
        elif key not in listed:
            miss = "show inventory names no Switch/Chassis entry for it"
        elif listed[key] is None:
            miss = "show inventory lists it twice, differently"
        else:
            miss = None

        serial = oper_serials.get(key)
        if serial is None:
            serial_why.append("no stack-oper serial-number")
        elif serial.upper() in repeated:
            serial_why.append("its stack-oper serial-number repeats on another stack-node")
        else:
            facts.update(serial=serial, serial_source="stack-oper")
        if facts["serial"] is None:
            if miss is None and entry.get("serial"):
                facts.update(serial=entry["serial"], serial_source="show inventory")
            else:
                serial_why.append(miss or "its show inventory entry has no SN")
                if consulted and lone_serial is not None:
                    facts.update(serial=lone_serial, serial_source=_LONE_CHASSIS)
                elif consulted:
                    serial_why.append("not a lone member beside a lone chassis entry")

        if facts["serial"] is not None:
            facts["serial"] = facts["serial"].upper()
            model = (by_serial.get(facts["serial"]) or {}).get("model")
            if model:
                facts.update(model=model, model_source="device-inventory")
            else:
                model_why.append("no device-inventory chassis part-number for its serial")
                listed_serial = str(entry.get("serial") or "").upper()
                if miss is not None:
                    model_why.append(miss)
                elif not listed_serial:
                    model_why.append("its show inventory entry has no SN")
                elif listed_serial != facts["serial"]:
                    model_why.append("its show inventory entry carries another SN")
                elif not entry.get("model"):
                    model_why.append("its show inventory entry has no PID")
                else:
                    facts.update(model=entry["model"], model_source="show inventory")
        identity[number] = facts
        whys[number] = (serial_why, model_why)

    # A serial still on two members (the sources contradict each other, or
    # show inventory repeats an SN) identifies neither: withdrawn from both.
    carriers = {}
    for number, facts in identity.items():
        if facts["serial"] is not None:
            carriers.setdefault(facts["serial"], []).append(number)
    for serial, numbers in carriers.items():
        if len(numbers) > 1:
            for number in numbers:
                identity[number] = dict.fromkeys(identity[number])
                whys[number] = (["one serial for more than one member: %s" % (serial,)], [])

    gaps = {}
    for number, facts in identity.items():
        serial_why, model_why = whys[number]
        if facts["serial"] is None:
            gap = ("no serial or model", tuple(serial_why))
        elif facts["model"] is None:
            gap = ("no model", tuple(model_why))
        else:
            continue
        gaps.setdefault(gap, []).append(number)
    notes.extend(
        "switch %s: %s (%s)" % (", ".join(numbers), label, "; ".join(why))
        for (label, why), numbers in gaps.items()
    )
    carried = {facts["serial"] for facts in identity.values() if facts["serial"]}
    unclaimed = [
        "%s (hw-dev-index %s)" % (facts["serial"], index)
        for index, facts in sorted(chassis.items(), key=lambda item: (len(item[0]), item[0]))
        if facts.get("serial") and facts["serial"].upper() not in carried
    ]
    if unclaimed:
        notes.append("device-inventory chassis serials on no member: %s" % (", ".join(unclaimed),))
    return identity, notes


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

    # Member models come from the hardware inventory the platform-health
    # check also reads — identical path and kwargs, so the per-run cache
    # issues one GET for both — found by serial, never by hw-dev-index.
    hardware = ctx.get(_HW_PATH)
    chassis = _chassis_inventory(hardware)
    raw["device-inventory chassis"] = chassis

    # stack-oper serves each member's serial and reload reason by switch
    # number. The read stays best-effort: where it is not served (older
    # releases; an SVL pair may not serve it) serials fall back to show
    # inventory below, never to a failed check. How the read went rides in
    # context: reload_reason vanishing from every member is then readable as
    # "not read this time", never as a reload.
    try:
        stack_oper = ctx.get(_STACK_OPER_PATH, ok_404=True)
    except Exception as exc:  # best-effort read; transport failure modes vary
        if type(exc).__name__ == "SoftTimeLimitExceeded":
            raise  # the Celery abort signal is never a note
        stack_oper = None
        stack_oper_read = "read failed"
        notes.append(
            "stack-oper read failed (%s): no reload reasons, member serials from the fallbacks"
            % (exc,)
        )
    else:
        stack_oper_read = "served"
        if stack_oper is None:
            stack_oper_read = "not served"
            notes.append(
                "stack-oper not served on this release: no reload reasons, member serials "
                "from the fallbacks"
            )
    raw["stack-oper"] = stack_oper
    nodes = _stack_nodes(stack_oper)
    if stack_oper is not None and not nodes:
        stack_oper_read = "served without stack-node entries"
        notes.append("stack-oper answered without stack-node entries")
    strays = sorted(set(nodes) - {str(int(number)) for number in members}, key=int)
    if strays:
        notes.append("stack-oper chassis-numbers with no roster member: %s" % (", ".join(strays),))

    identity, identity_notes = _member_identity(members, nodes, chassis)
    if any(facts["serial"] is None or facts["model"] is None for facts in identity.values()):
        # Only when stack-oper and the hardware inventory leave a member
        # without serial or model: its 'Switch <n>' / 'Chassis <n>' entry.
        # Best-effort like stack-oper: a failed fallback costs members their
        # identity (the lone-chassis rule still applies), never the roster
        # and ring.
        inventory_command = "show inventory"
        try:
            inventory = ctx.run_ssh(inventory_command)
        except Exception as exc:  # best-effort read; transport failure modes vary
            if type(exc).__name__ == "SoftTimeLimitExceeded":
                raise  # the Celery abort signal is never a note
            notes.append("show inventory failed (%s)" % (exc,))
            identity, identity_notes = _member_identity(
                members, nodes, chassis, inventory_failed=True
            )
        else:
            raw[inventory_command] = inventory
            identity, identity_notes = _member_identity(members, nodes, chassis, inventory)
    notes.extend(identity_notes)

    normalized = {}
    if stack:
        normalized["stack"] = stack
    for number, facts in members.items():
        entry = dict(facts)
        for field in ("model", "serial"):
            if identity[number][field] is not None:
                entry[field] = identity[number][field]
        # The reload reason stack-oper reports on the member's stack-node,
        # only where served. It holds until a reload, so a reload between
        # captures need not read unchanged; whether it is the member's own
        # or the stack's is unverified (see the section comment).
        node = nodes.get(str(int(number)))
        reload_reason = _stack_leaf(node, "reload-reason")
        if reload_reason is not None:
            entry["reload_reason"] = reload_reason
        # stack-oper's sso-ready-flag ("Standby SSO Ready flag", boolean): on
        # the standby it says whether a switchover would be stateful; on the
        # active and on plain members it reads false (field: false on a
        # standalone active and on members 1, 3 and 4 of a 4-member stack;
        # the standby was not captured). Only where served.
        sso_ready = common.yes(node.get("sso-ready-flag")) if isinstance(node, dict) else None
        if sso_ready is not None:
            entry["sso_ready"] = sso_ready
        normalized["switch|%s" % (number,)] = entry
    for key, facts in ports.items():
        normalized["stack-port|%s" % (key,)] = facts
    order = sorted(members, key=int)
    context = {
        "members_total": len(members),
        "members_ready": sum(1 for m in members.values() if m.get("state", "").lower() == "ready"),
        "stack_ports_total": len(ports),
        "stack_ports_ok": sum(1 for p in ports.values() if p.get("status") == "OK"),
        # Which source served each member's serial and model (None: none did),
        # and how the stack-oper read went. Context, never normalized: the
        # source may differ between captures while the value does not.
        "serial_source": {number: identity[number]["serial_source"] for number in order},
        "model_source": {number: identity[number]["model_source"] for number in order},
        "stack_oper": stack_oper_read,
    }
    if notes:
        raw["note"] = "; ".join(notes)
    return {"raw": raw, "normalized": normalized, "context": context}


register(
    CheckDef(
        id="iosxe_switch_stack",
        platform="iosxe",
        description=(
            "Switch stack members (role, state, model, serial, reload reason, SSO-ready "
            "flag) and stack-port ring health"
        ),
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


# --- iosxe_inventory ---------------------------------------------------------
# Chassis identity on every IOS-XE form (standalone, StackWise, StackWise
# Virtual, modular): model, serial, description and hardware version of every
# chassis, module, power supply, fan and transceiver the device lists.
# Source: device-inventory of Cisco-IOS-XE-device-hardware-oper on the GET
# platform-health and the stack check already make (a cache hit). Its list
# key is (hw-type hw-dev-index), and hw-dev-index is the item's physical
# inventory index (field-verified: 1, 8, 15 and 20 for the chassis of a
# 4-member 9300 stack), so a normalized row is keyed on the item's dev-name,
# else its serial, and on the index only when it carries neither — context
# names those rows. Fallback: `show inventory`, whose NAME plays dev-name.
# Member roles and the ring live in iosxe_switch_stack; identity lives here.

_INVENTORY_CLASSES = {
    "hw-type-chassis": "chassis",
    "hw-type-pim": "module",
    "hw-type-pem": "psu",
    "hw-type-fantray": "fan",
    "hw-type-transceiver": "transceiver",
}
# On-board parts (CPU, memory, storage) are not field-replaceable identity:
# counted in context, never keyed. hw-type-ssd also carries a lifetime
# percentage, which would drift. Any other hw-type reads as 'other'.
_INVENTORY_INTERNAL = (
    "hw-type-cpu",
    "hw-type-dram",
    "hw-type-flash",
    "hw-type-emmc",
    "hw-type-sdcard",
    "hw-type-usb",
    "hw-type-ssd",
)
_INVENTORY_LEAVES = (
    ("part-number", "model"),
    ("serial-number", "serial"),
    ("hw-description", "description"),
    ("version", "version"),
)
# Raw keeps at most this many device-inventory entries.
_INVENTORY_RAW_MAX = 512
_INVENTORY_COMMAND = "show inventory"
# `show inventory` names: a transceiver by its port ("Te1/1/1",
# "TwentyFiveGigE1/0/1"); the stack-level pseudo entry ("c93xx Stack")
# repeats the active member's PID and SN, so it would move with a
# switchover and is skipped (context names it).
_INVENTORY_PORT_NAME = re.compile(r"^[A-Za-z][A-Za-z-]*\d+(?:/\d+)+$")
_INVENTORY_STACK_NAME = re.compile(r"\bstack$", re.IGNORECASE)
_INVENTORY_CLASS_WORDS = (("power supply", "psu"), ("fan", "fan"), ("module", "module"))


def _inventory_facts(model, serial, description, version):
    """The four identity fields, each stripped text or None; serial upper-cased so a
    change of source never flips its spelling."""
    serial = _text_or_none(serial)
    return {
        "model": _text_or_none(model),
        "serial": serial.upper() if serial else None,
        "description": _text_or_none(description),
        "version": _text_or_none(version),
    }


def _inventory_place(normalized, key, facts, serial):
    """Store facts under key; a second item with the same key is suffixed by its
    serial (else by its occurrence ordinal, '#2', '#3', ... — never by the
    hw-dev-index, which may move across a reload) so neither hides the other.
    Returns the key used."""
    if key in normalized and normalized[key] != facts:
        if serial:
            key = "%s|sn:%s" % (key, serial)
        else:
            ordinal = 2
            while "%s|#%d" % (key, ordinal) in normalized:
                ordinal += 1
            key = "%s|#%d" % (key, ordinal)
    normalized[key] = facts
    return key


_inventory_entries = common.device_inventory


def _normalize_inventory(hardware_payload):
    """(normalized, facts) from device-inventory: '<class>|<dev-name>' (else
    '<class>|sn:<serial>', else '<class>|pn:<part-number>') -> model, serial,
    description, version. A row with neither name, serial nor part number has
    no replaceable identity, and its hw-dev-index may move across a reload, so
    it is never keyed: facts unidentified counts those per class. facts also
    carries items_by_class, keyed_by_part_number (the rows keyed on their part
    number alone) and internal_skipped (on-board parts by hw-type)."""
    normalized = {}
    by_class = {}
    keyed_by_pn = []
    unidentified = {}
    internal = {}
    for entry in _inventory_entries(hardware_payload):
        hw_type = str(entry.get("hw-type") or "").strip().split(":")[-1].lower()
        if hw_type in _INVENTORY_INTERNAL:
            internal[hw_type] = internal.get(hw_type, 0) + 1
            continue
        cls = _INVENTORY_CLASSES.get(hw_type, "other")
        facts = _inventory_facts(
            entry.get("part-number"),
            entry.get("serial-number"),
            entry.get("hw-description"),
            entry.get("version"),
        )
        name = _text_or_none(entry.get("dev-name"))
        by_class[cls] = by_class.get(cls, 0) + 1
        if name is not None:
            key = "%s|%s" % (cls, name)
        elif facts["serial"] is not None:
            key = "%s|sn:%s" % (cls, facts["serial"])
        elif facts["model"] is not None:
            key = "%s|pn:%s" % (cls, facts["model"])
        else:
            unidentified[cls] = unidentified.get(cls, 0) + 1
            continue
        key = _inventory_place(normalized, key, facts, facts["serial"])
        if name is None and facts["serial"] is None and key not in keyed_by_pn:
            keyed_by_pn.append(key)
    return normalized, {
        "items_by_class": by_class,
        "keyed_by_part_number": keyed_by_pn,
        "unidentified": unidentified,
        "internal_skipped": internal,
    }


def _inventory_cli_class(name, descr):
    """The identity class of a `show inventory` item from its NAME (and DESCR); None
    for the stack-level pseudo entry."""
    if _INVENTORY_MEMBER_NAME.match(name):
        return "chassis"
    if _INVENTORY_STACK_NAME.search(name):
        return None
    if _INVENTORY_PORT_NAME.match(name):
        return "transceiver"
    haystack = ("%s %s" % (name, descr)).lower()
    for word, cls in _INVENTORY_CLASS_WORDS:
        if word in haystack:
            return cls
    return "other"


def _normalize_inventory_cli(cli_output):
    """(normalized, facts) from `show inventory`: '<class>|<NAME>' -> model (PID),
    serial (SN), description (DESCR), version (VID); the CLI fallback's view,
    shaped like _normalize_inventory's. facts: items_by_class, skipped (the
    pseudo entries left out)."""
    normalized = {}
    by_class = {}
    skipped = []
    for item in _inventory_items(cli_output):
        cls = _inventory_cli_class(item["name"], item["descr"])
        if cls is None:
            skipped.append(item["name"])
            continue
        facts = _inventory_facts(item["pid"], item["sn"], item["descr"], item["vid"])
        _inventory_place(normalized, "%s|%s" % (cls, item["name"]), facts, facts["serial"])
        by_class[cls] = by_class.get(cls, 0) + 1
    return normalized, {
        "items_by_class": by_class,
        "keyed_by_part_number": [],
        "unidentified": {},
        "skipped": skipped,
    }


def _collect_inventory(ctx):
    hardware = ctx.get(_HW_PATH)
    if _container(hardware, "Cisco-IOS-XE-device-hardware-oper:device-hardware-data") is None:
        raise CollectError("device-hardware-data container missing from RESTCONF reply")
    raw = {}
    notes = []
    entries = _inventory_entries(hardware)
    raw["device-inventory"] = entries[:_INVENTORY_RAW_MAX]
    normalized, facts = _normalize_inventory(hardware)
    source = "device-inventory"
    if not normalized:
        # A device that answered lists its hardware somewhere: the model
        # served no identity rows, so the CLI is asked. Nothing here is ever
        # not-present — an empty inventory is a failed read.
        notes.append(
            "device-inventory served no entries"
            if not entries
            else "device-inventory served no chassis/module/psu/fan/transceiver entries"
        )
        if not ctx.has_ssh:
            raise CollectError("%s and no SSH transport for %s" % (notes[-1], _INVENTORY_COMMAND))
        output = ctx.run_ssh(_INVENTORY_COMMAND)
        raw[_INVENTORY_COMMAND] = output
        if _cli_rejected(output):
            raise CollectError("%s and '%s' rejected" % (notes[-1], _INVENTORY_COMMAND))
        normalized, facts = _normalize_inventory_cli(output)
        source = _INVENTORY_COMMAND
        if not normalized:
            raise CollectError("%s and '%s' listed no items" % (notes[-1], _INVENTORY_COMMAND))
    context = {"source": source}
    context.update(facts)
    if notes:
        raw["note"] = "; ".join(notes)
    return {"raw": raw, "normalized": normalized, "context": context}


register(
    CheckDef(
        id="iosxe_inventory",
        platform="iosxe",
        description=(
            "Hardware identity on every platform form: model, serial, description and "
            "version of each chassis, module, power supply, fan and transceiver"
        ),
        tier=1,
        compare={"mode": "equality_set"},
        miss_meaning=(
            "A hardware item changed identity, vanished or appeared — a chassis, module, "
            "power supply, fan or transceiver was replaced, removed or inserted during the "
            "window (a serial change on an unchanged key is a swap of that part; a removed "
            "key is a part no longer listed)."
        ),
        collector=_collect_inventory,
        tags=("platform", "inventory"),
    )
)
