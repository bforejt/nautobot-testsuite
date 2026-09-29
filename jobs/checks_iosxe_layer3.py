"""Catalyst layer-3 state the RIB cannot show: gateway roles and the EIGRP /
IS-IS adjacencies.

Three checks. ``iosxe_fhrp`` records which router is active/master for every
HSRP and VRRP group, because a flipped active router or a split brain is
invisible while every SVI reads up. ``iosxe_eigrp_neighbors`` and
``iosxe_isis_neighbors`` complete the adjacency set beside
``iosxe_ospf_neighbors`` / ``iosxe_bgp_peers`` (jobs/checks_iosxe.py): until
now those two protocols were seen only through their effect on the RIB.

Sources, YANG-first (leaf names verified against the published 17.15.1
models on disk, never from memory, then against what the lab switch that
produced the fixtures actually filled; release differences are recorded
where they matter):

* ``Cisco-IOS-XE-hsrp-oper`` ``hsrp-oper-data/hsrp-group-info[group-id
  if-name]`` (``priority``, ``preempt``, ``state``, ``active-ip``,
  ``standby-ip``, ``virtual-ip``) and ``hsrp-neighbor[if-name]/neighbor``
  (``address``, ``active-list``, ``standby-list``, ``passive``,
  ``bfd-enabled``). A release that does not advertise the model answers 404,
  one that does answers an empty container while no group is configured; the
  lab licence refuses ``standby`` configuration, so the HSRP fixture is hand-built from
  the model.
* ``Cisco-IOS-XE-vrrp-oper`` ``vrrp-oper-data/vrrp-oper-state[if-number
  group-id addr-type]``: ``if-name``, ``version``, ``virtual-ip``,
  ``vrrp-state``, ``master-ip``, ``is-owner``, ``priority``, ``preempt``;
  the transition facts ``master-transitions``, ``new-master-reason``,
  ``state-change-reason``, ``last-state-change-time``; ``track-list``
  (``track-name``, ``track-obj-state``). The lab filled one VRRPv3 group
  with every leaf of its 2019-05-01 revision (no ``track-list``,
  ``state-change-reason`` or BFD leaves in that revision).
* ``Cisco-IOS-XE-eigrp-oper`` ``eigrp-oper-data/eigrp-instance[afi vrf-name
  as-num]/eigrp-interface[name]/eigrp-nbr[afi nbr-address]``. The neighbor
  grouping carries the peer's software/TLV version, its stub flags
  (presence leaves) and the SRTT/RTO/retransmit counters — NO state leaf: a
  listed neighbor is an established adjacency, and that is what the key
  asserts. The lab filled one instance with two interfaces and, as the
  model says, no ``eigrp-nbr`` element at all when there is no neighbor.
  ``eigrp-topo`` (the whole topology table) and ``auth-val`` (whose
  ``auth-key`` holds a ``sha256-password`` leaf) are left out of the
  ``fields`` filter; when a release rejects the filter and the unfiltered
  retry answers, every ``*password*`` leaf is scrubbed before raw is kept.
* ``Cisco-IOS-XE-isis-oper`` ``isis-oper-data/isis-instance[tag]/
  isis-neighbor[system-id level if-name]``: ``ipv4-address``,
  ``ipv6-address``, ``state`` (``isis-adj-up`` ...), ``holdtime``. The lab
  serves the model empty and its licence has no ``router isis``, so the
  IS-IS fixture is hand-built from the model.

Every ``fields`` filter gets one unfiltered retry on HTTP 400, noted in raw.
Nothing here runs a ``show`` command: each protocol has a model. Nothing
here requests, parses or stores a username, a hostname or a key.

Not in this module: ARP (``iosxe_arp`` stays in checks_iosxe; a release that
fills only the deprecated flat ``arp-oper`` list is read there through a
recorded fallback, not a layer-3 rewrite).

Merge-friendliness: the per-check SEMANTICS and the shakedown KEY_MODELS
live here and are merged/exported at import; jobs/__init__.py and
tests/_loader.py discover ``checks_*`` modules by name.
"""

from . import iosxe_common as common
from .registry import SEMANTICS as _REGISTRY_SEMANTICS
from .registry import CheckDef, SkipCheck, register

# --- RESTCONF paths ----------------------------------------------------------

_HSRP_PATH = "/data/Cisco-IOS-XE-hsrp-oper:hsrp-oper-data"
# Every leaf of hsrp-group-info (there are no counters in it) and the
# neighbour list whole; passive-timer-remaining, the one countdown, rides in
# context.
_HSRP_FIELDS = (
    "hsrp-group-info(group-id;if-name;priority;preempt;state;active-ip;standby-ip;"
    "virtual-ip);hsrp-neighbor"
)

_VRRP_PATH = "/data/Cisco-IOS-XE-vrrp-oper:vrrp-oper-data"
# Keys, the role leaves, the transition facts and the track list; the packet
# and error counters of vrrp-group-state are not requested (they only ever
# count up). A release whose revision lacks a named leaf answers HTTP 400 and
# the unfiltered retry takes over, which is noted in raw.
_VRRP_FIELDS = (
    "vrrp-oper-state(if-number;group-id;addr-type;if-name;version;virtual-ip;"
    "virtual-mac;vrrp-state;master-ip;is-owner;priority;preempt;master-transitions;"
    "new-master-reason;state-change-reason;last-state-change-time;"
    "track-list;secondary-vip-addresses;bfd-enabled;bfd-state;omp-state)"
)

_EIGRP_PATH = "/data/Cisco-IOS-XE-eigrp-oper:eigrp-oper-data"
# Instances, their interfaces and the neighbours under them; eigrp-topo (the
# topology table, large on a distribution switch) and auth-val (holds a
# password leaf) are deliberately absent.
_EIGRP_FIELDS = (
    "eigrp-instance(afi;vrf-name;as-num;router-id;named-mode;name;"
    "eigrp-interface(name;passive;hello-interval;hold-timer;eigrp-nbr))"
)

_ISIS_PATH = "/data/Cisco-IOS-XE-isis-oper:isis-oper-data"
_ISIS_FIELDS = (
    "isis-instance(tag;isis-neighbor(system-id;level;if-name;ipv4-address;"
    "ipv6-address;state;holdtime))"
)

# yang-library module names the shakedown reports, so a 9300 shakedown shows
# at once which layer-3 collectors CAN work on the image.
KEY_MODELS = (
    "Cisco-IOS-XE-hsrp-oper",
    "Cisco-IOS-XE-vrrp-oper",
    "Cisco-IOS-XE-eigrp-oper",
    "Cisco-IOS-XE-isis-oper",
)

# Any leaf whose name carries this token is replaced before raw is stored
# (checks_iosxe's config scrub uses the same marker).
_SECRET_TOKEN = "password"
_SECRET_MARK = "***scrubbed***"

# Unresolved-address spellings a role leaf may carry (a group with no standby
# router, a master not yet learned): the honest value is None.
_UNRESOLVED_ADDRESSES = frozenset(("0.0.0.0", "::"))


# --- shared helpers (jobs/iosxe_common; historical names kept for callers) ---

_aslist = common.aslist
_entries = common.entries
_sub = common.sub
_to_int = common.to_int
_yes = common.yes
_short = common.short
_mac = common.mac
_compact = common.compact
_text_or_none = common.text_or_none
_dotted = common.dotted


def _address(value):
    """An address leaf as text; None when absent, blank or an unresolved 0.0.0.0 / ::."""
    text = _text_or_none(value)
    if text is None or text in _UNRESOLVED_ADDRESSES:
        return None
    return text


def _present(node_, name):
    """A YANG ``empty`` leaf: present (RESTCONF sends ``[null]``) means true."""
    return name in node_ if isinstance(node_, dict) else False


def _flags(node_, names):
    """Presence flags of container ``node_`` as booleans; every one None when it is absent."""
    if not isinstance(node_, dict):
        return {alias: None for _, alias in names}
    return {alias: _present(node_, leaf) for leaf, alias in names}


def _af(addr_type):
    """'ipv4-address' -> 'ipv4' (the addr-type enum as the lab spelled it); None when absent."""
    text = _text_or_none(addr_type)
    if text is not None and text.endswith("-address"):
        return text[: -len("-address")]
    return text


def _version(node_, major, minor):
    """'major.minor' from two integer leaves; None unless both are present."""
    high, low = _to_int(_sub(node_).get(major)), _to_int(_sub(node_).get(minor))
    if high is None or low is None:
        return None
    return "%d.%d" % (high, low)


def _scrub_secrets(node_):
    """Copy of a payload with every leaf named like a password replaced by the marker."""
    if isinstance(node_, dict):
        scrubbed = {}
        for key, value in node_.items():
            if _SECRET_TOKEN in str(key).lower():
                scrubbed[key] = _SECRET_MARK
            else:
                scrubbed[key] = _scrub_secrets(value)
        return scrubbed
    if isinstance(node_, list):
        return [_scrub_secrets(item) for item in node_]
    return node_


def _get_filtered(ctx, path, fields, notes, label):
    """A ``fields`` read that answers None for an absent model (404), retried once on 400.

    Returns (payload, path_used); the path is the one raw is keyed by, and a
    rejected filter is noted so the raw bundle explains its size.
    """
    read = common.get_filtered(ctx, path, fields, label=label, ok_404=True, notes=notes)
    return read.payload, read.path


def _model_status(payload, count, noun):
    """'not served (404)' / 'served, no <noun>' / '<n> <noun>' for context and skip messages."""
    if payload is None:
        return "not served (404)"
    if not count:
        return "served, no %s" % (noun,)
    return "%d %s" % (count, noun if count != 1 else noun.rstrip("s"))


# --- iosxe_fhrp --------------------------------------------------------------

_HSRP_STATE = "hsrp-state-"
_VRRP_STATE = "proto-state-"
_VRRP_MASTER_REASON = "reason-"
_VRRP_CHANGE_REASON = "cr-"
_VRRP_TRACK_STATE = "vrrp-track-state-"


def _hsrp_groups(payload):
    """'hsrp|<interface>|<group>' -> role facts, from hsrp-group-info."""
    normalized = {}
    for group in _entries(payload, "hsrp-group-info"):
        if_name = _text_or_none(group.get("if-name"))
        group_id = _to_int(group.get("group-id"))
        if if_name is None or group_id is None:
            continue
        normalized["hsrp|%s|%s" % (if_name, group_id)] = {
            "state": _short(group.get("state"), _HSRP_STATE),
            "vip": _address(group.get("virtual-ip")),
            "priority": _to_int(group.get("priority")),
            "preempt": _yes(group.get("preempt")),
            "active_ip": _address(group.get("active-ip")),
            "standby_ip": _address(group.get("standby-ip")),
        }
    return normalized


def _hsrp_neighbors(payload):
    """interface -> the HSRP routers heard on it (hsrp-neighbor), for context."""
    neighbors = {}
    for entry in _entries(payload, "hsrp-neighbor"):
        if_name = _text_or_none(entry.get("if-name"))
        if if_name is None:
            continue
        rows = []
        for neighbor in _aslist(entry.get("neighbor")):
            if not isinstance(neighbor, dict):
                continue
            rows.append(
                _compact(
                    {
                        "address": _address(neighbor.get("address")),
                        "active_groups": sorted(
                            group
                            for group in map(_to_int, _aslist(neighbor.get("active-list")))
                            if group is not None
                        ),
                        "standby_groups": sorted(
                            group
                            for group in map(_to_int, _aslist(neighbor.get("standby-list")))
                            if group is not None
                        ),
                        "passive": _yes(neighbor.get("passive")),
                        "passive_timer_remaining": _to_int(neighbor.get("passive-timer-remaining")),
                        "bfd_enabled": _yes(neighbor.get("bfd-enabled")),
                    }
                )
            )
        neighbors[if_name] = sorted(rows, key=lambda row: str(row.get("address")))
    return neighbors


def _vrrp_tracks(group):
    """track name -> resolved/unresolved, from the group's track-list."""
    tracks = {}
    for track in _aslist(group.get("track-list")):
        if not isinstance(track, dict):
            continue
        name = _text_or_none(track.get("track-name"))
        if name is not None:
            tracks[name] = _short(track.get("track-obj-state"), _VRRP_TRACK_STATE)
    return tracks


def _vrrp_groups(payload):
    """('vrrp|<interface>|<group>|<af>' -> role facts, key -> transition context)."""
    normalized = {}
    context = {}
    for group in _entries(payload, "vrrp-oper-state"):
        if_name = _text_or_none(group.get("if-name"))
        group_id = _to_int(group.get("group-id"))
        if if_name is None or group_id is None:
            continue
        key = "vrrp|%s|%s|%s" % (if_name, group_id, _af(group.get("addr-type")) or "unknown")
        normalized[key] = {
            "state": _short(group.get("vrrp-state"), _VRRP_STATE),
            "vip": _address(group.get("virtual-ip")),
            "priority": _to_int(group.get("priority")),
            "preempt": _yes(group.get("preempt")),
            "owner": _yes(group.get("is-owner")),
            "master_ip": _address(group.get("master-ip")),
        }
        context[key] = _compact(
            {
                "master_transitions": _to_int(group.get("master-transitions")),
                "new_master_reason": _short(group.get("new-master-reason"), _VRRP_MASTER_REASON),
                "state_change_reason": _short(
                    group.get("state-change-reason"), _VRRP_CHANGE_REASON
                ),
                "last_state_change": _text_or_none(group.get("last-state-change-time")),
                "tracks": _vrrp_tracks(group),
                "version": _text_or_none(group.get("version")),
                "virtual_mac": _mac(group.get("virtual-mac")),
                "secondary_vips": sorted(
                    address
                    for address in map(_address, _aslist(group.get("secondary-vip-addresses")))
                    if address is not None
                ),
                "bfd_enabled": _yes(group.get("bfd-enabled")),
                "bfd_state": _text_or_none(group.get("bfd-state")),
                "omp_state": _text_or_none(group.get("omp-state")),
            }
        )
    return normalized, context


def _normalize_fhrp(hsrp_payload, vrrp_payload):
    """(normalized, context) of the two FHRP reads; either payload may be None (404).

    Keys are 'hsrp|<interface>|<group>' and 'vrrp|<interface>|<group>|<af>'
    with the role facts only. Transition counters, reasons and times, track
    states and the HSRP neighbour lists go to context; the packet counters
    stay in raw.
    """
    hsrp = _hsrp_groups(hsrp_payload)
    vrrp, transitions = _vrrp_groups(vrrp_payload)
    normalized = dict(hsrp)
    normalized.update(vrrp)
    context = {
        "models": {
            "hsrp-oper": _model_status(hsrp_payload, len(hsrp), "groups"),
            "vrrp-oper": _model_status(vrrp_payload, len(vrrp), "groups"),
        },
        "hsrp_groups": len(hsrp),
        "vrrp_groups": len(vrrp),
        "vrrp": transitions,
        "hsrp_neighbors": _hsrp_neighbors(hsrp_payload),
    }
    return normalized, context


def _collect_fhrp(ctx):
    notes = []
    hsrp, hsrp_path = _get_filtered(ctx, _HSRP_PATH, _HSRP_FIELDS, notes, "hsrp-oper")
    vrrp, vrrp_path = _get_filtered(ctx, _VRRP_PATH, _VRRP_FIELDS, notes, "vrrp-oper")
    normalized, context = _normalize_fhrp(hsrp, vrrp)
    if not normalized:
        raise SkipCheck(
            "no HSRP or VRRP groups (hsrp-oper %s; vrrp-oper %s)"
            % (context["models"]["hsrp-oper"], context["models"]["vrrp-oper"])
        )
    raw = {hsrp_path: hsrp, vrrp_path: vrrp}
    if notes:
        raw["note"] = "; ".join(notes)
    return {"raw": raw, "normalized": normalized, "context": context}


# --- iosxe_eigrp_neighbors ---------------------------------------------------

_EIGRP_AFI = "eigrp-af-"
_EIGRP_STUB_FLAGS = (
    ("stubbed", "stub"),
    ("receive-only", "receive_only"),
    ("static-nbr", "static"),
)
_EIGRP_NBR_COUNTERS = (
    ("srtt", "srtt"),
    ("rto", "rto"),
    ("retransmit-count", "retransmit_count"),
    ("retry-count", "retry_count"),
    ("last-seq-number", "last_seq_number"),
)


def _normalize_eigrp_neighbors(payload):
    """(normalized, context) of an eigrp-oper read.

    Keys are '<afi>|<as>|<vrf>|<interface>|<neighbor>' (afi ipv4/ipv6, vrf
    'default' for the global table); a key's presence IS the adjacency — the
    model defines no state leaf for an EIGRP neighbour. Values are the
    peer's stub flags and versions, which only change when the far end is
    reconfigured or upgraded. Context carries the instances (router-id,
    name, interfaces with timers and passive flag, neighbour count) and each
    neighbour's SRTT/RTO/retransmit/retry/sequence readings.
    """
    normalized = {}
    instances = {}
    readings = {}
    for inst in _entries(payload, "eigrp-instance"):
        afi = _short(inst.get("afi"), _EIGRP_AFI) or "unknown"
        as_num = _to_int(inst.get("as-num"))
        vrf = _text_or_none(inst.get("vrf-name")) or "default"
        instance_key = "%s|%s|%s" % (afi, as_num, vrf)
        interfaces = {}
        count = 0
        for iface in _aslist(inst.get("eigrp-interface")):
            if not isinstance(iface, dict):
                continue
            if_name = _text_or_none(iface.get("name"))
            if if_name is None:
                continue
            interfaces[if_name] = _compact(
                {
                    "passive": _present(iface, "passive"),
                    "hello_interval": _to_int(iface.get("hello-interval")),
                    "hold_timer": _to_int(iface.get("hold-timer")),
                }
            )
            for neighbor in _aslist(iface.get("eigrp-nbr")):
                if not isinstance(neighbor, dict):
                    continue
                address = _address(neighbor.get("nbr-address"))
                if address is None:
                    continue
                key = "%s|%s" % (instance_key, "%s|%s" % (if_name, address))
                facts = _flags(neighbor.get("nbr-stubinfo"), _EIGRP_STUB_FLAGS)
                facts["sw_version"] = _version(
                    neighbor.get("nbr-sw-ver"), "os-majorver", "os-minorver"
                )
                facts["tlv_version"] = _version(
                    neighbor.get("nbr-sw-ver"), "tlv-majorrev", "tlv-minorrev"
                )
                normalized[key] = facts
                readings[key] = _compact(
                    {alias: _to_int(neighbor.get(leaf)) for leaf, alias in _EIGRP_NBR_COUNTERS}
                )
                count += 1
        instances[instance_key] = _compact(
            {
                "router_id": _dotted(inst.get("router-id")),
                "name": _text_or_none(inst.get("name")),
                "named_mode": _present(inst, "named-mode"),
                "interfaces": interfaces,
                "neighbors": count,
            }
        )
    context = {"instances": instances, "neighbors": readings}
    return normalized, context


def _collect_eigrp_neighbors(ctx):
    notes = []
    payload, path = _get_filtered(ctx, _EIGRP_PATH, _EIGRP_FIELDS, notes, "eigrp-oper")
    if payload is None:
        raise SkipCheck("EIGRP not running (eigrp-oper model not served)")
    normalized, context = _normalize_eigrp_neighbors(payload)
    if not context["instances"]:
        raise SkipCheck("EIGRP not running (no EIGRP instance)")
    raw = {path: _scrub_secrets(payload)}
    if notes:
        raw["note"] = "; ".join(notes)
    return {"raw": raw, "normalized": normalized, "context": context}


# --- iosxe_isis_neighbors ----------------------------------------------------

_ISIS_LEVEL = "isis-"
_ISIS_STATE = "isis-adj-"


def _normalize_isis_neighbors(payload):
    """(normalized, context) of an isis-oper read.

    Keys are '<tag>|<level>|<interface>|<system-id>' -> adjacency state (up
    is healthy) and the neighbour's IPv4/IPv6 addresses. Context carries the
    instances (neighbour count per tag) and each neighbour's hold timer.
    """
    normalized = {}
    instances = {}
    holdtimes = {}
    for inst in _entries(payload, "isis-instance"):
        tag = _text_or_none(inst.get("tag")) or "default"
        count = 0
        for neighbor in _aslist(inst.get("isis-neighbor")):
            if not isinstance(neighbor, dict):
                continue
            system_id = _mac(neighbor.get("system-id"))
            if_name = _text_or_none(neighbor.get("if-name"))
            if system_id is None or if_name is None:
                continue
            key = "%s|%s|%s|%s" % (
                tag,
                _short(neighbor.get("level"), _ISIS_LEVEL) or "unknown",
                if_name,
                system_id,
            )
            normalized[key] = {
                "state": _short(neighbor.get("state"), _ISIS_STATE),
                "ipv4_address": _address(neighbor.get("ipv4-address")),
                "ipv6_address": _address(neighbor.get("ipv6-address")),
            }
            holdtime = _to_int(neighbor.get("holdtime"))
            if holdtime is not None:
                holdtimes[key] = holdtime
            count += 1
        instances[tag] = {"neighbors": count}
    return normalized, {"instances": instances, "holdtime": holdtimes}


def _collect_isis_neighbors(ctx):
    notes = []
    payload, path = _get_filtered(ctx, _ISIS_PATH, _ISIS_FIELDS, notes, "isis-oper")
    if payload is None:
        raise SkipCheck("IS-IS not running (isis-oper model not served)")
    normalized, context = _normalize_isis_neighbors(payload)
    if not context["instances"]:
        raise SkipCheck("IS-IS not running (no IS-IS instance)")
    raw = {path: payload}
    if notes:
        raw["note"] = "; ".join(notes)
    return {"raw": raw, "normalized": normalized, "context": context}


# --- semantics (merged into registry.SEMANTICS at import) --------------------

SEMANTICS = {
    "iosxe_fhrp": (
        "First-hop redundancy roles. 'hsrp|<interface>|<group>' -> state (active/standby/"
        "listen/speak/learn/init/disabled, the model's hsrp-state-* without the prefix), "
        "vip, priority, preempt (bool), active_ip and standby_ip; "
        "'vrrp|<interface>|<group>|<af>' (af ipv4/ipv6 from the addr-type key) -> state "
        "(master/backup/init/recover), vip, priority, preempt, owner (this router holds the "
        "virtual address) and master_ip. On the lab switch master_ip read the local SVI "
        "address while it was master; an address the device reports as 0.0.0.0 or :: (no "
        "standby router known, master not yet learned) is None, so a missing peer is a "
        "None, never a spelling. A state that flipped between captures is a gateway move; "
        "two routers both reading active/master for one group is a split brain; a key "
        "that vanished is a group no longer configured or an interface that went down. "
        "Context 'vrrp' per key carries master_transitions (read as a delta: a count that "
        "advanced with no planned change is a flap that healed), new_master_reason "
        "(priority/preempt/master-no-response), state_change_reason where the release "
        "fills it, last_state_change, tracks (track object -> resolved/unresolved), the "
        "protocol version, virtual MAC, secondary VIPs and the BFD/OMP flags; "
        "'hsrp_neighbors' lists the HSRP routers heard per interface with the groups they "
        "are active or standby for. Packet and error counters stay in raw. Context 'models' "
        "says whether each model was served: a release that does not advertise hsrp-oper "
        "answers 404, and both are absent on an image without the feature. Not-present when "
        "neither model lists a group — the norm on an access stack."
    ),
    "iosxe_eigrp_neighbors": (
        "EIGRP adjacencies keyed '<afi>|<as>|<vrf>|<interface>|<neighbor-ip>' (afi ipv4/"
        "ipv6; vrf 'default' for the global table). The model defines no state leaf for a "
        "neighbour, so a key's presence IS the established adjacency and a key that "
        "vanished is a lost peer; values are facts about the far end that change only when "
        "it is reconfigured or upgraded: stub, receive_only and static (bools, None when "
        "the release omits the stub container), sw_version and tlv_version "
        "('major.minor'). Context 'instances' (per '<afi>|<as>|<vrf>') carries the "
        "router_id (dotted from the model's integer), the named-mode name, every "
        "EIGRP-enabled interface with its hello/hold timers and passive flag, and the "
        "neighbour count; context 'neighbors' carries each peer's srtt, rto, retransmit "
        "and retry counts and last sequence number (volatile; a retransmit count that "
        "keeps climbing is a lossy link). Uptime is not modelled. The topology table "
        "(eigrp-topo) is not requested — it is the RIB's job — and the interface "
        "authentication container is neither requested nor kept: on an unfiltered "
        "retry every password-named leaf is scrubbed from raw. Not-present when the "
        "model is not served or lists no EIGRP instance; an instance with no neighbour "
        "is an empty, successful view (the instance still shows in context)."
    ),
    "iosxe_isis_neighbors": (
        "IS-IS adjacencies keyed '<tag>|<level>|<interface>|<system-id>' (level-1 / "
        "level-2; the system-id as the model spells it, lower-cased) -> state (up is "
        "healthy; down/init/standby are not), ipv4_address and ipv6_address of the "
        "neighbour. A key that vanished is a lost adjacency; a state other than up on an "
        "unchanged key is a peer stuck forming. Context 'instances' counts neighbours per "
        "tag and 'holdtime' carries each neighbour's hold timer (a countdown, so volatile). "
        "Not-present when the model is not served (not every release advertises isis-oper, "
        "and IS-IS is not in every licence) or lists no instance; an instance with no "
        "neighbour is an empty, successful view."
    ),
}
_REGISTRY_SEMANTICS.update(SEMANTICS)


# --- registrations -----------------------------------------------------------

register(
    CheckDef(
        id="iosxe_fhrp",
        platform="iosxe",
        description=(
            "HSRP and VRRP gateway roles per interface/group: state, virtual IP, priority, "
            "preempt, active/standby (HSRP) or owner/master (VRRP); transitions, reasons and "
            "track states in context"
        ),
        tier=1,
        compare={"mode": "equality_set"},
        miss_meaning=(
            "A gateway group changed role (active/master moved, a standby vanished, both "
            "routers claim active) or a group disappeared — hosts behind that VIP lose or "
            "re-route their default gateway while every SVI still reads up."
        ),
        collector=_collect_fhrp,
        tags=("routing", "fhrp", "layer3"),
    )
)

register(
    CheckDef(
        id="iosxe_eigrp_neighbors",
        platform="iosxe",
        description=(
            "EIGRP adjacencies per AFI/AS/VRF/interface: neighbor stub flags and software "
            "version (a listed neighbor is an established adjacency); SRTT/RTO/retransmit "
            "readings in context"
        ),
        tier=1,
        compare={"mode": "equality_set"},
        miss_meaning=(
            "An EIGRP adjacency is missing or a peer's stub/version facts changed — a "
            "neighbor went away or was replaced, and every prefix it advertised is gone "
            "from the RIB with it."
        ),
        collector=_collect_eigrp_neighbors,
        tags=("routing", "eigrp", "layer3"),
    )
)

register(
    CheckDef(
        id="iosxe_isis_neighbors",
        platform="iosxe",
        description=(
            "IS-IS adjacencies per tag/level/interface: neighbor state and addresses; hold "
            "timers in context"
        ),
        tier=1,
        compare={"mode": "equality_set"},
        miss_meaning=(
            "An IS-IS adjacency is missing or not up — a neighbor stopped forming or "
            "dropped, and its prefixes leave the RIB with it."
        ),
        collector=_collect_isis_neighbors,
        tags=("routing", "isis", "layer3"),
    )
)
