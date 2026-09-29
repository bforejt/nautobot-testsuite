"""Helpers every IOS-XE checks module shares: payload access, paths, the one
filtered-GET-with-retry, interface-name and MAC normalisation, ``show
inventory`` parsing.

Module layout going forward
---------------------------

New IOS-XE checks live in *layer modules*, each self-contained — its own
``SEMANTICS`` dict (merged into ``registry.SEMANTICS`` at import) and its own
``KEY_MODELS`` tuple (the yang-library names the shakedown reports) — and
discovered by file name (``jobs/__init__.py`` and ``tests/_loader.py`` import
every ``jobs/checks_*.py``; ``tests/test_catalog_discovery.py`` requires each
one to register at least one check):

* ``checks_iosxe_layer2.py``   — VLANs, trunks, spanning tree, MAC learning,
  802.1X sessions
* ``checks_iosxe_layer3.py``   — FHRP, EIGRP and IS-IS adjacencies (ARP, OSPF,
  BGP, RIB/FIB and the CDP/LLDP neighbors remain in ``checks_iosxe`` until
  migrated)
* ``checks_iosxe_platform.py`` — persistence, licensing, PKI, TCAM (the stack,
  inventory, crash files and platform health remain in ``checks_iosxe``)
* ``checks_iosxe_poe.py``      — inline power and StackPower
* ``checks_iosxe_wireless.py`` — the 9800 controller catalog (gated by
  ``_controller``; registers under ``iosxe`` like the rest)

``checks_iosxe.py`` is the legacy core: its checks migrate into layer modules
incrementally, one check at a time, and nothing new is added there. This
module is NOT a catalog (no ``checks_`` prefix, registers nothing): it holds
what two or more of the above must spell identically, so the per-run
``CollectorContext`` cache issues one GET for every shared read and no module
re-derives a helper the next one already has.

Contract for what lives here: pure functions and constants only — stdlib,
``constants`` and ``registry`` (for ``CollectError``); nothing here touches a
device except through the ``ctx`` a caller passes in, and nothing here
registers a check or carries SEMANTICS. Every checks module imports what it
uses under its historical private name (``from .iosxe_common import aslist as
_aslist``), so ``tests/``, ``shakedown_job`` and any older caller keep their
``module._name`` handles.

Shared reads and the cache
--------------------------

``CollectorContext.get`` caches by ``(path, kwargs)``: two checks share one
GET only when they spell the path AND the keyword arguments identically. The
constants below are the paths more than one module reads; ``get_filtered``
passes a keyword only when the caller asked for it (``timeout=None`` and
``ok_404=False`` add nothing to the call), so wrapping a read in it never
changes its cache key.
"""

import datetime
import re
from collections import namedtuple

from . import constants as C
from .registry import CollectError

# --- RESTCONF paths read by more than one module -----------------------------

# Device hardware: platform-health, the stack check, the inventory check, the
# unsaved-config leaf and the wireless controller gate all read this container
# whole — one GET per capture.
HW_PATH = "/data/Cisco-IOS-XE-device-hardware-oper:device-hardware-data"
# Stack roster: the switch-stack check and the wireless platform check
# (both ``ok_404=True``).
STACK_OPER_PATH = "/data/Cisco-IOS-XE-stack-oper:stack-oper-data"
# The VLAN database (vlan-oper vlans/vlan[id]): iosxe_vlans reads it as the
# check's subject and iosxe_interfaces reads it, best-effort, to tell access
# ports from trunks and routed ports (both ``ok_404=True``).
VLAN_PATH = "/data/Cisco-IOS-XE-vlan-oper:vlans"
# One GET serves iosxe_interfaces and iosxe_errdisable (identical path and
# kwargs, so the per-run cache issues it once). Every leaf is defined by the
# interface-state grouping of Cisco-IOS-XE-interfaces-oper (17.12.1): the
# effective config (vrf, mask, ipv6-addrs, mtu, the security ACLs, the
# diffserv policy names), the negotiated Ethernet state (ether-state is the
# interface-class-ethernet case; the model's own `speed` leaf is a bandwidth
# estimate and is not requested), the extended state (valid only beside the
# intf-ext-state-support presence leaf: err-disable type and reason, mGig
# downshift), the storm-control filter states and the statistics counters.
# diffserv-info is cut to its keys: its classifier statistics are volatile
# and large. Unfiltered on HTTP 400 (see fetch_interfaces).
IFACE_BASE_PATH = "/data/Cisco-IOS-XE-interfaces-oper:interfaces"
IFACE_FIELDS = (
    "interface(name;description;admin-status;oper-status;vrf;ipv4;ipv4-subnet-mask;"
    "ipv6-addrs;mtu;input-security-acl;output-security-acl;"
    "diffserv-info(direction;policy-name);storm-control;"
    "intf-ext-state-support;intf-ext-state;statistics;"
    "ether-state(negotiated-port-speed;negotiated-duplex-mode;auto-negotiate))"
)
IFACE_PATH = "%s?fields=%s" % (IFACE_BASE_PATH, IFACE_FIELDS)
IFACE_CONTAINER = "Cisco-IOS-XE-interfaces-oper:interfaces"

# --- RESTCONF payload access ---------------------------------------------------


def aslist(node):
    """RESTCONF quirk: a single list entry may arrive as a bare dict, absent as None."""
    if node is None:
        return []
    if isinstance(node, list):
        return node
    return [node]


def container(payload, qualified_name):
    """Top-level container by its module-qualified name (bare-name fallback).

    ``container(p, "Cisco-IOS-XE-vlan-oper:vlans")`` finds that key, else
    ``"vlans"``; None when neither is present or the payload is not a dict.
    Strict form for a read whose wrapper is known (a container GET).
    """
    if not isinstance(payload, dict):
        return None
    if qualified_name in payload:
        return payload[qualified_name]
    return payload.get(qualified_name.split(":", 1)[-1])


def node(payload, name):
    """Value of the module-qualified top-level node ``name``, any module prefix.

    List reads answer ``{"mod:list": [...]}``; a container read (or a fixture
    harvested from one) answers ``{"mod:container": {"list": [...]}}`` — the
    second form is searched one level down so both shapes normalize alike.
    Lenient form for a list read that may have been wrapped either way.
    """
    if not isinstance(payload, dict):
        return None
    for key, value in payload.items():
        if key.split(":")[-1] == name:
            return value
    for value in payload.values():
        if isinstance(value, dict):
            for key, inner in value.items():
                if key.split(":")[-1] == name:
                    return inner
    return None


def entries(payload, name):
    """The dict entries of list ``name`` (see ``node``); [] when absent."""
    return [entry for entry in aslist(node(payload, name)) if isinstance(entry, dict)]


def sub(node_, *names):
    """Nested container lookup; {} when any level is missing or not a dict."""
    for name in names:
        node_ = node_.get(name) if isinstance(node_, dict) else None
    return node_ if isinstance(node_, dict) else {}


def leaf(node_, *names):
    """Nested leaf lookup; None when any level is missing."""
    return sub(node_, *names[:-1]).get(names[-1])


# --- scalar coercion -------------------------------------------------------------


def to_int(value):
    """int() that tolerates None and non-numeric junk; RESTCONF may string-ify numbers."""
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def to_float(value):
    """decimal64 leaves arrive as strings ('13.20'); None and junk stay None."""
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def yes(value):
    """Boolean leaf: RESTCONF JSON booleans, but tolerate 'true'/'false' strings.

    None stays None (unmeasured); any other value reads True only for
    'true'/'yes'/'1'/'enabled' (case-insensitive).
    """
    if isinstance(value, bool):
        return value
    if value is None:
        return None
    return str(value).strip().lower() in ("true", "yes", "1", "enabled")


def short(value, prefix):
    """Strip a YANG enum prefix ('stp-mode-rapid-pvst' -> 'rapid-pvst'); None stays None."""
    if value is None:
        return None
    value = str(value)
    return value[len(prefix) :] if value.startswith(prefix) else value


def strip_module(identityref):
    """'ietf-routing:static' -> 'static'; identityrefs carry their YANG module prefix."""
    if identityref is None:
        return None
    return str(identityref).split(":")[-1]


def dotted(value):
    """A uint32 address as a dotted quad (the EIGRP and OSPF models type router-ids as
    integers); any other value passes through ``text_or_none``."""
    number = to_int(value)
    if number is None or not 0 <= number <= 0xFFFFFFFF:
        return text_or_none(value)
    return "%d.%d.%d.%d" % (
        number >> 24 & 255,
        number >> 16 & 255,
        number >> 8 & 255,
        number & 255,
    )


_ISO_TIME = re.compile(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d+))?(Z|[+-]\d{2}:\d{2})?$")


def parse_iso(value):
    """A yang:date-and-time value -> aware UTC datetime; None when it does not parse.

    Fractional seconds are dropped; a value with no zone designator is read
    as UTC (the models serve '+00:00' or 'Z').
    """
    match = _ISO_TIME.match(str(value or "").strip())
    if match is None:
        return None
    base, _fraction, zone = match.groups()
    zone = "+00:00" if zone in (None, "Z") else zone
    try:
        stamp = datetime.datetime.fromisoformat(base + zone)
    except ValueError:
        return None
    return stamp.astimezone(datetime.timezone.utc)


def text_or_none(value):
    """Stripped text of a leaf; None when absent or blank."""
    text = "" if value is None else str(value).strip()
    return text or None


def compact(facts):
    """Drop unmeasured (None) facets: absent means the device did not publish it."""
    return {key: value for key, value in facts.items() if value is not None}


# --- MAC addresses -------------------------------------------------------------


def mac(value):
    """Lower-cased, stripped MAC text in whatever form the source used; None when empty.

    Shape-preserving on purpose: a matm-oper 'aa:bb:cc:dd:ee:ff' and a
    CLI 'aabb.ccdd.eeff' stay distinguishable in raw. Use ``mac_canonical``
    when a key must join across sources.
    """
    return str(value).strip().lower() if value else None


_MAC_HEX = re.compile(r"[^0-9a-f]")


def mac_canonical(value):
    """Any 48-bit MAC spelling -> 'aa:bb:cc:dd:ee:ff'; None when empty.

    Accepts dotted ('aabb.ccdd.eeff'), colon, dash and bare-hex forms, any
    case. Text that is not exactly twelve hex digits once separators are
    removed is returned as ``mac(value)`` (lower-cased, unchanged), so the
    value never changes type and never lies about what the device sent.
    """
    text = mac(value)
    if text is None:
        return None
    digits = _MAC_HEX.sub("", text)
    if len(digits) != 12:
        return text
    return ":".join(digits[i : i + 2] for i in range(0, 12, 2))


# --- interface names -----------------------------------------------------------

# (long, short) as IOS-XE prints them: the oper models carry the long form
# (interfaces-oper, vlan-oper, matm-oper) and ``show`` tables the short one
# (``show interfaces trunk``, ``show interfaces status``, ``show mac
# address-table``). Every pair below appears in a fixture or a lab capture
# under tests/fixtures; a prefix not listed passes through both helpers
# unchanged (they never invent a spelling). Order: longest short form first,
# so 'Twe' wins over 'Tw' and 'Fo' never eats 'FortyGigabitEthernet'.
IFNAME_PREFIXES = (
    ("TwentyFiveGigE", "Twe"),
    ("AppGigabitEthernet", "Ap"),
    ("Bluetooth", "Bl"),
    ("FiveGigabitEthernet", "Fi"),
    ("FortyGigabitEthernet", "Fo"),
    ("FastEthernet", "Fa"),
    ("GigabitEthernet", "Gi"),
    ("HundredGigE", "Hu"),
    ("Loopback", "Lo"),
    ("Port-channel", "Po"),
    ("TenGigabitEthernet", "Te"),
    ("Tunnel", "Tu"),
    ("TwoGigabitEthernet", "Tw"),
    ("Vlan", "Vl"),
)
_IFNAME_SPLIT = re.compile(r"^([A-Za-z][A-Za-z-]*?)(\d[\d/.]*)$")
_LONG_BY_LOWER = {long_.lower(): long_ for long_, _ in IFNAME_PREFIXES}
_SHORT_BY_LOWER = {short_.lower(): short_ for _, short_ in IFNAME_PREFIXES}
_SHORT_OF = {long_.lower(): short_ for long_, short_ in IFNAME_PREFIXES}
_LONG_OF = {short_.lower(): long_ for long_, short_ in IFNAME_PREFIXES}


def _split_ifname(name):
    """('GigabitEthernet', '1/0/1') for a port-shaped name; None otherwise."""
    match = _IFNAME_SPLIT.match(str(name or "").strip())
    return (match.group(1), match.group(2)) if match else None


def long_ifname(name):
    """'Gi1/0/1' -> 'GigabitEthernet1/0/1'; a long name keeps its canonical case.

    Case-insensitive on input. None, '' and names with no listed prefix
    come back unchanged (None stays None).
    """
    parts = _split_ifname(name)
    if parts is None:
        return name
    prefix, rest = parts
    lowered = prefix.lower()
    if lowered in _LONG_OF:
        return _LONG_OF[lowered] + rest
    if lowered in _LONG_BY_LOWER:
        return _LONG_BY_LOWER[lowered] + rest
    return name


def short_ifname(name):
    """'GigabitEthernet1/0/1' -> 'Gi1/0/1'; a short name keeps its canonical case.

    The inverse of ``long_ifname`` with the same pass-through rules.
    """
    parts = _split_ifname(name)
    if parts is None:
        return name
    prefix, rest = parts
    lowered = prefix.lower()
    if lowered in _SHORT_OF:
        return _SHORT_OF[lowered] + rest
    if lowered in _SHORT_BY_LOWER:
        return _SHORT_BY_LOWER[lowered] + rest
    return name


# Stack member from a physical port name: the first of the three slash-separated
# numbers (GigabitEthernet1/0/1, TwoGigabitEthernet2/0/48, Te3/1/4). A
# Port-channel, an SVI or "CPU" has no member.
MEMBER_PORT = re.compile(r"^[A-Za-z][A-Za-z-]*?(\d+)/\d+/\d+")


def member_of(port):
    """Stack member number (int) of a physical port name, long or short; None for anything else."""
    match = MEMBER_PORT.match(str(port or ""))
    return int(match.group(1)) if match else None


# --- CLI ---------------------------------------------------------------------------

# How IOS refuses a command (a privilege or command-authorization boundary),
# as opposed to answering it.
CLI_REFUSAL = re.compile(
    r"invalid input|incomplete command|ambiguous command|authorization failed"
    r"|not authorized|permission denied|access denied",
    re.IGNORECASE,
)


def cli_rejected(output):
    """True when IOS-XE refused the command form rather than answering it."""
    return bool(CLI_REFUSAL.search(output or ""))


# --- the filtered GET with one unfiltered retry ------------------------------------

# The two values ``FilteredGet.fields_filter`` takes; iosxe_interfaces stores
# this string in context so an analyst sees which shape raw carries.
FILTER_ACCEPTED = "accepted"
FILTER_REJECTED = "rejected (HTTP 400); unfiltered read"


class FilteredGet(namedtuple("FilteredGet", "payload path filtered note")):
    """What ``get_filtered`` returns.

    payload  — the reply (None only for a 404 read with ``ok_404=True``)
    path     — the resource path that actually answered: ``<path>?fields=…``
               when the filter was accepted, the bare path after the retry.
               Key raw by it.
    filtered — True when the ``fields`` filter was accepted
    note     — None, or the sentence for a raw note:
               '<label>: fields filter rejected (HTTP 400); unfiltered read used'
    """

    __slots__ = ()

    @property
    def fields_filter(self):
        """FILTER_ACCEPTED or FILTER_REJECTED, for context."""
        return FILTER_ACCEPTED if self.filtered else FILTER_REJECTED


def get_filtered(
    ctx,
    path,
    fields,
    label=None,
    ok_404=False,
    timeout=None,
    retry_timeout=C.BIG_GET_TIMEOUT,
    notes=None,
):
    """GET ``path?fields=<fields>`` with ONE unfiltered retry on HTTP 400.

    A release that rejects a ``fields`` filter answers HTTP 400; the retry
    reads ``path`` unfiltered (bigger, slower: ``retry_timeout``, the
    platform's BIG_GET_TIMEOUT unless told otherwise; None sends no timeout
    keyword at all) and the fallback is recorded in the result's ``note`` so
    the raw bundle explains its size. Any other error, and a 400 on the retry
    itself, propagate. ``fields`` None or '' means a plain GET of ``path``
    with no retry.

    Keyword arguments reach ``ctx.get`` only when asked for: ``ok_404`` is
    passed only when True and ``timeout`` only when not None, so a read moved
    behind this helper keeps the cache key it always had and still shares its
    GET with every other check that spells it the same way.

    ``label`` names the read in the note (default: the last path segment).
    ``notes`` (a list) receives the note too, for callers that collect one.
    """
    kwargs = {}
    if ok_404:
        kwargs["ok_404"] = True
    if timeout is not None:
        kwargs["timeout"] = timeout
    if not fields:
        return FilteredGet(ctx.get(path, **kwargs), path, True, None)
    filtered = "%s?fields=%s" % (path, fields)
    try:
        return FilteredGet(ctx.get(filtered, **kwargs), filtered, True, None)
    except Exception as exc:
        if getattr(exc, "status_code", None) != 400:
            raise
    note = "%s: fields filter rejected (HTTP 400); unfiltered read used" % (
        label or path.rstrip("/").rsplit("/", 1)[-1],
    )
    if notes is not None:
        notes.append(note)
    if retry_timeout is not None:
        kwargs["timeout"] = retry_timeout
    else:
        kwargs.pop("timeout", None)
    return FilteredGet(ctx.get(path, **kwargs), path, False, note)


def fetch_interfaces(ctx):
    """The widened interfaces GET (IFACE_PATH), retried once unfiltered on HTTP 400.

    Shared by iosxe_interfaces and iosxe_errdisable; the second caller is a
    cache hit. CollectError when the reply lacks the interfaces container.
    Returns a FilteredGet (payload, path, filtered, note).
    """
    # The unfiltered reply carries every leaf of every interface (the
    # diffserv classifier statistics included), so it gets the budget every
    # other unfiltered retry on the platform gets.
    read = get_filtered(ctx, IFACE_BASE_PATH, IFACE_FIELDS, label="interfaces")
    if container(read.payload, IFACE_CONTAINER) is None:
        raise CollectError("interfaces container missing from RESTCONF reply")
    return read


# --- device hardware and `show inventory` -------------------------------------------

HW_CONTAINER = "Cisco-IOS-XE-device-hardware-oper:device-hardware-data"

# --- the VLAN database's two port lists ----------------------------------------

VLAN_CONTAINER = "Cisco-IOS-XE-vlan-oper:vlans"
# The vlan-oper vlan list carries two interface lists (17.15.1 model): ``ports``
# ("Assigned ports") and ``vlan-interfaces`` ("List of interfaces for a given
# VLAN"). Which one a release fills is a field fact: the lab 9300 fills
# ``vlan-interfaces`` only, on every release captured (every physical
# switchport once, under its access VLAN or, for a trunk, under VLAN 1 — a
# trunk with native VLAN 999 sits under 1, not 999; ``ports`` empty on every
# VLAN). iosxe_vlans and iosxe_interfaces both read
# the lists through here so the two checks cannot disagree on the port set.
VLAN_PORT_LISTS = ("ports", "vlan-interfaces")


def vlan_port_lists(payload):
    """{list name: {interface: set of VLAN ids}} for the two vlan-oper port lists.

    Both names are always present (empty when the release fills nothing);
    a member without an interface name is skipped, as is a VLAN without an
    integer id.
    """
    lists = {name: {} for name in VLAN_PORT_LISTS}
    for vlan in entries(payload, "vlan"):
        vlan_id = to_int(vlan.get("id"))
        if vlan_id is None:
            continue
        for list_name in VLAN_PORT_LISTS:
            for member in aslist(vlan.get(list_name)):
                if not isinstance(member, dict) or not member.get("interface"):
                    continue
                lists[list_name].setdefault(str(member["interface"]), set()).add(vlan_id)
    return lists


def switchports(payload):
    """(names, source): the switchports the VLAN database lists and which list said so.

    ``ports`` is the model's "assigned ports" list and wins where a release
    fills it; otherwise ``vlan-interfaces``; (set(), None) when the container
    was served but neither list holds a member. The caller decides what a
    None payload (model not served) means.
    """
    lists = vlan_port_lists(payload)
    for name in VLAN_PORT_LISTS:
        if lists[name]:
            return set(lists[name]), name
    return set(), None


def device_inventory(hardware_payload):
    """The device-inventory list entries (dicts only) of a device-hardware-data payload."""
    hardware = sub(container(hardware_payload, HW_CONTAINER) or {}, "device-hardware")
    return [entry for entry in aslist(hardware.get("device-inventory")) if isinstance(entry, dict)]


# `show inventory` prints every item as a NAME/DESCR line followed by its
# PID/VID/SN line; empty fields print as nothing before the next comma.
#   NAME: "Switch 2", DESCR: "C9300-48UXM"
#   PID: C9300-48UXM       , VID: V02  , SN: FOC0000A002
INVENTORY_NAME_LINE = re.compile(r'^NAME:\s*"([^"]*)"', re.IGNORECASE)
INVENTORY_PID_LINE = re.compile(
    r"^PID:\s*(.*?)\s*,\s*VID:\s*(.*?)\s*,\s*SN:\s*(.*?)\s*$", re.IGNORECASE
)
INVENTORY_DESCR = re.compile(r',\s*DESCR:\s*"([^"]*)"', re.IGNORECASE)
# A member's own chassis: "Switch <n>" in a 9300 stack, "Chassis <n>" in an
# SVL pair. Anchored, so the stack-level "c93xx Stack" entry (a repeat of the
# active's PID and SN) and sub-items such as "Switch 1 - Power Supply A" or
# "Chassis 1 Fan Tray" never match.
INVENTORY_MEMBER_NAME = re.compile(r"^(?:Switch|Chassis)\s+(\d+)$", re.IGNORECASE)


def inventory_items(cli_output):
    """The NAME/DESCR + PID/VID/SN pairs of ``show inventory`` in print order.

    Each item is {name, descr, pid, vid, sn} with blank fields as ''. A
    PID line with no NAME line before it is ignored.
    """
    items = []
    name = None
    descr = ""
    for line in (cli_output or "").splitlines():
        stripped = line.strip()
        name_match = INVENTORY_NAME_LINE.match(stripped)
        if name_match:
            name = name_match.group(1).strip()
            descr_match = INVENTORY_DESCR.search(stripped)
            descr = descr_match.group(1).strip() if descr_match else ""
            continue
        pid_match = INVENTORY_PID_LINE.match(stripped)
        if pid_match is None or name is None:
            continue
        items.append(
            {
                "name": name,
                "descr": descr,
                "pid": pid_match.group(1),
                "vid": pid_match.group(2),
                "sn": pid_match.group(3),
            }
        )
        name = None
    return items


def parse_show_inventory(cli_output):
    """'<n>' -> {model, serial} from the member chassis entries of ``show inventory``.

    model is the PID and serial the SN, each only when printed. A switch
    number listed twice with different facts maps to None: ambiguous, so it
    names no member.
    """
    members = {}
    for item in inventory_items(cli_output):
        member = INVENTORY_MEMBER_NAME.match(item["name"])
        if member is None:
            continue
        facts = {}
        if item["pid"]:
            facts["model"] = item["pid"]
        if item["sn"]:
            facts["serial"] = item["sn"]
        number = str(int(member.group(1)))
        members[number] = facts if members.get(number, facts) == facts else None
    return members
