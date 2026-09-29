"""Catalyst PoE and StackPower state (IOS-XE, RESTCONF).

One check, ``iosxe_poe``, read from ``Cisco-IOS-XE-poe-oper`` with a
``fields`` filter: per-port inline-power state, and the StackPower ring the
members share their supplies over. It registers under the ``iosxe`` platform
like the switch catalog and needs no gate: a device that does not serve the
model (404), or serves it with no PoE module, no PoE ports and no power
stack, records not-present.

The model publishes the per-port table twice — ``poe-port-detail`` (the
richer list, its own enum vocabulary) and ``poe-port`` (the older list,
``ilpower-*`` enums). What a C9300-48UXM actually fills, settled by the lab
(plan §9 item 13): ``poe-port-detail`` only, and only for ports that are
POWERED — the lab harvest with one access point drawing power carried
exactly that one row, and an earlier probe with nothing powered carried no
per-port list at all while ``poe-module`` (num-ports 48), ``poe-stack`` and
``poe-switch`` were served. Both lists are still requested and normalized
into ONE vocabulary (on/off/faulty/deny/overdrawn/error-disable) so a release
that fills the other one lands in the same keys; context records which list
was read and whether the family was absent. Power figures never enter
normalized: under StackPower sharing the per-switch budget, allocation and
availability are drawn from the shared pool and move with demand, so they
live in context beside the watts each port drew.

Merge-friendliness follows checks_iosxe_wireless: SEMANTICS and KEY_MODELS
live here and are merged/exported at import; jobs/__init__.py and
tests/_loader.py discover ``checks_*`` modules by name. Every path, leaf and
enum below was checked against the 17.15.1 Cisco-IOS-XE-poe-oper.yang on
disk (the lab advertises revision 2024-07-10), including the model's own
spelling of the topology leaf,
``topolgy``. The per-port ``device-name`` leaf (the powered device's model
string) is deliberately not requested.
"""

from collections import Counter

from . import iosxe_common as common
from .registry import SEMANTICS as _REGISTRY_SEMANTICS
from .registry import CheckDef, SkipCheck, register

# --- RESTCONF path -----------------------------------------------------------

_POE_OPER = "/data/Cisco-IOS-XE-poe-oper:poe-oper-data"

# ``fields``: only the leaves the normalizer and context read. poe-port-detail
# (grouping poe-data-ethernet) and poe-port (grouping poe-ethernet) are both
# requested because a release fills one or the other; the small lists
# (poe-module, poe-stack, poe-switch) come whole.
_PORT_DETAIL_FIELDS = (
    "intf-name;admin-state;oper-state;pd-class;power-used;oper-power;max-power-drawn;"
    "power-admin-max;oper-police;pwr-state;device-detected;poe-intf-enabled;chassis-num;"
    "module-id"
)
_PORT_FIELDS = (
    "intf-name;admin-state;oper-state;pd-class;power-used;oper-power;oper-police;"
    "poe-intf-enabled;module"
)
_POE_FIELDS = "poe-port-detail(%s);poe-port(%s);poe-module;poe-stack;poe-switch" % (
    _PORT_DETAIL_FIELDS,
    _PORT_FIELDS,
)
_POE_PATH = "%s?fields=%s" % (_POE_OPER, _POE_FIELDS)

# yang-library module names the shakedown reports, so a switch shakedown shows
# at once whether this collector CAN work on the image.
KEY_MODELS = ("Cisco-IOS-XE-poe-oper",)

# Raw keeps the payload keyed by the exact path read. The filtered form is
# small; the unfiltered retry carries ~150 leaves per port, so each port list
# is capped in raw (never in normalized) and the cap is noted.
_RAW_PORT_ROWS_MAX = 600

_PORT_LISTS = ("poe-port-detail", "poe-port")


# --- shared helpers (jobs/iosxe_common; historical names kept for callers) ---

_aslist = common.aslist
_to_int = common.to_int
_to_float = common.to_float
_short = common.short
_compact = common.compact


def _poe_container(payload):
    """The poe-oper-data container, whichever wrapper the read (or a fixture) used.

    A container GET answers ``{"Cisco-IOS-XE-poe-oper:poe-oper-data": {...}}``;
    a fixture may carry the bare name or the inner dict itself. {} when none.
    """
    if not isinstance(payload, dict):
        return {}
    for key, value in payload.items():
        if key.split(":")[-1] == "poe-oper-data":
            return value if isinstance(value, dict) else {}
    if any(name in payload for name in _PORT_LISTS + ("poe-module", "poe-stack", "poe-switch")):
        return payload
    return {}


def _rows(container, name):
    return [entry for entry in _aslist(container.get(name)) if isinstance(entry, dict)]


def _word(value, prefix):
    """_short, with the model's 'not available' enum member read as unmeasured."""
    word = _short(value, prefix)
    return None if word == "null" else word


# --- enum vocabularies (both port lists -> one set of words) -----------------

# poe-port oper-state is ilpower-pd-power-state: pd-power-off / pd-power-on /
# pd-power-faulty / pd-power-deny / pd-power-overdrawn. poe-port-detail
# oper-state is poe-pd-power-state: power-deny / faulty / on / off /
# error-disable. Both reduce to one word so the normalized value never
# depends on which list a release fills.
_OPER_ALIASES = {"power-deny": "deny"}


def _oper_state(value):
    word = _short(value, "pd-power-")
    return _OPER_ALIASES.get(word, word)


def _pd_class(value):
    """poe-port ilpower-pd-class (poe-ieee4) and poe-port-detail poe-pd-class (pd-ieee4).

    Both reduce to ieee0..8, ieee-unknown-class, cisco, unknown or mismatch;
    the 'not available' members (poe-null / pd-null) read as unmeasured.
    """
    if value is None:
        return None
    word = str(value)
    for prefix in ("pd-", "poe-"):
        if word.startswith(prefix):
            word = word[len(prefix) :]
            break
    return None if word == "null" else word


def _admin_state(value):
    """ilpower-admin-state: admin-state-off / -auto / -static (-null is unmeasured)."""
    return _word(value, "admin-state-")


def _stack_mode(value):
    """power-stack-mode: stack-mode-rps / -sharing / -sharing-strict / -redundant / ..."""
    return _word(value, "stack-mode-")


def _stack_topology(value):
    """poe-stack-topo: stack-topo-ring / -star / -standalone / -none."""
    return _short(value, "stack-topo-")


def _stack_port_status(value):
    """poe-port-status: stack-port-status-connected / -not-connected / -shut / -unknown."""
    return _short(value, "stack-port-status-")


# --- normalizers (pure) ------------------------------------------------------


def _port_source(container):
    """(list name, entries): poe-port-detail when it carries port states, else poe-port.

    A list that exists but carries no admin or oper state (names only) does
    not win over one that does; when neither carries a state, the first
    non-empty list is used so the ports are still counted.
    """
    candidates = [(name, _rows(container, name)) for name in _PORT_LISTS]
    for name, entries in candidates:
        if any(
            entry.get("oper-state") is not None or entry.get("admin-state") is not None
            for entry in entries
        ):
            return name, entries
    for name, entries in candidates:
        if entries:
            return name, entries
    return None, []


def _normalize_ports(entries):
    """'port|<interface>' -> admin / oper / class, in the shared vocabulary.

    Every PoE-capable port is a key, powered or not: a port whose device went
    dark reads as oper on -> off with its class gone, never as a vanished
    key. Watts are context.
    """
    normalized = {}
    for entry in entries:
        name = entry.get("intf-name") if isinstance(entry, dict) else None
        if not name:
            continue
        normalized["port|%s" % (name,)] = _compact(
            {
                "admin": _admin_state(entry.get("admin-state")),
                "oper": _oper_state(entry.get("oper-state")),
                "class": _pd_class(entry.get("pd-class")),
            }
        )
    return normalized


def _normalize_stacks(entries):
    """'stack|<power-stack-name>' -> mode, topology, switches, supplies, total_watts.

    ``topology`` is read from the model's own leaf spelling, ``topolgy``.
    ``total_watts`` is the installed supply total, which changes only when a
    supply is added, removed or fails; the reserved/allocated/unused split
    moves with demand and is context.
    """
    normalized = {}
    for entry in entries:
        name = entry.get("power-stack-name") if isinstance(entry, dict) else None
        if name is None:
            continue
        normalized["stack|%s" % (name,)] = _compact(
            {
                "mode": _stack_mode(entry.get("mode")),
                "topology": _stack_topology(entry.get("topolgy")),
                "switches": _to_int(entry.get("num-sw")),
                "supplies": _to_int(entry.get("num-ps")),
                "total_watts": _to_int(entry.get("total-power")),
            }
        )
    return normalized


def _normalize_switches(entries):
    """'switch|<n>' -> port_one / port_two: the member's two StackPower cable ports."""
    normalized = {}
    for entry in entries:
        number = _to_int(entry.get("switch-num")) if isinstance(entry, dict) else None
        if number is None:
            continue
        normalized["switch|%s" % (number,)] = _compact(
            {
                "port_one": _stack_port_status(entry.get("port-one-status")),
                "port_two": _stack_port_status(entry.get("port-two-status")),
            }
        )
    return normalized


def _normalize_poe(payload):
    """The full normalized view of one poe-oper-data payload."""
    container = _poe_container(payload)
    _source, ports = _port_source(container)
    normalized = _normalize_ports(ports)
    normalized.update(_normalize_stacks(_rows(container, "poe-stack")))
    normalized.update(_normalize_switches(_rows(container, "poe-switch")))
    return normalized


def _sum_watts(entries, leaf):
    """Sum of a decimal64 leaf across rows, 2 dp; None when no row carried it."""
    readings = [_to_float(entry.get(leaf)) for entry in entries]
    readings = [reading for reading in readings if reading is not None]
    if not readings:
        return None
    return round(sum(readings), 2)


def _poe_context(payload):
    """Volatile readings, never normalized: budgets, allocations, watts, counts.

    ``port_source`` names the list the port keys were read from (a *field
    capture* question the plan leaves open); the per-switch figures are
    StackPower pool allocations that move with demand.
    """
    container = _poe_container(payload)
    source, ports = _port_source(container)
    modules = _rows(container, "poe-module")
    stacks = _rows(container, "poe-stack")
    switches = _rows(container, "poe-switch")
    # poe-module fills num-ports / used-ports / free-ports on the lab release
    # and not on older ones: the PoE-capable port count is None where the
    # release does not say, never 0.
    capacity = [_to_int(entry.get("num-ports")) for entry in modules]
    capacity = [count for count in capacity if count is not None]
    context = {
        "port_source": source,
        # The per-port family lists POWERED ports only on the lab releases:
        # its absence beside a served poe-module is "nothing powered", not
        # "unserved" (a 404 is not-present).
        "port_family_served": source is not None,
        "ports_total": len(ports),
        "poe_ports": sum(capacity) if capacity else None,
        "ports_by_oper": dict(
            sorted(
                Counter(
                    _oper_state(entry.get("oper-state")) or "unknown" for entry in ports
                ).items()
            )
        ),
        "ports_police_overdrawn": sum(
            1 for entry in ports if str(entry.get("oper-police") or "").endswith("overdrawn")
        ),
        "watts_drawn": _sum_watts(ports, "power-used"),
        "watts_remaining": _sum_watts(modules, "remaining-power"),
    }
    for entry in modules:
        number = _to_int(entry.get("module"))
        if number is None:
            continue
        context["module|%s" % (number,)] = _compact(
            {
                "chassis": _to_int(entry.get("chassis-num")),
                "available": _to_float(entry.get("available-power")),
                "used": _to_float(entry.get("used-power")),
                "remaining": _to_float(entry.get("remaining-power")),
                "ports": _to_int(entry.get("num-ports")),
                "used_ports": _to_int(entry.get("used-ports")),
                "free_ports": _to_int(entry.get("free-ports")),
            }
        )
    for entry in stacks:
        name = entry.get("power-stack-name")
        if name is None:
            continue
        context["stack|%s" % (name,)] = _compact(
            {
                "reserved": _to_int(entry.get("rsvd-power")),
                "allocated": _to_int(entry.get("alloc-power")),
                "unused": _to_int(entry.get("unused-power")),
            }
        )
    for entry in switches:
        number = _to_int(entry.get("switch-num"))
        if number is None:
            continue
        context["switch|%s" % (number,)] = _compact(
            {
                "power_stack": entry.get("power-stack-name"),
                "budget": _to_int(entry.get("power-budget")),
                "allocated": _to_int(entry.get("power-allocated")),
                "available": _to_int(entry.get("available-power")),
                "consumed_poe": _to_int(entry.get("consumed-poe-power")),
                "consumed_system": _to_int(entry.get("consumed-system-power")),
                "ps_a": _to_int(entry.get("ps-a")),
                "ps_b": _to_int(entry.get("ps-b")),
                "ps_c": _to_int(entry.get("ps-c")),
            }
        )
    return context


def _capped_raw(payload, notes):
    """The payload for raw, each port list cut to _RAW_PORT_ROWS_MAX rows (noted)."""
    container = _poe_container(payload)
    capped = dict(container)
    trimmed = False
    for name in _PORT_LISTS:
        rows = _aslist(container.get(name))
        if len(rows) > _RAW_PORT_ROWS_MAX:
            capped[name] = rows[:_RAW_PORT_ROWS_MAX]
            trimmed = True
            notes.append(
                "%s: %d of %d rows kept in raw (cap %d); normalized is complete"
                % (name, _RAW_PORT_ROWS_MAX, len(rows), _RAW_PORT_ROWS_MAX)
            )
    if not trimmed:
        return payload
    return {"Cisco-IOS-XE-poe-oper:poe-oper-data": capped}


# --- collector ---------------------------------------------------------------


def _collect_poe(ctx):
    notes = []
    read = common.get_filtered(
        ctx, _POE_OPER, _POE_FIELDS, label="poe-oper-data", ok_404=True, notes=notes
    )
    path, payload = read.path, read.payload
    if payload is None:
        raise SkipCheck("PoE state not served (poe-oper model absent)")
    container = _poe_container(payload)
    _source, ports = _port_source(container)
    modules = _rows(container, "poe-module")
    stacks = _rows(container, "poe-stack")
    switches = _rows(container, "poe-switch")
    if not ports and not modules and not stacks and not switches:
        raise SkipCheck(
            "no PoE module, no PoE ports and no StackPower state reported (non-PoE SKU, or "
            "the model is served empty)"
        )
    if not ports:
        if modules:
            # The lab releases list powered ports only (17.15.6 probe: a
            # 48-port UPOE module served with no per-port list while nothing
            # drew power). Not a fault, not a non-PoE SKU: no port keys.
            notes.append(
                "no per-port PoE rows: the model lists powered ports only and none is "
                "powered now (PoE module served); StackPower keys only"
            )
        else:
            notes.append(
                "no PoE ports and no PoE module reported; StackPower keys only (non-PoE SKU "
                "in a power stack)"
            )
    normalized = _normalize_ports(ports)
    normalized.update(_normalize_stacks(stacks))
    normalized.update(_normalize_switches(switches))
    raw = {path: _capped_raw(payload, notes)}
    if notes:
        raw["note"] = "; ".join(notes)
    return {"raw": raw, "normalized": normalized, "context": _poe_context(payload)}


# --- semantics (merged into registry.SEMANTICS at import) --------------------

SEMANTICS = {
    "iosxe_poe": (
        "Inline power and StackPower, from Cisco-IOS-XE-poe-oper. Keys 'port|<interface>' "
        "-> admin (auto/static/off), oper in one vocabulary whichever port list the "
        "release fills (on is healthy; off is a device that went dark; faulty, deny, "
        "overdrawn and error-disable are faults — deny means the budget could not grant "
        "the request), and class: ieee0..ieee8, cisco, ieee-unknown-class, mismatch or "
        "unknown, the model's own words with their list prefix removed; absent when the "
        "model reports the class as not available (pd-null / poe-null). WHICH ports are "
        "keys is what the device decides, and the 17.15.1 model describes both poe-port "
        "and poe-port-detail only as 'List of PoE interfaces' (no powered-only "
        "qualifier). On the lab 9300 (every capture), where context "
        "port_source reads poe-port-detail and port_family_served is True, the list held "
        "powered ports only — one row for the one access point drawing power, and no "
        "per-port list at all while nothing drew power, although poe-module still "
        "reported its 48 ports. On such a release the key set is the set of powered "
        "ports: an AP, phone or camera that lost power is a REMOVED key (with its link "
        "possibly still reading up elsewhere) and a device plugged in is an added one. "
        "Read class beside oper: unknown beside off is an empty port on a release or SKU "
        "that lists every PoE-capable port (there a device that lost power is a changed "
        "oper value, not a removed key), while a port keyed with oper off/faulty/deny "
        "and a class is a device the switch detected and would not or could not power. "
        "Context port_source names the list read (None when neither is served), "
        "port_family_served says whether a per-port list existed at all, ports_total "
        "counts its rows and poe_ports the module's PoE-capable port count where the "
        "release fills num-ports (None where it does not) — ports_total equal to "
        "poe_ports means the release listed every port. Not-present only when the "
        "model is not served (404) or answers with no module, no ports and no power stack "
        "(a non-PoE SKU); a PoE switch with nothing powered keeps its stack and switch "
        "keys with no port keys and a raw note saying so, as does a non-PoE member inside "
        "a power stack (no poe-module: the note says which). Keys 'stack|<power-stack>' "
        "are the power twin of the StackWise ring: the members' supplies pooled over "
        "StackPower cables — mode (sharing, redundant, rps, with -strict variants), "
        "topology (ring is healthy where two or more members are cabled; star is a cable "
        "missing or not reseated; standalone is what a single member reports, the lab's "
        "Powerstack-1; none is no StackPower), switches and supplies (a supply that failed "
        "or was pulled lowers the count) and total_watts (the installed supply total, "
        "which moves only with supplies: 1100 for the lab's one PSU). Keys 'switch|<n>' "
        "carry each member's two StackPower cable ports (connected is healthy; "
        "not-connected on a standalone member is normal, on a ring member it breaks the "
        "ring to that member; shut is administrative). Context holds what moves with "
        "demand and is never compared: ports by oper state, overdrawn-police counts, "
        "watts drawn per port set and remaining per module, and the per-switch budget, "
        "allocation, availability, PSU wattages (ps_a/ps_b, ps_c where served) and "
        "consumption, which under StackPower sharing are pool allocations rather than "
        "fixed hardware figures (the lab's did not move across three reads with a "
        "constant load; a device powering up moves them)."
    ),
}
_REGISTRY_SEMANTICS.update(SEMANTICS)


# --- registrations -----------------------------------------------------------

register(
    CheckDef(
        id="iosxe_poe",
        platform="iosxe",
        description=(
            "PoE port admin/oper/class per listed port (the observed 9300 releases list "
            "powered ports only, so a device that lost power is a removed key there; "
            "context port_source, ports_total and poe_ports say what this capture's "
            "release listed) and StackPower mode, topology, supplies and cable ports "
            "(not-present on a non-PoE SKU or when the model is absent)"
        ),
        tier=1,
        compare={"mode": "equality_set"},
        miss_meaning=(
            "A powered device lost or was denied power, a port fell into a PoE fault, or "
            "the StackPower ring degraded (topology, supply count, a cable port not "
            "connected) — an AP or phone that reads merely 'down' elsewhere, or one "
            "supply failure away from a dark stack."
        ),
        collector=_collect_poe,
        tags=("platform", "power"),
    )
)
