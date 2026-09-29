"""Catalyst switch layer-2 state: VLAN database, trunks, spanning tree, MAC learning.

Four checks that show what the running-config text cannot: how the layer-2
fabric REACTED. A VLAN that VTP overwrote, a trunk whose forwarding set lost
a VLAN, a root bridge that moved, a blocked uplink, and endpoints that were
learned on one port before a change and nowhere after — every one of these
is invisible to an up/down interface check and to a config diff.

Sources, YANG-first (paths and leaf names checked against the published
17.12.1 models, never from memory):

* ``Cisco-IOS-XE-vlan-oper`` ``vlans/vlan[id]``: ``name``, ``status``
  (``active``/``suspend``), the ``ports`` list and the ``vlan-interfaces``
  list. Which of the two lists holds trunks, voice members or down ports is
  a field-capture question, so both are inverted into context and the
  answer the device gave is recorded there.
* ``show vtp status`` (no oper model exists; ``Cisco-IOS-XE-vtp`` is config
  only): best-effort enrichment of ``iosxe_vlans`` and the pruning flag
  ``iosxe_trunks`` reads, the route-rollups pattern — a failed or rejected
  command is a raw note, never a failed check. Its ``MD5 digest`` lines are
  computed over the VLAN database and the VTP password, so they are redacted
  from raw and from the debug trace before anything is stored.
* ``show interfaces trunk``: the only source of the forwarding-and-not-pruned
  set. VLAN lists are rendered as canonical range strings after wrapped
  continuation lines are joined, so a value never changes shape. Where VTP
  pruning is enabled the forwarding set follows endpoint activity downstream,
  so it rides in context there and in normalized everywhere else.
* ``Cisco-IOS-XE-spanning-tree-oper`` ``stp-details``: ``stp-detail[instance]``
  bridge and root facts plus ``interfaces/interface[name]`` roles and
  states; ``stp-global`` mode, guard presence leaves and the MST identity.
* ``Cisco-IOS-XE-matm-oper`` ``matm-oper-data/matm-table[table-type
  vlan-id-number]/matm-mac-entry``: ``mac``, ``port``, ``mat-addr-type``
  (``static``/``dynamic``/``any`` — port-security's secure MACs live in
  ``psecure-oper`` and are not read here).

Every ``fields`` filter gets one unfiltered retry on HTTP 400, noted in raw.
Nothing here requests, parses or stores a username or an endpoint hostname:
the MAC table carries addresses and ports only, and the VTP text names an
updater IP, not a person.

Merge-friendliness: the per-check SEMANTICS and the shakedown KEY_MODELS
live here and are merged/exported at import; jobs/__init__.py and
tests/_loader.py discover ``checks_*`` modules by name.
"""

import re
from collections import Counter

from . import constants as C
from .registry import SEMANTICS as _REGISTRY_SEMANTICS
from .registry import CheckDef, SkipCheck, register

# --- RESTCONF paths ----------------------------------------------------------

_VLAN_PATH = "/data/Cisco-IOS-XE-vlan-oper:vlans"

_STP_PATH = "/data/Cisco-IOS-XE-spanning-tree-oper:stp-details"
# Only the leaves the normalizer reads (stp-oper-crimson, interfaces and
# stp-global groupings). Counters and timestamps requested here go to context.
_STP_FIELDS = (
    "stp-detail(instance;bridge-priority;bridge-address;designated-root-priority;"
    "designated-root-address;root-port;root-cost;topology-changes;"
    "time-of-last-topology-change;"
    "interfaces(interface(name;port-num;role;state;guard;bpdu-guard;link-type)));"
    "stp-global(mode;bridge-assurance;loop-guard;bpdu-guard;bpdu-filter;"
    "etherchannel-misconfig-guard;mst-only(mst-config-name;mst-config-revision;max-hops))"
)

_MATM_PATH = "/data/Cisco-IOS-XE-matm-oper:matm-oper-data/matm-table"
# ``aging-time`` rides along because context reports it; it is one leaf per
# table, not per entry, so it costs nothing.
_MATM_FIELDS = "table-type;vlan-id-number;aging-time;matm-mac-entry(mac;port;mat-addr-type)"

# yang-library module names the shakedown reports, so a 9300 shakedown shows
# at once which layer-2 collectors CAN work on the image.
KEY_MODELS = (
    "Cisco-IOS-XE-vlan-oper",
    "Cisco-IOS-XE-spanning-tree-oper",
    "Cisco-IOS-XE-matm-oper",
)

# MAC rows kept in the RAW bundle of iosxe_mac_table, so a prompt can join
# vendor OUIs to ports. Mirrors constants.WLC_CLIENT_RAW_MAX (the per-client
# raw cap): a large campus stack must never push the snapshot past the 10 MB
# artifact limit, and any truncation is noted next to the rows.
MAC_TABLE_RAW_MAX = 10000

# The trunk-status column can carry a bundle note ("trunk-inbndl (Po1)").
_TRUNK_STATUS_ROW = re.compile(r"^(\S+)\s+(\S+)\s+(\S+)\s+(\S+(?:\s+\(\S+\))?)\s+(\d+)\s*$")
# Header substrings of the four ``show interfaces trunk`` sections.
_TRUNK_SECTIONS = (
    ("native vlan", "status"),
    ("allowed on trunk", "allowed"),
    ("allowed and active", "active"),
    ("forwarding state and not pruned", "forwarding"),
)
# How IOS refuses a command (a privilege or command-authorization boundary),
# as opposed to answering it. Same shape as checks_iosxe's config guard.
_CLI_REFUSAL = re.compile(
    r"invalid input|incomplete command|ambiguous command|authorization failed"
    r"|not authorized|permission denied|access denied",
    re.IGNORECASE,
)
# Stack member from a physical port name: the first of the three slash-separated
# numbers (GigabitEthernet1/0/1, TwoGigabitEthernet2/0/48, Te3/1/4). A
# Port-channel, an SVI or "CPU" has no member.
_MEMBER_PORT = re.compile(r"^[A-Za-z][A-Za-z-]*?(\d+)/\d+/\d+")
# VTP lines that the normalizer reads; the first match wins for each, so on
# VTP v3 the "Feature VLAN" block is read and "Feature MST" is not.
_VTP_FIELDS = (
    (
        "mode",
        re.compile(r"^VTP Operating Mode[ \t]*:[ \t]*(.*?)[ \t]*$", re.IGNORECASE | re.MULTILINE),
    ),
    (
        "domain",
        re.compile(r"^VTP Domain Name[ \t]*:[ \t]*(.*?)[ \t]*$", re.IGNORECASE | re.MULTILINE),
    ),
    ("pruning", re.compile(r"^VTP Pruning Mode\s*:\s*(\S+)", re.IGNORECASE | re.MULTILINE)),
    ("revision", re.compile(r"^Configuration Revision\s*:\s*(\d+)", re.IGNORECASE | re.MULTILINE)),
    (
        "existing_vlans",
        re.compile(r"^Number of existing VLANs\s*:\s*(\d+)", re.IGNORECASE | re.MULTILINE),
    ),
)
_VTP_VERSION = (
    re.compile(r"^VTP version running\s*:\s*(\d+)", re.IGNORECASE | re.MULTILINE),
    re.compile(r"^VTP Version\s*:\s*running VTP\s*(\d+)", re.IGNORECASE | re.MULTILINE),
)
_VTP_COMMAND = "show vtp status"
# The digest line and the indented continuation lines that wrap its 16 bytes.
_VTP_DIGEST = re.compile(
    r"^([ \t]*MD5 digest[ \t]*:).*(?:\n[ \t]+0x[0-9A-Fa-f]{2}.*)*", re.MULTILINE
)


# --- shared helpers ----------------------------------------------------------


def _aslist(node):
    """RESTCONF quirk: a single list entry may arrive as a bare dict, absent as None."""
    if node is None:
        return []
    if isinstance(node, list):
        return node
    return [node]


def _node(payload, name):
    """Value of the module-qualified top-level node ``name``.

    List reads answer ``{"mod:list": [...]}``; a container read (or a fixture
    harvested from one) answers ``{"mod:container": {"list": [...]}}`` — the
    second form is searched one level down so both shapes normalize alike.
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


def _entries(payload, name):
    return [entry for entry in _aslist(_node(payload, name)) if isinstance(entry, dict)]


def _to_int(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _short(value, prefix):
    """Strip a YANG enum prefix ('stp-mode-rapid-pvst' -> 'rapid-pvst'); None stays None."""
    if value is None:
        return None
    value = str(value)
    return value[len(prefix) :] if value.startswith(prefix) else value


def _mac(value):
    return str(value).strip().lower() if value else None


def _compact(facts):
    """Drop unmeasured (None) facets: absent means the device did not publish it."""
    return {key: value for key, value in facts.items() if value is not None}


def _member_of(port):
    """Stack member number of a physical port name; None for anything else."""
    match = _MEMBER_PORT.match(str(port or ""))
    return int(match.group(1)) if match else None


def _cli_rejected(output):
    """True when IOS-XE refused the command form rather than answering it."""
    return bool(_CLI_REFUSAL.search(output or ""))


def _get_filtered(ctx, path, fields, notes, label):
    """GET ``path?fields=…`` with one unfiltered retry on HTTP 400; None on 404.

    Returns ``(payload, path_used)`` so raw can be keyed by the request that
    actually answered. The retry reads unfiltered (bigger, slower:
    BIG_GET_TIMEOUT) and is noted so the raw bundle explains its size.
    """
    filtered = "%s?fields=%s" % (path, fields)
    try:
        return ctx.get(filtered, ok_404=True), filtered
    except Exception as exc:
        if getattr(exc, "status_code", None) != 400:
            raise
    notes.append("%s: fields filter rejected (HTTP 400); unfiltered read used" % (label,))
    return ctx.get(path, ok_404=True, timeout=C.BIG_GET_TIMEOUT), path


# --- VLAN id sets ------------------------------------------------------------


def _vlan_set(text):
    """'1,10,20-30' -> {1, 10, 20, ..., 30}; 'none' -> {}; 'all' -> 1..4094."""
    ids = set()
    for token in str(text or "").replace(" ", "").split(","):
        if not token:
            continue
        lowered = token.lower()
        if lowered == "none":
            continue
        if lowered == "all":
            ids.update(range(1, 4095))
            continue
        if "-" in token:
            low, high = (_to_int(part) for part in token.split("-", 1))
            if low is None or high is None:
                continue
            ids.update(range(min(low, high), max(low, high) + 1))
        else:
            value = _to_int(token)
            if value is not None:
                ids.add(value)
    return ids


def _render_ranges(ids):
    """{1, 10, 20, 21, 22} -> '1,10,20-22' — one canonical spelling per set."""
    runs = []
    for value in sorted(set(ids)):
        if runs and value == runs[-1][1] + 1:
            runs[-1][1] = value
        else:
            runs.append([value, value])
    return ",".join(str(low) if low == high else "%d-%d" % (low, high) for low, high in runs)


def _vlan_ranges(text):
    """Canonical range string of a VLAN list as IOS prints it (any spelling)."""
    return _render_ranges(_vlan_set(text))


def _join_wrapped(head, continuation):
    """Append a wrapped VLAN-list line; IOS breaks at a comma, on either side of it."""
    if head.endswith(("-", ",")) or continuation.startswith(("-", ",")):
        return head + continuation
    return "%s,%s" % (head, continuation)


# --- iosxe_vlans -------------------------------------------------------------


def _normalize_vlans(payload):
    """(normalized, context) of a vlan-oper read.

    Keys 'vlan|<id>' -> name and status. Context carries the inverted
    per-port maps: 'ports' from each VLAN's ``ports`` list and
    'vlan_interfaces' from its ``vlan-interfaces`` list, each
    interface -> sorted VLAN ids. They are context, not keys, because an
    802.1X/MAB port's operational VLAN follows its session (a RADIUS-assigned,
    guest or critical VLAN while a session is up, the configured one after it
    clears) and nothing in the model tells such a port from a static one.
    """
    normalized = {}
    ports = {}
    vlan_interfaces = {}
    status_counts = Counter()
    for vlan in _entries(payload, "vlan"):
        vlan_id = _to_int(vlan.get("id"))
        if vlan_id is None:
            continue
        status = vlan.get("status")
        normalized["vlan|%d" % (vlan_id,)] = _compact(
            {
                "name": str(vlan["name"]) if vlan.get("name") is not None else None,
                "status": str(status) if status is not None else None,
            }
        )
        status_counts[str(status) if status is not None else "unknown"] += 1
        for list_name, target in (("ports", ports), ("vlan-interfaces", vlan_interfaces)):
            for member in _aslist(vlan.get(list_name)):
                if not isinstance(member, dict) or not member.get("interface"):
                    continue
                target.setdefault(str(member["interface"]), set()).add(vlan_id)
    context = {
        "vlan_total": len(normalized),
        "active": status_counts.get("active", 0),
        "suspended": status_counts.get("suspend", 0),
        "ports": {name: sorted(ids) for name, ids in sorted(ports.items())},
        "vlan_interfaces": {name: sorted(ids) for name, ids in sorted(vlan_interfaces.items())},
        # Which list the device fills (and whether they differ) is what the
        # field capture settles; the counts make the answer visible.
        "ports_listed": len(ports),
        "vlan_interfaces_listed": len(vlan_interfaces),
        "lists_agree": ports == vlan_interfaces,
    }
    return normalized, context


def _parse_vtp_status(text):
    """'show vtp status' -> VTP facts (mode/domain/version/pruning/revision, existing_vlans).

    Tolerates both the v1/v2 layout ("VTP Version : running VTP2") and the
    v2/v3 layout with per-feature blocks. Only the fields found are returned.
    """
    text = text or ""
    facts = {}
    for name, pattern in _VTP_FIELDS:
        match = pattern.search(text)
        if match:
            facts[name] = match.group(1)
    for pattern in _VTP_VERSION:
        match = pattern.search(text)
        if match:
            facts["version"] = match.group(1)
            break
    if "mode" in facts:
        facts["mode"] = facts["mode"].strip().lower()
    if "pruning" in facts:
        facts["pruning"] = facts["pruning"].strip().lower() == "enabled"
    for name in ("version", "revision", "existing_vlans"):
        if name in facts:
            facts[name] = _to_int(facts[name])
    return _compact(facts)


def _redact_vtp_status(text):
    """'show vtp status' with the MD5 digest value replaced by <redacted>.

    The digest is computed over the VLAN database and the VTP password;
    beside the domain, revision and VLAN list a snapshot already holds, it is
    the last input an offline attack on the password needs. The mode, domain,
    version, pruning and revision lines the parser reads are untouched.
    """
    return _VTP_DIGEST.sub(r"\1 <redacted>", text or "")


def _vtp_status(ctx, raw):
    """Best-effort `show vtp status` (the route-rollups pattern): raw gets the
    redacted output under the command and, on any trouble, a note; returns the
    parsed facts, {} when the command failed, was refused or was not
    recognised. The Celery abort signal is re-raised, never noted."""
    raw[_VTP_COMMAND] = None
    try:
        output = ctx.run_ssh(_VTP_COMMAND, redact=_redact_vtp_status)
    except Exception as exc:  # transport failure modes vary by SSH stack
        if type(exc).__name__ == "SoftTimeLimitExceeded":
            raise  # the Celery abort signal is never a note
        raw["note"] = "ssh '%s' failed: %s" % (_VTP_COMMAND, exc)
        return {}
    raw[_VTP_COMMAND] = _redact_vtp_status(output)
    if _cli_rejected(output):
        raw["note"] = "'%s' rejected on this platform; VTP facts unavailable" % (_VTP_COMMAND,)
        return {}
    facts = _parse_vtp_status(output)
    if not facts:
        raw["note"] = "no VTP fields recognised in '%s' output" % (_VTP_COMMAND,)
    return facts


def _collect_vlans(ctx):
    payload = ctx.get(_VLAN_PATH, ok_404=True)
    if payload is None:
        raise SkipCheck("VLAN database not served (vlan-oper model absent)")
    normalized, context = _normalize_vlans(payload)
    if not normalized:
        raise SkipCheck(
            "vlan-oper served no VLAN entries (every switch has VLAN 1, so the model "
            "answered empty)"
        )
    raw = {_VLAN_PATH: payload, _VTP_COMMAND: None, "note": None}
    if ctx.has_ssh:
        # Best-effort enrichment only: any SSH or parse trouble is recorded in
        # raw and the VLAN rows above still satisfy the check.
        vtp = _vtp_status(ctx, raw)
        existing = vtp.pop("existing_vlans", None)
        if existing is not None:
            context["vtp_existing_vlans"] = existing
        if vtp:
            normalized["vtp"] = vtp
    else:
        raw["note"] = "no SSH transport; VTP facts unavailable"
    return {"raw": raw, "normalized": normalized, "context": context}


# --- iosxe_trunks ------------------------------------------------------------


def _parse_interfaces_trunk(text):
    """'show interfaces trunk' -> {port: {mode, encapsulation, status, native_vlan,
    allowed, active, forwarding}} with every VLAN set as a canonical range string.

    The four sections are recognised by their header lines; a line that
    starts with whitespace continues the previous port's VLAN list (or its
    status note), and a blank line ends a section.
    """
    rows = {}
    section = None
    last_port = None
    for raw_line in (text or "").splitlines():
        line = raw_line.rstrip()
        stripped = line.strip()
        if not stripped:
            last_port = None
            continue
        if stripped.startswith("Port ") or stripped == "Port":
            lowered = stripped.lower()
            section = next((name for marker, name in _TRUNK_SECTIONS if marker in lowered), None)
            last_port = None
            continue
        if section is None:
            continue
        if line[0].isspace():
            if last_port is None:
                continue
            row = rows[last_port]
            if section == "status":
                row["status"] = "%s %s" % (row.get("status", ""), stripped)
            else:
                row["_" + section] = _join_wrapped(row.get("_" + section, ""), stripped)
            continue
        if section == "status":
            match = _TRUNK_STATUS_ROW.match(stripped)
            if not match:
                continue
            port, mode, encapsulation, status, native = match.groups()
            rows.setdefault(port, {}).update(
                {
                    "mode": mode,
                    "encapsulation": encapsulation,
                    "status": status,
                    "native_vlan": int(native),
                }
            )
        else:
            parts = stripped.split(None, 1)
            port = parts[0]
            rows.setdefault(port, {})["_" + section] = parts[1] if len(parts) > 1 else ""
        last_port = port
    for row in rows.values():
        for name in ("allowed", "active", "forwarding"):
            spelled = row.pop("_" + name, None)
            if spelled is not None:
                row[name] = _vlan_ranges(spelled)
    return rows


def _trunk_context(rows):
    """Counts plus, per trunk, the active VLANs that are NOT forwarding (pruned/blocked)."""
    not_forwarding = {}
    for port, row in rows.items():
        if "active" in row and "forwarding" in row:
            missing = _vlan_set(row["active"]) - _vlan_set(row["forwarding"])
            if missing:
                not_forwarding[port] = _render_ranges(missing)
    return {
        "trunk_total": len(rows),
        "trunking": sum(1 for row in rows.values() if row.get("status") == "trunking"),
        "forwarding_vlans": {
            port: len(_vlan_set(row["forwarding"]))
            for port, row in sorted(rows.items())
            if "forwarding" in row
        },
        "active_not_forwarding": dict(sorted(not_forwarding.items())),
    }


def _collect_trunks(ctx):
    if not ctx.has_ssh:
        raise SkipCheck("no SSH transport")
    command = "show interfaces trunk"
    output = ctx.run_ssh(command)
    if _cli_rejected(output):
        raise SkipCheck("'%s' rejected on this platform" % (command,))
    rows = _parse_interfaces_trunk(output)
    if not rows:
        raise SkipCheck("no trunk ports ('%s' lists none)" % (command,))
    raw = {command: output}
    # With VTP pruning on, a trunk's forwarding-and-not-pruned set follows the
    # downstream neighbor's joins, which follow its active ports: it moves with
    # endpoint activity, so it rides in context there. One extra allow-listed
    # command (SSH reads are not cached); best-effort, like iosxe_vlans' read.
    pruning = _vtp_status(ctx, raw).get("pruning")
    context = _trunk_context(rows)
    context["vtp_pruning"] = pruning
    context["forwarding"] = {}
    normalized = {}
    for port, row in sorted(rows.items()):
        row = dict(row)
        if pruning is True and "forwarding" in row:
            context["forwarding"][port] = row.pop("forwarding")
        normalized["trunk|%s" % (port,)] = row
    return {"raw": raw, "normalized": normalized, "context": context}


# --- iosxe_stp ---------------------------------------------------------------


def _stp_global(details):
    """The 'stp' key from stp-global: mode, guard presence flags, MST identity."""
    node = details.get("stp-global") if isinstance(details, dict) else None
    if not isinstance(node, dict):
        return None
    facts = {"mode": _short(node.get("mode"), "stp-mode-")}
    # ``type empty`` leaves arrive as [null] when set and are absent otherwise:
    # presence is the fact, so every flag is always a bool.
    for leaf, name in (
        ("bridge-assurance", "bridge_assurance"),
        ("loop-guard", "loop_guard"),
        ("bpdu-guard", "bpdu_guard"),
        ("bpdu-filter", "bpdu_filter"),
        ("etherchannel-misconfig-guard", "etherchannel_misconfig_guard"),
    ):
        facts[name] = leaf in node
    mst = node.get("mst-only")
    if isinstance(mst, dict):
        facts["mst_name"] = mst.get("mst-config-name")
        facts["mst_revision"] = _to_int(mst.get("mst-config-revision"))
        facts["mst_max_hops"] = _to_int(mst.get("max-hops"))
    return _compact(facts)


def _stp_is_root(detail):
    """True when this bridge is the root: root address is its own (or root-port is 0)."""
    own, root = _mac(detail.get("bridge-address")), _mac(detail.get("designated-root-address"))
    if own and root:
        return own == root
    root_port = _to_int(detail.get("root-port"))
    return root_port == 0 if root_port is not None else None


def _normalize_stp(payload):
    """(normalized, context) of an stp-details read.

    Keys: 'stp' (global), 'instance|<instance>' (bridge and root facts, the
    root port resolved to a name through port-num) and
    'port|<instance>|<interface>' for every port that is NOT plain
    designated-forwarding — the exclusion that keeps endpoint power-cycling
    out of the keys. Topology-change counters and times go to context.
    """
    details = _node(payload, "stp-details")
    details = details if isinstance(details, dict) else {}
    normalized = {}
    context = {"instances": {}, "ports_by_role": Counter(), "ports_by_state": Counter()}
    stp = _stp_global(details)
    if stp is not None:
        normalized["stp"] = stp
    keyed_ports = 0
    disabled_listed = 0
    for detail in _aslist(details.get("stp-detail")):
        if not isinstance(detail, dict) or not detail.get("instance"):
            continue
        instance = str(detail["instance"])
        interfaces = detail.get("interfaces")
        ports = [
            p
            for p in _aslist(interfaces.get("interface") if isinstance(interfaces, dict) else None)
            if isinstance(p, dict) and p.get("name")
        ]
        by_num = {_to_int(p.get("port-num")): str(p["name"]) for p in ports}
        root_port_num = _to_int(detail.get("root-port"))
        root_port = None
        if root_port_num:
            root_port = by_num.get(root_port_num) or str(root_port_num)
        normalized["instance|%s" % (instance,)] = _compact(
            {
                "bridge_priority": _to_int(detail.get("bridge-priority")),
                "root_address": _mac(detail.get("designated-root-address")),
                "root_priority": _to_int(detail.get("designated-root-priority")),
                "root_cost": _to_int(detail.get("root-cost")),
                "root_port": root_port,
                "is_root": _stp_is_root(detail),
            }
        )
        designated_forwarding = 0
        for port in ports:
            role = _short(port.get("role"), "stp-")
            state = _short(port.get("state"), "stp-")
            context["ports_by_role"][role or "unknown"] += 1
            context["ports_by_state"][state or "unknown"] += 1
            if state == "disabled":
                # A link-down port has no role in the topology (no root,
                # alternate or backup path runs through it); keyed, every
                # endpoint that powers off or on would add or remove a key.
                disabled_listed += 1
                continue
            if role == "designated" and state == "forwarding":
                designated_forwarding += 1
                continue
            keyed_ports += 1
            normalized["port|%s|%s" % (instance, port["name"])] = _compact(
                {
                    "role": role,
                    "state": state,
                    "guard": _short(port.get("guard"), "stp-port-guard-"),
                    "bpdu_guard": _short(port.get("bpdu-guard"), "stp-port-bpduguard-"),
                    "link_type": _short(port.get("link-type"), "stp-"),
                }
            )
        context["instances"][instance] = _compact(
            {
                "topology_changes": _to_int(detail.get("topology-changes")),
                "last_topology_change": detail.get("time-of-last-topology-change"),
                "designated_forwarding": designated_forwarding,
                "ports": len(ports),
            }
        )
    context["instance_total"] = len(context["instances"])
    context["ports_keyed"] = keyed_ports
    # Whether the release lists link-down ports as stp-disabled rows is a
    # field-capture question; the count answers it.
    context["disabled_ports_listed"] = disabled_listed
    context["ports_by_role"] = dict(context["ports_by_role"])
    context["ports_by_state"] = dict(context["ports_by_state"])
    return normalized, context


def _collect_stp(ctx):
    notes = []
    payload, path = _get_filtered(ctx, _STP_PATH, _STP_FIELDS, notes, "stp-details")
    if payload is None:
        raise SkipCheck("spanning-tree state not served (spanning-tree-oper model absent)")
    normalized, context = _normalize_stp(payload)
    if not normalized:
        raise SkipCheck("spanning tree serves no instances and no global state")
    raw = {path: payload}
    if notes:
        raw["note"] = "; ".join(notes)
    return {"raw": raw, "normalized": normalized, "context": context}


# --- iosxe_mac_table ---------------------------------------------------------


def _normalize_mac_table(payload):
    """(capability buckets, context, rows) of a matm-table read.

    Buckets count DYNAMIC entries only: 'total', 'vlan|<id>' (VLAN tables
    only — what vlan-id-number means for the other table types is a field
    question, and those tables are counted in context), 'member|<n>' from the
    port name and 'port|<interface>'. Static entries, aging times and the
    per-table-type split live in context. Rows carry mac/vlan/port/type and
    nothing that names an endpoint.
    """
    normalized = {"total": 0}
    static_total = 0
    by_type = Counter()
    by_table = Counter()
    aging = {}
    rows = []
    for table in _entries(payload, "matm-table"):
        table_type = _short(table.get("table-type"), "mat-")
        vlan_id = _to_int(table.get("vlan-id-number"))
        if table.get("aging-time") is not None and vlan_id is not None and table_type == "vlan":
            aging[str(vlan_id)] = _to_int(table.get("aging-time"))
        for entry in _aslist(table.get("matm-mac-entry")):
            if not isinstance(entry, dict):
                continue
            mac = _mac(entry.get("mac"))
            if not mac:
                continue
            addr_type = entry.get("mat-addr-type")
            addr_type = str(addr_type) if addr_type is not None else None
            port = str(entry.get("port")) if entry.get("port") is not None else None
            by_type[addr_type or "unknown"] += 1
            by_table[table_type or "unknown"] += 1
            rows.append(
                _compact(
                    {
                        "mac": mac,
                        "vlan": vlan_id,
                        "port": port,
                        "type": addr_type,
                        "table": table_type,
                    }
                )
            )
            if addr_type != "dynamic":
                if addr_type == "static":
                    static_total += 1
                continue
            normalized["total"] += 1
            if table_type == "vlan" and vlan_id is not None:
                key = "vlan|%d" % (vlan_id,)
                normalized[key] = normalized.get(key, 0) + 1
            if port:
                key = "port|%s" % (port,)
                normalized[key] = normalized.get(key, 0) + 1
                member = _member_of(port)
                if member is not None:
                    key = "member|%d" % (member,)
                    normalized[key] = normalized.get(key, 0) + 1
    rows.sort(key=lambda r: (r.get("vlan") if r.get("vlan") is not None else -1, r["mac"]))
    aging_values = set(aging.values())
    context = {
        "entries_total": len(rows),
        "dynamic_total": normalized["total"],
        "static_total": static_total,
        "by_type": dict(by_type),
        "by_table_type": dict(by_table),
        "ports_with_dynamic": sum(1 for key in normalized if key.startswith("port|")),
        "aging_time": aging_values.pop() if len(aging_values) == 1 else None,
        "aging_time_by_vlan": aging if len(aging_values) > 1 else {},
    }
    return normalized, context, rows


def _collect_mac_table(ctx):
    notes = []
    payload, path = _get_filtered(ctx, _MATM_PATH, _MATM_FIELDS, notes, "matm-table")
    if payload is None:
        raise SkipCheck("MAC address table not served (matm-oper model absent)")
    normalized, context, rows = _normalize_mac_table(payload)
    raw = {
        path: {
            "rows": rows[:MAC_TABLE_RAW_MAX],
            "rows_total": len(rows),
            "truncated": len(rows) > MAC_TABLE_RAW_MAX,
        }
    }
    if len(rows) > MAC_TABLE_RAW_MAX:
        notes.append("raw rows capped at %d of %d" % (MAC_TABLE_RAW_MAX, len(rows)))
    if notes:
        raw["note"] = "; ".join(notes)
    return {"raw": raw, "normalized": normalized, "context": context}


# --- semantics (merged into registry.SEMANTICS at import) --------------------

SEMANTICS = {
    "iosxe_vlans": (
        "The operational VLAN database keyed 'vlan|<id>' -> name and status (active is "
        "healthy; suspend cuts off every port in the VLAN while those ports still read up), "
        "plus one 'vtp' key (operating mode, domain, version, pruning on/off, configuration "
        "revision) from 'show vtp status' when SSH answered — the only view of VTP-held "
        "VLANs, which never reach the running-config text. A revision that moved with no "
        "planned VLAN edit is a VTP overwrite. Context carries the per-port maps "
        "(interface -> sorted VLAN ids) inverted from the model's 'ports' and "
        "'vlan-interfaces' lists, with counts showing which list the device fills and "
        "whether they agree. The maps are context, not keys, because an 802.1X/MAB port's "
        "operational VLAN follows its session (RADIUS-assigned, guest or critical while a "
        "session is up, the configured VLAN once it clears) and the model cannot tell such "
        "a port from a static one; a static port's VLAN is a config line the text diff "
        "already shows. Not-present when the vlan-oper model is absent (404) or served "
        "with no VLAN entries; the vtp key is absent, with a raw note, when SSH is "
        "unavailable or the command is refused. Raw keeps the 'show vtp status' text with "
        "its MD5 digest redacted (the digest is derived from the VTP password); the "
        "updater address stays."
    ),
    "iosxe_trunks": (
        "Per trunk 'trunk|<port>' -> mode, encapsulation, status, native_vlan and VLAN "
        "sets as canonical range strings ('1,10,20-30'): allowed (config), active "
        "(allowed and existing in the VLAN database) and forwarding (spanning-tree "
        "forwarding and not pruned — the set that actually carries traffic). A VLAN in "
        "active but not in forwarding on the only uplink is an outage for that VLAN while "
        "every port reads up; context active_not_forwarding lists exactly that difference "
        "per trunk. Where VTP pruning is enabled (context vtp_pruning True, read from "
        "'show vtp status' beside the trunk table) the forwarding set follows endpoint "
        "activity downstream — a neighbor's joins follow its active ports, so a VLAN whose "
        "last downstream endpoint slept is pruned from the uplink with nothing wrong — and "
        "it therefore rides in context 'forwarding' (port -> ranges), never in the keys; "
        "with pruning off, or unknown (vtp_pruning None: no SSH answer), forwarding stays "
        "a keyed field, where a change is STP blocking. Not-present when the switch has no "
        "trunk ports. Wrapped CLI continuation lines are joined before parsing, so a long "
        "list never changes shape."
    ),
    "iosxe_stp": (
        "Spanning tree: 'stp' -> mode (pvst/rapid-pvst/mst), the global guard flags as "
        "booleans (bridge_assurance, loop_guard, bpdu_guard, bpdu_filter, "
        "etherchannel_misconfig_guard) and the MST name/revision when MST runs; "
        "'instance|<instance>' -> bridge_priority, root_address, root_priority, root_cost, "
        "root_port (resolved to an interface name) and is_root; and "
        "'port|<instance>|<interface>' -> role, state, guard, bpdu_guard, link_type ONLY "
        "for ports that are not plain designated-forwarding (root ports, alternate/backup "
        "ports, anything blocking, listening, learning or broken). Ports in state "
        "disabled (link down: the model's stp-disabled) are never keys either — a down "
        "port has no role in the topology, and keyed it would add and remove a key per "
        "instance every time an endpoint powers off or on; context ports_by_state and "
        "disabled_ports_listed count them, so a capture shows whether the release lists "
        "them at all. A changed root_address or root_port is a root move; a new blocking "
        "key on an uplink is a lost path; the two exclusions keep endpoint power-cycling "
        "out of the keys. Context carries per-instance topology-change counters and "
        "last-change times (read as deltas: a count that advanced with no planned change "
        "is a flap that healed) plus the designated-forwarding count. Not-present when the "
        "model serves no instances and no global state."
    ),
    "iosxe_mac_table": (
        "Capability buckets over DYNAMICALLY learned MACs: 'total', 'vlan|<id>', "
        "'member|<n>' (stack member parsed from the port name) and 'port|<interface>'. A "
        "bucket that held five or more entries before must hold at least one after; only "
        "busy ports (uplinks, AP and FlexConnect ports, port-channels) gate themselves, so "
        "a laptop that slept is never a finding. A gating bucket absent after means "
        "nothing was learned there (the compare notes it as 'absent post (counts as "
        "zero)'): a real loss, not a measurement gap. This is the end-to-end 'endpoints "
        "are back' signal on a stack without 802.1X. Context carries static and per-type "
        "counts, the table types seen and the aging time; raw keeps mac/vlan/port/type "
        "rows capped at MAC_TABLE_RAW_MAX so an analyst can join vendor OUIs to ports. "
        "Port-security's secure MACs (psecure-oper) are not read; no username or hostname "
        "is ever requested or stored."
    ),
}
_REGISTRY_SEMANTICS.update(SEMANTICS)


# --- registrations -----------------------------------------------------------

register(
    CheckDef(
        id="iosxe_vlans",
        platform="iosxe",
        description=(
            "Operational VLAN database (name, status) plus VTP mode/domain/revision; "
            "per-port VLAN maps in context"
        ),
        tier=1,
        compare={"mode": "equality_set"},
        miss_meaning=(
            "A VLAN vanished, was suspended or renamed, or the VTP revision/mode moved — a "
            "VTP overwrite or a stray 'no vlan' cuts off every port in it while the ports "
            "still read up."
        ),
        collector=_collect_vlans,
        tags=("layer2", "vlans"),
    )
)

register(
    CheckDef(
        id="iosxe_trunks",
        platform="iosxe",
        description=(
            "Trunk ports: mode, encapsulation, native VLAN and the allowed/active/"
            "forwarding VLAN sets; forwarding moves to context where VTP pruning is on "
            "(not-present when no port trunks)"
        ),
        tier=1,
        compare={"mode": "equality_set"},
        miss_meaning=(
            "A trunk's forwarding set lost a VLAN (STP blocking or VTP pruning), its native "
            "VLAN or mode changed, or a trunk stopped trunking — an outage for those VLANs "
            "while the port stays up."
        ),
        collector=_collect_trunks,
        tags=("layer2", "trunks"),
    )
)

register(
    CheckDef(
        id="iosxe_stp",
        platform="iosxe",
        description=(
            "Spanning tree: mode and global guards, per-instance root facts, and every "
            "port that is neither designated-forwarding nor disabled (link down)"
        ),
        tier=1,
        compare={"mode": "equality_set"},
        miss_meaning=(
            "The root bridge or root port moved, an uplink went blocking/alternate, or a "
            "port is stuck outside forwarding — a topology change that every up/down check "
            "misses."
        ),
        collector=_collect_stp,
        tags=("layer2", "spanning-tree"),
    )
)

register(
    CheckDef(
        id="iosxe_mac_table",
        platform="iosxe",
        description=(
            "Dynamically learned MAC counts per VLAN, stack member and port, evaluated as "
            "capability (rows in raw, capped)"
        ),
        tier=2,
        # A bucket absent post is a VLAN, member or port on which nothing was
        # learned — a count of zero, not a sweep that did not measure it.
        compare={"mode": "capability", "floor_pre": 5, "min_post": 1, "absent_post": "zero"},
        miss_meaning=(
            "A VLAN, member or port that carried five or more learned MACs before carries "
            "none now — endpoints behind that path are not back (fewer merely means "
            "ramping)."
        ),
        collector=_collect_mac_table,
        tags=("layer2", "mac-table"),
    )
)
