"""Catalyst switch layer-2 state: VLAN database, trunks, spanning tree, MAC
learning and 802.1X/MAB sessions.

Five checks that show what the running-config text cannot: how the layer-2
fabric REACTED. A VLAN that VTP overwrote, a trunk whose forwarding set lost
a VLAN, a root bridge that moved, a blocked uplink, endpoints that were
learned on one port before a change and nowhere after, and sessions that no
longer authorize — every one of these is invisible to an up/down interface
check and to a config diff.

Sources, YANG-first (paths, leaf names and enum words checked against the
17.15.1 models on disk, never from memory, then against what a C9300-48UXM
actually returned: the lab harvest that the ``*_lab`` fixtures are sanitized
from, and the earlier shakedown probes of the same switch):

* ``Cisco-IOS-XE-vlan-oper`` ``vlans/vlan[id]``: ``name``, ``status``
  (``active``/``suspend``), the ``ports`` list and the ``vlan-interfaces``
  list. The lab settled which list the device fills: ``vlan-interfaces``
  carries every switchport (access ports under their VLAN, up or down; a
  trunk under VLAN 1 whatever its native VLAN; no voice VLAN, no port-channel) and
  ``ports`` stays empty. The per-port map in context is inverted from
  whichever list is populated and says which.
* ``show vtp status`` (no oper model exists; ``Cisco-IOS-XE-vtp`` is config
  only): best-effort enrichment of ``iosxe_vlans`` and the pruning flag
  ``iosxe_trunks`` reads, the route-rollups pattern — a failed or rejected
  command is a raw note, never a failed check. Its ``MD5 digest`` lines are
  computed over the VLAN database and the VTP password, so they are redacted
  from raw and from the debug trace before anything is stored.
* ``show interfaces trunk``: the only source of the forwarding-and-not-pruned
  set (the model above lists a trunk under VLAN 1 only). VLAN lists
  are rendered as canonical range strings after wrapped continuation lines
  are joined, so a value never changes shape. Where VTP pruning is enabled
  the forwarding set follows endpoint activity downstream, so it rides in
  context there and in normalized everywhere else.
* ``Cisco-IOS-XE-spanning-tree-oper`` ``stp-details``: ``stp-detail[instance]``
  bridge and root facts plus ``interfaces/interface[name]`` roles and
  states; ``stp-global`` mode, guard presence leaves and the MST identity.
  Both releases list only link-up ports and spell the instance ``VLAN0001``;
  ``root-port`` is a ``port-num`` (0 on the root bridge) and resolves to a
  name through the instance's own port rows.
* ``Cisco-IOS-XE-matm-oper`` ``matm-oper-data/matm-table[table-type
  vlan-id-number]/matm-mac-entry``: ``mac``, ``port``, ``mat-addr-type``
  (``static``/``dynamic``/``any`` — port-security's secure MACs live in
  ``psecure-oper`` and are not read here). Older releases spell ports short
  (``Tw1/0/1``, ``Vl2``), the lab release long (``TwoGigabitEthernet1/0/1``);
  the buckets keep the device's spelling and context records which form it used.
* ``Cisco-IOS-XE-identity-oper`` ``identity-oper-data/session-context-data[mac]``
  with a ``fields`` filter that names ``mac``, ``intf-name``, ``method-id``,
  ``domain``, ``state``, ``authorized``, ``vlan-id`` and ``policy-name`` and
  nothing else. The list also defines ``username``, the addresses and
  ``device-type``; none is ever requested, and this is the ONE read on the
  platform that gets no unfiltered retry on HTTP 400, because the unfiltered
  list carries usernames. The lab (no 802.1X) answered the filter with an
  empty 2xx: ``total`` 0, not not-present.

Every other ``fields`` filter gets one unfiltered retry on HTTP 400, noted in
raw. Nothing here requests, parses or stores a username or an endpoint
hostname: the MAC table and the session list carry addresses, ports and
outcomes only, and the VTP text names an updater IP, not a person.

Merge-friendliness: the per-check SEMANTICS and the shakedown KEY_MODELS
live here and are merged/exported at import; jobs/__init__.py and
tests/_loader.py discover ``checks_*`` modules by name.
"""

import re
from collections import Counter

from . import iosxe_common as common
from .registry import SEMANTICS as _REGISTRY_SEMANTICS
from .registry import CheckDef, SkipCheck, register

# --- RESTCONF paths ----------------------------------------------------------

# Shared with iosxe_interfaces (same path and kwargs: one GET per capture).
_VLAN_PATH = common.VLAN_PATH

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

_IDENTITY_PATH = "/data/Cisco-IOS-XE-identity-oper:identity-oper-data/session-context-data"
# The eight leaves of grouping sm-context this check reads, and no other:
# the list also defines username, ipv4/ipv6, device-type and user-role, which
# identify the person or the endpoint and never enter a snapshot. This filter
# is never retried unfiltered (see _collect_access_sessions).
_IDENTITY_FIELDS = "mac;intf-name;method-id;domain;state;authorized;vlan-id;policy-name"
_IDENTITY_FILTERED = "%s?fields=%s" % (_IDENTITY_PATH, _IDENTITY_FIELDS)
# authentication-method-id enum -> the bucket word the plan names
# (dot1x / mab / webauth); the rest keep the model's word minus its -id suffix.
_METHOD_WORDS = {
    "dot1x-auth-id": "dot1x",
    "mab-id": "mab",
    "web-auth-id": "webauth",
    "static-method-id": "static",
    "dot1x-supp-id": "dot1x-supplicant",
    "invalid-method-id": "invalid",
}

# yang-library module names the shakedown reports, so a 9300 shakedown shows
# at once which layer-2 collectors CAN work on the image.
KEY_MODELS = (
    "Cisco-IOS-XE-vlan-oper",
    "Cisco-IOS-XE-spanning-tree-oper",
    "Cisco-IOS-XE-matm-oper",
    "Cisco-IOS-XE-identity-oper",
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
_CLI_REFUSAL = common.CLI_REFUSAL
_MEMBER_PORT = common.MEMBER_PORT
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


# --- shared helpers (jobs/iosxe_common; historical names kept for callers) ---

_aslist = common.aslist
_node = common.node
_entries = common.entries
_to_int = common.to_int
_short = common.short
_mac = common.mac
_compact = common.compact
_member_of = common.member_of
_cli_rejected = common.cli_rejected
_long_ifname = common.long_ifname


def _get_filtered(ctx, path, fields, notes, label):
    """GET ``path?fields=…`` with one unfiltered retry on HTTP 400; None on 404.

    Returns ``(payload, path_used)`` so raw can be keyed by the request that
    actually answered — the historical shape of common.get_filtered, which
    notes the retry so the raw bundle explains its size.
    """
    read = common.get_filtered(ctx, path, fields, label=label, ok_404=True, notes=notes)
    return read.payload, read.path


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

    Keys 'vlan|<id>' -> name and status. Context carries the per-port map
    'port_vlans' (interface -> sorted VLAN ids) inverted from whichever of
    the model's two membership lists the device fills — ``ports`` when it
    holds anything, else ``vlan-interfaces`` — and 'port_map_source' names
    the list used (None when both are empty). Both raw inversions stay
    beside it with their counts so a release that fills both, or the other
    one, is visible at once. The map is context, not keys, because an
    802.1X/MAB port's operational VLAN follows its session (a RADIUS-assigned,
    guest or critical VLAN while a session is up, the configured one after it
    clears) and nothing in the model tells such a port from a static one.
    """
    normalized = {}
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
    # The two port lists come from the shared helper (iosxe_interfaces reads
    # the same lists through common.switchports to name the access ports, so
    # the two checks cannot disagree). The lab settled plan §9 item 9 on both
    # releases: ``ports`` is empty on every VLAN and ``vlan-interfaces`` lists
    # every switchport once (a trunk under VLAN 1, whatever its native VLAN). ``ports`` is
    # the model's "assigned ports" list, so it wins where a release fills it;
    # the source is recorded either way.
    lists = common.vlan_port_lists(payload)
    ports = {name: sorted(ids) for name, ids in sorted(lists["ports"].items())}
    vlan_interfaces = {name: sorted(ids) for name, ids in sorted(lists["vlan-interfaces"].items())}
    _names, source = common.switchports(payload)
    port_vlans = {"ports": ports, "vlan-interfaces": vlan_interfaces}.get(source, {})
    context = {
        "vlan_total": len(normalized),
        "active": status_counts.get("active", 0),
        "suspended": status_counts.get("suspend", 0),
        "port_vlans": port_vlans,
        "port_map_source": source,
        "ports": ports,
        "vlan_interfaces": vlan_interfaces,
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


# The model types time-of-last-topology-change as date-and-time ("POSIX time
# UTC"); both lab releases fill it with the AGE of the change counted from the
# 1970 epoch ("1970-01-01T00:09:09+00:00" = 549 s ago), so the string moves
# every capture even when nothing happened.
_EPOCH_AGE = re.compile(r"^1970-01-0(\d)T(\d{2}):(\d{2}):(\d{2})")


def _topology_change_age(value):
    """Seconds since the last topology change when the leaf is a 1970-epoch offset, else None."""
    match = _EPOCH_AGE.match(str(value or ""))
    if not match:
        return None
    day, hours, minutes, seconds = (int(part) for part in match.groups())
    return ((day - 1) * 24 + hours) * 3600 + minutes * 60 + seconds


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
                "last_topology_change_age": _topology_change_age(
                    detail.get("time-of-last-topology-change")
                ),
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


def _port_name_form(ports):
    """'short' / 'long' / 'mixed' for the physical port names a release printed; None for none.

    Older releases spell matm-oper ports ``Tw1/0/1``; the lab ``TwoGigabitEthernet1/0/1``.
    """
    forms = set()
    for port in ports:
        if _member_of(port) is None:
            continue  # CPU, an SVI or a port-channel: no member, no form to judge
        forms.add("long" if _long_ifname(port) == port else "short")
    if not forms:
        return None
    return forms.pop() if len(forms) == 1 else "mixed"


def _normalize_mac_table(payload):
    """(capability buckets, context, rows) of a matm-table read.

    Buckets count DYNAMIC entries only: 'total', 'vlan|<id>' (VLAN tables
    only — the vlan-independent table carries vlan-id-number 1 for its CPU
    group addresses, so it is counted in context, never as VLAN 1),
    'member|<n>' from the port name and 'port|<interface>' in the spelling
    the release printed. Static entries (CPU group addresses, SVI MACs and
    configured static entries alike), aging times and the per-table-type
    split live in context. Rows carry mac/vlan/port/type and nothing that
    names an endpoint.
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
    static_on_ports = sorted(
        {r["port"] for r in rows if r.get("type") == "static" and _member_of(r.get("port"))}
    )
    context = {
        "entries_total": len(rows),
        "dynamic_total": normalized["total"],
        "static_total": static_total,
        # Static entries on member ports are configured ones (``mac
        # address-table static``); CPU group addresses and SVI MACs are not.
        "static_on_ports": static_on_ports,
        "by_type": dict(by_type),
        "by_table_type": dict(by_table),
        "ports_with_dynamic": sum(1 for key in normalized if key.startswith("port|")),
        # The spelling this release printed: a release change between two
        # captures re-keys every port bucket (see SEMANTICS).
        "port_name_form": _port_name_form(r.get("port") for r in rows),
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


# --- iosxe_access_sessions ---------------------------------------------------


def _method_word(value):
    """authentication-method-id -> dot1x / mab / webauth / static / ...; None stays None."""
    if value is None:
        return None
    word = str(value)
    if word in _METHOD_WORDS:
        return _METHOD_WORDS[word]
    return word[: -len("-id")] if word.endswith("-id") else word


def _normalize_access_sessions(payload):
    """(capability buckets, context, rows) of a filtered session-context-data read.

    Buckets are flat counts of session rows: 'total', 'authorized' (rows
    whose ``authorized`` leaf is true), 'domain|<data|voice>', 'method|<dot1x
    |mab|webauth|...>', 'vlan|<id>' (the VLAN the session LANDED in, a
    RADIUS-assigned one included) and 'member|<n>' (the stack member parsed
    from ``intf-name``). An empty payload (the filtered read's empty 2xx when
    no session exists) is ``{'total': 0}``. Context counts sessions by state
    and by policy and totals the unauthorized ones; rows carry mac, port,
    method, domain, state, authorized, vlan and policy — never a username,
    address or device name, which the fields filter does not request.
    """
    normalized = {"total": 0, "authorized": 0}
    by_state = Counter()
    by_policy = Counter()
    rows = []
    for session in _entries(payload, "session-context-data"):
        mac = _mac(session.get("mac"))
        if not mac:
            continue
        port = session.get("intf-name")
        port = str(port) if port else None
        method = _method_word(session.get("method-id"))
        domain = _short(session.get("domain"), "domain-")
        state = session.get("state")
        state = str(state) if state is not None else None
        authorized = common.yes(session.get("authorized"))
        vlan = _to_int(session.get("vlan-id"))
        policy = session.get("policy-name")
        policy = str(policy) if policy else None
        rows.append(
            _compact(
                {
                    "mac": mac,
                    "port": port,
                    "method": method,
                    "domain": domain,
                    "state": state,
                    "authorized": authorized,
                    "vlan": vlan,
                    "policy": policy,
                }
            )
        )
        normalized["total"] += 1
        if authorized:
            normalized["authorized"] += 1
        by_state[state or "unknown"] += 1
        by_policy[policy or "none"] += 1
        for prefix, value in (("domain", domain), ("method", method), ("vlan", vlan)):
            if value is None:
                continue
            key = "%s|%s" % (prefix, value)
            normalized[key] = normalized.get(key, 0) + 1
        member = _member_of(port)
        if member is not None:
            key = "member|%d" % (member,)
            normalized[key] = normalized.get(key, 0) + 1
    rows.sort(key=lambda r: (r.get("port") or "", r["mac"]))
    context = {
        "sessions_total": normalized["total"],
        "unauthorized": normalized["total"] - normalized["authorized"],
        "by_state": dict(by_state),
        "by_policy": dict(by_policy),
        "ports_with_sessions": len({r["port"] for r in rows if r.get("port")}),
    }
    return normalized, context, rows


def _collect_access_sessions(ctx):
    # The ONE filtered read on the platform with no unfiltered retry: the
    # bare list carries username, the endpoint's addresses and device-type.
    # A 400 on the filter is therefore recorded as not-present, with the
    # reason, rather than read the wider shape. 404 = model absent.
    try:
        payload = ctx.get(_IDENTITY_FILTERED, ok_404=True)
    except Exception as exc:
        if getattr(exc, "status_code", None) != 400:
            raise
        raise SkipCheck(
            "identity-oper rejected the session fields filter (HTTP 400); not read "
            "unfiltered because that form carries usernames"
        ) from exc
    if payload is None:
        raise SkipCheck("802.1X/MAB session state not served (identity-oper model absent)")
    normalized, context, rows = _normalize_access_sessions(payload)
    raw = {
        _IDENTITY_FILTERED: {
            "rows": rows[:MAC_TABLE_RAW_MAX],
            "rows_total": len(rows),
            "truncated": len(rows) > MAC_TABLE_RAW_MAX,
        }
    }
    if len(rows) > MAC_TABLE_RAW_MAX:
        raw["note"] = "raw rows capped at %d of %d" % (MAC_TABLE_RAW_MAX, len(rows))
    if not rows:
        raw["note"] = "no 802.1X/MAB sessions (the filtered read answered empty); total 0"
    return {"raw": raw, "normalized": normalized, "context": context}


# --- semantics (merged into registry.SEMANTICS at import) --------------------

SEMANTICS = {
    "iosxe_vlans": (
        "The operational VLAN database keyed 'vlan|<id>' -> name and status (active is "
        "healthy; suspend cuts off every port in the VLAN while those ports still read up), "
        "plus one 'vtp' key (operating mode, domain, version, pruning on/off, configuration "
        "revision) from 'show vtp status' when SSH answered — the only view of VTP-held "
        "VLANs, which never reach the running-config text. A revision that moved with no "
        "planned VLAN edit is a VTP overwrite. Context carries the per-port map port_vlans "
        "(interface -> sorted VLAN ids) inverted from whichever of the model's two "
        "membership lists the device fills, and port_map_source names it: on the lab "
        "capture 'ports' is empty on every VLAN and 'vlan-interfaces' lists every "
        "switchport once — an access port under its VLAN whether up or down, a TRUNK under "
        "VLAN 1 whatever its native VLAN (its allowed set is in iosxe_trunks), no voice VLAN, no "
        "port-channel — so a port that shows one VLAN here can still carry many. Both raw "
        "inversions (ports, vlan_interfaces) stay in context with their counts and "
        "lists_agree, so a release that fills the other list is visible at once. The map "
        "is context, not keys, because an 802.1X/MAB port's operational VLAN follows its "
        "session (RADIUS-assigned, guest or critical while a session is up, the configured "
        "VLAN once it clears) and the model cannot tell such a port from a static one; a "
        "static port's VLAN is a config line the text diff already shows, and "
        "iosxe_access_sessions counts sessions per landed VLAN. Not-present when the "
        "vlan-oper model is absent (404) or served with no VLAN entries; the vtp key is "
        "absent, with a raw note, when SSH is unavailable or the command is refused. Raw "
        "keeps the 'show vtp status' text with its MD5 digest redacted (the digest is "
        "derived from the VTP password); the updater address stays."
    ),
    "iosxe_trunks": (
        "Per trunk 'trunk|<port>' (the short CLI spelling, Te1/0/48) -> mode, "
        "encapsulation, status, native_vlan and VLAN sets as canonical range strings "
        "('1,10,20-30'): allowed (config), active (allowed and existing in the VLAN "
        "database) and forwarding (spanning-tree forwarding and not pruned — the set that "
        "actually carries traffic). A VLAN in active but not in forwarding on the only "
        "uplink is an outage for that VLAN while every port reads up; context "
        "active_not_forwarding lists exactly that difference per trunk. Where VTP pruning "
        "is enabled (context vtp_pruning True, read from 'show vtp status' beside the "
        "trunk table) the forwarding set follows endpoint activity downstream — a "
        "neighbor's joins follow its active ports, so a VLAN whose last downstream "
        "endpoint slept is pruned from the uplink with nothing wrong — and it therefore "
        "rides in context 'forwarding' (port -> ranges), never in the keys; with pruning "
        "off, or unknown (vtp_pruning None: no SSH answer), forwarding stays a keyed "
        "field, where a change is STP blocking. On the lab (pruning disabled, one trunk "
        "allowed 1,3-4) the three sets were identical across three reads. A trunk whose "
        "neighbor sends nothing still reads trunking with its full active set forwarding: "
        "this check sees the local port's state, not the far end. Not-present when the "
        "switch has no trunk ports. Wrapped CLI continuation lines are joined before "
        "parsing, so a long list never changes shape."
    ),
    "iosxe_stp": (
        "Spanning tree: 'stp' -> mode (pvst/rapid-pvst/mst), the global guard flags as "
        "booleans (bridge_assurance, loop_guard, bpdu_guard, bpdu_filter, "
        "etherchannel_misconfig_guard) and the MST name/revision/max-hops (served under "
        "rapid-pvst too, as an empty name and revision 0); 'instance|<instance>' "
        "(spelled VLAN0001, or MST0) -> bridge_priority, root_address, root_priority, "
        "root_cost, root_port (the model's port-num resolved to an interface name through "
        "the instance's own port rows; absent on the root bridge, where port-num is 0) "
        "and is_root (own bridge address equals the root address); and "
        "'port|<instance>|<interface>' -> role, state, guard, bpdu_guard, link_type ONLY "
        "for ports that are not plain designated-forwarding (root ports, alternate/backup "
        "ports, anything blocking, listening, learning or broken). Ports in state "
        "disabled (link down: the model's stp-disabled) are never keys either — a down "
        "port has no role in the topology, and keyed it would add and remove a key per "
        "instance every time an endpoint powers off or on; the lab 9300 lists link-up "
        "ports only, so disabled_ports_listed reads 0 there and "
        "context ports_by_state shows what a release lists. A changed root_address or "
        "root_port is a root move; a new blocking key on an uplink is a lost path; the "
        "two exclusions keep endpoint power-cycling out of the keys, and on a root bridge "
        "with every port designated-forwarding the instance keys alone carry the state. "
        "Context carries per-instance topology_changes (read as a delta: a count that "
        "advanced with no planned change is a flap that healed), the "
        "last_topology_change string as served and last_topology_change_age in seconds "
        "when the device fills that leaf with an age counted from the 1970 epoch (both "
        "lab releases do, so the string moves every capture and only the counter is "
        "evidence), plus the designated-forwarding count. Not-present when the model "
        "serves no instances and no global state."
    ),
    "iosxe_mac_table": (
        "Capability buckets over DYNAMICALLY learned MACs: 'total', 'vlan|<id>', "
        "'member|<n>' (stack member parsed from the port name) and 'port|<interface>'. A "
        "bucket that held five or more entries before must hold at least one after; only "
        "busy ports (uplinks, AP and FlexConnect ports, port-channels) gate themselves, so "
        "a laptop that slept is never a finding. A gating bucket absent after means "
        "nothing was learned there (the compare notes it as 'absent post (counts as "
        "zero)'): a real loss, not a measurement gap. This is the end-to-end 'endpoints "
        "are back' signal on a stack without 802.1X. Port buckets keep the spelling the "
        "release printed — older releases short (Tw1/0/1), the lab long (TwoGigabitEthernet1/0/1), "
        "context port_name_form says which — so a release change between two captures "
        "re-keys every port bucket (the old keys read absent post, the new ones are never "
        "findings); vlan and member buckets are unaffected. Static entries never count: "
        "the CPU group addresses (01:00:0c:cc:cc:cc, 01:80:c2:00:00:0x, the broadcast "
        "address, in the vlan-independent table whose vlan-id-number reads 1 but is not "
        "VLAN 1), the SVI MACs on Vl<n> and configured static entries alike; context "
        "static_on_ports lists the member ports that carry a configured static MAC, "
        "static_total and by_type count them, by_table_type shows the tables and "
        "aging_time the timer. Raw keeps mac/vlan/port/type rows capped at "
        "MAC_TABLE_RAW_MAX so an analyst can join vendor OUIs to ports. Port-security's "
        "secure MACs (psecure-oper) are not read; no username or hostname is ever "
        "requested or stored."
    ),
    "iosxe_access_sessions": (
        "Capability buckets over 802.1X/MAB/web-auth sessions from identity-oper "
        "session-context-data: 'total', 'authorized' (sessions whose authorized leaf is "
        "true), 'domain|data' / 'domain|voice', 'method|dot1x' / 'method|mab' / "
        "'method|webauth' (the model's other method words static, eou, dot1x-supplicant "
        "and invalid appear when a release reports them), 'vlan|<id>' (the VLAN the "
        "session LANDED in — a RADIUS-assigned, guest or critical VLAN included, which is "
        "why iosxe_vlans keeps its per-port map in context) and 'member|<n>' (the stack "
        "member of the session's port). A bucket that held five or more sessions before "
        "must hold at least one after: 'RADIUS alive, every link up, nobody on the "
        "network' is the gap between iosxe_aaa_servers and the service, and a member or "
        "VLAN bucket that emptied is the port group or the policy that stopped "
        "authorizing. Fewer sessions merely means endpoints are still re-authenticating. "
        "Context counts sessions by state (idle, running, no-more-methods, authc-success, "
        "authc-failed, authz-success, authz-failed), by policy name, the unauthorized "
        "total and the ports with sessions. The read is the ONE filtered GET on the "
        "platform that is never retried unfiltered: the unfiltered list carries "
        "username, the endpoint's addresses and device type, so a release that rejects "
        "the fields filter (HTTP 400) records not-present with that reason. Not-present "
        "otherwise only when the model is absent (404); a switch without 802.1X answers "
        "the filter with an empty 2xx and records total 0 (the lab did), so the check is "
        "always on and a site that later enables 802.1X gains buckets without a code "
        "change. Raw keeps mac/port/method/domain/state/authorized/vlan/policy rows, "
        "capped like the MAC table, and nothing that names a person or an endpoint."
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

register(
    CheckDef(
        id="iosxe_access_sessions",
        platform="iosxe",
        description=(
            "802.1X/MAB/web-auth session counts per domain, method, landed VLAN and stack "
            "member, evaluated as capability (fields-filtered read only, never a username; "
            "not-present only when the model is absent or rejects the filter)"
        ),
        tier=1,
        # Buckets are counts of session rows: an absent bucket post is zero
        # sessions in that domain, method, VLAN or member, not an unmeasured one.
        compare={"mode": "capability", "floor_pre": 5, "min_post": 1, "absent_post": "zero"},
        miss_meaning=(
            "A domain, method, VLAN or stack member that carried five or more authorized "
            "sessions before carries none now — endpoints are not getting on although "
            "RADIUS answers and every link is up."
        ),
        collector=_collect_access_sessions,
        tags=("layer2", "access", "aaa"),
    )
)
