"""PAN-OS 11.x check catalog — CLI-first over SSH.

Every collector runs allowlisted operational commands through ``ctx.run_ssh``;
SshRunner's session prep (``set cli op-command-xml-output on``) makes the CLI
return the same XML the API would, so each parser here works on ``extract_xml``
output and ports unchanged to the XML API later.

Parsing lives in pure module-level ``_normalize_*`` / ``_parse_*`` functions
that take the raw CLI output string and return the normalized view — the CI
test battery calls them directly with fixture captures. Collectors stay thin:
run command(s), parse, shape ``{"raw": ..., "normalized": ...}``. ``raw`` for
every check is the raw CLI output keyed by the exact command string (that is
the audit trail), plus explicit metadata where a check produces some (zone
truncation, unparsed pairs, interface name mapping).

No ``_aslist`` helper here: this module consumes XML via ElementTree, whose
``findall`` is uniformly list-shaped — the list-or-dict RESTCONF quirk does
not exist on this path.
"""

import re
import time
from datetime import datetime, timezone

from . import constants as C
from .panos_xml import PanosParseError, extract_xml, result_of, text, to_int
from .registry import CheckDef, CollectError, SkipCheck, register


def _parse_or_fail(parser, cli_output, label):
    """Run a pure parser; a parse failure is a failed read, never emptiness."""
    try:
        return parser(cli_output)
    except PanosParseError as exc:
        raise CollectError("%s: %s" % (label, exc)) from exc


# --- panos_system_info -------------------------------------------------------

_SYSTEM_FIELDS = (
    ("sw-version", "sw_version"),
    ("app-version", "app_version"),
    ("threat-version", "threat_version"),
    ("av-version", "av_version"),
    ("wildfire-version", "wildfire_version"),
    ("model", "model"),
    ("serial", "serial"),
    ("hostname", "hostname"),
    # A multi-vsys flavor change across a replacement silently reshapes every
    # session/zone measurement (field finding: global counters count all vsys,
    # enumeration is scope-dependent) — it must surface as a diff.
    ("multi-vsys", "multi_vsys"),
)


def _normalize_system_info(cli_output):
    """'show system info' -> flat version/identity dict (present fields only).

    Uptime and clock are deliberately never emitted — they differ on every
    healthy capture and would drown the versions that matter.
    """
    result = result_of(extract_xml(cli_output))
    system = result.find("system") if result is not None else None
    if system is None:
        raise PanosParseError("no <system> element in 'show system info' output")
    normalized = {}
    for xml_name, field in _SYSTEM_FIELDS:
        value = text(system, xml_name)
        if value is not None:
            normalized[field] = value
    return normalized


def _collect_system_info(ctx):
    command = "show system info"
    output = ctx.run_ssh(command)
    normalized = _parse_or_fail(_normalize_system_info, output, command)
    return {"raw": {command: output}, "normalized": normalized}


# --- panos_ha ----------------------------------------------------------------


def _normalize_ha(cli_output):
    """'show high-availability state' -> enabled flag plus states when enabled.

    HA disabled (or <enabled> missing) is a recorded fact, not a skip — a
    cutover that silently drops HA must show up as a diff. Both the <group>
    and top-level layouts are tolerated; PAN-OS has shipped both.
    """
    result = result_of(extract_xml(cli_output))
    if result is None:
        raise PanosParseError("no <result> in HA state output")
    enabled = (text(result, "enabled") or "no").lower()
    if enabled != "yes":
        return {"enabled": "no"}
    return {
        "enabled": "yes",
        "local_state": text(result, "group/local-info/state") or text(result, "local-info/state"),
        "peer_state": text(result, "group/peer-info/state") or text(result, "peer-info/state"),
        "config_sync": text(result, "group/running-sync")
        or text(result, "running-sync")
        or "unknown",
    }


def _collect_ha(ctx):
    command = "show high-availability state"
    output = ctx.run_ssh(command)
    normalized = _parse_or_fail(_normalize_ha, output, command)
    return {"raw": {command: output}, "normalized": normalized}


# --- panos_session_info ------------------------------------------------------

_SESSION_FIELDS = (
    ("num-active", "active"),
    ("num-tcp", "tcp"),
    ("num-udp", "udp"),
    ("num-icmp", "icmp"),
)


def _normalize_session_info(cli_output):
    """'show session info' -> the four count fields the tolerance band covers.

    Rates (cps/pps/kbps) and num-max stay in raw only: rates are instantaneous
    noise and the table ceiling is a platform property, not a health signal.
    """
    result = result_of(extract_xml(cli_output))
    if result is None:
        raise PanosParseError("no <result> in 'show session info' output")
    normalized = {}
    for xml_name, field in _SESSION_FIELDS:
        value = to_int(text(result, xml_name))
        if value is not None:
            normalized[field] = value
    if not normalized:
        raise PanosParseError("no session counters in 'show session info' output")
    return normalized


def _collect_session_info(ctx):
    command = "show session info"
    output = ctx.run_ssh(command)
    normalized = _parse_or_fail(_normalize_session_info, output, command)
    return {"raw": {command: output}, "normalized": normalized}


# --- panos_session_matrix ----------------------------------------------------

# Zone names are interpolated into a CLI filter string. Restricting them to a
# conservative charset keeps a name with spaces/metacharacters from breaking
# the filter syntax — and keeps any hostile name from smuggling text past the
# command allowlist. Excluded names are recorded in raw, never silently lost.
_SAFE_ZONE = re.compile(r"^[A-Za-z0-9._-]+$")


def _parse_zones(cli_output):
    """'show interface all' -> sorted unique non-empty zone names."""
    result = result_of(extract_xml(cli_output))
    if result is None:
        raise PanosParseError("no <result> in 'show interface all' output")
    zones = set()
    for entry in result.findall("ifnet/entry"):
        zone = text(entry, "zone")
        if zone:
            zones.add(zone)
    return sorted(zones)


_NO_SESSIONS = re.compile(r"no\s+active\s+sessions?", re.IGNORECASE)
# Phrase-anchored so a stray earlier digit can never win. PAN-OS wraps free-
# text op output inconsistently (bare text under <result> on some commands,
# <member>-wrapped on others — both proven in PANW's own parsers), so the
# count is extracted from ALL descendant text, never result.text alone.
_COUNT_LINE = re.compile(r"match(?:es)?\s+filter:\s*(-?\d+)", re.IGNORECASE)


def _parse_session_count(cli_output):
    """Count out of a 'show session all ... count yes' response, or None.

    Tries the XML shapes first (a <count> element, the anchored count phrase
    anywhere in the result's descendant text, a bare numeric result), then the
    classic plain-text line "Number of sessions that match filter: N".

    Zero matches: PAN-OS answers a zero-match count query with an EMPTY
    <result/> on a success response rather than an explicit zero (found in
    the field — an unpatched parser floods "unparseable" for every quiet zone
    pair), and some paths print "No Active Sessions"; both mean 0. A
    status="error" response is never a zero — the query was refused. None
    means genuinely unparseable; the caller records it as such.
    """
    root = None
    try:
        root = extract_xml(cli_output)
    except PanosParseError:
        root = None
    if root is not None and root.tag == "response" and root.get("status") == "error":
        return None
    result = result_of(root)
    if result is not None:
        for path in ("count", "member/count"):
            value = to_int(text(result, path))
            if value is not None:
                return value
        blob = "".join(result.itertext())
        match = _COUNT_LINE.search(blob)
        if match:
            return int(match.group(1))
        # Multi-dataplane platforms (PA-5200s) answer with one count member
        # per DP and no aggregate phrase — the true total is the SUM. Labels
        # can contain digits ("DP0: 6134"), so take each member's LAST
        # integer. Guarded: a response holding <entry> children is a session
        # dump and must never be misread as counts. (Field regression: a
        # phrase-only parser read nothing here; an earlier first-member
        # parser read only DP0 — half the real count.)
        if result.find("entry") is None:
            member_counts = []
            for member in result.findall(".//member"):
                integers = re.findall(r"-?\d+", "".join(member.itertext()))
                if integers:
                    member_counts.append(int(integers[-1]))
            if member_counts:
                return sum(member_counts)
        stripped = blob.strip()
        # Bare numeric applies only to a CHILDLESS result (<result>7</result>);
        # a dump's concatenated digits must never pass an isdigit test.
        if len(result) == 0 and stripped.lstrip("-").isdigit():
            return int(stripped)
        if _NO_SESSIONS.search(blob):
            return 0
        if len(result) == 0 and not stripped:
            return 0
    match = _COUNT_LINE.search(cli_output or "")
    if match:
        return int(match.group(1))
    if cli_output and _NO_SESSIONS.search(cli_output):
        return 0
    return None


_RAW_OUTPUT_CAP = 20000  # chars kept per stored command output; dumps are not audit


def _record_raw(raw, command, output):
    """Store a command's output for the audit trail, capped.

    A response that unexpectedly turns out to be a full session dump must not
    balloon the raw artifact past the platform's per-file cap (field finding).
    """
    if output is not None and len(output) > _RAW_OUTPUT_CAP:
        raw[command] = output[:_RAW_OUTPUT_CAP] + "\n...[truncated %d chars]" % (
            len(output) - _RAW_OUTPUT_CAP,
        )
    else:
        raw[command] = output


# Abort the sweep when this many leading responses are ALL unreadable — a
# poisoned SSH session or wrong syntax makes hundreds more queries pointless
# (field finding: 186/186 unparseable after unproven query forms desynced the
# session; fail fast, keep the evidence).
_SWEEP_ABORT_AFTER = 5

# Emit a progress line to the job log every N sweep queries: a healthy
# multi-minute sweep must never look hung (field feedback).
_PROGRESS_EVERY = 50


def _fmt_duration(seconds):
    seconds = int(seconds)
    if seconds < 60:
        return "%ds" % (seconds,)
    return "%dm%02ds" % (seconds // 60, seconds % 60)


def _collect_session_matrix(ctx):
    """Ordered zone-pair session counts, PAIR FORM ONLY.

    Only `show session all filter count yes from <A> to <B>` is field-proven;
    single-sided from/to count queries broke a live sweep and are never sent.
    Per-zone directional totals ("Z>*", "*>Z") are DERIVED by row/column sums
    over the full matrix — complete because every ordered pair (intra-zone
    included) is swept — so the normalized key surface is unchanged and the
    from-total still reconciles against the unfiltered count in the sanity
    check. A row/column containing an unreadable cell derives a None total
    (unreadable, never a fabricated number).
    """
    interfaces_command = "show interface all"
    interfaces_output = ctx.run_ssh(interfaces_command)
    zones = _parse_or_fail(_parse_zones, interfaces_output, interfaces_command)
    raw = {interfaces_command: interfaces_output}
    excluded = [zone for zone in zones if not _SAFE_ZONE.match(zone)]
    if excluded:
        raw["zones_excluded"] = excluded
        zones = [zone for zone in zones if _SAFE_ZONE.match(zone)]
    raw["zones"] = zones
    if len(zones) < 2:
        raise SkipCheck("fewer than two zones — no zone pairs to sweep")
    if len(zones) * len(zones) > C.SESSION_MATRIX_MAX_PAIR_QUERIES:
        raise CollectError(
            "%d zones would need %d pair queries (cap %d) — this platform needs a "
            "scoped zone list before the matrix is usable"
            % (len(zones), len(zones) * len(zones), C.SESSION_MATRIX_MAX_PAIR_QUERIES)
        )

    total_queries = len(zones) * len(zones)
    if ctx.logger is not None:
        ctx.logger.info(
            "%s: session matrix — sweeping %d ordered zone pairs across %d zones "
            "with count-only queries; progress every %d queries.",
            ctx.device_name,
            total_queries,
            len(zones),
            _PROGRESS_EVERY,
        )
    sweep_started = time.monotonic()
    normalized = {}
    unparsed = []
    queries = 0
    parsed_ok = 0
    for a in zones:
        for b in zones:
            queries += 1
            command = "show session all filter count yes from %s to %s" % (a, b)
            output = ctx.run_ssh(command)
            _record_raw(raw, command, output)
            count = _parse_session_count(output)
            pair = "%s>%s" % (a, b)
            # None = unreadable (the capability differ's sentinel); a key
            # absent entirely means "not swept". Never conflate with zero.
            normalized[pair] = count
            if count is None:
                unparsed.append(pair)
                if ctx.logger is not None:
                    ctx.logger.warning(
                        "%s: session count for %s unparseable", ctx.device_name, pair
                    )
            else:
                parsed_ok += 1
            if queries >= _SWEEP_ABORT_AFTER and parsed_ok == 0:
                raise CollectError(
                    "first %d count responses all unreadable — aborting the sweep "
                    "(session or syntax problem; see the stored raw outputs)" % (queries,)
                )
            if (
                ctx.logger is not None
                and queries % _PROGRESS_EVERY == 0
                and queries < total_queries
            ):
                elapsed = time.monotonic() - sweep_started
                remaining = (elapsed / queries) * (total_queries - queries)
                ctx.logger.info(
                    "%s: session matrix %d/%d (%d%%) — %s elapsed, ~%s remaining.",
                    ctx.device_name,
                    queries,
                    total_queries,
                    100 * queries // total_queries,
                    _fmt_duration(elapsed),
                    _fmt_duration(remaining),
                )

    # Derived per-zone directional totals: the coverage layer.
    for zone in zones:
        row = [normalized["%s>%s" % (zone, b)] for b in zones]
        column = [normalized["%s>%s" % (a, zone)] for a in zones]
        normalized["%s>*" % (zone,)] = None if None in row else sum(row)
        normalized["*>%s" % (zone,)] = None if None in column else sum(column)

    raw["unparsed_pairs"] = unparsed
    if unparsed and len(unparsed) * 2 > queries:
        raise CollectError(
            "%d of %d session counts unparseable — sweep unusable" % (len(unparsed), queries)
        )
    _sanity_check_matrix(ctx, raw, normalized)
    # The reconciliation facts are the sweep's own proof of completeness —
    # promoted into the envelope (context) so the snapshot self-describes;
    # raw keeps them too as part of the audit trail.
    context_keys = (
        "matrix_total",
        "from_zone_total",
        "filterable_at_sweep",
        "session_info_at_sweep",
        "sanity_warning",
        "note_active_vs_filterable",
        "zones",
        "zones_excluded",
        "unparsed_pairs",
    )
    context = {key: raw[key] for key in context_keys if key in raw}
    return {"raw": raw, "normalized": normalized, "context": context}


_INFO_COUNTER_LEAVES = (
    ("active", "num-active"),
    ("tcp", "num-tcp"),
    ("udp", "num-udp"),
    ("icmp", "num-icmp"),
    ("predict", "num-predict"),
    ("mcast", "num-mcast"),
    ("bcast", "num-bcast"),
    ("installed", "num-installed"),
)


def _session_info_counters(cli_output):
    """Extended counters out of 'show session info', present ones only."""
    result = result_of(extract_xml(cli_output))
    if result is None:
        raise PanosParseError("no <result> in 'show session info' output")
    counters = {}
    for name, leaf in _INFO_COUNTER_LEAVES:
        value = to_int(text(result, leaf))
        if value is not None:
            counters[name] = value
    return counters


def _sanity_check_matrix(ctx, raw, normalized):
    """Reconcile the sweep — a silent-breakage tripwire. Best-effort, never fails.

    Two baselines, because they answer different questions:

    * ``show session all filter count yes`` (no other filter) is the SAME
      filter engine unfiltered — apples to apples. The matrix summing well
      below it means pairs are genuinely missing from the sweep (zones absent,
      multi-vsys scoping).
    * ``show session info`` num-active counts sessions the filter engine never
      enumerates (predict/ALG pinholes, multicast/broadcast, closing states),
      so a gap against it alone is normal on a busy box — recorded as an
      informational note, not a warning (field finding: 5.9k matrix vs 12.7k
      num-active with a complete matrix).
    """
    pair_total = sum(
        count for key, count in normalized.items() if "*" not in key and isinstance(count, int)
    )
    from_total = sum(
        count for key, count in normalized.items() if key.endswith(">*") and isinstance(count, int)
    )
    raw["matrix_total"] = pair_total
    raw["from_zone_total"] = from_total

    filterable = None
    try:
        command = "show session all filter count yes"
        output = ctx.run_ssh(command)
        raw[command] = output
        filterable = _parse_session_count(output)
    except Exception as exc:
        raw["filterable_at_sweep"] = "unavailable: %s" % (exc,)
    if filterable is not None:
        raw["filterable_at_sweep"] = filterable

    counters = {}
    try:
        info_output = ctx.run_ssh("show session info")
        counters = _session_info_counters(info_output)
        raw["session_info_at_sweep"] = counters
    except Exception as exc:
        raw["session_info_at_sweep"] = "unavailable: %s" % (exc,)
    active = counters.get("active")

    if isinstance(filterable, int) and filterable >= 100 and from_total * 5 < filterable * 4:
        # The from-totals cover EVERY discovered zone, so falling >20% below
        # the same engine's unfiltered count means discovery itself missed
        # traffic — not a pair-cap artifact.
        message = (
            "per-zone from-totals sum to %d but the unfiltered session count is %d — "
            "zone discovery missed traffic (zones absent from 'show interface all' "
            "parsing, zones_excluded, or multi-vsys scoping); treat the matrix as "
            "suspect" % (from_total, filterable)
        )
        raw["sanity_warning"] = message
        if ctx.logger is not None:
            ctx.logger.warning("%s: %s", ctx.device_name, message)
    elif (
        filterable is None
        and isinstance(active, int)
        and active >= 100
        and (from_total * 2 < active)
    ):
        # Fallback heuristic when the unfiltered count could not be read.
        message = (
            "per-zone from-totals sum to %d but the firewall reports %d active "
            "sessions (unfiltered filter-count unavailable) — possibly missing "
            "traffic; treat the matrix as suspect" % (from_total, active)
        )
        raw["sanity_warning"] = message
        if ctx.logger is not None:
            ctx.logger.warning("%s: %s", ctx.device_name, message)

    if isinstance(filterable, int) and isinstance(active, int) and active > filterable:
        gap = active - filterable
        if gap * 5 > active:
            raw["note_active_vs_filterable"] = (
                "num-active %d exceeds the filter engine's %d by %d — predict, "
                "multicast/broadcast, and closing-state sessions are counted by "
                "session info but not enumerable by filters; this gap is normal, "
                "not missing traffic" % (active, filterable, gap)
            )


# --- panos_session_meter -----------------------------------------------------


def _parse_session_meter(cli_output):
    """'show session meter' -> {"vsys<id>": current-session-count}.

    Per-vsys counts are the only view that reconciles global session counters
    with what any one scope can enumerate on a multi-vsys box (field finding:
    a "12k active vs 6k enumerable" mystery was a vsys split). Maximum/
    throttled stay in raw only.
    """
    result = result_of(extract_xml(cli_output))
    if result is None:
        raise PanosParseError("no <result> in 'show session meter' output")
    normalized = {}
    for entry in result.findall(".//entry"):
        vsys = text(entry, "vsys")
        current = to_int(text(entry, "current"))
        if vsys is None or current is None:
            continue
        key = vsys if vsys.lower().startswith("vsys") else "vsys%s" % (vsys,)
        normalized[key] = current
    return normalized


def _collect_session_meter(ctx):
    command = "show session meter"
    output = ctx.run_ssh(command)
    normalized = _parse_or_fail(_parse_session_meter, output, command)
    if not normalized:
        raise SkipCheck("no per-vsys meter entries (single-vsys platform or empty table)")
    return {"raw": {command: output}, "normalized": normalized}


# --- panos_routes ------------------------------------------------------------

_FLAG_PROTOCOLS = {"S": "static", "C": "connect", "B": "bgp", "R": "rip", "H": "host"}


def _protocol_from_flags(flags):
    """Protocol name from a route flags string ("A S", "A B", "A O2 E", ...).

    A (active) and * (preferred) are state, not protocol — stripped. Any O*
    token is OSPF regardless of area/external subtype. Modifiers such as E
    (ecmp) are skipped so the protocol letter beside them still wins.
    """
    for token in (flags or "").replace("*", " ").split():
        if token == "A":
            continue
        if token.startswith("O"):
            return "ospf"
        mapped = _FLAG_PROTOCOLS.get(token)
        if mapped:
            return mapped
    return "unknown"


def _parse_routes(cli_output):
    """Route output -> {"vr|destination": {protocol, next_hops, interface}}.

    ECMP shows as one entry per next hop; entries sharing vr|destination merge
    into one sorted next_hops list. Age and verbatim flags are never emitted —
    both churn on every capture without meaning anything.
    """
    result = result_of(extract_xml(cli_output))
    if result is None:
        raise PanosParseError("no <result> in route output")
    routes = {}
    hops = {}
    for entry in result.findall("entry"):
        destination = text(entry, "destination")
        if not destination:
            continue
        vr = text(entry, "virtual-router") or "default"
        key = "%s|%s" % (vr, destination)
        if key not in routes:
            routes[key] = {
                "protocol": _protocol_from_flags(text(entry, "flags")),
                "interface": text(entry, "interface"),
            }
            hops[key] = set()
        elif routes[key]["interface"] is None:
            routes[key]["interface"] = text(entry, "interface")
        nexthop = text(entry, "nexthop")
        if nexthop:
            hops[key].add(nexthop)
    for key, body in routes.items():
        body["next_hops"] = sorted(hops[key])
    return routes


def _collect_routes(ctx):
    # Legacy engine first; a parse failure or empty table falls through to the
    # advanced-routing engine. The detected engine is a pseudo-entry in the
    # normalized view, so an engine change across snapshots diffs — intended.
    legacy_command = "show routing route"
    legacy_output = ctx.run_ssh(legacy_command, timeout=C.SSH_BIG_READ_TIMEOUT)
    raw = {legacy_command: legacy_output}
    engine = "legacy"
    try:
        routes = _parse_routes(legacy_output)
    except PanosParseError:
        routes = {}
    if not routes:
        advanced_command = "show advanced-routing route"
        advanced_output = ctx.run_ssh(advanced_command, timeout=C.SSH_BIG_READ_TIMEOUT)
        raw[advanced_command] = advanced_output
        engine = "advanced"
        routes = _parse_or_fail(_parse_routes, advanced_output, advanced_command)
        if not routes:
            # A firewall always carries at least its connected routes; zero
            # from both engines is a failed read, not an empty table.
            raise CollectError("zero routes from both routing engines")
    normalized = dict(routes)
    normalized["engine|detected"] = {"value": engine}
    return {"raw": raw, "normalized": normalized}


# --- panos_interfaces --------------------------------------------------------


def _parse_interfaces(cli_output):
    """'show interface all' -> (normalized "zone|ip" view, {"zone|ip": ifname}).

    The interface name is deliberately excluded from normalized values — the
    VM-series vNIC naming differs from hardware — so identity is the zone/IP
    binding and the name lives in the returned mapping (stored in raw).
    """
    result = result_of(extract_xml(cli_output))
    if result is None:
        raise PanosParseError("no <result> in 'show interface all' output")
    hw_state = {}
    hw_mtu = {}
    for entry in result.findall("hw/entry"):
        name = text(entry, "name")
        if not name:
            continue
        hw_state[name] = text(entry, "state") or "unknown"
        mtu = to_int(text(entry, "mtu"))
        if mtu is not None:
            hw_mtu[name] = mtu
    normalized = {}
    name_map = {}
    for entry in result.findall("ifnet/entry"):
        ip = text(entry, "ip")
        if not ip or ip.upper() == "N/A":
            continue
        name = text(entry, "name") or "unknown"
        zone = text(entry, "zone") or "none"
        fwd = text(entry, "fwd")
        vr = fwd[len("vr:") :] if fwd and fwd.startswith("vr:") else fwd
        key = "%s|%s" % (zone, ip)
        body = {"vr": vr, "state": hw_state.get(name, "unknown")}
        if name in hw_mtu:
            body["mtu"] = hw_mtu[name]
        normalized[key] = body
        name_map[key] = name
    return normalized, name_map


def _collect_interfaces(ctx):
    command = "show interface all"
    output = ctx.run_ssh(command)
    normalized, name_map = _parse_or_fail(_parse_interfaces, output, command)
    return {"raw": {command: output, "interface_names": name_map}, "normalized": normalized}


# --- panos_arp ---------------------------------------------------------------


def _normalize_arp(cli_output):
    """'show arp all' -> {ip: {"status": ...}}. MAC/interface/ttl raw only."""
    result = result_of(extract_xml(cli_output))
    if result is None:
        raise PanosParseError("no <result> in 'show arp all' output")
    normalized = {}
    for entry in result.findall("entries/entry"):
        ip = text(entry, "ip")
        if not ip:
            continue
        normalized[ip] = {"status": text(entry, "status") or "unknown"}
    return normalized


def _collect_arp(ctx):
    command = "show arp all"
    output = ctx.run_ssh(command)
    normalized = _parse_or_fail(_normalize_arp, output, command)
    return {"raw": {command: output}, "normalized": normalized}


# --- panos_ipsec -------------------------------------------------------------


def _parse_sa_names(cli_output):
    """SA entry names from 'show vpn ike-sa' / 'show vpn ipsec-sa' output.

    The two commands nest entries differently across releases (<result><entry>
    vs <result><entries><entry>); both locations are read. Duplicate names
    (rekeys in flight) collapse when keyed into the normalized view.
    """
    result = result_of(extract_xml(cli_output))
    if result is None:
        raise PanosParseError("no <result> in VPN SA output")
    names = []
    for entry in result.findall("entry") + result.findall("entries/entry"):
        name = text(entry, "name")
        if name:
            names.append(name)
    return names


def _collect_ipsec(ctx):
    ike_command = "show vpn ike-sa"
    ipsec_command = "show vpn ipsec-sa"
    ike_output = ctx.run_ssh(ike_command)
    ipsec_output = ctx.run_ssh(ipsec_command)
    if _cli_rejected(ike_output) and _cli_rejected(ipsec_output):
        raise SkipCheck("VPN show commands rejected on this release — verify via shakedown")
    # Presence enumerations: a box with no SAs answers with no XML payload at
    # all (field finding on a tunnel-less firewall) — that IS the answer,
    # zero, never a failed read. Raw keeps the verbatim reply for audit.
    try:
        ike_names = _parse_sa_names(ike_output)
    except PanosParseError:
        ike_names = []
    try:
        ipsec_names = _parse_sa_names(ipsec_output)
    except PanosParseError:
        ipsec_names = []
    if not ike_names and not ipsec_names:
        raise SkipCheck("no IKE/IPsec SAs present (IPsec unused, or all tunnels down)")
    # Presence of the SA is the up signal; SPIs and lifetimes never emitted.
    normalized = {}
    for name in ike_names:
        normalized["ike|%s" % (name,)] = {"up": True}
    for name in ipsec_names:
        normalized["tunnel|%s" % (name,)] = {"up": True}
    return {
        "raw": {ike_command: ike_output, ipsec_command: ipsec_output},
        "normalized": normalized,
    }


# --- panos_licenses ----------------------------------------------------------


def _normalize_licenses(cli_output):
    """'request license info' -> {feature: {"expired": yes/no}}.

    expires/serial/authcode stay in raw only — the serial WILL differ across
    the hardware-to-VM replacement, by design.
    """
    result = result_of(extract_xml(cli_output))
    if result is None:
        raise PanosParseError("no <result> in 'request license info' output")
    normalized = {}
    for entry in result.findall("licenses/entry"):
        feature = text(entry, "feature")
        if not feature:
            continue
        normalized[feature] = {"expired": text(entry, "expired") or "unknown"}
    return normalized


def _collect_licenses(ctx):
    command = "request license info"  # exact string allowlisted; display-only despite the verb
    output = ctx.run_ssh(command)
    normalized = _parse_or_fail(_normalize_licenses, output, command)
    return {"raw": {command: output}, "normalized": normalized}


# --- panos_resources ---------------------------------------------------------


def _collect_resources(ctx):
    command = "show running resource-monitor minute last 1"
    output = ctx.run_ssh(command)
    return {"raw": {command: output}, "normalized": {}}


# --- registrations -----------------------------------------------------------

register(
    CheckDef(
        id="panos_system_info",
        platform="panos",
        description="Software/content versions, model, serial, and hostname",
        tier=3,
        compare={"mode": "equality_scalar"},
        miss_meaning=(
            "Software or content versions differ — content on the VM-500 must be >= the "
            "5250's or App-ID/Threat behavior silently changes. Model/serial changes are "
            "declared expectations."
        ),
        collector=_collect_system_info,
        tags=("system",),
    )
)

register(
    CheckDef(
        id="panos_ha",
        platform="panos",
        description="HA enablement, local/peer state, and running-config sync",
        tier=1,
        compare={"mode": "equality_scalar"},
        miss_meaning=(
            "HA topology changed — expect one active + one passive with running config "
            "synchronized."
        ),
        collector=_collect_ha,
        tags=("ha",),
    )
)

register(
    CheckDef(
        id="panos_session_info",
        platform="panos",
        description="Global session counts within tolerance of the baseline",
        tier=1,
        compare={"mode": "tolerance", "band": {"pct": C.SESSION_TOLERANCE_PCT}},
        miss_meaning=(
            "Session counts did not recover toward pre-change levels — traffic is not "
            "flowing at expected volume."
        ),
        collector=_collect_session_info,
        tags=("sessions",),
    )
)

register(
    CheckDef(
        id="panos_session_meter",
        platform="panos",
        description="Per-vsys session counts within tolerance of the baseline",
        tier=1,
        compare={"mode": "tolerance", "band": {"pct": C.SESSION_TOLERANCE_PCT}},
        miss_meaning=(
            "A vsys's session count did not recover — that vsys's traffic domain is not "
            "flowing (on multi-vsys, each vsys is its own traffic domain and global "
            "counters hide which one broke)."
        ),
        collector=_collect_session_meter,
        tags=("sessions",),
    )
)

register(
    CheckDef(
        id="panos_session_matrix",
        platform="panos",
        description="Per zone-pair session capability sweep",
        tier=1,
        compare={
            "mode": "capability",
            "floor_pre": C.CAPABILITY_FLOOR_PRE,
            "min_post": C.CAPABILITY_MIN_POST,
        },
        miss_meaning=(
            "A zone pair that carried real traffic pre-change has zero sessions now — the "
            "firewall is not establishing new flows on that path."
        ),
        collector=_collect_session_matrix,
        tags=("sessions",),
    )
)

register(
    CheckDef(
        id="panos_routes",
        platform="panos",
        description="Route table keyed by VR|destination, routing engine detected",
        tier=1,
        compare={"mode": "equality_set"},
        miss_meaning=(
            "The firewall's own routes changed — its default route and connected/static set "
            "are the contract this device offers and should be identical pre/post."
        ),
        collector=_collect_routes,
        tags=("routing",),
    )
)

register(
    CheckDef(
        id="panos_interfaces",
        platform="panos",
        description="L3 zone/IP/virtual-router bindings and link state",
        tier=1,
        compare={"mode": "equality_set"},
        miss_meaning=(
            "A zone/IP/virtual-router binding is missing or down on the VM-500 — an "
            "interface did not come up where the network expects it."
        ),
        collector=_collect_interfaces,
        tags=("interfaces",),
    )
)

register(
    CheckDef(
        id="panos_arp",
        platform="panos",
        description="ARP resolution status per IP",
        tier=2,
        compare={"mode": "equality_set"},
        miss_meaning=(
            "An L3 adjacency did not resolve from the firewall side — the next hop toward "
            "the core or upstream is not answering."
        ),
        collector=_collect_arp,
        tags=("interfaces",),
    )
)

register(
    CheckDef(
        id="panos_ipsec",
        platform="panos",
        description="IKE and IPsec SA presence per gateway/tunnel",
        tier=1,
        compare={"mode": "equality_set"},
        miss_meaning="A B2B tunnel did not re-establish on the VM-500.",
        collector=_collect_ipsec,
        tags=("vpn",),
    )
)

register(
    CheckDef(
        id="panos_licenses",
        platform="panos",
        description="Licensed features and their expiry flags",
        tier=3,
        compare={"mode": "equality_set"},
        miss_meaning=(
            "A licensed feature is missing or expired on the VM-500 — Threat/URL/WildFire "
            "enforcement may silently differ."
        ),
        collector=_collect_licenses,
        tags=("licensing",),
    )
)

register(
    CheckDef(
        id="panos_resources",
        platform="panos",
        description="Resource-monitor snapshot, stored verbatim (informational)",
        tier=3,
        compare={"mode": "info_only"},
        miss_meaning="",
        collector=_collect_resources,
        tags=("system",),
    )
)


# --- always-on optional-feature checks ---------------------------------------
# Doctrine: always ask, even for features this network may not use — a
# "not-present" record is information, not noise. Defensively parsed: a
# command rejected on some release records as not-present with the reason,
# never as garbage (command forms below are shakedown-pending on real 11.2).


def _cli_rejected(cli_output):
    """True when the CLI refused the command (error response or rejection text)."""
    try:
        root = extract_xml(cli_output)
        if root.tag == "response" and root.get("status") == "error":
            return True
    except PanosParseError:
        pass
    lowered = (cli_output or "").lower()
    return "invalid syntax" in lowered or "unknown command" in lowered


def _collect_bgp_peers(ctx):
    raw = {}
    for command in ("show routing protocol bgp summary", "show advanced-routing bgp summary"):
        output = ctx.run_ssh(command)
        _record_raw(raw, command, output)
        if _cli_rejected(output):
            continue
        try:
            result = result_of(extract_xml(output))
        except PanosParseError:
            continue
        normalized = {}
        for entry in result.findall(".//entry") if result is not None else []:
            peer = entry.get("name") or text(entry, "peer-address") or text(entry, "peer")
            if not peer:
                continue
            normalized["peer|%s" % (peer,)] = {
                "state": text(entry, "state") or text(entry, "status") or "unknown"
            }
        if normalized:
            return {"raw": raw, "normalized": normalized}
    raise SkipCheck("BGP not running (or summary form unsupported — verify via shakedown)")


def _collect_globalprotect(ctx):
    command = "show global-protect-gateway statistics"
    output = ctx.run_ssh(command)
    raw = {}
    _record_raw(raw, command, output)
    if _cli_rejected(output):
        raise SkipCheck("GlobalProtect not licensed/configured on this device")
    try:
        result = result_of(extract_xml(output))
    except PanosParseError as exc:
        raise CollectError("show global-protect-gateway statistics: %s" % (exc,)) from exc
    current = None
    if result is not None:
        current = to_int(text(result, "TotalCurrentUsers"))
        if current is None:
            current = to_int(text(result, "total-current-users"))
    if current is None:
        raise SkipCheck("GlobalProtect statistics empty — not in use")
    return {"raw": raw, "normalized": {"current_users": current}}


def _collect_dhcp(ctx):
    command = "show dhcp server lease all"
    output = ctx.run_ssh(command)
    raw = {}
    _record_raw(raw, command, output)
    if _cli_rejected(output):
        raise SkipCheck("DHCP server not in use (or lease form unsupported — verify via shakedown)")
    try:
        result = result_of(extract_xml(output))
    except PanosParseError:
        result = None
    entries = result.findall(".//entry") if result is not None else []
    context = {"lease_count": len(entries)}
    interfaces = sorted({text(entry, "interface") for entry in entries} - {None})
    if interfaces:
        context["interfaces"] = interfaces
    return {"raw": raw, "normalized": {}, "context": context}


register(
    CheckDef(
        id="panos_bgp_peers",
        platform="panos",
        description="BGP peer states (engine-aware; not-present when BGP is unused)",
        tier=1,
        compare={"mode": "equality_set"},
        miss_meaning=(
            "A BGP peer on the firewall changed state — routing exchange with that "
            "neighbor is impaired."
        ),
        collector=_collect_bgp_peers,
        tags=("routing",),
    )
)

register(
    CheckDef(
        id="panos_globalprotect",
        platform="panos",
        description="GlobalProtect gateway user count (not-present when GP is unused)",
        tier=3,
        compare={"mode": "info_only"},
        miss_meaning="",
        collector=_collect_globalprotect,
        tags=("vpn",),
    )
)

register(
    CheckDef(
        id="panos_dhcp",
        platform="panos",
        description="DHCP server lease overview (not-present when DHCP is unused)",
        tier=3,
        compare={"mode": "info_only"},
        miss_meaning="",
        collector=_collect_dhcp,
        tags=("services",),
    )
)


# --- day-0 hygiene checks (shakedown-pending shapes) --------------------------
# Telemetry, cloud connectivity, time sync, and commit hygiene. Output shapes
# below are UNVERIFIED on real 11.2 — raw is captured faithfully (capped) and
# normalization is best-effort; the shakedown advisory ("parsed but empty")
# drives refinement against real output. Collect first, normalize later.


def _collect_logging_status(ctx):
    """'show logging-status' captured raw; destination entries counted best-effort.

    A SIEM ingestion gap found weeks later is the classic day-2 failure of a
    firewall replacement — this check exists to catch it on day 0.
    """
    command = "show logging-status"
    output = ctx.run_ssh(command)
    raw = {}
    _record_raw(raw, command, output)
    if _cli_rejected(output):
        raise SkipCheck("command rejected on this release — verify via shakedown")
    context = {}
    try:
        root = extract_xml(output)
    except PanosParseError:
        root = None
    if root is not None:
        context["destination_entries"] = len(root.findall(".//entry"))
    return {"raw": raw, "normalized": {}, "context": context}


def _collect_url_cloud(ctx):
    """'show url-cloud status' -> connected / not-connected, from a text scan.

    The negative phrasings must be tested FIRST: "not connected" and
    "disconnected" both contain the substring "connected".
    """
    command = "show url-cloud status"
    output = ctx.run_ssh(command)
    raw = {}
    _record_raw(raw, command, output)
    if _cli_rejected(output):
        raise SkipCheck("URL filtering unlicensed (command rejected) — verify via shakedown")
    lowered = (output or "").lower()
    if "not connected" in lowered or "disconnected" in lowered:
        normalized = {"cloud": {"value": "not-connected"}}
    elif "connected" in lowered:
        normalized = {"cloud": {"value": "connected"}}
    else:
        normalized = {}
    return {"raw": raw, "normalized": normalized}


def _collect_ntp(ctx):
    """'show ntp' -> the synched leaf when one is found; raw kept regardless.

    Releases spell the leaf differently ('synched', 'sync', or nested under a
    server block) — each spelling is tried; none found leaves normalized empty.
    """
    command = "show ntp"
    output = ctx.run_ssh(command)
    raw = {}
    _record_raw(raw, command, output)
    if _cli_rejected(output):
        raise SkipCheck("command rejected on this release — verify via shakedown")
    try:
        result = result_of(extract_xml(output))
    except PanosParseError:
        result = None
    synched = None
    if result is not None:
        for path in ("synched", "sync", ".//synched"):
            synched = text(result, path)
            if synched is not None:
                break
    normalized = {"synched": {"value": synched}} if synched is not None else {}
    return {"raw": raw, "normalized": normalized}


# Word-anchored so "no" never matches inside "nothing"/"not"; yes wins when
# both words appear ("yes (no pending commit locks)").
_PENDING_YES = re.compile(r"\byes\b", re.IGNORECASE)
_PENDING_NO = re.compile(r"\bno\b", re.IGNORECASE)


def _collect_pending_changes(ctx):
    """'check pending-changes' -> {"pending": "yes"/"no"} from a yes/no reply.

    The reply is boolean-ish across shapes (XML <result>yes</result> or plain
    text); the word is searched in the result's text when XML parses, else in
    the raw output. Neither word found -> normalized {} with raw kept.
    """
    command = "check pending-changes"  # exact string allowlisted; pure status display
    output = ctx.run_ssh(command)
    raw = {}
    _record_raw(raw, command, output)
    if _cli_rejected(output):
        raise SkipCheck("command rejected on this release — verify via shakedown")
    blob = output or ""
    try:
        result = result_of(extract_xml(output))
    except PanosParseError:
        result = None
    if result is not None:
        blob = "".join(result.itertext())
    if _PENDING_YES.search(blob):
        normalized = {"pending": "yes"}
    elif _PENDING_NO.search(blob):
        normalized = {"pending": "no"}
    else:
        normalized = {}
    return {"raw": raw, "normalized": normalized}


register(
    CheckDef(
        id="panos_logging_status",
        platform="panos",
        description="Log forwarding status — is telemetry actually flowing",
        tier=3,
        compare={"mode": "info_only"},
        miss_meaning="",
        collector=_collect_logging_status,
        tags=("logging",),
    )
)

register(
    CheckDef(
        id="panos_url_cloud",
        platform="panos",
        description="URL-filtering cloud connectivity",
        tier=3,
        compare={"mode": "info_only"},
        miss_meaning="",
        collector=_collect_url_cloud,
        tags=("services",),
    )
)

register(
    CheckDef(
        id="panos_ntp",
        platform="panos",
        description="NTP synchronization state",
        tier=3,
        compare={"mode": "info_only"},
        miss_meaning="",
        collector=_collect_ntp,
        tags=("system",),
    )
)

register(
    CheckDef(
        id="panos_pending_changes",
        platform="panos",
        description="Uncommitted candidate-config changes present",
        tier=1,
        compare={"mode": "equality_scalar"},
        miss_meaning=(
            "Uncommitted changes at capture time — config-derived state may not reflect "
            "what is actually running (or someone left work half-finished on the box)."
        ),
        collector=_collect_pending_changes,
        tags=("system",),
    )
)


# --- approved Tier-B checks (shakedown-pending shapes) ------------------------
# PBF, drop counters, NAT pools, rule hit counts — approved for always-on
# capture. Command forms flagged unverified since the original research; every
# collector is defensive (rejected -> not-present with reason) and raw-first,
# with normalization refined against real 11.2 output via the shakedown loop.


def _collect_pbf(ctx):
    command = "show pbf rule all"
    output = ctx.run_ssh(command)
    raw = {}
    _record_raw(raw, command, output)
    if _cli_rejected(output):
        raise SkipCheck("PBF command rejected on this release — verify via shakedown")
    try:
        result = result_of(extract_xml(output))
    except PanosParseError:
        result = None
    normalized = {}
    for entry in result.findall(".//entry") if result is not None else []:
        name = entry.get("name") or text(entry, "name") or text(entry, "rule-name")
        if not name:
            continue
        value = {}
        action = text(entry, "action")
        if action is not None:
            value["action"] = action
        egress = text(entry, "egress-if") or text(entry, "interface")
        if egress is not None:
            value["egress"] = egress
        normalized["pbf|%s" % (name,)] = value
    if not normalized:
        # Presence enumeration: empty or non-XML reply IS the answer.
        raise SkipCheck("no PBF rules configured")
    return {"raw": raw, "normalized": normalized}


def _collect_drop_counters(ctx):
    command = "show counter global filter severity drop"
    output = ctx.run_ssh(command, timeout=C.SSH_BIG_READ_TIMEOUT)
    raw = {}
    _record_raw(raw, command, output)
    if _cli_rejected(output):
        raise SkipCheck("drop-counter command rejected on this release — verify via shakedown")
    try:
        result = result_of(extract_xml(output))
    except PanosParseError:
        result = None
    counters = {}
    for entry in result.findall(".//entry") if result is not None else []:
        name = text(entry, "name") or entry.get("name")
        value = to_int(text(entry, "value"))
        if name and value is not None:
            counters[name] = value
    # Values are cumulative-since-boot — informational by design (a fresh VM's
    # counts are since ITS boot). The analyst reads novelty: drop counters that
    # exist post but not pre, or wildly different profiles.
    top = sorted(counters.items(), key=lambda item: -item[1])[:40]
    normalized = {name: {"value": value} for name, value in top}
    context = {"counter_count": len(counters)}
    return {"raw": raw, "normalized": normalized, "context": context}


def _collect_nat_pools(ctx):
    commands = ("show running ippool", "show running global-ippool")
    raw = {}
    rejected = 0
    entry_counts = {}
    for command in commands:
        output = ctx.run_ssh(command)
        _record_raw(raw, command, output)
        if _cli_rejected(output):
            rejected += 1
            continue
        try:
            result = result_of(extract_xml(output))
        except PanosParseError:
            result = None
        entry_counts[command] = len(result.findall(".//entry")) if result is not None else 0
    if rejected == len(commands):
        raise SkipCheck("NAT pool commands rejected on this release — verify via shakedown")
    # Raw-first by design: the pool tables' shape is unverified; utilization
    # is load-dependent (exhaustion appears under load, not at 2 a.m.), so
    # the verbatim tables plus entry counts are the v1 deliverable.
    return {"raw": raw, "normalized": {}, "context": {"entries": entry_counts}}


def _collect_rule_hit_counts(ctx):
    # Field-verified on 11.2: the rule-hit-count tree takes a literal
    # `vsys-name` keyword before the value; the rule-use fallback does not.
    forms = (
        "show rule-hit-count vsys vsys-name vsys1 rule-base %s rules all",
        "show running rule-use hit-count vsys vsys1 rule-base %s rules all",
    )
    raw = {}
    normalized = {}
    accepted_form = None
    for rulebase in ("security", "nat"):
        for form in forms:
            if accepted_form is not None and form != accepted_form:
                continue
            command = form % (rulebase,)
            output = ctx.run_ssh(command, timeout=C.SSH_BIG_READ_TIMEOUT)
            _record_raw(raw, command, output)
            if _cli_rejected(output):
                continue
            accepted_form = form
            try:
                result = result_of(extract_xml(output))
            except PanosParseError:
                result = None
            for entry in result.findall(".//entry") if result is not None else []:
                name = entry.get("name") or text(entry, "rule-name") or text(entry, "name")
                if not name:
                    continue
                value = {}
                hits = to_int(text(entry, "hit-count") or text(entry, "rule-hit-count"))
                if hits is not None:
                    value["hit_count"] = hits
                last_hit = text(entry, "last-hit-timestamp") or text(entry, "last-hit")
                if last_hit is not None:
                    value["last_hit"] = last_hit
                normalized["%s|%s" % (rulebase, name)] = value
            break
    if accepted_form is None:
        raise SkipCheck(
            "rule-hit-count forms rejected on this release — awaiting field-verified syntax"
        )
    return {"raw": raw, "normalized": normalized}


register(
    CheckDef(
        id="panos_pbf",
        platform="panos",
        description="Policy-based forwarding rules (not-present when PBF is unused)",
        tier=1,
        compare={"mode": "equality_set"},
        miss_meaning=(
            "A policy-based forwarding rule changed — PBF steers traffic around the "
            "routing tables the other checks diff, so changes here are invisible "
            "everywhere else."
        ),
        collector=_collect_pbf,
        tags=("routing",),
    )
)

register(
    CheckDef(
        id="panos_drop_counters",
        platform="panos",
        description="Global drop-counter profile (informational canary)",
        tier=3,
        compare={"mode": "info_only"},
        miss_meaning="",
        collector=_collect_drop_counters,
        tags=("sessions",),
    )
)

register(
    CheckDef(
        id="panos_nat_pools",
        platform="panos",
        description="NAT pool tables, raw-first (utilization is load-dependent)",
        tier=3,
        compare={"mode": "info_only"},
        miss_meaning="",
        collector=_collect_nat_pools,
        tags=("services",),
    )
)

register(
    CheckDef(
        id="panos_rule_hit_counts",
        platform="panos",
        description="Security/NAT rule names with hit counts and last-hit times",
        tier=2,
        compare={"mode": "info_only"},
        miss_meaning=(
            "A rule vanished from the rulebase, or a previously-active rule stopped "
            "hitting — the single biggest replacement risk is a mistranslated rulebase."
        ),
        collector=_collect_rule_hit_counts,
        tags=("policy",),
    )
)


# --- panos_ospf_neighbors + panos_crash_files (approved TAC-lens additions) ---


def _collect_ospf_neighbors(ctx):
    """OSPF adjacencies, engine-aware — the firewalls DO run OSPF with the core
    (operator-confirmed), so this is the firewall's own view of the adjacency
    the 9500-side check sees from the other end."""
    raw = {}
    for command in (
        "show routing protocol ospf neighbor",
        "show advanced-routing ospf neighbor",
    ):
        output = ctx.run_ssh(command)
        _record_raw(raw, command, output)
        if _cli_rejected(output):
            continue
        try:
            result = result_of(extract_xml(output))
        except PanosParseError:
            continue
        normalized = {}
        for entry in result.findall(".//entry") if result is not None else []:
            neighbor = (
                entry.get("name")
                or text(entry, "neighbor-router-id")
                or text(entry, "neighbor-id")
                or text(entry, "neighbor-address")
            )
            if not neighbor:
                continue
            value = {}
            state = text(entry, "status") or text(entry, "state") or text(entry, "nbr-state")
            if state is not None:
                value["state"] = state
            address = text(entry, "neighbor-address") or text(entry, "address")
            if address is not None:
                value["address"] = address
            normalized["ospf|%s" % (neighbor,)] = value
        if normalized:
            return {"raw": raw, "normalized": normalized}
    raise SkipCheck("no OSPF neighbors reported (OSPF unused, or forms need shakedown)")


# ls-style listing: "-rw-r--r-- 1 root root 12345 Aug 24 18:22 core.pan_task"
# (time form = within ~6 months) or "... Aug 24 2025 core.old" (year form).
_LS_LINE = re.compile(
    r"^\S{10,}\s+\d+\s+\S+\s+\S+\s+\d+\s+([A-Z][a-z]{2})\s+(\d+)\s+([\d:]{4,5}|\d{4})\s+(\S+)\s*$"
)
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


def _parse_core_files(cli_output, now, recent_days):
    """(recent {name: {modified}}, older_count) from a `show system files` listing.

    ls semantics: a time in the last column means the file is under ~6 months
    old (year inferred: this year, or last year when the date lies ahead of
    now); an explicit year means older. Only window-recent files become
    normalized keys (a fresh core must ADD a key; ancient dumps must never
    alarm — operator requirement). Unparseable months fail safe as recent.
    """
    recent = {}
    older = 0
    for line in (cli_output or "").splitlines():
        match = _LS_LINE.match(line.strip())
        if not match:
            continue
        month, day, time_or_year, name = match.groups()
        month_num = _MONTHS.get(month)
        if month_num is None:
            recent[name] = {"modified": "%s %s %s" % (month, day, time_or_year)}
            continue
        if ":" in time_or_year:
            year = now.year
            modified = datetime(year, month_num, int(day), tzinfo=timezone.utc)
            if modified > now:
                modified = datetime(year - 1, month_num, int(day), tzinfo=timezone.utc)
        else:
            modified = datetime(int(time_or_year), month_num, int(day), tzinfo=timezone.utc)
        if (now - modified).days <= recent_days:
            recent[name] = {"modified": modified.strftime("%Y-%m-%d")}
        else:
            older += 1
    return recent, older


def _collect_crash_files(ctx, now=None):
    if now is None:
        now = datetime.now(timezone.utc)
    command = "show system files"
    output = ctx.run_ssh(command)
    raw = {}
    _record_raw(raw, command, output)
    if _cli_rejected(output):
        raise SkipCheck("show system files rejected on this release — verify via shakedown")
    recent, older = _parse_core_files(output, now, C.CRASH_RECENT_DAYS)
    normalized = {name: value for name, value in recent.items()}
    return {
        "raw": raw,
        "normalized": normalized,
        "context": {"older_files_ignored": older, "recent_window_days": C.CRASH_RECENT_DAYS},
    }


register(
    CheckDef(
        id="panos_ospf_neighbors",
        platform="panos",
        description="OSPF adjacencies, engine-aware (the firewall's view of the core)",
        tier=1,
        compare={"mode": "equality_set"},
        miss_meaning=(
            "An OSPF adjacency on the firewall changed — the routing exchange with the "
            "core that carries the changing prefixes is impaired from the firewall's "
            "side."
        ),
        collector=_collect_ospf_neighbors,
        tags=("routing",),
    )
)

register(
    CheckDef(
        id="panos_crash_files",
        platform="panos",
        description="Core/crash files within the recency window",
        tier=1,
        compare={"mode": "equality_set"},
        miss_meaning=(
            "A core file appeared during the window — a dataplane or management "
            "process crashed even if it recovered before anyone looked."
        ),
        collector=_collect_crash_files,
        tags=("platform",),
    )
)
