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


def _parse_session_count(cli_output):
    """Count out of a 'show session all ... count yes' response, or None.

    Tries the XML shapes first (a count-like element, then bare result text),
    then the classic text line "Number of sessions that match filter: N".

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
        for path in ("count", "member/count", "member"):
            value = to_int(text(result, path))
            if value is not None:
                return value
        if result.text and result.text.strip():
            value = to_int(result.text)
            if value is not None:
                return value
        text_blob = "".join(result.itertext())
        if _NO_SESSIONS.search(text_blob):
            return 0
        if len(result) == 0 and not text_blob.strip():
            return 0
    for line in (cli_output or "").splitlines():
        lowered = line.lower()
        if "match" in lowered and "filter" in lowered:
            value = to_int(line)
            if value is not None:
                return value
        if _NO_SESSIONS.search(line):
            return 0
    return None


def _collect_session_matrix(ctx):
    interfaces_command = "show interface all"
    interfaces_output = ctx.run_ssh(interfaces_command)
    zones = _parse_or_fail(_parse_zones, interfaces_output, interfaces_command)
    raw = {interfaces_command: interfaces_output}
    excluded = [zone for zone in zones if not _SAFE_ZONE.match(zone)]
    if excluded:
        raw["zones_excluded"] = excluded
        zones = [zone for zone in zones if _SAFE_ZONE.match(zone)]
    if len(zones) > C.SESSION_MATRIX_MAX_ZONES:
        raw["zones_truncated"] = {"zone_count": len(zones), "used": C.SESSION_MATRIX_MAX_ZONES}
        zones = zones[: C.SESSION_MATRIX_MAX_ZONES]
    raw["zones"] = zones
    if len(zones) < 2:
        raise SkipCheck("fewer than two zones — no zone pairs to sweep")
    normalized = {}
    unparsed = []
    total = 0
    # Every ORDERED pair including intra-zone (a>a): sessions between
    # interfaces in the same zone are real traffic, and without them the
    # matrix total could never reconcile with `show session info`.
    # Filter keywords verified against the PA KB: `from <zone>` / `to <zone>`
    # with `count yes` — NOT `from-zone`/`to-zone`, which the CLI rejects for
    # every pair (found in the field: 12k active sessions, zero parsed pairs).
    for a in zones:
        for b in zones:
            total += 1
            command = "show session all filter count yes from %s to %s" % (a, b)
            output = ctx.run_ssh(command)
            raw[command] = output
            count = _parse_session_count(output)
            pair = "%s>%s" % (a, b)
            # An unparseable count goes into the normalized view as None — the
            # capability differ treats it as "unreadable", never as zero. Only
            # keys absent entirely mean "not swept" (zone-set mismatch).
            normalized[pair] = count
            if count is None:
                unparsed.append(pair)
                if ctx.logger is not None:
                    ctx.logger.warning(
                        "%s: session count for zone pair %s unparseable",
                        ctx.device_name,
                        pair,
                    )
    raw["unparsed_pairs"] = unparsed
    if unparsed and len(unparsed) * 2 > total:
        raise CollectError(
            "%d of %d zone-pair counts unparseable — sweep unusable" % (len(unparsed), total)
        )
    _sanity_check_matrix(ctx, raw, normalized)
    return {"raw": raw, "normalized": normalized}


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
    matrix_total = sum(count for count in normalized.values() if isinstance(count, int))
    raw["matrix_total"] = matrix_total

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

    if isinstance(filterable, int) and filterable >= 100 and matrix_total * 5 < filterable * 4:
        # >20% below the same engine's unfiltered count: pairs are missing.
        message = (
            "session matrix totals %d but the unfiltered session count is %d — the "
            "sweep is missing traffic (zones absent from the sweep, or multi-vsys "
            "scoping); check raw zones/zones_excluded; treat the matrix as suspect"
            % (matrix_total, filterable)
        )
        raw["sanity_warning"] = message
        if ctx.logger is not None:
            ctx.logger.warning("%s: %s", ctx.device_name, message)
    elif (
        filterable is None
        and isinstance(active, int)
        and active >= 100
        and (matrix_total * 2 < active)
    ):
        # Fallback heuristic when the unfiltered count could not be read.
        message = (
            "session matrix totals %d but the firewall reports %d active sessions "
            "(unfiltered filter-count unavailable) — possibly missing traffic; "
            "treat the matrix as suspect" % (matrix_total, active)
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
    ike_names = _parse_or_fail(_parse_sa_names, ike_output, ike_command)
    ipsec_names = _parse_or_fail(_parse_sa_names, ipsec_output, ipsec_command)
    if not ike_names and not ipsec_names:
        raise SkipCheck("no IPsec configured")
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
