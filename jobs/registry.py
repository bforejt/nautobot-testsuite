"""Check registry and test packages. Pure: stdlib only, no Nautobot.

A check is a small declarative unit (ANTA-style): identity, platform, tier,
compare config, a one-line *miss interpretation* rendered next to failures,
and a collector callable. Collectors receive a CollectorContext (built by the
capture job) and return ``{"raw": <any>, "normalized": <dict>}``; they raise
SkipCheck when the feature legitimately is not present, and CollectError when
a required read failed — a failed read is never treated as emptiness.

Selection is data, not code: PACKAGES maps a package name to check ids; the
capture job filters the chosen package to the device's platform at run time.
"""

from dataclasses import dataclass, field


class CollectError(Exception):
    """A required read failed; the check is recorded as failed."""


class SkipCheck(Exception):
    """The feature is not present/configured; recorded as not-present, loudly."""


@dataclass(frozen=True)
class CheckDef:
    id: str
    platform: str  # "iosxe" | "panos"
    description: str
    tier: int  # 1 keyed assertions, 2 full-table diffs, 3 context
    compare: dict
    miss_meaning: str
    collector: object = None  # callable(ctx) -> {"raw": ..., "normalized": ...}
    tags: tuple = field(default_factory=tuple)


CHECKS = {}


def register(check):
    """Register a CheckDef; importable as a decorator target via functools.partial."""
    if check.id in CHECKS:
        raise ValueError("duplicate check id: %s" % (check.id,))
    CHECKS[check.id] = check
    return check


def checks_for(platform, check_ids=None):
    """Resolve check ids (or all registered) to CheckDefs for one platform."""
    if check_ids is None:
        wanted = sorted(CHECKS)
    else:
        wanted = list(check_ids)
    resolved = []
    for check_id in wanted:
        check = CHECKS.get(check_id)
        if check is not None and check.platform == platform:
            resolved.append(check)
    return resolved


# Capture-time subsetting (the old "test packages" concept) is retired by
# doctrine: capture EVERYTHING the platform supports, always — a feature that
# is not configured records loudly as "not-present", which is information,
# not noise. Subsets happen at ANALYSIS time, in the engineer's test-plan
# prompt. `override_checks` on the capture job remains as a development tool.


# --- per-check semantics (embedded into every snapshot for LLM/human readers) -
# One sentence-or-three per check explaining how to READ its normalized keys
# and what was deliberately excluded. This text ships inside the snapshot
# envelope so each artifact is self-describing: an engineer's test-plan prompt
# never needs to explain the data format — the file does.

SEMANTICS = {
    "iosxe_routes_rib": (
        "Keys are 'vrf|prefix' (e.g. 'default|0.0.0.0/0'); values carry the routing "
        "protocol, admin preference, and the sorted next-hop set (ip/interface). "
        "Route age and metrics are deliberately excluded as volatile. A prefix's "
        "next_hops changing is a routing-path change; a key vanishing is a lost route."
    ),
    "iosxe_routes_fib": (
        "The FORWARDING table (CEF): keys 'instance|prefix' with the programmed "
        "next-hop set. RIB says what the control plane decided; FIB proves the "
        "hardware programmed it — a prefix present in the RIB check but wrong/absent "
        "here is a silent forwarding failure. Packet counters excluded."
    ),
    "iosxe_route_rollups": (
        "Flat numeric route counts: total plus per-protocol (static/connected/ospf/"
        "bgp) and OSPF type splits (intra/inter-area, E1/E2) when available. Counts "
        "within a couple of the baseline are normal churn; a large drop usually means "
        "a neighbor stopped advertising — see iosxe_bgp_peers/iosxe_ospf_neighbors."
    ),
    "iosxe_bgp_peers": (
        "Keys 'afi|vrf|neighbor-ip'; values: session state (Established is healthy), "
        "remote AS, installed prefix count. Uptimes and message counters excluded. "
        "A peer's prefix count moving more than a few while Established suggests "
        "filtering or advertisement changes on the far side."
    ),
    "iosxe_ospf_neighbors": (
        "Keys 'instance|area|interface|neighbor-router-id'; values: adjacency state "
        "(FULL is healthy) and neighbor address. Dead-timer countdowns and LSA "
        "database contents excluded."
    ),
    "iosxe_arp": (
        "Keys 'vrf|ip' with the resolved MAC and interface. Entry age excluded. A "
        "next-hop IP missing here cannot forward traffic; a MAC change for the same "
        "IP means a different physical device now answers that address."
    ),
    "iosxe_neighbors": (
        "CDP and LLDP neighbor sets: keys 'cdp|device-id|local-interface' and "
        "'lldp|device-id|local-interface' with the remote port. A vanished neighbor "
        "usually means a link went down or was re-cabled; a moved neighbor appears "
        "as remove+add on different interfaces."
    ),
    "iosxe_interfaces": (
        "Keys are interface names; values: admin and oper status plus IPv4 address. "
        "Traffic/error counters excluded from the normalized view (see raw). Only "
        "up/down transitions matter here — expect them solely on interfaces the "
        "change touched."
    ),
    "iosxe_platform_health": (
        "Chassis invariants: 'boot-time' (an UNCHANGED value proves the switch did "
        "not reload during the change window), active hardware alarms keyed "
        "'alarm|id|instance', and environment sensor states keyed 'env|location/"
        "sensor' (state only; readings excluded as jitter)."
    ),
    "panos_system_info": (
        "Software/content versions and identity (model, serial, hostname, multi-vsys "
        "flag). Across a hardware REPLACEMENT the identity fields differ by design; "
        "what matters is content/threat/AV versions being equal-or-newer, and the "
        "multi-vsys flavor matching."
    ),
    "panos_ha": (
        "High-availability state: enabled flag, local/peer roles (expect one active "
        "+ one passive), and running-config sync status. Uptimes and heartbeat "
        "counters excluded."
    ),
    "panos_session_info": (
        "Global session counts (active/tcp/udp/icmp) at the capture instant. These "
        "ramp after a cutover: lower-than-baseline with sessions PRESENT indicates "
        "restored functionality still ramping; near-zero indicates traffic is not "
        "flowing. Rates (cps/pps) excluded as instantaneous noise."
    ),
    "panos_session_meter": (
        "Per-vsys session counts keyed 'vsys<N>'. On multi-vsys hardware this is "
        "the only view showing WHICH vsys's traffic domain changed; global counters "
        "sum all vsys."
    ),
    "panos_session_matrix": (
        "Session counts per ORDERED zone pair, keys 'fromZone>toZone' (intra-zone "
        "included). Derived roll-ups 'Z>*' (all sessions from zone Z) and '*>Z' "
        "(all into Z) sum the pair grid — summing pairs AND roll-ups triple-counts. "
        "This is the primary functionality signal for a firewall change: a pair "
        "that carried real traffic before should carry SOME traffic after — any "
        "sessions at all indicate the path works; zero on a previously-busy pair "
        "indicates it does not. The context block carries reconciliation totals "
        "proving sweep completeness."
    ),
    "panos_routes": (
        "The firewall's own routing table: keys 'virtual-router|destination' with "
        "protocol and sorted next-hop set; pseudo-key 'engine|detected' records "
        "legacy-VR vs Advanced Routing Engine (a flavor change across a replacement "
        "is itself notable). Route age/flags excluded."
    ),
    "panos_interfaces": (
        "L3 interface map keyed 'zone|ip' with virtual-router, link state, and MTU. "
        "Deliberately NOT keyed by interface name: hardware and VM platforms number "
        "ports differently, and across a replacement the (zone, IP) binding is the "
        "contract — the name mapping lives in raw as an informational table."
    ),
    "panos_arp": (
        "Firewall-side ARP keyed by IP with resolution status. MACs and interface "
        "names excluded (they change with hardware). An unresolved next-hop toward "
        "the core or upstream cannot pass traffic."
    ),
    "panos_ipsec": (
        "IKE and IPsec SA presence keyed 'ike|gateway' and 'tunnel|name'; presence "
        "of the SA is the up signal. SPIs and lifetimes excluded. Tunnels must "
        "re-establish after a cutover; the session matrix shows whether they carry "
        "traffic."
    ),
    "panos_licenses": (
        "Licensed feature set keyed by feature name with expired yes/no. Serials/"
        "authcodes excluded (they differ across a replacement by design); the "
        "feature SET and non-expired status are what must carry over."
    ),
    "panos_resources": (
        "Informational only: raw dataplane resource-monitor output (per-core CPU, "
        "buffers). Never compared — hardware and VM dataplanes are architecturally "
        "different; judge post-change values against absolute headroom, not the "
        "baseline."
    ),
    "panos_bgp_peers": (
        "The firewall's BGP peers keyed 'peer|<name-or-address>' with session state. "
        "Recorded as not-present when BGP is unused — always asked by doctrine, so "
        "BGP quietly appearing or disappearing across a change is visible."
    ),
    "panos_globalprotect": (
        "GlobalProtect connected-user count. Not-present when GP is unlicensed/"
        "unconfigured — always asked by doctrine. User counts vary by time of day; "
        "informational, never equality-compared."
    ),
    "panos_dhcp": (
        "DHCP server lease overview: lease count and serving interfaces in context. "
        "Not-present when DHCP is unused — always asked by doctrine. Individual "
        "leases churn constantly; informational only."
    ),
    "iosxe_dhcp": (
        "The switch's DHCP server/relay configuration (native config, stable) as one "
        "comparable blob under key 'dhcp-config'. Not-present when no DHCP config "
        "exists — always asked by doctrine. Per-interface helper addresses live in "
        "interface config, not here."
    ),
    "iosxe_routing_config": (
        "What a human TYPED: static-route statements and the OSPF/BGP router "
        "stanzas as stable config blobs (keys ip-route/ipv6-route/router), with "
        "credential-looking values masked. Config has zero volatility, so any diff "
        "is either the planned edit (verify it matches the change plan exactly) or "
        "an undeclared mid-window change. Config-vs-state separates operator error "
        "from network reaction."
    ),
    "iosxe_syslog_errors": (
        "Counts of error-and-worse syslog events (severity 0-3) from the finite "
        "logging buffer, keyed 'sev<N>|%FACILITY-N-MNEMONIC'. Informational: counts "
        "always drift; what an analyst reads is NOVELTY — event types present after a "
        "change that were absent before. The recent raw tail rides in the raw bundle."
    ),
    "iosxe_svl_health": (
        "StackWise Virtual link membership keyed 'svl-link|<chassis>/<link>': member "
        "ports and bundled state. LMP/SDP counters live in context (compare as deltas, "
        "never absolutes). Not-present on non-SVL systems. A degraded SVL multiplies "
        "every other risk during a change window."
    ),
    "iosxe_ntp": (
        "NTP synchronization scalars (synchronized state, stratum, selected server) "
        "when the device exposes them. Offsets and dispersion are jitter — raw only. "
        "If sync changed, timestamps in every other capture and in device logs are "
        "suspect."
    ),
    "panos_logging_status": (
        "Log-forwarding status, raw-first (shape refined against real output): is "
        "telemetry actually flowing to Panorama/syslog collectors. A SIEM ingestion "
        "gap discovered weeks later is the classic day-2 failure of firewall "
        "replacements — this check exists to catch it on day 0."
    ),
    "panos_url_cloud": (
        "URL-filtering cloud connectivity ('connected' / 'not-connected' when "
        "derivable). Not-present when URL filtering is unlicensed. User internet can "
        "break with perfect routing if the management plane cannot reach the cloud."
    ),
    "panos_ntp": (
        "NTP synchronization state, best-effort. If time sync changed, timestamps in "
        "every capture and log become suspect."
    ),
    "panos_pending_changes": (
        "Whether uncommitted candidate-config changes exist ('pending': yes/no). "
        "Pending changes at capture time mean config-derived state may not reflect "
        "what is running — or someone left work half-finished on the box."
    ),
    "panos_pbf": (
        "Policy-based forwarding rules keyed 'pbf|<rule>' with action/egress when "
        "derivable. PBF steers traffic AROUND the routing tables the other checks "
        "diff — changes here are invisible everywhere else. Not-present when PBF is "
        "unused."
    ),
    "panos_drop_counters": (
        "Top global drop counters by value, keyed by counter name. Values are "
        "cumulative since boot (a fresh VM counts from ITS boot) — informational by "
        "design; the analyst reads novelty: drop counters present after a change that "
        "were absent before (flow_fwd_l3_noroute = routing hole, flow_no_arp = "
        "unresolved adjacency, policy-deny spikes = rulebase mismatch). Full table in "
        "raw."
    ),
    "panos_nat_pools": (
        "NAT pool tables (ippool / global-ippool), raw-first: utilization is load-"
        "dependent, so exhaustion appears under load, not at cutover time. The DIPP "
        "oversubscription setting differing between hardware and VM platforms is a "
        "real finding to look for in the raw tables."
    ),
    "iosxe_optics": (
        "Transceiver DOM light levels per optical port: tx_dbm/rx_dbm. Healthy "
        "short-reach optics typically read roughly 0 to -10 dBm; values plunging "
        "toward -30 mean little/no light (dirty/bad fiber or optic) — the classic "
        "new-link failure that passes up/down checks while quietly eating frames. "
        "Temperature/voltage stay in raw as jitter. Informational: levels drift "
        "tenths of dB between healthy captures."
    ),
    "iosxe_crash_files": (
        "Crash and system-report files WITHIN the recency window (context notes the "
        "window and how many older files were ignored — ancient dumps never alarm). "
        "Keys 'active|<file>' / 'stby|<file>'. A key ADDED between captures means "
        "something on the chassis crashed during the change window, even if it "
        "recovered before anyone looked. Empty is the healthy state."
    ),
    "panos_ospf_neighbors": (
        "The firewall's OSPF adjacencies keyed 'ospf|<neighbor-id>' with state and "
        "address — the firewall's own view of the core adjacency the switch-side "
        "check sees from the other end (this network runs OSPF between firewall and "
        "core). Engine-aware: legacy and advanced-routing command forms both tried."
    ),
    "panos_crash_files": (
        "Core/crash files WITHIN the recency window (context notes the window and "
        "older files ignored — ancient dumps never alarm). A key ADDED between "
        "captures means a management or dataplane process crashed during the change "
        "window. Empty is the healthy state."
    ),
    "panos_jobs": (
        "Unfinished commit/config jobs keyed 'job|<id>' with status/type; finished-"
        "job history stays in context counts (jobs_total, jobs_not_ok) so churning "
        "history never diffs. Any key present means policy programming may be "
        "incomplete — the device answers, but the dataplane may not reflect config."
    ),
    "panos_chassis_ready": (
        "Dataplane readiness ('ready': yes/no). 'no' is the post-boot window where "
        "management answers but traffic blackholes — on a freshly booted replacement "
        "this must read yes before any traffic conclusion is drawn."
    ),
    "panos_disk_space": (
        "Filesystem use percentages keyed by mount point. Slow growth is normal "
        "(tolerance band); a jump toward full silently blocks commits, log writing, "
        "and content installs."
    ),
    "panos_panorama": (
        "Panorama connectivity keyed 'panorama|<server>' with connected yes/no. A "
        "disconnect breaks config pushes AND log forwarding, silently."
    ),
    "panos_environmentals": (
        "Hardware environmental ALARM states keyed 'env|<sensor description>' — "
        "alarm flags only; temperatures/RPM readings are jitter and stay in raw. "
        "Not-present on VM platforms (no sensors). On the hardware side, thermal/"
        "fan/PSU alarms precede hardware death and mid-change brownouts."
    ),
    "iosxe_errdisable": (
        "Ports currently err-disabled, keyed by interface, with the triggering "
        "reason. Healthy is EMPTY — an added key means a port was disabled by the "
        "platform during the work (security violation, link-flap, UDLD...) and "
        "reads as merely 'down' in the interface check."
    ),
    "iosxe_port_channels": (
        "Port-channel bundles keyed 'PoN' with bundle flags, protocol, and per-"
        "member flags. Member flag decode: P bundled (healthy), s suspended, D "
        "down, w waiting, H hot-standby — a suspended member quietly halves bundle "
        "capacity without downing the port-channel."
    ),
    "panos_syslog_events": (
        "High/critical system-log event counts from the capture-relative window "
        "(context notes window hours and how many lower-severity events were "
        "counted but not keyed). Keys 'severity|eventid'. Informational — counts "
        "drift; the analyst reads NOVELTY: event types present after the change "
        "that were absent before. The query is always time-bounded; an unbounded "
        "log dump is never issued."
    ),
    "panos_rule_hit_counts": (
        "Security and NAT rules keyed '<rulebase>|<rule-name>' with cumulative hit "
        "counts and last-hit timestamps (vsys1). Two signals in one: the rule-NAME "
        "set is the config-parity check (a mistranslated rulebase is the biggest "
        "replacement risk), and last-hit recency shows which rules actually carry "
        "traffic. Counts reset on a replacement device — compare activity, not "
        "absolutes."
    ),
}


def shakedown_advice(status, error, normalized_count, fetched_anything):
    """One-line advisory for the Collector Shakedown job's per-check verdicts.

    The interesting case is "parsed but empty": the device answered and the
    collector succeeded, yet the normalizer emitted nothing — on a live box
    that almost always means this software version spells a leaf/element name
    differently than the normalizer expects. That is exactly the tweak the
    shakedown run exists to surface before a change window.
    """
    if status == "ok" and normalized_count:
        return "ok"
    if status == "ok":
        return (
            "parsed but empty — if the trace payload shows data, this software "
            "version spells the leaf/element names differently; adjust the "
            "normalizer to match the trace"
        )
    if status == "not-present":
        return "feature not present on this device: %s" % (error,)
    if fetched_anything:
        return (
            "collector failed after fetching data — the payload shape surprised "
            "the parser; inspect the trace payload against the error: %s" % (error,)
        )
    return "nothing fetched — transport/path problem (404, timeout, auth): %s" % (error,)
