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
    platform: str  # "iosxe" | "panos" | "vmware" | "xcc"
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
        "The firewall's BGP peers keyed 'peer|<name>' with session state "
        "(Established is healthy), peer address, and remote AS when reported. "
        "Recorded as not-present when BGP is unused — always asked by doctrine, so "
        "BGP quietly appearing or disappearing across a change is visible. This is "
        "the firewall's own view of the peering the switch-side check sees from "
        "the other end."
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
        "Transceiver DOM light levels per optical port: tx_dbm/rx_dbm, plus "
        "tx_flag/rx_flag when the optic itself marks a threshold violation "
        "(-- low alarm, ++ high alarm, single -/+ warns). Healthy short-reach "
        "optics typically read roughly 0 to -10 dBm; values plunging toward -30 "
        "mean little/no light (dirty/bad fiber or optic) — the classic new-link "
        "failure that passes up/down checks while quietly eating frames. Any "
        "*_flag present is the optic raising its own alarm. Temperature/voltage "
        "stay in raw as jitter. Informational: levels drift tenths of dB between "
        "healthy captures."
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
        "incomplete — the device answers, but the dataplane may not reflect config. "
        "Known limit: candidate-config edits typed but never committed are NOT "
        "visible here (the CLI has no pending-changes query on this release; the "
        "XML API's check pending-changes would cover it if API access is enabled "
        "later)."
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
    # --- vmware: standalone ESXi set up as NFV compute (vim25 SOAP) ------------
    "vmware_host_identity": (
        "Flat hypervisor identity scalars: vendor/model/serial (serial_source says which "
        "field populated it), BIOS version and release date (verbatim string), ESXi "
        "version/build/apiType, hostname, CPU model/package/core/thread counts, "
        "hyperthreading_active (null when the host does not expose HT scheduling), "
        "memory_bytes, and the host's own state: maintenance_mode (a host left in "
        "maintenance mode answers every other check green and powers no VM on), "
        "power_state, standby_mode, power_policy (the APPLIED policy: static/dynamic/low/"
        "custom — the Power.CpuPolicy option is only the knob) and bmc_ip/bmc_mac (the BMC "
        "address the host holds, the join to the out-of-band envelope; the BMC login is never "
        "recorded). Context: boot_time and reboot_required (an UNCHANGED boot_time proves the "
        "host did not restart), the policies on offer, tpm_pcr_values (the PCR digests the "
        "TPM-sealed configuration archive depends on; empty without a TPM) and unreadable "
        "(host-state properties the build or role withheld). hostname is configuration — a "
        "change is a re-address, not a different box."
    ),
    "vmware_hardware_inventory": (
        "Keys 'cpu|<index>' (vendor/description), 'pci|<0000:bb:ss.f>' (vendor/device/class "
        "ids as unsigned hex, names, parent_bridge, is_vf, passthru_* and sriov_* state, "
        "VF counts — null when the device has no SR-IOV entry), 'numa|nodes' and "
        "'memory|bytes'. Virtual functions are their OWN pci| rows: a VF-count change reads "
        "as N added/removed keys plus one flipped sriov_active, not N unseated cards. "
        "passthru_enabled without passthru_active means a reboot is pending or a vmkernel "
        "driver still claims the device. Clock rates and CPU feature bits are raw-only."
    ),
    "vmware_pnics": (
        "Keys 'pnic|vmnicN': mac (identity — never overridden by ESXi), pci, driver, "
        "driver/firmware versions (8.0 U1+, else null), link_up, speed_mb, duplex (true = "
        "full), autoneg_supported, configured_speed_mb/duplex (null = auto-negotiate) and "
        "ens_enabled. A link_up flip or a different negotiated speed is the host-side view of "
        "a cable, transceiver or far-port change; the switch-side check names the port."
    ),
    "vmware_pnic_neighbors": (
        "Keys 'cdp|vmnicN' (device_id, port_id, platform, native_vlan, mtu, mgmt_addr, "
        "address, full_duplex) and 'lldp|vmnicN' (chassis_id, port_id, parameters) — what "
        "each uplink HEARS from its far port. Context 'discovery' records each vSwitch's "
        "protocol/operation; not-present only when no bond-bridged vSwitch listens "
        "(operation none/advertise). With discovery listening, an empty table or a missing "
        "row is a finding: the far port does not advertise, or the link is down. Timers, "
        "ttl and sample counts are excluded; a capture within ~3 minutes of link-up may "
        "still show a stale or absent neighbor."
    ),
    "vmware_vswitches": (
        "Keys 'vswitch|<name>': mtu, num_ports_configured (spec; runtime port counts are "
        "elastic and stay in context), uplinks and portgroups (sorted names), the security "
        "trio (promiscuous/mac_changes/forged_transmits), teaming_policy, active_uplinks "
        "and standby_uplinks in FAILOVER ORDER (never sorted), notify_switches, "
        "rolling_order, beacon_probing, bridge_type and discovery_protocol/operation (null "
        "on an uplink-less vSwitch). 'proxyswitch|count' is 0 without vCenter/DVS."
    ),
    "vmware_portgroups": (
        "Keys 'portgroup|<name>': vswitch, vlan_id (4095 = guest-tagged trunk), the "
        "EFFECTIVE security trio and teaming fields from computedPolicy, plus "
        "security_overridden/teaming_overridden (true when the port group sets its own "
        "policy instead of inheriting the vSwitch's). Attached-port counts move with VM "
        "power state and are raw-only. A VNF in L2/passthrough mode or with floating HA "
        "MACs needs promiscuous/mac_changes/forged_transmits true on its port groups."
    ),
    "vmware_vmknics": (
        "Keys 'vmk|vmkN': portgroup (null on a DVS/opaque network), ip, netmask, dhcp, "
        "ipv6_static (manually configured addresses only; link-local/autoconf excluded), "
        "mtu, mac (vmk0 inherits the first pnic's burned-in MAC), netstack, services "
        "(management/vmotion/... resolved by vnic key) and pinned_pnic. A DHCP vmk's ip is "
        "informational. Compare vmk MTU against the switchport MTU it lands on."
    ),
    "vmware_host_routes": (
        "Keys 'route|<netstack>|<net>/<len>' (gateway, device, family, in_config from the "
        "netstack's route table config, in_state from the default stack's live table — "
        "null for other stacks), 'gateway|<netstack>' (ipv4/ipv6 default gateways and "
        "devices), and 'dns|hostname', 'dns|domain', 'dns|servers' (ORDERED — a primary "
        "swap is a signal), 'dns|search', 'dns|dhcp'. IPv6 routes are included with family "
        "ipv6. Context notes whether the deprecated live route table was populated."
    ),
    "vmware_time_syslog": (
        "Flat scalars: ntp_servers (union of the configured list and the config file's "
        "server lines, sorted), time_services_enabled, clock_protocol (ntp/ptp), "
        "ntp_service_sync (the LIVE in-sync flag, 7.0.3+; null on older builds), "
        "fallback_disabled, ntp/ptp running and startup policy, syslog_loghost (sorted "
        "list; 8.x stores comma-separated targets), syslog_logdir, syslog_logdir_unique, "
        "syslog_check_ssl_certs, syslog_log_level. Last sync time, run time and the remote "
        "server actually used are context. Time zone is always UTC on ESXi (raw only)."
    ),
    "vmware_host_services": (
        "Keys 'service|<key>' (running, policy on/off/automatic, required, label) for "
        "whatever hostd lists — never a fixed set — plus 'lockdown|mode', 'mob|enabled' "
        "and 'vcenter|management_server' (null on a standalone host; a value means it was "
        "joined). A reboot stops hand-started policy=off services (TSM/TSM-SSH): running "
        "true -> false after a reboot is the reboot, not a regression; the other direction "
        "is what troubleshooting leaves behind. HostService has no uptime field."
    ),
    "vmware_advanced_options": (
        "Keys 'opt|<full key>' for a curated set (ESXi shell timeouts, shell warning, MOB, "
        "Net.MaxNetifTxQueueLen/CoalesceDefaultOn/TcpipHeapMax, Mem.AllocGuestLargePage/"
        "ShareForceSalting, Power.CpuPolicy, Numa.LocalityWeightActionAffinity, "
        "Misc.BlueScreenTimeout, Security.AccountLockFailures/PasswordQualityControl); "
        "values keep their native type. Context lists options_total and curated_absent "
        "(keys this build does not expose). Every option key=value is in raw: the curated "
        "block uncapped, the rest grouped by top-level prefix (Net, Mem, UserVars ...) with "
        "each group capped on its own and carrying its own '...[truncated N chars]' marker, "
        "secrets masked. ESXi persists advanced options only hourly and on clean shutdown, "
        "so an unclean power-off silently reverts recent edits."
    ),
    "vmware_firewall_rulesets": (
        "Keys 'ruleset|<key>': enabled, all_ip (true when no allowed-host restriction "
        "exists), allowed (sorted addresses and net/len), service, and the 8.0U2+ "
        "user_controllable/ip_list_user_configurable flags (null before). "
        "'firewall|incoming_blocked'/'outgoing_blocked' are the default policies. Port "
        "definitions are static package content and stay raw-only. Not-present when the "
        "host exposes no firewallInfo at all."
    ),
    "vmware_datastores": (
        "Keys 'datastore|<name>': type, uuid (VMFS/VFFS only; null for NFS, whose "
        "identity is 'remote' host:path), local, capacity_bytes and free_bytes (null while "
        "inaccessible; free_bytes carries a 10 percent / 10 GiB tolerance band), accessible "
        "and mounted (joined from the mounted-volume list; null when unjoined). Same name "
        "with a new uuid means reformatted; a resignature shows as removed plus added "
        "('snap-<id>-<name>'). Boot/OSDATA volumes are not datastores and are counted in "
        "context only. An empty datastore list on a successful read is {} — every removal "
        "is reported with its old identity."
    ),
    "vmware_storage_devices": (
        "Keys 'hba|vmhbaN' (type, driver, model, status — diffed, never asserted: unknown "
        "is normal for USB storage — storage_protocol, pci) and 'lun|<canonicalName>' for "
        "HostScsiDisk entries of deviceType disk only (vendor, model, capacity_bytes, "
        "operational_state sorted, ssd/local tri-state, protocol, disk_type). CD-ROM and "
        "other non-disk LUNs are counted in context, never keyed (virtual media comes and "
        "goes). mpx.* names embed the vmhba number and can renumber after a power cycle; "
        "naa./t10./eui. names are stable. Behind a RAID/mirror adapter a failed member "
        "leaves the virtual LUN ok — pair with the out-of-band storage view."
    ),
    "vmware_health_sensors": (
        "Keys 'sensor|<name>' (health green/yellow/red/unknown, type, state) with hostd's "
        "' --- <state text>' suffix stripped from discrete sensor names into the state field "
        "so a state change is a changed value, not removed+added ('|<id>' suffix only on a "
        "base-name collision; '|<id>|<state>' when hostd lists one discrete sensor once per "
        "asserted state, each state its own row), and 'status|cpu|…', 'status|memory|…', "
        "'status|storage|…' (health, "
        "lowercased) from the hardware-status half. Physical readings (temperatures, fan "
        "RPM, volts, watts) are scaled into context.readings, never diffed. Not-present "
        "only when both halves are empty. hostd refreshes IPMI on a timer: a capture "
        "minutes after boot may read unknown everywhere."
    ),
    "vmware_autostart": (
        "Keys 'defaults|enabled', 'defaults|start_delay', 'defaults|stop_delay', "
        "'defaults|wait_for_heartbeat', 'defaults|stop_action' and 'autostart|<vm name>' "
        "(configured, vm_registered, start_order, start_delay, start_action, stop_delay, "
        "stop_action, wait_for_heartbeat) — one row for EVERY registered VM, configured "
        "false when the VM is not in the autostart list, and a row with vm_registered "
        "false for a stale entry whose VM is no longer registered. On a standalone host "
        "autostart is the only mechanism that powers VMs on after a boot: defaults|enabled "
        "false, a VM with configured false, or a shuffled start_order is the 'everything "
        "green but the VNF never came up' outcome."
    ),
    "vmware_vlan_hints": (
        "Keys 'vlans|vmnicN' -> vlan_ids, the sorted VLAN ids whose broadcast traffic the "
        "uplink has observed (learned, not configured — the far port's allowed list as "
        "seen from the host). Observed subnets churn and stay in context. Hints need "
        "several minutes of link-up and some traffic to populate; an empty list right "
        "after a link came up is 'not yet heard', not 'pruned'. Not-present when the host "
        "returns no hints at all."
    ),
    "vmware_host_license": (
        "Flat scalars for the host's license: edition_key, name, total/used, cost_unit, "
        "license_key_tail (last 5 characters only — the key is never stored), expiration "
        "(verbatim timestamp; null on a perpetual key), product name/version and the "
        "sorted feature list. Remaining evaluation hours are context. An edition change "
        "means someone re-licensed; an expiring evaluation stops VMs from powering on."
    ),
    "vmware_vm_disks": (
        "Keys 'vdisk|<vm>|<label>': capacity_kb, backing_file ('[datastore] path'), "
        "datastore, backing_type, thin, eager_zeroed, disk_mode, controller (label) and "
        "unit_number. A backing_file change under the same label means the disk was moved, "
        "restored from elsewhere, or its datastore was resignatured. Not-present when the "
        "host has no VMs; a VM without disks contributes no rows."
    ),
    "vmware_recent_tasks": (
        "Informational: keys 'task|<key>' (description_id, state, entity, entity_type, "
        "user for operator-initiated tasks, queue/complete times verbatim) from hostd's "
        "~10-minute recent-task window, plus context.latest_event with is_own_login (the "
        "latest event is almost always the suite's own Login). The honest claim is 'the "
        "host is quiescent right now' — it cannot say who touched it last or what "
        "autostart did before the window."
    ),
    "vmware_vms": (
        "Keys 'vm|<name>' (|<moid> suffix on duplicate names) with a fixed field set: "
        "uuid (the hypervisor-side identity a guest also reports), instance_uuid (often "
        "null on never-vCenter-managed VMs — null is not identity loss), hw_version, "
        "guest_id, power/connection state, num_cpu, cores_per_socket, memory_mb, CPU/memory "
        "reservations, limits and shares, mem_locked_to_max, latency_sensitivity, "
        "cpu_affinity (sorted), tools status/running/version status, guest state and "
        "hostname, datastore (from the .vmx path), snapshot_count (whole tree), "
        "has_pending_question (the 'moved or copied?' prompt: power_state reads on but "
        "the guest never boots), firmware (bios/efi), efi_secure_boot, boot_delay_ms, "
        "boot_order (ordered 'disk:<key>'/'ethernet:<key>'/'cdrom' entries; [] = firmware "
        "default), vvtd_enabled (the vIOMMU a DPDK / VF-in-guest VNF needs), vbs_enabled, "
        "cpu_hot_add/memory_hot_add (hot-add disables vNUMA) and tools_sync_time_with_host — "
        "null when the property is absent, never a fabricated false. latency_sensitivity is "
        "configuration and never 'drops'; high with mem_reservation_mb below memory_mb means "
        "it is no longer honoured. Context: boot times, moids, question text, "
        "config_versions per VM (change_version, modified, vmx_config_checksum — an UNCHANGED "
        "checksum proves the whole .vmx is byte-identical) and guest_net (the guest's own "
        "per-MAC address report, volatile). Not-present when no VMs are registered; an "
        "unreadable (orphaned) VM keeps its row with null fields and is named in "
        "context.unreadable."
    ),
    "vmware_vm_nics": (
        "Keys 'vnic|<vm>|<label>' for every device with a MAC (any virtual Ethernet card "
        "type): adapter_type, mac (lowercase), address_type (generated on a standalone "
        "host; assigned = vCenter-managed), backing (port group name, also for SR-IOV — it "
        "sets the VF's VLAN; dvport:/opaque: forms otherwise), backing_type, pf (SR-IOV "
        "physical function), connected (null unless powered on, so a power change is not "
        "an adapter change), start_connected, pci_slot (the stable ordering key when MACs "
        "are not hypervisor-assigned), unit_number, upt_compatible. 'pcidev|<vm>|<label>' "
        "covers PCI passthrough devices (pci_id, device_name, vendor_id/device_id in the same "
        "0x-hex form as the host's pci| rows so the two views join, allowed_devices for "
        "Dynamic DirectPath, custom_label, vgpu). A VM with zero adapters is removed keys, "
        "not not-present."
    ),
    "vmware_vm_tuning": (
        "Keys 'tune|<vm>|<vmx key>' for an exact curated .vmx set (sched.cpu.*, "
        "sched.mem.*, numa.nodeAffinity/autosize/vcpu.*, hypervisor.cpuid.v0, "
        "uuid.action, monitor_control.disable_mmu_largepages, ethernetN coalescing/"
        "pnicFeatures/ctxPerDev/filter*, pciPassthru MMIO sizing) with values as strings; "
        "sched.cpu.affinity absent and 'all' normalise equal. 'api:' rows (latency "
        "sensitivity, CPU/memory reservation, memory pinned, CPU affinity) are the modeled "
        "values hostd may keep only in the API view. Bare numa.* keys are never keyed "
        "(numa.autosize.cookie rewrites at every power-on). A host with no NFV-tuned VMs "
        "legitimately shows only the api: rows and the affinity default."
    ),
    # --- xcc: Lenovo XClarity Controller, the SE350 BMC (Redfish) --------------
    "xcc_system": (
        "Flat scalars from the BMC: system identity (serial, uuid, model, sku, BIOS version), "
        "power_state, health/health_rollup, boot_override (a STRING: Disabled | Once | "
        "Continuous — anything but Disabled means a one-shot or persistent boot override is "
        "armed), boot_override_target, the three SecureBoot fields (all null together when the "
        "firmware has no SecureBoot resource), system_status (BootingOSOrInUndetectedOS is the "
        "steady state under a hypervisor with no Lenovo agent — it is not a fault), and the "
        "XCC's own firmware, health and management address "
        "(xcc_ip/xcc_ip_origin/xcc_gateway/xcc_vlan/xcc_mac, from the member named in "
        "eth_member_used; a DHCP re-lease is not a reconfiguration). Reboot count, power-on "
        "hours, XCC clock and TPM module facts ride in context as volatile/informational. MACs "
        "are lower-cased."
    ),
    "xcc_security_state": (
        "ThinkEdge Security Pack state as flat scalars, every field nullable: lockdown_mode "
        "(Active/Inactive), lockdown_control, motion_detection_enabled, "
        "motion_threshold/motion_orientation (spelled differently per generation, so either may "
        "be null), chassis_intrusion_enabled, host_shutdown_on_tamper, sed_encryption_enabled. "
        "Recorded as not-present when the Security resource carries none of these (mainstream "
        "ThinkSystem, or firmware that hides them) — the resource's mere existence never "
        "decides. context.property_sources names the real property behind each field; "
        "key_management summarises the external key-manager (SKLM/KMIP) configuration, which is "
        "escrow, not SED state. Key material (SED_AK, certificates) is never read or echoed. "
        "Read motion_detection_enabled true->false TOGETHER with lockdown_mode Active as the "
        "lockdown itself (the BMC disables motion detection on entering lockdown), not as an "
        "operator edit."
    ),
    "xcc_thermal": (
        "Keys 'temp|<Name>' (with '|<MemberId>' appended only when a Name repeats) -> health, "
        "state, physical_context and reading_c; 'fan|<Name>' -> health, state, reading, "
        "reading_units. reading_c is populated ONLY for ambient/intake/inlet/exhaust-class "
        "sensors (compared within 8 °C); CPU/DIMM/PCH readings are load-driven and live in "
        "context.readings_c, as do every published threshold and fan redundancy group. Fan "
        "reading is banded at 25 % — a fan reading 0 pre is itself a finding. A sensor with "
        "State Absent has no key (listed in context.absent), so a vanished key means the sensor "
        "disappeared, and health/state strings are verbatim, never pinned."
    ),
    "xcc_power": (
        "Keys 'psu|<MemberId>' (Name is often null on this BMC) -> state and health VERBATIM "
        "(the DMTF values are Enabled/Absent/UnavailableOffline; input loss on an external "
        "adapter most likely reads Enabled + Critical), line_input_voltage (banded 10 % as a "
        "change signal), input_in_range (true/false against the supply's own InputRanges; null "
        "when either is unpublished — a 120 V to 208 V feed change is legitimate when still in "
        "range), capacity_w and identity strings (null, never ''). 'redundancy|<MemberId>' "
        "exists only when the firmware publishes a Redundancy group (Disabled + OK is a single "
        "feed); 'voltage|<MemberId>' -> state, in_threshold (against the rail's critical/fatal "
        "thresholds; null without them) and health (usually null). Consumption, output watts "
        "and rail readings are context. Read-only by transport: this resource accepts changes "
        "on the BMC, the suite only ever GETs it."
    ),
    "xcc_inventory": (
        "Keys 'dimm|<Id>' (slot, socket, service_label, capacity_mib, type, speed_mhz as the "
        "firmware scales it — never banded — serial, part_number, manufacturer, health, state), "
        "'cpu|<Id>' (model, cores, enabled_cores, threads, health, state — a soldered CPU "
        "carries identity plus health; clock speed is a load-driven reading kept in "
        "context.clock_speed_mhz and raw, never diffed) and "
        "'pcie|<Id>' (manufacturer, model, device_type, firmware, serial, part_number, health, "
        "state, best-effort location). An unseated part most likely shows as a MISSING key, not "
        "a state change; unpopulated DIMM slots, when listed, appear identically on both sides "
        "with null serial/capacity. Inventory is populated at POST: a collection that answers "
        "empty is unmeasured whatever the power state (the host reads On throughout POST), so "
        "the check refuses (failed, never zero rows) and names the family and the power state; "
        "context.host_power_state / context.collections record the power state and whether each "
        "collection answered via $expand, a per-member walk, or was absent (404)."
    ),
    "xcc_host_nics": (
        "Keys 'nic|<Id>' (the BMC's port ids, e.g. ob-1) -> link_status verbatim (LinkUp; "
        "NoLink = no cable/transceiver; LinkDown = cable present, no link), permanent_mac "
        "(burned-in, lower-cased — it joins to the hypervisor's physical-NIC MAC since ESXi "
        "never overrides it), interface_enabled, health, state. The ToManager member (the USB "
        "Redfish host interface, not a port) is excluded before any request. speed_mbps is "
        "context only (null or 0 on this firmware family, both read as null); the constant "
        "vendor Description is dropped. Not-present when the collection is absent, empty, "
        "carries only ToManager, or reports null LinkStatus on every port. Link state is read "
        "via sideband and may not reflect a cable with the host off: compare captures taken in "
        "the same host power state (context.host_power_state)."
    ),
    "xcc_firmware": (
        "Keys 'fw|<Id>' (BMC-Primary, BMC-Backup, UEFI, LXPM*, Ob_N.M, Slot_N.M, *.Bundle ...) "
        "-> name, version verbatim (<BUILDID>-<ver>; the BMC notes this string can differ from "
        "the web UI's rendering — compare pairs case-insensitively), software_id (stable; tells "
        "two adapters sharing a Name apart), updateable, health (null when no Status). "
        "Status.State is deliberately NOT emitted: the backup BMC bank toggles between "
        "StandbyOffline and Enabled after a BMC restart. ReleaseDate, etags, "
        "LowestSupportedVersion, Description and Oem blocks are excluded. External power "
        "adapters carry no firmware entry; whether the LOM appears here depends on the "
        "firmware. context records whether one $expand GET or a per-member walk answered."
    ),
    "xcc_event_log": (
        "Keys 'sel|<CommonEventID>|<Id>' for entries of Severity Warning or Critical ONLY, from "
        "the whole platform event log read without any query window (no $top, no paging "
        "shortcuts): the FQXSP event code is in the key so an expectation glob such as "
        "'sel|FQXSPSE0000F|*' can bless a declared class of additions. Values: severity, "
        "source, serviceable, event_id, hidden. Ids are the BMC's monotonic sequence numbers, "
        "so a key is ADDED when an event is logged and REMOVED only when the log wrapped or was "
        "cleared — which one is a cross-capture reading of context: a post newest_id below the "
        "pre newest_id (or first_id jumping while last_seq_num falls) means the log was "
        "cleared; first_id advancing while newest_id keeps growing on a log whose at_capacity "
        "is true means it wrapped. A first_id above 1 on its own says nothing (the BMC's own "
        "samples start at 5). A firmware that pages the log is followed through its own "
        "continuation links (context.pages); one that pages with a window is refused, never "
        "read partially. OK/Informational entries are "
        "counted per event code in context.informational_by_code and never keyed; per-entry "
        "Created and Message text is in raw (newest first, capped). The log records what the "
        "BMC saw while powered — with AC removed it is not a live record of transit. "
        "context.log_service_used names PlatformLog or StandardLog. The BMC's AuditLog (where "
        "this tool's own logins land) is never read."
    ),
    "xcc_bios": (
        "Keys 'bios|<Attribute>' -> the current UEFI setting value verbatim, for the curated "
        "attribute families matched by name: hyper-threading, turbo, C-states/C1E, operating "
        "mode / power-performance bias, VT-d/IOMMU and virtualisation, SR-IOV, boot mode, MMIO "
        "above 4G, TPM/TCM and Secure Boot, NUMA/SNC, prefetchers, SpeedStep/P-states. "
        "Attribute names are the vendor's and are not renamed. Every other attribute is in raw "
        "as sorted key=value text (password-like attributes scrubbed) and counted in context. A "
        "changed value is a defaults load, a CMOS/RTC reset or an operator edit — the "
        "hypervisor sees only the effects (HT active, Secure Boot)."
    ),
    "xcc_storage": (
        "Keys 'controller|<Id>' (model, firmware, serial, health, state, drive/volume counts), "
        "'drive|<Id>' (serial, model, revision, capacity_bytes, media_type, protocol, health, "
        "state, failure_predicted, encryption_ability/encryption_status, location) and "
        "'volume|<Id>' (raid_type, capacity_bytes, health, state, encrypted, member drive ids); "
        "an id that repeats across controllers is prefixed with the controller id. Predicted "
        "media life is context (it only decreases). This is the only view of a mirror's "
        "individual members and of the SED encryption flags — the hypervisor's LUN stays 'ok' "
        "with one mirror half failed. Not-present when the BMC serves no Storage members "
        "(non-RAID M.2 may not enumerate at all)."
    ),
    "xcc_manager_network": (
        "Flat scalars for the BMC's own services and addressing: hostname/fqdn, ntp_enabled and "
        "ntp_servers (ordered as configured), <protocol>_enabled/<protocol>_port for HTTP, "
        "HTTPS, SSH, IPMI, SNMP, VirtualMedia, KVMIP, SSDP and Telnet, then the management "
        "port's ipv4_address/ipv4_origin/subnet/gateway, dhcpv4_enabled, dns_servers, "
        "static_dns_servers, ipv6_address_count, mtu, autoneg, vlan and interface_enabled. "
        "Community strings and certificates are scrubbed from raw. Link speed/state of the BMC "
        "port is context. NTP and DNS here timestamp every event-log entry and are what any "
        "outbound key-management or portal reactivation path needs."
    ),
    "xcc_chassis_location": (
        "Flat scalars from Chassis/1: chassis identity (type, model, serial, part_number, "
        "asset_tag), health/state/power_state, the operator-maintained Location record passed "
        "through generically as location_info plus 'postal_<field>' and 'placement_<field>' "
        "leaves (rack, rack_offset, row ... whichever this firmware fills), and the DMTF "
        "intrusion_sensor state (Normal / HardwareIntrusion / TamperingDetected) with its "
        "re-arm policy. The Location record only changes when someone edits it: after a "
        "physical relocation an UNCHANGED record means nobody updated it, so declare the "
        "expected edit; an intrusion_sensor leaving Normal is a hardware finding. Indicator LED "
        "state is context."
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
