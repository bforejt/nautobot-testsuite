# nautobot-testsuite

Pre/post change-validation jobs for Nautobot. Snapshot a device before a change,
make the change, snapshot again, compare — and get a JSON verdict on the JobResult
that separates the diffs you *declared* you would cause from the ones you did not.

Two jobs, both under the **Test Suite** grouping:

- **Test Suite Capture** — runs every read-only check the platform supports
  against one or more devices (mixed platforms in one run collect per device) and attaches a versioned snapshot envelope (plus a raw-evidence bundle)
  to the JobResult: `snapshot_<device>_<change_id>.json` / `raw_<device>_<change_id>.json`.
  A server whose BMC is modelled as an interface on its Device gets the BMC's
  checks in the same snapshot, beside the host's own: every check entry names
  its `target` (`host` or `bmc`).
  A `debug` checkbox additionally attaches `debug_<device>_<change_id>.json`: the
  full transport trace of both planes (every RESTCONF/Redfish path, SSH
  command and SOAP operation with timing, outcome, and payload, each entry
  labelled with its transport — configuration text only in its redacted form,
  BMC payloads only after their redactor), so even a FAILED check keeps its
  evidence.
- *(analysis happens outside Nautobot: download the snapshot files and feed
  them, with your test-plan prompt, to the LLM your organization approves —
  see below. `tools/diff_snapshots.py` builds an optional deterministic diff
  index locally.)*
- **Test Suite Shakedown (dev)** — hidden development job: runs *every* registered
  check for one device's platform in debug mode (and, when a BMC is modelled
  on the device, the `bmc` family through a second debug context) and
  attaches per-check verdicts (each naming its `target`)
  with advisories ("parsed but empty — leaf names likely differ on this
  version"), a per-platform `discovery` block (yang-library module inventory,
  RIB/FIB naming and where crash files live in the q-filesystem model on
  IOS-XE; hostd build, lockdown mode, CDP hearing
  and health-runtime population on ESXi; under `discovery.bmc` the BMC's
  Redfish version and vendor, resolved ids, `$expand` depth, OEM links, log
  services, collection counts and the platform log's sequence numbers before
  and after the run), and the full payload trace of both planes. This is
  how collectors get validated
  against real devices *before* a change window, and how CI fixtures are
  harvested (sanitize captures before committing). Check failures do not fail
  the JobResult — surfacing them is the point.

Platforms today: Catalyst 9500 StackWise Virtual pairs and Catalyst 9300 StackWise
stacks on IOS-XE 17.x (RESTCONF plus allowlisted read-only SSH commands), PAN-OS
firewalls (SSH, XML op-command output), standalone VMware ESXi 8.x hosts set up
as NFV compute (vim25 SOAP, read-only operation allowlist), and a server's
baseboard management controller: modelled as an Interface on its host Device,
never as a Device of its own, and captured in the host's own snapshot by the
vendor-neutral `bmc` check family over GET-only Redfish. The Lenovo XClarity
Controller is the verified one (a gen-1 ThinkSystem SE350 with XCC 6.10); on
other vendors the DMTF reads run unverified and the OEM-only reads record
`not-present` naming the vendor. Both server-side families are general —
`vmware` is "ESXi set up as NFV compute", `bmc` is any Redfish BMC — never a
host for one particular change: every check is always-on, and a feature that
is not in use records loudly as `not-present`.

## Installation

This repo is delivered through **Extensibility → Git Repositories** — it is synced
as source, never pip-installed:

1. Add the repository URL with the **Jobs** provided content.
2. Sync. Nautobot imports the `jobs` package and registers the jobs.
3. Enable **Test Suite Capture** and (for development) **Test Suite Shakedown**
   under Jobs (jobs arrive disabled by design; the
   shakedown is additionally hidden from the default list).

Worker requirements: `requests` and `netmiko`, both already present on any worker
running Golden Config or Device Onboarding. Nothing else — every other import is
stdlib or Nautobot core, and `pyproject.toml` carries dev tooling only. Device
credentials come from the device's assigned Secrets Group (or a per-run override
group), never from job inputs; a server's BMC takes its credentials from the
Secrets Group associated with its interface through the `bmc_secrets_group`
Relationship (see *NFV compute* below).

## Usage: a firewall cutover

Replacing an HA pair of PA-5250s with VM-500s behind a pair of Catalyst 9500s:

1. **Capture pre.** Run *Test Suite Capture* with `change_id = CHG0031337`,
   `kind = pre`, a `change_description`, and both 9500s plus the **active**
   PA-5250 selected (each device collects everything its platform supports;
   splitting into separate runs with the same change id also works).
2. **Cut over.** Do the change.
3. **Capture post.** Same again, `kind = post`, same `change_id` — now
   targeting the active VM-500 as the firewall.
4. **Analyze.** Download the `snapshot_*.json` files from both capture
   JobResults and feed them, with your test-plan prompt
   (docs/llm-test-plans.md has a worked example for exactly this change), to
   the LLM your organization approves. Optionally build the deterministic
   diff index first so vanished routes arrive pre-enumerated:

   ```sh
   python3 tools/diff_snapshots.py --pre pre/*.json --post post/*.json -o diff-index.json
   ```

   Devices pair by name; the renamed firewall shows up as pre-only/post-only
   "replacement candidate" sections for the analyst — no mapping input needed.

### NFV compute (ESXi + XCC)

An SE350 running ESXi is **one `dcim.Device`** in Nautobot — the host — and
its XClarity Controller is an **Interface on that Device**, never a Device of
its own. Selecting the host captures both management planes into one
snapshot (no separate BMC artifact exists): the host's `vmware_*` checks and
the BMC's `bmc_*` checks, every entry naming its `target`, and the envelope's
`device.bmc` block naming the interface, the address dialled and every
address seen, the transport, the vendor and product the BMC reported,
whether the BMC was captured and, when not, why. Detection does not
depend on the host's platform — any Device carrying such an interface gets
its BMC captured — and there is no switch: a modelled BMC is always captured,
an unmodelled one never is.

- **The host** — Platform "VMware ESXi" (`network_driver` containing
  `vmware` or `esxi`), role `nfv-host`, `primary_ip` = the vmk0 management
  address, Secrets Group `esxi-readonly` holding an HTTP(S)/Generic-typed
  username + password for a **local ESXi user with the built-in Read-only
  role** (hostd enforces the boundary server-side). Nothing about it changes
  for the BMC: `vmware_host_identity` already reports `bmc_ip`/`bmc_mac` from
  the host's side, so the analyst can confirm that the modelled BMC is the one
  the host itself points at.
- **The BMC interface**, on the host Device: named `xcc`, or anything whose
  first word is a BMC token — `xcc`, `xclarity`, `imm`, `idrac`, `ilo`,
  `cimc`, `bmc` or `ipmi`, with words split on anything that is not a letter
  or a digit and trailing digits dropped, so `xcc`, `XCC-mgmt`, `iLO 5`,
  `idrac-1` and `bmc0` match while `mgmt-xcc` does not. Any type, `mgmt_only`
  recommended, **exactly one per Device**. Assign the BMC's address to it as
  an IP Address; with several, the lowest IPv4 (else the lowest IPv6) is
  dialled and all of them are named in `device.bmc.addresses_seen`.
- **A Secrets Group for the BMC**, e.g. `bmc-readonly`: a username and a
  password Secret associated with access type HTTP(S) (Generic works too —
  the lookup cascades RESTCONF → HTTP → REST → Generic).
- **The Relationship, created once** (Extensibility → Relationships): key
  `bmc_secrets_group`, label "BMC credentials", type *one-to-many*, source
  `extras | secrets group`, destination `dcim | interface`; then associate
  the group on each BMC interface. The job accepts the reverse orientation
  too (interface as source). On Nautobot 2.4.40, open the Relationship form
  and check that both models appear in its type dropdowns before relying on
  it (so far verified on a 3.2.5 dev stack only).
- **The BMC account**: a local BMC user with a **ReadOnly** privilege and
  Redfish access enabled — on an XCC the built-in ReadOnly role, or a custom
  role whose OEM privilege is ReadOnly; on XCC 6.10 ReadOnly reads everything
  the catalog needs. **A human completes its first-login password change**
  once in the BMC's web UI (the suite never writes to a BMC); until then every
  authenticated GET is refused, and the probe hint names the pending change.
- `vmnicN` Interfaces with Cables to the switch ports document the planned
  uplink map — the collectors never read the ORM, so this is for the analyst,
  not for capture.
- The VM-Series (or any other VNF with its own platform) stays its own Device:
  a `virtualization.VirtualMachine` row with a `vm_uuid` custom field is
  documentation only.

What the capture does with each modelled state:

| Modelled | Capture |
| --- | --- |
| No interface matches | Host only; `device.bmc` is null. |
| An interface matches but carries no address | Host only; `device.bmc` names the interface with `captured` false and the note "no address assigned"; a job-log warning. |
| Two interfaces match | The device fails before any transport opens — an ambiguous model never picks one. |
| The BMC's credentials unresolvable (no Relationship with the key, no association on the interface, several groups, no usable username/password) or the BMC unreachable (TLS, 401, 403, a pending password change, timeout) | Every `bmc_*` check recorded `failed` with the reason; the host checks still run; device FAILED. |
| The host's credentials or transport failing, an addressed BMC modelled | The BMC is still captured; every host check recorded `failed` with the reason; device FAILED. |
| The host's platform unsupported (it maps to none of iosxe, panos, vmware), an addressed BMC modelled | The BMC is captured alone: `device.host_captured` and `device.platform_supported` false, a job-log warning, and the device succeeds when its BMC checks do. Without an addressed BMC such a Device fails ("cannot map platform"). |

Before deploying this version onto a Nautobot that already documents BMC
addresses, list the devices it will start capturing a BMC for — every
device with an interface whose first word is a BMC token and an IP address.
Each of them FAILS (fail-closed) until its interface has the Relationship
and a Secrets Group, or while its BMC is unreachable from the worker. From
`nautobot-server nbshell`:

```python
import re

from nautobot.dcim.models import Interface

TOKENS = ("xcc", "xclarity", "imm", "idrac", "ilo", "cimc", "bmc", "ipmi")
for iface in Interface.objects.filter(ip_addresses__isnull=False).distinct():
    words = [word for word in re.split(r"[^A-Za-z0-9]+", iface.name) if word]
    if words and words[0].lower().rstrip("0123456789") in TOKENS:
        print(iface.device.name, iface.name)
```

The per-run `secrets_group` override applies to the host platforms only: a
BMC always uses the group its interface's Relationship names. A dry run
probes both planes, and `override_checks` filters both families. A Device
whose own platform names a BMC (`xcc`, `redfish`, `lenovo`) maps no platform:
model the BMC as an interface on its host instead (the "cannot map platform"
error says so).

Do not rename Devices across a change — `tools/diff_snapshots.py` pairs by
`device.name`. Location may change (it is stringified into the envelope, never
compared); if the management subnet is re-addressed, update `primary_ip` (and
the BMC interface's IP address, which the capture dials) between captures
and let `vmware_vmknics` / `vmware_host_routes` / `bmc_manager_network`
document the before/after. Host and BMC are both HTTPS to the management
plane only: nothing here proves forwarding through the VNFs.

## Check catalog

Tiers: **1** keyed assertions, **2** full-table diffs, **3** context recorded for
the humans reading the report. Platform `bmc` is not a Device platform: those
checks run against the BMC modelled as an interface on a host Device (see
*NFV compute* above), beside the host's own checks, and each records in
`context.resolution` how the BMC's System, Manager and Chassis were found and
which vendor the BMC reports.

| Check id | Platform | Tier | Description |
| --- | --- | --- | --- |
| `iosxe_routes_rib` | iosxe | 2 | Full RIB (all VRFs, v4+v6): prefix → protocol, preference, next-hops |
| `iosxe_route_rollups` | iosxe | 1 | Per-protocol route counts from the RIB, plus best-effort OSPF type splits |
| `iosxe_routes_fib` | iosxe | 2 | CEF FIB: programmed prefix → next-hops per forwarding instance (attached-host /32 adjacencies, which follow ARP, are counted in context and never keyed) |
| `iosxe_bgp_peers` | iosxe | 1 | BGP sessions per AFI/VRF/peer: state, remote AS, installed prefixes |
| `iosxe_ospf_neighbors` | iosxe | 1 | OSPFv2 adjacencies per instance/area/interface: neighbor state, address; every instance, area and interface state in context, so an empty view is explained (not-present when no instance runs) |
| `iosxe_fhrp` | iosxe | 1 | HSRP and VRRP gateway roles per interface/group: state, virtual IP, priority, preempt, active/standby (HSRP) or owner/master (VRRP); transitions, reasons and track states in context |
| `iosxe_eigrp_neighbors` | iosxe | 1 | EIGRP adjacencies per AFI/AS/VRF/interface: neighbor stub flags and software version (a listed neighbor is an established adjacency); SRTT/RTO/retransmit readings in context |
| `iosxe_isis_neighbors` | iosxe | 1 | IS-IS adjacencies per tag/level/interface: neighbor state and addresses; hold timers in context |
| `iosxe_arp` | iosxe | 2 | ARP tables, all VRFs: resolved MAC and interface per address, from `arp-entry` or, on a release that fills only the deprecated flat `arp-oper` list, from that one — context `source`, `entries` and `vrfs` explain the view |
| `iosxe_neighbors` | iosxe | 2 | CDP and LLDP neighbor tables combined: who is on which local port, with the CDP neighbor's platform string, native VLAN, duplex and voice VLAN; context `sources` says how each model answered (not served, served empty — as the lab 9300's `cdp-oper` was on earlier harvests — or n neighbors) |
| `iosxe_interfaces` | iosxe | 2 | All interfaces: admin/oper status, auto-negotiation flag, negotiated speed and duplex (while up; on the access ports the VLAN database names — from whichever `vlan-oper` list the release fills, minus the trunks `show interfaces trunk` lists — they move to context; `link_scope`, `access_port_source` and `trunk_ports_excluded` say which), storm-control blocking, mGig downshift, and the effective config (IPv4/mask, VRF, IPv6, MTU, ACLs, QoS policies; an unaddressed port's 0.0.0.0 reads None); CRC, error and flap counters in context, with wrapped uint64 readings and not-present ports' statistics named in context and never counted |
| `iosxe_platform_health` | iosxe | 3 | Boot time (epoch seconds with a 60 s compare tolerance for the device's own jitter, the served string in context), last reboot reason and severity (context names any reload leaf the device did not serve), active hardware alarms, environment sensor states in one vocabulary (normal / shutdown / not-present / warning / critical / fault; the served word — `Norm` on the lab 9300, `Normal` on older releases — and every reading in context; PSU input presence visible as the `Power Supply A/B` sensor states, or the P0/P1 family where a release reports it) |
| `panos_system_info` | panos | 3 | Software/content versions, model, serial, and hostname |
| `panos_ha` | panos | 1 | HA enablement, local/peer state, and running-config sync |
| `panos_session_info` | panos | 1 | Global session counts within tolerance of the baseline |
| `panos_session_meter` | panos | 1 | Per-vsys session counts within tolerance of the baseline |
| `panos_session_matrix` | panos | 1 | Per zone-pair session capability sweep |
| `panos_routes` | panos | 1 | Route table keyed by VR\|destination, routing engine detected |
| `panos_interfaces` | panos | 1 | L3 zone/IP/virtual-router bindings and link state |
| `panos_arp` | panos | 2 | ARP resolution status per IP |
| `panos_ipsec` | panos | 1 | IKE and IPsec SA presence per gateway/tunnel |
| `panos_licenses` | panos | 3 | Licensed features and their expiry flags |
| `panos_resources` | panos | 3 | Resource-monitor snapshot, stored verbatim (informational) |
| `panos_bgp_peers` | panos | 1 | BGP peer states, engine-aware (not-present when BGP is unused) |
| `panos_globalprotect` | panos | 3 | GlobalProtect user count (not-present when GP is unused) |
| `panos_dhcp` | panos | 3 | DHCP server lease overview (not-present when DHCP is unused) |
| `iosxe_dhcp` | iosxe | 3 | DHCP configuration under native/ip/dhcp: server pools, excluded addresses, relay options and the DHCP-snooping globals (not-present when unused) |
| `iosxe_routing_config` | iosxe | 2 | Static-route and router-stanza configuration (secrets scrubbed) |
| `iosxe_config` | iosxe | 2 | Full running-config and startup-config text as line lists (secrets redacted, the header's `by <user>` accounts masked with their clock kept, changes diff as line-level hunks) and whether the two match |
| `iosxe_syslog_errors` | iosxe | 3 | Syslog event counts from the logging buffer: every severity 0-3 event plus the severity 4-5 events of the port, redundancy, edge-service and platform facilities; buffer header and oldest-line facts in context; usernames and logged commands redacted before the text is parsed, stored or traced |
| `iosxe_svl_health` | iosxe | 3 | StackWise Virtual link membership and bundled state (not-present when the model is unserved or serves locations with no link) |
| `iosxe_ntp` | iosxe | 3 | NTP sync from ntp-oper: synchronized (derived), stratum, the kind of reference (address, KoD code, reference clock) and each association's health class; the selected peer and per-peer selection status in context (not-present until NTP is configured) |
| `panos_logging_status` | panos | 3 | Log forwarding status — is telemetry actually flowing |
| `panos_url_cloud` | panos | 3 | URL-filtering cloud connectivity |
| `panos_ntp` | panos | 3 | NTP synchronization state |
| `panos_pbf` | panos | 1 | Policy-based forwarding rules (not-present when PBF is unused) |
| `panos_drop_counters` | panos | 3 | Global drop-counter profile (informational canary) |
| `panos_nat_pools` | panos | 3 | NAT pool tables, raw-first (utilization is load-dependent) |
| `panos_rule_hit_counts` | panos | 2 | Security/NAT rule names with hit counts and last-hit times |
| `panos_ospf_neighbors` | panos | 1 | OSPF adjacencies, engine-aware (the firewall's view of the core) |
| `panos_crash_files` | panos | 1 | Core/crash files within the recency window |
| `iosxe_optics` | iosxe | 3 | Transceiver DOM light levels (tx/rx dBm) per optical port |
| `iosxe_crash_files` | iosxe | 1 | Crash/system-report files within the recency window on every stack member's filesystem (`dir`, field-verified), plus the q-filesystem model's core-file list (a YANG best guess pending a shakedown) |
| `iosxe_errdisable` | iosxe | 1 | Ports in err-disabled state with the triggering reason, from the interfaces model's intf-ext-state (`show interfaces status err-disabled` fallback) |
| `iosxe_port_channels` | iosxe | 1 | Port-channel bundles with per-member flags, plus each member's LACP state and partner identity (system-id, key, port) from lacp-oper where the release serves it |
| `iosxe_switch_stack` | iosxe | 1 | Switch stack members (role, state, serial, model matched by serial, reload reason, SSO-ready flag) and stack-port ring health (not-present when the platform does not stack) |
| `iosxe_inventory` | iosxe | 1 | Hardware identity on every platform form: model, serial, description and version of each chassis, module, power supply, fan and transceiver, keyed by name, else serial, else part number (an item with none of the three is counted, never keyed; device-inventory, `show inventory` fallback; an empty inventory is a failed read, never not-present) |
| `iosxe_vlans` | iosxe | 1 | Operational VLAN database (name, status) plus VTP mode/domain/revision (`show vtp status`, its MD5 digest redacted); per-port VLAN map in context inverted from whichever membership list the release fills (`port_map_source` says which; the 9300 fills `vlan-interfaces`, trunks under VLAN 1 whatever their native VLAN) |
| `iosxe_trunks` | iosxe | 1 | Trunk ports (short CLI names): mode, encapsulation, native VLAN and the allowed/active/forwarding VLAN sets as canonical ranges; where VTP pruning is on the forwarding set moves to context (`vtp_pruning` says which) (not-present when no port trunks) |
| `iosxe_stp` | iosxe | 1 | Spanning tree: mode and global guards, per-instance root facts (root port resolved to a name through port-num), and every port that is neither designated-forwarding nor disabled; topology-change counter and its age in context (the device serves the last-change time as an age from the 1970 epoch) |
| `iosxe_mac_table` | iosxe | 2 | Dynamically learned MAC counts per VLAN, stack member and port, evaluated as capability (an absent bucket post counts as zero; port buckets keep the release's spelling, `port_name_form` in context; statics, CPU group addresses and SVI MACs in context only; rows in raw, capped) |
| `iosxe_access_sessions` | iosxe | 1 | 802.1X/MAB/web-auth session counts per domain, method, landed VLAN and stack member from identity-oper, evaluated as capability (fields-filtered read only, never a username, never retried unfiltered; an empty answer is `total` 0; not-present only when the model is absent or rejects the filter) |
| `iosxe_poe` | iosxe | 1 | PoE port admin/oper/class per listed port (the observed 9300 releases list powered ports only, so a device that lost power is a removed key there; context `port_source`, `ports_total` and `poe_ports` say what this capture's release listed) plus StackPower mode, topology (ring/star/standalone), supply count, installed watts and each member's two cable ports; budgets and wattages in context (not-present on a non-PoE SKU or when the model is absent) |
| `iosxe_persistence` | iosxe | 1 | Would a reload bring back what runs now: whether the running config is saved (None where the release does not serve `unsaved-config`), the software version, the SDM template in effect and the one pending a reload (`show sdm prefer`, no model), and per install location the running image's version, commit state, auto-abort timer, boot mode and the full image list (abort-timer end time and ROMMON in context) |
| `iosxe_license` | iosxe | 1 | Smart licensing level in effect (network and DNA), registration, authorization, transport and per-licence enforcement state from `cisco-smart-license` (`show license summary` fallback); evaluation and expiry countdowns in context; never licence keys, tokens, account names or the UDI |
| `iosxe_pki` | iosxe | 1 | PKI trustpoints and certificates from `crypto-pki-oper` (`show crypto pki certificates` fallback when the model is absent or answers a server error): subject, issuer, usage, validity end, status and self-signed flag per certificate, including the factory SUDI chain and the self-signed default; an enrolled identity certificate (whose default CN is the hostname) is keyed by its issuer with its naming RDNs withheld in normalized and raw; days to expiry and expiring-soon tallies in context |
| `iosxe_tcam` | iosxe | 3 | Forwarding-table capacity and utilisation per ASIC region (`tcam-oper`) and datapath feature (`switch-dp-resources-oper`); `used_pct` carries a 5-percentage-point tolerance, the band word and every reading in context (not-present when neither model is served) |
| `panos_jobs` | panos | 1 | Unfinished commit/config jobs (history counts in context) |
| `panos_chassis_ready` | panos | 1 | Dataplane readiness (show chassis-ready) |
| `panos_disk_space` | panos | 3 | Filesystem use percentages within tolerance |
| `panos_panorama` | panos | 1 | Panorama connectivity per configured server |
| `panos_environmentals` | panos | 3 | Hardware environmental ALARM states (not-present on VM) |
| `panos_syslog_events` | panos | 3 | High/critical system-log event counts, last 24 h (time-bounded query) |
| `vmware_host_identity` | vmware | 1 | Host identity: vendor/model/serial/UUID, BIOS, ESXi build, CPU/memory totals |
| `vmware_hardware_inventory` | vmware | 2 | CPU packages, PCI devices (ids in hex) with passthrough/SR-IOV state, NUMA |
| `vmware_pnics` | vmware | 1 | Physical NICs: MAC, PCI, driver/firmware, link state, speed/duplex |
| `vmware_pnic_neighbors` | vmware | 1 | CDP/LLDP neighbor per physical NIC (not-present when discovery is off) |
| `vmware_vswitches` | vmware | 1 | Standard vSwitches: MTU, uplinks, teaming order, security, discovery |
| `vmware_portgroups` | vmware | 1 | Port groups: VLAN, effective security trio, teaming, override flags |
| `vmware_vmknics` | vmware | 1 | VMkernel NICs: port group, IP/mask, DHCP, MTU, netstack, services |
| `vmware_host_routes` | vmware | 1 | Per-netstack routes and gateways plus DNS configuration |
| `vmware_time_syslog` | vmware | 1 | NTP/PTP configuration and live sync state; syslog targets and options |
| `vmware_host_services` | vmware | 1 | Host services (running/policy), lockdown mode, MOB, vCenter membership |
| `vmware_advanced_options` | vmware | 1 | Curated advanced options (shell timeouts, MOB, network/memory/power knobs) |
| `vmware_firewall_rulesets` | vmware | 2 | ESXi firewall rulesets: enabled, allowed sources, default policies |
| `vmware_datastores` | vmware | 1 | Datastores: type, VMFS uuid, locality, capacity/free within tolerance |
| `vmware_storage_devices` | vmware | 1 | HBAs and local disks (HostScsiDisk): model, capacity, state, ssd/local |
| `vmware_health_sensors` | vmware | 1 | IPMI sensor health states and hardware element status (readings in context) |
| `vmware_autostart` | vmware | 1 | Autostart defaults and per-VM start order/delay/actions |
| `vmware_vlan_hints` | vmware | 2 | VLANs observed on each physical NIC from broadcast hints |
| `vmware_host_license` | vmware | 3 | Host license edition, usage, expiration and feature set (key redacted) |
| `vmware_vm_disks` | vmware | 2 | Virtual disks per VM: capacity, backing file/datastore, provisioning, mode |
| `vmware_recent_tasks` | vmware | 3 | Recent hostd tasks and the latest event (quiescence evidence) |
| `vmware_vms` | vmware | 1 | Registered VMs: identity, hardware, reservations, power state, snapshots |
| `vmware_vm_nics` | vmware | 1 | VM network adapters and PCI passthrough devices: MAC, backing, slot, state |
| `vmware_vm_tuning` | vmware | 1 | Per-VM NFV tuning: curated .vmx keys plus the modeled reservation fallbacks |
| `bmc_system` | bmc | 1 | System identity, health, boot override, SecureBoot, power-restore/delay/power-mode, host watchdog and host-console policy, TPM, Lenovo front-panel USB and TPM presence, and the BMC's own consoles, health/state and address (leaves a firmware does not serve read null, never "off") |
| `bmc_security` | bmc | 1 | The vendor security resource leaf by leaf (`security\|<path>`: TLS mode and minimum, HTTPS/LDAPS/CIM, firmware rollback, encapsulation) and the external key manager (`sklm\|<path>`, certificate collections counted, never read); ThinkEdge tamper state as nullable scalars (not-present only without a security resource or a vendor mapping) |
| `bmc_thermal` | bmc | 1 | Chassis temperature sensors and fans (Thermal, else ThermalSubsystem fans): health/state, ambient-class readings within 8 °C; DTS margins and the temperature summary in context |
| `bmc_power` | bmc | 1 | Power supplies (legacy Power, else PowerSubsystem supplies with LineInputStatus), redundancy and voltage rails (an SE350's external adapters are not modelled as supplies: rails only there) |
| `bmc_inventory` | bmc | 2 | DIMMs (ranks, widths, allowed speeds, Lenovo FRU/date/MPFA; empty slots keyed Absent), CPUs (CPUID signature, microcode, max speed, TDP, turbo) and PCIe devices with a `pciefn\|<device>\|<function>` row per function (POST-populated: an empty collection is a failed read) |
| `bmc_host_nics` | bmc | 1 | Host network ports as the BMC sees them: link status and burned-in MAC (ToManager excluded; context names the collection that carried them) |
| `bmc_firmware` | bmc | 2 | Firmware (and SoftwareInventory where linked): every component's version and SoftwareId, the image the BMC runs from, Lenovo backup auto-promotion (a version on a `-Pending` member is a staged update) |
| `bmc_event_log` | bmc | 2 | BMC logs read whole: platform Warning/Critical entries keyed `sel\|<code>\|<Id>` (serviceable and by whom, failing FRU, log type) and every unresolved ActiveLog condition `active\|<code>\|<Id>`; maintenance history, audit sequence numbers and the SEL probe in context; account names in messages scrubbed |
| `bmc_bios` | bmc | 2 | Every UEFI attribute (`bios\|<Attribute>`), settings armed for the next reset (`pending\|<Attribute>`, only where they differ), reset-to-defaults pending and the UEFI password-set flags (not-present when Bios is unserved) |
| `bmc_storage` | bmc | 1 | Controllers (cache, RAID levels, Lenovo mode and battery), drives (health, SED status, link speed, block size, write cache, Lenovo status) and volumes (RAID, cache/strip/boot policies), plus drives only the Chassis lists (not-present when none enumerate) |
| `bmc_manager_network` | bmc | 2 | BMC network, time and services: addressing, DNS (DMTF and Lenovo, DDNS), NTP and the Lenovo date/time service, DMTF and Lenovo protocols and open ports, KCS, and the host interface: its credential bootstrapping and the BMC's own USB-LAN address |
| `bmc_chassis` | bmc | 1 | Chassis and system-board identity, LEDs as `led\|<Name>` rows (color, state), the indicator LED, the operator-maintained Location record and the intrusion sensor |

What this catalog captures per network layer, and the holes still open ranked
by general value, is tracked in `docs/coverage.md` (the living coverage map).
The IOS-XE switch catalog is split into self-contained *layer modules*, each
holding its own checks, their `SEMANTICS` (merged into `registry.SEMANTICS` at
import) and a `KEY_MODELS` tuple naming the yang-library modules it reads (the
shakedown merges every module's list into `discovery.key_models`):
`jobs/checks_iosxe_layer2.py` (VLANs, trunks, spanning tree, MAC learning,
802.1X sessions), `jobs/checks_iosxe_layer3.py` (FHRP, EIGRP and IS-IS
adjacencies), `jobs/checks_iosxe_platform.py` (persistence, licensing, PKI,
TCAM), `jobs/checks_iosxe_poe.py` (inline power and StackPower) and
`jobs/checks_iosxe_wireless.py` (the 9800 catalog, gated on a controller).
`jobs/checks_iosxe.py` is the legacy core (routes, ARP, neighbors, interfaces,
platform health, config text, syslog, NTP, stack, inventory, crash files) whose
checks migrate into the layer modules one at a time; nothing new is added there.
`jobs/iosxe_common.py` is not a catalog: it holds the RESTCONF paths, the
filtered-GET-with-one-unfiltered-retry helper, interface-name and MAC
normalisation and the parsers two or more modules must spell identically, so the
per-run cache issues one GET per shared read. Modules are discovered by file
name (`jobs/checks_*.py`), so a new layer module registers without editing the
package, the jobs or the test loader.

## Always-everything capture

Capture-time subsetting (the old "test packages") is retired by doctrine:
every capture collects **everything the device's platform supports**, and a
mixed selection (core switches + a firewall in one run) collects per-platform
per device automatically. Features that are not in use record loudly as
`not-present` — that is information, not noise: BGP quietly appearing on a
firewall, or DHCP config vanishing from a switch, is exactly the kind of
change worth seeing. Subsets happen at **analysis time**, in the engineer's
test-plan prompt ("for this change, focus on the session matrix and routes").
`override_checks` remains as a development tool for running a single check.

## Catalyst 9800 wireless controllers

A 9800 is IOS-XE, so a controller runs under the same `iosxe` platform, job,
RESTCONF client and credential cascade as the switches — and gets the switch
catalog (routes, ARP, interfaces, NTP, syslog, boot time, crash files) for
free. The wireless checks live in `jobs/checks_iosxe_wireless.py` and decide
for themselves whether they landed on a controller: a chassis model naming a
9800 is one outright; otherwise one cached read of the AP name/MAC map decides
(joined APs present = a controller, which also covers embedded controllers on
switches). On an ordinary switch every wireless check records `not-present`
at the cost of that single GET. On a controller a 404 for wireless data is a
**failed read** — the wireless process is not serving data — never an unused
feature, while a positively read empty AP roster is real data and records as
zero APs with `ap_count: 0` in context.

| Check id | Tier | Description |
| --- | --- | --- |
| `wlc_ap_inventory` | 1 | Joined-AP roster: identity, software, mode, admin/oper state and resolved policy/site/RF tags |
| `wlc_ap_radios` | 1 | Per-AP radio state: band, admin/oper, channel, width, power and whether RRM or a human set them |
| `wlc_ap_uplinks` | 2 | AP-to-switch-port map (CDP/LLDP seen from the AP) and AP Ethernet link, speed, duplex |
| `wlc_ap_join_stats` | 3 | AP join history: boot/join times, join counters, disconnect and reboot reasons |
| `wlc_clients_summary` | 1 | Client counts per WLAN, AP, band and landed VLAN, evaluated as capability (the session-matrix analogue) |
| `wlc_client_table` | 3 | Per-client rows: AP, WLAN/SSID, state, resolved VLAN, learned IP — non-run clients always, run-state rows capped |
| `wlc_wlan_config` | 2 | WLAN, policy-profile and policy-tag configuration (PSK/WEP keys scrubbed) |
| `wlc_tag_config` | 2 | Site/RF tags, FlexConnect profiles with VLAN maps, static per-AP tag assignments |
| `wlc_mobility` | 1 | Mobility group identity and per-peer control/data tunnel state and flap counts |
| `wlc_platform` | 3 | Controller identity, wireless management interface, chassis roles, `show redundancy` |
| `iosxe_aaa_servers` | 1 | RADIUS server state per group/server — generic IOS-XE, not gated on the controller (switches doing 802.1X have the same failure mode) |

Every list is read with a RESTCONF `fields` filter (an unfiltered
`capwap-data` measures ~10 KB per AP); a release that rejects a filter gets
one unfiltered retry, noted in raw. Client usernames and device hostnames are
never requested, and WLAN/flex configuration is scrubbed of PSK, WEP and
password leaves before it reaches normalized or raw. Paths and leaf names
were checked against the published 17.12.1 YANG models — the AP roster, radio
and stack-oper reads are bench-verified on a 9800-CL by nautobot-upgrades —
so run the shakedown against the controller first: its module inventory lists
the wireless models the image serves, and its trace is the fixture harvest
that replaces the synthetic `tests/fixtures/wlc_*` captures.

Catalog modules are discovered by file name (`jobs/checks_*.py`) by both
`jobs/__init__.py` and the test loader, so a new platform is one new module
and no shared file edit — several platform branches merge without touching
the same line. The shakedown's `key_models` block is assembled the same way:
every discovered module's `KEY_MODELS` tuple is merged (de-duplicated, in
module-name order) onto the platform's base list, so a new module's models
show as served or absent without an edit to the shakedown.

## Read-only guarantee

The guarantee is structural, not procedural. The RESTCONF client
(`jobs/transport_restconf.py`) and the Redfish client
(`jobs/transport_redfish.py`) implement **GET only** — there is no method that
can change device state; the Redfish client additionally fences every path
(literal or server-supplied `@odata.id` link) to `/redfish/v1/` with no
`Actions` or `SessionService` segment and no percent-escape (the HTTP library
would decode `%41ctions` to `Actions` after the check) before a request is
formed, and uses Basic auth so no BMC session is ever created; a `Redfish
fence guard` CI step pins that wiring (the fence call and the single
`session.get` site in `_send`). BMC payloads also pass a redactor inside
`CollectorContext.get` before the debug trace, the per-run cache or raw see
them: key material and credentials are scrubbed by exact leaf name (so the
password *policy* leaves survive), user-name leaves outside the local-accounts
list keep only whether they are set and the logged-in-user list only its
length, and the account names Lenovo writes into its log messages are
scrubbed wherever the entry repeats them; a redactor that fails withholds the
answer and fails the read. The SSH runner (`jobs/transport_ssh.py`)
refuses any command that does not match a per-platform read-only allowlist
(the `show ` prefix; the display-only `request license info` on PAN-OS; and on
IOS-XE the crashinfo `dir` listings — `dir crashinfo-<N>:` per stack member
as an anchored, numeric-only shape, and `dir crashinfo:` / `dir stby-crashinfo:`
as exact commands (the fallback, and the only form on a device with no stack
roster), the bare `dir` verb still banned —
deliberately not `test`/`ping`, since e.g. PAN-OS `test vpn ike-sa` *initiates*
SA negotiation; future probe commands get individually vetted entries, and
`tests/test_transport_allowlist.py` locks the allowlist in CI) and never enters
config mode. Collectors reach devices exclusively through the
`CollectorContext`, so no check can smuggle in its own transport. It is
grep-auditable, and **CI enforces it** — the `Read-only guard` step fails the
build if this ever matches anything:

```sh
grep -rniE --include='*.py' 'send_config|config_mode|\.(patch|post|put|delete|request|send)\(|urlopen\(|http\.client|PreparedRequest' jobs/ | grep -v '^jobs/transport_vsphere\.py:'
```

**The one declared exception is vSphere.** A standalone ESXi host exposes
its complete read-only state only through the vim25 SOAP API, and SOAP is
HTTP POST by protocol — so `jobs/transport_vsphere.py` is excluded from the
verb grep and held to a different, equally structural fence: every envelope
comes from `jobs/vsphere_soap.py`, which forms bytes for exactly six
operations (`RetrieveServiceContent`, `Login`, `Logout`,
`RetrievePropertiesEx`, `ContinueRetrievePropertiesEx`, `QueryNetworkHint`)
and refuses any other name, any unfenced managed-object id and any property
path outside a per-type allowlist before a byte exists; and the credential is
a local ESXi user holding the built-in **Read-only** role, so hostd enforces
the same boundary server-side (a coding mistake yields `NoPermissionFault`,
never a change). CI's `SOAP operation guard` step pins this: the other write
verbs stay banned in that file, exactly one `.post(` call site exists inside
`_post_envelope`, which is called from exactly one place — the one caller of
`vsphere_soap.build_envelope` — so no hand-built envelope has a path to the
wire; the vim25 namespace may appear only in the two vSphere modules, the
`OPERATIONS` frozenset must exist, and a blocklist of state-changing
operation names (the refusal corpus under `tests/` plus any `*_Task`
spelling) must not appear in either module.

## Development

Python 3.9-compatible, Ruff-formatted at line length 100:

```sh
pip install ruff pre-commit
pre-commit install
ruff check . && ruff format --check .
python -m unittest discover -s tests -t . -v
```

The test battery is pure stdlib — `diffcore`, `envelope`, `panos_xml`, the
registry, the BMC interface rule (`bmc_target`), the Redfish path fence
(`redfish_paths`), the vim25 envelope
builder/parser (`vsphere_soap`, including its refusal corpus), and every
`_normalize_*` / `_parse_*` function run against fixture captures without
Nautobot, netmiko, requests, or a network. CI (`.github/workflows/ci.yml`)
runs the same commands plus `python -m compileall -q .` as an import smoke test,
the read-only grep guard and the SOAP operation guard.

### Bringing a collector up against a real device

1. Run **Test Suite Shakedown (dev)** against one device of the platform.
2. Read the advisories: `ok` needs nothing (a check whose healthy state is an
   empty view, such as `bmc_event_log` on a unit with nothing to report, reads
   "ok — empty is this check's healthy state"); "parsed but empty" means the trace
   payload holds the real leaf/element names — adjust the normalizer to match;
   "nothing fetched" is a path/transport problem (check the module inventory in
   `discovery`).
   - On an **IOS-XE switch** `discovery.q_filesystem` reads the full
     platform-software `q-filesystem` list, `partition-content` included (every
     file on every partition — unbounded, so only the shakedown reads it), and
     reports per location (`<fru>/<slot>/<bay>/<chassis>`) each partition's
     entry counts by type, the entries whose own name looks crash-related
     (`crash`, `core`, `system-report`, `koops`; the first 20 plus a total) and
     the `core-files` count with its first entries. Read beside the per-member
     `dir crashinfo-<N>:` listings in the same trace (a `koops.dat` with the
     same timestamp on both sides pins a location to a member), it settles
     what `iosxe_crash_files` still guesses about its YANG source: whether
     `chassis` is the stack member number, what `core-files` lists and whether
     its `filename` is a name or a path, and which partitions carry crashinfo.
     Until then the check's `dir` listings stay the field-verified source.
     `payload_chars` sizes the full read; past 1,000,000 characters the trace
     keeps a marker in its place (`trace_payload_trimmed`), so one unbounded
     list never pushes the trace past the 10 MB artifact limit, and the
     summary plus the check's own narrowed read (also in the trace) still
     answer all three questions.
   - On a device with a **BMC** modelled, `discovery.bmc` answers the
     questions a first run against a new BMC vendor or firmware must
     (`checks_bmc.DISCOVERY_PROBES`, run before the checks): the service root
     (`RedfishVersion`, vendor and product, `ProtocolFeaturesSupported` —
     whether `$expand` is advertised decides the per-check GET budget
     strategy — and the root links) with how the System, Manager and Chassis
     ids were resolved; which OEM links and scalars those three carry (the
     vendor security resource among them); every log service with its entry
     type, size, overwrite policy and sequence-number leaves; the member count
     of every collection the family reads or will read, with the host power
     state and (on Lenovo) `SystemStatus` — DIMM/PCIe/storage/host-NIC views
     are populated at POST, so run it once with the host on and once off;
     whether `$expand` inlines one level and whether `$levels=2` also inlines
     a member's own sub-collections and their members; which environment and
     hardware views the Chassis links (legacy `Thermal`/`Power` versus
     `ThermalSubsystem`/`PowerSubsystem`, `Sensors`, `EnvironmentMetrics`,
     `Controls`, `PCIeSlots`, `PCIeDevices`, `NetworkAdapters`, `Drives`); the vendor
     security resource's property names; the capture account's own role and
     privileges as the BMC reports them (no other account); and the platform
     log's sequence numbers before the checks (`log_sequence_before`) and,
     re-read past the cache, after them (`log_sequence_after`) — what the run
     itself wrote to the log, which on XCC 6.10 is nothing. A BMC that cannot
     be opened is reported under `bmc_error` while the host is still shaken
     down.
   - On an **ESXi host** it records the hostd build and `apiType`, which vim25
     namespace versions the host advertised (or that the fallback SOAPAction
     was used), `config.lockdownMode` as the Read-only user sees it, whether
     `QueryNetworkHint` returns a `connectedSwitchPort` per uplink (i.e. the
     far port advertises CDP — vSwitches only listen by default), whether
     `runtime.healthSystemRuntime` is populated and which half, whether
     `PhysicalNic` carries driver/firmware versions on this build, whether the
     deprecated live route table is still filled, and how large `config.option`
     is (it is curated before the raw cap). Every probe reuses the collectors'
     own fetches, so it costs no extra calls.
3. Turn real payloads into fixtures and commit them under `tests/fixtures/`,
   replacing the synthetic ones, so CI locks in the real shapes. Three
   steps, all stdlib apart from the transports the harvest needs, none of
   which ever prints a credential:

   1. **Harvest** every payload the catalog reads from the device with
      `tools/harvest_live.py` — every registered check through a real
      `CollectorContext`, then the whole containers and `show` layouts a
      fixture set wants — into a directory outside the repository (the raw
      harvest is unsanitized). The login comes from the environment only:

      ```sh
      set -a; . /path/to/device.env; set +a
      python3 tools/harvest_live.py --host 192.0.2.10 --platform iosxe \
          --tag baseline --out /path/outside/the/repo \
          --interface TenGigabitEthernet1/0/48 --interface Vlan3 \
          --user-env user --password-env pass
      ```

      It prints the per-check table (ok / not-present / FAILED with the key
      count), saves `get__*.json` / `ssh__*.txt` per request plus
      `results.json`, `trace.json` and `manifest.json`, and exits 1 when a
      check FAILED. A capture of an anomaly (a loop, a root elsewhere, a
      native-VLAN mismatch) is just another `--tag`.

      A server's BMC is harvested over Redfish with `--platform bmc`, through
      the worker's own `RedfishClient` (GET only, fenced, paced, Basic auth):
      every `bmc_*` check, then the reads a fixture set wants beyond them —
      every collection the family walks, with and without `$expand`, the
      pending BIOS settings object, the registries, every OEM link under the
      System, Manager, Chassis and NetworkProtocol, and the resources the
      planned checks will read. Each read passes the family's redactor
      (secrets, people's names and logged-in users; local account names are
      kept, they are configuration), but addresses, serials, MACs and UUIDs
      are real: the harvest is as unsanitized as any other. `--host-env`
      names the variable that holds the address, so it never appears on a
      command line either:

      ```sh
      set -a; . /path/to/bmc.env; set +a
      python3 tools/harvest_live.py --host-env host --platform bmc \
          --user-env username --password-env password \
          --tag baseline --out /path/outside/the/repo
      ```

      Against a new BMC vendor or firmware, the first thing to run — before
      the shakedown or the harvest — is `tools/redfish_walk.py`: a crawl of
      every resource the Redfish service serves to the capture account,
      through the same client (so GET-only, fenced and paced), following every
      link except `JsonSchemas`, registry files, single log entries and the
      AuditLog's entries (those only with `--audit`), one JSON file per
      resource plus `_index.json`, resumable from what is already on disk.
      The collectors and the fixture set are designed against what it finds.
      Its output is unsanitized too (log messages carry user names and client
      addresses), and it refuses an `--out` inside the repository:

      ```sh
      set -a; . /path/to/bmc.env; set +a
      python3 tools/redfish_walk.py --out /path/outside/the/repo/walk \
          --host-env host --user-env username --password-env password
      ```
   2. **Sanitize** one harvest into fixtures with `tools/make_fixtures.py`,
      which maps each harvest file to its fixture name (`--list` prints the
      table) and runs every one through the sanitizer with one mapping file
      kept beside the raw payloads, so a re-harvest invents the same values
      as the last one and diffs cleanly:

      ```sh
      python3 tools/make_fixtures.py --payloads /path/outside/the/repo/baseline \
          --map /path/outside/the/repo/sanitize-map.json --out tests/fixtures \
          --env /path/to/device.env \
          --host sw-real-01=sw-lab-1 --host AP0000.1111.2222=ap-lab-1 \
          --net 10.0.0.0/24=192.0.2.0/24 --net 10.0.1.0/24=198.51.100.0/24 \
          [--replace OLD=NEW] [--suffix _lab_hairpin --only iosxe_stp_details_lab.json]
      ```

      It discovers the user names the device prints in its own config and
      log texts (`username` lines, `[user: …]` login lines, `by <user>`
      headers) and maps them to `netops`, scrubs every value of the `--env`
      file, applies `--replace` literals (kept in the mapping file) for a
      string that identifies nobody but must not reach the repository, then
      scans every written fixture for anything real the mapping knows and
      exits 1 on a hit (counts only, never a value). `--suffix` / `--only`
      produce an anomaly capture's fixtures (`*_lab_hairpin.*`) beside the
      baseline set without overwriting it. On a BMC harvest it also runs a
      learn pass over every harvest file before writing any (a drive serial
      may appear first inside a boot-order string, a part serial only in a
      maintenance-log message), and the account names Lenovo writes into its
      log messages become distinct `user-lab-<n>` inventions like the local
      account names they belong to (the capture account from `--env` stays
      `netops`).
   3. **Grep** the written fixtures once more for the real hostnames,
      addresses, names and serials before committing;
      `tests/test_lab_fixtures.py` keeps a shape-based guard running in CI
      (every serial, address and device name in a `_lab` fixture must be an
      invention the sanitizer could have produced).

   The sanitizer underneath, `tools/sanitize_trace.py`, also runs on its own
   over a `shakedown-trace_*.json` or any payload file:

   ```sh
   python3 tools/sanitize_trace.py \
       --env /path/to/device.env \
       --host sw-real-01=sw-lab-1 --host AP0000.1111.2222=ap-lab-1 \
       --user someone \
       --net 10.0.0.0/24=192.0.2.0/24 --net 10.0.1.0/24=198.51.100.0/24 \
       --mapping-out /tmp/sanitize-map.json \
       --out-dir tests/fixtures  payload-a.json  show-b.txt ...
   ```

   It is deterministic: the same real value always becomes the same invented
   value, within a run and across runs that share its mapping file, so a MAC
   in the CDP fixture is the same MAC in the MAC-table fixture. In order:
   every value in the `--env` credential file (the `user` value becomes
   `netops`, the rest `REDACTED`; matched as whole tokens, so a user named
   `admin` never eats the leaf `admin-status`, and the values never reach
   stdout or the mapping file); `--host REAL=FAKE` hostnames and CDP/LLDP ids
   (an id that embeds a MAC is listed whole, an advertised FQDN with its
   domain); `--user` names to `netops`; PEM bodies, fingerprints, IOS
   certificate-chain bodies and any 16+-digit hex run to a short `<hex:N>`
   placeholder, self-signed trustpoint names renumbered; Cisco-shape serials
   (`ABC1234D5EF`) and `--serial` values to invented serials of the same
   letter/digit pattern; MACs in dotted, colon, dash or bare spelling to
   invented MACs in the same spelling, keeping the multicast and
   locally-administered bits (group addresses, the VRRP/HSRP virtual-MAC
   blocks and the all-zero "no partner" MAC are left alone); IPv4 addresses
   per `--net SRC/24=DST/24` with the host octet kept, any other real /24
   deterministically into 198.18.0.0/16, with masks, wildcards, loopback,
   multicast and the RFC 5737 ranges untouched — an integer `router-id` leaf
   (OSPF, EIGRP) is the same address in host order and maps the same way;
   IPv6 addresses with an EUI-64 identifier rebuilt from the invented MAC
   (a neighbour's link-local is the same device as its MAC-table row), a
   global or unique-local /64 landing in 2001:db8::/32, link-local prefixes,
   multicast and the documentation range untouched. Redfish payloads add
   rules by leaf name: UUIDs invented with their version nibble and variant
   bits kept (before the MAC rules, so a UUID's 12-digit tail is never read
   as a MAC); any leaf ending in `SerialNumber` — of any shape — invented with
   the same letter/digit pattern, and the same invention wherever that serial
   appears in text (`SN: …` in a log message, a default BMC hostname, a boot
   order entry); asset tags and phone numbers invented; `EntitlementId` and
   licence or feature-key `Identifier` leaves to `<id:N>`; `Fingerprint` and
   an SNMP engine id to `<hex:N>`; `HostName`/`FQDN` leaves to
   `bmc-lab-<n>`(`.lab.example`) unless a `--host` pair names them; account,
   login and contact leaves to distinct `user-lab-<n>` names; and key material
   by the same exact-name rule the `bmc` family scrubs with (password policy
   leaves survive). An env file's `username` is the user; its address-shaped
   values (`host`) are never `REDACTED` — the address rules invent them, so a
   fixture keeps an address where the device had one. JSON files are walked
   (keys and values); everything else is treated as text. Fixtures harvested
   this way carry a `_lab` suffix when a richer hand-built fixture of the
   same name stays beside them; `tests/test_lab_fixtures.py` pins what every
   normalizer reads from them. Without `--out-dir` the result goes to
   stdout; `--mapping-in` reloads an earlier run's mapping.
4. Re-run the shakedown until every check reads `ok` — then the platform is
   ready for a real pre/post cycle.

Licensed under Apache 2.0.
