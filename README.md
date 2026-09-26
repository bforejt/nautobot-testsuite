# nautobot-testsuite

Pre/post change-validation jobs for Nautobot. Snapshot a device before a change,
make the change, snapshot again, compare — and get a JSON verdict on the JobResult
that separates the diffs you *declared* you would cause from the ones you did not.

Two jobs, both under the **Test Suite** grouping:

- **Test Suite Capture** — runs every read-only check the platform supports
  against one or more devices (mixed platforms in one run collect per device) and attaches a versioned snapshot envelope (plus a raw-evidence bundle)
  to the JobResult: `snapshot_<device>_<change_id>.json` / `raw_<device>_<change_id>.json`.
  A `debug` checkbox additionally attaches `debug_<device>_<change_id>.json`: the
  full transport trace (every RESTCONF/Redfish path, SSH command and SOAP
  operation with timing, outcome, and payload — configuration text only in
  its redacted form), so even a FAILED check keeps its evidence.
- *(analysis happens outside Nautobot: download the snapshot files and feed
  them, with your test-plan prompt, to the LLM your organization approves —
  see below. `tools/diff_snapshots.py` builds an optional deterministic diff
  index locally.)*
- **Test Suite Shakedown (dev)** — hidden development job: runs *every* registered
  check for one device's platform in debug mode and attaches per-check verdicts
  with advisories ("parsed but empty — leaf names likely differ on this
  version"), a per-platform `discovery` block (yang-library module inventory
  and RIB/FIB naming on IOS-XE; Redfish version, `$expand` support, OEM links
  and collection counts on an XCC; hostd build, lockdown mode, CDP hearing
  and health-runtime population on ESXi), and the full payload trace. This is
  how collectors get validated
  against real devices *before* a change window, and how CI fixtures are
  harvested (sanitize captures before committing). Check failures do not fail
  the JobResult — surfacing them is the point.

Platforms today: Catalyst 9500 StackWise Virtual pairs and Catalyst 9300 StackWise
stacks on IOS-XE 17.x (RESTCONF plus allowlisted read-only SSH commands), PAN-OS
firewalls (SSH, XML op-command output), standalone VMware ESXi 8.x hosts set up
as NFV compute (vim25 SOAP, read-only operation allowlist) and — built, tested
and currently **switched off** by `constants.XCC_ENABLED` because the BMCs are
unreachable at the current sites — their Lenovo XClarity Controllers, the
ThinkSystem SE350 BMC (Redfish, GET-only). The two NFV platforms are modelled
as "ESXi set up as NFV compute" in general, never as a host for one particular
change: every check is always-on, and a feature that is not in use records
loudly as `not-present`.

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
group), never from job inputs.

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

An SE350 running ESXi is **two `dcim.Device` records** in Nautobot, one per
management plane, and both are selected for a capture:

- `<site>-se350-N` — Platform "VMware ESXi" (`network_driver` containing
  `vmware` or `esxi`), role `nfv-host`, `primary_ip` = the vmk0 management
  address, Secrets Group `esxi-readonly` holding an HTTP(S)/Generic-typed
  username + password for a **local ESXi user with the built-in Read-only
  role** (hostd enforces the boundary server-side).
- *(tabled — `constants.XCC_ENABLED` is False)* `<site>-se350-N-xcc` —
  Platform "Lenovo XCC" (`network_driver` containing `xcc`, `redfish` or
  `lenovo`), role `bmc`, `primary_ip` = the XCC address, Secrets Group
  `xcc-readonly` holding a **ReadOnly-role XCC account** (Basic auth, no BMC
  session is ever created). When revived, the BMC will also be detected as an
  Interface on the host Device (names in `constants.XCC_INTERFACE_NAMES`, with
  an assigned address) and captured into its own
  `snapshot_<device>-xcc_<change_id>.json`.
- A `bmc_of` Relationship links the pair. `vmnicN` Interfaces with Cables to
  the switch ports document the planned uplink map — the collectors never read
  the ORM, so this is for the analyst and the expectations, not for capture.
- The VM-Series (or any other VNF with its own platform) stays its own Device:
  a `virtualization.VirtualMachine` row with a `vm_uuid` custom field is
  documentation only.

Do not rename Devices across a change — `tools/diff_snapshots.py` pairs by
`device.name`. Location may change (it is stringified into the envelope, never
compared); if the management subnet is re-addressed, update `primary_ip`
between captures and let `vmware_vmknics` / `vmware_host_routes` /
`xcc_manager_network` document the before/after. Both platforms are HTTPS to
the management plane only: nothing here proves forwarding through the VNFs.

## Check catalog

Tiers: **1** keyed assertions, **2** full-table diffs, **3** context recorded for
the humans reading the report.

| Check id | Platform | Tier | Description |
| --- | --- | --- | --- |
| `iosxe_routes_rib` | iosxe | 2 | Full RIB (all VRFs, v4+v6): prefix → protocol, preference, next-hops |
| `iosxe_route_rollups` | iosxe | 1 | Per-protocol route counts from the RIB, plus best-effort OSPF type splits |
| `iosxe_routes_fib` | iosxe | 2 | CEF FIB: programmed prefix → next-hops per forwarding instance |
| `iosxe_bgp_peers` | iosxe | 1 | BGP sessions per AFI/VRF/peer: state, remote AS, installed prefixes |
| `iosxe_ospf_neighbors` | iosxe | 1 | OSPFv2 adjacencies per instance/area/interface: neighbor state, address |
| `iosxe_arp` | iosxe | 2 | ARP tables, all VRFs: resolved MAC and interface per address |
| `iosxe_neighbors` | iosxe | 2 | CDP and LLDP neighbor tables combined: who is on which local port |
| `iosxe_interfaces` | iosxe | 2 | All interfaces: admin/oper status and IPv4 address |
| `iosxe_platform_health` | iosxe | 3 | Boot time, active hardware alarms, environment sensor states |
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
| `iosxe_dhcp` | iosxe | 3 | DHCP server/relay configuration (not-present when unused) |
| `iosxe_routing_config` | iosxe | 2 | Static-route and router-stanza configuration (secrets scrubbed) |
| `iosxe_config` | iosxe | 2 | Full running-config and startup-config text as line lists (secrets redacted, changes diff as line-level hunks) and whether the two match |
| `iosxe_syslog_errors` | iosxe | 3 | Error-and-worse syslog event counts from the logging buffer |
| `iosxe_svl_health` | iosxe | 3 | StackWise Virtual link membership and bundled state |
| `iosxe_ntp` | iosxe | 3 | NTP synchronization state |
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
| `iosxe_crash_files` | iosxe | 1 | Crash/system-report files within the recency window, on every stack member's filesystem |
| `iosxe_errdisable` | iosxe | 1 | Ports in err-disabled state with the triggering reason |
| `iosxe_port_channels` | iosxe | 1 | Port-channel bundles with per-member LACP flags |
| `iosxe_switch_stack` | iosxe | 1 | Switch stack members (role, state, model, serial) and stack-port ring health (not-present when the platform does not stack) |
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
| `xcc_system` | xcc | 1 | System identity, health, boot settings, SecureBoot and the XCC's own address |
| `xcc_security_state` | xcc | 1 | ThinkEdge Security Pack state: lockdown, motion/intrusion detection, SED (not-present on non-ThinkEdge units) |
| `xcc_thermal` | xcc | 1 | Chassis temperature sensors and fans: health/state, ambient-class readings banded |
| `xcc_power` | xcc | 1 | Power supplies/adapters, redundancy and voltage rails from Chassis/1/Power |
| `xcc_inventory` | xcc | 2 | DIMM, processor and PCIe device inventory with per-part identity and health (POST-populated) |
| `xcc_host_nics` | xcc | 1 | Host network ports as the BMC sees them: link status and burned-in MAC (ToManager excluded) |
| `xcc_firmware` | xcc | 2 | Firmware inventory: every component's version and SoftwareId |
| `xcc_event_log` | xcc | 2 | BMC platform event log: Warning/Critical entries keyed `sel\|<CommonEventID>\|<Id>`, whole log, no query window |
| `xcc_bios` | xcc | 2 | Curated UEFI settings: VT-d, SR-IOV, HT, power/turbo, boot mode, TPM (not-present when Bios is unserved) |
| `xcc_storage` | xcc | 1 | Storage controllers, physical drives (health, SED status) and RAID volumes (not-present when none enumerate) |
| `xcc_manager_network` | xcc | 2 | XCC network services: NTP, DNS, enabled protocols/ports, addressing origin |
| `xcc_chassis_location` | xcc | 3 | Operator-maintained chassis Location record and the intrusion sensor state |

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
the same line.

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
`session.get` site in `_send`). The SSH runner (`jobs/transport_ssh.py`)
refuses any command that does not match a per-platform read-only allowlist
(the `show ` prefix; the display-only `request license info` on PAN-OS; and on
IOS-XE the crashinfo `dir` listings — `dir crashinfo:` and
`dir stby-crashinfo:` as exact commands, `dir crashinfo-<N>:` per stack member
as an anchored, numeric-only shape, the bare `dir` verb still banned —
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
registry, the Redfish path fence (`redfish_paths`), the vim25 envelope
builder/parser (`vsphere_soap`, including its refusal corpus), and every
`_normalize_*` / `_parse_*` function run against fixture captures without
Nautobot, netmiko, requests, or a network. CI (`.github/workflows/ci.yml`)
runs the same commands plus `python -m compileall -q .` as an import smoke test,
the read-only grep guard and the SOAP operation guard.

### Bringing a collector up against a real device

1. Run **Test Suite Shakedown (dev)** against one device of the platform.
2. Read the advisories: `ok` needs nothing; "parsed but empty" means the trace
   payload holds the real leaf/element names — adjust the normalizer to match;
   "nothing fetched" is a path/transport problem (check the module inventory in
   `discovery`).
   - On an **XCC** the `discovery` block answers the questions the Redfish
     collectors were written around: `RedfishVersion`, whether the root
     advertises `$expand` (`ProtocolFeaturesSupported` — this decides the
     per-check GET budget strategy), which `Oem.Lenovo` links `Managers/1`
     exposes (the Security Pack resource among them, on ThinkEdge units), which
     `LogServices` branch `Systems/1` serves (`PlatformLog` vs `StandardLog`),
     and the member count of every collection the inventory checks walk —
     together with the host power state, because DIMM/PCIe/storage/host-NIC
     views are populated at POST. Run it once with the host on and once off.
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
3. Sanitize the interesting payloads from `shakedown-trace_*.json`
   (RFC 5737/1918 addresses, invented hostnames) and commit them under
   `tests/fixtures/`, replacing the synthetic ones, so CI locks in the real
   shapes.
4. Re-run the shakedown until every check reads `ok` — then the platform is
   ready for a real pre/post cycle.

Licensed under Apache 2.0.
