# Plan: the NFV core move (floors 6 → 5) and the VMware/SE350 test bundle

Status: **proposal** — nothing here is implemented yet. This document is the
output of a research-and-design pass (repo readers, VMware/Lenovo/Palo Alto
source research, three independent transport designs judged through three
lenses, a drafted check catalog with every check adversarially verified for
"exists on standalone ESXi 8.x / read-only / fits this repo", and a
completeness critique). Facts below carry the confidence the research
established; anything marked *shakedown* is settled only by the first live run.

## 0. Decisions taken (2026-09-24) and the doctrine that governs the build

- **Plan A accepted**: the CI read-only guard gains the `transport_vsphere.py`
  carve-out and a SOAP-operation guard step (§2c).
- Environment facts, for prompts and runbooks only: SE350s believed **gen-1**;
  VM-Series on **vmxnet3** in **L2 passthrough** mode with **HA peers on
  separate SE350s**, PAN-OS **11.2.7+**; the **management subnet moves** with
  the floor; **CDP is on** between the SE350 vSwitches and the switches.
- **XCC tabled (later the same day)**: the XCCs are unreachable at the current
  sites. The `xcc` platform is built, tested and switched off by
  `constants.XCC_ENABLED = False` (both jobs refuse an xcc device with an
  operator-facing message). When revived: the BMC is modelled as an
  **Interface on the SE350 Device** (name from `XCC_INTERFACE_NAMES`: xcc,
  xclarity, bmc, ilo, idrac, imm — with an assigned IP), not as a second
  Device; its evidence goes into a **separate
  `snapshot_<device>-xcc_<change_id>.json`**; XCC credentials still need a
  decision (per-run `xcc_secrets_group` override, a device relationship, or
  a second access type in the device's group).
- **Build it general.** The `vmware` platform is "ESXi set up as NFV compute",
  not "a host for this move": every check is always-on, `not-present` is
  recorded loudly, and collectors gather as much self-describing state as
  they can — readings and volatile fields go to context/raw rather than being
  dropped. Nothing in `jobs/` knows about floors, declared removals or this
  change. The "why for this move" columns below are analysis-prompt material
  and belong in `docs/prompts/`; the comparison is directed entirely by the
  engineer's custom prompt, per the README's always-everything doctrine.

## 1. The change and what the suite has to prove

A remote office collapses from two floors to one. The core moves: a Catalyst
9500 pair plus the NFV compute — Lenovo ThinkSystem SE350 edge servers running
ESXi 8.x, hosting the Palo Alto VM-Series firewall (and whatever other VNFs
share the boxes). Downstream, Catalyst 9300 stacks stay; access switches and
APs are *reduced* to fit the new footprint. The suite gets **direct local
access only** to the SE350s: no vCenter, no NSX, no Aria — treated as absent
and, in the transport, actively refused.

What differs from the firewall cutover the suite was built for:

| | Firewall cutover (done) | Core move (this plan) |
| --- | --- | --- |
| Firewall | replaced (PA-5250 → VM-500) | same VM-Series, same host — but the host is *carried* between floors |
| Core switches | untouched | physically moved, re-cabled, rebooted |
| Hypervisor | out of scope | **new platform**: the VM-Series' entire data path is vNIC → port group → vSwitch → vmnic → 9500 port |
| Downstream | untouched | 9300 stacks re-cabled to the core; access switches/APs removed *by design* |
| Hardware | switch only | SE350 chassis: shock-sensitive M.2/NVMe, DIMMs, risers, PSUs, and on Security Pack units a **tamper/motion lockdown that locks SED keys** |

So the bundle has to answer, per host, after the move: is it the same box with
the same parts and firmware; did it come back thermally and electrically
healthy; is every uplink on the intended floor-5 port; is the virtual wiring
byte-identical; is every VNF registered, powered, tuned and attached exactly
as before; and can each of those be joined to what the VM-Series says about
itself and what the 9500/9300s see.

## 2. Decision: how bytes reach the SE350s

Three designs were built independently and judged (read-only doctrine /
move-window feasibility / evidence value). Two of three judges picked the same
one; the third preferred SSH but grafted the same Redfish-first idea.

**Chosen: "out-of-band first" — two new platforms, both HTTPS via `requests`,
nothing enabled on the ESXi hosts, no SSH.**

### 2a. Platform `xcc` — Redfish GET-only to the XClarity Controller

- `jobs/transport_redfish.py`: `session.get()` with HTTP Basic auth against
  `https://<xcc>/redfish/v1/...`. XCC accepts Basic auth on GETs (Lenovo's own
  doc examples do this), so no `POST /SessionService/Sessions` is ever needed.
- Passes the existing CI read-only grep **byte-for-byte**. Ships first, with
  zero doctrine change, and can run the same afternoon it is written.
- Structural fence *before* a request is formed: path must start with
  `/redfish/v1/`, must not contain `/Actions/` or `SessionService`; the fence
  applies to server-supplied `@odata.id` links too, not just literals.
- Pacing ≥ 1 s between GETs, per-check GET caps (Lenovo tip HT512365 reports
  Redfish going out of service under stress on SE350; the tip itself returned
  403 during research — treat the number as prudent, not verified).
- Keeps answering while the host is powered off mid-move, and answers the
  Security Pack go/no-go before anyone lifts a chassis.
- Every Basic-auth GET lands in the XCC **AuditLog**; that log is therefore
  never a diffed view (the collector would diff its own footprint).

### 2b. Platform `vmware` — hand-rolled vim25 SOAP with a six-operation allowlist

- `jobs/vsphere_soap.py` (pure stdlib, loader-importable, CI-tested) builds
  envelopes for exactly `frozenset({RetrieveServiceContent, Login, Logout,
  RetrievePropertiesEx, ContinueRetrievePropertiesEx, QueryNetworkHint})` and
  refuses anything else before a byte exists. `jobs/transport_vsphere.py`
  sends them to `https://<esxi-mgmt>/sdk`.
- Why SOAP and not REST: the VI/JSON binding (`/sdk/vim25/...`) and the
  Automation API (`/api/...`) are **vCenter-only**; a standalone 8.x hostd
  answers 500/400 (third-party verified against 8.0.3 hostd; William Lam:
  "no"). The MOB, CIM/WBEM, SLP and SNMP are off by default and enabling any
  of them is a host change. pyVmomi is not on the workers. SOAP over `/sdk`
  is the only complete, read-only, stdlib-feasible source on a standalone host.
- Credential: a **local ESXi user with the built-in Read-only role**. hostd
  then enforces a second, server-side fence — a coding mistake yields
  `NoPermissionFault`, not a change. One `Login`/`Logout` per host per
  capture, self-declared in envelope context (account, login/logout ok) so an
  auditor can attribute the hostd `UserLoginSessionEvent` to the tool.
- Probe: `GET /sdk/vimServiceVersions.xml` (unauthenticated) for reachability
  and to pick the SOAPAction namespace instead of hard-coding one; then
  `RetrieveServiceContent` and **refuse if `about.apiType != "HostAgent"`** —
  a vCenter answering would violate the direct-host constraint, so it is
  enforced, not noted. `InvalidLoginFault` / `NoPermissionFault` / TLS errors
  map to a `probe_hint` so a lockdown or role problem is diagnosed at the
  *pre* capture, not on move day.
- Injection fence (grafted from the SSH design): every interpolated value is
  validated — moids fullmatch `[A-Za-z0-9._-]{1,160}` (Task moids such as
  `haTask-ha-host-vim.host.StorageSystem.refreshStorageSystem-123456789`
  exceed 64 chars, so the earlier 64 cap is wrong), property paths must be
  members of a per-managed-object-type frozenset, `<device>` is omitted (not
  emitted empty) when QueryNetworkHint means "all pnics". `tests/test_vsphere_soap.py`
  asserts refusal of everything else, plus a fake-ctx contract test that
  enumerates every `(operation, kwargs)` the collectors build and a refusal
  corpus kept under `tests/` (outside the grep's scope, so comments in `jobs/`
  never need to spell a forbidden name).

### 2c. The doctrine amendment, stated openly

SOAP is HTTP POST by protocol. The README's "GET only" sentence becomes false
for exactly one file, and the CI guard needs a carve-out. This is not a lexical
dodge (no `Session.send`/`http.client` trick to slip past the grep); it is a
declared extension of the *structural* guarantee:

- Existing guard step (as shipped after review): `--include='*.py'`, the verb
  list widened with `.send(|urlopen(|http.client|PreparedRequest` so no
  prepared-request or stdlib path slips past, and the exception filtered by
  **exact path** (`grep -v '^jobs/transport_vsphere\.py:'`, so a
  `jobs/sub/transport_vsphere.py` cannot inherit it).
- New **"Redfish fence guard"** step: `transport_redfish.py` must call
  `fence_path(path)` before sending and contain exactly one
  `self.session.get(` call site.
- New **"SOAP operation guard"** step: in `transport_vsphere.py` re-ban every
  other verb, assert exactly one `.post(`, `_post_envelope(` exactly twice
  (def + its one caller) and `S.build_envelope(` exactly once — so every
  envelope on the wire was formed by the allowlisted builder; `urn:vim25`
  may appear only in `vsphere_soap.py` and `transport_vsphere.py`; the
  `OPERATIONS = frozenset` line exists; a mutating-name blocklist (the
  refusal corpus plus any `<Name>_Task`) matches nothing in either file.
  Six bypass scenarios were verified to fail a guard in a scratch copy.
- README read-only paragraph: "RESTCONF and Redfish are GET-only; vSphere SOAP
  is POST by protocol and read-only by operation allowlist, enforced by a
  Read-only ESXi role on the server side."

**Plan B, documented and kept** if the team refuses the carve-out: SSH to the
ESXi shell via netmiko `terminal_server` (the `linux` device_type fails on the
`[root@host:~]` prompt — netmiko #1137, confirmed against current source),
prompt pattern anchored to `\[\w+@[\w.-]+:[^\]]*\]\s?$`, a *fullmatch* esxcli
`list|get` / vim-cmd leaf allowlist with a `[A-Za-z0-9 ._:/=-]` character ban,
`--formatter=keyvalue|xml` (json is **not** in the official 8.0 formatter
list). Costs: TSM-SSH enabled with a persistent policy, `ESXiShellTimeOut`
relaxed (a hardened 3600 s stops the service between pre and post), an
**Administrator-role** account (no read-only shell role exists), and lockdown
exceptions — on every host, for the whole window. Uniquely yields pnic
error/CRC counters, the VIB list, live `esxcli network vm port list`
(port → team uplink) and `esxtop`-class data; those are the only things Plan A
cannot see.

## 3. Framework changes (verified against the tree)

| Where | Change |
| --- | --- |
| `jobs/snapshot_job.py:_map_platform` and the shakedown copy | add `"xcc"`/`"redfish"`/`"lenovo"` → `xcc` and `"vmware"`/`"esxi"` → `vmware` branches **before** the `"cisco"` test (a platform named "Cisco UCS ESXi" must not map to iosxe); fix the "to iosxe or panos" wording in both jobs and the Capture `Meta.description` |
| creds ternary (`"ssh" if platform == "panos" else "restconf"`) | becomes `TRANSPORT_FOR = {"iosxe": "restconf", "panos": "ssh", "vmware": "https", "xcc": "https"}`; `creds._access_types` already cascades any non-ssh label through RESTCONF/HTTP/REST/GENERIC, so `creds.py` is untouched |
| transport construction (`_capture_device`, shakedown) | the bare `else` (which today treats *any* unknown platform as PAN-OS SSH) becomes `elif platform == "panos"` plus two new branches; a failed Redfish probe / SOAP `Login` fails the device early exactly like PAN-OS `ssh.open()` does |
| `jobs/context.py` | Redfish duck-types the existing `restconf` slot (`get(path, timeout=, ok_404=)`, same cache/trace) so `Managers/1` is fetched once for all `xcc_*` checks and the shakedown "fetched" heuristic works unchanged — parameterise the trace `transport` label (hard-coded `restconf` today). vSphere gets an `api=None` slot and `call(operation, **kwargs)` mirroring `get()`'s cache+trace shape (outcomes `ok`/`not-found`/`cache-hit`/`error`), `has_api`, and `close()` over three slots. **`call()` must canonicalise sequence kwargs to tuples** — the cache key is `tuple(sorted(kwargs.items()))` and a list-valued `pathSet` raises `TypeError: unhashable` (reproduced). |
| exception ladder | add `VsphereError` / `RedfishError` to the tuple that records "failed" (or subclass `CollectError`) |
| `jobs/registry.py` | `CheckDef.platform` comment widened; a `SEMANTICS` entry (>40 chars, contract-tested) for every new id; `compare` declared on every new `CheckDef` (the drafts all omitted it — it is required) |
| `jobs/__init__.py`, `tests/_loader.py` | register `checks_vmware`, `checks_xcc`, `vsphere_soap` |
| envelope | `device.platform` keeps the raw driver string (`vmware-esxi` / `lenovo-xcc`) so prompts recognise it; new context block records the suite's own footprint (account, login/logout, GET count) |
| raw bundle | the 20 000-char per-property-set cap will truncate `config.option` (1 212 OptionValues, ~158 KB on 8.0U3), per-VM device arrays and SDR sensor lists — curate raw *before* capping (curated keys uncapped, sorted key=value remainder with an honest truncation marker); compute normalized from the full response, never from capped raw |

Shared-fetch rule (same pattern as `_fetch_rib` in `checks_iosxe`): the
`vmware_*` host checks request `config.network` / `config.option` /
`config.service` with **identical** `(operation, kwargs)` so the per-run
cache issues one `RetrievePropertiesEx` for all of them; a pathSet entry is a
bare dotted property path — **never** `foo[]` or `service[key='ntpd']`, which
are not PropertyCollector grammar and would (correctly) be refused by the
frozenset fence and fault `InvalidProperty` on hostd. Field selection is
client-side. Honour the `RetrieveResult.token` with
`ContinueRetrievePropertiesEx` (large arrays page). `RetrieveOptions` is
mandatory even when empty. Read `xsi:type` on every polymorphic element.

## 4. Nautobot modelling

Two `dcim.Device` records per SE350:

- `<site>-se350-N` — Platform "VMware ESXi", role `nfv-host`, `primary_ip` =
  vmk0 management IP, Secrets Group `esxi-readonly` (HTTP(S)/Generic-typed
  username + password).
- `<site>-se350-N-xcc` — Platform "Lenovo XCC", role `bmc`, `primary_ip` =
  XCC IP, Secrets Group `xcc-readonly`.
- Relationship `bmc_of` links them. `vmnic0..N` Interfaces with Cables to the
  9500/9300 ports are the *planned* floor-5 uplink map that
  `vmware_pnic_neighbors` expectations are rendered from.
- VM-Series stay PAN-OS Devices. Optional `virtualization.VirtualMachine`
  rows with a `vm_uuid` custom field are documentation only — collectors
  never read the ORM.
- **Do not rename Devices across the move**: `tools/diff_snapshots.py` pairs
  by `device.name`. Location may change (stringified into the envelope, never
  compared). If the management subnet moves, `primary_ip` is updated between
  captures and `vmware_vmknics`/`vmware_host_routes` document the before/after.

## 5. Check catalog

Tiers as in the README: 1 keyed assertions, 2 full-table diffs, 3 context.
Every check below survived two independent skeptics (existence/read-only and
framework/change fit) with corrections; the corrections are folded in.
Three drafts were refuted on a *claim* but kept as checks, redrafted:
`vmware_time_syslog` (the API does expose live sync state since 7.0.3),
`xcc_security_state` (the OEM URI is documented; the not-present rule had to
change) and `xcc_event_log` (no `MessageId` on Lenovo entries, `$top`
returns the oldest entries, and additions must carry the event code in the
key). The completeness critic then added `vmware_autostart`,
`vmware_vlan_hints`, `vmware_host_license`, `vmware_vm_disks`, `xcc_bios`,
`xcc_storage`, `xcc_manager_network` and `xcc_chassis_location`.

### 5a. `vmware` — host

| Check id | Tier | Source (bare pathSet on `HostSystem ha-host` unless noted) | Normalized view | Why for this move |
| --- | --- | --- | --- | --- |
| `vmware_host_identity` | 1 | `hardware.systemInfo`, `hardware.biosInfo`, `config.product`, `summary.hardware`, `config.hyperThread`, `summary.config.name`, `runtime.bootTime`, `summary.rebootRequired` | flat scalars (equality_scalar): vendor, model, serial (fallback to `otherIdentifyingInfo` ServiceTag/SerialNumberTag; record which populated it), uuid, bios_version, bios_release_date (ISO date string, never re-parsed), esxi_version/build, api_type, hostname, cpu_model/pkgs/cores/threads, hyperthreading_active (None when HT not exposed), memory_bytes. Context: boot_time, reboot_required | same box, same firmware came back; HT/memory totals are what VM-Series reservations rest on. hostname is config-derived — a change means re-addressing, not a swap |
| `vmware_hardware_inventory` | 2 | `hardware.memorySize`, `hardware.cpuPkg`, `hardware.numaInfo`, `hardware.pciDevice`, `config.pciPassthruInfo` | `cpu|<index>`, `pci|<0000:bb:ss.f>` → vendor/device, **vendor_id/device_id/class_id masked `& 0xFFFF` and rendered hex** (xsd:short: 0x8086 arrives as −32122), parent_bridge, is_vf, passthru_capable/enabled/active, sriov_capable/enabled/active, num_vf_requested/num_vf (dispatch on `xsi:type=HostSriovInfo`); scalars `numa|nodes`, `memory|bytes`. Exclude hz/busHz/cpuFeature/threadId | shock unseats cards; the X722 ports and any passthrough/SR-IOV device must return at the same PCI address with the same state. SEMANTICS must say VFs are their own `pci|` rows, so a VF-count change is N removed keys + one flipped `sriov_active`, not N unseated cards; enabled≠active = "reboot pending *or* device still claimed by a vmkernel driver" (7.0+ toggles live) |
| `vmware_pnics` | 1 | `config.network.pnic` | `pnic|vmnicN` → mac, pci, driver, driver_version/firmware_version (**8.0 U1+ only**; None on GA), link_up, speed_mb, duplex (**bool**, true=full), autoneg_supported, configured_speed_mb/duplex (None = auto). `wakeOnLanSupported`, `validLinkSpecification` raw-only | host-side half of "every uplink is up at the same speed after re-plugging"; MACs seed the switch-side placement proof |
| `vmware_pnic_neighbors` | 1 | `QueryNetworkHint` on `HostNetworkSystem` (moid from `configManager.networkSystem`, `networkSystem` on hostd; `<device>` **omitted**) + `config.network.vswitch` bridge config | `cdp|vmnicN` → device_id, port_id, platform (hardwarePlatform), native_vlan (CdpInfo.vlan; None when not advertised), mtu, mgmt_addr, address; `lldp|vmnicN` (never on a vSS — Broadcom KB 406133). Exclude samples, **timeout, ttl**, cdpVersion; subnet hints context-only. Context per vSwitch: bridge type, protocol, operation | **the** re-cabling check: each SE350 uplink terminates on the intended 9500/9300 port from the host's own view. SkipCheck only when every *bond-bridged* vSwitch reports operation `none` (treat `advertise` like `none`: hears nothing by config); `spec.bridge` is polymorphic and optional — only `HostVirtualSwitchBondBridge` carries it, unset means ESXi default `listen`. Empty table with CDP on = a **finding**, not not-present |
| `vmware_vswitches` | 1 | `config.network.vswitch`, `config.network.proxySwitch`, plus `pnic`/`portgroup` to resolve keys (`key-vim.host.PhysicalNic-vmnic0`) to names | `vswitch|<name>` → mtu, num_ports_configured (`spec.numPorts`; runtime numPorts is elastic 1536/2560 — context), uplinks (sorted), portgroups (sorted), promiscuous/mac_changes/forged_transmits, teaming_policy, **active_uplinks / standby_uplinks ordered, never sorted**, notify_switches, rolling_order, beacon_probing, discovery_protocol/operation (None on an uplink-less vSwitch); `proxyswitch|count` (absent property → 0) | what turns re-cabled vmnics into the VM-Series data path; the CDP operation decides whether the neighbor check can see anything |
| `vmware_portgroups` | 1 | `config.network.portgroup` | `portgroup|<spec.name>` → vswitch (spec.vswitchName), vlan_id (4095 = VGT trunk), effective security trio and teaming_policy/active/standby/notify/failback from **computedPolicy**, `security_overridden`/`teaming_overridden` computed **per leaf** (hostd returns empty `<security/>` containers on inheriting port groups). Attached port count **raw only** (moves with VM power state) | hypervisor half of the trunk contract; an ESXi reinstall/config restore after a failed post-transport boot resets security to Reject/Reject/Reject and blackholes the VM-Series. In L3 mode VM-Series still needs MAC-changes/forged Accept unless hypervisor-assigned MACs are on; HA (floating MAC) needs both regardless |
| `vmware_vmknics` | 1 | `config.network.vnic`, `config.virtualNicManagerInfo` | `vmk|vmkN` → portgroup (None on DVS/opaque), ip, netmask, dhcp, ipv6_static (origin == `manual` only), mtu, mac (vmk0 inherits the pnic's burned-in MAC — stable), netstack, services (resolved via `selectedVnic` strings shaped `<nicType>.<vnic.key>`, joined on **key**, not device). `candidateVnic` dropped from raw | lead with **vmk MTU vs the floor-5 switchport MTU**; documents the declared management re-address if any; a DHCP vmk's ip is informational |
| `vmware_host_routes` | 1 | `config.network.routeTableInfo`, `ipRouteConfig`, `netStackInstance`, `dnsConfig` (no `maxObjects`) | `route|defaultTcpipStack|<net>/<len>` → gateway, device (routeTableInfo is default-stack **state** only — deprecated since 5.5 but still populated on 8.x, *shakedown*); `route|<stack>|…` from `netStackInstance[].routeTableConfig` (config, unwrap `HostIpRouteOp`); `gateway|<stack>`; `dns|hostname/domain/servers/search` (ordered — a primary-DNS swap is a signal), `dns|dhcp`. IPv6 routes included or the exclusion stated | makes an intended re-address visible and an unintended one loud. Observable failure is a *changed* gateway, not a vanished default route (that fails the capture at transport) |
| `vmware_time_syslog` | 1 | `config.dateTimeInfo`, `config.service`, `config.option` (shared fetch) | flat scalars: ntp_servers (union of `ntpConfig.server` and `server` lines in `ntpConfig.configFile` — 7.0U3+ may leave `server[]` empty), time_services_enabled, clock_protocol (`ntp`/`ptp`), **ntp_service_sync** (`serviceSync`, the live in-sync flag, 7.0.3+), ntp_in_fallback, ntp_running, ntp_policy (`on` is the persistent expectation), syslog_loghost (**sorted list** — 8.x stores comma-separated multi-targets), syslog_logdir, logdir_unique, logCheckSSLCerts, logLevel. Exclude lastSyncTime, ntpRunTime, durations; `remoteNtpServer` raw. timezone is always UTC — raw only | an NTP/syslog target that lived on floor 6 is lost without any interface going down; `serviceSync` is the only field that would actually show it. Host clock seeds the VM RTC at the scheduled post-move VM-Series reboot |
| `vmware_host_services` | 1 | `config.service.service`, `config.lockdownMode`, `config.option` (shared), `summary.managementServerIp` | `service|<key>` → running (bool), policy, required — iterate what hostd lists, never assert a fixed set (slpd/sfcbd are deprecated on 8.0); `lockdown|mode`; `mob|enabled`; `vcenter|management_server` (**null on standalone — the real "was it joined" signal**; vpxa is always listed, `running` is the flip). HostService has **no** uptime field — do not claim one | catches what troubleshooting left enabled (TSM/TSM-SSH). Asymmetry to state: Disabled→Normal/Strict lockdown is unobservable here (the Read-only user cannot Login; the capture fails at transport instead); a reboot clears hand-started `policy=off` services — read as "reboot cleared it", regression is the other direction |
| `vmware_advanced_options` | **1** (keyed, ~15 rows) | `config.option` (shared; page with Continue…) | `opt|<key>` for a curated frozenset (ESXiShellTimeOut, ESXiShellInteractiveTimeOut, SuppressShellWarning, enableMob, Net.MaxNetifTxQueueLen, Net.CoalesceDefaultOn, Net.TcpipHeapMax, Mem.AllocGuestLargePage, Mem.ShareForceSalting, Power.CpuPolicy, Numa.LocalityWeightActionAffinity, Misc.BlueScreenTimeout, Security.AccountLockFailures, Security.PasswordQualityControl). **Drop `Net.NetNetqRxQueueFeatPairEnable`** — not exposed via OptionManager on 7.x/8.x (esxcli-only, Plan B). Type by xsi:type (string/int/**long**/boolean; else str). Context `{options_total, curated_absent}`; full sorted dict into raw, secret-token scrub applied | ESXi persists advanced options to `state.tgz` only hourly and on clean shutdown — **an unclean power-off during the move reverts every option edited since the last backup**; put that in miss_meaning. ESXiShellTimeOut only guards *humans'* access under Plan A |
| `vmware_firewall_rulesets` | 2 | `config.firewall` (one path; SkipCheck if absent — `firewallInfo` "may not be present") | `ruleset|<key>` → enabled, all_ip (True when `allowedHosts` absent), allowed (sorted ip / net/len); `firewall|incoming_blocked`, `outgoing_blocked`; 8.0U2+ `userControllable`/`ipListUserConfigurable` optional | a tamper detector (sshServer/snmp enabled during the move). Honest limit: if `vSphereClient` restricts the worker's *post-move* address the capture fails at transport before this check runs — that is a **pre-move** prerequisite, not a diff |
| `vmware_datastores` | 1 | `datastore`, `config.fileSystemVolume.mountInfo`; then `Datastore <moid> summary` | key set driven by `HostSystem.datastore` → `summary.name` (mountInfo lists BOOTBANK/OSDATA volumes too — enrichment only, join by `mountInfo.path == summary.url` stripped of `ds://`); `datastore|<name>` → type, uuid (**HostVmfsVolume/HostVffsVolume only**, None for NFS/VFAT; NFS identity = host:path), local (bool, VMFS), capacity_bytes/free_bytes (only when accessible), accessible, mounted. `compare={"mode":"equality_set","fields":{"free_bytes":{"tolerance":{"pct":10,"abs":10737418240}}}}` — pct is of *old free*, so a 10 GiB absolute bound is needed on a near-full M.2. Drop `multipleHostAccess` (vCenter-only). Empty list on a successful read → `{}` (report the removal with its old uuid), CollectError only for a failed read | M.2/NVMe are shock-sensitive and hold every VNF. A resignature shows as removed+added (`snap-<id>-<name>`); same name + new uuid = reformatted. `freeSpace` is timer-refreshed on hostd (refresh is a 7th op — not allowed); the band absorbs it |
| `vmware_storage_devices` | 1 | `config.storageDevice.hostBusAdapter`, `config.storageDevice.scsiLun` (absent property = CollectError) | `hba|vmhbaN` → driver, model, status (**diffed, never asserted** — `unknown` is normal for usb-storage), storage_protocol; `lun|<canonicalName>` **only for `xsi:type=HostScsiDisk` with deviceType `disk`** → vendor/model (stripped), capacity_bytes, device_type, operational_state (sorted), ssd/local (tri-state). Curate raw (drop standardInquiry/durableName/descriptor) | separates "drive gone" from "volume not mounted". Caveats to state: the XCC virtual-media cdrom LUN comes and goes with the mount, not the hardware (hence the disk-only filter); `mpx.*` names embed the vmhba number and can renumber after a power-cycle (naa./t10./eui. are stable); behind the M.2 mirroring kit or a RAID adapter an unseated *member* leaves the virtual LUN "ok" — pair with `xcc_inventory`/Redfish storage for members |
| `vmware_health_sensors` | 1 | `runtime.healthSystemRuntime` (one path; absent from propSet — no fault — → SkipCheck) | `sensor|<base-name>` → health (`.lower()`), type — **strip the ` --- <reading text>` suffix hostd appends to discrete sensor names** (`Fan Redundancy --- Fully Redundant`) or every state change is removed+added; suffix `|<id>` on collision; `status|cpu|…`/`memory`/`storage` (**capitalised** enum, lowercase it; commonly empty with sfcbd off — SkipCheck only when *both* halves are empty). Readings context-only, scaled `currentReading * 10**unitModifier` | cheap inside view that works when the XCC network is not reachable from the worker; corroborates the Redfish checks. hostd refreshes IPMI on a timer: a POST capture minutes after boot shows `unknown` — schedule it later or declare unknown↔green benign |
| `vmware_autostart` | 1 | `config.autoStart` → `HostAutoStartManagerConfig.defaults` {enabled, startDelay, stopDelay, waitForHeartbeat, stopAction} + `powerInfo[]` keyed by VM moid (resolved to name via `vmware_vms`) | `autostart|<vm>` → start_order, start_delay, start_action, stop_action, wait_for_heartbeat; scalars `autostart|enabled` and the defaults | **a standalone host with no vCenter/HA relies entirely on autostart to bring the VM-Series and every VNF back after the post-move power-on.** A VM missing from `powerInfo`, a shuffled order (the firewall before its dependencies, or an HA peer first), or `defaults.enabled` false is the single most likely "everything is green but the firewall never came up" outcome. The critic rated this the most important omission |
| `vmware_vlan_hints` | 2 | same `QueryNetworkHint` call: `PhysicalNicHintInfo.subnet[]` {vlanId, ipSubnet} and `network[]` | `vlans|vmnicN` → sorted list of observed vlanIds (equality_set, the trunk plan is the expectation); ipSubnet stays context (churns) | host-side proof of which VLANs' traffic each uplink actually hears — the "wrong VLAN on the new floor's switch port" detector when CDP is silent. Hints are learned from observed broadcast: the POST capture must follow several minutes of link-up |
| `vmware_host_license` | 3 | `LicenseManager <serviceContent.licenseManager>` `licenses` (adds LicenseManager to the per-type frozenset; Read-only role can read it) | edition_key, name, total/used, expiration (from properties); **licenseKey redacted to the last 5 chars** | an ESXi host in evaluation mode whose 60-day clock expires during the window loses the ability to power on VMs; an edition change means someone re-licensed |
| `vmware_vm_disks` | 2 (or folded into `vmware_vms`) | `config.hardware.device` `VirtualDisk` entries | `vdisk|<vm>|<label>` → capacity_kb, backing file name, datastore, thin/eagerZeroed, disk_mode, controller/unit | a resignature or a restore from another host changes `backing.fileName`; `vmware_vms` only carries the .vmx datastore. Assert the VM-Series disk is 60 GB per Palo sizing |
| `vmware_recent_tasks` | 3 (info_only) | `TaskManager <serviceContent.taskManager>` `recentTask` with a **TraversalSpec** into `Task info.*` (one round trip, no per-task moid interpolation), `EventManager latestEvent` | `task|<info.key>` → description_id, state, entity, user (`xsi:type` of `<reason>`); context task_count, tasks_running, latest_event with **`is_own_login`** (it will almost always be our own `UserLoginSessionEvent` — it cannot say "who touched it last"; the honest claim is "quiescent right now"). Timestamps verbatim strings (py3.9 `fromisoformat` rejects `Z` + microseconds) | timestamped evidence the post capture ran on a quiescent host; retention ~10 min by hostd default, so it says nothing about autostart activity before that window. Shakedown will read "parsed but empty" on a quiet host — expected |

### 5b. `vmware` — VMs

| Check id | Tier | Source | Normalized view | Why for this move |
| --- | --- | --- | --- | --- |
| `vmware_vms` | 1 | `HostSystem.vm` → `VirtualMachine <moids as tuple>`: name, `config.uuid`, `config.instanceUuid`, version, guestId, `config.files.vmPathName`, hardware numCPU/numCoresPerSocket/autoCoresPerSocket (8.0.0.1+)/memoryMB, cpuAllocation, memoryAllocation, memoryReservationLockedToMax, latencySensitivity, cpuAffinity, `runtime.powerState/connectionState/bootTime/question`, guest state/tools/hostName, `snapshot` | `vm|<name>` → uuid (**the PAN-OS `vm-uuid` join key**), instance_uuid (**optional — typically unset on never-vCenter-managed VMs; None is not identity loss**), hw_version, guest_id, power_state, connection_state, num_cpu, cores_per_socket, memory_mb, cpu_reservation/limit/shares, mem_reservation_mb, mem_locked_to_max, latency_sensitivity, cpu_affinity, tools_running/version_status, guest_hostname, datastore (from vmPathName), snapshot_count (**recurse `childSnapshotList`**), **has_pending_question** (the `msg.uuid.altered` "moved or copied?" detector — powerState says on, guest never boots). Fixed field set; omitted optionals → None. SkipCheck when the host has no VMs. Tolerate `missingSet` on orphaned/inaccessible registrations | every VNF comes back exactly as it was. Causality to get right in SEMANTICS: `latency_sensitivity` is config and never "drops"; `high` with `mem_reservation_mb < memory_mb` means it is no longer honoured and the VM refuses to power on. snapshot_count should be 0 on a VM-Series (Palo: snapshots "should not be used" — best practice, not licensing) |
| `vmware_vm_nics` | 1 | `VirtualMachine`: name, `runtime.powerState`, `config.hardware.device`, `config.extraConfig`; Login with `locale=en` | select devices **by presence of `<macAddress>`** (any VirtualEthernetCard subclass — the draft's five-type list missed PCNet32/vmxnet/vmxnet2/vrdma) plus `xsi:type=VirtualPCIPassthrough` under a separate **`pcidev|<vm>|<label>`** prefix (GPU/NVMe share that class; no MAC). `vnic|<vm>|<label>` → adapter_type, mac (lowercase), address_type (`generated` on standalone; `assigned` = vCenter), backing (port group name — **also for SR-IOV**, it sets the VF's VLAN), pf (SR-IOV physical-function id; may be literal `Automatic-…`), pci_device / dynamic `allowedDevice` vendor:device for passthrough (Dynamic DirectPath has no `.id`), connected, start_connected, **pci_slot from `slotInfo.pciSlotNumber`** (not `extraConfig ethernetN` — labels and ethernet indices diverge after any remove/re-add), unit_number. `dvport`/`opaque` mapped, never crash. `connected` compared only when `powerState == poweredOn` on both sides | closes the chain vNIC → port group → vSwitch → vmnic → 9500 port. The MAC join to PAN-OS holds only with "Use Hypervisor Assigned MAC Addresses" on; otherwise join on pci_slot order (and `vm-mac-base` + index). A VM with zero adapters is removed keys, not not-present |
| `vmware_vm_tuning` | 1 | `VirtualMachine`: `config.extraConfig`, `config.latencySensitivity`, `config.cpuAffinity`, `config.cpuAllocation`, `config.memoryAllocation`, `config.memoryReservationLockedToMax`, `config.hardware.device` | `tune|<vm>|<vmx key>` for an **exact** curated set (sched.cpu.latencySensitivity, sched.cpu.min, sched.cpu.affinity — **absent and `"all"` normalise equal**, Broadcom KB 426009: Host Client writes `all` on any CPU edit —, sched.mem.min, sched.mem.pin, sched.mem.lpage.enable1GPage, sched.mem.pshare.enable, numa.nodeAffinity, numa.autosize, numa.vcpu.preferHT, numa.vcpu.maxPerVirtualNode, hypervisor.cpuid.v0, uuid.action, monitor_control.disable_mmu_largepages) plus prefixes `ethernetN.(coalescingScheme|pnicFeatures|ctxPerDev|filter*)` and `pciPassthru.(use64bitMMIO|64bitMMIOSizeGB)`; **never a bare `numa.*` prefix** (hostd rewrites `numa.autosize.cookie` at power-on). Plus the modeled fallbacks as `tune|<vm>|api:latencySensitivity`, `api:cpuReservationMHz`, `api:memReservationMB`, `api:memPinned`, `api:cpuAffinity` — hostd may keep these only in the modeled slot. SR-IOV/passthrough bindings are covered by `vmware_vm_nics`, not extraConfig (`pciPassthruN.id` lines are not reliably surfaced). Values coerced to str | the credible triggers are hands-on edits during the move (removing passthrough to boot, relaxing latency sensitivity when admission fails) or a rebuild from OVA — not re-registration, which never strips keys. Shakedown reads "parsed but empty" on non-NFV hosts — expected |

### 5c. `xcc` — SE350 out-of-band

| Check id | Tier | Source (GET) | Normalized view | Why for this move |
| --- | --- | --- | --- | --- |
| `xcc_system` | 1 | `/redfish/v1/Systems/1`; `/Systems/1/SecureBoot` (ok_404 → three Nones); `/Managers/1` (shared); `/Managers/1/EthernetInterfaces/NIC` directly (collection only as 404 fallback) — **never "first member"**: gen-1 documents `NIC` and `ToHost` (USB-LAN 169.254.x) and order is not guaranteed | equality_scalar: power_state, health, health_rollup, model, serial, sku, uuid, bios_version, cpu_count, memory_gib, boot_override (**string** `Disabled|Once|Continuous`, miss = `!= Disabled`), boot_override_target, secure_boot_enabled/current/mode, system_status (**`BootingOSOrInUndetectedOS` is the steady state under ESXi** — no Lenovo agent; say so or every analyst flags it), xcc_firmware, xcc_health (`Status.Health` else `Status.State`), xcc_ip, xcc_ip_origin (DHCP/Static — a re-leased BMC is not a reconfigured one), xcc_gateway, xcc_vlan_enabled + xcc_vlan (None when disabled), xcc_mac, eth_member_used. Context: reboot_count, power_on_hours, xcc_datetime | survives the host being down; proves which chassis is where, that it booted the intended way, and that the OOB path itself (possibly daisy-chained SE350 → SE350) works after re-cabling |
| `xcc_security_state` | 1 | `/Managers/1` → **`Oem.Lenovo.Security` link is documented** (`/redfish/v1/Managers/1/Oem/Lenovo/Security`, gen-1 guide) — but it exists on mainstream ThinkSystem too, so **not-present is decided by the ThinkEdge properties being absent**, never by the link. `SecureKeyLifecycleService` is the SKLM/KMIP *external key-manager* config, not SED state — read it only for `key_management` context. Every discovered `@odata.id` passes the fence | equality_scalar, every field optional and finalised from the first fixture: lockdown_mode (Active/Inactive — **property name unverified**, *shakedown*), lockdown_control (portal/xcc, unverified), motion_detection_enabled (`MotionDetection`), motion_threshold (`ThresholdLevel`/`StepCounter` on V2/XCC2; gen-1 has sensitivity/orientation instead — treat each generation's fields as optional), chassis_intrusion_enabled, host_shutdown_on_tamper (`HostShutdown`), sed_encryption_enabled (`EncryptionEnabled`). **Never echo `SED_AK`** (an action-valued setting); the fence keeps PATCH impossible on both OEM resources | the single biggest physical-move risk on Security Pack units, invisible from ESXi. Tamper signature to encode: `motion_detection_enabled` true→false **together with** lockdown Active is the lockdown itself (Lenovo disables motion detection on entering lockdown), not an operator edit. Post-move `lockdown_mode == Inactive` is an absolute assertion — it belongs in the analysis prompt. Kensington-lock removal and cover opening are triggers too; **removing the lock to move the chassis can itself trip it**. Whether an XCC ReadOnly user may GET the OEM resource: *shakedown* |
| `xcc_thermal` | 1 | `/Chassis/1/Thermal` (gen-1 still serves the pre-2020 `Thermal` resource; empty `Temperatures[]` after a 2xx JSON body = CollectError; non-JSON 200 raises like `RestconfClient`) | `temp|<Name>` (fallback `|<MemberId>` on duplicate Name) → health, state, physical_context, **reading_c only for Intake/Exhaust/Ambient** (CPU/DIMM/PCH readings are load-driven and the POST capture runs right after the VM-Series reboot — they go to context); `fan|<Name>` → health, state, reading, reading_units (RPM; a firmware flip to Percent must be self-explaining). Bands: `reading_c` abs 8, fan `reading` pct 25 (pct-of-zero passes only if post is 0 — a fan at 0 pre is itself a finding). `State == Absent` ≡ missing key; thresholds nullable → context. Match by Name, **not** `PhysicalContext` (`Intake` on gen-1, `Board` on XCC3) | the objective pre/post comparison of the thermal environment and the earliest warning that the floor-5 closet will cook the NFV core. SE350 fans are internal non-hot-swap — a fan going Critical after the move is transit damage, not "unplugged". Verify the 45 °C / 55 °C rating text against the SE350 product guide before it ships in every envelope |
| `xcc_power` | 1 | `/Chassis/1/Power` (`#Power.v1_6_0` on gen-1; SE350 V2/XCC2 documents `/Chassis/1/PowerSubsystem/PowerSupplies/PSUn` — add as fallback if V2 units ever join). The same URI accepts PATCH on XCC; the GET-only transport is what keeps it read-only — say so in SEMANTICS | key by **MemberId** (Name can be null): `psu|<MemberId>` → name, state (**raw string, enum never pinned** — `UnpluggedOrPoweredOff` is not a DMTF value; gen-1 most likely reports input loss as `Enabled` + Health `Critical`; *shakedown* records what a de-powered slot really shows), health, line_input_voltage (nullable; pct 10 band as a *change* signal), **input_in_range** (bool from `InputRanges` Min/Max — a 120 V → 208 V rack feed is a legitimate ~75 % change, not "out of spec"), capacity_w, serial/firmware/model (nullable, None never `''`); `redundancy|<MemberId>` → mode, state (`Disabled` + Health OK = single-feed), health, member_count (**only when `Redundancy[]` present**); `voltage|<MemberId>` → state, in_threshold (Lenovo's sample has no Health on Voltages). Context: power_consumed_w | losing a redundant feed is the most common silent outcome of a rack move and is only visible out-of-band. **SE350 caveat:** the node is fed by one or two *external* 240 W AC adapters (or a −48 V DC module), not hot-swap FRU PSUs — HT514429 shows XCC does track the slots and input loss, but serial/firmware/voltage may be null and the "redundancy gone" finding only exists on dual-fed units; confirm adapter count per site |
| `xcc_inventory` | 2 | `/Systems/1/Memory?$expand=.($levels=1)`, `/Systems/1/Processors?$expand=…`, `/Chassis/1/PCIeDevices?$expand=…` (ok_404; record which path answered + member count in context); per-member walk only when `$expand` is unsupported (*shakedown*); cap **16** GETs for this check | `dimm|<Id>` → slot, socket, service_label, capacity_mib, type, speed_mhz (firmware-scaled — Lenovo's example shows 21333; store as-is, never band), serial, part_number, manufacturer, health, state (unpopulated slots — if listed at all — emitted identically on both sides with serial/capacity None); `cpu|<Id>` → model, cores, enabled_cores, threads, health (**the SE350 CPU is soldered** — this family only carries health; drop `CurrentClockSpeedMHz` from raw); `pcie|<Id>` → manufacturer, model, firmware (per-part identity; not keyed again in `xcc_firmware`), serial, health, location (best-effort `Oem.Lenovo.Location.PartLocation.ServiceLabel` → `Slot.Location` → None; excluded from the diff if the shakedown shows it absent) | physical transport is the one time DIMMs and risers move; itemised proof every part came back. **Inventory is POST-populated** (UEFI/Host Interface), so it is valid only after the post-move POST completes — with the host off, PCIeDevices can return 200 with zero members and DIMMs read stale; an empty-200 collection is *unmeasured*, never "all devices gone". Record `Systems/1.PowerState` in context. An unseated DIMM most likely shows as a **missing `dimm|` key**, not a State change. Whether the LOM module and M.2 adapters enumerate at all is unverified (HT509995: XCC GUI omits non-RAID M.2 NVMe on the SE350) — *shakedown* |
| `xcc_host_nics` | 1 | `/Systems/1/EthernetInterfaces`, then each member **except `ToManager`** (the USB Redfish Host Interface, not a port — filter by `@odata.id` before fetching) — or one `$expand` GET. Lenovo's own reference script reads `/Chassis/1/NetworkAdapters/{ob-X\|slot-Y}` → `NetworkPorts/{n}` first and falls back to `EthernetInterfaces`; a field report has onboard ports under one and PCIe NICs under the other — *shakedown* picks, ~7 extra GETs for one LOM | `nic|<Id>` → link_status (`LinkUp|LinkDown|NoLink` — NoLink = no cable/SFP vs LinkDown = cable but no link, useful to the cabling team), permanent_mac (identity; ESXi never overrides burned-in MACs, so it joins to `vmware_pnics.mac`), health, state. **speed_mbps context only** (null on gen-1 docs, 0 on XCC3 — normalise both to None). `description` dropped (constant vendor string, spelled "Enternal" in the docs). SkipCheck on 404, empty/absent Members, only-`ToManager`, or LinkStatus null on every member (a firmware that never reports host link state would otherwise diff false-green); 5xx = CollectError | per-port link answer independent of ESXi; cross-checks `vmware_pnics`. **"Readable while the host is off" is unproven** — host-port LinkStatus depends on NC-SI/MCTP sideband and may read LinkDown/NoLink in S5; the shakedown captures with the host off, pulls one cable, re-captures. Capture post in the *same host power state* as pre or declare an expectation. On wireless-LOM SKUs the 1 GbE ports sit behind the embedded switch — BMC port count ≠ vmnic count |
| `xcc_firmware` | 2 | `/UpdateService/FirmwareInventory?$expand=.($levels=1)` — one paced GET; precondition `GET /redfish/v1` `ProtocolFeaturesSupported.ExpandQuery.ExpandAll == true` (gen-1 advertises it, MaxLevels 2). Fallback: members **sorted by `@odata.id`**, and **never silently truncated** — past the per-check budget raise CollectError with the count in context. Lenovo's own gen-1 example has 15 members, so a per-member walk alone would exhaust a flat capture cap | `fw|<Id>` (BMC-Primary, BMC-Backup, UEFI, LXPM, LXPM*Driver, Ob_N.M, Slot_N.M, *.Bundle) → name, version (verbatim `<BUILDID>-<ver>`, e.g. `TEI3E4D-4.12`; Redfish's string "can be different to the Version displayed in Web or Legacy CLI" — recipe comparison is case-insensitive on the pair), software_id (stable; disambiguates two adapters sharing a Name), updateable, health (None when Status absent; **never emit Status.State** — the backup bank toggles StandbyOffline/Enabled after an XCC reboot). Excluded: ReleaseDate, `@odata.etag`, LowestSupportedVersion, Description, Oem.* | rules out "someone also updated firmware". The Lenovo recipe baseline (UEFI `hye134c-*`, XCC `tei3e4d-*`) lives in the **test-plan prompt / expectations, not in SEMANTICS** (rot-prone strings shipped in every envelope forever). Expect no PSU members (external adapters); whether the X722 LOM firmware appears here on gen-1 is unverified — if not, NIC firmware is carried by `vmware_pnics` alone. Driver binding: X722 → i40en, I350 → igbn |
| `xcc_event_log` | 2 | `GET /Systems/1/LogServices` and **branch on its Members**: `PlatformLog` if present (gen-1 guide; V2 documents it too), else the Purley-era `StandardLog` filtered to platform entries — the SE350 gen-1 (2019 firmware) sits between the two documented branches, *shakedown* decides. Then the service resource (context: `MaxNumberOfRecords` 1024, `WrapsWhenFull`, `FirstSeqNum`/`LastSeqNum`) and `…/Entries` **with no query string** — Members are inline full objects; follow `Members@odata.nextLink` through the fence if the firmware pages. **Never `$top`**: undocumented on XCC, DSP0266 says 501 for unsupported `$` params, and where honoured it returns the *first* N in service order — Lenovo's 234-entry sample lists Id 5 first, so `$top=100` would return the oldest entries and never show a new event; a count window over a >100-entry log also turns every post-move addition into a spurious `removed`. No `Managers/1/LogServices` fallback (undocumented on gen-1, and a manager-level log is where our own Basic-auth logins would land). **AuditLog never read** | Lenovo entries have **no `MessageId` and no `SensorType`**; `EntryType` is uniformly `Oem`. The FQXSP code is `Oem.Lenovo.CommonEventID`; read top-level `EventId` (the Oem copy is deprecated). Key **`sel|<CommonEventID>|<Id>`** for Severity Warning/Critical only — `diffcore` expectations cannot select an ADDED entry by value (`to`/`to_contains` apply to `changed` only, verified at `jobs/diffcore.py:318-332`), so the code must be in the key for a glob like `sel|FQXSPSE0000F|*` to bless the declared additions. Value: severity, source, serviceable, lenovo_message_id, hidden (keep `Oem.Lenovo.Hidden` entries flagged or counts won't reconcile with `LastSeqNum`). OK/Informational churn on a healthy re-capture (IPv6 link-local, DHCP, NTP, NM/SE events) — count them per CommonEventID in context, like `panos_syslog_events` keys only high/critical. Per-entry Created/Message go to **raw** (context is curated facts, never bulk); context: entries_total, newest_id/created, log_service_used, **log_cleared** (max Id decreased). Ids are the monotonic `EventSequenceNumber`, stable across the wrap | the BMC log records what POST/the BMC detected at **re-power** (AC-lost on restoration, intrusion latch, DIMM errors at POST) — with AC removed the XCC itself is unpowered, so it is not a live record of transit. Confirmed SE350 codes: `FQXSPSE0000F` chassis opened / `FQXSPSE2000I` closed, `FQXSPPP4025I` powered up via button, `FQXSPPP4035I` powered off by chassis control, `FQXSPPW0001I`/`FQXSPPW2001I` PSU added/removed. **No AC-lost, boot-complete, motion or lockdown codes found** in the public catalogue — *shakedown*; lockdown state is read directly (`xcc_security_state`), never inferred from the log |
| `xcc_bios` | 2 | `/Systems/1/Bios` `Attributes`, curated frozenset (documented on gen-1; attribute names *shakedown*-harvested) | `bios|<attr>` for VT-d/IOMMU, SR-IOV enable, hyper-threading, OperatingMode/performance profile, C-states/C1E, Turbo, boot mode UEFI/legacy, MMIO above 4G, TPM-related | a CMOS/RTC-battery reset or a UEFI-defaults load in transit reverts exactly the settings the VM-Series VNF tuning guide requires; `vmware_host_identity` sees only HT-active and `xcc_system` only SecureBoot |
| `xcc_storage` | 1 | `/Systems/1/Storage` → members → `Drives[]`, `Volumes[]` (whether non-RAID M.2 NVMe enumerates: HT509995 says the GUI omits it — *shakedown*) | `drive|<Id>` → serial, model, capacity_bytes, media_type, health, state, failure_predicted, life_left_pct (context), location; `volume|<Id>` → raid_type, health, encrypted | the SE350 M.2 Mirroring Kit is a RAID1 whose member failure is invisible to `vmware_storage_devices` (the virtual LUN stays "ok"); also the only view of the SED `Encrypted` flag |
| `xcc_manager_network` | 2 | `/Managers/1/NetworkProtocol` (NTP servers/enabled, HTTPS/SSH/IPMI/SNMP/VirtualMedia enabled + ports, HostName/FQDN) plus the NIC member's DHCP/static origin and DNS servers (shared GET) | flat scalars | the XCC's own time source and DNS timestamp the SEL and are what the ThinkShield portal reactivation path needs (outbound 443 + DNS from the **new** floor); an XCC that lost NTP after the power cut backdates every event `xcc_event_log` reports. 2 GETs |
| `xcc_chassis_location` | 3 (expected-change) | `/Chassis/1` `Location` {PostalAddress, Placement.Rack/RackOffset/Row}, `PhysicalSecurity.IntrusionSensor` if this firmware has it | flat scalars | the operator-maintained "where is this box" record **must** change with the move — declare it; unchanged post-move means nobody updated it. `IntrusionSensor` (Normal/HardwareIntrusion/TamperingDetected) is a DMTF-standard field worth a probe since no SE350 tamper event IDs exist |

GET budget: `xcc_system` alone spends 4–5 GETs and Lenovo's own
FirmwareInventory example has 15 members, so a flat 20-GET-per-capture cap is
unrealistic. Cap **per check**, keep the ≥ 1 s pacing, prefer one
`?$expand=.($levels=1)` GET per collection (the path fence must then allowlist
query parameters — `$expand`/`$select` only), and never silently truncate: a
check that would exceed its budget raises CollectError with the count in
context. Every Basic-auth GET is an XCC login and an AuditLog entry.

Power-state caveat, stated once for the whole family: the XCC *answers* with
the host off, but Memory/PCIe inventory and host-NIC link state are populated
at POST / via sideband, so those views are trustworthy only after the
post-move POST completes; `xcc_thermal`, `xcc_power`, `xcc_event_log` and
`xcc_security_state` are the genuinely host-independent ones.

### 5d. Deliberately not in the catalog

ESXi ARP/neighbor table, pnic error/CRC counters, VIB list, live vm-port →
uplink, `esxtop` (esxcli/PerformanceManager only → Plan B or the switch side);
host *event history* (`CreateCollectorForEvents` is a seventh, session-scoped
operation — only `latestEvent` is read); MOB/CIM/SNMP/SLP (off by default;
enabling is a host change); `/host` and `vm-support.cgi`; DVS/LLDP (no
vCenter; LLDP is impossible on a vSS); XCC AuditLog as a diffed view; the
wireless-LOM embedded NXP switch (only on the wireless SE350 package —
*open question*); Nautobot VM reconciliation inside a pure checks module.

## 6. Sibling changes on the platforms that already exist

- **PAN-OS join fields** (`jobs/checks_panos.py` `_SYSTEM_FIELDS`): add
  `vm-uuid`, `vm-cpuid`, `vm-license`, `vm-mode`, `vm-mac-base`; expose the
  hw MAC per interface in `panos_interfaces` raw; add `show system setting
  dpdk-pkt-io` (DPDK must match across HA peers or HA2 stays down) and `show
  system state filter-pretty cfg.vm-license-type` (a hidden licence-type
  mismatch makes HA non-functional) — both show-prefixed, allowed today. The analysis prompt then joins PAN-OS `vm-uuid ==
  vmware_vms.uuid` and hw MAC / pci-slot order `== vmware_vm_nics`.
  **Licensing is tied to VM UUID + CPUID**: a cold move can change either and
  it only manifests *after reboot* as serial `unknown` and dropped licenses —
  schedule the POST capture **after** the post-move VM-Series reboot, answer
  "I moved it" never "I copied it", and pre-arrange the Support re-key path.
- **`iosxe_mac_table`** (new IOS-XE check, `Cisco-IOS-XE-matm-oper`, keyed
  `infra-mac|<mac>` → vlan, port), seeded from `vmware_pnics`,
  `xcc_host_nics` and `vmware_vm_nics` MACs. No MAC-table check exists today
  (18 iosxe checks, none for it). **This ships with the change, not as a
  follow-on**: it is the only switch-side placement proof when CDP is not
  heard — ESXi vSS CDP defaults to `listen`, so the 9500/9300 will not see
  the host as a neighbor unless the host is set to `both` (a host-side
  setting; decide whether to declare it a prerequisite), LLDP is impossible
  on a vSS, and `iosxe_arp` reports the SVI, not the physical port (and only
  if the 9500/9300 is the L3 gateway of the management VLAN). It also proves
  the VM-Series dataplane MACs are learned on the right trunk.
- **`iosxe_host_facing_interface_config`** (new, config-equality like
  `iosxe_routing_config`, `Cisco-IOS-XE-native` interface subtree for the
  designated SE350-facing and 9300-uplink ports on the 9500 pair: switchport
  mode / trunk allowed / native VLAN, mtu, portfast/bpduguard, storm-control,
  `cdp enable`, speed/duplex, description, channel-group). The deterministic
  switch-side half of "wrong VLAN on the new floor's port": the floor-5 ports
  the SE350s are re-plugged into must carry the same trunk contract as the
  floor-6 ports, caught before any MAC is learned and even when CDP is
  silent. Ports come from the Nautobot Cable plan; the port move itself is a
  declared expectation. Note a vSS cannot run LACP (VDS-only), so SE350
  uplinks never appear in `iosxe_port_channels`; IP-hash teaming on the
  host would need a static EtherChannel on the switch — the trunk-contract
  mismatch most likely to blackhole after re-cabling. Confirm teaming mode.
- **Expectations engine limit (verified `jobs/diffcore.py:318-332`)**:
  `to`/`to_contains` select `changed` entries only; an ADDED entry can be
  blessed only by key glob. Any check whose declared post-move deltas are
  *additions* (event log, syslog, crash files) must carry the discriminator
  in its key — hence `sel|<CommonEventID>|<Id>` above.
- **`--expectations <json>` in `tools/diff_snapshots.py`** (~20 lines;
  `diffcore.normalize_expectations`/`classify_diff` and
  `envelope.summarize_report` exist and are tested; the CLI does not wire them
  today). Declared move deltas then classify deterministically:
  `vmware_pnic_neighbors` op=changed per vmnic to the planned floor-5 port
  (**`to` values in the long CDP form `TwentyFiveGigE1/0/1`**, not Nautobot
  short names); `vmware_host_routes` gateway if the mgmt subnet moves;
  `xcc_event_log` additions matching the declared CommonEventIDs; thermal/power
  within bands; one boot-time change per relocated chassis; `iosxe_neighbors`
  removals for decommissioned access switches; `iosxe_interfaces` oper=down
  for removed AP/access ports. Same manifest text goes into
  `change_description` and the prompt's EXPECTED DIFFERENCES block.

## 7. The other environment differences (follow-on IOS-XE work)

- **9300 stacks.** `iosxe_svl_health` correctly reads not-present on a 9300
  (`ok_404` + SkipCheck; SVL is 9400/9500/9600 only). Add `iosxe_stack_members`
  from `Cisco-IOS-XE-stack-oper` (present in the 17.12.1 bundle):
  `member|<chassis>` → role, state, priority, serial, mac, hw-version,
  stack-port-1/2 state and neighbour; scalars `stack|size`, `stack|ring-status`
  (**tier 1 — half-ring after the move = a stack cable not reseated**),
  `stack|ring-speed`, `stack|stack-mac`; reload-reason/boot times in context;
  `Cisco-IOS-XE-stacking-oper` as the simpler fallback, `show switch` family
  over SSH as last resort. Register always-on with SkipCheck so it reads
  not-present on the 9500 SVL pair, mirror-image of `iosxe_svl_health`.
  `dir stby-crashinfo:` covers active+standby; on 3+ member stacks add exact
  `dir crashinfo-N:` entries to `ALLOWED_EXACT`. Whether
  `device-hardware-oper` enumerates boot-time/alarms per member or
  active-only: *shakedown*.
- **Downstream connectivity.** Already covered with no new code:
  `iosxe_neighbors` run on both ends yields reciprocal CDP/LLDP pairs (pair
  them in the prompt), `iosxe_interfaces`, `iosxe_port_channels` (LACP member
  flags), `iosxe_errdisable`, `iosxe_arp`, `iosxe_optics`,
  `iosxe_syslog_errors`. New, models verified in the 17.12.1 bundle (whether
  each image *serves* them: shakedown yang-library): `iosxe_stp`
  (`Cisco-IOS-XE-spanning-tree-oper`; root must not move), `iosxe_lacp_partners`
  (partner system-id proves the Po re-formed to the same chassis),
  `iosxe_poe` (`Cisco-IOS-XE-poe-oper`, AP ports), trunk allowed-VLAN parse
  (`show interfaces trunk`), `show ip dhcp snooping binding` (no oper YANG
  model exists) — register always-on, not-present when unused.
- **Access-switch / AP reduction.** A declared-removal manifest per site
  `{hostname, 9300 uplink ports, Po id, LACP system-id, AP switchports/MACs/
  mgmt IPs}` generates expectations mechanically: every removal *not* in the
  manifest surfaces as unexpected; every manifest entry *still present*
  surfaces as `expectations_unmatched` (someone forgot to unplug it, or stale
  CDP holdtime). Wireless is untouched today; only a Catalyst 9800 WLC would
  fit the IOS-XE transport for an AP-count check — otherwise AP presence is
  proven indirectly via PoE/CDP/MAC on the 9300s.

## 8. Before the pre capture: shakedown discovery list

The shakedown must answer these on one host and one XCC, and harvest
sanitised fixtures (RFC 5737 addresses, invented serials/UUIDs/MACs) from
`shakedown-trace_*.json`:

ESXi: build + `vimServiceVersions.xml` namespaces + `apiType`;
`config.lockdownMode` and whether the Read-only user can `Login` (lockdown is
settable from the DCUI even without vCenter); whether `QueryNetworkHint`
returns any `connectedSwitchPort` (is CDP advertised on the 9500/9300
host-facing ports; vSS default is listen); whether
`runtime.healthSystemRuntime` is populated with wbem off, and which half;
whether `PhysicalNic` exposes driver/firmware version on this build;
`routeTableInfo` still populated; default-route rendering (`0.0.0.0`/0);
`selectedVnic` string shape; `config.network.portgroup` non-empty and
`proxySwitch` absent; whether `pciPassthruInfo` has a row per device or per
capable device; `HostPciDevice.id` form (`0000:18:00.0`); whether the
Read-only user gets the full `config.option` array and `config.extraConfig`;
envelope size per host; what an idle host shows in `recentTask`.

Also at the ESXi shakedown: one `curl` against the VI/JSON REST binding —
if a standalone 8.0U3 host now serves it, a GET-only client would fit the CI
guard with no carve-out at all (last known answer: no, Nov 2023); whether
`config.lockdownMode` is even settable on a standalone host (two briefs
disagree: Broadcom KBs say vCenter-only, the DCUI brief says toggleable);
whether `esxcli --formatter=json` exists (Plan B only).

XCC: `RedfishVersion`; `ProtocolFeaturesSupported.ExpandQuery` (decides the
`$expand` strategy and the whole GET budget); which `Oem.Lenovo` links exist
under `Managers/1` and the property names the Security resource actually
returns; whether a ReadOnly XCC role may GET the OEM resources; which
`LogServices` branch `Systems/1` serves (PlatformLog vs StandardLog) and the
AC-lost / boot-complete CommonEventIDs; `EthernetInterfaces` member Ids and
whether LinkStatus tracks a cable pull with the host off; how the external
240 W adapters appear under `/Chassis/1/Power` and what a de-powered slot
reports; Memory/PCIeDevices/Storage/FirmwareInventory member counts with the
host on *and* off, and whether the LOM module and non-RAID M.2 enumerate at
all; Temperatures/Fans Name uniqueness; `PhysicalContext` values; the SE350
thermal-envelope and shock figures verified against the product guide
before any number ships in SEMANTICS text.

## 9. Runbook gates the tooling can expose but not prevent

1. **Security Pack go/no-go** (`xcc_security_state`, pre-move): if the units
   have motion detection or chassis intrusion armed, carrying the chassis to
   floor 5 puts it in lockdown and SED authentication keys are denied until
   re-activation — ThinkShield Key Vault Portal needs **outbound TCP/443 from
   the XCC on the new floor**, or the mobile app via USB service port, or
   manual challenge/response in XCC. Confirm an off-box, password-protected
   SED AK backup exists and who holds the single Administrator+ owner
   account. Decide whether to disable motion detection for the window
   (declare it as an expectation if so). Removing an anti-tamper Kensington
   lock to move the box is itself a tamper trigger on some units.
2. **ESXi TPM-sealed configuration** (no collector can capture this): on
   TPM 2.0 hosts with UEFI Secure Boot, ESXi 7+/8 encrypts its configuration
   archive sealed to the TPM. A TPM clear or BIOS-defaults load in transit
   produces "Unable to restore system configuration. A security violation
   was detected" at boot and needs the recovery key. Run `esxcli system
   settings encryption recovery list` **by hand before the chassis is
   unplugged** and store the key off-box. `xcc_system` SecureBoot +
   `Systems/1 TrustedModules` give the post-move evidence only.
3. Record the XCC RTL8363SC daisy-chain order if XCC ports are chained (up
   to 7 hosts) — re-cabling can strand downstream XCCs.
4. Autostart is configured and ordered for every VM — verified in the PRE
   capture (`vmware_autostart`), never assumed. Agree the "moved or copied?"
   answer policy (always *moved*) with whoever will be hands-on.
5. The suite proves **state, not forwarding**: no ping/traceroute is
   allowlisted on any platform. The runbook needs a manual end-to-end test
   from an access switch through the VM-Series after the POST capture.
6. POST capture timing: ≥ 3 min after uplinks come up (Cisco CDP 60 s
   advertise / 180 s holdtime — earlier reads as a vanished neighbor; a PRE
   taken right after an unplug still shows the stale entry), several minutes
   after hostd is up (IPMI sensor timer), and **after** the post-move
   VM-Series reboot (licensing/UUID manifests only then).
7. Clean shutdown before power is pulled (advanced options persist hourly;
   an unclean power-off reverts recent edits — `vmware_advanced_options` will
   show it, the runbook should prevent it).
8. NTP/syslog targets and the worker's own reachability to vmk0 and the XCC
   IPs from the new floor: a `vSphereClient` ruleset restricting the worker's
   old address fails the POST capture at transport — check before, not after.

## 10. Implementation sequence and effort

Roughly six to seven engineer-days plus two shakedown half-days and a
rehearsal, sequenced so the doctrine decision is isolated and the go/no-go
evidence exists first. The battery stays green at every step.

0. **Decisions day (before code)**: Plan A carve-out vs Plan B; SE350
   generation / Security Pack / LOM / adapter count per site; re-addressing
   yes or no; floor-5 port map and the declared-removal manifest frozen in
   Nautobot; TPM recovery key and SED-AK backup gates run by hand.
1. **Framework plumbing PR** (no platform behaviour yet): `_map_platform`
   branches, `TRANSPORT_FOR`, explicit `elif panos`, `CollectorContext` api
   slot + `call()` with tuple-canonicalised kwargs (regression test for the
   list-kwarg `TypeError`), parameterised trace label, exception tuple,
   error strings, loader/`__init__` imports prepared.
2. **Redfish platform PR** — `transport_redfish`, `checks_xcc` (all eleven
   ids in §5c, security fields optional until the first fixture), SEMANTICS,
   hand-built fixtures from the Lenovo gen-1 guide examples. Zero doctrine
   change; runs the same day.
3. **XCC shakedown (one unit, host on *and* off)**: the XCC half of §8, a
   cable-pull test for `xcc_host_nics`, harvest and sanitise fixtures. This
   alone answers the Security Pack go/no-go and can gate the move date.
4. **vSphere SOAP PR** — the doctrine day: `vsphere_soap`,
   `transport_vsphere`, CI carve-out + SOAP operation guard, README, refusal
   corpus. (If refused: swap to Plan B's SSH profile; every `vmware_*` check
   keeps its id and normalized shape.)
5. **`checks_vmware` PR** — collectors sharing one cached fetch per property
   group (`config.network` once, `config.option` once, one per-VM property
   set for vms/vm_nics/vm_tuning/vm_disks/autostart), fixed field sets with
   explicit None defaults, raw curated before the cap, SEMANTICS, hand-built
   fixtures, contract + fake-ctx tests.
6. **ESXi shakedown (one SE350)**: the ESXi half of §8; if CDP is not heard,
   either enable it on the 9500/9300 host-facing ports (a declared switch
   change) or accept `iosxe_mac_table` as the placement proof.
7. **Sibling PRs**: PAN-OS fields; `iosxe_stack_members`, `iosxe_mac_table`,
   `iosxe_host_facing_interface_config`, `iosxe_stp`, `iosxe_lacp_partners`,
   `iosxe_poe`, trunk/snooping SSH parses — each SkipCheck-symmetric so 9500s
   and 9300s read not-present for each other's features — gated by a 9300
   shakedown of the yang-library inventory; `dir crashinfo-N:` allowlist
   entries.
8. **Expectations wiring**: `--expectations <json>` in `tools/diff_snapshots.py`
   with a unit test; a manifest → expectations generator under `tools/` (port
   map, re-address deltas, boot-time changes, `xcc_event_log` CommonEventID
   globs, thermal/power bands, access/AP removals); `docs/prompts/nfv-core-move.md`
   with the EXPECTED DIFFERENCES block generated from the same manifest text
   used in `change_description`. Also spec the IOS-XE/PAN-OS side of a
   re-address (SVI addresses, `ip route`, management IP, syslog/NTP targets)
   if re-addressing is chosen — no brief covers it today.
9. **Dress rehearsal, one week out**: full PRE capture across every device,
   a second capture an hour later, diff → zero unexpected diffs (the noise
   baseline; anything else is a normalizer fix), elapsed time pinned against
   the 3300 s soft limit (SOAP ~6–10 calls/host; Redfish ~40–60 GETs/XCC at
   ≥ 1 s pacing, summed in `constants.py`).
10. **Move day**: PRE with hosts steady → hands-on gates (§9) → move → POST
    only after POST completes, ESXi boots, autostart finishes and the
    VM-Series has rebooted, ≥ 3 min after link-up, same host power state as
    PRE → diff with `--expectations` → LLM analysis → repeat POST after any
    fix until clean → re-arm motion detection and update Chassis Location
    (declared).

### The analysis prompt, ranked

The prompt pairs, per host, `snapshot_<esxi>`, `snapshot_<esxi>-xcc`,
`snapshot_<vmseries>` and the 9500/9300 files. What matters most, in order:

1. **Identity invariants** per SE350: host serial/uuid/build/BIOS, XCC
   serial/uuid/model, firmware and BIOS settings all `== pre`. Declared:
   boot_time, reboot_count, power-on hours, Chassis Location.
2. **Security Pack**: `lockdown_mode == Inactive` post-move (absolute);
   motion true→false *with* lockdown Active is the tamper signature; event
   log additions limited to the declared CommonEventIDs — any added
   Warning/Critical thermal/PSU/DIMM/intrusion key is a hardware finding.
3. **Re-cabling chain per uplink**: `vmware_pnics` link/speed, `xcc_host_nics`
   LinkUp, `vmware_pnic_neighbors` port == the planned map (declared per
   vmnic), `iosxe_mac_table` shows the vmnic MAC on that port,
   `iosxe_host_facing_interface_config` on the new port equals the old port's
   trunk contract. A vanished CDP key is a finding, not silence.
4. **Virtual wiring unchanged**: vswitches, portgroups (incl. 4095 trunks,
   effective security, teaming — IP-hash implies a static EtherChannel),
   `vmware_vlan_hints` match the trunk plan, vmknics. Declared only: a
   management re-address if chosen.
5. **Every VNF back**: all VMs poweredOn, tools running, uuid unchanged,
   reservations/latency/affinity unchanged, snapshot_count 0 on VM-Series,
   `has_pending_question` false, autostart enabled with the same order, vNIC
   label/slot/backing/MAC unchanged and connected, tuning byte-identical,
   disk paths unchanged.
6. **VM-Series licence and HA after its reboot**: serial != `unknown`,
   vm-uuid == `vmware_vms.uuid`, vm-cpuid/vm-license unchanged, HA restored,
   dpdk-pkt-io and vm-license-type identical on both peers, HA1/HA2 port
   groups on both hosts if peers are split.
7. **Storage whole**: every `lun|` present and ok, datastores same
   uuid/name and accessible (free space banded), RAID1 members healthy, no
   missing DIMM/PCIe keys, memory_bytes == pre.
8. **Thermal and power**: Ambient/Intake within 8 °C, every sensor OK, fans
   in band, PSU/adapters Enabled+OK, input_in_range, redundancy intact on
   dual-fed units.
9. **Time and telemetry**: `ntp_service_sync` true, same servers, syslog
   targets unchanged; XCC NTP/DNS set; `iosxe_ntp`/`panos_ntp` synced.
10. **Nothing left behind by hands-on work**: services, advanced options
    (a reverted value = unclean power-off, not sabotage), tasks quiescent,
    lockdown unchanged, `management_server` still null.
11. **Core switches**: SVL members and links up, boot-time changed
    (declared), routing/adjacencies/port-channels/optics unchanged except
    declared removals, STP root unchanged, LACP partners unchanged.
12. **9300 stacks**: every member Ready with the same role/priority/serial,
    full-ring, reciprocal neighbors on the planned ports, trunk VLANs and
    MAC-table counts within band.
13. **Access/AP reduction**: every manifest removal classified expected; any
    removal not in the manifest is unexpected; any manifest entry still
    present is `expectations_unmatched`; errdisable adds are never expected.
14. **Sanity of the evidence**: both captures succeeded on every device (a
    post-side collect failure is *unknown, not clean*); timing rules honoured;
    envelopes paired by unchanged names; manifest text identical in
    `change_description` and the prompt.

Cross-host assertions that need no collector: port group names/VLANs/
security identical across all SE350s (a VM re-registered on a sibling host
must find the same wires); HA peers on different hosts (or declared
same-host); per-host vCPU reservations ≤ physical cores − 1 (no overcommit
on a 1-NUMA SE350 after consolidation).

## 11. Open questions for the team

- Accept the CI carve-out for one POST-by-protocol transport (Plan A), or
  pay Plan B's host prerequisites (TSM-SSH, Administrator account, timeouts)?
- Are the SE350s **Security Pack** units, gen-1 (7Z46/7D1X/7D27) or V2
  (7DA9/7DBK, XCC2 — different motion model, different LOM), and which LOM
  package (wired 10G SFP+/10GBASE-T vs the wireless package with the embedded
  NXP switch)? Is XCC management daisy-chained?
- Are the VM-Series data interfaces vmxnet3 on a vSwitch, SR-IOV VFs, or full
  passthrough on the X722 ports? L3 (OSPF to the core) or L2/vwire? Are the
  two HA peers on different SE350s? Which PAN-OS version (ESXi 8.0 needs
  11.1.6-h4+ / 11.2.6+)? Which other VNFs share the hosts?
- Will the management subnet (vmk0, XCC) be re-addressed with the floor?
- Do the SE350 uplinks land on the 9500s or the 9300s, trunk or access, and
  will CDP be set to `both` on the vSwitches (or `iosxe_mac_table` carries
  the placement proof alone)?
- What is the WLC, and are the 9300 stacks 3+ members?
- Should a licensing Support case be pre-opened for the possible CPUID/UUID
  change on the VM-Series after the cold move?
