# Handoff: capture the BMC (XCC first) as part of the host's report

Status: **being built on branch `feat/bmc-capture`** — §10 carries the
per-step state and §10a what the build found wrong or missing in this plan.
All §11 defaults were accepted by the user (2026-09-30). Written
2026-09-30 against `main` after PR #12, the Nautobot 3.2.5 dev stack on this
box, and the lab XClarity Controller at the address in `/opt/stacks/.xcc.env`,
which was walked end to end the same day (425 resources, every existing
collector run live — §4 and Appendix C). It supersedes the XCC decisions
recorded in `docs/plans/nfv-core-move.md` §0 (a separate
`snapshot_<device>-xcc` artifact, a second Device per SE350, the
`constants.XCC_ENABLED` tabling) and the `xcc-tabled` memory. The next
session builds from this document; §10 is the order of work, §11 the decisions
still open (each with the default the plan assumes).

## 0. The answer in brief

- **The BMC is an Interface on the host Device, never a Device of its own.**
  An interface whose name leads with `xcc`, `xclarity`, `imm`, `idrac`, `ilo`,
  `cimc`, `bmc` or `ipmi` and carries an assigned IP address *is* the BMC.
  Detection lives in the capture job and is independent of the host's
  platform, so an ESXi host today and a Proxmox host later get the same
  treatment. There is no checkbox: a modelled BMC is always captured, an
  unmodelled one never is.
- **Credentials come from a Relationship** between the Interface and a
  Secrets Group (key `bmc_secrets_group`, one group to many interfaces). No
  new job input. A modelled BMC whose credentials or reachability fail marks
  the device FAILED (fail-closed, as any failed check does).
- **One report per server.** The host's snapshot envelope carries the BMC
  checks beside the host checks; every check entry gains `target: "host"` or
  `"bmc"`, and the envelope's `device` block gains a `bmc` sub-block naming
  the interface, address, transport and vendor. Artifact names do not change.
- **The check family becomes vendor-neutral**: platform key `bmc`, ids
  `bmc_*`, module `jobs/checks_bmc.py` (today `checks_xcc.py`, ids `xcc_*`).
  The DMTF-standard reads are the family; vendor OEM reads branch on the
  service root's `Vendor` and record `not-present` elsewhere. Lenovo is the
  only vendor verified here.
- **What the lab XCC answered.** A gen-1 ThinkSystem SE350 (machine type
  7Z46) on XCC firmware 6.10 of August 2025, Redfish 1.15.0. The whole tree
  was walked GET-only (425 resources, all HTTP 200) and **all twelve existing
  collectors ran live: eleven `ok`, one `not-present` by its own rule, zero
  failures, 30 GETs in ~30 s** (Appendix C). The walk settled the plan's
  open questions (§4, §12) and measured the footprint: **779 Basic-auth GETs
  wrote no entry to any BMC log**, so the risk raised in the first draft is
  closed. The 204 schema files give the exact property vocabulary (Appendix
  B). The account's first-login password change, which blocked the first
  attempt, is done, and the walk and the live run were then **repeated with
  the account moved to a ReadOnly-privilege role: identical tree, identical
  leaves, identical collector results** — the ReadOnly privilege reads
  everything the catalog needs on this firmware.
- **Catalog**: the twelve existing checks are renamed and widened, and ten
  new ones close the layers a BMC uniquely sees (boot order, power policy and
  watchdogs, the Sensors collection — which on this unit is the only view of
  the external power adapters, the chassis-movement and lockdown states —
  PCIe slots, network adapters, local accounts and providers, alerting
  destinations, certificates, licences, tasks). §5 has the table with the
  lab findings folded in; roughly 60–90 paced GETs per BMC.

## 1. Decisions taken and what follows from them

### 1a. Interface, not a second Device

The user's two options were (1) an interface named for the BMC on the server
Device, carrying the BMC address, with the secret attached to the interface,
or (2) a separate Device with an "installed in" relationship. Option 1 is
chosen: the BMC and the booted OS describe one physical server, the capture
of a server should always include its BMC when one is modelled, and the job
must stay free of platform-specific switches.

Consequences in the tree:

- `snapshot_job._map_platform` drops the `xcc` / `redfish` / `lenovo` tokens.
  A Device whose *own* platform is a BMC is no longer capturable; the "cannot
  map platform" hint names the interface convention instead.
- The README's two-Device model (`<site>-se350-N-xcc`, the `bmc_of`
  Relationship, Platform "Lenovo XCC") is retired. Nothing in production
  Nautobot was ever built that way (the platform never ran there).
- `constants.XCC_ENABLED` and `XCC_INTERFACE_NAMES` go; `BMC_INTERFACE_NAMES`
  and `BMC_SECRETS_RELATIONSHIP_KEY` arrive (§3).

### 1b. One envelope per server

The earlier decision (memory `xcc-tabled`, plan §0) was a separate
`snapshot_<device>-xcc_<change_id>.json`. The user now wants a single server
report because notable information comes from both sides and an analyst
reads one file per server. Schema 1.2 (additive) carries it: `device.bmc`,
per-check `target`, and one more sentence in the interpretation guide (§3).
`tools/diff_snapshots.py` pairs by device name and diffs by check id, so it
needs no change.

### 1c. Always on, loud when it cannot

| Modelled state | Capture behaviour |
| --- | --- |
| No interface matches | Host capture only; `device.bmc` is `null`. |
| Interface matches, no IP assigned | Host capture only; `device.bmc = {"interface": "xcc", "address": null, "captured": false, "note": "no address assigned"}` and a job-log warning. |
| Two interfaces match | The device fails before any transport opens (an ambiguous model must not pick one silently). |
| Interface + address, no credential association | Every `bmc_*` check is recorded `failed` with the credentials error; device FAILED. |
| Interface + address, probe fails (TLS, 401, 403, timeout) | Every `bmc_*` check recorded `failed` with the probe hint (the new `PasswordChangeRequired` hint among them); device FAILED. |
| Host platform unsupported (no `_map_platform` match) but a BMC is modelled | **Default assumed by this plan:** capture the BMC family alone, `device.host_captured = false`, `device.platform_supported = false`, a job-log *warning*, device counts as succeeded (what it claims to cover is trustworthy). See §11 decision 2. |

### 1d. Vendor-neutral family

The same interface convention will name iDRAC, iLO and CIMC. Redfish is the
common protocol and the DMTF resources (Systems, Chassis, Managers,
UpdateService, AccountService, EventService, LogServices, Bios, SecureBoot,
Storage, Sensors, NetworkAdapters, PCIeSlots, …) are the same on every one of
them; the vendor differences are member ids (`Systems/1` on Lenovo and HPE,
`Systems/System.Embedded.1` on Dell) and the `Oem.<Vendor>` sub-trees. So:

- registry platform `bmc`, check ids `bmc_*`, module `jobs/checks_bmc.py`,
  fixtures keep their `xcc_*.json` names (they are Lenovo payloads), the
  transport stays `transport_redfish.py` (transport names are protocols:
  restconf, ssh, vsphere, redfish);
- collectors resolve the System, Manager and Chassis ids from the collections
  once per run (§3, "id resolution") instead of hard-coding `/1`;
- OEM reads follow links from the parent resource (`Managers/<id>.Oem.Lenovo.Security`
  and friends — the existing `_fenced_link(_dig(manager, "Oem", "Lenovo", …))`
  pattern), branch on the service root `Vendor`, and record `not-present`
  with the vendor named when there is no mapping yet.

Only Lenovo has fixtures and a live unit. Dell/HPE/Cisco run the DMTF subset
unverified until a unit is available; the shakedown's discovery block (§7) is
built to make that first run cheap.

### 1e. Doctrine that does not move

GET-only transport with the path fence on every literal and server-supplied
link; Basic auth, no `SessionService` session; pacing `REDFISH_MIN_INTERVAL`;
per-check GET budgets, complete-or-refused; raw curated before storage
(`Actions`, etags dropped; key-material leaves scrubbed); the AuditLog's
*entries* are never read (our own logins land there); no usernames of people
in normalized, context or raw (the local-account exception in §5 follows the
`iosxe_config` precedent); SEMANTICS describe keys, never a change. Collect
as much self-describing state as the BMC serves (memory
`capture-general-not-change-specific`); readings ride in context, never
dropped.

## 2. Nautobot modelling (the operator's side)

1. **Interface** on the host Device (e.g. `nfvregclt1`): name `xcc` (or any
   name whose first word is a BMC token: `xcc`, `XCC-mgmt`, `iLO 5`, `idrac-1`,
   `bmc0` all match; `mgmt-xcc` does not), `mgmt_only = True` recommended,
   any type. Exactly one per device.
2. **IP address** assigned to that interface (the XCC's dedicated-port
   address). IPv4 preferred; with several addresses the lowest IPv4 is used
   and the rest are named in `device.bmc.addresses_seen`.
3. **Secrets Group**, e.g. `bmc-readonly`: a username and a password Secret
   associated with access type **HTTP(S)** (Generic also works — `creds`
   cascades RESTCONF → HTTP → REST → GENERIC for every HTTPS platform).
4. **Relationship** (Extensibility → Relationships): key `bmc_secrets_group`,
   label "BMC credentials", type *one-to-many*, source `extras | secrets group`,
   destination `dcim | interface`. Then on each BMC interface, associate the
   group. The job also accepts the reverse orientation (interface as source)
   so an operator who created it the other way round is not punished.
   Verified on the 3.2.5 dev stack: both `extras.secretsgroup` and
   `dcim.interface` are relationship-capable (169 models are). **Verify on
   production 2.4.40** by opening the Relationship form and checking both
   appear in the type dropdowns before relying on it (`SecretsGroup` is not
   decorated with the `relationships` feature explicitly; the capability
   comes from the model mixin, which 2.4 also has).
5. **The BMC account**: a local XCC user with a **ReadOnly** privilege (the
   built-in ReadOnly role, or a custom role whose OEM privilege is ReadOnly —
   on the lab unit roles CustomRole4–12 are such) and Redfish access
   enabled. **Its first-login password change must be completed by a human**
   (XCC web UI → log in as the account → set the new password, or as an
   administrator clear "change password on first access" for it); until
   then every authenticated GET is refused with
   `Base.1.12.PasswordChangeRequired` (seen on the lab unit 2026-09-30 before
   the user cleared it) and the capture's probe hint says exactly this. The
   lab account walked the tree first with the OEM *Supervisor* privilege and
   then, after the user moved it to a ReadOnly-privilege role, again with
   that: no resource, leaf or collector result differed (§4a), so ReadOnly is
   the privilege to give a production capture account.
6. Nothing changes for the ESXi record: platform `vmware`, `primary_ip` =
   vmk0, its own Secrets Group. `vmware_host_identity` already records
   `bmc_ip`/`bmc_mac` from `config.ipmi`, so the analyst can confirm the
   modelled BMC is the one the host itself points at. A future Proxmox host
   needs its own host platform (a separate plan: PVE REST API, GET-only,
   API token with the PVEAuditor role); the BMC path needs nothing from it,
   and on the BMC side `Managers/<id>/EthernetInterfaces/<nic>.Oem.Lenovo.OSIPv4Address`
   is the reverse join to the host's OS address.

## 3. Framework changes, file by file

| Where | Change |
| --- | --- |
| `jobs/constants.py` | Remove `XCC_ENABLED`, `XCC_INTERFACE_NAMES`. Add `BMC_INTERFACE_NAMES = ("xcc", "xclarity", "imm", "idrac", "ilo", "cimc", "bmc", "ipmi")`, `BMC_SECRETS_RELATIONSHIP_KEY = "bmc_secrets_group"`, `TRANSPORT_FOR["bmc"] = "https"` (drop `"xcc"`), `REDFISH_PROBE_SYSTEMS = "/redfish/v1/Systems"` (the collection; every vendor serves it) replacing `REDFISH_PROBE_SYSTEM`. `SCHEMA_VERSION = "1.2"`. Keep `REDFISH_MIN_INTERVAL`, `REDFISH_MAX_CHECK_BUDGET`, `REDFISH_GET_TIMEOUT` (the lab unit answered the root in ~150 ms; nothing suggests loosening). |
| `jobs/bmc_target.py` (new, pure, stdlib) | `match_bmc_interface(name) -> token or None`: split on `[^A-Za-z0-9]`, first word lower-cased with trailing digits removed, must be in `BMC_INTERFACE_NAMES`. `pick_address(addresses) -> (chosen, others)`: IPv4 first, lowest wins. `BmcTarget` dataclass (interface_name, address, others, token). Tested in CI without Nautobot. |
| `jobs/snapshot_job.py` | `_find_bmc(device)`: walk `device.interfaces.all()`, apply `match_bmc_interface`, refuse two matches, read `interface.ip_addresses.all()` (`ip.host`), build `BmcTarget`. `_capture_device`: after the host transport, resolve BMC credentials (below), build `RedfishClient(target.address, …)`, `ping()`; keep the host loop but factor the per-check loop into `_run_checks(ctx, checks, env, raw_bundle, target)` (soft-time-limit handling included) and call it once per context. Checks: `registry.checks_for(platform)` plus `registry.checks_for("bmc")` when a BMC is modelled; `override_checks` filters both. Envelope `device_info` gains the `bmc` block. `record_transport` already loops over the transports that report a footprint — pass the Redfish client too. Debug artifact: `trace = host_ctx.trace + bmc_ctx.trace` (entries already carry their transport label). Dry-run probes both. |
| `jobs/creds.py` | `resolve_bmc_credentials(interface, device)`: find the `RelationshipAssociation` whose `relationship.key == BMC_SECRETS_RELATIONSHIP_KEY` and whose source *or* destination is the interface; the other end must be a `SecretsGroup`; then the existing `_secret(group, device, TYPE_USERNAME/TYPE_PASSWORD, "https")` cascade (pass the host Device as `obj` so templated secret providers keep working). Distinct messages for "no Relationship with that key exists" (operator must create it), "no association on interface X" and provider failures. The per-run `secrets_group` override stays host-only (documented). |
| `jobs/context.py` | No change. The BMC runs in a **second `CollectorContext`** (`restconf=RedfishClient`, platform `"bmc"`), so `ctx.get`, the per-run cache, budgets and the trace all work unchanged and nothing is shared with the host's SOAP cache. |
| `jobs/envelope.py` | `new_envelope` passes `device_info` through unchanged (the job builds the `bmc` block). `record_check(..., target="host")` writes `"target"` into every entry. One guide sentence: "checks whose target is 'bmc' were read out of band from the server's baseboard management controller at device.bmc.address; they describe the same physical server as the host checks, from the BMC's own view, and are valid whatever the host's power state unless the check's describe says otherwise." Schema 1.2. |
| `jobs/transport_redfish.py` | `ping()`: anonymous root, then the authenticated **Systems collection**. `probe_get`: when the body is JSON, record `message_id` (`error.@Message.ExtendedInfo[0].MessageId`) and `message`. `probe_hint`: HTTP 403 with a `PasswordChangeRequired` message id → "the account's first-login password change is pending; complete it once in the BMC web UI (the suite never writes to a BMC), then re-run"; plain 403 keeps today's role hint. The docstring's claim that every Basic-auth GET is an audit-log entry is corrected: on XCC 6.10 the walk's 779 GETs wrote nothing to any log (§6); the pacing stays as prudence. Nothing else changes; the CI fence guard (one `session.get` site, `fence_path` before send) stays as is. |
| `jobs/redfish_paths.py` | No change needed: `?$expand=.($levels=2)` already passes the query grammar; `$filter` stays refused (unused). Add a test pin for the `$levels=2` form. |
| `jobs/checks_bmc.py` (rename of `checks_xcc.py`) | Ids `bmc_*` (§5). New shared helper `_targets(ctx)`: GET `/redfish/v1/` (vendor, product, features), `Systems`, and resolve `system_id`; then `Links.ManagedBy[0]` / `Links.Chassis[0]` from the system resource, falling back to the single member of `Managers` / `Chassis` (record `resolution` in every check's context via a small `_target_context`). A collection with several members and no link: prefer `1`, else `System.Embedded.1`, else the first sorted, and say so. All `_SYSTEM`/`_MANAGER`/`_CHASSIS` constants become functions of the resolved ids; the shakedown's imports of those names change accordingly. OEM branches: `vendor = root.Vendor`; Lenovo paths only under `vendor == "Lenovo"`; other vendors → `SkipCheck("no <vendor> mapping for …")` for OEM-only reads, DMTF reads unchanged. |
| `jobs/registry.py` | `CheckDef.platform` comment; SEMANTICS keys renamed; new entries (> 40 chars, contract-tested). |
| `jobs/shakedown_job.py` | Same detection; run both families; `discovery["bmc"]` = the renamed XCC probes plus the new ones in §7. Report entries gain `target`. |
| `jobs/__init__.py`, `tests/_loader.py` | Nothing: modules are discovered by file name; the loader's explicit `checks_xcc` handle becomes `checks_bmc`. |
| `tools/harvest_live.py` | A `bmc` platform spec: builds a `RedfishClient` (no SSH), runs `checks_for("bmc")`, then the extra reads a fixture set wants (every collection with and without `$expand`, `Bios/@Redfish.Settings`, `Registries`). |
| `tools/redfish_walk.py` (new; Appendix A) | The paced, fenced, GET-only crawl used at plan time: every `@odata.id` under `/redfish/v1/` minus `Actions`, `SessionService`, `JsonSchemas`, registry files and the AuditLog entries, one file per resource plus an index. The first thing to run on any new BMC vendor or firmware. |
| `tools/sanitize_trace.py`, `tools/make_fixtures.py` | Redfish payload shapes the sanitizer does not know yet: UUIDs (invented deterministically, version nibble kept), `SerialNumber` / `SystemBoardSerialNumber` / `FRUSerialNumber` leaves of any shape (key-aware rule, same letter/digit pattern), `AssetTag`, `EntitlementId`, `Identifier` on licence keys, `Fingerprint`, `HostName`/`FQDN`, the `Message` text of log entries (`Login ID: <user>`), `OSIPv4Address`. Map the `xcc_*.json` harvest files to fixture names. |
| `.github/workflows/ci.yml` | No change. The read-only grep and the Redfish fence guard cover the renamed module. |
| Docs | README (platform sentence, the "NFV compute (ESXi + XCC)" section rewritten to the interface model, catalog rows, the shakedown XCC paragraph, harvest example), `docs/coverage.md` (replace "Lenovo XCC — switched off" with a BMC layer table, §9 here), `docs/prompts/floor-consolidation.md` (the XCC row, the NO FILES bullet and the "out-of-band view while XCC capture is off" caveat), `docs/plans/nfv-core-move.md` §0 (one line: superseded by this document), `docs/llm-test-plans.md` if it names the artifact. |

`_capture_device`, sketched:

```
platform, driver = _map_platform(device)          # host platform, may be None
bmc = _find_bmc(device)                           # BmcTarget or None; raises on two matches
if platform is None and bmc is None: log error (hint names both conventions); return False
host transport exactly as today when platform is not None
if bmc and bmc.address:
    try: user, pw = creds.resolve_bmc_credentials(interface, device)
    except CredentialsError as exc: bmc_error = str(exc)
    else:
        redfish = RedfishClient(bmc.address, user, pw, logger=...)
        if not redfish.ping(): record = redfish.probe_get(C.REDFISH_PROBE_SYSTEMS); bmc_error = probe_hint(record)
host_checks = checks_for(platform) if platform else []
bmc_checks  = checks_for("bmc") if bmc and bmc.address else []
(override_ids filters both; an empty total selection is the operator error it is today)
env = new_envelope(device_info={..., "bmc": bmc_block, "host_captured": platform is not None}, ...)
_run_checks(host_ctx, host_checks, env, raw, target="host")
if bmc_checks:
    if bmc_error: for check in bmc_checks: record_check(env, check, "failed", error=bmc_error, target="bmc")
    else: _run_checks(bmc_ctx, bmc_checks, env, raw, target="bmc")
record_transport for every transport with a footprint; attach the same three artifacts as today
```

## 4. What the lab XCC told us (walk of 2026-09-30)

Facts the builder can rely on. The unit: ThinkSystem SE350, machine type
7Z46 (gen-1), one Xeon D-2123IT (4 cores / 8 threads), 64 GiB in two of four
DIMM slots, four SATA M.2 drives, onboard X722 (2×10G SFP+) and I350 (2×1G)
LOMs plus a Realtek RTL8125 2.5G NIC in the PCIe x16 slot, UEFI HYE140C, XCC
firmware `TEI3G4D 6.10 2025-08-08` (release `purley_gp_23-2`). The host was
powered on and booted; its UEFI boot order names Proxmox and TrueNAS entries,
so the lab box is exactly the future host platform this plan must not
preclude. Everything below was read with the account in
`/opt/stacks/.xcc.env`, first while its role carried the OEM *Supervisor*
privilege and then again after the user set the role's OEM privilege to
*ReadOnly*; the two walks and the two collector runs are indistinguishable
(same 425 resources, all HTTP 200, no leaf missing on any singleton, the
same statuses, keys and request lists from every collector).

### 4a. Service, account, footprint

- Service root anonymous in ~150 ms; `RedfishVersion 1.15.0`;
  `ProtocolFeaturesSupported`: ExpandQuery (ExpandAll, Links, Levels, NoLinks,
  MaxLevels 2), SelectQuery, FilterQuery, ExcerptQuery, OnlyMemberQuery. Root
  links: Systems, Chassis, Managers, UpdateService, AccountService,
  EventService, TaskService, JobService, TelemetryService, LicenseService,
  CertificateService, Registries, JsonSchemas, SessionService. One member
  each in Systems (`1`), Managers (`1`), Chassis (`1`).
- **`$expand=.($levels=1)` inlines a collection's members; `$levels=2` does
  not inline a member's own sub-collections** (PCIeDevices → PCIeFunctions
  and NetworkAdapters → Ports/NetworkDeviceFunctions come back as links), so
  those are read with one `$expand` GET per sub-collection. `$expand` on the
  89-member Sensors collection is one 55 KB answer that takes ~11 s (well
  inside `REDFISH_GET_TIMEOUT`; the per-member fallback would exceed the
  40-GET budget, so `$expand` is mandatory there).
- 425 resources, every one HTTP 200 for this account; typical answer 100–250
  ms. The one first-attempt failure was the account's pending first-login
  password change (`Base.1.12.PasswordChangeRequired`), cleared by the user.
- **Footprint: 779 Basic-auth GETs (the first walk) plus the 30 of the live
  collector run added no entry to the StandardLog** — its platform sequence
  number stayed at 140 and its audit sequence number moved by one, which
  was the user's own web-UI logoff. The read-only walk (another ~430 GETs
  plus 30) confirmed it: the four audit entries added meanwhile were the
  user's web login, the role change, an SNMPv3 setting and the logoff.
  Redfish Basic auth creates no session either
  (`AccountService.Oem.Lenovo.CurrentLoggedUsers` listed only the web
  session). The first draft's worry about log churn (old §6) is closed for
  this firmware; the pacing stays as prudence.
- Registries served: Base 1.12.1, ResourceEvent, ExtendedError, TaskEvent,
  EventRegistry, LenovoPrivilegeRegistry, LenovoFirmwareUpdateRegistry,
  LenovoExtendedWarning, BiosAttributeRegistry 1.0.0, License, LogService.

### 4b. What is served, what is not

| Area | Served on this firmware | Absent or empty (record as such, never fail on it) |
| --- | --- | --- |
| System | `Systems/1`: identity, `PowerState`, `Boot` (override enabled/target/mode, `AutomaticRetryConfig`), `HostWatchdogTimer`, `TrustedModules` (TPM2_0, firmware null), `ProcessorSummary`/`MemorySummary` with `Metrics` links, `Oem.Lenovo` (`NumberOfReboots`, `TotalPowerOnHours`, `SystemStatus` = `OSBooted` on this Proxmox host, `TPMSettings`, `FrontPanelUSB`, links `BootSettings`, `ScheduledPowerActions`, `Metrics`, `HistorySysPerf`), `PCIeDevices`/`PCIeFunctions` as link arrays, `NetworkInterfaces` (3, one per adapter), `VirtualMedia` | `PowerRestorePolicy`, `PowerMode`, `LastResetTime`, `BootProgress`, `PowerOn/Off/CycleDelaySeconds`, `SerialConsole`/`GraphicalConsole`/`VirtualMediaConfig`, `Boot.BootOrder`, `Boot.BootOptions` (no BootOptions collection at all), `SecureBootDatabases`, `Systems/1/PCIeDevices` collection |
| Boot | Lenovo `Oem/Lenovo/BootSettings`: five members (`BootOrder.BootOrder` with `BootOrderCurrent`/`BootOrderNext`/`BootOrderSupported` naming the OS entries, plus HardDisk, Network, CD/DVD and USB sub-orders whose strings embed device model and serial); `SecureBoot` (`SecureBootEnable`, `CurrentBoot`, `Mode`); VirtualMedia `RDOC1`/`RDOC2` under both `Managers/1` and `Systems/1` (`Inserted`, `ConnectedVia`, `Image`, `WriteProtected`); `RemoteControl.MountImages` (0) | DMTF boot order and options (above) |
| Manager | `Managers/1`: `FirmwareVersion`, `DateTime`/`DateTimeLocalOffset`/`AutoDSTEnabled`, `Links.ActiveSoftwareImage` + `SoftwareImages` (2), `EthernetInterfaces` (`NIC` dedicated static, `ToHost` 100 Mb/s USB LAN with `OSIPv4Address` and 14 `PortForwardingMap` rows), `HostInterfaces/1` (`CredentialBootstrapping` **enabled with RoleId Administrator**, `ExternallyAccessible` false), `SerialInterfaces/1` (115200 8N1, Lenovo CLI mode), `NetworkProtocol` (§4c), `Oem.Lenovo` scalars `KCSEnabled`, `TrespassMessage`, `release_name`, `ServiceAdvisor` and links `Configuration`, `DateTimeService`, `FoD`, `Recipients`, `RemoteControl`, `SecureKeyLifecycleService`, `Security`, `ServerProfile`, `ServiceData`, `SsoCertificates`, `Watchdogs` | `Managers/1/LogServices` is the same collection as the system's (the link points there); `TimeZoneName`, `LastResetTime`; `RemoteMap`, `AgentlessCapabilities`, `MPFAHealthStatusEnabled` not present in this release |
| Chassis | `Chassis/1`: type `StandAlone`, `EnvironmentalClass`, `HeightMm`, `Location` (`Placement.Rack/RackOffset/RackOffsetUnits`, `PostalAddress.Building/Location/Name/Room`, `Contacts`), `IndicatorLED`, `Oem.Lenovo` (`FruPartNumber`, `HasSwitchBoard` false, `ProductName`, `SystemBoardSerialNumber`, links `LEDs` (4: BMC Heartbeat, Identify, Power, Fault — colour and state) and `Slots` (6: five M.2 sockets and the PCIe x16, with connector layout and width)), `PCIeSlots` (one slot, `PartLocation.ServiceLabel` "PCIe 6", status, link to its device), `PCIeDevices` (4: the BMC VGA, the two LOMs, the slot-6 NIC; identity strings null on two of them — the function rows carry vendor/device ids), `NetworkAdapters` (3), `Sensors` (89), `Controls` (1: `PowerLimit`, programmable, sensor-backed), `EnvironmentMetrics`, `ThermalSubsystem` (`Fans` 3, `ThermalMetrics`), `PowerSubsystem` (status and the Lenovo power capability flags only) | `PhysicalSecurity` (no DMTF intrusion field — the "Chassis" and "Chassis Movement" discrete sensors carry it), `Chassis/1/Drives`, `PowerSubsystem/PowerSupplies`, `Memory` under Chassis links to the system's collection |
| Environment | `Thermal` (3 temperatures: Ambient/Intake, CPU Temp, **CPU DTS — a negative margin, not a temperature**; 3 fans in RPM; no redundancy group), `Power` (**no PowerSupplies at all** — the SE350's external adapters are not modelled there —, 4 voltage rails with thresholds, 3 `PowerControl` members with consumed watts for server, CPU and memory, `Oem.Lenovo` `LocalPowerControlEnabled`/`PowerOnPermissionEnabled`/`WakeOnLANEnabled`), `Sensors`: 21 numeric (temperature, voltage, fan tach as `AirFlow`, watts typed `Current`, presence sensors typed `Power`) and **68 discrete** (`ReadingType` null, `Reading` 0, `Status` only) covering DIMM and M.2 slots, drive keys, riser, LOM link, `Lockdown Mode`, `Chassis Movement`, `Low Security Jmp`, TPM, Secure Boot and firmware error latches, SEL fullness, watchdog, utilisation; thresholds only on the environmentals (ambient caution/critical/fatal, rail limits, fan lower critical, CMOS battery) | `PowerControl[].PowerLimit`, `Redundancy`, `PowerSupplyMetrics` |
| Inventory | `Memory` (4 members: **two `Absent` slots are listed** with null identity), DIMM leaves incl. `AllowedSpeedsMHz`, `RankCount`, `BaseModuleType`, `Location.PartLocation.ServiceLabel`, `Oem.Lenovo` FRU part number / manufacture date / MPFA; `Processors/1` with `ProcessorId` (family/model/step/registers; **`MicrocodeInfo` null**), `TDPWatts`, `MaxSpeedMHz`, `Oem.Lenovo` cache table and current clock, `ProcessorMetrics` (temperature, consumed watts); `PCIeFunctions` per device (6 total) with `DeviceClass`, `ClassCode`, `VendorId`/`DeviceId`, `FunctionType` Physical | — |
| L1 | `NetworkAdapters/{ob-2,ob-4,slot-6}` with `Controllers[0]` (`FirmwarePackageVersion` "1.2203.0" / "N/A" / "", capabilities counts, location), `NetworkPorts` (`LinkStatus` Down, `CurrentLinkSpeedMbps` null, capable speeds), `Ports` (`LinkStatus` NoLink, `MaxSpeedGbps`, `Ethernet.AssociatedMACAddresses`), `NetworkDeviceFunctions` (permanent and current MAC, MTU, enabled, links to the host EthernetInterface and PCIeFunction); **the slot-6 adapter has zero ports and functions** — the BMC has no sideband to it, and it is the NIC the host actually runs on, which is why every LOM port reads NoLink with the host up; `Systems/1/EthernetInterfaces` (`ToManager` 100 Mb/s plus `NIC1`–`NIC4`, all NoLink, `SpeedMbps` null) | — |
| Storage | `Storage` has four members `M.2_Slot_2`…`_5`, each one AHCI `StorageControllers[0]` (identity fields null, `SupportedDeviceProtocols` SATA) and one drive (`CapacityBytes`, `MediaType` SSD, `Model`, `PartNumber`, `SerialNumber`, `FailurePredicted`, `HotspareType`, `PhysicalLocation`), empty `Volumes` and `StoragePools`; drive firmware appears in `FirmwareInventory` as `Disk1`–`Disk4` | `Storage/*/Controllers` collection, `EncryptionAbility`/`EncryptionStatus` (null), `Chassis/1/Drives` |
| Firmware | `FirmwareInventory` 15 members: `BMC-Primary`, `BMC-Primary-Pending` (version null, state Disabled), `BMC-Backup` (StandbySpare), `UEFI`, `UEFI-Pending`, `LXPM`, `LXPMWindowsDriver`, `LXPMLinuxDriver`, `Ob_2.1`/`Ob_2.2` (X722 option ROM and Etrack id), `Ob_4.1` (I350, "N/A"), `Disk1`–`Disk4`; `UpdateService.Oem.Lenovo.XCCBackupAutoPromote`, `FirmwareServices` (1) | `SoftwareInventory` |
| Logs | `Systems/1/LogServices`: **StandardLog** (2048, WrapsWhenFull, `LogEntryType` Multiple — platform *and* audit entries in one log, told apart by `Oem.Lenovo.LogType` `StardandLogEntry-Platform` / `-Audit` (sic); the service's `Oem.Lenovo` carries `PlatformFirstSeqNum`/`PlatformLastSeqNum`, `AuditFirstSeqNum`/`AuditLastSeqNum`, hidden-entry counters, `EnableSELWrapping`; entry `Id` is the combined `TotalSequenceNumber`, `EventSequenceNumber` counts per type; 311 entries on this unit, every one Severity OK; codes such as FQXSPSD0000I drive added, FQXSPPW0001I supply added, FQXSPPW0008I/2008I host power off/on, FQXSPPP4034I "powered off for an unknown reason", FQXSPEM4009I UEFI definitions changed, FQXSPSE4001I/4032I/4059I login, logoff and password change **with user names and client addresses in the Message**); **ActiveLog** (1024; unresolved conditions; empty here); **MaintenanceLog** (750; firmware-update and configuration history such as "LXPM firmware is updated to … by XCC Web"; no severity or OEM block); **DiagnosticLog** (3 download pointers: FFDC, FailureScreen, MPFA); **SaLog** (5, empty); **SEL** (511, NeverOverWrites, no Entries link) | `PlatformLog` (the name the current collector prefers — its StandardLog fallback is what ran) |
| Services | `NetworkProtocol` (§4c), `Oem.Lenovo.Security` (`CryptographyManagement` TLS mode NIST / min TLS 1.2, `SSLSettings` HTTPS on / LDAPS off / CIM off, `Configurator.FWRollback` Enabled, `EncapSettings`, capabilities — **no ThinkEdge lockdown/motion properties**), `SecureKeyLifecycleService` (certificate collections only), `Watchdogs` (4: OS boot, OS, BIOS boot, IPMI with timer values and expired flags), `ScheduledPowerActions` (3, not activated) mirrored as `JobService/Jobs` `PowerOff`/`PowerOn`/`Restart` (Suspended, weekday schedule), `Configuration` (backup/restore status), `ServerProfile` (disabled), `ServiceData`, `RemoteControl` (enabled; sessions and mount images empty), `FoD` (Tier1, no keys), `DateTimeService` (NTP sync, servers, UTC offset, DST) | `Recipients` empty, `SsoCertificates` empty, `TaskService/Tasks` empty, `LicenseService/Licenses` empty, `TelemetryService.ServiceEnabled` false (12 report definitions and 6 reports exist, values empty) |
| Accounts | `AccountService`: lockout 10 / 60 / 60, password length 6–32, `LocalAccountAuth`, `LDAP` (username-and-password auth type, search settings, 16 `RemoteRoleMapping` rows), `OAuth2` link, `Oem.Lenovo` password policy (expiration, reuse cycle, change interval, first-access and next-login flags, complexity, web inactivity timeout) and `CurrentLoggedUsers`; `Accounts` 12 (3 enabled — two on Supervisor-privilege roles and the capture account, since the user's change, on a ReadOnly-privilege one — 9 disabled); `Roles` 31 (`Administrator`, `Operator`, `ReadOnly` predefined; `CustomRole1`–`12`, `GroupRole1`–`16`) with `AssignedPrivileges` and `OemPrivileges` (`Supervisor` or `ReadOnly`) | `ActiveDirectory`, `TACACSplus`, `AdditionalExternalAccountProviders` |
| Alerting, PKI, licences | `EventService` (enabled, retry 3 / 60 s, `SMTP` block with server, from address, port, auth method), `CertificateService/CertificateLocations` → one HTTPS server certificate (PEM, self-signed, validity 2020–2030, key usage; **no fingerprint or signature algorithm on this firmware**), `LicenseService` (enabled, warning days 0) | `Subscriptions` empty, `Recipients` empty, SNMP traps off with empty targets, every other certificate collection empty |

### 4c. `NetworkProtocol` as served

DMTF blocks with `ProtocolEnabled`/`Port`: DHCP (off), DHCPv6 (off), HTTP 80
(on), HTTPS 443 (on, `Certificates` link), IPMI 623 (off), KVMIP 3900 (on),
NTP (on, one server), SSDP 1900 (off, with notify scope/interval/TTL), SSH 22
(on), VirtualMedia 3900 (on). The DMTF `SNMP` block carries **no
`ProtocolEnabled`** on this firmware (the current collector reads null there);
the Lenovo block does: `Oem.Lenovo` has `CimOverHTTPS` 5989 (off), `SLP` 427
(off), `SFTP` 115 (off), `WebOverHTTPS` (on), `OpenPorts` (22, 80, 443, 3389,
3900, 5900), and links `DNS` (DNS disabled, DDNS, LXCA discovery), `LDAPClient`
(anonymous binding, pre-configured servers, search attributes), `SMTPClient`
(enabled, unconfigured server, CRAM-MD5 not required) and `SNMP` (v3 agent
off, traps off, empty targets, `CommunityNames` present). `NameServers` and
`StaticNameServers` on the NIC hold placeholder `::` and `0.0.0.0` entries
for unset slots.

### 4d. What the existing collectors did live

Run through a real `CollectorContext` and `RedfishClient` from this box
(Appendix C has the per-check table): eleven `ok`, `xcc_security_state`
`not-present` (the Security resource carries no ThinkEdge properties — the
rule the check was written with), no failures, 30 GETs, every collection
answered by one `$expand` GET. Normalizer facts worth carrying into the
build:

- `xcc_system`: 38 scalars; `xcc_health` reads the Manager's `State`
  (`Enabled`) because the Manager has no `Status.Health`; the boot override
  trio, SecureBoot trio and `system_status` (`OSBooted`) all populated;
  `eth_member_used` `NIC`.
- `xcc_thermal`: keys `temp|Ambient Temp`, `temp|CPU Temp`, `temp|CPU DTS`
  (its reading is a negative margin — context only, as designed, but the
  SEMANTICS should say what DTS is), `fan|Fan N Tach` (RPM, lower critical
  1552).
- `xcc_power`: four `voltage|` keys only; no `psu|`, no `redundancy|`;
  consumed watts in context. The adapters live in `bmc_sensors`.
- `xcc_inventory`: `dimm|1`–`4` (two Absent with null identity — the
  behaviour the plan wanted), `cpu|1`, `pcie|ob_1`, `ob_2`, `ob_4`, `slot_6`.
- `xcc_host_nics`: `nic|NIC1`–`NIC4`, all `NoLink` with the host up (see 4b:
  the host runs on the slot-6 NIC the BMC cannot see); `ToManager` excluded.
- `xcc_storage`: four `controller|M.2_Slot_N` (identity null) and four
  `drive|Drive.Slot_N`; volumes 0.
- `xcc_firmware`: all 15 members keyed, the `-Pending` ones with version
  None on both sides.
- `xcc_event_log`: 0 keyed entries (nothing Warning/Critical), 312 counted
  by code in context, `log_service_used` StandardLog, `first_seq_num` /
  `last_seq_num` **null because this firmware spells them
  `PlatformFirstSeqNum`/`AuditLastSeqNum` etc.**; the newest raw rows carry
  login, logoff and password-change messages with user names and client
  addresses — the redaction item in §5a is a real leak today, not a
  hypothetical one.
- `xcc_bios`: 20 of 126 attributes selected by the token list; registry
  `BiosAttributeRegistry.1.0.0`; `@Redfish.Settings.SettingsObject` points at
  `Systems/1/Bios/Pending` (the full attribute set as it will apply
  `OnReset`, with the time of the last apply).
- `xcc_manager_network`: 38 scalars; `dns_servers` reads the `::`
  placeholders and `static_dns_servers` the `0.0.0.0`/`::` placeholders
  verbatim (drop unset placeholders), `snmp_enabled` null (read the Lenovo
  SNMP block), `ipv4_origin` Static, VLAN disabled.
- `xcc_chassis_location`: 20 scalars; `postal_*` and `placement_*` leaves
  populated (`placement_rack_offset` 1, units EIA_310); `intrusion_sensor`
  null (no `PhysicalSecurity`).

## 5. The catalog

Tiers as in the README. "Source" names resources by their DMTF spelling; the
member ids come from the run's id resolution. Every check records
`host_power_state` in context where the view is POST-populated. GET counts
assume `$expand`; the per-member fallback is what the budget sizes for.

### 5a. Existing checks: renamed, and what each gains

| New id (old) | Tier | Gains |
| --- | --- | --- |
| `bmc_system` (`xcc_system`) | 1 | `power_restore_policy`, `power_on_delay_s` / `power_off_delay_s` / `power_cycle_delay_s`, `host_watchdog_enabled` / `_timeout_action` / `_warning_action`, `power_mode`, `tpm_count` / `tpm_interface_types` / `tpm_firmware` (from `TrustedModules[]`, today context), `serial_console_enabled` / `graphical_console_enabled` / `virtual_media_service_enabled` (the host console blocks), Lenovo `front_panel_usb_mode`, `tpm_rpp_enabled`; context adds `last_reset_time`, `boot_progress` (LastState/LastStateTime), `location_indicator_active`, `number_of_reboots`, `total_power_on_hours`, `release_name` (Lenovo firmware release name from `Managers/<id>.Oem.Lenovo`), `manager.last_reset_time`, `resolution` (how ids were found). Boot-override fields move to `bmc_boot` (builder's call: keep duplicates one release for continuity or move at once). |
| `bmc_chassis` (`xcc_chassis_location`) | 1 | Fault/identify LEDs: `led|<Location or Name>` → color, state (Lenovo `Chassis.Oem.Lenovo.LEDs`, one expand GET; DMTF `IndicatorLED` / `LocationIndicatorActive` as scalars). Lenovo identity scalars `system_board_serial`, `product_name`, `fru_part_number`; `height_mm` … context. Tier 1 now: a lit fault LED is a finding, the Location record still a key. |
| `bmc_inventory` (`xcc_inventory`) | 2 | DIMMs: `error_correction`, `rank_count`, `data_width_bits`, `allowed_speeds_mhz`, `base_module_type`, `fru_part_number`, `manufacture_date`, Lenovo MPFA `health_major/minor`; **empty slots keyed** when listed (`State Absent`, capacity null on both sides). CPUs: `microcode` (`ProcessorId.MicrocodeInfo`), `family/model/step`, `max_speed_mhz`, `tdp_w`, `turbo_state`, `serial`, cache sizes in context. PCIe: `Chassis/<id>/PCIeDevices?$expand=.($levels=2)` adds `pciefn|<device>|<fn>` → function_type (Physical/Virtual — SR-IOV VFs appear here), device_class, vendor/device/subsystem ids (hex strings as served), class_code, enabled. |
| `bmc_host_nics` (`xcc_host_nics`) | 1 | Unchanged view; context names whether `Systems/<id>/EthernetInterfaces` or the NetworkAdapters tree carried the ports (both are captured; `bmc_network_adapters` below is the richer one). |
| `bmc_firmware` (`xcc_firmware`) | 2 | Plus `UpdateService/SoftwareInventory` members when served (`sw|<Id>`), `manager_active_image` (from `Managers/<id>.Links.ActiveSoftwareImage`), Lenovo `xcc_backup_auto_promote` scalar; `ReleaseDate` stays out. |
| `bmc_event_log` (`xcc_event_log`) | 2 | `failing_fru` (part + serial) on keyed entries; context `audit_log_seq` (first/last from the **LogService resource's** `Oem.Lenovo.AuditFirstSeqNum/AuditLastSeqNum` — the service resource, never its entries) and `sel_wrapping_enabled`; **redact `Login ID: <user>` in every Message before raw and trace** (Lenovo logs remote logins into the platform log with the login id; the IOS-XE syslog redactor is the pattern). |
| `bmc_bios` (`xcc_bios`) | 2 | **Every attribute keyed** (`bios|<Attribute>`, password-like names scrubbed; the token curation goes — UEFI settings only move when someone moves them, and the full set is a few hundred small keys), plus `pending|<Attribute>` from the `@Redfish.Settings.SettingsObject` resource (a change armed but not yet applied), `reset_to_defaults_pending`, Lenovo `uefi_admin_password_set` / `uefi_power_on_password_set` (booleans), `attribute_registry` (name and version) in context. |
| `bmc_storage` (`xcc_storage`) | 1 | Controllers from both the deprecated `StorageControllers[]` and the `Controllers` collection (whichever is filled; context says), `cache_size_mib`, Lenovo battery `operational_status` (capacities, voltage, temperature in context), `supported_raid_levels`, `mode`; drives add `negotiated_speed_gbs`, `rotation_rpm`, `block_size_bytes`, `hotspare_type`, `write_cache_enabled`, Lenovo `drive_status` (temperature in context; SMART text raw-only, capped); volumes add `read_cache_policy`, `write_cache_policy`, `strip_size_bytes`, `is_boot_capable`, Lenovo `raid_level`, `bootable`, `access_policy`, `io_policy`; `Chassis/<id>/Drives` read for drives no controller lists (non-RAID M.2). |
| `bmc_thermal` (`xcc_thermal`) | 1 | Same keys; when `Thermal` is absent read `ThermalSubsystem/Fans` (+ `ThermalMetrics.TemperatureSummaryCelsius` into context whenever served). |
| `bmc_power` (`xcc_power`) | 1 | Same keys; `PowerSubsystem/PowerSupplies` (+ `Metrics`) when `Power` is absent; `line_input_status` where served. Capping/policy leaves move to `bmc_power_policy`. |
| `bmc_manager_network` (`xcc_manager_network`, split) | 2 | Addressing and time only: the NIC (as today) plus Lenovo `nic_mode` (dedicated/shared), `failover_mode`, `ipv4_assigned_by`, `domain_name`, `hostname_from_dhcp`; DNS (DMTF `NameServers`/`StaticNameServers` plus Lenovo DNS enable, preferred family, servers 1–3, DDNS, LXCA discovery); NTP (`NetworkProtocol.NTP` plus Lenovo `DateTimeService`: setting method, servers, UTC offset, DST); `Manager.DateTime`/`TimeZoneName` in context; `os_ipv4_address` (Lenovo, the host as the BMC sees it) in context; `HostInterfaces` (USB LAN: enabled, externally accessible, address). |
| `bmc_security` (`xcc_security_state`) | 1 | **Every scalar leaf of the vendor security resource keyed by dotted path** (`security|CryptographyManagement.TLSSecurityMode`, `security|SSLSettings.EnableHttps`, …; lists sorted) so the TLS mode, LDAPS, CIM-over-HTTPS, firmware-rollback and encapsulation settings this firmware serves are all captured; the ThinkEdge names (lockdown, motion, intrusion, SED) stay as optional first-class scalars found by the existing candidate lists, and `context.property_sources` keeps saying which leaf fed which. `sklm|…` leaves from `SecureKeyLifecycleService` (servers, protocol, EKMS polling/cache settings, certificate counts; never a key). `not-present` only when the vendor has no security resource at all. |

Lab notes for §5a (what the walk adds or corrects per check):

- `bmc_system`: the DMTF power-restore, delays, console and last-reset
  leaves are **absent on XCC 6.10** — emit them None, never assume. The
  Manager has no `Status.Health`, so name the field `xcc_state` or document
  the fallback. `SystemStatus` reads `OSBooted` on a Proxmox host, so the
  SEMANTICS sentence about `BootingOSOrInUndetectedOS` becomes "a value the
  firmware reports, verbatim".
- `bmc_chassis`: `PhysicalSecurity` is absent; the tamper facts are the
  `Chassis` and `Chassis Movement` discrete sensors (`bmc_sensors`). The
  four LEDs and six Slots collections are served and small.
- `bmc_inventory`: `PCIeFunctions` need one `$expand` GET per device
  (`$levels=2` does not inline them); `MicrocodeInfo` is null on this
  firmware; the BMC VGA and the slot-6 NIC have null `Manufacturer`/`Model`
  on the device — key the function rows, whose vendor/device ids identify
  the part.
- `bmc_host_nics`: SEMANTICS must say that NoLink on every LOM port with
  the host up is legitimate when the OS runs on an adapter the BMC has no
  sideband to (the slot-6 Realtek here), and that `Systems/1/NetworkInterfaces`
  maps 1:1 to `Chassis/1/NetworkAdapters`.
- `bmc_firmware`: keep the `-Pending` members (a version appearing there is
  a staged update); `SoftwareInventory` is absent here — optional read.
- `bmc_event_log`: read `Oem.Lenovo.Platform*/Audit*SeqNum` (the
  `FirstSeqNum`/`LastSeqNum` spelling the check expects is not served);
  record each keyed entry's `log_type`; add the **ActiveLog** (unresolved
  conditions — key every entry whatever its severity, `active|<code>|<Id>`,
  empty is the healthy state) and the **MaintenanceLog** (firmware-update and
  configuration history: newest rows in raw, counts and newest timestamp in
  context — `bmc_firmware` carries the diff); the SEL service has no
  `Entries` link on this firmware, so it is a probe only; **redact `Login
  ID: <x>`, `by user <x>` and `User <x> password modified by user <y>` in
  every Message before raw and trace** — those rows exist on the lab unit.
- `bmc_bios`: 126 attributes here (`DevicesandIOPorts` 45, `Processors` 18,
  per-LOM option-ROM families 10 each, `Memory` 10, `NetworkStackSettings`,
  `Power`, `SecureBootConfiguration`, `SystemRecovery`,
  `TrustedComputingGroup`, …); the pending set is `Systems/1/Bios/Pending`
  (full attributes; pending = differs from current; `@Redfish.Settings.Time`
  in context); `Oem.Lenovo.IsUefiAdminPasswordSet` / `IsUefiPowerOnPasswordSet`
  are booleans and must survive the secret scrub (§5b hygiene).
- `bmc_storage`: non-RAID M.2 SATA drives enumerate as one `Storage` member
  per slot with one AHCI controller (identity null) and one drive; `Volumes`
  and `StoragePools` are empty collections, `Controllers` is absent,
  `Chassis/1/Drives` is absent, encryption leaves are null. Drive firmware
  is in `bmc_firmware` (`Disk1`–`Disk4`), so join by drive model there.
- `bmc_thermal`: mark `CPU DTS`-style sensors (name contains `DTS`, or a
  negative reading) as margins in context; `ThermalMetrics.TemperatureSummaryCelsius`
  gives Ambient/Intake (Exhaust null) — context.
- `bmc_power`: no supplies on an SE350 — the `psu|` family is legitimately
  empty and the check must not fail on it (today it succeeds because the
  voltage rails populate); the external adapters' presence is the two
  `Power Adapter N` discrete sensors in `bmc_sensors`. `PowerSubsystem` has
  no `PowerSupplies` collection either.
- `bmc_manager_network`: drop `::` / `0.0.0.0` placeholders from the DNS
  lists; the DMTF `SNMP` block has no `ProtocolEnabled` (read the Lenovo
  block); add the `HostInterfaces/1` facts (`CredentialBootstrapping.Enabled`
  and its `RoleId` — Administrator on the lab unit — is a security-posture
  key), `InterfaceNicMode`, `InterfaceFailoverMode`, `DateTimeService`.
- `bmc_security`: the flatten yields eight leaves on this firmware (TLS
  mode and minimum level, HTTPS/LDAPS/CIM enablement, firmware rollback,
  encapsulation mode and whitelist, supported actions);
  `SecureKeyLifecycleService` has only certificate collections here; the
  ThinkEdge lockdown/motion facts are discrete sensors (`Lockdown Mode`,
  `Chassis Movement`) and belong to `bmc_sensors` — say so in SEMANTICS.

### 5b. New checks

| Id | Tier | Source (GETs) | Normalized view | Context | Why it is worth a check (general value) |
| --- | --- | --- | --- | --- | --- |
| `bmc_boot` | 1 | `Systems/<id>` (cached), `Boot.BootOptions` collection expanded (1; **absent on XCC 6.10** — optional), Lenovo `Oem.Lenovo.BootSettings` collection expanded (1; five members on the lab unit), `Systems/<id>/VirtualMedia` expanded (1; `Managers/<id>/VirtualMedia` is the same pair), Lenovo `RemoteControl.MountImages` (1) | scalars `boot_order` (ordered list), `boot_override` / `_target` / `_mode`, `boot_next`, `automatic_retry_config` / `_attempts`, `stop_boot_on_fault`, `trusted_module_required_to_boot`, `http_boot_uri`, Lenovo `boot_order_current` / `boot_order_next`; `option|<BootOptionReference>` → display_name, enabled, uefi_device_path, alias; `vmedia|<Id>` → inserted, image (userinfo stripped), media_types, connected_via, write_protected; Lenovo `mount|<Id>` → path, mounted, readonly | `boot_order_supported`, `remaining_automatic_retry_attempts` | Consumed by every reload, firmware, disk or defaults-load change; a reordered boot list or a leftover mounted ISO is the classic "came back on the wrong device" cause, invisible from the OS; stable between healthy captures; 4–5 GETs. |
| `bmc_power_policy` | 1 | `Systems/<id>` (cached), `Chassis/<id>/Power` (cached), `Chassis/<id>/Controls` expanded (1), Lenovo `Systems/<id>.Oem.Lenovo.ScheduledPowerActions` expanded (1), `JobService/Jobs` expanded (1; the same three actions with their weekday schedule and `JobState`), Lenovo `Managers/<id>.Oem.Lenovo.Watchdogs` expanded (1) | scalars `power_restore_policy` (DMTF and Lenovo `Power.Oem.Lenovo.Capabilities`, both), `wake_on_lan`, `power_on_permission`, `local_power_control`, `random_delay`, `host_watchdog_*`, `power_limit_w` / `power_limit_exception` / `power_capping_enabled` / `limit_mode` / `guaranteed_w`, `power_redundancy_policy` / `max_power_limit_w` / `power_failure_limit`; `control|<Id>` → control_type, control_mode, set_point, set_point_units, allowable min/max; `sched|<Id>` → type, activated, interval, time; `watchdog|<Id>` → type, state, timer_s, timeout_interval_s | `watchdog_expired` flags, `non_redundant_available_power_w`, readings of every Control | Consumed by every power event and any change that reboots or re-powers a server: whether the host returns after an AC loss, whether a cap or a scheduled power action can bite, whether a watchdog reset is armed; all configuration, so it diffs to nothing between healthy captures; 3 GETs. |
| `bmc_sensors` | 1 | `Chassis/<id>/Sensors?$expand=.($levels=1)` (1; 89 members and ~11 s on the lab unit, so the per-member fallback is refused above the budget rather than walked), `Chassis/<id>/EnvironmentMetrics` (1), `ThermalSubsystem/ThermalMetrics` (1) | `sensor|<Id>` → reading_type, physical_context (+ sub-context), state, health, reading_units, thresholds (non-null caution/critical/fatal readings, snake-cased), and `reading` only for ambient/intake/inlet/exhaust-class temperature sensors (8 °C tolerance, the `bmc_thermal` rule) | every reading (`readings` by key, with `ReadingTime`), peak readings, `environment` (chassis power W, energy kWh, temperature, humidity where served), sensor count by reading_type | The modern superset of Thermal/Power with one vocabulary (`ReadingType`): voltage rails, currents, energy, humidity and intrusion sensors that the legacy resources omit, and the view that survives when a firmware drops `Thermal`/`Power`; state/health keys are stable, readings are context; 1–2 GETs. Overlaps `bmc_thermal`/`bmc_power` by design (the legacy checks keep their fixtures and their field-verified semantics; the shakedown says whether both are served). |
| `bmc_pcie_slots` | 1 | `Chassis/<id>/PCIeSlots` (1), Lenovo `Chassis/<id>.Oem.Lenovo.Slots` expanded (1) | `slot|<index or Location.ServiceLabel>` → slot_type, pcie_type, lanes, state (Enabled/Absent), hot_pluggable, location, linked_devices (PCIeDevice ids); Lenovo extras connector_layout, max_data_width | slot count, occupied count | Consumed by any hardware swap, riser reseat or transport; an unseated card is an `Absent` slot here even when the device's own row simply vanishes from `bmc_inventory`; stable; 1–2 GETs. |
| `bmc_network_adapters` | 1 | `Chassis/<id>/NetworkAdapters?$expand=.($levels=1)` (1) then per adapter one `$expand` GET each on `Ports` (or `NetworkPorts` where `Ports` is absent) and `NetworkDeviceFunctions` (`$levels=2` does not inline them; 1 + 2 per adapter, 7 on the lab unit; budget 24) | `adapter|<Id>` → manufacturer, model, serial, part_number, firmware_package_version (Controllers[]), port_count, function_count, lldp_enabled; `port|<adapter>|<port>` → link_status, physical_port_number, active_link_technology, capable speeds (sorted), autoneg, flow_control_configuration; `netfn|<adapter>|<fn>` → net_dev_func_type, permanent_mac (lower-cased), device_enabled, boot_mode, virtual_functions_enabled, max_virtual_functions, assigned port | current_link_speed_mbps per port, Lenovo `port_max_speed_bps`, `physical_port_mac`, host_power_state | The BMC-side L1 view: adapter firmware (which `bmc_firmware` may list only as a bundle), per-port link and negotiated capability, burned-in MACs that join to the hypervisor's physical-NIC MACs (`vmware_pnics.mac`) and to the switch-side MAC table; consumed by every re-cabling, NIC firmware and SR-IOV change; 1–4 GETs. |
| `bmc_manager_services` | 2 | `Managers/<id>/NetworkProtocol` (cached) with its `Oem.Lenovo` block, `Managers/<id>` (cached) Oem links: `RemoteControl`, `RemoteMap`, `Configuration`, `ServerProfile` (1 each), `Managers/<id>/SerialInterfaces` expanded (1), NIC `Oem.Lenovo.PortForwarding` (+ maps, 1–2) | scalars per protocol `<protocol>_enabled` / `_port` for every DMTF block (HTTP, HTTPS, SSH, SNMP, IPMI, VirtualMedia, KVMIP, SSDP, DHCP, DHCPv6, RDP, RFB, Proxy) and Lenovo (CIM-over-HTTPS, SLP, Web-over-HTTPS, SFTP), `open_ports` (sorted), SNMP agent (`snmpv3_enabled` / `_port` / `contact` / `location`; community names **scrubbed**, v1 count only), `kcs_enabled`, `mpfa_health_enabled`, `remote_control_enabled`, `remote_map_enabled`, `server_profile_enabled` / `_server` / `_port`, `usb_port_forwarding_enabled` + `pfmap|<Id>` rows, `serial|<Id>` → bit_rate, parity, data/stop bits, flow_control, Lenovo CLI mode | active remote-control session **count** (never who), `trespass_message`, `agentless_capabilities`, `configuration_backup_status` / `restore_status` | The management plane's own attack surface and service set; consumed by every hardening, firmware and BMC-network change; configuration, so stable; 6–10 GETs. |
| `bmc_accounts` | 1 | `AccountService` (1) with `Oem.Lenovo`, `Accounts` expanded (1), `Roles` expanded (1), `LDAP` / `ActiveDirectory` / `AdditionalExternalAccountProviders` (1–2), Lenovo `NetworkProtocol.Oem.Lenovo.LDAPClient` (cached from the protocol read) | policy scalars (min/max password length, lockout threshold/duration/reset, auth-failure logging threshold, local account auth mode, password expiration days, Lenovo complexity, reuse cycle, change-on-first-access, web inactivity timeout); `account|<UserName>` → role_id, enabled, locked, password_change_required, account_types (sorted), snmpv3_configured, ssh_key_count; `role|<RoleId>` → assigned_privileges (sorted), oem_privileges (sorted), is_predefined; `provider|<type>` → enabled, service_addresses (sorted), base DNs, bind DN, role-mapping count (bind password and any key scrubbed) | `current_logged_users` **count only** (our own session is one of them), `supported_account_types` | Security posture of the management plane; local BMC accounts are configuration and are keyed by name on the `iosxe_config` precedent (a local-user change must diff; nothing about people's sessions is kept); consumed by every credential rotation, hardening and BMC firmware change; stable; 4–6 GETs. |
| `bmc_alerting` | 1 | `EventService` (1), `Subscriptions` expanded (1), Lenovo `Managers/<id>.Oem.Lenovo.Recipients` expanded (1), Lenovo SNMP traps block (cached), `LogServices/<platform log>` `SyslogFilters` if served | scalars `event_service_enabled`, `delivery_retry_attempts` / `_interval_s`, `smtp_enabled` / `_server` / `_port` / `_from` / `_connection_protocol` / `_auth_method` (credentials scrubbed); `subscription|<Id>` → destination (scheme://host:port, userinfo stripped), protocol, subscription_type, event_format, context, registry_prefixes, resource_types, status, heartbeat; `recipient|<Id>` → name, enabled, alert_type, address, include_event_log, critical/warning/system enabled flags and accepted event lists (sorted); `snmp_trap_enabled` / `_port` / `_v1` / `_v2`, `trap_targets` (sorted; communities scrubbed) | delivery counters if any | "Is anyone still being told": a subscription or recipient that stops resolving after a re-address, a management-server change or a firmware reset is silent otherwise; consumed by every network, addressing and management-tool change; stable; 3–5 GETs. |
| `bmc_certificates` | 1 | `CertificateService/CertificateLocations` (1) then each `Links.Certificates[]` member (budget 12) | `cert|<resource path>` → certificate_type, subject (CN, O, OU), issuer (CN, O), valid_not_before / valid_not_after, key_usage (sorted), signature_algorithm, self_signed, usage types | fingerprint + algorithm, serial number, days-to-expiry tallies | The `iosxe_pki` twin: a factory reset regenerates the self-signed HTTPS certificate, an LDAP/KMIP trust certificate expiring breaks authentication or key retrieval; consumed by every reset, hardening and PKI change; stable; 2–12 GETs. |
| `bmc_licenses` | 1 | `LicenseService` (1), `Licenses` expanded (1), Lenovo `Managers/<id>.Oem.Lenovo.FoD` (1) and its `Keys` expanded (1) | scalars `license_service_enabled`, `expiration_warning_days`, Lenovo `fod_tier`; `license|<Id>` → license_type, license_origin, removable, manufacturer, sku, part_number, status, authorization_scope, expiration_date, grace_period_days; `fodkey|<Id>` → identifier types, status, expires, use_count / use_limit | install_date, remaining_duration / use count | Feature entitlements (remote KVM, virtual media, XCC tier) are tied to the machine and vanish with a system-board swap or a reset; consumed by hardware and firmware changes; stable; **`LicenseString`, `Bytes` and any key material never stored** (add the tokens to the scrub list); 3–4 GETs. |
| `bmc_tasks` | 3 (`info_only`) | `TaskService` (1), `Tasks` expanded (1), `JobService` (1), `Jobs` expanded (1) | scalars `task_service_enabled`, `task_auto_delete_minutes`, `job_service_enabled`; `task|<Id>` / `job|<Id>` for **non-terminal** entries only → name, state, percent_complete | counts by terminal state, newest start/end times | The `vmware_recent_tasks` twin: a firmware update or configuration restore still running at capture time explains a half-populated inventory; quiescence evidence; 4 GETs. |
| `bmc_telemetry` (optional, last) | 3 | `TelemetryService` (1), `MetricReportDefinitions` expanded (1) | `report|<Id>` → type, schedule, metrics (sorted), enabled, report_updates | report count, newest report timestamp | Configuration of what the BMC records; values are never captured (bulky, volatile, `LenovoHistoryMetricValue` too). Low priority; listed so the hole is a decision, not an omission. |

Lab notes for §5b:

- `bmc_boot`: on XCC 6.10 the boot order is only in the Lenovo boot manager
  (`BootOrderCurrent`/`BootOrderNext`/`BootOrderSupported` per member; the
  sub-orders' strings embed device model and serial, which the sanitizer
  must learn). Key `order|<member>` → current list (ordered), `next` list,
  `supported` in context. Virtual media on both `Managers` and `Systems`
  are the same two RDOC slots — read one.
- `bmc_power_policy`: the DMTF `PowerRestorePolicy` and the Lenovo
  `Capabilities.PowerRestorePolicy` are **both absent** on this firmware —
  the AC-restore policy is not exposed by Redfish here (§12 keeps it as an
  open probe: the BIOS `Power_*` attributes carry performance bias and
  platform control only). What is served: the three Lenovo power flags,
  `Controls/PowerLimit`, `HostWatchdogTimer`, four Lenovo watchdogs (the
  IPMI one enabled with a 15 s timer), three scheduled power actions and
  their `JobService` twins.
- `bmc_sensors`: 68 of 89 sensors are discrete (`ReadingType` null,
  `Reading` 0, `ReadingUnits` empty) and their information is
  `Status.Health`/`State` plus the `Reading` assertion; key them by `Name`
  with the IPMI id as tiebreak, exactly as `bmc_thermal` keys by Name.
  Numeric readings go to context except the ambient class. `ReadingType`
  is not trustworthy for classification (watts typed `Current`, presence
  sensors typed `Power`, fans typed `AirFlow`): classify numeric-vs-discrete
  by the presence of `ReadingUnits`. Whether an asserted discrete sensor
  reads `1` or flips `Health` is still unobserved (§12).
- `bmc_pcie_slots`: one DMTF slot on the SE350 (PCIe 6) plus the six Lenovo
  slots (M.2 sockets and the x16) — small and stable.
- `bmc_network_adapters`: `Controllers[].FirmwarePackageVersion` is the only
  place the X722 LOM firmware (1.2203.0) appears besides `bmc_firmware`'s
  `Ob_2.1`; `Ports.LinkStatus` (NoLink) and `NetworkPorts.LinkStatus` (Down)
  spell the same fact differently — key one (`Ports`, the current schema)
  and keep the other in context; MACs come from
  `NetworkDeviceFunctions.Ethernet.PermanentMACAddress`.
- `bmc_manager_services`: `OpenPorts` is served as a list of strings — sort
  and key it; `RemoteMap` is not linked on this firmware (mount images hang
  off `RemoteControl`); `CredentialBootstrapping` on the host interface is a
  key (an enabled bootstrap with an Administrator role is exactly the kind
  of posture fact this check exists for).
- `bmc_accounts`: two of the lab unit's three enabled accounts hold the OEM
  `Supervisor` privilege and the capture account holds `ReadOnly`;
  `PasswordChangeRequired` reads null once cleared;
  `AccountTypes` lists eight types. The scrub rule must be **exact-name**
  (`Password`, `Passphrase`, `Secret`, `PrivateKey`, `AuthenticationKey`,
  `EncryptionKey`, `CommunityNames`, `TrapCommunity`, `LicenseString`,
  `CertificateString`, FoD `Bytes`, and any leaf ending in `Password`) rather
  than the substring test `_looks_secret` applies today, or every password
  *policy* leaf (`PasswordLength`, `PasswordExpirationPeriodDays`,
  `PasswordChangeOnFirstAccess`, `ComplexPassword`, `MinPasswordLength`,
  `IsUefiAdminPasswordSet`, …) is scrubbed with it.
- `bmc_alerting`: subscriptions, recipients and trap targets are all empty
  on the lab unit, so the check's fixtures for populated rows stay
  hand-built from the schema until a configured unit is captured; the
  `EventService.SMTP` block is populated (server, from address, port, auth
  method) and is the one live row.
- `bmc_certificates`: one location on this firmware (the HTTPS server
  certificate); `Fingerprint` and `SignatureAlgorithm` are absent, so the
  self-signed flag (issuer equals subject) and validity are the identity.
- `bmc_licenses` and `bmc_tasks`: empty collections on the lab unit —
  `not-present` is wrong for them (the services exist and answer), an empty
  keyed view is right.

Hygiene additions for the family (`_SECRET_TOKENS` and key-aware scrubs):
`communit` (CommunityNames, TrapCommunity), `licensestring`, `encryptionkey`,
`bytes` under FoD keys, `clientpassword`, `sshpublickey` (kept as a count),
`certificatestring` (PEM; raw-drop), userinfo in any URL (`Image`,
`Destination`), `UserName`/`Username`/`UserID` leaves *outside* the
`Accounts` collection replaced by a `…_set` boolean, `CurrentLoggedUsers` and
remote-control `Sessions` reduced to counts, `Login ID: <x>` redacted in log
messages.

### 5c. Deliberately not captured

AuditLog entries (our own footprint); TelemetryService metric *values* and
Lenovo history containers (volatile, bulky); `ServiceData`/FFDC and
screenshots (diagnostic dumps, not state); `SessionService` (fenced);
`Registries` and `JsonSchemas` bodies (static vendor files — the shakedown
records the registry *names* once); SMART text beyond a capped raw copy.

## 6. GET budget and timing

Per BMC, with `$expand` honoured: about 60–90 GETs, so 1.5–2 minutes at the
1 s pacing on top of the host capture; the 3300 s job soft limit is not in
sight. The existing catalog measured 30 GETs and ~30 s live (Appendix C).
Per-check budgets stay under `REDFISH_MAX_CHECK_BUDGET = 40`; `bmc_sensors`
(89 members here) and `bmc_certificates` refuse loudly with the member count
when `$expand` is not honoured rather than walking into the wall, exactly as
`xcc_inventory` does today. The Sensors expansion is the slowest single
answer (~11 s for 55 KB); everything else answers in 100–250 ms.

**Footprint, measured.** The first draft feared that Basic-auth GETs would
write one platform-log entry each. They do not on XCC 6.10: across the 779
GETs of the walk and the 30 of the live run, the StandardLog's platform
sequence number did not move and its audit sequence number moved once, for
the user's own web-UI logoff; no session was created. The old option (c),
a Redfish session per capture, is therefore not needed and the doctrine
stays GET-only with Basic auth. Re-measure once on any other firmware
generation (the shakedown's discovery block records the two sequence
numbers before and after the run).

## 7. Shakedown and fixtures

Done on 2026-09-30 from this box (not through Nautobot): the full walk
(`tools/redfish_walk.py`, Appendix A) and the live run of every existing
collector through a real `CollectorContext` (Appendix C). What remains:

1. ~~Walk again with a ReadOnly-privilege account~~ — **done 2026-09-30**:
   with the account's role set to OEM privilege `ReadOnly`, the walk and
   the live collector run matched the Supervisor ones resource for
   resource, leaf for leaf and key for key (Appendix C). Collectors still
   treat a 403 as a failed read with the role hint, because another
   firmware or vendor may restrict a ReadOnly role where this one does not.
2. **Shakedown through Nautobot** once PR A exists (the host Device with the
   BMC interface, the Relationship and the Secrets Group modelled on the dev
   stack): both families in one run, `discovery.bmc` filled (service root
   and features, resolved ids, OEM links under System/Manager/Chassis, log
   services, member counts of every collection the family walks, `$expand`
   depth honoured, legacy versus subsystem thermal/power resources, the
   security resource's property names, the capture account's role and
   privileges, host power state and `SystemStatus`, and the platform/audit
   sequence numbers before and after the run).
3. **Harvest and sanitize**: `tools/harvest_live.py --platform bmc`, then
   `tools/make_fixtures.py` (after the sanitizer additions in §3: UUIDs,
   serial-number leaves of any shape, MACs in the `AssociatedNetworkAddresses`
   bare-hex spelling and the `AssociatedMACAddresses` colon spelling, boot
   entry strings that embed drive serials, log messages with user names and
   client addresses, the `OSIPv4Address` leaf) into
   `tests/fixtures/xcc_*_lab.json`; `tests/test_lab_fixtures.py` pins what
   every normalizer reads. The walk's files in this session's scratchpad are
   unsanitized and stay out of the repository.
4. **Host off, then one cable pulled**: which views are POST-populated on
   this firmware (`bmc_inventory`, `bmc_pcie_slots`, `bmc_network_adapters`,
   `bmc_host_nics`, `bmc_storage`) and whether `Ports.LinkStatus` follows a
   cable with the host off; on this unit the LOM ports are unused, so plug
   one to see `LinkUp`. Also assert one discrete sensor (pull an M.2 drive
   or open the chassis) to learn how an asserted sensor reads.
5. **Stability**: two captures an hour apart must diff to nothing under each
   check's compare mode; anything else is a normalizer fix (readings to
   context, volatile ids out of keys). Expect `bmc_event_log` context counts
   to grow only by what the BMC itself logs.
   **State (2026-09-30):** for the PR A catalog, two real captures through
   the dev stack 25 minutes apart diffed to nothing under
   `tools/diff_snapshots.py` on all eleven checks that ran (`bmc_security`
   not-present on both sides); each widening and new check is re-measured
   the same way on the lab unit before it is reported done.

## 8. Tests

- `tests/test_bmc_target.py` (pure): the name rule table (matches and
  non-matches above), address preference, two-match refusal.
- `tests/test_checks_bmc.py`: `test_checks_xcc.py` renamed; the `_FakeCtx`
  pattern stays. Add fixtures for the id resolution (a Dell-shaped
  `Systems` collection with `System.Embedded.1` proves the resolver), for
  every new check (hand-built from the Appendix B vocabulary until the lab
  harvest replaces them), for the OEM branch (`Vendor` not Lenovo →
  `not-present` on OEM-only checks, DMTF checks unaffected), and for the
  scrub list (a payload seeded with every secret-shaped leaf must reach raw
  scrubbed).
- `tests/test_envelope.py`: `target` on every check entry, `device.bmc`
  passes through, schema 1.2.
- `tests/test_redfish_paths.py`: `$expand=.($levels=2)` allowed, `$filter`
  refused.
- `tests/test_catalog_discovery.py` / registry contract: every `bmc_*` id
  has SEMANTICS and a valid compare mode (unchanged tests, new ids).
- The job modules stay outside CI (Nautobot absent); the ORM glue is small
  and exercised by the dry-run against the dev stack.

## 9. Coverage map entry (for `docs/coverage.md`)

Replace "Lenovo XCC — switched off" with a BMC section in the map's shape.
Layers and what carries them once §5 lands: **identity/platform**
(`bmc_system`, `bmc_chassis`, `bmc_inventory`, `bmc_pcie_slots`),
**firmware & persistence** (`bmc_firmware`, `bmc_bios` with pending settings,
`bmc_boot`, `bmc_power_policy`, `bmc_licenses`), **environment**
(`bmc_sensors`, `bmc_thermal`, `bmc_power`), **L1** (`bmc_network_adapters`,
`bmc_host_nics`), **storage** (`bmc_storage`), **management-plane config**
(`bmc_manager_network`, `bmc_manager_services`, `bmc_security`,
`bmc_certificates`), **security posture** (`bmc_accounts`, `bmc_security`),
**alerting** (`bmc_alerting`), **logs** (`bmc_event_log`), **tasks**
(`bmc_tasks`). Holes to record from the start: telemetry values (decision),
AuditLog (doctrine), host-OS facts the BMC does not see (the host platform's
job), power-feed circuit diversity (a facility record, as on IOS-XE).

## 10. Build sequence

0. **Done 2026-09-30**: the lab account's first-login password change is
   cleared, the crawl (Appendix A) printed 200 for all 425 resources, and
   the same held after the user moved the account to a ReadOnly-privilege
   role. Nothing is owed from a human before PR A.
1. **PR A — framework** (no new checks): `bmc_target.py`, detection and the
   second context in both jobs, `resolve_bmc_credentials`, envelope 1.2,
   probe hints, `checks_xcc.py → checks_bmc.py` with the `bmc_*` rename and
   the id resolution, `XCC_ENABLED` removed, constants, `tools/redfish_walk.py`,
   the `bmc` harvest spec, README/docs skeleton. Battery green with the
   existing fixtures renamed. Dry-run against the dev stack with a fake
   device carrying an `xcc` interface proves the ORM glue.
   **State (2026-09-30):** built, together with the §5a lab-note normalizer
   fixes the user listed for this stage (platform sequence-number spelling,
   DNS placeholders, SNMP enablement from the Lenovo agent block, log-message
   user names redacted before the trace and raw, the exact-name secret rule,
   `bmc_health`/`bmc_state` instead of the borrowed `xcc_health`). Proven on
   the dev stack (3.2.5) against the lab unit through Nautobot: the lab SE350
   modelled as `se350-lab-1` (platform Proxmox VE — unsupported, so decision
   2), interface `xcc` with the BMC's address, text-file secrets in Secrets
   Group `bmc-readonly`, the `bmc_secrets_group` Relationship; dry-run ok;
   capture 11 ok + `bmc_security` not-present, 32 GETs, 33 s, schema 1.2,
   `device.bmc` filled (vendor Lenovo), every entry `target: "bmc"`, no
   account or person name in raw or the debug trace (107 of 316 log rows
   and 113 message arguments redacted); shakedown 10/12 ok (the two
   advisories are the expected not-present security resource and an event
   log with no Warning/Critical entry), 63 GETs, and the platform/audit
   sequence numbers read 140/176 before AND after the run — the footprint
   finding of §6 re-measured through the job.
2. **Shakedown 1** on the lab unit (host on): §7 items 2–3. The live run of
   the existing collectors is already green under both privileges (Appendix
   C), so this is the Nautobot-side run and the fixture harvest; fix the
   normalizer items listed under §5a (sequence-number names, DNS
   placeholders, SNMP enablement, log-message redaction); commit the `_lab`
   fixtures.
   **State (2026-09-30):** done. The Nautobot-side run is recorded under
   step 1; the harvest (`tools/harvest_live.py --platform bmc`, 12 checks
   plus 146 extra reads, 159 GETs) was sanitized by `tools/make_fixtures.py`
   into 145 `tests/fixtures/xcc_*_lab.json` fixtures (plain and `$expand`
   forms of every collection, every OEM link, the log services' entries;
   the history containers and ServiceData excluded), with the lab subnet on
   192.0.2.0/24 and the mapping kept beside the raw harvest outside the
   repository. `tests/test_lab_fixtures.py` guards them (every serial, UUID,
   host name, account, address and log name an invention) and pins what the
   family reads from them, one class per widening group of PR B.
3. **PR B — widen the existing checks** (§5a) on the lab fixtures.
   **State (2026-09-30):** built by four builders in parallel (one per check
   group, each in its own worktree at the fixtures commit), merged, reviewed
   adversarially (§10a item 11), committed and proven through the dev stack
   against the lab unit with the committed code: all twelve checks
   `success` (`bmc_security` now ok with its `security|` leaves and the key
   manager's two certificate counts), 48 GETs in 49 s for the capture; the
   shakedown 12/12 ok (the empty event log reads "ok — empty is this check's
   healthy state"), 80 GETs in 86 s, and the log's platform/audit sequence
   numbers 140/176 before and after the run. No account or person name in
   the snapshot, raw, debug trace or shakedown report; the shakedown trace
   did carry every local account name, from its account-discovery probe —
   fixed (§10a item 12). `bmc_manager_network` is not split (§10a item
   2); the boot-override trio stays in `bmc_system` until `bmc_boot` exists;
   the capping and policy leaves stay in `bmc_power`'s context until
   `bmc_power_policy` exists.
4. **PR C — new checks** (§5b, `bmc_telemetry` optional), coverage-map
   section, prompt updates.
   **State (2026-09-30):** ten builders, one per check, each in its own
   worktree at the PR B commit, merged one commit per check in the user's
   order, each with its fixtures, tests, SEMANTICS and README row:
   `bmc_sensors`, `bmc_boot`, `bmc_power_policy` and
   `bmc_network_adapters` landed. What the builders found wrong in §5b is
   §10a item 13.
5. **Shakedown 2 and 3** (§7 items 4–5): host off, cable pull, an asserted
   discrete sensor, stability.
6. **PR D — docs**: README catalog rows, `coverage.md` walked with the
   lab facts, `floor-consolidation.md`, the superseded note in
   `nfv-core-move.md`; memory updated.
7. **Production**: model the interface, address, Secrets Group and
   Relationship on each SE350 (§2), dry-run a day ahead, then pre/post as
   usual. The Charlotte hosts' XCC reachability from the worker is the one
   environment fact this plan cannot settle.

Effort: PR A about a day, the widening about a day, the new checks two to
three days with fixtures, plus three shakedown half-days.

### 10a. What the build found (corrections to this plan)

Recorded as they were found, each with how it was resolved.

1. **`jobs/context.py` did need a change.** §3 said none, but §5a asks for
   the log-message user names to be redacted *before the trace*, and the
   debug trace is written inside `CollectorContext.get` — so `get` gained a
   `redact` callable (the `run_ssh` pattern: applied before the trace copy,
   the cache and the return; fail-closed; never passed to the transport; not
   part of the cache key). Every `bmc_*` read passes one: the family's
   exact-name scrubber by default (key material, credentials, user-name
   leaves, logged-in users reduced to counts), the log redactor for
   `Entries` pages, the accounts variant (account names kept) for the
   local-accounts collection. The plan never said what keeps SNMP
   communities or passwords out of the *trace*; this does.
2. **`bmc_manager_services` is in the §5b table but not in the "ten new
   ones" of §0** (nor in the user's PR C list). §5a's "split" of
   `bmc_manager_network` into addressing-and-time would drop the protocol
   and service keys unless that check exists, so the build keeps the
   protocols in `bmc_manager_network` (no split) and adds the Lenovo SNMP
   enablement there (the lab note asks for it on this check). Whether a
   separate `bmc_manager_services` is wanted is a question for the user.
3. **`$expand=.($levels=2)`** was re-measured through the shakedown: it
   inlines each adapter's `Ports`/`NetworkPorts`/`NetworkDeviceFunctions`
   collection *resource*, whose `Members` are still bare links — §4a is
   right in effect; `discovery.bmc.expand` reports both facts
   (`nested_collections_inline`, `nested_members_inline`).
4. **The service root's `Product` is null on XCC 6.10** (§0 implied a
   product name); `device.bmc.product` records what the root says.
5. **Appendix A's Python block failed CI** (`ruff format --check .` formats
   code blocks inside Markdown): the plan branch as committed would not
   have passed. The appendix now points at `tools/redfish_walk.py`.
6. **Not in the §1c table: the host's own transport failing while a BMC is
   modelled.** The build records every host check failed with the host's
   reason and still captures the BMC (its view is valid whatever the host's
   state); a host-only device keeps today's behaviour (no envelope).
7. Lenovo logs some actions as done `by user system` / `by user LXPM`
   (service pseudo-users); the redactor scrubs those words in those rows
   too — harmless, noted so a masked `LXPM` is not mistaken for a person.
8. **An adversarially verified review of PR A** (three reviewers — the job
   glue against a stubbed Nautobot, the catalog against the real walk, the
   doctrine and the tests — each finding re-checked by a verifier) found
   defects the plan's design had left open; all are fixed on the branch:
   the host transport opened before the BMC probe could leak a vSphere
   session on a soft time limit (the BMC is now opened first — Basic auth
   leaves nothing behind — and the whole open phase closes what it opened
   on any exception; an unexpected probe exception becomes the BMC's error);
   an IPv6-only BMC address was never reachable (the client brackets IPv6
   literals); a refused host login lost its footprint from the envelope that
   is now attached anyway; `device.bmc.captured` was set before the run (now
   after it, with a note when the soft limit skipped the BMC); the guide's
   `host_captured` sentence was wrong for a failed host transport; the probe
   hint could name the wrong probe (the client keeps `last_probe`);
   interfaces on installed modules were not searched (`all_interfaces`); a
   link-local address could win the address pick; `bmc_storage`'s per-member
   fallback could exhaust its budget on the lab layout (an `$expand` refusal
   is now remembered for the check, budget 18 + resolution); the DMTF
   `CommunityString`, URL userinfo, `CreatedBy`/`Owner` and contact names
   were not scrubbed (the plain `Community` name was dropped: it would have
   scrubbed a postal locality); the free-text `Contact=` of a settings log
   message kept a person's name; one harvest error could lose the whole
   harvest and print the BMC's address; the walk tool's resume marked every
   file 200 and could write the address into its index.
   Two deviations from §3 are deliberate: `device.bmc.addresses_seen` lists
   every usable address in preference order (the chosen one first), and a
   user-name leaf becomes the scrub marker with its emptiness kept rather
   than a `…_set` boolean (the marker already says "set").
9. **Rollout risk, for the user to weigh:** detection runs on every captured
   device. A production Device that already carries an interface whose first
   word is a BMC token (`ilo`, `idrac`, `ipmi` ... documenting a BMC's address
   is common) with an IP starts BMC capture on the first run after deploy —
   and FAILS (fail-closed) until the `bmc_secrets_group` Relationship and a
   Secrets Group exist for it, or while the BMC is unreachable from the
   worker. Query production for such interfaces before deploying (the dry run
   also names them per device; the README's NFV compute section has the
   query).
10. **What PR B's builders found wrong in §4/§5a** (resolved as stated):
    the lab security resource keys nine leaves, not eight (the eight came
    from a positional flatten that dropped the empty encapsulation allowlist
    and split the actions list); `EnableSELWrapping` sits on the SEL service,
    not on the StandardLog (read from the SEL service first, the source
    named in context); the MaintenanceLog also records hardware add/remove
    rows with part serials (`EventGroupId` 1; firmware rows are 0), not only
    firmware and configuration history; the §5a inventory row's
    `PCIeDevices?$expand=.($levels=2)` does not add the functions (one
    `$expand` GET per device, as §4a says); a top-level
    `Processor.CurrentClockSpeedMHz` is not DMTF (the DMTF leaf is
    `OperatingSpeedMHz`; XCC 6.10 serves only `Oem.Lenovo.CurrentClockSpeedMHz`,
    now read); the Lenovo date-time service's `Frequency` is in minutes by its
    own schema (keyed `ntp_sync_interval_min`); the host's OS address
    (`OSIPv4Address`) sits on the USB-LAN `ToHost` interface, not on the
    management port. Additions beyond §5a, all stable configuration served
    on the lab unit or free of GETs, were kept: the BMC's own console services
    and `front_panel_usb_port_enabled` in `bmc_system`, `has_switch_board`
    and an LED's location in `bmc_chassis`, DIMM `bus_width_bits` (the only
    ECC evidence where `ErrorCorrection` is not served), the volume's drive
    cache policy. Unverifiable on the lab unit and coded from the schemas
    with hand-built fixtures: every DMTF power-restore/delay/console leaf,
    RAID depth, the Subsystem fallbacks, a populated ActiveLog, SR-IOV
    virtual functions, a configured key manager.
11. **An adversarially verified review of PR B** (reviewers for the catalog
    against the lab walk and the vendor schemas, stability and hygiene, and
    the budgets; each finding re-checked by a verifier) confirmed four
    defects, all fixed before the commit: the key manager's last-poll time is
    spelled `EKMS.EKMSLastPollingTime` by the lab's own
    `LenovoSecureKeyLifecycle_v1` schema, which the time-like rule (anchored
    at the start of the name) would have keyed — a diff on every pair once
    polling runs; the rule now matches anywhere in the name and the
    hand-built fixture uses the schema's names; Lenovo's `Serviceable` enum is
    `Not Serviceable` / `ServiceableByLenovo` / `ServiceableByCustomer` (the
    fixture's bare `Serviceable` was an invention), so both positive values now
    read true and a `serviceable_by` field keeps who acts; §5a's
    host-interface "address" was not captured (now `host_interface_address`
    and `host_interface_address_mode`, read from the USB-LAN interface the
    host interface names, for every vendor); and a listed PCIe device whose
    function collection answered empty or 404 was recorded as a device
    without functions (now unmeasured: the check refuses, as for an empty
    family). From the review notes, also fixed: `pciefn` `enabled` no longer
    infers a value from the state (null where unserved; `state` is its own
    field); `bmc_inventory` remembers an `$expand` refusal across its
    families as `bmc_storage` does, and an `$expand` form answering 404 beside
    a served collection counts as a refusal (budget 28 + resolution; the lab
    layout's worst walk is 23); `bmc_bios` has a spare GET; and the shakedown
    reads an empty `bmc_event_log` as ok, saying why (the `empty-ok` tag),
    instead of flagging the healthy state. Two findings were refuted by their
    verifiers and left as built.
12. **The shakedown's account probe put every local account name into the
    shakedown trace.** It listed the accounts through the accounts redactor
    (names kept, as `bmc_accounts` will) to find the capture account. It now
    reads the list past the per-run cache — so it never shares a copy with a
    check that keeps the names, in either order — through a redactor that
    scrubs every name but the capture's own (which the envelope's transport
    footprint already names). Found by the hygiene count of the dev-stack
    proof, not by a review.
13. **What PR C's builders found wrong in §5b** (resolved as stated):
    - `bmc_sensors`: the lab unit's 89 sensors are 12 numeric and 77
      discrete by the `ReadingUnits` rule (§4b's "21 / 68" counted
      `ReadingType`, which the lab note itself calls untrustworthy); a
      discrete `Reading` is not always 0 (two Disabled sensors serve null,
      a utilisation sensor reads 1); the table keys `sensor|<Id>` while its
      lab note keys by `Name` — built by Name, the Id only as a tiebreak; it
      costs three reads beyond the cached Chassis, not 1–2. `CPU DTS` is
      unitless yet a measurement (a negative margin): it follows
      `bmc_thermal`'s margin rule into context instead of being keyed as an
      assertion that would flip at the throttle point. XCC 6.10 puts RPM
      figures into `EnvironmentMetrics.FanSpeedsPercent` (recorded as
      served). The family-wide tests over the hand-built set now accept
      not-present from a check newer than that set (it serves no Sensors
      collection).
    - `bmc_boot`: the table's `boot_order_current` / `boot_order_next`
      scalars and the lab note's `order|<member>` rows disagree — built as
      rows, one per boot-manager member, current and next kept in order.
      Appendix B gives a remote-control image (`LenovoRemoteMountMedia`)
      only `Size` and `Readonly`; `FilePath` and `Mounted` belong to the
      remote-map image, so `mount|` rows read `path`/`mounted` from their own
      leaves (null for remote-control images) and `Size` rides in context;
      the remote-map service itself is not linked on XCC 6.10 and is not
      read. XCC 6.10 serves none of `Boot.BootOrder`, `AliasBootOrder`,
      `BootNext`, `AutomaticRetryAttempts`, `StopBootOnFault`,
      `TrustedModuleRequiredToBoot`, `HttpBootUri` or `BootOptions`: those
      are coded from the DMTF schema on hand-built fixtures. Beyond the plan:
      a boot manager none of whose members lists an entry is unmeasured
      (refused), like an empty collection.
    - `bmc_power_policy`: there is no nested `Power.Oem.Lenovo.Capabilities`
      object on XCC 6.10 — the Power resource's `Oem.Lenovo` block itself is
      the Capabilities type, holding the three power flags (read from the
      PowerSubsystem's Lenovo block where no legacy Power resource is
      served). It costs four `$expand` GETs beyond the cached reads, not 3.
      `PowerLimit`, Lenovo `PowerUtilization` and the Lenovo redundancy
      settings are unserved on the lab unit: coded from the schemas, and the
      hand-built fixture marks the Lenovo enum values it cannot know as
      placeholders rather than guessing them. Whether a Lenovo watchdog's
      `TimerValueInSec` is the configured timer or a countdown is for the
      stability pair to show. A DMTF Job's `Payload` (`HttpHeaders`,
      `JsonBody`) can carry credentials the family scrubber did not see; the
      check reads the Jobs through its own composed redactor (see
      `bmc_tasks`).
    - `bmc_network_adapters`: 1 + 3 GETs per adapter (10 on the lab unit),
      not 1 + 2 — the lab note's `Down` spelling and Lenovo's
      `PortMaxSpeedbps` live only on the `NetworkPorts` twin, which is read
      for context beside `Ports`. `MaxSpeedGbps` is the port's configured
      maximum, not its capable speeds, so it is its own field and
      `capable_speeds_gbps` reads `LinkConfiguration` (unserved on the lab
      unit: null there). The lab serves a `LenovoPort` OEM type on `Port`
      that Appendix B does not list. `CapableLinkSpeedMbps` and
      `PortMaxSpeedbps` read 10 × 2^30 for a 10 Gbit/s port (a binary
      multiplier in a decimal unit): kept as served, in context. The iSCSI
      boot CHAP secrets and user names were not in the family scrubber (nor
      the sanitizer's rule): added to both.

## 11. Decisions still open (default assumed in parentheses)

1. Rename `xcc_*` → `bmc_*`, platform `xcc` → `bmc`, module `checks_bmc.py`
   (**yes**; nothing in production ever consumed the old ids, and iDRAC/iLO
   will reuse the family). Alternative: keep `xcc_*` and add vendor
   families later, at the cost of duplicated DMTF collectors.
2. A modelled BMC on a host whose platform the suite does not support yet
   (Proxmox today): capture the BMC alone and count the device as succeeded
   with a warning (**yes**), or fail the device (louder, but every capture of
   such a host is FAILED until its platform exists).
3. Relationship shape: key `bmc_secrets_group`, one Secrets Group to many
   Interfaces (**as stated**; both orientations accepted by the job).
4. Interface-name tokens and the "first word" rule (**as stated**; `ilom`,
   `irmc` can be added when an Oracle or Fujitsu unit appears).
5. Local BMC account names as keys in `bmc_accounts` (**yes**, the
   `iosxe_config` local-user precedent; sessions never).
6. Reading the AuditLog's first/last sequence numbers from the LogService
   *resource* (**yes**: it is the service resource, not its entries; the
   entries stay unread).
7. `bmc_telemetry` (**later**).
8. ~~A Redfish session per capture if Basic-auth GETs churned the platform
   log~~ — closed by the §6 measurement: no entry is written; GET-only with
   Basic auth stays.

## 12. Open questions the shakedown settles

Answered by the walk (§4): the SE350 generation (gen-1, 7Z46) and that its
security resource carries no ThinkEdge properties; member ids (`1` for
System, Manager and Chassis) and every collection size; `$expand` depth
(one level inlines, two does not); which thermal/power resources are
populated (legacy `Thermal`/`Power` plus `ThermalSubsystem/Fans`,
`ThermalMetrics`, `EnvironmentMetrics`, `Sensors`; no supplies anywhere);
that non-RAID M.2 SATA drives enumerate under `Storage` one per slot;
that Basic-auth GETs write no log entry; the log services offered (six, no
PlatformLog, audit entries inside StandardLog); the pending-BIOS link
(`Systems/1/Bios/Pending`) and registry (`BiosAttributeRegistry.1.0.0`, 126
attributes); that the boot order lives only in the Lenovo boot manager;
that the DMTF and Lenovo power-restore policy leaves are both absent.

Also answered: a ReadOnly-privilege account reads the entire tree on this
firmware (walk and collectors identical to the Supervisor run).

Still open: whether
port link state follows a cable with the host off, and whether an asserted
discrete sensor reads `1` or changes `Health` (§7 item 4); where, if
anywhere, this firmware exposes the AC power-restore policy (the XCC web UI
has the setting; Redfish here does not — probe the BIOS attribute registry
and the IPMI-only paths before declaring it unobservable); what a
de-powered external adapter does to the `Power Adapter N` sensors; whether
`SEL` ever exposes entries; how the `-Pending` firmware members read while
an update is staged; and, on a unit that has them, the shapes of populated
`Subscriptions`, `Recipients`, `Licenses`, `Tasks` and `PhysicalSecurity`.

## Appendix A — `tools/redfish_walk.py` (planning aid, promoted in PR A)

The crawl used at plan time is now `tools/redfish_walk.py` (PR A). It is
GET-only, fenced and paced **through the worker's own `RedfishClient`**
(the path fence, the 1 s `REDFISH_MIN_INTERVAL`, Basic auth, no session —
the planning aid had its own mini-fence and pacing); credentials and the
address come from the environment only (`--host-env`, `--user-env`,
`--password-env`) and are never printed (a connection error is shown with
`<host>` in place of the address); `--out` must lie outside the repository;
one JSON file per resource plus `_index.json`; a resource whose file already
exists is read from disk, so an interrupted walk resumes without touching the
BMC; `JsonSchemas`, `$metadata`/`odata`, registry files, single log entries
(the `Entries` collection inlines them) and AuditLog entries (unless
`--audit`) are skipped. `tests/test_redfish_walk.py` pins the link
classification and the file naming.

Run (the build session re-walked the lab unit this way on 2026-09-30: 425
resources, all HTTP 200, 427 GETs including the two probes):

    set -a; . /opt/stacks/.xcc.env; set +a
    python3 tools/redfish_walk.py --out /path/outside/the/repo/walk \
        --host-env host --user-env username --password-env password

## Appendix B — Lenovo OEM vocabulary served by the lab firmware

From the anonymously served `/redfish/v1/metadata/Lenovo*_v1.xml` files
(2026-09-30). Property names only; enum members omitted. Where a type is an
`Oem.Lenovo` block of a DMTF resource, the parent is named.

- **LenovoAccountService** (AccountService.Oem.Lenovo): PasswordExpirationPeriodDays, PasswordExpirationWarningPeriod, PasswordLength, MinimumPasswordReuseCycle, MinimumPasswordChangeIntervalHours, PasswordChangeOnFirstAccess, PasswordChangeOnNextLogin, CurrentLoggedUsers[] (LoginID, SessionType, IP_Hostname), WebInactivitySessionTimeout, ComplexPassword, GroupProfiles → LenovoManagerGroup (GroupName, Privilege[], Links.Role).
- **LenovoManagerAccount** (ManagerAccount.Oem.Lenovo): SSHPublicKey[].
- **LenovoManager** (Manager.Oem.Lenovo): RecipientsSettings (RetryCount, RetryInterval, RntryRetryInterval), ServiceAdvisor, KCSEnabled, release_name, OPSettings (SSOState, AuthorizationServerUri, UserInfoUri, ClientID, PubKey), AgentlessCapabilities[], MPFAHealthStatusEnabled, TrespassMessage; links Recipients, Security, RemoteControl, RemoteMap, Configuration, ServerProfile, ServiceData, FoD, Watchdogs, DateTimeService, SecureKeyLifecycleService.
- **LenovoAlertRecipient**: RecipientSettings (RecipientName, Enabledstate, AlertType, Address, IncludeEventLog, EnabledAlerts {CriticalEvents, WarningEvents, SystemEvents: Enabled, AcceptedEvents[]}).
- **LenovoSecurityService**: CryptographyManagement (TLSSecurityMode, MinTLSLevel), Configurator (FWRollback), EncapSettings (EncapMode, WhiteList[]), SSLSettings (EnableHttps, EnableLDAPS, EnableCIMOverHttps), SecurityCapabilities (SupportedActions[]). No ThinkEdge properties on this firmware.
- **LenovoSecureKeyLifecycle**: KeyRepoServers[] (HostName, Port, Index), EKMS (local cached key settings/status, polling settings/status, last polling time), DeviceGroup, Protocol, TestConnectionTimeoutInSec, ClientCertificate, ServerCertificate.
- **LenovoRemoteControlService**: ServiceEnabled, Sessions → LenovoRemoteControlSession (Username, ActiveSession, Timeout), MountImages → LenovoRemoteMountMedia (Size, Readonly). **LenovoRemoteMapService**: ServiceEnabled, MountImages → LenovoRemoteMapMedia (FilePath, Type, Username, Password, Domain, Readonly, Options, Owner, Mounted).
- **LenovoConfigurationService**: BackupStatus, RestoreStatus. **LenovoServerProfileService**: Enabled, ServerIP, ServerPort, UserID, Password, Certificates. **LenovoServiceData**: CaptureTimeout, FileTransferTimeout, DataCollectionType, ExportingSchemes, ExportProgress, IsScreenAvailable.
- **LenovoFoDService**: Tier, Keys → LenovoFoDKey (IdTypes[], Identifier, DescTypeCode, Status, Expires, UseCount, UseLimit, Bytes[]).
- **LenovoWatchdog**: TimerValueInSec, State, Type, TimeoutIntervalInSec, TimerExpired.
- **LenovoDateTimeService**: SettingMethod, DateTime, HostTimeFormat, UTCOffset, AutoDST, NTPServerAddresses[], Frequency.
- **LenovoManagerNetworkProtocol** (ManagerNetworkProtocol.Oem.Lenovo): CimOverHTTPS (ProtocolEnabled, Port, BackendEnabled), SLP (ProtocolEnabled, Port, MulticastAddress, AddressType), WebOverHTTPS (ProtocolEnabled), SFTP (ProtocolEnabled, Port), OpenPorts[], SNMP → LenovoSNMPProtocol, DNS → LenovoDNS, SMTPClient → LenovoSMTPClient, LDAPClient → LenovoLDAPClient.
- **LenovoSNMPProtocol**: CommunityNames[], SNMPv3Agent (ProtocolEnabled, Port, ContactPerson, Location, Links.UsersSNMPv3Settings), SNMPTraps (ProtocolEnabled, Port, SNMPv1TrapEnabled, SNMPv2TrapEnabled, AlertRecipient {EnabledAlert}, Targets[] {Addresses[]}).
- **LenovoDNS**: DNSEnable, PreferredAddresstype, IPv4Address1-3, IPv6Address1-3, DDNS[] (DDNSEnable, DomainNameSource, DomainName), LXCADNSDiscovery (DiscoverLXCAEnabled, XClarityManager, XClarityManagerList[]).
- **LenovoSMTPClient**: ProtocolEnabled, AccessInfo, AccessPort, Reverse-path, Authentication (Required, Password, UserName, Method).
- **LenovoLDAPClient**: ProtocolEnabled, Authorization, LDAPServers (Method, Server1-4 HostName_IPAddress and Port, SearchDomain), RootDN, UIDSearchAttribute, BindingMethod (Method, ClientDN, ClientPassword), ActiveDirectory (RoleBasedSecurity, ServerTargetName, ForestName, Links.GroupProfiles), GroupFilter, GroupSearchAttribute, LoginPermissionAttribute.
- **LenovoEthernetInterface** (EthernetInterface.Oem.Lenovo on the manager NIC): IPv6AddressAssignedby[], IPv4AddressAssignedby, InterfaceFailoverMode, InterfaceNicMode, DomainName, NetworkSettingSync, IPv4Enabled, IPv6Enabled, HostNameFromDHCPEnabled, AddressMode, OSIPv4Address, PortForwarding → LenovoPortForwarding (USBPortForwardingEnabled, PortForwardingMap → LenovoPortForwardingMap: Initialized, DefaultIPEnabled, IPAddress, AddressMode, Type, USBPort, ExternalPort).
- **LenovoSerialInterface** (SerialInterface.Oem.Lenovo): CLIMode, EnterCLIKeySequence, SerialInterfaceState.
- **LenovoComputerSystem** (ComputerSystem.Oem.Lenovo): NumberOfReboots, TotalPowerOnHours, SystemStatus, TPMSettings (AssertRPP, EnableRPP, AssertDurationMins), FrontPanelUSB (FPMode, InactivityTimeoutMins, IDButton, PortSwitchingTo, PortEnabled), Metrics, HistorySysPerf, ScheduledPowerActions → LenovoScheduledPowerAction (Type, Activated, Interval, Time), BootSettings → LenovoBootManager (BootOrderNext[], BootOrderCurrent[], BootOrderSupported[]).
- **LenovoBios** (Bios.Oem.Lenovo): IsUefiPowerOnPasswordSet, IsUefiAdminPasswordSet.
- **LenovoChassis** (Chassis.Oem.Lenovo): HasSwitchBoard, SystemBoardSerialNumber, ProductName, VPD_ID, POS_ID, PRODUCT_ID, Entity_ID, Device_ID, FruPartNumber, Slots → LenovoSlot (ConnectorLayout, Number, MaxDataWidth, SupportsHotPlug), LEDs → LenovoLED (Color, State, DutyCycle, PeriodInMillSec, Location, EntityID, EntityInstance, DeviceEntity).
- **LenovoPower** (Power.Oem.Lenovo and members): Capabilities (PowerRestorePolicy, WakeOnLANEnabled, PowerOnPermissionEnabled, LocalPowerControlEnabled, RandomDelay); PowerControl.Oem.Lenovo: PowerUtilization (UtilizationMode, EnablePowerCapping, LimitMode, GuaranteedInWatts, MinLimitInWatts, MaxLimitInWatts, CapacityMinAC/MaxAC/MinDC/MaxDC), HistoryPowerMetric; PowerSupply.Oem.Lenovo: Location, FruPartNumber, HistoryPowerSupplyMetric. **LenovoRedundancy**: NonRedundantAvailablePower, PowerRedundancySettings (PowerRedundancyPolicy, MaxPowerLimitWatts, PowerFailureLimit, EstimatedUsage).
- **LenovoThermal**: HistoryTempMetric; LenovoFan: Location.
- **LenovoMemory** (Memory.Oem.Lenovo): FruPartNumber, ManufactureDate, MPFA (MPFA_HealthStatus {Major, Minor}, MPFA_SevereFaults {FaultType, ErrorCnt, Timestamp, Location}).
- **LenovoProcessor** (Processor.Oem.Lenovo): NumberOfEnabledCores, ExternalBusClockSpeedMHz, CurrentClockSpeedMHz, ProcessorFamily, CacheInfo[] (CacheLevel, MaxCacheSizeKByte, InstalledSizeKByte).
- **LenovoNetworkPort** (NetworkPort.Oem.Lenovo): PortMaxSpeedbps, PhysicalPortMacAddress.
- **LenovoStorage** (StorageController.Oem.Lenovo): SupportedRaidLevels, Mode, Battery (DesignCapacity, FullChargeCapacity, RemainingCapacity, DesignVoltageMV, VoltageMV, CurrentMA, TemperatureCelsius, ProductName, Manufacturer, FirmwareDescription, SerialNumber, BatteryType, OperationalStatus, Chemistry), MinStripeSizeBytes, MaxStripeSizeBytes. **LenovoVolume**: DriveCachePolicy, AccessPolicy, IOPolicy, RaidLevel, Bootable, SpanDepth, DiskPerSpan. **LenovoDrive**: Temperature, DriveStatus, SMARTData.
- **LenovoUpdateService** (UpdateService.Oem.Lenovo): XCCBackupAutoPromote, FirmwaresDataReady, FirmwareServices → LenovoFirmwareService (BMAppStatus, FreeRdocSpaceInKB, Started, BMU_Credential {RemoteID, Secret}, ChangeHistory).
- **LenovoLogService** (LogService.Oem.Lenovo): SupportedCategories, DesiredCategories, VMMoveCategory[], PlatformFirstSeqNum, PlatformLastSeqNum, AuditFirstSeqNum, AuditLastSeqNum, PlatformHidden*/AuditHidden* sequence numbers, AuditLogCapabilities[], EnableSELWrapping, MPFA_FirstSeqNum, MPFA_LastSeqNum.
- **LenovoLogEntry** (LogEntry.Oem.Lenovo): Source, Serviceable[], CommonEventID, LenovoMessageID, Hidden, FailingFRU[] (FRUNumber, FRUSerialNumber), EventSequenceNumber, AuxiliaryData, AffectedIndicatorLEDs[] (LEDIdentifier, LEDState), EventFlag, EventType, IsLocalEvent, EventID, ReportingChain, RelatedEventID, RawDebugLogURL, TSLVersion, TotalSequenceNumber, LogType.
- **LenovoMessageRegistry**: MessageID, AlertCategory, TrapType, SeverityCode, Audit, EventID, CallHome, Serviceable, Device, Hidden.
- **LenovoTask** (Task.Oem.Lenovo): FFDCForDownloading (Path, Port), ServProfData. **LenovoDeviceInfo**: UUID, Location. **LenovoEvent**: SystemUUID, SystemSerialNumber, SystemMachineTypeModel, EventInformation.
- **LenovoHistoryMetricValueContainer**: ContainerName, TimeScope, Container[] (MetricType, MetricValue, Duration, Timestamp, TimestampWithTZ).

## Appendix C — Live results on the lab unit (2026-09-30)

Existing collectors, run from this box through `RedfishClient` and
`CollectorContext` with `debug=True` (the harness is the `bmc` platform spec
`tools/harvest_live.py` gains in PR A). 30 GETs, ~30 s, TLS default. Run
twice: with the account on a Supervisor-privilege role and, after the user
changed it, on a ReadOnly-privilege role — statuses, key sets and request
lists were identical, and the read-only walk of the tree matched the first
one on every path and every leaf.

| Check | Status | Keys | GETs (beyond the cached root/system/manager reads) |
| --- | --- | --- | --- |
| `xcc_system` | ok | 38 | `Systems/1/SecureBoot`, `Managers/1/EthernetInterfaces/NIC` |
| `xcc_security_state` | not-present | 0 | `Managers/1/Oem/Lenovo/Security` (no ThinkEdge properties) |
| `xcc_thermal` | ok | 6 | `Chassis/1/Thermal` |
| `xcc_power` | ok | 4 | `Chassis/1/Power` |
| `xcc_inventory` | ok | 9 | Memory, Processors, PCIeDevices, each one `$expand` |
| `xcc_host_nics` | ok | 4 | `Systems/1/EthernetInterfaces?$expand` |
| `xcc_storage` | ok | 8 | `Storage?$expand`, four drives, four `Volumes?$expand` |
| `xcc_firmware` | ok | 15 | `UpdateService/FirmwareInventory?$expand` |
| `xcc_event_log` | ok | 0 (312 informational) | `LogServices`, `StandardLog`, `StandardLog/Entries` (one page) |
| `xcc_bios` | ok | 20 (of 126) | `Systems/1/Bios` |
| `xcc_manager_network` | ok | 38 | `Managers/1/NetworkProtocol` |
| `xcc_chassis_location` | ok | 20 | `Chassis/1` |

Resource inventory from the walk (member counts; singletons omitted):

```
Systems 1 · Managers 1 · Chassis 1 · Registries 11
AccountService/Accounts 12 · Roles 31 · Oem/Lenovo/GroupProfiles 16 · LDAP/Certificates 0
EventService/Subscriptions 0 · JobService/Jobs 3 · TaskService/Tasks 0 · LicenseService/Licenses 0
TelemetryService/MetricDefinitions 2 · MetricReportDefinitions 12 · MetricReports 6
UpdateService/FirmwareInventory 15 · Oem/Lenovo/FirmwareServices 1 · RemoteServerCertificates 0
Systems/1/LogServices 6 (StandardLog 311 entries, ActiveLog 0, MaintenanceLog 73, SaLog 0, DiagnosticLog 3, SEL no Entries link)
Systems/1/Memory 4 · Processors 1 · EthernetInterfaces 5 · NetworkInterfaces 3 · Storage 4 (Volumes 0 and StoragePools 0 each) · VirtualMedia 2
Systems/1/Oem/Lenovo/BootSettings 5 · ScheduledPowerActions 3 · Metrics 0
Chassis/1/Sensors 89 · NetworkAdapters 3 (Ports 2/2/0, NetworkPorts 2/2/0, NetworkDeviceFunctions 2/2/0) · PCIeDevices 4 (PCIeFunctions 1/2/2/1) · Controls 1
Chassis/1/ThermalSubsystem/Fans 3 · Oem/Lenovo/LEDs 4 · Oem/Lenovo/Slots 6
Managers/1/EthernetInterfaces 2 (ToHost PortForwardingMap 14) · HostInterfaces 1 · SerialInterfaces 1 · VirtualMedia 2
Managers/1/NetworkProtocol/HTTPS/Certificates 1
Managers/1/Oem/Lenovo/Watchdogs 4 · Recipients 0 · SsoCertificates 0 · FoD/Keys 0 · RemoteControl/Sessions 0 · RemoteControl/MountImages 0
Managers/1/Oem/Lenovo/SecureKeyLifecycleService/{ClientCertificate,ServerCertificate} 0 · ServerProfile/Certificates 0
```
