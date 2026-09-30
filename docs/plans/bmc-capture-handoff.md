# Handoff: capture the BMC (XCC first) as part of the host's report

Status: **plan only — nothing built.** Written 2026-09-30 against `main` after
PR #12, the Nautobot 3.2.5 dev stack on this box, and the lab XClarity
Controller at the address in `/opt/stacks/.xcc.env`. It supersedes the XCC
decisions recorded in `docs/plans/nfv-core-move.md` §0 (a separate
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
- **What the lab XCC answered.** Redfish 1.15.0, `$expand` to two levels,
  `$select`, and every service root link the catalog wants (Systems, Chassis,
  Managers, UpdateService, AccountService, EventService, TaskService,
  JobService, TelemetryService, LicenseService, CertificateService). Its 204
  schema files are readable anonymously and give the exact property
  vocabulary (§4, Appendix B). **Nothing below the service root could be read:
  the account in `/opt/stacks/.xcc.env` answers every authenticated GET with HTTP 403
  `Base.1.12.PasswordChangeRequired`** (first-login password change pending).
  Clearing that is a human step in the XCC web UI and is item 0 of §10; the
  suite never writes to a BMC.
- **Catalog**: the twelve existing checks are renamed and widened, and ten
  new ones close the layers a BMC uniquely sees (boot order, power-restore
  policy and watchdogs, the Sensors collection, PCIe slots, network adapters,
  local accounts and providers, alerting destinations, certificates,
  licences, tasks). §5 has the table; roughly 60–100 paced GETs per BMC.

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
5. **The BMC account**: a local XCC user with the built-in **ReadOnly** role
   and Redfish/REST access enabled. **Its first-login password change must be
   completed by a human** (XCC web UI → log in as the account → set the new
   password, or as an administrator clear "change password on first access"
   for it). Until then every authenticated GET is refused with
   `Base.1.12.PasswordChangeRequired` (found on the lab unit 2026-09-30) and
   the capture's probe hint will say exactly this.
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
| `jobs/transport_redfish.py` | `ping()`: anonymous root, then the authenticated **Systems collection**. `probe_get`: when the body is JSON, record `message_id` (`error.@Message.ExtendedInfo[0].MessageId`) and `message`. `probe_hint`: HTTP 403 with a `PasswordChangeRequired` message id → "the account's first-login password change is pending; complete it once in the BMC web UI (the suite never writes to a BMC), then re-run"; plain 403 keeps today's role hint. Nothing else changes; the CI fence guard (one `session.get` site, `fence_path` before send) stays as is. |
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

## 4. What the lab XCC told us on 2026-09-30

Facts, so the builder does not have to rediscover them:

- Reachable over HTTPS; the service root answers anonymously in ~150 ms.
  `RedfishVersion 1.15.0`, `ServiceRoot.v1_13_0`, `Vendor Lenovo`,
  `ProtocolFeaturesSupported`: ExpandQuery (ExpandAll, Links, Levels, NoLinks,
  MaxLevels 2), SelectQuery, FilterQuery, ExcerptQuery, OnlyMemberQuery,
  DeepOperations (irrelevant: never used). Root links: Systems, Chassis,
  Managers, UpdateService, AccountService, EventService, TaskService,
  JobService, TelemetryService, LicenseService, CertificateService,
  Registries, JsonSchemas, SessionService. So the `$expand` strategy the
  collectors already prefer is the right one, and `$levels=2` can inline
  `PCIeDevices → PCIeFunctions` and `NetworkAdapters → Ports/DeviceFunctions`.
- The account in `/opt/stacks/.xcc.env` is blocked, not the device: every authenticated GET (Systems,
  Chassis, Managers, UpdateService, AccountService, …) returned HTTP 403 with
  `Base.1.12.PasswordChangeRequired` pointing at
  `/redfish/v1/AccountService/Accounts/3`. Only a PATCH of the password
  clears it, which the suite must never do. Human step (§2 item 5), then
  everything in §7 becomes possible. Until then the unit's model, generation,
  host power state, member ids and collection sizes are **unknown**.
- `/redfish/v1/$metadata` and its 204 referenced schema files under
  `/redfish/v1/metadata/` are anonymous. They are the authoritative list of
  resource types and properties this firmware implements (a service only
  references what it serves). Highlights, with the schema version served:
  ComputerSystem 1.17 (PowerRestorePolicy, HostWatchdogTimer, Boot.BootOrder,
  BootOptions, LastResetTime, BootProgress, PowerOn/Off/CycleDelaySeconds,
  SerialConsole/GraphicalConsole/VirtualMediaConfig, TrustedModules,
  PowerMode, IdlePowerSaver, KeyManagement), Chassis 1.19 (Sensors,
  PCIeSlots, NetworkAdapters, PowerSubsystem, ThermalSubsystem,
  EnvironmentMetrics, Controls, Drives, PhysicalSecurity, Location,
  LocationIndicatorActive, Certificates), Manager 1.14, ManagerNetworkProtocol
  1.8 (HTTP/HTTPS/SSH/SNMP/IPMI/VirtualMedia/KVMIP/SSDP/NTP/DHCP/DHCPv6/RDP/RFB/Proxy),
  Sensor 1.5 with Thresholds, PowerSupply 1.3 + PowerSupplyMetrics, Fan 1.1,
  ThermalMetrics (TemperatureSummaryCelsius Intake/Exhaust/Ambient/Internal),
  Power 1.7 and Thermal 1.7 (the legacy resources the current checks read
  are still served), PCIeSlots 1.5, PCIeDevice 1.9, PCIeFunction 1.3,
  NetworkAdapter 1.9 (Controllers[].FirmwarePackageVersion, LLDPEnabled),
  NetworkPort 1.4, NetworkDeviceFunction 1.8, Port 1.6, Memory 1.14 +
  MemoryMetrics, Processor 1.14 (ProcessorId.MicrocodeInfo, TDPWatts,
  TurboState) + ProcessorMetrics, Storage 1.14, Drive 1.14, Volume 1.7,
  StoragePool, Bios 1.2 (ResetBiosToDefaultsPending) + AttributeRegistry +
  Settings (pending), SecureBoot 1.1 (**no** SecureBootDatabases schema:
  not served), BootOption 1.0, Certificate 1.5 + CertificateLocations,
  License 1.0 + LicenseService, EventService 1.7 (SMTP block) +
  EventDestination 1.11 (SNMP, Syslog filters), LogService 1.3 + LogEntry
  1.11, Job/JobService, Task/TaskService, TelemetryService +
  MetricReportDefinition/MetricReport/Triggers, AccountService 1.10 +
  ManagerAccount 1.8 (PasswordChangeRequired, AccountTypes) + Role +
  ExternalAccountProvider 1.3, HostInterface 1.3, SerialInterface,
  VirtualMedia 1.5, SoftwareInventory 1.6, UpdateService 1.11, Assembly,
  Redundancy, Endpoint/Fabric/CompositionService (rarely populated).
- Lenovo OEM types (Appendix B has every property): `LenovoSecurityService`
  on this firmware carries **TLS/crypto mode, SSL enablement, firmware
  rollback and encapsulation settings — no ThinkEdge lockdown, motion,
  intrusion or SED properties**. So on this unit `xcc_security_state` would
  read not-present by its own rule, which is why §5 turns it into a generic
  "flatten every leaf" security check with the ThinkEdge fields as optional
  named extras. Also served: `LenovoAlertRecipient` (email/syslog recipients
  with per-severity event filters), `LenovoSNMPProtocol` (agent, traps,
  targets, community names), `LenovoDNS`, `LenovoSMTPClient`,
  `LenovoLDAPClient`, `LenovoDateTimeService`, `LenovoScheduledPowerAction`,
  `LenovoWatchdog`, `LenovoBootManager` (BootOrderCurrent/Next/Supported),
  `LenovoFoDService`/`LenovoFoDKey` (feature tier and keys),
  `LenovoLED`/`LenovoSlot` under Chassis, `LenovoPortForwarding`,
  `LenovoRemoteControlService`/`RemoteMap`, `LenovoConfigurationService`
  (backup/restore status), `LenovoServerProfileService`, `LenovoUpdateService`
  (XCCBackupAutoPromote), `LenovoAccountService` (password policy incl.
  `PasswordChangeOnFirstAccess`, `CurrentLoggedUsers`), `LenovoLogService`
  (Platform/Audit first and last sequence numbers, `EnableSELWrapping`),
  `LenovoLogEntry` (CommonEventID, FailingFRU, EventSequenceNumber),
  `LenovoMemory` (FRU part number, manufacture date, MPFA health),
  `LenovoProcessor`, `LenovoNetworkPort` (PhysicalPortMacAddress),
  `LenovoEthernetInterface` (NIC mode dedicated/shared, failover mode,
  OSIPv4Address), `LenovoPower` (Capabilities.PowerRestorePolicy,
  WakeOnLAN, PowerUtilization capping), `LenovoRedundancy`
  (PowerRedundancySettings), `LenovoStorage` (controller battery, RAID
  levels), `LenovoVolume`, `LenovoDrive` (temperature, SMART), `LenovoBios`
  (admin/power-on password *set* flags), `LenovoComputerSystem`
  (NumberOfReboots, TotalPowerOnHours, SystemStatus, TPMSettings,
  FrontPanelUSB, ScheduledPowerActions, BootSettings),
  `LenovoManager` (KCSEnabled, TrespassMessage, AgentlessCapabilities,
  release_name, links to every OEM service above).
- The raw crawl output (`xcc-crawl/`), the schema files and the property
  dump live only in this session's scratchpad; Appendix B keeps what matters.

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

### 5b. New checks

| Id | Tier | Source (GETs) | Normalized view | Context | Why it is worth a check (general value) |
| --- | --- | --- | --- | --- | --- |
| `bmc_boot` | 1 | `Systems/<id>` (cached), `Boot.BootOptions` collection expanded (1), Lenovo `Oem.Lenovo.BootSettings` collection expanded (1), `Managers/<id>/VirtualMedia` or `Systems/<id>/VirtualMedia` expanded (1), Lenovo `RemoteMap` mount images (1) | scalars `boot_order` (ordered list), `boot_override` / `_target` / `_mode`, `boot_next`, `automatic_retry_config` / `_attempts`, `stop_boot_on_fault`, `trusted_module_required_to_boot`, `http_boot_uri`, Lenovo `boot_order_current` / `boot_order_next`; `option|<BootOptionReference>` → display_name, enabled, uefi_device_path, alias; `vmedia|<Id>` → inserted, image (userinfo stripped), media_types, connected_via, write_protected; Lenovo `mount|<Id>` → path, mounted, readonly | `boot_order_supported`, `remaining_automatic_retry_attempts` | Consumed by every reload, firmware, disk or defaults-load change; a reordered boot list or a leftover mounted ISO is the classic "came back on the wrong device" cause, invisible from the OS; stable between healthy captures; 4–5 GETs. |
| `bmc_power_policy` | 1 | `Systems/<id>` (cached), `Chassis/<id>/Power` (cached), `Chassis/<id>/Controls` expanded (1), Lenovo `Systems/<id>.Oem.Lenovo.ScheduledPowerActions` expanded (1), Lenovo `Managers/<id>.Oem.Lenovo.Watchdogs` expanded (1) | scalars `power_restore_policy` (DMTF and Lenovo `Power.Oem.Lenovo.Capabilities`, both), `wake_on_lan`, `power_on_permission`, `local_power_control`, `random_delay`, `host_watchdog_*`, `power_limit_w` / `power_limit_exception` / `power_capping_enabled` / `limit_mode` / `guaranteed_w`, `power_redundancy_policy` / `max_power_limit_w` / `power_failure_limit`; `control|<Id>` → control_type, control_mode, set_point, set_point_units, allowable min/max; `sched|<Id>` → type, activated, interval, time; `watchdog|<Id>` → type, state, timer_s, timeout_interval_s | `watchdog_expired` flags, `non_redundant_available_power_w`, readings of every Control | Consumed by every power event and any change that reboots or re-powers a server: whether the host returns after an AC loss, whether a cap or a scheduled power action can bite, whether a watchdog reset is armed; all configuration, so it diffs to nothing between healthy captures; 3 GETs. |
| `bmc_sensors` | 1 | `Chassis/<id>/Sensors?$expand=.($levels=1)` (1; per-member fallback needs the budget raised to the collection size, reported by the shakedown), `Chassis/<id>/EnvironmentMetrics` (1) | `sensor|<Id>` → reading_type, physical_context (+ sub-context), state, health, reading_units, thresholds (non-null caution/critical/fatal readings, snake-cased), and `reading` only for ambient/intake/inlet/exhaust-class temperature sensors (8 °C tolerance, the `bmc_thermal` rule) | every reading (`readings` by key, with `ReadingTime`), peak readings, `environment` (chassis power W, energy kWh, temperature, humidity where served), sensor count by reading_type | The modern superset of Thermal/Power with one vocabulary (`ReadingType`): voltage rails, currents, energy, humidity and intrusion sensors that the legacy resources omit, and the view that survives when a firmware drops `Thermal`/`Power`; state/health keys are stable, readings are context; 1–2 GETs. Overlaps `bmc_thermal`/`bmc_power` by design (the legacy checks keep their fixtures and their field-verified semantics; the shakedown says whether both are served). |
| `bmc_pcie_slots` | 1 | `Chassis/<id>/PCIeSlots` (1), Lenovo `Chassis/<id>.Oem.Lenovo.Slots` expanded (1) | `slot|<index or Location.ServiceLabel>` → slot_type, pcie_type, lanes, state (Enabled/Absent), hot_pluggable, location, linked_devices (PCIeDevice ids); Lenovo extras connector_layout, max_data_width | slot count, occupied count | Consumed by any hardware swap, riser reseat or transport; an unseated card is an `Absent` slot here even when the device's own row simply vanishes from `bmc_inventory`; stable; 1–2 GETs. |
| `bmc_network_adapters` | 1 | `Chassis/<id>/NetworkAdapters?$expand=.($levels=2)` (1; fallback: collection + per adapter + its Ports/NetworkPorts + NetworkDeviceFunctions, budget 16) | `adapter|<Id>` → manufacturer, model, serial, part_number, firmware_package_version (Controllers[]), port_count, function_count, lldp_enabled; `port|<adapter>|<port>` → link_status, physical_port_number, active_link_technology, capable speeds (sorted), autoneg, flow_control_configuration; `netfn|<adapter>|<fn>` → net_dev_func_type, permanent_mac (lower-cased), device_enabled, boot_mode, virtual_functions_enabled, max_virtual_functions, assigned port | current_link_speed_mbps per port, Lenovo `port_max_speed_bps`, `physical_port_mac`, host_power_state | The BMC-side L1 view: adapter firmware (which `bmc_firmware` may list only as a bundle), per-port link and negotiated capability, burned-in MACs that join to the hypervisor's physical-NIC MACs (`vmware_pnics.mac`) and to the switch-side MAC table; consumed by every re-cabling, NIC firmware and SR-IOV change; 1–4 GETs. |
| `bmc_manager_services` | 2 | `Managers/<id>/NetworkProtocol` (cached) with its `Oem.Lenovo` block, `Managers/<id>` (cached) Oem links: `RemoteControl`, `RemoteMap`, `Configuration`, `ServerProfile` (1 each), `Managers/<id>/SerialInterfaces` expanded (1), NIC `Oem.Lenovo.PortForwarding` (+ maps, 1–2) | scalars per protocol `<protocol>_enabled` / `_port` for every DMTF block (HTTP, HTTPS, SSH, SNMP, IPMI, VirtualMedia, KVMIP, SSDP, DHCP, DHCPv6, RDP, RFB, Proxy) and Lenovo (CIM-over-HTTPS, SLP, Web-over-HTTPS, SFTP), `open_ports` (sorted), SNMP agent (`snmpv3_enabled` / `_port` / `contact` / `location`; community names **scrubbed**, v1 count only), `kcs_enabled`, `mpfa_health_enabled`, `remote_control_enabled`, `remote_map_enabled`, `server_profile_enabled` / `_server` / `_port`, `usb_port_forwarding_enabled` + `pfmap|<Id>` rows, `serial|<Id>` → bit_rate, parity, data/stop bits, flow_control, Lenovo CLI mode | active remote-control session **count** (never who), `trespass_message`, `agentless_capabilities`, `configuration_backup_status` / `restore_status` | The management plane's own attack surface and service set; consumed by every hardening, firmware and BMC-network change; configuration, so stable; 6–10 GETs. |
| `bmc_accounts` | 1 | `AccountService` (1) with `Oem.Lenovo`, `Accounts` expanded (1), `Roles` expanded (1), `LDAP` / `ActiveDirectory` / `AdditionalExternalAccountProviders` (1–2), Lenovo `NetworkProtocol.Oem.Lenovo.LDAPClient` (cached from the protocol read) | policy scalars (min/max password length, lockout threshold/duration/reset, auth-failure logging threshold, local account auth mode, password expiration days, Lenovo complexity, reuse cycle, change-on-first-access, web inactivity timeout); `account|<UserName>` → role_id, enabled, locked, password_change_required, account_types (sorted), snmpv3_configured, ssh_key_count; `role|<RoleId>` → assigned_privileges (sorted), oem_privileges (sorted), is_predefined; `provider|<type>` → enabled, service_addresses (sorted), base DNs, bind DN, role-mapping count (bind password and any key scrubbed) | `current_logged_users` **count only** (our own session is one of them), `supported_account_types` | Security posture of the management plane; local BMC accounts are configuration and are keyed by name on the `iosxe_config` precedent (a local-user change must diff; nothing about people's sessions is kept); consumed by every credential rotation, hardening and BMC firmware change; stable; 4–6 GETs. |
| `bmc_alerting` | 1 | `EventService` (1), `Subscriptions` expanded (1), Lenovo `Managers/<id>.Oem.Lenovo.Recipients` expanded (1), Lenovo SNMP traps block (cached), `LogServices/<platform log>` `SyslogFilters` if served | scalars `event_service_enabled`, `delivery_retry_attempts` / `_interval_s`, `smtp_enabled` / `_server` / `_port` / `_from` / `_connection_protocol` / `_auth_method` (credentials scrubbed); `subscription|<Id>` → destination (scheme://host:port, userinfo stripped), protocol, subscription_type, event_format, context, registry_prefixes, resource_types, status, heartbeat; `recipient|<Id>` → name, enabled, alert_type, address, include_event_log, critical/warning/system enabled flags and accepted event lists (sorted); `snmp_trap_enabled` / `_port` / `_v1` / `_v2`, `trap_targets` (sorted; communities scrubbed) | delivery counters if any | "Is anyone still being told": a subscription or recipient that stops resolving after a re-address, a management-server change or a firmware reset is silent otherwise; consumed by every network, addressing and management-tool change; stable; 3–5 GETs. |
| `bmc_certificates` | 1 | `CertificateService/CertificateLocations` (1) then each `Links.Certificates[]` member (budget 12) | `cert|<resource path>` → certificate_type, subject (CN, O, OU), issuer (CN, O), valid_not_before / valid_not_after, key_usage (sorted), signature_algorithm, self_signed, usage types | fingerprint + algorithm, serial number, days-to-expiry tallies | The `iosxe_pki` twin: a factory reset regenerates the self-signed HTTPS certificate, an LDAP/KMIP trust certificate expiring breaks authentication or key retrieval; consumed by every reset, hardening and PKI change; stable; 2–12 GETs. |
| `bmc_licenses` | 1 | `LicenseService` (1), `Licenses` expanded (1), Lenovo `Managers/<id>.Oem.Lenovo.FoD` (1) and its `Keys` expanded (1) | scalars `license_service_enabled`, `expiration_warning_days`, Lenovo `fod_tier`; `license|<Id>` → license_type, license_origin, removable, manufacturer, sku, part_number, status, authorization_scope, expiration_date, grace_period_days; `fodkey|<Id>` → identifier types, status, expires, use_count / use_limit | install_date, remaining_duration / use count | Feature entitlements (remote KVM, virtual media, XCC tier) are tied to the machine and vanish with a system-board swap or a reset; consumed by hardware and firmware changes; stable; **`LicenseString`, `Bytes` and any key material never stored** (add the tokens to the scrub list); 3–4 GETs. |
| `bmc_tasks` | 3 (`info_only`) | `TaskService` (1), `Tasks` expanded (1), `JobService` (1), `Jobs` expanded (1) | scalars `task_service_enabled`, `task_auto_delete_minutes`, `job_service_enabled`; `task|<Id>` / `job|<Id>` for **non-terminal** entries only → name, state, percent_complete | counts by terminal state, newest start/end times | The `vmware_recent_tasks` twin: a firmware update or configuration restore still running at capture time explains a half-populated inventory; quiescence evidence; 4 GETs. |
| `bmc_telemetry` (optional, last) | 3 | `TelemetryService` (1), `MetricReportDefinitions` expanded (1) | `report|<Id>` → type, schedule, metrics (sorted), enabled, report_updates | report count, newest report timestamp | Configuration of what the BMC records; values are never captured (bulky, volatile, `LenovoHistoryMetricValue` too). Low priority; listed so the hole is a decision, not an omission. |

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

Per BMC, with `$expand` honoured: ~60–100 GETs, at the 1 s pacing 1.5–2
minutes on top of the host capture; the 3300 s job soft limit is not in
sight. Per-check budgets stay under `REDFISH_MAX_CHECK_BUDGET = 40`; the two
checks that could exceed it on a per-member fallback (`bmc_sensors` on a
chassis with >40 sensors, `bmc_certificates` on a BMC with many locations)
refuse loudly with the member count, exactly as `xcc_inventory` does today,
and the shakedown's collection counts (§7) say beforehand whether `$expand`
makes the fallback moot on this firmware.

**A risk to measure at the first shakedown**: Lenovo writes remote-login
events into the *platform* log for web and CLI sessions. If Basic-auth
Redfish GETs also produce one platform-log entry each (rather than an
AuditLog entry only), a capture would add ~80 informational entries to a
1024-entry ring, churn `bmc_event_log`'s `informational_by_code` and, over
many captures, wrap Warning/Critical entries out of the log. Measure: read
the platform log's `LastSeqNum` before and after one capture. If it moves by
the GET count, the options are (a) accept and document, (b) fewer GETs
(`$expand` everywhere, one resolution GET), (c) a Redfish session (one POST
to `SessionService/Sessions` and one DELETE per capture — a doctrine change
of the vSphere-carve-out kind, decided by the user, never slipped in).

## 7. Shakedown and fixtures (once the account works)

1. `tools/redfish_walk.py` (Appendix A) against the lab unit: every resource
   under `/redfish/v1/` as ReadOnly. Read the index for 403s (which resources
   the ReadOnly role may not GET — `AccountService`, `LicenseService`,
   `CertificateService` and the OEM services are the candidates), collection
   sizes, and the member ids. Keep the crawl outside the repository.
2. Test Suite Shakedown (dev) on the host Device with the BMC modelled (or
   `tools/harvest_live.py --platform bmc` from a workstation). The
   `discovery.bmc` block answers: `RedfishVersion`, `ProtocolFeaturesSupported`,
   vendor/product, resolved ids and how, the `Oem.<Vendor>` links under the
   Manager, System and Chassis, LogServices members, member counts of every
   collection the family walks (memory, processors, PCIe devices, host NICs,
   network adapters, firmware, software, storage, manager NICs, sensors, boot
   options, accounts, roles, subscriptions, recipients, licences, FoD keys,
   certificate locations, tasks, jobs, controls, scheduled actions,
   watchdogs), whether `$expand=.($levels=2)` inlines functions and ports,
   which of `Thermal`/`Power` and `ThermalSubsystem`/`PowerSubsystem` are
   served, the security resource's property names (ThinkEdge or not), the
   capture account's role and privileges, host power state and `SystemStatus`,
   and the platform-log `LastSeqNum` delta across the run (§6).
3. Harvest with `tools/harvest_live.py --platform bmc`, sanitize with
   `tools/make_fixtures.py` (after the sanitizer additions in §3) into
   `tests/fixtures/xcc_*_lab.json`, replacing the hand-built Lenovo-doc
   fixtures where the shapes differ; `tests/test_lab_fixtures.py` pins what
   every normalizer reads.
4. Second shakedown with the host **off**, then one with one cable pulled:
   settles which views are POST-populated on this firmware (`bmc_inventory`,
   `bmc_pcie_slots`, `bmc_network_adapters`, `bmc_host_nics`, `bmc_storage`)
   and whether port link state follows a cable with the host off.
5. Stability: two captures an hour apart must diff to nothing under each
   check's compare mode; anything else is a normalizer fix (readings to
   context, volatile ids out of keys).

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

0. **Human, before any code runs against the lab**: complete the lab account's
   first-login password change in the XCC web UI (or clear the flag),
   confirm it holds the ReadOnly role with Redfish access, and re-run the
   crawl (Appendix A) — it should print 200 for every resource it visits.
   Record any 403 by path.
1. **PR A — framework** (no new checks): `bmc_target.py`, detection and the
   second context in both jobs, `resolve_bmc_credentials`, envelope 1.2,
   probe hints, `checks_xcc.py → checks_bmc.py` with the `bmc_*` rename and
   the id resolution, `XCC_ENABLED` removed, constants, `tools/redfish_walk.py`,
   the `bmc` harvest spec, README/docs skeleton. Battery green with the
   existing fixtures renamed. Dry-run against the dev stack with a fake
   device carrying an `xcc` interface proves the ORM glue.
2. **Shakedown 1** on the lab unit (host on): §7 items 1–3. Fix every
   "parsed but empty" advisory; commit the `_lab` fixtures.
3. **PR B — widen the existing checks** (§5a) on the lab fixtures.
4. **PR C — new checks** (§5b, `bmc_telemetry` optional), coverage-map
   section, prompt updates.
5. **Shakedown 2 and 3** (§7 items 4–5): host off, cable pull, stability.
6. **PR D — docs**: README catalog rows, `coverage.md` walked with the
   lab facts, `floor-consolidation.md`, the superseded note in
   `nfv-core-move.md`; memory updated.
7. **Production**: model the interface, address, Secrets Group and
   Relationship on each SE350 (§2), dry-run a day ahead, then pre/post as
   usual. The Charlotte hosts' XCC reachability from the worker is the one
   environment fact this plan cannot settle.

Effort: PR A about a day, the widening about a day, the new checks two to
three days with fixtures, plus three shakedown half-days.

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
8. Only if §6's measurement shows platform-log churn per GET: accept,
   shrink, or a Redfish session (**not decided here**).

## 12. Open questions the shakedown settles

The SE350 generation and whether it is a Security Pack unit (the security
resource says); which member ids and collection sizes; whether ReadOnly may
GET the account, licence, certificate and OEM services; `$expand` depth
honoured on PCIeDevices and NetworkAdapters; which of the legacy and new
thermal/power resources are populated; whether host-port link state follows a
cable with the host off; whether Basic-auth GETs write platform-log entries;
whether non-RAID M.2 enumerates under `Storage`, `Chassis/Drives` or nowhere;
what a de-powered external adapter slot reports under `Power`; the log
services offered under `Systems` and `Managers`; the exact `@Redfish.Settings`
link for pending BIOS attributes; the attribute registry's name and size.

## Appendix A — `tools/redfish_walk.py` (planning aid used on 2026-09-30)

GET-only, fenced, paced; credentials from the environment; one JSON file per
resource plus `_index.json`. Promote into `tools/` in PR A (add `--out`
outside-the-repo enforcement and the `--user-env/--password-env` convention
of `harvest_live.py`).

```python
#!/usr/bin/env python3
"""GET-only Redfish crawl of one BMC into a directory of JSON files (planning aid).

Never sends anything but GET. Follows every @odata.id / nextLink found in any
payload, fenced to /redfish/v1/, skipping Actions, SessionService, JsonSchemas,
$metadata and registry files. AuditLog entries are skipped unless AUDIT=1.
Paced PACE seconds apart (default 1.0). Credentials from the environment only.
"""

import collections
import json
import os
import re
import sys
import time

import requests
import urllib3

urllib3.disable_warnings()

host = os.environ["host"]
user = os.environ["username"]
password = os.environ["password"]
out = sys.argv[1]
pace = float(os.environ.get("PACE", "1.0"))
max_resources = int(os.environ.get("MAX", "2500"))
os.makedirs(out, exist_ok=True)

session = requests.Session()
session.auth = (user, password)
session.verify = False
session.headers.update({"Accept": "application/json", "OData-Version": "4.0"})

BANNED = ("actions", "sessionservice", "jsonschemas", "$metadata", "odata")
SKIP_RE = re.compile(r"\.json$|/Registries/[^/]+/.+")


def ok_path(path):
    if not path.startswith("/redfish/v1"):
        return False
    if "%" in path:
        return False
    segments = path.split("?")[0].split("#")[0].split("/")
    return not any(segment.lower() in BANNED for segment in segments)


def find_links(node, acc):
    if isinstance(node, dict):
        for key, value in node.items():
            if key in ("@odata.id", "Members@odata.nextLink") and isinstance(value, str):
                acc.append(value)
            else:
                find_links(value, acc)
    elif isinstance(node, list):
        for value in node:
            find_links(value, acc)


def file_name(path):
    name = re.sub(r"[^A-Za-z0-9._-]+", "_", path.replace("/redfish/v1", "root")).strip("_")
    return (name or "root") + ".json"


queue = collections.deque(["/redfish/v1/"])
seen = set(queue)
index = []
last = 0.0
while queue and len(index) < max_resources:
    path = queue.popleft()
    wait = last + pace - time.monotonic()
    if wait > 0:
        time.sleep(wait)
    last = time.monotonic()
    started = time.monotonic()
    try:
        resp = session.get("https://%s%s" % (host, path), timeout=(10, 120))
        status, body = resp.status_code, resp.content
    except Exception as exc:  # noqa: BLE001 - planning aid
        index.append({"path": path, "status": None, "error": str(exc)})
        print("ERR %s %s" % (path, exc), flush=True)
        continue
    elapsed = int((time.monotonic() - started) * 1000)
    entry = {"path": path, "status": status, "ms": elapsed, "bytes": len(body), "file": file_name(path)}
    try:
        payload = resp.json()
    except Exception:  # noqa: BLE001
        payload = None
        entry["nonjson"] = True
    with open(os.path.join(out, entry["file"]), "w") as handle:
        json.dump(
            payload if payload is not None else {"_text": body.decode("utf-8", "replace")[:20000]},
            handle,
            indent=1,
            sort_keys=True,
        )
    if isinstance(payload, dict):
        entry["odata_type"] = payload.get("@odata.type")
        members = payload.get("Members")
        entry["members"] = len(members) if isinstance(members, list) else None
        links = []
        find_links(payload, links)
        for link in links:
            link = link.split("#")[0]
            if link.rstrip("/") == path.rstrip("/"):
                continue
            if not ok_path(link):
                entry.setdefault("refused", []).append(link)
                continue
            if SKIP_RE.search(link):
                entry.setdefault("skipped", []).append(link)
                continue
            if "AuditLog/Entries" in link and not os.environ.get("AUDIT"):
                entry.setdefault("skipped", []).append(link)
                continue
            if link not in seen:
                seen.add(link)
                queue.append(link)
    index.append(entry)
    print(
        "%s %s %dms %dB %s" % (status, path, elapsed, len(body), entry.get("odata_type") or ""),
        flush=True,
    )

with open(os.path.join(out, "_index.json"), "w") as handle:
    json.dump({"index": index, "queued_unvisited": list(queue)}, handle, indent=1)
print("done: %d resources, %d unvisited" % (len(index), len(queue)), flush=True)
```

Run: `set -a; . /opt/stacks/.xcc.env; set +a; PACE=1.0 python3 tools/redfish_walk.py /path/outside/repo/xcc-crawl`.

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
