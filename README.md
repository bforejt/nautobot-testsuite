# nautobot-testsuite

Pre/post change-validation jobs for Nautobot. Snapshot a device before a change,
make the change, snapshot again, compare — and get a JSON verdict on the JobResult
that separates the diffs you *declared* you would cause from the ones you did not.

Two jobs, both under the **Network Validation** grouping:

- **Capture Snapshot** — runs every read-only check the platform supports
  against one or more devices (mixed platforms in one run collect per device) and attaches a versioned snapshot envelope (plus a raw-evidence bundle)
  to the JobResult: `snapshot_<device>_<change_id>.json` / `raw_<device>_<change_id>.json`.
  A `debug` checkbox additionally attaches `debug_<device>_<change_id>.json`: the
  full transport trace (every RESTCONF path and SSH command with timing, outcome,
  and payload), so even a FAILED check keeps its evidence.
- *(analysis happens outside Nautobot: download the snapshot files and feed
  them, with your test-plan prompt, to the LLM your organization approves —
  see below. `tools/diff_snapshots.py` builds an optional deterministic diff
  index locally.)*
- **Collector Shakedown (dev)** — hidden development job: runs *every* registered
  check for one device's platform in debug mode and attaches per-check verdicts
  with advisories ("parsed but empty — leaf names likely differ on this
  version"), the yang-library module inventory, discovered rib/FIB instance
  naming, and the full payload trace. This is how collectors get validated
  against real devices *before* a change window, and how CI fixtures are
  harvested (sanitize captures before committing). Check failures do not fail
  the JobResult — surfacing them is the point.

Platforms today: Catalyst 9500 / IOS-XE 17.x (RESTCONF) and PAN-OS firewalls (SSH,
XML op-command output).

## Installation

This repo is delivered through **Extensibility → Git Repositories** — it is synced
as source, never pip-installed:

1. Add the repository URL with the **Jobs** provided content.
2. Sync. Nautobot imports the `jobs` package and registers the jobs.
3. Enable **Capture Snapshot** and (for development) **Collector Shakedown**
   under Jobs (jobs arrive disabled by design; the
   shakedown is additionally hidden from the default list).

Worker requirements: `requests` and `netmiko`, both already present on any worker
running Golden Config or Device Onboarding. Nothing else — every other import is
stdlib or Nautobot core, and `pyproject.toml` carries dev tooling only. Device
credentials come from the device's assigned Secrets Group (or a per-run override
group), never from job inputs.

## Usage: a firewall cutover

Replacing an HA pair of PA-5250s with VM-500s behind a pair of Catalyst 9500s:

1. **Capture pre.** Run *Capture Snapshot* with `change_id = CHG0031337`,
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
| `iosxe_routing_config` | iosxe | 2 | Static-route and router-stanza configuration (secrets scrubbed) |\n| `iosxe_syslog_errors` | iosxe | 3 | Error-and-worse syslog event counts from the logging buffer |
| `iosxe_svl_health` | iosxe | 3 | StackWise Virtual link membership and bundled state |
| `iosxe_ntp` | iosxe | 3 | NTP synchronization state |
| `panos_logging_status` | panos | 3 | Log forwarding status — is telemetry actually flowing |
| `panos_url_cloud` | panos | 3 | URL-filtering cloud connectivity |
| `panos_ntp` | panos | 3 | NTP synchronization state |
| `panos_pending_changes` | panos | 1 | Uncommitted candidate-config changes present |
| `panos_pbf` | panos | 1 | Policy-based forwarding rules (not-present when PBF is unused) |
| `panos_drop_counters` | panos | 3 | Global drop-counter profile (informational canary) |
| `panos_nat_pools` | panos | 3 | NAT pool tables, raw-first (utilization is load-dependent) |
| `panos_rule_hit_counts` | panos | 2 | Security/NAT rule names with hit counts and last-hit times |
| `panos_ospf_neighbors` | panos | 1 | OSPF adjacencies, engine-aware (the firewall's view of the core) |
| `panos_crash_files` | panos | 1 | Core/crash files within the recency window |
| `iosxe_optics` | iosxe | 3 | Transceiver DOM light levels (tx/rx dBm) per optical port |
| `iosxe_crash_files` | iosxe | 1 | Crash/system-report files within the recency window |
| `iosxe_errdisable` | iosxe | 1 | Ports in err-disabled state with the triggering reason |
| `iosxe_port_channels` | iosxe | 1 | Port-channel bundles with per-member LACP flags |
| `panos_jobs` | panos | 1 | Unfinished commit/config jobs (history counts in context) |
| `panos_chassis_ready` | panos | 1 | Dataplane readiness (show chassis-ready) |
| `panos_disk_space` | panos | 3 | Filesystem use percentages within tolerance |
| `panos_panorama` | panos | 1 | Panorama connectivity per configured server |
| `panos_environmentals` | panos | 3 | Hardware environmental ALARM states (not-present on VM) |
| `panos_syslog_events` | panos | 3 | High/critical system-log event counts, last 24 h (time-bounded query) |

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

## Read-only guarantee

The guarantee is structural, not procedural. The RESTCONF client
(`jobs/transport_restconf.py`) implements **GET only** — there is no method that
can change device state. The SSH runner (`jobs/transport_ssh.py`) refuses any
command that does not match a per-platform read-only allowlist (the `show `
prefix, plus the display-only `request license info` on PAN-OS — deliberately
not `test`/`ping`, since e.g. PAN-OS `test vpn ike-sa` *initiates* SA
negotiation; future probe commands get individually vetted entries) and never
enters config mode. Collectors reach devices exclusively through the
`CollectorContext`, so no check can smuggle in its own transport. It is
grep-auditable, and **CI enforces it** — the `Read-only guard` step fails the
build if this ever matches anything:

```sh
grep -rniE 'send_config|config_mode|\.(patch|post|put|delete|request)\(' jobs/
```

## Development

Python 3.9-compatible, Ruff-formatted at line length 100:

```sh
pip install ruff pre-commit
pre-commit install
ruff check . && ruff format --check .
python -m unittest discover -s tests -t . -v
```

The test battery is pure stdlib — `diffcore`, `envelope`, `panos_xml`, the
registry, and every `_normalize_*` / `_parse_*` function run against fixture
captures without Nautobot, netmiko, or a network. CI (`.github/workflows/ci.yml`)
runs the same commands plus `python -m compileall -q .` as an import smoke test
and the read-only grep guard.

### Bringing a collector up against a real device

1. Run **Collector Shakedown (dev)** against one device of the platform.
2. Read the advisories: `ok` needs nothing; "parsed but empty" means the trace
   payload holds the real leaf/element names — adjust the normalizer to match;
   "nothing fetched" is a path/transport problem (check the module inventory in
   `discovery`).
3. Sanitize the interesting payloads from `shakedown-trace_*.json`
   (RFC 5737/1918 addresses, invented hostnames) and commit them under
   `tests/fixtures/`, replacing the synthetic ones, so CI locks in the real
   shapes.
4. Re-run the shakedown until every check reads `ok` — then the platform is
   ready for a real pre/post cycle.

Licensed under Apache 2.0.
