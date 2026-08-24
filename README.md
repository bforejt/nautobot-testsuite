# nautobot-testsuite

Pre/post change-validation jobs for Nautobot. Snapshot a device before a change,
make the change, snapshot again, compare — and get a JSON verdict on the JobResult
that separates the diffs you *declared* you would cause from the ones you did not.

Three jobs, all under the **Network Validation** grouping:

- **Capture Snapshot** — runs every read-only check the platform supports
  against one or more devices (mixed platforms in one run collect per device) and attaches a versioned snapshot envelope (plus a raw-evidence bundle)
  to the JobResult: `snapshot_<device>_<change_id>.json` / `raw_<device>_<change_id>.json`.
  A `debug` checkbox additionally attaches `debug_<device>_<change_id>.json`: the
  full transport trace (every RESTCONF path and SSH command with timing, outcome,
  and payload), so even a FAILED check keeps its evidence.
- **Compare Snapshots** — pairs a pre and a post envelope per device, diffs every
  check under its declared compare mode, classifies each diff against your
  expectations list, and attaches `report_<device>.json`. A pre snapshot older
  than 24 hours draws a warning.
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
3. Enable **Capture Snapshot**, **Compare Snapshots**, and (for development)
   **Collector Shakedown** under Jobs (jobs arrive disabled by design; the
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
4. **Compare (optional deterministic assist).** Run *Compare Snapshots* typing
   just the `change_id` — it merges every matching capture run per side. The
   firewall was renamed, so `device_map` maps the pre-change device name to
   its post-change replacement:

   ```json
   {"dc1-fw-5250-a": "dc1-fw-vm500-a"}
   ```

   and `expectations` declares the diffs the change was *supposed* to make,
   e.g. the 9500s' default route now pointing at the VM-500 pair:

   ```json
   [
     {"check": "iosxe_routes_rib", "key": "default|0.0.0.0/0", "op": "changed",
      "field": "next_hops", "to_contains": "10.99.1.6",
      "note": "default next-hop moves to the VM-500 HA pair"}
   ]
   ```

   `fail_on_unexpected` controls whether unexpected diffs fail the JobResult or
   just report; `baseline_max_age_hours` overrides the stale-baseline warning.

The report classifies every observed diff `expected` or `unexpected`, and lists
expectations that matched nothing (`not_observed`) — a declared change that did
not happen is a finding too.

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

## Expectations syntax

`expectations` is a JSON list of objects; each classifies matching diff entries
as expected:

| Key | Meaning |
| --- | --- |
| `check` | Exact check id; omit to match any check |
| `key` | Glob against the diff entry's key (default `*`), e.g. `default\|0.0.0.0/0` |
| `op` | `added`, `removed`, `changed`, or `any` (default) |
| `device` | Glob against the pre/post device name; omit to apply on every pair |
| `field` | Exact field name, for `changed` entries on dict-valued keys |
| `to` | `changed` only: new value must equal this |
| `to_contains` | `changed` only: substring of the new value |
| `id`, `note` | Optional label and human note, echoed in the report |

Tolerance and capability misses match as `op: changed` (keyed by the bucket key
or field name), so a planned numeric shift can be declared expected too. An
entry with no selector keys at all is rejected — a deliberate match-everything
wildcard must say `{"key": "*"}` explicitly.

Expectation matching is **run-global**: an expectation is reported
`not_observed` only when *no* device pair in the run matched it, so per-device
expectations do not false-alarm on their neighbors. Failed reads are never
treated as emptiness — a check whose collection failed is reported failed (and
fails the compare JobResult regardless of `fail_on_unexpected`), not as a wall
of `removed` entries.

## LLM-assisted analysis

Snapshots are **self-describing**: every `snapshot_*.json` embeds an
interpretation guide, per-check descriptions/semantics, curated context facts
(e.g. the session-matrix reconciliation totals), the device's role/location,
and the operator's `change_description`. The intended analysis workflow: the
engineer building the change writes the test plan **as a prompt** (plain
language — intent, priorities, suspicions), downloads the pre and post
snapshot files, and feeds both to whatever LLM the organization approves.
The prompt never explains the data format; the files do. Nautobot never
contacts an LLM. `Compare Snapshots` remains available as a deterministic
assist — its exhaustive diff index saves an LLM from doing set arithmetic
over large tables with attention. See
[docs/llm-test-plans.md](docs/llm-test-plans.md) for the contract and a
worked firewall-replacement example.

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
