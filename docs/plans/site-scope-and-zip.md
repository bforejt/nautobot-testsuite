# Plan: site-scoped device selection and a zip download option

Status: **PR A merged 2026-10-01; PR B accepted for PR 2026-10-02.** Task 1 lets the
Capture job pick devices by location and other filters, pull in the
controllers that managed devices depend on, and skip unsupported devices
gracefully. Task 2 adds a single compressed download. They share one new
artifact, the run manifest (§3).

- §0 records the decisions, including the production GUI results.
- §7 lists what is still the user's to do.
- §8 is the pass/fail list each PR must meet.
- §9 tracks build status. Implementing sessions update it as they go.

## 0. Decisions (2026-10-01)

1. **Platforms.** Production keeps separate Platform objects named
   `cisco_ios`, `cisco_nxos` and `cisco_wap`. IOS-XE switches and the 9800s
   are on `cisco_ios`, and the 9800s stay there: the wireless checks detect a
   controller for themselves, so no re-label is needed. `cisco_ios` keeps
   mapping to `iosxe`. A classic-IOS box on `cisco_ios`, if one exists, fails
   loudly and is handled with `exclude_devices`. The deny tokens (§2.3) are
   matched against **both** the `network_driver` and the platform name, so
   `cisco_nxos` and `cisco_wap` are refused even if their driver field also
   says `cisco_ios`. Decision 9 confirms that `cisco_wap`'s driver does.
2. **APs are linked to controllers through Nautobot's built-in models**
   (Controller → Controller-Managed Device Group). No custom Relationship
   fallback is built.
3. **Statuses.** A `statuses` filter that accepts any selection. Leaving it
   empty means Active, and the job log says so. Active is the normal use.
4. **No primary IP.** The existing fallback to the device name stays. **No
   new code** is added for address handling. Assigning a primary IP is a
   process standard, not something the job enforces. `skipped_no_address` is
   dropped from §2.3.
5. **A device picked by hand that the job can't capture is an error**, as
   today. Skipping applies only to devices swept in by a filter.
6. **The 2.4.43 field check was done in the GUI**: decisions 9–15.
7. **`artifact_format` defaults to separate files** (`files`).
8. **`dynamic_group` and `tags` ship in PR B** with the other scope inputs.

Production GUI results (the user, 2026-10-01):

9. **Platform drivers.**

   | Platform name | `network_driver` |
   | --- | --- |
   | `cisco_ios` | `cisco_ios` |
   | `cisco_nxos` | `cisco_nxos` |
   | `cisco_wap` | **`cisco_ios`** |
   | `paloalto_panos` | `paloalto_panos` |
   | `vmware_esxi` | *blank* |

   This confirms why the deny tokens must read the platform name as well as
   the driver. Without that, an AP whose group is missing would map to
   `iosxe` through its driver. A blank driver already falls back to the
   slug or name, so `vmware_esxi` maps to `vmware` today. Both cases go into
   the `map_platform` tests.
10. **The driver is used to identify the device, never to pick a
    transport.** `network_driver` only chooses the check family. The
    transport settings are fixed per family in `snapshot_job.py`
    (`SshRunner("cisco_xe", …)`, `SshRunner("paloalto_panos", …)`), and
    neither plan adds a transport or a device read. The user's rule is
    **structured data queries to all devices, whatever the transport**
    (SSH returning XML, as PAN-OS does, is fine; scraping display text is
    not). It is planned in `docs/plans/structured-data-queries.md` and is
    out of scope here.
11. **Controllers.** The 9800 is a Controller with *Controller device* set,
    no redundancy group, and the *Wireless* capability. Its managed device
    group holds the APs, and a test AP shows the group on its device page,
    on the `cisco_wap` platform.
12. **One controller device per Controller is the supported shape.**
    Production has two controllers per AP group in reality, but the user
    isn't modelling that now. PR B builds and tests only *Controller
    device*. Redundancy groups are deferred (§2.4). A Controller that carries
    a redundancy group instead of a device is recorded as
    `controller_not_capturable`, with a reason saying redundancy groups
    aren't supported yet. It is never an error, and nothing is guessed.
    Background for later: Nautobot lets a Controller have **either** a
    device **or** a Device Redundancy Group, never both (`Controller.clean`,
    verified on 3.2.5).
13. **Locations.** The hierarchy is Company → Site → Place (floors). Most
    devices are attached to the Site itself, and Companies hold no devices.
    Picking a Site therefore captures the site's devices and every floor's.
    Picking a Company would sweep **every** site, which is what the size
    guard in §2.5 is for.
14. **Dynamic Groups** have the *Group type* field, as on dev.
15. **Time limits** can be overridden on the Job's Edit page in the 2.4.43
    GUI (*Soft time limit* and *Time limit*), as on dev.

Verified while writing (2026-10-01, dev stack Nautobot 3.2.5; production is
2.4.43, whose GUI results are decisions 9–15):

- `DeviceFilterSet.location` is a `TreeNodeMultipleChoiceFilter`: filtering
  on a site matches every device on its floors, rooms and other descendants.
- The native controller model is present. Its chain is Device →
  `controller_managed_device_group` → `controller` → `controller_device`
  **or** `controller_device_redundancy_group`. `capabilities` exists on both
  Controller and group, and `wireless` is its only choice.
- `Job.create_file(filename, content)` accepts `bytes`. The cap is
  `JOB_CREATE_FILE_MAX_SIZE` (default 10 MB, configurable through Constance
  or the environment), and it applies to the zip as a whole.
- The REST API serves `/api/extras/file-proxies/` with a `download` action
  (relevant to the client-side alternative in §5.4).

---

## 1. Where the job is today

- `devices` is a required `MultiObjectVar`. You build a site's capture by
  picking devices one at a time from a type-ahead list.
- Every selected device is attempted. A device the job can't capture fails
  the run, and so does one it misjudges as capturable. Examples: an Opengear
  console server (`docs/prompts/floor-consolidation.md` says so outright), or
  any device whose platform driver contains `cisco` but isn't IOS-XE, such
  as an AP, NX-OS, an ASA or AireOS. `_map_platform` maps that substring
  straight to `iosxe`, the RESTCONF probe fails, and the device is FAILED.
- AP data comes only from the 9800 (`wlc_ap_*`). Nothing connects an AP in
  Nautobot to the controller you must remember to select.
- Each device attaches 2–3 files (`snapshot_`, `raw_`, and optionally
  `debug_`), each downloaded by hand from the JobResult.

## 2. Task 1: selecting a site

### 2.1 Prior art

| Prior art | What it does | What carries over |
| --- | --- | --- |
| **Golden Config** `FormEntry` + `get_job_filter` (installed on dev, 3.0.7) | 11 optional `MultiObjectVar`s (tenant group, tenant, location, rack group, rack, role, manufacturer, platform, device type, device, tags, status) fed to `DeviceFilterSet`. Different fields combine with AND; values within one field combine with OR. | Reusing `DeviceFilterSet` makes the job's semantics match the Devices list view you already use. **Gotcha:** it ANDs `device` with the other fields, so picking a device next to a location *narrows* the set instead of adding to it. That surprise is common, so this plan does not copy it. |
| **Device Onboarding** "Sync Devices" job (5.5.1) | `devices`, plus single `location`, `role` and `platform` vars described as "Only update devices at…" | A small set of narrowing filters is enough. Its location var uses `query_params={"content_type": "dcim.device"}`, which hides parent location types (a Site whose devices sit on its Floors), so this plan does **not** restrict the location picker. |
| **Dynamic Groups** (core; Golden Config uses one as its scope) | A saved, named filter, or a static list, with a Members tab that previews the result. | A scope you can preview before running and reuse for pre **and** post. Using the same definition both times is what keeps the two device sets comparable. |
| **Job Buttons** (core) | A button on an object's detail page, such as "Capture this site" on a Location. | Rejected for now. A Job Button Receiver gets the object but no form, so `change_id` and `kind` cannot be supplied. |
| **Ansible `--limit`, Nornir `F()`** | A target set, then limit and exclude. | The operator's model: add, narrow, then take away. |

### 2.2 Recommended inputs

All are optional. At least one of `devices`, `locations` or `dynamic_group`
must be given.

| Input | Type | Meaning |
| --- | --- | --- |
| `locations` | MultiObjectVar(Location) | Every device at these locations **and their descendants** |
| `dynamic_group` | ObjectVar(DynamicGroup, `content_type=dcim.device`) | Every member of a saved group |
| `devices` | MultiObjectVar(Device), now `required=False` | Explicit picks, **added** to the result. They are not filtered. |
| `roles` | MultiObjectVar(Role, `content_types=dcim.device`) | Narrows the location and group result |
| `statuses` | MultiObjectVar(Status, `content_types=dcim.device`) | Narrows the location and group result. Any selection is accepted. Empty means `C.SCOPE_DEFAULT_STATUSES = ("Active",)`, matched by name, and the log says so (decision 3). The description says "Empty means Active". The default is applied at run time, not as a form default, because a form default would need a Status pk, which differs per install. |
| `tags` | MultiObjectVar(Tag, `content_types=dcim.device`) | Narrows the location and group result |
| `exclude_devices` | MultiObjectVar(Device) | Removed last, including a pulled-in controller |
| `include_controllers` | BooleanVar, default **on** | Adds the controllers of in-scope managed devices (§2.4) |

The scope is resolved like this:

```
scope = ( (locations ∪ dynamic_group members)  ∩ roles ∩ statuses ∩ tags )
        ∪ devices
        ∪ controllers-of(scope)            # when include_controllers
        − exclude_devices
```

- **Narrowing fields need an anchor.** `roles`, `statuses` and `tags` apply
  only to `locations` and `dynamic_group`. Without an anchor, "role = access"
  would sweep every site in the inventory.
- Platform is deliberately **not** a filter. The point of a site sweep is to
  take everything and let the classifier (§2.3) decide what is capturable.
- All eight inputs ship in PR B (decision 8).
- Nautobot job forms have no fieldsets, so `field_order` groups them: change
  inputs, then scope inputs, then output and run options.

### 2.3 Classifying devices: skip on modelled facts, never on failures

This is the central rule. **Every skip decision is made from Nautobot data
before any transport opens. A runtime failure is never turned into a skip.**
An in-scope, supported device that is unreachable still fails the run. The
fail-closed doctrine stands: an outage must never vanish into "skipped".

Each resolved device gets exactly one disposition:

| Disposition | When | Effect on the run |
| --- | --- | --- |
| `capture` | Supported platform, or an unsupported host with a modelled BMC (today's rule) | Captured; a failure fails the run |
| `covered_by_controller` | Managed by a controller whose group or controller has the `wireless` capability, and not itself that controller's device. If capabilities are empty: managed **and** its platform maps to nothing. | Not captured directly. The log and manifest name the controller whose snapshot holds its data. |
| `controller_not_capturable` | As above, but the controller has no device modelled, or its device is skipped | A warning naming the fix. It does not fail the run. |
| `skipped_unsupported` | Platform maps to nothing, or matches a deny token (below), and there is no BMC | Skipped with a reason naming the fix (as `PLATFORM_HINT` does today) |
| `excluded` | Listed in `exclude_devices` | Recorded only |

There is deliberately no disposition for a missing primary IP. The existing
`_device_host` fallback to the device name stands unchanged (decision 4), so
a device that doesn't resolve fails loudly like any unreachable one.

**Explicit picks keep today's loudness.** A device you pick by hand that
classifies as `skipped_unsupported` is an error, as it is today: you asked
for something the job can't do. An AP picked by hand is `covered_by_controller`
like any other, and its controller is pulled in.

**Tightening the platform map.** It applies to every path, since it only
replaces a confusing transport failure with a clear "unsupported". A
`C.PLATFORM_DENY_TOKENS` list is tested before the `cisco` → `iosxe`
substring. It holds `nxos`, `wap`, `ap`, `xr`, `asa`, `ftd`, `aireos`,
`meraki`, `apic` and `viptela`. Two details matter:

- **Both fields are checked.** The tokens are matched against the
  platform's `network_driver` **and** its name (and slug, on older records).
  `_map_platform` reads the driver first, so a `cisco_nxos` platform whose
  driver field happened to say `cisco_ios` would otherwise slip through
  (decision 1).
- **Tokens match whole words, not substrings.** Names are split on anything
  that isn't a letter or digit, as `bmc_target` already does: `cisco_wap` →
  `cisco`, `wap`. Then `ap` matches `cisco_ap` but not `paloalto`, and `xr`
  never matches inside a longer word.

`cisco_ios` keeps mapping to `iosxe`, and the 9800s stay on it (decision 1).
APs are normally caught earlier, by the `wireless` controller rule, so the
`wap` token is the backstop for an AP that isn't in a managed group.

### 2.4 Pulling in controllers

For each in-scope device with a `controller_managed_device_group`:

1. Walk to `group.controller`.
2. Resolve the controller's capturable device:
   - a plain `controller_device`;
   - an embedded controller, whose `controller_device` is the switch itself
     and so is usually already in scope (de-duplicated by pk);
   - a `controller_device_redundancy_group`: **deferred** (decision 12).
     The controller's managed devices are recorded as
     `controller_not_capturable` with the reason "controller redundancy
     groups are not supported yet; set Controller device". When it is
     built, the rule is: capture every member with its own management
     address; members sharing one address (an SSO pair) are captured once,
     choosing the best `device_redundancy_group_priority`.
3. The controller device goes through the same classifier. A controller that
   is not capturable (for example a Catalyst Center appliance without a
   supported platform) is recorded, and its managed devices become
   `controller_not_capturable`.
4. The controller may be at **another site**, as a central WLC is. That is
   the point of pulling it in: it is captured whatever its location, and the
   manifest says it was pulled in by which devices.

This is general rather than wireless-specific. A device managed by a
non-wireless controller (say, a switch under Catalyst Center) is captured
directly when its own platform is supported, and its controller is also
pulled in and classified.

The 9800's snapshot holds **every** AP joined to it, not just this site's.
That is consistent with the always-everything doctrine. To let an analysis
prompt focus on the site, the manifest lists under each controller the
in-scope device names it covers. That costs nothing extra, since the
resolver already holds them. Caveat: a Nautobot AP name can differ from the
AP's name on the WLC. That's a data-quality matter, so the plan records it
rather than reconciling it.

### 2.5 Run behaviour

- **Order:** controllers first (one capture covers many in-scope devices, so
  if the time limit hits, the widest coverage is already captured), then by
  name. The order is deterministic, so pre and post walk the same order.
- **Pre-flight log:** one summary line, for example "42 resolved: 18
  capture, 21 covered by controller WLC-A, 2 unsupported, 1 pulled in
  (WLC-A)", then one line per non-captured device carrying the device
  object link.
- **Dry run** becomes the scope preview. It prints the full resolution and
  the per-device readiness that exists today, and does no collection.
- **Outcome:** skipped, covered and excluded devices never fail the run. The
  existing failed and succeeded message gains the skipped and covered counts.
  A scope that resolves to zero capturable devices is an error.
- **Time budget:** the loop stays serial, and the class defaults stay
  `soft_time_limit=3300` and `time_limit=3600`. A long site sweep raises
  them on the Job's **Edit** page in the GUI (*Soft time limit* and *Time
  limit* overrides, present on 2.4.43 and on dev; decision 15). The README's
  site-sweep section says where, and says to keep the hard limit at least
  300 s above the soft limit. That gap is the time the job has to attach
  partial artifacts, and the zip, after the soft limit fires.

  Before a limit goes past 3600 s, confirm the production worker doesn't
  run with `CELERY_TASK_ACKS_LATE` (dev leaves it unset). With late acks on
  a Redis broker, a task running longer than the broker's visibility timeout
  (one hour by default) can be handed to a second worker and run twice.
  The manifest records each device's `duration_s`, so the limit and the
  size guard below can be set from measured sweeps rather than guesses.

  The existing soft-limit path (partial artifacts attached, devices not
  visited listed) carries into the manifest as `not_visited`. Parallel
  capture is out of scope.
- **Size guard:** if more devices resolve to `capture` than
  `C.SCOPE_MAX_CAPTURE` allows (initially 30, revisited once the first real
  sweeps record their durations), the run refuses before any I/O. The
  message names the count and says to pick a Site rather than a Company, or
  to split the run. A dry run is never refused: it prints the full
  resolution and says the real run would refuse. This catches the
  Company-level pick (decision 13) and every other accidental sweep.

### 2.6 Pre/post symmetry

A floor consolidation retires devices: post-change Nautobot may hold fewer
devices, or devices with a different status. A re-run filter can then
resolve a different set, and the manifest records both sets. The README
will recommend using the same scope definition for pre and post, ideally a
Dynamic Group, and `tools/diff_snapshots.py` gains manifest awareness: a
pre-only device that the post manifest lists as excluded or skipped is
reported as such, instead of "replaced or removed?".

### 2.7 Code shape (house pattern: a pure module, Nautobot glue in the job)

- **New `jobs/scope.py`** (stdlib only, like `bmc_target.py`). It takes plain
  rows: `{pk, name, platform_driver, has_bmc, address, status,
  managed_group: {controller_pk, capabilities}, source}` and controller rows.
  It returns ordered dispositions plus the manifest scope block. All the rules
  in §2.3–§2.5 live here and are unit-tested in `tests/test_scope.py`:
  embedded controllers, a controller with no device, a
  controller at another site, excluding a pulled-in controller, explicit vs
  swept unsupported devices, and the no-anchor refusal.
- **`jobs/snapshot_job.py`** runs the ORM queries through `DeviceFilterSet`
  and `DynamicGroup.members`, using
  `select_related("platform", "controller_managed_device_group__controller")`.
  It builds the rows, calls `scope.resolve`, and loops over the `capture`
  dispositions with the existing `_capture_device`, which is unchanged.
- **The platform mapping moves into `scope.py`** as `map_platform(driver,
  name, slug)`, so the deny tokens and the word-matching are unit-tested.
  Today the mapping lives in `snapshot_job.py`, which CI can't import.
  `_map_platform` becomes a thin wrapper that reads the three attributes off
  the Platform. The shakedown job's use of it (if any) gets the same wrapper.
- **README:** a "Capturing a whole site" section. The prompt docs' "What to
  capture" tables gain a note that a site sweep handles the controller and
  unsupported rows automatically.

## 3. Shared: the run manifest

Today nothing records the run as a whole. A new
`manifest_<change_id>_<kind>.json` is attached once per run, in both
download formats:

```json
{
  "schema": 1,
  "change_id": "…", "kind": "pre", "job_result_id": "…", "user": "…",
  "job_version": "0.1.0-dev", "started": "…Z", "finished": "…Z",
  "inputs": {"locations": ["…"], "dynamic_group": null, "devices": ["…"],
             "roles": [], "statuses": ["Active"], "tags": [],
             "exclude_devices": [], "include_controllers": true,
             "artifact_format": "zip"},
  "devices": [
    {"name": "…", "id": "…", "location": "…", "role": "…", "platform": "…",
     "source": ["location", "controller_of"],
     "disposition": "capture", "reason": null,
     "outcome": "succeeded|failed|not_visited|null",
     "files": [{"name": "snapshot_….json", "bytes": 0, "sha256": "…"}]}
  ],
  "controllers": [
    {"name": "WLC-A", "devices": ["wlc-a-1"], "covers": ["ap-5-01", "…"]}
  ]
}
```

It holds names and identifiers only, with no credentials (per the
names-not-credentials rule). Envelope schema 1.2 is unchanged: the manifest
describes the run, and the envelopes still describe their devices.

## 4. Task 2: a zip download

### 4.1 Recommended input

```
artifact_format = ChoiceVar(
    choices=(("files", "Separate JSON files"), ("zip", "One zip file")),
    default="files",          # decision 7
    description="Attach each device's files separately, or all of them in one zip.",
)
```

`run()` gains `artifact_format="files"` (ScheduledJob rule: every kwarg has
a default, so stored schedules replay unchanged). There is no "both" option:
it would double the JobResult's database storage for no download benefit.

### 4.2 Zip layout and naming

- File name: `testsuite_<change_id>_<kind>_<YYYYMMDDTHHMMZ>.zip` (new
  `C.ZIP_FILENAME`). Including the kind and the time keeps a pre and a post,
  or two re-runs, from colliding in a Downloads folder.
- Inside, everything sits under a `<kind>/` folder, with today's file names
  unchanged:

  ```
  pre/manifest_CHG123_pre.json
  pre/snapshot_core-1_CHG123.json
  pre/raw_core-1_CHG123.json
  pre/debug_core-1_CHG123.json        (when debug is on)
  ```

  Unzipping the pre and post zips into one directory gives `pre/` and
  `post/`, which is exactly what `diff_snapshots.py --pre pre/*.json --post
  post/*.json` expects.
- Compression is `ZIP_DEFLATED` at level 6 (stdlib `zlib`). JSON with
  `indent=1` typically compresses 5–10×, so the zip also shrinks the
  JobResult's database storage by roughly that factor. There is no zip
  password: legacy zip encryption is weak, and the content is already
  redacted upstream. The JobResult's permissions stay the guard.

### 4.3 Mechanics: an artifact sink

`_attach_artifact` becomes one of two sinks behind one interface,
`add(filename, payload)` / `finish()`:

- `FileSink` behaves as today: each file is attached the moment its device
  finishes.
- `ZipSink` opens a `zipfile.ZipFile` on a `tempfile.TemporaryFile()` at
  run start and writes each device's files as members as soon as the device
  finishes. Memory stays bounded by one device's payload, not the site's.
  `finish()` closes the zip, reads the bytes and calls `create_file` once.

The pure part (member naming, the per-file sha256 and size the manifest
records, and the size split below) lives in a stdlib-only `jobs/bundle.py`
with `tests/test_bundle.py`. The `create_file` call stays in the job.

### 4.4 Failure paths

These are the real trade-off of zipping.

- **Incremental attach is lost in zip mode.** Today each device's evidence
  is attached as soon as the device finishes, so a crash mid-run keeps
  everything captured before it. In zip mode, `finish()` runs in a `finally`
  in `run()`, so the zip is attached on every *Python* exit path: success,
  failed devices (before the "Snapshot failed" `RuntimeError`), the soft
  time limit (inside the 300 s soft-to-hard gap that exists for exactly
  this), and an unexpected exception.
- What a zip cannot survive is a **hard kill** (the 3600 s SIGKILL, or a
  worker OOM or restart): the temp file dies with the process. The soft
  limit exists to prevent the hard kill. The README will still say: for a
  very long sweep, choose separate files.
- **Size cap.** If the finished zip exceeds `JOB_CREATE_FILE_MAX_SIZE`
  (read through `get_settings_or_config`, falling back to 10 MB), it is
  repacked greedily **at device boundaries** into `…_part1of3.zip` and so
  on, with the manifest in part 1. Member compressed sizes are known from
  `ZipInfo`, so the split is computed, not guessed. A single device whose
  compressed files alone exceed the cap takes today's path: logged and
  dropped, and the manifest marks those files `not_attached`.
- `create_file` already logs a download link per file. In zip mode that
  means one link, or one per part.

### 4.5 Related changes

- `tools/diff_snapshots.py` accepts `.zip` arguments directly (stdlib
  `zipfile`), for example `--pre pre.zip --post post.zip`. It reads the
  `snapshot_*.json` members and the manifest (§2.6).
- README: the usage sections say "download the zip, unzip, feed the
  `snapshot_*.json` files to the LLM". Some LLM front ends don't open zips,
  so the files are unzipped first.
- The Shakedown job is unchanged: it captures one device, and its trace is a
  single file.
- CI read-only guard: `zipfile` and `tempfile` calls don't match the
  write-verb pattern. The build must still avoid `.delete(`-style names in
  `jobs/`; `TemporaryFile` cleans itself up on close.

### 4.6 Alternative considered: download all files client-side

A `tools/fetch_artifacts.py <job_result_id>` could list
`/api/extras/file-proxies/` filtered to the JobResult and download every
file into a folder, with no change to the job. It is useful for automation,
but it needs an API token on the analyst's machine and a Python run. It
doesn't help someone clicking through the UI, which is the stated pain, so
it stays an optional follow-up rather than the answer.

## 5. Delivery: two PRs, smallest first

1. **PR A: manifest + zip.** `jobs/bundle.py` (with tests), the sinks,
   `artifact_format`, the run manifest (inputs, per-device outcome, files),
   `diff_snapshots.py` reading zips, README. It is independent of scope work
   and low risk.
2. **PR B: site scope.** `jobs/scope.py` (with tests), the new inputs,
   classification, the platform deny tokens, controller pull-in,
   dispositions and controllers in the manifest, dry-run preview, manifest
   awareness in `diff_snapshots.py`, README, and the prompt-doc notes.

## 6. Proving it live (dev stack, 3.2.5)

The job glue imports Nautobot, so CI can't exercise it (house limit). Proof
follows the BMC pattern: deploy to the dev stack and run it. The dev DB
holds one device (`se350-lab-1`), so B needs fixtures **created in dev
Nautobot with your OK**:

- a Site → Floor tree;
- a fake AP and a fake Opengear (unreachable on purpose, since both should
  be skipped);
- a 9800 Device with a Controller and a Controller-Managed Device Group
  holding the AP;
- `se350-lab-1` moved under the floor.

Possibly also the lab 9300 (10.40.2.148), read-only as always, so one
supported switch is captured for real. A dry run then proves the resolution
with no I/O, and one real run proves the skips, the BMC capture and the zip
end to end. The 9800 is unreachable in dev, so the pulled-in controller
fails its capture; that correctly demonstrates fail-closed.

## 7. Production GUI checks (2.4.43): answered

All eight checks were answered on 2026-10-01, and the results are decisions
9–15 in §0. Nothing is outstanding on the user's side. Controller redundancy
groups are deferred by decision, not waiting on anyone (decision 12).

## 8. Done when (each PR's pass/fail list)

The implementing session states its approach against this plan before
editing, and shows evidence for every item before calling the PR done:
command output, not assertions.

**Both PRs:**
- `python3 -m unittest discover -s tests -t .` passes, with new tests for
  every rule the PR adds.
- Ruff `check .` and `format --check .` are clean, run through the pinned
  Docker image (the host has no ruff).
- `python3 -m compileall -q .` passes.
- Every guard step in `.github/workflows/ci.yml` passes locally (extract the
  `run: |` blocks and run them).
- The README and this plan's §9 are updated.
- No model identifiers appear in commits, the PR or code.
- `/code-review high` runs in a fresh context, and correctness findings are
  fixed or answered.

**PR A (manifest + zip):**
- `tests/test_bundle.py` covers:
  - member naming under `<kind>/`;
  - the per-file sha256 and size;
  - the greedy split at device boundaries, including one device larger than
    the cap;
  - the manifest round-trip.
- `diff_snapshots.py` gives the same index from a zip as from the unzipped
  files (a test with a fixture zip).
- Deployed to the dev stack, `se350-lab-1` is captured three times:
  - `files`: identical to today's output, plus `manifest_*.json`;
  - `zip`: one zip, with the manifest's file list matching the members;
  - `zip` with `debug` on: the `debug_` file is inside the zip.
- The failure path is proven. Make one device fail, for example by picking
  an unsupported device by hand next to the SE350. The zip is still attached
  before the run's error.

**PR B (scope):**
- `tests/test_scope.py` covers:
  - every disposition;
  - the no-anchor refusal;
  - explicit picks added, not filtered;
  - exclusion of a pulled-in controller;
  - an embedded controller already in scope;
  - a controller with no device;
  - a controller at another site;
  - deny tokens on driver **and** name, with word matching (`paloalto` is
    not `ap`). The production rows from decision 9 are test cases verbatim:
    `cisco_wap` with driver `cisco_ios` is refused, `cisco_nxos` is
    refused, `vmware_esxi` with a blank driver maps to `vmware`, and
    `cisco_ios` maps to `iosxe`;
  - the size guard refuses a real run and lets a dry run through;
  - a Controller with a single *Controller device* (the production shape)
    pulls that device in and covers its APs;
  - a Controller with only a redundancy group yields
    `controller_not_capturable` with the "not supported yet" reason, and
    the run does not fail;
  - an unsupported device picked by hand is an error, while one swept in is
    skipped.
- Dev-stack fixtures are created **only with the user's OK** (§6). A dry run
  over the fixture site prints the expected resolution with no I/O. A real
  run then:
  - captures the SE350 (with its BMC);
  - skips the Opengear and the AP;
  - pulls in the 9800, which fails because it is unreachable in dev, as
    fail-closed requires;
  - produces a manifest that names all of it.

## 9. Build status and notes for the implementing session

| Step | State |
| --- | --- |
| Plan and decisions | Done (2026-10-01) |
| §7 GUI checks on 2.4.43 | Answered (§0, 9–15) |
| Controller redundancy groups | Deferred (decision 12); a follow-up when production models them |
| PR A: manifest + zip (branch `codex/zip-artifacts`) | Merged in PR #18 (2026-10-01) |
| PR B: site scope (branch `codex/site-scope`, from main after A merges) | Implemented, reviewed and accepted for PR (2026-10-02), from merged main `c95f546` |

Notes:
- **One PR per fresh session, in order:** A, then B. Both touch `run()` and
  the manifest, so they don't run in parallel. Branch each from an up-to-date
  main.
- **Lint:** `docker run --rm -u "$(id -u):$(id -g)" -v "$PWD":/io -w /io
  ghcr.io/astral-sh/ruff:0.16.4 check --no-cache .` (and `format --check`).
  The image tag has no `v`.
- **The job glue can't be unit-tested** (it imports Nautobot). Keep the
  logic in `bundle.py` and `scope.py`, and prove the glue on the dev stack.
  Jobs are deployed into
  `/opt/stacks/nautobot-composer/jobs/nautobot_testsuite/jobs` through a
  helper container, because `JOBS_ROOT` is owned by uid 999. Read-only
  queries: `docker exec nautobot nautobot-server nbshell`.
- **Doctrine that binds this work:**
  - fail-closed: a skip comes only from modelled data, never from a runtime
    failure;
  - always-everything: no check filtering, and no change-specific logic in
    `jobs/`;
  - names, not credentials, in the manifest.

### PR A implementation and evidence (2026-10-01)

`jobs/bundle.py` provides the pure sinks, file metadata and whole-device size
splitting. Capture defaults to separate files, adds a manifest in either format,
and finalizes evidence on failed devices, soft limits and unexpected exits.
The zip sink spools on disk and streams repacking; only attachment-sized output
is read into memory. The configured size cap comes from the same
`get_settings_or_config` utility as `Job.create_file`.

The manifest records the current inputs (`devices`, `artifact_format`, `debug`
and `dryrun`); the location/group/controller fields arrive in PR B. Dry runs
produce a manifest without device snapshots. `diff_snapshots.py` reads all zip
parts directly and ignores raw/debug/manifest siblings in unzipped globs;
disposition-aware analysis remains PR B.

Command output from the final source tree:

```text
python3 -m unittest discover -s tests -t .
Ran 1519 tests in 9.678s
OK

Ruff 0.16.4 check --no-cache .: All checks passed!
Ruff 0.16.4 format --check .: 77 files already formatted
python3 -m compileall -q .: exit 0
Python 3.9 syntax: PASS
Read-only guard: PASS
Redfish fence guard: PASS
SOAP operation guard: PASS
```

A fresh-context correctness review found and verified fixes for a first soft
limit during packaging, sanitized device-name collisions, manifest growth after
a failed part, retry flag consistency, malformed zip-name diagnostics and
interrupted cleanup. Its final review had no correctness blockers; it also ran
274 source-line timeout scenarios and 2,000 randomized size/integrity trials.
Colliding device names now refuse before transports open, preserving the existing
artifact filenames. Finalization retries use confirmed downloads and persisted
FileProxy names to avoid duplicate attachments.

Dev proof used actual `CaptureSnapshot` instances and JobResults in a fresh
Nautobot 3.2.5 `nbshell`, after deploying the final job sources. The unsupported
explicit selection was an existing device with its platform cleared only in
memory; no fixture objects or device-model changes were needed.

| Proof | Device outcomes | Downloads | Members | BMC checks | Download bytes |
| --- | --- | --- | --- | --- | --- |
| Default `files` (argument omitted) | succeeded | 3 | 3 | 22 successful | 653191 |
| `zip` | succeeded | 1 | 3 | 22 successful | 86814 |
| `zip`, debug on | succeeded | 1 | 4 | 22 successful | 150299 |
| Unsupported explicit device + BMC host | failed, succeeded | 1 | 3 | 22 successful | 86959 |

All four verified schema 1.2 envelopes, the manifest's exact file list, every
byte size and SHA-256, archive CRCs, and the debug member when enabled. Injected
collection soft limits and unexpected exits preserved partial evidence with
`not_visited` devices. First packaging timeouts and timeouts immediately after
archive, device-file and manifest persistence recovered without duplicate
downloads. Filename collisions refused in both formats before device I/O.

```text
PR A dev proof: PASS (4 live captures, timeout/exit/retry/collision paths)
```

### PR B implementation and evidence (2026-10-02)

Implementation starts from PR A's merged main. `scope.py` resolves plain rows
before any transport opens; the job applies Nautobot's validated
`DeviceFilterSet` to location descendants and Dynamic Group members, then adds
explicit devices and controller dependencies before exclusions. The capture
loop visits only `capture` dispositions. Dry runs use a separate readiness path
that does not open host or BMC transports; reachability requires a real capture.

Two installed and 2.4.43 source details refine the prior-art summary in §2.1:
selected tags are conjoined (all must match), while roles and statuses use OR
within each field. The public `DynamicGroup.members` queryset is its cached
membership in both releases, matching the Members tab. Capture reads it without
updating the cache; operators refresh membership outside the read-only job.

The diff tool keeps support for separate runs on one side of a change. It reads
the newest supplied manifest row per device, correlates snapshots to their
JobResult, and rejects inconsistent evidence rather than allowing an older
successful snapshot to hide a later failed capture.

Explicit exclusions are recorded even when a device has fallen outside the
narrowed scope. They are added after controller expansion and cannot pull in
extra controllers. Paired diff reports retain manifest outcomes; a failed run
cannot look successful merely because its persisted snapshot's checks passed.
Supported devices without snapshots appear in `missing_snapshots`, including
failures present on both sides. Rollback and adhoc captures remain valid on
either comparison side; snapshot/manifest run correlation uses their actual kind.

Command output from the reviewed source tree:

```text
python3 -m unittest discover -s tests -t .
Ran 1602 tests in 9.181s
OK

Ruff 0.16.4 check --no-cache .: All checks passed!
Ruff 0.16.4 format --check .: 79 files already formatted
python3 -m compileall -q .: exit 0
Python 3.9 syntax: PASS
Read-only guard: PASS
Redfish fence guard: PASS
SOAP operation guard: PASS
git diff --check: exit 0
```

Fresh-context correctness review completed with no remaining source blockers.
It verified fixes for out-of-filter exclusions, paired failed capture outcomes,
and rollback/adhoc comparison compatibility. Independent isolated glue checks
proved 30- and 31-device dry runs do not open transports; a 31-device real run
refuses before collection or credential lookup and preserves `not_visited`
outcomes in its manifest.

The deployed job imports and renders all optional scope fields on dev Nautobot
3.2.5. On 2026-10-02 the user performed a full ad-hoc capture for the actual lab
site, downloaded and inspected its zip, and accepted the result for commit,
push and PR. The JobResult completed successfully from 01:15:44 to 01:17:44 UTC,
with one zip download. The deployed scope, constants, capture and bundle source
hashes match the reviewed worktree.

The run used `locations=["lab"]`, no explicit devices, default Active statuses,
`include_controllers=false`, `artifact_format="zip"`, and no dry-run or debug.
Both devices were location-sourced `capture` dispositions:

| Device | Outcome | Check statuses | Duration |
| --- | --- | --- | --- |
| `9300-lab` | succeeded | 30 success, 15 not-present | 17.833 s |
| `se350-lab-1` | succeeded | 22 BMC checks, all success | 101.242 s |

Read-only verification of the persisted download:

```text
ZIP bytes: 163879
ZIP members: 5 (manifest, two snapshots, two raw bundles)
Archive CRC: PASS
Exact manifest-to-member set: PASS
All four file byte sizes and SHA-256: PASS
Snapshot schema 1.2 and JobResult/kind/change/device correlation: PASS
Original BMC host location retained; synthetic fixture count: 0
```

This user-accepted actual site run is the live acceptance evidence for publishing
PR B in place of §8's proposed synthetic fixture scenario. No fixture objects
were created and the existing BMC host was not relocated. Synthetic controller,
unsupported-device and exclusion cases remain covered by the pure tests and
independent isolated glue checks; they are not claimed as live controller proof.
