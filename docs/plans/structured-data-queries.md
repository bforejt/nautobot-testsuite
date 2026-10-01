# Plan: structured data queries to every device

Status: **rule and decisions recorded 2026-10-01; nothing built.** This
document records:

- the rule: query every device for structured data, never scrape
  display text;
- why;
- an inventory of every read the Capture job makes today that parses text;
- the structured source for each, where one exists;
- how the reads that can't move are declared;
- defects found during the research.

The site-scope plan (`docs/plans/site-scope-and-zip.md`, decision 10) points
here.

## 1. The rule

**Structured data queries to all devices. The transport doesn't matter; the
data's structure does.** (The user, 2026-10-01.)

- **Acceptable:** any query whose answer comes back as structured data with
  named fields:
  - RESTCONF/YANG JSON, Redfish JSON, vim25 SOAP;
  - **SSH returning XML or JSON**, as PAN-OS does with
    `set cli op-command-xml-output on`.
- **Not acceptable:** "netmiko-style scraping", meaning regexes or column
  positions over human-oriented display text to pull out field values. A
  `show` table parsed by regex is scraping on any transport.

An earlier draft of this plan, the same day, read the preference as "REST
APIs only". It planned a PAN-OS move from SSH to the XML API, Basic auth for
it, a request allowlist, and removing netmiko. The user corrected the rule,
so **everything that existed only because of the transport is set aside**,
not deferred. PAN-OS keeps SSH with XML output, and netmiko stays.

**Why the rule.** These are the reasons that are about structure, not
transport:

- **Self-description.** Field names come from the model or the XML schema,
  not from a regex author's reading of a column header. That is the
  self-describing capture the suite is built for (capture-general
  doctrine).
- **Diff stability.** Display formats change between releases (column
  widths, wording, a new column). Structured keys change far less, so pre
  and post captures stay comparable across upgrades.
- **Honest failure.** A missing element in structured data is detectable.
  A regex that stops matching usually returns nothing, which reads as "no
  data" rather than "parser broken". Several advisories in the shakedown
  exist to catch exactly that.

### 1a. Design-level exceptions (D5)

**Decision D5 (the user, 2026-10-01):** two unstructured reads are
reasonable, and are called out as exceptions **needed at a design level**.
**Every other unstructured read needs its own justification** (§4).

**Exception A: the running and startup configuration as text**
(`iosxe_config`: `show running-config`, `show startup-config`).

- *What it does:* it keeps every line, redacted, as one object per config,
  and compares the two line by line to report unsaved changes. It pulls no
  values out of the text, apart from a few facts in the header lines
  ("Last configuration change at …").
- *Why it is needed:* the text is the device's own input language, the
  configuration exactly as an operator writes and reads it, so its layout is
  the syntax rather than a display. It is also the only complete record:
  - `Cisco-IOS-XE-native` gives the running config as JSON but omits every
    line it doesn't model;
  - the startup config has no structured source at all (no startup
    datastore is advertised, only the `unsaved-config` bool).

**Exception B: the logging buffer** (`iosxe_syslog_errors`: `show logging`).

- *What it does:* it keeps **no line text**, by design, because log lines
  name users and can carry typed commands. It parses each line's
  `%FACILITY-SEVERITY-MNEMONIC` tag and counts events by type: every
  severity 0–3 event, plus a curated set of severity 4–5 transients
  (err-disable, STP, FHRP, MAC flaps, PoE, 802.1X, duplicate addresses). It
  also reads the buffer header's facts (counters, size, the oldest line's
  timestamp and tag).
- *Why it is needed:* the tag is Cisco's documented message format, not a
  screen layout. Events that heal before a capture leave no trace in any
  state model; the buffer is the only record of them. And the buffer has no
  structured source on cat9k: `openconfig-system/messages` is deviated
  not-supported, and `CISCO-SYSLOG-MIB`'s history table is a different,
  smaller table.
- The header facts ride with the exception as part of the same read.

**What being a design-level exception means:**

- Both are declared like every other unstructured read (§4): in the
  register, the check context, the envelope and the job log. The README
  lists them under their own heading, **"Design-level exceptions"**, above
  the justified list, with the reasons above.
- They carry **no shrink target**. They are revisited only if a structured
  source appears that covers the whole of what they capture (for A, a
  startup datastore and complete native coverage; for B, a modelled
  buffer). A structured complement may be added beside them (for example
  native YANG config next to the text), but it doesn't replace them.
- Adding a third design-level exception takes an explicit user decision,
  recorded in this section. The register can't grow one quietly.

## 2. PAN-OS

Today, every PAN-OS check runs over SSH with
`set cli op-command-xml-output on`, and almost every parser reads XML
(`panos_xml.extract_xml` / `result_of`). **That conforms to the rule.**

These reads still pull values out of text:

| Read | Check | How it parses today | Structured alternative |
| --- | --- | --- | --- |
| `show system files` | panos_crash_files | `ls`-line regex over text (`_parse_core_files`, `:1480`) | none known; the command returns text inside `<result>` |
| `show system disk-space` | panos_disk_space | `df`-line regex (`_parse_disk_space`, `:1635`) | none known |
| `show panorama-status` | panos_panorama | regexes for server and "Connected" (`_parse_panorama`, `:1662`) | none known; candidates to try on the lab firewall: an XML-returning Panorama/device-telemetry status command, or `show system info` fields |
| `show url-cloud status` | panos_url_cloud | substring scan for "connected" (`_collect_url_cloud`, `:1135`) | none known |
| `show chassis-ready` | panos_chassis_ready | `yes`/`no` regex over the XML element's text (`:1607`) | effectively structured: a single-value element. Read the element and drop the regex. |
| `show session all filter … count yes` | panos_session_matrix | XML first, then a text fallback for "Number of sessions that match filter: N" (`_parse_session_count`, `:180`) | the XML path is primary. Keep the fallback only if the lab shows a release that needs it, declared. |

"None known" is from documentation and the code. The lab firewall the user
will provide (D3) is where each command's real output is checked, and where
any structured alternative is tried. None is a design-level exception (§1a),
so each needs a `justified` register entry (gap, value, exit) to stay.
Until the lab firewall settles them, they are declared with provisional
justifications, not removed.

## 3. IOS-XE

IOS-XE is RESTCONF/YANG-first, but **17 distinct SSH commands serving 14
checks** return CLI display text that is parsed by regex. All of them are in
scope. The facts come from the YangModels/yang `vendor/cisco/xe/17121`
models, with spot checks against 17.15.1. Per-platform presence comes from
`yang-set-cat9300.xml`, `yang-set-cat9500.xml` and
`yang-set-wireless.xml`. A model says what is defined, not what a device
fills in, so every candidate still needs a live GET before it replaces
anything.

### 3.1 Delete now: the structured read is already primary (no data loss)

| Text read | Check | Already-primary model |
| --- | --- | --- |
| `show license summary` | iosxe_license | `cisco-smart-license:licensing/state` |
| `show interfaces status err-disabled` | iosxe_errdisable | `Cisco-IOS-XE-interfaces-oper` `intf-ext-state/{error-type,port-error-reason}` |
| `show inventory` (×2) | iosxe_inventory, iosxe_switch_stack | `device-hardware-oper` `device-inventory` (`dev-name` carries "Switch 1") |
| `show interfaces trunk` (the trunk-port exclusion only) | iosxe_interfaces | `openconfig-interfaces … switched-vlan/state/interface-mode` |

### 3.2 Structured on paper, but needs a field check first

| Text read | Check | Candidate | What the shakedown must show |
| --- | --- | --- | --- |
| `show crypto pki certificates` | iosxe_pki (fallback) | `Cisco-IOS-XE-crypto-pki-oper` `crypto-pki-bundle[label]/cert[]` with validity dates | The lab 9300 answered **HTTP 500** on the container on 17.15.6. Re-test on 17.12, and try a narrower GET (`…/crypto-pki-bundle`, or one `=<label>`). |
| `show ip route summary` | iosxe_route_rollups (OSPF intra/inter/E1/E2/N1/N2) | derive from the RIB GET the check already makes: `ietf-ospf` `route-type` | whether the device fills `route-type` |
| `show switch detail` | iosxe_switch_stack, iosxe_crash_files | `Cisco-IOS-XE-stack-oper` `stack-node[]` (role, state, priority, MAC, hw-version, stack ports), `stack-info` | already lab-served; only `mac_origin` is missing (deprecated `stacking-oper` `is-local-mac`) |

### 3.3 Partial, or no structured equivalent

| Text read | Check | Best structured candidate | Gap |
| --- | --- | --- | --- |
| `show vtp status` | iosxe_vlans, iosxe_trunks | `native/vtp` (config) + `vlan-oper` count | configuration revision; the native values are *configured*, not operational (and VTP server/client data may live only in `vlan.dat`) |
| `show interfaces trunk` (sole source) | iosxe_trunks | OC `switched-vlan/state`; on **17.15+** `Cisco-IOS-XE-switchport-oper` `switchport-info` | encapsulation; the VTP-pruned set |
| `show redundancy` | wlc_platform | `Cisco-IOS-XE-ha-oper` `ha-infra` (lab-served) | switchover **count** (only a bool and a time); hardware mode; communications |
| `show interfaces transceiver [detail]` | iosxe_optics | `Cisco-IOS-XE-transceiver-oper` power in dBm, per lane | alarm and warning threshold flags |
| `show switch stack-ports summary` | iosxe_switch_stack | `stack-oper` port state + `stack-member-oper` cable length and link flaps | link_ok, link_active, sync_ok, loopback |
| `dir crashinfo-<N>:` and related | iosxe_crash_files | `platform-software-oper` `q-filesystem/partitions/partition-content` | per-member coverage on a stack (the lab showed one location, chassis −1) |
| `show etherchannel summary` | iosxe_port_channels | `lacp-oper` (per-member state on **17.15+**), `interfaces-oper` `lag-aggregate-state/members`, native `channel-group/mode` | per-member flags for PAgP and static (`on`) bundles; nothing on the 9800 |
| `show running-config` | iosxe_config | `Cisco-IOS-XE-native:native` (structured config) | **design-level exception A** (§1a); native omits unmodelled lines, so the text stays the complete record |
| `show startup-config` | iosxe_config | none: no startup datastore is advertised; only the `unsaved-config` bool | **design-level exception A** (§1a) |
| `show logging` (buffer) | iosxe_syslog_errors | none: `openconfig-system/messages` is deviated not-supported on cat9k | **design-level exception B** (§1a): event-tag counts and header facts; no line text is kept |
| `show sdm prefer` | iosxe_persistence | `native/sdm/prefer` (config; the enum lacks most real template names) | **no structured equivalent** for the template in effect |
| `show privilege` | iosxe_config | none | **no structured equivalent.** It is *not* part of exception A: it is a separate scraped read (a lower-privileged session is shown only part of the config, so the check warns), and it needs its own justification, or a structured way to prove the session sees the whole config |

**Bridges to try, both unverified:**

- **SMIv2 MIB modules over RESTCONF.** The yang-sets list `CISCO-VTP-MIB`,
  `CISCO-SYSLOG-MIB`, `CISCO-RF-MIB` and `CISCO-CONFIG-MAN-MIB` as
  implemented. They would cover the VTP revision, syslog history,
  switchover history and config-change timestamps. Whether RESTCONF serves
  them is unproven. Every path must be fenced: `CISCO-VTP-MIB`'s
  `vtpAuthenticationTable` holds the VTP password and secret key.
- **Structured CLI output.** Under this rule, an SSH command that returns
  XML is as good as RESTCONF. Whether 17.12's CLI offers structured output
  for any of these commands (an XML `| format` facility exists on some IOS
  trains) is unverified. One look on the lab switch settles it.

### 3.4 Release dependency (D4)

- **The production fleet is on 17.12.** The 17.15-only models
  (`switchport-oper` for trunks, `lacp-oper` per-member state) are out of
  reach. Those reads stay declared until the fleet moves to 17.15 or later,
  which is their recorded revisit condition.
- **The user will downgrade the lab 9300 to 17.12**, so 9300 field checks run
  at the fleet's release. The 9500 and the 9800 have no lab unit: their
  field checks need a read-only Test Suite Shakedown (`only_checks`)
  against one production 17.12 device of each.
- **Before the downgrade:**
  - Harvest one full debug shakedown on 17.15.6 as the 17.15 reference for
    that revisit. **Done 2026-10-01** (19:56 UTC, about ten minutes after a
    boot, so the AP was up): 45 checks, 30 ok, 15 not-present, 0 failed.
    `crypto-pki-oper` answered HTTP 500 again (F7). It is kept unsanitized
    outside the repository, in the lab notes, and is not a fixture.
  - Label the existing `tests/fixtures/*_lab*` captures as 17.15.6. They are
    kept; they're the only record of 17.15 shapes.
- **After the downgrade:**
  - Confirm RESTCONF, SSH and the VLAN 2 management path came back. A saved
    configuration from a newer release can lose lines.
  - Re-run the shakedown on 17.12.
- **A check may need to be release-aware.** It reads the newer model where
  it is served and falls back to the declared read where it isn't, and the
  declaration (§4) says so in the snapshot.

## 4. Declared unstructured reads: shrink them, and make every use loud (D1)

**Decision D1: shrink the exceptions, and loudly declare any that remain.**
No unstructured read happens silently, on any platform or transport.

**The register is the only list.** `C.UNSTRUCTURED_READS` lists every read
that doesn't return structured data. Each entry records:

- the platform, the command, and the check ids;
- its class:
  - **`design`:** one of the two design-level exceptions in §1a. The class
    is closed: only §1a may add a member;
  - **`justified`:** everything else, each with a written justification.
- for `justified` entries, the **justification**. It answers three
  questions, and an entry missing any of them fails review:
  1. **Gap:** which fields have no structured source on the fleet's release
     (17.12), with the models and alternatives checked named;
  2. **Value:** why those fields are worth keeping, by the capture-general
     yardstick (the layer of state they cover, how many kinds of change
     consume them, and that they can't be derived from what is already
     captured);
  3. **Exit:** the revisit condition ("fleet on 17.15+", "SMIv2 bridge
     proven", "lab firewall shows an XML form").

  A read whose justification fails is moved to structured data, narrowed to
  the fields that pass, or dropped, and the drop is recorded in this plan.

**CI pins it from both directions:**

- A test walks every `ctx.run_ssh(...)` command string in `jobs/checks_*.py`.
  Each must be either an XML-returning PAN-OS command parsed through
  `panos_xml`, or declared in the register. The six PAN-OS text reads in §2
  are declared.
- The `cisco_xe` SSH allowlist and the register's IOS-XE commands must
  match. A command allowed but not declared fails the build, and so does a
  declaration nothing uses.

**Every use is loud, in four places:**

1. **The check entry.** Its `context` carries
   `data_form: "structured" | "unstructured"`. An unstructured read adds
   `exception: "design" | "justified"` and the register's reason.
2. **The envelope.** A top-level `unstructured_reads` list holds the
   commands used, their checks, their class and their reason. An analyst, or
   the LLM, sees it without opening every check. This is schema 1.3,
   additive.
3. **The job log.** One WARNING per device names every unstructured read
   used, for example "Unstructured read: `show sdm prefer`
   (iosxe_persistence, justified): no structured source for the template
   in effect on 17.12." Design-level exceptions are logged too, at INFO,
   since they are expected on every IOS-XE capture.
4. **The README.** It has two sections, "Design-level exceptions" and
   "Justified unstructured reads", both tested against the register so the
   docs can't drift.

**Shrinking applies to `justified` entries only. It means three things:**

- Justify each exception **per field**, not per command. A check reads
  structured data for everything modelled and keeps the text read only for
  the gap.
- Where a gap field has little general value, measured by the
  capture-general yardstick (which layer it covers, how many kinds of change
  consume it, whether it can be derived), drop the field instead and record
  the drop here.
- Review the register whenever a revisit condition is met.

## 5. Defects found during the research

These stand on their own, whatever the rule. F1–F3 are plain defects in the
SSH plumbing that PAN-OS and IOS-XE both still use. They are kept because
they are bugs, not because of any transport preference.

| # | Where | What | Effect |
| --- | --- | --- | --- |
| F1 | `context.py:350` | `ctx.has_ssh` is just `self.ssh is not None`, and every iosxe device always gets an `SshRunner` | Every "no SSH transport" skip or note is reachable only in tests and harvest runs, never in production |
| F2 | `transport_ssh.py:128-136` | `open()` sets `self.conn` only on success, and nothing remembers a failure | A device without SSH reachability pays the 15 s connect timeout once **per SSH-using check** (about 14 on IOS-XE). It should fail once and record why. |
| F3 | `snapshot_job.py:396` | The comment says "only the SSH-based rollup check pays the connect cost" | Stale: about 14 checks now use SSH |
| F4 | `checks_panos.py` `_collect_syslog_events` (`:1802`), `_parse_core_files` (`:1502-1506`) | The log window and the `ls` times are built and read as UTC, but PAN-OS works in the firewall's **local** time | On a firewall not set to UTC, the 24-hour window shifts and a crash file can cross the 7-day cut-off. Unverified on a device; check on the lab firewall. |
| F5 | `tests/fixtures/panos_session_count_xml.txt` | It echoes `… from-zone trust to-zone untrust …`, not the field-proven `from … to …` form | The parser doesn't care, but the fixture is misleading |
| F6 | `checks_panos.py` panos_bgp_peers, panos_dhcp | `show advanced-routing bgp peer` is probably `… bgp peer status` on ARE, and `show dhcp server lease all` may really be `… lease interface all` | These may already be skipping or failing on real firewalls. Unverified; settle on the lab firewall (`debug cli on` shows the accepted forms). |
| F7 | iosxe_pki | `crypto-pki-oper-data` answered HTTP 500 on the lab 9300 (17.15.6) | The check depends on its text fallback today; re-test on 17.12 (§3.2) |

## 6. Phasing

Each phase is its own PR in a fresh session, landed between change windows.
A pre/post pair must be captured with the same code, and moving a read from
text to a model can change its keys.

0. **Defects F1–F3 and F5** (small; no shape change). F4 and F6 wait for the
   lab firewall.
1. **IOS-XE §3.1 deletions:** text fallbacks whose structured read is
   already primary. No data loss.
2. **The register and the loud declarations** (§4), covering every
   remaining unstructured read on both platforms. This lands before further
   moves, so every later step shrinks a visible list.
3. **IOS-XE field checks** (§3.2, §3.3, and the bridges): on the lab 9300 at
   17.12, plus read-only shakedowns on a production 9500 and 9800. Then move
   or narrow each read, updating the register in the same PR.
4. **PAN-OS text reads** (§2) on the lab firewall: try the structured
   alternatives, and fix F4 and F6.
5. **Revisit on events:** a fleet upgrade to 17.15 or later, or a proven
   bridge.

The site-scope work (PR A and PR B) goes first. Phases 0 and 1 don't touch
the same code, so they can go in between.

## 7. Decisions (the user, 2026-10-01)

- **The rule:** structured data queries to all devices. The transport
  doesn't matter, and SSH returning XML or JSON is acceptable. Plans that
  existed only because of the transport are set aside.
- **D1:** shrink the exceptions, and loudly declare any that remain (§4).
- **D3:** the user will provide a lab firewall. It is used for the PAN-OS
  text reads, F4 and F6, and it is no longer a prerequisite for anything
  else.
- **D4:** the production fleet is on 17.12. The user will downgrade the lab
  9300 to 17.12 (§3.4).
- **Set aside:** D2 (PAN-OS Basic auth) and the whole PAN-OS XML API
  migration. If either ever returns, it will be for a reason other than
  this rule.
- **D5:** the running and startup config as text (A) and the logging
  buffer (B) are **design-level exceptions**, called out as such (§1a).
  **Every other unstructured read needs a justification** (§4), on both
  platforms.
