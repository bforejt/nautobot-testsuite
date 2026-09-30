# Coverage map

What the capture sees on each platform, layer by layer, and what it still
cannot see — ranked by general informational value, never by the last
change that happened to need it. This is the living status page for the
catalog: the plans under `docs/plans/` propose checks, the README catalog
table lists what shipped, and this map says where the holes are and which
ones are worth closing next.

**How the tables read.** One row per layer. *Captured today* names the
check ids whose normalized view or context carries that layer (the README
row and the check's SEMANTICS say exactly what each key holds). *Holes*
names what no check records. *General value* scores each hole on four
questions that apply to any change:

- **Consumers** — which classes of change would read it (a reload, a
  re-cabling, an access-edge migration, a routing change, an upgrade, a
  hardware swap). A hole only one kind of change would ever read ranks low.
- **Derivable?** — can an analyst already get it from something captured
  (a join across two checks, a delta between two captures)? A derivable hole
  costs reviewer attention, not a collector.
- **Diff stability** — would two healthy captures an hour apart diff to
  nothing? Volatile data can only ever be context or raw, which caps its
  value.
- **Cost** — new requests per capture, transport doctrine (GET and `show`
  only), hygiene (no usernames, no secrets), and reviewer attention.

## Process

After every LLM analysis of a real pre/post pair, harvest the analyst's
caveats — "I could not tell whether …", "this diff was noise because …",
"I had to infer … from …" — into this map: a caveat about something no
check records is a hole; a caveat about noise is a stability defect on an
existing row; a caveat about an inference is a derivable hole that may
deserve a join in context. Then re-rank the open items by the four
questions above. The ranking is by general value across the classes of
change the fleet undergoes; the change that surfaced a caveat is evidence
that a class of change consumes it, never the reason on its own. Nothing in
`jobs/` refers to a change, site or migration, and neither does this map.

## IOS-XE (Catalyst switches and stacks; the 9800 wireless catalog rides on the same platform)

Every row below was walked against a real Catalyst 9300 (C9300-48UXM, a
single-member stack on 17.15.6): the lab harvest that every `_lab` fixture
is sanitized from and the closing full-catalog runs (45 checks: 30 ok, 15
not-present, 0 failed; every empty `ok` explained by its context); the
17.15.1 YANG models on disk were the reference for every leaf name. Where a release fills a different list or leaf than another, the
check records which one it read in context (`port_map_source`,
`port_family_served`, `port_name_form`, `sources`, `models`, `leaves_seen`,
`counters_invalid`) rather than guessing.

| Layer | Captured today | Holes remaining | General value of closing each hole |
| --- | --- | --- | --- |
| L1 / physical | `iosxe_interfaces` (admin/oper, the auto-negotiation flag, negotiated speed and duplex while up and mGig downshift — as keys on trunks and routed ports, in context `access_link` for the access ports the VLAN database names from whichever list the release fills minus the trunks `show interfaces trunk` lists, `link_scope`, `access_port_source` and `trunk_ports_excluded` naming which; CRC, in-error and flap counters in context, with wrapped uint64 readings named under `counters_invalid` and never counted and a not-present port's statistics never read), `iosxe_optics` (DOM light levels, optic-raised alarms), `iosxe_inventory` (transceiver identity), `iosxe_switch_stack` (stack ring ports, SSO-ready flag), `iosxe_svl_health` (SVL link bundling), `iosxe_neighbors` (CDP-reported duplex where the CDP model is filled; context `sources` says how each model answered), `iosxe_poe` (port power state), `iosxe_port_channels` (per-member LACP state and partner identity from `lacp-oper` where the release serves it) | (a) Counter **deltas** are not evaluated: CRC/error/flap counts sit in context, so a port that took errors between captures is found by the analyst reading two contexts, not by a compare mode (`diffcore` reserves an `activity` mode, unwired). (b) UDLD state: no oper model; `show udld` only. (c) Cable diagnostics need an active `test` command — outside the read-only allowlist by doctrine, permanently. | (a) Consumed by every change that touches a cable or an optic; derivable today from two contexts; stable by construction (a delta, not a level); cost is a compare mode, no new request. (b) Consumed by fiber and uplink changes; not derivable; stable; one `show` parse. (c) Not closable. |
| L2 topology | `iosxe_stp` (mode, guards, per-instance root facts with the root port resolved to a name, every port that is neither designated-forwarding nor disabled/link-down; topology-change counter and its age in context), `iosxe_trunks` (allowed/active sets, native VLAN; the forwarding set as a key where VTP pruning is off, in context where it is on, `vtp_pruning` naming which), `iosxe_vlans` (VLAN database, VTP, the per-port VLAN map in context inverted from whichever list the release fills, `port_map_source`), `iosxe_port_channels` (bundles, member flags, and per member the LACP state, partner system-id, key and port), `iosxe_neighbors` (CDP/LLDP), `iosxe_svl_health` | (a) Per-port VLAN membership stays context, not keys: the field capture settled that `vlan-interfaces` lists every switchport once — an access port under its VLAN, a trunk under VLAN 1 whatever its native VLAN — down ports included, and nothing marks a session-controlled (802.1X) port, so a key would move with an endpoint's session. (b) **The CDP model answered an empty container on the lab 9300** on earlier harvests while `show cdp neighbors detail` listed the AP — the CDP platform string, native VLAN, voice VLAN and duplex that `iosxe_neighbors` normalizes come only from LLDP on such a capture, and a CDP native-VLAN mismatch is unobservable YANG-first there; the later full runs served one to three CDP neighbors, so it is a per-capture fact, now recorded in context `sources`. (c) A CDP native-VLAN mismatch is derivable (where CDP is filled) but not flagged. | (a) By design; the map in context answers it for static ports. (b) Consumed by every access-edge and re-cabling change (phones and APs speak CDP, many switches only CDP); not derivable; stable; one `show cdp neighbors detail` parse as the fallback when the container is empty. (c) Derivable in analysis by joining `iosxe_neighbors` native_vlan against `iosxe_trunks` native_vlan; a context flag would cost nothing. |
| L2 forwarding | `iosxe_mac_table` (dynamic MAC counts per VLAN/member/port as capability; statics, CPU group addresses and SVI MACs in context; rows in raw), `iosxe_access_sessions` (802.1X/MAB/web-auth outcomes as capability buckets per domain, method, landed VLAN and member; fields-filtered read only, never a username), `iosxe_arp` (all VRFs, from `arp-entry` or the deprecated flat `arp-oper` list a release fills instead, `source` in context), `iosxe_errdisable` (err-disabled ports with the model's reason), `iosxe_interfaces` (storm-control blocking) | (a) Closed: `iosxe_arp` reads the flat `arp-oper` list where a release fills only that one, and context `source` / `entries` / `vrfs` explain the view. (b) **`matm-oper` spells ports short on older releases (`Tw1/0/1`) and long on the lab's (`TwoGigabitEthernet1/0/1`)**, so an upgrade between the pre and post captures re-keys every `port\|` bucket (`port_name_form` in context says which form was read). (c) Port-security secure MACs (`psecure-oper`, served from 17.15 on). (d) DHCP-snooping and device-tracking bindings: no oper model; `show` only. | (a) Closed on this branch. (b) Consumed by every upgrade; a fix that keys buckets and rows by the long name (`common.long_ifname`) plus one test-pin change; zero new requests. (c) Consumed by access-edge changes on port-security sites; not derivable; stable; one GET. (d) Consumed by the same changes; not derivable; volatile (leases age); `show` parse to context. |
| L3 / control plane | `iosxe_routes_rib`, `iosxe_routes_fib` (attached-host /32 adjacencies, which follow ARP, counted in context and never keyed), `iosxe_route_rollups`, `iosxe_bgp_peers`, `iosxe_ospf_neighbors`, `iosxe_eigrp_neighbors` (a listed neighbor is the adjacency — the model has no state leaf), `iosxe_isis_neighbors`, `iosxe_fhrp` (HSRP and VRRP roles, VIPs, priorities; transitions and reasons in context), `iosxe_arp`, `iosxe_routing_config`, `iosxe_interfaces` (IPv4/mask with 0.0.0.0 read as None, VRF, IPv6, MTU, ACLs, QoS policies) | (a) IPv6 neighbor table (the ARP twin). (b) Multicast state (IGMP snooping, PIM neighbors). (c) HSRP and IS-IS are coded to the 17.15.1 models and hand-built fixtures only: the lab image refuses `standby` and `router isis`, so how HSRP spells `active-ip` for the local router and what an IS-IS adjacency row carries are unverified live. | (a) Consumed by IPv6 rollouts; derivable from nothing captured; churns like ARP (tier 2 full-table). (b) Consumed by multicast changes only; ranks low until a site runs it. (c) Settled by one capture on a distribution pair, not a check. |
| Platform / identity | `iosxe_persistence` (config saved, software version, SDM template in effect and pending, per install location the running image's version, commit state, abort timer and image list), `iosxe_license` (level in effect, registration, authorization, per-licence enforcement; never keys, tokens, account names or the UDI), `iosxe_pki` (trustpoints and certificates with validity end and status; an enrolled identity certificate keyed by its issuer with its naming RDNs withheld; days-to-expiry tallies in context), `iosxe_tcam` (TCAM and datapath utilisation with a tolerance; the band word and readings in context), `iosxe_platform_health` (boot time as epoch seconds with a 60 s tolerance, last reload reason, alarms, sensor states as keys in one vocabulary — `Power Supply A/B` on the 9300, the P0/P1 family where a release reports it; served words and readings in context), `iosxe_inventory`, `iosxe_switch_stack` (roster, ring, `sso_ready` where served), `iosxe_svl_health`, `iosxe_crash_files` (recency-windowed), `iosxe_poe` (StackPower) | (a) `boot-time` is served with seconds that jitter between reads of a box that never reloaded (a derived timestamp: now minus uptime; :43 / :44 on the 17.15.6 runs), so the key holds it as integer UTC seconds under a 60 s compare tolerance with the served string in context `boot_time` (cutting it to the minute only moved the failure to the minute boundary); a reload takes minutes, so none hides inside the tolerance. (b) `unsaved-config` is unserved on older releases (`config_saved` reads None there, never False) and `crypto-pki-oper` answers HTTP 500 on the lab's (the CLI fallback carries `iosxe_pki`): both are release facts recorded in context, not holes, but a fleet on such releases has no model-side flag. (c) The q-filesystem core-file source of `iosxe_crash_files` stays a model-shape best guess (the lab harvest fixtured the model's shape; `dir` remains the field-verified source). (d) **Power-feed diversity is not observable from the device**: supply input presence is (`Power Supply A/B` states); whether two supplies sit on separate circuits is a facility record. Closed as unobservable. | (a) Closed by construction. (b) Not closable on those releases; the checks say so. (c) Settled by a crash on a 17.15 box, not a check. (d) Not closable here. |
| Powered devices (phones, APs, cameras) | `iosxe_poe` (per-port admin/oper/class for every listed port — the observed 9300 releases list powered ports only, so a device that lost power is a removed key there; `port_source`, `ports_total` and `poe_ports` in context say what a release listed; budgets, allocations and watts drawn in context), `iosxe_neighbors` (CDP identity where CDP is filled, LLDP chassis/port otherwise), `iosxe_access_sessions` (802.1X outcomes for phones), on a controller the `wlc_*` catalog | (a) A count of powered devices by class and neighbor platform (a capability view like `wlc_clients_summary`) is derivable from the normalized views but not emitted. (b) On the observed releases only powered ports are listed, so an "off" or "faulty" per-port state never appears as a value there — a fault reads as a removed key, and the reason is only in syslog (`%ILPOWER-*`, counted by `iosxe_syslog_errors`); a release or SKU that lists every PoE-capable port reads an empty port as oper off with class unknown (the SEMANTICS say to read class beside oper). | (a) Consumed by any access-edge or PoE-budget change; derivable by joining `iosxe_poe` and `iosxe_neighbors`; capability mode is stable; zero new requests. (b) A `show power inline` parse would add the fault reason; YANG-first says the model exists, so this stays a documented reading. |
| Configuration | `iosxe_config` (running and startup text as redacted line lists with the header's `by <user>` masked and its clock kept, hunk-level diff, whether they match), `iosxe_persistence` (`config_saved` as a flag), `iosxe_routing_config`, `iosxe_dhcp` (pools, excluded addresses, relay options and the DHCP-snooping globals), `iosxe_interfaces` (effective per-port config leaves), `iosxe_vlans` (the VTP-held VLAN database) | (a) Secret rotation is invisible behind constant redaction: a changed RADIUS/TACACS+ key, SNMP community or routing-protocol key diffs to nothing (its effect may show in `iosxe_aaa_servers`). (b) Defaults changed by an upgrade leave no line. (c) RADIUS-applied per-session policy (dynamic VLANs, downloadable ACLs, interface templates) is not config text (`iosxe_access_sessions` counts the landed VLANs). (d) A configured local user's `username <name> …` line keeps its name by the grammar-position rule, because a local-user change must diff (the header's `by <user>` account is masked in raw and the trace and never lifted into context). | (a) Consumed by every credential rotation; not derivable; a digest keyed with a deployment secret would be stable and leak nothing; cost is a design decision (an unkeyed hash of a type-7 string is reversible). (b) Consumed by upgrades; not closable in general — the state checks are the answer. (c) See `iosxe_access_sessions`. (d) A doctrine decision to record, not a bug. |
| Services (time, AAA, DHCP, logging) | `iosxe_ntp` (synchronized derived from stratum, the refid kind and one system peer; per-association health class; the selected peer in context because it moves between healthy servers), `iosxe_aaa_servers` (RADIUS server liveness per group/server; counters in context), `iosxe_dhcp`, `iosxe_syslog_errors` (severity 0–3 counts plus severity 4–5 for the port, redundancy, edge-service and platform facilities; buffer header and oldest-line timestamp and tag in context; usernames and logged commands redacted before the text is parsed, stored or traced) | (a) TACACS+ server liveness (RADIUS only today). (b) SNMP, EEM and call-home have no oper model. | (a) Consumed by AAA changes on TACACS+ sites; one GET if the model serves it. (b) Not closable YANG-first. |
| Reachability | Nothing active. Passive evidence only: OSPF/EIGRP/IS-IS/BGP adjacency states, FHRP roles, ARP and MAC learning, 802.1X outcomes, NTP sync, RADIUS liveness, and interface counters in two captures' contexts. | **Held by decision.** An allow-listed, derived-target `ping` (targets read from the device's own tables — next-hops, configured servers — never from job input) would be the one active probe in the catalog. The passive alternative is counter deltas between captures (L1 row, hole a). | Consumed by every change; partly derivable from counter deltas and adjacency states; an active probe changes the transport doctrine (`test`/`ping` are banned because on some platforms they initiate state), so the decision is doctrinal, not a ranking. Recorded here so it is not re-litigated per change. |
| Self-description | Every check's SEMANTICS in the envelope; the IOS-XE release as `iosxe_persistence` `device` -> `software_version` (normalized, so an upgrade is a key diff); context notes recording which leaves and lists a release served (`leaves_seen`, `fields_filter`, `source`, `sources`, `models`, `port_source`, `port_family_served`, `port_map_source`, `port_name_form`, `counters_invalid`), raw notes on every unfiltered retry after an HTTP 400; hardware revisions in `iosxe_inventory` (VID) and `iosxe_switch_stack` (`hw_version`); the shakedown's `discovery` (yang-library module inventory, `key_models` merged from every catalog module, RIB/FIB naming, q-filesystem shape). | (a) The yang-library module inventory is read only by the shakedown, so a capture pair spanning an upgrade does not itself say which served models changed (an upgrade onto the lab release adds hsrp-, isis-, lacp-, psecure-, poe-health- and stack-member-oper). | (a) Consumed by upgrades and by any analysis of a "parsed but empty" check; not derivable from a capture; stable; one small filtered GET into context. |

### The 9300 plan: status of its ten recommendations and §10 defects

`docs/plans/iosxe-9300-config-coverage.md` §8 and §10. "Landed" means the
check exists, is fixture-tested on the lab payloads and ran live.

| Item | Status | Where |
| --- | --- | --- |
| Rec. 1 `iosxe_persistence` | **landed** — `config_saved` (None where `unsaved-config` is unserved), `software_version`, SDM template in effect and pending (`show sdm prefer`, no model), per install location version/state/abort timer/boot mode plus the full image list (the plan's "the `is-default` row" is unfilled on the 9300: both rows read false, so the running image is the default row, else uncommitted, else committed) | `jobs/checks_iosxe_platform.py` |
| Rec. 2 `iosxe_vlans` | **landed** — the lab fills `vlan-interfaces` only (`ports` empty): every switchport once under its access or native VLAN, down ports included, `port_map_source` in context | `jobs/checks_iosxe_layer2.py` |
| Rec. 3 `iosxe_trunks` | **landed** — short CLI port names, canonical ranges; forwarding set keyed while pruning is off | `jobs/checks_iosxe_layer2.py` |
| Rec. 4 `iosxe_stp` | **landed** — `VLAN0001` spelling, root port resolved through `port-num`, only up ports listed; the last-change time is served as an age from the 1970 epoch, so its seconds go to context | `jobs/checks_iosxe_layer2.py` |
| Rec. 5 `iosxe_poe` | **landed** — `poe-port-detail`, powered ports only on both releases; StackPower standalone member verified | `jobs/checks_iosxe_poe.py` |
| Rec. 6 `iosxe_access_sessions` | **landed** — eight-leaf fields filter only, an HTTP 400 is not-present (never retried unfiltered: that form carries usernames), an empty 2xx is `total` 0 | `jobs/checks_iosxe_layer2.py` |
| Rec. 7 widen `iosxe_interfaces`, `iosxe_errdisable`, `iosxe_neighbors` | **landed** (previous branch) — plus, on this one, 0.0.0.0 -> None, wrapped uint64 counters and not-present ports' statistics named in context | `jobs/checks_iosxe.py` |
| Rec. 8 widen `iosxe_syslog_errors` | **landed** — the plan's exact facility allowlist for severities 4–5; header, oldest-line timestamp and tag in context; text redacted before parse, raw and trace | `jobs/checks_iosxe.py` |
| Rec. 9 `iosxe_fhrp` | **landed** — VRRP verified live (one master group); HSRP coded to the 17.15.1 model, unverifiable on the lab image | `jobs/checks_iosxe_layer3.py` |
| Rec. 10 `iosxe_mac_table` | **landed** — verified on the real table; port buckets keep the release's spelling (open item 3 below) | `jobs/checks_iosxe_layer2.py` |
| Beyond the plan | **landed** — `iosxe_license`, `iosxe_pki`, `iosxe_tcam` (the "license level and SDM template" and "TCAM utilisation" holes of the previous map), `iosxe_eigrp_neighbors`, `iosxe_isis_neighbors`, LACP partner identity in `iosxe_port_channels`, `sso_ready` in `iosxe_switch_stack`, `iosxe_svl_health` reading not-present on a location-only container | layer modules, `jobs/checks_iosxe.py` |
| §10 `iosxe_ntp` invented leaf names | **landed** — rewritten on `ntp-oper`'s real leaves; `synchronized` derived; the sys-peer moves between healthy servers, so it is context | `jobs/checks_iosxe.py` |
| §10 `iosxe_interfaces` fetches `vrf`, never normalizes it | **landed** (rec. 7) | `jobs/checks_iosxe.py` |
| §10 `iosxe_dhcp` SEMANTICS omit the snooping globals | **landed** — description, SEMANTICS and the not-present message name them | `jobs/checks_iosxe.py` |
| §10 `iosxe_syslog_errors` counts 0–3 only | **landed** (rec. 8) | `jobs/checks_iosxe.py` |
| §10 `show logging` text unscrubbed in raw and the trace | **landed** — `CollectorContext.run_ssh` applies the redactor before the trace copy and before the return (fail-closed); the config header's `by <user>` is masked the same way and the account is never lifted into context (the header facts keep only the clocks) | `jobs/context.py`, `jobs/checks_iosxe.py` |

### Open items, ranked by general value

1. **Counter deltas as a compare mode** (`activity`, reserved in `diffcore`): CRC/error/flap counters already in context. Cable and optic changes; no new request.
2. ~~`iosxe_arp` fallback to the flat `arp-oper` list~~ — landed: a release that fills only the deprecated list keys the same entries, context `source` says which list was read.
3. **`iosxe_mac_table` port buckets keyed by the long interface name.** `matm-oper` spells ports short on older releases and long on the lab's, so an upgrade between pre and post re-keys every `port|` bucket. Every upgrade; a fix plus one fixture-pin change.
4. **CDP CLI fallback for `iosxe_neighbors`** (`show cdp neighbors detail`) when `cdp-oper` answers an empty container, as the lab 9300 did on earlier harvests while CDP had neighbors (context `sources` now records which case a capture is): phone and AP platform strings, native and voice VLAN are otherwise unobservable. Access-edge and re-cabling changes; one `show` parse.
5. **yang-library inventory into the capture** (context). Upgrades; one small GET.
6. ~~Drop the `by <user>` groups from `iosxe_config`'s header facts~~ — landed: the header regex matches the account and never captures it.
7. **Port-security secure MACs** (`psecure-oper`, served from 17.15). Access-edge changes on port-security sites; one GET.
8. **Re-verify on a device that has what the lab lacks.** The 17.15.6 run confirmed what was coded from the 17.15.1 models and the probe trace: `lacp-oper` served (members down, partner None, `sources` says so), the wrapped `num-flaps` counters named in `counters_invalid` on 17 interfaces (the 12 empty uplink-module ports, the management port and the four SVIs) and never counted, the SVL location-only container reading not-present, `arp-entry` filled (6 keys), `matm-oper` long port names, `poe-port-detail` with the AP powered. Still unseen live: `identity-oper` with sessions, `poe-oper` with nothing powered (the probe served no per-port list), an LACP partner actually bundled, and HSRP `active-ip` spelling on an image that runs HSRP. `tools/harvest_live.py` re-runs unchanged.
9. **TACACS+ liveness**; **IPv6 neighbors**; **UDLD**; **DHCP-snooping and device-tracking bindings**; **multicast state**; **powered-device counts by class** (derivable) — real, site-dependent, each one request or a join.
10. **Secret-rotation digest** in `iosxe_config` — a design decision (keyed digest), not a collector.

**Closed as not observable or not closable:** power-feed circuit diversity
(a facility record); cable diagnostics and any other active `test`; defaults
that an upgrade changes silently (the state checks are the answer);
SNMP/EEM/call-home state (no oper model); `unsaved-config` on older releases
and a working `crypto-pki-oper` on the lab's (release facts the checks record).

**Held by decision:** the reachability probe (see the row above).

### What the lab capture settled (plan §9)

Every question the plan left to a field capture was answered by the lab
9300 (live on 17.15.6, with earlier probes of the same switch for the
release differences) and coded into the checks; the fixtures under
`tests/fixtures/iosxe_*_lab.*` are the sanitized payloads (harvested with
`tools/harvest_live.py`, sanitized with `tools/make_fixtures.py`) and
`tests/test_lab_fixtures.py` pins what each normalizer reads.

- Models served: the lab release advertises all eight the plan needed plus
  lacp/psecure/isis/poe-health/stack-member; older releases do not advertise
  hsrp-, isis-, lacp-, psecure-, poe-health- or stack-member-oper (404s).
  An unadvertised model is a 404, never an empty 2xx; an advertised model
  with nothing configured (hsrp, isis, psecure, poe-health on the lab) is an
  empty 2xx.
- `device-system-data`: the lab fills `unsaved-config`, `software-version`,
  `rommon-version` (the literal `IOS-XE ROMMON`), `reload-history` and
  `mac-address`; older releases have no `unsaved-config` leaf.
- `sso-ready-flag`: served per member; on a single member it reads false and
  `ha-oper` fills `peer-state db-rf-disabled`.
- CDP `native-vlan`/`vvid`: the CDP model was an empty container on earlier
  harvests while the CLI listed the AP (open item 4); the later runs served
  the AP (and, with one port hairpinned into the uplink's LAN, the switch
  itself twice with a native-VLAN mismatch), and `iosxe_neighbors` context
  `sources` records which case a capture saw.
- Syslog: buffered at debugging; the sev-4/5 tags of the allowlist seen on
  the lab include `%CDP-4-NATIVE_VLAN_MISMATCH`, `%LINEPROTO-5-UPDOWN`,
  `%SYS-5-CONFIG_I`, `%ILPOWER-5-*`, `%STACKMGR-4-SWITCH_ADDED`;
  `%SEC_LOGIN-5-LOGIN_SUCCESS` carries `[user: …]` (the leak the redactor
  now masks — the harvested buffer already carries the marker).
- `ntp-oper`: no sync leaf; `refid` is a container (`ip-addr` / `kod-data` /
  `ref-clk-src-data` / `exception-code`); exactly one association is the
  system peer and it moves between healthy servers across reads.
- `install-location-information`: one row per member keyed
  `fru-rp/0/0/chassis <n>`; the fields filter is accepted; on the lab
  `commit-type` and `boot-mode` read `user` / `install` and the abort timer
  `inactive` once the image is committed (`install|1|rp|0|0` ->
  `provisioned-committed 17.15.06.0.770`, an older image left on flash
  `present`); older releases leave `commit-type` and `boot-mode` unfilled and
  their idle timer reads `unknown`.
- `vlan-oper`: `ports` empty on every VLAN; `vlan-interfaces` lists every
  physical switchport once under its access VLAN or, for a trunk, under VLAN
  1 whatever its native VLAN (Te1/0/47, native 999, sits under 1);
  Port-channels absent; nothing marks 802.1X ports.
- VTP server mode, v1, pruning disabled; VLAN lines are present in the
  running-config text on this platform even in server mode.
- STP: instances spelled `VLAN0001`; `root-port` is a `port-num` (0 when
  root) resolved through `interfaces[].port-num`; only up ports are listed;
  `time-of-last-topology-change` is a 1970-epoch offset (an age); the
  designated-forwarding exclusion produced identical keys across three reads.
- `show interfaces trunk`: the two-row layout (native 1 and native 999); sets `1,3-4` and `3-4,999`; pruning off.
- PoE: `poe-port-detail` is the populated list and holds only powered ports
  (no `poe-port` list at all); the 17.15.6 probe served no per-port list
  while nothing was powered; per-port state and per-switch budgets were
  identical across three reads.
- `identity-oper`: the eight-leaf fields filter is accepted; an empty 2xx
  with no 802.1X (the unfiltered container still answers ~1.5 KB).
- FHRP: `vrrp-oper` fills one row with state, VIP, priority, preempt, owner,
  master-ip, virtual-mac and the transition counters; `master-ip` reads the
  local SVI address while master.
- `matm-oper`: 16 KB whole / 9 KB filtered for 79 entries; static/dynamic
  types; 21 CPU group MACs in the vlan-independent table with
  `vlan-id-number` 1; SVI MACs static on `Vlan<n>`; ports long on the lab,
  short on older releases (open item 3).
- Widened `interfaces-oper` leaves: all populated on all 71 interfaces;
  `port-error-reason` reads `port-err-none` everywhere (no err-disabled port
  existed to compare); host-port speed stable across three reads; `ipv4`
  reads `0.0.0.0` on unaddressed ports (now None); the lab served wrapped
  `num-flaps` (>= 2^63) on not-present ports and two SVIs (now named in
  context, never counted).
- Config text: `sdm prefer` does not print in the config (`show sdm prefer`
  says Access); the config header's `by <user>` reaches the trace already
  masked.
- Stability (two harvests minutes apart, and two full-catalog runs): every
  normalized view identical under its compare mode except
  the four now handled — `boot-time` seconds (an epoch key under a 60 s
  tolerance), the NTP system peer (context), MAC-table dynamic counts
  (capability mode) and a CEF attached-host /32 that appeared between two
  17.15.6 runs five minutes apart (counted in `iosxe_routes_fib` context,
  never keyed); `iosxe_syslog_errors` counts grow (`info_only`).

## PAN-OS — not yet walked

The same layer walk has not been applied to the firewall catalog. Known
without walking: interface error counters are one `show` away and are not
read; session, route, HA, IPsec and policy hit-count views exist (README
catalog). Walk it, fill a table in this shape, and rank its holes by the
same four questions.

## VMware ESXi — not yet walked

Not yet walked. Known without walking: physical-NIC packet and error counters
are unreachable over the vim25 SOAP allowlist by design (the performance
manager is outside the six permitted operations), so L1 evidence on a host
stays at link state, speed/duplex and CDP/LLDP neighbor; VLAN hints, port
groups, vmknics, routes, services, sensors and VM state are captured. Walk it
and rank in this shape.

## BMC (server baseboard management controllers over Redfish; Lenovo XCC walked)

A server's BMC is modelled as an Interface on its host Device and captured in
the host's own snapshot by the vendor-neutral `bmc` family (every entry
`target: "bmc"`; the envelope's `device.bmc` names the interface, the
address, the transport and the vendor). The DMTF resources are the family:
the System, Manager and Chassis ids are resolved per run and recorded in
every check's `context.resolution`, and a vendor OEM read branches on the
vendor the BMC reports, recording `not-present` with that vendor where no
mapping exists. Only Lenovo is mapped. Every row below was walked
against a gen-1 ThinkSystem SE350 on XCC 6.10: a GET-only crawl of its whole
Redfish tree (`tools/redfish_walk.py`, 425 resources) and a live run of the
twelve collectors under their earlier `xcc_*` names (eleven ok, the security
check not-present by its own rule, none failed, 30 GETs), both repeated with
the capture account on a ReadOnly-privilege role with identical results; the
normalizer fixes coded from that walk (the 6.10 spelling of the log sequence
numbers, the DNS placeholders, SNMP enablement from the Lenovo agent, the
account names in log messages) are pinned by tests on hand-built payloads.
The `bmc` family then ran through the capture job on a Nautobot 3.2.5 dev
stack against the same unit: eleven ok and `bmc_security` not-present again,
32 GETs in 33 s, no account or person name in raw or the debug trace. Widened
per `docs/plans/bmc-capture-handoff.md` §5a (PR B), all twelve are ok there
(48 GETs in 49 s; the shakedown 12/12 ok in 80 GETs, the log's sequence
numbers unchanged across it). *Captured today* is what the checks carry now;
the new checks of §5b are holes until they land.

| Layer | Captured today | Holes remaining | General value of closing each hole |
| --- | --- | --- | --- |
| Identity / platform | `bmc_system` (system identity — manufacturer, model, serial, SKU, part number, UUID, asset tag, host name, BIOS version — CPU and memory summaries with health, power state, health and rollup, Lenovo `system_status` verbatim; the TPM modules as keys (count, interface types, firmware); the BMC's own firmware, model, UUID, health, state and console services; reboot count, power-on hours, the BMC clock, boot progress and last reset times in context), `bmc_inventory` (every DIMM with ranks, widths, allowed speeds, module type and the Lenovo FRU number, manufacture date and predictive-failure health — empty slots keyed `Absent` with null identity; every CPU with its CPUID signature, microcode (null on XCC 6.10), maximum speed, TDP and turbo state; every PCIe device, and every PCIe function as a `pciefn\|<device>\|<function>` row with class, vendor/device/subsystem ids and state, which is what names the parts whose device row serves null identity; POST-populated, so an empty collection — or a listed device whose function collection answers empty — is a failed read), `bmc_chassis` (tier 1: chassis and system-board identity, the Lenovo LEDs as `led\|<Name>` rows with colour and state, the indicator LED, the operator-maintained Location record with empty fields read null, and the DMTF intrusion sensor — null on the SE350, which serves no `PhysicalSecurity`), `bmc_pcie_slots` (the DMTF slot table — one slot on the SE350, `PCIe 6`, holding the add-in NIC; its type, generation and lanes are unserved on XCC 6.10 — with state, health, hot-plug and the devices each slot holds, the join to `bmc_inventory`; Lenovo's slot table — five M.2 sockets and the x16 — with connector layout and data width; POST-populated, so an empty table is a failed read) | (a) Whether SR-IOV virtual-function rows follow the host OS's VF enablement (a capture of a host with VFs enabled settles it). (b) Whether XCC 6.10 keeps listing an emptied slot as `Absent` or drops it (a card pull settles it). | (a) Settled by one capture, not a check. (b) Settled by the host-off / card-pull shakedown (plan §7 item 4), not a check. |
| Firmware & persistence | `bmc_firmware` (every firmware-inventory member — both BMC banks, UEFI, the provisioning manager and its drivers, adapter option ROMs, drives — with version, software id, updateable flag and health, a version on a `-Pending` member being a staged update; `SoftwareInventory` where linked; the image the BMC runs from and Lenovo's backup auto-promotion), `bmc_bios` (every UEFI attribute keyed — 126 on the lab unit — plus `pending\|<Attribute>` for a setting armed for the next reset that differs from the current one, reset-to-defaults pending, and the UEFI admin / power-on password-set flags), `bmc_system` (boot override enabled/target/mode, the SecureBoot trio, the DMTF power-restore policy, power-on/off/cycle delays, power mode and host watchdog — the DMTF policy leaves are unserved on XCC 6.10 and read null there), `bmc_boot` (the boot path: the DMTF order, override, BootNext, retry, fault and TPM policy and HTTP boot URI — on XCC 6.10 only the override and the retry configuration are served; UEFI boot options where linked; on Lenovo the boot manager's current and next orders per member, kept in order, where XCC 6.10 keeps the order; the virtual media slots with any inserted image; the Lenovo remote-control images; a UEFI-populated collection that answers empty is a failed read), `bmc_licenses` (the licence service and Lenovo's tier — Tier1 on the lab unit — every installed licence and every Lenovo feature-on-demand key as rows, both empty on the lab unit, the healthy empty view; licence strings, key bytes and entitlement ids never stored; install dates, remaining time and use counts in context), `bmc_power_policy` (the AC power-restore policy — DMTF and Lenovo, neither served on XCC 6.10, so null there — the Lenovo Wake-on-LAN, power-permission and local-power flags, the host watchdog, the power cap and the Lenovo capping and redundancy settings, the chassis controls — one power-limit control on the lab unit — the Lenovo scheduled power actions and watchdogs as rows; control readings, expired flags and the JobService twins of the scheduled actions in context) | (a) The AC power-restore policy itself: not served over Redfish on XCC 6.10 (plan §12). (b) Whether XCC mirrors each feature-on-demand key as a DMTF licence (both collections are empty on the lab unit). (c) Lenovo remote-map (network share) images: the service is not linked on XCC 6.10, so `bmc_boot` does not read it. | (a) Settled by a firmware that serves it, or read from the UEFI settings if one names it; not a check. (b) Settled by one capture of a unit with a key installed; not a check. (c) Settled by a firmware that links it; one GET. |
| Environment | `bmc_thermal` (temperature sensors and fans — from `Thermal`, else from `ThermalSubsystem/Fans` keyed the same way: health, state and physical context; a reading keyed only for ambient/intake/inlet/exhaust-class sensors, within 8 °C, and for fans banded at 25 %; every other reading, every threshold, the DTS-style margins and the `ThermalMetrics` temperature summary in context), `bmc_power` (supplies from `Power`, else from `PowerSubsystem/PowerSupplies` with their metrics and `LineInputStatus`; redundancy groups and voltage rails with an in-threshold flag; consumption in context — on the SE350 only the four rails, because its external power adapters are not modelled as supplies), `bmc_sensors` (every member of the Chassis Sensors collection — 89 on the lab unit, 12 numeric and 77 discrete by the `ReadingUnits` rule — keyed by name with reading type, physical context, state, health, units and thresholds; a discrete sensor's reading as an asserted flag, utilisation-class and DTS-style margin readings to context; ambient-class temperatures within 8 °C; the only Redfish view of the SE350's external power adapters, lockdown and chassis-intrusion/movement state, drive, DIMM and M.2 presence and the TPM, Secure Boot and firmware error latches; `EnvironmentMetrics` and the `ThermalMetrics` summary in context; one `$expand` GET, a member walk the budget cannot fit refused) | (a) How an asserted discrete sensor reads (1, a health change, or both) and whether discrete sensors such as the IPMI watchdog, SMM mode, boot progress or TPM lock move between healthy captures. | (a) Settled by a capture with an adapter unplugged and by the stability pair (plan §7 items 4–5); not a check. |
| L1 | `bmc_host_nics` (host ports as the BMC sees them: link status verbatim, burned-in MAC lower-cased so it joins to `vmware_pnics`, enabled, health; the USB host interface excluded; speed and the collection that carried the ports in context). On the lab unit every onboard port reads `NoLink` with the host up: the host runs on an add-in NIC the BMC has no sideband to. `bmc_network_adapters` (every adapter of the Chassis with its identity, controller firmware — the only adapter-level firmware string beside `bmc_firmware`'s rows — port and function counts, NPAR and LLDP; every port with link status, configured maximum and capable speeds, autonegotiation, flow control and LLDP, from `Ports`, the older `NetworkPorts` spelling in context; every device function with its burned-in MAC — equal to `bmc_host_nics`' MACs on the lab unit — SR-IOV, boot mode, assigned port and its joins to `bmc_host_nics` and `bmc_inventory`; the add-in NIC the BMC has no sideband to keyed with zero rows; iSCSI CHAP credentials scrubbed family-wide; POST-populated, so an empty or contradicted collection is a failed read). | (a) Whether a port's link state follows its cable with the host off. | (a) Settled by one capture with the host off and a cable pulled, not a check. |
| Storage | `bmc_storage` (controllers — from `StorageControllers[]` or the `Controllers` collection, whichever is filled — with cache size, supported RAID levels, the Lenovo mode and battery status; drives with serial, model, revision, capacity, media type, protocol, health, state, predicted failure, encryption ability and status, location, negotiated speed, rotation, block size, hot-spare type, write cache and Lenovo drive status; volumes with RAID type, encryption, member drives, cache, strip and boot policies and the Lenovo RAID level, access and IO policies; drives only the Chassis lists; predicted media life and drive temperatures in context). Non-RAID M.2 SATA drives enumerate one Storage member per slot with one AHCI controller. | (a) Verification on a RAID unit: every RAID-depth field is coded from the DMTF and Lenovo schemas and hand-built fixtures — the lab unit's M.2 slots serve none of them. | (a) Consumed by disk, RAID and controller-firmware changes on RAID units; settled by one capture of such a unit, not a check. |
| Management-plane config | `bmc_manager_network` (host name and FQDN; NTP enablement and servers and the Lenovo date-time service — method, servers, UTC offset, DST, sync interval; the DMTF protocol blocks (HTTP, HTTPS, SSH, IPMI, SNMP — the Lenovo SNMPv3 agent answers where the DMTF block does not — VirtualMedia, KVMIP, SSDP, Telnet) and the Lenovo ones (CIM over HTTPS, SLP, SFTP, web over HTTPS), the open-ports list, the SNMPv3 agent and trap enablement, KCS; the management port's addressing, DHCP, DNS servers with the unset placeholders dropped, the Lenovo NIC mode, failover mode, domain and DNS settings (enablement, preferred family, configured servers, dynamic DNS, management-server discovery), IPv6, MTU, VLAN; the Redfish host interface with its credential bootstrapping — enabled with an Administrator role on the lab unit — and the BMC's own address on that USB LAN; link state and the host's OS address as the BMC sees it in context), `bmc_system` (the BMC's address, origin, mask, gateway, VLAN and MAC), `bmc_certificates` (every certificate CertificateLocations lists — on the lab unit the one self-signed HTTPS certificate — with type, subject and issuer names, validity in UTC, key usage and the self-signed flag; PEM bodies never stored, a user certificate's holder names and any certificate e-mail scrubbed; serial, fingerprint where served and days to expiry in context) | (a) The services the plan's `bmc_manager_services` listed that no check keys yet: remote control and remote map, server profile, USB port forwarding and its maps, the serial interfaces, the SNMP agent's contact and location, configuration backup status — whether they become a check of their own is open. (b) Whether XCC 6.10's CertificateLocations lists the LDAP, key-manager, single-sign-on and virtual-media trust certificates once they are configured (all empty on the lab unit). | (a) Consumed by hardening, firmware and BMC-network changes; not derivable; configuration, so stable; 4–6 GETs. (b) Settled by one capture of a unit with a trust certificate installed; if they are not listed, a read of each collection would have to be added. |
| Security posture | `bmc_security` (every leaf of the vendor security resource keyed by dotted path — TLS mode and minimum level, HTTPS/LDAPS/CIM enablement, firmware rollback, encapsulation mode and allowlist, supported actions on XCC 6.10 — the external key manager's configuration with its certificate collections counted, and the ThinkEdge Security Pack state as nullable scalars; not-present only without a security resource or a vendor mapping), `bmc_system` (the SecureBoot trio, TPM modules), `bmc_manager_network` (which protocols are on, credential bootstrapping), `bmc_accounts` (local accounts keyed by name on the `iosxe_config` local-user precedent — role, enabled, locked, account types, SNMP protocols, bootstrap flag, SSH key count; three accounts and nine empty slots on the lab unit — the roles with their privileges, the password and lockout policy, and every directory provider — LDAP, Active Directory, TACACS+, OAuth2, Lenovo's LDAP client — with its bind identity scrubbed; logged-in users a count only), and the lockdown and chassis-movement state that the SE350's security resource does not carry, from its discrete sensors (`bmc_sensors`) | (a) Whether the lockout durations XCC 6.10 serves (60 and 60) are seconds, as the DMTF schema says, or minutes, as Lenovo's interface speaks of them. | (a) Settled by reading the configured value in the XCC web interface once; not a check. |
| Alerting | `bmc_alerting` (the event service's state and retry policy and its SMTP relay; every Redfish subscription with its destination — userinfo, query and fragment never kept — filters, retry policy and state, the subscriber's Context a set/unset flag; the Lenovo alert recipients with their event classes; SNMP traps and targets with communities never keyed; the Lenovo SMTP client; e-mail addresses by domain only, recipient names never kept. On the lab unit subscriptions, recipients and trap targets are empty — the healthy empty view — and the SMTP relay is unconfigured.) | (a) A configured unit: every subscription and recipient row is coded from the schemas and pinned on hand-built payloads only. | (a) Settled by one capture of a unit with a subscription or recipient configured; not a check. |
| Logs | `bmc_event_log` (the platform log — `PlatformLog`, else `StandardLog`, which on XCC 6.10 interleaves platform and audit events — read whole with no query window: Warning/Critical entries keyed `sel\|<code>\|<Id>` with serviceable flag and who services it (Lenovo or the customer), failing FRU and log type, the rest counted per event code; every unresolved `ActiveLog` condition keyed `active\|<code>\|<Id>` whatever its severity, empty when healthy; the `MaintenanceLog` — firmware-update, configuration and hardware add/remove history — as newest rows in raw with counts and the newest time in context; the platform and audit sequence numbers from the log service resource, SEL wrapping and the SEL service as a probe; every account name a message carries scrubbed before the trace or raw keep a copy, client addresses kept) | (a) Whether `ActiveLog` entry ids are stable per condition (the lab unit's ActiveLog is empty). (b) Whether `SEL` ever exposes entries. | (a) Settled by raising and clearing one condition on the lab unit; if ids renumber, the key moves to the condition's own time. (b) Settled by a capture, not a check. |
| Tasks | Nothing. | (a) `bmc_tasks` (tier 3): non-terminal tasks and jobs — a firmware update or configuration restore still running at capture time — with terminal ones counted. On the lab unit `Tasks` is empty and `Jobs` holds the three scheduled power actions. | (a) Consumed by any change with a firmware or configuration step (quiescence evidence, the `vmware_recent_tasks` twin); not derivable; stable except while something runs; 4 GETs. |

### BMC open items, ranked by general value

1. ~~`bmc_sensors`~~ — landed (PR C).
2. ~~Boot order and virtual media (`bmc_boot`)~~ — landed (PR C).
3. ~~`bmc_power_policy`~~ — landed (PR C); the AC-restore leaf itself is unserved on XCC 6.10.
4. ~~`bmc_accounts` and `bmc_certificates`~~ — landed (PR C).
5. ~~Hardware depth: `bmc_pcie_slots`, `bmc_network_adapters`~~ — landed (PR C).
6. **The remaining manager services** (an open question: a `bmc_manager_services` check of its own; `bmc_alerting` landed in PR C). BMC-network, hardening and management-tool changes.
7. **`bmc_tasks`** — real, but empty of running work on the lab unit (`bmc_licenses` landed in PR C).
8. **Verification on units that have what the lab lacks**: RAID depth in `bmc_storage`, a populated `ActiveLog`, SR-IOV virtual functions, a ThinkEdge security resource, a firmware that serves only the Subsystem resources.

**Closed by doctrine or not observable here:** AuditLog entries (never read,
by doctrine: the capture's own logins would land there; audit sequence
numbers come from the log service resource, never from its entries — on XCC
6.10 the audit events share the StandardLog, where `bmc_event_log` counts
them by code with account names scrubbed); host-OS facts the BMC does not see
(the booted OS's configuration, VMs and services are the host platform's job
— `vmware_*` on ESXi; a host whose platform is not supported yet gets its BMC
captured alone, and `device.host_captured` says so); power-feed circuit
diversity (whether two feeds sit on separate circuits is a facility record,
as on IOS-XE); diagnostic dumps (FFDC, screenshots), which are not state; and
`SessionService`, which the path fence refuses.

**Held by decision:** telemetry metric values (`TelemetryService` reports and
the Lenovo history containers are volatile and bulky; only the report
definitions are a candidate, `bmc_telemetry`, deferred).

### What the BMC lab walk settled

From the walk of the gen-1 SE350 on XCC 6.10; the BMC plan's §4 and §12
hold the detail.

- Resolution and paging: one System, Manager and Chassis, each with member
  id `1`; the service root names the vendor but no product;
  `$expand=.($levels=1)` inlines a collection's members, while `$levels=2`
  inlines a member's own sub-collection resources with their members still
  bare links (adapter ports and functions, PCIe functions), so those take
  one `$expand` GET each.
- Access: all 425 resources answered HTTP 200 to the capture account, on a
  Supervisor-privilege role and again on a ReadOnly-privilege one, with
  identical trees, leaves and collector results. The one first-attempt
  failure was the account's pending first-login password change (an error
  body carrying `PasswordChangeRequired`), which the probe hint now names.
- Footprint: 779 Basic-auth GETs, and the collector runs after them, wrote no
  entry to any BMC log and created no session; the shakedown job measured it
  again (its platform and audit sequence numbers read the same before and
  after its own run) and does so on any other firmware
  (`log_sequence_before` / `log_sequence_after`), while the pacing stays as
  prudence. Typical answers take 100–250 ms; the 89-member Sensors `$expand`
  about 11 s for 55 KB; the twelve collectors 30 GETs in about 30 s.
- Environment: legacy `Thermal`/`Power` are served beside `ThermalSubsystem`,
  `ThermalMetrics`, `EnvironmentMetrics` and `Sensors` (21 numeric, 68
  discrete); no power supply is modelled anywhere — the external adapters
  exist only as presence sensors — and `ReadingType` cannot classify a
  sensor (watts typed `Current`, presence typed `Power`).
- Security: the security resource carries no ThinkEdge property on a gen-1
  SE350; lockdown and chassis movement are discrete sensors, and there is no
  `PhysicalSecurity`.
- Logs: six log services and no `PlatformLog`; `StandardLog` interleaves
  platform and audit events (an OEM log type tells them apart), spells its
  sequence numbers `PlatformFirstSeqNum` / `AuditLastSeqNum` and so on, and
  names accounts and client addresses in its login, logoff and
  password-change messages; `ActiveLog` is empty; `SEL` has no `Entries`
  link.
- Firmware, BIOS, boot and power policy: fifteen firmware members, with
  `-Pending` twins (version null while nothing is staged) and a standby BMC
  bank, and no `SoftwareInventory`; 126 BIOS attributes, the pending set a
  separate settings resource; the boot order only in the Lenovo boot manager
  (no DMTF `BootOrder`, no `BootOptions`); the DMTF and Lenovo
  power-restore-policy leaves both absent.
- Host side: non-RAID M.2 SATA drives enumerate one `Storage` member per
  slot (no `Controllers`, empty `Volumes`); with the host booted every
  onboard port reads `NoLink`, because the OS runs on a slot NIC the BMC has
  no sideband to (that adapter lists no ports or functions); unset DNS slots
  are served as `::` / `0.0.0.0` placeholders, and the DMTF SNMP block
  carries no `ProtocolEnabled` (the Lenovo SNMPv3 agent block does).

Still open, for the next shakedowns rather than a check: whether port link
state follows a cable with the host off; how an asserted discrete sensor
reads; where, if anywhere, this firmware exposes the AC power-restore
policy; what a de-powered adapter does to its sensors; whether `SEL` ever
lists entries; how the `-Pending` firmware members read while an update is
staged; and the populated shapes of subscriptions, recipients, licences,
tasks and `PhysicalSecurity`.

## Console servers — not yet a platform

An out-of-band console server is a device class of its own, not a hole in
any existing bundle; its value scales with the number of sites that have one,
independently of any change. When one is added, it is one new
`jobs/checks_<platform>.py` module, a GET-only transport under the same
read-only guarantee, and a section here.
