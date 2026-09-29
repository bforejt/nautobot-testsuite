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

| Layer | Captured today | Holes remaining | General value of closing each hole |
| --- | --- | --- | --- |
| L1 / physical | `iosxe_interfaces` (admin/oper, the auto-negotiation flag, negotiated speed and duplex while up and mGig downshift — as keys on trunks and routed ports, in context `access_link` for the ports the VLAN database lists as access ports, `link_scope` naming which; CRC, in-error and flap counters in context), `iosxe_optics` (DOM light levels, optic-raised alarms), `iosxe_inventory` (transceiver identity), `iosxe_switch_stack` (stack ring ports), `iosxe_svl_health` (SVL link bundling), `iosxe_neighbors` (CDP-reported duplex), `iosxe_poe` (port power state) | (a) Counter **deltas** are not evaluated: CRC/error/flap counts sit in context, so a port that took errors between captures is found by the analyst reading two contexts, not by a compare mode (`diffcore` reserves an `activity` mode, unwired). (b) UDLD state: no oper model; `show udld` only. (c) Cable diagnostics need an active `test` command — outside the read-only allowlist by doctrine, permanently. | (a) Consumed by every change that touches a cable or an optic; derivable today from two contexts; stable by construction (a delta, not a level); cost is a compare mode, no new request. (b) Consumed by fiber and uplink changes; not derivable; stable; one `show` parse. (c) Not closable. |
| L2 topology | `iosxe_stp` (mode, guards, per-instance root facts, every port that is neither designated-forwarding nor disabled/link-down; topology-change counters and the disabled count in context), `iosxe_trunks` (allowed/active sets, native VLAN; the forwarding set as a key where VTP pruning is off, in context where it is on, `vtp_pruning` naming which), `iosxe_vlans` (VLAN database, VTP, per-port VLAN maps in context), `iosxe_port_channels` (bundles and member flags), `iosxe_neighbors` (CDP/LLDP, CDP native VLAN), `iosxe_svl_health` | (a) LACP partner identity per member (which far-end system and port each member bundled with) is not read; the member flags are. (b) Per-port VLAN membership is context, not keys, because nothing in the VLAN model marks a port as session-controlled (an 802.1X port moves VLAN with its endpoint's session). (c) A CDP native-VLAN mismatch is derivable but not flagged. | (a) Consumed by any re-cabling or uplink change; not derivable; stable; one GET (`lacp-oper`) or one `show`. (b) Consumed by access-edge changes; derivable from context for static ports once the field capture shows which ports the model lists; stability is the open question. (c) Derivable in analysis by joining `iosxe_neighbors` native_vlan against `iosxe_trunks` native_vlan; a context flag would cost nothing. |
| L2 forwarding | `iosxe_mac_table` (dynamic MAC counts per VLAN/member/port as capability; rows in raw), `iosxe_arp` (all VRFs), `iosxe_errdisable` (err-disabled ports with the model's reason), `iosxe_interfaces` (storm-control blocking) | (a) **Plan rec. 6, `iosxe_access_sessions`**: 802.1X/MAB session outcomes (authorized, method, domain, landed VLAN) — the gap between "RADIUS alive" and "endpoints on". (b) Port-security secure MACs (`psecure-oper`). (c) DHCP-snooping and device-tracking bindings: no oper model exists; `show` only. | (a) Consumed by every access-edge change and every RADIUS/AAA change; partly derivable from MAC-table capability (learned, not authorized); capability mode keeps it stable; one filtered GET, with the username hygiene rule (no unfiltered retry). Highest-value open L2 item. (b) Consumed by access-edge changes on port-security sites; not derivable; stable; one GET. (c) Consumed by the same changes; not derivable; volatile (leases age); `show` parse to context. |
| L3 / control plane | `iosxe_routes_rib`, `iosxe_routes_fib`, `iosxe_route_rollups`, `iosxe_bgp_peers`, `iosxe_ospf_neighbors`, `iosxe_arp`, `iosxe_routing_config`, `iosxe_interfaces` (IPv4/mask, VRF, IPv6, MTU, ACLs, QoS policies) | (a) **Plan rec. 9, `iosxe_fhrp`**: HSRP/VRRP roles, VIPs and priorities. (b) EIGRP and IS-IS adjacencies (models exist). (c) IPv6 neighbor table (the ARP twin). (d) Multicast state (IGMP snooping, PIM neighbors). | (a) Consumed by any distribution-layer or gateway change; not derivable (an SVI reads up on both routers); stable except the transition counters, which go to context; two `ok_404` GETs. (b) Consumed at sites that run them; not derivable; stable; one GET each. (c) Consumed by IPv6 rollouts; derivable from nothing captured; churns like ARP (tier 2 full-table). (d) Consumed by multicast changes only; ranks low until a site runs it. |
| Platform / identity | `iosxe_platform_health` (boot time, last reload reason, alarms, sensor states as keys, the P0/P1 supply-slot family included; readings in context), `iosxe_inventory` (model/serial/hardware-version per chassis, module, PSU, fan, transceiver, keyed by name, else serial, else part number), `iosxe_switch_stack` (roster, ring), `iosxe_svl_health`, `iosxe_crash_files` (recency-windowed), `iosxe_poe` (StackPower mode, topology, supplies, installed watts) | (a) **Plan rec. 1, `iosxe_persistence`**: is the running config saved, and is the installed image committed (`unsaved-config`, `install-oper` state, abort timer). (b) SSO readiness per member (`sso-ready-flag` is fetched and kept raw-only). (c) License level and SDM template in effect (both take effect at the next reload). (d) The q-filesystem core-file source of `iosxe_crash_files` is a YANG best guess pending a shakedown. (e) **Power-feed diversity is not observable from the device**: supply input presence is (the P0/P1 sensor states); whether two supplies sit on separate circuits is a facility record, not device state. Closed as unobservable; keep it in the source of record for facilities. (f) TCAM and control-plane resource utilization (context only, if ever). | (a) Consumed by every change (a post capture with an unsaved config dies at the next reload; a pre capture with one means the operator's save persists someone else's edits); not derivable — the config-text diff names the unsaved lines but not whether any exist as a flag; stable; zero new requests for the flag (cached GET), one filtered GET for install state. Highest-value open item overall. (b) Consumed by every change on a stack or SVL pair; not derivable; stable; zero new requests. (c) Consumed by upgrades; not derivable; stable; one GET plus one `show`. (d) Settled by one shakedown, not a check. (e) Not closable here. (f) Consumed by scale changes; volatile; context only. |
| Powered devices (phones, APs, cameras) | `iosxe_poe` (per-port admin/oper/class; budgets, allocations and watts drawn in context), `iosxe_neighbors` (CDP identity — device-id and capability string — the platform string and the voice VLAN of the powered device, all normalized), on a controller the `wlc_*` catalog (AP roster, radios, uplinks, client capability) | (a) Whether per-port PoE oper state is stable across two healthy captures is a field-capture question; if endpoints power-cycle between captures, oper moves to context. (b) A count of powered devices by class and neighbor platform (a capability view like `wlc_clients_summary`) is derivable from the normalized views but not emitted. (c) 802.1X outcomes for phones (rec. 6, above). | (a) Settled by two captures an hour apart, not a check. (b) Consumed by any access-edge or PoE-budget change; derivable by joining `iosxe_poe` and `iosxe_neighbors`; capability mode is stable; zero new requests. (c) See L2 forwarding. |
| Configuration | `iosxe_config` (running and startup text as redacted line lists, hunk-level diff, whether they match), `iosxe_routing_config`, `iosxe_dhcp`, `iosxe_interfaces` (effective per-port config leaves), `iosxe_vlans` (the VTP-held VLAN database, which never reaches the text); `iosxe_config` context `last_change_at`/`last_change_by`, `nvram_updated_at`/`nvram_updated_by` and `no_change_since_restart`, the header facts lifted from the text (the `*_by` values name a user, so they are context and never keys) | (a) Secret rotation is invisible behind constant redaction: a changed RADIUS/TACACS+ key, SNMP community or routing-protocol key diffs to nothing (its effect may show in `iosxe_aaa_servers`). (b) Defaults changed by an upgrade leave no line. (c) RADIUS-applied per-session policy (dynamic VLANs, downloadable ACLs, interface templates) is not config text (rec. 6 counts the landed VLANs). (d) **§10 defect**: `iosxe_dhcp` also returns the DHCP-snooping globals but its SEMANTICS and not-present message describe server/relay config only. | (a) Consumed by every credential rotation; not derivable; a digest keyed with a deployment secret would be stable and leak nothing; cost is a design decision (an unkeyed hash of a type-7 string is reversible). (b) Consumed by upgrades; not derivable; not closable in general — the state checks are the answer. (c) See rec. 6. (d) A SEMANTICS fix, zero cost. |
| Services (time, AAA, DHCP, logging) | `iosxe_ntp` (sync scalars), `iosxe_aaa_servers` (RADIUS server liveness per group/server; counters in context), `iosxe_dhcp`, `iosxe_syslog_errors` (severity 0–3 counts) | (a) **§10 defect**: `iosxe_ntp` reads sync and refid leaf names the NTP model does not define, so loss of sync shows only by accident (stratum 16, a `str()` of the refid container). (b) **Plan rec. 8**: severity-4/5 events from a curated facility allowlist (err-disables, FHRP changes, MAC flaps, PoE denials, 802.1X failures, duplicate addresses) are never counted; they reach raw only while inside the last 20,000 characters. (c) **§10 defect**: the raw `show logging` tail and the debug trace leave the device unscrubbed; log lines can name users and, with command logging on, typed secrets. (d) TACACS+ server liveness (RADIUS only today). (e) SNMP, EEM and call-home have no oper model. | (a) A fix against the model, zero new requests, one field capture to confirm the filled leaves. High value: timestamps in every other capture depend on it. (b) Consumed by every change (transients that heal before the post capture leave no state); not derivable — the state checks are blind to what healed; `info_only` counts are stable enough; zero new commands. (c) Hygiene, not coverage: a scrub pass over the same text the config-text check already redacts; zero new requests. (d) Consumed by AAA changes on TACACS+ sites; one GET if the model serves it. (e) Not closable YANG-first. |
| Reachability | Nothing active. Passive evidence only: OSPF/BGP adjacency states, ARP and MAC learning, NTP sync, RADIUS liveness, and interface counters in two captures' contexts. | **Held by decision.** An allow-listed, derived-target `ping` (targets read from the device's own tables — next-hops, configured servers — never from job input) would be the one active probe in the catalog. The passive alternative is counter deltas between captures (L1 row, hole a). | Consumed by every change; partly derivable from counter deltas and adjacency states; an active probe changes the transport doctrine (`test`/`ping` are banned because on some platforms they initiate state), so the decision is doctrinal, not a ranking. Recorded here so it is not re-litigated per change. |
| Self-description | Every check's SEMANTICS in the envelope; context notes recording which leaves a release served (`leaves_seen`, `fields_filter`, `source`, `port_source`, `ports_listed`/`lists_agree`), raw notes on every unfiltered retry after an HTTP 400; hardware revisions in `iosxe_inventory` (VID) and `iosxe_switch_stack` (`hw_version`, the H/W column of `show switch`); the shakedown's `discovery` (yang-library module inventory, `key_models` merged from every catalog module, RIB/FIB naming, q-filesystem shape). | (a) The yang-library module inventory is read only by the shakedown, so a capture pair spanning an upgrade does not itself say which served models changed. (b) **The IOS-XE release is raw-only today**: no check normalizes or contexts `software-version`; it exists in a switch capture only inside the cached `_HW_PATH` payload (where the device fills `device-system-data/software-version`) and as the major-only `version 17.x` line of the config text. An upgrade is therefore not a normalized or context fact in either snapshot. | (a) Consumed by upgrades and by any analysis of a "parsed but empty" check; not derivable from a capture; stable; one small filtered GET into context. (b) Consumed by every upgrade and by any analysis of a "parsed but empty" check; not derivable (the inventory versions are hardware revisions); stable between upgrades; zero new requests, since `_HW_PATH` is cached — plan rec. 1's `device` -> `software_version`, part of open item 1. |

### Open items, ranked by general value

1. **Plan rec. 1 — `iosxe_persistence`** (saved config, the IOS-XE release as `device` -> `software_version`, install commit state, abort timer). Every change and every upgrade; zero to one new request (the release rides the cached `_HW_PATH` GET); stable.
2. **Plan rec. 8 — widen `iosxe_syslog_errors`** to curated severity-4/5 facilities, tags and timestamps only. Every change; zero new commands; the only record of transients that healed.
3. **§10 — `iosxe_ntp` leaf names** against the NTP model (the check's tests use invented names). A fix; every other capture's timestamps depend on it.
4. **§10 — scrub the raw `show logging` text** with the config-text redaction (usernames, logged commands). Hygiene; zero new requests.
5. **Plan rec. 6 — `iosxe_access_sessions`** (802.1X/MAB outcomes as capability buckets; filtered GET only, no unfiltered retry, never `username`). Access-edge and AAA changes; the one end-to-end "endpoints got on" signal on 802.1X sites.
6. **Counter deltas as a compare mode** (`activity`, reserved in `diffcore`): CRC/error/flap counters already in context. Cable and optic changes; no new request.
7. **Plan rec. 9 — `iosxe_fhrp`**. Distribution and gateway changes; two `ok_404` GETs; not-present is the norm on an access stack.
8. **SSO readiness** promoted from raw into `iosxe_switch_stack` keys. Stack and SVL changes; zero new requests; one field capture (the standby's flag) decides the reading.
9. **yang-library inventory into the capture** (context). Upgrades; one small GET.
10. **LACP partner identity** per bundle member. Re-cabling and uplink changes; one GET or one `show`.
11. **The `iosxe_dhcp` SEMANTICS fix** for the snooping globals. Zero requests. (The config header "changed by / saved by" facts are already `iosxe_config` context; see the Configuration row.)
12. **License level and SDM template**; **EIGRP/IS-IS**; **port-security MACs**; **IPv6 neighbors**; **UDLD**; **TACACS+ liveness** — real, site-dependent, each one request.

**Landed on this branch** (plan recs. 2, 3, 4, 5, 7 and 10, plus the
§10 VRF defect): `iosxe_vlans`, `iosxe_trunks`, `iosxe_stp`, `iosxe_poe`,
`iosxe_mac_table`, `iosxe_inventory`; `iosxe_interfaces` widened to the
negotiated and effective-config leaves (VRF and the auto-negotiation flag now
normalized; the negotiated values of VLAN-database access ports in context),
`iosxe_errdisable` read from the interfaces model with the CLI as fallback,
`iosxe_neighbors` with the CDP platform, native/voice VLAN and duplex,
`iosxe_platform_health` with sensor readings in context and the supply-slot
sensor family named in SEMANTICS. Where the plan left a stability question to
the field capture (host-port renegotiation, pruned trunks, link-down STP rows)
the collectors code both outcomes and record in context which one the device
gave (`link_scope`, `vtp_pruning`, `disabled_ports_listed`).

**Closed as not observable or not closable:** power-feed circuit diversity
(a facility record); cable diagnostics and any other active `test`; defaults
that an upgrade changes silently (the state checks are the answer);
SNMP/EEM/call-home state (no oper model).

**Held by decision:** the reachability probe (see the row above).

### Field-capture questions the first shakedown of this branch settles

Each is recorded by the check itself in context or raw, so the first capture
answers it without a probe. When an answer contradicts an assumption, fix the
normalizer and harvest the caveat here.

- Whether the widened `interfaces-oper` fields filter is accepted (an HTTP
  400 falls back to one unfiltered GET, noted in raw and context), and
  whether `ether-state`, `intf-ext-state`, `storm-control`, `diffserv-info`
  and `statistics` are populated on access ports (`leaves_seen`).
- Whether the VLAN database's assigned-`ports` list names the access ports
  and only them: `iosxe_interfaces` keys speed, duplex and mGig downshift only
  on ports absent from it and records `link_scope` and `access_ports_listed`;
  if the list also holds trunks, uplink speed moves to context with them and
  the scope rule needs a second marker.
- Whether `port-error-reason` agrees with `show interfaces status
  err-disabled`; the two sources key ports (long vs short name) and spell
  reasons differently, and context names the source used.
- Whether `device-inventory` fills `dev-name` on stacks (keys are
  `<class>|<dev-name>`, else `<class>|sn:<serial>`, else `<class>|pn:<model>`;
  a row with none of the three is counted in context `unidentified`, never
  keyed), and whether fan trays and modules carry serials and versions.
- The exact PSU sensor names and units per release; readings ride in context
  whatever the names are.
- Whether CDP fills `platform-name`, `native-vlan` and `vvid` for switches,
  APs and phones (0 and absent both read None for the VLANs).
- Which of `ports` and `vlan-interfaces` the VLAN model fills, and whether
  trunks, voice members and down ports appear (both lists are inverted into
  context with `ports_listed`, `vlan_interfaces_listed` and `lists_agree`).
- The `show vtp status` layout and how `show interfaces trunk` wraps long
  VLAN lists on the release in use; where VTP pruning is on (`vtp_pruning` in
  context) the forwarding set is context (`forwarding`, `active_not_forwarding`)
  and two captures show whether it moved; with pruning off it stays a key.
- How STP instances are spelled, whether `root-port` resolves to a name, and
  whether link-down ports appear as `stp-disabled` rows (`ports_by_state`,
  `disabled_ports_listed`; such rows are never keys either way).
- Which PoE port list the release fills (`port_source`), what a non-cabled
  StackPower member reports, and whether per-port oper state and the
  per-switch budgets are stable (budgets are context-only regardless).
- The MAC table's payload size, whether its fields filter is accepted, what
  `vlan-id-number` means for non-VLAN table types, and whether `aging-time`
  is populated per table.

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

## Lenovo XCC — switched off

Built and tested, disabled by `constants.XCC_ENABLED` because the BMCs are
unreachable from the capture worker at present. Nothing to iterate until
they are reachable.

## Console servers — not yet a platform

An out-of-band console server is a device class of its own, not a hole in
any existing bundle; its value scales with the number of sites that have one,
independently of any change. When one is added, it is one new
`jobs/checks_<platform>.py` module, a GET-only transport under the same
read-only guarantee, and a section here.
