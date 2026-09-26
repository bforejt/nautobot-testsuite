# Plan: Catalyst 9300 running-config coverage and the gaps worth closing

Status: **analysis only. Nothing here is implemented.** The question is how
much of a Catalyst 9300's running-config (and startup-config) the existing
snapshot structure cannot show, and which of those gaps deserve a check.

Method:

- Every IOS-XE collector and its SEMANTICS was read on `main` at `54b6d3f`.
  All `file:line` citations are against that commit; the parallel crash,
  reboot, stack and config branches will shift them.
- Two representative 9300 running-configs were modelled section by section.
- Every candidate source was checked against the IOS-XE 17.9.1 and 17.12.1
  YANG models (YangModels/yang `vendor/cisco/xe/1791` and
  `vendor/cisco/xe/17121`; model line numbers below are in the 17.9.1
  files) and against what a 9300 implements in each release.

Line counts are modelled, not measured. Anything marked *field capture* is
settled on the 4-member 9300 stack. Today's Test Suite Shakedown answers
some of it from its module inventory and payload trace. The rest needs
read-only requests that no check makes yet; §9 lists them and says how to
issue them.

A bare `:N` refers to the file most recently named in the same table cell or
list. Where no file is named, it means `jobs/checks_iosxe.py`.

## 0. The answer in brief

- **By section.** A 9300 config breaks down into 74 sections and
  interface-line types.
  - 9 are fully represented in a normalized view: 5 as state, 2 as config,
    2 as both.
  - 10 are partly represented, and 2 reach only the raw bundle.
  - **53 (72%) are not represented anywhere** (§4, §5a).
- **By lines**, interface stanzas dominate.
  - A 4-member 48-port access stack carries about 3,060 lines, 80% of them
    interface stanzas. **About 87% of its lines have no representation
    anywhere in the snapshot.** The range is 76–91% as the per-port stanza
    varies from 6 to 18 lines. A further 3% are raw-only, and 9% are fully
    or partly normalized.
  - A distribution 9300 (about 1,320 lines, 47% interfaces) fares better
    because routing is covered. There, 72% of lines are absent, 4.5% are
    raw-only and 24% are fully or partly normalized (§5b).
- **Startup-config.** Nothing reads it. Its one device-side proxy,
  `unsaved-config` in `device-system-data`, is defined in the model and
  fetched by `iosxe_platform_health`, but it is never normalized (§5c).
- **The config-text check** is being added on a parallel branch: running and
  startup text as single objects, secrets redacted, with a line diff. It makes
  every line visible as text, and each gap was re-judged against it (§6).
  - **The text diff is enough (verdict A)** for the management plane and
    for the content of ACLs, QoS, routing policy and SPAN.
  - **The gaps worth closing are operational state** (B), meaning what the
    config produced:
    - the VLAN database and trunk forwarding;
    - spanning tree;
    - PoE and StackPower;
    - 802.1X/MAB outcomes;
    - FHRP roles;
    - negotiated link properties;
    - MAC learning;
    - transients that heal before the post capture;
    - whether the change survives a reload (unsaved config, uncommitted
      install).
  - **Only one structured config view (C) survived the review**, and only
    because it is free: the effective interface settings (mask, IPv6
    addresses, VRF, MTU, attached ACLs and QoS policies) that ride a GET
    `iosxe_interfaces` already makes, and that show what templates and
    defaults actually applied (rec. 7, §6a).
- **Ten recommendations** (§8).
  - They read YANG models first. SSH parsing is used only for trunk
    forwarding (VTP pruning has no model), VTP status and the syslog
    widening.
  - Together they add 8 RESTCONF GETs and 2 SSH commands per capture. The
    two widenings add no request at all.
  - After all ten, about two thirds of an access stack's lines have their
    effect at least partly in a normalized view, up from 9% today. What
    remains is left to the text diff on purpose.
- **Coverage defects found while mapping** (§10, not fixed here):
  - `iosxe_ntp` looks for leaf names that the 17.9.1/17.12.1 model does not
    define;
  - `iosxe_interfaces` fetches `vrf` and then drops it;
  - `iosxe_dhcp` also carries DHCP-snooping config that its SEMANTICS does
    not mention;
  - the syslog check never counts the severity-4/5 events that record most
    access-layer transients;
  - the `show logging` text that raw and debug traces carry can hold
    usernames and, on some configs, typed secrets.

## 1. Scope, doctrine and method

### 1a. What "covered" means

Each section is classified by the best representation any existing check
gives it:

| Class | Meaning |
| --- | --- |
| **config** | the section's own configuration is in a normalized view |
| **state** | the operational state the section produces is in a normalized view |
| **partial** | part of the section's content, or part of the state it produces, is normalized: an address without its mask, for example |
| **raw-only** | the value reaches the raw bundle but no normalized view |
| **none** | neither the lines nor their effect appear anywhere in the snapshot |

Some sections leave a trace only when they fail. A bpduguard trip shows up as
an err-disable reason, while the bpduguard setting and the spanning-tree
state it protects appear nowhere. Such sections are classed **none**, and the
Evidence column names the consequence. §6 weighs that consequence when
judging value.

### 1b. The doctrine every recommendation obeys

- **Capture generally.** Every proposal is always on and records
  `not-present` when the feature is unused. Nothing knows about a particular
  change. SEMANTICS says how to read the keys, never why some change needs
  them.
- **State over structure.** Once the config text is in the snapshot, a
  structured check earns its place only by showing what the text cannot: how
  the network reacted, or what actually runs where the text misleads
  (§6a).
- **Stable normalized views.**
  - Counters, readings, ages and timestamps go to context or raw.
  - A value never changes type between captures.
  - Two healthy captures of an unchanged device diff to nothing.
- **YANG first.**
  - RESTCONF operational models are read with `fields` filters.
  - SSH `show` parsing is used only where no model exists.
  - Code tolerates absent leaves and containers, because a model says what
    is defined, not what a device fills in.
- **Cost.** Every check spends device time and reviewer attention, so breadth
  for its own sake is not a reason to add one.

### 1c. Sources, and a 17.12.1 quirk

- **Code:**
  - `jobs/checks_iosxe.py`;
  - the 9300-relevant part of `jobs/checks_iosxe_wireless.py`
    (`iosxe_aaa_servers` and the controller gate);
  - the SEMANTICS in `jobs/registry.py`;
  - the SSH allowlist in `jobs/transport_ssh.py`.
- **Models, and the 17.12.1 quirk.**
  - 17.9.1 advertises its native models in the NETCONF hello, so
    `capability-cat9300.xml` answers "does a 9300 implement it?".
  - **17.12.1 moved every native model to YANG 1.1**
    (`vendor/cisco/xe/17121/README.md`, "YANG Model Version 1.1").
    YANG 1.1 modules are advertised through `ietf-yang-library`, not the
    hello, so the 17.12.1 `capability-cat9300.xml` lists no `Cisco-IOS-XE-*`
    module at all.
  - For 17.12.1 the platform evidence is therefore `yang-set-cat9300.xml`, a
    `modules-state` reply. §7 records the revision each release implements.
- **Field evidence** comes from the 4-member C9300-48UXM stack.
  - `Cisco-IOS-XE-stack-oper` is served, and its leaf spellings are
    field-verified.
  - `device-inventory` `hw-dev-index` values are not switch numbers; the
    stack branch fixes that join.
  - No other 9300 payload has been captured yet. Which of the §7 models the
    stack actually serves is therefore the first *field capture* question
    (§9).

### 1d. Counting lines

A line is one non-blank line of `show running-config`, not counting the `!`
separators. Each line is attributed to exactly one class. The counts model
typical configs (§3) rather than measure one; the first capture of the
config-text check replaces them (§9).

## 2. What the catalog reads on a 9300 today

| Check | Source (`file:line`) | Normalized keys (`file:line`) | Config it evidences |
| --- | --- | --- | --- |
| `iosxe_interfaces` | GET `Cisco-IOS-XE-interfaces-oper:interfaces?fields=interface(name;description;admin-status;oper-status;vrf;ipv4)` (`checks_iosxe.py:38-41`) | `<name>` → `admin`, `oper`, `ipv4` (`:445-452`); `description` raw-only by design (`:437-438`) | interface existence, `shutdown`, `ip address` (address only) |
| `iosxe_neighbors` | GET `Cisco-IOS-XE-cdp-oper:cdp-neighbor-details` (unfiltered) and `Cisco-IOS-XE-lldp-oper:lldp-entries` (`:42-43`, `:418-428`) | `cdp\|<device-id>\|<local>` → `port`, `caps`; `lldp\|<device-id>\|<local>` → `port` (`:393-397`, `:412-414`) | `cdp`/`lldp`, global and per interface |
| `iosxe_port_channels` | SSH `show etherchannel summary` (`:1352`) | `Po<N>` → `flags`, `protocol`, `members{port: flags}` (`:1325-1346`) | `channel-group` |
| `iosxe_errdisable` | SSH `show interfaces status err-disabled` (`:1313`) | `<interface>` → `reason` (`:1296-1307`) | consequences of bpduguard, UDLD, port-security, storm-control `shutdown`, DHCP/ARP rate limits, link-flap |
| `iosxe_optics` | SSH `show interfaces transceiver detail`, bare form as fallback (`:1102-1104`) | `<interface>` → `tx_dbm`, `rx_dbm`, `*_flag` (`:1061-1091`); `info_only` | none: DOM readings do not depend on the `transceiver type all` / `monitoring` config (P2) |
| `iosxe_platform_health` | GET `Cisco-IOS-XE-device-hardware-oper:device-hardware-data` (`:44`, `:500`) and `environment-sensors` (`:503`) | `boot-time`, `alarm\|<id>\|<instance>`, `env\|<location>/<sensor>` (`:466-496`) | reload detection only; `software-version`, `rommon-version` and, where populated, `unsaved-config` ride in raw (`:504`) |
| `iosxe_switch_stack` | SSH `show switch detail` and `show switch stack-ports summary`; cached `_HW_PATH`; `stack-oper` kept raw-only (`:1593-1667`) | `stack`, `switch\|<n>`, `stack-port\|<n>/<p>` (`:1650-1658`) | `switch N provision`; priority (which is not in running-config) |
| `iosxe_crash_files` | SSH `dir crashinfo:`, `dir stby-crashinfo:`, `dir crashinfo-<N>:` (`:1214`, `:1236-1237`) | `active\|<file>`, `stby\|<file>`, `member<N>\|<file>` (`:1197-1198`) | none (platform health) |
| `iosxe_syslog_errors` | SSH `show logging` (`:717`) | `sev<N>\|%FAC-N-MNEMONIC` → `count`, severities 0–3 only (`:698-711`); `info_only` | the contents of `logging buffered`, not its config |
| `iosxe_ntp` | GET `Cisco-IOS-XE-ntp-oper:ntp-oper-data` (`:887`) | `synchronized`, `stratum`, `server` (`:909-926`); see §10 | `ntp server`, `clock` |
| `iosxe_aaa_servers` | GET `Cisco-IOS-XE-aaa-oper:aaa-data/aaa-radius-stats?fields=…` (`checks_iosxe_wireless.py:1453`, fields `:142-146`) | `radius\|<group>\|<ip>:<auth-port>` → `state`, `instances`, `instances_alive`, `acct_port`, `radsec` (`checks_iosxe_wireless.py:1405-1435`) | `radius server`, `aaa group server radius` |
| `iosxe_dhcp` | GET `Cisco-IOS-XE-native:native/ip/dhcp` (`checks_iosxe.py:664`) | `dhcp-config` → the whole subtree as one value (`:669-670`) | DHCP pools and relay globals, **and the DHCP-snooping globals** (§10) |
| `iosxe_routing_config` | GET `native/ip/route`, `native/ipv6/route`, `native/router` (`:982-986`) | `ip-route`, `ipv6-route`, `router` → one scrubbed blob each (`:994-995`) | static routes, routing-protocol stanzas |
| `iosxe_routes_rib`, `iosxe_route_rollups`, `iosxe_routes_fib` | GET `ietf-routing:routing-state` (`:24`, shared fetch `:195-200`) and `fib-oper` (`:25-29`); SSH `show ip route summary` (`:216`) | `vrf\|prefix` (`:146-154`), per-protocol counts (`:159-166`), `instance\|prefix` (`:254`) | `ip routing`, routes, VRFs (as routing instances) |
| `iosxe_bgp_peers`, `iosxe_ospf_neighbors` | GET `bgp-state-data/neighbors` (`:30`) and `ospf-oper-data?fields=…` (`:31-36`) | `afi\|vrf\|neighbor` (`:278-287`), `instance\|area\|interface\|nbr-id` (`:326-330`) | `router bgp`, `router ospf`, `ip ospf` |
| `iosxe_arp` | GET `arp-oper:arp-data` (`:37`) | `vrf\|address` → `mac`, `interface` (`:365-368`) | SVI addressing, as adjacencies |
| `iosxe_svl_health`, `wlc_*` | — | `not-present` on a 9300. SVL is 9400/9500/9600 only (`:855-859`). The wireless gate costs one cached AP-map GET (`checks_iosxe_wireless.py:339-361`) | — |

Several values are fetched today but never normalized. They cost nothing
more to promote:

- interface `description` and `vrf` (`iosxe_interfaces`);
- CDP `native-vlan`, `duplex`, `vvid`, `platform-name` and `version`, because
  the CDP GET is unfiltered;
- `software-version`, `rommon-version` and, where the device populates it,
  `unsaved-config` (all in the `_HW_PATH` payload);
- per-member `reload-reason` and `sso-ready-flag` in `stack-oper` (in
  `iosxe_switch_stack` raw, `:1640-1646`);
- every severity-4-to-7 line of `show logging`. The regex matches severities
  0–3 only (`:698`), so these lines are never counted; they reach raw only
  while they sit in its last 20,000 characters (`:702`, `:723`).

## 3. Two representative configs

**Access stack.** Four 48-port mGig/UPOE members (the field stack is 4 ×
C9300-48UXM), each with an 8-port 10G network module.

- Layer 2 access with a management SVI.
- IBNS 2.0 802.1X/MAB in closed mode, with a voice VLAN.
- Auto-QoS on phone ports, and PoE for phones and APs.
- Device-tracking, DHCP snooping, storm-control, and portfast/bpduguard.
- A 2-link cross-stack LACP uplink trunk.
- VTP transparent (so VLAN lines are in the text) and rapid-PVST.
- The usual management plane: TACACS+ admin AAA, SNMP, syslog, NTP, banners,
  `line` blocks, PKI, the call-home defaults and archive.

A mid-sized access-port stanza is 12.5 lines on average (the description is
on half the ports):

```
interface TwoGigabitEthernet1/0/1
 description <user port>
 switchport access vlan 10
 switchport mode access
 switchport voice vlan 20
 device-tracking attach-policy <policy>
 source template <802.1X template>
 spanning-tree portfast
 service-policy input <auto-QoS input policy>
 service-policy output <auto-QoS output policy>
 auto qos voip cisco-phone
 storm-control broadcast level 1.00
 storm-control action trap
```

The low case (6 lines) is a plain access port on a stack that runs neither
802.1X nor QoS, so it also drops the 75 lines of IBNS globals and the 120
lines of auto-QoS maps. Its 18 RADIUS lines stay; dropping them too moves
the result by under half a point. The high case (18 lines) spells out the
IBNS 2.0 commands on every port instead of sourcing a template.

**Distribution or collapsed core.** Two 24-port SFP members with 8-port
network modules.

- 16 downlink trunk members, bundled as 8 two-port port-channels to the
  access stacks.
- 4 routed uplinks running OSPF.
- 30 SVIs, each with HSRP and two DHCP helpers.
- OSPF and BGP, static routes, prefix-lists and route-maps.
- About 120 lines of ACLs, plus MQC QoS, IP SLA/track and PIM.
- The same management plane as the access stack, minus 802.1X.

Neither modelled config runs Flexible NetFlow, TrustSec, telemetry
subscriptions or IPv6 addressing. Where a site does, those lines add to the
absent share; their verdicts are in §6.

Section-size assumptions shared by both:

- `snmp-server enable traps` is stored as one line per trap family, several
  dozen on a 9300, so SNMP is about 80 lines.
- Two PKI trustpoints (the self-signed `TP-self-signed-<n>` and Cisco's
  `SLA-TrustPoint`) print their certificate chains as hex, about 80 lines.
- Auto-QoS generates about 120 lines of `AutoQos-*` class, policy and table
  maps.
- Other section sizes are typical values, listed with the arithmetic in §5b.

## 4. Section-by-section coverage

Each interface stanza mixes covered and uncovered lines, so interface stanzas
are split by line type. Section ids (I, G, L, P, M) are referenced in §5–§6.

### 4a. Interface stanzas, by line type

| # | Lines | Coverage | Evidence | Missing |
| --- | --- | --- | --- | --- |
| I1 | `interface …`, `shutdown` / `no shutdown` | state | `iosxe_interfaces` key `<name>` → `admin`, `oper` (`checks_iosxe.py:445-452`) | — |
| I2 | `description` | raw-only | requested by the fields filter (`:40`), deliberately not normalized (`:437-438`) | by design (cosmetic) |
| I3 | `ip address` (SVIs, routed ports, Gi0/0) | partial | `ipv4` (`:451`); while the interface is up, its connected (`direct`) prefix reaches `iosxe_routes_rib` (`:121-156`; the fixture `tests/fixtures/iosxe_rib_routing_state.json` carries such routes) | the mask on the interface itself (`ipv4-subnet-mask` is never requested) and secondary addresses (the model has a single `ipv4` leaf) |
| I4 | `vrf forwarding` | raw-only | `vrf` is requested (`:40`) but not normalized (`:448-452`) | a change of VRF membership |
| I5 | `switchport mode access`, `switchport access vlan`, `switchport voice vlan` | none | — | the effective access and voice VLAN per port |
| I6 | `switchport mode trunk`, `switchport trunk allowed vlan`, `switchport trunk native vlan` | none | the far end's CDP-advertised native VLAN is raw-only (unfiltered `_CDP_PATH`, `:42`, `:419`; the normalizer keeps `port`/`caps`, `:393-397`) | allowed, active and forwarding VLAN sets; native VLAN |
| I7 | `channel-group N mode …` | state | `iosxe_port_channels` `Po<N>` → `flags`, `protocol`, `members` (`:1325-1346`) | LACP partner identity (§6: not worth it) |
| I8 | `spanning-tree portfast` / `bpduguard` / `guard` / `link-type` | none | consequence only: `iosxe_errdisable` reason `bpduguard` (`:1296-1307`) | port role and state, root |
| I9 | `storm-control … level` / `action` | none | consequence only: err-disable when the action is `shutdown`; `%STORM_CONTROL-3-*` is counted by `iosxe_syslog_errors` (`:698`) while it is still in the buffer | the filter state (blocking or forwarding) |
| I10 | `power inline …` | none | — | PoE admin/oper state, class, budget |
| I11 | `authentication`, `access-session`, `mab`, `dot1x pae`, `source template`, `service-policy type control subscriber` | none | server reachability only: `iosxe_aaa_servers` (`checks_iosxe_wireless.py:1405-1471`) | session outcomes |
| I12 | `device-tracking attach-policy`, `ip dhcp snooping trust` / `limit rate`, `ip arp inspection trust` / `limit`, `ip verify source` | none | consequence only: `iosxe_errdisable` reasons `dhcp-rate-limit`, `arp-inspection` (`:1296-1307`) | bindings, drops |
| I13 | `service-policy input` / `output`, `auto qos`, `trust device` | none | — | the attached policy per direction |
| I14 | `ip access-group` | none | — | the attached ACL per direction |
| I15 | `speed`, `duplex`, `mtu`, `negotiation` | none | oper status only | negotiated speed/duplex; the effective MTU, which the global `system mtu` (P2) sets on every port without a per-port line |
| I16 | `udld port …` | none | consequence only: `iosxe_errdisable` reason `udld` (`:1296-1307`) | — |
| I17 | `switchport port-security …` | none | consequence only: `iosxe_errdisable` reason `psecure-violation` (`:1296-1307`) | — |
| I18 | `ip helper-address` (SVIs) | none | `iosxe_dhcp` SEMANTICS says per-interface helpers are not captured (`registry.py:212-217`) | — |
| I19 | `standby …` / `vrrp …` | none | — | FHRP state, active router, virtual IP |
| I20 | `ip ospf …` / `ip pim …` | partial | OSPF adjacency per interface: `iosxe_ospf_neighbors` `instance\|area\|interface\|nbr-id` (`:304-331`) | cost/timers/authentication; PIM entirely |
| I21 | `cdp enable`, `lldp transmit` / `receive` | state | `iosxe_neighbors` `cdp\|…` / `lldp\|…` keys (`:382-428`) | — |
| I22 | `load-interval`, `logging event link-status`, `snmp trap link-status`, `carrier-delay`, `ip flow monitor … input` / `output` (M14) | none | — | telemetry settings |
| I23 | `ipv6 address`, `ipv6 enable`, `ipv6 nd …` (SVIs, routed ports) | partial | connected IPv6 prefixes reach `iosxe_routes_rib`, which reads the v4 and v6 RIBs alike (`:121-156`) | the addresses themselves: `interfaces-oper` `ipv6-addrs` (`Cisco-IOS-XE-interfaces-oper.yang:4782`) is never requested |

### 4b. Layer-2 and access-security globals

| # | Lines | Coverage | Evidence | Missing |
| --- | --- | --- | --- | --- |
| G1 | `vlan N` / `name` | none | — (in VTP server or client mode these lines are not in the running-config at all; the VLAN database lives in `vlan.dat`) | VLAN existence and status |
| G2 | `vtp mode` / `domain` / `version` / `pruning` | none | — | mode, revision, pruning |
| G3 | `spanning-tree mode` / `vlan … priority` / `portfast default` / `bpduguard default` / `loopguard default` | none | — | root per instance, topology changes |
| G4 | `errdisable recovery cause` / `interval` | partial | `iosxe_errdisable` lists ports err-disabled at capture time (`:1310-1318`) | a port that is err-disabled and auto-recovers inside the window reaches raw at best. `%PM-4-ERR_DISABLE` and `%PM-4-ERR_RECOVER` are severity 4, which `iosxe_syslog_errors` never counts (`:694-698`); they survive in its raw only while they sit in the last 20,000 characters (`:702`, `:723`). The link bounce's `%LINK-3-UPDOWN` is counted, but without a port or a reason |
| G5 | `udld enable` / `aggressive` | none | consequence only: `iosxe_errdisable` reason `udld` (`:1296-1307`) | — |
| G6 | `ip dhcp snooping`, `… vlan`, `no … information option` | config | `iosxe_dhcp` `dhcp-config` (`:663-671`). The 17.9.1 `Cisco-IOS-XE-dhcp.yang` augments `ip-dhcp-grouping` (`:777`, which holds `snooping` and `snooping-conf`) into `/native/ip/dhcp` (`:2477-2479`) | binding table, drop counters |
| G7 | `ip arp inspection vlan …` | none | — | — |
| G8 | `device-tracking policy …`, `ipv6 nd raguard policy …`, `ipv6 dhcp guard policy …` | none | no oper model exists (§7) | — |
| G9 | IBNS 2.0: `class-map` / `policy-map type control subscriber`, `service-template`, `template`, `dot1x system-auth-control`, `access-session` globals | none | — | session outcomes |
| G10 | `radius server`, `aaa group server radius` | state | `iosxe_aaa_servers` `radius\|<group>\|<ip>:<auth-port>` → `state`, `instances`, `instances_alive`, `acct_port`, `radsec` (`checks_iosxe_wireless.py:1405-1435`) | — |
| G11 | `radius-server dead-criteria` / `deadtime` / `attribute`, `aaa server radius dynamic-author` (CoA), `ip radius source-interface` | none | — | — |
| G12 | `ip igmp snooping …`, `ipv6 mld snooping` | none | — | — |
| G13 | `mac address-table aging-time` / `notification` / `static` | none | — | MAC learning |
| G14 | `monitor session …` (SPAN/RSPAN) | none | — | — |
| G15 | `lldp run`, `cdp run` | state | `iosxe_neighbors`, which records `not-present` only when neither table is served (`:418-428`) | — |
| G16 | `class-map`, `policy-map`, `table-map` (including auto-QoS maps), `qos queue-softmax-multiplier` | none | — | — |
| G17 | `port-channel load-balance …`, `lacp system-priority` | none | — | the hash in effect |
| G18 | TrustSec: `cts role-based enforcement`, `cts authorization list`, `cts sxp …`, per-port `cts manual` | none | — | environment data from ISE, SXP connections, SGT enforcement |

### 4c. Layer-3 globals (distribution)

| # | Lines | Coverage | Evidence | Missing |
| --- | --- | --- | --- | --- |
| L1 | `ip routing`, `ipv6 unicast-routing`, `ip route`, `ipv6 route` | config + state | `iosxe_routing_config` `ip-route`, `ipv6-route` (`:982-995`); `iosxe_routes_rib` `vrf\|prefix` → protocol, preference, next-hops (`:121-156`); `iosxe_routes_fib` (`:233-255`) | — |
| L2 | `router ospf` / `bgp` / `eigrp …` | config + state | `iosxe_routing_config` `router` (`:985`); `iosxe_ospf_neighbors` (`:304-341`), `iosxe_bgp_peers` (`:268-298`), `iosxe_route_rollups` (`:159-227`) | EIGRP and IS-IS adjacencies (only their RIB effect is seen) |
| L3 | `ip prefix-list`, `route-map`, `ip community-list`, `ip as-path` | none | effects only: the RIB (`:121-156`) and BGP `installed_prefixes` (`:278-287`) | — |
| L4 | `vrf definition` (RD, route targets, address families) | partial | the RIB and FIB are keyed per routing instance (`:134`, `:146`; `:240`, `:254`) | RD/RT and import/export; interface membership is raw-only (I4) |
| L5 | `ip access-list …`, `vlan access-map` / `vlan filter` (VACLs) | none | — | — |
| L6 | `ip sla …`, `track …` | none | effects only: the RIB (`:121-156`) | — |
| L7 | `ip multicast-routing`, `ip pim rp-address` | none | — | — |
| L8 | `ip dhcp pool …`, `ip dhcp excluded-address`, relay globals | config | `iosxe_dhcp` (`:663-671`) | lease and relay state |
| L9 | `key chain …` | none | `iosxe_routing_config` scrubs key values by leaf name (`:959-978`) | — |

### 4d. Platform and stack

| # | Lines | Coverage | Evidence | Missing |
| --- | --- | --- | --- | --- |
| P1 | `version`, `boot system` (install mode, `packages.conf`) | partial | `iosxe_platform_health` `boot-time` proves a reload (`:480-482`); `software-version` and `rommon-version` are only in its raw (`:500-504`). `last-reboot-reason` / `reason-severity` are being added on the reboot branch | the running version (normalized), the install commit state, the auto-abort timer |
| P2 | `service …`, `platform …`, `system mtu`, `memory free low-watermark`, `diagnostic bootup`, `transceiver type all`, `login block-for` | none | — | — |
| P3 | `hostname` | none | the device's own name is never read (the envelope name comes from Nautobot); neighbors see it as their CDP/LLDP device-id | — |
| P4 | `switch N provision …` | partial | `iosxe_switch_stack` `switch\|<n>` → role, state, priority, MAC, hardware version, plus model/serial from the inventory join (`:1650-1656`). The join looks each member number up among the inventory's `hw-dev-index` values (`:1581-1589`, `:1655`). The field capture found those indexes are not switch numbers, so on `main` only member 1 gets its model | the actual model of members 2–4, to compare with the provisioned one. State once the stack branch lands |
| P5 | `stack-power stack …` / `stack-power switch …` | none | — | StackPower topology and budget |
| P6 | `redundancy` / `mode sso` | partial | stack roles and states (`iosxe_switch_stack`, `:1650-1656`) | SSO readiness (standby-hot), although `stack-oper`'s per-member `sso-ready-flag` is already fetched (`:1640-1646`) |
| P7 | `license boot level …`, `license smart …` | none | — | the license level in effect |
| P8 | `control-plane` / `service-policy input system-cpp-policy` | none | — | — |
| P9 | `sdm prefer …` | none | — | the SDM template in effect, and the one for the next reload. Whether the line prints in `show running-config` on the stack's release: *field capture* |

Some stack configuration never appears in the running-config at all:

- `switch N priority` and `switch N renumber` are exec commands kept outside
  the configuration. `iosxe_switch_stack` normalizes the priority.
- The VLAN database in VTP server/client mode lives in `vlan.dat` (G1).
- An interface template's expansion is not printed: the stanza shows one
  `source template` line, while `show derived-config` shows what the port
  actually runs.

### 4e. Management plane

| # | Lines | Coverage | Evidence | Missing |
| --- | --- | --- | --- | --- |
| M1 | `aaa new-model`, `aaa authentication` / `authorization` / `accounting`, `tacacs server …`, `aaa group server tacacs+`, `ip tacacs source-interface` | none | `aaa-oper` also defines `aaa-tacacs-stats` (`Cisco-IOS-XE-aaa-oper.yang:1093`), but it holds connection counters only (no alive/dead flag) and is not read | — |
| M2 | `username …`, `enable secret …` | none | — | — |
| M3 | `snmp-server …`, including `snmp-server trap-source` | none | — | — |
| M4 | `logging host` / `trap` / `buffered` / `source-interface` | partial | `iosxe_syslog_errors` counts buffer contents at severities 0–3 (`:698-724`) | destinations and levels; severity 4–7 events |
| M5 | `ntp server` / `source`, `clock timezone` / `summer-time` | partial | `iosxe_ntp` (`:887-933`). Per the model, only `stratum` and a stringified `refid` container come out (§10) | the sync flag |
| M6 | `ip name-server`, `ip domain name` / `lookup` | none | — | — |
| M7 | `banner motd` / `login` / `exec` | none | — | — |
| M8 | `line con 0`, `line vty …` (`access-class`, `transport input`, `exec-timeout`, `login authentication`) | none | incidental: the capture's own SSH session proves vty reachability for its account | — |
| M9 | `ip ssh …`, `ip scp server enable`, `ip http …` (including `secure-server` and the source interfaces), `restconf`, `netconf-yang` | none | incidental: the capture's own RESTCONF and SSH sessions | — |
| M10 | `crypto pki trustpoint …`, `crypto pki certificate chain …` | none | — | certificate validity |
| M11 | `archive` / `log config` | none | — | — |
| M12 | `event manager applet …` | none | — | — |
| M13 | `call-home` | none | — | — |
| M14 | Flexible NetFlow: `flow record`, `flow exporter`, `flow monitor` (the per-port attachment is I22) | none | — | exporter and cache state |
| M15 | model-driven telemetry: `telemetry ietf subscription …` | none | — | subscription validity, receiver connection state |

Every line has one home row. The management VRF and the `GigabitEthernet0/0`
stanza are counted under L4 and I1–I4/I15: Gi0/0 state reaches
`iosxe_interfaces` (`:445-452`) and `Mgmt-vrf` routes reach
`iosxe_routes_rib` (`:121-156`). Each `source-interface` line is counted with
its service: TACACS+ in M1, RADIUS in G11, SNMP in M3, logging in M4, NTP in
M5, SSH and HTTP in M9.

## 5. How much is not available

### 5a. By section

| Class | Sections | Count |
| --- | --- | --- |
| state | I1, I7, I21, G10, G15 | 5 |
| config | G6, L8 | 2 |
| config + state | L1, L2 | 2 |
| partial | I3, I20, I23, G4, L4, P1, P4, P6, M4, M5 | 10 |
| raw-only | I2, I4 | 2 |
| none | the other 53 | **53 of 74 (72%)** |

**Nine of 74 sections (12%) are fully represented in a normalized view.** P4
returns to state once the stack branch fixes the inventory join. On an access
stack the section count understates the gap, because one row (I5, for
example) stands for 192 port stanzas. The line share below is the more honest
measure.

### 5b. By lines

**Access stack, mid case** (12.5 lines per access port):

| Block | Lines | Normalized | Partial | Raw-only | None |
| --- | --- | --- | --- | --- | --- |
| 192 access-port stanzas (192 × 12.5) | 2,400 | 192 (headers) | 0 | 96 (descriptions) | 2,112 (192 × 11) |
| other stanzas: 32 NM ports (2 in the uplink), Po1, Gi0/0, 4 AppGig, Vlan1, Vlan99 | 62 | 44 | 2 | 5 | 11 |
| L2/access-security globals | 265 | 15 (RADIUS servers 10, DHCP snooping 4, LLDP 1) | 5 (errdisable recovery) | 0 | 245 (QoS 120, IBNS 75, VLANs 20, device-tracking 8, RADIUS globals 8, STP 5, UDLD/MAC/IGMP 3, VTP 2, DAI 2, SPAN 2) |
| L3 globals | 33 | 2 (static routes) | 6 (`Mgmt-vrf` definition) | 0 | 25 (ACLs) |
| platform and management globals | 301 | 0 | 19 (NTP 6, logging 5, switch provision 4, `version` and `boot system` 2, `redundancy` and `mode sso` 2) | 0 | 282 (PKI 80, SNMP 80, AAA/TACACS 30, other boilerplate 26, lines 15, management services 12, banners 10, StackPower 8, call-home 6, EEM 5, archive 4, DNS 3, control-plane 2, `end` 1) |
| **Total** | **3,061** | **253 (8.3%)** | **32 (1.0%)** | **101 (3.3%)** | **2,675 (87.4%)** |

- **Interface stanzas are 2,462 of 3,061 lines (80%).**
- **Of the lines in an access-port stanza, 88% are absent**, because only the
  header (existence and admin state) is normalized.
- **Sensitivity to the per-port stanza size:**
  - At 6 lines per port, without the IBNS and auto-QoS globals (§3), the
    config is 1,618 lines, 75% of them interfaces, and 76.1% are absent.
  - At 18 lines per port it is 4,117 lines, 85% interfaces, and 90.6% are
    absent.
  - Raw-only stays between 2.5% and 6.2%.

**Distribution 9300:**

| Block | Lines | Normalized | Partial | Raw-only | None |
| --- | --- | --- | --- | --- | --- |
| interface stanzas: 16 trunk members, 8 Po, 4 routed uplinks, 44 unused ports, 30 SVIs, Lo0, Gi0/0, AppGig | 621 | 167 (headers, unused-port `shutdown`, `channel-group`) | 44 (`ip address`, `ip ospf`) | 59 (descriptions, VRF) | 351 (SVI helpers/HSRP/redirects 270, trunk and Po switchport 72, other 9) |
| L2 globals | 137 | 1 | 4 | 0 | 132 (VLANs 60, QoS 60, STP 6, UDLD/MAC 4, VTP 2) |
| L3 globals | 268 | 65 (BGP 25, OSPF 20, static 10, DHCP 10) | 15 (VRF definitions) | 0 | 188 (ACLs 120, route-maps 25, prefix-lists 20, IP SLA/track 12, key chains 6, multicast 5) |
| platform and management globals | 292 | 0 | 18 (NTP 6, logging 6, switch provision 2, `version` and `boot system` 2, `redundancy` and `mode sso` 2) | 0 | 274 |
| **Total** | **1,318** | **233 (17.7%)** | **81 (6.1%)** | **59 (4.5%)** | **945 (71.7%)** |

The distribution switch is better covered only because routing is: the
routing stanzas are config-captured, and the RIB, FIB, OSPF and BGP are
state-captured. Its SVIs (HSRP, helpers) and its ACL, QoS and routing-policy
content are as dark as the access stack's ports.

Assumptions behind both tables:

- VTP is transparent or off; in server or client mode the VLAN lines vanish
  from the text (G1).
- Unused access ports are configured like used ones (template practice).
- The counts are what `show running-config` prints, without `all`.
- The per-section sizes are the typical values listed in the tables.

The shape of the answer does not depend on these numbers: **interface
stanzas are most of an access switch, and almost all of an access-port
stanza is dark.**

### 5c. Startup-config

Nothing reads the startup-config, so all of it is absent.

- The device's own summary of it, `unsaved-config` (defined at
  `Cisco-IOS-XE-device-hardware-oper.yang:462`), already arrives in the
  cached `_HW_PATH` payload whenever the device fills it in. It is never
  normalized, and the 9500 fixture does not contain it.
- The model warns that the flag "might indicate that the configuration is
  dirty, when there are no actual changes". It is the device's answer, not a
  diff.
- Recommendation 1 pairs the flag with the running/startup text comparison
  that the config-text check makes possible.

### 5d. After the ten recommendations

Replaying the same line model with the §8 checks in place changes classes,
not line counts. Nothing else is assumed to land; in particular the stack
branch has not, so `switch N provision` stays partial.

| Config | Normalized | Partial | Raw-only | None |
| --- | --- | --- | --- | --- |
| access stack (mid) | 689 (22.5%) | 1,370 (44.8%) | 100 (3.3%) | 902 (29.5%) |
| distribution | 513 (38.9%) | 39 (3.0%) | 58 (4.4%) | 708 (53.7%) |

The lines that change class:

- **Access-port stanzas.** Each port's 12.5 lines split like this:
  - **Normalized (3):** the header and the two `service-policy` lines
    (rec. 7's effective policy per direction).
  - **Partial (6):**
    - the mode, access-VLAN and voice-VLAN lines. The VLAN's existence and
      status are normalized (rec. 2); the port's landed VLAN is context
      (rec. 2), and rec. 6 counts sessions per landed VLAN;
    - the 802.1X template (its outcome only, rec. 6);
    - auto-QoS (the policy names only, rec. 7);
    - the storm-control level (the filter state only, rec. 7).
  - **Raw-only (0.5):** the description.
  - **None (3):** device-tracking, portfast and the storm-control action.
- **Other interface stanzas** (the access stack gains 10 normalized lines,
  the distribution switch 206):
  - trunk `switchport` lines on uplinks, bundle members and port-channels
    (rec. 3): 6 lines on the access stack, 48 on the distribution switch;
  - every `ip address` line (rec. 7's mask), and Gi0/0's `vrf forwarding`
    and `negotiation auto` (rec. 7);
  - on the distribution SVIs, the three `standby` lines (rec. 9) and
    `ip access-group` (rec. 7).
- **Globals.**
  - Normalized: VLAN definitions and VTP (rec. 2), spanning-tree globals
    (rec. 4), StackPower (rec. 5), `version` and `boot system` (rec. 1),
    and `errdisable recovery` (rec. 8 counts the recoveries).
  - Partial: the IBNS globals (their outcomes, rec. 6) and the auto-QoS maps
    (their names, rec. 7).

What stays absent is mostly PKI, SNMP, AAA, `line` blocks, banners, the
content of ACLs, QoS policies and routing policy, DHCP helpers,
`no ip redirects` / `proxy-arp`, PIM, guard lines, DHCP-snooping trust,
device-tracking and portfast. §6 leaves all of these to the text diff
(verdict A) or finds them not worth a check (D).

## 6. Value review

Verdicts:

- **A**: the full-config text diff is enough.
- **B**: worth a structured state check.
- **C**: worth a structured config check.
- **D**: not worth a check.

How often each failure happens is field judgement, not measurement.

| Gap (sections) | Failure it would catch during a change | How often | Verdict |
| --- | --- | --- | --- |
| Access/voice VLAN per port, VLAN database, VTP (I5, G1, G2) | a re-cabled or re-provisioned port lands in the wrong or a missing VLAN; a VLAN is deleted or suspended (VTP revision overwrite, `no vlan`). In VTP server/client mode the text diff cannot see VLANs at all | wrong VLAN: common in port moves; VTP wipe: rare but site-wide | **B** for the VLAN database and VTP (rec. 2). The per-port VLAN goes to context: on an 802.1X port it follows the session, and on a static port the text diff already shows the `switchport` line |
| Trunk allowed/active/forwarding sets, native VLAN (I6) | a VLAN missing from an uplink after re-cabling to a new port, pruned by VTP, or STP-blocked on the only path; a native-VLAN mismatch. Every port reads up while one VLAN is dark | common in re-cabling | **B** (rec. 3) |
| Spanning tree (I8, G3) | the root moved (a new switch at default priority), an uplink went alternate or blocking, or a port is stuck `broken` (loop-inconsistent, root-inconsistent, PVID mismatch). Also a topology-change storm | occasional; severe | **B** (rec. 4) |
| PoE and StackPower (I10, P5) | APs, phones or cameras unpowered or at a lower class after a reload, member replacement or PSU loss; a supply dropped out of the power stack; the StackPower ring broke | occasional | **B** (rec. 5) |
| 802.1X/MAB outcomes (I11, G9) | RADIUS is alive but sessions fail (policy, a VLAN assignment to a missing VLAN, a dACL); one member's endpoints never re-authorize | common in 802.1X sites during AAA/policy work and re-cabling | **B** (rec. 6) |
| RADIUS globals, CoA (G11) | CoA refused; dead-criteria changed | rare | A |
| Negotiated speed/duplex, MTU, mask, IPv6 addresses, VRF membership, ACL and QoS attachment, storm-control filter state (I3, I4, I9, I13, I14, I15, I23) | an uplink or AP port renegotiated to 100M or half duplex after re-cabling or an optic swap, or an mGig port downshifted on a poor cable; an MTU mismatch; a mask typo; a policy not re-attached after a template edit; storm-control actively blocking | occasional; the data is nearly free | **B** for negotiated speed/duplex, mGig downshift and the storm-control filter state. **C, free**, for the effective mask, IPv6 addresses, VRF, MTU and attached ACL/QoS policies, which templates, `system mtu` and DHCP can set without the value appearing in the port's stanza (rec. 7, §6a) |
| Transients that heal before POST (G4, I9, I12, I16, I17; FHRP/STP/MAC flaps) | a port err-disabled and auto-recovered; HSRP flapped and settled; the root changed and came back; minutes of MAC flapping (a loop) | occasional. No state check can see them. Their severity-4/5 lines are never counted and reach raw only while they sit in its last 20,000 characters; `%LINK-3-UPDOWN` is counted, without a port or a reason | **B** (rec. 8) |
| FHRP (I19) | the active gateway flipped, giving asymmetric paths through stateful devices; both routers active after a trunk change; a group stuck in init/listen | occasional (distribution) | **B** (rec. 9) |
| MAC learning (G13; the effect of I5/I6) | endpoints not re-learned on a member or VLAN; a loop | occasional | **B** (rec. 10) |
| Unsaved config, running version, install commit state (P1, startup-config) | the change was never saved, so a later reload reverts it; pre-existing unsaved edits get persisted by the engineer's `write memory`; an install was activated but not committed, so the auto-abort timer or the next reload rolls it back | unsaved: common; uncommitted: occasional | **B** (rec. 1) |
| SSO readiness (P6) | the standby is not HOT after a member reload, so the next failure is not stateful | occasional | B, small, and free: `stack-oper` is already fetched (below the line, §8) |
| Stack member model and serial (P4 remainder) | a replaced member 2–4 goes unnoticed | occasional | fixed by the in-flight stack branch; no new check |
| EIGRP/IS-IS adjacencies (L2 remainder) | an adjacency lost where EIGRP is run | site-specific | B if used (below the line) |
| DHCP-snooping bindings and drops, DAI, device-tracking (G6 state, G7, G8, I12) | a missing `ip dhcp snooping trust` on a new uplink drops offers | occasional. The binding table lags (leases outlive the window), drops are counters, and no model exists | D (revisit with field evidence; the SSH fallback would be `show ip dhcp snooping statistics`) |
| UDLD, port-security (G5, I16, I17) | already caught as err-disable reasons | — | D |
| LACP partner identity (I7 remainder) | a bundle re-formed to a different chassis | rare. CDP on each member port already names the far end, and an SVL pair or a stack presents one LACP system-id anyway | D |
| IGMP/MLD snooping, multicast routing (G12, L7) | multicast paging or video breaks | site-specific | D (revisit where multicast is used; `pim-oper` and `mroute-oper` exist) |
| TrustSec (G18) | after AAA work the switch fails to download its environment data from ISE, or an SXP peer drops, and SGT enforcement denies traffic | site-specific | D (revisit where SGTs are enforced: `trustsec-oper` has `cts-env-data` `status` (`Cisco-IOS-XE-trustsec-oper.yang:1067`) and `cts-sxp-connections` (`:1029`), and a 9300 advertises it in both releases) |
| SPAN (G14) | a SPAN session left behind | rare | A |
| QoS, ACL (including VACLs), load-balance hash, prefix-list/route-map, IP SLA/track, key-chain and VRF RD/RT content (G16, G17, L3, L4 remainder, L5, L6, L9) | content edits | occasional | A. Their effects already show in the RIB, BGP and FHRP; ACL/QoS hit counters would be D (volatile) |
| DHCP helpers and pools (I18, L8 state) | a helper missing on a moved SVI | occasional | A |
| OSPF/PIM interface settings (I20 remainder) | a cost change reroutes traffic | occasional | A (the RIB shows the path change) |
| Platform boilerplate, `system mtu`, hostname, CoPP (P2, P3, P8) | — | rare | A |
| License level and SDM template (P7, P9) | a `license boot level` or `sdm prefer` edit that has not been reloaded changes features or TCAM allocation at the next reload, long after the window. The text shows the setting for the next reload, not what runs | rare | D, below the line (§8). The level in effect is in `cisco-smart-license` `licensing/state` usage (`cisco-smart-license.yang:2233`, `:2303`; advertised in both releases); the SDM template has no model (`show sdm prefer`) |
| AAA/TACACS+, local users (M1, M2) | admin lockout | occasional | A. When the capture account is TACACS-backed, the capture's own login is the functional test; `aaa-tacacs-stats` holds counters only |
| SNMP, logging config, DNS, banners, lines, SSH/HTTP/RESTCONF/NETCONF, archive, EEM, call-home, NetFlow exporters, telemetry subscriptions (M3, M4 remainder, M6–M9, M11–M15) | monitoring or management silently broken | occasional | A. The switch cannot prove that a collector received anything. `flow-monitor-oper` and `mdt-oper` (receiver `state`) are advertised in both releases; a check on them is D unless the site's monitoring depends on dial-out telemetry |
| NTP (M5) | sync lost | occasional | the state check exists; repair it (§10) |
| PKI (M10) | certificate expiry | rare; not caused by a change | D (the suite does not verify TLS today: `constants.VERIFY_TLS = False`) |
| description, per-port telemetry settings including the NetFlow attachment (I2, I22) | — | — | D (the description is raw-only by design) |

### 6a. Why only one structured config view (C) survived

Once the text is in the snapshot, a structured config view adds value in
only two cases, and a state check usually covers both:

1. **The expectations engine needs per-key config to bless a declared
   change.** `iosxe_trunks` and `iosxe_fhrp` give per-key views of the
   config's effect, which a diff can bless per port or per group.
2. **The text is misleading.** Templates, VTP-held VLANs and changed
   defaults are all cases where state shows what actually runs.

Rec. 7's effective interface settings are the one config view that meets
both cases and still earns a place. The mask, IPv6 addresses, VRF, MTU and
attached ACL and QoS policies are config, but the oper model reports what
runs: an interface template, `system mtu` or a DHCP lease sets them without
the value appearing in the port's stanza. They are also per-port keys, and
they cost nothing, because `iosxe_interfaces` already makes the GET. Drop
them if the field capture shows them noisy.

The per-port VLAN did not earn the same place. It was considered for rec. 2
and kept in context: on a static port it restates the `switchport` line, and
on an 802.1X port it follows the session, which would churn a tier-1 view
between two healthy captures (rec. 2).

The existing config blobs are now dominated by the text diff:

- `iosxe_routing_config` and `iosxe_dhcp` emit one value per section, so a
  one-line edit reads as "the whole blob changed", while the text diff names
  the line.
- They cost 4 GETs and work without SSH, so keep them for now.
- **Revisit them after the config-text check has run in one real change
  window.** If the analyst never needs them, retire them.

### 6b. What the text diff cannot show (notes for the config-text check)

1. **Config that is not in the running-config text:**
   - the VLAN database in VTP server/client mode;
   - `switch N priority` and `renumber`;
   - interface-template expansions;
   - defaults (an upgrade can change one with no line changing);
   - per-session policy from RADIUS: dynamic VLANs, downloadable ACLs and
     RADIUS-applied interface templates;
   - the install and commit state of the boot image;
   - the license level and the SDM template in effect: `license boot level`
     and `sdm prefer` take effect only at the next reload, so any line they
     leave shows the next state, not the running one (whether `sdm prefer`
     prints at all: P9).
2. **Secret rotation behind constant redaction.** If every secret becomes one
   fixed token, a changed RADIUS or TACACS+ key, SNMP community, HSRP, OSPF
   or NTP authentication key, or key chain is invisible.
   - A digest keyed with a deployment secret would show "changed" without
     leaking anything.
   - An unkeyed hash of a type-7 string is dictionary-attackable, because
     type 7 is reversible encoding.
   - The effect of a wrong RADIUS key still shows: servers go dead in
     `iosxe_aaa_servers`.
3. **Header comments.** `! Last configuration change at … by …` and
   `! NVRAM config last updated at … by …` record who changed and who saved
   the config, and when. They change only when the config or the save
   changes, so they are signal, not noise.
4. **Identifiers in the text.** Serial numbers (in license UDI lines on some
   releases), the self-signed trustpoint's number and MACs in static entries
   are fine inside a snapshot, because they are the device's own data. Any
   fixture harvested from one must be sanitized.
5. **Size.**
   - The modelled access stack is about 95 KB of text per copy, roughly
     25–30k LLM tokens.
   - Pre plus post, running plus startup, across several stacks, exceeds
     most analysis contexts.
   - The analyst should read the line diff, not the full texts.

### 6c. Earlier proposals, revisited

`docs/plans/nfv-core-move.md` §6–§7 proposed IOS-XE follow-ons. This review
keeps some and drops others:

- **`iosxe_mac_table`** (`nfv-core-move.md:324-334`) was keyed
  `infra-mac|<mac>` and seeded from other checks' MACs. A collector sees only
  its own device, and seeding would be change-specific.
  - Replace it with the generic capability view (rec. 10).
  - Join vendor MACs in the prompt, from raw.
- **`iosxe_host_facing_interface_config`** (`:335-347`) is superseded. The
  text diff shows the stanzas, and `iosxe_vlans`, `iosxe_trunks` and
  `iosxe_stp` show their effect. Drop it.
- **`iosxe_stp`, `iosxe_poe` and the `show interfaces trunk` parse**
  (`:386-391`) are kept, and are specified in §8.
- **`iosxe_lacp_partners`** (`:388-389`) gets verdict D.
- **`show ip dhcp snooping binding`** (`:391-392`) gets verdict D.
- The stack-member proposal (`:368-381`) shipped as `iosxe_switch_stack`;
  field fixes are in flight on the stack branch.
- `docs/prompts/floor-consolidation.md:533-541` lists what the data cannot
  see: CRC/FCS counters, switch-port speed/duplex, PoE and StackPower,
  spanning tree, trunk and VLAN config, MAC tables, and whether redundant
  supplies sit on separate circuits. Recommendations 2–5, 7 and 10 close the
  switch-side items on lines 535–540; switch-port CRC reaches context
  through rec. 7. Host-NIC CRC counters (`:535`) and the supply circuits
  (`:541`) are outside these recommendations. Update the list as each check
  lands.

## 7. YANG-first sourcing for the recommendations

In the table below:

- **17.9.1 hello** is the module revision advertised in
  `vendor/cisco/xe/1791/capability-cat9300.xml`.
- **17.12.1** is the revision in `vendor/cisco/xe/17121/yang-set-cat9300.xml`.
  The differences listed come from comparing the two releases' leaf trees
  and enum sets.

| Need (rec.) | 17.9.1 model and path | 17.9.1 hello | 17.12.1 revision and differences | Already fetched by |
| --- | --- | --- | --- | --- |
| saved config, versions (1) | `Cisco-IOS-XE-device-hardware-oper` `device-hardware-data/device-hardware/device-system-data`: `unsaved-config` (`:462`), `software-version` (`:440`), `rommon-version` | 2021-03-01 | 2023-03-01; adds `reload-history`; these leaves are unchanged | **yes**: `iosxe_platform_health`, `iosxe_switch_stack` and the wireless gate all GET `_HW_PATH` (cached) |
| install state (1) | `Cisco-IOS-XE-install-oper` `install-oper-data/install-location-information` (`:1714`, `:1732`; keyed `fru slot bay chassis`, `:1733`) → `install-version-info` (`is-default`; `current` ∈ `install-version-state-provisioned-committed` / `-provisioned-uncommitted` / …; `commit-type`), `oper-state/auto-abort-timer` (`:898`), `oper-state/boot-mode` | 2022-07-01 | 2023-07-01; adds transaction history and `scheduled-start`/`-end`; these leaves are unchanged | no |
| VLAN database, per-port map for context (2) | `Cisco-IOS-XE-vlan-oper` `vlans/vlan[id]` (`:131`) → `name`, `status` (`active`/`suspend`), `ports` ("Assigned ports", `:118`), `vlan-interfaces` ("List of interfaces for a given VLAN", `:123`). Which ports each list holds, trunks included or not, is unverified (§9) | 2019-05-01 | 2022-11-01; no change | no |
| VTP status (2) | no oper model (`Cisco-IOS-XE-vtp` is config only). SSH `show vtp status` | — | — | no |
| trunk sets (3) | no model gives the set that is forwarding and not pruned. Parts exist: `vlan-oper` `vlan-interfaces` may list trunk members (unverified, §9); under rapid-PVST, `spanning-tree-oper` gives each VLAN's port roles and states (rec. 4); `openconfig-vlan` `trunk-vlans` mirrors config. SSH `show interfaces trunk` gives all four sets in one place and is the only source for VTP pruning | — | — | no |
| spanning tree (4) | `Cisco-IOS-XE-spanning-tree-oper` `stp-details/stp-detail[instance]` (`:429`, `:433`) → bridge and root facts, `topology-changes` (`:347`); `interfaces/interface[name]` → `role`, `state`, `guard`, `bpdu-guard`, `link-type`; `stp-global` (`:439`) | 2019-05-01 | 2022-11-01; no structural or enum change | no |
| PoE, StackPower (5) | `Cisco-IOS-XE-poe-oper` `poe-oper-data` (`:2235`) → `poe-port` / `poe-port-detail[intf-name]` (`:2239`, `:2245`), `poe-module` (`:2251`), `poe-stack[power-stack-name]` (`:2257`: `mode` ∈ `stack-mode-*`, **`topolgy`**, the model's spelling, ∈ `stack-topo-ring` / `-star` / `-standalone` / `-none` (`:2072`), `total-power` int watts (`:2077`), `num-sw`, `num-ps`), `poe-switch[switch-num]` (`:2263`: `port-one-status` / `port-two-status` ∈ `stack-port-status-*` (`:2148`), `power-budget`, `available-power`) | 2022-07-01 | 2023-07-01; adds `device-tag`; `topolgy` keeps its spelling | no |
| 802.1X/MAB sessions (6) | `Cisco-IOS-XE-identity-oper` `identity-oper-data/session-context-data[mac]` (`:3179`, `:3183`) → `intf-name`, `method-id`, `domain`, `state`, `authorized`, `vlan-id`, `policy-name`; **never `username`** (`:1592`) | 2021-07-01 | 2022-11-01; no change | no (`iosxe_aaa_servers` reads the servers, not the sessions) |
| interface widening (7) | `Cisco-IOS-XE-interfaces-oper` `interfaces/interface`: `ipv4-subnet-mask` (`:4739`), `ipv6-addrs` (`:4782`), `input-security-acl` (`:4754`) / `output-security-acl`, `mtu`, `diffserv-info` (`:4721`), `storm-control` (`:4820`; filter-state ∈ `inactive`/`link-down`/`blocking`/`forwarding`), `ether-state` (`:4839`) → `negotiated-port-speed` (`:4058`), `negotiated-duplex-mode` (`:4050`); `intf-ext-state` (`:4814`, valid when `intf-ext-state-support` is present, `:4809`) → `error-type`, `port-error-reason`, `mgig-downshift-enabled` (`:4411`); `statistics`. `speed` (`:4706`) is a bandwidth estimate, not the negotiated speed. The err-disable enums are `port-error-code` and `port-err-reason` in `Cisco-IOS-XE-ios-common-oper.yang` (`:1771`, `:1788`: `port-err-bpduguard`, `-unidirectional-link-detection`, `-psecure-violation`, `-link-flap`, `-dhcp-rate-limit`, `-arp-inspection`, `-storm-control`, `-inline-power`, …) | 2021-03-01 | 2022-11-01; adds `eee-status` only; the err-disable enums are identical | partly: the same GET with a six-leaf `fields` filter (`checks_iosxe.py:38-41`). Err-disable comes from SSH today (`iosxe_errdisable`, `:1313`) |
| CDP widening (7) | `Cisco-IOS-XE-cdp-oper` `cdp-neighbor-detail`: `native-vlan` (`:337`), `duplex` (`:312`), `vvid` | 2022-03-01 | 2022-11-01; no change | **yes**: the unfiltered CDP GET (`checks_iosxe.py:42`, `:419`) |
| transients (8) | no state model. The event models (`Cisco-IOS-XE-hsrp-events`, 17.12.1's new `Cisco-IOS-XE-spanning-tree-events`) define notifications, which a GET-only client cannot receive. Use the `show logging` output already fetched | — | — | **yes** (`checks_iosxe.py:717`) |
| FHRP (9) | `Cisco-IOS-XE-hsrp-oper` `hsrp-oper-data/hsrp-group-info` (`:189`, `:193`); `Cisco-IOS-XE-vrrp-oper` `vrrp-oper-data/vrrp-oper-state` (`:418`, `:422`) | 2020-11-01 / 2021-11-01 | 2022-11-01 for both; no change | no |
| MAC learning (10) | `Cisco-IOS-XE-matm-oper` `matm-oper-data/matm-table[table-type vlan-id-number]/matm-mac-entry` (`:170`, `:174`) → `port`, `mat-addr-type` (`static`/`dynamic`/`any` only; port-security's secure MACs are in `Cisco-IOS-XE-psecure-oper`) | 2019-05-01 | 2022-11-01; no change | no |
| SSO readiness (below the line) | `Cisco-IOS-XE-stack-oper` `stack-oper-data/stack-node[chassis-number]` (`:604`, `:608`) → `sso-ready-flag`, "Standby SSO Ready flag" (`:484`). Richer: `Cisco-IOS-XE-ha-oper` `ha-oper-data/ha-infra` (`Cisco-IOS-XE-ha-oper.yang:212`, `:216`) → `ha-state`, `peer-state` (`db-rf-standby-hot` …), `has-switchover-occured`, `last-switchover-reason` | 2022-03-01 (stack) / 2019-11-01 (ha) | 2022-11-01 for both; no change | **partly**: `iosxe_switch_stack` keeps the `stack-oper` payload in raw (`checks_iosxe.py:1640-1646`). The field capture shows `sso-ready-flag: false` on members 1, 3 and 4; the standby, member 2, was not captured. `ha-oper` is not fetched |

- **The D-verdict gaps also checked for a model:**
  - Device-tracking and DHCP-snooping bindings have none. The only SISF oper
    model a 9300 advertises is the wireless
    `Cisco-IOS-XE-wireless-sisf-global-oper` (DHCPv4 statistics, no binding
    table), and `dhcp-oper` covers the server, client and relay only.
  - `Cisco-IOS-XE-dhcp-security-track-server-oper` tracks the DHCP servers
    that snooping has seen, not the bindings.
- **UDLD, VTP, SNMP, EEM and call-home have no oper model in 17.9.1 at
  all.** Storm-control's only state is the per-interface filter state in
  `interfaces-oper` (rec. 7).
- **Err-disable does have one.** `interfaces-oper` `intf-ext-state` carries
  `error-type` and `port-error-reason` per port (see the interface-widening
  row). The reason enum covers bpduguard, UDLD, port-security, link-flap,
  DHCP and ARP rate limits, storm-control and inline power, so UDLD's
  err-disable consequence is modelled too. Rec. 7 makes it the source for
  `iosxe_errdisable`, which today reads SSH only and skips without it
  (`checks_iosxe.py:1311-1312`).

## 8. Recommendations, prioritized

The ten items below are ranked by value: failure frequency × severity ×
invisibility elsewhere, divided by cost. Every item is a state check (B),
except rec. 7's effective-config leaves (C, free). Every item is always on
and has `not-present` semantics.

1. **`iosxe_persistence`: would a reload bring back what runs now?**
   - **Tier and compare:** tier 1, `equality_set`.
   - **Sources:**
     - the cached `_HW_PATH` GET (no new request): `unsaved-config`,
       `software-version`, `rommon-version`;
     - one GET of `install-oper-data/install-location-information` with a
       `fields` filter: `install-version-info(version;is-default;current;commit-type)`
       and `oper-state(auto-abort-timer;boot-mode)`.
   - **Keys:**
     - `device` → `config_saved` (the inverse of `unsaved-config`; None
       when the leaf is absent), `software_version`;
     - `install|<chassis>|<fru>|<slot>|<bay>` → `boot_mode`, `version` (the
       `is-default` one), `state`, `commit_type`, `abort_timer`. The key is
       the list's full key: a dual-supervisor chassis reports two rows with
       one chassis number, and keyed by chassis alone the last row read
       would hide the other.
   - **Context:** the abort-timer end time, and `rommon_version`. The latter
     is one device-wide leaf, so on a stack it can describe only one member,
     and a switchover between members with different ROMMON versions would
     read as an upgrade.
   - **Not-present:** the `install|` keys are omitted, with a raw note, when
     the model is absent.
   - **Why:**
     - `config_saved: false` in the POST capture means the change dies at
       the next reload.
     - `false` in the PRE capture means the engineer's `write memory` will
       also persist someone else's pending edits.
     - An uncommitted install rolls back when its timer fires.
     - The text diff between running and startup names the unsaved lines;
       this check says whether any exist.
2. **`iosxe_vlans`: the VLAN database, and where each port landed.**
   - **Tier and compare:** tier 1, `equality_set`.
   - **Sources:**
     - GET `Cisco-IOS-XE-vlan-oper:vlans` (small, no filter needed);
     - SSH `show vtp status`, as best-effort enrichment recorded in raw
       (the `iosxe_route_rollups` pattern).
   - **Keys:**
     - `vlan|<id>` → `name`, `status`;
     - `vtp` → `mode`, `domain`, `version`, `pruning`, `revision`.
   - **Context:** the per-port map, `<interface>` → a sorted list of VLAN
     ids built by inverting each VLAN's assigned `ports`; VLAN totals and
     the suspended count.
   - **Why the per-port map is context, not keys:**
     - `vlan-oper` reports the operational VLAN. On an 802.1X/MAB port that
       follows the session: a RADIUS-assigned, guest, auth-fail or critical
       VLAN while a session is up, and the configured VLAN once it clears.
       On the §3 closed-mode stack, a laptop that sleeps between PRE and
       POST moves its port from VLAN 30 back to VLAN 10 with nothing wrong.
     - On a static port the map restates the `switchport access vlan`
       line, which the text diff already shows.
     - Nothing in `vlan-oper` tells the two kinds of port apart. If the
       field capture finds a stable marker of 802.1X-controlled ports,
       static ports can move back into `port|<interface>` keys.
   - **Why:**
     - A VLAN deleted or suspended (a VTP revision overwrite, a stray
       `no vlan`) cuts off every port in it while those ports still read
       up.
     - This is the only view of VTP-held VLANs, which never reach the
       text.
     - A port in the wrong VLAN is a config fact the text diff shows, or a
       session outcome rec. 6 counts per landed VLAN; the per-port map in
       context lets the analyst confirm either.
3. **`iosxe_trunks`: what each trunk actually carries.**
   - **Tier and compare:** tier 1, `equality_set`.
   - **Source:** SSH `show interfaces trunk`. No model gives the
     not-pruned set (§7). If the probe (§9) shows that `vlan-oper`
     `vlan-interfaces` lists trunk members and rec. 4 gives per-VLAN port
     states, this check shrinks to the pruning column.
   - **Keys:** `trunk|<port>` → `mode`, `encapsulation`, `status`,
     `native_vlan`, `allowed`, `active`, `forwarding`. The VLAN sets are
     rendered as canonical range strings (`1,10,20-30`) so the type never
     changes, with wrapped continuation lines joined first.
   - **Not-present:** when no trunk rows exist or the command is rejected.
   - **Why:** the forwarding set ("spanning tree forwarding state and not
     pruned") is where VTP pruning and STP blocking show up. A VLAN allowed
     but not forwarding on the only uplink is an outage for that VLAN while
     every port reads up.
   - **Stability:** with VTP pruning on, a neighbor's joins follow its
     active ports, so the not-pruned set can move with endpoint activity
     downstream. Two probe runs an hour apart decide whether `forwarding`
     stays normalized or moves to context where pruning is enabled.
4. **`iosxe_stp`: roots, and every port that is not plain
   designated-forwarding.**
   - **Tier and compare:** tier 1, `equality_set`.
   - **Source:** GET `stp-details` with a `fields` filter on the instance
     and port leaves listed in §7.
   - **Keys:**
     - `stp` → `mode` plus the global guard flags and the MST name/revision;
     - `instance|<instance>` → `bridge_priority`, `root_address`,
       `root_priority`, `root_cost`, `root_port` (resolved to a name through
       `port-num`), `is_root`;
     - `port|<instance>|<interface>` → `role`, `state`, `guard`,
       `bpdu_guard`, `link_type`, **only when the role is not designated or
       the state is not forwarding**.
   - **Context:** per instance, `topology-changes` and the last change time,
     read as a delta, plus the count of designated-forwarding ports.
   - **Not-present:** when the container is empty.
   - **Why:** root moves, blocked uplinks and broken ports are invisible to
     up/down checks, and topology-change deltas reveal flaps that healed.
   - **Stability:** the designated-forwarding exclusion is what keeps
     endpoint power-cycling from churning the keys.
5. **`iosxe_poe`: power where it matters.**
   - **Tier and compare:** tier 1, `equality_set`.
   - **Source:** GET `poe-oper-data` with a `fields` filter. Prefer the
     richer `poe-port-detail`, falling back to `poe-port`; *field capture*
     decides which is populated. Whole `poe-module`, `poe-stack` and
     `poe-switch`.
   - **Keys:**
     - `port|<interface>` → `admin`, `oper` (`pd-power-on` / `off` /
       `faulty` / `deny` / `overdrawn`), `class`;
     - `stack|<power-stack-name>` → `mode` (`stack-mode-*`), `topology`,
       `switches` (`num-sw`), `supplies` (`num-ps`) and `total_watts`
       (`total-power`, an int that changes only with supplies). Read
       `topology` from the model's own spelling, `topolgy` (`stack-topo-ring`
       / `-star` / `-standalone` / `-none`); a normalizer that reads
       `topology` gets None forever;
     - `switch|<n>` → `port_one`, `port_two`: the StackPower cable ports
       (`port-one-status` / `port-two-status`, `stack-port-status-*`).
   - **Context:** per-switch `power-budget`, `power-allocated` and
     `available-power`; watts drawn and remaining; ports by oper state.
     Under StackPower sharing the per-switch figures are probably
     allocations from the shared pool that move with demand (*field
     capture*), so they stay out of normalized.
   - **Not-present:** on a non-PoE SKU or when the model is absent.
   - **Why:**
     - Dark or down-classed APs and phones after a reload, member swap or
       PSU loss read only as "down" elsewhere.
     - A StackPower ring that fell to star is a cable not reseated, the
       power twin of the stack ring.
6. **`iosxe_access_sessions`: do endpoints get on?**
   - **Tier and compare:** tier 1, capability (`floor_pre` 5, `min_post` 1,
     the `wlc_clients_summary` shape).
   - **Source:** GET `identity-oper-data/session-context-data?fields=mac;intf-name;method-id;domain;state;authorized;vlan-id;policy-name`.
     Never request `username`: the house rule at
     `checks_iosxe_wireless.py:103` keeps it out of every snapshot. This
     plan also leaves out the session's addresses and `device-name`, which
     identify the endpoint just as well.
   - **No unfiltered retry.** An unfiltered read of this list would carry
     `username` into raw, so a 400 on the `fields` filter records
     not-present with a note instead (the exception to the retry rule
     below).
   - **Buckets:** `total`, `authorized`, `domain|<data|voice>`,
     `method|<dot1x|mab|webauth>`, `vlan|<id>` (the landed VLAN, including
     RADIUS-assigned ones), and `member|<n>` (parsed from the interface
     name).
   - **Context:** counts by state (`authc-failed`, `authz-failed`,
     `running`, …), unauthorized totals, and per-policy counts.
   - **Not-present:** only on a 404. An empty 2xx records `total: 0`.
   - **Why:** "RADIUS alive, every link up, nobody on the network" is
     exactly the gap between `iosxe_aaa_servers` and the service.
7. **Widen `iosxe_interfaces` and `iosxe_neighbors`. Zero new requests.**
   - **Tiers stay at 2.**
   - **`iosxe_interfaces`:**
     - Extend its `fields` filter (`checks_iosxe.py:38-41`) with the leaves
       in §7.
     - Normalize state (B): `speed` and `duplex` from `ether-state`
       `negotiated-port-speed` and `negotiated-duplex-mode`, emitted only
       when oper is up (the model's own `speed` leaf is a bandwidth
       estimate); `mgig_downshift` (`intf-ext-state`
       `mgig-downshift-enabled`); and `storm` (the traffic types whose
       filter-state is `blocking`).
     - Normalize the effective config (C, free, §6a): `vrf` (already
       fetched), `mask`, `ipv6` (the sorted `ipv6-addrs`), `mtu`, `acl_in` /
       `acl_out`, and `qos_in` / `qos_out` (from `diffserv-info`).
     - Put nonzero CRC, in-error and flap counters per port into context,
       never into normalized.
   - **`iosxe_errdisable`:** read `intf-ext-state` from the same widened
     GET, a cache hit, as the primary source: a key per port whose
     `error-type` is `port-error-disable`, with its `port-error-reason`.
     Keep `show interfaces status err-disabled` as the fallback when the
     leaves are absent. The check then works without SSH. Its reason words
     change spelling (`port-err-bpduguard`), so it lands between change
     windows like any new field. `iosxe_interfaces` does not normalize the
     err-disable leaves itself, so one event is not reported twice.
   - **`iosxe_neighbors`:** add CDP `native_vlan`, `duplex` and `voice_vlan`
     from the payload it already fetches.
   - **Why:** this is the cheapest large gain, covering I3, I4, I9,
     I13–I15 and I23. It answers "speed/duplex" and "CRC" on the prompt's
     cannot-see list, and a CDP native-VLAN mismatch becomes a changed
     field.
   - **Stability risk:** host ports renegotiate with endpoint power state
     (*field capture*, via two probe runs an hour apart). If that proves
     noisy, emit speed and duplex only for ports absent from every
     `vlan-oper` assigned-ports list, that is, trunks and routed ports
     (§9 asks whether `ports` holds trunks).
8. **Widen `iosxe_syslog_errors` to curated severity-4/5 events. Zero new
   commands.**
   - **Tier and compare:** tier 3 and `info_only`, both unchanged.
   - **Keys:** keep the key shape `sev<N>|%FAC-N-MNEMONIC`. Count severities
     4–5 only for an allowlist of facilities:
     - port and link: `PM`, `SPANTREE`, `EC`, `UDLD`, `CDP`;
     - redundancy and routing: `HSRP`, `VRRP`, `OSPF`, `BGP`, `DUAL`;
     - edge services: `ILPOWER`, `DOT1X`, `MAB`, `SESSION_MGR`, `AUTHMGR`,
       `RADIUS`, `DHCP_SNOOPING`, `SW_DAI`;
     - platform and address: `STACKMGR`, `PLATFORM_STACKPOWER`, `SW_MATM`,
       `IP`.
   - **Typical messages this catches**, with their usual severities:
     `%PM-4-ERR_DISABLE`, `%HSRP-5-STATECHANGE`, `%SW_MATM-4-MACFLAP_NOTIF`,
     `%CDP-4-NATIVE_VLAN_MISMATCH`, `%ILPOWER-5-*`, `%DOT1X-5-FAIL`,
     `%RADIUS-4-RADIUS_DEAD`, `%IP-4-DUPADDR`. *Field capture:* grep the
     stack's buffer to confirm them on its release.
   - **Context:** the buffer header (size, buffered level, messages logged)
     and the timestamp and `%FAC-N-MNEMONIC` tag of the oldest buffered
     line, so the analyst can see whether the change window is still inside
     the buffer. Never the line's text: log lines name users and can carry
     typed commands (§10).
   - **Why:** transients that heal before POST leave no trace in any state
     check. The full `show logging` is already fetched
     (`checks_iosxe.py:717`). Its severity-4/5 lines are never counted
     today and reach raw only while they sit in its last 20,000 characters
     (`:723`). This widening makes them normalized, countable events.
9. **`iosxe_fhrp`: gateway roles.**
   - **Tier and compare:** tier 1, `equality_set`.
   - **Sources:** GET `hsrp-group-info` and `vrrp-oper-state`, both
     `ok_404`.
   - **Keys:**
     - `hsrp|<interface>|<group>` → `state`, `vip`, `priority`, `preempt`,
       `active_ip`, `standby_ip`;
     - `vrrp|<interface>|<group>|<af>` → `state`, `vip`, `priority`,
       `preempt`, `owner`, `master_ip`.
   - **Context:** VRRP `master-transitions` (read as a delta), the new-master
     reason, and track states.
   - **Not-present:** when both models are absent or empty, which is the
     norm on an access stack.
   - **Why:** a flipped active router or a split brain is invisible while
     every SVI reads up.
10. **`iosxe_mac_table`: are endpoints being learned where they were?**
    - **Tier and compare:** tier 2, capability (`floor_pre` 5, `min_post` 1).
    - **Source:** GET `matm-table?fields=table-type;vlan-id-number;matm-mac-entry(mac;port;mat-addr-type)`.
    - **Buckets** (dynamic entries only): `total`, `vlan|<id>`,
      `member|<n>` and `port|<interface>`. Per-port buckets select
      themselves: only ports that carried five or more MACs, meaning uplinks
      and busy AP or FlexConnect ports, gate the comparison.
    - **Context:** static counts and the aging time. The model's address
      types are only `static`, `dynamic` and `any`; port-security's secure
      MACs live in `psecure-oper`.
    - **Raw:** MAC rows, capped like `constants.WLC_CLIENT_RAW_MAX`, so a
      prompt can join vendor MACs to ports.
    - **Why:** this is the one end-to-end L2 "endpoints are back" signal on
      a stack without 802.1X. It overlaps rec. 6, which is why it ranks
      last.

**Below the line** (real, but not top ten):

- **SSO readiness.** Once the stack branch lands, promote `stack-oper`'s
  per-member `sso-ready-flag` into `iosxe_switch_stack`'s `switch|<n>`
  keys. The check already fetches the payload and keeps it raw-only
  (`checks_iosxe.py:1640-1646`), so this costs no request. Read `ha-oper`
  `ha-infra` (`ha-state`, `peer-state`, last switchover) for one more GET
  only if the flag proves unpopulated or misleading on the standby (§9).
  `install-oper` `oper-state/sso-state` (`Cisco-IOS-XE-install-oper.yang:913`)
  is a system-wide flag that would ride rec. 1's GET if added to its
  filter.
- **License level and SDM template.** Only if a field incident needs them:
  the level in effect from `cisco-smart-license` `licensing/state` usage
  (one GET), the SDM template from `show sdm prefer` (no model). Both
  belong beside rec. 1, since both change at the next reload.
- **Repair `iosxe_ntp` against the model** (§10). This is a fix, not a new
  check.
- **EIGRP/IS-IS adjacency checks**, at sites that run them. Their models
  exist.
- **Context-only readings**, if a field incident ever needs them: PKI
  `validity-end` (`crypto-pki-oper`) and TCAM/`switch-dp-resources-oper`
  utilization.

**Cost and build order.**

- All ten together add 8 GETs and 2 SSH commands per capture. The present
  catalog issues about 20 GETs and a dozen SSH commands on a 9300.
- **Build order:**
  0. The model probe (§9), run twice on the stack an hour apart, so every
     normalizer below is written against real payloads.
  1. Recs. 7, 8 and 1. They need no new request, or one. Rec. 8's
     `show logging` and rec. 1's `_HW_PATH` leaves are already in today's
     shakedown trace; rec. 7's widened leaves and rec. 1's install rows
     arrive with the probe.
  2. The layer-2 trio: recs. 2, 3 and 4.
  3. Recs. 5, 6 and 10.
  4. Rec. 9, when a distribution 9300 is in scope.
- **Rules for every item:**
  - It lands **between change windows**. A pre captured on older code
    against a post on newer code shows every new field or check as a
    difference.
  - It registers a CheckDef, its SEMANTICS, a README catalog row, and
    stdlib tests on sanitized fixtures (synthetic serials and MACs of the
    real shape).
  - Each new model goes into `IOSXE_KEY_MODELS` (`shakedown_job.py:67-83`),
    so the shakedown's `key_models` answers "served?" at a glance.
    `matm-oper`, `interfaces-oper`, `cdp-oper` and `device-hardware-oper`
    are already listed there (`:73-78`).
  - Every `fields` filter gets one unfiltered retry on HTTP 400, as
    `iosxe_aaa_servers` does (`checks_iosxe_wireless.py:1455-1461`),
    except rec. 6's, whose unfiltered form carries usernames.
  - Two healthy captures an hour apart must diff to nothing.

## 9. Assumptions and unknowns a field capture settles

Today's Test Suite Shakedown runs the registered checks plus three IOS-XE
discovery probes: `modules`, `rib_names` and `fib_instances`
(`DISCOVERY_PROBES`, `shakedown_job.py:329-334`). It always runs with
`debug=True` (`:463`), so its trace carries every payload and every SSH
output in full. That settles §9a. It cannot settle §9b, because nothing
issues those requests yet.

### 9a. Settled by today's shakedown

1. **Which of the eight models behind the new checks the stack's image
   serves:** install, VLAN, spanning-tree, PoE, identity, HSRP, VRRP and
   MATM. Answered by `discovery.modules` (`shakedown_job.py:94-104`).
   `matm-oper` already appears in `key_models`; the other seven will once
   they are added.
2. **The stack's IOS-XE release.** The field notes do not record it. 17.9
   versus 17.12 changes revisions, not the paths recommended here.
3. **Whether `device-system-data` fills `unsaved-config`,
   `software-version` and `rommon-version` on a 9300.** Answered by the
   `_HW_PATH` payload in the trace. The 9500 fixture has the versions but
   not the flag.
4. **What `sso-ready-flag` reads on the standby when it is HOT.** The field
   capture shows `false` on members 1, 3 and 4, but member 2, the standby,
   was not captured. Answered by the `stack-oper` payload that
   `iosxe_switch_stack` keeps in raw.
5. **Whether CDP fills `native-vlan` and `vvid`** for switches, APs and
   phones.
6. **Syslog.**
   - The `logging buffered` size and level.
   - How many hours the buffer spans on a busy 802.1X stack.
   - The actual severities of the allowlisted mnemonics on this release.
7. **Which `ntp-oper` leaves are populated.** This settles §10's first
   defect.

### 9b. Settled only by a probe

**The probe (build step 0).** Add one `model_probes` entry to the IOS-XE
discovery probes. It issues the read-only requests below, records each
answer's outcome and size under `discovery`, and leaves the full payloads in
the trace. A separate sister Job could issue the same requests, but the
shakedown already has the device, both transports and the full-payload
trace, so an entry there needs no new Job and costs nothing in a capture.
Every command passes the SSH allowlist (`show ` is the only IOS-XE prefix,
`transport_ssh.py:30-33`). Run the shakedown twice, an hour apart, for the
stability questions.

- GET `install-oper-data/install-location-information` with rec. 1's
  `fields` filter.
- GET `Cisco-IOS-XE-vlan-oper:vlans`.
- GET `Cisco-IOS-XE-spanning-tree-oper:stp-details`.
- GET `Cisco-IOS-XE-poe-oper:poe-oper-data`.
- GET `identity-oper-data/session-context-data` **with rec. 6's `fields`
  filter only**. Unfiltered, it returns usernames.
- GET `Cisco-IOS-XE-hsrp-oper:hsrp-oper-data` and
  `Cisco-IOS-XE-vrrp-oper:vrrp-oper-data`, both `ok_404`.
- GET `matm-oper-data` with rec. 10's `fields` filter.
- GET `interfaces-oper` for every port with rec. 7's widened `fields`
  filter, and one access port and one uplink without a filter, each
  addressed by its list key (`…/interface=TwoGigabitEthernet1%2F0%2F1`), to
  see which leaves are populated at all.
- SSH `show vlan brief`, `show vtp status` and `show interfaces trunk`.

The alternative is to ship each check as a best guess that keeps its payload
in raw, and let the shakedown's "parsed but empty" advice drive refinement
(`registry.py:782-806`). That is how `iosxe_svl_health` and `iosxe_ntp` were
built (`checks_iosxe.py:741-748`, `:881-885`), and it suits tier-3 checks.
The tier-1 keys proposed here should not reach a change window before two
healthy runs show them stable, and the probe gets the same payloads without
touching a capture. Its traces carry MACs, serials and hostnames, so sanitize
them before committing fixtures.

8. **`install-location-information` rows per member.**
   - How `chassis` maps to switch numbers. The `hw-dev-index` lesson says to
     check, not assume.
   - Which `fru`, `slot` and `bay` values each row carries (rec. 1's key).
   - The steady-state `auto-abort-timer` value.
9. **`vlan-oper` `ports` and `vlan-interfaces`.**
   - Does each list hold access ports only, or trunks too?
   - Is voice-VLAN membership listed?
   - Are down ports included?
   - Does `ports` list an 802.1X port under its RADIUS-assigned VLAN while
     the session is up, as `show vlan brief` does?
   - Does anything mark a port as 802.1X-controlled, so static ports could
     get normalized per-port keys (rec. 2)?

   Compare the payload with `show vlan brief`.
10. **Which VTP mode the stack runs.** In server or client mode the VLAN
    lines are absent from the config text.
11. **Spanning tree.**
    - How `instance` is spelled (`VLAN0010`? `MST0`?).
    - How `root-port` numbers map to names.
    - Row counts on the stack.
    - Whether the designated-forwarding exclusion keeps two runs identical.
12. **`show interfaces trunk`.**
    - Its exact layout on the stack's release, including how VLAN lists
      wrap.
    - Whether the not-pruned set moves between two runs where VTP pruning
      is on.
13. **PoE.**
    - Which list is populated: `poe-port` or `poe-port-detail`?
    - Does `poe-stack`/`poe-switch` describe StackPower on the 48UXM stack?
    - Is per-port oper state stable across two runs?
    - Do the per-switch budget figures move with PoE demand under
      StackPower sharing?
14. **`identity-oper`.**
    - Is it populated for IBNS 2.0 sessions?
    - Is the `fields` filter accepted?
    - What is the payload size per session?
    - Does the stack run 802.1X at all (otherwise the check records
      not-present)?
15. **HSRP/VRRP on an access stack: a 404 or an empty 2xx?** The answer
    decides the `not-present` rule.
16. **`matm-oper`.**
    - Payload size.
    - Entry types.
    - Whether CPU or router MACs appear.
    - What `vlan-id-number` means for non-VLAN table types.
17. **The widened `interfaces-oper` leaves.**
    - Are `ether-state`, `storm-control`, `diffserv-info` and
      `intf-ext-state` populated on access ports?
    - Does `port-error-reason` agree with
      `show interfaces status err-disabled` for an err-disabled port?
    - How noisy is host-port speed renegotiation across two runs?

### 9c. Settled by the config-text check

18. **Real per-section line counts.** The first config-text capture replaces
    §5b's model, including the actual per-port stanza size, and shows
    whether `sdm prefer` prints in the running-config (P9).

## 10. Coverage defects found along the way (not fixed here)

- **`iosxe_ntp` reads leaf names that the model does not define.**
  - The normalizer looks for sync leaves `sys-status`, `clock-state`,
    `assoc-status` and `status` (`checks_iosxe.py:889`), and for refid
    leaves `sys-refid`, `refid` and `server` (`:891`).
  - In 17.9.1, `ntp-status-info` (`Cisco-IOS-XE-ntp-oper.yang:777`, built
    from the grouping `ntp-container-data`, `:713`) has no sync leaf. Its
    `refid` is a container (`:716`) whose content is one case of the choice
    in `refid-pkt-content` (`:560`): `ip-addr`, `kod-data`,
    `ref-clk-src-data` or `exception-code`. `stratum` is at `:732`.
  - Each association carries its own `refid` (`:633`) and marks selection
    with `peer-selection-status` (`:690`, values `ntp-peer-sys-peer` …).
    17.12.1 is identical.
  - Per the model, then:
    - `synchronized` is never emitted;
    - `server` becomes `str()` of the `refid` dict;
    - the association fallback cannot match, because it reads the same
      invented names.
  - Loss of sync would show as `stratum` 16 (unsynchronized) and, where the
    device fills the refid, as a changed `server` string: a KoD code such
    as `INIT` in place of an address. The check still catches it, but only
    by accident of `str()`.
  - The tests use invented leaf names (`tests/test_checks_iosxe.py:443-478`).
    *Field capture* confirms what the device fills.
- **`iosxe_interfaces` requests `vrf` (`checks_iosxe.py:40`) but never
  normalizes it (`:448-452`).** A VRF membership change is raw-only. Rec. 7
  fixes this.
- **`iosxe_dhcp` also returns the DHCP-snooping globals (G6).** Its SEMANTICS
  (`registry.py:212-217`) and its `not-present` message (`checks_iosxe.py:666`)
  still describe server and relay config only. A switch with snooping but no
  pools records the snooping blob under a description that does not mention
  it.
- **`iosxe_syslog_errors` counts severities 0–3 only (`:694-698`).** The
  choice is deliberate and was right for noise. Its cost is the transient
  record of err-disables, FHRP changes, MAC flaps, PoE denials and 802.1X
  failures, which rec. 8 recovers without the noise.
- **The `show logging` text leaves the device unscrubbed.**
  - Raw keeps the last 20,000 characters verbatim (`checks_iosxe.py:723`).
    A debug trace keeps the whole output (`jobs/context.py:159`): always in
    the shakedown, and in a capture when its `debug` option is set
    (`jobs/snapshot_job.py:191`). Neither is redacted.
  - Log lines name users: `%SEC_LOGIN-5-LOGIN_SUCCESS` carries
    `[user: …]`.
  - With `archive` / `log config` / `notify syslog` and no `hidekeys`
    (M11), `%PARSER-5-CFGLOG_LOGGEDCMD` records every typed command,
    including a `key 0 …` or a `password …` in clear text. The message
    formats are product knowledge; the capture of a stack that logs
    commands would confirm them.
  - That breaks two of the repo's own rules: secrets never leave the device
    inside a snapshot (`checks_iosxe.py:962-967`), and usernames never enter
    one (`checks_iosxe_wireless.py:103`). The config-text check's redaction
    should also scrub this raw text, and rec. 8 keeps only tags and
    timestamps in context.
