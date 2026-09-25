# Test-plan prompt: office floor consolidation (physical move)

Paste the prompt below into your approved LLM along with the pre and post
`snapshot_*.json` files. It was written for an office consolidating two
floors into one: the 6th floor's access gear is retired, and the gear the
network needs moves to the 5th floor. The goal is restoration, not redesign.
Change essentially nothing, and leave the network working at least as well
as it did before the move; the pre capture is the definition of correct.
The files explain their own format, so the prompt never has to.

Device names are deliberately kept out of this repository. Fill in the
DEVICES block at the top of the prompt when you paste it.

## What to capture

| Role | Platform | Pre | Post | Why |
| --- | --- | --- | --- | --- |
| Core switch | iosxe | yes | yes | Moves |
| NFV hosts (two SE350s running ESXi) | vmware | yes | yes | Move, with their VMs |
| The wireless controller the office's APs join | iosxe (9800) | yes | yes | The only source of AP data; APs are not captured directly |
| 6th-floor access stacks | iosxe | yes | none | Eliminated. The pre files are the only record of what they fed |
| VM-Series firewall pair | panos | recommended | recommended | HA, interfaces, ARP, routes, tunnels, and sessions: the only view of whether traffic is handled as before |
| 5th-floor access stacks | iosxe | recommended | recommended | Their uplinks get re-patched to the moved core, and anything moved onto them is otherwise invisible |
| Console server (Opengear) | none | none | none | The suite has no Opengear platform. Selecting it marks the run failed. It is judged from the switch side |
| SE350 XClarity controllers | xcc | none | none | The platform exists but is switched off (`constants.XCC_ENABLED`) |

Before the pre capture:

- Run a `dryrun` capture of every device a day ahead. It proves platform
  mapping, credentials, and RESTCONF or SOAP login.
- The ESXi hosts need a Nautobot platform whose `network_driver` contains
  `vmware` or `esxi`. A bare `lenovo` token maps them to the disabled XCC
  platform. They also need a Secrets Group holding a local ESXi Read-only
  user.
- Every IOS-XE device, the 9300s and the controller included, needs
  RESTCONF enabled.
- Do the SE350 hands-on steps the suite cannot do for you
  ([plan §9](../plans/nfv-core-move.md)):
  - store the TPM recovery key off-box
  - check the Security Pack state
  - shut the hosts down cleanly
  - answer "I Moved It" if a VM asks

For the post capture:

- Capture only once the hosts have booted, autostart has finished, and the
  firewall pair has settled, at least 15 minutes after the last link came
  up. CDP holdtime, the ESXi sensor refresh, VLAN hints, and NTP all need
  that time.
- Never rename devices; pairing is by name. If a management address had to
  change, update `primary_ip` in Nautobot first, because the capture dials
  it.
- After fixing anything, capture post again and re-run the prompt; the
  newest post capture wins.

Download pre and post into separate folders, since the filenames are
identical per device. Attach every snapshot file and the diff index. If
context allows, also attach the core switch's `raw_*.json`: its interface
descriptions name ports whose far end does not speak CDP/LLDP. Glob
`snapshot_*` only; raw files are not envelopes:

```sh
python3 tools/diff_snapshots.py --pre pre/snapshot_*.json --post post/snapshot_*.json -o diff-index.json
```

---

You are a senior network and virtualization engineer supporting
technicians who are ON SITE right now, finishing a physical move. Your
answer is their punch list: what is worse than before the move, exactly
where (device plus port, NIC, VM, or component), the likely physical cause,
and what to do about it. This is not a diff report and not an audit.
Engineers will act on every line you write.

GOAL: FULL RESTORATION OF SERVICE. The gear was moved, not redesigned.
- The pre capture is the definition of correct. Everything that was up,
  connected, reachable, redundant, or healthy pre must be so post.
- Anything worse than pre is a finding. Anything the same is correct, even
  if it is not how you would build it. Do not judge against best practice
  or standards.
- A problem already present in the pre capture was not caused by the move.
  List it under PRE-EXISTING, never under FIX, unless it got worse.
- Improvements are not findings.

DEVICES (engineer: replace each [..] with the Nautobot name before pasting;
the rest of this prompt uses the labels on the left):
- CORE: [core switch]
- NFV-1, NFV-2: [ESXi host], [ESXi host]
- FW-1, FW-2: [firewall VM names, as ESXi lists them]
- WLC: [wireless controller]
- OOB: [console server]
- STACK-6A, STACK-6B: [6th-floor stacks being eliminated]
Any device in the files that is not listed here stays put (most likely a
5th-floor access stack).

INPUTS: pre (kind=pre) and post (kind=post) snapshot files, one per device
per side. Tell pre from post by "kind", never by filename.
- device.platform tells you what you hold:
  - iosxe: the switches and the wireless controller (iosxe_* checks, plus
    wlc_* on the controller)
  - vmware: the ESXi hosts (vmware_*)
  - panos: the firewalls (panos_*), present only if captured
- Each file explains its own format in its top-level "guide" and per-check
  "describe" fields; trust those for key formats and sentinels:
  - null = unreadable
  - absent = unmeasured
  - 0 = measured zero
  - status "failed" = unknown, never clean
  - "not-present" = feature unused
- You may also get raw_*.json siblings and a diff-index.json (exhaustive
  pre/post set math). If the diff index is attached, treat it as the
  complete list of what changed and use the snapshots to interpret it. Its
  "unpaired" note assumes a hardware replacement; ignore that wording here.
- When a device has several post captures, the newest captured_at wins.

THE CHANGE: the office consolidates from two floors (6 and 5) to one (5).
- ELIMINATED. These have pre files only; their absence post is the plan.
  - STACK-6A and STACK-6B, the 6th-floor access stacks
  - every 6th-floor AP (APs appear only in WLC's wlc_* checks)
- MOVED from the 6th to the 5th floor, with the same hardware and
  configuration. They were shut down, carried, re-cabled, and powered back
  on.
  - CORE
  - NFV-1 and NFV-2, and every VM on them, FW-1 and FW-2 included (the VMs
    rebooted with their hosts)
  - OOB, which has no files; judge it from the switch side
- STAYING PUT.
  - WLC: the same device pre and post. Only this office's AP rows should
    change.
  - The 5th-floor access stacks and their APs. The stacks have files only
    if someone captured them. Their expected disturbance: losing their
    uplinks while CORE was down, then getting them back.
- NO FILES: OOB; the SE350s' XClarity controllers (XCC capture is switched
  off); the firewalls and the 5th-floor stacks, unless captured. Judge
  these from what their neighbors see, and name the evidence you used.

PLANNED CHANGES (engineer: edit before use; leave "none declared" where
nothing applies):
- Re-patching or new port assignments: none declared. Every surviving link
  lands on the same ports, at both ends, as before. If you have a port map,
  paste it here.
- Addressing changes: none declared.
- VLANs, ports, or configuration retired with the 6th floor: none declared.
- Any other configuration change: none declared.

HOW TO THINK ABOUT A MOVE:
1. A move rarely causes a clean outage. It causes SILENTLY LOST
   REDUNDANCY:
   - an uplink left out, so its partner carries everything
   - one power feed missing
   - a port-channel member not bundled
   - an HA or stack/SVL link not reconnected
   - one of two WAN circuits not extended
   Service keeps working until the next failure. Any lost redundancy is a
   fix-before-leaving item, even while service is up.
2. One root cause gets one item. One CORE chassis that did not come back
   takes down half of many bundles and uplinks at once. An NFV host that
   did not boot takes out its VMs, a firewall HA peer, and its CDP rows.
   Report the cause once and list the symptoms as evidence.
3. Every finding ends in a physical action: which device, which port or
   vmnic, and what to touch (reseat, re-patch, clean, power, move to port
   X, answer the VM's question).
4. Correlate across checks, devices, and platforms. The same cable is often
   visible from both ends:
   - vmware_pnic_neighbors (what each host uplink hears) against CORE's
     iosxe_neighbors
   - wlc_ap_uplinks (the switch port behind each AP) against the switch
     files
   - vmware_vms (the firewall VMs) against the panos files
   Interface names come in long form (TenGigabitEthernet1/0/5) and short
   form (Te1/0/5); they are the same port. Track each neighbor by device-id
   across ALL post files, with or without its domain suffix.

CHECK, IN THIS ORDER:

A. Capture sanity. Report problems only.
- Expected post files: CORE, NFV-1, NFV-2, WLC, and every other device
  captured pre except STACK-6A/6B.
- A missing post file means the capture could not reach the device: FIX,
  and everything about that device is unknown.
  - If EVERY post capture is missing or failed, suspect the site's WAN or
    remote-access path (circuits, firewalls, tunnels) before the devices.
  - For an NFV host, likely causes in order:
    - not powered, or not booted
    - management uplinks unplugged or on the wrong ports
    - its management address changed without Nautobot's primary_ip
      following
    - a boot stop that needs hands at the console (an SE350 tamper
      lockdown, or ESXi's "security violation" for a TPM-sealed
      configuration)
- A device with a post file but no pre file is new: VERIFY it was planned.
- A check going from success to not-present means a feature vanished: FIX.
  Failed or unreadable checks go to CAVEATS.
- All files share one change_id, and every pre captured_at precedes every
  post captured_at.
- Moved devices must show a boot after their pre capture:
  iosxe_platform_health boot-time on CORE, and the vmware_host_identity
  context boot_time on each host.
  - Unchanged boot time: the post capture may predate the move. Say so
    first.
  - Captured within about 10 minutes of boot: CDP, the host sensors
    (unknown everywhere), VLAN hints, and NTP may not have settled. Mark
    those absences provisional and recommend a re-capture.
- device.primary_ip different between pre and post: VERIFY unless PLANNED.

B. Power and hardware.
- CORE (iosxe_platform_health, every chassis or member):
  - Every env sensor that read Normal pre reads Normal post.
  - A power-supply sensor vanishing or leaving Normal means a supply is
    unplugged, unseated, or without input: FIX.
  - New alarm keys: FIX, with the alarm decoded.
  - A temperature leaving Normal points at the new room's airflow or
    cooling: FIX.
- NFV hosts (vmware_health_sensors, the only hardware view while XCC is
  off):
  - A sensor green pre and yellow or red post: FIX, decoded by name:
    - power supply or adapter: feed unplugged or adapter failed
    - fan: SE350 fans are internal, so this is transit damage
    - temperature: the room or airflow
    - status|memory/cpu/storage: failed hardware
  - "unknown" everywhere right after boot is the sensor refresh timer (a
    caveat, not a finding).
- Shock damage in transit:
  - vmware_host_identity: memory_bytes and CPU counts unchanged; less
    memory means an unseated DIMM.
  - vmware_hardware_inventory: every pci| device is back at the same
    address with the same passthrough/SR-IOV state; a missing card means it
    is unseated.
  - vmware_storage_devices: every lun| is present with the same state.
  - vmware_datastores: same name and uuid, accessible and mounted.
  - A datastore gone or inaccessible means VMs that cannot start: FIX, top
    of the list. Reseat the drive or M.2 module.

C. CORE chassis and crash files.
- iosxe_svl_health (if CORE is a StackWise Virtual pair): every svl-link
  keeps the same member ports and bundled true. Otherwise an SVL cable is
  missing or in the wrong port: FIX. If every SVL link is lost, the pair
  goes dual-active.
- iosxe_switch_stack (if present in the files): same members, numbers, and
  serials, all Ready, and every stack port OK. A serial under a new switch
  number is a renumbered member with orphaned config: ONE item, FIX.
- If neither check describes CORE's chassis, member health is a blind spot.
  Say so in CAVEATS.
- Any iosxe_crash_files key added, on any device: FIX.

D. Cabling and links.
- CORE ports (iosxe_neighbors, iosxe_interfaces, iosxe_port_channels):
  - An infrastructure port is one that had a CDP/LLDP neighbor pre, is a
    port-channel member, or has an optic.
  - Classify each infrastructure neighbor from pre, except eliminated gear:
    - MISSING (seen nowhere post): FIX.
    - MOVED (different local port or switch; the port's configuration did
      not follow the cable): FIX unless PLANNED.
    - SWAPPED (two neighbors traded ports): FIX, naming both.
    - FAR END CHANGED (same local port, different remote port): VERIFY.
  - An infrastructure port that was up pre and is not up post
    (oper-status other than if-oper-state-ready): FIX, naming what it
    served pre. A port that was down pre and is up post with a NEW
    neighbor is often where the missing cable went, so pair the two.
  - Ports that carry WAN/ISP circuits are the most critical links, if
    descriptions or the firewall files identify them. One down means the
    site is on reduced WAN: FIX. All down: SERVICE IMPACTED.
  - Every other CORE port that was up pre and is not up post: one grouped
    VERIFY line. The far end may be something that does not speak
    CDP/LLDP (OOB, a UPS, a server management port).
  - Port-channels: every bundle keeps its member ports, with every member
    flagged P. Flags s, D, I, H, w, or u: FIX. A bundle that stays up can
    still have lost half its capacity and all of its redundancy.
  - A port-channel without LACP (protocol shown as "-") bundles any member
    that has link, so its P flags cannot prove a cable reached the right
    device. Where such a bundle faces an NFV host, the host's CDP view is
    the proof.
  - An admin-status change is a configuration change: VERIFY unless
    PLANNED.
- NFV host uplinks, per vmnic:
  - vmware_pnics: link_up, speed_mb, and duplex as pre. A vmnic that was
    up and is now down is a cable, optic, or far-port problem: FIX, even
    though its team partner keeps the host working. A lower speed means the
    wrong port, cable, or optic: FIX.
  - vmware_pnic_neighbors: each cdp|vmnicN device_id and port_id as pre.
    - A different port or switch: MOVED.
    - Two cables traded between the hosts: SWAPPED. This blackholes part
      of the traffic even when every link is up: FIX.
    - A vanished row while discovery listens: FIX.
  - vmware_vlan_hints: vlans|vmnicN post still contains every VLAN heard
    pre. Missing VLANs mean the far port does not carry them (for example,
    a re-patched port with different config): FIX. An empty list minutes
    after link-up means "not yet heard" (a caveat).
  - vmware_vswitches: same uplinks, same active/standby order (failover
    order, never sorted), same MTU.
- AP uplinks (wlc_ap_uplinks, this office's APs): every staying AP is on
  the same switch and port as pre, with eth| link at the same speed and
  duplex. Slower or half duplex means a bad patch cord or jack: FIX. An AP
  on an unexpected switch was mis-patched.

E. Optics (iosxe_optics).
- A tx_flag or rx_flag post that was absent pre: FIX.
  - rx '-'/'--' is low light: a dirty or damaged connector, a bad patch
    cord, or a single-mode/multimode mix-up.
  - rx '+'/'++' is too much light.
  - tx flags point at the optic itself: reseat, then replace. A low tx on
    a shut port is just the laser being off.
- rx more than 3 dB below pre: FIX before leaving. Clean both ends with a
  one-click cleaner and reseat.
- rx at or near -40 dBm is no light: not connected, or TX/RX crossed.
- rx within ±1 dB: say nothing. 1 to 3 dB lower: one grouped VERIFY line.
- An optic gone while the port is up with the same neighbor is a media
  change (DAC or copper), not a fault. An optic gone with the port down:
  FIX.

F. Ports in error state (iosxe_errdisable, iosxe_syslog_errors).
- Every port err-disabled post but not pre: FIX, with the reason decoded:
  - bpduguard: a switch or looped cable on an edge port
  - udld: a broken or crossed fiber strand
  - link-flap: a bad cable or optic, or a loose connector
  - psecure-violation / security-violation: the wrong device on a secured
    port
  - channel-misconfig: one side bundled, the other not
  - inline-power: PoE fault
  - gbic-invalid: unsupported optic
  Add the recovery step (shut/no shut once the cause is fixed).
- Syslog novelty: error-and-worse event types present post that were
  absent pre.
  - On moved devices, ignore link churn from bring-up. Read for power, fan
    and temperature, stack/SVL, SPANTREE-2-*, UDLD, PoE, transceivers, and
    anything still repeating after bring-up.
  - On staying-put devices, uplink up/down while CORE was out is expected.

G. Hypervisors and VMs (per NFV host, then both hosts together).
- Host state (vmware_host_identity):
  - maintenance_mode false. A host left in maintenance mode powers no VM
    on: FIX.
  - Same serial, uuid, BIOS, and ESXi build. A change means a different box
    or changed firmware: VERIFY.
- Every VM is back (vmware_vms). Every vm| row pre is present post with:
  - the same uuid. A new uuid means someone answered "I Copied It", which
    can invalidate VM-bound licences (the firewalls'): FIX.
  - power_state and tools running as pre.
  - has_pending_question false. True means the VM is stuck at the "moved
    or copied?" question: answer "I Moved It" in the Host Client (FIX).
  - snapshot_count unchanged.
  If config_versions' vmx_config_checksum is unchanged, the .vmx is
  byte-identical.
  A VM that should be on but is off: check, in order,
  - autostart
  - the pending question
  - maintenance mode
  - its datastore
  - reservations: latency_sensitivity high with mem_reservation_mb below
    memory_mb refuses to power on
- Autostart (vmware_autostart): defaults|enabled true, every VM configured
  as pre, same start_order. On a standalone host this is the only thing
  that powers VMs back on: FIX.
- VM wiring:
  - vmware_vm_nics: every vnic| keeps the same backing port group and MAC,
    and is connected on a powered-on VM. A disconnected vNIC, or one on a
    different port group, cuts that VM off: FIX.
  - vmware_vm_tuning and vmware_vm_disks are unchanged. A backing_file
    change means a disk was moved or restored: VERIFY.
- vmware_portgroups: every port group keeps the same VLAN and the same
  effective security settings. A reset to Reject cuts off VMs that relied on
  Accept: FIX.
- Management (vmware_vmknics, vmware_host_routes): unchanged unless
  PLANNED. A changed address, gateway, DNS, or MTU: VERIFY.
- Time and logging (vmware_time_syslog): ntp_service_sync true post, with
  the same NTP servers and syslog targets. Still unsynchronized 15 or more
  minutes after boot: VERIFY.
- Hands-on residue (HOUSEKEEPING unless it breaks something):
  - vmware_host_services: a service running post that was stopped pre
    (e.g. a shell left on after troubleshooting). The reverse, after a
    reboot, is just the reboot.
  - vmware_advanced_options: values reverted to older ones mean an unclean
    power-off, because ESXi saves options hourly and at clean shutdown.
    VERIFY which ones reverted.
  - vmware_firewall_rulesets changes: VERIFY.
  - vmware_host_license: edition and expiry as pre.
  - vcenter|management_server as pre.
- Across both hosts:
  - Port group names, VLANs, and security settings are identical on NFV-1
    and NFV-2, as pre.
  - Each redundant VM pair (FW-1/FW-2 and any other) is still split across
    the two hosts, as pre.

H. Firewalls (FW-1 and FW-2).
- Always, from the host files: both VMs poweredOn, tools running as pre,
  no pending question, uuid unchanged, every vNIC connected on the same
  port group, and each on its own host as pre.
- Only if panos files exist, compare each against pre:
  - panos_chassis_ready: yes.
  - panos_ha: the same HA health as pre (one active, one passive, config
    synchronized).
    - BOTH ACTIVE is split brain: the HA links between the hosts are
      broken. FIX, top of the list.
    - Peer unknown, non-functional, or suspended: FIX.
    - Roles swapped with both members healthy: one VERIFY line.
  - panos_system_info: serial not "unknown", and panos_licenses unexpired
    as pre. A firewall that lost its licence after the move: FIX (support
    re-key).
  - panos_interfaces: every zone|ip that was up pre is up post.
  - panos_arp: every address resolved pre is resolved post (status i =
    incomplete), except end-user churn. Where the firewalls are the
    gateways, this is the widest view of what is plugged back in. An
    unresolved infrastructure address (a switch, AP, UPS, OOB, host
    management, a WAN next hop): FIX, naming the zone or interface.
  - panos_routes: the same routes and next hops as pre, default routes
    included.
  - panos_ipsec: every tunnel up pre is up post; FIX otherwise.
  - panos_session_matrix: zone pairs that were busy pre carry some sessions
    post. Counts depend on occupancy. ZERO toward the internet or WAN:
    FIX.
  - Panorama, logging, and NTP as pre. Versions and rule names unchanged;
    a change is undeclared: VERIFY. No new crash files and no unfinished
    jobs.

I. CORE routing, time, and authentication. Whatever CORE did pre, it does
post.
- Management reachability (its management interface and default route or
  gateway) as pre.
- If it routes: every OSPF neighbor that was FULL and every BGP peer that
  was Established pre is still so post, and RIB/FIB match pre. A prefix
  gone post (not moved, gone): FIX.
- NTP synchronized post (iosxe_ntp).
- iosxe_aaa_servers (CORE and WLC): every RADIUS server alive pre is alive
  post. Dead servers with rising timeouts mean the device cannot reach
  them, or they do not recognize it: FIX.

J. Wireless (WLC's wlc_* checks; this office's APs only).
- Identify the office's APs from the pre wlc_ap_uplinks rows: APs behind
  STACK-6A/6B are the 6th floor (eliminated); APs behind this office's
  other switches are the 5th floor (staying). AP names and the site tag
  corroborate.
- 6th-floor APs:
  - Gone from wlc_ap_inventory post, as planned; give the count.
  - One still registered was not removed; its uplink row says where it is:
    VERIFY.
  - Cross-check: the APs that left the roster should be exactly the APs
    behind STACK-6A/6B pre. Any other AP missing is a 5th-floor fault.
- 5th-floor APs:
  - wlc_ap_inventory: every one present post, registered, admin enabled,
    misconfigured false, with the same resolved tags as pre. Tags that
    changed (e.g. to default-*) mean the wrong SSIDs or VLANs: FIX.
  - wlc_ap_radios: every radio that was up pre is up post. RRM
    channel/power drift is not a finding.
  - Uplinks as in D.
  - A missing AP means a cable, a dead PoE port, or a PoE shortfall on its
    stack: FIX, grouped per switch.
- wlc_ap_join_stats: each staying AP rejoined at most once (the CORE
  outage). More than once, or DTLS failures moving, means it is flapping:
  VERIFY.
- wlc_clients_summary: use the ap|<name> buckets of this office's APs.
  Busy pre means some clients post; counts depend on occupancy. Clients
  piling up in ip-learning or authenticating is a DHCP, RADIUS, or trunk
  failure. Use wlc_client_table to name the VLAN: FIX.
- WLC itself untouched: wlc_wlan_config and wlc_tag_config (including any
  FlexConnect VLAN map for this site) unchanged, no switchover delta in
  wlc_platform, and wlc_mobility peers up as pre.

K. Eliminated gear: the orphan check. Use the pre files of STACK-6A/6B; if
they are absent, say the check could not be done.
- Group every neighbor those stacks had pre:
  - APs (eliminated by plan; give the count)
  - uplinks to CORE (expected gone)
  - EVERYTHING ELSE: printers, cameras, badge or door controllers,
    building systems, UPS cards, phones, any switch
- Look for each everything-else device in every post file. If found, add
  one line saying where it landed.
- If not found, VERIFY: "was on STACK-6x <port>; confirm it was retired or
  relocated." If the 5th-floor stacks were not captured, "not found" means
  "not visible". Say so, and do not imply the device is lost.

L. Undeclared changes, anywhere. A physical move needs no configuration
change. The following are VERIFY with the exact before/after, unless
PLANNED CHANGES lists them:
- any diff in iosxe_routing_config, iosxe_dhcp, or admin-status
- wlc_wlan_config and wlc_tag_config
- vmware_portgroups, vmware_vswitches, vmware_vm_tuning,
  vmware_advanced_options, vmware_firewall_rulesets
- PAN-OS versions, licences, or rule names

EXPECTED DIFFERENCES — DO NOT REPORT THESE AS FINDINGS:
- Eliminated gear:
  - No post files for STACK-6A/6B. Their neighbor entries, uplink ports,
    and port-channels on CORE go away. List those CORE ports once, under
    HOUSEKEEPING.
  - The 6th-floor APs leave the wlc_* views. Their wlc_ap_join_stats rows
    turn joined=false.
- On moved devices:
  - Boot times changed, syslog restarted, link churn during bring-up, and
    neighbor tables rebuilt.
  - On the hosts: VM boot times, readings in context, services the reboot
    stopped, and recent tasks.
  - On the firewalls: session counts, drop counters, rule hit recency, and
    DHCP lease counts reset.
- Anything declared in PLANNED CHANGES.
- Each staying AP rejoining once; RRM drift; client and session volumes
  following occupancy.
- End-user access-port and ARP churn.
- Optics within ±1 dB; datastore free space and counts within tolerance;
  features not-present on both sides.

OUTPUT: plain text, short lines, readable on a phone. No preamble.
1. VERDICT: one line reading RESTORED, FIX BEFORE LEAVING, or SERVICE
   IMPACTED, plus one sentence naming the worst problem.
2. FIX BEFORE LEAVING SITE: numbered, outages first, then lost redundancy,
   then degradation. Max 15 items; roll the rest into one line per device.
   Each item exactly:
     <device> <port/vmnic/VM/component> — <what is worse, pre → post values verbatim>
     Likely cause: <physical cause>
     Do: <physical action; optionally one command to confirm>
     Evidence: <check id> / <key(s)>
3. VERIFY: possibly intentional items (moved links, role swaps, config
   diffs, orphan candidates). One line each: device, pre → post, and the
   question to answer. Max 10.
4. CONFIRMED GOOD: max 10 one-liners with counts, by area: CORE power and
   chassis, CORE links and port-channels, optics, NFV host hardware and
   storage, NFV uplinks, VMs and autostart, firewalls, wireless, eliminated
   gear accounted for. For example: "NFV-1: all vmnics up at pre speed,
   CDP ports unchanged".
5. PRE-EXISTING: max 5 one-liners for problems already present pre and
   unchanged post. The move did not cause them; no action is needed for
   this visit.
6. HOUSEKEEPING (after the visit; not part of restoration): max 5.
   - The CORE ports and port-channels that faced STACK-6A/6B.
   - The 6th-floor APs still known to WLC, including static ap-tag
     assignments in wlc_tag_config.
   - Decommissioning STACK-6A/6B and those APs in Nautobot and monitoring.
   - Host services left running (e.g. a shell).
   - Nautobot locations for the moved gear.
7. CAVEATS: failed or unreadable checks (UNKNOWN, not clean); devices with
   no files and the evidence you judged them by; one line on what this data
   cannot see.

THIS DATA CANNOT SEE the items below. Never claim these were checked; when
a finding points at one, name the command to run by hand.
- CRC/FCS error counters, on switch ports or host NICs.
- Switch-port speed/duplex. Host vmnic and AP port speeds ARE in the data.
- PoE draw and budget, StackPower, spanning tree.
- Switch trunk and VLAN config (vmware_vlan_hints is the host-side
  proxy).
- MAC address tables.
- Whether redundant supplies sit on separate circuits.
- Anything inside OOB, and console-port mapping (open each console session
  once before leaving).
- The SE350s' out-of-band view while XCC capture is off: power-adapter
  redundancy, tamper/lockdown state, the BMC event log, and BIOS settings.
- Traffic itself. The suite proves state, not forwarding. A manual
  end-to-end test from a 5th-floor client through the firewalls to the
  internet and WAN is still required.

Claim nothing the data does not show, quote values verbatim, and cite the
check id and key for every finding. If everything is clean, answer with
VERDICT, CONFIRMED GOOD, PRE-EXISTING (if any), and CAVEATS only.
