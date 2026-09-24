# Test-plan prompt: NFV core move (ESXi on SE350 + VM-Series + core switches)

Paste the prompt below into your approved LLM along with the pre and post
`snapshot_*.json` files: per SE350 the ESXi host file (`snapshot_<site>-se350-N`)
and its XCC file (`snapshot_<site>-se350-N-xcc`), the VM-Series files, and the
9500 / 9300 files. Adapt the specifics — the planned uplink map, the declared
removals, whether the management subnet was re-addressed, whether motion
detection was disarmed for the window — per change; the files explain their
own format, so the prompt never has to. Where a fact below is bracketed, fill
it from the change record before pasting. Attach `tools/diff_snapshots.py`
output when the tables are large (the XCC event log, the PCI inventory, the
9300 MAC tables) so the LLM interprets an exhaustive index instead of doing
its own set arithmetic.

This is the ONLY place change-specific language belongs. The collectors know
nothing about floors, moves or declared removals: the `vmware` platform is
"ESXi set up as NFV compute" in general and the `xcc` platform is "an SE350
BMC" in general — every check is always-on and `not-present` is recorded, not
skipped. The comparison is directed entirely from here.

---

You are a senior network and virtualization engineer performing POST-CHANGE
TRIAGE using before/after operational snapshots (attached JSON files). Each
file explains its own format in its top-level "guide" and per-check
"describe" fields — trust those for sentinel meanings (null = unreadable,
absent = unmeasured, 0 = measured zero; "not-present" = feature legitimately
unused). Pair files by device name: each SE350 has TWO files per capture —
the ESXi host (platform vmware) and its XClarity Controller (platform xcc) —
and both must be read together.

THE CHANGE: a remote office collapsed from two floors to one. The core moved
with it: a Catalyst 9500 pair (StackWise Virtual), the NFV compute — Lenovo
ThinkSystem SE350 edge servers (gen-1) running standalone ESXi 8.x, hosting
the Palo Alto VM-Series firewall HA pair (PAN-OS 11.2.7+, vmxnet3 adapters,
L2 / virtual-wire mode, the two HA peers on SEPARATE SE350s) — and the
access 9300 stacks that remain. The SE350s were powered down cleanly,
physically carried, re-cabled to [the planned floor-5 ports] and powered
back on; the VM-Series rebooted as part of that. The management subnet
MOVED with the floor: vmk0 and XCC addresses were re-addressed to
[new subnet], and the Nautobot primary IPs were updated between captures.
CDP is enabled between the SE350 vSwitches and the switches. The declared
removals — access switches and APs that no longer exist after the
consolidation — are listed in the EXPECTED DIFFERENCES block below and in
each file's change_description; those two lists must match.

YOUR JOB IS TRIAGE, NOT A DIFF REPORT. Surface only what did NOT survive
the move and needs immediate attention. Do not enumerate every difference.
If everything looks healthy, say so in two sentences and stop.

PRIMARY SUCCESS INDICATORS, in order:
1. Identity invariants per SE350: vmware_host_identity serial/uuid/build/
   BIOS, xcc_system serial/uuid/model, xcc_firmware and xcc_bios all equal
   to pre. The ONLY declared differences on this front are boot_time,
   reboot_count, power-on hours and (if the operator updated it) the XCC
   Chassis Location record. A different serial or a changed BIOS setting is
   immediate-attention.
2. Security Pack: xcc_security_state lockdown_mode must read Inactive post
   (absolute). motion_detection_enabled true -> false TOGETHER with
   lockdown_mode Active is the tamper signature, not an operator edit.
   xcc_event_log additions are limited to the declared CommonEventIDs
   [AC-lost / boot-complete codes]; any ADDED Warning/Critical thermal,
   PSU, DIMM or intrusion key is a hardware finding. An intrusion_sensor on
   xcc_chassis_location leaving Normal is immediate-attention.
3. The re-cabling chain, per uplink: vmware_pnics link_up and speed as pre,
   xcc_host_nics LinkUp, vmware_pnic_neighbors port_id equals the planned
   map (declared per vmnic below), iosxe_mac_table shows that vmnic's MAC on
   that switch port, and the new port's host-facing interface config equals
   the old port's trunk contract. A VANISHED cdp| key is a finding, not
   silence — discovery is listening on these vSwitches by configuration.
4. Virtual wiring unchanged: vmware_vswitches, vmware_portgroups (including
   VLAN 4095 trunks, the effective security trio, teaming — IP-hash implies
   a static EtherChannel on the switch), vmware_vlan_hints matching the
   trunk plan, vmware_vmknics. The management re-address is the ONLY
   declared vmknic/route/DNS difference.
5. Every VNF back: vmware_vms every VM poweredOn with tools running, uuid
   unchanged, reservations/latency_sensitivity/cpu_affinity unchanged,
   snapshot_count 0 on the VM-Series, has_pending_question false (a pending
   "moved or copied?" question means the firewall never booted);
   vmware_autostart enabled with the same start order; vmware_vm_nics every
   adapter label/pci_slot/backing/mac unchanged and connected;
   vmware_vm_tuning byte-identical; vmware_vm_disks backing paths unchanged.
6. VM-Series licence and HA after its reboot: panos_system_info serial not
   "unknown", the vm-uuid equal to vmware_vms uuid, vm-cpuid/vm-license
   fields unchanged, panos_ha restored with one active + one passive,
   dpdk-pkt-io and vm-license-type identical on both peers, and the HA1/HA2
   port groups present on BOTH hosts (the peers are on separate SE350s).
7. Storage whole: every vmware_storage_devices lun| key present and ok;
   vmware_datastores same uuid and name, accessible (free space is banded);
   xcc_storage RAID members healthy with no failure_predicted; xcc_inventory
   with no missing dimm|/pcie| keys; vmware_host_identity memory_bytes
   unchanged.
8. Thermal and power: xcc_thermal ambient/intake readings within band, every
   sensor OK, fans in band; xcc_power every PSU/adapter Enabled + OK with
   input_in_range true and redundancy intact on dual-fed units;
   vmware_health_sensors nothing red.
9. Time and telemetry: vmware_time_syslog ntp_service_sync true with the
   same servers and unchanged syslog targets; xcc_manager_network NTP and
   DNS set; iosxe_ntp and panos_ntp synchronized.
10. Nothing left behind by hands-on work: vmware_host_services (a service
    running post that was not running pre is troubleshooting residue; the
    reverse after a reboot is just the reboot), vmware_advanced_options (a
    REVERTED value means an unclean power-off, not sabotage), recent tasks
    quiescent, lockdown|mode unchanged, vcenter|management_server still
    null.

SECONDARY (check quickly, flag only if wrong):
- Core switches (9500s): SVL members and links up, boot-time changed
  (declared), routing tables / adjacencies / port-channels / optics
  unchanged except the declared removals, STP root unchanged, LACP partners
  unchanged.
- 9300 stacks: every member Ready with the same role/priority/serial,
  full-ring, reciprocal neighbors on the planned ports, trunk VLAN lists and
  MAC-table counts within band.
- Access/AP reduction: every removal in the manifest classified as expected;
  any removal NOT in the manifest is unexpected; any manifest entry still
  present post is a failed removal; errdisable additions are never expected.
- Cross-host assertions that need no collector: port group names/VLANs/
  security identical across all SE350s (a VM re-registered on a sibling
  must find the same wires); the HA peers on different hosts; per host the
  sum of vCPU reservations at most physical cores minus one (no overcommit
  on a single-NUMA SE350 after consolidation).

EXPECTED DIFFERENCES — DO NOT REPORT THESE AS FINDINGS:
- boot_time / bootTime, reboot_count, power-on hours, XCC clock, uptime and
  every counter on every device that was moved: the move IS a power cycle.
- The management re-address: vmk0 ip/netmask/gateway, dns| entries, the
  XCC ipv4_address/gateway, iosxe SVI addresses on [old management VLAN]
  -> [new management VLAN], and the resulting ARP/route rows.
- xcc_event_log entries with CommonEventID in [declared codes] (AC lost,
  power restored, boot complete) added during the window.
- xcc_chassis_location: [the operator updated the Location record to floor
  5 / the record was NOT updated — pick one and say so].
- vmware_pnic_neighbors port_id and iosxe_neighbors moving from the old
  port map to the planned one (declared per vmnic):
  [se350-1 vmnic0 -> 9500-A Twe1/0/N, vmnic1 -> 9500-B Twe1/0/N, ...].
- The declared removals on the 9500s/9300s: [list the access switches, APs,
  port-channels and SVIs that were decommissioned].
- Session, route-count and counter values drifting within normal churn;
  vmware_vlan_hints and observed subnets still populating for a few minutes
  after link-up; vmware_health_sensors reading unknown if the post capture
  was taken minutes after boot (say so as a caveat, do not alarm).
- The VM-Series: vm-uuid and vm-cpuid MAY change after a cold move on a
  different host — if they did, that is a licensing follow-up, not a
  forwarding fault; report it once under WATCH ITEMS.

OUTPUT FORMAT:
1. VERDICT — one line: HEALTHY / NEEDS ATTENTION / SERIOUS PROBLEMS, plus
   one sentence of justification.
2. IMMEDIATE ATTENTION — ranked list, max 10 items. Each: what is wrong, the
   device, the check id and exact key it rests on, the pre vs post values,
   and the one-line operational consequence. Omit the section if empty.
3. WATCH ITEMS — max 5 minor observations worth a look later. Optional.
4. CAVEATS — any check that failed to collect or reads unreadable is
   UNKNOWN, not clean: name it and say what cannot be assessed. A post-side
   collect failure on any device is a caveat, never a pass. State whether
   the post captures honoured the timing rules (at least 3 minutes after
   link-up, after the VM-Series reboot, same host power state as pre).

Claim nothing the data does not show; quote values verbatim. When a check is
"not-present" on both sides, it is not a finding. The suite proves STATE, not
forwarding: an end-to-end test through the VM-Series is a manual runbook step
and its absence must be named in the caveats.
