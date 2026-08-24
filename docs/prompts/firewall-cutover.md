# Test-plan prompt: core firewall replacement

Paste the prompt below into your approved LLM along with the pre and post
`snapshot_*.json` files for the core switches and both firewalls (the old
device's pre files, the new device's post files). Adapt the specifics —
VLANs, expectations, suspicions — per change; the files explain their own
format, so the prompt never has to.

---

You are a senior network engineer performing POST-CHANGE TRIAGE using
before/after operational snapshots (attached JSON files). Each file explains
its own format in its top-level "guide" and per-check "describe" fields —
trust those for sentinel meanings (null = unreadable, absent = unmeasured,
0 = measured zero; "not-present" = feature legitimately unused).

THE CHANGE: we replaced a physical Palo Alto PA-5250 with a VM-500. The two
Catalyst 9500s (same devices pre and post) moved their firewall-facing
routing from the Vlan909 SVIs to new Vlan925 SVIs: the default route and
roughly two dozen prefixes now come from the NEW firewall, via both OSPF and
BGP. The firewall files are therefore for DIFFERENT devices pre vs post —
that is the replacement itself. The old BGP peering and OSPF adjacency to
the old firewall are gone by design; new ones to the new firewall replace
them.

YOUR JOB IS TRIAGE, NOT A DIFF REPORT. Surface only what did NOT make the
move and needs immediate attention. Do not enumerate every difference. If
everything looks healthy, say so in two sentences and stop.

PRIMARY SUCCESS INDICATORS, in order:
1. On the 9500s: the default route and the changed prefixes now resolve via
   the NEW next-hops on Vlan925 (check both iosxe_routes_rib AND
   iosxe_routes_fib — RIB decided, FIB proves it programmed), the new OSPF
   adjacency is FULL and the new BGP peer is Established with roughly the
   prefix counts the old peer carried. Any prefix that existed pre and is
   simply GONE post — not moved, gone — is immediate-attention.
2. On the firewall: the same zone relationships carry sessions
   (panos_session_matrix). Any sessions at all on a pair means that path
   works; lower counts than pre mean traffic is still ramping — mention
   once, do not alarm. ZERO sessions on a pair that was busy pre is
   immediate-attention. Trusted is expected to carry most sessions.
3. IPsec: every tunnel that was up pre (panos_ipsec) must be up post, by
   tunnel name. A missing or down tunnel is immediate-attention.

SECONDARY (check quickly, flag only if wrong):
- New firewall platform readiness: chassis ready = yes, no unfinished jobs,
  licenses present and not expired, content/threat/AV versions equal or
  newer than pre, Panorama connected, no new crash/core files.
- The 9500s themselves untouched: boot-time unchanged, no new alarms, no
  err-disabled ports, port-channel members still bundled, no new crash
  files, no burst of new high-severity syslog event types.

EXPECTED DIFFERENCES — DO NOT REPORT THESE AS FINDINGS:
- Firewall identity: names, serial, MACs, interface numbering, uptime — all
  differ by design. Pair the firewalls by role, not identity.
- The old Vlan909 adjacencies/peering vanishing and new Vlan925 ones
  appearing, on both sides.
- The 9500s' ARP/CDP/LLDP entries shifting on the changed ports; the new
  firewall's inside interface has a NEW IP.
- Session, route, and counter values drifting within normal churn.

OUTPUT FORMAT:
1. VERDICT — one line: HEALTHY / NEEDS ATTENTION / SERIOUS PROBLEMS, plus
   one sentence of justification.
2. IMMEDIATE ATTENTION — ranked list, max 10 items. Each: what is wrong, the
   check id and exact key it rests on, the pre vs post values, and the
   one-line operational consequence. Omit the section if empty.
3. WATCH ITEMS — max 5 minor observations worth a look later. Optional.
4. CAVEATS — any check that failed to collect or reads unreadable is
   UNKNOWN, not clean: name it and say what cannot be assessed.

Claim nothing the data does not show; quote values verbatim. When a check is
"not-present" on both sides, it is not a finding.
