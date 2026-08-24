# Writing an LLM test plan for a change

The division of labor in this framework:

- **Nautobot captures.** `Capture Snapshot` produces one self-describing JSON
  per device per point in time (`snapshot_<device>_<change_id>.json`). Each
  file embeds its own interpretation guide, per-check descriptions, and
  curated context facts — a reader (human or LLM) holding one file needs
  nothing else to read it correctly.
- **The engineer writes the test plan — as a prompt.** The same person
  building the change's test plan writes what the LLM should verify, in
  plain language, with all the intuition and priorities a schema never
  captures. The prompt never explains the data format: the files do that.
- **The LLM analyzes.** Feed it the prompt plus the pre and post files (or
  sets of files) in whatever LLM your organization approves. Nautobot never
  contacts an LLM.

`Compare Snapshots` remains available as an optional deterministic assist —
its report enumerates every added/removed/changed key, which no attention
mechanism can guarantee over large tables. Attach its `report_*.json`
alongside the snapshots when you want the LLM to interpret an exhaustive
diff index rather than perform its own set arithmetic.

## The contract

**Files self-describe; the prompt describes the change and the tests.**

You never need to tell the LLM what `null` means, how zone-pair keys are
formatted, or that counters were excluded — the `guide` and per-check
`describe` blocks in every snapshot carry that. Spend the prompt entirely on:

1. What the change is (topology, before/after intent)
2. What "working" means for this change — ranked
3. What is expected to differ (so it isn't reported as a finding)
4. What to be suspicious of
5. Output you want (verdict first, findings with evidence, caveats)

## Worked example: core firewall replacement

> You are a senior network engineer reviewing a completed change using
> before/after operational snapshots (attached JSON files; each file explains
> its own format in its `guide` and per-check `describe` fields).
>
> **The change:** we replaced a physical Palo Alto PA-5250 ("fw-old") with a
> VM-500 ("fw-new") in our NFV environment. The core switch pair (the two
> 9500 files) stays the same hardware; its default route and roughly two
> dozen prefixes moved from the Vlan909 SVIs to new Vlan925 SVIs. The
> firewall files will be for DIFFERENT devices pre vs post — that is the
> replacement itself, so names, serials, interface numbering, and MAC
> addresses all differ by design and are not findings.
>
> **What matters most, in order:**
> 1. The same zone relationships carry sessions after as before. Use the
>    session-matrix check: any pair that carried real traffic pre must carry
>    SOME traffic post. Sessions present at lower counts mean functionality
>    is restored and ramping — note it, don't alarm on it. Zero sessions on
>    a previously busy pair is a finding.
> 2. On the core switches: the declared route moves happened (next-hops now
>    on Vlan925), and NOTHING ELSE in the routing tables changed. Any other
>    prefix appearing, vanishing, or changing next-hop is a finding.
> 3. The firewall's own route table, zone/IP interface map, IPsec tunnels,
>    and licensed features should match across the replacement. Content/
>    threat/AV versions must be equal or newer on the new firewall.
> 4. The core switches themselves must be untouched: boot-time unchanged, no
>    new alarms, all non-firewall adjacencies identical.
>
> **Output:** start with a one-paragraph verdict (healthy / investigate /
> concerning). Then findings ranked by operational severity, each citing the
> exact check id and key it rests on, with the before/after values. Close
> with caveats: any check that failed to collect or reads as unreadable is
> unknown, not clean — say so explicitly. Claim nothing the data does not
> show.

Adapt freely — add suspicions ("watch NAT pool behavior, we changed DIPP
settings last month"), ask questions, have a conversation with the LLM about
what it found. The files stay authoritative; the prompt is yours.

## Practical notes

- Download the `snapshot_*.json` files from each capture JobResult (Advanced
  tab). One change id ties all captures for a change together.
- The `raw_*.json` sibling holds verbatim device output per check — attach
  it too when you want the LLM to dig beneath the normalized view.
- Set `change_description` when capturing: it embeds the change intent into
  every file, so even a stray snapshot found later explains itself.
- Big tables (full RIBs) are where LLM attention is weakest. That is what
  the optional `Compare Snapshots` diff index is for — deterministic set
  math the LLM interprets instead of performs.
