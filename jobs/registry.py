"""Check registry and test packages. Pure: stdlib only, no Nautobot.

A check is a small declarative unit (ANTA-style): identity, platform, tier,
compare config, a one-line *miss interpretation* rendered next to failures,
and a collector callable. Collectors receive a CollectorContext (built by the
capture job) and return ``{"raw": <any>, "normalized": <dict>}``; they raise
SkipCheck when the feature legitimately is not present, and CollectError when
a required read failed — a failed read is never treated as emptiness.

Selection is data, not code: PACKAGES maps a package name to check ids; the
capture job filters the chosen package to the device's platform at run time.
"""

from dataclasses import dataclass, field


class CollectError(Exception):
    """A required read failed; the check is recorded as failed."""


class SkipCheck(Exception):
    """The feature is not present/configured; recorded as not-present, loudly."""


@dataclass(frozen=True)
class CheckDef:
    id: str
    platform: str  # "iosxe" | "panos"
    description: str
    tier: int  # 1 keyed assertions, 2 full-table diffs, 3 context
    compare: dict
    miss_meaning: str
    collector: object = None  # callable(ctx) -> {"raw": ..., "normalized": ...}
    tags: tuple = field(default_factory=tuple)


CHECKS = {}


def register(check):
    """Register a CheckDef; importable as a decorator target via functools.partial."""
    if check.id in CHECKS:
        raise ValueError("duplicate check id: %s" % (check.id,))
    CHECKS[check.id] = check
    return check


def checks_for(platform, check_ids=None):
    """Resolve check ids (or all registered) to CheckDefs for one platform."""
    if check_ids is None:
        wanted = sorted(CHECKS)
    else:
        wanted = list(check_ids)
    resolved = []
    for check_id in wanted:
        check = CHECKS.get(check_id)
        if check is not None and check.platform == platform:
            resolved.append(check)
    return resolved


# --- test packages -----------------------------------------------------------
# A package may mix platforms; the capture job filters to the target device's
# platform. None means "every registered check for the platform".

PACKAGES = {
    "full": None,
    "fw-cutover-core-switch": [
        "iosxe_routes_rib",
        "iosxe_routes_fib",
        "iosxe_route_rollups",
        "iosxe_bgp_peers",
        "iosxe_ospf_neighbors",
        "iosxe_arp",
        "iosxe_neighbors",
        "iosxe_interfaces",
        "iosxe_platform_health",
    ],
    "fw-cutover-firewall": [
        "panos_system_info",
        "panos_ha",
        "panos_session_info",
        "panos_session_matrix",
        "panos_routes",
        "panos_interfaces",
        "panos_arp",
        "panos_ipsec",
        "panos_licenses",
        "panos_resources",
    ],
    "quick-health": [
        "iosxe_interfaces",
        "iosxe_neighbors",
        "iosxe_platform_health",
        "panos_system_info",
        "panos_ha",
        "panos_session_info",
    ],
}


def package_check_ids(package, platform):
    """Check ids for a package on one platform; None package entry means all."""
    ids = PACKAGES.get(package)
    checks = checks_for(platform, ids)
    return [check.id for check in checks]


def shakedown_advice(status, error, normalized_count, fetched_anything):
    """One-line advisory for the Collector Shakedown job's per-check verdicts.

    The interesting case is "parsed but empty": the device answered and the
    collector succeeded, yet the normalizer emitted nothing — on a live box
    that almost always means this software version spells a leaf/element name
    differently than the normalizer expects. That is exactly the tweak the
    shakedown run exists to surface before a change window.
    """
    if status == "ok" and normalized_count:
        return "ok"
    if status == "ok":
        return (
            "parsed but empty — if the trace payload shows data, this software "
            "version spells the leaf/element names differently; adjust the "
            "normalizer to match the trace"
        )
    if status == "not-present":
        return "feature not present on this device: %s" % (error,)
    if fetched_anything:
        return (
            "collector failed after fetching data — the payload shape surprised "
            "the parser; inspect the trace payload against the error: %s" % (error,)
        )
    return "nothing fetched — transport/path problem (404, timeout, auth): %s" % (error,)
