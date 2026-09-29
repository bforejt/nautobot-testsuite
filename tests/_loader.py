"""Test-battery loader: import jobs modules without executing jobs/__init__.py.

jobs/__init__.py imports Nautobot (absent in CI), so we register a synthetic
``jobs`` package whose ``__path__`` points at the real package directory and
import submodules through it. Only pure modules may be loaded this way —
snapshot_job / compare_job / creds / transport_* import third-party packages
and must never be touched here — with one sanctioned exception:
test_transport_allowlist stubs netmiko in sys.modules and loads transport_ssh
so the read-only command allowlist is locked in by CI.

Checks modules register CheckDefs into the shared registry at import time.
Loading them exactly once, here, at loader-import time — and having every
test module take its handles from this module — keeps registry.CHECKS from
seeing duplicate registrations across the battery.
"""

import importlib
import ipaddress
import json
import pathlib
import sys
import types

ROOT = pathlib.Path(__file__).resolve().parents[1]
FIXTURES = pathlib.Path(__file__).resolve().parent / "fixtures"

_pkg = types.ModuleType("jobs")
_pkg.__path__ = [str(ROOT / "jobs")]
sys.modules.setdefault("jobs", _pkg)


def load(name):
    """Import ``jobs.<name>`` through the synthetic package (pure modules only)."""
    return importlib.import_module("jobs." + name)


def fixture_json(name):
    """Parsed JSON fixture from tests/fixtures/."""
    with open(FIXTURES / name, encoding="utf-8") as handle:
        return json.load(handle)


def fixture_text(name):
    """Raw text fixture from tests/fixtures/."""
    with open(FIXTURES / name, encoding="utf-8") as handle:
        return handle.read()


# The only IPv4 ranges a committed fixture may carry: the sanitizer's targets
# (RFC 5737 documentation nets, RFC 2544 benchmark space) plus what it leaves
# untouched because it identifies nobody (masks and wildcards in 0/8 and
# 255/8, loopback, multicast, reserved). Shape rules, so the guard never has
# to name a real address to catch one.
LAB_ADDRESS_RANGES = tuple(
    ipaddress.ip_network(net)
    for net in (
        "192.0.2.0/24",
        "198.51.100.0/24",
        "203.0.113.0/24",
        "198.18.0.0/15",
        "0.0.0.0/8",
        "127.0.0.0/8",
        "224.0.0.0/4",
        "240.0.0.0/4",
        "255.0.0.0/8",
    )
)


def allowed_lab_address(text):
    """True when a dotted quad is a mask (255.x / 0.x) or sits in an allowed range."""
    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        return False
    return any(address in net for net in LAB_ADDRESS_RANGES)


constants = load("constants")
diffcore = load("diffcore")
envelope = load("envelope")
registry = load("registry")
panos_xml = load("panos_xml")
redfish_paths = load("redfish_paths")
vsphere_soap = load("vsphere_soap")
context = load("context")
checks_iosxe = load("checks_iosxe")
checks_panos = load("checks_panos")
checks_vmware = load("checks_vmware")
checks_xcc = load("checks_xcc")

# Every catalog module is loaded by file name, mirroring jobs/__init__.py, so
# a platform branch that adds jobs/checks_<platform>.py needs no edit here
# (importlib caches modules: the explicit handles above register nothing
# twice). tests/test_catalog_discovery.py locks the mirror in.
CHECK_MODULES = {path.stem: load(path.stem) for path in sorted((ROOT / "jobs").glob("checks_*.py"))}
