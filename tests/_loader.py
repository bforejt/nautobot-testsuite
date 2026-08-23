"""Test-battery loader: import jobs modules without executing jobs/__init__.py.

jobs/__init__.py imports Nautobot (absent in CI), so we register a synthetic
``jobs`` package whose ``__path__`` points at the real package directory and
import submodules through it. Only pure modules may be loaded this way —
snapshot_job / compare_job / creds / transport_* import third-party packages
and must never be touched here.

Checks modules register CheckDefs into the shared registry at import time.
Loading them exactly once, here, at loader-import time — and having every
test module take its handles from this module — keeps registry.CHECKS from
seeing duplicate registrations across the battery.
"""

import importlib
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


constants = load("constants")
diffcore = load("diffcore")
envelope = load("envelope")
registry = load("registry")
panos_xml = load("panos_xml")
context = load("context")
checks_iosxe = load("checks_iosxe")
checks_panos = load("checks_panos")
