"""Test Suite jobs — self-describing pre/post change snapshots.

Nautobot's Git-repository loader imports only this package; every Job class
must be imported and passed to register_jobs() here (Nautobot issue #5971).

Check catalogs (``checks_<platform>.py``) register their CheckDefs into the
registry as an import side effect. They are discovered by file name rather
than listed here, so a platform branch adds its catalog as one new module and
never edits this file — several platform branches then merge without
touching the same line. tests/test_catalog_discovery.py locks in that no
``checks_*`` module is missed by the test loader's mirror of this loop.
"""

import importlib
import pkgutil

from nautobot.apps.jobs import register_jobs

from .constants import JOB_VERSION
from .shakedown_job import CollectorShakedown
from .snapshot_job import CaptureSnapshot

__version__ = JOB_VERSION

for _module in pkgutil.iter_modules(__path__):
    if _module.name.startswith("checks_"):
        importlib.import_module("." + _module.name, __name__)

register_jobs(CaptureSnapshot, CollectorShakedown)
