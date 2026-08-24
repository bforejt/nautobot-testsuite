"""Network Validation jobs — pre/post change snapshots and comparison.

Nautobot's Git-repository loader imports only this package; every Job class
must be imported and passed to register_jobs() here (Nautobot issue #5971).
Importing the checks modules populates the check registry as a side effect.
"""

from nautobot.apps.jobs import register_jobs

from . import checks_iosxe, checks_panos  # noqa: F401  (registry population)
from .constants import JOB_VERSION
from .shakedown_job import CollectorShakedown
from .snapshot_job import CaptureSnapshot

__version__ = JOB_VERSION

register_jobs(CaptureSnapshot, CollectorShakedown)
