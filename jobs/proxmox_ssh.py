"""Lazy, independently credentialed Linux reads for Proxmox API complements.

This wrapper performs no I/O until a collector asks for an allowed read.
The credential callback and runner factory are supplied by the job, keeping
Nautobot and netmiko outside this pure module.
"""

from . import constants as C


class LazySsh:
    def __init__(self, credentials, factory):
        self._credentials = credentials
        self._factory = factory
        self._runner = None

    def run(self, command, **kwargs):
        if command not in C.PROXMOX_SSH_COMMANDS:
            raise ValueError("Proxmox SSH read is not allowlisted")
        if self._runner is None:
            username, password = self._credentials()
            if "!" in username:
                raise ValueError(
                    "Proxmox host observations require separate Linux SSH credentials; "
                    "assign SSH Username/Password secrets to the host Secrets Group"
                )
            self._runner = self._factory(username, password)
        return self._runner.run(command, **kwargs)

    def close(self):
        if self._runner is not None:
            self._runner.close()
