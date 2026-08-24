"""Read-only SSH command runner over netmiko, with a per-platform allowlist.

The allowlist is the structural read-only guarantee for CLI devices: every
command must match an allowed prefix (or be an explicitly named session-prep
command), nothing in this repo ever enters configuration mode, and CI's
read-only guard step fails the build if a write verb ever appears in jobs/.

PAN-OS session prep switches the CLI to XML output (``set cli
op-command-xml-output on``): a session-scoped presentation setting, not device
config, that makes every op command return the same XML the API would — so
parsers written against SSH transport port unchanged to the XML API later.
"""

from netmiko import ConnectHandler

from . import constants as C

# Prefix allowlist per netmiko device_type. "show " is the ONLY prefix:
# broader verbs are traps — PAN-OS "test vpn ike-sa/ipsec-sa" INITIATES SA
# negotiation (a state change), so a bare "test " prefix would break the
# read-only guarantee. Future probe checks must add narrowly vetted entries
# to ALLOWED_EXACT (or a full-command prefix like "test security-policy-match ")
# — never a bare verb. "request license info" is a pure display command
# despite the verb (verified against PA KB); no other "request" form is
# permitted. (Field lesson: `check` is not a CLI command at all on 11.2 —
# a once-allowlisted "check pending-changes" entry was removed dead.)
ALLOWED_PREFIXES = {
    "paloalto_panos": ("show ",),
    "cisco_xe": ("show ",),
}
ALLOWED_EXACT = {
    "paloalto_panos": ("request license info",),
    # `dir` listings are pure reads; the two crashinfo filesystems are the
    # only vetted targets (field finding: the guard correctly refused the
    # crash-files collector until these exact commands were allowlisted).
    # The bare `dir ` verb stays banned like every other non-show verb.
    "cisco_xe": ("dir crashinfo:", "dir stby-crashinfo:"),
}
# Session-scoped presentation settings sent once after connect. Safe: they
# alter this CLI session's output format only.
SESSION_PREP = {
    "paloalto_panos": ("set cli pager off", "set cli op-command-xml-output on"),
    "cisco_xe": ("terminal length 0",),
}


class SshCommandRefused(Exception):
    """Command did not match the read-only allowlist; never sent to the device."""


class SshRunner:
    """One SSH session to one device. ``run()`` is the only way to send anything."""

    def __init__(self, device_type, host, username, password, *, logger=None):
        if device_type not in ALLOWED_PREFIXES:
            raise ValueError("unsupported device_type: %r" % (device_type,))
        self.device_type = device_type
        self.host = host
        self._params = {
            "device_type": device_type,
            "host": host,
            "username": username,
            "password": password,
            "conn_timeout": C.SSH_CONNECT_TIMEOUT,
            "fast_cli": False,
        }
        self.logger = logger
        self.conn = None

    def __enter__(self):
        self.open()
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()

    def open(self):
        if self.conn is not None:
            return
        self.conn = ConnectHandler(**self._params)
        for command in SESSION_PREP[self.device_type]:
            self._send(command, timeout=30)

    def close(self):
        if self.conn is None:
            return
        try:
            self.conn.disconnect()
        except Exception as exc:  # teardown must never fail a finished job
            if self.logger is not None:
                self.logger.warning(
                    "%s: SSH disconnect raised %s: %s — ignored (teardown)",
                    self.host,
                    type(exc).__name__,
                    exc,
                )
        finally:
            self.conn = None

    def _allowed(self, command):
        cmd = command.strip()
        if cmd in SESSION_PREP[self.device_type]:
            return True
        if cmd in ALLOWED_EXACT[self.device_type]:
            return True
        return cmd.startswith(ALLOWED_PREFIXES[self.device_type])

    def _send(self, command, *, timeout):
        return self.conn.send_command(
            command, read_timeout=timeout, strip_prompt=True, strip_command=True
        )

    def run(self, command, *, timeout=C.SSH_READ_TIMEOUT):
        """Send one allowlisted operational command; return its raw output text."""
        if not self._allowed(command):
            raise SshCommandRefused("refused non-allowlisted command: %r" % (command,))
        if self.conn is None:
            self.open()
        return self._send(command.strip(), timeout=timeout)
