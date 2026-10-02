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

import re
import threading
import time

import paramiko
from netmiko import ConnectHandler

from . import constants as C

# Prefix allowlist per netmiko device_type. "show " is the ONLY prefix:
# broader verbs are traps — PAN-OS "test vpn ike-sa/ipsec-sa" INITIATES SA
# negotiation (a state change), so a bare "test " prefix would break the
# read-only guarantee. Future probe checks must add narrowly vetted entries
# to ALLOWED_EXACT, an anchored full-command shape to ALLOWED_PATTERNS, or a
# full-command prefix like "test security-policy-match " — never a bare verb.
# "request license info" is a pure display command despite the verb (verified
# against PA KB); no other "request" form is permitted. (Field lesson: `check`
# is not a CLI command at all on 11.2 — a once-allowlisted "check
# pending-changes" entry was removed dead.)
ALLOWED_PREFIXES = {
    "paloalto_panos": ("show ",),
    "cisco_xe": ("show ",),
    "linux": (),
}
ALLOWED_EXACT = {
    "paloalto_panos": ("request license info",),
    # `dir` listings are pure reads; the two crashinfo filesystems are the
    # only vetted targets (field finding: the guard correctly refused the
    # crash-files collector until these exact commands were allowlisted).
    # The bare `dir ` verb stays banned like every other non-show verb.
    "cisco_xe": ("dir crashinfo:", "dir stby-crashinfo:"),
    "linux": C.PROXMOX_SSH_COMMANDS,
}
# Vetted command SHAPES — full-command regexes anchored at both ends — for the
# one read an exact list cannot spell out: a stack member's own crashinfo
# filesystem, `dir crashinfo-<N>:` with N the switch number. crashinfo: and
# stby-crashinfo: are aliases of the active's and the standby's; a third or
# later Catalyst 9300 stack member is reachable only by number. The shape
# admits a numeric member suffix and nothing else — no other filesystem, no
# path, no pipe or option — so the bare `dir ` verb stays banned like every
# other non-show verb. Locked in by tests/test_transport_allowlist.py.
ALLOWED_PATTERNS = {
    "paloalto_panos": (),
    "cisco_xe": (re.compile(r"^dir crashinfo-\d+:$"),),
    "linux": (),
}
# Session-scoped presentation settings sent once after connect. Safe: they
# alter this CLI session's output format only.
SESSION_PREP = {
    "paloalto_panos": ("set cli pager off", "set cli op-command-xml-output on"),
    "cisco_xe": ("terminal length 0",),
    "linux": (),
}


class SshCommandRefused(Exception):
    """Command did not match the read-only allowlist; never sent to the device."""


class SshReadError(Exception):
    """Refused incomplete Linux evidence; output is never interpolated into errors.

    The collector context must redact these diagnostic attributes before it
    retains them. They can contain partial output when a deadline is reached.
    """

    def __init__(self, message, *, stdout=b"", stderr=b"", exit_status=None):
        super().__init__(message)

        def diagnostic(data):
            try:
                return data.decode("utf-8", errors="strict")
            except UnicodeError:
                return "<invalid UTF-8 diagnostic withheld; %d bytes received>" % len(data)

        self.stdout = diagnostic(stdout)
        self.stderr = diagnostic(stderr)
        self.exit_status = exit_status
        self.partial = True


class SshOutput(str):
    """Compatible stdout string with separate complete stderr/status metadata."""

    def __new__(cls, stdout, stderr="", exit_status=0):
        value = super().__new__(cls, stdout)
        value.stdout = stdout
        value.stderr = stderr
        value.exit_status = exit_status
        return value


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
        if self.device_type == "linux":
            self._open_linux()
            return
        self.conn = ConnectHandler(**self._params)
        for command in SESSION_PREP[self.device_type]:
            self._send(command, timeout=30)

    def _open_linux(self):
        # No interactive shell, PTY, session commands, key discovery or agent
        # fallback. Linux account credentials are resolved independently.
        if "!" in self._params["username"]:
            raise SshReadError("Linux SSH requires separate host account credentials")
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(
                hostname=self.host,
                username=self._params["username"],
                password=self._params["password"],
                timeout=C.SSH_CONNECT_TIMEOUT,
                banner_timeout=C.SSH_CONNECT_TIMEOUT,
                auth_timeout=C.SSH_CONNECT_TIMEOUT,
                look_for_keys=False,
                allow_agent=False,
            )
        except Exception as exc:
            try:
                client.close()
            except Exception as close_exc:
                if type(close_exc).__name__ == "SoftTimeLimitExceeded":
                    raise
            if type(exc).__name__ == "SoftTimeLimitExceeded":
                raise
            raise SshReadError("Linux SSH connect failed (%s)" % type(exc).__name__) from None
        self.conn = client

    def close(self):
        if self.conn is None:
            return
        try:
            if self.device_type == "linux":
                self.conn.close()
            else:
                self.conn.disconnect()
        except Exception as exc:  # teardown must never fail a finished job
            if self.device_type == "linux" and type(exc).__name__ == "SoftTimeLimitExceeded":
                raise
            if self.logger is not None:
                self.logger.warning(
                    "%s: SSH disconnect raised %s: %s — ignored (teardown)",
                    self.host,
                    type(exc).__name__,
                    type(exc).__name__ if self.device_type == "linux" else exc,
                )
        finally:
            self.conn = None

    def _allowed(self, command):
        cmd = command.strip()
        if cmd in SESSION_PREP[self.device_type]:
            return True
        if cmd in ALLOWED_EXACT[self.device_type]:
            return True
        if any(pattern.match(cmd) for pattern in ALLOWED_PATTERNS[self.device_type]):
            return True
        return cmd.startswith(ALLOWED_PREFIXES[self.device_type])

    def _send(self, command, *, timeout):
        if self.device_type == "linux":
            return self._send_linux(command, timeout=timeout)
        return self.conn.send_command(
            command, read_timeout=timeout, strip_prompt=True, strip_command=True
        )

    def _send_linux(self, command, *, timeout):
        """Drain both SSH streams before exit status; accept only complete UTF-8.

        Paramiko's exec acknowledgement has an unbounded event wait even
        after settimeout(), so a short-lived worker bounds that request too.
        Closing a timed-out channel releases Paramiko's acknowledgement wait.
        """
        if timeout <= 0:
            raise ValueError("SSH read timeout must be positive")
        deadline = time.monotonic() + timeout
        stdout, stderr = bytearray(), bytearray()
        channel = None
        exit_status = None

        def failure(message):
            return SshReadError(
                message, stdout=bytes(stdout), stderr=bytes(stderr), exit_status=exit_status
            )

        try:
            transport = self.conn.get_transport()
            if transport is None or not transport.is_active():
                raise failure("Linux SSH transport is not active")
            channel = transport.open_session(timeout=max(0.001, deadline - time.monotonic()))
            channel.settimeout(0.0)
            acknowledged = threading.Event()
            request_errors = []

            def request():
                try:
                    channel.exec_command(command)
                    channel.shutdown_write()
                except Exception as exc:
                    if type(exc).__name__ == "SoftTimeLimitExceeded":
                        request_errors.append(exc)
                    else:
                        request_errors.append(type(exc).__name__)
                finally:
                    acknowledged.set()

            threading.Thread(target=request, daemon=True).start()
            if not acknowledged.wait(max(0.0, deadline - time.monotonic())):
                raise failure("Linux SSH read deadline exceeded before exec acknowledgement")
            if request_errors:
                if not isinstance(request_errors[0], str):
                    raise request_errors[0]
                raise failure("Linux SSH exec request failed (%s)" % request_errors[0])
            while True:
                if time.monotonic() >= deadline:
                    raise failure("Linux SSH read deadline exceeded; partial output refused")
                progressed = False
                # Alternating bounded reads prevents either stream exhausting
                # the shared SSH window and blocking the other stream forever.
                if channel.recv_ready():
                    stdout.extend(channel.recv(65536))
                    progressed = True
                if channel.recv_stderr_ready():
                    stderr.extend(channel.recv_stderr(65536))
                    progressed = True
                if (
                    (channel.eof_received or channel.closed)
                    and not channel.recv_ready()
                    and not channel.recv_stderr_ready()
                    and channel.exit_status_ready()
                ):
                    exit_status = channel.recv_exit_status()
                    break
                if not progressed:
                    time.sleep(min(0.01, max(0.0, deadline - time.monotonic())))
            if type(exit_status) is not int:
                raise failure("Linux SSH read returned an invalid exit status; output refused")
            if exit_status != 0:
                raise failure("Linux SSH read exited with status %s; output refused" % exit_status)
            try:
                result = bytes(stdout).decode("utf-8", errors="strict")
                diagnostics = bytes(stderr).decode("utf-8", errors="strict")
            except UnicodeError:
                raise failure("Linux SSH read returned invalid UTF-8; output refused") from None
            return SshOutput(result, diagnostics, exit_status)
        except SshReadError:
            raise
        except Exception as exc:
            if type(exc).__name__ == "SoftTimeLimitExceeded":
                raise
            raise failure("Linux SSH read failed (%s)" % type(exc).__name__) from None
        finally:
            if channel is not None:
                try:
                    channel.close()
                except Exception as exc:
                    if type(exc).__name__ == "SoftTimeLimitExceeded":
                        raise

    def run(self, command, *, timeout=C.SSH_READ_TIMEOUT):
        """Send one allowlisted operational command; return its raw output text."""
        if not self._allowed(command):
            raise SshCommandRefused("refused non-allowlisted command: %r" % (command,))
        if self.conn is None:
            self.open()
        return self._send(command.strip(), timeout=timeout)
