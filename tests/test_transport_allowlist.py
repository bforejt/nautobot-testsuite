"""SSH command fences and complete Linux exec reads, without connections.

transport_ssh imports netmiko at module level (absent in CI), so a stub
module satisfies that one import here and ``SshRunner._allowed`` — the
structural read-only guarantee for CLI devices — is locked in by the
battery. Nothing connects: the stub's ConnectHandler is never called, and a
refused command raises before ``open()`` is ever reached. Linux exec fixtures
exercise complete streams, flow control, EOF/status ordering and deadlines
through fake Paramiko clients/channels, including Celery interruptions.
"""

import sys
import threading
import types
import unittest
from unittest import mock

if __package__:
    from . import _loader
else:  # unittest discover -s tests imports test modules as top-level
    import _loader

if "netmiko" not in sys.modules:
    _stub = types.ModuleType("netmiko")
    _stub.ConnectHandler = None  # never called: run() refuses before connecting
    sys.modules["netmiko"] = _stub

if "paramiko" not in sys.modules:
    _stub = types.ModuleType("paramiko")
    _stub.SSHClient = None
    _stub.AutoAddPolicy = object
    sys.modules["paramiko"] = _stub

transport_ssh = _loader.load("transport_ssh")


class TestCiscoXeAllowlist(unittest.TestCase):
    def setUp(self):
        self.runner = transport_ssh.SshRunner("cisco_xe", "203.0.113.1", "user", "secret")

    def test_show_prefix_and_session_prep(self):
        for command in ("show switch detail", "show ip route summary", "terminal length 0"):
            self.assertTrue(self.runner._allowed(command), command)

    def test_exact_crashinfo_aliases(self):
        self.assertTrue(self.runner._allowed("dir crashinfo:"))
        self.assertTrue(self.runner._allowed("dir stby-crashinfo:"))

    def test_member_crashinfo_shape_admits_a_numeric_suffix_only(self):
        for command in ("dir crashinfo-1:", "dir crashinfo-12:", "  dir crashinfo-3:  "):
            self.assertTrue(self.runner._allowed(command), command)
        for command in (
            "dir",
            "dir ",
            "dir flash:",
            "dir flash-1:",
            "dir crashinfo-1:/",
            "dir crashinfo-1:core",
            "dir crashinfo-a:",
            "dir crashinfo-:",
            "dir crashinfo-1: | include txt",
            "dir crashinfo-1:\nreload",
            "dir stby-crashinfo-1:",
        ):
            self.assertFalse(self.runner._allowed(command), command)

    def test_write_verbs_refused_before_any_connection(self):
        for command in (
            "configure terminal",
            "reload",
            "copy running-config startup-config",
            "delete crashinfo:system-report.tar.gz",
            "write memory",
            "clear counters",
        ):
            with self.assertRaises(transport_ssh.SshCommandRefused):
                self.runner.run(command)
        self.assertIsNone(self.runner.conn)


class TestPanosAllowlist(unittest.TestCase):
    def setUp(self):
        self.runner = transport_ssh.SshRunner("paloalto_panos", "203.0.113.2", "user", "secret")

    def test_show_the_one_request_form_and_session_prep(self):
        for command in (
            "show system info",
            "request license info",
            "set cli pager off",
            "set cli op-command-xml-output on",
        ):
            self.assertTrue(self.runner._allowed(command), command)

    def test_state_changing_forms_refused(self):
        for command in (
            "test vpn ike-sa",
            "request restart system",
            "request license fetch",
            "dir crashinfo-1:",
            "configure",
            "set cli timeout 0",
        ):
            self.assertFalse(self.runner._allowed(command), command)


class TestProxmoxLinuxAllowlist(unittest.TestCase):
    def test_exact_json_reads_only_and_no_shell_suffix(self):
        runner = transport_ssh.SshRunner("linux", "192.0.2.12", "collector", "secret")
        for command in _loader.constants.PROXMOX_SSH_COMMANDS:
            self.assertTrue(runner._allowed(command))
            for suffix in ("; reboot", "\nreboot", " | cat", " && rm -rf /"):
                self.assertFalse(runner._allowed(command + suffix))
        for command in (
            "ip link show",
            "ip -j link set eth0 down",
            "cat /etc/shadow",
            "python3",
            "show version",
            "sudo lshw -json",
        ):
            with self.assertRaises(transport_ssh.SshCommandRefused):
                runner.run(command)
        self.assertIsNone(runner.conn)


class ExecChannel:
    """Both streams share flow control; exit status can arrive before EOF."""

    def __init__(self, stdout=b"{}", stderr=b"", *, status=0, eof=True, status_ready=True):
        self.stdout = bytearray(stdout)
        self.stderr = bytearray(stderr)
        self.status = status
        self.eof_received = eof
        self.status_ready = status_ready
        self.closed = False
        self.executed = []
        self.drained = []
        self.exit_reads = 0
        self.stdin_closed = False
        self.request_gate = None
        self.request_finished = threading.Event()

    def settimeout(self, timeout):
        self.timeout = timeout

    def exec_command(self, command):
        self.executed.append(command)
        try:
            if self.request_gate is not None:
                self.request_gate.wait()
        finally:
            self.request_finished.set()

    def shutdown_write(self):
        self.stdin_closed = True

    def recv_ready(self):
        return bool(self.stdout)

    def recv_stderr_ready(self):
        return bool(self.stderr)

    def recv(self, size):
        if self.stderr and self.drained and self.drained[-1] == "stdout":
            raise AssertionError("stderr must drain fairly to release shared SSH window")
        self.drained.append("stdout")
        data = bytes(self.stdout[:size])
        del self.stdout[:size]
        return data

    def recv_stderr(self, size):
        self.drained.append("stderr")
        data = bytes(self.stderr[:size])
        del self.stderr[:size]
        return data

    def exit_status_ready(self):
        return self.status_ready

    def recv_exit_status(self):
        if self.stdout or self.stderr:
            raise AssertionError("exit status before draining streams can deadlock")
        self.exit_reads += 1
        return self.status

    def close(self):
        self.closed = True
        if self.request_gate is not None:
            self.request_gate.set()


class TestLinuxExecReads(unittest.TestCase):
    def _runner(self, channel):
        client = mock.Mock()
        transport = client.get_transport.return_value
        transport.is_active.return_value = True
        transport.open_session.return_value = channel
        runner = transport_ssh.SshRunner("linux", "192.0.2.12", "collector", "ssh-secret")
        runner.conn = client
        return runner

    def test_multiline_fixed_script_uses_exec_without_prompt_echo_or_pty(self):
        channel = ExecChannel(b'{"files":[],"errors":[]}\n')
        runner = self._runner(channel)
        command = _loader.constants.PROXMOX_CONFIG_COMMAND
        self.assertIn("\n", command)
        result = runner.run(command)
        self.assertEqual(result, '{"files":[],"errors":[]}\n')
        self.assertEqual(channel.executed, [command])
        self.assertTrue(channel.stdin_closed)
        self.assertTrue(channel.closed)
        self.assertEqual(result.stdout, result)
        self.assertEqual(result.stderr, "")
        self.assertEqual(result.exit_status, 0)
        runner.conn.send_command.assert_not_called()
        runner.conn.invoke_shell.assert_not_called()

    def test_large_stdout_and_stderr_are_both_complete_before_exit_status(self):
        output = '{"large":"' + "\u00e9" * 1500000 + '"}\n'
        diagnostics = "diagnostic\n" * 400000
        channel = ExecChannel(output.encode(), diagnostics.encode())
        result = self._runner(channel).run(_loader.constants.PROXMOX_HARDWARE_COMMAND)
        self.assertEqual(result, output)
        self.assertEqual(result.stderr, diagnostics)
        self.assertGreater(channel.drained.count("stdout"), 40)
        self.assertGreater(channel.drained.count("stderr"), 40)
        self.assertEqual(channel.exit_reads, 1)

    def test_nonzero_status_preserves_diagnostics_without_exposing_them_in_error(self):
        channel = ExecChannel(b'{"partial":true}', b"remote-secret-canary", status=1)
        with self.assertRaisesRegex(transport_ssh.SshReadError, "status 1") as caught:
            self._runner(channel).run(_loader.constants.PROXMOX_CONFIG_COMMAND)
        self.assertNotIn("canary", str(caught.exception))
        self.assertEqual(caught.exception.stdout, '{"partial":true}')
        self.assertEqual(caught.exception.stderr, "remote-secret-canary")
        self.assertEqual(caught.exception.exit_status, 1)
        self.assertTrue(channel.closed)

    def test_deadline_refuses_partial_output_and_exit_status_without_eof(self):
        for ready in (False, True):
            with self.subTest(exit_status_ready=ready):
                channel = ExecChannel(
                    b'{"partial":', b"diagnostic-canary", eof=False, status_ready=ready
                )
                with self.assertRaisesRegex(transport_ssh.SshReadError, "deadline") as caught:
                    self._runner(channel).run(
                        _loader.constants.PROXMOX_CONFIG_COMMAND, timeout=0.03
                    )
                self.assertEqual(caught.exception.stdout, '{"partial":')
                self.assertNotIn("canary", str(caught.exception))
                self.assertEqual(channel.exit_reads, 0)
                self.assertTrue(channel.closed)

    def test_exec_acknowledgement_also_obeys_deadline_and_releases_worker(self):
        channel = ExecChannel()
        channel.request_gate = threading.Event()
        with self.assertRaisesRegex(transport_ssh.SshReadError, "before exec acknowledgement"):
            self._runner(channel).run(_loader.constants.PROXMOX_CONFIG_COMMAND, timeout=0.03)
        self.assertTrue(channel.closed)
        self.assertTrue(channel.request_finished.wait(1))

    def test_invalid_utf8_or_missing_remote_status_never_returns_success(self):
        for stdout, stderr, status, expected in (
            (b"\xffsecret-canary", b"", 0, "invalid UTF-8"),
            (b"{}", b"\xffsecret-canary", 0, "invalid UTF-8"),
            (b"{}", b"", -1, "status -1"),
            (b"{}", b"", False, "invalid exit status"),
        ):
            with self.subTest(stdout=stdout, stderr=stderr, status=status):
                channel = ExecChannel(stdout, stderr, status=status)
                with self.assertRaisesRegex(transport_ssh.SshReadError, expected) as caught:
                    self._runner(channel).run(_loader.constants.PROXMOX_CONFIG_COMMAND)
                self.assertNotIn("canary", str(caught.exception))
                if b"\xff" in stdout + stderr:
                    self.assertNotIn("canary", caught.exception.stdout + caught.exception.stderr)
                    self.assertIn("withheld", caught.exception.stdout + caught.exception.stderr)
                self.assertTrue(channel.closed)

    def test_linux_connect_is_lazy_and_uses_only_the_assigned_password_account(self):
        channel = ExecChannel()
        client = mock.Mock()
        client.get_transport.return_value.is_active.return_value = True
        client.get_transport.return_value.open_session.return_value = channel
        runner = transport_ssh.SshRunner("linux", "192.0.2.12", "collector", "ssh-secret")
        with (
            mock.patch.object(transport_ssh.paramiko, "SSHClient", return_value=client) as factory,
            mock.patch.object(transport_ssh, "ConnectHandler") as interactive,
        ):
            with self.assertRaises(transport_ssh.SshCommandRefused):
                runner.run("cat /etc/shadow")
            factory.assert_not_called()
            runner.run(_loader.constants.PROXMOX_CONFIG_COMMAND)
            factory.assert_called_once_with()
            interactive.assert_not_called()
            client.connect.assert_called_once_with(
                hostname="192.0.2.12",
                username="collector",
                password="ssh-secret",
                timeout=_loader.constants.SSH_CONNECT_TIMEOUT,
                banner_timeout=_loader.constants.SSH_CONNECT_TIMEOUT,
                auth_timeout=_loader.constants.SSH_CONNECT_TIMEOUT,
                look_for_keys=False,
                allow_agent=False,
            )
            runner.close()
            client.close.assert_called_once_with()
            self.assertIsNone(runner.conn)

    def test_linux_connect_failure_is_sanitized_and_closes_client(self):
        client = mock.Mock()
        client.connect.side_effect = ValueError("credential-secret-canary")
        runner = transport_ssh.SshRunner("linux", "192.0.2.12", "collector", "ssh-secret")
        with mock.patch.object(transport_ssh.paramiko, "SSHClient", return_value=client):
            with self.assertRaisesRegex(transport_ssh.SshReadError, "connect failed") as caught:
                runner.run(_loader.constants.PROXMOX_CONFIG_COMMAND)
        self.assertNotIn("canary", str(caught.exception))
        client.close.assert_called_once_with()
        self.assertIsNone(runner.conn)

    def test_celery_soft_limit_propagates_and_closes_connect_or_exec_resources(self):
        class SoftTimeLimitExceeded(Exception):
            pass

        signal = SoftTimeLimitExceeded()
        client = mock.Mock()
        client.connect.side_effect = signal
        runner = transport_ssh.SshRunner("linux", "192.0.2.12", "collector", "ssh-secret")
        with mock.patch.object(transport_ssh.paramiko, "SSHClient", return_value=client):
            with self.assertRaises(SoftTimeLimitExceeded) as caught:
                runner.run(_loader.constants.PROXMOX_CONFIG_COMMAND)
        self.assertIs(caught.exception, signal)
        client.close.assert_called_once_with()
        for stage in ("exec_command", "recv"):
            with self.subTest(stage=stage):
                channel = ExecChannel()
                setattr(channel, stage, mock.Mock(side_effect=signal))
                with self.assertRaises(SoftTimeLimitExceeded) as caught:
                    self._runner(channel).run(_loader.constants.PROXMOX_CONFIG_COMMAND)
                self.assertIs(caught.exception, signal)
                self.assertTrue(channel.closed)


if __name__ == "__main__":
    unittest.main()
