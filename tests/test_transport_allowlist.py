"""The SSH read-only allowlist, exercised without netmiko.

transport_ssh imports netmiko at module level (absent in CI), so a stub
module satisfies that one import here and ``SshRunner._allowed`` — the
structural read-only guarantee for CLI devices — is locked in by the
battery. Nothing connects: the stub's ConnectHandler is never called, and a
refused command raises before ``open()`` is ever reached.
"""

import sys
import types
import unittest

if __package__:
    from . import _loader
else:  # unittest discover -s tests imports test modules as top-level
    import _loader

if "netmiko" not in sys.modules:
    _stub = types.ModuleType("netmiko")
    _stub.ConnectHandler = None  # never called: run() refuses before connecting
    sys.modules["netmiko"] = _stub

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


if __name__ == "__main__":
    unittest.main()
