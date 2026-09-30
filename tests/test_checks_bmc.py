"""checks_bmc normalizers and collectors driven with hand-built XCC gen-1 Redfish fixtures."""

import copy
import json
import unittest

if __package__:
    from . import _loader
else:  # unittest discover -s tests imports test modules as top-level
    import _loader

checks = _loader.checks_bmc
registry = _loader.registry

SYS = "/redfish/v1/Systems/1"
MGR = "/redfish/v1/Managers/1"
CH = "/redfish/v1/Chassis/1"
EXPAND = "?$expand=.($levels=1)"
# The id resolution every check starts with (the first one pays, the rest hit the cache).
RESOLVE = ["/redfish/v1/", "/redfish/v1/Systems", SYS]


class _FakeRedfishError(Exception):
    """Same shape as transport_redfish.RedfishError: status_code None for budget/fence."""

    def __init__(self, message, status_code=None):
        super().__init__(message)
        self.status_code = status_code


class _FakeBudget:
    """Mirrors transport_redfish._GetBudget: counts real GETs, raises before the one over."""

    def __init__(self, ctx, label, max_gets):
        self.ctx = ctx
        self.label = label
        self.max_gets = max_gets
        self.used = 0

    def charge(self, path):
        if self.used >= self.max_gets:
            raise _FakeRedfishError(
                "%s: GET budget of %d exhausted before %s" % (self.label, self.max_gets, path)
            )
        self.used += 1

    def __enter__(self):
        self.ctx.active_budget = self
        return self

    def __exit__(self, *exc):
        self.ctx.active_budget = None
        return False


class _OpaqueBudget:
    """A budget manager that counts but exposes neither ``used`` nor ``max_gets``
    (a transport the collector cannot pre-check against): the transport's
    own refusal is then what stops a walk."""

    def __init__(self, ctx, label, cap):
        self.ctx = ctx
        self.label = label
        self._cap = cap
        self._spent = 0

    def charge(self, path):
        if self._spent >= self._cap:
            raise _FakeRedfishError(
                "%s: GET budget of %d exhausted before %s" % (self.label, self._cap, path)
            )
        self._spent += 1

    def __enter__(self):
        self.ctx.active_budget = self
        return self

    def __exit__(self, *exc):
        self.ctx.active_budget = None
        return False


class _FakeCtx:
    """Duck-typed CollectorContext over a path -> payload map.

    A path missing from ``payloads`` answers 404 (None with ok_404, an error
    otherwise); ``errors`` maps a path to an HTTP status to raise. GETs are
    cached per (path, ok_404) like the real context, so ``gets`` lists only
    the requests that reached the "wire".
    """

    has_ssh = False
    has_api = False

    def __init__(self, payloads, errors=None, opaque_budget=False):
        self.payloads = payloads
        self.errors = errors or {}
        self.opaque_budget = opaque_budget
        self.gets = []
        self.redacted = []
        self.budgets = []
        self.active_budget = None
        self.device_name = "se350-a"
        self.logger = None
        self._cache = {}

    def get(self, path, redact=None, **kwargs):
        ok_404 = bool(kwargs.get("ok_404", False))
        key = (path, ok_404) + tuple(sorted((k, v) for k, v in kwargs.items() if k != "ok_404"))
        if key in self._cache:
            cached = self._cache[key]
            return redact(cached) if redact is not None and cached is not None else cached
        if self.active_budget is not None:
            self.active_budget.charge(path)
        self.gets.append(path)
        if path in self.errors:
            raise _FakeRedfishError(
                "GET %s: HTTP %s" % (path, self.errors[path]), status_code=self.errors[path]
            )
        if path not in self.payloads:
            if ok_404:
                self._cache[key] = None
                return None
            raise _FakeRedfishError("GET %s: 404 not found" % (path,), status_code=404)
        payload = copy.deepcopy(self.payloads[path])
        if redact is not None:
            payload = redact(payload)
        self.redacted.append((path, getattr(redact, "__name__", None)))
        self._cache[key] = payload
        return payload

    def budget(self, label, max_gets):
        self.budgets.append((label, max_gets))
        if self.opaque_budget:
            return _OpaqueBudget(self, label, max_gets)
        return _FakeBudget(self, label, max_gets)


def _fx(name):
    return _loader.fixture_json(name)


def _split_collection(expanded):
    """An expanded collection fixture -> (link-only collection, {member path: member})."""
    collection = copy.deepcopy(expanded)
    members = {}
    collection["Members"] = []
    for member in expanded["Members"]:
        members[member["@odata.id"]] = member
        collection["Members"].append({"@odata.id": member["@odata.id"]})
    return collection, members


def _base_payloads():
    """Every fixture at its documented path, $expand forms included."""
    payloads = {
        "/redfish/v1/": _fx("xcc_service_root.json"),
        "/redfish/v1/Systems": {
            "@odata.id": "/redfish/v1/Systems",
            "Members": [{"@odata.id": SYS}],
            "Members@odata.count": 1,
        },
        SYS: _fx("xcc_system.json"),
        SYS + "/SecureBoot": _fx("xcc_secure_boot.json"),
        MGR: _fx("xcc_manager.json"),
        MGR + "/EthernetInterfaces/NIC": _fx("xcc_manager_nic.json"),
        MGR + "/EthernetInterfaces/ToHost": _fx("xcc_manager_nic_tohost.json"),
        MGR + "/EthernetInterfaces": _fx("xcc_manager_nics.json"),
        MGR + "/Oem/Lenovo/Security": _fx("xcc_security.json"),
        MGR + "/Oem/Lenovo/SecureKeyLifecycleService": _fx("xcc_sklm.json"),
        MGR + "/NetworkProtocol": _fx("xcc_network_protocol.json"),
        CH: _fx("xcc_chassis.json"),
        CH + "/Thermal": _fx("xcc_thermal.json"),
        CH + "/Power": _fx("xcc_power.json"),
        SYS + "/Memory" + EXPAND: _fx("xcc_memory_expanded.json"),
        SYS + "/Processors" + EXPAND: _fx("xcc_processors_expanded.json"),
        CH + "/PCIeDevices" + EXPAND: _fx("xcc_pcie_expanded.json"),
        CH + "/PCIeDevices/ob_1/PCIeFunctions" + EXPAND: _fx(
            "xcc_inventory_pciefunctions_expanded.json"
        ),
        # bmc_pcie_slots: the Lenovo slot table the hand-built Chassis links (Oem.Lenovo.Slots)
        CH + "/Slots" + EXPAND: _fx("xcc_pcie_slots_lenovo_expanded.json"),
        SYS + "/EthernetInterfaces" + EXPAND: _fx("xcc_host_nics_expanded.json"),
        "/redfish/v1/UpdateService/FirmwareInventory" + EXPAND: _fx("xcc_firmware_expanded.json"),
        SYS + "/LogServices": _fx("xcc_log_services.json"),
        SYS + "/LogServices/PlatformLog": _fx("xcc_log_service_platform.json"),
        SYS + "/LogServices/PlatformLog/Entries": _fx("xcc_log_entries.json"),
        SYS + "/Bios": _fx("xcc_bios.json"),
        SYS + "/Storage" + EXPAND: _fx("xcc_storage_expanded.json"),
        SYS + "/Storage/RAID_Slot1/Drives/Disk.0": _fx("xcc_storage_drive_0.json"),
        SYS + "/Storage/RAID_Slot1/Drives/Disk.1": _fx("xcc_storage_drive_1.json"),
        SYS + "/Storage/RAID_Slot1/Volumes" + EXPAND: _fx("xcc_storage_volumes_expanded.json"),
    }
    # Plain (link-only) collection forms for the per-member fallback walks.
    for expanded_path in [path for path in payloads if path.endswith(EXPAND)]:
        plain, members = _split_collection(payloads[expanded_path])
        payloads[expanded_path[: -len(EXPAND)]] = plain
        for member_path, member in members.items():
            payloads.setdefault(member_path, member)
    # The NetworkAdapters tree the hand-built Chassis links (bmc_network_adapters).
    for path, payload in _network_adapter_payloads().items():
        payloads.setdefault(path, payload)
    return payloads


def _without_expand(payloads):
    """Payload map where every $expand form answers 404 (firmware without ExpandQuery)."""
    return {path: value for path, value in payloads.items() if not path.endswith(EXPAND)}


class TestRegistrations(unittest.TestCase):
    EXPECTED_IDS = {
        "bmc_system",
        "bmc_security",
        "bmc_thermal",
        "bmc_power",
        "bmc_inventory",
        "bmc_host_nics",
        "bmc_firmware",
        "bmc_event_log",
        "bmc_bios",
        "bmc_storage",
        "bmc_manager_network",
        "bmc_chassis",
        "bmc_sensors",
        "bmc_boot",
        "bmc_power_policy",
        "bmc_network_adapters",
        "bmc_pcie_slots",
        "bmc_accounts",
        "bmc_alerting",
    }

    def test_all_registered_once(self):
        registered = {
            check_id for check_id, check in registry.CHECKS.items() if check.platform == "bmc"
        }
        self.assertEqual(registered, self.EXPECTED_IDS)

    def test_checks_for_filters_by_platform(self):
        ids = {check.id for check in registry.checks_for("bmc")}
        self.assertEqual(ids, self.EXPECTED_IDS)

    def test_every_check_has_collector_compare_and_tier(self):
        diffcore = _loader.diffcore
        for check in registry.CHECKS.values():
            if check.platform != "bmc":
                continue
            self.assertTrue(callable(check.collector), check.id)
            self.assertIn("mode", check.compare, check.id)
            self.assertIn(check.compare["mode"], diffcore.MODES, check.id)
            self.assertIn(check.tier, (1, 2, 3), check.id)
            self.assertTrue(check.description, check.id)

    def test_only_the_checks_whose_healthy_state_is_empty_are_tagged_so(self):
        # the shakedown reads their empty view as ok; every other empty view is flagged
        tagged = {
            check.id for check in registry.checks_for("bmc") if registry.EMPTY_OK_TAG in check.tags
        }
        self.assertEqual(tagged, {"bmc_event_log"})

    def test_budgets_within_transport_ceiling(self):
        ceiling = _loader.constants.REDFISH_MAX_CHECK_BUDGET
        for name in dir(checks):
            if name.startswith("_BUDGET_"):
                value = getattr(checks, name)
                self.assertTrue(1 <= value <= ceiling, name)

    def test_every_collector_declares_a_budget_named_after_its_check(self):
        for check in registry.checks_for("bmc"):
            ctx = _FakeCtx(_base_payloads())
            try:
                check.collector(ctx)
            except (registry.SkipCheck, registry.CollectError):
                pass
            self.assertEqual([label for label, _n in ctx.budgets], [check.id], check.id)


class TestCuration(unittest.TestCase):
    def test_actions_etags_dropped_and_secrets_scrubbed(self):
        curated = checks._curate(_fx("xcc_security.json"))
        self.assertNotIn("Actions", curated)
        self.assertEqual(curated["SED"]["SED_AK"], "***scrubbed***")
        self.assertTrue(curated["SED"]["EncryptionEnabled"])
        system = checks._curate(_fx("xcc_system.json"))
        self.assertNotIn("@odata.etag", system)
        self.assertNotIn("Actions", system)
        self.assertEqual(system["Oem"]["Lenovo"]["SystemStatus"], "BootingOSOrInUndetectedOS")

    def test_capped_lines_marks_truncation(self):
        pairs = [("k%05d" % (i,), "v" * 50) for i in range(1000)]
        text = checks._capped_lines(pairs)
        self.assertLessEqual(len(text), checks._RAW_TEXT_CAP + 40)
        self.assertIn("...[truncated", text)
        self.assertTrue(text.startswith("k00000=v"))

    def test_fenced_link_refuses_actions(self):
        with self.assertRaises(checks.CollectError):
            checks._fenced_link({"@odata.id": SYS + "/Actions/ComputerSystem.Reset"}, "t")
        self.assertEqual(
            checks._fenced_link({"@odata.id": CH + "/Thermal#/Fans/0"}, "t"), CH + "/Thermal"
        )
        self.assertIsNone(checks._fenced_link(None, "t"))
        self.assertIsNone(checks._fenced_link({"Name": "no link"}, "t"))


class TestSystem(unittest.TestCase):
    def test_normalize_from_fixtures(self):
        view = checks._normalize_system(
            _fx("xcc_system.json"),
            _fx("xcc_secure_boot.json"),
            _fx("xcc_manager.json"),
            _fx("xcc_manager_nic.json"),
            "NIC",
            lenovo=True,
        )
        self.assertEqual(view["serial"], "J3001ABC")
        self.assertEqual(view["uuid"], "3C7F1E2A-5B6C-4D8E-9F01-23456789ABCD")
        self.assertEqual(view["model"], "7Z46CTO1WW")
        self.assertEqual(view["bios_version"], "HYE134C-2.31")
        self.assertEqual(view["power_state"], "On")
        self.assertEqual(view["health"], "OK")
        self.assertEqual(view["cpu_count"], 1)
        self.assertEqual(view["memory_gib"], 128)
        self.assertEqual(view["boot_override"], "Disabled")  # string, never bool
        self.assertEqual(view["boot_override_target"], "None")
        self.assertIs(view["secure_boot_enabled"], True)
        self.assertEqual(view["secure_boot_current"], "Enabled")
        self.assertEqual(view["secure_boot_mode"], "DeployedMode")
        self.assertEqual(view["system_status"], "BootingOSOrInUndetectedOS")
        self.assertEqual(view["bmc_firmware"], "TEI3E4D-4.12")
        self.assertEqual(view["bmc_health"], "OK")
        self.assertEqual(view["bmc_state"], "Enabled")
        self.assertEqual(view["bmc_ip"], "192.0.2.21")
        self.assertEqual(view["bmc_ip_origin"], "Static")
        self.assertEqual(view["bmc_gateway"], "192.0.2.1")
        self.assertIs(view["bmc_vlan_enabled"], False)
        self.assertIsNone(view["bmc_vlan"])  # None when VLAN disabled
        self.assertEqual(view["bmc_mac"], "08:94:ef:aa:bb:01")  # lower-cased
        self.assertFalse([key for key in view if key.startswith("xcc_")])
        self.assertEqual(view["eth_member_used"], "NIC")
        self.assertIsNone(view["asset_tag"])  # '' is unset, never ''
        # The widened fields exist on every view; this System serves only the TPM list.
        self.assertEqual(
            (view["tpm_count"], view["tpm_interface_types"], view["tpm_firmware"]),
            (1, ["TPM2_0"], ["7.2.2.0"]),
        )
        for field in (
            "power_restore_policy",  # the fixture's Oem SystemPowerRestorePolicy is not it
            "power_on_delay_s",
            "power_mode",
            "host_watchdog_enabled",
            "serial_console_enabled",
            "graphical_console_enabled",
            "virtual_media_service_enabled",
            "front_panel_usb_mode",  # FrontPanelUSB.Mode is not the served FPMode
            "tpm_rpp_enabled",
            "bmc_serial_console_enabled",
            "bmc_command_shell_enabled",
        ):
            self.assertIn(field, view)
            self.assertIsNone(view[field], field)

    def test_secure_boot_404_gives_three_nones_and_bmc_health_never_borrows_the_state(self):
        # XCC 6.10 serves the Manager's Status with a State and no Health.
        manager = _fx("xcc_manager.json")
        manager["Status"] = {"State": "Enabled"}
        view = checks._normalize_system(_fx("xcc_system.json"), None, manager, None, None)
        self.assertIsNone(view["secure_boot_enabled"])
        self.assertIsNone(view["secure_boot_current"])
        self.assertIsNone(view["secure_boot_mode"])
        self.assertIsNone(view["bmc_health"])
        self.assertEqual(view["bmc_state"], "Enabled")
        self.assertIsNone(view["bmc_ip"])
        self.assertIsNone(view["eth_member_used"])

    def test_collector_direct_nic_and_shared_fetches(self):
        ctx = _FakeCtx(_base_payloads())
        result = checks._collect_system(ctx)
        self.assertEqual(result["normalized"]["eth_member_used"], "NIC")
        self.assertEqual(result["context"]["manager_nic"]["source"], "direct")
        self.assertEqual(result["context"]["reboot_count"], 27)
        self.assertEqual(result["context"]["power_on_hours"], 9137)
        self.assertEqual(result["context"]["bmc_datetime"], "2026-09-24T14:02:11+00:00")
        self.assertEqual(result["context"]["trusted_modules"][0]["interface_type"], "TPM2_0")
        self.assertEqual(
            ctx.gets, RESOLVE + [SYS + "/SecureBoot", MGR, MGR + "/EthernetInterfaces/NIC"]
        )
        self.assertIn(MGR + "/EthernetInterfaces/NIC", result["raw"])
        self.assertNotIn("Actions", result["raw"][SYS])
        # The same GETs serve the sibling checks from the cache: no new wire requests.
        checks._collect_manager_network(ctx)
        self.assertEqual(ctx.gets[6:], [MGR + "/NetworkProtocol"])

    def test_collector_nic_collection_fallback_never_takes_first_member(self):
        payloads = _base_payloads()
        del payloads[MGR + "/EthernetInterfaces/NIC"]
        # The collection lists ToHost first; the real management port is the
        # one with a routable address, however the firmware orders Members.
        payloads[MGR + "/EthernetInterfaces"]["Members"] = [
            {"@odata.id": MGR + "/EthernetInterfaces/ToHost"},
            {"@odata.id": MGR + "/EthernetInterfaces/eth0"},
        ]
        payloads[MGR + "/EthernetInterfaces/eth0"] = dict(_fx("xcc_manager_nic.json"), Id="eth0")
        ctx = _FakeCtx(payloads)
        result = checks._collect_system(ctx)
        self.assertEqual(result["normalized"]["eth_member_used"], "eth0")
        self.assertEqual(result["normalized"]["bmc_ip"], "192.0.2.21")
        self.assertEqual(result["context"]["manager_nic"]["source"], "collection")
        self.assertNotIn(MGR + "/EthernetInterfaces/ToHost", ctx.gets)

    def test_collector_secure_boot_404_and_no_manager_nic_at_all(self):
        payloads = _base_payloads()
        del payloads[SYS + "/SecureBoot"]
        del payloads[MGR + "/EthernetInterfaces/NIC"]
        del payloads[MGR + "/EthernetInterfaces"]
        result = checks._collect_system(_FakeCtx(payloads))
        self.assertIsNone(result["normalized"]["secure_boot_enabled"])
        self.assertIsNone(result["raw"][SYS + "/SecureBoot"])
        self.assertEqual(result["context"]["manager_nic"]["source"], "absent")
        self.assertIsNone(result["normalized"]["bmc_mac"])

    def test_missing_system_is_a_failed_read(self):
        payloads = _base_payloads()
        del payloads[SYS]
        with self.assertRaises(_FakeRedfishError):
            checks._collect_system(_FakeCtx(payloads))


class TestSystemPolicy(unittest.TestCase):
    """Power restore, delays, watchdog, host consoles, TPM and the Lenovo leaves (hand-built:
    XCC 6.10 serves only the watchdog and the TPM list among the DMTF ones)."""

    def _payloads(self, vendor=None):
        payloads = _base_payloads()
        payloads[SYS] = _fx("xcc_system_dmtf_policy.json")
        manager = payloads[MGR]
        manager["LastResetTime"] = "2026-09-27T23:10:00+00:00"
        manager["Oem"]["Lenovo"]["release_name"] = "release-x"
        manager["SerialConsole"] = {"ServiceEnabled": True, "ConnectTypesSupported": ["SSH"]}
        manager["GraphicalConsole"] = {"ServiceEnabled": False}
        manager["CommandShell"] = {"ServiceEnabled": True}
        if vendor:
            payloads["/redfish/v1/"] = dict(payloads["/redfish/v1/"], Vendor=vendor)
        return payloads

    def test_every_dmtf_policy_leaf_is_read(self):
        result = checks._collect_system(_FakeCtx(self._payloads()))
        view = result["normalized"]
        self.assertEqual(view["power_restore_policy"], "LastState")
        self.assertEqual(
            (view["power_on_delay_s"], view["power_off_delay_s"], view["power_cycle_delay_s"]),
            (30.0, 0.0, 5.5),
        )
        self.assertEqual(view["power_mode"], "BalancedPerformance")
        self.assertIs(view["host_watchdog_enabled"], True)
        self.assertEqual(view["host_watchdog_timeout_action"], "ResetSystem")
        self.assertEqual(view["host_watchdog_warning_action"], "DiagnosticInterrupt")
        self.assertIs(view["serial_console_enabled"], True)  # SSH on, IPMI and Telnet off
        self.assertIs(view["graphical_console_enabled"], True)
        self.assertIs(view["virtual_media_service_enabled"], False)
        # sorted, and a module serving no firmware version adds none
        self.assertEqual(view["tpm_count"], 2)
        self.assertEqual(view["tpm_interface_types"], ["TPM1_2", "TPM2_0"])
        self.assertEqual(view["tpm_firmware"], ["7.2.2.0"])
        self.assertEqual(view["system_status"], "OSBooted")
        self.assertEqual(view["front_panel_usb_mode"], "Shared")
        self.assertIs(view["front_panel_usb_port_enabled"], True)
        self.assertIs(view["tpm_rpp_enabled"], False)
        # the BMC's own console services are the Manager's blocks, never the host's
        self.assertIs(view["bmc_serial_console_enabled"], True)
        self.assertIs(view["bmc_graphical_console_enabled"], False)
        self.assertIs(view["bmc_command_shell_enabled"], True)
        self.assertEqual(view["boot_override"], "Once")  # the trio stays until bmc_boot

    def test_volatile_facts_ride_in_context(self):
        context = checks._collect_system(_FakeCtx(self._payloads()))["context"]
        self.assertEqual(context["last_reset_time"], "2026-09-28T06:14:02+00:00")
        self.assertEqual(
            context["boot_progress"],
            {"last_state": "OSRunning", "last_state_time": "2026-09-28T06:16:40+00:00"},
        )
        self.assertIs(context["location_indicator_active"], False)
        self.assertEqual(context["manager_last_reset_time"], "2026-09-27T23:10:00+00:00")
        self.assertEqual(context["release_name"], "release-x")
        self.assertEqual(
            context["serial_console_protocols"], {"IPMI": False, "SSH": True, "Telnet": False}
        )
        self.assertEqual((context["reboot_count"], context["power_on_hours"]), (3, 120))
        self.assertEqual(len(context["trusted_modules"]), 2)  # the per-module list stays

    def test_serial_console_any_on_all_off_or_none_served(self):
        console = checks._system_serial_console
        self.assertEqual(
            console(
                {
                    "SerialConsole": {
                        "IPMI": {"ServiceEnabled": False},
                        "SSH": {"ServiceEnabled": True},
                    }
                }
            ),
            (True, {"IPMI": False, "SSH": True}),
        )
        self.assertEqual(
            console({"SerialConsole": {"IPMI": {"ServiceEnabled": False}, "Telnet": {"Port": 23}}}),
            (False, {"IPMI": False}),  # a block without ServiceEnabled is not served
        )
        for system in (
            {},
            {"SerialConsole": {"MaxConcurrentSessions": 2}},
            {"SerialConsole": None},
        ):
            self.assertEqual(console(system), (None, {}), system)

    def test_tpm_trio(self):
        self.assertEqual(checks._system_tpm({}), (None, None, None))  # unserved
        self.assertEqual(checks._system_tpm({"TrustedModules": []}), (0, [], []))
        self.assertEqual(
            checks._system_tpm(
                {"TrustedModules": [{"InterfaceType": "TPM2_0", "FirmwareVersion": ""}]}
            ),
            (1, ["TPM2_0"], []),
        )

    def test_lenovo_leaves_only_for_lenovo(self):
        system = _fx("xcc_system_dmtf_policy.json")
        view = checks._normalize_system(system, None, None, None, None)  # lenovo defaults off
        for field in (
            "system_status",
            "front_panel_usb_mode",
            "front_panel_usb_port_enabled",
            "tpm_rpp_enabled",
        ):
            self.assertIsNone(view[field], field)
        self.assertEqual(view["power_restore_policy"], "LastState")  # DMTF: every vendor
        result = checks._collect_system(_FakeCtx(self._payloads(vendor="Contoso")))
        self.assertIsNone(result["normalized"]["system_status"])
        self.assertIs(result["normalized"]["host_watchdog_enabled"], True)
        context = result["context"]
        self.assertEqual((context["reboot_count"], context["power_on_hours"]), (None, None))
        self.assertIsNone(context["release_name"])

    def test_the_same_system_twice_diffs_to_nothing(self):
        compare = registry.CHECKS["bmc_system"].compare
        pre = checks._collect_system(_FakeCtx(self._payloads()))["normalized"]
        post = checks._collect_system(_FakeCtx(self._payloads()))["normalized"]
        self.assertEqual(_loader.diffcore.diff_check(pre, post, compare)["result"], "pass")
        post["power_restore_policy"] = "AlwaysOff"
        diff = _loader.diffcore.diff_check(pre, post, compare)
        self.assertEqual(
            [(row["key"], row["old"], row["new"]) for row in diff["changed"]],
            [("power_restore_policy", "LastState", "AlwaysOff")],
        )


class TestSecurityState(unittest.TestCase):
    THINKEDGE = (
        "lockdown_mode",
        "lockdown_control",
        "motion_detection_enabled",
        "motion_threshold",
        "motion_orientation",
        "chassis_intrusion_enabled",
        "host_shutdown_on_tamper",
        "sed_encryption_enabled",
    )

    def test_normalize_finds_fields_under_nested_blocks(self):
        view, sources, readings = checks._normalize_security_state(_fx("xcc_security.json"))
        self.assertEqual(view["lockdown_mode"], "Inactive")
        self.assertEqual(view["lockdown_control"], "ThinkShieldPortal")
        self.assertIs(view["motion_detection_enabled"], True)
        self.assertEqual(view["motion_threshold"], "Medium")
        self.assertEqual(view["motion_orientation"], "Horizontal")
        self.assertIs(view["chassis_intrusion_enabled"], True)
        self.assertIs(view["host_shutdown_on_tamper"], False)
        self.assertIs(view["sed_encryption_enabled"], True)
        self.assertEqual(sources["lockdown_mode"], "SystemLockdown.LockdownMode")
        self.assertEqual(sources["sed_encryption_enabled"], "SED.EncryptionEnabled")
        self.assertNotIn("SED.SED_AK", checks._flatten(_fx("xcc_security.json")))
        # ...and every leaf keyed verbatim beside them (the first-class field is the boolean)
        self.assertEqual(view["security|SystemLockdown.LockdownMode"], "Inactive")
        self.assertEqual(view["security|MotionDetection"], "Enabled")
        self.assertIs(view["security|SED.EncryptionEnabled"], True)
        self.assertFalse([key for key in view if "SED_AK" in key or "Actions" in key])
        self.assertEqual(readings, {})

    def test_normalize_plain_resource_has_no_sources(self):
        view, sources, _readings = checks._normalize_security_state(_fx("xcc_security_plain.json"))
        self.assertEqual(sources, {})
        self.assertTrue(all(view[field] is None for field in self.THINKEDGE))
        self.assertEqual(view["security|SSLSettings.HTTPSCertificateExpiry"], "2027-01-01")
        # the key-manager link inside the resource is navigation, not a leaf
        self.assertEqual(
            sorted(key for key in view if key.startswith("security|")),
            ["security|SSLSettings.HTTPSCertificateExpiry"],
        )

    def test_collector_present(self):
        ctx = _FakeCtx(_base_payloads())
        result = checks._collect_security_state(ctx)
        view = result["normalized"]
        self.assertEqual(view["lockdown_mode"], "Inactive")
        self.assertEqual(result["context"]["security_resource"], MGR + "/Oem/Lenovo/Security")
        self.assertEqual(view["sklm|KeyManagementType"], "Local")
        self.assertEqual(view["sklm|KeyRepoServers"], [])
        self.assertEqual(view["sklm|Status.State"], "Enabled")
        self.assertFalse([key for key in view if "Password" in key])  # never keyed
        self.assertEqual(
            result["context"]["key_management"],
            {
                "resource": MGR + "/Oem/Lenovo/SecureKeyLifecycleService",
                "served": True,
                "certificate_collections": [],
            },
        )
        self.assertEqual(
            result["raw"][MGR + "/Oem/Lenovo/SecureKeyLifecycleService"][
                "ClientCertificatePassword"
            ],
            "***scrubbed***",
        )
        self.assertEqual(
            result["raw"][MGR + "/Oem/Lenovo/Security"]["SED"]["SED_AK"], "***scrubbed***"
        )
        self.assertNotIn("Actions", result["raw"][MGR + "/Oem/Lenovo/Security"])
        self.assertNotIn("not-a-real-password", json.dumps(result))

    def test_collector_ok_without_thinkedge_fields(self):
        # A mainstream ThinkSystem serves the resource without any Security Pack leaf:
        # its settings are the capture, the ThinkEdge fields read None.
        payloads = _base_payloads()
        payloads[MGR + "/Oem/Lenovo/Security"] = _fx("xcc_security_plain.json")
        result = checks._collect_security_state(_FakeCtx(payloads))
        self.assertTrue(all(result["normalized"][field] is None for field in self.THINKEDGE))
        self.assertIn("security|SSLSettings.HTTPSCertificateExpiry", result["normalized"])
        self.assertEqual(result["context"]["property_sources"], {})

    def test_an_empty_security_body_is_a_failed_read(self):
        payloads = _base_payloads()
        payloads[MGR + "/Oem/Lenovo/Security"] = {}
        with self.assertRaises(checks.CollectError):
            checks._collect_security_state(_FakeCtx(payloads))

    def test_collector_not_present_on_404_even_without_the_link(self):
        payloads = _base_payloads()
        del payloads[MGR + "/Oem/Lenovo/Security"]
        with self.assertRaises(checks.SkipCheck):
            checks._collect_security_state(_FakeCtx(payloads))
        del payloads[MGR]["Oem"]["Lenovo"]["Security"]
        ctx = _FakeCtx(payloads)
        with self.assertRaises(checks.SkipCheck):
            checks._collect_security_state(ctx)
        self.assertIn(MGR + "/Oem/Lenovo/Security", ctx.gets)  # documented path still tried

    def test_collector_403_is_a_failed_read_not_absence(self):
        ctx = _FakeCtx(_base_payloads(), errors={MGR + "/Oem/Lenovo/Security": 403})
        with self.assertRaises(_FakeRedfishError):
            checks._collect_security_state(ctx)

    def test_collector_refuses_a_security_link_into_actions(self):
        payloads = _base_payloads()
        payloads[MGR]["Oem"]["Lenovo"]["Security"] = {
            "@odata.id": MGR + "/Actions/Oem/Lenovo/Security"
        }
        ctx = _FakeCtx(payloads)
        with self.assertRaises(checks.CollectError):
            checks._collect_security_state(ctx)
        self.assertEqual(ctx.gets, RESOLVE + [MGR])


class TestSecurityLeaves(unittest.TestCase):
    """Leaf-by-leaf keys of the security resource and the key manager (hand-built SKLM: the
    lab unit serves only its two certificate collections; the EKMS names follow the lab's own
    LenovoSecureKeyLifecycle_v1 schema, the values are illustrative)."""

    SKLM = MGR + "/Oem/Lenovo/SecureKeyLifecycleService"

    def _payloads(self, client_members=1, server_count=2):
        payloads = _base_payloads()
        payloads[self.SKLM] = _fx("xcc_security_sklm_configured.json")
        client = self.SKLM + "/ClientCertificate"
        payloads[client] = {
            "@odata.id": client,
            "Members": [{"@odata.id": client + "/%d" % (n,)} for n in range(1, client_members + 1)],
        }
        server = self.SKLM + "/ServerCertificate"
        payloads[server] = {
            "@odata.id": server,
            "Members@odata.count": server_count,
            "Members": [{"@odata.id": server + "/%d" % (n,)} for n in range(1, server_count + 1)],
        }
        return payloads

    def test_lists_are_one_key_sorted_and_structure_is_skipped(self):
        leaves = checks._security_leaves(
            {
                "@odata.id": "/redfish/v1/x",
                "Id": "Security",
                "Name": "Security",
                "Description": "d",
                "Links": {"Related": [{"@odata.id": "/redfish/v1/y"}]},
                "Actions": {"#X.Y": {"target": "/redfish/v1/x/Actions/X.Y"}},
                "WhiteList": ["192.0.2.9", "192.0.2.10", "192.0.2.1"],
                "Ports": [443, 22, 80],
                "Empty": [],
                "Blank": "",
                "Nested": {
                    "Name": "kept below the top",
                    "Mode": "Strict",
                    "Link": {"@odata.id": "/redfish/v1/z"},
                },
                "Servers": [{"Port": 2, "Host": "b"}, {"Port": 1, "Host": "a", "Password": "pw"}],
                "Mixed": ["b", None, "a"],
                "Certificates": [{"@odata.id": "/redfish/v1/c/1"}],
                "Password": "pw",
                "CommunityNames": ["public"],
                "ComplexPassword": True,
            }
        )
        self.assertEqual(
            leaves,
            {
                "WhiteList": ["192.0.2.1", "192.0.2.10", "192.0.2.9"],
                "Ports": [22, 80, 443],
                "Empty": [],
                "Blank": None,
                "Nested.Name": "kept below the top",
                "Nested.Mode": "Strict",
                "Servers": [{"Host": "a", "Port": 1}, {"Host": "b", "Port": 2}],
                "Mixed": ["a", "b", None],
                "ComplexPassword": True,  # a policy flag, not a credential
            },
        )

    def test_a_reordered_list_is_no_change(self):
        first = checks._security_leaves({"S": [{"Index": 2, "H": "b"}, {"Index": 1, "H": "a"}]})
        second = checks._security_leaves({"S": [{"H": "a", "Index": 1}, {"H": "b", "Index": 2}]})
        self.assertEqual(first, second)

    def test_time_like_leaves_are_readings_never_keys(self):
        # matched anywhere in the leaf name: the schema prefixes its own (EKMSLastPollingTime)
        keyed, readings = checks._security_keyed(
            {
                "EKMS.EKMSLastPollingTime": "2026-09-30T02:00:00+00:00",
                "EKMS.LastPollingTime": "2026-09-30T02:00:00+00:00",
                "Clock.DateTime": "2026-09-30T02:00:01+00:00",
                "Clock.LocalDateTime": "2026-09-30T02:00:01+00:00",
                "Cert.LastRenewalDate": "2026-09-01",
                "EKMS.EKMSPollingStatus": "Success",
                "EKMS.EKMSPollingSettings.PollIntervalMinutes": 60,
                "TestConnectionTimeoutInSec": 10,
                "TimeoutLastResort": 3,  # 'Last' not followed by a time word at the end
            },
            "sklm",
        )
        self.assertEqual(
            keyed,
            {
                "sklm|EKMS.EKMSPollingStatus": "Success",
                "sklm|EKMS.EKMSPollingSettings.PollIntervalMinutes": 60,
                "sklm|TestConnectionTimeoutInSec": 10,
                "sklm|TimeoutLastResort": 3,
            },
        )
        self.assertEqual(
            sorted(readings),
            [
                "sklm|Cert.LastRenewalDate",
                "sklm|Clock.DateTime",
                "sklm|Clock.LocalDateTime",
                "sklm|EKMS.EKMSLastPollingTime",
                "sklm|EKMS.LastPollingTime",
            ],
        )

    def test_a_configured_key_manager_is_keyed_and_its_certificates_counted_never_read(self):
        ctx = _FakeCtx(self._payloads())
        result = checks._collect_security_state(ctx)
        view = result["normalized"]
        sklm = {key: value for key, value in view.items() if key.startswith("sklm|")}
        self.assertEqual(
            sklm,
            {
                "sklm|DeviceGroup": "SED_GROUP_1",
                "sklm|EKMS.EKMSLocalCachedKeySettings.LocalCachedKeyEnabled": True,
                "sklm|EKMS.EKMSLocalCachedKeySettings.CacheExpirationIntervalHours": 24,
                "sklm|EKMS.EKMSLocalCachedKeyStatus": "Valid",
                "sklm|EKMS.EKMSPollingSettings.PollingEnabled": True,
                "sklm|EKMS.EKMSPollingSettings.PollIntervalMinutes": 60,
                "sklm|EKMS.EKMSPollingStatus": "Success",
                "sklm|KeyRepoServers": [
                    {"HostName": "kms-a.example.net", "Index": 1, "Port": 5696},
                    {"HostName": "kms-b.example.net", "Index": 2, "Port": 5696},
                    {"HostName": None, "Index": 3, "Port": 5696},
                ],
                "sklm|Protocol": "KMIP",
                "sklm|TestConnectionTimeoutInSec": 10,
                "sklm|ClientCertificate.Members@odata.count": 1,
                "sklm|ServerCertificate.Members@odata.count": 2,
            },
        )
        self.assertEqual(
            result["context"]["readings"],
            {"sklm|EKMS.EKMSLastPollingTime": "2026-09-30T02:00:00+00:00"},
        )
        self.assertEqual(
            result["context"]["key_management"]["certificate_collections"],
            ["ClientCertificate", "ServerCertificate"],
        )
        # the collections are read, their certificates never
        self.assertEqual(
            ctx.gets[-3:],
            [self.SKLM, self.SKLM + "/ClientCertificate", self.SKLM + "/ServerCertificate"],
        )
        self.assertFalse([path for path in ctx.gets if "/ServerCertificate/" in path])
        self.assertNotIn("not-a-real-password", json.dumps(result))
        self.assertEqual(result["raw"][self.SKLM]["ClientCertificatePassword"], checks._SCRUBBED)
        self.assertNotIn("Actions", result["raw"][self.SKLM])
        self.assertLessEqual(len(ctx.gets), checks._BUDGET_SECURITY)

    def test_a_certificate_collection_that_404s_counts_none(self):
        payloads = self._payloads()
        del payloads[self.SKLM + "/ServerCertificate"]
        result = checks._collect_security_state(_FakeCtx(payloads))
        self.assertIsNone(result["normalized"]["sklm|ServerCertificate.Members@odata.count"])
        self.assertIsNone(result["raw"][self.SKLM + "/ServerCertificate"])

    def test_a_certificate_link_into_actions_is_refused(self):
        payloads = self._payloads()
        payloads[self.SKLM]["ServerCertificate"] = {"@odata.id": self.SKLM + "/Actions/x"}
        with self.assertRaises(checks.CollectError):
            checks._collect_security_state(_FakeCtx(payloads))

    def test_certificate_counts_are_refused_up_front_when_the_budget_cannot_cover_them(self):
        payloads = self._payloads()
        for n in range(checks._BUDGET_SECURITY):
            payloads[self.SKLM]["ExtraCertificate%d" % (n,)] = {
                "@odata.id": self.SKLM + "/ExtraCertificate%d" % (n,)
            }
        ctx = _FakeCtx(payloads)
        with self.assertRaises(checks.CollectError) as caught:
            checks._collect_security_state(ctx)
        self.assertIn("certificate collection", str(caught.exception))
        self.assertEqual(ctx.gets[-1], self.SKLM)  # nothing counted before the refusal

    def test_no_key_manager_leaves_the_check_ok_without_sklm_keys(self):
        payloads = _base_payloads()
        del payloads[self.SKLM]
        result = checks._collect_security_state(_FakeCtx(payloads))
        self.assertFalse([key for key in result["normalized"] if key.startswith("sklm|")])
        self.assertIs(result["context"]["key_management"]["served"], False)
        del payloads[MGR]["Oem"]["Lenovo"]["SecureKeyLifecycleService"]
        ctx = _FakeCtx(payloads)
        result = checks._collect_security_state(ctx)
        self.assertIsNone(result["context"]["key_management"]["resource"])
        self.assertNotIn(self.SKLM, ctx.gets)  # followed by link only, never guessed

    def test_the_same_resource_twice_diffs_to_nothing_and_a_setting_is_one_change(self):
        compare = registry.CHECKS["bmc_security"].compare
        pre = checks._collect_security_state(_FakeCtx(self._payloads()))["normalized"]
        post = checks._collect_security_state(_FakeCtx(self._payloads()))["normalized"]
        self.assertEqual(_loader.diffcore.diff_check(pre, post, compare)["result"], "pass")
        post["sklm|Protocol"] = "SKLM"
        diff = _loader.diffcore.diff_check(pre, post, compare)
        self.assertEqual([row["key"] for row in diff["changed"]], ["sklm|Protocol"])


class TestThermal(unittest.TestCase):
    def test_normalize_keys_readings_and_absent(self):
        view, context = checks._normalize_thermal(_fx("xcc_thermal.json"))
        self.assertEqual(view["temp|Ambient Temp"]["reading_c"], 24)
        self.assertEqual(view["temp|Ambient Temp"]["physical_context"], "Intake")
        self.assertEqual(view["temp|Exhaust Temp"]["reading_c"], 38)
        self.assertIsNone(view["temp|CPU Temp"]["reading_c"])  # load-driven: context only
        self.assertEqual(context["readings_c"]["temp|CPU Temp"], 61)
        # Duplicate Name -> MemberId fallback in the key, both rows kept.
        self.assertIn("temp|DIMM Temp|2", view)
        self.assertIn("temp|DIMM Temp|3", view)
        self.assertNotIn("temp|DIMM Temp", view)
        self.assertNotIn("temp|M.2 Temp", view)  # State Absent == no key
        self.assertEqual(context["absent"], ["temp|M.2 Temp"])
        self.assertEqual(context["thresholds"]["temp|Ambient Temp"]["upper_threshold_critical"], 46)
        self.assertNotIn("upper_threshold_fatal", context["thresholds"]["temp|Ambient Temp"])
        self.assertEqual(
            view["fan|Fan 1"],
            {"health": "OK", "state": "Enabled", "reading": 4200, "reading_units": "RPM"},
        )
        self.assertEqual(view["fan|Fan 3"]["health"], "Warning")
        self.assertEqual(context["temperatures_total"], 6)
        self.assertEqual(context["fans_total"], 3)
        self.assertEqual(context["fan_redundancy"][0]["member_count"], 3)
        self.assertEqual(context["fan_redundancy"][0]["mode"], "N+m")
        self.assertEqual(context["margins"], [])  # no DTS sensor, no negative reading
        self.assertIsNone(context["temperature_summary_c"])  # ThermalMetrics not read

    def test_collector_and_empty_temperatures_is_a_failed_read(self):
        ctx = _FakeCtx(_base_payloads())
        result = checks._collect_thermal(ctx)
        # the Chassis (shared with bmc_chassis) names the thermal resources it serves
        self.assertEqual(ctx.gets, RESOLVE + [CH, CH + "/Thermal"])
        self.assertIn("temp|Ambient Temp", result["normalized"])
        context = result["context"]
        self.assertEqual(context["temperatures_source"], CH + "/Thermal")
        self.assertEqual(context["fans_source"], CH + "/Thermal")
        # the hand-built Chassis links no ThermalSubsystem: no summary read
        self.assertIsNone(context["temperature_summary_c"])
        self.assertIsNone(context["temperature_summary_source"])
        self.assertEqual(set(result["raw"]), {CH + "/Thermal"})
        payloads = _base_payloads()
        payloads[CH + "/Thermal"]["Temperatures"] = []
        with self.assertRaises(checks.CollectError):
            checks._collect_thermal(_FakeCtx(payloads))

    def test_bands_declared_as_the_plan_states(self):
        compare = registry.CHECKS["bmc_thermal"].compare
        self.assertEqual(compare["fields"]["reading_c"]["tolerance"], {"abs": 8})
        self.assertEqual(compare["fields"]["reading"]["tolerance"], {"pct": 25})


class TestThermalSubsystem(unittest.TestCase):
    """bmc_thermal beyond the legacy resource: margins, the ThermalMetrics summary, and the
    ThermalSubsystem fans that stand in where a firmware serves no Thermal."""

    SUB = CH + "/ThermalSubsystem"

    def _fan(self, fan_id, name, rpm=None, percent=None, state="Enabled", health="OK"):
        speed = {"DataSourceUri": CH + "/Sensors/" + fan_id}
        if rpm is not None:
            speed["SpeedRPM"] = rpm
        if percent is not None:
            speed["Reading"] = percent
        return {
            "@odata.id": self.SUB + "/Fans/" + fan_id,
            "Id": fan_id,
            "Name": name,
            "PhysicalContext": "Fan",
            "Status": {"State": state, "Health": health},
            "SpeedPercent": speed,
        }

    def _fans(self, members, payloads, expand=True):
        fans = {"@odata.id": self.SUB + "/Fans", "Members": members}
        payloads.pop(self.SUB + "/Fans" + EXPAND, None)
        if expand:
            payloads[self.SUB + "/Fans" + EXPAND] = fans
        plain, by_path = _split_collection(fans)
        payloads[self.SUB + "/Fans"] = plain
        payloads.update(by_path)
        return payloads

    def _payloads(self, with_thermal=False, expand=True):
        """The hand-built set with a ThermalSubsystem linked (and Thermal served or not)."""
        payloads = _base_payloads()
        payloads[CH]["ThermalSubsystem"] = {"@odata.id": self.SUB}
        if not with_thermal:
            del payloads[CH + "/Thermal"]
        payloads[self.SUB] = {
            "@odata.id": self.SUB,
            "Id": "ThermalSubsystem",
            "Status": {"State": "Enabled", "Health": "OK"},
            "Fans": {"@odata.id": self.SUB + "/Fans"},
            "ThermalMetrics": {"@odata.id": self.SUB + "/ThermalMetrics"},
            "FanRedundancy": [
                {
                    "RedundancyType": "NPlusM",
                    "MaxSupportedInGroup": 3,
                    "MinNeededInGroup": 2,
                    "RedundancyGroup": [
                        {"@odata.id": self.SUB + "/Fans/" + fan} for fan in ("F1", "F2", "F3")
                    ],
                    "Status": {"State": "Enabled", "Health": "OK"},
                }
            ],
        }
        payloads[self.SUB + "/ThermalMetrics"] = {
            "@odata.id": self.SUB + "/ThermalMetrics",
            "TemperatureSummaryCelsius": {
                "Ambient": {"Reading": 23, "DataSourceUri": CH + "/Sensors/Ambient"},
                "Intake": {"Reading": 23.5},
                "Exhaust": {"Reading": 31},
                "Internal": {"Reading": None},
            },
            "TemperatureReadingsCelsius": [{"PhysicalContext": "CPU", "Reading": 61}],
        }
        members = [
            self._fan("F1", "Fan 1", rpm=4200),
            self._fan("F2", "Fan 2", percent=41),
            self._fan("F3", "Fan 3", rpm=6100, health="Warning"),
            self._fan("F4", "Fan 4", state="Absent", health=None),
        ]
        return self._fans(members, payloads, expand=expand)

    def test_margins_are_dts_names_and_negative_readings(self):
        thermal = _fx("xcc_thermal.json")
        status = {"State": "Enabled", "Health": "OK"}
        thermal["Temperatures"] += [
            # named DTS: a margin whatever its sign
            {"MemberId": "6", "Name": "CPU1 DTS", "ReadingCelsius": 12, "Status": status},
            # a negative reading is headroom, not cold
            {"MemberId": "7", "Name": "PCH Margin", "ReadingCelsius": -8, "Status": status},
        ]
        view, context = checks._normalize_thermal(thermal)
        self.assertEqual(context["margins"], ["temp|CPU1 DTS", "temp|PCH Margin"])
        # keyed like any sensor, their readings in context only
        self.assertIsNone(view["temp|CPU1 DTS"]["reading_c"])
        self.assertEqual(context["readings_c"]["temp|PCH Margin"], -8)

    def test_the_summary_is_one_get_whenever_the_chassis_links_a_subsystem(self):
        payloads = self._payloads(with_thermal=True)
        ctx = _FakeCtx(payloads)
        result = checks._collect_thermal(ctx)
        # the subsystem resource itself is not needed beside the legacy one
        self.assertEqual(ctx.gets, RESOLVE + [CH, CH + "/Thermal", self.SUB + "/ThermalMetrics"])
        self.assertEqual(
            result["context"]["temperature_summary_c"],
            {"ambient": 23.0, "intake": 23.5, "exhaust": 31.0, "internal": None},
        )
        self.assertEqual(
            result["context"]["temperature_summary_source"], self.SUB + "/ThermalMetrics"
        )
        self.assertIn(self.SUB + "/ThermalMetrics", result["raw"])
        # the keys are the legacy ones, unchanged by the summary
        plain = checks._collect_thermal(_FakeCtx(_base_payloads()))["normalized"]
        self.assertEqual(result["normalized"], plain)
        # a firmware that serves no ThermalMetrics leaves the summary null, never fails
        del payloads[self.SUB + "/ThermalMetrics"]
        result = checks._collect_thermal(_FakeCtx(payloads))
        self.assertIsNone(result["context"]["temperature_summary_c"])
        self.assertIsNone(result["context"]["temperature_summary_source"])
        self.assertEqual(result["normalized"], plain)

    def test_without_thermal_the_subsystem_fans_are_keyed_the_same_way(self):
        ctx = _FakeCtx(self._payloads())
        result = checks._collect_thermal(ctx)
        view, context = result["normalized"], result["context"]
        self.assertEqual(sorted(view), ["fan|Fan 1", "fan|Fan 2", "fan|Fan 3"])
        # the same key and row the legacy Fans[] member gives for the same fan
        legacy = checks._normalize_thermal(_fx("xcc_thermal.json"))[0]
        self.assertEqual(view["fan|Fan 1"], legacy["fan|Fan 1"])
        self.assertEqual(view["fan|Fan 2"]["reading"], 41)
        self.assertEqual(view["fan|Fan 2"]["reading_units"], "Percent")  # no RPM served
        self.assertEqual(view["fan|Fan 3"]["health"], "Warning")
        self.assertEqual(context["absent"], ["fan|Fan 4"])
        self.assertFalse([key for key in view if key.startswith("temp|")])
        self.assertIsNone(context["temperatures_source"])
        self.assertEqual(context["fans_source"], self.SUB + "/Fans")
        self.assertEqual(context["fans_collection"]["strategy"], "expand")
        self.assertEqual(
            context["fan_redundancy"],
            [
                {
                    "member_id": None,
                    "mode": "NPlusM",
                    "state": "Enabled",
                    "health": "OK",
                    "member_count": 3,
                }
            ],
        )
        self.assertEqual(context["temperature_summary_c"]["exhaust"], 31.0)
        self.assertEqual(
            ctx.gets,
            RESOLVE
            + [
                CH,
                CH + "/Thermal",
                self.SUB,
                self.SUB + "/ThermalMetrics",
                self.SUB + "/Fans" + EXPAND,
            ],
        )
        self.assertEqual(
            set(result["raw"]),
            {self.SUB, self.SUB + "/ThermalMetrics", self.SUB + "/Fans" + EXPAND},
        )

    def test_fans_are_walked_one_by_one_when_expand_is_not_usable(self):
        ctx = _FakeCtx(self._payloads(expand=False))
        result = checks._collect_thermal(ctx)
        self.assertEqual(result["context"]["fans_collection"]["strategy"], "members")
        self.assertIn(self.SUB + "/Fans/F4", ctx.gets)
        self.assertEqual(sorted(result["normalized"]), ["fan|Fan 1", "fan|Fan 2", "fan|Fan 3"])

    def _many_fans(self, count):
        payloads = self._payloads(expand=False)
        del payloads[SYS]["Links"]  # the id resolution then costs its full five GETs
        payloads["/redfish/v1/Managers"] = {"Members": [{"@odata.id": MGR}]}
        payloads["/redfish/v1/Chassis"] = {"Members": [{"@odata.id": CH}]}
        members = [self._fan("F%d" % n, "Fan %d" % n, rpm=5000) for n in range(1, count + 1)]
        return self._fans(members, payloads, expand=False)

    def test_sixteen_fans_walked_fit_the_budget_and_more_are_refused_whole(self):
        ctx = _FakeCtx(self._many_fans(16))
        result = checks._collect_thermal(ctx)
        self.assertEqual(len(result["normalized"]), 16)
        self.assertEqual(len(ctx.gets), checks._BUDGET_THERMAL)
        with self.assertRaises(checks.CollectError) as caught:
            checks._collect_thermal(_FakeCtx(self._many_fans(17)))
        self.assertIn("17 members to fetch", str(caught.exception))

    def test_not_present_and_failed_shapes(self):
        # neither view linked nor served: not present
        payloads = _base_payloads()
        del payloads[CH + "/Thermal"]
        del payloads[CH]["Thermal"]
        with self.assertRaises(registry.SkipCheck):
            checks._collect_thermal(_FakeCtx(payloads))
        # the Chassis links Thermal, it answers 404 and no subsystem stands in: failed
        payloads = _base_payloads()
        del payloads[CH + "/Thermal"]
        with self.assertRaises(checks.CollectError):
            checks._collect_thermal(_FakeCtx(payloads))
        # a linked subsystem that answers 404: failed
        payloads = self._payloads()
        del payloads[self.SUB]
        with self.assertRaises(checks.CollectError):
            checks._collect_thermal(_FakeCtx(payloads))
        # a linked Fans collection that answers 404: failed, never "no fans"
        payloads = self._payloads(expand=False)
        del payloads[self.SUB + "/Fans"]
        with self.assertRaises(checks.CollectError):
            checks._collect_thermal(_FakeCtx(payloads))
        # a subsystem that lists no present fan: nothing to key, not present
        for members in ([], [self._fan("F4", "Fan 4", state="Absent", health=None)]):
            payloads = self._fans(members, self._payloads())
            with self.assertRaises(registry.SkipCheck) as caught:
                checks._collect_thermal(_FakeCtx(payloads))
            self.assertIn("lists no present fan", str(caught.exception))


class TestPower(unittest.TestCase):
    def test_normalize_psu_redundancy_voltages(self):
        view, context = checks._normalize_power(_fx("xcc_power.json"))
        psu0 = view["psu|0"]
        self.assertIsNone(psu0["name"])  # Name null on Lenovo: key is MemberId
        self.assertEqual(psu0["state"], "Enabled")
        self.assertEqual(psu0["health"], "OK")
        self.assertEqual(psu0["line_input_voltage"], 121)
        self.assertIs(psu0["input_in_range"], True)
        self.assertEqual(psu0["capacity_w"], 240)
        self.assertEqual(psu0["serial"], "ADP0000001")
        self.assertIsNone(psu0["firmware"])
        self.assertIsNone(psu0["line_input_status"])  # a legacy Power supply carries none
        psu1 = view["psu|1"]
        self.assertEqual(psu1["health"], "Critical")
        self.assertIs(psu1["input_in_range"], False)  # 160 V sits between the two ranges
        self.assertIsNone(psu1["serial"])  # '' -> None, never ''
        self.assertEqual(
            view["redundancy|0"],
            {"mode": "N+1", "state": "Enabled", "health": "Warning", "member_count": 2},
        )
        self.assertIs(view["voltage|0"]["in_threshold"], True)
        self.assertIs(view["voltage|1"]["in_threshold"], False)
        self.assertIsNone(view["voltage|2"]["in_threshold"])  # no thresholds published
        self.assertIsNone(view["voltage|0"]["health"])
        self.assertEqual(context["power_consumed_w"], 96)
        self.assertEqual(context["voltage_readings"]["1"], 3.9)
        self.assertEqual(context["psu_readings"]["0"]["last_output_w"], 90)

    def test_no_redundancy_block_means_no_redundancy_key(self):
        power = _fx("xcc_power.json")
        del power["Redundancy"]
        view, _context = checks._normalize_power(power)
        self.assertFalse([key for key in view if key.startswith("redundancy|")])

    def test_collector(self):
        ctx = _FakeCtx(_base_payloads())
        result = checks._collect_power(ctx)
        self.assertEqual(ctx.gets, RESOLVE + [CH, CH + "/Power"])
        self.assertNotIn("Actions", result["raw"][CH + "/Power"])
        self.assertEqual(result["context"]["psu_source"], CH + "/Power")
        self.assertEqual(result["context"]["psu_total"], 2)
        self.assertNotIn("supplies_collection", result["context"])
        self.assertEqual(
            registry.CHECKS["bmc_power"].compare["fields"]["line_input_voltage"]["tolerance"],
            {"pct": 10},
        )


class TestPowerSubsystem(unittest.TestCase):
    """bmc_power where the legacy resource is absent or models nothing: PowerSubsystem supplies
    (a case the lab unit lacks — it serves no supply anywhere — hand-built from the DMTF
    PowerSupply schema in xcc_power_subsystem_supplies_expanded.json)."""

    SUB = CH + "/PowerSubsystem"
    SUPPLIES = SUB + "/PowerSupplies"

    def _metrics(self, bay, volts, watts_in, watts_out):
        return {
            "@odata.id": self.SUPPLIES + "/" + bay + "/Metrics",
            "Status": {"State": "Enabled", "Health": "OK"},
            "InputVoltage": {"Reading": volts, "DataSourceUri": CH + "/Sensors/" + bay + "V"},
            "InputPowerWatts": {"Reading": watts_in},
            "OutputPowerWatts": {"Reading": watts_out},
        }

    def _supplies(self, payloads, supplies, expand=True):
        payloads.pop(self.SUPPLIES + EXPAND, None)
        if expand:
            payloads[self.SUPPLIES + EXPAND] = supplies
        plain, by_path = _split_collection(supplies)
        payloads[self.SUPPLIES] = plain
        payloads.update(by_path)
        return payloads

    def _payloads(self, legacy=None, expand=True):
        """The hand-built set with a PowerSubsystem; ``legacy`` replaces Power (None: 404)."""
        payloads = _base_payloads()
        if legacy is None:
            del payloads[CH + "/Power"]
        else:
            payloads[CH + "/Power"] = legacy
        payloads[CH]["PowerSubsystem"] = {"@odata.id": self.SUB}
        payloads[self.SUB] = {
            "@odata.id": self.SUB,
            "Id": "PowerSubsystem",
            "CapacityWatts": 1500,
            "Status": {"State": "Enabled", "Health": "Critical"},
            "PowerSupplies": {"@odata.id": self.SUPPLIES},
            "PowerSupplyRedundancy": [
                {
                    "RedundancyType": "Failover",
                    "MaxSupportedInGroup": 2,
                    "MinNeededInGroup": 1,
                    "RedundancyGroup": [
                        {"@odata.id": self.SUPPLIES + "/Bay1"},
                        {"@odata.id": self.SUPPLIES + "/Bay2"},
                    ],
                    "Status": {"State": "Enabled", "Health": "Critical"},
                }
            ],
        }
        payloads[self.SUPPLIES + "/Bay1/Metrics"] = self._metrics("Bay1", 207.5, 212, 198)
        payloads[self.SUPPLIES + "/Bay2/Metrics"] = self._metrics("Bay2", 0, 0, 0)
        return self._supplies(
            payloads, _fx("xcc_power_subsystem_supplies_expanded.json"), expand=expand
        )

    def test_supplies_and_their_metrics_stand_in_for_an_absent_power(self):
        ctx = _FakeCtx(self._payloads())
        result = checks._collect_power(ctx)
        view, context = result["normalized"], result["context"]
        self.assertEqual(sorted(view), ["psu|Bay1", "psu|Bay2", "redundancy|0"])
        bay1 = view["psu|Bay1"]
        self.assertEqual(bay1["name"], "Power Supply Bay 1")
        self.assertEqual((bay1["state"], bay1["health"]), ("Enabled", "OK"))
        self.assertEqual(bay1["line_input_voltage"], 207.5)  # from the supply's Metrics
        self.assertEqual(bay1["line_input_status"], "Normal")
        self.assertEqual(bay1["line_input_voltage_type"], "AC200To240V")
        self.assertIsNone(bay1["input_in_range"])  # these ranges carry no voltage bounds
        self.assertEqual(bay1["capacity_w"], 750)
        self.assertEqual((bay1["serial"], bay1["firmware"]), ("PSU0000001", "1.2.3"))
        bay2 = view["psu|Bay2"]
        self.assertEqual((bay2["health"], bay2["line_input_status"]), ("Critical", "LossOfInput"))
        self.assertEqual(bay2["line_input_voltage"], 0)  # a zero reading is a reading
        self.assertIsNone(bay2["serial"])  # '' -> None, never ''
        self.assertEqual(
            view["redundancy|0"],
            {"mode": "Failover", "state": "Enabled", "health": "Critical", "member_count": 2},
        )
        self.assertEqual(
            context["psu_readings"]["Bay1"],
            {"input_w": 212, "output_w": 198, "last_output_w": None},
        )
        self.assertEqual(context["power_capacity_w"], 1500)
        self.assertIsNone(context["power_consumed_w"])
        self.assertEqual(context["psu_source"], self.SUPPLIES)
        self.assertEqual(context["supplies_collection"]["strategy"], "expand")
        self.assertEqual(
            ctx.gets,
            RESOLVE
            + [
                CH,
                CH + "/Power",
                self.SUB,
                self.SUPPLIES + EXPAND,
                self.SUPPLIES + "/Bay1/Metrics",
                self.SUPPLIES + "/Bay2/Metrics",
            ],
        )
        self.assertEqual(
            set(result["raw"]),
            {
                self.SUB,
                self.SUPPLIES + EXPAND,
                self.SUPPLIES + "/Bay1/Metrics",
                self.SUPPLIES + "/Bay2/Metrics",
            },
        )
        self.assertNotIn("Actions", json.dumps(result["raw"][self.SUPPLIES + EXPAND]))

    def test_a_power_resource_that_models_nothing_reads_the_subsystem_too(self):
        hollow = {
            "@odata.id": CH + "/Power",
            "Id": "Power",
            "PowerControl": [{"MemberId": "0", "PowerConsumedWatts": 180}],
        }
        result = checks._collect_power(_FakeCtx(self._payloads(legacy=hollow)))
        self.assertEqual(sorted(result["normalized"]), ["psu|Bay1", "psu|Bay2", "redundancy|0"])
        self.assertEqual(result["context"]["power_consumed_w"], 180)
        self.assertEqual(result["context"]["psu_source"], self.SUPPLIES)
        self.assertIn(CH + "/Power", result["raw"])

    def test_rails_without_supplies_never_read_the_subsystem(self):
        # the SE350 shape: an empty psu family is legitimate while the rails are keyed
        rails = _fx("xcc_power.json")
        del rails["PowerSupplies"]
        del rails["Redundancy"]
        ctx = _FakeCtx(self._payloads(legacy=rails))
        result = checks._collect_power(ctx)
        self.assertEqual(sorted(result["normalized"]), ["voltage|0", "voltage|1", "voltage|2"])
        self.assertEqual(result["context"]["psu_total"], 0)
        self.assertEqual(result["context"]["psu_source"], CH + "/Power")
        self.assertNotIn(self.SUB, ctx.gets)

    def _many_supplies(self, count):
        payloads = self._payloads(expand=False)
        del payloads[SYS]["Links"]  # the id resolution then costs its full five GETs
        payloads["/redfish/v1/Managers"] = {"Members": [{"@odata.id": MGR}]}
        payloads["/redfish/v1/Chassis"] = {"Members": [{"@odata.id": CH}]}
        template = _fx("xcc_power_subsystem_supplies_expanded.json")["Members"][0]
        members = []
        for n in range(1, count + 1):
            bay = "Bay%d" % (n,)
            member = json.loads(json.dumps(template).replace("Bay1", bay))
            members.append(member)
            payloads[self.SUPPLIES + "/" + bay + "/Metrics"] = self._metrics(bay, 208, 100, 90)
        return self._supplies(payloads, {"Members": members}, expand=False)

    def test_four_supplies_walked_fit_the_budget_and_a_fifth_is_refused_whole(self):
        ctx = _FakeCtx(self._many_supplies(4))
        result = checks._collect_power(ctx)
        self.assertEqual(len([key for key in result["normalized"] if key.startswith("psu|")]), 4)
        self.assertEqual(result["context"]["supplies_collection"]["strategy"], "members")
        self.assertEqual(len(ctx.gets), checks._BUDGET_POWER)
        with self.assertRaises(checks.CollectError) as caught:
            checks._collect_power(_FakeCtx(self._many_supplies(5)))
        self.assertIn("5 supply metrics to fetch", str(caught.exception))

    def test_not_present_and_failed_shapes(self):
        # no legacy resource and a PowerSubsystem that models no supply and no group (the
        # SE350 shape): not present
        payloads = self._payloads()
        del payloads[self.SUB]["PowerSupplies"]
        del payloads[self.SUB]["PowerSupplyRedundancy"]
        with self.assertRaises(registry.SkipCheck) as caught:
            checks._collect_power(_FakeCtx(payloads))
        self.assertIn("models no supply", str(caught.exception))
        # a linked supplies collection that answers 404: failed, never "no supplies"
        payloads = self._payloads(expand=False)
        del payloads[self.SUPPLIES]
        with self.assertRaises(checks.CollectError):
            checks._collect_power(_FakeCtx(payloads))
        # a linked subsystem that answers 404 where no Power is served: failed
        payloads = self._payloads()
        del payloads[self.SUB]
        with self.assertRaises(checks.CollectError):
            checks._collect_power(_FakeCtx(payloads))
        # a Power resource that models nothing, and nothing to stand in: failed, as before
        payloads = _base_payloads()
        payloads[CH + "/Power"] = {"@odata.id": CH + "/Power", "Id": "Power", "PowerControl": []}
        with self.assertRaises(checks.CollectError):
            checks._collect_power(_FakeCtx(payloads))
        # the Chassis links Power, it answers 404 and no subsystem is linked: failed
        payloads = _base_payloads()
        del payloads[CH + "/Power"]
        with self.assertRaises(checks.CollectError):
            checks._collect_power(_FakeCtx(payloads))
        # neither linked nor served: not present
        del payloads[CH]["Power"]
        with self.assertRaises(registry.SkipCheck):
            checks._collect_power(_FakeCtx(payloads))


class TestInventory(unittest.TestCase):
    def test_normalize(self):
        view = checks._normalize_inventory(
            _fx("xcc_memory_expanded.json")["Members"],
            _fx("xcc_processors_expanded.json")["Members"],
            _fx("xcc_pcie_expanded.json")["Members"],
        )
        self.assertEqual(view["dimm|DIMM_1"]["capacity_mib"], 32768)
        self.assertEqual(view["dimm|DIMM_1"]["speed_mhz"], 21333)  # firmware-scaled, as-is
        self.assertEqual(view["dimm|DIMM_1"]["serial"], "0DA10001")
        self.assertEqual(view["dimm|DIMM_1"]["service_label"], "DIMM 1")
        self.assertEqual(view["dimm|DIMM_4"]["state"], "Absent")
        self.assertIsNone(view["dimm|DIMM_4"]["serial"])
        dimm = view["dimm|DIMM_1"]
        self.assertEqual(
            (dimm["error_correction"], dimm["rank_count"], dimm["base_module_type"]),
            ("MultiBitECC", 2, "RDIMM"),
        )
        self.assertEqual((dimm["data_width_bits"], dimm["bus_width_bits"]), (64, 72))
        self.assertEqual(dimm["allowed_speeds_mhz"], [2666])
        # no Lenovo FRU / MPFA leaves in this payload: present, and None
        for field in ("fru_part_number", "manufacture_date", "mpfa_health_major"):
            self.assertIsNone(dimm[field], field)
        self.assertEqual(
            view["cpu|1"],
            {
                "model": "Intel(R) Xeon(R) D-2183IT CPU @ 2.20GHz",
                "socket": "CPU 1",
                "cores": 16,
                "enabled_cores": 16,
                "threads": 32,
                "health": "OK",
                "state": "Enabled",
                "effective_family": "0x6",
                "effective_model": "0x55",
                "step": "0x4",
                "microcode": None,
                "max_speed_mhz": 2200,
                "tdp_w": None,
                "turbo_state": None,
                "serial": None,
            },
        )
        self.assertEqual(view["pcie|ob_1"]["location"], "Onboard 1")  # Oem.Lenovo path
        self.assertEqual(view["pcie|slot_1"]["location"], "Slot 1")  # Slot.Location fallback
        self.assertIsNone(view["pcie|slot_2"]["location"])
        self.assertEqual(view["pcie|slot_1"]["serial"], "M2K0000001")

    def test_collector_expand_strategy(self):
        ctx = _FakeCtx(_base_payloads())
        result = checks._collect_inventory(ctx)
        self.assertEqual(
            ctx.gets,
            RESOLVE
            + [
                SYS + "/Memory" + EXPAND,
                SYS + "/Processors" + EXPAND,
                CH + "/PCIeDevices" + EXPAND,
                # ob_1 links its PCIeFunctions collection; slot_1/slot_2 link none
                CH + "/PCIeDevices/ob_1/PCIeFunctions" + EXPAND,
            ],
        )
        self.assertEqual(result["context"]["collections"]["memory"]["strategy"], "expand")
        self.assertEqual(result["context"]["collections"]["memory"]["members"], 4)
        self.assertEqual(result["context"]["host_power_state"], "On")
        self.assertEqual(result["context"]["unmeasured"], [])
        self.assertEqual(
            result["context"]["pcie_functions"],
            {
                "ob_1": {"source": "PCIeFunctions", "strategy": "expand", "members": 2},
                "slot_1": {"source": None, "strategy": None, "members": None},
                "slot_2": {"source": None, "strategy": None, "members": None},
            },
        )
        self.assertEqual(
            sorted(key for key in result["normalized"] if key.startswith("pciefn|")),
            ["pciefn|ob_1|ob_1.00", "pciefn|ob_1|ob_1.vf0"],
        )
        self.assertIn("dimm|DIMM_1", result["normalized"])
        processors_raw = result["raw"][SYS + "/Processors" + EXPAND]
        # Clock speed is a reading: kept in raw and context, absent from the rows.
        self.assertIn("CurrentClockSpeedMHz", processors_raw["Members"][0])
        self.assertEqual(processors_raw["Members"][0]["TotalCores"], 16)
        self.assertEqual(
            result["context"]["clock_speed_mhz"],
            {"1": processors_raw["Members"][0]["CurrentClockSpeedMHz"]},
        )
        self.assertEqual(result["context"]["clock_speed_source"], {"1": "CurrentClockSpeedMHz"})
        self.assertNotIn("clock", str(result["normalized"]).lower())

    def test_collector_member_walk_when_expand_unsupported(self):
        payloads = _without_expand(_base_payloads())
        payloads["/redfish/v1/"]["ProtocolFeaturesSupported"]["ExpandQuery"]["ExpandAll"] = False
        payloads["/redfish/v1/"]["ProtocolFeaturesSupported"]["ExpandQuery"]["NoLinks"] = False
        ctx = _FakeCtx(payloads)
        result = checks._collect_inventory(ctx)
        self.assertFalse([path for path in ctx.gets if EXPAND in path])
        self.assertEqual(result["context"]["collections"]["memory"]["strategy"], "members")
        self.assertEqual(result["context"]["collections"]["memory"]["members"], 4)
        self.assertIn(SYS + "/Memory/DIMM_3", ctx.gets)
        self.assertEqual(result["normalized"]["dimm|DIMM_3"]["serial"], "0DA10003")
        self.assertIn(SYS + "/Memory/DIMM_3", result["raw"])

    def test_collector_falls_back_when_expand_refused_or_ignored(self):
        # Advertised but refused with an HTTP error -> walk, and the refusal is paid once:
        # Processors, PCIeDevices and the function collections are walked without asking.
        payloads = _base_payloads()
        ctx = _FakeCtx(payloads, errors={SYS + "/Memory" + EXPAND: 501})
        result = checks._collect_inventory(ctx)
        self.assertEqual(result["context"]["collections"]["memory"]["strategy"], "members")
        self.assertEqual(result["context"]["collections"]["memory"]["expand_refused"], "HTTP 501")
        self.assertEqual(result["context"]["collections"]["processors"]["strategy"], "members")
        self.assertEqual(result["context"]["collections"]["pcie"]["strategy"], "members")
        self.assertEqual(
            [path for path in ctx.gets if path.endswith(EXPAND)], [SYS + "/Memory" + EXPAND]
        )
        self.assertEqual(result["context"]["pcie_functions"]["ob_1"]["strategy"], "members")
        self.assertIn("pciefn|ob_1|ob_1.vf0", result["normalized"])
        # An $expand form answering 404 beside a served collection is a refusal too.
        payloads = _base_payloads()
        del payloads[SYS + "/Memory" + EXPAND]
        ctx = _FakeCtx(payloads)
        result = checks._collect_inventory(ctx)
        self.assertEqual(result["context"]["collections"]["memory"]["expand_refused"], "HTTP 404")
        self.assertEqual(
            [path for path in ctx.gets if path.endswith(EXPAND)], [SYS + "/Memory" + EXPAND]
        )
        # Honoured with 200 but members are bare links -> walk.
        payloads = _base_payloads()
        payloads[CH + "/PCIeDevices" + EXPAND] = payloads[CH + "/PCIeDevices"]
        ctx = _FakeCtx(payloads)
        result = checks._collect_inventory(ctx)
        self.assertEqual(result["context"]["collections"]["pcie"]["strategy"], "members")
        self.assertEqual(
            result["context"]["collections"]["pcie"]["expand_refused"], "members returned as links"
        )
        self.assertEqual(len([key for key in result["normalized"] if key.startswith("pcie|")]), 3)

    def test_host_off_with_empty_collection_is_unmeasured_not_all_gone(self):
        payloads = _base_payloads()
        payloads[SYS]["PowerState"] = "Off"
        payloads[CH + "/PCIeDevices" + EXPAND]["Members"] = []
        with self.assertRaises(checks.CollectError) as caught:
            checks._collect_inventory(_FakeCtx(payloads))
        self.assertIn("pcie", str(caught.exception))
        self.assertIn("Off", str(caught.exception))

    def test_host_on_with_empty_collection_is_still_unmeasured(self):
        # Inventory repopulates during POST while PowerState already reads On:
        # an empty family can never be recorded as zero rows on either side.
        payloads = _base_payloads()
        payloads[CH + "/PCIeDevices" + EXPAND]["Members"] = []
        payloads[SYS + "/Memory" + EXPAND]["Members"] = []
        with self.assertRaises(checks.CollectError) as caught:
            checks._collect_inventory(_FakeCtx(payloads))
        self.assertIn("memory, pcie", str(caught.exception))
        self.assertIn("PowerState On", str(caught.exception))
        self.assertIn("unmeasured", str(caught.exception))

    def test_absent_collections(self):
        payloads = _base_payloads()
        for path in list(payloads):
            if path.startswith(CH + "/PCIeDevices"):
                del payloads[path]
        result = checks._collect_inventory(_FakeCtx(payloads))
        self.assertEqual(result["context"]["collections"]["pcie"]["strategy"], "absent")
        self.assertIsNone(result["context"]["collections"]["pcie"]["members"])
        for path in list(payloads):
            if path.startswith(SYS + "/Memory") or path.startswith(SYS + "/Processors"):
                del payloads[path]
        with self.assertRaises(checks.SkipCheck):
            checks._collect_inventory(_FakeCtx(payloads))

    def test_walk_refused_before_it_starts_when_the_budget_cannot_cover_it(self):
        payloads = _without_expand(_base_payloads())
        payloads["/redfish/v1/"]["ProtocolFeaturesSupported"]["ExpandQuery"]["ExpandAll"] = False
        payloads["/redfish/v1/"]["ProtocolFeaturesSupported"]["ExpandQuery"]["NoLinks"] = False
        # 40 DIMM links > what the budget has left after the resolution and the collection.
        collection = payloads[SYS + "/Memory"]
        collection["Members"] = [{"@odata.id": SYS + "/Memory/DIMM_%d" % (i,)} for i in range(40)]
        ctx = _FakeCtx(payloads)
        with self.assertRaises(checks.CollectError) as caught:
            checks._collect_inventory(ctx)
        self.assertIn("40 members", str(caught.exception))
        self.assertFalse([path for path in ctx.gets if path.startswith(SYS + "/Memory/DIMM_")])


class TestInventoryWidened(unittest.TestCase):
    """DIMM configuration, the CPUID signature, clock/cache context and the PCIe function rows."""

    FUNCTIONS = CH + "/PCIeDevices/ob_1/PCIeFunctions"

    def _payloads(self):
        return _base_payloads()  # ob_1's PCIeFunctions, expanded and plain, are in the base set

    def test_dimm_lenovo_leaves_and_the_mpfa_block(self):
        dimm = dict(
            _fx("xcc_memory_expanded.json")["Members"][0],
            AllowedSpeedsMHz=[2933, "2400", 2666, None],
            Oem={
                "Lenovo": {
                    "FruPartNumber": " 01DE974 ",
                    "ManufactureDate": "year 2020 week 07",
                    "MPFA": {"MPFA_HealthStatus": {"Major": 0, "Minor": 2}},
                }
            },
        )
        row = checks._normalize_inventory([dimm], None, None)["dimm|DIMM_1"]
        self.assertEqual(row["allowed_speeds_mhz"], [2400, 2666, 2933])  # sorted ints
        self.assertEqual(row["fru_part_number"], "01DE974")
        self.assertEqual(row["manufacture_date"], "year 2020 week 07")
        self.assertEqual((row["mpfa_health_major"], row["mpfa_health_minor"]), (0, 2))
        # a served empty list stays a list; an unserved leaf is None
        del dimm["AllowedSpeedsMHz"]
        empty = dict(dimm, Id="DIMM_9", AllowedSpeedsMHz=[])
        view = checks._normalize_inventory([dimm, empty], None, None)
        self.assertIsNone(view["dimm|DIMM_1"]["allowed_speeds_mhz"])
        self.assertEqual(view["dimm|DIMM_9"]["allowed_speeds_mhz"], [])

    def test_cpu_rated_limits_and_signature(self):
        cpu = dict(
            _fx("xcc_processors_expanded.json")["Members"][0],
            TDPWatts=100,
            TurboState="Enabled",
            SerialNumber="",
        )
        cpu["ProcessorId"] = dict(cpu["ProcessorId"], MicrocodeInfo="0x2007006")
        row = checks._normalize_inventory(None, [cpu], None)["cpu|1"]
        self.assertEqual(row["model"], "Intel(R) Xeon(R) D-2183IT CPU @ 2.20GHz")  # marketing
        self.assertEqual((row["effective_model"], row["microcode"]), ("0x55", "0x2007006"))
        self.assertEqual((row["tdp_w"], row["turbo_state"]), (100, "Enabled"))
        self.assertIsNone(row["serial"])  # '' is unset, never ''

    def test_clock_speed_and_caches_fall_back_through_the_served_leaves(self):
        cpu = copy.deepcopy(_fx("xcc_processors_expanded.json")["Members"][0])
        del cpu["CurrentClockSpeedMHz"]
        cpu["Oem"]["Lenovo"]["CurrentClockSpeedMHz"] = 2200
        cpu["ProcessorMemory"] = [
            {"MemoryType": "L2Cache", "CapacityMiB": 16},
            {"MemoryType": "HBM2", "CapacityMiB": 8192},
        ]
        context = checks._inventory_cpu_context([cpu])
        self.assertEqual(context["clock_speed_mhz"], {"1": 2200})
        self.assertEqual(context["clock_speed_source"], {"1": "Oem.Lenovo.CurrentClockSpeedMHz"})
        self.assertEqual(
            context["cpu_caches"]["1"],
            {"source": "ProcessorMemory", "caches": [{"level": "L2Cache", "capacity_mib": 16}]},
        )
        cpu["CurrentClockSpeedMHz"] = 1900  # the top-level leaf wins over the OEM one ...
        self.assertEqual(checks._inventory_cpu_context([cpu])["clock_speed_mhz"], {"1": 1900})
        cpu["OperatingSpeedMHz"] = 1800  # ... and the DMTF leaf over both
        cpu["Oem"]["Lenovo"]["CacheInfo"] = [
            {"CacheLevel": "L1", "InstalledSizeKByte": 1024, "MaxCacheSizeKByte": 1024}
        ]
        context = checks._inventory_cpu_context([cpu])
        self.assertEqual(context["clock_speed_mhz"], {"1": 1800})
        self.assertEqual(context["clock_speed_source"], {"1": "OperatingSpeedMHz"})
        self.assertEqual(context["cpu_caches"]["1"]["source"], "Oem.Lenovo.CacheInfo")
        self.assertEqual(
            checks._inventory_cpu_context([{"Id": "2"}]),
            {
                "clock_speed_mhz": {"2": None},
                "clock_speed_source": {"2": None},
                "cpu_caches": {"2": {"source": None, "caches": []}},
            },
        )

    def test_function_rows_one_expand_get_per_device(self):
        ctx = _FakeCtx(self._payloads())
        result = checks._collect_inventory(ctx)
        view = result["normalized"]
        self.assertEqual(
            view["pciefn|ob_1|ob_1.00"],
            {
                "function_type": "Physical",
                "device_class": "NetworkController",
                "class_code": "0x020000",
                "vendor_id": "0x8086",
                "device_id": "0x37d2",
                "subsystem_id": "0x4020",
                "subsystem_vendor_id": "0x17aa",
                "enabled": True,
                "state": "Enabled",
            },
        )
        vf = view["pciefn|ob_1|ob_1.vf0"]  # an SR-IOV VF: Enabled and the State, each as served
        self.assertEqual(
            (vf["function_type"], vf["enabled"], vf["state"]), ("Virtual", False, "Enabled")
        )
        self.assertEqual(ctx.gets[-1], self.FUNCTIONS + EXPAND)
        self.assertEqual(
            result["context"]["pcie_functions"]["ob_1"],
            {"source": "PCIeFunctions", "strategy": "expand", "members": 2},
        )
        self.assertIn(self.FUNCTIONS + EXPAND, result["raw"])
        self.assertNotIn("Actions", json.dumps(result["raw"][self.FUNCTIONS + EXPAND]))

    def test_enabled_is_the_served_leaf_never_inferred_from_the_state(self):
        # XCC 6.10 serves no PCIeFunction.Enabled: null there, the state its own field.
        row = checks._inventory_function({"Status": {"State": "Disabled"}})
        self.assertEqual((row["enabled"], row["state"]), (None, "Disabled"))
        row = checks._inventory_function({"Status": {"State": "Enabled"}})
        self.assertEqual((row["enabled"], row["state"]), (None, "Enabled"))
        row = checks._inventory_function({"Enabled": False, "Status": {"State": "Enabled"}})
        self.assertEqual((row["enabled"], row["state"]), (False, "Enabled"))
        row = checks._inventory_function({"VendorId": "0x8086"})
        self.assertEqual((row["enabled"], row["state"]), (None, None))

    def test_a_listed_device_without_functions_is_unmeasured(self):
        # Every PCI device has function 0: an empty or 404 function collection on a
        # listed device refuses the check rather than diffing as "functions gone".
        for served in ({"Members": []}, None):
            payloads = self._payloads()
            for path in [path for path in payloads if path.startswith(self.FUNCTIONS)]:
                del payloads[path]
            if served is not None:
                payloads[self.FUNCTIONS] = served
            with self.assertRaises(checks.CollectError) as caught:
                checks._collect_inventory(_FakeCtx(payloads))
            self.assertIn("ob_1", str(caught.exception))
            self.assertIn("unmeasured", str(caught.exception))
        # An Absent or Disabled device may carry none: recorded, never refused.
        for state in ("Absent", "Disabled"):
            payloads = self._payloads()
            for path in [path for path in payloads if path.startswith(self.FUNCTIONS)]:
                del payloads[path]
            payloads[self.FUNCTIONS] = {"Members": []}
            payloads[CH + "/PCIeDevices" + EXPAND]["Members"][0]["Status"]["State"] = state
            result = checks._collect_inventory(_FakeCtx(payloads))
            self.assertEqual(result["context"]["pcie_functions"]["ob_1"]["members"], 0, state)
            self.assertFalse([key for key in result["normalized"] if key.startswith("pciefn|")])

    def test_the_deprecated_links_array_is_read_link_by_link(self):
        payloads = self._payloads()
        device = payloads[CH + "/PCIeDevices" + EXPAND]["Members"][0]
        del device["PCIeFunctions"]
        device["Links"] = {"PCIeFunctions": [{"@odata.id": self.FUNCTIONS + "/ob_1.00"}]}
        ctx = _FakeCtx(payloads)
        result = checks._collect_inventory(ctx)
        self.assertIn("pciefn|ob_1|ob_1.00", result["normalized"])
        self.assertNotIn("pciefn|ob_1|ob_1.vf0", result["normalized"])
        self.assertEqual(ctx.gets[-1], self.FUNCTIONS + "/ob_1.00")
        self.assertEqual(
            result["context"]["pcie_functions"]["ob_1"],
            {"source": "Links.PCIeFunctions", "strategy": "members", "members": 1},
        )

    def test_a_refused_expand_is_never_retried_for_the_functions(self):
        # The device collection had to be walked: no function collection tries $expand.
        payloads = self._payloads()
        ctx = _FakeCtx(payloads, errors={CH + "/PCIeDevices" + EXPAND: 501})
        result = checks._collect_inventory(ctx)
        self.assertNotIn(self.FUNCTIONS + EXPAND, ctx.gets)
        self.assertEqual(result["context"]["pcie_functions"]["ob_1"]["strategy"], "members")
        self.assertIn("pciefn|ob_1|ob_1.vf0", result["normalized"])
        # The first function collection refuses: the next device is not asked again.
        payloads = self._payloads()
        second = CH + "/PCIeDevices/slot_1/PCIeFunctions"
        payloads[CH + "/PCIeDevices" + EXPAND]["Members"][1]["PCIeFunctions"] = {
            "@odata.id": second
        }
        payloads[second] = {"Members": [{"@odata.id": second + "/slot_1.00"}]}
        payloads[second + "/slot_1.00"] = {"Id": "slot_1.00", "VendorId": "0x15b3"}
        ctx = _FakeCtx(payloads, errors={self.FUNCTIONS + EXPAND: 501})
        result = checks._collect_inventory(ctx)
        self.assertNotIn(second + EXPAND, ctx.gets)
        self.assertEqual(ctx.gets[-2:], [second, second + "/slot_1.00"])
        self.assertEqual(
            result["context"]["pcie_functions"]["slot_1"],
            {"source": "PCIeFunctions", "strategy": "members", "members": 1},
        )

    def test_function_reads_the_budget_cannot_cover_are_refused_before_any_is_sent(self):
        payloads = self._payloads()
        devices = payloads[CH + "/PCIeDevices" + EXPAND]["Members"]
        for index in range(30):
            devices.append(
                {
                    "@odata.id": CH + "/PCIeDevices/extra_%d" % (index,),
                    "Id": "extra_%d" % (index,),
                    "PCIeFunctions": {
                        "@odata.id": CH + "/PCIeDevices/extra_%d/PCIeFunctions" % (index,)
                    },
                }
            )
        ctx = _FakeCtx(payloads)
        with self.assertRaises(checks.CollectError) as caught:
            checks._collect_inventory(ctx)
        self.assertIn("PCIe functions of 33 device(s)", str(caught.exception))
        self.assertFalse([path for path in ctx.gets if "PCIeFunctions" in path])

    def test_a_function_link_into_actions_is_refused(self):
        payloads = self._payloads()
        payloads[CH + "/PCIeDevices" + EXPAND]["Members"][0]["PCIeFunctions"] = {
            "@odata.id": CH + "/PCIeDevices/ob_1/Actions/x"
        }
        ctx = _FakeCtx(payloads)
        with self.assertRaises(checks.CollectError):
            checks._collect_inventory(ctx)
        self.assertFalse([path for path in ctx.gets if "Actions" in path])


class TestHostNics(unittest.TestCase):
    def test_normalize(self):
        members = [
            m for m in _fx("xcc_host_nics_expanded.json")["Members"] if m["Id"] != "ToManager"
        ]
        view, context = checks._normalize_host_nics(members)
        self.assertEqual(set(view), {"nic|ob-1", "nic|ob-2", "nic|ob-3", "nic|ob-4"})
        self.assertEqual(view["nic|ob-1"]["link_status"], "LinkUp")
        self.assertEqual(view["nic|ob-3"]["link_status"], "NoLink")
        self.assertEqual(view["nic|ob-4"]["link_status"], "LinkDown")
        self.assertEqual(view["nic|ob-1"]["permanent_mac"], "08:94:ef:aa:bb:11")
        self.assertNotIn("description", view["nic|ob-1"])
        self.assertNotIn("speed_mbps", view["nic|ob-1"])
        self.assertIsNone(context["speed_mbps"]["ob-1"])
        self.assertEqual(context["mac_source"]["ob-1"], "PermanentMACAddress")

    def test_speed_zero_and_null_both_read_none(self):
        members = _fx("xcc_host_nics_expanded.json")["Members"][:2]
        members[0]["SpeedMbps"] = 0
        members[1]["SpeedMbps"] = None
        _view, context = checks._normalize_host_nics(members)
        self.assertIsNone(context["speed_mbps"]["ob-1"])
        self.assertIsNone(context["speed_mbps"]["ob-2"])

    def test_collector_expand_excludes_tomanager(self):
        ctx = _FakeCtx(_base_payloads())
        result = checks._collect_host_nics(ctx)
        self.assertNotIn("nic|ToManager", result["normalized"])
        self.assertEqual(result["context"]["excluded"], ["ToManager"])
        self.assertEqual(result["context"]["strategy"], "expand")
        self.assertEqual(result["context"]["members_total"], 5)
        self.assertEqual(result["context"]["host_power_state"], "On")
        self.assertEqual(result["context"]["port_source"], SYS + "/EthernetInterfaces")

    def test_collector_walk_never_fetches_tomanager(self):
        ctx = _FakeCtx(_without_expand(_base_payloads()))
        result = checks._collect_host_nics(ctx)
        self.assertEqual(result["context"]["strategy"], "members")
        self.assertNotIn(SYS + "/EthernetInterfaces/ToManager", ctx.gets)
        self.assertIn(SYS + "/EthernetInterfaces/ob-4", ctx.gets)
        self.assertEqual(
            set(result["normalized"]), {"nic|ob-1", "nic|ob-2", "nic|ob-3", "nic|ob-4"}
        )
        self.assertNotIn(SYS + "/EthernetInterfaces/ToManager", result["raw"])
        self.assertEqual(result["context"]["port_source"], SYS + "/EthernetInterfaces")

    def test_collector_not_present_shapes(self):
        payloads = _base_payloads()
        for path in list(payloads):
            if path.startswith(SYS + "/EthernetInterfaces"):
                del payloads[path]
        with self.assertRaises(checks.SkipCheck):
            checks._collect_host_nics(_FakeCtx(payloads))  # 404
        payloads = _base_payloads()
        payloads[SYS + "/EthernetInterfaces" + EXPAND]["Members"] = [
            m
            for m in payloads[SYS + "/EthernetInterfaces" + EXPAND]["Members"]
            if m["Id"] == "ToManager"
        ]
        with self.assertRaises(checks.SkipCheck):
            checks._collect_host_nics(_FakeCtx(payloads))  # only ToManager
        payloads = _base_payloads()
        for member in payloads[SYS + "/EthernetInterfaces" + EXPAND]["Members"]:
            member["LinkStatus"] = None
        with self.assertRaises(checks.SkipCheck):
            checks._collect_host_nics(_FakeCtx(payloads))  # link state never reported
        payloads = _base_payloads()
        payloads[SYS + "/EthernetInterfaces" + EXPAND]["Members"] = []
        with self.assertRaises(checks.SkipCheck):
            checks._collect_host_nics(_FakeCtx(payloads))  # empty

    def test_collector_5xx_is_a_failed_read(self):
        ctx = _FakeCtx(_without_expand(_base_payloads()), errors={SYS + "/EthernetInterfaces": 500})
        with self.assertRaises(_FakeRedfishError):
            checks._collect_host_nics(ctx)


class TestFirmware(unittest.TestCase):
    def test_normalize_excludes_state_and_dates(self):
        view = checks._normalize_firmware(_fx("xcc_firmware_expanded.json")["Members"])
        self.assertEqual(len([key for key in view if key.startswith("fw|")]), 15)
        # the two scalars are always present, None when their resources were not read
        self.assertEqual(len(view), 17)
        self.assertIsNone(view["manager_active_image"])
        self.assertIsNone(view["backup_auto_promote"])
        self.assertEqual(
            view["fw|BMC-Primary"],
            {
                "name": "BMC-Primary",
                "version": "TEI3E4D-4.12",
                "software_id": "TEI3E4D",
                "updateable": True,
                "health": "OK",
            },
        )
        self.assertIsNone(
            view["fw|BMC-Backup"]["health"]
        )  # StandbyOffline bank: no Health, no State
        self.assertNotIn("state", view["fw|BMC-Backup"])
        self.assertNotIn("release_date", view["fw|UEFI"])
        self.assertEqual(view["fw|Ob_1.0"]["version"], "4.10 0x80001a5e")
        self.assertIs(view["fw|TPM"]["updateable"], False)

    def test_collector_one_expand_get(self):
        ctx = _FakeCtx(_base_payloads())
        result = checks._collect_firmware(ctx)
        self.assertEqual(
            ctx.gets,
            RESOLVE
            + [
                "/redfish/v1/UpdateService/FirmwareInventory" + EXPAND,
                MGR,
                "/redfish/v1/UpdateService",  # absent from this fixture set: 404, optional
            ],
        )
        self.assertEqual(result["context"]["strategy"], "expand")
        self.assertEqual(result["context"]["members"], 15)
        self.assertIsNone(result["context"]["update_service"])
        self.assertEqual(result["context"]["software_inventory"], {"linked": False})
        raw = result["raw"]["/redfish/v1/UpdateService/FirmwareInventory" + EXPAND]
        self.assertNotIn("@odata.etag", raw["Members"][0])

    def test_collector_walk_sorted_by_link_and_complete(self):
        ctx = _FakeCtx(_without_expand(_base_payloads()))
        result = checks._collect_firmware(ctx)
        self.assertEqual(result["context"]["strategy"], "members")
        self.assertEqual(len([key for key in result["normalized"] if key.startswith("fw|")]), 15)
        # resolution (root, Systems, System), expand attempt (404), collection, members,
        # then the Manager and the UpdateService
        self.assertEqual(len(ctx.gets), 3 + 1 + 1 + 15 + 2)

    def test_collector_refuses_a_walk_the_budget_cannot_cover(self):
        payloads = _without_expand(_base_payloads())
        collection = payloads["/redfish/v1/UpdateService/FirmwareInventory"]
        collection["Members"] = [
            {"@odata.id": "/redfish/v1/UpdateService/FirmwareInventory/Slot_%d.0" % (i,)}
            for i in range(30)
        ]
        ctx = _FakeCtx(payloads)
        with self.assertRaises(checks.CollectError) as caught:
            checks._collect_firmware(ctx)
        self.assertIn("30 members", str(caught.exception))
        self.assertNotIn("/redfish/v1/UpdateService/FirmwareInventory/Slot_0.0", ctx.gets)

    def test_budget_exhaustion_from_the_transport_propagates(self):
        # A budget the collector cannot pre-check (unknown member cost) still
        # ends in the transport's refusal, never in a partial view.
        payloads = _without_expand(_base_payloads())
        ctx = _FakeCtx(payloads, opaque_budget=True)
        original = checks._BUDGET_FIRMWARE
        checks._BUDGET_FIRMWARE = 3
        try:
            with self.assertRaises(_FakeRedfishError) as caught:
                checks._collect_firmware(ctx)
        finally:
            checks._BUDGET_FIRMWARE = original
        self.assertIn("budget", str(caught.exception))
        self.assertEqual(len(ctx.gets), 3)

    def test_empty_inventory_is_a_failed_read(self):
        payloads = _base_payloads()
        payloads["/redfish/v1/UpdateService/FirmwareInventory" + EXPAND]["Members"] = []
        ctx = _FakeCtx(payloads)
        with self.assertRaises(checks.CollectError):
            checks._collect_firmware(ctx)
        self.assertNotIn(MGR, ctx.gets)  # refused before anything else is spent


class TestFirmwareWidened(unittest.TestCase):
    """SoftwareInventory rows, the BMC's active image and Lenovo's backup-promotion policy."""

    UPDATE = "/redfish/v1/UpdateService"
    SOFTWARE = "/redfish/v1/UpdateService/SoftwareInventory"

    def _payloads(self):
        payloads = _base_payloads()
        payloads[self.UPDATE] = _fx("xcc_firmware_updateservice.json")
        payloads[self.SOFTWARE + EXPAND] = _fx("xcc_firmware_softwareinventory_expanded.json")
        plain, members = _split_collection(payloads[self.SOFTWARE + EXPAND])
        payloads[self.SOFTWARE] = plain
        payloads.update(members)
        payloads[MGR]["Links"]["ActiveSoftwareImage"] = {
            "@odata.id": "/redfish/v1/UpdateService/FirmwareInventory/BMC-Primary"
        }
        return payloads

    def test_software_rows_active_image_and_backup_policy(self):
        ctx = _FakeCtx(self._payloads())
        result = checks._collect_firmware(ctx)
        view = result["normalized"]
        self.assertEqual(
            view["sw|Driver-i40e"],
            {
                "name": "Intel(R) Ethernet driver",
                "version": "2.22.20",
                "software_id": "DRV-i40e",
                "updateable": False,
                "health": "OK",
            },
        )
        self.assertIsNone(view["sw|Agent-ISM"]["health"])  # no Status served
        self.assertNotIn("release_date", view["sw|Agent-ISM"])
        self.assertEqual(len([key for key in view if key.startswith("fw|")]), 15)
        self.assertEqual(view["manager_active_image"], "BMC-Primary")
        self.assertIs(view["backup_auto_promote"], True)
        self.assertEqual(ctx.gets[-1], self.SOFTWARE + EXPAND)
        self.assertEqual(
            result["context"]["software_inventory"],
            {"linked": True, "strategy": "expand", "members": 2},
        )
        self.assertEqual(result["context"]["update_service"], self.UPDATE)
        self.assertNotIn("Actions", result["raw"][self.UPDATE])
        # the rows diff like any other key: a bank switch is one changed scalar
        post = dict(view, manager_active_image="BMC-Backup")
        diff = _loader.diffcore.diff_check(view, post, registry.CHECKS["bmc_firmware"].compare)
        self.assertEqual(
            diff["changed"],
            [
                {
                    "key": "manager_active_image",
                    "field": None,
                    "old": "BMC-Primary",
                    "new": "BMC-Backup",
                }
            ],
        )

    def test_a_refused_expand_is_not_paid_twice(self):
        ctx = _FakeCtx(
            self._payloads(),
            errors={"/redfish/v1/UpdateService/FirmwareInventory" + EXPAND: 501},
        )
        result = checks._collect_firmware(ctx)
        self.assertNotIn(self.SOFTWARE + EXPAND, ctx.gets)
        self.assertEqual(result["context"]["software_inventory"]["strategy"], "members")
        self.assertIn("sw|Agent-ISM", result["normalized"])

    def test_a_linked_software_inventory_that_answers_404_is_recorded_absent(self):
        payloads = self._payloads()
        for path in (self.SOFTWARE, self.SOFTWARE + EXPAND):
            del payloads[path]
        result = checks._collect_firmware(_FakeCtx(payloads))
        self.assertFalse([key for key in result["normalized"] if key.startswith("sw|")])
        self.assertEqual(
            result["context"]["software_inventory"],
            {"linked": True, "strategy": "absent", "members": None},
        )

    def test_unserved_leaves_read_none_and_other_vendors_keep_the_dmtf_reads(self):
        payloads = self._payloads()
        del payloads[MGR]["Links"]["ActiveSoftwareImage"]
        del payloads[self.UPDATE]["Oem"]
        payloads["/redfish/v1/"] = dict(payloads["/redfish/v1/"], Vendor="Contoso")
        result = checks._collect_firmware(_FakeCtx(payloads))
        self.assertIsNone(result["normalized"]["manager_active_image"])
        self.assertIsNone(result["normalized"]["backup_auto_promote"])
        self.assertIn("sw|Driver-i40e", result["normalized"])

    def test_an_active_image_link_into_actions_is_refused(self):
        payloads = self._payloads()
        payloads[MGR]["Links"]["ActiveSoftwareImage"] = {"@odata.id": MGR + "/Actions/x"}
        with self.assertRaises(checks.CollectError):
            checks._collect_firmware(_FakeCtx(payloads))


class TestEventLog(unittest.TestCase):
    def test_normalize_keys_only_warning_and_critical(self):
        entries = _fx("xcc_log_entries.json")["Members"]
        view, context = checks._normalize_event_log(entries, _fx("xcc_log_service_platform.json"))
        self.assertEqual(
            set(view), {"sel|FQXSPPW0003I|120", "sel|FQXSPSE0000F|200", "sel|FQXSPCA0016M|234"}
        )
        self.assertEqual(
            view["sel|FQXSPSE0000F|200"],
            {
                "severity": "Critical",
                "source": "Security",
                "serviceable": False,
                "serviceable_by": None,  # the sample's boolean names no party
                "event_id": "0x810700C8",
                "hidden": False,
                # Lenovo's documentation sample serves neither leaf: null, never guessed
                "failing_fru": None,
                "log_type": None,
            },
        )
        self.assertIs(view["sel|FQXSPPW0003I|120"]["serviceable"], True)
        self.assertNotIn("message", view["sel|FQXSPPW0003I|120"])
        self.assertEqual(context["entries_by_log_type"], {})
        self.assertEqual(context["entries_total"], 9)
        self.assertEqual(context["keyed_entries"], 3)
        self.assertEqual(context["hidden_entries"], 1)
        self.assertEqual(context["informational_by_code"]["FQXSPNM4028I"], 2)
        self.assertEqual(context["informational_by_code"]["FQXSPNM4001I"], 1)
        self.assertEqual(context["newest_id"], 234)
        self.assertEqual(context["first_id"], 5)
        self.assertEqual(context["newest_created"], "2026-09-24T13:58:12+00:00")
        self.assertEqual(context["max_records"], 1024)
        self.assertEqual(context["overwrite_policy"], "WrapsWhenFull")
        self.assertEqual(context["last_seq_num"], 234)
        self.assertEqual(context["first_seq_num"], 5)
        # A first Id above 1 is how Lenovo's own sample reads; "cleared" is a
        # cross-capture fact and is never claimed from one capture.
        self.assertNotIn("log_cleared", context)
        self.assertIs(context["at_capacity"], False)

    def test_at_capacity_is_the_only_single_capture_wrap_fact(self):
        entries = _fx("xcc_log_entries.json")["Members"]
        _view, context = checks._normalize_event_log(entries, {"MaxNumberOfRecords": 9})
        self.assertIs(context["at_capacity"], True)
        _view, context = checks._normalize_event_log(entries, {"MaxNumberOfRecords": 1024})
        self.assertIs(context["at_capacity"], False)
        _view, context = checks._normalize_event_log([], None)
        self.assertIsNone(context["at_capacity"])
        self.assertIsNone(context["newest_id"])
        self.assertIsNone(context["first_id"])

    def test_missing_common_event_id_keys_unknown(self):
        entry = _fx("xcc_log_entries.json")["Members"][3]
        del entry["Oem"]
        view, _context = checks._normalize_event_log([entry])
        self.assertEqual(list(view), ["sel|unknown|120"])
        self.assertIsNone(view["sel|unknown|120"]["source"])

    def test_collector_platform_log_no_query_string(self):
        ctx = _FakeCtx(_base_payloads())
        result = checks._collect_event_log(ctx)
        self.assertEqual(
            ctx.gets,
            RESOLVE
            + [
                # one $expand try for the services (this hand-built set does not serve it)
                SYS + "/LogServices" + EXPAND,
                SYS + "/LogServices",
                SYS + "/LogServices/PlatformLog",
                SYS + "/LogServices/PlatformLog/Entries",
            ],
        )
        # the log itself is read without any query string: no $top window, no paging choice
        self.assertFalse([path for path in ctx.gets if "$top" in path])
        self.assertFalse([path for path in ctx.gets if "/Entries" in path and "?" in path])
        # every Entries page passes the log redactor, every other read the scrubber
        self.assertIn((SYS + "/LogServices/PlatformLog/Entries", "_redact_log_page"), ctx.redacted)
        self.assertIn((SYS + "/LogServices", "_scrub_payload"), ctx.redacted)
        self.assertEqual(result["context"]["log_service_used"], "PlatformLog")
        self.assertEqual(result["context"]["pages"], 1)
        self.assertEqual(result["context"]["log_services_strategy"], "members")
        self.assertEqual(result["context"]["log_services_served"], ["PlatformLog"])
        # nothing beside the platform log is listed: every auxiliary block says so
        for block in ("active_log", "maintenance_log", "sel"):
            self.assertIs(result["context"][block]["served"], False, block)
        self.assertEqual(result["context"]["audit_log_seq"], {"first": None, "last": None})
        raw_entries = result["raw"][SYS + "/LogServices/PlatformLog/Entries"]["Members"]
        self.assertEqual(raw_entries[0]["Id"], "234")  # newest first
        self.assertEqual(
            raw_entries[0]["Message"],
            "Sensor Ambient Temp has transitioned from normal to non-critical state.",
        )
        self.assertIn("Created", raw_entries[0])
        self.assertNotIn("Actions", result["raw"][SYS + "/LogServices/PlatformLog"])

    def test_collector_standard_log_branch_and_neither(self):
        payloads = _base_payloads()
        payloads[SYS + "/LogServices"]["Members"] = [
            {"@odata.id": SYS + "/LogServices/StandardLog"}
        ]
        payloads[SYS + "/LogServices/StandardLog"] = dict(
            payloads[SYS + "/LogServices/PlatformLog"],
            Id="StandardLog",
            Entries={"@odata.id": SYS + "/LogServices/StandardLog/Entries"},
        )
        payloads[SYS + "/LogServices/StandardLog/Entries"] = payloads[
            SYS + "/LogServices/PlatformLog/Entries"
        ]
        result = checks._collect_event_log(_FakeCtx(payloads))
        self.assertEqual(result["context"]["log_service_used"], "StandardLog")
        payloads[SYS + "/LogServices"]["Members"] = [
            {"@odata.id": SYS + "/LogServices/AuditLog"},
            {"@odata.id": SYS + "/LogServices/Other"},
        ]
        with self.assertRaises(checks.CollectError):
            checks._collect_event_log(_FakeCtx(payloads))

    def test_collector_follows_next_link_through_the_fence(self):
        # The DSP0266 continuation form: the server pages with $skip (or
        # $skiptoken). The collector never CHOOSES a window — it follows what
        # the server hands back, through the fence.
        payloads = _base_payloads()
        entries = payloads[SYS + "/LogServices/PlatformLog/Entries"]
        second = dict(entries, Members=entries["Members"][5:])
        first = dict(entries, Members=entries["Members"][:5])
        first["Members@odata.nextLink"] = SYS + "/LogServices/PlatformLog/Entries?$skip=5"
        payloads[SYS + "/LogServices/PlatformLog/Entries"] = first
        payloads[SYS + "/LogServices/PlatformLog/Entries?$skip=5"] = second
        ctx = _FakeCtx(payloads)
        result = checks._collect_event_log(ctx)
        self.assertEqual(result["context"]["pages"], 2)
        self.assertEqual(result["context"]["entries_total"], 9)
        self.assertEqual(
            set(result["normalized"]),
            {"sel|FQXSPPW0003I|120", "sel|FQXSPSE0000F|200", "sel|FQXSPCA0016M|234"},
        )
        self.assertEqual(ctx.gets[-1], SYS + "/LogServices/PlatformLog/Entries?$skip=5")
        raw = result["raw"][SYS + "/LogServices/PlatformLog/Entries"]
        self.assertEqual(len(raw["pages_fetched"]), 2)
        # A path-shaped continuation and a $skiptoken one are followed too.
        for link in (
            SYS + "/LogServices/PlatformLog/Entries/Page2",
            SYS + "/LogServices/PlatformLog/Entries?$skiptoken=p2",
        ):
            first["Members@odata.nextLink"] = link
            payloads[link] = second
            self.assertEqual(checks._collect_event_log(_FakeCtx(payloads))["context"]["pages"], 2)
        # A continuation that carries $top (a window) or anything outside the
        # fence is refused loudly, never read as a partial log.
        for link in (
            SYS + "/LogServices/PlatformLog/Entries?$skip=5&$top=5",
            SYS + "/LogServices/PlatformLog/Entries/Actions/x",
        ):
            first["Members@odata.nextLink"] = link
            payloads[link] = second
            with self.assertRaises(checks.CollectError) as caught:
                checks._collect_event_log(_FakeCtx(payloads))
            self.assertIn("continuation", str(caught.exception))

    def test_raw_entries_capped_newest_first(self):
        entries = [
            {
                "Id": str(i),
                "Severity": "OK",
                "Created": "t",
                "Message": "m",
                "Oem": {"Lenovo": {"CommonEventID": "FQXSPNM4028I"}},
            }
            for i in range(1, checks._RAW_LOG_ENTRIES + 51)
        ]
        rows, omitted = checks._curate_entries(entries)
        self.assertEqual(len(rows), checks._RAW_LOG_ENTRIES)
        self.assertEqual(omitted, 50)
        self.assertEqual(rows[0]["Id"], str(checks._RAW_LOG_ENTRIES + 50))


class TestEventLogServices(unittest.TestCase):
    """The ActiveLog, the MaintenanceLog, the SEL probe and the audit counters (hand-built).

    A gen-1-guide-shaped tree: PlatformLog (whose service spells its counters
    FirstSeqNum/LastSeqNum) beside ActiveLog, MaintenanceLog, SEL, AuditLog
    and DiagnosticLog. The lab unit's ActiveLog is empty, so the populated one
    is hand-built in the lab's entry shape (xcc_event_log_active_entries.json).
    """

    LS = SYS + "/LogServices"

    def _history(self, count):
        return [
            {
                "@odata.id": self.LS + "/MaintenanceLog/Entries/%d" % (index,),
                "Id": str(index),
                "EntryType": "Oem",
                "Severity": None,
                "EventGroupId": 1 if index % 3 == 0 else 0,
                "Created": "2026-09-%02dT10:00:00Z" % (1 + index % 28,),
                "Message": "UEFI firmware is updated to HYE1%02dA by XCC Web." % (index % 100,),
            }
            for index in range(1, count + 1)
        ]

    def _services(self):
        def service(service_id, entries=True, **extra):
            body = {"@odata.id": self.LS + "/" + service_id, "Id": service_id}
            body["ServiceEnabled"] = True
            if entries:
                body["Entries"] = {"@odata.id": self.LS + "/" + service_id + "/Entries"}
            body.update(extra)
            return body

        return [
            _fx("xcc_log_service_platform.json"),
            service("ActiveLog", MaxNumberOfRecords=1024),
            service("MaintenanceLog", MaxNumberOfRecords=750),
            service(
                "SEL",
                entries=False,
                MaxNumberOfRecords=511,
                OverWritePolicy="NeverOverWrites",
                Oem={"Lenovo": {"EnableSELWrapping": False}},
            ),
            service("AuditLog", Oem={"Lenovo": {"FirstSeqNum": 3, "LastSeqNum": 88}}),
            service("DiagnosticLog", MaxNumberOfRecords=3),
        ]

    def _payloads(self, expand=False, history=5):
        payloads = _base_payloads()
        services = self._services()
        payloads[self.LS] = {
            "@odata.id": self.LS,
            "Members": [{"@odata.id": body["@odata.id"]} for body in services],
            "Members@odata.count": len(services),
        }
        for body in services:
            payloads[body["@odata.id"]] = body
        if expand:
            payloads[self.LS + EXPAND] = {"@odata.id": self.LS, "Members": copy.deepcopy(services)}
        payloads[self.LS + "/ActiveLog/Entries"] = _fx("xcc_event_log_active_entries.json")
        payloads[self.LS + "/MaintenanceLog/Entries"] = {
            "@odata.id": self.LS + "/MaintenanceLog/Entries",
            "Members": self._history(history),
            "Members@odata.count": history,
        }
        # Never to be read: the audit log's entries (the capture's own logins
        # would land there) and the diagnostic dumps.
        payloads[self.LS + "/AuditLog/Entries"] = {
            "Members": [{"Id": "1", "Message": "Login ID: alice from webguis at IP address x."}]
        }
        payloads[self.LS + "/DiagnosticLog/Entries"] = {"Members": []}
        return payloads

    def test_members_strategy_reads_only_the_services_it_uses(self):
        ctx = _FakeCtx(self._payloads())
        result = checks._collect_event_log(ctx)
        self.assertEqual(
            ctx.gets,
            RESOLVE
            + [self.LS + EXPAND, self.LS]
            + [self.LS + "/" + name for name in ("PlatformLog", "ActiveLog", "MaintenanceLog")]
            + [self.LS + "/SEL", self.LS + "/AuditLog"]
            + [self.LS + "/%s/Entries" % (name,) for name in ("PlatformLog", "ActiveLog")]
            + [self.LS + "/MaintenanceLog/Entries"],
        )
        self.assertFalse([path for path in ctx.gets if "AuditLog/Entries" in path])
        self.assertFalse([path for path in ctx.gets if "DiagnosticLog" in path])
        context = result["context"]
        self.assertEqual(context["log_services_strategy"], "members")
        self.assertIsNone(context["log_services_expand_refused"])
        self.assertEqual(
            context["log_services_served"],
            ["ActiveLog", "AuditLog", "DiagnosticLog", "MaintenanceLog", "PlatformLog", "SEL"],
        )
        self.assertEqual(context["log_service_used"], "PlatformLog")
        # every read passes a redactor, every Entries page the log redactor
        for path in (self.LS + "/ActiveLog/Entries", self.LS + "/MaintenanceLog/Entries"):
            self.assertIn((path, "_redact_log_page"), ctx.redacted)
        self.assertIn((self.LS + "/SEL", "_scrub_payload"), ctx.redacted)

    def test_expand_strategy_is_one_get_for_every_service(self):
        ctx = _FakeCtx(self._payloads(expand=True))
        result = checks._collect_event_log(ctx)
        self.assertEqual(
            ctx.gets,
            RESOLVE
            + [self.LS + EXPAND]
            + [self.LS + "/%s/Entries" % (name,) for name in ("PlatformLog", "ActiveLog")]
            + [self.LS + "/MaintenanceLog/Entries"],
        )
        self.assertEqual(result["context"]["log_services_strategy"], "expand")
        self.assertIn(self.LS + EXPAND, result["raw"])
        # the same view and the same facts whichever way the services were found
        walked = checks._collect_event_log(_FakeCtx(self._payloads()))
        self.assertEqual(result["normalized"], walked["normalized"])
        for key in ("audit_log_seq", "sel", "active_log", "maintenance_log", "log_services_served"):
            self.assertEqual(result["context"][key], walked["context"][key], key)

    def test_active_log_keys_every_condition_whatever_its_severity(self):
        result = checks._collect_event_log(_FakeCtx(self._payloads()))
        view = result["normalized"]
        self.assertEqual(
            {key: row for key, row in view.items() if key.startswith("active|")},
            {
                "active|FQXSPCA0002M|12": {
                    "severity": "Critical",
                    "message_id": None,
                    "created": "2026-09-21T04:12:55.120-05:00",
                    "serviceable": True,  # ServiceableByLenovo
                    "serviceable_by": "Lenovo",
                    "failing_fru": [
                        {"part": "01PF614", "serial": "ZZRSR0000001"},
                        {"part": "01PG900", "serial": "ZZFAN0000002"},
                    ],
                },
                "active|FQXSPPW0008L|13": {
                    "severity": "Warning",
                    "message_id": None,
                    "created": "2026-09-22T11:40:03.004-05:00",
                    "serviceable": False,  # Not Serviceable
                    "serviceable_by": None,
                    "failing_fru": [],
                },
            },
        )
        # the platform log's keys are unchanged beside them
        self.assertEqual(
            {key for key in view if key.startswith("sel|")},
            {"sel|FQXSPPW0003I|120", "sel|FQXSPSE0000F|200", "sel|FQXSPCA0016M|234"},
        )
        self.assertEqual(
            result["context"]["active_log"],
            {
                "served": True,
                "service_enabled": True,
                "max_records": 1024,
                "overwrite_policy": None,
                "entries_link": True,
                "entries_total": 2,
                "pages": 1,
            },
        )
        raw = result["raw"][self.LS + "/ActiveLog/Entries"]
        self.assertEqual([row["Id"] for row in raw["Members"]], ["13", "12"])  # newest first
        self.assertNotIn("@odata.etag", json.dumps(raw))
        # an OK entry is keyed too, and a vendor without CommonEventID keys by MessageId
        other = {
            "Id": "7",
            "Severity": "OK",
            "MessageId": "Contoso.1.0.SensorReset",
            "Created": "t",
        }
        self.assertEqual(
            checks._event_log_normalize_active([other]),
            {
                "active|Contoso.1.0.SensorReset|7": {
                    "severity": "OK",
                    "message_id": "Contoso.1.0.SensorReset",
                    "created": "t",
                    "serviceable": None,
                    "serviceable_by": None,
                    "failing_fru": None,
                }
            },
        )

    def test_an_empty_active_log_is_the_healthy_state(self):
        payloads = self._payloads()
        payloads[self.LS + "/ActiveLog/Entries"] = {"Members": [], "Members@odata.count": 0}
        result = checks._collect_event_log(_FakeCtx(payloads))
        self.assertFalse([key for key in result["normalized"] if key.startswith("active|")])
        self.assertEqual(result["context"]["active_log"]["entries_total"], 0)

    def test_maintenance_log_is_context_and_its_newest_rows_raw(self):
        result = checks._collect_event_log(_FakeCtx(self._payloads(history=130)))
        self.assertEqual({key.split("|")[0] for key in result["normalized"]}, {"sel", "active"})
        self.assertEqual(
            result["context"]["maintenance_log"],
            {
                "served": True,
                "service_enabled": True,
                "max_records": 750,
                "overwrite_policy": None,
                "entries_link": True,
                "pages": 1,
                "entries_total": 130,
                "by_event_group_id": {"0": 87, "1": 43},
                "first_id": 1,
                "newest_id": 130,
                "newest_created": "2026-09-19T10:00:00Z",
                "at_capacity": False,
            },
        )
        raw = result["raw"][self.LS + "/MaintenanceLog/Entries"]
        self.assertEqual(len(raw["Members"]), checks._EVENT_LOG_MAINTENANCE_ROWS)
        self.assertEqual(raw["entries_omitted_from_raw"], 130 - checks._EVENT_LOG_MAINTENANCE_ROWS)
        self.assertEqual(raw["Members"][0]["Id"], "130")
        self.assertEqual(raw["Members"][0]["EventGroupId"], 0)
        self.assertEqual(raw["Members@odata.count"], 130)

    def test_sel_is_a_probe_and_its_wrapping_flag_is_read_where_served(self):
        ctx = _FakeCtx(self._payloads())
        context = checks._collect_event_log(ctx)["context"]
        self.assertEqual(
            context["sel"],
            {
                "served": True,
                "service_enabled": True,
                "max_records": 511,
                "overwrite_policy": "NeverOverWrites",
                "entries_link": False,
            },
        )
        self.assertIs(context["sel_wrapping_enabled"], False)
        self.assertEqual(context["sel_wrapping_source"], "SEL Oem.Lenovo.EnableSELWrapping")
        # a SEL that links Entries is still only probed
        payloads = self._payloads()
        payloads[self.LS + "/SEL"]["Entries"] = {"@odata.id": self.LS + "/SEL/Entries"}
        payloads[self.LS + "/SEL/Entries"] = {"Members": []}
        ctx = _FakeCtx(payloads)
        context = checks._collect_event_log(ctx)["context"]
        self.assertIs(context["sel"]["entries_link"], True)
        self.assertNotIn(self.LS + "/SEL/Entries", ctx.gets)
        # without it on the SEL, the platform log's own service answers
        payloads = self._payloads()
        del payloads[self.LS + "/SEL"]["Oem"]
        payloads[self.LS + "/PlatformLog"]["Oem"]["Lenovo"]["EnableSELWrapping"] = True
        context = checks._collect_event_log(_FakeCtx(payloads))["context"]
        self.assertIs(context["sel_wrapping_enabled"], True)
        self.assertEqual(context["sel_wrapping_source"], "PlatformLog Oem.Lenovo.EnableSELWrapping")

    def test_audit_counters_come_from_a_service_resource_never_its_entries(self):
        # The platform service carries no Audit* counters here: the AuditLog's
        # own resource answers, in its plain spelling.
        ctx = _FakeCtx(self._payloads())
        context = checks._collect_event_log(ctx)["context"]
        self.assertEqual(context["audit_log_seq"], {"first": 3, "last": 88})
        self.assertEqual(
            context["audit_log_seq_source"], "AuditLog Oem.Lenovo.FirstSeqNum/LastSeqNum"
        )
        self.assertIn(self.LS + "/AuditLog", ctx.gets)
        self.assertNotIn(self.LS + "/AuditLog/Entries", ctx.gets)
        # The XCC 6.10 spelling on the platform service wins, and the AuditLog is not read.
        payloads = self._payloads()
        payloads[self.LS + "/PlatformLog"]["Oem"]["Lenovo"].update(
            AuditFirstSeqNum=1, AuditLastSeqNum=176
        )
        ctx = _FakeCtx(payloads)
        context = checks._collect_event_log(ctx)["context"]
        self.assertEqual(context["audit_log_seq"], {"first": 1, "last": 176})
        self.assertEqual(
            context["audit_log_seq_source"],
            "PlatformLog Oem.Lenovo.AuditFirstSeqNum/AuditLastSeqNum",
        )
        self.assertFalse([path for path in ctx.gets if "AuditLog" in path])
        # an AuditLog's own Audit* spelling is preferred to its plain one
        audit = {"Oem": {"Lenovo": {"AuditFirstSeqNum": 2, "AuditLastSeqNum": 9, "LastSeqNum": 1}}}
        self.assertEqual(
            checks._event_log_audit_seq({}, "PlatformLog", audit, "AuditLog"),
            ({"first": 2, "last": 9}, "AuditLog Oem.Lenovo.AuditFirstSeqNum/AuditLastSeqNum"),
        )
        self.assertEqual(
            checks._event_log_audit_seq({}, "PlatformLog"), ({"first": None, "last": None}, None)
        )

    def test_serviceable_reads_lenovo_strings_as_booleans(self):
        for value, expected in (
            ("ServiceableByLenovo", True),
            ("Not Serviceable", False),
            ("not serviceable", False),
            ("NOT_SERVICEABLE", False),
            ("NotServiceable", False),
            (True, True),
            (False, False),
            (["ServiceableByCustomer"], True),
            (["Not Serviceable", "Not Serviceable"], False),
            (["ServiceableByLenovo", "Not Serviceable"], None),
            ([], None),
            ("Unknown", None),
            (None, None),
            (1, None),
            # the LenovoLogEntry enum: who services it is its own field
            ("ServiceableByCustomer", True),
            ("Serviceable By Lenovo", True),
        ):
            self.assertIs(checks._event_log_serviceable(value), expected, value)
        for value, expected in (
            ("ServiceableByLenovo", "Lenovo"),
            ("ServiceableByCustomer", "Customer"),
            ("serviceable by customer", "Customer"),
            ("Serviceable_By_Lenovo", "Lenovo"),
            (["ServiceableByLenovo"], "Lenovo"),
            (["ServiceableByLenovo", "ServiceableByCustomer"], None),
            ("Serviceable", None),
            ("Not Serviceable", None),
            (True, None),
            (None, None),
        ):
            self.assertEqual(checks._event_log_serviceable_by(value), expected, value)

    def test_failing_fru_pairs_are_sorted_and_placeholders_dropped(self):
        def entry(frus):
            return {"Oem": {"Lenovo": {"FailingFRU": frus}}}

        self.assertEqual(
            checks._event_log_failing_fru(
                entry(
                    [
                        {"FRUNumber": "02B", "FRUSerialNumber": ""},
                        {"FRUNumber": "", "FRUSerialNumber": ""},
                        {"FRUNumber": "01A", "FRUSerialNumber": "S2"},
                    ]
                )
            ),
            [{"part": "01A", "serial": "S2"}, {"part": "02B", "serial": None}],
        )
        self.assertEqual(checks._event_log_failing_fru(entry([{"FRUNumber": ""}])), [])
        # a lone pair served without its list reads as a one-element list
        self.assertEqual(
            checks._event_log_failing_fru(entry({"FRUNumber": "01A"})),
            [{"part": "01A", "serial": None}],
        )
        self.assertIsNone(checks._event_log_failing_fru({"Oem": {"Lenovo": {}}}))
        self.assertIsNone(checks._event_log_failing_fru({}))

    def test_a_listed_service_that_answers_404_is_not_served(self):
        payloads = self._payloads()
        del payloads[self.LS + "/ActiveLog"]
        ctx = _FakeCtx(payloads)
        result = checks._collect_event_log(ctx)
        self.assertEqual(
            result["context"]["active_log"],
            {
                "served": False,
                "service_enabled": None,
                "max_records": None,
                "overwrite_policy": None,
                "entries_link": None,
                "entries_total": None,
                "pages": 0,
            },
        )
        self.assertNotIn(self.LS + "/ActiveLog/Entries", ctx.gets)
        self.assertFalse([key for key in result["normalized"] if key.startswith("active|")])
        self.assertIsNone(result["raw"][self.LS + "/ActiveLog"])  # asked, absent
        # the platform log's own service answering 404 is a failed read, never emptiness
        payloads = self._payloads()
        del payloads[self.LS + "/PlatformLog"]
        with self.assertRaises(_FakeRedfishError):
            checks._collect_event_log(_FakeCtx(payloads))

    def test_expand_refused_or_ignored_falls_back_and_other_failures_propagate(self):
        ctx = _FakeCtx(self._payloads(), errors={self.LS + EXPAND: 501})
        context = checks._collect_event_log(ctx)["context"]
        self.assertEqual(context["log_services_strategy"], "members")
        self.assertEqual(context["log_services_expand_refused"], "HTTP 501")
        payloads = self._payloads()
        payloads[self.LS + EXPAND] = payloads[self.LS]  # members come back as bare links
        context = checks._collect_event_log(_FakeCtx(payloads))["context"]
        self.assertEqual(context["log_services_expand_refused"], "members returned as links")
        self.assertEqual(context["active_log"]["entries_total"], 2)

        # a failure without an HTTP status (budget, fence, network) is never a fallback
        class _Unreachable(_FakeCtx):
            def get(self, path, redact=None, **kwargs):
                if path.endswith("/LogServices" + EXPAND):
                    self.gets.append(path)
                    raise _FakeRedfishError("GET %s: connection reset" % (path,))
                return super().get(path, redact=redact, **kwargs)

        ctx = _Unreachable(self._payloads())
        with self.assertRaises(_FakeRedfishError):
            checks._collect_event_log(ctx)
        self.assertEqual(ctx.gets[-1], self.LS + EXPAND)

    def test_no_mapping_is_decided_before_any_member_read(self):
        payloads = _base_payloads()
        payloads["/redfish/v1/"] = dict(payloads["/redfish/v1/"], Vendor="Dell")
        payloads[self.LS] = {
            "Members": [{"@odata.id": self.LS + "/Sel"}, {"@odata.id": self.LS + "/Lclog"}]
        }
        ctx = _FakeCtx(payloads)
        with self.assertRaises(registry.SkipCheck):
            checks._collect_event_log(ctx)
        self.assertEqual(ctx.gets, RESOLVE + [self.LS + EXPAND, self.LS])

    def test_a_lone_audit_log_is_never_taken_for_the_platform_log(self):
        payloads = self._payloads()
        payloads[self.LS] = {"Members": [{"@odata.id": self.LS + "/AuditLog"}]}
        ctx = _FakeCtx(payloads)
        with self.assertRaises(registry.SkipCheck) as caught:
            checks._collect_event_log(ctx)
        self.assertIn("audit log, whose entries are never read", str(caught.exception))
        self.assertFalse([path for path in ctx.gets if "AuditLog" in path])

    def test_a_continuation_that_names_a_page_already_read_is_refused(self):
        payloads = _base_payloads()
        entries_path = self.LS + "/PlatformLog/Entries"
        entries = payloads[entries_path]
        second = dict(entries, Members=entries["Members"][5:])
        entries["Members"] = entries["Members"][:5]
        entries["Members@odata.nextLink"] = entries_path + "?$skip=5"
        second["Members@odata.nextLink"] = entries_path  # back to the first page, forever
        payloads[entries_path + "?$skip=5"] = second
        with self.assertRaises(checks.CollectError) as caught:
            checks._collect_event_log(_FakeCtx(payloads))
        self.assertIn("names a page already read", str(caught.exception))

    def test_every_log_page_is_redacted_before_raw(self):
        payloads = self._payloads()
        rows = payloads[self.LS + "/MaintenanceLog/Entries"]["Members"]
        rows[-1]["Message"] = "UEFI firmware is updated to HYE140C by user alice."
        rows[-1]["MessageArgs"] = ["HYE140C", "alice"]
        result = checks._collect_event_log(_FakeCtx(payloads))
        raw = json.dumps(result["raw"])
        self.assertNotIn("alice", raw)
        newest = result["raw"][self.LS + "/MaintenanceLog/Entries"]["Members"][0]
        self.assertEqual(
            newest["Message"], "UEFI firmware is updated to HYE140C by user ***scrubbed***."
        )

    def test_the_worst_case_walk_fits_the_budget_and_one_page_more_is_refused(self):
        payloads = self._payloads()
        del payloads[SYS]["Links"]  # the id resolution then costs its full five GETs
        payloads["/redfish/v1/Managers"] = {"Members": [{"@odata.id": MGR}]}
        payloads["/redfish/v1/Chassis"] = {"Members": [{"@odata.id": CH}]}

        def paged(path, pages):
            first = payloads[path]
            for number in range(pages):
                page = {"Members": first["Members"] if number == 0 else []}
                if number + 1 < pages:
                    page["Members@odata.nextLink"] = path + "?$skip=%d" % (number + 1,)
                payloads[path if number == 0 else path + "?$skip=%d" % (number,)] = page

        # every log pages: the platform log ten times, the two others three times each
        paged(self.LS + "/PlatformLog/Entries", 10)
        paged(self.LS + "/ActiveLog/Entries", 3)
        paged(self.LS + "/MaintenanceLog/Entries", 3)
        ctx = _FakeCtx(payloads)
        result = checks._collect_event_log(ctx)
        self.assertEqual(len(ctx.gets), checks._BUDGET_EVENT_LOG)
        self.assertEqual(result["context"]["pages"], 10)
        self.assertEqual(result["context"]["maintenance_log"]["pages"], 3)
        # one page more is refused before it is sent: complete or refused
        paged(self.LS + "/MaintenanceLog/Entries", 4)
        with self.assertRaises(_FakeRedfishError) as caught:
            checks._collect_event_log(_FakeCtx(payloads))
        self.assertIn("budget", str(caught.exception))


class TestBios(unittest.TestCase):
    def test_normalize_keys_every_attribute_verbatim(self):
        bios = _fx("xcc_bios.json")
        view = checks._normalize_bios(bios)
        keyed = {key.split("|", 1)[1]: value for key, value in view.items() if "|" in key}
        # every attribute but the two password-valued ones, each value verbatim
        passwords = {"SystemSecurity_AdminPassword", "Q00001_Password"}
        self.assertEqual(set(keyed), set(bios["Attributes"]) - passwords)
        self.assertEqual(keyed, {name: bios["Attributes"][name] for name in keyed})
        self.assertEqual(view["bios|Processors_HyperThreading"], "Enable")
        # outside the retired token curation, now keyed like the rest
        self.assertEqual(view["bios|Memory_MemoryMode"], "Independent")
        self.assertEqual(view["bios|SystemInformation_SerialNumber"], "J3001ABC")
        self.assertFalse([key for key in view if key.startswith("pending|")])
        # an unset string attribute reads None, never ''
        bios["Attributes"]["SystemInformation_AssetTag"] = ""
        self.assertIsNone(checks._normalize_bios(bios)["bios|SystemInformation_AssetTag"])
        # the scalar fields are always present, None where unserved
        self.assertEqual(
            {key: value for key, value in view.items() if "|" not in key},
            {
                "reset_to_defaults_pending": None,
                "uefi_admin_password_set": None,
                "uefi_power_on_password_set": None,
            },
        )

    def test_collector_raw_keeps_the_curated_resource_whole(self):
        ctx = _FakeCtx(_base_payloads())
        result = checks._collect_bios(ctx)
        self.assertEqual(ctx.gets, RESOLVE + [SYS + "/Bios"])  # no settings object linked
        self.assertEqual(list(result["raw"]), [SYS + "/Bios"])
        raw = result["raw"][SYS + "/Bios"]
        self.assertNotIn("Actions", raw)
        self.assertNotIn("@odata.etag", raw)
        self.assertEqual(len(raw["Attributes"]), 29)
        self.assertEqual(raw["Attributes"]["Memory_MemoryMode"], "Independent")
        self.assertEqual(raw["Attributes"]["SystemSecurity_AdminPassword"], "")  # emptiness only
        context = result["context"]
        self.assertEqual(context["attributes_total"], 29)
        self.assertEqual(context["password_attributes_dropped"], 2)
        self.assertEqual(len(result["normalized"]), 27 + 3)
        self.assertEqual(context["pending_total"], 0)
        self.assertIsNone(context["settings_object"])
        self.assertIsNone(context["settings_object_served"])
        self.assertEqual(
            context["attribute_registry"],
            {
                "id": "BiosAttributeRegistryHYE134C-2.31",
                "name": "BiosAttributeRegistryHYE134C-2.31",
                "version": None,
            },
        )

    def test_collector_skip_on_404_and_fail_without_attributes(self):
        payloads = _base_payloads()
        del payloads[SYS + "/Bios"]
        with self.assertRaises(checks.SkipCheck):
            checks._collect_bios(_FakeCtx(payloads))
        payloads = _base_payloads()
        payloads[SYS + "/Bios"]["Attributes"] = {}
        with self.assertRaises(checks.CollectError):
            checks._collect_bios(_FakeCtx(payloads))


class TestBiosPending(unittest.TestCase):
    """The @Redfish.Settings object: settings armed for the next reset, fenced and optional."""

    SETTINGS = SYS + "/Bios/Settings"

    def _payloads(self, settings=None, link=None):
        payloads = _base_payloads()
        bios = payloads[SYS + "/Bios"]
        bios["@Redfish.Settings"] = {
            "@odata.type": "#Settings.v1_3_4.Settings",
            "SettingsObject": {"@odata.id": link or self.SETTINGS},
            "SupportedApplyTimes": ["OnReset", "AtMaintenanceWindowStart"],
            "Time": "2026-09-05T17:47:47-05:00",
            "Messages": [{"MessageId": "Base.1.12.Success"}],
        }
        bios["ResetBiosToDefaultsPending"] = True
        bios["Oem"] = {
            "Lenovo": {"IsUefiAdminPasswordSet": True, "IsUefiPowerOnPasswordSet": False}
        }
        if settings is not None:
            payloads[self.SETTINGS] = settings
        return payloads

    def _changes_only(self):
        """A settings object holding only the changes (the form other vendors serve)."""
        return {
            "@odata.id": self.SETTINGS,
            "Attributes": {
                "Processors_HyperThreading": "Disable",  # armed
                "Processors_TurboMode": "Enable",  # equal to the current value: not pending
                "Processors_NewKnob": 3,  # unknown to the current set: pending
                "SystemSecurity_AdminPassword": "n3w-s3cret",  # never stored anywhere
            },
            "@Redfish.SettingsApplyTime": {"ApplyTime": "OnReset"},
        }

    def test_pending_is_only_what_differs_from_the_current_value(self):
        ctx = _FakeCtx(self._payloads(self._changes_only()))
        result = checks._collect_bios(ctx)
        self.assertEqual(ctx.gets, RESOLVE + [SYS + "/Bios", self.SETTINGS])
        self.assertIn((self.SETTINGS, "_scrub_payload"), ctx.redacted)
        view = result["normalized"]
        self.assertEqual(
            {key: value for key, value in view.items() if key.startswith("pending|")},
            {"pending|Processors_HyperThreading": "Disable", "pending|Processors_NewKnob": 3},
        )
        self.assertEqual(view["bios|Processors_HyperThreading"], "Enable")  # not applied yet
        self.assertIs(view["reset_to_defaults_pending"], True)
        context = result["context"]
        self.assertEqual(context["pending_total"], 2)
        self.assertEqual(context["settings_object"], self.SETTINGS)
        self.assertIs(context["settings_object_served"], True)
        self.assertEqual(context["settings_object_attributes"], 4)
        self.assertEqual(context["settings_apply_time"], "2026-09-05T17:47:47-05:00")
        self.assertEqual(context["supported_apply_times"], ["AtMaintenanceWindowStart", "OnReset"])
        self.assertEqual(context["settings_messages"], ["Base.1.12.Success"])
        self.assertEqual(context["pending_apply_time"], "OnReset")
        # the armed password reaches neither normalized, context nor raw
        self.assertNotIn("n3w-s3cret", json.dumps(result))
        settings_raw = result["raw"][self.SETTINGS]
        self.assertEqual(
            settings_raw["Attributes"]["SystemSecurity_AdminPassword"], checks._SCRUBBED
        )

    def test_a_whole_set_equal_to_the_current_one_is_an_empty_pending_family(self):
        whole = {"@odata.id": self.SETTINGS, "Attributes": dict(_fx("xcc_bios.json")["Attributes"])}
        result = checks._collect_bios(_FakeCtx(self._payloads(whole)))
        self.assertFalse([key for key in result["normalized"] if key.startswith("pending|")])
        self.assertEqual(result["context"]["settings_object_attributes"], 29)
        self.assertEqual(result["context"]["pending_total"], 0)

    def test_uefi_password_flags_are_booleans_that_survive_the_scrub(self):
        result = checks._collect_bios(_FakeCtx(self._payloads(self._changes_only())))
        self.assertIs(result["normalized"]["uefi_admin_password_set"], True)
        self.assertIs(result["normalized"]["uefi_power_on_password_set"], False)
        self.assertEqual(
            result["raw"][SYS + "/Bios"]["Oem"]["Lenovo"],
            {"IsUefiAdminPasswordSet": True, "IsUefiPowerOnPasswordSet": False},
        )

    def test_a_settings_object_that_answers_404_is_no_pending_set(self):
        ctx = _FakeCtx(self._payloads())  # linked, but never served
        result = checks._collect_bios(ctx)
        self.assertIn(self.SETTINGS, ctx.gets)
        self.assertFalse([key for key in result["normalized"] if key.startswith("pending|")])
        self.assertIs(result["context"]["settings_object_served"], False)
        self.assertIsNone(result["context"]["settings_object_attributes"])
        self.assertIsNone(result["raw"][self.SETTINGS])  # asked, absent

    def test_a_settings_object_error_is_a_failed_read(self):
        ctx = _FakeCtx(self._payloads(self._changes_only()), errors={self.SETTINGS: 500})
        with self.assertRaises(_FakeRedfishError):
            checks._collect_bios(ctx)

    def test_the_settings_link_is_fenced_before_it_is_followed(self):
        link = SYS + "/Bios/Actions/Bios.ChangePassword"
        ctx = _FakeCtx(self._payloads(link=link))
        with self.assertRaises(checks.CollectError):
            checks._collect_bios(ctx)
        self.assertEqual(ctx.gets, RESOLVE + [SYS + "/Bios"])

    def test_registry_name_and_version(self):
        self.assertEqual(
            checks._bios_registry("BiosAttributeRegistry.1.0.0"),
            {
                "id": "BiosAttributeRegistry.1.0.0",
                "name": "BiosAttributeRegistry",
                "version": "1.0.0",
            },
        )
        self.assertEqual(
            checks._bios_registry("BiosAttributeRegistryHYE134C-2.31")["version"], None
        )
        for unserved in (None, "", "  "):
            self.assertEqual(
                checks._bios_registry(unserved), {"id": None, "name": None, "version": None}
            )


class TestStorage(unittest.TestCase):
    def test_normalize(self):
        controllers = _fx("xcc_storage_expanded.json")["Members"]
        drives = {"RAID_Slot1": [_fx("xcc_storage_drive_0.json"), _fx("xcc_storage_drive_1.json")]}
        volumes = {"RAID_Slot1": _fx("xcc_storage_volumes_expanded.json")["Members"]}
        view, context = checks._normalize_storage(controllers, drives, volumes)
        self.assertEqual(view["controller|RAID_Slot1"]["firmware"], "2.3.10.1193")
        self.assertEqual(view["controller|RAID_Slot1"]["drive_count"], 2)
        self.assertEqual(view["drive|Disk.0"]["serial"], "M2SSD000000")
        self.assertEqual(view["drive|Disk.0"]["capacity_bytes"], 480103981056)
        self.assertEqual(view["drive|Disk.0"]["media_type"], "SSD")
        self.assertEqual(view["drive|Disk.0"]["encryption_ability"], "SelfEncryptingDrive")
        self.assertEqual(view["drive|Disk.0"]["location"], "M.2 Bay 0")
        self.assertIs(view["drive|Disk.1"]["failure_predicted"], True)
        self.assertEqual(view["drive|Disk.1"]["health"], "Warning")
        self.assertNotIn("life_left_pct", view["drive|Disk.1"])
        self.assertEqual(context["life_left_pct"]["drive|Disk.1"], 71)
        self.assertEqual(view["volume|0"]["raid_type"], "RAID1")
        self.assertIs(view["volume|0"]["encrypted"], False)
        self.assertEqual(view["volume|0"]["drives"], ["Disk.0", "Disk.1"])
        # DMTF leaves served by this hand-built set; the Lenovo ones are not: present, None
        controller = view["controller|RAID_Slot1"]
        self.assertEqual(controller["supported_raid_levels"], ["RAID1"])
        self.assertIsNone(controller["cache_size_mib"])
        self.assertIsNone(controller["battery_operational_status"])
        self.assertIsNone(controller["mode"])
        self.assertEqual(context["controller_source"], {"RAID_Slot1": "StorageControllers"})
        self.assertEqual(context["raid_levels_source"], {"RAID_Slot1": "SupportedRAIDTypes"})
        self.assertEqual(context["battery"], {})
        drive = view["drive|Disk.0"]
        self.assertEqual((drive["block_size_bytes"], drive["negotiated_speed_gbs"]), (512, 6.0))
        self.assertEqual(drive["hotspare_type"], "None")  # the served word, verbatim
        self.assertIsNone(drive["write_cache_enabled"])
        self.assertIsNone(drive["drive_status"])
        self.assertIsNone(context["drive_temperature_c"]["drive|Disk.0"])
        volume = view["volume|0"]
        for field in ("read_cache_policy", "strip_size_bytes", "raid_level", "io_policy"):
            self.assertIsNone(volume[field], field)

    def test_duplicate_drive_ids_across_controllers_are_prefixed(self):
        controllers = [{"Id": "A"}, {"Id": "B"}]
        drive = _fx("xcc_storage_drive_0.json")
        view, _context = checks._normalize_storage(controllers, {"A": [drive], "B": [drive]}, {})
        self.assertIn("drive|A|Disk.0", view)
        self.assertIn("drive|B|Disk.0", view)

    def test_collector_expand_then_drives_then_volumes(self):
        ctx = _FakeCtx(_base_payloads())
        result = checks._collect_storage(ctx)
        self.assertEqual(
            ctx.gets,
            RESOLVE
            + [
                SYS + "/Storage" + EXPAND,
                SYS + "/Storage/RAID_Slot1/Drives/Disk.0",
                SYS + "/Storage/RAID_Slot1/Drives/Disk.1",
                SYS + "/Storage/RAID_Slot1/Volumes" + EXPAND,
                CH,  # its Drives links (none here); the read bmc_chassis shares
            ],
        )
        self.assertEqual(result["context"]["strategy"], "expand")
        self.assertEqual(result["context"]["drives_total"], 2)
        self.assertEqual(result["context"]["volumes_total"], 1)
        self.assertEqual(result["context"]["controllers_collection"], {})
        self.assertEqual(
            result["context"]["chassis_drives"],
            {"source": None, "strategy": None, "members": 0, "unlisted": 0},
        )
        self.assertNotIn("Actions", result["raw"][SYS + "/Storage/RAID_Slot1/Drives/Disk.0"])
        self.assertNotIn(CH, result["raw"])  # bmc_chassis keeps the Chassis

    def test_collector_walk(self):
        ctx = _FakeCtx(_without_expand(_base_payloads()))
        result = checks._collect_storage(ctx)
        self.assertEqual(result["context"]["strategy"], "members")
        self.assertIn(SYS + "/Storage/RAID_Slot1", ctx.gets)
        self.assertIn(SYS + "/Storage/RAID_Slot1/Volumes/0", ctx.gets)
        self.assertEqual(result["normalized"]["volume|0"]["raid_type"], "RAID1")

    def test_collector_not_present_shapes(self):
        payloads = _base_payloads()
        for path in list(payloads):
            if path.startswith(SYS + "/Storage"):
                del payloads[path]
        with self.assertRaises(checks.SkipCheck):
            checks._collect_storage(_FakeCtx(payloads))
        payloads = _base_payloads()
        payloads[SYS + "/Storage" + EXPAND]["Members"] = []
        with self.assertRaises(checks.SkipCheck):
            checks._collect_storage(_FakeCtx(payloads))

    def test_collector_refuses_a_drive_link_into_actions(self):
        payloads = _base_payloads()
        payloads[SYS + "/Storage" + EXPAND]["Members"][0]["Drives"].append(
            {"@odata.id": SYS + "/Storage/RAID_Slot1/Actions/Drive.SecureErase"}
        )
        ctx = _FakeCtx(payloads)
        with self.assertRaises(checks.CollectError):
            checks._collect_storage(ctx)
        self.assertFalse([path for path in ctx.gets if "Actions" in path])


class TestStorageWidened(unittest.TestCase):
    """Controller cache/battery/RAID modes, drive and volume policies, the Controllers
    collection, the Chassis's own drive list and the capped SMART text."""

    RAID = SYS + "/Storage/RAID_Slot3"

    def _payloads(self):
        """A Lenovo RAID adapter (hand-built from Lenovo's schema) in place of the M.2 kit."""
        payloads = _base_payloads()
        payloads[SYS + "/Storage" + EXPAND] = _fx("xcc_storage_raid_lenovo_expanded.json")
        plain, members = _split_collection(payloads[SYS + "/Storage" + EXPAND])
        payloads[SYS + "/Storage"] = plain
        payloads.update(members)
        for index in (0, 1):
            payloads[self.RAID + "/Drives/Disk.%d" % index] = _fx(
                "xcc_storage_raid_lenovo_drive_%d.json" % index
            )
        volumes = _fx("xcc_storage_raid_lenovo_volumes_expanded.json")
        payloads[self.RAID + "/Volumes" + EXPAND] = volumes
        plain, members = _split_collection(volumes)
        payloads[self.RAID + "/Volumes"] = plain
        payloads.update(members)
        return payloads

    def test_lenovo_controller_drive_and_volume_leaves(self):
        result = checks._collect_storage(_FakeCtx(self._payloads()))
        view, context = result["normalized"], result["context"]
        controller = view["controller|RAID_Slot3"]
        self.assertEqual(controller["cache_size_mib"], 2048)
        self.assertEqual(controller["battery_operational_status"], "Optimal")
        # Lenovo's one-string SupportedRaidLevels: its comma-separated parts, sorted
        self.assertEqual(
            controller["supported_raid_levels"], ["RAID 0", "RAID 1", "RAID 10", "RAID 5"]
        )
        self.assertEqual(controller["mode"], "RAID")
        self.assertEqual(
            context["raid_levels_source"], {"RAID_Slot3": "Oem.Lenovo.SupportedRaidLevels"}
        )
        self.assertEqual(
            context["battery"]["controller|RAID_Slot3"],
            {
                "design_capacity": "3500 J",
                "full_charge_capacity": "3300 J",
                "remaining_capacity": "3100 J",
                "design_voltage_mv": 9500,
                "voltage_mv": 9420,
                "current_ma": 0,
                "temperature_c": 31,
            },
        )
        drive = view["drive|Disk.0"]
        self.assertEqual(
            {
                field: drive[field]
                for field in (
                    "negotiated_speed_gbs",
                    "rotation_rpm",
                    "block_size_bytes",
                    "hotspare_type",
                    "write_cache_enabled",
                    "drive_status",
                )
            },
            {
                "negotiated_speed_gbs": 6.0,
                "rotation_rpm": 0,
                "block_size_bytes": 512,
                "hotspare_type": "None",
                "write_cache_enabled": False,
                "drive_status": "Online",
            },
        )
        self.assertEqual(context["drive_temperature_c"], {"drive|Disk.0": 34, "drive|Disk.1": 35})
        volume = view["volume|1"]
        self.assertEqual(
            {field: volume[field] for field in sorted(volume) if field not in ("name", "drives")},
            {
                "access_policy": "ReadWrite",
                "bootable": True,
                "capacity_bytes": 959656755200,
                "drive_cache_policy": "Disable",
                "encrypted": False,
                "health": "OK",
                "io_policy": "DirectIO",
                "is_boot_capable": True,
                "raid_level": "RAID 1",
                "raid_type": "RAID1",
                "read_cache_policy": "ReadAhead",
                "state": "Enabled",
                "strip_size_bytes": 262144,
                "write_cache_policy": "ProtectedWriteBack",
            },
        )

    def test_smart_data_is_raw_only_and_capped(self):
        result = checks._collect_storage(_FakeCtx(self._payloads()))
        self.assertNotIn("smart", json.dumps(result["normalized"]).lower())
        self.assertNotIn("smart", json.dumps(result["context"]).lower())
        lenovo = result["raw"][self.RAID + "/Drives/Disk.0"]["Oem"]["Lenovo"]
        self.assertTrue(lenovo["SMARTData"].endswith("...[truncated 1024 chars]"))
        self.assertEqual(len(lenovo["SMARTData"]), checks._STORAGE_SMART_CAP + 25)
        short = result["raw"][self.RAID + "/Drives/Disk.1"]["Oem"]["Lenovo"]["SMARTData"]
        self.assertEqual(short, "AAEC")  # under the cap: kept whole
        self.assertNotIn("Actions", result["raw"][self.RAID + "/Drives/Disk.0"])

    def test_the_controllers_collection_is_preferred_and_named(self):
        payloads = self._payloads()
        storage = payloads[SYS + "/Storage" + EXPAND]["Members"][0]
        storage["Controllers"] = {"@odata.id": self.RAID + "/Controllers"}
        modern = dict(
            storage["StorageControllers"][0],
            **{"@odata.id": self.RAID + "/Controllers/0", "Id": "0", "FirmwareVersion": "52.1"},
        )
        payloads[self.RAID + "/Controllers" + EXPAND] = {"Members": [modern]}
        ctx = _FakeCtx(payloads)
        result = checks._collect_storage(ctx)
        self.assertEqual(result["normalized"]["controller|RAID_Slot3"]["firmware"], "52.1")
        self.assertEqual(result["context"]["controller_source"], {"RAID_Slot3": "Controllers"})
        self.assertEqual(
            result["context"]["controllers_collection"],
            {"RAID_Slot3": {"strategy": "expand", "members": 1}},
        )
        self.assertIn(self.RAID + "/Controllers" + EXPAND, ctx.gets)
        # an empty Controllers collection leaves the deprecated array in charge
        payloads[self.RAID + "/Controllers" + EXPAND] = {"Members": []}
        result = checks._collect_storage(_FakeCtx(payloads))
        self.assertEqual(result["normalized"]["controller|RAID_Slot3"]["firmware"], "50.9.1-3639")
        self.assertEqual(
            result["context"]["controller_source"], {"RAID_Slot3": "StorageControllers"}
        )

    def test_the_expand_refusal_is_remembered_for_every_sub_collection(self):
        payloads = self._payloads()
        storage = payloads[SYS + "/Storage" + EXPAND]["Members"][0]
        storage["Controllers"] = {"@odata.id": self.RAID + "/Controllers"}
        payloads[self.RAID + "/Controllers"] = {"Members": []}
        payloads[CH]["Drives"] = {"@odata.id": CH + "/Drives"}
        payloads[CH + "/Drives"] = {"Members": []}
        # The Storage collection refuses: nothing below it tries $expand.
        ctx = _FakeCtx(payloads, errors={SYS + "/Storage" + EXPAND: 501})
        checks._collect_storage(ctx)
        self.assertEqual([path for path in ctx.gets if "?" in path], [SYS + "/Storage" + EXPAND])
        # The Controllers collection refuses after it: the Volumes and the Chassis drives
        # are read plain.
        ctx = _FakeCtx(payloads, errors={self.RAID + "/Controllers" + EXPAND: 501})
        result = checks._collect_storage(ctx)
        self.assertEqual(
            [path for path in ctx.gets if "?" in path],
            [SYS + "/Storage" + EXPAND, self.RAID + "/Controllers" + EXPAND],
        )
        self.assertIn(self.RAID + "/Volumes", ctx.gets)
        self.assertEqual(result["context"]["chassis_drives"]["strategy"], "members")

    def test_drives_only_the_chassis_lists_are_keyed_and_listed_ones_never_twice(self):
        payloads = self._payloads()
        payloads[CH]["Drives"] = {"@odata.id": CH + "/Drives"}
        listed = copy.deepcopy(payloads[self.RAID + "/Drives/Disk.0"])
        same_serial = dict(listed, **{"@odata.id": CH + "/Drives/Bay0", "Id": "Bay0"})
        nvme = {
            "@odata.id": CH + "/Drives/Disk.1",  # an id that clashes with a listed drive's
            "Id": "Disk.1",
            "SerialNumber": "NVME0000001",
            "MediaType": "SSD",
            "Protocol": "NVMe",
            "Status": {"State": "Enabled", "Health": "OK"},
        }
        payloads[CH + "/Drives" + EXPAND] = {"Members": [listed, same_serial, nvme]}
        result = checks._collect_storage(_FakeCtx(payloads))
        drives = sorted(key for key in result["normalized"] if key.startswith("drive|"))
        # the clashing id is prefixed on both sides; the listed drive and its serial twin
        # are one drive, keyed once
        self.assertEqual(
            drives, ["drive|Disk.0", "drive|RAID_Slot3|Disk.1", "drive|chassis|Disk.1"]
        )
        self.assertEqual(result["normalized"]["drive|chassis|Disk.1"]["protocol"], "NVMe")
        self.assertEqual(
            result["context"]["chassis_drives"],
            {"source": "Drives", "strategy": "expand", "members": 3, "unlisted": 1},
        )
        self.assertEqual(result["context"]["drives_total"], 3)

    def test_the_chassis_links_array_reads_only_unlisted_drives(self):
        payloads = self._payloads()
        extra = CH + "/Drives/NVMe.0"
        payloads[CH]["Links"]["Drives"] = [
            {"@odata.id": self.RAID + "/Drives/Disk.0"},
            {"@odata.id": extra},
        ]
        payloads[extra] = {"@odata.id": extra, "Id": "NVMe.0", "Protocol": "NVMe"}
        ctx = _FakeCtx(payloads)
        result = checks._collect_storage(ctx)
        self.assertEqual(ctx.gets.count(self.RAID + "/Drives/Disk.0"), 1)  # never re-read
        self.assertEqual(ctx.gets[-1], extra)
        self.assertIn("drive|NVMe.0", result["normalized"])
        self.assertEqual(
            result["context"]["chassis_drives"],
            {"source": "Links.Drives", "strategy": "members", "members": 2, "unlisted": 1},
        )


class TestManagerNetwork(unittest.TestCase):
    def test_normalize(self):
        view = checks._normalize_manager_network(
            _fx("xcc_network_protocol.json"), _fx("xcc_manager_nic.json")
        )
        self.assertEqual(view["hostname"], "se350-a-xcc")
        self.assertEqual(view["fqdn"], "se350-a-xcc.example.net")
        self.assertIs(view["ntp_enabled"], True)
        self.assertEqual(view["ntp_servers"], ["203.0.113.123", "203.0.113.124"])
        self.assertIs(view["https_enabled"], True)
        self.assertEqual(view["https_port"], 443)
        self.assertIs(view["ipmi_enabled"], False)
        self.assertEqual(view["ipmi_port"], 623)
        self.assertIs(view["snmp_enabled"], True)
        self.assertIs(view["virtualmedia_enabled"], True)
        self.assertEqual(view["ipv4_address"], "192.0.2.21")
        self.assertEqual(view["ipv4_origin"], "Static")
        self.assertIs(view["dhcpv4_enabled"], False)
        self.assertEqual(view["dns_servers"], ["198.51.100.53", "198.51.100.54"])
        self.assertEqual(view["ipv6_address_count"], 1)
        self.assertEqual(view["mtu"], 1500)
        self.assertIsNone(view["vlan_id"])
        self.assertNotIn("speed_mbps", view)
        self.assertIsNone(view["ipv6_gateway"])  # '::' is the unset placeholder, no gateway
        # every widened key is present, None where its resource was not given
        for key in (
            "nic_mode",
            "failover_mode",
            "ipv4_assigned_by",
            "domain_name",
            "hostname_from_dhcp",
            "dns_enabled",
            "dns_preferred_family",
            "dns_configured_servers",
            "ddns",
            "lxca_discovery_enabled",
            "time_setting_method",
            "time_ntp_servers",
            "utc_offset",
            "auto_dst",
            "ntp_sync_interval_min",
            "host_interface_enabled",
            "host_interface_externally_accessible",
            "credential_bootstrapping_enabled",
            "credential_bootstrapping_role",
            "credential_bootstrapping_enable_after_reset",
            "cimoverhttps_enabled",
            "cimoverhttps_port",
            "slp_enabled",
            "slp_port",
            "sftp_enabled",
            "sftp_port",
            "webhttps_enabled",
            "open_ports",
            "snmpv3_agent_enabled",
            "snmp_traps_enabled",
            "kcs_enabled",
        ):
            self.assertIn(key, view)
            self.assertIsNone(view[key], key)

    def test_normalize_without_nic(self):
        view = checks._normalize_manager_network(_fx("xcc_network_protocol.json"), None)
        self.assertIsNone(view["ipv4_address"])
        self.assertEqual(view["dns_servers"], [])
        self.assertEqual(view["hostname"], "se350-a-xcc")

    def test_collector(self):
        ctx = _FakeCtx(_base_payloads())
        result = checks._collect_manager_network(ctx)
        # the Manager (shared with bmc_system) carries the time and the Lenovo links; the
        # hand-built one links no DateTimeService or HostInterfaces, and the hand-built
        # protocol serves its DNS block inline, so nothing more is fetched
        self.assertEqual(
            ctx.gets, RESOLVE + [MGR + "/NetworkProtocol", MGR, MGR + "/EthernetInterfaces/NIC"]
        )
        self.assertEqual(result["context"]["snmp_source"], "SNMP.ProtocolEnabled")
        view = result["normalized"]
        self.assertIs(view["dns_enabled"], True)
        self.assertEqual(view["dns_preferred_family"], "IPv4")  # spelled PreferredAddressType
        self.assertIsNone(view["dns_configured_servers"])  # no IPv4Address1-3 slot served
        self.assertEqual(
            result["context"]["dns_source"], MGR + "/NetworkProtocol Oem.Lenovo.DNS (inline)"
        )
        self.assertIsNone(result["context"]["host_interfaces"])
        self.assertIsNone(result["context"]["os_ipv4_address"])
        self.assertEqual(result["context"]["bmc_datetime"], "2026-09-24T14:02:11+00:00")
        self.assertEqual(result["context"]["bmc_datetime_offset"], "+00:00")
        self.assertIsNone(result["context"]["time_zone_name"])
        self.assertIn(MGR, result["raw"])
        self.assertNotIn("Actions", result["raw"][MGR])
        self.assertEqual(result["context"]["manager_nic"]["member"], "NIC")
        self.assertEqual(result["context"]["nic_speed_mbps"], 1000)
        self.assertEqual(result["context"]["nic_link_status"], "LinkUp")
        self.assertIn(MGR + "/EthernetInterfaces/NIC", result["raw"])
        self.assertNotIn("Actions", result["raw"][MGR + "/NetworkProtocol"])


class TestManagerNetworkWidened(unittest.TestCase):
    """bmc_manager_network's Lenovo port, DNS, time and service leaves and the host interface,
    in the populated shapes the lab unit lacks (configured DNS servers and DDNS, bootstrapping
    off, several host interfaces, a shared port)."""

    NP = MGR + "/NetworkProtocol"
    DNS = NP + "/Oem/Lenovo/DNS"
    SNMP = NP + "/Oem/Lenovo/SNMP"
    TIME = MGR + "/Oem/Lenovo/DateTimeService"
    HOSTS = MGR + "/HostInterfaces"
    NIC = MGR + "/EthernetInterfaces/NIC"
    TOHOST = MGR + "/EthernetInterfaces/ToHost"

    def _host_interface(self, member_id, enabled, bootstrapping):
        return {
            "@odata.id": self.HOSTS + "/" + member_id,
            "Id": member_id,
            "HostInterfaceType": "NetworkHostInterface",
            "InterfaceEnabled": enabled,
            "ExternallyAccessible": False,
            "CredentialBootstrapping": bootstrapping,
            "ManagerEthernetInterface": {"@odata.id": self.TOHOST},
        }

    def _payloads(self, expand=True):
        payloads = _base_payloads()
        payloads[self.NP]["Oem"]["Lenovo"] = {
            "DNS": {"@odata.id": self.DNS},
            "SNMP": {"@odata.id": self.SNMP},
            "CimOverHTTPS": {"ProtocolEnabled": True, "Port": 5989, "BackendEnabled": False},
            "SLP": {"ProtocolEnabled": False, "Port": 427, "AddressType": "Multicast"},
            "SFTP": {"ProtocolEnabled": True, "Port": 115},
            "WebOverHTTPS": {"ProtocolEnabled": True},
            "OpenPorts": ["443", "22", "5989", "22", "n/a"],
        }
        payloads[self.DNS] = {
            "@odata.id": self.DNS,
            "DNSEnable": True,
            "PreferredAddresstype": "IPv6",
            "IPv4Address1": "198.51.100.53",
            "IPv4Address2": "0.0.0.0",
            "IPv4Address3": "198.51.100.54",
            "IPv6Address1": "::",
            "IPv6Address2": "2001:db8::53",
            "IPv6Address3": "::",
            "DDNS": [
                {"DDNSEnable": True, "DomainNameSource": "Custom", "DomainName": "example.net"}
            ],
            "LXCADNSDiscovery": {"DiscoverLXCAEnabled": True, "XClarityManagerList": []},
        }
        payloads[self.SNMP] = {
            "@odata.id": self.SNMP,
            "CommunityNames": ["not-a-real-community"],
            "SNMPv3Agent": {"ProtocolEnabled": True, "Port": 161, "ContactPerson": "Jane Roe"},
            "SNMPTraps": {"ProtocolEnabled": True, "Port": 162},
        }
        manager = payloads[MGR]
        manager["Oem"]["Lenovo"].update(
            {"DateTimeService": {"@odata.id": self.TIME}, "KCSEnabled": True}
        )
        manager["HostInterfaces"] = {"@odata.id": self.HOSTS}
        manager["TimeZoneName"] = "America/Chicago"
        payloads[self.TIME] = {
            "@odata.id": self.TIME,
            "SettingMethod": "SyncwithNTP",
            "NTPServerAddresses": ["203.0.113.123", "", "203.0.113.124", ""],
            "UTCOffset": "+0:00",
            "AutoDST": False,
            "Frequency": 80,
            "HostTimeFormat": "UTC",
            "Actions": {"#LenovoDateTimeService.ImmediatelySync": {"target": self.TIME + "/x"}},
        }
        hosts = {
            "@odata.id": self.HOSTS,
            "Members": [
                self._host_interface("2", False, {"Enabled": True, "RoleId": "Administrator"}),
                self._host_interface(
                    "1", True, {"Enabled": False, "EnableAfterReset": False, "RoleId": "ReadOnly"}
                ),
            ],
        }
        if expand:
            payloads[self.HOSTS + EXPAND] = hosts
        plain, members = _split_collection(hosts)
        payloads[self.HOSTS] = plain
        payloads.update(members)
        payloads[self.TOHOST] = dict(
            payloads[self.TOHOST],
            Oem={"Lenovo": {"OSIPv4Address": "198.18.0.10", "AddressMode": "IPv6LLA"}},
        )
        nic = payloads[self.NIC]
        nic["Oem"] = {
            "Lenovo": {
                "InterfaceNicMode": "Shared",
                "InterfaceFailoverMode": "Failover",
                "IPv4AddressAssignedby": "Static",
                "DomainName": "example.net",
                "HostNameFromDHCPEnabled": False,
            }
        }
        nic["IPv6DefaultGateway"] = "2001:db8::1"
        return payloads

    def test_every_leaf_is_read_from_its_resource(self):
        ctx = _FakeCtx(self._payloads())
        result = checks._collect_manager_network(ctx)
        view, context = result["normalized"], result["context"]
        self.assertEqual(
            ctx.gets,
            RESOLVE
            + [self.NP, MGR, self.SNMP, self.DNS, self.TIME, self.HOSTS + EXPAND]
            + [self.NIC, self.TOHOST],
        )
        expected = {
            "nic_mode": "Shared",
            "failover_mode": "Failover",
            "ipv4_assigned_by": "Static",
            "domain_name": "example.net",
            "hostname_from_dhcp": False,
            "ipv6_gateway": "2001:db8::1",
            "dns_enabled": True,
            "dns_preferred_family": "IPv6",
            "dns_configured_servers": ["198.51.100.53", "198.51.100.54", "2001:db8::53"],
            "ddns": [
                {"enabled": True, "domain_name_source": "Custom", "domain_name": "example.net"}
            ],
            "lxca_discovery_enabled": True,
            "time_setting_method": "SyncwithNTP",
            "time_ntp_servers": ["203.0.113.123", "203.0.113.124"],
            "utc_offset": "+0:00",
            "auto_dst": False,
            "ntp_sync_interval_min": 80,
            # the lowest host interface id is described, whatever the served order
            "host_interface_enabled": True,
            "host_interface_externally_accessible": False,
            "credential_bootstrapping_enabled": False,
            "credential_bootstrapping_role": "ReadOnly",
            "credential_bootstrapping_enable_after_reset": False,
            # the BMC side of the host interface: its USB LAN (ToHost), as served
            "host_interface_address": "169.254.95.118",
            "host_interface_address_mode": "IPv6LLA",
            "cimoverhttps_enabled": True,
            "cimoverhttps_port": 5989,
            "slp_enabled": False,
            "slp_port": 427,
            "sftp_enabled": True,
            "sftp_port": 115,
            "webhttps_enabled": True,
            "open_ports": [22, 443, 5989],  # served as strings, duplicates and junk dropped
            "snmpv3_agent_enabled": True,
            "snmp_traps_enabled": True,
            "kcs_enabled": True,
        }
        self.assertEqual({key: view[key] for key in expected}, expected)
        # every key the check had before is kept, the DMTF SNMP block still first
        self.assertEqual(view["ipv4_address"], "192.0.2.21")
        self.assertIs(view["snmp_enabled"], True)
        self.assertEqual(context["snmp_source"], "SNMP.ProtocolEnabled")
        self.assertEqual(context["host_interfaces"]["members"], ["1", "2"])
        self.assertEqual(context["host_interfaces"]["used"], "1")
        self.assertEqual(context["host_interfaces"]["strategy"], "expand")
        self.assertEqual(
            (context["os_ipv4_address"], context["os_ipv4_address_member"]),
            ("198.18.0.10", "ToHost"),
        )
        self.assertEqual(context["host_interface_usb_lan_member"], "ToHost")
        self.assertEqual(context["time_zone_name"], "America/Chicago")
        self.assertEqual(context["dns_source"], self.DNS)
        for path in (self.NP, MGR, self.SNMP, self.DNS, self.TIME, self.HOSTS + EXPAND):
            self.assertIn(path, result["raw"])
        self.assertIn(self.TOHOST, result["raw"])
        self.assertNotIn("Actions", result["raw"][self.TIME])
        # the community and the SNMP contact never reach raw
        raw = json.dumps(result["raw"])
        self.assertNotIn("not-a-real-community", raw)
        self.assertNotIn("Jane", raw)

    def test_an_address_on_the_management_port_wins(self):
        payloads = self._payloads()
        payloads[self.NIC]["Oem"]["Lenovo"]["OSIPv4Address"] = "198.18.0.11"
        ctx = _FakeCtx(payloads)
        result = checks._collect_manager_network(ctx)
        context = result["context"]
        self.assertEqual(
            (context["os_ipv4_address"], context["os_ipv4_address_member"]), ("198.18.0.11", "NIC")
        )
        # the USB LAN is still read once, for the host interface's own address
        self.assertEqual(ctx.gets.count(self.TOHOST), 1)
        self.assertEqual(result["normalized"]["host_interface_address"], "169.254.95.118")

    def test_a_host_interface_naming_the_management_port_costs_no_get(self):
        payloads = self._payloads()
        for member in ("1", "2"):
            payloads[self.HOSTS + "/" + member]["ManagerEthernetInterface"] = {
                "@odata.id": self.NIC
            }
        payloads[self.HOSTS + EXPAND] = dict(
            payloads[self.HOSTS + EXPAND],
            Members=[payloads[self.HOSTS + "/2"], payloads[self.HOSTS + "/1"]],
        )
        ctx = _FakeCtx(payloads)
        result = checks._collect_manager_network(ctx)
        self.assertNotIn(self.TOHOST, ctx.gets)
        self.assertEqual(result["context"]["host_interface_usb_lan_member"], "NIC")
        self.assertEqual(result["normalized"]["host_interface_address"], "192.0.2.21")
        # an unset 0.0.0.0 USB LAN address is no address
        payloads = self._payloads()
        payloads[self.TOHOST]["IPv4Addresses"] = [{"Address": "0.0.0.0"}]
        result = checks._collect_manager_network(_FakeCtx(payloads))
        self.assertIsNone(result["normalized"]["host_interface_address"])

    def test_other_vendors_read_the_host_interface_and_no_lenovo_resource(self):
        payloads = self._payloads()
        payloads["/redfish/v1/"] = dict(payloads["/redfish/v1/"], Vendor="Contoso")
        for path in (self.NIC, self.TOHOST):
            payloads[path] = {key: value for key, value in payloads[path].items() if key != "Oem"}
        ctx = _FakeCtx(payloads)
        result = checks._collect_manager_network(ctx)
        self.assertFalse([path for path in ctx.gets if "/Oem/Lenovo" in path])
        self.assertIn(self.HOSTS + EXPAND, ctx.gets)  # the host interface is DMTF ...
        self.assertIn(self.TOHOST, ctx.gets)  # ... and so is the USB LAN it names
        view = result["normalized"]
        self.assertEqual(view["credential_bootstrapping_role"], "ReadOnly")
        self.assertEqual(view["host_interface_address"], "169.254.95.118")
        self.assertIsNone(view["host_interface_address_mode"])  # a Lenovo leaf
        for key in (
            "dns_enabled",
            "dns_configured_servers",
            "ddns",
            "time_setting_method",
            "time_ntp_servers",
            "ntp_sync_interval_min",
            "snmpv3_agent_enabled",
            "snmp_traps_enabled",
        ):
            self.assertIsNone(view[key], key)
        self.assertIsNone(result["context"]["os_ipv4_address"])
        self.assertIsNone(result["context"]["dns_source"])

    def test_host_interfaces_walked_or_absent(self):
        ctx = _FakeCtx(self._payloads(expand=False))
        result = checks._collect_manager_network(ctx)
        self.assertEqual(result["context"]["host_interfaces"]["strategy"], "members")
        self.assertEqual(result["normalized"]["credential_bootstrapping_role"], "ReadOnly")
        # a linked collection that answers 404 describes no interface, and says so
        payloads = self._payloads(expand=False)
        del payloads[self.HOSTS]
        result = checks._collect_manager_network(_FakeCtx(payloads))
        self.assertEqual(result["context"]["host_interfaces"]["strategy"], "absent")
        self.assertIsNone(result["normalized"]["host_interface_enabled"])
        self.assertIsNone(result["normalized"]["host_interface_address"])
        self.assertIsNone(result["context"]["os_ipv4_address"])

    def test_unserved_leaves_read_none_and_placeholders_are_no_addresses(self):
        protocol, nic = _fx("xcc_network_protocol.json"), _fx("xcc_manager_nic.json")
        # a DNS resource that serves only placeholder slots configures no server
        dns = {"DNSEnable": False, "IPv4Address1": "0.0.0.0", "IPv6Address1": "::", "DDNS": []}
        view = checks._normalize_manager_network(protocol, nic, dns=dns, datetime_service={})
        self.assertEqual(view["dns_configured_servers"], [])
        self.assertEqual(view["ddns"], [])
        self.assertIsNone(view["dns_preferred_family"])
        self.assertIsNone(view["time_ntp_servers"])  # the resource serves no server list
        self.assertIsNone(view["ntp_sync_interval_min"])
        self.assertIsNone(view["ipv6_gateway"])  # '::'
        protocol["Oem"]["Lenovo"]["OpenPorts"] = []
        self.assertEqual(checks._normalize_manager_network(protocol, nic)["open_ports"], [])

    def test_the_worst_walk_fits_the_budget(self):
        payloads = self._payloads(expand=False)
        del payloads[SYS]["Links"]  # the id resolution then costs its full five GETs
        payloads["/redfish/v1/Managers"] = {"Members": [{"@odata.id": MGR}]}
        payloads["/redfish/v1/Chassis"] = {"Members": [{"@odata.id": CH}]}
        # no NIC member: the port is found through the collection
        payloads[MGR + "/EthernetInterfaces/eth0"] = dict(payloads.pop(self.NIC), Id="eth0")
        payloads[MGR + "/EthernetInterfaces"]["Members"] = [
            {"@odata.id": self.TOHOST},
            {"@odata.id": MGR + "/EthernetInterfaces/eth0"},
        ]
        ctx = _FakeCtx(payloads)
        result = checks._collect_manager_network(ctx)
        self.assertEqual(result["context"]["manager_nic"]["member"], "eth0")
        self.assertEqual(result["normalized"]["nic_mode"], "Shared")
        self.assertEqual(result["context"]["os_ipv4_address"], "198.18.0.10")
        self.assertLessEqual(len(ctx.gets), checks._BUDGET_MANAGER_NETWORK)


class TestChassisLocation(unittest.TestCase):
    def test_normalize_generic_postal_and_placement(self):
        view = checks._normalize_chassis_location(_fx("xcc_chassis.json"))
        self.assertEqual(view["serial"], "J3001ABC")
        self.assertEqual(view["chassis_type"], "RackMount")
        self.assertEqual(view["location_info"], "Rack A / Row 1 / U3")
        self.assertEqual(view["postal_building"], "HQ")
        self.assertEqual(view["postal_room"], "Comms room 6B")
        self.assertEqual(view["postal_name"], "Example Site")
        self.assertEqual(view["placement_rack"], "A")
        self.assertEqual(view["placement_rack_offset"], 3)
        self.assertEqual(view["placement_row"], "1")
        self.assertEqual(view["intrusion_sensor"], "Normal")
        self.assertEqual(view["intrusion_sensor_rearm"], "Automatic")
        self.assertIsNone(view["asset_tag"])
        self.assertEqual(view["indicator_led"], "Off")
        self.assertIsNone(view["location_indicator_active"])
        self.assertIsNone(view["system_board_serial"])  # Lenovo leaves only when asked for

    def test_normalize_without_location_or_security(self):
        chassis = _fx("xcc_chassis.json")
        del chassis["Location"]
        del chassis["PhysicalSecurity"]
        view = checks._normalize_chassis_location(chassis)
        self.assertIsNone(view["location_info"])
        self.assertIsNone(view["intrusion_sensor"])
        self.assertFalse([key for key in view if key.startswith("postal_")])

    def test_empty_postal_and_placement_fields_read_none(self):
        chassis = _fx("xcc_chassis.json")
        chassis["Location"]["PostalAddress"].update(Room="", Building="  ")
        chassis["Location"]["Placement"]["Rack"] = ""
        view = checks._normalize_chassis_location(chassis)
        self.assertIsNone(view["postal_room"])
        self.assertIsNone(view["postal_building"])
        self.assertIsNone(view["placement_rack"])
        self.assertEqual(view["placement_rack_offset"], 3)  # numbers stay numbers

    def test_collector(self):
        ctx = _FakeCtx(_base_payloads())
        result = checks._collect_chassis_location(ctx)
        # the hand-built chassis links its LED collection where nothing answers: absent
        self.assertEqual(ctx.gets, RESOLVE + [CH, CH + "/LEDs" + EXPAND, CH + "/LEDs"])
        self.assertIs(result["context"]["location_present"], True)
        self.assertIs(result["context"]["physical_security_present"], True)
        self.assertEqual(result["context"]["leds"]["strategy"], "absent")
        self.assertEqual(result["normalized"]["indicator_led"], "Off")
        self.assertFalse([key for key in result["normalized"] if key.startswith("led|")])
        self.assertNotIn("Actions", result["raw"][CH])


class TestChassisLeds(unittest.TestCase):
    """Lenovo's chassis LED collection as 'led|' rows, and the Lenovo identity scalars."""

    LEDS = CH + "/Oem/Lenovo/LEDs"

    def _payloads(self, expand=True):
        payloads = _base_payloads()
        chassis = payloads[CH]
        chassis["Oem"]["Lenovo"].update(
            LEDs={"@odata.id": self.LEDS},
            SystemBoardSerialNumber="S1BD9X00001",
            ProductName="ThinkSystem SE350",
            FruPartNumber="01XX001",
            HasSwitchBoard=False,
        )
        chassis.update(HeightMm=44.45, EnvironmentalClass="A4", LocationIndicatorActive=False)
        expanded = _fx("xcc_chassis_leds_repeated_names.json")
        if expand:
            payloads[self.LEDS + EXPAND] = expanded
        else:
            plain, members = _split_collection(expanded)
            payloads[self.LEDS] = plain
            payloads.update(members)
        return payloads

    def test_keyed_by_name_with_the_id_only_when_a_name_repeats(self):
        rows = checks._normalize_chassis_leds(
            _fx("xcc_chassis_leds_repeated_names.json")["Members"]
        )
        self.assertEqual(
            sorted(rows),
            ["led|9", "led|Fan Fault|5", "led|Fan Fault|6", "led|Fault", "led|Identify"],
        )
        self.assertEqual(
            rows["led|Fault"], {"color": "Yellow", "state": "On", "location": "Front Panel"}
        )
        self.assertEqual(rows["led|Fan Fault|6"]["location"], "Fan 2")
        self.assertIsNone(rows["led|9"]["location"])  # '' reads None

    def test_collector_reads_the_linked_collection_in_one_expand_get(self):
        ctx = _FakeCtx(self._payloads())
        result = checks._collect_chassis_location(ctx)
        view, context = result["normalized"], result["context"]
        self.assertEqual(ctx.gets, RESOLVE + [CH, self.LEDS + EXPAND])
        self.assertEqual(len([key for key in view if key.startswith("led|")]), 5)
        self.assertEqual(view["system_board_serial"], "S1BD9X00001")
        self.assertEqual(view["product_name"], "ThinkSystem SE350")
        self.assertEqual(view["fru_part_number"], "01XX001")
        self.assertIs(view["has_switch_board"], False)
        self.assertIs(view["location_indicator_active"], False)
        self.assertEqual((context["height_mm"], context["environmental_class"]), (44.45, "A4"))
        self.assertIsNone(context["weight_kg"])
        self.assertEqual(
            (context["leds"]["resource"], context["leds"]["strategy"], context["leds"]["members"]),
            (self.LEDS, "expand", 5),
        )
        self.assertIn(self.LEDS + EXPAND, result["raw"])

    def test_collector_walks_the_members_when_expand_is_not_honoured(self):
        ctx = _FakeCtx(self._payloads(expand=False))
        result = checks._collect_chassis_location(ctx)
        self.assertEqual(result["context"]["leds"]["strategy"], "members")
        self.assertEqual(len([key for key in result["normalized"] if key.startswith("led|")]), 5)
        self.assertLessEqual(len(ctx.gets), checks._BUDGET_CHASSIS)

    def test_a_walk_the_budget_cannot_cover_is_refused_before_it_starts(self):
        payloads = self._payloads(expand=False)
        payloads[self.LEDS]["Members"] = [
            {"@odata.id": self.LEDS + "/%d" % (n,)} for n in range(checks._BUDGET_CHASSIS)
        ]
        ctx = _FakeCtx(payloads)
        with self.assertRaises(checks.CollectError):
            checks._collect_chassis_location(ctx)
        self.assertEqual(ctx.gets[-1], self.LEDS)  # no member was fetched

    def test_other_vendors_get_no_led_read_and_no_lenovo_scalars(self):
        payloads = self._payloads()
        payloads["/redfish/v1/"] = dict(payloads["/redfish/v1/"], Vendor="Contoso")
        ctx = _FakeCtx(payloads)
        result = checks._collect_chassis_location(ctx)
        self.assertEqual(ctx.gets, RESOLVE + [CH])
        self.assertIsNone(result["normalized"]["system_board_serial"])
        self.assertEqual(result["normalized"]["indicator_led"], "Off")  # DMTF: every vendor
        self.assertIn("no Contoso mapping", result["context"]["leds"]["note"])

    def test_a_led_link_into_actions_is_refused(self):
        payloads = self._payloads()
        payloads[CH]["Oem"]["Lenovo"]["LEDs"] = {"@odata.id": CH + "/Actions/Oem/LEDs"}
        with self.assertRaises(checks.CollectError):
            checks._collect_chassis_location(_FakeCtx(payloads))

    def test_a_lit_fault_led_is_one_changed_row(self):
        compare = registry.CHECKS["bmc_chassis"].compare
        self.assertEqual(compare["mode"], "equality_set")
        pre = checks._collect_chassis_location(_FakeCtx(self._payloads()))["normalized"]
        post = checks._collect_chassis_location(_FakeCtx(self._payloads()))["normalized"]
        self.assertEqual(_loader.diffcore.diff_check(pre, post, compare)["result"], "pass")
        post["led|Fan Fault|5"] = dict(post["led|Fan Fault|5"], state="On")
        diff = _loader.diffcore.diff_check(pre, post, compare)
        self.assertEqual(
            [(row["key"], row["field"], row["old"], row["new"]) for row in diff["changed"]],
            [("led|Fan Fault|5", "state", "Off", "On")],
        )


class TestWholeFamily(unittest.TestCase):
    def test_every_check_succeeds_on_the_fixture_set_within_its_budget(self):
        ctx = _FakeCtx(_base_payloads())
        for check in registry.checks_for("bmc"):
            result = _collect_on_base_set(check, ctx)
            if result is None:
                continue  # a check newer than the hand-built set: not-present on it
            self.assertEqual(set(result), {"raw", "normalized", "context"}, check.id)
            self.assertTrue(result["normalized"], check.id)
            for key in result["raw"]:
                self.assertTrue(key.startswith("/redfish/v1/"), (check.id, key))
        # Shared resources are fetched once for the whole family.
        self.assertEqual(ctx.gets.count(SYS), 1)
        self.assertEqual(ctx.gets.count(MGR), 1)
        self.assertEqual(ctx.gets.count("/redfish/v1/"), 1)
        self.assertEqual(ctx.gets.count(MGR + "/EthernetInterfaces/NIC"), 1)
        self.assertEqual(ctx.gets.count("/redfish/v1/Systems"), 1)
        # + bmc_sensors' two 404s (the base set serves no Sensors collection)
        # + bmc_network_adapters' 6 (its hand-built adapter tree)
        # + bmc_pcie_slots' 2 (a PCIeSlots probe the base set answers 404, the Lenovo table)
        # + bmc_accounts' 1 (the AccountService the base set answers 404: not-present)
        self.assertLessEqual(len(ctx.gets), 41)
        # No request ever carried a query other than the allowlisted $expand.
        for path in ctx.gets:
            self.assertIsNone(_loader.redfish_paths.path_refusal(path), path)
            if "?" in path:
                self.assertTrue(path.endswith(EXPAND), path)

    def test_every_check_succeeds_without_expand_support(self):
        ctx = _FakeCtx(_without_expand(_base_payloads()))
        for check in registry.checks_for("bmc"):
            result = _collect_on_base_set(check, ctx)
            if result is None:
                continue  # a check newer than the hand-built set: not-present on it
            self.assertTrue(result["normalized"], check.id)
        # PR B's widened family, every $expand refused: measured, kept tight on purpose
        # (+ bmc_sensors' two 404s: the base set serves no Sensors collection)
        # (+ bmc_network_adapters' 17: its hand-built adapter tree walked)
        # (+ bmc_pcie_slots' 6: the PCIeSlots probe, then the Lenovo table walked)
        # (+ bmc_accounts' 1: the AccountService probe)
        self.assertLessEqual(len(ctx.gets), 91)


class TestResolution(unittest.TestCase):
    """Member ids come from the collections and the System's links, never from '/1'."""

    DELL_SYS = "/redfish/v1/Systems/System.Embedded.1"

    def _dell(self):
        payloads = _base_payloads()
        payloads["/redfish/v1/"] = dict(payloads["/redfish/v1/"], Vendor="Dell")
        payloads["/redfish/v1/Systems"]["Members"] = [{"@odata.id": self.DELL_SYS}]
        system = copy.deepcopy(payloads[SYS])
        system["@odata.id"] = self.DELL_SYS
        system["Id"] = "System.Embedded.1"
        system["Links"] = {
            "ManagedBy": [{"@odata.id": "/redfish/v1/Managers/iDRAC.Embedded.1"}],
            "Chassis": [{"@odata.id": self.DELL_SYS.replace("Systems", "Chassis")}],
        }
        payloads[self.DELL_SYS] = system
        return payloads

    def test_lenovo_lab_shape_resolves_to_the_linked_members(self):
        targets = checks._targets(_FakeCtx(_base_payloads()))
        self.assertEqual(
            (targets["system"], targets["manager"], targets["chassis"]), (SYS, MGR, CH)
        )
        resolution = targets["resolution"]
        self.assertEqual(resolution["system_found_by"], "only member")
        self.assertEqual(resolution["manager_found_by"], "System Links.ManagedBy")
        self.assertEqual(resolution["chassis_found_by"], "System Links.Chassis")
        # the hand-built root predates ServiceRoot.Vendor: the System names the maker
        self.assertEqual(resolution["vendor"], "Lenovo")
        self.assertEqual(resolution["vendor_source"], "ComputerSystem.Manufacturer")

    def test_dell_shaped_ids_are_resolved_not_assumed(self):
        targets = checks._targets(_FakeCtx(self._dell()))
        self.assertEqual(targets["system"], self.DELL_SYS)
        self.assertEqual(targets["manager"], "/redfish/v1/Managers/iDRAC.Embedded.1")
        self.assertEqual(targets["chassis"], "/redfish/v1/Chassis/System.Embedded.1")
        self.assertEqual(targets["vendor"], "Dell")
        self.assertEqual(targets["resolution"]["vendor_source"], "ServiceRoot.Vendor")

    def test_unlinked_members_come_from_their_collections(self):
        payloads = _base_payloads()
        del payloads[SYS]["Links"]
        payloads["/redfish/v1/Managers"] = {"Members": [{"@odata.id": MGR}]}
        payloads["/redfish/v1/Chassis"] = {
            "Members": [{"@odata.id": "/redfish/v1/Chassis/Enclosure"}, {"@odata.id": CH}]
        }
        ctx = _FakeCtx(payloads)
        targets = checks._targets(ctx)
        self.assertEqual(targets["manager"], MGR)
        self.assertEqual(targets["resolution"]["manager_found_by"], "only member")
        self.assertEqual(targets["chassis"], CH)
        self.assertEqual(
            targets["resolution"]["chassis_found_by"], "id 1 preferred among 2 members"
        )
        self.assertEqual(ctx.gets, RESOLVE + ["/redfish/v1/Managers", "/redfish/v1/Chassis"])

    def test_several_systems_prefer_1_then_dell_then_first_sorted(self):
        choose = checks._choose_member
        make = lambda *ids: {"Members": [{"@odata.id": "/redfish/v1/Systems/" + i} for i in ids]}  # noqa: E731
        self.assertEqual(choose(make("2", "1"), "Systems")[0], "/redfish/v1/Systems/1")
        self.assertEqual(
            choose(make("A", "System.Embedded.1"), "Systems")[0],
            "/redfish/v1/Systems/System.Embedded.1",
        )
        path, how = choose(make("node-b", "node-a"), "Systems")
        self.assertEqual(path, "/redfish/v1/Systems/node-a")
        self.assertIn("first id of 2 members", how)
        with self.assertRaises(checks.CollectError):
            choose({"Members": []}, "Systems")

    def test_a_systems_link_into_actions_is_refused(self):
        payloads = _base_payloads()
        payloads["/redfish/v1/Systems"]["Members"] = [{"@odata.id": SYS + "/Actions/x"}]
        with self.assertRaises(checks.CollectError):
            checks._targets(_FakeCtx(payloads))

    def test_the_dmtf_checks_run_on_dell_shaped_paths(self):
        dell = {"system": "System.Embedded.1", "manager": "iDRAC.Embedded.1"}

        def dellify(text):
            text = text.replace(SYS, "/redfish/v1/Systems/" + dell["system"])
            text = text.replace(MGR, "/redfish/v1/Managers/" + dell["manager"])
            return text.replace(CH, "/redfish/v1/Chassis/" + dell["system"])

        # the paths AND every link inside the payloads, as a Dell serves them
        payloads = {
            dellify(path): json.loads(dellify(json.dumps(payload)))
            for path, payload in _base_payloads().items()
        }
        payloads["/redfish/v1/"] = dict(payloads["/redfish/v1/"], Vendor="Dell")
        payloads["/redfish/v1/Systems"] = {
            "Members": [{"@odata.id": "/redfish/v1/Systems/" + dell["system"]}]
        }
        system = copy.deepcopy(payloads["/redfish/v1/Systems/" + dell["system"]])
        system["Links"] = {
            "ManagedBy": [{"@odata.id": "/redfish/v1/Managers/" + dell["manager"]}],
            "Chassis": [{"@odata.id": "/redfish/v1/Chassis/" + dell["system"]}],
        }
        payloads["/redfish/v1/Systems/" + dell["system"]] = system
        ctx = _FakeCtx(payloads)
        for collector in (
            checks._collect_thermal,
            checks._collect_power,
            checks._collect_inventory,
            checks._collect_host_nics,
            checks._collect_firmware,
            checks._collect_storage,
            checks._collect_bios,
            checks._collect_chassis_location,
            checks._collect_manager_network,
            checks._collect_system,
        ):
            result = collector(ctx)
            self.assertTrue(result["normalized"], collector.__name__)
            self.assertEqual(
                result["context"]["resolution"]["system"],
                "/redfish/v1/Systems/System.Embedded.1",
                collector.__name__,
            )
        self.assertFalse(
            [path for path in ctx.gets if "/Systems/1" in path or "/Managers/1" in path]
        )
        # no Lenovo read was attempted on a Dell service; the manager port came from
        # its collection's listed members (the vendor-neutral walk)
        self.assertFalse([path for path in ctx.gets if "/Oem/Lenovo" in path])
        self.assertEqual(result["context"]["manager_nic"]["source"], "collection")

    def test_every_check_records_the_resolution(self):
        ctx = _FakeCtx(_base_payloads())
        for check in registry.checks_for("bmc"):
            result = _collect_on_base_set(check, ctx)
            if result is None:
                continue  # a check newer than the hand-built set: not-present on it
            self.assertEqual(result["context"]["resolution"]["system"], SYS, check.id)


class TestVendorBranch(unittest.TestCase):
    """OEM reads are Lenovo's; another vendor gets the DMTF checks and a named not-present."""

    def _other_vendor(self, vendor="Contoso"):
        payloads = _base_payloads()
        payloads["/redfish/v1/"] = dict(payloads["/redfish/v1/"], Vendor=vendor)
        return payloads

    def test_oem_only_security_is_not_present_naming_the_vendor(self):
        with self.assertRaises(registry.SkipCheck) as caught:
            checks._collect_security_state(_FakeCtx(self._other_vendor()))
        self.assertIn("no Contoso mapping", str(caught.exception))

    def test_dmtf_checks_are_unaffected(self):
        ctx = _FakeCtx(self._other_vendor())
        for collector in (
            checks._collect_thermal,
            checks._collect_power,
            checks._collect_inventory,
            checks._collect_firmware,
            checks._collect_storage,
            checks._collect_chassis_location,
            checks._collect_bios,
        ):
            self.assertTrue(collector(ctx)["normalized"], collector.__name__)

    def test_manager_nic_is_found_through_the_collection_on_other_vendors(self):
        payloads = self._other_vendor()
        payloads[MGR + "/EthernetInterfaces"]["Members"] = [
            {"@odata.id": MGR + "/EthernetInterfaces/ToHost"},
            {"@odata.id": MGR + "/EthernetInterfaces/NIC"},
        ]
        ctx = _FakeCtx(payloads)
        result = checks._collect_system(ctx)
        self.assertEqual(result["context"]["manager_nic"]["source"], "collection")
        self.assertEqual(result["normalized"]["bmc_ip"], "192.0.2.21")

    def test_several_log_services_without_a_mapping_is_not_present(self):
        payloads = self._other_vendor("Dell")
        payloads[SYS + "/LogServices"] = {
            "Members": [
                {"@odata.id": SYS + "/LogServices/Sel"},
                {"@odata.id": SYS + "/LogServices/Lclog"},
            ]
        }
        with self.assertRaises(registry.SkipCheck) as caught:
            checks._collect_event_log(_FakeCtx(payloads))
        self.assertIn("no Dell mapping for the platform log service", str(caught.exception))
        self.assertIn("Lclog, Sel", str(caught.exception))

    def test_a_single_log_service_is_read_whatever_the_vendor(self):
        payloads = self._other_vendor("Dell")
        payloads[SYS + "/LogServices"] = {
            "Members": [{"@odata.id": SYS + "/LogServices/PlatformLog"}]
        }
        result = checks._collect_event_log(_FakeCtx(payloads))
        self.assertEqual(result["context"]["log_service_used"], "PlatformLog")


class TestHygiene(unittest.TestCase):
    """Secrets by exact leaf name, people's names, logged-in users — before trace and raw."""

    def _seeded(self):
        return {
            "Password": "hunter2",
            "ClientPassword": "x",
            "BindPassword": "y",
            "Passphrase": "p",
            "Secret": "s",
            "PrivateKey": "k",
            "AuthenticationKey": "a",
            "EncryptionKey": "e",
            "CommunityNames": ["public", "private"],
            "TrapCommunity": "t",
            "LicenseString": "L-123",
            "CertificateString": "-----BEGIN CERTIFICATE-----x-----END CERTIFICATE-----",
            "SSHPublicKey": ["ssh-ed25519 AAAA", None],
            "Keys": {"@odata.id": "/redfish/v1/Managers/1/Oem/Lenovo/FoD/Keys"},
            "Bytes": [1, 2, 3],
            "SED_AK": "ak",
            "BMU_Credential": {"RemoteID": "r", "Secret": "s"},
            # policy leaves that must survive
            "ComplexPassword": True,
            "PasswordLength": 8,
            "MinPasswordLength": 8,
            "PasswordChangeOnFirstAccess": True,
            "PasswordExpirationPeriodDays": 90,
            "IsUefiAdminPasswordSet": False,
            "EncryptionKeySet": False,
            "PasswordSet": True,
            "AuthenticationKey@Redfish.OptionalOnCreate": True,
            # people
            "UserName": "someone",
            "Username": "",
            "UserID": "other",
            "CurrentLoggedUsers": [{"LoginID": "someone", "IP_Hostname": "192.0.2.9"}],
            "Nested": {"Authentication": {"UserName": "smtp-user", "Password": None}},
        }

    def test_dmtf_community_strings_urls_and_job_owners(self):
        payload = {
            "SNMP": {
                "CommunityStrings": [
                    {"Name": "ro", "AccessMode": "Limited", "CommunityString": "s3cret"}
                ]
            },
            "Image": "https://jane:pw@203.0.113.9/iso/installer.iso",
            "Destination": "https://203.0.113.10:8443/events",
            "CreatedBy": "jane",
            "Owner": "jane",
            "PostalAddress": {"Community": "Riverside"},
        }
        scrubbed = checks._scrub_payload(payload)
        community = scrubbed["SNMP"]["CommunityStrings"][0]
        self.assertEqual(community["CommunityString"], checks._SCRUBBED)
        self.assertEqual((community["Name"], community["AccessMode"]), ("ro", "Limited"))
        self.assertEqual(scrubbed["Image"], "https://***scrubbed***@203.0.113.9/iso/installer.iso")
        self.assertEqual(scrubbed["Destination"], payload["Destination"])
        self.assertEqual((scrubbed["CreatedBy"], scrubbed["Owner"]), (checks._SCRUBBED,) * 2)
        # a locality is not a secret
        self.assertEqual(scrubbed["PostalAddress"]["Community"], "Riverside")
        self.assertNotIn("jane", json.dumps(scrubbed))

    def test_people_are_scrubbed_even_where_account_names_are_kept(self):
        payload = {
            "Location": {
                "Contacts": [{"ContactName": "Jane Roe", "EmailAddress": "", "PhoneNumber": "1"}]
            },
            "SNMPv3Agent": {"ContactPerson": "Jane Roe", "Location": "rack 1"},
            "UserName": "netops",
        }
        for scrubbed in (checks._scrub_payload(payload), checks._scrub_accounts(payload)):
            contact = scrubbed["Location"]["Contacts"][0]
            self.assertEqual(contact["ContactName"], checks._SCRUBBED)
            self.assertEqual(contact["EmailAddress"], "")  # emptiness kept
            self.assertEqual(scrubbed["SNMPv3Agent"]["ContactPerson"], checks._SCRUBBED)
            self.assertEqual(scrubbed["SNMPv3Agent"]["Location"], "rack 1")
        self.assertEqual(checks._scrub_accounts(payload)["UserName"], "netops")
        self.assertTrue(checks._is_secret("OAuthServiceSigningKeys", ["k"]))

    def test_exact_name_rule(self):
        for key, value in (
            ("Password", "x"),
            ("ClientPassword", None),
            ("BindPassword", "x"),
            ("communitynames", []),
            ("SSHPublicKey", []),
            ("Bytes", [1]),
        ):
            self.assertTrue(checks._is_secret(key, value), key)
        for key, value in (
            ("ComplexPassword", True),
            ("PasswordLength", 8),
            ("PasswordChangeOnFirstAccess", False),
            ("IsUefiAdminPasswordSet", True),
            ("EncryptionKeySet", False),
            ("PasswordExpiration", "2027-01-01"),
            ("KeyUsage", ["DigitalSignature"]),
            ("Keys", {"@odata.id": "/x"}),
            ("CredentialBootstrapping", {"Enabled": True}),
            ("EnterCLIKeySequence", "ESC ("),
            ("AuthenticationKey@Redfish.OptionalOnCreate", True),
        ):
            self.assertFalse(checks._is_secret(key, value), key)

    def test_scrub_payload_and_raw(self):
        scrubbed = checks._scrub_payload(self._seeded())
        marker = checks._SCRUBBED
        for key in (
            "Password",
            "ClientPassword",
            "BindPassword",
            "Passphrase",
            "Secret",
            "PrivateKey",
            "AuthenticationKey",
            "EncryptionKey",
            "TrapCommunity",
            "LicenseString",
            "CertificateString",
            "SED_AK",
            "BMU_Credential",
            "UserName",
            "UserID",
        ):
            self.assertEqual(scrubbed[key], marker, key)
        # element counts and emptiness survive, content never
        self.assertEqual(scrubbed["CommunityNames"], [marker, marker])
        self.assertEqual(scrubbed["SSHPublicKey"], [marker, None])
        self.assertEqual(scrubbed["Bytes"], [marker, marker, marker])
        self.assertEqual(scrubbed["Username"], "")
        self.assertEqual(scrubbed["CurrentLoggedUsers"], [marker])
        self.assertEqual(
            scrubbed["Nested"]["Authentication"], {"UserName": marker, "Password": None}
        )
        for key in (
            "ComplexPassword",
            "PasswordLength",
            "MinPasswordLength",
            "PasswordChangeOnFirstAccess",
            "PasswordExpirationPeriodDays",
            "IsUefiAdminPasswordSet",
            "EncryptionKeySet",
            "PasswordSet",
            "AuthenticationKey@Redfish.OptionalOnCreate",
            "Keys",
        ):
            self.assertEqual(scrubbed[key], self._seeded()[key], key)
        # idempotent, and the accounts variant keeps account names only
        self.assertEqual(checks._scrub_payload(scrubbed), scrubbed)
        kept = checks._scrub_accounts(self._seeded())
        self.assertEqual(kept["UserName"], "someone")
        self.assertEqual(kept["Password"], marker)
        # raw curation keeps scrubbing on top of it
        raw = json.dumps(checks._curate(self._seeded()))
        for secret in ("hunter2", "public", "private", "L-123", "ssh-ed25519", "BEGIN CERT"):
            self.assertNotIn(secret, raw)

    def test_every_read_passes_the_scrubber(self):
        ctx = _FakeCtx(_base_payloads())
        for check in registry.checks_for("bmc"):
            _collect_on_base_set(check, ctx)
        self.assertTrue(ctx.redacted)
        for path, redactor in ctx.redacted:
            self.assertIn(
                redactor,
                ("_scrub_payload", "_redact_log_page", "_redact_task_page", "_alerting_redact"),
                path,
            )


class TestStorageWalkBudget(unittest.TestCase):
    """The lab layout (one AHCI controller per M.2 slot) walked without $expand."""

    def test_four_controllers_without_expand_and_unlinked_members_fit_the_budget(self):
        payloads = _without_expand(_base_payloads())
        del payloads[SYS]["Links"]  # the id resolution then costs its full five GETs
        payloads["/redfish/v1/Managers"] = {"Members": [{"@odata.id": MGR}]}
        payloads["/redfish/v1/Chassis"] = {"Members": [{"@odata.id": CH}]}
        members = []
        for slot in (2, 3, 4, 5):
            base = SYS + "/Storage/M.2_Slot_%d" % slot
            drive = base + "/Drives/Slot_%d" % slot
            members.append({"@odata.id": base})
            payloads[base] = {
                "@odata.id": base,
                "Id": "M.2_Slot_%d" % slot,
                "StorageControllers": [{"MemberId": "0", "Name": "AHCI"}],
                "Drives": [{"@odata.id": drive}],
                "Volumes": {"@odata.id": base + "/Volumes"},
                "Status": {"Health": "OK", "State": "Enabled"},
            }
            payloads[drive] = {"@odata.id": drive, "Id": "Slot_%d" % slot, "MediaType": "SSD"}
            payloads[base + "/Volumes"] = {"Members": []}
        payloads[SYS + "/Storage"] = {"Members": members}
        ctx = _FakeCtx(payloads)
        result = checks._collect_storage(ctx)
        self.assertEqual(len([k for k in result["normalized"] if k.startswith("drive|")]), 4)
        # $expand was tried once (the Storage collection) and never again for the Volumes
        self.assertEqual(
            [path for path in ctx.gets if path.endswith(EXPAND)], [SYS + "/Storage" + EXPAND]
        )
        # resolution 5, the attempt, the collection, 4 members, 4 drives, 4 Volumes, the Chassis
        self.assertEqual(len(ctx.gets), 5 + 1 + 1 + 4 + 4 + 4 + 1)
        self.assertLessEqual(len(ctx.gets), checks._BUDGET_STORAGE)


class TestIscsiBootHygiene(unittest.TestCase):
    def test_chap_credentials_are_scrubbed_by_the_family_scrubber(self):
        boot = {
            "iSCSIBoot": {
                "AuthenticationMethod": "MutualCHAP",
                "CHAPUsername": "initiator-login",
                "CHAPSecret": "not-a-real-secret",
                "MutualCHAPUsername": "",
                "MutualCHAPSecret": "not-a-real-secret-either",
                "TargetInfoViaDHCP": False,
            }
        }
        scrubbed = checks._scrub_payload(boot)["iSCSIBoot"]
        self.assertEqual(scrubbed["CHAPSecret"], checks._SCRUBBED)
        self.assertEqual(scrubbed["MutualCHAPSecret"], checks._SCRUBBED)
        self.assertEqual(scrubbed["CHAPUsername"], checks._SCRUBBED)
        self.assertEqual(scrubbed["MutualCHAPUsername"], "")  # emptiness kept
        self.assertEqual(scrubbed["AuthenticationMethod"], "MutualCHAP")
        self.assertIs(scrubbed["TargetInfoViaDHCP"], False)


class TestLogRedaction(unittest.TestCase):
    """Lenovo audit rows in the platform log name people; the lab shapes, invented names."""

    ROWS = (
        (
            "Remote Login Successful. Login ID: alice using WEB from webguis at IP address "
            "192.0.2.50.",
            ["alice", "WEB", "webguis", "192.0.2.50"],
        ),
        ("Login ID: alice from webguis at IP address 192.0.2.50 has logged off.", ["alice"]),
        ("The Boot_Order setting has been changed to x by user bob.", ["Boot_Order", "x", "bob"]),
        ("Flash of UEFI from web succeeded for user bob .", ["UEFI", "web", "bob"]),
        ("User carol has mounted file pve_proxmox.iso from RDOC1.", ["carol", "mounted"]),
        (
            "User dave password modified by user erin from web at IP address 192.0.2.51.",
            ["dave", "erin"],
        ),
        ("User dave created by user erin from web at IP address 192.0.2.51.", ["dave", "erin"]),
        ("Date and Time set by user frank: Date=09/30/2026, Time-01:02:03.", ["frank"]),
        ("Management Controller 1 reset was initiated by user USERID.", ["1", "USERID"]),
    )

    def _page(self):
        members = []
        for index, (message, args) in enumerate(self.ROWS, 1):
            members.append(
                {
                    "Id": str(index),
                    "Message": message,
                    "MessageArgs": list(args),
                    "Severity": "OK",
                    "Oem": {"Lenovo": {"CommonEventID": "FQXSPSE4001I", "AuxiliaryData": args[0]}},
                }
            )
        return {"Members": members, "Members@odata.count": len(members)}

    def test_names_found_in_every_lab_phrasing(self):
        found = set()
        for message, _args in self.ROWS:
            found |= checks._log_names(message)
        self.assertEqual(found, {"alice", "bob", "carol", "dave", "erin", "frank", "USERID"})

    def test_page_is_scrubbed_everywhere_and_addresses_stay(self):
        page = checks._redact_log_page(self._page())
        text = json.dumps(page)
        for name in ("alice", "bob", "carol", "dave", "erin", "frank", "USERID"):
            self.assertNotIn(name, text, name)
        self.assertIn("192.0.2.50", text)
        self.assertIn("Login ID: ***scrubbed*** using WEB", page["Members"][0]["Message"])
        self.assertEqual(page["Members"][0]["MessageArgs"][0], checks._SCRUBBED)
        self.assertIn("pve_proxmox.iso", page["Members"][4]["Message"])
        self.assertEqual(checks._redact_log_page(page), page)  # idempotent

    def test_the_free_text_contact_of_a_settings_message_is_scrubbed(self):
        entry = {
            "Message": "Server General Settings set by user dave: Name=SN#   X1, "
            "Contact=Jane Roe, Location=, Room=, RackID=, Rack U-position=1, Address=.",
            "MessageArgs": ["dave", "SN#   X1", "Jane Roe", "", "", "", "1", ""],
        }
        redacted = checks._redact_log_entry(entry)
        self.assertNotIn("Jane", json.dumps(redacted))
        self.assertNotIn("dave", json.dumps(redacted))
        self.assertIn("Contact=***scrubbed***, Location=,", redacted["Message"])
        self.assertIn("Name=SN#   X1", redacted["Message"])
        # free text with a comma is taken whole from the message argument
        comma = dict(
            entry,
            Message=entry["Message"].replace("Contact=Jane Roe", "Contact=Roe, Jane"),
            MessageArgs=["dave", "SN#   X1", "Roe, Jane", "", "", "", "1", ""],
        )
        redacted = checks._redact_log_entry(comma)
        self.assertNotIn("Jane", json.dumps(redacted))
        self.assertIn("Contact=***scrubbed***, Location=,", redacted["Message"])
        # an empty Contact= stays empty
        empty = checks._redact_log_entry(dict(entry, Message="x: Contact=, Location=."))
        self.assertIn("Contact=, Location=", empty["Message"])

    def test_collector_raw_rows_carry_no_names(self):
        payloads = _base_payloads()
        payloads[SYS + "/LogServices/PlatformLog/Entries"] = self._page()
        ctx = _FakeCtx(payloads)
        result = checks._collect_event_log(ctx)
        raw = json.dumps(result["raw"])
        for name in ("alice", "bob", "carol", "dave", "erin", "frank", "USERID"):
            self.assertNotIn(name, raw)
        self.assertEqual(result["context"]["entries_total"], len(self.ROWS))


class TestLabNotes(unittest.TestCase):
    """The normalizer fixes the live run on XCC 6.10 surfaced (handoff §4d / §5a)."""

    def test_platform_sequence_numbers_are_read_in_the_6_10_spelling(self):
        service = {
            "Oem": {
                "Lenovo": {
                    "PlatformFirstSeqNum": 1,
                    "PlatformLastSeqNum": 140,
                    "AuditFirstSeqNum": 1,
                    "AuditLastSeqNum": 176,
                }
            }
        }
        _view, context = checks._normalize_event_log([], service)
        self.assertEqual((context["first_seq_num"], context["last_seq_num"]), (1, 140))
        self.assertEqual(
            context["seq_num_source"], "Oem.Lenovo.PlatformFirstSeqNum/PlatformLastSeqNum"
        )
        legacy = {"Oem": {"Lenovo": {"FirstSeqNum": 5, "LastSeqNum": 9}}}
        _view, context = checks._normalize_event_log([], legacy)
        self.assertEqual((context["first_seq_num"], context["last_seq_num"]), (5, 9))
        _view, context = checks._normalize_event_log([], {})
        self.assertIsNone(context["seq_num_source"])

    def test_dns_placeholders_are_not_servers(self):
        nic = dict(
            _fx("xcc_manager_nic.json"),
            NameServers=["", "", "", "::", "::", "::"],
            StaticNameServers=["0.0.0.0", "198.51.100.53", "0.0.0.0", "::", "::", "::"],
        )
        view = checks._normalize_manager_network(_fx("xcc_network_protocol.json"), nic)
        self.assertEqual(view["dns_servers"], [])
        self.assertEqual(view["static_dns_servers"], ["198.51.100.53"])

    def test_snmp_enablement_from_the_lenovo_agent_when_the_dmtf_block_is_silent(self):
        payloads = _base_payloads()
        protocol = payloads[MGR + "/NetworkProtocol"]
        protocol["SNMP"] = {"EnableSNMPv3": False, "Port": 161}
        protocol.setdefault("Oem", {})["Lenovo"] = {
            "SNMP": {"@odata.id": MGR + "/NetworkProtocol/Oem/Lenovo/SNMP"}
        }
        payloads[MGR + "/NetworkProtocol/Oem/Lenovo/SNMP"] = {
            "CommunityNames": ["public"],
            "SNMPv3Agent": {"ProtocolEnabled": False, "Port": 161},
            "SNMPTraps": {"ProtocolEnabled": False, "Port": 162},
        }
        ctx = _FakeCtx(payloads)
        result = checks._collect_manager_network(ctx)
        self.assertIs(result["normalized"]["snmp_enabled"], False)
        self.assertEqual(result["normalized"]["snmp_port"], 161)
        self.assertEqual(result["context"]["snmp_source"], "Oem.Lenovo.SNMP.SNMPv3Agent")
        self.assertNotIn("public", json.dumps(result["raw"]))
        self.assertIn(MGR + "/NetworkProtocol/Oem/Lenovo/SNMP", ctx.gets)


class TestDiscovery(unittest.TestCase):
    """The shakedown's BMC discovery probes, on the hand-built set (the job is not in CI)."""

    def test_every_probe_answers(self):
        payloads = _base_payloads()
        ctx = _FakeCtx(payloads)
        ctx.restconf = type("Client", (), {"username": "netops"})()
        report = {label: probe(ctx) for label, probe in checks.DISCOVERY_PROBES}
        self.assertEqual(report["service_root"]["resolution"]["system"], SYS)
        self.assertIn("Security", report["oem"]["manager"]["links"])
        self.assertEqual(report["collections"]["collections"]["memory"], 4)
        self.assertEqual(report["collections"]["collections"]["accounts"], "absent (404)")
        self.assertIs(report["environment"]["Thermal"], True)
        self.assertIs(report["environment"]["ThermalSubsystem"], False)
        self.assertIn("PlatformLog", report["log_services"])
        self.assertTrue(report["security"]["properties"])
        self.assertEqual(
            report["capture_account"],
            {"found": False, "note": "/redfish/v1/AccountService answered 404"},
        )
        # the log's sequence numbers are the shakedown's first and last reads,
        # never one of the state probes that run after the checks
        self.assertNotIn("log_sequence_before", report)
        self.assertEqual(checks._discover_log_sequence(ctx)["service"], "PlatformLog")

    def test_expand_depth_tells_inlined_collections_from_inlined_members(self):
        payloads = _base_payloads()
        adapters = CH + "/NetworkAdapters?$expand=.($levels=2)"
        link = {"@odata.id": CH + "/NetworkAdapters/ob-2/Ports/1"}
        payloads[adapters] = {
            "Members": [{"Id": "ob-2", "Ports": {"Members": [link], "Members@odata.count": 1}}]
        }
        report = checks._discover_expand(_FakeCtx(payloads))
        self.assertEqual(
            report["levels_2"],
            {
                "members": 1,
                "members_inline": True,
                "nested_collections_inline": True,
                "nested_members_inline": False,
            },
        )
        payloads[adapters]["Members"][0]["Ports"]["Members"] = [dict(link, LinkStatus="NoLink")]
        self.assertIs(
            checks._discover_expand(_FakeCtx(payloads))["levels_2"]["nested_members_inline"], True
        )

    def test_log_sequence_after_is_a_fresh_read(self):
        ctx = _FakeCtx(_base_payloads())
        checks._discover_log_sequence(ctx)
        before = ctx.gets.count(SYS + "/LogServices/PlatformLog")
        checks._discover_log_sequence(ctx, fresh=True)
        self.assertEqual(ctx.gets.count(SYS + "/LogServices/PlatformLog"), before + 1)

    def test_capture_account_role_without_naming_anyone(self):
        payloads = _base_payloads()
        payloads["/redfish/v1/AccountService"] = {
            "Accounts": {"@odata.id": "/redfish/v1/AccountService/Accounts"}
        }
        payloads["/redfish/v1/AccountService/Accounts" + EXPAND] = {
            "Members": [
                {"Id": "1", "UserName": "admin-person", "RoleId": "Administrator"},
                {
                    "Id": "3",
                    "UserName": "netops",
                    "RoleId": "CustomRole4",
                    "Enabled": True,
                    "AccountTypes": ["Redfish", "WebUI"],
                    "Links": {
                        "Role": {"@odata.id": "/redfish/v1/AccountService/Roles/CustomRole4"}
                    },
                },
            ]
        }
        payloads["/redfish/v1/AccountService/Roles/CustomRole4"] = {
            "AssignedPrivileges": ["Login"],
            "OemPrivileges": ["ReadOnly"],
        }
        ctx = _FakeCtx(payloads)
        ctx.restconf = type("Client", (), {"username": "netops"})()
        # a check that keeps every account name (bmc_accounts, decision 5) read it first
        accounts = "/redfish/v1/AccountService/Accounts"
        checks._fetch_collection(ctx, accounts, "accounts", redact=checks._scrub_accounts)
        report = checks._discover_account(ctx)
        self.assertEqual(report["role_id"], "CustomRole4")
        self.assertEqual(report["oem_privileges"], ["ReadOnly"])
        self.assertEqual(report["account_types"], ["Redfish", "WebUI"])
        self.assertNotIn("admin-person", json.dumps(report))
        self.assertNotIn("netops", json.dumps(report))
        # discovery read the list again, fresh, and what it read (and the trace kept)
        # names no account but the capture's own
        self.assertEqual(ctx.gets.count(accounts + EXPAND), 2)
        fresh = [
            payload
            for key, payload in ctx._cache.items()
            if key[0] == accounts + EXPAND and len(key) > 2
        ]
        self.assertEqual(
            [row["UserName"] for row in fresh[0]["Members"]], [checks._SCRUBBED, "netops"]
        )

    def test_the_discovery_redactor_is_idempotent_and_copies(self):
        redact = checks._discovery_account_redactor("netops")
        payload = {
            "Members": [
                {"UserName": "admin-person", "Password": "pw"},
                {"UserName": "netops"},
                {"UserName": ""},
            ]
        }
        once = redact(payload)
        self.assertEqual(once, redact(once))
        self.assertEqual(
            [row["UserName"] for row in once["Members"]], [checks._SCRUBBED, "netops", ""]
        )
        self.assertEqual(payload["Members"][0]["UserName"], "admin-person")  # a copy
        self.assertEqual(once["Members"][0]["Password"], checks._SCRUBBED)
        self.assertEqual(redact({"UserName": "someone"})["UserName"], checks._SCRUBBED)


# The hand-built base set (_base_payloads) models the twelve checks PR B shipped. A check
# added since brings its own fixtures, so on that set its resources answer 404 and it is
# not-present there: the family-wide loops above (TestWholeFamily, TestResolution,
# TestHygiene) accept that from a newer check and never from one of the twelve.
_BASE_SET_CHECKS = frozenset(
    {
        "bmc_system",
        "bmc_security",
        "bmc_thermal",
        "bmc_power",
        "bmc_inventory",
        "bmc_host_nics",
        "bmc_firmware",
        "bmc_event_log",
        "bmc_bios",
        "bmc_storage",
        "bmc_manager_network",
        "bmc_chassis",
    }
)


def _collect_on_base_set(check, ctx):
    """``check``'s result on the hand-built base set; None for a newer check not-present there."""
    try:
        return check.collector(ctx)
    except registry.SkipCheck:
        if check.id in _BASE_SET_CHECKS:
            raise
        return None


class TestSensors(unittest.TestCase):
    """bmc_sensors on hand-built payloads: the DMTF vocabulary another vendor serves
    (xcc_sensors_dmtf_*.json, built from the Sensor and EnvironmentMetrics schemas — every
    value an invention) and Lenovo shapes the lab unit lacks. The lab SE350's own 89 sensors
    are pinned in test_lab_fixtures.TestBmcLabSensors."""

    SENSORS = CH + "/Sensors"
    ENV = CH + "/EnvironmentMetrics"
    SUB = CH + "/ThermalSubsystem"
    FIELDS = {
        "reading_type",
        "physical_context",
        "physical_sub_context",
        "state",
        "health",
        "reading_units",
        "thresholds",
        "reading",
        "asserted",
    }

    @staticmethod
    def _members():
        return _fx("xcc_sensors_dmtf_expanded.json")["Members"]

    def _sensors(self, expanded, payloads, expand=True):
        """Serve ``expanded`` as the Sensors collection: $expand form, plain form, members."""
        payloads.pop(self.SENSORS + EXPAND, None)
        if expand:
            payloads[self.SENSORS + EXPAND] = expanded
        plain, members = _split_collection(expanded)
        payloads[self.SENSORS] = plain
        payloads.update(members)
        return payloads

    def _payloads(self, vendor="Contoso", expand=True):
        """The hand-built base set with the DMTF sensor fixtures linked from its Chassis."""
        payloads = _base_payloads()
        payloads["/redfish/v1/"] = dict(payloads["/redfish/v1/"], Vendor=vendor)
        payloads[CH]["Sensors"] = {"@odata.id": self.SENSORS}
        payloads[CH]["EnvironmentMetrics"] = {"@odata.id": self.ENV}
        payloads[self.ENV] = _fx("xcc_sensors_dmtf_environmentmetrics.json")
        return self._sensors(_fx("xcc_sensors_dmtf_expanded.json"), payloads, expand=expand)

    @staticmethod
    def _discrete(sensor_id, name, reading, state="Enabled", health="OK", **extra):
        """A Lenovo-shaped discrete sensor (as XCC 6.10 serves one: ReadingUnits '')."""
        sensor = {
            "@odata.id": CH + "/Sensors/" + sensor_id,
            "Id": sensor_id,
            "Name": name,
            "ReadingType": None,
            "ReadingUnits": "",
            "Reading": reading,
            "PhysicalContext": None,
            "Status": {"State": state, "Health": health},
        }
        sensor.update(extra)
        return sensor

    def test_every_member_is_keyed_with_every_field(self):
        view, _context = checks._normalize_sensors(self._members())
        self.assertEqual(
            sorted(view),
            sorted(
                [
                    "sensor|Inlet Temperature",
                    "sensor|Exhaust Temperature",
                    "sensor|CPU1 Temperature",
                    # a Name that repeats gets its Id; a null Name is the Id
                    "sensor|DIMM Temperature|DIMMA1Temp",
                    "sensor|DIMM Temperature|DIMMB1Temp",
                    "sensor|VR_CPU1",
                    "sensor|PSU1 Input Power",
                    "sensor|PSU2 Input Power",
                    "sensor|Ambient Humidity",
                    "sensor|Chassis Energy",
                    "sensor|Fan 1",
                    "sensor|Chassis Intrusion",
                ]
            ),
        )
        for key, row in view.items():
            self.assertEqual(set(row), self.FIELDS, key)
        self.assertEqual(
            view["sensor|Inlet Temperature"],
            {
                "reading_type": "Temperature",
                "physical_context": "Intake",
                "physical_sub_context": None,
                "state": "Enabled",
                "health": "OK",
                "reading_units": "Cel",
                "thresholds": {"upper_caution": 40, "upper_caution_user": 35, "upper_critical": 45},
                "reading": 22.5,
                "asserted": None,
            },
        )
        # an Absent sensor is keyed like any other, its state verbatim and every field present
        self.assertEqual(
            view["sensor|PSU2 Input Power"],
            {
                "reading_type": "Power",
                "physical_context": "PowerSupply",
                "physical_sub_context": "Input",
                "state": "Absent",
                "health": None,
                "reading_units": "W",
                "thresholds": None,
                "reading": None,
                "asserted": None,
            },
        )
        self.assertEqual(view["sensor|DIMM Temperature|DIMMB1Temp"]["health"], "Warning")

    def test_thresholds_are_the_non_null_readings_snake_cased(self):
        view, _context = checks._normalize_sensors(self._members())
        thresholds = {key: row["thresholds"] for key, row in view.items()}
        # a kind served with a null Reading is no threshold; a *User kind keeps its suffix
        self.assertEqual(
            thresholds["sensor|Inlet Temperature"],
            {"upper_caution": 40, "upper_caution_user": 35, "upper_critical": 45},
        )
        self.assertEqual(
            thresholds["sensor|CPU1 Temperature"], {"upper_critical": 95, "upper_fatal": 100}
        )
        self.assertEqual(thresholds["sensor|Fan 1"], {"lower_critical": 1000})
        self.assertEqual(thresholds["sensor|VR_CPU1"], {})  # a block with nothing set
        self.assertIsNone(thresholds["sensor|PSU1 Input Power"])  # no block served
        self.assertIsNone(thresholds["sensor|Chassis Intrusion"])

    def test_units_classify_and_only_ambient_class_temperatures_key_a_reading(self):
        view, context = checks._normalize_sensors(self._members())
        keyed = {key: row["reading"] for key, row in view.items() if row["reading"] is not None}
        # 'Ambient Humidity' is ambient-named but no temperature; the CPU and DIMMs follow load
        self.assertEqual(
            keyed, {"sensor|Inlet Temperature": 22.5, "sensor|Exhaust Temperature": 31.0}
        )
        self.assertEqual(
            context["counts"],
            {
                "total": 12,
                "numeric": 11,
                "discrete": 1,
                "by_reading_type": {
                    "EnergykWh": 1,
                    "Humidity": 1,
                    "Power": 2,
                    "Rotational": 1,
                    "Temperature": 5,
                    "Voltage": 1,
                    "none": 1,
                },
            },
        )
        # every numeric reading rides in context, an unreadable one as None
        self.assertEqual(len(context["readings"]), 11)
        self.assertEqual(context["readings"]["sensor|CPU1 Temperature"], 58)
        self.assertEqual(context["readings"]["sensor|Fan 1"], 7200)
        self.assertIsNone(context["readings"]["sensor|PSU2 Input Power"])
        # a sensor serving no ReadingUnits at all is discrete
        self.assertNotIn("sensor|Chassis Intrusion", context["readings"])
        self.assertIsNone(view["sensor|Chassis Intrusion"]["reading_units"])
        self.assertIs(view["sensor|Chassis Intrusion"]["asserted"], False)
        # XCC's 'C' is Celsius too, and a numeric sensor typed Temperature counts whatever its
        # unit ('Celsius' below is hand-built: a spelling neither XCC 6.10 nor the DMTF uses);
        # an inlet-named sensor that measures anything else keys no reading
        view, _context = checks._normalize_sensors(
            [
                {"Id": "208L0", "Name": "Ambient Temp", "ReadingUnits": "C", "Reading": 21},
                {
                    "Id": "7",
                    "Name": "Outlet Temp",
                    "ReadingType": "Temperature",
                    "ReadingUnits": "Celsius",
                    "Reading": 35,
                },
                {
                    "Id": "8",
                    "Name": "Inlet Fan",
                    "ReadingType": "Rotational",
                    "ReadingUnits": "RPM",
                    "Reading": 6000,
                },
            ]
        )
        self.assertEqual(view["sensor|Ambient Temp"]["reading"], 21)
        self.assertEqual(view["sensor|Outlet Temp"]["reading"], 35)
        self.assertIsNone(view["sensor|Inlet Fan"]["reading"])

    def test_a_discrete_reading_is_an_asserted_flag_unless_it_is_a_measurement(self):
        sensors = [
            self._discrete("189L0", "Chassis", 0),
            # hand-built: how an asserted discrete sensor reads (1, a Health change or both)
            # has not been observed on a live unit — any reading but 0 or null asserts
            self._discrete("190L0", "Chassis Movement", 1, health="Critical"),
            self._discrete("128L0", "M2 Drive 0", None, state="Disabled", health=None),
            self._discrete(
                "164L0", "Sys Utilization", 37, Thresholds={"UpperCritical": {"Reading": None}}
            ),
            self._discrete("235L0", "CPU DTS", -51, ReadingType="Temperature"),
            self._discrete("901", "CPU1 DTS", 0),  # named DTS: a margin at 0 too
            self._discrete("902", "PCH Margin", -8),  # a negative reading is headroom
        ]
        view, context = checks._normalize_sensors(sensors)
        self.assertEqual(
            {key: row["asserted"] for key, row in view.items()},
            {
                "sensor|Chassis": False,
                "sensor|Chassis Movement": True,
                "sensor|M2 Drive 0": None,
                "sensor|Sys Utilization": None,
                "sensor|CPU DTS": None,
                "sensor|CPU1 DTS": None,
                "sensor|PCH Margin": None,
            },
        )
        self.assertEqual(view["sensor|Chassis Movement"]["health"], "Critical")
        self.assertEqual(view["sensor|M2 Drive 0"]["state"], "Disabled")
        self.assertEqual(view["sensor|Sys Utilization"]["thresholds"], {})
        # host load and margins are readings: context only, never a key
        self.assertEqual(context["utilisation_readings"], {"sensor|Sys Utilization": 37})
        self.assertEqual(
            context["margin_readings"],
            {"sensor|CPU DTS": -51, "sensor|CPU1 DTS": 0, "sensor|PCH Margin": -8},
        )
        self.assertEqual(context["readings"], {})  # none of them names a unit
        self.assertEqual((context["counts"]["numeric"], context["counts"]["discrete"]), (0, 7))
        self.assertEqual({row["reading"] for row in view.values()}, {None})

    def test_reading_times_and_peak_readings_ride_in_context(self):
        _view, context = checks._normalize_sensors(self._members())
        self.assertEqual(
            context["reading_times"],
            {
                "sensor|Inlet Temperature": "2026-09-30T10:15:00+00:00",
                "sensor|Exhaust Temperature": "2026-09-30T10:15:00+00:00",
            },
        )
        self.assertEqual(context["peak_readings"], {"sensor|Inlet Temperature": 26.0})

    def test_environment_metrics_as_served_joined_to_the_sensor_keys(self):
        _view, context = checks._normalize_sensors(
            self._members(), environment=_fx("xcc_sensors_dmtf_environmentmetrics.json")
        )
        self.assertEqual(
            context["environment"],
            {
                "power_watts": 212.0,
                "energy_kwh": 1234.5,
                "temperature_celsius": 22.5,
                "humidity_percent": 38.0,
                # by the sensor the excerpt names, else its DeviceName
                "fan_speeds_percent": {
                    "sensor|Fan 1": {"reading": 45, "speed_rpm": 7200},
                    "Fan 2": {"reading": 44, "speed_rpm": 7100},
                },
                "sources": {
                    "power_watts": "sensor|PSU1 Input Power",
                    "energy_kwh": "sensor|Chassis Energy",
                    "temperature_celsius": "sensor|Inlet Temperature",
                    "humidity_percent": "sensor|Ambient Humidity",
                },
            },
        )
        # an excerpt naming a sensor this read did not list keeps its URI; unserved reads None
        other = "/redfish/v1/Chassis/2/Sensors/P"
        _view, context = checks._normalize_sensors(
            self._members(), environment={"PowerWatts": {"Reading": 90, "DataSourceUri": other}}
        )
        self.assertEqual(context["environment"]["sources"]["power_watts"], other)
        self.assertIsNone(context["environment"]["energy_kwh"])
        self.assertIsNone(context["environment"]["fan_speeds_percent"])
        # not read at all: null, as the ThermalMetrics summary is
        _view, context = checks._normalize_sensors(self._members())
        self.assertIsNone(context["environment"])
        self.assertIsNone(context["temperature_summary_c"])

    def test_the_security_sensors_are_named_per_role_on_lenovo_only(self):
        sensors = [
            self._discrete("189L0", "Chassis", 0),
            self._discrete("190L0", "Chassis Movement", 0),
            self._discrete("246L0", "Lockdown Mode", 0),
            self._discrete("17L0", "Low Security Jmp", 0),
            self._discrete("197L0", "Power Adapter 2", 0, ReadingType="Power"),
            self._discrete("196L0", "Power Adapter 1", 0, ReadingType="Power"),
            # near misses: the names are matched whole
            self._discrete("900", "Chassis Intrusion", 0),
            self._discrete("901", "Power Adapter", 0),
        ]
        _view, context = checks._normalize_sensors(sensors, lenovo=True)
        self.assertEqual(
            context["security_sensors"],
            {
                "chassis_intrusion": ["sensor|Chassis"],
                "chassis_movement": ["sensor|Chassis Movement"],
                "lockdown_mode": ["sensor|Lockdown Mode"],
                "low_security_jumper": ["sensor|Low Security Jmp"],
                "power_adapters": ["sensor|Power Adapter 1", "sensor|Power Adapter 2"],
            },
        )
        # the names are Lenovo's: another vendor gets no mapping, never a guess
        self.assertIsNone(checks._normalize_sensors(sensors)[1]["security_sensors"])
        # none of them served: every role an empty list
        _view, context = checks._normalize_sensors(self._members(), lenovo=True)
        self.assertEqual({len(keys) for keys in context["security_sensors"].values()}, {0})

    def test_collector_one_expand_get_and_the_linked_environment_metrics(self):
        ctx = _FakeCtx(self._payloads())
        result = checks._collect_sensors(ctx)
        # the hand-built Chassis links no ThermalSubsystem: no ThermalMetrics read
        self.assertEqual(ctx.gets, RESOLVE + [CH, self.ENV, self.SENSORS + EXPAND])
        self.assertEqual(len(result["normalized"]), 12)
        context = result["context"]
        self.assertEqual(context["sensors_collection"]["strategy"], "expand")
        self.assertEqual(context["sensors_source"], self.SENSORS)
        self.assertEqual(context["environment_source"], self.ENV)
        self.assertEqual(context["environment"]["power_watts"], 212.0)
        self.assertIsNone(context["temperature_summary_source"])
        self.assertIsNone(context["temperature_summary_c"])
        self.assertEqual(context["host_power_state"], "On")
        self.assertEqual(context["resolution"]["vendor"], "Contoso")
        # DMTF reads for every vendor; only the Lenovo sensor names go unmapped
        self.assertIsNone(context["security_sensors"])
        self.assertIn("no Contoso mapping", context["security_sensors_note"])
        self.assertEqual(set(result["raw"]), {self.SENSORS + EXPAND, self.ENV})
        raw = json.dumps(result["raw"])
        self.assertNotIn("Actions", raw)
        self.assertNotIn("@odata.etag", raw)
        self.assertEqual({redactor for _path, redactor in ctx.redacted}, {"_scrub_payload"})

    def test_the_thermal_metrics_summary_is_one_get_shared_with_bmc_thermal(self):
        payloads = self._payloads(vendor="Lenovo")
        payloads[CH]["ThermalSubsystem"] = {"@odata.id": self.SUB}
        payloads[self.SUB + "/ThermalMetrics"] = {
            "@odata.id": self.SUB + "/ThermalMetrics",
            "TemperatureSummaryCelsius": {"Ambient": {"Reading": 23}, "Intake": {"Reading": 23.5}},
        }
        ctx = _FakeCtx(payloads)
        sensors = checks._collect_sensors(ctx)
        thermal = checks._collect_thermal(ctx)
        self.assertEqual(ctx.gets.count(self.SUB + "/ThermalMetrics"), 1)
        summary = {"ambient": 23.0, "intake": 23.5, "exhaust": None, "internal": None}
        self.assertEqual(sensors["context"]["temperature_summary_c"], summary)
        self.assertEqual(thermal["context"]["temperature_summary_c"], summary)
        self.assertEqual(
            sensors["context"]["temperature_summary_source"], self.SUB + "/ThermalMetrics"
        )
        self.assertIn(self.SUB + "/ThermalMetrics", sensors["raw"])
        self.assertIsNone(sensors["context"]["security_sensors_note"])
        # a subsystem serving no ThermalMetrics leaves the summary null, never fails
        del payloads[self.SUB + "/ThermalMetrics"]
        result = checks._collect_sensors(_FakeCtx(payloads))
        self.assertIsNone(result["context"]["temperature_summary_c"])
        self.assertIsNone(result["context"]["temperature_summary_source"])
        self.assertEqual(result["normalized"], sensors["normalized"])

    def test_members_are_walked_when_expand_is_not_usable(self):
        ctx = _FakeCtx(self._payloads(expand=False))
        result = checks._collect_sensors(ctx)
        meta = result["context"]["sensors_collection"]
        self.assertEqual((meta["strategy"], meta["expand_refused"]), ("members", "HTTP 404"))
        walked = [path for path in ctx.gets if path.startswith(self.SENSORS + "/")]
        self.assertEqual(len(walked), 12)
        self.assertEqual(
            ctx.gets, RESOLVE + [CH, self.ENV, self.SENSORS + EXPAND, self.SENSORS] + walked
        )
        # the same view either way
        expanded = checks._collect_sensors(_FakeCtx(self._payloads()))
        self.assertEqual(result["normalized"], expanded["normalized"])

    def _many(self, count):
        """``count`` discrete sensors, $expand unusable, the System unlinked (the id resolution
        costs its full five GETs) and both metrics linked: the check's widest walk."""
        payloads = _base_payloads()
        del payloads[SYS]["Links"]
        payloads["/redfish/v1/Managers"] = {"Members": [{"@odata.id": MGR}]}
        payloads["/redfish/v1/Chassis"] = {"Members": [{"@odata.id": CH}]}
        payloads[CH]["Sensors"] = {"@odata.id": self.SENSORS}
        payloads[CH]["EnvironmentMetrics"] = {"@odata.id": self.ENV}
        payloads[CH]["ThermalSubsystem"] = {"@odata.id": self.SUB}
        payloads[self.ENV] = _fx("xcc_sensors_dmtf_environmentmetrics.json")
        payloads[self.SUB + "/ThermalMetrics"] = {"TemperatureSummaryCelsius": {}}
        members = [self._discrete("%dL0" % n, "Sensor %d" % n, 0) for n in range(1, count + 1)]
        expanded = {"@odata.id": self.SENSORS, "Members": members, "Members@odata.count": count}
        return self._sensors(expanded, payloads, expand=False)

    def test_the_widest_walk_fits_the_budget_and_a_wider_one_is_refused_before_it_starts(self):
        # resolution 5, the Chassis, EnvironmentMetrics, ThermalMetrics, the $expand attempt
        # and the collection: 10 of the 35, leaving a walk of 25
        ctx = _FakeCtx(self._many(25))
        result = checks._collect_sensors(ctx)
        self.assertEqual(len(result["normalized"]), 25)
        self.assertEqual(len(ctx.gets), 5 + 1 + 2 + 1 + 1 + 25)
        self.assertEqual(len(ctx.gets), checks._BUDGET_SENSORS)
        ctx = _FakeCtx(self._many(26))
        with self.assertRaises(checks.CollectError) as caught:
            checks._collect_sensors(ctx)
        self.assertIn("26 members to fetch but only 25 GET(s) left", str(caught.exception))
        self.assertFalse([path for path in ctx.gets if path.startswith(self.SENSORS + "/")])
        self.assertEqual(len(ctx.gets), 10)

    def test_not_present_and_failed_shapes(self):
        # the hand-built Chassis links no Sensors and none is served: not present
        ctx = _FakeCtx(_base_payloads())
        with self.assertRaises(registry.SkipCheck) as caught:
            checks._collect_sensors(ctx)
        self.assertIn("links no Sensors collection", str(caught.exception))
        self.assertEqual(ctx.gets, RESOLVE + [CH, self.SENSORS + EXPAND, self.SENSORS])
        # linked, but answering 404: failed, never "no sensors"
        payloads = self._payloads()
        for path in [path for path in payloads if path.startswith(self.SENSORS)]:
            del payloads[path]
        with self.assertRaises(checks.CollectError) as caught:
            checks._collect_sensors(_FakeCtx(payloads))
        self.assertIn("but it answered 404", str(caught.exception))
        # served with zero members: unmeasured, never "every sensor gone"
        empty = {"@odata.id": self.SENSORS, "Members": [], "Members@odata.count": 0}
        with self.assertRaises(checks.CollectError) as caught:
            checks._collect_sensors(_FakeCtx(self._sensors(empty, self._payloads())))
        self.assertIn("zero members (host PowerState On)", str(caught.exception))
        # a server error on the collection is a failed read (on its $expand form, a refusal)
        errors = {self.SENSORS + EXPAND: 500, self.SENSORS: 500}
        with self.assertRaises(_FakeRedfishError):
            checks._collect_sensors(_FakeCtx(self._payloads(), errors=errors))
        # a linked EnvironmentMetrics answering 404: no environment, the check still ok
        payloads = self._payloads()
        del payloads[self.ENV]
        result = checks._collect_sensors(_FakeCtx(payloads))
        self.assertIsNone(result["context"]["environment"])
        self.assertIsNone(result["context"]["environment_source"])
        self.assertEqual(len(result["normalized"]), 12)
        # an empty Chassis body is a broken read
        payloads = self._payloads()
        payloads[CH] = {}
        with self.assertRaises(checks.CollectError):
            checks._collect_sensors(_FakeCtx(payloads))

    def test_a_paged_or_short_collection_is_refused_never_recorded_partially(self):
        expanded = _fx("xcc_sensors_dmtf_expanded.json")
        page = dict(expanded, Members=expanded["Members"][:6])
        page["Members@odata.nextLink"] = self.SENSORS + "?$skip=6"
        with self.assertRaises(checks.CollectError) as caught:
            checks._collect_sensors(_FakeCtx(self._sensors(page, self._payloads())))
        self.assertIn("one page of the collection", str(caught.exception))
        short = dict(expanded, Members=expanded["Members"][:11])  # still counting 12
        with self.assertRaises(checks.CollectError) as caught:
            checks._collect_sensors(_FakeCtx(self._sensors(short, self._payloads())))
        self.assertIn("counts 12 members but listed 11", str(caught.exception))
        # the walked collection is held to the same rule
        payloads = self._sensors(short, self._payloads(), expand=False)
        with self.assertRaises(checks.CollectError) as caught:
            checks._collect_sensors(_FakeCtx(payloads))
        self.assertIn("counts 12 members but listed 11", str(caught.exception))

    def test_links_into_actions_are_refused(self):
        for leaf in ("Sensors", "EnvironmentMetrics", "ThermalSubsystem"):
            payloads = self._payloads()
            payloads[CH][leaf] = {"@odata.id": CH + "/Actions/Chassis.Reset"}
            with self.assertRaises(checks.CollectError, msg=leaf):
                checks._collect_sensors(_FakeCtx(payloads))

    def test_two_sensors_on_one_key_are_refused_rather_than_merged(self):
        sensors = [self._discrete("1L0", "PSU", 0), self._discrete("PSU", None, 0)]
        with self.assertRaises(checks.CollectError) as caught:
            checks._normalize_sensors(sensors)
        self.assertIn("sensor|PSU", str(caught.exception))

    def test_only_stable_facts_diff_and_the_ambient_reading_is_banded(self):
        check = registry.CHECKS["bmc_sensors"]
        compare = check.compare
        self.assertEqual(
            compare, {"mode": "equality_set", "fields": {"reading": {"tolerance": {"abs": 8}}}}
        )
        self.assertEqual(check.tier, 1)
        self.assertNotIn(registry.EMPTY_OK_TAG, check.tags)  # a chassis always has sensors
        diff = _loader.diffcore.diff_check
        pre = checks._normalize_sensors(self._members())[0]
        members = self._members()
        by_id = {sensor["Id"]: sensor for sensor in members}
        # every numeric reading moves (load, the room): only the ambient class is keyed
        for sensor in members:
            if sensor.get("ReadingUnits") and sensor.get("Reading") is not None:
                sensor["Reading"] += 7
        self.assertEqual(
            diff(pre, checks._normalize_sensors(members)[0], compare)["result"], "pass"
        )
        by_id["InletTemp"]["Reading"] = 22.5 + 9  # beyond the 8 °C band
        by_id["Intrusion"]["Reading"] = 1  # the discrete sensor asserts
        by_id["Fan1"]["Thresholds"]["LowerCritical"]["Reading"] = 1200  # reconfigured
        changed = diff(pre, checks._normalize_sensors(members)[0], compare)["changed"]
        self.assertEqual(
            sorted((row["key"], row["field"]) for row in changed),
            [
                ("sensor|Chassis Intrusion", "asserted"),
                ("sensor|Fan 1", "thresholds"),
                ("sensor|Inlet Temperature", "reading"),
            ],
        )


class TestBoot(unittest.TestCase):
    """bmc_boot on the shapes the lab unit lacks, hand-built from the schema vocabulary.

    xcc_boot_dmtf_boot_block.json (every DMTF ComputerSystem Boot leaf),
    xcc_boot_bootoptions_expanded.json (a BootOption collection),
    xcc_boot_virtualmedia_inserted_expanded.json (a slot with an image inserted)
    and xcc_boot_mountimages_expanded.json (one LenovoRemoteMountMedia member:
    Size and Readonly, its schema's own leaves) are hand-built; the Lenovo boot
    manager is the lab unit's real BootSettings collection.
    """

    BOOT_OPTIONS = SYS + "/BootOptions"
    SETTINGS = SYS + "/Oem/Lenovo/BootSettings"
    MEDIA = SYS + "/VirtualMedia"
    RC = MGR + "/Oem/Lenovo/RemoteControl"
    MOUNTS = RC + "/MountImages"
    SCALARS = (
        "boot_order",
        "alias_boot_order",
        "boot_order_property_selection",
        "boot_override",
        "boot_override_target",
        "boot_override_mode",
        "uefi_target",
        "boot_next",
        "automatic_retry_config",
        "automatic_retry_attempts",
        "stop_boot_on_fault",
        "trusted_module_required_to_boot",
        "http_boot_uri",
    )

    def _payloads(self, expand=True):
        payloads = _base_payloads()
        system = payloads[SYS]
        system["Boot"] = _fx("xcc_boot_dmtf_boot_block.json")
        system["VirtualMedia"] = {"@odata.id": self.MEDIA}
        system["Oem"]["Lenovo"]["BootSettings"] = {"@odata.id": self.SETTINGS}
        payloads[MGR]["Oem"]["Lenovo"]["RemoteControl"] = {"@odata.id": self.RC}
        payloads[self.RC] = {
            "@odata.id": self.RC,
            "Id": "RemoteControl",
            "ServiceEnabled": True,
            "MountImages": {"@odata.id": self.MOUNTS},
            "Sessions": {"@odata.id": self.RC + "/Sessions"},
        }
        collections = {
            self.SETTINGS: _fx("xcc_system_lenovo_bootsettings_expanded_lab.json"),
            self.MEDIA: _fx("xcc_boot_virtualmedia_inserted_expanded.json"),
            self.MOUNTS: _fx("xcc_boot_mountimages_expanded.json"),
            self.BOOT_OPTIONS: _fx("xcc_boot_bootoptions_expanded.json"),
        }
        for path, expanded in collections.items():
            if expand:
                payloads[path + EXPAND] = expanded
            else:
                plain, members = _split_collection(expanded)
                payloads[path] = plain
                payloads.update(members)
        return payloads

    def test_every_scalar_is_present_and_none_without_a_boot_block(self):
        view, context = checks._normalize_boot({})
        self.assertEqual(view, dict.fromkeys(self.SCALARS))
        self.assertEqual(
            context,
            {
                "host_power_state": None,
                "remaining_automatic_retry_attempts": None,
                "boot_order_supported": None,
                "override_targets_allowable": None,
                "mount_image_sizes": None,
            },
        )

    def test_the_dmtf_boot_block_keeps_its_orders_and_the_retry_countdown_is_context(self):
        system = {"Boot": _fx("xcc_boot_dmtf_boot_block.json"), "PowerState": "Off"}
        view, context = checks._normalize_boot(system)
        self.assertEqual(
            {key: view[key] for key in self.SCALARS if key != "http_boot_uri"},
            {
                # both orders exactly as served: the order is the fact
                "boot_order": ["Boot0002", "Boot0000", "Boot0001", "Boot0004", "Boot0003"],
                "alias_boot_order": ["Hdd", "Pxe", "UefiHttp", "UefiShell"],
                "boot_order_property_selection": "BootOrder",
                "boot_override": "Once",
                "boot_override_target": "UefiBootNext",
                "boot_override_mode": "UEFI",
                "uefi_target": None,
                "boot_next": "Boot0004",
                "automatic_retry_config": "RetryAttempts",
                "automatic_retry_attempts": 3,
                "stop_boot_on_fault": "Never",
                "trusted_module_required_to_boot": "Disabled",
            },
        )
        self.assertEqual(context["remaining_automatic_retry_attempts"], 2)
        self.assertEqual(context["host_power_state"], "Off")
        self.assertIn("UefiBootNext", context["override_targets_allowable"])
        # the countdown moves on its own: never a diff
        system["Boot"]["RemainingAutomaticRetryAttempts"] = 1
        self.assertEqual(checks._normalize_boot(system)[0], view)

    def test_collector_reads_each_source_in_one_expand_get(self):
        ctx = _FakeCtx(self._payloads())
        result = checks._collect_boot(ctx)
        view, context = result["normalized"], result["context"]
        self.assertEqual(
            ctx.gets,
            RESOLVE
            + [MGR, self.SETTINGS + EXPAND, self.MEDIA + EXPAND, self.RC, self.MOUNTS + EXPAND]
            + [self.BOOT_OPTIONS + EXPAND],
        )
        self.assertEqual(
            sorted(key.split("|", 1)[0] for key in view if "|" in key),
            ["mount"] + ["option"] * 5 + ["order"] * 5 + ["vmedia"] * 2,
        )
        self.assertEqual(
            view["option|Boot0003"],
            {
                "display_name": "UEFI: Built-in EFI Shell",
                "enabled": False,  # the option's own BootOptionEnabled
                "uefi_device_path": "Fv(00000000-0000-4000-8000-000000000002)/"
                "FvFile(00000000-0000-4000-8000-000000000003)",
                "alias": "UefiShell",
            },
        )
        self.assertEqual(
            view["vmedia|RDOC1"],
            {
                "inserted": True,
                "image": "https://***scrubbed***@203.0.113.30/iso/installer.iso",
                "image_name": "installer.iso",
                "media_types": ["CD", "DVD", "Floppy", "USBStick"],  # sorted
                "connected_via": "URI",
                "write_protected": True,
                "transfer_protocol_type": "HTTPS",
                "transfer_method": "Stream",
                "verify_certificate": False,
            },
        )
        # a LenovoRemoteMountMedia serves Size and Readonly; the remote-map leaves read None
        self.assertEqual(
            view["mount|1"],
            {"name": "installer.iso", "path": None, "mounted": None, "readonly": True},
        )
        self.assertEqual(context["mount_image_sizes"], {"1": 1073741824})
        self.assertEqual(
            view["http_boot_uri"], "https://***scrubbed***@203.0.113.20/boot/efi/bootx64.efi"
        )
        self.assertIs(context["remote_control_enabled"], True)
        self.assertEqual(context["remote_control"], {"resource": self.RC, "served": True})
        for label, path in (
            ("boot_options", self.BOOT_OPTIONS),
            ("boot_settings", self.SETTINGS),
            ("virtual_media", self.MEDIA),
            ("mount_images", self.MOUNTS),
        ):
            self.assertEqual(
                (context[label]["resource"], context[label]["strategy"]), (path, "expand"), label
            )
        self.assertEqual(context["virtual_media"]["owner"], "System")
        # no credential of the image share or the HTTP boot server anywhere
        text = json.dumps(result)
        for secret in ("user-a", "pw-a"):
            self.assertNotIn(secret, text)
        self.assertEqual({name for _path, name in ctx.redacted}, {"_scrub_payload"})
        self.assertNotIn(self.RC + "/Sessions", ctx.gets)  # who is connected is never read

    def test_without_expand_every_collection_is_walked_and_the_refusal_paid_once(self):
        expanded = checks._collect_boot(_FakeCtx(self._payloads()))
        ctx = _FakeCtx(self._payloads(expand=False))
        result = checks._collect_boot(ctx)
        self.assertEqual(result["normalized"], expanded["normalized"])
        self.assertEqual(
            [path for path in ctx.gets if path.endswith(EXPAND)], [self.SETTINGS + EXPAND]
        )
        # resolution 3, the Manager, BootSettings 1 + 1 + 5, VirtualMedia 1 + 2,
        # RemoteControl, MountImages 1 + 1, BootOptions 1 + 5
        self.assertEqual(len(ctx.gets), 3 + 1 + 7 + 3 + 1 + 2 + 6)
        self.assertLessEqual(len(ctx.gets), checks._BUDGET_BOOT)
        self.assertEqual(result["context"]["boot_options"]["strategy"], "members")

    def test_a_boot_options_walk_the_budget_cannot_cover_is_refused_before_it_starts(self):
        payloads = self._payloads(expand=False)
        payloads[self.BOOT_OPTIONS]["Members"] = [
            {"@odata.id": self.BOOT_OPTIONS + "/Boot%04X" % (n,)}
            for n in range(checks._BUDGET_BOOT)
        ]
        ctx = _FakeCtx(payloads)
        with self.assertRaises(checks.CollectError) as caught:
            checks._collect_boot(ctx)
        self.assertIn("%d members" % (checks._BUDGET_BOOT,), str(caught.exception))
        self.assertEqual(ctx.gets[-1], self.BOOT_OPTIONS)  # no option was fetched

    def test_an_empty_uefi_collection_is_unmeasured_never_every_entry_gone(self):
        # boot options and the boot manager are the host UEFI's, populated at POST
        payloads = self._payloads()
        payloads[self.BOOT_OPTIONS + EXPAND]["Members"] = []
        with self.assertRaises(checks.CollectError) as caught:
            checks._collect_boot(_FakeCtx(payloads))
        self.assertIn("Boot.BootOptions", str(caught.exception))
        self.assertIn("host PowerState On", str(caught.exception))
        payloads = self._payloads()
        payloads[self.SETTINGS + EXPAND]["Members"] = []
        with self.assertRaises(checks.CollectError) as caught:
            checks._collect_boot(_FakeCtx(payloads))
        self.assertIn("zero members", str(caught.exception))
        payloads = self._payloads()
        for member in payloads[self.SETTINGS + EXPAND]["Members"]:
            member.update(BootOrderCurrent=[], BootOrderNext=[], BootOrderSupported=[])
        with self.assertRaises(checks.CollectError) as caught:
            checks._collect_boot(_FakeCtx(payloads))
        self.assertIn("lists no boot entry in any of its 5 members", str(caught.exception))

    def test_an_empty_bmc_side_collection_is_an_empty_view(self):
        payloads = self._payloads()
        payloads[self.MEDIA + EXPAND]["Members"] = []
        payloads[self.MOUNTS + EXPAND]["Members"] = []
        result = checks._collect_boot(_FakeCtx(payloads))
        view, context = result["normalized"], result["context"]
        self.assertFalse([key for key in view if key.startswith(("vmedia|", "mount|"))])
        self.assertEqual(
            (context["virtual_media"]["members"], context["mount_images"]["members"]), (0, 0)
        )
        self.assertEqual(context["mount_image_sizes"], {})

    def test_a_linked_resource_that_answers_404_is_a_failed_read(self):
        payloads = self._payloads()
        del payloads[self.MEDIA + EXPAND]
        with self.assertRaises(checks.CollectError) as caught:
            checks._collect_boot(_FakeCtx(payloads))
        self.assertIn(self.MEDIA + " is linked but answered 404", str(caught.exception))
        payloads = self._payloads()
        del payloads[self.RC]
        with self.assertRaises(checks.CollectError) as caught:
            checks._collect_boot(_FakeCtx(payloads))
        self.assertIn(self.RC + " is linked but answered 404", str(caught.exception))

    def test_other_vendors_get_the_dmtf_reads_only(self):
        payloads = self._payloads()
        payloads["/redfish/v1/"] = dict(payloads["/redfish/v1/"], Vendor="Contoso")
        ctx = _FakeCtx(payloads)
        result = checks._collect_boot(ctx)
        view, context = result["normalized"], result["context"]
        # the System links its VirtualMedia: the Manager is not even read
        self.assertEqual(ctx.gets, RESOLVE + [self.MEDIA + EXPAND, self.BOOT_OPTIONS + EXPAND])
        self.assertEqual(len([key for key in view if key.startswith("option|")]), 5)
        self.assertEqual(len([key for key in view if key.startswith("vmedia|")]), 2)
        self.assertFalse([key for key in view if key.startswith(("order|", "mount|"))])
        self.assertIn("no Contoso mapping for the boot manager", context["boot_settings"]["note"])
        self.assertIn("no Contoso mapping", context["mount_images"]["note"])
        self.assertEqual(context["remote_control"], {"resource": None, "served": False})
        self.assertIsNone(context["remote_control_enabled"])
        self.assertIsNone(context["boot_order_supported"])

    def test_the_dmtf_reads_follow_dell_shaped_links(self):
        dell_system = "/redfish/v1/Systems/System.Embedded.1"

        def dellify(text):
            text = text.replace(SYS, dell_system)
            text = text.replace(MGR, "/redfish/v1/Managers/iDRAC.Embedded.1")
            return text.replace(CH, "/redfish/v1/Chassis/System.Embedded.1")

        payloads = {
            dellify(path): json.loads(dellify(json.dumps(body)))
            for path, body in self._payloads().items()
        }
        payloads["/redfish/v1/"] = dict(payloads["/redfish/v1/"], Vendor="Dell")
        payloads["/redfish/v1/Systems"] = {"Members": [{"@odata.id": dell_system}]}
        ctx = _FakeCtx(payloads)
        result = checks._collect_boot(ctx)
        self.assertEqual(
            ctx.gets,
            ["/redfish/v1/", "/redfish/v1/Systems", dell_system]
            + [dell_system + "/VirtualMedia" + EXPAND, dell_system + "/BootOptions" + EXPAND],
        )
        view = result["normalized"]
        self.assertEqual(len([key for key in view if key.startswith("option|")]), 5)
        self.assertEqual(view["boot_order"][0], "Boot0002")
        self.assertIs(view["vmedia|RDOC1"]["inserted"], True)
        self.assertEqual(result["context"]["resolution"]["system"], dell_system)

    def test_the_managers_virtual_media_where_the_system_links_none(self):
        payloads = self._payloads()
        del payloads[SYS]["VirtualMedia"]
        manager_media = MGR + "/VirtualMedia"
        payloads[MGR]["VirtualMedia"] = {"@odata.id": manager_media}
        payloads[manager_media + EXPAND] = json.loads(
            json.dumps(payloads.pop(self.MEDIA + EXPAND)).replace(self.MEDIA, manager_media)
        )
        result = checks._collect_boot(_FakeCtx(payloads))
        media = result["context"]["virtual_media"]
        self.assertEqual((media["owner"], media["resource"]), ("Manager", manager_media))
        self.assertIs(result["normalized"]["vmedia|RDOC1"]["inserted"], True)

    def test_not_present_only_when_nothing_about_booting_is_served(self):
        payloads = _base_payloads()
        del payloads[SYS]["Boot"]
        with self.assertRaises(registry.SkipCheck) as caught:
            checks._collect_boot(_FakeCtx(payloads))
        self.assertIn("serves no Boot block", str(caught.exception))
        # a Boot block alone is a view: its scalars
        view = checks._collect_boot(_FakeCtx(_base_payloads()))["normalized"]
        self.assertEqual(set(view), set(self.SCALARS))
        self.assertEqual(view["boot_override"], "Disabled")

    def test_links_into_actions_are_refused(self):
        for mutate in (
            lambda p: p[SYS]["Boot"].update(BootOptions={"@odata.id": SYS + "/Actions/x"}),
            lambda p: p[MGR]["Oem"]["Lenovo"].update(
                RemoteControl={"@odata.id": MGR + "/Actions/x"}
            ),
            lambda p: p[self.RC].update(MountImages={"@odata.id": self.RC + "/Actions/x"}),
        ):
            payloads = self._payloads()
            mutate(payloads)
            with self.assertRaises(checks.CollectError):
                checks._collect_boot(_FakeCtx(payloads))

    def test_a_repeated_or_missing_reference_keys_by_id(self):
        rows = checks._boot_option_rows(
            [
                {"Id": "A", "BootOptionReference": "Boot0001"},
                {"Id": "B", "BootOptionReference": "Boot0001"},
                {"Id": "C", "BootOptionReference": None, "BootOptionEnabled": True},
                {"Id": "D", "BootOptionReference": "Boot0002"},
            ]
        )
        self.assertEqual(
            sorted(rows), ["option|Boot0001|A", "option|Boot0001|B", "option|Boot0002", "option|C"]
        )
        self.assertEqual(
            rows["option|C"],
            {"display_name": None, "enabled": True, "uefi_device_path": None, "alias": None},
        )

    def test_a_reordered_boot_order_is_a_change_and_reordered_media_types_are_not(self):
        compare = registry.CHECKS["bmc_boot"].compare
        self.assertEqual(compare, {"mode": "equality_set"})
        pre = checks._collect_boot(_FakeCtx(self._payloads()))["normalized"]
        payloads = self._payloads()
        payloads[self.MEDIA + EXPAND]["Members"][1]["MediaTypes"].reverse()
        post = checks._collect_boot(_FakeCtx(payloads))["normalized"]
        self.assertEqual(_loader.diffcore.diff_check(pre, post, compare)["result"], "pass")
        payloads[SYS]["Boot"]["BootOrder"][:2] = ["Boot0000", "Boot0002"]
        members = payloads[self.SETTINGS + EXPAND]["Members"]
        members[0]["BootOrderNext"] = ["proxmox", "TrueNAS-0"] + members[0]["BootOrderNext"][2:]
        post = checks._collect_boot(_FakeCtx(payloads))["normalized"]
        diff = _loader.diffcore.diff_check(pre, post, compare)
        self.assertEqual(
            [(row["key"], row["field"]) for row in diff["changed"]],
            [("boot_order", None), ("order|BootOrder.BootOrder", "next")],
        )


class TestPowerPolicy(unittest.TestCase):
    """bmc_power_policy. HAND-BUILT for what the lab unit lacks: a cap set, Lenovo's capping,
    capability and redundancy-settings blocks (xcc_power_policy_capping.json) and a Range control
    (xcc_power_policy_controls_expanded.json), spelled as the DMTF Power and Control schemas and
    the plan's Appendix B name them — every Lenovo enum string there is a '<placeholder:...>',
    never a claimed enum member, since the lab unit serves none of those leaves. The scheduled
    power actions, the watchdogs and the JobService jobs are the lab unit's own payloads."""

    CONTROLS = CH + "/Controls"
    SPA = SYS + "/Oem/Lenovo/ScheduledPowerActions"
    DOGS = MGR + "/Oem/Lenovo/Watchdogs"
    JOBS = "/redfish/v1/JobService/Jobs"
    # read in this order by the collector
    COLLECTIONS = (
        (CONTROLS, "xcc_power_policy_controls_expanded.json"),
        (SPA, "xcc_system_lenovo_scheduledpoweractions_expanded_lab.json"),
        (DOGS, "xcc_manager_lenovo_watchdogs_expanded_lab.json"),
        (JOBS, "xcc_jobservice_jobs_expanded_lab.json"),
    )
    LENOVO_SCALARS = (
        "lenovo_power_restore_policy",
        "wake_on_lan",
        "power_on_permission",
        "local_power_control",
        "random_delay",
        "power_capping_enabled",
        "limit_mode",
        "guaranteed_w",
        "capping_min_w",
        "capping_max_w",
        "power_redundancy_policy",
        "max_power_limit_w",
        "power_failure_limit",
    )

    def _payloads(self, expand=True):
        """The hand-built set with every source of this check linked from its parent."""
        payloads = _base_payloads()
        payloads["/redfish/v1/"]["JobService"] = {"@odata.id": "/redfish/v1/JobService"}
        system = _fx("xcc_system_dmtf_policy.json")
        system["Oem"]["Lenovo"]["ScheduledPowerActions"] = {"@odata.id": self.SPA}
        payloads[SYS] = system
        payloads[CH]["Controls"] = {"@odata.id": self.CONTROLS}
        payloads[MGR]["Oem"]["Lenovo"]["Watchdogs"] = {"@odata.id": self.DOGS}
        payloads[CH + "/Power"] = _fx("xcc_power_policy_capping.json")
        for path, name in self.COLLECTIONS:
            expanded = _fx(name)
            plain, members = _split_collection(expanded)
            payloads[path] = plain
            payloads.update(members)
            if expand:
                payloads[path + EXPAND] = expanded
        return payloads

    def _collect(self, payloads, **kwargs):
        ctx = _FakeCtx(payloads, **kwargs)
        return ctx, checks._collect_power_policy(ctx)

    def test_every_scalar_is_read_from_its_own_leaf(self):
        _ctx, result = self._collect(self._payloads())
        view, context = result["normalized"], result["context"]
        self.assertEqual(
            {key: value for key, value in view.items() if "|" not in key},
            {
                "power_restore_policy": "LastState",
                "lenovo_power_restore_policy": "<placeholder:PowerRestorePolicy>",
                "wake_on_lan": False,
                "power_on_permission": True,
                "local_power_control": False,
                "random_delay": "<placeholder:RandomDelay>",
                "host_watchdog_enabled": True,
                "host_watchdog_timeout_action": "ResetSystem",
                "host_watchdog_warning_action": "DiagnosticInterrupt",
                "power_limit_w": 450,
                "power_limit_exception": "LogEventOnly",
                "power_limit_correction_ms": 1000,
                "power_capping_enabled": True,
                "limit_mode": "<placeholder:LimitMode>",
                "guaranteed_w": 310,
                "capping_min_w": 310,
                "capping_max_w": 750,
                "power_redundancy_policy": "<placeholder:PowerRedundancyPolicy>",
                "max_power_limit_w": 750,
                "power_failure_limit": 2,
            },
        )
        # the cap is the first (server-level) PowerControl member's, never the CPU sub-system's
        self.assertEqual(context["power_control_member"], "0")
        self.assertEqual(context["lenovo_capabilities_source"], "Power Oem.Lenovo")
        self.assertEqual(context["redundancy_member"], "0")
        self.assertEqual(context["non_redundant_available_power_w"], 1500)
        self.assertEqual(context["redundancy_estimated_usage"], "<placeholder:EstimatedUsage>")
        self.assertEqual(context["host_power_state"], "On")
        self.assertEqual(context["power_resource"], CH + "/Power")
        self.assertIsNone(context["unmapped"])
        self.assertEqual(context["resolution"]["system"], SYS)

    def test_rows_carry_every_field_and_what_moves_rides_in_context(self):
        _ctx, result = self._collect(self._payloads())
        view, context = result["normalized"], result["context"]
        self.assertEqual(
            [key for key in view if "|" in key],
            ["control|IntakeTemperature", "control|PowerLimit"]
            + ["sched|1", "sched|2", "sched|3"]
            + ["watchdog|1", "watchdog|2", "watchdog|3", "watchdog|4"],
        )
        self.assertEqual(
            view["control|PowerLimit"],
            {
                "control_type": "Power",
                "control_mode": "Automatic",
                "set_point": 450,
                "set_point_units": "Watt",
                "set_point_type": "Single",
                "setting_min": None,
                "setting_max": None,
                "allowable_min": 310,
                "allowable_max": 750,
                "implementation": "Programmable",
                "physical_context": "Chassis",
                "health": "OK",
                "state": "Enabled",
            },
        )
        # a Range control holds its bounds, never a set point
        intake = view["control|IntakeTemperature"]
        self.assertEqual((intake["set_point_type"], intake["set_point"]), ("Range", None))
        self.assertEqual((intake["setting_min"], intake["setting_max"]), (18, 27))
        self.assertEqual((intake["control_mode"], intake["set_point_units"]), ("Override", "Cel"))
        # a control's reading and its set-point time are context, never row fields
        self.assertEqual(
            context["control_readings"]["control|PowerLimit"],
            {
                "reading": 212,
                "data_source": CH + "/Sensors/204L0",
                "set_point_update_time": "2026-09-28T06:14:02+00:00",
            },
        )
        self.assertEqual(context["control_readings"]["control|IntakeTemperature"]["reading"], 22.5)
        self.assertEqual(
            view["sched|2"],
            {"type": "GracefulShutdown", "activated": False, "interval": "Daily", "time": "00:00"},
        )
        self.assertEqual(
            view["watchdog|4"],
            {"type": "IPMI", "state": "Enabled", "timer_s": 15, "timeout_interval_s": 15},
        )
        self.assertEqual(
            view["watchdog|1"],
            {
                "type": "OSBootProcess",
                "state": "Disabled",
                "timer_s": None,
                "timeout_interval_s": None,
            },
        )
        self.assertEqual(
            context["watchdog_expired"], {"watchdog|%d" % (n,): False for n in (1, 2, 3, 4)}
        )
        self.assertEqual(context["jobs"]["PowerOn"]["state"], "Suspended")
        self.assertEqual(context["jobs"]["PowerOn"]["schedule"]["name"], "Lenovo:Power On")
        self.assertEqual(context["jobs"]["PowerOn"]["schedule"]["enabled_days_of_week"], [])
        # every row of a family carries the same fields, whatever its member serves
        for prefix in ("control|", "sched|", "watchdog|"):
            shapes = {tuple(sorted(row)) for key, row in view.items() if key.startswith(prefix)}
            self.assertEqual(len(shapes), 1, prefix)

    def test_one_expand_get_per_collection_and_the_shared_reads_come_from_the_cache(self):
        ctx, result = self._collect(self._payloads())
        collections = [path + EXPAND for path, _name in self.COLLECTIONS]
        self.assertEqual(ctx.gets, RESOLVE + [CH, CH + "/Power", MGR] + collections)
        self.assertEqual(ctx.budgets, [("bmc_power_policy", checks._BUDGET_POWER_POLICY)])
        self.assertEqual(
            {
                family: report["strategy"]
                for family, report in result["context"]["collections"].items()
            },
            dict.fromkeys(("controls", "scheduled_power_actions", "watchdogs", "jobs"), "expand"),
        )
        self.assertEqual(set(result["raw"]), {CH + "/Power"} | set(collections))
        self.assertNotIn("@odata.etag", json.dumps(result["raw"]))
        # after bmc_power (the same Power read) and bmc_system (the Manager): the collections only
        ctx = _FakeCtx(self._payloads())
        checks._collect_power(ctx)
        checks._collect_system(ctx)
        before = len(ctx.gets)
        checks._collect_power_policy(ctx)
        self.assertEqual(ctx.gets[before:], collections)

    def test_the_expand_refusal_is_remembered_and_the_worst_walk_fits_the_budget(self):
        payloads = self._payloads(expand=False)
        del payloads[SYS]["Links"]  # the id resolution then costs its full five GETs
        payloads["/redfish/v1/Managers"] = {"Members": [{"@odata.id": MGR}]}
        payloads["/redfish/v1/Chassis"] = {"Members": [{"@odata.id": CH}]}
        ctx, result = self._collect(payloads, errors={self.CONTROLS + EXPAND: 501})
        # $expand is tried once, on the first collection read, and never again
        self.assertEqual([path for path in ctx.gets if "?" in path], [self.CONTROLS + EXPAND])
        collections = result["context"]["collections"]
        self.assertEqual(collections["controls"]["expand_refused"], "HTTP 501")
        self.assertEqual({report["strategy"] for report in collections.values()}, {"members"})
        # resolution 5, the Chassis, Power and the Manager, the Controls 1 + 1 + 2, the scheduled
        # actions 1 + 3, the watchdogs 1 + 4, the jobs 1 + 3
        self.assertEqual(len(ctx.gets), 5 + 3 + 4 + 4 + 5 + 4)
        self.assertLessEqual(len(ctx.gets), checks._BUDGET_POWER_POLICY)
        expanded = self._collect(self._payloads())[1]
        self.assertEqual(result["normalized"], expanded["normalized"])
        self.assertEqual(result["context"]["jobs"], expanded["context"]["jobs"])

    def test_a_walk_the_budget_cannot_cover_is_refused_before_its_first_member(self):
        payloads = self._payloads(expand=False)
        payloads[self.DOGS]["Members"] = [
            {"@odata.id": "%s/%d" % (self.DOGS, n)} for n in range(1, 31)
        ]
        ctx = _FakeCtx(payloads)
        with self.assertRaises(checks.CollectError) as caught:
            checks._collect_power_policy(ctx)
        self.assertIn("30 members to fetch", str(caught.exception))
        self.assertEqual(ctx.gets[-1], self.DOGS)  # the collection, and no member of it

    def test_linked_collections_that_answer_404_fail_and_unlinked_ones_cost_nothing(self):
        for path in (self.CONTROLS, self.SPA, self.DOGS):
            payloads = self._payloads(expand=False)
            del payloads[path]
            with self.assertRaises(checks.CollectError) as caught:
                checks._collect_power_policy(_FakeCtx(payloads))
            self.assertIn("%s is linked but answered 404" % (path,), str(caught.exception))
        payloads = self._payloads()
        del payloads[CH]["Controls"]
        del payloads[SYS]["Oem"]["Lenovo"]["ScheduledPowerActions"]
        del payloads[MGR]["Oem"]["Lenovo"]["Watchdogs"]
        del payloads["/redfish/v1/"]["JobService"]
        ctx, result = self._collect(payloads)
        self.assertEqual(ctx.gets, RESOLVE + [CH, CH + "/Power", MGR])
        self.assertFalse([key for key in result["normalized"] if "|" in key])
        reports = result["context"]["collections"].values()
        self.assertEqual({report["resource"] for report in reports}, {None})
        self.assertIsNone(result["context"]["jobs"])
        # the Jobs path is the linked JobService's mandated child: a 404 there is "not served"
        payloads = self._payloads(expand=False)
        del payloads[self.JOBS]
        _ctx, result = self._collect(payloads)
        self.assertIsNone(result["context"]["jobs"])
        self.assertEqual(result["context"]["collections"]["jobs"]["strategy"], "absent")

    def test_empty_collections_are_an_empty_family_never_absence(self):
        payloads = self._payloads()
        for path, _name in self.COLLECTIONS:
            payloads[path + EXPAND] = {"@odata.id": path, "Members": [], "Members@odata.count": 0}
        _ctx, result = self._collect(payloads)
        view, context = result["normalized"], result["context"]
        self.assertFalse([key for key in view if "|" in key])
        self.assertEqual({report["members"] for report in context["collections"].values()}, {0})
        self.assertEqual(
            (context["jobs"], context["watchdog_expired"], context["control_readings"]),
            ({}, {}, {}),
        )
        self.assertEqual(view["power_limit_w"], 450)  # the scalars stand

    def test_other_vendors_get_the_dmtf_reads_and_no_lenovo_scalar_or_row(self):
        payloads = self._payloads()
        payloads["/redfish/v1/"]["Vendor"] = "Contoso"
        ctx, result = self._collect(payloads)
        view, context = result["normalized"], result["context"]
        # no Manager read and no Lenovo path: the Controls and the JobService's jobs only
        self.assertEqual(
            ctx.gets,
            RESOLVE + [CH, CH + "/Power", self.CONTROLS + EXPAND, self.JOBS + EXPAND],
        )
        for field in self.LENOVO_SCALARS:
            self.assertIsNone(view[field], field)  # although the payloads carry Oem.Lenovo
        self.assertEqual((view["power_restore_policy"], view["power_limit_w"]), ("LastState", 450))
        self.assertEqual(
            [key for key in view if "|" in key], ["control|IntakeTemperature", "control|PowerLimit"]
        )
        self.assertEqual(sorted(context["jobs"]), ["PowerOff", "PowerOn", "Restart"])
        self.assertIn("no Contoso mapping", context["unmapped"])
        self.assertIsNone(context["redundancy_member"])
        self.assertIsNone(context["collections"]["watchdogs"]["resource"])

    def test_dell_shaped_paths_are_resolved_never_assumed(self):
        dell = "System.Embedded.1"

        def dellify(text):
            text = text.replace(SYS, "/redfish/v1/Systems/" + dell)
            text = text.replace(MGR, "/redfish/v1/Managers/iDRAC.Embedded.1")
            return text.replace(CH, "/redfish/v1/Chassis/" + dell)

        payloads = {
            dellify(path): json.loads(dellify(json.dumps(body)))
            for path, body in self._payloads().items()
        }
        payloads["/redfish/v1/"]["Vendor"] = "Dell"
        ctx, result = self._collect(payloads)
        for path in ctx.gets:
            for lenovo_member in (SYS, MGR, CH):
                resource = path.partition("?")[0]
                self.assertFalse(
                    resource == lenovo_member or resource.startswith(lenovo_member + "/"), path
                )
        self.assertEqual(result["context"]["resolution"]["chassis"], "/redfish/v1/Chassis/" + dell)
        self.assertEqual(result["normalized"]["control|PowerLimit"]["set_point"], 450)
        self.assertEqual(result["normalized"]["power_limit_w"], 450)

    def test_the_lenovo_flags_come_from_the_power_subsystem_where_no_power_is_served(self):
        payloads = self._payloads()
        del payloads[CH]["Power"]
        del payloads[CH + "/Power"]
        payloads[CH]["PowerSubsystem"] = {"@odata.id": CH + "/PowerSubsystem"}
        payloads[CH + "/PowerSubsystem"] = _fx("xcc_chassis_powersubsystem_lab.json")
        _ctx, result = self._collect(payloads)
        view, context = result["normalized"], result["context"]
        self.assertEqual(
            (view["wake_on_lan"], view["power_on_permission"], view["local_power_control"]),
            (True, True, True),
        )
        self.assertEqual(context["lenovo_capabilities_source"], "PowerSubsystem Oem.Lenovo")
        self.assertEqual(context["power_subsystem_resource"], CH + "/PowerSubsystem")
        self.assertIsNone(context["power_resource"])
        self.assertIsNone(view["power_limit_w"])  # the cap is the PowerLimit control's there
        self.assertIn(CH + "/PowerSubsystem", result["raw"])
        # only Lenovo's flags come from there: another vendor never reads it
        payloads["/redfish/v1/"]["Vendor"] = "Contoso"
        ctx, _result = self._collect(payloads)
        self.assertNotIn(CH + "/PowerSubsystem", ctx.gets)
        # a linked subsystem that answers 404 fails, and so does a linked Power that does
        del payloads["/redfish/v1/"]["Vendor"]
        del payloads[CH + "/PowerSubsystem"]
        with self.assertRaises(checks.CollectError):
            checks._collect_power_policy(_FakeCtx(payloads))
        payloads = self._payloads()
        del payloads[CH + "/Power"]
        with self.assertRaises(checks.CollectError) as caught:
            checks._collect_power_policy(_FakeCtx(payloads))
        self.assertIn("links %s but it answered 404" % (CH + "/Power",), str(caught.exception))

    def test_job_payload_text_never_reaches_the_trace_or_raw(self):
        payloads = self._payloads()
        job = payloads[self.JOBS + EXPAND]["Members"][0]
        job.update(
            HidePayload=False,
            CreatedBy="jane",
            Payload={
                "HttpHeaders": ["Authorization: Basic c2VjcmV0LXRva2Vu", "X-Request: power"],
                "HttpOperation": "POST",
                "JsonBody": '{"ResetType": "ForceOff", "Password": "hunter2"}',
                "TargetUri": SYS + "/Actions/ComputerSystem.Reset",
            },
            Messages=[{"Message": "Power Off schedule set by user erin.", "MessageArgs": ["erin"]}],
        )
        ctx, result = self._collect(payloads)
        self.assertIn((self.JOBS + EXPAND, "_redact_task_page"), ctx.redacted)
        text = json.dumps(result)
        for secret in ("c2VjcmV0LXRva2Vu", "X-Request", "hunter2", "ForceOff", "jane", "erin"):
            self.assertNotIn(secret, text, secret)
        raw_job = result["raw"][self.JOBS + EXPAND]["Members"][0]
        payload = raw_job["Payload"]
        self.assertEqual(payload["HttpHeaders"], [checks._SCRUBBED, checks._SCRUBBED])
        self.assertEqual(payload["JsonBody"], checks._SCRUBBED)
        self.assertEqual(
            (payload["HttpOperation"], payload["TargetUri"]),
            ("POST", SYS + "/Actions/ComputerSystem.Reset"),
        )
        self.assertEqual(
            raw_job["Messages"][0]["Message"], "Power Off schedule set by user ***scrubbed***."
        )
        # the collection page and a member read on its own alike, and idempotent
        page = checks._redact_task_page(payloads[self.JOBS + EXPAND])
        self.assertEqual(checks._redact_task_page(page), page)
        self.assertEqual(checks._redact_task_page(job)["Payload"]["JsonBody"], checks._SCRUBBED)
        # every other read of the check passes the family's scrubber
        self.assertEqual(
            {name for path, name in ctx.redacted if path != self.JOBS + EXPAND},
            {"_scrub_payload"},
        )

    def test_nothing_served_is_not_present_and_a_served_empty_family_is_measured(self):
        payloads = _base_payloads()  # the hand-built System carries neither policy leaf
        del payloads[CH]["Power"]
        del payloads[CH + "/Power"]
        with self.assertRaises(registry.SkipCheck) as caught:
            checks._collect_power_policy(_FakeCtx(payloads))
        self.assertIn("nothing to key", str(caught.exception))
        payloads[CH]["Controls"] = {"@odata.id": self.CONTROLS}
        payloads[self.CONTROLS + EXPAND] = {"@odata.id": self.CONTROLS, "Members": []}
        result = checks._collect_power_policy(_FakeCtx(payloads))
        self.assertTrue(result["normalized"])  # every scalar is present ...
        self.assertTrue(all(value is None for value in result["normalized"].values()))  # ... null
        self.assertEqual(result["context"]["collections"]["controls"]["members"], 0)

    def test_links_into_actions_are_refused(self):
        for mutate in (
            lambda p: p[CH].update(Controls={"@odata.id": CH + "/Actions/Oem/Controls"}),
            lambda p: p[MGR]["Oem"]["Lenovo"].update(
                Watchdogs={"@odata.id": MGR + "/Actions/Oem/Watchdogs"}
            ),
            lambda p: p["/redfish/v1/"].update(
                JobService={"@odata.id": "/redfish/v1/JobService/Actions/Oem"}
            ),
        ):
            payloads = self._payloads()
            mutate(payloads)
            with self.assertRaises(checks.CollectError):
                checks._collect_power_policy(_FakeCtx(payloads))

    def test_the_same_capture_twice_diffs_to_nothing_and_an_activated_slot_is_one_change(self):
        compare = registry.CHECKS["bmc_power_policy"].compare
        self.assertEqual(compare, {"mode": "equality_set"})
        diff_check = _loader.diffcore.diff_check
        pre = self._collect(self._payloads())[1]["normalized"]
        payloads = self._payloads()
        # what moves on its own moves: readings, set-point times, expired flags, job states
        power_limit = payloads[self.CONTROLS + EXPAND]["Members"][0]
        power_limit["Sensor"]["Reading"] = 480
        power_limit["SetPointUpdateTime"] = "2026-09-29T01:02:03+00:00"
        payloads[self.DOGS + EXPAND]["Members"][3]["TimerExpired"] = True
        payloads[self.JOBS + EXPAND]["Members"][1]["JobState"] = "Running"
        settings = payloads[CH + "/Power"]["Redundancy"][0]["Oem"]["Lenovo"]
        settings["PowerRedundancySettings"]["EstimatedUsage"] = "<placeholder:EstimatedUsage-2>"
        post = self._collect(payloads)[1]
        self.assertEqual(diff_check(pre, post["normalized"], compare)["result"], "pass")
        self.assertIs(post["context"]["watchdog_expired"]["watchdog|4"], True)
        self.assertEqual(post["context"]["jobs"]["PowerOn"]["state"], "Running")
        # a scheduled power action activated for 03:30: one row, two changed fields
        payloads[self.SPA + EXPAND]["Members"][1].update(Activated=True, Time="03:30")
        diff = diff_check(pre, self._collect(payloads)[1]["normalized"], compare)
        self.assertEqual(
            [(row["key"], row["field"], row["old"], row["new"]) for row in diff["changed"]],
            [("sched|2", "activated", False, True), ("sched|2", "time", "00:00", "03:30")],
        )

    def test_registration(self):
        check = registry.CHECKS["bmc_power_policy"]
        self.assertEqual((check.platform, check.tier), ("bmc", 1))
        self.assertIs(check.collector, checks._collect_power_policy)
        self.assertNotIn(registry.EMPTY_OK_TAG, check.tags)  # its scalars are always present
        self.assertTrue(registry.SEMANTICS["bmc_power_policy"].endswith(registry._BMC_RESOLUTION))
        self.assertLessEqual(
            checks._BUDGET_POWER_POLICY, _loader.constants.REDFISH_MAX_CHECK_BUDGET
        )


# --- bmc_network_adapters -----------------------------------------------------
# A hand-built adapter tree (tests/fixtures/xcc_network_adapters_*.json): the DMTF
# NetworkAdapter / Port / NetworkPort / NetworkDeviceFunction vocabulary and the
# Lenovo OEM leaves the lab XCC serves, every value invented (MACs from the IANA
# documentation range). slot-1 links Ports with a NetworkPorts twin and carries
# SR-IOV, a boot mode and iSCSI boot credentials; ob-1 links NetworkPorts only,
# the deprecated schema older firmware serves. The real payloads are pinned in
# test_lab_fixtures.TestBmcLabNetworkAdapters.

NA = CH + "/NetworkAdapters"
_NETWORK_ADAPTER_FIXTURES = (
    "xcc_network_adapters_expanded.json",
    "xcc_network_adapters_slot_1_ports_expanded.json",
    "xcc_network_adapters_slot_1_networkports_expanded.json",
    "xcc_network_adapters_slot_1_networkdevicefunctions_expanded.json",
    "xcc_network_adapters_ob_1_networkports_expanded.json",
    "xcc_network_adapters_ob_1_networkdevicefunctions_expanded.json",
)


def _network_adapter_payloads():
    """The hand-built adapter tree at its own paths: $expand forms, plain forms and members."""
    payloads = {}
    for name in _NETWORK_ADAPTER_FIXTURES:
        expanded = _fx(name)
        payloads[expanded["@odata.id"] + EXPAND] = expanded
        plain, members = _split_collection(expanded)
        payloads[expanded["@odata.id"]] = plain
        for member_path, member in members.items():
            payloads.setdefault(member_path, member)
    return payloads


class TestNetworkAdapters(unittest.TestCase):
    """bmc_network_adapters on the hand-built tree: both port schemas, the functions, the joins."""

    SLOT = NA + "/slot-1"
    OB = NA + "/ob-1"

    def _run(self, payloads=None, **kwargs):
        ctx = _FakeCtx(_base_payloads() if payloads is None else payloads, **kwargs)
        return checks._collect_network_adapters(ctx), ctx

    def test_rows_from_both_port_schemas_carry_every_field(self):
        view = self._run()[0]["normalized"]
        self.assertEqual(
            sorted(view),
            [
                "adapter|ob-1",
                "adapter|slot-1",
                "netfn|ob-1|1.1",
                "netfn|slot-1|1.1",
                "netfn|slot-1|2.1",
                "port|ob-1|1",
                "port|slot-1|1",
                "port|slot-1|2",
            ],
        )
        self.assertEqual(
            view["adapter|slot-1"],
            {
                "manufacturer": "Contoso",
                "model": "25GbE 2-port SFP28 adapter",
                "serial": "HBNA00000001",
                "part_number": "HBNA-PN-0001",
                "sku": "HBNA-SKU-0001",
                "firmware_package_version": "26.36.1010",
                "location": "PCIe 1",
                "pcie_devices": ["slot_1"],
                "port_count": 2,
                "function_count": 2,
                "controller_port_count": 2,
                "controller_function_count": 2,
                "npar_enabled": False,
                "lldp_enabled": True,
                "health": "OK",
                "state": "Enabled",
            },
        )
        onboard = view["adapter|ob-1"]
        self.assertEqual((onboard["model"], onboard["sku"]), ("N/A", None))  # 'N/A' kept, '' null
        self.assertEqual((onboard["npar_enabled"], onboard["lldp_enabled"]), (None, None))
        # a Ports row, in the current schema's words (the port number is Lenovo's OEM leaf)
        self.assertEqual(
            view["port|slot-1|1"],
            {
                "link_status": "LinkUp",
                "physical_port_number": "1",
                "port_id": "P1",
                "active_link_technology": "Ethernet",
                "max_speed_gbps": 25,
                "capable_speeds_gbps": [10, 25],
                "autoneg": True,
                "autoneg_capable": True,
                "flow_control_configuration": "TX_RX",
                "lldp_enabled": True,
                "health": "OK",
                "state": "Enabled",
            },
        )
        second = view["port|slot-1|2"]
        self.assertEqual(
            (second["link_status"], second["autoneg"], second["flow_control_configuration"]),
            ("LinkDown", False, "None"),  # the enum member None, verbatim
        )
        # a NetworkPorts row where no Ports is linked: the same fields, the Port-only ones null
        self.assertEqual(
            view["port|ob-1|1"],
            {
                "link_status": "Up",
                "physical_port_number": "1",
                "port_id": None,
                "active_link_technology": "Ethernet",
                "max_speed_gbps": None,
                "capable_speeds_gbps": [0.1, 1.0],  # CapableLinkSpeedMbps / 1000, sorted
                "autoneg": None,  # the NetworkPort schema serves the capability only
                "autoneg_capable": True,
                "flow_control_configuration": "None",
                "lldp_enabled": None,
                "health": "OK",
                "state": "Enabled",
            },
        )
        for prefix in ("adapter|", "port|", "netfn|"):
            shapes = {tuple(sorted(row)) for key, row in view.items() if key.startswith(prefix)}
            self.assertEqual(len(shapes), 1, prefix)
        self.assertNotIn("", [value for row in view.values() for value in row.values()])

    def test_network_port_speeds_in_either_spelling(self):
        # NetworkPort v1_0 served one LinkSpeedMbps per capability; v1_2 a CapableLinkSpeedMbps list
        row = checks._network_adapters_network_port
        older = {"SupportedLinkCapabilities": [{"LinkSpeedMbps": 10000}, {"LinkSpeedMbps": 1000}]}
        self.assertEqual(row(older)["capable_speeds_gbps"], [1.0, 10.0])
        speeds = checks._network_adapters_link_speeds_mbps
        self.assertEqual(speeds(older["SupportedLinkCapabilities"]), [1000, 10000])
        self.assertEqual(speeds([{"CapableLinkSpeedMbps": []}]), [])  # served, empty
        self.assertIsNone(speeds([{"AutoSpeedNegotiation": True}]))  # not served
        self.assertIsNone(row({})["capable_speeds_gbps"])
        self.assertIsNone(row({})["autoneg_capable"])

    def test_function_rows_sriov_boot_mode_and_joins(self):
        view = self._run()[0]["normalized"]
        self.assertEqual(
            view["netfn|slot-1|1.1"],
            {
                "net_dev_func_type": "Ethernet",
                "permanent_mac": "00:00:5e:00:53:01",  # lower-cased for the pnic join
                "device_enabled": True,
                "boot_mode": "PXE",
                "virtual_functions_enabled": True,
                "max_virtual_functions": 64,
                "assigned_port": "1",
                "ethernet_interfaces": ["NIC5"],
                "pcie_function": "slot_1.00",
                "health": "OK",
                "state": "Enabled",
            },
        )
        second = view["netfn|slot-1|2.1"]
        self.assertEqual(
            (second["boot_mode"], second["virtual_functions_enabled"], second["assigned_port"]),
            ("iSCSI", False, "2"),
        )
        self.assertEqual(second["ethernet_interfaces"], ["NIC6"])  # the Links array form
        onboard = view["netfn|ob-1|1.1"]
        self.assertEqual(
            (onboard["assigned_port"], onboard["ethernet_interfaces"], onboard["pcie_function"]),
            ("1", None, "ob_1.00"),  # the hand-built inventory's pciefn|ob_1|ob_1.00
        )
        for field in ("boot_mode", "virtual_functions_enabled", "max_virtual_functions"):
            self.assertIsNone(onboard[field], field)  # not served: null, never assumed

    def test_the_assigned_port_leaf_follows_the_port_rows(self):
        functions = self._run()[0]["context"]["functions"]
        self.assertEqual(
            functions["netfn|slot-1|1.1"]["assigned_port_source"],
            "Links.PhysicalNetworkPortAssignment",
        )
        # 2.1 serves only the deprecated root NetworkPort link: that family answers
        self.assertEqual(
            functions["netfn|slot-1|2.1"]["assigned_port_source"], "PhysicalPortAssignment"
        )
        self.assertEqual(
            functions["netfn|ob-1|1.1"]["assigned_port_source"], "Links.PhysicalPortAssignment"
        )
        # the current MAC and MTU can follow the host's configuration: context only
        self.assertEqual(
            (functions["netfn|slot-1|2.1"]["mac"], functions["netfn|slot-1|2.1"]["mtu"]),
            ("00:00:5e:00:53:22", 1500),
        )
        both = {
            "Links": {
                "PhysicalNetworkPortAssignment": {"@odata.id": NA + "/x/Ports/7"},
                "PhysicalPortAssignment": {"@odata.id": NA + "/x/NetworkPorts/8"},
            },
            "PhysicalNetworkPortAssignment": {"@odata.id": NA + "/x/Ports/9"},
        }
        assigned = checks._network_adapters_assigned_port
        self.assertEqual(assigned(both), ("7", "Links.PhysicalNetworkPortAssignment"))
        self.assertEqual(assigned(both, False), ("8", "Links.PhysicalPortAssignment"))
        del both["Links"]
        self.assertEqual(assigned(both, False), ("9", "PhysicalNetworkPortAssignment"))
        self.assertEqual(assigned({}), (None, None))
        with self.assertRaises(checks.CollectError):  # a link into Actions is never trusted
            assigned({"Links": {"PhysicalNetworkPortAssignment": {"@odata.id": NA + "/Actions/x"}}})

    def test_one_expand_get_per_collection_and_the_twin_rides_in_context(self):
        result, ctx = self._run()
        self.assertEqual(
            ctx.gets,
            RESOLVE
            + [CH, NA + EXPAND]
            + [self.SLOT + name + EXPAND for name in ("/Ports", "/NetworkPorts")]
            + [self.SLOT + "/NetworkDeviceFunctions" + EXPAND]
            + [self.OB + name + EXPAND for name in ("/NetworkPorts", "/NetworkDeviceFunctions")],
        )
        context = result["context"]
        # the NetworkPorts twin of a Ports collection: the same fact in the older words
        self.assertEqual(result["normalized"]["port|slot-1|1"]["link_status"], "LinkUp")
        self.assertEqual(
            context["network_ports"],
            {
                "slot-1|1": {
                    "link_status": "Up",
                    "current_link_speed_mbps": 25000,
                    "capable_link_speeds_mbps": [10000, 25000],
                    "physical_port_number": "1",
                    "port_maximum_mtu": 9600,
                    "port_max_speed_bps": 25000000000,
                    "physical_port_mac": "00005E005301",
                },
                "slot-1|2": {
                    "link_status": "Down",
                    "current_link_speed_mbps": None,
                    "capable_link_speeds_mbps": [10000, 25000],
                    "physical_port_number": "2",
                    "port_maximum_mtu": 9600,
                    "port_max_speed_bps": 25000000000,
                    "physical_port_mac": "00005E005302",
                },
            },
        )  # ob-1's NetworkPorts are its rows, never a twin
        self.assertEqual(
            context["ports"]["port|slot-1|1"],
            {
                "current_speed_gbps": 25,
                "current_link_speed_mbps": None,
                "associated_macs": ["00:00:5e:00:53:01"],
                "port_maximum_mtu": 9600,
                "port_max_speed_bps": None,
                "physical_port_mac": "00005E005301",
            },
        )
        onboard = context["ports"]["port|ob-1|1"]
        self.assertEqual(
            (onboard["current_link_speed_mbps"], onboard["port_max_speed_bps"]), (1000, 1000000000)
        )
        self.assertEqual(onboard["associated_macs"], ["00005e005311"])  # as served, lower-cased
        collections = context["collections"]
        self.assertEqual(
            collections["slot-1"]["ports"],
            {
                "source": self.SLOT + "/Ports",
                "strategy": "expand",
                "members": 2,
                "collection": "Ports",
            },
        )
        self.assertEqual(collections["ob-1"]["ports"]["collection"], "NetworkPorts")
        self.assertIsNone(collections["ob-1"]["network_ports_twin"])
        self.assertEqual(context["adapters_collection"]["strategy"], "expand")
        self.assertEqual(context["adapters_source"], NA)
        self.assertEqual(context["host_power_state"], "On")
        self.assertEqual(
            (context["adapters_without_ports"], context["adapters_without_functions"]), ([], [])
        )
        self.assertEqual(context["resolution"]["chassis"], CH)
        self.assertEqual(set(result["raw"]), {path for path in ctx.gets if path.startswith(NA)})

    def test_an_expand_refusal_is_paid_for_once(self):
        expected = self._run()[0]["normalized"]
        result, ctx = self._run(errors={NA + EXPAND: 501})
        self.assertEqual([path for path in ctx.gets if path.endswith(EXPAND)], [NA + EXPAND])
        self.assertEqual(result["normalized"], expected)
        context = result["context"]
        self.assertEqual(context["adapters_collection"]["expand_refused"], "HTTP 501")
        self.assertEqual(
            {
                entry["strategy"]
                for report in context["collections"].values()
                for entry in report.values()
                if entry is not None
            },
            {"members"},
        )
        self.assertIn(self.SLOT + "/NetworkDeviceFunctions/2.1", ctx.gets)
        # the first sub-collection that refuses turns $expand off for every later read
        result, ctx = self._run(errors={self.SLOT + "/Ports" + EXPAND: 501})
        self.assertEqual(
            [path for path in ctx.gets if path.endswith(EXPAND)],
            [NA + EXPAND, self.SLOT + "/Ports" + EXPAND],
        )
        self.assertEqual(result["normalized"], expected)
        self.assertEqual(
            result["context"]["collections"]["slot-1"]["ports"]["expand_refused"], "HTTP 501"
        )
        # an $expand answered with bare links is a refusal too
        payloads = _base_payloads()
        payloads[self.SLOT + "/NetworkPorts" + EXPAND] = payloads[self.SLOT + "/NetworkPorts"]
        result, ctx = self._run(payloads)
        self.assertEqual(
            result["context"]["collections"]["slot-1"]["network_ports_twin"]["expand_refused"],
            "members returned as links",
        )
        self.assertNotIn(self.SLOT + "/NetworkDeviceFunctions" + EXPAND, ctx.gets)
        self.assertEqual(result["normalized"], expected)

    def test_without_expand_support_every_collection_is_walked(self):
        expected = self._run()[0]["normalized"]
        payloads = _without_expand(_base_payloads())
        payloads["/redfish/v1/"]["ProtocolFeaturesSupported"]["ExpandQuery"]["ExpandAll"] = False
        payloads["/redfish/v1/"]["ProtocolFeaturesSupported"]["ExpandQuery"]["NoLinks"] = False
        del payloads[SYS]["Links"]  # the id resolution then costs its full five GETs
        payloads["/redfish/v1/Managers"] = {"Members": [{"@odata.id": MGR}]}
        payloads["/redfish/v1/Chassis"] = {"Members": [{"@odata.id": CH}]}
        result, ctx = self._run(payloads)
        self.assertFalse([path for path in ctx.gets if EXPAND in path])
        self.assertEqual(result["normalized"], expected)
        # resolution 5, the Chassis, the adapters 1 + 2, slot-1 3 + 6, ob-1 2 + 2
        self.assertEqual(len(ctx.gets), 5 + 1 + 3 + 9 + 4)
        self.assertLessEqual(len(ctx.gets), checks._BUDGET_NETWORK_ADAPTERS)

    def test_an_empty_adapter_collection_is_unmeasured(self):
        payloads = _base_payloads()
        payloads[NA + EXPAND]["Members"] = []
        payloads[SYS]["PowerState"] = "Off"
        with self.assertRaises(checks.CollectError) as caught:
            self._run(payloads)
        message = str(caught.exception)
        self.assertIn(NA + " answered with zero members (host PowerState Off)", message)
        self.assertIn("unmeasured", message)

    def test_absent_linked_and_unlinked_collections(self):
        payloads = {path: body for path, body in _base_payloads().items() if NA not in path}
        with self.assertRaises(checks.CollectError) as caught:  # the Chassis links it
            self._run(payloads)
        self.assertIn("the Chassis links %s but it answered 404" % (NA,), str(caught.exception))
        del payloads[CH]["NetworkAdapters"]
        with self.assertRaises(registry.SkipCheck) as caught:
            self._run(payloads)
        self.assertIn("the Chassis links no NetworkAdapters collection", str(caught.exception))
        # served but not linked: read at its DMTF path
        payloads = _base_payloads()
        del payloads[CH]["NetworkAdapters"]
        result = self._run(payloads)[0]
        self.assertEqual(result["context"]["adapters_source"], NA)
        self.assertIn("port|slot-1|1", result["normalized"])

    def test_an_adapter_without_sideband_is_keyed_with_zero_rows(self):
        # An add-in card the BMC has no sideband path to: listed, identity '', no ports,
        # no functions, and its controller declares none — recorded, never refused.
        payloads = _base_payloads()
        base = NA + "/slot-2"
        payloads[NA + EXPAND]["Members"].append(
            {
                "@odata.id": base,
                "Id": "slot-2",
                "Name": "Slot 2",
                "Manufacturer": "",
                "Model": "",
                "SerialNumber": "",
                "PartNumber": "",
                "SKU": "",
                "Status": {"State": "Enabled", "Health": "OK"},
                "Controllers": [
                    {
                        "FirmwarePackageVersion": "",
                        "ControllerCapabilities": {
                            "NetworkPortCount": 0,
                            "NetworkDeviceFunctionCount": 0,
                        },
                        "Links": {
                            "PCIeDevices": [{"@odata.id": CH + "/PCIeDevices/slot_2"}],
                            "Ports": [],
                            "NetworkPorts": [],
                            "NetworkDeviceFunctions": [],
                        },
                    }
                ],
                "Ports": {"@odata.id": base + "/Ports"},
                "NetworkPorts": {"@odata.id": base + "/NetworkPorts"},
                "NetworkDeviceFunctions": {"@odata.id": base + "/NetworkDeviceFunctions"},
            }
        )
        for name in ("/Ports", "/NetworkPorts", "/NetworkDeviceFunctions"):
            payloads[base + name + EXPAND] = {"@odata.id": base + name, "Members": []}
        result = self._run(payloads)[0]
        row = result["normalized"]["adapter|slot-2"]
        self.assertEqual(
            (row["port_count"], row["function_count"], row["controller_port_count"]), (0, 0, 0)
        )
        for field in ("manufacturer", "model", "serial", "part_number", "sku"):
            self.assertIsNone(row[field], field)  # served '', read null
        self.assertIsNone(row["firmware_package_version"])
        self.assertEqual(row["pcie_devices"], ["slot_2"])
        self.assertFalse([key for key in result["normalized"] if "|slot-2|" in key])
        context = result["context"]
        self.assertEqual(context["adapters_without_ports"], ["slot-2"])
        self.assertEqual(context["adapters_without_functions"], ["slot-2"])
        self.assertEqual(context["collections"]["slot-2"]["functions"]["members"], 0)
        # an adapter that links no collection at all: counts null, named the same way
        payloads[NA + EXPAND]["Members"][-1] = {"@odata.id": base, "Id": "slot-2"}
        result = self._run(payloads)[0]
        row = result["normalized"]["adapter|slot-2"]
        self.assertEqual((row["port_count"], row["function_count"]), (None, None))
        self.assertEqual(
            result["context"]["collections"]["slot-2"],
            {"ports": None, "network_ports_twin": None, "functions": None},
        )
        self.assertEqual(result["context"]["adapters_without_ports"], ["slot-2"])

    def test_declared_ports_or_functions_read_empty_or_404_are_unmeasured(self):
        for collection, declared in (
            ("/Ports", "Ports empty, its controllers declare ports"),
            ("/NetworkDeviceFunctions", "NetworkDeviceFunctions empty, its controllers declare"),
        ):
            payloads = _base_payloads()
            payloads[self.SLOT + collection + EXPAND]["Members"] = []
            with self.assertRaises(checks.CollectError) as caught:
                self._run(payloads)
            message = str(caught.exception)
            self.assertIn("slot-1 (" + declared, message)
            self.assertIn("(host PowerState On)", message)
            self.assertIn("unmeasured", message)
        # the controller's links alone are a declaration too
        payloads = _base_payloads()
        controller = payloads[NA + EXPAND]["Members"][0]["Controllers"][0]
        del controller["ControllerCapabilities"]
        payloads[self.SLOT + "/Ports" + EXPAND]["Members"] = []
        with self.assertRaises(checks.CollectError):
            self._run(payloads)
        # ... and so is a NetworkPorts twin that lists the ports the Ports collection lacks
        del controller["Links"]
        with self.assertRaises(checks.CollectError) as caught:
            self._run(payloads)
        self.assertIn("slot-1 (Ports empty while its NetworkPorts list 2)", str(caught.exception))
        payloads[self.SLOT + "/NetworkPorts" + EXPAND]["Members"] = []
        result = self._run(payloads)[0]  # nothing says otherwise: zero rows, named
        self.assertEqual(result["normalized"]["adapter|slot-1"]["port_count"], 0)
        self.assertEqual(result["context"]["adapters_without_ports"], ["slot-1"])
        # a linked collection answering 404 is a failed read, never "no functions"
        payloads = {
            path: body
            for path, body in _base_payloads().items()
            if not path.startswith(self.OB + "/NetworkDeviceFunctions")
        }
        with self.assertRaises(checks.CollectError) as caught:
            self._run(payloads)
        self.assertIn("ob-1 (NetworkDeviceFunctions answered 404)", str(caught.exception))

    def test_a_missing_twin_leaves_the_rows_alone(self):
        expected = self._run()[0]["normalized"]
        payloads = {
            path: body
            for path, body in _base_payloads().items()
            if not path.startswith(self.SLOT + "/NetworkPorts")
        }
        result = self._run(payloads)[0]
        self.assertEqual(result["normalized"], expected)
        twin = result["context"]["collections"]["slot-1"]["network_ports_twin"]
        self.assertEqual((twin["strategy"], twin["members"]), ("absent", None))
        self.assertEqual(result["context"]["network_ports"], {})

    def test_a_tree_the_budget_cannot_cover_is_refused_before_any_port_is_read(self):
        payloads = _base_payloads()
        members = payloads[NA + EXPAND]["Members"]
        for index in range(12):
            adapter = copy.deepcopy(members[0])
            adapter_path = NA + "/extra-%d" % (index,)
            adapter.update({"@odata.id": adapter_path, "Id": "extra-%d" % (index,)})
            for name in ("Ports", "NetworkPorts", "NetworkDeviceFunctions"):
                adapter[name] = {"@odata.id": adapter_path + "/" + name}
            members.append(adapter)
        ctx = _FakeCtx(payloads)
        with self.assertRaises(checks.CollectError) as caught:
            checks._collect_network_adapters(ctx)
        self.assertIn("collections of 14 adapter(s) take at least 41 GET(s)", str(caught.exception))
        self.assertFalse([path for path in ctx.gets if path.startswith(NA + "/")])

    def test_eight_adapters_fit_even_when_this_check_pays_the_full_resolution(self):
        payloads = _base_payloads()
        del payloads[SYS]["Links"]
        payloads["/redfish/v1/Managers"] = {"Members": [{"@odata.id": MGR}]}
        payloads["/redfish/v1/Chassis"] = {"Members": [{"@odata.id": CH}]}
        members = payloads[NA + EXPAND]["Members"]
        del members[1]  # ob-1: keep slot-1's three collections, add seven more adapters
        for index in range(7):
            adapter_path = NA + "/extra-%d" % (index,)
            adapter = {"@odata.id": adapter_path, "Id": "extra-%d" % (index,)}
            for name in ("Ports", "NetworkPorts", "NetworkDeviceFunctions"):
                adapter[name] = {"@odata.id": adapter_path + "/" + name}
                payloads[adapter_path + "/" + name + EXPAND] = {"Members": []}
            members.append(adapter)
        result, ctx = self._run(payloads)
        self.assertEqual(len(ctx.gets), 5 + 1 + 1 + 8 * 3)
        self.assertLessEqual(len(ctx.gets), checks._BUDGET_NETWORK_ADAPTERS)
        self.assertEqual(
            len([key for key in result["normalized"] if key.startswith("adapter|")]), 8
        )

    def test_other_vendors_read_the_dmtf_leaves_only(self):
        payloads = _base_payloads()
        payloads["/redfish/v1/"] = dict(payloads["/redfish/v1/"], Vendor="Contoso")
        result, ctx = self._run(payloads)
        view, context = result["normalized"], result["context"]
        self.assertIsNone(view["port|slot-1|1"]["physical_port_number"])  # Lenovo's leaf
        self.assertEqual(view["port|slot-1|1"]["port_id"], "P1")
        self.assertEqual(view["port|ob-1|1"]["physical_port_number"], "1")  # a DMTF leaf there
        self.assertIsNone(context["ports"]["port|slot-1|1"]["physical_port_mac"])
        self.assertIsNone(context["network_ports"]["slot-1|1"]["port_max_speed_bps"])
        self.assertFalse([path for path in ctx.gets if "/Oem/" in path])
        lenovo = self._run()[0]["normalized"]
        for key, row in view.items():
            if not key.startswith("port|"):
                self.assertEqual(row, lenovo[key], key)

    def test_dell_shaped_paths_are_resolved_not_assumed(self):
        dell = "System.Embedded.1"

        def dellify(text):
            text = text.replace(SYS, "/redfish/v1/Systems/" + dell)
            text = text.replace(MGR, "/redfish/v1/Managers/iDRAC.Embedded.1")
            return text.replace(CH, "/redfish/v1/Chassis/" + dell)

        payloads = {
            dellify(path): json.loads(dellify(json.dumps(payload)))
            for path, payload in _base_payloads().items()
        }
        payloads["/redfish/v1/"] = dict(payloads["/redfish/v1/"], Vendor="Dell")
        payloads["/redfish/v1/Systems"] = {
            "Members": [{"@odata.id": "/redfish/v1/Systems/" + dell}]
        }
        payloads["/redfish/v1/Systems/" + dell]["Links"] = {
            "ManagedBy": [{"@odata.id": "/redfish/v1/Managers/iDRAC.Embedded.1"}],
            "Chassis": [{"@odata.id": "/redfish/v1/Chassis/" + dell}],
        }
        result, ctx = self._run(payloads)
        self.assertEqual(result["context"]["adapters_source"], dellify(NA))
        self.assertEqual(result["normalized"]["netfn|slot-1|1.1"]["assigned_port"], "1")
        self.assertEqual(len(result["normalized"]), 8)
        self.assertFalse(
            [path for path in ctx.gets if "/Chassis/1" in path or "/Systems/1" in path]
        )

    def test_iscsi_boot_credentials_never_reach_raw_rows_or_context(self):
        result = self._run()[0]
        text = json.dumps(result)
        for secret in ("hand-built-chap-secret", "hand-built-mutual-secret"):
            self.assertNotIn(secret, text)
        for user in ("hand-built-chap-user", "hand-built-mutual-user"):
            self.assertNotIn(user, text)
        functions = result["raw"][self.SLOT + "/NetworkDeviceFunctions" + EXPAND]["Members"]
        iscsi = functions[1]["iSCSIBoot"]
        self.assertEqual(
            (iscsi["CHAPSecret"], iscsi["CHAPUsername"], iscsi["MutualCHAPSecret"]),
            (checks._SCRUBBED,) * 3,
        )
        self.assertEqual(iscsi["PrimaryTargetIPAddress"], "192.0.2.62")  # a network fact, kept
        self.assertNotIn("Actions", json.dumps(result["raw"]))
        # emptiness survives the scrub
        empty = {"iSCSIBoot": {"CHAPSecret": None, "MutualCHAPUsername": ""}}
        self.assertEqual(checks._network_adapters_scrub_credentials(empty), empty)

    def test_stable_between_captures_and_a_lost_link_is_one_changed_field(self):
        compare = registry.CHECKS["bmc_network_adapters"].compare
        pre = self._run()[0]["normalized"]
        # readings and host-driven values move without a diff
        payloads = _base_payloads()
        ports = payloads[self.SLOT + "/Ports" + EXPAND]["Members"]
        ports[0]["CurrentSpeedGbps"] = 10
        functions = payloads[self.SLOT + "/NetworkDeviceFunctions" + EXPAND]["Members"]
        functions[1]["Ethernet"].update(MACAddress="00:00:5e:00:53:33", MTUSize=9000)
        post = self._run(payloads)[0]["normalized"]
        self.assertEqual(_loader.diffcore.diff_check(pre, post, compare)["result"], "pass")
        ports[0]["LinkStatus"] = "NoLink"
        post = self._run(payloads)[0]["normalized"]
        diff = _loader.diffcore.diff_check(pre, post, compare)
        self.assertEqual(
            [(row["key"], row["field"], row["old"], row["new"]) for row in diff["changed"]],
            [("port|slot-1|1", "link_status", "LinkUp", "NoLink")],
        )

    def test_registration_and_semantics(self):
        check = registry.CHECKS["bmc_network_adapters"]
        self.assertEqual((check.platform, check.tier), ("bmc", 1))
        self.assertEqual(check.compare, {"mode": "equality_set"})
        self.assertNotIn(registry.EMPTY_OK_TAG, check.tags)  # a healthy unit keys its adapters
        text = registry.SEMANTICS["bmc_network_adapters"]
        self.assertTrue(text.endswith(registry._BMC_RESOLUTION))
        for phrase in (
            "NoLink",
            "PhysicalNetworkPortAssignment",
            "adapters_without_ports",
            "vmware_pnics.mac",
            "10 x 2^30",
            "unmeasured",
        ):
            self.assertIn(phrase, text)
        self.assertLessEqual(
            checks._BUDGET_NETWORK_ADAPTERS, _loader.constants.REDFISH_MAX_CHECK_BUDGET
        )


class TestPcieSlots(unittest.TestCase):
    """bmc_pcie_slots: the DMTF PCIeSlots rows and Lenovo's slot table.

    xcc_pcie_slots_mixed.json (DMTF PCIeSlots) and xcc_pcie_slots_lenovo_expanded.json
    (LenovoSlot members) are HAND-BUILT from the schema vocabulary: the lab unit has one
    labelled, occupied slot and serves no SlotType/PCIeType/Lanes, so empty, unlabelled,
    repeated and bifurcated slots are invented here. The lab shapes are pinned in
    test_lab_fixtures.TestBmcLabPcieSlots.
    """

    SLOTS = CH + "/PCIeSlots"
    LENOVO = CH + "/Slots"  # where the hand-built Chassis links Oem.Lenovo.Slots
    SLOT_FIELDS = {
        "slot_type",
        "pcie_type",
        "lanes",
        "state",
        "health",
        "hot_pluggable",
        "location",
        "linked_devices",
    }
    LENOVO_FIELDS = {"name", "number", "connector_layout", "max_data_width", "supports_hot_plug"}

    def _payloads(self, expand=True, linked=True):
        payloads = _base_payloads()
        if linked:
            payloads[CH]["PCIeSlots"] = {"@odata.id": self.SLOTS}
        payloads[self.SLOTS] = _fx("xcc_pcie_slots_mixed.json")
        return payloads if expand else _without_expand(payloads)

    def _big_table(self, count):
        """No $expand, an unlinked System (the resolution's full five GETs), ``count`` slots."""
        payloads = self._payloads(expand=False)
        del payloads[SYS]["Links"]
        payloads["/redfish/v1/Managers"] = {"Members": [{"@odata.id": MGR}]}
        payloads["/redfish/v1/Chassis"] = {"Members": [{"@odata.id": CH}]}
        members = []
        for number in range(1, count + 1):
            link = self.LENOVO + "/%d" % (number,)
            members.append({"@odata.id": link})
            payloads[link] = {
                "@odata.id": link,
                "Id": str(number),
                "Name": "LenovoSlot",
                "Number": "Slot %d" % (number,),
                "ConnectorLayout": "PCI Express Gen 3 x8",
                "MaxDataWidth": "8x or x8",
                "SupportsHotPlug": False,
            }
        payloads[self.LENOVO] = {
            "@odata.id": self.LENOVO,
            "Members": members,
            "Members@odata.count": count,
        }
        return payloads

    def test_registered_tier_1_equality_set_never_empty_when_ok(self):
        check = registry.CHECKS["bmc_pcie_slots"]
        self.assertEqual((check.platform, check.tier), ("bmc", 1))
        self.assertEqual(check.compare, {"mode": "equality_set"})
        # an ok view always holds rows: an empty slot table is refused, never recorded
        self.assertNotIn(registry.EMPTY_OK_TAG, check.tags)
        semantics = registry.SEMANTICS["bmc_pcie_slots"]
        self.assertIn("unseated card", semantics)
        self.assertIn("vanishes from bmc_inventory", semantics)
        self.assertTrue(semantics.endswith(registry._BMC_RESOLUTION))
        self.assertLessEqual(checks._BUDGET_PCIE_SLOTS, _loader.constants.REDFISH_MAX_CHECK_BUDGET)

    def test_rows_keyed_by_label_else_position_every_field_present(self):
        view, context = checks._normalize_pcie_slots(_fx("xcc_pcie_slots_mixed.json"))
        # 'Riser 1' labels two slots: the position tells them apart; '' is no label
        self.assertEqual(
            sorted(view),
            ["slot|2", "slot|PCIe 1", "slot|PCIe 2", "slot|Riser 1|3", "slot|Riser 1|4"],
        )
        self.assertEqual(
            view["slot|PCIe 1"],
            {
                "slot_type": "FullLength",
                "pcie_type": "Gen4",
                "lanes": 16,
                "state": "Enabled",
                "health": "OK",
                "hot_pluggable": False,
                "location": "PCIe 1",
                "linked_devices": ["slot_1"],
            },
        )
        # an empty slot the firmware lists: Absent, no device, no health — still a row
        empty = view["slot|PCIe 2"]
        self.assertEqual(
            (empty["state"], empty["health"], empty["linked_devices"], empty["hot_pluggable"]),
            ("Absent", None, [], True),
        )
        # no link list served is null, never an empty list; no label is a null location
        self.assertIsNone(view["slot|2"]["linked_devices"])
        self.assertIsNone(view["slot|2"]["location"])
        self.assertIsNone(view["slot|2"]["hot_pluggable"])
        # a bifurcated riser slot holds two devices, sorted
        self.assertEqual(view["slot|Riser 1|3"]["linked_devices"], ["riser_1a", "riser_1b"])
        bare = view["slot|Riser 1|4"]
        self.assertEqual((bare["state"], bare["location"]), ("Absent", "Riser 1"))
        for field in ("slot_type", "pcie_type", "lanes", "health", "hot_pluggable"):
            self.assertIsNone(bare[field], field)
        for key, row in view.items():
            self.assertEqual(set(row), self.SLOT_FIELDS, key)
            self.assertNotIn("", row.values(), key)
        # occupied: Enabled AND a linked device ('slot|2' is Enabled without a link)
        self.assertEqual(
            context, {"slots_total": 5, "slots_occupied": 2, "lenovo_slots_total": None}
        )

    def test_a_label_spelling_another_slots_position_never_overwrites_it(self):
        view, _context = checks._normalize_pcie_slots(
            {
                "Slots": [
                    {"Location": {"PartLocation": {"ServiceLabel": "1"}}},
                    {"Status": {"State": "Absent"}},
                    None,  # not a slot: skipped, the positions stay the served ones
                    {"Location": {"PartLocation": {"ServiceLabel": "PCIe 3"}}},
                ]
            }
        )
        self.assertEqual(sorted(view), ["slot|1|0", "slot|1|1", "slot|PCIe 3"])

    def test_lenovo_rows_every_field_verbatim(self):
        members = _fx("xcc_pcie_slots_lenovo_expanded.json")["Members"]
        view, context = checks._normalize_pcie_slots(None, members)
        self.assertEqual(sorted(view), ["lenovo_slot|1", "lenovo_slot|2", "lenovo_slot|3"])
        self.assertEqual(
            view["lenovo_slot|2"],
            {
                "name": "LenovoSlot",
                "number": "Slot 2",
                "connector_layout": "PCI Express Gen 3 x8",
                "max_data_width": "8x or x8",
                "supports_hot_plug": True,
            },
        )
        self.assertIsNone(view["lenovo_slot|3"]["number"])  # '' reads None
        self.assertIsNone(view["lenovo_slot|3"]["supports_hot_plug"])  # not served
        for key, row in view.items():
            self.assertEqual(set(row), self.LENOVO_FIELDS, key)
        self.assertEqual(
            context, {"slots_total": None, "slots_occupied": None, "lenovo_slots_total": 3}
        )

    def test_collector_two_gets_beyond_the_chassis(self):
        ctx = _FakeCtx(self._payloads())
        result = checks._collect_pcie_slots(ctx)
        view, context = result["normalized"], result["context"]
        self.assertEqual(ctx.gets, RESOLVE + [CH, self.SLOTS, self.LENOVO + EXPAND])
        self.assertEqual(ctx.budgets, [("bmc_pcie_slots", checks._BUDGET_PCIE_SLOTS)])
        self.assertEqual(len([key for key in view if key.startswith("slot|")]), 5)
        self.assertEqual(len([key for key in view if key.startswith("lenovo_slot|")]), 3)
        self.assertEqual(
            (context["slots_total"], context["slots_occupied"], context["lenovo_slots_total"]),
            (5, 2, 3),
        )
        self.assertEqual(context["host_power_state"], "On")
        self.assertEqual(context["pcie_slots_source"], self.SLOTS)
        lenovo = context["lenovo_slots"]
        self.assertEqual(
            (lenovo["resource"], lenovo["strategy"], lenovo["members"], lenovo["note"]),
            (self.LENOVO, "expand", 3, None),
        )
        self.assertEqual(context["resolution"]["chassis"], CH)
        # raw: the two tables, keyed by the request sent, curated
        self.assertEqual(sorted(result["raw"]), [self.SLOTS, self.LENOVO + EXPAND])
        self.assertNotIn("@odata.etag", result["raw"][self.SLOTS])
        self.assertNotIn("@odata.etag", result["raw"][self.LENOVO + EXPAND]["Members"][0])
        self.assertEqual({name for _path, name in ctx.redacted}, {"_scrub_payload"})

    def test_an_unlinked_pcie_slots_is_read_at_the_schema_path_or_absent(self):
        ctx = _FakeCtx(self._payloads(linked=False))
        result = checks._collect_pcie_slots(ctx)
        self.assertEqual(ctx.gets, RESOLVE + [CH, self.SLOTS, self.LENOVO + EXPAND])
        self.assertEqual(result["context"]["pcie_slots_source"], self.SLOTS)
        payloads = self._payloads(linked=False)
        del payloads[self.SLOTS]
        result = checks._collect_pcie_slots(_FakeCtx(payloads))
        context = result["context"]
        self.assertIsNone(context["pcie_slots_source"])
        self.assertEqual((context["slots_total"], context["slots_occupied"]), (None, None))
        self.assertEqual(
            sorted(result["normalized"]), ["lenovo_slot|1", "lenovo_slot|2", "lenovo_slot|3"]
        )

    def test_the_table_is_walked_when_expand_is_not_honoured(self):
        ctx = _FakeCtx(self._payloads(expand=False))
        result = checks._collect_pcie_slots(ctx)
        members = [self.LENOVO + "/%d" % (number,) for number in (1, 2, 3)]
        self.assertEqual(
            ctx.gets, RESOLVE + [CH, self.SLOTS, self.LENOVO + EXPAND, self.LENOVO] + members
        )
        self.assertEqual(result["context"]["lenovo_slots"]["strategy"], "members")
        expanded = checks._collect_pcie_slots(_FakeCtx(self._payloads()))
        self.assertEqual(result["normalized"], expanded["normalized"])

    def test_twenty_slots_walked_fit_the_budget_and_one_more_is_refused_whole(self):
        ctx = _FakeCtx(self._big_table(20))
        result = checks._collect_pcie_slots(ctx)
        self.assertEqual(result["context"]["lenovo_slots_total"], 20)
        # resolution 5, the Chassis, PCIeSlots, the $expand attempt, the table, 20 members
        self.assertEqual(len(ctx.gets), 5 + 1 + 1 + 1 + 1 + 20)
        self.assertLessEqual(len(ctx.gets), checks._BUDGET_PCIE_SLOTS)
        ctx = _FakeCtx(self._big_table(21))
        with self.assertRaises(checks.CollectError) as caught:
            checks._collect_pcie_slots(ctx)
        self.assertIn("21 members", str(caught.exception))
        self.assertEqual(ctx.gets[-1], self.LENOVO)  # no member was fetched

    def test_an_empty_table_is_unmeasured_naming_it_and_the_power_state(self):
        payloads = self._payloads()
        payloads[self.SLOTS]["Slots"] = []
        payloads[SYS]["PowerState"] = "Off"
        with self.assertRaises(checks.CollectError) as caught:
            checks._collect_pcie_slots(_FakeCtx(payloads))
        message = str(caught.exception)
        self.assertIn(self.SLOTS + " (no Slots[] entry)", message)
        self.assertIn("host PowerState Off", message)
        self.assertIn("unmeasured", message)
        # host On changes nothing, and the Lenovo table is named when it is empty too
        payloads = self._payloads()
        payloads[self.LENOVO + EXPAND]["Members"] = []
        with self.assertRaises(checks.CollectError) as caught:
            checks._collect_pcie_slots(_FakeCtx(payloads))
        self.assertIn(self.LENOVO + " (no member)", str(caught.exception))
        self.assertIn("host PowerState On", str(caught.exception))
        del payloads[self.SLOTS]["Slots"]  # a body without the array is no slot either
        with self.assertRaises(checks.CollectError) as caught:
            checks._collect_pcie_slots(_FakeCtx(payloads))
        self.assertIn(
            "(no Slots[] entry) and %s (no member)" % (self.LENOVO,), str(caught.exception)
        )

    def test_a_linked_table_that_is_not_there_is_a_failed_read(self):
        payloads = self._payloads()
        del payloads[self.SLOTS]
        with self.assertRaises(checks.CollectError) as caught:
            checks._collect_pcie_slots(_FakeCtx(payloads))
        self.assertIn("links %s but it answered 404" % (self.SLOTS,), str(caught.exception))
        payloads = self._payloads()
        del payloads[self.LENOVO + EXPAND], payloads[self.LENOVO]
        with self.assertRaises(checks.CollectError) as caught:
            checks._collect_pcie_slots(_FakeCtx(payloads))
        self.assertIn("links %s but it answered 404" % (self.LENOVO,), str(caught.exception))
        payloads = self._payloads()
        payloads[self.SLOTS] = {}
        with self.assertRaises(checks.CollectError):
            checks._collect_pcie_slots(_FakeCtx(payloads))
        # any other HTTP error is the transport's failed read, never absence
        with self.assertRaises(_FakeRedfishError):
            checks._collect_pcie_slots(_FakeCtx(self._payloads(), errors={self.SLOTS: 500}))

    def test_not_present_when_neither_table_is_served(self):
        payloads = _base_payloads()  # no PCIeSlots link, nothing at the schema path
        del payloads[CH]["Oem"]["Lenovo"]["Slots"]
        ctx = _FakeCtx(payloads)
        with self.assertRaises(registry.SkipCheck) as caught:
            checks._collect_pcie_slots(ctx)
        self.assertIn("links no Oem.Lenovo.Slots", str(caught.exception))
        self.assertEqual(ctx.gets, RESOLVE + [CH, self.SLOTS])

    def test_other_vendors_read_the_dmtf_slots_only(self):
        payloads = self._payloads()
        payloads["/redfish/v1/"] = dict(payloads["/redfish/v1/"], Vendor="Contoso")
        ctx = _FakeCtx(payloads)
        result = checks._collect_pcie_slots(ctx)
        self.assertEqual(ctx.gets, RESOLVE + [CH, self.SLOTS])
        self.assertEqual(len(result["normalized"]), 5)  # the DMTF rows, every vendor
        self.assertFalse([key for key in result["normalized"] if key.startswith("lenovo_slot|")])
        self.assertIn("no Contoso mapping", result["context"]["lenovo_slots"]["note"])
        self.assertIsNone(result["context"]["lenovo_slots_total"])
        # nothing DMTF to read: not-present, naming the vendor
        del payloads[self.SLOTS], payloads[CH]["PCIeSlots"]
        with self.assertRaises(registry.SkipCheck) as caught:
            checks._collect_pcie_slots(_FakeCtx(payloads))
        self.assertIn("no Contoso mapping for the PCIe slot table", str(caught.exception))

    def test_the_slots_hang_off_the_resolved_chassis(self):
        dell_chassis = "/redfish/v1/Chassis/System.Embedded.1"
        payloads = self._payloads()
        payloads["/redfish/v1/"] = dict(payloads["/redfish/v1/"], Vendor="Dell")
        payloads[SYS]["Links"]["Chassis"] = [{"@odata.id": dell_chassis}]
        payloads[dell_chassis] = dict(
            copy.deepcopy(payloads[CH]),
            PCIeSlots={"@odata.id": dell_chassis + "/PCIeSlots"},
        )
        payloads[dell_chassis + "/PCIeSlots"] = payloads.pop(self.SLOTS)
        ctx = _FakeCtx(payloads)
        result = checks._collect_pcie_slots(ctx)
        self.assertEqual(ctx.gets, RESOLVE + [dell_chassis, dell_chassis + "/PCIeSlots"])
        self.assertEqual(result["context"]["resolution"]["chassis"], dell_chassis)
        self.assertEqual(len(result["normalized"]), 5)

    def test_links_into_actions_are_refused_before_any_is_sent(self):
        def pcie_slots(payloads):
            payloads[CH]["PCIeSlots"] = {"@odata.id": CH + "/Actions/Oem/PCIeSlots"}

        def slot_table(payloads):
            payloads[CH]["Oem"]["Lenovo"]["Slots"] = {"@odata.id": CH + "/Actions/Oem/Slots"}

        def device(payloads):
            links = payloads[self.SLOTS]["Slots"][0]["Links"]["PCIeDevice"]
            links.append({"@odata.id": CH + "/PCIeDevices/slot_1/Actions/x"})

        for mutate in (pcie_slots, slot_table, device):
            payloads = self._payloads()
            mutate(payloads)
            ctx = _FakeCtx(payloads)
            with self.assertRaises(checks.CollectError, msg=mutate.__name__):
                checks._collect_pcie_slots(ctx)
            self.assertFalse([path for path in ctx.gets if "Actions" in path], mutate.__name__)

    def test_an_unseated_card_is_one_changed_row(self):
        compare = registry.CHECKS["bmc_pcie_slots"].compare
        pre = checks._collect_pcie_slots(_FakeCtx(self._payloads()))["normalized"]
        again = checks._collect_pcie_slots(_FakeCtx(self._payloads()))["normalized"]
        self.assertEqual(_loader.diffcore.diff_check(pre, again, compare)["result"], "pass")
        payloads = self._payloads()
        slot = payloads[self.SLOTS]["Slots"][0]
        slot["Status"] = {"State": "Absent"}
        slot["Links"] = {"PCIeDevice@odata.count": 0, "PCIeDevice": []}
        post = checks._collect_pcie_slots(_FakeCtx(payloads))["normalized"]
        diff = _loader.diffcore.diff_check(pre, post, compare)
        self.assertEqual((diff["added"], diff["removed"]), ([], []))
        self.assertEqual(
            [(row["key"], row["field"], row["old"], row["new"]) for row in diff["changed"]],
            [
                ("slot|PCIe 1", "health", "OK", None),
                ("slot|PCIe 1", "linked_devices", ["slot_1"], []),
                ("slot|PCIe 1", "state", "Enabled", "Absent"),
            ],
        )


class TestAccounts(unittest.TestCase):
    """bmc_accounts on hand-built payloads in the DMTF AccountService / ManagerAccount / Role /
    ExternalAccountProvider and Lenovo LenovoAccountService / LenovoManagerAccount /
    LenovoLDAPClient vocabulary (xcc_accounts_*.json): the lab XCC configures no directory,
    holds no SSH key and locks no account, so those shapes are built here; the lab's own
    payloads are pinned in test_lab_fixtures.TestBmcLabAccounts."""

    SERVICE = "/redfish/v1/AccountService"
    ACCOUNTS = SERVICE + "/Accounts"
    ROLES = SERVICE + "/Roles"
    PROVIDERS = SERVICE + "/ExternalAccountProviders"
    PROTOCOL = MGR + "/NetworkProtocol"
    LDAP_CLIENT = PROTOCOL + "/Oem/Lenovo/LDAPClient"
    # every seeded credential, key, token, keytab and signing key; the logged-in users and
    # their client addresses; a role mapping's remote (directory) user
    NEVER_STORED = ("not-a-real", "someone", "192.0.2.77", "directory-person-1")

    @staticmethod
    def _roles():
        """The three predefined roles in the lab's shape (DMTF Role, Lenovo OEM privileges)."""

        def role(role_id, assigned, oem):
            return {
                "@odata.id": "/redfish/v1/AccountService/Roles/" + role_id,
                "Id": role_id,
                "RoleId": role_id,
                "IsPredefined": True,
                "AssignedPrivileges": assigned,
                "OemPrivileges": oem,
            }

        return {
            "@odata.id": "/redfish/v1/AccountService/Roles",
            "Members@odata.count": 3,
            "Members": [
                role(
                    "Administrator",
                    ["Login", "ConfigureManager", "ConfigureUsers", "ConfigureSelf"],
                    ["Supervisor"],
                ),
                role("Operator", ["Login", "ConfigureSelf"], ["RemoteServerPowerRestartAccess"]),
                role("ReadOnly", ["Login", "ConfigureSelf"], ["ReadOnly"]),
            ],
        }

    def _payloads(self):
        """The family's fixture set plus a configured account service at its paths."""
        payloads = _base_payloads()
        payloads["/redfish/v1/"]["AccountService"] = {"@odata.id": self.SERVICE}
        payloads[self.SERVICE] = _fx("xcc_accounts_service_directories.json")
        payloads[self.ACCOUNTS + EXPAND] = _fx("xcc_accounts_members_populated.json")
        payloads[self.ROLES + EXPAND] = self._roles()
        payloads[self.PROVIDERS + EXPAND] = _fx("xcc_accounts_providers_expanded.json")
        payloads[self.PROTOCOL]["Oem"]["Lenovo"]["LDAPClient"] = {"@odata.id": self.LDAP_CLIENT}
        payloads[self.LDAP_CLIENT] = _fx("xcc_accounts_ldapclient_configured.json")
        for path in (self.ACCOUNTS, self.ROLES, self.PROVIDERS):
            plain, members = _split_collection(payloads[path + EXPAND])
            payloads[path] = plain
            for member_path, member in members.items():
                payloads.setdefault(member_path, member)
        return payloads

    def test_policy_scalars_every_one_present(self):
        result = checks._collect_accounts(_FakeCtx(self._payloads()))
        view, context = result["normalized"], result["context"]
        expected = {
            "account_service_enabled": True,
            "local_account_auth": "Fallback",
            "min_password_length": 10,
            "max_password_length": 32,
            "lockout_threshold": 5,
            "lockout_duration_s": 300,
            "lockout_counter_reset_s": 120,
            "lockout_counter_reset_enabled": True,
            "auth_failure_logging_threshold": 3,
            "password_expiration_days": 90,  # the DMTF leaf wins over Lenovo's 180
            "password_expiration_warning_days": 14,
            "password_length": 10,
            "complex_password": True,
            "password_reuse_cycle": 5,
            "password_change_interval_h": 1,
            "password_change_on_first_access": True,
            "password_change_on_next_login": False,
            "web_inactivity_timeout": 10,
        }
        self.assertEqual({key: value for key, value in view.items() if "|" not in key}, expected)
        self.assertEqual(context["password_expiration_days_source"], "PasswordExpirationDays")
        self.assertEqual(
            context["supported_account_types"],
            sorted(_fx("xcc_accounts_service_directories.json")["SupportedAccountTypes"]),
        )
        self.assertIs(context["oauth2_enabled"], True)
        # the logged-in users are a count, never who: the list was reduced before the read
        self.assertEqual(context["current_logged_users"], 2)
        # without the DMTF leaf, Lenovo's period answers and context names it
        payloads = self._payloads()
        del payloads[self.SERVICE]["PasswordExpirationDays"]
        result = checks._collect_accounts(_FakeCtx(payloads))
        self.assertEqual(result["normalized"]["password_expiration_days"], 180)
        self.assertEqual(
            result["context"]["password_expiration_days_source"],
            "Oem.Lenovo.PasswordExpirationPeriodDays",
        )

    def test_every_provider_row_carries_every_field(self):
        view = checks._collect_accounts(_FakeCtx(self._payloads()))["normalized"]
        blank = dict.fromkeys(checks._ACCOUNTS_PROVIDER_FIELDS)
        marker = checks._SCRUBBED
        self.assertEqual(
            sorted(key for key in view if key.startswith("provider|")),
            [
                "provider|active_directory",
                "provider|additional|Corp",
                "provider|ldap",
                "provider|lenovo_ldap_client",
                "provider|oauth2",
                "provider|tacacs_plus",
            ],
        )
        for key in (key for key in view if key.startswith("provider|")):
            self.assertEqual(list(view[key]), list(checks._ACCOUNTS_PROVIDER_FIELDS), key)
        self.assertEqual(
            view["provider|ldap"],
            dict(
                blank,
                enabled=True,
                # the two unset slots dropped, the rest sorted
                service_addresses=[
                    "ldaps://ldap-a.example.net:636",
                    "ldaps://ldap-b.example.net:636",
                ],
                authentication_type="UsernameAndPassword",
                bind_dn=marker,  # the DMTF bind Username is a user-name leaf: set, never shown
                bind_password_set=True,
                base_dns=["ou=Admins,dc=example,dc=net", "ou=Staff,dc=example,dc=net"],
                username_attribute="uid",
                group_name_attribute="cn",
                groups_attribute="memberOf",
                role_mapping_count=3,
                role_mappings=[
                    {"local_role": "GroupRole1", "remote_group": "bmc-admins", "remote_user": None},
                    {
                        "local_role": "GroupRole2",
                        "remote_group": "bmc-operators",
                        "remote_user": None,
                    },
                    {"local_role": "GroupRole3", "remote_group": None, "remote_user": marker},
                ],
            ),
        )
        self.assertEqual(
            view["provider|active_directory"],
            dict(
                blank,
                enabled=False,
                service_addresses=["dc1.example.net"],
                authentication_type="KerberosKeytab",
                role_mapping_count=0,
                role_mappings=[],
            ),
        )
        self.assertEqual(
            view["provider|tacacs_plus"],
            dict(
                blank,
                enabled=False,
                service_addresses=["203.0.113.49:49"],
                authentication_type="UsernameAndPassword",
            ),
        )
        self.assertEqual(
            view["provider|oauth2"],
            dict(
                blank,
                enabled=True,
                oauth2_mode="Discovery",
                oauth2_issuer="https://idp.example.net/realms/bmc",
            ),
        )
        self.assertEqual(
            view["provider|additional|Corp"],
            dict(
                blank,
                enabled=True,
                provider_type="LDAPService",
                service_addresses=["ldaps://ldap-c.example.net:636"],
                authentication_type="Token",
                base_dns=["dc=example,dc=net"],
                username_attribute="uid",
                group_name_attribute="cn",
                groups_attribute="memberOf",
                role_mapping_count=1,
                role_mappings=[
                    {
                        "local_role": "Administrator",
                        "remote_group": "bmc-admins",
                        "remote_user": None,
                    }
                ],
            ),
        )
        self.assertEqual(
            view["provider|lenovo_ldap_client"],
            dict(
                blank,
                enabled=True,
                service_addresses=["198.51.100.41:636", "ldap-b.example.net:636"],
                authentication_type="Anonymously",
                bind_dn=checks._SCRUBBED,  # a bind identity can name a person: set, never shown
                base_dns=["dc=example,dc=net"],
                username_attribute="uid",
                group_name_attribute="memberOf",
                server_discovery="Pre_Configured",
                authorization="LDAPServer",
                group_filter="bmc-",
                login_permission_attribute="bmcLoginPermission",
                role_based_security=True,
                forest_name="example.net",
                server_target_name="bmc-lab-1",
            ),
        )

    def test_accounts_keyed_by_name_and_empty_slots_only_counted(self):
        result = checks._collect_accounts(_FakeCtx(self._payloads()))
        view, context = result["normalized"], result["context"]
        self.assertEqual(
            sorted(key for key in view if key.startswith("account|")),
            ["account|host-bootstrap", "account|ops-admin", "account|svc-capture"],
        )
        self.assertEqual(
            view["account|ops-admin"],
            {
                "account_id": "1",
                "role_id": "Administrator",
                "enabled": True,
                "locked": False,
                "password_change_required": False,
                "account_types": ["ManagerConsole", "Redfish", "SNMP", "WebUI"],
                "oem_account_types": None,
                "host_bootstrap_account": False,
                "snmp_auth_protocol": "HMAC128_SHA224",
                "snmp_encryption_protocol": "CFB128_AES128",
                "snmp_auth_key_set": True,
                "snmp_encryption_key_set": True,
                "snmpv3_configured": True,
                "ssh_key_count": 2,  # two of four slots hold a key; the keys are never stored
            },
        )
        capture = view["account|svc-capture"]
        self.assertEqual(
            (capture["locked"], capture["password_change_required"], capture["role_id"]),
            (True, True, "ReadOnly"),
        )
        self.assertEqual(
            (capture["snmpv3_configured"], capture["snmp_auth_key_set"], capture["ssh_key_count"]),
            (False, None, 0),
        )
        bootstrap = view["account|host-bootstrap"]
        self.assertIs(bootstrap["host_bootstrap_account"], True)
        for field in (
            "snmp_auth_protocol",
            "snmp_encryption_protocol",
            "snmpv3_configured",
            "ssh_key_count",  # no Oem block served on this one
            "password_change_required",
        ):
            self.assertIsNone(bootstrap[field], field)
        # slot 3 ('') and slot 5 (null) are counted, never keyed
        self.assertEqual((context["accounts_total"], context["empty_account_slots"]), (5, 2))
        self.assertEqual(context["roles_total"], 3)
        # a timestamp every password change moves: context only
        self.assertEqual(
            context["password_expiration"],
            {
                "account|ops-admin": "2027-03-01T00:00:00+00:00",
                "account|svc-capture": None,
                "account|host-bootstrap": "2026-12-24T12:00:00+00:00",
            },
        )
        self.assertEqual(
            view["role|Administrator"],
            {
                "assigned_privileges": [
                    "ConfigureManager",
                    "ConfigureSelf",
                    "ConfigureUsers",
                    "Login",
                ],
                "oem_privileges": ["Supervisor"],
                "is_predefined": True,
            },
        )

    def test_a_repeated_name_or_role_id_keeps_every_row(self):
        view, context = checks._normalize_accounts(
            {},
            [{"Id": "1", "UserName": "ops"}, {"Id": "7", "UserName": "ops"}, {"Id": "2"}],
            [{"Id": "a", "RoleId": "X"}, {"Id": "b", "RoleId": "X"}, {"Id": "Operator"}],
        )
        self.assertEqual(
            sorted(key for key in view if "|" in key),
            ["account|ops|1", "account|ops|7", "role|Operator", "role|X|a", "role|X|b"],
        )
        self.assertEqual(context["empty_account_slots"], 1)

    def test_secrets_sessions_and_directory_people_never_reach_raw_context_or_cache(self):
        ctx = _FakeCtx(self._payloads())
        result = checks._collect_accounts(ctx)
        marker = checks._SCRUBBED
        # the cache holds what the redactors returned: what the trace copy is taken from
        stored = json.dumps(result) + json.dumps([value for value in ctx._cache.values()])
        for text in self.NEVER_STORED:
            self.assertNotIn(text, stored, text)
        raw = result["raw"]
        members = raw[self.ACCOUNTS + EXPAND]["Members"]
        # local account names are configuration: kept in raw as in the keys
        self.assertEqual(
            [member["UserName"] for member in members],
            ["ops-admin", "svc-capture", "", "host-bootstrap", None],
        )
        self.assertEqual(members[0]["Oem"]["Lenovo"]["SSHPublicKey"], [marker, None, marker, ""])
        self.assertEqual(
            (members[0]["SNMP"]["AuthenticationKey"], members[1]["Password"]), (marker, marker)
        )
        service = raw[self.SERVICE]
        self.assertEqual(service["Oem"]["Lenovo"]["CurrentLoggedUsers"], [marker, marker])
        self.assertEqual(service["LDAP"]["Authentication"]["Username"], marker)
        self.assertEqual(service["LDAP"]["RemoteRoleMapping"][2]["RemoteUser"], marker)
        self.assertEqual(service["ActiveDirectory"]["Authentication"]["KerberosKeytab"], marker)
        self.assertEqual(service["TACACSplus"]["Authentication"]["EncryptionKey"], marker)
        self.assertIs(service["TACACSplus"]["Authentication"]["EncryptionKeySet"], True)
        self.assertEqual(service["OAuth2"]["OAuth2Service"]["OAuthServiceSigningKeys"], marker)
        provider = raw[self.PROVIDERS + EXPAND]["Members"][0]
        self.assertEqual(provider["Authentication"]["Token"], marker)
        client = raw[self.LDAP_CLIENT]
        self.assertEqual(client["BindingMethod"]["ClientPassword"], marker)
        self.assertEqual(client["BindingMethod"]["ClientDN"], marker)
        self.assertNotIn("@odata.etag", json.dumps(raw))

    def test_the_redactors_scrub_what_the_family_rule_does_not_name(self):
        marker = checks._SCRUBBED
        service = {
            "LDAP": {
                "Authentication": {
                    "AuthenticationType": "Token",
                    "Token": "t0k",
                    "KerberosKeytab": "kt",
                    "Username": "cn=bind",
                },
                "RemoteRoleMapping": [
                    {"LocalRole": "GroupRole1", "RemoteGroup": "admins", "RemoteUser": "person"},
                    {"LocalRole": "GroupRole2", "RemoteUser": ""},
                ],
            },
            "MultiFactorAuth": {"GoogleAuthenticator": {"SecretKey": "s3", "SecretKeySet": True}},
            "Token@Redfish.AllowableValues": ["x"],
        }
        scrubbed = checks._scrub_payload(service)
        authentication = scrubbed["LDAP"]["Authentication"]
        self.assertEqual(
            [authentication[key] for key in ("Token", "KerberosKeytab", "Username")], [marker] * 3
        )
        self.assertEqual(authentication["AuthenticationType"], "Token")
        self.assertEqual(
            scrubbed["LDAP"]["RemoteRoleMapping"],
            [
                {"LocalRole": "GroupRole1", "RemoteGroup": "admins", "RemoteUser": marker},
                {"LocalRole": "GroupRole2", "RemoteUser": ""},  # emptiness kept
            ],
        )
        self.assertEqual(
            scrubbed["MultiFactorAuth"]["GoogleAuthenticator"],
            {"SecretKey": marker, "SecretKeySet": True},
        )
        self.assertEqual(scrubbed["Token@Redfish.AllowableValues"], ["x"])  # an annotation
        self.assertEqual(checks._scrub_payload(scrubbed), scrubbed)  # idempotent
        # the accounts redactor keeps the local account name and nothing else of a person
        # (DMTF ManagerAccount's one-time-passcode delivery address and contact leaves)
        account = {
            "UserName": "ops-admin",
            "Password": "pw",
            "OneTimePasscodeDeliveryAddress": "ops@example.net",
            "EmailAddress": "ops@example.net",
        }
        kept = checks._scrub_accounts(account)
        self.assertEqual(
            kept,
            {
                "UserName": "ops-admin",
                "Password": marker,
                "OneTimePasscodeDeliveryAddress": marker,
                "EmailAddress": marker,
            },
        )
        self.assertEqual(checks._scrub_accounts(kept), kept)
        self.assertEqual(checks._scrub_payload(account)["UserName"], marker)  # anywhere else

    def test_every_read_passes_its_redactor_and_each_collection_is_one_get(self):
        ctx = _FakeCtx(self._payloads())
        checks._collect_accounts(ctx)
        self.assertEqual(
            ctx.gets,
            RESOLVE
            + [self.SERVICE, self.ACCOUNTS + EXPAND, self.ROLES + EXPAND, self.PROVIDERS + EXPAND]
            + [self.PROTOCOL, self.LDAP_CLIENT],
        )
        self.assertEqual(
            dict(ctx.redacted),
            {
                "/redfish/v1/": "_scrub_payload",
                "/redfish/v1/Systems": "_scrub_payload",
                SYS: "_scrub_payload",
                self.SERVICE: "_scrub_payload",
                self.ACCOUNTS + EXPAND: "_scrub_accounts",  # names kept here only
                self.ROLES + EXPAND: "_scrub_payload",
                self.PROVIDERS + EXPAND: "_scrub_payload",
                self.PROTOCOL: "_scrub_payload",  # bmc_manager_network's read, shared
                self.LDAP_CLIENT: "_scrub_payload",
            },
        )
        self.assertEqual(ctx.budgets, [("bmc_accounts", checks._BUDGET_ACCOUNTS)])

    def test_without_expand_a_small_layout_is_walked_and_expand_asked_once(self):
        expanded = checks._collect_accounts(_FakeCtx(self._payloads()))
        ctx = _FakeCtx(_without_expand(self._payloads()))
        walked = checks._collect_accounts(ctx)
        self.assertEqual(walked["normalized"], expanded["normalized"])
        self.assertEqual(
            [path for path in ctx.gets if path.endswith(EXPAND)], [self.ACCOUNTS + EXPAND]
        )
        self.assertEqual(
            {name: read["strategy"] for name, read in walked["context"]["collections"].items()},
            {"accounts": "members", "roles": "members", "additional_providers": "members"},
        )
        # resolution 3, the service, Accounts 1 + 1 + 5, Roles 1 + 3, providers 1 + 1, Lenovo 2
        self.assertEqual(len(ctx.gets), 3 + 1 + 7 + 4 + 2 + 2)

    def test_a_walk_the_budget_cannot_cover_is_refused_before_its_first_member(self):
        payloads = _without_expand(self._payloads())
        del payloads[SYS]["Links"]  # the id resolution then costs its full five GETs
        payloads["/redfish/v1/Managers"] = {"Members": [{"@odata.id": MGR}]}
        payloads["/redfish/v1/Chassis"] = {"Members": [{"@odata.id": CH}]}
        # the lab XCC's 31 roles, served as links only
        payloads[self.ROLES] = {
            "Members": [{"@odata.id": "%s/CustomRole%d" % (self.ROLES, n)} for n in range(1, 32)]
        }
        ctx = _FakeCtx(payloads)
        with self.assertRaises(registry.CollectError) as caught:
            checks._collect_accounts(ctx)
        self.assertIn("31 members to fetch but only 26 GET(s) left", str(caught.exception))
        self.assertFalse([path for path in ctx.gets if path.startswith(self.ROLES + "/")])
        # resolution 5, the service, Accounts 1 + 1 + 5, then the Roles collection
        self.assertEqual(len(ctx.gets), 5 + 1 + 7 + 1)

    def test_an_unlinked_service_answering_404_is_not_present_and_a_linked_one_fails(self):
        ctx = _FakeCtx(_base_payloads())  # the hand-built root links no AccountService
        with self.assertRaises(registry.SkipCheck) as caught:
            checks._collect_accounts(ctx)
        self.assertIn("links no AccountService", str(caught.exception))
        self.assertEqual(ctx.gets, RESOLVE + [self.SERVICE])
        payloads = self._payloads()
        del payloads[self.SERVICE]
        with self.assertRaises(registry.CollectError) as caught:
            checks._collect_accounts(_FakeCtx(payloads))
        self.assertIn("links /redfish/v1/AccountService but it answered 404", str(caught.exception))
        # a refused read is a failed read, never an absent service
        with self.assertRaises(_FakeRedfishError):
            checks._collect_accounts(_FakeCtx(self._payloads(), errors={self.SERVICE: 403}))

    def test_a_linked_collection_that_answers_404_is_a_failed_read(self):
        for path in (self.ACCOUNTS, self.ROLES, self.PROVIDERS):
            payloads = self._payloads()
            del payloads[path], payloads[path + EXPAND]
            with self.assertRaises(registry.CollectError) as caught:
                checks._collect_accounts(_FakeCtx(payloads))
            self.assertIn("links %s but it answered 404" % (path,), str(caught.exception))
        # an unlinked collection whose DMTF path answers 404 is not served: no rows, said so
        payloads = self._payloads()
        del payloads[self.SERVICE]["Accounts"]
        del payloads[self.ACCOUNTS], payloads[self.ACCOUNTS + EXPAND]
        result = checks._collect_accounts(_FakeCtx(payloads))
        self.assertFalse([key for key in result["normalized"] if key.startswith("account|")])
        self.assertEqual(result["context"]["collections"]["accounts"]["strategy"], "absent")
        self.assertIsNone(result["context"]["empty_account_slots"])
        # the additional providers are read only where the service links them
        payloads = self._payloads()
        del payloads[self.SERVICE]["AdditionalExternalAccountProviders"]
        ctx = _FakeCtx(payloads)
        result = checks._collect_accounts(ctx)
        self.assertFalse([path for path in ctx.gets if "ExternalAccountProviders" in path])
        self.assertIsNone(result["context"]["collections"]["additional_providers"])
        self.assertNotIn("provider|additional|Corp", result["normalized"])

    def test_account_names_an_earlier_read_withheld_are_refused_never_keyed(self):
        payloads = self._payloads()
        payloads[self.ACCOUNTS + EXPAND]["Members"][0]["UserName"] = checks._SCRUBBED
        with self.assertRaises(registry.CollectError) as caught:
            checks._collect_accounts(_FakeCtx(payloads))
        self.assertIn("withheld (slots 1)", str(caught.exception))

    def test_other_vendors_read_the_dmtf_service_and_nothing_of_lenovo(self):
        payloads = self._payloads()
        payloads["/redfish/v1/"]["Vendor"] = "Contoso"
        ctx = _FakeCtx(payloads)
        result = checks._collect_accounts(ctx)
        view, context = result["normalized"], result["context"]
        self.assertNotIn(self.PROTOCOL, ctx.gets)
        self.assertFalse([path for path in ctx.gets if "Lenovo" in path])
        self.assertNotIn("provider|lenovo_ldap_client", view)
        for field in (
            "password_expiration_warning_days",
            "password_length",
            "complex_password",
            "password_reuse_cycle",
            "password_change_interval_h",
            "password_change_on_first_access",
            "password_change_on_next_login",
            "web_inactivity_timeout",
        ):
            self.assertIsNone(view[field], field)
        self.assertEqual(view["password_expiration_days"], 90)  # the DMTF leaf, every vendor
        self.assertEqual(
            {view[key]["ssh_key_count"] for key in view if key.startswith("account|")}, {None}
        )
        self.assertIsNone(context["current_logged_users"])
        self.assertIsNone(context["lenovo_ldap_client"])
        lenovo = checks._collect_accounts(_FakeCtx(self._payloads()))["normalized"]
        for key in ("provider|ldap", "provider|oauth2", "role|ReadOnly"):
            self.assertEqual(view[key], lenovo[key], key)

    def test_a_link_into_actions_is_refused(self):
        payloads = self._payloads()
        payloads[self.SERVICE]["Roles"] = {"@odata.id": self.SERVICE + "/Actions/Roles.Reset"}
        with self.assertRaises(registry.CollectError):
            checks._collect_accounts(_FakeCtx(payloads))
        payloads = self._payloads()
        payloads["/redfish/v1/"]["AccountService"] = {"@odata.id": "/redfish/v1/Actions/x"}
        with self.assertRaises(registry.CollectError):
            checks._collect_accounts(_FakeCtx(payloads))

    def test_unset_server_slots_are_no_addresses(self):
        address = checks._accounts_address
        for unset in (None, "", ":389", "0.0.0.0:389", "::", "[::]:636", "ldap://:389"):
            self.assertIsNone(address(unset), unset)
        for kept in (
            "ldaps://ldap-a.example.net:636",
            "198.51.100.41",
            "dc1.example.net",
            "2001:db8::10",
            "[2001:db8::10]:636",
        ):
            self.assertEqual(address(kept), kept)
        servers = {"Server1HostName_IPAddress": "2001:db8::10", "Server1Port": "636"}
        self.assertEqual(checks._accounts_lenovo_server(servers, 1), "[2001:db8::10]:636")
        self.assertIsNone(checks._accounts_lenovo_server(servers, 2))

    def test_snmpv3_configured_reads_the_two_protocol_leaves_only(self):
        snmpv3 = checks._accounts_snmpv3
        self.assertIsNone(snmpv3(None, None))
        self.assertIs(snmpv3("None", "None"), False)
        self.assertIs(snmpv3("None", None), False)
        self.assertIs(snmpv3("HMAC_SHA96", "None"), True)
        self.assertIs(snmpv3(None, "CFB128_AES128"), True)

    def test_a_lockout_a_new_account_and_a_role_edit_diff_and_a_rotation_does_not(self):
        compare = registry.CHECKS["bmc_accounts"].compare
        diff_check = _loader.diffcore.diff_check
        pre = checks._collect_accounts(_FakeCtx(self._payloads()))["normalized"]
        self.assertEqual(diff_check(pre, copy.deepcopy(pre), compare)["result"], "pass")
        payloads = self._payloads()
        members = payloads[self.ACCOUNTS + EXPAND]["Members"]
        members[0]["PasswordExpiration"] = "2027-06-01T00:00:00+00:00"  # a password rotation
        post = checks._collect_accounts(_FakeCtx(payloads))["normalized"]
        self.assertEqual(diff_check(pre, post, compare)["result"], "pass")
        members[0]["Locked"] = True
        members[2]["UserName"] = "new-operator"  # the empty slot 3 gets an account
        payloads[self.ROLES + EXPAND]["Members"][2]["OemPrivileges"] = ["Supervisor"]
        post = checks._collect_accounts(_FakeCtx(payloads))["normalized"]
        diff = diff_check(pre, post, compare)
        self.assertEqual([row["key"] for row in diff["added"]], ["account|new-operator"])
        self.assertEqual(diff["removed"], [])
        self.assertEqual(
            [(row["key"], row["field"], row["old"], row["new"]) for row in diff["changed"]],
            [
                ("account|ops-admin", "locked", False, True),
                ("role|ReadOnly", "oem_privileges", ["ReadOnly"], ["Supervisor"]),
            ],
        )


class TestAlerting(unittest.TestCase):
    """bmc_alerting on hand-built shapes the lab unit lacks — populated subscriptions and
    recipients, SNMP traps on, a configured mail relay. The fixtures (xcc_alerting_*.json) are
    hand-built: the subscriptions from the DMTF EventDestination schema (Protocol,
    SubscriptionType, EventFormatType and DeliveryRetryPolicy members as the lab's own
    Subscriptions capabilities object allows them, plus the DMTF SSE type and SNMPv3
    authentication/encryption protocol members); the recipients from the LenovoAlertRecipient
    names of handoff Appendix B (no AlertType or AcceptedEvents member is known offline, so the
    fixture serves AlertType null and empty event lists, the spelling the lab's SNMP trap filter
    serves); the trap block in the lab's LenovoSNMPProtocol shape."""

    ES = "/redfish/v1/EventService"
    SUBS = ES + "/Subscriptions"
    RCPT = MGR + "/Oem/Lenovo/Recipients"
    NP = MGR + "/NetworkProtocol"
    SNMP = NP + "/Oem/Lenovo/SNMP"
    SMTP = NP + "/Oem/Lenovo/SMTPClient"
    LS = SYS + "/LogServices"
    # what must never leave a read: people's addresses and names, credentials, a webhook token
    PEOPLE = (
        "jane",
        "Jane",
        "Roe",
        "xcc-alerts",
        "smtp-user",
        "relay-user",
        "hunter2",
        "hand-built-token",
        "hand-built-community",
        "hand-built-auth-key",
        "hand-built-privacy-key",
    )
    SUBSCRIPTION_FIELDS = {
        "destination",
        "protocol",
        "subscription_type",
        "event_format",
        "context_set",
        "registry_prefixes",
        "resource_types",
        "message_ids",
        "event_types",
        "origin_resources",
        "metric_report_definitions",
        "subordinate_resources",
        "include_origin_of_condition",
        "delivery_retry_policy",
        "send_heartbeat",
        "heartbeat_interval_min",
        "verify_certificate",
        "snmp_authentication_protocol",
        "snmp_encryption_protocol",
        "syslog_filters",
        "state",
        "health",
    }

    def _payloads(self, expand=True):
        payloads = _base_payloads()
        payloads["/redfish/v1/"] = dict(
            payloads["/redfish/v1/"], EventService={"@odata.id": self.ES}
        )
        payloads[self.ES] = {
            "@odata.id": self.ES,
            "@odata.type": "#EventService.v1_7_2.EventService",
            "Id": "EventService",
            "Name": "Event Service",
            "ServiceEnabled": True,
            "Status": {"State": "Enabled", "Health": "OK"},
            "DeliveryRetryAttempts": 5,
            "DeliveryRetryIntervalSeconds": 30,
            "EventFormatTypes": ["MetricReport", "Event"],
            "RegistryPrefixes": ["ResourceEvent", "Base"],
            "ResourceTypes": ["LogService"],
            "ServerSentEventUri": self.ES + "/ServerSentEvent",
            "SubordinateResourcesSupported": True,
            "IncludeOriginOfConditionSupported": True,
            "Subscriptions": {"@odata.id": self.SUBS},
            "SMTP": {
                "ServiceEnabled": True,
                "ServerAddress": "smtp.example.com",
                "Port": 587,
                "FromAddress": "xcc-alerts@example.com",
                "ConnectionProtocol": "AutoDetect",
                "Authentication": "Login",
                "Username": "smtp-user",
                "Password": "hunter2",
            },
            "Actions": {
                "#EventService.SubmitTestEvent": {
                    "target": self.ES + "/Actions/EventService.SubmitTestEvent"
                }
            },
        }
        for path, name in (
            (self.SUBS, "xcc_alerting_subscriptions_populated.json"),
            (self.RCPT, "xcc_alerting_recipients_populated.json"),
        ):
            expanded = _fx(name)
            if expand:
                payloads[path + EXPAND] = expanded
            plain, members = _split_collection(expanded)
            payloads[path] = plain
            payloads.update(members)
        lenovo = payloads[MGR]["Oem"]["Lenovo"]
        lenovo["Recipients"] = {"@odata.id": self.RCPT}
        lenovo["RecipientsSettings"] = {
            "RetryCount": 3,
            "RetryInterval": 1.5,
            "RntryRetryInterval": 2,
        }
        payloads[self.NP]["Oem"]["Lenovo"].update(
            {"SNMP": {"@odata.id": self.SNMP}, "SMTPClient": {"@odata.id": self.SMTP}}
        )
        payloads[self.SNMP] = _fx("xcc_alerting_snmp_traps_configured.json")
        payloads[self.SMTP] = {
            "@odata.id": self.SMTP,
            "@odata.type": "#LenovoSMTPClient.v1_0_0.LenovoSMTPClient",
            "Id": "SMTPClient",
            "Name": "SMTP Client",
            "ProtocolEnabled": True,
            "AccessInfo": "smtp.example.com",
            "AccessPort": 25,
            "Reverse-path": "jane.roe@example.com",
            "Authentication": {
                "Required": True,
                "Method": "CRAM_MD5",
                "UserName": "relay-user",
                "Password": "hunter2",
            },
        }
        return payloads

    def test_every_scalar_and_row_is_read_from_its_resource(self):
        ctx = _FakeCtx(self._payloads())
        result = checks._collect_alerting(ctx)
        view, context = result["normalized"], result["context"]
        scalars = {
            "event_service_enabled": True,
            "event_service_state": "Enabled",
            "event_service_health": "OK",
            "delivery_retry_attempts": 5,
            "delivery_retry_interval_s": 30,
            "smtp_enabled": True,
            "smtp_server": "smtp.example.com",
            "smtp_port": 587,
            "smtp_from": "@example.com",  # the domain only: the local part names a person
            "smtp_from_set": True,
            "smtp_connection_protocol": "AutoDetect",
            "smtp_auth_method": "Login",
            "recipient_retry_count": 3,
            "recipient_retry_interval": 1.5,
            "recipient_entry_retry_interval": 2.0,
            "snmp_trap_enabled": True,
            "snmp_trap_port": 162,
            "snmp_trap_v1": True,
            "snmp_trap_v2": False,
            # every target's addresses, sorted, the unset placeholders dropped
            "trap_targets": ["192.0.2.61", "192.0.2.62", "trap-b.example.com"],
            "snmp_trap_critical_enabled": True,
            "snmp_trap_critical_events": [],
            "snmp_trap_warning_enabled": True,
            "snmp_trap_warning_events": [],
            "snmp_trap_system_enabled": False,
            "snmp_trap_system_events": [],
            "smtp_client_enabled": True,
            "smtp_client_server": "smtp.example.com",
            "smtp_client_port": 25,
            "smtp_client_reverse_path": "@example.com",
            "smtp_client_reverse_path_set": True,
            "smtp_client_auth_required": True,
            "smtp_client_auth_method": "CRAM_MD5",
            "platform_log_syslog_filters": None,  # the hand-built platform log serves none
        }
        self.assertEqual({key: view[key] for key in scalars}, scalars)
        rows = sorted(key for key in view if "|" in key)
        self.assertEqual(set(view), set(scalars) | set(rows))
        # the SSE stream (subscription 5) is a client session: counted, never keyed
        self.assertEqual(
            rows,
            ["recipient|1", "recipient|2"] + ["subscription|%d" % n for n in (1, 2, 3, 4)],
        )
        self.assertEqual(context["sse_subscriptions"], 1)
        self.assertEqual(
            view["subscription|1"],
            {
                # the webhook's query (its token) is never kept
                "destination": "https://collector.example.com:8443/redfish/events",
                "protocol": "Redfish",
                "subscription_type": "RedfishEvent",
                "event_format": "Event",
                "context_set": True,  # the string itself is scrubbed: it can be a secret
                "registry_prefixes": ["Base", "ResourceEvent"],
                "resource_types": ["LogService"],
                "message_ids": [],
                "event_types": None,  # the deprecated filter, not served here
                "origin_resources": ["/redfish/v1/Chassis/1", "/redfish/v1/Systems/1"],
                "metric_report_definitions": [],
                "subordinate_resources": True,
                "include_origin_of_condition": True,
                "delivery_retry_policy": "SuspendRetries",
                "send_heartbeat": True,
                "heartbeat_interval_min": 10,
                "verify_certificate": True,
                "snmp_authentication_protocol": None,
                "snmp_encryption_protocol": None,
                "syslog_filters": None,
                "state": "Enabled",
                "health": "OK",
            },
        )
        for key in rows:
            if key.startswith("subscription|"):
                self.assertEqual(set(view[key]), self.SUBSCRIPTION_FIELDS, key)
        # an SNMP URI's userinfo is its community: never kept
        self.assertEqual(view["subscription|2"]["destination"], "snmp://192.0.2.60:162")
        self.assertIs(view["subscription|2"]["context_set"], False)  # served ''
        inform = view["subscription|3"]
        self.assertEqual(
            (
                inform["protocol"],
                inform["subscription_type"],
                inform["snmp_authentication_protocol"],
                inform["snmp_encryption_protocol"],
                inform["delivery_retry_policy"],
                inform["state"],
                inform["registry_prefixes"],
                inform["resource_types"],  # not served: None, never []
            ),
            (
                "SNMPv3",
                "SNMPInform",
                "HMAC_SHA96",
                "CFB128_AES128",
                "RetryForeverWithBackoff",
                "Disabled",
                ["EventRegistry"],
                None,
            ),
        )
        mail = view["subscription|4"]
        self.assertEqual(mail["destination"], "mailto:@example.com")
        self.assertIs(mail["context_set"], True)
        self.assertIsNone(mail["subscription_type"])  # not served on this member
        self.assertEqual(
            view["recipient|1"],
            {
                "name_set": True,  # the name itself is never kept
                "enabled": True,
                "alert_type": None,
                "address": "@example.com",
                "address_set": True,
                "include_event_log": True,
                "critical_enabled": True,
                "critical_events": [],
                "warning_enabled": False,
                "warning_events": [],
                "system_enabled": True,
                "system_events": [],
            },
        )
        syslog = view["recipient|2"]
        self.assertEqual(
            (syslog["name_set"], syslog["enabled"], syslog["address"], syslog["address_set"]),
            (False, False, "192.0.2.77", True),  # a host without '@' is verbatim
        )
        self.assertEqual(
            ctx.gets,
            RESOLVE
            + [self.ES, MGR, self.NP, self.SNMP, self.SMTP]
            + [self.SUBS + EXPAND, self.RCPT + EXPAND]
            # the platform log service, read the way bmc_event_log reads it
            + [self.LS + EXPAND, self.LS, self.LS + "/PlatformLog"],
        )
        self.assertEqual(
            context["sources"],
            {
                "event_service": self.ES,
                "subscriptions": self.SUBS,
                "recipients": self.RCPT,
                "recipients_settings": MGR + " Oem.Lenovo.RecipientsSettings",
                "snmp": self.SNMP,
                "smtp_client": self.SMTP,
            },
        )
        self.assertEqual(
            (context["subscriptions"]["strategy"], context["subscriptions"]["members"]),
            ("expand", 5),
        )
        self.assertEqual(
            (context["recipients"]["strategy"], context["recipients"]["members"]), ("expand", 2)
        )
        self.assertEqual(
            context["syslog_filters_source"],
            {
                "service": "PlatformLog",
                "strategy": "members",
                "expand_refused": "HTTP 404",
                "note": None,
            },
        )
        self.assertEqual(
            (context["smtp_username_set"], context["smtp_client_username_set"]), (True, True)
        )
        self.assertEqual(
            context["event_service_capabilities"]["event_format_types"], ["Event", "MetricReport"]
        )
        self.assertIsNone(context["vendor_mapping"])
        self.assertEqual(context["resolution"]["system"], SYS)
        self.assertEqual(
            sorted(result["raw"]),
            sorted([self.ES, self.SUBS + EXPAND, self.RCPT + EXPAND, self.SNMP, self.SMTP]),
        )
        self.assertNotIn("Actions", json.dumps(result["raw"]))

    def test_people_and_credentials_never_reach_the_view_raw_or_the_trace(self):
        ctx = _FakeCtx(self._payloads())
        result = checks._collect_alerting(ctx)
        stored = json.dumps(result)
        # the per-run cache holds exactly what the debug trace copies
        cached = json.dumps([payload for payload in ctx._cache.values() if payload])
        for token in self.PEOPLE:
            self.assertNotIn(token, stored, token)
            self.assertNotIn(token, cached, token)
        raw = result["raw"]
        members = {member["Id"]: member for member in raw[self.SUBS + EXPAND]["Members"]}
        self.assertEqual(
            members["1"]["Destination"],
            "https://collector.example.com:8443/redfish/events?***scrubbed***",
        )
        self.assertEqual(members["2"]["Destination"], "snmp://***scrubbed***@192.0.2.60:162")
        self.assertEqual(members["4"]["Destination"], "mailto:***scrubbed***@example.com")
        self.assertEqual(
            members["3"]["SNMP"],
            {
                "AuthenticationProtocol": "HMAC_SHA96",
                "AuthenticationKey": "***scrubbed***",
                "EncryptionProtocol": "CFB128_AES128",
                "EncryptionKey": "***scrubbed***",
            },
        )
        recipient = raw[self.RCPT + EXPAND]["Members"][0]
        self.assertEqual(recipient["Name"], "***scrubbed***")
        self.assertEqual(recipient["RecipientSettings"]["RecipientName"], "***scrubbed***")
        self.assertEqual(recipient["RecipientSettings"]["Address"], "***scrubbed***@example.com")
        self.assertEqual(
            raw[self.RCPT + EXPAND]["Members"][1]["RecipientSettings"]["RecipientName"], ""
        )
        self.assertEqual(raw[self.ES]["SMTP"]["FromAddress"], "***scrubbed***@example.com")
        self.assertEqual(raw[self.SMTP]["Reverse-path"], "***scrubbed***@example.com")
        self.assertEqual(raw[self.SNMP]["CommunityNames"], ["***scrubbed***", None, None])
        # the alerting reads pass the alerting redactor, the shared ones the family's own
        redactors = dict(ctx.redacted)
        for path in (self.ES, self.SMTP, self.SUBS + EXPAND, self.RCPT + EXPAND):
            self.assertEqual(redactors[path], "_alerting_redact", path)
        for path in (MGR, self.NP, self.SNMP, self.LS, self.LS + "/PlatformLog"):
            self.assertEqual(redactors[path], "_scrub_payload", path)

    def test_the_redactor_is_idempotent_and_never_mutates_its_input(self):
        member = {
            "@odata.id": self.SUBS + "/9",
            "Destination": "https://user:pw@collector.example.com:8443/in?code=secret#top",
            "Context": "ops jane.roe@example.com",
            "HttpHeaders": [{"Authorization": "Bearer secret"}],
            "SNMP": {"TrapCommunity": "c"},
            "Members@odata.count": 1,
        }
        original = copy.deepcopy(member)
        redacted = checks._alerting_redact(member)
        self.assertEqual(member, original)
        self.assertEqual(
            redacted["Destination"],
            "https://***scrubbed***@collector.example.com:8443/in?***scrubbed***#top",
        )
        self.assertEqual(redacted["Context"], checks._SCRUBBED)  # it can be a shared secret
        self.assertEqual(redacted["HttpHeaders"], ["***scrubbed***"])  # the count survives
        self.assertEqual(redacted["SNMP"]["TrapCommunity"], "***scrubbed***")
        self.assertEqual(redacted["@odata.id"], self.SUBS + "/9")
        self.assertEqual(checks._alerting_redact(redacted), redacted)
        self.assertNotIn("secret", json.dumps(redacted))
        self.assertNotIn("jane", json.dumps(redacted))
        # an address leaf keeps its domain and nothing else: no display name, no bare
        # local part; a recipient's bare Address is a syslog host and stays
        addresses = checks._alerting_redact(
            {
                "SMTP": {"FromAddress": "Jane Roe <jane.roe@example.com>"},
                "Reverse-path": "jroe",
                "RecipientSettings": {"Address": "syslog.example.com:514"},
                "Other": {"Address": "Jane Roe <jane.roe@example.com>", "Note": "no address"},
            }
        )
        self.assertEqual(
            addresses,
            {
                "SMTP": {"FromAddress": "***scrubbed***@example.com"},
                "Reverse-path": "***scrubbed***",
                "RecipientSettings": {"Address": "syslog.example.com:514"},
                "Other": {"Address": "***scrubbed***@example.com", "Note": "no address"},
            },
        )
        self.assertEqual(checks._alerting_redact(addresses), addresses)

    def test_destination_forms(self):
        destination = checks._alerting_destination
        for served, keyed in (
            (
                "https://collector.example.com:8443/redfish/events?code=t#frag",
                "https://collector.example.com:8443/redfish/events",
            ),
            ("https://***scrubbed***@collector.example.com/in", "https://collector.example.com/in"),
            ("https://user:pw@collector.example.com", "https://collector.example.com"),
            ("snmp://***scrubbed***@192.0.2.60:162", "snmp://192.0.2.60:162"),
            ("syslog://[2001:db8::10]:514", "syslog://[2001:db8::10]:514"),
            ("mailto:***scrubbed***@example.com", "mailto:@example.com"),
            ("mailto:a@example.com,b@example.net?subject=x", "mailto:@example.com,@example.net"),
            ("192.0.2.77", "192.0.2.77"),
            ("", None),
            (None, None),
        ):
            self.assertEqual(destination(served), keyed, served)

    def test_email_addresses_are_keyed_as_their_domain_with_a_set_flag(self):
        for smtp, keyed in (
            ({"FromAddress": "xcc-alerts@example.com"}, ("@example.com", True)),
            ({"FromAddress": "<xcc-alerts@Mail.Example.com>"}, ("@Mail.Example.com", True)),
            ({"FromAddress": "***scrubbed***@example.com"}, ("@example.com", True)),
            ({"FromAddress": "xcc"}, (None, True)),  # set, but it names no domain
            ({"FromAddress": ""}, (None, False)),
            ({"FromAddress": None}, (None, False)),
            ({}, (None, None)),  # the leaf is not served
        ):
            view, _context = checks._normalize_alerting({"SMTP": smtp})
            self.assertEqual((view["smtp_from"], view["smtp_from_set"]), keyed, smtp)
        view, _context = checks._normalize_alerting(None)
        self.assertEqual((view["smtp_from"], view["smtp_from_set"]), (None, None))

    def test_recipient_leaves_are_read_verbatim_and_never_inferred(self):
        # 'value-b'/'value-a' are placeholder tokens, not Lenovo enum members: the
        # normalizer never interprets AlertType or AcceptedEvents, it sorts and keeps them
        row = checks._alerting_recipient(
            {
                "RecipientSettings": {
                    "RecipientName": "***scrubbed***",
                    "EnabledState": "Enabled",  # the case variant of Lenovo's Enabledstate
                    "AlertType": "value-a",
                    "Address": "0.0.0.0",
                    "EnabledAlerts": {
                        "CriticalEvents": {
                            "Enabled": True,
                            "AcceptedEvents": ["value-b", "value-a"],
                        }
                    },
                }
            }
        )
        self.assertEqual(
            row,
            {
                "name_set": True,
                "enabled": True,
                "alert_type": "value-a",
                "address": None,  # the unset placeholder is no address
                "address_set": False,
                "include_event_log": None,
                "critical_enabled": True,
                "critical_events": ["value-a", "value-b"],
                "warning_enabled": None,  # an unserved class stays None, never False
                "warning_events": None,
                "system_enabled": None,
                "system_events": None,
            },
        )
        for served, enabled in ((False, False), ("Disabled", False), (None, None)):
            settings = {"RecipientSettings": {"Enabledstate": served}}
            self.assertIs(checks._alerting_recipient(settings)["enabled"], enabled, served)
        # no settings block at all: every field present, None
        self.assertEqual(set(checks._alerting_recipient({}).values()), {None})

    def test_syslog_filters_of_the_platform_log_and_of_a_subscription(self):
        payloads = self._payloads()
        payloads[self.LS + "/PlatformLog"]["SyslogFilters"] = [
            {"LogFacilities": ["Local0", "Daemon"], "LowestSeverity": "Warning"},
            {"LogFacilities": [], "LowestSeverity": "Critical"},
        ]
        view = checks._collect_alerting(_FakeCtx(payloads))["normalized"]
        self.assertEqual(
            view["platform_log_syslog_filters"],
            [
                {"log_facilities": [], "lowest_severity": "Critical"},
                {"log_facilities": ["Daemon", "Local0"], "lowest_severity": "Warning"},
            ],
        )
        row = checks._alerting_subscription(
            {"Protocol": "SyslogUDP", "SyslogFilters": [{"LowestSeverity": "Error"}]}
        )
        self.assertEqual(
            row["syslog_filters"], [{"log_facilities": None, "lowest_severity": "Error"}]
        )

    def test_the_platform_log_is_left_unread_where_the_family_cannot_resolve_one(self):
        payloads = self._payloads()
        payloads[self.LS] = {
            "Members": [{"@odata.id": self.LS + "/Audit"}, {"@odata.id": self.LS + "/Other"}]
        }
        result = checks._collect_alerting(_FakeCtx(payloads))
        source = result["context"]["syslog_filters_source"]
        self.assertIsNone(source["service"])
        self.assertIn("neither PlatformLog nor StandardLog", source["note"])
        self.assertIsNone(result["normalized"]["platform_log_syslog_filters"])
        del payloads[self.LS]
        source = checks._collect_alerting(_FakeCtx(payloads))["context"]["syslog_filters_source"]
        self.assertEqual(source["note"], self.LS + " answered 404")
        # any other failure of the read fails the check
        with self.assertRaises(_FakeRedfishError):
            checks._collect_alerting(_FakeCtx(self._payloads(), errors={self.LS: 500}))

    def test_a_refused_expand_is_paid_once_and_the_walk_is_complete(self):
        expanded = checks._collect_alerting(_FakeCtx(self._payloads()))["normalized"]
        for payloads, errors in (
            (self._payloads(expand=False), {}),  # $expand answers 404
            (self._payloads(), {self.SUBS + EXPAND: 501}),  # $expand refused
        ):
            ctx = _FakeCtx(payloads, errors=errors)
            result = checks._collect_alerting(ctx)
            self.assertEqual(result["normalized"], expanded)
            self.assertEqual([path for path in ctx.gets if "?" in path], [self.SUBS + EXPAND])
            self.assertEqual(result["context"]["subscriptions"]["strategy"], "members")
            self.assertEqual(result["context"]["recipients"]["strategy"], "members")
            # resolution 3, five singletons, the attempt + the collection + 5 members,
            # the collection + 2 members, the LogServices collection + the platform log
            self.assertEqual(len(ctx.gets), 3 + 5 + 7 + 3 + 2)
            self.assertLessEqual(len(ctx.gets), checks._BUDGET_ALERTING)
            # the raw of a walk is every request sent, each member curated and redacted
            self.assertIn(self.SUBS + "/1", result["raw"])
            self.assertNotIn("hand-built-token", json.dumps(result["raw"]))

    def test_ignored_expand_is_walked_too(self):
        payloads = self._payloads()
        payloads[self.SUBS + EXPAND] = copy.deepcopy(payloads[self.SUBS])  # links only
        ctx = _FakeCtx(payloads)
        result = checks._collect_alerting(ctx)
        self.assertEqual(
            result["context"]["subscriptions"]["expand_refused"], "members returned as links"
        )
        self.assertEqual(len([key for key in result["normalized"] if "subscription|" in key]), 4)
        self.assertEqual([path for path in ctx.gets if "?" in path], [self.SUBS + EXPAND])

    def test_a_walk_the_budget_cannot_cover_is_refused_before_its_first_member(self):
        payloads = self._payloads(expand=False)
        payloads[self.SUBS] = {
            "@odata.id": self.SUBS,
            "Members": [{"@odata.id": "%s/%d" % (self.SUBS, n)} for n in range(1, 41)],
        }
        ctx = _FakeCtx(payloads)
        with self.assertRaises(checks.CollectError) as caught:
            checks._collect_alerting(ctx)
        self.assertIn("bmc_alerting subscriptions: 40 members to fetch", str(caught.exception))
        self.assertFalse([path for path in ctx.gets if path.startswith(self.SUBS + "/")])

    def test_a_linked_resource_that_answers_404_is_a_failed_read(self):
        for gone, parent in (
            ((self.ES,), "the service root"),
            ((self.SUBS, self.SUBS + EXPAND), self.ES),
            ((self.RCPT, self.RCPT + EXPAND), MGR),
            ((self.SNMP,), self.NP),
            ((self.SMTP,), self.NP),
        ):
            payloads = self._payloads()
            for path in gone:
                del payloads[path]
            with self.assertRaises(checks.CollectError) as caught:
                checks._collect_alerting(_FakeCtx(payloads))
            self.assertIn(
                "%s links %s but it answered 404" % (parent, gone[0]), str(caught.exception)
            )
        payloads = self._payloads()
        payloads[self.SMTP] = {}
        with self.assertRaises(checks.CollectError) as caught:
            checks._collect_alerting(_FakeCtx(payloads))
        self.assertIn("answered without a resource body", str(caught.exception))

    def test_a_link_into_actions_is_refused(self):
        payloads = self._payloads()
        payloads[self.ES]["Subscriptions"] = {"@odata.id": self.ES + "/Actions/x"}
        with self.assertRaises(checks.CollectError) as caught:
            checks._collect_alerting(_FakeCtx(payloads))
        self.assertIn("server-supplied link refused", str(caught.exception))

    def test_empty_services_are_an_empty_keyed_view(self):
        payloads = self._payloads()
        for path in (self.SUBS, self.RCPT):
            payloads[path + EXPAND] = {"@odata.id": path, "Members": [], "Members@odata.count": 0}
        result = checks._collect_alerting(_FakeCtx(payloads))
        view = result["normalized"]
        self.assertFalse([key for key in view if "|" in key])
        self.assertIs(view["event_service_enabled"], True)
        self.assertEqual(result["context"]["subscriptions"]["members"], 0)
        self.assertEqual(result["context"]["recipients"]["members"], 0)

    def test_other_vendors_read_the_dmtf_event_service_and_nothing_of_lenovo(self):
        payloads = self._payloads()
        payloads["/redfish/v1/"] = dict(payloads["/redfish/v1/"], Vendor="Contoso")
        ctx = _FakeCtx(payloads)
        result = checks._collect_alerting(ctx)
        view = result["normalized"]
        self.assertEqual(
            sorted(key for key in view if "|" in key),
            ["subscription|%d" % n for n in (1, 2, 3, 4)],
        )
        for field in (
            "recipient_retry_count",
            "snmp_trap_enabled",
            "trap_targets",
            "smtp_client_enabled",
            "smtp_client_reverse_path_set",
        ):
            self.assertIsNone(view[field], field)
        self.assertEqual(view["smtp_server"], "smtp.example.com")
        self.assertFalse([path for path in ctx.gets if "/Oem/Lenovo" in path])
        self.assertNotIn(MGR, ctx.gets)
        self.assertIn("no Contoso mapping", result["context"]["vendor_mapping"])
        # without an EventService there is nothing this family can read there
        payloads["/redfish/v1/"].pop("EventService")
        with self.assertRaises(registry.SkipCheck) as caught:
            checks._collect_alerting(_FakeCtx(payloads))
        self.assertIn("no Contoso mapping for the alerting resources", str(caught.exception))

    def test_a_lenovo_bmc_linking_nothing_is_not_present(self):
        # the hand-built base set: no EventService link, no Lenovo alerting link
        ctx = _FakeCtx(_base_payloads())
        with self.assertRaises(registry.SkipCheck) as caught:
            checks._collect_alerting(ctx)
        self.assertIn("links no EventService", str(caught.exception))
        self.assertNotIn("/redfish/v1/EventService", ctx.gets)

    def test_shared_reads_answer_from_the_cache(self):
        ctx = _FakeCtx(self._payloads())
        checks._collect_manager_network(ctx)
        checks._collect_event_log(ctx)
        before = len(ctx.gets)
        checks._collect_alerting(ctx)
        # the Manager, NetworkProtocol, SNMP and log service reads are the other checks' own
        self.assertEqual(
            ctx.gets[before:], [self.ES, self.SMTP, self.SUBS + EXPAND, self.RCPT + EXPAND]
        )

    def test_the_same_view_twice_diffs_to_nothing_and_a_disabled_recipient_is_one_change(self):
        compare = registry.CHECKS["bmc_alerting"].compare
        self.assertEqual(compare, {"mode": "equality_set"})
        pre = checks._collect_alerting(_FakeCtx(self._payloads()))["normalized"]
        post = checks._collect_alerting(_FakeCtx(self._payloads()))["normalized"]
        self.assertEqual(_loader.diffcore.diff_check(pre, post, compare)["result"], "pass")
        payloads = self._payloads()
        payloads[self.RCPT + EXPAND]["Members"][0]["RecipientSettings"]["Enabledstate"] = False
        post = checks._collect_alerting(_FakeCtx(payloads))["normalized"]
        diff = _loader.diffcore.diff_check(pre, post, compare)
        self.assertEqual(
            [(row["key"], row["field"], row["old"], row["new"]) for row in diff["changed"]],
            [("recipient|1", "enabled", True, False)],
        )


if __name__ == "__main__":
    unittest.main()
