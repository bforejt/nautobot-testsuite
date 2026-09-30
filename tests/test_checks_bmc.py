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


class TestSecurityState(unittest.TestCase):
    def test_normalize_finds_fields_under_nested_blocks(self):
        view, sources = checks._normalize_security_state(_fx("xcc_security.json"))
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

    def test_normalize_plain_resource_has_no_sources(self):
        view, sources = checks._normalize_security_state(_fx("xcc_security_plain.json"))
        self.assertEqual(sources, {})
        self.assertTrue(all(value is None for value in view.values()))

    def test_collector_present(self):
        ctx = _FakeCtx(_base_payloads())
        result = checks._collect_security_state(ctx)
        self.assertEqual(result["normalized"]["lockdown_mode"], "Inactive")
        self.assertEqual(result["context"]["security_resource"], MGR + "/Oem/Lenovo/Security")
        self.assertEqual(result["context"]["key_management"]["KeyManagementType"], "Local")
        self.assertNotIn("ClientCertificatePassword", result["context"]["key_management"])
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

    def test_collector_not_present_when_thinkedge_fields_absent(self):
        payloads = _base_payloads()
        payloads[MGR + "/Oem/Lenovo/Security"] = _fx("xcc_security_plain.json")
        with self.assertRaises(checks.SkipCheck):
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

    def test_collector_and_empty_temperatures_is_a_failed_read(self):
        ctx = _FakeCtx(_base_payloads())
        result = checks._collect_thermal(ctx)
        self.assertEqual(ctx.gets, RESOLVE + [CH + "/Thermal"])
        self.assertIn("temp|Ambient Temp", result["normalized"])
        payloads = _base_payloads()
        payloads[CH + "/Thermal"]["Temperatures"] = []
        with self.assertRaises(checks.CollectError):
            checks._collect_thermal(_FakeCtx(payloads))

    def test_bands_declared_as_the_plan_states(self):
        compare = registry.CHECKS["bmc_thermal"].compare
        self.assertEqual(compare["fields"]["reading_c"]["tolerance"], {"abs": 8})
        self.assertEqual(compare["fields"]["reading"]["tolerance"], {"pct": 25})


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
        self.assertEqual(ctx.gets, RESOLVE + [CH + "/Power"])
        self.assertNotIn("Actions", result["raw"][CH + "/Power"])
        self.assertEqual(
            registry.CHECKS["bmc_power"].compare["fields"]["line_input_voltage"]["tolerance"],
            {"pct": 10},
        )


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
            ],
        )
        self.assertEqual(result["context"]["collections"]["memory"]["strategy"], "expand")
        self.assertEqual(result["context"]["collections"]["memory"]["members"], 4)
        self.assertEqual(result["context"]["host_power_state"], "On")
        self.assertEqual(result["context"]["unmeasured"], [])
        self.assertIn("dimm|DIMM_1", result["normalized"])
        processors_raw = result["raw"][SYS + "/Processors" + EXPAND]
        # Clock speed is a reading: kept in raw and context, absent from the rows.
        self.assertIn("CurrentClockSpeedMHz", processors_raw["Members"][0])
        self.assertEqual(processors_raw["Members"][0]["TotalCores"], 16)
        self.assertEqual(
            result["context"]["clock_speed_mhz"],
            {"1": processors_raw["Members"][0]["CurrentClockSpeedMHz"]},
        )
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
        # Advertised but refused with an HTTP error -> walk.
        payloads = _base_payloads()
        ctx = _FakeCtx(payloads, errors={SYS + "/Memory" + EXPAND: 501})
        result = checks._collect_inventory(ctx)
        self.assertEqual(result["context"]["collections"]["memory"]["strategy"], "members")
        self.assertEqual(result["context"]["collections"]["memory"]["expand_refused"], "HTTP 501")
        self.assertEqual(result["context"]["collections"]["processors"]["strategy"], "expand")
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
        # 40 DIMM links > what the 16-GET budget has left after root + system + collection.
        collection = payloads[SYS + "/Memory"]
        collection["Members"] = [{"@odata.id": SYS + "/Memory/DIMM_%d" % (i,)} for i in range(40)]
        ctx = _FakeCtx(payloads)
        with self.assertRaises(checks.CollectError) as caught:
            checks._collect_inventory(ctx)
        self.assertIn("40 members", str(caught.exception))
        self.assertFalse([path for path in ctx.gets if path.startswith(SYS + "/Memory/DIMM_")])


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
        self.assertEqual(len(view), 15)
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
            ctx.gets, RESOLVE + ["/redfish/v1/UpdateService/FirmwareInventory" + EXPAND]
        )
        self.assertEqual(result["context"]["strategy"], "expand")
        self.assertEqual(result["context"]["members"], 15)
        raw = result["raw"]["/redfish/v1/UpdateService/FirmwareInventory" + EXPAND]
        self.assertNotIn("@odata.etag", raw["Members"][0])

    def test_collector_walk_sorted_by_link_and_complete(self):
        ctx = _FakeCtx(_without_expand(_base_payloads()))
        result = checks._collect_firmware(ctx)
        self.assertEqual(result["context"]["strategy"], "members")
        self.assertEqual(len(result["normalized"]), 15)
        # resolution (root, Systems, System), expand attempt (404), collection, members
        self.assertEqual(len(ctx.gets), 3 + 1 + 1 + 15)

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
                "event_id": "0x810700C8",
                "hidden": False,
            },
        )
        self.assertIs(view["sel|FQXSPPW0003I|120"]["serviceable"], True)
        self.assertNotIn("message", view["sel|FQXSPPW0003I|120"])
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
                SYS + "/LogServices",
                SYS + "/LogServices/PlatformLog",
                SYS + "/LogServices/PlatformLog/Entries",
            ],
        )
        self.assertFalse([path for path in ctx.gets if "$top" in path or "?" in path])
        # every Entries page passes the log redactor, every other read the scrubber
        self.assertIn((SYS + "/LogServices/PlatformLog/Entries", "_redact_log_page"), ctx.redacted)
        self.assertIn((SYS + "/LogServices", "_scrub_payload"), ctx.redacted)
        self.assertEqual(result["context"]["log_service_used"], "PlatformLog")
        self.assertEqual(result["context"]["pages"], 1)
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


class TestBios(unittest.TestCase):
    def test_normalize_curated_tokens(self):
        view = checks._normalize_bios(_fx("xcc_bios.json"))
        self.assertEqual(view["bios|Processors_HyperThreading"], "Enable")
        self.assertEqual(view["bios|Devices_and_IO_Ports_IntelVTforDirectedIOVTd"], "Enable")
        self.assertEqual(view["bios|Devices_and_IO_Ports_SRIOV"], "Enable")
        self.assertEqual(view["bios|OperatingModes_ChooseOperatingMode"], "MaximumPerformance")
        self.assertEqual(view["bios|Processors_CStates"], "Disable")
        self.assertEqual(view["bios|Processors_C1EnhancedMode"], "Disable")
        self.assertEqual(view["bios|Processors_TurboMode"], "Enable")
        self.assertEqual(view["bios|BootModes_SystemBootMode"], "UEFIMode")
        self.assertEqual(view["bios|Devices_and_IO_Ports_Above4GBMMIO"], "Enable")
        self.assertEqual(view["bios|SystemSecurity_TPMSetting"], "Enable")
        self.assertNotIn("bios|SystemSecurity_AdminPassword", view)
        self.assertNotIn("bios|Q00001_Password", view)
        self.assertNotIn("bios|SystemInformation_SerialNumber", view)
        self.assertNotIn("bios|Memory_MemoryMode", view)

    def test_collector_raw_curated_and_capped(self):
        ctx = _FakeCtx(_base_payloads())
        result = checks._collect_bios(ctx)
        self.assertEqual(ctx.gets, RESOLVE + [SYS + "/Bios"])
        raw = result["raw"][SYS + "/Bios"]
        self.assertNotIn("Attributes", raw)
        self.assertNotIn("Actions", raw)
        self.assertIn("Processors_HyperThreading", raw["attributes_selected"])
        self.assertIn("Memory_MemoryMode=Independent", raw["attributes_other"])
        self.assertNotIn("AdminPassword", raw["attributes_other"])
        self.assertEqual(result["context"]["attributes_total"], 29)
        self.assertEqual(result["context"]["attributes_selected"], len(result["normalized"]))
        self.assertEqual(
            result["context"]["attribute_registry"], "BiosAttributeRegistryHYE134C-2.31"
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
            ],
        )
        self.assertEqual(result["context"]["strategy"], "expand")
        self.assertEqual(result["context"]["drives_total"], 2)
        self.assertEqual(result["context"]["volumes_total"], 1)
        self.assertNotIn("Actions", result["raw"][SYS + "/Storage/RAID_Slot1/Drives/Disk.0"])

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

    def test_normalize_without_nic(self):
        view = checks._normalize_manager_network(_fx("xcc_network_protocol.json"), None)
        self.assertIsNone(view["ipv4_address"])
        self.assertEqual(view["dns_servers"], [])
        self.assertEqual(view["hostname"], "se350-a-xcc")

    def test_collector(self):
        ctx = _FakeCtx(_base_payloads())
        result = checks._collect_manager_network(ctx)
        self.assertEqual(
            ctx.gets, RESOLVE + [MGR + "/NetworkProtocol", MGR + "/EthernetInterfaces/NIC"]
        )
        self.assertEqual(result["context"]["snmp_source"], "SNMP.ProtocolEnabled")
        self.assertEqual(result["context"]["manager_nic"]["member"], "NIC")
        self.assertEqual(result["context"]["nic_speed_mbps"], 1000)
        self.assertEqual(result["context"]["nic_link_status"], "LinkUp")
        self.assertIn(MGR + "/EthernetInterfaces/NIC", result["raw"])
        self.assertNotIn("Actions", result["raw"][MGR + "/NetworkProtocol"])


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

    def test_normalize_without_location_or_security(self):
        chassis = _fx("xcc_chassis.json")
        del chassis["Location"]
        del chassis["PhysicalSecurity"]
        view = checks._normalize_chassis_location(chassis)
        self.assertIsNone(view["location_info"])
        self.assertIsNone(view["intrusion_sensor"])
        self.assertFalse([key for key in view if key.startswith("postal_")])

    def test_collector(self):
        ctx = _FakeCtx(_base_payloads())
        result = checks._collect_chassis_location(ctx)
        self.assertEqual(ctx.gets, RESOLVE + [CH])
        self.assertIs(result["context"]["location_present"], True)
        self.assertIs(result["context"]["physical_security_present"], True)
        self.assertEqual(result["context"]["indicator_led"], "Off")
        self.assertNotIn("Actions", result["raw"][CH])


class TestWholeFamily(unittest.TestCase):
    def test_every_check_succeeds_on_the_fixture_set_within_its_budget(self):
        ctx = _FakeCtx(_base_payloads())
        for check in registry.checks_for("bmc"):
            result = check.collector(ctx)
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
        self.assertLessEqual(len(ctx.gets), 31)
        # No request ever carried a query other than the allowlisted $expand.
        for path in ctx.gets:
            self.assertIsNone(_loader.redfish_paths.path_refusal(path), path)
            if "?" in path:
                self.assertTrue(path.endswith(EXPAND), path)

    def test_every_check_succeeds_without_expand_support(self):
        ctx = _FakeCtx(_without_expand(_base_payloads()))
        for check in registry.checks_for("bmc"):
            result = check.collector(ctx)
            self.assertTrue(result["normalized"], check.id)
        self.assertLessEqual(len(ctx.gets), 61)


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
            result = check.collector(ctx)
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
            check.collector(ctx)
        self.assertTrue(ctx.redacted)
        for path, redactor in ctx.redacted:
            self.assertIn(redactor, ("_scrub_payload", "_redact_log_page"), path)


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
        self.assertLessEqual(len(ctx.gets), checks._BUDGET_STORAGE)


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
        report = checks._discover_account(ctx)
        self.assertEqual(report["role_id"], "CustomRole4")
        self.assertEqual(report["oem_privileges"], ["ReadOnly"])
        self.assertEqual(report["account_types"], ["Redfish", "WebUI"])
        self.assertNotIn("admin-person", json.dumps(report))
        self.assertNotIn("netops", json.dumps(report))


if __name__ == "__main__":
    unittest.main()
