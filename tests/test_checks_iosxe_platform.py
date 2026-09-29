"""checks_iosxe_platform: persistence, licensing, PKI and TCAM normalizers, context, collectors.

Driven by sanitized captures of the 9300 lab: the ``*_lab`` fixtures for the
rec-1 filtered install read, licensing/state, 'show license summary', 'show
sdm prefer', tcam-details, switch-dp-resources (unfiltered, 109 KB) and the
shared device-hardware read. iosxe_crypto_pki_oper.json is the one fixture
the device could NOT supply — the lab release answers HTTP 500 on
crypto-pki-oper-data — so it is hand-built to the 17.15.1 model
(Cisco-IOS-XE-crypto-pki-oper.yang, rev 2022-11-01) from the sanitized 'show
crypto pki certificates' listing, and the tests require the two sources to
normalize to the same certificate keys. The lab payload carries
unsaved-config false; true and an unserved leaf are exercised on edited
copies. No Nautobot, no network.
"""

import copy
import datetime
import json
import unittest

if __package__:
    from . import _loader
else:  # unittest discover -s tests imports test modules as top-level
    import _loader

platform = _loader.CHECK_MODULES["checks_iosxe_platform"]
common = _loader.load("iosxe_common")
registry = _loader.registry
diffcore = _loader.diffcore
J = _loader.fixture_json
T = _loader.fixture_text

EXPECTED_IDS = {"iosxe_persistence", "iosxe_license", "iosxe_pki", "iosxe_tcam"}

HW = "iosxe_device_hardware_lab.json"
INSTALL = "iosxe_install_location_information_lab.json"
LICENSE = "iosxe_smart_license_state_lab.json"
LICENSE_CLI = "iosxe_show_license_summary_lab.txt"
SDM = "iosxe_show_sdm_prefer_lab.txt"
PKI = "iosxe_crypto_pki_oper.json"
PKI_CLI = "iosxe_show_crypto_pki_certificates_lab.txt"
TCAM = "iosxe_tcam_details_lab.json"
DP = "iosxe_switch_dp_resources_lab.json"

REFUSED = "% Invalid input detected at '^' marker."
NOW = datetime.datetime(2026, 9, 29, 12, 0, 0, tzinfo=datetime.timezone.utc)


class _Http(Exception):
    """Stand-in for RestconfError: carries the HTTP status the collectors inspect."""

    def __init__(self, status):
        super().__init__("HTTP %s" % (status,))
        self.status_code = status


class _Ctx:
    """Duck-typed CollectorContext.

    GET paths route to payloads by the LONGEST token found in the resource
    path (the part before any ?fields=). A payload may be an exception
    (raised) or a callable (called with the full path). Unknown paths answer
    None under ok_404 (the 404 case). ``ssh`` maps commands to outputs; an
    exception value is raised; ``ssh=None`` means no SSH transport.
    """

    def __init__(self, payloads=None, ssh=None):
        self.payloads = payloads or {}
        self.ssh_outputs = ssh
        self.calls = []
        self.kwargs = []
        self.ssh_calls = []
        self.redactors = {}
        self.platform = "iosxe"
        self.device_name = "sw-test"

    def get(self, path, **kwargs):
        self.calls.append(path)
        self.kwargs.append(kwargs)
        resource = path.split("?", 1)[0]
        tokens = sorted((t for t in self.payloads if t in resource), key=len, reverse=True)
        if not tokens:
            if kwargs.get("ok_404"):
                return None
            raise AssertionError("unexpected GET %s" % (path,))
        payload = self.payloads[tokens[0]]
        if isinstance(payload, Exception):
            raise payload
        if callable(payload):
            return payload(path)
        return payload

    @property
    def has_ssh(self):
        return self.ssh_outputs is not None

    def run_ssh(self, command, **kwargs):
        # Mirrors CollectorContext.run_ssh: a ``redact`` callable is recorded
        # and applied to the returned output (the real one traces the same copy).
        self.ssh_calls.append(command)
        self.redactors[command] = kwargs.get("redact")
        output = self.ssh_outputs.get(command, "")
        if isinstance(output, Exception):
            raise output
        return output if kwargs.get("redact") is None else kwargs["redact"](output)


def _reject_fields(payload):
    """A payload callable: HTTP 400 for the filtered path, ``payload`` unfiltered."""

    def answer(path):
        if "?fields=" in path:
            raise _Http(400)
        return payload

    return answer


def _system_data_with(unsaved):
    """The lab hardware payload with its unsaved-config leaf set, or removed for None
    (a release that does not serve the leaf)."""
    payload = copy.deepcopy(J(HW))
    system = payload[common.HW_CONTAINER]["device-hardware"]["device-system-data"]
    if unsaved is None:
        system.pop("unsaved-config", None)
    else:
        system["unsaved-config"] = unsaved
    return payload


def _assert_stable_types(case, normalized):
    for key, facts in normalized.items():
        case.assertIsInstance(facts, dict, key)
        for facet, value in facts.items():
            case.assertIsInstance(value, (str, int, float, bool, list, type(None)), key)
            if isinstance(value, list):
                for item in value:
                    case.assertIsInstance(item, str, "%s.%s" % (key, facet))
    json.dumps(normalized)


# =============================================================================
# contract
# =============================================================================


class TestContract(unittest.TestCase):
    def test_this_module_owns_exactly_its_catalog(self):
        owned = {
            check.id
            for check in registry.CHECKS.values()
            if check.collector.__module__ == platform.__name__
        }
        self.assertEqual(owned, EXPECTED_IDS)
        for check_id in EXPECTED_IDS:
            check = registry.CHECKS[check_id]
            self.assertEqual(check.platform, "iosxe")
            self.assertIn(check.compare["mode"], diffcore.MODES, check_id)
            self.assertIn("platform", check.tags)
        self.assertEqual(
            {c.id for c in registry.checks_for("iosxe") if c.id in EXPECTED_IDS}, EXPECTED_IDS
        )

    def test_tiers_and_tolerance(self):
        self.assertEqual(registry.CHECKS["iosxe_persistence"].tier, 1)
        self.assertEqual(registry.CHECKS["iosxe_license"].tier, 1)
        self.assertEqual(registry.CHECKS["iosxe_pki"].tier, 1)
        self.assertEqual(registry.CHECKS["iosxe_tcam"].tier, 3)
        compare = registry.CHECKS["iosxe_tcam"].compare
        self.assertEqual(compare["fields"]["used_pct"]["tolerance"], {"abs": 5.0})

    def test_semantics_merged_into_the_registry(self):
        for check_id in EXPECTED_IDS:
            self.assertIn(check_id, registry.SEMANTICS, check_id)
            self.assertEqual(registry.SEMANTICS[check_id], platform.SEMANTICS[check_id])
        self.assertIn("5 percentage points", platform.SEMANTICS["iosxe_tcam"])
        self.assertIn("self-signed", platform.SEMANTICS["iosxe_pki"].lower())
        self.assertIn("unsaved-config", platform.SEMANTICS["iosxe_persistence"])
        self.assertIn("show license summary", platform.SEMANTICS["iosxe_license"])

    def test_key_models_for_the_shakedown(self):
        self.assertEqual(
            platform.KEY_MODELS,
            (
                "Cisco-IOS-XE-device-hardware-oper",
                "Cisco-IOS-XE-install-oper",
                "cisco-smart-license",
                "Cisco-IOS-XE-crypto-pki-oper",
                "Cisco-IOS-XE-tcam-oper",
                "Cisco-IOS-XE-switch-dp-resources-oper",
            ),
        )

    def test_reads_are_read_only_and_ssh_commands_are_shows(self):
        for command in (platform._SDM_COMMAND, platform._LICENSE_COMMAND, platform._PKI_COMMAND):
            self.assertTrue(command.startswith("show "), command)
        # the shared hardware read is spelled like every other module's, so
        # the per-run cache issues it once
        self.assertEqual(
            common.HW_PATH, "/data/Cisco-IOS-XE-device-hardware-oper:device-hardware-data"
        )


# =============================================================================
# iosxe_persistence
# =============================================================================


class TestPersistenceNormalizers(unittest.TestCase):
    def setUp(self):
        self.rows = platform._install_rows(J(INSTALL))
        self.system = platform._system_data(J(HW))

    def test_install_key_is_the_full_list_key(self):
        normalized = platform._normalize_install(self.rows)
        self.assertEqual(list(normalized), ["install|1|rp|0|0"])

    def test_running_image_falls_back_to_the_provisioned_row(self):
        # the lab flags neither version is-default; the committed one runs,
        # the older image left on flash is merely present
        facts = platform._normalize_install(self.rows)["install|1|rp|0|0"]
        self.assertEqual(
            facts,
            {
                "boot_mode": "install",
                "version": "17.15.06.0.770",
                "state": "provisioned-committed",
                "commit_type": "user",
                "abort_timer": "inactive",
                "images": [
                    "17.12.04.0.5766 present",
                    "17.15.06.0.770 provisioned-committed",
                ],
            },
        )

    def test_is_default_and_uncommitted_rows_win_in_that_order(self):
        rows = copy.deepcopy(self.rows)
        versions = rows[0]["install-version-info"]
        versions[0]["current"] = "install-version-state-provisioned-uncommitted"
        versions[0]["commit-type"] = "install-commit-pend"
        rows[0]["oper-state"]["auto-abort-timer"] = {
            "state": "install-timer-state-active",
            "end-time": "2026-09-29T17:12:00.000+00:00",
        }
        rows[0]["oper-state"]["boot-mode"] = "install-boot-mode-install"
        facts = platform._normalize_install(rows)["install|1|rp|0|0"]
        self.assertEqual(facts["version"], "17.15.06.0.770")
        self.assertEqual(facts["state"], "provisioned-uncommitted")
        self.assertEqual(facts["commit_type"], "pend")
        self.assertEqual(facts["abort_timer"], "active")
        self.assertEqual(facts["boot_mode"], "install")
        context = platform._persistence_context(self.system, rows)
        self.assertEqual(context["install|1|rp|0|0"]["abort_timer_end"], "2026-09-29T17:12:00Z")
        versions[1]["is-default"] = True
        self.assertEqual(
            platform._normalize_install(rows)["install|1|rp|0|0"]["version"], "17.12.04.0.5766"
        )

    def test_version_extension_joins_the_version(self):
        rows = copy.deepcopy(self.rows)
        rows[0]["install-version-info"][0]["version-extension"] = "1"
        facts = platform._normalize_install(rows)["install|1|rp|0|0"]
        self.assertEqual(facts["version"], "17.15.06.0.770.1")

    def test_device_key_on_the_lab_payload(self):
        sdm = platform._parse_sdm_prefer(T(SDM))
        self.assertEqual(
            platform._normalize_device(self.system, sdm),
            {
                "config_saved": True,
                "software_version": "17.15.6",
                "sdm_template": "Access",
                "sdm_template_next": None,
            },
        )

    def test_config_saved_inverts_the_leaf_when_served(self):
        for unsaved, saved in ((False, True), (True, False), ("true", False)):
            system = platform._system_data(_system_data_with(unsaved))
            self.assertEqual(platform._normalize_device(system)["config_saved"], saved, unsaved)
        self.assertEqual(
            platform._persistence_context(platform._system_data(_system_data_with(False)), [])[
                "config_saved_source"
            ],
            "unsaved-config leaf",
        )

    def test_software_version_word(self):
        self.assertEqual(platform._software_version("Version 17.15.6, RELEASE"), "17.15.6")
        self.assertEqual(platform._software_version("Cisco IOS XE 17.9\nmore"), "Cisco IOS XE 17.9")
        self.assertIsNone(platform._software_version(""))
        self.assertIsNone(platform._software_version(None))

    def test_sdm_prefer_parsing(self):
        self.assertEqual(platform._parse_sdm_prefer(T(SDM)), {"template": "Access", "next": None})
        pending = T(SDM) + '\nOn next reload, template will be "Advanced" template.\n'
        self.assertEqual(
            platform._parse_sdm_prefer(pending), {"template": "Access", "next": "Advanced"}
        )
        self.assertEqual(platform._parse_sdm_prefer(""), {"template": None, "next": None})

    def test_context_on_the_lab_payload(self):
        context = platform._persistence_context(self.system, self.rows)
        self.assertEqual(context["rommon_version"], "IOS-XE ROMMON")
        self.assertEqual(context["config_saved_source"], "unsaved-config leaf")
        self.assertIn("Version 17.15.6", context["software_banner"])
        without = platform._persistence_context(platform._system_data(_system_data_with(None)), [])
        self.assertEqual(
            without["config_saved_source"], "unsaved-config leaf not served on this release"
        )
        self.assertEqual(context["install_rows"], 1)
        self.assertEqual(context["install|1|rp|0|0"], {"abort_timer_end": None, "images": 2})

    def test_two_healthy_captures_diff_to_nothing(self):
        first = {
            "device": platform._normalize_device(self.system, platform._parse_sdm_prefer(T(SDM)))
        }
        first.update(platform._normalize_install(self.rows))
        again = {
            "device": platform._normalize_device(
                platform._system_data(copy.deepcopy(J(HW))), platform._parse_sdm_prefer(T(SDM))
            )
        }
        again.update(platform._normalize_install(platform._install_rows(copy.deepcopy(J(INSTALL)))))
        self.assertEqual(first, again)
        self.assertEqual(
            diffcore.diff_check(first, again, {"mode": "equality_set"})["result"], "pass"
        )
        _assert_stable_types(self, first)


class TestPersistenceCollector(unittest.TestCase):
    def _ctx(self, **overrides):
        payloads = {
            "device-hardware-data": J(HW),
            "install-location-information": J(INSTALL),
        }
        payloads.update(overrides.pop("payloads", {}))
        ssh = overrides.pop("ssh", {"show sdm prefer": T(SDM)})
        return _Ctx(payloads, ssh=ssh)

    def test_raw_keyed_by_exact_paths_and_command(self):
        ctx = self._ctx()
        result = platform._collect_persistence(ctx)
        self.assertEqual(
            set(result["raw"]),
            {
                common.HW_PATH,
                "%s?fields=%s" % (platform._INSTALL_PATH, platform._INSTALL_FIELDS),
                "show sdm prefer",
            },
        )
        self.assertIn(common.HW_PATH, ctx.calls)
        self.assertEqual(ctx.kwargs[ctx.calls.index(common.HW_PATH)], {})
        self.assertEqual(ctx.ssh_calls, ["show sdm prefer"])
        self.assertEqual(set(result["normalized"]), {"device", "install|1|rp|0|0"})
        self.assertEqual(result["context"]["install_fields_filter"], "accepted")
        # raw keeps only the device-system-data of the shared hardware read
        hardware = result["raw"][common.HW_PATH][common.HW_CONTAINER]["device-hardware"]
        self.assertEqual(set(hardware), {"device-system-data"})

    def test_install_404_omits_the_install_keys_with_a_note(self):
        ctx = self._ctx()
        del ctx.payloads["install-location-information"]
        result = platform._collect_persistence(ctx)
        self.assertEqual(set(result["normalized"]), {"device"})
        self.assertIn("install-oper not served (404)", result["raw"]["note"])
        self.assertIsNone(result["context"]["install_fields_filter"])

    def test_install_served_empty_is_noted(self):
        ctx = self._ctx(payloads={"install-location-information": {}})
        result = platform._collect_persistence(ctx)
        self.assertEqual(set(result["normalized"]), {"device"})
        self.assertIn("served empty", result["raw"]["note"])

    def test_fields_rejection_retries_unfiltered_once(self):
        ctx = self._ctx(payloads={"install-location-information": _reject_fields(J(INSTALL))})
        result = platform._collect_persistence(ctx)
        self.assertIn(platform._INSTALL_PATH, result["raw"])
        self.assertIn("fields filter rejected", result["raw"]["note"])
        self.assertEqual(result["context"]["install_fields_filter"], common.FILTER_REJECTED)
        self.assertEqual(result["normalized"]["install|1|rp|0|0"]["version"], "17.15.06.0.770")

    def test_other_http_errors_propagate(self):
        ctx = self._ctx(payloads={"install-location-information": _Http(503)})
        with self.assertRaises(_Http):
            platform._collect_persistence(ctx)

    def test_missing_system_data_is_a_collect_error(self):
        ctx = self._ctx(payloads={"device-hardware-data": {common.HW_CONTAINER: {}}})
        with self.assertRaises(registry.CollectError):
            platform._collect_persistence(ctx)

    def test_no_ssh_leaves_sdm_unmeasured(self):
        result = platform._collect_persistence(self._ctx(ssh=None))
        self.assertIsNone(result["normalized"]["device"]["sdm_template"])
        self.assertIn("no SSH transport", result["raw"]["note"])
        self.assertNotIn("show sdm prefer", result["raw"])

    def test_refused_sdm_command_is_noted(self):
        result = platform._collect_persistence(self._ctx(ssh={"show sdm prefer": REFUSED}))
        self.assertIsNone(result["normalized"]["device"]["sdm_template"])
        self.assertIn("refused", result["raw"]["note"])

    def test_unsaved_config_served(self):
        for unsaved, saved in ((False, True), (True, False)):
            ctx = self._ctx(payloads={"device-hardware-data": _system_data_with(unsaved)})
            result = platform._collect_persistence(ctx)
            self.assertEqual(result["normalized"]["device"]["config_saved"], saved)
            self.assertEqual(result["context"]["config_saved_source"], "unsaved-config leaf")

    def test_no_secrets_or_users_in_normalized(self):
        result = platform._collect_persistence(self._ctx())
        self.assertNotIn("netops", json.dumps(result["normalized"]))


# =============================================================================
# iosxe_license
# =============================================================================


class TestLicenseNormalizers(unittest.TestCase):
    def setUp(self):
        self.state = platform._license_state(J(LICENSE))
        self.normalized = platform._normalize_license_model(self.state)

    def test_state_container_from_either_wrapper(self):
        whole = {"cisco-smart-license:licensing": {"config": {}, "state": self.state}}
        self.assertEqual(platform._license_state(whole), self.state)
        self.assertEqual(platform._license_state({}), {})
        self.assertEqual(platform._license_state(None), {})

    def test_level_in_effect_on_the_lab(self):
        self.assertEqual(
            self.normalized["licensing"],
            {
                "smart_enabled": True,
                "registration": "not-registered",
                "authorization": "none",
                "transport": "callhome",
                "eval_in_use": False,
                "eval_expired": False,
                "policy": None,
                "level": "network-essentials",
                "dna_level": "dna-essentials",
            },
        )
        self.assertEqual(
            self.normalized["license|network-essentials"],
            {"count": 1, "enforcement": "invalid-tag", "status": "in-use"},
        )
        self.assertEqual(
            set(self.normalized),
            {"licensing", "license|network-essentials", "license|dna-essentials"},
        )

    def test_usage_name_fallbacks(self):
        self.assertEqual(platform._usage_name({"license-name": "x", "short-name": "y"}), "x")
        self.assertEqual(platform._usage_name({"license-name": "", "short-name": "y"}), "y")
        self.assertEqual(
            platform._usage_name(
                {"entitlement-tag": "regid.2017-05.com.cisco.C9300_48P_NW_essentialsk9,1.0_abc"}
            ),
            "C9300_48P_NW_essentialsk9",
        )
        self.assertIsNone(platform._usage_name({}))

    def test_context_on_the_lab(self):
        context = platform._license_context(self.state)
        self.assertEqual(context["agent_version"], "6.1.4/6feb8bc10")
        self.assertEqual(context["eval_days_left"], 0.0)
        self.assertIsNone(context["registration_expire_time"])
        self.assertEqual(context["licenses_in_use"], 2)
        self.assertFalse(context["export_control_allowed"])

    def test_context_deadlines_when_served(self):
        state = copy.deepcopy(self.state)
        info = state["state-info"]
        info["evaluation"] = {
            "eval-in-use": True,
            "eval-expired": False,
            "eval-period-left": {"time-left": 86400 * 3},
        }
        info["authorization"] = {
            "authorization-state": "auth-state-out-of-compliance",
            "authorization-out-of-compliance": {
                "comm-deadline-time": "2026-12-01T00:00:00+00:00",
                "ooc-time": "2026-09-01T10:00:00+00:00",
            },
        }
        info["registration"]["registration-complete"] = {"expire-time": "2027-01-01T00:00:00+00:00"}
        context = platform._license_context(state)
        self.assertEqual(context["eval_days_left"], 3.0)
        self.assertEqual(context["authorization_deadline"], "2026-12-01T00:00:00Z")
        self.assertEqual(context["out_of_compliance_since"], "2026-09-01T10:00:00Z")
        self.assertEqual(context["registration_expire_time"], "2027-01-01T00:00:00Z")
        self.assertEqual(
            platform._normalize_license_model(state)["licensing"]["authorization"],
            "out-of-compliance",
        )

    def test_raw_projection_drops_udi_and_account_material(self):
        raw = platform._license_raw(J(LICENSE))
        text = json.dumps(raw)
        for banned in (
            "udi",
            "FOC8704M57A",
            "customer-info",
            "custom-id",
            "subscription-id",
            "mac-address",
        ):
            self.assertNotIn(banned, text, banned)
        state = raw["cisco-smart-license:state"]
        self.assertEqual(state["state-info"]["usage"][0]["license-name"], "network-essentials")
        self.assertIn("evaluation", state["state-info"])
        self.assertEqual(
            state["state-info"]["transport"], {"transport-type": "transport-type-callhome"}
        )

    def test_cli_summary_parses_the_lab_and_older_layouts(self):
        summary = platform._parse_license_summary(T(LICENSE_CLI))
        self.assertEqual(
            summary["licenses"],
            [
                {"name": "network-essentials", "count": 1, "status": "in-use"},
                {"name": "dna-essentials", "count": 1, "status": "in-use"},
            ],
        )
        self.assertIsNone(summary["registration"])
        older = (
            "Smart Licensing is ENABLED\n\nRegistration:\n  Status: REGISTERED\n"
            "  Smart Account: Example\n\nLicense Authorization:\n"
            "  Status: AUTHORIZED on Jan 01 2026\n\n"
            "License Usage:\n  License  Entitlement tag  Count Status\n  ---\n"
            "  network-advantage  (C9300-24 Network Advan...)  1 IN USE\n"
            "  dna-advantage  (C9300-24 DNA Advantage)  1 IN USE\n"
        )
        summary = platform._parse_license_summary(older)
        self.assertEqual(summary["registration"], "registered")
        self.assertEqual(summary["authorization"], "authorized")
        normalized = platform._normalize_license_cli(summary)
        self.assertEqual(normalized["licensing"]["level"], "network-advantage")
        self.assertEqual(normalized["licensing"]["dna_level"], "dna-advantage")
        self.assertIsNone(normalized["licensing"]["smart_enabled"])
        self.assertEqual(
            set(normalized["license|network-advantage"]), {"count", "enforcement", "status"}
        )
        self.assertEqual(set(normalized["licensing"]), set(self.normalized["licensing"]))
        self.assertEqual(platform._parse_license_summary(REFUSED)["licenses"], [])

    def test_two_healthy_captures_diff_to_nothing(self):
        again = platform._normalize_license_model(
            platform._license_state(copy.deepcopy(J(LICENSE)))
        )
        self.assertEqual(self.normalized, again)
        self.assertEqual(
            diffcore.diff_check(self.normalized, again, {"mode": "equality_set"})["result"], "pass"
        )
        _assert_stable_types(self, self.normalized)


class TestLicenseCollector(unittest.TestCase):
    def test_model_read_raw_keyed_by_the_filtered_path(self):
        ctx = _Ctx({"licensing/state": J(LICENSE)}, ssh={"show license summary": T(LICENSE_CLI)})
        result = platform._collect_license(ctx)
        path = "%s?fields=%s" % (platform._LICENSE_PATH, platform._LICENSE_FIELDS)
        self.assertEqual(set(result["raw"]), {path})
        self.assertEqual(result["context"]["source"], "cisco-smart-license")
        self.assertEqual(result["context"]["fields_filter"], "accepted")
        self.assertEqual(ctx.ssh_calls, [])
        self.assertEqual(result["normalized"]["licensing"]["level"], "network-essentials")
        self.assertNotIn("udi", json.dumps(result["raw"]))

    def test_fields_rejection_retries_unfiltered_and_projects_raw(self):
        ctx = _Ctx({"licensing/state": _reject_fields(J(LICENSE))})
        result = platform._collect_license(ctx)
        self.assertEqual(set(result["raw"]), {platform._LICENSE_PATH, "note"})
        self.assertNotIn("udi", json.dumps(result["raw"]))
        self.assertEqual(result["context"]["fields_filter"], common.FILTER_REJECTED)

    def test_404_falls_back_to_the_cli(self):
        ctx = _Ctx({}, ssh={"show license summary": T(LICENSE_CLI)})
        result = platform._collect_license(ctx)
        self.assertEqual(result["context"]["source"], "show license summary")
        self.assertEqual(set(result["raw"]), {"show license summary", "note"})
        self.assertIn("not served (404)", result["raw"]["note"])
        self.assertEqual(result["normalized"]["licensing"]["level"], "network-essentials")
        self.assertIsNone(result["normalized"]["license|dna-essentials"]["enforcement"])

    def test_empty_state_falls_back_to_the_cli(self):
        ctx = _Ctx({"licensing/state": {}}, ssh={"show license summary": T(LICENSE_CLI)})
        result = platform._collect_license(ctx)
        self.assertEqual(result["context"]["source"], "show license summary")
        self.assertIn("served empty", result["raw"]["note"])

    def test_404_without_ssh_is_not_present(self):
        with self.assertRaises(registry.SkipCheck):
            platform._collect_license(_Ctx({}, ssh=None))

    def test_404_and_refused_cli_is_not_present(self):
        with self.assertRaises(registry.SkipCheck):
            platform._collect_license(_Ctx({}, ssh={"show license summary": REFUSED}))
        with self.assertRaises(registry.SkipCheck):
            platform._collect_license(_Ctx({}, ssh={"show license summary": "License Usage:\n"}))

    def test_other_http_errors_propagate(self):
        with self.assertRaises(_Http):
            platform._collect_license(_Ctx({"licensing/state": _Http(500)}))


# =============================================================================
# iosxe_pki
# =============================================================================


class TestPkiNormalizers(unittest.TestCase):
    def setUp(self):
        self.model = platform._normalize_pki_model(J(PKI))
        self.certs = platform._parse_pki_certificates(T(PKI_CLI))
        self.cli = platform._normalize_pki_cli(self.certs)

    def test_cli_parser_reads_every_block(self):
        self.assertEqual(len(self.certs), 10)
        first = self.certs[0]
        self.assertEqual(first["header"], "Certificate")
        self.assertEqual(first["status"], "available")
        self.assertEqual(first["usage"], "general-purpose")
        self.assertEqual(first["trustpoints"], ["CISCO_IDEVID_CMCA_SUDI"])
        self.assertEqual(first["issuer"], ["cn=Cisco Manufacturing CA", "o=Cisco Systems"])
        self.assertEqual(
            first["end"], datetime.datetime(2029, 5, 14, 20, 25, 42, tzinfo=datetime.timezone.utc)
        )
        # a trustpoint the listing repeats on one certificate is listed once
        root = [
            c for c in self.certs if c["subject"] == ["cn=Cisco Root CA 2048", "o=Cisco Systems"]
        ]
        self.assertEqual(
            root[0]["trustpoints"], ["CISCO_IDEVID_CMCA_SUDI0", "CISCO_IDEVID_SUDI0", "Trustpool"]
        )
        self_signed = [c for c in self.certs if c["header"].startswith("Router Self-Signed")][0]
        self.assertEqual(self_signed["storage"], "nvram:IOS-Self-Sig#5.cer")
        # repeated trustpoint names are listed once
        licensing = [c for c in self.certs if "SLA-TrustPoint" in c["trustpoints"]][0]
        self.assertEqual(licensing["trustpoints"], ["Trustpool", "SLA-TrustPoint"])
        self.assertEqual(platform._parse_pki_certificates(""), [])

    def test_both_sources_normalize_to_the_same_certificate_keys(self):
        cert_keys = {key for key in self.model if key.startswith("cert|")}
        self.assertEqual(cert_keys, {key for key in self.cli if key.startswith("cert|")})
        self.assertEqual(len(cert_keys), 17)
        for key in cert_keys:
            model_facts = dict(self.model[key], key_type=None)  # the CLI cannot see the key type
            self.assertEqual(model_facts, self.cli[key], key)
        self.assertEqual(
            {key for key in self.model if key.startswith("trustpoint|")},
            {key for key in self.cli if key.startswith("trustpoint|")},
        )
        for key in self.cli:
            if key.startswith("trustpoint|"):
                self.assertEqual(
                    self.cli[key]["certificates"], self.model[key]["certificates"], key
                )
                self.assertEqual(
                    self.cli[key]["authenticated"], self.model[key]["authenticated"], key
                )
                self.assertEqual(self.cli[key]["enrolled"], self.model[key]["enrolled"], key)

    def test_the_self_signed_default(self):
        key = "cert|TP-self-signed-276118150|id|IOS-Self-Signed-Certificate-276118150"
        facts = self.model[key]
        self.assertTrue(facts["self_signed"])
        self.assertEqual(facts["validity_end"], "2024-12-31T00:05:39Z")
        self.assertEqual(facts["usage"], "general-purpose")
        self.assertEqual(facts["key_type"], "rsa")
        self.assertEqual(self.model["trustpoint|TP-self-signed-276118150"]["mode"], "none")

    def test_roles_and_dn_spelling(self):
        sudi = self.model["cert|CISCO_IDEVID_CMCA2_SUDI|id|C9300-48UXM-4401E4B45B26"]
        self.assertEqual(
            sudi["subject"],
            "cn=C9300-48UXM-4401E4B45B26, serialnumber=PID:C9300-48UXM SN:FOC8704M57A",
        )
        self.assertEqual(sudi["issuer"], "cn=Cisco Manufacturing CA SHA2, o=Cisco")
        self.assertFalse(sudi["self_signed"])
        self.assertIn("cert|Trustpool|ca|Cisco Root CA M2", self.model)
        self.assertEqual(
            platform._dn_from_text("CN=Example Root, O=Example Org"),
            "cn=Example Root, o=Example Org",
        )
        self.assertEqual(platform._cn_of("o=Example Org"), "o=Example Org")
        self.assertEqual(platform._cert_usage("crypto-pki-cert-usage-usage-keys"), "usage-keys")
        self.assertEqual(platform._cert_usage("crypto-pki-cert-general-purpose"), "general-purpose")
        self.assertEqual(platform._cert_role("signature"), "ca")
        self.assertEqual(platform._cert_role("encryption"), "id")

    def test_cli_time_zone_handling(self):
        self.assertEqual(
            platform._parse_cli_time("20:25:42 UTC May 14 2029"),
            datetime.datetime(2029, 5, 14, 20, 25, 42, tzinfo=datetime.timezone.utc),
        )
        self.assertEqual(platform._parse_cli_time("00:05:39 EST Jan 1 2015").year, 2015)
        self.assertIsNone(platform._parse_cli_time("never"))
        self.assertEqual(
            platform._utc_text("2026-09-29T17:12:00.123-05:00"), "2026-09-29T22:12:00Z"
        )
        self.assertEqual(platform._utc_text("soon"), "soon")

    def test_serials_and_fingerprints_never_normalized(self):
        text = json.dumps(self.model)
        self.assertNotIn("<hex:", text)
        self.assertNotIn("md5", text)

    def test_context_days_to_expiry(self):
        context = platform._pki_context(self.model, NOW)
        self.assertEqual(context["certificates"], 17)
        self.assertEqual(context["expired"], 1)
        self.assertEqual(context["expiring_soon"], [])
        self.assertEqual(
            context["soonest_expiry"],
            "cert|TP-self-signed-276118150|id|IOS-Self-Signed-Certificate-276118150",
        )
        self.assertEqual(context[context["soonest_expiry"]]["days_to_expiry"], -638)
        self.assertEqual(
            context["cert|CISCO_IDEVID_CMCA2_SUDI|ca|Cisco Manufacturing CA SHA2"][
                "days_to_expiry"
            ],
            4062,
        )
        self.assertEqual(context["as_of"], "2026-09-29T12:00:00Z")
        soon = copy.deepcopy(self.model)
        soon["cert|SLA-TrustPoint|ca|Cisco Licensing Root CA"]["validity_end"] = (
            "2026-10-10T00:00:00Z"
        )
        self.assertEqual(
            platform._pki_context(soon, NOW)["expiring_soon"],
            ["cert|SLA-TrustPoint|ca|Cisco Licensing Root CA"],
        )

    def test_two_healthy_captures_diff_to_nothing(self):
        again = platform._normalize_pki_model(copy.deepcopy(J(PKI)))
        self.assertEqual(self.model, again)
        self.assertEqual(
            diffcore.diff_check(self.model, again, {"mode": "equality_set"})["result"], "pass"
        )
        cli_again = platform._normalize_pki_cli(platform._parse_pki_certificates(T(PKI_CLI)))
        self.assertEqual(self.cli, cli_again)
        _assert_stable_types(self, self.model)
        _assert_stable_types(self, self.cli)

    def test_an_enrolled_identity_certificate_names_no_host(self):
        # IOS-XE enrols with CN=<hostname>.<domain> (and the same name under
        # hostname=): the key takes the issuer, the naming RDNs are withheld
        # in normalized and raw, the CA certificate's organisation stays.
        bundle = {
            "label": "LAB-CA",
            "mode": "crypto-pki-mode-none",
            "tp-authenticated": True,
            "tp-keys-generated": True,
            "tp-enrolled": True,
            "cert": [
                {
                    "cert-avail": "crypto-pki-cert-available",
                    "cert-usage": "crypto-pki-cert-usage-general-purpose",
                    "cert-key-type": "crypto-pki-cert-key-rsa",
                    "subject-name": (
                        "hostname=sw-real-01.example.net,cn=sw-real-01.example.net,o=Example"
                    ),
                    "issuer-name": "cn=Example Issuing CA,o=Example",
                    "validity-start": "2026-01-01T00:00:00+00:00",
                    "validity-end": "2027-01-01T00:00:00+00:00",
                },
                {
                    "cert-avail": "crypto-pki-cert-available",
                    "cert-usage": "crypto-pki-cert-usage-signature",
                    "cert-key-type": "crypto-pki-cert-key-rsa",
                    "subject-name": "cn=Example Issuing CA,o=Example",
                    "issuer-name": "cn=Example Root,o=Example",
                    "validity-start": "2020-01-01T00:00:00+00:00",
                    "validity-end": "2030-01-01T00:00:00+00:00",
                },
            ],
        }
        payload = {
            "Cisco-IOS-XE-crypto-pki-oper:crypto-pki-oper-data": {"crypto-pki-bundle": [bundle]}
        }
        normalized = platform._normalize_pki_model(payload)
        self.assertEqual(
            sorted(normalized),
            [
                "cert|LAB-CA|ca|Example Issuing CA",
                "cert|LAB-CA|id|issued-by Example Issuing CA",
                "trustpoint|LAB-CA",
            ],
        )
        identity = normalized["cert|LAB-CA|id|issued-by Example Issuing CA"]
        self.assertEqual(
            identity["subject"], "hostname=***scrubbed***, cn=***scrubbed***, o=Example"
        )
        self.assertEqual(identity["issuer"], "cn=Example Issuing CA, o=Example")
        self.assertFalse(identity["self_signed"])
        self.assertEqual(identity["validity_end"], "2027-01-01T00:00:00Z")
        self.assertEqual(
            normalized["cert|LAB-CA|ca|Example Issuing CA"]["subject"],
            "cn=Example Issuing CA, o=Example",
        )
        self.assertNotIn("sw-real-01", json.dumps(normalized))
        # raw: the model's subject-name leaf is withheld the same way; the
        # factory shapes and the CA subjects of the lab payload are untouched.
        scrubbed, count = platform._scrub_pki_payload(copy.deepcopy(payload))
        self.assertEqual(count, 1)
        self.assertNotIn("sw-real-01", json.dumps(scrubbed))
        self.assertIn("cn=Example Issuing CA,o=Example", json.dumps(scrubbed))
        lab, count = platform._scrub_pki_payload(copy.deepcopy(J(PKI)))
        self.assertEqual((count, lab), (0, J(PKI)))
        self.assertEqual(platform._normalize_pki_model(J(PKI)), self.model)

    def test_act2_sudi_subject_is_a_factory_shape_and_keeps_its_cn(self):
        # 17.15.6 live: the ACT2 Lite SUDI identity subject is cn=<PID> (no
        # MAC) with ou=ACT-2 Lite SUDI and serialNumber=PID:<pid> SN:<serial>;
        # the serialNumber RDN marks it factory, so the key keeps the CN and
        # nothing is withheld, in the model and in the CLI listing alike.
        subject = (
            "cn=C9300-48UXM,ou=ACT-2 Lite SUDI,o=Cisco,serialNumber=PID:C9300-48UXM SN:FOC8704M57A"
        )
        bundle = {
            "label": "CISCO_IDEVID_SUDI",
            "cert": [
                {
                    "cert-avail": "crypto-pki-cert-available",
                    "cert-usage": "crypto-pki-cert-usage-general-purpose",
                    "cert-key-type": "crypto-pki-cert-key-ec",
                    "subject-name": subject,
                    "issuer-name": "cn=ACT2 SUDI CA,o=Cisco",
                    "validity-end": "2099-12-31T23:59:59+00:00",
                }
            ],
        }
        payload = {
            "Cisco-IOS-XE-crypto-pki-oper:crypto-pki-oper-data": {"crypto-pki-bundle": [bundle]}
        }
        normalized = platform._normalize_pki_model(payload)
        self.assertIn("cert|CISCO_IDEVID_SUDI|id|C9300-48UXM", normalized)
        self.assertEqual(
            normalized["cert|CISCO_IDEVID_SUDI|id|C9300-48UXM"]["subject"],
            "cn=C9300-48UXM, ou=ACT-2 Lite SUDI, o=Cisco, "
            "serialnumber=PID:C9300-48UXM SN:FOC8704M57A",
        )
        self.assertEqual(platform._scrub_pki_payload(copy.deepcopy(payload))[1], 0)
        text = (
            "Certificate\n"
            "  Status: Available\n"
            "  Certificate Usage: General Purpose\n"
            "  Issuer: \n"
            "    cn=ACT2 SUDI CA\n"
            "    o=Cisco\n"
            "  Subject:\n"
            "    Name: C9300-48UXM\n"
            "    Serial Number: PID:C9300-48UXM SN:FOC8704M57A\n"
            "    cn=C9300-48UXM\n"
            "    ou=ACT-2 Lite SUDI\n"
            "    o=Cisco\n"
            "    serialNumber=PID:C9300-48UXM SN:FOC8704M57A\n"
            "  Validity Date: \n"
            "    start date: 00:00:00 UTC Jan 1 2020\n"
            "    end   date: 23:59:59 UTC Dec 31 2099\n"
            "  Associated Trustpoints: CISCO_IDEVID_SUDI \n"
        )
        self.assertEqual(platform._scrub_pki_cli(text), text)
        cli = platform._normalize_pki_cli(platform._parse_pki_certificates(text))
        self.assertIn("cert|CISCO_IDEVID_SUDI|id|C9300-48UXM", cli)

    def test_cli_listing_is_scrubbed_before_it_is_stored_or_traced(self):
        text = T(PKI_CLI) + (
            "Certificate\n"
            "  Status: Available\n"
            "  Certificate Serial Number (hex): 1A\n"
            "  Certificate Usage: General Purpose\n"
            "  Issuer: \n"
            "    cn=Example Issuing CA\n"
            "    o=Example\n"
            "  Subject:\n"
            "    Name: sw-real-01.example.net\n"
            "    hostname=sw-real-01.example.net\n"
            "    cn=sw-real-01.example.net\n"
            "    o=Example\n"
            "  Validity Date: \n"
            "    start date: 00:00:00 UTC Jan 1 2026\n"
            "    end   date: 00:00:00 UTC Jan 1 2027\n"
            "  Associated Trustpoints: LAB-CA \n"
        )
        scrubbed = platform._scrub_pki_cli(text)
        self.assertNotIn("sw-real-01", scrubbed)
        self.assertIn(
            "    Name: ***scrubbed***\n    hostname=***scrubbed***\n    cn=***scrubbed***\n"
            "    o=Example",
            scrubbed,
        )
        # the SUDI, self-signed and CA blocks of the lab listing are untouched
        self.assertEqual(platform._scrub_pki_cli(T(PKI_CLI)), T(PKI_CLI))
        certs = platform._parse_pki_certificates(scrubbed)
        normalized = platform._normalize_pki_cli(certs)
        self.assertIn("cert|LAB-CA|id|issued-by Example Issuing CA", normalized)
        self.assertEqual(
            normalized["cert|LAB-CA|id|issued-by Example Issuing CA"]["subject"],
            "hostname=***scrubbed***, cn=***scrubbed***, o=Example",
        )
        self.assertNotIn("sw-real-01", json.dumps(normalized))
        # the collector hands the scrubber to run_ssh as the redactor
        ctx = _Ctx({}, ssh={platform._PKI_COMMAND: text})
        result = platform._collect_pki(ctx)
        self.assertNotIn("sw-real-01", json.dumps(result))
        self.assertIs(ctx.redactors[platform._PKI_COMMAND], platform._scrub_pki_cli)


class TestPkiCollector(unittest.TestCase):
    def test_model_read_raw_keyed_by_the_filtered_path(self):
        ctx = _Ctx(
            {"crypto-pki-oper-data": J(PKI)}, ssh={"show crypto pki certificates": T(PKI_CLI)}
        )
        result = platform._collect_pki(ctx)
        path = "%s?fields=%s" % (platform._PKI_PATH, platform._PKI_FIELDS)
        self.assertEqual(set(result["raw"]), {path})
        self.assertEqual(result["context"]["source"], "crypto-pki-oper")
        self.assertEqual(ctx.ssh_calls, [])
        self.assertEqual(len(result["normalized"]), 26)
        self.assertIn("days_to_expiry", result["context"]["cert|Trustpool|ca|Cisco Root CA M2"])

    def test_server_error_falls_back_to_the_cli(self):
        # what the lab release does: HTTP 500 on the container
        ctx = _Ctx(
            {"crypto-pki-oper-data": _Http(500)}, ssh={"show crypto pki certificates": T(PKI_CLI)}
        )
        result = platform._collect_pki(ctx)
        self.assertEqual(result["context"]["source"], "show crypto pki certificates")
        self.assertEqual(set(result["raw"]), {"show crypto pki certificates", "note"})
        self.assertIn("HTTP 500", result["raw"]["note"])
        self.assertEqual(len(result["normalized"]), 26)

    def test_404_falls_back_to_the_cli(self):
        ctx = _Ctx({}, ssh={"show crypto pki certificates": T(PKI_CLI)})
        result = platform._collect_pki(ctx)
        self.assertIn("not served (404)", result["raw"]["note"])
        self.assertEqual(result["context"]["source"], "show crypto pki certificates")

    def test_fields_rejection_retries_unfiltered_once(self):
        ctx = _Ctx({"crypto-pki-oper-data": _reject_fields(J(PKI))})
        result = platform._collect_pki(ctx)
        self.assertIn(platform._PKI_PATH, result["raw"])
        self.assertEqual(result["context"]["fields_filter"], common.FILTER_REJECTED)

    def test_empty_model_is_reported_not_skipped(self):
        result = platform._collect_pki(_Ctx({"crypto-pki-oper-data": {}}))
        self.assertEqual(result["normalized"], {})
        self.assertIn("no trustpoints", result["raw"]["note"])
        self.assertEqual(result["context"]["certificates"], 0)

    def test_empty_cli_is_reported_not_skipped(self):
        result = platform._collect_pki(_Ctx({}, ssh={"show crypto pki certificates": ""}))
        self.assertEqual(result["normalized"], {})
        self.assertIn("listed no certificates", result["raw"]["note"])

    def test_unreadable_is_a_collect_error_never_emptiness(self):
        with self.assertRaises(registry.CollectError):
            platform._collect_pki(_Ctx({}, ssh=None))
        with self.assertRaises(registry.CollectError):
            platform._collect_pki(
                _Ctx(
                    {"crypto-pki-oper-data": _Http(500)},
                    ssh={"show crypto pki certificates": REFUSED},
                )
            )

    def test_client_errors_propagate(self):
        with self.assertRaises(_Http):
            platform._collect_pki(_Ctx({"crypto-pki-oper-data": _Http(401)}))


# =============================================================================
# iosxe_tcam
# =============================================================================


class TestTcamNormalizers(unittest.TestCase):
    def setUp(self):
        self.tcam = platform._normalize_tcam(J(TCAM))
        self.dp = platform._normalize_dp(J(DP))

    def test_tcam_regions_on_the_lab(self):
        self.assertEqual(len(self.tcam), 40)
        self.assertEqual(
            self.tcam["tcam|0|Mac Address Table"],
            {"tcam_max": 1024, "hash_max": 32768, "used_pct": 1.76},
        )
        self.assertEqual(self.tcam["tcam|3|IP Route Table"]["used_pct"], 0.02)
        self.assertEqual({key.split("|")[1] for key in self.tcam}, {"0", "1", "2", "3"})

    def test_dp_features_on_the_lab(self):
        self.assertEqual(len(self.dp), 53)
        self.assertTrue(all(key.startswith("dp|1|fp|0|0|0|") for key in self.dp))
        self.assertEqual(
            self.dp["dp|1|fp|0|0|0|control-plane|ipv4|ingress"],
            {"used_pct": 56.64},
        )
        self.assertEqual(
            self.dp["dp|1|fp|0|0|0|mac-address-table|other|ingress"],
            {"used_pct": 2.15},
        )

    def test_bands(self):
        self.assertIsNone(platform._band(None))
        for pct, word in (
            (0.0, "low"),
            (49.99, "low"),
            (50.0, "moderate"),
            (80.0, "high"),
            (89.9, "high"),
            (90.0, "critical"),
            (100.0, "critical"),
        ):
            self.assertEqual(platform._band(pct), word, pct)
        self.assertIsNone(platform._pct(3, 0))
        self.assertEqual(platform._pct("17", "1024"), 1.66)

    def test_tolerance_lets_churn_pass_and_flags_a_fill(self):
        compare = registry.CHECKS["iosxe_tcam"].compare
        again = copy.deepcopy(self.tcam)
        again["tcam|0|Mac Address Table"]["used_pct"] = 6.5
        self.assertEqual(diffcore.diff_check(self.tcam, again, compare)["result"], "pass")
        again["tcam|0|Mac Address Table"]["used_pct"] = 6.9
        diff = diffcore.diff_check(self.tcam, again, compare)
        self.assertEqual(diff["result"], "diffs")
        self.assertEqual(diff["changed"][0]["field"], "used_pct")
        # The band word is context, so a region hovering at an edge (49.5 ->
        # 50.5, within tolerance) passes instead of flipping low -> moderate.
        for key in self.tcam:
            self.assertNotIn("band", self.tcam[key])
        for key in self.dp:
            self.assertNotIn("band", self.dp[key])
        pre = {"tcam|0|IP Route Table": {"tcam_max": 8192, "hash_max": 0, "used_pct": 49.5}}
        post = {"tcam|0|IP Route Table": {"tcam_max": 8192, "hash_max": 0, "used_pct": 50.5}}
        self.assertEqual(diffcore.diff_check(pre, post, compare)["result"], "pass")

    def test_context_readings(self):
        context = platform._tcam_context(J(TCAM), J(DP))
        self.assertEqual(context["tcam_regions"], 40)
        self.assertEqual(context["dp_features"], 53)
        self.assertEqual(
            context["tcam|0|Mac Address Table"],
            {"tcam_used": 18, "hash_used": 18, "hash_used_pct": 0.05, "band": "low"},
        )
        self.assertEqual(
            context["dp|1|fp|0|0|0|mac-address-table|other|ingress"],
            {"tcam_pct": 2.15, "em_pct": 0.23, "acl_ids_pct": 0.0, "lpm_pct": 0.0, "band": "low"},
        )
        self.assertEqual(context["dp|1|fp|0|0|0|control-plane|ipv4|ingress"]["band"], "moderate")
        self.assertEqual(
            context["highest"],
            {"key": "dp|1|fp|0|0|0|control-plane|ipv4|ingress", "used_pct": 56.64},
        )
        self.assertEqual(context["at_or_above_80_pct"], [])
        self.assertEqual(platform._tcam_context(None, None)["highest"], None)

    def test_dp_raw_is_cut_to_feature_level(self):
        raw = platform._dp_raw(J(DP))
        text = json.dumps(raw)
        self.assertNotIn("instance-list", text)
        self.assertNotIn("shared-ftr-list", text)
        self.assertLess(len(text), 20000)
        location = raw["Cisco-IOS-XE-switch-dp-resources-oper:switch-dp-resources-oper-data"][
            "location"
        ][0]
        self.assertEqual(location["chassis"], 1)
        self.assertEqual(len(location["dp-feature-resource"]), 53)

    def test_two_healthy_captures_diff_to_nothing(self):
        first = dict(self.tcam)
        first.update(self.dp)
        again = platform._normalize_tcam(copy.deepcopy(J(TCAM)))
        again.update(platform._normalize_dp(copy.deepcopy(J(DP))))
        self.assertEqual(first, again)
        self.assertEqual(
            diffcore.diff_check(first, again, registry.CHECKS["iosxe_tcam"].compare)["result"],
            "pass",
        )
        _assert_stable_types(self, first)


class TestTcamCollector(unittest.TestCase):
    def test_both_models_raw_keyed_by_exact_paths(self):
        ctx = _Ctx({"tcam-details": J(TCAM), "switch-dp-resources-oper-data": J(DP)})
        result = platform._collect_tcam(ctx)
        self.assertEqual(
            set(result["raw"]),
            {platform._TCAM_PATH, "%s?fields=%s" % (platform._DP_PATH, platform._DP_FIELDS)},
        )
        self.assertEqual(ctx.kwargs[ctx.calls.index(platform._TCAM_PATH)], {"ok_404": True})
        self.assertEqual(len(result["normalized"]), 93)
        self.assertEqual(result["context"]["dp_fields_filter"], "accepted")
        self.assertEqual(result["context"]["used_pct_tolerance"], 5.0)

    def test_neither_model_is_not_present(self):
        with self.assertRaises(registry.SkipCheck):
            platform._collect_tcam(_Ctx({}))

    def test_both_served_empty_is_not_present(self):
        with self.assertRaises(registry.SkipCheck):
            platform._collect_tcam(_Ctx({"tcam-details": {}, "switch-dp-resources-oper-data": {}}))

    def test_one_model_missing_is_noted(self):
        result = platform._collect_tcam(_Ctx({"tcam-details": J(TCAM)}))
        self.assertEqual(len(result["normalized"]), 40)
        self.assertIn("switch-dp-resources-oper not served (404)", result["raw"]["note"])
        self.assertIsNone(result["context"]["dp_fields_filter"])
        result = platform._collect_tcam(_Ctx({"switch-dp-resources-oper-data": J(DP)}))
        self.assertEqual(len(result["normalized"]), 53)
        self.assertIn("tcam-oper not served (404)", result["raw"]["note"])

    def test_dp_fields_rejection_retries_unfiltered_and_cuts_raw(self):
        ctx = _Ctx(
            {"tcam-details": J(TCAM), "switch-dp-resources-oper-data": _reject_fields(J(DP))}
        )
        result = platform._collect_tcam(ctx)
        self.assertIn(platform._DP_PATH, result["raw"])
        self.assertNotIn("instance-list", json.dumps(result["raw"][platform._DP_PATH]))
        self.assertIn("instance-list dropped from raw", result["raw"]["note"])
        self.assertEqual(result["context"]["dp_fields_filter"], common.FILTER_REJECTED)
        self.assertEqual(len(result["normalized"]), 93)

    def test_other_http_errors_propagate(self):
        with self.assertRaises(_Http):
            platform._collect_tcam(_Ctx({"tcam-details": _Http(500)}))


if __name__ == "__main__":
    unittest.main()
