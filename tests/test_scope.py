"""Inventory scope is decided from plain modelled facts before collection."""

import copy
import unittest
from uuid import UUID

if __package__:
    from . import _loader
else:
    import _loader

scope = _loader.load("scope")


def device(pk="sw", name=None, driver="cisco_ios", **changes):
    row = {
        "pk": pk,
        "name": name or str(pk),
        "platform_driver": driver,
        "platform": driver,
        "platform_slug": "",
        "has_bmc": False,
        "location": "Site A / Floor 1",
        "role": "Access",
        "status": "Active",
    }
    row.update(changes)
    return row


def controller(target=None, pk="ctrl", name="WLC-A", capabilities=("wireless",), **changes):
    row = {
        "pk": pk,
        "name": name,
        "device": target,
        "capabilities": list(capabilities),
        "has_redundancy_group": False,
    }
    row.update(changes)
    return row


def managed(pk="ap", controller_pk="ctrl", capabilities=(), driver="cisco_wap", **changes):
    return device(
        pk,
        driver=driver,
        managed_group={"controller_pk": controller_pk, "capabilities": list(capabilities)},
        **changes,
    )


def resolve(rows=(), controllers=(), **options):
    options.setdefault("locations", ("Site A",))
    return scope.resolve(rows, controllers, **options)


def entries(result):
    return {row["id"]: row for row in result["devices"]}


class PlatformMapping(unittest.TestCase):
    def test_production_platform_rows(self):
        cases = (
            ("cisco_ios", "cisco_ios", "iosxe"),
            ("cisco_ios", "cisco_wap", None),
            ("cisco_nxos", "cisco_nxos", None),
            ("paloalto_panos", "paloalto_panos", "panos"),
            ("", "vmware_esxi", "vmware"),
        )
        for driver, name, expected in cases:
            with self.subTest(driver=driver, name=name):
                self.assertEqual(scope.map_platform(driver, name)[0], expected)

    def test_each_deny_token_in_driver_name_and_slug(self):
        self.assertEqual(
            _loader.constants.PLATFORM_DENY_TOKENS,
            ("nxos", "wap", "ap", "xr", "asa", "ftd", "aireos", "meraki", "apic", "viptela"),
        )
        for token in _loader.constants.PLATFORM_DENY_TOKENS:
            for index in range(3):
                values = ["cisco_ios", "Cisco IOS", "cisco-ios"]
                values[index] = "Cisco_" + token.upper()
                with self.subTest(token=token, field=index):
                    self.assertIsNone(scope.map_platform(*values)[0])

    def test_whole_words_with_non_alphanumeric_boundaries(self):
        for spelling in ("cisco_ap", "cisco-ap", "cisco.ap", "cisco AP", "cisco/AP", "AP"):
            with self.subTest(spelling=spelling):
                self.assertIsNone(scope.map_platform("cisco_ios", spelling)[0])
        for spelling in (
            "paloalto_panos",
            "cisco_rapid",
            "cisco_xray",
            "cisco_appliance",
            "cisco_nxos9",
        ):
            with self.subTest(spelling=spelling):
                self.assertIsNotNone(scope.map_platform(spelling)[0])

    def test_mapping_precedence_and_selected_driver(self):
        cases = (
            ("PANOS VM-Series on VMware", "", "", ("panos", "panos vm-series on vmware")),
            ("Cisco UCS ESXi", "", "", ("vmware", "cisco ucs esxi")),
            ("CISCO_IOS", "", "", ("iosxe", "cisco_ios")),
            (None, "Cisco", "vmware_esxi", ("vmware", "vmware_esxi")),
            (None, "VMware ESXi", None, ("vmware", "vmware esxi")),
            (None, None, None, (None, "")),
        )
        for driver, name, slug, expected in cases:
            with self.subTest(driver=driver, name=name, slug=slug):
                self.assertEqual(scope.map_platform(driver, name, slug), expected)

    def test_driver_still_wins_for_family_and_unmapped_stays_unmapped(self):
        self.assertEqual(
            scope.map_platform("unknown", "Cisco IOS", "vmware_esxi"), (None, "unknown")
        )
        for driver in ("lenovo", "redfish", "xcc", "opengear", ""):
            with self.subTest(driver=driver):
                self.assertEqual(scope.map_platform(driver)[0], None)


class Selection(unittest.TestCase):
    def test_no_anchor_refuses_and_cannot_sweep_rows_accidentally(self):
        result = scope.resolve([device()], roles=("Access",), statuses=("Active",), tags=("prod",))
        self.assertEqual(result["devices"], [])
        self.assertEqual(result["capture_ids"], [])
        self.assertEqual(len(result["errors"]), 1)
        self.assertIn("anchor", result["errors"][0])

    def test_no_inputs_and_dry_run_without_anchor_refuse(self):
        for dryrun in (False, True):
            with self.subTest(dryrun=dryrun):
                result = scope.resolve([], dryrun=dryrun)
                self.assertTrue(result["errors"])
                self.assertIn("Pick at least one", result["errors"][0])

    def test_dynamic_group_is_a_valid_anchor(self):
        result = scope.resolve([device()], dynamic_group="Saved scope")
        self.assertEqual(result["capture_ids"], ["sw"])
        self.assertEqual(entries(result)["sw"]["source"], ["dynamic_group"])
        self.assertFalse(result["errors"])

    def test_explicit_picks_are_added_outside_narrowed_scope(self):
        outside = device("outside", location="Site B", role="Core", status="Offline")
        result = resolve(
            [device()],
            explicit_devices=[outside],
            roles=["Access"],
            statuses=["Active"],
            tags=["prod"],
        )
        self.assertEqual(result["capture_ids"], ["outside", "sw"])
        self.assertEqual(entries(result)["outside"]["source"], ["explicit"])
        self.assertEqual(entries(result)["outside"]["status"], "Offline")

    def test_explicit_only_selection_ignores_narrowing_filters(self):
        result = scope.resolve(
            [],
            explicit_devices=[device(status="Offline")],
            roles=["Other"],
            statuses=["Active"],
            tags=["other"],
        )
        self.assertEqual(result["capture_ids"], ["sw"])
        self.assertFalse(result["errors"])

    def test_duplicate_origins_merge_by_primary_key(self):
        row = device(source=["location"])
        group_row = device(source=["dynamic_group"])
        result = resolve([row, group_row], dynamic_group="Group", explicit_devices=[row])
        self.assertEqual(len(result["devices"]), 1)
        self.assertEqual(entries(result)["sw"]["source"], ["location", "dynamic_group", "explicit"])

    def test_duplicate_names_do_not_merge_distinct_devices(self):
        result = resolve([device("a", name="switch"), device("b", name="switch")])
        self.assertEqual(result["capture_ids"], ["a", "b"])

    def test_primary_keys_normalize_to_strings(self):
        pk = UUID("00000000-0000-0000-0000-000000000001")
        result = resolve([device(pk)])
        self.assertEqual(result["capture_ids"], [str(pk)])
        self.assertEqual(result["devices"][0]["pk"], str(pk))

    def test_missing_device_primary_key_is_a_clear_error(self):
        row = device()
        row.pop("pk")
        with self.assertRaisesRegex(ValueError, "primary key"):
            resolve([row])

    def test_exclusion_wins_after_explicit_addition(self):
        result = resolve([device()], explicit_devices=[device()], exclude_devices=[device()])
        row = entries(result)["sw"]
        self.assertEqual(row["disposition"], "excluded")
        self.assertEqual(row["source"], ["location", "explicit"])
        self.assertIsNone(row["outcome"])
        self.assertEqual(result["capture_ids"], [])

    def test_out_of_scope_exclusion_records_metadata_without_capture(self):
        result = resolve([device()], exclude_devices=[device("outside")])
        self.assertEqual(result["capture_ids"], ["sw"])
        row = entries(result)["outside"]
        self.assertEqual(row["disposition"], "excluded")
        self.assertEqual(row["source"], ["exclude_devices"])
        self.assertIsNone(row["outcome"])
        self.assertEqual(row["files"], [])

    def test_out_of_scope_exclusion_does_not_pull_in_its_controller(self):
        result = resolve(
            [device()],
            [controller(device("wlc"))],
            exclude_devices=[managed("outside")],
        )
        self.assertEqual(result["capture_ids"], ["sw"])
        self.assertNotIn("wlc", entries(result))
        self.assertEqual(result["controllers"], [])
        self.assertEqual(entries(result)["outside"]["disposition"], "excluded")

    def test_inputs_are_unchanged_and_result_artifact_lists_are_independent(self):
        rows = [device("one"), device("two")]
        original = copy.deepcopy(rows)
        result = resolve(rows, explicit_devices=[rows[0]])
        result["devices"][0]["source"].append("modified")
        result["devices"][0]["files"].append({"name": "snapshot"})
        self.assertEqual(rows, original)
        self.assertEqual(result["devices"][1]["files"], [])


class Dispositions(unittest.TestCase):
    def test_supported_capture_carries_manifest_metadata_only(self):
        result = resolve([device(address="192.0.2.1", source="location")])
        row = result["devices"][0]
        self.assertEqual(row["disposition"], "capture")
        self.assertIsNone(row["reason"])
        self.assertEqual(row["outcome"], "not_visited")
        self.assertIsNone(row["duration_s"])
        self.assertEqual(row["files"], [])
        self.assertEqual(row["location"], "Site A / Floor 1")
        self.assertEqual(row["role"], "Access")
        self.assertEqual(row["platform"], "cisco_ios")
        for key in ("address", "platform_driver", "managed_group", "has_bmc"):
            self.assertNotIn(key, row)

    def test_swept_unsupported_is_skipped_without_error(self):
        result = resolve([device(), device("console", driver="opengear")])
        row = entries(result)["console"]
        self.assertEqual(row["disposition"], "skipped_unsupported")
        self.assertIn("supported", row["reason"])
        self.assertFalse(result["errors"])
        self.assertIsNone(row["outcome"])

    def test_explicit_unsupported_is_error_before_capture(self):
        result = resolve([device()], explicit_devices=[device("console", driver="opengear")])
        self.assertEqual(entries(result)["console"]["disposition"], "skipped_unsupported")
        self.assertEqual(len(result["errors"]), 1)
        self.assertIn("Explicit device 'console'", result["errors"][0])

    def test_excluded_explicit_unsupported_is_not_an_explicit_error(self):
        result = resolve(
            [device()],
            explicit_devices=[device("console", driver="opengear")],
            exclude_devices=["console"],
        )
        self.assertEqual(entries(result)["console"]["disposition"], "excluded")
        self.assertFalse(result["errors"])

    def test_denied_platform_reports_token_and_modelling_fix(self):
        result = resolve([device(), device("ap", driver="cisco_ios", platform="cisco_wap")])
        row = entries(result)["ap"]
        self.assertEqual(row["disposition"], "skipped_unsupported")
        self.assertIn("wap", row["reason"])
        self.assertIn("managed-device group", row["reason"])

    def test_unsupported_or_denied_host_with_modelled_bmc_captures(self):
        for platform in ("unknown", "cisco_ap", None):
            with self.subTest(platform=platform):
                result = resolve([device(driver=platform, has_bmc=True)])
                self.assertEqual(result["capture_ids"], ["sw"])
                self.assertFalse(result["errors"])

    def test_missing_address_does_not_skip_supported_device(self):
        result = resolve([device(address=None)])
        self.assertEqual(result["capture_ids"], ["sw"])
        self.assertFalse(result["errors"])

    def test_zero_capturable_scope_is_error_even_in_dry_run(self):
        for dryrun in (False, True):
            with self.subTest(dryrun=dryrun):
                result = resolve([device(driver="opengear")], dryrun=dryrun)
                self.assertIn("zero capturable", result["errors"][0])


class Controllers(unittest.TestCase):
    def setUp(self):
        self.wlc = device("wlc", name="wlc-a-1", location="Central Site")
        self.controller = controller(self.wlc)

    def test_single_controller_device_is_pulled_from_another_site_and_covers_ap(self):
        result = resolve([managed(name="ap-floor-1")], [self.controller])
        rows = entries(result)
        self.assertEqual(result["capture_ids"], ["wlc"])
        self.assertEqual(rows["ap"]["disposition"], "covered_by_controller")
        self.assertIn("WLC-A", rows["ap"]["reason"])
        self.assertEqual(rows["wlc"]["source"], ["controller_of"])
        self.assertEqual(rows["wlc"]["location"], "Central Site")
        self.assertEqual(rows["wlc"]["pulled_in_by"], ["ap-floor-1"])
        self.assertEqual(
            result["controllers"],
            [{"id": "ctrl", "name": "WLC-A", "devices": ["wlc-a-1"], "covers": ["ap-floor-1"]}],
        )
        self.assertFalse(result["errors"])

    def test_explicit_ap_is_covered_instead_of_unsupported_error(self):
        result = scope.resolve([], [self.controller], explicit_devices=[managed()])
        self.assertEqual(entries(result)["ap"]["disposition"], "covered_by_controller")
        self.assertFalse(result["errors"])

    def test_group_wireless_capability_is_sufficient(self):
        result = resolve(
            [managed(capabilities=["wireless"])], [controller(self.wlc, capabilities=[])]
        )
        self.assertEqual(entries(result)["ap"]["disposition"], "covered_by_controller")

    def test_wireless_managed_supported_device_is_covered(self):
        result = resolve([managed(driver="cisco_ios")], [self.controller])
        self.assertEqual(result["capture_ids"], ["wlc"])
        self.assertEqual(entries(result)["ap"]["disposition"], "covered_by_controller")

    def test_empty_capabilities_cover_unsupported_managed_devices(self):
        result = resolve([managed(driver="unknown")], [controller(self.wlc, capabilities=[])])
        self.assertEqual(entries(result)["ap"]["disposition"], "covered_by_controller")

    def test_empty_capabilities_use_platform_mapping_even_with_a_modelled_bmc(self):
        result = resolve(
            [managed(driver="unknown", has_bmc=True)],
            [controller(self.wlc, capabilities=[])],
        )
        self.assertEqual(entries(result)["ap"]["disposition"], "covered_by_controller")
        self.assertEqual(result["capture_ids"], ["wlc"])

    def test_empty_capabilities_leave_supported_managed_devices_direct(self):
        result = resolve([managed(driver="cisco_ios")], [controller(self.wlc, capabilities=[])])
        self.assertEqual(result["capture_ids"], ["wlc", "ap"])
        self.assertEqual(entries(result)["ap"]["disposition"], "capture")
        self.assertEqual(result["controllers"][0]["covers"], [])

    def test_nonwireless_capability_does_not_cover_unsupported_device(self):
        result = resolve(
            [managed(driver="unknown")], [controller(self.wlc, capabilities=["other"])]
        )
        self.assertEqual(entries(result)["ap"]["disposition"], "skipped_unsupported")
        self.assertEqual(result["capture_ids"], ["wlc"])

    def test_nonwireless_unsupported_controller_does_not_fail_supported_switch(self):
        result = resolve(
            [managed(driver="cisco_ios")],
            [controller(device("dnac", driver="unknown"), capabilities=[])],
        )
        self.assertEqual(entries(result)["ap"]["disposition"], "capture")
        self.assertEqual(entries(result)["dnac"]["disposition"], "skipped_unsupported")
        self.assertFalse(result["errors"])

    def test_embedded_controller_already_in_scope_deduplicates(self):
        embedded = managed("wlc", driver="cisco_ios", name="embedded")
        result = resolve([embedded, managed()], [controller(embedded)])
        self.assertEqual(result["capture_ids"], ["wlc"])
        self.assertEqual(len(result["devices"]), 2)
        self.assertEqual(entries(result)["wlc"]["source"], ["location", "controller_of"])
        self.assertEqual(entries(result)["wlc"]["disposition"], "capture")
        self.assertEqual(entries(result)["ap"]["disposition"], "covered_by_controller")

    def test_embedded_controller_is_not_covered_by_itself(self):
        embedded = managed("wlc", driver="cisco_ios")
        result = resolve([embedded], [controller(embedded)])
        self.assertEqual(result["capture_ids"], ["wlc"])
        self.assertEqual(entries(result)["wlc"]["source"], ["location"])
        self.assertNotIn("pulled_in_by", entries(result)["wlc"])

    def test_excluded_pulled_in_controller_removes_coverage(self):
        result = resolve([device("other"), managed()], [self.controller], exclude_devices=["wlc"])
        rows = entries(result)
        self.assertEqual(rows["wlc"]["disposition"], "excluded")
        self.assertEqual(rows["ap"]["disposition"], "controller_not_capturable")
        self.assertIn("excluded", rows["ap"]["reason"])
        self.assertEqual(result["capture_ids"], ["other"])
        self.assertFalse(result["errors"])
        self.assertTrue(result["warnings"])
        self.assertEqual(result["controllers"][0]["covers"], [])

    def test_exclusion_applies_after_controller_pull_in(self):
        result = resolve([managed()], [self.controller], exclude_devices=["ap"])
        self.assertEqual(result["capture_ids"], ["wlc"])
        self.assertEqual(entries(result)["ap"]["disposition"], "excluded")
        self.assertEqual(result["controllers"][0]["covers"], [])

    def test_controller_without_device_warns_without_failing_other_capture(self):
        result = resolve([device("other"), managed()], [controller()])
        self.assertEqual(entries(result)["ap"]["disposition"], "controller_not_capturable")
        self.assertIn("set Controller device", entries(result)["ap"]["reason"])
        self.assertFalse(result["errors"])
        self.assertEqual(result["controllers"][0]["devices"], [])

    def test_missing_controller_row_warns_without_guessing_a_device(self):
        result = resolve([device("other"), managed()])
        self.assertEqual(entries(result)["ap"]["disposition"], "controller_not_capturable")
        self.assertEqual(result["capture_ids"], ["other"])
        self.assertIn("ctrl", entries(result)["ap"]["reason"])
        self.assertFalse(result["errors"])

    def test_managed_group_without_a_controller_is_not_directly_captured(self):
        result = resolve(
            [
                device("other"),
                managed(controller_pk=None, capabilities=["wireless"], driver="cisco_ios"),
            ]
        )
        row = entries(result)["ap"]
        self.assertEqual(row["disposition"], "controller_not_capturable")
        self.assertIn("group has no controller", row["reason"])
        self.assertEqual(result["capture_ids"], ["other"])
        self.assertEqual(result["controllers"], [])
        self.assertFalse(result["errors"])

    def test_redundancy_group_is_deferred_without_run_failure(self):
        result = resolve([device("other"), managed()], [controller(has_redundancy_group=True)])
        row = entries(result)["ap"]
        self.assertEqual(row["disposition"], "controller_not_capturable")
        self.assertIn(
            "controller redundancy groups are not supported yet; set Controller device",
            row["reason"],
        )
        self.assertFalse(result["errors"])
        self.assertEqual(result["capture_ids"], ["other"])

    def test_unsupported_controller_removes_coverage(self):
        result = resolve(
            [device("other"), managed()], [controller(device("wlc", driver="unknown"))]
        )
        self.assertEqual(entries(result)["wlc"]["disposition"], "skipped_unsupported")
        self.assertEqual(entries(result)["ap"]["disposition"], "controller_not_capturable")
        self.assertIn("supported platform", entries(result)["ap"]["reason"])
        self.assertFalse(result["errors"])

    def test_controller_with_bmc_is_capturable_even_if_host_platform_is_unsupported(self):
        result = resolve([managed()], [controller(device("wlc", driver="unknown", has_bmc=True))])
        self.assertEqual(result["capture_ids"], ["wlc"])
        self.assertEqual(entries(result)["ap"]["disposition"], "covered_by_controller")

    def test_disabling_pull_in_reports_unselected_controller(self):
        result = resolve([device("other"), managed()], [self.controller], include_controllers=False)
        self.assertNotIn("wlc", entries(result))
        self.assertEqual(entries(result)["ap"]["disposition"], "controller_not_capturable")
        self.assertIn("enable include_controllers", entries(result)["ap"]["reason"])
        self.assertFalse(result["errors"])

    def test_disabling_pull_in_still_covers_when_controller_selected_independently(self):
        result = resolve(
            [managed()], [self.controller], include_controllers=False, explicit_devices=[self.wlc]
        )
        self.assertEqual(result["capture_ids"], ["wlc"])
        self.assertEqual(entries(result)["wlc"]["source"], ["explicit"])
        self.assertEqual(entries(result)["ap"]["disposition"], "covered_by_controller")

    def test_shared_controller_pulled_once_with_all_device_names(self):
        result = resolve([managed("ap-b"), managed("ap-a")], [self.controller])
        self.assertEqual(result["capture_ids"], ["wlc"])
        self.assertEqual(entries(result)["wlc"]["pulled_in_by"], ["ap-a", "ap-b"])
        self.assertEqual(result["controllers"][0]["covers"], ["ap-a", "ap-b"])

    def test_nested_controller_chain_deduplicates_and_preserves_fail_closed_coverage(self):
        middle = managed("middle", controller_pk="upper", driver="cisco_ios")
        upper = device("upper-device")
        result = resolve(
            [managed()],
            [controller(middle), controller(upper, pk="upper", name="Upper", capabilities=[])],
        )
        self.assertEqual(result["capture_ids"], ["middle", "upper-device"])
        self.assertEqual(entries(result)["ap"]["disposition"], "covered_by_controller")
        self.assertEqual(entries(result)["upper-device"]["pulled_in_by"], ["middle"])

    def test_controller_cycle_finishes_without_capturing_covered_devices(self):
        one = managed("one", controller_pk="second", driver="cisco_ios")
        two = managed("two", controller_pk="first", driver="cisco_ios")
        result = resolve(
            [device("other"), one], [controller(one, pk="first"), controller(two, pk="second")]
        )
        self.assertEqual(result["capture_ids"], ["other"])
        self.assertEqual(entries(result)["one"]["disposition"], "controller_not_capturable")
        self.assertEqual(entries(result)["two"]["disposition"], "controller_not_capturable")


class OrderAndGuard(unittest.TestCase):
    def test_controller_captures_come_first_then_deterministic_names(self):
        ctrl_a = device("ctrl-a", name="z-WLC")
        ctrl_b = device("ctrl-b", name="B-WLC")
        rows = [
            device("z", name="Z-switch"),
            managed("ap-a", controller_pk="a"),
            device("a", name="a-switch"),
            managed("ap-b", controller_pk="b"),
        ]
        ctrls = [controller(ctrl_a, pk="a"), controller(ctrl_b, pk="b")]
        result = resolve(rows, ctrls)
        self.assertEqual(result["capture_ids"], ["ctrl-b", "ctrl-a", "a", "z"])
        reversed_result = resolve(list(reversed(rows)), list(reversed(ctrls)))
        self.assertEqual(result, reversed_result)

    def test_size_guard_refuses_real_run_before_collection(self):
        result = resolve([device(str(i)) for i in range(31)])
        self.assertEqual(len(result["capture_ids"]), 31)
        self.assertEqual(len(result["errors"]), 1)
        self.assertIn("31 captures", result["errors"][0])
        self.assertIn("Site rather than a Company", result["errors"][0])

    def test_size_guard_dry_run_shows_full_resolution_and_warning(self):
        result = resolve([device(str(i)) for i in range(31)], dryrun=True)
        self.assertEqual(len(result["devices"]), 31)
        self.assertFalse(result["errors"])
        self.assertIn("real run would refuse", result["warnings"][0])

    def test_size_limit_counts_only_captures_and_accepts_exact_limit(self):
        result = resolve(
            [device(str(i)) for i in range(30)] + [device("unsupported", driver="opengear")]
        )
        self.assertEqual(result["counts"]["capture"], 30)
        self.assertEqual(result["counts"]["skipped_unsupported"], 1)
        self.assertFalse(result["errors"])

    def test_pulled_controller_counts_toward_guard_covered_devices_do_not(self):
        wlc = device("wlc")
        result = resolve(
            [managed("ap1"), managed("ap2"), device("sw")], [controller(wlc)], max_capture=1
        )
        self.assertEqual(result["counts"]["capture"], 2)
        self.assertEqual(result["counts"]["covered_by_controller"], 2)
        self.assertIn("2 captures", result["errors"][0])

    def test_configured_limit_changes_refusal_threshold(self):
        result = resolve([device("a"), device("b")], max_capture=2)
        self.assertFalse(result["errors"])
        result = resolve([device("a"), device("b")], max_capture=1)
        self.assertIn("limit of 1", result["errors"][0])

    def test_default_status_names_are_portable(self):
        self.assertEqual(_loader.constants.SCOPE_DEFAULT_STATUSES, ("Active",))
        self.assertEqual(_loader.constants.SCOPE_MAX_CAPTURE, 30)


if __name__ == "__main__":
    unittest.main()
