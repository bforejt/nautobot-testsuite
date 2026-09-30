"""tools/redfish_walk.py: which links a GET-only crawl follows, records or skips.

The crawl itself talks to a BMC and runs outside CI; the battery locks in the
classification every server-supplied link goes through (the jobs' own path
fence first, then the walk's skip rules) and the one-file-per-resource naming.
Stdlib only: the tool's transport import happens inside main().
"""

import importlib.util
import pathlib
import unittest

if __package__:
    from . import _loader
else:  # unittest discover -s tests imports test modules as top-level
    import _loader

_TOOL = pathlib.Path(__file__).resolve().parents[1] / "tools" / "redfish_walk.py"
_spec = importlib.util.spec_from_file_location("redfish_walk", _TOOL)
redfish_walk = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(redfish_walk)

fence = _loader.redfish_paths.fence_path


class TestClassify(unittest.TestCase):
    def test_follows_resources_and_continuation_links(self):
        for link in (
            "/redfish/v1/Systems/1",
            "/redfish/v1/Chassis/1/Sensors",
            "/redfish/v1/Systems/1/LogServices/StandardLog/Entries",
            "/redfish/v1/Systems/1/LogServices/StandardLog/Entries?$skip=100",
            "/redfish/v1/Registries/Base.1.12.1",
        ):
            self.assertEqual(redfish_walk.classify(link, fence), ("follow", link), link)

    def test_the_fence_refuses_before_anything_is_sent(self):
        for link in (
            "/redfish/v1/Systems/1/Actions/ComputerSystem.Reset",
            "/redfish/v1/SessionService/Sessions",
            "/redfish/v1/Systems/1/%41ctions/x",
            "https://elsewhere.example/redfish/v1/",
        ):
            self.assertEqual(redfish_walk.classify(link, fence)[0], "refused", link)

    def test_skips_documents_single_entries_and_the_audit_log(self):
        for link in (
            "/redfish/v1/JsonSchemas",
            "/redfish/v1/$metadata",
            "/redfish/v1/odata",
            "/redfish/v1/Registries/Base.1.12.1/Base.1.12.1.json",
            "/redfish/v1/Systems/1/LogServices/StandardLog/Entries/311",
            "/redfish/v1/Managers/1/LogServices/AuditLog/Entries",
        ):
            self.assertEqual(redfish_walk.classify(link, fence)[0], "skipped", link)
        audit = "/redfish/v1/Managers/1/LogServices/AuditLog/Entries"
        self.assertEqual(redfish_walk.classify(audit, fence, audit=True), ("follow", audit))

    def test_links_are_found_anywhere_in_a_payload(self):
        payload = {
            "@odata.id": "/redfish/v1/Chassis/1",
            "Links": {"ManagedBy": [{"@odata.id": "/redfish/v1/Managers/1"}]},
            "Members@odata.nextLink": "/redfish/v1/Chassis?$skiptoken=2",
            "Oem": {"Lenovo": {"LEDs": {"@odata.id": "/redfish/v1/Chassis/1/Oem/Lenovo/LEDs"}}},
        }
        self.assertEqual(
            sorted(redfish_walk.find_links(payload, [])),
            [
                "/redfish/v1/Chassis/1",
                "/redfish/v1/Chassis/1/Oem/Lenovo/LEDs",
                "/redfish/v1/Chassis?$skiptoken=2",
                "/redfish/v1/Managers/1",
            ],
        )

    def test_one_file_per_resource(self):
        self.assertEqual(redfish_walk.file_name("/redfish/v1/"), "root.json")
        self.assertEqual(
            redfish_walk.file_name("/redfish/v1/Systems/1/Bios"), "root_Systems_1_Bios.json"
        )
        self.assertEqual(
            redfish_walk.file_name("/redfish/v1/Chassis?$skiptoken=2"),
            "root_Chassis_skiptoken_2.json",
        )


if __name__ == "__main__":
    unittest.main()
