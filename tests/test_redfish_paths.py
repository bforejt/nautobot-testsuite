"""redfish_paths: the GET fence that runs before any Redfish request is formed."""

import unittest

if __package__:
    from . import _loader
else:  # unittest discover -s tests imports test modules as top-level
    import _loader

fence = _loader.redfish_paths

ALLOWED = [
    "/redfish/v1/",
    "/redfish/v1/Systems/1",
    "/redfish/v1/Systems/1/SecureBoot",
    "/redfish/v1/Managers/1/EthernetInterfaces/NIC",
    "/redfish/v1/Managers/1/Oem/Lenovo/Security",
    "/redfish/v1/Chassis/1/Thermal",
    "/redfish/v1/Chassis/1/NetworkAdapters/ob-1/NetworkPorts/1",
    "/redfish/v1/Systems/1/LogServices/PlatformLog/Entries",
    "/redfish/v1/Systems/1/Memory?$expand=.($levels=1)",
    "/redfish/v1/UpdateService/FirmwareInventory?$expand=*($levels=2)&$select=Name,Version",
    "/redfish/v1/Systems/1/Storage/RAID_Slot1/Drives/Disk.0",
    "/redfish/v1/Systems/1/Bios",
    "/redfish/v1/Managers/1/NetworkProtocol",
    # the two page selectors a service may put in Members@odata.nextLink
    "/redfish/v1/Systems/1/LogServices/PlatformLog/Entries?$skip=5",
    "/redfish/v1/Systems/1/LogServices/PlatformLog/Entries?$skiptoken=abc",
    "/redfish/v1/Systems/1/LogServices/PlatformLog/Entries?$skip=50&$skiptoken=x1",
]

REFUSED = [
    # actions and sessions, in every case spelling
    "/redfish/v1/Managers/1/Actions/Manager.Reset",
    "/redfish/v1/Systems/1/Actions/ComputerSystem.Reset",
    "/redfish/v1/Systems/1/ACTIONS/ComputerSystem.Reset",
    "/redfish/v1/Actions",
    "/redfish/v1/SessionService",
    "/redfish/v1/SessionService/Sessions",
    "/redfish/v1/sessionservice/",
    # percent-escapes: requests would unquote these to Actions / SessionService
    "/redfish/v1/Systems/1/%41ctions/ComputerSystem.Reset",
    "/redfish/v1/%53essionService/Sessions",
    "/redfish/v1/Systems/1/%41ctions/x",
    "/redfish/v1/Systems/1%2FActions/x",
    "/redfish/v1/Systems/%31",
    # outside the service root
    "/redfish/",
    "/redfish/v1",  # allowed only as the exact root spelling — see test_root_alias
    "/redfish/v2/Systems/1",
    "redfish/v1/Systems/1",
    "https://192.0.2.10/redfish/v1/Systems/1",
    "/Systems/1",
    "/",
    "",
    # traversal / grammar
    "/redfish/v1/../v1/Systems/1",
    "/redfish/v1/Systems/./1",
    "/redfish/v1/Systems//1",
    "/redfish/v1/Systems/1 ",
    " /redfish/v1/Systems/1",
    "/redfish/v1/Sys tems/1",
    "/redfish/v1/Systems/1\n",
    "/redfish/v1/Systems/1\t",
    "/redfish/v1/Systems/<1>",
    '/redfish/v1/Systems/"1"',
    "/redfish/v1/Systems/1?$expand=<script>",
    # query parameters outside the allowlist or malformed ($top never: a
    # collector must not choose a window, and a nextLink carrying one is
    # refused rather than followed)
    "/redfish/v1/Systems/1/LogServices/PlatformLog/Entries?$top=100",
    "/redfish/v1/Systems/1/LogServices/PlatformLog/Entries?$top=50&$skip=50",
    "/redfish/v1/Systems/1?$filter=Id eq '1'",
    "/redfish/v1/Systems/1?$expand=*&$top=5",
    "/redfish/v1/Systems/1?$skip",
    "/redfish/v1/Systems/1?$skip=",
    "/redfish/v1/Systems/1?$skip=5%",
    "/redfish/v1/Systems/1?$expand",
    "/redfish/v1/Systems/1?$expand=",
    "/redfish/v1/Systems/1?expand=*",
    "/redfish/v1/Systems/1?$select=Name&only=true",
    "/redfish/v1/Systems/1?$expand=*($levels=1)#frag",
]


class TestFence(unittest.TestCase):
    def test_allowed_paths_pass_unchanged(self):
        for path in ALLOWED:
            with self.subTest(path=path):
                self.assertIsNone(fence.path_refusal(path))
                self.assertTrue(fence.is_allowed_path(path))
                self.assertEqual(fence.fence_path(path), path)

    def test_refused_paths_raise_with_a_reason(self):
        for path in REFUSED:
            if path == "/redfish/v1":
                continue
            with self.subTest(path=path):
                reason = fence.path_refusal(path)
                self.assertIsInstance(reason, str)
                self.assertTrue(reason)
                self.assertFalse(fence.is_allowed_path(path))
                with self.assertRaises(fence.RedfishPathRefused):
                    fence.fence_path(path)

    def test_non_strings_refused(self):
        for value in (None, 42, b"/redfish/v1/", ["/redfish/v1/"]):
            with self.subTest(value=value):
                self.assertIsNotNone(fence.path_refusal(value))
                with self.assertRaises(fence.RedfishPathRefused):
                    fence.fence_path(value)

    def test_root_alias(self):
        # The bare root is the one allowed slash-less spelling; it is
        # normalised so the cache key and the wire path agree.
        self.assertIsNone(fence.path_refusal("/redfish/v1"))
        self.assertEqual(fence.fence_path("/redfish/v1"), "/redfish/v1/")

    def test_fragment_is_a_pointer_not_a_request(self):
        # Lenovo links like Power#/PowerSupplies/0 name a JSON pointer inside
        # the Power resource; the resource is what goes on the wire.
        link = "/redfish/v1/Chassis/1/Power#/PowerSupplies/0"
        self.assertIsNone(fence.path_refusal(link))
        self.assertEqual(fence.fence_path(link), "/redfish/v1/Chassis/1/Power")
        # ...but a fragment cannot smuggle an Actions segment past the fence
        # either way round.
        self.assertIsNotNone(fence.path_refusal("/redfish/v1/Chassis/1/Actions/x#/y"))

    def test_server_supplied_links_go_through_the_same_fence(self):
        # A firmware handing back an @odata.id into Actions must be refused
        # exactly like a literal: there is one fence, not two.
        payload = {
            "Members": [
                {"@odata.id": "/redfish/v1/Systems/1/Memory/DIMM_1"},
                {"@odata.id": "/redfish/v1/Systems/1/Actions/ComputerSystem.Reset"},
            ]
        }
        verdicts = [fence.is_allowed_path(m["@odata.id"]) for m in payload["Members"]]
        self.assertEqual(verdicts, [True, False])

    def test_query_allowlist_is_expand_select_and_the_page_selectors(self):
        self.assertEqual(
            fence.ALLOWED_QUERY_PARAMS, frozenset({"$expand", "$select", "$skip", "$skiptoken"})
        )

    def test_reason_names_the_offending_segment(self):
        self.assertIn("Actions", fence.path_refusal("/redfish/v1/Systems/1/Actions/x"))
        self.assertIn("$top", fence.path_refusal("/redfish/v1/Systems/1?$top=1"))
        self.assertIn("percent", fence.path_refusal("/redfish/v1/Systems/1/%41ctions/x"))

    def test_percent_escapes_never_reach_the_wire(self):
        # The fence checks the spelling; the HTTP library would decode %41 to
        # 'A' before sending, so the only safe answer is to refuse any escape.
        for path in (
            "/redfish/v1/Systems/1/%41ctions/ComputerSystem.Reset",
            "/redfish/v1/%53essionService/Sessions",
            "/redfish/v1/Systems/1?$expand=%2A",
        ):
            with self.subTest(path=path):
                self.assertIsNotNone(fence.path_refusal(path))


if __name__ == "__main__":
    unittest.main()
