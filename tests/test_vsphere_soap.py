"""vsphere_soap: operation pinning, the refusal corpus, envelope shapes, response parsing.

The refusal corpus below is the only place in the repo where state-changing
vim25 operation names are spelled — CI greps jobs/ for them and this file is
outside that scope on purpose.
"""

import unittest
import xml.etree.ElementTree as ET

if __package__:
    from . import _loader
else:  # unittest discover -s tests imports test modules as top-level
    import _loader

soap = _loader.vsphere_soap

NS = "urn:vim25"
XSI = "http://www.w3.org/2001/XMLSchema-instance"
SOAPENV = "http://schemas.xmlsoap.org/soap/envelope/"

SIX = frozenset(
    {
        "RetrieveServiceContent",
        "Login",
        "Logout",
        "RetrievePropertiesEx",
        "ContinueRetrievePropertiesEx",
        "QueryNetworkHint",
    }
)

PC = "ha-property-collector"
HOST_PATHS = ["config.network", "hardware.systemInfo"]


def _ok_retrieve(**overrides):
    params = {
        "property_collector": PC,
        "type": "HostSystem",
        "moids": ["ha-host"],
        "paths": HOST_PATHS,
    }
    params.update(overrides)
    return params


LONG_MOID = "haTask-ha-host-vim.host.StorageSystem.refreshStorageSystem-123456789"

# (operation, kwargs) pairs that must be refused BEFORE any bytes form.
REFUSAL_CORPUS = [
    # --- operations outside the six (the names CI bans from jobs/) ---
    ("ReconfigVM_Task", {}),
    ("PowerOnVM_Task", {}),
    ("PowerOffVM_Task", {}),
    ("ResetVM_Task", {}),
    ("UpdateNetworkConfig", {}),
    ("UpdateOptions", {}),
    ("EnableRuleset", {}),
    ("DisableRuleset", {}),
    ("CreateContainerView", {}),
    ("DestroyView", {}),
    ("ClearLog", {}),
    ("Destroy_Task", {}),
    ("RebootHost_Task", {}),
    ("ShutdownHost_Task", {}),
    ("EnterMaintenanceMode_Task", {}),
    ("UpdateDateTimeConfig", {}),
    ("UpdateServicePolicy", {}),
    ("StartService", {}),
    ("StopService", {}),
    ("RestartService", {}),
    ("CreateSnapshot_Task", {}),
    ("RegisterVM_Task", {}),
    ("UnregisterVM", {}),
    ("ReconfigureAutostart", {}),
    ("CreateCollectorForEvents", {}),
    ("RetrieveProperties", {}),  # the deprecated non-Ex form: not on the list
    ("CreateFilter", {}),
    ("WaitForUpdatesEx", {}),
    ("QueryPerf", {}),
    ("RefreshStorageSystem", {}),
    ("retrievepropertiesex", _ok_retrieve()),  # case matters
    ("RetrievePropertiesEx ", _ok_retrieve()),  # and so does whitespace
    ("", {}),
    (None, {}),
    # --- RetrievePropertiesEx: unfenced values ---
    ("RetrievePropertiesEx", _ok_retrieve(moids=["ha-host; drop"])),
    ("RetrievePropertiesEx", _ok_retrieve(moids=["ha host"])),
    ("RetrievePropertiesEx", _ok_retrieve(moids=["<ha-host>"])),
    ("RetrievePropertiesEx", _ok_retrieve(moids=["../ha-host"])),
    ("RetrievePropertiesEx", _ok_retrieve(moids=["a" * 161])),
    ("RetrievePropertiesEx", _ok_retrieve(moids=[""])),
    ("RetrievePropertiesEx", _ok_retrieve(moids=[])),
    ("RetrievePropertiesEx", _ok_retrieve(moids="ha-host")),  # a str is not a list
    ("RetrievePropertiesEx", _ok_retrieve(moids=[42])),
    ("RetrievePropertiesEx", _ok_retrieve(moids=[None])),
    ("RetrievePropertiesEx", _ok_retrieve(paths=["config.network.pnic[]"])),
    ("RetrievePropertiesEx", _ok_retrieve(paths=["config.service.service[key='ntpd']"])),
    ("RetrievePropertiesEx", _ok_retrieve(paths=["config"])),  # whole config: never
    ("RetrievePropertiesEx", _ok_retrieve(paths=["*"])),
    ("RetrievePropertiesEx", _ok_retrieve(paths=[""])),
    ("RetrievePropertiesEx", _ok_retrieve(paths=[])),  # empty = 'all', refused
    ("RetrievePropertiesEx", _ok_retrieve(paths="config.network")),
    ("RetrievePropertiesEx", _ok_retrieve(paths=["config.network", "nope.nothing"])),
    ("RetrievePropertiesEx", _ok_retrieve(paths=["config.network "])),
    ("RetrievePropertiesEx", _ok_retrieve(paths=["Config.Network"])),
    ("RetrievePropertiesEx", _ok_retrieve(type="SessionManager", paths=["sessionList"])),
    ("RetrievePropertiesEx", _ok_retrieve(type="PropertyCollector", paths=["filter"])),
    ("RetrievePropertiesEx", _ok_retrieve(type="Folder", paths=["childEntity"])),
    ("RetrievePropertiesEx", _ok_retrieve(type="VirtualMachine", paths=["config.network"])),
    ("RetrievePropertiesEx", _ok_retrieve(type="Datastore", paths=["hardware.systemInfo"])),
    ("RetrievePropertiesEx", _ok_retrieve(type=None)),
    ("RetrievePropertiesEx", _ok_retrieve(property_collector="ha property collector")),
    ("RetrievePropertiesEx", _ok_retrieve(all=True)),
    ("RetrievePropertiesEx", _ok_retrieve(skip=True)),
    ("RetrievePropertiesEx", _ok_retrieve(max_objects=0)),
    ("RetrievePropertiesEx", _ok_retrieve(max_objects=-5)),
    ("RetrievePropertiesEx", _ok_retrieve(max_objects="100")),
    ("RetrievePropertiesEx", _ok_retrieve(max_objects=True)),
    ("RetrievePropertiesEx", _ok_retrieve(traverse="recentTask")),
    ("RetrievePropertiesEx", _ok_retrieve(traverse={"path": "vm", "type": "VirtualMachine"})),
    (
        "RetrievePropertiesEx",
        _ok_retrieve(
            traverse={"path": "vm", "type": "VirtualMachine", "paths": ["config.network"]}
        ),
    ),
    (
        "RetrievePropertiesEx",
        _ok_retrieve(traverse={"path": "nope", "type": "Task", "paths": ["info"]}),
    ),
    (
        "RetrievePropertiesEx",
        _ok_retrieve(traverse={"path": "vm", "type": "VirtualMachine", "paths": []}),
    ),
    (
        "RetrievePropertiesEx",
        _ok_retrieve(
            traverse={"path": "vm", "type": "VirtualMachine", "paths": ["name"], "skip": True}
        ),
    ),
    ("RetrievePropertiesEx", {"type": "HostSystem", "moids": ["ha-host"], "paths": HOST_PATHS}),
    ("RetrievePropertiesEx", {}),
    # --- ContinueRetrievePropertiesEx ---
    ("ContinueRetrievePropertiesEx", {"property_collector": PC}),
    ("ContinueRetrievePropertiesEx", {"property_collector": PC, "token": ""}),
    ("ContinueRetrievePropertiesEx", {"property_collector": PC, "token": "1 OR 1"}),
    ("ContinueRetrievePropertiesEx", {"property_collector": PC, "token": "<1>"}),
    ("ContinueRetrievePropertiesEx", {"property_collector": PC, "token": 1}),
    ("ContinueRetrievePropertiesEx", {"property_collector": PC, "token": "1", "extra": 1}),
    # --- QueryNetworkHint ---
    ("QueryNetworkHint", {}),
    ("QueryNetworkHint", {"network_system": "network system"}),
    ("QueryNetworkHint", {"network_system": "networkSystem", "devices": ["vmnic0; rm"]}),
    ("QueryNetworkHint", {"network_system": "networkSystem", "devices": ["eth0"]}),
    ("QueryNetworkHint", {"network_system": "networkSystem", "devices": ["vmnic"]}),
    ("QueryNetworkHint", {"network_system": "networkSystem", "devices": ["VMNIC0"]}),
    ("QueryNetworkHint", {"network_system": "networkSystem", "devices": "vmnic0"}),
    ("QueryNetworkHint", {"network_system": "networkSystem", "devices": [""]}),
    ("QueryNetworkHint", {"network_system": "networkSystem", "device": ["vmnic0"]}),
    # --- Login / Logout / RetrieveServiceContent ---
    ("Login", {"session_manager": "ha-sessionmgr", "username": "ro", "password": "x"}),
    (
        "Login",
        {"session_manager": "ha-sessionmgr", "username": "", "password": "x", "locale": "en"},
    ),
    (
        "Login",
        {"session_manager": "ha-sessionmgr", "username": "ro", "password": None, "locale": "en"},
    ),
    (
        "Login",
        {
            "session_manager": "ha-sessionmgr",
            "username": "ro",
            "password": "x",
            "locale": "en; drop",
        },
    ),
    (
        "Login",
        {"session_manager": "ha session", "username": "ro", "password": "x", "locale": "en"},
    ),
    ("Logout", {}),
    ("Logout", {"session_manager": "ha-sessionmgr", "force": True}),
    ("RetrieveServiceContent", {"moid": "ServiceInstance"}),
]


class TestOperationPinning(unittest.TestCase):
    def test_exactly_six_operations(self):
        self.assertEqual(soap.OPERATIONS, SIX)
        self.assertIsInstance(soap.OPERATIONS, frozenset)

    def test_every_operation_has_a_builder(self):
        for operation in SIX:
            self.assertIn(operation, soap._BUILDERS)
        self.assertEqual(set(soap._BUILDERS), SIX)

    def test_namespace_fence(self):
        for namespace in ("urn:vim2", "http://evil.example/vim25", "", None, "urn:vim25;x"):
            with self.subTest(namespace=namespace):
                with self.assertRaises(soap.SoapRefused):
                    soap.build_envelope("RetrieveServiceContent", namespace)
        soap.build_envelope("RetrieveServiceContent", "urn:vim25")
        soap.build_envelope("RetrieveServiceContent", "urn:vim25/8.0.3.0")

    def test_action_namespace(self):
        self.assertEqual(soap.action_namespace("8.0.3.0"), "urn:vim25/8.0.3.0")
        self.assertEqual(soap.action_namespace(soap.FALLBACK_VERSION), "urn:vim25/6.5")
        for bad in ("", "x/../y", "8.0.3.0 ", None, "8.0<"):
            with self.assertRaises(soap.SoapRefused):
                soap.action_namespace(bad)


class TestRefusalCorpus(unittest.TestCase):
    def test_corpus_is_large_enough_to_mean_something(self):
        self.assertGreaterEqual(len(REFUSAL_CORPUS), 40)

    def test_every_entry_is_refused_before_bytes_form(self):
        for operation, kwargs in REFUSAL_CORPUS:
            with self.subTest(operation=operation, kwargs=kwargs):
                with self.assertRaises(soap.SoapRefused):
                    soap.build_envelope(operation, NS, **kwargs)

    def test_property_paths_cover_the_catalog_types(self):
        for mo_type in (
            "HostSystem",
            "VirtualMachine",
            "Datastore",
            "TaskManager",
            "Task",
            "EventManager",
            "LicenseManager",
            "HostNetworkSystem",
        ):
            self.assertIn(mo_type, soap.PROPERTY_PATHS)
            self.assertIsInstance(soap.PROPERTY_PATHS[mo_type], frozenset)
        # Every allowlisted path is a bare dotted path — no brackets, no filters.
        for paths in soap.PROPERTY_PATHS.values():
            for path in paths:
                self.assertRegex(path, r"^[A-Za-z][A-Za-z0-9]*(\.[A-Za-z][A-Za-z0-9]*)*$")

    def test_long_task_moid_is_allowed(self):
        self.assertEqual(soap.check_moid(LONG_MOID), LONG_MOID)
        self.assertGreater(len(LONG_MOID), 64)


# --- envelope shapes ---------------------------------------------------------


def _body(envelope_bytes):
    root = ET.fromstring(envelope_bytes)
    body = root.find("{%s}Body" % SOAPENV)
    children = list(body)
    return children[0]


def _tag(element):
    return element.tag.rsplit("}", 1)[-1]


class TestEnvelopeShapes(unittest.TestCase):
    def test_declaration_and_envelope(self):
        raw = soap.build_envelope("RetrieveServiceContent", NS)
        self.assertIsInstance(raw, bytes)
        self.assertTrue(raw.startswith(b'<?xml version="1.0" encoding="UTF-8"?>'))
        op = _body(raw)
        self.assertEqual(op.tag, "{%s}RetrieveServiceContent" % NS)
        this = op.find("{%s}_this" % NS)
        self.assertEqual(this.get("type"), "ServiceInstance")
        self.assertEqual(this.text, "ServiceInstance")

    def test_login_and_logout(self):
        raw = soap.build_envelope(
            "Login",
            NS,
            session_manager="ha-sessionmgr",
            username="ro&user",
            password='p<a>ss"w&rd',
            locale="en",
        )
        op = _body(raw)
        self.assertEqual([_tag(c) for c in op], ["_this", "userName", "password", "locale"])
        self.assertEqual(op.find("{%s}_this" % NS).get("type"), "SessionManager")
        self.assertEqual(op.find("{%s}userName" % NS).text, "ro&user")
        self.assertEqual(op.find("{%s}password" % NS).text, 'p<a>ss"w&rd')  # escaped, round-trips
        self.assertEqual(op.find("{%s}locale" % NS).text, "en")
        raw = soap.build_envelope("Logout", NS, session_manager="ha-sessionmgr")
        op = _body(raw)
        self.assertEqual([_tag(c) for c in op], ["_this"])

    def test_retrieve_properties_shape(self):
        raw = soap.build_envelope(
            "RetrievePropertiesEx",
            NS,
            property_collector=PC,
            type="HostSystem",
            moids=("ha-host",),
            paths=("hardware.systemInfo", "config.network", "hardware.systemInfo"),
        )
        op = _body(raw)
        self.assertEqual([_tag(c) for c in op], ["_this", "specSet", "options"])
        self.assertEqual(op.find("{%s}_this" % NS).get("type"), "PropertyCollector")
        spec = op.find("{%s}specSet" % NS)
        self.assertEqual([_tag(c) for c in spec], ["propSet", "objectSet"])
        prop = spec.find("{%s}propSet" % NS)
        self.assertEqual(prop.find("{%s}type" % NS).text, "HostSystem")
        self.assertEqual(prop.find("{%s}all" % NS).text, "false")
        # deduplicated and sorted: identical kwargs -> identical bytes -> one cache entry
        self.assertEqual(
            [p.text for p in prop.findall("{%s}pathSet" % NS)],
            ["config.network", "hardware.systemInfo"],
        )
        obj = spec.find("{%s}objectSet" % NS)
        self.assertEqual(obj.find("{%s}obj" % NS).get("type"), "HostSystem")
        self.assertEqual(obj.find("{%s}obj" % NS).text, "ha-host")
        self.assertEqual(obj.find("{%s}skip" % NS).text, "false")
        self.assertIsNone(obj.find("{%s}selectSet" % NS))
        # RetrieveOptions is mandatory even when empty
        options = op.find("{%s}options" % NS)
        self.assertIsNotNone(options)
        self.assertEqual(list(options), [])
        self.assertIn(b"<options/>", raw)

    def test_retrieve_properties_multiple_objects_and_max_objects(self):
        raw = soap.build_envelope(
            "RetrievePropertiesEx",
            NS,
            property_collector=PC,
            type="VirtualMachine",
            moids=["1", "2", "42"],
            paths=["name", "config.uuid"],
            max_objects=100,
        )
        op = _body(raw)
        spec = op.find("{%s}specSet" % NS)
        objs = spec.findall("{%s}objectSet" % NS)
        self.assertEqual([o.find("{%s}obj" % NS).text for o in objs], ["1", "2", "42"])
        self.assertEqual(op.find("{%s}options/{%s}maxObjects" % (NS, NS)).text, "100")

    def test_retrieve_properties_with_traversal(self):
        raw = soap.build_envelope(
            "RetrievePropertiesEx",
            NS,
            property_collector=PC,
            type="TaskManager",
            moids=["ha-taskmgr"],
            paths=["recentTask"],
            traverse={"path": "recentTask", "type": "Task", "paths": ["info.key", "info.state"]},
        )
        op = _body(raw)
        spec = op.find("{%s}specSet" % NS)
        props = spec.findall("{%s}propSet" % NS)
        self.assertEqual([p.find("{%s}type" % NS).text for p in props], ["TaskManager", "Task"])
        obj = spec.find("{%s}objectSet" % NS)
        self.assertEqual(obj.find("{%s}skip" % NS).text, "false")
        select = obj.find("{%s}selectSet" % NS)
        self.assertEqual(select.get("{%s}type" % XSI), "TraversalSpec")
        self.assertEqual(select.find("{%s}type" % NS).text, "TaskManager")
        self.assertEqual(select.find("{%s}path" % NS).text, "recentTask")
        # Traversal-only (no root paths): root objects are skipped, not fetched.
        raw = soap.build_envelope(
            "RetrievePropertiesEx",
            NS,
            property_collector=PC,
            type="TaskManager",
            moids=["ha-taskmgr"],
            paths=[],
            traverse={"path": "recentTask", "type": "Task", "paths": ["info"]},
        )
        spec = _body(raw).find("{%s}specSet" % NS)
        self.assertEqual(len(spec.findall("{%s}propSet" % NS)), 1)
        self.assertEqual(spec.find("{%s}objectSet/{%s}skip" % (NS, NS)).text, "true")

    def test_continue(self):
        raw = soap.build_envelope(
            "ContinueRetrievePropertiesEx", NS, property_collector=PC, token="1"
        )
        op = _body(raw)
        self.assertEqual([_tag(c) for c in op], ["_this", "token"])
        self.assertEqual(op.find("{%s}token" % NS).text, "1")

    def test_query_network_hint_omits_device_when_all(self):
        raw = soap.build_envelope("QueryNetworkHint", NS, network_system="networkSystem")
        op = _body(raw)
        self.assertEqual([_tag(c) for c in op], ["_this"])
        self.assertEqual(op.find("{%s}_this" % NS).get("type"), "HostNetworkSystem")
        self.assertNotIn(b"<device", raw)
        raw = soap.build_envelope(
            "QueryNetworkHint", NS, network_system="networkSystem", devices=[]
        )
        self.assertNotIn(b"<device", raw)
        raw = soap.build_envelope(
            "QueryNetworkHint", NS, network_system="networkSystem", devices=["vmnic0", "vmnic1"]
        )
        op = _body(raw)
        self.assertEqual([d.text for d in op.findall("{%s}device" % NS)], ["vmnic0", "vmnic1"])

    def test_versioned_namespace_lands_on_the_operation_element(self):
        raw = soap.build_envelope("RetrieveServiceContent", "urn:vim25/8.0.3.0")
        self.assertEqual(_body(raw).tag, "{urn:vim25/8.0.3.0}RetrieveServiceContent")


# --- parsing -----------------------------------------------------------------

_ENVELOPE = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    '<soapenv:Envelope xmlns:soapenc="http://schemas.xmlsoap.org/soap/encoding/" '
    'xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" '
    'xmlns:xsd="http://www.w3.org/2001/XMLSchema" '
    'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"><soapenv:Body>%s'
    "</soapenv:Body></soapenv:Envelope>"
)

RETRIEVE_PAGE_1 = _ENVELOPE % (
    '<RetrievePropertiesExResponse xmlns="urn:vim25"><returnval>'
    "<objects>"
    '<obj type="HostSystem">ha-host</obj>'
    '<propSet><name>config.network.pnic</name><val xsi:type="ArrayOfPhysicalNic">'
    '<PhysicalNic xsi:type="PhysicalNic"><key>key-vim.host.PhysicalNic-vmnic0</key>'
    "<device>vmnic0</device><pci>0000:18:00.0</pci><driver>i40en</driver>"
    "<linkSpeed><speedMb>10000</speedMb><duplex>true</duplex></linkSpeed>"
    "<mac>00:11:22:33:44:55</mac></PhysicalNic>"
    '<PhysicalNic xsi:type="PhysicalNic"><key>key-vim.host.PhysicalNic-vmnic1</key>'
    "<device>vmnic1</device><pci>0000:18:00.1</pci><driver>i40en</driver>"
    "<mac>00:11:22:33:44:56</mac></PhysicalNic>"
    "</val></propSet>"
    '<propSet><name>hardware.pciDevice</name><val xsi:type="ArrayOfHostPciDevice">'
    "<HostPciDevice><id>0000:18:00.0</id><classId>512</classId><vendorId>-32634</vendorId>"
    "<deviceId>14239</deviceId><vendorName>Intel Corporation</vendorName></HostPciDevice>"
    "</val></propSet>"
    '<propSet><name>summary.rebootRequired</name><val xsi:type="xsd:boolean">false</val></propSet>'
    '<propSet><name>hardware.memorySize</name><val xsi:type="xsd:long">137438953472</val></propSet>'
    "<propSet><name>hardware.cpuInfo.numCpuCores</name>"
    '<val xsi:type="xsd:short">-32634</val></propSet>'
    "<propSet><name>runtime.bootTime</name>"
    '<val xsi:type="xsd:dateTime">2026-09-20T03:14:15.123456Z</val></propSet>'
    "<propSet><name>summary.config.name</name>"
    '<val xsi:type="xsd:string">se350-1.example.net</val></propSet>'
    '<propSet><name>configManager.networkSystem</name><val type="HostNetworkSystem" '
    'xsi:type="ManagedObjectReference">networkSystem</val></propSet>'
    '<propSet><name>datastore</name><val xsi:type="ArrayOfManagedObjectReference">'
    '<ManagedObjectReference type="Datastore" xsi:type="ManagedObjectReference">'
    "5f1e0000-aaaa-bbbb-cccc-000000000001</ManagedObjectReference></val></propSet>"
    '<propSet><name>config.option</name><val xsi:type="ArrayOfOptionValue">'
    "<OptionValue><key>UserVars.ESXiShellTimeOut</key>"
    '<value xsi:type="xsd:int">0</value></OptionValue>'
    "<OptionValue><key>Net.TcpipHeapMax</key>"
    '<value xsi:type="xsd:long">1024</value></OptionValue>'
    "<OptionValue><key>Config.HostAgent.plugins.solo.enableMob</key>"
    '<value xsi:type="xsd:boolean">false</value></OptionValue>'
    "<OptionValue><key>Syslog.global.logHost</key>"
    '<value xsi:type="xsd:string"></value></OptionValue>'
    "</val></propSet>"
    '<propSet><name>config.pciPassthruInfo</name><val xsi:type="ArrayOfHostPciPassthruInfo">'
    '<HostPciPassthruInfo xsi:type="HostSriovInfo"><id>0000:18:00.0</id>'
    "<passthruEnabled>false</passthruEnabled><sriovCapable>true</sriovCapable>"
    "<numVirtualFunction>0</numVirtualFunction></HostPciPassthruInfo>"
    "<HostPciPassthruInfo><id>0000:00:1f.0</id><passthruEnabled>false</passthruEnabled>"
    "</HostPciPassthruInfo>"
    "</val></propSet>"
    '<propSet><name>config.network.portgroup</name><val xsi:type="ArrayOfHostPortGroup">'
    "<HostPortGroup><key>key-vim.host.PortGroup-Management Network</key>"
    "<spec><name>Management Network</name><vlanId>0</vlanId><vswitchName>vSwitch0</vswitchName>"
    "<policy><security/></policy></spec></HostPortGroup>"
    "</val></propSet>"
    '<propSet><name>runtime.healthSystemRuntime</name><val xsi:type="HealthSystemRuntime">'
    "<systemHealthInfo><numericSensorInfo><name>Fan Redundancy --- Fully Redundant</name>"
    "<healthState><key>green</key></healthState></numericSensorInfo></systemHealthInfo>"
    "</val></propSet>"
    "<missingSet><path>config.firewall</path><fault>"
    '<fault xsi:type="InvalidProperty"><name>config.firewall</name></fault>'
    "<localizedMessage>A specified parameter was not correct: config.firewall</localizedMessage>"
    "</fault></missingSet>"
    "</objects>"
    "<token>1</token>"
    "</returnval></RetrievePropertiesExResponse>"
)

RETRIEVE_PAGE_2 = _ENVELOPE % (
    '<ContinueRetrievePropertiesExResponse xmlns="urn:vim25"><returnval>'
    '<objects><obj type="VirtualMachine">1</obj>'
    '<propSet><name>name</name><val xsi:type="xsd:string">fw-vm500-a</val></propSet>'
    "<propSet><name>runtime.powerState</name>"
    '<val xsi:type="VirtualMachinePowerState">poweredOn</val></propSet>'
    "</objects>"
    '<objects><obj type="VirtualMachine">2</obj>'
    '<propSet><name>name</name><val xsi:type="xsd:string">fw-vm500-b</val></propSet>'
    "<missingSet><path>runtime.powerState</path><fault>"
    '<fault xsi:type="NotAuthenticated"><object type="VirtualMachine">2</object>'
    "<privilegeId>System.View</privilegeId></fault></fault></missingSet>"
    "</objects>"
    "</returnval></ContinueRetrievePropertiesExResponse>"
)

RETRIEVE_EMPTY = _ENVELOPE % '<RetrievePropertiesExResponse xmlns="urn:vim25"/>'

FAULT_LOGIN = _ENVELOPE % (
    "<soapenv:Fault><faultcode>ServerFaultCode</faultcode>"
    "<faultstring>Cannot complete login due to an incorrect user name or password.</faultstring>"
    '<detail><InvalidLoginFault xsi:type="InvalidLogin"></InvalidLoginFault></detail>'
    "</soapenv:Fault>"
)

FAULT_PERMISSION = _ENVELOPE % (
    "<soapenv:Fault><faultcode>ServerFaultCode</faultcode>"
    "<faultstring>Permission to perform this operation was denied.</faultstring>"
    '<detail><NoPermissionFault xsi:type="NoPermission"><object type="HostSystem">ha-host</object>'
    "<privilegeId>Host.Config.Network</privilegeId></NoPermissionFault></detail>"
    "</soapenv:Fault>"
)

FAULT_NO_DETAIL = _ENVELOPE % (
    "<soapenv:Fault><faultcode>ServerFaultCode</faultcode>"
    "<faultstring>Unexpected</faultstring></soapenv:Fault>"
)

SERVICE_CONTENT = _ENVELOPE % (
    '<RetrieveServiceContentResponse xmlns="urn:vim25"><returnval>'
    '<rootFolder type="Folder">ha-folder-root</rootFolder>'
    '<propertyCollector type="PropertyCollector">ha-property-collector</propertyCollector>'
    "<about><name>VMware ESXi</name><fullName>VMware ESXi 8.0.3 build-24022510</fullName>"
    "<vendor>VMware, Inc.</vendor><version>8.0.3</version><build>24022510</build>"
    "<osType>vmnix-x86</osType><productLineId>embeddedEsx</productLineId>"
    "<apiType>HostAgent</apiType><apiVersion>8.0.3.0</apiVersion></about>"
    '<setting type="OptionManager">HostAgentSettings</setting>'
    '<sessionManager type="SessionManager">ha-sessionmgr</sessionManager>'
    '<taskManager type="TaskManager">ha-taskmgr</taskManager>'
    '<eventManager type="EventManager">ha-eventmgr</eventManager>'
    '<licenseManager type="LicenseManager">ha-license-manager</licenseManager>'
    "</returnval></RetrieveServiceContentResponse>"
)

NETWORK_HINT = _ENVELOPE % (
    '<QueryNetworkHintResponse xmlns="urn:vim25">'
    "<returnval><device>vmnic0</device>"
    "<subnet><ipSubnet>10.10.10.0</ipSubnet><vlanId>10</vlanId></subnet>"
    "<subnet><ipSubnet>10.10.20.0</ipSubnet><vlanId>20</vlanId></subnet>"
    "<connectedSwitchPort><cdpVersion>2</cdpVersion><timeout>0</timeout><ttl>142</ttl>"
    "<devId>core-9500-a.example.net</devId><address>10.0.0.1</address>"
    "<portId>TwentyFiveGigE1/0/1</portId><hardwarePlatform>cisco C9500-24Y4C</hardwarePlatform>"
    "<vlan>1</vlan><fullDuplex>true</fullDuplex><mtu>9198</mtu></connectedSwitchPort>"
    "</returnval>"
    "<returnval><device>vmnic1</device></returnval>"
    "</QueryNetworkHintResponse>"
)

SERVICE_VERSIONS = (
    '<?xml version="1.0" encoding="UTF-8" ?>'
    '<namespaces version="1.0">'
    "<namespace><name>urn:vim25</name><version>8.0.3.0</version>"
    "<priorVersions><version>8.0.2.0</version><version>7.0.3.0</version></priorVersions>"
    "</namespace>"
    "<namespace><name>urn:vim2</name><version>2.0</version></namespace>"
    "</namespaces>"
)


class TestRetrieveResultParsing(unittest.TestCase):
    def setUp(self):
        self.page = soap.parse_retrieve_result(RETRIEVE_PAGE_1)
        self.props = self.page["objects"][0]["props"]

    def test_object_token_and_missing(self):
        self.assertEqual(self.page["token"], "1")
        self.assertEqual(len(self.page["objects"]), 1)
        self.assertEqual(self.page["objects"][0]["obj"], {"type": "HostSystem", "moid": "ha-host"})
        self.assertEqual(
            self.page["objects"][0]["missing"],
            [
                {
                    "path": "config.firewall",
                    "fault": "InvalidProperty",
                    "message": "A specified parameter was not correct: config.firewall",
                }
            ],
        )

    def test_typed_leaves(self):
        self.assertIs(self.props["summary.rebootRequired"], False)
        self.assertEqual(self.props["hardware.memorySize"], 137438953472)
        self.assertIsInstance(self.props["hardware.memorySize"], int)
        # dateTime stays a verbatim string (py3.9 fromisoformat rejects Z+micros)
        self.assertEqual(self.props["runtime.bootTime"], "2026-09-20T03:14:15.123456Z")
        self.assertEqual(self.props["summary.config.name"], "se350-1.example.net")

    def test_short_signed_by_default_and_masked_on_request(self):
        self.assertEqual(self.props["hardware.cpuInfo.numCpuCores"], -32634)
        masked = soap.parse_retrieve_result(RETRIEVE_PAGE_1, mask_short=True)
        self.assertEqual(masked["objects"][0]["props"]["hardware.cpuInfo.numCpuCores"], 0x8086)
        # Untyped shorts inside data objects arrive as strings; the helper masks them.
        pci = self.props["hardware.pciDevice"][0]
        self.assertEqual(pci["vendorId"], "-32634")
        self.assertEqual(soap.to_unsigned_short(pci["vendorId"]), 0x8086)
        self.assertEqual(soap.to_unsigned_short(pci["deviceId"]), 14239)
        self.assertIsNone(soap.to_unsigned_short(None))
        self.assertIsNone(soap.to_unsigned_short("n/a"))

    def test_arrays_and_data_objects(self):
        pnics = self.props["config.network.pnic"]
        self.assertIsInstance(pnics, list)
        self.assertEqual([p["device"] for p in pnics], ["vmnic0", "vmnic1"])
        self.assertEqual(pnics[0]["_type"], "PhysicalNic")
        self.assertEqual(pnics[0]["linkSpeed"], {"speedMb": "10000", "duplex": "true"})
        self.assertNotIn("linkSpeed", pnics[1])  # absent optional stays absent
        # Untyped leaves are strings; helpers convert.
        self.assertEqual(soap.to_int(pnics[0]["linkSpeed"]["speedMb"]), 10000)
        self.assertIs(soap.to_bool(pnics[0]["linkSpeed"]["duplex"]), True)
        self.assertIsNone(soap.to_bool("maybe"))
        # An ArrayOf item without its own xsi:type inherits the array's item type.
        self.assertEqual(self.props["hardware.pciDevice"][0]["_type"], "HostPciDevice")

    def test_polymorphic_xsi_type_is_preserved(self):
        passthru = self.props["config.pciPassthruInfo"]
        self.assertEqual([p["_type"] for p in passthru], ["HostSriovInfo", "HostPciPassthruInfo"])
        self.assertEqual(passthru[0]["numVirtualFunction"], "0")
        health = self.props["runtime.healthSystemRuntime"]
        self.assertEqual(health["_type"], "HealthSystemRuntime")
        sensor = health["systemHealthInfo"]["numericSensorInfo"]
        self.assertEqual(sensor["name"], "Fan Redundancy --- Fully Redundant")
        self.assertEqual(sensor["healthState"], {"key": "green"})
        # A single repeated-capable child arrives as a value; aslist() makes it uniform.
        self.assertEqual(soap.aslist(sensor), [sensor])
        self.assertEqual(soap.aslist(None), [])
        self.assertEqual(soap.aslist([1, 2]), [1, 2])

    def test_managed_object_references(self):
        self.assertEqual(
            self.props["configManager.networkSystem"],
            {"type": "HostNetworkSystem", "moid": "networkSystem"},
        )
        self.assertEqual(
            self.props["datastore"],
            [{"type": "Datastore", "moid": "5f1e0000-aaaa-bbbb-cccc-000000000001"}],
        )

    def test_option_values_typed_by_xsi_type(self):
        options = {o["key"]: o["value"] for o in self.props["config.option"]}
        self.assertEqual(options["UserVars.ESXiShellTimeOut"], 0)
        self.assertEqual(options["Net.TcpipHeapMax"], 1024)
        self.assertIs(options["Config.HostAgent.plugins.solo.enableMob"], False)
        self.assertEqual(options["Syslog.global.logHost"], "")  # typed empty string, not None

    def test_empty_container_is_none(self):
        # hostd emits <security/> on inheriting port groups: no children, no
        # text, no type — that is "unset", the repo's None, never {} or "".
        portgroup = self.props["config.network.portgroup"][0]
        self.assertIsNone(portgroup["spec"]["policy"]["security"])

    def test_empty_typed_data_object_keeps_its_type(self):
        # An empty vim25 data object whose only content is its xsi:type
        # (a CD-ROM entry in bootOrder) is {"_type": ...}; an empty xsd-typed
        # leaf stays "" and an untyped empty element stays None.
        page = soap.parse_retrieve_result(
            _ENVELOPE
            % (
                '<RetrievePropertiesExResponse xmlns="urn:vim25"><returnval>'
                '<objects><obj type="VirtualMachine">1</obj>'
                "<propSet><name>config.bootOptions</name>"
                '<val xsi:type="VirtualMachineBootOptions"><bootDelay>0</bootDelay>'
                '<bootOrder xsi:type="VirtualMachineBootOptionsBootableDiskDevice">'
                "<deviceKey>2000</deviceKey></bootOrder>"
                '<bootOrder xsi:type="VirtualMachineBootOptionsBootableCdromDevice"></bootOrder>'
                '<bootOrder xsi:type="VirtualMachineBootOptionsBootableFloppyDevice"/>'
                "<networkBootProtocol></networkBootProtocol></val></propSet>"
                '<propSet><name>config.firmware</name><val xsi:type="xsd:string"></val></propSet>'
                "</objects></returnval></RetrievePropertiesExResponse>"
            )
        )
        props = page["objects"][0]["props"]
        self.assertEqual(
            props["config.bootOptions"]["bootOrder"],
            [
                {"_type": "VirtualMachineBootOptionsBootableDiskDevice", "deviceKey": "2000"},
                {"_type": "VirtualMachineBootOptionsBootableCdromDevice"},
                {"_type": "VirtualMachineBootOptionsBootableFloppyDevice"},
            ],
        )
        self.assertIsNone(props["config.bootOptions"]["networkBootProtocol"])
        self.assertEqual(props["config.firmware"], "")

    def test_continuation_page_and_per_object_missing(self):
        page = soap.parse_retrieve_result(RETRIEVE_PAGE_2)
        self.assertIsNone(page["token"])
        self.assertEqual([o["obj"]["moid"] for o in page["objects"]], ["1", "2"])
        self.assertEqual(page["objects"][0]["props"]["runtime.powerState"], "poweredOn")
        self.assertEqual(page["objects"][1]["props"], {"name": "fw-vm500-b"})
        self.assertEqual(page["objects"][1]["missing"][0]["fault"], "NotAuthenticated")
        self.assertEqual(page["objects"][1]["missing"][0]["path"], "runtime.powerState")

    def test_empty_result(self):
        self.assertEqual(soap.parse_retrieve_result(RETRIEVE_EMPTY), {"objects": [], "token": None})

    def test_bytes_and_str_and_wrong_shapes(self):
        self.assertEqual(
            soap.parse_retrieve_result(RETRIEVE_PAGE_2.encode("utf-8"))["objects"][0]["obj"][
                "moid"
            ],
            "1",
        )
        with self.assertRaises(soap.SoapParseError):
            soap.parse_retrieve_result("<html>not soap</html>")
        with self.assertRaises(soap.SoapParseError):
            soap.parse_retrieve_result("<<<")
        with self.assertRaises(soap.SoapParseError):
            soap.parse_retrieve_result(SERVICE_CONTENT)  # wrong response element
        with self.assertRaises(soap.SoapParseError):
            soap.parse_retrieve_result(FAULT_LOGIN)


class TestFaultParsing(unittest.TestCase):
    def test_invalid_login(self):
        self.assertEqual(
            soap.parse_fault(FAULT_LOGIN),
            (
                "InvalidLoginFault",
                "Cannot complete login due to an incorrect user name or password.",
            ),
        )

    def test_no_permission(self):
        fault_type, message = soap.parse_fault(FAULT_PERMISSION)
        self.assertEqual(fault_type, "NoPermissionFault")
        self.assertIn("denied", message)

    def test_fault_without_detail_falls_back_to_code(self):
        self.assertEqual(soap.parse_fault(FAULT_NO_DETAIL), ("ServerFaultCode", "Unexpected"))

    def test_non_fault_is_none_none(self):
        self.assertEqual(soap.parse_fault(RETRIEVE_PAGE_1), (None, None))
        self.assertEqual(soap.parse_fault("<html/>"), (None, None))

    def test_malformed_raises(self):
        with self.assertRaises(soap.SoapParseError):
            soap.parse_fault("<<<")


class TestServiceContentAndVersions(unittest.TestCase):
    def test_service_content(self):
        content = soap.parse_service_content(SERVICE_CONTENT)
        self.assertEqual(content["about"]["apiType"], "HostAgent")
        self.assertEqual(content["about"]["build"], "24022510")
        for key, mo_type, moid in (
            ("sessionManager", "SessionManager", "ha-sessionmgr"),
            ("propertyCollector", "PropertyCollector", "ha-property-collector"),
            ("taskManager", "TaskManager", "ha-taskmgr"),
            ("eventManager", "EventManager", "ha-eventmgr"),
            ("licenseManager", "LicenseManager", "ha-license-manager"),
            ("rootFolder", "Folder", "ha-folder-root"),
        ):
            self.assertEqual(content[key], {"type": mo_type, "moid": moid})

    def test_service_content_missing_pieces(self):
        broken = SERVICE_CONTENT.replace(
            '<sessionManager type="SessionManager">ha-sessionmgr</sessionManager>', ""
        )
        with self.assertRaises(soap.SoapParseError):
            soap.parse_service_content(broken)
        with self.assertRaises(soap.SoapParseError):
            soap.parse_service_content(FAULT_LOGIN)

    def test_network_hint_returnvals(self):
        hints = soap.parse_returnval(NETWORK_HINT)
        self.assertEqual([h["device"] for h in hints], ["vmnic0", "vmnic1"])
        self.assertEqual([s["vlanId"] for s in hints[0]["subnet"]], ["10", "20"])
        port = hints[0]["connectedSwitchPort"]
        self.assertEqual(port["portId"], "TwentyFiveGigE1/0/1")
        self.assertEqual(port["devId"], "core-9500-a.example.net")
        self.assertNotIn("connectedSwitchPort", hints[1])

    def test_service_versions(self):
        parsed = soap.parse_service_versions(SERVICE_VERSIONS)
        self.assertEqual(parsed["namespace"], "urn:vim25")
        self.assertEqual(parsed["version"], "8.0.3.0")
        self.assertEqual(parsed["prior_versions"], ["8.0.2.0", "7.0.3.0"])
        self.assertIsNone(soap.parse_service_versions("<namespaces/>"))
        with self.assertRaises(soap.SoapParseError):
            soap.parse_service_versions("<<<")


if __name__ == "__main__":
    unittest.main()
