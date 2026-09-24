"""checks_vmware normalizers driven with hand-built vim25 SOAP fixtures, plus
collector tests through a REAL CollectorContext wrapped around a fake api-slot
client (so the cache-sharing assertions exercise the real per-run cache)."""

import unittest

if __package__:
    from . import _loader
else:  # unittest discover -s tests imports test modules as top-level
    import _loader

checks = _loader.checks_vmware
context = _loader.context
registry = _loader.registry
soap = _loader.vsphere_soap

HOST_FIXTURES = (
    "vsphere_host_identity.xml",
    "vsphere_host_hardware.xml",
    "vsphere_host_network.xml",
    "vsphere_host_services.xml",
    "vsphere_host_storage.xml",
    "vsphere_host_health.xml",
    "vsphere_host_vm_refs.xml",
)


def _page(name):
    return soap.parse_retrieve_result(_loader.fixture_text(name))


def _host_props():
    """Every host property the fixtures carry, merged into one props dict."""
    props = {}
    for name in HOST_FIXTURES:
        for obj in _page(name)["objects"]:
            props.update(obj["props"])
    return props


def _vm_objects():
    """The drained two-page per-VM result, as the transport would assemble it."""
    first = _page("vsphere_vms.xml")
    second = _page("vsphere_vms_page2.xml")
    return first["objects"] + second["objects"]


def _network():
    return _host_props()["config.network"]


def _hints():
    return soap.parse_returnval(_loader.fixture_text("vsphere_network_hint.xml"))


def _filtered(obj, paths):
    """What hostd returns for one object when only ``paths`` were requested."""
    return {
        "obj": obj["obj"],
        "props": {path: value for path, value in obj["props"].items() if path in paths},
        "missing": [entry for entry in obj["missing"] if entry["path"] in paths],
    }


class _FakeVsphere:
    """Duck-typed VsphereClient: canned, path-filtered answers; records every call."""

    transport_label = "vsphere"

    def __init__(self, host_props=None, host_missing=(), vm_objects=None, hints=None):
        self.calls = []
        self.host_props = dict(_host_props() if host_props is None else host_props)
        self.host_missing = list(host_missing)
        self.vm_objects = _vm_objects() if vm_objects is None else vm_objects
        self.vm_pages = 2
        self.vm_token = None
        self.hints = _hints() if hints is None else hints
        self.datastores = _page("vsphere_datastores.xml")["objects"]
        self.content = soap.parse_service_content(
            _loader.fixture_text("vsphere_service_content.xml")
        )
        self.tasks = _page("vsphere_recent_tasks.xml")
        self.events = _page("vsphere_latest_event.xml")
        self.license = _page("vsphere_license.xml")
        self.closed = False

    def call(self, operation, **kwargs):
        self.calls.append((operation, kwargs))
        if operation == "RetrieveServiceContent":
            return self.content
        if operation == "QueryNetworkHint":
            return list(self.hints)
        if operation != "RetrievePropertiesEx":
            raise AssertionError("collector used unexpected operation %r" % (operation,))
        mo_type, moids, paths = kwargs["type"], kwargs["moids"], kwargs["paths"]
        if mo_type == "HostSystem":
            self._require(moids == ["ha-host"], "host moid %r" % (moids,))
            obj = {
                "obj": {"type": "HostSystem", "moid": "ha-host"},
                "props": {path: self.host_props[path] for path in paths if path in self.host_props},
                "missing": [entry for entry in self.host_missing if entry["path"] in paths],
            }
            return {"objects": [obj], "token": None, "pages": 1}
        if mo_type == "VirtualMachine":
            objects = [
                _filtered(obj, paths) for obj in self.vm_objects if obj["obj"]["moid"] in moids
            ]
            return {"objects": objects, "token": self.vm_token, "pages": self.vm_pages}
        if mo_type == "Datastore":
            objects = [
                _filtered(obj, paths) for obj in self.datastores if obj["obj"]["moid"] in moids
            ]
            return {"objects": objects, "token": None, "pages": 1}
        if mo_type == "TaskManager":
            self._require(kwargs.get("traverse") is not None, "task traversal")
            return dict(self.tasks, pages=1)
        if mo_type == "EventManager":
            return dict(self.events, pages=1)
        if mo_type == "LicenseManager":
            return dict(self.license, pages=1)
        raise AssertionError("collector requested unexpected type %r" % (mo_type,))

    @staticmethod
    def _require(condition, what):
        if not condition:
            raise AssertionError("unexpected request: %s" % (what,))

    def close(self):
        self.closed = True


def _ctx(api=None):
    return context.CollectorContext("esx-test", "vmware", api=api or _FakeVsphere())


def _host_calls(api, path):
    """RetrievePropertiesEx HostSystem calls whose pathSet includes ``path``."""
    return [
        kwargs
        for operation, kwargs in api.calls
        if operation == "RetrievePropertiesEx"
        and kwargs["type"] == "HostSystem"
        and path in kwargs["paths"]
    ]


# --- registrations ---------------------------------------------------------------


class TestRegistrations(unittest.TestCase):
    EXPECTED_IDS = {
        "vmware_host_identity",
        "vmware_hardware_inventory",
        "vmware_pnics",
        "vmware_pnic_neighbors",
        "vmware_vswitches",
        "vmware_portgroups",
        "vmware_vmknics",
        "vmware_host_routes",
        "vmware_time_syslog",
        "vmware_host_services",
        "vmware_advanced_options",
        "vmware_firewall_rulesets",
        "vmware_datastores",
        "vmware_storage_devices",
        "vmware_health_sensors",
        "vmware_autostart",
        "vmware_vlan_hints",
        "vmware_host_license",
        "vmware_vm_disks",
        "vmware_recent_tasks",
        "vmware_vms",
        "vmware_vm_nics",
        "vmware_vm_tuning",
    }

    def test_all_registered_once(self):
        registered = {
            check_id for check_id, check in registry.CHECKS.items() if check.platform == "vmware"
        }
        self.assertEqual(registered, self.EXPECTED_IDS)

    def test_checks_for_filters_by_platform(self):
        ids = {check.id for check in registry.checks_for("vmware")}
        self.assertEqual(ids, self.EXPECTED_IDS)

    def test_every_check_has_collector_compare_and_valid_mode(self):
        diffcore = _loader.diffcore
        for check in registry.checks_for("vmware"):
            self.assertTrue(callable(check.collector), check.id)
            self.assertIn("mode", check.compare, check.id)
            self.assertIn(check.compare["mode"], diffcore.MODES, check.id)

    def test_every_check_has_semantics(self):
        # The self-description contract, per platform (the panos battery
        # asserts it across the whole registry as well).
        for check_id in self.EXPECTED_IDS:
            self.assertIn(check_id, registry.SEMANTICS, check_id)
            self.assertGreater(len(registry.SEMANTICS[check_id]), 40, check_id)

    def test_every_pathset_is_allowlisted(self):
        for group in (
            checks._IDENTITY_PATHS,
            checks._HARDWARE_PATHS,
            checks._NETWORK_PATHS,
            checks._TIME_PATHS,
            checks._SERVICE_PATHS,
            checks._OPTION_PATHS,
            checks._FIREWALL_PATHS,
            checks._DATASTORE_HOST_PATHS,
            checks._STORAGE_PATHS,
            checks._HEALTH_PATHS,
            checks._AUTOSTART_PATHS,
            checks._HOST_VM_PATHS,
        ):
            for path in group:
                self.assertIn(path, soap.PROPERTY_PATHS["HostSystem"], path)
        for path in checks._VM_PATHS:
            self.assertIn(path, soap.PROPERTY_PATHS["VirtualMachine"], path)
        for path in checks._DATASTORE_PATHS:
            self.assertIn(path, soap.PROPERTY_PATHS["Datastore"], path)

    def test_every_request_the_collectors_build_passes_the_fence(self):
        # The fake-ctx contract test: every (operation, kwargs) the catalog
        # forms must produce an envelope, i.e. every path/moid/traversal is
        # inside vsphere_soap's fence. Transport-only kwargs are stripped the
        # way VsphereClient.call() strips them.
        api = _FakeVsphere()
        ctx = _ctx(api)
        for check in registry.checks_for("vmware"):
            check.collector(ctx)
        self.assertTrue(api.calls)
        for operation, kwargs in api.calls:
            params = {
                key: value
                for key, value in kwargs.items()
                if key not in ("timeout", "mask_short", "drain")
            }
            if operation in ("RetrievePropertiesEx", "ContinueRetrievePropertiesEx"):
                params["property_collector"] = "ha-property-collector"
            soap.build_envelope(operation, soap.NAMESPACE, **params)


# --- host identity ---------------------------------------------------------------


class TestHostIdentity(unittest.TestCase):
    def test_flat_scalars_and_context(self):
        normalized, ctx = checks._normalize_host_identity(_host_props())
        self.assertEqual(
            normalized,
            {
                "vendor": "Lenovo",
                "model": "ThinkSystem SE350 -[7Z46CTO1WW]-",
                "serial": "J900ABCD",
                "serial_source": "serialNumber",
                "uuid": "4c4c4544-0000-4d10-8058-b4c04f303032",
                "bios_version": "-[HYE134C-4.20]-",
                "bios_release_date": "2025-03-11T00:00:00Z",
                "esxi_version": "8.0.3",
                "esxi_build": "24022510",
                "api_type": "HostAgent",
                "api_version": "8.0.3.0",
                "hostname": "se350-1.example.net",
                "cpu_model": "Intel(R) Xeon(R) D-2183IT CPU @ 2.20GHz",
                "cpu_pkgs": 1,
                "cpu_cores": 16,
                "cpu_threads": 32,
                "hyperthreading_active": True,
                "memory_bytes": 137438953472,
                "maintenance_mode": False,
                "power_state": "poweredOn",
                "standby_mode": "none",
                "power_policy": "static",
                "bmc_ip": "192.0.2.60",
                "bmc_mac": "7c:d3:0a:00:00:60",
            },
        )
        self.assertEqual(ctx["boot_time"], "2026-09-01T04:12:09.417Z")
        self.assertFalse(ctx["reboot_required"])
        self.assertEqual(ctx["num_nics"], 4)
        self.assertEqual(ctx["power_policy_name"], "PowerPolicy.static.name")
        self.assertEqual(ctx["power_policies_available"], ["custom", "dynamic", "low", "static"])
        # PCR digests: signed-byte leaves rendered as hex, ordered by index.
        self.assertEqual(
            ctx["tpm_pcr_values"],
            [
                {
                    "index": 0,
                    "digest_method": "SHA256",
                    "digest": "01ff1234",
                    "object_name": "PCR 0",
                },
                {
                    "index": 7,
                    "digest_method": "SHA256",
                    "digest": "a510007f",
                    "object_name": "PCR 7",
                },
            ],
        )

    def test_host_state_absent_reads_none_not_false(self):
        # No TPM, no BMC, no power policy exposed: every new scalar is null
        # and the PCR list is empty — never a fabricated "not in maintenance".
        props = _host_props()
        for path in checks._IDENTITY_TOLERATED:
            props.pop(path, None)
        normalized, ctx = checks._normalize_host_identity(props)
        for field in ("maintenance_mode", "power_state", "standby_mode", "power_policy", "bmc_ip"):
            self.assertIsNone(normalized[field], field)
        self.assertEqual(ctx["tpm_pcr_values"], [])
        self.assertEqual(ctx["power_policies_available"], [])

    def test_serial_falls_back_to_service_tag_and_records_source(self):
        props = _host_props()
        system = dict(props["hardware.systemInfo"])
        del system["serialNumber"]
        props["hardware.systemInfo"] = system
        normalized, _ = checks._normalize_host_identity(props)
        self.assertEqual(normalized["serial"], "J900ABCD")
        self.assertEqual(normalized["serial_source"], "ServiceTag")

    def test_hyperthreading_not_exposed_is_none(self):
        props = _host_props()
        del props["config.hyperThread"]
        normalized, ctx = checks._normalize_host_identity(props)
        self.assertIsNone(normalized["hyperthreading_active"])
        self.assertIsNone(ctx["hyperthreading_available"])

    def test_collector_keys_raw_by_request_and_fails_on_missing_set(self):
        api = _FakeVsphere()
        result = checks._collect_host_identity(_ctx(api))
        key = "RetrievePropertiesEx HostSystem[ha-host] %s" % (",".join(checks._IDENTITY_PATHS),)
        self.assertEqual(list(result["raw"]), [key])
        self.assertIn("hardware.systemInfo", result["raw"][key]["ha-host"])
        self.assertEqual(result["context"]["unreadable"], [])
        # The BMC login never enters a snapshot; the address does.
        ipmi_raw = result["raw"][key]["ha-host"]["config.ipmi"]
        self.assertEqual(ipmi_raw["bmcIpAddress"], "192.0.2.60")
        self.assertNotIn("login", ipmi_raw)
        self.assertNotIn("USERID", str(result))
        broken = _FakeVsphere(
            host_missing=[
                {"path": "hardware.systemInfo", "fault": "NoPermission", "message": "denied"}
            ]
        )
        with self.assertRaises(checks.CollectError):
            checks._collect_host_identity(_ctx(broken))

    def test_withheld_host_state_property_is_a_recorded_gap_not_a_failure(self):
        props = _host_props()
        del props["runtime.tpmPcrValues"]
        api = _FakeVsphere(
            host_props=props,
            host_missing=[
                {"path": "runtime.tpmPcrValues", "fault": "NoPermission", "message": "denied"}
            ],
        )
        result = checks._collect_host_identity(_ctx(api))
        self.assertEqual(result["context"]["unreadable"], ["runtime.tpmPcrValues"])
        self.assertEqual(result["context"]["tpm_pcr_values"], [])
        self.assertEqual(result["normalized"]["serial"], "J900ABCD")
        key = next(iter(result["raw"]))
        self.assertEqual(
            result["raw"][key]["ha-host"]["missing"][0]["path"], "runtime.tpmPcrValues"
        )


# --- hardware inventory ----------------------------------------------------------


class TestHardwareInventory(unittest.TestCase):
    def setUp(self):
        self.normalized = checks._normalize_hardware_inventory(_host_props())

    def test_pci_ids_are_unsigned_hex_and_sriov_dispatches_on_type(self):
        x722 = self.normalized["pci|0000:18:00.0"]
        self.assertEqual(x722["vendor_id"], "0x8086")
        self.assertEqual(x722["device_id"], "0x37d0")
        self.assertEqual(x722["class_id"], "0x0200")
        self.assertEqual(x722["parent_bridge"], "0000:17:00.0")
        self.assertFalse(x722["is_vf"])
        self.assertTrue(x722["sriov_capable"])
        self.assertTrue(x722["sriov_active"])
        self.assertEqual(x722["num_vf"], 2)
        self.assertFalse(x722["passthru_active"])
        nvme = self.normalized["pci|0000:5e:00.0"]
        self.assertEqual(nvme["vendor_id"], "0x144d")
        self.assertEqual(nvme["device_id"], "0xa808")
        self.assertTrue(nvme["passthru_capable"])
        # Plain HostPciPassthruInfo: the SR-IOV fields are null, not False.
        self.assertIsNone(nvme["sriov_capable"])
        self.assertIsNone(nvme["num_vf"])

    def test_virtual_functions_are_their_own_rows(self):
        vf = self.normalized["pci|0000:18:02.0"]
        self.assertTrue(vf["is_vf"])
        self.assertTrue(vf["passthru_active"])
        self.assertEqual(vf["device_id"], "0x37cd")

    def test_cpu_numa_memory_rows(self):
        self.assertEqual(
            self.normalized["cpu|0"],
            {"vendor": "intel", "description": "Intel(R) Xeon(R) D-2183IT CPU @ 2.20GHz"},
        )
        self.assertEqual(self.normalized["numa|nodes"], {"value": 1})
        self.assertEqual(self.normalized["memory|bytes"], {"value": 137438953472})

    def test_device_without_passthru_entry_reads_none(self):
        row = self.normalized["pci|0000:00:00.0"]
        self.assertIsNone(row["passthru_capable"])
        self.assertIsNone(row["parent_bridge"])

    def test_collector_prunes_cpu_features_from_raw(self):
        result = checks._collect_hardware_inventory(_ctx())
        raw = next(iter(result["raw"].values()))["ha-host"]
        self.assertNotIn("cpuFeature", str(raw["hardware.cpuPkg"]))
        self.assertEqual(result["context"]["pci_devices"], 7)


# --- pnics -----------------------------------------------------------------------


class TestPnics(unittest.TestCase):
    def test_link_speed_driver_and_configured_fields(self):
        normalized = checks._normalize_pnics(_network())
        self.assertEqual(
            normalized["pnic|vmnic0"],
            {
                "mac": "00:11:22:33:44:55",
                "pci": "0000:18:00.0",
                "driver": "i40en",
                "driver_version": "2.6.0.34",
                "firmware_version": "6.01 0x800039ad 1.3131.0",
                "link_up": True,
                "speed_mb": 10000,
                "duplex": True,
                "autoneg_supported": True,
                "configured_speed_mb": 10000,
                "configured_duplex": True,
                "ens_enabled": False,
            },
        )
        down = normalized["pnic|vmnic1"]
        self.assertFalse(down["link_up"])
        self.assertIsNone(down["speed_mb"])
        self.assertIsNone(down["configured_speed_mb"])  # auto-negotiate
        self.assertTrue(normalized["pnic|vmnic2"]["ens_enabled"])

    def test_collector_context_and_candidate_vnic_pruned_from_raw(self):
        result = checks._collect_pnics(_ctx())
        self.assertEqual(result["context"], {"pnics_total": 4, "links_up": 3})
        raw = next(iter(result["raw"].values()))["ha-host"]
        self.assertNotIn("candidateVnic", str(raw["config.virtualNicManagerInfo"]))
        self.assertIn("selectedVnic", str(raw["config.virtualNicManagerInfo"]))
        # config.network is stored per sub-array, attached ports pruned.
        network_raw = raw["config.network"]
        self.assertEqual(len(network_raw["pnic"]), 4)
        self.assertEqual(len(network_raw["portgroup"]), 6)
        self.assertNotIn("port", network_raw["portgroup"][0])
        self.assertIn("spec", network_raw["portgroup"][0])
        self.assertNotIn("truncated", network_raw)

    def test_network_raw_caps_each_sub_array_on_its_own(self):
        # A host with many port groups: only the oversized sub-array carries a
        # marker (cut between items, still parseable); the other six checks'
        # raw evidence stays whole.
        props = _host_props()
        network = dict(props["config.network"])
        template = network["portgroup"][0]
        network["portgroup"] = [
            dict(template, spec=dict(template["spec"], name="pg-%03d" % (index,)))
            for index in range(60)
        ]
        props["config.network"] = network
        result = checks._collect_vswitches(_ctx(_FakeVsphere(host_props=props)))
        network_raw = next(iter(result["raw"].values()))["ha-host"]["config.network"]
        self.assertTrue(network_raw["portgroup"]["truncated"])
        self.assertEqual(network_raw["portgroup"]["items_total"], 60)
        self.assertGreater(network_raw["portgroup"]["items_kept"], 0)
        self.assertLess(network_raw["portgroup"]["items_kept"], 60)
        self.assertEqual(network_raw["portgroup"]["items"][0]["spec"]["name"], "pg-000")
        for sub in ("pnic", "vswitch", "vnic", "netStackInstance", "dnsConfig"):
            self.assertIn(sub, network_raw)
            self.assertNotIn("truncated", network_raw[sub])
        self.assertEqual(len(network_raw["pnic"]), 4)


# --- pnic neighbors --------------------------------------------------------------


class TestPnicNeighbors(unittest.TestCase):
    def test_discovery_per_vswitch(self):
        discovery = checks._discovery_by_vswitch(_network())
        self.assertEqual(
            discovery["vSwitch0"],
            {"bridge_type": "HostVirtualSwitchBondBridge", "protocol": "cdp", "operation": "both"},
        )
        self.assertEqual(discovery["vSwitch1"]["operation"], "listen")
        self.assertEqual(
            discovery["vSwitch2"], {"bridge_type": None, "protocol": None, "operation": None}
        )
        self.assertTrue(checks._neighbors_expected(discovery))

    def test_unset_bridge_config_means_esxi_default_listen(self):
        network = _network()
        bridge = dict(network["vswitch"][0]["spec"]["bridge"])
        del bridge["linkDiscoveryProtocolConfig"]
        network["vswitch"][0]["spec"]["bridge"] = bridge
        self.assertEqual(checks._discovery_by_vswitch(network)["vSwitch0"]["operation"], "listen")

    def test_cdp_rows_exclude_timers(self):
        normalized = checks._normalize_pnic_neighbors(_hints())
        self.assertEqual(sorted(normalized), ["cdp|vmnic0", "cdp|vmnic2"])
        self.assertEqual(
            normalized["cdp|vmnic0"],
            {
                "device_id": "core-a.example.net",
                "port_id": "TwentyFiveGigE1/0/1",
                "platform": "cisco C9500-24Y4C",
                "native_vlan": 100,
                "mtu": 9198,
                "mgmt_addr": "192.0.2.2",
                "address": "192.0.2.2",
                "full_duplex": True,
            },
        )
        for banned in ("ttl", "timeout", "samples", "cdpVersion", "softwareVersion"):
            self.assertNotIn(banned, str(normalized))

    def test_lldp_rows_when_present(self):
        hints = [
            {
                "device": "vmnic5",
                "lldpInfo": {
                    "chassisId": "aa:bb:cc:dd:ee:ff",
                    "portId": "Eth1/1",
                    "timeToLive": "120",
                    "parameter": [{"key": "System Name", "value": "leaf-1"}],
                },
            }
        ]
        normalized = checks._normalize_pnic_neighbors(hints)
        self.assertEqual(
            normalized["lldp|vmnic5"],
            {
                "chassis_id": "aa:bb:cc:dd:ee:ff",
                "port_id": "Eth1/1",
                "parameters": {"System Name": "leaf-1"},
            },
        )

    def test_collector_records_hint_raw_and_context(self):
        api = _FakeVsphere()
        result = checks._collect_pnic_neighbors(_ctx(api))
        self.assertIn("QueryNetworkHint networkSystem", result["raw"])
        self.assertEqual(result["context"]["cdp_neighbors"], 2)
        self.assertEqual(result["context"]["pnics_with_hints"], 4)
        hint_calls = [kw for op, kw in api.calls if op == "QueryNetworkHint"]
        self.assertEqual(hint_calls, [{"network_system": "networkSystem"}])  # <device> omitted

    def test_skips_only_when_no_vswitch_listens(self):
        props = _host_props()
        network = props["config.network"]
        for vswitch in network["vswitch"]:
            bridge = vswitch["spec"].get("bridge")
            if bridge:
                bridge["linkDiscoveryProtocolConfig"] = {
                    "protocol": "cdp",
                    "operation": "advertise",
                }
        with self.assertRaises(checks.SkipCheck):
            checks._collect_pnic_neighbors(_ctx(_FakeVsphere(host_props=props)))

    def test_empty_table_with_discovery_listening_is_a_finding(self):
        silent = [{"device": "vmnic0"}, {"device": "vmnic1"}]
        result = checks._collect_pnic_neighbors(_ctx(_FakeVsphere(hints=silent)))
        self.assertEqual(result["normalized"], {})
        self.assertEqual(result["context"]["cdp_neighbors"], 0)


# --- vswitches -------------------------------------------------------------------


class TestVswitches(unittest.TestCase):
    def setUp(self):
        self.normalized, self.runtime = checks._normalize_vswitches(_network())

    def test_uplinks_resolved_from_keys_and_failover_order_preserved(self):
        row = self.normalized["vswitch|vSwitch0"]
        self.assertEqual(row["uplinks"], ["vmnic0", "vmnic1"])
        self.assertEqual(row["portgroups"], ["Management Network", "VM Network"])
        self.assertEqual(row["active_uplinks"], ["vmnic1", "vmnic0"])  # never sorted
        self.assertEqual(row["standby_uplinks"], [])
        self.assertEqual(row["num_ports_configured"], 128)
        self.assertEqual(row["mtu"], 1500)
        self.assertEqual(row["teaming_policy"], "loadbalance_srcid")
        self.assertTrue(row["notify_switches"])
        self.assertFalse(row["rolling_order"])
        self.assertFalse(row["beacon_probing"])
        self.assertEqual(row["discovery_operation"], "both")
        self.assertFalse(row["promiscuous"])
        self.assertTrue(row["mac_changes"])

    def test_explicit_failover_and_beacon(self):
        row = self.normalized["vswitch|vSwitch1"]
        self.assertEqual(row["teaming_policy"], "failover_explicit")
        self.assertEqual(row["active_uplinks"], ["vmnic2"])
        self.assertEqual(row["standby_uplinks"], ["vmnic3"])
        self.assertTrue(row["beacon_probing"])
        self.assertEqual(row["mtu"], 9000)
        self.assertTrue(row["promiscuous"])

    def test_uplinkless_vswitch_and_absent_proxy_switch(self):
        row = self.normalized["vswitch|vSwitch2"]
        self.assertEqual(row["uplinks"], [])
        self.assertIsNone(row["bridge_type"])
        self.assertIsNone(row["discovery_protocol"])
        self.assertIsNone(row["discovery_operation"])
        self.assertEqual(self.normalized["proxyswitch|count"], {"value": 0})
        self.assertEqual(self.runtime["vSwitch0"], {"num_ports": 2560, "num_ports_available": 2547})

    def test_collector_context(self):
        result = checks._collect_vswitches(_ctx())
        self.assertEqual(result["context"]["vswitches_total"], 3)


# --- portgroups ------------------------------------------------------------------


class TestPortgroups(unittest.TestCase):
    def setUp(self):
        self.normalized = checks._normalize_portgroups(_network())

    def test_effective_policy_from_computed_and_per_leaf_override_flags(self):
        mgmt = self.normalized["portgroup|Management Network"]
        self.assertEqual(mgmt["vswitch"], "vSwitch0")
        self.assertEqual(mgmt["vlan_id"], 100)
        self.assertFalse(mgmt["promiscuous"])
        self.assertTrue(mgmt["forged_transmits"])
        # Empty <security/> = inherits; nicOrder set = teaming overridden.
        self.assertFalse(mgmt["security_overridden"])
        self.assertTrue(mgmt["teaming_overridden"])
        self.assertEqual(mgmt["active_uplinks"], ["vmnic0"])
        self.assertEqual(mgmt["standby_uplinks"], ["vmnic1"])

    def test_inheriting_and_overriding_groups(self):
        plain = self.normalized["portgroup|VM Network"]
        self.assertFalse(plain["security_overridden"])
        self.assertFalse(plain["teaming_overridden"])
        self.assertEqual(plain["active_uplinks"], ["vmnic1", "vmnic0"])
        trunk = self.normalized["portgroup|Trunk-VGT"]
        self.assertEqual(trunk["vlan_id"], 4095)
        self.assertTrue(trunk["security_overridden"])
        self.assertFalse(trunk["teaming_overridden"])
        self.assertTrue(trunk["promiscuous"])
        sync = self.normalized["portgroup|HA-Sync"]
        self.assertTrue(sync["teaming_overridden"])  # notifySwitches set on the group
        self.assertFalse(sync["security_overridden"])

    def test_port_counts_are_raw_only(self):
        result = checks._collect_portgroups(_ctx())
        self.assertEqual(result["raw"]["attached_ports"]["Trunk-VGT"], 2)
        self.assertNotIn("ports", str(result["normalized"]["portgroup|Trunk-VGT"]))
        self.assertEqual(result["context"]["portgroups_total"], 6)


# --- vmknics ---------------------------------------------------------------------


class TestVmknics(unittest.TestCase):
    def setUp(self):
        props = _host_props()
        self.normalized = checks._normalize_vmknics(
            props["config.network"], props["config.virtualNicManagerInfo"]
        )

    def test_rows_join_services_by_key_and_keep_manual_ipv6_only(self):
        self.assertEqual(
            self.normalized["vmk|vmk0"],
            {
                "portgroup": "Management Network",
                "ip": "192.0.2.11",
                "netmask": "255.255.255.0",
                "dhcp": False,
                "ipv6_static": ["2001:db8:1::11/64"],
                "mtu": 1500,
                "mac": "00:11:22:33:44:55",
                "netstack": "defaultTcpipStack",
                "services": ["management"],
                "pinned_pnic": None,
            },
        )
        vmk1 = self.normalized["vmk|vmk1"]
        self.assertTrue(vmk1["dhcp"])
        self.assertEqual(vmk1["services"], ["vSphereBackupNFC", "vmotion"])
        self.assertEqual(vmk1["netstack"], "vmotion")
        self.assertEqual(vmk1["ipv6_static"], [])

    def test_dvs_or_opaque_vmk_has_no_portgroup(self):
        network = _network()
        vnic = dict(network["vnic"][1])
        del vnic["portgroup"]
        spec = dict(vnic["spec"])
        del spec["portgroup"]
        vnic["spec"] = spec
        network["vnic"][1] = vnic
        normalized = checks._normalize_vmknics(network, None)
        self.assertIsNone(normalized["vmk|vmk1"]["portgroup"])
        self.assertEqual(normalized["vmk|vmk1"]["services"], [])

    def test_collector_context(self):
        result = checks._collect_vmknics(_ctx())
        self.assertEqual(result["context"], {"vmknics_total": 2, "ipv6_enabled": True})


# --- host routes -----------------------------------------------------------------


class TestHostRoutes(unittest.TestCase):
    def setUp(self):
        self.normalized, self.context = checks._normalize_host_routes(_network())

    def test_default_stack_routes_merge_config_and_state(self):
        default = self.normalized["route|defaultTcpipStack|0.0.0.0/0"]
        self.assertEqual(
            default,
            {
                "gateway": "192.0.2.1",
                "device": "vmk0",
                "family": "ipv4",
                "in_config": True,
                "in_state": True,
            },
        )
        # Configured but not in the live table.
        static = self.normalized["route|defaultTcpipStack|203.0.113.0/24"]
        self.assertTrue(static["in_config"])
        self.assertFalse(static["in_state"])
        # Live only (link-local v6).
        local = self.normalized["route|defaultTcpipStack|fe80::/64"]
        self.assertEqual(local["family"], "ipv6")
        self.assertFalse(local["in_config"])
        self.assertTrue(local["in_state"])
        # Other stacks are config-only: in_state unobservable.
        vmotion = self.normalized["route|vmotion|0.0.0.0/0"]
        self.assertEqual(vmotion["gateway"], "198.51.100.1")
        self.assertIsNone(vmotion["in_state"])

    def test_gateways_and_dns(self):
        self.assertEqual(
            self.normalized["gateway|defaultTcpipStack"],
            {
                "ipv4": "192.0.2.1",
                "ipv4_device": "vmk0",
                "ipv6": "2001:db8:1::1",
                "ipv6_device": "vmk0",
            },
        )
        self.assertEqual(
            self.normalized["gateway|vSphereProvisioning"],
            {"ipv4": None, "ipv4_device": None, "ipv6": None, "ipv6_device": None},
        )
        self.assertEqual(self.normalized["dns|hostname"], {"value": "se350-1"})
        self.assertEqual(self.normalized["dns|servers"], {"value": ["192.0.2.53", "192.0.2.54"]})
        self.assertEqual(self.normalized["dns|search"], {"value": ["example.net"]})
        self.assertEqual(self.normalized["dns|dhcp"], {"value": False})

    def test_context(self):
        self.assertEqual(
            self.context["stacks"], ["defaultTcpipStack", "vmotion", "vSphereProvisioning"]
        )
        self.assertTrue(self.context["route_table_info_present"])
        self.assertEqual(self.context["ipv6_routes"], 3)

    def test_route_table_info_absent_is_recorded_not_fatal(self):
        network = _network()
        del network["routeTableInfo"]
        normalized, ctx = checks._normalize_host_routes(network)
        self.assertFalse(ctx["route_table_info_present"])
        self.assertFalse(normalized["route|defaultTcpipStack|0.0.0.0/0"]["in_state"])
        self.assertNotIn("route|defaultTcpipStack|fe80::/64", normalized)

    def test_legacy_shape_without_netstacks_uses_host_route_config(self):
        network = _network()
        del network["netStackInstance"]
        normalized, ctx = checks._normalize_host_routes(network)
        self.assertEqual(ctx["stacks"], [])
        self.assertEqual(normalized["gateway|defaultTcpipStack"]["ipv4"], "192.0.2.1")
        self.assertTrue(normalized["route|defaultTcpipStack|0.0.0.0/0"]["in_state"])


# --- time / syslog ---------------------------------------------------------------


class TestTimeSyslog(unittest.TestCase):
    def test_flat_scalars(self):
        props = _host_props()
        normalized, ctx = checks._normalize_time_syslog(
            props["config.dateTimeInfo"],
            checks._services_dict(props["config.service"]),
            checks._options_dict(props["config.option"]),
        )
        self.assertEqual(
            normalized,
            {
                "ntp_servers": ["192.0.2.123", "192.0.2.124"],
                "time_services_enabled": True,
                "clock_protocol": "ntp",
                "ntp_service_sync": True,
                "fallback_disabled": False,
                "ntp_running": True,
                "ntp_policy": "on",
                "ptp_running": False,
                "ptp_policy": "off",
                "syslog_loghost": ["ssl://logs.example.net:1514", "udp://192.0.2.200:514"],
                "syslog_logdir": "[] /scratch/log",
                "syslog_logdir_unique": False,
                "syslog_check_ssl_certs": True,
                "syslog_log_level": "info",
            },
        )
        self.assertEqual(ctx["timezone"], "UTC")
        self.assertEqual(ctx["remote_ntp_server"], "192.0.2.123")
        self.assertEqual(ctx["ntp_run_time"], 1234567)

    def test_pre_703_shape_reads_none_not_false(self):
        date_time = {"ntpConfig": {"server": "192.0.2.5"}}
        normalized, _ = checks._normalize_time_syslog(date_time, {}, {})
        self.assertEqual(normalized["ntp_servers"], ["192.0.2.5"])
        self.assertIsNone(normalized["ntp_service_sync"])
        self.assertIsNone(normalized["time_services_enabled"])
        self.assertIsNone(normalized["ntp_running"])
        self.assertEqual(normalized["syslog_loghost"], [])
        self.assertIsNone(normalized["syslog_logdir"])

    def test_collector_stores_three_requests_with_option_curation(self):
        result = checks._collect_time_syslog(_ctx())
        self.assertEqual(len(result["raw"]), 3)
        option_raw = result["raw"]["RetrievePropertiesEx HostSystem[ha-host] config.option"]
        curated = option_raw["ha-host"]["config.option"]["curated"]
        self.assertIn("Syslog.global.logHost", curated)
        self.assertIn(
            "apiToken=***scrubbed***",
            option_raw["ha-host"]["config.option"]["remainder"]["UserVars"],
        )


# --- host services ---------------------------------------------------------------


class TestHostServices(unittest.TestCase):
    def test_rows_and_scalars(self):
        props = _host_props()
        normalized = checks._normalize_host_services(
            props["config.service"],
            props["config.lockdownMode"],
            props.get("summary.managementServerIp"),
            checks._options_dict(props["config.option"]),
        )
        self.assertEqual(
            normalized["service|TSM-SSH"],
            {"running": True, "policy": "off", "required": False, "label": "SSH"},
        )
        self.assertEqual(normalized["service|vpxa"]["running"], False)
        self.assertEqual(normalized["lockdown|mode"], {"value": "lockdownDisabled"})
        self.assertEqual(normalized["mob|enabled"], {"value": False})
        # Standalone host: managementServerIp is unset -> None, not "".
        self.assertEqual(normalized["vcenter|management_server"], {"value": None})
        self.assertEqual(sum(1 for key in normalized if key.startswith("service|")), 8)

    def test_collector_context_and_source_package_pruned(self):
        result = checks._collect_host_services(_ctx())
        self.assertEqual(result["context"]["services_running"], ["TSM-SSH", "ntpd", "vmsyslogd"])
        service_raw = result["raw"][
            "RetrievePropertiesEx HostSystem[ha-host] %s" % (",".join(checks._SERVICE_PATHS),)
        ]
        self.assertNotIn("sourcePackage", str(service_raw))


# --- advanced options ------------------------------------------------------------


class TestAdvancedOptions(unittest.TestCase):
    def test_curated_rows_keep_native_types(self):
        options = checks._options_dict(_host_props()["config.option"])
        normalized, absent = checks._normalize_advanced_options(options)
        self.assertEqual(absent, [])
        self.assertEqual(len(normalized), len(checks._CURATED_OPTIONS))
        self.assertEqual(normalized["opt|UserVars.ESXiShellTimeOut"], {"value": 0})
        self.assertEqual(normalized["opt|Net.TcpipHeapMax"], {"value": 1024})
        self.assertEqual(
            normalized["opt|Config.HostAgent.plugins.solo.enableMob"], {"value": False}
        )
        self.assertEqual(normalized["opt|Power.CpuPolicy"], {"value": "High Performance"})
        self.assertNotIn("opt|UserVars.HostClientCEIPOptIn", normalized)

    def test_absent_curated_key_is_reported_not_fabricated(self):
        options = checks._options_dict(_host_props()["config.option"])
        del options["Misc.BlueScreenTimeout"]
        normalized, absent = checks._normalize_advanced_options(options)
        self.assertEqual(absent, ["Misc.BlueScreenTimeout"])
        self.assertNotIn("opt|Misc.BlueScreenTimeout", normalized)

    def test_collector_context_and_raw_scrub(self):
        result = checks._collect_advanced_options(_ctx())
        self.assertEqual(result["context"]["options_total"], 24)
        self.assertEqual(result["context"]["curated_absent"], [])
        raw = next(iter(result["raw"].values()))["ha-host"]["config.option"]
        self.assertEqual(
            raw["curated"]["Security.PasswordQualityControl"].split()[0], "similar=deny"
        )
        self.assertIn(
            "UserVars.ExampleVendorAgent.apiToken=***scrubbed***", raw["remainder"]["UserVars"]
        )
        self.assertNotIn("not-a-real-token", str(raw["remainder"]))
        self.assertEqual(raw["remainder_count"], 24 - len(raw["curated"]))
        self.assertEqual(
            raw["remainder_count"],
            sum(len(block.split("\n")) for block in raw["remainder"].values()),
        )
        # Stored as the curator produced it — never re-cut as JSON text.
        self.assertNotIn("head", raw)
        self.assertNotIn("truncated", raw)

    def test_realistic_option_list_is_grouped_by_prefix_and_never_double_capped(self):
        # ~1 200 OptionValues (an 8.0U3 host): every prefix block is present
        # and parseable, a marker only where a block was cut, and the whole
        # entry is what the curator built (not a JSON text head).
        families = {"Net": 500, "Mem": 300, "Misc": 200, "UserVars": 150, "Syslog": 60}
        options = [{"key": "Power.CpuPolicy", "value": "Balanced"}]
        for prefix, count in families.items():
            options += [
                {"key": "%s.Option%04d" % (prefix, index), "value": "value-%d" % (index,) * 3}
                for index in range(count)
            ]
        props = _host_props()
        props["config.option"] = options
        result = checks._collect_advanced_options(_ctx(_FakeVsphere(host_props=props)))
        raw = next(iter(result["raw"].values()))["ha-host"]["config.option"]
        self.assertEqual(raw["curated"], {"Power.CpuPolicy": "Balanced"})
        self.assertEqual(raw["remainder_count"], sum(families.values()))
        self.assertEqual(sorted(raw["remainder"]), sorted(families))
        for prefix, block in raw["remainder"].items():
            lines = block.split("\n")
            self.assertTrue(lines[0].startswith("%s.Option0000=" % (prefix,)), prefix)
            if "...[truncated" in block:
                self.assertEqual(prefix, "Net")
            else:
                self.assertEqual(len(lines), families[prefix], prefix)
        self.assertIn("...[truncated", raw["remainder"]["Net"])
        self.assertNotIn("head", raw)
        self.assertEqual(result["normalized"]["opt|Power.CpuPolicy"], {"value": "Balanced"})


# --- firewall --------------------------------------------------------------------


class TestFirewall(unittest.TestCase):
    def test_rulesets_and_default_policy(self):
        normalized = checks._normalize_firewall(_host_props()["config.firewall"])
        self.assertEqual(
            normalized["ruleset|sshServer"],
            {
                "enabled": True,
                "all_ip": False,
                "allowed": ["192.0.2.10", "198.51.100.0/24"],
                "service": "TSM-SSH",
                "user_controllable": True,
                "ip_list_user_configurable": True,
            },
        )
        # No allowedHosts block at all = unrestricted; 8.0U2 flags absent -> None.
        syslog = normalized["ruleset|syslog"]
        self.assertTrue(syslog["all_ip"])
        self.assertEqual(syslog["allowed"], [])
        self.assertIsNone(syslog["user_controllable"])
        self.assertFalse(normalized["ruleset|snmp"]["enabled"])
        self.assertEqual(normalized["firewall|incoming_blocked"], {"value": True})
        self.assertEqual(normalized["firewall|outgoing_blocked"], {"value": True})

    def test_absent_is_not_present_and_missing_set_is_failed(self):
        props = _host_props()
        del props["config.firewall"]
        with self.assertRaises(checks.SkipCheck):
            checks._collect_firewall_rulesets(_ctx(_FakeVsphere(host_props=props)))
        broken = _FakeVsphere(
            host_missing=[{"path": "config.firewall", "fault": "InvalidProperty", "message": "x"}]
        )
        with self.assertRaises(checks.CollectError):
            checks._collect_firewall_rulesets(_ctx(broken))

    def test_collector_prunes_port_rules_from_raw(self):
        result = checks._collect_firewall_rulesets(_ctx())
        self.assertEqual(
            result["context"]["rulesets_enabled"],
            ["ntpClient", "sshServer", "syslog", "vSphereClient"],
        )
        self.assertNotIn("portType", str(result["raw"]))


# --- datastores ------------------------------------------------------------------


class TestDatastores(unittest.TestCase):
    def test_rows_join_mount_info_and_dispatch_on_info_type(self):
        props = _host_props()
        objects = _page("vsphere_datastores.xml")["objects"]
        normalized = checks._normalize_datastores(
            objects, props["config.fileSystemVolume.mountInfo"]
        )
        self.assertEqual(
            normalized["datastore|datastore1"],
            {
                "type": "VMFS",
                "uuid": "5f1e0000-aaaa-bbbb-cccc-000000000001",
                "remote": None,
                "local": True,
                "capacity_bytes": 479600000000,
                "free_bytes": 301000000000,
                "accessible": True,
                "mounted": True,
            },
        )
        nfs = normalized["datastore|nfs-backup"]
        self.assertEqual(nfs["type"], "NFS")
        self.assertIsNone(nfs["uuid"])
        self.assertEqual(nfs["remote"], "203.0.113.50:/export/backup")
        self.assertIsNone(nfs["local"])
        self.assertTrue(nfs["mounted"])

    def test_inaccessible_datastore_has_no_capacity_numbers(self):
        objects = _page("vsphere_datastores.xml")["objects"]
        summary = dict(objects[0]["props"]["summary"])
        summary["accessible"] = "false"
        objects[0]["props"]["summary"] = summary
        normalized = checks._normalize_datastores(objects, None)
        row = normalized["datastore|datastore1"]
        self.assertFalse(row["accessible"])
        self.assertIsNone(row["free_bytes"])
        self.assertIsNone(row["mounted"])  # no mount list to join

    def test_collector_context_and_empty_list_is_empty_not_skip(self):
        result = checks._collect_datastores(_ctx())
        self.assertEqual(result["context"]["datastores_total"], 2)
        self.assertEqual(result["context"]["mounted_volumes_total"], 4)
        self.assertEqual(
            result["context"]["unjoined_volumes"],
            ["BOOTBANK1", "OSDATA-5f1e0000-eeee-ffff-0000-000000000009"],
        )
        self.assertEqual(len(result["raw"]), 2)
        props = _host_props()
        del props["datastore"]
        empty = checks._collect_datastores(_ctx(_FakeVsphere(host_props=props)))
        self.assertEqual(empty["normalized"], {})
        self.assertEqual(empty["context"]["datastores_total"], 0)

    def test_compare_declares_free_bytes_band(self):
        check = registry.CHECKS["vmware_datastores"]
        self.assertEqual(
            check.compare["fields"]["free_bytes"]["tolerance"], {"pct": 10, "abs": 10737418240}
        )


# --- storage devices -------------------------------------------------------------


class TestStorageDevices(unittest.TestCase):
    def test_hbas_and_disk_only_luns(self):
        props = _host_props()
        normalized, other = checks._normalize_storage_devices(
            props["config.storageDevice.hostBusAdapter"], props["config.storageDevice.scsiLun"]
        )
        self.assertEqual(
            normalized["hba|vmhba0"],
            {
                "type": "HostPcieHba",
                "driver": "nvme_pcie",
                "model": "NVMe SSD Controller PM1725b",
                "status": "unknown",
                "storage_protocol": "nvme",
                "pci": "0000:5e:00.0",
            },
        )
        nvme = normalized[
            "lun|t10.NVMe____SAMSUNG_MZ1LB480HAJQ2D00007______________ABCDEF1234567890"
        ]
        self.assertEqual(nvme["vendor"], "NVMe")
        self.assertEqual(nvme["model"], "SAMSUNG MZ1LB480HAJQ-00007")
        self.assertEqual(nvme["capacity_bytes"], 512 * 937703088)
        self.assertEqual(nvme["operational_state"], ["ok"])
        self.assertTrue(nvme["ssd"])
        self.assertTrue(nvme["local"])
        self.assertEqual(nvme["protocol"], "NVMe")
        self.assertIn("lun|mpx.vmhba1:C0:T0:L0", normalized)
        self.assertNotIn("lun|mpx.vmhba32:C0:T0:L0", normalized)  # the virtual-media cdrom
        self.assertEqual(other, {"cdrom": 1})

    def test_collector_context_raw_pruning_and_absent_property_is_failed(self):
        result = checks._collect_storage_devices(_ctx())
        self.assertEqual(result["context"]["disks_total"], 2)
        self.assertEqual(result["context"]["non_disk_luns"], {"cdrom": 1})
        self.assertNotIn("standardInquiry", str(result["raw"]))
        self.assertNotIn("durableName", str(result["raw"]))
        props = _host_props()
        del props["config.storageDevice.scsiLun"]
        with self.assertRaises(checks.CollectError):
            checks._collect_storage_devices(_ctx(_FakeVsphere(host_props=props)))


# --- health sensors --------------------------------------------------------------


class TestHealthSensors(unittest.TestCase):
    def setUp(self):
        self.normalized, self.readings, self.context = checks._normalize_health_sensors(
            _host_props()["runtime.healthSystemRuntime"]
        )

    def test_suffix_stripped_and_collisions_suffixed_by_id(self):
        self.assertEqual(
            self.normalized["sensor|Fan Redundancy"],
            {"health": "green", "type": "other", "state": "Fully Redundant"},
        )
        self.assertIsNone(self.normalized["sensor|Ambient Temp"]["state"])
        self.assertEqual(self.normalized["sensor|Power Supply 2"]["health"], "red")
        self.assertNotIn("sensor|Drive Slot 0", self.normalized)
        self.assertEqual(self.normalized["sensor|Drive Slot 0|0.0.32.1:9"]["health"], "green")
        self.assertEqual(self.normalized["sensor|Drive Slot 0|0.0.32.1:10"]["health"], "yellow")
        for key in self.normalized:
            self.assertNotIn(" --- ", key)

    def test_one_discrete_sensor_listed_per_asserted_state_keeps_every_row(self):
        # hostd lists each asserted state of one IPMI discrete sensor as its
        # own entry with the SAME id: each state is a row, none overwrites
        # another, and the count reconciles with the keyed rows.
        runtime = {
            "systemHealthInfo": {
                "numericSensorInfo": [
                    {
                        "name": "Drive Slot 0 --- Drive Present",
                        "id": "0.0.32.1:9",
                        "healthState": {"key": "green"},
                        "sensorType": "storage",
                    },
                    {
                        "name": "Drive Slot 0 --- Predictive Failure",
                        "id": "0.0.32.1:9",
                        "healthState": {"key": "yellow"},
                        "sensorType": "storage",
                    },
                    {
                        "name": "Drive Slot 1 --- Drive Present",
                        "id": "0.0.32.1:11",
                        "healthState": {"key": "green"},
                        "sensorType": "storage",
                    },
                ]
            }
        }
        normalized, _readings, context = checks._normalize_health_sensors(runtime)
        self.assertEqual(
            sorted(normalized),
            [
                "sensor|Drive Slot 0|0.0.32.1:9|Drive Present",
                "sensor|Drive Slot 0|0.0.32.1:9|Predictive Failure",
                "sensor|Drive Slot 1",
            ],
        )
        self.assertEqual(
            normalized["sensor|Drive Slot 0|0.0.32.1:9|Predictive Failure"]["health"], "yellow"
        )
        self.assertEqual(normalized["sensor|Drive Slot 1"]["state"], "Drive Present")
        self.assertEqual(context["sensors_total"], len(normalized))
        # Listing order does not move a state between keys.
        runtime["systemHealthInfo"]["numericSensorInfo"].reverse()
        self.assertEqual(checks._normalize_health_sensors(runtime)[0], normalized)

    def test_status_half_lowercased(self):
        self.assertEqual(self.normalized["status|memory|Memory"], {"health": "green"})
        self.assertEqual(
            self.normalized["status|storage|Disk mpx.vmhba1:C0:T0:L0"], {"health": "unknown"}
        )
        self.assertEqual(self.context, {"sensors_total": 10, "status_elements_total": 4})

    def test_readings_scaled_into_context_only(self):
        self.assertEqual(self.readings["Ambient Temp"], {"reading": 23.0, "units": "Degrees C"})
        self.assertEqual(self.readings["Fan 1 Tach"], {"reading": 5200, "units": "RPM"})
        self.assertEqual(self.readings["PS 1 Vout"]["reading"], 12.0)
        self.assertNotIn("Fan Redundancy", self.readings)
        self.assertNotIn("reading", str(self.normalized))

    def test_skip_rules(self):
        props = _host_props()
        del props["runtime.healthSystemRuntime"]
        with self.assertRaises(checks.SkipCheck):
            checks._collect_health_sensors(_ctx(_FakeVsphere(host_props=props)))
        props = _host_props()
        props["runtime.healthSystemRuntime"] = {"_type": "HealthSystemRuntime"}
        with self.assertRaises(checks.SkipCheck):
            checks._collect_health_sensors(_ctx(_FakeVsphere(host_props=props)))
        # One half empty is enough to record.
        props["runtime.healthSystemRuntime"] = {
            "hardwareStatusInfo": {"cpuStatusInfo": {"name": "CPU 1", "status": {"key": "Green"}}}
        }
        result = checks._collect_health_sensors(_ctx(_FakeVsphere(host_props=props)))
        self.assertEqual(result["normalized"], {"status|cpu|CPU 1": {"health": "green"}})


# --- per-VM set ------------------------------------------------------------------


class TestVmSet(unittest.TestCase):
    def test_records_unique_names_and_tolerated_missing_set(self):
        records = checks._vm_records({"objects": _vm_objects()})
        self.assertEqual([record["name"] for record in records], ["fw-a", "orphan-vm", "fw-b"])
        self.assertEqual(records[1]["missing"][0]["path"], "config.uuid")
        duplicate = _vm_objects()
        duplicate[2]["props"]["name"] = "fw-a"
        names = [record["name"] for record in checks._vm_records({"objects": duplicate})]
        self.assertEqual(names, ["fw-a|1", "orphan-vm", "fw-a|2"])

    def test_fetch_uses_one_big_timeout_request_and_records_pages(self):
        api = _FakeVsphere()
        records, raw, ctx = checks._fetch_vm_set(_ctx(api))
        self.assertEqual(len(records), 3)
        self.assertEqual(ctx["vms_total"], 3)
        self.assertEqual(ctx["pages"], 2)
        self.assertEqual(
            ctx["unreadable"], {"orphan-vm": ["config.hardware.device", "config.uuid"]}
        )
        vm_calls = [kw for op, kw in api.calls if kw.get("type") == "VirtualMachine"]
        self.assertEqual(len(vm_calls), 1)
        self.assertEqual(vm_calls[0]["moids"], ["1", "2", "42"])
        self.assertEqual(vm_calls[0]["timeout"], _loader.constants.VSPHERE_BIG_CALL_TIMEOUT)
        self.assertEqual(vm_calls[0]["paths"], list(checks._VM_PATHS))
        self.assertIn("RetrievePropertiesEx VirtualMachine[1,2,42] name,", "".join(raw))

    def test_undrained_token_is_refused(self):
        api = _FakeVsphere()
        api.vm_token = "1"
        with self.assertRaises(checks.CollectError):
            checks._fetch_vm_set(_ctx(api))

    def test_no_vms_is_not_present_for_vm_checks(self):
        props = _host_props()
        del props["vm"]
        for collector in (
            checks._collect_vms,
            checks._collect_vm_nics,
            checks._collect_vm_tuning,
            checks._collect_vm_disks,
        ):
            with self.assertRaises(checks.SkipCheck):
                collector(_ctx(_FakeVsphere(host_props=props)))


# --- vms -------------------------------------------------------------------------


class TestVms(unittest.TestCase):
    def setUp(self):
        self.normalized = checks._normalize_vms(checks._vm_records({"objects": _vm_objects()}))

    def test_tuned_vm_row(self):
        self.assertEqual(
            self.normalized["vm|fw-a"],
            {
                "uuid": "564d0001-0000-4000-8000-000000000001",
                "instance_uuid": "52400001-0000-4000-8000-000000000001",
                "hw_version": "vmx-19",
                "guest_id": "otherLinux64Guest",
                "power_state": "poweredOn",
                "connection_state": "connected",
                "num_cpu": 8,
                "cores_per_socket": 8,
                "auto_cores_per_socket": False,
                "memory_mb": 16384,
                "cpu_reservation_mhz": 8800,
                "cpu_limit_mhz": -1,
                "cpu_shares": 8000,
                "cpu_shares_level": "high",
                "mem_reservation_mb": 16384,
                "mem_limit_mb": -1,
                "mem_shares_level": "normal",
                "mem_locked_to_max": True,
                "latency_sensitivity": "high",
                "cpu_affinity": [2, 3, 4, 5],
                "tools_status": "toolsOk",
                "tools_running": "guestToolsRunning",
                "tools_version_status": "guestToolsUnmanaged",
                "guest_state": "running",
                "guest_hostname": "fw-a",
                "datastore": "datastore1",
                "snapshot_count": 3,
                "has_pending_question": False,
                "firmware": "efi",
                "efi_secure_boot": True,
                "boot_delay_ms": 0,
                "boot_order": ["disk:2000", "ethernet:4000", "cdrom"],
                "vvtd_enabled": True,
                "vbs_enabled": False,
                "cpu_hot_add": False,
                "memory_hot_add": False,
                "tools_sync_time_with_host": False,
            },
        )

    def test_never_vcenter_managed_vm_reads_none_not_loss(self):
        row = self.normalized["vm|fw-b"]
        self.assertIsNone(row["instance_uuid"])
        self.assertIsNone(row["auto_cores_per_socket"])
        self.assertIsNone(row["cpu_affinity"])
        self.assertEqual(row["snapshot_count"], 0)  # empty array omitted on the wire
        self.assertTrue(row["has_pending_question"])
        self.assertEqual(row["power_state"], "poweredOff")
        # flags / bootOptions / tools omitted -> null, never a fabricated false.
        self.assertEqual(row["firmware"], "bios")
        self.assertTrue(row["cpu_hot_add"])
        for field in (
            "efi_secure_boot",
            "boot_delay_ms",
            "boot_order",
            "vvtd_enabled",
            "vbs_enabled",
            "memory_hot_add",
            "tools_sync_time_with_host",
        ):
            self.assertIsNone(row[field], field)
        self.assertEqual(checks._boot_order({"bootDelay": "0"}), [])

    def test_orphan_keeps_its_row_with_fixed_fields(self):
        row = self.normalized["vm|orphan-vm"]
        self.assertEqual(set(row), set(self.normalized["vm|fw-a"]))
        self.assertIsNone(row["uuid"])
        self.assertEqual(row["connection_state"], "orphaned")
        self.assertEqual(row["snapshot_count"], 0)

    def test_collector_context(self):
        result = checks._collect_vms(_ctx())
        self.assertEqual(result["context"]["powered_on"], ["fw-a"])
        self.assertEqual(result["context"]["moids"]["fw-b"], "2")
        self.assertEqual(list(result["context"]["boot_times"]), ["fw-a"])
        self.assertTrue(result["context"]["questions"]["fw-b"].startswith("msg.uuid.altered"))
        # The whole-.vmx fingerprint, verbatim; null where hostd withheld it.
        self.assertEqual(
            result["context"]["config_versions"]["fw-a"],
            {
                "change_version": "2026-08-30T11:02:55.417123Z",
                "modified": "1970-01-01T00:00:00Z",
                "vmx_config_checksum": "c2hhMjU2OmZha2UtZmluZ2VycHJpbnQtZnctYQ==",
            },
        )
        self.assertEqual(
            result["context"]["config_versions"]["orphan-vm"],
            {"change_version": None, "modified": None, "vmx_config_checksum": None},
        )
        self.assertEqual(
            result["context"]["guest_net"],
            {
                "fw-a": [
                    {
                        "mac": "00:0c:29:aa:bb:01",
                        "ip_addresses": ["192.0.2.11", "fe80::20c:29ff:feaa:bb01"],
                        "connected": True,
                        "network": "Management Network",
                        "device_config_id": 4000,
                    },
                    {
                        "mac": "00:0c:29:aa:bb:03",
                        "ip_addresses": ["198.51.100.1"],
                        "connected": True,
                        "network": "HA-Sync",
                        "device_config_id": 4002,
                    },
                ]
            },
        )


# --- vm nics ---------------------------------------------------------------------


class TestVmNics(unittest.TestCase):
    def setUp(self):
        self.normalized = checks._normalize_vm_nics(checks._vm_records({"objects": _vm_objects()}))

    def test_every_mac_bearing_device_is_a_vnic_row(self):
        self.assertEqual(
            sorted(key for key in self.normalized if key.startswith("vnic|fw-a")),
            [
                "vnic|fw-a|Network adapter 1",
                "vnic|fw-a|Network adapter 2",
                "vnic|fw-a|Network adapter 3",
                "vnic|fw-a|Network adapter 4",
            ],
        )
        self.assertEqual(
            self.normalized["vnic|fw-a|Network adapter 1"],
            {
                "adapter_type": "VirtualVmxnet3",
                "mac": "00:0c:29:aa:bb:01",
                "address_type": "generated",
                "backing": "Management Network",
                "backing_type": "VirtualEthernetCardNetworkBackingInfo",
                "pf": None,
                "connected": True,
                "start_connected": True,
                "pci_slot": 160,
                "unit_number": 7,
                "upt_compatible": False,
            },
        )
        self.assertEqual(self.normalized["vnic|fw-a|Network adapter 3"]["mac"], "00:0c:29:aa:bb:03")
        sriov = self.normalized["vnic|fw-a|Network adapter 4"]
        self.assertEqual(sriov["adapter_type"], "VirtualSriovEthernetCard")
        self.assertEqual(sriov["pf"], "0000:18:00.0")
        self.assertEqual(sriov["backing"], "Inside-VL10")

    def test_passthrough_devices_under_their_own_prefix(self):
        row = self.normalized["pcidev|fw-a|PCI device 0"]
        self.assertEqual(row["backing_type"], "VirtualPCIPassthroughDynamicBackingInfo")
        self.assertIsNone(row["pci_id"])
        self.assertIsNone(row["device_id"])
        self.assertEqual(row["allowed_devices"], ["0x8086:0x37cd"])
        self.assertEqual(row["custom_label"], "x722-vf")
        self.assertEqual(row["pci_slot"], 1184)

    def test_fixed_directpath_ids_join_the_host_pci_rows_byte_for_byte(self):
        # The Fixed backing's deviceId is a bare hex string on the wire; it is
        # rendered exactly as the host's pci| row renders its xsd:short.
        row = self.normalized["pcidev|fw-b|PCI device 0"]
        self.assertEqual(row["backing_type"], "VirtualPCIPassthroughDeviceBackingInfo")
        self.assertEqual(row["pci_id"], "0000:18:00.1")
        self.assertEqual(row["allowed_devices"], [])
        host = checks._normalize_hardware_inventory(_host_props())["pci|0000:18:00.1"]
        self.assertEqual(row["device_id"], host["device_id"])
        self.assertEqual(row["vendor_id"], host["vendor_id"])
        self.assertEqual(row["device_id"], "0x37d0")
        self.assertIsNone(row["connected"])  # powered off
        self.assertEqual(checks._pci_hex_string("not-hex"), "not-hex")
        self.assertIsNone(checks._pci_hex_string(None))

    def test_powered_off_vm_has_null_connected_and_assigned_mac_type(self):
        e1000 = self.normalized["vnic|fw-b|Network adapter 1"]
        self.assertEqual(e1000["adapter_type"], "VirtualE1000e")
        self.assertEqual(e1000["address_type"], "assigned")
        self.assertIsNone(e1000["connected"])
        self.assertTrue(e1000["start_connected"])
        self.assertFalse(self.normalized["vnic|fw-b|Network adapter 2"]["start_connected"])
        self.assertIsNone(self.normalized["vnic|fw-b|Network adapter 1"]["upt_compatible"])

    def test_dvport_and_opaque_backings_never_crash(self):
        records = [
            {
                "moid": "7",
                "name": "x",
                "props": {
                    "runtime.powerState": "poweredOn",
                    "config.hardware.device": [
                        {
                            "_type": "VirtualVmxnet3",
                            "key": "4000",
                            "macAddress": "00:0c:29:00:00:01",
                            "backing": {
                                "_type": "VirtualEthernetCardDistributedVirtualPortBackingInfo",
                                "port": {"switchUuid": "50 11 22", "portgroupKey": "dvportgroup-9"},
                            },
                        },
                        {
                            "_type": "VirtualVmxnet3",
                            "key": "4001",
                            "macAddress": "00:0c:29:00:00:02",
                            "backing": {
                                "_type": "VirtualEthernetCardOpaqueNetworkBackingInfo",
                                "opaqueNetworkId": "abc",
                                "opaqueNetworkType": "nsx.LogicalSwitch",
                            },
                        },
                    ],
                },
                "missing": [],
            }
        ]
        normalized = checks._normalize_vm_nics(records)
        self.assertEqual(normalized["vnic|x|key-4000"]["backing"], "dvport:50 11 22/dvportgroup-9")
        self.assertEqual(normalized["vnic|x|key-4001"]["backing"], "opaque:abc")

    def test_collector_context(self):
        result = checks._collect_vm_nics(_ctx())
        self.assertEqual(result["context"]["vnics_total"], 6)
        self.assertEqual(result["context"]["passthrough_total"], 2)


# --- vm tuning -------------------------------------------------------------------


class TestVmTuning(unittest.TestCase):
    def setUp(self):
        self.normalized = checks._normalize_vm_tuning(
            checks._vm_records({"objects": _vm_objects()})
        )

    def test_curated_keys_only_values_as_strings(self):
        rows = {
            key.split("|", 2)[2]: row["value"]
            for key, row in self.normalized.items()
            if "|fw-a|" in key
        }
        self.assertEqual(rows["sched.cpu.latencySensitivity"], "high")
        self.assertEqual(rows["sched.mem.pin"], "TRUE")
        self.assertEqual(rows["numa.nodeAffinity"], "0")
        self.assertEqual(rows["ethernet0.coalescingScheme"], "disabled")
        self.assertEqual(rows["ethernet1.filter4.name"], "dvfilter-generic-vmware")
        self.assertEqual(rows["pciPassthru.64bitMMIOSizeGB"], "64")
        self.assertEqual(rows["monitor_control.disable_mmu_largepages"], "TRUE")
        for banned in (
            "numa.autosize.cookie",
            "ethernet0.pciSlotNumber",
            "migrate.hostLog",
            "nvram",
            "pciBridge0.present",
        ):
            self.assertNotIn(banned, rows)

    def test_affinity_absent_and_all_normalise_equal(self):
        self.assertEqual(self.normalized["tune|fw-a|sched.cpu.affinity"], {"value": "all"})
        self.assertEqual(self.normalized["tune|fw-b|sched.cpu.affinity"], {"value": "all"})

    def test_api_modeled_fallbacks(self):
        self.assertEqual(self.normalized["tune|fw-a|api:latencySensitivity"], {"value": "high"})
        self.assertEqual(self.normalized["tune|fw-a|api:cpuReservationMHz"], {"value": "8800"})
        self.assertEqual(self.normalized["tune|fw-a|api:memReservationMB"], {"value": "16384"})
        self.assertEqual(self.normalized["tune|fw-a|api:memPinned"], {"value": "true"})
        self.assertEqual(self.normalized["tune|fw-a|api:cpuAffinity"], {"value": "2,3,4,5"})
        self.assertEqual(self.normalized["tune|fw-b|api:cpuAffinity"], {"value": "all"})
        self.assertEqual(self.normalized["tune|fw-b|api:memPinned"], {"value": "false"})
        # An unreadable VM still gets the fixed api: rows, as None.
        self.assertEqual(self.normalized["tune|orphan-vm|api:latencySensitivity"], {"value": None})


# --- vm disks --------------------------------------------------------------------


class TestVmDisks(unittest.TestCase):
    def test_rows_resolve_controller_and_datastore(self):
        normalized = checks._normalize_vm_disks(checks._vm_records({"objects": _vm_objects()}))
        self.assertEqual(
            normalized["vdisk|fw-a|Hard disk 1"],
            {
                "capacity_kb": 62914560,
                "backing_file": "[datastore1] fw-a/fw-a.vmdk",
                "datastore": "datastore1",
                "backing_type": "VirtualDiskFlatVer2BackingInfo",
                "thin": False,
                "eager_zeroed": True,
                "disk_mode": "persistent",
                "controller": "SCSI controller 0",
                "unit_number": 0,
            },
        )
        self.assertTrue(normalized["vdisk|fw-b|Hard disk 1"]["thin"])
        self.assertEqual(len(normalized), 2)

    def test_collector_context(self):
        self.assertEqual(checks._collect_vm_disks(_ctx())["context"]["disks_total"], 2)


# --- autostart -------------------------------------------------------------------


class TestAutostart(unittest.TestCase):
    def test_defaults_every_vm_and_stale_entries(self):
        config = _host_props()["config.autoStart"]
        normalized = checks._normalize_autostart(
            config, {"1": "fw-a", "2": "fw-b", "42": "orphan-vm"}
        )
        self.assertEqual(normalized["defaults|enabled"], {"value": True})
        self.assertEqual(normalized["defaults|start_delay"], {"value": 120})
        self.assertEqual(normalized["defaults|stop_action"], {"value": "guestShutdown"})
        self.assertEqual(normalized["defaults|wait_for_heartbeat"], {"value": False})
        self.assertEqual(
            normalized["autostart|fw-a"],
            {
                "configured": True,
                "vm_registered": True,
                "start_order": 1,
                "start_delay": -1,
                "start_action": "powerOn",
                "stop_delay": -1,
                "stop_action": "systemDefault",
                "wait_for_heartbeat": "systemDefault",
            },
        )
        self.assertEqual(normalized["autostart|fw-b"]["start_order"], 2)
        self.assertEqual(normalized["autostart|fw-b"]["stop_action"], "guestShutdown")
        # Registered VM absent from powerInfo: a row, configured False.
        self.assertFalse(normalized["autostart|orphan-vm"]["configured"])
        self.assertTrue(normalized["autostart|orphan-vm"]["vm_registered"])
        # Stale powerInfo entry whose VM is gone: keyed by moid.
        self.assertFalse(normalized["autostart|77"]["vm_registered"])
        self.assertEqual(normalized["autostart|77"]["start_action"], "none")

    def test_collector_resolves_names_through_the_shared_vm_set(self):
        api = _FakeVsphere()
        result = checks._collect_autostart(_ctx(api))
        self.assertEqual(result["context"]["configured"], ["77", "fw-a", "fw-b"])
        self.assertEqual(result["context"]["unconfigured"], ["orphan-vm"])
        self.assertEqual(result["context"]["vms_total"], 3)
        self.assertEqual(len([kw for op, kw in api.calls if kw.get("type") == "VirtualMachine"]), 1)

    def test_absent_autostart_is_not_present_and_no_vms_is_fine(self):
        props = _host_props()
        del props["config.autoStart"]
        with self.assertRaises(checks.SkipCheck):
            checks._collect_autostart(_ctx(_FakeVsphere(host_props=props)))
        props = _host_props()
        del props["vm"]
        result = checks._collect_autostart(_ctx(_FakeVsphere(host_props=props)))
        self.assertEqual(result["context"]["vms_total"], 0)
        self.assertFalse(result["normalized"]["autostart|1"]["vm_registered"])


# --- vlan hints ------------------------------------------------------------------


class TestVlanHints(unittest.TestCase):
    def test_sorted_deduplicated_vlans_per_pnic(self):
        normalized, subnets = checks._normalize_vlan_hints(_hints())
        self.assertEqual(normalized["vlans|vmnic0"], {"vlan_ids": [100, 101]})
        self.assertEqual(normalized["vlans|vmnic1"], {"vlan_ids": []})
        self.assertEqual(normalized["vlans|vmnic2"], {"vlan_ids": [10, 20, 30]})
        self.assertEqual(normalized["vlans|vmnic3"], {"vlan_ids": [10]})
        self.assertEqual(subnets["vmnic2"], ["10.10.10.0@10", "10.10.20.0@20", "10.10.30.0@30"])

    def test_collector_context_and_skip(self):
        result = checks._collect_vlan_hints(_ctx())
        self.assertEqual(result["context"]["pnics_with_hints"], 4)
        self.assertEqual(result["context"]["subnets"]["vmnic1"], [])
        with self.assertRaises(checks.SkipCheck):
            checks._collect_vlan_hints(_ctx(_FakeVsphere(hints=[])))


# --- license ---------------------------------------------------------------------


class TestHostLicense(unittest.TestCase):
    def test_flat_scalars_with_redacted_key(self):
        licenses = _page("vsphere_license.xml")["objects"][0]["props"]["licenses"]
        normalized, ctx = checks._normalize_host_license(licenses)
        self.assertEqual(
            normalized,
            {
                "edition_key": "esx.enterprisePlus.cpuPackageCoreLimited",
                "name": "VMware vSphere 8 Enterprise Plus",
                "total": 1,
                "used": 1,
                "cost_unit": "cpuPackage:32core",
                "license_key_tail": "...EEEEE",
                "expiration": "2027-01-31T00:00:00Z",
                "product_name": "VMware ESX Server",
                "product_version": "8.0",
                "features": ["dvfilter", "sriov", "vsmp"],
            },
        )
        self.assertEqual(ctx, {"licenses_total": 1, "expiration_hours": 3067})

    def test_collector_redacts_raw_and_uses_service_content_moid(self):
        api = _FakeVsphere()
        result = checks._collect_host_license(_ctx(api))
        self.assertNotIn("AAAAA-BBBBB", str(result["raw"]))
        self.assertIn("...EEEEE", str(result["raw"]))
        license_calls = [kw for op, kw in api.calls if kw.get("type") == "LicenseManager"]
        self.assertEqual(license_calls[0]["moids"], ["ha-license-manager"])

    def test_no_licenses_is_empty(self):
        self.assertEqual(checks._normalize_host_license(None), ({}, {"licenses_total": 0}))


# --- recent tasks ----------------------------------------------------------------


class TestRecentTasks(unittest.TestCase):
    def test_task_rows_from_traversal_objects(self):
        objects = _page("vsphere_recent_tasks.xml")["objects"]
        normalized = checks._normalize_recent_tasks(objects)
        self.assertEqual(
            normalized["task|haTask-ha-host-vim.host.StorageSystem.refreshStorageSystem-123456789"],
            {
                "description_id": "vim.host.StorageSystem.refreshStorageSystem",
                "state": "success",
                "entity": "se350-1.example.net",
                "entity_type": "HostSystem",
                "user": "root",
                "queue_time": "2026-09-24T09:58:01.204Z",
                "complete_time": "2026-09-24T09:58:03.881Z",
            },
        )
        running = normalized["task|haTask-1-vim.VirtualMachine.powerOn-987654"]
        self.assertEqual(running["state"], "running")
        self.assertIsNone(running["user"])  # TaskReasonSystem
        self.assertIsNone(running["complete_time"])

    def test_collector_uses_traversal_and_flags_own_login(self):
        api = _FakeVsphere()
        result = checks._collect_recent_tasks(_ctx(api))
        self.assertEqual(result["context"]["task_count"], 2)
        self.assertEqual(
            result["context"]["tasks_running"], ["haTask-1-vim.VirtualMachine.powerOn-987654"]
        )
        event = result["context"]["latest_event"]
        self.assertTrue(event["is_own_login"])
        self.assertEqual(event["user_name"], "testsuite-ro")
        self.assertEqual(event["type"], "UserLoginSessionEvent")
        task_calls = [kw for op, kw in api.calls if kw.get("type") == "TaskManager"]
        self.assertEqual(
            task_calls[0]["traverse"], {"path": "recentTask", "type": "Task", "paths": ["info"]}
        )
        self.assertEqual(task_calls[0]["moids"], ["ha-taskmgr"])
        self.assertEqual(registry.CHECKS["vmware_recent_tasks"].compare, {"mode": "info_only"})

    def test_quiet_host_is_parsed_but_empty(self):
        api = _FakeVsphere()
        api.tasks = {
            "objects": [
                {"obj": {"type": "TaskManager", "moid": "ha-taskmgr"}, "props": {}, "missing": []}
            ],
            "token": None,
        }
        result = checks._collect_recent_tasks(_ctx(api))
        self.assertEqual(result["normalized"], {})
        self.assertEqual(result["context"]["task_count"], 0)


# --- cache sharing and raw discipline --------------------------------------------


class TestCacheSharing(unittest.TestCase):
    def test_network_group_is_fetched_once_for_seven_checks(self):
        api = _FakeVsphere()
        ctx = _ctx(api)
        for collector in (
            checks._collect_pnics,
            checks._collect_pnic_neighbors,
            checks._collect_vswitches,
            checks._collect_portgroups,
            checks._collect_vmknics,
            checks._collect_host_routes,
            checks._collect_vlan_hints,
        ):
            collector(ctx)
        self.assertEqual(len(_host_calls(api, "config.network")), 1)
        self.assertEqual(len([kw for op, kw in api.calls if op == "QueryNetworkHint"]), 1)
        outcomes = [entry["outcome"] for entry in ctx.trace]
        self.assertEqual(outcomes.count("ok"), 2)
        self.assertGreaterEqual(outcomes.count("cache-hit"), 7)

    def test_option_and_service_groups_are_shared(self):
        api = _FakeVsphere()
        ctx = _ctx(api)
        checks._collect_time_syslog(ctx)
        checks._collect_host_services(ctx)
        checks._collect_advanced_options(ctx)
        self.assertEqual(len(_host_calls(api, "config.option")), 1)
        self.assertEqual(len(_host_calls(api, "config.service")), 1)
        self.assertEqual(len(_host_calls(api, "config.dateTimeInfo")), 1)

    def test_per_vm_property_set_is_shared_by_five_checks(self):
        api = _FakeVsphere()
        ctx = _ctx(api)
        for collector in (
            checks._collect_vms,
            checks._collect_vm_nics,
            checks._collect_vm_tuning,
            checks._collect_vm_disks,
            checks._collect_autostart,
        ):
            collector(ctx)
        self.assertEqual(len([kw for op, kw in api.calls if kw.get("type") == "VirtualMachine"]), 1)
        self.assertEqual(len(_host_calls(api, "vm")), 1)

    def test_full_catalog_runs_with_every_check_success_or_declared_skip(self):
        api = _FakeVsphere()
        ctx = _ctx(api)
        outcomes = {}
        for check in registry.checks_for("vmware"):
            try:
                result = check.collector(ctx)
            except checks.SkipCheck as exc:
                outcomes[check.id] = "not-present: %s" % (exc,)
                continue
            self.assertEqual(set(result), {"raw", "normalized", "context"}, check.id)
            self.assertIsInstance(result["normalized"], dict, check.id)
            outcomes[check.id] = "ok"
        self.assertEqual(sorted(outcomes), sorted(TestRegistrations.EXPECTED_IDS))
        self.assertTrue(all(value == "ok" for value in outcomes.values()), outcomes)
        # 23 checks, 19 DISTINCT requests (one per property group / manager /
        # hint call) — every sibling read was a cache hit.
        self.assertEqual(len(api.calls), 19, [op for op, _ in api.calls])
        self.assertEqual(len(api.calls), len({str(call) for call in api.calls}))


class TestRawCuration(unittest.TestCase):
    def test_cap_leaves_small_values_alone_and_marks_big_ones(self):
        small = {"a": 1}
        self.assertIs(checks._capped(small), small)
        big = {"blob": "x" * (checks._RAW_CAP + 100)}
        capped = checks._capped(big)
        self.assertTrue(capped["truncated"])
        self.assertEqual(capped["chars_kept"], checks._RAW_CAP)
        self.assertGreater(capped["chars_total"], checks._RAW_CAP)
        self.assertEqual(len(capped["head"]), checks._RAW_CAP)

    def test_cap_cuts_a_list_between_items(self):
        # A list keeps whole leading items so what survives stays parseable.
        big = [{"n": index, "pad": "x" * 100} for index in range(400)]
        capped = checks._capped(big)
        self.assertTrue(capped["truncated"])
        self.assertEqual(capped["items_total"], 400)
        self.assertEqual(len(capped["items"]), capped["items_kept"])
        self.assertLess(capped["items_kept"], 400)
        self.assertEqual(capped["items"][-1]["n"], capped["items_kept"] - 1)
        self.assertLessEqual(len(__import__("json").dumps(capped["items"])), checks._RAW_CAP)
        # One item alone bigger than the cap falls back to the text head.
        capped = checks._capped(["y" * (checks._RAW_CAP + 1)])
        self.assertIn("head", capped)
        # A curator's pre-capped dict passes through untouched.
        pre = checks._Precapped({"remainder": {"Big": "z" * (checks._RAW_CAP + 5)}})
        self.assertEqual(checks._capped(pre), dict(pre))
        self.assertNotIn("head", checks._capped(pre))

    def test_curated_options_keep_curated_block_uncapped(self):
        options = [{"key": "Curated.Key", "value": 1}]
        options += [{"key": "Bulk.Key%05d" % (index,), "value": "v" * 40} for index in range(800)]
        options.append({"key": "Some.Password", "value": "hunter2"})
        options.append({"key": "Small.One", "value": "s"})
        entry = checks._curated_options(options, {"Curated.Key"})
        self.assertIsInstance(entry, checks._Precapped)
        self.assertEqual(entry["curated"], {"Curated.Key": 1})
        self.assertEqual(entry["remainder_count"], 802)
        self.assertEqual(sorted(entry["remainder"]), ["Bulk", "Small", "Some"])
        self.assertIn("...[truncated", entry["remainder"]["Bulk"])
        self.assertEqual(entry["remainder"]["Small"], "Small.One=s")
        self.assertEqual(entry["remainder"]["Some"], "Some.Password=***scrubbed***")
        self.assertNotIn("hunter2", str(entry))
        self.assertFalse(checks._secret_key("Security.PasswordQualityControl"))
        self.assertTrue(checks._secret_key("UserVars.SomeAgent.apiToken"))

    def test_prune_drops_keys_at_any_depth(self):
        node = {"keep": [{"drop": 1, "keep": {"drop": 2}}]}
        self.assertEqual(checks._prune(node, {"drop"}), {"keep": [{"keep": {}}]})


if __name__ == "__main__":
    unittest.main()
