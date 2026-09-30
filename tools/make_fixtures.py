#!/usr/bin/env python3
"""Turn one ``tools/harvest_live.py`` harvest into sanitized ``tests/fixtures/`` files.

Usage (from the repository root; stdlib only, the login never printed):

    python3 tools/make_fixtures.py --payloads /path/outside/the/repo/<tag> \\
        --map /path/outside/the/repo/sanitize-map.json --out tests/fixtures \\
        --env /path/to/device.env \\
        [--host REAL=FAKE ...] [--user NAME ...] [--net SRC/24=DST/24 ...] \\
        [--replace OLD=NEW ...] [--suffix _lab_variant --only NAME[,NAME...]] [--list]

What it does, in order:

1. Reads the mapping file (``tools/sanitize_trace.py``'s real -> invented
   table: hosts, users, serials, asset tags, UUIDs, MACs, networks, IPv6
   addresses) so this run invents the same values as the last one, and adds
   the ``--host`` / ``--net`` pairs to it. The file lives beside the raw
   payloads, outside the repository.
2. Discovers the user names the device itself prints: on a switch the
   ``username`` lines in the config texts, ``[user: ...]`` login lines and
   ``by <user>`` config headers, mapped with ``--user`` names to ``netops``;
   on a BMC the account names Lenovo log messages carry (``Login ID: <x>``,
   ``by user <x>``, ``for user <x>``, ``User <x> ...``, ``Userid is <x>``) in
   the log-entry pages and every other harvest JSON, each mapped to its own
   ``user-lab-<n>`` (the BMC's own actors, ``system`` or ``LXPM``, are not
   people; a harvest's ``***scrubbed***`` marker is not a user).
3. Learns from EVERY ``*.json`` of the harvest before sanitizing anything: the
   serials of any shape, asset tags, hostnames and account names the Redfish
   leaves name, so a serial a log message or a boot entry mentions is replaced
   wherever it appears, whichever file names it.
4. Sanitizes every payload the table below names (a harvest file -> a fixture
   name) with the mapping, the discovered users and every value of the
   ``--env`` credential file (the file's ``user`` / ``username`` value becomes
   ``netops``, an address is invented like any other, the rest ``REDACTED``);
   the values are never printed or written.
5. Applies ``--replace OLD=NEW`` literals (kept in the mapping file under
   ``literals`` so a re-run repeats them): for a string that must not reach
   the repository although it identifies nobody — the version of an image
   left on flash from a release the environment does not run, for instance.
6. Writes each fixture, then scans every written file for anything real the
   mapping knows (counts only, never the values) and exits 1 on a hit.

``--suffix`` renames the fixtures for a variant capture (``_lab`` in a name is
replaced by it; a name without ``_lab`` gets it before the extension) and
``--only`` limits the run to the named fixtures, so an anomaly harvest — a
loop, a root elsewhere, a mismatch — produces ``*_lab_hairpin.*`` beside the
baseline set without overwriting it. ``--list`` prints the table and exits.

Then grep the fixtures for the real hostnames, addresses and names one more
time (``tests/test_lab_fixtures.py`` keeps the shape-based guard running in
CI) before committing.
"""

import argparse
import json
import pathlib
import re
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import sanitize_trace  # noqa: E402

_G = "get__data_"
_R = "get__redfish_v1_"

# Harvest file -> fixture name. The fixture name is what the tests read; the
# harvest name is what tools/harvest_live.py wrote (``__f<hash>`` marks a
# fields-filtered read: the one the check issues, so the fixture is exactly
# the payload the normalizer sees).
TABLE = {
    # --- payloads the checks read (filtered where the check filters) --------
    _G + "Cisco_IOS_XE_arp_oper_arp_data.json": "iosxe_arp_oper_lab.json",
    _G + "Cisco_IOS_XE_environment_oper_environment_sensors.json": (
        "iosxe_environment_sensors_lab.json"
    ),
    _G + "Cisco_IOS_XE_fib_oper_fib_oper_data__f80385c.json": "iosxe_fib_oper_lab.json",
    _G + "Cisco_IOS_XE_lldp_oper_lldp_entries.json": "iosxe_lldp_entries_lab.json",
    _G + "ietf_routing_routing_state.json": "iosxe_rib_routing_state_lab.json",
    "ssh__show_ip_route_summary.txt": "iosxe_route_summary_lab.txt",
    "ssh__show_logging.txt": "iosxe_show_logging.txt",
    _G + "Cisco_IOS_XE_platform_software_oper_cisco_platform_software__f1717b0.json": (
        "iosxe_q_filesystem_model_shape_lab.json"
    ),
    _G + "Cisco_IOS_XE_vlan_oper_vlans.json": "iosxe_vlan_oper_lab.json",
    _G + "Cisco_IOS_XE_spanning_tree_oper_stp_details__f5e9714.json": (
        "iosxe_stp_details_lab.json"
    ),
    _G + "Cisco_IOS_XE_matm_oper_matm_oper_data_matm_table__f3a92db.json": (
        "iosxe_matm_table_lab.json"
    ),
    _G + "Cisco_IOS_XE_poe_oper_poe_oper_data__fa2bcd6.json": "iosxe_poe_oper_lab.json",
    "ssh__show_interfaces_trunk.txt": "iosxe_show_interfaces_trunk_lab.txt",
    "ssh__show_vtp_status.txt": "iosxe_show_vtp_status_lab.txt",
    _G + "Cisco_IOS_XE_stack_oper_stack_oper_data.json": "iosxe_stack_oper_lab.json",
    "ssh__show_switch_detail.txt": "iosxe_show_switch_detail_lab.txt",
    "ssh__show_switch_stack_ports_summary.txt": "iosxe_show_switch_stack_ports_summary_lab.txt",
    "ssh__show_inventory.txt": "iosxe_show_inventory_9300_lab.txt",
    _G + "Cisco_IOS_XE_device_hardware_oper_device_hardware_data.json": (
        "iosxe_device_hardware_lab.json"
    ),
    _G + "Cisco_IOS_XE_interfaces_oper_interfaces__f003b82.json": "iosxe_interfaces_oper_lab.json",
    _G + "Cisco_IOS_XE_ospf_oper_ospf_oper_data__f26193a.json": "iosxe_ospf_oper_lab.json",
    _G + "Cisco_IOS_XE_cdp_oper_cdp_neighbor_details.json": "iosxe_cdp_neighbors_lab.json",
    _G + "Cisco_IOS_XE_bgp_oper_bgp_state_data_neighbors.json": "iosxe_bgp_neighbors_lab.json",
    _G + "Cisco_IOS_XE_aaa_oper_aaa_data_aaa_radius_stats__fad6beb.json": (
        "iosxe_aaa_radius_stats_lab.json"
    ),
    "ssh__show_running_config.txt": "iosxe_show_running_config_lab.txt",
    "ssh__show_startup_config.txt": "iosxe_show_startup_config_lab.txt",
    _G + "Cisco_IOS_XE_install_oper_install_oper_data_install_location_information__f056f66.json": (
        "iosxe_install_location_information_lab.json"
    ),
    _G + "Cisco_IOS_XE_identity_oper_identity_oper_data_session_context_data__fa64070.json": (
        "iosxe_identity_session_context_lab.json"
    ),
    _G + "Cisco_IOS_XE_lacp_oper_lag_oper_data.json": "iosxe_lacp_oper_lab.json",
    _G + "Cisco_IOS_XE_switch_cp_svl_oper_switch_cp_svl_oper_data.json": (
        "iosxe_svl_oper_locations_only_lab.json"
    ),
    _G + "Cisco_IOS_XE_hsrp_oper_hsrp_oper_data.json": "iosxe_hsrp_oper_lab.json",
    _G + "Cisco_IOS_XE_isis_oper_isis_oper_data.json": "iosxe_isis_oper_lab.json",
    _G + "Cisco_IOS_XE_psecure_oper_psecure_oper_data.json": "iosxe_psecure_oper_lab.json",
    _G + "Cisco_IOS_XE_poe_health_oper_poe_health_oper_data.json": "iosxe_poe_health_oper_lab.json",
    # --- whole containers beside the filtered reads, and models read whole --
    _G + "Cisco_IOS_XE_vrrp_oper_vrrp_oper_data.json": "iosxe_vrrp_oper_lab.json",
    _G + "Cisco_IOS_XE_eigrp_oper_eigrp_oper_data.json": "iosxe_eigrp_oper_lab.json",
    _G + "Cisco_IOS_XE_ospf_oper_ospf_oper_data.json": "iosxe_ospf_oper_full_lab.json",
    _G + "Cisco_IOS_XE_bgp_oper_bgp_state_data.json": "iosxe_bgp_state_data_lab.json",
    _G + "Cisco_IOS_XE_ntp_oper_ntp_oper_data.json": "iosxe_ntp_oper_lab.json",
    _G + "Cisco_IOS_XE_ha_oper_ha_oper_data.json": "iosxe_ha_oper_lab.json",
    _G + "cisco_smart_license_licensing_state.json": "iosxe_smart_license_state_lab.json",
    _G + "Cisco_IOS_XE_tcam_oper_tcam_details.json": "iosxe_tcam_details_lab.json",
    _G + "Cisco_IOS_XE_switch_dp_resources_oper_switch_dp_resources_oper_data.json": (
        "iosxe_switch_dp_resources_lab.json"
    ),
    _G + "Cisco_IOS_XE_device_hardware_oper_device_hardware_data_device_hardware"
    "_device_system_data.json": "iosxe_device_system_data_lab.json",
    _G + "Cisco_IOS_XE_poe_oper_poe_oper_data.json": "iosxe_poe_oper_full_lab.json",
    _G + "Cisco_IOS_XE_spanning_tree_oper_stp_details.json": "iosxe_stp_details_full_lab.json",
    _G + "Cisco_IOS_XE_matm_oper_matm_oper_data.json": "iosxe_matm_oper_full_lab.json",
    _G + "Cisco_IOS_XE_interfaces_oper_interfaces_interface_TenGigabitEthernet1_2F0_2F48.json": (
        "iosxe_interface_trunk_port_lab.json"
    ),
    _G + "Cisco_IOS_XE_interfaces_oper_interfaces_interface_TwoGigabitEthernet1_2F0_2F14.json": (
        "iosxe_interface_wap_port_lab.json"
    ),
    _G + "Cisco_IOS_XE_interfaces_oper_interfaces_interface_Vlan3.json": (
        "iosxe_interface_svi_lab.json"
    ),
    _G + "Cisco_IOS_XE_native_native_router.json": "iosxe_native_router_lab.json",
    _G + "Cisco_IOS_XE_native_native_ip_dhcp.json": "iosxe_native_ip_dhcp_lab.json",
    _G + "Cisco_IOS_XE_platform_oper_components.json": "iosxe_platform_components_lab.json",
    # --- show command layouts ---------------------------------------------
    "ssh__show_license_summary.txt": "iosxe_show_license_summary_lab.txt",
    "ssh__show_sdm_prefer.txt": "iosxe_show_sdm_prefer_lab.txt",
    "ssh__show_vrrp_brief.txt": "iosxe_show_vrrp_brief_lab.txt",
    "ssh__show_standby_brief.txt": "iosxe_show_standby_brief_refused_lab.txt",
    "ssh__show_ip_eigrp_neighbors.txt": "iosxe_show_ip_eigrp_neighbors_lab.txt",
    "ssh__show_ip_eigrp_interfaces.txt": "iosxe_show_ip_eigrp_interfaces_lab.txt",
    "ssh__show_isis_neighbors.txt": "iosxe_show_isis_neighbors_refused_lab.txt",
    "ssh__show_vlan_brief.txt": "iosxe_show_vlan_brief_lab.txt",
    "ssh__show_power_inline.txt": "iosxe_show_power_inline_lab.txt",
    "ssh__show_power_inline_TwoGigabitEthernet1_0_14_detail.txt": (
        "iosxe_show_power_inline_detail_lab.txt"
    ),
    "ssh__show_cdp_neighbors_detail.txt": "iosxe_show_cdp_neighbors_detail_lab.txt",
    "ssh__show_lldp_neighbors_detail.txt": "iosxe_show_lldp_neighbors_detail_lab.txt",
    "ssh__show_etherchannel_summary.txt": "iosxe_show_etherchannel_summary_lab.txt",
    "ssh__show_ntp_status.txt": "iosxe_show_ntp_status_lab.txt",
    "ssh__show_ntp_associations.txt": "iosxe_show_ntp_associations_lab.txt",
    "ssh__show_crypto_pki_certificates.txt": "iosxe_show_crypto_pki_certificates_lab.txt",
    "ssh__show_interfaces_status_err_disabled.txt": (
        "iosxe_show_interfaces_status_err_disabled_lab.txt"
    ),
    "ssh__show_interfaces_status.txt": "iosxe_show_interfaces_status_lab.txt",
    "ssh__show_spanning_tree.txt": "iosxe_show_spanning_tree_lab.txt",
    "ssh__show_spanning_tree_summary.txt": "iosxe_show_spanning_tree_summary_lab.txt",
    "ssh__show_ip_route.txt": "iosxe_show_ip_route_lab.txt",
    "ssh__show_ip_ospf_neighbor.txt": "iosxe_show_ip_ospf_neighbor_lab.txt",
    "ssh__show_ip_ospf_interface_brief.txt": "iosxe_show_ip_ospf_interface_brief_lab.txt",
    "ssh__show_ip_protocols.txt": "iosxe_show_ip_protocols_lab.txt",
    "ssh__show_port_security.txt": "iosxe_show_port_security_lab.txt",
    "ssh__show_mac_address_table.txt": "iosxe_show_mac_address_table_lab.txt",
    "ssh__show_install_summary.txt": "iosxe_show_install_summary_lab.txt",
    "ssh__show_version.txt": "iosxe_show_version_lab.txt",
    "ssh__show_storm_control.txt": "iosxe_show_storm_control_lab.txt",
    "ssh__show_errdisable_recovery.txt": "iosxe_show_errdisable_recovery_lab.txt",
    "ssh__show_environment_all.txt": "iosxe_show_environment_all_lab.txt",
    "ssh__show_platform.txt": "iosxe_show_platform_lab.txt",
    "ssh__show_boot.txt": "iosxe_show_boot_lab.txt",
    "ssh__show_ip_dhcp_pool.txt": "iosxe_show_ip_dhcp_pool_lab.txt",
    "ssh__show_access_lists.txt": "iosxe_show_access_lists_lab.txt",
    "ssh__show_policy_map_interface.txt": "iosxe_show_policy_map_interface_lab.txt",
    "ssh__show_interfaces_TenGigabitEthernet1_0_48.txt": "iosxe_show_interfaces_trunk_port_lab.txt",
    "ssh__show_interfaces_transceiver_detail.txt": (
        "iosxe_show_interfaces_transceiver_detail_lab.txt"
    ),
    "ssh__show_logging_include_4_5.txt": "iosxe_show_logging_sev45_lab.txt",
    "ssh__dir_crashinfo.txt": "iosxe_dir_crashinfo_lab.txt",
    # --- a server's BMC (tools/harvest_live.py --platform bmc; the lab unit is
    # a gen-1 ThinkSystem SE350 on XCC 6.10, so the fixtures keep the xcc_
    # prefix): every Redfish payload the bmc family and the next checks read,
    # plain and $expand forms of each collection; the history containers
    # (HistorySysPerf, Metrics) and ServiceData are volatile and not mapped.
    "get__redfish_v1.json": "xcc_service_root_lab.json",
    _R + "AccountService.json": "xcc_accountservice_lab.json",
    _R + "AccountService_Accounts.json": "xcc_accountservice_accounts_lab.json",
    _R + "AccountService_Accounts__f2e3cd0.json": "xcc_accountservice_accounts_expanded_lab.json",
    _R + "AccountService_Roles.json": "xcc_accountservice_roles_lab.json",
    _R + "AccountService_Roles__f4e85b2.json": "xcc_accountservice_roles_expanded_lab.json",
    _R + "CertificateService.json": "xcc_certificateservice_lab.json",
    _R + "CertificateService_CertificateLocations.json": (
        "xcc_certificateservice_certificatelocations_lab.json"
    ),
    _R + "CertificateService_CertificateLocations__f5b1010.json": (
        "xcc_certificateservice_certificatelocations_expanded_lab.json"
    ),
    _R + "Chassis.json": "xcc_chassis_collection_lab.json",
    _R + "Chassis_1.json": "xcc_chassis_lab.json",
    _R + "Chassis_1_Controls.json": "xcc_chassis_controls_lab.json",
    _R + "Chassis_1_Controls__f3d74d1.json": "xcc_chassis_controls_expanded_lab.json",
    _R + "Chassis_1_EnvironmentMetrics.json": "xcc_chassis_environmentmetrics_lab.json",
    _R + "Chassis_1_NetworkAdapters.json": "xcc_chassis_networkadapters_lab.json",
    _R + "Chassis_1_NetworkAdapters_ob_2_NetworkDeviceFunctions__fb4bb08.json": (
        "xcc_chassis_networkadapters_ob_2_networkdevicefunctions_expanded_lab.json"
    ),
    _R + "Chassis_1_NetworkAdapters_ob_2_NetworkPorts__f19aafa.json": (
        "xcc_chassis_networkadapters_ob_2_networkports_expanded_lab.json"
    ),
    _R + "Chassis_1_NetworkAdapters_ob_2_Ports__f6ca55d.json": (
        "xcc_chassis_networkadapters_ob_2_ports_expanded_lab.json"
    ),
    _R + "Chassis_1_NetworkAdapters_ob_4_NetworkDeviceFunctions__fbf7ccb.json": (
        "xcc_chassis_networkadapters_ob_4_networkdevicefunctions_expanded_lab.json"
    ),
    _R + "Chassis_1_NetworkAdapters_ob_4_NetworkPorts__fb65d55.json": (
        "xcc_chassis_networkadapters_ob_4_networkports_expanded_lab.json"
    ),
    _R + "Chassis_1_NetworkAdapters_ob_4_Ports__fee2a9c.json": (
        "xcc_chassis_networkadapters_ob_4_ports_expanded_lab.json"
    ),
    _R + "Chassis_1_NetworkAdapters_slot_6_NetworkDeviceFunctions__f24aca5.json": (
        "xcc_chassis_networkadapters_slot_6_networkdevicefunctions_expanded_lab.json"
    ),
    _R + "Chassis_1_NetworkAdapters_slot_6_NetworkPorts__f69824b.json": (
        "xcc_chassis_networkadapters_slot_6_networkports_expanded_lab.json"
    ),
    _R + "Chassis_1_NetworkAdapters_slot_6_Ports__f9378c1.json": (
        "xcc_chassis_networkadapters_slot_6_ports_expanded_lab.json"
    ),
    _R + "Chassis_1_NetworkAdapters__f374aa8.json": "xcc_chassis_networkadapters_expanded_lab.json",
    _R + "Chassis_1_Oem_Lenovo_LEDs.json": "xcc_chassis_lenovo_leds_lab.json",
    _R + "Chassis_1_Oem_Lenovo_LEDs__f1618aa.json": "xcc_chassis_lenovo_leds_expanded_lab.json",
    _R + "Chassis_1_Oem_Lenovo_Slots.json": "xcc_chassis_lenovo_slots_lab.json",
    _R + "Chassis_1_Oem_Lenovo_Slots__f3f8efe.json": "xcc_chassis_lenovo_slots_expanded_lab.json",
    _R + "Chassis_1_PCIeDevices.json": "xcc_chassis_pciedevices_lab.json",
    _R + "Chassis_1_PCIeDevices_ob_1_PCIeFunctions__f81e088.json": (
        "xcc_chassis_pciedevices_ob_1_pciefunctions_expanded_lab.json"
    ),
    _R + "Chassis_1_PCIeDevices_ob_2_PCIeFunctions__f5ddc49.json": (
        "xcc_chassis_pciedevices_ob_2_pciefunctions_expanded_lab.json"
    ),
    _R + "Chassis_1_PCIeDevices_ob_4_PCIeFunctions__ff74ec2.json": (
        "xcc_chassis_pciedevices_ob_4_pciefunctions_expanded_lab.json"
    ),
    _R + "Chassis_1_PCIeDevices_slot_6_PCIeFunctions__f08cb0f.json": (
        "xcc_chassis_pciedevices_slot_6_pciefunctions_expanded_lab.json"
    ),
    _R + "Chassis_1_PCIeDevices__f6bb6e1.json": "xcc_chassis_pciedevices_expanded_lab.json",
    _R + "Chassis_1_PCIeSlots.json": "xcc_chassis_pcieslots_lab.json",
    _R + "Chassis_1_Power.json": "xcc_chassis_power_lab.json",
    _R + "Chassis_1_PowerSubsystem.json": "xcc_chassis_powersubsystem_lab.json",
    _R + "Chassis_1_Sensors.json": "xcc_chassis_sensors_lab.json",
    _R + "Chassis_1_Sensors__f1131f3.json": "xcc_chassis_sensors_expanded_lab.json",
    _R + "Chassis_1_Thermal.json": "xcc_chassis_thermal_lab.json",
    _R + "Chassis_1_ThermalSubsystem.json": "xcc_chassis_thermalsubsystem_lab.json",
    _R + "Chassis_1_ThermalSubsystem_Fans.json": "xcc_chassis_thermalsubsystem_fans_lab.json",
    _R + "Chassis_1_ThermalSubsystem_Fans__f6ad276.json": (
        "xcc_chassis_thermalsubsystem_fans_expanded_lab.json"
    ),
    _R + "Chassis_1_ThermalSubsystem_ThermalMetrics.json": (
        "xcc_chassis_thermalsubsystem_thermalmetrics_lab.json"
    ),
    _R + "Chassis__f91f03b.json": "xcc_chassis_collection_expanded_lab.json",
    _R + "EventService.json": "xcc_eventservice_lab.json",
    _R + "EventService_Subscriptions.json": "xcc_eventservice_subscriptions_lab.json",
    _R + "EventService_Subscriptions__f12f73b.json": (
        "xcc_eventservice_subscriptions_expanded_lab.json"
    ),
    _R + "JobService.json": "xcc_jobservice_lab.json",
    _R + "JobService_Jobs.json": "xcc_jobservice_jobs_lab.json",
    _R + "JobService_Jobs__fd3a9f0.json": "xcc_jobservice_jobs_expanded_lab.json",
    _R + "LicenseService.json": "xcc_licenseservice_lab.json",
    _R + "LicenseService_Licenses.json": "xcc_licenseservice_licenses_lab.json",
    _R + "LicenseService_Licenses__fb27284.json": "xcc_licenseservice_licenses_expanded_lab.json",
    _R + "Managers.json": "xcc_managers_collection_lab.json",
    _R + "Managers_1.json": "xcc_manager_lab.json",
    _R + "Managers_1_EthernetInterfaces.json": "xcc_manager_ethernetinterfaces_lab.json",
    _R + "Managers_1_EthernetInterfaces_NIC.json": "xcc_manager_ethernetinterfaces_nic_lab.json",
    _R + "Managers_1_EthernetInterfaces__f89a8ea.json": (
        "xcc_manager_ethernetinterfaces_expanded_lab.json"
    ),
    _R + "Managers_1_HostInterfaces.json": "xcc_manager_hostinterfaces_lab.json",
    _R + "Managers_1_HostInterfaces__f05d94c.json": "xcc_manager_hostinterfaces_expanded_lab.json",
    _R + "Managers_1_NetworkProtocol.json": "xcc_manager_networkprotocol_lab.json",
    _R + "Managers_1_NetworkProtocol_HTTPS_Certificates.json": (
        "xcc_manager_networkprotocol_https_certificates_lab.json"
    ),
    _R + "Managers_1_NetworkProtocol_HTTPS_Certificates__fc61cc5.json": (
        "xcc_manager_networkprotocol_https_certificates_expanded_lab.json"
    ),
    _R + "Managers_1_NetworkProtocol_Oem_Lenovo_DNS.json": (
        "xcc_manager_networkprotocol_lenovo_dns_lab.json"
    ),
    _R + "Managers_1_NetworkProtocol_Oem_Lenovo_LDAPClient.json": (
        "xcc_manager_networkprotocol_lenovo_ldapclient_lab.json"
    ),
    _R + "Managers_1_NetworkProtocol_Oem_Lenovo_SMTPClient.json": (
        "xcc_manager_networkprotocol_lenovo_smtpclient_lab.json"
    ),
    _R + "Managers_1_NetworkProtocol_Oem_Lenovo_SNMP.json": (
        "xcc_manager_networkprotocol_lenovo_snmp_lab.json"
    ),
    _R + "Managers_1_Oem_Lenovo_Configuration.json": "xcc_manager_lenovo_configuration_lab.json",
    _R + "Managers_1_Oem_Lenovo_DateTimeService.json": (
        "xcc_manager_lenovo_datetimeservice_lab.json"
    ),
    _R + "Managers_1_Oem_Lenovo_FoD.json": "xcc_manager_lenovo_fod_lab.json",
    _R + "Managers_1_Oem_Lenovo_FoD_Keys.json": "xcc_manager_lenovo_fod_keys_lab.json",
    _R + "Managers_1_Oem_Lenovo_Recipients.json": "xcc_manager_lenovo_recipients_lab.json",
    _R + "Managers_1_Oem_Lenovo_Recipients__f634034.json": (
        "xcc_manager_lenovo_recipients_expanded_lab.json"
    ),
    _R + "Managers_1_Oem_Lenovo_RemoteControl.json": "xcc_manager_lenovo_remotecontrol_lab.json",
    _R + "Managers_1_Oem_Lenovo_RemoteControl_MountImages.json": (
        "xcc_manager_lenovo_remotecontrol_mountimages_lab.json"
    ),
    _R + "Managers_1_Oem_Lenovo_RemoteControl_Sessions.json": (
        "xcc_manager_lenovo_remotecontrol_sessions_lab.json"
    ),
    _R + "Managers_1_Oem_Lenovo_SecureKeyLifecycleService.json": (
        "xcc_manager_lenovo_securekeylifecycleservice_lab.json"
    ),
    _R + "Managers_1_Oem_Lenovo_SecureKeyLifecycleService_ClientCertificate.json": (
        "xcc_manager_lenovo_securekeylifecycleservice_clientcertificate_lab.json"
    ),
    _R + "Managers_1_Oem_Lenovo_SecureKeyLifecycleService_ServerCertificate.json": (
        "xcc_manager_lenovo_securekeylifecycleservice_servercertificate_lab.json"
    ),
    _R + "Managers_1_Oem_Lenovo_Security.json": "xcc_manager_lenovo_security_lab.json",
    _R + "Managers_1_Oem_Lenovo_ServerProfile.json": "xcc_manager_lenovo_serverprofile_lab.json",
    _R + "Managers_1_Oem_Lenovo_ServerProfile_Certificates.json": (
        "xcc_manager_lenovo_serverprofile_certificates_lab.json"
    ),
    _R + "Managers_1_Oem_Lenovo_SsoCertificates.json": (
        "xcc_manager_lenovo_ssocertificates_lab.json"
    ),
    _R + "Managers_1_Oem_Lenovo_SsoCertificates__f827509.json": (
        "xcc_manager_lenovo_ssocertificates_expanded_lab.json"
    ),
    _R + "Managers_1_Oem_Lenovo_Watchdogs.json": "xcc_manager_lenovo_watchdogs_lab.json",
    _R + "Managers_1_Oem_Lenovo_Watchdogs__f476772.json": (
        "xcc_manager_lenovo_watchdogs_expanded_lab.json"
    ),
    _R + "Managers_1_SerialInterfaces.json": "xcc_manager_serialinterfaces_lab.json",
    _R + "Managers_1_SerialInterfaces__f0464b0.json": (
        "xcc_manager_serialinterfaces_expanded_lab.json"
    ),
    _R + "Managers_1_VirtualMedia.json": "xcc_manager_virtualmedia_lab.json",
    _R + "Managers_1_VirtualMedia__f459621.json": "xcc_manager_virtualmedia_expanded_lab.json",
    _R + "Managers__f14b9c8.json": "xcc_managers_collection_expanded_lab.json",
    _R + "Registries.json": "xcc_registries_lab.json",
    _R + "Registries__f33d968.json": "xcc_registries_expanded_lab.json",
    _R + "Systems.json": "xcc_systems_collection_lab.json",
    _R + "Systems_1.json": "xcc_system_lab.json",
    _R + "Systems_1_Bios.json": "xcc_system_bios_lab.json",
    _R + "Systems_1_Bios_Pending.json": "xcc_system_bios_pending_lab.json",
    _R + "Systems_1_EthernetInterfaces.json": "xcc_system_ethernetinterfaces_lab.json",
    _R + "Systems_1_EthernetInterfaces__f03ed08.json": (
        "xcc_system_ethernetinterfaces_expanded_lab.json"
    ),
    _R + "Systems_1_LogServices.json": "xcc_system_logservices_lab.json",
    _R + "Systems_1_LogServices_ActiveLog_Entries.json": (
        "xcc_system_logservices_activelog_entries_lab.json"
    ),
    _R + "Systems_1_LogServices_DiagnosticLog_Entries.json": (
        "xcc_system_logservices_diagnosticlog_entries_lab.json"
    ),
    _R + "Systems_1_LogServices_MaintenanceLog_Entries.json": (
        "xcc_system_logservices_maintenancelog_entries_lab.json"
    ),
    _R + "Systems_1_LogServices_SaLog_Entries.json": (
        "xcc_system_logservices_salog_entries_lab.json"
    ),
    _R + "Systems_1_LogServices_StandardLog.json": "xcc_system_logservices_standardlog_lab.json",
    _R + "Systems_1_LogServices_StandardLog_Entries.json": (
        "xcc_system_logservices_standardlog_entries_lab.json"
    ),
    _R + "Systems_1_LogServices__faefcb8.json": "xcc_system_logservices_expanded_lab.json",
    _R + "Systems_1_Memory.json": "xcc_system_memory_lab.json",
    _R + "Systems_1_Memory__f67bb1a.json": "xcc_system_memory_expanded_lab.json",
    _R + "Systems_1_NetworkInterfaces.json": "xcc_system_networkinterfaces_lab.json",
    _R + "Systems_1_NetworkInterfaces__fa2913a.json": (
        "xcc_system_networkinterfaces_expanded_lab.json"
    ),
    _R + "Systems_1_Oem_Lenovo_BootSettings.json": "xcc_system_lenovo_bootsettings_lab.json",
    _R + "Systems_1_Oem_Lenovo_BootSettings__f360875.json": (
        "xcc_system_lenovo_bootsettings_expanded_lab.json"
    ),
    _R + "Systems_1_Oem_Lenovo_ScheduledPowerActions.json": (
        "xcc_system_lenovo_scheduledpoweractions_lab.json"
    ),
    _R + "Systems_1_Oem_Lenovo_ScheduledPowerActions__f7407e8.json": (
        "xcc_system_lenovo_scheduledpoweractions_expanded_lab.json"
    ),
    _R + "Systems_1_Processors.json": "xcc_system_processors_lab.json",
    _R + "Systems_1_Processors__f114b65.json": "xcc_system_processors_expanded_lab.json",
    _R + "Systems_1_SecureBoot.json": "xcc_system_secureboot_lab.json",
    _R + "Systems_1_Storage.json": "xcc_system_storage_lab.json",
    _R + "Systems_1_Storage_M_2_Slot_2_Drives_Slot_2.json": (
        "xcc_system_storage_m_2_slot_2_drives_slot_2_lab.json"
    ),
    _R + "Systems_1_Storage_M_2_Slot_2_StoragePools__ff8612e.json": (
        "xcc_system_storage_m_2_slot_2_storagepools_expanded_lab.json"
    ),
    _R + "Systems_1_Storage_M_2_Slot_2_Volumes__f0f5a6f.json": (
        "xcc_system_storage_m_2_slot_2_volumes_expanded_lab.json"
    ),
    _R + "Systems_1_Storage_M_2_Slot_3_Drives_Slot_3.json": (
        "xcc_system_storage_m_2_slot_3_drives_slot_3_lab.json"
    ),
    _R + "Systems_1_Storage_M_2_Slot_3_StoragePools__fcb1d0e.json": (
        "xcc_system_storage_m_2_slot_3_storagepools_expanded_lab.json"
    ),
    _R + "Systems_1_Storage_M_2_Slot_3_Volumes__f9054a5.json": (
        "xcc_system_storage_m_2_slot_3_volumes_expanded_lab.json"
    ),
    _R + "Systems_1_Storage_M_2_Slot_4_Drives_Slot_4.json": (
        "xcc_system_storage_m_2_slot_4_drives_slot_4_lab.json"
    ),
    _R + "Systems_1_Storage_M_2_Slot_4_StoragePools__f3bff6f.json": (
        "xcc_system_storage_m_2_slot_4_storagepools_expanded_lab.json"
    ),
    _R + "Systems_1_Storage_M_2_Slot_4_Volumes__f4d63df.json": (
        "xcc_system_storage_m_2_slot_4_volumes_expanded_lab.json"
    ),
    _R + "Systems_1_Storage_M_2_Slot_5_Drives_Slot_5.json": (
        "xcc_system_storage_m_2_slot_5_drives_slot_5_lab.json"
    ),
    _R + "Systems_1_Storage_M_2_Slot_5_StoragePools__f651818.json": (
        "xcc_system_storage_m_2_slot_5_storagepools_expanded_lab.json"
    ),
    _R + "Systems_1_Storage_M_2_Slot_5_Volumes__f299faf.json": (
        "xcc_system_storage_m_2_slot_5_volumes_expanded_lab.json"
    ),
    _R + "Systems_1_Storage__f98d110.json": "xcc_system_storage_expanded_lab.json",
    _R + "Systems_1_VirtualMedia.json": "xcc_system_virtualmedia_lab.json",
    _R + "Systems_1_VirtualMedia_RDOC1_Certificates__f5b0116.json": (
        "xcc_system_virtualmedia_rdoc1_certificates_expanded_lab.json"
    ),
    _R + "Systems_1_VirtualMedia_RDOC2_Certificates__f76c15f.json": (
        "xcc_system_virtualmedia_rdoc2_certificates_expanded_lab.json"
    ),
    _R + "Systems_1_VirtualMedia__f5722c9.json": "xcc_system_virtualmedia_expanded_lab.json",
    _R + "Systems__f7fe427.json": "xcc_systems_collection_expanded_lab.json",
    _R + "TaskService.json": "xcc_taskservice_lab.json",
    _R + "TaskService_Tasks.json": "xcc_taskservice_tasks_lab.json",
    _R + "TaskService_Tasks__ff5b330.json": "xcc_taskservice_tasks_expanded_lab.json",
    _R + "UpdateService.json": "xcc_updateservice_lab.json",
    _R + "UpdateService_FirmwareInventory.json": "xcc_updateservice_firmwareinventory_lab.json",
    _R + "UpdateService_FirmwareInventory__fac59e1.json": (
        "xcc_updateservice_firmwareinventory_expanded_lab.json"
    ),
}

# The texts a device prints its own users in (-> netops).
_USER_SOURCES = (
    "ssh__show_running_config.txt",
    "ssh__show_startup_config.txt",
    "ssh__show_logging.txt",
)
# A BMC harvest: the log-entry pages first, then every other payload (an
# expanded log service, the trace); Lenovo prints account names in each
# entry's Message (-> user-lab-<n>, one per account).
_LOG_USER_SOURCES = ("get__redfish_v1_*Entries*.json", "*.json")
_USER_PATTERNS = (
    re.compile(r"^username (\S+)", re.M),
    re.compile(r"\[user: ([^\]\s]+)\]"),
    re.compile(r"Last configuration change at .* by (\S+)"),
    re.compile(r"NVRAM configuration last updated at .* by (\S+)"),
) + sanitize_trace.LOG_USER_PATTERNS


def fixture_name(name, suffix=None):
    """The fixture name for a variant: ``_lab`` replaced by the suffix, or the suffix inserted."""
    if not suffix:
        return name
    if "_lab" in name:
        return name.replace("_lab", suffix, 1)
    stem, dot, ext = name.rpartition(".")
    return "%s%s%s%s" % (stem, suffix, dot, ext) if dot else name + suffix


_ACCOUNT = re.compile(r"^[A-Za-z][\w.@-]*$")


def discover_users(texts):
    """Sorted user names a device names in its own config and log texts.

    Only account-shaped tokens count: a redaction marker the transport already
    put in a login line (``[user: ***scrubbed***]``) is not a user, and
    neither is an actor a BMC names in its own messages (``by user system``).
    """
    found = set()
    for text in texts:
        for pattern in _USER_PATTERNS:
            for name in pattern.findall(text):
                if (
                    pattern in sanitize_trace.LOG_USER_PATTERNS
                    and name.lower() in sanitize_trace.SYSTEM_ACTORS
                ):
                    continue
                found.add(name)
    return sorted(name for name in found if _ACCOUNT.match(name))


def discover_log_users(payloads):
    """Sorted account names the ``Message`` of any log entry in parsed JSON payloads carries."""
    found = set()
    stack = list(payloads)
    while stack:
        node = stack.pop()
        if isinstance(node, dict):
            for key, value in node.items():
                if key == "Message" and isinstance(value, str):
                    found.update(sanitize_trace.log_user_names(value))
                else:
                    stack.append(value)
        elif isinstance(node, list):
            stack.extend(node)
    return sorted(found)


def harvest_json(src):
    """Every ``*.json`` of a harvest, log-entry pages first, each once, in a stable order."""
    paths, seen = [], set()
    for pattern in _LOG_USER_SOURCES:
        for path in sorted(src.glob(pattern)):
            if path not in seen:
                seen.add(path)
                paths.append(path)
    return paths


def apply_literals(text, literals):
    """Plain substring rewrites, longest first, after sanitizing."""
    for old in sorted(literals, key=len, reverse=True):
        text = text.replace(old, literals[old])
    return text


def real_values(mapping):
    """Every real value a mapping knows, in the spellings a payload may carry (substrings)."""
    values = {host for host in mapping.get("hosts", {}) if not sanitize_trace.is_word_host(host)}
    values |= set(mapping.get("serials", {})) | set(mapping.get("assets", {}))
    values |= set(mapping.get("uuids", {}))
    values |= set(mapping.get("ips", {})) | set(mapping.get("ipv6", {}))
    values |= set(mapping.get("literals", {}))
    for digits in mapping.get("macs", {}):
        values.add(digits)
        values.add(".".join(digits[i : i + 4] for i in (0, 4, 8)))
        values.add(":".join(digits[i : i + 2] for i in range(0, 12, 2)))
        values.add("-".join(digits[i : i + 2] for i in range(0, 12, 2)))
    return {value for value in values if value}


def real_tokens(mapping, extra=()):
    """Whole-token patterns for what the mapping knows as words: people and word-like hosts."""
    words = (set(mapping.get("users", {})) | set(extra)) - sanitize_trace.ROLE_WORDS
    words |= {host for host in mapping.get("hosts", {}) if sanitize_trace.is_word_host(host)}
    return [re.compile(sanitize_trace._TOKEN_EDGE % re.escape(word)) for word in words if word]


def leak_hits(text, values, tokens=()):
    """How many known real values (substring, case-insensitive) or whole tokens the text carries."""
    lower = text.lower()
    hits = sum(1 for value in values if value.lower() in lower)
    hits += sum(1 for pattern in tokens if pattern.search(text))
    return hits


def _pairs(items, what):
    out = {}
    for item in items or ():
        if "=" not in item:
            raise SystemExit("--%s expects REAL=FAKE, got %r" % (what, item))
        real, fake = item.split("=", 1)
        out[real] = fake
    return out


def main(argv=None):
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--payloads", help="one harvest directory (OUT/TAG of harvest_live.py)")
    parser.add_argument("--map", help="mapping JSON, read and updated (outside the repository)")
    parser.add_argument("--out", help="fixture directory, normally tests/fixtures")
    parser.add_argument("--env", help="key=value credential file; its values are scrubbed")
    parser.add_argument("--host", action="append", default=[], help="REAL=FAKE hostname")
    parser.add_argument("--user", action="append", default=[], help="user name -> netops")
    parser.add_argument("--net", action="append", default=[], help="SRC/24=DST/24")
    parser.add_argument("--replace", action="append", default=[], help="OLD=NEW literal")
    parser.add_argument("--suffix", help="fixture-name suffix for a variant capture")
    parser.add_argument("--only", help="comma-separated fixture names (before --suffix)")
    parser.add_argument("--salt", default="nautobot-testsuite", help="hash salt for inventions")
    parser.add_argument("--list", action="store_true", help="print the table and exit")
    args = parser.parse_args(argv)

    if args.list:
        for source, name in TABLE.items():
            print("%-100s -> %s" % (source, fixture_name(name, args.suffix)))
        return 0
    if not (args.payloads and args.map and args.out):
        parser.error("--payloads, --map and --out are required")
    src = pathlib.Path(args.payloads)
    dst = pathlib.Path(args.out)
    map_path = pathlib.Path(args.map)
    mapping = json.loads(map_path.read_text(encoding="utf-8")) if map_path.exists() else {}
    literals = dict(mapping.get("literals", {}))
    literals.update(_pairs(args.replace, "replace"))
    only = None
    if args.only:
        only = set(args.only.split(","))
        unknown = only - set(TABLE.values())
        if unknown:
            parser.error("--only names no fixture: %s" % ", ".join(sorted(unknown)))

    texts = [
        (src / name).read_text(encoding="utf-8", errors="replace")
        for name in _USER_SOURCES
        if (src / name).exists()
    ]
    users = sorted(set(discover_users(texts)) | set(args.user))
    payloads = []
    for path in harvest_json(src):
        try:
            payloads.append(json.loads(path.read_text(encoding="utf-8", errors="replace")))
        except ValueError:
            continue
    secrets = sanitize_trace.read_env(args.env) if args.env else {}
    people = sorted(set(discover_log_users(payloads)) - set(users) - set(secrets.values()))
    sanitizer = sanitize_trace.Sanitizer(
        hosts=_pairs(args.host, "host"),
        users=users,
        people=people,
        nets=_pairs(args.net, "net"),
        secrets=secrets,
        salt=args.salt,
        mapping={key: value for key, value in mapping.items() if key != "literals"},
    )
    # learn from every payload before sanitizing the first: a serial a log line
    # or a boot entry mentions may only be named by a leaf in another file
    for payload in payloads:
        sanitizer.learn(payload)
    written, missing = [], []
    for source, name in TABLE.items():
        if only is not None and name not in only:
            continue
        path = src / source
        if not path.exists():
            missing.append(source)
            continue
        target = dst / fixture_name(name, args.suffix)
        target.write_text(apply_literals(sanitizer.file(path), literals), encoding="utf-8")
        written.append(target.name)
    mapping = sanitizer.export_map()
    mapping["literals"] = literals
    map_path.write_text(json.dumps(mapping, indent=1, sort_keys=True) + "\n", encoding="utf-8")

    # The leak scan: counts only, never a value. Credentials, user names and
    # word-like hosts count as whole tokens (a user name that is also a leaf
    # prefix is not leaked by the leaf; "xcc" is not leaked by "XCC Web").
    values = real_values(mapping)
    tokens = real_tokens(mapping, set(secrets.values()) | set(users) | set(people))
    leaks = 0
    for name in written:
        hits = leak_hits((dst / name).read_text(encoding="utf-8"), values, tokens)
        if hits:
            leaks += 1
            print("LEAK in %s: %d real value(s)" % (name, hits))
    for source in missing:
        print("MISSING %s" % source)
    print(
        "wrote %d fixture(s) to %s; %d user name(s) mapped; %d missing payload(s); "
        "%d file(s) with leaks"
        % (len(written), dst, len(set(users) | set(people)), len(missing), leaks)
    )
    for name in written:
        print("  " + name)
    return 1 if leaks else 0


if __name__ == "__main__":
    sys.exit(main())
