"""tools/sanitize_trace.py: deterministic, mapping-preserving fixture sanitizer.

Invented inputs only (invented hostnames, serials, MACs, UUIDs, account names
and private ranges that name no site; documentation ranges as targets); the
only credential file read is one a test writes itself. The tool is
stdlib-only, so the battery locks in the rules a harvested fixture depends on:
same real value -> same invention, shape preserved, group MACs and netmasks
untouched, credentials never echoed; for Redfish payloads, the key-aware rules
(serials of any shape, UUIDs, hostnames, people, key material) and the learn
pass that lets a serial named in one file be replaced in every other.
"""

import contextlib
import importlib.util
import io
import json
import pathlib
import re
import tempfile
import unittest

_TOOL = pathlib.Path(__file__).resolve().parents[1] / "tools" / "sanitize_trace.py"
_spec = importlib.util.spec_from_file_location("sanitize_trace", _TOOL)
sanitize_trace = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(sanitize_trace)

Sanitizer = sanitize_trace.Sanitizer


def _make(**overrides):
    kwargs = dict(
        hosts={"sw-real-01": "sw-lab-1", "AP0000.1111.2222": "ap-lab-1"},
        users=["someone"],
        nets={"10.0.0.0/24": "192.0.2.0/24", "10.0.1.0/24": "198.51.100.0/24"},
        secrets={"user": "labadmin", "pass": "labadmin", "enable": "hunter2"},
    )
    kwargs.update(overrides)
    return Sanitizer(**kwargs)


class TestCredentialsAndNames(unittest.TestCase):
    def test_credentials_are_whole_tokens_and_never_survive(self):
        out = _make().text("by labadmin\nadmin-status (labadmin) enable hunter2")
        self.assertNotIn("labadmin", out)
        self.assertNotIn("hunter2", out)
        self.assertEqual(out, "by netops\nadmin-status (netops) enable REDACTED")
        # glued to a hyphen or a letter it is another token, not the credential
        self.assertEqual(_make().text("labadmin-x sublabadmin"), "labadmin-x sublabadmin")

    def test_hostnames_case_insensitive_and_embedded_mac_ids_map_whole(self):
        san = _make()
        self.assertEqual(
            san.text("hostname SW-REAL-01; id AP0000.1111.2222"), "hostname sw-lab-1; id ap-lab-1"
        )

    def test_user_names_become_netops_as_whole_tokens(self):
        self.assertEqual(_make().text("someone someone-else"), "netops someone-else")


class TestSerialsAndMacs(unittest.TestCase):
    def test_serial_keeps_shape_and_prefix_and_is_deterministic(self):
        a, b = _make(), _make()
        fake = a.text("SN: ABC1234D5EF")
        self.assertEqual(fake, b.text("SN: ABC1234D5EF"))
        self.assertRegex(fake, r"^SN: ABC\d{4}[A-Z0-9]{4}$")
        self.assertNotIn("ABC1234D5EF", fake)
        self.assertNotIn("1234D5EF", fake)

    def test_distinct_serials_stay_distinct_and_product_ids_are_left_alone(self):
        san = _make()
        out = san.text("ABC1234D5EF XYZ9876K1LM ABC5555ZZ99 AIR-CAP3702I-B-K9 C9300-48UXM")
        fakes = out.split()
        self.assertEqual(len(set(fakes[:3])), 3)
        self.assertEqual(fakes[3:], ["AIR-CAP3702I-B-K9", "C9300-48UXM"])

    def test_mac_spelling_case_and_low_bits_are_preserved(self):
        san = _make()
        dotted = san.text("00ab.cdef.1234")
        colon = san.text("00:ab:cd:ef:12:34")
        upper = san.text("00AB.CDEF.1234")
        self.assertRegex(dotted, r"^[0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4}$")
        self.assertRegex(colon, r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$")
        self.assertEqual(upper, dotted.upper())
        self.assertEqual(colon.replace(":", ""), dotted.replace(".", ""))
        self.assertNotEqual(dotted, "00ab.cdef.1234")
        local = san.text("02:00:00:11:22:33")
        self.assertEqual(int(local[:2], 16) & 0x03, 0x02)

    def test_group_addresses_are_not_identifying_and_stay(self):
        san = _make()
        for mac in ("0100.0ccc.cccc", "0180.c200.0000", "ffff.ffff.ffff", "01:00:5e:00:00:01"):
            self.assertEqual(san.text(mac), mac)
        # the all-zero MAC means "none" (an LACP member without a partner)
        for mac in ("00:00:00:00:00:00", "0000.0000.0000"):
            self.assertEqual(san.text(mac), mac)

    def test_same_mac_maps_the_same_across_payloads_and_a_second_pass_is_a_no_op(self):
        san = _make()
        first = san.json({"cdp": {"mac": "0000.1111.2222"}})["cdp"]["mac"]
        second = san.json({"matm": [{"mac": "00:00:11:11:22:22"}]})["matm"][0]["mac"]
        self.assertEqual(first.replace(".", ""), second.replace(":", ""))
        self.assertEqual(san.text(first), first)


class TestAddresses(unittest.TestCase):
    def test_explicit_nets_keep_the_host_octet(self):
        san = _make()
        self.assertEqual(san.text("10.0.0.148/23 via 10.0.1.7"), "192.0.2.148/23 via 198.51.100.7")

    def test_other_real_ranges_land_in_benchmark_space_consistently(self):
        san = _make()
        first = san.text("10.3.0.2")
        self.assertTrue(first.startswith("198.18."))
        self.assertEqual(san.text("10.3.0.9")[: first.rfind(".")], first[: first.rfind(".")])
        self.assertEqual(first, _make().text("10.3.0.2"))

    def test_masks_wildcards_loopback_multicast_and_doc_ranges_are_untouched(self):
        san = _make()
        line = "255.255.254.0 0.0.0.255 0.0.0.0 127.0.0.1 224.0.0.10 255.255.255.255 192.0.2.5"
        self.assertEqual(san.text(line), line)

    def test_version_strings_are_not_addresses(self):
        self.assertEqual(
            _make().text("Version 17.15.6 and 1.2.3.4.5"), "Version 17.15.6 and 1.2.3.4.5"
        )


class TestIPv6(unittest.TestCase):
    def test_eui64_identifier_is_rebuilt_from_the_invented_mac(self):
        san = _make()
        mac = san.text("00:00:11:11:22:22").split(":")
        link_local = san.text("fe80::200:11ff:fe11:2222")
        # universal/local bit flipped back in, ff:fe in the middle, the MAC's low three octets
        first = "%x" % ((int(mac[0], 16) ^ 0x02) << 8 | int(mac[1], 16))
        self.assertEqual(
            link_local, "fe80::%s:%sff:fe%s:%s%s" % (first, mac[2], mac[3], mac[4], mac[5])
        )
        self.assertNotIn("11ff:fe11", link_local)
        # the same address in the CDP model, the FIB and a CLI listing maps the same
        self.assertEqual(san.text("FE80::200:11FF:FE11:2222/128"), link_local.upper() + "/128")
        self.assertEqual(san.text("fe80::200:11ff:fe11:2222%Vlan2"), link_local + "%Vlan2")

    def test_global_and_unique_local_prefixes_land_in_documentation_space(self):
        san = _make()
        static = san.text("2001:4860:4860::8888")
        self.assertTrue(static.startswith("2001:db8:"))
        self.assertTrue(static.endswith("::8888"))  # a static identifier is kept
        self.assertEqual(static, _make().text("2001:4860:4860::8888"))
        ula = san.text("fd00:1:2:3:200:11ff:fe11:2222")
        self.assertTrue(ula.startswith("2001:db8:"))
        self.assertNotIn("11ff:fe11", ula)
        self.assertNotEqual(ula[: ula.rfind(":", 0, 20)], static[: static.rfind(":", 0, 20)])

    def test_unspecified_loopback_multicast_link_local_prefix_and_doc_range_stay(self):
        san = _make()
        line = ":: ::1 ff02::1 ff00::/8 fe80::/10 fe80::1 2001:db8::5 T17:33:06.363+00:00"
        self.assertEqual(san.text(line), line)
        self.assertEqual(san.map["ipv6"], {})

    def test_colon_macs_clocks_and_fingerprints_are_not_ipv6(self):
        san = _make()
        self.assertRegex(san.text("00:11:22:33:44:55"), r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$")
        self.assertNotEqual(san.text("00:11:22:33:44:55"), "00:11:22:33:44:55")
        self.assertEqual(san.text("at 17:33:06 UTC"), "at 17:33:06 UTC")
        self.assertEqual(
            san.text("1A:2B:3C:4D:5E:6F:70:81:92:A3:B4:C5:D6:E7:F8:09:1A:2B:3C:4D"), "<hex:20>"
        )


class TestCertificateMaterial(unittest.TestCase):
    def test_pem_fingerprints_hex_dumps_and_runs_become_placeholders(self):
        san = _make()
        pem = (
            "-----BEGIN CERTIFICATE-----\n"
            "MIIBszCCARygAwIBAgIBATANBgkqhkiG9w0BAQUFADAWMRQw\n"
            "-----END CERTIFICATE-----"
        )
        self.assertRegex(san.text(pem), r"^<pem:\d+>$")
        digest = (
            "MD5 digest: 0x77 0xF0 0x98 0x6A 0x95 0xFC 0xBC 0xD3\n"
            "        0xAD 0x94 0x65 0x9C 0x19 0xCC 0x92 0x18\nnext line"
        )
        self.assertEqual(san.text(digest), "MD5 digest: <hex:16>\nnext line")
        fingerprint = "1A:2B:3C:4D:5E:6F:70:81:92:A3:B4:C5:D6:E7:F8:09:1A:2B:3C:4D"
        self.assertEqual(san.text(fingerprint), "<hex:20>")
        self.assertEqual(
            san.text("3082010A0282010100C4F1D2E3A4B5C6D7E8F90A1B2C3D4E5F6071"), "<hex:54>"
        )

    def test_self_signed_names_are_renumbered_consistently(self):
        san = _make()
        out = san.text("TP-self-signed-1234567890 IOS-Self-Signed-Certificate-1234567890")
        a, b = out.split()
        self.assertRegex(a, r"^TP-self-signed-\d{10}$")
        self.assertEqual(a.rsplit("-", 1)[1], b.rsplit("-", 1)[1])
        self.assertNotIn("1234567890", out)


class TestJsonAndMapping(unittest.TestCase):
    def test_json_walk_covers_keys_and_values_and_leaves_numbers_alone(self):
        out = _make().json({"0000.1111.2222": {"ip": "10.0.0.148", "count": 5, "flag": True}})
        ((key, value),) = out.items()
        self.assertNotEqual(key, "0000.1111.2222")
        self.assertEqual(value, {"ip": "192.0.2.148", "count": 5, "flag": True})

    def test_integer_router_id_leaves_are_addresses(self):
        san = _make()
        out = san.json({"router-id": 167772308, "as-num": 1, "router-id-text": 167772308})
        # 10.0.0.148 in host order -> 192.0.2.148 in host order; other ints untouched
        self.assertEqual(out["router-id"], 3221226132)
        self.assertEqual(out["as-num"], 1)
        self.assertEqual(out["router-id-text"], 167772308)
        self.assertEqual(san.json({"router-id": "10.0.0.148"})["router-id"], "192.0.2.148")

    def test_mapping_round_trips_without_credentials(self):
        san = _make()
        san.text("sw-real-01 ABC1234D5EF 0011.2233.4455 10.0.0.148 10.3.0.2")
        dumped = json.loads(json.dumps(san.map))
        self.assertEqual(set(dumped), {"hosts", "users", "serials", "macs", "nets", "ips", "ipv6"})
        self.assertNotIn("labadmin", json.dumps(dumped))
        again = Sanitizer(mapping=dumped)
        self.assertEqual(
            again.text("ABC1234D5EF 0011.2233.4455 10.0.0.148 10.3.0.2"),
            san.text("ABC1234D5EF 0011.2233.4455 10.0.0.148 10.3.0.2"),
        )
        san.text("fe80::211:22ff:fe33:4455")
        again = Sanitizer(mapping=json.loads(json.dumps(san.map)))
        self.assertEqual(
            again.text("fe80::211:22ff:fe33:4455"), san.text("fe80::211:22ff:fe33:4455")
        )


# --- Redfish payloads (BMC harvests) ---------------------------------------------

UUID_A = "4a1b2c3d-1111-4222-8333-0023456789ab"
SERIAL_A = "Z1AB2345"  # a system serial of the BMC's shape (letter, digits, letter ...)
DRIVE_SERIAL = "240801A00017"  # an all-hex 12-character drive serial: not a MAC
_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")


def _pattern(value):
    return re.sub(r"[0-9]", "9", re.sub(r"[a-z]", "a", re.sub(r"[A-Z]", "A", value)))


def _bmc(**overrides):
    kwargs = dict(
        secrets={"username": "capture_ro", "password": "pw-Secret-1", "host": "10.20.30.40"}
    )
    kwargs.update(overrides)
    return Sanitizer(**kwargs)


class TestUuids(unittest.TestCase):
    def test_uuid_keeps_version_variant_and_case_and_is_deterministic(self):
        san = _bmc()
        fake = san.text(UUID_A)
        self.assertRegex(fake, _UUID_RE)
        self.assertNotEqual(fake, UUID_A)
        self.assertEqual(fake[14], "4")  # the version nibble
        self.assertIn(fake[19], "89ab")  # RFC 4122 variant: 10xx
        self.assertEqual(san.text(UUID_A.upper()), fake.upper())  # the same UUID, its own case
        self.assertEqual(san.json({"UUID": UUID_A})["UUID"], fake)
        self.assertEqual(_bmc().text(UUID_A), fake)  # deterministic across runs
        self.assertNotEqual(san.text("4a1b2c3d-1111-1222-c333-0023456789ab")[14], "4")
        self.assertIn(san.text("4a1b2c3d-1111-1222-c333-0023456789ab")[19], "cd")  # 110x kept
        self.assertEqual(san.text(fake), fake)  # a second pass is a no-op

    def test_uuid_tail_is_never_taken_for_a_bare_mac(self):
        san = _bmc()
        out = san.text("UUID %s MAC 0023456789ab" % UUID_A)
        uuid, mac = out.split()[1], out.split()[3]
        self.assertRegex(uuid, _UUID_RE)
        self.assertNotEqual(uuid[-12:], mac)  # the tail is the UUID's invention, not the MAC's
        self.assertEqual(san.map["macs"], {"0023456789ab": mac})
        self.assertEqual(san.map["uuids"], {UUID_A: uuid})

    def test_nil_and_glued_uuids_are_not_rewritten_as_uuids(self):
        san = _bmc()
        nil = "00000000-0000-0000-0000-000000000000"
        self.assertEqual(san.text(nil), nil)
        # a software-ID tag names a licence product: the UUID rule leaves it to the
        # older rules, exactly as before (the IOS-XE licence fixture depends on it)
        tag = "regid.2017-05.com.example.widget_essentials,1.0_" + UUID_A
        self.assertTrue(san.text(tag).startswith(tag[:-12]))
        self.assertNotIn("uuids", san.map)  # the category appears only when used


class TestKeyAwareSerials(unittest.TestCase):
    def test_serial_leaves_of_any_shape_keep_their_pattern(self):
        san = _bmc()
        payload = {
            "SerialNumber": SERIAL_A,
            "Oem": {"Lenovo": {"SystemBoardSerialNumber": "Q7ZT0ABC1X2"}},
            "FRUs": [{"FRUSerialNumber": "k2x8m3p9q4"}, {"FRUSerialNumber": ""}],
            "Drive": {"SerialNumber": DRIVE_SERIAL},
        }
        out = san.json(payload)
        pairs = (
            (payload["SerialNumber"], out["SerialNumber"]),
            ("Q7ZT0ABC1X2", out["Oem"]["Lenovo"]["SystemBoardSerialNumber"]),
            ("k2x8m3p9q4", out["FRUs"][0]["FRUSerialNumber"]),
            (DRIVE_SERIAL, out["Drive"]["SerialNumber"]),
        )
        for real, fake in pairs:
            self.assertNotEqual(real, fake)
            self.assertEqual(_pattern(real), _pattern(fake))
        self.assertEqual(out["FRUs"][1]["FRUSerialNumber"], "")
        self.assertEqual(len({fake for _real, fake in pairs}), 4)

    def test_placeholders_are_not_serials(self):
        san = _bmc()
        for value in ("N/A", "", None, "Not Specified", "0000000000", "System Serial Number"):
            self.assertEqual(san.json({"SerialNumber": value})["SerialNumber"], value)
        self.assertEqual(san.map["serials"], {})

    def test_a_learned_serial_is_replaced_in_text_that_comes_before_its_leaf(self):
        san = _bmc()
        san.learn({"@odata.id": "/redfish/v1/Systems/1", "SerialNumber": SERIAL_A})
        texts = san.json(
            {
                "Message": "Management Controller SN#   %s reset was initiated." % SERIAL_A,
                "CommonName": "XCC-7X99-%s" % SERIAL_A,
                "Name": "SN#   %s" % SERIAL_A,
            }
        )
        fake = san.json({"SerialNumber": SERIAL_A})["SerialNumber"]
        self.assertNotEqual(fake, SERIAL_A)
        self.assertEqual(texts["CommonName"], "XCC-7X99-" + fake)
        self.assertEqual(
            texts["Message"], "Management Controller SN#   %s reset was initiated." % fake
        )
        self.assertEqual(texts["Name"], "SN#   " + fake)

    def test_sn_tokens_are_serials_even_without_a_leaf(self):
        san = _bmc()
        out = san.text(
            "M2 Left Card(SN: K9LM12345678X) is added. DIMM(SN: 80CE0000ABCD1234) in slot 1"
        )
        self.assertNotIn("K9LM12345678X", out)
        self.assertNotIn("80CE0000ABCD1234", out)  # 16 hex digits, still a serial, not <hex:16>
        self.assertRegex(
            out, r"^M2 Left Card\(SN: [A-Z]\d[A-Z]{2}\d{8}[A-Z]\) is added\. DIMM\(SN: "
        )
        self.assertEqual(len(san.map["serials"]), 2)
        # "SN:" with nothing after it on its line names nothing (an IOS inventory FAN row)
        self.assertEqual(san.text("SN:\nPID: C9300-48UXM"), "SN:\nPID: C9300-48UXM")
        learner = _bmc()
        learner.learn("PID: X , SN: K9LM12345678X\n")
        self.assertIn("K9LM12345678X", learner.map["serials"])

    def test_an_all_hex_serial_in_text_is_the_serial_not_a_mac(self):
        san = _bmc()
        san.learn({"SerialNumber": DRIVE_SERIAL, "SKU": DRIVE_SERIAL})
        out = san.json({"SerialNumber": DRIVE_SERIAL, "SKU": DRIVE_SERIAL})
        self.assertEqual(out["SKU"], out["SerialNumber"])
        self.assertRegex(out["SKU"], r"^\d{6}[A-Z]\d{5}$")
        self.assertEqual(san.map["macs"], {})

    def test_a_short_serial_is_invented_where_it_stands_only(self):
        san = _bmc()
        out = san.json({"SerialNumber": "A12", "Note": "A12 A12"})
        self.assertRegex(out["SerialNumber"], r"^[A-Z]\d\d$")
        self.assertEqual(out["Note"], "A12 A12")  # too short to search for in text
        self.assertEqual(san.map["serials"], {})

    def test_a_three_letter_prefix_is_kept_only_where_it_leads(self):
        san = _bmc()
        self.assertTrue(san.json({"SerialNumber": "PHY12345678"})["SerialNumber"].startswith("PHY"))
        fake = san.json({"SerialNumber": SERIAL_A})["SerialNumber"]
        self.assertEqual(_pattern(fake), _pattern(SERIAL_A))


class TestBootEntries(unittest.TestCase):
    ENTRY = "SATA: ACME-SSD240X2   20XY123Z45678 SSD, GPT (%s)" % UUID_A.upper()

    def test_a_boot_entry_serial_is_learned_and_its_model_kept(self):
        san = _bmc()
        # the boot order file is read before the drive that names the model
        san.learn({"BootOrderCurrent": [self.ENTRY], "BootOrderSupported": [self.ENTRY]})
        san.learn({"Model": "ACME-SSD240X2", "SerialNumber": "S0X"})
        out = san.json({"BootOrderCurrent": [self.ENTRY], "Name": "20XY123Z45678"})
        entry = out["BootOrderCurrent"][0]
        self.assertTrue(entry.startswith("SATA: ACME-SSD240X2   "))  # the model stays
        self.assertNotIn("20XY123Z45678", entry)
        self.assertNotIn(UUID_A.upper(), entry)
        self.assertRegex(entry.split()[2], r"^\d\d[A-Z]{2}\d{3}[A-Z]\d{5}$")
        self.assertEqual(out["Name"], entry.split()[2])  # the same serial wherever it stands

    def test_a_dmtf_boot_option_display_name_is_a_boot_entry(self):
        san = _bmc()
        option = {"BootOptionReference": "Boot0001", "DisplayName": self.ENTRY}
        san.learn({"Model": "ACME-SSD240X2"})
        san.learn(option)
        self.assertNotIn("20XY123Z45678", san.json(option)["DisplayName"])


class TestIdentifiersByKey(unittest.TestCase):
    def test_asset_tags_and_phone_numbers_keep_their_pattern(self):
        san = _bmc()
        san.learn({"AssetTag": "IT-004711"})
        out = san.json(
            {"AssetTag": "IT-004711", "Note": "tag IT-004711", "PhoneNumber": "+1 919 555 0142"}
        )
        self.assertRegex(out["AssetTag"], r"^[A-Z]{2}-\d{6}$")
        self.assertNotEqual(out["AssetTag"], "IT-004711")
        self.assertEqual(out["Note"], "tag " + out["AssetTag"])
        self.assertRegex(out["PhoneNumber"], r"^\+\d \d{3} \d{3} \d{4}$")
        self.assertNotIn("919 555 0142", json.dumps(out))
        self.assertEqual(san.json({"AssetTag": ""}), {"AssetTag": ""})

    def test_entitlements_and_licence_identifiers_become_placeholders(self):
        out = _bmc().json(
            {
                "EntitlementId": "ENT-1234-5678",
                "Identifier": [{"IdentifierType": "MachineTypeSerial", "Value": "7X99Z1AB2345"}],
                "Keys": [{"Identifier": "7X99Z1AB2345"}, {"Identifier": ""}],
            }
        )
        self.assertEqual(out["EntitlementId"], "<id:13>")
        self.assertEqual(
            out["Identifier"], [{"IdentifierType": "MachineTypeSerial", "Value": "<id:12>"}]
        )
        self.assertEqual(out["Keys"], [{"Identifier": "<id:12>"}, {"Identifier": ""}])

    def test_fingerprints_and_the_snmp_engine_id_become_hex_placeholders(self):
        fingerprint = ":".join(["AB"] * 20)
        out = _bmc().json(
            {
                "Fingerprint": fingerprint,
                "EngineId": {
                    "ArchitectureId": "80 00 1f 88 04 62 6d 63",
                    "PrivateEnterpriseId": "80 00 1f 88",
                },
            }
        )
        self.assertEqual(out["Fingerprint"], "<hex:20>")
        # eight bytes: below the 16-byte run the text rule needs, caught by its key
        self.assertEqual(out["EngineId"]["ArchitectureId"], "<hex:8>")
        self.assertEqual(out["EngineId"]["PrivateEnterpriseId"], "80 00 1f 88")


class TestHostnamesByKey(unittest.TestCase):
    def test_hostname_and_fqdn_leaves_become_inventions_and_text_follows(self):
        san = _bmc()
        san.learn({"HostName": "bmc-rack7-a", "FQDN": "bmc-rack7-a.plant.acme-corp.net"})
        out = san.json(
            {
                "HostName": "bmc-rack7-a",
                "FQDN": "bmc-rack7-a.plant.acme-corp.net",
                "Message": "ENET[CIM:ep1] IP-Cfg:HstName=BMC-RACK7-A, IP@=10.20.30.40 .",
                "DNS": "plant.acme-corp.net",
            }
        )
        self.assertEqual(out["HostName"], "bmc-lab-1")
        self.assertEqual(out["FQDN"], "bmc-lab-1.lab.example")
        self.assertTrue(
            out["Message"].startswith("ENET[CIM:ep1] IP-Cfg:HstName=bmc-lab-1, IP@=198.18.")
        )
        self.assertEqual(out["DNS"], "lab.example")
        self.assertEqual(
            san.json({"DomainName": "plant.acme-corp.net"}), {"DomainName": "lab.example"}
        )

    def test_a_host_pair_names_the_leaf(self):
        san = _bmc(hosts={"bmc-rack7-a": "bmc-lab-9"})
        self.assertEqual(san.json({"HostName": "BMC-RACK7-A"})["HostName"], "bmc-lab-9")

    def test_a_vendor_default_hostname_is_a_whole_token_in_its_own_spelling(self):
        san = _bmc()
        out = san.json(
            {
                "HostName": "xcc",
                "Message": "Hostname set to xcc by user capture_ro.",
                "Name": "XCC Web",
                "File": "lnvgy_fw_xcc_abc12zz.uxz",
            }
        )
        self.assertEqual(out["HostName"], "bmc-lab-1")
        self.assertEqual(out["Message"], "Hostname set to bmc-lab-1 by user netops.")
        self.assertEqual(out["Name"], "XCC Web")
        self.assertEqual(out["File"], "lnvgy_fw_xcc_abc12zz.uxz")

    def test_address_and_no_name_values_stay_what_they_are(self):
        san = _bmc()
        self.assertTrue(san.json({"HostName": "10.20.30.41"})["HostName"].startswith("198.18."))
        for value in ("localhost", "", None):
            self.assertEqual(san.json({"HostName": value})["HostName"], value)


class TestSecretsByKey(unittest.TestCase):
    PEM = (
        "-----BEGIN CERTIFICATE-----\n"
        "MIIBszCCARygAwIBAgIBATANBgkqhkiG9w0BAQUFADAW\n"
        "-----END CERTIFICATE-----\n"
    )

    def test_exact_name_secrets_are_redacted_with_their_shape_kept(self):
        out = _bmc().json(
            {
                "Password": "hunter22",
                "passphrase": "x y z",
                "ClientSecret": "abc",
                "PrivateKey": "k",
                "AuthenticationKey": "ak",
                "EncryptionKey": None,
                "CommunityNames": [None, "public-ro", ""],
                "TrapCommunity": "traps",
                "LicenseString": "L",
                "Bytes": "QkFTRTY0",
                "SSHPublicKey": [None, "ssh-ed25519 AAAAC3Nz", None, None],
                "SED_AK": "s",
                "BMU_Credential": "b",
                "OAuthServiceSigningKeys": "jwks",
                "BindPassword": "bp",
                "CertificateString": self.PEM,
                "Scrubbed": {"Password": "***scrubbed***"},
            }
        )
        redacted = "REDACTED"
        for key in ("Password", "passphrase", "ClientSecret", "PrivateKey", "AuthenticationKey"):
            self.assertEqual(out[key], redacted, key)
        for key in ("TrapCommunity", "LicenseString", "Bytes", "SED_AK", "BMU_Credential"):
            self.assertEqual(out[key], redacted, key)
        self.assertEqual(out["OAuthServiceSigningKeys"], redacted)
        self.assertEqual(out["BindPassword"], redacted)
        self.assertIsNone(out["EncryptionKey"])
        self.assertEqual(out["CommunityNames"], [None, redacted, ""])
        self.assertEqual(out["SSHPublicKey"], [None, redacted, None, None])
        self.assertRegex(out["CertificateString"], r"^<pem:\d+>\n$")
        self.assertEqual(out["Scrubbed"], {"Password": "***scrubbed***"})

    def test_password_policy_leaves_and_annotations_stay(self):
        payload = {
            "ComplexPassword": True,
            "PasswordLength": 8,
            "MinPasswordLength": 10,
            "PasswordChangeOnFirstAccess": False,
            "IsUefiAdminPasswordSet": True,
            "EncryptionKeySet": False,
            "PasswordSet": True,
            "PasswordExpirationPeriodDays": 90,
            "PasswordExpiration": "2027-01-01T00:00:00+00:00",
            "AuthenticationKey@Redfish.OptionalOnCreate": True,
            "PasswordName@Redfish.AllowableValues": ["AdminPassword", "UserPassword"],
            "sha256-password": "left-to-the-text-rules",
        }
        self.assertEqual(_bmc().json(payload), payload)

    def test_the_secret_rule_agrees_with_the_family_redactor(self):
        if __package__:
            from . import _loader
        else:  # unittest discover -s tests imports test modules as top-level
            import _loader
        family = _loader.checks_bmc
        for name in family._SECRET_NAMES:
            self.assertTrue(sanitize_trace.is_secret_key(name, "x"), name)
        cases = (
            ("Password", "x"),
            ("ClientPassword", None),
            ("BindPassword", "x"),
            ("communitynames", []),
            ("Bytes", [1]),
            ("ComplexPassword", True),
            ("PasswordLength", 8),
            ("EncryptionKeySet", False),
            ("PasswordExpiration", "2027-01-01"),
            ("KeyUsage", ["DigitalSignature"]),
            ("EnterCLIKeySequence", "ESC ("),
            ("AuthenticationKey@Redfish.OptionalOnCreate", True),
        )
        for key, value in cases:
            self.assertEqual(
                sanitize_trace.is_secret_key(key, value), family._is_secret(key, value), key
            )

    def test_free_text_a_site_types_in_is_redacted(self):
        out = _bmc().json(
            {
                "Location": {
                    "PostalAddress": {"Building": "B7", "Room": "", "City": "Springfield"}
                },
                "BindDN": "cn=svc-bmc,ou=Service Accounts,dc=acme-corp,dc=net",
                "BaseDistinguishedNames": ["dc=acme-corp,dc=net", ""],
                "TrespassMessage": "Property of ACME Corp",
            }
        )
        self.assertEqual(
            out["Location"]["PostalAddress"],
            {"Building": "REDACTED", "Room": "", "City": "REDACTED"},
        )
        self.assertEqual(out["BindDN"], "cn=REDACTED,ou=REDACTED,dc=REDACTED,dc=REDACTED")
        self.assertEqual(out["BaseDistinguishedNames"], ["dc=REDACTED,dc=REDACTED", ""])
        self.assertEqual(out["TrespassMessage"], "REDACTED")


class TestPeople(unittest.TestCase):
    ACCOUNTS = {
        "Members": [
            {"Id": "1", "UserName": "opsjane", "RoleId": "Administrator"},
            {"Id": "2", "UserName": "opsjoe", "RoleId": "Operator"},
            {"Id": "3", "UserName": "capture_ro", "RoleId": "ReadOnly"},
            {"Id": "4", "UserName": "", "RoleId": "NoAccess"},
        ]
    }

    def test_accounts_become_distinct_inventions_and_the_capture_account_netops(self):
        san = _bmc()
        san.learn(self.ACCOUNTS)
        names = [member["UserName"] for member in san.json(self.ACCOUNTS)["Members"]]
        self.assertEqual(names, ["user-lab-1", "user-lab-2", "netops", ""])
        self.assertNotIn("capture_ro", san.export_map()["users"])
        line = "Login ID: opsjane from WEB at IP address 10.20.30.41 has logged off."
        out = san.text(line)
        self.assertTrue(out.startswith("Login ID: user-lab-1 from WEB at IP address 198.18."))
        self.assertEqual(_bmc().json(self.ACCOUNTS), san.json(self.ACCOUNTS))  # deterministic

    def test_log_message_users_are_learned_and_the_bmc_actors_are_not(self):
        page = {
            "Members": [
                {
                    "Message": "Remote Login Successful. Login ID: opsmary using default "
                    "authentication from WEB at IP address 10.20.30.41.",
                    "MessageArgs": ["opsmary", "default authentication", "WEB", "10.20.30.41"],
                },
                {"Message": "The UEFI setting has been changed to the latest by user system."},
                {"Message": "User LXPM has mounted file diag_boot.img from Local."},
                {
                    "Message": "Flash of SN#   Z1AB2345 from (10.20.30.41) succeeded "
                    "for user opstom ."
                },
                {"Message": "User opsann password modified by user opsmary from WEB."},
                {"Message": "Userid is opsbob."},
                {"Message": "Login ID: ***scrubbed*** from WEB has logged off."},
            ]
        }
        san = _bmc()
        san.learn(page)
        self.assertEqual(sorted(san.map["users"]), ["opsann", "opsbob", "opsmary", "opstom"])
        out = json.dumps(san.json(page))
        for name in ("opsmary", "opstom", "opsann", "opsbob", "Z1AB2345", "10.20.30.41"):
            self.assertNotIn(name, out)
        for kept in ("by user system.", "User LXPM has mounted", "Login ID: ***scrubbed***"):
            self.assertIn(kept, out)

    def test_other_person_leaves_are_invented_with_emptiness_kept(self):
        out = _bmc().json(
            {
                "SMTP": {"Username": "relay-svc", "Password": None},
                "UserID": "",
                "LoginID": None,
                "Contacts": [
                    {"ContactName": "Jane Q Ops", "EmailAddress": "jane.ops@acme-corp.net"}
                ],
                "SNMPv3Agent": {"ContactPerson": ""},
                "Notify": {"EmailAddress": "capture_ro@acme-corp.net"},
            }
        )
        self.assertRegex(out["SMTP"]["Username"], r"^user-lab-\d+$")
        self.assertEqual((out["UserID"], out["LoginID"]), ("", None))
        contact = out["Contacts"][0]
        self.assertRegex(contact["ContactName"], r"^user-lab-\d+$")
        self.assertRegex(contact["EmailAddress"], r"^user-lab-\d+@example\.com$")
        self.assertEqual(out["SNMPv3Agent"]["ContactPerson"], "")
        self.assertEqual(out["Notify"]["EmailAddress"], "netops@example.com")
        self.assertNotIn("acme-corp", json.dumps(out))

    def test_an_account_named_like_a_role_is_invented_but_roles_stay(self):
        san = _bmc()
        account = {
            "UserName": "Administrator",
            "RoleId": "Administrator",
            "Links": {"Role": "Administrator"},
        }
        san.learn(account)
        out = san.json(account)
        self.assertEqual(out["UserName"], "user-lab-1")
        self.assertEqual((out["RoleId"], out["Links"]["Role"]), ("Administrator", "Administrator"))


class TestBmcEnvFile(unittest.TestCase):
    def _env(self, text):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        path = pathlib.Path(folder.name) / "bmc.env"
        path.write_text(text, encoding="utf-8")
        return sanitize_trace.read_env(path)

    def test_username_is_netops_the_password_redacted_and_the_host_an_address(self):
        env = self._env("username=capture_ro\npassword='pw-Secret-1'\nhost=10.20.30.40\n")
        san = Sanitizer(secrets=env)
        out = san.text("capture_ro logged in to 10.20.30.40 with pw-Secret-1")
        self.assertRegex(out, r"^netops logged in to 198\.18\.\d+\.40 with REDACTED$")
        self.assertIn("10.20.30.40", san.map["ips"])  # the leak scan knows the real address
        dumped = json.dumps(san.export_map())
        self.assertNotIn("capture_ro", dumped)
        self.assertNotIn("pw-Secret-1", dumped)

    def test_an_address_is_never_redacted_and_a_host_name_is_a_hostname(self):
        san = Sanitizer(
            secrets=self._env("user=capture_ro\nserver=10.20.30.50\nhost=bmc-rack7-a\n")
        )
        self.assertTrue(san.text("to 10.20.30.50").startswith("to 198.18."))
        self.assertEqual(san.text("HstName=bmc-rack7-a"), "HstName=bmc-lab-1")
        self.assertEqual(san.text("by capture_ro"), "by netops")  # the IOS-XE key still works


class TestLearnPassAndCli(unittest.TestCase):
    def test_learning_registers_without_rewriting(self):
        san = _bmc()
        payload = {"SerialNumber": SERIAL_A, "UUID": UUID_A, "Members": [{"UserName": "opsjane"}]}
        before = json.dumps(payload)
        san.learn(payload)
        self.assertEqual(json.dumps(payload), before)
        self.assertIn(SERIAL_A, san.map["serials"])
        self.assertIn("opsjane", san.map["users"])
        self.assertEqual(san.map["macs"], {})

    def test_the_cli_learns_every_input_before_writing_any(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        base = pathlib.Path(folder.name)
        first = base / "a_certificate.json"  # names the serial only inside a hostname
        first.write_text(json.dumps({"Subject": {"CommonName": "XCC-7X99-" + SERIAL_A}}))
        second = base / "b_system.json"
        second.write_text(json.dumps({"SerialNumber": SERIAL_A, "UUID": UUID_A}))
        env = base / "bmc.env"
        env.write_text("username=capture_ro\npassword=pw-Secret-1\n")
        out_dir = base / "out"
        out_dir.mkdir()
        mapping = base / "map.json"
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            code = sanitize_trace.main(
                ["--env", str(env), "--mapping-out", str(mapping), "--out-dir", str(out_dir)]
                + [str(first), str(second)]
            )
        self.assertEqual((code, stdout.getvalue()), (0, ""))
        cert = json.loads((out_dir / first.name).read_text())
        system = json.loads((out_dir / second.name).read_text())
        self.assertEqual(cert["Subject"]["CommonName"], "XCC-7X99-" + system["SerialNumber"])
        self.assertNotEqual(system["SerialNumber"], SERIAL_A)
        written = mapping.read_text()
        self.assertIn(SERIAL_A, written)  # the mapping holds real values ...
        self.assertNotIn("pw-Secret-1", written)  # ... never a credential
        self.assertNotIn("capture_ro", written)

    def test_a_second_pass_and_a_reloaded_mapping_change_nothing(self):
        san = _bmc()
        payload = {
            "SerialNumber": SERIAL_A,
            "UUID": UUID_A,
            "HostName": "bmc-rack7-a",
            "AssetTag": "IT-004711",
            "Members": [{"UserName": "opsjane", "Password": "x"}],
            "Message": "Login ID: opsjane from 10.20.30.41, SN: K9LM12345678X",
        }
        san.learn(payload)
        once = san.json(payload)
        self.assertEqual(san.json(once), once)
        again = Sanitizer(mapping=json.loads(json.dumps(san.export_map())))
        self.assertEqual(again.json(payload), once)
        self.assertEqual(set(again.map) - {"uuids", "assets"}, set(sanitize_trace._CATEGORIES))


if __name__ == "__main__":
    unittest.main()
