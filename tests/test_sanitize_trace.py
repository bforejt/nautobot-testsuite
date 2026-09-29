"""tools/sanitize_trace.py: deterministic, mapping-preserving fixture sanitizer.

Invented inputs only (invented hostnames, serials, MACs and private ranges that
name no site; documentation ranges as targets); nothing here reads a credential
file. The tool is stdlib-only, so the battery locks in
the rules a harvested fixture depends on: same real value -> same invention,
shape preserved, group MACs and netmasks untouched, credentials never echoed.
"""

import importlib.util
import json
import pathlib
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


if __name__ == "__main__":
    unittest.main()
