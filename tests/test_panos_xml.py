"""panos_xml: XML extraction from noisy CLI captures and the query helpers."""

import unittest
import xml.etree.ElementTree as ET

if __package__:
    from . import _loader
else:  # unittest discover -s tests imports test modules as top-level
    import _loader

panos_xml = _loader.panos_xml

# What netmiko hands back: command echo + banner noise before the payload,
# trailing blank lines after it (the trailing prompt is consumed by the
# transport's prompt detection).
NOISY_RESPONSE = (
    "show system info\n"
    "\n"
    '<response status="success"><result><system>\n'
    "  <hostname>fw-edge-01</hostname>\n"
    "  <ip-address>192.0.2.10</ip-address>\n"
    "  <sw-version>11.1.4-h7</sw-version>\n"
    "</system></result></response>\n"
    "\n\n"
)

BARE_RESULT = "\n<result>\n  <entry>\n    <name>vsys1</name>\n  </entry>\n</result>\n"


class TestExtractXml(unittest.TestCase):
    def test_response_with_prompt_noise(self):
        root = panos_xml.extract_xml(NOISY_RESPONSE)
        self.assertEqual(root.tag, "response")
        self.assertEqual(root.get("status"), "success")
        self.assertEqual(panos_xml.text(root, "./result/system/hostname"), "fw-edge-01")

    def test_bare_result_document(self):
        root = panos_xml.extract_xml(BARE_RESULT)
        self.assertEqual(root.tag, "result")
        self.assertEqual(panos_xml.text(root, "./entry/name"), "vsys1")

    def test_trailing_device_prompt_survives(self):
        # If netmiko ever fails to strip the prompt, the '>' in it must not
        # extend the slice past the XML document.
        root = panos_xml.extract_xml(NOISY_RESPONSE + "admin@fw-edge-01> ")
        self.assertEqual(root.tag, "response")
        self.assertEqual(panos_xml.text(root, "./result/system/hostname"), "fw-edge-01")

    def test_trailing_prompt_after_bare_result(self):
        root = panos_xml.extract_xml(BARE_RESULT + "admin@fw-edge-01> ")
        self.assertEqual(root.tag, "result")
        self.assertEqual(panos_xml.text(root, "./entry/name"), "vsys1")

    def test_garbage_raises(self):
        with self.assertRaises(panos_xml.PanosParseError):
            panos_xml.extract_xml("Unknown command: shw system info\n")

    def test_none_raises(self):
        with self.assertRaises(panos_xml.PanosParseError):
            panos_xml.extract_xml(None)

    def test_truncated_xml_raises(self):
        with self.assertRaises(panos_xml.PanosParseError):
            panos_xml.extract_xml('<response status="success"><result><system>')

    def test_empty_string_raises(self):
        with self.assertRaises(panos_xml.PanosParseError):
            panos_xml.extract_xml("")


class TestQueryHelpers(unittest.TestCase):
    def setUp(self):
        self.root = ET.fromstring(
            "<result>"
            "<system><hostname>  fw-edge-01  </hostname><empty></empty></system>"
            "<members><member>ethernet1/1</member><member> ethernet1/2 </member>"
            "<member>   </member></members>"
            "</result>"
        )

    def test_text_found_and_stripped(self):
        self.assertEqual(panos_xml.text(self.root, "./system/hostname"), "fw-edge-01")

    def test_text_missing_returns_default(self):
        self.assertIsNone(panos_xml.text(self.root, "./system/nope"))
        self.assertEqual(panos_xml.text(self.root, "./system/nope", "n/a"), "n/a")

    def test_text_empty_node_returns_default(self):
        self.assertEqual(panos_xml.text(self.root, "./system/empty", "dflt"), "dflt")

    def test_text_none_element(self):
        self.assertEqual(panos_xml.text(None, "./x", "dflt"), "dflt")

    def test_texts_skips_empty(self):
        self.assertEqual(
            panos_xml.texts(self.root, "./members/member"),
            ["ethernet1/1", "ethernet1/2"],
        )

    def test_texts_none_element(self):
        self.assertEqual(panos_xml.texts(None, "./x"), [])


class TestToInt(unittest.TestCase):
    def test_plain_number(self):
        self.assertEqual(panos_xml.to_int("48213"), 48213)

    def test_number_with_suffix(self):
        self.assertEqual(panos_xml.to_int("23 sessions"), 23)

    def test_number_embedded_in_sentence(self):
        self.assertEqual(panos_xml.to_int("Number of sessions that match filter: 23"), 23)

    def test_negative(self):
        self.assertEqual(panos_xml.to_int("-5"), -5)

    def test_int_passthrough(self):
        self.assertEqual(panos_xml.to_int(42), 42)

    def test_none_and_garbage(self):
        self.assertIsNone(panos_xml.to_int(None))
        self.assertEqual(panos_xml.to_int(None, 0), 0)
        self.assertIsNone(panos_xml.to_int("no digits here"))
        self.assertEqual(panos_xml.to_int("no digits here", -1), -1)


class TestResultOf(unittest.TestCase):
    def test_response_wrapping_result(self):
        root = ET.fromstring("<response><result><x>1</x></result></response>")
        result = panos_xml.result_of(root)
        self.assertEqual(result.tag, "result")
        self.assertEqual(panos_xml.text(result, "./x"), "1")

    def test_root_is_result(self):
        root = ET.fromstring("<result><x>1</x></result>")
        self.assertIs(panos_xml.result_of(root), root)

    def test_none_and_resultless(self):
        self.assertIsNone(panos_xml.result_of(None))
        self.assertIsNone(panos_xml.result_of(ET.fromstring("<response><msg>ok</msg></response>")))


if __name__ == "__main__":
    unittest.main()
