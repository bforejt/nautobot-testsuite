"""PAN-OS CLI/XML parsing helpers. Pure: stdlib xml.etree only, no network.

With ``set cli op-command-xml-output on`` every op command returns its XML
document over the SSH channel — identical in structure to the XML API
response. These helpers extract and query that XML so collectors stay small
and the parsers are exercised in CI against fixture captures.
"""

import re
import xml.etree.ElementTree as ET

_XML_START = re.compile(r"<(response|result)[\s>/]")


class PanosParseError(Exception):
    """Output did not contain a parseable XML payload."""


def extract_xml(cli_output):
    """Pull the XML document out of raw CLI output and parse it.

    CLI transport may wrap the payload in prompt fragments or blank lines.
    Prefer slicing at the root element's own closing tag — a trailing device
    prompt containing '>' (netmiko normally strips it, but never rely on it)
    must not extend the slice past the document. Fall back to the last '>'.
    """
    if cli_output is None:
        raise PanosParseError("no output")
    match = _XML_START.search(cli_output)
    if not match:
        raise PanosParseError("no XML payload in output (%d chars)" % (len(cli_output),))
    start = match.start()
    root_tag = match.group(1)
    candidates = []
    close = cli_output.rfind("</%s>" % root_tag)
    if close > start:
        candidates.append(cli_output[start : close + len(root_tag) + 3])
    candidates.append(cli_output[start : cli_output.rfind(">") + 1])
    last_exc = None
    for snippet in candidates:
        try:
            return ET.fromstring(snippet)
        except ET.ParseError as exc:
            last_exc = exc
    raise PanosParseError("XML parse failed: %s" % (last_exc,)) from last_exc


def text(element, path, default=None):
    """Text of the first match of ``path`` under ``element``, stripped."""
    if element is None:
        return default
    found = element.find(path)
    if found is None or found.text is None:
        return default
    return found.text.strip()


def texts(element, path):
    """Stripped text of every match of ``path`` (skips empty nodes)."""
    if element is None:
        return []
    out = []
    for node in element.findall(path):
        if node.text and node.text.strip():
            out.append(node.text.strip())
    return out


def to_int(value, default=None):
    """Parse the leading integer out of a value like '48213' or '23 sessions'."""
    if value is None:
        return default
    match = re.search(r"-?\d+", str(value))
    return int(match.group()) if match else default


def result_of(root):
    """The <result> element of a <response>, or the root itself if it is one."""
    if root is None:
        return None
    if root.tag == "result":
        return root
    return root.find("result")
