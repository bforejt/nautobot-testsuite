#!/usr/bin/env python3
"""Sanitize captured device payloads into committable fixtures — deterministic,
mapping-preserving, stdlib only.

A shakedown trace or a lab harvest carries what a snapshot must never carry
into the repo: real hostnames, addresses, MACs, chassis serials, UUIDs, user
names, certificate material and the credentials of the capture session. This
tool rewrites every one of them so that the SHAPE the parser sees is unchanged
(a dotted MAC stays dotted, a serial keeps its letter/digit pattern, a /23
keeps its host octets, a UUID keeps its version) while nothing identifies the
site any more. The same real value always maps to the same invented value,
within one run and across runs that share a mapping file, so a fixture set
harvested from ten payloads stays internally consistent (the MAC in the CDP
table is the MAC in the MAC table, the drive serial in the boot order is the
serial of the drive) and a later re-harvest diffs cleanly against the last one.

Usage (from the repository root):

    python3 tools/sanitize_trace.py \\
        --env /path/to/device.env \\
        --host sw-real-01=sw-lab-1 --host AP0000.1111.2222=ap-lab-1 \\
        --user someone \\
        --net 10.0.0.0/24=192.0.2.0/24 --net 10.0.1.0/24=198.51.100.0/24 \\
        --mapping-out /tmp/sanitize-map.json \\
        --out-dir tests/fixtures  payload-a.json  show-b.txt ...

    python3 tools/sanitize_trace.py --mapping-in /tmp/sanitize-map.json one.json > one.clean.json

Before anything is written, every input is read once to LEARN the identifiers
its JSON names by key (below) and the ``SN: <token>`` serials its texts print,
so a serial that a log message or a boot entry mentions before the file whose
leaf names it is processed is still replaced.

What is rewritten in text, in this order (earlier rules win where they overlap):

1. **Credentials** — every value in the ``--env`` file (``key=value`` lines,
   the capture session's own secrets). The value under the ``user`` or
   ``username`` key becomes ``netops``; every other value becomes
   ``REDACTED``, except an address (the ``host`` key, or any value that
   parses as an IP address), which rules 8-9 invent so the fixture keeps an
   address shape (a ``host`` that is a DNS name is a hostname, rule 2).
   Matched only as a whole word that is not part of a hyphenated token, so a
   user named ``admin`` never eats the YANG leaf ``admin-status``. The values
   are never printed, logged or written to the mapping file.
2. **Hostnames** given with ``--host REAL=FAKE`` or learned from a
   ``HostName`` / ``FQDN`` / ``DomainName`` leaf (case-insensitive, longest
   first). A CDP/LLDP device id that embeds a MAC (``AP0000.1111.2222``) is
   listed here so the whole id maps, not just the MAC inside it. A vendor
   default (``xcc``, ``xclarity``, ``imm``, ``bmc``, ``localhost`` ...)
   identifies nobody and is also a product word (``XCC Web``), so it is
   matched only as a whole token in its own spelling.
3. **User names**: ``--user NAME`` -> ``netops``; a person learned from a
   ``UserName`` / ``Username`` / ``UserID`` / ``LoginID`` / ``ContactName`` /
   ``ContactPerson`` / ``EmailAddress`` leaf or from a Lenovo log message
   (``Login ID: <x>``, ``by user <x>``, ``for user <x>``, ``User <x> ...`` at
   the start of a sentence, ``Userid is <x>``) -> a distinct ``user-lab-<n>``
   (two real accounts never collapse onto one key; the capture account stays
   ``netops``). Same whole-word rule as credentials. The BMC's own actors
   (``system``, ``LXPM`` ...) and the ``***scrubbed***`` marker are not users.
4. **UUIDs** (8-4-4-4-12 hex, any case) -> an invented UUID with the same
   version nibble, variant bits and case, BEFORE the MAC and hex rules, so a
   UUID's 12-digit tail is never taken for a bare MAC. The nil UUID is left
   alone, and so is a UUID glued to a word (``regid...,1.0_<uuid>``, a
   software-ID tag naming a licence product): the later rules treat it as
   they always have.
5. **Learned identifiers**: every serial and asset tag learned from a leaf
   (6+ characters, as spelled), and every ``SN: <token>`` / ``SN#<token>``
   serial -> its invention (rule 7's machinery), before the hex and MAC rules
   can take a piece of one.
6. **Certificate material**: PEM bodies, hex fingerprints, IOS certificate
   chain bodies (lines of 8-digit hex groups) and any hex run of 16+ digits
   (with or without ``:``/space separators, ``0x``-prefixed dumps included)
   -> a short placeholder that keeps the length class visible (``<hex:64>``).
   Self-signed trustpoint and certificate names carry the chassis identity in
   their numeric suffix and are renumbered.
7. **Serials**: every token of the Cisco shape (three letters, four digits,
   four alphanumerics: ``ABC1234D5EF``) plus any ``--serial`` value -> an
   invented token with the same letter/digit pattern and case, distinct per
   source; a leading three-letter site prefix (``FOC``, ``DCC``) is kept.
8. **MACs** in dotted, colon, dash or bare 12-digit spelling -> an invented MAC in the same
   spelling and case, keeping the multicast and locally-administered bits of
   the first octet. Group addresses (multicast bit set: STP, CDP, IPv4
   multicast, broadcast), the protocol blocks (VRRP, HSRP virtual MACs) and
   the all-zero MAC (no partner, no address) identify nobody and are left alone.
9. **IPv4 addresses**: ``--net SRC/24=DST/24`` pairs map a real /24 onto a
   documentation /24 with the host octet kept; any other real /24 lands
   deterministically in 198.18.0.0/16 (RFC 2544 benchmarking space) with its
   host octet kept. Addresses in 0/8, 127/8, 224/4 and 240/4 (masks,
   wildcards, loopback, multicast, broadcast) and the RFC 5737 documentation
   ranges are never touched, so a netmask stays a netmask. A JSON
   ``router-id`` leaf served as an integer (the OSPF and EIGRP models type it
   uint32) is the same address in host order and maps through the same rule.
10. **IPv6 addresses**: an EUI-64 interface identifier (``...ff:fe...``)
   embeds the port's MAC, so it is rebuilt from that MAC's invention (rule 8:
   the link-local of a CDP neighbour is the same device as its MAC table row);
   any other identifier is kept. A global or unique-local /64 prefix lands
   deterministically in 2001:db8::/32 (RFC 3849 documentation space); the
   link-local prefix ``fe80::/10``, the unspecified and loopback addresses,
   multicast ``ff00::/8`` and the documentation range are never touched. The
   spelling (compressed form, upper or lower case) is preserved.

JSON inputs are walked (keys and string values); anything else is treated as
text. In JSON, a leaf is also judged by its KEY (Redfish names, exact spelling;
null, empty and list lengths are always kept):

- a key ending in ``SerialNumber`` holds a serial of ANY shape -> an invented
  serial with the same pattern (placeholders such as ``N/A`` stay);
  ``AssetTag`` -> an invented tag of the same pattern;
- ``HostName`` / ``FQDN`` -> ``bmc-lab-<n>`` / ``bmc-lab-<n>.lab.example``
  unless a ``--host`` pair names them; ``DomainName`` -> ``lab.example``;
- ``UserName`` and the other person leaves -> ``user-lab-<n>`` (the capture
  account -> ``netops``); ``EmailAddress`` -> ``<user>@example.com``;
- ``EntitlementId`` and the ``Identifier`` of licence and FoD keys ->
  ``<id:N>``; ``Fingerprint`` and the SNMP engine's ``ArchitectureId`` (hex
  bytes that spell the BMC's hostname) -> ``<hex:N>``;
- key material and credentials, by exact name as ``jobs/checks_bmc.py``
  judges them (``Password``, ``Passphrase``, ``Secret``, ``ClientSecret``,
  ``PrivateKey``, ``AuthenticationKey``, ``EncryptionKey``,
  ``CommunityNames``, ``Community``, ``CommunityString``, ``TrapCommunity``,
  ``LicenseString``,
  ``CertificateString``, ``Bytes``, ``SSHPublicKey``, ``SED_AK``,
  ``BMU_Credential``, and any other ``...Password`` leaf that is not a boolean
  or a number) -> ``REDACTED`` (a PEM body -> ``<pem:N>``); the password
  POLICY leaves (``ComplexPassword``, ``PasswordLength``, ``PasswordSet``
  ...) and annotations (``Name@Redfish.*``) are configuration and stay, and so
  does a harvest's own ``***scrubbed***`` marker;
- free text a site types in: ``PostalAddress`` fields, LDAP distinguished
  names (``cn=REDACTED,dc=REDACTED``) and the ``TrespassMessage`` banner;
- the Lenovo boot-order strings (``BootOrderCurrent`` / ``Next`` /
  ``Supported``) embed the drive's serial after its model: a token of 8+
  characters with digits that no ``Model`` / ``PartNumber`` leaf spells is
  learned as a serial.

The mapping file lists real -> invented for hostnames, users, serials, asset
tags, UUIDs, MACs, networks and IPv6 addresses (never credentials) so a later
run can reuse it; keep it beside the raw payloads, outside the repository.
"""

import argparse
import hashlib
import ipaddress
import json
import pathlib
import re
import sys

USER_PLACEHOLDER = "netops"
SECRET_PLACEHOLDER = "REDACTED"
USER_INVENTION = "user-lab-%d"
HOST_INVENTION = "bmc-lab-%d"
DOMAIN_INVENTION = "lab.example"
EMAIL_DOMAIN = "example.com"

# A credential or user name as a whole token: not glued to a letter, digit,
# underscore or hyphen on either side (``admin`` in ``by admin`` matches;
# ``admin`` in ``admin-status`` or ``sysadmin`` does not).
_TOKEN_EDGE = r"(?<![\w-])%s(?![\w-])"

_PEM = re.compile(r"-----BEGIN [A-Z ]+-----[A-Za-z0-9+/=\s]+?-----END [A-Z ]+-----", re.MULTILINE)
# Hex material: 0x-byte dumps, ':'-separated fingerprints and bare hex runs.
_HEX_0X = re.compile(r"0x[0-9A-Fa-f]{2}(?:(?:[ \t]+|\r?\n[ \t]+)0x[0-9A-Fa-f]{2}){7,}")
_HEX_SEP = re.compile(r"(?<![0-9A-Fa-f])(?:[0-9A-Fa-f]{2}[: ]){15,}[0-9A-Fa-f]{2}(?![0-9A-Fa-f])")
_HEX_RUN = re.compile(r"(?<![0-9A-Za-z])[0-9A-Fa-f]{16,}(?![0-9A-Za-z])")
# IOS ``crypto pki certificate chain`` bodies: lines of 8-digit hex groups.
_HEX_GROUPS = re.compile(
    r"(?<![0-9A-Fa-f])(?:[0-9A-Fa-f]{8}[ \t]+){2,}[0-9A-Fa-f]{2,8}(?![0-9A-Fa-f])"
)
_SELF_SIGNED = re.compile(r"(TP-self-signed-|IOS-Self-Signed-Certificate-|SLA-TrustPoint-)(\d+)")

_SERIAL = re.compile(r"(?<![A-Z0-9])[A-Z]{3}\d{4}[A-Z0-9]{4}(?![A-Z0-9])")
# A serial a text names outright: ``SN: FOC1234X5YZ``, ``(SN:J300ABCD)``, Lenovo's
# ``SN#   J300ABCD``. Blanks only after the marker: ``SN:`` at a line end names nothing.
_SN_TOKEN = re.compile(r"(\bSN[:#][ \t]*)([A-Za-z0-9]+)(?![A-Za-z0-9])")
_MAC_DOTTED = re.compile(
    r"(?<![0-9A-Fa-f])([0-9A-Fa-f]{4})\.([0-9A-Fa-f]{4})\.([0-9A-Fa-f]{4})(?![0-9A-Fa-f])"
)
_MAC_SEP = re.compile(
    r"(?<![0-9A-Fa-f])([0-9A-Fa-f]{2})([:-])((?:[0-9A-Fa-f]{2}[:-]){4}[0-9A-Fa-f]{2})"
    r"(?![0-9A-Fa-f])"
)
# A bare 12-digit MAC as SUDI certificate names spell it (``C9300-48UXM-001122AABBCC``).
_MAC_BARE = re.compile(r"(?<![0-9A-Za-z])([0-9A-Fa-f]{12})(?![0-9A-Za-z])")
_IPV4 = re.compile(r"(?<![\d.])(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?!\.?\d)")
# An IPv6 candidate: a run of hex groups with at least two colons that the
# ipaddress module accepts (a colon MAC, a clock and a fingerprint all fail
# that parse and fall through to their own rules).
_IPV6 = re.compile(r"(?<![0-9A-Za-z:.])[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7}(?![0-9A-Za-z:.])")
_IPV6_DOC = ipaddress.ip_network("2001:db8::/32")
_IPV6_LINK_LOCAL = ipaddress.ip_network("fe80::/10")
# A UUID as a token of its own (see rule 4 for what is left alone).
_UUID = re.compile(
    r"(?<![\w-])[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}(?![\w-])"
)
_NIL_UUIDS = ("0" * 32, "f" * 32)
_EMAIL = re.compile(r"([^@\s]+)@([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)")

# Virtual MACs a protocol assigns from a well-known block: VRRP (00-00-5E-00-01-xx),
# HSRPv1 (00-00-0C-07-AC-xx) and HSRPv2 (00-00-0C-9F-Fx-xx) name a group, not a device.
_PROTOCOL_MACS = ("00005e0001", "00000c07ac", "00000c9ff")
# The all-zero MAC is "none" (an LACP member without a partner, an unset UDI).
_NO_MAC = "000000000000"

_UNTOUCHED_NETS = tuple(
    ipaddress.ip_network(net)
    for net in (
        "0.0.0.0/8",
        "127.0.0.0/8",
        "224.0.0.0/4",
        "240.0.0.0/4",
        "192.0.2.0/24",
        "198.51.100.0/24",
        "203.0.113.0/24",
        "198.18.0.0/15",
    )
)
_UNTOUCHED_NETS6 = tuple(
    ipaddress.ip_network(net) for net in ("::/128", "::1/128", "ff00::/8", "2001:db8::/32")
)

# --- key-aware rules (Redfish property names, exact spelling) ------------------
# Key material and credentials, judged as jobs/checks_bmc.py judges them: exact
# leaf names (case-insensitive), plus any other "...password" leaf that is not a
# boolean or a number (ClientPassword goes; ComplexPassword stays).
SECRET_NAMES = frozenset(
    name.lower()
    for name in (
        "Password",
        "Passphrase",
        "Secret",
        "ClientSecret",
        "PrivateKey",
        "AuthenticationKey",
        "EncryptionKey",
        "CommunityNames",
        "Community",
        "CommunityString",
        "TrapCommunity",
        "LicenseString",
        "CertificateString",
        "Bytes",
        "SSHPublicKey",
        "SED_AK",
        "BMU_Credential",
        "OAuthServiceSigningKeys",
        "CHAPSecret",
        "MutualCHAPSecret",
    )
)
PERSON_KEYS = frozenset(
    {"UserName", "Username", "UserID", "UserId", "LoginID", "LoginId", "LoginName"}
    | {"CHAPUsername", "MutualCHAPUsername"}
    | {"ContactName", "ContactPerson"}
)
EMAIL_KEYS = frozenset({"EmailAddress"})
PHONE_KEYS = frozenset({"PhoneNumber"})
HOST_KEYS = frozenset({"HostName", "FQDN"})
DOMAIN_KEYS = frozenset({"DomainName"})
ASSET_KEYS = frozenset({"AssetTag"})
ID_KEYS = frozenset({"EntitlementId", "Identifier"})
HEX_KEYS = frozenset({"Fingerprint", "ArchitectureId"})
FREE_TEXT_KEYS = frozenset({"TrespassMessage"})
ADDRESS_BLOCK_KEYS = frozenset({"PostalAddress"})
# The Lenovo boot manager's descriptive entries (``SATA: <model> <serial> ...``).
BOOT_ORDER_KEYS = frozenset({"BootOrderCurrent", "BootOrderNext", "BootOrderSupported"})
# Leaves whose words name a product, never a unit: a boot entry's token that one of
# them spells is a model, not a serial.
MODEL_KEYS = frozenset({"Model", "PartNumber", "Manufacturer", "ProductName", "FruPartNumber"})
SERIAL_SUFFIX = "SerialNumber"
# A leaf ending in this is an LDAP distinguished name (BindDN, RootDN, BaseDistinguishedNames).
_DN_KEY = re.compile(r"(?:DN|DistinguishedNames?)$")
_DN_VALUE = re.compile(r"(?i)\b([a-z]+)=([^,+]+)")

# Values that stand for "nothing here", not for one unit.
_PLACEHOLDER_VALUES = frozenset(
    value.lower()
    for value in (
        "N/A",
        "NA",
        "N.A.",
        "None",
        "Null",
        "Unknown",
        "Unavailable",
        "Not Available",
        "Not Applicable",
        "Not Specified",
        "Not Supported",
        "To Be Filled By O.E.M.",
        "Default string",
    )
)
# What a harvest or an earlier pass already put in place of a value.
_MARKERS = frozenset({"***scrubbed***", SECRET_PLACEHOLDER})
_PLACEHOLDER_TOKEN = re.compile(r"^<(?:pem|hex|id):\d+>$")
_MIN_LEARNED = 6  # a learned serial or tag shorter than this is invented where it stands only

# A vendor default hostname names nobody and is also a product word.
GENERIC_HOSTS = frozenset(
    {"xcc", "xclarity", "imm", "imm2", "bmc", "idrac", "ilo", "cimc", "ipmi"}
    | {"localhost", "localhost.localdomain", "localdomain", "local"}
)
# ... and these mean "no name configured": left alone wherever they stand.
_NO_NAMES = frozenset({"localhost", "localhost.localdomain", "localdomain", "local"})
_DOC_DOMAINS = re.compile(r"(?i)(?:^|\.)(?:example(?:\.com|\.net|\.org)?|test|invalid|localhost)$")

# Lenovo audit events carry the account in the message (XCC 6.10: "Remote Login
# Successful. Login ID: <x> using ...", "... by user <x>.", "... succeeded for
# user <x> .", "User <x> has mounted ...", "Userid is <x>"): the same patterns
# jobs/checks_bmc.py scrubs with.
_NAME_TAIL = r"(\S+?)(?=[.,:;]?(?:\s|$))"
LOG_USER_PATTERNS = (
    re.compile(r"\bLogin ID:\s*" + _NAME_TAIL),
    re.compile(r"\b[Bb]y user\s+" + _NAME_TAIL),
    re.compile(r"\b[Ff]or user\s+" + _NAME_TAIL),
    re.compile(r"\b[Uu]serid(?: is)?:?\s+" + _NAME_TAIL),
    re.compile(r"(?:^|(?<=[.;:]\s))User\s+" + _NAME_TAIL),
)
# The BMC's own actors in those messages ("by user system", "User LXPM has mounted
# ..."): product words, never people, and mapping them would rewrite every
# "LXPM firmware" line.
SYSTEM_ACTORS = frozenset(
    {"system", "lxpm", "lxca", "xcc", "imm", "uefi", "host", "bmc", "ipmi", "snmp", "cim"}
    | {"cli", "web", "redfish", "local", "os", "internal"}
)
_ACCOUNT = re.compile(r"^[A-Za-z][\w.@-]*$")
# An account named like a predefined Redfish role (HPE's default "Administrator")
# is invented where a person leaf names it but never rewritten in text: every
# RoleId would go with it.
ROLE_WORDS = frozenset({"Administrator", "Operator", "ReadOnly", "NoAccess"})

_ENV_USER_KEYS = ("user", "username")
_ENV_HOST_KEYS = ("host",)

# Inventions parked while later text rules run (private-use code points no rule matches).
_PARK_OPEN, _PARK_CLOSE, _PARK_DIGIT = "\ue000", "\ue001", 0xE010
_PARKED = re.compile("\ue000([\ue010-\ue019]+)\ue001")

# Mapping categories every mapping file carries, and the ones added when used.
_CATEGORIES = ("hosts", "users", "serials", "macs", "nets", "ips", "ipv6")
_LAZY_CATEGORIES = ("uuids", "assets")


def _digest(salt, kind, value):
    return hashlib.sha256(("%s|%s|%s" % (salt, kind, value)).encode("utf-8")).digest()


def read_env(path):
    """{key: value} from a ``key=value`` / ``export key=value`` file. Never print it."""
    values = {}
    for line in pathlib.Path(path).read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        if line.startswith("export "):
            line = line[len("export ") :]
        key, _, value = line.partition("=")
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        if value:
            values[key.strip()] = value
    return values


def is_address(value):
    """True for a string that parses as an IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def is_secret_key(key, value=None):
    """True for a leaf holding key material or a credential (the checks_bmc rule).

    Annotations (``AuthenticationKey@Redfish.OptionalOnCreate``) describe a
    property and never hold its value. YANG leaves are kebab-case
    (``sha256-password``) and stay with the text rules, as they always have.
    """
    name = str(key)
    if "@" in name:
        return False
    lowered = name.lower()
    if lowered in SECRET_NAMES:
        return True
    return (
        lowered.endswith("password")
        and "-" not in name
        and not isinstance(value, (bool, int, float))
    )


def is_generic_host(name):
    """True for a vendor default hostname (``xcc``, ``localhost`` ...): it names nobody."""
    return str(name).lower() in GENERIC_HOSTS


def is_word_host(name):
    """True for a host matched as a whole token in its own spelling, not as a substring.

    A vendor default is also a product word (``xcc`` in ``XCC Web``) and a
    short name is also a word; either would rewrite text it does not name.
    """
    return is_generic_host(name) or len(name) < 5


def is_placeholder(value):
    """True for a value that stands for "nothing here" (``N/A``, ``0000000``, a marker)."""
    stripped = value.strip()
    if not stripped or stripped in _MARKERS or _PLACEHOLDER_TOKEN.match(stripped):
        return True
    if stripped.lower() in _PLACEHOLDER_VALUES:
        return True
    return len(set(stripped)) == 1 or not any(char.isalnum() for char in stripped)


def log_user_names(message):
    """Account names a Lenovo log message carries (the BMC's own actors and markers excluded)."""
    names = set()
    if not isinstance(message, str):
        return names
    for pattern in LOG_USER_PATTERNS:
        for name in pattern.findall(message):
            if _ACCOUNT.match(name) and name.lower() not in SYSTEM_ACTORS:
                names.add(name)
    return names


def _serial_like(token):
    """A token a text names as a serial: 4+ characters with a digit, not a placeholder."""
    return len(token) >= 4 and any(char.isdigit() for char in token) and not is_placeholder(token)


class Sanitizer:
    """Rewrites text and JSON with one consistent mapping (see the module doc)."""

    def __init__(
        self,
        *,
        hosts=None,
        users=(),
        serials=(),
        nets=None,
        secrets=None,
        salt="nautobot-testsuite",
        mapping=None,
        people=(),
    ):
        self.salt = salt
        self.hosts = dict(hosts or {})
        self.users = list(users)
        self.nets = {}
        for src, dst in (nets or {}).items():
            self.nets[ipaddress.ip_network(src, strict=False)] = ipaddress.ip_network(
                dst, strict=False
            )
        # {real: fake} for the categories a later run may reuse; credentials
        # are deliberately not part of it.
        self.map = {category: {} for category in _CATEGORIES}
        if mapping:
            for category, pairs in mapping.items():
                if category in self.map or category in _LAZY_CATEGORIES:
                    self.map.setdefault(category, {}).update(pairs)
        for src, dst in self.map["nets"].items():
            self.nets.setdefault(
                ipaddress.ip_network(src, strict=False), ipaddress.ip_network(dst, strict=False)
            )
        # Credentials: (compiled pattern, replacement); values never leave here.
        self._secrets = []
        self._credentials = set()
        self._env_users = set()
        env_hosts = []
        for key, value in (secrets or {}).items():
            lowered = key.strip().lower()
            if is_address(value) or lowered in _ENV_HOST_KEYS:
                if not is_address(value):
                    env_hosts.append(value)
                continue  # an address is invented by the address rules, never REDACTED
            if lowered in _ENV_USER_KEYS:
                replacement = USER_PLACEHOLDER
                self._env_users.add(value)
            else:
                replacement = SECRET_PLACEHOLDER
            self._credentials.add(value)
            if value in ROLE_WORDS and lowered in _ENV_USER_KEYS:
                continue  # a factory login named like a role: leaves only (see ROLE_WORDS)
            self._secrets.append((re.compile(_TOKEN_EDGE % re.escape(value)), replacement))
        self._secrets.sort(key=lambda item: -len(item[0].pattern))
        self._forget_credentials()
        for real, fake in self.hosts.items():
            self.map["hosts"][real] = fake
        for name in self.users:
            if name not in self._credentials:
                self.map["users"][name] = USER_PLACEHOLDER
        self._used_serials = set(self.map["serials"].values())
        self._used_serials.update(self.map.get("assets", {}).values())
        self._used_macs = set(self.map["macs"].values())
        self._used_uuids = set(self.map.get("uuids", {}).values())
        self._used_users = set(self.map["users"].values())
        self._used_hosts = set(self.map["hosts"].values())
        self._models = set()
        self._pending_boot = []
        self._rules_key = None
        self._host_rules = []
        self._learned = None
        self._learned_lookup = {}
        for serial in serials:
            self.map["serials"].setdefault(serial, self._invent_serial(serial))
            self._used_serials.add(self.map["serials"][serial])
        for name in sorted(set(people)):
            self.person(name)
        for value in env_hosts:
            self.hostname(value)

    def _category(self, name):
        return self.map.setdefault(name, {})

    def _forget_credentials(self):
        """Drop any mapping entry whose real side is a credential (a reused mapping file)."""
        for pairs in self.map.values():
            for value in self._credentials & set(pairs):
                del pairs[value]

    def export_map(self):
        """The mapping to write: every category, never a credential."""
        self._forget_credentials()
        return {category: dict(pairs) for category, pairs in self.map.items()}

    # -- inventions -----------------------------------------------------------

    def _invent_serial(self, serial, kind="serial"):
        digest = _digest(self.salt, kind, serial)
        letters = "ABCDEFGHJKLMNPQRSTUVWXYZ"
        alnum = "ABCDEFGHJKLMNPQRSTUVWXYZ0123456789"
        # a three-letter site prefix (FOC, DCC ...) names a factory, not a unit
        keep = 3 if kind == "serial" and serial[:3].isalpha() and len(serial) >= 8 else 0
        chars = []
        for index, char in enumerate(serial):
            byte = digest[index % len(digest)]
            if index < keep:
                chars.append(char.upper() if char.isascii() else char)
            elif char.isdigit():
                chars.append(str(byte % 10))
            elif char.isalpha():
                fake = letters[byte % len(letters)]
                chars.append(fake.lower() if char.islower() else fake)
            elif char.isalnum():
                chars.append(alnum[byte % len(alnum)])
            else:
                chars.append(char)
        return "".join(chars)

    def serial(self, real):
        if real in self._used_serials:
            return real  # already an invention: a second pass is a no-op
        fake = self.map["serials"].get(real)
        if fake is None:
            fake = self._invent_serial(real)
            attempt = 0
            while fake in self._used_serials and fake != real:
                attempt += 1
                fake = self._invent_serial("%s#%d" % (real, attempt))[: len(real)]
            self.map["serials"][real] = fake
            self._used_serials.add(fake)
        return fake

    def serial_leaf(self, value):
        """A serial named by its key, any shape: learned when long enough to find in text."""
        if not isinstance(value, str) or is_placeholder(value):
            return value
        if " " in value.strip() and not any(char.isdigit() for char in value):
            return value  # a phrase ("System Serial Number"): a vendor placeholder, not a unit
        if len(value) >= _MIN_LEARNED:
            return self.serial(value)
        if value in self._used_serials:
            return value
        return self._invent_serial(value)

    def asset(self, value, kind="asset"):
        """An asset tag (or a phone number) -> an invention of the same letter/digit pattern."""
        if not isinstance(value, str) or is_placeholder(value) or value in self._used_serials:
            return value
        assets = self._category("assets")
        fake = assets.get(value)
        if fake is None:
            fake = self._invent_serial(value, kind=kind)
            attempt = 0
            while fake in self._used_serials and fake != value:
                attempt += 1
                fake = self._invent_serial("%s#%d" % (value, attempt), kind=kind)[: len(value)]
            if len(value) < _MIN_LEARNED:
                return fake  # invented where it stands, never searched for in text
            assets[value] = fake
            self._used_serials.add(fake)
        return fake

    def _invent_mac(self, digits, attempt=0):
        key = digits if not attempt else "%s#%d" % (digits, attempt)
        digest = _digest(self.salt, "mac", key)
        first = (digest[0] & 0xFC) | (int(digits[:2], 16) & 0x03)
        return "%02x" % first + digest[1:6].hex()

    def mac_digits(self, real_digits):
        """12 lower-case hex digits -> invented digits; group and protocol MACs unchanged."""
        digits = real_digits.lower()
        if int(digits[:2], 16) & 0x01 or digits.startswith(_PROTOCOL_MACS) or digits == _NO_MAC:
            return digits
        if digits in self._used_macs:
            return digits  # already an invention: a second pass is a no-op
        fake = self.map["macs"].get(digits)
        if fake is None:
            fake = self._invent_mac(digits)
            attempt = 0
            while fake in self._used_macs:
                attempt += 1
                fake = self._invent_mac(digits, attempt)
            self.map["macs"][digits] = fake
            self._used_macs.add(fake)
        return fake

    def _invent_uuid(self, digits, attempt=0):
        key = digits if not attempt else "%s#%d" % (digits, attempt)
        nibbles = list(_digest(self.salt, "uuid", key)[:16].hex())
        nibbles[12] = digits[12]  # the version
        variant = int(digits[16], 16)
        if not variant & 0x8:
            kept = 0x8  # 0xxx: NCS
        elif not variant & 0x4:
            kept = 0xC  # 10xx: RFC 4122 / 9562
        else:
            kept = 0xE  # 110x Microsoft, 111x reserved
        nibbles[16] = "%x" % ((variant & kept) | (int(nibbles[16], 16) & ~kept & 0xF))
        out = "".join(nibbles)
        return "-".join((out[:8], out[8:12], out[12:16], out[16:20], out[20:]))

    def uuid(self, real):
        """One UUID -> its invention (version nibble, variant bits and case kept)."""
        key = real.lower()
        digits = key.replace("-", "")
        if digits in _NIL_UUIDS or key in self._used_uuids:
            return real
        uuids = self._category("uuids")
        fake = uuids.get(key)
        if fake is None:
            fake = self._invent_uuid(digits)
            attempt = 0
            while fake in self._used_uuids:
                attempt += 1
                fake = self._invent_uuid(digits, attempt)
            uuids[key] = fake
            self._used_uuids.add(fake)
        return fake.upper() if real.isupper() else fake

    def person(self, name):
        """A person's or an account's name -> a distinct ``user-lab-<n>`` (the capture: netops)."""
        if not isinstance(name, str) or not name or name in _MARKERS:
            return name
        if name in self._env_users:
            return USER_PLACEHOLDER  # the capture account; never written to the mapping
        users = self.map["users"]
        fake = users.get(name)
        if fake is not None:
            return fake
        if name in self._used_users or name == USER_PLACEHOLDER:
            return name  # already an invention
        if _EMAIL.fullmatch(name):
            return self.email(name)
        taken = [int(v[len("user-lab-") :]) for v in self._used_users if _is_numbered(v, "user")]
        fake = USER_INVENTION % (max(taken, default=0) + 1)
        users[name] = fake
        self._used_users.add(fake)
        return fake

    def email(self, value):
        """An e-mail address -> ``<its user's invention>@example.com`` (or the domain's)."""
        if not isinstance(value, str) or not value or value in _MARKERS:
            return value
        match = _EMAIL.fullmatch(value)
        if match is None:
            return self.person(value)
        users = self.map["users"]
        if value in users:
            return users[value]
        if value in self._used_users:
            return value
        local, domain = match.groups()
        fake_local = self.person(local)
        fake_domain = domain if _DOC_DOMAINS.search(domain) else self._domain(domain, EMAIL_DOMAIN)
        fake = "%s@%s" % (fake_local, fake_domain)
        if local not in self._env_users:
            users[value] = fake
        self._used_users.add(fake)
        return fake

    def _domain(self, domain, invention=DOMAIN_INVENTION):
        """A real DNS domain -> its invention, registered when specific enough to search for."""
        hosts = self.map["hosts"]
        for real, fake in hosts.items():
            if real.lower() == domain.lower():
                return fake
        if domain in self._used_hosts or _DOC_DOMAINS.search(domain):
            return domain
        if "." in domain and not is_generic_host(domain):
            hosts[domain] = invention
            self._used_hosts.add(invention)
        return invention

    def hostname(self, value):
        """A hostname or FQDN leaf -> ``bmc-lab-<n>`` / ``bmc-lab-<n>.lab.example``."""
        if not isinstance(value, str) or is_placeholder(value) or value.lower() in _NO_NAMES:
            return value
        if is_address(value):
            return self.text(value)
        hosts = self.map["hosts"]
        if value in hosts:
            return hosts[value]
        for real, fake in hosts.items():
            if real.lower() == value.lower():
                return fake
        if value in self._used_hosts:
            return value
        label, dot, domain = value.partition(".")
        if dot and label and domain:
            fake = "%s.%s" % (self.hostname(label), self._domain(domain))
        else:
            taken = [int(v[len("bmc-lab-") :]) for v in self._used_hosts if _is_numbered(v, "bmc")]
            fake = HOST_INVENTION % (max(taken, default=0) + 1)
        hosts[value] = fake
        self._used_hosts.add(fake)
        return fake

    def phone(self, value):
        """A phone number -> an invented number of the same pattern (``+1 555 0100`` shape)."""
        return self.asset(value, kind="phone")

    def domain_leaf(self, value):
        """A DomainName leaf -> ``lab.example`` (a vendor default stays)."""
        if not isinstance(value, str) or is_placeholder(value) or is_generic_host(value):
            return value
        return self._domain(value)

    def _net_for(self, address):
        for src, dst in self.nets.items():
            if address in src:
                return src, dst
        block = ipaddress.ip_network("%s/24" % address, strict=False)
        digest = _digest(self.salt, "net", str(block))
        third = digest[0]
        dst = ipaddress.ip_network("198.18.%d.0/24" % third)
        taken = set(self.nets.values())
        attempt = 1
        while dst in taken:
            dst = ipaddress.ip_network("198.18.%d.0/24" % ((third + attempt) % 256))
            attempt += 1
        self.nets[block] = dst
        self.map["nets"][str(block)] = str(dst)
        return block, dst

    def ipv4(self, text):
        try:
            address = ipaddress.ip_address(text)
        except ValueError:
            return text
        for net in _UNTOUCHED_NETS:
            if address in net:
                return text
        fake = self.map["ips"].get(text)
        if fake is None:
            src, dst = self._net_for(address)
            offset = int(address) - int(src.network_address)
            fake = str(dst.network_address + (offset % dst.num_addresses))
            self.map["ips"][text] = fake
        return fake

    def ipv6(self, text):
        """One IPv6 address -> its invention (see rule 10); anything else unchanged."""
        try:
            address = ipaddress.IPv6Address(text)
        except ValueError:
            return text
        if any(address in net for net in _UNTOUCHED_NETS6):
            return text
        key = address.compressed
        fake = self.map["ipv6"].get(key)
        if fake is None:
            packed = bytearray(address.packed)
            if packed[11:13] == b"\xff\xfe":
                # EUI-64: the port's MAC with its universal/local bit flipped
                real = bytes([packed[8] ^ 0x02]) + bytes(packed[9:11]) + bytes(packed[13:16])
                mac = bytes.fromhex(self.mac_digits(real.hex()))
                packed[8:11] = bytes([mac[0] ^ 0x02]) + mac[1:3]
                packed[13:16] = mac[3:6]
            if address not in _IPV6_LINK_LOCAL:
                digest = _digest(self.salt, "net6", str(ipaddress.ip_network((address, 64), False)))
                packed[0:8] = _IPV6_DOC.network_address.packed[0:4] + digest[:4]
            fake = ipaddress.IPv6Address(bytes(packed)).compressed
            if fake == key:
                return text  # a link-local with a static identifier names nobody
            self.map["ipv6"][key] = fake
        return fake.upper() if text.isupper() else fake

    # -- learning -------------------------------------------------------------

    def learn(self, value):
        """Register the identifiers a payload names, without rewriting anything.

        A parsed JSON value registers what its keys name (serials of any shape,
        asset tags, hostnames, people, model words) plus every ``SN: <token>``
        and log-message user in its strings; a text registers its ``SN:``
        serials. Run it over every input before sanitizing the first one.
        """
        if isinstance(value, str):
            self._learn_text(value)
        else:
            self._learn_node(value)

    def learn_file(self, source):
        """``learn`` over one file (JSON when it parses, else text)."""
        raw = pathlib.Path(source).read_text(encoding="utf-8", errors="replace")
        if str(source).endswith(".json"):
            try:
                self._learn_node(json.loads(raw))
                return
            except ValueError:
                pass
        self._learn_text(raw)

    def _learn_text(self, text):
        for _marker, token in _SN_TOKEN.findall(text):
            if _serial_like(token):
                self.serial_leaf(token)

    def _learn_node(self, node):
        if isinstance(node, dict):
            for key, value in node.items():
                self._learn_leaf(str(key), value, node)
                self._learn_node(value)
        elif isinstance(node, list):
            for item in node:
                self._learn_node(item)
        elif isinstance(node, str):
            self._learn_text(node)

    def _learn_leaf(self, key, value, parent):
        if key.endswith(SERIAL_SUFFIX):
            rule = self.serial_leaf
        elif key in ASSET_KEYS:
            rule = self.asset
        elif key in HOST_KEYS:
            rule = self._learn_host
        elif key in DOMAIN_KEYS:
            rule = self.domain_leaf
        elif key in PERSON_KEYS:
            rule = self.person
        elif key in EMAIL_KEYS:
            rule = self.email
        elif key in PHONE_KEYS:
            rule = self.phone
        elif key in MODEL_KEYS:
            rule = self._learn_model
        elif key == "Message":
            rule = self._learn_message
        else:
            rule = None
        if self._is_boot_description(key, parent):
            rule = self._learn_boot_entry
        for text in _strings(value) if rule is not None else ():
            rule(text)

    def _learn_host(self, value):
        if not is_address(value):  # an address leaf is the address rules' business
            self.hostname(value)

    def _learn_message(self, value):
        for name in sorted(log_user_names(value)):
            self.person(name)

    def _learn_model(self, value):
        self._models.update(word.lower() for word in re.findall(r"[A-Za-z0-9]+", value))

    @staticmethod
    def _is_boot_description(key, parent):
        return key in BOOT_ORDER_KEYS or (key == "DisplayName" and "BootOptionReference" in parent)

    def _learn_boot_entry(self, value):
        """Queue a boot entry: its serial is judged once every model word is known."""
        self._pending_boot.append(value)

    def _resolve_boot_entries(self):
        """A boot entry's serial: an 8+ character token with digits that no model spells."""
        pending, self._pending_boot = self._pending_boot, []
        for entry in pending:
            for token in re.findall(r"[A-Za-z0-9]+", _UUID.sub(" ", entry)):
                if len(token) < 8 or sum(char.isdigit() for char in token) < 2:
                    continue
                if token.lower() in self._models or is_placeholder(token):
                    continue
                if re.fullmatch(r"[0-9A-Fa-f]+", token) and (len(token) == 12 or len(token) >= 16):
                    continue  # a bare MAC or a hex run: the MAC and hex rules own those
                self.serial_leaf(token)

    def _each(self, value, rule):
        """A leaf rule on a string or on every string of a list (length kept); else the walk."""
        if isinstance(value, str):
            return rule(value) if value else value
        if isinstance(value, list):
            return [self._each(item, rule) for item in value]
        if isinstance(value, dict):
            return self.json(value)
        return value

    # -- text ---------------------------------------------------------------

    def _rules(self):
        """Compiled host rules and the learned-identifier pattern, rebuilt as the mapping grows."""
        if self._pending_boot:
            self._resolve_boot_entries()
        key = (
            len(self.map["hosts"]),
            len(self.map["serials"]),
            len(self.map.get("assets", {})),
        )
        if key != self._rules_key:
            self._host_rules = []
            for real in sorted(self.map["hosts"], key=len, reverse=True):
                if is_word_host(real):
                    pattern = re.compile(_TOKEN_EDGE % re.escape(real))
                else:
                    pattern = re.compile(re.escape(real), re.IGNORECASE)
                self._host_rules.append((pattern, self.map["hosts"][real]))
            lookup = {}
            for category in ("serials", "assets"):
                for real, fake in self.map.get(category, {}).items():
                    if len(real) >= _MIN_LEARNED and not is_placeholder(real):
                        lookup.setdefault(real, fake)
            self._learned_lookup = lookup
            self._learned = None
            if lookup:
                alternatives = sorted(lookup, key=len, reverse=True)
                self._learned = re.compile("|".join(re.escape(real) for real in alternatives))
            self._rules_key = key
        return self._host_rules, self._learned

    def text(self, value):
        if not isinstance(value, str) or not value:
            return value
        out = value
        for pattern, replacement in self._secrets:
            out = pattern.sub(replacement, out)
        host_rules, learned = self._rules()
        for pattern, fake in host_rules:
            out = pattern.sub(fake, out)
        for real in sorted(self.map["users"], key=len, reverse=True):
            if real in ROLE_WORDS:
                continue
            fake = self.map["users"][real]
            out = re.sub(_TOKEN_EDGE % re.escape(real), lambda _m, fake=fake: fake, out)
        # Inventions from here to the hex and MAC rules are parked, so no later
        # rule takes a piece of one (a UUID's 12-digit tail is not a bare MAC).
        parked = [] if _PARK_OPEN not in out else None
        out = _UUID.sub(lambda m: self._park(parked, self.uuid(m.group(0))), out)
        if learned is not None:
            out = learned.sub(lambda m: self._park(parked, self._learned_fake(m.group(0))), out)
        out = _SN_TOKEN.sub(lambda m: self._sub_sn(m, parked), out)
        out = _PEM.sub(lambda m: "<pem:%d>" % len(m.group(0)), out)
        out = _HEX_0X.sub(lambda m: "<hex:%d>" % len(re.findall(r"0x", m.group(0))), out)
        out = _HEX_SEP.sub(lambda m: "<hex:%d>" % (len(m.group(0)) // 3 + 1), out)
        out = _HEX_GROUPS.sub(lambda m: "<hex:%d>" % len(re.sub(r"\s", "", m.group(0))), out)
        out = _MAC_BARE.sub(self._sub_bare, out)
        out = _HEX_RUN.sub(lambda m: "<hex:%d>" % len(m.group(0)), out)
        out = _SELF_SIGNED.sub(lambda m: m.group(1) + self._renumber(m.group(2)), out)
        out = self._serial_pattern().sub(lambda m: self.serial(m.group(0)), out)
        out = _IPV6.sub(lambda m: self.ipv6(m.group(0)), out)
        out = _MAC_DOTTED.sub(self._sub_dotted, out)
        out = _MAC_SEP.sub(self._sub_sep, out)
        out = _IPV4.sub(lambda m: self.ipv4(m.group(0)), out)
        if parked:
            out = _PARKED.sub(lambda m: parked[_park_index(m.group(1))], out)
        return out

    @staticmethod
    def _park(parked, fake):
        if parked is None:
            return fake  # the text itself carries the park marker: nothing is parked
        parked.append(fake)
        digits = "".join(chr(_PARK_DIGIT + int(d)) for d in str(len(parked) - 1))
        return _PARK_OPEN + digits + _PARK_CLOSE

    def _learned_fake(self, found):
        return self._learned_lookup[found]

    def _sub_sn(self, match, parked):
        token = match.group(2)
        if not _serial_like(token):
            return match.group(0)
        return match.group(1) + self._park(parked, self.serial_leaf(token))

    def _serial_pattern(self):
        """One pass for explicit serials and the Cisco shape, so an invention is never re-hit."""
        explicit = sorted(self.map["serials"], key=len, reverse=True)
        if not explicit:
            return _SERIAL
        return re.compile("|".join(re.escape(real) for real in explicit) + "|" + _SERIAL.pattern)

    def _renumber(self, digits):
        fake = str(int.from_bytes(_digest(self.salt, "cert", digits)[:4], "big"))
        return fake[: len(digits)].rjust(len(digits), "1")

    @staticmethod
    def _keep_case(sample, digits):
        return digits.upper() if sample.isupper() and not sample.isdigit() else digits

    def _sub_dotted(self, match):
        digits = self.mac_digits("".join(match.groups()))
        digits = self._keep_case(match.group(0), digits)
        return ".".join(digits[i : i + 4] for i in range(0, 12, 4))

    def _sub_bare(self, match):
        return self._keep_case(match.group(0), self.mac_digits(match.group(1)))

    def _sub_sep(self, match):
        sep = match.group(2)
        digits = self.mac_digits((match.group(1) + match.group(3)).replace(sep, ""))
        digits = self._keep_case(match.group(0), digits)
        return sep.join(digits[i : i + 2] for i in range(0, 12, 2))

    # -- JSON -----------------------------------------------------------------

    def json(self, value):
        if isinstance(value, dict):
            return {self.text(key): self._leaf(key, item, value) for key, item in value.items()}
        if isinstance(value, list):
            return [self.json(item) for item in value]
        return self.text(value)

    def _leaf(self, key, value, parent=None):
        if key == "router-id" and isinstance(value, int) and 0 <= value <= 0xFFFFFFFF:
            return int(ipaddress.IPv4Address(self.ipv4(str(ipaddress.IPv4Address(value)))))
        if not isinstance(key, str):
            return self.json(value)
        if is_secret_key(key, value):
            return self._redact(value)
        if key.endswith(SERIAL_SUFFIX):
            return self._each(value, self.serial_leaf)
        if key in ASSET_KEYS:
            return self._each(value, self.asset)
        if key in HOST_KEYS:
            return self._each(value, self.hostname)
        if key in DOMAIN_KEYS:
            return self._each(value, self.domain_leaf)
        if key in PERSON_KEYS:
            return self._each(value, self.person)
        if key in EMAIL_KEYS:
            return self._each(value, self.email)
        if key in PHONE_KEYS:
            return self._each(value, self.phone)
        if key in ID_KEYS:
            return self._placeholders(value, "<id:%d>")
        if key in HEX_KEYS or (key == "EngineId" and isinstance(value, str)):
            return self._each(value, _hex_placeholder)
        if key in FREE_TEXT_KEYS:
            return self._each(value, _redact_text)
        if key in ADDRESS_BLOCK_KEYS:
            return self._placeholders(value, SECRET_PLACEHOLDER)
        if _DN_KEY.search(key):
            return self._each(value, _redact_dn)
        if parent is not None and self._is_boot_description(key, parent):
            for text in _strings(value):
                self._learn_boot_entry(text)
        return self.json(value)

    def _redact(self, value):
        """Key material or a credential: null, empty and list lengths kept, content never."""
        if value is None or isinstance(value, bool) or value in ("", [], {}):
            return value
        if isinstance(value, list):
            return [self._redact(item) for item in value]
        if isinstance(value, dict):
            return {self.text(key): self._redact(item) for key, item in value.items()}
        if isinstance(value, str):
            if value in _MARKERS or _PLACEHOLDER_TOKEN.match(value):
                return value  # what the harvest's own redactor or an earlier pass left
            pem = _PEM.sub(lambda m: "<pem:%d>" % len(m.group(0)), value)
            if pem != value and not re.sub(r"<pem:\d+>|\s", "", pem):
                return pem
        return SECRET_PLACEHOLDER

    def _placeholders(self, value, template):
        """Every string leaf -> the placeholder (a ``...Type`` enum beside it stays)."""
        if isinstance(value, dict):
            return {
                self.text(key): (
                    self.json(item)
                    if str(key).endswith("Type")
                    else self._placeholders(item, template)
                )
                for key, item in value.items()
            }
        if isinstance(value, list):
            return [self._placeholders(item, template) for item in value]
        if isinstance(value, str) and value and value not in _MARKERS:
            if _PLACEHOLDER_TOKEN.match(value):
                return value
            return template % len(value) if "%d" in template else template
        return value

    def file(self, source):
        """Sanitized text of ``source``: JSON is walked when it parses, else rewritten as text."""
        raw = pathlib.Path(source).read_text(encoding="utf-8")
        if str(source).endswith(".json"):
            try:
                return json.dumps(self.json(json.loads(raw)), indent=1, sort_keys=False) + "\n"
            except ValueError:
                pass
        return self.text(raw)


def _strings(value):
    """The non-empty strings of a leaf: the string itself, or those of a (nested) list."""
    if isinstance(value, str):
        if value:
            yield value
    elif isinstance(value, list):
        for item in value:
            yield from _strings(item)


def _is_numbered(value, kind):
    """True for an invention of the ``user-lab-<n>`` / ``bmc-lab-<n>`` series."""
    return re.fullmatch(r"%s-lab-\d+" % kind, value) is not None


def _park_index(digits):
    return int("".join(str(ord(char) - _PARK_DIGIT) for char in digits))


def _hex_placeholder(value):
    """Hex bytes (``AB:CD ...``, ``ab cd ...``, a bare run) -> ``<hex:N>`` (N bytes or digits)."""
    if is_placeholder(value):
        return value
    groups = [group for group in re.split(r"[\s:-]+", value.strip()) if group]
    return "<hex:%d>" % (len(groups) if len(groups) > 1 else len(value.strip()))


def _redact_text(value):
    return value if is_placeholder(value) else SECRET_PLACEHOLDER


def _redact_dn(value):
    """An LDAP DN keeps its attribute names: ``cn=REDACTED,dc=REDACTED``."""
    if is_placeholder(value):
        return value
    return _DN_VALUE.sub(lambda m: "%s=%s" % (m.group(1), SECRET_PLACEHOLDER), value)


def _pairs(values, what):
    out = {}
    for item in values or ():
        if "=" not in item:
            raise SystemExit("--%s expects REAL=FAKE, got %r" % (what, item))
        real, fake = item.split("=", 1)
        out[real] = fake
    return out


def main(argv=None):
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("inputs", nargs="+", help="payload files (.json is walked, else text)")
    parser.add_argument("--env", help="key=value credential file; its values are scrubbed")
    parser.add_argument("--host", action="append", default=[], help="REAL=FAKE hostname")
    parser.add_argument("--user", action="append", default=[], help="user name -> netops")
    parser.add_argument("--serial", action="append", default=[], help="serial to invent")
    parser.add_argument("--net", action="append", default=[], help="SRC/24=DST/24")
    parser.add_argument("--salt", default="nautobot-testsuite", help="hash salt for inventions")
    parser.add_argument("--mapping-in", help="mapping JSON from an earlier run")
    parser.add_argument("--mapping-out", help="write the (credential-free) mapping here")
    parser.add_argument("--out-dir", help="write each input's sanitized copy here (same name)")
    args = parser.parse_args(argv)

    mapping = None
    if args.mapping_in:
        with open(args.mapping_in, encoding="utf-8") as handle:
            mapping = json.load(handle)
    sanitizer = Sanitizer(
        hosts=_pairs(args.host, "host"),
        users=args.user,
        serials=args.serial,
        nets=_pairs(args.net, "net"),
        secrets=read_env(args.env) if args.env else None,
        salt=args.salt,
        mapping=mapping,
    )
    # learn from every input before writing any: a serial a log line names may
    # only be named by a leaf in a later file
    for source in args.inputs:
        sanitizer.learn_file(source)
    for source in args.inputs:
        clean = sanitizer.file(source)
        if args.out_dir:
            target = pathlib.Path(args.out_dir) / pathlib.Path(source).name
            target.write_text(clean, encoding="utf-8")
        else:
            sys.stdout.write(clean)
    if args.mapping_out:
        with open(args.mapping_out, "w", encoding="utf-8") as handle:
            json.dump(sanitizer.export_map(), handle, indent=1, sort_keys=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
