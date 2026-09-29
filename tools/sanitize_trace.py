#!/usr/bin/env python3
"""Sanitize captured device payloads into committable fixtures — deterministic,
mapping-preserving, stdlib only.

A shakedown trace or a lab harvest carries what a snapshot must never carry
into the repo: real hostnames, addresses, MACs, chassis serials, user names,
certificate material and the credentials of the capture session. This tool
rewrites every one of them so that the SHAPE the parser sees is unchanged
(a dotted MAC stays dotted, a serial keeps its letter/digit pattern, a /23
keeps its host octets) while nothing identifies the site any more. The same
real value always maps to the same invented value, within one run and across
runs that share a mapping file, so a fixture set harvested from ten payloads
stays internally consistent (the MAC in the CDP table is the MAC in the MAC
table) and a later re-harvest diffs cleanly against the last one.

Usage (from the repository root):

    python3 tools/sanitize_trace.py \\
        --env /path/to/device.env \\
        --host sw-real-01=sw-lab-1 --host AP0000.1111.2222=ap-lab-1 \\
        --user someone \\
        --net 10.0.0.0/24=192.0.2.0/24 --net 10.0.1.0/24=198.51.100.0/24 \\
        --mapping-out /tmp/sanitize-map.json \\
        --out-dir tests/fixtures  payload-a.json  show-b.txt ...

    python3 tools/sanitize_trace.py --mapping-in /tmp/sanitize-map.json one.json > one.clean.json

What is rewritten, in this order (earlier rules win where they overlap):

1. **Credentials** — every value in the ``--env`` file (``key=value`` lines,
   the capture session's own secrets). The value under the ``user`` key
   becomes ``netops``; every other value becomes ``REDACTED``. Matched only
   as a whole word that is not part of a hyphenated token, so a user named
   ``admin`` never eats the YANG leaf ``admin-status``. The values are never
   printed, logged or written to the mapping file.
2. **Hostnames** given with ``--host REAL=FAKE`` (case-insensitive, longest
   first). A CDP/LLDP device id that embeds a MAC (``AP0000.1111.2222``) is
   listed here so the whole id maps, not just the MAC inside it.
3. **User names** given with ``--user NAME`` -> ``netops`` (same word rule).
4. **Certificate material**: PEM bodies, hex fingerprints, IOS certificate
   chain bodies (lines of 8-digit hex groups) and any hex run of 16+ digits
   (with or without ``:``/space separators, ``0x``-prefixed dumps included)
   -> a short placeholder that keeps the length class visible (``<hex:64>``).
   Self-signed trustpoint and certificate names carry the chassis identity in
   their numeric suffix and are renumbered.
5. **Serials**: every token of the Cisco shape (three letters, four digits,
   four alphanumerics: ``ABC1234D5EF``) plus any ``--serial`` value -> an
   invented token with the same letter/digit pattern, distinct per source.
6. **MACs** in dotted, colon, dash or bare 12-digit spelling -> an invented MAC in the same
   spelling and case, keeping the multicast and locally-administered bits of
   the first octet. Group addresses (multicast bit set: STP, CDP, IPv4
   multicast, broadcast), the protocol blocks (VRRP, HSRP virtual MACs) and
   the all-zero MAC (no partner, no address) identify nobody and are left alone.
7. **IPv4 addresses**: ``--net SRC/24=DST/24`` pairs map a real /24 onto a
   documentation /24 with the host octet kept; any other real /24 lands
   deterministically in 198.18.0.0/16 (RFC 2544 benchmarking space) with its
   host octet kept. Addresses in 0/8, 127/8, 224/4 and 240/4 (masks,
   wildcards, loopback, multicast, broadcast) and the RFC 5737 documentation
   ranges are never touched, so a netmask stays a netmask. A JSON
   ``router-id`` leaf served as an integer (the OSPF and EIGRP models type it
   uint32) is the same address in host order and maps through the same rule.
8. **IPv6 addresses**: an EUI-64 interface identifier (``...ff:fe...``)
   embeds the port's MAC, so it is rebuilt from that MAC's invention (rule 6:
   the link-local of a CDP neighbour is the same device as its MAC table row);
   any other identifier is kept. A global or unique-local /64 prefix lands
   deterministically in 2001:db8::/32 (RFC 3849 documentation space); the
   link-local prefix ``fe80::/10``, the unspecified and loopback addresses,
   multicast ``ff00::/8`` and the documentation range are never touched. The
   spelling (compressed form, upper or lower case) is preserved.

JSON inputs are walked (keys and string values); anything else is treated as
text. The mapping file lists real -> invented for hostnames, users, serials,
MACs, networks and IPv6 addresses (never credentials) so a later run can reuse
it; keep it beside the raw payloads, outside the repository.
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
        self.map = {
            "hosts": {},
            "users": {},
            "serials": {},
            "macs": {},
            "nets": {},
            "ips": {},
            "ipv6": {},
        }
        if mapping:
            for category, pairs in mapping.items():
                if category in self.map:
                    self.map[category].update(pairs)
        for src, dst in self.map["nets"].items():
            self.nets.setdefault(
                ipaddress.ip_network(src, strict=False), ipaddress.ip_network(dst, strict=False)
            )
        for real, fake in self.hosts.items():
            self.map["hosts"][real] = fake
        for name in self.users:
            self.map["users"][name] = USER_PLACEHOLDER
        for serial in serials:
            self.map["serials"].setdefault(serial, self._invent_serial(serial))
        # Credentials: (compiled pattern, replacement); values never leave here.
        self._secrets = []
        for key, value in (secrets or {}).items():
            replacement = USER_PLACEHOLDER if key == "user" else SECRET_PLACEHOLDER
            self._secrets.append((re.compile(_TOKEN_EDGE % re.escape(value)), replacement))
        self._secrets.sort(key=lambda item: -len(item[0].pattern))
        self._used_serials = set(self.map["serials"].values())
        self._used_macs = set(self.map["macs"].values())

    # -- inventions -----------------------------------------------------------

    def _invent_serial(self, serial):
        digest = _digest(self.salt, "serial", serial)
        letters = "ABCDEFGHJKLMNPQRSTUVWXYZ"
        alnum = "ABCDEFGHJKLMNPQRSTUVWXYZ0123456789"
        chars = []
        for index, char in enumerate(serial):
            byte = digest[index % len(digest)]
            if index < 3 and char.isalpha():
                chars.append(serial[index].upper())  # keep the site prefix (FOC, DCC ...)
            elif char.isdigit():
                chars.append(str(byte % 10))
            elif char.isalpha():
                chars.append(letters[byte % len(letters)])
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
        """One IPv6 address -> its invention (see rule 8); anything else unchanged."""
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

    # -- text ---------------------------------------------------------------

    def text(self, value):
        if not isinstance(value, str) or not value:
            return value
        out = value
        for pattern, replacement in self._secrets:
            out = pattern.sub(replacement, out)
        for real in sorted(self.map["hosts"], key=len, reverse=True):
            out = re.sub(re.escape(real), self.map["hosts"][real], out, flags=re.IGNORECASE)
        for real in sorted(self.map["users"], key=len, reverse=True):
            out = re.sub(_TOKEN_EDGE % re.escape(real), USER_PLACEHOLDER, out)
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
        return out

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
            return {self.text(key): self._leaf(key, item) for key, item in value.items()}
        if isinstance(value, list):
            return [self.json(item) for item in value]
        return self.text(value)

    def _leaf(self, key, value):
        if key == "router-id" and isinstance(value, int) and 0 <= value <= 0xFFFFFFFF:
            return int(ipaddress.IPv4Address(self.ipv4(str(ipaddress.IPv4Address(value)))))
        return self.json(value)

    def file(self, source):
        """Sanitized text of ``source``: JSON is walked when it parses, else rewritten as text."""
        raw = pathlib.Path(source).read_text(encoding="utf-8")
        if str(source).endswith(".json"):
            try:
                return json.dumps(self.json(json.loads(raw)), indent=1, sort_keys=False) + "\n"
            except ValueError:
                pass
        return self.text(raw)


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
    for source in args.inputs:
        clean = sanitizer.file(source)
        if args.out_dir:
            target = pathlib.Path(args.out_dir) / pathlib.Path(source).name
            target.write_text(clean, encoding="utf-8")
        else:
            sys.stdout.write(clean)
    if args.mapping_out:
        with open(args.mapping_out, "w", encoding="utf-8") as handle:
            json.dump(sanitizer.map, handle, indent=1, sort_keys=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
