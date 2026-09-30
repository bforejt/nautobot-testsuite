"""Which interface of a host Device is its BMC, and which address reaches it.

Pure (stdlib and ``constants`` only), so the CI battery tests the rule
without Nautobot; the capture and shakedown jobs read the interface names and
their assigned addresses from the ORM and hand them here.

The rule (docs/plans/bmc-capture-handoff.md §2): an interface whose name's
FIRST WORD is a BMC token IS the server's baseboard management controller.
Words are split on anything that is not a letter or a digit; the first word
is lower-cased and its trailing digits dropped before the lookup, so ``xcc``,
``XCC-mgmt``, ``iLO 5``, ``idrac-1`` and ``bmc0`` match while ``mgmt-xcc``
(first word ``mgmt``) and ``eth0`` do not. Exactly one interface per device
may match: two matches are an ambiguous model, and the capture refuses the
device before any transport opens rather than pick one silently. The BMC is
reached on the interface's lowest IPv4 address (the lowest IPv6 when it has
no IPv4), a link-local address only when it carries nothing else; every
address it carries is named in the envelope.
"""

import ipaddress
import re
from dataclasses import dataclass

from . import constants as C

_WORD_SPLIT = re.compile(r"[^A-Za-z0-9]+")


class AmbiguousBmc(ValueError):
    """More than one interface of a device matches the BMC naming rule."""


def match_bmc_interface(name, tokens=C.BMC_INTERFACE_NAMES):
    """The BMC token an interface name's first word matches, else None."""
    words = [word for word in _WORD_SPLIT.split(str(name or "")) if word]
    if not words:
        return None
    first = words[0].lower().rstrip("0123456789")
    return first if first in tokens else None


def _as_ip(text):
    """ipaddress object for ``10.0.0.5``, ``10.0.0.5/24`` or an IPv6 spelling; None otherwise."""
    try:
        return ipaddress.ip_interface(str(text).strip()).ip
    except ValueError:
        return None


def pick_address(addresses):
    """(chosen, every usable address in preference order), both as strings.

    IPv4 before IPv6, then the lowest address — but a link-local address
    (169.254/16, fe80::/10: a BMC's USB-LAN side, never its management port)
    only when nothing else is assigned. Duplicates and anything that does not
    parse as an address are dropped. ``(None, [])`` when nothing is usable.
    """
    parsed = {ip for ip in (_as_ip(item) for item in addresses or ()) if ip is not None}
    ordered = sorted(parsed, key=lambda ip: (ip.is_link_local, ip.version, int(ip)))
    if not ordered:
        return None, []
    return str(ordered[0]), [str(ip) for ip in ordered]


@dataclass(frozen=True)
class BmcTarget:
    """The modelled BMC of one device: which interface, which token, which address."""

    interface_name: str
    token: str
    address: object = None  # str, or None when the interface carries no usable address
    addresses_seen: tuple = ()
    interface_id: object = None


def find_bmc(interfaces):
    """The device's one BMC interface as a BmcTarget, or None when no interface matches.

    ``interfaces`` yields ``(name, addresses, interface_id)`` tuples. Raises
    AmbiguousBmc naming every match when more than one interface matches.
    """
    matches = []
    for name, addresses, interface_id in interfaces:
        token = match_bmc_interface(name)
        if token is not None:
            matches.append((str(name), token, list(addresses or ()), interface_id))
    if not matches:
        return None
    if len(matches) > 1:
        raise AmbiguousBmc(
            "%d interfaces match the BMC naming rule (%s) — exactly one per device may be "
            "named for its BMC; rename the others so their first word is not one of %s"
            % (
                len(matches),
                ", ".join(sorted(match[0] for match in matches)),
                "/".join(C.BMC_INTERFACE_NAMES),
            )
        )
    name, token, addresses, interface_id = matches[0]
    chosen, seen = pick_address(addresses)
    return BmcTarget(
        interface_name=name,
        token=token,
        address=chosen,
        addresses_seen=tuple(seen),
        interface_id=interface_id,
    )


def bmc_block(target, *, captured, note=None, vendor=None, product=None, transport="redfish"):
    """The envelope's ``device.bmc`` dict for ``target``; None when no BMC is modelled.

    ``captured`` says whether the BMC family ran against the address (its
    checks may still have failed individually); ``note`` explains a BMC that
    was modelled but not captured. ``vendor``/``product`` are what the BMC's
    service root reported, when a check read it.
    """
    if target is None:
        return None
    return {
        "interface": target.interface_name,
        "token": target.token,
        "address": target.address,
        "addresses_seen": list(target.addresses_seen),
        "transport": transport if target.address else None,
        "vendor": vendor,
        "product": product,
        "captured": bool(captured),
        "note": note,
    }
