"""The check catalog as a set of modules: which ``jobs/checks_*.py`` files exist
and which yang-library models each platform's catalog reads.

Pure (stdlib, ``registry`` only) so the CI battery can drive it through
``tests/_loader.py``; ``shakedown_job`` re-exports these names for its own
callers. The IOS-XE base list lives here because the shakedown reports it
merged with every catalog module's ``KEY_MODELS`` (first occurrence wins), so a
merged platform branch never edits the base list: a layer module's models ride
in with the module.
"""

import importlib
import os
import pkgutil

from . import registry

# Models the IOS-XE switch catalog (checks_iosxe) reads from — presence/revision
# is reported so a shakedown immediately shows which collectors CAN work on this
# image. checks_iosxe's own KEY_MODELS supersets this list with vlan-, ntp- and
# lacp-oper; every catalog module contributes its KEY_MODELS on top.
IOSXE_KEY_MODELS = (
    "ietf-routing",
    "Cisco-IOS-XE-fib-oper",
    "Cisco-IOS-XE-bgp-oper",
    "Cisco-IOS-XE-ospf-oper",
    "Cisco-IOS-XE-arp-oper",
    "Cisco-IOS-XE-cdp-oper",
    "Cisco-IOS-XE-lldp-oper",
    "Cisco-IOS-XE-interfaces-oper",
    "Cisco-IOS-XE-device-hardware-oper",
    "Cisco-IOS-XE-environment-oper",
    "Cisco-IOS-XE-platform-software-oper",
    "Cisco-IOS-XE-matm-oper",
    "Cisco-IOS-XE-switch-cp-svl-oper",
    # iosxe_switch_stack's per-member serial source, plus the reload-reason
    # each stack-node carries (per member or stack-wide: still unverified);
    # leaf spellings field-verified on a 4-member 9300. Where it is absent,
    # the check falls back to `show inventory` for member serials.
    "Cisco-IOS-XE-stack-oper",
)

# Per-platform base lists; only IOS-XE has a yang-library to check against today.
PLATFORM_KEY_MODELS = {"iosxe": IOSXE_KEY_MODELS}


def catalog_modules():
    """Every ``jobs/checks_*.py`` module, in name order — jobs/__init__.py's loop."""
    modules = []
    for entry in sorted(pkgutil.iter_modules([os.path.dirname(__file__)]), key=lambda e: e.name):
        if entry.name.startswith("checks_"):
            modules.append(importlib.import_module("." + entry.name, __package__))
    return modules


def catalog_key_models(platform):
    """yang-library module names the platform's catalog reads, order-stable, de-duplicated.

    The platform's base list comes first, then the ``KEY_MODELS`` of every
    catalog module that registers a check for this platform, in module-name
    order (a module without the attribute contributes nothing, and one whose
    attribute is a bare string is read as a one-model list, never spliced
    into characters; another platform's catalog never leaks in). First
    occurrence wins, so a model two modules both read is reported once.
    """
    owners = {check.collector.__module__ for check in registry.checks_for(platform)}
    models = list(PLATFORM_KEY_MODELS.get(platform, ()))
    for module in catalog_modules():
        if module.__name__ in owners:
            declared = getattr(module, "KEY_MODELS", ())
            models.extend([declared] if isinstance(declared, str) else declared)
    ordered = []
    for model in models:
        if model not in ordered:
            ordered.append(model)
    return tuple(ordered)
