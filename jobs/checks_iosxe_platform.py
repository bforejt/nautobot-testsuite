"""Catalyst platform persistence, licensing, PKI and forwarding-table capacity
(IOS-XE, RESTCONF with SSH ``show`` only where no model answers).

Four checks, all always-on, registered under the ``iosxe`` platform:

* ``iosxe_persistence`` — would a reload bring back what runs now? The
  cached device-hardware read (``unsaved-config``, ``software-version``,
  ``rommon-version``), one filtered GET of ``install-oper``'s
  ``install-location-information`` (image versions, commit state, the
  auto-abort timer, boot mode) and ``show sdm prefer`` (the SDM template has
  no operational model).
* ``iosxe_license`` — the licence level in effect and its status from
  ``cisco-smart-license`` ``licensing/state``; ``show license summary`` only
  when the model is not served.
* ``iosxe_pki`` — trustpoints and certificates from ``crypto-pki-oper``;
  ``show crypto pki certificates`` when the model is not served or answers a
  server error (the lab 9300 answers HTTP 500 on the container).
* ``iosxe_tcam`` — forwarding-table utilisation from ``tcam-oper`` and
  ``switch-dp-resources-oper``: capacity and banded utilisation normalized,
  the readings in context.

Every path, leaf and enum below was checked against the 17.15.1 models on
disk (Cisco-IOS-XE-install-oper rev 2024-03-01, Cisco-IOS-XE-device-hardware-
oper rev 2024-07-10, cisco-smart-license rev 2021-03-01, Cisco-IOS-XE-crypto-
pki-oper rev 2022-11-01, Cisco-IOS-XE-tcam-oper rev 2023-07-01, Cisco-IOS-XE-
switch-dp-resources-oper rev 2022-11-01) and the normalizers against what the
9300 lab actually returned:

* ``device-system-data`` fills ``unsaved-config`` on the lab release; on a
  release that does not serve the leaf ``config_saved`` is None, never False.
* ``install-location-information`` carried one row (``fru-rp/0/0``, chassis
  1) with two versions, neither ``is-default``; ``commit-type`` and
  ``boot-mode`` were not filled; the idle auto-abort timer reads
  ``install-timer-state-unknown``, not inactive.
* ``licensing/state`` filled ``usage`` (network-essentials, dna-essentials)
  with ``enforcement-invalid-tag`` on an unregistered switch.
* ``crypto-pki-oper-data`` answered HTTP 500; the CLI listed the SUDI chain,
  the self-signed certificate and the licensing root.
* ``tcam-details`` served 40 rows over four ASIC numbers; the dp-resources
  container is 109 KB unfiltered (its per-instance table data), so it is
  read with a ``fields`` filter and cut to feature level in raw.

Nothing here requests, parses or stores a username, a device hostname, a
licence key or token, a certificate fingerprint in normalized, or the smart
licensing UDI beyond what identity already carries (raw keeps a projection of
the licensing state without ``udi``, account names or report keys).
"""

import datetime
import re

from . import iosxe_common as common
from .registry import SEMANTICS as _REGISTRY_SEMANTICS
from .registry import CheckDef, CollectError, SkipCheck, register

# --- paths, filters and commands ---------------------------------------------

# Rec. 1's filter, exactly as the lab harvest issued it (accepted by the lab):
# the list key, each version's state and commit trigger, the abort timer and
# the boot mode. Unfiltered on HTTP 400 (the same list, more leaves).
_INSTALL_PATH = "/data/Cisco-IOS-XE-install-oper:install-oper-data/install-location-information"
_INSTALL_FIELDS = (
    "fru;slot;bay;chassis;install-version-info(version;is-default;current;commit-type);"
    "oper-state(auto-abort-timer;boot-mode)"
)
_SDM_COMMAND = "show sdm prefer"

# Smart licensing state: the agent flags, registration and authorization
# states, the evaluation period, the transport type, per-licence usage and
# (SLP releases) the policy. The udi container, account names, trust codes,
# RUM report keys and factory-purchase lists are never requested; a release
# that rejects the filter answers unfiltered and raw is projected to the same
# leaves (see _license_raw).
_LICENSE_PATH = "/data/cisco-smart-license:licensing/state"
_LICENSE_FIELDS = (
    "always-enabled;smart-enabled;version;state-info(registration(registration-state;"
    "export-control-allowed;registration-complete(complete-time;expire-time;"
    "last-renew-success));authorization;evaluation;transport(transport-type);"
    "usage(entitlement-tag;short-name;license-name;description;count;enforcement-mode;"
    "post-paid);policy(policy-type;policy-name))"
)
_LICENSE_COMMAND = "show license summary"

_PKI_PATH = "/data/Cisco-IOS-XE-crypto-pki-oper:crypto-pki-oper-data"
_PKI_FIELDS = (
    "crypto-pki-bundle(label;mode;tp-authenticated;tp-keys-generated;tp-enrolled;"
    "cert(cert-avail;cert-usage;cert-key-type;subject-name;issuer-name;validity-start;"
    "validity-end;asc-tp))"
)
_PKI_COMMAND = "show crypto pki certificates"

_TCAM_PATH = "/data/Cisco-IOS-XE-tcam-oper:tcam-details"
_DP_PATH = "/data/Cisco-IOS-XE-switch-dp-resources-oper:switch-dp-resources-oper-data"
_DP_FIELDS = (
    "location(fru;slot;bay;chassis;node;dp-feature-resource(feature;protocol;direction;"
    "max-tcam-percentage-used;max-em-percentage-used;max-acl-ids-percentage-used;"
    "max-lpm-percentage-used))"
)

# yang-library module names the shakedown reports, so a switch shakedown
# shows at once whether these collectors CAN work on the image.
KEY_MODELS = (
    "Cisco-IOS-XE-device-hardware-oper",
    "Cisco-IOS-XE-install-oper",
    "cisco-smart-license",
    "Cisco-IOS-XE-crypto-pki-oper",
    "Cisco-IOS-XE-tcam-oper",
    "Cisco-IOS-XE-switch-dp-resources-oper",
)

# Utilisation band edges (percent used, inclusive lower bound) for the tcam
# check's normalized view; the reading itself carries the tolerance.
_BANDS = ((90.0, "critical"), (80.0, "high"), (50.0, "moderate"), (0.0, "low"))
# used_pct tolerance: five percentage points either way (an absolute band on
# a percentage; a relative band would flag any first entry in an empty region).
_USED_PCT_TOLERANCE = 5.0
# Certificates whose remaining validity is at or under this many days are
# counted as expiring in context.
_EXPIRY_HORIZON_DAYS = 90

# --- shared helpers (jobs/iosxe_common) --------------------------------------

_aslist = common.aslist
_entries = common.entries
_sub = common.sub
_to_int = common.to_int
_to_float = common.to_float
_yes = common.yes
_short = common.short
_text_or_none = common.text_or_none


def _rows(node_, name):
    """The dict entries of list ``name`` inside a container node."""
    return [entry for entry in _aslist((node_ or {}).get(name)) if isinstance(entry, dict)]


def _server_error(exc):
    """True for a RESTCONF error whose HTTP status is a server-side failure (5xx)."""
    status = getattr(exc, "status_code", None)
    return isinstance(status, int) and 500 <= status <= 599


def _utc_now():
    return datetime.datetime.now(datetime.timezone.utc)


# A yang:date-and-time -> aware UTC datetime (shared: platform health keys the
# boot time by it too).
_parse_iso = common.parse_iso


def _iso_utc(stamp):
    """'YYYY-MM-DDTHH:MM:SSZ' for an aware datetime; None for None."""
    if stamp is None:
        return None
    return stamp.astimezone(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _utc_text(value):
    """A model timestamp normalized to '...Z'; the text itself when it does not parse."""
    stamp = _parse_iso(value)
    return _iso_utc(stamp) if stamp is not None else _text_or_none(value)


def _days_until(stamp, now):
    """Whole days from ``now`` to ``stamp`` (negative once past); None when unknown."""
    if stamp is None or now is None:
        return None
    return int((stamp - now).total_seconds() // 86400)


# =============================================================================
# iosxe_persistence
# =============================================================================

_VERSION_WORD = re.compile(r"\bVersion\s+([^\s,]+)", re.IGNORECASE)
# "This is the Access template." / 'This is the "Advanced" template.'
_SDM_CURRENT = re.compile(r"This is the\s+\"?([^\"\n]+?)\"?\s+template\b", re.IGNORECASE)
# 'On next reload, template will be "Advanced" template.'
_SDM_NEXT = re.compile(
    r"On next reload,?\s+template will be\s+\"?([^\"\n]+?)\"?\s+template\b", re.IGNORECASE
)


def _system_data(hardware_payload):
    """The device-system-data container of a device-hardware-data payload ({} when absent)."""
    hardware = common.container(hardware_payload, common.HW_CONTAINER) or {}
    return _sub(hardware, "device-hardware", "device-system-data")


def _software_version(banner):
    """'17.15.6' out of the software-version banner; its first line when no 'Version' word."""
    text = _text_or_none(banner)
    if text is None:
        return None
    match = _VERSION_WORD.search(text)
    return match.group(1) if match else text.splitlines()[0].strip()


def _parse_sdm_prefer(text):
    """'show sdm prefer' -> {template, next}: the template in effect, the one after a reload.

    ``next`` is None unless the device prints the "On next reload" line
    (an ``sdm prefer`` edit waiting for its reload).
    """
    text = text or ""
    current = _SDM_CURRENT.search(text)
    pending = _SDM_NEXT.search(text)
    return {
        "template": current.group(1).strip() if current else None,
        "next": pending.group(1).strip() if pending else None,
    }


def _normalize_device(system_data, sdm=None):
    """The 'device' key: config_saved, software_version, sdm_template, sdm_template_next.

    ``config_saved`` inverts the model's ``unsaved-config`` and is None when
    the release does not serve the leaf (older releases do not).
    """
    sdm = sdm or {}
    unsaved = system_data.get("unsaved-config") if isinstance(system_data, dict) else None
    saved = None if unsaved is None else not _yes(unsaved)
    return {
        "config_saved": saved,
        "software_version": _software_version(system_data.get("software-version")),
        "sdm_template": sdm.get("template"),
        "sdm_template_next": sdm.get("next"),
    }


def _install_rows(payload):
    return _entries(payload, "install-location-information")


def _install_key(row):
    """'install|<chassis>|<fru>|<slot>|<bay>' — the list's full key, fru without its prefix."""
    return "install|%s|%s|%s|%s" % (
        row.get("chassis"),
        _short(row.get("fru"), "fru-"),
        row.get("slot"),
        row.get("bay"),
    )


def _version_state(value):
    return _short(value, "install-version-state-")


def _version_name(entry):
    """The version, with its extension when the release keys on one."""
    version = _text_or_none(entry.get("version"))
    extension = _text_or_none(entry.get("version-extension"))
    if version is None:
        return None
    return "%s.%s" % (version, extension) if extension else version


def _running_image(entries):
    """The version row that describes the running image.

    The ``is-default`` row when one is flagged; else the provisioned row
    (uncommitted before committed: an activated-but-uncommitted image is the
    one running and the one a reload would lose). The lab flagged neither
    version default, so the fallback is what a 9300 exercises.
    """
    entries = [entry for entry in entries if isinstance(entry, dict)]
    for entry in entries:
        if _yes(entry.get("is-default")):
            return entry
    for wanted in ("provisioned-uncommitted", "provisioned-committed"):
        for entry in entries:
            if _version_state(entry.get("current")) == wanted:
                return entry
    return None


def _normalize_install(rows):
    """'install|...' -> boot_mode, version, state, commit_type, abort_timer, images."""
    normalized = {}
    for row in rows:
        versions = _rows(row, "install-version-info")
        running = _running_image(versions) or {}
        timer = _sub(row, "oper-state", "auto-abort-timer")
        normalized[_install_key(row)] = {
            "boot_mode": _short(common.leaf(row, "oper-state", "boot-mode"), "install-boot-mode-"),
            "version": _version_name(running),
            "state": _version_state(running.get("current")),
            "commit_type": _short(running.get("commit-type"), "install-commit-"),
            "abort_timer": _short(timer.get("state"), "install-timer-state-"),
            "images": sorted(
                "%s %s" % (_version_name(entry), _version_state(entry.get("current")))
                for entry in versions
                if _version_name(entry) is not None
            ),
        }
    return normalized


def _persistence_context(system_data, rows, sdm=None):
    """Volatile or device-wide readings: the abort-timer end time, ROMMON, sources."""
    context = {
        "rommon_version": _text_or_none(system_data.get("rommon-version")),
        "config_saved_source": (
            "unsaved-config leaf"
            if system_data.get("unsaved-config") is not None
            else "unsaved-config leaf not served on this release"
        ),
        "software_banner": _text_or_none(system_data.get("software-version")),
        "install_rows": len(rows),
    }
    for row in rows:
        timer = _sub(row, "oper-state", "auto-abort-timer")
        context[_install_key(row)] = {
            "abort_timer_end": _utc_text(timer.get("end-time")),
            "images": len(_rows(row, "install-version-info")),
        }
    if sdm is not None:
        context["sdm_template_next"] = sdm.get("next")
    return context


def _collect_persistence(ctx):
    notes = []
    hardware = ctx.get(common.HW_PATH)
    system_data = _system_data(hardware)
    if not system_data:
        raise CollectError("device-system-data missing from device-hardware-data reply")
    install = common.get_filtered(
        ctx,
        _INSTALL_PATH,
        _INSTALL_FIELDS,
        label="install-location-information",
        ok_404=True,
        notes=notes,
    )
    rows = _install_rows(install.payload) if install.payload is not None else []
    if install.payload is None:
        notes.append("install-oper not served (404); install| keys omitted")
    elif not rows:
        notes.append("install-location-information served empty; install| keys omitted")
    sdm_text = None
    sdm = {"template": None, "next": None}
    if ctx.has_ssh:
        sdm_text = ctx.run_ssh(_SDM_COMMAND)
        if common.cli_rejected(sdm_text):
            notes.append("%s refused; sdm_template unmeasured" % (_SDM_COMMAND,))
        else:
            sdm = _parse_sdm_prefer(sdm_text)
            if sdm["template"] is None:
                notes.append("%s: template line not recognised" % (_SDM_COMMAND,))
    else:
        notes.append("no SSH transport; sdm_template unmeasured")
    normalized = {"device": _normalize_device(system_data, sdm)}
    normalized.update(_normalize_install(rows))
    context = _persistence_context(system_data, rows, sdm)
    context["install_fields_filter"] = install.fields_filter if install.payload else None
    # The hardware payload is shared with three other checks (one cached GET);
    # raw keeps the leaves this check read, under the exact path.
    raw = {
        common.HW_PATH: {
            common.HW_CONTAINER: {"device-hardware": {"device-system-data": system_data}}
        }
    }
    if install.payload is not None:
        raw[install.path] = install.payload
    if sdm_text is not None:
        raw[_SDM_COMMAND] = sdm_text
    if notes:
        raw["note"] = "; ".join(notes)
    return {"raw": raw, "normalized": normalized, "context": context}


# =============================================================================
# iosxe_license
# =============================================================================

_LEVEL_FAMILIES = (("level", "network-"), ("dna_level", "dna-"))


def _license_state(payload):
    """The ``state`` container, from a licensing/state read or a whole licensing read."""
    state = common.container(payload, "cisco-smart-license:state")
    if state is None:
        licensing = common.container(payload, "cisco-smart-license:licensing")
        state = _sub(licensing, "state") if isinstance(licensing, dict) else None
    return state if isinstance(state, dict) else {}


def _usage_name(entry):
    """The licence name: license-name, else short-name, else the tag's product part."""
    for leaf_name in ("license-name", "short-name"):
        name = _text_or_none(entry.get(leaf_name))
        if name is not None:
            return name
    tag = _text_or_none(entry.get("entitlement-tag"))
    if tag is None:
        return None
    # regid.2017-05.com.cisco.C9300_48P_NW_essentialsk9,1.0_<uuid> -> C9300_48P_NW_essentialsk9
    return tag.split(",", 1)[0].rsplit(".", 1)[-1]


def _levels(license_keys):
    """The network and DNA level in effect, from the licence names in use."""
    names = list(license_keys)
    facts = {}
    for facet, prefix in _LEVEL_FAMILIES:
        matches = sorted(name for name in names if name.lower().startswith(prefix))
        facts[facet] = matches[0] if matches else None
    return facts


def _normalize_license_model(state):
    """'licensing' and 'license|<name>' keys from a cisco-smart-license state container."""
    info = _sub(state, "state-info")
    normalized = {}
    for entry in _rows(info, "usage"):
        name = _usage_name(entry)
        if name is None:
            continue
        count = _to_int(entry.get("count"))
        normalized["license|%s" % (name,)] = {
            "count": count,
            "enforcement": _short(entry.get("enforcement-mode"), "enforcement-"),
            # the model lists usage only for licences in use (count >= 1)
            "status": "in-use" if count is None or count >= 1 else "not-in-use",
        }
    licensing = {
        "smart_enabled": _yes(state.get("smart-enabled")),
        "registration": _short(
            common.leaf(info, "registration", "registration-state"), "reg-state-"
        ),
        "authorization": _short(
            common.leaf(info, "authorization", "authorization-state"), "auth-state-"
        ),
        "transport": _short(common.leaf(info, "transport", "transport-type"), "transport-type-"),
        "eval_in_use": _yes(common.leaf(info, "evaluation", "eval-in-use")),
        "eval_expired": _yes(common.leaf(info, "evaluation", "eval-expired")),
        "policy": _text_or_none(common.leaf(info, "policy", "policy-name")),
    }
    licensing.update(_levels(key.split("|", 1)[1] for key in normalized))
    normalized["licensing"] = licensing
    return normalized


# "  network-essentials      (C9300-48 Network Essen...)       1 IN USE"
_SUMMARY_ROW = re.compile(
    r"^\s*(\S+)\s+\((?P<tag>[^)]*)\)\s+(?P<count>\d+)\s+(?P<status>[A-Z][A-Z ]*?)\s*$"
)
_SUMMARY_ROW_NO_TAG = re.compile(r"^\s*(\S+)\s+(?P<count>\d+)\s+(?P<status>[A-Z][A-Z ]*?)\s*$")
# Older summaries print the agent state above the table:
#   Registration:\n  Status: REGISTERED ... / License Authorization:\n  Status: AUTHORIZED on ...
_SUMMARY_STATE = re.compile(
    r"^\s*(Registration|License Authorization):\s*\n\s*Status:\s*([A-Z][A-Z _-]*?)(?:\s+on\b|\s*$)",
    re.IGNORECASE | re.MULTILINE,
)


def _parse_license_summary(text):
    """'show license summary' -> {licenses: [{name, count, status}], registration, authorization}.

    The agent-state lines are only printed by older summaries; None otherwise.
    """
    text = text or ""
    licenses = []
    for line in text.splitlines():
        match = _SUMMARY_ROW.match(line) or _SUMMARY_ROW_NO_TAG.match(line)
        if match is None or match.group(1).lower() in ("license", "count"):
            continue
        licenses.append(
            {
                "name": match.group(1),
                "count": int(match.group("count")),
                "status": match.group("status").strip().lower().replace(" ", "-"),
            }
        )
    facts = {"licenses": licenses, "registration": None, "authorization": None}
    for match in _SUMMARY_STATE.finditer(text):
        word = match.group(2).strip().lower().replace(" ", "-")
        facts["registration" if match.group(1).lower() == "registration" else "authorization"] = (
            word
        )
    return facts


def _normalize_license_cli(summary):
    """The same keys as the model view, from the summary; unmeasured facets are None."""
    normalized = {}
    for entry in summary.get("licenses", []):
        normalized["license|%s" % (entry["name"],)] = {
            "count": entry["count"],
            "enforcement": None,
            "status": entry["status"],
        }
    licensing = {
        "smart_enabled": None,
        "registration": summary.get("registration"),
        "authorization": summary.get("authorization"),
        "transport": None,
        "eval_in_use": None,
        "eval_expired": None,
        "policy": None,
    }
    licensing.update(_levels(key.split("|", 1)[1] for key in normalized))
    normalized["licensing"] = licensing
    return normalized


def _license_context(state):
    """Expiry and evaluation facts: days remaining, deadlines, the agent version."""
    info = _sub(state, "state-info")
    seconds_left = _to_int(common.leaf(info, "evaluation", "eval-period-left", "time-left"))
    authorization = _sub(info, "authorization")
    deadline = None
    ooc_time = None
    for node_ in authorization.values():
        if isinstance(node_, dict):
            deadline = deadline or _utc_text(node_.get("comm-deadline-time"))
            ooc_time = ooc_time or _utc_text(node_.get("ooc-time"))
    return {
        "agent_version": _text_or_none(state.get("version")),
        "always_enabled": _yes(state.get("always-enabled")),
        "eval_days_left": round(seconds_left / 86400.0, 1) if seconds_left is not None else None,
        "eval_expire_time": _utc_text(
            common.leaf(info, "evaluation", "eval-expire-time", "expire-time")
        ),
        "registration_expire_time": _utc_text(
            common.leaf(info, "registration", "registration-complete", "expire-time")
        ),
        "authorization_deadline": deadline,
        "out_of_compliance_since": ooc_time,
        "export_control_allowed": _yes(common.leaf(info, "registration", "export-control-allowed")),
        "licenses_in_use": len(_rows(info, "usage")),
        "policy_type": _short(common.leaf(info, "policy", "policy-type"), "policy-type-"),
    }


# What raw keeps of the licensing state, whichever shape the read answered:
# True keeps a subtree whole, a dict keeps only the named children (lists
# entry by entry). Everything unnamed — udi, custom-id, trust codes, RUM
# reports, factory purchases, imported authorizations, customer info,
# account names, subscription ids — is dropped.
_LICENSE_KEEP = {
    "always-enabled": True,
    "smart-enabled": True,
    "version": True,
    "state-info": {
        "registration": {
            "registration-state": True,
            "export-control-allowed": True,
            "registration-in-progress": True,
            "registration-failed": True,
            "registration-retry": True,
            "registration-complete": {
                "complete-time": True,
                "last-renew-time": True,
                "next-renew-time": True,
                "expire-time": True,
                "last-renew-success": True,
                "fail-message": True,
            },
        },
        "authorization": True,
        "evaluation": True,
        "transport": {"transport-type": True},
        "privacy": True,
        "utility": {"enabled": True, "reporting": True, "reporting-times": True},
        "usage": {
            "entitlement-tag": True,
            "short-name": True,
            "license-name": True,
            "description": True,
            "count": True,
            "enforcement-mode": True,
            "post-paid": True,
        },
        "policy": True,
    },
}


def _project(node_, keep):
    """``node_`` cut to the ``keep`` spec (see _LICENSE_KEEP)."""
    if keep is True:
        return node_
    if isinstance(node_, list):
        return [_project(item, keep) for item in node_]
    if not isinstance(node_, dict):
        return node_
    return {name: _project(node_[name], spec) for name, spec in keep.items() if name in node_}


def _license_raw(payload):
    """The licensing state projected to the leaves this check reads, under the state wrapper."""
    state = _license_state(payload)
    return {"cisco-smart-license:state": _project(state, _LICENSE_KEEP)}


def _collect_license(ctx):
    notes = []
    read = common.get_filtered(
        ctx, _LICENSE_PATH, _LICENSE_FIELDS, label="licensing/state", ok_404=True, notes=notes
    )
    state = _license_state(read.payload) if read.payload is not None else {}
    raw = {}
    context = {"fields_filter": read.fields_filter if read.payload is not None else None}
    if state and (_sub(state, "state-info") or state.get("smart-enabled") is not None):
        normalized = _normalize_license_model(state)
        context.update(_license_context(state))
        context["source"] = "cisco-smart-license"
        raw[read.path] = _license_raw(read.payload)
    else:
        notes.append(
            "cisco-smart-license state not served (404)"
            if read.payload is None
            else "cisco-smart-license state served empty"
        )
        if not ctx.has_ssh:
            raise SkipCheck(
                "no licence state: cisco-smart-license not served and no SSH transport for "
                "'%s'" % (_LICENSE_COMMAND,)
            )
        text = ctx.run_ssh(_LICENSE_COMMAND)
        raw[_LICENSE_COMMAND] = text
        summary = _parse_license_summary(text)
        if common.cli_rejected(text) or not summary["licenses"]:
            raise SkipCheck(
                "no licence state: cisco-smart-license not served and '%s' %s"
                % (_LICENSE_COMMAND, "refused" if common.cli_rejected(text) else "listed nothing")
            )
        normalized = _normalize_license_cli(summary)
        context["source"] = _LICENSE_COMMAND
        context["licenses_in_use"] = len(summary["licenses"])
        notes.append(
            "%s used; enforcement, evaluation and transport unmeasured" % (_LICENSE_COMMAND,)
        )
    if notes:
        raw["note"] = "; ".join(notes)
    return {"raw": raw, "normalized": normalized, "context": context}


# =============================================================================
# iosxe_pki
# =============================================================================

_DN_ATTR = re.compile(r"^\s*([A-Za-z][A-Za-z0-9.-]*)\s*=\s*(.*?)\s*$")


def _dn(parts):
    """'attr=value, attr=value' with lower-cased attribute names, from RDN strings."""
    rdns = []
    for part in parts:
        match = _DN_ATTR.match(part or "")
        if match:
            rdns.append("%s=%s" % (match.group(1).lower(), match.group(2)))
        elif _text_or_none(part):
            rdns.append(part.strip())
    return ", ".join(rdns) if rdns else None


def _dn_from_text(text):
    """A model subject-name/issuer-name ('cn=X,o=Y' or 'CN=X, O=Y') -> the shared DN spelling."""
    text = _text_or_none(text)
    if text is None:
        return None
    return _dn(re.split(r",\s*(?=[A-Za-z][A-Za-z0-9.-]*\s*=)", text))


def _cn_of(dn):
    """The cn RDN of a normalized DN; the DN itself when it has none."""
    if dn is None:
        return None
    for rdn in dn.split(", "):
        if rdn.lower().startswith("cn="):
            return rdn[3:]
    return dn


def _cert_usage(value):
    """crypto-pki-cert-usage enum -> general-purpose, signature, encryption, usage-keys, unset."""
    word = _short(value, "crypto-pki-cert-")
    return _short(word, "usage-") if word not in (None, "usage-keys") else word


def _cert_role(usage):
    """'ca' for a signature-only certificate (a CA or root), 'id' otherwise.

    Derived the same way from both sources so a software upgrade that
    switches the source does not move the keys. A usage-keys trustpoint's
    signature certificate reads 'ca' by this rule (rare; SEMANTICS says so).
    """
    return "ca" if usage == "signature" else "id"


_CLI_USAGE = {"general purpose": "general-purpose", "usage keys": "usage-keys"}


def _cli_usage(text):
    word = (text or "").strip().lower()
    return _CLI_USAGE.get(word, word.replace(" ", "-")) or None


_MONTHS = {
    "jan": 1, "feb": 2, "mar": 3, "apr": 4, "may": 5, "jun": 6,
    "jul": 7, "aug": 8, "sep": 9, "oct": 10, "nov": 11, "dec": 12,
}  # fmt: skip
# "13:00:17 UTC Nov 12 2037"
_CLI_TIME = re.compile(r"(\d{1,2}):(\d{2}):(\d{2})\s+(\S+)\s+([A-Za-z]{3})\s+(\d{1,2})\s+(\d{4})")


def _parse_cli_time(text):
    """A 'show crypto pki certificates' validity date -> aware UTC datetime; None when unparsed.

    The device prints its clock's zone; UTC and GMT are exact, any other zone
    is read as UTC (a few hours' error on a horizon measured in days).
    """
    match = _CLI_TIME.search(text or "")
    if match is None:
        return None
    hour, minute, second, _zone, month, day, year = match.groups()
    month_number = _MONTHS.get(month.lower())
    if month_number is None:
        return None
    try:
        return datetime.datetime(
            int(year), month_number, int(day), int(hour), int(minute), int(second),
            tzinfo=datetime.timezone.utc,
        )  # fmt: skip
    except ValueError:
        return None


def _parse_pki_certificates(text):
    """'show crypto pki certificates' -> one dict per certificate block.

    Each block: header ('Certificate', 'CA Certificate', 'Router Self-Signed
    Certificate'), the two-space fields (Status, Certificate Usage,
    Associated Trustpoints, Storage) and the four-space sections under
    Issuer, Subject and Validity Date. Subject's restatement lines
    ('Name:', 'Serial Number:') are skipped; the RDN lines make the DN.
    """
    certs = []
    current = None
    section = None
    for line in (text or "").splitlines():
        if not line.strip():
            continue
        indent = len(line) - len(line.lstrip(" "))
        stripped = line.strip()
        if indent == 0:
            current = {
                "header": stripped, "status": None, "usage": None, "trustpoints": [],
                "storage": None, "issuer": [], "subject": [], "start": None, "end": None,
            }  # fmt: skip
            certs.append(current)
            section = None
            continue
        if current is None:
            continue
        if indent <= 2:
            name, _sep, value = stripped.partition(":")
            name = name.strip().lower()
            value = value.strip()
            section = None
            if name == "status":
                current["status"] = value.lower().replace(" ", "-") or None
            elif name == "certificate usage":
                current["usage"] = _cli_usage(value)
            elif name == "associated trustpoints":
                seen = []
                for label in value.split():
                    if label not in seen:
                        seen.append(label)
                current["trustpoints"] = seen
            elif name == "storage":
                current["storage"] = value or None
            elif name in ("issuer", "subject", "validity date"):
                section = name
            continue
        if section in ("issuer", "subject"):
            if _DN_ATTR.match(stripped):
                current[section].append(stripped)
        elif section == "validity date":
            match = re.match(r"^(start|end)\s+date:\s*(.+)$", stripped, re.IGNORECASE)
            if match:
                current[match.group(1).lower()] = _parse_cli_time(match.group(2))
    return certs


# The subject shapes an identity certificate carries that name no site: the
# factory SUDI — cn 'C9300-48UXM-<12 hex of the chassis MAC>' (PID plus base
# MAC) on the CMCA chains, cn '<PID>' with 'ou=ACT-2 Lite SUDI' on the ACT2
# chain (17.15.6 live), both carrying 'serialNumber=PID:<pid> SN:<serial>' —
# and the device's own default ('IOS-Self-Signed-Certificate-<n>'). Any other
# identity subject is an enrolled one, and IOS-XE's default subject-name for
# an enrolment is CN=<hostname>.<domain> (with the same name under the
# 'hostname' / unstructuredName RDN), so its naming RDNs are withheld from the
# key, the facts and raw alike: no hostname enters a snapshot. A CA
# certificate's subject names an organisation and is kept whole.
_FACTORY_CN = (
    re.compile(r"^[A-Z0-9][A-Z0-9-]*-[0-9A-Fa-f]{12}$"),
    re.compile(r"^IOS-Self-Signed-Certificate-\d+$"),
)
_SUDI_SERIAL = re.compile(r"^PID:\S+\s+SN:\S+$", re.IGNORECASE)
_NAMING_RDNS = ("cn", "hostname", "unstructuredname", "unstructuredaddress")
_NAME_MARK = "***scrubbed***"


def _rdns(dn):
    """The '(attr, value)' pairs of a normalized DN ('cn=X, o=Y')."""
    pairs = []
    for rdn in (dn or "").split(", "):
        attr, sep, value = rdn.partition("=")
        pairs.append((attr.lower(), value) if sep else (None, rdn))
    return pairs


def _factory_name(cn):
    return cn is not None and any(shape.match(cn) for shape in _FACTORY_CN)


def _factory_subject(pairs):
    """True for a SUDI or self-signed subject ((attr, value) pairs): a factory CN
    shape, or the SUDI's 'serialNumber=PID:<pid> SN:<serial>' RDN."""
    for attr, value in pairs:
        if attr == "cn" and _factory_name(value):
            return True
        if attr == "serialnumber" and _SUDI_SERIAL.match(value or ""):
            return True
    return False


def _device_named(role, subject):
    """True when an identity certificate's subject names the device by something
    other than a factory shape (an enrolled CN=<hostname.domain>)."""
    if role != "id" or subject is None:
        return False
    pairs = _rdns(subject)
    if _factory_subject(pairs):
        return False
    return any(attr in _NAMING_RDNS for attr, _value in pairs)


def _withheld_subject(subject):
    """The DN with every naming RDN's value replaced by the mark."""
    return ", ".join(
        "%s=%s" % (attr, _NAME_MARK)
        if attr in _NAMING_RDNS
        else (rdn if attr is None else "%s=%s" % (attr, rdn))
        for attr, rdn in _rdns(subject)
    )


def _cert_label(role, subject, issuer):
    """The key's discriminator: the subject CN (a CA's organisation, the SUDI or
    self-signed shape), or 'issued-by <issuer cn>' for an enrolled identity
    certificate whose CN would name the device."""
    if _device_named(role, subject):
        return "issued-by %s" % (_cn_of(issuer),)
    return _cn_of(subject)


def _cert_key(label, role, subject, issuer=None):
    return "cert|%s|%s|%s" % (label, role, _cert_label(role, subject, issuer))


def _cert_facts(subject, issuer, usage, end, status, key_type):
    role = _cert_role(usage)
    return {
        "subject": _withheld_subject(subject) if _device_named(role, subject) else subject,
        "issuer": issuer,
        "usage": usage,
        "validity_end": _iso_utc(end),
        "status": status,
        "key_type": key_type,
        "self_signed": (subject == issuer) if subject is not None else None,
    }


def _trustpoint_facts(mode, authenticated, keys_generated, enrolled, certificates):
    return {
        "mode": mode,
        "authenticated": authenticated,
        "keys_generated": keys_generated,
        "enrolled": enrolled,
        "certificates": certificates,
    }


def _pki_bundles(payload):
    return _entries(payload, "crypto-pki-bundle")


def _normalize_pki_model(payload):
    """'trustpoint|<label>' and 'cert|<label>|<role>|<cn>' keys from crypto-pki-oper."""
    normalized = {}
    for bundle in _pki_bundles(payload):
        label = _text_or_none(bundle.get("label"))
        if label is None:
            continue
        certs = _rows(bundle, "cert")
        normalized["trustpoint|%s" % (label,)] = _trustpoint_facts(
            _short(bundle.get("mode"), "crypto-pki-mode-"),
            _yes(bundle.get("tp-authenticated")),
            _yes(bundle.get("tp-keys-generated")),
            _yes(bundle.get("tp-enrolled")),
            len(certs),
        )
        for cert in certs:
            usage = _cert_usage(cert.get("cert-usage"))
            subject = _dn_from_text(cert.get("subject-name"))
            issuer = _dn_from_text(cert.get("issuer-name"))
            key_type = _short(cert.get("cert-key-type"), "crypto-pki-cert-key-")
            normalized[_cert_key(label, _cert_role(usage), subject, issuer)] = _cert_facts(
                subject,
                issuer,
                usage,
                _parse_iso(cert.get("validity-end")),
                _short(cert.get("cert-avail"), "crypto-pki-cert-"),
                None if key_type == "none" else key_type,
            )
    return normalized


def _normalize_pki_cli(certs):
    """The same keys from the parsed CLI listing; trustpoint flags derived from its certificates."""
    normalized = {}
    per_label = {}
    for cert in certs:
        usage = cert["usage"]
        role = _cert_role(usage)
        subject = _dn(cert["subject"])
        issuer = _dn(cert["issuer"])
        facts = _cert_facts(subject, issuer, usage, cert["end"], cert["status"], None)
        # a CA certificate authenticates the trustpoint; so does a self-signed
        # identity certificate (the device is its own authority there)
        authenticates = role == "ca" or bool(facts["self_signed"])
        for label in cert["trustpoints"] or ["unassociated"]:
            normalized[_cert_key(label, role, subject, issuer)] = facts
            per_label.setdefault(label, []).append((role, authenticates))
    for label, roles in per_label.items():
        normalized["trustpoint|%s" % (label,)] = _trustpoint_facts(
            None,
            any(authenticates for _role, authenticates in roles),
            None,
            any(role == "id" for role, _authenticates in roles),
            len(roles),
        )
    return normalized


def _scrub_pki_payload(payload):
    """The crypto-pki-oper payload with each device-naming identity subject-name
    withheld (the same rule as the keys); every other leaf verbatim."""
    scrubbed = 0
    for bundle in _pki_bundles(payload):
        for cert in _rows(bundle, "cert"):
            role = _cert_role(_cert_usage(cert.get("cert-usage")))
            subject = _dn_from_text(cert.get("subject-name"))
            if _device_named(role, subject):
                cert["subject-name"] = _withheld_subject(subject)
                scrubbed += 1
    return payload, scrubbed


_CLI_SUBJECT_NAME = re.compile(
    r"^(\s+(?:Name:\s*|(?:cn|hostname|unstructuredName|unstructuredAddress)=))(.*)$", re.IGNORECASE
)


def _scrub_subject_block(lines):
    """A CLI Subject block's lines with the naming lines (Name:, cn=, hostname=,
    unstructuredName=) masked, unless the block is a factory subject."""
    pairs = []
    for line in lines:
        match = _DN_ATTR.match(line.strip())
        if match:
            pairs.append((match.group(1).lower(), match.group(2)))
    if _factory_subject(pairs):
        return lines
    scrubbed = []
    for line in lines:
        match = _CLI_SUBJECT_NAME.match(line)
        scrubbed.append(match.group(1) + _NAME_MARK if match else line)
    return scrubbed


def _scrub_pki_cli(text):
    """'show crypto pki certificates' with the device-naming lines of every
    non-CA certificate's Subject block masked (Name:, cn=, hostname=,
    unstructuredName=), factory subjects kept whole; the ctx.run_ssh redactor,
    so the trace copy and the stored text are the same scrubbed form."""
    out = []
    ca_block = False
    subject = None  # the Subject block being gathered, for a non-CA certificate
    for line in str(text or "").splitlines():
        stripped = line.strip()
        indent = len(line) - len(line.lstrip(" "))
        if stripped and indent <= 2:
            if subject is not None:
                out.extend(_scrub_subject_block(subject))
                subject = None
            if indent == 0:
                ca_block = stripped.lower().startswith("ca certificate")
            elif stripped.lower().startswith("subject") and not ca_block:
                subject = []
        if subject is not None and indent > 2:
            subject.append(line)
            continue
        out.append(line)
    if subject is not None:
        out.extend(_scrub_subject_block(subject))
    text = str(text or "")
    return "\n".join(out) + ("\n" if text.endswith("\n") else "")


def _pki_context(normalized, now):
    """Days to expiry per certificate key, and the expired / expiring-soon tallies."""
    context = {"certificates": 0, "expired": 0, "expiring_within_days": _EXPIRY_HORIZON_DAYS}
    expiring = []
    soonest = None
    for key, facts in sorted(normalized.items()):
        if not key.startswith("cert|"):
            continue
        context["certificates"] += 1
        days = _days_until(_parse_iso(facts.get("validity_end")), now)
        context[key] = {"days_to_expiry": days}
        if days is None:
            continue
        if days < 0:
            context["expired"] += 1
        elif days <= _EXPIRY_HORIZON_DAYS:
            expiring.append(key)
        if soonest is None or days < soonest[1]:
            soonest = (key, days)
    context["expiring_soon"] = expiring
    context["soonest_expiry"] = soonest[0] if soonest else None
    context["as_of"] = _iso_utc(now)
    return context


def _collect_pki(ctx):
    notes = []
    read = None
    try:
        read = common.get_filtered(
            ctx, _PKI_PATH, _PKI_FIELDS, label="crypto-pki-oper-data", ok_404=True, notes=notes
        )
    except Exception as exc:
        if not _server_error(exc):
            raise
        notes.append("crypto-pki-oper answered HTTP %s" % (exc.status_code,))
    raw = {}
    context = {}
    if read is not None and read.payload is not None:
        normalized = _normalize_pki_model(read.payload)
        payload, scrubbed = _scrub_pki_payload(read.payload)
        raw[read.path] = payload
        if scrubbed:
            notes.append("%d identity subject(s) naming the device withheld" % (scrubbed,))
        context["source"] = "crypto-pki-oper"
        context["fields_filter"] = read.fields_filter
        if not _pki_bundles(read.payload):
            notes.append("crypto-pki-oper served no trustpoints")
    else:
        if read is not None:
            notes.append("crypto-pki-oper not served (404)")
        if not ctx.has_ssh:
            raise CollectError(
                "PKI state unreadable: crypto-pki-oper unavailable and no SSH transport for '%s'"
                % (_PKI_COMMAND,)
            )
        text = ctx.run_ssh(_PKI_COMMAND, redact=_scrub_pki_cli)
        if common.cli_rejected(text):
            raise CollectError(
                "PKI state unreadable: crypto-pki-oper unavailable and '%s' refused"
                % (_PKI_COMMAND,)
            )
        raw[_PKI_COMMAND] = text
        certs = _parse_pki_certificates(text)
        normalized = _normalize_pki_cli(certs)
        context["source"] = _PKI_COMMAND
        context["fields_filter"] = None
        notes.append("%s used; trustpoint mode and key state unmeasured" % (_PKI_COMMAND,))
        if not certs:
            notes.append("%s listed no certificates" % (_PKI_COMMAND,))
    context.update(_pki_context(normalized, _utc_now()))
    if notes:
        raw["note"] = "; ".join(notes)
    return {"raw": raw, "normalized": normalized, "context": context}


# =============================================================================
# iosxe_tcam
# =============================================================================


def _band(pct):
    if pct is None:
        return None
    for floor, word in _BANDS:
        if pct >= floor:
            return word
    return "low"


def _pct(used, maximum):
    """used / maximum as a percentage, 2 dp; None when the region has no capacity."""
    used, maximum = _to_int(used), _to_int(maximum)
    if used is None or not maximum:
        return None
    return round(used * 100.0 / maximum, 2)


def _tcam_rows(payload):
    return _entries(payload, "tcam-detail")


def _tcam_key(row):
    return "tcam|%s|%s" % (row.get("asic-no"), row.get("name"))


def _normalize_tcam(payload):
    """'tcam|<asic>|<region>' -> tcam_max, hash_max, used_pct (the band word is context)."""
    normalized = {}
    for row in _tcam_rows(payload):
        if row.get("name") is None:
            continue
        normalized[_tcam_key(row)] = {
            "tcam_max": _to_int(row.get("tcam-entries-max")),
            "hash_max": _to_int(row.get("hash-entries-max")),
            "used_pct": _pct(row.get("tcam-entries-used"), row.get("tcam-entries-max")),
        }
    return normalized


_DP_PCT_LEAVES = (
    ("tcam_pct", "max-tcam-percentage-used"),
    ("em_pct", "max-em-percentage-used"),
    ("acl_ids_pct", "max-acl-ids-percentage-used"),
    ("lpm_pct", "max-lpm-percentage-used"),
)


def _dp_locations(payload):
    return _entries(payload, "location")


def _dp_key(location, feature):
    return "dp|%s|%s|%s|%s|%s|%s|%s|%s" % (
        location.get("chassis"),
        _short(location.get("fru"), "fru-"),
        location.get("slot"),
        location.get("bay"),
        location.get("node"),
        _short(feature.get("feature"), "dp-feature-"),
        _short(feature.get("protocol"), "dp-proto-"),
        _short(feature.get("direction"), "dp-direction-"),
    )


def _dp_readings(feature):
    return {facet: _to_float(feature.get(leaf_name)) for facet, leaf_name in _DP_PCT_LEAVES}


def _normalize_dp(payload):
    """'dp|<chassis>|<fru>|<slot>|<bay>|<node>|<feature>|<protocol>|<direction>' -> used_pct.

    used_pct is the highest of the feature's four table percentages (TCAM,
    exact-match, ACL ids, LPM): the one that fills first is the one that
    limits the feature. The band word rides in context: it is derived from
    the same reading at fixed edges with no hysteresis, so beside a
    tolerance-protected used_pct it would diff on every capture pair while a
    region hovers at an edge.
    """
    normalized = {}
    for location in _dp_locations(payload):
        for feature in _rows(location, "dp-feature-resource"):
            if feature.get("feature") is None:
                continue
            readings = [value for value in _dp_readings(feature).values() if value is not None]
            normalized[_dp_key(location, feature)] = {
                "used_pct": round(max(readings), 2) if readings else None
            }
    return normalized


def _tcam_context(tcam_payload, dp_payload):
    """Every reading behind used_pct and the band word per key: entries used per
    region, the four percentages per feature, the highest reading and the regions
    at or above 80 percent."""
    context = {"tcam_regions": 0, "dp_features": 0, "at_or_above_80_pct": []}
    highest = None
    for row in _tcam_rows(tcam_payload):
        if row.get("name") is None:
            continue
        key = _tcam_key(row)
        used_pct = _pct(row.get("tcam-entries-used"), row.get("tcam-entries-max"))
        context[key] = {
            "tcam_used": _to_int(row.get("tcam-entries-used")),
            "hash_used": _to_int(row.get("hash-entries-used")),
            "hash_used_pct": _pct(row.get("hash-entries-used"), row.get("hash-entries-max")),
            "band": _band(used_pct),
        }
        context["tcam_regions"] += 1
        if used_pct is not None and used_pct >= 80.0:
            context["at_or_above_80_pct"].append(key)
        if used_pct is not None and (highest is None or used_pct > highest[1]):
            highest = (key, used_pct)
    for location in _dp_locations(dp_payload):
        for feature in _rows(location, "dp-feature-resource"):
            if feature.get("feature") is None:
                continue
            key = _dp_key(location, feature)
            readings = _dp_readings(feature)
            context["dp_features"] += 1
            values = [value for value in readings.values() if value is not None]
            used_pct = round(max(values), 2) if values else None
            context[key] = dict(readings, band=_band(used_pct))
            if used_pct is not None and used_pct >= 80.0:
                context["at_or_above_80_pct"].append(key)
            if used_pct is not None and (highest is None or used_pct > highest[1]):
                highest = (key, used_pct)
    context["highest"] = {"key": highest[0], "used_pct": highest[1]} if highest else None
    return context


def _dp_raw(payload):
    """The dp-resources payload cut to feature level: the per-instance table data is dropped."""
    name = "Cisco-IOS-XE-switch-dp-resources-oper:switch-dp-resources-oper-data"
    locations = []
    for location in _dp_locations(payload):
        cut = {key: value for key, value in location.items() if key != "dp-feature-resource"}
        cut["dp-feature-resource"] = [
            {
                key: value
                for key, value in feature.items()
                if key not in ("instance-list", "shared-ftr-list")
            }
            for feature in _rows(location, "dp-feature-resource")
        ]
        locations.append(cut)
    return {name: {"location": locations}}


def _collect_tcam(ctx):
    notes = []
    tcam_payload = ctx.get(_TCAM_PATH, ok_404=True)
    dp_read = common.get_filtered(
        ctx, _DP_PATH, _DP_FIELDS, label="switch-dp-resources-oper-data", ok_404=True, notes=notes
    )
    dp_payload = dp_read.payload
    if tcam_payload is None and dp_payload is None:
        raise SkipCheck(
            "no forwarding-table utilisation served (tcam-oper and switch-dp-resources-oper absent)"
        )
    normalized = _normalize_tcam(tcam_payload)
    normalized.update(_normalize_dp(dp_payload))
    if not normalized:
        raise SkipCheck("tcam-oper and switch-dp-resources-oper served no regions or features")
    if tcam_payload is None:
        notes.append("tcam-oper not served (404); tcam| keys omitted")
    elif not _tcam_rows(tcam_payload):
        notes.append("tcam-details served empty; tcam| keys omitted")
    if dp_payload is None:
        notes.append("switch-dp-resources-oper not served (404); dp| keys omitted")
    elif not _dp_locations(dp_payload):
        notes.append("switch-dp-resources-oper-data served empty; dp| keys omitted")
    raw = {}
    if tcam_payload is not None:
        raw[_TCAM_PATH] = tcam_payload
    if dp_payload is not None:
        raw[dp_read.path] = _dp_raw(dp_payload)
        if not dp_read.filtered:
            notes.append("dp-resources instance-list dropped from raw; normalized is complete")
    context = _tcam_context(tcam_payload, dp_payload)
    context["dp_fields_filter"] = dp_read.fields_filter if dp_payload is not None else None
    context["used_pct_tolerance"] = _USED_PCT_TOLERANCE
    if notes:
        raw["note"] = "; ".join(notes)
    return {"raw": raw, "normalized": normalized, "context": context}


# --- semantics (merged into registry.SEMANTICS at import) --------------------

SEMANTICS = {
    "iosxe_persistence": (
        "Would a reload bring back what runs now? Key 'device': config_saved inverts the "
        "device-hardware model's unsaved-config leaf (False means the running config differs from "
        "startup and dies at the next reload; None means the release does not serve the leaf — "
        "older releases do not — so read iosxe_config's running/startup match there); "
        "software_version is the release word out of the software-version banner (the banner "
        "itself is in context); sdm_template is the SDM template in effect from 'show sdm prefer' "
        "(no model exists) and sdm_template_next the template a pending 'sdm prefer' edit will "
        "apply at the next reload (None when nothing is pending). Keys "
        "'install|<chassis>|<fru>|<slot>|<bay>' (the install-oper list's full key, so a "
        "dual-supervisor chassis keeps both rows) describe the running image: version and state "
        "are the is-default version's, or, when no version is flagged default (the 9300 flags "
        "none), the provisioned one — provisioned-uncommitted is an activated image that rolls "
        "back when its timer fires, provisioned-committed survives a reload; commit_type "
        "(pend/auto/user) and boot_mode (install/bundle) are None when the release does not fill "
        "them (older releases fill neither); abort_timer is the auto-abort timer state (active "
        "means an uncommitted install is counting down; an idle timer reads inactive on the lab "
        "release, unknown on releases that do not say); images lists every version the location "
        "holds with its state, so a staged (present) or uncommitted image shows even when it is "
        "not the running one. The install| keys are omitted, with a raw note, when the model is "
        "not served. Context holds the abort-timer end time, rommon_version (one device-wide "
        "leaf: on a stack it describes one member, and it reads the literal 'IOS-XE ROMMON' "
        "rather than a version on the lab 9300), the software banner, which source config_saved "
        "came from and whether the install fields filter was accepted. Raw keeps the "
        "device-system-data container of the cached hardware read, the install rows and the 'show "
        "sdm prefer' text."
    ),
    "iosxe_license": (
        "The licence level in effect and its status, from cisco-smart-license licensing/state "
        "('show license summary' only when the model is not served; context.source says "
        "which). Key 'licensing': level is the network licence in use (network-essentials / "
        "network-advantage) and dna_level the DNA one, each None when no such licence is in "
        "use; smart_enabled, registration (not-registered / complete / in-progress / retry / "
        "failed), authorization (none / eval / eval-expired / authorized / "
        "authorized-reservation / out-of-compliance / authorization-expired), transport "
        "(callhome / smart / cslu / off / automatic), eval_in_use, eval_expired and policy "
        "(the SLP policy name) are the model's words with their enum prefix removed and None "
        "when unmeasured (the CLI fallback measures only registration, authorization and the "
        "licences). Keys 'license|<name>' cover every licence the agent reports in use: count, "
        "enforcement (in-compliance is healthy; waiting, evaluation, evaluation-expired, "
        "out-of-compliance, overage, authorization-expired and invalid-tag are the states to "
        "read; an unregistered switch reports invalid-tag) and status (in-use; the model lists "
        "only licences in use, the CLI prints its own status word). A licence level change "
        "takes effect at the next reload, so a key that moves between captures means a "
        "reload happened with a different level configured. Context holds what counts down: "
        "eval_days_left, the evaluation, registration and authorization deadlines, the "
        "out-of-compliance start, export_control_allowed, the agent version and the policy "
        "type. Never collected: licence keys, tokens, trust codes, RUM report keys, account "
        "names and the UDI (raw is a projection of the state without them; the chassis "
        "serial is already in identity). Not-present only when neither the model nor the CLI "
        "answers."
    ),
    "iosxe_pki": (
        "Trustpoints and their certificates, from crypto-pki-oper ('show crypto pki "
        "certificates' when the model is not served or answers a server error — the lab 9300 "
        "answers HTTP 500; context.source says which). Keys 'cert|<trustpoint>|<role>|<cn>': "
        "subject and issuer as 'attr=value' DNs with lower-cased attribute names, usage "
        "(general-purpose, signature, encryption, usage-keys), validity_end in UTC, status "
        "(available / not-available), key_type (rsa / ec; None from the CLI) and self_signed "
        "(subject equals issuer). role is 'ca' for a signature-only certificate (a CA or "
        "root) and 'id' otherwise, derived the same way from both sources so a switch of "
        "source does not move keys (a usage-keys trustpoint's signature certificate reads "
        "'ca' by this rule); a certificate associated with several trustpoints, including "
        "the built-in Trustpool bundle, is keyed under each. Keys 'trustpoint|<label>': mode "
        "(none / ra / subcs), authenticated, keys_generated, enrolled and the certificate "
        "count — from the CLI, authenticated means a CA certificate is present and enrolled "
        "an identity certificate, and mode and keys_generated are None. Every IOS-XE device "
        "reports the factory SUDI chain (CISCO_IDEVID_SUDI*, Cisco Manufacturing and Root "
        "CAs), the licensing root (SLA-TrustPoint) and, once HTTPS or SSH-RSA has run, a "
        "self-signed 'TP-self-signed-<n>' certificate whose subject is "
        "IOS-Self-Signed-Certificate-<n>: that one is the device's own default and expires "
        "or is regenerated with no change made by anyone — an expired default is why a "
        "browser warns on the device's HTTPS page. A validity_end that moved is a renewal or "
        "re-enrolment; a cert key that vanished is a trustpoint removed or a chain "
        "reimported. Certificate serial numbers and fingerprints are never normalized. "
        "No hostname enters the snapshot: an identity certificate whose subject is neither "
        "a factory SUDI shape (cn=<PID>-<12 hex of the base MAC> on the CMCA chains; "
        "cn=<PID> with ou=ACT-2 Lite SUDI on the ACT2 chain; both carry serialNumber=PID:"
        "<pid> SN:<serial>) nor the self-signed default is an enrolled one, and IOS-XE "
        "enrols with CN=<hostname>.<domain> by "
        "default — such a certificate is keyed 'cert|<trustpoint>|id|issued-by <issuer cn>' "
        "(two identity certificates from one issuer under one trustpoint, a renewal overlap, "
        "share the key and the later listed wins), its subject's naming RDNs (cn, hostname, "
        "unstructuredName) read '***scrubbed***' in normalized and in raw (the model's "
        "subject-name leaf, the CLI's Subject block and the debug trace alike; the raw note "
        "counts them), and its issuer, usage, validity and status are kept. "
        "Context holds days_to_expiry per certificate against the capture host's UTC clock, "
        "the expired and expiring-within-90-days tallies and the soonest expiry. Always "
        "reported: an empty view means the device listed no certificates; a failed read is a "
        "failure, never emptiness."
    ),
    "iosxe_tcam": (
        "Forwarding-table utilisation (tier 3: capacity planning, not a pass/fail). Keys "
        "'tcam|<asic>|<region>' from tcam-oper (one row per ASIC and region such as 'Mac "
        "Address Table', 'IP Route Table', 'Security ACL'): tcam_max and hash_max are the "
        "region's capacities, which move only with the SDM template or the release; used_pct "
        "is TCAM entries used over tcam_max (None where a region has no TCAM capacity); the "
        "band word (low under 50, moderate 50-79, high 80-89, critical 90 and above) rides "
        "in context under the same key, not in the diffed view. "
        "Keys 'dp|<chassis>|<fru>|<slot>|<bay>|<node>|<feature>|<protocol>|<direction>' from "
        "switch-dp-resources-oper (the location list's full key, then the feature key): "
        "used_pct is the highest of the feature's four table percentages (TCAM, exact-match, "
        "ACL ids, LPM — the one that fills first limits the feature), its band word again "
        "in context. used_pct carries a tolerance of 5 percentage points either way (an "
        "absolute band on a percentage, so the first entries in an empty region are not a "
        "change), which lets the ordinary churn of MAC learning and route updates pass and "
        "surfaces a region filling up or emptying; the band is derived from the same reading "
        "at fixed edges with no hysteresis, so it is context (a region hovering at 50, 80 or "
        "90 percent would otherwise flip the key on every capture pair the tolerance was "
        "written to pass) — read it beside used_pct there. A move in tcam_max or hash_max "
        "with the same release is an SDM template change that took effect. Context holds "
        "every reading: entries and hash entries used and the band per region, the four "
        "percentages and the band per feature, the highest reading, the regions at "
        "or above 80 percent, the counts and the tolerance. Raw keeps tcam-details whole and "
        "dp-resources cut to feature level (its per-instance table data, 100 KB unfiltered, "
        "is dropped). Not-present when neither model is served."
    ),
}
_REGISTRY_SEMANTICS.update(SEMANTICS)


# --- registrations -----------------------------------------------------------

register(
    CheckDef(
        id="iosxe_persistence",
        platform="iosxe",
        description=(
            "Whether the running config is saved, the software version, the SDM template in "
            "effect (and the one pending a reload), and per install location the running "
            "image's version, commit state, auto-abort timer and boot mode"
        ),
        tier=1,
        compare={"mode": "equality_set"},
        miss_meaning=(
            "config_saved false after the change means it dies at the next reload (before, it "
            "means a 'write memory' will also persist someone else's pending edits); an "
            "uncommitted image or an active abort timer rolls the software back when the "
            "timer fires; a pending SDM template or a different image version means a reload "
            "happened, or is about to change what runs."
        ),
        collector=_collect_persistence,
        tags=("platform", "software"),
    )
)

register(
    CheckDef(
        id="iosxe_license",
        platform="iosxe",
        description=(
            "Smart licensing level in effect (network and DNA), registration, authorization "
            "and per-licence enforcement state (evaluation and expiry countdowns in context)"
        ),
        tier=1,
        compare={"mode": "equality_set"},
        miss_meaning=(
            "A licence level or enforcement state that changed means a reload took effect with "
            "a different level configured, an evaluation or authorization period ran out, or "
            "the device fell out of compliance — features and support entitlements silently "
            "differ from before."
        ),
        collector=_collect_license,
        tags=("platform", "licensing"),
    )
)

register(
    CheckDef(
        id="iosxe_pki",
        platform="iosxe",
        description=(
            "PKI trustpoints and certificates: subject, issuer, usage, validity end and status "
            "per certificate (days to expiry in context); includes the factory SUDI chain and "
            "the self-signed default"
        ),
        tier=1,
        compare={"mode": "equality_set"},
        miss_meaning=(
            "A certificate that changed validity was renewed or re-enrolled; one that vanished "
            "means a trustpoint was removed or a chain reimported; an expired identity "
            "certificate breaks HTTPS, 802.1X EAP-TLS or SD-WAN/DNAC onboarding that trusts it."
        ),
        collector=_collect_pki,
        tags=("platform", "security"),
    )
)

register(
    CheckDef(
        id="iosxe_tcam",
        platform="iosxe",
        description=(
            "Forwarding-table (TCAM / exact-match) capacity and utilisation per ASIC region "
            "and datapath feature (used_pct with a 5-point tolerance; the band word and every "
            "reading in context)"
        ),
        tier=3,
        compare={
            "mode": "equality_set",
            "fields": {"used_pct": {"tolerance": {"abs": _USED_PCT_TOLERANCE}}},
        },
        miss_meaning=(
            "A region that moved more than five percentage points is filling "
            "up (routes, MACs, ACL entries or multicast groups landing on this switch) or "
            "emptied (a table lost); a capacity that moved is an SDM template change that "
            "took effect at a reload."
        ),
        collector=_collect_tcam,
        tags=("platform", "capacity"),
    )
)
