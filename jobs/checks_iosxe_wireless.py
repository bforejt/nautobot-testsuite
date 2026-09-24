"""Catalyst 9800 wireless controller check catalog (IOS-XE, RESTCONF).

A 9800 is IOS-XE: same RESTCONF client, same credential cascade, same
read-only guarantee, and most of the switch catalog (routes, ARP, interfaces,
NTP, syslog, boot time, crash files) is just as useful on a controller. So
these checks register under the ``iosxe`` platform — one job, one transport
decision, no Nautobot-metadata mapping — and decide for themselves whether the
device they landed on is a controller:

* ``_controller(ctx)`` is the gate every wireless collector calls first. A
  chassis model naming a 9800 is a controller outright; otherwise one cached
  read of the AP name/MAC map decides (joined APs present = a controller,
  which also covers an embedded controller on a switch). Anything else raises
  SkipCheck, so on an ordinary switch the whole catalog records not-present
  at the cost of ONE cached GET per capture — information, not failure.
* On a controller the absence of wireless data is never "feature not in use":
  a 404 on the AP roster is the wireless process not serving data, and
  ``_required`` turns it into a CollectError so the capture fails closed. A
  positively read EMPTY roster (2xx, no entries) is a real answer — zero
  joined APs — and records as a success with zero entries plus ``ap_count``
  0 in context, the loudest finding an analyst can get.

Every list read is scoped with a RESTCONF ``fields`` filter (the pattern the
FIB and OSPF collectors already use): the sister repo measured ~10 KB per AP
for an unfiltered capwap read, and the per-client tables are larger still. A
release that rejects a filter (HTTP 400) gets one unfiltered retry, noted in
raw. Client usernames and device hostnames are never requested; WLAN and
flex-profile config is scrubbed of PSK/WEP/password leaves before it enters
normalized OR raw.

Merge-friendliness: the per-check SEMANTICS and the shakedown KEY_MODELS live
here and are merged/exported at import, and jobs/__init__.py plus
tests/_loader.py discover ``checks_*`` modules by name — a platform branch is
one new file. Paths and leaf names below were checked against the published
17.12.1 YANG set; capwap-data, oper-data, radio-oper-data and stack-oper were
bench-verified on a 9800-CL by nautobot-upgrades. The rest is exactly what
the Test Suite Shakedown exists to confirm before a change window.
"""

import re
from collections import Counter

from . import constants as C
from .registry import SEMANTICS as _REGISTRY_SEMANTICS
from .registry import CheckDef, CollectError, SkipCheck, register

# --- RESTCONF paths ----------------------------------------------------------

# Identical string (and kwargs) to checks_iosxe's hardware read, so the
# per-run cache serves platform-health, the stack check and this gate from
# one GET.
_HW_PATH = "/data/Cisco-IOS-XE-device-hardware-oper:device-hardware-data"
_STACK_OPER_PATH = "/data/Cisco-IOS-XE-stack-oper:stack-oper-data"

_AP_OPER = "/data/Cisco-IOS-XE-wireless-access-point-oper:access-point-oper-data"
_AP_NAME_MAP_PATH = _AP_OPER + "/ap-name-mac-map"
_AP_GLOBAL_OPER = "/data/Cisco-IOS-XE-wireless-ap-global-oper:ap-global-oper-data"
_CLIENT_OPER = "/data/Cisco-IOS-XE-wireless-client-oper:client-oper-data"
_CLIENT_GLOBAL_OPER = "/data/Cisco-IOS-XE-wireless-client-global-oper:client-global-oper-data"
_WLAN_GLOBAL_OPER = "/data/Cisco-IOS-XE-wireless-wlan-global-oper:wlan-global-oper-data"
_MOBILITY_OPER = "/data/Cisco-IOS-XE-wireless-mobility-oper:mobility-oper-data"
_GENERAL_OPER = "/data/Cisco-IOS-XE-wireless-general-oper:general-oper-data"
_WLAN_CFG = "/data/Cisco-IOS-XE-wireless-wlan-cfg:wlan-cfg-data"
_SITE_CFG = "/data/Cisco-IOS-XE-wireless-site-cfg:site-cfg-data"
_RF_CFG = "/data/Cisco-IOS-XE-wireless-rf-cfg:rf-cfg-data"
_FLEX_CFG = "/data/Cisco-IOS-XE-wireless-flex-cfg:flex-cfg-data"
_AP_CFG = "/data/Cisco-IOS-XE-wireless-ap-cfg:ap-cfg-data"
_MOBILITY_CFG = "/data/Cisco-IOS-XE-wireless-mobility-cfg:mobility-cfg-data"
_AAA_OPER = "/data/Cisco-IOS-XE-aaa-oper:aaa-data"

# ``fields`` filters: only the leaves the normalizers read. Nested containers
# use the parenthesised RFC 8040 form the FIB path already relies on.
_CAPWAP_FIELDS = (
    "wtp-mac;ip-addr;name;country-code;num-radio-slots;ap-lag-enabled;"
    "device-detail(static-info(board-data(wtp-serial-num;wtp-enet-mac);ap-models(model));"
    "wtp-version(sw-version));ap-location(floor;location);"
    "tag-info(tag-source;is-ap-misconfigured;resolved-tag-info;policy-tag-info;site-tag;rf-tag);"
    "ap-state;ap-mode-data(wtp-mode;ap-sub-mode);ap-time-info;reboot-stats;disconnect-detail"
)
_RADIO_FIELDS = (
    "wtp-mac;radio-slot-id;slot-id;radio-type;admin-state;oper-state;radio-mode;"
    "radio-sub-mode;current-band-id;current-active-band;"
    "phy-ht-cfg(cfg-data(curr-freq;chan-width;phy-ht-cfg-config-type;rrm-channel-change-reason));"
    "radio-band-info(band-id;regulatory-domain;"
    "phy-tx-pwr-cfg(cfg-data(phy-tx-power-config-type;current-tx-power-level));"
    "phy-tx-pwr-lvl-cfg(cfg-data(curr-tx-power-in-dbm)));station-cfg(cfg-data(bssid))"
)
_CDP_FIELDS = (
    "mac-addr;cdp-cache-device-id;wtp-mac-addr;ap-name;cdp-cache-device-port;"
    "cdp-cache-local-port;cdp-cache-platform;cdp-cache-ip-address-value;cdp-cache-duplex;"
    "cdp-cache-interface-speed"
)
_LLDP_FIELDS = "wtp-mac;neigh-mac;port-id;local-port;system-name;port-description;mgmt-addr"
_ETH_FIELDS = (
    "wtp-mac;if-index;if-name;oper-status;duplex;link-speed;input-errors;input-crc;output-errors"
)
_JOIN_FIELDS = (
    "wtp-mac;ap-disconnect-reason;reboot-reason;disconnect-reason;"
    "ap-join-info(ap-name;ap-ethernet-mac;is-joined;num-join-req-recvd;num-succ-join-resp-sent;"
    "num-unsucc-join-req-procn;last-succ-join-atmpt-time;last-fail-join-atmpt-time;"
    "last-error-type;last-error-time);dtls-sess-info(ctrl-dtls-failure;data-dtls-failure)"
)
# Deliberately NOT requested: username (PII) — never enters a snapshot.
_CLIENT_FIELDS = (
    "client-mac;ap-name;ms-ap-slot-id;ms-radio-type;wlan-id;client-type;co-state;vrf-name;"
    "wlan-policy(current-switching-mode;central-authentication)"
)
_CLIENT_DOT11_FIELDS = (
    "ms-mac-address;vap-ssid;ms-wlan-id;policy-profile;ms-bssid;current-channel;"
    "ewlc-ms-phy-type;security-mode;encryption-type;dot11-state;ms-assoc-time"
)
_CLIENT_POLICY_FIELDS = "mac;res-vlan-id;res-vlan-name"
_CLIENT_SISF_FIELDS = "mac-addr;ipv4-binding(ip-key(ip-addr))"
_EXCLUSION_FIELDS = "client-mac;exclude-reason;wlan-id;ap-name;vlan-id"
_WLAN_INFO_FIELDS = "wlan-profile;curr-clients-count"
_MOBILITY_NODE_FIELDS = (
    "node-ip;nat-ip;group-name;num-clients;tunnel-plumbed;is-anchor;ulink-status;"
    "ctrl-state(peer-status;link-status;flaps-cnt);data-state(peer-status;link-status;flaps-cnt)"
)
_AP_PEER_FIELDS = "peer-ip;ap-count;source"
_WLAN_FIELDS = (
    "profile-name;wlan-id;description;security-wpa;webauth-enabled;dot11-auth-type;"
    "wep-enabled;apf-vap-id-data(ssid;wlan-status;broadcast-ssid)"
)
_POLICY_FIELDS = (
    "policy-profile-name;description;status;interface-name;"
    "wlan-switching-policy(central-switching;central-authentication;central-dhcp;"
    "central-assoc-enable);wlan-flex-policy(vlan-central-switching)"
)
_POLICY_TAG_FIELDS = (
    "tag-name;description;wlan-policies(wlan-policy(wlan-profile-name;policy-profile-name))"
)
_SITE_TAG_FIELDS = "site-tag-name;description;flex-profile;ap-join-profile;is-local-site"
_RF_TAG_FIELDS = (
    "tag-name;description;dot11a-rf-profile-name;dot11b-rf-profile-name;dot11-6ghz-rf-prof-name"
)
_FLEX_FIELDS = (
    "policy-name;description;native-vlan-id;vlan-enable;is-local-roaming-enable;"
    "radius-server-group-name;if-name-vlan-ids(if-name-vlan-id(interface-name;vlan-id))"
)
_AP_TAG_FIELDS = "ap-mac;policy-tag;site-tag;rf-tag"
_AAA_FIELDS = (
    "group-name;radius-server-ip;auth-port;acct-port;is-server-radsec;"
    "server-detail(aaa-inst-id;inst-type;server-state);authen-access-accepts;"
    "authen-access-rejects;authen-timeout-access-requests"
)

# yang-library module names the shakedown reports, so a 9800 shakedown shows
# at once which wireless collectors CAN work on the image.
KEY_MODELS = (
    "Cisco-IOS-XE-wireless-access-point-oper",
    "Cisco-IOS-XE-wireless-ap-global-oper",
    "Cisco-IOS-XE-wireless-client-oper",
    "Cisco-IOS-XE-wireless-client-global-oper",
    "Cisco-IOS-XE-wireless-wlan-global-oper",
    "Cisco-IOS-XE-wireless-mobility-oper",
    "Cisco-IOS-XE-wireless-general-oper",
    "Cisco-IOS-XE-wireless-wlan-cfg",
    "Cisco-IOS-XE-wireless-site-cfg",
    "Cisco-IOS-XE-wireless-rf-cfg",
    "Cisco-IOS-XE-wireless-flex-cfg",
    "Cisco-IOS-XE-wireless-ap-cfg",
    "Cisco-IOS-XE-wireless-mobility-cfg",
    "Cisco-IOS-XE-aaa-oper",
)

# Chassis model tokens that identify a controller outright (C9800-CL-K9,
# C9800-40-K9, C9800-80-K9, C9800-L-*). Embedded controllers on switches are
# caught by the wireless-data probe instead.
_CONTROLLER_MODEL_TOKENS = ("9800",)

_RADIO_BANDS = {
    "radio-80211bg": "2.4GHz",
    "radio-80211a": "5GHz",
    "radio-80211-6ghz": "6GHz",
    "radio-80211-xor-5-6ghz": "xor-5-6GHz",
    "radio-80211abgn": "xor-2.4-5GHz",
}
_CLIENT_BANDS = {
    "dot11-radio-type-bg": "2.4GHz",
    "dot11-radio-type-a": "5GHz",
    "dot11-radio-type-6ghz": "6GHz",
}
_DEVICE_RADIO_STATS = {
    "stats-80211-bg-rad": "2.4GHz",
    "stats-80211-a-rad": "5GHz",
    "stats-80211-6ghz-radios": "6GHz",
    "stats-80211-all-rad": "all",
}

# Secret leaves in the wireless config models (wlan-cfg: psk, mpsk-key,
# wep-key; flex-cfg local-auth-users: password) plus generic tokens. Exact
# names keep the FLAGS readable — auth-key-mgmt-psk, psk-type and wep-key-size
# describe the security mode and are not secrets.
_SECRET_LEAVES = frozenset(
    ("psk", "mpsk-key", "wep-key", "password", "secret", "key", "shared-secret", "radius-key")
)
_SECRET_TOKENS = ("password", "secret", "passphrase")


# --- shared helpers ----------------------------------------------------------


def _aslist(node):
    """RESTCONF quirk: a single list entry may arrive as a bare dict, absent as None."""
    if node is None:
        return []
    if isinstance(node, list):
        return node
    return [node]


def _node(payload, name):
    """Value of the module-qualified top-level node ``name``.

    List reads answer ``{"mod:list": [...]}``; a container read (or a fixture
    harvested from one) answers ``{"mod:container": {"list": [...]}}`` — the
    second form is searched one level down so both shapes normalize alike.
    """
    if not isinstance(payload, dict):
        return None
    for key, value in payload.items():
        if key.split(":")[-1] == name:
            return value
    for value in payload.values():
        if isinstance(value, dict):
            for key, inner in value.items():
                if key.split(":")[-1] == name:
                    return inner
    return None


def _entries(payload, name):
    return [entry for entry in _aslist(_node(payload, name)) if isinstance(entry, dict)]


def _sub(node, *names):
    """Nested container lookup; {} when any level is missing or not a dict."""
    for name in names:
        node = node.get(name) if isinstance(node, dict) else None
    return node if isinstance(node, dict) else {}


def _leaf(node, *names):
    """Nested leaf lookup; None when any level is missing."""
    return _sub(node, *names[:-1]).get(names[-1])


def _to_int(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _yes(value):
    """Boolean leaf: RESTCONF JSON booleans, but tolerate 'true'/'false' strings."""
    if isinstance(value, bool):
        return value
    if value is None:
        return None
    return str(value).strip().lower() in ("true", "yes", "1", "enabled")


def _short(value, prefix):
    """Strip a YANG enum prefix ('client-status-run' -> 'run'); None stays None."""
    if value is None:
        return None
    value = str(value)
    return value[len(prefix) :] if value.startswith(prefix) else value


def _mac(value):
    return str(value).strip().lower() if value else None


def _compact(facts):
    """Drop unmeasured (None) facets: absent means the device did not publish it."""
    return {key: value for key, value in facts.items() if value is not None}


def _ap_mode(value):
    """'local-mode' -> 'local', 'mode-flex-connect' -> 'flex-connect'."""
    if value is None:
        return None
    value = str(value)
    if value.startswith("mode-"):
        value = value[len("mode-") :]
    if value.endswith("-mode"):
        value = value[: -len("-mode")]
    return value


def _config_source(value):
    """w-config-type: 'config-auto' (RRM decided) vs 'customized' (a human typed it)."""
    if value is None:
        return None
    return {"config-auto": "auto", "customized": "static"}.get(str(value), str(value))


def _scrub(node):
    """Mask secret leaves in place (see _SECRET_LEAVES); returns the node."""
    if isinstance(node, dict):
        for key in list(node):
            lowered = str(key).lower()
            if lowered in _SECRET_LEAVES or any(token in lowered for token in _SECRET_TOKENS):
                node[key] = "***scrubbed***"
            else:
                _scrub(node[key])
    elif isinstance(node, list):
        for item in node:
            _scrub(item)
    return node


# --- the controller gate -----------------------------------------------------


def _chassis_identity(hardware_payload):
    """(part-number, hw-description) of the chassis inventory entry; '' when absent."""
    hardware = _sub(_node(hardware_payload, "device-hardware-data"), "device-hardware")
    for entry in _aslist(hardware.get("device-inventory")):
        if not isinstance(entry, dict):
            continue
        if "chassis" not in str(entry.get("hw-type") or "").lower():
            continue
        return (
            str(entry.get("part-number") or "").strip(),
            str(entry.get("hw-description") or "").strip(),
        )
    return "", ""


def _is_controller_model(model, description):
    haystack = ("%s %s" % (model, description)).lower()
    return any(token in haystack for token in _CONTROLLER_MODEL_TOKENS)


def _controller(ctx):
    """Positive controller identification, or SkipCheck.

    Returns the facts dict every wireless check embeds in raw/context: the
    chassis model and WHY the device was treated as a controller. The
    hardware read is the one platform-health already makes (cache hit); the
    fallback probe is one cached GET shared by every wireless check, so an
    ordinary switch pays for exactly one extra request per capture.
    """
    hardware = ctx.get(_HW_PATH)
    model, description = _chassis_identity(hardware)
    facts = _compact({"model": model or None, "description": description or None})
    if _is_controller_model(model, description):
        facts["identified_by"] = "chassis model"
        return facts
    probe = ctx.get(_AP_NAME_MAP_PATH, ok_404=True)
    if _entries(probe, "ap-name-mac-map"):
        facts["identified_by"] = "wireless oper data"
        return facts
    raise SkipCheck(
        "not a wireless controller (chassis %s; no wireless oper data served)"
        % (model or "unknown",)
    )


def _required(ctx, facts, path, **kwargs):
    """A wireless read a controller MUST answer: 404 is a failed read, never emptiness.

    A 2xx with no body ({}) is a positively read empty list and passes through.
    """
    payload = ctx.get(path, ok_404=True, **kwargs)
    if payload is None:
        raise CollectError(
            "%s not served (HTTP 404) by this %s — missing wireless data on a controller "
            "is a failed read, never an unused feature"
            % (path.split("?", 1)[0], facts.get("model") or "controller")
        )
    return payload


def _fetch(ctx, facts, base, list_name, fields, timeout=C.GET_TIMEOUT, notes=None):
    """(entries, payload) of a scoped list read.

    A release that rejects the ``fields`` filter answers HTTP 400; the one
    retry reads the list unfiltered (bigger, slower: BIG_GET_TIMEOUT) and the
    fallback is noted so the raw bundle explains its size.
    """
    path = "%s/%s?fields=%s" % (base, list_name, fields)
    try:
        payload = _required(ctx, facts, path, timeout=timeout)
    except CollectError:
        raise
    except Exception as exc:
        if getattr(exc, "status_code", None) != 400:
            raise
        if notes is not None:
            notes.append(
                "%s: fields filter rejected (HTTP 400); unfiltered read used" % (list_name,)
            )
        payload = _required(ctx, facts, "%s/%s" % (base, list_name), timeout=C.BIG_GET_TIMEOUT)
    return _entries(payload, list_name), payload


def _ap_names(ctx):
    """{mac: ap-name} for both the radio (wtp) and Ethernet MAC of every joined AP.

    Same path and kwargs as the gate's probe, so this is a cache hit whenever
    the gate had to probe; the roster-class lists key by wtp-mac, the config
    tag map by Ethernet MAC — both resolve here.
    """
    payload = ctx.get(_AP_NAME_MAP_PATH, ok_404=True)
    names = {}
    for entry in _entries(payload, "ap-name-mac-map"):
        name = entry.get("wtp-name")
        if not name:
            continue
        for mac in (entry.get("wtp-mac"), entry.get("eth-mac")):
            if mac:
                names[_mac(mac)] = str(name)
    return names


def _ap_label(names, mac):
    """AP name for a MAC when the controller knows it, else the MAC itself."""
    mac = _mac(mac)
    return names.get(mac, mac)


def _capwap(ctx, facts, notes):
    """The joined-AP roster, shared (identical path + kwargs) by three checks."""
    return _fetch(
        ctx, facts, _AP_OPER, "capwap-data", _CAPWAP_FIELDS, timeout=C.BIG_GET_TIMEOUT, notes=notes
    )


# --- wlc_ap_inventory --------------------------------------------------------


def _normalize_ap_inventory(entries):
    """'ap|<name>' -> identity, state, mode, tags; keyed by name (MAC when unnamed)."""
    normalized = {}
    for ap in entries:
        name = ap.get("name") or _mac(ap.get("wtp-mac"))
        if not name:
            continue
        tag = _sub(ap, "tag-info")
        resolved = _sub(tag, "resolved-tag-info")
        normalized["ap|%s" % (name,)] = _compact(
            {
                "mac": _mac(ap.get("wtp-mac")),
                "eth_mac": _mac(
                    _leaf(ap, "device-detail", "static-info", "board-data", "wtp-enet-mac")
                ),
                "model": _leaf(ap, "device-detail", "static-info", "ap-models", "model"),
                "serial": _leaf(ap, "device-detail", "static-info", "board-data", "wtp-serial-num"),
                "ip": ap.get("ip-addr"),
                "sw_version": _leaf(ap, "device-detail", "wtp-version", "sw-version"),
                "mode": _ap_mode(_leaf(ap, "ap-mode-data", "wtp-mode")),
                "sub_mode": _leaf(ap, "ap-mode-data", "ap-sub-mode"),
                "admin_state": _short(_leaf(ap, "ap-state", "ap-admin-state"), "adminstate-"),
                "oper_state": _leaf(ap, "ap-state", "ap-operation-state"),
                "country": ap.get("country-code"),
                "location": _leaf(ap, "ap-location", "location"),
                "floor": _leaf(ap, "ap-location", "floor"),
                "policy_tag": resolved.get("resolved-policy-tag")
                or _leaf(tag, "policy-tag-info", "policy-tag-name"),
                "site_tag": resolved.get("resolved-site-tag")
                or _leaf(tag, "site-tag", "site-tag-name"),
                "rf_tag": resolved.get("resolved-rf-tag") or _leaf(tag, "rf-tag", "rf-tag-name"),
                "tag_source": _short(tag.get("tag-source"), "tag-source-"),
                "misconfigured": _yes(tag.get("is-ap-misconfigured")),
                "ap_profile": _leaf(tag, "site-tag", "ap-profile"),
                "flex_profile": _leaf(tag, "site-tag", "flex-profile"),
                "radio_slots": _to_int(ap.get("num-radio-slots")),
                "lag": _yes(ap.get("ap-lag-enabled")),
            }
        )
    return normalized


def _ap_context(normalized):
    aps = list(normalized.values())
    return {
        "ap_count": len(aps),
        "registered": sum(1 for ap in aps if ap.get("oper_state") == "registered"),
        "not_registered": sum(1 for ap in aps if ap.get("oper_state") != "registered"),
        "admin_disabled": sum(1 for ap in aps if ap.get("admin_state") == "disabled"),
        "misconfigured": sum(1 for ap in aps if ap.get("misconfigured")),
        "by_mode": dict(Counter(ap.get("mode") or "unknown" for ap in aps)),
        "by_model": dict(Counter(ap.get("model") or "unknown" for ap in aps)),
        "by_version": dict(Counter(ap.get("sw_version") or "unknown" for ap in aps)),
    }


def _collect_ap_inventory(ctx):
    facts = _controller(ctx)
    notes = []
    aps, payload = _capwap(ctx, facts, notes)
    normalized = _normalize_ap_inventory(aps)
    context = _ap_context(normalized)
    context["controller"] = facts
    raw = {"capwap-data": payload, "controller": facts}
    if notes:
        raw["note"] = "; ".join(notes)
    return {"raw": raw, "normalized": normalized, "context": context}


# --- wlc_ap_radios -----------------------------------------------------------


def _normalize_radios(entries, names):
    """'radio|<ap>|<slot>' -> band, states, channel/width/power and their sources."""
    normalized = {}
    for radio in entries:
        mac = _mac(radio.get("wtp-mac"))
        slot = radio.get("radio-slot-id", radio.get("slot-id"))
        if not mac or slot is None:
            continue
        ht = _sub(radio, "phy-ht-cfg", "cfg-data")
        bands = [band for band in _aslist(radio.get("radio-band-info")) if isinstance(band, dict)]
        current = radio.get("current-band-id")
        band = next((b for b in bands if b.get("band-id") == current), bands[0] if bands else {})
        power = _sub(band, "phy-tx-pwr-cfg", "cfg-data")
        level = _sub(band, "phy-tx-pwr-lvl-cfg", "cfg-data")
        normalized["radio|%s|%s" % (_ap_label(names, mac), slot)] = _compact(
            {
                "band": _RADIO_BANDS.get(str(radio.get("radio-type")), radio.get("radio-type")),
                "radio_type": radio.get("radio-type"),
                "admin_state": radio.get("admin-state"),
                "oper_state": _short(radio.get("oper-state"), "radio-"),
                "mode": radio.get("radio-mode"),
                "sub_mode": radio.get("radio-sub-mode"),
                "channel": _to_int(ht.get("curr-freq")),
                "width": _to_int(ht.get("chan-width")),
                "channel_source": _config_source(ht.get("phy-ht-cfg-config-type")),
                "channel_change_reason": ht.get("rrm-channel-change-reason"),
                "power_level": _to_int(power.get("current-tx-power-level")),
                "power_source": _config_source(power.get("phy-tx-power-config-type")),
                "power_dbm": _to_int(level.get("curr-tx-power-in-dbm")),
                "reg_domain": band.get("regulatory-domain"),
                "bssid": _mac(_leaf(radio, "station-cfg", "cfg-data", "bssid")),
                "bands": len(bands) if len(bands) > 1 else None,
            }
        )
    return normalized


def _radio_context(normalized, stats_payload):
    radios = list(normalized.values())
    per_band = {}
    for radio in radios:
        bucket = per_band.setdefault(
            radio.get("band") or "unknown", {"total": 0, "up": 0, "down": 0}
        )
        bucket["total"] += 1
        bucket["up" if radio.get("oper_state") == "up" else "down"] += 1
    context = {
        "radios_total": len(radios),
        "radios_up": sum(1 for r in radios if r.get("oper_state") == "up"),
        "radios_down": sum(1 for r in radios if r.get("oper_state") != "up"),
        "radios_admin_disabled": sum(1 for r in radios if r.get("admin_state") == "disabled"),
        "per_band": per_band,
    }
    stats = _node(stats_payload, "ewlc-ap-stats")
    if isinstance(stats, dict):
        reported = {}
        for leaf, band in _DEVICE_RADIO_STATS.items():
            block = stats.get(leaf)
            if isinstance(block, dict):
                reported[band] = _compact(
                    {
                        "total": _to_int(block.get("total-radios")),
                        "up": _to_int(block.get("radios-up")),
                        "down": _to_int(block.get("radios-down")),
                    }
                )
        context["device_reported"] = reported
        misconfigured = _to_int(stats.get("stats-misconfigured-aps"))
        if misconfigured is not None:
            context["device_reported_misconfigured_aps"] = misconfigured
    return context


def _collect_ap_radios(ctx):
    facts = _controller(ctx)
    notes = []
    names = _ap_names(ctx)
    radios, payload = _fetch(
        ctx,
        facts,
        _AP_OPER,
        "radio-oper-data",
        _RADIO_FIELDS,
        timeout=C.BIG_GET_TIMEOUT,
        notes=notes,
    )
    normalized = _normalize_radios(radios, names)
    # Device-computed per-band totals corroborate the per-radio view; a blip
    # here must never fail the check.
    stats = ctx.get(_AP_GLOBAL_OPER + "/ewlc-ap-stats", ok_404=True)
    if stats is None:
        notes.append("ewlc-ap-stats not served; device-reported totals skipped")
    context = _radio_context(normalized, stats)
    raw = {"radio-oper-data": payload, "ewlc-ap-stats": stats}
    if notes:
        raw["note"] = "; ".join(notes)
    return {"raw": raw, "normalized": normalized, "context": context}


# --- wlc_ap_uplinks ----------------------------------------------------------


def _normalize_uplinks(cdp, lldp, eth, names):
    """'cdp|<ap>|<port>', 'lldp|<ap>|<port>', 'eth|<ap>|<if>' -> where the AP plugs in."""
    normalized = {}
    for entry in cdp:
        ap = entry.get("ap-name") or _ap_label(
            names, entry.get("wtp-mac-addr") or entry.get("mac-addr")
        )
        port = entry.get("cdp-cache-local-port") or "?"
        normalized["cdp|%s|%s" % (ap, port)] = _compact(
            {
                "neighbor": entry.get("cdp-cache-device-id"),
                "neighbor_port": entry.get("cdp-cache-device-port"),
                "neighbor_platform": entry.get("cdp-cache-platform"),
                "neighbor_ip": entry.get("cdp-cache-ip-address-value"),
                "duplex": entry.get("cdp-cache-duplex"),
                "speed": entry.get("cdp-cache-interface-speed"),
            }
        )
    for entry in lldp:
        ap = _ap_label(names, entry.get("wtp-mac"))
        port = entry.get("local-port") or "?"
        normalized["lldp|%s|%s" % (ap, port)] = _compact(
            {
                "neighbor": entry.get("system-name"),
                "neighbor_port": entry.get("port-id"),
                "neighbor_port_description": entry.get("port-description"),
                "neighbor_ip": entry.get("mgmt-addr"),
            }
        )
    for entry in eth:
        ap = _ap_label(names, entry.get("wtp-mac"))
        ifname = entry.get("if-name") or entry.get("if-index")
        if ap is None or ifname is None:
            continue
        normalized["eth|%s|%s" % (ap, ifname)] = _compact(
            {
                "link": entry.get("oper-status"),
                "speed": entry.get("link-speed"),
                "duplex": entry.get("duplex"),
            }
        )
    return normalized


def _uplink_context(normalized):
    eth = [v for k, v in normalized.items() if k.startswith("eth|")]
    slow = [
        k
        for k, v in normalized.items()
        if k.startswith("eth|")
        and _to_int(v.get("speed")) is not None
        and 0 < _to_int(v.get("speed")) < 1000
    ]
    return {
        "aps_with_cdp": len({k.split("|")[1] for k in normalized if k.startswith("cdp|")}),
        "aps_with_lldp": len({k.split("|")[1] for k in normalized if k.startswith("lldp|")}),
        "eth_ports": len(eth),
        "eth_ports_down": sum(1 for v in eth if "down" in str(v.get("link") or "").lower()),
        "eth_ports_below_1g": sorted(slow),
    }


def _collect_ap_uplinks(ctx):
    facts = _controller(ctx)
    notes = []
    names = _ap_names(ctx)
    cdp, cdp_payload = _fetch(ctx, facts, _AP_OPER, "cdp-cache-data", _CDP_FIELDS, notes=notes)
    lldp, lldp_payload = _fetch(ctx, facts, _AP_OPER, "lldp-neigh", _LLDP_FIELDS, notes=notes)
    eth, eth_payload = _fetch(ctx, facts, _AP_OPER, "ethernet-if-stats", _ETH_FIELDS, notes=notes)
    normalized = _normalize_uplinks(cdp, lldp, eth, names)
    raw = {
        "cdp-cache-data": cdp_payload,
        "lldp-neigh": lldp_payload,
        "ethernet-if-stats": eth_payload,
    }
    if notes:
        raw["note"] = "; ".join(notes)
    return {"raw": raw, "normalized": normalized, "context": _uplink_context(normalized)}


# --- wlc_ap_join_stats -------------------------------------------------------


def _normalize_join_stats(join_entries, capwap_entries, names):
    """'ap|<name>' -> join/boot times, join counters, last disconnect and reboot reasons.

    ap-join-stats remembers every AP the controller has ever seen (joined or
    not); capwap-data's time and reboot facts are merged in for the APs joined
    right now, and win over the history list when both report a reason.
    """
    normalized = {}
    for entry in join_entries:
        info = _sub(entry, "ap-join-info")
        dtls = _sub(entry, "dtls-sess-info")
        ap = info.get("ap-name") or _ap_label(names, entry.get("wtp-mac"))
        if not ap:
            continue
        normalized["ap|%s" % (ap,)] = _compact(
            {
                "joined": _yes(info.get("is-joined")),
                "join_requests": _to_int(info.get("num-join-req-recvd")),
                "join_successes": _to_int(info.get("num-succ-join-resp-sent")),
                "join_failures": _to_int(info.get("num-unsucc-join-req-procn")),
                "last_join_success": info.get("last-succ-join-atmpt-time"),
                "last_join_failure": info.get("last-fail-join-atmpt-time"),
                "last_error": info.get("last-error-type"),
                "last_error_time": info.get("last-error-time"),
                "disconnect_reason": entry.get("disconnect-reason"),
                "ap_disconnect_reason": entry.get("ap-disconnect-reason"),
                "reboot_reason": entry.get("reboot-reason"),
                "dtls_ctrl_failures": _to_int(dtls.get("ctrl-dtls-failure")),
                "dtls_data_failures": _to_int(dtls.get("data-dtls-failure")),
            }
        )
    for ap in capwap_entries:
        name = ap.get("name") or _mac(ap.get("wtp-mac"))
        if not name:
            continue
        entry = normalized.setdefault("ap|%s" % (name,), {})
        entry.update(
            _compact(
                {
                    "joined": True,
                    "boot_time": _leaf(ap, "ap-time-info", "boot-time"),
                    "join_time": _leaf(ap, "ap-time-info", "join-time"),
                    "join_time_taken_s": _to_int(_leaf(ap, "ap-time-info", "join-time-taken")),
                    "reboot_reason": _leaf(ap, "reboot-stats", "reboot-reason"),
                    "reboot_type": _leaf(ap, "reboot-stats", "reboot-type"),
                    "disconnect_reason": _leaf(ap, "disconnect-detail", "disconnect-reason"),
                }
            )
        )
    return normalized


def _collect_ap_join_stats(ctx):
    facts = _controller(ctx)
    notes = []
    names = _ap_names(ctx)
    joins, join_payload = _fetch(
        ctx, facts, _AP_GLOBAL_OPER, "ap-join-stats", _JOIN_FIELDS, notes=notes
    )
    aps, _ = _capwap(ctx, facts, notes)  # cache hit after wlc_ap_inventory
    normalized = _normalize_join_stats(joins, aps, names)
    context = {
        "known_total": len(normalized),
        "joined": sum(1 for v in normalized.values() if v.get("joined")),
        "not_joined": sum(1 for v in normalized.values() if not v.get("joined")),
    }
    raw = {"ap-join-stats": join_payload, "note": "capwap-data rides in the wlc_ap_inventory raw"}
    if notes:
        raw["note"] += "; " + "; ".join(notes)
    return {"raw": raw, "normalized": normalized, "context": context}


# --- wlc_clients_summary -----------------------------------------------------


def _normalize_clients_summary(live, wlans, clients, policies, exclusions):
    """(capability buckets, context) — the wireless analogue of the session matrix.

    Normalized keys are flat counts the capability diff evaluates: a bucket
    busy pre must carry SOMETHING post. Only the healthy 'run-state' count is
    a bucket; the other client states (stuck in auth / IP-learn / webauth)
    are informational and live in context, where a jump reads as the failure
    signature instead of a false capability miss.
    """
    normalized = {"total": len(clients)}
    run_state = _to_int(live.get("run-state-clients"))
    if run_state is not None:
        normalized["run-state"] = run_state
    for wlan in wlans:
        profile = wlan.get("wlan-profile")
        if profile:
            normalized["wlan|%s" % (profile,)] = _to_int(wlan.get("curr-clients-count"))
    by_ap = Counter(c.get("ap-name") for c in clients if c.get("ap-name"))
    for ap, count in by_ap.items():
        normalized["ap|%s" % (ap,)] = count
    by_band = Counter(
        _CLIENT_BANDS.get(str(c.get("ms-radio-type")), str(c.get("ms-radio-type")))
        for c in clients
        if c.get("ms-radio-type") is not None
    )
    for band, count in by_band.items():
        normalized["band|%s" % (band,)] = count
    vlan_names = {}
    by_vlan = Counter()
    for policy in policies:
        vlan = policy.get("res-vlan-id")
        if vlan is None:
            continue
        by_vlan[str(vlan)] += 1
        if policy.get("res-vlan-name"):
            vlan_names[str(vlan)] = policy.get("res-vlan-name")
    for vlan, count in by_vlan.items():
        normalized["vlan|%s" % (vlan,)] = count

    live_states = {}
    for leaf, value in live.items():
        if str(leaf).endswith("-state-clients"):
            live_states[str(leaf)[: -len("-state-clients")]] = _to_int(value)
    table_states = Counter(
        _short(c.get("co-state"), "client-status-") or "unknown" for c in clients
    )
    context = {
        "live_states": live_states,
        "live_total": sum(v for v in live_states.values() if v is not None),
        "random_mac_clients": _to_int(live.get("random-mac-clients")),
        "table_total": len(clients),
        "table_by_state": dict(table_states),
        "not_run_state": sum(n for state, n in table_states.items() if state != "run"),
        "wlan_total": sum(v for k, v in normalized.items() if k.startswith("wlan|") and v),
        "aps_with_clients": len(by_ap),
        "vlan_names": vlan_names,
        "excluded_total": len(exclusions),
        "excluded_by_reason": dict(
            Counter(_short(e.get("exclude-reason"), "exclude-") or "unknown" for e in exclusions)
        ),
    }
    return normalized, context


def _client_reads(ctx, facts, notes):
    """The two client lists the summary and the table both consume (cached)."""
    clients, client_payload = _fetch(
        ctx,
        facts,
        _CLIENT_OPER,
        "common-oper-data",
        _CLIENT_FIELDS,
        timeout=C.BIG_GET_TIMEOUT,
        notes=notes,
    )
    policies, policy_payload = _fetch(
        ctx,
        facts,
        _CLIENT_OPER,
        "policy-data",
        _CLIENT_POLICY_FIELDS,
        timeout=C.BIG_GET_TIMEOUT,
        notes=notes,
    )
    return clients, policies, client_payload, policy_payload


def _collect_clients_summary(ctx):
    facts = _controller(ctx)
    notes = []
    live_payload = _required(ctx, facts, _CLIENT_GLOBAL_OPER + "/client-live-stats")
    live = _node(live_payload, "client-live-stats")
    live = live if isinstance(live, dict) else {}
    wlans, wlan_payload = _fetch(
        ctx, facts, _WLAN_GLOBAL_OPER, "wlan-info", _WLAN_INFO_FIELDS, notes=notes
    )
    clients, policies, _, _ = _client_reads(ctx, facts, notes)
    exclusions, exclusion_payload = _fetch(
        ctx, facts, _CLIENT_OPER, "exclusion-data", _EXCLUSION_FIELDS, notes=notes
    )
    normalized, context = _normalize_clients_summary(live, wlans, clients, policies, exclusions)
    # The per-client lists ride in the wlc_client_table raw (capped there);
    # here raw keeps the small device-computed views only.
    raw = {
        "client-live-stats": live_payload,
        "wlan-info": wlan_payload,
        "exclusion-data": exclusion_payload,
        "note": "per-client rows live in the wlc_client_table raw",
    }
    if notes:
        raw["note"] += "; " + "; ".join(notes)
    return {"raw": raw, "normalized": normalized, "context": context}


# --- wlc_client_table --------------------------------------------------------


def _client_rows(clients, dot11, policies, sisf):
    """{mac: row} joining the four per-client lists; usernames are never present."""
    dot11_by = {_mac(e.get("ms-mac-address")): e for e in dot11 if e.get("ms-mac-address")}
    policy_by = {_mac(e.get("mac")): e for e in policies if e.get("mac")}
    ip_by = {
        _mac(e.get("mac-addr")): _leaf(e, "ipv4-binding", "ip-key", "ip-addr")
        for e in sisf
        if e.get("mac-addr")
    }
    rows = {}
    for client in clients:
        mac = _mac(client.get("client-mac"))
        if not mac:
            continue
        d11 = dot11_by.get(mac, {})
        policy = policy_by.get(mac, {})
        rows[mac] = _compact(
            {
                "ap": client.get("ap-name"),
                "slot": _to_int(client.get("ms-ap-slot-id")),
                "band": _CLIENT_BANDS.get(
                    str(client.get("ms-radio-type")), client.get("ms-radio-type")
                ),
                "wlan_id": _to_int(client.get("wlan-id")),
                "ssid": d11.get("vap-ssid"),
                "policy_profile": d11.get("policy-profile"),
                "state": _short(client.get("co-state"), "client-status-"),
                "dot11_state": d11.get("dot11-state"),
                "vlan": _to_int(policy.get("res-vlan-id")),
                "vlan_name": policy.get("res-vlan-name"),
                "ip": ip_by.get(mac),
                "switching": _leaf(client, "wlan-policy", "current-switching-mode"),
                "phy": d11.get("ewlc-ms-phy-type"),
                "security": d11.get("security-mode"),
                "encryption": d11.get("encryption-type"),
                "bssid": _mac(d11.get("ms-bssid")),
                "channel": _to_int(d11.get("current-channel")),
                "assoc_time": d11.get("ms-assoc-time"),
                "vrf": client.get("vrf-name") or None,
            }
        )
    return rows


def _cap_client_rows(rows, cap):
    """Non-run clients always; run-state clients until the cap. Returns (kept, omitted)."""
    normalized = {}
    omitted = 0
    for mac in sorted(rows, key=lambda m: (rows[m].get("state") == "run", m)):
        if rows[mac].get("state") != "run" or len(normalized) < cap:
            normalized["client|%s" % (mac,)] = rows[mac]
        else:
            omitted += 1
    return normalized, omitted


def _collect_client_table(ctx):
    facts = _controller(ctx)
    notes = []
    clients, policies, _, _ = _client_reads(ctx, facts, notes)  # cache hits after the summary
    dot11, _ = _fetch(
        ctx,
        facts,
        _CLIENT_OPER,
        "dot11-oper-data",
        _CLIENT_DOT11_FIELDS,
        timeout=C.BIG_GET_TIMEOUT,
        notes=notes,
    )
    sisf, _ = _fetch(
        ctx,
        facts,
        _CLIENT_OPER,
        "sisf-db-mac",
        _CLIENT_SISF_FIELDS,
        timeout=C.BIG_GET_TIMEOUT,
        notes=notes,
    )
    rows = _client_rows(clients, dot11, policies, sisf)
    normalized, omitted = _cap_client_rows(rows, C.WLC_CLIENT_TABLE_MAX)
    context = {
        "clients_total": len(rows),
        "emitted": len(normalized),
        "omitted_run_state": omitted,
        "cap": C.WLC_CLIENT_TABLE_MAX,
        "by_state": dict(Counter(row.get("state") or "unknown" for row in rows.values())),
    }
    raw_rows = dict(sorted(rows.items())[: C.WLC_CLIENT_RAW_MAX])
    raw = {"rows": raw_rows}
    if len(rows) > len(raw_rows):
        notes.append("raw rows truncated to %d of %d" % (len(raw_rows), len(rows)))
    if notes:
        raw["note"] = "; ".join(notes)
    return {"raw": raw, "normalized": normalized, "context": context}


# --- wlc_wlan_config ---------------------------------------------------------


def _normalize_wlan_config(wlans, policies, tags):
    """'wlan|<profile>', 'policy|<profile>', 'policy-tag|<tag>' — the SSID contract."""
    normalized = {}
    for wlan in wlans:
        profile = wlan.get("profile-name")
        if not profile:
            continue
        vap = _sub(wlan, "apf-vap-id-data")
        normalized["wlan|%s" % (profile,)] = _compact(
            {
                "wlan_id": _to_int(wlan.get("wlan-id")),
                "ssid": vap.get("ssid"),
                "enabled": _yes(vap.get("wlan-status")),
                "broadcast_ssid": _yes(vap.get("broadcast-ssid")),
                "security_wpa": _yes(wlan.get("security-wpa")),
                "dot11_auth_type": wlan.get("dot11-auth-type"),
                "webauth": _yes(wlan.get("webauth-enabled")),
                "wep": _yes(wlan.get("wep-enabled")),
                "description": wlan.get("description"),
            }
        )
    for policy in policies:
        name = policy.get("policy-profile-name")
        if not name:
            continue
        switching = _sub(policy, "wlan-switching-policy")
        flex = _sub(policy, "wlan-flex-policy")
        normalized["policy|%s" % (name,)] = _compact(
            {
                "enabled": _yes(policy.get("status")),
                "vlan": policy.get("interface-name"),
                "central_switching": _yes(switching.get("central-switching")),
                "central_authentication": _yes(switching.get("central-authentication")),
                "central_dhcp": _yes(switching.get("central-dhcp")),
                "central_assoc": _yes(switching.get("central-assoc-enable")),
                "vlan_central_switching": _yes(flex.get("vlan-central-switching")),
                "description": policy.get("description"),
            }
        )
    for tag in tags:
        name = tag.get("tag-name")
        if not name:
            continue
        mapping = {}
        for entry in _aslist(_sub(tag, "wlan-policies").get("wlan-policy")):
            if isinstance(entry, dict) and entry.get("wlan-profile-name"):
                mapping[str(entry["wlan-profile-name"])] = entry.get("policy-profile-name")
        normalized["policy-tag|%s" % (name,)] = _compact(
            {"wlans": mapping, "description": tag.get("description")}
        )
    return _scrub(normalized)


def _collect_wlan_config(ctx):
    facts = _controller(ctx)
    notes = []
    wlans, wlan_payload = _fetch(
        ctx, facts, _WLAN_CFG + "/wlan-cfg-entries", "wlan-cfg-entry", _WLAN_FIELDS, notes=notes
    )
    policies, policy_payload = _fetch(
        ctx, facts, _WLAN_CFG + "/wlan-policies", "wlan-policy", _POLICY_FIELDS, notes=notes
    )
    tags, tag_payload = _fetch(
        ctx,
        facts,
        _WLAN_CFG + "/policy-list-entries",
        "policy-list-entry",
        _POLICY_TAG_FIELDS,
        notes=notes,
    )
    normalized = _normalize_wlan_config(wlans, policies, tags)
    raw = _scrub(
        {
            "wlan-cfg-entry": wlan_payload,
            "wlan-policy": policy_payload,
            "policy-list-entry": tag_payload,
        }
    )
    if notes:
        raw["note"] = "; ".join(notes)
    context = {
        "wlans": sum(1 for k in normalized if k.startswith("wlan|")),
        "wlans_enabled": sum(
            1 for k, v in normalized.items() if k.startswith("wlan|") and v.get("enabled")
        ),
        "policy_profiles": sum(1 for k in normalized if k.startswith("policy|")),
        "policy_tags": sum(1 for k in normalized if k.startswith("policy-tag|")),
    }
    return {"raw": raw, "normalized": normalized, "context": context}


# --- wlc_tag_config ----------------------------------------------------------


def _normalize_tag_config(site_tags, rf_tags, flex_profiles, ap_tags, names):
    """Site/RF tags, flex profiles with their VLAN maps, and the static per-AP tag map."""
    normalized = {}
    for tag in site_tags:
        name = tag.get("site-tag-name")
        if name:
            normalized["site-tag|%s" % (name,)] = _compact(
                {
                    "flex_profile": tag.get("flex-profile"),
                    "ap_join_profile": tag.get("ap-join-profile"),
                    "local_site": _yes(tag.get("is-local-site")),
                    "description": tag.get("description"),
                }
            )
    for tag in rf_tags:
        name = tag.get("tag-name") or tag.get("rf-tag-name")
        if name:
            normalized["rf-tag|%s" % (name,)] = _compact(
                {
                    "rf_profile_24ghz": tag.get("dot11b-rf-profile-name"),
                    "rf_profile_5ghz": tag.get("dot11a-rf-profile-name"),
                    "rf_profile_6ghz": tag.get("dot11-6ghz-rf-prof-name"),
                    "description": tag.get("description"),
                }
            )
    for flex in flex_profiles:
        name = flex.get("policy-name")
        if not name:
            continue
        vlan_map = {}
        for entry in _aslist(_sub(flex, "if-name-vlan-ids").get("if-name-vlan-id")):
            if isinstance(entry, dict) and entry.get("interface-name"):
                vlan_map[str(entry["interface-name"])] = _to_int(entry.get("vlan-id"))
        normalized["flex|%s" % (name,)] = _compact(
            {
                "native_vlan": _to_int(flex.get("native-vlan-id")),
                "vlan_support": _yes(flex.get("vlan-enable")),
                "local_roaming": _yes(flex.get("is-local-roaming-enable")),
                "radius_group": flex.get("radius-server-group-name"),
                "vlan_map": vlan_map,
                "description": flex.get("description"),
            }
        )
    for tag in ap_tags:
        mac = _mac(tag.get("ap-mac"))
        if mac:
            normalized["ap-tag|%s" % (mac,)] = _compact(
                {
                    "policy_tag": tag.get("policy-tag"),
                    "site_tag": tag.get("site-tag"),
                    "rf_tag": tag.get("rf-tag"),
                    "ap_name": names.get(mac),
                }
            )
    return _scrub(normalized)


def _collect_tag_config(ctx):
    facts = _controller(ctx)
    notes = []
    names = _ap_names(ctx)
    site_tags, site_payload = _fetch(
        ctx,
        facts,
        _SITE_CFG + "/site-tag-configs",
        "site-tag-config",
        _SITE_TAG_FIELDS,
        notes=notes,
    )
    rf_tags, rf_payload = _fetch(
        ctx, facts, _RF_CFG + "/rf-tags", "rf-tag", _RF_TAG_FIELDS, notes=notes
    )
    flex, flex_payload = _fetch(
        ctx,
        facts,
        _FLEX_CFG + "/flex-policy-entries",
        "flex-policy-entry",
        _FLEX_FIELDS,
        notes=notes,
    )
    ap_tags, ap_tag_payload = _fetch(
        ctx, facts, _AP_CFG + "/ap-tags", "ap-tag", _AP_TAG_FIELDS, notes=notes
    )
    normalized = _normalize_tag_config(site_tags, rf_tags, flex, ap_tags, names)
    raw = _scrub(
        {
            "site-tag-config": site_payload,
            "rf-tag": rf_payload,
            "flex-policy-entry": flex_payload,
            "ap-tag": ap_tag_payload,
        }
    )
    if notes:
        raw["note"] = "; ".join(notes)
    context = {
        "site_tags": len(site_tags),
        "rf_tags": len(rf_tags),
        "flex_profiles": len(flex),
        "static_ap_tags": len(ap_tags),
        "static_ap_tags_joined": sum(
            1 for k, v in normalized.items() if k.startswith("ap-tag|") and v.get("ap_name")
        ),
    }
    return {"raw": raw, "normalized": normalized, "context": context}


# --- wlc_mobility ------------------------------------------------------------


def _normalize_mobility(global_data, config, nodes, ap_peers):
    """'self' plus 'peer|<ip>' with control/data tunnel state and flap counts."""
    normalized = {
        "self": _compact(
            {
                "mobility_mac": _mac(global_data.get("mm-mac-addr")),
                "group": config.get("local-group"),
                "multicast": config.get("local-multicast-address")
                if _yes(config.get("local-mcast-addr-enabled"))
                else None,
            }
        )
    }
    ap_counts = {
        str(p.get("peer-ip")): _to_int(p.get("ap-count")) for p in ap_peers if p.get("peer-ip")
    }
    for node in nodes:
        ip = node.get("node-ip")
        if not ip:
            continue
        ctrl = _sub(node, "ctrl-state")
        data = _sub(node, "data-state")
        normalized["peer|%s" % (ip,)] = _compact(
            {
                "group": node.get("group-name"),
                "status": _short(node.get("ulink-status"), "status-"),
                "control_link": _yes(ctrl.get("link-status")),
                "control_peer": _yes(ctrl.get("peer-status")),
                "control_flaps": _to_int(ctrl.get("flaps-cnt")),
                "data_link": _yes(data.get("link-status")),
                "data_peer": _yes(data.get("peer-status")),
                "data_flaps": _to_int(data.get("flaps-cnt")),
                "tunnel_plumbed": _yes(node.get("tunnel-plumbed")),
                "anchor": _yes(node.get("is-anchor")),
                "clients": _to_int(node.get("num-clients")),
                "nat_ip": node.get("nat-ip") if node.get("nat-ip") not in (None, ip) else None,
                "ap_count": ap_counts.get(str(ip)),
            }
        )
    return normalized


def _collect_mobility(ctx):
    facts = _controller(ctx)
    notes = []
    global_payload = _required(ctx, facts, _MOBILITY_OPER + "/mm-global-data")
    global_data = _node(global_payload, "mm-global-data")
    global_data = global_data if isinstance(global_data, dict) else {}
    # The configured group name lives in the cfg model; best-effort, since a
    # release may spell the container differently.
    config_payload = ctx.get(_MOBILITY_CFG + "/mobility-config", ok_404=True)
    config = _node(config_payload, "mobility-config")
    config = config if isinstance(config, dict) else {}
    if config_payload is None:
        notes.append("mobility-config not served; group name unavailable")
    nodes, node_payload = _fetch(
        ctx, facts, _MOBILITY_OPER, "mobility-node-data", _MOBILITY_NODE_FIELDS, notes=notes
    )
    ap_peers, peer_payload = _fetch(
        ctx, facts, _MOBILITY_OPER, "ap-peer-list", _AP_PEER_FIELDS, notes=notes
    )
    normalized = _normalize_mobility(global_data, config, nodes, ap_peers)
    peers = [v for k, v in normalized.items() if k.startswith("peer|")]
    context = {
        "peers_total": len(peers),
        "peers_up": sum(1 for p in peers if p.get("status") == "up"),
        "peer_groups": sorted({p.get("group") for p in peers if p.get("group")}),
    }
    raw = {
        "mm-global-data": global_payload,
        "mobility-config": config_payload,
        "mobility-node-data": node_payload,
        "ap-peer-list": peer_payload,
    }
    if notes:
        raw["note"] = "; ".join(notes)
    return {"raw": raw, "normalized": normalized, "context": context}


# --- wlc_platform ------------------------------------------------------------

_REDUNDANCY_SCALARS = (
    ("hardware_mode", re.compile(r"^\s*Hardware Mode\s*=\s*(.+?)\s*$", re.MULTILINE)),
    (
        "configured_mode",
        re.compile(r"^\s*Configured Redundancy Mode\s*=\s*(.+?)\s*$", re.MULTILINE),
    ),
    ("operating_mode", re.compile(r"^\s*Operating Redundancy Mode\s*=\s*(.+?)\s*$", re.MULTILINE)),
    ("communications", re.compile(r"^\s*Communications\s*=\s*(.+?)\s*$", re.MULTILINE)),
    (
        "last_switchover_reason",
        re.compile(r"^\s*Last switchover reason\s*=\s*(.+?)\s*$", re.MULTILINE),
    ),
)
_REDUNDANCY_SWITCHOVERS = re.compile(
    r"^\s*Switchovers system experienced\s*=\s*(\d+)", re.MULTILINE
)
_REDUNDANCY_STATE = re.compile(r"^\s*Current Software state\s*=\s*(.+?)\s*$", re.MULTILINE)
_REDUNDANCY_PEER_ABSENT = re.compile(
    r"Peer[^\n]*?information is not available because it is in '?([A-Za-z ]+?)'? state",
    re.IGNORECASE,
)


def _parse_show_redundancy(text):
    """Scalars from `show redundancy`; {} when nothing recognizable was printed.

    'Current Software state' appears once per processor: the first is the
    active, the second (when a standby exists) is the peer. A standalone
    prints the peer as unavailable in a DISABLED state.
    """
    text = text or ""
    parsed = {}
    for field, pattern in _REDUNDANCY_SCALARS:
        match = pattern.search(text)
        if match:
            parsed[field] = match.group(1)
    match = _REDUNDANCY_SWITCHOVERS.search(text)
    if match:
        parsed["switchovers"] = int(match.group(1))
    states = _REDUNDANCY_STATE.findall(text)
    if states:
        parsed["active_state"] = states[0]
        if len(states) > 1:
            parsed["peer_state"] = states[1]
    match = _REDUNDANCY_PEER_ABSENT.search(text)
    if match and "peer_state" not in parsed:
        parsed["peer_state"] = "not available (%s)" % (match.group(1).strip(),)
    return parsed


def _cli_rejected(output):
    lowered = (output or "").lower()
    return "invalid input" in lowered or "incomplete command" in lowered


def _normalize_platform(facts, mgmt, joined_aps, stack_nodes, redundancy):
    normalized = {"controller": dict(facts)}
    if mgmt:
        normalized["mgmt-intf"] = _compact(
            {
                "name": mgmt.get("intf-name"),
                "type": mgmt.get("intf-type"),
                "ip": mgmt.get("mgmt-ip"),
                "netmask": mgmt.get("net-mask"),
                "mac": _mac(mgmt.get("mgmt-mac")),
            }
        )
    if joined_aps is not None:
        normalized["joined-aps"] = {"count": joined_aps}
    for index, node in enumerate(stack_nodes, 1):
        number = node.get("chassis-number", index)
        normalized["chassis|%s" % (number,)] = _compact(
            {
                "role": _short(node.get("role"), "role-"),
                "state": _short(node.get("node-state"), "state-"),
                "serial": node.get("serial-number"),
                "mac": _mac(node.get("mac-address")),
                "priority": _to_int(node.get("priority")),
                "mode": node.get("mode"),
                "configured_mode": node.get("configured-mode"),
                "sso_ready": _yes(node.get("sso-ready-flag")),
                "reload_reason": node.get("reload-reason"),
            }
        )
    if redundancy:
        normalized["redundancy"] = redundancy
    return normalized


def _collect_platform(ctx):
    facts = _controller(ctx)
    notes = []
    mgmt_payload = _required(ctx, facts, _GENERAL_OPER + "/mgmt-intf-data")
    mgmt = _node(mgmt_payload, "mgmt-intf-data")
    mgmt = mgmt if isinstance(mgmt, dict) else {}
    joined_payload = ctx.get(_AP_GLOBAL_OPER + "/emltd-join-count-stat", ok_404=True)
    joined = _to_int(_sub(_node(joined_payload, "emltd-join-count-stat")).get("joined-aps-count"))
    if joined_payload is None:
        notes.append("emltd-join-count-stat not served; joined-AP count skipped")
    # Same path + kwargs as the switch-stack supplement: cached on a shared run.
    stack_payload = ctx.get(_STACK_OPER_PATH, ok_404=True)
    stack_nodes = _entries(stack_payload, "stack-node")
    if stack_payload is None:
        notes.append("stack-oper-data not served; chassis roles skipped")
    redundancy = {}
    raw = {
        "mgmt-intf-data": mgmt_payload,
        "emltd-join-count-stat": joined_payload,
        "stack-oper-data": stack_payload,
    }
    if ctx.has_ssh:
        command = "show redundancy"
        output = ctx.run_ssh(command)
        raw[command] = output
        if _cli_rejected(output):
            notes.append("show redundancy rejected on this platform")
        else:
            redundancy = _parse_show_redundancy(output)
            if not redundancy:
                notes.append("show redundancy answered but nothing parsed — format needs shakedown")
    else:
        notes.append("no SSH transport; show redundancy skipped")
    normalized = _normalize_platform(facts, mgmt, joined, stack_nodes, redundancy)
    context = {
        "controller": facts,
        "chassis_total": len(stack_nodes),
        "chassis_active": sum(1 for n in stack_nodes if _short(n.get("role"), "role-") == "active"),
    }
    if notes:
        raw["note"] = "; ".join(notes)
    return {"raw": raw, "normalized": normalized, "context": context}


# --- iosxe_aaa_servers (generic IOS-XE: switches doing 802.1X need it too) ---


def _normalize_aaa_servers(entries):
    """'radius|<group>|<ip>:<auth-port>' -> alive/dead/mixed across the server instances."""
    normalized = {}
    for server in entries:
        key = "radius|%s|%s:%s" % (
            server.get("group-name"),
            server.get("radius-server-ip"),
            server.get("auth-port"),
        )
        details = [d for d in _aslist(server.get("server-detail")) if isinstance(d, dict)]
        states = [str(d.get("server-state")) for d in details if d.get("server-state") is not None]
        alive = sum(1 for state in states if state.endswith("alive"))
        dead = sum(1 for state in states if state.endswith("dead"))
        if not states:
            state = None
        elif alive == len(states):
            state = "alive"
        elif dead == len(states):
            state = "dead"
        else:
            state = "mixed"
        normalized[key] = _compact(
            {
                "state": state,
                "instances": len(details) or None,
                "instances_alive": alive if states else None,
                "acct_port": _to_int(server.get("acct-port")),
                "radsec": _yes(server.get("is-server-radsec")),
            }
        )
    return normalized


def _aaa_context(entries, normalized):
    return {
        "servers_total": len(normalized),
        "servers_not_alive": sum(1 for v in normalized.values() if v.get("state") != "alive"),
        "authen_accepts": sum(_to_int(e.get("authen-access-accepts")) or 0 for e in entries),
        "authen_rejects": sum(_to_int(e.get("authen-access-rejects")) or 0 for e in entries),
        "authen_timeouts": sum(
            _to_int(e.get("authen-timeout-access-requests")) or 0 for e in entries
        ),
    }


def _collect_aaa_servers(ctx):
    # Not gated on the controller: a 9300 access switch doing 802.1X has the
    # same servers and the same failure mode.
    path = "%s/aaa-radius-stats?fields=%s" % (_AAA_OPER, _AAA_FIELDS)
    notes = []
    try:
        payload = ctx.get(path, ok_404=True)
    except Exception as exc:
        if getattr(exc, "status_code", None) != 400:
            raise
        notes.append("aaa-radius-stats: fields filter rejected (HTTP 400); unfiltered read used")
        payload = ctx.get(_AAA_OPER + "/aaa-radius-stats", ok_404=True)
    if payload is None:
        raise SkipCheck("RADIUS server statistics not served (aaa-oper model absent)")
    entries = _entries(payload, "aaa-radius-stats")
    if not entries:
        raise SkipCheck("no RADIUS servers configured")
    normalized = _normalize_aaa_servers(entries)
    raw = {"aaa-radius-stats": payload}
    if notes:
        raw["note"] = "; ".join(notes)
    return {"raw": raw, "normalized": normalized, "context": _aaa_context(entries, normalized)}


# --- semantics (merged into registry.SEMANTICS at import) --------------------

SEMANTICS = {
    "wlc_ap_inventory": (
        "The joined-AP roster keyed 'ap|<name>': radio and Ethernet MAC, model, serial, "
        "IP, software version, mode (local/flex-connect/monitor...), admin and oper state "
        "(registered is healthy), country, configured location, and the RESOLVED policy/"
        "site/RF tags with their source (static, filter, default, location) plus the "
        "controller's own misconfigured flag. A key that vanished is an AP that did not "
        "come back; an AP whose tags read default-* after a move broadcasts the wrong "
        "SSIDs on the wrong VLAN. Context carries counts by state, mode, model and "
        "version — ap_count 0 on a controller is the loudest finding there is. Join and "
        "boot times live in wlc_ap_join_stats so an expected fleet-wide rejoin never "
        "drowns this table in changes."
    ),
    "wlc_ap_radios": (
        "Per-radio state keyed 'radio|<ap>|<slot>': band, admin state, oper state (up is "
        "healthy), channel and width, power level and dBm, and whether channel/power were "
        "decided by RRM (auto) or typed by a human (static). Channel and power DRIFT under "
        "RRM between healthy captures — the state and the static assignments are what "
        "gate; a radio down under a registered AP is invisible in the inventory. Context "
        "carries up/down totals per band, alongside the controller's own per-band radio "
        "counters as corroboration."
    ),
    "wlc_ap_uplinks": (
        "Where each AP plugs in, from the controller's side: 'cdp|<ap>|<port>' and "
        "'lldp|<ap>|<port>' name the switch and switch port behind the AP (pair with the "
        "switch-side iosxe_neighbors view), and 'eth|<ap>|<interface>' carries the AP "
        "port's link, speed and duplex. Re-cabled APs move by design; an AP that came "
        "back at 100 Mb or half duplex, or on an unexpected switch, is a finding. Context "
        "lists ports below 1G."
    ),
    "wlc_ap_join_stats": (
        "Join history keyed 'ap|<name>' for every AP the controller has ever seen: "
        "joined flag, boot and join time, join-time-taken, join request/success/failure "
        "COUNTERS (cumulative — read deltas), last error, last disconnect and reboot "
        "reasons, DTLS failure counters. Informational: across a migration every AP is "
        "expected to rejoin ONCE for the declared reason; more than one join in the "
        "window, a reboot reason other than the expected one, or a boot_time that changed "
        "when no AP reload was planned is a finding. joined=false entries are APs the "
        "controller remembers but no longer serves."
    ),
    "wlc_clients_summary": (
        "Client-count buckets evaluated as CAPABILITY, the session-matrix analogue: "
        "'total', 'run-state', 'wlan|<profile>', 'ap|<name>', 'band|<band>' and "
        "'vlan|<id>' (the VLAN each client actually landed on). A bucket busy pre must "
        "carry SOME clients post: fewer means users are still ramping back, zero on a "
        "previously busy WLAN or AP means that path does not work. Context holds the "
        "informational client-state distribution — a jump in ip-learning or "
        "authenticating clients is the DHCP-or-RADIUS failure signature — plus VLAN "
        "names, exclusions by reason, and reconciliation totals."
    ),
    "wlc_client_table": (
        "Per-client rows keyed 'client|<mac>': AP, slot, band, WLAN id and SSID, policy "
        "profile, client state, resolved VLAN, learned IPv4 address, switching mode, PHY, "
        "security. Usernames and device hostnames are deliberately never collected. The "
        "row set churns constantly and is informational; what the analyst reads is WHICH "
        "clients are not in the run state and where they sit (VLAN without an IP = DHCP "
        "or trunk problem on that VLAN). Non-run clients are always present; run-state "
        "rows fill up to a cap (context notes what was omitted)."
    ),
    "wlc_wlan_config": (
        "What a human TYPED for the SSID contract: 'wlan|<profile>' (WLAN id, SSID, "
        "enabled, broadcast, WPA/web-auth/WEP flags), 'policy|<profile>' (VLAN, "
        "central vs local switching, central authentication and DHCP), and "
        "'policy-tag|<tag>' (which WLAN maps to which policy profile). PSK, MPSK and WEP "
        "keys are scrubbed before the data leaves the collector. Config has zero "
        "volatility: any diff is either the planned edit or an undeclared change, and "
        "across a controller-to-controller migration the WLAN and policy sets must match."
    ),
    "wlc_tag_config": (
        "The site-specific configuration: 'site-tag|<name>' (AP join profile, flex "
        "profile, local-site flag), 'rf-tag|<name>' (per-band RF profiles), "
        "'flex|<name>' (native VLAN and the interface-to-VLAN map a FlexConnect site "
        "switches locally), and 'ap-tag|<ethernet-mac>' (the STATIC per-AP tag "
        "assignment, with the AP name when that AP is currently joined). For a "
        "FlexConnect site the flex VLAN map IS the migration. Local-auth passwords are "
        "scrubbed."
    ),
    "wlc_mobility": (
        "Mobility keyed 'self' (mobility MAC and group) and 'peer|<ip>' (peer group, "
        "unified status — up is healthy — control and data tunnel link/peer flags, "
        "tunnel plumbed, anchor role, clients on the peer, and flap COUNTS that only "
        "increment when a tunnel bounced). Peers must be up for roaming to work and for "
        "APs failing over between controllers during a migration; a new flap count "
        "means the tunnel dropped inside the window."
    ),
    "wlc_platform": (
        "Controller identity and HA: 'controller' (chassis model and how the device was "
        "identified as a controller), 'mgmt-intf' (the wireless management interface, "
        "IP and MAC — every AP joins to this address, so a change means a fleet-wide "
        "rejoin), 'joined-aps' count, 'chassis|<n>' (role and state per chassis — one "
        "active/ready chassis is a standalone; the mode strings are constants a "
        "standalone publishes too and mean nothing), and 'redundancy' from show "
        "redundancy (hardware/operating mode, peer state, switchover COUNT — a delta "
        "means a switchover happened in the window)."
    ),
    "iosxe_aaa_servers": (
        "RADIUS servers keyed 'radius|<group>|<ip>:<auth-port>' with the state across "
        "the device's server instances (alive is healthy; mixed means some instances "
        "mark it dead) and RadSec flag. Not-present when no RADIUS server is "
        "configured. Authentication accept/reject/timeout counters are cumulative and "
        "live in context — a rising timeout count with dead servers after a re-IP is "
        "the classic 'everything is up but nobody can log in'. Applies to switches "
        "doing 802.1X as much as to controllers."
    ),
}
_REGISTRY_SEMANTICS.update(SEMANTICS)


# --- registrations -----------------------------------------------------------

register(
    CheckDef(
        id="wlc_ap_inventory",
        platform="iosxe",
        description="Joined-AP roster: identity, software, mode, admin/oper state, resolved tags",
        tier=1,
        compare={"mode": "equality_set"},
        miss_meaning=(
            "An AP did not come back, changed mode or tags, or is no longer registered — "
            "a site without its APs has no wireless at all, and an AP on default tags "
            "serves the wrong SSIDs."
        ),
        collector=_collect_ap_inventory,
        tags=("wireless", "access-points"),
    )
)

register(
    CheckDef(
        id="wlc_ap_radios",
        platform="iosxe",
        description="Per-AP radio state: band, admin/oper, channel, width, power and their sources",
        tier=1,
        compare={"mode": "equality_set"},
        miss_meaning=(
            "A radio is down or disabled under an AP that reads as registered, or a static "
            "channel/power assignment changed — coverage lost that the AP inventory "
            "cannot see."
        ),
        collector=_collect_ap_radios,
        tags=("wireless", "access-points", "rf"),
    )
)

register(
    CheckDef(
        id="wlc_ap_uplinks",
        platform="iosxe",
        description="AP uplinks: switch/port per AP (CDP/LLDP), Ethernet link/speed/duplex",
        tier=2,
        compare={"mode": "equality_set"},
        miss_meaning=(
            "An AP moved to an unexpected switch or port, or came back below gigabit / "
            "half duplex — the classic re-cabling error that passes every up/down check."
        ),
        collector=_collect_ap_uplinks,
        tags=("wireless", "access-points", "topology"),
    )
)

register(
    CheckDef(
        id="wlc_ap_join_stats",
        platform="iosxe",
        description="AP join history: boot/join times, join counters, disconnect/reboot reasons",
        tier=3,
        compare={"mode": "info_only"},
        miss_meaning=(
            "Informational — read join counters as deltas: an AP that joined more than "
            "once, rebooted for an unexpected reason, or whose boot time moved without a "
            "planned reload bounced during the window."
        ),
        collector=_collect_ap_join_stats,
        tags=("wireless", "access-points"),
    )
)

register(
    CheckDef(
        id="wlc_clients_summary",
        platform="iosxe",
        description="Client counts per WLAN, AP, band and landed VLAN, evaluated as capability",
        tier=1,
        compare={"mode": "capability", "floor_pre": 5, "min_post": 1},
        miss_meaning=(
            "A WLAN, AP, band or VLAN that carried clients before carries none now — that "
            "path does not work after the change (fewer clients merely means ramping)."
        ),
        collector=_collect_clients_summary,
        tags=("wireless", "clients"),
    )
)

register(
    CheckDef(
        id="wlc_client_table",
        platform="iosxe",
        description="Per-client rows: AP, WLAN/SSID, state, resolved VLAN, learned IP (capped)",
        tier=3,
        compare={"mode": "info_only"},
        miss_meaning=(
            "Informational — the rows churn; the analyst reads which clients are stuck "
            "outside the run state and on which VLAN/AP they sit."
        ),
        collector=_collect_client_table,
        tags=("wireless", "clients"),
    )
)

register(
    CheckDef(
        id="wlc_wlan_config",
        platform="iosxe",
        description="WLAN, policy-profile and policy-tag configuration (keys scrubbed)",
        tier=2,
        compare={"mode": "equality_set"},
        miss_meaning=(
            "The SSID contract changed: a WLAN, its VLAN, switching mode or tag mapping "
            "differs — either the planned edit or an undeclared change; across a "
            "controller migration the sets must match."
        ),
        collector=_collect_wlan_config,
        tags=("wireless", "config"),
    )
)

register(
    CheckDef(
        id="wlc_tag_config",
        platform="iosxe",
        description="Site/RF tags, flex profiles with VLAN maps, static per-AP tag assignments",
        tier=2,
        compare={"mode": "equality_set"},
        miss_meaning=(
            "Site-specific configuration changed — a flex VLAN map, native VLAN, RF "
            "profile or an AP's static tag — which decides what a site's APs actually "
            "serve."
        ),
        collector=_collect_tag_config,
        tags=("wireless", "config"),
    )
)

register(
    CheckDef(
        id="wlc_mobility",
        platform="iosxe",
        description="Mobility group identity and per-peer control/data tunnel state",
        tier=1,
        compare={"mode": "equality_set"},
        miss_meaning=(
            "A mobility peer went down or flapped — roaming and controller failover "
            "break silently while every AP stays registered."
        ),
        collector=_collect_mobility,
        tags=("wireless", "mobility"),
    )
)

register(
    CheckDef(
        id="wlc_platform",
        platform="iosxe",
        description="Controller identity, wireless management interface, chassis roles, redundancy",
        tier=3,
        compare={"mode": "info_only"},
        miss_meaning=(
            "Informational — a changed management IP forces every AP to rejoin; a chassis "
            "role change or switchover count delta means an HA switchover happened."
        ),
        collector=_collect_platform,
        tags=("wireless", "platform"),
    )
)

register(
    CheckDef(
        id="iosxe_aaa_servers",
        platform="iosxe",
        description="RADIUS server state per group/server (not-present when none configured)",
        tier=1,
        compare={"mode": "equality_set"},
        miss_meaning=(
            "A RADIUS server is dead or newly missing — 802.1X and web-auth clients "
            "cannot authenticate even though every link and route is up."
        ),
        collector=_collect_aaa_servers,
        tags=("services", "aaa"),
    )
)
