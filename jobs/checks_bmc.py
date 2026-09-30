"""BMC check catalog (baseboard management controllers over Redfish) — GET only.

A server's BMC is modelled as an Interface on its host Device (jobs/bmc_target.py);
the capture job runs this family against the interface's address in a second
CollectorContext beside the host's own checks, and every entry it records
carries ``target: "bmc"``. Collectors reach the BMC only through ``ctx.get``:
the context's restconf slot holds a RedfishClient duck-typed to the RESTCONF
client, so every ``bmc_*`` check shares one per-run cache and the service
root, the System, the Manager and the Chassis are fetched once for the whole
family. This module imports nothing but stdlib and the jobs package's pure
modules, so the CI battery loads it and drives every ``_normalize_*`` function
with fixture payloads (hand-built from vendor documentation, and ``*_lab``
payloads harvested from a gen-1 ThinkSystem SE350 on XCC 6.10).

Vendor-neutral by construction: the DMTF resources (Systems, Chassis,
Managers, UpdateService, LogServices, Bios, Storage ...) are the family; the
member ids are RESOLVED once per run from the collections and the System's
links (``Systems/1`` on Lenovo and HPE, ``Systems/System.Embedded.1`` on Dell)
and recorded in every check's ``context.resolution``; vendor OEM reads follow
links from their parent resource, branch on the vendor the service root
names, and record ``not-present`` naming the vendor where no mapping exists
yet. Lenovo (XCC) is the only vendor verified against a live unit.

Redfish specifics that shape every collector here:

- *Fence before follow.* A server-supplied ``@odata.id`` passes through
  ``redfish_paths.fence_path`` before it is fetched; a link outside the
  read-only surface fails the check instead of being sent (the client fences
  again — this is the belt to its braces).
- *Budget per check.* ``ctx.budget(check_id, n)`` caps the real GETs one
  check may issue; the GET that would exceed it raises before being sent, so
  a capture is complete-or-refused, never silently partial. Collectors that
  walk collections pre-check the member count against what is left of the
  budget and raise CollectError with both numbers rather than walking into
  the wall. Every budget includes the id resolution (``_TARGET_GETS``), which
  whichever check runs first pays.
- *One GET per collection.* ``?$expand=.($levels=1)`` inlines a collection's
  members; when the firmware refuses it (HTTP error) or ignores it (members
  come back as bare links) the collector walks the members one by one and
  records which strategy answered in context.
- *Keys by Id.* Redfish ``Name`` may be null or duplicated; ``MemberId``/``Id``
  is the stable identity wherever a key needs one, and Name is only used
  where it is shown unique.
- *Enums are never pinned.* Status/state strings are carried verbatim; the
  SEMANTICS text explains the values the documentation names and the
  analyst reads the rest.
- *Secrets and people never leave the read.* Every GET passes a redactor to
  ``ctx.get`` that scrubs key material and credentials by exact leaf name and
  user-name leaves (``_scrub_payload``) — and, for log entries, the user
  names Lenovo audit messages carry (``_redact_log_page``) — BEFORE the debug
  trace keeps a copy, before the per-run cache and before a normalizer sees
  it. Raw is curated on top: ``Actions`` blocks and etags dropped, per-check
  raw keyed by the exact request path, bulk remainders capped with an honest
  truncation marker. Normalized is always computed from the full (scrubbed)
  response, never from capped raw.

Power-state caveat, once for the family: a BMC answers with the host off,
but Memory/PCIe inventory, storage and host-NIC link state are populated at
POST or via sideband, so those views are trustworthy only after the host has
completed POST; thermal, power, the event log and the security state are
host-independent. The System's ``PowerState`` rides in context wherever it
matters.
"""

import re

from . import constants as C
from .redfish_paths import RedfishPathRefused, fence_path
from .registry import EMPTY_OK_TAG, CheckDef, CollectError, SkipCheck, register

# --- Redfish paths -----------------------------------------------------------
# Only the collections are literal: every member path (the System, Manager
# and Chassis a capture reads) is resolved per run by _targets().

_ROOT = "/redfish/v1/"
_SYSTEMS = "/redfish/v1/Systems"
_MANAGERS = "/redfish/v1/Managers"
_CHASSIS_COLLECTION = "/redfish/v1/Chassis"
_FIRMWARE = "/redfish/v1/UpdateService/FirmwareInventory"

# A collection with several members and nothing linking one: Lenovo and HPE
# number from 1, Dell names its server ``System.Embedded.1``; else the first
# id in sorted order — and context.resolution says which rule chose.
_PREFERRED_MEMBER_IDS = ("1", "System.Embedded.1")

# One paced GET inlines a whole collection when the firmware honours it
# (gen-1 XCC advertises ProtocolFeaturesSupported.ExpandQuery.ExpandAll).
_EXPAND = "?$expand=.($levels=1)"

# --- per-check GET budgets ---------------------------------------------------
# Each check declares the most it may spend; cache hits never count. The BMC
# answered 779 Basic-auth GETs on XCC 6.10 without a log entry, but SE350
# Redfish has been reported to fold under request stress, so the budgets stay
# proportionate. Sized from the lab unit and Lenovo's samples (15
# FirmwareInventory members, five host EthernetInterfaces, four M.2 drives)
# with room for the per-member fallback walk. _TARGET_GETS covers the id
# resolution (root, Systems, the System, and the Managers/Chassis collections
# when the System does not link them), paid by whichever check runs first.
_TARGET_GETS = 5
_BUDGET_SYSTEM = 8 + _TARGET_GETS
_BUDGET_SECURITY = 8 + _TARGET_GETS  # Manager, Security, key manager, <= 5 cert collections
_BUDGET_THERMAL = 22 + _TARGET_GETS  # chassis, Thermal, subsystem, metrics, 18 for 16 fans
_BUDGET_POWER = 13 + _TARGET_GETS  # chassis, Power, subsystem, 10 for 4 supplies
_BUDGET_INVENTORY = 28 + _TARGET_GETS
_BUDGET_HOST_NICS = 12 + _TARGET_GETS
_BUDGET_FIRMWARE = 24 + _TARGET_GETS
_BUDGET_EVENT_LOG = 23 + _TARGET_GETS  # 7 log-service reads, 10 + 3 + 3 Entries pages
_BUDGET_BIOS = 3 + _TARGET_GETS  # Bios, its settings object, one spare
_BUDGET_STORAGE = 18 + _TARGET_GETS
_BUDGET_MANAGER_NETWORK = 16 + _TARGET_GETS  # 5 singletons, 4 host interfaces, 6 port, USB LAN
_BUDGET_CHASSIS = 16 + _TARGET_GETS  # Chassis, LED collection (+ <= 13 members unexpanded)

# --- hygiene: secrets, user names, raw curation --------------------------------
# Dropped from every stored payload: Actions blocks are POST targets, not
# evidence of state; etags/contexts churn on every capture.
_DROP_KEYS = frozenset({"Actions", "@odata.etag", "@odata.context"})
# Leaves that hold key material or a credential, matched on the EXACT leaf
# name (case-insensitive) — a substring test would scrub the password POLICY
# with them (PasswordLength, ComplexPassword, PasswordChangeOnFirstAccess,
# IsUefiAdminPasswordSet, EncryptionKeySet are all served by XCC 6.10 and are
# configuration an analyst needs). Any other leaf whose name ENDS in
# "password" is scrubbed unless its value is a boolean or a number
# (ClientPassword and BindPassword go; ComplexPassword stays).
_SECRET_NAMES = frozenset(
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
        "CommunityString",
        "TrapCommunity",
        "LicenseString",
        "CertificateString",
        "Bytes",
        "SSHPublicKey",
        "SED_AK",
        "BMU_Credential",
        "OAuthServiceSigningKeys",
        # NetworkDeviceFunction.iSCSIBoot: the CHAP secrets an adapter boots with
        "CHAPSecret",
        "MutualCHAPSecret",
    )
)
# Leaves that name a person's account outside the local-accounts collection
# (SMTP and image-share logins, server-profile user ids, logged-in users):
# scrubbed with their emptiness kept, so "set / unset" survives.
_USER_NAME_KEYS = frozenset(
    {"username", "userid", "loginid", "createdby", "owner", "chapusername", "mutualchapusername"}
)
# Leaves that name a person whatever resource carries them (a chassis
# location's contacts, the SNMP agent's contact): scrubbed even where account
# names are kept; emptiness kept.
_PERSON_KEYS = frozenset({"contactname", "contactperson", "emailaddress", "phonenumber"})
# Lists that record who is logged in right now: reduced to their length.
_COUNT_ONLY_KEYS = frozenset({"currentloggedusers"})
# A login embedded in a URL (virtual-media Image, an event Destination):
# scheme://user:password@host/... keeps everything but the userinfo.
_URL_USERINFO = re.compile(r"(?<=://)[^/@\s]+@")
_SCRUBBED = "***scrubbed***"
_RAW_TEXT_CAP = 20000  # chars kept for a sorted key=value remainder in raw
_RAW_LOG_ENTRIES = 500  # newest event-log entries kept in raw (curated, per entry)


def _is_secret(key, value=None):
    """True for a leaf that may hold key material or a credential (exact-name rule).

    Annotation keys (``AuthenticationKey@Redfish.OptionalOnCreate``) describe
    a property and never hold its value, so they are never secret.
    """
    name = str(key)
    if "@" in name:
        return False
    lowered = name.lower()
    if lowered in _SECRET_NAMES:
        return True
    return lowered.endswith("password") and not isinstance(value, (bool, int, float))


def _scrub_value(value):
    """The scrubbed form of a leaf: emptiness kept (None, '', [], {}), content never."""
    if value is None or value in ("", [], {}):
        return value
    if isinstance(value, list):
        return [_scrub_value(item) for item in value]  # the element count survives
    return _SCRUBBED


def _scrub_payload(node, keep_user_names=False):
    """Deep copy of a payload with secrets, user names and logged-in users scrubbed.

    The redactor every BMC GET passes to ``ctx.get``: applied before the
    debug trace keeps a copy, before the cache and before any normalizer
    sees the payload. ``keep_user_names`` is for the local-accounts
    collection only, whose account names are configuration (the
    ``iosxe_config`` local-user precedent). Idempotent.
    """
    if isinstance(node, dict):
        out = {}
        for key, value in node.items():
            lowered = str(key).lower()
            if _is_secret(key, value) or lowered in _PERSON_KEYS:
                out[key] = _scrub_value(value)
            elif lowered in _USER_NAME_KEYS and not keep_user_names:
                out[key] = _scrub_value(value)
            elif lowered in _COUNT_ONLY_KEYS and isinstance(value, list):
                out[key] = [_SCRUBBED for _item in value]
            else:
                out[key] = _scrub_payload(value, keep_user_names)
        return out
    if isinstance(node, list):
        return [_scrub_payload(item, keep_user_names) for item in node]
    if isinstance(node, str) and "://" in node:
        return _URL_USERINFO.sub(_SCRUBBED + "@", node)
    return node


def _looks_secret(key, value=None):
    """Kept for the flatteners and the BIOS attribute filter: see _is_secret."""
    return _is_secret(key, value)


def _curate(node):
    """Deep copy of a payload fit for the raw bundle (see _DROP_KEYS / _is_secret)."""
    if isinstance(node, dict):
        out = {}
        for key, value in node.items():
            if key in _DROP_KEYS:
                continue
            if _is_secret(key, value):
                out[key] = _scrub_value(value)
                continue
            out[key] = _curate(value)
        return out
    if isinstance(node, list):
        return [_curate(item) for item in node]
    return node


def _capped_lines(pairs):
    """Sorted ``key=value`` lines joined and capped with an honest marker."""
    text = "\n".join("%s=%s" % (key, value) for key, value in sorted(pairs))
    if len(text) > _RAW_TEXT_CAP:
        return text[:_RAW_TEXT_CAP] + "\n...[truncated %d chars]" % (len(text) - _RAW_TEXT_CAP,)
    return text


# --- log messages: people's names --------------------------------------------
# Lenovo writes its audit events into the platform log with the account in the
# message text and in MessageArgs (XCC 6.10: "Remote Login Successful. Login
# ID: <x> using ...", "... by user <x>.", "Flash of ... succeeded for user <x>
# .", "User <x> has mounted file ...", "User <x> password modified by user <y>
# ...", "User <x> created by user <y> ...", "User <x> role set to ..."). The
# names are found in the Message and then scrubbed from every string of the
# entry, MessageArgs included, before the trace, the cache and raw see it.
# Client addresses stay (a network fact; the IOS-XE syslog precedent).
_NAME_TAIL = r"(\S+?)(?=[.,:;]?(?:\s|$))"
_LOG_NAME_PATTERNS = (
    re.compile(r"\bLogin ID:\s*" + _NAME_TAIL),
    re.compile(r"\b[Bb]y user\s+" + _NAME_TAIL),
    re.compile(r"\b[Ff]or user\s+" + _NAME_TAIL),
    re.compile(r"\b[Uu]serid(?: is)?:?\s+" + _NAME_TAIL),
    re.compile(r"(?:^|(?<=[.;:]\s))User\s+" + _NAME_TAIL),
)


def _log_names(message):
    """Account names a log message carries (the scrub marker itself is never a name)."""
    names = set()
    if not isinstance(message, str):
        return names
    for pattern in _LOG_NAME_PATTERNS:
        for name in pattern.findall(message):
            if name and name != _SCRUBBED:
                names.add(name)
    return names


def _scrub_strings(node, pattern):
    if isinstance(node, dict):
        return {key: _scrub_strings(value, pattern) for key, value in node.items()}
    if isinstance(node, list):
        return [_scrub_strings(item, pattern) for item in node]
    if isinstance(node, str):
        return pattern.sub(_SCRUBBED, node)
    return node


# "Server General Settings set by user <x>: Name=..., Contact=<free text>, ..."
# names whoever the operator typed as the server's contact.
_LOG_CONTACT = re.compile(r"(\bContact=)([^,]+)")


def _redact_log_entry(entry):
    """One log entry with every account name its Message reveals scrubbed everywhere in it.

    The free-text ``Contact=`` field of a settings message is scrubbed too
    (a person's name when set).
    """
    if not isinstance(entry, dict):
        return entry
    message = entry.get("Message")
    if isinstance(message, str) and "Contact=" in message:
        # The value is free text and may hold commas: the message argument it
        # was formatted from is the value; the regex is the fallback.
        args = entry.get("MessageArgs") if isinstance(entry.get("MessageArgs"), list) else []
        contacts = [
            arg
            for arg in args
            if isinstance(arg, str) and arg.strip() and "Contact=" + arg in message
        ]
        if contacts:
            for contact in sorted(contacts, key=len, reverse=True):
                message = message.replace("Contact=" + contact, "Contact=" + _SCRUBBED)
            args = [_SCRUBBED if arg in contacts else arg for arg in args]
            entry = dict(entry, Message=message, MessageArgs=args)
        else:
            entry = dict(entry, Message=_LOG_CONTACT.sub(r"\g<1>" + _SCRUBBED, message))
    names = _log_names(entry.get("Message"))
    if not names:
        return entry
    alternatives = "|".join(re.escape(name) for name in sorted(names, key=len, reverse=True))
    pattern = re.compile(r"(?<![\w@-])(?:%s)(?![\w@-])" % (alternatives,))
    return _scrub_strings(entry, pattern)


def _scrub_accounts(node):
    """The redactor for the local-accounts collection: secrets go, account names stay."""
    return _scrub_payload(node, keep_user_names=True)


def _redact_log_page(page):
    """The redactor for a log Entries page: _scrub_payload, then every member's names."""
    page = _scrub_payload(page)
    if isinstance(page, dict) and isinstance(page.get("Members"), list):
        page["Members"] = [_redact_log_entry(member) for member in page["Members"]]
    return page


# --- shared helpers ----------------------------------------------------------


def _aslist(node):
    if node is None:
        return []
    if isinstance(node, list):
        return node
    return [node]


def _dicts(node):
    return [item for item in _aslist(node) if isinstance(item, dict)]


def _dig(node, *keys):
    """Nested lookup tolerant of missing/non-dict levels: None when any step fails."""
    for key in keys:
        if not isinstance(node, dict):
            return None
        node = node.get(key)
    return node


def _to_int(value):
    if isinstance(value, bool):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _to_float(value):
    if isinstance(value, bool):
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _to_bool(value):
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in ("true", "enabled", "yes", "on"):
            return True
        if lowered in ("false", "disabled", "no", "off"):
            return False
    return None


def _text(value):
    """Non-empty string or None — Redfish nulls and empty strings both mean unset."""
    if value is None:
        return None
    value = str(value).strip()
    return value or None


def _mac(value):
    """MACs lower-cased so they join to the ESXi-side pnic view byte-for-byte."""
    value = _text(value)
    return value.lower() if value else None


def _status(node):
    """(health, state) from a Redfish Status block; both None when absent."""
    return _text(_dig(node, "Status", "Health")), _text(_dig(node, "Status", "State"))


def _leaf_id(link):
    """Last path segment of an @odata.id (query/fragment stripped)."""
    resource = str(link).partition("?")[0].partition("#")[0].rstrip("/")
    return resource.rsplit("/", 1)[-1]


def _member_id(member):
    """Stable identity of a collection member: Id, then MemberId, then the link leaf."""
    if not isinstance(member, dict):
        return None
    for key in ("Id", "MemberId"):
        if _text(member.get(key)) is not None:
            return _text(member.get(key))
    link = member.get("@odata.id")
    return _leaf_id(link) if link else None


def _fenced_link(node, label):
    """The fenced @odata.id of ``node`` (a link dict), or None when it has none.

    A link the fence refuses fails the check: a firmware handing back a
    reference into Actions/ must never be followed, and silently skipping it
    would hide that the resource tree looks wrong.
    """
    link = _dig(node, "@odata.id") if isinstance(node, dict) else None
    if link is None:
        return None
    try:
        return fence_path(link)
    except RedfishPathRefused as exc:
        raise CollectError("%s: server-supplied link refused: %s" % (label, exc)) from exc


def _member_links(collection, label):
    """Fenced links of every Members[] entry of a collection resource."""
    links = []
    for member in _dicts(_dig(collection, "Members")):
        link = _fenced_link(member, label)
        if link is not None:
            links.append(link)
    return links


def _http_status(exc):
    """HTTP status carried by a transport error (None for fence/budget/network errors)."""
    return getattr(exc, "status_code", None)


def _get(ctx, path, redact=_scrub_payload, **kwargs):
    """Required resource: a 404 is a failed read (the transport raises).

    ``redact`` runs inside ``ctx.get`` before the trace, the cache and the
    caller see the payload; the default scrubs secrets and user names.
    ``kwargs`` go to the transport (and into the cache key).
    """
    return ctx.get(path, redact=redact, **kwargs)


def _get_optional(ctx, path, redact=_scrub_payload, **kwargs):
    """Optional resource: None on 404. Always the same kwargs so the cache is shared."""
    return ctx.get(path, ok_404=True, redact=redact, **kwargs)


def _budget_left(budget):
    """GETs still allowed under a transport budget manager; None when the transport has none."""
    max_gets = getattr(budget, "max_gets", None)
    used = getattr(budget, "used", None)
    if isinstance(max_gets, int) and isinstance(used, int):
        return max_gets - used
    return None


def _require_budget(budget, needed, label, what):
    """Refuse a walk that cannot complete: partial inventories are never recorded."""
    left = _budget_left(budget)
    if left is not None and needed > left:
        raise CollectError(
            "%s: %d %s to fetch but only %d GET(s) left in the budget of %d — the "
            "collector would be silently partial; $expand was not usable here"
            % (label, needed, what, left, budget.max_gets)
        )


def _expand_advertised(root):
    """True/False when the service root states $expand support, None when it is silent."""
    expand = _dig(root, "ProtocolFeaturesSupported", "ExpandQuery")
    if not isinstance(expand, dict):
        return None
    expand_all, no_links = expand.get("ExpandAll"), expand.get("NoLinks")
    if not isinstance(expand_all, bool) and not isinstance(no_links, bool):
        return None
    return bool(expand_all) or bool(no_links)


def _expanded(members):
    """True when every member came back as a resource, not a bare @odata.id link."""
    return all(any(key != "@odata.id" for key in member) for member in members)


def _fetch_collection(
    ctx,
    path,
    label,
    *,
    ok_404=False,
    exclude=frozenset(),
    budget=None,
    redact=_scrub_payload,
    try_expand=True,
    fresh=False,
):
    """Members of a Redfish collection as full resources: (members, meta, raw).

    Strategy, recorded in ``meta["strategy"]``: ``expand`` (one GET, members
    inline), ``members`` (collection GET plus one GET per member), or
    ``absent`` (404 with ok_404 — members is None). ``exclude`` names member
    ids (lower-cased) that are dropped *before* any GET is spent on them.
    ``raw`` maps each request path actually sent to its curated payload.
    ``redact`` is the redactor every read of the walk passes to ``ctx.get``;
    ``try_expand=False`` skips the ``$expand`` attempt (a check that already
    saw it refused or ignored does not pay for it again). ``fresh`` reads past
    the per-run cache (a distinct timeout is a distinct cache key), so a caller
    with a stricter redactor never shares a cached copy with a laxer reader of
    the same collection, whichever reads first.
    """
    fresh_kwargs = {"timeout": C.REDFISH_GET_TIMEOUT + 1} if fresh else {}
    raw = {}
    meta = {"strategy": None, "members_total": 0, "excluded": [], "expand_advertised": None}
    meta["expand_advertised"] = _expand_advertised(_get(ctx, _ROOT))
    if meta["expand_advertised"] is not False and try_expand:
        expanded_path = path + _EXPAND
        try:
            payload = _get_optional(ctx, expanded_path, redact=redact, **fresh_kwargs)
        except Exception as exc:  # transport error class is not importable here
            if _http_status(exc) is None:
                raise  # budget, fence or network failure — never a fallback trigger
            meta["expand_refused"] = "HTTP %s" % (_http_status(exc),)
            payload = None
        if payload is not None:
            members = _dicts(payload.get("Members"))
            if _expanded(members):
                raw[expanded_path] = _curate(payload)
                kept, excluded = [], []
                for member in members:
                    member_id = _member_id(member)
                    if member_id is not None and member_id.lower() in exclude:
                        excluded.append(member_id)
                    else:
                        kept.append(member)
                meta.update(strategy="expand", members_total=len(members), excluded=excluded)
                return kept, meta, raw
            meta["expand_refused"] = "members returned as links"
    expand_answered_404 = (
        meta["expand_advertised"] is not False and try_expand and "expand_refused" not in meta
    )
    if ok_404:
        collection = _get_optional(ctx, path, redact=redact, **fresh_kwargs)
    else:
        collection = _get(ctx, path, redact=redact, **fresh_kwargs)
    if collection is None:
        meta["strategy"] = "absent"
        return None, meta, raw
    if expand_answered_404:
        # The collection exists but its $expand form answered 404: a refusal too.
        meta["expand_refused"] = "HTTP 404"
    raw[path] = _curate(collection)
    links = _member_links(collection, label)
    kept, excluded = [], []
    for link in links:
        if _leaf_id(link).lower() in exclude:
            excluded.append(_leaf_id(link))
        else:
            kept.append(link)
    _require_budget(budget, len(kept), label, "members")
    members = []
    for link in kept:
        member = _get(ctx, link, redact=redact, **fresh_kwargs)
        raw[link] = _curate(member)
        members.append(member)
    meta.update(strategy="members", members_total=len(links), excluded=excluded)
    return members, meta, raw


def _first_ipv4(nic):
    return next(iter(_dicts(_dig(nic, "IPv4Addresses"))), {})


def _sub(base, *parts):
    """A child path of a resolved member path: ``_sub("/redfish/v1/Systems/1", "Bios")``."""
    return "/".join((str(base).rstrip("/"),) + tuple(str(part) for part in parts))


# --- member resolution (every check) -----------------------------------------


def _choose_member(collection, label):
    """(path, how) of the member this capture reads from a Systems/Managers/Chassis collection."""
    links = _member_links(collection, label)
    if not links:
        raise CollectError("%s lists no members" % (label,))
    if len(links) == 1:
        return links[0], "only member"
    by_id = {_leaf_id(link): link for link in links}
    for preferred in _PREFERRED_MEMBER_IDS:
        if preferred in by_id:
            return by_id[preferred], "id %s preferred among %d members" % (preferred, len(links))
    first = sorted(by_id)[0]
    return by_id[first], "first id of %d members (none preferred, none linked)" % (len(links),)


def _linked_member(resource, keys, label):
    """The fenced first link of ``resource.<keys>`` (a Links array), or None."""
    for item in _dicts(_dig(resource, *keys)):
        link = _fenced_link(item, label)
        if link is not None:
            return link
    return None


def _oem_key(resource):
    """The one vendor key of a resource's Oem block, or None when there is not exactly one."""
    oem = _dig(resource, "Oem")
    if not isinstance(oem, dict):
        return None
    keys = [key for key in oem if not str(key).startswith("@")]
    return keys[0] if len(keys) == 1 else None


def _vendor(root, system):
    """(vendor, where it was read): ServiceRoot.Vendor, else a lone Oem key, else Manufacturer."""
    vendor = _text(_dig(root, "Vendor"))
    if vendor:
        return vendor, "ServiceRoot.Vendor"
    vendor = _oem_key(root)
    if vendor:
        return vendor, "ServiceRoot.Oem"
    vendor = _text(_dig(system, "Manufacturer"))
    if vendor:
        return vendor, "ComputerSystem.Manufacturer"
    vendor = _oem_key(system)
    if vendor:
        return vendor, "ComputerSystem.Oem"
    return None, None


def _targets(ctx):
    """The System, Manager and Chassis paths this capture reads, and the BMC's vendor.

    GETs (every one cached for the rest of the family): the service root, the
    Systems collection and the chosen System; the Managers or Chassis
    collection only when the System does not link its manager
    (``Links.ManagedBy``) or chassis (``Links.Chassis``). Returns a dict with
    ``system``, ``manager``, ``chassis``, ``vendor`` and ``resolution`` (the
    context block every check records, saying how each was found).
    """
    root = _get(ctx, _ROOT)
    systems = _get(ctx, _SYSTEMS)
    system_path, system_how = _choose_member(systems, "Systems")
    system = _get(ctx, system_path)
    if not isinstance(system, dict) or not system:
        raise CollectError("%s answered without a resource body" % (system_path,))
    manager_path = _linked_member(system, ("Links", "ManagedBy"), "System Links.ManagedBy")
    manager_how = "System Links.ManagedBy"
    if manager_path is None:
        manager_path, manager_how = _choose_member(_get(ctx, _MANAGERS), "Managers")
    chassis_path = _linked_member(system, ("Links", "Chassis"), "System Links.Chassis")
    chassis_how = "System Links.Chassis"
    if chassis_path is None:
        chassis_path, chassis_how = _choose_member(_get(ctx, _CHASSIS_COLLECTION), "Chassis")
    vendor, vendor_source = _vendor(root, system)
    return {
        "system": system_path,
        "manager": manager_path,
        "chassis": chassis_path,
        "vendor": vendor,
        "resolution": {
            "vendor": vendor,
            "vendor_source": vendor_source,
            "product": _text(_dig(root, "Product")),
            "redfish_version": _text(_dig(root, "RedfishVersion")),
            "system": system_path,
            "system_found_by": system_how,
            "manager": manager_path,
            "manager_found_by": manager_how,
            "chassis": chassis_path,
            "chassis_found_by": chassis_how,
        },
    }


def _is_lenovo(targets):
    return "lenovo" in str(targets.get("vendor") or "").lower()


def _no_mapping(targets, what):
    """The SkipCheck an OEM-only read raises on a vendor this family has no mapping for."""
    return SkipCheck(
        "no %s mapping for %s yet (only Lenovo is mapped; the DMTF checks of this family "
        "are unaffected)" % (targets.get("vendor") or "unknown-vendor", what)
    )


def _with_resolution(context, targets):
    """``context`` with the member resolution recorded (every check carries it)."""
    context = dict(context or {})
    context["resolution"] = dict(targets["resolution"])
    return context


# --- bmc_system --------------------------------------------------------------

# The BMC's own management port is the documented ``NIC`` member on Lenovo;
# gen-1 also serves ``ToHost`` (the USB-LAN link to the host OS, 169.254.x)
# and the collection order is not guaranteed — so the collection is the
# fallback (and the only path on other vendors) and "first member" is never
# taken.
_USB_LAN_IDS = frozenset({"tohost", "tomanager"})


def _fetch_manager_nic(ctx, targets):
    """(payload, meta, raw) for the BMC's management interface; payload None when absent.

    ``raw`` maps every request path sent to its curated payload; ``meta``
    records which member answered and how it was found.
    """
    raw = {}
    manager_nics = _sub(targets["manager"], "EthernetInterfaces")
    if _is_lenovo(targets):
        direct = _sub(manager_nics, "NIC")
        nic = _get_optional(ctx, direct)
        if nic is not None:
            raw[direct] = _curate(nic)
            return nic, {"member": _member_id(nic) or "NIC", "source": "direct"}, raw
    collection = _get_optional(ctx, manager_nics)
    if collection is None:
        return None, {"member": None, "source": "absent"}, raw
    raw[manager_nics] = _curate(collection)
    candidates = [
        link
        for link in _member_links(collection, "bmc manager EthernetInterfaces")
        if _leaf_id(link).lower() not in _USB_LAN_IDS
    ]
    chosen = None
    for link in candidates:
        payload = _get_optional(ctx, link)
        if payload is None:
            continue
        raw[link] = _curate(payload)
        if chosen is None:
            chosen = payload
        address = _text(_first_ipv4(payload).get("Address"))
        if address and not address.startswith("169.254."):
            chosen = payload
            break
    if chosen is None:
        return None, {"member": None, "source": "collection-empty"}, raw
    return chosen, {"member": _member_id(chosen), "source": "collection"}, raw


def _system_serial_console(system):
    """(enabled, {protocol: enabled}) for the host serial console the System serves.

    ComputerSystem.SerialConsole (v1_13 and later) holds one block per
    protocol (IPMI, SSH, Telnet), each with its own ServiceEnabled: enabled is
    True when any served protocol is on, False when every served one is off,
    and None when none is served. XCC 6.10 serves no SerialConsole on the
    System at all; the Manager's console blocks are the BMC's own services
    (``bmc_serial_console_enabled`` and friends), never the host's.
    """
    protocols = {}
    block = _dig(system, "SerialConsole")
    if isinstance(block, dict):
        for name in sorted(block, key=str):
            enabled = _to_bool(_dig(block, name, "ServiceEnabled"))
            if enabled is not None:
                protocols[str(name)] = enabled
    if not protocols:
        return None, protocols
    return any(protocols.values()), protocols


def _system_tpm(system):
    """(count, interface types, firmware versions) from TrustedModules[]; a None trio if unserved.

    Both lists are sorted and hold only what the modules serve: XCC 6.10
    serves each module's FirmwareVersion as null, so its firmware list is [].
    """
    modules = _dig(system, "TrustedModules")
    if not isinstance(modules, list):
        return None, None, None
    modules = _dicts(modules)
    types = sorted(value for value in (_text(m.get("InterfaceType")) for m in modules) if value)
    firmware = sorted(
        value for value in (_text(m.get("FirmwareVersion")) for m in modules) if value
    )
    return len(modules), types, firmware


def _normalize_system(system, secure_boot, manager, nic, eth_member_used, lenovo=False):
    """Flat identity/health/policy scalars from the System, SecureBoot, the Manager and its NIC.

    Every field is always present (None when the resource or leaf is absent)
    so pre and post compare field-for-field: the DMTF power-restore, delay,
    power-mode and host-console leaves are absent on XCC 6.10 and read None
    there, never a default. SecureBoot's three fields are None as a trio when
    the resource 404s. ``bmc_health`` is the Manager's Status.Health only —
    XCC 6.10 serves Status.State alone, which is ``bmc_state`` — so a missing
    health is None, never borrowed from the state. The Lenovo leaves
    (system_status, the front-panel USB port, TPM physical presence) are read
    only when ``lenovo`` says the service is Lenovo's; None otherwise.
    """
    system = system if isinstance(system, dict) else {}
    secure_boot = secure_boot if isinstance(secure_boot, dict) else {}
    manager = manager if isinstance(manager, dict) else {}
    nic = nic if isinstance(nic, dict) else {}
    oem = _dig(system, "Oem", "Lenovo") if lenovo else None
    health, state = _status(system)
    bmc_health, bmc_state = _status(manager)
    ipv4 = _first_ipv4(nic)
    vlan_enabled = _to_bool(_dig(nic, "VLAN", "VLANEnable"))
    watchdog = _dig(system, "HostWatchdogTimer")
    serial_console, _protocols = _system_serial_console(system)
    tpm_count, tpm_types, tpm_firmware = _system_tpm(system)
    return {
        "power_state": _text(system.get("PowerState")),
        "health": health,
        "health_rollup": _text(_dig(system, "Status", "HealthRollup")),
        "state": state,
        "manufacturer": _text(system.get("Manufacturer")),
        "model": _text(system.get("Model")),
        "serial": _text(system.get("SerialNumber")),
        "sku": _text(system.get("SKU")),
        "part_number": _text(system.get("PartNumber")),
        "uuid": _text(system.get("UUID")),
        "asset_tag": _text(system.get("AssetTag")),
        "hostname": _text(system.get("HostName")),
        "bios_version": _text(system.get("BiosVersion")),
        "cpu_count": _to_int(_dig(system, "ProcessorSummary", "Count")),
        "cpu_model": _text(_dig(system, "ProcessorSummary", "Model")),
        "cpu_health": _text(_dig(system, "ProcessorSummary", "Status", "Health")),
        "memory_gib": _to_float(_dig(system, "MemorySummary", "TotalSystemMemoryGiB")),
        "memory_health": _text(_dig(system, "MemorySummary", "Status", "Health")),
        # Strings, never booleans: Disabled | Once | Continuous.
        "boot_override": _text(_dig(system, "Boot", "BootSourceOverrideEnabled")),
        "boot_override_target": _text(_dig(system, "Boot", "BootSourceOverrideTarget")),
        "boot_override_mode": _text(_dig(system, "Boot", "BootSourceOverrideMode")),
        "secure_boot_enabled": _to_bool(secure_boot.get("SecureBootEnable")),
        "secure_boot_current": _text(secure_boot.get("SecureBootCurrentBoot")),
        "secure_boot_mode": _text(secure_boot.get("SecureBootMode")),
        # What the host does after an AC loss or a hang, and what reaches its console.
        "power_restore_policy": _text(system.get("PowerRestorePolicy")),
        "power_on_delay_s": _to_float(system.get("PowerOnDelaySeconds")),
        "power_off_delay_s": _to_float(system.get("PowerOffDelaySeconds")),
        "power_cycle_delay_s": _to_float(system.get("PowerCycleDelaySeconds")),
        "power_mode": _text(system.get("PowerMode")),
        "host_watchdog_enabled": _to_bool(_dig(watchdog, "FunctionEnabled")),
        "host_watchdog_timeout_action": _text(_dig(watchdog, "TimeoutAction")),
        "host_watchdog_warning_action": _text(_dig(watchdog, "WarningAction")),
        "serial_console_enabled": serial_console,
        "graphical_console_enabled": _to_bool(_dig(system, "GraphicalConsole", "ServiceEnabled")),
        "virtual_media_service_enabled": _to_bool(
            _dig(system, "VirtualMediaConfig", "ServiceEnabled")
        ),
        "tpm_count": tpm_count,
        "tpm_interface_types": tpm_types,
        "tpm_firmware": tpm_firmware,
        "system_status": _text(_dig(oem, "SystemStatus")),
        "front_panel_usb_mode": _text(_dig(oem, "FrontPanelUSB", "FPMode")),
        "front_panel_usb_port_enabled": _to_bool(_dig(oem, "FrontPanelUSB", "PortEnabled")),
        "tpm_rpp_enabled": _to_bool(_dig(oem, "TPMSettings", "EnableRPP")),
        "bmc_firmware": _text(manager.get("FirmwareVersion")),
        "bmc_model": _text(manager.get("Model")),
        "bmc_uuid": _text(manager.get("UUID")),
        "bmc_health": bmc_health,
        "bmc_state": bmc_state,
        # The console services the Manager reports for itself (DMTF: the manager's own
        # consoles; the host's are the System's SerialConsole/GraphicalConsole above).
        "bmc_serial_console_enabled": _to_bool(_dig(manager, "SerialConsole", "ServiceEnabled")),
        "bmc_graphical_console_enabled": _to_bool(
            _dig(manager, "GraphicalConsole", "ServiceEnabled")
        ),
        "bmc_command_shell_enabled": _to_bool(_dig(manager, "CommandShell", "ServiceEnabled")),
        "bmc_hostname": _text(nic.get("HostName")),
        "bmc_ip": _text(ipv4.get("Address")),
        "bmc_ip_origin": _text(ipv4.get("AddressOrigin")),
        "bmc_subnet_mask": _text(ipv4.get("SubnetMask")),
        "bmc_gateway": _text(ipv4.get("Gateway")),
        "bmc_vlan_enabled": vlan_enabled,
        "bmc_vlan": _to_int(_dig(nic, "VLAN", "VLANId")) if vlan_enabled else None,
        "bmc_mac": _mac(nic.get("MACAddress")),
        "eth_member_used": eth_member_used,
    }


def _system_context(system, manager, nic_meta, secure_boot, lenovo=False):
    """Volatile or bulky facts an analyst wants next to the identity scalars.

    Counters, clocks and last-reset/boot-progress times move on their own;
    the Lenovo ones (reboot count, power-on hours, the BMC's firmware
    release name) are read only when ``lenovo`` says the service is Lenovo's.
    """
    modules = []
    for module in _dicts(_dig(system, "TrustedModules")):
        modules.append(
            {
                "interface_type": _text(module.get("InterfaceType")),
                "firmware": _text(module.get("FirmwareVersion")),
                "state": _text(_dig(module, "Status", "State")),
            }
        )
    system_oem = _dig(system, "Oem", "Lenovo") if lenovo else None
    manager_oem = _dig(manager, "Oem", "Lenovo") if lenovo else None
    _enabled, console_protocols = _system_serial_console(system)
    return {
        "reboot_count": _to_int(_dig(system_oem, "NumberOfReboots")),
        "power_on_hours": _to_int(_dig(system_oem, "TotalPowerOnHours")),
        "indicator_led": _text(_dig(system, "IndicatorLED")),
        "location_indicator_active": _to_bool(_dig(system, "LocationIndicatorActive")),
        "last_reset_time": _text(_dig(system, "LastResetTime")),
        "boot_progress": {
            "last_state": _text(_dig(system, "BootProgress", "LastState")),
            "last_state_time": _text(_dig(system, "BootProgress", "LastStateTime")),
        },
        "serial_console_protocols": console_protocols,
        "bmc_datetime": _text(_dig(manager, "DateTime")),
        "bmc_datetime_offset": _text(_dig(manager, "DateTimeLocalOffset")),
        "bmc_power_state": _text(_dig(manager, "PowerState")),
        "manager_last_reset_time": _text(_dig(manager, "LastResetTime")),
        "release_name": _text(_dig(manager_oem, "release_name")),
        "secure_boot_resource": secure_boot is not None,
        "trusted_modules": modules,
        "manager_nic": nic_meta,
    }


def _collect_system(ctx):
    with ctx.budget("bmc_system", _BUDGET_SYSTEM):
        targets = _targets(ctx)
        system = _get(ctx, targets["system"])
        secure_boot_path = _sub(targets["system"], "SecureBoot")
        secure_boot = _get_optional(ctx, secure_boot_path)
        manager = _get(ctx, targets["manager"])
        nic, nic_meta, nic_raw = _fetch_manager_nic(ctx, targets)
    lenovo = _is_lenovo(targets)
    raw = {targets["system"]: _curate(system), targets["manager"]: _curate(manager)}
    raw[secure_boot_path] = _curate(secure_boot) if secure_boot is not None else None
    raw.update(nic_raw)
    normalized = _normalize_system(
        system, secure_boot, manager, nic, nic_meta["member"], lenovo=lenovo
    )
    return {
        "raw": raw,
        "normalized": normalized,
        "context": _with_resolution(
            _system_context(system, manager, nic_meta, secure_boot, lenovo=lenovo), targets
        ),
    }


# --- bmc_security ------------------------------------------------------------

# The vendor security resource (Lenovo: Managers/<id> Oem/Lenovo/Security) is
# keyed leaf by leaf, 'security|<dotted path>', and so is the external key
# manager SED keys are escrowed with, 'sklm|<dotted path>' — the TLS mode,
# HTTPS/LDAPS/CIM enablement, firmware rollback and encapsulation settings a
# mainstream ThinkSystem serves there are all captured. ThinkEdge (Security
# Pack) units add their tamper state to the same resource; those properties
# also stay first-class scalars found by candidate name: each field takes the
# first leaf (by dotted path) whose last segment is one of its names; every
# field is optional — gen-1 and V2 spell the motion model differently and the
# lockdown names are unverified. The check is not-present only when no
# security resource is served at all, or the vendor has no mapping yet.
_SECURITY_FIELDS = (
    ("lockdown_mode", ("LockdownMode", "SystemLockdownMode", "LockdownStatus", "Lockdown")),
    ("lockdown_control", ("LockdownControl", "LockdownControlMode", "LockdownManagedBy")),
    (
        "motion_detection_enabled",
        ("MotionDetection", "MotionDetectionEnabled", "MotionDetectionEnable"),
    ),
    ("motion_threshold", ("ThresholdLevel", "StepCounter", "MotionSensitivity", "Sensitivity")),
    ("motion_orientation", ("Orientation", "MotionOrientation")),
    (
        "chassis_intrusion_enabled",
        ("ChassisIntrusionDetection", "ChassisIntrusion", "IntrusionDetection"),
    ),
    ("host_shutdown_on_tamper", ("HostShutdown", "HostShutdownOnTamper")),
    ("sed_encryption_enabled", ("EncryptionEnabled", "SEDEncryptionEnabled", "SEDEncryption")),
)
_FLATTEN_SKIP = ("@odata.", "Actions", "Links", "Id", "Name", "Description")


def _flatten(node, prefix=""):
    """Dotted-path -> scalar leaves of a resource (metadata, Actions and secrets skipped)."""
    leaves = {}
    if isinstance(node, dict):
        for key, value in node.items():
            if str(key).startswith("@") or (not prefix and key in _FLATTEN_SKIP):
                continue
            if _is_secret(key, value):
                continue
            leaves.update(_flatten(value, "%s.%s" % (prefix, key) if prefix else str(key)))
    elif isinstance(node, list):
        for index, value in enumerate(node):
            leaves.update(_flatten(value, "%s[%d]" % (prefix, index)))
    elif prefix:
        leaves[prefix] = node
    return leaves


def _pick_leaf(leaves, names):
    """(path, value) of the first leaf whose last segment is in ``names``; (None, None) if none."""
    for name in names:
        for path in sorted(leaves):
            if path.rsplit(".", 1)[-1] == name:
                return path, leaves[path]
    return None, None


# Structure, not state: the resource's own identity at its top level, and
# navigation and POST targets at any depth.
_SECURITY_SKIP_TOP = frozenset({"Id", "Name", "Description"})
_SECURITY_SKIP_ANY = frozenset({"Actions", "Links"})
# Leaves that move on their own (a key manager's last-poll time, a clock) ride
# in context.readings, never in a key.
_SECURITY_VOLATILE = re.compile(r"(?:last\w*(?:time|timestamp|date)|datetime)$", re.IGNORECASE)


def _security_is_link(node):
    """True for a bare link: a dict carrying @odata.id and nothing but annotations."""
    return (
        isinstance(node, dict)
        and "@odata.id" in node
        and all(str(key).startswith("@") for key in node)
    )


def _security_sorted(values):
    """A list's values in a stable order: the order a firmware serves them is not state."""
    if all(isinstance(value, str) for value in values):
        return sorted(values)
    if all(isinstance(value, (int, float)) and not isinstance(value, bool) for value in values):
        return sorted(values)
    return sorted(values, key=repr)  # mixed or structured: any stable order will do


def _security_value(node):
    """A leaf made comparable: '' reads None, lists sorted, annotations and secrets dropped."""
    if isinstance(node, dict):
        return {
            str(key): _security_value(value)
            for key, value in sorted(node.items(), key=lambda item: str(item[0]))
            if not str(key).startswith("@")
            and key not in _SECURITY_SKIP_ANY
            and not _is_secret(key, value)
        }
    if isinstance(node, list):
        return _security_sorted([_security_value(item) for item in node])
    if isinstance(node, str) and not node.strip():
        return None
    return node


def _security_leaves(node, prefix=""):
    """{dotted path: value} for every leaf of a vendor resource, a list being ONE leaf.

    The keying sibling of _flatten: a list is keyed once by its own path with
    its values sorted (_security_value), so a reordered list is no change and
    an empty one is still a leaf; '' reads None; the resource's own
    Id/Name/Description, Links and Actions blocks, annotations and secret
    leaves are skipped, and a bare link (or a list of nothing but links) is
    navigation and yields nothing.
    """
    leaves = {}
    if not isinstance(node, dict):
        return leaves
    for key, value in node.items():
        name = str(key)
        if name.startswith("@") or name in _SECURITY_SKIP_ANY or _is_secret(key, value):
            continue
        if not prefix and name in _SECURITY_SKIP_TOP:
            continue
        path = "%s.%s" % (prefix, name) if prefix else name
        if isinstance(value, dict):
            leaves.update(_security_leaves(value, path))
        elif isinstance(value, list) and value and all(_security_is_link(v) for v in value):
            continue
        else:
            leaves[path] = _security_value(value)
    return leaves


def _security_keyed(leaves, family):
    """({'<family>|<path>': value}, {'<family>|<path>': value} of the time-like leaves)."""
    keyed, readings = {}, {}
    for path in sorted(leaves):
        volatile = _SECURITY_VOLATILE.search(path.rsplit(".", 1)[-1])
        (readings if volatile else keyed)["%s|%s" % (family, path)] = leaves[path]
    return keyed, readings


def _security_certificate_links(resource, label, prefix=""):
    """[(dotted path, fenced link)] of every certificate collection a resource links, any depth."""
    found = []
    if not isinstance(resource, dict):
        return found
    for key in sorted(resource, key=str):
        name, value = str(key), resource[key]
        if name.startswith("@") or name in _SECURITY_SKIP_ANY:
            continue
        path = "%s.%s" % (prefix, name) if prefix else name
        if _security_is_link(value):
            if "certificate" in name.lower():
                found.append((path, _fenced_link(value, label)))
        elif isinstance(value, dict):
            found.extend(_security_certificate_links(value, label, path))
    return found


def _security_member_count(collection):
    """Members@odata.count of a collection (else len(Members)); None when it is not served."""
    if not isinstance(collection, dict):
        return None
    count = collection.get("Members@odata.count")
    if isinstance(count, int) and not isinstance(count, bool):
        return count
    members = collection.get("Members")
    return len(members) if isinstance(members, list) else None


def _security_require_budget(budget, needed):
    """Refuse the certificate counts up front when what is left of the budget cannot cover them."""
    left = _budget_left(budget)
    if left is not None and needed > left:
        raise CollectError(
            "bmc_security: the key manager links %d certificate collection(s) but only %d "
            "GET(s) are left in the budget of %d — the counts would be partial"
            % (needed, left, budget.max_gets)
        )


def _normalize_security_state(security, sklm=None, certificate_counts=None):
    """(normalized, sources, readings) for the vendor security resource and its key manager.

    ``normalized`` holds every _SECURITY_FIELDS (ThinkEdge) entry — None when
    the leaf is absent — then 'security|<dotted path>' for every leaf of the
    security resource and 'sklm|<dotted path>' for every leaf of the key
    manager (_security_leaves), plus 'sklm|<link path>.Members@odata.count'
    for each certificate collection the key manager links
    (``certificate_counts`` maps the link's dotted path to its member count:
    counted, never read). ``sources`` maps each populated ThinkEdge field to
    the dotted path it came from so the shakedown can pin the real property
    names; booleans arrive as bools or Enabled/Disabled strings and both
    become bools, '' reads None, anything else is verbatim. ``readings`` holds
    the time-like leaves (_SECURITY_VOLATILE), which never become keys.
    """
    leaves = _flatten(security)
    normalized = {}
    sources = {}
    for field, names in _SECURITY_FIELDS:
        path, value = _pick_leaf(leaves, names)
        if path is None:
            normalized[field] = None
            continue
        sources[field] = path
        as_bool = _to_bool(value)
        if as_bool is not None:
            normalized[field] = as_bool
        else:
            normalized[field] = _text(value) if isinstance(value, str) else value
    keyed, readings = _security_keyed(_security_leaves(security), "security")
    normalized.update(keyed)
    if isinstance(sklm, dict):
        keyed, sklm_readings = _security_keyed(_security_leaves(sklm), "sklm")
        normalized.update(keyed)
        readings.update(sklm_readings)
    for path, count in sorted((certificate_counts or {}).items()):
        normalized["sklm|%s.Members@odata.count" % (path,)] = count
    return normalized, sources, readings


def _collect_security_state(ctx):
    raw = {}
    certificate_counts = {}
    with ctx.budget("bmc_security", _BUDGET_SECURITY) as budget:
        targets = _targets(ctx)
        if not _is_lenovo(targets):
            raise _no_mapping(targets, "the BMC security resource")
        manager = _get(ctx, targets["manager"])
        link = _fenced_link(_dig(manager, "Oem", "Lenovo", "Security"), "bmc_security")
        security_path = link or _sub(targets["manager"], "Oem", "Lenovo", "Security")
        security = _get_optional(ctx, security_path)
        if security is None:
            raise SkipCheck(
                "no Oem/Lenovo/Security resource on this BMC (%s answered 404)" % (security_path,)
            )
        if not isinstance(security, dict) or not security:
            raise CollectError("%s answered without a resource body" % (security_path,))
        # The external key manager (SKLM/KMIP) SED keys are escrowed with: its
        # settings are keyed; its certificate collections are counted, never read.
        sklm_path = _fenced_link(
            _dig(manager, "Oem", "Lenovo", "SecureKeyLifecycleService"), "bmc_security"
        )
        sklm = _get_optional(ctx, sklm_path) if sklm_path else None
        collections = _security_certificate_links(sklm, "bmc_security key manager")
        _security_require_budget(budget, len(collections))
        for path, collection_link in collections:
            collection = _get_optional(ctx, collection_link)
            raw[collection_link] = _curate(collection) if collection is not None else None
            certificate_counts[path] = _security_member_count(collection)
    raw[security_path] = _curate(security)
    if sklm is not None:
        raw[sklm_path] = _curate(sklm)
    normalized, sources, readings = _normalize_security_state(security, sklm, certificate_counts)
    return {
        "raw": raw,
        "normalized": normalized,
        "context": _with_resolution(
            {
                "security_resource": security_path,
                "property_sources": sources,
                "key_management": {
                    "resource": sklm_path,
                    "served": sklm is not None,
                    "certificate_collections": [path for path, _link in collections],
                },
                "readings": readings,
            },
            targets,
        ),
    }


# --- bmc_thermal -------------------------------------------------------------

# Only environment-class sensors carry a comparable reading: CPU/DIMM/PCH
# temperatures follow the host's load, so those readings ride in context.
# Matched on Name, not PhysicalContext — gen-1 says Intake where later
# firmware says Board.
_AMBIENT_TOKENS = ("ambient", "inlet", "intake", "exhaust", "outlet")
# ThermalMetrics.TemperatureSummaryCelsius members (DMTF ThermalMetrics v1).
_THERMAL_SUMMARY = ("Ambient", "Intake", "Exhaust", "Internal")


def _sensor_key(kind, name, member_id, name_counts):
    """'<kind>|<Name>'; '|<MemberId>' appended when Name repeats; '<kind>|<MemberId>' when null."""
    if name is None:
        return "%s|%s" % (kind, member_id)
    if name_counts.get(name, 0) > 1:
        return "%s|%s|%s" % (kind, name, member_id)
    return "%s|%s" % (kind, name)


def _name_counts(items):
    counts = {}
    for item in items:
        name = _text(item.get("Name"))
        if name is not None:
            counts[name] = counts.get(name, 0) + 1
    return counts


def _thresholds(sensor):
    """Non-null threshold leaves of a sensor, snake_cased; {} when none."""
    found = {}
    for key in (
        "UpperThresholdNonCritical",
        "UpperThresholdCritical",
        "UpperThresholdFatal",
        "LowerThresholdNonCritical",
        "LowerThresholdCritical",
        "LowerThresholdFatal",
    ):
        value = _to_float(sensor.get(key))
        if value is not None:
            found[_snake(key)] = value
    return found


def _snake(name):
    return re.sub(r"(?<!^)(?=[A-Z])", "_", str(name)).lower()


def _is_ambient(name):
    lowered = (name or "").lower()
    return any(token in lowered for token in _AMBIENT_TOKENS)


def _thermal_is_margin(name, reading):
    """True for a sensor that reads a margin rather than a temperature.

    A DTS (the CPU's digital thermal sensor: 'CPU DTS' reads -51 on XCC 6.10)
    reports how far the die is below its throttle point, not how hot it is;
    any negative reading is read the same way.
    """
    return "dts" in (name or "").lower() or (reading is not None and reading < 0)


def _thermal_fan_reading(fan):
    """(reading, units) of a fan: the legacy Reading/ReadingUnits pair, else SpeedPercent.

    A ThermalSubsystem Fan carries its speed as a sensor excerpt. SpeedRPM is
    preferred, so a fan reads the same RPM from either resource (XCC 6.10 also
    puts the RPM figure into SpeedPercent.Reading, which DMTF defines as a
    percent); the percent Reading answers only where no RPM is served.
    """
    speed = fan.get("SpeedPercent")
    if not isinstance(speed, dict):
        return _to_float(fan.get("Reading")), _text(fan.get("ReadingUnits"))
    rpm = _to_float(speed.get("SpeedRPM"))
    if rpm is not None:
        return rpm, "RPM"
    percent = _to_float(speed.get("Reading"))
    return percent, ("Percent" if percent is not None else None)


def _thermal_summary(metrics):
    """ThermalMetrics.TemperatureSummaryCelsius as {ambient, intake, exhaust, internal}.

    None when the ThermalMetrics resource was not read; a member it does not
    serve (XCC 6.10: Exhaust and Internal) reads None.
    """
    if not isinstance(metrics, dict):
        return None
    return {
        name.lower(): _to_float(_dig(metrics, "TemperatureSummaryCelsius", name, "Reading"))
        for name in _THERMAL_SUMMARY
    }


def _normalize_thermal(thermal, fans=None, fan_redundancy=None, metrics=None):
    """(normalized, context) from Chassis/<id>/Thermal, else the ThermalSubsystem fans.

    ``thermal`` is the legacy resource. Where the firmware serves none it is
    None, and ``fans`` (the ThermalSubsystem's Fan resources) and
    ``fan_redundancy`` (its FanRedundancy groups) stand in for Fans[] and
    Redundancy[]; there are no temperature sensors to key then.
    ``temp|<Name>`` -> health, state, physical_context, reading_c (ambient/
    intake/exhaust class only; None on the rest). ``fan|<Name>`` -> health,
    state, reading, reading_units, keyed the same way from either resource.
    State == Absent means no key. Every reading and every non-null threshold
    is recorded in context; ``margins`` lists the temperature keys that read a
    margin (_thermal_is_margin) and ``temperature_summary_c`` the ThermalMetrics
    summary (None when ``metrics`` was not read).
    """
    normalized = {}
    context = {
        "temperatures_total": 0,
        "fans_total": 0,
        "absent": [],
        "readings_c": {},
        "fan_readings": {},
        "thresholds": {},
        "fan_redundancy": [],
        "margins": [],
        "temperature_summary_c": _thermal_summary(metrics),
    }
    temperatures = _dicts(_dig(thermal, "Temperatures"))
    counts = _name_counts(temperatures)
    for sensor in temperatures:
        context["temperatures_total"] += 1
        name = _text(sensor.get("Name"))
        member_id = _text(sensor.get("MemberId")) or _text(sensor.get("Id")) or "?"
        key = _sensor_key("temp", name, member_id, counts)
        health, state = _status(sensor)
        if state == "Absent":
            context["absent"].append(key)
            continue
        reading = _to_float(sensor.get("ReadingCelsius"))
        normalized[key] = {
            "health": health,
            "state": state,
            "physical_context": _text(sensor.get("PhysicalContext")),
            "reading_c": reading if _is_ambient(name) else None,
        }
        context["readings_c"][key] = reading
        if _thermal_is_margin(name, reading):
            context["margins"].append(key)
        thresholds = _thresholds(sensor)
        if thresholds:
            context["thresholds"][key] = thresholds
    fan_rows = _dicts(_dig(thermal, "Fans")) if thermal is not None else _dicts(fans)
    counts = _name_counts(fan_rows)
    for fan in fan_rows:
        context["fans_total"] += 1
        name = _text(fan.get("Name")) or _text(fan.get("FanName"))
        member_id = _text(fan.get("MemberId")) or _text(fan.get("Id")) or "?"
        key = _sensor_key("fan", name, member_id, counts)
        health, state = _status(fan)
        if state == "Absent":
            context["absent"].append(key)
            continue
        reading, units = _thermal_fan_reading(fan)
        normalized[key] = {
            "health": health,
            "state": state,
            "reading": reading,
            "reading_units": units,
        }
        context["fan_readings"][key] = reading
        thresholds = _thresholds(fan)
        if thresholds:
            context["thresholds"][key] = thresholds
    groups = _dig(thermal, "Redundancy") if thermal is not None else fan_redundancy
    for group in _dicts(groups):
        # Legacy Redundancy: Mode + RedundancySet; ThermalSubsystem.FanRedundancy
        # (a RedundantGroup): RedundancyType + RedundancyGroup.
        members = group.get("RedundancySet", group.get("RedundancyGroup"))
        context["fan_redundancy"].append(
            {
                "member_id": _text(group.get("MemberId")),
                "mode": _text(group.get("Mode")) or _text(group.get("RedundancyType")),
                "state": _text(_dig(group, "Status", "State")),
                "health": _text(_dig(group, "Status", "Health")),
                "member_count": len(_dicts(members)),
            }
        )
    return normalized, context


def _collect_thermal(ctx):
    raw = {}
    subsystem = metrics = fans = fans_meta = fans_path = metrics_path = None
    with ctx.budget("bmc_thermal", _BUDGET_THERMAL) as budget:
        targets = _targets(ctx)
        chassis = _get(ctx, targets["chassis"])
        thermal_link = _fenced_link(_dig(chassis, "Thermal"), "bmc_thermal Thermal")
        path = thermal_link or _sub(targets["chassis"], "Thermal")
        thermal = _get_optional(ctx, path)
        subsystem_link = _fenced_link(
            _dig(chassis, "ThermalSubsystem"), "bmc_thermal ThermalSubsystem"
        )
        if subsystem_link is not None and thermal is not None:
            # One GET for the temperature summary: the DMTF-mandated child path
            # of the linked subsystem, whose own resource is not needed here.
            metrics_path = _sub(subsystem_link, "ThermalMetrics")
        elif subsystem_link is not None:
            # No legacy resource: the subsystem's own links name its fans.
            subsystem = _get_optional(ctx, subsystem_link)
            if subsystem is None:
                raise CollectError(
                    "%s answered 404 and the Chassis links %s, which answered 404 too"
                    % (path, subsystem_link)
                )
            fans_path = _fenced_link(subsystem.get("Fans"), "bmc_thermal Fans")
            metrics_path = _fenced_link(subsystem.get("ThermalMetrics"), "bmc_thermal Metrics")
        if metrics_path is not None:
            metrics = _get_optional(ctx, metrics_path)
        if fans_path is not None:
            fans, fans_meta, fans_raw = _fetch_collection(
                ctx, fans_path, "bmc_thermal fans", ok_404=True, budget=budget
            )
            raw.update(fans_raw)
    if thermal is not None:
        if not _dicts(_dig(thermal, "Temperatures")):
            # A 2xx JSON body with no sensors is a broken read, never a chassis
            # with no thermal sensors.
            raise CollectError("%s answered with an empty Temperatures[]" % (path,))
        raw[path] = _curate(thermal)
    elif subsystem is None:
        if thermal_link is not None:
            raise CollectError(
                "the Chassis links %s but it answered 404, and no ThermalSubsystem is linked"
                % (path,)
            )
        raise SkipCheck("%s is not served and the Chassis links no ThermalSubsystem" % (path,))
    else:
        raw[subsystem_link] = _curate(subsystem)
        if fans_path is not None and fans is None:
            raise CollectError("%s is linked but answered 404" % (fans_path,))
    if metrics is not None:
        raw[metrics_path] = _curate(metrics)
    normalized, context = _normalize_thermal(
        thermal, fans, _dig(subsystem, "FanRedundancy"), metrics
    )
    if thermal is None and not normalized:
        raise SkipCheck(
            "%s is not served and %s lists no present fan: nothing to key (the temperature "
            "summary is in ThermalMetrics, each temperature sensor in the Sensors collection)"
            % (path, subsystem_link)
        )
    if thermal is not None:
        context["temperatures_source"] = context["fans_source"] = path
    else:
        context["temperatures_source"] = None
        context["fans_source"] = fans_path if fans is not None else None
    context["temperature_summary_source"] = metrics_path if metrics is not None else None
    if fans_meta is not None:
        context["fans_collection"] = fans_meta
    return {"raw": raw, "normalized": normalized, "context": _with_resolution(context, targets)}


# --- bmc_power ---------------------------------------------------------------


def _input_in_range(reading, ranges):
    """True/False when a line-input reading and at least one Min/Max range exist; else None."""
    if reading is None:
        return None
    verdicts = []
    for band in _dicts(ranges):
        low = _to_float(band.get("MinimumVoltage"))
        high = _to_float(band.get("MaximumVoltage"))
        if low is None or high is None:
            continue
        verdicts.append(low <= reading <= high)
    if not verdicts:
        return None
    return any(verdicts)


def _in_threshold(reading, sensor):
    """True/False against the critical (else fatal) thresholds; None without both sides' data."""
    if reading is None:
        return None
    for suffix in ("Critical", "Fatal"):
        low = _to_float(sensor.get("LowerThreshold" + suffix))
        high = _to_float(sensor.get("UpperThreshold" + suffix))
        if low is not None or high is not None:
            return (low is None or reading >= low) and (high is None or reading <= high)
    return None


def _power_first(*values):
    """The first value that is not None (a 0 reading is a reading, never a fallback trigger)."""
    for value in values:
        if value is not None:
            return value
    return None


def _power_psu(psu, metrics=None):
    """(row, readings) for one supply, from either power schema.

    ``psu`` is a legacy Power.PowerSupplies[] member or a PowerSubsystem
    PowerSupply, ``metrics`` the latter's PowerSupplyMetrics (None when not
    read). The two schemas spell the same facts differently: the line voltage
    is the legacy LineInputVoltage or the metrics' InputVoltage reading, the
    voltage class LineInputVoltageType or InputNominalVoltageType, input and
    output watts PowerInputWatts/PowerOutputWatts or the metrics'
    InputPowerWatts/OutputPowerWatts. LineInputStatus (Normal / LossOfInput /
    OutOfRange) is the PowerSupply schema's own verdict on the feed; None
    where not served.
    """
    health, state = _status(psu)
    line_v = _power_first(
        _to_float(psu.get("LineInputVoltage")),
        _to_float(_dig(metrics, "InputVoltage", "Reading")),
    )
    row = {
        "name": _text(psu.get("Name")),
        "state": state,
        "health": health,
        "power_supply_type": _text(psu.get("PowerSupplyType")),
        "line_input_voltage_type": _text(psu.get("LineInputVoltageType"))
        or _text(psu.get("InputNominalVoltageType")),
        "line_input_voltage": line_v,
        "line_input_status": _text(psu.get("LineInputStatus")),
        "input_in_range": _input_in_range(line_v, psu.get("InputRanges")),
        "capacity_w": _to_float(psu.get("PowerCapacityWatts")),
        "serial": _text(psu.get("SerialNumber")),
        "model": _text(psu.get("Model")),
        "part_number": _text(psu.get("PartNumber")),
        "manufacturer": _text(psu.get("Manufacturer")),
        "firmware": _text(psu.get("FirmwareVersion")),
    }
    readings = {
        "input_w": _power_first(
            _to_float(psu.get("PowerInputWatts")),
            _to_float(_dig(metrics, "InputPowerWatts", "Reading")),
        ),
        "output_w": _power_first(
            _to_float(psu.get("PowerOutputWatts")),
            _to_float(_dig(metrics, "OutputPowerWatts", "Reading")),
        ),
        "last_output_w": _to_float(psu.get("LastPowerOutputWatts")),
    }
    return row, readings


def _normalize_power(power, supplies=None, supply_metrics=None, subsystem=None):
    """(normalized, context) from Chassis/<id>/Power, else the PowerSubsystem supplies.

    ``power`` is the legacy resource (None where the firmware serves none);
    ``supplies`` are PowerSubsystem PowerSupply resources read in its place,
    ``supply_metrics`` maps a supply id to its PowerSupplyMetrics and
    ``subsystem`` is the PowerSubsystem (PowerSupplyRedundancy, CapacityWatts).
    ``psu|<MemberId>`` (legacy; Name may be null on Lenovo) or ``psu|<Id>``
    -> state/health verbatim, line_input_voltage, line_input_status,
    input_in_range, capacity_w, identity strings (None, never '').
    ``redundancy|<MemberId>`` (legacy Redundancy[]) or ``redundancy|<index>``
    (PowerSupplyRedundancy) only when a redundancy group is published.
    ``voltage|<MemberId>`` (legacy only) -> state, in_threshold, health
    (Lenovo serves no Health on Voltages, so it is usually None). Consumption
    and readings go to context.
    """
    normalized = {}
    context = {
        "power_consumed_w": None,
        "power_capacity_w": None,
        "power_limit_w": None,
        "psu_readings": {},
        "voltage_readings": {},
        "psu_total": 0,
    }
    control = next(iter(_dicts(_dig(power, "PowerControl"))), {})
    context["power_consumed_w"] = _to_float(control.get("PowerConsumedWatts"))
    context["power_capacity_w"] = _power_first(
        _to_float(control.get("PowerCapacityWatts")), _to_float(_dig(subsystem, "CapacityWatts"))
    )
    context["power_limit_w"] = _to_float(_dig(control, "PowerLimit", "LimitInWatts"))
    rows = [
        (_text(psu.get("MemberId")) or _text(psu.get("Id")) or "?", psu, None)
        for psu in _dicts(_dig(power, "PowerSupplies"))
    ]
    for psu in _dicts(supplies):
        member_id = _member_id(psu) or "?"
        rows.append((member_id, psu, (supply_metrics or {}).get(member_id)))
    for member_id, psu, metrics in rows:
        context["psu_total"] += 1
        row, readings = _power_psu(psu, metrics)
        normalized["psu|%s" % (member_id,)] = row
        context["psu_readings"][member_id] = readings
    for group in _dicts(_dig(power, "Redundancy")):
        member_id = _text(group.get("MemberId")) or _text(group.get("Id")) or "?"
        health, state = _status(group)
        normalized["redundancy|%s" % (member_id,)] = {
            "mode": _text(group.get("Mode")),
            "state": state,
            "health": health,
            "member_count": len(_dicts(group.get("RedundancySet"))),
        }
    for index, group in enumerate(_dicts(_dig(subsystem, "PowerSupplyRedundancy"))):
        # A RedundantGroup carries no MemberId: its position is its identity.
        health, state = _status(group)
        normalized["redundancy|%d" % (index,)] = {
            "mode": _text(group.get("RedundancyType")),
            "state": state,
            "health": health,
            "member_count": len(_dicts(group.get("RedundancyGroup"))),
        }
    for sensor in _dicts(_dig(power, "Voltages")):
        member_id = _text(sensor.get("MemberId")) or _text(sensor.get("Id")) or "?"
        health, state = _status(sensor)
        reading = _to_float(sensor.get("ReadingVolts"))
        normalized["voltage|%s" % (member_id,)] = {
            "name": _text(sensor.get("Name")),
            "state": state,
            "health": health,
            "in_threshold": _in_threshold(reading, sensor),
        }
        context["voltage_readings"][member_id] = reading
    return normalized, context


def _collect_power(ctx):
    raw = {}
    subsystem = supplies = supplies_meta = supplies_path = None
    supply_metrics = {}
    with ctx.budget("bmc_power", _BUDGET_POWER) as budget:
        targets = _targets(ctx)
        chassis = _get(ctx, targets["chassis"])
        power_link = _fenced_link(_dig(chassis, "Power"), "bmc_power Power")
        path = power_link or _sub(targets["chassis"], "Power")
        power = _get_optional(ctx, path)
        if power is not None and (not isinstance(power, dict) or not power):
            raise CollectError("%s answered without a resource body" % (path,))
        subsystem_link = _fenced_link(_dig(chassis, "PowerSubsystem"), "bmc_power PowerSubsystem")
        if subsystem_link is not None and not _normalize_power(power)[0]:
            # No legacy resource, or one that models nothing (no supply, rail or
            # redundancy group): the supplies are read from the PowerSubsystem.
            subsystem = _get_optional(ctx, subsystem_link)
            supplies_path = _fenced_link(
                _dig(subsystem, "PowerSupplies"), "bmc_power PowerSupplies"
            )
        if supplies_path is not None:
            supplies, supplies_meta, supplies_raw = _fetch_collection(
                ctx, supplies_path, "bmc_power supplies", ok_404=True, budget=budget
            )
            raw.update(supplies_raw)
            metric_links = []
            for supply in _dicts(supplies):
                link = _fenced_link(supply.get("Metrics"), "bmc_power supply Metrics")
                if link is not None:
                    metric_links.append((_member_id(supply) or "?", link))
            _require_budget(budget, len(metric_links), "bmc_power", "supply metrics")
            for member_id, link in metric_links:
                metrics = _get_optional(ctx, link)
                supply_metrics[member_id] = metrics
                if metrics is not None:
                    raw[link] = _curate(metrics)
    if power is not None:
        raw[path] = _curate(power)
    if subsystem is not None:
        raw[subsystem_link] = _curate(subsystem)
    if supplies_path is not None and supplies is None:
        raise CollectError("%s is linked but answered 404" % (supplies_path,))
    normalized, context = _normalize_power(power, supplies, supply_metrics, subsystem)
    if not normalized:
        if power is not None:
            raise CollectError(
                "%s carries no PowerSupplies/Voltages/Redundancy members%s"
                % (path, "" if subsystem is None else " and %s lists no supply" % (subsystem_link,))
            )
        if subsystem is not None:
            # An SE350 models its external adapters as sensors, never as supplies.
            raise SkipCheck(
                "%s is not served and %s models no supply: nothing to key" % (path, subsystem_link)
            )
        if subsystem_link is not None:
            raise CollectError(
                "%s answered 404 and the Chassis links %s, which answered 404 too"
                % (path, subsystem_link)
            )
        if power_link is not None:
            raise CollectError(
                "the Chassis links %s but it answered 404, and no PowerSubsystem is linked"
                % (path,)
            )
        raise SkipCheck("%s is not served and the Chassis links no PowerSubsystem" % (path,))
    context["psu_source"] = (
        supplies_path if supplies is not None else (path if power is not None else None)
    )
    if supplies_meta is not None:
        context["supplies_collection"] = supplies_meta
    return {"raw": raw, "normalized": normalized, "context": _with_resolution(context, targets)}


# --- bmc_inventory -----------------------------------------------------------
# GETs, the lab SE350 (four DIMM slots, one CPU, four PCIe devices carrying
# 1/2/2/1 functions): with $expand honoured one per collection (Memory,
# Processors, PCIeDevices) and one per device for its PCIeFunctions collection
# ($levels=2 does not inline those on XCC 6.10) — 7 beyond the id resolution.
# The per-member fallback, $expand advertised but refused or ignored (the
# attempt is paid once, on Memory, and never again for Processors, PCIeDevices
# or the functions): Memory 1 + 1 + 4, Processors 1 + 1, PCIeDevices 1 + 4, then
# the functions 4 collections + 6 members — 23 on the lab layout.
# _BUDGET_INVENTORY = 28 + _TARGET_GETS leaves room for a dual-port card beyond
# that. A bigger server without $expand is refused loudly with the counts (the
# function reads are pre-checked before the first is sent), never recorded
# partially.


def _service_label(node):
    """Best-effort physical location of a part: Lenovo OEM, then DMTF Location, then Slot."""
    for path in (
        ("Oem", "Lenovo", "Location", "PartLocation", "ServiceLabel"),
        ("Location", "PartLocation", "ServiceLabel"),
        ("PhysicalLocation", "PartLocation", "ServiceLabel"),
        ("Slot", "Location", "PartLocation", "ServiceLabel"),
        ("Slot", "Location", "Info"),
    ):
        value = _text(_dig(node, *path))
        if value is not None:
            return value
    return None


def _inventory_scalar(value):
    """A served scalar leaf verbatim (strings stripped); None when unset or not a scalar."""
    if isinstance(value, str):
        return _text(value)
    if isinstance(value, (dict, list)):
        return None
    return value


def _inventory_sorted(value, convert):
    """The served list's items converted and sorted; None when the leaf is not served as a list."""
    if not isinstance(value, list):
        return None
    return sorted(item for item in (convert(entry) for entry in value) if item is not None)


def _inventory_dimm(dimm):
    """One 'dimm|<Id>' row: identity, configuration and health (an empty slot has null identity)."""
    health, state = _status(dimm)
    lenovo = _dig(dimm, "Oem", "Lenovo")
    mpfa = _dig(lenovo, "MPFA", "MPFA_HealthStatus")  # not served on XCC 6.10
    return {
        "slot": _text(dimm.get("DeviceLocator")),
        "socket": _to_int(_dig(dimm, "MemoryLocation", "Socket")),
        "service_label": _service_label(dimm),
        "capacity_mib": _to_int(dimm.get("CapacityMiB")),
        "type": _text(dimm.get("MemoryDeviceType")),
        # Firmware-scaled (Lenovo's example shows 21333): stored as-is, never banded.
        "speed_mhz": _to_int(dimm.get("OperatingSpeedMhz")),
        "serial": _text(dimm.get("SerialNumber")),
        "part_number": _text(dimm.get("PartNumber")),
        "manufacturer": _text(dimm.get("Manufacturer")),
        "health": health,
        "state": state,
        "error_correction": _text(dimm.get("ErrorCorrection")),  # not served on XCC 6.10
        "rank_count": _to_int(dimm.get("RankCount")),
        "data_width_bits": _to_int(dimm.get("DataWidthBits")),
        # 72 over a 64-bit data path is the ECC evidence where ErrorCorrection is unserved.
        "bus_width_bits": _to_int(dimm.get("BusWidthBits")),
        "allowed_speeds_mhz": _inventory_sorted(dimm.get("AllowedSpeedsMHz"), _to_int),
        "base_module_type": _text(dimm.get("BaseModuleType")),
        "fru_part_number": _text(_dig(lenovo, "FruPartNumber")),
        "manufacture_date": _text(_dig(lenovo, "ManufactureDate")),
        "mpfa_health_major": _inventory_scalar(_dig(mpfa, "Major")),
        "mpfa_health_minor": _inventory_scalar(_dig(mpfa, "Minor")),
    }


def _inventory_cpu(cpu):
    """One 'cpu|<Id>' row: identity, the CPUID signature as served, rated limits and health.

    ProcessorId's EffectiveFamily / EffectiveModel / Step are hex strings kept as served
    (``model`` is the marketing string, so the CPUID model is ``effective_model``).
    """
    health, state = _status(cpu)
    processor_id = _dig(cpu, "ProcessorId")
    return {
        "model": _text(cpu.get("Model")),
        "socket": _text(cpu.get("Socket")),
        "cores": _to_int(cpu.get("TotalCores")),
        "enabled_cores": _to_int(cpu.get("TotalEnabledCores")),
        "threads": _to_int(cpu.get("TotalThreads")),
        "health": health,
        "state": state,
        "effective_family": _text(_dig(processor_id, "EffectiveFamily")),
        "effective_model": _text(_dig(processor_id, "EffectiveModel")),
        "step": _text(_dig(processor_id, "Step")),
        "microcode": _text(_dig(processor_id, "MicrocodeInfo")),  # null on XCC 6.10
        "max_speed_mhz": _to_int(cpu.get("MaxSpeedMHz")),
        "tdp_w": _to_int(cpu.get("TDPWatts")),
        "turbo_state": _text(cpu.get("TurboState")),  # not served on XCC 6.10
        "serial": _text(cpu.get("SerialNumber")),
    }


def _inventory_function(function):
    """One 'pciefn|<device>|<function>' row: the ids that name the silicon, as served (hex)."""
    _health, state = _status(function)
    return {
        "function_type": _text(function.get("FunctionType")),
        "device_class": _text(function.get("DeviceClass")),
        "class_code": _text(function.get("ClassCode")),
        "vendor_id": _text(function.get("VendorId")),
        "device_id": _text(function.get("DeviceId")),
        "subsystem_id": _text(function.get("SubsystemId")),
        "subsystem_vendor_id": _text(function.get("SubsystemVendorId")),
        # PCIeFunction.Enabled is recent and XCC 6.10 serves none: null there,
        # never inferred from the state, which is its own field.
        "enabled": _to_bool(function.get("Enabled")),
        "state": state,
    }


def _normalize_inventory(memory, processors, pcie, functions=None):
    """'dimm|<Id>' / 'cpu|<Id>' / 'pcie|<Id>' / 'pciefn|<device Id>|<function Id>' rows.

    Each list may be None (absent). ``functions`` maps a PCIe device id to the members
    of its PCIeFunctions collection; a device the BMC identifies by nothing but null
    strings (the BMC's own VGA, an add-in NIC on the lab unit) is named by its
    function rows' vendor and device ids.
    """
    normalized = {}
    for dimm in _dicts(memory):
        normalized["dimm|%s" % (_member_id(dimm) or "?",)] = _inventory_dimm(dimm)
    for cpu in _dicts(processors):
        # The SE350 CPU is soldered: identity, rated limits and health, never a reading.
        normalized["cpu|%s" % (_member_id(cpu) or "?",)] = _inventory_cpu(cpu)
    for device in _dicts(pcie):
        health, state = _status(device)
        normalized["pcie|%s" % (_member_id(device) or "?",)] = {
            "manufacturer": _text(device.get("Manufacturer")),
            "model": _text(device.get("Model")),
            "device_type": _text(device.get("DeviceType")),
            "firmware": _text(device.get("FirmwareVersion")),
            "serial": _text(device.get("SerialNumber")),
            "part_number": _text(device.get("PartNumber")),
            "health": health,
            "state": state,
            "location": _service_label(device),
        }
    for device_id in sorted(functions or {}):
        for function in _dicts(functions[device_id]):
            key = "pciefn|%s|%s" % (device_id, _member_id(function) or "?")
            normalized[key] = _inventory_function(function)
    return normalized


# Where a CPU's current clock is served, first found wins: the DMTF OperatingSpeedMHz,
# a top-level CurrentClockSpeedMHz (not a DMTF property; the leaf this check always
# read), else Lenovo's OEM leaf — the only one XCC 6.10 fills.
_INVENTORY_CLOCK_LEAVES = (
    ("OperatingSpeedMHz",),
    ("CurrentClockSpeedMHz",),
    ("Oem", "Lenovo", "CurrentClockSpeedMHz"),
)


def _inventory_caches(cpu):
    """A CPU's cache sizes: Lenovo's CacheInfo (KiB), else the DMTF ProcessorMemory caches (MiB)."""
    caches = [
        {
            "level": _text(entry.get("CacheLevel")),
            "installed_kib": _to_int(entry.get("InstalledSizeKByte")),
            "max_kib": _to_int(entry.get("MaxCacheSizeKByte")),
        }
        for entry in _dicts(_dig(cpu, "Oem", "Lenovo", "CacheInfo"))
    ]
    if caches:
        return {"source": "Oem.Lenovo.CacheInfo", "caches": caches}
    caches = [
        {"level": _text(entry.get("MemoryType")), "capacity_mib": _to_int(entry.get("CapacityMiB"))}
        for entry in _dicts(cpu.get("ProcessorMemory"))
        if str(entry.get("MemoryType") or "").lower().endswith("cache")
    ]
    return {"source": "ProcessorMemory" if caches else None, "caches": caches}


def _inventory_cpu_context(processors):
    """Per CPU: the current clock (a load-driven reading), the leaf it came from, cache sizes."""
    speeds, sources, caches = {}, {}, {}
    for cpu in _dicts(processors):
        cpu_id = _member_id(cpu) or "?"
        speeds[cpu_id], sources[cpu_id] = None, None
        for path in _INVENTORY_CLOCK_LEAVES:
            speed = _to_int(_dig(cpu, *path))
            if speed is not None:
                speeds[cpu_id], sources[cpu_id] = speed, ".".join(path)
                break
        caches[cpu_id] = _inventory_caches(cpu)
    return {"clock_speed_mhz": speeds, "clock_speed_source": sources, "cpu_caches": caches}


# A PCIe device in one of these states may legitimately carry no function rows.
_PCIE_UNENUMERATED_STATES = frozenset({"Absent", "Disabled"})


def _inventory_functions(ctx, devices, budget, try_expand):
    """({device id: [PCIeFunction]}, {device id: how it was read}, raw) for every PCIe device.

    A device's ``PCIeFunctions`` collection is read with one $expand GET (``$levels=2`` on
    the device collection does not inline it on XCC 6.10), else walked member by member;
    a device that links no collection but lists ``Links.PCIeFunctions`` (the deprecated
    array) has each function read by its own link. ``try_expand`` starts as the device
    collection's own answer and turns off at the first refusal, so a firmware that
    refuses $expand pays for the attempt once, never once per device. A listed device
    (State neither Absent nor Disabled) whose linked collection answers 404 or empty
    refuses the check: unmeasured, never recorded as a device without functions.
    """
    plan = []
    for device in _dicts(devices):
        collection = _fenced_link(device.get("PCIeFunctions"), "bmc_inventory PCIeFunctions")
        links = []
        if collection is None:
            for item in _dicts(_dig(device, "Links", "PCIeFunctions")):
                link = _fenced_link(item, "bmc_inventory Links.PCIeFunctions")
                if link is not None:
                    links.append(link)
        plan.append((_member_id(device) or "?", collection, links, _status(device)[1]))
    # Complete-or-refused: the fewest GETs these reads can take must fit before one is sent.
    needed = sum(1 if collection else len(links) for _id, collection, links, _state in plan)
    left = _budget_left(budget)
    if left is not None and needed > left:
        raise CollectError(
            "bmc_inventory: the PCIe functions of %d device(s) take at least %d GET(s) but only "
            "%d are left in the budget of %d — refused rather than recorded partially"
            % (len(plan), needed, left, budget.max_gets)
        )
    functions, report, raw, unmeasured = {}, {}, {}, []
    for device_id, collection, links, state in plan:
        if collection is not None:
            members, meta, member_raw = _fetch_collection(
                ctx,
                collection,
                "bmc_inventory PCIeFunctions",
                ok_404=True,
                budget=budget,
                try_expand=try_expand,
            )
            raw.update(member_raw)
            if meta.get("expand_refused"):
                try_expand = False
            if not members and state not in _PCIE_UNENUMERATED_STATES:
                # Every PCI device has at least function 0: a listed device's empty or
                # missing function collection is unmeasured, never "no functions".
                unmeasured.append(device_id)
            functions[device_id] = members or []
            report[device_id] = {
                "source": "PCIeFunctions",
                "strategy": meta["strategy"],
                "members": len(members) if members is not None else None,
            }
        elif links:
            functions[device_id] = []
            for link in links:
                member = _get(ctx, link)
                raw[link] = _curate(member)
                functions[device_id].append(member)
            report[device_id] = {
                "source": "Links.PCIeFunctions",
                "strategy": "members",
                "members": len(links),
            }
        else:
            report[device_id] = {"source": None, "strategy": None, "members": None}
    if unmeasured:
        raise CollectError(
            "bmc_inventory: the PCIeFunctions collection of device(s) %s answered 404 or with "
            "zero members — every PCI device has at least one function, so the read is "
            "unmeasured (populated at POST), never 'no functions'; capture again after the "
            "host completes POST" % (", ".join(unmeasured),)
        )
    return functions, report, raw


def _collect_inventory(ctx):
    raw = {}
    collections = {}
    context = {"host_power_state": None, "collections": {}, "unmeasured": []}
    try_expand = True
    with ctx.budget("bmc_inventory", _BUDGET_INVENTORY) as budget:
        targets = _targets(ctx)
        system = _get(ctx, targets["system"])
        context["host_power_state"] = _text(_dig(system, "PowerState"))
        for family, path in (
            ("memory", _sub(targets["system"], "Memory")),
            ("processors", _sub(targets["system"], "Processors")),
            ("pcie", _sub(targets["chassis"], "PCIeDevices")),
        ):
            members, meta, family_raw = _fetch_collection(
                ctx,
                path,
                "bmc_inventory %s" % (family,),
                ok_404=True,
                budget=budget,
                try_expand=try_expand,
            )
            if meta.get("expand_refused"):
                try_expand = False  # a refusal is paid for once per check, never per family
            collections[family] = members
            context["collections"][family] = dict(
                meta, members=len(members) if members is not None else None
            )
            raw.update(family_raw)
        if all(members is None for members in collections.values()):
            raise SkipCheck("Memory, Processors and PCIeDevices collections all answered 404")
        # Inventory is POST-populated (UEFI / Host Interface). An empty 200
        # collection is unmeasured — with the host off, or On but still in POST,
        # or on a firmware that never enumerates the family — and a diff cannot
        # tell "unmeasured" from "every part gone", so the read is refused
        # whatever the power state says (before any function is read); a Memory
        # or Processors collection is never legitimately empty on a server.
        for family, members in collections.items():
            if members is not None and not members:
                context["unmeasured"].append(family)
        if context["unmeasured"]:
            raise CollectError(
                "%s answered with zero members (host PowerState %s) — inventory is populated "
                "at POST and an empty collection is unmeasured, never 'all parts gone'; capture "
                "again after the host completes POST"
                % (", ".join(context["unmeasured"]), context["host_power_state"])
            )
        functions, context["pcie_functions"], functions_raw = _inventory_functions(
            ctx,
            collections["pcie"],
            budget,
            try_expand=try_expand and context["collections"]["pcie"]["strategy"] == "expand",
        )
        raw.update(functions_raw)
    normalized = _normalize_inventory(
        collections["memory"], collections["processors"], collections["pcie"], functions
    )
    # Clock speed is load-driven (and this CPU is soldered): a reading, so it
    # rides in context next to the identity rows and stays in raw, never diffed;
    # so do the cache sizes (bulk, and fixed by the part the rows already name).
    context.update(_inventory_cpu_context(collections["processors"]))
    return {"raw": raw, "normalized": normalized, "context": _with_resolution(context, targets)}


# --- bmc_host_nics -----------------------------------------------------------

# ``ToManager`` is the USB Redfish Host Interface (host OS <-> BMC), not a
# port; it is filtered by id before any GET is spent on it.
_HOST_NIC_EXCLUDE = frozenset({"tomanager"})


def _normalize_host_nics(members):
    """(normalized, context): 'nic|<Id>' -> link_status, permanent_mac, health, state, ...

    speed_mbps is context only — null on gen-1 documentation, 0 on later
    firmware; both read as None. The constant vendor Description is dropped.
    """
    normalized = {}
    context = {"speed_mbps": {}, "mac_source": {}, "full_duplex": {}}
    for nic in _dicts(members):
        nic_id = _member_id(nic) or "?"
        health, state = _status(nic)
        permanent = _mac(nic.get("PermanentMACAddress"))
        source = "PermanentMACAddress"
        if permanent is None:
            permanent = _mac(nic.get("MACAddress"))
            source = "MACAddress" if permanent else None
        normalized["nic|%s" % (nic_id,)] = {
            "name": _text(nic.get("Name")),
            "link_status": _text(nic.get("LinkStatus")),
            "permanent_mac": permanent,
            "interface_enabled": _to_bool(nic.get("InterfaceEnabled")),
            "health": health,
            "state": state,
        }
        speed = _to_int(nic.get("SpeedMbps"))
        context["speed_mbps"][nic_id] = speed if speed else None
        context["mac_source"][nic_id] = source
        context["full_duplex"][nic_id] = _to_bool(nic.get("FullDuplex"))
    return normalized, context


def _collect_host_nics(ctx):
    with ctx.budget("bmc_host_nics", _BUDGET_HOST_NICS) as budget:
        targets = _targets(ctx)
        system = _get(ctx, targets["system"])
        path = _sub(targets["system"], "EthernetInterfaces")
        members, meta, raw = _fetch_collection(
            ctx, path, "bmc_host_nics", ok_404=True, exclude=_HOST_NIC_EXCLUDE, budget=budget
        )
    if members is None:
        raise SkipCheck("%s is not served by this firmware" % (path,))
    if not members:
        raise SkipCheck(
            "%s lists no host ports (excluded: %s)" % (path, ", ".join(meta["excluded"]) or "none")
        )
    normalized, context = _normalize_host_nics(members)
    if all(row["link_status"] is None for row in normalized.values()):
        # A firmware that never reports host link state would otherwise diff
        # false-green on every capture.
        raise SkipCheck("LinkStatus is null on every host port — link state not reported")
    context.update(meta)
    # The collection that carried the ports: the System's EthernetInterfaces
    # (the Chassis NetworkAdapters tree describes the same ports per adapter).
    context["port_source"] = path
    context["host_power_state"] = _text(_dig(system, "PowerState"))
    return {"raw": raw, "normalized": normalized, "context": _with_resolution(context, targets)}


# --- bmc_firmware ------------------------------------------------------------
# GETs: FirmwareInventory (one $expand GET; the fallback walk is 1 + 1 + 15 on
# the lab unit), the Manager (its Links.ActiveSoftwareImage; the same cached
# read bmc_system and bmc_security make), the UpdateService (Lenovo's backup
# promotion policy, and the link to a SoftwareInventory collection where one is
# served — XCC 6.10 links none, so nothing more is requested there) and that
# collection. The lab worst case, 17 + 1 + 1 = 19 beyond the id resolution, sits
# inside _BUDGET_FIRMWARE (24 + _TARGET_GETS).
_FIRMWARE_UPDATE_SERVICE = "/redfish/v1/UpdateService"


def _firmware_rows(members, prefix):
    """'<prefix>|<Id>' -> name, version (verbatim), software_id, updateable, health."""
    rows = {}
    for member in sorted(_dicts(members), key=lambda item: _member_id(item) or ""):
        health, _state = _status(member)
        rows["%s|%s" % (prefix, _member_id(member) or "?")] = {
            "name": _text(member.get("Name")),
            "version": _text(member.get("Version")),
            "software_id": _text(member.get("SoftwareId")),
            "updateable": _to_bool(member.get("Updateable")),
            "health": health,
        }
    return rows


def _normalize_firmware(members, software=None, manager=None, update_service=None):
    """The firmware view: 'fw|<Id>' and 'sw|<Id>' rows plus two scalars, always present.

    Rows come from FirmwareInventory and, where served, SoftwareInventory (the same
    fields). Status.State is never emitted: the backup XCC bank toggles between
    StandbyOffline and Enabled after a BMC reboot. ReleaseDate, etags,
    LowestSupportedVersion, Description and Oem.* are excluded. The '-Pending'
    members are kept (a version there is a staged update). ``manager_active_image``
    is the leaf id of the Manager's Links.ActiveSoftwareImage (the inventory member
    the BMC runs from); ``backup_auto_promote`` is Lenovo's
    UpdateService.Oem.Lenovo.XCCBackupAutoPromote. Both None when unserved.
    """
    normalized = _firmware_rows(members, "fw")
    normalized.update(_firmware_rows(software, "sw"))
    active = _fenced_link(
        _dig(manager, "Links", "ActiveSoftwareImage"), "bmc_firmware Links.ActiveSoftwareImage"
    )
    normalized["manager_active_image"] = _leaf_id(active) if active else None
    normalized["backup_auto_promote"] = _to_bool(
        _dig(update_service, "Oem", "Lenovo", "XCCBackupAutoPromote")
    )
    return normalized


def _collect_firmware(ctx):
    software = None
    software_meta = {"linked": False}
    with ctx.budget("bmc_firmware", _BUDGET_FIRMWARE) as budget:
        targets = _targets(ctx)
        members, meta, raw = _fetch_collection(ctx, _FIRMWARE, "bmc_firmware", budget=budget)
        if not members:
            raise CollectError("UpdateService/FirmwareInventory lists no members")
        manager = _get(ctx, targets["manager"])
        update_path = (
            _fenced_link(_dig(_get(ctx, _ROOT), "UpdateService"), "bmc_firmware UpdateService")
            or _FIRMWARE_UPDATE_SERVICE
        )
        update_service = _get_optional(ctx, update_path)
        software_link = _fenced_link(
            _dig(update_service, "SoftwareInventory"), "bmc_firmware SoftwareInventory"
        )
        if software_link:
            # The FirmwareInventory's answer decides: a refused $expand is not paid twice.
            software, software_fetch, software_raw = _fetch_collection(
                ctx,
                software_link,
                "bmc_firmware SoftwareInventory",
                ok_404=True,
                budget=budget,
                try_expand=meta["strategy"] == "expand",
            )
            raw.update(software_raw)
            software_meta = {
                "linked": True,
                "strategy": software_fetch["strategy"],
                "members": len(software) if software is not None else None,
            }
    if update_service is not None:
        raw[update_path] = _curate(update_service)
    context = dict(meta, members=len(members))
    context.update(
        {
            "update_service": update_path if update_service is not None else None,
            "software_inventory": software_meta,
        }
    )
    return {
        "raw": raw,
        "normalized": _normalize_firmware(members, software, manager, update_service),
        "context": _with_resolution(context, targets),
    }


# --- bmc_event_log -----------------------------------------------------------

_KEYED_SEVERITIES = frozenset({"warning", "critical"})
# Log services read beside the platform log, found by id among the
# LogServices members (Lenovo's names, compared lower-cased): the ActiveLog
# (the BMC's unresolved conditions, every entry keyed), the MaintenanceLog
# (firmware-update and hardware history: context and raw), the IPMI SEL (a
# probe: its size policy, never its entries) and the AuditLog (its SERVICE
# resource's sequence numbers, read only where the platform log's service
# lacks them; never its entries, where the capture's own logins would land).
_EVENT_LOG_ACTIVE = "activelog"
_EVENT_LOG_MAINTENANCE = "maintenancelog"
_EVENT_LOG_SEL = "sel"
_EVENT_LOG_AUDIT = "auditlog"
# Newest MaintenanceLog rows kept in raw (XCC 6.10 holds up to 750; the lab
# unit's whole history is 73). bmc_firmware carries the versions themselves.
_EVENT_LOG_MAINTENANCE_ROWS = 100


def _pick_log_service(links, targets=None):
    """PlatformLog (gen-1 guide, V2 too) else StandardLog (Purley era, XCC 6.10) else a lone member.

    Those two names are Lenovo's; another vendor with several log services
    has no mapping yet and records not-present naming them. An audit log is
    never the lone member taken: its entries hold the capture's own logins.
    """
    by_id = {_leaf_id(link): link for link in links}
    for wanted in ("PlatformLog", "StandardLog"):
        if wanted in by_id:
            return by_id[wanted], wanted
    if len(links) == 1:
        if "audit" in _leaf_id(links[0]).lower():
            raise SkipCheck(
                "the only log service is %s, an audit log, whose entries are never read"
                % (_leaf_id(links[0]),)
            )
        return links[0], _leaf_id(links[0])
    if targets is not None and not _is_lenovo(targets):
        raise _no_mapping(
            targets, "the platform log service (members: %s)" % (", ".join(sorted(by_id)),)
        )
    raise CollectError(
        "LogServices offers neither PlatformLog nor StandardLog (members: %s)"
        % (", ".join(sorted(by_id)) or "none",)
    )


def _entry_sort_id(entry):
    value = _to_int(entry.get("Id"))
    return (0, value) if value is not None else (1, str(entry.get("Id")))


def _event_log_code(entry):
    """The event class an entry is keyed and counted by: CommonEventID, else MessageId."""
    return (
        _text(_dig(entry, "Oem", "Lenovo", "CommonEventID"))
        or _text(_dig(entry, "MessageId"))
        or "unknown"
    )


def _event_log_serviceable(value):
    """Lenovo's Serviceable as a boolean; None when it says neither.

    The LenovoLogEntry schema's enum is 'Not Serviceable', 'ServiceableByLenovo'
    and 'ServiceableByCustomer' (case, spaces and separators are ignored here);
    Lenovo's older samples serve a boolean; a one-element list (the schema's
    collection form) reads as its element. Who services it is
    _event_log_serviceable_by.
    """
    if isinstance(value, list):
        verdicts = {_event_log_serviceable(item) for item in value}
        return verdicts.pop() if len(verdicts) == 1 else None
    if isinstance(value, str):
        squashed = re.sub(r"[^a-z]", "", value.lower())
        if squashed.startswith("notserviceable"):
            return False
        if squashed.startswith("serviceable"):
            return True
    return _to_bool(value)


def _event_log_serviceable_by(value):
    """'Lenovo' / 'Customer' from ServiceableByLenovo / ServiceableByCustomer; else None."""
    if isinstance(value, list):
        parties = {_event_log_serviceable_by(item) for item in value}
        return parties.pop() if len(parties) == 1 else None
    if isinstance(value, str):
        match = re.match(r"serviceable[\s_-]*by[\s_-]*([a-z]+)$", value.strip(), re.IGNORECASE)
        if match:
            return match.group(1).capitalize()
    return None


def _event_log_failing_fru(entry):
    """Oem.Lenovo.FailingFRU as sorted [{part, serial}]; None when the leaf is not served.

    XCC 6.10 serves one {"FRUNumber": "", "FRUSerialNumber": ""} placeholder
    on an entry that names no part: placeholders are dropped, so "no part" is [].
    """
    node = _dig(entry, "Oem", "Lenovo", "FailingFRU")
    if node is None:
        return None
    frus = []
    for fru in _dicts(node):
        part, serial = _text(fru.get("FRUNumber")), _text(fru.get("FRUSerialNumber"))
        if part is not None or serial is not None:
            frus.append({"part": part, "serial": serial})
    return sorted(frus, key=lambda fru: (fru["part"] or "", fru["serial"] or ""))


def _normalize_event_log(entries, log_service=None):
    """(normalized, context) over the whole platform-log Entries collection.

    Keys 'sel|<code>|<Id>' for Severity Warning/Critical only — the event
    code (Lenovo's CommonEventID, else the entry's MessageId) sits in the key
    so additions can be grouped by event class; values add the failing FRUs
    and Lenovo's LogType (platform or audit) to severity, source, serviceable,
    event_id and hidden. Every other entry is counted per code in context,
    and every entry per LogType. Ids are the BMC's monotonic sequence numbers.
    Whether the log was cleared is a cross-capture fact (a post newest_id
    below the pre newest_id) that one capture cannot know, so context carries
    the facts the comparison needs — first_id, newest_id, the service's own
    platform sequence numbers (XCC 6.10 spells them ``PlatformFirstSeqNum`` /
    ``PlatformLastSeqNum``; ``FirstSeqNum`` / ``LastSeqNum`` elsewhere;
    ``seq_num_source`` names the spelling read), entries_total — and
    ``at_capacity`` (the log holds MaxNumberOfRecords entries, so the next
    event overwrites the oldest) as the one wrap-related fact a single
    capture can state.
    """
    normalized = {}
    informational = {}
    by_log_type = {}
    hidden_total = 0
    ids = []
    newest = None
    for entry in _dicts(entries):
        entry_id = _text(entry.get("Id")) or "?"
        code = _event_log_code(entry)
        severity = _text(entry.get("Severity"))
        hidden = _to_bool(_dig(entry, "Oem", "Lenovo", "Hidden"))
        log_type = _text(_dig(entry, "Oem", "Lenovo", "LogType"))
        if hidden:
            hidden_total += 1
        if log_type is not None:
            by_log_type[log_type] = by_log_type.get(log_type, 0) + 1
        numeric = _to_int(entry.get("Id"))
        if numeric is not None:
            ids.append(numeric)
        if newest is None or _entry_sort_id(entry) > _entry_sort_id(newest):
            newest = entry
        if (severity or "").lower() in _KEYED_SEVERITIES:
            normalized["sel|%s|%s" % (code, entry_id)] = {
                "severity": severity,
                "source": _text(_dig(entry, "Oem", "Lenovo", "Source"))
                or _text(entry.get("SensorType")),
                "serviceable": _event_log_serviceable(_dig(entry, "Oem", "Lenovo", "Serviceable")),
                "serviceable_by": _event_log_serviceable_by(
                    _dig(entry, "Oem", "Lenovo", "Serviceable")
                ),
                "event_id": _text(entry.get("EventId")),
                "hidden": bool(hidden),
                "failing_fru": _event_log_failing_fru(entry),
                "log_type": log_type,
            }
        else:
            informational[code] = informational.get(code, 0) + 1
    max_records = _to_int(_dig(log_service, "MaxNumberOfRecords"))
    overwrite_policy = _text(_dig(log_service, "OverWritePolicy"))
    at_capacity = None
    if max_records is not None:
        at_capacity = len(_dicts(entries)) >= max_records
    context = {
        "entries_total": len(_dicts(entries)),
        "keyed_entries": len(normalized),
        "hidden_entries": hidden_total,
        "informational_by_code": dict(sorted(informational.items())),
        "entries_by_log_type": dict(sorted(by_log_type.items())),
        "first_id": min(ids) if ids else None,
        "newest_id": max(ids) if ids else None,
        "newest_created": _text(newest.get("Created")) if newest else None,
        "at_capacity": at_capacity,
        "max_records": max_records,
        "overwrite_policy": overwrite_policy,
    }
    context.update(_platform_seq_nums(log_service))
    return normalized, context


def _platform_seq_nums(log_service):
    """first_seq_num / last_seq_num of the platform log and the spelling they were read from."""
    oem = _dig(log_service, "Oem", "Lenovo")
    for first, last in (
        ("PlatformFirstSeqNum", "PlatformLastSeqNum"),
        ("FirstSeqNum", "LastSeqNum"),
    ):
        if isinstance(oem, dict) and (first in oem or last in oem):
            return {
                "first_seq_num": _to_int(oem.get(first)),
                "last_seq_num": _to_int(oem.get(last)),
                "seq_num_source": "Oem.Lenovo.%s/%s" % (first, last),
            }
    return {"first_seq_num": None, "last_seq_num": None, "seq_num_source": None}


def _event_log_audit_seq(platform, platform_id, audit=None, audit_id=None):
    """({first, last}, source) of the audit log's sequence numbers, from a SERVICE resource.

    The platform log's service first (XCC 6.10's StandardLog carries
    Oem.Lenovo.AuditFirstSeqNum / AuditLastSeqNum beside its platform
    counters), else an AuditLog service's own resource (the Audit* spelling,
    else its plain FirstSeqNum / LastSeqNum). The AuditLog's entries are
    never read.
    """
    for label, service, spellings in (
        (platform_id, platform, (("AuditFirstSeqNum", "AuditLastSeqNum"),)),
        (
            audit_id,
            audit,
            (("AuditFirstSeqNum", "AuditLastSeqNum"), ("FirstSeqNum", "LastSeqNum")),
        ),
    ):
        oem = _dig(service, "Oem", "Lenovo")
        if not isinstance(oem, dict):
            continue
        for first, last in spellings:
            if first in oem or last in oem:
                return (
                    {"first": _to_int(oem.get(first)), "last": _to_int(oem.get(last))},
                    "%s Oem.Lenovo.%s/%s" % (label, first, last),
                )
    return {"first": None, "last": None}, None


def _event_log_sel_wrapping(sel, sel_id, platform, platform_id):
    """(enabled, source) of Lenovo's EnableSELWrapping: the SEL service's, else the platform's."""
    for label, service in ((sel_id, sel), (platform_id, platform)):
        oem = _dig(service, "Oem", "Lenovo")
        if isinstance(oem, dict) and "EnableSELWrapping" in oem:
            return _to_bool(oem["EnableSELWrapping"]), "%s Oem.Lenovo.EnableSELWrapping" % (label,)
    return None, None


def _event_log_service_facts(service):
    """Size policy of a log service resource; every field None when it was not served."""
    served = isinstance(service, dict)
    return {
        "served": served,
        "service_enabled": _to_bool(_dig(service, "ServiceEnabled")),
        "max_records": _to_int(_dig(service, "MaxNumberOfRecords")),
        "overwrite_policy": _text(_dig(service, "OverWritePolicy")),
        "entries_link": bool(_dig(service, "Entries", "@odata.id")) if served else None,
    }


def _event_log_normalize_active(entries):
    """'active|<code>|<Id>' for EVERY ActiveLog entry, whatever its severity.

    Values: severity, message_id (the DMTF MessageId), created (the
    condition's own timestamp, stable per entry), serviceable, failing_fru.
    """
    normalized = {}
    for entry in _dicts(entries):
        key = "active|%s|%s" % (_event_log_code(entry), _member_id(entry) or "?")
        normalized[key] = {
            "severity": _text(entry.get("Severity")),
            "message_id": _text(entry.get("MessageId")),
            "created": _text(entry.get("Created")),
            "serviceable": _event_log_serviceable(_dig(entry, "Oem", "Lenovo", "Serviceable")),
            "serviceable_by": _event_log_serviceable_by(
                _dig(entry, "Oem", "Lenovo", "Serviceable")
            ),
            "failing_fru": _event_log_failing_fru(entry),
        }
    return normalized


def _event_log_history(entries):
    """MaintenanceLog counts: total, per EventGroupId, first/newest id and newest Created.

    Every field is None when the log was not read (``entries`` None).
    """
    if entries is None:
        return dict.fromkeys(
            ("entries_total", "by_event_group_id", "first_id", "newest_id", "newest_created")
        )
    entries = _dicts(entries)
    ids = [value for value in (_to_int(entry.get("Id")) for entry in entries) if value is not None]
    by_group = {}
    for entry in entries:
        group = entry.get("EventGroupId")
        label = "none" if group is None else str(group)
        by_group[label] = by_group.get(label, 0) + 1
    newest = max(entries, key=_entry_sort_id) if entries else None
    return {
        "entries_total": len(entries),
        "by_event_group_id": dict(sorted(by_group.items())),
        "first_id": min(ids) if ids else None,
        "newest_id": max(ids) if ids else None,
        "newest_created": _text(newest.get("Created")) if newest else None,
    }


def _event_log_platform_row(entry):
    """A raw row of the platform log."""
    return {
        "Id": entry.get("Id"),
        "Created": entry.get("Created"),
        "Severity": entry.get("Severity"),
        "EventId": entry.get("EventId"),
        "CommonEventID": _dig(entry, "Oem", "Lenovo", "CommonEventID"),
        "LogType": _dig(entry, "Oem", "Lenovo", "LogType"),
        "Hidden": _dig(entry, "Oem", "Lenovo", "Hidden"),
        "Message": entry.get("Message"),
    }


def _event_log_aux_row(entry):
    """A raw row of the ActiveLog or the MaintenanceLog."""
    return {
        "Id": entry.get("Id"),
        "Created": entry.get("Created"),
        "Severity": entry.get("Severity"),
        "MessageId": entry.get("MessageId"),
        "CommonEventID": _dig(entry, "Oem", "Lenovo", "CommonEventID"),
        "EventGroupId": entry.get("EventGroupId"),
        "Message": entry.get("Message"),
    }


def _curate_entries(entries, cap=_RAW_LOG_ENTRIES, row=None):
    """Per-entry rows for raw, newest first and capped: (rows, how many were left out).

    ``row`` builds one row from an entry; the default is the platform log's
    (Id, Created, Severity, EventId, CommonEventID, LogType, Hidden, Message).
    """
    ordered = sorted(_dicts(entries), key=_entry_sort_id, reverse=True)
    build = row or _event_log_platform_row
    return [build(entry) for entry in ordered[:cap]], max(0, len(ordered) - cap)


def _event_log_raw_page(entries, pages, served_count, cap, row=None):
    """The raw record of one log's Entries: curated rows plus what was read and left out."""
    rows, omitted = _curate_entries(entries, cap, row)
    return {
        "Members@odata.count": served_count,
        "Members": rows,
        "entries_omitted_from_raw": omitted,
        "pages_fetched": pages,
    }


def _event_log_read_entries(ctx, entries_link, label):
    """(entries, pages, served count) of one log's whole Entries collection.

    The whole collection, no query string: $top is undocumented on XCC and
    where honoured returns the OLDEST entries first. A firmware that pages
    hands back Members@odata.nextLink; the fence lets its $skip / $skiptoken
    through and refuses a link carrying $top (or anything else) loudly rather
    than reading a partial log, and a continuation naming a page already read
    fails too (the per-run cache would answer it forever). Every page passes
    the log redactor: Lenovo audit rows name people in the message.
    """
    page = _get(ctx, entries_link, redact=_redact_log_page)
    if not isinstance(page, dict):
        raise CollectError("%s answered without a collection body" % (entries_link,))
    entries = list(_dicts(page.get("Members")))
    pages = [entries_link]
    served_count = page.get("Members@odata.count")
    while _text(page.get("Members@odata.nextLink")):
        next_link = _fenced_link(
            {"@odata.id": page["Members@odata.nextLink"]}, "%s continuation" % (label,)
        )
        if next_link in pages:
            raise CollectError("%s continuation: %s names a page already read" % (label, next_link))
        page = _get(ctx, next_link, redact=_redact_log_page)
        if not isinstance(page, dict):
            raise CollectError("%s answered without a collection body" % (next_link,))
        entries.extend(_dicts(page.get("Members")))
        pages.append(next_link)
    if not isinstance(served_count, int) or isinstance(served_count, bool):
        served_count = len(entries)
    return entries, pages, served_count


def _event_log_services(ctx, services_path, targets):
    """The platform log's service and the ones read beside it, the cheapest way offered.

    One ``$expand`` GET inlines every service resource (XCC 6.10: six). When
    the firmware refuses or ignores it, the collection is read plain and only
    the services this check uses are fetched — the platform log first, so a
    tree this family has no mapping for is not-present before any other
    member is read; a listed auxiliary service that answers 404 is not served.
    Returns ``links`` (every member, fenced), ``platform_link`` /
    ``platform_id`` / ``platform``, ``services`` ({lower-cased id: (link,
    resource or None)} for the ActiveLog, MaintenanceLog, SEL and — only where
    the platform service carries no audit sequence numbers — the AuditLog),
    ``strategy`` (expand / members), ``expand_refused`` and ``raw``.
    """
    raw = {}
    inline = None
    expand_refused = None
    if _expand_advertised(_get(ctx, _ROOT)) is not False:
        expanded_path = services_path + _EXPAND
        try:
            payload = _get_optional(ctx, expanded_path)
        except Exception as exc:  # transport error class is not importable here
            if _http_status(exc) is None:
                raise  # budget, fence or network failure — never a fallback trigger
            payload, expand_refused = None, "HTTP %s" % (_http_status(exc),)
        if payload is not None and _expanded(_dicts(payload.get("Members"))):
            raw[expanded_path] = _curate(payload)
            inline = {}
            for member in _dicts(payload.get("Members")):
                link = _fenced_link(member, "bmc_event_log log service")
                if link is not None:
                    inline[link] = member
        elif payload is not None:
            expand_refused = "members returned as links"
    if inline is not None:
        links = list(inline)
    else:
        collection = _get(ctx, services_path)
        raw[services_path] = _curate(collection)
        links = _member_links(collection, "bmc_event_log")

    def read(link, required):
        if inline is not None:
            return inline.get(link)
        payload = _get(ctx, link) if required else _get_optional(ctx, link)
        raw[link] = _curate(payload) if payload is not None else None
        return payload

    platform_link, platform_id = _pick_log_service(links, targets)
    platform = read(platform_link, True)
    if not isinstance(platform, dict):
        raise CollectError("%s answered without a resource body" % (platform_link,))
    by_id = {}
    for link in links:
        by_id.setdefault(_leaf_id(link).lower(), link)
    wanted = [_EVENT_LOG_ACTIVE, _EVENT_LOG_MAINTENANCE, _EVENT_LOG_SEL]
    if _event_log_audit_seq(platform, platform_id)[1] is None:
        wanted.append(_EVENT_LOG_AUDIT)
    services = {_EVENT_LOG_AUDIT: (None, None)}
    for name in wanted:
        link = by_id.get(name)
        if link is None:
            services[name] = (None, None)
        elif link == platform_link:
            services[name] = (link, platform)
        else:
            services[name] = (link, read(link, False))
    return {
        "links": links,
        "platform_link": platform_link,
        "platform_id": platform_id,
        "platform": platform,
        "services": services,
        "strategy": "expand" if inline is not None else "members",
        "expand_refused": expand_refused,
        "raw": raw,
    }


def _event_log_read_aux(ctx, found, name):
    """(service, entries link, entries, pages, served count) of the ActiveLog or MaintenanceLog.

    Nothing is read when the service is not served, links no Entries, or is
    the platform log itself (whose entries are read already).
    """
    link, service = found["services"][name]
    if service is None or link == found["platform_link"]:
        return service, None, [], [], None
    label = "bmc_event_log %s" % (_leaf_id(link),)
    entries_link = _fenced_link(_dig(service, "Entries"), label)
    if entries_link is None:
        return service, None, [], [], None
    return (service, entries_link) + _event_log_read_entries(ctx, entries_link, label)


def _collect_event_log(ctx):
    with ctx.budget("bmc_event_log", _BUDGET_EVENT_LOG):
        targets = _targets(ctx)
        found = _event_log_services(ctx, _sub(targets["system"], "LogServices"), targets)
        entries_link = _fenced_link(found["platform"].get("Entries"), "bmc_event_log") or (
            found["platform_link"] + "/Entries"
        )
        entries, pages, served_count = _event_log_read_entries(ctx, entries_link, "bmc_event_log")
        active_read = _event_log_read_aux(ctx, found, _EVENT_LOG_ACTIVE)
        history_read = _event_log_read_aux(ctx, found, _EVENT_LOG_MAINTENANCE)
    normalized, context = _normalize_event_log(entries, found["platform"])
    raw = dict(found["raw"])
    raw[entries_link] = _event_log_raw_page(entries, pages, served_count, _RAW_LOG_ENTRIES)
    service, link, active, active_pages, count = active_read
    active_log = dict(
        _event_log_service_facts(service), entries_total=None, pages=len(active_pages)
    )
    if link is not None:
        normalized.update(_event_log_normalize_active(active))
        active_log["entries_total"] = len(active)
        raw[link] = _event_log_raw_page(
            active, active_pages, count, _RAW_LOG_ENTRIES, _event_log_aux_row
        )
    service, link, history, history_pages, count = history_read
    maintenance_log = dict(_event_log_service_facts(service), pages=len(history_pages))
    maintenance_log.update(_event_log_history(history if link is not None else None))
    if link is not None:
        raw[link] = _event_log_raw_page(
            history, history_pages, count, _EVENT_LOG_MAINTENANCE_ROWS, _event_log_aux_row
        )
    total, limit = maintenance_log["entries_total"], maintenance_log["max_records"]
    maintenance_log["at_capacity"] = (
        total >= limit if total is not None and limit is not None else None
    )
    sel_link, sel = found["services"][_EVENT_LOG_SEL]
    audit_link, audit = found["services"][_EVENT_LOG_AUDIT]
    audit_seq, audit_source = _event_log_audit_seq(
        found["platform"], found["platform_id"], audit, _leaf_id(audit_link) if audit_link else None
    )
    wrapping, wrapping_source = _event_log_sel_wrapping(
        sel, _leaf_id(sel_link) if sel_link else None, found["platform"], found["platform_id"]
    )
    context.update(
        {
            "log_service_used": found["platform_id"],
            "pages": len(pages),
            "log_services_served": sorted(_leaf_id(link) for link in found["links"]),
            "log_services_strategy": found["strategy"],
            "log_services_expand_refused": found["expand_refused"],
            "audit_log_seq": audit_seq,
            "audit_log_seq_source": audit_source,
            "sel_wrapping_enabled": wrapping,
            "sel_wrapping_source": wrapping_source,
            "sel": _event_log_service_facts(sel),
            "active_log": active_log,
            "maintenance_log": maintenance_log,
        }
    )
    return {"raw": raw, "normalized": normalized, "context": _with_resolution(context, targets)}


# --- bmc_bios ----------------------------------------------------------------

# Registry ids are ``<Name>.<Major>.<Minor>.<Errata>`` in the DMTF form
# (BiosAttributeRegistry.1.0.0 on XCC 6.10); an id outside that form (Lenovo's
# documentation sample spells BiosAttributeRegistryHYE134C-2.31) is kept whole
# as the name, with no version.
_BIOS_REGISTRY_ID = re.compile(r"^(?P<name>.+?)\.(?P<version>\d+\.\d+\.\d+)$")


def _bios_registry(value):
    """{id, name, version} of an AttributeRegistry string; all None when unserved."""
    registry_id = _text(value)
    if registry_id is None:
        return {"id": None, "name": None, "version": None}
    match = _BIOS_REGISTRY_ID.match(registry_id)
    if match is None:
        return {"id": registry_id, "name": registry_id, "version": None}
    return {"id": registry_id, "name": match.group("name"), "version": match.group("version")}


def _bios_attributes(payload):
    """{name: value} of a Bios resource or settings object, password-valued attributes dropped.

    Values are verbatim, except that an empty (or blank) string reads None:
    an unset string attribute, never ''.
    """
    attributes = _dig(payload, "Attributes")
    if not isinstance(attributes, dict):
        return {}
    return {
        name: None if isinstance(value, str) and not value.strip() else value
        for name, value in attributes.items()
        if not _is_secret(name, value)
    }


def _normalize_bios(bios, pending=None):
    """Every UEFI attribute keyed, the pending differences keyed, and the reset/password flags.

    'bios|<Attribute>' -> the current value verbatim, for EVERY attribute
    (a password-valued one is dropped by the exact-name rule, never stored);
    'pending|<Attribute>' -> the value the settings object holds, ONLY where
    it differs from the current one (a firmware that serves the whole set
    there, as XCC 6.10 does, and one that serves only the changes read
    alike), so the pending family is empty on a healthy unit;
    reset_to_defaults_pending (DMTF) and Lenovo's uefi_admin_password_set /
    uefi_power_on_password_set — always present, None when unserved.
    """
    current = _bios_attributes(bios)
    normalized = {"bios|%s" % (name,): current[name] for name in sorted(current)}
    for name, value in sorted(_bios_attributes(pending).items()):
        if name not in current or current[name] != value:
            normalized["pending|%s" % (name,)] = value
    lenovo = _dig(bios, "Oem", "Lenovo")
    normalized["reset_to_defaults_pending"] = _to_bool(_dig(bios, "ResetBiosToDefaultsPending"))
    normalized["uefi_admin_password_set"] = _to_bool(_dig(lenovo, "IsUefiAdminPasswordSet"))
    normalized["uefi_power_on_password_set"] = _to_bool(_dig(lenovo, "IsUefiPowerOnPasswordSet"))
    return normalized


def _bios_context(bios, pending, settings_link, normalized):
    """Registry, counts and the settings object's apply facts (all volatile or descriptive)."""
    settings = _dig(bios, "@Redfish.Settings")
    attributes = _dig(bios, "Attributes") if isinstance(_dig(bios, "Attributes"), dict) else {}
    pending_attributes = _dig(pending, "Attributes")
    return {
        "attribute_registry": _bios_registry(_dig(bios, "AttributeRegistry")),
        "attributes_total": len(attributes),
        "password_attributes_dropped": len(attributes) - len(_bios_attributes(bios)),
        "pending_total": len([key for key in normalized if key.startswith("pending|")]),
        "settings_object": settings_link,
        "settings_object_served": (pending is not None) if settings_link else None,
        "settings_object_attributes": (
            len(pending_attributes) if isinstance(pending_attributes, dict) else None
        ),
        "settings_apply_time": _text(_dig(settings, "Time")),
        "supported_apply_times": sorted(
            _text(item) for item in _aslist(_dig(settings, "SupportedApplyTimes")) if _text(item)
        ),
        "settings_messages": [
            _text(_dig(message, "MessageId")) for message in _dicts(_dig(settings, "Messages"))
        ],
        "pending_apply_time": _text(_dig(pending, "@Redfish.SettingsApplyTime", "ApplyTime")),
    }


def _collect_bios(ctx):
    pending = None
    settings_link = None
    with ctx.budget("bmc_bios", _BUDGET_BIOS):
        targets = _targets(ctx)
        path = _sub(targets["system"], "Bios")
        bios = _get_optional(ctx, path)
        if bios is None:
            raise SkipCheck("%s is not served by this firmware" % (path,))
        attributes = _dig(bios, "Attributes")
        if not isinstance(attributes, dict) or not attributes:
            raise CollectError("%s answered without an Attributes block" % (path,))
        # The settings object (a change armed for the next reset) is linked
        # by the server: fenced before it is followed, optional when read.
        settings_link = _fenced_link(
            _dig(bios, "@Redfish.Settings", "SettingsObject"), "bmc_bios settings object"
        )
        if settings_link is not None:
            pending = _get_optional(ctx, settings_link)
    normalized = _normalize_bios(bios, pending)
    raw = {path: _curate(bios)}
    if settings_link is not None:
        raw[settings_link] = _curate(pending) if pending is not None else None
    return {
        "raw": raw,
        "normalized": normalized,
        "context": _with_resolution(
            _bios_context(bios, pending, settings_link, normalized), targets
        ),
    }


# --- bmc_storage -------------------------------------------------------------
# GETs, the lab layout (four Storage members of one AHCI controller and one M.2
# drive each, empty Volumes, no Controllers link, no Chassis Drives): with
# $expand honoured 1 (Storage) + 4 (drives) + 4 (Volumes) + 1 (the Chassis, the
# same cached read bmc_chassis makes) = 10 beyond the id resolution; with
# $expand refused or ignored 1 (the attempt) + 1 (the collection) + 4 (members)
# + 4 (drives) + 4 (Volumes, $expand never re-tried) + 1 = 15, inside
# _BUDGET_STORAGE (18 + _TARGET_GETS). A Controllers collection costs one GET
# per Storage member that links one, a Chassis Drives collection one more;
# their member walks are pre-checked against the budget like every other.
_STORAGE_SMART_CAP = 2048  # characters of a drive's Lenovo SMARTData kept in raw


def _storage_raid_levels(controller):
    """(sorted RAID levels, the leaf read): DMTF SupportedRAIDTypes, else Lenovo's text.

    Lenovo's ``SupportedRaidLevels`` is one string (its schema says so); its
    comma-separated parts are the levels. (None, None) when neither is served.
    """
    served = controller.get("SupportedRAIDTypes")
    if isinstance(served, list):
        return sorted({_text(item) for item in served if _text(item)}), "SupportedRAIDTypes"
    text = _text(_dig(controller, "Oem", "Lenovo", "SupportedRaidLevels"))
    if text is None:
        return None, None
    levels = sorted({part.strip() for part in text.split(",") if part.strip()})
    return levels, "Oem.Lenovo.SupportedRaidLevels"


def _storage_battery(battery):
    """A controller battery's readings (context only): capacities as served, mV, mA, °C."""
    return {
        "design_capacity": _text(battery.get("DesignCapacity")),
        "full_charge_capacity": _text(battery.get("FullChargeCapacity")),
        "remaining_capacity": _text(battery.get("RemainingCapacity")),
        "design_voltage_mv": _to_int(battery.get("DesignVoltageMV")),
        "voltage_mv": _to_int(battery.get("VoltageMV")),
        "current_ma": _to_int(battery.get("CurrentMA")),
        "temperature_c": _to_int(battery.get("TemperatureCelsius")),
    }


def _storage_drive(drive):
    """One 'drive|<Id>' row: identity, media, link and cache settings, health."""
    health, state = _status(drive)
    return {
        "serial": _text(drive.get("SerialNumber")),
        "model": _text(drive.get("Model")),
        "manufacturer": _text(drive.get("Manufacturer")),
        "revision": _text(drive.get("Revision")),
        "capacity_bytes": _to_int(drive.get("CapacityBytes")),
        "media_type": _text(drive.get("MediaType")),
        "protocol": _text(drive.get("Protocol")),
        "health": health,
        "state": state,
        "failure_predicted": _to_bool(drive.get("FailurePredicted")),
        "encryption_ability": _text(drive.get("EncryptionAbility")),
        "encryption_status": _text(drive.get("EncryptionStatus")),
        "location": _service_label(drive) or _text(_dig(drive, "PhysicalLocation", "Info")),
        "negotiated_speed_gbs": _to_float(drive.get("NegotiatedSpeedGbs")),
        "rotation_rpm": _to_int(drive.get("RotationSpeedRPM")),
        "block_size_bytes": _to_int(drive.get("BlockSizeBytes")),
        "hotspare_type": _text(drive.get("HotspareType")),
        "write_cache_enabled": _to_bool(drive.get("WriteCacheEnabled")),
        "drive_status": _text(_dig(drive, "Oem", "Lenovo", "DriveStatus")),
    }


def _normalize_storage(controllers, drives, volumes, controller_members=None, chassis_drives=None):
    """(normalized, context) over Storage members, their controllers, Drives[] and Volumes.

    ``controllers`` is the list of Storage member payloads; ``drives`` and
    ``volumes`` map a Storage id to its member payloads; ``controller_members``
    maps a Storage id to the members of its ``Controllers`` collection where one
    was read (preferred to the deprecated ``StorageControllers[]`` when it lists
    any — context.controller_source names which one fed each row);
    ``chassis_drives`` are drives the Chassis links that no Storage member lists.
    Keys are 'controller|<Id>' (one per Storage member, from its first
    controller), 'drive|<Id>' and 'volume|<Id>'; a drive/volume id that repeats is
    prefixed with its Storage id ('chassis' for a drive only the Chassis lists).
    """
    normalized = {}
    context = {
        "life_left_pct": {},
        "drives_total": 0,
        "volumes_total": 0,
        "controller_source": {},
        "raid_levels_source": {},
        "battery": {},
        "drive_temperature_c": {},
    }
    controller_members = controller_members or {}
    chassis_drives = _dicts(chassis_drives)
    drive_ids = [_member_id(d) for rows in drives.values() for d in _dicts(rows)]
    drive_ids += [_member_id(d) for d in chassis_drives]
    volume_ids = [_member_id(v) for rows in volumes.values() for v in _dicts(rows)]

    def _key(kind, controller_id, item_id, all_ids):
        if all_ids.count(item_id) > 1:
            return "%s|%s|%s" % (kind, controller_id, item_id)
        return "%s|%s" % (kind, item_id)

    def _add_drive(owner, drive):
        context["drives_total"] += 1
        key = _key("drive", owner, _member_id(drive) or "?", drive_ids)
        normalized[key] = _storage_drive(drive)
        context["life_left_pct"][key] = _to_float(drive.get("PredictedMediaLifeLeftPercent"))
        context["drive_temperature_c"][key] = _to_int(_dig(drive, "Oem", "Lenovo", "Temperature"))

    for controller in _dicts(controllers):
        controller_id = _member_id(controller) or "?"
        embedded = _dicts(controller.get("StorageControllers"))
        from_collection = _dicts(controller_members.get(controller_id))
        if from_collection:
            first, source = from_collection[0], "Controllers"
        elif embedded:
            first, source = embedded[0], "StorageControllers"
        else:
            first, source = {}, None
        health, state = _status(controller)
        raid_levels, raid_source = _storage_raid_levels(first)
        battery = _dig(first, "Oem", "Lenovo", "Battery")
        key = "controller|%s" % (controller_id,)
        normalized[key] = {
            "name": _text(controller.get("Name")),
            "model": _text(first.get("Model")),
            "manufacturer": _text(first.get("Manufacturer")),
            "firmware": _text(first.get("FirmwareVersion")),
            "serial": _text(first.get("SerialNumber")),
            "health": health or _text(_dig(first, "Status", "Health")),
            "state": state or _text(_dig(first, "Status", "State")),
            "drive_count": len(_dicts(drives.get(controller_id))),
            "volume_count": len(_dicts(volumes.get(controller_id))),
            "cache_size_mib": _to_int(_dig(first, "CacheSummary", "TotalCacheSizeMiB")),
            "battery_operational_status": _text(_dig(battery, "OperationalStatus")),
            "supported_raid_levels": raid_levels,
            "mode": _text(_dig(first, "Oem", "Lenovo", "Mode")),
        }
        context["controller_source"][controller_id] = source
        context["raid_levels_source"][controller_id] = raid_source
        if isinstance(battery, dict):
            context["battery"][key] = _storage_battery(battery)
        for drive in _dicts(drives.get(controller_id)):
            _add_drive(controller_id, drive)
        for volume in _dicts(volumes.get(controller_id)):
            context["volumes_total"] += 1
            volume_id = _member_id(volume) or "?"
            key = _key("volume", controller_id, volume_id, volume_ids)
            health, state = _status(volume)
            member_drives = sorted(
                _leaf_id(item["@odata.id"])
                for item in _dicts(_dig(volume, "Links", "Drives"))
                if item.get("@odata.id")
            )
            lenovo = _dig(volume, "Oem", "Lenovo")
            normalized[key] = {
                "name": _text(volume.get("Name")),
                "raid_type": _text(volume.get("RAIDType")) or _text(volume.get("VolumeType")),
                "capacity_bytes": _to_int(volume.get("CapacityBytes")),
                "health": health,
                "state": state,
                "encrypted": _to_bool(volume.get("Encrypted")),
                "drives": member_drives,
                "read_cache_policy": _text(volume.get("ReadCachePolicy")),
                "write_cache_policy": _text(volume.get("WriteCachePolicy")),
                "strip_size_bytes": _to_int(volume.get("StripSizeBytes")),
                "is_boot_capable": _to_bool(volume.get("IsBootCapable")),
                "raid_level": _text(_dig(lenovo, "RaidLevel")),
                "bootable": _to_bool(_dig(lenovo, "Bootable")),
                "access_policy": _text(_dig(lenovo, "AccessPolicy")),
                "io_policy": _text(_dig(lenovo, "IOPolicy")),
                "drive_cache_policy": _text(_dig(lenovo, "DriveCachePolicy")),
            }
    for drive in chassis_drives:
        _add_drive("chassis", drive)
    return normalized, context


def _storage_resource(link):
    """The resource part of a path or an @odata.id (fragment, query and trailing '/' dropped)."""
    return str(link or "").partition("#")[0].partition("?")[0].rstrip("/")


def _storage_chassis_drives(ctx, targets, drives, listed_links, budget, try_expand):
    """(drives, meta, raw): the drives the Chassis links that no Storage member lists.

    Read from the Chassis's ``Drives`` collection when it links one (none on XCC
    6.10), else from its ``Links.Drives`` array (empty there); the Chassis itself
    is the read bmc_chassis makes (cached per run). A drive at a path a Storage
    member already listed — or carrying a listed drive's serial number — is that
    drive, never a second one. A walked collection is pre-checked for all its
    members although the listed ones answer from the cache (loud, never partial).
    """
    listed_paths = {_storage_resource(link) for link in listed_links}
    listed_serials = set()
    for rows in drives.values():
        for drive in _dicts(rows):
            listed_paths.add(_storage_resource(drive.get("@odata.id")))
            if _text(drive.get("SerialNumber")):
                listed_serials.add(_text(drive.get("SerialNumber")))
    listed_paths.discard("")
    meta = {"source": None, "strategy": None, "members": 0, "unlisted": 0}
    raw = {}
    chassis = _get(ctx, targets["chassis"])
    collection = _fenced_link(_dig(chassis, "Drives"), "bmc_storage chassis Drives")
    if collection is not None:
        members, fetch, raw = _fetch_collection(
            ctx,
            collection,
            "bmc_storage chassis Drives",
            ok_404=True,
            budget=budget,
            try_expand=try_expand,
        )
        meta.update(source="Drives", strategy=fetch["strategy"], members=len(members or []))
        candidates = members or []
    else:
        links = []
        for item in _dicts(_dig(chassis, "Links", "Drives")):
            link = _fenced_link(item, "bmc_storage chassis Links.Drives")
            if link is not None:
                links.append(link)
        unread = [link for link in links if _storage_resource(link) not in listed_paths]
        _require_budget(budget, len(unread), "bmc_storage chassis Links.Drives", "drives")
        candidates = []
        for link in unread:
            drive = _get(ctx, link)
            raw[link] = _curate(drive)
            candidates.append(drive)
        if links:
            meta.update(source="Links.Drives", strategy="members", members=len(links))
    unlisted = []
    for drive in candidates:
        serial = _text(drive.get("SerialNumber"))
        if _storage_resource(drive.get("@odata.id")) in listed_paths:
            continue
        if serial is not None and serial in listed_serials:
            continue
        unlisted.append(drive)
    meta["unlisted"] = len(unlisted)
    return unlisted, meta, raw


def _storage_cap_smart(node):
    """A curated payload with every SMARTData text capped (raw only; never normalized)."""
    if isinstance(node, dict):
        out = {}
        for key, value in node.items():
            if key == "SMARTData" and isinstance(value, str) and len(value) > _STORAGE_SMART_CAP:
                out[key] = value[:_STORAGE_SMART_CAP] + "...[truncated %d chars]" % (
                    len(value) - _STORAGE_SMART_CAP,
                )
            else:
                out[key] = _storage_cap_smart(value)
        return out
    if isinstance(node, list):
        return [_storage_cap_smart(item) for item in node]
    return node


def _collect_storage(ctx):
    drives = {}
    volumes = {}
    controller_members = {}
    controllers_read = {}
    listed_links = []
    with ctx.budget("bmc_storage", _BUDGET_STORAGE) as budget:
        targets = _targets(ctx)
        system = _get(ctx, targets["system"])
        path = _sub(targets["system"], "Storage")
        controllers, meta, raw = _fetch_collection(
            ctx, path, "bmc_storage", ok_404=True, budget=budget
        )
        if controllers is None:
            raise SkipCheck("%s is not served by this firmware" % (path,))
        if not controllers:
            raise SkipCheck(
                "%s lists no controllers (host PowerState %s; non-RAID M.2 may not "
                "enumerate at all)" % (path, _text(_dig(system, "PowerState")))
            )
        # The $expand-refusal memory: the Storage collection's answer decides for
        # every sub-collection, and the first refusal after it turns $expand off.
        expand_ok = meta["strategy"] == "expand"
        for controller in controllers:
            controller_id = _member_id(controller) or "?"
            drive_links = []
            for item in _dicts(controller.get("Drives")):
                link = _fenced_link(item, "bmc_storage")
                if link:
                    drive_links.append(link)
            _require_budget(budget, len(drive_links), "bmc_storage", "drives")
            drives[controller_id] = []
            volumes[controller_id] = []
            for link in drive_links:
                drive = _get(ctx, link)
                raw[link] = _curate(drive)
                drives[controller_id].append(drive)
                listed_links.append(link)
            for label, link in (
                ("controllers", _fenced_link(controller.get("Controllers"), "bmc_storage")),
                ("volumes", _fenced_link(controller.get("Volumes"), "bmc_storage")),
            ):
                if not link:
                    continue
                members, fetch, member_raw = _fetch_collection(
                    ctx,
                    link,
                    "bmc_storage %s" % (label,),
                    ok_404=True,
                    budget=budget,
                    try_expand=expand_ok,
                )
                raw.update(member_raw)
                expand_ok = expand_ok and not fetch.get("expand_refused")
                if label == "volumes":
                    volumes[controller_id] = members or []
                    continue
                controllers_read[controller_id] = {
                    "strategy": fetch["strategy"],
                    "members": len(members) if members is not None else None,
                }
                if members is not None:
                    controller_members[controller_id] = members
        chassis_drives, chassis_meta, chassis_raw = _storage_chassis_drives(
            ctx, targets, drives, listed_links, budget, expand_ok
        )
        raw.update(chassis_raw)
    normalized, context = _normalize_storage(
        controllers, drives, volumes, controller_members, chassis_drives
    )
    context.update(meta)
    context["controllers_collection"] = controllers_read
    context["chassis_drives"] = chassis_meta
    context["host_power_state"] = _text(_dig(system, "PowerState"))
    raw = {request: _storage_cap_smart(payload) for request, payload in raw.items()}
    return {"raw": raw, "normalized": normalized, "context": _with_resolution(context, targets)}


# --- bmc_manager_network -----------------------------------------------------

_PROTOCOLS = ("HTTP", "HTTPS", "SSH", "IPMI", "SNMP", "VirtualMedia", "KVMIP", "SSDP", "Telnet")
# Unset address slots are served as placeholders (XCC 6.10: '' and '::' in
# NameServers, '0.0.0.0' and '::' in StaticNameServers and in the Lenovo DNS
# resource's IPv4Address1-3 / IPv6Address1-3, '::' as IPv6DefaultGateway) —
# never addresses.
_DNS_PLACEHOLDERS = frozenset({"", "::", "0.0.0.0"})
# The Lenovo DNS resource's server slots, in the order the analyst reads them.
_MANAGER_NETWORK_DNS_SLOTS = tuple("IPv4Address%d" % (n,) for n in (1, 2, 3)) + tuple(
    "IPv6Address%d" % (n,) for n in (1, 2, 3)
)
# Services the Lenovo block of NetworkProtocol carries beside the DMTF ones:
# (key prefix, block name, whether the block serves a Port).
_MANAGER_NETWORK_LENOVO_SERVICES = (
    ("cimoverhttps", "CimOverHTTPS", True),
    ("slp", "SLP", True),
    ("sftp", "SFTP", True),
    ("webhttps", "WebOverHTTPS", False),
)


def _dns_servers(values):
    """Configured name servers in served order, the unset-slot placeholders dropped."""
    servers = []
    for value in _aslist(values):
        text = _text(value)
        if text is not None and text not in _DNS_PLACEHOLDERS:
            servers.append(text)
    return servers


def _snmp_enablement(protocol, vendor_snmp):
    """(enabled, port, source) for the SNMP agent.

    The DMTF ``SNMP.ProtocolEnabled`` when the firmware serves it; XCC 6.10
    does not (its DMTF block carries only EnableSNMPv3, Port and the engine
    id), so the Lenovo SNMP resource's ``SNMPv3Agent.ProtocolEnabled`` — the
    only agent that firmware runs — answers instead. ``source`` names the leaf.
    """
    block = protocol.get("SNMP") if isinstance(protocol.get("SNMP"), dict) else {}
    enabled = _to_bool(block.get("ProtocolEnabled"))
    port = _to_int(block.get("Port"))
    if enabled is not None:
        return enabled, port, "SNMP.ProtocolEnabled"
    agent = _dig(vendor_snmp, "SNMPv3Agent")
    if isinstance(agent, dict) and _to_bool(agent.get("ProtocolEnabled")) is not None:
        if port is None:
            port = _to_int(agent.get("Port"))
        return _to_bool(agent.get("ProtocolEnabled")), port, "Oem.Lenovo.SNMP.SNMPv3Agent"
    return None, port, None


def _manager_network_address(value):
    """An address leaf; None for an unset-slot placeholder ('', '::', '0.0.0.0')."""
    text = _text(value)
    return None if text in _DNS_PLACEHOLDERS else text


def _manager_network_leaf(node, name):
    """``node[name]`` matched case-insensitively (XCC 6.10 spells PreferredAddresstype)."""
    if isinstance(node, dict):
        for key, value in node.items():
            if str(key).lower() == name.lower():
                return value
    return None


def _manager_network_list(node, key):
    """The placeholder-free address list at ``node[key]``; None when the leaf is not served."""
    if not isinstance(node, dict) or key not in node:
        return None
    return _dns_servers(node.get(key))


def _manager_network_dns_servers(dns):
    """The Lenovo DNS slots (IPv4 1-3, then IPv6 1-3), placeholders dropped; None unserved."""
    if not isinstance(dns, dict):
        return None
    slots = [name for name in _MANAGER_NETWORK_DNS_SLOTS if name in dns]
    return _dns_servers([dns[name] for name in slots]) if slots else None


def _manager_network_ddns(dns):
    """Every DDNS entry of the Lenovo DNS resource in served order; None when not served."""
    if not isinstance(dns, dict) or not isinstance(dns.get("DDNS"), list):
        return None
    return [
        {
            "enabled": _to_bool(entry.get("DDNSEnable")),
            "domain_name_source": _text(entry.get("DomainNameSource")),
            "domain_name": _text(entry.get("DomainName")),
        }
        for entry in _dicts(dns["DDNS"])
    ]


def _manager_network_ports(values):
    """OpenPorts (served as strings) as sorted unique ints; None when not served."""
    if not isinstance(values, list):
        return None
    return sorted({port for port in (_to_int(value) for value in values) if port is not None})


def _normalize_manager_network(
    protocol,
    nic,
    vendor_snmp=None,
    *,
    manager=None,
    dns=None,
    datetime_service=None,
    host_interface=None,
    usb_lan=None,
):
    """Flat scalars: the BMC's services, addressing, DNS, time and host interface.

    ``protocol`` is NetworkProtocol and ``nic`` the management port (DMTF,
    with their Oem.Lenovo leaves); ``vendor_snmp``, ``dns`` and
    ``datetime_service`` are the Lenovo SNMP, DNS and DateTimeService
    resources (None on other vendors and where not served), ``manager`` the
    Manager (KCSEnabled), ``host_interface`` the HostInterface described and
    ``usb_lan`` the BMC-side interface it names (ToHost on XCC 6.10).
    Every key is always present: None where the leaf is not served, a list
    only where the list is.
    """
    protocol = protocol if isinstance(protocol, dict) else {}
    nic = nic if isinstance(nic, dict) else {}
    ipv4 = _first_ipv4(nic)
    ntp = _dig(protocol, "NTP") if isinstance(_dig(protocol, "NTP"), dict) else {}
    normalized = {
        "hostname": _text(protocol.get("HostName")),
        "fqdn": _text(protocol.get("FQDN")),
        "ntp_enabled": _to_bool(ntp.get("ProtocolEnabled")),
        "ntp_servers": [_text(s) for s in _aslist(ntp.get("NTPServers")) if _text(s)],
    }
    for name in _PROTOCOLS:
        block = protocol.get(name) if isinstance(protocol.get(name), dict) else {}
        normalized["%s_enabled" % (name.lower(),)] = _to_bool(block.get("ProtocolEnabled"))
        normalized["%s_port" % (name.lower(),)] = _to_int(block.get("Port"))
    snmp_enabled, snmp_port, _source = _snmp_enablement(protocol, vendor_snmp)
    normalized["snmp_enabled"] = snmp_enabled
    normalized["snmp_port"] = snmp_port
    vlan_enabled = _to_bool(_dig(nic, "VLAN", "VLANEnable"))
    lenovo_nic = _dig(nic, "Oem", "Lenovo")
    normalized.update(
        {
            "nic_hostname": _text(nic.get("HostName")),
            "nic_fqdn": _text(nic.get("FQDN")),
            "ipv4_address": _text(ipv4.get("Address")),
            "ipv4_origin": _text(ipv4.get("AddressOrigin")),
            "ipv4_subnet_mask": _text(ipv4.get("SubnetMask")),
            "ipv4_gateway": _text(ipv4.get("Gateway")),
            "dhcpv4_enabled": _to_bool(_dig(nic, "DHCPv4", "DHCPEnabled")),
            "dns_servers": _dns_servers(nic.get("NameServers")),
            "static_dns_servers": _dns_servers(nic.get("StaticNameServers")),
            "ipv6_address_count": len(_dicts(nic.get("IPv6Addresses"))),
            "ipv6_gateway": _manager_network_address(nic.get("IPv6DefaultGateway")),
            "mtu": _to_int(nic.get("MTUSize")),
            "autoneg": _to_bool(nic.get("AutoNeg")),
            "vlan_enabled": vlan_enabled,
            "vlan_id": _to_int(_dig(nic, "VLAN", "VLANId")) if vlan_enabled else None,
            "interface_enabled": _to_bool(nic.get("InterfaceEnabled")),
            # the management port's Lenovo leaves
            "nic_mode": _text(_dig(lenovo_nic, "InterfaceNicMode")),
            "failover_mode": _text(_dig(lenovo_nic, "InterfaceFailoverMode")),
            "ipv4_assigned_by": _text(_dig(lenovo_nic, "IPv4AddressAssignedby")),
            "domain_name": _text(_dig(lenovo_nic, "DomainName")),
            "hostname_from_dhcp": _to_bool(_dig(lenovo_nic, "HostNameFromDHCPEnabled")),
            # DNS (the Lenovo DNS resource)
            "dns_enabled": _to_bool(_dig(dns, "DNSEnable")),
            "dns_preferred_family": _text(_manager_network_leaf(dns, "PreferredAddresstype")),
            "dns_configured_servers": _manager_network_dns_servers(dns),
            "ddns": _manager_network_ddns(dns),
            "lxca_discovery_enabled": _to_bool(
                _dig(dns, "LXCADNSDiscovery", "DiscoverLXCAEnabled")
            ),
            # time (the Lenovo DateTimeService; Frequency is in minutes)
            "time_setting_method": _text(_dig(datetime_service, "SettingMethod")),
            "time_ntp_servers": _manager_network_list(datetime_service, "NTPServerAddresses"),
            "utc_offset": _text(_dig(datetime_service, "UTCOffset")),
            "auto_dst": _to_bool(_dig(datetime_service, "AutoDST")),
            "ntp_sync_interval_min": _to_int(_dig(datetime_service, "Frequency")),
            # the Redfish host interface (DMTF HostInterface)
            "host_interface_enabled": _to_bool(_dig(host_interface, "InterfaceEnabled")),
            "host_interface_externally_accessible": _to_bool(
                _dig(host_interface, "ExternallyAccessible")
            ),
            "credential_bootstrapping_enabled": _to_bool(
                _dig(host_interface, "CredentialBootstrapping", "Enabled")
            ),
            "credential_bootstrapping_role": _text(
                _dig(host_interface, "CredentialBootstrapping", "RoleId")
            ),
            "credential_bootstrapping_enable_after_reset": _to_bool(
                _dig(host_interface, "CredentialBootstrapping", "EnableAfterReset")
            ),
            "host_interface_address": _manager_network_usb_lan_address(usb_lan),
            "host_interface_address_mode": _text(_dig(usb_lan, "Oem", "Lenovo", "AddressMode")),
        }
    )
    lenovo_protocol = _dig(protocol, "Oem", "Lenovo")
    for prefix, block, has_port in _MANAGER_NETWORK_LENOVO_SERVICES:
        node = _dig(lenovo_protocol, block)
        normalized[prefix + "_enabled"] = _to_bool(_dig(node, "ProtocolEnabled"))
        if has_port:
            normalized[prefix + "_port"] = _to_int(_dig(node, "Port"))
    normalized.update(
        {
            "open_ports": _manager_network_ports(_dig(lenovo_protocol, "OpenPorts")),
            "snmpv3_agent_enabled": _to_bool(_dig(vendor_snmp, "SNMPv3Agent", "ProtocolEnabled")),
            "snmp_traps_enabled": _to_bool(_dig(vendor_snmp, "SNMPTraps", "ProtocolEnabled")),
            "kcs_enabled": _to_bool(_dig(manager, "Oem", "Lenovo", "KCSEnabled")),
        }
    )
    return normalized


def _manager_network_host_interface(members):
    """(the HostInterface the scalars describe, every member id): the lowest id when several."""
    rows = sorted(_dicts(members), key=lambda member: _member_id(member) or "")
    return (rows[0] if rows else None), [_member_id(row) for row in rows]


def _manager_network_usb_lan(ctx, nic, nic_meta, host_interface):
    """(payload, member, raw): the BMC side of the Redfish host interface — its USB LAN.

    The HostInterface names it as its ManagerEthernetInterface, a DMTF link
    read for every vendor (one GET; ``ToHost`` on XCC 6.10, where the host
    OS's address as the BMC sees it, Oem.Lenovo.OSIPv4Address, also sits).
    The management port itself when the link names it; None when the host
    interface links nothing or the link answers 404.
    """
    link = _fenced_link(
        _dig(host_interface, "ManagerEthernetInterface"),
        "bmc_manager_network ManagerEthernetInterface",
    )
    if link is None:
        return None, None, {}
    if _leaf_id(link).lower() == str(nic_meta.get("member") or "").lower():
        return nic, nic_meta.get("member"), {}
    usb_lan = _get_optional(ctx, link)
    if usb_lan is None:
        return None, None, {}
    return usb_lan, _member_id(usb_lan), {link: _curate(usb_lan)}


def _manager_network_usb_lan_address(usb_lan):
    """The USB LAN's IPv4 address (the unset 0.0.0.0 placeholder reads None)."""
    address = _text(_first_ipv4(usb_lan).get("Address")) if isinstance(usb_lan, dict) else None
    return None if address in _DNS_PLACEHOLDERS else address


def _collect_manager_network(ctx):
    raw = {}
    vendor_snmp = dns = datetime_service = host_interface = host_meta = None
    snmp_link = dns_link = datetime_link = None
    os_address = os_member = None
    with ctx.budget("bmc_manager_network", _BUDGET_MANAGER_NETWORK) as budget:
        targets = _targets(ctx)
        lenovo = _is_lenovo(targets)
        protocol_path = _sub(targets["manager"], "NetworkProtocol")
        protocol = _get(ctx, protocol_path)
        manager = _get(ctx, targets["manager"])
        if lenovo:
            snmp_link = _fenced_link(
                _dig(protocol, "Oem", "Lenovo", "SNMP"), "bmc_manager_network SNMP"
            )
            vendor_snmp = _get_optional(ctx, snmp_link) if snmp_link else None
            dns_node = _dig(protocol, "Oem", "Lenovo", "DNS")
            dns_link = _fenced_link(dns_node, "bmc_manager_network DNS")
            if dns_link is not None:
                dns = _get_optional(ctx, dns_link)
            elif isinstance(dns_node, dict) and dns_node:
                dns = dns_node  # served inline: nothing to fetch
            datetime_link = _fenced_link(
                _dig(manager, "Oem", "Lenovo", "DateTimeService"),
                "bmc_manager_network DateTimeService",
            )
            datetime_service = _get_optional(ctx, datetime_link) if datetime_link else None
        host_link = _fenced_link(
            _dig(manager, "HostInterfaces"), "bmc_manager_network HostInterfaces"
        )
        if host_link is not None:
            members, meta, host_raw = _fetch_collection(
                ctx, host_link, "bmc_manager_network host interfaces", ok_404=True, budget=budget
            )
            raw.update(host_raw)
            host_interface, host_ids = _manager_network_host_interface(members)
            host_meta = dict(meta, members=host_ids, used=_member_id(host_interface))
        nic, nic_meta, nic_raw = _fetch_manager_nic(ctx, targets)
        usb_lan, usb_member, usb_raw = _manager_network_usb_lan(ctx, nic, nic_meta, host_interface)
        raw.update(usb_raw)
    # The host OS's address as the BMC sees it (a Lenovo leaf, read from the
    # payloads already fetched): on the port read, else on the USB LAN.
    for payload, member in ((nic, nic_meta.get("member")), (usb_lan, usb_member)):
        os_address = _text(_dig(payload, "Oem", "Lenovo", "OSIPv4Address"))
        if os_address is not None:
            os_member = member
            break
    raw[protocol_path] = _curate(protocol)
    raw[targets["manager"]] = _curate(manager)
    for link, payload in (
        (snmp_link, vendor_snmp),
        (dns_link, dns),
        (datetime_link, datetime_service),
    ):
        if link is not None and payload is not None:
            raw[link] = _curate(payload)
    raw.update(nic_raw)
    _enabled, _port, snmp_source = _snmp_enablement(protocol, vendor_snmp)
    if dns is None:
        dns_source = None
    else:
        dns_source = dns_link or "%s Oem.Lenovo.DNS (inline)" % (protocol_path,)
    return {
        "raw": raw,
        "normalized": _normalize_manager_network(
            protocol,
            nic,
            vendor_snmp,
            manager=manager,
            dns=dns,
            datetime_service=datetime_service,
            host_interface=host_interface,
            usb_lan=usb_lan,
        ),
        "context": _with_resolution(
            {
                "manager_nic": nic_meta,
                "nic_speed_mbps": _to_int(_dig(nic, "SpeedMbps")) if nic else None,
                "nic_link_status": _text(_dig(nic, "LinkStatus")) if nic else None,
                "snmp_source": snmp_source,
                "dns_source": dns_source,
                "host_interfaces": host_meta,
                "os_ipv4_address": os_address,
                "os_ipv4_address_member": os_member,
                "host_interface_usb_lan_member": usb_member,
                "bmc_datetime": _text(_dig(manager, "DateTime")),
                "bmc_datetime_offset": _text(_dig(manager, "DateTimeLocalOffset")),
                "time_zone_name": _text(_dig(manager, "TimeZoneName")),
            },
            targets,
        ),
    }


# --- bmc_chassis -------------------------------------------------------------


def _chassis_led_key(name, led_id, name_counts):
    """'led|<Name>'; '|<Id>' appended only when a Name repeats; 'led|<Id>' when Name is null.

    The lab SE350's four LEDs have unique Names (BMC Heartbeat, Identify,
    Power, Fault) while their Location repeats, so the Name is the key.
    """
    if name is None:
        return "led|%s" % (led_id,)
    if name_counts.get(name, 0) > 1:
        return "led|%s|%s" % (name, led_id)
    return "led|%s" % (name,)


def _normalize_chassis_leds(members):
    """'led|<Name>' -> color, state (On | Off | Blink, verbatim), location, per LED member."""
    leds = _dicts(members)
    name_counts = {}
    for led in leds:
        name = _text(led.get("Name"))
        if name is not None:
            name_counts[name] = name_counts.get(name, 0) + 1
    rows = {}
    for led in leds:
        key = _chassis_led_key(_text(led.get("Name")), _member_id(led) or "?", name_counts)
        rows[key] = {
            "color": _text(led.get("Color")),
            "state": _text(led.get("State")),
            "location": _text(led.get("Location")),
        }
    return rows


def _normalize_chassis_location(chassis, leds=None, lenovo=False):
    """Chassis identity, indicator, Location record and intrusion scalars, plus 'led|' rows.

    Every scalar is always present (None when unserved); ``lenovo`` gates the
    Lenovo identity leaves (system-board serial, product name, FRU part
    number, switch board). PostalAddress and Placement are passed through
    generically as 'postal_<field>' / 'placement_<field>' so whichever leaves
    this firmware fills are compared, an empty one reading None; the
    operator-maintained record is expected to be edited when the chassis is
    relocated. ``leds`` is the LED collection's members (Lenovo), or None.
    """
    chassis = chassis if isinstance(chassis, dict) else {}
    oem = _dig(chassis, "Oem", "Lenovo") if lenovo else None
    health, state = _status(chassis)
    normalized = {
        "chassis_type": _text(chassis.get("ChassisType")),
        "manufacturer": _text(chassis.get("Manufacturer")),
        "model": _text(chassis.get("Model")),
        "serial": _text(chassis.get("SerialNumber")),
        "part_number": _text(chassis.get("PartNumber")),
        "asset_tag": _text(chassis.get("AssetTag")),
        "health": health,
        "state": state,
        "power_state": _text(chassis.get("PowerState")),
        "indicator_led": _text(chassis.get("IndicatorLED")),
        "location_indicator_active": _to_bool(chassis.get("LocationIndicatorActive")),
        "system_board_serial": _text(_dig(oem, "SystemBoardSerialNumber")),
        "product_name": _text(_dig(oem, "ProductName")),
        "fru_part_number": _text(_dig(oem, "FruPartNumber")),
        "has_switch_board": _to_bool(_dig(oem, "HasSwitchBoard")),
        "location_info": _text(_dig(chassis, "Location", "Info")),
        "location_info_format": _text(_dig(chassis, "Location", "InfoFormat")),
        "intrusion_sensor": _text(_dig(chassis, "PhysicalSecurity", "IntrusionSensor")),
        "intrusion_sensor_rearm": _text(_dig(chassis, "PhysicalSecurity", "IntrusionSensorReArm")),
    }
    for block, prefix in (("PostalAddress", "postal_"), ("Placement", "placement_")):
        node = _dig(chassis, "Location", block)
        if not isinstance(node, dict):
            continue
        for key in sorted(node):
            value = node[key]
            if isinstance(value, (dict, list)) or str(key).startswith("@"):
                continue
            normalized[prefix + _snake(key)] = _text(value) if isinstance(value, str) else value
    normalized.update(_normalize_chassis_leds(leds))
    return normalized


def _chassis_context(chassis, leds_meta):
    """Size and rating facts of the enclosure, and how the LED collection was read."""
    return {
        "height_mm": _to_float(chassis.get("HeightMm")),
        "width_mm": _to_float(chassis.get("WidthMm")),
        "depth_mm": _to_float(chassis.get("DepthMm")),
        "weight_kg": _to_float(chassis.get("WeightKg")),
        "environmental_class": _text(chassis.get("EnvironmentalClass")),
        "location_present": isinstance(chassis.get("Location"), dict),
        "physical_security_present": isinstance(chassis.get("PhysicalSecurity"), dict),
        "leds": leds_meta,
    }


def _collect_chassis_location(ctx):
    raw = {}
    leds = None
    leds_meta = {"resource": None, "strategy": None, "members": None, "note": None}
    with ctx.budget("bmc_chassis", _BUDGET_CHASSIS) as budget:
        targets = _targets(ctx)
        chassis = _get(ctx, targets["chassis"])
        if not isinstance(chassis, dict) or not chassis:
            raise CollectError("%s answered without a resource body" % (targets["chassis"],))
        lenovo = _is_lenovo(targets)
        # The LED collection is Lenovo's (Chassis Oem.Lenovo.LEDs), read only
        # through the link the Chassis serves; DMTF IndicatorLED and
        # LocationIndicatorActive are the scalars every vendor gets.
        link = None
        if lenovo:
            link = _fenced_link(_dig(chassis, "Oem", "Lenovo", "LEDs"), "bmc_chassis LEDs")
            if link is None:
                leds_meta["note"] = "the Chassis links no Oem.Lenovo.LEDs collection"
        else:
            leds_meta["note"] = "no %s mapping for the chassis LEDs yet" % (
                targets["vendor"] or "unknown-vendor",
            )
        if link is not None:
            leds, meta, leds_raw = _fetch_collection(
                ctx, link, "bmc_chassis LEDs", ok_404=True, budget=budget
            )
            raw.update(leds_raw)
            leds_meta = dict(
                meta, resource=link, members=len(leds) if leds is not None else None, note=None
            )
    raw[targets["chassis"]] = _curate(chassis)
    return {
        "raw": raw,
        "normalized": _normalize_chassis_location(chassis, leds, lenovo=lenovo),
        "context": _with_resolution(_chassis_context(chassis, leds_meta), targets),
    }


# --- bmc_sensors -------------------------------------------------------------
# GETs beyond the id resolution, with $expand honoured (the lab SE350): the
# Chassis (the read bmc_chassis, bmc_thermal and bmc_power make; cached per
# run), its EnvironmentMetrics, the ThermalSubsystem's ThermalMetrics (at the
# path bmc_thermal reads, so one answer serves both) and ONE $expand GET that
# inlines the whole Sensors collection (89 members, ~55 KB, ~11 s on XCC 6.10)
# — 4. The two single reads come before the collection, so the member walk,
# pre-checked against what is left before its first GET, is the last thing
# the check spends; Sensors is the only collection read, so an $expand refusal
# is paid at most once. The per-member fallback on the lab layout would be the
# attempt, the collection and 89 members — 91 GETs for the collection alone,
# past the transport ceiling of 40 — so it is refused up front naming the
# member count, never walked into the wall. _BUDGET_SENSORS = 30 +
# _TARGET_GETS: the resolution (5), the Chassis, the two metrics, the attempt
# and the collection (10 in all) leave a fallback walk of up to 25 sensors room
# to complete.
_BUDGET_SENSORS = 30 + _TARGET_GETS
# ReadingType is served carelessly (XCC 6.10 types watts Current, presence
# sensors Power, fan tachometers AirFlow, most discrete sensors null), so a
# sensor is numeric when it serves a non-empty ReadingUnits, discrete otherwise.
# A Celsius reading's units: XCC 6.10's 'C', the DMTF's (UCUM) 'Cel'.
_SENSORS_CELSIUS = frozenset({"C", "Cel"})
# Unitless sensors whose Reading is host load, never an assertion (Lenovo's
# Sys/CPU/Mem/IO Utilization): matched on the name.
_SENSORS_UTILISATION = ("utilization", "utilisation")
# The sensors that carry what an SE350 on XCC 6.10 exposes nowhere else (no
# PhysicalSecurity, no PowerSupplies, no ThinkEdge security leaves): the
# chassis intrusion switch, the motion sensor, the lockdown state, the
# low-security jumper and the external power adapters — Lenovo's names,
# matched whole.
_SENSORS_SECURITY = (
    ("chassis_intrusion", re.compile(r"Chassis")),
    ("chassis_movement", re.compile(r"Chassis Movement")),
    ("lockdown_mode", re.compile(r"Lockdown Mode")),
    ("low_security_jumper", re.compile(r"Low Security Jmp")),
    ("power_adapters", re.compile(r"Power Adapter \d+")),
)
# The Chassis EnvironmentMetrics excerpts read into context (DMTF
# EnvironmentMetrics v1), each Reading as served; the FanSpeedsPercent array
# is read beside them.
_SENSORS_ENVIRONMENT = (
    ("power_watts", "PowerWatts"),
    ("energy_kwh", "EnergykWh"),
    ("temperature_celsius", "TemperatureCelsius"),
    ("humidity_percent", "HumidityPercent"),
)


def _sensors_path(link):
    """The resource part of an @odata.id or DataSourceUri: fragment, query, trailing '/' gone."""
    return str(link or "").partition("#")[0].partition("?")[0].rstrip("/")


def _sensors_thresholds(sensor):
    """{snake-cased kind: reading} of every Thresholds.<Kind> served with a non-null Reading.

    ``{}`` when the sensor serves a Thresholds block with nothing set (XCC
    6.10's utilisation and power sensors), None when it serves no block (its
    discrete sensors). Kinds are the DMTF ones — LowerCaution ... UpperFatal
    and the *User variants — snake-cased: lower_caution, upper_critical_user.
    """
    block = sensor.get("Thresholds")
    if not isinstance(block, dict):
        return None
    found = {}
    for kind in sorted(block, key=str):
        if str(kind).startswith("@"):
            continue
        value = _to_float(_dig(block, kind, "Reading"))
        if value is not None:
            found[_snake(kind)] = value
    return found


def _sensors_is_utilisation(name):
    lowered = (name or "").lower()
    return any(token in lowered for token in _SENSORS_UTILISATION)


def _sensors_source(excerpt, keys_by_path):
    """The sensor key an excerpt's DataSourceUri names, else the URI as served, else None."""
    uri = _text(_dig(excerpt, "DataSourceUri"))
    if uri is None:
        return None
    return keys_by_path.get(_sensors_path(uri), uri)


def _sensors_environment(metrics, keys_by_path):
    """The Chassis EnvironmentMetrics readings as served; None when the resource was not read.

    power_watts, energy_kwh, temperature_celsius and humidity_percent (each
    excerpt's Reading, None where unserved), fan_speeds_percent ({source:
    {reading, speed_rpm}}, the source being the sensor key the excerpt's
    DataSourceUri names, else its DeviceName; None when the array is unserved —
    XCC 6.10 puts RPM figures in these percent readings) and sources (the
    sensor behind each single excerpt).
    """
    if not isinstance(metrics, dict):
        return None
    environment, sources = {}, {}
    for field, leaf in _SENSORS_ENVIRONMENT:
        excerpt = metrics.get(leaf)
        environment[field] = _to_float(_dig(excerpt, "Reading"))
        sources[field] = _sensors_source(excerpt, keys_by_path)
    fans = None
    if isinstance(metrics.get("FanSpeedsPercent"), list):
        fans = {}
        for index, excerpt in enumerate(_dicts(metrics["FanSpeedsPercent"])):
            label = (
                _sensors_source(excerpt, keys_by_path)
                or _text(excerpt.get("DeviceName"))
                or "#%d" % (index,)
            )
            if label in fans:
                label = "%s#%d" % (label, index)
            fans[label] = {
                "reading": _to_float(excerpt.get("Reading")),
                "speed_rpm": _to_float(excerpt.get("SpeedRPM")),
            }
    environment["fan_speeds_percent"] = fans
    environment["sources"] = sources
    return environment


def _sensors_security(named):
    """{role: sorted keys} of the security-relevant sensors present, from (Name, key) pairs."""
    found = {role: [] for role, _pattern in _SENSORS_SECURITY}
    for name, key in named:
        for role, pattern in _SENSORS_SECURITY:
            if name is not None and pattern.fullmatch(name):
                found[role].append(key)
    return {role: sorted(keys) for role, keys in found.items()}


def _normalize_sensors(members, environment=None, metrics=None, lenovo=False):
    """(normalized, context) over the members of the Chassis Sensors collection.

    'sensor|<Name>' ('|<Id>' appended only when a Name repeats, 'sensor|<Id>'
    when the Name is null) for EVERY member whatever its state -> reading_type
    (verbatim, never a classification), physical_context, physical_sub_context,
    state, health, reading_units, thresholds (_sensors_thresholds), reading and
    asserted, every field always present. A sensor is numeric when it serves a
    non-empty ReadingUnits: its reading rides in context.readings, and only an
    ambient-class temperature (_is_ambient, in Celsius or typed Temperature)
    keeps it in its row. A discrete sensor's Reading is keyed as asserted (True
    when neither 0 nor None, False at 0, None when null) except where it is a
    measurement: a utilisation-class name (context.utilisation_readings) or a
    margin (_thermal_is_margin: context.margin_readings). ``environment`` is the
    Chassis EnvironmentMetrics, ``metrics`` the ThermalMetrics resource (None
    when not read); ``lenovo`` gates the security-sensor names, which are
    Lenovo's. Two sensors mapping to one key (a nameless sensor whose Id is
    another's Name) refuse the check rather than merge silently.
    """
    sensors = _dicts(members)
    name_counts = _name_counts(sensors)
    normalized = {}
    readings, reading_times, peaks, utilisation, margins = {}, {}, {}, {}, {}
    by_type = {}
    numeric = 0
    named, keys_by_path = [], {}
    for sensor in sensors:
        name = _text(sensor.get("Name"))
        key = _sensor_key("sensor", name, _member_id(sensor) or "?", name_counts)
        if key in normalized:
            raise CollectError(
                "bmc_sensors: two sensors map to the key %s (e.g. a nameless sensor whose Id is "
                "another's Name) — refused rather than merged into one row" % (key,)
            )
        named.append((name, key))
        link = _sensors_path(sensor.get("@odata.id"))
        if link:
            keys_by_path[link] = key
        health, state = _status(sensor)
        reading_type = _text(sensor.get("ReadingType"))
        units = _text(sensor.get("ReadingUnits"))
        reading = _to_float(sensor.get("Reading"))
        by_type[reading_type or "none"] = by_type.get(reading_type or "none", 0) + 1
        row = {
            "reading_type": reading_type,
            "physical_context": _text(sensor.get("PhysicalContext")),
            "physical_sub_context": _text(sensor.get("PhysicalSubContext")),
            "state": state,
            "health": health,
            "reading_units": units,
            "thresholds": _sensors_thresholds(sensor),
            "reading": None,
            "asserted": None,
        }
        if units is not None:
            numeric += 1
            readings[key] = reading
            celsius = units in _SENSORS_CELSIUS or reading_type == "Temperature"
            if celsius and _is_ambient(name):
                row["reading"] = reading
        elif _sensors_is_utilisation(name):
            utilisation[key] = reading
        elif _thermal_is_margin(name, reading):
            margins[key] = reading
        elif reading is not None:
            row["asserted"] = reading != 0
        reading_time = _text(sensor.get("ReadingTime"))
        if reading_time is not None:
            reading_times[key] = reading_time
        peak = _to_float(sensor.get("PeakReading"))
        if peak is not None:
            peaks[key] = peak
        normalized[key] = row
    context = {
        "counts": {
            "total": len(sensors),
            "numeric": numeric,
            "discrete": len(sensors) - numeric,
            "by_reading_type": dict(sorted(by_type.items())),
        },
        "readings": readings,
        "reading_times": reading_times,
        "peak_readings": peaks,
        "utilisation_readings": utilisation,
        "margin_readings": margins,
        "security_sensors": _sensors_security(named) if lenovo else None,
        "environment": _sensors_environment(environment, keys_by_path),
        "temperature_summary_c": _thermal_summary(metrics),
    }
    return normalized, context


def _sensors_require_whole(raw, meta, path):
    """Refuse a Sensors answer that is not the whole collection: one page of it, or short.

    ``raw`` and ``meta`` are _fetch_collection's; the payload that listed the
    members is the $expand answer or the plain collection, whichever answered.
    """
    listing = raw.get(path + _EXPAND) if meta["strategy"] == "expand" else raw.get(path)
    if not isinstance(listing, dict):
        return
    if _text(listing.get("Members@odata.nextLink")):
        raise CollectError(
            "%s answered one page of the collection (Members@odata.nextLink) — the sensor view "
            "would be partial; refused, never recorded partially" % (path,)
        )
    count = listing.get("Members@odata.count")
    listed = meta["members_total"]
    if isinstance(count, int) and not isinstance(count, bool) and count > listed:
        raise CollectError(
            "%s counts %d members but listed %d — refused, never recorded partially"
            % (path, count, listed)
        )


def _collect_sensors(ctx):
    raw = {}
    environment = metrics = metrics_path = None
    with ctx.budget("bmc_sensors", _BUDGET_SENSORS) as budget:
        targets = _targets(ctx)
        system = _get(ctx, targets["system"])
        chassis = _get(ctx, targets["chassis"])
        if not isinstance(chassis, dict) or not chassis:
            raise CollectError("%s answered without a resource body" % (targets["chassis"],))
        # The two single reads first: the member walk below, pre-checked against
        # what is left before its first GET, is then the last thing spent.
        environment_path = _fenced_link(
            _dig(chassis, "EnvironmentMetrics"), "bmc_sensors EnvironmentMetrics"
        )
        if environment_path is not None:
            environment = _get_optional(ctx, environment_path)
        subsystem_link = _fenced_link(
            _dig(chassis, "ThermalSubsystem"), "bmc_sensors ThermalSubsystem"
        )
        if subsystem_link is not None:
            # The DMTF-mandated child of the linked subsystem, spelled as bmc_thermal
            # reads it: one cached answer serves both checks.
            metrics_path = _sub(subsystem_link, "ThermalMetrics")
            metrics = _get_optional(ctx, metrics_path)
        sensors_link = _fenced_link(_dig(chassis, "Sensors"), "bmc_sensors Sensors")
        path = sensors_link or _sub(targets["chassis"], "Sensors")
        members, meta, sensors_raw = _fetch_collection(
            ctx, path, "bmc_sensors", ok_404=True, budget=budget
        )
    host_power_state = _text(_dig(system, "PowerState"))
    if members is None:
        if sensors_link is not None:
            raise CollectError("the Chassis links %s but it answered 404" % (path,))
        raise SkipCheck("%s is not served and the Chassis links no Sensors collection" % (path,))
    _sensors_require_whole(sensors_raw, meta, path)
    if not members:
        raise CollectError(
            "%s answered with zero members (host PowerState %s) — a chassis always carries "
            "sensors, so an empty collection is unmeasured (a BMC still enumerating them after "
            "its own restart), never 'every sensor gone'; capture again" % (path, host_power_state)
        )
    lenovo = _is_lenovo(targets)
    normalized, context = _normalize_sensors(members, environment, metrics, lenovo=lenovo)
    context.update(
        {
            "host_power_state": host_power_state,
            "sensors_source": path,
            "sensors_collection": meta,
            "environment_source": environment_path if environment is not None else None,
            "temperature_summary_source": metrics_path if metrics is not None else None,
            "security_sensors_note": None
            if lenovo
            else "no %s mapping for the security-relevant sensor names yet (only Lenovo is mapped)"
            % (targets["vendor"] or "unknown-vendor",),
        }
    )
    raw.update(sensors_raw)
    if environment is not None:
        raw[environment_path] = _curate(environment)
    if metrics is not None:
        raw[metrics_path] = _curate(metrics)
    return {"raw": raw, "normalized": normalized, "context": _with_resolution(context, targets)}


# --- bmc_boot ----------------------------------------------------------------
# What the host boots from next, as the BMC holds it: the System's DMTF Boot
# block (the cached System read), its Boot.BootOptions collection where the
# System links one (XCC 6.10 links none), Lenovo's UEFI boot manager (System
# Oem.Lenovo.BootSettings: the boot order and its per-class sub-orders, the only
# place XCC 6.10 serves the order), the virtual media slots the BMC presents to
# the host (the System's VirtualMedia collection; the Manager's only where the
# System links none — on the lab unit both list the same two RDOC slots, so one
# is read) and the images Lenovo's remote-control service holds (Manager
# Oem.Lenovo.RemoteControl and its MountImages collection).
#
# GETs, the lab SE350 with $expand honoured: the Manager (the read bmc_system
# makes, cached for the family), BootSettings, VirtualMedia, RemoteControl and
# MountImages, one each — 5 beyond the id resolution. The per-member fallback,
# $expand advertised but refused (the attempt is paid once, on BootSettings,
# and never asked again): the Manager 1, BootSettings 1 + 1 + 5, VirtualMedia
# 1 + 2, RemoteControl 1, MountImages 1 (empty) — 13 beyond a full five-GET
# resolution, 18 in all. _BUDGET_BOOT = 30 + _TARGET_GETS leaves 17 for a
# Boot.BootOptions collection walked the same way (the collection and 16
# options) on firmware that links one: it is read last, and every walk is
# pre-checked against what is left of the budget (_fetch_collection), so a
# bigger one is refused with its member count, never recorded partially.
_BUDGET_BOOT = 30 + _TARGET_GETS


def _boot_list(value):
    """A served list kept in the firmware's order (the order is the fact); None when unserved."""
    return list(value) if isinstance(value, list) else None


def _boot_sorted(value):
    """A served list's strings sorted (their order is not state); None when not a list."""
    if not isinstance(value, list):
        return None
    return sorted(text for text in (_text(item) for item in value) if text is not None)


def _boot_scalars(boot):
    """The DMTF Boot block's scalars, every one present (None when the leaf is not served).

    The override trio repeats bmc_system's keys of the same names for one
    release; uefi_target is the device path a UefiTarget override boots.
    """
    boot = boot if isinstance(boot, dict) else {}
    return {
        "boot_order": _boot_list(boot.get("BootOrder")),
        "alias_boot_order": _boot_list(boot.get("AliasBootOrder")),
        "boot_order_property_selection": _text(boot.get("BootOrderPropertySelection")),
        # Strings, never booleans: Disabled | Once | Continuous.
        "boot_override": _text(boot.get("BootSourceOverrideEnabled")),
        "boot_override_target": _text(boot.get("BootSourceOverrideTarget")),
        "boot_override_mode": _text(boot.get("BootSourceOverrideMode")),
        "uefi_target": _text(boot.get("UefiTargetBootSourceOverride")),
        "boot_next": _text(boot.get("BootNext")),
        "automatic_retry_config": _text(boot.get("AutomaticRetryConfig")),
        "automatic_retry_attempts": _to_int(boot.get("AutomaticRetryAttempts")),
        "stop_boot_on_fault": _text(boot.get("StopBootOnFault")),
        "trusted_module_required_to_boot": _text(boot.get("TrustedModuleRequiredToBoot")),
        # Its userinfo is scrubbed by the family redactor before anything sees it.
        "http_boot_uri": _text(boot.get("HttpBootUri")),
    }


def _boot_option_rows(options):
    """'option|<BootOptionReference>' rows; '|<Id>' appended when a reference repeats.

    A member serving no reference is keyed 'option|<Id>'. ``enabled`` is the
    option's own BootOptionEnabled, None where it is not served.
    """
    options = _dicts(options)
    counts = {}
    for option in options:
        reference = _text(option.get("BootOptionReference"))
        if reference is not None:
            counts[reference] = counts.get(reference, 0) + 1
    rows = {}
    for option in options:
        reference = _text(option.get("BootOptionReference"))
        key = _sensor_key("option", reference, _member_id(option) or "?", counts)
        rows[key] = {
            "display_name": _text(option.get("DisplayName")),
            "enabled": _to_bool(option.get("BootOptionEnabled")),
            "uefi_device_path": _text(option.get("UefiDevicePath")),
            "alias": _text(option.get("Alias")),
        }
    return rows


def _boot_order_rows(orders):
    """('order|<Id>' rows, {Id: BootOrderSupported}) of Lenovo's boot-manager members.

    current (BootOrderCurrent) and next (BootOrderNext) are kept in the
    firmware's order: a reorder is a change. An empty sub-order (no CD/DVD or
    USB boot device) is [] and real; a list the member does not serve is None.
    """
    rows, supported = {}, {}
    for member in _dicts(orders):
        member_id = _member_id(member) or "?"
        rows["order|%s" % (member_id,)] = {
            "current": _boot_list(member.get("BootOrderCurrent")),
            "next": _boot_list(member.get("BootOrderNext")),
        }
        supported[member_id] = _boot_list(member.get("BootOrderSupported"))
    return rows, supported


def _boot_manager_empty(orders):
    """True when no boot-manager member lists a single entry (current, next or supported)."""
    for member in _dicts(orders):
        for leaf in ("BootOrderCurrent", "BootOrderNext", "BootOrderSupported"):
            if _boot_list(member.get(leaf)):
                return False
    return True


def _boot_media_rows(media):
    """'vmedia|<Id>' rows: what each virtual media slot presents to the host."""
    rows = {}
    for slot in _dicts(media):
        rows["vmedia|%s" % (_member_id(slot) or "?",)] = {
            "inserted": _to_bool(slot.get("Inserted")),
            "image": _text(slot.get("Image")),
            "image_name": _text(slot.get("ImageName")),
            "media_types": _boot_sorted(slot.get("MediaTypes")),
            "connected_via": _text(slot.get("ConnectedVia")),
            "write_protected": _to_bool(slot.get("WriteProtected")),
            "transfer_protocol_type": _text(slot.get("TransferProtocolType")),
            "transfer_method": _text(slot.get("TransferMethod")),
            "verify_certificate": _to_bool(slot.get("VerifyCertificate")),
        }
    return rows


def _boot_mount_rows(mounts):
    """('mount|<Id>' rows, {Id: Size}) of the images Lenovo's remote-control service holds.

    Lenovo's schemas give a remote-control mount image (LenovoRemoteMountMedia)
    Size and Readonly, and a remote-map image (LenovoRemoteMapMedia) FilePath,
    Mounted and Readonly: each field reads its own leaf and is None where the
    member serves none (no populated member has been observed). Size rides in
    context: whether it is final while an upload runs is unobserved.
    """
    rows, sizes = {}, {}
    for image in _dicts(mounts):
        image_id = _member_id(image) or "?"
        rows["mount|%s" % (image_id,)] = {
            "name": _text(image.get("Name")),
            "path": _text(image.get("FilePath")),
            "mounted": _to_bool(image.get("Mounted")),
            "readonly": _to_bool(image.get("Readonly")),
        }
        sizes[image_id] = _to_int(image.get("Size"))
    return rows, sizes


def _normalize_boot(system, options=None, orders=None, media=None, mounts=None):
    """(normalized, context) of the host's boot path.

    ``system`` is the ComputerSystem (its Boot block); ``options`` the
    Boot.BootOptions members, ``orders`` the Lenovo boot-manager members,
    ``media`` the VirtualMedia members and ``mounts`` the Lenovo
    remote-control mount images — each None when not read. Every scalar is
    always present; every row carries every field (None when unserved).
    """
    system = system if isinstance(system, dict) else {}
    boot = system.get("Boot") if isinstance(system.get("Boot"), dict) else {}
    normalized = _boot_scalars(boot)
    normalized.update(_boot_option_rows(options))
    order_rows, supported = _boot_order_rows(orders)
    normalized.update(order_rows)
    normalized.update(_boot_media_rows(media))
    mount_rows, sizes = _boot_mount_rows(mounts)
    normalized.update(mount_rows)
    context = {
        "host_power_state": _text(system.get("PowerState")),
        # Counts down on its own as failed boots are retried.
        "remaining_automatic_retry_attempts": _to_int(boot.get("RemainingAutomaticRetryAttempts")),
        # Every device the UEFI could boot: moves as devices come and go.
        "boot_order_supported": supported if orders is not None else None,
        "override_targets_allowable": _boot_list(
            boot.get("BootSourceOverrideTarget@Redfish.AllowableValues")
        ),
        "mount_image_sizes": sizes if mounts is not None else None,
    }
    return normalized, context


def _boot_collection(ctx, link, label, budget, try_expand):
    """(members, meta, raw) of a collection the service links: a 404 there is a failed read."""
    members, meta, raw = _fetch_collection(
        ctx, link, label, ok_404=True, budget=budget, try_expand=try_expand
    )
    if members is None:
        raise CollectError("%s: %s is linked but answered 404" % (label, link))
    return members, meta, raw


def _boot_unmeasured(what, link, detail, power_state):
    """The refusal for a host-UEFI family with nothing to key: it is populated at POST."""
    return CollectError(
        "bmc_boot: %s (%s) %s (host PowerState %s) — the host UEFI populates it at POST, so "
        "the read is unmeasured, never 'no boot entry'; capture again after the host "
        "completes POST" % (what, link, detail, power_state)
    )


def _boot_source(link, meta=None, members=None, note=None):
    """How one source was read, for context: its resource, strategy and member count."""
    if meta is None:
        return {"resource": link, "strategy": None, "members": None, "note": note}
    return dict(meta, resource=link, members=len(members), note=note)


def _collect_boot(ctx):
    raw = {}
    options = orders = media = mounts = remote_control = None
    try_expand = True  # turned off at the first refusal: a firmware pays for it once
    with ctx.budget("bmc_boot", _BUDGET_BOOT) as budget:
        targets = _targets(ctx)
        lenovo = _is_lenovo(targets)
        vendor = targets["vendor"] or "unknown-vendor"
        system = _get(ctx, targets["system"])
        power_state = _text(system.get("PowerState"))
        options_link = _fenced_link(_dig(system, "Boot", "BootOptions"), "bmc_boot BootOptions")
        media_link = _fenced_link(system.get("VirtualMedia"), "bmc_boot VirtualMedia")
        media_owner = "System" if media_link is not None else None
        manager = None
        if lenovo or media_link is None:
            manager = _get(ctx, targets["manager"])
        if media_link is None:
            # Before ComputerSystem v1_13 the slots hang off the Manager only.
            media_link = _fenced_link(_dig(manager, "VirtualMedia"), "bmc_boot VirtualMedia")
            media_owner = "Manager" if media_link is not None else None
        # The host UEFI's boot manager (Lenovo): populated at POST.
        settings_link = None
        if lenovo:
            settings_link = _fenced_link(
                _dig(system, "Oem", "Lenovo", "BootSettings"), "bmc_boot BootSettings"
            )
            settings = _boot_source(None, note="the System links no Oem.Lenovo.BootSettings")
        else:
            settings = _boot_source(None, note="no %s mapping for the boot manager yet" % (vendor,))
        if settings_link is not None:
            orders, meta, part = _boot_collection(
                ctx, settings_link, "bmc_boot BootSettings", budget, try_expand
            )
            raw.update(part)
            try_expand = try_expand and not meta.get("expand_refused")
            settings = _boot_source(settings_link, meta, orders)
            if not orders:
                raise _boot_unmeasured(
                    "the boot manager", settings_link, "answered with zero members", power_state
                )
            if _boot_manager_empty(orders):
                raise _boot_unmeasured(
                    "the boot manager",
                    settings_link,
                    "lists no boot entry in any of its %d members" % (len(orders),),
                    power_state,
                )
        # The BMC's own virtual media slots: an empty collection is an empty view.
        if media_link is not None:
            media, meta, part = _boot_collection(
                ctx, media_link, "bmc_boot VirtualMedia", budget, try_expand
            )
            raw.update(part)
            try_expand = try_expand and not meta.get("expand_refused")
            virtual_media = dict(_boot_source(media_link, meta, media), owner=media_owner)
        else:
            virtual_media = dict(
                _boot_source(None, note="neither the System nor the Manager links VirtualMedia"),
                owner=None,
            )
        # Images the Lenovo remote-control service holds (its sessions are never read).
        rc_link = mounts_link = None
        if lenovo:
            rc_link = _fenced_link(
                _dig(manager, "Oem", "Lenovo", "RemoteControl"), "bmc_boot RemoteControl"
            )
            mount_images = _boot_source(None, note="the Manager links no Oem.Lenovo.RemoteControl")
        else:
            mount_images = _boot_source(
                None, note="no %s mapping for the remote-control images yet" % (vendor,)
            )
        if rc_link is not None:
            remote_control = _get_optional(ctx, rc_link)
            if remote_control is None:
                raise CollectError(
                    "bmc_boot RemoteControl: %s is linked but answered 404" % (rc_link,)
                )
            raw[rc_link] = _curate(remote_control)
            mounts_link = _fenced_link(_dig(remote_control, "MountImages"), "bmc_boot MountImages")
            mount_images = _boot_source(None, note="RemoteControl links no MountImages")
        if mounts_link is not None:
            mounts, meta, part = _boot_collection(
                ctx, mounts_link, "bmc_boot MountImages", budget, try_expand
            )
            raw.update(part)
            try_expand = try_expand and not meta.get("expand_refused")
            mount_images = _boot_source(mounts_link, meta, mounts)
        # The UEFI's boot options (DMTF): populated at POST, sized by the host's
        # devices — the one open-ended walk, read last against what is left.
        if options_link is not None:
            options, meta, part = _boot_collection(
                ctx, options_link, "bmc_boot BootOptions", budget, try_expand
            )
            raw.update(part)
            boot_options = _boot_source(options_link, meta, options)
            if not options:
                raise _boot_unmeasured(
                    "Boot.BootOptions", options_link, "answered with zero members", power_state
                )
        else:
            boot_options = _boot_source(None, note="the System's Boot block links no BootOptions")
    if not isinstance(system.get("Boot"), dict) and all(
        found is None for found in (options, orders, media, mounts)
    ):
        raise SkipCheck(
            "%s serves no Boot block and links no boot options, boot manager or virtual media"
            % (targets["system"],)
        )
    raw[targets["system"]] = _curate(system)
    normalized, context = _normalize_boot(system, options, orders, media, mounts)
    context.update(
        {
            "remote_control_enabled": _to_bool(_dig(remote_control, "ServiceEnabled")),
            "boot_options": boot_options,
            "boot_settings": settings,
            "virtual_media": virtual_media,
            "remote_control": {"resource": rc_link, "served": remote_control is not None},
            "mount_images": mount_images,
        }
    )
    return {"raw": raw, "normalized": normalized, "context": _with_resolution(context, targets)}


# --- bmc_power_policy --------------------------------------------------------
# GETs, the lab SE350 (Lenovo: one chassis Control, three scheduled power
# actions mirrored by three JobService jobs, four watchdogs): the System, the
# Chassis, its Power resource and the Manager are the reads bmc_system,
# bmc_chassis and bmc_power make (cached per run); beyond them one $expand GET
# each for the Controls, the ScheduledPowerActions, the Watchdogs and the Jobs
# — 7 beyond the id resolution on a cold cache. The per-member fallback,
# $expand advertised but refused or ignored (the attempt is paid once, on the
# first collection read, and never again): the Chassis, Power and the Manager
# 3, then Controls 1 + 1 + 1, ScheduledPowerActions 1 + 3, Watchdogs 1 + 4 and
# Jobs 1 + 3 — 19 beyond the id resolution. _BUDGET_POWER_POLICY = 24 +
# _TARGET_GETS leaves room for the PowerSubsystem read a firmware without the
# legacy Power resource needs and for a few more members; a walk the rest of
# the budget cannot cover is refused loudly, with the counts, before its first
# member is read.
_BUDGET_POWER_POLICY = 24 + _TARGET_GETS
# A DMTF Job's Payload is the request the job will send: its HTTP headers (an
# Authorization header among them, possibly) and its JSON body are free text
# the exact-name scrub cannot see into, so both are scrubbed whole (emptiness
# and element counts kept); the operation and the target URI stay.
_POWER_POLICY_JOB_PAYLOAD_TEXT = ("HttpHeaders", "JsonBody")


def _power_policy_scalar(value):
    """A served scalar leaf verbatim (strings stripped, '' None); None for a block or a list."""
    if isinstance(value, str):
        return _text(value)
    if isinstance(value, (dict, list)):
        return None
    return value


def _power_policy_redact_job(job):
    """One Job resource with its Payload's headers and body scrubbed whole and, in each of its
    Messages, the account names the text reveals scrubbed (the log redactor's rule)."""
    if not isinstance(job, dict):
        return job
    payload = job.get("Payload")
    if isinstance(payload, dict):
        scrubbed = dict(payload)
        for name in _POWER_POLICY_JOB_PAYLOAD_TEXT:
            if name in scrubbed:
                scrubbed[name] = _scrub_value(scrubbed[name])
        job = dict(job, Payload=scrubbed)
    if isinstance(job.get("Messages"), list):
        job = dict(job, Messages=[_redact_log_entry(message) for message in job["Messages"]])
    return job


def _power_policy_redact_jobs(node):
    """The redactor for the JobService's Jobs: _scrub_payload, then each job's payload, messages.

    Applied alike to the collection page (expanded or not) and to a member
    read on its own; idempotent, as ``ctx.get`` requires.
    """
    node = _scrub_payload(node)
    if isinstance(node, dict) and isinstance(node.get("Members"), list):
        node = dict(node, Members=[_power_policy_redact_job(member) for member in node["Members"]])
    return _power_policy_redact_job(node)


def _power_policy_first(items):
    """(MemberId, member) of the first entry of a legacy Power array; (None, {}) when empty.

    The server-level PowerControl is the first member on every firmware seen
    (the lab SE350 serves 'Server Power Control', then the CPU and memory
    sub-systems); context.power_control_member names the one read.
    """
    for member in _dicts(items):
        return _text(member.get("MemberId")) or _text(member.get("Id")), member
    return None, {}


def _power_policy_redundancy(power):
    """(MemberId, Lenovo block) of the first Power Redundancy group carrying one; (None, None).

    Lenovo's LenovoRedundancy block (NonRedundantAvailablePower,
    PowerRedundancySettings) is the Oem block of a legacy Power.Redundancy[]
    group; an SE350 publishes no redundancy group at all.
    """
    for group in _dicts(_dig(power, "Redundancy")):
        block = _dig(group, "Oem", "Lenovo")
        if isinstance(block, dict):
            return _text(group.get("MemberId")) or _text(group.get("Id")), block
    return None, None


def _power_policy_capabilities(power, power_subsystem):
    """(block, source) of Lenovo's power capability leaves; (None, None) when neither serves one.

    The Power resource's Oem.Lenovo block (typed LenovoPower Capabilities),
    else the PowerSubsystem's, which XCC 6.10 also serves with the same three
    flags and which is read only where no legacy Power resource is served.
    """
    for label, resource in (("Power", power), ("PowerSubsystem", power_subsystem)):
        block = _dig(resource, "Oem", "Lenovo")
        if isinstance(block, dict):
            return block, "%s Oem.Lenovo" % (label,)
    return None, None


def _power_policy_control_row(control):
    """One 'control|<Id>' row (DMTF Control): what it governs, its mode, set point and limits."""
    health, state = _status(control)
    return {
        "control_type": _text(control.get("ControlType")),
        "control_mode": _text(control.get("ControlMode")),
        "set_point": _to_float(control.get("SetPoint")),
        "set_point_units": _text(control.get("SetPointUnits")),
        "set_point_type": _text(control.get("SetPointType")),
        # the bounds a Range control holds its reading between (SetPoint is a Single's)
        "setting_min": _to_float(control.get("SettingMin")),
        "setting_max": _to_float(control.get("SettingMax")),
        "allowable_min": _to_float(control.get("AllowableMin")),
        "allowable_max": _to_float(control.get("AllowableMax")),
        "implementation": _text(control.get("Implementation")),
        "physical_context": _text(control.get("PhysicalContext")),
        "health": health,
        "state": state,
    }


def _power_policy_control_reading(control):
    """What moves on a control (context only): its sensor's reading and source, set-point time."""
    return {
        "reading": _to_float(_dig(control, "Sensor", "Reading")),
        "data_source": _text(_dig(control, "Sensor", "DataSourceUri")),
        "set_point_update_time": _text(control.get("SetPointUpdateTime")),
    }


def _power_policy_sched_row(action):
    """One 'sched|<Id>' row (Lenovo ScheduledPowerAction): type, activated, interval, time."""
    return {
        "type": _text(action.get("Type")),
        "activated": _to_bool(action.get("Activated")),
        "interval": _text(action.get("Interval")),
        # the time of day the action fires, as configured — never a clock reading
        "time": _text(action.get("Time")),
    }


def _power_policy_watchdog_row(watchdog):
    """One 'watchdog|<Id>' row (Lenovo Watchdog): type, state and its two timer settings."""
    return {
        "type": _text(watchdog.get("Type")),
        "state": _text(watchdog.get("State")),
        "timer_s": _to_int(watchdog.get("TimerValueInSec")),
        "timeout_interval_s": _to_int(watchdog.get("TimeoutIntervalInSec")),
    }


def _power_policy_list(value):
    """A served list of scalars in served order (strings stripped); None when not a list."""
    if not isinstance(value, list):
        return None
    return [_power_policy_scalar(item) for item in value]


def _power_policy_job(job):
    """A JobService job for context: name, JobState, JobStatus and its DMTF Schedule."""
    schedule = job.get("Schedule")
    if isinstance(schedule, dict):
        schedule = {
            "name": _text(schedule.get("Name")),
            "initial_start_time": _text(schedule.get("InitialStartTime")),
            "recurrence_interval": _text(schedule.get("RecurrenceInterval")),
            "enabled_days_of_week": _power_policy_list(schedule.get("EnabledDaysOfWeek")),
            "enabled_days_of_month": _power_policy_list(schedule.get("EnabledDaysOfMonth")),
            "enabled_months_of_year": _power_policy_list(schedule.get("EnabledMonthsOfYear")),
            "enabled_intervals": _power_policy_list(schedule.get("EnabledIntervals")),
            "lifetime": _text(schedule.get("Lifetime")),
            "max_occurrences": _to_int(schedule.get("MaxOccurrences")),
        }
    else:
        schedule = None
    return {
        "name": _text(job.get("Name")),
        "state": _text(job.get("JobState")),
        "status": _text(job.get("JobStatus")),
        "schedule": schedule,
    }


def _normalize_power_policy(
    system,
    power=None,
    *,
    controls=None,
    scheduled=None,
    watchdogs=None,
    lenovo=False,
    power_subsystem=None,
):
    """(normalized, context): the host's power policy scalars and its control/sched/watchdog rows.

    ``system`` is the ComputerSystem, ``power`` the legacy Chassis Power
    resource (None where not served) and ``power_subsystem`` the
    PowerSubsystem, read in its place for Lenovo's flags only; ``controls``,
    ``scheduled`` and ``watchdogs`` are the members of the Chassis Controls,
    Lenovo ScheduledPowerActions and Lenovo Watchdogs collections (None when
    not read). Every scalar is always present — None when unserved, never ''
    — and the Lenovo ones are read only when ``lenovo`` says the service is
    Lenovo's; every row carries every field. The cap comes from the first
    PowerControl member. Readings, set-point times, expired flags and the
    redundancy group's estimated usage go to context, never into a key.
    """
    system = system if isinstance(system, dict) else {}
    watchdog = _dig(system, "HostWatchdogTimer")
    control_member, control = _power_policy_first(_dig(power, "PowerControl"))
    limit = _dig(control, "PowerLimit")
    capabilities = source = utilization = redundancy = redundancy_member = None
    if lenovo:
        capabilities, source = _power_policy_capabilities(power, power_subsystem)
        utilization = _dig(control, "Oem", "Lenovo", "PowerUtilization")
        redundancy_member, redundancy = _power_policy_redundancy(power)
    settings = _dig(redundancy, "PowerRedundancySettings")
    normalized = {
        # what the host does when AC returns: DMTF, then Lenovo's own leaf
        "power_restore_policy": _text(system.get("PowerRestorePolicy")),
        "lenovo_power_restore_policy": _text(_dig(capabilities, "PowerRestorePolicy")),
        "wake_on_lan": _to_bool(_dig(capabilities, "WakeOnLANEnabled")),
        "power_on_permission": _to_bool(_dig(capabilities, "PowerOnPermissionEnabled")),
        "local_power_control": _to_bool(_dig(capabilities, "LocalPowerControlEnabled")),
        "random_delay": _power_policy_scalar(_dig(capabilities, "RandomDelay")),
        # the DMTF host watchdog (the leaves bmc_system reads too)
        "host_watchdog_enabled": _to_bool(_dig(watchdog, "FunctionEnabled")),
        "host_watchdog_timeout_action": _text(_dig(watchdog, "TimeoutAction")),
        "host_watchdog_warning_action": _text(_dig(watchdog, "WarningAction")),
        # the power cap: DMTF PowerLimit, then Lenovo's PowerUtilization
        "power_limit_w": _to_float(_dig(limit, "LimitInWatts")),
        "power_limit_exception": _text(_dig(limit, "LimitException")),
        "power_limit_correction_ms": _to_int(_dig(limit, "CorrectionInMs")),
        "power_capping_enabled": _to_bool(_dig(utilization, "EnablePowerCapping")),
        "limit_mode": _text(_dig(utilization, "LimitMode")),
        "guaranteed_w": _to_float(_dig(utilization, "GuaranteedInWatts")),
        "capping_min_w": _to_float(_dig(utilization, "MinLimitInWatts")),
        "capping_max_w": _to_float(_dig(utilization, "MaxLimitInWatts")),
        # Lenovo's power-supply redundancy settings
        "power_redundancy_policy": _text(_dig(settings, "PowerRedundancyPolicy")),
        "max_power_limit_w": _to_float(_dig(settings, "MaxPowerLimitWatts")),
        "power_failure_limit": _power_policy_scalar(_dig(settings, "PowerFailureLimit")),
    }
    context = {
        "power_control_member": control_member,
        "lenovo_capabilities_source": source,
        "redundancy_member": redundancy_member,
        "non_redundant_available_power_w": _to_float(
            _dig(redundancy, "NonRedundantAvailablePower")
        ),
        "redundancy_estimated_usage": _power_policy_scalar(_dig(settings, "EstimatedUsage")),
        "control_readings": {},
        "watchdog_expired": {},
    }
    rows = {}
    for member in _dicts(controls):
        key = "control|%s" % (_member_id(member) or "?",)
        rows[key] = _power_policy_control_row(member)
        context["control_readings"][key] = _power_policy_control_reading(member)
    for action in _dicts(scheduled):
        rows["sched|%s" % (_member_id(action) or "?",)] = _power_policy_sched_row(action)
    for member in _dicts(watchdogs):
        key = "watchdog|%s" % (_member_id(member) or "?",)
        rows[key] = _power_policy_watchdog_row(member)
        # sticky once the watchdog fired, cleared by whoever re-arms it: context
        context["watchdog_expired"][key] = _to_bool(member.get("TimerExpired"))
    for key in sorted(rows):
        normalized[key] = rows[key]
    return normalized, context


def _power_policy_collection(
    ctx, link, family, budget, try_expand, redact=_scrub_payload, required=True
):
    """(members, report, raw, try_expand) of one collection this check reads.

    ``link`` None (nothing links it, or the vendor has no mapping) reads
    nothing: members None. A collection its parent links that answers 404
    fails the check (``required``: a broken tree, never "none configured");
    one that answers empty is an empty family — all four are the BMC's own
    services and settings, not host inventory (whether the chassis Controls
    enumerate with the host off is unverified; context.host_power_state rides
    beside them). ``try_expand`` turns off at the first $expand refusal and
    stays off for the rest of the check.
    """
    report = {"resource": link, "strategy": None, "members": None, "expand_refused": None}
    if link is None:
        return None, report, {}, try_expand
    members, meta, raw = _fetch_collection(
        ctx,
        link,
        "bmc_power_policy %s" % (family,),
        ok_404=True,
        budget=budget,
        redact=redact,
        try_expand=try_expand,
    )
    if meta.get("expand_refused"):
        try_expand = False
    if members is None and required:
        raise CollectError("bmc_power_policy: %s is linked but answered 404" % (link,))
    report.update(
        strategy=meta["strategy"],
        members=len(members) if members is not None else None,
        expand_refused=meta.get("expand_refused"),
    )
    return members, report, raw, try_expand


def _collect_power_policy(ctx):
    raw = {}
    members = {}
    reports = {}
    power_subsystem = subsystem_link = None
    try_expand = True
    with ctx.budget("bmc_power_policy", _BUDGET_POWER_POLICY) as budget:
        targets = _targets(ctx)
        lenovo = _is_lenovo(targets)
        system = _get(ctx, targets["system"])
        chassis = _get(ctx, targets["chassis"])
        if not isinstance(chassis, dict) or not chassis:
            raise CollectError("%s answered without a resource body" % (targets["chassis"],))
        # The legacy Power resource: the read bmc_power makes (same path, same redactor).
        power_link = _fenced_link(_dig(chassis, "Power"), "bmc_power_policy Power")
        power_path = power_link or _sub(targets["chassis"], "Power")
        power = _get_optional(ctx, power_path)
        if power is None and power_link is not None:
            raise CollectError("the Chassis links %s but it answered 404" % (power_path,))
        if power is not None and (not isinstance(power, dict) or not power):
            raise CollectError("%s answered without a resource body" % (power_path,))
        if lenovo and power is None:
            # No legacy resource: Lenovo's power flags from the PowerSubsystem's block.
            subsystem_link = _fenced_link(
                _dig(chassis, "PowerSubsystem"), "bmc_power_policy PowerSubsystem"
            )
            if subsystem_link is not None:
                power_subsystem = _get_optional(ctx, subsystem_link)
                if power_subsystem is None:
                    raise CollectError(
                        "%s is not served and the Chassis links %s, which answered 404"
                        % (power_path, subsystem_link)
                    )
        plan = [
            (
                "controls",
                _fenced_link(_dig(chassis, "Controls"), "bmc_power_policy Controls"),
                _scrub_payload,
                True,
            )
        ]
        if lenovo:
            # Lenovo's collections, each through the link its parent serves.
            manager = _get(ctx, targets["manager"])
            plan.append(
                (
                    "scheduled_power_actions",
                    _fenced_link(
                        _dig(system, "Oem", "Lenovo", "ScheduledPowerActions"),
                        "bmc_power_policy ScheduledPowerActions",
                    ),
                    _scrub_payload,
                    True,
                )
            )
            plan.append(
                (
                    "watchdogs",
                    _fenced_link(
                        _dig(manager, "Oem", "Lenovo", "Watchdogs"), "bmc_power_policy Watchdogs"
                    ),
                    _scrub_payload,
                    True,
                )
            )
        # The JobService (DMTF, every vendor) as the service root links it; its Jobs
        # collection is the service's mandated child path, so a 404 there is "not
        # served", never a failed read.
        job_service = _fenced_link(
            _dig(_get(ctx, _ROOT), "JobService"), "bmc_power_policy JobService"
        )
        plan.append(
            (
                "jobs",
                _sub(job_service, "Jobs") if job_service is not None else None,
                _power_policy_redact_jobs,
                False,
            )
        )
        for family, link, redact, required in plan:
            members[family], reports[family], family_raw, try_expand = _power_policy_collection(
                ctx, link, family, budget, try_expand, redact=redact, required=required
            )
            raw.update(family_raw)
    for family in ("controls", "scheduled_power_actions", "watchdogs", "jobs"):
        members.setdefault(family, None)
        reports.setdefault(
            family, {"resource": None, "strategy": None, "members": None, "expand_refused": None}
        )
    served = (
        power is not None
        or power_subsystem is not None
        or any(leaf in system for leaf in ("PowerRestorePolicy", "HostWatchdogTimer"))
        or any(found is not None for found in members.values())
    )
    if not served:
        raise SkipCheck(
            "nothing to key: the System serves no PowerRestorePolicy or HostWatchdogTimer, %s "
            "is not served, and no Controls, scheduled power actions, watchdogs or JobService "
            "jobs are read" % (power_path,)
        )
    if power is not None:
        raw[power_path] = _curate(power)
    if power_subsystem is not None:
        raw[subsystem_link] = _curate(power_subsystem)
    normalized, context = _normalize_power_policy(
        system,
        power,
        controls=members["controls"],
        scheduled=members["scheduled_power_actions"],
        watchdogs=members["watchdogs"],
        lenovo=lenovo,
        power_subsystem=power_subsystem,
    )
    jobs = members["jobs"]
    context.update(
        {
            "host_power_state": _text(_dig(system, "PowerState")),
            "power_resource": power_path if power is not None else None,
            "power_subsystem_resource": subsystem_link if power_subsystem is not None else None,
            "collections": reports,
            # Every JobService job (on XCC 6.10 the scheduled power actions' twins):
            # its state moves as it runs, so it rides here, never in a key.
            "jobs": (
                None
                if jobs is None
                else {_member_id(job) or "?": _power_policy_job(job) for job in _dicts(jobs)}
            ),
            "unmapped": (
                None
                if lenovo
                else "no %s mapping for the Lenovo power flags, capping and redundancy settings, "
                "scheduled power actions and watchdogs yet (the DMTF reads of this check are "
                "unaffected)" % (targets["vendor"] or "unknown-vendor",)
            ),
        }
    )
    return {"raw": raw, "normalized": normalized, "context": _with_resolution(context, targets)}


# --- bmc_network_adapters ----------------------------------------------------
# GETs, the lab SE350 (the X722 and I350 LOMs with two ports and two functions
# each, the slot-6 add-in NIC with none): the Chassis (the read bmc_chassis
# makes, cached in a capture), the NetworkAdapters collection with one $expand
# GET, then per adapter one $expand GET each on Ports (the keyed rows),
# NetworkPorts (the deprecated twin of the same ports, read for context) and
# NetworkDeviceFunctions — $levels=2 inlines those collections with their
# members as bare links on XCC 6.10, so each needs its own read: 1 + 1 + 3 x 3
# = 11 beyond the id resolution. The per-member fallback, $expand advertised
# but refused or ignored (the attempt is paid once, on the adapter collection,
# and never again): the Chassis 1, the adapters 1 + 1 + 3, ob-2 and ob-4 three
# collections and six members each, slot-6 three empty collections — 1 + 5 +
# 9 + 9 + 3 = 27 beyond the id resolution, 32 with its full five GETs.
# _BUDGET_NETWORK_ADAPTERS = 28 + _TARGET_GETS covers that walk with a GET to
# spare, and eight adapters linking all three collections with $expand
# honoured even when this check pays the full resolution (5 + 1 + 1 + 8 x 3 =
# 31); a bigger tree is refused before its first port or function collection
# is read (those reads are pre-checked), and a member walk the budget cannot
# cover is refused with its count, never recorded partially.
_BUDGET_NETWORK_ADAPTERS = 28 + _TARGET_GETS

# DMTF NetworkDeviceFunction.iSCSIBoot carries the iSCSI boot credentials. The
# family's exact-name list does not name them, so no row or context field reads
# that block and this check's raw scrubs them on top of _curate.
_NETWORK_ADAPTERS_CREDENTIALS = frozenset(
    name.lower()
    for name in ("CHAPUsername", "CHAPSecret", "MutualCHAPUsername", "MutualCHAPSecret")
)
# The leaves naming the port a function is assigned to, per family of port rows,
# current spelling first: NetworkDeviceFunction v1_8 moved the Port-typed
# PhysicalNetworkPortAssignment into Links; v1_5 deprecated the NetworkPort-typed
# Links.PhysicalPortAssignment, whose root form v1_3 had moved into Links. The
# other family answers only where the preferred one serves no link.
_NETWORK_ADAPTERS_PORT_LINKS = (
    ("Links", "PhysicalNetworkPortAssignment"),
    ("PhysicalNetworkPortAssignment",),
)
_NETWORK_ADAPTERS_NETWORK_PORT_LINKS = (
    ("Links", "PhysicalPortAssignment"),
    ("PhysicalPortAssignment",),
)


def _network_adapters_scrub_credentials(node):
    """A payload with the iSCSI boot CHAP user names and secrets scrubbed (emptiness kept)."""
    if isinstance(node, dict):
        return {
            key: (
                _scrub_value(value)
                if str(key).lower() in _NETWORK_ADAPTERS_CREDENTIALS
                else _network_adapters_scrub_credentials(value)
            )
            for key, value in node.items()
        }
    if isinstance(node, list):
        return [_network_adapters_scrub_credentials(item) for item in node]
    return node


def _network_adapters_number(value):
    """A served number verbatim (an int stays an int), a numeric string converted; else None."""
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return value
    return _to_float(value)


def _network_adapters_any(values):
    """True when any served boolean is true, False when every served one is false, else None."""
    served = [value for value in (_to_bool(item) for item in values) if value is not None]
    return any(served) if served else None


def _network_adapters_speeds(entries, leaf, divisor=1):
    """Sorted unique numbers of every ``entries[].<leaf>`` list, divided by ``divisor``.

    None when no entry serves the list; a served list without a number reads [].
    """
    speeds, served = set(), False
    for entry in _dicts(entries):
        values = entry.get(leaf)
        if not isinstance(values, list):
            continue
        served = True
        for value in values:
            number = _network_adapters_number(value)
            if number is not None:
                speeds.add(number / divisor if divisor != 1 else number)
    return sorted(speeds) if served else None


def _network_adapters_link_speeds_mbps(capabilities):
    """A NetworkPort's capable speeds in Mbit/s as served, sorted; None when none is served.

    SupportedLinkCapabilities[].CapableLinkSpeedMbps (a list, NetworkPort v1_2)
    and the single LinkSpeedMbps it replaced (v1_0), whichever the entries carry.
    """
    speeds = _network_adapters_speeds(capabilities, "CapableLinkSpeedMbps")
    singles = [
        _network_adapters_number(entry.get("LinkSpeedMbps")) for entry in _dicts(capabilities)
    ]
    singles = [value for value in singles if value is not None]
    if speeds is None and not singles:
        return None
    return sorted(set(speeds or []) | set(singles))


def _network_adapters_link_ids(links, label):
    """Sorted leaf ids of a served list of links (each fenced); None when the leaf is no list."""
    if not isinstance(links, list):
        return None
    ids = set()
    for item in _dicts(links):
        link = _fenced_link(item, label)
        if link is not None:
            ids.add(_leaf_id(link))
    return sorted(ids)


def _network_adapters_controller_links(controllers, name):
    """Sorted leaf ids every controller links under Links.<name>; None when none serves it."""
    ids = None
    for controller in controllers:
        found = _network_adapters_link_ids(
            _dig(controller, "Links", name), "bmc_network_adapters Controllers Links.%s" % (name,)
        )
        if found is not None:
            ids = sorted(set(ids or []) | set(found))
    return ids


def _network_adapters_capability(controllers, name):
    """ControllerCapabilities.<name> summed over the controllers; None when none serves it."""
    counts = [
        _to_int(_dig(controller, "ControllerCapabilities", name)) for controller in controllers
    ]
    counts = [count for count in counts if count is not None]
    return sum(counts) if counts else None


def _network_adapters_expects(controllers, capability, links):
    """True when the adapter's own controllers say it carries ports (or functions).

    A capability count above zero, or a non-empty controller Links array of that family.
    """
    if _network_adapters_capability(controllers, capability):
        return True
    return any(_dicts(_dig(c, "Links", name)) for c in controllers for name in links)


def _network_adapters_adapter(adapter, port_count, function_count):
    """One 'adapter|<Id>' row: identity, the first controller's firmware, counts, LLDP, health."""
    controllers = _dicts(adapter.get("Controllers"))
    first = controllers[0] if controllers else {}
    health, state = _status(adapter)
    return {
        "manufacturer": _text(adapter.get("Manufacturer")),
        "model": _text(adapter.get("Model")),
        "serial": _text(adapter.get("SerialNumber")),
        "part_number": _text(adapter.get("PartNumber")),
        "sku": _text(adapter.get("SKU")),
        "firmware_package_version": _text(first.get("FirmwarePackageVersion")),
        "location": _service_label(adapter) or _service_label(first),
        "pcie_devices": _network_adapters_controller_links(controllers, "PCIeDevices"),
        "port_count": port_count,
        "function_count": function_count,
        "controller_port_count": _network_adapters_capability(controllers, "NetworkPortCount"),
        "controller_function_count": _network_adapters_capability(
            controllers, "NetworkDeviceFunctionCount"
        ),
        "npar_enabled": _network_adapters_any(
            _dig(controller, "ControllerCapabilities", "NPAR", "NparEnabled")
            for controller in controllers
        ),
        "lldp_enabled": _to_bool(adapter.get("LLDPEnabled")),
        "health": health,
        "state": state,
    }


def _network_adapters_port(port, lenovo=False):
    """One 'port|<adapter>|<Id>' row from a Port resource (the current schema).

    LinkStatus is LinkUp | Starting | Training | LinkDown | NoLink; MaxSpeedGbps
    is the most the port is configured to negotiate and LinkConfiguration[]
    lists the speeds it is capable of and whether it autonegotiates. The port
    number is Lenovo's OEM leaf (the Port schema has none; PortId is its label).
    """
    health, state = _status(port)
    oem = _dig(port, "Oem", "Lenovo") if lenovo else None
    configurations = _dicts(port.get("LinkConfiguration"))
    ethernet = port.get("Ethernet") if isinstance(port.get("Ethernet"), dict) else {}
    return {
        "link_status": _text(port.get("LinkStatus")),
        "physical_port_number": _text(_dig(oem, "PhysicalPortNumber")),
        "port_id": _text(port.get("PortId")),
        "active_link_technology": _text(port.get("LinkNetworkTechnology")),
        "max_speed_gbps": _network_adapters_number(port.get("MaxSpeedGbps")),
        "capable_speeds_gbps": _network_adapters_speeds(configurations, "CapableLinkSpeedGbps"),
        "autoneg": _network_adapters_any(
            entry.get("AutoSpeedNegotiationEnabled") for entry in configurations
        ),
        "autoneg_capable": _network_adapters_any(
            entry.get("AutoSpeedNegotiationCapable") for entry in configurations
        ),
        "flow_control_configuration": _text(ethernet.get("FlowControlConfiguration")),
        "lldp_enabled": _to_bool(ethernet.get("LLDPEnabled")),
        "health": health,
        "state": state,
    }


def _network_adapters_network_port(port):
    """The same row from a NetworkPort (the deprecated schema), where no Ports is linked.

    LinkStatus is Up | Down | Starting | Training; the capable speeds are
    CapableLinkSpeedMbps (and the older single LinkSpeedMbps) in Gbit/s as
    served; AutoSpeedNegotiation is a capability, so ``autoneg`` (the
    configured setting), like the other Port-only leaves, reads None.
    """
    health, state = _status(port)
    capabilities = _dicts(port.get("SupportedLinkCapabilities"))
    speeds = _network_adapters_link_speeds_mbps(capabilities)
    return {
        "link_status": _text(port.get("LinkStatus")),
        "physical_port_number": _text(port.get("PhysicalPortNumber")),
        "port_id": None,
        "active_link_technology": _text(port.get("ActiveLinkTechnology")),
        "max_speed_gbps": None,
        "capable_speeds_gbps": None if speeds is None else [speed / 1000 for speed in speeds],
        "autoneg": None,
        "autoneg_capable": _network_adapters_any(
            entry.get("AutoSpeedNegotiation") for entry in capabilities
        ),
        "flow_control_configuration": _text(port.get("FlowControlConfiguration")),
        "lldp_enabled": None,
        "health": health,
        "state": state,
    }


def _network_adapters_macs(values):
    """A served list of addresses lower-cased and sorted; None when the leaf is no list."""
    if not isinstance(values, list):
        return None
    return sorted(mac for mac in (_mac(value) for value in values) if mac)


def _network_adapters_port_context(port, source, lenovo=False):
    """The readings and vendor leaves of one keyed port (context only)."""
    oem = _dig(port, "Oem", "Lenovo") if lenovo else None
    if source == "NetworkPorts":
        return {
            "current_speed_gbps": None,
            "current_link_speed_mbps": _network_adapters_number(port.get("CurrentLinkSpeedMbps")),
            "associated_macs": _network_adapters_macs(port.get("AssociatedNetworkAddresses")),
            "port_maximum_mtu": _to_int(port.get("PortMaximumMTU")),
            "port_max_speed_bps": _network_adapters_number(_dig(oem, "PortMaxSpeedbps")),
            "physical_port_mac": _text(_dig(oem, "PhysicalPortMacAddress")),
        }
    return {
        "current_speed_gbps": _network_adapters_number(port.get("CurrentSpeedGbps")),
        "current_link_speed_mbps": None,
        "associated_macs": _network_adapters_macs(_dig(port, "Ethernet", "AssociatedMACAddresses")),
        "port_maximum_mtu": _to_int(_dig(oem, "PortMaximumMTU")),
        "port_max_speed_bps": _network_adapters_number(_dig(oem, "PortMaxSpeedbps")),
        "physical_port_mac": _text(_dig(oem, "PhysicalPortMacAddress")),
    }


def _network_adapters_twin(port, lenovo=False):
    """A NetworkPort read beside a Ports collection: the same port in the older words (context)."""
    oem = _dig(port, "Oem", "Lenovo") if lenovo else None
    return {
        "link_status": _text(port.get("LinkStatus")),
        "current_link_speed_mbps": _network_adapters_number(port.get("CurrentLinkSpeedMbps")),
        "capable_link_speeds_mbps": _network_adapters_link_speeds_mbps(
            port.get("SupportedLinkCapabilities")
        ),
        "physical_port_number": _text(port.get("PhysicalPortNumber")),
        "port_maximum_mtu": _to_int(port.get("PortMaximumMTU")),
        "port_max_speed_bps": _network_adapters_number(_dig(oem, "PortMaxSpeedbps")),
        "physical_port_mac": _text(_dig(oem, "PhysicalPortMacAddress")),
    }


def _network_adapters_assigned_port(function, prefer_ports=True):
    """(port id, the leaf it was read from) of the port a function is assigned to.

    The leaves of the family the port rows came from first (Port: the
    PhysicalNetworkPortAssignment spellings; NetworkPort: PhysicalPortAssignment),
    the other family only where those serve no link; (None, None) when none does.
    """
    families = (_NETWORK_ADAPTERS_PORT_LINKS, _NETWORK_ADAPTERS_NETWORK_PORT_LINKS)
    for family in families if prefer_ports else families[::-1]:
        for path in family:
            leaf = ".".join(path)
            link = _fenced_link(_dig(function, *path), "bmc_network_adapters %s" % (leaf,))
            if link is not None:
                return _leaf_id(link), leaf
    return None, None


def _network_adapters_ethernet_interfaces(function):
    """Sorted ids of the host EthernetInterfaces a function links; None when it links none."""
    label = "bmc_network_adapters Links.EthernetInterface"
    single = _fenced_link(_dig(function, "Links", "EthernetInterface"), label)
    several = _network_adapters_link_ids(_dig(function, "Links", "EthernetInterfaces"), label)
    if single is None and several is None:
        return None
    return sorted(set(several or []) | ({_leaf_id(single)} if single is not None else set()))


def _network_adapters_function(function, prefer_ports=True):
    """(one 'netfn|<adapter>|<Id>' row, the leaf its assigned port was read from)."""
    health, state = _status(function)
    assigned, source = _network_adapters_assigned_port(function, prefer_ports)
    pcie_function = _fenced_link(
        _dig(function, "Links", "PCIeFunction"), "bmc_network_adapters Links.PCIeFunction"
    )
    row = {
        "net_dev_func_type": _text(function.get("NetDevFuncType")),
        # burned-in, lower-cased: the join to the hypervisor's physical-NIC MAC
        "permanent_mac": _mac(_dig(function, "Ethernet", "PermanentMACAddress")),
        "device_enabled": _to_bool(function.get("DeviceEnabled")),
        "boot_mode": _text(function.get("BootMode")),
        "virtual_functions_enabled": _to_bool(function.get("VirtualFunctionsEnabled")),
        "max_virtual_functions": _to_int(function.get("MaxVirtualFunctions")),
        "assigned_port": assigned,
        "ethernet_interfaces": _network_adapters_ethernet_interfaces(function),
        "pcie_function": _leaf_id(pcie_function) if pcie_function is not None else None,
        "health": health,
        "state": state,
    }
    return row, source


def _normalize_network_adapters(adapters, ports=None, functions=None, twins=None, lenovo=False):
    """(normalized, context) over the adapters and the port and function collections read.

    ``ports`` maps an adapter id to (the collection its port rows came from —
    "Ports" or "NetworkPorts" — and that collection's members, None when it
    answered 404); ``functions`` maps an adapter id to its NetworkDeviceFunctions
    members and ``twins`` to the NetworkPorts members read beside a Ports
    collection. An adapter missing from a map links no such collection: its
    count reads None. Keys: 'adapter|<Id>', 'port|<adapter Id>|<port Id>' and
    'netfn|<adapter Id>|<function Id>', every row carrying every field (None
    where not served). ``lenovo`` gates the Oem.Lenovo port leaves.
    """
    ports, functions, twins = ports or {}, functions or {}, twins or {}
    normalized = {}
    context = {
        "adapters_without_ports": [],
        "adapters_without_functions": [],
        "ports": {},
        "network_ports": {},
        "functions": {},
    }
    for adapter in _dicts(adapters):
        adapter_id = _member_id(adapter) or "?"
        source, port_members = ports.get(adapter_id, (None, None))
        function_members = functions.get(adapter_id)
        port_rows, function_rows = _dicts(port_members), _dicts(function_members)
        normalized["adapter|%s" % (adapter_id,)] = _network_adapters_adapter(
            adapter,
            len(port_rows) if port_members is not None else None,
            len(function_rows) if function_members is not None else None,
        )
        if not port_rows:
            context["adapters_without_ports"].append(adapter_id)
        if not function_rows:
            context["adapters_without_functions"].append(adapter_id)
        for port in port_rows:
            key = "port|%s|%s" % (adapter_id, _member_id(port) or "?")
            if source == "NetworkPorts":
                normalized[key] = _network_adapters_network_port(port)
            else:
                normalized[key] = _network_adapters_port(port, lenovo)
            context["ports"][key] = _network_adapters_port_context(port, source, lenovo)
        for port in _dicts(twins.get(adapter_id)):
            twin_key = "%s|%s" % (adapter_id, _member_id(port) or "?")
            context["network_ports"][twin_key] = _network_adapters_twin(port, lenovo)
        for function in function_rows:
            key = "netfn|%s|%s" % (adapter_id, _member_id(function) or "?")
            row, assigned_source = _network_adapters_function(function, source != "NetworkPorts")
            normalized[key] = row
            context["functions"][key] = {
                # the current MAC and MTU can follow the host's configuration: context only
                "mac": _mac(_dig(function, "Ethernet", "MACAddress")),
                "mtu": _to_int(_dig(function, "Ethernet", "MTUSize")),
                "assigned_port_source": assigned_source,
            }
    context["adapters_without_ports"].sort()
    context["adapters_without_functions"].sort()
    return normalized, context


def _network_adapters_plan(adapter):
    """(adapter id, [(role, fenced link)]) of the collections one adapter links, in read order.

    Roles: "Ports" (the keyed rows), else "NetworkPorts" where no Ports is
    linked; "twin" (a NetworkPorts collection beside a linked Ports, read for
    context); "functions" (NetworkDeviceFunctions).
    """
    adapter_id = _member_id(adapter) or "?"
    label = "bmc_network_adapters %s" % (adapter_id,)
    ports = _fenced_link(adapter.get("Ports"), label + " Ports")
    network_ports = _fenced_link(adapter.get("NetworkPorts"), label + " NetworkPorts")
    functions = _fenced_link(
        adapter.get("NetworkDeviceFunctions"), label + " NetworkDeviceFunctions"
    )
    reads = []
    if ports is not None:
        reads.append(("Ports", ports))
        if network_ports is not None:
            reads.append(("twin", network_ports))
    elif network_ports is not None:
        reads.append(("NetworkPorts", network_ports))
    if functions is not None:
        reads.append(("functions", functions))
    return adapter_id, reads


def _network_adapters_unmeasured(adapters, ports, functions, twins=None):
    """The adapters whose port or function rows cannot be recorded, each with the reason.

    A port or function collection the rows come from that answered 404, or one
    that answered empty while the adapter says otherwise: its own controllers
    declare ports or functions, or its NetworkPorts twin lists ports. (An adapter
    the BMC has no sideband to declares none, lists none and is recorded with
    zero rows; the twin itself is context, so its 404 is recorded, never fatal.)
    """
    twins = twins or {}
    found = []
    for adapter in _dicts(adapters):
        adapter_id = _member_id(adapter) or "?"
        controllers = _dicts(adapter.get("Controllers"))
        if adapter_id in ports:
            source, members = ports[adapter_id]
            if members is None:
                found.append("%s (%s answered 404)" % (adapter_id, source))
            elif not members and _network_adapters_expects(
                controllers, "NetworkPortCount", ("Ports", "NetworkPorts")
            ):
                found.append("%s (%s empty, its controllers declare ports)" % (adapter_id, source))
            elif not members and _dicts(twins.get(adapter_id)):
                found.append(
                    "%s (%s empty while its NetworkPorts list %d)"
                    % (adapter_id, source, len(_dicts(twins[adapter_id])))
                )
        if adapter_id in functions:
            members = functions[adapter_id]
            if members is None:
                found.append("%s (NetworkDeviceFunctions answered 404)" % (adapter_id,))
            elif not members and _network_adapters_expects(
                controllers, "NetworkDeviceFunctionCount", ("NetworkDeviceFunctions",)
            ):
                found.append(
                    "%s (NetworkDeviceFunctions empty, its controllers declare functions)"
                    % (adapter_id,)
                )
    return found


def _collect_network_adapters(ctx):
    ports, twins, functions, collections = {}, {}, {}, {}
    with ctx.budget("bmc_network_adapters", _BUDGET_NETWORK_ADAPTERS) as budget:
        targets = _targets(ctx)
        lenovo = _is_lenovo(targets)
        host_power_state = _text(_dig(_get(ctx, targets["system"]), "PowerState"))
        chassis = _get(ctx, targets["chassis"])
        linked = _fenced_link(
            _dig(chassis, "NetworkAdapters"), "bmc_network_adapters NetworkAdapters"
        )
        path = linked or _sub(targets["chassis"], "NetworkAdapters")
        adapters, meta, raw = _fetch_collection(
            ctx, path, "bmc_network_adapters", ok_404=True, budget=budget
        )
        if adapters is None:
            if linked is not None:
                raise CollectError("the Chassis links %s but it answered 404" % (path,))
            raise SkipCheck(
                "%s is not served and the Chassis links no NetworkAdapters collection" % (path,)
            )
        if not adapters:
            # Populated at POST (UEFI and the adapters' sideband): an empty collection is
            # unmeasured whatever the power state says, never "no adapters".
            raise CollectError(
                "%s answered with zero members (host PowerState %s) — network adapters are "
                "populated at POST and an empty collection is unmeasured, never 'no adapters'; "
                "capture again after the host completes POST" % (path, host_power_state)
            )
        plan = [_network_adapters_plan(adapter) for adapter in adapters]
        # Complete-or-refused: the fewest GETs these reads can take must fit before one is sent.
        needed = sum(len(reads) for _adapter_id, reads in plan)
        left = _budget_left(budget)
        if left is not None and needed > left:
            raise CollectError(
                "bmc_network_adapters: the port and function collections of %d adapter(s) take "
                "at least %d GET(s) but only %d are left in the budget of %d — refused rather "
                "than recorded partially" % (len(plan), needed, left, budget.max_gets)
            )
        # The adapter collection's answer decides, and the first refusal after it turns
        # $expand off for the rest of the check: a refusal is paid for once, never per read.
        try_expand = meta["strategy"] == "expand"
        for adapter_id, reads in plan:
            report = collections.setdefault(
                adapter_id, {"ports": None, "network_ports_twin": None, "functions": None}
            )
            for role, link in reads:
                members, fetch, member_raw = _fetch_collection(
                    ctx,
                    link,
                    "bmc_network_adapters %s %s" % (adapter_id, role),
                    ok_404=True,
                    budget=budget,
                    try_expand=try_expand,
                )
                raw.update(member_raw)
                if fetch.get("expand_refused"):
                    try_expand = False
                entry = {
                    "source": link,
                    "strategy": fetch["strategy"],
                    "members": len(members) if members is not None else None,
                }
                if fetch.get("expand_refused"):
                    entry["expand_refused"] = fetch["expand_refused"]
                if role == "twin":
                    twins[adapter_id] = members
                    report["network_ports_twin"] = entry
                elif role == "functions":
                    functions[adapter_id] = members
                    report["functions"] = entry
                else:
                    ports[adapter_id] = (role, members)
                    report["ports"] = dict(entry, collection=role)
    unmeasured = _network_adapters_unmeasured(adapters, ports, functions, twins)
    if unmeasured:
        raise CollectError(
            "bmc_network_adapters: %s (host PowerState %s) — ports and functions are populated "
            "at POST and through the adapter's sideband, so the read is unmeasured, never 'no "
            "ports'; capture again after the host completes POST"
            % ("; ".join(unmeasured), host_power_state)
        )
    normalized, context = _normalize_network_adapters(
        adapters, ports, functions, twins, lenovo=lenovo
    )
    context.update(
        {
            "host_power_state": host_power_state,
            "adapters_source": path,
            "adapters_collection": dict(meta, members=len(adapters)),
            "collections": collections,
        }
    )
    raw = {request: _network_adapters_scrub_credentials(body) for request, body in raw.items()}
    return {"raw": raw, "normalized": normalized, "context": _with_resolution(context, targets)}


# --- shakedown discovery (development tooling, never part of a capture) ------
# The questions a first run against a new BMC vendor or firmware answers
# (docs/plans/bmc-capture-handoff.md §7): the Test Suite Shakedown reads
# _discover_log_sequence first, runs the checks, then DISCOVERY_PROBES
# (best-effort) and _discover_log_sequence once more past the cache. Reads use
# the collectors' own spelling where a collector reads the same path, so the
# per-run cache serves them.

_ACCOUNT_SERVICE = "/redfish/v1/AccountService"
_DISCOVERY_COLLECTIONS = (
    # (label, resolved member the path hangs off — None for a literal path, path)
    ("memory", "system", "Memory"),
    ("processors", "system", "Processors"),
    ("host_nics", "system", "EthernetInterfaces"),
    ("storage", "system", "Storage"),
    ("log_services", "system", "LogServices"),
    ("virtual_media", "system", "VirtualMedia"),
    ("pcie_devices", "chassis", "PCIeDevices"),
    ("network_adapters", "chassis", "NetworkAdapters"),
    ("sensors", "chassis", "Sensors"),
    ("controls", "chassis", "Controls"),
    ("manager_nics", "manager", "EthernetInterfaces"),
    ("firmware_inventory", None, _FIRMWARE),
    ("software_inventory", None, "/redfish/v1/UpdateService/SoftwareInventory"),
    ("accounts", None, _ACCOUNT_SERVICE + "/Accounts"),
    ("roles", None, _ACCOUNT_SERVICE + "/Roles"),
    ("subscriptions", None, "/redfish/v1/EventService/Subscriptions"),
    ("tasks", None, "/redfish/v1/TaskService/Tasks"),
    ("jobs", None, "/redfish/v1/JobService/Jobs"),
    ("licenses", None, "/redfish/v1/LicenseService/Licenses"),
    ("certificate_locations", None, "/redfish/v1/CertificateService/CertificateLocations"),
)
# Chassis links that say which environment and hardware views a firmware serves:
# the legacy Thermal/Power pair, their Subsystem successors, the Sensors collection.
_ENVIRONMENT_LINKS = (
    "Thermal",
    "Power",
    "ThermalSubsystem",
    "PowerSubsystem",
    "Sensors",
    "EnvironmentMetrics",
    "Controls",
    "PCIeSlots",
    "PCIeDevices",
    "NetworkAdapters",
    "Drives",
)


def _collection_count(payload):
    count = payload.get("Members@odata.count") if isinstance(payload, dict) else None
    if isinstance(count, int) and not isinstance(count, bool):
        return count
    return len(_aslist(_dig(payload, "Members")))


def _oem_links(resource):
    """{vendor key, links, scalars} of a resource's single Oem block."""
    key = _oem_key(resource)
    block = _dig(resource, "Oem", key) if key else None
    links, scalars = {}, []
    for name, value in sorted((block or {}).items()):
        if isinstance(value, dict) and value.get("@odata.id"):
            links[name] = value["@odata.id"]
        elif not isinstance(value, (dict, list)) and not str(name).startswith("@"):
            scalars.append(name)
    return {"oem_key": key, "links": links, "scalars": scalars}


def _discover_service_root(ctx):
    """RedfishVersion, vendor, product, $expand and other protocol features, root links, ids."""
    root = _get(ctx, _ROOT) or {}
    targets = _targets(ctx)
    return {
        "redfish_version": root.get("RedfishVersion"),
        "vendor": root.get("Vendor"),
        "product": root.get("Product"),
        "protocol_features": root.get("ProtocolFeaturesSupported"),
        "root_links": sorted(
            key for key, value in root.items() if isinstance(value, dict) and "@odata.id" in value
        ),
        "resolution": targets["resolution"],
    }


def _discover_oem(ctx):
    """Which OEM links and scalars the System, Manager and Chassis carry."""
    targets = _targets(ctx)
    manager = _get(ctx, targets["manager"])
    return {
        "system": _oem_links(_get(ctx, targets["system"])),
        "manager": dict(
            _oem_links(manager),
            firmware_version=_text(_dig(manager, "FirmwareVersion")),
            model=_text(_dig(manager, "Model")),
        ),
        "chassis": _oem_links(_get(ctx, targets["chassis"])),
    }


def _discover_log_services(ctx):
    """Every log service the System offers, with its size policy and sequence-number leaves."""
    targets = _targets(ctx)
    services = _get(ctx, _sub(targets["system"], "LogServices"))
    report = {}
    for link in _member_links(services, "discovery log services"):
        try:
            service = _get(ctx, link)  # the event log's spelling: one cached read
        except Exception as exc:  # transport error class is not importable here
            report[_leaf_id(link)] = "HTTP %s" % (_http_status(exc),)
            continue
        oem = _dig(service, "Oem", _oem_key(service)) if _oem_key(service) else None
        report[_leaf_id(link)] = {
            "log_entry_type": _text(service.get("LogEntryType")),
            "max_records": _to_int(service.get("MaxNumberOfRecords")),
            "overwrite_policy": _text(service.get("OverWritePolicy")),
            "entries_link": _fenced_link(service.get("Entries"), "discovery log entries"),
            "sequence_numbers": {
                key: value
                for key, value in sorted((oem or {}).items())
                if str(key).endswith("SeqNum")
            },
        }
    return report


def _discover_collections(ctx):
    """Member count of every collection the family reads, with the host's power state."""
    targets = _targets(ctx)
    system = _get(ctx, targets["system"])
    counts = {}
    for label, parent, suffix in _DISCOVERY_COLLECTIONS:
        path = suffix if parent is None else _sub(targets[parent], suffix)
        payload = _get_optional(ctx, path)
        counts[label] = "absent (404)" if payload is None else _collection_count(payload)
    return {
        "host_power_state": _text(system.get("PowerState")),
        "system_status": _text(_dig(system, "Oem", "Lenovo", "SystemStatus")),
        "collections": counts,
    }


def _discover_expand(ctx):
    """Whether $expand inlines one level, and whether $levels=2 inlines a member's collections."""
    targets = _targets(ctx)
    report = {}
    for label, path, nested in (
        ("levels_1", _sub(targets["system"], "Memory") + _EXPAND, None),
        (
            "levels_2",
            _sub(targets["chassis"], "NetworkAdapters") + "?$expand=.($levels=2)",
            ("Ports", "NetworkPorts", "NetworkDeviceFunctions"),
        ),
    ):
        try:
            payload = _get_optional(ctx, path)
        except Exception as exc:  # transport error class is not importable here
            if _http_status(exc) is None:
                raise
            report[label] = "refused: HTTP %s" % (_http_status(exc),)
            continue
        if payload is None:
            report[label] = "absent (404)"
            continue
        members = _dicts(payload.get("Members"))
        inline = bool(members) and _expanded(members)
        entry = {"members": len(members), "members_inline": inline}
        if nested:
            # XCC 6.10 inlines each adapter's Ports/NetworkPorts/Functions
            # collection resource at $levels=2, but its members as bare links.
            rows = [
                _dig(member, name, "Members")
                for member in members
                for name in nested
                if isinstance(_dig(member, name, "Members"), list)
            ]
            entry["nested_collections_inline"] = bool(rows)
            entry["nested_members_inline"] = any(
                bool(row) and _expanded(_dicts(row)) for row in rows
            )
        report[label] = entry
    return report


def _discover_environment(ctx):
    """Which environment and hardware views the Chassis links (legacy versus subsystem)."""
    targets = _targets(ctx)
    chassis = _get(ctx, targets["chassis"])
    return {name: isinstance(_dig(chassis, name), dict) for name in _ENVIRONMENT_LINKS}


def _discover_security(ctx):
    """The vendor security resource's property names (bmc_security keys every leaf of it)."""
    targets = _targets(ctx)
    if not _is_lenovo(targets):
        return {"vendor": targets["vendor"], "note": "no mapping for this vendor yet"}
    manager = _get(ctx, targets["manager"])
    link = _fenced_link(_dig(manager, "Oem", "Lenovo", "Security"), "discovery security")
    security = _get_optional(ctx, link) if link else None
    return {
        "resource": link,
        "properties": sorted(_flatten(security)) if security is not None else None,
    }


def _discovery_account_redactor(username):
    """The accounts redactor, then every account name but the capture account's scrubbed.

    Discovery lists the accounts only to find its own; the other local account
    names are bmc_accounts' keys (decision 5), never the shakedown trace's.
    Idempotent, and it returns a copy (``_scrub_accounts`` does).
    """

    def redact(node):
        node = _scrub_accounts(node)
        if not isinstance(node, dict):
            return node
        rows = _dicts(node.get("Members")) + ([node] if "UserName" in node else [])
        for row in rows:
            if row.get("UserName") not in (None, "", username):
                row["UserName"] = _SCRUBBED
        return node

    return redact


def _discover_account(ctx):
    """The capture account's role and privileges as the BMC reports them (no other account).

    The account list is read fresh (never the cached copy bmc_accounts keeps
    with every name) through a redactor that scrubs every name but this
    capture's own, which the envelope's transport footprint already names.
    """
    username = getattr(getattr(ctx, "restconf", None), "username", None)
    if not username:
        return {"note": "the transport does not name its account"}
    root = _get(ctx, _ROOT) or {}
    service_link = _fenced_link(root.get("AccountService"), "discovery") or _ACCOUNT_SERVICE
    service = _get_optional(ctx, service_link)
    if service is None:
        return {"found": False, "note": "%s answered 404" % (service_link,)}
    accounts_link = _fenced_link(service.get("Accounts"), "discovery") or _sub(
        service_link, "Accounts"
    )
    members, meta, _raw = _fetch_collection(
        ctx,
        accounts_link,
        "discovery accounts",
        ok_404=True,
        redact=_discovery_account_redactor(username),
        fresh=True,
    )
    mine = [member for member in _dicts(members) if member.get("UserName") == username]
    if not mine:
        return {"found": False, "accounts_strategy": meta["strategy"]}
    account = mine[0]
    role_link = _fenced_link(_dig(account, "Links", "Role"), "discovery role")
    role = _get_optional(ctx, role_link) if role_link else None
    return {
        "found": True,
        "role_id": _text(account.get("RoleId")),
        "enabled": _to_bool(account.get("Enabled")),
        "locked": _to_bool(account.get("Locked")),
        "password_change_required": _to_bool(account.get("PasswordChangeRequired")),
        "account_types": sorted(_text(item) for item in _aslist(account.get("AccountTypes"))),
        "assigned_privileges": sorted(
            _text(item) for item in _aslist(_dig(role, "AssignedPrivileges"))
        ),
        "oem_privileges": sorted(_text(item) for item in _aslist(_dig(role, "OemPrivileges"))),
    }


def _discover_log_sequence(ctx, fresh=False):
    """The platform log's sequence-number leaves now: before the checks, and after them.

    ``fresh`` re-reads the log service past the per-run cache (the cache keys
    on kwargs, so a distinct timeout forces a real GET), so a before/after
    pair measures what this run itself added to the log — nothing, on XCC 6.10.
    """
    targets = _targets(ctx)
    services = _get(ctx, _sub(targets["system"], "LogServices"))
    try:
        link, service_id = _pick_log_service(
            _member_links(services, "discovery log sequence"), targets
        )
    except (CollectError, SkipCheck) as exc:
        return {"note": str(exc)}
    if fresh:
        service = ctx.get(link, timeout=C.REDFISH_GET_TIMEOUT + 1, redact=_scrub_payload)
    else:
        service = _get(ctx, link)
    oem = _dig(service, "Oem", _oem_key(service)) if _oem_key(service) else None
    return {
        "service": service_id,
        "sequence_numbers": {
            key: value for key, value in sorted((oem or {}).items()) if str(key).endswith("SeqNum")
        },
    }


# Run by the shakedown after the checks (so each check met a cold cache and its
# own budget, exactly as in a capture); each answer lands under
# discovery["bmc"][label] (an error record on failure). _discover_log_sequence
# is not among them: the shakedown reads it first, before any other GET of the
# run, and again past the cache at the end.
DISCOVERY_PROBES = (
    ("service_root", _discover_service_root),
    ("oem", _discover_oem),
    ("log_services", _discover_log_services),
    ("collections", _discover_collections),
    ("expand", _discover_expand),
    ("environment", _discover_environment),
    ("security", _discover_security),
    ("capture_account", _discover_account),
)


# --- registrations -----------------------------------------------------------

register(
    CheckDef(
        id="bmc_system",
        platform="bmc",
        description=(
            "System identity, health, boot override, SecureBoot, power/watchdog/console policy, "
            "TPM, and the BMC's own services and address."
        ),
        tier=1,
        compare={"mode": "equality_scalar"},
        miss_meaning=(
            "An identity field (serial/uuid/model/BIOS/BMC firmware) differs — a different "
            "chassis or a firmware change; a boot/SecureBoot change means the host was "
            "not booted the intended way; a power-restore, watchdog, console or TPM change "
            "alters how the host comes back after an AC loss or a hang and what can reach its "
            "console; a BMC address change means the BMC was re-addressed or re-leased."
        ),
        collector=_collect_system,
        tags=("platform", "identity"),
    )
)

register(
    CheckDef(
        id="bmc_security",
        platform="bmc",
        description=(
            "BMC security settings leaf by leaf (TLS, HTTPS/LDAPS/CIM, firmware rollback, key "
            "manager) and ThinkEdge tamper state."
        ),
        tier=1,
        compare={"mode": "equality_set"},
        miss_meaning=(
            "A management-plane security setting changed — TLS mode or minimum version, "
            "HTTPS/LDAPS/CIM-over-HTTPS enablement, firmware rollback, encapsulation, the "
            "external key manager — or, on a ThinkEdge unit, the tamper state: an active "
            "lockdown denies SED keys until re-activation, and motion detection flipping off "
            "together with lockdown Active is the lockdown itself, not an operator edit."
        ),
        collector=_collect_security_state,
        tags=("platform", "security"),
    )
)

register(
    CheckDef(
        id="bmc_thermal",
        platform="bmc",
        description=(
            "Chassis temperature sensors and fans (Thermal, else ThermalSubsystem fans): "
            "health/state, ambient-class readings."
        ),
        tier=1,
        compare={
            "mode": "equality_set",
            "fields": {
                "reading_c": {"tolerance": {"abs": 8}},
                "reading": {"tolerance": {"pct": 25}},
            },
        },
        miss_meaning=(
            "A sensor or fan degraded, vanished, or the ambient/intake reading moved more "
            "than 8 °C — the thermal environment or the chassis cooling changed (on an SE350 "
            "the fans are internal and not hot-swap)."
        ),
        collector=_collect_thermal,
        tags=("platform", "environment"),
    )
)

register(
    CheckDef(
        id="bmc_power",
        platform="bmc",
        description=(
            "Power supplies, redundancy and voltage rails (Chassis Power, else PowerSubsystem)."
        ),
        tier=1,
        compare={
            "mode": "equality_set",
            "fields": {"line_input_voltage": {"tolerance": {"pct": 10}}},
        },
        miss_meaning=(
            "A feed was lost or changed: a supply not Enabled/OK, input out of its declared "
            "range or reported LossOfInput/OutOfRange, redundancy degraded, or a rail outside its "
            "thresholds."
        ),
        collector=_collect_power,
        tags=("platform", "environment"),
    )
)

register(
    CheckDef(
        id="bmc_inventory",
        platform="bmc",
        description="DIMMs, CPUs, PCIe devices and functions: identity, configuration, health.",
        tier=2,
        compare={"mode": "equality_set"},
        miss_meaning=(
            "A part is missing, replaced or unhealthy — a DIMM or riser that did not come "
            "back is a missing key or an Absent slot, a swapped part is a serial or PCI id "
            "change; a different CPU microcode is a UEFI update."
        ),
        collector=_collect_inventory,
        tags=("platform", "inventory"),
    )
)

register(
    CheckDef(
        id="bmc_host_nics",
        platform="bmc",
        description="Host network ports as the BMC sees them: link status and burned-in MAC.",
        tier=1,
        compare={"mode": "equality_set"},
        miss_meaning=(
            "A host port's link state changed independently of the host OS — a cable not "
            "reconnected (NoLink) or connected but not up (LinkDown)."
        ),
        collector=_collect_host_nics,
        tags=("interfaces",),
    )
)

register(
    CheckDef(
        id="bmc_firmware",
        platform="bmc",
        description="Firmware and software inventory, the BMC's active image and bank policy.",
        tier=2,
        compare={"mode": "equality_set"},
        miss_meaning=(
            "A firmware version changed or a component vanished from the inventory — an "
            "undeclared update, or an adapter that did not enumerate; a version on a -Pending "
            "member is a staged update; a changed active image is a BMC bank switch."
        ),
        collector=_collect_firmware,
        tags=("platform", "firmware"),
    )
)

register(
    CheckDef(
        id="bmc_event_log",
        platform="bmc",
        description="BMC logs: platform Warning/Critical entries and every ActiveLog condition.",
        tier=2,
        compare={"mode": "equality_set"},
        miss_meaning=(
            "A Warning/Critical event was logged (sel key added) or an unresolved condition "
            "was raised (active key added) between captures — a hardware or environment "
            "finding; a removed sel key means the log was cleared or wrapped, a removed "
            "active key a condition that cleared."
        ),
        collector=_collect_event_log,
        tags=("platform", "logs", EMPTY_OK_TAG),  # nothing keyed is the healthy state
    )
)

register(
    CheckDef(
        id="bmc_bios",
        platform="bmc",
        description="Every UEFI setting, settings armed for the next reset, UEFI password flags.",
        tier=2,
        compare={"mode": "equality_set"},
        miss_meaning=(
            "A UEFI setting reverted or changed — a defaults load, CMOS/RTC reset or an "
            "operator edit, and the host OS's virtualisation and performance tuning depends "
            "on these; a pending key that appears is a setting armed but not yet applied, "
            "one that disappears was applied at a reset or withdrawn."
        ),
        collector=_collect_bios,
        tags=("platform", "bios"),
    )
)

register(
    CheckDef(
        id="bmc_storage",
        platform="bmc",
        description="Storage controllers (cache, battery, RAID), drives and volumes (policies).",
        tier=1,
        compare={"mode": "equality_set"},
        miss_meaning=(
            "A drive or volume degraded, vanished or was replaced — a RAID1 member failure "
            "is invisible to the hypervisor's LUN view; an encryption flag change is a "
            "key-management event; a cache policy or controller battery change puts written "
            "data at risk."
        ),
        collector=_collect_storage,
        tags=("platform", "storage"),
    )
)

register(
    CheckDef(
        id="bmc_manager_network",
        platform="bmc",
        description=(
            "BMC network, time and services: addressing, DNS, NTP, protocols/ports, host interface."
        ),
        tier=2,
        compare={"mode": "equality_scalar"},
        miss_meaning=(
            "The BMC's own network/time configuration changed — NTP or DNS lost means "
            "back-dated event-log timestamps and broken outbound paths (key management, "
            "alert delivery, management-server discovery); a service or port opened, or the "
            "host interface's credential bootstrapping switched on, widens who can reach the BMC."
        ),
        collector=_collect_manager_network,
        tags=("platform", "management"),
    )
)

register(
    CheckDef(
        id="bmc_chassis",
        platform="bmc",
        description=(
            "Chassis identity, LEDs and indicator, the operator-maintained Location record and "
            "the intrusion sensor."
        ),
        tier=1,
        compare={"mode": "equality_set"},
        miss_meaning=(
            "A chassis LED changed — a Fault LED leaving Off is a hardware finding, a lit "
            "Identify LED means someone is locating the server — or the chassis or system-board "
            "identity changed, the location record changed (expected when a chassis is "
            "relocated — declare it), or the intrusion sensor left Normal."
        ),
        collector=_collect_chassis_location,
        tags=("platform", "identity", "location"),
    )
)

register(
    CheckDef(
        id="bmc_sensors",
        platform="bmc",
        description=(
            "Every chassis sensor (Sensors collection): reading type, context, state/health, "
            "units, thresholds, discrete assertions and ambient-class readings."
        ),
        tier=1,
        compare={"mode": "equality_set", "fields": {"reading": {"tolerance": {"abs": 8}}}},
        miss_meaning=(
            "A sensor degraded, appeared or vanished, a threshold was reconfigured, a discrete "
            "sensor asserted or cleared, or the ambient reading moved more than 8 °C — on an "
            "SE350 the Power Adapter, Chassis, Chassis Movement and Lockdown Mode sensors are the "
            "only record of the external power adapters, chassis intrusion and movement, and the "
            "lockdown state."
        ),
        collector=_collect_sensors,
        tags=("platform", "environment", "security"),
    )
)

register(
    CheckDef(
        id="bmc_boot",
        platform="bmc",
        description=(
            "Boot path: boot order and override, retry and fault policy, boot options, Lenovo "
            "boot-manager orders, virtual media slots and remote-control images."
        ),
        tier=1,
        compare={"mode": "equality_set"},
        miss_meaning=(
            "The host's boot path changed — a boot order reordered, a device gone from or "
            "added to an order, a change armed for the next boot, an override or one-time "
            "boot set, or an image left inserted in a virtual media slot or held by the BMC: "
            "the classic cause of a server coming back on the wrong device, invisible from "
            "the OS."
        ),
        collector=_collect_boot,
        tags=("platform", "boot"),
    )
)

register(
    CheckDef(
        id="bmc_power_policy",
        platform="bmc",
        description=(
            "Power policy: AC-restore and Lenovo power flags, host watchdog, power cap and chassis "
            "controls, scheduled power actions, watchdogs."
        ),
        tier=1,
        compare={"mode": "equality_set"},
        miss_meaning=(
            "How the host is powered changed — the AC-restore policy or a Lenovo power flag "
            "(Wake-on-LAN, power-on permission, local power control), a power cap or a chassis "
            "control set, lifted or moved, a scheduled power action activated (the BMC then "
            "powers the host on or off or restarts it on that schedule) or a watchdog armed or "
            "disarmed (an armed one acts on a host that stops servicing it)."
        ),
        collector=_collect_power_policy,
        tags=("platform", "power"),
    )
)

register(
    CheckDef(
        id="bmc_network_adapters",
        platform="bmc",
        description=(
            "Network adapters as the BMC sees them: identity and controller firmware, per-port "
            "link and capability, per-function burned-in MAC, SR-IOV and boot mode."
        ),
        tier=1,
        compare={"mode": "equality_set"},
        miss_meaning=(
            "An adapter, port or function vanished or changed — a card not reseated or not "
            "enumerated, a port's link lost (NoLink: no cable or transceiver; LinkDown: cabled, "
            "no link), its speed, autonegotiation, flow-control or LLDP setting changed, adapter "
            "firmware updated, or a function's burned-in MAC, SR-IOV or boot mode changed (a "
            "replaced card, or an edit in UEFI setup)."
        ),
        collector=_collect_network_adapters,
        tags=("platform", "interfaces"),
    )
)
