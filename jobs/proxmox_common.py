"""Shared Proxmox capture helpers; responses remain complete and redacted."""

import copy
import json
import re
from urllib.parse import urlencode, urlsplit, urlunsplit

from . import constants as C
from .proxmox_paths import ProxmoxPathRefused, fence_path
from .registry import CollectError

SCRUBBED = "***scrubbed***"
_SECRET = re.compile(
    r"password|passwd|passphrase|secret|credential|private.?key|privkey|"
    r"authorization|cookie|ticket|csrf|community|keytab|license.?key|"
    r"^(?:key|keys|token|authkey|clientkey|clientsecret|cipassword|sshkeys|certificate|pem|signature|serverid)$",
    re.I,
)
_PERSONAL = frozenset(
    {
        "firstname",
        "lastname",
        "email",
        "contact",
        "fullname",
        "mailto",
        "mailfrom",
        "fromaddress",
        "recipient",
        "recipients",
    }
)
_POLICY = re.compile(
    r"policy|min(?:imum)?|max(?:imum)?|length|expir|enabled?|required|rotation|status", re.I
)
_ACCOUNT = re.compile(r"(?<![\w@])([A-Za-z0-9_.+-]+@[A-Za-z0-9_.-]+)(?:![A-Za-z0-9_.-]+)?")
_INLINE_SECRET = re.compile(
    r"(?i)((?<![A-Za-z0-9_.-])(?:[A-Za-z0-9_.-]*[_.-])?"
    r"(?:password|passwd|passphrase|secret|key|token|community|credential|cipassword|"
    r"clientsecret|authorization|secretkey|username)\s*[=:]\s*)"
    r"(?:\"[^\"]*\"|'[^']*'|[^\s,;]+)"
)
_ARG_SECRET = re.compile(
    r"(?i)((?:--?|\b)(?:password|passwd|passphrase|secret|token|credential)\s+)"
    r"(?:\"[^\"]*\"|'[^']*'|[^\s,;]+)"
)
_PEM = re.compile(r"-----BEGIN [^-]+-----.*?-----END [^-]+-----", re.S)
_URL = re.compile(r"(?<![A-Za-z0-9+.-])[A-Za-z][A-Za-z0-9+.-]*://[^\s\"'<>]+")
_AUTH = re.compile(r"(?i)PVEAPIToken\s*=\s*[^\s,;]+")
_SSH_KEY = re.compile(r"\b(?:ssh-(?:rsa|ed25519)|ecdsa-sha2-[A-Za-z0-9-]+)\s+[A-Za-z0-9+/=]+")
_SSH_KEYS_YAML = re.compile(r"(?m)^[ \t]*ssh_authorized_keys[ \t]*:[^\n]*(?:\n[ \t]+[^\n]*)*")
_OPAQUE_SECRET_BLOCK = re.compile(
    r"(?im)^\s*(?:password|passwd|secret|private.?key|clientsecret|cipassword)\s*:\s*[|>]"
)


def scrub_text(value):
    """Mask credentials and operators in inherently free-text evidence."""
    if not isinstance(value, str):
        raise TypeError("text redactor requires a string")
    if _OPAQUE_SECRET_BLOCK.search(value):
        return "[withheld: opaque multiline credential]"
    value = _PEM.sub(SCRUBBED, value)
    if "-----BEGIN " in value or "-----END " in value:
        return "[withheld: incomplete key material]"
    value = _INLINE_SECRET.sub(lambda match: match.group(1) + SCRUBBED, value)
    value = _ARG_SECRET.sub(lambda match: match.group(1) + SCRUBBED, value)
    value = _ACCOUNT.sub(SCRUBBED, value)
    return _string(value)


def _string(value):
    if _OPAQUE_SECRET_BLOCK.search(value):
        return "[withheld: opaque multiline credential]"
    value = _PEM.sub(SCRUBBED, value)
    if "-----BEGIN " in value or "-----END " in value:
        return "[withheld: incomplete key material]"
    value = _AUTH.sub(SCRUBBED, value)
    value = _SSH_KEYS_YAML.sub("ssh_authorized_keys: [" + SCRUBBED + "]", value)
    value = _SSH_KEY.sub(SCRUBBED, value)
    value = _INLINE_SECRET.sub(lambda match: match.group(1) + SCRUBBED, value)
    value = _ARG_SECRET.sub(lambda match: match.group(1) + SCRUBBED, value)

    def url(match):
        parsed = urlsplit(match.group(0))
        authority = parsed.netloc.rsplit("@", 1)[-1]
        if "@" in parsed.netloc:
            authority = SCRUBBED + "@" + authority
        return urlunsplit(
            (parsed.scheme, authority, parsed.path, SCRUBBED if parsed.query else "", "")
        )

    return _URL.sub(url, value) if "://" in value else value


def _access_identity_map(kind, value, *, acl=False):
    """Preserve native access map IDs; every metadata object is recursively scrubbed.

    Token metadata maps cannot carry secret token values: values must be objects,
    and credential leaves inside those objects always pass through scrub again.
    Scalar access role values are only the documented 0/1 policy flags.
    """
    out = {}
    for identifier, record in value.items():
        if not isinstance(identifier, str):
            raise TypeError("invalid configured access map identity")
        user = r"[^\s:/]+@[A-Za-z][A-Za-z0-9_.-]+"
        grammar = user if kind == "users" else r"[A-Za-z0-9_.-]+"
        if kind == "tokens":
            grammar = r"(?:" + user + r"!)?[A-Za-z][A-Za-z0-9_.-]*"
        if re.fullmatch(grammar, identifier) is None:
            raise TypeError("invalid configured access map identity")
        if kind != "tokens" and type(record) in (bool, int) and record in (0, 1):
            out[identifier] = record
        elif isinstance(record, dict):
            if acl and kind in ("users", "groups", "tokens"):
                out[identifier] = _access_identity_map("roles", record)
            else:
                out[identifier] = _scrub(record, acl=acl)
        else:
            raise TypeError("invalid configured access metadata object")
    return out


def _acl_children(value):
    """Native ACL children are path segment identities, with scrubbed node bodies."""
    out = {}
    for segment, node in value.items():
        if (
            not isinstance(segment, str)
            or not segment
            or "/" in segment
            or not isinstance(node, dict)
        ):
            raise TypeError("invalid native ACL child object")
        out[segment] = _scrub(node, acl=True)
    return out


def _storage_metadata_ids(value):
    """Verified native Storage::config ids map, retaining scrubbed record bodies."""
    out = {}
    for identifier, record in value.items():
        if (
            not isinstance(identifier, str)
            or re.fullmatch(r"[A-Za-z][A-Za-z0-9_.-]*", identifier) is None
            or not isinstance(record, dict)
        ):
            raise TypeError("invalid native storage metadata object")
        out[identifier] = _scrub(record)
    return out


def _pool_policy_map(value):
    """Native user.cfg pool bodies have typed VM/storage membership flag maps."""
    out = {}
    for identifier, record in value.items():
        if (
            not isinstance(identifier, str)
            or re.fullmatch(r"[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*", identifier) is None
            or not isinstance(record, dict)
        ):
            raise TypeError("invalid native pool policy object")
        body = _scrub(record)
        for kind in ("storage", "vms"):
            members = record.get(kind)
            if members is None:
                continue
            if not isinstance(members, dict):
                raise TypeError("invalid native pool membership map")
            flags = {}
            grammar = r"[A-Za-z][A-Za-z0-9_.-]*" if kind == "storage" else r"[1-9][0-9]{2,8}"
            for member, flag in members.items():
                if (
                    not isinstance(member, str)
                    or re.fullmatch(grammar, member) is None
                    or type(flag) not in (bool, int)
                    or flag not in (0, 1)
                ):
                    raise TypeError("invalid native pool membership flag")
                flags[member] = flag
            body[kind] = flags
        out[identifier] = body
    return out


def scrub(payload):
    """Copy JSON, masking secrets before cache/trace; unsupported values fail closed.

    Configured access identities remain meaningful identifiers. Personal names,
    contacts and operators in message/log text are masked. Booleans/numbers in
    explicitly named policy fields remain policy values; credential leaves do not.
    """
    return _scrub(payload)


def _scrub(payload, *, acl=False, native=None):
    if isinstance(payload, dict):
        out = {}
        # Proxmox option/pending rows encode a setting name separately from value.
        setting = payload.get("key", payload.get("name"))
        secret_setting = isinstance(setting, str) and _SECRET.search(setting)
        for key, value in payload.items():
            if not isinstance(key, str):
                raise TypeError("JSON object key is not a string")
            lowered = key.lower().replace("-", "").replace("_", "")
            sensitive = bool(_SECRET.search(key)) or lowered in _PERSONAL
            if re.fullmatch(r"[A-Za-z0-9_.+-]+@[A-Za-z0-9_.-]+(?:![A-Za-z0-9_.-]+)?", key):
                sensitive = False
            if key == "key" and any(
                field in payload for field in ("value", "pending", "current", "default")
            ):
                sensitive = False
            if secret_setting and key in ("value", "pending", "current", "default"):
                sensitive = True
            if sensitive and value not in (None, "", [], {}):
                policy_key = (
                    setting
                    if secret_setting and key in ("value", "pending", "current", "default")
                    else key
                )
                policy = isinstance(value, (bool, int, float)) and _POLICY.search(policy_key)
                out[key] = value if policy else SCRUBBED
            elif key.lower() in (
                "t",
                "text",
                "content",
                "message",
                "msg",
                "log",
                "output",
                "description",
            ) and isinstance(value, str):
                out[key] = scrub_text(value)
            elif key in ("users", "groups", "roles", "tokens") and isinstance(value, dict):
                out[key] = _access_identity_map(key, value, acl=acl)
            elif acl and key == "children" and isinstance(value, dict):
                out[key] = _acl_children(value)
            elif native == "storage" and key == "ids" and isinstance(value, dict):
                out[key] = _storage_metadata_ids(value)
            elif native == "access" and key == "pools" and isinstance(value, dict):
                out[key] = _pool_policy_map(value)
            else:
                out[key] = _scrub(
                    value,
                    acl=acl or key in ("acl", "acl_root"),
                    native=key if key in ("access", "storage") else None,
                )
        return out
    if isinstance(payload, list):
        return [_scrub(value, acl=acl) for value in payload]
    if isinstance(payload, str):
        return _string(payload)
    if payload is None or isinstance(payload, (bool, int, float)):
        return payload
    raise TypeError("unsupported JSON value")


def property_string(value):
    """Parse native comma-separated key=value grammar without coercing unknown values."""
    if value is None or value == "":
        return {}
    if not isinstance(value, str):
        raise CollectError("Proxmox property string is not a string")
    out = {}
    for index, part in enumerate(value.split(",")):
        key, sep, item = part.partition("=")
        if not sep and index == 0:
            key, item = "value", part
        elif not sep:
            raise CollectError("Malformed Proxmox property string")
        if not key or key in out:
            raise CollectError("Duplicate or absent Proxmox property key")
        out[key] = item
    return out


def stable(row, omit=()):
    """Copy every source field except explicitly nominated volatile leaves."""
    if not isinstance(row, dict):
        raise CollectError("Proxmox object is not a dictionary")
    excluded = frozenset(omit)
    return {key: copy.deepcopy(value) for key, value in row.items() if key not in excluded}


def keyed(rows, field, prefix=""):
    """Make a complete object map; absent and duplicate native identities refuse."""
    out = {}
    for row in rows:
        if not isinstance(row, dict) or field not in row or row[field] in (None, ""):
            raise CollectError("Proxmox row has no stable identity")
        value = row[field]
        if isinstance(value, (dict, list, bool)):
            raise CollectError("Proxmox row identity has an invalid type")
        key = prefix + str(value)
        if key in out:
            raise CollectError("Duplicate Proxmox row identity")
        out[key] = copy.deepcopy(row)
    return out


def request_path(path, params=None):
    """Exact canonical request key: sort and encode query names/values once."""
    if not isinstance(path, str) or "?" in path and params:
        raise CollectError("Ambiguous Proxmox request parameters")
    if not params:
        try:
            return fence_path(path)
        except ProxmoxPathRefused:
            raise CollectError("Proxmox request refused by the read-only path fence") from None
    if not isinstance(params, dict):
        raise CollectError("Proxmox parameters are not a dictionary")
    pairs = []
    for key, value in sorted(params.items()):
        if not isinstance(key, str) or isinstance(value, (dict, list, tuple, set)):
            raise CollectError("Proxmox parameter has an invalid type")
        if isinstance(value, bool):
            value = int(value)
        if value is None:
            raise CollectError("Proxmox parameter is absent")
        pairs.append((key, str(value)))
    try:
        return fence_path(path + "?" + urlencode(pairs))
    except ProxmoxPathRefused:
        raise CollectError("Proxmox request refused by the read-only path fence") from None


class Capture:
    """One collector's complete API envelopes, normalized data, and source outcomes."""

    def __init__(self, ctx):
        self.ctx = ctx
        ctx._proxmox_capture = self
        self.raw = {}
        self.context = {"sources": {}, "unsupported": []}
        self._node = None
        self._uncached_gets = 0

    def read(self, path, *, params=None, optional=False):
        request = request_path(path, params)
        client = getattr(self.ctx, "restconf", None)
        label = getattr(client, "transport_label", "proxmox")
        source = getattr(client, "public_path", lambda value: value)(request)
        cache_key = (label, request, (("ok_404", optional),))
        cache = getattr(self.ctx, "_cache", {})
        if cache_key not in cache:
            if self._uncached_gets >= C.PROXMOX_MAX_CHECK_BUDGET:
                self.context["sources"][source] = {
                    "outcome": "refused",
                    "reason": "budget-exhausted",
                }
                raise CollectError("Proxmox GET budget exhausted before complete capture")
            self._uncached_gets += 1
        self.context["budget"] = {
            "limit": C.PROXMOX_MAX_CHECK_BUDGET,
            "uncached_gets": self._uncached_gets,
        }
        try:
            answer = self.ctx.get(request, redact=scrub, ok_404=optional)
        except Exception as exc:
            if optional and getattr(exc, "feature_absent", False):
                kind = getattr(exc, "kind", None) or "ceph-not-initialized"
                self.raw[source] = {"data": None, "feature_absent": kind}
                self.context["sources"][source] = {
                    "outcome": "not-present",
                    "status": getattr(exc, "status_code", None),
                    "unavailable_reason": kind,
                }
                self.context["unsupported"].append(source)
                return None
            self.context["sources"][source] = {
                "outcome": "refused",
                "status": getattr(exc, "status_code", None),
            }
            raise
        # Fake contexts and callers still pass through the same fail-closed policy.
        answer = scrub(answer)
        self.raw[source] = answer
        if answer is None:
            self.context["sources"][source] = {"outcome": "not-present"}
            self.context["unsupported"].append(source)
            return None
        if not isinstance(answer, dict) or "data" not in answer:
            raise CollectError("Proxmox response has no API data envelope")
        self.context["sources"][source] = {"outcome": "complete"}
        return copy.deepcopy(answer["data"])

    def rows(self, path, *, params=None, optional=False):
        value = self.read(path, params=params, optional=optional)
        if value is None and optional:
            return None
        if not isinstance(value, list) or any(not isinstance(row, dict) for row in value):
            raise CollectError("Proxmox response is not a list of objects")
        return value

    def envelope(self, path, *, params=None):
        return copy.deepcopy(self.raw[request_path(path, params)])

    def node(self):
        if self._node is None:
            rows = self.rows("/cluster/status")
            local = [
                row
                for row in rows
                if row.get("type") == "node" and row.get("local") in (1, True, "1")
            ]
            if len(local) != 1 or not isinstance(local[0].get("name"), str):
                raise CollectError("Proxmox API did not identify exactly one local node")
            name = local[0]["name"]
            if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", name) is None:
                raise CollectError("Proxmox API local node identity is invalid")
            self._node = name
            self.context["node"] = name
        return self._node

    def visibility(self, required=None, *, syslog=False):
        """Verify effective audit grants at exact ACL paths before inventory reads.

        A permission's 0/1 value describes propagation, not whether it is
        granted. Callers nominate exact scope paths. This proof cannot
        discover fully hidden NoAccess descendants; callers must reconcile an
        authoritative resource/ACL source before declaring complete visibility.
        """
        node = self.node()
        required = required or {
            "/": ("Sys.Audit",),
            "/nodes/%s" % (node,): ("Sys.Audit",),
            "/vms": ("VM.Audit",),
            "/storage": ("Datastore.Audit",),
        }
        if syslog:
            required = dict(required)
            path = "/nodes/%s" % (node,)
            required[path] = tuple(required.get(path, ())) + ("Sys.Syslog",)
        proof = {}
        for path, privileges in required.items():
            data = self.read("/access/permissions", params={"path": path})
            leaf = data.get(path) if isinstance(data, dict) else None
            if not isinstance(leaf, dict):
                raise CollectError("Proxmox effective audit visibility could not be verified")
            for privilege in privileges:
                if privilege not in leaf or leaf[privilege] is None:
                    raise CollectError("Proxmox required audit privilege is absent at %s" % (path,))
            proof[path] = stable(leaf)
        self.context["visibility"] = {
            "effective_audit_paths": proof,
            "descendant_exclusions": "require authoritative inventory/ACL reconciliation",
        }
        return proof

    def paged(self, path, *, params=None):
        """Exhaust offset pages; source totals and every page envelope are retained."""
        params = dict(params or {})
        if "start" in params or "limit" in params:
            raise CollectError("Paged Proxmox read owns start and limit")
        size = C.PROXMOX_PAGE_SIZE
        rows = []
        start = 0
        total = None
        seen = set()
        for _ in range(C.PROXMOX_MAX_PAGES):
            query = dict(params, start=start, limit=size)
            page = self.rows(path, params=query)
            envelope = self.raw[request_path(path, query)]
            reported = envelope.get("total")
            if reported is not None:
                if not isinstance(reported, int) or isinstance(reported, bool) or reported < 0:
                    raise CollectError("Invalid Proxmox pagination total")
                if total is not None and total != reported:
                    raise CollectError("Proxmox pagination source changed during capture")
                total = reported
            if len(page) > size:
                raise CollectError("Proxmox pagination exceeded its requested page size")
            fingerprint = json.dumps(page, sort_keys=True, separators=(",", ":"))
            if page and fingerprint in seen:
                raise CollectError("Proxmox pagination repeated a page")
            seen.add(fingerprint)
            rows.extend(page)
            start += len(page)
            if total is not None:
                if start > total or not page and start < total:
                    raise CollectError("Incomplete Proxmox pagination")
                if start == total:
                    return rows
            elif len(page) < size:
                return rows
        raise CollectError("Proxmox page budget exhausted before complete capture")

    def result(self, normalized):
        return {"raw": self.raw, "normalized": normalized, "context": self.context}
