"""Private native task references and nonpersonal public Proxmox task IDs.

PVE::UPID encodes node/pid/process-start/start-time/type/id/actor. The native
header provides process identity; only the final actor is replaced publicly.
Native references are authorized only by validated observed task lists.
"""

import re
from urllib.parse import parse_qsl, urlencode

from .proxmox_common import SCRUBBED
from .proxmox_paths import ProxmoxPathRefused, fence_path

ACTOR = "redacted@redacted"
_UPID = re.compile(
    r"(?P<header>UPID:(?P<node>[A-Za-z0-9][A-Za-z0-9-]*):"
    r"[A-Fa-f0-9]{8}:[A-Fa-f0-9]{8,9}:[A-Fa-f0-9]{8}:"
    r"[A-Za-z0-9_.-]+:[A-Za-z0-9_.-]*:)"
    r"(?P<actor>[A-Za-z0-9_.+-]+@[A-Za-z0-9_.-]+(?:![A-Za-z0-9_.-]+)?):"
)
_DETAIL = re.compile(r"/nodes/(?P<node>[^/]+)/tasks/(?P<upid>[^/]+)(?P<suffix>/(?:status|log))?")
_LIST = re.compile(r"/(?:nodes/(?P<node>[^/]+)/tasks|cluster/tasks)")
_EMBEDDED = re.compile(
    r"(?P<header>UPID:[^:\s/]+:[A-Fa-f0-9]{8}:[A-Fa-f0-9]{8,9}:"
    r"[A-Fa-f0-9]{8}:[^:\s/]+:[^:\s/]*:)[^:\s/]+:"
)
_TEXT = frozenset(
    ("t", "text", "message", "msg", "log", "output", "description", "exitstatus", "status")
)


class TaskPrivacyError(Exception):
    """Safe fixed-message refusal; never includes a native ID or response."""


def _parts(upid):
    match = _UPID.fullmatch(upid) if isinstance(upid, str) else None
    if match is None:
        raise TaskPrivacyError("Proxmox task identity is malformed")
    try:
        fence_path("/nodes/%s/tasks/%s/status" % (match["node"], upid))
    except ProxmoxPathRefused:
        raise TaskPrivacyError("Proxmox task identity is outside the reviewed read shape") from None
    return match


class TaskAliases:
    def __init__(self):
        self.__native = {}
        self.__actors = set()

    def clear(self):
        self.__native.clear()
        self.__actors.clear()

    def wire_path(self, request):
        resource, mark, query = request.partition("?")
        detail = _DETAIL.fullmatch(resource)
        if detail is None:
            return request
        alias = detail["upid"]
        identity = _parts(alias)
        if identity["actor"] != ACTOR or alias not in self.__native:
            raise TaskPrivacyError("Proxmox task detail requires an observed nonpersonal reference")
        if identity["node"] != detail["node"]:
            raise TaskPrivacyError("Proxmox task detail node does not match its observed reference")
        native = self.__native[alias]
        _parts(native)
        return "/nodes/%s/tasks/%s%s%s" % (
            detail["node"],
            native,
            detail["suffix"] or "",
            mark + query if mark else "",
        )

    def public_path(self, path):
        """Sanitize trace/source labels without registering any reference."""
        if not isinstance(path, str):
            return "<invalid Proxmox request>"
        resource, mark, query = path.partition("?")
        if resource.startswith("/api2/json/"):
            resource = resource[len("/api2/json") :]
        matched = re.match(r"(/(?:nodes/[^/]+/tasks|cluster/tasks))(?:/|$)", resource)
        if matched is None:
            return path
        base = matched[1]
        detail = _DETAIL.fullmatch(resource)
        if resource != base:
            if detail is None:
                resource = base + "/<redacted-task>"
            else:
                try:
                    identity = _parts(detail["upid"])
                    alias = identity["header"] + ACTOR + ":"
                except TaskPrivacyError:
                    alias = "<redacted-task>"
                resource = base + "/" + alias + (detail["suffix"] or "")
        if mark:
            try:
                fence_path(path)
                pairs = parse_qsl(query, keep_blank_values=True, strict_parsing=True)
                query = urlencode(
                    [
                        (key, SCRUBBED if key == "userfilter" else self._text(value))
                        for key, value in pairs
                    ]
                )
            except (ValueError, ProxmoxPathRefused):
                query = "<redacted-query>"
        return resource + ("?" + query if mark else "")

    def _text(self, value, *, actors=None, free_text=False):
        actors = self.__actors if actors is None else actors
        # Even references mentioned only in logs cannot retain their actors;
        # these aliases do not authorize a later detail request.
        value = _EMBEDDED.sub(lambda match: match["header"] + ACTOR + ":", value)
        for actor in sorted(actors, key=len, reverse=True):
            if actor == ACTOR:
                continue
            value = value.replace(actor, SCRUBBED)
            account = actor.partition("!")[0]
            if account == ACTOR:
                continue
            value = value.replace(account, SCRUBBED)
            if free_text:
                username = account.partition("@")[0]
                value = re.sub(
                    r"(?<![A-Za-z0-9_.+-])" + re.escape(username) + r"(?![A-Za-z0-9_.+-])",
                    SCRUBBED,
                    value,
                )
        return value

    def _scrub(self, value, actors, key=""):
        if isinstance(value, dict):
            result = {}
            for name, item in value.items():
                if not isinstance(name, str):
                    raise TaskPrivacyError("Proxmox task object keys are malformed")
                public = self._text(name, actors=actors)
                if public in result:
                    raise TaskPrivacyError(
                        "Proxmox task metadata aliases collide; response withheld"
                    )
                result[public] = (
                    SCRUBBED
                    if name.lower() in ("user", "tokenid") and item not in (None, "")
                    else self._scrub(item, actors, name)
                )
            return result
        if isinstance(value, list):
            return [self._scrub(item, actors, key) for item in value]
        if isinstance(value, str):
            return self._text(value, actors=actors, free_text=key.lower() in _TEXT)
        return value

    def envelope(self, request, envelope):
        resource = request.partition("?")[0]
        listed = _LIST.fullmatch(resource)
        detail = _DETAIL.fullmatch(resource)
        if listed is None and detail is None:
            return envelope
        pending = dict(self.__native)
        actors = set(self.__actors)
        data = envelope["data"]
        if listed is not None:
            if not isinstance(data, list) or any(not isinstance(row, dict) for row in data):
                raise TaskPrivacyError("Proxmox task list is malformed")
            observed = set()
            for row in data:
                identity = _parts(row.get("upid"))
                native = row["upid"]
                alias = identity["header"] + ACTOR + ":"
                if native in observed:
                    raise TaskPrivacyError("Proxmox task list contains duplicate identities")
                observed.add(native)
                if listed["node"] is not None and listed["node"] != identity["node"]:
                    raise TaskPrivacyError(
                        "Proxmox task list node does not match its task identity"
                    )
                if alias in pending and pending[alias] != native:
                    raise TaskPrivacyError("Proxmox task aliases collide; response withheld")
                pending[alias] = native
                actor = identity["actor"]
                actors.add(actor)
                if row.get("user") not in (actor, actor.partition("!")[0]):
                    raise TaskPrivacyError("Proxmox task owner does not match its task identity")
        elif detail["suffix"] == "/status":
            if not isinstance(data, dict) or data.get("upid") != pending.get(detail["upid"]):
                raise TaskPrivacyError("Proxmox task status does not match its observed identity")
            identity = _parts(data["upid"])
            if data.get("user") not in (identity["actor"], identity["actor"].partition("!")[0]):
                raise TaskPrivacyError("Proxmox task status owner does not match its identity")
            actors.add(identity["actor"])
        result = self._scrub(envelope, actors)
        self.__native = pending
        self.__actors = actors
        return result
