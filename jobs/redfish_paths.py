"""Redfish path fence — decides, before any request is formed, whether a path
may be fetched. Pure: stdlib only, loader-importable, CI-tested.

The XCC accepts state changes on many of the same resources it serves for
reading (Power, Bios, Manager network settings), so the transport is GET-only
by construction and this fence keeps the GETs inside the read-only surface:

- the path must start with ``/redfish/v1/`` (the service root itself is the
  only allowed bare form and is normalised to the trailing-slash spelling);
- no ``Actions`` segment (every Redfish action lives under ``.../Actions/``)
  and no ``SessionService`` segment (session creation is a state change and
  Basic auth makes it unnecessary);
- the query string may carry only ``$expand`` and ``$select`` (the two
  parameters the collectors use to keep GET counts down) and the two
  read-only page selectors a service puts in ``Members@odata.nextLink``,
  ``$skip`` and ``$skiptoken`` — never ``$top``, so a collector cannot choose
  a window and a continuation link that carries one is refused loudly;
- no percent-escapes: ``requests`` unquotes unreserved escapes before
  sending, so ``%41ctions`` would reach the BMC as ``Actions`` — XCC ids never
  need encoding, so any ``%`` is refused rather than decoded;
- no dot-segments, absolute URLs, whitespace or control characters.

The fence is applied to every path, including server-supplied ``@odata.id``
links — a firmware could hand back a link into ``Actions`` and a collector
following links blindly would otherwise send it. A fragment (``#/PowerSupplies/0``)
names a JSON pointer inside a resource, never a different request, so it is
stripped and the resource path is what the caller gets back.
"""

import re

REDFISH_ROOT = "/redfish/v1/"
ALLOWED_QUERY_PARAMS = frozenset({"$expand", "$select", "$skip", "$skiptoken"})

# RFC 3986 pchar minus pct-encoded: Redfish ids are alphanumerics with a
# few separators (`ob-1`, `DIMM_1`, `Slot_2.1`, `BMC-Primary`).
_PATH_RE = re.compile(r"/redfish/v1/[A-Za-z0-9._~!$&'()*+,;=:@/-]*")
_QUERY_VALUE_RE = re.compile(r"[A-Za-z0-9._,()$=*/@:-]+")
_BANNED_SEGMENTS = frozenset({"actions", "sessionservice"})


class RedfishPathRefused(ValueError):
    """Path did not pass the read-only fence; nothing was sent."""


def path_refusal(path):
    """None when ``path`` is allowed, else a short operator-facing reason."""
    if not isinstance(path, str):
        return "path is %s, not a string" % (type(path).__name__,)
    if not path:
        return "empty path"
    if any(ord(char) < 0x21 or ord(char) == 0x7F for char in path):
        return "whitespace or control character in path"
    resource, _, query = path.partition("?")
    resource = resource.split("#", 1)[0]
    if resource == REDFISH_ROOT.rstrip("/"):
        resource = REDFISH_ROOT
    if not resource.startswith(REDFISH_ROOT):
        return "path must start with %s" % (REDFISH_ROOT,)
    if "%" in resource:
        # The segment ban is checked on the spelling here, but the HTTP
        # library decodes unreserved escapes before the bytes leave, so
        # %41ctions would be sent as Actions. Refuse rather than decode.
        return "percent-encoding in path"
    if _PATH_RE.fullmatch(resource) is None:
        return "path contains characters outside the Redfish resource grammar"
    segments = resource[len(REDFISH_ROOT) :].split("/")
    for segment in segments:
        if segment in (".", ".."):
            return "dot-segment in path"
        if segment.lower() in _BANNED_SEGMENTS:
            return "%r segment is outside the read-only surface" % (segment,)
    if "//" in resource:
        return "empty segment in path"
    if query:
        for pair in query.split("&"):
            name, sep, value = pair.partition("=")
            if name not in ALLOWED_QUERY_PARAMS:
                return "query parameter %r is not allowlisted (%s only)" % (
                    name,
                    "/".join(sorted(ALLOWED_QUERY_PARAMS)),
                )
            if not sep or _QUERY_VALUE_RE.fullmatch(value) is None:
                return "query parameter %r has an unreadable value" % (name,)
    return None


def is_allowed_path(path):
    return path_refusal(path) is None


def fence_path(path):
    """Return the request path for an allowed ``path``; raise RedfishPathRefused otherwise.

    The returned path is what goes on the wire: fragment stripped, bare
    service root normalised to ``/redfish/v1/``.
    """
    reason = path_refusal(path)
    if reason is not None:
        raise RedfishPathRefused("%r refused: %s" % (path, reason))
    resource, sep, query = path.partition("?")
    resource = resource.split("#", 1)[0]
    if resource == REDFISH_ROOT.rstrip("/"):
        resource = REDFISH_ROOT
    return resource + sep + query
