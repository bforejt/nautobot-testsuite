"""Read-only Redfish client for the Lenovo XClarity Controller. GET is the only verb.

Same contract as RestconfClient — ``get(path, timeout=, ok_404=)``, a
``RedfishError`` carrying the HTTP status, ``ping()``/``probe_get()`` for
the reachability gate — so the CollectorContext's restconf slot takes it
unchanged and every ``xcc_*`` check shares the per-run cache.

Three things are specific to a BMC and live here:

- the path fence (``redfish_paths``) runs before every request, on literal
  paths and on server-supplied ``@odata.id`` links alike;
- GETs to one XCC are paced at least ``REDFISH_MIN_INTERVAL`` apart (SE350
  Redfish has been reported to go out of service under request stress);
- a per-check GET budget (``budget()``, reached through ``ctx.budget``):
  the GET that would exceed a declared budget raises instead of being sent,
  so a capture is complete-or-refused, never silently partial.

Authentication is HTTP Basic on every GET (``requests.Session.auth``): XCC
accepts it and no ``SessionService`` session is ever created. Depends only
on ``requests``.
"""

import json
import time

import requests
import urllib3
from requests.auth import AuthBase

from . import constants as C
from .redfish_paths import RedfishPathRefused, fence_path
from .transport_restconf import _is_tls_failure, _LegacyTlsAdapter


class RedfishError(Exception):
    """Redfish failure carrying the HTTP status (None for transport/fence errors)."""

    def __init__(self, message, status_code=None):
        super().__init__(message)
        self.status_code = status_code


class _Anonymous(AuthBase):
    """Leaves the request untouched — overrides the session's Basic auth for
    the one GET that must be anonymous (the service root probe)."""

    def __call__(self, request):
        return request


def probe_hint(record):
    """Operator-facing interpretation of a failed reachability probe record."""
    error = str((record or {}).get("error") or "")
    status = (record or {}).get("status")
    if _is_tls_failure(record):
        return (
            "TLS handshake refused by the XCC (default and legacy TLS both tried). "
            "Check the BMC's HTTPS certificate/TLS settings under BMC Configuration > "
            "Security in the XCC web UI."
        )
    if status == 401:
        return "HTTP 401 — credentials rejected; check the Secrets Group values."
    if status == 403:
        return (
            "HTTP 403 — authenticated but not authorized; the XCC user needs at least "
            "the ReadOnly role and Redfish access enabled."
        )
    if status == 404:
        return (
            "HTTP 404 — HTTPS answers but %s is absent; this is not an XCC (or its "
            "Redfish service is disabled)." % (C.REDFISH_PROBE_SYSTEM,)
        )
    if status is None:
        return "No HTTP response — TCP connectivity problem: %s" % (error or "unknown")
    return "HTTP %s from the XCC." % (status,)


class _GetBudget:
    """Context manager counting real GETs for one check against a declared cap."""

    def __init__(self, client, label, max_gets):
        self.client = client
        self.label = label
        self.max_gets = max_gets
        self.used = 0
        self._outer = None

    def charge(self, path):
        if self.used >= self.max_gets:
            raise RedfishError(
                "%s: GET budget of %d exhausted before %s — the collector would be "
                "silently partial; narrow it with $expand/$select or raise the budget"
                % (self.label, self.max_gets, path)
            )
        self.used += 1

    def __enter__(self):
        self._outer = self.client._budget
        self.client._budget = self
        return self

    def __exit__(self, exc_type, exc, tb):
        self.client._budget = self._outer
        return False


class RedfishClient:
    """One XCC, one session. Basic auth over HTTPS, JSON in, GET only."""

    transport_label = "redfish"

    def __init__(
        self, host, username, password, *, port=C.REDFISH_PORT, verify=C.VERIFY_TLS, logger=None
    ):
        self.host = host
        self.username = username
        self.base = "https://%s:%s" % (host, port)
        self.verify = verify
        self.logger = logger
        self.tls_mode = "default"
        self.gets = 0  # every GET sent, probes included — the AuditLog footprint
        self._last_request = None
        self._budget = None
        self.session = requests.Session()
        self.session.auth = (username, password)
        self.session.headers.update({"Accept": "application/json", "OData-Version": "4.0"})
        if not verify:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    def close(self):
        self.session.close()

    def enable_legacy_tls(self):
        """Mount the downgraded-TLS adapter for this session (verify-off only)."""
        self.session.mount("https://", _LegacyTlsAdapter())
        self.tls_mode = "legacy"

    def budget(self, label, max_gets):
        """``with client.budget("xcc_inventory", 16):`` — GETs inside count against the cap."""
        if not isinstance(max_gets, int) or max_gets < 1 or max_gets > C.REDFISH_MAX_CHECK_BUDGET:
            raise RedfishError(
                "%s: budget must be 1..%d GETs, got %r"
                % (label, C.REDFISH_MAX_CHECK_BUDGET, max_gets)
            )
        return _GetBudget(self, label, max_gets)

    def footprint(self):
        """What this capture did to the BMC, for the envelope's transport block."""
        return {"account": self.username, "gets": self.gets, "tls_mode": self.tls_mode}

    def _pace(self):
        """Never two GETs closer than REDFISH_MIN_INTERVAL to one XCC."""
        if self._last_request is not None:
            wait = self._last_request + C.REDFISH_MIN_INTERVAL - time.monotonic()
            if wait > 0:
                time.sleep(wait)
        self._last_request = time.monotonic()

    def _send(self, path, timeout, auth=None):
        """Fenced, paced, budgeted GET; returns the Response. Only place a request forms."""
        try:
            fenced = fence_path(path)
        except RedfishPathRefused as exc:
            raise RedfishError("GET %s: refused by the path fence: %s" % (path, exc)) from exc
        if self._budget is not None:
            self._budget.charge(fenced)
        self._pace()
        self.gets += 1
        kwargs = {"verify": self.verify, "timeout": (C.CONNECT_TIMEOUT, timeout)}
        if auth is not None:
            kwargs["auth"] = auth
        return self.session.get(self.base + fenced, **kwargs)

    def get(self, path, *, timeout=C.REDFISH_GET_TIMEOUT, ok_404=False):
        """GET a Redfish path. Returns parsed dict; {} on empty 2xx; None on 404 when ok_404.

        Raises RedfishError otherwise — including on a non-JSON 2xx body, so
        garbage can never masquerade as legitimate emptiness, and on a path
        the fence refuses (nothing is sent).
        """
        try:
            resp = self._send(path, timeout)
        except requests.RequestException as exc:
            raise RedfishError("GET %s: %s" % (path, exc)) from exc
        if resp.status_code == 404:
            if ok_404:
                return None
            raise RedfishError("GET %s: 404 not found" % (path,), status_code=404)
        if not resp.ok:
            raise RedfishError(
                "GET %s: HTTP %s" % (path, resp.status_code), status_code=resp.status_code
            )
        if resp.status_code == 204 or not resp.content:
            return {}
        try:
            return resp.json()
        except (json.JSONDecodeError, ValueError) as exc:
            raise RedfishError(
                "GET %s: 2xx with non-JSON body (%d bytes)" % (path, len(resp.content)),
                status_code=resp.status_code,
            ) from exc

    def probe_get(self, path, *, timeout=C.REDFISH_GET_TIMEOUT, anonymous=False):
        """Never-raising evidence recorder: {status, elapsed_ms, content_bytes, error}."""
        record = {
            "path": path,
            "status": None,
            "elapsed_ms": None,
            "content_bytes": 0,
            "error": None,
        }
        try:
            resp = self._send(path, timeout, auth=_Anonymous() if anonymous else None)
            record["status"] = resp.status_code
            record["elapsed_ms"] = int(resp.elapsed.total_seconds() * 1000)
            record["content_bytes"] = len(resp.content)
        except (requests.RequestException, RedfishError) as exc:
            record["error"] = str(exc)
        return record

    def _probe_all(self):
        """Service root anonymously (reachability, no login recorded), then the
        system resource with credentials (auth + role). Both must answer 2xx."""
        record = self.probe_get(C.REDFISH_SERVICE_ROOT, timeout=30, anonymous=True)
        if record["status"] is None or not 200 <= record["status"] < 300:
            return False, record
        record = self.probe_get(C.REDFISH_PROBE_SYSTEM, timeout=30)
        if record["status"] is not None and 200 <= record["status"] < 300:
            return True, record
        return False, record

    def ping(self):
        """True when the service root answers anonymously AND Systems/1 answers
        with the credentials. One legacy-TLS retry mirrors RestconfClient.ping
        (BMC HTTPS stacks are the classic TLS-1.3 casualties)."""
        ok, record = self._probe_all()
        if ok:
            return True
        if not self.verify and self.tls_mode == "default" and _is_tls_failure(record):
            if self.logger is not None:
                self.logger.warning(
                    "%s: default TLS handshake failed (%s) — retrying with legacy "
                    "TLS (max 1.2, relaxed ciphers).",
                    self.host,
                    record.get("error"),
                )
            self.enable_legacy_tls()
            ok, _ = self._probe_all()
            if ok:
                return True
        return False
