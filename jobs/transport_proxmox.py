"""Token-authenticated, fenced GET-only Proxmox VE HTTPS transport.

No login/logout, console, guest execution or write API operation is exposed.
All returned API envelopes pass through the family scrubber before they can
reach a context trace or cache. Errors carry status only, never server bodies,
request headers, session tokens, or exceptions that may echo credentials.
"""

import ipaddress
import json
import re
import time

import requests
import urllib3

from . import constants as C
from .proxmox_common import scrub
from .proxmox_paths import ProxmoxPathRefused, fence_path
from .proxmox_tasks import TaskAliases, TaskPrivacyError


class ProxmoxError(Exception):
    """Safe transport failure with an optional HTTP status."""

    def __init__(self, message, status_code=None, *, feature_absent=False, kind=None):
        super().__init__(message)
        self.status_code = status_code
        self.feature_absent = feature_absent
        self.kind = kind


class _GetBudget:
    def __init__(self, client, label, max_gets):
        self.client, self.label, self.max_gets = client, label, max_gets
        self.used = 0
        self.outer = None

    def __enter__(self):
        self.outer = self.client._budget
        self.client._budget = self
        return self

    def charge(self):
        if self.used >= self.max_gets:
            raise ProxmoxError("Proxmox GET budget exhausted before complete capture")
        self.used += 1

    def __exit__(self, exc_type, exc, tb):
        self.client._budget = self.outer
        return False


class ProxmoxClient:
    """One selected Proxmox endpoint; username is token ID, password token secret."""

    transport_label = "proxmox"

    def __init__(
        self, host, username, password, *, port=C.PROXMOX_PORT, verify=C.VERIFY_TLS, logger=None
    ):
        if not isinstance(host, str) or not host or any(char in host for char in "/@?#%"):
            raise ProxmoxError("Invalid Proxmox host")
        bare = host[1:-1] if host.startswith("[") and host.endswith("]") else host
        try:
            address = ipaddress.ip_address(bare)
            authority = "[%s]" % (bare,) if address.version == 6 else bare
        except ValueError:
            if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]*", host) is None:
                raise ProxmoxError("Invalid Proxmox host") from None
            authority = host
        if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
            raise ProxmoxError("Invalid Proxmox HTTPS port")
        if (
            not isinstance(username, str)
            or re.fullmatch(r"[A-Za-z0-9_.+-]+@[A-Za-z0-9_.-]+![A-Za-z0-9_.-]+", username) is None
        ):
            raise ProxmoxError("Proxmox username must be a full user@realm!token API token ID")
        if (
            not isinstance(password, str)
            or not password
            or any(ord(char) < 33 or ord(char) == 127 for char in password)
        ):
            raise ProxmoxError("Invalid Proxmox API token secret")
        self.host, self.username = host, username
        self.base = "https://%s:%d/api2/json" % (authority, port)
        self.verify, self.logger = verify, logger
        self.gets = 0
        self.last_probe = None
        self._last_http_status = None
        self._budget = None
        self.__tasks = TaskAliases()
        self.session = requests.Session()
        self.session.trust_env = False
        self.session.headers.update(
            {
                "Accept": "application/json",
                "Authorization": "PVEAPIToken=%s=%s" % (username, password),
            }
        )
        if not verify:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    def close(self):
        self.__tasks.clear()
        self.session.close()

    def public_path(self, path):
        return self.__tasks.public_path(path)

    def footprint(self):
        return {"account": self.username, "gets": self.gets, "tls_mode": "default"}

    def budget(self, label, max_gets):
        if (
            not isinstance(max_gets, int)
            or isinstance(max_gets, bool)
            or not (1 <= max_gets <= C.PROXMOX_MAX_CHECK_BUDGET)
        ):
            raise ProxmoxError("Invalid Proxmox GET budget")
        return _GetBudget(self, label, max_gets)

    def get(self, path, *, timeout=C.PROXMOX_GET_TIMEOUT, ok_404=False):
        try:
            request = fence_path(path)
            wire_request = fence_path(self.__tasks.wire_path(request))
        except (ProxmoxPathRefused, TaskPrivacyError):
            raise ProxmoxError("Proxmox GET refused by the read-only path fence") from None
        if self._budget is not None:
            self._budget.charge()
        self.gets += 1
        try:
            response = self.session.get(
                self.base + wire_request,
                verify=self.verify,
                timeout=(C.CONNECT_TIMEOUT, timeout),
                allow_redirects=False,
            )
        except requests.RequestException:
            raise ProxmoxError("Proxmox HTTPS request failed") from None
        status = response.status_code
        self._last_http_status = status
        if status == 404 and ok_404:
            return None
        if not 200 <= status < 300:
            absent = False
            kind = None
            journal = re.fullmatch(r"/nodes/[^/]+/journal", request.partition("?")[0])
            if status == 400 and journal:
                try:
                    body = response.json()
                    expected = (
                        "property is not defined in schema "
                        "and the schema does not allow additional properties"
                    )
                    absent = isinstance(body, dict) and body.get("errors") == {
                        "structured": expected
                    }
                    if absent:
                        kind = "structured-journal-unavailable"
                except (ValueError, TypeError):
                    pass
            if status == 500 and re.fullmatch(
                r"/nodes/[^/]+/ceph(?:/.*)?", request.partition("?")[0]
            ):
                candidates = [getattr(response, "reason", "")]
                try:
                    body = response.json()
                    if isinstance(body, dict):
                        candidates.append(body.get("message", ""))
                except (ValueError, TypeError):
                    pass
                absent = any(
                    isinstance(value, str)
                    and re.fullmatch(
                        r"(?:binary not installed: /usr/bin/ceph-mon|"
                        r"pveceph configuration not initialized - missing '/etc/pve/ceph.conf')\s*",
                        value,
                    )
                    is not None
                    for value in candidates
                )
                if absent:
                    kind = "ceph-not-initialized"
            raise ProxmoxError(
                "Proxmox GET HTTP %d" % (status,),
                status_code=status,
                feature_absent=absent,
                kind=kind,
            )
        try:
            if re.fullmatch(r"/nodes/[^/]+/journal", request.partition("?")[0]):
                envelope = json.loads(response.content.decode("utf-8", errors="strict"))
            else:
                envelope = response.json()
        except (ValueError, TypeError, UnicodeDecodeError):
            raise ProxmoxError("Proxmox GET returned invalid JSON", status_code=status) from None
        if not isinstance(envelope, dict) or "data" not in envelope:
            raise ProxmoxError("Proxmox GET returned an invalid API envelope", status_code=status)
        if envelope.get("success") in (0, False) or envelope.get("error") or envelope.get("errors"):
            raise ProxmoxError("Proxmox GET API source reported a failure", status_code=status)
        if re.fullmatch(r"/nodes/[^/]+/journal", request.partition("?")[0]):
            # Official mini-journalreader -J emits one complete JSON envelope,
            # gzip encoded by Nodes.pm; requests decodes the HTTP content layer.
            if (
                envelope.get("success") != 1
                or not isinstance(envelope["data"], list)
                or any(not isinstance(row, dict) for row in envelope["data"])
            ):
                raise ProxmoxError(
                    "Proxmox structured journal was incomplete or malformed", status_code=status
                )
            envelope = dict(envelope, source_format="proxmox-journal-json-envelope")
        try:
            return scrub(self.__tasks.envelope(request, envelope))
        except Exception as exc:
            if type(exc).__name__ == "SoftTimeLimitExceeded":
                raise
            raise ProxmoxError("Proxmox response withheld by redaction") from None

    def probe_get(self, path, *, timeout=C.PROXMOX_GET_TIMEOUT, **kwargs):
        """Never-raising status evidence; no response body or unsafe exception text."""
        record = {"path": None, "status": None, "elapsed_ms": None, "error": None}
        started = time.monotonic()
        try:
            request = fence_path(path)
            record["path"] = self.public_path(request)
            if kwargs:
                raise ProxmoxError("Unsupported Proxmox probe options")
            self.get(request, timeout=timeout)
            record["status"] = self._last_http_status
        except (ProxmoxPathRefused, ProxmoxError) as exc:
            record["status"] = getattr(exc, "status_code", None)
            record["error"] = str(exc)
        record["elapsed_ms"] = int((time.monotonic() - started) * 1000)
        self.last_probe = record
        return record

    def probe(self):
        record = {"path": "/version", "status": None, "elapsed_ms": None, "error": None}
        started = time.monotonic()
        try:
            envelope = self.get("/version")
            record["status"] = self._last_http_status
            data = envelope["data"]
            if (
                not isinstance(data, dict)
                or not isinstance(data.get("version"), str)
                or re.fullmatch(r"[0-9]+(?:\.[0-9]+)+(?:[-+][A-Za-z0-9_.-]+)?", data["version"])
                is None
            ):
                raise ProxmoxError("Selected endpoint did not report a Proxmox API version")
        except ProxmoxError as exc:
            record["status"] = exc.status_code or record["status"]
            record["error"] = str(exc)
            self.last_probe = record
            raise
        finally:
            record["elapsed_ms"] = int((time.monotonic() - started) * 1000)
            self.last_probe = record
        return record

    def ping(self):
        try:
            self.probe()
        except ProxmoxError:
            return False
        return True

    def discovery(self):
        """Actual safe probes of version, local node and effective visibility."""
        out = {"transport": self.transport_label, "sources": {}, "node": None}
        for path in ("/version", "/cluster/status", "/access/permissions"):
            try:
                envelope = self.get(path)
                out["sources"][path] = {"outcome": "complete", "envelope": envelope}
                if path == "/cluster/status":
                    data = envelope["data"]
                    if not isinstance(data, list) or any(not isinstance(row, dict) for row in data):
                        raise ProxmoxError("Invalid Proxmox cluster discovery list")
                    local = [
                        row
                        for row in data
                        if row.get("type") == "node" and row.get("local") in (True, 1, "1")
                    ]
                    if (
                        len(local) != 1
                        or re.fullmatch(
                            r"[A-Za-z0-9][A-Za-z0-9_.-]*", str(local[0].get("name") or "")
                        )
                        is None
                    ):
                        raise ProxmoxError("Proxmox discovery did not identify one local node")
                    out["node"] = local[0]["name"]
            except ProxmoxError as exc:
                out["sources"][path] = {
                    "outcome": "refused",
                    "status": exc.status_code,
                    "error": str(exc),
                }
        if out["node"] is not None:
            path = "/nodes/%s/capabilities" % (out["node"],)
            try:
                out["sources"][path] = {"outcome": "complete", "envelope": self.get(path)}
            except ProxmoxError as exc:
                out["sources"][path] = {
                    "outcome": "refused",
                    "status": exc.status_code,
                    "error": str(exc),
                }
        out["visibility"] = "effective ACLs and source outcomes; successful lists may be filtered"
        return out
