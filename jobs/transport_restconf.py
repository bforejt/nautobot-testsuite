"""Read-only RESTCONF client for IOS-XE. GET is the only verb in this module.

Modeled on the nautobot-upgrades RestconfClient, deliberately reduced to the
read half so the test suite's read-only guarantee is structural: there is no
method here that can change device state, and CI greps for write verbs.
Depends only on ``requests`` (present in every Nautobot worker).
"""

import json

import requests
import urllib3

from . import constants as C


class RestconfError(Exception):
    """RESTCONF failure carrying the HTTP status (None for transport errors)."""

    def __init__(self, message, status_code=None):
        super().__init__(message)
        self.status_code = status_code


class RestconfClient:
    """One device, one session. Basic auth over HTTPS, yang-data+json."""

    def __init__(
        self, host, username, password, *, port=C.RESTCONF_PORT, verify=C.VERIFY_TLS, logger=None
    ):
        self.host = host
        self.base = "https://%s:%s/restconf" % (host, port)
        self.verify = verify
        self.logger = logger
        self.session = requests.Session()
        self.session.auth = (username, password)
        self.session.headers.update(
            {
                "Accept": "application/yang-data+json",
                "Content-Type": "application/yang-data+json",
            }
        )
        if not verify:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    def close(self):
        self.session.close()

    def get(self, path, *, timeout=C.GET_TIMEOUT, ok_404=False):
        """GET a data path. Returns parsed dict; {} on empty 2xx; None on 404 when ok_404.

        Raises RestconfError otherwise — including on a non-JSON 2xx body, so
        garbage can never masquerade as legitimate emptiness.
        """
        url = self.base + path
        try:
            resp = self.session.get(url, verify=self.verify, timeout=(C.CONNECT_TIMEOUT, timeout))
        except requests.RequestException as exc:
            raise RestconfError("GET %s: %s" % (path, exc)) from exc
        if resp.status_code == 404:
            if ok_404:
                return None
            raise RestconfError("GET %s: 404 not found" % (path,), status_code=404)
        if not resp.ok:
            raise RestconfError(
                "GET %s: HTTP %s" % (path, resp.status_code), status_code=resp.status_code
            )
        if resp.status_code == 204 or not resp.content:
            return {}
        try:
            return resp.json()
        except (json.JSONDecodeError, ValueError) as exc:
            raise RestconfError(
                "GET %s: 2xx with non-JSON body (%d bytes)" % (path, len(resp.content)),
                status_code=resp.status_code,
            ) from exc

    def probe_get(self, path, *, timeout=C.GET_TIMEOUT):
        """Never-raising evidence recorder: {status, elapsed_ms, content_bytes, error}."""
        url = self.base + path
        record = {
            "path": path,
            "status": None,
            "elapsed_ms": None,
            "content_bytes": 0,
            "error": None,
        }
        try:
            resp = self.session.get(url, verify=self.verify, timeout=(C.CONNECT_TIMEOUT, timeout))
            record["status"] = resp.status_code
            record["elapsed_ms"] = int(resp.elapsed.total_seconds() * 1000)
            record["content_bytes"] = len(resp.content)
        except requests.RequestException as exc:
            record["error"] = str(exc)
        return record

    def ping(self):
        """True on a genuine 2xx from the device-hardware probe, or — fallback —
        from the RFC 8040-mandatory yang-library. One vendor model going
        missing on a given image must not read as "device unreachable"; both
        404ing means the DMI is not serving data at all.
        """
        for path in (C.DATA_DEVICE_SYSTEM, C.DATA_YANG_LIBRARY):
            record = self.probe_get(path, timeout=30)
            if record["status"] is not None and 200 <= record["status"] < 300:
                return True
        return False
