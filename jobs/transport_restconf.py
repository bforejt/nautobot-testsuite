"""Read-only RESTCONF client for IOS-XE. GET is the only verb in this module.

Modeled on the nautobot-upgrades RestconfClient, deliberately reduced to the
read half so the test suite's read-only guarantee is structural: there is no
method here that can change device state, and CI greps for write verbs.
Depends only on ``requests`` (present in every Nautobot worker).
"""

import json
import ssl

import requests
import urllib3
from requests.adapters import HTTPAdapter

from . import constants as C


class RestconfError(Exception):
    """RESTCONF failure carrying the HTTP status (None for transport errors)."""

    def __init__(self, message, status_code=None):
        super().__init__(message)
        self.status_code = status_code


class _LegacyTlsAdapter(HTTPAdapter):
    """TLS 1.2-max, relaxed-cipher context for device HTTPS stacks that abort
    the default handshake with server alerts like TLSV1_ALERT_INTERNAL_ERROR
    (older nginx/OpenSSL builds mishandling a TLS 1.3 ClientHello, or pinned
    ``ip http tls-version`` / restricted ciphersuite configs).

    Only mounted when certificate verification is already off — the context
    disables verification, mirroring verify=False semantics.
    """

    def init_poolmanager(self, *args, **kwargs):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.maximum_version = ssl.TLSVersion.TLSv1_2
        try:
            ctx.set_ciphers("DEFAULT:@SECLEVEL=1")
        except ssl.SSLError:  # non-OpenSSL backends without SECLEVEL syntax
            pass
        ctx.options |= getattr(ssl, "OP_LEGACY_SERVER_CONNECT", 0x4)
        kwargs["ssl_context"] = ctx
        return super().init_poolmanager(*args, **kwargs)


def _is_tls_failure(record):
    error = str((record or {}).get("error") or "")
    return "SSL" in error or "TLS" in error


def probe_hint(record):
    """Operator-facing interpretation of a failed reachability probe record."""
    error = str((record or {}).get("error") or "")
    status = (record or {}).get("status")
    if _is_tls_failure(record):
        return (
            "TLS handshake refused by the device (default and legacy TLS both tried). "
            "On the switch check `show ip http server secure status` and "
            "`show crypto pki trustpoints` — a missing or broken self-signed "
            "certificate is the classic cause (bounce `ip http secure-server` to "
            "regenerate it); a pinned `ip http tls-version` or restricted "
            "`ip http secure-ciphersuite` is the other."
        )
    if status == 401:
        return "HTTP 401 — credentials rejected; check the Secrets Group values."
    if status == 403:
        return "HTTP 403 — authenticated but not authorized; RESTCONF requires privilege 15."
    if status == 404:
        return (
            "HTTP 404 — HTTPS is up but the DMI is not serving this data. If RESTCONF "
            "was enabled recently, `show platform software yang-management process` "
            "should show every process Running."
        )
    if status is None:
        return "No HTTP response — TCP connectivity problem: %s" % (error or "unknown")
    return "HTTP %s from the device." % (status,)


class RestconfClient:
    """One device, one session. Basic auth over HTTPS, yang-data+json."""

    def __init__(
        self, host, username, password, *, port=C.RESTCONF_PORT, verify=C.VERIFY_TLS, logger=None
    ):
        self.host = host
        self.base = "https://%s:%s/restconf" % (host, port)
        self.verify = verify
        self.logger = logger
        self.tls_mode = "default"
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

    def enable_legacy_tls(self):
        """Mount the downgraded-TLS adapter for this session (verify-off only)."""
        self.session.mount("https://", _LegacyTlsAdapter())
        self.tls_mode = "legacy"

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

    def _probe_all(self):
        record = None
        for path in (C.DATA_DEVICE_SYSTEM, C.DATA_YANG_LIBRARY):
            record = self.probe_get(path, timeout=30)
            if record["status"] is not None and 200 <= record["status"] < 300:
                return True, record
        return False, record

    def ping(self):
        """True on a genuine 2xx from the device-hardware probe, or — fallback —
        from the RFC 8040-mandatory yang-library. One vendor model going
        missing on a given image must not read as "device unreachable"; both
        404ing means the DMI is not serving data at all.

        A TLS-alert failure with verification already off is a device-side
        HTTPS-stack quirk (seen in the field: TLSV1_ALERT_INTERNAL_ERROR), so
        one retry runs in legacy TLS mode (1.2 max, relaxed ciphers) before
        the device is declared unreachable; the session keeps whichever mode
        worked for the rest of the run.
        """
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
