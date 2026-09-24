"""vim25 SOAP client for one standalone ESXi host — the suite's one POST-by-protocol transport.

SOAP is HTTP POST; the read-only guarantee for this file is therefore not
"GET only" but an operation allowlist: every envelope comes from
``vsphere_soap.build_envelope``, which forms bytes for exactly the six
operations in ``vsphere_soap.OPERATIONS`` and refuses anything else, and the
credential is a local ESXi user holding the built-in **Read-only** role so
hostd enforces the same fence server-side (a coding mistake yields
``NoPermissionFault``, not a change). CI's "SOAP operation guard" step pins
this file to exactly one ``session`` POST call, bans the other verbs, and
greps a mutating-name blocklist over this module and ``vsphere_soap``.

Session discipline: ``probe()`` reads ``/sdk/vimServiceVersions.xml``
(unauthenticated) to pick the SOAPAction version — the header is
``urn:vim25/<version>`` — then ``RetrieveServiceContent`` and refuses any
answer whose ``about.apiType`` is not ``HostAgent`` (a vCenter answering
would break the direct-host constraint, so it is enforced, not noted).
``login()``/``logout()`` run exactly once per capture and are the only path
for the Login/Logout operations, so credentials never pass through
``CollectorContext.call`` (whose trace records kwargs). ``footprint()``
self-declares account, login/logout outcome and call count so an auditor
can attribute the hostd ``UserLoginSessionEvent`` to the tool. Depends only
on ``requests``.
"""

import requests
import urllib3

from . import constants as C
from . import vsphere_soap as S
from .transport_restconf import _is_tls_failure, _LegacyTlsAdapter


class VsphereError(Exception):
    """vSphere failure carrying the HTTP status and the vim25 fault name (None when n/a)."""

    def __init__(self, message, status_code=None, fault=None):
        super().__init__(message)
        self.status_code = status_code
        self.fault = fault


def probe_hint(exc):
    """Operator-facing interpretation of a failed probe/login (a VsphereError or record dict)."""
    if isinstance(exc, VsphereError):
        record = {"error": str(exc), "status": exc.status_code, "fault": exc.fault}
    else:
        record = dict(exc or {})
    fault = record.get("fault")
    status = record.get("status")
    error = str(record.get("error") or "")
    if fault == "InvalidLoginFault":
        return (
            "InvalidLogin — hostd rejected the credentials. Either the Secrets Group "
            "values are wrong, or the host is in Normal/Strict lockdown mode (a local "
            "Read-only user cannot Login under lockdown; add it to the exception list "
            "or capture before lockdown is enabled)."
        )
    if fault == "NoPermissionFault":
        return (
            "NoPermission — the account authenticated but its role lacks the privilege "
            "for this read; assign the built-in Read-only role on the host."
        )
    if fault == "NotAuthenticatedFault":
        return (
            "NotAuthenticated — the session was dropped mid-capture (hostd restart or "
            "idle timeout)."
        )
    if _is_tls_failure(record):
        return (
            "TLS handshake refused by hostd (default and legacy TLS both tried). Check "
            "the host's rhttpproxy certificate and the UserVars.ESXiVPsDisabledProtocols "
            "advanced option."
        )
    if status == 404:
        return "HTTP 404 — HTTPS answers but /sdk is absent; this is not an ESXi host."
    if status == 503:
        return "HTTP 503 — hostd is starting or overloaded; retry after the host settles."
    if "apiType" in error:
        return error
    if status is None:
        return "No HTTP response — TCP connectivity problem: %s" % (error or "unknown")
    return "HTTP %s from the host: %s" % (status, error)


class VsphereClient:
    """One ESXi host, one session. Allowlisted vim25 operations over HTTPS."""

    transport_label = "vsphere"

    def __init__(
        self, host, username, password, *, port=C.VSPHERE_PORT, verify=C.VERIFY_TLS, logger=None
    ):
        self.host = host
        self.username = username
        self._password = password
        self.base = "https://%s:%s" % (host, port)
        self.verify = verify
        self.logger = logger
        self.tls_mode = "default"
        self.action = S.action_namespace(S.FALLBACK_VERSION)
        self.versions = None  # parsed vimServiceVersions.xml, None when unreadable
        self.content = None  # service content after probe()
        self.calls = 0  # every SOAP round trip, login/logout included
        self.login_ok = False
        self.logout_ok = None  # None until logout is attempted
        self.session = requests.Session()
        self.session.headers.update(
            {
                "Content-Type": "text/xml; charset=utf-8",
                "User-Agent": "%s/%s" % (C.FRAMEWORK_NAME, C.JOB_VERSION),
            }
        )
        if not verify:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    def enable_legacy_tls(self):
        """Mount the downgraded-TLS adapter for this session (verify-off only)."""
        self.session.mount("https://", _LegacyTlsAdapter())
        self.tls_mode = "legacy"

    def footprint(self):
        """What this capture did to the host, for the envelope's transport block."""
        about = (self.content or {}).get("about") or {}
        return {
            "account": self.username,
            "login_ok": self.login_ok,
            "logout_ok": self.logout_ok,
            "calls": self.calls,
            "action_namespace": self.action,
            "api_type": about.get("apiType"),
            "tls_mode": self.tls_mode,
        }

    # --- wire -----------------------------------------------------------------

    def _post_envelope(self, operation, envelope, timeout):
        """Send one built envelope; return the parsed XML root. The only request path."""
        url = self.base + C.VSPHERE_SDK_PATH
        headers = {"SOAPAction": '"%s"' % (self.action,)}
        self.calls += 1
        try:
            resp = self.session.post(
                url,
                data=envelope,
                headers=headers,
                verify=self.verify,
                timeout=(C.CONNECT_TIMEOUT, timeout),
            )
        except requests.RequestException as exc:
            raise VsphereError("%s: %s" % (operation, exc)) from exc
        try:
            fault_type, message = S.parse_fault(resp.content)
        except S.SoapParseError:
            fault_type = message = None
            if resp.ok:
                raise VsphereError(
                    "%s: HTTP %s with a non-SOAP body (%d bytes)"
                    % (operation, resp.status_code, len(resp.content)),
                    status_code=resp.status_code,
                ) from None
        if fault_type is not None:
            raise VsphereError(
                "%s: %s: %s" % (operation, fault_type, message),
                status_code=resp.status_code,
                fault=fault_type,
            )
        if not resp.ok:
            raise VsphereError(
                "%s: HTTP %s" % (operation, resp.status_code), status_code=resp.status_code
            )
        return resp.content

    def _invoke(self, operation, timeout=C.VSPHERE_CALL_TIMEOUT, **params):
        try:
            envelope = S.build_envelope(operation, S.NAMESPACE, **params)
        except S.SoapRefused as exc:
            raise VsphereError("%s refused before sending: %s" % (operation, exc)) from exc
        return self._post_envelope(operation, envelope, timeout)

    # --- session ----------------------------------------------------------------

    def _fetch_versions(self):
        """GET vimServiceVersions.xml; a never-raising record plus the parsed namespaces."""
        url = self.base + C.VSPHERE_VERSIONS_PATH
        record = {"path": C.VSPHERE_VERSIONS_PATH, "status": None, "error": None}
        try:
            resp = self.session.get(url, verify=self.verify, timeout=(C.CONNECT_TIMEOUT, 30))
            record["status"] = resp.status_code
            if resp.ok:
                try:
                    self.versions = S.parse_service_versions(resp.content)
                except S.SoapParseError as exc:
                    record["error"] = str(exc)
        except requests.RequestException as exc:
            record["error"] = str(exc)
        return record

    def probe(self):
        """Reachability + identity gate. Returns a probe record; raises VsphereError.

        Picks the SOAPAction version hostd advertises (falls back to the
        module's FALLBACK_VERSION and says so), then reads the service
        content and refuses a non-HostAgent answer.
        """
        record = self._fetch_versions()
        if (
            record["status"] is None
            and not self.verify
            and self.tls_mode == "default"
            and _is_tls_failure(record)
        ):
            if self.logger is not None:
                self.logger.warning(
                    "%s: default TLS handshake failed (%s) — retrying with legacy "
                    "TLS (max 1.2, relaxed ciphers).",
                    self.host,
                    record.get("error"),
                )
            self.enable_legacy_tls()
            record = self._fetch_versions()
        if record["status"] is None:
            raise VsphereError("GET %s: %s" % (C.VSPHERE_VERSIONS_PATH, record["error"]))
        if self.versions is not None:
            self.action = S.action_namespace(self.versions["version"])
            versions_source = C.VSPHERE_VERSIONS_PATH
        else:
            versions_source = "fallback (%s)" % (record["error"] or "HTTP %s" % record["status"],)
        body = self._invoke("RetrieveServiceContent", timeout=C.VSPHERE_LOGIN_TIMEOUT)
        try:
            content = S.parse_service_content(body)
        except S.SoapParseError as exc:
            raise VsphereError("RetrieveServiceContent: %s" % (exc,)) from exc
        api_type = (content.get("about") or {}).get("apiType")
        if api_type != C.VSPHERE_REQUIRED_API_TYPE:
            raise VsphereError(
                "%s answered with apiType=%r, not %r — the suite talks to ESXi hosts "
                "directly; point the Device's primary IP at the host, never at vCenter."
                % (self.host, api_type, C.VSPHERE_REQUIRED_API_TYPE)
            )
        self.content = content
        return {
            "versions_source": versions_source,
            "action_namespace": self.action,
            "prior_versions": (self.versions or {}).get("prior_versions"),
            "about": content.get("about"),
            "tls_mode": self.tls_mode,
        }

    def login(self):
        """Login once (locale fixed). Raises VsphereError; a second call is a bug."""
        if self.content is None:
            raise VsphereError("login() before probe()")
        if self.login_ok:
            raise VsphereError("login() called twice — one Login per capture")
        self._invoke(
            "Login",
            timeout=C.VSPHERE_LOGIN_TIMEOUT,
            session_manager=self.content["sessionManager"]["moid"],
            username=self.username,
            password=self._password,
            locale=C.VSPHERE_LOCALE,
        )
        self.login_ok = True

    def logout(self):
        """Logout once; records the outcome in logout_ok and re-raises."""
        if not self.login_ok or self.logout_ok is not None:
            return
        try:
            self._invoke(
                "Logout",
                timeout=C.VSPHERE_LOGIN_TIMEOUT,
                session_manager=self.content["sessionManager"]["moid"],
            )
        except VsphereError:
            self.logout_ok = False
            raise
        self.logout_ok = True

    def close(self):
        """Teardown: best-effort logout (logged, never raised), then drop the session."""
        try:
            self.logout()
        except VsphereError as exc:
            if self.logger is not None:
                self.logger.warning("%s: Logout failed: %s — ignored (teardown)", self.host, exc)
        finally:
            self.session.close()

    # --- operations -------------------------------------------------------------

    def call(self, operation, **kwargs):
        """Run one read operation; returns its parsed result.

        - RetrievePropertiesEx(type, moids, paths, traverse=, max_objects=,
          mask_short=, drain=True, timeout=) -> {"objects", "token", "pages"};
          with drain (the default) every continuation token is followed and
          token is None.
        - ContinueRetrievePropertiesEx(token, mask_short=, timeout=) -> one page.
        - QueryNetworkHint(network_system, devices=, timeout=) -> [PhysicalNicHintInfo].
        - RetrieveServiceContent() -> the service content dict.
        Login/Logout are refused here: use login()/logout().
        """
        if operation not in S.OPERATIONS:
            raise VsphereError("%r is not one of the six read-only operations" % (operation,))
        if operation in ("Login", "Logout"):
            raise VsphereError("%s goes through login()/logout(), never call()" % (operation,))
        if operation == "RetrieveServiceContent":
            timeout = kwargs.pop("timeout", C.VSPHERE_LOGIN_TIMEOUT)
            body = self._invoke(operation, timeout=timeout, **kwargs)
            return self._parse(operation, S.parse_service_content, body)
        if self.content is None or not self.login_ok:
            raise VsphereError("%s before probe()+login()" % (operation,))
        timeout = kwargs.pop("timeout", C.VSPHERE_CALL_TIMEOUT)
        if operation == "QueryNetworkHint":
            body = self._invoke(operation, timeout=timeout, **kwargs)
            return self._parse(operation, S.parse_returnval, body)
        mask_short = bool(kwargs.pop("mask_short", False))
        collector = self.content["propertyCollector"]["moid"]
        if operation == "ContinueRetrievePropertiesEx":
            body = self._invoke(operation, timeout=timeout, property_collector=collector, **kwargs)
            return self._parse(
                operation, lambda xml: S.parse_retrieve_result(xml, mask_short=mask_short), body
            )
        drain = bool(kwargs.pop("drain", True))
        body = self._invoke(operation, timeout=timeout, property_collector=collector, **kwargs)
        page = self._parse(
            operation, lambda xml: S.parse_retrieve_result(xml, mask_short=mask_short), body
        )
        page["pages"] = 1
        if not drain:
            return page
        while page["token"] is not None:
            if page["pages"] >= C.VSPHERE_MAX_PAGES:
                raise VsphereError(
                    "%s: continuation token still set after %d pages — refusing to spin"
                    % (operation, page["pages"])
                )
            body = self._invoke(
                "ContinueRetrievePropertiesEx",
                timeout=timeout,
                property_collector=collector,
                token=page["token"],
            )
            more = self._parse(
                "ContinueRetrievePropertiesEx",
                lambda xml: S.parse_retrieve_result(xml, mask_short=mask_short),
                body,
            )
            page["objects"].extend(more["objects"])
            page["token"] = more["token"]
            page["pages"] += 1
        return page

    def retrieve_properties(self, mo_type, moids, paths, **options):
        """Convenience: RetrievePropertiesEx drained -> the objects list.

        ``options`` pass through (traverse=, max_objects=, mask_short=, timeout=).
        """
        result = self.call(
            "RetrievePropertiesEx", type=mo_type, moids=list(moids), paths=list(paths), **options
        )
        return result["objects"]

    @staticmethod
    def _parse(operation, parser, body):
        try:
            return parser(body)
        except S.SoapParseError as exc:
            raise VsphereError("%s: %s" % (operation, exc)) from exc
