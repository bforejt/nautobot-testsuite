"""Per-device collector context — the only thing a check collector receives.

Checks modules never import transports or Nautobot; they duck-type this
object. The capture job builds one per device with the right transports
attached. HTTP GETs and API calls are cached per run so multiple checks can
share one fetch of a big table (the RIB feeds both the route diff and the
rollups; ``config.network`` feeds every vSwitch/portgroup/vmknic check).

Three transport slots, all optional:

- ``restconf`` — any GET-shaped client: ``get(path, timeout=, ok_404=)``.
  The IOS-XE RestconfClient and the XCC RedfishClient both live here; the
  trace labels each entry with the client's ``transport_label`` (defaulting
  to ``restconf`` for the original client, which predates the attribute).
- ``ssh`` — an SshRunner (opened lazily on first use).
- ``api`` — an operation-shaped client: ``call(operation, **kwargs)``. The
  vSphere SOAP client lives here.

Because every device interaction flows through here, the context also keeps a
transport trace: one entry per GET / SSH command / API call with timing and
outcome. With ``debug=True`` each entry additionally carries the full payload
or output — the raw material for the Collector Shakedown job and for
harvesting test fixtures — at the cost of memory proportional to everything
fetched, so debug runs belong on one device at a time. An SSH read whose
output holds secrets (the configuration text) passes ``run_ssh`` a
``redact`` callable: the trace keeps only the redacted copy, the callable
never reaches the transport, and the SSH library's own DEBUG echo of the
channel is held back while the read runs.
"""

import contextlib
import logging
import threading
import time


def canonical_kwargs(kwargs):
    """Hashable, order-independent form of a kwargs dict for cache keys.

    Lists and tuples become tuples, dicts become sorted item tuples, sets
    become sorted tuples — recursively. A list-valued kwarg (a SOAP pathSet
    is naturally one) used to raise ``TypeError: unhashable type`` when the
    key was built from ``kwargs.items()`` directly (reproduced in the field
    on the first vmware collector); this is the regression guard.
    """
    return tuple(sorted((key, _canonical(value)) for key, value in kwargs.items()))


def _canonical(value):
    if isinstance(value, dict):
        return tuple(sorted((str(key), _canonical(item)) for key, item in value.items()))
    if isinstance(value, (list, tuple)):
        return tuple(_canonical(item) for item in value)
    if isinstance(value, (set, frozenset)):
        return tuple(sorted(_canonical(item) for item in value))
    return value


def _traced(redact, text):
    """The copy of ``text`` the trace may keep: ``redact(text)`` when a redactor is given.

    Fail-closed: a redactor that raises withholds the text instead of letting
    the verbatim copy through (the Celery soft-time-limit signal still
    propagates).
    """
    if redact is None or text is None:
        return text
    try:
        return redact(text)
    except Exception as exc:
        if type(exc).__name__ == "SoftTimeLimitExceeded":
            raise
        return "[withheld: redaction failed with %s]" % (type(exc).__name__,)


class _ChannelEchoGuard:
    """Holds the SSH library's loggers at INFO while any redacted read is in flight.

    netmiko writes every channel read into its DEBUG log ("read_channel:
    <data>", "Pattern found: ... <output>" — netmiko 4.7.0, all on its package
    logger), so a worker started at DEBUG would copy a redacted read's
    verbatim text into the worker log. Child loggers inherit the level; the
    first read in saves the levels, the last one out restores them.
    """

    def __init__(self, names):
        self.names = names
        self.lock = threading.Lock()
        self.depth = 0
        self.saved = {}

    @contextlib.contextmanager
    def held(self):
        with self.lock:
            if self.depth == 0:
                for name in self.names:
                    logger = logging.getLogger(name)
                    self.saved[name] = logger.level
                    if logger.getEffectiveLevel() < logging.INFO:
                        logger.setLevel(logging.INFO)
            self.depth += 1
        try:
            yield
        finally:
            with self.lock:
                self.depth -= 1
                if self.depth == 0:
                    for name, level in self.saved.items():
                        logging.getLogger(name).setLevel(level)
                    self.saved.clear()


_CHANNEL_ECHO = _ChannelEchoGuard(("netmiko",))


class CollectorContext:
    def __init__(
        self,
        device_name,
        platform,
        *,
        restconf=None,
        ssh=None,
        api=None,
        logger=None,
        debug=False,
    ):
        self.device_name = device_name
        self.platform = platform  # "iosxe" | "panos" | "vmware" | "xcc"
        self.restconf = restconf  # RestconfClient / RedfishClient or None
        self.ssh = ssh  # SshRunner or None (opened lazily)
        self.api = api  # VsphereClient or None
        self.logger = logger
        self.debug = debug
        self.trace = []  # transport trace, one dict per interaction
        self._cache = {}

    def get(self, path, **kwargs):
        """HTTP GET through the restconf-slot client, cached per run by (path, kwargs)."""
        if self.restconf is None:
            raise RuntimeError("no HTTP GET transport for %s" % (self.device_name,))
        label = getattr(self.restconf, "transport_label", "restconf")
        key = (label, path, canonical_kwargs(kwargs))
        if key in self._cache:
            self.trace.append({"transport": label, "target": path, "outcome": "cache-hit"})
            return self._cache[key]
        entry = {"transport": label, "target": path}
        if kwargs:
            entry["kwargs"] = dict(kwargs)
        started = time.monotonic()
        try:
            payload = self.restconf.get(path, **kwargs)
        except Exception as exc:
            entry["elapsed_ms"] = int((time.monotonic() - started) * 1000)
            entry["outcome"] = "error"
            entry["error"] = "%s: %s" % (type(exc).__name__, exc)
            self.trace.append(entry)
            raise
        entry["elapsed_ms"] = int((time.monotonic() - started) * 1000)
        # None is the ok_404 "path absent" result — cached like any other answer.
        entry["outcome"] = "ok" if payload is not None else "not-found"
        if self.debug:
            entry["payload"] = payload
        self.trace.append(entry)
        self._cache[key] = payload
        return payload

    def call(self, operation, **kwargs):
        """API operation through the api-slot client, cached per run by (operation, kwargs).

        Mirrors ``get()``: same outcomes (ok / not-found for a None answer /
        cache-hit / error), same debug payload capture. kwargs are recorded
        in the trace as given, so a client must never accept secrets through
        here (the vSphere client refuses Login/Logout via call() for exactly
        that reason).
        """
        if self.api is None:
            raise RuntimeError("no API transport for %s" % (self.device_name,))
        label = getattr(self.api, "transport_label", "api")
        key = (label, operation, canonical_kwargs(kwargs))
        if key in self._cache:
            self.trace.append({"transport": label, "target": operation, "outcome": "cache-hit"})
            return self._cache[key]
        entry = {"transport": label, "target": operation}
        if kwargs:
            entry["kwargs"] = dict(kwargs)
        started = time.monotonic()
        try:
            payload = self.api.call(operation, **kwargs)
        except Exception as exc:
            entry["elapsed_ms"] = int((time.monotonic() - started) * 1000)
            entry["outcome"] = "error"
            entry["error"] = "%s: %s" % (type(exc).__name__, exc)
            self.trace.append(entry)
            raise
        entry["elapsed_ms"] = int((time.monotonic() - started) * 1000)
        entry["outcome"] = "ok" if payload is not None else "not-found"
        if self.debug:
            entry["payload"] = payload
        self.trace.append(entry)
        self._cache[key] = payload
        return payload

    def run_ssh(self, command, *, redact=None, **kwargs):
        """Run one allowlisted operational command over SSH (opens lazily).

        ``redact`` (text -> text) is for a command whose output holds secrets:
        it is applied to the copy the debug trace keeps and to a traced error
        message, it holds the SSH library's DEBUG channel echo back for the
        duration of the read, and it is never passed to the transport. The
        caller still receives the verbatim output and owns redacting whatever
        it stores.
        """
        if self.ssh is None:
            raise RuntimeError("no SSH transport for %s" % (self.device_name,))
        entry = {"transport": "ssh", "target": command}
        started = time.monotonic()
        withheld = _CHANNEL_ECHO.held() if redact is not None else contextlib.nullcontext()
        try:
            with withheld:
                output = self.ssh.run(command, **kwargs)
        except Exception as exc:
            entry["elapsed_ms"] = int((time.monotonic() - started) * 1000)
            entry["outcome"] = "error"
            entry["error"] = _traced(redact, "%s: %s" % (type(exc).__name__, exc))
            self.trace.append(entry)
            raise
        entry["elapsed_ms"] = int((time.monotonic() - started) * 1000)
        entry["outcome"] = "ok"
        entry["chars"] = len(output or "")
        if self.debug:
            entry["output"] = _traced(redact, output)
        self.trace.append(entry)
        return output

    def budget(self, label, max_fetches):
        """Per-check fetch budget, when a transport offers one; a no-op otherwise.

        The Redfish client counts real GETs inside the ``with`` block and
        raises before the request that would exceed ``max_fetches`` (never
        silently partial). Cache hits never reach the client, so they never
        count. Transports without a budget concept (RESTCONF, SSH, SOAP)
        make this a null context, so collectors can declare a budget
        unconditionally.
        """
        for transport in (self.restconf, self.api):
            factory = getattr(transport, "budget", None)
            if factory is not None:
                return factory(label, max_fetches)
        return contextlib.nullcontext()

    @property
    def has_ssh(self):
        return self.ssh is not None

    @property
    def has_api(self):
        return self.api is not None

    def close(self):
        # Teardown is best-effort: a transport refusing to close cleanly must
        # never fail a job whose work already finished (field finding: a
        # completed shakedown went FAILED on teardown), and one transport's
        # tantrum must not skip closing the others.
        for transport in (self.restconf, self.ssh, self.api):
            if transport is None:
                continue
            try:
                transport.close()
            except Exception:
                pass
