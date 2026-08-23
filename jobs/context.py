"""Per-device collector context — the only thing a check collector receives.

Checks modules never import transports or Nautobot; they duck-type this
object. The capture job builds one per device with the right transports
attached. RESTCONF GETs are cached per run so multiple checks can share one
fetch of a big table (the RIB feeds both the route diff and the rollups).

Because every device interaction flows through here, the context also keeps a
transport trace: one entry per RESTCONF GET / SSH command with timing and
outcome. With ``debug=True`` each entry additionally carries the full payload
or output — the raw material for the Collector Shakedown job and for
harvesting test fixtures — at the cost of memory proportional to everything
fetched, so debug runs belong on one device at a time.
"""

import time


class CollectorContext:
    def __init__(self, device_name, platform, *, restconf=None, ssh=None, logger=None, debug=False):
        self.device_name = device_name
        self.platform = platform  # "iosxe" | "panos"
        self.restconf = restconf  # RestconfClient or None
        self.ssh = ssh  # SshRunner or None (opened lazily)
        self.logger = logger
        self.debug = debug
        self.trace = []  # transport trace, one dict per interaction
        self._cache = {}

    def get(self, path, **kwargs):
        """RESTCONF GET with a per-run cache keyed by (path, kwargs)."""
        if self.restconf is None:
            raise RuntimeError("no RESTCONF transport for %s" % (self.device_name,))
        key = (path, tuple(sorted(kwargs.items())))
        if key in self._cache:
            self.trace.append({"transport": "restconf", "target": path, "outcome": "cache-hit"})
            return self._cache[key]
        entry = {"transport": "restconf", "target": path}
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

    def run_ssh(self, command, **kwargs):
        """Run one allowlisted operational command over SSH (opens lazily)."""
        if self.ssh is None:
            raise RuntimeError("no SSH transport for %s" % (self.device_name,))
        entry = {"transport": "ssh", "target": command}
        started = time.monotonic()
        try:
            output = self.ssh.run(command, **kwargs)
        except Exception as exc:
            entry["elapsed_ms"] = int((time.monotonic() - started) * 1000)
            entry["outcome"] = "error"
            entry["error"] = "%s: %s" % (type(exc).__name__, exc)
            self.trace.append(entry)
            raise
        entry["elapsed_ms"] = int((time.monotonic() - started) * 1000)
        entry["outcome"] = "ok"
        entry["chars"] = len(output or "")
        if self.debug:
            entry["output"] = output
        self.trace.append(entry)
        return output

    @property
    def has_ssh(self):
        return self.ssh is not None

    def close(self):
        if self.restconf is not None:
            self.restconf.close()
        if self.ssh is not None:
            self.ssh.close()
