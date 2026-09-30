#!/usr/bin/env python3
"""GET-only crawl of one BMC's Redfish tree into a directory of JSON files.

The first thing to run on a new BMC vendor or firmware: it shows every
resource the service serves to the capture account, so the collectors and the
fixture set are designed against what is really there. Usage (from the
repository root; the address and the login come from the environment, never
from the command line, and are never printed or written):

    set -a; . /path/to/bmc.env; set +a
    python3 tools/redfish_walk.py --out /path/outside/the/repo/walk \\
        --host-env host --user-env username --password-env password \\
        [--pace 1.0] [--max 2500] [--audit]

Every request goes through ``jobs/transport_redfish.RedfishClient`` — the
worker's own transport — so the walk is GET-only, fenced (no ``Actions`` or
``SessionService`` segment, no percent-escape, ``/redfish/v1/`` only), paced
at least ``REDFISH_MIN_INTERVAL`` apart (``--pace`` may only slow it down) and
authenticated with HTTP Basic, so no BMC session is ever created. It follows
every ``@odata.id`` and ``Members@odata.nextLink`` it finds, and skips:
``JsonSchemas``, ``$metadata``/``odata`` documents, registry files under
``Registries/<id>/``, individual log entries (the ``Entries`` collection
already inlines them) and AuditLog entries unless ``--audit`` is given (the
capture never reads them: its own logins land there).

A resource whose file already exists in the output directory is read from
disk, so an interrupted walk resumes without touching the BMC again. The
output is one JSON file per resource plus ``_index.json`` (per resource:
status, elapsed, size, ``@odata.type``, member count, links refused by the
fence and links skipped). Everything saved is UNSANITIZED — log messages
carry user names and client addresses — so ``--out`` must be outside the
repository.
"""

import argparse
import collections
import importlib
import json
import logging
import os
import pathlib
import re
import sys
import time
import types

ROOT = pathlib.Path(__file__).resolve().parents[1]

# Segments the walk never follows although the fence would allow them: schema
# and metadata documents describe the protocol, not the server.
SKIPPED_SEGMENTS = frozenset({"jsonschemas", "$metadata", "odata"})
# Registry files, per-entry log resources (their collection inlines them).
SKIPPED_RE = re.compile(r"\.json$|/Registries/[^/]+/.+|/LogServices/[^/]+/Entries/[^/?]+$")
AUDIT_RE = re.compile(r"/LogServices/AuditLog/Entries", re.IGNORECASE)


def load_jobs():
    """Import the jobs modules through a synthetic package (no Nautobot)."""
    if "jobs" not in sys.modules:
        package = types.ModuleType("jobs")
        package.__path__ = [str(ROOT / "jobs")]
        sys.modules["jobs"] = package
    constants = importlib.import_module("jobs.constants")
    paths = importlib.import_module("jobs.redfish_paths")
    transport = importlib.import_module("jobs.transport_redfish")
    return constants, paths, transport


def find_links(node, acc):
    """Every ``@odata.id`` / ``Members@odata.nextLink`` string anywhere in ``node``."""
    if isinstance(node, dict):
        for key, value in node.items():
            if key in ("@odata.id", "Members@odata.nextLink") and isinstance(value, str):
                acc.append(value)
            else:
                find_links(value, acc)
    elif isinstance(node, list):
        for value in node:
            find_links(value, acc)
    return acc


def classify(link, fence, audit=False):
    """('follow', path) | ('refused', reason) | ('skipped', why) for one link.

    ``fence`` is ``redfish_paths.fence_path``: a link it refuses is recorded,
    never sent.
    """
    try:
        path = fence(link)
    except ValueError as exc:
        return "refused", str(exc)
    resource = path.split("?", 1)[0]
    segments = [segment.lower() for segment in resource.split("/")]
    if any(segment in SKIPPED_SEGMENTS for segment in segments):
        return "skipped", "schema or metadata document"
    if SKIPPED_RE.search(resource):
        return "skipped", "registry file or single log entry"
    if AUDIT_RE.search(resource) and not audit:
        return "skipped", "AuditLog entries (read only with --audit)"
    return "follow", path


def file_name(path):
    """One file per resource: the path's word characters with root spelled ``root``."""
    name = re.sub(r"[^A-Za-z0-9._-]+", "_", path.replace("/redfish/v1", "root")).strip("_")
    return (name or "root") + ".json"


def main(argv=None):
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--out", required=True, help="directory OUTSIDE the repository")
    parser.add_argument("--host-env", default="BMC_HOST", help="env var holding the address")
    parser.add_argument("--user-env", default="HARVEST_USER", help="env var holding the login")
    parser.add_argument(
        "--password-env", default="HARVEST_PASSWORD", help="env var holding the password"
    )
    parser.add_argument("--pace", type=float, default=None, help="seconds between GETs (>= 1)")
    parser.add_argument("--max", type=int, default=2500, help="stop after this many resources")
    parser.add_argument("--audit", action="store_true", help="also read AuditLog entries")
    args = parser.parse_args(argv)

    host = os.environ.get(args.host_env)
    username = os.environ.get(args.user_env)
    password = os.environ.get(args.password_env)
    if not host or not username or not password:
        parser.error(
            "set %s, %s and %s in the environment (never on the command line)"
            % (args.host_env, args.user_env, args.password_env)
        )
    out = pathlib.Path(args.out)
    if ROOT in out.resolve().parents or out.resolve() == ROOT:
        parser.error("--out must be outside the repository (the walk is unsanitized)")
    constants, paths, transport = load_jobs()
    pace = args.pace if args.pace is not None else constants.REDFISH_MIN_INTERVAL
    if pace < constants.REDFISH_MIN_INTERVAL:
        parser.error(
            "--pace may not go below REDFISH_MIN_INTERVAL (%s s)"
            % (constants.REDFISH_MIN_INTERVAL,)
        )
    out.mkdir(parents=True, exist_ok=True)

    logging.basicConfig(level=logging.ERROR)
    client = transport.RedfishClient(host, username, password, logger=logging.getLogger("walk"))
    if not client.ping():
        record = client.last_probe or client.probe_get(constants.REDFISH_SERVICE_ROOT, timeout=30)
        client.close()
        # A connection error names the address; the walk never prints it.
        hint = str(transport.probe_hint(record)).replace(host, "<host>")
        raise SystemExit("Redfish probe failed: %s" % (hint,))

    # A resumed walk keeps each resource's status from the previous index (a file
    # on disk may hold an error body); a resource without one reads "unknown".
    previous = {}
    if (out / "_index.json").exists():
        try:
            earlier = json.loads((out / "_index.json").read_text(encoding="utf-8"))
            previous = {item.get("path"): item.get("status") for item in earlier.get("index", [])}
        except ValueError:
            previous = {}
    queue = collections.deque([constants.REDFISH_SERVICE_ROOT])
    seen = set(queue)
    index = []
    fetched = 0
    started_walk = time.monotonic()
    try:
        while queue and len(index) < args.max:
            path = queue.popleft()
            target = out / file_name(path)
            entry = {"path": path, "file": target.name}
            if target.exists():
                payload = json.loads(target.read_text(encoding="utf-8"))
                entry.update(
                    status=previous.get(path, "unknown"),
                    from_disk=True,
                    ms=0,
                    bytes=target.stat().st_size,
                )
            else:
                extra = pace - constants.REDFISH_MIN_INTERVAL
                if extra > 0:
                    time.sleep(extra)
                started = time.monotonic()
                try:
                    # The client's one request site: fenced, paced, Basic auth, GET only.
                    resp = client._send(path, constants.REDFISH_GET_TIMEOUT)
                except Exception as exc:  # noqa: BLE001 - a walk records failures, it does not stop
                    # a connection error names the address; the index never does
                    error = str(exc).replace(host, "<host>")
                    index.append({"path": path, "status": None, "error": error})
                    print("ERR %s %s" % (path, type(exc).__name__), flush=True)
                    continue
                fetched += 1
                entry.update(
                    status=resp.status_code,
                    ms=int((time.monotonic() - started) * 1000),
                    bytes=len(resp.content),
                )
                try:
                    payload = resp.json()
                except ValueError:
                    payload = None
                    entry["nonjson"] = True
                body = payload
                if payload is None:
                    body = {"_text": resp.content.decode("utf-8", "replace")[:20000]}
                target.write_text(json.dumps(body, indent=1, sort_keys=True), encoding="utf-8")
            if isinstance(payload, dict):
                entry["odata_type"] = payload.get("@odata.type")
                members = payload.get("Members")
                entry["members"] = len(members) if isinstance(members, list) else None
                for link in find_links(payload, []):
                    link = link.split("#", 1)[0]
                    if not link or link.rstrip("/") == path.rstrip("/"):
                        continue
                    verdict, detail = classify(link, paths.fence_path, audit=args.audit)
                    if verdict != "follow":
                        entry.setdefault(verdict, []).append(link)
                        continue
                    if detail not in seen:
                        seen.add(detail)
                        queue.append(detail)
            index.append(entry)
            print(
                "%s %s %s %s"
                % (
                    entry.get("status"),
                    path,
                    "disk" if entry.get("from_disk") else "%dms" % entry.get("ms", 0),
                    entry.get("odata_type") or "",
                ),
                flush=True,
            )
    finally:
        client.close()
    summary = {
        "index": index,
        "queued_unvisited": list(queue),
        "fetched_this_run": fetched,
        "gets_sent": client.gets,
        "elapsed_s": int(time.monotonic() - started_walk),
    }
    (out / "_index.json").write_text(json.dumps(summary, indent=1), encoding="utf-8")
    statuses = collections.Counter(str(item.get("status")) for item in index)
    print(
        "done: %d resources (%d fetched this run, %d GETs incl. probes), %d unvisited; statuses %s"
        % (len(index), fetched, client.gets, len(queue), dict(sorted(statuses.items()))),
        flush=True,
    )
    return 0 if set(statuses) <= {"200"} else 1


if __name__ == "__main__":
    sys.exit(main())
