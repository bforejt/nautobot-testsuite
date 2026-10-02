#!/usr/bin/env python3
"""Deterministic diff index over downloaded snapshot files — LLM recall insurance.

Judgment belongs to the engineer and their LLM; this tool only does the set
math no attention mechanism can guarantee over large tables. Run it locally
on snapshot files downloaded from the capture JobResults, and (optionally)
hand its output to the LLM alongside the snapshots so vanished routes,
appeared neighbors, and changed values arrive pre-enumerated instead of
being rediscovered by eyeball.

Usage:
    python3 tools/diff_snapshots.py --pre pre/*.json --post post/*.json \
        -o diff-index.json
    python3 tools/diff_snapshots.py --pre pre.zip --post post.zip -o diff-index.json

Each side accepts snapshot files, zip downloads, or a mixture (including all
parts of a split download). Zip snapshots are read directly, without extracting
files. Raw and debug siblings are ignored. Run manifests explain devices that
have no snapshot, including exclusions, controller coverage, and failed captures.

Devices pair by name across the two sides; unpaired devices (a replaced
firewall appears pre-only and post-only under different names) are listed as
replacement candidates for the analyst rather than force-matched. Stdlib
only — runs anywhere Python 3.9+ does, no Nautobot required.
"""

import argparse
import importlib
import json
import pathlib
import re
import sys
import types
import zipfile
import zlib

ROOT = pathlib.Path(__file__).resolve().parents[1]
# Import the pure jobs modules without executing jobs/__init__ (which needs
# Nautobot) — same synthetic-package trick the CI test battery uses.
_pkg = types.ModuleType("jobs")
_pkg.__path__ = [str(ROOT / "jobs")]
sys.modules.setdefault("jobs", _pkg)
diffcore = importlib.import_module("jobs.diffcore")
envelope = importlib.import_module("jobs.envelope")
bundle = importlib.import_module("jobs.bundle")


def _parse_snapshot(label, source, content):
    try:
        env = json.loads(content)
    except ValueError as exc:
        sys.exit("%s: unreadable snapshot %s: %s" % (label, source, exc))
    if not isinstance(env, dict) or "schema_version" not in env:
        sys.exit("%s: %s is not a snapshot envelope (no schema_version)" % (label, source))
    for field in ("device", "framework", "checks", "job"):
        if env.get(field) is not None and not isinstance(env[field], dict):
            sys.exit("%s: invalid snapshot %s: %s must be an object" % (label, source, field))
    name = (env.get("device") or {}).get("name")
    if name is not None and not isinstance(name, str):
        sys.exit("%s: invalid snapshot %s: device.name must be a string" % (label, source))
    run_id = (env.get("job") or {}).get("job_result_id")
    if run_id is not None and not isinstance(run_id, str):
        sys.exit("%s: invalid snapshot %s: job.job_result_id must be a string" % (label, source))
    for check_id, check in (env.get("checks") or {}).items():
        if not isinstance(check, dict):
            sys.exit(
                "%s: invalid snapshot %s: checks.%s must be an object" % (label, source, check_id)
            )
        for field in ("normalized", "compare", "describe"):
            if check.get(field) is not None and not isinstance(check[field], dict):
                sys.exit(
                    "%s: invalid snapshot %s: checks.%s.%s must be an object"
                    % (label, source, check_id, field)
                )
    return env


DISPOSITIONS = frozenset(
    {
        "capture",
        "excluded",
        "skipped_unsupported",
        "covered_by_controller",
        "controller_not_capturable",
    }
)


def _parse_manifest(label, source, content):
    try:
        manifest = json.loads(content)
    except ValueError as exc:
        sys.exit("%s: unreadable manifest %s: %s" % (label, source, exc))

    def invalid(message):
        sys.exit("%s: invalid manifest %s: %s" % (label, source, message))

    if not isinstance(manifest, dict):
        invalid("must be an object")
    if type(manifest.get("schema")) is not int or manifest["schema"] != 1:
        invalid("this tool requires manifest schema 1")
    for field in ("change_id", "job_result_id"):
        if not isinstance(manifest.get(field), str) or not manifest[field]:
            invalid("%s must be a nonempty string" % field)
    if manifest.get("kind") not in ("pre", "post", "rollback", "adhoc"):
        invalid("kind must be pre, post, rollback, or adhoc")
    started = envelope.parse_iso(manifest.get("started"))
    finished = envelope.parse_iso(manifest.get("finished"))
    if started is None:
        invalid("started must be a UTC timestamp")
    if manifest.get("finished") is not None and (finished is None or finished < started):
        invalid("finished must be a UTC timestamp at or after started")
    if not isinstance(manifest.get("devices"), list):
        invalid("devices must be a list")
    if not isinstance(manifest.get("inputs", {}), dict):
        invalid("inputs must be an object")
    if type(manifest.get("inputs", {}).get("dryrun", False)) is not bool:
        invalid("inputs.dryrun must be a boolean")
    seen = set()
    for row in manifest["devices"]:
        if not isinstance(row, dict) or not isinstance(row.get("name"), str) or not row["name"]:
            invalid("each device must be an object with a nonempty name")
        name = row["name"]
        if name in seen:
            invalid("duplicate device name %s" % name)
        seen.add(name)
        if not isinstance(row.get("disposition"), str) or row["disposition"] not in DISPOSITIONS:
            invalid("device %s has an unknown disposition" % name)
        if row.get("reason") is not None and not isinstance(row["reason"], str):
            invalid("device %s reason must be a string or null" % name)
        if row.get("outcome") not in (None, "succeeded", "failed", "not_visited"):
            invalid("device %s has an unknown outcome" % name)
    controllers = manifest.get("controllers", [])
    if not isinstance(controllers, list):
        invalid("controllers must be a list")
    for controller in controllers:
        if (
            not isinstance(controller, dict)
            or not isinstance(controller.get("name"), str)
            or not controller["name"]
        ):
            invalid("each controller must be an object with a nonempty name")
        for field in ("devices", "covers"):
            values = controller.get(field)
            if not isinstance(values, list) or any(not isinstance(value, str) for value in values):
                invalid("controller %s %s must be a list of names" % (controller["name"], field))
    return manifest


def _artifacts(label, path):
    """Yield source, basename, type, payload; archives are never extracted."""
    path = pathlib.Path(path)
    if path.suffix.lower() == ".zip":
        try:
            with zipfile.ZipFile(path) as archive:
                for member in sorted(archive.infolist(), key=lambda item: item.filename):
                    name = pathlib.PurePosixPath(member.filename).name
                    if (
                        not member.is_dir()
                        and name.endswith(".json")
                        and (name.endswith(".parts.json") or name.startswith("artifactpart_"))
                    ):
                        if name.startswith(("raw_", "debug_")) or (
                            name.startswith("artifactpart_") and not _snapshot_part(name)
                        ):
                            continue
                        source = "%s!%s" % (path, member.filename)
                        content = archive.read(member)
                        if name.endswith(".parts.json"):
                            yield source, name, "parts", json.loads(content)
                        else:
                            yield source, name, "part", content
                        continue
                    artifact_type = "snapshot" if name.startswith("snapshot_") else "manifest"
                    if (
                        member.is_dir()
                        or not name.endswith(".json")
                        or not name.startswith(("snapshot_", "manifest_"))
                    ):
                        continue
                    source = "%s!%s" % (path, member.filename)
                    try:
                        content = archive.read(member)
                    except (
                        OSError,
                        zipfile.BadZipFile,
                        RuntimeError,
                        NotImplementedError,
                        EOFError,
                        zlib.error,
                    ) as exc:
                        sys.exit("%s: unreadable %s %s: %s" % (label, artifact_type, source, exc))
                    parse = _parse_snapshot if artifact_type == "snapshot" else _parse_manifest
                    yield source, name, artifact_type, parse(label, source, content)
        except (OSError, UnicodeError, zipfile.BadZipFile, zipfile.LargeZipFile) as exc:
            sys.exit("%s: unreadable zip %s: %s" % (label, path, exc))
    else:
        if path.suffix == ".json" and path.name.startswith(("raw_", "debug_")):
            return
        if path.name.startswith("artifactpart_"):
            if _snapshot_part(path.name):
                yield str(path), path.name, "part", path.read_bytes()
            return
        if path.name.endswith(".parts.json"):
            yield str(path), path.name, "parts", json.loads(path.read_bytes())
            return
        artifact_type = "manifest" if path.name.startswith("manifest_") else "snapshot"
        try:
            content = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as exc:
            sys.exit("%s: unreadable %s %s: %s" % (label, artifact_type, path, exc))
        parse = _parse_snapshot if artifact_type == "snapshot" else _parse_manifest
        yield str(path), path.name, artifact_type, parse(label, str(path), content)


def _snapshot_part(name):
    return re.match(r"^artifactpart_[0-9a-f]{16}_snapshot_", name) is not None


def _reassembled_artifacts(label, paths):
    """Collect snapshot chunks across all zip/file inputs before verifying indexes."""
    parts, indexes = {}, []
    for path in paths:
        try:
            for source, name, kind, payload in _artifacts(label, path):
                if kind == "part":
                    if name in parts and parts[name] != payload:
                        sys.exit("%s: conflicting artifact part %s" % (label, name))
                    parts[name] = payload
                elif kind == "parts":
                    indexes.append((source, payload))
                else:
                    yield source, name, kind, payload
        except (OSError, ValueError, UnicodeError, zipfile.BadZipFile) as exc:
            sys.exit("%s: unreadable artifact %s: %s" % (label, path, exc))
    referenced = set()
    for source, index in indexes:
        try:
            name = index.get("artifact", "")
            if not isinstance(name, str) or not name.startswith("snapshot_"):
                continue
            data = bundle.reassemble(index, parts)
            referenced.update(part["name"] for part in index["parts"])
            yield source, name, "snapshot", _parse_snapshot(label, source, data)
        except (ValueError, TypeError, AttributeError, KeyError) as exc:
            sys.exit("%s: incomplete artifact %s: %s" % (label, source, exc))
    orphaned = sorted(set(parts) - referenced)
    if orphaned:
        sys.exit("%s: missing multipart index for artifact part %s" % (label, orphaned[0]))


def _load_side_data(label, paths, prefer_manifest=False):
    """Load newest snapshots and all run manifests independently."""
    side = {}
    manifests = {}
    tied = {}
    for source, basename, artifact_type, env in _reassembled_artifacts(label, paths):
        if artifact_type == "manifest":
            run_id = env["job_result_id"]
            held = manifests.get(run_id)
            if held is not None and held[1] != env:
                sys.exit("%s: conflicting manifests for job result %s" % (label, run_id))
            manifests[run_id] = (source, env)
            continue
        major = str(env.get("schema_version", "")).split(".", 1)[0]
        if major != "1":
            print(
                "warning: %s has schema %s; this tool speaks 1.x — results may "
                "be unreliable" % (source, env.get("schema_version")),
                file=sys.stderr,
            )
        name = (env.get("device") or {}).get("name") or basename
        held = side.get(name)
        if held is not None:
            new_at = envelope.parse_iso(env.get("captured_at"))
            held_at = envelope.parse_iso(held.get("captured_at"))
            if new_at is not None and held_at is not None and new_at <= held_at:
                if new_at == held_at:
                    tied.setdefault(name, [held]).append(env)
                continue
        side[name] = env
        tied.pop(name, None)
    if not side and not manifests:
        sys.exit("%s side: no snapshot envelopes loaded" % (label,))
    manifests = {run_id: held[1] for run_id, held in manifests.items()}
    if prefer_manifest:
        scopes = _latest_scopes(label, manifests)
        for name, candidates in tied.items():
            scope = scopes.get(name)
            if scope is not None:
                run_id = scope[1]["job_result_id"]
                for candidate in candidates:
                    if (candidate.get("job") or {}).get("job_result_id") == run_id:
                        side[name] = candidate
                        break
    return side, manifests


def _latest_scopes(label, manifests):
    """Newest stated disposition per device; separate split runs can coexist."""
    scopes = {}

    def stamp(manifest):
        return envelope.parse_iso(manifest["started"])

    for manifest in sorted(manifests.values(), key=stamp, reverse=True):
        at = stamp(manifest)
        for row in manifest["devices"]:
            held = scopes.get(row["name"])
            if held is None or at > held[0]:
                scopes[row["name"]] = (at, manifest, row)
            elif at == held[0] and manifest["job_result_id"] != held[1]["job_result_id"]:
                sys.exit(
                    "%s: ambiguous manifest run order for %s at %s; "
                    "supply one run's artifacts for that device"
                    % (label, row["name"], manifest["started"])
                )
    return scopes


def _load_side(label, paths):
    """{device_name: envelope} from files/zips; newest capture wins per device."""
    side, _manifest = _load_side_data(label, paths)
    if not side:
        sys.exit("%s side: no snapshot envelopes loaded" % (label,))
    return side


def _validate_run(label, side, manifests, scopes):
    """Do not pair a stale snapshot with a newer stated capture failure."""
    for manifest in manifests.values():
        if manifest.get("inputs", {}).get("dryrun"):
            sys.exit(
                "%s: manifest job result %s is a dry-run scope preview, "
                "not capture evidence; supply an actual capture run"
                % (label, manifest["job_result_id"])
            )
    for name, env in side.items():
        run_id = (env.get("job") or {}).get("job_result_id")
        scope = scopes.get(name)
        if scope is None:
            if run_id in manifests:
                sys.exit(
                    "%s: manifest job result %s does not list snapshot device %s"
                    % (label, run_id, name)
                )
            continue
        _at, manifest, row = scope
        if (
            run_id != manifest["job_result_id"]
            or env.get("change_id") != manifest["change_id"]
            or env.get("kind") != manifest["kind"]
            or row is None
            or row["disposition"] != "capture"
            or row.get("outcome") == "not_visited"
        ):
            sys.exit(
                "%s: snapshot for %s does not match latest manifest job result %s; "
                "supply snapshots and manifest from the same run"
                % (label, name, manifest["job_result_id"])
            )


def _scope_note(scopes, name):
    scope = scopes.get(name)
    if scope is None:
        return None
    _at, manifest, row = scope
    note = {field: row.get(field) for field in ("disposition", "reason", "outcome")}
    controllers = [
        controller for controller in manifest.get("controllers", []) if name in controller["covers"]
    ]
    if controllers:
        note["controllers"] = controllers
    return note


def _unpaired_note(env, scopes, field):
    note = _side_note(env)
    scope = _scope_note(scopes, note["device"])
    if scope is not None:
        note[field] = scope
    return note


def _missing_message(name, label, scope):
    if scope is None:
        question = "replaced or removed?" if label == "post" else "replacement or new?"
        return "%s: %s-only (%s)" % (name, "pre" if label == "post" else "post", question)
    disposition = scope["disposition"]
    if disposition == "capture":
        detail = "snapshot missing (capture outcome: %s) — unknown, not clean" % (
            scope["outcome"] or "unknown",
        )
    else:
        detail = disposition
    if scope.get("reason"):
        detail += ": " + scope["reason"]
    if scope.get("controllers"):
        detail += " (controller: %s)" % ", ".join(
            controller["name"] for controller in scope["controllers"]
        )
    return "%s: %s %s" % (name, label, detail)


def _missing_captures(side, scopes):
    """Supported capture evidence must remain visible without a baseline."""
    missing = []
    for name in sorted(scopes):
        _at, manifest, row = scopes[name]
        if name not in side and row["disposition"] == "capture":
            note = _scope_note(scopes, name)
            note.update({"device": name, "job_result_id": manifest["job_result_id"]})
            missing.append(note)
    return missing


def _side_note(env):
    return {
        "device": (env.get("device") or {}).get("name"),
        "kind": env.get("kind"),
        "change_id": env.get("change_id"),
        "captured_at": env.get("captured_at"),
    }


def _diff_pair(pre_env, post_env):
    """One report for a paired device: per-check added/removed/changed buckets."""
    report = envelope.new_report(pre_env, post_env, (pre_env.get("device") or {}).get("name"))
    pre_checks = pre_env.get("checks") or {}
    post_checks = post_env.get("checks") or {}
    for check_id in sorted(set(pre_checks) | set(post_checks)):
        pre_check = pre_checks.get(check_id)
        post_check = post_checks.get(check_id)
        pre_status = (pre_check or {}).get("status")
        post_status = (post_check or {}).get("status")
        if pre_status == "success" and post_status == "success":
            body = diffcore.diff_check(
                pre_check.get("normalized") or {},
                post_check.get("normalized") or {},
                pre_check.get("compare") or post_check.get("compare"),
            )
        elif pre_status == "success":
            body = {
                "result": "failed",
                "note": "post side did not collect (%s) — unknown, not clean" % (post_status,),
            }
        elif post_status == "success":
            body = {"result": "skipped", "note": "no pre baseline (pre side: %s)" % (pre_status,)}
        else:
            body = {"result": "skipped", "note": "not collected on either side"}
        describe = (pre_check or post_check or {}).get("describe") or {}
        if describe and body.get("result") in ("diffs", "failed"):
            body["describe"] = describe
        report["checks"][check_id] = body
    envelope.summarize_report(report)
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--pre", nargs="+", required=True, help="pre-change snapshot files or zips")
    parser.add_argument(
        "--post", nargs="+", required=True, help="post-change snapshot files or zips"
    )
    parser.add_argument("-o", "--out", help="write the index here (default: stdout)")
    args = parser.parse_args(argv)

    pre_side, pre_manifests = _load_side_data("pre", args.pre, prefer_manifest=True)
    post_side, post_manifests = _load_side_data("post", args.post, prefer_manifest=True)
    pre_scopes = _latest_scopes("pre", pre_manifests)
    post_scopes = _latest_scopes("post", post_manifests)
    _validate_run("pre", pre_side, pre_manifests, pre_scopes)
    _validate_run("post", post_side, post_manifests, post_scopes)

    index = {
        "note": (
            "Deterministic diff index over snapshot files: exhaustive set math, "
            "zero judgment. Interpretation belongs to the analyst — each entry "
            "cites the check and key it came from; the snapshot files remain the "
            "authority."
        ),
        "generated_at": envelope.utcnow_iso(),
        "pairs": {},
        "unpaired": {},
    }
    paired = sorted(set(pre_side) & set(post_side))
    for name in paired:
        report = _diff_pair(pre_side[name], post_side[name])
        for label, scopes in (("pre", pre_scopes), ("post", post_scopes)):
            scope = _scope_note(scopes, name)
            if scope is not None:
                report[label + "_scope"] = scope
        index["pairs"][name] = report
    pre_only = sorted(set(pre_side) - set(post_side))
    post_only = sorted(set(post_side) - set(pre_side))
    if pre_only or post_only:
        index["unpaired"] = {
            "note": (
                "Devices present on only one side — with a hardware replacement "
                "this is the replacement itself (compare these across sides by "
                "role, not identity)."
            ),
            "pre_only": [
                _unpaired_note(pre_side[name], post_scopes, "post_scope") for name in pre_only
            ],
            "post_only": [
                _unpaired_note(post_side[name], pre_scopes, "pre_scope") for name in post_only
            ],
        }
        if any("post_scope" in note for note in index["unpaired"]["pre_only"]) or any(
            "pre_scope" in note for note in index["unpaired"]["post_only"]
        ):
            index["unpaired"]["note"] += (
                " Scope metadata states exclusions, skips, controller coverage, "
                "or missing capture evidence; a missing capture is unknown, not clean."
            )

    missing = {
        "pre": _missing_captures(pre_side, pre_scopes),
        "post": _missing_captures(post_side, post_scopes),
    }
    if any(missing.values()):
        index["missing_snapshots"] = missing

    rendered = json.dumps(index, indent=1, sort_keys=True)
    if args.out:
        pathlib.Path(args.out).write_text(rendered + "\n")
    else:
        print(rendered)

    for name in paired:
        summary = index["pairs"][name]["summary"]
        print(
            "%s: %d checks — %d pass, %d with diffs (%d entries), %d failed"
            % (
                name,
                summary["checks_total"],
                summary["checks_passed"],
                summary["checks_with_diffs"],
                summary["diffs_total"],
                summary["checks_failed"],
            ),
            file=sys.stderr,
        )
        for label in ("pre", "post"):
            scope = index["pairs"][name].get(label + "_scope", {})
            if scope.get("outcome") in ("failed", "not_visited"):
                message = "%s: %s capture outcome %s — incomplete, unknown, not clean" % (
                    name,
                    label,
                    scope["outcome"],
                )
                if scope.get("reason"):
                    message += ": " + scope["reason"]
                print(message, file=sys.stderr)
    for name in pre_only:
        print(_missing_message(name, "post", _scope_note(post_scopes, name)), file=sys.stderr)
    for name in post_only:
        print(_missing_message(name, "pre", _scope_note(pre_scopes, name)), file=sys.stderr)
    for label, already_reported in (("pre", post_only), ("post", pre_only)):
        for scope in missing[label]:
            if scope["device"] not in already_reported:
                print(_missing_message(scope["device"], label, scope), file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
