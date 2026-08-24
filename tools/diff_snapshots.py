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

Devices pair by name across the two sides; unpaired devices (a replaced
firewall appears pre-only and post-only under different names) are listed as
replacement candidates for the analyst rather than force-matched. Stdlib
only — runs anywhere Python 3.9+ does, no Nautobot required.
"""

import argparse
import importlib
import json
import pathlib
import sys
import types

ROOT = pathlib.Path(__file__).resolve().parents[1]
# Import the pure jobs modules without executing jobs/__init__ (which needs
# Nautobot) — same synthetic-package trick the CI test battery uses.
_pkg = types.ModuleType("jobs")
_pkg.__path__ = [str(ROOT / "jobs")]
sys.modules.setdefault("jobs", _pkg)
diffcore = importlib.import_module("jobs.diffcore")
envelope = importlib.import_module("jobs.envelope")


def _load_side(label, paths):
    """{device_name: envelope} from snapshot files; newest capture wins per device."""
    side = {}
    for path in paths:
        try:
            env = json.loads(pathlib.Path(path).read_text())
        except (OSError, ValueError) as exc:
            sys.exit("%s: unreadable snapshot %s: %s" % (label, path, exc))
        if not isinstance(env, dict) or "schema_version" not in env:
            sys.exit("%s: %s is not a snapshot envelope (no schema_version)" % (label, path))
        major = str(env.get("schema_version", "")).split(".", 1)[0]
        if major != "1":
            print(
                "warning: %s has schema %s; this tool speaks 1.x — results may "
                "be unreliable" % (path, env.get("schema_version")),
                file=sys.stderr,
            )
        name = (env.get("device") or {}).get("name") or pathlib.Path(path).name
        held = side.get(name)
        if held is not None:
            new_at = envelope.parse_iso(env.get("captured_at"))
            held_at = envelope.parse_iso(held.get("captured_at"))
            if new_at is not None and held_at is not None and new_at <= held_at:
                continue
        side[name] = env
    if not side:
        sys.exit("%s side: no snapshot envelopes loaded" % (label,))
    return side


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
    envelope.summarize_report(report, [], set())
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--pre", nargs="+", required=True, help="pre-change snapshot files")
    parser.add_argument("--post", nargs="+", required=True, help="post-change snapshot files")
    parser.add_argument("-o", "--out", help="write the index here (default: stdout)")
    args = parser.parse_args(argv)

    pre_side = _load_side("pre", args.pre)
    post_side = _load_side("post", args.post)

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
        index["pairs"][name] = _diff_pair(pre_side[name], post_side[name])
    pre_only = sorted(set(pre_side) - set(post_side))
    post_only = sorted(set(post_side) - set(pre_side))
    if pre_only or post_only:
        index["unpaired"] = {
            "note": (
                "Devices present on only one side — with a hardware replacement "
                "this is the replacement itself (compare these across sides by "
                "role, not identity)."
            ),
            "pre_only": [_side_note(pre_side[name]) for name in pre_only],
            "post_only": [_side_note(post_side[name]) for name in post_only],
        }

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
    for name in pre_only:
        print("%s: pre-only (replaced or removed?)" % (name,), file=sys.stderr)
    for name in post_only:
        print("%s: post-only (replacement or new?)" % (name,), file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
