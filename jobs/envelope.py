"""Snapshot-envelope and diff-report builders. Pure: stdlib only, no Nautobot.

The envelope is the on-disk contract between the capture and compare jobs —
strictly versioned (``schema_version``), loosely typed per check so that new
fields never require a schema-release event. Raw payloads live in a sibling
raw bundle keyed by check id; the envelope holds only normalized views.
"""

import re
from datetime import datetime, timezone

from . import constants as C

_SAFE = re.compile(r"[^A-Za-z0-9._-]+")


def safe_name(value):
    """Sanitize a device name / change id for use in an artifact filename."""
    return _SAFE.sub("-", str(value)).strip("-") or "unnamed"


def utcnow_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_iso(stamp):
    """Parse our own utcnow_iso() output; returns aware datetime or None."""
    try:
        return datetime.strptime(stamp, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except (TypeError, ValueError):
        return None


def new_envelope(device_info, change_id, kind, package, check_ids, job_info):
    """Start a snapshot envelope. ``device_info``/``job_info`` are plain dicts."""
    return {
        "schema_version": C.SCHEMA_VERSION,
        "kind": kind,
        "change_id": change_id,
        "captured_at": utcnow_iso(),
        "framework": {"name": C.FRAMEWORK_NAME, "version": C.JOB_VERSION},
        "job": job_info,
        "device": device_info,
        "package": package,
        "requested_checks": sorted(check_ids),
        "checks": {},
    }


def record_check(
    envelope, check, status, normalized=None, error=None, duration_s=None, collector_meta=None
):
    """Record one check's outcome into the envelope.

    status: success | failed | skipped | not-present. The check's effective
    compare config is copied in so pre and post can never disagree about how
    to compare.
    """
    envelope["checks"][check.id] = {
        "status": status,
        "error": error,
        "duration_s": round(duration_s, 2) if duration_s is not None else None,
        "tier": check.tier,
        "compare": check.compare,
        "collector": collector_meta or {},
        "normalized": normalized if normalized is not None else {},
    }


def envelope_summary(envelope):
    """Counts by status, for the capture job's mini-report."""
    counts = {}
    for result in envelope["checks"].values():
        counts[result["status"]] = counts.get(result["status"], 0) + 1
    return counts


def new_report(pre_env, post_env, device_label):
    return {
        "schema_version": C.SCHEMA_VERSION,
        "change_id": pre_env.get("change_id"),
        "device": device_label,
        "pre": {
            "device": (pre_env.get("device") or {}).get("name"),
            "captured_at": pre_env.get("captured_at"),
            "framework_version": (pre_env.get("framework") or {}).get("version"),
        },
        "post": {
            "device": (post_env.get("device") or {}).get("name"),
            "captured_at": post_env.get("captured_at"),
            "framework_version": (post_env.get("framework") or {}).get("version"),
        },
        "generated_at": utcnow_iso(),
        "summary": {},
        "checks": {},
        "expectations": {"matched": [], "unmatched": []},
    }


def summarize_report(report, expectations, matched_ids):
    """Fill the report's summary and unmatched-expectations blocks, in place."""
    checks = report["checks"]
    diffs_total = expected = unexpected = 0
    by_result = {}
    for body in checks.values():
        result = body.get("result", "unknown")
        by_result[result] = by_result.get(result, 0) + 1
        for bucket in ("added", "removed", "changed"):
            for entry in body.get(bucket) or []:
                diffs_total += 1
                if entry.get("classification") == "expected":
                    expected += 1
                else:
                    unexpected += 1
        for entry in body.get("evaluations") or []:
            if entry.get("within") is False or entry.get("ok") is False:
                diffs_total += 1
                if entry.get("classification") == "expected":
                    expected += 1
                else:
                    unexpected += 1
    unmatched = [
        {"id": exp["id"], "note": exp.get("note"), "status": "not_observed"}
        for exp in expectations
        if exp["id"] not in matched_ids
    ]
    report["expectations"]["matched"] = sorted(matched_ids)
    report["expectations"]["unmatched"] = unmatched
    report["summary"] = {
        "checks_total": len(checks),
        "checks_passed": by_result.get("pass", 0),
        "checks_with_diffs": by_result.get("diffs", 0),
        "checks_failed": by_result.get("failed", 0),
        "checks_skipped": by_result.get("skipped", 0) + by_result.get("info", 0),
        "diffs_total": diffs_total,
        "expected": expected,
        "unexpected": unexpected,
        "expectations_unmatched": len(unmatched),
    }
    return report
