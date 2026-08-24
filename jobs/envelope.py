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


# Embedded in every snapshot so each artifact is SELF-DESCRIBING: a human or
# LLM holding one file needs nothing else to read it correctly. An engineer's
# test-plan prompt therefore never explains the data format — only the change.
INTERPRETATION_GUIDE = [
    "This file is a point-in-time operational snapshot of one network device, "
    "captured read-only. Compare two captures (before and after a change) to "
    "see what the change did.",
    "checks.<id>.normalized is the curated view: lists are re-keyed by stable "
    "natural identities and volatile data (counters, uptimes, ages, timestamps) "
    "is deliberately absent, so two healthy captures differ only where the "
    "network differs.",
    "Value sentinels — 0: a measured zero. null/None: the device answered but "
    "the value was unreadable (treat as unknown, never as zero). Key entirely "
    "absent: not measured on this capture. Never conflate the three.",
    "checks.<id>.status — success: data is trustworthy. failed: the READ failed; "
    "the data is missing, which says nothing about the network (treat as a "
    "caveat, never as 'everything vanished'). not-present: the feature is not "
    "configured/available on this device (a legitimate fact, not an error).",
    "checks.<id>.describe explains that check's key format and what was "
    "deliberately excluded; checks.<id>.context carries small curated "
    "measurements recorded at capture time (e.g. reconciliation totals).",
    "All counts are instantaneous at captured_at; two captures minutes apart "
    "differ by normal churn even on an unchanged network.",
    "Raw command/API output for every check is preserved in a sibling "
    "raw_<device>_<change_id>.json artifact on the same JobResult, keyed by "
    "check id — the audit trail when the normalized view raises questions.",
    "change_id tags every capture belonging to one change; kind records which "
    "side of the change (pre/post/rollback/adhoc) this capture was taken on; "
    "change_description is the operator's statement of what the change is.",
]


def new_envelope(device_info, change_id, kind, package, check_ids, job_info, change_description=""):
    """Start a snapshot envelope. ``device_info``/``job_info`` are plain dicts."""
    return {
        "schema_version": C.SCHEMA_VERSION,
        "guide": INTERPRETATION_GUIDE,
        "kind": kind,
        "change_id": change_id,
        "change_description": change_description,
        "captured_at": utcnow_iso(),
        "framework": {"name": C.FRAMEWORK_NAME, "version": C.JOB_VERSION},
        "job": job_info,
        "device": device_info,
        "package": package,
        "requested_checks": sorted(check_ids),
        "checks": {},
    }


def record_check(
    envelope,
    check,
    status,
    normalized=None,
    error=None,
    duration_s=None,
    collector_meta=None,
    describe=None,
    context=None,
):
    """Record one check's outcome into the envelope.

    status: success | failed | skipped | not-present. The check's effective
    compare config is copied in so pre and post can never disagree about how
    to compare. ``describe`` (description/semantics/miss_meaning) makes the
    entry self-describing; ``context`` carries the collector's small curated
    facts (never bulk data — that is what normalized and raw are for).
    """
    envelope["checks"][check.id] = {
        "status": status,
        "error": error,
        "duration_s": round(duration_s, 2) if duration_s is not None else None,
        "tier": check.tier,
        "compare": check.compare,
        "collector": collector_meta or {},
        "describe": describe or {},
        "context": context or {},
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
