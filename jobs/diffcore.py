"""Pure snapshot-comparison engine: dict in, dict out.

No Nautobot, no network, no third-party imports — stdlib only, so the CI test
battery can load and exercise every path here without a worker environment.

Vocabulary
----------
A *normalized view* is what a collector emits for one check: a flat dict whose
keys are stable natural identities ("default|0.0.0.0/0", "inside|10.0.0.1",
"trust|untrust") and whose values are scalars or one-level dicts of stable
fields. Volatile data (counters, ages, uptimes) is never emitted into a
normalized view — scrubbing happens at normalize time, not diff time.

A *compare config* declares how a check's normalized views are compared::

    {"mode": "equality_set",
     "fields": {"installed_prefixes": {"tolerance": {"abs": 3}}}}

Modes: equality_set, equality_scalar, tolerance, presence_only, capability,
info_only. ("activity" — counters that must advance across two post samples —
is reserved and not yet wired.)

The diff output shape is the report shape: added / removed / changed buckets
with old→new values, or per-field/per-key evaluations for the numeric modes.
"""

from fnmatch import fnmatchcase

MODES = (
    "equality_set",
    "equality_scalar",
    "tolerance",
    "presence_only",
    "capability",
    "info_only",
)


# --- normalization helpers ---------------------------------------------------


def scrub(obj, exclude_paths):
    """Delete dotted paths (with ``*`` wildcard segments) from a nested dict, in place.

    ``scrub(data, ["vrfs.*.routes.*.age", "*.uptime"])`` — used by collectors
    that pass structured raw data through generically. Returns ``obj``.
    """
    for path in exclude_paths:
        _scrub_one(obj, path.split("."))
    return obj


def _scrub_one(node, parts):
    if not parts or not isinstance(node, dict):
        return
    head, rest = parts[0], parts[1:]
    keys = list(node) if head == "*" else ([head] if head in node else [])
    for key in keys:
        if rest:
            _scrub_one(node[key], rest)
        else:
            node.pop(key, None)


# --- diff dispatch -----------------------------------------------------------


def diff_check(pre, post, compare):
    """Compare two normalized views under a compare config; return a diff dict.

    ``pre`` and ``post`` are the normalized views (dicts). The returned dict
    always carries ``result`` in {"pass", "diffs", "info"}; collection-level
    failures (a side missing entirely) are the caller's concern, not ours.
    """
    mode = (compare or {}).get("mode", "equality_set")
    if mode == "equality_set":
        return _diff_equality_set(pre, post, compare)
    if mode == "equality_scalar":
        return _diff_equality_scalar(pre, post)
    if mode == "tolerance":
        return _diff_tolerance(pre, post, compare)
    if mode == "presence_only":
        return _diff_presence(pre, post)
    if mode == "capability":
        return _diff_capability(pre, post, compare)
    if mode == "info_only":
        return {"result": "info"}
    raise ValueError("unknown compare mode: %r" % (mode,))


def _field_cfg(compare, field):
    fields = (compare or {}).get("fields") or {}
    cfg = fields.get(field)
    return cfg if isinstance(cfg, dict) else {}


def _within_band(old, new, band):
    """True when new is within a tolerance band of old.

    Band keys: ``abs`` (allowed absolute delta), ``pct`` (allowed percent delta
    of old), ``direction`` in {"min_only", "max_only"} — min_only tolerates any
    increase and bounds only decreases (and vice versa). Passing either bound
    is enough when both are given. With neither bound, any change is out.
    """
    delta = new - old
    direction = band.get("direction")
    if direction == "min_only" and delta >= 0:
        return True
    if direction == "max_only" and delta <= 0:
        return True
    allowed = []
    if band.get("abs") is not None:
        allowed.append(abs(delta) <= band["abs"])
    if band.get("pct") is not None:
        if old:
            allowed.append(abs(delta) / abs(old) * 100.0 <= band["pct"])
        else:
            # percent of zero is undefined; a pct-only band on a zero baseline
            # passes only when nothing appeared.
            allowed.append(new == 0)
    return any(allowed) if allowed else delta == 0


def _diff_equality_set(pre, post, compare):
    added, removed, changed = [], [], []
    pre_keys, post_keys = set(pre), set(post)
    for key in sorted(post_keys - pre_keys):
        added.append({"key": key, "value": post[key]})
    for key in sorted(pre_keys - post_keys):
        removed.append({"key": key, "value": pre[key]})
    for key in sorted(pre_keys & post_keys):
        old_val, new_val = pre[key], post[key]
        if old_val == new_val:
            continue
        if isinstance(old_val, dict) and isinstance(new_val, dict):
            for fld in sorted(set(old_val) | set(new_val)):
                a, b = old_val.get(fld), new_val.get(fld)
                if a == b:
                    continue
                band = _field_cfg(compare, fld).get("tolerance")
                if (
                    band is not None
                    and isinstance(a, (int, float))
                    and isinstance(b, (int, float))
                    and _within_band(a, b, band)
                ):
                    continue
                changed.append({"key": key, "field": fld, "old": a, "new": b})
        else:
            changed.append({"key": key, "field": None, "old": old_val, "new": new_val})
    result = "diffs" if (added or removed or changed) else "pass"
    return {"result": result, "added": added, "removed": removed, "changed": changed}


def _diff_equality_scalar(pre, post):
    changed = []
    for fld in sorted(set(pre) | set(post)):
        if pre.get(fld) != post.get(fld):
            changed.append({"key": fld, "field": None, "old": pre.get(fld), "new": post.get(fld)})
    return {
        "result": "diffs" if changed else "pass",
        "added": [],
        "removed": [],
        "changed": changed,
    }


def _diff_tolerance(pre, post, compare):
    """Numeric fields compared within declared bands; real values always reported.

    ``compare["band"]`` is the default band for fields without their own
    config — used by rollup checks whose field set is data-dependent.
    """
    default_band = (compare or {}).get("band") or {}
    fields = (compare or {}).get("fields") or {
        fld: {}
        for fld in sorted(set(pre) | set(post))
        if isinstance(pre.get(fld), (int, float)) or isinstance(post.get(fld), (int, float))
    }
    evaluations = []
    misses = 0
    for fld in sorted(fields):
        cfg = fields[fld] if isinstance(fields[fld], dict) else {}
        cfg = cfg or default_band
        old, new = pre.get(fld), post.get(fld)
        entry = {"field": fld, "old": old, "new": new}
        if not isinstance(old, (int, float)) or not isinstance(new, (int, float)):
            entry["within"] = None
            entry["note"] = "not numeric on both sides"
        else:
            entry["delta"] = new - old
            entry["delta_pct"] = round((new - old) / old * 100.0, 1) if old else None
            entry["within"] = _within_band(old, new, cfg)
            if not entry["within"]:
                misses += 1
        evaluations.append(entry)
    return {"result": "diffs" if misses else "pass", "evaluations": evaluations}


def _diff_presence(pre, post):
    added = [{"key": key} for key in sorted(set(post) - set(pre))]
    removed = [{"key": key} for key in sorted(set(pre) - set(post))]
    return {
        "result": "diffs" if (added or removed) else "pass",
        "added": added,
        "removed": removed,
        "changed": [],
    }


def _diff_capability(pre, post, compare):
    """Buckets meaningfully populated pre must be nonzero post.

    The point is capability, not parity: a pair that carried 1,842 sessions
    before needs only ``min_post`` after to prove the path works — zero means
    it does not.

    Sentinels: a ``None`` value means "present but unreadable" (the collector
    could not parse this bucket's count) and an absent key means "not measured
    on that side". Neither may masquerade as a measured zero: an unreadable
    pre leaves gating unknown (visible, never silently non-gating), and a
    gating bucket that is unreadable or unmeasured post fails closed.
    """
    floor = (compare or {}).get("floor_pre", 5)
    min_post = (compare or {}).get("min_post", 1)
    evaluations = []
    misses = 0
    for key in sorted(set(pre) | set(post)):
        old = pre.get(key)
        new = post.get(key)
        entry = {"key": key, "old": old, "new": new}
        if key not in pre:
            # New bucket post-side: never gating (new things are never findings).
            entry["gating"] = False
            entry["ok"] = None
        elif old is None:
            entry["gating"] = None
            entry["ok"] = None
            entry["note"] = "pre count unreadable — gating unknown"
        else:
            entry["gating"] = old >= floor
            if not entry["gating"]:
                entry["ok"] = None
            elif key not in post:
                entry["ok"] = False
                entry["note"] = "not measured post (sweep mismatch)"
            elif new is None:
                entry["ok"] = False
                entry["note"] = "post count unreadable"
            else:
                entry["ok"] = new >= min_post
        if entry["ok"] is False:
            misses += 1
        evaluations.append(entry)
    return {"result": "diffs" if misses else "pass", "evaluations": evaluations}


# --- expectations ------------------------------------------------------------


_SELECTOR_KEYS = ("check", "key", "op", "field", "to", "to_contains", "device")


def normalize_expectations(raw):
    """Validate a user-supplied expectations list; assign ids where missing.

    Returns (expectations, problems). Each expectation is a dict with keys:
    check (optional exact check id), key (glob, default "*"), op in
    {added, removed, changed, any}, optional device (glob on the device name),
    field / to / to_contains / note.

    An entry with no selector key at all (only id/note, or empty) is rejected:
    defaulting it would silently create a match-everything wildcard that
    blesses every diff on every device. A deliberate wildcard must say
    {"key": "*"} explicitly.
    """
    expectations, problems = [], []
    if raw is None:
        return expectations, problems
    if not isinstance(raw, list):
        return [], ["expectations must be a JSON list of objects"]
    for idx, exp in enumerate(raw):
        if not isinstance(exp, dict):
            problems.append("expectation #%d is not an object" % (idx + 1,))
            continue
        if not any(key in exp for key in _SELECTOR_KEYS):
            problems.append(
                "expectation #%d has no selector keys; add check/key/op/field "
                '(use {"key": "*"} for a deliberate wildcard)' % (idx + 1,)
            )
            continue
        exp = dict(exp)
        exp.setdefault("id", "exp-%d" % (idx + 1,))
        exp.setdefault("key", "*")
        op = exp.setdefault("op", "any")
        if op not in ("added", "removed", "changed", "any"):
            problems.append("expectation %s: unknown op %r" % (exp["id"], op))
            continue
        expectations.append(exp)
    return expectations, problems


def expectations_for_device(expectations, device_names):
    """Expectations whose optional ``device`` glob matches any of the names.

    Expectations without a device selector apply everywhere. Used by the
    compare job so an expectation scoped to one device is never reported as
    "not observed" on its neighbors.
    """
    out = []
    for exp in expectations:
        pattern = str(exp.get("device", "*"))
        if any(fnmatchcase(str(name), pattern) for name in device_names if name):
            out.append(exp)
    return out


def _expectation_matches(exp, check_id, op, entry):
    if exp.get("check") not in (None, check_id):
        return False
    if exp.get("op", "any") not in ("any", op):
        return False
    if not fnmatchcase(str(entry.get("key", "")), str(exp.get("key", "*"))):
        return False
    if exp.get("field") is not None and entry.get("field") != exp.get("field"):
        return False
    if op == "changed":
        if "to" in exp and entry.get("new") != exp["to"]:
            return False
        if "to_contains" in exp and str(exp["to_contains"]) not in str(entry.get("new")):
            return False
    return True


def classify_diff(check_id, diff, expectations, matched_ids):
    """Annotate a diff's entries expected/unexpected in place.

    Walks the added/removed/changed buckets AND the numeric-mode misses in
    ``evaluations`` (a tolerance/capability miss is matched as a "changed"
    entry — it carries old/new — keyed by its bucket key or field name), so a
    planned numeric change can be declared expected like any other diff.

    ``matched_ids`` is a set accumulated across checks so the report can list
    expectations that matched nothing ("expected but not observed").
    Returns (expected_count, unexpected_count).
    """
    expected = unexpected = 0
    for bucket, op in (("added", "added"), ("removed", "removed"), ("changed", "changed")):
        for entry in diff.get(bucket) or []:
            if _classify_entry(check_id, op, entry, entry, expectations, matched_ids):
                expected += 1
            else:
                unexpected += 1
    for entry in diff.get("evaluations") or []:
        if entry.get("within") is False or entry.get("ok") is False:
            match_view = dict(entry)
            if match_view.get("key") is None:
                match_view["key"] = match_view.get("field")
            if _classify_entry(check_id, "changed", match_view, entry, expectations, matched_ids):
                expected += 1
            else:
                unexpected += 1
    return expected, unexpected


def _classify_entry(check_id, op, match_view, entry, expectations, matched_ids):
    """Match one entry against the expectations; annotate it; True when expected."""
    for exp in expectations:
        if _expectation_matches(exp, check_id, op, match_view):
            entry["classification"] = "expected"
            entry["expectation_id"] = exp["id"]
            matched_ids.add(exp["id"])
            return True
    entry["classification"] = "unexpected"
    return False
