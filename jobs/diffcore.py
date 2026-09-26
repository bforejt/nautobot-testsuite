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
info_only, text_diff. ("activity" — counters that must advance across two post samples —
is reserved and not yet wired.)

The diff output shape is the report shape: added / removed / changed buckets
with old→new values, or per-field/per-key evaluations for the numeric modes.

text_diff is for views holding whole texts as line lists ({"lines": [...]},
a device configuration): each contiguous run of changed lines — one hunk of
a zero-context unified diff between the two line lists — is its own
'changed' entry: field is the hunk's '@@ -a,b +c,d @@' header, old/new the
removed/added lines, and section the indentation parents of its first line
when that line is indented. Runs are matched line by line even where a line
repeats all over the text, and a stanza added or removed whole is lined up
to start at its own first line (see _text_opcodes), so an edit comes back as
a few entries an expectation can match, never one enormous changed value
(to_contains reads the added lines; a hunk that only removes lines is
matched by key and op). A text key added or removed whole carries
{"line_count": N} rather than the text (the snapshot files already hold it,
and a diff index that repeats whole configurations buries the finding);
every other value compares exactly as in equality_set.
"""

import difflib
from fnmatch import fnmatchcase

MODES = (
    "equality_set",
    "equality_scalar",
    "tolerance",
    "presence_only",
    "capability",
    "info_only",
    "text_diff",
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
    if mode == "text_diff":
        return _diff_text(pre, post, compare)
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


def _text_lines(value):
    """The line list of a text value ({"lines": [...]}) as strings; None for any other value."""
    if isinstance(value, dict) and isinstance(value.get("lines"), list):
        return [line if isinstance(line, str) else str(line) for line in value["lines"]]
    return None


def _text_summary(value):
    """A text value with its line list replaced by the count; any other value unchanged."""
    lines = _text_lines(value)
    if lines is None:
        return value
    summary = {field: item for field, item in value.items() if field != "lines"}
    summary["line_count"] = len(lines)
    return summary


def _unified_range(start, stop):
    """One side of a hunk header exactly as difflib.unified_diff prints it.

    1-based start and ',length' — the length is omitted when it is 1, and an
    empty range names the line just before it.
    """
    length = stop - start
    if length == 1:
        return "%d" % (start + 1,)
    return "%d,%d" % (start + 1 if length else start, length)


def _enclosing_lines(lines, wanted):
    """{index: [enclosing lines, outermost first]} for the wanted indexes, in one pass.

    A line's parents are the nearest preceding lines of smaller indentation
    (IOS-style hierarchical text); blank and '!' comment lines are never
    parents. A line at column 0 has none.
    """
    found = {}
    stack = []  # (indent, stripped line) of the stanzas currently open
    for index, line in enumerate(lines):
        text = line.strip()
        indent = len(line) - len(line.lstrip())
        if index in wanted:
            found[index] = [opener for level, opener in stack if level < indent]
            if len(found) == len(wanted):
                break
        if not text or text.startswith("!"):
            continue
        while stack and stack[-1][0] >= indent:
            stack.pop()
        stack.append((indent, text))
    return found


# difflib's autojunk heuristic (texts of 200+ lines) never anchors a match on
# a line repeating in more than 1% of the text — in a configuration '!',
# ' switchport mode access', ' spanning-tree portfast' — so two edits either
# side of such a line come back as ONE replace run that lists the untouched
# line as removed and re-added. Each replace run is re-matched without the
# heuristic; that match is quadratic, so a run is refined only up to this
# many line pairs, and one diff only up to the budget.
_TEXT_REFINE_CELLS = 250000
_TEXT_REFINE_BUDGET = 2000000


def _stanza_start_rank(line):
    """How badly a hunk starting on this line reads: a '!'/blank start worst, then deeper indent."""
    text = line.strip()
    return (not text or text.startswith("!"), len(line) - len(line.lstrip()))


def _slide_block(lines, start, stop, low, high):
    """Where a pure insert/delete block lines[start:stop] reads as whole stanzas: its new start.

    A block of added (or removed) lines can shift while it stays the same
    text: down while its first line equals the line after it, up while its
    last line equals the line before it, within the unchanged run [low, high)
    around it. difflib takes whichever alignment it met first, so a stanza
    added after a sibling that ends with the same lines comes back starting
    inside the sibling (its trailing lines, '!', then the new stanza's head).
    Of the equivalent positions, the block whose first line opens a stanza —
    least indented, not a '!' separator — wins; ties keep the topmost.
    """
    while start > low and lines[start - 1] == lines[stop - 1]:
        start, stop = start - 1, stop - 1
    best, best_rank = start, _stanza_start_rank(lines[start])
    while stop < high and lines[start] == lines[stop]:
        start, stop = start + 1, stop + 1
        rank = _stanza_start_rank(lines[start])
        if rank < best_rank:
            best, best_rank = start, rank
    return best


def _text_opcodes(old_lines, new_lines):
    """The non-equal (tag, i1, i2, j1, j2) runs of a line diff, one per hunk.

    difflib's line match, with each replace run re-matched without autojunk
    and each pure insert/delete block slid to stanza boundaries (both above).
    Neither changes what the hunks add up to: applying them to the old lines
    still gives the new ones.
    """
    budget = _TEXT_REFINE_BUDGET
    opcodes = []
    for tag, i1, i2, j1, j2 in difflib.SequenceMatcher(None, old_lines, new_lines).get_opcodes():
        cells = (i2 - i1) * (j2 - j1)
        if tag == "replace" and 1 < cells <= min(budget, _TEXT_REFINE_CELLS):
            budget -= cells
            finer = difflib.SequenceMatcher(
                None, old_lines[i1:i2], new_lines[j1:j2], autojunk=False
            ).get_opcodes()
            opcodes.extend((t, i1 + a1, i1 + a2, j1 + b1, j1 + b2) for t, a1, a2, b1, b2 in finer)
        else:
            opcodes.append((tag, i1, i2, j1, j2))
    runs = [list(opcode) for opcode in opcodes if opcode[0] != "equal"]
    for index, run in enumerate(runs):
        tag, i1, i2, j1, j2 = run
        if tag not in ("insert", "delete"):
            continue
        # The unchanged runs either side bound the slide (the previous run
        # has already settled where it ends).
        before = runs[index - 1] if index else None
        after = runs[index + 1] if index + 1 < len(runs) else None
        if tag == "insert":
            low = before[4] if before else 0
            high = after[3] if after else len(new_lines)
            shift = _slide_block(new_lines, j1, j2, low, high) - j1
        else:
            low = before[2] if before else 0
            high = after[1] if after else len(old_lines)
            shift = _slide_block(old_lines, i1, i2, low, high) - i1
        # Both sides move together: the unchanged runs around the block keep
        # equal lengths on either side.
        run[1:] = [i1 + shift, i2 + shift, j1 + shift, j2 + shift]
    return [tuple(run) for run in runs]


def _text_hunks(key, old_lines, new_lines):
    """One 'changed' entry per hunk of a zero-context line diff of two line lists.

    Zero context makes every hunk exactly one contiguous replace/insert/delete
    run (see _text_opcodes), so old/new are precisely the removed/added lines.
    'section' carries the hunk's enclosing stanza lines (post side when it
    added lines, pre side for a pure deletion) — the answer to "which
    interface was that?".
    """
    opcodes = _text_opcodes(old_lines, new_lines)
    new_anchors = {j1 for _tag, _i1, _i2, j1, j2 in opcodes if j2 > j1}
    old_anchors = {i1 for _tag, i1, _i2, j1, j2 in opcodes if j2 == j1}
    new_parents = _enclosing_lines(new_lines, new_anchors) if new_anchors else {}
    old_parents = _enclosing_lines(old_lines, old_anchors) if old_anchors else {}
    entries = []
    for _tag, i1, i2, j1, j2 in opcodes:
        entry = {
            "key": key,
            "field": "@@ -%s +%s @@" % (_unified_range(i1, i2), _unified_range(j1, j2)),
            "old": old_lines[i1:i2],
            "new": new_lines[j1:j2],
        }
        section = new_parents.get(j1) if j2 > j1 else old_parents.get(i1)
        if section:
            entry["section"] = section
        entries.append(entry)
    return entries


def _diff_text(pre, post, compare):
    """text_diff: line-level hunks for text values, equality_set for everything else.

    A key holding {"lines": [...]} on both sides yields one 'changed' entry per
    hunk (see _text_hunks); its other fields, if any, compare field by field.
    Every remaining key goes through equality_set with text values reduced to
    their line count, so added/removed/changed entries stay bounded however
    large the texts are.
    """
    text_keys = {
        key
        for key in set(pre) & set(post)
        if _text_lines(pre[key]) is not None and _text_lines(post[key]) is not None
    }
    rest_pre, rest_post = {}, {}
    for side, rest in ((pre, rest_pre), (post, rest_post)):
        for key, value in side.items():
            if key in text_keys:
                rest[key] = {field: item for field, item in value.items() if field != "lines"}
            else:
                rest[key] = _text_summary(value)
    diff = _diff_equality_set(rest_pre, rest_post, compare)
    for key in sorted(text_keys):
        diff["changed"].extend(_text_hunks(key, _text_lines(pre[key]), _text_lines(post[key])))
    diff["changed"].sort(key=lambda entry: str(entry.get("key")))
    diff["result"] = "diffs" if (diff["added"] or diff["removed"] or diff["changed"]) else "pass"
    return diff


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
