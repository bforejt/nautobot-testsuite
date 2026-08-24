"""Compare Snapshots job — diff a PRE capture against a POST capture.

Consumes the snapshot envelopes attached to two Capture Snapshot JobResults;
touches no device. Every comparison decision (modes, tolerance bands, the
capability doctrine) lives in diffcore — this job only pairs envelopes,
routes each check's two sides through diff_check, classifies diffs against
operator expectations, and renders/attaches one report per device pair.

Doctrine encoded here: a post-side collection failure is a finding (it can
mask a real outage), while a check that only exists post is never a finding
(new things need a baseline first).
"""

import json
from datetime import datetime, timezone

from nautobot.apps.jobs import BooleanVar, IntegerVar, Job, JSONVar, ObjectVar, StringVar
from nautobot.extras.choices import JobResultStatusChoices
from nautobot.extras.models import JobResult

from . import constants as C
from . import diffcore, envelope, registry
from .snapshot_job import CaptureSnapshot, _attach_artifact

# Jobs-UI grouping header (house convention).
name = C.UI_GROUP

# JobResult.name for capture runs — kept in lockstep with the capture job.
CAPTURE_NAME = getattr(CaptureSnapshot.Meta, "name", "Capture Snapshot")


def _read_fileproxy(fileproxy):
    """Bytes of one attached artifact; tolerates storages without .open()."""
    handle = fileproxy.file
    if hasattr(handle, "open"):
        handle.open("rb")
        try:
            return handle.read()
        finally:
            handle.close()
    return handle.read()


def _load_snapshots(job_result):
    """Load every snapshot envelope attached to a Capture Snapshot JobResult.

    Returns {device_name: envelope} — possibly empty (a dryrun capture
    attaches nothing; the CALLER decides whether an empty side is fatal).
    A corrupt artifact still raises: fail-closed, never silently skipped.
    """
    snapshots = {}
    for fileproxy in job_result.files.all():
        filename = getattr(fileproxy, "name", "") or ""
        if not filename.startswith("snapshot_"):
            continue
        try:
            env = json.loads(_read_fileproxy(fileproxy))
        except (ValueError, OSError) as exc:
            raise RuntimeError(
                "Artifact %s on JobResult %s is unreadable: %s" % (filename, job_result.pk, exc)
            ) from exc
        if not isinstance(env, dict) or "schema_version" not in env:
            raise RuntimeError(
                "Artifact %s on JobResult %s is not a snapshot envelope "
                "(no schema_version)." % (filename, job_result.pk)
            )
        device_name = (env.get("device") or {}).get("name")
        if not device_name:
            raise RuntimeError(
                "Artifact %s on JobResult %s has no device name." % (filename, job_result.pk)
            )
        snapshots[device_name] = env
    return snapshots


def _schema_major(version):
    """Prefix before the first '.' — the compatibility-gating half of the version."""
    return str(version or "").split(".", 1)[0]


def _render_entry(entry):
    """One human line for a diff entry or numeric-mode miss: 'key: field old -> new'."""
    key = entry.get("key")
    if key is None:
        key = entry.get("field")
    if "old" in entry or "new" in entry:
        field = entry.get("field")
        if field and entry.get("key") is not None:
            prefix = "%s: %s" % (key, field)
        else:
            prefix = "%s" % (key,)
        return "%s %s -> %s" % (prefix, entry.get("old"), entry.get("new"))
    if "value" in entry:
        return "%s: %s" % (key, entry.get("value"))
    return str(key)


def _miss_lines(body):
    """Human lines for a check body's unexpected diff entries and band/capability misses."""
    lines = []
    for bucket in ("added", "removed", "changed"):
        for entry in body.get(bucket) or []:
            if entry.get("classification") == "expected":
                continue
            lines.append("%s: %s" % (bucket, _render_entry(entry)))
    for entry in body.get("evaluations") or []:
        if entry.get("within") is False or entry.get("ok") is False:
            if entry.get("classification") == "expected":
                continue
            line = "out-of-band: %s" % (_render_entry(entry),)
            if entry.get("note"):
                line = "%s (%s)" % (line, entry["note"])
            lines.append(line)
    return lines


class CompareSnapshots(Job):
    """Diff pre vs post snapshot envelopes and attach one report per device pair."""

    change_id = StringVar(
        required=False,
        description=(
            "Auto-select ALL successful Capture Snapshot runs tagged with this "
            "change id — the same id you typed at capture time — merging their "
            "per-device snapshots per side (a change may span several capture "
            "runs). The explicit pickers below override per side."
        ),
    )
    pre_result = ObjectVar(
        model=JobResult,
        required=False,
        query_params={"name": [CAPTURE_NAME]},
        description=(
            "Explicit PRE-side pick (overrides change_id auto-selection). Nautobot's "
            "dropdown labels carry no change context — the run log echoes each "
            "side's change id and kind, so a mis-pick is visible immediately."
        ),
    )
    post_result = ObjectVar(
        model=JobResult,
        required=False,
        query_params={"name": [CAPTURE_NAME]},
        description="Explicit POST-side pick (overrides change_id auto-selection).",
    )
    device_map = JSONVar(
        required=False,
        description=(
            'Replacement mapping {"pre-device-name": "post-device-name"} for '
            "hardware-swap changes; unmapped devices pair by identical name."
        ),
    )
    expectations = JSONVar(
        required=False,
        description=(
            "List of expected-diff objects: {check, key glob, op "
            "added|removed|changed|any, device glob?, field?, to?, to_contains?, "
            "note?}. Diffs matching an expectation are reported as expected, not "
            "as findings; tolerance/capability misses match as op `changed`."
        ),
    )
    fail_on_unexpected = BooleanVar(
        default=False,
        description=(
            "Fail the JobResult when any unexpected diff remains. Leave off while "
            "tuning — unexpected diffs are reported either way."
        ),
    )
    baseline_max_age_hours = IntegerVar(
        default=C.BASELINE_MAX_AGE_H,
        min_value=0,
        description="Warn when the pre snapshot is older than this many hours (0 disables).",
    )

    class Meta:
        name = "Compare Snapshots"
        description = (
            "Pairs the snapshot envelopes attached to a PRE and a POST Capture "
            "Snapshot JobResult (by device name, or via `device_map` for hardware "
            "swaps), diffs every check under its recorded compare config, classifies "
            "each diff against the operator's expectations, and attaches one "
            "`report_*.json` per device pair. Touches no device."
        )
        has_sensitive_variables = False
        read_only = True
        # Budget: pure JSON diffing of already-attached artifacts, no device I/O.
        # 540s soft / 600s hard is generous even for dozens of pairs with
        # full-RIB-sized envelopes.
        soft_time_limit = 540
        time_limit = 600
        field_order = [
            "change_id",
            "pre_result",
            "post_result",
            "device_map",
            "expectations",
            "fail_on_unexpected",
            "baseline_max_age_hours",
        ]

    def run(
        self,
        *,
        change_id="",
        pre_result=None,
        post_result=None,
        device_map=None,
        expectations=None,
        fail_on_unexpected=False,
        baseline_max_age_hours=C.BASELINE_MAX_AGE_H,
    ):
        """Compare two capture runs. Every kwarg defaults (ScheduledJob rule)."""
        self.logger.info("Compare Snapshots starting — %s v%s", C.FRAMEWORK_NAME, C.JOB_VERSION)
        change_id = str(change_id or "").strip()
        if (pre_result is None or post_result is None) and not change_id:
            raise RuntimeError(
                "Provide a change_id (auto-selects all matching capture runs) "
                "or pick both pre_result and post_result explicitly."
            )
        pre_results, post_results = self._select_results(change_id, pre_result, post_result)
        if pre_result.pk == post_result.pk:
            self.logger.warning(
                "pre_result and post_result are the same JobResult — every check "
                "will trivially pass."
            )
        if device_map is not None and not isinstance(device_map, dict):
            raise RuntimeError('device_map must be a JSON object {"pre-name": "post-name"}.')
        mapping = device_map or {}
        if baseline_max_age_hours is None:
            baseline_max_age_hours = C.BASELINE_MAX_AGE_H

        pre_snaps = self._load_side("pre", pre_results)
        post_snaps = self._load_side("post", post_results)
        self._echo_sides(change_id, pre_snaps, post_snaps)

        want_major = _schema_major(C.SCHEMA_VERSION)
        for side, snaps in (("pre", pre_snaps), ("post", post_snaps)):
            for device_name in sorted(snaps):
                version = snaps[device_name].get("schema_version")
                if _schema_major(version) != want_major:
                    self.logger.warning(
                        "%s snapshot for %s has schema version %r; this code speaks "
                        "%s — comparing anyway, results may be unreliable.",
                        side,
                        device_name,
                        version,
                        C.SCHEMA_VERSION,
                    )

        # A malformed expectations payload must fail closed, exactly like
        # device_map: silently dropping the operator's plan would classify
        # every planned diff as unexpected during the window. One json.loads
        # heals the double-encoded-string case the UI can produce.
        if isinstance(expectations, str):
            try:
                expectations = json.loads(expectations)
            except ValueError as exc:
                raise RuntimeError(
                    "expectations is a string that is not valid JSON: %s" % (exc,)
                ) from exc
        if expectations is not None and not isinstance(expectations, list):
            raise RuntimeError(
                "expectations must be a JSON list of objects, got %s."
                % (type(expectations).__name__,)
            )
        expectation_list, problems = diffcore.normalize_expectations(expectations)
        for problem in problems:
            self.logger.warning("expectations: %s", problem)

        pairing_failures = []
        pairs = []
        used_post = set()
        for pre_name in sorted(pre_snaps):
            post_name = mapping.get(pre_name, pre_name)
            post_env = post_snaps.get(post_name)
            if post_env is None:
                pairing_failures.append(pre_name)
                self.logger.error(
                    "%s: no post snapshot named %r — check device_map or the post "
                    "run's device list.",
                    pre_name,
                    post_name,
                )
                continue
            used_post.add(post_name)
            pairs.append((pre_name, post_name, pre_snaps[pre_name], post_env))
        for post_name in sorted(set(post_snaps) - used_post):
            self.logger.info(
                "post-only snapshot %s has no pre baseline — ignored "
                "(new things are never findings).",
                post_name,
            )

        now = datetime.now(timezone.utc)
        totals = {"pairs": 0, "pass": 0, "diffs": 0, "unexpected": 0, "failed": 0, "unmatched": 0}

        # Phase 1: diff every pair, accumulating matches RUN-GLOBALLY. An
        # expectation is "not observed" only when NO pair matched it — a
        # per-device expectation matching its own device must not be reported
        # missing on every other device in the run.
        pair_outcomes = []
        global_matched = set()
        for pre_name, post_name, pre_env, post_env in pairs:
            label = "%s -> %s" % (pre_name, post_name) if pre_name != post_name else pre_name
            self._check_staleness(
                label, pre_env, post_env, now=now, max_age_hours=baseline_max_age_hours
            )
            applicable = diffcore.expectations_for_device(expectation_list, (pre_name, post_name))
            report, matched = self._compare_pair(label, pre_env, post_env, applicable)
            global_matched |= matched
            pair_outcomes.append((label, post_name, report, applicable))

        # Phase 2: finalize each report against the run-global match set,
        # attach, and accumulate totals.
        for label, post_name, report, applicable in pair_outcomes:
            pair_matched = {exp["id"] for exp in applicable if exp["id"] in global_matched}
            envelope.summarize_report(report, applicable, pair_matched)
            _attach_artifact(
                self,
                C.REPORT_FILENAME.format(device=envelope.safe_name(post_name)),
                report,
            )
            summary = report["summary"]
            totals["pairs"] += 1
            totals["pass"] += summary["checks_passed"]
            totals["diffs"] += summary["checks_with_diffs"]
            totals["unexpected"] += summary["unexpected"]
            totals["failed"] += summary["checks_failed"]
            self.logger.info(
                "%s: %d checks: %d pass, %d diffs (%d unexpected), %d failed; "
                "expectations unmatched: %d",
                label,
                summary["checks_total"],
                summary["checks_passed"],
                summary["checks_with_diffs"],
                summary["unexpected"],
                summary["checks_failed"],
                summary["expectations_unmatched"],
            )

        run_unmatched = [exp for exp in expectation_list if exp["id"] not in global_matched]
        totals["unmatched"] = len(run_unmatched)
        for exp in run_unmatched:
            self.logger.warning(
                "expectation %s matched nothing on any device (%s) — the change it "
                "anticipated was not observed.",
                exp["id"],
                exp.get("note") or "no note",
            )

        summary_text = (
            "Compared %(pairs)d device pair(s): %(pass)d checks pass, %(diffs)d with "
            "diffs (%(unexpected)d unexpected), %(failed)d failed; "
            "%(unmatched)d expectation(s) unmatched" % totals
        )
        if pairing_failures:
            raise RuntimeError(
                "Pairing failed for: %s (no matching post snapshot). %s"
                % (", ".join(pairing_failures), summary_text)
            )
        if totals["failed"]:
            # Fail-closed regardless of fail_on_unexpected: a failed post-side
            # read is an operational error that can mask a real outage, never a
            # tunable finding. The reports are already attached.
            raise RuntimeError(
                "%d check(s) failed to compare (collection failure on one side). %s"
                % (totals["failed"], summary_text)
            )
        if fail_on_unexpected and totals["unexpected"]:
            raise RuntimeError(
                "%d unexpected diff(s) with fail_on_unexpected set. %s"
                % (totals["unexpected"], summary_text)
            )
        return summary_text

    def _select_results(self, change_id, pre_result, post_result):
        """ALL successful capture runs whose stored kwargs carry change_id, per side.

        One change usually spans several capture runs (the Palo sweep in one
        run, the switches in another) — every matching run contributes, and
        _load_side merges their per-device snapshots (newest run wins per
        device). Explicit picks always win per side. With no plain post
        capture, the ROLLBACK captures serve as the post side (rollback-vs-pre
        proves restoration). task_kwargs exist because
        has_sensitive_variables=False.
        """
        if pre_result is not None and post_result is not None:
            return [pre_result], [post_result]
        candidates = JobResult.objects.filter(
            name=CAPTURE_NAME, status=JobResultStatusChoices.STATUS_SUCCESS
        ).order_by("-date_created")[: C.AUTOSELECT_SCAN_LIMIT]
        seen_change_ids = set()
        matches = []  # newest first, (kind, JobResult)
        for candidate in candidates:
            kwargs = candidate.task_kwargs if isinstance(candidate.task_kwargs, dict) else {}
            cid = str(kwargs.get("change_id") or "").strip()
            if cid:
                seen_change_ids.add(cid)
            if cid == change_id:
                matches.append((str(kwargs.get("kind") or "pre"), candidate))

        def matching(kinds):
            return [candidate for kind, candidate in matches if kind in kinds]

        pre_results = [pre_result] if pre_result is not None else matching(("pre",))
        if post_result is not None:
            post_results = [post_result]
        else:
            post_results = matching(("post",))
            if not post_results:
                post_results = matching(("rollback",))
                if post_results:
                    self.logger.warning(
                        "No post capture for change %r — using ROLLBACK capture(s) as "
                        "the post side (rollback verification).",
                        change_id,
                    )
        missing = [
            side for side, values in (("pre", pre_results), ("post", post_results)) if not values
        ]
        if missing:
            raise RuntimeError(
                "No successful Capture Snapshot run found for change %r (%s side). "
                "Change ids seen in the last %d capture runs: %s"
                % (
                    change_id,
                    " and ".join(missing),
                    C.AUTOSELECT_SCAN_LIMIT,
                    ", ".join(sorted(seen_change_ids)[:8]) or "none",
                )
            )
        return pre_results, post_results

    def _load_side(self, side, results):
        """Merge per-device snapshots across a side's runs; newest run wins.

        A run contributing nothing (a dryrun capture attaches no artifacts) is
        a warning, not fatal — but a side with nothing at all is. Corrupt
        artifacts raise from _load_snapshots regardless: fail-closed.
        """
        merged = {}
        for result in results:  # newest first
            snaps = _load_snapshots(result)
            if not snaps:
                self.logger.warning(
                    "%s side: JobResult %s has no snapshot artifacts (dryrun capture?) — skipped.",
                    side,
                    result.pk,
                )
                continue
            provided = []
            for name, env in snaps.items():
                if name in merged:
                    self.logger.warning(
                        "%s side: device %s already provided by a newer run — ignoring "
                        "the older copy in JobResult %s.",
                        side,
                        name,
                        result.pk,
                    )
                    continue
                merged[name] = env
                provided.append(name)
            if provided:
                self.logger.info(
                    "%s side: JobResult %s (created %s) provides %s.",
                    side,
                    result.pk,
                    result.date_created,
                    ", ".join(sorted(provided)),
                )
        if not merged:
            raise RuntimeError(
                "%s side has no snapshot artifacts across %d selected run(s) — were "
                "they dryrun captures?" % (side, len(results))
            )
        return merged

    def _echo_sides(self, change_id, pre_snaps, post_snaps):
        """Make every selection verifiable in the log — mis-picks must be visible."""
        for side, snaps in (("pre", pre_snaps), ("post", post_snaps)):
            kinds = sorted({str(env.get("kind")) for env in snaps.values()})
            cids = sorted({str(env.get("change_id")) for env in snaps.values()})
            self.logger.info(
                "%s side: %d device snapshot(s), change_id(s) %s, kind(s) %s.",
                side,
                len(snaps),
                ", ".join(cids),
                ", ".join(kinds),
            )
            if change_id and set(cids) - {change_id}:
                self.logger.warning(
                    "%s side carries change_id(s) %s, not %r — check the selection.",
                    side,
                    ", ".join(cids),
                    change_id,
                )
        if {str(env.get("kind")) for env in pre_snaps.values()} == {"post"}:
            self.logger.warning("pre side is a POST capture — the inputs may be swapped.")
        if {str(env.get("kind")) for env in post_snaps.values()} == {"pre"}:
            self.logger.warning("post side is a PRE capture — the inputs may be swapped.")

    def _check_staleness(self, label, pre_env, post_env, *, now, max_age_hours):
        """Warn on a stale baseline or swapped inputs; never blocks the compare."""
        pre_dt = envelope.parse_iso(pre_env.get("captured_at"))
        post_dt = envelope.parse_iso(post_env.get("captured_at"))
        if pre_dt is not None and max_age_hours:
            age_hours = (now - pre_dt).total_seconds() / 3600.0
            if age_hours > max_age_hours:
                self.logger.warning(
                    "%s: pre snapshot is %.1f h old (limit %d h) — the baseline may "
                    "no longer reflect the pre-change network.",
                    label,
                    age_hours,
                    max_age_hours,
                )
        if pre_dt is not None and post_dt is not None and post_dt < pre_dt:
            self.logger.warning(
                "%s: post snapshot was captured before the pre snapshot — the "
                "inputs are likely swapped.",
                label,
            )

    def _compare_pair(self, label, pre_env, post_env, expectation_list):
        """Build and log the diff report for one pair; return (report, matched_ids).

        The report is NOT summarized here — the caller finalizes it against the
        run-global expectation-match set once every pair has been diffed.
        """
        report = envelope.new_report(pre_env, post_env, device_label=label)
        matched_ids = set()
        pre_checks = pre_env.get("checks") or {}
        post_checks = post_env.get("checks") or {}
        for check_id in sorted(set(pre_checks) | set(post_checks)):
            pre_check = pre_checks.get(check_id)
            post_check = post_checks.get(check_id)
            pre_status = (pre_check or {}).get("status")
            post_status = (post_check or {}).get("status")
            expected_n = unexpected_n = 0

            if pre_status == "success" and post_status == "success":
                body = diffcore.diff_check(
                    pre_check.get("normalized") or {},
                    post_check.get("normalized") or {},
                    pre_check.get("compare") or post_check.get("compare"),
                )
                expected_n, unexpected_n = diffcore.classify_diff(
                    check_id, body, expectation_list, matched_ids
                )
            elif pre_status == "success":
                # Post side failed, went missing, or lost the feature: fail-closed,
                # because "could not read it" can mask "it is down".
                if post_status == "not-present":
                    note = "present in pre but not present in post"
                else:
                    note = "post collection failed — treat as possibly masking a real outage"
                body = {"result": "failed", "note": note}
                self.logger.error("%s: %s: %s", label, check_id, note)
            elif post_status == "success":
                body = {"result": "skipped", "note": "no pre baseline for this check"}
                self.logger.info(
                    "%s: %s: post-only, no pre baseline — skipped (new things are never findings).",
                    label,
                    check_id,
                )
            else:
                body = {"result": "skipped", "note": "not present on either side"}

            check_def = registry.CHECKS.get(check_id)
            if check_def is not None and body.get("result") in ("diffs", "failed"):
                body["description"] = check_def.description
                body["miss_meaning"] = check_def.miss_meaning
            report["checks"][check_id] = body

            self._log_check(label, check_id, body, expected_n, unexpected_n)

        return report, matched_ids

    def _log_check(self, label, check_id, body, expected_n, unexpected_n):
        """Per-check log line(s); failure branches log at their decision sites."""
        result = body.get("result")
        if result == "pass":
            self.logger.info("%s: %s: pass", label, check_id)
            return
        if result != "diffs":
            return
        # expected_n/unexpected_n come from classify_diff, which already counts
        # tolerance/capability misses — do not re-count evaluations here.
        self.logger.warning(
            "%s: %s: %d added / %d removed / %d changed (%d expected, %d unexpected)",
            label,
            check_id,
            len(body.get("added") or []),
            len(body.get("removed") or []),
            len(body.get("changed") or []),
            expected_n,
            unexpected_n,
        )
        lines = _miss_lines(body)
        for line in lines[:5]:
            self.logger.warning("%s: %s:   %s", label, check_id, line)
        if len(lines) > 5:
            self.logger.warning(
                "%s: %s:   ... and %d more (see the attached report)",
                label,
                check_id,
                len(lines) - 5,
            )
        if body.get("miss_meaning"):
            self.logger.warning("%s: %s: miss meaning: %s", label, check_id, body["miss_meaning"])
