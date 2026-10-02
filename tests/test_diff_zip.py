"""Offline diff CLI: zip downloads and separate artifacts produce the same index."""

import contextlib
import importlib.util
import io
import json
import pathlib
import tempfile
import unittest
import zipfile
from unittest import mock

if __package__:
    from . import _loader
else:
    import _loader

_spec = importlib.util.spec_from_file_location(
    "diff_snapshots_zip_tests", _loader.ROOT / "tools" / "diff_snapshots.py"
)
diff_snapshots = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(diff_snapshots)


def _snapshot(
    name,
    kind="pre",
    normalized=None,
    captured_at="2026-10-01T01:00:00Z",
    job_result_id=None,
):
    env = _loader.envelope.new_envelope(
        {"name": name, "platform": "iosxe"},
        "CHG1",
        kind,
        "full",
        ["routes"],
        {"job_result_id": job_result_id or kind + "-run"},
    )
    env["captured_at"] = captured_at
    env["checks"]["routes"] = {
        "status": "success",
        "compare": {"mode": "equality_set"},
        "normalized": normalized or {},
        "describe": {"miss_meaning": "route disappeared"},
    }
    return env


def _manifest(kind, devices=(), job_result_id=None, started="2026-10-01T00:59:00Z", **kwargs):
    manifest = {
        "schema": 1,
        "change_id": "CHG1",
        "kind": kind,
        "job_result_id": job_result_id or kind + "-run",
        "started": started,
        "finished": "2026-10-01T03:00:00Z",
        "devices": [
            {
                "name": name,
                "disposition": "capture",
                "reason": None,
                "outcome": "succeeded",
            }
            if isinstance(name, str)
            else name
            for name in devices
        ],
        "controllers": [],
    }
    manifest.update(kwargs)
    return manifest


class TestZipDiff(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = pathlib.Path(self.temp.name)

    def _file(self, name, payload):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload), encoding="utf-8")
        return path

    def _zip(self, name, members, compression=zipfile.ZIP_DEFLATED):
        path = self.root / name
        with zipfile.ZipFile(path, "w", compression=compression) as archive:
            for member, payload in members.items():
                content = payload if isinstance(payload, bytes) else json.dumps(payload)
                archive.writestr(member, content)
        return path

    def _index(self, pre, post):
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(io.StringIO()):
            result = diff_snapshots.main(
                ["--pre"] + [str(path) for path in pre] + ["--post"] + [str(path) for path in post]
            )
        self.assertEqual(result, 0)
        index = json.loads(stdout.getvalue())
        index.pop("generated_at")
        for report in index["pairs"].values():
            report.pop("generated_at")
        return index

    def test_zip_and_unzipped_artifacts_have_identical_index(self):
        pre = {
            "pre/snapshot_core-1_CHG1.json": _snapshot(
                "core-1", normalized={"old": "a", "changed": "before"}
            ),
            "pre/snapshot_retired_CHG1.json": _snapshot("retired"),
            "pre/raw_core-1_CHG1.json": {"routes": "raw evidence"},
            "pre/debug_core-1_CHG1.json": {"calls": []},
            "pre/manifest_CHG1_pre.json": _manifest("pre", ["core-1", "retired"]),
        }
        post = {
            "post/snapshot_core-1_CHG1.json": _snapshot(
                "core-1", kind="post", normalized={"new": "b", "changed": "after"}
            ),
            "post/snapshot_replacement_CHG1.json": _snapshot("replacement", kind="post"),
            "post/raw_core-1_CHG1.json": {"routes": "raw evidence"},
            "post/manifest_CHG1_post.json": _manifest("post", ["core-1", "replacement"]),
        }
        pre_zip, post_zip = self._zip("pre.zip", pre), self._zip("post.zip", post)
        pre_files = [self._file(name, payload) for name, payload in pre.items()]
        post_files = [self._file(name, payload) for name, payload in post.items()]
        files_index = self._index(pre_files, post_files)
        with (
            mock.patch.object(zipfile.ZipFile, "extract", side_effect=AssertionError("extracted")),
            mock.patch.object(
                zipfile.ZipFile, "extractall", side_effect=AssertionError("extracted")
            ),
        ):
            zip_index = self._index([pre_zip], [post_zip])
        self.assertEqual(zip_index, files_index)
        routes = zip_index["pairs"]["core-1"]["checks"]["routes"]
        self.assertEqual([entry["key"] for entry in routes["added"]], ["new"])
        self.assertEqual([entry["key"] for entry in routes["removed"]], ["old"])
        self.assertEqual(routes["changed"][0]["old"], "before")
        self.assertEqual(zip_index["unpaired"]["pre_only"][0]["device"], "retired")
        self.assertEqual(zip_index["unpaired"]["post_only"][0]["device"], "replacement")

    def test_split_parts_mixed_with_files_use_newest_capture_in_any_order(self):
        old = _snapshot("core-1", normalized={"route": "old"})
        new = _snapshot("core-1", normalized={"route": "new"}, captured_at="2026-10-01T02:00:00Z")
        part1 = self._zip(
            "pre_part1of3.zip",
            {"pre/manifest_CHG1_pre.json": _manifest("pre", ["core-1", "edge-1"])},
        )
        part2 = self._zip("pre_part2of3.zip", {"pre/snapshot_core-1_CHG1.json": new})
        part3 = self._zip(
            "pre_part3of3.zip", {"pre/snapshot_edge-1_CHG1.json": _snapshot("edge-1")}
        )
        old_file = self._file("snapshot_core-1_CHG1.json", old)
        expected = {"core-1": new, "edge-1": _snapshot("edge-1")}
        for paths in ([part1, part2, part3, old_file], [old_file, part3, part2, part1]):
            with self.subTest(paths=paths):
                actual = diff_snapshots._load_side("pre", paths)
                self.assertEqual(actual, expected)

    def test_newest_duplicate_member_wins_and_equal_time_keeps_first(self):
        older = _snapshot("core-1")
        newer = _snapshot("core-1", normalized={"route": "new"}, captured_at="2026-10-01T02:00:00Z")
        same_time = _snapshot(
            "core-1", normalized={"route": "other"}, captured_at=newer["captured_at"]
        )
        archive = self._zip(
            "reruns.zip",
            {
                "pre/snapshot_a.json": newer,
                "pre/snapshot_b.json": older,
                "pre/snapshot_c.json": same_time,
            },
        )
        self.assertEqual(diff_snapshots._load_side("pre", [archive]), {"core-1": newer})

    def test_plain_files_keep_nonstandard_filename_and_nameless_fallback(self):
        env = _snapshot("core-1")
        plain = self._file("download.json", env)
        self.assertEqual(diff_snapshots._load_side("pre", [plain]), {"core-1": env})
        env["device"] = {}
        plain = self._file("snapshot_unnamed.json", env)
        archive = self._zip("nameless.zip", {"pre/snapshot_unnamed.json": env})
        self.assertEqual(
            diff_snapshots._load_side("pre", [plain]),
            diff_snapshots._load_side("pre", [archive]),
        )

    def test_zip_ignores_unrelated_members_and_directories(self):
        env = _snapshot("core-1")
        archive = self._zip(
            "pre.zip",
            {
                "pre/snapshot_core-1.json": env,
                "pre/snapshot_directory.json/": b"",
                "pre/raw_core-1.json": b"invalid JSON",
                "pre/debug_core-1.json": b"invalid JSON",
                "pre/manifest_CHG1_pre.json": _manifest("pre", ["core-1"]),
                "pre/unrelated.json": b"invalid JSON",
                "pre/snapshot_core-1.txt": b"invalid JSON",
            },
        )
        self.assertEqual(diff_snapshots._load_side("pre", [archive]), {"core-1": env})

    def test_known_unzipped_siblings_are_ignored_without_parsing(self):
        snapshot = self._file("snapshot_core-1.json", _snapshot("core-1"))
        siblings = []
        for name in ("raw_core-1.json", "debug_core-1.json"):
            path = self.root / name
            path.write_bytes(b"invalid JSON")
            siblings.append(path)
        self.assertEqual(set(diff_snapshots._load_side("pre", siblings + [snapshot])), {"core-1"})

    def test_empty_snapshot_side_is_an_error(self):
        for members in ({}, {"pre/manifest_CHG1_pre.json": _manifest("pre")}):
            with self.subTest(members=members):
                archive = self._zip("empty.zip", members)
                with self.assertRaisesRegex(SystemExit, "pre side: no snapshot envelopes loaded"):
                    diff_snapshots._load_side("pre", [archive])

    def test_unreadable_archive_identifies_side_and_path(self):
        broken = self.root / "broken.zip"
        broken.write_bytes(b"not a zip")
        for path in (broken, self.root / "missing.zip"):
            with self.subTest(path=path):
                with self.assertRaisesRegex(SystemExit, r"post: unreadable zip .*%s" % path.name):
                    diff_snapshots._load_side("post", [path])

    def test_corrupted_archive_member_is_a_useful_error(self):
        archive = self._zip(
            "corrupted.zip", {"pre/snapshot_core-1.json": _snapshot("core-1")}, zipfile.ZIP_STORED
        )
        with zipfile.ZipFile(archive) as handle:
            member = handle.infolist()[0]
            offset = (
                member.header_offset + 30 + len(member.filename.encode("utf-8")) + len(member.extra)
            )
        content = bytearray(archive.read_bytes())
        content[offset] ^= 1
        archive.write_bytes(content)
        with self.assertRaisesRegex(
            SystemExit, r"pre: unreadable snapshot .*corrupted.zip!pre/snapshot_core-1.json.*CRC"
        ):
            diff_snapshots._load_side("pre", [archive])

    def test_invalid_utf8_member_name_identifies_archive(self):
        archive = self._zip("bad-name.zip", {"pre/snapshot_\u00e9.json": _snapshot("core-1")})
        content = archive.read_bytes()
        self.assertEqual(content.count(b"\xc3\xa9"), 2)
        archive.write_bytes(content.replace(b"\xc3\xa9", b"\xff\xa9"))
        with self.assertRaisesRegex(SystemExit, r"pre: unreadable zip .*bad-name.zip"):
            diff_snapshots._load_side("pre", [archive])

    def test_malformed_json_or_envelope_identifies_archive_member(self):
        for payload, message in ((b"{", "unreadable snapshot"), ({}, "not a snapshot envelope")):
            with self.subTest(payload=payload):
                archive = self._zip("bad.zip", {"pre/snapshot_bad.json": payload})
                with self.assertRaisesRegex(
                    SystemExit, r"pre: .*bad.zip!pre/snapshot_bad.json"
                ) as caught:
                    diff_snapshots._load_side("pre", [archive])
                self.assertIn(message, str(caught.exception))

    def test_invalid_snapshot_structure_is_reported_for_both_formats(self):
        for field, bad in (("device", []), ("framework", []), ("checks", [])):
            env = _snapshot("core-1")
            env[field] = bad
            paths = [
                self._file("snapshot_bad.json", env),
                self._zip("bad.zip", {"pre/snapshot_bad.json": env}),
            ]
            for path in paths:
                with self.subTest(field=field, path=path):
                    with self.assertRaisesRegex(
                        SystemExit, "invalid snapshot .*%s must be an object" % field
                    ):
                        diff_snapshots._load_side("pre", [path])

    def test_invalid_check_structure_is_reported(self):
        cases = ["not an object", {"normalized": []}, {"compare": []}, {"describe": []}]
        for check in cases:
            with self.subTest(check=check):
                env = _snapshot("core-1")
                env["checks"]["routes"] = check
                archive = self._zip("bad.zip", {"pre/snapshot_bad.json": env})
                with self.assertRaisesRegex(SystemExit, "invalid snapshot .*checks.routes"):
                    diff_snapshots._load_side("pre", [archive])

    def test_invalid_device_name_is_reported(self):
        for name in (42, {"unexpected": "object"}):
            with self.subTest(name=name):
                env = _snapshot(name)
                archive = self._zip("bad.zip", {"pre/snapshot_bad.json": env})
                with self.assertRaisesRegex(SystemExit, "device.name must be a string"):
                    diff_snapshots._load_side("pre", [archive])

    def test_future_schema_still_warns_and_loads(self):
        env = _snapshot("core-1")
        env["schema_version"] = "2.0"
        archive = self._zip("future.zip", {"pre/snapshot_core-1.json": env})
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            actual = diff_snapshots._load_side("pre", [archive])
        self.assertEqual(actual, {"core-1": env})
        self.assertIn("future.zip!pre/snapshot_core-1.json has schema 2.0", stderr.getvalue())


class TestManifestDiff(unittest.TestCase):
    setUp = TestZipDiff.setUp
    _file = TestZipDiff._file
    _zip = TestZipDiff._zip
    _index = TestZipDiff._index

    def _row(self, name, disposition, reason=None, outcome=None):
        return {
            "name": name,
            "disposition": disposition,
            "reason": reason,
            "outcome": outcome,
        }

    def _missing_index(self, row, controllers=()):
        pre = self._file("snapshot_edge_pre.json", _snapshot("edge"))
        manifest = self._file(
            "manifest_CHG1_post.json", _manifest("post", [row], controllers=list(controllers))
        )
        return self._index([pre], [manifest])

    def test_each_non_capture_disposition_explains_pre_only_device(self):
        for disposition in (
            "excluded",
            "skipped_unsupported",
            "covered_by_controller",
            "controller_not_capturable",
        ):
            with self.subTest(disposition=disposition):
                row = self._row("edge", disposition, "modelled reason")
                index = self._missing_index(row)
                self.assertEqual(
                    index["unpaired"]["pre_only"][0]["post_scope"],
                    {
                        "disposition": disposition,
                        "reason": "modelled reason",
                        "outcome": None,
                    },
                )
                message = diff_snapshots._missing_message("edge", "post", row)
                self.assertIn(disposition, message)
                self.assertIn("modelled reason", message)
                self.assertNotIn("replaced or removed", message)

    def test_capture_outcomes_never_become_skips(self):
        for outcome in ("failed", "not_visited", "succeeded", None):
            with self.subTest(outcome=outcome):
                row = self._row("edge", "capture", "soft limit", outcome)
                index = self._missing_index(row)
                scope = index["unpaired"]["pre_only"][0]["post_scope"]
                self.assertEqual(scope["disposition"], "capture")
                self.assertEqual(scope["outcome"], outcome)
                message = diff_snapshots._missing_message("edge", "post", scope)
                self.assertIn("snapshot missing", message)
                self.assertIn("unknown, not clean", message)
                self.assertIn(outcome or "unknown", message)

    def test_missing_captures_are_visible_without_any_baseline_snapshot(self):
        pre = self._file(
            "manifest_CHG1_pre.json",
            _manifest("pre", [self._row("edge", "capture", "pre outage", "failed")]),
        )
        post = self._file(
            "manifest_CHG1_post.json",
            _manifest(
                "post",
                [
                    self._row("edge", "capture", "soft limit", "not_visited"),
                    self._row("new-device", "capture", "post outage", "failed"),
                    self._row("ap", "covered_by_controller", "WLC-A"),
                ],
            ),
        )
        index = self._index([pre], [post])
        self.assertEqual(index["pairs"], {})
        self.assertEqual(index["unpaired"], {})
        self.assertEqual([row["device"] for row in index["missing_snapshots"]["pre"]], ["edge"])
        self.assertEqual(
            [row["device"] for row in index["missing_snapshots"]["post"]], ["edge", "new-device"]
        )
        self.assertEqual(index["missing_snapshots"]["post"][0]["outcome"], "not_visited")
        self.assertEqual(index["missing_snapshots"]["post"][1]["job_result_id"], "post-run")

    def test_missing_capture_is_emitted_once_on_stderr_and_has_index_diagnostic(self):
        pre = self._file("snapshot_edge_pre.json", _snapshot("edge"))
        post = self._file(
            "manifest_CHG1_post.json",
            _manifest(
                "post",
                [
                    self._row("edge", "capture", "unreachable", "failed"),
                    self._row("new-device", "capture", "unreachable", "failed"),
                ],
            ),
        )
        stderr = io.StringIO()
        index = self._index([pre], [post])
        with contextlib.redirect_stderr(stderr), contextlib.redirect_stdout(io.StringIO()):
            diff_snapshots.main(["--pre", str(pre), "--post", str(post)])
        self.assertEqual(stderr.getvalue().count("edge: post snapshot missing"), 1)
        self.assertEqual(stderr.getvalue().count("new-device: post snapshot missing"), 1)
        self.assertEqual(len(index["missing_snapshots"]["post"]), 2)

    def test_exclusions_skips_and_coverage_are_not_missing_supported_captures(self):
        index = self._missing_index(self._row("edge", "skipped_unsupported", "unsupported"))
        self.assertNotIn("missing_snapshots", index)

    def test_controller_coverage_preserves_names_and_devices(self):
        controller = {"name": "WLC-A", "devices": ["wlc-a-1"], "covers": ["edge", "other-ap"]}
        unrelated = {"name": "WLC-B", "devices": ["wlc-b-1"], "covers": ["other-ap"]}
        index = self._missing_index(
            self._row("edge", "covered_by_controller", "covered by WLC-A"),
            [controller, unrelated],
        )
        scope = index["unpaired"]["pre_only"][0]["post_scope"]
        self.assertEqual(scope["controllers"], [controller])
        self.assertIn("controller: WLC-A", diff_snapshots._missing_message("edge", "post", scope))

    def test_manifest_json_and_zip_split_parts_produce_same_scope_index(self):
        pre = self._file("snapshot_edge_pre.json", _snapshot("edge"))
        manifest = _manifest("post", [self._row("edge", "excluded", "manual exclusion"), "core"])
        post = _snapshot("core", kind="post")
        paths = [
            self._file("manifest_CHG1_post.json", manifest),
            self._file("snapshot_core_post.json", post),
        ]
        part1 = self._zip("post_part1of2.zip", {"post/manifest_CHG1_post.json": manifest})
        part2 = self._zip("post_part2of2.zip", {"post/snapshot_core.json": post})
        self.assertEqual(self._index([pre], paths), self._index([pre], [part2, part1]))

    def test_rollback_and_adhoc_capture_kinds_work_on_either_comparison_side(self):
        for pre_kind, post_kind in (("pre", "rollback"), ("rollback", "adhoc"), ("adhoc", "pre")):
            with self.subTest(pre_kind=pre_kind, post_kind=post_kind):
                files, archives = {}, {}
                for label, kind in (("pre", pre_kind), ("post", post_kind)):
                    members = {
                        kind + "/snapshot_edge_CHG1.json": _snapshot("edge", kind=kind),
                        kind + "/manifest_CHG1_" + kind + ".json": _manifest(kind, ["edge"]),
                    }
                    files[label] = [
                        self._file(label + "/" + name, payload) for name, payload in members.items()
                    ]
                    archives[label] = [self._zip(label + ".zip", members)]
                file_index = self._index(files["pre"], files["post"])
                zip_index = self._index(archives["pre"], archives["post"])
                self.assertEqual(file_index, zip_index)
                self.assertEqual(file_index["pairs"]["edge"]["summary"]["checks_passed"], 1)

    def test_snapshot_kind_still_must_match_its_actual_manifest_kind(self):
        pre = self._file("snapshot_edge_pre.json", _snapshot("edge"))
        post = self._file("snapshot_edge_post.json", _snapshot("edge", kind="post"))
        manifest = self._file(
            "manifest_CHG1_rollback.json", _manifest("rollback", ["edge"], job_result_id="post-run")
        )
        with self.assertRaisesRegex(SystemExit, "supply snapshots and manifest from the same run"):
            self._index([pre], [post, manifest])

    def test_post_only_has_symmetric_pre_scope(self):
        pre = self._file(
            "manifest_CHG1_pre.json", _manifest("pre", [self._row("edge", "excluded", "excluded")])
        )
        post = self._file("snapshot_edge_post.json", _snapshot("edge", kind="post"))
        note = self._index([pre], [post])["unpaired"]["post_only"][0]
        self.assertEqual(note["pre_scope"]["disposition"], "excluded")

    def test_valid_manifests_with_no_snapshots_can_explain_both_sides(self):
        pre = self._file("manifest_CHG1_pre.json", _manifest("pre"))
        post = self._file("manifest_CHG1_post.json", _manifest("post"))
        index = self._index([pre], [post])
        self.assertEqual(index["pairs"], {})
        self.assertEqual(index["unpaired"], {})

    def test_old_manifest_reason_does_not_override_newer_capture_failure(self):
        pre = self._file("snapshot_edge_pre.json", _snapshot("edge"))
        older = self._file(
            "old/manifest_CHG1_post.json",
            _manifest(
                "post", [self._row("edge", "excluded", "old exclusion")], job_result_id="old"
            ),
        )
        newer = self._file(
            "new/manifest_CHG1_post.json",
            _manifest(
                "post",
                [self._row("edge", "capture", "unreachable", "failed")],
                job_result_id="new",
                started="2026-10-01T02:00:00Z",
            ),
        )
        first = self._index([pre], [older, newer])
        second = self._index([pre], [newer, older])
        self.assertEqual(first, second)
        self.assertEqual(first["unpaired"]["pre_only"][0]["post_scope"]["disposition"], "capture")

    def test_split_runs_with_same_change_id_and_different_devices_coexist(self):
        pre_paths, post_paths = [], []
        for kind, paths in (("pre", pre_paths), ("post", post_paths)):
            for name, hour in (("edge", "01"), ("core", "02")):
                run_id = kind + "-" + name
                paths.extend(
                    [
                        self._file(
                            "%s/%s/snapshot_%s.json" % (kind, name, name),
                            _snapshot(name, kind=kind, job_result_id=run_id),
                        ),
                        self._file(
                            "%s/%s/manifest_CHG1_%s.json" % (kind, name, kind),
                            _manifest(
                                kind,
                                [name],
                                job_result_id=run_id,
                                started="2026-10-01T%s:00:00Z" % hour,
                            ),
                        ),
                    ]
                )
        index = self._index(pre_paths, post_paths)
        self.assertEqual(set(index["pairs"]), {"core", "edge"})
        self.assertEqual(index["unpaired"], {})
        self.assertEqual(index, self._index(list(reversed(pre_paths)), list(reversed(post_paths))))

    def test_later_split_manifest_omission_keeps_earlier_device_reason(self):
        pre = self._file("snapshot_edge_pre.json", _snapshot("edge"))
        first = self._file(
            "first/manifest_CHG1_post.json",
            _manifest("post", [self._row("edge", "excluded", "first run")], job_result_id="first"),
        )
        second = self._file(
            "second/manifest_CHG1_post.json",
            _manifest("post", ["core"], job_result_id="second", started="2026-10-01T02:00:00Z"),
        )
        scope = self._index([pre], [first, second])["unpaired"]["pre_only"][0]["post_scope"]
        self.assertEqual(scope["reason"], "first run")

    def test_stale_snapshot_cannot_hide_newer_failed_or_skipped_run(self):
        pre = self._file("snapshot_edge_pre.json", _snapshot("edge"))
        stale = self._file(
            "snapshot_edge_post.json", _snapshot("edge", kind="post", job_result_id="old")
        )
        older = self._file(
            "old/manifest_CHG1_post.json", _manifest("post", ["edge"], job_result_id="old")
        )
        for disposition, outcome in (
            ("capture", "failed"),
            ("capture", "not_visited"),
            ("excluded", None),
        ):
            with self.subTest(disposition=disposition, outcome=outcome):
                newer = self._file(
                    "new/manifest_CHG1_post.json",
                    _manifest(
                        "post",
                        [self._row("edge", disposition, None, outcome)],
                        job_result_id="new",
                        started="2026-10-01T02:00:00Z",
                    ),
                )
                with self.assertRaisesRegex(SystemExit, "does not match latest manifest"):
                    self._index([pre], [stale, older, newer])

    def test_snapshot_from_newer_run_cannot_use_old_manifest_reason(self):
        pre = self._file("snapshot_edge_pre.json", _snapshot("edge"))
        post = self._file(
            "snapshot_edge_post.json", _snapshot("edge", kind="post", job_result_id="new")
        )
        manifest = self._file(
            "manifest_CHG1_post.json", _manifest("post", ["edge"], job_result_id="old")
        )
        with self.assertRaisesRegex(SystemExit, "supply snapshots and manifest from the same run"):
            self._index([pre], [manifest, post])

    def test_equal_capture_times_use_matching_manifest_run_in_any_input_order(self):
        pre = self._file("snapshot_edge_pre.json", _snapshot("edge"))
        old = self._file(
            "old/snapshot_edge_post.json",
            _snapshot("edge", kind="post", job_result_id="old", normalized={"route": "old"}),
        )
        new = self._file(
            "new/snapshot_edge_post.json",
            _snapshot("edge", kind="post", job_result_id="new", normalized={"route": "new"}),
        )
        manifest = self._file(
            "manifest_CHG1_post.json", _manifest("post", ["edge"], job_result_id="new")
        )
        expected = self._index([pre], [new, old, manifest])
        self.assertEqual(self._index([pre], [old, manifest, new]), expected)
        self.assertEqual(
            diff_snapshots._load_side("post", [old, new])["edge"]["job"]["job_result_id"], "old"
        )

    def test_failed_partial_snapshot_keeps_envelope_comparison_fail_closed(self):
        pre = self._file("snapshot_edge_pre.json", _snapshot("edge"))
        post_env = _snapshot("edge", kind="post")
        post_env["checks"]["routes"]["status"] = "failed"
        post = self._file("snapshot_edge_post.json", post_env)
        manifest = self._file(
            "manifest_CHG1_post.json",
            _manifest("post", [self._row("edge", "capture", "read failed", "failed")]),
        )
        check = self._index([pre], [manifest, post])["pairs"]["edge"]["checks"]["routes"]
        self.assertEqual(check["result"], "failed")
        self.assertIn("unknown, not clean", check["note"])

    def test_failed_manifest_keeps_paired_scope_and_warns_despite_successful_checks(self):
        for failed_side in ("pre", "post"):
            with self.subTest(failed_side=failed_side):
                paths = {}
                for kind in ("pre", "post"):
                    row = (
                        self._row(
                            "edge", "capture", "interrupted after snapshot persisted", "failed"
                        )
                        if kind == failed_side
                        else self._row("edge", "capture", outcome="succeeded")
                    )
                    paths[kind] = [
                        self._file("snapshot_edge_%s.json" % kind, _snapshot("edge", kind=kind)),
                        self._file("manifest_CHG1_%s.json" % kind, _manifest(kind, [row])),
                    ]
                index = self._index(paths["pre"], paths["post"])
                report = index["pairs"]["edge"]
                self.assertEqual(report["summary"]["checks_passed"], 1)
                self.assertEqual(report["summary"]["checks_failed"], 0)
                self.assertEqual(report[failed_side + "_scope"]["outcome"], "failed")
                self.assertEqual(
                    report[failed_side + "_scope"]["reason"], "interrupted after snapshot persisted"
                )
                self.assertIn("pre_scope", report)
                self.assertIn("post_scope", report)
                stderr = io.StringIO()
                with contextlib.redirect_stderr(stderr), contextlib.redirect_stdout(io.StringIO()):
                    diff_snapshots.main(
                        ["--pre"]
                        + [str(path) for path in paths["pre"]]
                        + ["--post"]
                        + [str(path) for path in paths["post"]]
                    )
                self.assertIn("%s capture outcome failed" % failed_side, stderr.getvalue())
                self.assertIn("unknown, not clean", stderr.getvalue())
                self.assertIn("interrupted after snapshot persisted", stderr.getvalue())

    def test_duplicate_manifest_downloads_are_safe_but_conflicting_same_run_errors(self):
        pre = self._file("snapshot_edge_pre.json", _snapshot("edge"))
        payload = _manifest("post", [self._row("edge", "excluded", "reason")])
        manifest = self._file("manifest_CHG1_post.json", payload)
        archive = self._zip("post.zip", {"post/manifest_CHG1_post.json": payload})
        self.assertEqual(self._index([pre], [manifest]), self._index([pre], [manifest, archive]))
        payload["devices"][0]["reason"] = "different"
        archive = self._zip("post.zip", {"post/manifest_CHG1_post.json": payload})
        with self.assertRaisesRegex(SystemExit, "conflicting manifests for job result post-run"):
            self._index([pre], [manifest, archive])

    def test_equal_run_timestamps_for_overlapping_device_are_ambiguous(self):
        pre = self._file("snapshot_edge_pre.json", _snapshot("edge"))
        first = self._file(
            "first/manifest_CHG1_post.json", _manifest("post", ["edge"], job_result_id="first")
        )
        second = self._file(
            "second/manifest_CHG1_post.json",
            _manifest("post", ["edge"], job_result_id="second", finished="2026-10-01T04:00:00Z"),
        )
        for paths in ([first, second], [second, first]):
            with self.subTest(paths=paths):
                with self.assertRaisesRegex(SystemExit, "ambiguous manifest run order for edge"):
                    self._index([pre], paths)

    def test_newest_run_resolves_ambiguity_between_older_manifests_in_any_order(self):
        pre = self._file("snapshot_edge_pre.json", _snapshot("edge"))
        first = self._file(
            "first/manifest_CHG1_post.json", _manifest("post", ["edge"], job_result_id="first")
        )
        second = self._file(
            "second/manifest_CHG1_post.json", _manifest("post", ["edge"], job_result_id="second")
        )
        newest = self._file(
            "newest/manifest_CHG1_post.json",
            _manifest(
                "post",
                [self._row("edge", "excluded", "newest run")],
                job_result_id="newest",
                started="2026-10-01T02:00:00Z",
            ),
        )
        expected = self._index([pre], [newest, first, second])
        for paths in ([first, second, newest], [second, newest, first], [newest, second, first]):
            with self.subTest(paths=paths):
                self.assertEqual(self._index([pre], paths), expected)

    def test_dryrun_manifest_is_a_preview_and_cannot_be_comparison_evidence(self):
        pre = self._file("snapshot_edge_pre.json", _snapshot("edge"))
        for devices in ([], [self._row("edge", "capture")], [self._row("edge", "excluded")]):
            with self.subTest(devices=devices):
                manifest = self._file(
                    "manifest_CHG1_post.json", _manifest("post", devices, inputs={"dryrun": True})
                )
                with self.assertRaisesRegex(
                    SystemExit, "dry-run scope preview, not capture evidence"
                ):
                    self._index([pre], [manifest])

    def test_missing_snapshot_device_in_its_own_manifest_is_an_error(self):
        pre = self._file("snapshot_edge_pre.json", _snapshot("edge"))
        post = self._file("snapshot_edge_post.json", _snapshot("edge", kind="post"))
        manifest = self._file("manifest_CHG1_post.json", _manifest("post", []))
        with self.assertRaisesRegex(SystemExit, "does not list snapshot device edge"):
            self._index([pre], [manifest, post])

    def test_malformed_manifest_shapes_and_duplicate_devices_fail_usefully(self):
        bad_values = [
            ("schema", 2, "schema 1"),
            ("schema", True, "schema 1"),
            ("devices", {}, "devices must be a list"),
            ("inputs", [], "inputs must be an object"),
            ("inputs", {"dryrun": "true"}, "inputs.dryrun must be a boolean"),
            ("devices", ["edge"], "each device must be an object"),
            ("devices", [{"name": "edge", "disposition": []}], "unknown disposition"),
            ("devices", [self._row("edge", "excluded", 3)], "reason must be a string"),
            ("devices", [self._row("edge", "capture", outcome="ok")], "unknown outcome"),
            ("devices", [self._row("edge", "excluded")] * 2, "duplicate device name edge"),
            ("kind", "unknown", "kind must be pre, post, rollback, or adhoc"),
            ("started", "yesterday", "started must be a UTC timestamp"),
            ("finished", "2026-09-30T00:00:00Z", "finished must be a UTC timestamp"),
            ("job_result_id", [], "job_result_id must be a nonempty string"),
            ("controllers", {}, "controllers must be a list"),
            (
                "controllers",
                [{"name": "WLC-A", "devices": [], "covers": {}}],
                "covers must be a list",
            ),
        ]
        for field, value, message in bad_values:
            with self.subTest(field=field, value=value):
                payload = _manifest("post")
                payload[field] = value
                for path in (
                    self._file("manifest_bad_post.json", payload),
                    self._zip("bad.zip", {"post/manifest_bad_post.json": payload}),
                ):
                    with self.assertRaisesRegex(SystemExit, "post: invalid manifest .*" + message):
                        diff_snapshots._load_side_data("post", [path])

    def test_invalid_manifest_json_is_read_in_both_formats(self):
        plain = self.root / "manifest_bad_post.json"
        plain.write_bytes(b"{")
        archive = self._zip("bad.zip", {"post/manifest_bad_post.json": b"{"})
        for path in (plain, archive):
            with self.subTest(path=path):
                with self.assertRaisesRegex(SystemExit, "post: unreadable manifest"):
                    diff_snapshots._load_side_data("post", [path])


if __name__ == "__main__":
    unittest.main()
