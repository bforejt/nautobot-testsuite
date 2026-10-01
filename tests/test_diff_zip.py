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


def _snapshot(name, kind="pre", normalized=None, captured_at="2026-10-01T01:00:00Z"):
    env = _loader.envelope.new_envelope(
        {"name": name, "platform": "iosxe"}, "CHG1", kind, "full", ["routes"], {}
    )
    env["captured_at"] = captured_at
    env["checks"]["routes"] = {
        "status": "success",
        "compare": {"mode": "equality_set"},
        "normalized": normalized or {},
        "describe": {"miss_meaning": "route disappeared"},
    }
    return env


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
            "pre/manifest_CHG1_pre.json": {"schema": 1, "devices": []},
        }
        post = {
            "post/snapshot_core-1_CHG1.json": _snapshot(
                "core-1", kind="post", normalized={"new": "b", "changed": "after"}
            ),
            "post/snapshot_replacement_CHG1.json": _snapshot("replacement", kind="post"),
            "post/raw_core-1_CHG1.json": {"routes": "raw evidence"},
            "post/manifest_CHG1_post.json": {"schema": 1, "devices": []},
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
        part1 = self._zip("pre_part1of3.zip", {"pre/manifest_CHG1_pre.json": {"schema": 1}})
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
                "pre/manifest_CHG1_pre.json": b"invalid JSON",
                "pre/unrelated.json": b"invalid JSON",
                "pre/snapshot_core-1.txt": b"invalid JSON",
            },
        )
        self.assertEqual(diff_snapshots._load_side("pre", [archive]), {"core-1": env})

    def test_known_unzipped_siblings_are_ignored_without_parsing(self):
        snapshot = self._file("snapshot_core-1.json", _snapshot("core-1"))
        siblings = []
        for name in ("raw_core-1.json", "debug_core-1.json", "manifest_CHG1_pre.json"):
            path = self.root / name
            path.write_bytes(b"invalid JSON")
            siblings.append(path)
        self.assertEqual(set(diff_snapshots._load_side("pre", siblings + [snapshot])), {"core-1"})

    def test_empty_snapshot_side_is_an_error(self):
        for members in ({}, {"pre/manifest_CHG1_pre.json": {"schema": 1}}):
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


if __name__ == "__main__":
    unittest.main()
