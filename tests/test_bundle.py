"""Artifact bytes, exact zip cap enforcement, whole-device splits and cleanup."""

import hashlib
import io
import json
import random
import string
import unittest
import zipfile
from unittest import mock

if __package__:
    from . import _loader
else:
    import _loader

bundle = _loader.load("bundle")


class TestDeviceNames(unittest.TestCase):
    def test_sanitization_collision_names_the_original_devices(self):
        with self.assertRaisesRegex(ValueError, "'sw/1' and 'sw\\?1'"):
            bundle.validate_device_names(["sw/1", "sw?1"])

    def test_distinct_normal_names_are_accepted(self):
        self.assertIsNone(bundle.validate_device_names(["core-1", "core-2", "edge_1"]))


def _payload(seed, length):
    rng = random.Random(seed)
    return {"data": "".join(rng.choices(string.ascii_letters + string.digits, k=length))}


def _archive(data):
    return zipfile.ZipFile(io.BytesIO(data))


def _zip_bytes(name, payload):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as archive:
        archive.writestr(name, bundle.json_bytes(payload))
    return stream.getvalue()


class TestFileSink(unittest.TestCase):
    def test_legacy_bytes_and_metadata_are_attached_immediately(self):
        downloads = {}
        sink = bundle.FileSink(lambda name, data: downloads.setdefault(name, data) is data)
        payload = {"z": [1, 2], "a": "caf\u00e9"}
        metadata = sink.add("snapshot_core.json", payload, device="core")
        expected = json.dumps(payload, indent=1, sort_keys=True).encode("utf-8")
        self.assertEqual(downloads, {"snapshot_core.json": expected})
        self.assertEqual(
            metadata,
            {
                "name": "snapshot_core.json",
                "bytes": len(expected),
                "sha256": hashlib.sha256(expected).hexdigest(),
            },
        )
        manifest = {"devices": [{"name": "core", "files": [metadata]}]}
        self.assertEqual(
            sink.finish("manifest_pre.json", manifest),
            ["snapshot_core.json", "manifest_pre.json"],
        )
        self.assertEqual(json.loads(downloads["manifest_pre.json"]), manifest)
        self.assertEqual(sink.finish("manifest_pre.json", manifest), list(downloads))

    def test_rejected_file_is_marked_in_manifest(self):
        downloads = {}

        def attach(name, data):
            if name == "snapshot_core.json":
                return False
            downloads[name] = data
            return True

        sink = bundle.FileSink(attach)
        metadata = sink.add("snapshot_core.json", {"checks": []})
        self.assertTrue(metadata["not_attached"])
        sink.finish("manifest_pre.json", {"files": [metadata]})
        self.assertTrue(json.loads(downloads["manifest_pre.json"])["files"][0]["not_attached"])

    def test_closed_sink_cannot_add_more_artifacts(self):
        sink = bundle.FileSink(lambda name, data: False)
        self.assertTrue(sink.add("snapshot_core.json", {})["not_attached"])
        sink.close()
        sink.close()
        with self.assertRaises(ValueError):
            sink.add("snapshot_other.json", {})

    def test_manifest_callback_timeout_can_be_retried(self):
        class TimeoutSignal(Exception):
            pass

        calls = []

        def attach(name, data):
            calls.append((name, data))
            if len(calls) == 1:
                raise TimeoutSignal("soft time limit")
            return True

        sink = bundle.FileSink(attach)
        with self.assertRaisesRegex(TimeoutSignal, "soft time limit"):
            sink.finish("manifest_pre.json", {})
        self.assertFalse(sink._closed)
        self.assertEqual(sink.finish("manifest_pre.json", {}), ["manifest_pre.json"])
        self.assertTrue(sink._closed)
        self.assertEqual(len(calls), 2)
        sink.finish("manifest_pre.json", {})
        self.assertEqual(len(calls), 2)

    def test_preprovided_metadata_survives_callback_timeout(self):
        class TimeoutSignal(Exception):
            pass

        downloaded = {}

        def attach(name, data):
            downloaded[name] = data
            raise TimeoutSignal("signal after persistence")

        metadata = {}
        sink = bundle.FileSink(attach)
        try:
            with self.assertRaisesRegex(TimeoutSignal, "signal after persistence"):
                sink.add("snapshot_core.json", {"checks": []}, metadata=metadata)
        finally:
            sink.close()
        data = downloaded["snapshot_core.json"]
        self.assertEqual(metadata["name"], "snapshot_core.json")
        self.assertEqual(metadata["bytes"], len(data))
        self.assertEqual(metadata["sha256"], hashlib.sha256(data).hexdigest())
        self.assertTrue(metadata["not_attached"])


class TestZipSink(unittest.TestCase):
    def _run(self, rows, cap=100000, attach=None):
        downloads, warnings = {}, []

        def store(name, data):
            downloads[name] = data
            return True

        sink = bundle.ZipSink(
            attach or store,
            kind="pre",
            filename="testsuite_CHG123_pre_20261001T1200Z.zip",
            max_bytes=cap,
            warn=warnings.append,
        )
        manifest = {"schema": 1, "devices": []}
        for device, files in rows:
            entry = {"name": device, "files": []}
            manifest["devices"].append(entry)
            for name, payload in files:
                entry["files"].append(sink.add(name, payload, device=device))
        self.assertEqual(downloads, {})
        result = sink.finish("manifest_CHG123_pre.json", manifest)
        return sink, manifest, downloads, warnings, result

    def test_round_trip_member_names_hashes_and_no_incremental_attachment(self):
        rows = [
            ("core", [("snapshot_core_CHG123.json", {"checks": [1, 2]})]),
            ("edge", [("snapshot_edge_CHG123.json", {"checks": [3]})]),
        ]
        sink, manifest, downloads, warnings, result = self._run(rows)
        self.assertEqual(warnings, [])
        self.assertEqual(result, list(downloads))
        self.assertEqual(len(downloads), 1)
        with _archive(next(iter(downloads.values()))) as archive:
            self.assertEqual(
                archive.namelist(),
                [
                    "pre/manifest_CHG123_pre.json",
                    "pre/snapshot_core_CHG123.json",
                    "pre/snapshot_edge_CHG123.json",
                ],
            )
            self.assertEqual(json.loads(archive.read(archive.namelist()[0])), manifest)
            for entry in manifest["devices"]:
                for metadata in entry["files"]:
                    data = archive.read("pre/" + metadata["name"])
                    self.assertEqual(len(data), metadata["bytes"])
                    self.assertEqual(hashlib.sha256(data).hexdigest(), metadata["sha256"])
                    self.assertEqual(
                        archive.getinfo("pre/" + metadata["name"]).compress_type,
                        zipfile.ZIP_DEFLATED,
                    )
        self.assertTrue(sink._spool.closed)
        self.assertEqual(sink.finish("manifest_CHG123_pre.json", manifest), result)
        sink.close()

    def test_exact_full_archive_cap_and_one_byte_less(self):
        rows = [
            ("core", [("snapshot_core.json", _payload(1, 1000))]),
            ("edge", [("snapshot_edge.json", _payload(2, 1000))]),
        ]
        _, _, baseline, _, _ = self._run(rows)
        exact = len(next(iter(baseline.values())))
        _, _, fits, _, _ = self._run(rows, cap=exact)
        self.assertEqual(len(fits), 1)
        self.assertEqual(len(next(iter(fits.values()))), exact)
        _, _, split, _, _ = self._run(rows, cap=exact - 1)
        self.assertEqual(len(split), 2)
        self.assertTrue(all(len(data) <= exact - 1 for data in split.values()))
        self.assertTrue(any(name.endswith("_part1of2.zip") for name in split))
        self.assertTrue(any(name.endswith("_part2of2.zip") for name in split))

    def test_split_keeps_each_device_files_together_and_manifest_in_part_one(self):
        rows = [
            (
                device,
                [
                    ("snapshot_%s.json" % device, _payload(seed, 600)),
                    ("raw_%s.json" % device, _payload(seed + 1, 600)),
                ],
            )
            for device, seed in (("a", 10), ("b", 20), ("c", 30))
        ]
        _, _, downloads, warnings, _ = self._run(rows, cap=1600)
        self.assertEqual(warnings, [])
        self.assertGreater(len(downloads), 1)
        device_parts = {}
        for name, data in downloads.items():
            self.assertLessEqual(len(data), 1600)
            with _archive(data) as archive:
                members = archive.namelist()
                self.assertEqual("pre/manifest_CHG123_pre.json" in members, "_part1of" in name)
                for device, files in rows:
                    if "pre/" + files[0][0] in members:
                        self.assertIn("pre/" + files[1][0], members)
                        device_parts[device] = name
        self.assertEqual(set(device_parts), {"a", "b", "c"})

    def test_manifest_header_and_compressed_bytes_count_toward_split(self):
        payload = _payload(1, 1400)
        cap = len(_zip_bytes("pre/snapshot_core.json", payload))
        rows = [("core", [("snapshot_core.json", payload)])]
        _, _, downloads, warnings, _ = self._run(rows, cap=cap)
        self.assertEqual(warnings, [])
        self.assertEqual(len(downloads), 2)
        for name, data in downloads.items():
            self.assertLessEqual(len(data), cap)
            with _archive(data) as archive:
                self.assertEqual(
                    archive.namelist(),
                    ["pre/manifest_CHG123_pre.json"]
                    if "_part1of" in name
                    else ["pre/snapshot_core.json"],
                )

    def test_oversize_device_is_dropped_and_manifest_records_all_its_files(self):
        rows = [
            (
                "big",
                [("snapshot_big.json", _payload(1, 900)), ("raw_big.json", _payload(2, 900))],
            ),
            ("small", [("snapshot_small.json", {"checks": []})]),
        ]
        _, manifest, downloads, warnings, _ = self._run(rows, cap=1200)
        self.assertTrue(all(row["not_attached"] for row in manifest["devices"][0]["files"]))
        self.assertNotIn("not_attached", manifest["devices"][1]["files"][0])
        self.assertEqual(len(warnings), 1)
        with _archive(next(iter(downloads.values()))) as archive:
            self.assertNotIn("pre/snapshot_big.json", archive.namelist())
            self.assertNotIn("pre/raw_big.json", archive.namelist())
            attached_manifest = json.loads(archive.read("pre/manifest_CHG123_pre.json"))
            self.assertEqual(attached_manifest, manifest)
            self.assertIn("pre/snapshot_small.json", archive.namelist())

    def test_failed_data_part_is_marked_before_manifest_attachment(self):
        downloads = {}

        def attach(name, data):
            if "_part2of" in name:
                return False
            downloads[name] = data
            return True

        rows = [
            (device, [("snapshot_%s.json" % device, _payload(seed, 500))])
            for device, seed in (("a", 1), ("b", 2), ("c", 3))
        ]
        sink, manifest, _, _, _ = self._run(rows, cap=600, attach=attach)
        self.assertTrue(sink._spool.closed)
        part_one = next(data for name, data in downloads.items() if "_part1of" in name)
        with _archive(part_one) as archive:
            attached = json.loads(archive.read("pre/manifest_CHG123_pre.json"))
        self.assertEqual(attached, manifest)
        self.assertTrue(manifest["devices"][0]["files"][0]["not_attached"])

    def test_failed_only_archive_marks_shared_metadata_and_closes_spool(self):
        sink, manifest, _, _, result = self._run(
            [("core", [("snapshot_core.json", {})])], attach=lambda name, data: False
        )
        self.assertEqual(result, [])
        self.assertTrue(manifest["devices"][0]["files"][0]["not_attached"])
        self.assertTrue(sink._spool.closed)

    def test_callback_timeout_preserves_source_and_retry_attaches_evidence(self):
        class TimeoutSignal(Exception):
            pass

        calls, downloads = [], {}

        def attach(name, data):
            calls.append(name)
            if len(calls) == 1:
                raise TimeoutSignal("soft time limit")
            downloads[name] = data
            return True

        sink = bundle.ZipSink(attach, kind="pre", filename="run.zip", max_bytes=9999)
        metadata = sink.add("snapshot_core.json", {}, device="core")
        with self.assertRaisesRegex(TimeoutSignal, "soft time limit"):
            sink.finish("manifest.json", {"files": [metadata]})
        self.assertFalse(sink._spool.closed)
        self.assertNotIn("not_attached", metadata)
        self.assertEqual(sink.finish("manifest.json", {"files": [metadata]}), ["run.zip"])
        self.assertTrue(sink._spool.closed)
        self.assertEqual(calls, ["run.zip", "run.zip"])
        with _archive(downloads["run.zip"]) as archive:
            self.assertEqual(json.loads(archive.read("pre/snapshot_core.json")), {})

    def test_empty_capture_still_attaches_manifest(self):
        _, manifest, downloads, _, _ = self._run([])
        with _archive(next(iter(downloads.values()))) as archive:
            self.assertEqual(archive.namelist(), ["pre/manifest_CHG123_pre.json"])
            self.assertEqual(json.loads(archive.read(archive.namelist()[0])), manifest)

    def test_unattachable_manifest_does_not_drop_device_evidence(self):
        downloads, warnings = {}, []
        sink = bundle.ZipSink(
            lambda name, data: downloads.setdefault(name, data) is data,
            kind="post",
            filename="run.zip",
            max_bytes=250,
            warn=warnings.append,
        )
        sink.add("snapshot_core.json", {}, device="core")
        sink.finish("manifest.json", _payload(2, 1000))
        self.assertIn("Manifest manifest.json exceeds", warnings[0])
        with _archive(downloads["run.zip"]) as archive:
            self.assertEqual(archive.namelist(), ["post/snapshot_core.json"])

    def test_no_empty_zip_when_nothing_can_be_attached(self):
        _, manifest, downloads, warnings, _ = self._run(
            [("core", [("snapshot_core.json", {})])], cap=10
        )
        self.assertEqual(downloads, {})
        self.assertTrue(manifest["devices"][0]["files"][0]["not_attached"])
        self.assertEqual(len(warnings), 2)

    def test_utf8_member_names_are_counted_exactly(self):
        payload = {"checks": [1]}
        rows = [("caf\u00e9", [("snapshot_caf\u00e9.json", payload)])]
        _, _, baseline, _, _ = self._run(rows)
        cap = len(next(iter(baseline.values())))
        _, _, downloads, _, _ = self._run(rows, cap=cap)
        self.assertEqual(len(downloads), 1)
        self.assertEqual(len(next(iter(downloads.values()))), cap)

    def test_explicit_close_cleans_up_after_repacking_raises(self):
        sink = bundle.ZipSink(
            lambda name, data: True, kind="pre", filename="run.zip", max_bytes=9999
        )
        metadata = sink.add("snapshot_core.json", {}, device="core")
        with mock.patch.object(sink, "_build_part", side_effect=OSError("disk failure")):
            with self.assertRaisesRegex(OSError, "disk failure"):
                sink.finish("manifest.json", {})
        self.assertFalse(sink._spool.closed)
        sink.close()
        self.assertTrue(sink._spool.closed)
        self.assertTrue(metadata["not_attached"])
        with self.assertRaises(ValueError):
            sink.add("snapshot_other.json", {})

    def test_repacking_timeout_can_be_retried_from_cached_source(self):
        class TimeoutSignal(Exception):
            pass

        downloads = {}
        sink = bundle.ZipSink(
            lambda name, data: downloads.setdefault(name, data) is data,
            kind="pre",
            filename="run.zip",
            max_bytes=9999,
        )
        metadata = sink.add("snapshot_core.json", _payload(1, 500), device="core")
        manifest = {"files": [metadata]}
        build = sink._build_part
        calls = []

        def interrupted(*args, **kwargs):
            calls.append(True)
            if len(calls) == 1:
                raise TimeoutSignal("soft time limit")
            return build(*args, **kwargs)

        with mock.patch.object(sink, "_build_part", side_effect=interrupted):
            with self.assertRaisesRegex(TimeoutSignal, "soft time limit"):
                sink.finish("manifest.json", manifest)
            self.assertFalse(sink._spool.closed)
            self.assertEqual(sink.finish("manifest.json", manifest), ["run.zip"])
        self.assertTrue(sink._spool.closed)
        self.assertNotIn("not_attached", metadata)
        with _archive(downloads["run.zip"]) as archive:
            self.assertEqual(json.loads(archive.read("pre/snapshot_core.json")), _payload(1, 500))

    def test_multipart_retry_preserves_names_and_skips_confirmed_downloads(self):
        class TimeoutSignal(Exception):
            pass

        downloads, calls = {}, []
        interrupted = False

        def attach(name, data):
            nonlocal interrupted
            calls.append(name)
            if "_part3of" in name and not interrupted:
                interrupted = True
                raise TimeoutSignal("soft time limit")
            downloads[name] = data
            return True

        sink = bundle.ZipSink(attach, kind="pre", filename="run.zip", max_bytes=919)
        manifest = {"devices": []}
        for device, seed in (("a", 1), ("b", 2), ("c", 3)):
            metadata = sink.add("snapshot_%s.json" % device, _payload(seed, 500), device=device)
            manifest["devices"].append({"name": device, "files": [metadata]})
        with self.assertRaisesRegex(TimeoutSignal, "soft time limit"):
            sink.finish("manifest.json", manifest)
        names = [sink._part_filename(index, len(sink._finish_parts)) for index in range(4)]
        self.assertEqual(list(downloads), [names[1]])
        self.assertFalse(sink._spool.closed)
        sink.finish("manifest.json", manifest)
        self.assertEqual(set(downloads), set(names))
        self.assertEqual(calls.count(names[1]), 1)
        self.assertEqual(calls.count(names[2]), 2)
        self.assertTrue(sink._spool.closed)
        members = []
        for data in downloads.values():
            self.assertLessEqual(len(data), 919)
            with _archive(data) as archive:
                members.extend(archive.namelist())
        self.assertEqual(
            set(members),
            {
                "pre/manifest.json",
                "pre/snapshot_a.json",
                "pre/snapshot_b.json",
                "pre/snapshot_c.json",
            },
        )

    def test_failure_flag_growth_retains_every_healthy_device(self):
        downloads = {}

        def attach(name, data):
            if "_part2of" in name:
                return False
            downloads[name] = data
            return True

        rows = [
            (device, [("snapshot_%s.json" % device, _payload(seed, 500))])
            for device, seed in (("a", 1), ("b", 2), ("c", 3))
        ]
        _, manifest, _, warnings, _ = self._run(rows, cap=919, attach=attach)
        self.assertEqual(warnings, [])
        members = set()
        attached_manifest = None
        for data in downloads.values():
            self.assertLessEqual(len(data), 919)
            with _archive(data) as archive:
                members.update(archive.namelist())
                if "pre/manifest_CHG123_pre.json" in archive.namelist():
                    attached_manifest = json.loads(archive.read("pre/manifest_CHG123_pre.json"))
        self.assertEqual(attached_manifest, manifest)
        for entry in manifest["devices"]:
            metadata = entry["files"][0]
            self.assertEqual(
                "pre/" + metadata["name"] in members, not metadata.get("not_attached", False)
            )
        self.assertIn("pre/snapshot_b.json", members)
        self.assertIn("pre/snapshot_c.json", members)

    def test_timeout_during_source_close_keeps_completed_downloads(self):
        class TimeoutSignal(Exception):
            pass

        downloads = {}
        sink = bundle.ZipSink(
            lambda name, data: downloads.setdefault(name, data) is data,
            kind="pre",
            filename="run.zip",
            max_bytes=9999,
        )
        metadata = sink.add("snapshot_core.json", {}, device="core")
        with mock.patch.object(
            sink._zip, "_write_end_record", side_effect=TimeoutSignal("soft time limit")
        ):
            with self.assertRaisesRegex(TimeoutSignal, "soft time limit"):
                sink.finish("manifest.json", {"files": [metadata]})
        self.assertTrue(sink._spool.closed)
        self.assertEqual(sink.finish("manifest.json", {"files": [metadata]}), ["run.zip"])
        self.assertEqual(len(downloads), 1)
        self.assertNotIn("not_attached", metadata)
        with _archive(downloads["run.zip"]) as archive:
            self.assertEqual(archive.namelist(), ["pre/manifest.json", "pre/snapshot_core.json"])

    def test_interrupted_zip_add_keeps_metadata_and_omits_unconfirmed_member(self):
        class TimeoutSignal(Exception):
            pass

        downloads = {}
        sink = bundle.ZipSink(
            lambda name, data: downloads.setdefault(name, data) is data,
            kind="pre",
            filename="run.zip",
            max_bytes=9999,
        )
        metadata = {}
        write = sink._zip.writestr

        def interrupted(name, data):
            write(name, data)
            raise TimeoutSignal("signal after member write")

        with mock.patch.object(sink._zip, "writestr", side_effect=interrupted):
            with self.assertRaisesRegex(TimeoutSignal, "signal after member write"):
                sink.add("snapshot_core.json", {"checks": []}, metadata=metadata)
        self.assertEqual(metadata["name"], "snapshot_core.json")
        self.assertEqual(metadata["bytes"], len(bundle.json_bytes({"checks": []})))
        self.assertTrue(metadata["not_attached"])
        sink.finish("manifest.json", {"files": [metadata]})
        with _archive(downloads["run.zip"]) as archive:
            self.assertEqual(archive.namelist(), ["pre/manifest.json"])
            self.assertEqual(json.loads(archive.read("pre/manifest.json")), {"files": [metadata]})

    def test_timeout_while_marking_failed_part_preserves_terminal_failure_on_retry(self):
        class TimeoutSignal(Exception):
            pass

        downloads, calls = {}, []

        def attach(name, data):
            calls.append(name)
            if "_part2of" in name and calls.count(name) == 1:
                return False
            downloads[name] = data
            return True

        sink = bundle.ZipSink(attach, kind="pre", filename="run.zip", max_bytes=919)
        manifest = {"devices": []}
        for device, seed in (("a", 1), ("b", 2), ("c", 3)):
            metadata = sink.add("snapshot_%s.json" % device, _payload(seed, 500), device=device)
            manifest["devices"].append({"name": device, "files": [metadata]})
        mark = sink._mark_missing
        interrupted = False

        def interrupted_mark(members):
            nonlocal interrupted
            mark(members)
            if not interrupted:
                interrupted = True
                raise TimeoutSignal("signal after missing flags")

        with mock.patch.object(sink, "_mark_missing", side_effect=interrupted_mark):
            with self.assertRaisesRegex(TimeoutSignal, "signal after missing flags"):
                sink.finish("manifest.json", manifest)
            sink.finish("manifest.json", manifest)
        failed_name = next(name for name in calls if "_part2of" in name)
        self.assertEqual(calls.count(failed_name), 1)
        self.assertNotIn(failed_name, downloads)
        members = set()
        for data in downloads.values():
            with _archive(data) as archive:
                members.update(archive.namelist())
                if "pre/manifest.json" in archive.namelist():
                    self.assertEqual(json.loads(archive.read("pre/manifest.json")), manifest)
        for entry in manifest["devices"]:
            metadata = entry["files"][0]
            self.assertEqual(
                "pre/" + metadata["name"] in members, not metadata.get("not_attached", False)
            )

    def test_interrupted_close_detaches_writer_and_cleanup_remains_idempotent(self):
        class TimeoutSignal(Exception):
            pass

        sink = bundle.ZipSink(
            lambda name, data: True, kind="pre", filename="run.zip", max_bytes=9999
        )
        metadata = sink.add("snapshot_core.json", {}, device="core")
        with mock.patch.object(sink._zip, "close", side_effect=TimeoutSignal("before zip close")):
            with self.assertRaisesRegex(TimeoutSignal, "before zip close"):
                sink.close()
            self.assertTrue(sink._spool.closed)
            self.assertTrue(sink._closed)
            self.assertIsNone(sink._zip.fp)
            self.assertTrue(metadata["not_attached"])
            sink.close()
        sink.close()
        sink._zip.close()


if __name__ == "__main__":
    unittest.main()
