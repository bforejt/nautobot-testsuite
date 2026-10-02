"""Artifact serialization and bounded zip downloads, without Nautobot imports.

``attach`` receives a filename and bytes and returns whether the download was
attached. Metadata returned by ``add`` is deliberately mutable: the run manifest
holds the same objects, so a size-cap or attachment failure can mark evidence as
``not_attached`` without changing a device's capture outcome.
"""

import base64
import copy
import hashlib
import json
import shutil
import tempfile
import zipfile
import zlib
from collections import OrderedDict
from dataclasses import dataclass

from .envelope import safe_name


def validate_device_names(names):
    """Refuse a selection whose existing sanitized artifact names would collide."""
    seen = {}
    for name in names:
        safe = safe_name(name)
        if safe in seen:
            raise ValueError(
                "Device names %r and %r produce the same artifact name %r"
                % (seen[safe], name, safe)
            )
        seen[safe] = name


def json_bytes(payload):
    """Preserve the legacy JSON serialization, including its final-byte shape."""
    return json.dumps(payload, indent=1, sort_keys=True).encode("utf-8")


def _metadata(filename, data):
    return {"name": filename, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def artifact_parts(filename, payload, max_bytes):
    """Lossless, independently attachable JSON parts plus a checksum index.

    Ordinary artifacts retain their exact legacy serialization and filename.
    Large native text, tables and snapshots are split as serialized bytes,
    rather than truncating fields or changing the collector's data model.
    """
    if max_bytes < 1024:
        raise ValueError("artifact part byte limit must be at least 1024")
    data = json_bytes(payload)
    reserve = min(4096, max_bytes // 4)
    ceiling = max_bytes - reserve
    if len(data) <= ceiling:
        return [(filename, payload)]
    checksum = hashlib.sha256(data).hexdigest()
    # Base64 has a known upper bound and avoids splitting UTF-8 characters.
    chunk_size = (ceiling - 512) * 3 // 4
    if chunk_size < 1:
        raise ValueError("artifact byte limit cannot hold a part header")
    count = (len(data) + chunk_size - 1) // chunk_size
    stem = filename[:-5] if filename.endswith(".json") else filename
    result = []
    entries = []
    for offset in range(count):
        name = "artifactpart_%s_%s_%04d.json" % (checksum[:16], stem, offset + 1)
        part = {
            "schema": 1,
            "artifact": filename,
            "encoding": "base64",
            "part": offset + 1,
            "part_count": count,
            "artifact_sha256": checksum,
            "data": base64.b64encode(data[offset * chunk_size : (offset + 1) * chunk_size]).decode(
                "ascii"
            ),
        }
        encoded = json_bytes(part)
        if len(encoded) > ceiling:
            raise ValueError("artifact part header exceeds reserved capacity")
        entries.append(_metadata(name, encoded))
        result.append((name, part))
    index = {
        "schema": 1,
        "artifact": filename,
        "encoding": "base64",
        "bytes": len(data),
        "sha256": checksum,
        "parts": entries,
    }
    if len(json_bytes(index)) > ceiling:
        raise ValueError("artifact part index exceeds attachment capacity")
    result.append(("%s.%s.parts.json" % (stem, checksum[:16]), index))
    return result


def reassemble(index, parts):
    """Validate an index and each original serialized part, then return bytes.

    ``parts`` maps a filename to its serialized JSON bytes. No paths in an
    index are ever opened; callers supply already downloaded evidence.
    """
    if not isinstance(index, dict) or index.get("schema") != 1 or index.get("encoding") != "base64":
        raise ValueError("invalid artifact part index")
    entries = index.get("parts")
    if not isinstance(entries, list) or not entries:
        raise ValueError("artifact part index has no parts")
    chunks = []
    names = set()
    for number, entry in enumerate(entries, 1):
        if not isinstance(entry, dict) or not isinstance(entry.get("name"), str):
            raise ValueError("invalid artifact part entry")
        name = entry["name"]
        if name in names:
            raise ValueError("duplicate artifact part")
        names.add(name)
        if name not in parts:
            raise ValueError("missing artifact part %s" % name)
        data = parts[name]
        if len(data) != entry.get("bytes") or hashlib.sha256(data).hexdigest() != entry.get(
            "sha256"
        ):
            raise ValueError("artifact part checksum mismatch: %s" % name)
        part = json.loads(data)
        if (
            part.get("artifact") != index.get("artifact")
            or part.get("part") != number
            or part.get("part_count") != len(entries)
            or part.get("encoding") != "base64"
            or part.get("artifact_sha256") != index.get("sha256")
        ):
            raise ValueError("artifact part identity mismatch: %s" % name)
        try:
            chunks.append(base64.b64decode(part["data"], validate=True))
        except (ValueError, KeyError, TypeError) as exc:
            raise ValueError("invalid artifact part encoding: %s" % name) from exc
    data = b"".join(chunks)
    if len(data) != index.get("bytes") or hashlib.sha256(data).hexdigest() != index.get("sha256"):
        raise ValueError("reassembled artifact checksum mismatch")
    return data


def _filename_bytes(name):
    # ZipFile writes ASCII names directly and sets the UTF-8 flag otherwise.
    try:
        return name.encode("ascii")
    except UnicodeEncodeError:
        return name.encode("utf-8")


def _archive_size(infos):
    """Exact size of our seekable, comment-free archives, including ZIP64.

    Member sizes alone omit two filename-bearing headers and the central
    directory. ZIP64 adds local/central extras and end records as necessary.
    We create ZipInfos without custom extras, comments or data descriptors.
    """
    offset = central_size = 0
    for info in infos:
        name_size = len(_filename_bytes(info.filename))
        local_zip64 = info.file_size * 1.05 > zipfile.ZIP64_LIMIT
        local_size = 30 + name_size + (20 if local_zip64 else 0) + info.compress_size
        central_zip64 = 0
        if info.file_size > zipfile.ZIP64_LIMIT or info.compress_size > zipfile.ZIP64_LIMIT:
            central_zip64 += 16
        if offset > zipfile.ZIP64_LIMIT:
            central_zip64 += 8
        central_size += 46 + name_size + (4 + central_zip64 if central_zip64 else 0)
        offset += local_size
    end_size = 22
    if (
        len(infos) > zipfile.ZIP_FILECOUNT_LIMIT
        or offset > zipfile.ZIP64_LIMIT
        or central_size > zipfile.ZIP64_LIMIT
    ):
        end_size += 76
    return offset + central_size + end_size


def _compressed_info(filename, data):
    info = zipfile.ZipInfo(filename)
    info.compress_type = zipfile.ZIP_DEFLATED
    info.file_size = len(data)
    compressor = zlib.compressobj(6, zlib.DEFLATED, -15)
    info.compress_size = len(compressor.compress(data)) + len(compressor.flush())
    return info


def _manifest_bound_info(filename, manifest):
    """Reserve a safe compressed-size bound for every attachment-flag variant."""
    maximum = copy.deepcopy(manifest)

    def reserve_flags(value):
        if isinstance(value, dict):
            if {"name", "bytes", "sha256"}.issubset(value):
                # false is one byte longer than true, and an absent flag is
                # shorter still. Only this copy gains speculative flags.
                value["not_attached"] = False
            for child in value.values():
                reserve_flags(child)
        elif isinstance(value, list):
            for child in value:
                reserve_flags(child)

    reserve_flags(maximum)
    size = len(json_bytes(maximum))
    info = zipfile.ZipInfo(filename)
    info.compress_type = zipfile.ZIP_DEFLATED
    info.file_size = size
    # zlib deflateBound for windowBits=15, memLevel=8 (our compressobj defaults):
    # n + (n>>12) + (n>>14) + (n>>25) + 13 - 6 + wrapper_length.
    # Raw deflate has no wrapper, so the constant is 7. This is a guaranteed
    # upper bound, unlike compressing just the all-missing flag combination.
    # https://github.com/madler/zlib/blob/v1.3.1/deflate.c (deflateBound)
    info.compress_size = size + (size >> 12) + (size >> 14) + (size >> 25) + 7
    return info


@dataclass
class _Member:
    info: zipfile.ZipInfo
    metadata: dict


class _Sink:
    def __init__(self, attach, warn=None):
        self._attach = attach
        self._warn = warn or (lambda message: None)
        self._closed = False
        self._finished = False
        self._downloads = []

    def _ensure_open(self):
        if self._closed or self._finished:
            raise ValueError("artifact sink is already closed")

    def _attach_file(self, filename, data):
        # The Nautobot callback owns ordinary attachment-error handling. A soft
        # time limit also subclasses Exception and must reach the job's handler.
        attached = bool(self._attach(filename, data))
        if attached:
            self._downloads.append(filename)
        return attached

    def close(self):
        """Abandon an unfinished sink; safe to call repeatedly."""
        self._closed = True


class FileSink(_Sink):
    """Attach each device file immediately, preserving separate-file behavior."""

    def add(self, filename, payload, *, device=None, metadata=None):
        self._ensure_open()
        if metadata is None:
            metadata = {}
        metadata["name"] = filename
        try:
            data = json_bytes(payload)
            metadata.update(_metadata(filename, data))
            if not self._attach_file(filename, data):
                metadata["not_attached"] = True
        except BaseException:
            metadata["not_attached"] = True
            raise
        return metadata

    def finish(self, manifest_filename, manifest):
        if self._finished:
            return list(self._downloads)
        self._ensure_open()
        if manifest_filename not in self._downloads:
            self._attach_file(manifest_filename, json_bytes(manifest))
        self._finished = True
        self.close()
        return list(self._downloads)


class ZipSink(_Sink):
    """Spool a run to disk, then attach compressed parts at device boundaries.

    Supply the same ``device`` key for every file belonging to one device.
    Without a key each file is its own group. Repacking streams members rather
    than retaining the run, or even a decompressed large member, in memory.
    An exceptional ``finish`` leaves the source open for retry or explicit
    caller cleanup; a successful ``finish`` closes it.
    """

    def __init__(self, attach, *, kind, filename, max_bytes, warn=None):
        if max_bytes < 1:
            raise ValueError("max_bytes must be positive")
        if not kind or "/" in kind or "\\" in kind or kind in (".", ".."):
            raise ValueError("kind must be a single folder name")
        super().__init__(attach, warn)
        self.kind = kind
        self.filename = filename
        self.max_bytes = max_bytes
        self._groups = OrderedDict()
        self._add_failed = set()
        self._confirmed = set()
        self._attempted = set()
        self._finish_parts = None
        self._manifest_name = None
        self._manifest_filename = None
        self._finalizing = False
        self._names = set()
        self._spool = tempfile.TemporaryFile()
        try:
            self._zip = zipfile.ZipFile(
                self._spool, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6
            )
        except Exception:
            self._spool.close()
            raise

    def add(self, filename, payload, *, device=None, metadata=None):
        self._ensure_open()
        if self._finalizing:
            raise ValueError("cannot add artifacts after finalization starts")
        if filename in self._names:
            raise ValueError("duplicate artifact filename: %s" % filename)
        if metadata is None:
            metadata = {}
        metadata["name"] = filename
        try:
            data = json_bytes(payload)
            metadata.update(_metadata(filename, data))
            name = "%s/%s" % (self.kind, filename)
            self._zip.writestr(name, data)
            self._names.add(filename)
            key = ("device", device) if device is not None else ("file", filename)
            self._groups.setdefault(key, []).append(_Member(self._zip.getinfo(name), metadata))
        except BaseException:
            metadata["not_attached"] = True
            self._add_failed.add(id(metadata))
            raise
        return metadata

    def _mark_missing(self, members):
        for member in members:
            member.metadata["not_attached"] = True

    def _mark_confirmed(self, members):
        for member in members:
            member.metadata.pop("not_attached", None)
            self._confirmed.add(id(member.metadata))

    def _plan(self):
        groups = []
        for original in self._groups.values():
            members = [member for member in original if id(member.metadata) not in self._add_failed]
            if not members:
                continue
            if _archive_size([member.info for member in members]) > self.max_bytes:
                self._mark_missing(members)
                self._warn(
                    "Device artifacts %s exceed the zip size cap (%d bytes); not attached"
                    % (", ".join(member.metadata["name"] for member in members), self.max_bytes)
                )
            else:
                groups.append(members)
        return groups

    def _parts(self, groups, manifest_info):
        parts = [[]]
        infos = [manifest_info] if manifest_info is not None else []
        for members in groups:
            additions = [member.info for member in members]
            if _archive_size(infos + additions) > self.max_bytes:
                parts.append([])
                infos = []
            parts[-1].extend(members)
            infos.extend(additions)
        return parts

    def _part_filename(self, index, count):
        if count == 1:
            return self.filename
        stem = self.filename[:-4] if self.filename.lower().endswith(".zip") else self.filename
        return "%s_part%dof%d.zip" % (stem, index + 1, count)

    def _prepare_finish(self, manifest_filename, manifest):
        groups = self._plan()
        manifest_name = "%s/%s" % (self.kind, manifest_filename)
        info = _compressed_info(manifest_name, json_bytes(manifest))
        if _archive_size([info]) > self.max_bytes:
            self._warn(
                "Manifest %s exceeds the zip size cap (%d bytes); not attached"
                % (manifest_filename, self.max_bytes)
            )
            manifest_name = info = None
        parts = self._parts(groups, info)
        if info is not None and len(parts) > 1:
            # Earlier part failures can change the manifest's compressed size.
            # Keep the plan fixed across retries, reserving the guaranteed bound.
            bound = _manifest_bound_info(manifest_name, manifest)
            if _archive_size([bound]) <= self.max_bytes:
                parts = self._parts(groups, bound)
            else:
                # Even the reservation alone exceeds the cap. Isolate the
                # manifest so flag growth can never evict healthy device files.
                parts = [[]] + self._parts(groups, None)
        self._manifest_name = manifest_name
        self._manifest_filename = manifest_filename
        self._finish_parts = parts

    def _build_part(self, source, members, manifest_name=None, manifest_data=None):
        with tempfile.TemporaryFile() as spool:
            with zipfile.ZipFile(
                spool, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6
            ) as archive:
                if manifest_name is not None:
                    archive.writestr(manifest_name, manifest_data)
                for member in members:
                    info = copy.copy(member.info)
                    with source.open(member.info) as reader, archive.open(info, "w") as writer:
                        shutil.copyfileobj(reader, writer, length=64 * 1024)
            size = spool.tell()
            if size > self.max_bytes:
                raise ValueError("zip part exceeds its planned size cap: %d bytes" % size)
            spool.seek(0)
            return spool.read()

    def finish(self, manifest_filename, manifest):
        if self._finished:
            return list(self._downloads)
        self._ensure_open()
        self._finalizing = True
        if self._finish_parts is None:
            self._prepare_finish(manifest_filename, manifest)
        elif manifest_filename != self._manifest_filename:
            raise ValueError("cannot change the manifest filename during finalization")
        parts = self._finish_parts
        # ZipFile.open(info, 'r') can read completed members before its writer
        # closes. Keep the source writer open: interrupted central-directory
        # finalization is then never a prerequisite for recovering staged data.
        for index in list(range(1, len(parts))) + [0]:
            members = parts[index]
            name = self._part_filename(index, len(parts))
            if name in self._downloads:
                self._mark_confirmed(members)
                continue
            if name in self._attempted:
                self._mark_missing(members)
                continue
            # A part without a recorded attempt is still pending. Clear any
            # interrupted-attempt flags before serializing part 1's manifest.
            for member in members:
                member.metadata.pop("not_attached", None)
            manifest_name = self._manifest_name if index == 0 else None
            manifest_data = json_bytes(manifest) if manifest_name is not None else None
            if manifest_name is not None:
                infos = [_compressed_info(manifest_name, manifest_data)]
                infos.extend(member.info for member in members)
                if _archive_size(infos) > self.max_bytes:
                    self._warn(
                        "Updated manifest %s exceeds its reserved zip capacity; not attached"
                        % manifest_filename
                    )
                    manifest_name = manifest_data = None
            if not members and manifest_name is None:
                self._attempted.add(name)
                continue
            data = self._build_part(self._zip, members, manifest_name, manifest_data)
            attached = self._attach_file(name, data)
            # Record the terminal callback result before metadata changes. A
            # signal while marking missing files can then be resumed faithfully.
            self._attempted.add(name)
            if attached:
                self._mark_confirmed(members)
            else:
                self._mark_missing(members)
            del data
        self._finished = True
        self.close()
        return list(self._downloads)

    def close(self):
        try:
            if not self._spool.closed:
                self._zip.close()
        finally:
            # A signal before ZipFile.close enters its own finally can leave fp
            # pointing to our soon-closed spool. Detach it first so repeated
            # cleanup and ZipFile.__del__ cannot seek a closed file.
            self._zip.fp = None
            try:
                self._spool.close()
            finally:
                try:
                    if not self._finished:
                        for members in self._groups.values():
                            self._mark_missing(
                                member
                                for member in members
                                if id(member.metadata) not in self._confirmed
                            )
                finally:
                    super().close()
