"""Safe extraction of report payloads from attachments.

Supports plain XML, gzip (.xml.gz / .gz), zip (possibly with multiple members) and
nesting up to ``max_nesting_depth``. All decompression is streamed with hard limits
so that zip/gzip bombs are rejected instead of exhausting memory. Nothing is ever
written to disk or executed.
"""

from __future__ import annotations

import gzip
import io
import zipfile
import zlib
from dataclasses import dataclass

from dmarc.config import Settings, get_settings

GZIP_MAGIC = b"\x1f\x8b"
ZIP_MAGIC = (b"PK\x03\x04", b"PK\x05\x06")
CHUNK = 64 * 1024


class ExtractionError(Exception):
    """Payload could not be extracted (corrupt archive, limit exceeded, ...)."""


class LimitExceeded(ExtractionError):
    """A safety limit (size, member count, ratio, nesting) was exceeded."""


@dataclass(frozen=True)
class Payload:
    name: str
    data: bytes


def sniff(data: bytes) -> str:
    """Return 'gzip', 'zip', 'xml' or 'unknown' based on content, not filename."""
    if data.startswith(GZIP_MAGIC):
        return "gzip"
    if data.startswith(ZIP_MAGIC):
        return "zip"
    head = data[:512].lstrip(b"\xef\xbb\xbf\r\n\t ")
    if head.startswith(b"\xff\xfe") or head.startswith(b"\xfe\xff"):
        return "xml"  # UTF-16 with BOM, let the XML parser decide
    if head.startswith(b"<"):
        return "xml"
    return "unknown"


def _check_ratio(uncompressed: int, compressed: int, s: Settings, name: str) -> None:
    # Small files compress extremely well legitimately; only apply the ratio check
    # once there is enough data for it to be meaningful.
    if uncompressed > 1024 * 1024 and compressed > 0 and uncompressed / compressed > s.max_compression_ratio:
        raise LimitExceeded(f"{name}: compression ratio exceeds {s.max_compression_ratio}:1")


def _gunzip(data: bytes, name: str, s: Settings) -> bytes:
    out = io.BytesIO()
    total = 0
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(data)) as gz:
            while True:
                chunk = gz.read(CHUNK)
                if not chunk:
                    break
                total += len(chunk)
                if total > s.max_uncompressed_bytes:
                    raise LimitExceeded(f"{name}: decompressed size exceeds {s.max_uncompressed_bytes} bytes")
                _check_ratio(total, len(data), s, name)
                out.write(chunk)
    except (OSError, EOFError, zlib.error) as exc:
        raise ExtractionError(f"{name}: invalid gzip data ({exc})") from exc
    return out.getvalue()


def _unzip(data: bytes, name: str, s: Settings) -> list[Payload]:
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except (zipfile.BadZipFile, zlib.error, ValueError) as exc:
        raise ExtractionError(f"{name}: invalid zip archive ({exc})") from exc

    with zf:
        members = [i for i in zf.infolist() if not i.is_dir()]
        if len(members) > s.max_archive_members:
            raise LimitExceeded(f"{name}: {len(members)} members exceeds limit of {s.max_archive_members}")

        results: list[Payload] = []
        grand_total = 0
        for info in members:
            if info.flag_bits & 0x1:
                raise ExtractionError(f"{name}: encrypted zip member {info.filename!r}")
            # Declared size is attacker-controlled; check it, but also enforce while reading.
            if info.file_size > s.max_uncompressed_bytes:
                raise LimitExceeded(f"{name}/{info.filename}: declared size exceeds limit")
            buf = io.BytesIO()
            size = 0
            try:
                with zf.open(info) as fh:
                    while True:
                        chunk = fh.read(CHUNK)
                        if not chunk:
                            break
                        size += len(chunk)
                        grand_total += len(chunk)
                        if size > s.max_uncompressed_bytes:
                            raise LimitExceeded(f"{name}/{info.filename}: decompressed size exceeds limit")
                        if grand_total > s.max_total_uncompressed_bytes:
                            raise LimitExceeded(f"{name}: total decompressed size exceeds limit")
                        _check_ratio(size, max(info.compress_size, 1), s, f"{name}/{info.filename}")
                        buf.write(chunk)
            except (zipfile.BadZipFile, zlib.error, EOFError, NotImplementedError) as exc:
                raise ExtractionError(f"{name}/{info.filename}: cannot read member ({exc})") from exc
            # Strip any path component; we never touch the filesystem but keep names tidy.
            member_name = info.filename.replace("\\", "/").rsplit("/", 1)[-1]
            results.append(Payload(member_name, buf.getvalue()))
        return results


def extract_payloads(data: bytes, name: str = "attachment", settings: Settings | None = None, _depth: int = 0) -> list[Payload]:
    """Return all XML payloads contained in ``data``.

    Non-XML members inside archives are skipped silently (e.g. a README in a zip).
    Raises ExtractionError if the data is corrupt or no XML could be found at top level.
    """
    s = settings or get_settings()
    if _depth > s.max_nesting_depth:
        raise LimitExceeded(f"{name}: archive nesting deeper than {s.max_nesting_depth}")
    if _depth == 0 and len(data) > s.max_attachment_bytes:
        raise LimitExceeded(f"{name}: attachment of {len(data)} bytes exceeds limit")

    kind = sniff(data)
    if kind == "xml":
        return [Payload(name, data)]
    if kind == "gzip":
        inner_name = name[:-3] if name.lower().endswith(".gz") else name
        return extract_payloads(_gunzip(data, name, s), inner_name, s, _depth + 1)
    if kind == "zip":
        payloads: list[Payload] = []
        for member in _unzip(data, name, s):
            if sniff(member.data) == "unknown":
                continue
            payloads.extend(extract_payloads(member.data, member.name, s, _depth + 1))
        if _depth == 0 and not payloads:
            raise ExtractionError(f"{name}: zip archive contains no XML report")
        return payloads
    if _depth == 0:
        raise ExtractionError(f"{name}: not XML, gzip or zip data")
    return []
