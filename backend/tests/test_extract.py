import gzip
import io
import zipfile

import pytest

from dmarc.config import Settings
from dmarc.parsing.extract import ExtractionError, LimitExceeded, extract_payloads, sniff
from tests.conftest import fixture_bytes

XML = fixture_bytes("src", "google.xml")


def _zip(files: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for n, d in files.items():
            zf.writestr(n, d)
    return buf.getvalue()


def test_sniff():
    assert sniff(XML) == "xml"
    assert sniff(b"\xef\xbb\xbf  <?xml version='1.0'?><a/>") == "xml"
    assert sniff(gzip.compress(XML)) == "gzip"
    assert sniff(_zip({"a.xml": XML})) == "zip"
    assert sniff(b"%PDF-1.4") == "unknown"


def test_plain_xml(settings):
    [p] = extract_payloads(XML, "r.xml", settings)
    assert p.data == XML and p.name == "r.xml"


def test_gzip(settings):
    [p] = extract_payloads(gzip.compress(XML), "report.xml.gz", settings)
    assert p.data == XML and p.name == "report.xml"


def test_zip_multiple_members_skips_non_xml(settings):
    payloads = extract_payloads(fixture_bytes("rua", "multi.zip"), "multi.zip", settings)
    assert sorted(p.name for p in payloads) == ["google.xml", "yahoo.xml"]


def test_zip_with_gz_inside(settings):
    [p] = extract_payloads(fixture_bytes("rua", "nested.zip"), "nested.zip", settings)
    assert p.name == "microsoft.xml" and b"<feedback" in p.data


def test_zip_without_xml(settings):
    with pytest.raises(ExtractionError, match="no XML"):
        extract_payloads(_zip({"readme.txt": b"hello"}), "x.zip", settings)


def test_corrupt_inputs(settings):
    with pytest.raises(ExtractionError, match="gzip"):
        extract_payloads(fixture_bytes("broken", "corrupt.xml.gz"), "c.gz", settings)
    with pytest.raises(ExtractionError, match="zip"):
        extract_payloads(fixture_bytes("broken", "corrupt.zip"), "c.zip", settings)
    with pytest.raises(ExtractionError, match="not XML"):
        extract_payloads(b"%PDF-1.4 ...", "x.pdf", settings)


def small_limits(**kw) -> Settings:
    base = dict(max_uncompressed_bytes=2 * 1024 * 1024, max_total_uncompressed_bytes=3 * 1024 * 1024)
    base.update(kw)
    return Settings(_env_file=None, **base)


def test_gzip_bomb_rejected():
    bomb = gzip.compress(b"<" + b"\0" * (10 * 1024 * 1024))  # ~10 KB -> 10 MB
    with pytest.raises(LimitExceeded):
        extract_payloads(bomb, "bomb.xml.gz", small_limits())


def test_zip_bomb_rejected():
    bomb = _zip({"bomb.xml": b"<" + b"\0" * (10 * 1024 * 1024)})
    with pytest.raises(LimitExceeded):
        extract_payloads(bomb, "bomb.zip", small_limits())


def test_zip_total_size_limit():
    member = b"<" + b"a" * (1536 * 1024)
    z = _zip({f"{i}.xml": member for i in range(3)})
    with pytest.raises(LimitExceeded, match="total"):
        extract_payloads(z, "many.zip", small_limits(max_compression_ratio=100000))


def test_compression_ratio_limit():
    data = gzip.compress(b"<" + b"\0" * (1800 * 1024))
    with pytest.raises(LimitExceeded, match="ratio"):
        extract_payloads(data, "r.gz", small_limits(max_compression_ratio=50))


def test_too_many_members():
    z = _zip({f"{i}.xml": XML for i in range(11)})
    with pytest.raises(LimitExceeded, match="members"):
        extract_payloads(z, "many.zip", Settings(_env_file=None, max_archive_members=10))


def test_nesting_depth_limit():
    data = XML
    for _ in range(4):
        data = gzip.compress(data)
    with pytest.raises(LimitExceeded, match="nesting"):
        extract_payloads(data, "deep.gz", Settings(_env_file=None, max_nesting_depth=2))


def test_attachment_size_limit():
    with pytest.raises(LimitExceeded, match="attachment"):
        extract_payloads(XML, "big.xml", Settings(_env_file=None, max_attachment_bytes=100))
