import hashlib

import pytest

from phishscope.extractors import ExtractorAnalyzer
from phishscope.models import AttachmentInfo, ParsedEmail, Severity


@pytest.fixture
def empty_email():
    return ParsedEmail(
        file_path="memory",
        file_sha256="hash",
        subject="",
        from_header="",
        to_headers=[],
        cc_headers=[],
        date=None,
        message_id="",
        reply_to="",
        return_path="",
        received_headers=[],
        x_headers={},
        raw_headers=[],
        body_plain="",
        body_html="",
        attachments=[],
        defects=[],
    )


def test_extract_plain_text_urls(empty_email):
    email = ParsedEmail(
        **{
            **empty_email.__dict__,
            "body_plain": "Check out http://example.com and hxxps://evil[.]com/login",
        }
    )
    analyzer = ExtractorAnalyzer()
    findings, urls = analyzer.analyze(email)

    assert len(urls) == 2

    normal_url = next(u for u in urls if "example.com" in u.hostname)
    assert normal_url.original == "http://example.com"
    assert normal_url.normalized == "http://example.com"
    assert normal_url.defanged == "hxxp://example[.]com"
    assert normal_url.scheme == "http"

    obfuscated_url = next(u for u in urls if "evil.com" in u.hostname)
    assert obfuscated_url.original == "hxxps://evil[.]com/login"
    assert obfuscated_url.normalized == "https://evil.com/login"
    assert obfuscated_url.defanged == "hxxps://evil[.]com/login"


def test_extract_html_urls(empty_email):
    html = (
        '<html><body><a href="https://example.com">Click</a> '
        '<a href="javascript:alert(1)">XSS</a></body></html>'
    )
    email = ParsedEmail(**{**empty_email.__dict__, "body_html": html})
    analyzer = ExtractorAnalyzer()
    findings, urls = analyzer.analyze(email)

    assert len(urls) == 2
    assert any(u.scheme == "javascript" for u in urls)

    # Check finding for suspicious scheme
    assert any(f.id == "URL-SUSPICIOUS-SCHEME" for f in findings)


def test_link_text_mismatch(empty_email):
    html = '<a href="http://attacker.com">http://paypal.com/login</a>'
    email = ParsedEmail(**{**empty_email.__dict__, "body_html": html})
    analyzer = ExtractorAnalyzer()
    findings, urls = analyzer.analyze(email)

    mismatch = next(f for f in findings if f.id == "URL-LINK-MISMATCH")
    assert mismatch.severity == Severity.MEDIUM
    assert "paypal.com" in mismatch.evidence
    assert "attacker.com" in mismatch.evidence


def test_ip_based_url(empty_email):
    email = ParsedEmail(**{**empty_email.__dict__, "body_plain": "Go to http://192.168.1.1/admin"})
    analyzer = ExtractorAnalyzer()
    findings, urls = analyzer.analyze(email)

    ip_finding = next(f for f in findings if f.id == "URL-IP-BASED")
    assert "192.168.1.1" in ip_finding.evidence


def test_url_shortener(empty_email):
    email = ParsedEmail(**{**empty_email.__dict__, "body_plain": "http://bit.ly/12345"})
    analyzer = ExtractorAnalyzer()
    findings, urls = analyzer.analyze(email)

    assert any(f.id == "URL-SHORTENER" for f in findings)


def test_punycode_url(empty_email):
    email = ParsedEmail(**{**empty_email.__dict__, "body_plain": "http://xn--bcher-kva.example"})
    analyzer = ExtractorAnalyzer()
    findings, urls = analyzer.analyze(email)

    assert any(f.id == "URL-IDN-PUNYCODE" for f in findings)


def test_deep_subdomain(empty_email):
    email = ParsedEmail(**{**empty_email.__dict__, "body_plain": "http://a.b.c.d.e.example.com"})
    analyzer = ExtractorAnalyzer()
    findings, urls = analyzer.analyze(email)

    assert any(f.id == "URL-DEEP-SUBDOMAIN" for f in findings)


def test_attachment_hashes_and_types(empty_email):
    payload = b"Hello, World!"
    sha256 = hashlib.sha256(payload).hexdigest()
    md5 = hashlib.md5(payload).hexdigest()

    att = AttachmentInfo(
        filename="invoice.pdf.exe",
        sanitized_filename="invoice.pdf.exe",
        content_type="application/octet-stream",
        size_bytes=len(payload),
        payload_bytes=payload,
    )

    email = ParsedEmail(**{**empty_email.__dict__, "attachments": [att]})
    analyzer = ExtractorAnalyzer()
    findings, urls = analyzer.analyze(email)

    hash_finding = next(f for f in findings if f.id == "ATT-HASHES")
    assert sha256 in hash_finding.evidence
    assert md5 in hash_finding.evidence

    double_ext = next(f for f in findings if f.id == "ATT-DOUBLE-EXTENSION")
    assert double_ext.severity == Severity.HIGH


def test_macro_document(empty_email):
    att = AttachmentInfo(
        filename="report.docm",
        sanitized_filename="report.docm",
        content_type="application/vnd.ms-word.document.macroEnabled.12",
        size_bytes=100,
        payload_bytes=b"",
    )
    email = ParsedEmail(**{**empty_email.__dict__, "attachments": [att]})
    analyzer = ExtractorAnalyzer()
    findings, urls = analyzer.analyze(email)
    assert any(f.id == "ATT-MACRO-DOC" for f in findings)


def test_iso_and_lnk_attachments(empty_email):
    att1 = AttachmentInfo(
        filename="image.iso",
        sanitized_filename="image.iso",
        content_type="application/x-iso9660-image",
        size_bytes=100,
        payload_bytes=b"",
    )
    att2 = AttachmentInfo(
        filename="shortcut.lnk",
        sanitized_filename="shortcut.lnk",
        content_type="application/x-ms-shortcut",
        size_bytes=100,
        payload_bytes=b"",
    )
    email = ParsedEmail(**{**empty_email.__dict__, "attachments": [att1, att2]})
    analyzer = ExtractorAnalyzer()
    findings, urls = analyzer.analyze(email)
    assert any(f.id == "ATT-ISO" for f in findings)
    assert any(f.id == "ATT-LNK" for f in findings)


def test_mime_mismatch(empty_email):
    att = AttachmentInfo(
        filename="document.pdf",
        sanitized_filename="document.pdf",
        content_type="application/x-dosexec",
        size_bytes=100,
        payload_bytes=b"",
    )
    email = ParsedEmail(**{**empty_email.__dict__, "attachments": [att]})
    analyzer = ExtractorAnalyzer()
    findings, urls = analyzer.analyze(email)
    assert any(f.id == "ATT-MIME-MISMATCH" for f in findings)
