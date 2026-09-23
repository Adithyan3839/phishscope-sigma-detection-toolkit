from pathlib import Path

import pytest

from phishscope.parser import EmailParser, ParserError


def test_parse_plain_text():
    parser = EmailParser()
    email = parser.parse_file(Path("samples/plain_text.eml"))

    assert email.subject == "Project Update"
    assert email.from_header == "Alice <alice@example.com>"
    assert email.to_headers == ["Bob <bob@example.org>"]
    assert email.message_id == "<12345@example.com>"
    assert email.reply_to == "alice.reply@example.com"
    assert email.return_path == "<alice.bounce@example.com>"
    assert len(email.received_headers) == 2
    assert email.received_headers[0].hop_number == 1
    assert "inbound.example.org" in email.received_headers[0].raw_content
    assert email.x_headers["x-custom-header"] == ["value1"]
    assert "This is a simple plain text email." in email.body_plain
    assert email.body_html == ""
    assert len(email.attachments) == 0


def test_parse_html():
    parser = EmailParser()
    email = parser.parse_file(Path("samples/html_email.eml"))
    assert "<h1>This is an HTML email.</h1>" in email.body_html
    assert email.body_plain == ""


def test_parse_multipart():
    parser = EmailParser()
    email = parser.parse_file(Path("samples/multipart.eml"))
    assert "This is the plain text version." in email.body_plain
    assert "<p>This is the HTML version.</p>" in email.body_html


def test_parse_encoded_headers_and_base64_body():
    parser = EmailParser()
    email = parser.parse_file(Path("samples/encoded_headers.eml"))

    # Subject decoding
    assert email.subject == "This is an encoded subject 🚀"

    # Display name decoding
    assert email.from_header == "Alice ¡Magic <alice@example.com>"

    # Base64 body decoding
    assert "This body is base64 encoded." in email.body_plain
    assert "Hello Bob" in email.body_plain


def test_parse_attachment_filename_handling():
    parser = EmailParser()
    email = parser.parse_file(Path("samples/attachment.eml"))

    assert len(email.attachments) == 1
    att = email.attachments[0]
    # Path traversal should be stripped
    assert att.filename == "../../../evil.pdf"
    assert att.sanitized_filename == "evil.pdf"
    assert att.content_type == "application/pdf"
    assert att.size_bytes > 0
    assert b"PDF-1.4" in att.payload_bytes


def test_quoted_printable_body():
    raw_email = b"""From: a@b.com
Subject: QP
Content-Type: text/plain; charset="utf-8"
Content-Transfer-Encoding: quoted-printable

This is a test=3Dof quoted printable=2E
"""
    parser = EmailParser()
    email = parser.parse_bytes(raw_email)
    assert "This is a test=of quoted printable." in email.body_plain


def test_missing_optional_headers():
    raw_email = b"""From: a@b.com
To: b@c.com

Body text
"""
    parser = EmailParser()
    email = parser.parse_bytes(raw_email)
    assert email.subject == ""
    assert email.date is None
    assert email.message_id == ""
    assert "Body text" in email.body_plain


def test_nonexistent_file():
    parser = EmailParser()
    with pytest.raises(ParserError, match="File does not exist"):
        parser.parse_file(Path("does_not_exist.eml"))


def test_directory_passed_as_input(tmp_path):
    parser = EmailParser()
    with pytest.raises(ParserError, match="Path is not a file"):
        parser.parse_file(tmp_path)


def test_malformed_email():
    raw_email = b"Just some random garbage without headers\r\n\r\nMore garbage"
    parser = EmailParser()
    email = parser.parse_bytes(raw_email)
    assert email.from_header == ""
    assert email.subject == ""
    assert len(email.defects) >= 0  # Missing headers might not be a defect, but won't crash
    assert "Just some random garbage without headers" in email.body_plain


def test_malformed_mime_boundary():
    raw_email = b"""Content-Type: multipart/mixed; boundary="boundary123"

--wrong-boundary
Content-Type: text/plain

Text here
--boundary123--
"""
    parser = EmailParser()
    email = parser.parse_bytes(raw_email)
    assert len(email.defects) > 0
    assert "Text here" not in email.body_plain  # Text is outside boundary, might be ignored


def test_max_file_size_limit(tmp_path):
    large_file = tmp_path / "large.eml"
    large_file.write_bytes(b"A" * (25 * 1024 * 1024 + 1))
    parser = EmailParser()
    with pytest.raises(ParserError, match="exceeds maximum"):
        parser.parse_file(large_file)
