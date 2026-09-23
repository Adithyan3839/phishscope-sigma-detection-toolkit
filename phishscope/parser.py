import email
import email.utils
import hashlib
import logging
import re
from datetime import datetime
from email.message import EmailMessage
from email.policy import default
from pathlib import Path

from phishscope.models import AttachmentInfo, ParsedEmail, ReceivedHop

logger = logging.getLogger(__name__)


class ParserError(Exception):
    """Fatal error when parsing cannot proceed."""

    pass


class EmailParser:
    """Safe, structural email parser."""

    MAX_FILE_SIZE = 25 * 1024 * 1024  # 25 MB
    MAX_MIME_DEPTH = 50

    def parse_file(self, file_path: str | Path) -> ParsedEmail:
        """Parses an .eml file from disk safely."""
        path = Path(file_path)

        if not path.exists():
            raise ParserError(f"File does not exist: {path}")
        if not path.is_file():
            raise ParserError(f"Path is not a file: {path}")

        file_size = path.stat().st_size
        if file_size > self.MAX_FILE_SIZE:
            raise ParserError(f"File size {file_size} exceeds maximum {self.MAX_FILE_SIZE} bytes")

        try:
            raw_bytes = path.read_bytes()
        except OSError as e:
            raise ParserError(f"Failed to read file: {e}") from e

        return self.parse_bytes(raw_bytes, str(path))

    def parse_bytes(self, raw_bytes: bytes, file_path: str = "memory") -> ParsedEmail:
        """Parses email from raw bytes."""
        file_sha256 = hashlib.sha256(raw_bytes).hexdigest()

        # Parse with default policy (handles RFC 2047 decoding, body extraction)
        msg: EmailMessage = email.message_from_bytes(raw_bytes, policy=default)

        return self._build_parsed_email(msg, file_path, file_sha256)

    def _build_parsed_email(
        self, msg: EmailMessage, file_path: str, file_sha256: str
    ) -> ParsedEmail:
        date_obj = self._parse_date(msg.get("Date", ""))

        # Standard headers
        subject = msg.get("Subject", "")
        from_header = msg.get("From", "")
        to_headers = [t.strip() for t in msg.get_all("To", []) if t.strip()]
        cc_headers = [c.strip() for c in msg.get_all("Cc", []) if c.strip()]
        message_id = msg.get("Message-ID", "")
        reply_to = msg.get("Reply-To", "")
        return_path = msg.get("Return-Path", "")

        # Received headers
        raw_received = msg.get_all("Received", [])
        received_hops = [
            ReceivedHop(hop_number=i + 1, raw_content=val.strip())
            for i, val in enumerate(raw_received)
        ]

        # X-Headers and raw
        x_headers = {}
        raw_headers = []
        for k, v in msg.items():
            raw_headers.append((k, v))
            k_lower = k.lower()
            if k_lower.startswith("x-"):
                x_headers.setdefault(k_lower, []).append(v)

        # Body and Attachments
        attachments = []
        attachments = []

        # The walker uses lists to mutate, so we gather them here
        # It's possible to have multiple text/plain parts in a mixed email, join them.
        body_plain_list: list[str] = []
        body_html_list: list[str] = []
        self._walk_parts(msg, attachments, body_plain_list, body_html_list, depth=0)

        defects = [type(defect).__name__ for defect in msg.defects]

        return ParsedEmail(
            file_path=file_path,
            file_sha256=file_sha256,
            subject=subject,
            from_header=from_header,
            to_headers=to_headers,
            cc_headers=cc_headers,
            date=date_obj,
            message_id=message_id,
            reply_to=reply_to,
            return_path=return_path,
            received_headers=received_hops,
            x_headers=x_headers,
            raw_headers=raw_headers,
            body_plain="\n".join(body_plain_list),
            body_html="\n".join(body_html_list),
            attachments=attachments,
            defects=defects,
        )

    def _walk_parts(
        self, part, attachments: list, body_plain_list: list, body_html_list: list, depth: int
    ):
        """Recursively walk MIME parts safely with a depth limit."""
        if depth > self.MAX_MIME_DEPTH:
            logger.warning("Max MIME depth reached, stopping recursion.")
            return

        if part.is_multipart():
            for subpart in part.iter_parts():
                self._walk_parts(subpart, attachments, body_plain_list, body_html_list, depth + 1)
            return

        content_disposition = part.get_content_disposition()
        filename = part.get_filename()

        # If it has a filename or is explicitly an attachment, treat as attachment
        if content_disposition == "attachment" or filename:
            self._handle_attachment(part, filename, attachments)
            return

        # Otherwise, check if it's text body
        content_type = part.get_content_type()

        if content_type == "text/plain":
            try:
                body_plain_list.append(part.get_content())
            except Exception as e:
                logger.warning(f"Failed to decode text/plain body: {e}")
        elif content_type == "text/html":
            try:
                body_html_list.append(part.get_content())
            except Exception as e:
                logger.warning(f"Failed to decode text/html body: {e}")
        else:
            # Inline non-text elements (e.g. inline images without explicit disposition)
            # If they have a filename, they are caught above. If not, they are just random parts.
            pass

    def _handle_attachment(self, part, original_filename: str | None, attachments: list):
        """Safely extract and sanitize attachment information."""
        raw_filename = original_filename or "unnamed_attachment"
        sanitized = self._sanitize_filename(raw_filename)
        content_type = part.get_content_type()

        try:
            payload_bytes = part.get_content()
            if isinstance(payload_bytes, str):
                payload_bytes = payload_bytes.encode("utf-8", errors="replace")
        except Exception as e:
            logger.warning(f"Failed to decode attachment bytes: {e}")
            payload_bytes = b""

        # get_content() tries to decode base64/qp and return bytes for binary
        # Or string for text. If it fails, fallback to get_payload(decode=True)
        if not payload_bytes:
            payload_bytes = part.get_payload(decode=True) or b""

        attachments.append(
            AttachmentInfo(
                filename=raw_filename,
                sanitized_filename=sanitized,
                content_type=content_type,
                size_bytes=len(payload_bytes),
                payload_bytes=payload_bytes,
            )
        )

    def _sanitize_filename(self, filename: str) -> str:
        """Removes directory paths and unsafe characters from a filename."""
        # Remove directory paths (both Unix and Windows)
        base = Path(filename).name
        # Remove null bytes
        base = base.replace("\x00", "")
        # Allow only safe characters
        sanitized = re.sub(r"[^a-zA-Z0-9.\-_ ]", "_", base)
        return sanitized.strip()

    def _parse_date(self, date_str: str) -> datetime | None:
        """Safely parse RFC 2822 date."""
        if not date_str:
            return None
        parsed_tuple = email.utils.parsedate_tz(date_str)
        if parsed_tuple:
            return email.utils.datetime.datetime.fromtimestamp(
                email.utils.mktime_tz(parsed_tuple), email.utils.datetime.timezone.utc
            )
        return None
