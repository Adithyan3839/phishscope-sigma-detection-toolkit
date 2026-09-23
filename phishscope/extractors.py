import hashlib
import ipaddress
import re
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urlparse

from phishscope.models import (
    Confidence,
    Finding,
    FindingCategory,
    ParsedEmail,
    Severity,
    URLInfo,
)

# Common URL shorteners
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly"}

# Potentially suspicious schemes
SUSPICIOUS_SCHEMES = {"javascript", "file", "data", "vbscript"}

# Macro extensions
MACRO_EXTENSIONS = {".docm", ".xlsm", ".pptm", ".dotm", ".xltm"}


class SafeHTMLParser(HTMLParser):
    """Safely extracts links and their visible text from HTML without executing it."""

    def __init__(self):
        super().__init__()
        self.extracted_links = []
        self._current_href = None
        self._current_text = []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            for attr, value in attrs:
                if attr == "href":
                    self._current_href = value
                    self._current_text = []

    def handle_data(self, data):
        if self._current_href is not None:
            self._current_text.append(data)

    def handle_endtag(self, tag):
        if tag == "a" and self._current_href is not None:
            text = "".join(self._current_text).strip()
            self.extracted_links.append((self._current_href, text))
            self._current_href = None
            self._current_text = []


class ExtractorAnalyzer:
    """Analyzes email bodies and attachments for IOCs and suspicious indicators."""

    def __init__(
        self,
        url_len_threshold: int = 150,
        subdomain_depth_threshold: int = 4,
        large_attachment_bytes: int = 10 * 1024 * 1024,
    ):
        self.url_len_threshold = url_len_threshold
        self.subdomain_depth_threshold = subdomain_depth_threshold
        self.large_attachment_bytes = large_attachment_bytes
        # Regex to find URLs in plain text. Catches standard and obfuscated variants.
        # It looks for http/https/hxxp/hxxps followed by :// and non-space characters.
        self.text_url_re = re.compile(r'(?:https?|hxxps?)://[^\s<>"]+', re.IGNORECASE)

    def analyze(self, email_data: ParsedEmail) -> tuple[list[Finding], list[URLInfo]]:
        findings = []

        # Analyze URLs
        html_urls = self._extract_html_urls(email_data.body_html)
        text_urls = self._extract_text_urls(email_data.body_plain)

        all_url_infos = html_urls + text_urls
        # Deduplicate on the normalized string
        seen_normalized = set()
        unique_urls = []
        for u in all_url_infos:
            if u.normalized not in seen_normalized:
                seen_normalized.add(u.normalized)
                unique_urls.append(u)

        for uinfo in unique_urls:
            findings.extend(self._analyze_url(uinfo))

        # Analyze Attachments
        findings.extend(self._analyze_attachments(email_data))

        return findings, unique_urls

    def _normalize_url_string(self, raw_url: str) -> str:
        """De-obfuscates hxxp and [.] structures for internal analysis."""
        norm = raw_url
        norm = re.sub(
            r"^hxxps?://", lambda m: m.group(0).replace("x", "t"), norm, flags=re.IGNORECASE
        )
        norm = norm.replace("[.]", ".")
        return norm

    def _defang_url(self, normalized_url: str) -> str:
        """Deterministically defangs a URL for safe reporting."""
        defanged = normalized_url
        defanged = re.sub(
            r"^https?://", lambda m: m.group(0).replace("t", "x", 2), defanged, flags=re.IGNORECASE
        )
        # We only replace dots in the hostname
        defanged = defanged.replace(".", "[.]")
        return defanged

    def _build_url_info(
        self, raw_url: str, source: str, link_text: str | None = None
    ) -> URLInfo | None:
        try:
            normalized = self._normalize_url_string(raw_url)
            parsed = urlparse(normalized)

            # If there's no scheme and no netloc, it might be heavily malformed.
            # E.g., 'http://' missing. urlparse handles it, but scheme might be empty.
            if not parsed.scheme and not parsed.netloc:
                return None

            defanged = self._defang_url(normalized)

            return URLInfo(
                original=raw_url,
                normalized=normalized,
                defanged=defanged,
                scheme=parsed.scheme.lower(),
                hostname=(parsed.hostname or "").lower(),
                port=parsed.port,
                path=parsed.path,
                query=parsed.query,
                source=source,
                link_text=link_text,
            )
        except Exception:
            return None

    def _extract_html_urls(self, body_html: str) -> list[URLInfo]:
        urls = []
        if not body_html:
            return urls

        parser = SafeHTMLParser()
        try:
            parser.feed(body_html)
            for href, text in parser.extracted_links:
                info = self._build_url_info(href, source="html", link_text=text)
                if info:
                    urls.append(info)
        except Exception:
            # Malformed HTML should not crash extraction
            pass
        return urls

    def _extract_text_urls(self, body_plain: str) -> list[URLInfo]:
        urls = []
        if not body_plain:
            return urls

        matches = self.text_url_re.findall(body_plain)
        for m in matches:
            info = self._build_url_info(m, source="text")
            if info:
                urls.append(info)
        return urls

    def _analyze_url(self, uinfo: URLInfo) -> list[Finding]:
        findings = []

        # 1. Suspicious Schemes
        if uinfo.scheme in SUSPICIOUS_SCHEMES:
            findings.append(
                Finding(
                    id="URL-SUSPICIOUS-SCHEME",
                    name="Suspicious URL Scheme",
                    category=FindingCategory.URL,
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    description=(
                        f"The URL uses a potentially dangerous scheme ({uinfo.scheme}:), "
                        "often used to execute local code."
                    ),
                    evidence=f"Defanged URL: {uinfo.defanged}",
                    source="ExtractorAnalyzer",
                )
            )

        # 2. IP-based URL
        if uinfo.hostname:
            try:
                ipaddress.ip_address(uinfo.hostname)
                findings.append(
                    Finding(
                        id="URL-IP-BASED",
                        name="IP-Based URL Hostname",
                        category=FindingCategory.URL,
                        severity=Severity.MEDIUM,
                        confidence=Confidence.HIGH,
                        description=(
                            "The URL uses a raw IP address rather than a domain name, "
                            "which is common in phishing infrastructure."
                        ),
                        evidence=f"Hostname: {uinfo.hostname} | Defanged URL: {uinfo.defanged}",
                        source="ExtractorAnalyzer",
                    )
                )
            except ValueError:
                pass

        # 3. URL Shorteners
        if uinfo.hostname in SHORTENERS:
            findings.append(
                Finding(
                    id="URL-SHORTENER",
                    name="URL Shortener Service Used",
                    category=FindingCategory.URL,
                    severity=Severity.LOW,
                    confidence=Confidence.HIGH,
                    description=(
                        "URL uses a recognized URL-shortening service, "
                        "obscuring the final destination."
                    ),
                    evidence=f"Hostname: {uinfo.hostname} | Defanged URL: {uinfo.defanged}",
                    source="ExtractorAnalyzer",
                )
            )

        # 4. Punycode Domain
        if "xn--" in uinfo.hostname:
            findings.append(
                Finding(
                    id="URL-IDN-PUNYCODE",
                    name="URL Hostname contains IDN/Punycode",
                    category=FindingCategory.URL,
                    severity=Severity.LOW,
                    confidence=Confidence.HIGH,
                    description=(
                        "URL hostname contains an IDN/Punycode representation, "
                        "which is sometimes used for homograph attacks."
                    ),
                    evidence=f"Hostname: {uinfo.hostname}",
                    source="ExtractorAnalyzer",
                )
            )

        # 5. Long URLs
        if len(uinfo.original) > self.url_len_threshold:
            findings.append(
                Finding(
                    id="URL-LONG",
                    name="Unusually Long URL",
                    category=FindingCategory.URL,
                    severity=Severity.LOW,
                    confidence=Confidence.HIGH,
                    description=(
                        "The URL length exceeds the typical threshold. "
                        "This can be used for obfuscation or data exfiltration."
                    ),
                    evidence=f"URL Length: {len(uinfo.original)}",
                    source="ExtractorAnalyzer",
                )
            )

        # 6. Deep Subdomains
        if uinfo.hostname:
            depth = len(uinfo.hostname.split("."))
            if depth > self.subdomain_depth_threshold:
                findings.append(
                    Finding(
                        id="URL-DEEP-SUBDOMAIN",
                        name="Deep Subdomain",
                        category=FindingCategory.URL,
                        severity=Severity.LOW,
                        confidence=Confidence.HIGH,
                        description=(
                            "The URL contains an unusually deep subdomain structure, "
                            "which can be an indicator of malicious dynamic DNS."
                        ),
                        evidence=f"Subdomain depth: {depth} | Hostname: {uinfo.hostname}",
                        source="ExtractorAnalyzer",
                    )
                )

        # 7. Link text mismatch
        if uinfo.source == "html" and uinfo.link_text and uinfo.hostname:
            # Only trigger if the visible text looks like a URL/domain itself
            text_lower = uinfo.link_text.lower()
            looks_like_url = "http" in text_lower or "." in text_lower
            if looks_like_url:
                # Try to extract hostname from the link text
                try:
                    text_norm = self._normalize_url_string(text_lower)
                    # if it lacks a scheme, urlparse might put the domain in the path. Hacky fix:
                    if not text_norm.startswith("http"):
                        text_norm = "http://" + text_norm
                    text_parsed = urlparse(text_norm)
                    text_host = (text_parsed.hostname or "").lower()

                    if text_host and text_host != uinfo.hostname:
                        findings.append(
                            Finding(
                                id="URL-LINK-MISMATCH",
                                name="Visible Link Text Mismatch",
                                category=FindingCategory.URL,
                                severity=Severity.MEDIUM,
                                confidence=Confidence.HIGH,
                                description=(
                                    "The visible HTML link text resembles a URL or domain, "
                                    "but points to a different actual destination."
                                ),
                                evidence=(
                                    f"Visible text: {uinfo.link_text} | "
                                    f"Actual href host: {uinfo.hostname}"
                                ),
                                source="ExtractorAnalyzer",
                            )
                        )
                except Exception:
                    pass

        return findings

    def _analyze_attachments(self, email_data: ParsedEmail) -> list[Finding]:
        findings = []

        for att in email_data.attachments:
            # Calculate Hashes
            sha256 = hashlib.sha256(att.payload_bytes).hexdigest()
            md5 = hashlib.md5(att.payload_bytes).hexdigest()

            # Record informational hash finding (can be fed to reporting)
            findings.append(
                Finding(
                    id="ATT-HASHES",
                    name="Attachment Extracted",
                    category=FindingCategory.ATTACHMENT,
                    severity=Severity.INFO,
                    confidence=Confidence.HIGH,
                    description="Attachment metadata and hashes successfully extracted.",
                    evidence=(f"Filename: {att.filename} | SHA256: {sha256} | MD5: {md5}"),
                    source="ExtractorAnalyzer",
                )
            )

            # Suffixes analysis
            p = Path(att.filename)
            suffixes = [s.lower() for s in p.suffixes]
            final_ext = suffixes[-1] if suffixes else ""

            # Double extension
            if len(suffixes) > 1:
                # Disregard common innocuous multi-dot like .tar.gz
                if not (suffixes[-2] == ".tar" and suffixes[-1] in {".gz", ".bz2", ".xz"}):
                    findings.append(
                        Finding(
                            id="ATT-DOUBLE-EXTENSION",
                            name="Double Extension Detected",
                            category=FindingCategory.ATTACHMENT,
                            severity=Severity.HIGH,
                            confidence=Confidence.HIGH,
                            description=(
                                "The attachment filename contains multiple extensions, "
                                "a common technique to spoof file types."
                            ),
                            evidence=f"Original filename: {att.filename} | Suffixes: {suffixes}",
                            source="ExtractorAnalyzer",
                        )
                    )

            # Macro / Dangerous types
            if final_ext in MACRO_EXTENSIONS:
                findings.append(
                    Finding(
                        id="ATT-MACRO-DOC",
                        name="Macro-Enabled Document",
                        category=FindingCategory.ATTACHMENT,
                        severity=Severity.MEDIUM,
                        confidence=Confidence.HIGH,
                        description=(
                            "The attachment is a macro-enabled Office document, "
                            "which can contain embedded scripts."
                        ),
                        evidence=f"Extension: {final_ext} | Filename: {att.filename}",
                        source="ExtractorAnalyzer",
                    )
                )

            if final_ext in {".html", ".htm"}:
                findings.append(
                    Finding(
                        id="ATT-HTML",
                        name="HTML Attachment",
                        category=FindingCategory.ATTACHMENT,
                        severity=Severity.MEDIUM,
                        confidence=Confidence.HIGH,
                        description=(
                            "The attachment is an HTML file, "
                            "often used in credential harvesting workflows."
                        ),
                        evidence=f"Extension: {final_ext} | Filename: {att.filename}",
                        source="ExtractorAnalyzer",
                    )
                )

            if final_ext == ".iso":
                findings.append(
                    Finding(
                        id="ATT-ISO",
                        name="ISO Disk Image Attachment",
                        category=FindingCategory.ATTACHMENT,
                        severity=Severity.HIGH,
                        confidence=Confidence.HIGH,
                        description=(
                            "The attachment is an ISO disk image, "
                            "which can bypass Mark-of-the-Web (MotW) defenses."
                        ),
                        evidence=f"Extension: {final_ext} | Filename: {att.filename}",
                        source="ExtractorAnalyzer",
                    )
                )

            if final_ext == ".lnk":
                findings.append(
                    Finding(
                        id="ATT-LNK",
                        name="LNK Shortcut Attachment",
                        category=FindingCategory.ATTACHMENT,
                        severity=Severity.HIGH,
                        confidence=Confidence.HIGH,
                        description=(
                            "The attachment is a Windows shortcut (LNK) file, "
                            "a high-risk executable container."
                        ),
                        evidence=f"Extension: {final_ext} | Filename: {att.filename}",
                        source="ExtractorAnalyzer",
                    )
                )

            # MIME Mismatch (simplistic check)
            # E.g. PDF claiming to be executable, or executable claiming to be PDF
            # Just a weak heuristic for Phase 4
            mime_lower = att.content_type.lower()
            if final_ext == ".pdf" and "application/pdf" not in mime_lower:
                findings.append(
                    Finding(
                        id="ATT-MIME-MISMATCH",
                        name="Extension vs MIME Mismatch",
                        category=FindingCategory.ATTACHMENT,
                        severity=Severity.LOW,
                        confidence=Confidence.LOW,
                        description=(
                            "The file extension does not match the declared MIME Content-Type."
                        ),
                        evidence=(f"Extension: {final_ext} | Declared MIME: {att.content_type}"),
                        source="ExtractorAnalyzer",
                    )
                )

            # Size check
            if att.size_bytes > self.large_attachment_bytes:
                findings.append(
                    Finding(
                        id="ATT-LARGE-SIZE",
                        name="Unusually Large Attachment",
                        category=FindingCategory.ATTACHMENT,
                        severity=Severity.INFO,
                        confidence=Confidence.HIGH,
                        description="The attachment size exceeds the informational threshold.",
                        evidence=f"Size: {att.size_bytes} bytes",
                        source="ExtractorAnalyzer",
                    )
                )

        return findings
