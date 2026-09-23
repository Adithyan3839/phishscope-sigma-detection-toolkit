from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum


class Severity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class Confidence(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class FindingCategory(str, Enum):
    HEADER = "HEADER"
    URL = "URL"
    ATTACHMENT = "ATTACHMENT"
    AUTHENTICATION = "AUTHENTICATION"


@dataclass(frozen=True)
class Finding:
    """Represents a discrete security finding produced by an analyzer."""

    id: str
    name: str
    category: FindingCategory
    severity: Severity
    confidence: Confidence
    description: str
    evidence: str
    source: str


@dataclass(frozen=True)
class ReceivedHop:
    """Represents a single routing hop extracted from Received headers."""

    hop_number: int
    raw_content: str


@dataclass(frozen=True)
class AttachmentInfo:
    """Safely extracted attachment metadata and content bytes."""

    filename: str
    sanitized_filename: str
    content_type: str
    size_bytes: int
    payload_bytes: bytes = field(repr=False)


@dataclass(frozen=True)
class URLInfo:
    """Extracted and analyzed URL safely processed."""

    original: str
    normalized: str
    defanged: str
    scheme: str
    hostname: str
    port: int | None
    path: str
    query: str
    source: str  # 'html' or 'text'
    link_text: str | None = None


@dataclass(frozen=True)
class AuthMethodResult:
    """Structured result of a single authentication method (e.g., SPF, DKIM, DMARC)."""

    method: str
    result: str
    domain: str | None
    original_text: str


@dataclass(frozen=True)
class AuthHeaderInfo:
    """Parsed representation of an Authentication-Results or Received-SPF header."""

    header_name: str
    server_id: str
    methods: list[AuthMethodResult]
    raw_header: str


@dataclass
class ParsedEmail:
    """Structured representation of an email, free of security verdicts."""

    file_path: str
    file_sha256: str

    # Standard headers (decoded)
    subject: str
    from_header: str
    to_headers: list[str]
    cc_headers: list[str]
    date: datetime | None
    message_id: str
    reply_to: str
    return_path: str

    # Routing and Custom headers
    received_headers: list[ReceivedHop]
    x_headers: dict[str, list[str]]
    raw_headers: list[tuple[str, str]]

    # Body Content
    body_plain: str
    body_html: str

    # Attachments
    attachments: list[AttachmentInfo]

    # Email RFC compliance defects caught by the parser
    defects: list[str]


class RiskLevel(str, Enum):
    SAFE = "SAFE"
    SUSPICIOUS = "SUSPICIOUS"
    HIGH_RISK = "HIGH_RISK"
    CRITICAL = "CRITICAL"


class AssessmentConfidence(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


@dataclass
class CategoryScore:
    category: FindingCategory
    raw_score: float
    capped_score: float
    contributing_findings: list[Finding]


@dataclass
class AnalysisResult:
    score: int
    risk_level: RiskLevel
    assessment_confidence: AssessmentConfidence
    category_scores: dict[FindingCategory, CategoryScore]
    all_findings: list[Finding]
