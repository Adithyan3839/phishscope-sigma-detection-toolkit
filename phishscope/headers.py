import re
from datetime import datetime
from email.utils import getaddresses, parsedate_to_datetime

from phishscope.models import Confidence, Finding, FindingCategory, ParsedEmail, Severity

# A configurable, small set of high-value brands/terms for display-name spoofing
HIGH_VALUE_BRANDS = {
    "microsoft",
    "apple",
    "google",
    "paypal",
    "ceo",
    "security",
    "support",
    "admin",
}

# A small configurable set of free-mail domains
FREE_MAIL_DOMAINS = {"gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "aol.com"}

# Urgency keywords
URGENCY_KEYWORDS = {
    "urgent",
    "immediately",
    "verify",
    "account suspended",
    "payment",
    "invoice",
    "wire transfer",
    "password expires",
    "action required",
}


class HeaderAnalyzer:
    """Analyzes structural email headers for potentially suspicious characteristics."""

    def analyze(self, email_data: ParsedEmail) -> list[Finding]:
        findings = []

        findings.extend(self._check_mismatches(email_data))
        findings.extend(self._check_display_name_spoofing(email_data))
        findings.extend(self._check_lookalike_domains(email_data))
        findings.extend(self._analyze_received_chain(email_data))
        findings.extend(self._analyze_message_id(email_data))
        findings.extend(self._analyze_subject(email_data))

        return findings

    def _normalize_domain(self, domain: str) -> str:
        """Lowercases, strips whitespace and trailing dots. Handles IDNA."""
        if not domain:
            return ""
        d = domain.strip().lower()
        if d.endswith("."):
            d = d[:-1]
        try:
            # basic IDNA handling if punycode is present
            d = d.encode("idna").decode("utf-8")
        except Exception:
            pass
        return d

    def _extract_address_parts(self, header_value: str) -> tuple[str, str, str]:
        """Returns (display_name, local_part, domain)."""
        if not header_value:
            return "", "", ""
        parsed = getaddresses([header_value])
        if not parsed:
            return "", "", ""

        display_name, address = parsed[0]
        if "@" in address:
            local_part, domain = address.rsplit("@", 1)
        else:
            local_part, domain = address, ""

        return display_name.strip(), local_part.strip(), self._normalize_domain(domain)

    def _check_mismatches(self, email_data: ParsedEmail) -> list[Finding]:
        findings = []
        _, _, from_domain = self._extract_address_parts(email_data.from_header)

        # Reply-To
        if email_data.reply_to:
            _, _, reply_to_domain = self._extract_address_parts(email_data.reply_to)
            if from_domain and reply_to_domain and from_domain != reply_to_domain:
                findings.append(
                    Finding(
                        id="HDR-REPLYTO-MISMATCH",
                        name="From vs Reply-To Mismatch",
                        category=FindingCategory.HEADER,
                        severity=Severity.MEDIUM,
                        confidence=Confidence.HIGH,
                        description=(
                            "The Reply-To domain differs from the From domain "
                            "and may warrant investigation."
                        ),
                        evidence=f"From domain: {from_domain} | Reply-To domain: {reply_to_domain}",
                        source="HeaderAnalyzer",
                    )
                )

        # Return-Path
        if email_data.return_path:
            _, _, return_path_domain = self._extract_address_parts(email_data.return_path)
            if from_domain and return_path_domain and from_domain != return_path_domain:
                findings.append(
                    Finding(
                        id="HDR-RETURNPATH-MISMATCH",
                        name="From vs Return-Path Mismatch",
                        category=FindingCategory.HEADER,
                        severity=Severity.MEDIUM,
                        confidence=Confidence.HIGH,
                        description=(
                            "The Return-Path (Envelope-From) domain differs from the From domain."
                        ),
                        evidence=f"From: {from_domain} | Return-Path: {return_path_domain}",
                        source="HeaderAnalyzer",
                    )
                )
        return findings

    def _check_display_name_spoofing(self, email_data: ParsedEmail) -> list[Finding]:
        findings = []
        display_name, _, from_domain = self._extract_address_parts(email_data.from_header)

        if not display_name or not from_domain:
            return findings

        display_name_lower = display_name.lower()

        # Check if high-value brand is in display name but domain is unrelated free-mail or random
        matched_brands = [b for b in HIGH_VALUE_BRANDS if b in display_name_lower]
        if matched_brands:
            for brand in matched_brands:
                if brand not in from_domain:
                    # Generic roles should primarily flag if originating from freemail or known bad
                    generic_roles = {"ceo", "security", "support", "admin"}
                    if brand in generic_roles and from_domain not in FREE_MAIL_DOMAINS:
                        continue

                    findings.append(
                        Finding(
                            id="HDR-DISPLAY-SPOOF",
                            name="Display Name Spoofing",
                            category=FindingCategory.HEADER,
                            severity=Severity.MEDIUM,
                            confidence=Confidence.MEDIUM,
                            description=(
                                "Display name contains a high-value brand/role, "
                                "but the sender domain does not match."
                            ),
                            evidence=(
                                f"Display name: {display_name} | "
                                f"Domain: {from_domain} | Brand: {brand}"
                            ),
                            source="HeaderAnalyzer",
                        )
                    )
                    break

        return findings

    def _levenshtein(self, s1: str, s2: str) -> int:
        if len(s1) < len(s2):
            return self._levenshtein(s2, s1)
        if len(s2) == 0:
            return len(s1)
        previous_row = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row
        return previous_row[-1]

    def _check_lookalike_domains(self, email_data: ParsedEmail) -> list[Finding]:
        findings = []
        _, _, from_domain = self._extract_address_parts(email_data.from_header)

        if not from_domain or from_domain in FREE_MAIL_DOMAINS:
            return findings

        # Strip TLD for base comparison (simplistic for this phase)
        base_domain = from_domain.split(".")[0]

        for brand in HIGH_VALUE_BRANDS:
            if base_domain == brand:
                continue  # Exact match, not a lookalike

            # Subtitutions check (0/o, rn/m)
            normalized_lookalike = (
                base_domain.replace("0", "o").replace("1", "l").replace("rn", "m")
            )
            if normalized_lookalike == brand:
                findings.append(
                    Finding(
                        id="HDR-LOOKALIKE-DOMAIN",
                        name="Lookalike Domain Detected",
                        category=FindingCategory.HEADER,
                        severity=Severity.HIGH,
                        confidence=Confidence.HIGH,
                        description=(
                            "The sender domain uses common visual substitution "
                            "(homoglyph/typo) techniques."
                        ),
                        evidence=(
                            f"Observed: {from_domain} | Brand: {brand} | Reason: substitution"
                        ),
                        source="HeaderAnalyzer",
                    )
                )
                continue

            # Edit distance check (1 char difference)
            if len(base_domain) > 3 and self._levenshtein(base_domain, brand) == 1:
                findings.append(
                    Finding(
                        id="HDR-LOOKALIKE-DOMAIN",
                        name="Lookalike Domain Detected",
                        category=FindingCategory.HEADER,
                        severity=Severity.MEDIUM,
                        confidence=Confidence.MEDIUM,
                        description=(
                            "The sender domain closely resembles a known high-value brand."
                        ),
                        evidence=(
                            f"Observed: {from_domain} | Brand: {brand} | Reason: edit distance 1"
                        ),
                        source="HeaderAnalyzer",
                    )
                )

        # IDN/Punycode check
        if email_data.from_header and "xn--" in email_data.from_header.lower():
            findings.append(
                Finding(
                    id="HDR-IDN-PUNYCODE",
                    name="Internationalized Domain Name (Punycode)",
                    category=FindingCategory.HEADER,
                    severity=Severity.LOW,
                    confidence=Confidence.HIGH,
                    description=(
                        "The sender uses a Punycode domain, which is "
                        "sometimes used for homograph attacks."
                    ),
                    evidence=f"Original header: {email_data.from_header}",
                    source="HeaderAnalyzer",
                )
            )

        return findings

    def _analyze_received_chain(self, email_data: ParsedEmail) -> list[Finding]:
        findings = []
        hops = email_data.received_headers
        if not hops:
            return findings

        # Originating IP candidate (extract from the last/oldest hop if available)
        # Received headers are appended at the top, so index -1 is the earliest hop.
        earliest_hop = hops[-1].raw_content
        ip_match = re.search(r"\[?(\d{1,3}(?:\.\d{1,3}){3})\]?", earliest_hop)
        if ip_match:
            candidate_ip = ip_match.group(1)
            findings.append(
                Finding(
                    id="HDR-RCVD-ORIGINATING-IP",
                    name="Candidate Originating IP",
                    category=FindingCategory.HEADER,
                    severity=Severity.INFO,
                    confidence=Confidence.LOW,
                    description=(
                        "Extracted a candidate originating IP address "
                        "from the earliest Received hop."
                    ),
                    evidence=f"IP: {candidate_ip} | Extracted from: {earliest_hop}",
                    source="HeaderAnalyzer",
                )
            )

        # Timestamp inconsistency
        # Hops are from newest (0) to oldest (-1)
        prev_time: datetime | None = None
        for i, hop in enumerate(hops):
            try:
                # Basic extraction of the date part (after the last semicolon)
                parts = hop.raw_content.rsplit(";", 1)
                if len(parts) == 2:
                    date_str = parts[1].strip()
                    dt = parsedate_to_datetime(date_str)

                    if prev_time and dt > prev_time:
                        findings.append(
                            Finding(
                                id="HDR-RCVD-TIME-INCONSISTENCY",
                                name="Received-chain timestamp inconsistency",
                                category=FindingCategory.HEADER,
                                severity=Severity.LOW,
                                confidence=Confidence.MEDIUM,
                                description=(
                                    "A hop appears to have occurred before a prior "
                                    "hop, suggesting potential forgery or misconfigured clocks."
                                ),
                                evidence=f"Hop {i + 1} time ({dt}) > Hop {i} time ({prev_time})",
                                source="HeaderAnalyzer",
                            )
                        )
                        break  # Only report once
                    prev_time = dt
            except Exception:
                # Malformed date in hop, gracefully skip
                pass

        return findings

    def _analyze_message_id(self, email_data: ParsedEmail) -> list[Finding]:
        findings = []
        msg_id = email_data.message_id
        if not msg_id:
            findings.append(
                Finding(
                    id="HDR-MSGID-MISSING",
                    name="Missing Message-ID",
                    category=FindingCategory.HEADER,
                    severity=Severity.LOW,
                    confidence=Confidence.HIGH,
                    description=(
                        "The email lacks a Message-ID header, "
                        "which is unusual for legitimate mailers."
                    ),
                    evidence="Message-ID header is empty.",
                    source="HeaderAnalyzer",
                )
            )
        elif "@" not in msg_id:
            findings.append(
                Finding(
                    id="HDR-MSGID-MALFORMED",
                    name="Malformed Message-ID",
                    category=FindingCategory.HEADER,
                    severity=Severity.LOW,
                    confidence=Confidence.HIGH,
                    description="The Message-ID header does not contain a domain part.",
                    evidence=f"Observed Message-ID: {msg_id}",
                    source="HeaderAnalyzer",
                )
            )
        return findings

    def _analyze_subject(self, email_data: ParsedEmail) -> list[Finding]:
        findings = []
        subject = email_data.subject
        if not subject:
            return findings

        subject_lower = subject.lower()
        matched = [kw for kw in URGENCY_KEYWORDS if kw in subject_lower]

        if matched:
            findings.append(
                Finding(
                    id="HDR-SUBJECT-URGENCY",
                    name="Urgency/Financial Language in Subject",
                    category=FindingCategory.HEADER,
                    severity=Severity.LOW,
                    confidence=Confidence.HIGH,
                    description=(
                        "The subject contains keywords commonly used in "
                        "social engineering to create urgency."
                    ),
                    evidence=(
                        f"Matched keywords: {', '.join(matched)} | Original subject: {subject}"
                    ),
                    source="HeaderAnalyzer",
                )
            )

        return findings
