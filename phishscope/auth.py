import re
from email.utils import parseaddr

from phishscope.models import (
    AuthHeaderInfo,
    AuthMethodResult,
    Confidence,
    Finding,
    FindingCategory,
    ParsedEmail,
    Severity,
)


class AuthAnalyzer:
    """Analyzes email authentication headers (SPF, DKIM, DMARC) statically."""

    def analyze(self, email_data: ParsedEmail) -> tuple[list[Finding], list[AuthHeaderInfo]]:
        findings = []
        auth_headers = []

        # 1. Parse Authentication-Results
        for key, value in email_data.raw_headers:
            if key.lower() == "authentication-results":
                parsed_hdr = self._parse_authentication_results(value)
                if parsed_hdr:
                    auth_headers.append(parsed_hdr)
            elif key.lower() == "received-spf":
                parsed_hdr = self._parse_received_spf(value)
                if parsed_hdr:
                    auth_headers.append(parsed_hdr)

        # 2. Extract From domain for alignment checks
        _, from_addr = parseaddr(email_data.from_header)
        from_domain = from_addr.split("@")[-1].lower() if "@" in from_addr else None

        # 3. Analyze parsed records
        findings.extend(self._evaluate_auth_results(auth_headers, from_domain))

        return findings, auth_headers

    def _unfold_header(self, header_value: str) -> str:
        """Removes CRLF and excess whitespace from folded headers."""
        return re.sub(r"\s+", " ", header_value).strip()

    def _parse_authentication_results(self, header_value: str) -> AuthHeaderInfo | None:
        """
        Parses an Authentication-Results header.
        Format: server_id; method1=result1 prop1=val1; method2=result2 prop2=val2
        """
        unfolded = self._unfold_header(header_value)
        if not unfolded:
            return None

        parts = [p.strip() for p in unfolded.split(";") if p.strip()]
        if not parts:
            return None

        # The first part is the server ID (authserv-id), occasionally prefixed by a version
        server_part = parts[0]
        server_id = server_part
        # Strip version if present (e.g., "1; mx.google.com")
        # We will just take the first part as server_id

        methods = []
        for part in parts[1:]:
            method_result = self._parse_auth_method(part)
            if method_result:
                methods.append(method_result)

        return AuthHeaderInfo(
            header_name="Authentication-Results",
            server_id=server_id,
            methods=methods,
            raw_header=unfolded,
        )

    def _parse_auth_method(self, method_part: str) -> AuthMethodResult | None:
        """
        Parses a single method chunk: e.g., "spf=pass smtp.mailfrom=example.com"
        """
        tokens = method_part.split()
        if not tokens:
            return None

        method_res = tokens[0]
        if "=" not in method_res:
            return None

        method_name, result = method_res.split("=", 1)
        method_name = method_name.lower().strip()
        result = result.lower().strip()

        if not result or not method_name:
            return None

        # Try to find a domain property
        domain = None
        for token in tokens[1:]:
            if "=" in token:
                key, val = token.split("=", 1)
                key = key.lower()
                # Remove quotes or brackets if present
                val = val.strip("\"'<>")

                if method_name == "spf" and key in ("smtp.mailfrom", "smtp.helo", "header.from"):
                    domain = val.lower()
                elif method_name == "dkim" and key == "header.d":
                    domain = val.lower()
                elif method_name == "dmarc" and key == "header.from":
                    domain = val.lower()

        return AuthMethodResult(
            method=method_name, result=result, domain=domain, original_text=method_part
        )

    def _parse_received_spf(self, header_value: str) -> AuthHeaderInfo | None:
        """
        Parses a Received-SPF header.
        Format: result (comments) [properties]
        e.g., Received-SPF: pass (domain.com: ... ) client-ip=...;
        """
        unfolded = self._unfold_header(header_value)
        if not unfolded:
            return None

        # Extract result which is usually the first word
        tokens = unfolded.split()
        if not tokens:
            return None

        result = tokens[0].lower()
        domain = None

        # Try to extract envelope-from from properties
        for token in tokens[1:]:
            if "envelope-from=" in token.lower():
                _, val = token.split("=", 1)
                val = val.strip(";\"'<>")
                if "@" in val:
                    domain = val.split("@")[-1].lower()
                else:
                    domain = val.lower()
                break

        method_result = AuthMethodResult(
            method="spf", result=result, domain=domain, original_text=unfolded
        )

        return AuthHeaderInfo(
            header_name="Received-SPF",
            server_id="unknown",
            methods=[method_result],
            raw_header=unfolded,
        )

    def _evaluate_auth_results(
        self, auth_headers: list[AuthHeaderInfo], from_domain: str | None
    ) -> list[Finding]:
        findings = []

        if not auth_headers:
            findings.append(
                Finding(
                    id="AUTH-MISSING",
                    name="Missing Authentication Headers",
                    category=FindingCategory.AUTHENTICATION,
                    severity=Severity.INFO,
                    confidence=Confidence.HIGH,
                    description=(
                        "No authentication result metadata was available for static analysis."
                    ),
                    evidence="Headers not found.",
                    source="AuthAnalyzer",
                )
            )
            return findings

        # Aggregate results across all headers to detect conflicts
        all_spf = []
        all_dkim = []
        all_dmarc = []

        for hdr in auth_headers:
            for m in hdr.methods:
                if m.method == "spf":
                    all_spf.append(m)
                elif m.method == "dkim":
                    all_dkim.append(m)
                elif m.method == "dmarc":
                    all_dmarc.append(m)

        findings.extend(self._evaluate_mechanism("SPF", all_spf, from_domain))
        findings.extend(self._evaluate_mechanism("DKIM", all_dkim, from_domain))
        findings.extend(self._evaluate_mechanism("DMARC", all_dmarc, from_domain))

        findings.extend(self._check_conflicts("SPF", all_spf))
        findings.extend(self._check_conflicts("DKIM", all_dkim))
        findings.extend(self._check_conflicts("DMARC", all_dmarc))

        return findings

    def _evaluate_mechanism(
        self, mech_name: str, results: list[AuthMethodResult], from_domain: str | None
    ) -> list[Finding]:
        findings = []
        if not results:
            findings.append(
                Finding(
                    id=f"AUTH-{mech_name}-MISSING",
                    name=f"Missing {mech_name} Results",
                    category=FindingCategory.AUTHENTICATION,
                    severity=Severity.INFO,
                    confidence=Confidence.HIGH,
                    description=f"No {mech_name} authentication results were found in the headers.",
                    evidence="None",
                    source="AuthAnalyzer",
                )
            )
            return findings

        # Evaluate the first observed result for alignment/failure logic
        # (Conflicts are handled separately)
        primary = results[0]
        res = primary.result

        if res == "pass":
            findings.append(
                Finding(
                    id=f"AUTH-{mech_name}-PASS",
                    name=f"{mech_name} Authentication Pass",
                    category=FindingCategory.AUTHENTICATION,
                    severity=Severity.INFO,
                    confidence=Confidence.HIGH,
                    description=(
                        f"{mech_name} authentication passed. Note: this does "
                        "not inherently prove the message is safe."
                    ),
                    evidence=f"Result: {res} | Domain: {primary.domain}",
                    source="AuthAnalyzer",
                )
            )
        elif res in ("fail", "hardfail"):
            findings.append(
                Finding(
                    id=f"AUTH-{mech_name}-FAIL",
                    name=f"{mech_name} Authentication Failure",
                    category=FindingCategory.AUTHENTICATION,
                    severity=Severity.MEDIUM,  # High if DMARC, handled below
                    confidence=Confidence.HIGH,
                    description=f"{mech_name} authentication explicitly failed.",
                    evidence=f"Result: {res} | Original: {primary.original_text}",
                    source="AuthAnalyzer",
                )
            )
        elif res == "softfail":
            findings.append(
                Finding(
                    id=f"AUTH-{mech_name}-SOFTFAIL",
                    name=f"{mech_name} Authentication Softfail",
                    category=FindingCategory.AUTHENTICATION,
                    severity=Severity.LOW,
                    confidence=Confidence.HIGH,
                    description=f"{mech_name} authentication resulted in a softfail.",
                    evidence=f"Result: {res} | Original: {primary.original_text}",
                    source="AuthAnalyzer",
                )
            )
        elif res in ("none", "neutral"):
            findings.append(
                Finding(
                    id=f"AUTH-{mech_name}-NONE",
                    name=f"{mech_name} Authentication None/Neutral",
                    category=FindingCategory.AUTHENTICATION,
                    severity=Severity.INFO,
                    confidence=Confidence.HIGH,
                    description=(
                        f"{mech_name} authentication returned {res}, indicating "
                        "no policy or neutral policy."
                    ),
                    evidence=f"Result: {res}",
                    source="AuthAnalyzer",
                )
            )
        elif res in ("temperror", "permerror"):
            findings.append(
                Finding(
                    id=f"AUTH-{mech_name}-ERROR",
                    name=f"{mech_name} Authentication Error",
                    category=FindingCategory.AUTHENTICATION,
                    severity=Severity.INFO,
                    confidence=Confidence.HIGH,
                    description=(
                        f"{mech_name} authentication encountered an error during evaluation."
                    ),
                    evidence=f"Result: {res} | Original: {primary.original_text}",
                    source="AuthAnalyzer",
                )
            )

        # Elevate DMARC fail to HIGH
        if mech_name == "DMARC" and res in ("fail", "hardfail"):
            for f in findings:
                if f.id == "AUTH-DMARC-FAIL":
                    findings.remove(f)
                    findings.append(
                        Finding(
                            id="AUTH-DMARC-FAIL",
                            name="DMARC Authentication Failure",
                            category=FindingCategory.AUTHENTICATION,
                            severity=Severity.HIGH,
                            confidence=Confidence.HIGH,
                            description=(
                                "DMARC authentication result reported as fail by the supplied "
                                "authentication metadata. Finding severity is not the final "
                                "email risk verdict."
                            ),
                            evidence=f"Result: {res}",
                            source="AuthAnalyzer",
                        )
                    )

        # Alignment Check
        if mech_name != "DMARC" and primary.domain and from_domain and res == "pass":
            # Very simplistic alignment check: exact match or subdomain (heuristic)
            # A true organizational domain alignment would need a Public Suffix List.
            if (
                from_domain != primary.domain
                and not from_domain.endswith("." + primary.domain)
                and not primary.domain.endswith("." + from_domain)
            ):
                findings.append(
                    Finding(
                        id=f"AUTH-{mech_name}-ALIGNMENT-MISMATCH",
                        name=f"{mech_name} Domain Alignment Mismatch",
                        category=FindingCategory.AUTHENTICATION,
                        severity=Severity.MEDIUM,
                        confidence=Confidence.MEDIUM,
                        description=(
                            f"The {mech_name} authenticated domain does not "
                            "align with the From header domain."
                        ),
                        evidence=(
                            f"From domain: {from_domain} | {mech_name} domain: {primary.domain}"
                        ),
                        source="AuthAnalyzer",
                    )
                )
            else:
                findings.append(
                    Finding(
                        id=f"AUTH-{mech_name}-ALIGNED",
                        name=f"{mech_name} Domain Aligned",
                        category=FindingCategory.AUTHENTICATION,
                        severity=Severity.INFO,
                        confidence=Confidence.MEDIUM,
                        description=(
                            f"The {mech_name} authenticated domain aligns "
                            "with the From header domain."
                        ),
                        evidence=f"From: {from_domain} | {mech_name}: {primary.domain}",
                        source="AuthAnalyzer",
                    )
                )

        return findings

    def _check_conflicts(self, mech_name: str, results: list[AuthMethodResult]) -> list[Finding]:
        findings = []
        if len(results) <= 1:
            return findings

        # Group by result
        result_types = {r.result for r in results}
        if len(result_types) > 1:
            evidence_parts = [f"'{r.result}' ({r.original_text})" for r in results]
            findings.append(
                Finding(
                    id=f"AUTH-{mech_name}-CONFLICT",
                    name=f"Conflicting {mech_name} Results",
                    category=FindingCategory.AUTHENTICATION,
                    severity=Severity.MEDIUM,
                    confidence=Confidence.HIGH,
                    description=(
                        f"Multiple {mech_name} results were found with conflicting conclusions."
                    ),
                    evidence=" | ".join(evidence_parts),
                    source="AuthAnalyzer",
                )
            )

        return findings
