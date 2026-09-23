from datetime import datetime, timezone

import pytest

from phishscope.auth import AuthAnalyzer
from phishscope.models import ParsedEmail, Severity


@pytest.fixture
def base_email():
    return ParsedEmail(
        file_path="memory",
        file_sha256="hash",
        subject="",
        from_header='"Test" <sender@example.com>',
        to_headers=[],
        cc_headers=[],
        date=datetime.now(timezone.utc),
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


def _build_email(base, raw_headers):
    return ParsedEmail(**{**base.__dict__, "raw_headers": raw_headers})


def test_spf_variants(base_email):
    results = ["pass", "fail", "softfail", "none", "temperror", "permerror"]
    analyzer = AuthAnalyzer()

    for res in results:
        email = _build_email(
            base_email,
            [("Authentication-Results", (f"mx.test; spf={res} smtp.mailfrom=example.com"))],
        )
        findings, auth_hdrs = analyzer.analyze(email)

        method = auth_hdrs[0].methods[0]
        assert method.method == "spf"
        assert method.result == res
        assert method.domain == "example.com"

        # Check finding

        if res in ("fail", "softfail", "none", "pass", "error"):
            # just assert finding exists with right name
            assert any(f.name.startswith("SPF Authentication") for f in findings)


def test_dkim_variants(base_email):
    for res in ["pass", "fail"]:
        email = _build_email(
            base_email, [("Authentication-Results", f"mx.test; dkim={res} header.d=example.com")]
        )
        analyzer = AuthAnalyzer()
        findings, auth_hdrs = analyzer.analyze(email)
        method = auth_hdrs[0].methods[0]
        assert method.method == "dkim"
        assert method.result == res
        assert method.domain == "example.com"


def test_dmarc_variants(base_email):
    for res in ["pass", "fail", "none"]:
        email = _build_email(
            base_email,
            [("Authentication-Results", f"mx.test; dmarc={res} header.from=example.com")],
        )
        analyzer = AuthAnalyzer()
        findings, auth_hdrs = analyzer.analyze(email)
        method = auth_hdrs[0].methods[0]
        assert method.method == "dmarc"
        assert method.result == res

        if res == "fail":
            fail_finding = next(f for f in findings if f.id == "AUTH-DMARC-FAIL")
            assert fail_finding.severity == Severity.HIGH


def test_multiple_headers_and_conflicts(base_email):
    headers = [
        ("Authentication-Results", "mx1; spf=pass smtp.mailfrom=example.com"),
        ("Authentication-Results", "mx2; spf=fail smtp.mailfrom=evil.com"),
    ]
    email = _build_email(base_email, headers)
    analyzer = AuthAnalyzer()
    findings, auth_hdrs = analyzer.analyze(email)

    assert len(auth_hdrs) == 2
    assert any(f.id == "AUTH-SPF-CONFLICT" for f in findings)


def test_folded_and_capitalization(base_email):
    headers = [
        (
            "Authentication-Results",
            "mx.test; \r\n  sPf=PaSs smtp.mailfrom=example.com; \r\n  DkIm=FaIl header.d=evil.com",
        )
    ]
    email = _build_email(base_email, headers)
    analyzer = AuthAnalyzer()
    findings, auth_hdrs = analyzer.analyze(email)

    methods = auth_hdrs[0].methods
    assert methods[0].method == "spf"
    assert methods[0].result == "pass"
    assert methods[1].method == "dkim"
    assert methods[1].result == "fail"


def test_missing_parameters_and_malformed(base_email):
    headers = [("Authentication-Results", "mx.test; spf=pass; dkim=; malformed_token")]
    email = _build_email(base_email, headers)
    analyzer = AuthAnalyzer()
    findings, auth_hdrs = analyzer.analyze(email)

    methods = auth_hdrs[0].methods
    assert len(methods) == 1
    assert methods[0].method == "spf"
    assert methods[0].result == "pass"
    assert methods[0].domain is None


def test_received_spf(base_email):
    for res in ["pass", "fail", "softfail"]:
        email = _build_email(
            base_email,
            [
                (
                    "Received-SPF",
                    f"{res} (domain.com: ...) client-ip=1.2.3.4; envelope-from=example.com;",
                )
            ],
        )
        analyzer = AuthAnalyzer()
        findings, auth_hdrs = analyzer.analyze(email)

        method = auth_hdrs[0].methods[0]
        assert method.method == "spf"
        assert method.result == res
        assert method.domain == "example.com"


def test_received_spf_malformed(base_email):
    email = _build_email(base_email, [("Received-SPF", " \r\n ")])
    analyzer = AuthAnalyzer()
    findings, auth_hdrs = analyzer.analyze(email)
    assert len(auth_hdrs) == 0


def test_alignment_logic(base_email):
    # From is sender@example.com

    # Aligned
    email_aligned = _build_email(
        base_email, [("Authentication-Results", "mx; spf=pass smtp.mailfrom=example.com")]
    )
    findings, _ = AuthAnalyzer().analyze(email_aligned)
    assert any(f.id == "AUTH-SPF-ALIGNED" for f in findings)

    # Unaligned
    email_unaligned = _build_email(
        base_email, [("Authentication-Results", "mx; spf=pass smtp.mailfrom=evil.com")]
    )
    findings, _ = AuthAnalyzer().analyze(email_unaligned)
    assert any(f.id == "AUTH-SPF-ALIGNMENT-MISMATCH" for f in findings)

    # DKIM aligned
    email_dkim = _build_email(
        base_email, [("Authentication-Results", "mx; dkim=pass header.d=example.com")]
    )
    findings, _ = AuthAnalyzer().analyze(email_dkim)
    assert any(f.id == "AUTH-DKIM-ALIGNED" for f in findings)

    # DMARC aligned (should NOT generate alignment finding)
    email_dmarc = _build_email(
        base_email, [("Authentication-Results", "mx; dmarc=pass header.from=example.com")]
    )
    findings, _ = AuthAnalyzer().analyze(email_dmarc)
    assert not any(f.id == "AUTH-DMARC-ALIGNED" for f in findings)


def test_no_auth_headers(base_email):
    email = _build_email(base_email, [])
    findings, auth_hdrs = AuthAnalyzer().analyze(email)
    assert len(auth_hdrs) == 0
    assert any(f.id == "AUTH-MISSING" for f in findings)


def test_conflicting_spf_sources(base_email):
    headers = [
        ("Received-SPF", "fail (example.com: ...)"),
        ("Authentication-Results", "mx; spf=pass smtp.mailfrom=example.com"),
    ]
    email = _build_email(base_email, headers)
    findings, auth_hdrs = AuthAnalyzer().analyze(email)
    assert len(auth_hdrs) == 2
    assert any(f.id == "AUTH-SPF-CONFLICT" for f in findings)


def test_duplicate_auth_headers_no_conflict(base_email):
    headers = [
        ("Authentication-Results", "mx1; spf=pass smtp.mailfrom=example.com"),
        ("Authentication-Results", "mx2; spf=pass smtp.mailfrom=example.com"),
    ]
    email = _build_email(base_email, headers)
    findings, auth_hdrs = AuthAnalyzer().analyze(email)
    assert len(auth_hdrs) == 2
    assert not any(f.id == "AUTH-SPF-CONFLICT" for f in findings)


def test_malformed_auth_results_header(base_email):
    headers = [("Authentication-Results", "just_a_string_no_semicolons")]
    email = _build_email(base_email, headers)
    findings, auth_hdrs = AuthAnalyzer().analyze(email)

    # Should parse server_id but no methods
    assert len(auth_hdrs) == 1
    assert len(auth_hdrs[0].methods) == 0


def test_multiple_authserv_id(base_email):
    headers = [
        ("Authentication-Results", "mx1.example.com; spf=pass smtp.mailfrom=example.com"),
        ("Authentication-Results", "mx2.example.com; spf=fail smtp.mailfrom=evil.com"),
    ]
    email = _build_email(base_email, headers)
    findings, auth_hdrs = AuthAnalyzer().analyze(email)

    assert len(auth_hdrs) == 2
    assert auth_hdrs[0].server_id == "mx1.example.com"
    assert auth_hdrs[1].server_id == "mx2.example.com"

    methods0 = auth_hdrs[0].methods[0]
    methods1 = auth_hdrs[1].methods[0]
    assert methods0.result == "pass"
    assert methods1.result == "fail"

    assert any(f.id == "AUTH-SPF-CONFLICT" for f in findings)


def test_missing_optional_parameters(base_email):
    headers = [("Authentication-Results", "mx.test; spf=pass; dkim=pass; dmarc=pass")]
    email = _build_email(base_email, headers)
    findings, auth_hdrs = AuthAnalyzer().analyze(email)

    methods = auth_hdrs[0].methods
    assert len(methods) == 3
    assert methods[0].method == "spf"
    assert methods[0].result == "pass"
    assert methods[0].domain is None

    assert methods[1].method == "dkim"
    assert methods[1].result == "pass"
    assert methods[1].domain is None

    assert methods[2].method == "dmarc"
    assert methods[2].result == "pass"
    assert methods[2].domain is None


def test_unknown_result_values(base_email):
    headers = [("Authentication-Results", "mx.test; spf=bizarre_value smtp.mailfrom=example.com")]
    email = _build_email(base_email, headers)
    findings, auth_hdrs = AuthAnalyzer().analyze(email)

    methods = auth_hdrs[0].methods
    assert methods[0].method == "spf"
    assert methods[0].result == "bizarre_value"


def test_malformed_empty_garbage_tokens(base_email):
    headers = [("Authentication-Results", "mx.test; =pass; spf=; ; ; dkim=pass = = =")]
    email = _build_email(base_email, headers)
    findings, auth_hdrs = AuthAnalyzer().analyze(email)

    methods = auth_hdrs[0].methods
    # =pass is ignored (no method name), spf= is ignored (no result), dkim=pass is parsed
    assert len(methods) == 1
    assert methods[0].method == "dkim"
    assert methods[0].result == "pass"


def test_dkim_alignment_non_matching(base_email):
    email = _build_email(
        base_email, [("Authentication-Results", "mx; dkim=pass header.d=evil.com")]
    )
    findings, _ = AuthAnalyzer().analyze(email)
    assert any(f.id == "AUTH-DKIM-ALIGNMENT-MISMATCH" for f in findings)


def test_no_crash_on_duplicate_malformed(base_email):
    headers = [
        ("Authentication-Results", "mx.test; spf=pass"),
        ("Authentication-Results", "mx.test; spf=pass"),
        ("Authentication-Results", "mx.test;;;;;"),
        ("Authentication-Results", "mx.test; spf=fail"),
        ("Authentication-Results", ""),
        ("Received-SPF", ""),
        ("Received-SPF", "malformed_no_domain"),
    ]
    email = _build_email(base_email, headers)
    findings, auth_hdrs = AuthAnalyzer().analyze(email)
    assert len(auth_hdrs) >= 2
