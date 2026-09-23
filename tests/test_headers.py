from datetime import datetime, timezone

import pytest

from phishscope.headers import HeaderAnalyzer
from phishscope.models import ParsedEmail, ReceivedHop, Severity


@pytest.fixture
def base_email():
    return ParsedEmail(
        file_path="memory",
        file_sha256="hash",
        subject="Normal Subject",
        from_header="Alice <alice@example.com>",
        to_headers=["Bob <bob@example.com>"],
        cc_headers=[],
        date=datetime.now(timezone.utc),
        message_id="<123@example.com>",
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


def test_no_findings_for_normal_email(base_email):
    analyzer = HeaderAnalyzer()
    findings = analyzer.analyze(base_email)
    assert len(findings) == 0


def test_reply_to_mismatch(base_email):
    email = ParsedEmail(**{**base_email.__dict__, "reply_to": "attacker@evil.com"})
    analyzer = HeaderAnalyzer()
    findings = analyzer.analyze(email)
    assert any(f.id == "HDR-REPLYTO-MISMATCH" for f in findings)


def test_return_path_mismatch(base_email):
    email = ParsedEmail(**{**base_email.__dict__, "return_path": "<attacker@evil.com>"})
    analyzer = HeaderAnalyzer()
    findings = analyzer.analyze(email)
    assert any(f.id == "HDR-RETURNPATH-MISMATCH" for f in findings)


def test_display_name_spoofing(base_email):
    email = ParsedEmail(
        **{**base_email.__dict__, "from_header": '"PayPal Security" <attacker@gmail.com>'}
    )
    analyzer = HeaderAnalyzer()
    findings = analyzer.analyze(email)
    assert any(f.id == "HDR-DISPLAY-SPOOF" for f in findings)


def test_no_display_spoof_if_domain_matches(base_email):
    email = ParsedEmail(
        **{**base_email.__dict__, "from_header": '"PayPal Security" <admin@paypal.com>'}
    )
    analyzer = HeaderAnalyzer()
    findings = analyzer.analyze(email)
    assert not any(f.id == "HDR-DISPLAY-SPOOF" for f in findings)


def test_lookalike_domain_substitution(base_email):
    email = ParsedEmail(**{**base_email.__dict__, "from_header": '"Support" <admin@paypa1.com>'})
    analyzer = HeaderAnalyzer()
    findings = analyzer.analyze(email)
    lookalikes = [f for f in findings if f.id == "HDR-LOOKALIKE-DOMAIN"]
    assert len(lookalikes) > 0
    assert lookalikes[0].severity == Severity.HIGH


def test_lookalike_domain_edit_distance(base_email):
    email = ParsedEmail(**{**base_email.__dict__, "from_header": '"Support" <admin@paypel.com>'})
    analyzer = HeaderAnalyzer()
    findings = analyzer.analyze(email)
    lookalikes = [f for f in findings if f.id == "HDR-LOOKALIKE-DOMAIN"]
    assert len(lookalikes) > 0
    assert lookalikes[0].severity == Severity.MEDIUM


def test_punycode_domain(base_email):
    email = ParsedEmail(
        **{**base_email.__dict__, "from_header": '"Support" <admin@xn--80ak6aa92e.com>'}
    )
    analyzer = HeaderAnalyzer()
    findings = analyzer.analyze(email)
    assert any(f.id == "HDR-IDN-PUNYCODE" for f in findings)


def test_received_chain_analysis(base_email):
    hops = [
        ReceivedHop(
            hop_number=1,
            raw_content="from mx.example.com by mta.example.com with ESMTP id 123; "
            "Wed, 24 Sep 2026 10:00:10 +0000",
        ),
        ReceivedHop(
            hop_number=2,
            raw_content="from [192.168.1.100] by mx.example.com with HTTP; "
            "Wed, 24 Sep 2026 10:05:10 +0000",
        ),  # Notice this is 5 mins LATER
    ]
    email = ParsedEmail(**{**base_email.__dict__, "received_headers": hops})
    analyzer = HeaderAnalyzer()
    findings = analyzer.analyze(email)

    assert any(f.id == "HDR-RCVD-ORIGINATING-IP" for f in findings)
    assert any(f.id == "HDR-RCVD-TIME-INCONSISTENCY" for f in findings)


def test_message_id_missing(base_email):
    email = ParsedEmail(**{**base_email.__dict__, "message_id": ""})
    analyzer = HeaderAnalyzer()
    findings = analyzer.analyze(email)
    assert any(f.id == "HDR-MSGID-MISSING" for f in findings)


def test_message_id_malformed(base_email):
    email = ParsedEmail(**{**base_email.__dict__, "message_id": "<just_a_string>"})
    analyzer = HeaderAnalyzer()
    findings = analyzer.analyze(email)
    assert any(f.id == "HDR-MSGID-MALFORMED" for f in findings)


def test_subject_urgency(base_email):
    email = ParsedEmail(
        **{**base_email.__dict__, "subject": "Urgent: Action Required on your account"}
    )
    analyzer = HeaderAnalyzer()
    findings = analyzer.analyze(email)
    assert any(f.id == "HDR-SUBJECT-URGENCY" for f in findings)
