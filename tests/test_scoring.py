import pytest

from phishscope.models import (
    AssessmentConfidence,
    Confidence,
    Finding,
    FindingCategory,
    RiskLevel,
    Severity,
)
from phishscope.scoring import ScoringEngine


@pytest.fixture
def engine():
    return ScoringEngine()

def _f(id, category, severity, confidence, evidence="ev"):
    return Finding(
        id=id,
        name=f"Name {id}",
        category=category,
        severity=severity,
        confidence=confidence,
        description="Desc",
        evidence=evidence,
        source="Test"
    )

def test_empty_findings(engine):
    res = engine.evaluate([])
    assert res.score == 0
    assert res.risk_level == RiskLevel.SAFE
    assert res.assessment_confidence == AssessmentConfidence.LOW

def test_info_only(engine):
    res = engine.evaluate([_f("1", FindingCategory.HEADER, Severity.INFO, Confidence.HIGH)])
    assert res.score == 0
    assert res.risk_level == RiskLevel.SAFE
    assert res.assessment_confidence == AssessmentConfidence.LOW

def test_one_low(engine):
    res = engine.evaluate([_f("1", FindingCategory.HEADER, Severity.LOW, Confidence.HIGH)])
    assert res.score == 10
    assert res.risk_level == RiskLevel.SAFE
    assert res.assessment_confidence == AssessmentConfidence.LOW

def test_one_medium(engine):
    res = engine.evaluate([_f("1", FindingCategory.URL, Severity.MEDIUM, Confidence.HIGH)])
    assert res.score == 30
    assert res.risk_level == RiskLevel.SUSPICIOUS
    assert res.assessment_confidence == AssessmentConfidence.MEDIUM

def test_one_high(engine):
    res = engine.evaluate([_f("1", FindingCategory.ATTACHMENT, Severity.HIGH, Confidence.HIGH)])
    assert res.score == 50
    assert res.risk_level == RiskLevel.HIGH_RISK
    assert res.assessment_confidence == AssessmentConfidence.MEDIUM

def test_one_critical_exceptional(engine):
    # Exception: a genuinely critical severity finding
    res = engine.evaluate([_f("1", FindingCategory.ATTACHMENT, Severity.CRITICAL, Confidence.HIGH)])
    assert res.score == 75
    assert res.risk_level == RiskLevel.CRITICAL
    assert res.assessment_confidence == AssessmentConfidence.MEDIUM

def test_confidence_multipliers(engine):
    # MEDIUM (30) * LOW (0.5) = 15
    res = engine.evaluate([_f("1", FindingCategory.URL, Severity.MEDIUM, Confidence.LOW)])
    assert res.score == 15
    assert res.assessment_confidence == AssessmentConfidence.LOW

def test_category_saturation(engine):
    findings = [
        _f("1", FindingCategory.URL, Severity.LOW, Confidence.HIGH, "e1"),
        _f("1", FindingCategory.URL, Severity.LOW, Confidence.HIGH, "e2"),
        _f("1", FindingCategory.URL, Severity.LOW, Confidence.HIGH, "e3"),
    ]
    res = engine.evaluate(findings)
    # 10 + 5 + 2.5 = 17.5 -> 18
    assert res.score == 18

def test_category_caps(engine):
    # Header cap is 30.
    findings = [
        _f("1", FindingCategory.HEADER, Severity.HIGH, Confidence.HIGH, "e1"),
        _f("2", FindingCategory.HEADER, Severity.HIGH, Confidence.HIGH, "e2"),
    ]
    res = engine.evaluate(findings)
    assert res.score == 30 # Capped at 30

def test_exact_duplicate_removal(engine):
    # Same ID and same evidence
    findings = [
        _f("1", FindingCategory.URL, Severity.MEDIUM, Confidence.HIGH, "exact_same"),
        _f("1", FindingCategory.URL, Severity.MEDIUM, Confidence.HIGH, "exact_same"),
    ]
    res = engine.evaluate(findings)
    assert res.score == 30 # Only counts once

def test_highest_confidence_duplicate_preservation(engine):
    findings = [
        _f("1", FindingCategory.URL, Severity.MEDIUM, Confidence.LOW, "exact_same"),
        _f("1", FindingCategory.URL, Severity.MEDIUM, Confidence.HIGH, "exact_same"),
    ]
    res = engine.evaluate(findings)
    assert res.score == 30 # Preserves HIGH (1.0) over LOW (0.5)

def test_multiple_categories(engine):
    findings = [
        _f("1", FindingCategory.HEADER, Severity.LOW, Confidence.HIGH), # 10
        _f("2", FindingCategory.URL, Severity.LOW, Confidence.HIGH),    # 10
        _f("3", FindingCategory.AUTHENTICATION, Severity.LOW, Confidence.HIGH), # 10
    ]
    res = engine.evaluate(findings)
    assert res.score == 30

def test_critical_cross_category(engine):
    findings = [
        _f("1", FindingCategory.ATTACHMENT, Severity.HIGH, Confidence.HIGH), # 50
        _f("2", FindingCategory.URL, Severity.MEDIUM, Confidence.HIGH),      # 30
    ]
    res = engine.evaluate(findings)
    assert res.score == 80
    assert res.risk_level == RiskLevel.CRITICAL
    assert res.assessment_confidence == AssessmentConfidence.HIGH

def test_order_independence(engine):
    f1 = _f("1", FindingCategory.ATTACHMENT, Severity.LOW, Confidence.HIGH, "e1") # 10
    f2 = _f("2", FindingCategory.ATTACHMENT, Severity.HIGH, Confidence.HIGH, "e2") # 50
    # Saturation sorts descending, so order shouldn't matter
    res1 = engine.evaluate([f1, f2])
    res2 = engine.evaluate([f2, f1])
    assert res1.score == res2.score
    assert res1.score == 55 # 50 + 10*0.5 = 55

def test_score_bounds(engine):
    findings = [
        _f("1", FindingCategory.ATTACHMENT, Severity.CRITICAL, Confidence.HIGH), # 75
        _f("2", FindingCategory.URL, Severity.CRITICAL, Confidence.HIGH), # 75 (capped 60)
    ]
    res = engine.evaluate(findings)
    assert res.score == 100 # Capped at 100

def test_two_high_one_category(engine):
    findings = [
        _f("1", FindingCategory.ATTACHMENT, Severity.HIGH, Confidence.HIGH, "e1"), # 50
        _f("2", FindingCategory.ATTACHMENT, Severity.HIGH, Confidence.HIGH, "e2"), # 25
    ]
    res = engine.evaluate(findings)
    assert res.score == 75
    assert res.risk_level == RiskLevel.HIGH_RISK

def test_saturation_reaches_75(engine):
    findings = [
        _f("1", FindingCategory.ATTACHMENT, Severity.HIGH, Confidence.HIGH, "e1"), # 50
        _f("2", FindingCategory.ATTACHMENT, Severity.MEDIUM, Confidence.HIGH, "e2"), # 15
        _f("3", FindingCategory.ATTACHMENT, Severity.MEDIUM, Confidence.HIGH, "e3"), # 7.5
        _f("4", FindingCategory.ATTACHMENT, Severity.LOW, Confidence.HIGH, "e4"),
        _f("5", FindingCategory.ATTACHMENT, Severity.LOW, Confidence.HIGH, "e5"),
        _f("6", FindingCategory.ATTACHMENT, Severity.LOW, Confidence.HIGH, "e6"),
    ]
    res = engine.evaluate(findings)
    assert res.score == 75
    assert res.risk_level == RiskLevel.HIGH_RISK

def test_actual_critical_finding(engine):
    findings = [
        _f("1", FindingCategory.ATTACHMENT, Severity.CRITICAL, Confidence.HIGH, "e1")
    ]
    res = engine.evaluate(findings)
    assert res.score == 75
    assert res.risk_level == RiskLevel.CRITICAL
    assert res.assessment_confidence == AssessmentConfidence.MEDIUM

def test_high_attach_med_url(engine):
    findings = [
        _f("1", FindingCategory.ATTACHMENT, Severity.HIGH, Confidence.HIGH, "e1"),
        _f("2", FindingCategory.URL, Severity.MEDIUM, Confidence.HIGH, "e2"),
    ]
    res = engine.evaluate(findings)
    assert res.score == 80
    assert res.risk_level == RiskLevel.CRITICAL

def test_high_auth_med_header(engine):
    findings = [
        _f("1", FindingCategory.AUTHENTICATION, Severity.HIGH, Confidence.HIGH, "e1"),
        _f("2", FindingCategory.HEADER, Severity.MEDIUM, Confidence.HIGH, "e2"),
    ]
    res = engine.evaluate(findings)
    assert res.score == 70
    assert res.risk_level == RiskLevel.HIGH_RISK

def test_score_75_two_categories_no_critical(engine):
    findings = [
        _f("1", FindingCategory.URL, Severity.HIGH, Confidence.HIGH, "e1"), # 50
        _f("2", FindingCategory.HEADER, Severity.MEDIUM, Confidence.HIGH, "e2"), # 30
    ]
    res = engine.evaluate(findings)
    assert res.score == 80
    assert res.risk_level == RiskLevel.CRITICAL

def test_score_75_one_category_no_critical(engine):
    findings = [
        _f("1", FindingCategory.ATTACHMENT, Severity.HIGH, Confidence.HIGH, "e1"), # 50
        _f("2", FindingCategory.ATTACHMENT, Severity.HIGH, Confidence.HIGH, "e2"), # 25
    ]
    res = engine.evaluate(findings)
    assert res.score == 75
    assert res.risk_level == RiskLevel.HIGH_RISK
