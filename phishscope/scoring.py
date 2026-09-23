from collections import defaultdict

from .models import (
    AnalysisResult,
    AssessmentConfidence,
    CategoryScore,
    Confidence,
    Finding,
    FindingCategory,
    RiskLevel,
    Severity,
)


class ScoringEngine:
    def __init__(self):
        self.category_caps = {
            FindingCategory.AUTHENTICATION: 40.0,
            FindingCategory.HEADER: 30.0,
            FindingCategory.URL: 60.0,
            FindingCategory.ATTACHMENT: 80.0,
        }

        self.severity_values = {
            Severity.INFO: 0.0,
            Severity.LOW: 10.0,
            Severity.MEDIUM: 30.0,
            Severity.HIGH: 50.0,
            Severity.CRITICAL: 75.0,
        }

        self.confidence_multipliers = {
            Confidence.LOW: 0.5,
            Confidence.MEDIUM: 0.75,
            Confidence.HIGH: 1.0,
        }

    def evaluate(self, findings: list[Finding]) -> AnalysisResult:
        # 1. Deduplicate exact (finding_id, evidence) preserving highest confidence
        unique_findings_map = {}
        for f in findings:
            key = (f.id, f.evidence)
            if key not in unique_findings_map:
                unique_findings_map[key] = f
            else:
                existing = unique_findings_map[key]
                if (
                    self.confidence_multipliers[f.confidence]
                    > self.confidence_multipliers[existing.confidence]
                ):
                    unique_findings_map[key] = f

        deduplicated = list(unique_findings_map.values())

        # Group by category
        cat_findings = defaultdict(list)
        for f in deduplicated:
            cat_findings[f.category].append(f)

        category_scores: dict[FindingCategory, CategoryScore] = {}
        total_raw_uncapped = 0.0
        active_categories = 0
        has_high_conf_finding = False

        for category, cat_list in cat_findings.items():
            # Calculate base scores
            scored_list = []
            for f in cat_list:
                base = self.severity_values[f.severity] * self.confidence_multipliers[f.confidence]
                scored_list.append((base, f))

                if f.severity != Severity.INFO:
                    if f.confidence == Confidence.HIGH:
                        has_high_conf_finding = True

            # Sort descending by base score
            scored_list.sort(key=lambda x: x[0], reverse=True)

            # Apply saturation
            cat_raw_score = 0.0
            for rank, (base_val, _) in enumerate(scored_list):
                cat_raw_score += base_val * (0.5**rank)

            total_raw_uncapped += cat_raw_score

            # Check if category has meaningful non-INFO findings
            if any(f.severity != Severity.INFO for f in cat_list):
                active_categories += 1

            cap = self.category_caps.get(category, 100.0)
            capped_score = min(cat_raw_score, cap)

            category_scores[category] = CategoryScore(
                category=category,
                raw_score=cat_raw_score,
                capped_score=capped_score,
                contributing_findings=cat_list,
            )

        # Ensure all known categories exist in result even if empty
        for cat in self.category_caps.keys():
            if cat not in category_scores:
                category_scores[cat] = CategoryScore(
                    category=cat, raw_score=0.0, capped_score=0.0, contributing_findings=[]
                )

        total_score_float = min(sum(cs.capped_score for cs in category_scores.values()), 100.0)
        final_score = int(round(total_score_float))

        # Risk Classification
        if final_score <= 10:
            risk_level = RiskLevel.SAFE
        elif final_score <= 49:
            risk_level = RiskLevel.SUSPICIOUS
        elif final_score <= 74:
            risk_level = RiskLevel.HIGH_RISK
        else:
            has_critical_severity = any(f.severity == Severity.CRITICAL for f in deduplicated)
            if has_critical_severity or active_categories >= 2:
                risk_level = RiskLevel.CRITICAL
            else:
                risk_level = RiskLevel.HIGH_RISK

        # Assessment Confidence
        if final_score < 15 or (
            deduplicated and all(f.confidence == Confidence.LOW for f in deduplicated)
        ):
            assessment_confidence = AssessmentConfidence.LOW
        elif final_score >= 50 and active_categories >= 2 and has_high_conf_finding:
            assessment_confidence = AssessmentConfidence.HIGH
        else:
            assessment_confidence = AssessmentConfidence.MEDIUM

        # Exception for LOW conf if no findings
        if not deduplicated:
            assessment_confidence = AssessmentConfidence.LOW

        return AnalysisResult(
            score=final_score,
            risk_level=risk_level,
            assessment_confidence=assessment_confidence,
            category_scores=category_scores,
            all_findings=deduplicated,
        )
