"""
Risk scoring engine.

Produces a unified risk score where **100 is safe** and **0 is dangerous**.

Score starts at 100 and each finding contributes positive/negative points.
Every finding is preserved in an itemized breakdown so users can see exactly
why a URL lost points (e.g. "Domain registered very recently [-40]").
"""
from __future__ import annotations

from dataclasses import dataclass, field

# Verdict thresholds (score is 100=safe ... 0=dangerous)
VERDICT_LEVELS = [
    (85, "SAFE", "safe"),
    (70, "LOW RISK", "low"),
    (40, "SUSPICIOUS", "suspicious"),
    (0, "DANGEROUS", "critical"),
]


@dataclass
class RiskReport:
    """Final risk output for one scan."""

    score: int
    verdict: str
    risk_level: str
    findings: list[dict] = field(default_factory=list)
    category_totals: dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "risk_score": self.score,
            "verdict": self.verdict,
            "risk_level": self.risk_level,
            "category_totals": self.category_totals,
        }


def classify(score: int) -> tuple[str, str]:
    """Map a 0..100 score to (verdict, risk_level)."""
    for threshold, verdict, level in VERDICT_LEVELS:
        if score >= threshold:
            return verdict, level
    return "DANGEROUS", "critical"


def compute_risk(findings: list[dict]) -> RiskReport:
    """
    Aggregate findings into a final score.

    Findings look like::

        {"category": "Heuristics", "label": "...", "points": -40,
         "severity": "critical", "detail": "..."}
    """
    score = 100
    category_totals: dict[str, int] = {}
    normalized: list[dict] = []

    for f in findings:
        points = int(f.get("points", 0))
        score += points
        category = f.get("category", "Other")
        category_totals[category] = category_totals.get(category, 0) + points
        normalized.append(f)

    score = max(0, min(100, score))
    verdict, level = classify(score)
    return RiskReport(
        score=score,
        verdict=verdict,
        risk_level=level,
        findings=normalized,
        category_totals=category_totals,
    )
