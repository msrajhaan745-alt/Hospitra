"""The agreed qualitative risk model (spec §8) — the ONLY implementation of the formula.

    Impact     = max(Confidentiality, Integrity, Availability)
    Risk Score = Likelihood × Impact            (integer, 1–25)

    Severity:  1–4 Low · 5–9 Moderate · 10–16 High · 17–25 Critical

Every other layer (API, services, exports, PDF, frontend) consumes the values produced
here; none of them re-implements the calculation. The score is an illustrative,
qualitative rating — not a calibrated probability or a certified hospital risk rating.
"""

from __future__ import annotations

from dataclasses import dataclass

from app.core.constants import Severity

RATING_MIN = 1
RATING_MAX = 5

# Inclusive score bands. Ordered; first match wins.
SEVERITY_BANDS: tuple[tuple[int, int, Severity], ...] = (
    (1, 4, Severity.LOW),
    (5, 9, Severity.MODERATE),
    (10, 16, Severity.HIGH),
    (17, 25, Severity.CRITICAL),
)


class RiskInputError(ValueError):
    """Raised when a likelihood or CIA rating is outside the permitted 1–5 integer range."""


@dataclass(frozen=True)
class RiskAssessment:
    likelihood: int
    confidentiality: int
    integrity: int
    availability: int
    overall_impact: int
    risk_score: int
    severity: Severity

    @property
    def explanation(self) -> str:
        return (
            f"Impact = max(C={self.confidentiality}, I={self.integrity}, A={self.availability}) = "
            f"{self.overall_impact}; Risk Score = {self.likelihood} × {self.overall_impact} = "
            f"{self.risk_score}; Severity = {self.severity.value}"
        )


def _validate_rating(name: str, value: object) -> int:
    # bool is a subclass of int; reject it explicitly.
    if isinstance(value, bool) or not isinstance(value, int):
        raise RiskInputError(f"{name} must be an integer between {RATING_MIN} and {RATING_MAX}.")
    if not RATING_MIN <= value <= RATING_MAX:
        raise RiskInputError(f"{name} must be between {RATING_MIN} and {RATING_MAX} (got {value}).")
    return value


def calculate_overall_impact(confidentiality: int, integrity: int, availability: int) -> int:
    c = _validate_rating("Confidentiality impact", confidentiality)
    i = _validate_rating("Integrity impact", integrity)
    a = _validate_rating("Availability impact", availability)
    return max(c, i, a)


def calculate_risk_score(likelihood: int, overall_impact: int) -> int:
    likelihood = _validate_rating("Likelihood", likelihood)
    overall_impact = _validate_rating("Overall impact", overall_impact)
    return likelihood * overall_impact


def severity_for_score(score: int) -> Severity:
    if isinstance(score, bool) or not isinstance(score, int):
        raise RiskInputError("Risk score must be an integer.")
    for low, high, severity in SEVERITY_BANDS:
        if low <= score <= high:
            return severity
    raise RiskInputError(f"Risk score must be between 1 and 25 (got {score}).")


def assess_risk(likelihood: int, confidentiality: int, integrity: int, availability: int) -> RiskAssessment:
    return _assess(likelihood, confidentiality, integrity, availability)


# ---------------------------------------------------------------------------------------
# V2 residual risk — approved "level reduction" model
#
#   Only IMPLEMENTED controls on ACTIVE control records count.
#   Preventive controls reduce likelihood; detective and corrective controls reduce impact.
#   Partial = 1 level, Substantial = 2 levels.
#   Only the single strongest control on each axis counts (no stacking).
#   Residual L = max(1, L − strongest likelihood reduction)
#   Residual I = max(1, Impact − strongest impact reduction)
#   Residual Score = Residual L × Residual I, mapped with the SAME severity bands.
# ---------------------------------------------------------------------------------------

@dataclass(frozen=True)
class ControlEffect:
    """One counted control's effect on one axis."""

    code: str
    axis: str        # "likelihood" | "impact"
    reduction: int   # 1 (Partial) or 2 (Substantial)


@dataclass(frozen=True)
class ResidualAssessment:
    inherent_likelihood: int
    inherent_impact: int
    likelihood_reduction: int
    impact_reduction: int
    likelihood_control: str | None
    impact_control: str | None
    residual_likelihood: int
    residual_impact: int
    residual_score: int
    residual_severity: Severity

    @property
    def likelihood_expression(self) -> str:
        source = f" ({self.likelihood_control})" if self.likelihood_control else " (no implemented preventive control)"
        return (f"Residual L = max(1, {self.inherent_likelihood} − {self.likelihood_reduction}){source} "
                f"= {self.residual_likelihood}")

    @property
    def impact_expression(self) -> str:
        source = f" ({self.impact_control})" if self.impact_control else " (no implemented detective/corrective control)"
        return (f"Residual Impact = max(1, {self.inherent_impact} − {self.impact_reduction}){source} "
                f"= {self.residual_impact}")

    @property
    def score_expression(self) -> str:
        return f"Residual Score = {self.residual_likelihood} × {self.residual_impact} = {self.residual_score}"


def assess_residual(likelihood: int, overall_impact: int, effects: list[ControlEffect] | tuple = ()) -> ResidualAssessment:
    likelihood = _validate_rating("Likelihood", likelihood)
    overall_impact = _validate_rating("Overall impact", overall_impact)
    best: dict[str, ControlEffect] = {}
    for effect in effects:
        if effect.axis not in ("likelihood", "impact"):
            raise RiskInputError(f"Unknown control axis '{effect.axis}'.")
        if isinstance(effect.reduction, bool) or effect.reduction not in (1, 2):
            raise RiskInputError("Control reduction must be 1 (Partial) or 2 (Substantial).")
        current = best.get(effect.axis)
        # Strongest reduction wins; ties resolved by control code for determinism.
        if current is None or (effect.reduction, current.code) > (current.reduction, effect.code):
            best[effect.axis] = effect
    l_eff, i_eff = best.get("likelihood"), best.get("impact")
    l_red = l_eff.reduction if l_eff else 0
    i_red = i_eff.reduction if i_eff else 0
    residual_l = max(1, likelihood - l_red)
    residual_i = max(1, overall_impact - i_red)
    score = residual_l * residual_i
    return ResidualAssessment(
        inherent_likelihood=likelihood,
        inherent_impact=overall_impact,
        likelihood_reduction=l_red,
        impact_reduction=i_red,
        likelihood_control=l_eff.code if l_eff else None,
        impact_control=i_eff.code if i_eff else None,
        residual_likelihood=residual_l,
        residual_impact=residual_i,
        residual_score=score,
        residual_severity=severity_for_score(score),
    )


def _assess(likelihood: int, confidentiality: int, integrity: int, availability: int) -> RiskAssessment:
    impact = calculate_overall_impact(confidentiality, integrity, availability)
    score = calculate_risk_score(likelihood, impact)
    return RiskAssessment(
        likelihood=likelihood,
        confidentiality=confidentiality,
        integrity=integrity,
        availability=availability,
        overall_impact=impact,
        risk_score=score,
        severity=severity_for_score(score),
    )
