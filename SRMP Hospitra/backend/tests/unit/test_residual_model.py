"""The approved V2 residual model (level reduction, strongest control per axis, floor 1)."""

import pytest

from app.core.constants import Severity
from app.core.risk_model import ControlEffect, RiskInputError, assess_residual, severity_for_score

L, I = "likelihood", "impact"


def test_no_controls_residual_equals_inherent():
    r = assess_residual(4, 5, [])
    assert (r.residual_likelihood, r.residual_impact, r.residual_score, r.residual_severity) == (4, 5, 20, Severity.CRITICAL)
    assert r.likelihood_control is None and r.impact_control is None


def test_preventive_partial_and_substantial_reduce_likelihood():
    assert assess_residual(4, 5, [ControlEffect("C1", L, 1)]).residual_score == 3 * 5
    assert assess_residual(4, 5, [ControlEffect("C1", L, 2)]).residual_score == 2 * 5


def test_impact_axis_reduction():
    r = assess_residual(4, 5, [ControlEffect("C8", I, 2)])
    assert (r.residual_likelihood, r.residual_impact, r.residual_score) == (4, 3, 12)


def test_both_axes_worked_example():
    # Spec example risk L4 × I5 = 20 Critical; C06 Partial (L) and C08 Substantial (I) → 3 × 3 = 9 Moderate.
    r = assess_residual(4, 5, [ControlEffect("C06", L, 1), ControlEffect("C08", I, 2)])
    assert (r.residual_score, r.residual_severity) == (9, Severity.MODERATE)
    assert r.score_expression == "Residual Score = 3 × 3 = 9"
    assert "C06" in r.likelihood_expression and "C08" in r.impact_expression


def test_no_stacking_only_strongest_counts():
    r = assess_residual(5, 5, [ControlEffect("C1", L, 1), ControlEffect("C2", L, 1), ControlEffect("C3", L, 1)])
    assert r.residual_likelihood == 4
    r = assess_residual(5, 5, [ControlEffect("C1", L, 1), ControlEffect("C2", L, 2)])
    assert r.residual_likelihood == 3 and r.likelihood_control == "C2"


def test_tie_is_deterministic():
    a = assess_residual(5, 5, [ControlEffect("C09", I, 1), ControlEffect("C02", I, 1)])
    b = assess_residual(5, 5, [ControlEffect("C02", I, 1), ControlEffect("C09", I, 1)])
    assert a.impact_control == b.impact_control == "C02"


def test_floor_of_one():
    r = assess_residual(1, 2, [ControlEffect("C1", L, 2), ControlEffect("C2", I, 2)])
    assert (r.residual_likelihood, r.residual_impact, r.residual_score, r.residual_severity) == (1, 1, 1, Severity.LOW)


def test_exhaustive_against_definition():
    for lik in range(1, 6):
        for imp in range(1, 6):
            for rl in (0, 1, 2):
                for ri in (0, 1, 2):
                    effects = ([ControlEffect("A", L, rl)] if rl else []) + ([ControlEffect("B", I, ri)] if ri else [])
                    r = assess_residual(lik, imp, effects)
                    expected = max(1, lik - rl) * max(1, imp - ri)
                    assert r.residual_score == expected
                    assert r.residual_severity is severity_for_score(expected)
                    assert r.residual_score <= lik * imp


@pytest.mark.parametrize("effect", [ControlEffect("X", "speed", 1), ControlEffect("X", L, 3), ControlEffect("X", L, 0),
                                    ControlEffect("X", L, True)])
def test_invalid_effects_rejected(effect):
    with pytest.raises(RiskInputError):
        assess_residual(3, 3, [effect])


@pytest.mark.parametrize("bad", [0, 6, "3", None])
def test_invalid_inherent_inputs_rejected(bad):
    with pytest.raises(RiskInputError):
        assess_residual(bad, 3)
    with pytest.raises(RiskInputError):
        assess_residual(3, bad)
