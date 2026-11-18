import pytest

from app.core.constants import Severity
from app.core.risk_model import (
    RiskInputError,
    assess_risk,
    calculate_overall_impact,
    calculate_risk_score,
    severity_for_score,
)


def test_overall_impact_is_max_of_cia():
    assert calculate_overall_impact(4, 3, 5) == 5
    assert calculate_overall_impact(1, 1, 1) == 1
    assert calculate_overall_impact(2, 5, 3) == 5
    assert calculate_overall_impact(3, 3, 3) == 3


def test_overall_impact_is_not_an_average():
    # Average would be 2; the agreed model takes the maximum.
    assert calculate_overall_impact(1, 1, 4) == 4


def test_risk_score_is_likelihood_times_impact():
    assert calculate_risk_score(4, 5) == 20
    assert calculate_risk_score(1, 1) == 1
    assert calculate_risk_score(5, 5) == 25


def test_spec_worked_example():
    result = assess_risk(likelihood=4, confidentiality=4, integrity=3, availability=5)
    assert result.overall_impact == 5
    assert result.risk_score == 20
    assert result.severity is Severity.CRITICAL
    assert "4 × 5 = 20" in result.explanation


@pytest.mark.parametrize(
    "score,expected",
    [
        (1, Severity.LOW), (4, Severity.LOW),
        (5, Severity.MODERATE), (9, Severity.MODERATE),
        (10, Severity.HIGH), (16, Severity.HIGH),
        (17, Severity.CRITICAL), (25, Severity.CRITICAL),
    ],
)
def test_severity_band_boundaries(score, expected):
    assert severity_for_score(score) is expected


def test_every_reachable_score_maps_to_exactly_the_agreed_band():
    for likelihood in range(1, 6):
        for impact in range(1, 6):
            score = likelihood * impact
            expected = (
                Severity.LOW if score <= 4 else
                Severity.MODERATE if score <= 9 else
                Severity.HIGH if score <= 16 else Severity.CRITICAL
            )
            assert severity_for_score(score) is expected


@pytest.mark.parametrize("bad", [0, 6, -1, 2.5, "3", None, True])
def test_invalid_ratings_rejected(bad):
    with pytest.raises(RiskInputError):
        assess_risk(bad, 3, 3, 3)
    with pytest.raises(RiskInputError):
        assess_risk(3, bad, 3, 3)
    with pytest.raises(RiskInputError):
        assess_risk(3, 3, bad, 3)
    with pytest.raises(RiskInputError):
        assess_risk(3, 3, 3, bad)


@pytest.mark.parametrize("bad", [0, 26, -5])
def test_out_of_range_scores_rejected(bad):
    with pytest.raises(RiskInputError):
        severity_for_score(bad)
