# Risk model

Hospitra uses the agreed **transparent qualitative** model. It is implemented once, in
`backend/app/core/risk_model.py`; every other layer (API, register, exports, PDF, frontend) displays
the values it produces.

## Inputs

| Input | Range | Notes |
|---|---|---|
| Likelihood | integer 1–5 | |
| Confidentiality impact | integer 1–5 | |
| Integrity impact | integer 1–5 | |
| Availability impact | integer 1–5 | |

Data classification (Public / Internal / Confidential / Restricted) and asset criticality
(Low / Medium / High / Critical) are stored on the asset and are **not** inputs to the formula.

## Formula

```
Impact     = max(Confidentiality, Integrity, Availability)
Risk Score = Likelihood × Impact           (integer 1–25)
```

## Severity bands

| Score | Severity |
|---:|---|
| 1–4 | Low |
| 5–9 | Moderate |
| 10–16 | High |
| 17–25 | Critical |

## Worked example

Likelihood 4, C 4, I 3, A 5 → Impact = max(4, 3, 5) = 5 → Score = 4 × 5 = 20 → **Critical**
(seeded as `RSK-0001`, HSP-A-CLN-001, T1 × V6; covered by `test_spec_worked_example`).

## Validation and integrity

- Non-integers, booleans and values outside 1–5 are rejected (`RiskInputError`; HTTP 422 at the API).
- `overall_impact`, `risk_score` and `severity` cannot be supplied by clients (`extra="forbid"`).
- The database enforces CHECK constraints on all ranges.
- Updating any input recalculates the derived values and the audit entry records the before/after score and severity.
- The API returns a `calculation` object (`impact_expression`, `score_expression`, `severity_band`) so the UI displays the server's calculation verbatim.

## Residual risk (Version 2)

Approved "level reduction" model, implemented once in `core/risk_model.py::assess_residual` and
applied by `risk_service.apply_assessment` whenever a risk's inputs, its control links, or a linked
control's type/active flag change:

| Rule | Detail |
|---|---|
| What counts | Only links with status **Implemented** to an **active** control. *Planned* links and inactive controls have no effect. |
| Axis | **Preventive** controls reduce **likelihood**; **Detective** and **Corrective** controls reduce **impact**. |
| Strength | **Partial** = 1 level, **Substantial** = 2 levels. |
| No stacking | Only the single strongest counted control on each axis is applied (ties: lowest control code). |
| Floor | Residual likelihood and impact never go below 1. |
| Result | `Residual Score = Residual L × Residual Impact`, mapped with the **same** 1–4 / 5–9 / 10–16 / 17–25 bands. |

```
Residual L      = max(1, L − strongest preventive reduction)
Residual Impact = max(1, Impact − strongest detective/corrective reduction)
Residual Score  = Residual L × Residual Impact
```

Worked example (seeded `RSK-0001`, HSP-A-CLN-001, T1 × V6): inherent L4 × I5 = 20 Critical.
C06 Patch management (Preventive, Implemented, Partial) → L 4−1 = 3; C08 Immutable backups
(Corrective, Implemented, Substantial) → Impact 5−2 = 3; **Residual = 3 × 3 = 9 Moderate**.
The same risk at Branch C has both controls only *Planned*, so its residual stays 20 Critical.

Residual values are derived fields (`residual_likelihood`, `residual_impact`, `residual_score`,
`residual_severity`), protected by CHECK constraints and rejected as API input. Every change that
alters them writes an audit entry with the before/after values. Residual scores are illustrative:
control effectiveness is a qualitative judgement, not a measured value.

Seeded distribution (fresh dataset): inherent Low 8 · Moderate 15 · High 17 · Critical 2 →
residual Low 13 · Moderate 17 · High 11 · Critical 1.

## Interpretation

Scores are **illustrative** ratings for a fictional hospital. They are not statistically calibrated
probabilities, confirmed findings or certified hospital risk ratings.

## Threat–vulnerability pairings

Threats are **not** paired with every vulnerability. 14 documented pairings, each with a rationale,
are seeded (for example T2 × V2: *"With single-factor VPN, a stolen password alone grants remote
network access (initial access only)."*). A risk may still be recorded for an undocumented
combination; the UI then states that no documented rationale exists.

## Seeded risks

14 templates × 3 branches = 42 risks. Branch B uses likelihood − 1 (clamped to 1–5), an illustrative
assumption reflecting its outpatient footprint. Distribution at seed time: Low 8 · Moderate 15 · High 17 · Critical 2.
