# Scoring

This document describes the public contract in `probe.scoring`'s module docstrings.
The current `scoring_version` is `1.0`.

```python
from probe.engine.outcomes import Transport
from probe.scoring import compute_score

score = compute_score(catalog, results, Transport.STDIO)
interim = compute_score(catalog, results, Transport.STDIO, scoring_profile="public-interim")
```

`catalog` is an iterable of `CheckMeta`; `results` is an iterable of `CheckResult`.
Supply the whole catalog, including unrun checks. The function returns the report's
`Score` model without modifying either input. Duplicate catalog IDs, duplicate result
rows, result IDs absent from the catalog, and unknown transports or scoring profiles
raise `ValueError`. Report models reject nonfinite or out-of-range percentages,
negative weights, failed weights exceeding applicable weights, inconsistent family
nulls, and an overall/grade pair with only one null member.

## Weights and applicability

The check's **catalog severity** determines its weight: critical 10, high 5,
medium 2, low 1, info 0. Finding severity does not change that weight. Each FAIL
check contributes its weight once, even if it has findings for many tools.
Checks with the `llm` requirement have zero headline and coverage weight and cannot
trigger caps; their supplemental evidence remains in the report.

Only PASS and FAIL checks are applicable. ERROR, not_applicable, SKIPPED and missing
result rows add no applicable or failed weight. For each family:

```text
family_score = 100 × (1 − failed_weight / applicable_weight)
```

Zero applicable weight produces a null family score. Overall is the weighted average
of non-null family scores, using safety 30, behavior 25, schema 20, protocol 15 and
operability 10. Weights are renormalized when a family is null. With no weighted
applicable checks, overall and grade are null and coverage is 0; the target is ungraded.
Unavailable targets also remain ungraded.

All intermediate arithmetic uses exact fractions. Family scores, overall and coverage
are rounded to one decimal with **round-half-even** only when producing the output.
Overall uses the exact family values rather than their rounded displays. Grade uses
the displayed overall, so an exact 89.95 rounds to 90.0 and receives raw grade A.

For example, applicable/failed weights of safety 30/5, behavior 25/2, schema 18/1,
protocol 12/0 and operability 6/1 produce family displays 83.3, 92.0, 94.4, 100.0 and
83.3. Their exact weighted average rounds to **90.2** (raw A). One eligible high
finding caps this grade at **B**.

## Coverage

Coverage is a **percentage from 0 to 100**:

```text
100 × applicable catalog weight / whole supplied catalog weight
```

Both sides include only checks supporting the target transport and eligible for the
selected scoring profile, with info and LLM weight zero. A result from another transport
cannot affect scoring or caps. Era-specific checks remain in the denominator even if
the server's era cannot exercise them. Mode exclusions, skips, errors and missing rows
also leave the denominator intact, preventing unrun checks from inflating coverage.

The scan uses the entire currently registered catalog. This is coverage of that catalog,
not a claim that every planned check or every possible server behavior was exercised.
A clean reference server can receive A with partial coverage. Treat grade and coverage
as separate measurements; a high grade with low coverage offers limited evidence.

## Grades and caps

Raw grades are A at 90 or above, B at 80, C at 70, D at 60 and F below 60.
An actual critical finding caps the grade at D; a high finding caps it at B.
Caps never raise an already lower grade and never change the numeric overall.

A cap requires a finding attached to an eligible weighted FAIL result, with check ID
and family matching the catalog entry. Info observations, zero-weight checks,
PASS/ERROR/NA/SKIPPED evidence and unrelated findings cannot trigger caps.
`caps_applied` records triggered rules in fixed order:
`critical_instance_caps_at_D`, then `high_instance_caps_at_B`. These rules are recorded
even when the raw grade is already below their ceiling. No-score results have no caps.

## Disclosure profiles and report compatibility

`full` is the default. `public-interim` uniformly excludes all checks whose
`CheckMeta.disclosure` is `private`, for every server, whether they passed, failed,
errored or were not run. They contribute nothing to score, coverage numerator or
denominator, or caps. This applies automatically to future checks carrying that metadata.
Neither finding counts nor instance severities from an excluded check can affect the score.
Interim caps also ignore private-disclosure findings attached to otherwise public checks;
full-profile caps retain those findings.

**Computing an interim score does not make a report safe to publish.** Results and
findings remain in the report. Embargo-aware removal and publishing belong to the
publishing workflow (T50).

The API accepts `RunConfig(scoring_profile="public-interim", ...)` for future callers;
the CLI continues to select `full` without adding a publishing flag. Reports record
`scoring_profile` explicitly. JSON round-tripping retains it, and older reports missing
this field default to `full`.

`schema_version` remains `1.0`; the exported report schema adds this defaulted field
and bounds score percentages/weights. Pre-scoring reports contained null grades and a
placeholder coverage fraction. Regenerate those reports to obtain scored coverage in
percent; do not interpret an old fraction as a current percentage or a null as 100.

## Console and thresholds

Completed scans show grade (or `ungraded`), overall, coverage with `%`, and caps.
The summary uses the existing console sanitization and Rich markup escaping.

`--min-score` accepts only finite numbers from 0 through 100, validated before launching
the target. It compares against the reported, rounded overall and works alongside
`--fail-on`: either failed threshold produces exit 1. A capped grade does not change the
numeric score threshold. Equality passes. A null score fails **every requested minimum,
including 0**; without a requested minimum, a null score alone does not fail the run.

Existing failure precedence is retained: usage/configuration errors exit 2, target
unavailability exits 3, internal errors exit 4 and sandbox unavailability exits 5.
A score threshold does not replace these errors. `--fail-on` still uses findings in the
full report; selecting an API scoring profile does not redact findings or change this
separate finding threshold.
