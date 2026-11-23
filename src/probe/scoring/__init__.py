"""Scoring v1.0: deterministic, catalog-weighted scores for one target transport.

``compute_score(catalog, results, transport, scoring_profile="full")`` returns a report Score.
Supply the whole catalog, including checks that were not run. PASS and FAIL are applicable;
ERROR, NA, SKIPPED and absent rows do not add applicable weight. A FAIL counts once per check,
regardless of finding count. Catalog severity weights are critical=10, high=5, medium=2, low=1,
info=0. Checks requiring ``llm`` have zero weight, including for coverage and caps.

Family score = 100 * (1 - failed_weight / applicable_weight), or null at zero applicable weight.
Headline weights are safety=30, behavior=25, schema=20, protocol=15, operability=10, renormalized
across non-null families. Arithmetic uses exact fractions; family displays, overall and coverage
are rounded only at the output boundary to one decimal with round-half-even. Overall uses exact
family values, not their rounded displays. Grade uses the displayed overall: A>=90, B>=80,
C>=70, D>=60, F otherwise. No weighted applicable checks means overall/grade null and coverage 0.

Coverage is a percentage (0..100): applicable catalog weight divided by the whole supplied
catalog's weight for the target transport. Era, mode, skips and missing rows do not reduce the
denominator. Both numerator and denominator use the same transport and disclosure filters.

Caps use actual high/critical findings attached to an eligible FAIL result, whose check id and
family match its catalog metadata. Critical caps at D, high at B, without raising a lower grade.
Info and LLM checks and nonjudged/unrelated evidence cannot cap. ``caps_applied`` records triggered
rules, critical then high, even when the raw grade is already lower than the cap.

``full`` keeps all tiers. ``public-interim`` excludes every private-tier check uniformly, using
CheckMeta.disclosure, from weights, coverage and caps regardless of its result. This calculation
does not remove or publish report findings; embargo-safe publishing is a separate responsibility.
Duplicate catalog ids/result rows, unknown result ids and invalid transport/profile values raise
ValueError rather than producing misleading coverage. Inputs are never mutated.
"""

from probe.scoring.compute import compute_score

__all__ = ["compute_score"]
