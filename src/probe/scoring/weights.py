"""Headline family weights; severity weights are shared with the engine's result vocabulary."""

from probe.engine.outcomes import SEVERITY_WEIGHT, CheckMeta, Family

FAMILY_WEIGHT: dict[Family, int] = {
    Family.SAFETY: 30,
    Family.BEHAVIOR: 25,
    Family.SCHEMA: 20,
    Family.PROTOCOL: 15,
    Family.OPERABILITY: 10,
}


def check_weight(meta: CheckMeta) -> int:
    """LLM evidence is supplemental; it cannot affect headline scoring or coverage."""
    return 0 if "llm" in meta.requires else SEVERITY_WEIGHT[meta.severity]
