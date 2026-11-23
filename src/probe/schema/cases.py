"""A generated test input and its stable identity (the design's section 9, point 8)."""

from dataclasses import dataclass
from typing import Any, Literal

CaseKind = Literal["valid", "boundary", "malformed"]


def case_id(tool: str, kind: CaseKind, rule: str, index: int) -> str:
    """``<tool>:<kind>:<rule>:<index>``: reproducible from (seed, mode) and quotable in a report."""
    return f"{tool}:{kind}:{rule}:{index}"


@dataclass(frozen=True, slots=True)
class Case:
    tool: str
    kind: CaseKind
    rule: str  # what produced it, e.g. "minimal", "example", "hypothesis", "minLength-1"
    index: int  # position among the cases of this tool, kind and rule
    arguments: (
        Any  # the tools/call ``arguments`` value (usually an object; malformed ones may not be)
    )

    @property
    def id(self) -> str:
        return case_id(self.tool, self.kind, self.rule, self.index)
