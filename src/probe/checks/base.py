"""The contract every check implements, and the value a check hands back to the engine."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, ClassVar

from probe.engine.outcomes import (
    CheckMeta,
    Evidence,
    Finding,
    ReproCase,
    Severity,
    Status,
)
from probe.util.hashing import finding_id

if TYPE_CHECKING:
    from probe.checks.context import ScanContext

# Findings at or above this severity make a check FAIL; INFO ones are observations only.
FAILING = frozenset({Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW})


@dataclass(frozen=True, slots=True)
class Applicability:
    ok: bool
    reason: str = ""

    @classmethod
    def yes(cls) -> "Applicability":
        return cls(True)

    @classmethod
    def no(cls, reason: str) -> "Applicability":
        return cls(False, reason)


@dataclass(slots=True)
class CheckOutcome:
    """What ``run`` returns. Leave ``status`` unset to derive it from the findings.

    Derived: any finding of severity low or above means FAIL; otherwise PASS (info findings
    are observations and never fail a check). A check may state NA (e.g. no baseline call
    could be made) explicitly; stating PASS or FAIL must agree with the findings.
    """

    findings: list[Finding] = field(default_factory=list)
    status: Status | None = None
    reason: str | None = None

    @classmethod
    def na(cls, reason: str) -> "CheckOutcome":
        return cls(status=Status.NA, reason=reason)

    @classmethod
    def error(cls, reason: str) -> "CheckOutcome":
        """The check could not reach a verdict (never counted against the server)."""
        return cls(status=Status.ERROR, reason=reason)


class Check(ABC):
    meta: ClassVar[CheckMeta]
    # False for a post-phase check that only reads what the scan already recorded, so it still
    # runs after the target is declared unstable. Post checks that call the target are blocked.
    drives_target: ClassVar[bool] = True

    def applicable(self, ctx: "ScanContext") -> Applicability:
        """Check-specific applicability, after the engine's own gating by ``meta``."""
        return Applicability.yes()

    @abstractmethod
    async def run(self, ctx: "ScanContext") -> CheckOutcome: ...

    def finding(
        self,
        ctx: "ScanContext",
        *,
        severity: Severity,
        title: str,
        message: str,
        evidence: Evidence,
        repro: ReproCase,
        tool: str | None = None,
    ) -> Finding:
        """A finding for this check with a stable id (same target, tool and case: same id)."""
        meta = self.meta
        fid = finding_id(meta.id, tool, repro.case_id, ctx.config.target_identity)
        repro = repro.model_copy(update={"command": f"probe repro report.json --finding {fid}"})
        return Finding(
            finding_id=fid,
            check_id=meta.id,
            family=meta.family,
            severity=severity,
            tool=tool,
            title=title,
            message=message,
            evidence=evidence,
            repro=repro,
            disclosure=meta.disclosure,
        )
