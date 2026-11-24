"""The optional LLM judge behind ``--llm``."""

from probe.llm.budget import LlmBudget, LlmBudgetExhausted
from probe.llm.cache import JudgeCache
from probe.llm.fake_judge import FakeJudge
from probe.llm.judge import Judge, JudgeError, JudgeResult

__all__ = [
    "FakeJudge",
    "Judge",
    "JudgeCache",
    "JudgeError",
    "JudgeResult",
    "LlmBudget",
    "LlmBudgetExhausted",
]
