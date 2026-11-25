"""Build the judge a scan asked for (``--llm``), or explain why it cannot be built."""

import os
from collections.abc import Mapping
from pathlib import Path

from probe.llm.anthropic_judge import AnthropicJudge
from probe.llm.budget import LlmBudget
from probe.llm.cache import JudgeCache
from probe.llm.judge import Judge
from probe.util.redact import Redactor

KEY_VARIABLE = "ANTHROPIC_API_KEY"


class LlmUnavailable(Exception):
    """``--llm`` was asked for but cannot be honored (exit code 2)."""


def make_judge(
    *,
    budget_usd: float,
    cache_dir: Path | None,
    environ: Mapping[str, str] | None = None,
    redactor: Redactor | None = None,
) -> Judge:
    env = os.environ if environ is None else environ
    key = env.get(KEY_VARIABLE)
    if not key:
        raise LlmUnavailable(f"--llm needs {KEY_VARIABLE} in the environment")
    if budget_usd < 0:
        raise LlmUnavailable("--llm-budget-usd cannot be negative")
    try:
        import anthropic
    except ImportError as exc:
        raise LlmUnavailable(
            "--llm needs the anthropic package: pip install 'probe-mcp[llm]'"
        ) from exc
    client = anthropic.AsyncAnthropic(api_key=key)
    return AnthropicJudge(
        client, cache=JudgeCache(cache_dir), budget=LlmBudget(budget_usd), redactor=redactor
    )
