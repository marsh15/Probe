"""The real judge: Claude Haiku with forced tool use, temperature 0, cached on disk.

Needs the ``anthropic`` package (``pip install probe-mcp[llm]``) and ``ANTHROPIC_API_KEY``.
What it sends to Anthropic: the tool's name, description and input schema, the arguments of a
failed call and (in one arm of the experiment) the server's error message.
"""

import json
from typing import Any

from probe.engine.outcomes import ToolInfo
from probe.llm.budget import LlmBudget, cost_usd, estimate_usd
from probe.llm.cache import JudgeCache, cache_key
from probe.llm.judge import (
    SYSTEM_PROMPT,
    TOOL_NAME,
    JudgeError,
    JudgeResult,
    build_prompt,
    render_user_message,
)

MODEL = "claude-haiku-4-5-20251001"
MAX_TOKENS = 1024
_TOOL = {
    "name": TOOL_NAME,
    "description": "Submit the corrected arguments for the tool call.",
    "input_schema": {
        "type": "object",
        "properties": {"arguments": {"type": "object"}},
        "required": ["arguments"],
    },
}


class AnthropicJudge:
    def __init__(
        self,
        client: Any,
        *,
        cache: JudgeCache,
        budget: LlmBudget,
        model: str = MODEL,
    ) -> None:
        self._client = client
        self._cache = cache
        self.budget = budget
        self.model = model

    async def propose_fix(
        self, tool: ToolInfo, failed_args: dict[str, Any], error_text: str | None
    ) -> JudgeResult:
        prompt = build_prompt(tool, failed_args, error_text)
        key = cache_key(self.model, prompt)
        hit = self._cache.get(key)
        if hit is not None and "raw" in hit:
            cached_args = hit.get("args")
            return JudgeResult(
                cached_args if isinstance(cached_args, dict) else None,
                str(hit["raw"]),
                True,
                0.0,
                key,
            )
        message = render_user_message(prompt)
        self.budget.reserve(estimate_usd(len(message) + len(SYSTEM_PROMPT), MAX_TOKENS))
        try:
            response = await self._client.messages.create(
                model=self.model,
                max_tokens=MAX_TOKENS,
                temperature=0,
                system=SYSTEM_PROMPT,
                tools=[_TOOL],
                tool_choice={"type": "tool", "name": TOOL_NAME},
                messages=[{"role": "user", "content": message}],
            )
        except Exception as exc:
            raise JudgeError(f"{type(exc).__name__} from the Anthropic API") from exc
        usage = getattr(response, "usage", None)
        spent = cost_usd(
            int(getattr(usage, "input_tokens", 0) or 0),
            int(getattr(usage, "output_tokens", 0) or 0),
        )
        self.budget.charge(spent)
        args: dict[str, Any] | None = None
        raw = ""
        for block in getattr(response, "content", []):
            if getattr(block, "type", None) == "tool_use" and block.name == TOOL_NAME:
                raw = json.dumps(block.input, sort_keys=True, default=str)
                proposed = block.input.get("arguments") if isinstance(block.input, dict) else None
                args = proposed if isinstance(proposed, dict) else None
                break
        self._cache.put(key, {"args": args, "raw": raw, "model": self.model})
        return JudgeResult(args, raw, False, spent, key)
