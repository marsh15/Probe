"""A deterministic judge for tests: fills missing required fields with minimal valid values."""

from typing import Any

from probe.engine.outcomes import ToolInfo
from probe.llm.judge import JudgeResult

_MINIMAL: dict[str, Any] = {
    "string": "x",
    "integer": 1,
    "number": 1,
    "boolean": True,
    "array": [],
    "object": {},
}


def minimal_value(schema: Any) -> Any:
    if not isinstance(schema, dict):
        return "x"
    if "const" in schema:
        return schema["const"]
    if isinstance(schema.get("enum"), list) and schema["enum"]:
        return schema["enum"][0]
    kind = schema.get("type")
    kind = next((k for k in kind if k != "null"), "string") if isinstance(kind, list) else kind
    value = _MINIMAL.get(kind, "x") if isinstance(kind, str) else "x"
    if kind == "integer" and isinstance(schema.get("minimum"), int):
        value = max(value, schema["minimum"])
    return value


class FakeJudge:
    """Repairs a call only when it can see what is wrong.

    With the server's error text it fills every missing required field; without it, it can
    only repeat the failed arguments, so it models a judge that gains from good error messages.
    """

    model = "fake-judge"

    def __init__(self, *, fail_on: set[str] | None = None) -> None:
        self.calls: list[tuple[str, bool]] = []
        self._fail_on = fail_on or set()

    async def propose_fix(
        self, tool: ToolInfo, failed_args: dict[str, Any], error_text: str | None
    ) -> JudgeResult:
        self.calls.append((tool.name, error_text is not None))
        if tool.name in self._fail_on:
            return JudgeResult(None, "gave up", cached=False, cost_usd=0.0)
        if error_text is None or not error_text.strip() or error_text.strip() == "Error":
            return JudgeResult(dict(failed_args), "unchanged", cached=False, cost_usd=0.0)
        properties = tool.input_schema.get("properties")
        properties = properties if isinstance(properties, dict) else {}
        required = tool.input_schema.get("required")
        fixed = dict(failed_args)
        for name in required if isinstance(required, list) else []:
            if name not in fixed or fixed[name] is None:
                fixed[name] = minimal_value(properties.get(name))
        return JudgeResult(fixed, "filled required fields", cached=False, cost_usd=0.0)
