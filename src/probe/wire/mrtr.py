"""Multi round-trip requests: answer a server's ``input_required`` and retry.

A modern server may answer a request with ``resultType: "input_required"`` and a set of
``inputRequests`` (things it needs from the client) and/or an opaque ``requestState``. The
client retries the original request with a new id, adding ``inputResponses`` keyed like the
requests and echoing ``requestState``. This module does that loop for any sender, records every
round, and notes each way the server's request objects break the rules, so a check can judge them.
"""

import re
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from probe.wire.jsonrpc import ErrorResponse, Response, ResultResponse

MAX_ROUNDS = 5
INPUT_METHODS = ("elicitation/create", "sampling/createMessage", "roots/list")
CANNED_SAMPLING = {
    "role": "assistant",
    "content": {"type": "text", "text": "probe-sampled-response"},
    "model": "probe-fake",
    "stopReason": "endTurn",
}
_PRIMITIVES = frozenset({"string", "number", "integer", "boolean"})

# Sends one request (a fresh id each time) and returns the response.
Sender = Callable[[str, dict[str, Any]], Awaitable[Response]]


@dataclass(frozen=True, slots=True)
class ElicitationRule:
    """One profile answer: when it applies, and what to answer."""

    key: str | None
    message_regex: str | None
    action: str
    content: dict[str, Any] | None = None

    def matches(self, key: str, message: str) -> bool:
        if self.key is not None and self.key != key:
            return False
        return self.message_regex is None or re.search(self.message_regex, message) is not None


@dataclass(slots=True)
class InputPolicy:
    """How to answer what the server asks for."""

    rules: Sequence[ElicitationRule] = ()
    roots: Sequence[str] = ("file:///data/allowed",)
    # Overrides the answer to an elicitation (e.g. accept with content built from the schema).
    elicit: Callable[[str, dict[str, Any]], dict[str, Any] | None] | None = None

    def answer(self, key: str, request: Mapping[str, Any]) -> dict[str, Any]:
        method = request.get("method")
        params = request.get("params")
        params = params if isinstance(params, Mapping) else {}
        if method == "elicitation/create":
            if self.elicit is not None:
                custom = self.elicit(key, dict(params))
                if custom is not None:
                    return custom
            message = str(params.get("message", ""))
            for rule in self.rules:
                if rule.matches(key, message):
                    answer: dict[str, Any] = {"action": rule.action}
                    if rule.content is not None:
                        answer["content"] = rule.content
                    return answer
            return {"action": "decline"}
        if method == "sampling/createMessage":
            return dict(CANNED_SAMPLING)
        if method == "roots/list":
            return {"roots": [{"uri": uri, "name": uri.rsplit("/", 1)[-1]} for uri in self.roots]}
        return {}


@dataclass(slots=True)
class Round:
    index: int
    params: dict[str, Any]
    response: Response | None = None


@dataclass(slots=True)
class MrtrRun:
    rounds: list[Round] = field(default_factory=list)
    violations: list[str] = field(default_factory=list)
    exceeded: bool = False  # still wanting input after ``max_rounds`` retries

    @property
    def final(self) -> Response | None:
        return self.rounds[-1].response if self.rounds else None

    @property
    def input_required(self) -> bool:
        """Did the server ask for input at least once?"""
        return any(is_input_required(r.response) for r in self.rounds)

    @property
    def completed(self) -> bool:
        final = self.final
        return isinstance(final, ResultResponse) and not is_input_required(final)


def is_input_required(response: Response | None) -> bool:
    return (
        isinstance(response, ResultResponse)
        and isinstance(response.result, dict)
        and response.result.get("resultType") == "input_required"
    )


def input_request_problems(result: Mapping[str, Any]) -> list[str]:
    """Everything wrong with one ``InputRequiredResult``, in plain words."""
    problems: list[str] = []
    requests = result.get("inputRequests")
    state = result.get("requestState")
    if requests is None and state is None:
        problems.append("input_required result has neither inputRequests nor requestState")
    if state is not None and not isinstance(state, str):
        problems.append("requestState is not a string")
    if requests is None:
        return problems
    if not isinstance(requests, dict):
        return [*problems, "inputRequests is not an object"]
    for key, request in requests.items():
        problems.extend(_request_problems(str(key), request))
    return problems


def _request_problems(key: str, request: Any) -> list[str]:
    if not isinstance(request, dict):
        return [f"inputRequests[{key!r}] is not an object"]
    method = request.get("method")
    if method is None:
        return [f"inputRequests[{key!r}] has no method"]
    if method not in INPUT_METHODS:
        return [f"inputRequests[{key!r}] has unknown method {method!r}"]
    params = request.get("params")
    if method == "elicitation/create":
        if not isinstance(params, dict):
            return [f"inputRequests[{key!r}] has no params"]
        return _elicitation_problems(key, params)
    if params is not None and not isinstance(params, dict):
        return [f"inputRequests[{key!r}].params is not an object"]
    return []


def _elicitation_problems(key: str, params: dict[str, Any]) -> list[str]:
    problems: list[str] = []
    if not isinstance(params.get("message"), str):
        problems.append(f"inputRequests[{key!r}] elicitation has no message")
    schema = params.get("requestedSchema")
    if params.get("mode") == "url":
        return problems
    if not isinstance(schema, dict):
        return [*problems, f"inputRequests[{key!r}] elicitation has no requestedSchema"]
    if schema.get("type") != "object":
        problems.append(f"inputRequests[{key!r}] requestedSchema is not an object schema")
    properties = schema.get("properties")
    if not isinstance(properties, dict):
        problems.append(f"inputRequests[{key!r}] requestedSchema has no properties")
        return problems
    for name, spec in properties.items():
        kind = spec.get("type") if isinstance(spec, dict) else None
        if kind not in _PRIMITIVES:
            problems.append(f"inputRequests[{key!r}] property {name!r} is not a primitive type")
    return problems


async def call_with_mrtr(
    send: Sender,
    method: str,
    params: Mapping[str, Any],
    policy: InputPolicy | None = None,
    *,
    max_rounds: int = MAX_ROUNDS,
) -> MrtrRun:
    """Send ``method``; while the server wants input, answer and retry (new id each time).

    ``max_rounds`` counts the retries. A server that is still asking after that many is cut off
    and the run is marked ``exceeded``.
    """
    policy = policy or InputPolicy()
    run = MrtrRun()
    current = dict(params)
    for index in range(max_rounds + 1):
        round_ = Round(index, current)
        run.rounds.append(round_)
        round_.response = await send(method, current)
        response = round_.response
        if isinstance(response, ErrorResponse) or not is_input_required(response):
            return run
        result = response.result if isinstance(response, ResultResponse) else None
        if not isinstance(result, dict):  # is_input_required already ruled this out
            return run
        run.violations.extend(f"round {index}: {p}" for p in input_request_problems(result))
        if index == max_rounds:
            run.exceeded = True
            return run
        current = retry_params(params, result, policy)
    return run


def retry_params(
    original: Mapping[str, Any], result: Mapping[str, Any], policy: InputPolicy
) -> dict[str, Any]:
    retry = dict(original)
    requests = result.get("inputRequests")
    if isinstance(requests, dict):
        retry["inputResponses"] = {
            str(key): policy.answer(str(key), request)
            for key, request in requests.items()
            if isinstance(request, dict)
        }
    if "requestState" in result:
        retry["requestState"] = result["requestState"]
    return retry
