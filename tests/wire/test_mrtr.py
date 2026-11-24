"""The MRTR loop against a scripted sender."""

from typing import Any

from probe.wire.jsonrpc import ErrorObject, ErrorResponse, Response, ResultResponse
from probe.wire.mrtr import ElicitationRule, InputPolicy, call_with_mrtr, input_request_problems

ASK = {
    "resultType": "input_required",
    "requestState": "state-1",
    "inputRequests": {
        "confirm": {
            "method": "elicitation/create",
            "params": {
                "message": "Delete everything?",
                "requestedSchema": {
                    "type": "object",
                    "properties": {"confirm": {"type": "boolean"}},
                },
            },
        }
    },
}


class Script:
    def __init__(self, *replies: Response) -> None:
        self.replies = list(replies)
        self.sent: list[tuple[str, dict[str, Any]]] = []

    async def __call__(self, method: str, params: dict[str, Any]) -> Response:
        self.sent.append((method, params))
        return self.replies.pop(0)


def done() -> Response:
    return ResultResponse(9, {"resultType": "complete", "content": []})


async def test_a_call_that_needs_no_input_is_one_round() -> None:
    send = Script(done())
    run = await call_with_mrtr(send, "tools/call", {"name": "t"})
    assert len(run.rounds) == 1 and run.completed and not run.input_required


async def test_the_retry_carries_answers_and_the_echoed_state() -> None:
    send = Script(ResultResponse(1, ASK), done())
    policy = InputPolicy([ElicitationRule("confirm", None, "accept", {"confirm": True})])
    run = await call_with_mrtr(send, "tools/call", {"name": "t", "arguments": {"a": 1}}, policy)
    assert run.completed and run.input_required and not run.violations
    retry = send.sent[1][1]
    assert retry["name"] == "t" and retry["arguments"] == {"a": 1}
    assert retry["requestState"] == "state-1"
    assert retry["inputResponses"] == {
        "confirm": {"action": "accept", "content": {"confirm": True}}
    }


async def test_unmatched_elicitations_are_declined() -> None:
    send = Script(ResultResponse(1, ASK), done())
    await call_with_mrtr(send, "tools/call", {"name": "t"})
    assert send.sent[1][1]["inputResponses"]["confirm"] == {"action": "decline"}


async def test_a_server_that_never_stops_asking_is_cut_off() -> None:
    send = Script(*(ResultResponse(i, ASK) for i in range(10)))
    run = await call_with_mrtr(send, "tools/call", {"name": "t"}, max_rounds=3)
    assert run.exceeded and len(run.rounds) == 4 and not run.completed


async def test_an_error_ends_the_loop() -> None:
    send = Script(ErrorResponse(1, ErrorObject(-32602, "bad")))
    run = await call_with_mrtr(send, "tools/call", {"name": "t"})
    assert len(run.rounds) == 1 and not run.completed


def test_a_request_with_no_method_is_malformed() -> None:
    bad = {"resultType": "input_required", "inputRequests": {"x": {"params": {}}}}
    assert any("no method" in p for p in input_request_problems(bad))


def test_an_unknown_method_and_a_bad_schema_are_reported() -> None:
    bad = {
        "resultType": "input_required",
        "inputRequests": {
            "a": {"method": "tools/call", "params": {}},
            "b": {
                "method": "elicitation/create",
                "params": {
                    "message": "m",
                    "requestedSchema": {"type": "object", "properties": {"x": {"type": "object"}}},
                },
            },
        },
    }
    problems = input_request_problems(bad)
    assert any("unknown method" in p for p in problems)
    assert any("not a primitive" in p for p in problems)


def test_a_result_with_nothing_to_act_on_is_malformed() -> None:
    assert input_request_problems({"resultType": "input_required"})


def test_well_formed_requests_have_no_problems() -> None:
    assert input_request_problems(ASK) == []
