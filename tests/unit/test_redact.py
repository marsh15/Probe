"""Redaction keeps real credentials out of traces and reports; fixture fakes stay as evidence."""

from probe.util.redact import REDACTED, Redactor, redact_headers


def test_sensitive_headers_are_redacted_case_insensitively() -> None:
    headers = {
        "Authorization": "Bearer abc",
        "cookie": "sid=1",
        "Set-Cookie": "sid=2",
        "PROXY-AUTHORIZATION": "Basic x",
        "X-Api-Key": "k",
        "Content-Type": "application/json",
    }
    redacted = redact_headers(headers)
    assert redacted == {
        "Authorization": REDACTED,
        "cookie": REDACTED,
        "Set-Cookie": REDACTED,
        "PROXY-AUTHORIZATION": REDACTED,
        "X-Api-Key": REDACTED,
        "Content-Type": "application/json",
    }


def test_redact_headers_does_not_mutate_its_input() -> None:
    headers = {"Authorization": "Bearer abc"}
    redact_headers(headers)
    assert headers == {"Authorization": "Bearer abc"}


def test_secret_values_are_replaced_in_text() -> None:
    redactor = Redactor(["s3cr3t-token"])
    assert redactor.redact_text("token=s3cr3t-token!") == f"token={REDACTED}!"


def test_every_occurrence_is_replaced() -> None:
    redactor = Redactor(["s3cr3t"])
    assert redactor.redact_text("s3cr3t and s3cr3t") == f"{REDACTED} and {REDACTED}"


def test_longer_secret_wins_when_one_contains_another() -> None:
    redactor = Redactor(["abcd1234", "abcd1234xyz"])
    assert redactor.redact_text("v=abcd1234xyz") == f"v={REDACTED}"


def test_very_short_values_are_ignored_to_avoid_shredding_everything() -> None:
    redactor = Redactor(["ab", "", "x"])
    assert redactor.redact_text("abx ab") == "abx ab"


def test_unlisted_values_such_as_fixture_fake_secrets_are_kept() -> None:
    redactor = Redactor(["real-secret-value"])
    assert redactor.redact_text("FAKE_KEY_canary_1234") == "FAKE_KEY_canary_1234"


def test_redact_json_walks_nested_structures() -> None:
    redactor = Redactor(["hunter2!"])
    data = {"a": ["x hunter2! y", {"b": "hunter2!"}], "n": 5, "ok": None, "hunter2!": "key kept"}
    assert redactor.redact_json(data) == {
        "a": [f"x {REDACTED} y", {"b": REDACTED}],
        "n": 5,
        "ok": None,
        "hunter2!": "key kept",
    }


def test_redact_json_does_not_mutate_its_input() -> None:
    redactor = Redactor(["hunter2!"])
    data = {"a": ["hunter2!"]}
    redactor.redact_json(data)
    assert data == {"a": ["hunter2!"]}


def test_redactor_with_no_secrets_is_a_no_op() -> None:
    assert Redactor([]).redact_text("anything") == "anything"
