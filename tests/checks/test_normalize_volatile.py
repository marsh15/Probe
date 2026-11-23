"""Volatile values (timestamps, ids, durations) must not make two equal results differ."""

import pytest

from probe.checks.normalize_volatile import normalize_volatile, stable_equal

NOW = 1_800_000_000.0  # seconds
NOW_MS = int(NOW * 1000)


def norm(value: object) -> object:
    return normalize_volatile(value, now=NOW)


@pytest.mark.parametrize(
    "text",
    [
        "2026-11-23T10:15:30Z",
        "2026-11-23T10:15:30.123456+05:30",
        "2026-11-23 10:15:30",
        "2026-11-23T10:15Z",
    ],
)
def test_iso_timestamps(text: str) -> None:
    assert norm(f"saved at {text} ok") == "saved at <timestamp> ok"


def test_uuids_ulids_and_long_hex_ids() -> None:
    assert norm("id 123e4567-e89b-12d3-a456-426614174000.") == "id <uuid>."
    assert norm("id 01ARZ3NDEKTSV4RRFFQ69G5FAV") == "id <ulid>"
    assert norm("sha " + "ab12cd34ef56ab78") == "sha <hex-id>"
    assert norm("sha " + "ab" * 32) == "sha <hex-id>"


def test_short_hex_and_plain_words_are_left_alone() -> None:
    assert norm("deadbeef cafe 1234567") == "deadbeef cafe 1234567"
    assert norm("abcdefabcdefabcdefabcdefg") == "abcdefabcdefabcdefabcdefg"  # not all hex


@pytest.mark.parametrize("text", ["took 15ms", "took 1.5 s", "took 20 ms.", "took 3s"])
def test_durations(text: str) -> None:
    assert norm(text) == "took <duration>" or norm(text) == "took <duration>."


def test_words_that_merely_contain_units_are_left_alone() -> None:
    assert norm("5 seconds and 2 tools and 4ms2") == "5 seconds and 2 tools and 4ms2"


def test_epoch_milliseconds_near_now_only() -> None:
    assert norm({"n": NOW_MS + 3_600_000}) == {"n": "<epoch-ms>"}
    assert norm([NOW_MS - 86_000_000]) == ["<epoch-ms>"]
    assert norm({"n": NOW_MS + 90_000_000}) == {"n": NOW_MS + 90_000_000}
    assert norm({"n": 1234}) == {"n": 1234}
    assert norm({"n": True}) == {"n": True}
    assert norm({"n": float(NOW_MS)}) == {"n": "<epoch-ms>"}


@pytest.mark.parametrize(
    "key",
    ["created_at", "updated_at", "timestamp", "time", "date", "elapsed", "duration",
     "request_id", "trace_id", "start_time", "Created_At"],
)  # fmt: skip
def test_volatile_keys_lose_their_whole_value(key: str) -> None:
    assert norm({key: {"any": ["thing", 1]}}) == {key: "<volatile>"}


@pytest.mark.parametrize("key", ["id", "title", "dated", "atlas", "runtime_note", "at"])
def test_ordinary_keys_are_kept(key: str) -> None:
    assert norm({key: "x"}) == {key: "x"}


def test_nested_structures_and_input_is_not_mutated() -> None:
    value = {"items": [{"id": 1, "created_at": "yesterday", "note": "ran 5ms"}], "n": None}
    assert norm(value) == {
        "items": [{"id": 1, "created_at": "<volatile>", "note": "ran <duration>"}],
        "n": None,
    }
    assert value["items"][0]["created_at"] == "yesterday"  # type: ignore[index]


async def test_stable_equal_passes_on_first_match_without_rerun() -> None:
    calls = 0

    async def produce() -> tuple[object, object]:
        nonlocal calls
        calls += 1
        return {"a": "took 5ms"}, {"a": "took 9ms"}

    assert await stable_equal(produce, now=NOW) is True
    assert calls == 1


async def test_stable_equal_reruns_once_and_passes_if_the_second_run_matches() -> None:
    runs = iter([({"v": 1}, {"v": 2}), ({"v": 2}, {"v": 2})])

    async def produce() -> tuple[object, object]:
        return next(runs)

    assert await stable_equal(produce, now=NOW) is True


async def test_stable_equal_fails_only_when_both_runs_mismatch() -> None:
    calls = 0

    async def produce() -> tuple[object, object]:
        nonlocal calls
        calls += 1
        return {"v": 1}, {"v": 2}

    assert await stable_equal(produce, now=NOW) is False
    assert calls == 2
