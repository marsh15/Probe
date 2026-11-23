"""Fixture values are fixed, local, and independent of ambient state."""

from probe.schema.formats import format_values


def test_url_path_email_and_datetime_values():
    assert format_values("url", {}, role="url_param") == ["http://public.probe.test/hello.txt"]
    assert format_values("path", {}, role="path_param", allowed_roots=["/data", "/work/"]) == [
        "/data/hello.txt",
        "/work/hello.txt",
    ]
    assert format_values("path", {}, role="path_param") == []
    assert format_values("mail", {"format": "email"}) == ["probe@example.test"]
    assert format_values("time", {"format": "date-time"}) == ["2026-01-01T00:00:00Z"]
    assert format_values("link", {"format": "uri"}) == ["http://public.probe.test/hello.txt"]


def test_ids_only_use_explicit_fixture_values_and_preserve_types():
    values = {"user_id": [7, "user-2"], "other": [42]}
    assert format_values("user_id", {}, id_values=values) == [7, "user-2"]
    assert format_values("missing_id", {}, id_values=values) == []
    assert format_values("other", {}, id_values=values) == []
    assert format_values("plain", {}) == []
