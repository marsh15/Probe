from probe.report.text import md_text


def test_hostile_markdown_cannot_mention_or_autolink():
    text = md_text("@org/team https://evil.example www.evil.example user@evil.example")
    assert "@" not in text
    assert "https://evil.example" not in text
    assert "www.evil.example" not in text
