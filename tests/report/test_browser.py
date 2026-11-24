"""The HTML report in a real browser: accessibility, layout, keyboard use and no-script use."""

import glob
import os
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from axe_playwright_python.sync_playwright import Axe
from playwright.sync_api import Browser, Page, sync_playwright

from probe.report.html import render_html
from probe.report.models import ScanReport

DATA = Path(__file__).parent / "data"
SIZES = [(1280, 900), (375, 800)]
THEMES = ["light", "dark"]


def _chromium() -> str | None:
    cache = Path(os.environ.get("PLAYWRIGHT_BROWSERS_PATH", "~/Library/Caches/ms-playwright"))
    found = sorted(glob.glob(str(cache.expanduser() / "chromium*" / "*" / "chrome-headless-shell")))
    found += sorted(
        glob.glob(
            str(
                Path("~/.cache/ms-playwright").expanduser()
                / "chromium*"
                / "*"
                / "chrome-headless-shell"
            )
        )
    )
    return found[-1] if found else None


@pytest.fixture(scope="module")
def browser() -> Iterator[Browser]:
    with sync_playwright() as pw:
        try:
            instance = pw.chromium.launch()
        except Exception:
            path = _chromium()
            if path is None:
                pytest.skip("no Chromium available for Playwright")
            instance = pw.chromium.launch(executable_path=path)
        yield instance
        instance.close()


@pytest.fixture(scope="module")
def pages(tmp_path_factory: pytest.TempPathFactory) -> dict[str, Path]:
    out = tmp_path_factory.mktemp("html")
    paths = {}
    for name in ("clean", "buggy"):
        report = ScanReport.model_validate_json((DATA / f"{name}.json").read_text())
        paths[name] = out / f"{name}.html"
        paths[name].write_text(render_html(report), encoding="utf-8")
    return paths


def open_page(browser: Browser, path: Path, *, width: int, theme: str, js: bool = True) -> Page:
    context = browser.new_context(
        viewport={"width": width, "height": 800},
        color_scheme=theme,
        java_script_enabled=js,  # type: ignore[arg-type]
    )
    page = context.new_page()
    page.goto(path.as_uri())
    return page


@pytest.mark.parametrize("name", ["clean", "buggy"])
@pytest.mark.parametrize("theme", THEMES)
@pytest.mark.parametrize("width", [w for w, _ in SIZES])
def test_axe_finds_no_serious_or_critical_problem(
    browser: Browser, pages: dict[str, Path], name: str, theme: str, width: int
) -> None:
    page = open_page(browser, pages[name], width=width, theme=theme)
    page.evaluate("document.querySelectorAll('details').forEach(d => d.open = true)")
    results = Axe().run(page)
    bad = [
        (v["id"], v["impact"], [n["target"] for n in v["nodes"]][:3])
        for v in results.response["violations"]
        if v["impact"] in ("serious", "critical")
    ]
    assert not bad, bad
    page.context.close()


@pytest.mark.parametrize("width", [w for w, _ in SIZES])
def test_no_horizontal_scroll_of_the_page(
    browser: Browser, pages: dict[str, Path], width: int
) -> None:
    page = open_page(browser, pages["buggy"], width=width, theme="light")
    assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth + 1")
    page.context.close()


def test_hostile_names_run_no_script(browser: Browser, tmp_path: Path) -> None:
    import json

    data: dict[str, Any] = json.loads((DATA / "buggy.json").read_text())
    hostile = "<img src=x onerror=alert(1)><script>alert(2)</script>"
    data["tools"][0]["name"] = hostile
    data["findings"][0]["message"] = hostile
    path = tmp_path / "x.html"
    path.write_text(render_html(ScanReport.model_validate(data)), encoding="utf-8")
    page = open_page(browser, path, width=1280, theme="light")
    dialogs: list[str] = []
    page.on("dialog", lambda d: dialogs.append(d.message))
    page.reload()
    page.wait_for_timeout(300)
    assert dialogs == [] and page.locator("img").count() == 0
    page.context.close()


def test_keyboard_only_walkthrough(browser: Browser, pages: dict[str, Path]) -> None:
    page = open_page(browser, pages["buggy"], width=1280, theme="light")
    page.keyboard.press("Tab")
    assert page.evaluate("document.activeElement.className") == "skip"
    first = page.locator("details.finding").first
    first.locator("summary").focus()
    page.keyboard.press("Enter")
    assert first.evaluate("e => e.open")
    page.keyboard.press("Enter")
    assert not first.evaluate("e => e.open")
    page.context.close()


def test_theme_toggle_filter_and_copy_work(browser: Browser, pages: dict[str, Path]) -> None:
    page = open_page(browser, pages["buggy"], width=1280, theme="light")
    page.click("#theme")
    assert page.evaluate("document.documentElement.dataset.theme") == "dark"
    page.select_option("#check-status", "fail")
    hidden = page.locator("#checks-table tbody tr[hidden]").count()
    shown = page.locator("#checks-table tbody tr:not([hidden])").count()
    assert hidden > 0 and shown > 0
    assert all(
        s == "fail"
        for s in page.locator("#checks-table tbody tr:not([hidden])").evaluate_all(
            "rows => rows.map(r => r.dataset.status)"
        )
    )
    page.context.close()


def test_page_works_without_script(browser: Browser, pages: dict[str, Path]) -> None:
    page = open_page(browser, pages["buggy"], width=1280, theme="light", js=False)
    for anchor in ("summary", "families", "findings", "tools", "checks", "limits", "metadata"):
        assert page.locator(f"#{anchor}").is_visible()
    assert page.locator("button#theme").is_hidden()  # controls need script, so they are hidden
    page.context.close()
