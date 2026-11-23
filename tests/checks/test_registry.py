"""Registering checks, run order, and loading plugins from entry points."""

from collections.abc import Iterable
from typing import Any

import pytest

from probe.checks import registry as registry_module
from probe.checks.base import Check, CheckOutcome
from probe.checks.registry import Registry, RegistryError
from probe.engine.outcomes import Family
from tests.checks.helpers import make_meta


def check_class(check_id: str, **meta: Any) -> type[Check]:
    class Dummy(Check):
        async def run(self, ctx: Any) -> CheckOutcome:
            return CheckOutcome()

    Dummy.meta = make_meta(check_id, **meta)
    return Dummy


def test_register_and_get() -> None:
    registry = Registry()
    cls = registry.register(check_class("protocol.a"))
    assert registry.get("protocol.a") is cls
    assert "protocol.a" in registry
    assert len(registry) == 1


def test_register_works_as_a_decorator() -> None:
    registry = Registry()

    @registry.register
    class Mine(Check):
        meta = make_meta("schema.mine")

        async def run(self, ctx: Any) -> CheckOutcome:
            return CheckOutcome()

    assert registry.get("schema.mine") is Mine


def test_duplicate_ids_are_refused_but_reregistering_the_same_class_is_fine() -> None:
    registry = Registry()
    cls = registry.register(check_class("protocol.a"))
    registry.register(cls)
    with pytest.raises(RegistryError, match="already registered"):
        registry.register(check_class("protocol.a"))


@pytest.mark.parametrize("bad", ["protocol", "Protocol.a", "protocol.", "protocol.A", "a b.c"])
def test_malformed_ids_are_refused(bad: str) -> None:
    cls = check_class("protocol.ok")
    cls.meta = cls.meta.model_copy(update={"id": bad})
    with pytest.raises(RegistryError, match="must look like"):
        Registry().register(cls)


def test_id_prefix_must_match_the_family() -> None:
    cls = check_class("protocol.ok")
    cls.meta = cls.meta.model_copy(update={"family": Family.SAFETY})
    with pytest.raises(RegistryError):
        Registry().register(cls)


def test_multi_segment_ids_such_as_delegated_scenarios_are_allowed() -> None:
    Registry().register(check_class("protocol.official.tools_list"))


def test_a_check_without_meta_is_refused() -> None:
    class NoMeta(Check):
        async def run(self, ctx: Any) -> CheckOutcome:
            return CheckOutcome()

    with pytest.raises(RegistryError, match="no meta"):
        Registry().register(NoMeta)


def test_unknown_id_lookup() -> None:
    with pytest.raises(KeyError, match="no check"):
        Registry().get("protocol.nope")


def test_iteration_is_phase_order_then_id_regardless_of_registration_order() -> None:
    registry = Registry()
    for check_id, phase in [
        ("safety.z", "active.adversarial"),
        ("protocol.b", "static"),
        ("behavior.stress", "active.stress"),
        ("protocol.a", "static"),
        ("operability.post", "post"),
        ("behavior.passive", "passive"),
        ("behavior.safe", "active.safe"),
        ("behavior.write", "active.write"),
    ]:
        registry.register(check_class(check_id, phase=phase))
    assert [c.meta.id for c in registry] == [
        "protocol.a",
        "protocol.b",
        "behavior.safe",
        "behavior.write",
        "safety.z",
        "behavior.stress",
        "behavior.passive",
        "operability.post",
    ]


class FakeEntryPoint:
    def __init__(self, name: str, target: Any = None, error: Exception | None = None) -> None:
        self.name, self._target, self._error = name, target, error

    def load(self) -> Any:
        if self._error is not None:
            raise self._error
        return self._target


def patch_entry_points(monkeypatch: pytest.MonkeyPatch, points: Iterable[FakeEntryPoint]) -> None:
    seen: list[str] = []

    def fake(*, group: str) -> list[FakeEntryPoint]:
        seen.append(group)
        return list(points)

    monkeypatch.setattr(registry_module, "entry_points", fake)
    patch_entry_points.groups = seen  # type: ignore[attr-defined]


def test_entry_points_can_name_a_check_class(monkeypatch: pytest.MonkeyPatch) -> None:
    plugin = check_class("protocol.from_plugin")
    patch_entry_points(monkeypatch, [FakeEntryPoint("p", plugin)])
    registry = Registry()
    registry.load_entry_points()
    assert "protocol.from_plugin" in registry
    assert patch_entry_points.groups == ["probe.checks"]  # type: ignore[attr-defined]


def test_entry_points_can_be_modules_that_register_on_import(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    registry = Registry()

    def importing_module() -> object:
        registry.register(check_class("schema.side_effect"))
        return object()  # what a module looks like to load(): not a Check subclass

    class ModulePoint(FakeEntryPoint):
        def load(self) -> Any:
            return importing_module()

    patch_entry_points(monkeypatch, [ModulePoint("m")])
    registry.load_entry_points()
    assert "schema.side_effect" in registry


def test_a_broken_plugin_is_recorded_and_does_not_stop_the_others(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    good = check_class("protocol.good")
    clash = check_class("protocol.good")  # same id as `good`
    patch_entry_points(
        monkeypatch,
        [
            FakeEntryPoint("boom", error=ImportError("no module named x")),
            FakeEntryPoint("good", good),
            FakeEntryPoint("clash", clash),
        ],
    )
    registry = Registry()
    registry.load_entry_points()
    assert "protocol.good" in registry
    assert [name for name, _ in registry.plugin_errors] == ["boom", "clash"]
    assert "ImportError" in registry.plugin_errors[0][1]
