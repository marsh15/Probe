"""The call and wall-clock budget that keeps a scan bounded."""

import pytest

from probe.engine.budget import Budget, BudgetExhausted


class Clock:
    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now


def test_take_counts_calls_until_the_limit() -> None:
    budget = Budget(calls=3)
    budget.take()
    budget.take(2)
    assert (budget.used, budget.remaining) == (3, 0)
    with pytest.raises(BudgetExhausted, match="call budget"):
        budget.take()
    assert budget.used == 3  # a refused call is not counted


def test_a_request_larger_than_what_remains_is_refused_whole() -> None:
    budget = Budget(calls=5)
    budget.take(4)
    with pytest.raises(BudgetExhausted):
        budget.take(2)
    assert budget.remaining == 1


def test_wall_clock_deadline() -> None:
    clock = Clock()
    budget = Budget(calls=100, seconds=10, clock=clock)
    budget.take()
    clock.now = 10.5
    with pytest.raises(BudgetExhausted, match="time budget"):
        budget.take()
    assert budget.expired


def test_no_time_limit_by_default() -> None:
    clock = Clock()
    budget = Budget(calls=2, clock=clock)
    clock.now = 1e9
    budget.take()
    assert not budget.expired


@pytest.mark.parametrize("calls", [0, -1])
def test_nonpositive_call_limit_is_a_programming_error(calls: int) -> None:
    with pytest.raises(ValueError):
        Budget(calls=calls)


def test_take_rejects_nonpositive_counts() -> None:
    with pytest.raises(ValueError):
        Budget(calls=3).take(0)


def test_child_budget_draws_from_the_parent_too() -> None:
    parent = Budget(calls=5)
    child = parent.child(calls=3)
    child.take(3)
    with pytest.raises(BudgetExhausted):
        child.take()
    assert parent.used == 3
    other = parent.child(calls=10)
    other.take(2)
    with pytest.raises(BudgetExhausted):  # the parent is now empty
        other.take()
    assert parent.used == 5
