"""A dollar budget for judge calls: estimate before each call, stop when it would not fit."""

# claude-haiku-4-5: US dollars per million tokens.
INPUT_USD_PER_MTOK = 1.0
OUTPUT_USD_PER_MTOK = 5.0
_CHARS_PER_TOKEN = 3  # deliberately pessimistic, so the estimate is an upper bound


class LlmBudgetExhausted(Exception):
    """The next call would take the spend over the limit."""


def cost_usd(input_tokens: int, output_tokens: int) -> float:
    return (input_tokens * INPUT_USD_PER_MTOK + output_tokens * OUTPUT_USD_PER_MTOK) / 1_000_000


def estimate_usd(prompt_chars: int, max_output_tokens: int) -> float:
    return cost_usd(prompt_chars // _CHARS_PER_TOKEN + 1, max_output_tokens)


class LlmBudget:
    def __init__(self, limit_usd: float) -> None:
        if limit_usd < 0:
            raise ValueError("the budget cannot be negative")
        self.limit_usd = limit_usd
        self.spent_usd = 0.0

    def reserve(self, estimate: float) -> None:
        """Refuse a call whose worst case does not fit in what is left."""
        if self.spent_usd + estimate > self.limit_usd:
            raise LlmBudgetExhausted(
                f"the next call could cost up to ${estimate:.4f}; "
                f"${self.limit_usd - self.spent_usd:.4f} of ${self.limit_usd:.2f} is left"
            )

    def charge(self, actual: float) -> None:
        self.spent_usd += actual
