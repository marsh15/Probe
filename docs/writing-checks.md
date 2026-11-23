# Writing a check

A check is a class with a `meta` (`CheckMeta`) and an async `run(ctx)`. Register it with
`@register`, or ship it in a package that declares an entry point in the `probe.checks`
group (naming the class, or a module that registers on import). A plugin that fails to
load is recorded and skipped; it cannot stop a scan.

```python
@register
class NoExample(Check):
    meta = CheckMeta(id="protocol.no_example", family=Family.PROTOCOL, phase="static", ...)

    async def run(self, ctx: ScanContext) -> CheckOutcome:
        response = await ctx.request("tools/list")
        ...
        return CheckOutcome([self.finding(ctx, severity=Severity.MEDIUM, ...)])
```

## What the engine decides for you

Before `run`, the engine gates on `meta`. Not in this mode is SKIPPED. Then NA when the era,
transport or protocol version does not match or the server lacks what `requires` names
(tools, URL or path parameters, writing tools, the Tasks extension, auth identities, a second
instance, HTTP). Then SKIPPED when the run lacks sandbox fixtures, permission for side effects,
or `--llm`. Finally your own `applicable(ctx)` can answer NA.

## Statuses

Leave `CheckOutcome.status` unset: any finding of severity low or higher means FAIL, otherwise
PASS. Info findings are observations and never fail a check. Return
`CheckOutcome.na("reason")` when you cannot judge, most often because
`ctx.establish_baseline` found no successful valid call: **a check that compares against
expected behavior needs a baseline, and without one it is NA, never FAIL.** An exception
inside `run` is ERROR, which is a Probe fault and never counts against the server.

## Calls, budget and crashes

Make every call through `ctx.request` / `ctx.call`: they are budgeted and counted, and a dying
target is recorded as a `CrashEvent` and restarted (at most three times; the third crash
makes the target unstable and later active checks end in ERROR `target_unstable`). If a call
raises `TargetCrashed`, your check may fail on it only if `await ctx.reproduces_crash(...)`
is true; otherwise let it propagate (ERROR, crash still counted by
`behavior.survives_campaign`). Catch `BudgetExhausted` to report what you saw so far.

Compare results with `normalize_volatile` (timestamps, ids, durations) and `stable_equal`,
which reruns a mismatch once before believing it.

## Side effects

Use `ctx.callable_tools()` rather than `ctx.tools` when a check makes calls: read tools are
always callable, but tools that may write (destructive, exec, write, and unknown, which counts
as write) only when the run has `--allow-side-effects` or a sandbox. Local and URL targets have
no fixtures, so a check that needs them lists `fixtures` in `requires` and is skipped there.
A URL target is never restarted or stopped by Probe, and Probe refuses non-local hosts unless
`--i-have-permission` is given.
