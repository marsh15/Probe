# Tool classification API

`probe.classify.classify_tool` is a synchronous, standalone function. It returns
an existing `probe.engine.outcomes.ToolInfo`; importing it does not start a
server, load an MCP SDK, or perform I/O.

```python
from probe.classify import classify_tool

info = classify_tool(
    "fetch_document",
    {"type": "object", "properties": {"url": {"format": "uri"}}},
    description="Fetch a document by URL.",
)
assert info.kind == "read"
assert info.param_roles == {"url": "url_param"}
```

The signature is:

```python
classify_tool(
    name: str,
    input_schema: dict[str, Any],
    *,
    title: str | None = None,
    description: str | None = None,
    output_schema: dict[str, Any] | None = None,
    annotations: Mapping[str, Any] | None = None,
    profile: Mapping[str, Any] | None = None,
) -> ToolInfo
```

Pass schemas directly, with snake_case argument names. Pass a profile as a
mapping, for example `{"tools": {"fetch_document": {"kind": "read"}}}`.
The tool name is an exact profile key. An absent kind leaves classification to
other evidence; an explicitly invalid kind raises `ValueError`, including null,
uppercase spellings, numbers, and unrecognized values. Malformed `tools` or
selected tool entries also raise `ValueError`. The classifier does not validate
unrelated profile fields or unrelated tool entries.

The returned metadata and nested schema values are independent copies. The
function neither modifies caller data nor resolves `$ref`, combines schemas, or
generates arguments. Scan/CLI integration is separate work.

## Evidence and safety

Each result records a source and a human-readable explanation. Profile evidence
wins over annotation evidence. Any nonempty annotation mapping activates hint
defaults, even if it contains only a title or an unrelated extension. Only the
boolean `True` makes `readOnlyHint` read-only. Otherwise, only the boolean `False`
for `destructiveHint` permits the write category; a missing or malformed value
selects destructive. Numeric `1` and the string `"true"` cannot claim read-only.
A strict read-only hint wins even when the other hint conflicts.

Without profile or annotation evidence, the explicit vocabulary in
[`lexicon.py`](../src/probe/classify/lexicon.py) classifies identifier tokens.
Tokens split on separators and camelCase/acronym boundaries; prose punctuation
also separates words. Higher-risk categories win regardless of where their
matching tokens occur. Tokens are exact words, with no stemming, substring
matching, negation analysis, or server-specific vocabulary.

A description supplies fallback kind evidence when the name has no recognized
words. In addition, when name evidence selects `write`, any destructive token
in the first description sentence raises the result to `destructive`. This
includes optional destructive capabilities of tools that otherwise create or
edit data. It does not promote a tool to read-only or infer execution from the
description of a recognized name. Recognized read, destructive, and exec names
retain their name-based result.

The destructive vocabulary includes these explicit additional word forms in
names and descriptions:

- `deletes`, `deleted`, `deleting`, `deletion`, `deletions`
- `dismiss`, `dismisses`, `dismissed`, `dismissing`, `dismissal`, `dismissals`
- `archives`, `archived`, `archiving`

These match complete tokens; `undeleted`, `archiver`, and `dismissalish` do not
match. There is no general stemming or negation analysis: even “without
deletion” can conservatively raise a write tool to destructive. Nouns or past
participles can therefore cause false positives. The new rule does not attempt
to determine whether a described capability is enabled for particular inputs.

Only the first description sentence is inspected for kind evidence. Sentence
endings are `.`, `!`, or `?` followed by whitespace or the end of the string;
abbreviations are not interpreted linguistically. A missing match yields
`unknown`, which the existing engine includes in its writing-tool gate.
Classification is a deterministic hint, not proof of what a server will do.

These two refinements supersede the initial fixed vocabulary and
description-only-as-fallback rules under the user's explicit approval,
“Refine heuristics; keep 95% gate.” Profile and strict annotation precedence,
parameter roles, pagination, copying, and unknown gating remain unchanged.
Synthetic tests cover the new forms, escalation, substring and sentence limits,
ambiguous negation, and overriding evidence. The existing read-name precedence
test retains its original assertion.

## Parameter roles

Only direct input `properties` are considered. SQL and command parameters need
tool-level context: complete tokens from the name or full description, or an
exec kind for commands. Property descriptions alone do not establish those
contexts. URL descriptions match the word `URL`, case-insensitively. Format
names use exact JSON Schema spelling. Parameter-name patterns are
case-insensitive; the sensitive-name pattern intentionally matches within a
name (for example, `access_token`). This conservative pattern can also match
`auth` inside `author`.

A property can match multiple roles. `flags` retains every detected role across
all properties. `param_roles` chooses one primary role per property using this
stable priority:

1. `sensitive_param`
2. `command_param`
3. `sql_param`
4. `path_param`
5. `url_param`

Pagination contributes a flag rather than a parameter role. It uses exact,
case-sensitive direct input or output property names. Nested definitions,
references, and composed schemas do not contribute signals. Malformed property
containers are ignored. A malformed property definition can still contribute
name-based signals, but its format/description values are ignored unless they
have the expected string type.

## Corpus evaluation

[`expected.yaml`](../tests/classify/expected.yaml) associates all 60 existing
schema filenames with independently chosen semantic kinds, actual tool names
(with the fixture's server prefix removed), and pinned source links. Labels
were written before implementing or running the classifier. The descriptions
are hand-authored summaries of the linked implementations, rather than exact
live metadata snapshots. The fixture files themselves remain unchanged.

The corpus evaluation uses one consistent input policy: every case supplies its
actual tool name, the corresponding schema, and its independently authored
source-backed description summary. No case supplies profile overrides or
annotations. Profile and annotation precedence remain covered separately by
unit tests. This separates inference quality from explicitly configured answers.

Independent agreement is **57/60 (95%)**, meeting the unchanged **95%** corpus
gate for T19b. The genuine baseline before refinement was **54/60 (90%)**.
Destructive description escalation and the explicit word forms correct
`projects_write`, `update_dependabot_alert`, and `patch-page`. All three
remaining disagreements are recorded in
[`known_misses.yaml`](../tests/classify/known_misses.yaml): `git_log` (the noun
`commit` matches write), `open_nodes` (`open` matches write), and `post-search`
(HTTP `post` matches write). Each is semantically read-only in this corpus;
the classifier conservatively returns write. Refinement stopped at the gate.

An earlier evaluation reached 57/60 using one label-derived profile override
and two selectively supplied annotations. Review rejected that acceptance
measurement; those inputs were removed without changing semantic labels or
descriptions. The current 57/60 result uses the uniformly evaluated inputs and
the user-approved general heuristic refinements described above.

This remains an evaluation of source-backed summaries rather than unchanged
live tools/list metadata. The lexical rules can misclassify nouns, HTTP
method names, multiplexed tools, and capabilities mentioned only in schemas.
The rules were refined with knowledge of this corpus's misses, so reaching the
gate does not establish accuracy on unseen servers or live descriptions.
Broader generalization requires separate evaluation.
