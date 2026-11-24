# The HTML report

`probe run` writes `report.html` next to `report.json` (the default is `--format json,html`;
`--format json` skips the page). It is one self-contained file with no network requests.

Sections: summary (grade, overall score, coverage, caps), families (score, meter and counts),
findings (grouped by severity, then family; each one opens to show the evidence, the spec
reference, why it matters, how to fix it and the `probe repro` command), tools, every check
and its status (filterable), limitations, and scan metadata.

## Safety of the page

- Everything the scanned server said (tool names, messages, excerpts) is HTML-escaped.
- A `Content-Security-Policy` meta tag allows no network access and only the one inline
  script, pinned by its hash. There are no inline event handlers.
- With scripts off the page still shows every section; only the copy buttons, the theme
  toggle, "Expand all" and the checks filter need script.
- The page lists at most 300 findings, most severe first, and says how many more are in
  `report.json`. This keeps the file under 1.5 MB.

## Accessibility and layout

Severity and status are always shown as a word plus a symbol, never by colour alone. Light and
dark themes follow the system setting, with a toggle. The tests run axe on both themes at
375 and 1280 px and require no serious or critical violations, check there is no sideways
scrolling on a phone, and walk through the page with the keyboard only.
