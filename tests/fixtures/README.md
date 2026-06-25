# Test fixtures

## tiny.out

**Status:** Synthetic (hand-crafted).

build-recorder requires `ptrace` privileges and a compiled binary to run.
In this environment the tool is not yet compiled, so `tiny.out` was constructed
manually to match the exact flat-triple Turtle format that `build-recorder`
produces, verified against the regex patterns in `enrich.py` and `verify-build.py`.

**Format:** flat (one triple per line), using `:` prefix for data URIs and
`b:` prefix for predicates, matching `@prefix` declarations at file top.

**Contents:**
- 2 processes: `:p0` (make), `:p1` (cc1 compiler frontend)
- 3 files: `:f0` (cc1 executable), `:f1` (hello.c source), `:f2` (hello.o output)
- Relations: `b:creates` (p0→p1), `b:executable` (p1→f0), `b:reads` (p1→f1),
  `b:writes` (p1→f2)

**How to regenerate with real build-recorder** (once compiled):
```bash
build-recorder -o tests/fixtures/tiny.out cc -o /tmp/hello examples/f1.c
```
Environment: ALT Linux p11, build-recorder from `main` branch.

**Integer literals** (e.g. `b:pid 1001 .`, `b:size 256 .`) are written
without quotes, as required by Turtle (xsd:integer range in the schema).

---

## tiny.expected.json

Pre-computed expected output of `brec.model.parse_out("tests/fixtures/tiny.out")`
wrapped in an `IRDocument` envelope (see `brec/ir.py`, T0.1).

Used as the golden baseline in `tests/test_model.py` (T0.2).

The `execs` list in each `ProcessNode` aggregates both `b:creates` and
`b:execs` predicates (both represent parent→child process relationships).

---

## Future fixtures (added by later tickets)

| File | Added in | Purpose |
|------|----------|---------|
| `tiny_grouped.out` | T0.2 | Grouped (semicolon-separated) Turtle format |
| `tiny_escaped.out` | T0.2 | Paths with spaces, quotes, unicode in abspath |
| `tiny_enriched_old.out` | T0.4 | Old `b:rpm_*` + `b:dep_type` predicates |
| `tiny_enriched_new.out` | T0.4 | New `b:pkg_*` predicates |
