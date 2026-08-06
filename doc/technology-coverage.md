# build-recorder — technology coverage: gaps & fork implementation plan

## Goal

Make `build-recorder` produce a complete source→artifact provenance graph for the
three compilation **technologies** we care about, not just one:

| Technology | Compiler model | Status today |
|------------|----------------|--------------|
| **Native exec-based** (GCC/Clang: C/C++/Fortran) | driver forks one process per phase (`cc1`, `as`, `ld`) | **supported** — reference/control |
| **JVM** (`javac` via Maven/Gradle/Ant/direct) | compiles **in-process** inside a long-lived `java` process | **not captured** — no compile edges |
| **.NET** (Roslyn / `csc` via `dotnet`/MSBuild) | compiles **in-process** on the CLR, often in a resident build server | **tracer aborts at startup**; even if it ran, no compile edges |

This document splits the work into independent **tasks**. Tasks 1–2 are small,
technology-agnostic robustness fixes that are realistic to land in the fork (and
Task 1 also closes an existing upstream bug). Tasks 3–4 are large, technology-
specific instrumentation efforts — they are *not* bug fixes and are scoped here
honestly so we can decide whether they are worth attempting.

---

## Why the model works for one technology and not the others

`build-recorder` does not understand compilation. It observes syscalls via
`ptrace` — `fork`/`exec` and file `open` — and **infers** provenance from a
pattern: *a process `execve`s a compiler, then `open`s its inputs for reading and
its outputs for writing.* A source→artifact edge exists only because a single
translation unit is a **distinct OS-level process** with a distinct read-set and
write-set.

**Native (works).** The GCC/Clang driver forks a separate process per phase:

```
gcc foo.c ─┬─ cc1   : reads foo.c            → writes foo.s
           ├─ as    : reads foo.s            → writes foo.o
           └─ ld    : reads *.o, libs        → writes a.out
```

Each phase is a real `execve` whose opens map input→output. The graph is complete
*because compilation is decomposed into observable process/file events*.

**In-process compilers destroy that decomposition.** `javac` and Roslyn are not
native binaries that fork per file — they are compilers written *for* a managed
runtime, executing inside one long-lived process (`java` / the CLR). One process
opens **thousands** of files — every source, every classpath/assembly dependency,
every output — with no process boundary separating one translation unit from the
next. The input→output mapping that build-recorder relies on happens **in memory,
inside the process**, and emits no syscall that links a specific source to a
specific artifact. `ptrace` cannot see inside a process's address space, so the
edges are unrecoverable from syscalls alone. This is a limitation of the *model*,
not a bug — see Tasks 3 and 4 for what recovering it actually costs.

---

## TASK-1 — Robustness: unresolvable path must not abort the whole trace
**Priority: 1 · Effort: XS (≈1 line + guard) · Fork-implementable: yes · Upstream: yes (closes #226)**

### Symptom
Under some builds (notably .NET runtime startup, which probes
`/sys/devices/system/cpu/...`), the tracer dies with:

```
build-recorder: on handle_open absolutepath: No such file or directory
```

and produces an `.out` containing only the schema preamble (`record_start`
writes `schema[]` before any process/file triple — `record.c:33`), i.e. **zero
process/file triples**. The build never gets traced.

### Root cause
`handle_open` → `absolutepath()` calls `realpath(path, NULL)`
(`tracer.c:227`). For a `/sys` path that does not resolve (restricted/partial
`/sys`, absent cache-index level, etc.) `realpath` returns `NULL` with `ENOENT`,
and the caller does a **fatal** `error(EXIT_FAILURE, …)` at **`tracer.c:274-275`**.
A single unresolvable path aborts the entire trace.

Note: the accompanying `mmaping '…': No such device` line is a **non-fatal
warning** from `hash.c:68` (`error(0, …)`, status 0) — sysfs files cannot be
`mmap`ed (`ENODEV`), so hashing is skipped. It is unrelated to the abort; do not
conflate the two.

### Proposed direction
In `handle_open`, treat `abspath == NULL` as "skip this file" (free and return),
not as a fatal error. A file we cannot resolve simply gets no provenance node.

### Acceptance
- A `dotnet build` of a minimal .NET project runs to completion under the tracer
  (no abort); the graph is non-empty.
- The existing native `make` build is unchanged (control still produces the full
  graph).
- Verifies against upstream **#226** repro as well.

---

## TASK-2 — Robustness: signal-safe teardown → always-valid Turtle
**Priority: 2 · Effort: S · Fork-implementable: yes · Upstream: yes (independent)**

### Symptom
When a traced build dies on a signal (e.g. SIGSEGV under `ptrace`), the `.out` is
**truncated mid-statement** and no longer parses (`rdflib` →
`IndexError: string index out of range`). Truncating to the last complete ` .`
makes it parseable again.

### Root cause (two independent defects)
1. **`WIFSIGNALED` is never handled.** The wait loop (`tracer.c:613-705`) only
   branches on `WIFSTOPPED` and `WIFEXITED`. A tracee killed by a signal falls
   through: `running` is not decremented, `record_process_end` (only at
   `tracer.c:691`, under `WIFEXITED`) is not written, and its `pinfo[]` slot is
   never freed/removed. This bookkeeping desync is a plausible trigger for the
   tracer *itself* crashing.
2. **No flush/close on teardown.** `record.c` has no `fclose`/`fflush`/
   `record_stop`; `fout` is `fopen("w")` (block-buffered) and relies entirely on
   normal `exit()` to flush (`main.c:39`). If the **tracer process** is terminated
   by a signal instead of returning normally, the stdio buffer is lost → truncated
   Turtle.

> Diagnostic caveat before implementing: confirm **which** process returns 139.
> The tracer and tracee are separate processes; a tracee dying by signal would
> not, by itself, lose buffered output (the tracer still `exit()`s and flushes).
> Truncation implies the **tracer** died unflushed — so `exit 139` may belong to
> `build-recorder`, not to the build command. Fixing defect (1) may remove the
> tracer crash; defect (2) is the safety net that guarantees a valid file
> regardless.

### Proposed direction
- Add a `WIFSIGNALED` branch: decrement `running`, emit `record_process_end`,
  free the slot (mirror the `WIFEXITED` path).
- Add `record_stop()` that `fflush`/`fclose`es `fout`; register it via `atexit()`
  **and** from a fatal-signal handler, so the Turtle is closed on a valid ` .`
  even when the tracer is killed.

### Acceptance
- A build whose child dies on SIGSEGV still yields a **parseable** `.out`
  (round-trips through `rdflib` with no truncation).
- Native control build unchanged.

---

## TASK-3 — JVM technology support (in-process `javac`)
**Priority: 3 · Effort: L (weeks–months) · Fork-implementable: doubtful · Upstream: only if implemented**

### Symptom
Building a JVM project (Maven/Gradle) under the tracer captures only a handful of
processes (`java`, `mvn`, shell helpers) and **no** `.java`→`.class` edges. The
graph lists dependency artifacts (jars on the classpath) but records no
compilation provenance.

### Root cause
The build tool invokes the compiler through the in-process Compiler API
(`javax.tools.JavaCompiler`) inside the single `java` process. There is no
per-translation-unit `execve`. Even the file `open`s that *are* visible collapse
onto one `java` PID whose read-set (all sources + all classpath jars + config)
and write-set (all `.class`) cannot be partitioned back into per-source edges —
the mapping was done in memory.

### Why this is not a bug fix (scope)
`ptrace` cannot observe intra-process work, so provenance must come from a
**second, JVM-specific instrumentation subsystem**, of which none are cheap:

- **javac plugin / annotation-processor / `JavaFileManager` hook** — instrument
  the compiler from inside the JVM to emit, per compilation, its input sources and
  output classes, then feed that back into build-recorder's RDF sink. Requires a
  Java-side agent, an IPC/serialization path to the tracer, and coverage of *every*
  invocation style (Maven compiler plugin, Gradle, Ant, direct `javac`) **and**
  alternative compilers (`ecj`/Eclipse is a completely different implementation).
- **JVMTI native agent** (`-agentlib`) — hooks JVM events, but javac compilation
  is not a first-class JVMTI event; you still end up hooking the compiler's file
  API. Different mechanism, similar coverage burden.
- **Forked-`javac` mode** (`maven-compiler-plugin <fork>true</fork>`,
  Gradle `options.fork = true`) — makes `javac` a separate `execve`, so the tracer
  sees one `javac` process. But (a) that one process still batch-compiles *all* its
  inputs → you get only **module/batch-level** provenance ("this javac run read
  these sources and wrote these classes"), never file-to-file; and (b) it forces a
  change to the **build configuration**, which build-recorder is meant to observe
  passively, not mandate.

Net: full per-source JVM provenance = new subsystem + broad tool coverage +
incremental-compilation handling. Forked mode is the only low-effort partial win,
and it is coarse-grained and intrusive.

### Proposed direction (if attempted)
Prototype the **coarse** path first: detect forked `javac` execs and record
batch-level (invocation → sources / classes) edges — no new agent, reuses the
existing exec/open path. Treat full per-TU edges as a separate, later effort.

### Acceptance (coarse tier)
A forked-`javac` build yields, per `javac` invocation, a node linking its input
`.java` set to its output `.class` set.

---

## TASK-4 — .NET technology support (in-process Roslyn / `csc`)
**Priority: 4 · Effort: XL · Fork-implementable: no · Upstream: only if implemented**

### Symptom
`dotnet build` currently aborts the tracer at startup (that abort is **TASK-1**).
Once it can run, the same in-process blindness as JVM applies — no
source→artifact edges — but the situation is strictly worse than JVM.

### Root cause (and why worse than JVM)
- Roslyn (`csc`) is itself a .NET program running on the CLR. `dotnet build` runs
  **MSBuild**, which loads Roslyn **in-process**, typically via `VBCSCompiler` — a
  **resident build-server process** that stays alive across invocations to speed up
  builds. Compilation is therefore even more detached from the build command than
  javac: no per-file `execve`, and the work may not even happen in a child of the
  traced process.
- There is no `ptrace`-visible per-translation-unit event to key on.

### Why this is not a bug fix (scope)
Recovering provenance needs a **.NET-runtime-specific** source, none reachable by
extending exec/open tracing:

- **CLR profiler** (`ICorProfiler`, loaded via `CORECLR_PROFILER`) — the CLR
  analogue of JVMTI: a native profiling agent inside the runtime. Powerful but a
  large, different API and a whole new ingestion path.
- **Roslyn analyzer / source-generator hook** — instrument the compiler from
  inside, similar trade-offs to the javac-plugin route.
- **MSBuild structured/binary log (`-bl` binlog, or a custom `ILogger`)** — the
  most practical source: MSBuild already records every `Csc` task with its full
  input file list and outputs. This is **build-system-level** provenance (task
  granularity), obtained by parsing MSBuild's log, *not* by syscall tracing — a
  completely separate ingestion path bolted onto build-recorder.

Net: .NET cannot be covered by the ptrace mechanism at all; the realistic route is
ingesting MSBuild's own logs, which is a different data source and only
task-level granular.

### Proposed direction (if attempted)
Do **TASK-1 first** (so `dotnet` runs at all), then evaluate an MSBuild-binlog
ingester as an optional, separate provenance source — explicitly outside the
ptrace path.

### Acceptance (log-ingestion tier)
For a `dotnet build`, each `Csc` task's inputs (`.cs` set) and outputs
(assembly/`.dll`) appear as provenance edges sourced from the MSBuild log.

---

## TASK-5 — Document the technology support matrix
**Priority: 2 · Effort: XS · Fork-implementable: yes**

Add to README/USAGE an explicit statement of the model and its reach:

> build-recorder infers provenance from `exec`+`open` syscalls. It fully supports
> **exec-based toolchains** (GCC/Clang) that fork one process per translation
> unit. It does **not** capture **in-process compilation** inside a managed
> runtime — **JVM** (`javac`) and **.NET** (Roslyn/`csc`) — because the
> source→artifact mapping happens in memory and emits no linking syscall.
> (Tracking: TASK-3 / TASK-4.)

This is worth doing regardless of whether 3–4 are ever attempted.

---

## Reference — native exec-based build (control / definition of "done")

A native C project built with `make -j` under the tracer is the baseline for a
*complete* graph and the regression control for Tasks 1–2:

- compiler phases visible as separate execs: `cc1`, `x86_64-…-gcc`, `as`, `lto1`,
  `collect2`/`ld`
- every `.c` source resolved and hashed; `.o`/`.a` artifacts linked back to their
  sources; the only "ready-made binaries" are the toolchain itself
- source→artifact graph complete and as expected

Any change from Tasks 1–2 must leave this graph unchanged.

---

## Task summary

| Task | What | Effort | Fork? | Upstream? |
|------|------|--------|-------|-----------|
| **1** | Skip unresolvable paths instead of aborting (`tracer.c:274`) | XS | yes | yes — closes #226 |
| **2** | Handle `WIFSIGNALED` + flush/close Turtle on teardown | S | yes | yes |
| **3** | JVM in-process compilation provenance (coarse forked-`javac` first) | L | doubtful | if implemented |
| **4** | .NET in-process compilation provenance (MSBuild binlog ingester) | XL | no | if implemented |
| **5** | Document the technology support matrix | XS | yes | yes |

**Recommended order:** 1 → 2 → 5 (all cheap, all landable), then reassess 3 (coarse
tier) and 4 (log-ingestion tier) as separate, optional efforts. Upstream a fix
only after it is implemented and verified in the fork; Task 1 is the clearest
upstream candidate because it also closes #226.
