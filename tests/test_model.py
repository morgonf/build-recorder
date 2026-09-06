"""T0.2 acceptance tests — brec/model.py parse_out()."""

import json
from pathlib import Path

from brec.model import parse_out


# ── Golden test: tiny.out ─────────────────────────────────────────────────────

def test_golden_file_count(tiny_out: Path, tiny_expected: Path) -> None:
    graph = parse_out(tiny_out)
    expected = json.loads(tiny_expected.read_text(encoding="utf-8"))
    assert len(graph.files) == len(expected["payload"]["files"])


def test_golden_proc_count(tiny_out: Path, tiny_expected: Path) -> None:
    graph = parse_out(tiny_out)
    expected = json.loads(tiny_expected.read_text(encoding="utf-8"))
    assert len(graph.procs) == len(expected["payload"]["procs"])


def test_golden_file_properties(tiny_out: Path, tiny_expected: Path) -> None:
    graph = parse_out(tiny_out)
    expected_files = json.loads(tiny_expected.read_text(encoding="utf-8"))["payload"]["files"]
    for uri, efn in expected_files.items():
        assert uri in graph.files, f"missing file {uri}"
        fn = graph.files[uri]
        assert fn.uri == efn["uri"]
        assert fn.abspath == efn["abspath"]
        assert fn.name == efn["name"]
        assert fn.size == efn["size"]
        assert fn.git_blob_sha1 == efn["git_blob_sha1"]


def test_golden_proc_relations(tiny_out: Path, tiny_expected: Path) -> None:
    graph = parse_out(tiny_out)
    expected_procs = json.loads(tiny_expected.read_text(encoding="utf-8"))["payload"]["procs"]
    for uri, epn in expected_procs.items():
        assert uri in graph.procs, f"missing process {uri}"
        pn = graph.procs[uri]
        assert pn.executable == epn["executable"]
        assert sorted(pn.reads)  == sorted(epn["reads"])
        assert sorted(pn.writes) == sorted(epn["writes"])
        assert sorted(pn.execs)  == sorted(epn["execs"])


def test_golden_proc_metadata(tiny_out: Path, tiny_expected: Path) -> None:
    graph = parse_out(tiny_out)
    expected_procs = json.loads(tiny_expected.read_text(encoding="utf-8"))["payload"]["procs"]
    for uri, epn in expected_procs.items():
        pn = graph.procs[uri]
        assert pn.pid  == epn["pid"]
        assert pn.cmd  == epn["cmd"]
        assert pn.start == epn["start"]
        assert pn.end   == epn["end"]


def test_golden_role_is_none(tiny_out: Path) -> None:
    """Parser must leave role=None (CLASSIFY fills it later)."""
    graph = parse_out(tiny_out)
    for pn in graph.procs.values():
        assert pn.role is None


# ── Flat format ───────────────────────────────────────────────────────────────

def test_flat_format_file_count(flat_out: Path) -> None:
    graph = parse_out(flat_out)
    assert len(graph.files) == 3


def test_flat_format_proc_count(flat_out: Path) -> None:
    graph = parse_out(flat_out)
    assert len(graph.procs) == 2


def test_flat_format_file_properties(flat_out: Path) -> None:
    graph = parse_out(flat_out)
    f0 = graph.files[":f0"]
    assert f0.abspath == "/usr/bin/gcc"
    assert f0.name    == "gcc"
    assert f0.size    == 2000
    assert f0.git_blob_sha1 == "1111111111111111111111111111111111111111"


def test_flat_format_proc_relations(flat_out: Path) -> None:
    graph = parse_out(flat_out)
    p0, p1 = graph.procs[":p0"], graph.procs[":p1"]
    assert p0.execs == [":p1"]
    assert p1.executable == ":f0"
    assert p1.reads  == [":f1"]
    assert p1.writes == [":f2"]


def test_flat_format_proc_metadata(flat_out: Path) -> None:
    graph = parse_out(flat_out)
    p1 = graph.procs[":p1"]
    assert p1.pid == 201
    assert p1.cmd == "/usr/bin/gcc -o out.o in.c"
    assert p1.start == "2024-02-01T08:00:01"
    assert p1.end   == "2024-02-01T08:00:05"


# ── Grouped format ────────────────────────────────────────────────────────────

def test_grouped_format_file_count(grouped_out: Path) -> None:
    graph = parse_out(grouped_out)
    assert len(graph.files) == 3


def test_grouped_format_proc_count(grouped_out: Path) -> None:
    graph = parse_out(grouped_out)
    assert len(graph.procs) == 2


def test_grouped_format_file_properties(grouped_out: Path) -> None:
    graph = parse_out(grouped_out)
    f1 = graph.files[":f1"]
    assert f1.abspath == "/home/user/project/in.c"
    assert f1.size    == 512
    assert f1.git_blob_sha1 == "2222222222222222222222222222222222222222"


def test_grouped_format_proc_relations(grouped_out: Path) -> None:
    graph = parse_out(grouped_out)
    p0, p1 = graph.procs[":p0"], graph.procs[":p1"]
    assert p0.execs == [":p1"]
    assert p1.executable == ":f0"
    assert p1.reads  == [":f1"]
    assert p1.writes == [":f2"]


# ── flat.out and grouped.out represent the same graph ─────────────────────────

def test_flat_grouped_equivalent_files(flat_out: Path, grouped_out: Path) -> None:
    fg = parse_out(flat_out)
    gg = parse_out(grouped_out)
    assert set(fg.files.keys()) == set(gg.files.keys())
    for uri in fg.files:
        ff, gf = fg.files[uri], gg.files[uri]
        assert ff.abspath       == gf.abspath
        assert ff.name          == gf.name
        assert ff.size          == gf.size
        assert ff.git_blob_sha1 == gf.git_blob_sha1


def test_flat_grouped_equivalent_procs(flat_out: Path, grouped_out: Path) -> None:
    fg = parse_out(flat_out)
    gg = parse_out(grouped_out)
    assert set(fg.procs.keys()) == set(gg.procs.keys())
    for uri in fg.procs:
        fp, gp = fg.procs[uri], gg.procs[uri]
        assert fp.pid        == gp.pid
        assert fp.cmd        == gp.cmd
        assert fp.start      == gp.start
        assert fp.end        == gp.end
        assert fp.executable == gp.executable
        assert sorted(fp.reads)  == sorted(gp.reads)
        assert sorted(fp.writes) == sorted(gp.writes)
        assert sorted(fp.execs)  == sorted(gp.execs)


# ── Escaped paths ─────────────────────────────────────────────────────────────

def test_escaped_double_quotes_in_path(escaped_paths_out: Path) -> None:
    graph = parse_out(escaped_paths_out)
    f0 = graph.files[":f0"]
    assert f0.abspath == '/path/with "quotes"/file.c'


def test_escaped_backslash_in_path(escaped_paths_out: Path) -> None:
    graph = parse_out(escaped_paths_out)
    f1 = graph.files[":f1"]
    assert f1.abspath == "/path/with\\backslash/file.c"


def test_spaces_in_path(escaped_paths_out: Path) -> None:
    graph = parse_out(escaped_paths_out)
    f2 = graph.files[":f2"]
    assert f2.abspath == "/path/with spaces/file.c"


def test_unicode_in_path(escaped_paths_out: Path) -> None:
    graph = parse_out(escaped_paths_out)
    f3 = graph.files[":f3"]
    assert f3.abspath == "/путь/к/файлу.c"
    assert f3.name    == "файлу.c"


def test_escaped_cmd_unescaped(escaped_paths_out: Path) -> None:
    graph = parse_out(escaped_paths_out)
    p0 = graph.procs[":p0"]
    # The raw cmd contains \" sequences that should be unescaped to "
    assert '"' in p0.cmd


# ── Unescaping ────────────────────────────────────────────────────────────────

def test_carriage_return_unescaped(tmp_path: Path) -> None:
    """The tracer writes \\r (record_triple() in src/record.c); parsing must undo it."""
    out = tmp_path / "cr.out"
    out.write_text(
        ":f0 a b:file .\n"
        ':f0 b:abspath "/tmp/we\\rird.c" .\n',
        encoding="utf-8",
    )
    assert parse_out(out).files[":f0"].abspath == "/tmp/we\rird.c"


def test_escaped_backslash_does_not_start_a_new_escape(tmp_path: Path) -> None:
    r"""``\\n`` is a backslash followed by "n", not a newline.

    Unescaping by chained replaces turned it into a newline: ``\\`` became a
    single backslash first, and the next pass read the result as ``\n``.
    """
    out = tmp_path / "bs.out"
    out.write_text(
        ":f0 a b:file .\n"
        ':f0 b:abspath "/tmp/dir\\\\name.c" .\n',
        encoding="utf-8",
    )
    assert parse_out(out).files[":f0"].abspath == "/tmp/dir\\name.c"


# ── Idempotency ───────────────────────────────────────────────────────────────

def test_parse_out_idempotent(tiny_out: Path) -> None:
    """Parsing the same file twice gives equivalent BuildGraph objects."""
    g1 = parse_out(tiny_out)
    g2 = parse_out(tiny_out)
    assert set(g1.files.keys()) == set(g2.files.keys())
    assert set(g1.procs.keys()) == set(g2.procs.keys())
    for uri in g1.files:
        assert g1.files[uri].abspath == g2.files[uri].abspath
    for uri in g1.procs:
        assert g1.procs[uri].reads == g2.procs[uri].reads


# ── Name defaults to Path.name when b:name absent ────────────────────────────

def test_name_defaults_from_abspath(tmp_path: Path) -> None:
    """If b:name is absent, name should be derived from the abspath basename."""
    out = tmp_path / "minimal.out"
    out.write_text(
        "@prefix : <http://build-recorder.org/data#> .\n"
        "@prefix b: <http://build-recorder.org/rdf#> .\n"
        ":f0 a b:file .\n"
        ":f0 b:abspath \"/usr/lib/libfoo.a\" .\n"
        ":f0 b:size 500 .\n"
        ":f0 b:hash \"aaaa000000000000000000000000000000000001\" .\n",
        encoding="utf-8",
    )
    graph = parse_out(out)
    assert graph.files[":f0"].name == "libfoo.a"


# ── Node type determined by a b:file / a b:process, not URI prefix ────────────

def test_node_type_by_declaration_not_prefix(tmp_path: Path) -> None:
    """URIs like :xyz (non-standard prefix) are classified by their type triple."""
    out = tmp_path / "nonstandard.out"
    out.write_text(
        "@prefix : <http://build-recorder.org/data#> .\n"
        "@prefix b: <http://build-recorder.org/rdf#> .\n"
        ":myfile a b:file .\n"
        ":myfile b:abspath \"/tmp/x\" .\n"
        ":myfile b:size 1 .\n"
        ":myfile b:hash \"0000000000000000000000000000000000000001\" .\n"
        ":myproc a b:process .\n"
        ":myproc b:pid 99 .\n"
        ":myproc b:cmd \"true\" .\n"
        ":myproc b:reads :myfile .\n",
        encoding="utf-8",
    )
    graph = parse_out(out)
    assert ":myfile" in graph.files
    assert ":myproc" in graph.procs
    assert graph.procs[":myproc"].reads == [":myfile"]


# ── b:rename → ProcessNode.renames ───────────────────────────────────────────

def test_rename_parsed_into_renames(tmp_path: Path) -> None:
    out = tmp_path / "rename.out"
    out.write_text(
        "@prefix : <http://build-recorder.org/data#> .\n"
        "@prefix b: <http://build-recorder.org/rdf#> .\n"
        ":f0 a b:file .\n"
        ":f0 b:abspath \"/tmp/foo\" .\n"
        ":f0 b:size 0 .\n"
        ":f0 b:hash \"0000000000000000000000000000000000000001\" .\n"
        ":p0 a b:process .\n"
        ":p0 b:pid 1 .\n"
        ":p0 b:cmd \"mv\" .\n"
        ":p0 b:rename :f0 .\n",
        encoding="utf-8",
    )
    graph = parse_out(out)
    assert graph.procs[":p0"].renames == [":f0"]


def test_rename_blank_node_resolves_to_the_file_it_produced(tmp_path: Path) -> None:
    """The shape record_rename() actually writes: a pair hung off a blank node."""
    out = tmp_path / "rename_bnode.out"
    out.write_text(
        "@prefix : <http://build-recorder.org/data#> .\n"
        "@prefix b: <http://build-recorder.org/rdf#> .\n"
        ":f0 a b:file .\n"
        ":f0 b:abspath \"/tmp/foo.tmp\" .\n"
        ":f1 a b:file .\n"
        ":f1 b:abspath \"/tmp/foo\" .\n"
        ":p0 a b:process .\n"
        ":p0 b:pid 1 .\n"
        ":p0 b:cmd \"mv\" .\n"
        ":p0 b:rename _:rename0 .\n"
        "_:rename0 b:rename-from :f0 .\n"
        "_:rename0 b:rename-to :f1 .\n",
        encoding="utf-8",
    )
    graph = parse_out(out)
    assert graph.procs[":p0"].renames == [":f1"]


def test_rename_blank_node_without_a_target_is_dropped(tmp_path: Path) -> None:
    """An undescribed blank node yields nothing, not an unresolvable URI."""
    out = tmp_path / "rename_dangling.out"
    out.write_text(
        "@prefix : <http://build-recorder.org/data#> .\n"
        "@prefix b: <http://build-recorder.org/rdf#> .\n"
        ":p0 a b:process .\n"
        ":p0 b:pid 1 .\n"
        ":p0 b:cmd \"mv\" .\n"
        ":p0 b:rename _:rename7 .\n",
        encoding="utf-8",
    )
    assert parse_out(out).procs[":p0"].renames == []


# ── One process, several programs ────────────────────────────────────────────

def test_every_executable_is_kept(tmp_path: Path) -> None:
    """A pid that execs several times records a b:executable for each.

    Keeping only the last one silently dropped a fifth of the exec facts in a
    real trace, so tool-invocation counts came out far below what was recorded.
    """
    out = tmp_path / "execs.out"
    out.write_text(
        "@prefix : <http://build-recorder.org/data#> .\n"
        "@prefix b: <http://build-recorder.org/rdf#> .\n"
        ":fsh a b:file .\n:fsh b:abspath \"/bin/sh\" .\n"
        ":fwrap a b:file .\n:fwrap b:abspath \"/usr/bin/gcc_wrapper\" .\n"
        ":fcc1 a b:file .\n:fcc1 b:abspath \"/usr/libexec/cc1\" .\n"
        ":p0 a b:process .\n"
        ":p0 b:pid 1 .\n"
        ":p0 b:cmd \"cc -c x.c\" .\n"
        ":p0 b:executable :fsh .\n"
        ":p0 b:executable :fwrap .\n"
        ":p0 b:executable :fcc1 .\n",
        encoding="utf-8",
    )
    proc = parse_out(out).procs[":p0"]
    assert proc.executables == [":fsh", ":fwrap", ":fcc1"]
    # ... and the process still has one identity: the program it ended up as.
    assert proc.executable == ":fcc1"


# ── Node order is the trace's order, and the same on every run ───────────────

def test_nodes_keep_trace_order(tmp_path: Path) -> None:
    """Order must not come from a set.

    Callers keep one entry per path and take the last node they see, so an
    order that varies between runs makes them report a different hash for the
    same artifact from one run to the next.
    """
    out = tmp_path / "order.out"
    lines = [
        "@prefix : <http://build-recorder.org/data#> .",
        "@prefix b: <http://build-recorder.org/rdf#> .",
    ]
    for i in range(30):
        lines += [
            f":f{i} a b:file .",
            f':f{i} b:abspath "/build/out.o" .',
            f':f{i} b:hash "{i:040d}" .',
            f":p{i} a b:process .",
            f":p{i} b:pid {i} .",
            f':p{i} b:cmd "cc" .',
        ]
    out.write_text("\n".join(lines) + "\n", encoding="utf-8")

    graph = parse_out(out)
    assert list(graph.files) == [f":f{i}" for i in range(30)]
    assert list(graph.procs) == [f":p{i}" for i in range(30)]
    # ... so "the last node for this path" is the last version written.
    assert list(graph.files.values())[-1].git_blob_sha1 == f"{29:040d}"


# ── b:creates and b:execs both map to ProcessNode.execs ──────────────────────

def test_creates_maps_to_execs(tmp_path: Path) -> None:
    out = tmp_path / "creates.out"
    out.write_text(
        "@prefix : <http://build-recorder.org/data#> .\n"
        "@prefix b: <http://build-recorder.org/rdf#> .\n"
        ":p0 a b:process .\n"
        ":p0 b:pid 1 .\n"
        ":p0 b:cmd \"shell\" .\n"
        ":p1 a b:process .\n"
        ":p1 b:pid 2 .\n"
        ":p1 b:cmd \"child\" .\n"
        ":p0 b:creates :p1 .\n",
        encoding="utf-8",
    )
    graph = parse_out(out)
    assert graph.procs[":p0"].execs == [":p1"]


def test_execs_maps_to_execs(tmp_path: Path) -> None:
    out = tmp_path / "execs.out"
    out.write_text(
        "@prefix : <http://build-recorder.org/data#> .\n"
        "@prefix b: <http://build-recorder.org/rdf#> .\n"
        ":p0 a b:process .\n"
        ":p0 b:pid 1 .\n"
        ":p0 b:cmd \"shell\" .\n"
        ":p1 a b:process .\n"
        ":p1 b:pid 2 .\n"
        ":p1 b:cmd \"child\" .\n"
        ":p0 b:execs :p1 .\n",
        encoding="utf-8",
    )
    graph = parse_out(out)
    assert graph.procs[":p0"].execs == [":p1"]


# ── Empty file produces empty graph ──────────────────────────────────────────

def test_empty_file_gives_empty_graph(tmp_path: Path) -> None:
    out = tmp_path / "empty.out"
    out.write_text("@prefix : <http://build-recorder.org/data#> .\n", encoding="utf-8")
    graph = parse_out(out)
    assert graph.files == {}
    assert graph.procs == {}


def test_undeclared_process_subject_is_still_a_process(tmp_path):
    """Edges must survive a subject the tracer never typed.

    Traces produced before the tracer declared forked children carry reads and
    writes under subjects with no `a b:process` line; keying strictly on the
    declaration dropped a third of the processes on a cargo build, silently.
    """
    out = tmp_path / "undeclared.out"
    out.write_text(
        "@prefix : <http://build-recorder.org/data#> .\n"
        "@prefix b: <http://build-recorder.org/rdf#> .\n"
        ":f0 a b:file .\n"
        ':f0 b:abspath "/usr/include/stdio.h" .\n'
        ':f0 b:name "stdio.h" .\n'
        ":f0 b:size 1 .\n"
        ':f0 b:hash "aa00000000000000000000000000000000000001" .\n'
        ":p9 b:reads :f0 .\n"           # subject never declared
        ":p9 b:pid 4242 .\n",
        encoding="utf-8",
    )
    graph = parse_out(out)
    assert ":p9" in graph.procs
    assert graph.procs[":p9"].reads == [":f0"]
    assert graph.procs[":p9"].pid == 4242
    assert ":p9" not in graph.files
