"""brec/components.py — one registry of vendorable third-party components.

sbom.py (versions, purls, OSV names) and verify-build.py (upstream git repos)
used to keep separate tables that overlapped in five components.  These tests
state what the merge must preserve: every entry either table had, the detection
order the SBOM depends on, and the rule that a component without an upstream
URL is simply not verifiable rather than an error.
"""

from pathlib import Path

import pytest

from brec.components import (
    COMPONENTS,
    match_by_dirname,
    match_by_filename,
    upstream_for,
)

# What each tool knew before the merge; nothing here may be lost.
_SBOM_KEYS = {
    "luafilesystem", "sqlite", "lua", "duktape", "lsqlite3", "luaxml",
    "lua_struct", "expat", "zlib", "libpng", "cjson", "jsmn", "mbedtls",
}
_UPSTREAM_KEYS = {
    "wslay", "zlib", "lua", "luafilesystem", "duktape", "expat", "libutp",
    "civetweb",
}


def test_registry_keeps_every_sbom_component() -> None:
    assert _SBOM_KEYS <= set(COMPONENTS)


def test_registry_keeps_every_upstream_component() -> None:
    assert _UPSTREAM_KEYS <= set(COMPONENTS)


def test_overlapping_components_carry_both_halves() -> None:
    """The five components both tables described now hold one merged entry."""
    for key in _SBOM_KEYS & _UPSTREAM_KEYS:
        comp = COMPONENTS[key]
        assert comp.file_triggers, f"{key} lost its SBOM detection triggers"
        assert comp.upstream_url,  f"{key} lost its upstream repository"


def test_purl_fields_present_for_sbom_components() -> None:
    for key in _SBOM_KEYS:
        comp = COMPONENTS[key]
        assert comp.display_name
        assert comp.purl_name, f"{key} has no purl name"


# ── Detection ─────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("filename,expected", [
    ("sqlite3.c",  "sqlite"),
    ("lfs.h",      "luafilesystem"),
    ("duk_config.h", "duktape"),
    ("zlib.h",     "zlib"),
    ("main.c",     None),
])
def test_match_by_filename(filename: str, expected) -> None:
    assert match_by_filename(filename) == expected


@pytest.mark.parametrize("dirname,expected", [
    ("sqlite-3.44.2",  ("sqlite", "3.44.2")),
    ("lua-5.4.6",      ("lua", "5.4.6")),
    ("mbedtls_2.28.0", ("mbedtls", "2.28.0")),
    ("src",            None),
])
def test_match_by_dirname(dirname: str, expected) -> None:
    assert match_by_dirname(dirname) == expected


def test_upstream_only_components_are_invisible_to_sbom_detection() -> None:
    """wslay, libutp and civetweb carry no triggers, so the SBOM never claims them."""
    for key in _UPSTREAM_KEYS - _SBOM_KEYS:
        assert not COMPONENTS[key].file_triggers
        assert COMPONENTS[key].dir_re is None


# ── Upstream lookup ───────────────────────────────────────────────────────────

def test_upstream_for_known_component() -> None:
    comp = upstream_for("wslay")
    assert comp is not None
    assert comp.upstream_url.endswith("wslay.git")
    assert "lib/wslay_event.c" in comp.upstream_key_files


def test_upstream_for_component_without_a_repo() -> None:
    """SQLite is in the registry but too large to clone: not verifiable, not an error."""
    assert "sqlite" in COMPONENTS
    assert upstream_for("sqlite") is None


def test_upstream_for_unknown_directory() -> None:
    assert upstream_for("no-such-component") is None


# ── The tools read this registry rather than their own ────────────────────────

def test_cli_scripts_have_no_private_component_tables() -> None:
    commands = Path(__file__).parent.parent / "brec" / "commands"
    sbom_src = (commands / "sbom.py").read_text(encoding="utf-8")
    verify_src = (commands / "verify.py").read_text(encoding="utf-8")
    assert "KNOWN_COMPONENTS" not in sbom_src
    assert "class ComponentSpec" not in sbom_src
    assert "UPSTREAM_DB" not in verify_src
    assert "class UpstreamSpec" not in verify_src
