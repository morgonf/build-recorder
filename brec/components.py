"""brec.components — the registry of third-party components a build may vendor.

One entry per component, carrying everything the analysis layer knows about it:

  * how to recognise it in a build graph (file names, directory patterns),
  * how to read its version out of its own source,
  * how to name it to a vulnerability database (OSV, purl),
  * where its upstream git repository is, for hash-level verification.

``sbom.py`` and ``verify-build.py`` used to keep separate tables: the SBOM knew
versions and purls, the verifier knew upstream URLs, and five components
(zlib, lua, luafilesystem, duktape, expat) were described twice, each half
knowing nothing of the other.  One table means a component added for one tool
is visible to both.

Entry order matters: :func:`match_by_filename` returns the first component whose
triggers match, so more specific entries come before more generic ones.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Callable, Optional


def _duk_version(v: str) -> str:
    """Duktape writes its version as a single integer: 20500 → 2.5.0."""
    n = int(v)
    return f"{n // 10000}.{(n % 10000) // 100}.{n % 100}"


@dataclass
class Component:
    display_name: str

    # ── Detection ────────────────────────────────────────────────────────────
    # File names that identify the component wherever they appear, and a
    # pattern matching a versioned directory name (e.g. "sqlite-3.44.2").
    file_triggers: set = field(default_factory=set)
    dir_re: Optional[re.Pattern] = None

    # ── Version extraction from the vendored source ──────────────────────────
    version_re: Optional[re.Pattern] = None
    version_transform: Optional[Callable[[str], str]] = None

    # ── Vulnerability lookup ─────────────────────────────────────────────────
    osv_ecosystem: str = ""
    osv_name: str = ""
    purl_type: str = "generic"
    purl_ns: str = ""
    purl_name: str = ""
    homepage: str = ""

    # ── Upstream verification (blob hashes against real history) ─────────────
    # An empty upstream_url means "no automatic clone for this one".
    upstream_url: str = ""
    # Paths relative to the upstream repo root that identify the component.
    # If empty, every .c/.h file under the vendor directory is compared.
    upstream_key_files: list[str] = field(default_factory=list)
    upstream_max_commits: int = 300


COMPONENTS: dict[str, Component] = {
    "luafilesystem": Component(
        display_name="LuaFileSystem",
        file_triggers={"lfs.c", "lfs.h"},
        version_re=re.compile(r'#\s*define\s+LFS_VERSION\s+"([^"]+)"'),
        osv_ecosystem="GitHub",
        osv_name="lunarmodules/luafilesystem",
        purl_type="github", purl_ns="lunarmodules", purl_name="luafilesystem",
        homepage="https://github.com/lunarmodules/luafilesystem",
        upstream_url="https://github.com/lunarmodules/luafilesystem.git",
        upstream_key_files=["src/lfs.c", "src/lfs.h"],
    ),
    "sqlite": Component(
        display_name="SQLite",
        file_triggers={"sqlite3.c", "sqlite3.h"},
        dir_re=re.compile(r"sqlite[3-]?[-_](\d[\d.]*)"),
        version_re=re.compile(r'#\s*define\s+SQLITE_VERSION\s+"([^"]+)"'),
        # OSV lacks a reliable ecosystem for upstream SQLite; query via binary scan
        # with cve-bin-tool instead: cve-bin-tool libcivetweb.so
        osv_ecosystem="",
        osv_name="",
        purl_type="generic", purl_ns="", purl_name="sqlite",
        homepage="https://sqlite.org",
        # No upstream_url: the history is far too large to clone for a check.
        # Point --cache-dir at a pre-cloned repository instead.
    ),
    "lua": Component(
        display_name="Lua",
        file_triggers={"lua.h", "lualib.h", "lauxlib.h"},
        dir_re=re.compile(r"lua[-_](\d+\.\d+[\.\d]*)"),
        version_re=re.compile(r'#\s*define\s+LUA_RELEASE\s+"Lua ([^"]+)"'),
        osv_ecosystem="GitHub",
        osv_name="lua/lua",
        purl_type="github", purl_ns="lua", purl_name="lua",
        homepage="https://www.lua.org",
        upstream_url="https://github.com/lua/lua.git",
        upstream_key_files=["ldo.c", "lvm.c", "lua.h", "lstate.c", "lobject.h"],
        upstream_max_commits=500,
    ),
    "duktape": Component(
        display_name="Duktape",
        file_triggers={"duktape.c", "duktape.h", "duk_config.h"},
        dir_re=re.compile(r"duktape[-_](\d+\.\d+[\.\d]*)"),
        version_re=re.compile(r'#\s*define\s+DUK_VERSION\s+(\d+)'),
        version_transform=_duk_version,
        osv_ecosystem="GitHub",
        osv_name="svaarala/duktape",
        purl_type="github", purl_ns="svaarala", purl_name="duktape",
        homepage="https://duktape.org",
        upstream_url="https://github.com/svaarala/duktape.git",
        upstream_key_files=["src/duktape.c", "src/duktape.h", "src/duk_config.h"],
        upstream_max_commits=100,
    ),
    "lsqlite3": Component(
        display_name="lsqlite3",
        file_triggers={"lsqlite3.c"},
        version_re=re.compile(r'VERSION\s*=\s*"([^"]+)"'),
        osv_ecosystem="GitHub",
        osv_name="LuaDist/lsqlite3",
        purl_type="github", purl_ns="LuaDist", purl_name="lsqlite3",
        homepage="https://github.com/LuaDist/lsqlite3",
    ),
    "luaxml": Component(
        display_name="LuaXML",
        file_triggers={"LuaXML_lib.c", "LuaXML_lib.h", "LuaXML.lua"},
        osv_ecosystem="GitHub",
        osv_name="LuaDist/luaxml",
        purl_type="github", purl_ns="LuaDist", purl_name="luaxml",
        homepage="https://github.com/LuaDist/luaxml",
    ),
    "lua_struct": Component(
        display_name="lua-struct",
        file_triggers={"lua_struct.c"},
        osv_ecosystem="GitHub",
        osv_name="iamclint/lua-struct",
        purl_type="github", purl_ns="iamclint", purl_name="lua-struct",
    ),
    "expat": Component(
        display_name="Expat",
        file_triggers={"expat.h", "xmlparse.c", "xmltok.c"},
        dir_re=re.compile(r"expat[-_](\d+\.\d+[\.\d]*)"),
        version_re=re.compile(r'#\s*define\s+XML_MAJOR_VERSION\s+(\d+)'),
        osv_ecosystem="GitHub",
        osv_name="libexpat/libexpat",
        purl_type="github", purl_ns="libexpat", purl_name="libexpat",
        upstream_url="https://github.com/libexpat/libexpat.git",
        upstream_key_files=[
            "expat/lib/xmlparse.c", "expat/lib/xmltok.c",
            "expat/lib/expat.h",
        ],
    ),
    "zlib": Component(
        display_name="zlib",
        file_triggers={"zlib.h", "inflate.c", "deflate.c"},
        dir_re=re.compile(r"zlib[-_](\d+\.\d+[\.\d]*)"),
        version_re=re.compile(r'#\s*define\s+ZLIB_VERSION\s+"([^"]+)"'),
        osv_ecosystem="GitHub",
        osv_name="madler/zlib",
        purl_type="github", purl_ns="madler", purl_name="zlib",
        upstream_url="https://github.com/madler/zlib.git",
        upstream_key_files=["inflate.c", "deflate.c", "zlib.h", "crc32.c", "adler32.c"],
    ),
    "libpng": Component(
        display_name="libpng",
        file_triggers={"png.h", "png.c", "pngconf.h"},
        version_re=re.compile(r'#\s*define\s+PNG_LIBPNG_VER_STRING\s+"([^"]+)"'),
        osv_ecosystem="GitHub",
        osv_name="pnggroup/libpng",
        purl_type="github", purl_ns="pnggroup", purl_name="libpng",
    ),
    "cjson": Component(
        display_name="cJSON",
        file_triggers={"cJSON.c", "cJSON.h"},
        version_re=re.compile(r'#\s*define\s+CJSON_VERSION_MAJOR\s+(\d+)'),
        osv_ecosystem="GitHub",
        osv_name="DaveGamble/cJSON",
        purl_type="github", purl_ns="DaveGamble", purl_name="cJSON",
    ),
    "jsmn": Component(
        display_name="jsmn",
        file_triggers={"jsmn.c", "jsmn.h"},
        osv_ecosystem="GitHub",
        osv_name="zserge/jsmn",
        purl_type="github", purl_ns="zserge", purl_name="jsmn",
    ),
    "mbedtls": Component(
        display_name="Mbed TLS",
        file_triggers={"ssl.h", "aes.h", "sha256.c"},
        dir_re=re.compile(r"mbedtls[-_](\d+\.\d+[\.\d]*)"),
        version_re=re.compile(r'#\s*define\s+MBEDTLS_VERSION_STRING\s+"([^"]+)"'),
        osv_ecosystem="GitHub",
        osv_name="Mbed-TLS/mbedtls",
        purl_type="github", purl_ns="Mbed-TLS", purl_name="mbedtls",
    ),

    # ── Known upstreams without SBOM detection rules yet ─────────────────────
    # These carry no file_triggers, so the SBOM never claims to have found
    # them; upstream verification reaches them by vendor-directory name.
    "wslay": Component(
        display_name="wslay",
        upstream_url="https://github.com/tatsuhiro-t/wslay.git",
        upstream_key_files=[
            "lib/wslay_event.c", "lib/wslay_frame.c",
            "lib/wslay_net.c",   "lib/wslay_queue.c",
            "lib/wslay_event.h", "lib/wslay_frame.h",
            "lib/wslay_net.h",   "lib/wslay_queue.h",
            "lib/includes/wslay/wslay.h",
        ],
    ),
    "libutp": Component(
        display_name="libutp",
        upstream_url="https://github.com/bittorrent/libutp.git",
        upstream_key_files=["utp.cpp", "utp.h", "utp_internal.cpp"],
    ),
    "civetweb": Component(
        display_name="CivetWeb",
        upstream_url="https://github.com/civetweb/civetweb.git",
        upstream_key_files=["src/civetweb.c", "include/civetweb.h"],
        upstream_max_commits=100,
    ),
}


def match_by_filename(filename: str) -> Optional[str]:
    """Return the key of the first component *filename* identifies, else None."""
    for key, comp in COMPONENTS.items():
        if filename in comp.file_triggers:
            return key
    return None


def match_by_dirname(dirname: str) -> Optional[tuple[str, str]]:
    """Return ``(component_key, version)`` read off a versioned directory name."""
    for key, comp in COMPONENTS.items():
        if comp.dir_re:
            m = comp.dir_re.search(dirname)
            if m:
                return key, m.group(1)
    return None


def upstream_for(vendor_dir_name: str) -> Optional[Component]:
    """Return the component vendored under *vendor_dir_name* if we can clone it."""
    comp = COMPONENTS.get(vendor_dir_name)
    if comp is not None and comp.upstream_url:
        return comp
    return None
